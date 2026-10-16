#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <setjmp.h>
#include <new>
#include "../ntw2_clones.h"
#include "native_brain2.h"
#include "native_brain_workers.h"
#include "native_region_table.h"
#pragma fenv_access(on)

static_assert(sizeof(void*) == 4, "BRAIN_W is the pinned Win32 x86 native closure");
namespace ntw2_brain_workers {
namespace {
using B = uint8_t;
constexpr DWORD kRefuse = 0xE042B301u;
// last_fault_code when the bound model LCG word changed during a dispatch (see RunWorklist); not an exception.
constexpr U kLcgRaced = 0xE042B302u;
constexpr U kMaxParticipants = 16, kTimerOffset = 0x518, kActivationOffset = 0x30;
constexpr U kStageBytes = 32 * 1024, kMaxEvents = 8192, kEventsPerOccurrence = 4, kNone = ~0u;
constexpr U kDiffBytesPerEntity = 448, kMinDiffPool = 1u << 20, kChunkMin = 16, kChunkMax = 512;
constexpr U kBoundary = 0xFFFF;
static_assert(kReceiverBytes % 64 == 0 && kTimerBytes % 64 == 0, "digest consumes 64-byte groups");
static_assert(kEventsPerOccurrence * 2 <= 255, "event counter is one byte");
// New private pointers the step is known to publish at offsets that held no self pointer at capture
// (reference destructor: A+0x1E0 = A+0x5E4, native-brain-kernel-seams.md 2.3).
constexpr U kEscapeAllowed[] = {0x1E0};

enum State : B { SlotUnprocessed, SlotComputed, SlotRefused, SlotSkipped };
struct SpanHeader { uint16_t target, offset, length; };
enum SpanTarget : uint16_t { TargetSoldier = 0, TargetTimer = 1 };

// Slots are not cleared per stage: a slot whose stamp differs from the arena's current stamp was not written this
// stage and reads as Unprocessed. The stamp cycles 1..255; the whole slot array is zeroed when it wraps.
struct Slot {
    U entity, timer;
    U digestA[4], digestT[4];
    U spanOffset, spanBytes, eventFirst;
    B state, reason, service, eventCount;
    uint16_t spanCount; B stamp, pad;
    U draws; // stream draws of this ordinal's worker run (meaningful when computed)
};
static_assert(sizeof(Slot) == 64, "one slot per cache line");
struct Event {
    U kind, target, receiver, argc, arg[3];
    B payload[0x30];
};

struct Counters {
    U speculated, computed, refused, capacity, overflow, diffBytes, diffSpans, faults, regionQueries;
    U depOverflow, gates;
    U events[kEventKinds], reasons[kReasonCount], services[kServiceRows];
    U lastService, lastEntity, lastReason;
    // RDTSC sums of this stage (worker phase profile): per speculated ordinal and per chunk.
    ULONGLONG captureTicks, cloneTicks, publishTicks, busyTicks, maxChunkTicks;
};

// Readable ranges are proven per stage (native_region_table.h) before any footprint byte is touched, so no access
// violation (and no crash-recorder entry) is raised by a speculative read; SEH remains the backstop for a region
// freed concurrently.
using RegionTable = ntw2_region::Table;

struct Arena;
struct Participant;
// Per-participant cache of the static gate verdicts (ntw2_brain2::WorkerStaticVerdict plus this module's forced/hard/
// deferred-event exclusions): `replacement` is the callee the gate continues to (the target itself when forwarded,
// the worker clone entry when cloned), 0 when the gate must classify per call. WorkerServiceGate's fast path reads it
// in assembly: index ((site ^ target) * 0x9E3779B1) >> 23, 16-byte entries, so kGateSlots is fixed at 512.
struct GateEntry { U site, target, replacement, pad; };
constexpr U kGateSlots = 512;
inline U GateIndex(U site, U target) { return ((site ^ target) * 0x9E3779B1u) >> 23; }
struct Current {
    GateEntry* gateCache; // offset 0 (WorkerServiceGate fast path)
    U fastGates;          // offset 4: gates the fast path served (WorkerServiceGate fast path)
    Participant* participant;
    Arena* arena;
    Slot* slot;
    U entity, work, timer, timerWork;
    U reason, service, pendingTarget, pendingKind;
    U eventBase, eventCount, stageBytes, stageSpans, ordinal;
    ntw2_brain2::WitnessDeps* deps; // this ordinal's witness dependencies (arena-owned, read by the owner at commit)
    U stream, draws; // private model-LCG word served to 5FC070 on the bound receiver, and its draw count
    bool hasTimer, jumpArmed; // jumpArmed: refuseJump is live (RunCloneGuarded's frame is on the stack)
    ULONGLONG captured, cloned; // RDTSC at clone start / clone return (0: not reached)
    jmp_buf refuseJump;
};
struct alignas(64) Participant {
    // Native-space baseline (starts as the pristine capture), private working copy, native-space export.
    alignas(16) B base[kReceiverBytes + 16];
    alignas(16) B work[kReceiverBytes + 16];
    alignas(16) B out[kReceiverBytes + 16];
    alignas(16) B timerBase[kTimerBytes + 16];
    alignas(16) B timerWork[kTimerBytes + 16];
    alignas(16) B timerOut[kTimerBytes + 16];
    alignas(16) B stage[kStageBytes];
    U rebased[kReceiverBytes / 4 / 32], rebasedTimer;
    Counters counters;
    RegionTable regions;
    ntw2_brain2::WitnessMemo memo; // bound around this participant's chunks; new epoch per dispatch
    GateEntry gateCache[kGateSlots];
    Current current;
};
struct Arena {
    Slot* slots = nullptr;
    U* list = nullptr;
    B* diff = nullptr;
    Event* events = nullptr;
    ntw2_brain2::WitnessDeps* deps = nullptr; // one record per ordinal
    B* blocks = nullptr; // kGuardBlocks capture checksums per ordinal (guard-miss attribution only)
    U capacity = 0, diffCapacity = 0, count = 0, chunkSize = 0, chunks = 0, mxcsr = 0;
    // Stage RNG binding: the model LCG word (0: unbound), its value at stage start, the stage generation.
    U rngLcg = 0, rngState = 0, rngGeneration = 0;
    unsigned short cw = 0;
    B stamp = 0; // current slot stamp (Slot::stamp), 1..255
    volatile LONG diffUsed = 0, eventUsed = 0, nextParticipant = 0, epoch = 0, diffExhausted = 0;
    ULONGLONG bytes = 0;
};

struct Config {
    bool started = false, quiet = false;
    U delta = 0, workers = 0, participants = 0, minEntities = 64, deferMask = 0;
    ntw2_clone_set family{};
    U stubs[kEventKinds] = {};
    Participant* participant[kMaxParticipants] = {};
    Arena arena;
};
Config g;
void (__stdcall* g_dispatch)(U, U, U, void*);
U g_pool;
U g_words[WordCount];
U g_phase[kPhaseWords];
U g_guardFirst[kReceiverBytes / 16]; // first-changed-block histogram of soldier guard misses (owner only)
U g_missService[kServiceRows + 1];   // refusal service + 1 of the owner-run soldier preceding a soldier miss
volatile LONG g_sticky, g_epochCounter;
U g_rngGeneration; // bound stages since Start/Reset
RegionTable g_ownerRegions;
__declspec(thread) Current* t_current;
// fs-relative offset of the TLS slot mirroring t_current for WorkerServiceGate's fast path (TEB TlsSlots at fs:[E10h]
// + 4 * index, the layout TlsGetValue reads for index < 64); 0 disables the fast path (cache still used in C++).
U g_gateTls, g_gateTlsIndex = TLS_OUT_OF_INDEXES;
// Owner-walk witness memo for WitnessDepsHold (world read sets only; new epoch after every native write but commits).
ntw2_brain2::WitnessMemo g_ownerMemo;
__declspec(thread) Participant* t_participant;
__declspec(thread) LONG t_epoch;
#ifdef NTW2_BRAIN_WORKERS_ORACLE
FaultInjector g_injector;
bool g_computeOnly;
#endif

inline U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
inline U V(U va) { return va + g.delta; }
inline U D(U a) { return *reinterpret_cast<volatile const U*>(static_cast<uintptr_t>(a)); }
inline B Byte(U a) { return *reinterpret_cast<volatile const B*>(static_cast<uintptr_t>(a)); }
inline U Get(const B* p, U o) { U v; memcpy(&v, p + o, 4); return v; }
inline void Put(B* p, U o, U v) { memcpy(p + o, &v, 4); }
inline LONGLONG Now() { LARGE_INTEGER v; QueryPerformanceCounter(&v); return v.QuadPart; }
LONGLONG g_frequency;
inline U Microseconds(LONGLONG ticks) {
    if (!g_frequency) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_frequency = f.QuadPart; }
    return static_cast<U>((ticks * 1000000) / g_frequency);
}
inline ULONGLONG Tsc() { return __rdtsc(); }
// RDTSC ticks -> microseconds with the current stage's calibration (QPC microseconds per TSC tick over the stage).
struct TscScale {
    ULONGLONG tsc; U us;
    U operator()(ULONGLONG ticks) const { return tsc ? static_cast<U>(ticks * us / tsc) : 0; }
};

// 128-bit footprint digest: four AES lanes, two rounds per 16-byte block, cross-lane finalization. Not
// cryptographic, but a changed byte survives with probability 2^-128, which the commit guard treats as exact.
// CaptureLoop computes the identical digest while it copies.
struct DigestKeys {
    __m128i k0, k1, k2, k3;
    DigestKeys() {
        k0 = _mm_set_epi32(0x13198a2e, 0x03707344, static_cast<int>(0xa4093822), 0x299f31d0);
        k1 = _mm_set_epi32(0x082efa98, static_cast<int>(0xec4e6c89), 0x452821e6, 0x38d01377);
        k2 = _mm_set_epi32(static_cast<int>(0xbe5466cf), 0x34e90c6c, static_cast<int>(0xc0ac29b7), static_cast<int>(0xc97c50dd));
        k3 = _mm_set_epi32(0x3f84d5b5, static_cast<int>(0xb5470917), static_cast<int>(0x9216d5d9), static_cast<int>(0x8979fb1b));
    }
};
#define DIGEST_GROUP(K, s0, s1, s2, s3, v0, v1, v2, v3) \
    s0 = _mm_aesenc_si128(_mm_aesenc_si128(_mm_xor_si128(s0, v0), K.k1), K.k2); \
    s1 = _mm_aesenc_si128(_mm_aesenc_si128(_mm_xor_si128(s1, v1), K.k2), K.k3); \
    s2 = _mm_aesenc_si128(_mm_aesenc_si128(_mm_xor_si128(s2, v2), K.k3), K.k0); \
    s3 = _mm_aesenc_si128(_mm_aesenc_si128(_mm_xor_si128(s3, v3), K.k0), K.k1)
#define DIGEST_FINAL(K, s0, s1, s2, s3, out) do { \
    __m128i a_ = _mm_aesenc_si128(_mm_xor_si128(s0, s2), s1); \
    const __m128i b_ = _mm_aesenc_si128(_mm_xor_si128(s1, s3), s0); \
    a_ = _mm_aesenc_si128(_mm_aesenc_si128(a_, b_), K.k0); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), a_); } while (0)
void Digest(const void* data, U bytes, U out[4]) {
    const DigestKeys K;
    __m128i s0 = _mm_xor_si128(K.k0, _mm_cvtsi32_si128(static_cast<int>(bytes))), s1 = K.k1, s2 = K.k2, s3 = K.k3;
    const __m128i* p = reinterpret_cast<const __m128i*>(data);
    for (U i = 0; i < bytes / 64; ++i, p += 4) {
        DIGEST_GROUP(K, s0, s1, s2, s3, _mm_loadu_si128(p + 0), _mm_loadu_si128(p + 1), _mm_loadu_si128(p + 2), _mm_loadu_si128(p + 3));
    }
    DIGEST_FINAL(K, s0, s1, s2, s3, out);
}
inline bool Same(const U a[4], const U b[4]) { return !((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])); }
// Guard-miss attribution: one byte per 16-byte block of the soldier footprint (a changed block escapes with
// probability 2^-8, reported as an unlocated miss). Diagnostics only; the digest above is the guard.
constexpr U kGuardBlocks = kReceiverBytes / 16;
void BlockSums(const B* data, B* out) {
    for (U i = 0; i < kGuardBlocks; ++i) {
        U w[4]; memcpy(w, data + 16 * i, 16);
        const U h = (w[0] * 0x9E3779B1u) ^ (w[1] * 0x85EBCA77u) ^ (w[2] * 0xC2B2AE3Du) ^ (w[3] * 0x27D4EB2Fu);
        out[i] = static_cast<B>((h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24)) & 0xFF);
    }
}
// SEH-guarded copy of live native bytes; false on any fault, destination undefined.
bool CopyLive(void* dst, U src, U bytes) {
    __try { memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(src)), bytes); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Lane mask (bit per dword) of `v` in [lo, lo + limit) unsigned; limit 0 matches nothing.
inline int InRange(const __m128i& v, const __m128i& lo, const __m128i& biasedLimit) {
    const __m128i bias = _mm_set1_epi32(static_cast<int>(0x80000000u));
    return _mm_movemask_ps(_mm_castsi128_ps(_mm_cmplt_epi32(_mm_xor_si128(_mm_sub_epi32(v, lo), bias), biasedLimit)));
}
inline __m128i BiasedLimit(U limit) { return _mm_set1_epi32(static_cast<int>(limit ^ 0x80000000u)); }

// A refusal abandons the clone run. Inside RunCloneGuarded it leaves through longjmp (see there); anywhere else it
// raises kRefuse for RunSlotBody's filter.
__declspec(noreturn, noinline) void Refuse(Current* c, Reason reason, U service) {
    c->reason = reason; c->service = service;
    if (c->jumpArmed) { c->jumpArmed = false; longjmp(c->refuseJump, 1); }
    RaiseException(kRefuse, EXCEPTION_NONCONTINUABLE, 0, nullptr);
}

// ---- pointer translation between the native soldier and its private copy ----
inline U Rebase(const Current& c, U v) {
    if (v - c.entity < kReceiverBytes) return c.work + (v - c.entity);
    if (c.hasTimer && v - c.timer < kTimerBytes) return c.timerWork + (v - c.timer);
    return v;
}
inline bool Private(const Current& c, U v) {
    return v - c.work < kReceiverBytes || (c.hasTimer && v - c.timerWork < kTimerBytes);
}
inline U Native(const Current& c, U v) {
    if (v - c.work < kReceiverBytes) return c.entity + (v - c.work);
    if (c.hasTimer && v - c.timerWork < kTimerBytes) return c.timer + (v - c.timerWork);
    return v;
}
bool EscapeAllowed(U offset) {
    for (U o : kEscapeAllowed) if (o == offset) return true;
    return false;
}
// Capture of the soldier footprint in ONE pass over the live bytes: the pristine copy (`base`), its digest
// (identical to Digest over the same bytes) and the private working copy (`work`) in which every dword pointing into
// the soldier or its timer is rebased onto the participant copies; `bits` (zeroed by the caller) receives the
// rebased dword offsets. Faults propagate (the caller's SEH scope); the bytes were proven readable first.
__declspec(noinline) void CaptureLoop(const Current& c, const B* native, B* base, B* work, U* bits, U digest[4]) {
    const DigestKeys K;
    const __m128i selfLo = _mm_set1_epi32(static_cast<int>(c.entity)), selfLimit = BiasedLimit(kReceiverBytes);
    const __m128i timerLo = _mm_set1_epi32(static_cast<int>(c.timer)), timerLimit = BiasedLimit(c.hasTimer ? kTimerBytes : 0);
    __m128i s0 = _mm_xor_si128(K.k0, _mm_cvtsi32_si128(static_cast<int>(kReceiverBytes))), s1 = K.k1, s2 = K.k2, s3 = K.k3;
    for (U group = 0; group < kReceiverBytes; group += 64) {
        const __m128i* p = reinterpret_cast<const __m128i*>(native + group);
        const __m128i v0 = _mm_loadu_si128(p + 0), v1 = _mm_loadu_si128(p + 1), v2 = _mm_loadu_si128(p + 2), v3 = _mm_loadu_si128(p + 3);
        DIGEST_GROUP(K, s0, s1, s2, s3, v0, v1, v2, v3);
        const __m128i* const v[4] = {&v0, &v1, &v2, &v3};
        for (U j = 0; j < 4; ++j) {
            const U at = group + 16 * j;
            _mm_storeu_si128(reinterpret_cast<__m128i*>(base + at), *v[j]);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(work + at), *v[j]);
            int lanes = InRange(*v[j], selfLo, selfLimit) | InRange(*v[j], timerLo, timerLimit);
            while (lanes) {
                unsigned long lane; _BitScanForward(&lane, static_cast<unsigned long>(lanes)); lanes &= lanes - 1;
                const U off = at + 4 * lane;
                Put(work, off, Rebase(c, Get(base, off)));
                bits[off / 128] |= 1u << ((off / 4) & 31);
            }
        }
    }
    DIGEST_FINAL(K, s0, s1, s2, s3, digest);
}
// Export + diff in one pass over 16-byte blocks. `out` = `work` with private pointers translated back to native
// space; a private pointer at an offset that held no self pointer at capture (`bits`, or the timer's rebased mask)
// and is not an allowed escape refuses the occurrence (ReasonEscape). Appends the byte spans where `out` differs
// from `base`: gaps of up to three equal bytes are bridged, except when events are deferred (a replayed service may
// legitimately change a bridged byte before the next span lands). `keepBase` (a later segment follows) makes `out`
// the new baseline.
U NextDiff(const uint16_t* masks, U blocks, U from) {
    U block = from >> 4;
    if (block >= blocks) return blocks * 16;
    U bits = masks[block] & (0xFFFFu << (from & 15));
    while (!bits) {
        if (++block == blocks) return blocks * 16;
        bits = masks[block];
    }
    unsigned long bit; _BitScanForward(&bit, bits);
    return block * 16 + bit;
}
void Publish(Current& c, const B* work, B* base, B* out, U bytes, bool timer, SpanTarget target, bool keepBase) {
    const U* const bits = c.participant->rebased;
    const __m128i workLo = _mm_set1_epi32(static_cast<int>(c.work)), workLimit = BiasedLimit(kReceiverBytes);
    const __m128i timerLo = _mm_set1_epi32(static_cast<int>(c.timerWork)), timerLimit = BiasedLimit(c.hasTimer ? kTimerBytes : 0);
    uint16_t masks[kReceiverBytes / 16];
    const U blocks = bytes / 16;
    for (U b = 0; b < blocks; ++b) {
        const U at = 16 * b;
        const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(work + at));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + at), v);
        int lanes = InRange(v, workLo, workLimit) | InRange(v, timerLo, timerLimit);
        while (lanes) {
            unsigned long lane; _BitScanForward(&lane, static_cast<unsigned long>(lanes)); lanes &= lanes - 1;
            const U off = at + 4 * lane, value = Get(work, off);
            const bool known = timer ? (c.participant->rebasedTimer >> (off / 4)) & 1
                                     : ((bits[off / 128] >> ((off / 4) & 31)) & 1) || EscapeAllowed(off);
            if (!known) Refuse(&c, ReasonEscape, kServiceRows - 1);
            Put(out, off, Native(c, value));
        }
        const __m128i now = _mm_loadu_si128(reinterpret_cast<const __m128i*>(out + at));
        const __m128i was = _mm_loadu_si128(reinterpret_cast<const __m128i*>(base + at));
        masks[b] = static_cast<uint16_t>(~_mm_movemask_epi8(_mm_cmpeq_epi8(now, was)));
    }
    B* const stage = c.participant->stage;
    const U bridge = g.deferMask ? 0u : 3u;
    U i = NextDiff(masks, blocks, 0);
    while (i < bytes) {
        const U start = i;
        U last = i, next;
        for (;;) {
            next = NextDiff(masks, blocks, last + 1);
            if (next < bytes && next - last <= bridge) last = next; else break;
        }
        const U length = last - start + 1;
        if (c.stageBytes + sizeof(SpanHeader) + length > kStageBytes) Refuse(&c, ReasonSpanCapacity, kServiceRows - 1);
        const SpanHeader h = {target, static_cast<uint16_t>(start), static_cast<uint16_t>(length)};
        memcpy(stage + c.stageBytes, &h, sizeof(h));
        memcpy(stage + c.stageBytes + sizeof(h), out + start, length);
        c.stageBytes += sizeof(h) + length; ++c.stageSpans;
        i = next;
    }
    if (keepBase) memcpy(base, out, bytes);
}
// Closes the current checkpoint: diff of the exported private state against the running native-space baseline.
// `last`: no later segment of this occurrence follows, so the baseline is not advanced.
void CloseSegment(Current& c, bool last) {
    Participant& p = *c.participant;
    Publish(c, reinterpret_cast<const B*>(static_cast<uintptr_t>(c.work)), p.base + (c.entity & 15), p.out + (c.entity & 15),
            kReceiverBytes, false, TargetSoldier, !last);
    if (c.hasTimer)
        Publish(c, reinterpret_cast<const B*>(static_cast<uintptr_t>(c.timerWork)), p.timerBase + (c.timer & 15),
                p.timerOut + (c.timer & 15), kTimerBytes, true, TargetTimer, !last);
}

// ---- event deferral (owner replay at a checkpoint) ----
U EventKindOf(U original, U site) {
    if (site == 0x63C4D3) return EventCharge;
    switch (original) {
    case 0x6631A0: case 0x662E70: return EventOrder;
    case 0x655B20: return EventArrival;
    case 0x659520: return EventRequest;
    default: return kNone;
    }
}
constexpr U kEventArgc[kEventKinds] = {3, 1, 2, 1};
void __stdcall RecordEvent(U kind, U receiver, const U* args) {
    Current& c = *t_current;
    Arena& a = *c.arena;
    if (!c.eventCount) {
        const LONG first = _InterlockedExchangeAdd(&a.eventUsed, kEventsPerOccurrence);
        if (static_cast<U>(first) + kEventsPerOccurrence > kMaxEvents) Refuse(&c, ReasonEventCapacity, kServiceRows - 1);
        c.eventBase = static_cast<U>(first);
        c.slot->eventFirst = c.eventBase;
    }
    if (c.eventCount == kEventsPerOccurrence) Refuse(&c, ReasonEventCapacity, kServiceRows - 1);
    Event& e = a.events[c.eventBase + c.eventCount];
    memset(&e, 0, sizeof(e));
    e.kind = kind; e.argc = kEventArgc[kind]; e.receiver = Native(c, receiver);
    e.target = kind == EventCharge ? c.pendingTarget : 0;
    if (kind == EventRequest) {
        memcpy(e.payload, reinterpret_cast<const void*>(static_cast<uintptr_t>(args[0])), 20);
        memcpy(e.payload + 20, reinterpret_cast<const void*>(static_cast<uintptr_t>(args[1])), 0x1c);
    } else {
        for (U i = 0; i < e.argc; ++i) e.arg[i] = Native(c, args[i]);
    }
    CloseSegment(c, false);
    const SpanHeader marker = {kBoundary, static_cast<uint16_t>(c.eventCount), 0};
    if (c.stageBytes + sizeof(marker) > kStageBytes) Refuse(&c, ReasonSpanCapacity, kServiceRows - 1);
    memcpy(c.participant->stage + c.stageBytes, &marker, sizeof(marker));
    c.stageBytes += sizeof(marker);
    ++c.eventCount;
    ++c.participant->counters.events[kind];
}
// Replacement callees of the deferred services: same stack cleanup, no result, receiver in ECX.
#define EVENT_STUB(name, kindValue, cleanup) \
    __declspec(naked) void name() { \
        __asm lea eax, [esp+4] \
        __asm push eax \
        __asm push ecx \
        __asm push kindValue \
        __asm call RecordEvent \
        __asm xor eax, eax \
        __asm ret cleanup \
    }
EVENT_STUB(OrderStub, 0, 0Ch)
EVENT_STUB(ArrivalStub, 1, 4)
EVENT_STUB(RequestStub, 2, 8)
EVENT_STUB(ChargeStub, 3, 4)
#undef EVENT_STUB

// ---- participant gates ----
bool HardRefused(U original) {
    switch (original) {
    case 0x658BA0: case 0x66BF80: case 0x6666E0: case 0x7FD070: case 0x7E1ED0: return true;
    default: return false;
    }
}
bool LocalForcedSite(U site) { return site == 0x658F39 || site == 0x658BD3 || site == 0x66BF95 || site == 0x658F16; }
// GateEntry::replacement for (site, target): nonzero exactly when every call there continues to one fixed callee with
// no per-call classification, refusal, stream redirect or event stub (the static part of the decision below).
U StaticReplacement(U site, U target) {
    const U original = target - g.delta;
    if (LocalForcedSite(site) || HardRefused(original)) return 0;
    if (g.deferMask) {
        const U kind = EventKindOf(original, site);
        if (kind != kNone && (g.deferMask >> kind & 1)) return 0;
    }
    switch (ntw2_brain2::WorkerStaticVerdict(target, site)) {
    case ntw2_brain2::StaticForward: return target;
    case ntw2_brain2::StaticClone: return g.family.entries[ntw2_brain2::CloneIdFor(original)];
    default: return 0;
    }
}

// Stack at entry: [source site, actual target, native return address, args...]; registers in PUSHAD layout
// (written back by POPAD: the stream redirect replaces ECX).
void __stdcall WorkerEnter(U* stack, U* registers) {
    Current* c = t_current;
    if (!c) return;
    ++c->participant->counters.gates;
    const U site = stack[0], target = stack[1], receiver = registers[6], original = target - g.delta;
    GateEntry& cached = c->gateCache[GateIndex(site, target)];
    if (cached.site != site || cached.target != target) cached = GateEntry{site, target, StaticReplacement(site, target), 0};
    if (cached.replacement) { stack[1] = cached.replacement; return; }
    if (LocalForcedSite(site) || ntw2_brain2::WorkerSiteForced(site)) Refuse(c, ReasonSiteForced, ntw2_brain2::Unknown);
    if (HardRefused(original)) Refuse(c, ReasonHardList, ntw2_brain2::Unknown);
    if (g.deferMask) {
        const U kind = EventKindOf(original, site);
        if (kind != kNone && (g.deferMask >> kind & 1)) {
            if (kind == EventCharge) c->pendingTarget = target;
            stack[1] = g.stubs[kind];
            return;
        }
    }
    const U id = ntw2_brain2::CloneIdFor(original);
    U service = ntw2_brain2::Unknown;
    const ntw2_brain2::Classification cls =
        ntw2_brain2::WorkerClassify(target, site, receiver, stack + 3, c->work, &service, c->deps);
    if (id != kNone) {
        // A cloned container is Inactive at entry unless its site is forced or its entry predicate (WrapperService)
        // is unresolved; its descendants are classified at their own gates.
        if (cls != ntw2_brain2::Inactive)
            Refuse(c, cls == ntw2_brain2::Active ? ReasonServiceActive : ReasonServiceUnresolved, service);
        stack[1] = g.family.entries[id];
        return;
    }
    if (cls == ntw2_brain2::Inactive) {
        // 5FC070 on the bound model LCG: run the ORIGINAL 5FC070 against this occurrence's private stream word.
        // ECX is dead after the call at all six cloned sites (5B7C9F/5B7CEE/5B7E49, 66DE62/66DF04/66E002 each
        // reload or overwrite it first), so redirecting it is invisible; the output format is native by construction
        // and the shared word is never read or written here.
        if (ntw2_brain2::WorkerRandomStream(target, receiver)) {
            registers[6] = Address(&c->stream);
            ++c->draws;
            return;
        }
        // Forwardable == not cloned (id above), not 5FC070, and WorkerClassify Inactive (native_brain2.h): all three
        // already hold here, so the original is forwarded without classifying the call a second time.
        if (original != 0x5FC070) return;
        Refuse(c, ReasonServiceReceiver, service);
    }
    Refuse(c, cls == ntw2_brain2::Active ? ReasonServiceActive : ReasonServiceUnresolved, service);
}
void __stdcall WorkerObserve(U site, const U* registers) {
    Current* c = t_current;
    if (!c) return;
    ++c->participant->counters.gates;
    const ntw2_brain2::Classification cls = ntw2_brain2::WorkerObserveClassify(site, registers, c->work, c->deps);
    if (cls == ntw2_brain2::Inactive) return;
    Refuse(c, cls == ntw2_brain2::Active ? ReasonObserveActive : ReasonObserveUnresolved, ntw2_brain2::MutableRead);
}
// Transparent forwarding gates. Only the volatile XMM registers are saved around the C++ decision, which uses
// no x87 and never changes MXCSR or the x87 control word.
// WorkerServiceGate first tries the participant's GateEntry cache in a few GPR instructions (EAX/ECX/EDX saved and
// restored, no XMM, no C++ call): a hit continues to the cached callee exactly as WorkerEnter would. It clobbers the
// arithmetic flags, which no x86 calling convention passes into a callee (DF is untouched); the slow path below
// still preserves everything. The Current pointer comes from the TLS slot g_gateTls mirrors t_current into.
__declspec(naked) void WorkerServiceGate() {
    __asm {
        push eax
        push ecx
        push edx
        mov eax, g_gateTls
        test eax, eax
        jz gate_slow
        mov ecx, fs:[eax]
        test ecx, ecx
        jz gate_slow
        mov edx, [esp+12]
        xor edx, [esp+16]
        imul edx, edx, -1640531535
        shr edx, 23
        shl edx, 4
        add edx, [ecx]
        mov eax, [esp+12]
        cmp eax, [edx]
        jne gate_slow
        mov eax, [esp+16]
        cmp eax, [edx+4]
        jne gate_slow
        mov eax, [edx+8]
        test eax, eax
        jz gate_slow
        mov [esp+16], eax
        inc dword ptr [ecx+4]
        pop edx
        pop ecx
        pop eax
        lea esp, [esp+4]
        ret
    gate_slow:
        pop edx
        pop ecx
        pop eax
    }
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 144
    __asm and esp, -16
    __asm movaps [esp], xmm0
    __asm movaps [esp+16], xmm1
    __asm movaps [esp+32], xmm2
    __asm movaps [esp+48], xmm3
    __asm movaps [esp+64], xmm4
    __asm movaps [esp+80], xmm5
    __asm movaps [esp+96], xmm6
    __asm movaps [esp+112], xmm7
    __asm cld
    __asm push ebp
    __asm lea eax, [ebp+36]
    __asm push eax
    __asm call WorkerEnter
    __asm movaps xmm0, [esp]
    __asm movaps xmm1, [esp+16]
    __asm movaps xmm2, [esp+32]
    __asm movaps xmm3, [esp+48]
    __asm movaps xmm4, [esp+64]
    __asm movaps xmm5, [esp+80]
    __asm movaps xmm6, [esp+96]
    __asm movaps xmm7, [esp+112]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm lea esp, [esp+4]
    __asm ret
}
__declspec(naked) void WorkerObserveGate() {
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 144
    __asm and esp, -16
    __asm movaps [esp], xmm0
    __asm movaps [esp+16], xmm1
    __asm movaps [esp+32], xmm2
    __asm movaps [esp+48], xmm3
    __asm movaps [esp+64], xmm4
    __asm movaps [esp+80], xmm5
    __asm movaps [esp+96], xmm6
    __asm movaps [esp+112], xmm7
    __asm cld
    __asm push ebp
    __asm push dword ptr [ebp+40]
    __asm call WorkerObserve
    __asm movaps xmm0, [esp]
    __asm movaps xmm1, [esp+16]
    __asm movaps xmm2, [esp+32]
    __asm movaps xmm3, [esp+48]
    __asm movaps xmm4, [esp+64]
    __asm movaps xmm5, [esp+80]
    __asm movaps xmm6, [esp+96]
    __asm movaps xmm7, [esp+112]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret 4
}

// ---- worker occurrence ----
void InstallFp(const Arena& a) {
    unsigned short cw = a.cw;
    __asm fninit
    __asm fldcw cw
    _mm_setcsr(a.mxcsr);
}
// Control bits only (DAZ, exception masks, rounding, FTZ): native code legitimately sets the sticky status flags.
// The x87 stack must be empty (TOP zero after FNINIT) with the owner's control word.
bool FpInstalled(const Arena& a) {
    unsigned short cw, sw;
    __asm fnstcw cw
    __asm fnstsw sw
    return ((_mm_getcsr() ^ a.mxcsr) & 0xFFC0u) == 0 && cw == a.cw && (sw & 0x3800) == 0;
}
LONG Filter(Current& c, EXCEPTION_POINTERS* info) {
    const EXCEPTION_RECORD& r = *info->ExceptionRecord;
    if (r.ExceptionCode == kRefuse) return EXCEPTION_EXECUTE_HANDLER;
    g_words[LastFaultCode] = r.ExceptionCode;
    g_words[LastFaultEip] = Address(r.ExceptionAddress);
    g_words[LastFaultEntity] = c.entity;
    g_words[LastFaultAddress] = (r.ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) &&
        r.NumberParameters >= 2 ? static_cast<U>(r.ExceptionInformation[1]) : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}
void Record(Participant& p, Slot& slot, Reason reason, U service) {
    slot.state = SlotRefused; slot.reason = static_cast<B>(reason); slot.service = static_cast<B>(service);
    ++p.counters.refused; ++p.counters.reasons[reason];
    if (service < kServiceRows) ++p.counters.services[service];
    p.counters.lastService = service + 1; p.counters.lastEntity = slot.entity; p.counters.lastReason = reason;
}
__declspec(noinline) void RunClone(U entry, U work) {
    reinterpret_cast<void (__thiscall*)(U)>(static_cast<uintptr_t>(entry))(work);
}
// The clone run and its checkpoint publication. A gate refusal leaves through longjmp: MSVC's longjmp unwinds the
// abandoned clone frames with RtlUnwind (their __finally / C++ unwind actions run exactly as in the unwind pass of a
// raised exception) but skips RaiseException's kernel round trip, the vectored handlers (the runtime crash recorder)
// and the filter search pass (measured on this host: 4.5 us vs 0.04 us per refusal across a 10-frame stack). A native
// __except/catch(...) in the clone can no longer intercept a refusal either. Real faults still raise and reach
// RunSlotBody's filter. Returns false when refused (c.reason set).
__declspec(noinline) bool RunCloneGuarded(Arena& a, Current& c, U entry) {
#pragma warning(suppress : 4611) // no C++ object with a destructor lives in this frame
    if (setjmp(c.refuseJump)) return false;
    c.jumpArmed = true;
#ifdef NTW2_BRAIN_WORKERS_ORACLE
    if (g_injector && g_injector(c.entity, c.ordinal) == 1) *reinterpret_cast<volatile U*>(0x10) = 1;
#endif
    RunClone(entry, c.work);
    c.cloned = Tsc();
    CloseSegment(c, true);
#ifdef NTW2_BRAIN_WORKERS_ORACLE
    // Stands in for the timing-dependent refusals (capacity, participant overflow) after a full worker run.
    if (g_injector && g_injector(c.entity, c.ordinal) == 2) Refuse(&c, ReasonInjected, kServiceRows - 1);
    // Stands in for a forwarded original that advanced the shared model LCG word from this thread.
    if (g_injector && g_injector(c.entity, c.ordinal) == 3 && a.rngLcg)
        _InterlockedIncrement(reinterpret_cast<volatile LONG*>(static_cast<uintptr_t>(a.rngLcg)));
#endif
    c.jumpArmed = false;
    return true;
}
// The live footprint's cache lines, a few ordinals ahead of the walk/capture that will read them (never faults).
inline void PrefetchFootprint(U entity) {
    const char* p = reinterpret_cast<const char*>(static_cast<uintptr_t>(entity));
    for (U off = 0; off < kReceiverBytes; off += 64) _mm_prefetch(p + off, _MM_HINT_T0);
}
// One worklist ordinal. False only after a REAL fault: sticky is set and the chunk stops. Sets c.captured when the
// clone run starts and c.cloned when it returns (RunSlot's phase split).
bool RunSlotBody(Arena& a, Participant& p, U ordinal) {
    if (ordinal + 1 < a.count) PrefetchFootprint(a.list[ordinal + 1]);
    Slot& slot = a.slots[ordinal];
    const U entity = a.list[ordinal];
    memset(&slot, 0, sizeof(slot));
    slot.entity = entity; slot.stamp = a.stamp;
    Current& c = p.current;
    memset(&c, 0, sizeof(c));
    c.gateCache = p.gateCache;
    c.participant = &p; c.arena = &a; c.slot = &slot; c.entity = entity; c.ordinal = ordinal;
    c.deps = &a.deps[ordinal]; c.deps->count = 0; c.deps->overflow = 0;
    // The same seed the owner writes into the real word before running this ordinal itself.
    if (a.rngLcg) c.stream = StreamSeed(a.rngState, a.rngGeneration, ordinal);
    ++p.counters.speculated;
    if (!p.regions.Readable(entity, kReceiverBytes, p.counters.regionQueries)) {
        // Only the activation byte decides whether this ordinal is an occurrence at all.
        if (p.regions.Readable(entity + kActivationOffset, 1, p.counters.regionQueries) &&
            Byte(entity + kActivationOffset) != 1) { slot.state = SlotSkipped; --p.counters.speculated; return true; }
        Record(p, slot, ReasonFootprint, kServiceRows - 1); return true;
    }
    U vtable = 0;
    __try {
        if (Byte(entity + kActivationOffset) != 1) { slot.state = SlotSkipped; --p.counters.speculated; return true; }
        vtable = D(entity);
        c.timer = D(entity + kTimerOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) { Record(p, slot, ReasonLifetime, kServiceRows - 1); return true; }
    U entry = 0;
    if (!p.regions.Readable(vtable + 0xC, 4, p.counters.regionQueries)) { Record(p, slot, ReasonClass, kServiceRows - 1); return true; }
    __try { entry = D(vtable + 0xC); } __except (EXCEPTION_EXECUTE_HANDLER) { Record(p, slot, ReasonLifetime, kServiceRows - 1); return true; }
    U id;
    if (entry == V(0x66CE00) || entry == V(0x6F50F0)) id = NTW2_CLONE_BRAIN_W;
    else if (entry == V(0x602EB0)) id = NTW2_CLONE_BRAIN_W_602EB0;
    else if (entry == V(0x5FCEB0)) id = NTW2_CLONE_BRAIN_W_5FCEB0;
    else { Record(p, slot, ReasonClass, kServiceRows - 1); return true; }
    c.hasTimer = c.timer != 0;
    B* const timerBase = p.timerBase + (c.timer & 15);
    if (c.hasTimer) {
        if (!p.regions.Readable(c.timer, kTimerBytes, p.counters.regionQueries) || !CopyLive(timerBase, c.timer, kTimerBytes)) {
            Record(p, slot, ReasonTimer, kServiceRows - 1); return true;
        }
        Digest(timerBase, kTimerBytes, slot.digestT);
    }
    // The worker copy keeps the native low address bits: native SSE code may rely on the object's alignment.
    B* const base = p.base + (entity & 15);
    B* const work = p.work + (entity & 15);
    B* const timerWork = p.timerWork + (c.timer & 15);
    c.work = Address(work); c.timerWork = Address(timerWork);
    memset(p.rebased, 0, sizeof(p.rebased)); p.rebasedTimer = 0;
    __try {
        CaptureLoop(c, reinterpret_cast<const B*>(static_cast<uintptr_t>(entity)), base, work, p.rebased, slot.digestA);
    } __except (EXCEPTION_EXECUTE_HANDLER) { Record(p, slot, ReasonLifetime, kServiceRows - 1); return true; }
    // The capture-time block checksums only serve guard-miss attribution; quiet mode counts misses without them.
    if (!g.quiet) BlockSums(base, a.blocks + static_cast<size_t>(ordinal) * kGuardBlocks);
    slot.timer = c.timer;
    if (c.hasTimer) for (U off = 0; off < kTimerBytes; off += 4) {
        const U v = Get(timerBase, off), r = Rebase(c, v);
        Put(timerWork, off, r);
        if (r != v) p.rebasedTimer |= 1u << (off / 4);
    }
    c.captured = Tsc();
    bool faulted = false;
    t_current = &c;
    if (g_gateTls) TlsSetValue(g_gateTlsIndex, &c);
    __try {
        __try {
            RunCloneGuarded(a, c, g.family.entries[id]);
            // Unconsumed event slots of a refused/finished occurrence are never read: eventCount is authoritative.
        } __except (Filter(c, GetExceptionInformation())) {
            faulted = c.reason == ReasonNone;
        }
    } __finally {
        t_current = nullptr; c.jumpArmed = false;
        if (g_gateTls) TlsSetValue(g_gateTlsIndex, nullptr);
    }
    p.counters.gates += c.fastGates;
    if (c.reason != ReasonNone || faulted) {
        InstallFp(a);
        if (faulted) { ++p.counters.faults; Record(p, slot, ReasonFault, kServiceRows - 1); _InterlockedExchange(&g_sticky, 1); return false; }
        Record(p, slot, static_cast<Reason>(c.reason), c.service);
        return true;
    }
    if (!FpInstalled(a)) { InstallFp(a); Record(p, slot, ReasonFpInstall, kServiceRows - 1); return true; }
    // More witness-dependent proofs than the record holds: the commit could not validate them all.
    if (c.deps->overflow) { ++p.counters.depOverflow; Record(p, slot, ReasonServiceUnresolved, kServiceRows - 1); return true; }
    const LONG at = _InterlockedExchangeAdd(&a.diffUsed, static_cast<LONG>(c.stageBytes));
    if (static_cast<U>(at) + c.stageBytes > a.diffCapacity) {
        _InterlockedExchange(&a.diffExhausted, 1);
        ++p.counters.capacity; Record(p, slot, ReasonSpanCapacity, kServiceRows - 1);
        return true;
    }
    memcpy(a.diff + at, p.stage, c.stageBytes);
    slot.spanOffset = static_cast<U>(at); slot.spanBytes = c.stageBytes; slot.spanCount = static_cast<uint16_t>(c.stageSpans);
    slot.eventCount = static_cast<B>(c.eventCount);
    slot.draws = c.draws;
    slot.state = SlotComputed;
    ++p.counters.computed;
    p.counters.diffBytes += c.stageBytes; p.counters.diffSpans += c.stageSpans;
    return true;
}
// RunSlotBody with its phase profile: capture until the clone starts (or the refusal before it), clone until it
// returns (or the refusal/fault inside it), publication for the rest.
bool RunSlot(Arena& a, Participant& p, U ordinal) {
    const ULONGLONG t0 = Tsc();
    const bool ok = RunSlotBody(a, p, ordinal);
    const ULONGLONG t = Tsc();
    const Current& c = p.current;
    Counters& k = p.counters;
    if (!c.captured) k.captureTicks += t - t0;
    else {
        k.captureTicks += c.captured - t0;
        if (c.cloned) { k.cloneTicks += c.cloned - c.captured; k.publishTicks += t - c.cloned; }
        else k.cloneTicks += t - c.captured;
    }
    return ok;
}

// Pool body: contiguous ordinal range; the participant is acquired once per thread per dispatch.
void __fastcall Chunk(void* context, U chunk) {
    Arena& a = *static_cast<Arena*>(context);
    if (g_sticky) return;
    if (t_epoch != a.epoch) {
        t_epoch = a.epoch; t_participant = nullptr;
        const LONG index = _InterlockedIncrement(&a.nextParticipant) - 1;
        if (static_cast<U>(index) < g.participants) {
            Participant* const q = g.participant[index];
            q->regions.Clear();
            // Native memory is frozen during the dispatch (workers write only private copies), so memoized read sets
            // and static gate verdicts stay valid for exactly this dispatch.
            ntw2_brain2::BumpWitnessMemo(q->memo);
            memset(q->gateCache, 0, sizeof(q->gateCache));
            t_participant = q;
        }
    }
    Participant* const p = t_participant;
    if (!p) { _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_words[ParticipantOverflow])); return; }
    const U begin = chunk * a.chunkSize, end = (a.count < begin + a.chunkSize) ? a.count : begin + a.chunkSize;
    const U savedCsr = _mm_getcsr();
    unsigned short savedCw;
    __asm fnstcw savedCw
    const ULONGLONG start = Tsc();
    ntw2_brain2::BindWitnessMemo(&p->memo);
    __try {
        // Full controls, not just rounding: FTZ, DAZ and x87 precision all participate in the native arithmetic.
        InstallFp(a);
        if (!FpInstalled(a)) {
            // Nothing ran: the whole range stays Unprocessed and the owner executes it at its ordinals.
            ++p->counters.reasons[ReasonFpInstall];
            for (U i = begin; i < end; ++i) {
                a.slots[i].entity = a.list[i]; a.slots[i].state = SlotUnprocessed; a.slots[i].stamp = a.stamp;
            }
        } else {
            if (begin < end) PrefetchFootprint(a.list[begin]);
            for (U i = begin; i < end; ++i) {
                if (g_sticky) break;
                if (!RunSlot(a, *p, i)) break;
            }
        }
    } __finally {
        ntw2_brain2::BindWitnessMemo(nullptr);
        __asm fnclex
        __asm fldcw savedCw
        _mm_setcsr(savedCsr);
    }
    const ULONGLONG ticks = Tsc() - start;
    p->counters.busyTicks += ticks;
    if (ticks > p->counters.maxChunkTicks) p->counters.maxChunkTicks = ticks;
}

// ---- owner commit ----
void ReplayEvent(const Event& e) {
    using T0 = void (__thiscall*)(U);
    using T1 = void (__thiscall*)(U, U);
    using T2 = void (__thiscall*)(U, U, U);
    using T3 = void (__thiscall*)(U, U, U, U);
    switch (e.kind) {
    case EventOrder: reinterpret_cast<T3>(static_cast<uintptr_t>(V(0x6631A0)))(e.receiver, e.arg[0], e.arg[1], e.arg[2]); break;
    case EventArrival: reinterpret_cast<T1>(static_cast<uintptr_t>(V(0x655B20)))(e.receiver, e.arg[0]); break;
    case EventRequest: {
        alignas(16) B descriptor[20], options[0x1c];
        memcpy(descriptor, e.payload, 20); memcpy(options, e.payload + 20, 0x1c);
        reinterpret_cast<T2>(static_cast<uintptr_t>(V(0x659520)))(e.receiver, Address(descriptor), Address(options));
        break;
    }
    default: reinterpret_cast<T1>(static_cast<uintptr_t>(e.target))(e.receiver, e.arg[0]); break;
    }
    (void)sizeof(T0);
}
// Owner, inside Commit's SEH scope: a soldier digest miss. Locate the first changed 16-byte block against the
// capture checksums and note whether the entity also sits at an earlier ordinal of the captured list. Quiet mode
// took no checksums and skips the O(ordinal) duplicate scan: the miss is counted only.
U g_prevOwner, g_prevOwnerService; // most recent owner-run soldier of this stage and its refusal service + 1
void AttributeSoldierMiss(const Arena& a, U ordinal, U entity) {
    ++g_words[GuardMissSoldier];
    // Writer candidate: the most recent owner-run soldier Y (only owner runs write other soldiers).
    if (const U y = g_prevOwner) {
        ++g_missService[g_prevOwnerService <= kServiceRows ? g_prevOwnerService : 0];
        if (y != entity && g_ownerRegions.Readable(y, kReceiverBytes, g_words[RegionQueries])) {
            if (D(y + 0x1EC) == entity) ++g_phase[PhaseMissPrevTarget];
            else if (D(y + 0x5B8) == entity) ++g_phase[PhaseMissPrevReference];
            else if (D(entity + 0x5B8) == y) ++g_phase[PhaseMissPrevFollower];
            else ++g_phase[PhaseMissPrevOther];
        } else ++g_phase[PhaseMissPrevOther];
    }
    if (g.quiet) return;
    B live[kGuardBlocks];
    BlockSums(reinterpret_cast<const B*>(static_cast<uintptr_t>(entity)), live);
    const B* captured = a.blocks + static_cast<size_t>(ordinal) * kGuardBlocks;
    U first = ~0u, changed = 0;
    for (U i = 0; i < kGuardBlocks; ++i) {
        if (live[i] == captured[i]) continue;
        if (first == ~0u) first = i;
        ++changed;
    }
    if (first == ~0u) ++g_words[GuardMissUnlocated];
    else ++g_guardFirst[first];
    g_words[GuardMissLastOffset] = first == ~0u ? ~0u : first * 16;
    g_words[GuardMissLastEntity] = entity; g_words[GuardMissLastBlocks] = changed;
    for (U k = 0; k < ordinal; ++k) if (a.list[k] == entity) { ++g_words[GuardMissDuplicate]; break; }
}
// The owner walk binds its world-only memo (BumpWitnessMemo after every native write but commits' footprint spans).
bool DepsHold(const ntw2_brain2::WitnessDeps& deps) {
    ntw2_brain2::BindWitnessMemo(&g_ownerMemo);
    bool held;
    __try { held = ntw2_brain2::WitnessDepsHold(deps); }
    __except (EXCEPTION_EXECUTE_HANDLER) { held = false; }
    ntw2_brain2::BindWitnessMemo(nullptr);
    return held;
}
// Crew dependency (header, phase row): soldiers a crew-node step of an owner-run soldier wrote this stage. Owner only;
// generation-stamped so a stage start is O(1). A full table stops marking (those soldiers are simply validated).
struct CrewSet {
    static constexpr U kSlots = 2048, kNodeVtable = 0x133AE34;
    U keys[kSlots], stamps[kSlots], generation, size;
    void Clear() { size = 0; if (++generation == 0) { memset(stamps, 0, sizeof(stamps)); generation = 1; } }
    bool Has(U soldier) const {
        if (!size) return false;
        for (U i = 0, s = (soldier >> 4) * 2654435761u >> 21; i < kSlots; ++i, s = (s + 1) & (kSlots - 1)) {
            if (stamps[s] != generation) return false;
            if (keys[s] == soldier) return true;
        }
        return false;
    }
    void Add(U soldier) {
        if (size >= kSlots / 2) return;
        for (U i = 0, s = (soldier >> 4) * 2654435761u >> 21; i < kSlots; ++i, s = (s + 1) & (kSlots - 1)) {
            if (stamps[s] != generation) { stamps[s] = generation; keys[s] = soldier; ++size; return; }
            if (keys[s] == soldier) return;
        }
    }
};
CrewSet g_crew;
// Before the owner runs soldier Y: does its inline node at Y+22C (vtable 0x133AE34, one-shot byte Y+2A4 unset) write
// the crew soldier [Y+28C] when stepped (GateClassify4: 6F46A0 -> 6C9070 / 6D0AE0 store S+6AC..+6EC)?
void NoteCrewWriter(U y) {
    if (!g_ownerRegions.Readable(y + 0x22C, 0x2A5 - 0x22C, g_words[RegionQueries])) return;
    if (D(y + 0x22C) != V(CrewSet::kNodeVtable) || Byte(y + 0x2A4) != 0) return;
    const U crew = D(y + 0x28C);
    if (crew && crew != y) { g_crew.Add(crew); ++g_phase[PhaseCrewMarks]; }
}
// True when the occurrence was published. False (nothing written) sends it to the owner-serial path.
inline B SlotState(const Arena& a, const Slot& slot) { return slot.stamp == a.stamp ? slot.state : B(SlotUnprocessed); }
bool Commit(Arena& a, U ordinal, U entity) {
    Slot& slot = a.slots[ordinal];
    const B state = SlotState(a, slot);
    if (state != SlotComputed) {
        if (state == SlotUnprocessed) ++g_words[Unprocessed];
        if (state == SlotSkipped) ++g_words[LateActivations];
        return false;
    }
    // A crew step of an earlier owner-run soldier wrote this soldier: quiet mode skips the validation it would fail.
    const bool crew = g_crew.Has(entity);
    if (crew && g.quiet) { ++g_phase[PhaseCrewRefusals]; return false; }
    ++g_phase[PhaseCommitAttempts];
    if (!g_ownerRegions.Readable(entity, kReceiverBytes, g_words[RegionQueries]) ||
        (slot.timer && !g_ownerRegions.Readable(slot.timer, kTimerBytes, g_words[RegionQueries]))) {
        ++g_words[GuardMisses]; ++g_words[GuardMissUnreadable]; return false;
    }
    U digest[4], timerDigest[4];
    __try {
        Digest(reinterpret_cast<const void*>(static_cast<uintptr_t>(entity)), kReceiverBytes, digest);
        if (!Same(digest, slot.digestA)) {
            ++g_words[GuardMisses]; AttributeSoldierMiss(a, ordinal, entity);
            if (crew) ++g_phase[PhaseCrewMarkedMisses];
            return false;
        }
        if (slot.timer) {
            Digest(reinterpret_cast<const void*>(static_cast<uintptr_t>(slot.timer)), kTimerBytes, timerDigest);
            if (!Same(timerDigest, slot.digestT)) { ++g_words[GuardMisses]; ++g_words[GuardMissTimer]; return false; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ++g_words[GuardMisses]; ++g_words[GuardMissUnreadable]; return false; }
    // Witness proofs this soldier consumed must still hold NOW, at its ordinal: an earlier owner-run soldier may
    // have changed a unit/slot/battle value after the stage snapshot. A miss is a stale result, not a broken proof.
    // The foreign read-set hashes re-read heap objects; a fault there is a miss, never a published result.
    const ntw2_brain2::WitnessDeps& deps = a.deps[ordinal];
    if (deps.count && !DepsHold(deps)) { ++g_words[WitnessDepMisses]; return false; }
    const B* s = a.diff + slot.spanOffset;
    const B* const end = s + slot.spanBytes;
    while (s < end) {
        SpanHeader h; memcpy(&h, s, sizeof(h)); s += sizeof(h);
        if (h.target == kBoundary) {
            const Event& e = a.events[slot.eventFirst + h.offset];
            ReplayEvent(e);
            ntw2_brain2::BumpWitnessMemo(g_ownerMemo);
            ++g_words[EventsReplayed + e.kind];
            continue;
        }
        B* const dst = reinterpret_cast<B*>(static_cast<uintptr_t>(h.target == TargetTimer ? slot.timer : entity)) + h.offset;
        memcpy(dst, s, h.length);
        s += h.length;
    }
    if (crew) ++g_phase[PhaseCrewMarkedCommits];
    return true;
}

// ---- RNG streams (owner) ----
constexpr DWORD kWritable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
bool WritableWord(U address) {
    MEMORY_BASIC_INFORMATION m;
    if (!address || address + 4 < address || !VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), &m, sizeof(m)))
        return false;
    const U end = static_cast<U>(reinterpret_cast<uintptr_t>(m.BaseAddress)) + static_cast<U>(m.RegionSize);
    return m.State == MEM_COMMIT && !(m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (m.Protect & kWritable) && address + 4 <= end;
}
// The model LCG word [[A+28]+8]+50 of the first ==1 brain-class soldier (the class check RunSlot and
// WitnessBegin apply), proven committed and writable; 0 when there is none. Owner thread, before the dispatch.
U StreamWord(const Arena& a) {
    for (U k = 0; k < a.count; ++k) {
        const U entity = a.list[k];
        if (!g_ownerRegions.Readable(entity, kActivationOffset + 1, g_words[RegionQueries]) || Byte(entity + kActivationOffset) != 1)
            continue;
        const U vtable = D(entity);
        if (!g_ownerRegions.Readable(vtable + 0xC, 4, g_words[RegionQueries])) continue;
        const U entry = D(vtable + 0xC);
        if (entry != V(0x66CE00) && entry != V(0x6F50F0) && entry != V(0x602EB0) && entry != V(0x5FCEB0)) continue;
        const U root = D(entity + 0x28);
        if (!g_ownerRegions.Readable(root + 8, 4, g_words[RegionQueries])) return 0;
        const U model = D(root + 8);
        return model && WritableWord(model + 0x50) ? model + 0x50 : 0;
    }
    return 0;
}
// Steps the bound word took during one owner-run occurrence that started from `seed`.
void CountOwnerDraws(U seed, U now) {
    U x = seed;
    for (U n = 0; n <= kOwnerDrawScan; ++n) {
        if (x == now) { g_words[RngOwnerDraws] += n; return; }
        x = x * 0x343FDu + 0x269EC3u;
    }
    ++g_words[RngOwnerUnmatched];
}

bool EnsureArena(U count) {
    Arena& a = g.arena;
    if (count <= a.capacity && a.slots) return true;
    U capacity = (count + (count >> 2) + 255u) & ~255u;
    const ULONGLONG slots = static_cast<ULONGLONG>(capacity) * sizeof(Slot), list = static_cast<ULONGLONG>(capacity) * 4;
    const U diff = capacity * kDiffBytesPerEntity > kMinDiffPool ? capacity * kDiffBytesPerEntity : kMinDiffPool;
    const ULONGLONG events = static_cast<ULONGLONG>(kMaxEvents) * sizeof(Event);
    const ULONGLONG deps = static_cast<ULONGLONG>(capacity) * sizeof(ntw2_brain2::WitnessDeps);
    // Guard-miss block checksums exist only outside quiet mode.
    const ULONGLONG blocks = g.quiet ? 0 : static_cast<ULONGLONG>(capacity) * kGuardBlocks;
    const ULONGLONG total = slots + list + diff + events + deps + blocks;
    B* block = static_cast<B*>(VirtualAlloc(nullptr, static_cast<SIZE_T>(total), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!block) return false;
    if (a.slots) VirtualFree(a.slots, 0, MEM_RELEASE);
    a.slots = reinterpret_cast<Slot*>(block);
    a.list = reinterpret_cast<U*>(block + slots);
    a.diff = block + slots + list;
    a.events = reinterpret_cast<Event*>(block + slots + list + diff);
    a.deps = reinterpret_cast<ntw2_brain2::WitnessDeps*>(block + slots + list + diff + events);
    a.blocks = g.quiet ? nullptr : block + slots + list + diff + events + deps;
    a.stamp = 0; // fresh (zeroed) slots: the next stage starts the stamp cycle again
    a.capacity = capacity; a.diffCapacity = diff; a.bytes = total;
    return true;
}
void FreeArena() {
    Arena& a = g.arena;
    if (a.slots) VirtualFree(a.slots, 0, MEM_RELEASE);
    a.slots = nullptr; a.list = nullptr; a.diff = nullptr; a.events = nullptr; a.deps = nullptr; a.blocks = nullptr;
    a.capacity = a.diffCapacity = 0; a.bytes = 0;
}
bool HasAes() {
    int info[4]; __cpuid(info, 1);
    return (info[2] & (1 << 25)) != 0 && (info[3] & (1 << 26)) != 0;
}
} // namespace

bool Start(const Binding& b) {
    Stop();
    if (!b.image_base || !b.clones || !b.bindings || !HasAes()) return false;
    for (U id = NTW2_CLONE_BRAIN_W; id <= NTW2_CLONE_BRAIN_W_UNLINK; ++id) if (!b.clones->entries[id]) return false;
    U bindings[NTW2_BIND_COUNT];
    memcpy(bindings, b.bindings, sizeof(bindings));
    bindings[NTW2_BIND_B2_SERVICE_GATE] = Address(reinterpret_cast<const void*>(&WorkerServiceGate));
    bindings[NTW2_BIND_B2_OBSERVE] = Address(reinterpret_cast<const void*>(&WorkerObserveGate));
    g = Config{};
    g.delta = b.image_base - 0x400000;
    if (ntw2_build_brain_worker_family(b.clones, b.image_base, bindings, &g.family)) { g = Config{}; return false; }
    g.stubs[EventOrder] = Address(reinterpret_cast<const void*>(&OrderStub));
    g.stubs[EventArrival] = Address(reinterpret_cast<const void*>(&ArrivalStub));
    g.stubs[EventRequest] = Address(reinterpret_cast<const void*>(&RequestStub));
    g.stubs[EventCharge] = Address(reinterpret_cast<const void*>(&ChargeStub));
    g.workers = b.workers; g.minEntities = b.min_entities; g.deferMask = b.defer_events & ((1u << kEventKinds) - 1);
    g.quiet = b.quiet;
    g.participants = (b.workers + 1 < kMaxParticipants) ? b.workers + 1 : kMaxParticipants;
    if (!b.dispatch) g.participants = 1;
    for (U i = 0; i < g.participants; ++i) {
        void* memory = _aligned_malloc(sizeof(Participant), 64);
        if (!memory) { Stop(); return false; }
        g.participant[i] = new (memory) Participant;
        memset(g.participant[i], 0, sizeof(Participant));
        ntw2_brain2::WitnessMemo& memo = g.participant[i]->memo;
        memo.privateLo = Address(g.participant[i]); memo.privateHi = memo.privateLo + sizeof(Participant);
    }
    memset(&g_ownerMemo, 0, sizeof(g_ownerMemo));
    g_ownerMemo.worldOnly = 1;
    // WorkerServiceGate's fast path addresses the TEB TlsSlots entry directly (index < 64 only).
    g_gateTlsIndex = TlsAlloc();
    g_gateTls = g_gateTlsIndex < 64 ? 0xE10 + 4 * g_gateTlsIndex : 0;
    g_dispatch = b.dispatch; g_pool = b.pool;
    g.started = true;
    g_sticky = 0;
    g_rngGeneration = 0;
    memset(g_words, 0, sizeof(g_words)); memset(g_guardFirst, 0, sizeof(g_guardFirst));
    memset(g_phase, 0, sizeof(g_phase)); memset(g_missService, 0, sizeof(g_missService));
    return true;
}

void Stop() {
    ntw2_brain2::SetWorkerRandomStream(0);
    g_gateTls = 0;
    if (g_gateTlsIndex != TLS_OUT_OF_INDEXES) { TlsFree(g_gateTlsIndex); g_gateTlsIndex = TLS_OUT_OF_INDEXES; }
    for (Participant*& p : g.participant) {
        if (!p) continue;
        p->~Participant(); _aligned_free(p); p = nullptr;
    }
    FreeArena();
    if (g.family.allocation) VirtualFree(g.family.allocation, 0, MEM_RELEASE);
    g = Config{};
    g_dispatch = nullptr; g_pool = 0;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words)); memset(g_guardFirst, 0, sizeof(g_guardFirst));
    memset(g_phase, 0, sizeof(g_phase)); memset(g_missService, 0, sizeof(g_missService));
    g_sticky = 0;
    g_rngGeneration = 0; // per battle activation: stream generations restart with the battle
}
U StreamSeed(U stageState, U generation, U ordinal) {
    uint64_t z = (static_cast<uint64_t>(stageState) << 32 | generation) +
                 static_cast<uint64_t>(ordinal + 1) * 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    return static_cast<U>(z) ^ static_cast<U>(z >> 32);
}
U LcgAdvance(U state, U steps) {
    U mul = 1, add = 0, a = 0x343FDu, c = 0x269EC3u;
    for (; steps; steps >>= 1) {
        if (steps & 1) { mul *= a; add = add * a + c; }
        c *= a + 1; a *= a;
    }
    return mul * state + add;
}
bool Started() { return g.started; }
const char* ReasonName(U reason) {
    static const char* const names[kReasonCount] = { NTW2_BRAIN_WORKER_REASON_LABELS };
    return reason < kReasonCount ? names[reason] : "invalid";
}
#ifdef NTW2_BRAIN_WORKERS_ORACLE
void SetFaultInjector(FaultInjector injector) { g_injector = injector; }
void SetComputeOnly(bool value) { g_computeOnly = value; }
#endif

bool RunWorklist(U manager, const U* cloneEntries) {
    if (!g.started || g_sticky || !cloneEntries) return false;
    Arena& a = g.arena;
    const U count = D(manager + 0x260);
    if (!count || count < g.minEntities || !EnsureArena(count)) { ++g_words[Handoffs]; return false; }
    const U first = D(manager + 0x264);
    const LONGLONG captureStart = Now();
    const ULONGLONG tscStart = Tsc();
    const U probeQueries0 = ntw2_brain2::WitnessProbeQueries(), regionQueries0 = g_words[RegionQueries];
    if (!CopyLive(a.list, first, count * 4)) { ++g_words[Handoffs]; return false; }
    // From here this function owns the whole loop, including the Stage-1 bookkeeping RunWorklist would do.
    ntw2_brain2::WitnessBegin(manager);
    const LONGLONG witnessBegun = Now();
    ntw2_brain2::BeginDispatch();
    // Slots are stamped instead of cleared (Slot); the array is zeroed only when the stamp cycle wraps.
    a.stamp = static_cast<B>(a.stamp % 255 + 1);
    if (a.stamp == 1) memset(a.slots, 0, static_cast<size_t>(a.capacity) * sizeof(Slot));
    a.count = count;
    a.mxcsr = _mm_getcsr();
    unsigned short cw;
    __asm fnstcw cw
    a.cw = cw;
    U size = count / (g.participants * 16);
    size = (size + 7) & ~7u;
    size = size < kChunkMin ? kChunkMin : size > kChunkMax ? kChunkMax : size;
    a.chunkSize = size; a.chunks = (count + size - 1) / size;
    a.diffUsed = 0; a.eventUsed = 0; a.nextParticipant = 0; a.diffExhausted = 0;
    a.epoch = _InterlockedIncrement(&g_epochCounter);
    if (!a.epoch) a.epoch = _InterlockedIncrement(&g_epochCounter);
    for (U i = 0; i < g.participants; ++i) { memset(&g.participant[i]->counters, 0, sizeof(Counters)); }
    g_ownerRegions.Clear();
    ntw2_brain2::BumpWitnessMemo(g_ownerMemo);
    // RNG stream binding (header "RNG streams"). Event deferral replays services at checkpoints the worker
    // stream does not model, so a deferring configuration keeps 5FC070 refused.
    a.rngLcg = g.deferMask ? 0 : StreamWord(a);
    a.rngState = a.rngLcg ? D(a.rngLcg) : 0;
    a.rngGeneration = a.rngLcg ? ++g_rngGeneration : 0;
    ntw2_brain2::SetWorkerRandomStream(a.rngLcg);
    const LONGLONG dispatchStart = Now();
    if (g_dispatch) g_dispatch(g_pool, Address(reinterpret_cast<const void*>(&Chunk)), a.chunks, &a);
    else for (U i = 0; i < a.chunks; ++i) Chunk(&a, i);
    const LONGLONG dispatchEnd = Now();
    ++g_words[Dispatches]; g_words[Chunks] += a.chunks;
    if (size > g_words[MaxChunkEntities]) g_words[MaxChunkEntities] = size;
    U stageSpeculated = 0, workerQueries = 0;
    ULONGLONG captureTicks = 0, cloneTicks = 0, publishTicks = 0, busyTicks = 0, criticalTicks = 0, maxChunkTicks = 0;
    for (U i = 0; i < g.participants; ++i) {
        const Counters& k = g.participant[i]->counters;
        g_words[Speculated] += k.speculated; g_words[WorkerComputed] += k.computed; g_words[WorkerRefused] += k.refused;
        g_words[CapacityRefusals] += k.capacity; g_words[Faults] += k.faults; g_words[RegionQueries] += k.regionQueries;
        g_words[WitnessDepOverflow] += k.depOverflow;
        g_words[DiffBytes] += k.diffBytes; g_words[DiffSpans] += k.diffSpans;
        stageSpeculated += k.speculated; workerQueries += k.regionQueries; g_phase[PhaseWorkerGates] += k.gates;
        captureTicks += k.captureTicks; cloneTicks += k.cloneTicks; publishTicks += k.publishTicks; busyTicks += k.busyTicks;
        if (k.busyTicks > criticalTicks) criticalTicks = k.busyTicks;
        if (k.maxChunkTicks > maxChunkTicks) maxChunkTicks = k.maxChunkTicks;
        for (U e = 0; e < kEventKinds; ++e) g_words[EventsRecorded + e] += k.events[e];
        for (U r = 0; r < kReasonCount; ++r) g_words[ReasonCounts + r] += k.reasons[r];
        for (U s = 0; s < kServiceRows; ++s) g_words[ServiceRefusals + s] += k.services[s];
        if (k.lastReason) {
            g_words[LastRefuseServicePlus1] = k.lastService; g_words[LastRefuseEntity] = k.lastEntity;
            g_words[LastRefuseReason] = k.lastReason;
        }
    }
    // Workers draw only from private words, so the bound word must still hold S. A change means a forwarded original
    // advanced it from a pool thread (a classification hole in WorkerForwardable). Nothing is published yet: every
    // worker result is dropped (the owner reruns each ordinal from its seed) and the feature disables stickily.
    if (a.rngLcg && D(a.rngLcg) != a.rngState) {
        for (U k = 0; k < count; ++k) if (SlotState(a, a.slots[k]) == SlotComputed) a.slots[k].state = SlotRefused;
        _InterlockedExchange(&g_sticky, 1);
        g_words[LastFaultCode] = kLcgRaced; g_words[LastFaultAddress] = a.rngLcg;
    }
#ifdef NTW2_BRAIN_WORKERS_ORACLE
    // Proof hook: stop after the worker phase so a test can show no native byte changed before the owner commits.
    if (g_computeOnly) { ntw2_brain2::SetWorkerRandomStream(0); ntw2_brain2::WitnessAbort(); return true; }
#endif
    ntw2_brain2::SetWorkerRandomStream(0);
    const LONGLONG replayStart = Now();
    volatile U* const lcg = reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a.rngLcg));
    U walked = 0, walkedSpeculated = 0;
    g_prevOwner = g_prevOwnerService = 0;
    g_crew.Clear();
    // Owner walk profile: RDTSC only where the walk switches between commit and owner-run ordinals.
    enum : U { SegmentCommit, SegmentOwner };
    ULONGLONG segmentTicks[2] = {}, segmentStart = Tsc();
    U segment = SegmentCommit;
    constexpr U kCommitPrefetch = 4;
    // The native loop, verbatim: live cursor, ==1 filter, end reloaded from live data/count after EVERY entry.
    U cursor = D(manager + 0x264);
    const U origin = cursor;
    U end = cursor + 4 * D(manager + 0x260);
    while (cursor != end) {
        const U entity = D(cursor);
        if (Byte(entity + kActivationOffset) == 1) {
            ++g_words[Occurrences]; ++walked;
            const U k = (cursor - origin) >> 2;
            const bool speculative = k < count && a.list[k] == entity;
            const B state = speculative ? SlotState(a, a.slots[k]) : B(SlotUnprocessed);
            if (state == SlotComputed || state == SlotRefused) ++walkedSpeculated;
            // The commit digest reads the whole live footprint: request a later computed ordinal's lines now.
            if (k + kCommitPrefetch < count) {
                const Slot& ahead = a.slots[k + kCommitPrefetch];
                if (SlotState(a, ahead) == SlotComputed) {
                    PrefetchFootprint(ahead.entity);
                    if (ahead.timer) _mm_prefetch(reinterpret_cast<const char*>(static_cast<uintptr_t>(ahead.timer)), _MM_HINT_T0);
                }
            }
            const U kind = state == SlotComputed ? SegmentCommit : SegmentOwner;
            if (kind != segment) {
                const ULONGLONG t = Tsc();
                segmentTicks[segment] += t - segmentStart; segmentStart = t; segment = kind;
            }
            if (speculative && Commit(a, k, entity)) { ++g_words[Committed]; g_words[RngWorkerDraws] += a.slots[k].draws; }
            else {
                if (!speculative) ++g_words[Desyncs];
                ++g_words[OwnerRan];
                // Owner-run ordinal k draws the real word from the seed its worker run would have used.
                const U seed = lcg ? StreamSeed(a.rngState, a.rngGeneration, k) : 0;
                if (lcg) *lcg = seed;
                NoteCrewWriter(entity);
                ntw2_brain2::RunOccurrence(entity, cloneEntries);
                ntw2_brain2::BumpWitnessMemo(g_ownerMemo);
                if (lcg) CountOwnerDraws(seed, *lcg);
                g_prevOwner = entity;
                g_prevOwnerService = state == SlotRefused ? a.slots[k].service + 1u : 0u;
            }
        } else ++g_words[Skipped];
        cursor += 4;
        end = D(manager + 0x264) + 4 * D(manager + 0x260);
    }
    segmentTicks[segment] += Tsc() - segmentStart;
    // Deterministic stage-end advance: one LCG step per walked occurrence, independent of which ordinals
    // committed, so the post-stage sequence never depends on thread timing.
    if (lcg) { *lcg = LcgAdvance(a.rngState, walked); g_words[RngLcgAdvance] += walked; }
    // Speculated ordinals the walk never reached as ==1: deactivated by an earlier occurrence, or cut off by a
    // shrinking list. They explain speculated > occurrences; they are not executions.
    g_words[SpeculatedUnwalked] += stageSpeculated - walkedSpeculated;
    const LONGLONG walkEnd = Now();
    // Every commit validated its own witness dependencies at its ordinal, so a changed value here never means a
    // published stale result; it is telemetry for the static-during-site-6 claims, not a reason to disable.
    g_words[WitnessViolations] += ntw2_brain2::WitnessEnd();
    const LONGLONG replayEnd = Now();
    const ULONGLONG tscEnd = Tsc();
    const U captureUs = Microseconds(dispatchStart - captureStart), dispatchUs = Microseconds(dispatchEnd - dispatchStart);
    const U replayUs = Microseconds(replayEnd - replayStart), totalUs = Microseconds(replayEnd - captureStart);
    g_words[CaptureUs] += captureUs;
    g_words[DispatchUs] += dispatchUs;
    g_words[ReplayUs] += replayUs;
    // RDTSC sub-phases, converted with this stage's own calibration.
    const TscScale us = {tscEnd - tscStart, totalUs};
    const U commitUs = us(segmentTicks[SegmentCommit]), ownerUs = us(segmentTicks[SegmentOwner]);
    const U witnessEndUs = Microseconds(replayEnd - walkEnd);
    g_words[ChunkTimeSumUs] += us(busyTicks);
    if (us(maxChunkTicks) > g_words[MaxChunkUs]) g_words[MaxChunkUs] = us(maxChunkTicks);
    ++g_phase[PhaseStages];
    g_phase[PhaseCaptureUs] += captureUs;
    g_phase[PhaseWitnessBeginUs] += Microseconds(witnessBegun - captureStart);
    g_phase[PhaseDispatchUs] += dispatchUs;
    g_phase[PhaseCommitUs] += commitUs;
    g_phase[PhaseOwnerRunUs] += ownerUs;
    g_phase[PhaseWalkOtherUs] += replayUs > commitUs + ownerUs + witnessEndUs ? replayUs - commitUs - ownerUs - witnessEndUs : 0;
    g_phase[PhaseWitnessEndUs] += witnessEndUs;
    g_phase[PhaseWorkerCaptureUs] += us(captureTicks);
    g_phase[PhaseWorkerCloneUs] += us(cloneTicks);
    g_phase[PhaseWorkerPublishUs] += us(publishTicks);
    g_phase[PhaseWorkerBusyUs] += us(busyTicks);
    g_phase[PhaseWorkerCriticalUs] += us(criticalTicks);
    g_phase[PhaseWitnessRegionQueries] += ntw2_brain2::WitnessProbeQueries() - probeQueries0;
    g_phase[PhaseWorkerRegionQueries] += workerQueries;
    g_phase[PhaseOwnerRegionQueries] += g_words[RegionQueries] - regionQueries0 - workerQueries;
    g_phase[PhaseLastCaptureUs] = captureUs; g_phase[PhaseLastDispatchUs] = dispatchUs;
    g_phase[PhaseLastCommitUs] = commitUs; g_phase[PhaseLastOwnerRunUs] = ownerUs;
    g_phase[PhaseLastOccurrences] = walked; g_phase[PhaseLastTotalUs] = totalUs;
    if (totalUs) g_phase[PhaseTscKhz] = static_cast<U>((tscEnd - tscStart) * 1000 / totalUs);
    if (g_sticky) g_words[Sticky] = 1;
    return true;
}
void Snapshot(U* words) {
    memcpy(words, g_words, sizeof(g_words));
    words[Version] = kVersion; words[Enabled] = g.started;
    words[Participants] = g.participants; words[Workers] = g.workers;
    words[Sticky] = g_sticky != 0;
    words[ReceiverBytes] = kReceiverBytes;
    ULONGLONG storage = g.arena.bytes;
    for (U i = 0; i < g.participants; ++i) storage += sizeof(Participant);
    words[StorageBytes] = storage > UINT32_MAX ? UINT32_MAX : static_cast<U>(storage);
    words[SharePermille] = g_words[Occurrences] ? static_cast<U>(static_cast<ULONGLONG>(g_words[Committed]) * 1000 / g_words[Occurrences]) : 0;
    // Most frequent first-changed block offsets of soldier guard misses (count desc, offset asc; zero-filled).
    bool taken[kGuardBlocks] = {};
    for (U t = 0; t < kGuardTop; ++t) {
        U best = ~0u;
        for (U i = 0; i < kGuardBlocks; ++i)
            if (!taken[i] && g_guardFirst[i] && (best == ~0u || g_guardFirst[i] > g_guardFirst[best])) best = i;
        words[GuardMissTop + 2 * t] = best == ~0u ? 0 : best * 16;
        words[GuardMissTop + 2 * t + 1] = best == ~0u ? 0 : g_guardFirst[best];
        if (best != ~0u) taken[best] = true;
    }
}
void PhaseSnapshot(U* words) {
    memcpy(words, g_phase, sizeof(g_phase));
    words[PhaseVersion] = kPhaseVersion; words[PhaseQuiet] = g.started && g.quiet;
    U best = 0;
    for (U i = 1; i <= kServiceRows; ++i) if (g_missService[i] > g_missService[best]) best = i;
    words[PhaseMissPrevServiceTop] = g_missService[best] ? best : 0;
    words[PhaseMissPrevServiceCount] = g_missService[best];
}
} // namespace ntw2_brain_workers
