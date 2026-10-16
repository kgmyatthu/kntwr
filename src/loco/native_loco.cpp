#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <malloc.h>
#include <stdlib.h>
#include <algorithm>
#include <new>
#include <vector>
#include <array>
#include <utility>
#include "../ntw2_clones.h"
#include "native_loco.h"
#include "native_sweep.h"
#include "native_resolve.h"
#include "native_env.h"

static_assert(sizeof(void*) == 4, "native locomotion is a Win32 x86 adapter");

namespace ntw2_loco {
namespace {
using U = uint32_t;
using TC0 = void (__thiscall*)(void*);
using Free = void (__cdecl*)(void*);
U g_delta;
Binding g_binding;
U g_words[WordCount];
U g_gateWords[GateWordCount];
U g_generation;
bool g_started;
bool g_stage;
U g_runDepth;
LARGE_INTEGER g_frequency;
// 14543B4 has a polymorphic 20-byte vector header. The other two objects are
// zero-constructed 16-byte headers, NOT embedded backing arrays. 801140 owns
// their growth via 444B40/FF7EF0. See the pinned cold tails/destructor sources.
alignas(16) U g_scratchFirst[5];
alignas(16) U g_scratchSecond[4];
alignas(16) U g_scratchThird[4];
U g_guards[3];
U g_serviceTargets[ServiceCount];
constexpr U kTraceCapacity = 256;
ServiceRecord g_trace[kTraceCapacity];
U g_traceCount;
U g_entityServices;
constexpr U kServiceFrames = 64;
struct ServiceFrame { U returnAddress, service; LARGE_INTEGER start; };
ServiceFrame g_serviceFrames[kServiceFrames];
U g_serviceDepth;
bool g_timingEnabled;
bool g_shadowEnabled;
uint8_t g_originalInout;
U g_timingWords[ServiceWordCount];
struct TimingTotals {
    unsigned long long cloneWall, serviceUnion;
    unsigned long long service[ServiceCount], maximum[ServiceCount];
} g_timingTotals;
volatile LONG g_timingSequence; // owner writes; monitor snapshots must not tear 64-bit QPC totals

// Sanity ceilings for ActivateOwned arguments ONLY: nothing is reserved at these sizes. Every real buffer is
// derived from the activation Capacity (movement slots from capacity.primary, grid from records/cells/memberships)
// and from the actual workers+caller count.
constexpr U kMaxRecords = 131072, kMaxCells = 1048576, kMaxMembers = 2097152;
constexpr U kParallelRun = 256, kParallelChunks = 32, kPrivateBytes = 0x1DC;
// Owned-grid build geometry. The native cell id is (z << shift) + x, so z rows are contiguous cell ranges. The z rows
// are split into at most kGridStrips equal strips; a strip is the unit of ownership of both the per-chunk membership
// accounting (dispatch 1) and the cell scan/scatter (dispatch 2). Cells carry bit 31 while they hold a build tally.
constexpr U kGridStrips = 64, kGridMaxTasks = 2 * kParallelChunks, kGridTag = 0x80000000u, kNoSlot = ~0u;
U g_gridWords[GridWordCount], g_gridV2Words[GridV2WordCount], g_parallelWords[ParallelWordCount];
// Cross-epoch identity (the only per-record state the NEXT capture reads from the previous one). Double buffered
// and flipped; everything else in the published view is single-buffered and rewritten in place, because a view
// is invalid from Stage entry / CaptureGrid entry onward.
struct GridIdentity {
    U count, occupied, memberships, epoch;
    U *record, *serial, *incarnation, *active, *inserted, *hash;
};
struct alignas(64) GridChunkStat {
    U committed, fromRecord, births, reused, deactivations, removals;
    U birthBase, removed;
};
struct GridStore {
    ntw2_workload::Capacity cap;
    U chunks, hashSize, rowCap, slotMask;
    unsigned char* base;
    size_t bytes, allocBytes;
    GridIdentity id[2];
    U *team, *flags, *nodeType, *left, *right, *top, *bottom;
    float *x, *z, *y, *extent, *radius;
    // dense: published cell -> row+1; during a build the same words hold the bit-31 tagged membership tally.
    // fill: per-row scatter cursor. stripMembers/stripRows: chunk-major [chunks][kGridStrips] build accounting.
    U *committed, *dense, *cellIds, *offsets, *occupants, *fill, *stripMembers, *stripRows;
    GridChunkStat* stats;
};
GridStore g_gridStore;
GridStore* g_grid; // null until ActivateOwned allocates the block
U g_gridModel;
U g_gridCurrent, g_incarnation, g_storageBytes;
// Dense-map invariant: every word outside a live strip is zero. Dirty = a build started and never completed, so
// the map may hold residual tallies anywhere and the next build clears all of it before counting.
bool g_gridDenseDirty;
bool g_gridStripLive[kGridStrips];
U g_gridLiveStripHeight, g_gridLiveShift; // geometry the live strips were published under
U g_storageWords[StorageWordCount]; // cached allocation breakdown; first eight words sum to g_storageBytes
U g_catalogStorage[CatalogStorageWordCount]; // cached catalog geometry breakdown; first five sum to StorageCatalog
static_assert(CatalogStorageWordCount == ntw2_resolve::CatalogStorageWordCount, "catalog breakdown width");
bool g_gridValid, g_gridCommittedReady;
GridView g_gridView;
struct PublicationEvent { U entity, which, receiver; }; // all four native link services are thiscall/no stack args
struct WorkerOccurrence {
    U entity, serial, ordinal, state, eventCount, queryCount;
    bool wrapper;
    alignas(16) unsigned char input[kPrivateBytes], output[kPrivateBytes];
    PublicationEvent events[4];
};
struct WorkerArena { WorkerOccurrence occurrences[kParallelRun]; };
WorkerArena* g_workers;
__declspec(thread) WorkerOccurrence* g_workerOccurrence;
U g_parallelInFlight;

constexpr U kOwnedBytes = 0x680, kOwnedPrefix = 0x200, kNoOccurrence = ~0u;
constexpr U kOwnedChunkMin = 32, kOwnedChunkMax = 256, kOwnedHistogram = 8;
constexpr U kOwnedClasses = 13, kOwnedVirtualWords = 0xF4 / 4;
constexpr DWORD kOwnedUnsupported = 0xE042B201;
enum OwnedState : unsigned char { OwnedUnprocessed, OwnedComputed, OwnedRefused, OwnedSkipped, OwnedCommitted };
template <class T> inline T Raw(const unsigned char* p) { T v; memcpy(&v, p, sizeof(v)); return v; }
// Compact movement slot, one per worklist ordinal. The private receiver still gets the full 0x200 prefix, but
// the slot retains only the audited footprint of the closed mover closure (all offsets are native receiver offsets):
//  * GUARD = every receiver byte the closure can read before writing it (live-in): MOVE 7F08F0 and WRAP 7F0260
//    operands, vf+74 (64C780 -> +1D8), 80DBF0 (+44), 80E9D0 (+160..+16B,+170), 814AA0 (+110,+116), the resolve/
//    sweep/env port views (+10,+18,+48..+5C,+60,+64,+D4..+DC,+110,+117,+13C,+174..+176,+188,+199,+1A8,+1F0,+B4..+B6),
//    the class predicate slots (+0 vptr, +67C handled separately) and the admission reads of OwnedReason (+0,+10,+18,
//    +28,+2C,+30,+A1,+A8,+B0,+B4,+B5,+EC,+170,+628). Compared again against the live receiver at commit.
//    +4 is guarded only for an admitted 54E920 receiver predicate; other links, +98, +AC and +5ED are owned/overwritten
//    by native service replay or latch rollover, not movement inputs.
//  * OUTPUT = every receiver dword the closure can write. A written dword is either guarded (so writing back an
//    unchanged value is exact) or rewritten on every committed path (ALWAYS_WRITTEN: +54,+B8,+BC,+C8,+CC).
//    The wrapper-only dwords (+14C,+150,+190,+1A4) are written by WRAP on every path and by MOVE never, so
//    they are stored in their own group and committed only for wrapper slots.
//  * Other padding and unread fields are untouched; the separately handled latch at +5EC and predicate at +67C
//    are described below. The +1D8 receiver is included despite lying beyond the bulk movement fields.
#ifdef NTW2_LOCO_ORACLE
using Span = OwnedSpanForTest;
#else
struct Span { U offset, bytes; };
#endif
constexpr Span kGuardSpans[] = {
    {0x000, 4}, {0x010, 4}, {0x018, 4}, {0x028, 20}, {0x040, 8}, {0x048, 12}, {0x058, 64}, {0x0A0, 12},
    {0x0B0, 8}, {0x0C0, 8}, {0x0D0, 36}, {0x110, 8}, {0x12C, 4}, {0x13C, 4}, {0x160, 12}, {0x170, 8},
    {0x188, 8}, {0x194, 8}, {0x1A8, 4}, {0x1D8, 4}, {0x1F0, 4}, {0x628, 4}
};
constexpr Span kOutputSpans[] = {
    {0x010, 4}, {0x038, 4}, {0x040, 4}, {0x048, 16}, {0x064, 4}, {0x070, 40}, {0x0A0, 4}, {0x0B4, 56},
    {0x0F0, 4}, {0x13C, 4}, {0x174, 4}, {0x18C, 4}, {0x194, 8}, {0x1A8, 4}
};
constexpr Span kWrapperSpans[] = {{0x14C, 8}, {0x190, 4}, {0x1A4, 4}};
constexpr U kAlwaysWritten[] = {0x54, 0xB8, 0xBC, 0xC8, 0xCC};
constexpr size_t kGuardSpanCount = sizeof(kGuardSpans) / sizeof(Span), kOutputSpanCount = sizeof(kOutputSpans) / sizeof(Span),
                 kWrapperSpanCount = sizeof(kWrapperSpans) / sizeof(Span), kAlwaysWrittenCount = sizeof(kAlwaysWritten) / sizeof(U);
template <size_t N> constexpr U SpanTotal(const Span (&spans)[N]) { U total = 0; for (const Span& s : spans) total += s.bytes; return total; }
template <size_t N> constexpr std::array<U, N> SpanStarts(const Span (&spans)[N]) {
    std::array<U, N> starts{}; U total = 0;
    for (size_t i = 0; i < N; ++i) { starts[i] = total; total += spans[i].bytes; }
    return starts;
}
// Packed byte position of a receiver offset inside one span table; ~0u when the table does not cover it.
template <size_t N> constexpr U PackedOffset(const Span (&spans)[N], U offset) {
    U packed = 0;
    for (const Span& s : spans) { if (offset >= s.offset && offset < s.offset + s.bytes) return packed + offset - s.offset; packed += s.bytes; }
    return ~0u;
}
constexpr U kGuardBytes = SpanTotal(kGuardSpans), kOutputBytes = SpanTotal(kOutputSpans), kWrapperBytes = SpanTotal(kWrapperSpans);
constexpr auto kGuardStart = SpanStarts(kGuardSpans);
constexpr auto kOutputStart = SpanStarts(kOutputSpans);
constexpr auto kWrapperStart = SpanStarts(kWrapperSpans);
// Spans ascend, are disjoint, dword aligned and stay below `limit`; only the final guard span (+628) lies past the copied prefix.
template <size_t N> constexpr bool SpansOrdered(const Span (&spans)[N], U lastLimit, bool lastBeyondPrefix) {
    U end = 0;
    for (size_t i = 0; i < N; ++i) {
        const Span& s = spans[i];
        if (!s.bytes || ((s.offset | s.bytes) & 3) || s.offset < end) return false;
        end = s.offset + s.bytes;
        if (end > (i + 1 == N && lastBeyondPrefix ? lastLimit : kOwnedPrefix)) return false;
    }
    return true;
}
template <size_t N> constexpr bool SpansCover(const Span (&spans)[N], U offset) { return PackedOffset(spans, offset) != ~0u; }
constexpr bool OutputsProtected() {
    for (const Span& s : kOutputSpans) for (U at = s.offset; at < s.offset + s.bytes; at += 4) {
        bool always = false;
        for (U w : kAlwaysWritten) always |= w == at;
        if (!SpansCover(kGuardSpans, at) && !always) return false;
    }
    return true;
}
constexpr bool WrapperGroupsDisjoint() {
    for (const Span& w : kWrapperSpans) for (U at = w.offset; at < w.offset + w.bytes; at += 4)
        if (SpansCover(kOutputSpans, at)) return false;
    return true;
}
static_assert(SpansOrdered(kGuardSpans, 0x62C, true) && SpansOrdered(kOutputSpans, 0, false) && SpansOrdered(kWrapperSpans, 0, false),
              "movement footprint spans are ordered, dword aligned and inside the copied prefix");
static_assert(OutputsProtected(), "every committed dword is guarded or rewritten on every committed path");
static_assert(WrapperGroupsDisjoint(), "wrapper-only outputs never overlap the common outputs");
struct OwnedSlot {
    U entity, services, inputPredicate;
    unsigned char reason, detail, serviceCount, active, wrapper, readsPredicate, inputLatch, resultLatches[2], readsLinkByte, inputLinkByte, spare;
    unsigned char guard[kGuardBytes];
    unsigned char output[kOutputBytes + kWrapperBytes];
};
template <size_t N, class F> __forceinline void EachSpanOf(F&& fn) {
    [&]<size_t... I>(std::index_sequence<I...>) { (fn(std::integral_constant<size_t, I>{}), ...); }(std::make_index_sequence<N>{});
}
template <U Offset> inline U GuardWord(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kGuardSpans, Offset);
    static_assert(at != ~0u, "offset is outside the guard footprint");
    return Raw<U>(s.guard + at);
}
template <U Offset> inline unsigned char GuardByte(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kGuardSpans, Offset);
    static_assert(at != ~0u, "offset is outside the guard footprint");
    return s.guard[at];
}
template <U Offset> inline U OutputWord(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kOutputSpans, Offset);
    static_assert(at != ~0u, "offset is outside the output footprint");
    return Raw<U>(s.output + at);
}
template <U Bytes> inline U SpanDiff(const unsigned char* a, const unsigned char* b) {
    U diff = 0, i = 0;
    for (; i + 16 <= Bytes; i += 16)
        diff |= static_cast<U>(_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i)),
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i)))) ^ 0xFFFF);
    for (; i < Bytes; i += 4) diff |= Raw<U>(a + i) ^ Raw<U>(b + i);
    return diff;
}
// `live` is the native receiver (guard reads +628 beyond the copied prefix); work is the private 0x680 receiver.
inline void GatherGuard(OwnedSlot& slot, const unsigned char* live) {
    EachSpanOf<kGuardSpanCount>([&](auto i) {
        constexpr Span s = kGuardSpans[decltype(i)::value];
        memcpy(slot.guard + kGuardStart[decltype(i)::value], live + s.offset, s.bytes);
    });
}
inline void GatherOutput(OwnedSlot& slot, const unsigned char* work) {
    EachSpanOf<kOutputSpanCount>([&](auto i) {
        constexpr Span s = kOutputSpans[decltype(i)::value];
        memcpy(slot.output + kOutputStart[decltype(i)::value], work + s.offset, s.bytes);
    });
    EachSpanOf<kWrapperSpanCount>([&](auto i) {
        constexpr Span s = kWrapperSpans[decltype(i)::value];
        memcpy(slot.output + kOutputBytes + kWrapperStart[decltype(i)::value], work + s.offset, s.bytes);
    });
}
// True when every byte the worker could have read still holds the value it read (branch-free over the footprint).
inline bool OwnedGuardMatches(const OwnedSlot& slot, const unsigned char* live) {
    U diff = 0;
    EachSpanOf<kGuardSpanCount>([&](auto i) {
        constexpr Span s = kGuardSpans[decltype(i)::value];
        diff |= SpanDiff<s.bytes>(live + s.offset, slot.guard + kGuardStart[decltype(i)::value]);
    });
    diff |= static_cast<U>(live[0x5EC] ^ slot.inputLatch);
    if (slot.readsPredicate) diff |= Raw<U>(live + 0x67C) ^ slot.inputPredicate;
    if (slot.readsLinkByte) diff |= static_cast<U>(live[4] ^ slot.inputLinkByte);
    return diff == 0;
}
// Writes exactly the proven footprint; links/+98/+A8/+AC belong to the replayed native services.
inline void CommitOwnedFields(const OwnedSlot& slot) {
    unsigned char* const native = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(slot.entity));
    EachSpanOf<kOutputSpanCount>([&](auto i) {
        constexpr Span s = kOutputSpans[decltype(i)::value];
        memcpy(native + s.offset, slot.output + kOutputStart[decltype(i)::value], s.bytes);
    });
    if (slot.wrapper) EachSpanOf<kWrapperSpanCount>([&](auto i) {
        constexpr Span s = kWrapperSpans[decltype(i)::value];
        memcpy(native + s.offset, slot.output + kOutputBytes + kWrapperStart[decltype(i)::value], s.bytes);
    });
    memcpy(native + 0x5EC, slot.resultLatches, 2);
}
// The occurrence a participant is executing right now (service gates read it through TLS).
struct OwnedCurrent {
    U entity, ordinal, serial, services;
    unsigned char reason, detail, serviceCount;
    ntw2_env::Result environment;
};
// Heavy per-participant worker contexts. Created by ActivateOwned only, one per ACTUAL participant.
struct OwnedContexts {
    ntw2_sweep::WorkerContext sweep;
    ntw2_resolve::WorkerContext resolve;
    ntw2_env::WorkerContext env;
};
struct OwnedParticipant {
    ntw2_clone_set clones{};
    U first[5]{}, second[4]{}, third[4]{};
    OwnedContexts* ctx = nullptr;
    OwnedCurrent current{};
    LONGLONG maximum = 0;
    ULONGLONG cpu100ns = 0, cpuAtMaximum100ns = 0;
    // Private receiver. Bytes outside the copied prefix/latches/+67C are never read by the closed closure and stay zero.
    alignas(64) unsigned char work[kOwnedBytes]{};
};
struct OwnedArena {
    ntw2_sweep::WorkerScene scene;
    ntw2_resolve::WorkerCatalog catalog;
    OwnedParticipant* participants[kParallelChunks]{}; // only participantsCount entries are ever allocated
    U virtualTables[kOwnedClasses][kOwnedVirtualWords];
    bool classRoute[kOwnedClasses]{}, predicate67C[kOwnedClasses]{}, predicateLinkByte[kOwnedClasses]{};
    unsigned char* movement = nullptr; // one block: slots | worklist | states, all sized by capacity.primary
    U movementBytes = 0;
    OwnedSlot* slots = nullptr;
    unsigned char* states = nullptr;
    U slotCapacity = 0;
    U* worklist = nullptr;
    U activationModel = 0;
    bool activated = false;
    U list = 0, count = 0, participantsCount = 0, owner = 0, mxcsr = 0, chunkSize = 0, chunks = 0;
    U failureReason = OwnedNeedsUnit;
    unsigned short cw = 0;
    bool valid = false;
    volatile LONG epoch = 0, nextParticipant = 0, overflow = 0, computed = 0, refused = 0, chunkTimeUs = 0;
    volatile LONG histogram[kOwnedHistogram] = {};
};
static_assert(sizeof(OwnedSlot) == kOwnedSlotBytes, "published movement slot width");
OwnedArena* g_owned;
U g_ownedWords[OwnedWordCount], g_locoBindings[NTW2_BIND_COUNT];
U g_ownedDetails[OwnedDetailWordCount], g_ownedPhase[OwnedPhaseWordCount];
U g_ownedLoad[OwnedLoadWordCount];
LONGLONG g_replayCommitTicks, g_replayFallbackTicks;
U g_ownedReplaySeq, g_ownedFallbackSeq;
bool g_quiet;
U g_stageEntity, g_stageOrdinal;
__declspec(thread) OwnedCurrent* g_ownedOccurrence;
__declspec(thread) OwnedParticipant* g_ownedParticipant;
__declspec(thread) LONG g_ownedEpoch;
#ifdef NTW2_LOCO_ORACLE
OwnedServiceObserverForTest g_ownedObserver;
void ObserveOwned(U entity, U service, U ordinal, OwnedTestPhase phase) {
    if (g_ownedObserver) g_ownedObserver(entity, static_cast<Service>(service), ordinal, phase);
}
#endif
U g_stageGatherTarget, g_stageResetTarget, g_stagingReturn;
LONGLONG g_stagingStart;
bool g_stagingActive;
enum OccurrenceState : U { Ready, Computed, Faulted };
struct ParallelJob { U count, chunks, owner, mxcsr; unsigned short cw; };
enum GridPhase : U { GridPhaseCapture, GridPhaseBuild, GridPhaseVerify };
// Contiguous run of active strips owned by one build task: it scans those strips' cells, assigns rows and
// membership offsets from the exact bases the owner computed, and scatters the records that touch them.
struct GridTask { U first, last, rowBase, rowEnd, memberBase, memberEnd, zLo, zHi; };
// One normal build = exactly two dispatches, with only owner work in between:
//   1. capture (record chunks): snapshot, identity, node validation, bounds, per-cell tally, per-chunk strip totals,
//      committed-ordinal -> slot mapping;
//   2. build (tasks, then record chunks): per-strip cell scan -> rows/offsets/dense, in-order scatter, and
//      the incarnation/accounting finish.
// No chunk waits for another chunk of the same dispatch. Every cross-chunk dependency (strip totals, row and
// offset bases, birth prefix) is resolved by the owner between the dispatches, so serial, reversed and concurrent
// dispatchers publish identical output.
struct GridJob {
    GridStore* store;
    GridIdentity* next;
    const GridIdentity* old;
    U phase, chunks, tasks, members, rows, incarnationBase, committedCount;
    U shift, origin, maximum, cells, nativeCells, mxcsr, stripHeight, strips, activeStrips;
    float scale, bump;
    unsigned short cw;
    volatile LONG failure, mismatches, unsupported, nativeMembers;
    U active[kGridStrips], stripRows[kGridStrips];
    GridTask task[kGridMaxTasks];
};

inline U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
inline void* P(U address) { return reinterpret_cast<void*>(static_cast<uintptr_t>(address)); }
inline U V(U va) { return va + g_delta; }
inline U D(U address) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(address)); }
inline uint8_t B(U address) { return *reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(address)); }
inline void Call(U address, U receiver) { reinterpret_cast<TC0>(address)(P(receiver)); }
inline void Max(U word, U value) { if (g_words[word] < value) g_words[word] = value; }
inline LONGLONG Now() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
inline U Microseconds(LONGLONG ticks) {
    return static_cast<U>((static_cast<unsigned long long>(ticks) * 1000000ull) /
                          static_cast<unsigned long long>(g_frequency.QuadPart));
}

inline float Float(U address) { return *reinterpret_cast<const float*>(static_cast<uintptr_t>(address)); }
inline float GridAdd(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline float GridSub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
U GridCoordinate(float value, const GridJob& job) {
    float scaled = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(value), _mm_set_ss(job.scale))), half = -0.5f;
    int rounded;
    __asm { fld scaled }
    __asm { fadd st(0), st(0) }
    __asm { fadd half }
    __asm { fistp rounded }
    const U coordinate = static_cast<U>(rounded >> 1) + job.origin;
    return coordinate < job.maximum ? coordinate : job.maximum;
}
void Prefault(void* base, size_t bytes);
// Hash capacity: power of two, at most 2/3 loaded at full record capacity.
U HashSizeFor(U records) { U size = 16; while (size < records + records / 2 + 1) size <<= 1; return size; }
// Smallest b >= 1 with 2^b >= values.
U BitsFor(U values) { U bits = 1; while (bits < 31 && (1u << bits) < values) ++bits; return bits; }
bool ValidCapacity(const ntw2_workload::Capacity& c) {
    return c.primary && c.records >= c.primary && c.cells && c.memberships &&
        c.records <= kMaxRecords && c.cells <= kMaxCells && c.memberships <= kMaxMembers;
}
// Carves (or, with base==null, only sizes) the single grid block. Each array is padded to 64 bytes.
// words: identity 2*(5R+H) | view 12R | committed R | dense C | cellIds Q | offsets Q+1 | occupants M | fill Q |
// stripMembers chunks*64 | stripRows chunks*64 | stats chunks*64B, with
// R=records, H=HashSizeFor(R), Q=min(cells,memberships), M=memberships, C=cells.
struct GridCarve {
    unsigned char* base;
    unsigned long long offset;
    template <class T> T* Take(unsigned long long count) {
        T* const p = base ? reinterpret_cast<T*>(base + offset) : nullptr;
        offset += (count * sizeof(T) + 63) & ~63ull;
        return p;
    }
};
unsigned long long CarveGrid(const ntw2_workload::Capacity& c, U chunks, GridStore& s, unsigned char* base) {
    GridCarve m = {base, 0};
    const U R = c.records, H = HashSizeFor(R), C = c.cells, M = c.memberships, Q = (std::min)(C, M);
    s.cap = c; s.chunks = chunks; s.hashSize = H; s.rowCap = Q;
    s.slotMask = (1u << BitsFor(R + 1)) - 1; // identity hash entries carry slot+1 in the low bits and a hash tag above
    for (GridIdentity& id : s.id) {
        id.record = m.Take<U>(R); id.serial = m.Take<U>(R); id.incarnation = m.Take<U>(R);
        id.active = m.Take<U>(R); id.inserted = m.Take<U>(R); id.hash = m.Take<U>(H);
    }
    s.team = m.Take<U>(R); s.flags = m.Take<U>(R); s.nodeType = m.Take<U>(R);
    s.left = m.Take<U>(R); s.right = m.Take<U>(R); s.top = m.Take<U>(R); s.bottom = m.Take<U>(R);
    s.x = m.Take<float>(R); s.z = m.Take<float>(R); s.y = m.Take<float>(R); s.extent = m.Take<float>(R); s.radius = m.Take<float>(R);
    s.committed = m.Take<U>(R); s.dense = m.Take<U>(C);
    s.cellIds = m.Take<U>(Q); s.offsets = m.Take<U>(Q + 1ull);
    s.occupants = m.Take<U>(M); s.fill = m.Take<U>(Q);
    s.stripMembers = m.Take<U>(static_cast<unsigned long long>(chunks) * kGridStrips);
    s.stripRows = m.Take<U>(static_cast<unsigned long long>(chunks) * kGridStrips);
    s.stats = m.Take<GridChunkStat>(chunks);
    return m.offset;
}
bool AllocateGrid(const ntw2_workload::Capacity& c) {
    const U chunks = (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1));
    GridStore plan = {};
    const unsigned long long bytes = CarveGrid(c, chunks, plan, nullptr);
    if (bytes > 0x7FFFFFFFull) return false;
    const unsigned long long allocation = (bytes + 4095) & ~4095ull;
    unsigned char* const base = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(allocation), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base) return false;
    g_gridStore = GridStore{};
    CarveGrid(c, chunks, g_gridStore, base);
    g_gridStore.base = base; g_gridStore.bytes = static_cast<size_t>(bytes);
    g_gridStore.allocBytes = static_cast<size_t>(allocation);
    Prefault(base, static_cast<size_t>(allocation)); // every page, before hook publication
    g_grid = &g_gridStore;
    g_gridCurrent = 0; g_gridDenseDirty = false; g_gridLiveStripHeight = g_gridLiveShift = 0;
    memset(g_gridStripLive, 0, sizeof(g_gridStripLive));
    g_gridWords[GridBytes] = static_cast<U>(bytes);
    return true;
}
void ReleaseGrid() {
    if (g_gridStore.base) VirtualFree(g_gridStore.base, 0, MEM_RELEASE);
    g_gridStore = GridStore{};
    g_grid = nullptr;
}
bool GridCovers(const ntw2_workload::Capacity& c) {
    const ntw2_workload::Capacity& a = g_gridStore.cap;
    return c.primary <= a.primary && c.records <= a.records && c.cells <= a.cells && c.memberships <= a.memberships;
}
U SaturatedWord(unsigned long long value) { return value > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(value); }
// Every owned allocation, retained capacities included, split into the cached breakdown. Called once per
// activation event, never per tick. The first eight words sum to the returned total (barring saturation).
U ComputeStorage() {
    unsigned long long movement = 0, grid = 0, scene = 0, catalog = 0, participants = 0, sweep = 0, resolve = 0, env = 0;
    memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    if (g_workers) participants += sizeof(WorkerArena);
    if (g_grid) grid = g_gridStore.allocBytes;
    if (g_owned) {
        const OwnedArena& arena = *g_owned;
        participants += sizeof(OwnedArena);
        movement = arena.movementBytes;
        scene = ntw2_sweep::HeapBytes(arena.scene); catalog = ntw2_resolve::HeapBytes(arena.catalog);
        ntw2_resolve::SampleCatalogStorage(arena.catalog, g_catalogStorage);
        for (U i = 0; i < arena.participantsCount; ++i) {
            const OwnedParticipant* participant = arena.participants[i];
            if (!participant) continue;
            participants += sizeof(OwnedParticipant) + participant->clones.allocation_bytes;
            if (participant->ctx) {
                participants += sizeof(OwnedContexts);
                sweep += ntw2_sweep::HeapBytes(participant->ctx->sweep);
                resolve += ntw2_resolve::HeapBytes(participant->ctx->resolve);
                env += ntw2_env::HeapBytes(participant->ctx->env);
            }
        }
        ntw2_sweep::SampleCounts(arena.scene, g_storageWords + StorageSceneNodes);
    }
    g_storageWords[StorageMovement] = SaturatedWord(movement); g_storageWords[StorageGrid] = SaturatedWord(grid);
    g_storageWords[StorageScene] = SaturatedWord(scene); g_storageWords[StorageCatalog] = SaturatedWord(catalog);
    g_storageWords[StorageParticipants] = SaturatedWord(participants); g_storageWords[StorageSweep] = SaturatedWord(sweep);
    g_storageWords[StorageResolve] = SaturatedWord(resolve); g_storageWords[StorageEnv] = SaturatedWord(env);
    return SaturatedWord(movement + grid + scene + catalog + participants + sweep + resolve + env);
}
inline U GridHash(U record) { return (record >> 4) * 2654435761u; }
// Identity hash entry = (high product bits & ~slotMask) | (slot + 1): a non-matching probe is rejected by the tag
// without touching the record array; a tag match is always confirmed against the full record address.
U GridSlot(const GridStore& s, const GridIdentity& id, U record) {
    const U product = GridHash(record), mask = s.hashSize - 1, tagMask = ~s.slotMask;
    for (U h = product & mask;; h = (h + 1) & mask) {
        const U entry = id.hash[h];
        if (!entry) return kNoSlot;
        if (!((entry ^ product) & tagMask)) {
            const U slot = (entry & s.slotMask) - 1;
            if (id.record[slot] == record) return slot;
        }
    }
}
// Atomic maximum: duplicate occurrences of one record keep the highest committed ordinal, like the old serial scan.
inline void GridRaiseCommitted(U& word, U value) {
    volatile LONG* const target = reinterpret_cast<volatile LONG*>(&word);
    LONG current = _InterlockedCompareExchange(target, 0, 0);
    while (current < static_cast<LONG>(value)) {
        const LONG seen = _InterlockedCompareExchange(target, static_cast<LONG>(value), current);
        if (seen == current) break;
        current = seen;
    }
}
void GridFail(GridJob& job) { _InterlockedExchange(&job.failure, 1); }
void GridMismatch(GridJob& job) { _InterlockedIncrement(&job.mismatches); GridFail(job); }
inline void GridRange(U n, U chunks, U chunk, U& begin, U& end) {
    const U size = (n + chunks - 1) / chunks;
    begin = (std::min)(n, chunk * size); end = (std::min)(n, begin + size);
}
// First touch of a cell in this build replaces whatever the previous publication left there with tag|1; later touches
// add one. Exactly one caller observes the first touch (true), whichever chunk it is, so the per-strip row counts the
// owner derives are exact and schedule independent. Nothing reads a tally before the dispatch has joined.
inline bool GridTally(U& word) {
    volatile LONG* const target = reinterpret_cast<volatile LONG*>(&word);
    LONG current = *target;
    for (;;) {
        const LONG next = (static_cast<U>(current) & kGridTag) ? current + 1 : static_cast<LONG>(kGridTag | 1u);
        const LONG seen = _InterlockedCompareExchange(target, next, current);
        if (seen == current) return !(static_cast<U>(current) & kGridTag);
        current = seen;
    }
}
// Dispatch 1 (record chunks): snapshot, identity, node validation, bounds, per-cell tally, per-chunk strip totals.
void GridCaptureRecord(GridJob& job, U i, U chunk) {
    GridStore& s = *job.store;
    GridIdentity& b = *job.next;
    const GridIdentity& old = *job.old;
    GridChunkStat& stat = s.stats[chunk];
    const U record = b.record[i];
    s.left[i] = s.right[i] = s.top[i] = s.bottom[i] = b.inserted[i] = s.nodeType[i] = 0;
    if (!record) { b.serial[i] = b.incarnation[i] = s.team[i] = s.flags[i] = b.active[i] = 0;
        s.x[i] = s.y[i] = s.z[i] = s.extent[i] = s.radius[i] = 0; return; }
    b.serial[i] = D(record + 0x2C); s.team[i] = D(record + 0x44); s.flags[i] = D(record + 0x38);
    b.active[i] = B(record + 0x30); b.inserted[i] = D(record + 0xAC);
    const U previous = GridSlot(s, old, record);
    if (previous < old.count && old.serial[previous] == b.serial[i]) {
        b.incarnation[i] = old.incarnation[previous];
        stat.deactivations += old.active[previous] && !b.active[i];
        stat.removals += old.inserted[previous] && !b.inserted[i];
    } else {
        // The finish phase assigns births in record order from the owner's per-chunk prefix.
        b.incarnation[i] = 0; ++stat.births;
        stat.reused += previous < old.count;
    }
    const unsigned char* const pose = static_cast<const unsigned char*>(P(record + 0x48));
    memcpy(&s.x[i], pose, sizeof(float)); memcpy(&s.y[i], pose + 4, sizeof(float));
    memcpy(&s.z[i], pose + 8, sizeof(float)); memcpy(&s.extent[i], pose + 12, sizeof(float));
    memcpy(&s.radius[i], pose + 16, sizeof(float));
    if (!b.inserted[i]) return; // AC, not activity/A1, owns grid absence.
    const U nodes = D(record + 0xA8);
    const float radius = B(record + 0x5C) == 1 ? GridAdd(s.radius[i], job.bump) : s.radius[i];
    const U left = GridCoordinate(GridSub(s.x[i], radius), job), right = GridCoordinate(GridAdd(s.x[i], radius), job);
    const U top = GridCoordinate(GridSub(s.z[i], radius), job), bottom = GridCoordinate(GridAdd(radius, s.z[i]), job);
    if (!nodes || left > right || top > bottom || b.inserted[i] > D(record + 0xB0) ||
        static_cast<unsigned long long>(right - left + 1) * (bottom - top + 1) != b.inserted[i]) {
        GridMismatch(job); return;
    }
    s.left[i] = left; s.right[i] = right; s.top[i] = top; s.bottom[i] = bottom;
    s.nodeType[i] = D(nodes);
    U* const stripMembers = s.stripMembers + static_cast<size_t>(chunk) * kGridStrips;
    U* const stripRows = s.stripRows + static_cast<size_t>(chunk) * kGridStrips;
    U n = 0;
    for (U z = top; z <= bottom; ++z) {
        U fresh = 0;
        for (U x = left; x <= right; ++x, ++n) {
            const U node = nodes + n * 0x1C, cell = (z << job.shift) + x;
            if (D(node) != 8 || D(node + 4) != b.serial[i] || D(node + 8) != record + 0x30 ||
                D(node + 12) != record || D(node + 24) != job.nativeCells + 4 * cell) {
                _InterlockedIncrement(&job.unsupported); GridMismatch(job); return;
            }
            fresh += GridTally(s.dense[cell]);
        }
        const U strip = z / job.stripHeight;
        stripMembers[strip] += right - left + 1; stripRows[strip] += fresh;
    }
}
void GridCapturePhase(GridJob& job, U chunk) {
    GridStore& s = *job.store;
    U begin, end;
    GridRange(job.next->count, job.chunks, chunk, begin, end);
    for (U i = begin; i < end && !job.failure; ++i) GridCaptureRecord(job, i, chunk);
    // Committed ordinals -> registry slots, split by worklist range. The registry hash is complete and read-only
    // during this dispatch; s.committed is read only by the build dispatch's finish chunks, after the join.
    if (job.committedCount) {
        const OwnedArena& arena = *g_owned;
        GridRange(job.committedCount, job.chunks, chunk, begin, end);
        for (U ordinal = begin; ordinal < end; ++ordinal) {
            if (arena.states[ordinal] != OwnedCommitted) continue;
            const U slot = GridSlot(s, *job.next, arena.worklist[ordinal]);
            if (slot < job.next->count) GridRaiseCommitted(s.committed[slot], ordinal + 1);
        }
    }
}
// Dispatch 2, one task per run of active strips. Scan the run's cells in ascending order, turning each tallied cell
// into a row (consecutive offsets from the owner's exact bases) and zeroing stale entries of the previous publication;
// then scatter, in ascending record slot, every record that touches the run's z range. Rows and positions are owned
// by exactly one task, so each row's occupants ascend by slot whatever the chunk or task count.
void GridBuildTask(GridJob& job, U task) {
    GridStore& s = *job.store;
    const GridTask& t = job.task[task];
    const __m128i zero = _mm_setzero_si128();
    U row = t.rowBase, position = t.memberBase;
    for (U a = t.first; a < t.last; ++a) {
        const U firstRow = job.active[a] * job.stripHeight;
        const U begin = firstRow << job.shift;
        const U end = (std::min)((std::min)(firstRow + job.stripHeight, job.maximum + 1) << job.shift, job.cells);
        for (U cell = begin; cell < end;) {
            if (cell + 4 <= end &&
                _mm_movemask_epi8(_mm_cmpeq_epi32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(s.dense + cell)), zero)) == 0xFFFF) {
                cell += 4; continue;
            }
            const U value = s.dense[cell];
            if (value & kGridTag) {
                const U count = value & ~kGridTag;
                if (row >= t.rowEnd || position + count > t.memberEnd) { GridFail(job); return; }
                s.cellIds[row] = cell; s.offsets[row] = position; s.fill[row] = position;
                s.dense[cell] = row + 1; ++row; position += count;
            } else if (value) s.dense[cell] = 0;
            ++cell;
        }
    }
    if (row != t.rowEnd || position != t.memberEnd) { GridFail(job); return; }
    const GridIdentity& b = *job.next;
    for (U i = 0; i < b.count; ++i) {
        const U top = s.top[i], bottom = s.bottom[i];
        if (bottom < t.zLo || top > t.zHi || !b.inserted[i]) continue;
        const U last = (std::min)(bottom, t.zHi);
        for (U z = (std::max)(top, t.zLo); z <= last; ++z) for (U x = s.left[i]; x <= s.right[i]; ++x) {
            const U r = s.dense[(z << job.shift) + x] - 1;
            if (r < t.rowBase || r >= t.rowEnd) { GridFail(job); return; }
            const U to = s.fill[r]++;
            if (to >= t.memberEnd) { GridFail(job); return; }
            s.occupants[to] = i;
        }
    }
}
// Owner step between the dispatches: per-chunk strip totals -> exact membership and row totals -> active strips (new
// members or stale rows of the previous publication) -> weight-balanced tasks, each with exact row/offset bases.
// O(chunks * strips) words. False = capacity refusal or inconsistent totals, before anything is published.
bool GridPlan(GridJob& job) {
    const GridStore& s = *job.store;
    unsigned long long stripMembers[kGridStrips] = {}, members = 0, rows = 0;
    for (U k = 0; k < job.strips; ++k) {
        unsigned long long m = 0, r = 0;
        for (U c = 0; c < job.chunks; ++c) { m += s.stripMembers[c * kGridStrips + k]; r += s.stripRows[c * kGridStrips + k]; }
        stripMembers[k] = m; job.stripRows[k] = static_cast<U>(r); members += m; rows += r;
    }
    if (members > s.cap.memberships || rows > s.rowCap) return false;
    job.members = static_cast<U>(members); job.rows = static_cast<U>(rows);
    const unsigned long long scanWeight = ((static_cast<unsigned long long>(job.stripHeight) << job.shift) >> 5) + 1;
    unsigned long long cumulative[kGridStrips + 1], weight = 0;
    U count = 0;
    for (U k = 0; k < job.strips; ++k) {
        if (!stripMembers[k] && !g_gridStripLive[k]) continue;
        job.active[count] = k; cumulative[count++] = weight; weight += stripMembers[k] + scanWeight;
    }
    cumulative[count] = weight;
    const U tasks = (std::min)(count, (std::min)(kGridMaxTasks, 2 * job.chunks));
    U cut[kGridMaxTasks + 1];
    cut[0] = 0;
    for (U g = 1; g < tasks; ++g) { // non-empty groups; each cut at the first strip reaching g/tasks of the weight
        U position = cut[g - 1] + 1;
        const unsigned long long target = weight * g / tasks;
        while (position < count - (tasks - g) && cumulative[position] < target) ++position;
        cut[g] = position;
    }
    cut[tasks] = count;
    U rowBase = 0, memberBase = 0;
    for (U g = 0; g < tasks; ++g) {
        GridTask& t = job.task[g];
        t.first = cut[g]; t.last = cut[g + 1]; t.rowBase = rowBase; t.memberBase = memberBase;
        for (U a = t.first; a < t.last; ++a) { rowBase += job.stripRows[job.active[a]]; memberBase += static_cast<U>(stripMembers[job.active[a]]); }
        t.rowEnd = rowBase; t.memberEnd = memberBase;
        t.zLo = job.active[t.first] * job.stripHeight;
        t.zHi = (std::min)((job.active[t.last - 1] + 1) * job.stripHeight, job.maximum + 1) - 1;
    }
    job.tasks = tasks; job.activeStrips = count;
    return true;
}
// Build dispatch, record-chunk tasks: birth incarnations in record order, registry removals and source accounting.
void GridFinishPhase(GridJob& job, U chunk) {
    GridStore& s = *job.store;
    GridIdentity& b = *job.next;
    const GridIdentity& old = *job.old;
    GridChunkStat& stat = s.stats[chunk];
    U begin, end;
    GridRange(b.count, job.chunks, chunk, begin, end);
    U incarnation = job.incarnationBase + stat.birthBase;
    // Births take incarnations in record order. Result-buffer vs live-record read accounting rides the same pass: pose
    // values published by capture always come from the live record, and a committed result counts as "direct" only
    // while the record still equals the worker's stored pose (and serial).
    for (U i = begin; i < end; ++i) {
        if (!b.record[i]) continue;
        if (!b.incarnation[i]) b.incarnation[i] = ++incarnation;
        const U committed = s.committed[i];
        bool direct = false;
        if (committed && g_owned) {
            const OwnedSlot& slot = g_owned->slots[committed - 1];
            U pose[5];
            memcpy(&pose[0], &s.x[i], sizeof(U)); memcpy(&pose[1], &s.y[i], sizeof(U)); memcpy(&pose[2], &s.z[i], sizeof(U));
            memcpy(&pose[3], &s.extent[i], sizeof(U)); memcpy(&pose[4], &s.radius[i], sizeof(U));
            direct = GuardWord<0x2C>(slot) == b.serial[i] && OutputWord<0x48>(slot) == pose[0] && OutputWord<0x4C>(slot) == pose[1] &&
                OutputWord<0x50>(slot) == pose[2] && OutputWord<0x54>(slot) == pose[3] && GuardWord<0x58>(slot) == pose[4];
        }
        if (direct) ++stat.committed; else ++stat.fromRecord;
    }
    GridRange(old.count, job.chunks, chunk, begin, end);
    U removed = 0;
    for (U i = begin; i < end; ++i) if (old.record[i]) {
        const U slot = GridSlot(s, b, old.record[i]);
        removed += slot == kNoSlot || b.serial[slot] != old.serial[i];
    }
    stat.removed = removed;
}
// Optional separate dispatch: compare every native chain with the published identity. Never part of the build.
void GridVerifyPhase(GridJob& job, U chunk) {
    const GridStore& s = *job.store;
    U begin, end;
    GridRange(job.cells, job.chunks, chunk, begin, end);
    U members = 0;
    for (U cell = begin; cell < end && !job.failure; ++cell) {
        U previous = 0, node = D(job.nativeCells + cell * 4);
        while (node) {
            if (++members > s.cap.memberships) { GridMismatch(job); break; }
            const U owner = D(node + 12), slot = GridSlot(s, *job.next, owner);
            if (slot == kNoSlot || D(node) != 8 || D(node + 8) != owner + 0x30 ||
                D(node + 4) != D(owner + 0x2C) || D(node + 16) != previous ||
                D(node + 24) != job.nativeCells + cell * 4) { GridMismatch(job); break; }
            const U offset = node - D(owner + 0xA8);
            if (offset % 0x1C || offset / 0x1C >= D(owner + 0xAC)) { GridMismatch(job); break; }
            previous = node; node = D(node + 20);
        }
    }
    _InterlockedExchangeAdd(&job.nativeMembers, static_cast<LONG>(members));
}
void __fastcall GridChunk(void* context, U chunk) {
    GridJob& job = *static_cast<GridJob*>(context);
    // Only capture touches floating point (native FISTP cell bounds follow the owner's rounding mode).
    const bool floating = job.phase == GridPhaseCapture;
    const U saved = _mm_getcsr(); unsigned short cw = 0, ownerCw = job.cw;
    if (floating) {
        __asm { fnstcw cw }
        _mm_setcsr(job.mxcsr);
        __asm { fldcw ownerCw }
    }
    __try {
        __try {
            switch (job.phase) {
            case GridPhaseCapture: GridCapturePhase(job, chunk); break;
            case GridPhaseBuild:
                if (chunk < job.tasks) GridBuildTask(job, chunk); else GridFinishPhase(job, chunk - job.tasks);
                break;
            default: GridVerifyPhase(job, chunk); break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_gridWords[GridFaults]));
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_gridV2Words[GridV2Faults])); GridFail(job);
        }
    } __finally {
        if (floating) {
            __asm { fnclex }
            __asm { fldcw cw }
            _mm_setcsr(saved);
        }
    }
}
void GridDispatch(GridJob& job, U phase, U count) {
    job.phase = phase;
    ++g_gridV2Words[GridV2Dispatches];
    if (g_binding.dispatch) g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&GridChunk)), count, &job);
    else for (U i = 0; i < count; ++i) GridChunk(&job, i);
}
bool CaptureGridImpl(U manager) {
    GridStore& s = *g_grid;
    GridIdentity& old = s.id[g_gridCurrent];
    GridIdentity& next = s.id[g_gridCurrent ^ 1];
    const LONGLONG captureStart = Now();
    GridJob job = {}; job.store = &s; job.next = &next; job.old = &old;
    const U root = D(manager), model = root ? D(root + 8) : 0, grid = model ? D(model + 0xA4) : 0;
    if (!grid || model != g_gridModel) return false;
    job.shift = D(grid + 8); job.origin = D(grid + 0x10); job.maximum = D(grid + 0x14);
    if (job.shift > 20 || job.maximum >= (1u << job.shift)) return false;
    const unsigned long long cells = (static_cast<unsigned long long>(job.maximum) << job.shift) + job.maximum + 1;
    if (cells > s.cap.cells) return false;
    job.cells = static_cast<U>(cells); job.nativeCells = D(grid); job.scale = Float(grid + 0x24);
    job.bump = Float(V(0x1318038)); job.mxcsr = _mm_getcsr(); unsigned short cw;
    __asm { fnstcw cw }
    job.cw = cw; job.chunks = s.chunks;
    const U primary = D(manager + 0x24C), secondary = D(manager + 0x278);
    // Fixed capacities: an oversized registry refuses here, before any build step or game write.
    if (primary > s.cap.primary || secondary > s.cap.records) return false;
    next.count = next.memberships = next.occupied = 0; next.epoch = old.epoch + 1;
    memset(next.hash, 0, static_cast<size_t>(s.hashSize) * sizeof(U));
    const U hashMask = s.hashSize - 1, tagMask = ~s.slotMask;
    U* const hash = next.hash;
    for (U domain = 0; domain < 2; ++domain) {
        const U count = domain ? secondary : primary, records = D(manager + (domain ? 0x27C : 0x250));
        for (U n = 0; n < count; ++n) {
            if (n + 8 < count) {
                const U ahead = D(records + (n + 8) * 4);
                if (ahead) _mm_prefetch(reinterpret_cast<const char*>(hash + (GridHash(ahead) & hashMask)), _MM_HINT_T0);
            }
            const U record = D(records + n * 4);
            if (!record) { // primary null holes keep their registry index; secondary holes are skipped
                if (domain) continue;
                if (next.count == s.cap.records) return false;
                const U i = next.count++;
                next.record[i] = 0; s.committed[i] = 0;
                continue;
            }
            // One probe both finds an existing identity and locates the insertion slot.
            const U product = GridHash(record);
            U h = product & hashMask;
            bool duplicate = false;
            for (U entry; (entry = hash[h]) != 0; h = (h + 1) & hashMask)
                if (!((entry ^ product) & tagMask) && next.record[(entry & s.slotMask) - 1] == record) { duplicate = true; break; }
            if (duplicate) { if (!domain) return false; continue; }
            if (next.count == s.cap.records) return false;
            const U i = next.count++;
            next.record[i] = record; s.committed[i] = 0;
            hash[h] = (product & tagMask) | (i + 1);
        }
    }
    job.committedCount = g_stage && g_gridCommittedReady && g_owned && g_owned->count <= g_owned->slotCapacity ? g_owned->count : 0;
    job.incarnationBase = g_incarnation;
    job.stripHeight = (job.maximum + 1 + kGridStrips - 1) / kGridStrips;
    job.strips = (job.maximum + job.stripHeight) / job.stripHeight;
    // Dense-map invariant: words outside the previous publication's live strips are zero. An interrupted build or a
    // different strip geometry voids it, so the map is cleared whole (rare; never on the normal path).
    bool anyLive = false;
    for (const bool live : g_gridStripLive) anyLive |= live;
    if (g_gridDenseDirty || (anyLive && (g_gridLiveStripHeight != job.stripHeight || g_gridLiveShift != job.shift))) {
        memset(s.dense, 0, static_cast<size_t>(s.cap.cells) * sizeof(U));
        memset(g_gridStripLive, 0, sizeof(g_gridStripLive));
    }
    g_gridDenseDirty = true; // from here the map holds tallies; only a completed publication clears this
    memset(s.stats, 0, static_cast<size_t>(job.chunks) * sizeof(GridChunkStat));
    memset(s.stripMembers, 0, static_cast<size_t>(job.chunks) * kGridStrips * sizeof(U));
    memset(s.stripRows, 0, static_cast<size_t>(job.chunks) * kGridStrips * sizeof(U));
    const U captureUs = Microseconds(Now() - captureStart);
    g_gridWords[GridCaptureUs] += captureUs; g_parallelWords[ParallelCaptureUs] += captureUs;
    LONGLONG verifyTicks = 0;
    GridDispatch(job, GridPhaseCapture, job.chunks);
    if (!job.failure) {
        U births = 0;
        for (U c = 0; c < job.chunks; ++c) { s.stats[c].birthBase = births; births += s.stats[c].births; }
        if (!GridPlan(job)) GridFail(job); // fixed capacity: refuse, publish nothing
        else {
            next.memberships = job.members;
            GridDispatch(job, GridPhaseBuild, job.tasks + job.chunks);
            if (!job.failure) { s.offsets[job.rows] = job.members; next.occupied = job.rows; }
        }
    }
    if (!job.failure && g_binding.verify_grid) {
        const LONGLONG verifyStart = Now();
        GridDispatch(job, GridPhaseVerify, job.chunks);
        verifyTicks = Now() - verifyStart;
        if (!job.failure && static_cast<U>(job.nativeMembers) != next.memberships) GridMismatch(job);
    }
    // Normal build time is everything the owner spends from entry to the published view (serial registry/identity
    // construction and strip planning included); only the optional verification dispatch is excluded.
    const U buildUs = Microseconds(Now() - captureStart - verifyTicks);
    g_gridV2Words[GridV2BuildUs] += buildUs;
    g_gridV2Words[GridV2MaxBuildUs] = (std::max)(g_gridV2Words[GridV2MaxBuildUs], buildUs);
    g_gridV2Words[GridV2VerifyUs] += Microseconds(verifyTicks);
    const U csrUs = buildUs > captureUs ? buildUs - captureUs : 0; // dispatches plus the owner step between them
    g_gridWords[GridCsrUs] += csrUs; g_parallelWords[ParallelCsrUs] += csrUs;
    g_gridWords[GridMismatches] += static_cast<U>(job.mismatches);
    g_gridWords[GridUnsupported] += static_cast<U>(job.unsupported);
    g_gridV2Words[GridV2VerifyMismatches] += static_cast<U>(job.mismatches);
    U births = 0, removed = 0;
    for (U c = 0; c < job.chunks; ++c) {
        const GridChunkStat& stat = s.stats[c];
        g_gridV2Words[GridV2CommittedRecords] += stat.committed; g_gridV2Words[GridV2RecordReads] += stat.fromRecord;
        g_gridWords[GridBirths] += stat.births; g_gridWords[GridReused] += stat.reused;
        g_gridWords[GridDeactivations] += stat.deactivations; g_gridWords[GridMembershipRemovals] += stat.removals;
        births += stat.births; removed += stat.removed;
    }
    if (job.failure) return false;
    g_gridDenseDirty = false; g_gridLiveStripHeight = job.stripHeight; g_gridLiveShift = job.shift;
    for (U k = 0; k < kGridStrips; ++k) g_gridStripLive[k] = k < job.strips && job.stripRows[k] != 0;
    g_incarnation += births; // numbers are consumed only by a publication that actually happens
    g_gridWords[GridRemovals] += removed;
    ++g_gridWords[GridCaptures]; g_gridWords[GridRecords] += next.count;
    g_gridWords[GridPrimary] += primary; g_gridWords[GridSecondary] += next.count - primary;
    g_gridWords[GridMemberships] += next.memberships; g_gridWords[GridCells] += next.occupied;
    g_gridWords[GridMaxRecords] = (std::max)(g_gridWords[GridMaxRecords], next.count);
    g_gridWords[GridMaxMemberships] = (std::max)(g_gridWords[GridMaxMemberships], next.memberships);
    ++g_gridV2Words[GridV2Builds]; g_gridV2Words[GridV2Records] += next.count;
    g_gridV2Words[GridV2Memberships] += next.memberships; g_gridV2Words[GridV2Epoch] = next.epoch;
    g_gridWords[GridEpoch] = next.epoch; g_gridCurrent ^= 1;
    g_gridView = {g_generation, next.epoch, next.count, next.occupied, next.memberships,
        next.record, next.serial, next.incarnation, s.team, s.flags,
        s.x, s.z, s.y, s.extent, s.radius, s.left, s.right, s.top, s.bottom,
        next.inserted, s.cellIds, s.offsets, s.occupants, next.active,
        manager, model, D(model + 0x58), primary, secondary, D(manager + 0x250), D(manager + 0x27C),
        grid, job.nativeCells, job.cells, job.shift, job.origin, job.maximum, job.scale, s.dense, s.nodeType};
    return true;
}

// Only integer operations: the service thunks preserve flags and ALL integer
// registers, and neither this recorder nor its callees touch x87/MXCSR/XMM.
// In particular, no arbitrary observer callback can perturb live mover values.
__declspec(naked) void __stdcall RecordService(U, U) {
    __asm {
        mov eax, dword ptr [esp + 4]
        inc dword ptr [g_words + ServiceCalls * 4]
        inc dword ptr [g_words + eax * 4 + ServiceUnlinkGrid * 4]
        inc dword ptr [g_entityServices]
        mov edx, dword ptr [g_traceCount]
        cmp edx, 256
        jae trace_full
        lea ecx, [g_trace + edx * 8]
        mov dword ptr [ecx], eax
        mov eax, dword ptr [esp + 8]
        mov dword ptr [ecx + 4], eax
        inc dword ptr [g_traceCount]
        ret 8
    trace_full:
        inc dword ptr [g_words + TraceOverflow * 4]
        ret 8
    }
}

void ServiceExit(); // defined below as a naked function (the attribute belongs on the definition only)
__declspec(noinline) void __stdcall BeginService(U service, U* returnSlot, U receiver) {
#ifdef NTW2_LOCO_ORACLE
    ObserveOwned(g_stageEntity ? g_stageEntity : receiver - (service == WrapperQuery ? 0xF4 : 0),
        service, g_stageOrdinal, OwnedTestSerial);
#endif
    if (g_serviceDepth == kServiceFrames) {
        ++g_timingWords[TimingOverflows];
        return; // no return-address substitution: execute the original exactly once
    }
    ServiceFrame& frame = g_serviceFrames[g_serviceDepth];
    frame.returnAddress = *returnSlot;
    frame.service = service;
    if (!QueryPerformanceCounter(&frame.start)) {
        ++g_timingWords[TimingQpcFailures];
        return;
    }
    ++g_serviceDepth;
    if (g_serviceDepth > g_timingWords[TimingMaxDepth]) g_timingWords[TimingMaxDepth] = g_serviceDepth;
    *returnSlot = Address(reinterpret_cast<void*>(&ServiceExit));
    if (g_shadowEnabled) {
        if (service == Sweep)
            ntw2_sweep::ShadowBefore(reinterpret_cast<ntw2_sweep::Agent*>(receiver),
                reinterpret_cast<ntw2_sweep::Scratch*>(returnSlot[1]),
                reinterpret_cast<const ntw2_sweep::Aabb*>(returnSlot[2]), returnSlot[3]);
        else if (service == Resolve)
            ntw2_resolve::ShadowBefore(reinterpret_cast<ntw2_resolve::Agent*>(receiver),
                reinterpret_cast<ntw2_resolve::Scratch*>(returnSlot[1]),
                reinterpret_cast<const ntw2_resolve::Aabb*>(returnSlot[2]));
        else if (service == HeightOwner)
            ntw2_env::ShadowBefore(reinterpret_cast<ntw2_env::Agent*>(receiver),
                reinterpret_cast<ntw2_env::Scratch*>(returnSlot[1]));
    }
}
__declspec(noinline) U __stdcall EndService(U originalReturn) {
    LARGE_INTEGER end;
    const bool clockOk = QueryPerformanceCounter(&end) != FALSE;
    const ServiceFrame frame = g_serviceFrames[--g_serviceDepth];
    if (clockOk && end.QuadPart >= frame.start.QuadPart) {
        const auto ticks = static_cast<unsigned long long>(end.QuadPart - frame.start.QuadPart);
        _InterlockedIncrement(&g_timingSequence);
        ++g_timingWords[TimingCalls];
        ++g_timingWords[TimingServiceCalls + frame.service];
        g_timingTotals.service[frame.service] += ticks;
        if (ticks > g_timingTotals.maximum[frame.service]) g_timingTotals.maximum[frame.service] = ticks;
        if (!g_serviceDepth) g_timingTotals.serviceUnion += ticks;
        _InterlockedIncrement(&g_timingSequence);
    } else ++g_timingWords[TimingQpcFailures];
    if (g_shadowEnabled) {
        if (frame.service == Sweep) ntw2_sweep::ShadowAfter();
        else if (frame.service == Resolve) {
            ntw2_resolve::ObserveOriginalInout(g_originalInout);
            ntw2_resolve::ShadowAfter(static_cast<uint8_t>(originalReturn));
        }
        else if (frame.service == HeightOwner) ntw2_env::ShadowAfter();
    }
    return frame.returnAddress;
}
// Same post-cleanup return-slot technique as runtime SiteExit/SITE_THUNK.
// Preserve every native result register, EFLAGS, x87 stack/control and SSE state.
// The original callee, not this trampoline, still performs its RET n cleanup.
__declspec(naked) void ServiceExit() {
    __asm push eax
    __asm mov al, byte ptr [esp-4]
    __asm mov byte ptr [g_originalInout], al
    __asm pop eax
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm push dword ptr [ebp+28]
    __asm call EndService
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
void AbandonServiceFrames(U base) {
    // An exception may unwind past a substituted return. Discard those timer
    // frames at the enclosing invocation's finally seam; never replay services.
    if (g_serviceDepth > base) {
        g_timingWords[TimingAbandoned] += g_serviceDepth - base;
        g_serviceDepth = base;
        ntw2_sweep::Abandon(); ntw2_resolve::Abandon(); ntw2_env::Abandon();
    }
}
void RecordCloneTime(LONGLONG ticks) {
    if (!g_timingEnabled) return;
    if (ticks < 0) { ++g_timingWords[TimingQpcFailures]; return; }
    _InterlockedIncrement(&g_timingSequence);
    g_timingTotals.cloneWall += static_cast<unsigned long long>(ticks);
    _InterlockedIncrement(&g_timingSequence);
}
#define LOCO_SERVICE(name, index, offset) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm push ecx \
        __asm push index \
        __asm call RecordService \
        __asm cmp byte ptr [g_timingEnabled], 0 \
        __asm je name##Untimed \
        __asm cmp dword ptr [g_runDepth], 0 \
        __asm je name##Untimed \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm lea eax, [ebp+36] \
        __asm push dword ptr [ebp+24] \
        __asm push eax \
        __asm push index \
        __asm call BeginService \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm name##Untimed: \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [g_serviceTargets + offset] \
    }
LOCO_SERVICE(UnlinkGridGate, 0, 0)
LOCO_SERVICE(UnlinkOwnerGate, 1, 4)
LOCO_SERVICE(InsertOwnerGate, 2, 8)
LOCO_SERVICE(InsertGridGate, 3, 12)
LOCO_SERVICE(SweepGate, 4, 16)
LOCO_SERVICE(ResolveGate, 5, 20)
LOCO_SERVICE(HeightOwnerGate, 6, 24)
LOCO_SERVICE(WrapperQueryGate, 7, 28)
#undef LOCO_SERVICE

void RefuseOwned(U reason, U detail = 0) {
    g_ownedOccurrence->reason = reason;
    g_ownedOccurrence->detail = detail;
    RaiseException(kOwnedUnsupported, EXCEPTION_NONCONTINUABLE, 0, nullptr);
}
// The native MOVE decides whether F0 actually clamps the integrated position.
// Refuse only its reached +70 callback, before the unclosed holder/NODE effects.
void __fastcall OwnedClamp(void*, void*) {
    RefuseOwned(OwnedNeedsStaging, OwnedDetailClampCallback);
}
// Participant clone calls obey the original thiscall ABI. No blanket register/FP save is needed:
// these are real replacement callees, not instrumentation inserted into an instruction stream.
__forceinline void OwnedService(Service service, void* receiver) {
    OwnedCurrent& occurrence = *g_ownedOccurrence;
    if (occurrence.serviceCount == 8 ||
        Address(receiver) != Address(g_ownedParticipant->work) + (service == WrapperQuery ? 0xF4 : 0))
        RefuseOwned(OwnedNeedsCapacity);
    occurrence.services |= service << (4 * occurrence.serviceCount++);
#ifdef NTW2_LOCO_ORACLE
    ObserveOwned(occurrence.entity, service, occurrence.ordinal, OwnedTestPort);
#endif
}
template <Service service> void __fastcall OwnedLink(void* agent, void*) {
    OwnedService(service, agent);
    if (service == UnlinkOwner) *reinterpret_cast<U*>(static_cast<unsigned char*>(agent) + 0x98) = 0;
}
U __fastcall OwnedQuery(void* descriptor, void*) {
    OwnedService(WrapperQuery, descriptor);
    return reinterpret_cast<U (__thiscall*)(void*)>(g_serviceTargets[WrapperQuery])(descriptor);
}
void __fastcall OwnedSweep(void* agent, void*, void* scratch, const ntw2_sweep::Aabb* box, U mode) {
    OwnedService(Sweep, agent);
    if (mode & 8) RefuseOwned(OwnedNeedsEnv);
    if (!ntw2_sweep::WorkerSweep(g_ownedParticipant->ctx->sweep, agent,
        g_ownedOccurrence->entity, scratch, *box, mode)) RefuseOwned(OwnedNeedsSweep);
}
uint8_t __fastcall OwnedResolve(void* agent, void*, void* scratch, const ntw2_resolve::Aabb* box) {
    OwnedService(Resolve, agent);
    uint8_t result = 0;
    if (!ntw2_resolve::WorkerResolve(g_ownedParticipant->ctx->resolve, agent,
        g_ownedOccurrence->entity, scratch, *box, result)) RefuseOwned(OwnedNeedsResolve);
    return result;
}
void __fastcall OwnedEnvironment(void* agent, void*, void* scratch) {
    OwnedService(HeightOwner, agent);
    if (!ntw2_env::WorkerEnv(g_ownedParticipant->ctx->env, agent,
        g_ownedOccurrence->entity, scratch, g_ownedOccurrence->environment)) RefuseOwned(OwnedNeedsEnv);
    // Buildings/owner graph and transition callbacks have not had a live oracle
    // replay. Preserve owner execution rather than extrapolate the flat-terrain proof.
    if (g_ownedOccurrence->environment.event_count || D(Address(agent) + 0x10))
        RefuseOwned(OwnedNeedsEnv);
}
// Worker gates never enter native mutation/scratch closures. Four link services
// have no stack arguments or meaningful return value; their receiver is the
// entire argument contract. The admitted A1==0 closure normally emits none.
U __stdcall WorkerServiceTarget(U service, U receiver, U ownerGate) {
    WorkerOccurrence* occurrence = g_workerOccurrence;
    if (!occurrence) return ownerGate;
    if (service == WrapperQuery) { ++occurrence->queryCount; return g_serviceTargets[service]; }
    if (service >= Sweep || receiver != Address(occurrence->output) || occurrence->eventCount == 4)
        RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    occurrence->events[occurrence->eventCount++] = {occurrence->entity, service, occurrence->entity};
    return 0;
}
#define LOCO_RECORDING_GATE(name, index, ownerGate) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm cmp dword ptr [g_parallelInFlight], 0 \
        __asm jne name##Worker \
        __asm cmp byte ptr [g_quiet], 0 \
        __asm je name##Owner \
        __asm popfd \
        __asm jmp dword ptr [g_serviceTargets + index * 4] \
        __asm name##Owner: \
        __asm popfd \
        __asm jmp ownerGate \
        __asm name##Worker: \
        __asm popfd \
        __asm lea esp, [esp-4] \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm push offset ownerGate \
        __asm push ecx \
        __asm push index \
        __asm call WorkerServiceTarget \
        __asm mov dword ptr [ebp+36], eax \
        __asm test eax, eax \
        __asm jz name##Recorded \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm ret \
        __asm name##Recorded: \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm lea esp, [esp+4] \
        __asm ret \
    }
LOCO_RECORDING_GATE(RecordUnlinkGridGate, 0, UnlinkGridGate)
LOCO_RECORDING_GATE(RecordUnlinkOwnerGate, 1, UnlinkOwnerGate)
LOCO_RECORDING_GATE(RecordInsertOwnerGate, 2, InsertOwnerGate)
LOCO_RECORDING_GATE(RecordInsertGridGate, 3, InsertGridGate)
LOCO_RECORDING_GATE(RecordSweepGate, 4, SweepGate)
LOCO_RECORDING_GATE(RecordResolveGate, 5, ResolveGate)
LOCO_RECORDING_GATE(RecordHeightOwnerGate, 6, HeightOwnerGate)
LOCO_RECORDING_GATE(RecordWrapperQueryGate, 7, WrapperQueryGate)
#undef LOCO_RECORDING_GATE

void StagingExit();
void __stdcall BeginStaging(U*) {
    g_stagingActive = !g_quiet && g_stage && g_binding.use_parallel;
    if (g_stagingActive) g_stagingStart = Now();
}
void __stdcall FinishStagingAfterReturn(U* returnSlot) {
    if (!g_stagingActive) return;
    g_stagingReturn = *returnSlot;
    *returnSlot = Address(reinterpret_cast<void*>(&StagingExit));
}
U __stdcall EndStaging() {
    g_parallelWords[ParallelStagingUs] += Microseconds(Now() - g_stagingStart);
    g_stagingActive = false;
    return g_stagingReturn;
}
__declspec(naked) void StagingExit() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call EndStaging
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
#define LOCO_STAGING_GATE(name, helper, target) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm lea eax, [ebp+36] \
        __asm push eax \
        __asm call helper \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [target] \
    }
LOCO_STAGING_GATE(StageGatherGate, BeginStaging, g_stageGatherTarget)
LOCO_STAGING_GATE(StageResetGate, FinishStagingAfterReturn, g_stageResetTarget)
#undef LOCO_STAGING_GATE

constexpr U kTables[] = {
    0x1333714, 0x13473D0, 0x13475E4, 0x13477F8, 0x13479B4,
    0x1347B70, 0x1347D2C, 0x1347EE8, 0x13480A4, 0x1348260,
    0x134841C, 0x132B7D8, 0x132BA04
};
static_assert(sizeof(kTables) / sizeof(kTables[0]) == kOwnedClasses, "private worker vtable inventory");
bool Candidate(U table, U* index = nullptr) {
    for (U i = 0; i < kOwnedClasses; ++i)
        if (table == V(kTables[i])) { if (index) *index = i; return true; }
    return false;
}
bool Stub(U target) {
    return target == V(0x444B60) || target == V(0x461180) ||
           target == V(0x462CB0) || target == V(0x447880) || target == V(0x62DF00);
}
bool Holder(U holder) {
    if (B(holder + 0x8F) != 1) return true;
    const U table = D(holder + 8);
    return table && Stub(D(table + 0xC)) && Stub(D(table + 0x14)) &&
           Stub(D(table + 0x24)) && Stub(D(table + 0x28));
}
bool ReferenceNode(U a) {
    if (B(a + 0x2C4) != 1) return true;
    const U n = a + 0x22C;
    if (D(n) != V(0x1334180) || D(n + 4) != a || !D(n + 0x14) || !D(n + 0x1C)) return false;
    static const U slots[13] = {
        0x624F80, 0x6666B0, 0x66E670, 0x461180, 0x461180, 0x461180,
        0x447880, 0x462CB0, 0x462CB0, 0x462CB0, 0x462CB0, 0x447880, 0x462CB0
    };
    for (U i = 0; i < 13; ++i) if (D(D(n) + i * 4) != V(slots[i])) return false;
    return D(D(n + 0x14) + 8) != 0;
}
bool ClassSlotsOk(U table) {
    return D(table + 0x10) == V(table == V(0x132BA04) ? 0x5B2CA0 : 0x62A290) &&
        D(table + 0x74) == V(0x64C780) && D(table + 0x70) == V(0x63D5B0) &&
        D(table + 0x64) == V(0x66B0F0);
}
bool ClassRouteOk(U a) {
    const U table = D(a);
    U index;
    if (!Candidate(table, &index)) return false;
    return g_owned && g_owned->activated ? g_owned->classRoute[index] : ClassSlotsOk(table);
}
U ContextModel(U a) {
    __try { const U context = D(a + 0x28); return context ? D(context + 8) : 0; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
bool EnvironmentOk(U a, U model) {
    __try {
        if (!B(a + 0xA1)) return true;
        return model && D(model + 0xA4) && D(model + 0xA8) &&
            D(a + 0xA8) && D(a + 0xB0) && D(a + 0xAC) <= D(a + 0xB0);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
U ClassifyImpl(U a) {
    if (!g_started || !a) return Lifetime;
    if (!ClassRouteOk(a)) return Class;
    const U model = ContextModel(a);
    if (!model) return Lifetime;
    if (D(a + 0x628)) return Parked;
    if (D(a + 0x18)) return Pending;
    if (!EnvironmentOk(a, model)) return Environment;
    // This is an instruction-identical, serial OWNER mover, not an owned NODE
    // or worker kernel. Activity, order, fire, target and holder state do not
    // authorize a different mover implementation. All native helper effects,
    // selector latches/staging and class-wrapper work retain their exact order.
    return Eligible;
}
bool NodeDiagnosticOk(U a, U gate, bool& fault) {
    // Borrowed NODE/holder shapes are diagnostic only. An unsupported shape
    // must not turn a valid owner-thread MOVE into a lifetime refusal.
    __try {
        switch (gate) {
        case GateReferenceNode: return ReferenceNode(a);
        case GateHolder2CC: return Holder(a + 0x2CC);
        case GateHolder51C: return Holder(a + 0x51C);
        default: {
            const U row = D(a + 0x444);
            if (!row || !D(row + 4) || D(a + 0x1C0) >= D(D(row + 4) + 0x50)) return false;
            return D(row) != 0x5D && D(row) != 0x5E;
        }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { fault = true; return false; }
}
inline bool Detail(U word, bool failed) {
    if (failed) ++g_gateWords[word];
    return failed;
}
inline U GateBit(U reason) { return 1u << (reason - 1); }
void CensusImpl(U a, U& reason) {
    if (!Candidate(D(a))) {
        ++g_gateWords[GateClass];
        ++g_gateWords[GateUnclassified];
        reason = Class;
        return; // no soldier-layout reads on unrelated classes
    }
    ++g_gateWords[GateCandidates];
    U failed = ClassRouteOk(a) ? 0 : GateBit(Class);
    const U model = ContextModel(a);
    if (!model) failed |= GateBit(Lifetime);
    if (D(a + 0x628)) failed |= GateBit(Parked);
    if (D(a + 0x18)) failed |= GateBit(Pending);
    if (!EnvironmentOk(a, model)) failed |= GateBit(Environment);
    // Compute admission once from the enforced gates, before examining any
    // diagnostic-only borrowed node/holder state.
    reason = Eligible;
    if (failed) for (U i = 0; i < 10; ++i) if (failed & (1u << i)) { reason = i + 1; break; }

    // Evaluate every old proof gate independently, including when an earlier
    // gate failed. These counters describe the intersection, not first-fail
    // attribution. The four detailed charge/fire words identify the exact
    // DWORD fields; the byte latches below were never the old fire predicate.
    const U activity = D(a + 0x1B8);
    U activityWord = GateActivityOther;
    switch (activity) {
    case 0: activityWord = GateActivity0; break;
    case 1: activityWord = GateActivity1; break;
    case 9: activityWord = GateActivity9; break;
    case 0x1D: activityWord = GateActivity1D; break;
    case 0x23: activityWord = GateActivity23; break;
    case 0xC: activityWord = GateActivity0C; break;
    }
    ++g_gateWords[activityWord];
    if (activity != 1 && activity != 9 && activity != 0x1D) failed |= GateBit(Activity);
    if (D(a + 0x1EC)) failed |= GateBit(Target);
    const bool charge = Detail(GateCharge4E8, D(a + 0x4E8) != 0);
    const bool fire = Detail(GateFire390, D(a + 0x390) != 0);
    const bool watchA = Detail(GateFire3BC, D(a + 0x3BC) != 0);
    const bool watchB = Detail(GateFire3C8, D(a + 0x3C8) != 0);
    if (charge || fire || watchA || watchB) failed |= GateBit(ChargeFire);
    const bool posture = Detail(GatePosture220, D(a + 0x220) != 0);
    const U order = D(a + 0x1D8);
    const bool orderFailed = Detail(GateOrder,
        ((activity == 1 || activity == 9) && order != 4) ||
        (activity == 0x1D && order != 0 && order != 4));
    if (posture || orderFailed) failed |= GateBit(PostureOrder);
    bool diagnosticFault = false;
    const bool row = Detail(GateSlotRow, activity == 0x1D &&
        !NodeDiagnosticOk(a, GateSlotRow, diagnosticFault));
    const bool node = Detail(GateReferenceNode, !NodeDiagnosticOk(a, GateReferenceNode, diagnosticFault));
    const bool holderA = Detail(GateHolder2CC, !NodeDiagnosticOk(a, GateHolder2CC, diagnosticFault));
    const bool holderB = Detail(GateHolder51C, !NodeDiagnosticOk(a, GateHolder51C, diagnosticFault));
    if (row || node || holderA || holderB) failed |= GateBit(Node);
    Detail(GateLatch618, B(a + 0x618) != 0);
    Detail(GateLatch619, B(a + 0x619) != 0);
    Detail(GateLatchF1, B(a + 0xF1) != 0);
    Detail(GateLatch5AB, B(a + 0x5AB) != 0);
    if (diagnosticFault) ++g_gateWords[GateDiagnosticFaults];
    for (U i = 0; i < 10; ++i) if (failed & (1u << i)) ++g_gateWords[GateClass + i];
    if (!failed) ++g_gateWords[GateLegacyAdmitted];
    if (reason == Eligible && failed) ++g_gateWords[GateNewlyAdmitted];
}
U Census(U a) {
    ++g_gateWords[GateEntities];
    U reason = Lifetime;
    __try { CensusImpl(a, reason); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_gateWords[GateDiagnosticFaults]; }
    if (reason == Eligible) ++g_gateWords[GateAdmitted];
    return reason;
}
void FinishServices() {
    Max(MaxEntityServices, g_entityServices);
    if (g_entityServices) ++g_words[ServicedEntities];
}

U WorkerReason(U a) {
    if (Classify(P(a)) != Eligible) return ParallelNeedsAdmission;
    if (D(a) == V(0x132BA04)) return ParallelNeedsClassWrapper;
    // Even motionless in-bounds A1!=0 reaches the unclosed 81AE40 closure.
    if (B(a + 0xA1)) return ParallelNeedsEnv;
    if (D(a + 0x10) || D(a + 0x18) || D(a + 0x170)) return ParallelNeedsRelationship;
    if (!B(a + 0xA3)) return ParallelNeedsStaging;
    return 0;
}
U CountEntity(U a) {
    ++g_words[Entities];
    const U reason = g_quiet ? Classify(P(a)) : Census(a);
    ++g_words[reason ? Rejected : Admitted];
    if (reason) ++g_words[RejectClass + reason - 1];
    if (Candidate(D(a))) {
        if (g_binding.use_owned_services) {
            if (B(a + 0xA1)) ++g_ownedWords[OwnedActiveEntities];
            if (B(a + 0xF0)) ++g_ownedDetails[OwnedDetailObservedF0];
            if (!B(a + 0xA3)) ++g_ownedDetails[OwnedDetailObservedInitialA3];
        }
        if (B(a + 0xEC) == 1) ++g_words[WrapperBattle];
        else if (D(a + 0x628) && D(a + 0x62C) == 4) {
            ++g_words[WrapperAlternate];
            if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailAlternate];
        }
        else ++g_words[Direct];
        if (D(a) == V(0x132BA04)) {
            ++g_words[ClassWrapper];
            if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailClassWrapper];
        }
    } else if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailOtherClass];
    return reason;
}
int WorkerFault(WorkerOccurrence& occurrence, EXCEPTION_POINTERS* exception) {
    occurrence.state = Faulted; occurrence.eventCount = 0;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_parallelWords[ParallelFaults]));
    if (!_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_parallelWords[ParallelSticky]), 1, 0)) {
        g_parallelWords[ParallelLastException] = exception->ExceptionRecord->ExceptionCode;
        g_parallelWords[ParallelLastEntity] = occurrence.entity;
        g_parallelWords[ParallelLastOrdinal] = occurrence.ordinal;
        g_parallelWords[ParallelLastEip] = exception->ContextRecord->Eip;
        const U code = exception->ExceptionRecord->ExceptionCode;
        g_parallelWords[ParallelLastAccess] = (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
            exception->ExceptionRecord->NumberParameters >= 2
            ? static_cast<U>(exception->ExceptionRecord->ExceptionInformation[1]) : 0;
        g_parallelWords[ParallelLastSerial] = occurrence.serial;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
void __fastcall ParallelChunk(void* context, U chunk) {
    ParallelJob& job = *static_cast<ParallelJob*>(context);
    const U saved = _mm_getcsr(); unsigned short cw, ownerCw = job.cw;
    __asm { fnstcw cw }
    _mm_setcsr(job.mxcsr);
    __asm { fldcw ownerCw }
    const U size = (job.count + job.chunks - 1) / job.chunks;
    U i = chunk * size;
    __try {
        __try {
            for (; i < (std::min)(job.count, (chunk + 1) * size); ++i) {
                WorkerOccurrence& occurrence = g_workers->occurrences[i];
                g_workerOccurrence = &occurrence;
                Call(occurrence.wrapper ? g_binding.wrap_clone : g_binding.move_clone, Address(occurrence.output));
                // The closed early-return path has no publication. A recorded
                // link here is a proof violation, never permission to continue.
                if (occurrence.eventCount) RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
                occurrence.state = Computed; g_workerOccurrence = nullptr;
            }
        } __except(WorkerFault(g_workers->occurrences[(std::min)(i, job.count - 1)], GetExceptionInformation())) {}
    } __finally {
        g_workerOccurrence = nullptr;
        __asm { fnclex }
        __asm { fldcw cw }
        _mm_setcsr(saved);
    }
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_parallelWords[
        GetCurrentThreadId() == job.owner ? ParallelInlineChunks : ParallelChunks]));
}
void CommitWorker(WorkerOccurrence& occurrence) {
    unsigned char* native = static_cast<unsigned char*>(P(occurrence.entity));
    const unsigned char* result = occurrence.output;
    // Exact A1==0 footprint, not whole-agent scatter or a shallow graph copy.
    static const U ranges[][2] = {{0x38,4},{0x54,4},{0x80,8},{0x88,4},{0xB8,24}};
    native[0x5ED] = native[0x5EC]; native[0x5EC] = 0;
    for (const auto& range : ranges) memcpy(native + range[0], result + range[0], range[1]);
    if (occurrence.wrapper) {
        static const U wrapperRanges[][2] = {
            {0x190,8},{0x1A4,4},{0x174,3},{0x199,1},{0x150,4},{0x14C,4},{0x18C,1}
        };
        for (const auto& range : wrapperRanges) memcpy(native + range[0], result + range[0], range[1]);
    }
}
U ParallelRun(U manager, U cursor, U end) {
    if (!g_binding.use_parallel || g_parallelWords[ParallelSticky]) return 0;
    const U list = D(manager + 0x264), count = D(manager + 0x260);
    U ready = 0;
    __try {
        for (U next = cursor; next != end && ready < kParallelRun; next += 4) {
            const U a = D(next);
            if (B(a + 0x30) != 1 || WorkerReason(a)) break;
            bool duplicate = false;
            for (U i = 0; i < ready; ++i) if (g_workers->occurrences[i].entity == a) { duplicate = true; break; }
            if (duplicate) { ++g_parallelWords[ParallelNeedsDuplicate]; break; }
            WorkerOccurrence& occurrence = g_workers->occurrences[ready++];
            occurrence.entity = a; occurrence.serial = D(a + 0x2C); occurrence.ordinal = (next - list) / 4;
            occurrence.wrapper = B(a + 0xEC) == 1;
            occurrence.state = Ready; occurrence.eventCount = occurrence.queryCount = 0;
            memcpy(occurrence.input, P(a), kPrivateBytes);
            memcpy(occurrence.output, occurrence.input, kPrivateBytes);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_parallelWords[ParallelInvalidated]; return 0;
    }
    if (!ready) return 0;
    ParallelJob job = {ready, (std::min)(ready, (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1))),
        GetCurrentThreadId(), _mm_getcsr(), 0};
    unsigned short cw;
    __asm { fnstcw cw }
    job.cw = cw;
    const LONGLONG start = Now();
    g_parallelInFlight = 1;
    __try {
        if (g_binding.dispatch) g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&ParallelChunk)), job.chunks, &job);
        else for (U i = 0; i < job.chunks; ++i) ParallelChunk(&job, i);
    } __finally { g_parallelInFlight = 0; }
    const LONGLONG elapsed = Now() - start;
    g_parallelWords[ParallelKernelUs] += Microseconds(elapsed);
    if (g_parallelWords[ParallelSticky]) return 0;
    // Every destination is revalidated before the first irreversible store.
    if (D(manager + 0x264) != list || D(manager + 0x260) != count) {
        ++g_parallelWords[ParallelInvalidated]; return 0;
    }
    for (U i = 0; i < ready; ++i) {
        const WorkerOccurrence& occurrence = g_workers->occurrences[i];
        if (occurrence.state != Computed || D(cursor + i * 4) != occurrence.entity ||
            memcmp(P(occurrence.entity), occurrence.input, kPrivateBytes) || WorkerReason(occurrence.entity)) {
            ++g_parallelWords[ParallelInvalidated]; return 0;
        }
    }
    const LONGLONG replayStart = Now();
    for (U i = 0; i < ready; ++i) {
        WorkerOccurrence& occurrence = g_workers->occurrences[i];
        CountEntity(occurrence.entity); CommitWorker(occurrence); ++g_words[Cloned];
        ResetServiceTrace();
        for (U n = 0; n < occurrence.queryCount; ++n) RecordService(WrapperQuery, occurrence.entity + 0xF4);
        FinishServices();
        ++g_parallelWords[ParallelWorkerEntities]; ++g_parallelWords[ParallelCommitted];
    }
    g_parallelWords[ParallelReplayUs] += Microseconds(Now() - replayStart);
    g_parallelWords[ParallelMaxWorkerRun] = (std::max)(g_parallelWords[ParallelMaxWorkerRun], ready);
    g_words[AdmittedUs] += Microseconds(elapsed); RecordCloneTime(elapsed);
    return ready;
}

void DestroyOwned() {
    if (!g_owned) return;
    OwnedArena* arena = g_owned;
    g_owned = nullptr;
    for (OwnedParticipant*& participant : arena->participants) {
        if (!participant) continue;
        if (participant->clones.allocation) VirtualFree(participant->clones.allocation, 0, MEM_RELEASE);
        delete participant->ctx;
        participant->~OwnedParticipant();
        _aligned_free(participant);
        participant = nullptr;
    }
    if (arena->movement) VirtualFree(arena->movement, 0, MEM_RELEASE);
    arena->~OwnedArena();
    _aligned_free(arena);
}
// Start: only the small per-participant state and its private clone pair exist. The heavy sweep/resolve/environment
// contexts and every capacity-sized buffer are created by ActivateOwned from the actual workers+caller count.
bool CreateOwned() {
    if (!g_binding.use_owned_services) return true;
    void* const raw = _aligned_malloc(sizeof(OwnedArena), 64);
    if (!raw) return false;
    g_owned = new (raw) OwnedArena;
    for (U i = 0; i < kOwnedClasses; ++i) {
        const U table = V(kTables[i]);
        g_owned->classRoute[i] = ClassSlotsOk(table);
        g_owned->predicate67C[i] = D(table + 0xE8) == V(0x5DB820) ||
            D(table + 0xEC) == V(0x5DB820) || D(table + 0xF0) == V(0x5DB820);
        g_owned->predicateLinkByte[i] = D(table + 0x3C) == V(0x54E920) || D(table + 0x50) == V(0x54E920);
        memcpy(g_owned->virtualTables[i], P(V(kTables[i])), sizeof(g_owned->virtualTables[i]));
        g_owned->virtualTables[i][0x70 / 4] = Address(reinterpret_cast<void*>(&OwnedClamp));
    }
    g_owned->participantsCount = (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1));
    for (U i = 0; i < g_owned->participantsCount; ++i) {
        void* const memory = _aligned_malloc(sizeof(OwnedParticipant), 64);
        if (!memory) { DestroyOwned(); return false; }
        OwnedParticipant& participant = *new (memory) OwnedParticipant;
        g_owned->participants[i] = &participant;
        U bindings[NTW2_BIND_COUNT];
        memcpy(bindings, g_locoBindings, sizeof(bindings));
        participant.first[0] = V(0x1312358);
        bindings[NTW2_BIND_LOCO_SCRATCH_14543B4] = Address(participant.first);
        bindings[NTW2_BIND_LOCO_SCRATCH_15A1888] = Address(participant.second);
        bindings[NTW2_BIND_LOCO_SCRATCH_15A189C] = Address(participant.third);
        bindings[NTW2_BIND_LOCO_SERVICE_811ED0] = Address(reinterpret_cast<void*>(&OwnedLink<UnlinkGrid>));
        bindings[NTW2_BIND_LOCO_SERVICE_811D50] = Address(reinterpret_cast<void*>(&OwnedLink<UnlinkOwner>));
        bindings[NTW2_BIND_LOCO_SERVICE_7EFDD0] = Address(reinterpret_cast<void*>(&OwnedLink<InsertOwner>));
        bindings[NTW2_BIND_LOCO_SERVICE_7EFA80] = Address(reinterpret_cast<void*>(&OwnedLink<InsertGrid>));
        bindings[NTW2_BIND_LOCO_SERVICE_801140] = Address(reinterpret_cast<void*>(&OwnedSweep));
        bindings[NTW2_BIND_LOCO_SERVICE_80F290] = Address(reinterpret_cast<void*>(&OwnedResolve));
        bindings[NTW2_BIND_LOCO_SERVICE_81AE40] = Address(reinterpret_cast<void*>(&OwnedEnvironment));
        bindings[NTW2_BIND_LOCO_SERVICE_814AA0] = Address(reinterpret_cast<void*>(&OwnedQuery));
        if (ntw2_build_loco_participant(g_binding.wrap_clone, g_binding.move_clone, bindings, &participant.clones)) {
            DestroyOwned(); return false;
        }
    }
    return true;
}
// Worker-side classification: reads only this entity's own cache lines plus static class/context state.
U OwnedReason(U a, U& classIndex) {
    if (!Candidate(D(a), &classIndex) || !g_owned->classRoute[classIndex]) return OwnedNeedsUnit;
    if (D(a) == V(0x132BA04)) return OwnedNeedsClassWrapper;
    if (B(a + 0xEC) != 1 && D(a + 0x628) && D(a + 0x62C) == 4) return OwnedNeedsAlternateWrapper;
    if (D(a + 0x18)) return OwnedNeedsPending;
    if (D(a + 0x170)) return OwnedNeedsForeignTransform;
    if (D(a + 0x10)) return OwnedNeedsEnv;
    const U model = ContextModel(a);
    if (!model || D(a + 0x628) || !EnvironmentOk(a, model)) return OwnedNeedsUnit;
    // The alternative secondary terrain vtable is not the proven bilinear sampler.
    if (B(a + 0xB4) && B(a + 0xB5) && D(model + 0xE0)) return OwnedNeedsEnv;
    return 0;
}
int OwnedFilter(OwnedCurrent& current, EXCEPTION_POINTERS* exception) {
    if (exception->ExceptionRecord->ExceptionCode == kOwnedUnsupported && current.reason)
        return EXCEPTION_EXECUTE_HANDLER;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ownedWords[OwnedFaults]));
    WorkerOccurrence fault{};
    fault.entity = current.entity; fault.serial = current.serial; fault.ordinal = current.ordinal;
    return WorkerFault(fault, exception);
}
__declspec(noinline) void OwnedRaiseFault(OwnedCurrent& current) {
    __try { RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr); }
    __except(OwnedFilter(current, GetExceptionInformation())) {}
}
// One worklist ordinal. Returns false only after a REAL fault (sticky is set; the chunk stops, the entity stays
// Unprocessed and every later one runs natively). Refusals are per entity and never touch siblings.
bool OwnedRunEntity(OwnedArena& arena, OwnedParticipant& participant, U index) {
    OwnedSlot& slot = arena.slots[index];
    OwnedCurrent& current = participant.current;
    const U a = arena.worklist[index];
    slot.entity = a;
    if (B(a + 0x30) != 1) { arena.states[index] = OwnedSkipped; return true; }
    current.entity = a; current.ordinal = index; current.serial = D(a + 0x2C);
    current.services = 0; current.serviceCount = 0; current.reason = 0; current.detail = 0;
    current.environment = {};
    U classIndex = kNoOccurrence;
    const U reason = OwnedReason(a, classIndex);
    if (reason) {
        slot.reason = static_cast<unsigned char>(reason); slot.detail = 0;
        arena.states[index] = OwnedRefused; return true;
    }
    slot.active = B(a + 0xA1) != 0; slot.wrapper = B(a + 0xEC) == 1;
    // The private receiver keeps the whole prefix; the slot keeps only the audited live-in guard footprint.
    const unsigned char* const live = static_cast<const unsigned char*>(P(a));
    unsigned char* const work = participant.work;
    memcpy(work, live, kOwnedPrefix);
    GatherGuard(slot, live);
    slot.inputLatch = live[0x5EC];
    slot.readsPredicate = slot.active && arena.predicate67C[classIndex];
    slot.inputPredicate = slot.readsPredicate ? D(a + 0x67C) : 0;
    slot.readsLinkByte = slot.active && arena.predicateLinkByte[classIndex];
    slot.inputLinkByte = slot.readsLinkByte ? live[4] : 0;
    const bool initialA3 = work[0xA3] != 0;
    // The private vptr never reaches native memory: every slot equals the class table except +70 (clamp trap).
    const U privateTable = Address(arena.virtualTables[classIndex]);
    memcpy(work, &privateTable, sizeof(privateTable));
    work[0x5ED] = slot.inputLatch; work[0x5EC] = 0; // selector latch rollover
    memcpy(work + 0x67C, &slot.inputPredicate, sizeof(slot.inputPredicate));
    // Headers are participant-private; a refused call can have left a count behind.
    participant.first[3] = participant.second[2] = participant.third[2] = 0;
    bool ok = false;
    __try {
        Call(participant.clones.entries[slot.wrapper ? NTW2_CLONE_LOCO_WRAP : NTW2_CLONE_LOCO_MOVE], Address(work));
        // 62A290 tests the POST-MOVE A3 byte: zero really does stage. Never inverted.
        if (!work[0xA3])
            RefuseOwned(OwnedNeedsStaging, initialA3 ? OwnedDetailResultA3 : OwnedDetailInitialA3);
        ok = true;
    } __except(OwnedFilter(current, GetExceptionInformation())) {}
    if (!ok) {
        // A refusal/fault unwound out of the middle of the private mover: its x87 stack is unknown.
        const unsigned short controlWord = arena.cw;
        __asm { fninit }
        __asm { fldcw controlWord }
        if (current.reason) {
            slot.reason = current.reason; slot.detail = current.detail;
            arena.states[index] = OwnedRefused; return true;
        }
        arena.states[index] = OwnedUnprocessed; return false;
    }
    slot.reason = 0; slot.detail = 0;
    slot.services = current.services; slot.serviceCount = current.serviceCount;
    GatherOutput(slot, work);
    slot.resultLatches[0] = work[0x5EC]; slot.resultLatches[1] = work[0x5ED];
    arena.states[index] = OwnedComputed;
    return true;
}
// ntw_pool_dispatch body: ONE dispatch per stage, chunk = contiguous worklist range claimed atomically by the pool.
// The participant (clone pair, scratch, port contexts, receiver) is acquired once per thread per dispatch.
ULONGLONG ThreadCpu100ns() {
    FILETIME created, exited, kernel, user;
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) return 0;
    return (static_cast<ULONGLONG>(kernel.dwHighDateTime) << 32) + kernel.dwLowDateTime +
           (static_cast<ULONGLONG>(user.dwHighDateTime) << 32) + user.dwLowDateTime;
}
void __fastcall OwnedChunk(void* context, U chunk) {
    OwnedArena& arena = *static_cast<OwnedArena*>(context);
    if (g_parallelWords[ParallelSticky]) return; // untouched ordinals stay Unprocessed and run natively
    if (g_ownedEpoch != arena.epoch) {
        g_ownedEpoch = arena.epoch; g_ownedParticipant = nullptr;
        const LONG slotIndex = _InterlockedIncrement(&arena.nextParticipant) - 1;
        if (static_cast<U>(slotIndex) < arena.participantsCount) {
            OwnedParticipant& acquired = *arena.participants[slotIndex];
            acquired.first[2] = acquired.first[3] = acquired.first[4] = 0;
            acquired.second[1] = acquired.second[2] = acquired.second[3] = 0;
            acquired.third[1] = acquired.third[2] = acquired.third[3] = 0;
            acquired.maximum = 0;
            acquired.cpu100ns = acquired.cpuAtMaximum100ns = 0;
            g_ownedParticipant = &acquired;
        }
    }
    OwnedParticipant* const participant = g_ownedParticipant;
    if (!participant) { _InterlockedIncrement(&arena.overflow); return; }
    const U begin = chunk * arena.chunkSize;
    const U end = (std::min)(arena.count, begin + arena.chunkSize);
    const U savedCsr = _mm_getcsr();
    unsigned short savedCw, installedCw, ownerCw = arena.cw;
    __asm { fnstcw savedCw }
    g_ownedOccurrence = &participant->current;
    U computed = 0, refused = 0;
    const LONGLONG start = Now();
    const ULONGLONG cpuStart = ThreadCpu100ns();
    __try {
        // Full controls, not just rounding: FTZ, DAZ and x87 precision all participate in the native arithmetic.
        _mm_setcsr(arena.mxcsr);
        __asm { fnclex }
        __asm { fldcw ownerCw }
        __asm { fnstcw installedCw }
        if (_mm_getcsr() != arena.mxcsr || installedCw != ownerCw) {
            participant->current.entity = arena.worklist[begin]; participant->current.ordinal = begin;
            participant->current.serial = 0; participant->current.reason = 0;
            OwnedRaiseFault(participant->current);
        } else {
            for (U i = begin; i < end; ++i) {
                if (g_parallelWords[ParallelSticky]) break;
                if (i + 4 < arena.count) {
                    const U ahead = arena.worklist[i + 4];
                    for (U line = 0; line < kOwnedPrefix; line += 64) _mm_prefetch(reinterpret_cast<const char*>(ahead + line), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x5EC), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x67C), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x628), _MM_HINT_T0);
                }
                if (!OwnedRunEntity(arena, *participant, i)) break;
                const unsigned char state = arena.states[i];
                if (state == OwnedComputed) ++computed; else if (state == OwnedRefused) ++refused;
            }
        }
    } __finally {
        g_ownedOccurrence = nullptr;
        __asm { fnclex }
        __asm { fldcw savedCw }
        _mm_setcsr(savedCsr);
    }
    const LONGLONG ticks = Now() - start;
    const ULONGLONG cpuEnd = ThreadCpu100ns();
    const ULONGLONG cpu = cpuStart && cpuEnd >= cpuStart ? cpuEnd - cpuStart : 0;
    participant->cpu100ns += cpu;
    const U us = Microseconds(ticks);
    _InterlockedExchangeAdd(&arena.chunkTimeUs, static_cast<LONG>(us));
    _InterlockedExchangeAdd(&arena.computed, static_cast<LONG>(computed));
    _InterlockedExchangeAdd(&arena.refused, static_cast<LONG>(refused));
    _InterlockedIncrement(&arena.histogram[us <= 16 ? 0 : us <= 32 ? 1 : us <= 64 ? 2 : us <= 128 ? 3 :
        us <= 256 ? 4 : us <= 512 ? 5 : us <= 1024 ? 6 : 7]);
    if (ticks > participant->maximum) {
        participant->maximum = ticks; participant->cpuAtMaximum100ns = cpu;
    }
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_parallelWords[
        GetCurrentThreadId() == arena.owner ? ParallelInlineChunks : ParallelChunks]));
}
// Activation only: full scene/catalog construction and participant scratch preparation.
struct OwnedCapture {
    U model, sceneUs = 0, catalogUs = 0;
    bool ready = false;
};
int ActivationException(EXCEPTION_POINTERS* exception) {
    g_ownedLoad[OwnedLoadException] = exception->ExceptionRecord->ExceptionCode;
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        exception->ExceptionRecord->NumberParameters >= 2)
        g_ownedLoad[OwnedLoadDetail] = static_cast<U>(exception->ExceptionRecord->ExceptionInformation[1]);
    return EXCEPTION_EXECUTE_HANDLER;
}
void CaptureOwnedPorts(OwnedCapture& capture) {
    OwnedArena& arena = *g_owned;
    LONGLONG t = Now();
    g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneCapture;
    bool ok = ntw2_sweep::PrepareScene(arena.scene, capture.model, g_delta, g_generation);
    LONGLONG next = Now(); capture.sceneUs = Microseconds(next - t); t = next;
    if (ok) {
        g_ownedLoad[OwnedLoadFailureReason] = ActivationCatalog;
        ok = ntw2_resolve::PrepareCatalog(arena.catalog, arena.scene);
        capture.catalogUs = Microseconds(Now() - t);
    }
    if (!ok) {
        if (arena.scene.failure == ntw2_sweep::SceneVerificationFailure)
            g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneVerification;
        else if (arena.scene.failure == ntw2_sweep::SceneIdentityFailure)
            g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneIdentity;
        g_ownedLoad[OwnedLoadDetail] = arena.scene.failureAddress;
        g_ownedLoad[OwnedLoadActual] = arena.scene.failureActual;
    }
    capture.ready = ok;
}
void CaptureOwnedPortsCatching(OwnedCapture& capture) {
    try { CaptureOwnedPorts(capture); }
    catch (const std::bad_alloc&) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; }
}
void CaptureOwnedPortsGuarded(void* context) {
    OwnedCapture& capture = *static_cast<OwnedCapture*>(context);
    __try { CaptureOwnedPortsCatching(capture); }
    __except(ActivationException(GetExceptionInformation())) { capture.ready = false; }
}
bool PrepareOwnedWorkers() {
    OwnedArena& arena = *g_owned;
    for (U i = 0; i < arena.participantsCount; ++i) {
        OwnedParticipant& participant = *arena.participants[i];
        g_ownedLoad[OwnedLoadFailureReason] = ActivationSweepWorker;
        if (!participant.ctx) {
            participant.ctx = new (std::nothrow) OwnedContexts;
            if (!participant.ctx) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; return false; }
        }
        OwnedContexts& context = *participant.ctx;
        if (!ntw2_sweep::PrepareWorker(context.sweep, arena.scene)) return false;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationResolveWorker;
        if (!ntw2_resolve::PrepareWorker(context.resolve, arena.catalog)) return false;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationEnvWorker;
        if (!ntw2_env::PrepareWorker(context.env, arena.scene)) return false;
        context.sweep.fp = context.resolve.fp = context.env.fp = {arena.mxcsr, arena.cw};
        context.sweep.fp_managed = context.resolve.fp_managed = context.env.fp_managed = true;
    }
    return true;
}
bool PrepareOwnedWorkersCatching() {
    try { return PrepareOwnedWorkers(); }
    catch (const std::bad_alloc&) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; return false; }
}
// Touch every page so the first tick never takes a demand-zero fault (VirtualAlloc pages are already zero).
void Prefault(void* base, size_t bytes) {
    volatile unsigned char* const page = static_cast<volatile unsigned char*>(base);
    for (size_t offset = 0; offset < bytes; offset += 4096) page[offset] = 0;
}
// One block: slots[capacity] | worklist[capacity] | states[capacity]. capacity is the PRIMARY occurrence capacity.
bool AllocateOwnedSlots(OwnedArena& arena, U capacity) {
    const unsigned long long slotBytes = static_cast<unsigned long long>(capacity) * sizeof(OwnedSlot),
        listBytes = static_cast<unsigned long long>(capacity) * sizeof(U), total = slotBytes + listBytes + capacity;
    if (total > 0x7FFFFFFFull) return false;
    unsigned char* const block = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(total), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!block) return false;
    arena.movement = block; arena.movementBytes = static_cast<U>(total);
    arena.slots = reinterpret_cast<OwnedSlot*>(block);
    arena.worklist = reinterpret_cast<U*>(block + slotBytes);
    arena.states = block + slotBytes + listBytes; // zero == OwnedUnprocessed
    Prefault(block, static_cast<size_t>(total));
    arena.slotCapacity = capacity;
    return true;
}
void WarmOwnedClones(U model) {
    alignas(16) unsigned char fp[512];
    __asm { fxsave fp }
    __try {
        U context[3] = {0, 0, model};
        for (U i = 0; i < g_owned->participantsCount; ++i) {
            OwnedParticipant& p = *g_owned->participants[i];
            memset(p.work, 0, sizeof(p.work));
            *reinterpret_cast<U*>(p.work) = Address(g_owned->virtualTables[0]);
            *reinterpret_cast<U*>(p.work + 0x28) = Address(context);
            p.work[0xA3] = p.work[0xEC] = p.work[0x13D] = 1;
            // A1==0: private arithmetic only; +13D bypasses descriptor queries in the wrapper.
            Call(p.clones.entries[NTW2_CLONE_LOCO_WRAP], Address(p.work));
            memset(p.work, 0, sizeof(p.work));
        }
    } __finally {
        __asm { fxrstor fp }
    }
}
LONG g_ownedEpochCounter; // never reset: stale thread-local participants cannot match a recreated arena
void PrepareOwned(U manager) {
    if (!g_owned || g_parallelWords[ParallelSticky]) return;
    OwnedArena& arena = *g_owned;
    arena.valid = false; arena.failureReason = OwnedNeedsUnit;
    const LONGLONG begin = Now();
    arena.list = D(manager + 0x264); arena.count = D(manager + 0x260);
    if (!arena.count) return;
    if (!arena.activated || arena.count > arena.slotCapacity) {
        ++g_ownedLoad[OwnedLoadCapacityRefusals]; arena.failureReason = OwnedNeedsCapacity; return;
    }
    const U model = D(D(manager) + 8);
    if (model != arena.activationModel) {
        ++g_ownedLoad[OwnedLoadModelChanges]; arena.failureReason = OwnedNeedsSweep; return;
    }
    memcpy(arena.worklist, P(arena.list), arena.count * sizeof(U));
    memset(arena.states, OwnedUnprocessed, arena.count);
    arena.mxcsr = _mm_getcsr();
    unsigned short cw; __asm { fnstcw cw }
    arena.cw = cw; arena.owner = GetCurrentThreadId();
    const U participants = arena.participantsCount;
    U size = arena.count / (participants * 32);
    size = (std::max)(kOwnedChunkMin, (std::min)(kOwnedChunkMax, (size + 7) & ~7u));
    arena.chunkSize = size; arena.chunks = (arena.count + size - 1) / size;
    arena.epoch = ++g_ownedEpochCounter; arena.nextParticipant = 0; arena.overflow = 0;
    arena.computed = arena.refused = arena.chunkTimeUs = 0;
    for (auto& bucket : arena.histogram) bucket = 0;
    const LONGLONG identityStart = Now();
    // Already activated: PrepareScene performs only fixed-size identity/header checks.
    const bool ready = ntw2_sweep::PrepareScene(arena.scene, model, g_delta, g_generation);
    const U sceneUs = Microseconds(Now() - identityStart), catalogUs = 0;
    const LONGLONG fpStart = Now();
    for (U i = 0; i < participants; ++i) {
        OwnedParticipant& p = *arena.participants[i];
        p.ctx->sweep.fp = p.ctx->resolve.fp = p.ctx->env.fp = {arena.mxcsr, arena.cw};
        p.maximum = 0; p.cpu100ns = p.cpuAtMaximum100ns = 0;
    }
    const U workerUs = Microseconds(Now() - fpStart);
    const U prepareUs = Microseconds(Now() - begin);
    g_ownedWords[OwnedCaptureUs] += prepareUs;
    g_ownedPhase[OwnedPhaseIndexUs] += prepareUs - (std::min)(prepareUs, sceneUs + catalogUs + workerUs);
    g_ownedPhase[OwnedPhaseScenePrepareUs] += sceneUs;
    g_ownedPhase[OwnedPhaseCatalogPrepareUs] += catalogUs;
    g_ownedPhase[OwnedPhaseWorkerPrepareUs] += workerUs;
    g_ownedPhase[OwnedPhaseListEntities] += arena.count;
    if (!ready) { ++g_ownedLoad[OwnedLoadModelChanges]; arena.failureReason = OwnedNeedsSweep; return; }
    arena.valid = true;
    const LONGLONG kernel = Now();
    g_parallelInFlight = 1;
    // One synchronous dispatch per stage; no live publication is permitted before the join.
    if (g_binding.dispatch)
        g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&OwnedChunk)), arena.chunks, &arena);
    else for (U i = 0; i < arena.chunks; ++i) OwnedChunk(&arena, i);
    g_parallelInFlight = 0;
    const U elapsed = Microseconds(Now() - kernel);
    g_ownedWords[OwnedKernelUs] += elapsed; g_parallelWords[ParallelKernelUs] += elapsed;
    g_ownedPhase[OwnedPhaseDispatchWallUs] += elapsed;
    ++g_ownedPhase[OwnedPhaseDispatches];
    g_ownedPhase[OwnedPhaseChunks] += arena.chunks;
    g_ownedWords[OwnedChunks] += arena.chunks;
    g_ownedPhase[OwnedPhaseChunkSizeLast] = arena.chunkSize;
    g_ownedPhase[OwnedPhaseMaxChunkEntities] = (std::max)(g_ownedPhase[OwnedPhaseMaxChunkEntities],
        (std::min)(arena.chunkSize, arena.count));
    for (U b = 0; b < kOwnedHistogram; ++b) g_ownedPhase[OwnedPhaseChunkLe16 + b] += static_cast<U>(arena.histogram[b]);
    g_ownedWords[OwnedWorkerTimeUs] += static_cast<U>(arena.chunkTimeUs);
    g_ownedPhase[OwnedPhaseChunkTimeSumUs] += static_cast<U>(arena.chunkTimeUs);
    g_ownedPhase[OwnedPhaseComputed] += static_cast<U>(arena.computed);
    g_ownedPhase[OwnedPhaseWorkerRefused] += static_cast<U>(arena.refused);
    g_ownedPhase[OwnedPhaseParticipantOverflow] += static_cast<U>(arena.overflow);
    g_ownedPhase[OwnedPhaseParticipantsUsed] += (std::min)(participants, static_cast<U>(arena.nextParticipant));
    for (U i = 0; i < participants; ++i) {
        const OwnedParticipant& p = *arena.participants[i];
        const U wall = Microseconds(p.maximum);
        g_ownedWords[OwnedMaxChunkUs] = (std::max)(g_ownedWords[OwnedMaxChunkUs], wall);
        g_ownedLoad[OwnedLoadChunkCpuUs] += static_cast<U>(p.cpu100ns / 10);
        if (wall > g_ownedLoad[OwnedLoadChunkWallMaxUs]) {
            g_ownedLoad[OwnedLoadChunkWallMaxUs] = wall;
            g_ownedLoad[OwnedLoadChunkCpuAtWallMaxUs] = static_cast<U>(p.cpuAtMaximum100ns / 10);
        }
    }
    U unprocessed = 0;
    for (U i = 0; i < arena.count; ++i) unprocessed += arena.states[i] == OwnedUnprocessed;
    g_ownedPhase[OwnedPhaseUnprocessed] += unprocessed;
}
void CountCommitted(const OwnedSlot& slot) {
    ++g_words[Entities]; ++g_words[Admitted];
    if (slot.active) ++g_ownedWords[OwnedActiveEntities];
    if (GuardByte<0xF0>(slot)) ++g_ownedDetails[OwnedDetailObservedF0];
    if (!GuardByte<0xA3>(slot)) ++g_ownedDetails[OwnedDetailObservedInitialA3];
    ++g_words[slot.wrapper ? WrapperBattle : Direct];
}
void InvalidateOwned(OwnedArena& arena, U cursor) {
    arena.valid = false; arena.failureReason = OwnedNeedsUnit; ++g_parallelWords[ParallelInvalidated];
    if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[OwnedNeedsUnit];
}
bool CommitOwned(U manager, U cursor) {
    if (!g_owned || g_parallelWords[ParallelSticky]) return false;
    OwnedArena& arena = *g_owned;
    if (!arena.valid) {
        if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[arena.failureReason];
        return false;
    }
    // A fallback that changed the worklist shape (erase-shift, reallocation) invalidates every prepared ordinal.
    if (D(manager + 0x264) != arena.list || D(manager + 0x260) != arena.count ||
        cursor < arena.list || (cursor - arena.list) / 4 >= arena.count) { InvalidateOwned(arena, cursor); return false; }
    const U index = (cursor - arena.list) / 4;
    const unsigned char state = arena.states[index];
    if (state == OwnedSkipped) return false;
    // Never inspect the slot of an ordinal no worker reached: its contents are stale.
    if (state == OwnedUnprocessed) {
        if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[OwnedNeedsCapacity];
        return false;
    }
    OwnedSlot& slot = arena.slots[index];
    if (D(cursor) != slot.entity) { InvalidateOwned(arena, cursor); return false; }
    if (index + 6 < arena.count) {
        const U ahead = D(arena.list + (index + 6) * 4);
        for (U line = 0; line < kOwnedPrefix; line += 64) _mm_prefetch(reinterpret_cast<const char*>(ahead + line), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x5EC), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x67C), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x628), _MM_HINT_T0);
    }
    if (state == OwnedRefused) {
        ++g_ownedWords[slot.reason];
        if (slot.detail) ++g_ownedDetails[slot.detail];
        return false;
    }
    if (state != OwnedComputed) { ++g_ownedWords[OwnedNeedsCapacity]; return false; }
    const bool sample = !(++g_ownedReplaySeq & 15);
    const LONGLONG sampleStart = sample ? Now() : 0;
    const unsigned char* const live = static_cast<const unsigned char*>(P(slot.entity));
    // An earlier fallback/replay may have changed this very receiver (duplicate occurrence, class-wrapper children
    // callbacks...): the speculative result is stale, so this one entity runs natively at its ordinal.
    if (!OwnedGuardMatches(slot, live)) {
        ++g_ownedWords[OwnedNeedsUnit]; ++g_ownedWords[OwnedDuplicateRefusals];
        ++g_ownedPhase[OwnedPhaseValidationRefusals]; ++g_parallelWords[ParallelInvalidated];
        return false;
    }
    if (g_quiet) CountCommitted(slot); else CountEntity(slot.entity);
    if (!g_quiet) ResetServiceTrace();
    // Unlinks see the native pre-step receiver and live chain links. The result footprint is installed only
    // between unlink and insert; links, soft nodes, counts and owner masks are never copied from a stale snapshot.
    bool committed = false;
    for (U i = 0; i < slot.serviceCount; ++i) {
        const U service = (slot.services >> (4 * i)) & 15;
        if (service == InsertOwner || service == InsertGrid) {
            if (!committed) { CommitOwnedFields(slot); committed = true; }
        }
#ifdef NTW2_LOCO_ORACLE
        ObserveOwned(slot.entity, service, index, OwnedTestReplay);
#endif
        if (!g_quiet) RecordService(service, slot.entity + (service == WrapperQuery ? 0xF4 : 0));
        if (service < Sweep) {
            Call(g_serviceTargets[service], slot.entity);
            ++g_ownedWords[OwnedReplayUnlinkGrid + service];
        }
        ++g_parallelWords[ParallelReplayedServices];
    }
    if (!committed) CommitOwnedFields(slot);
    arena.states[index] = OwnedCommitted;
    g_gridCommittedReady = true;
    // Predicted transition events are env_untested and refuse before commit. No staging transaction is admitted.
    if (!g_quiet) FinishServices();
    ++g_words[Cloned]; ++g_parallelWords[ParallelWorkerEntities]; ++g_parallelWords[ParallelCommitted];
    ++g_ownedWords[slot.active ? (slot.wrapper ? OwnedWorkerBattle : OwnedWorkerDirect) : OwnedWorkerInactive];
    if (GuardByte<0xF0>(slot)) ++g_ownedDetails[OwnedDetailWorkerF0];
    if (sample) {
        g_replayCommitTicks += Now() - sampleStart;
        g_ownedPhase[OwnedPhaseReplayCommitEstUs] = Microseconds(g_replayCommitTicks * 16);
        ++g_ownedPhase[OwnedPhaseReplaySamples];
    }
    return true;
}
void FreeScratch(U* header, bool polymorphic) {
    const U data = header[polymorphic ? 4 : 3];
    // 444B60 is the pinned one-byte RET element destructor; no pointee owns
    // storage. Only the native allocator's backing buffer needs destruction.
    if (data) reinterpret_cast<Free>(V(0xFF7EF0))(P(data));
    memset(header, 0, (polymorphic ? 5 : 4) * sizeof(U));
    if (polymorphic) header[0] = V(0x1312358);
}
} // namespace

void Bind(U image_delta, U* bindings) {
    g_delta = image_delta;
    g_stageGatherTarget = V(0x7FC120); g_stageResetTarget = V(0x7F7140);
    bindings[NTW2_BIND_LOCO_STAGE_GATHER] = Address(reinterpret_cast<void*>(&StageGatherGate));
    bindings[NTW2_BIND_LOCO_STAGE_RESET] = Address(reinterpret_cast<void*>(&StageResetGate));
    bindings[NTW2_BIND_LOCO_SCRATCH_14543B4] = Address(g_scratchFirst);
    bindings[NTW2_BIND_LOCO_SCRATCH_15A1888] = Address(g_scratchSecond);
    bindings[NTW2_BIND_LOCO_SCRATCH_15A189C] = Address(g_scratchThird);
    bindings[NTW2_BIND_LOCO_GUARD_15A1884] = Address(&g_guards[0]);
    bindings[NTW2_BIND_LOCO_GUARD_15A1898] = Address(&g_guards[1]);
    bindings[NTW2_BIND_LOCO_GUARD_15A18AC] = Address(&g_guards[2]);
    bindings[NTW2_BIND_LOCO_SERVICE_811ED0] = Address(reinterpret_cast<void*>(&RecordUnlinkGridGate));
    bindings[NTW2_BIND_LOCO_SERVICE_811D50] = Address(reinterpret_cast<void*>(&RecordUnlinkOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_7EFDD0] = Address(reinterpret_cast<void*>(&RecordInsertOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_7EFA80] = Address(reinterpret_cast<void*>(&RecordInsertGridGate));
    bindings[NTW2_BIND_LOCO_SERVICE_801140] = Address(reinterpret_cast<void*>(&RecordSweepGate));
    bindings[NTW2_BIND_LOCO_SERVICE_80F290] = Address(reinterpret_cast<void*>(&RecordResolveGate));
    bindings[NTW2_BIND_LOCO_SERVICE_81AE40] = Address(reinterpret_cast<void*>(&RecordHeightOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_814AA0] = Address(reinterpret_cast<void*>(&RecordWrapperQueryGate));
    const U targets[ServiceCount] = {0x811ED0, 0x811D50, 0x7EFDD0, 0x7EFA80, 0x801140, 0x80F290, 0x81AE40, 0x814AA0};
    for (U i = 0; i < ServiceCount; ++i) g_serviceTargets[i] = V(targets[i]);
    memcpy(g_locoBindings, bindings, sizeof(g_locoBindings));
}

bool Start(const Binding& binding) {
    if (g_started || g_stage || g_runDepth || binding.image_delta != g_delta ||
        !QueryPerformanceFrequency(&g_frequency) || g_frequency.QuadPart <= 0) return false;
    if (binding.use_clone && (!binding.wrap_clone || !binding.move_clone ||
        !binding.selector_clone || !binding.class_wrap_clone)) return false;
    if (binding.use_parallel && !binding.use_clone) return false;
    if (binding.use_shadow && !binding.use_clone) return false;
    if (binding.use_owned_services && !binding.use_parallel) return false;
    if (binding.use_quiet && !binding.use_owned_services) return false;
    g_grid = nullptr; g_gridModel = 0; g_storageBytes = 0;
    memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    g_workers = nullptr;
    // Only the legacy contiguous-run path uses the 256-occurrence arena; owned execution never touches it.
    if (binding.use_parallel && !binding.use_owned_services) {
        g_workers = static_cast<WorkerArena*>(VirtualAlloc(nullptr, sizeof(WorkerArena), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_workers) return false;
    }
    g_gridCurrent = g_incarnation = 0; g_gridValid = false;
    memset(&g_gridView, 0, sizeof(g_gridView));
    memset(g_gridWords, 0, sizeof(g_gridWords));
    memset(g_gridV2Words, 0, sizeof(g_gridV2Words));
    g_gridV2Words[GridV2Version] = 2;
    g_gridV2Words[GridV2Enabled] = binding.use_grid || binding.verify_grid;
    g_gridV2Words[GridV2VerifyEnabled] = binding.verify_grid;
    memset(g_parallelWords, 0, sizeof(g_parallelWords));
    memset(g_ownedWords, 0, sizeof(g_ownedWords));
    g_ownedWords[OwnedVersion] = 1;
    g_ownedWords[OwnedEnabled] = binding.use_owned_services ? 1 : 0;
    memset(g_ownedDetails, 0, sizeof(g_ownedDetails));
    g_quiet = binding.use_quiet;
    g_ownedDetails[OwnedDetailVersion] = 1;
    g_ownedDetails[OwnedDetailQuiet] = g_quiet ? 1 : 0;
    memset(g_ownedPhase, 0, sizeof(g_ownedPhase));
    g_ownedPhase[OwnedPhaseVersion] = binding.use_owned_services ? 1 : 0;
    memset(g_ownedLoad, 0, sizeof(g_ownedLoad));
    g_ownedLoad[OwnedLoadVersion] = binding.use_owned_services ? 1 : 0;
    g_replayCommitTicks = g_replayFallbackTicks = 0;
    g_ownedReplaySeq = g_ownedFallbackSeq = 0;
    // Grid off: every grid word except the version stays zero (generation/bytes belong to a running grid).
    g_gridWords[GridVersion] = 1;
    g_parallelWords[ParallelVersion] = 1;
    g_parallelWords[ParallelEnabled] = binding.use_parallel ? 1 : 0;
    g_binding = binding;
    g_binding.use_grid = binding.use_grid || binding.verify_grid;
    memset(g_words, 0, sizeof(g_words));
    memset(g_gateWords, 0, sizeof(g_gateWords));
    g_gateWords[GateVersion] = 1;
    g_gateWords[GateEnforcedMask] = kMoveGateMask;
    memset(g_timingWords, 0, sizeof(g_timingWords));
    memset(&g_timingTotals, 0, sizeof(g_timingTotals));
    g_timingSequence = 0;
    g_serviceDepth = 0;
    g_timingEnabled = binding.use_clone && !g_quiet;
    g_timingWords[TimingVersion] = 1;
    g_timingWords[TimingEnabled] = g_timingEnabled ? 1u : 0u;
    memset(g_scratchFirst, 0, sizeof(g_scratchFirst));
    memset(g_scratchSecond, 0, sizeof(g_scratchSecond));
    memset(g_scratchThird, 0, sizeof(g_scratchThird));
    g_scratchFirst[0] = V(0x1312358);
    // Guards are bound for census completeness, but every TLS init check and
    // cold registration path was removed from the private mover by pinned rewrites.
    g_guards[0] = g_guards[1] = g_guards[2] = 0x80000000u;
    ResetServiceTrace();
    g_words[Version] = 1;
    g_words[Generation] = ++g_generation;
    if (g_binding.use_grid) g_gridWords[GridGeneration] = g_generation;
    g_words[CloneEnabled] = binding.use_clone ? 1u : 0u;
    g_words[CloneBytes] = binding.clone_bytes;
    g_parallelInFlight = 0; g_stagingActive = false;
    g_shadowEnabled = binding.use_shadow && !g_quiet;
    const bool portsEnabled = g_shadowEnabled || binding.use_owned_services;
    if (!ntw2_sweep::Start({g_delta, g_generation, portsEnabled}) ||
        !ntw2_resolve::Start({g_delta, g_generation, portsEnabled}) ||
        !ntw2_env::Start({g_delta, g_generation, portsEnabled, g_shadowEnabled}) || !CreateOwned()) {
        ntw2_sweep::Stop(); ntw2_resolve::Stop(); ntw2_env::Stop();
        DestroyOwned();
        ReleaseGrid();
        if (g_workers) VirtualFree(g_workers, 0, MEM_RELEASE);
        g_workers = nullptr;
        g_shadowEnabled = false; return false;
    }
    g_started = true;
    g_storageBytes = ComputeStorage();
    return true;
}
bool ActivateOwned(void* model, const ntw2_workload::Capacity& capacity) {
    if (!g_started) { g_ownedLoad[OwnedLoadFailureReason] = ActivationNotStarted; return false; }
    if (!g_owned && !g_binding.use_grid) { g_ownedLoad[OwnedLoadFailureReason] = ActivationDisabled; return false; }
    if (g_stage || g_runDepth) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBusy; return false; }
    if (!model) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBadModel; return false; }
    if (!ValidCapacity(capacity)) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBadCapacity; return false; }
    if (g_gridModel && g_gridModel != Address(model)) {
        g_ownedLoad[OwnedLoadFailureReason] = ActivationModelMismatch; return false;
    }
    if (g_binding.use_grid) {
        if (!g_grid) {
            // This is battle activation, never a tick or collision-entry lazy build.
            if (!AllocateGrid(capacity)) {
                g_ownedLoad[OwnedLoadFailureReason] = ActivationGridAllocation;
                g_storageBytes = ComputeStorage(); return false;
            }
            g_gridModel = Address(model);
        } else if (!GridCovers(capacity)) {
            g_ownedLoad[OwnedLoadFailureReason] = ActivationBadCapacity; return false;
        }
    }
    if (!g_owned) { g_storageBytes = ComputeStorage(); return true; } // grid-only mode does not prepare sweep/environment scenes
    OwnedArena& arena = *g_owned;
    if (arena.activated) {
        const bool same = arena.activationModel == Address(model) && capacity.primary <= arena.slotCapacity;
        g_ownedLoad[OwnedLoadFailureReason] = same ? ActivationOk : ActivationModelMismatch;
        return same;
    }
    // An unsuccessful attempt is not retried inside a generation.
    if (g_ownedLoad[OwnedLoadCalls]) { g_ownedLoad[OwnedLoadFailureReason] = ActivationAlreadyAttempted; return false; }
    ++g_ownedLoad[OwnedLoadCalls];
    const LONGLONG start = Now();
    OwnedCapture capture = {Address(model)};
    U workerUs = 0;
    g_ownedLoad[OwnedLoadException] = g_ownedLoad[OwnedLoadDetail] = g_ownedLoad[OwnedLoadActual] = 0;
    arena.mxcsr = _mm_getcsr();
    unsigned short cw; __asm { fnstcw cw }
    arena.cw = cw;
    bool ready = false;
    __try {
        const LONGLONG allocation = Now();
        g_ownedLoad[OwnedLoadFailureReason] = ActivationSlotAllocation;
        // Movement slots are sized by the PRIMARY occurrence capacity, never by primary+secondary records.
        ready = AllocateOwnedSlots(arena, capacity.primary);
        g_ownedLoad[OwnedLoadArenaUs] = Microseconds(Now() - allocation);
        if (ready) {
            // Warmup only runs inactive clones; it does not need the captured scene.
            // Keep this and every large arena/participant prefault off the tick owner.
            g_ownedLoad[OwnedLoadFailureReason] = ActivationWarmup;
            WarmOwnedClones(Address(model));
            g_ownedLoad[OwnedLoadFailureReason] = ActivationOwnerUnavailable;
            const bool captured = g_binding.capture_at_tick ?
                g_binding.capture_at_tick(&CaptureOwnedPortsGuarded, &capture) :
                (CaptureOwnedPortsGuarded(&capture), true);
            ready = captured && capture.ready;
        }
        if (ready) {
            const LONGLONG participants = Now();
            ready = PrepareOwnedWorkersCatching();
            workerUs = Microseconds(Now() - participants);
        }
    } __except(ActivationException(GetExceptionInformation())) { ready = false; }
    g_ownedLoad[OwnedLoadSceneUs] = capture.sceneUs;
    g_ownedLoad[OwnedLoadCatalogUs] = capture.catalogUs;
    g_ownedLoad[OwnedLoadParticipantsUs] = workerUs;
    g_ownedLoad[OwnedLoadUs] = Microseconds(Now() - start);
    if (ready) {
        arena.activationModel = Address(model); arena.activated = true;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationOk;
    }
    g_storageBytes = ComputeStorage(); // vector capacities are final here: never iterated again per tick
    return ready;
}
void Stop() {
    if (!g_started) return;
    // Runtime drains the owner before stopping; never clean a published call
    // while it is running, nor rerun it after an exception.
    FreeScratch(g_scratchFirst, true);
    FreeScratch(g_scratchSecond, false);
    FreeScratch(g_scratchThird, false);
    ntw2_sweep::Stop(); ntw2_resolve::Stop(); ntw2_env::Stop(); g_shadowEnabled = false;
    DestroyOwned();
    g_gridValid = false; g_gridModel = 0;
    ReleaseGrid();
    if (g_workers) VirtualFree(g_workers, 0, MEM_RELEASE);
    g_workers = nullptr;
    g_storageBytes = 0; memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    g_started = false;
    g_timingEnabled = false; // retain the published generation's metadata/counters
}
U Classify(void* entity) {
    __try { return ClassifyImpl(Address(entity)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return Lifetime; }
}
void ResetServiceTrace() { g_traceCount = 0; g_entityServices = 0; }
const ServiceRecord* ServiceTrace(U* count) { if (count) *count = g_traceCount; return g_trace; }
void Run(void* entity, bool wrapper) {
    if (!g_started || g_runDepth || !(wrapper ? g_binding.wrap_clone : g_binding.move_clone))
        RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    ++g_runDepth;
    ResetServiceTrace();
    const U frameBase = g_serviceDepth;
    const LONGLONG start = g_timingEnabled ? Now() : 0;
    __try { Call(wrapper ? g_binding.wrap_clone : g_binding.move_clone, Address(entity)); }
    __finally {
        if (g_timingEnabled) RecordCloneTime(Now() - start);
        AbandonServiceFrames(frameBase);
        FinishServices();
        --g_runDepth;
    }
}
U __fastcall Stage(void* manager) {
    const U m = Address(manager);
    if (!g_started || g_stage || g_runDepth) {
        if (g_started) ++g_words[ReentryRefusals];
        Call(V(0x531AF0), m);
        return D(m + 0x264) + 4 * D(m + 0x260);
    }
    // Epoch authorization belongs to the runtime's current tick, not the
    // first thread seen in this battle. A quiescent tick-owner handoff must
    // not disable all later serial occurrences on the new owner.
    g_words[OwnerThread] = GetCurrentThreadId();
    g_stage = true;
    ++g_words[Calls];
    const LONGLONG dispatchStart = Now();
    g_gridValid = false; g_gridCommittedReady = false; // publication occurs only after replay
    if (g_shadowEnabled) {
        __try { ntw2_sweep::Activate(D(D(m)+8)); }
        __except(EXCEPTION_EXECUTE_HANDLER) { /* Before records a failed capture without changing gameplay. */ }
    }
    U entities = 0;
    U cursor = D(m + 0x264);
    U end = cursor + 4 * D(m + 0x260);
    __try {
        PrepareOwned(m);
        if (g_binding.grid_window) g_binding.grid_window(manager, 1); // probation: owner's relink window opens
        const LONGLONG replayStart = g_binding.use_owned_services ? Now() : 0;
        while (cursor != end) {
            const U parallel = g_binding.use_owned_services ? (CommitOwned(m, cursor) ? 1u : 0u) : ParallelRun(m, cursor, end);
            if (parallel) {
                entities += parallel; cursor += parallel * 4;
                end = D(m + 0x264) + 4 * D(m + 0x260);
                continue;
            }
            const U a = D(cursor);
            g_stageEntity = a; g_stageOrdinal = (cursor - D(m + 0x264)) / 4;
            if (B(a + 0x30) == 1) {
                ++entities;
                const U reason = CountEntity(a);
                const bool selector = Candidate(D(a));
                if (g_binding.use_parallel) {
                    ++g_parallelWords[ParallelOwnerEntities];
                    const U needs = g_binding.use_owned_services ? 0 : WorkerReason(a);
                    if (needs) ++g_parallelWords[needs];
                    if (needs == ParallelNeedsEnv) {
                        ++g_parallelWords[ParallelNeedsSweep]; ++g_parallelWords[ParallelNeedsResolve];
                    }
                    if (g_parallelWords[ParallelSticky]) ++g_parallelWords[ParallelNativeFallbacks];
                    if (g_binding.use_owned_services) ++g_ownedWords[OwnedFallbackEntities];
                }
                const LONGLONG start = g_quiet ? 0 : Now();
                const bool sampleFallback = g_binding.use_owned_services && !(++g_ownedFallbackSeq & 15);
                const LONGLONG fallbackStart = sampleFallback ? Now() : 0;
                LONGLONG elapsed = 0;
                if (!reason && g_binding.use_clone && !g_parallelWords[ParallelSticky]) {
                    ++g_words[Cloned];
                    ++g_runDepth;
                    ResetServiceTrace();
                    const U frameBase = g_serviceDepth;
                    __try { Call(D(a) == V(0x132BA04) ? g_binding.class_wrap_clone : g_binding.selector_clone, a); }
                    __finally {
                        if (!g_quiet) {
                            elapsed = Now() - start;
                            RecordCloneTime(elapsed);
                        }
                        AbandonServiceFrames(frameBase);
                        FinishServices();
                        --g_runDepth;
                    }
                } else {
                    ++g_words[Native];
                    Call(D(D(a) + 0x10), a);
                    if (!g_quiet) elapsed = Now() - start;
                }
                if (sampleFallback) {
                    g_replayFallbackTicks += Now() - fallbackStart;
                    g_ownedPhase[OwnedPhaseReplayFallbackEstUs] = Microseconds(g_replayFallbackTicks * 16);
                }
                if (!g_quiet) {
                    const U us = Microseconds(elapsed);
                    const U sum = reason ? RejectedUs : AdmittedUs;
                    g_words[sum] += us;
                    Max(sum + 1, us);
                }
                // Selector tests A3 AFTER integrating; the pre-call value can
                // differ at map bounds. No staging callback is replayed here.
                if (selector && B(a + 0xA3) == 0) ++g_words[Staging];
            } else ++g_words[Filtered];
            // Exact 531AF0 semantics: keep the absolute cursor; reload BOTH
            // list base and count after each occurrence (including filtered).
            cursor += 4;
            end = D(m + 0x264) + 4 * D(m + 0x260);
        }
        if (g_binding.use_owned_services) {
            const U replayUs = Microseconds(Now() - replayStart);
            g_ownedWords[OwnedReplayUs] += replayUs;
            g_ownedPhase[OwnedPhaseReplayLoopUs] += replayUs;
            g_parallelWords[ParallelReplayUs] += replayUs;
        }
        if (g_binding.use_grid) CaptureGrid(manager); // one end-of-site-13 publication for following collision
    } __finally {
        // Probation: the owner's relink window closes after replay and grid publication; this re-arms the heads.
        if (g_binding.grid_window) g_binding.grid_window(manager, 0);
        const U us = Microseconds(Now() - dispatchStart);
        g_words[DispatchUs] += us;
        Max(DispatchMaxUs, us);
        Max(MaxEntities, entities);
        g_stage = false;
        g_stagingActive = false;
        g_stageEntity = g_stageOrdinal = 0;
        g_parallelInFlight = 0;
        if (g_owned) g_owned->valid = false;
    }
    return end;
}
void Sample(U words[WordCount]) { memcpy(words, g_words, sizeof(g_words)); }
void SampleGates(U words[GateWordCount]) { memcpy(words, g_gateWords, sizeof(g_gateWords)); }
void SampleGrid(U words[GridWordCount]) { memcpy(words, g_gridWords, sizeof(g_gridWords)); }
void SampleGridV2(U words[GridV2WordCount]) { memcpy(words, g_gridV2Words, sizeof(g_gridV2Words)); }
void SampleParallel(U words[ParallelWordCount]) { memcpy(words, g_parallelWords, sizeof(g_parallelWords)); }
void SampleOwned(U words[OwnedWordCount]) { memcpy(words, g_ownedWords, sizeof(g_ownedWords)); }
void SampleOwnedDetails(U words[OwnedDetailWordCount]) { memcpy(words, g_ownedDetails, sizeof(g_ownedDetails)); }
void SampleOwnedPhase(U words[OwnedPhaseWordCount]) { memcpy(words, g_ownedPhase, sizeof(g_ownedPhase)); }
void SampleOwnedLoad(U words[OwnedLoadWordCount]) { memcpy(words, g_ownedLoad, sizeof(g_ownedLoad)); }
U StorageBytes() { return g_storageBytes; }
void SampleStorage(U words[StorageWordCount]) { memcpy(words, g_storageWords, sizeof(g_storageWords)); }
void SampleCatalogStorage(U words[CatalogStorageWordCount]) { memcpy(words, g_catalogStorage, sizeof(g_catalogStorage)); }
U EstimateActivationBytes(const ntw2_workload::Capacity& capacity) {
    if (!g_started || !ValidCapacity(capacity)) return 0xFFFFFFFFu;
    unsigned long long total = 0;
    if (g_binding.use_grid && !g_grid) {
        GridStore plan = {};
        const U chunks = (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1));
        total += (CarveGrid(capacity, chunks, plan, nullptr) + 4095) & ~4095ull;
    }
    if (g_owned && !g_owned->activated) {
        total += static_cast<unsigned long long>(capacity.primary) * (sizeof(OwnedSlot) + sizeof(U) + 1);
        for (U i = 0; i < g_owned->participantsCount; ++i)
            if (g_owned->participants[i] && !g_owned->participants[i]->ctx) total += sizeof(OwnedContexts);
    }
    return total >= 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(total);
}
bool CaptureGrid(void* manager) {
    if (!g_started || !g_binding.use_grid) return false;
    g_gridValid = false;
    bool captured = false;
    __try { captured = g_grid && CaptureGridImpl(Address(manager)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_gridWords[GridFaults]; ++g_gridV2Words[GridV2Faults]; }
    if (!captured) { ++g_gridWords[GridRefusals]; ++g_gridV2Words[GridV2Refusals]; }
    g_gridValid = captured;
    return captured;
}
const GridView* ReadGrid() { return g_started && g_gridValid ? &g_gridView : nullptr; }
const GridView* ReadGridForCollision(void* manager) {
    const GridView* view = ReadGrid();
    if (!view || g_stage || view->manager != Address(manager)) return nullptr;
    __try {
        const U m = Address(manager), root = D(m), model = root ? D(root + 8) : 0;
        if (model != view->model || D(model + 0xA4) != view->grid ||
            D(m + 0x24C) != view->primary_count || D(m + 0x278) != view->secondary_count ||
            D(m + 0x250) != view->primary_registry || D(m + 0x27C) != view->secondary_registry) return nullptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    // The collision adapter additionally checks every identity and live geometry
    // before any solver writes; no chain import or lazy rebuild occurs here.
    return view;
}
void SampleServices(U words[ServiceWordCount]) {
    TimingTotals totals;
    for (;;) {
        const LONG before = _InterlockedCompareExchange(&g_timingSequence, 0, 0);
        if (before & 1) { YieldProcessor(); continue; }
        memcpy(&totals, &g_timingTotals, sizeof(totals));
        memcpy(words, g_timingWords, sizeof(g_timingWords));
        if (_InterlockedCompareExchange(&g_timingSequence, 0, 0) == before) break;
    }
    if (g_frequency.QuadPart <= 0) return;
    const auto frequency = static_cast<unsigned long long>(g_frequency.QuadPart);
    const auto us = [frequency](unsigned long long ticks) {
        return static_cast<U>((ticks / frequency) * 1000000ull + ((ticks % frequency) * 1000000ull) / frequency);
    };
    words[TimingCloneWallUs] = us(totals.cloneWall);
    words[TimingUnionUs] = us(totals.serviceUnion);
    // Compare raw totals before wrapping the public cumulative u32 words.
    words[TimingOutsideUs] = totals.cloneWall >= totals.serviceUnion
        ? words[TimingCloneWallUs] - words[TimingUnionUs] : 0;
    for (U i = 0; i < ServiceCount; ++i) {
        words[TimingServiceUs + i] = us(totals.service[i]);
        words[TimingServiceMaxUs + i] = us(totals.maximum[i]);
    }
}
#ifdef NTW2_LOCO_ORACLE
U SetServiceTargetForTest(Service service, U address) {
    if (service >= ServiceCount || !address || g_runDepth || g_serviceDepth) return 0;
    const U old = g_serviceTargets[service];
    g_serviceTargets[service] = address;
    return old;
}
OwnedLayoutForTest OwnedLayout() {
    return {static_cast<U>(sizeof(OwnedSlot)), kGuardBytes, kOutputBytes, kWrapperBytes,
        static_cast<U>(kGuardSpanCount), static_cast<U>(kOutputSpanCount), static_cast<U>(kWrapperSpanCount), static_cast<U>(kAlwaysWrittenCount),
        kGuardSpans, kOutputSpans, kWrapperSpans, kAlwaysWritten};
}
OwnedServiceObserverForTest SetOwnedServiceObserverForTest(OwnedServiceObserverForTest observer) {
    if (g_stage || g_runDepth || g_parallelInFlight) return g_ownedObserver;
    const auto previous = g_ownedObserver; g_ownedObserver = observer; return previous;
}
#endif
} // namespace ntw2_loco
