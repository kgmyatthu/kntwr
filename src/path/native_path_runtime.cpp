// native_path_runtime: private-workspace planning and owner-thread consumption of the ORIGINAL pathfinder request chain
// (ABI, routing and semantics: native_path_runtime.h).  Everything numeric is mirrored by ntw_path_workspace (differentially
// verified engine); this file adds scheduling, the staleness proof and the materialization into the real G.
//
// PER TICK (npr_scheduler_hook, owner = the game thread that runs the battle tick):
//   1. gate: enabled, scheduler clone configured, exclusive owner (CAS), (root, model, pf) binding re-read.
//   2. PREPASS (owner only, read-only w.r.t. game state): retain live cached requests; in native queue order attempt at most
//      maxNewPerTick new state-0 requests whose query kind is 0 and position source is the pure branch of 0x816CA0. Build the
//      INPUTS the real prefix 0x80FF1B..0x8101F5 will build: start / goal nodes through the ORIGINAL 0x7EB210 into PRIVATE seed
//      nodes, via position through the original 0x816CA0, world-rect flag (0x810130), region flags (7FE320 port).  The 67A790
//      cell lookup that 7EB210 may reach runs on the owner thread exactly as in the native flow (transient global scratch).
//   3. SEARCH: short searches run inline. Substantial batches use ONE persistent-team dispatch: workers repeatedly advance
//      exclusively claimed private workspaces to their next successor request or terminal state (no game reads/calls).
//      The owner dispatch body services completed advances: PLAN gate (native_path_footprint.h), ORIGINAL 0x800210 on
//      private G, then SealSuccessors. Interlocked slot handoffs publish sealed inputs/results; no worker owns a slot while
//      its callback runs. The pool barrier joins all bodies before validation/materialization or reuse.
//   4. the ORIGINAL 0x81A2C0 (clone) runs.  When its stepper clone reaches the solve call (npr_solve) the runtime validates and
//      consumes the private result or runs the original 0x8026F0 untouched.
//   5. npr_end: retain completed unconsumed results and their immutable footprints; publish counters and release ownership.
//
// CONSUMPTION PROOF (npr_solve; every item must hold, otherwise STALE++ and the original 0x8026F0 runs on the real G):
//   a. owner thread inside an active tick, G == cfg.pf + 0x1BC, [G+4] == root, [G+8] == G, [pf+0x2E4] == the planned request.
//   b. INPUT EQUALITY: solve-relevant query fields (QueryInputs below), start / goal node fields (every semantic field; graph == G),
//      via argument, flag byte, engine limit [G+0xE8], overwrite byte [G+0xC], the five sentinel words, the via node REBUILT now
//      by the original 0x7EB210 (world read at consumption) and the two region flags recomputed now.
//   c. READ-SET EQUALITY: every game-memory byte the original successor read during planning (edge arrays, edges, topologies,
//      segments, gateways, vtable slots, region records, query chain, height-field header and the cells a sample can touch) is
//      compared with the live bytes (memcmp against the snapshot).  Unchanged read set + equal inputs + deterministic original
//      code => the private result is exactly what 0x8026F0 would compute now.
//      No part of this argument requires the planning tick to equal the consuming tick. Prepass checks request membership
//      and query identity without refreshing the result/read set; full validation remains mandatory after any number of ticks.
//   Height field: the recorded cells are the EXACT read set of the original 64C5F0 arithmetic for every sample point in the proven
//   domain (see SampleHeightField: proof for any x87 precision / rounding mode, finite |t| <= 2^20); the domain is checked BEFORE the
//   callback (HeightFieldDomainOk) and anything outside it is refused.  No table-wide immutability is assumed.
//   Lifetime: a path node's object / edge pointers are values the callback read from recorded ranges (edge array, edge, destination
//   fields); with those bytes unchanged the original would compute the same pointers now, so no pointer is trusted beyond the bytes.
//
// Materialization reproduces the 0x8026F0 post-state on the real G with the ORIGINAL allocators (0x80B0F0, 0x448B90) on the owner:
// arena B reset like 0x802A80, output nodes + output vector, G+0xE4, G+0x120 += expansions, and the epilogue state.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <emmintrin.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

#include <new>

#include "native_path_footprint.h"
#include "native_path_runtime.h"
#include "native_path_workspace.h"
#include "native_worker_dispatch.h"

extern "C" {
ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool);
void __stdcall ntw_pool_dispatch(ntw_u32 user, ntw_u32 body, ntw_u32 chunks, void* ctx);
ntw_u32 __stdcall ntw_pool_worker_start(void* param);
}

namespace pw = ntw_path_workspace;

static_assert(sizeof(void*) == 4, "x86 build required");

// ---- generated source pins (tools/generate_path_pins.py) -----------------------------------------------------------------------
struct NprSourceSpan {
    uint32_t va, size;
    uint64_t hash;
    uint32_t relocStart, relocCount;
};
struct NprDataWord {
    uint32_t va, value, reloc;
};
#include "native_path_runtime_pins.inc"

// ---- exports ----------------------------------------------------------------------------------------------------------------
#pragma comment(linker, "/EXPORT:npr_initialize=_npr_initialize@4")
#pragma comment(linker, "/EXPORT:npr_stop=_npr_stop@4")
#pragma comment(linker, "/EXPORT:npr_scheduler_hook=@npr_scheduler_hook@4")
#pragma comment(linker, "/EXPORT:npr_prepass=@npr_prepass@4")
#pragma comment(linker, "/EXPORT:npr_end=@npr_end@4")
#pragma comment(linker, "/EXPORT:npr_solve=@npr_solve@28")

extern "C" __declspec(dllexport) volatile uint32_t npr_state[NPR_STATE_WORDS] = {NPR_ABI, NPR_STATE_BYTES};
static_assert(sizeof(npr_state) == NPR_STATE_BYTES, "npr_state is NPR_STATE_WORDS u32 words");

// Bytes of memory this module currently HOLDS through its own allocation (slot control array + per-slot workspace + footprint
// storage; one VirtualAlloc).  Set when a session is published, 0 after npr_stop / a failed start.  The persistent pool, when owned,
// is static storage inside the DLL (NTW_POOL_BYTES) and is not counted here.
extern "C" __declspec(dllexport) volatile uint32_t npr_storage_bytes = 0;

// Optional diagnostic ABI, deliberately absent from production builds. Values are cumulative QPC ticks,
// read only while the owner is idle / after the dispatch barrier. The oracle uses before/after deltas.
// Order: native callback, footprint gate+record, seal, owner advance, worker advance, owner wait, setup, consume.
#ifdef NPR_TIMING
extern "C" __declspec(dllexport) uint64_t npr_timing_ticks[8] = {};
static uint64_t TimingNow() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart);
}
struct NprTimer {
    uint64_t& total;
    uint64_t start;
    explicit NprTimer(uint64_t& dst) : total(dst), start(TimingNow()) {}
    ~NprTimer() { total += TimingNow() - start; }
};
#define NPR_TIME(name, dst) NprTimer name(dst)
#else
#define NPR_TIME(name, dst) ((void)0)
#endif

extern "C" {
uint32_t __stdcall npr_initialize(void* config);
uint32_t __stdcall npr_stop(void* unused);
void __fastcall npr_scheduler_hook(void* pf);
void __fastcall npr_prepass(void* pf);
void __fastcall npr_end(void* pf);
uint32_t __fastcall npr_solve(void* g, void* edx, const void* query, const void* start, void* goal, void* via, uint32_t flag);
}

namespace {

constexpr uint32_t kLifeNone = 0, kLifeInitializing = 1, kLifeReady = 2, kLifeStopped = 3, kLifeStopping = 4;
constexpr uint32_t kStopToken = 0xFFFFFFFFu;
constexpr uint32_t kMaxQueueWalk = 4096;
constexpr uint32_t kMaxRounds = 1u << 20;
constexpr uint32_t kInlineRounds = 8;       // do not wake a team for short searches
constexpr uint32_t kMinTeamSlots = 4, kMinTeamNeighbors = 16;
constexpr uint32_t kFpRanges = 24576;
constexpr uint32_t kFpTable = 65536;            // power of two > kFpRanges
constexpr uint32_t kFpBytes = 1u << 20;
constexpr uint32_t kWorkerStackBytes = 0x100000;
constexpr size_t kMaxTotalBytes = 0x60000000u;

// defaults for npr_config fields that are 0
constexpr uint32_t kDefOpen = 8192, kDefNeighbors = 64, kDefNodeBlocks = 96, kDefEntryBlocks = 24, kDefHashLevels = 8;
constexpr uint32_t kDefOutput = 2048;

enum SlotState : uint32_t { kSlotFree = 0, kSlotRunning, kSlotDone, kSlotFailed, kSlotConsumed,
                            kSlotAdvancing, kSlotAdvanced };

inline volatile long* VL(volatile uint32_t* p) { return reinterpret_cast<volatile long*>(p); }
inline uint32_t Xchg(volatile uint32_t* p, uint32_t v) { return static_cast<uint32_t>(_InterlockedExchange(VL(p), static_cast<long>(v))); }
inline uint32_t Cas(volatile uint32_t* p, uint32_t desired, uint32_t expected) {
    return static_cast<uint32_t>(_InterlockedCompareExchange(VL(p), static_cast<long>(desired), static_cast<long>(expected)));
}
inline uint32_t Inc(volatile uint32_t* p) { return static_cast<uint32_t>(_InterlockedIncrement(VL(p))); }
inline void Store(uint32_t word, uint32_t v) { npr_state[word] = v; }
inline void Bump(uint32_t word) { Inc(&npr_state[word]); }
inline uint32_t Err(uint32_t cls, uint32_t detail) { return cls | (detail << 8); }
inline void Wr32(uint32_t a, uint32_t v) { *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(a)) = v; }
inline size_t AlignUp(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }

// ---- original code entry points (thiscall == fastcall with an ignored edx) ------------------------------------------------------
typedef void(__fastcall* SuccFn)(void* g, void* edx, void* a1, void* neighbors, void* arenaB);                              // 0x800210 ret 0xC
typedef pw::Node*(__fastcall* SeedFn)(void* node, void* edx, const void* rootSlot, void* g, const void* q, const void* pos, float radius);  // 0x7EB210 ret 0x14
typedef void*(__fastcall* StartPosFn)(const void* q, void* edx, void* outPos, void* pf, void* viaOut);                      // 0x816CA0 ret 0xC
typedef void*(__fastcall* AllocFn)(void* arena, void* edx, uint32_t size, uint32_t shift);                                  // 0x80B0F0 ret 8
typedef void*(__fastcall* PushFn)(void* vec, void* edx, void* valuePtr);                                                    // 0x448B90 ret 4
typedef uint32_t(__fastcall* SolveFn)(void* g, void* edx, const void* q, const void* start, void* goal, void* via, uint32_t flag);  // 0x8026F0 ret 0x14

constexpr uint32_t kRequiredSpans[] = {
    0x800210, 0x7EB210, 0x7EB2A0, 0x7EB5C0, 0x80B0F0, 0x79AE00, 0x448B90, 0x807AF0, 0x808D00, 0x7ED270, 0x80EA60, 0x80ABD0,
    0x559C10, 0x57E870, 0x66BB40, 0x64C5F0, 0x10D0900, 0x7F1630, 0x6A3110, 0x4E74C0, 0x531E30, 0x531E40, 0x6B7F90, 0x6ABC80,
    0x7FF170, 0x54E920, 0x4470B0, 0x461180, 0x8026F0, 0x81C080, 0x81C050, 0x80E9D0, 0x7F4950,
    0x816CA0, 0x56CF70, 0x815FA0, 0x7EAE90, 0x53FBD0};   // the last five are NOT in the generator's current roots (see report)


// Query fields that can influence the supported solve. The prefix dereferences +C/+10 (start source chain) and, through 7EB210 ->
// 80E9D0 on the goal position Q+0x18, the transform pointer at +0x28 (7F4950 reads [[Q+0x28]+0x9C..]); 800210 reads +4, +24, +2C,
// +34, +50; the via leg (Q+4 == 2) reads +3C..+48. Kind 1 and special goals are refused before callbacks.
// Not inputs: +14 (kind-1 only), +30, +38 (special goal only), +4C and +51..+57. The scheduler's own stores
// (req+14/+1C/+DA, pf counters) lie OUTSIDE Q = req+0x28 and never enter identity; req+DA is checked through the effective flag.
constexpr uint32_t kQueryOffsets[] = {0, 4, 8, 0xC, 0x10, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x34, 0x3C, 0x40, 0x44, 0x48};
constexpr uint32_t kQueryWords = sizeof(kQueryOffsets) / sizeof(kQueryOffsets[0]);
struct QueryInputs {
    uint32_t words[kQueryWords];
    uint32_t gate; // byte value, widened to avoid uninitialized structure padding
};
void SnapshotQuery(uint32_t q, QueryInputs& out) {
    for (uint32_t i = 0; i < kQueryWords; ++i) out.words[i] = npr::Rd32(q + kQueryOffsets[i]);
    out.gate = npr::Rd8(q + 0x50);
}
bool QuerySame(uint32_t q, const QueryInputs& snap) {
    for (uint32_t i = 0; i < kQueryWords; ++i)
        if (npr::Rd32(q + kQueryOffsets[i]) != snap.words[i]) return false;
    return npr::Rd8(q + 0x50) == snap.gate;
}
void RecordQuery(npr::Fp& fp, uint32_t q) {
    for (uint32_t i = 0; i < kQueryWords; ++i) fp.Add(q + kQueryOffsets[i], 4);
    fp.Add(q + 0x50, 1);
}

void Reject(uint32_t kind) {
    Bump(NPR_S_REJECTED);
    // Owner-only diagnostic lanes saturate independently; never corrupt the next lane.
    const uint32_t bits = npr_state[NPR_S_REJECT_KINDS];
    if (NPR_REJECT_COUNT(bits, kind) != 0xFFu)
        Store(NPR_S_REJECT_KINDS, bits + (1u << (8u * kind)));
}
// ---- slots ------------------------------------------------------------------------------------------------------------------------
struct Slot {
    pw::Workspace ws;
    uint8_t* wsMem;
    size_t wsBytes;
    npr::Fp fp;
    pw::Config wcfg;
    uint32_t state;
    uint32_t dirty;          // workspace must be re-initialised before reuse (a failed solve may leave it inconsistent)
    uint32_t broken;         // re-initialisation failed: never used again
    uint32_t req, query, viaPtr, limit;
    uint64_t planningTick;   // monotonic planning age; cache hits never refresh it
    uint32_t advRes, rounds;
#ifdef NPR_TIMING
    uint64_t advanceTicks;   // exclusively written during Advance, read only after its owner handoff
    uint32_t advanceThread;
#endif
    uint8_t overwrite, flag, region1, region2, hasVia;
    float radius;
    uint32_t sentinel[5];
    QueryInputs querySnap;
    pw::Node startSnap, goalSnap, viaSnap, viaCheck;
};

volatile uint32_t g_life = kLifeNone;
volatile uint32_t g_owner = 0;           // 0 idle, thread id during a tick, kStopToken once stopping/stopped
volatile uint32_t g_tickActive = 0;
volatile uint32_t g_tickByHook = 0;
bool g_poolOwn = false, g_poolLive = false, g_pinned = false;
uint32_t g_poolUser = 0;

uint32_t g_delta = 0, g_root = 0, g_model = 0, g_pf = 0, g_sched = 0, g_slotCount = 0, g_workers = 0;
uint32_t g_usable = 0;                   // slots handed to the planner
uint32_t g_maxNewPerTick = 4;
uint64_t g_planningTick = 0;

// Only query-local refusals (kind != 0 / special goal != 0) are deterministic from
// this key. World-dependent shape/gate failures and capacity/budget/faults are NOT
// remembered: the same query can succeed after the world or available resources change.
// A memory hit suppresses planning only; the actual solve always uses the original.
constexpr uint32_t kRefusals = 64, kRefusalTicks = 64;
struct Refusal {
    uint32_t req;   // 0 = empty
    uint64_t tick;
    QueryInputs q;
};
Refusal g_refused[kRefusals];
SuccFn g_succ = nullptr;
SeedFn g_seed = nullptr;
StartPosFn g_startPos = nullptr;
AllocFn g_alloc = nullptr;
PushFn g_push = nullptr;
SolveFn g_solve = nullptr;
npr::Targets g_targets{};
Slot* g_slots = nullptr;
uint8_t* g_mem = nullptr;
uint32_t g_teamSteps = 0, g_workerChunks = 0, g_ticks = 0, g_planned = 0, g_callbacks = 0;

__declspec(align(64)) uint8_t g_poolMem[NTW_POOL_BYTES];
ntw_pool* OwnPool() { return reinterpret_cast<ntw_pool*>(g_poolMem); }

inline uint32_t V(uint32_t preferred) { return preferred + g_delta; }

// ---- pins -------------------------------------------------------------------------------------------------------------------------
uint64_t HashSpan(const uint8_t* p, uint32_t size, const uint32_t* rel, uint32_t nrel, uint32_t delta) {
    uint64_t h = 0xCBF29CE484222325ull;
    uint32_t ri = 0;
    for (uint32_t i = 0; i < size;) {
        if (ri < nrel && rel[ri] == i) {
            uint32_t v;
            memcpy(&v, p + i, 4);
            v -= delta;
            for (int k = 0; k < 4; ++k) h = (h ^ static_cast<uint8_t>(v >> (8 * k))) * 0x100000001B3ull;
            i += 4;
            ++ri;
        } else {
            h = (h ^ p[i]) * 0x100000001B3ull;
            ++i;
        }
    }
    return h;
}

// 0: ok, else detail (1-based span index, 0x1000 + word index, 0x2000 + required index)
uint32_t VerifyImageImpl(uint32_t delta) {
    const uint32_t nSpans = static_cast<uint32_t>(sizeof(kSources) / sizeof(kSources[0]));
    for (uint32_t i = 0; i < nSpans; ++i) {
        const NprSourceSpan& s = kSources[i];
        if (s.relocStart + s.relocCount > sizeof(kSourceRelocs) / sizeof(kSourceRelocs[0])) return i + 1;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(s.va + delta));
        if (HashSpan(p, s.size, kSourceRelocs + s.relocStart, s.relocCount, delta) != s.hash) return i + 1;
    }
    const uint32_t nWords = static_cast<uint32_t>(sizeof(kWords) / sizeof(kWords[0]));
    for (uint32_t i = 0; i < nWords; ++i) {
        const NprDataWord& w = kWords[i];
        const uint32_t live = *reinterpret_cast<const volatile uint32_t*>(static_cast<uintptr_t>(w.va + delta));
        if (live != (w.reloc ? w.value + delta : w.value)) return 0x1000 + i;
    }
    for (uint32_t r = 0; r < sizeof(kRequiredSpans) / sizeof(kRequiredSpans[0]); ++r) {
        bool found = false;
        for (uint32_t i = 0; i < nSpans && !found; ++i) found = kSources[i].va == kRequiredSpans[r];
        if (!found) return 0x2000 + r;
    }
    return 0;
}
uint32_t VerifyImage(uint32_t delta) {
    __try {
        return VerifyImageImpl(delta);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0x3000;
    }
}

// ---- guarded game reads -----------------------------------------------------------------------------------------------------------
bool Bound(uint32_t pf) {
    __try {
        return pf != 0 && pf == g_pf && npr::Rd32(pf) == g_root && npr::Rd32(g_root + 8) == g_model && npr::Rd32(g_model + NPR_VA_MODEL_PF_OFFSET) == pf;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void DropResult(Slot& s, uint32_t reason = 0) {
    if (s.state == kSlotDone) {
        Bump(NPR_S_UNUSED);
        if (reason != 0) Bump(reason);
        if (reason == NPR_S_INVALID_EVICTED) Bump(NPR_S_EVICTED);
    }
    s.state = kSlotFree;
}

struct Collect {
    uint32_t n, faulted, complete;
    uint8_t seen[NPR_MAX_SLOTS];   // 0 unproven, 1 same pending query inputs, 2 changed query, 3 not pending
    uint8_t refSeen[kRefusals];
};

// Native scheduler order: 0x81A2D4 head, 0x81A304 next; viability 0x81B7B0. Collect only the first cap
// eligible requests for the priority window, but finish the bounded walk to establish cached request membership.
void CollectImpl(uint32_t pf, uint32_t cap, uint32_t* out, Collect* c) {
    uint32_t req = npr::Rd32(pf + 0x130);
    for (uint32_t visited = 0; req != 0 && visited < kMaxQueueWalk; ++visited) {
        const uint32_t next = npr::Rd32(req + 0x24);
        const bool pending = npr::Rd32(req + 0x10) != 0 && npr::Rd32(req + 0x14) == 0;
        const uint32_t q = req + 0x28;
        for (uint32_t i = 0; i < g_usable; ++i) {
            Slot& s = g_slots[i];
            if (s.state != kSlotDone || s.req != req) continue;
            c->seen[i] = !pending ? 3 : (QuerySame(q, s.querySnap) ? 1 : 2);
        }
        for (uint32_t i = 0; i < kRefusals; ++i)
            if (g_refused[i].req == req && pending) c->refSeen[i] = 1;
        if (pending && c->n < cap &&
            (npr::Rd32(q) != 0 || npr::Rd32(npr::Rd32(q + 0xC) + 0x2CC) != 0)) out[c->n++] = req;
        req = next;
    }
    c->complete = req == 0;
}
void CollectRequests(uint32_t pf, uint32_t cap, uint32_t* out, Collect* c) {
    memset(c, 0, sizeof *c);
    __try {
        CollectImpl(pf, cap, out, c);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        c->faulted = 1;
    }
    for (uint32_t i = 0; i < g_usable; ++i) {
        if (g_slots[i].state != kSlotDone || c->seen[i] == 1) continue;
        const uint32_t reason = c->seen[i] == 2 ? NPR_S_INVALID_QUERY :
            (c->seen[i] == 3 || c->complete ? NPR_S_INVALID_PENDING : NPR_S_INVALID_WALK);
        DropResult(g_slots[i], reason);
    }
    for (uint32_t i = 0; i < kRefusals; ++i)
        if (c->refSeen[i] == 0) g_refused[i].req = 0;
}

void RecordRefusal(uint32_t req, const QueryInputs& query) {
    Refusal* dst = nullptr;
    for (uint32_t i = 0; i < kRefusals && dst == nullptr; ++i)
        if (g_refused[i].req == req) dst = &g_refused[i];
    for (uint32_t i = 0; i < kRefusals && dst == nullptr; ++i)
        if (g_refused[i].req == 0) dst = &g_refused[i];
    if (dst == nullptr) {
        dst = &g_refused[0];
        for (uint32_t i = 1; i < kRefusals; ++i)
            if (g_refused[i].tick < dst->tick) dst = &g_refused[i];
    }
    dst->req = 0;
    dst->q = query;
    dst->tick = g_planningTick;
    dst->req = req;
}

bool IsRefused(uint32_t req) {
    for (uint32_t i = 0; i < kRefusals; ++i) {
        Refusal& e = g_refused[i];
        if (e.req != req) continue;
        bool same = false;
        if (g_planningTick - e.tick < kRefusalTicks) {
            __try {
                same = QuerySame(req + 0x28, e.q);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
        if (!same) e.req = 0;
        else Bump(NPR_S_REFUSAL_MEMORY);
        return same;
    }
    return false;
}

bool InPriorityWindow(uint32_t req, const uint32_t* reqs, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) if (reqs[i] == req) return true;
    return false;
}

Slot* PlanningSlot(const uint32_t* reqs, uint32_t n) {
    Slot* oldest = nullptr;
    for (uint32_t i = 0; i < g_usable; ++i) {
        Slot& s = g_slots[i];
        if (s.broken) continue;
        if (s.state == kSlotFree) return &s;
        if (s.state == kSlotDone && !InPriorityWindow(s.req, reqs, n) &&
            (oldest == nullptr || s.planningTick < oldest->planningTick)) oldest = &s;
    }
    // Never trade an earlier native-scheduler request for a later one. Without this protection a full
    // cache could churn forever over a stationary queue larger than its capacity.
    if (oldest != nullptr) DropResult(*oldest, NPR_S_INVALID_EVICTED);
    return oldest;
}

// ---- planning: inputs ---------------------------------------------------------------------------------------------------------------
inline bool InsideRect(uint32_t w, const pw::Node* n) {   // 0x810130..0x8101AD, comiss semantics (NaN -> outside)
    const float x0 = npr::RdF(w + 0x84), z0 = npr::RdF(w + 0x88), x1 = npr::RdF(w + 0x8C), z1 = npr::RdF(w + 0x90);
    return n->x >= x0 && n->z >= z0 && x1 > n->x && z1 > n->z;
}

// 0 built, 1 input shape (world-dependent), 2 capacity, 3 fault, 4 deterministic query-local refusal.
uint32_t BuildInputsImpl(Slot& s, uint32_t pf, uint32_t req) {
    const uint32_t q = req + 0x28;
    const uint32_t realG = pf + 0x1BC;
    pw::Workspace& ws = s.ws;
    pw::Graph& pg = ws.graph();
    ws.ClearSeed(ws.StartSeed());
    ws.ClearSeed(ws.ViaSeed());
    ws.ClearSeed(ws.GoalSeed());
    s.req = req;
    s.query = q;
    s.hasVia = 0;
    SnapshotQuery(q, s.querySnap);

    if (npr::Rd32(realG + 8) != realG || npr::Rd32(realG + 4) != g_root) return 1;
    // query shapes whose start-position source is proven pure (0x816CA0 kind 0 -> 0x815FA0 -> 0x56CF70 [sub+0xEC] == 0 -> 0x53FBD0)
    if (npr::Rd32(q) != 0 || npr::Rd32(q + 0x34) != 0) return 4;
    uint32_t sub = npr::Rd32(q + 0x10);
    if (sub == 0) sub = npr::Rd32(npr::Rd32(q + 0xC) + 0xADC);
    sub += 0x62C;
    if (npr::Rd32(sub + 0xEC) != 0) return 1;

    alignas(16) uint8_t startPos[0x20];
    memset(startPos, 0, sizeof startPos);
    uint32_t viaPtr = 0;
    g_startPos(reinterpret_cast<const void*>(static_cast<uintptr_t>(q)), nullptr, startPos, reinterpret_cast<void*>(static_cast<uintptr_t>(pf)), &viaPtr);
    if (viaPtr != 0 && viaPtr != q + 0x3C) return 1;
    s.viaPtr = viaPtr;
    s.radius = npr::RdF(q + 0x2C);

    const void* pfAsRootSlot = reinterpret_cast<const void*>(static_cast<uintptr_t>(pf));   // [pf] == root, as in the real prefix
    const void* qp = reinterpret_cast<const void*>(static_cast<uintptr_t>(q));
    pw::Node* start = g_seed(ws.StartSeed(), nullptr, pfAsRootSlot, &pg, qp, startPos, s.radius);
    pw::Node* goal = g_seed(ws.GoalSeed(), nullptr, pfAsRootSlot, &pg, qp, reinterpret_cast<const void*>(static_cast<uintptr_t>(q + 0x18)), s.radius);
    pw::Node* via = nullptr;
    if (viaPtr != 0) {
        via = g_seed(ws.ViaSeed(), nullptr, &pg.root, &pg, qp, reinterpret_cast<const void*>(static_cast<uintptr_t>(viaPtr)), s.radius);   // 0x8026F0 prologue
        s.hasVia = 1;
    }
    if (start->object == nullptr || goal->object == nullptr || (via != nullptr && via->object == nullptr)) return 1;

    // flag byte (0x810130..0x8101DB): inside the world rect -> [req+0xDA], else 1 (the real code also stores 1 there; we never write)
    const bool inside = InsideRect(g_model, start) && InsideRect(g_model, goal);
    s.flag = inside ? npr::Rd8(req + 0xDA) : 1;
    s.region1 = pw::RegionCrossFlag(qp, start, via != nullptr ? via : goal);
    s.region2 = via != nullptr ? pw::RegionCrossFlag(qp, via, goal) : 0;
    s.limit = npr::Rd32(realG + 0xE8);
    s.overwrite = npr::Rd8(realG + 0xC);
    for (uint32_t i = 0; i < 5; ++i) s.sentinel[i] = npr::Rd32(V(0x150FCA0) + 4 * i);
    // The workspace holds the sentinel only as init-time constants (graph reset values + 8026F0 epilogue state of the PRIVATE graph).
    // Refuse the request unless the live words still equal them, so the private solve and the validated live snapshot can never
    // disagree about the constants (Materialize itself writes the live words, never these).
    static_assert(sizeof(pw::Constants) == 20, "sentinel constants are five contiguous words");
    if (memcmp(s.sentinel, &s.wcfg.constants, sizeof s.sentinel) != 0) return 1;
    s.startSnap = *start;
    s.goalSnap = *goal;
    s.viaSnap = via != nullptr ? *via : pw::Node{};

    s.fp.Reset();
    RecordQuery(s.fp, q);
    s.fp.Add(V(0x150FCA0), 0x14);
    s.fp.Add(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(start->object)) + 0x1C, 4);   // Workspace::Begin reads the start hash id

    pg.expansionLimit = s.limit;
    pg.overwriteNode = s.overwrite;
    pw::SolveRequest r;
    r.query = qp;
    r.start = start;
    r.goal = goal;
    r.via = via;
    r.flag124 = s.flag;
    r.regionFlagLeg1 = s.region1;
    r.regionFlagLeg2 = s.region2;
    r.costLimit = 0.0f;
    r.bareEngine = false;
    if (ws.Begin(r) != pw::Result::kOk) return 2;
    if (s.fp.overflow) return 2;
    return 0;
}
uint32_t BuildInputs(Slot& s, uint32_t pf, uint32_t req) {
    __try {
        return BuildInputsImpl(s, pf, req);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Bump(NPR_S_FAULTS);
        return 3;
    }
}

// ---- planning: one successor callback (owner) -----------------------------------------------------------------------------------------
// 0 ok; 1 unsupported gate; 2 capacity; 3 fault; 4 bad shape / consistency.
uint32_t CallbackImpl(Slot& s) {
    pw::Workspace& ws = s.ws;
    pw::Graph& g = ws.graph();
    pw::Node* a1 = ws.PendingNode();
    if (a1 == nullptr || g.nodes.current == nullptr) return 4;
    for (uint32_t i = 0; i < 5; ++i)   // the original reads the sentinel at callback time: it must still be the planning-time value
        if (npr::Rd32(V(0x150FCA0) + 4 * i) != s.sentinel[i]) return 4;
    npr::Plan plan;
    const uint32_t ncap = g.neighbors.capacity;
    npr::PlanStatus st;
    {
        NPR_TIME(recordTime, npr_timing_ticks[1]);
        st = npr::PlanExpansion(s.fp, g_targets, g, a1, s.query, ncap, ws.NodeCapacity(), &plan);
    }
    if (st != npr::kPlanOk)
        return st == npr::kPlanCapacity ? 2u : st == npr::kPlanFault ? 3u : st == npr::kPlanBadShape ? 4u : 1u;
    if (s.fp.overflow) return 2;

    pw::ArenaBlock* const b0 = g.nodes.current;
    const uint32_t u0 = b0->used;
    {
        NPR_TIME(callbackTime, npr_timing_ticks[0]);
        g_succ(&g, nullptr, a1, &g.neighbors, &g.nodes);
    }
    Bump(NPR_S_CALLBACKS);

    if (g.neighbors.size > plan.maxNodes || g.neighbors.size > ncap) return 4;
    // walk the nodes this call allocated (also the ones dropped by the duplicate test): bound check + height-field samples
    {
        NPR_TIME(recordTime, npr_timing_ticks[1]);
        pw::ArenaBlock* b = b0;
        uint32_t off = u0, n = 0;
        for (;;) {
            const uint32_t end = (b == g.nodes.current) ? b->used : pw::kBlockData;
            for (; off + (pw::kNodeBytes + 4) <= end; off += pw::kNodeBytes + 4) {
                const pw::Node* nd = reinterpret_cast<const pw::Node*>(reinterpret_cast<const uint8_t*>(b) + off);
                if (++n > plan.maxNodes) return 4;
                if (plan.hf != 0 && !npr::SampleHeightField(s.fp, plan.hf, nd->x, nd->z)) return s.fp.overflow ? 2u : 1u;
            }
            if (b == g.nodes.current) break;
            b = b->next;
            off = 0;
            if (b == nullptr) return 4;
        }
    }
    if (s.fp.overflow) return 2;
    NPR_TIME(sealTime, npr_timing_ticks[2]);
    const pw::Result sealed = ws.SealSuccessors();
    return sealed == pw::Result::kOk ? 0u :
        (sealed >= pw::Result::kCapacityOpen && sealed <= pw::Result::kCapacityHash ? 2u : 4u);
}
uint32_t RunCallback(Slot& s) {
    __try {
        return CallbackImpl(s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 3;
    }
}

// ---- search scheduling --------------------------------------------------------------------------------------------------------------
struct AdvanceCtx {
    Slot* slots[NPR_MAX_SLOTS];
    uint32_t n, owner, remaining;
    volatile uint32_t done, workerChunks;
};

void AdvanceSlot(Slot& s) {
#ifdef NPR_TIMING
    s.advanceTicks = 0;
    s.advanceThread = GetCurrentThreadId();
    NPR_TIME(advanceTime, s.advanceTicks);
#endif
    const uint32_t csr = _mm_getcsr();
    if (csr != 0x1F80) _mm_setcsr(0x1F80);   // native numerical semantics, without changing owner callback FP state
    s.advRes = static_cast<uint32_t>(s.ws.Advance());
    ++s.rounds;
    if (csr != 0x1F80) _mm_setcsr(csr);
}

void FailSlot(Slot& s, uint32_t kind, bool fault = false) {
    s.dirty = 1;
    Reject(kind);
    if (fault) Bump(NPR_S_FAULTS);
    Xchg(&s.state, kSlotFailed);
}

// Owner only. The acquired kSlotAdvanced token excludes workers until all callback reads, native scratch use,
// footprint writes and SealSuccessors have finished. Publish kSlotRunning LAST, including on the inline path.
void ServiceAdvance(Slot& s) {
#ifdef NPR_TIMING
    npr_timing_ticks[s.advanceThread == g_owner ? 3 : 4] += s.advanceTicks;
#endif
    switch (static_cast<pw::Result>(s.advRes)) {
        case pw::Result::kNeedSuccessors: {
            const uint32_t r = RunCallback(s);
            if (r != 0) FailSlot(s, r == 2 ? NPR_REJECT_CAPACITY : r == 1 ? NPR_REJECT_GATE : NPR_REJECT_BAD_SHAPE, r == 3);
            else if (s.rounds == kMaxRounds) FailSlot(s, NPR_REJECT_CAPACITY);
            else Xchg(&s.state, kSlotRunning);
            break;
        }
        case pw::Result::kFound:
        case pw::Result::kNoPath:
        case pw::Result::kExpansionLimit:
            ++g_planned;
            Bump(NPR_S_PLANNED);
            Xchg(&s.state, kSlotDone);
            break;
        default:
            FailSlot(s, s.advRes >= static_cast<uint32_t>(pw::Result::kCapacityOpen) &&
                s.advRes <= static_cast<uint32_t>(pw::Result::kCapacityHash) ? NPR_REJECT_CAPACITY : NPR_REJECT_BAD_SHAPE);
            break;
    }
}

bool ClaimAdvance(AdvanceCtx& ctx, uint32_t& cursor) {
    for (uint32_t i = 0; i < ctx.n; ++i) {
        Slot& s = *ctx.slots[cursor];
        if (++cursor == ctx.n) cursor = 0;
        if (Cas(&s.state, kSlotAdvancing, kSlotRunning) != kSlotRunning) continue;
        AdvanceSlot(s);
        Xchg(&s.state, kSlotAdvanced);
        return true;
    }
    return false;
}

// One dispatch spans all remaining successor rounds, rather than waking/joining the team for each tiny Advance.
// Liveness: chunks <= workers+1 and each worker body stays here until owner completion, so workers cannot consume
// every chunk before the caller enters a body. Failed wakes / dispatcher inline fallback still enter on the owner:
// it services callbacks AND claims ready work, so it needs no worker to make progress. Subsequent bodies see done.
// Race proof: immutable ctx/slot pointers are published by dispatch; only the successful Running->Advancing CAS
// may touch a workspace. Advanced publication transfers it to the owner; Running publication transfers sealed
// private inputs back. Workers never touch footprint/game memory or owner counters. Done/Failed slots cannot be
// claimed. The owner's final done store follows ALL terminal slots; the dispatcher barrier precedes ctx destruction,
// consume/materialize, EndTick, stop and storage reuse. No callback runs concurrently with Advance on its own slot.
void __fastcall AdvanceBody(void* opaque, uint32_t chunk) {
    AdvanceCtx& ctx = *static_cast<AdvanceCtx*>(opaque);
    uint32_t cursor = chunk % ctx.n;
    if (GetCurrentThreadId() == ctx.owner) {
        while (ctx.remaining != 0) {
#ifdef NPR_TIMING
            const uint64_t waitStart = TimingNow();
#endif
            bool serviced = false;
            for (uint32_t i = 0; i < ctx.n; ++i) {
                Slot& s = *ctx.slots[i];
                if (Cas(&s.state, kSlotAdvanced, kSlotAdvanced) != kSlotAdvanced) continue;
                ServiceAdvance(s);
                // A published Running slot may already be advancing again; only terminal states decrement remaining.
                const uint32_t state = Cas(&s.state, 0, 0);
                if (state == kSlotDone || state == kSlotFailed) --ctx.remaining;
                serviced = true;
            }
            if (ctx.remaining != 0 && !serviced && !ClaimAdvance(ctx, cursor)) {
                _mm_pause();
#ifdef NPR_TIMING
                npr_timing_ticks[5] += TimingNow() - waitStart;
#endif
            }
        }
        Xchg(&ctx.done, 1);
    } else {
        uint32_t advances = 0;
        while (Cas(&ctx.done, 0, 0) == 0) {
            if (ClaimAdvance(ctx, cursor)) ++advances;
            else _mm_pause();   // awaiting an owner seal, not artificial work to keep a chunk occupied
        }
        _InterlockedExchangeAdd(VL(&ctx.workerChunks), static_cast<long>(advances));
    }
}

void DispatchAdvance(AdvanceCtx& ctx) {
    ntw_pool* p = reinterpret_cast<ntw_pool*>(static_cast<uintptr_t>(g_poolUser));
    const uint32_t inlineBefore = p->st_inline;
    const uint32_t chunks = ctx.n < p->workers + 1 ? ctx.n : p->workers + 1;
    ctx.owner = GetCurrentThreadId();
    ctx.remaining = ctx.n;
    ctx.done = ctx.workerChunks = 0;
    ntw_pool_dispatch(g_poolUser, static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&AdvanceBody)), chunks, &ctx);
    if (p->st_inline == inlineBefore) ++g_teamSteps;
    // Count actual private engine advances, not worker bodies which might wake after the owner finishes.
    g_workerChunks += ctx.workerChunks;
}

uint32_t PlanTick(uint32_t pf) {
#ifdef NPR_TIMING
    const uint64_t setupStart = TimingNow();
#endif
    uint32_t reqs[NPR_MAX_SLOTS];
    Collect c;
    CollectRequests(pf, g_usable, reqs, &c);
    if (c.faulted) Bump(NPR_S_FAULTS);
    uint32_t attempts = 0;
    for (uint32_t i = 0; i < c.n && attempts < g_maxNewPerTick; ++i) {
        bool cached = false;
        for (uint32_t j = 0; j < g_usable; ++j)
            if (g_slots[j].state == kSlotDone && g_slots[j].req == reqs[i]) { cached = true; break; }
        if (cached || IsRefused(reqs[i])) continue;
        Slot* slot = PlanningSlot(reqs, c.n);
        if (slot == nullptr) break;
        ++attempts;   // refused builds consume budget too, not just successful searches
        Slot& s = *slot;
        if (s.dirty) {
            s.ws.Shutdown();
            if (s.ws.Init(s.wsMem, s.wsBytes, s.wcfg) != pw::Result::kOk) {
                s.broken = 1;
                Reject(NPR_REJECT_CAPACITY);
                continue;
            }
            s.dirty = 0;
        }
        const uint32_t r = BuildInputs(s, pf, reqs[i]);
        if (r != 0) {
            Reject(r == 2 ? NPR_REJECT_CAPACITY : r == 3 ? NPR_REJECT_BAD_SHAPE : NPR_REJECT_INPUT);
            if (r == 4) RecordRefusal(reqs[i], s.querySnap);
            s.dirty = 1;   // seeds / workspace phase are unknown after a refused build
            continue;
        }
        s.planningTick = g_planningTick;
        s.rounds = 0;
        s.state = kSlotRunning;
    }
#ifdef NPR_TIMING
    npr_timing_ticks[6] += TimingNow() - setupStart;
#endif
    AdvanceCtx ctx;
    for (uint32_t round = 0; round < kMaxRounds; ++round) {
        ctx.n = 0;
        uint32_t neighbors = 0;
        for (uint32_t i = 0; i < g_usable; ++i) {
            Slot& s = g_slots[i];
            if (s.state != kSlotRunning) continue;
            ctx.slots[ctx.n++] = &s;
            neighbors += s.ws.graph().neighbors.size;
        }
        if (ctx.n == 0) break;
        const ntw_pool* pool = reinterpret_cast<const ntw_pool*>(static_cast<uintptr_t>(g_poolUser));
        if (round >= kInlineRounds && ctx.n >= kMinTeamSlots && neighbors >= kMinTeamNeighbors && pool->workers != 0) {
            DispatchAdvance(ctx);
            break;
        }
        // Short or narrow batches do not touch the dispatcher and therefore never wake sleeping workers.
        for (uint32_t i = 0; i < ctx.n; ++i) AdvanceSlot(*ctx.slots[i]);
        for (uint32_t i = 0; i < ctx.n; ++i) ServiceAdvance(*ctx.slots[i]);
    }
    uint32_t available = 0;
    for (uint32_t i = 0; i < g_usable; ++i) {
        if (g_slots[i].state == kSlotDone) ++available;
        else if (g_slots[i].state == kSlotFailed) {
            g_slots[i].state = kSlotFree;
        }
    }
    return available;   // a tick with no NEW plans can still consume carried results
}

// ---- tick lifecycle ----------------------------------------------------------------------------------------------------------------
void PublishStats() {
    Store(NPR_S_TEAM_STEPS, g_teamSteps);
    Store(NPR_S_WORKER_CHUNKS, g_workerChunks);
}

void ReleaseOwner() {
    g_tickActive = 0;
    g_tickByHook = 0;
    Store(NPR_S_OWNER_THREAD, 0);
    Xchg(&g_owner, 0);
}

bool BeginTick(uint32_t pf, bool byHook) {
    if (npr_state[NPR_S_ENABLED] == 0 || g_sched == 0) return false;
    const uint32_t tid = GetCurrentThreadId();
    if (Cas(&g_owner, tid, 0) != 0) return false;                       // re-entrant, another thread, or stopping
    if (npr_state[NPR_S_ENABLED] == 0 || !Bound(pf)) {                   // stop raced the CAS / foreign pathfinder
        Xchg(&g_owner, 0);
        return false;
    }
    Store(NPR_S_OWNER_THREAD, tid);
    ++g_ticks;
    ++g_planningTick;
    Store(NPR_S_TICKS, g_ticks);
    const uint32_t act = PlanTick(pf);
    if (act == 0) {
        PublishStats();
        ReleaseOwner();
        return false;
    }
    g_tickByHook = byHook ? 1 : 0;
    g_tickActive = 1;
    return true;
}

void EndTick() {
    for (uint32_t i = 0; i < g_usable; ++i) {
        Slot& s = g_slots[i];
        if (s.state == kSlotDone) Bump(NPR_S_CARRIED);
        else if (s.state != kSlotFree) s.state = kSlotFree;
    }
    PublishStats();
    ReleaseOwner();
}

// ---- consumption -------------------------------------------------------------------------------------------------------------------------
bool NodeSame(const pw::Node* real, const pw::Node& snap, uint32_t q, uint32_t g) {
    // every semantic field of the 0x34-byte node; the pad bytes (+0x1A/+0x1B/+0x25..+0x27) are never written by 0x7EB5C0 / 0x7EB210
    // and never read by the engine, so they are not compared.  graph must be the REAL G and query the request's query.
    return real->object == snap.object && memcmp(&real->x, &snap.x, 16) == 0 &&   // x, y, z, tag
           memcmp(&real->aux14, &snap.aux14, 4) == 0 && real->flag18 == snap.flag18 && real->flag19 == snap.flag19 &&
           static_cast<uint32_t>(reinterpret_cast<uintptr_t>(real->graph)) == g &&
           static_cast<uint32_t>(reinterpret_cast<uintptr_t>(real->query)) == q && real->goalMarker == snap.goalMarker &&
           real->aux28 == snap.aux28 && memcmp(&real->scale, &snap.scale, 8) == 0;                                    // scale, accumulated
}

bool ValidateImpl(Slot& s, uint32_t g, const pw::Node* start, const pw::Node* goal, uint32_t via, uint32_t flag) {
    const uint32_t q = s.query;
    if (npr::Rd32(g + 8) != g || npr::Rd32(g + 4) != g_root) return false;
    if (npr::Rd32(g_pf + 0x2E4) != s.req) return false;
    if (npr::Rd32(g + 0xE8) != s.limit || npr::Rd8(g + 0xC) != s.overwrite) return false;
    for (uint32_t i = 0; i < 5; ++i)
        if (npr::Rd32(V(0x150FCA0) + 4 * i) != s.sentinel[i]) return false;
    if (!QuerySame(q, s.querySnap)) return false;
    if (via != s.viaPtr || static_cast<uint8_t>(flag) != s.flag) return false;
    if (!NodeSame(start, s.startSnap, q, g) || !NodeSame(goal, s.goalSnap, q, g)) return false;
    const void* qp = reinterpret_cast<const void*>(static_cast<uintptr_t>(q));
    const pw::Node* target = goal;
    if (s.hasVia) {   // rebuild the via seed exactly as 0x8026F0 would now, then compare
        memset(&s.viaCheck, 0, sizeof s.viaCheck);
        pw::Node* v = g_seed(&s.viaCheck, nullptr, reinterpret_cast<const void*>(static_cast<uintptr_t>(g + 4)), reinterpret_cast<void*>(static_cast<uintptr_t>(g)), qp,
                             reinterpret_cast<const void*>(static_cast<uintptr_t>(via)), s.radius);
        if (v->object == nullptr || !NodeSame(v, s.viaSnap, q, g)) return false;
        target = v;
    }
    if (pw::RegionCrossFlag(qp, start, target) != s.region1) return false;
    if (s.hasVia && pw::RegionCrossFlag(qp, target, goal) != s.region2) return false;
    return s.fp.Equal();
}
bool Validate(Slot& s, uint32_t g, const pw::Node* start, const pw::Node* goal, uint32_t via, uint32_t flag) {
    __try {
        return ValidateImpl(s, g, start, goal, via, flag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Bump(NPR_S_FAULTS);
        return false;
    }
}

// Post-state of 0x8026F0 on the real G (arena reset of 0x802A80, output vector, epilogue 0x802A0B..0x802A74).
uint32_t Materialize(Slot& s, uint32_t g) {
    const pw::Graph& pg = s.ws.graph();
    const bool found = s.ws.LastResult() == pw::Result::kFound;
    Wr32(g + 0xE4, 0);
    Wr32(g + 0xF4, 0);                                        // output.size = 0 (data / capacity are kept, as natively)
    const uint32_t head = npr::Rd32(g + 0x7C);                // arena B: current = head, head->used = 0
    Wr32(g + 0x80, head);
    if (head != 0) Wr32(head + 0x2804, 0);
    const uint32_t n = s.ws.OutputCount();
    pw::Node* const* out = s.ws.Output();
    for (uint32_t i = 0; i < n; ++i) {
        pw::Node* dst = static_cast<pw::Node*>(g_alloc(reinterpret_cast<void*>(static_cast<uintptr_t>(g + 0x7C)), nullptr, pw::kNodeBytes, pw::kArenaShift));
        memcpy(dst, out[i], pw::kNodeBytes);
        dst->graph = reinterpret_cast<pw::Graph*>(static_cast<uintptr_t>(g));
        g_push(reinterpret_cast<void*>(static_cast<uintptr_t>(g + 0xEC)), nullptr, &dst);
    }
    Wr32(g + 0xE4, pg.expansions);
    Wr32(g + 0x120, npr::Rd32(g + 0x120) + pg.expansions);
    Wr32(g + 0xFC, 0);
    Wr32(g + 0x100, 0);
    const uint32_t k = V(0x150FCA0);
    Wr32(g + 0x104, npr::Rd32(k + 8));
    Wr32(g + 0x108, npr::Rd32(k + 0xC));
    Wr32(g + 0x10C, npr::Rd32(k + 0x10));
    Wr32(g + 0x110, npr::Rd32(k));
    Wr32(g + 0x114, npr::Rd32(k + 4));
    Wr32(g + 0x118, npr::Rd32(k));
    Wr32(g + 0x11C, npr::Rd32(k + 4));
    *reinterpret_cast<volatile uint16_t*>(static_cast<uintptr_t>(g + 0x124)) = 0;   // flag124 = regionFlag = 0
    return found ? 1u : 0u;
}

bool TryConsume(uint32_t g, uint32_t q, const pw::Node* start, const pw::Node* goal, uint32_t via, uint32_t flag, uint32_t* result) {
    NPR_TIME(consumeTime, npr_timing_ticks[7]);
    if (g != g_pf + 0x1BC) return false;
    Slot* s = nullptr;
    for (uint32_t i = 0; i < g_usable && s == nullptr; ++i)
        if (g_slots[i].state == kSlotDone && g_slots[i].query == q) s = &g_slots[i];
    if (s == nullptr) return false;
    s->state = kSlotConsumed;   // single use, whatever the outcome
    if (!Bound(g_pf) || !Validate(*s, g, start, goal, via, flag)) {
        Bump(NPR_S_STALE);
        return false;
    }
    *result = Materialize(*s, g);
    Bump(NPR_S_CONSUMED);
    return true;
}

}  // namespace

// ---- hooks -------------------------------------------------------------------------------------------------------------------------
extern "C" uint32_t __fastcall npr_solve(void* g, void* edx, const void* query, const void* start, void* goal, void* via, uint32_t flag) {
    if (g_owner == GetCurrentThreadId() && g_tickActive != 0) {
        uint32_t r = 0;
        if (TryConsume(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g)), static_cast<uint32_t>(reinterpret_cast<uintptr_t>(query)),
                       static_cast<const pw::Node*>(start), static_cast<const pw::Node*>(goal), static_cast<uint32_t>(reinterpret_cast<uintptr_t>(via)), flag, &r))
            return r;
    }
    Bump(NPR_S_FALLBACKS);
    return g_solve(g, edx, query, start, goal, via, flag);
}

extern "C" void __fastcall npr_scheduler_hook(void* pf) {
    const bool owned = BeginTick(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pf)), true);
    __try {
        reinterpret_cast<void(__fastcall*)(void*)>(static_cast<uintptr_t>(g_sched ? g_sched : V(NPR_VA_SCHEDULER)))(pf);
    } __finally {
        if (owned) EndTick();   // also while an exception unwinds: the owner slot and the tick never stay open
    }
}

extern "C" void __fastcall npr_prepass(void* pf) {
    if (g_owner == GetCurrentThreadId()) return;   // inside a hook tick (or already prepassed)
    BeginTick(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pf)), false);
}

extern "C" void __fastcall npr_end(void*) {
    if (g_owner == GetCurrentThreadId() && g_tickActive != 0 && g_tickByHook == 0) EndTick();
}

// ---- lifecycle ---------------------------------------------------------------------------------------------------------------------
namespace {

bool ReadConfig(const void* p, npr_config* out) {
    if (!p) return false;
    __try {
        memcpy(out, p, sizeof *out);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SafeLiveWords(uint32_t delta, uint32_t* out) {
    __try {
        for (uint32_t i = 0; i < 5; ++i) out[i] = npr::Rd32(0x150FCA0 + delta + 4 * i);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool PoolReady(uint32_t pool) {
    __try {
        const ntw_pool* p = reinterpret_cast<const ntw_pool*>(static_cast<uintptr_t>(pool));
        return p->abi == NTW_POOL_ABI && p->state == NTW_POOL_S_READY;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SameImage(uint32_t pf, uint32_t root, uint32_t model) {
    __try {
        return npr::Rd32(pf) == root && npr::Rd32(root + 8) == model && npr::Rd32(model + NPR_VA_MODEL_PF_OFFSET) == pf;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void FreeSlots() {
    if (g_mem != nullptr) {
        for (uint32_t i = 0; i < g_slotCount; ++i) {
            DropResult(g_slots[i]);
            g_slots[i].ws.Shutdown();
        }
        VirtualFree(g_mem, 0, MEM_RELEASE);
    }
    g_mem = nullptr;
    npr_storage_bytes = 0;
    g_slots = nullptr;
    g_slotCount = 0;
    g_usable = 0;
}

}  // namespace

extern "C" uint32_t __stdcall npr_initialize(void* config) {
    npr_config c;
    if (!ReadConfig(config, &c)) return Err(NPR_E_ARG, 0);
    if (c.abi != NPR_ABI || c.size != NPR_CONFIG_BYTES || c.root == 0 || c.model == 0 || c.pf == 0 || c.workers > NPR_MAX_WORKERS ||
        c.slots == 0 || c.slots > NPR_MAX_SLOTS || c.openCapacity > (1u << 20) || c.neighborCapacity == 1 || c.neighborCapacity > 4096 ||
        c.nodeBlocks > 4096 || c.entryBlocks > 4096 || c.hashLevels > 12 || c.maxNewPerTick > NPR_MAX_SLOTS)
        return Err(NPR_E_ARG, 0);

    uint32_t from = kLifeNone;
    if (Cas(&g_life, kLifeInitializing, kLifeNone) != kLifeNone) {
        if (Cas(&g_life, kLifeInitializing, kLifeStopped) != kLifeStopped) return Err(NPR_E_STATE, 0);
        from = kLifeStopped;
    }
    if (from == kLifeStopped) {
        if (c.imageDelta != g_delta) { Xchg(&g_life, from); return Err(NPR_E_ARG, 1); }
        if (npr_state[NPR_S_PHASE] != 2 || npr_state[NPR_S_ENABLED] != 0 || npr_state[NPR_S_OWNER_THREAD] != 0 || g_owner != kStopToken || g_poolLive) {
            Xchg(&g_life, from);
            return Err(NPR_E_STATE, 1);
        }
    }
    auto fail = [&](uint32_t e) {
        Xchg(&g_life, from);
        return e;
    };

    const uint32_t imgDetail = VerifyImage(c.imageDelta);
    if (imgDetail != 0) return fail(Err(NPR_E_IMAGE, imgDetail));
    uint32_t sentinel[5];
    if (!SafeLiveWords(c.imageDelta, sentinel) || !SameImage(c.pf, c.root, c.model)) return fail(Err(NPR_E_ARG, 1));

    pw::Config wc;
    wc.openCapacity = c.openCapacity ? c.openCapacity : kDefOpen;
    wc.neighborCapacity = c.neighborCapacity ? c.neighborCapacity : kDefNeighbors;
    wc.outputCapacity = kDefOutput;
    wc.entryBlocks = c.entryBlocks ? c.entryBlocks : kDefEntryBlocks;
    wc.nodeBlocks = c.nodeBlocks ? c.nodeBlocks : kDefNodeBlocks;
    wc.hashLevels = c.hashLevels ? c.hashLevels : kDefHashLevels;
    wc.expansionLimit = pw::kDefaultExpansionLimit;
    wc.graphVtable = 0x1347250u + c.imageDelta;
    wc.root = reinterpret_cast<const void*>(static_cast<uintptr_t>(c.root));
    wc.overwriteNode = 0;
    memcpy(&wc.constants.sentinelPair[0], &sentinel[0], 4);
    memcpy(&wc.constants.sentinelPair[1], &sentinel[1], 4);
    memcpy(&wc.constants.sentinelPos[0], &sentinel[2], 4);
    memcpy(&wc.constants.sentinelPos[1], &sentinel[3], 4);
    memcpy(&wc.constants.sentinelPos[2], &sentinel[4], 4);
    const size_t wsBytes = pw::Workspace::RequiredBytes(wc);
    if (wsBytes == 0) return fail(Err(NPR_E_ARG, 0));
    const size_t offCtl = AlignUp(static_cast<size_t>(c.slots) * sizeof(Slot), 64);   // contiguous Slot array first
    const size_t offWs = 0;
    const size_t offRanges = offWs + AlignUp(wsBytes, 64);
    const size_t offTable = offRanges + AlignUp(static_cast<size_t>(kFpRanges) * sizeof(npr::Fp::Range), 64);
    const size_t offBytes = offTable + AlignUp(static_cast<size_t>(kFpTable) * 4, 64);
    const size_t stride = offBytes + AlignUp(kFpBytes, 64);   // per-slot data block (workspace + footprint)
    if (stride > (kMaxTotalBytes - offCtl) / c.slots) return fail(Err(NPR_E_ARG, 0));
    const size_t total = offCtl + stride * c.slots;
    uint8_t* mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!mem) return fail(Err(NPR_E_MEMORY, GetLastError()));

    if (!g_pinned) {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, reinterpret_cast<LPCWSTR>(&npr_initialize), &self)) {
            const uint32_t le = GetLastError();
            VirtualFree(mem, 0, MEM_RELEASE);
            return fail(Err(NPR_E_MEMORY, le));
        }
        g_pinned = true;
    }

    bool poolOwn = false;
    uint32_t poolUser;
    if (c.pool != 0) {
        if (!PoolReady(c.pool)) { VirtualFree(mem, 0, MEM_RELEASE); return fail(Err(NPR_E_POOL, 0x100)); }
        poolUser = c.pool;
    } else {
        ntw_pool_config pc;
        memset(&pc, 0, sizeof pc);
        pc.abi = NTW_POOL_ABI;
        pc.workers = c.workers;
        pc.stack_bytes = kWorkerStackBytes;
        pc.api.create_event = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CreateEventW));
        pc.api.close_handle = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CloseHandle));
        pc.api.set_event = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&SetEvent));
        pc.api.wait_single = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&WaitForSingleObject));
        pc.api.create_thread = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CreateThread));
        pc.api.worker_entry = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&ntw_pool_worker_start));
        const ntw_u32 pr = ntw_pool_init(OwnPool(), &pc);
        if (pr != NTW_POOL_OK) { VirtualFree(mem, 0, MEM_RELEASE); return fail(Err(NPR_E_POOL, pr)); }
        poolOwn = true;
        poolUser = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(OwnPool()));
    }

    // slots
    Slot* const ctl = reinterpret_cast<Slot*>(mem);
    uint32_t built = 0;
    bool ok = true;
    for (uint32_t i = 0; i < c.slots && ok; ++i) {
        uint8_t* base = mem + offCtl + stride * i;
        Slot* s = new (&ctl[i]) Slot();
        s->wcfg = wc;
        s->wsMem = base + offWs;
        s->wsBytes = wsBytes;
        s->fp.ranges = reinterpret_cast<npr::Fp::Range*>(base + offRanges);
        s->fp.capRanges = kFpRanges;
        s->fp.table = reinterpret_cast<uint32_t*>(base + offTable);
        s->fp.tableMask = kFpTable - 1;
        s->fp.bytes = base + offBytes;
        s->fp.capBytes = kFpBytes;
        s->fp.Reset();
        ok = s->ws.Init(s->wsMem, s->wsBytes, s->wcfg) == pw::Result::kOk;
        built = i + 1;
        (void)0;
    }
    if (!ok) {
        for (uint32_t i = 0; i < built; ++i) ctl[i].ws.Shutdown();
        if (poolOwn) {
            const ntw_u32 sr = ntw_pool_shutdown(OwnPool());
            if (sr != NTW_POOL_OK) return fail(Err(NPR_E_POOL, sr));   // team that cannot be joined keeps the memory it may touch
        }
        VirtualFree(mem, 0, MEM_RELEASE);
        return fail(Err(NPR_E_MEMORY, 0x200));
    }

    // g_slots[i] is the contiguous control array; each slot's workspace / footprint storage lives in its own data block.

    // publish (exclusive and disabled: first session nobody can own; later session the stop token is still held)
    FreeSlots();   // releases a previous session's slots (stopped state only)
    g_mem = mem;
    npr_storage_bytes = static_cast<uint32_t>(total);
    g_slotCount = c.slots;
    g_usable = c.slots;
    g_maxNewPerTick = c.maxNewPerTick ? c.maxNewPerTick : 4;
    g_planningTick = 0;
    memset(g_refused, 0, sizeof g_refused);
    g_slots = ctl;
    g_poolOwn = poolOwn;
    g_poolLive = poolOwn;
    g_poolUser = poolUser;
    g_workers = c.workers;
    g_root = c.root;
    g_model = c.model;
    g_pf = c.pf;
    g_sched = c.scheduler;
    g_teamSteps = g_workerChunks = g_ticks = g_planned = g_callbacks = 0;
    if (from == kLifeNone) {
        g_delta = c.imageDelta;
        g_succ = reinterpret_cast<SuccFn>(static_cast<uintptr_t>(V(NPR_VA_SUCCESSOR)));
        g_seed = reinterpret_cast<SeedFn>(static_cast<uintptr_t>(V(0x7EB210)));
        g_startPos = reinterpret_cast<StartPosFn>(static_cast<uintptr_t>(V(0x816CA0)));
        g_alloc = reinterpret_cast<AllocFn>(static_cast<uintptr_t>(V(0x80B0F0)));
        g_push = reinterpret_cast<PushFn>(static_cast<uintptr_t>(V(0x448B90)));
        g_solve = reinterpret_cast<SolveFn>(static_cast<uintptr_t>(V(NPR_VA_SOLVE)));
        g_targets.gwSelf = V(0x4470B0);
        g_targets.gwZero = V(0x461180);
        g_targets.gwFlag = V(0x6B7F90);
        g_targets.iface = V(0x7FF170);
        g_targets.embedded = V(0x54E920);
    }
    for (uint32_t w = NPR_S_TICKS; w < NPR_STATE_WORDS; ++w) Store(w, 0);
    Xchg(&g_life, kLifeReady);
    Xchg(&npr_state[NPR_S_PHASE], 1);
    Xchg(&npr_state[NPR_S_ENABLED], 1);
    Xchg(&g_owner, 0);
    return NPR_OK;
}

extern "C" uint32_t __stdcall npr_stop(void*) {
    for (;;) {
        const uint32_t life = g_life;
        if (life == kLifeNone) return Err(NPR_E_STATE, 0);
        if (life == kLifeStopped) return NPR_OK;
        if (life != kLifeReady) return Err(NPR_E_BUSY, 0);
        if (Cas(&g_life, kLifeStopping, kLifeReady) == kLifeReady) break;
    }
    Xchg(&npr_state[NPR_S_ENABLED], 0);                                   // no new tick can start from here on
    if (Cas(&g_owner, kStopToken, 0) != 0) { Xchg(&g_life, kLifeReady); return Err(NPR_E_BUSY, 0); }   // a tick is active: call again later
    PublishStats();
    if (g_poolOwn) {
        const ntw_u32 r = ntw_pool_shutdown(OwnPool());
        if (r != NTW_POOL_OK) {
            Xchg(&g_owner, 0);   // stays disabled; the team is never used again
            Xchg(&g_life, kLifeReady);
            return Err(NPR_E_POOL, r);
        }
        g_poolLive = false;
    }
    FreeSlots();                // no tick can exist and npr_solve never touches slots without owning a tick
    Xchg(&npr_state[NPR_S_PHASE], 2);
    Xchg(&g_life, kLifeStopped);   // g_owner keeps the stop token until a new session is published
    return NPR_OK;
}
