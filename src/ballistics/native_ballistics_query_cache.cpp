// native_ballistics_query_cache.dll: precomputes the PURE numeric narrow phase of the ballistic unit test (original 0x809620) for
// the candidates of ONE projectile grid query and answers the original call with it.  See native_ballistics_query_cache.h for the
// ABI and the clone seams.  Numerics are the existing nbc ABI 3 core (native_ballistics_collision.cpp, linked unchanged) on the
// relocated WORKER kit and the existing persistent dispatcher; this file adds no arithmetic.
//
// Per query (all on the owner thread unless noted):
//   nqc_query_hook     claims ONE exclusive scope (CAS on g_owner, once per query), checks enabled and the configured model /
//                      root / grid identity, runs the private clone of 0x6392C0 synchronously and releases the scope in a
//                      __finally (an exception of the original code is never swallowed).  Busy / other thread / wrong model
//                      runs the ORIGINAL 0x6392C0.
//   nqc_gather_hook    ORIGINAL 0x10EED80 once, then (owner scope only) snapshots, from the frame of the query and READ ONLY,
//                      every kind-8 candidate the original loop could hand to 0x809620 (type mask, 0x6DC9A0 == byte [obj+0x30],
//                      unit visited bit clear, [obj+0x34] & 8, pure getter leaf), copies the immutable numeric inputs (five unit
//                      floats, six ray floats, mode, extra, getter value) into private contiguous storage, runs ONE nbc batch
//                      (inline below minParallel, otherwise the shared persistent team) and returns with every register,
//                      EFLAGS, x87 and MXCSR state exactly as the original call left it.  Nothing here writes game memory,
//                      calls a game function or invokes the opaque getter; workers see only private values.
//   nqc_unit_hook      replaces the original 0x809620 call.  Serves the cached boolean + t only when the owner scope, ray,
//                      mode, selector, extra, FP controls, the five unit floats and the getter (vtable slot +0x18 target, its
//                      pinned pure leaf bytes and the value they produce) are re-read and unchanged; otherwise calls the
//                      ORIGINAL 0x809620 exactly once.  Hit positions, appends, RNG and effects remain the original code.
//
// Lifecycle (one life word; initialize / stop never overlap): nqc_stop disables entries FIRST, then takes the owner slot with a
// CAS (busy while a scope is active), keeps the stop token so no scope can start and the DLL stays pinned.  The private storage
// is one block: a restart reuses it when the new layout fits, else replaces it (see nqc_initialize).  A new session (same imageDelta, optionally new root/model/clone/pool/kernels/capacity) is accepted only from
// that stopped, disabled, ownerless state.  The pool is shared: this module never initialises or shuts it down.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <emmintrin.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

#include "native_ballistics_collision.h"
#include "native_ballistics_query_cache.h"
#include "native_worker_dispatch.h"

static_assert(sizeof(void*) == 4, "x86 build required");

// ---- source pins (generated) -------------------------------------------------------------------------------------------------
struct NqcPinHole {
    uint32_t off, kind, expect;
};
struct NqcPinRegion {
    uint32_t va, size;
    uint64_t hash;
    uint32_t first, count;
};
struct NqcKernelPin {
    uint32_t va, len;
    uint8_t bytes[24];
};
enum : uint32_t { kHoleAbs = 0, kHoleRel = 1, kHoleGather = 2, kHoleUnit = 3, kHoleTable = 4 };
#include "native_ballistics_query_cache_pins.inc"
static_assert(sizeof(kPinRegions) / sizeof(kPinRegions[0]) == 4, "pin regions: query, unit_hit, gather, predicate");
static_assert(sizeof(kPinKernels) / sizeof(kPinKernels[0]) == 6, "six kernels");

// ---- exports ------------------------------------------------------------------------------------------------------------------
#pragma comment(linker, "/EXPORT:nqc_initialize=_nqc_initialize@4")
#pragma comment(linker, "/EXPORT:nqc_stop=_nqc_stop@4")
#pragma comment(linker, "/EXPORT:nqc_query_hook=@nqc_query_hook@44")
#pragma comment(linker, "/EXPORT:nqc_gather_hook=_nqc_gather_hook")
#pragma comment(linker, "/EXPORT:nqc_unit_hook=@nqc_unit_hook@28")

extern "C" __declspec(dllexport) volatile uint32_t nqc_state[NQC_STATE_WORDS] = {NQC_ABI, NQC_STATE_BYTES};
static_assert(sizeof(nqc_state) == NQC_STATE_BYTES, "nqc_state is sixteen u32 words");

extern "C" {
// call target of the naked gather thunk (original 0x10EED80 at imageDelta, set once by the first session)
volatile uint32_t g_nqcOrigGather = 0;
void __cdecl nqc_gather_prep(uint32_t ebp, uint32_t ebx, const uint32_t* env);
uint32_t __stdcall nqc_initialize(void* config);
uint32_t __stdcall nqc_stop(void* unused);
uint32_t __fastcall nqc_query_hook(void* grid, void* edx, uint32_t out, uint32_t segment, uint32_t stop, uint32_t mask,
                                   uint32_t alt, uint32_t mode, uint32_t visited, uint32_t arg8, uint32_t extra);
uint32_t __fastcall nqc_unit_hook(void* object, void* edx, const float* ray, uint32_t mode, float* outT, uint32_t selector,
                                  uint32_t extra);
}

namespace {

constexpr uint32_t kLifeNone = 0, kLifeInitializing = 1, kLifeReady = 2, kLifeStopped = 3, kLifeStopping = 4;
constexpr uint32_t kStopToken = 0xFFFFFFFFu;   // g_owner value while stopping / stopped; never a thread id
constexpr uint32_t kNoSlot = 0xFFFFFFFFu;

constexpr uint32_t kMaxCells = 0x10000;        // gathered cells of one query
constexpr uint32_t kMaxEntries = 0x100000;     // list entries walked per query
constexpr uint32_t kMaxShift = 16;
constexpr uint32_t kLeafBytes = 8;

constexpr uint32_t kFrameGrid = 0x18, kFrameVec = 0x10, kFrameBitset = 0x3C;      // [ebp - x]
constexpr uint32_t kFrameSegment = 0xC, kFrameMask = 0x14, kFrameMode = 0x1C, kFrameExtra = 0x28;   // [ebp + x]

enum : uint32_t { kFormNone = 0, kFormZero = 1, kFormThis = 2, kFormLoad = 3, kFormLea = 4 };

// ---- low level helpers ----------------------------------------------------------------------------------------------------------
inline volatile long* VL(volatile uint32_t* p) { return reinterpret_cast<volatile long*>(p); }
inline uint32_t Xchg(volatile uint32_t* p, uint32_t v) { return static_cast<uint32_t>(_InterlockedExchange(VL(p), static_cast<long>(v))); }
inline uint32_t Cas(volatile uint32_t* p, uint32_t desired, uint32_t expected) {
    return static_cast<uint32_t>(_InterlockedCompareExchange(VL(p), static_cast<long>(desired), static_cast<long>(expected)));
}
inline void Inc(uint32_t word) { _InterlockedIncrement(VL(&nqc_state[word])); }
inline void AddN(uint32_t word, uint32_t n) { if (n) _InterlockedExchangeAdd(VL(&nqc_state[word]), static_cast<long>(n)); }
inline uint32_t R32(uint32_t a) { return *reinterpret_cast<const volatile uint32_t*>(static_cast<uintptr_t>(a)); }
inline uint32_t Tid() { return static_cast<uint32_t>(__readfsdword(0x24)); }   // TEB.ClientId.UniqueThread: no call, no import
inline uint32_t Err(uint32_t cls, uint32_t detail) { return cls | (detail << 8); }
inline uint32_t Bits(const float& f) { return *reinterpret_cast<const uint32_t*>(&f); }

// SEH filter of every guarded read of game memory: a bad pointer only declines the optimisation.  Anything else keeps propagating.
inline int Decline(unsigned long code) {
    return (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

bool ReadBytes(uint32_t addr, void* dst, uint32_t n) {
    __try {
        memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), n);
        return true;
    } __except (Decline(GetExceptionCode())) {
        return false;
    }
}

bool ExecOk(uint32_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), &mbi, sizeof mbi)) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

uint64_t Fnv(const uint8_t* b, uint32_t n, uint64_t h) {
    for (uint32_t i = 0; i < n; ++i) h = (h ^ b[i]) * 0x100000001B3ULL;
    return h;
}

// ---- session globals (published by nqc_initialize under the stop token; read by hooks only while enabled) -----------------------
volatile uint32_t g_life = kLifeNone;
volatile uint32_t g_owner = 0;      // 0 idle, thread id during a scope, kStopToken while stopping / stopped
bool g_pinned = false;
uint32_t g_delta = 0;
uint32_t g_root = 0, g_model = 0, g_clone = 0, g_minParallel = 1, g_dispatch = 0, g_pool = 0;
uint32_t g_origQuery = 0, g_origUnit = 0;
nbc_kernels g_kernels = {};

#pragma pack(push, 8)
struct Rec {                 // one distinct unit object of the current query
    uint32_t object;
    uint32_t u5[5];          // float bits at +0x48 .. +0x58
    uint32_t vtable;
    uint32_t leaf;           // [vtable + 0x18]
    uint32_t form;           // kForm*
    int32_t disp;
    uint32_t value;          // getter result the pure leaf produces
    uint32_t slot;           // batch index, kNoSlot for a declined object
    uint32_t mapPos;
    uint32_t len;            // pinned leaf bytes
    uint8_t bytes[kLeafBytes];
};
#pragma pack(pop)
static_assert(sizeof(Rec) == 64, "record size");

struct Store {
    nbc_cand* cands;
    nbc_result* results;
    Rec* recs;
    uint32_t* map;
    uint32_t mapBits;
    uint32_t capacity;
    uint32_t bytes;
};
Store g_store = {};

struct alignas(64) Cache {
    volatile uint32_t valid;   // 1: results[] are complete and may be consumed by the owner thread
    uint32_t count;            // records (cached + declined) in recs[] / map
    uint32_t grid;             // scope grid (ECX of the query)
    uint32_t rayPtr;           // alt + 4 of the query
    uint32_t ray[6];
    uint32_t mode, extra, selector;
    uint32_t mxcsr, cw;        // owner FP controls captured by nbc_run
    nbc_segment src, alt;
    nbc_batch batch;
};
Cache g_cache;

inline uint32_t HashPtr(uint32_t p, uint32_t bits) { return (p * 0x9E3779B1u) >> (32u - bits); }

Rec* Lookup(uint32_t obj) {
    const Store& s = g_store;
    const uint32_t mask = (1u << s.mapBits) - 1u;
    uint32_t i = HashPtr(obj, s.mapBits);
    for (;;) {
        const uint32_t e = s.map[i];
        if (!e) return nullptr;
        if (s.recs[e - 1].object == obj) return &s.recs[e - 1];
        i = (i + 1u) & mask;
    }
}

// Clears the cache of the scope (owner only, or under the stop token).  Keeps the map all zero between queries without a memset.
void InvalidateCache() {
    Cache& c = g_cache;
    c.valid = 0;
    const Store& s = g_store;
    if (s.map) {
        for (uint32_t i = 0; i < c.count; ++i) s.map[s.recs[i].mapPos] = 0;
    }
    c.count = 0;
}

// ---- pure leaf recognition ---------------------------------------------------------------------------------------------------------
// Only these leaves are accepted (every one ends in RET, touches no memory except one read of [ecx+disp], has no call / prologue):
//   xor eax,eax; ret | mov eax,ecx; ret | mov eax,[ecx+disp]; ret | lea eax,[ecx+disp]; ret
// A byte-only load, movzx, an immediate, a jmp thunk, a hot-patch prefix, anything with a prologue or a stack frame is refused.
bool ClassifyLeaf(const uint8_t* b, uint32_t* form, int32_t* disp, uint32_t* len) {
    *disp = 0;
    if ((b[0] == 0x33 || b[0] == 0x31) && b[1] == 0xC0 && b[2] == 0xC3) { *form = kFormZero; *len = 3; return true; }
    if (((b[0] == 0x8B && b[1] == 0xC1) || (b[0] == 0x89 && b[1] == 0xC8)) && b[2] == 0xC3) { *form = kFormThis; *len = 3; return true; }
    if (b[0] != 0x8B && b[0] != 0x8D) return false;
    const uint32_t f = b[0] == 0x8B ? kFormLoad : kFormLea;
    if (b[1] == 0x01 && b[2] == 0xC3) { *form = f; *len = 3; return true; }
    if (b[1] == 0x41 && b[3] == 0xC3) { *form = f; *disp = static_cast<int8_t>(b[2]); *len = 4; return true; }
    if (b[1] == 0x81 && b[6] == 0xC3) {
        int32_t d;
        memcpy(&d, b + 2, 4);
        *form = f; *disp = d; *len = 7;
        return true;
    }
    return false;
}

inline uint32_t EvalLeaf(uint32_t form, int32_t disp, uint32_t obj) {   // Load reads game memory: caller is under SEH
    switch (form) {
    case kFormZero: return 0;
    case kFormThis: return obj;
    case kFormLoad: return R32(obj + static_cast<uint32_t>(disp));
    default: return obj + static_cast<uint32_t>(disp);
    }
}

// ---- shared pool (read only here) --------------------------------------------------------------------------------------------------
struct PoolSnap {
    uint32_t team, mainChunks, inlineRuns, workerChunks;
};

bool PoolDispatchable() {
    __try {
        const volatile ntw_pool* p = reinterpret_cast<const volatile ntw_pool*>(static_cast<uintptr_t>(g_pool));
        return p->abi == NTW_POOL_ABI && (p->state == NTW_POOL_S_READY || p->state == NTW_POOL_S_BUSY) && p->workers <= NTW_POOL_MAX_WORKERS;
    } __except (Decline(GetExceptionCode())) {
        return false;
    }
}

bool SnapPool(PoolSnap* s) {
    __try {
        const volatile ntw_pool* p = reinterpret_cast<const volatile ntw_pool*>(static_cast<uintptr_t>(g_pool));
        uint32_t worker = 0;
        const uint32_t n = p->workers < NTW_POOL_MAX_WORKERS ? p->workers : NTW_POOL_MAX_WORKERS;
        for (uint32_t i = 0; i < n; ++i) worker += p->slots[i].chunks;
        s->team = p->st_team;
        s->mainChunks = p->st_main_chunks;
        s->inlineRuns = p->st_inline;
        s->workerChunks = worker;
        return true;
    } __except (Decline(GetExceptionCode())) {
        return false;
    }
}

// ---- query scope -------------------------------------------------------------------------------------------------------------------
bool Bound(uint32_t grid) {
    __try {
        return grid != 0 && R32(g_model) == g_root && R32(g_model + NQC_VA_MODEL_GRID) == grid;
    } __except (Decline(GetExceptionCode())) {
        return false;
    }
}

bool BeginScope(uint32_t grid) {
    if (nqc_state[NQC_S_ENABLED] == 0) return false;
    const uint32_t tid = Tid();
    if (Cas(&g_owner, tid, 0) != 0) return false;                                  // busy, reentrant, other thread, or stopping
    if (nqc_state[NQC_S_ENABLED] == 0) { Xchg(&g_owner, 0); return false; }       // stop raced the CAS: it cannot see us
    if (!Bound(grid)) { Xchg(&g_owner, 0); return false; }
    g_cache.grid = grid;
    InvalidateCache();
    Xchg(&nqc_state[NQC_S_OWNER_THREAD], tid);
    Xchg(&nqc_state[NQC_S_BUSY], 1);
    return true;
}

void EndScope() {
    InvalidateCache();
    g_cache.grid = 0;
    Xchg(&nqc_state[NQC_S_BUSY], 0);
    Xchg(&nqc_state[NQC_S_OWNER_THREAD], 0);
    Xchg(&g_owner, 0);
}

// ---- gather preparation -----------------------------------------------------------------------------------------------------------
enum : uint32_t { kWalkOk = 0, kWalkShape = 1, kWalkMalformed = 2, kWalkFault = 3 };
struct WalkOut {
    uint32_t status;
    uint32_t unsupported;
    uint32_t capacitySkipped;
};

// Reads the query frame and the grid READ ONLY.  Every read of game memory is guarded by the caller's SEH (decline only).
void WalkImpl(uint32_t ebp, uint32_t ebx, WalkOut* w) {
    Cache& c = g_cache;
    const Store& s = g_store;
    const uint32_t grid = R32(ebp - kFrameGrid);
    const uint32_t vec = R32(ebp - kFrameVec);
    const uint32_t bitset = R32(ebp - kFrameBitset);
    const uint32_t src = R32(ebp + kFrameSegment);
    const uint32_t mask = R32(ebp + kFrameMask);
    const uint32_t mode = R32(ebp + kFrameMode);
    const uint32_t extra = R32(ebp + kFrameExtra);
    if (grid != c.grid || !src || !bitset) { w->status = kWalkShape; return; }
    // Target query: source segment type 2 against alt segment type 2 (selector 2).  Anything else is native.
    if (R32(src) != 2u || R32(ebx) != 2u) { w->status = kWalkShape; return; }
    if (!(mask & 8u)) return;                                         // no unit entry can pass the type mask

    c.src.type = 2;
    c.alt.type = 2;
    for (uint32_t i = 0; i < 3; ++i) {
        *reinterpret_cast<uint32_t*>(&c.src.p0[i]) = R32(src + 4 + 4 * i);
        *reinterpret_cast<uint32_t*>(&c.src.p1[i]) = R32(src + 0x10 + 4 * i);
        *reinterpret_cast<uint32_t*>(&c.alt.p0[i]) = R32(ebx + 4 + 4 * i);
        *reinterpret_cast<uint32_t*>(&c.alt.p1[i]) = R32(ebx + 0x10 + 4 * i);
    }
    for (uint32_t i = 0; i < 6; ++i) c.ray[i] = R32(ebx + 4 + 4 * i);
    c.rayPtr = ebx + 4;
    c.mode = mode;
    c.extra = extra;
    c.selector = 2;
    float extraF;
    memcpy(&extraF, &extra, 4);

    const uint32_t cells = R32(vec + 8);
    const uint32_t cellData = R32(vec + 0xC);
    if (cells == 0) return;
    if (cells > kMaxCells || !cellData) { w->status = kWalkMalformed; return; }
    const uint32_t gridData = R32(grid + 0);
    const uint32_t shift = R32(grid + 8);
    const uint32_t dim = R32(grid + 0xC);
    if (dim == 0) return;                                              // every cell is rejected by the original
    if (!gridData || shift > kMaxShift || dim > (1u << shift)) { w->status = kWalkMalformed; return; }

    uint32_t steps = 0;
    for (uint32_t ci = 0; ci < cells; ++ci) {
        const uint32_t x = R32(cellData + 8 * ci);
        const uint32_t z = R32(cellData + 8 * ci + 4);
        if (x >= dim || z >= dim) continue;
        uint32_t e = R32(gridData + (((z << shift) + x) << 2));
        for (; e; e = R32(e + 0x14)) {
            if (++steps > kMaxEntries) { w->status = kWalkMalformed; return; }
            const uint32_t kind = R32(e);
            if (!(kind & mask) || kind != 8u) continue;
            const uint32_t obj = R32(e + 0xC);
            if (*reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(obj + 0x30)) == 0) continue;   // 0x6DC9A0
            const uint32_t id = *reinterpret_cast<const volatile uint16_t*>(static_cast<uintptr_t>(e + 4));
            if ((R32(bitset + ((id >> 5) << 2)) >> (id & 31u)) & 1u) continue;                                // visited
            if (!(R32(obj + 0x34) & 8u)) continue;                                                             // selector 2 gate
            if (Lookup(obj)) continue;                                                                         // dedupe by object
            if (c.count >= s.capacity) { ++w->capacitySkipped; continue; }

            Rec r;
            memset(&r, 0, sizeof r);
            r.object = obj;
            r.slot = kNoSlot;
            r.vtable = R32(obj);
            r.leaf = R32(r.vtable + 0x18);
            uint8_t leaf[kLeafBytes];
            memcpy(leaf, reinterpret_cast<const void*>(static_cast<uintptr_t>(r.leaf)), kLeafBytes);   // code bytes only: never executed
            if (ClassifyLeaf(leaf, &r.form, &r.disp, &r.len)) {
                memcpy(r.bytes, leaf, r.len);
                r.value = EvalLeaf(r.form, r.disp, obj);
                for (uint32_t i = 0; i < 5; ++i) r.u5[i] = R32(obj + 0x48 + 4 * i);
                float u5f[5];
                memcpy(u5f, r.u5, sizeof u5f);
                const uint32_t slot = c.batch.count;
                if (nbc_add_unit(&c.batch, obj, 0, mode, u5f, r.value, 0, 2, extraF) == NBC_OK) r.slot = slot;
                else r.form = kFormNone;
            } else {
                r.form = kFormNone;
            }
            if (r.slot == kNoSlot) ++w->unsupported;
            // private writes only from here on (cannot fault)
            uint32_t pos = HashPtr(obj, s.mapBits);
            const uint32_t mmask = (1u << s.mapBits) - 1u;
            while (s.map[pos]) pos = (pos + 1u) & mmask;
            r.mapPos = pos;
            s.recs[c.count] = r;
            s.map[pos] = c.count + 1u;
            ++c.count;
        }
    }
}

void Walk(uint32_t ebp, uint32_t ebx, WalkOut* w) {
    __try {
        WalkImpl(ebp, ebx, w);
    } __except (Decline(GetExceptionCode())) {
        w->status = kWalkFault;
    }
}

void CurrentFp(uint32_t* mxcsr, uint32_t* cw) {
    unsigned short w = 0;
    __asm fnstcw word ptr[w]
    *cw = w;
    *mxcsr = _mm_getcsr();
}

}  // namespace

// Called by the naked thunk AFTER the original 0x10EED80 returned, with every register / flag / x87 / MXCSR / xmm state saved and
// restored around it.  `env` is the fnstenv image of the state right after the original call (already reloaded: the control word
// is the original one).  Never writes game memory.
extern "C" void __cdecl nqc_gather_prep(uint32_t ebp, uint32_t ebx, const uint32_t* env) {
    if (g_owner != Tid()) return;                              // not our scope: the clone only runs inside nqc_query_hook
    InvalidateCache();                                         // a second gather in one scope drops the first cache
    if (nqc_state[NQC_S_ENABLED] == 0 || g_cache.grid == 0) return;
    if ((env[2] & 0xFFFFu) != 0xFFFFu || (ebp & 3u) || (ebx & 3u) || ebp < 0x10000u || ebx < 0x10000u) {   // x87 stack must be empty
        Inc(NQC_S_UNSUPPORTED);
        return;
    }
    Cache& c = g_cache;
    const Store& s = g_store;
    if (nbc_batch_init(&c.batch, s.cands, s.results, s.capacity, &c.src, &c.alt, 0, &g_kernels) != NBC_OK) {
        Inc(NQC_S_UNSUPPORTED);
        return;
    }
    c.batch.min_parallel = g_minParallel;
    const bool team = PoolDispatchable();
    if (team) {
        c.batch.dispatch = g_dispatch;
        c.batch.dispatch_user = g_pool;
        c.batch.body_entry = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&nbc_chunk_body));
    }
    Inc(NQC_S_PREPARATIONS);
    WalkOut w = {};
    Walk(ebp, ebx, &w);
    AddN(NQC_S_UNSUPPORTED, w.unsupported);
    AddN(NQC_S_CAPACITY_SKIPPED, w.capacitySkipped);
    if (w.status != kWalkOk) {
        Inc(NQC_S_UNSUPPORTED);
        InvalidateCache();
        return;
    }
    if (c.batch.count == 0) { InvalidateCache(); return; }

    PoolSnap before = {}, after = {};
    const bool snap = team && SnapPool(&before);
    const uint32_t rc = nbc_run(&c.batch);                    // captures the owner MXCSR / x87 CW, synchronous barrier
    if (rc != NBC_OK) {                                        // NBC_E_FPCW / NBC_E_ARG: nothing was computed for use
        Inc(NQC_S_UNSUPPORTED);
        InvalidateCache();
        return;
    }
    for (uint32_t i = 0; i < c.batch.count; ++i) {
        if (s.results[i].status > NBC_R_HIT) {                 // unit candidates are only ever HIT / MISS
            Inc(NQC_S_UNSUPPORTED);
            InvalidateCache();
            return;
        }
    }
    const uint32_t chunks = c.batch.st_chunks;
    if (!c.batch.st_dispatched) {
        AddN(NQC_S_CALLER_CHUNKS, chunks);                     // inline: every chunk ran on the owner
    } else if (snap && SnapPool(&after)) {
        AddN(NQC_S_TEAM_DISPATCHES, after.team - before.team);
        AddN(NQC_S_WORKER_CHUNKS, after.workerChunks - before.workerChunks);
        AddN(NQC_S_CALLER_CHUNKS, after.mainChunks - before.mainChunks);
        if (after.inlineRuns != before.inlineRuns) AddN(NQC_S_CALLER_CHUNKS, chunks);   // the team was not ours: serial on the owner
    }
    AddN(NQC_S_CANDIDATES, c.batch.count);
    c.mxcsr = c.batch.mxcsr;
    c.cw = c.batch.x87_cw;
    Xchg(&c.valid, 1);
}

// 0x10EED80 replacement (ECX = cell vector, five stack dwords, ret 0x14).  Original first, once; then preparation with the complete
// post-call state saved: EFLAGS, all GPRs (pushad), xmm0..7, MXCSR, x87 environment (fnstenv then fldenv keeps the control word).
extern "C" __declspec(naked) void nqc_gather_hook() {
    __asm {
        push dword ptr [esp + 0x14]        // arg5
        push dword ptr [esp + 0x14]        // arg4
        push dword ptr [esp + 0x14]        // arg3
        push dword ptr [esp + 0x14]        // arg2
        push dword ptr [esp + 0x14]        // arg1
        call dword ptr [g_nqcOrigGather]   // callee pops the copies (ret 0x14); the original arguments stay on our stack
        pushfd
        pushad
        cld
        sub esp, 0xA0
        movups xmmword ptr [esp + 0x20], xmm0
        movups xmmword ptr [esp + 0x30], xmm1
        movups xmmword ptr [esp + 0x40], xmm2
        movups xmmword ptr [esp + 0x50], xmm3
        movups xmmword ptr [esp + 0x60], xmm4
        movups xmmword ptr [esp + 0x70], xmm5
        movups xmmword ptr [esp + 0x80], xmm6
        movups xmmword ptr [esp + 0x90], xmm7
        stmxcsr dword ptr [esp + 0x1C]
        fnstenv [esp]
        fldenv [esp]
        mov eax, esp
        push eax                           // env
        push dword ptr [esp + 0xB4]        // saved EBX (pushad +0x10)
        push dword ptr [esp + 0xB0]        // saved EBP (pushad +0x08)
        call nqc_gather_prep
        add esp, 12
        ldmxcsr dword ptr [esp + 0x1C]
        fldenv [esp]
        movups xmm0, xmmword ptr [esp + 0x20]
        movups xmm1, xmmword ptr [esp + 0x30]
        movups xmm2, xmmword ptr [esp + 0x40]
        movups xmm3, xmmword ptr [esp + 0x50]
        movups xmm4, xmmword ptr [esp + 0x60]
        movups xmm5, xmmword ptr [esp + 0x70]
        movups xmm6, xmmword ptr [esp + 0x80]
        movups xmm7, xmmword ptr [esp + 0x90]
        add esp, 0xA0
        popad
        popfd
        ret 0x14
    }
}

// ---- query hook ------------------------------------------------------------------------------------------------------------------
typedef uint32_t(__fastcall* QueryFn)(void*, void*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                      uint32_t);

extern "C" uint32_t __fastcall nqc_query_hook(void* grid, void* edx, uint32_t out, uint32_t segment, uint32_t stop, uint32_t mask,
                                              uint32_t alt, uint32_t mode, uint32_t visited, uint32_t arg8, uint32_t extra) {
    if (!BeginScope(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(grid)))) {
        Inc(NQC_S_FALLBACKS);
        return reinterpret_cast<QueryFn>(static_cast<uintptr_t>(g_origQuery))(grid, edx, out, segment, stop, mask, alt, mode, visited,
                                                                                 arg8, extra);
    }
    uint32_t r = 0;
    __try {
        r = reinterpret_cast<QueryFn>(static_cast<uintptr_t>(g_clone))(grid, edx, out, segment, stop, mask, alt, mode, visited, arg8,
                                                                         extra);
    } __finally {
        EndScope();   // also while an exception of the original code unwinds: never leaves the scope or the cache open
    }
    return r;
}

// ---- unit hook -------------------------------------------------------------------------------------------------------------------
namespace {

// 1 = unchanged, 0 = changed, -1 = unreadable.  Re-reads everything the cached numeric result was computed from.
int ValidateRec(const Rec* r, uint32_t obj, uint32_t ray) {
    __try {
        for (uint32_t i = 0; i < 6; ++i)
            if (R32(ray + 4 * i) != g_cache.ray[i]) return 0;
        for (uint32_t i = 0; i < 5; ++i)
            if (R32(obj + 0x48 + 4 * i) != r->u5[i]) return 0;
        const uint32_t vt = R32(obj);
        if (vt != r->vtable) return 0;
        const uint32_t leaf = R32(vt + 0x18);
        if (leaf != r->leaf) return 0;
        uint8_t now[kLeafBytes];
        memcpy(now, reinterpret_cast<const void*>(static_cast<uintptr_t>(leaf)), kLeafBytes);
        if (memcmp(now, r->bytes, r->len) != 0) return 0;
        uint32_t form, len;
        int32_t disp;
        if (!ClassifyLeaf(now, &form, &disp, &len) || form != r->form || disp != r->disp || len != r->len) return 0;
        return EvalLeaf(form, disp, obj) == r->value ? 1 : 0;
    } __except (Decline(GetExceptionCode())) {
        return -1;
    }
}

bool TryServe(uint32_t obj, uint32_t ray, uint32_t mode, float* outT, uint32_t selector, uint32_t extra, uint32_t* ret) {
    Cache& c = g_cache;
    if (g_owner != Tid()) { Inc(NQC_S_FALLBACKS); return false; }
    if (!c.valid || nqc_state[NQC_S_ENABLED] == 0) { Inc(NQC_S_FALLBACKS); return false; }
    if (ray != c.rayPtr || mode != c.mode || selector != c.selector || extra != c.extra) {
        Inc(NQC_S_CHANGED);
        Inc(NQC_S_FALLBACKS);
        return false;
    }
    uint32_t mx, cw;
    CurrentFp(&mx, &cw);
    if (((mx ^ c.mxcsr) & 0xFFC0u) || ((cw ^ c.cw) & 0x1F3Fu)) {
        Inc(NQC_S_CHANGED);
        Inc(NQC_S_FALLBACKS);
        return false;
    }
    const Rec* r = Lookup(obj);
    if (!r || r->slot == kNoSlot) { Inc(NQC_S_FALLBACKS); return false; }
    if (ValidateRec(r, obj, ray) != 1) {
        Inc(NQC_S_CHANGED);
        Inc(NQC_S_FALLBACKS);
        return false;
    }
    const nbc_result& res = g_store.results[r->slot];
    uint32_t* t = reinterpret_cast<uint32_t*>(outT);
    if (res.status == NBC_R_HIT) {
        *t = Bits(res.t);
        *ret = 1;
    } else {
        *t = 0;   // the original stores 0 first and the caller reads t only on a hit
        *ret = 0;
    }
    Inc(NQC_S_CACHE_HITS);
    return true;
}

typedef uint32_t(__fastcall* UnitFn)(void*, void*, const float*, uint32_t, float*, uint32_t, uint32_t);

}  // namespace

extern "C" uint32_t __fastcall nqc_unit_hook(void* object, void* edx, const float* ray, uint32_t mode, float* outT, uint32_t selector,
                                             uint32_t extra) {
    uint32_t r;
    if (TryServe(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(object)), static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ray)),
                 mode, outT, selector, extra, &r))
        return r;
    return reinterpret_cast<UnitFn>(static_cast<uintptr_t>(g_origUnit))(object, edx, ray, mode, outT, selector, extra);
}

// ---- initialisation: source pins ------------------------------------------------------------------------------------------------
namespace {

constexpr uint32_t kTableTargets[4] = {0x639668u, 0x639670u, 0x639670u, 0x639668u};

// Class codes of a failing check (detail bits 0..3 for the clone, bits 4..7 for the image): 2 bytes differ, 3 operand wrong,
// 4 jump table, 5 gather seam, 6 unit seam.  Returns 0 or class | hole << 8.
uint32_t CheckBuf(const NqcPinRegion& r, const uint8_t* buf, uint32_t live, uint32_t delta, bool clone, uint32_t* tableAddr) {
    uint64_t h = 0xCBF29CE484222325ULL;
    uint32_t pos = 0;
    for (uint32_t i = 0; i < r.count; ++i) {
        const NqcPinHole& hl = kPinHoles[r.first + i];
        h = Fnv(buf + pos, hl.off - pos, h);
        pos = hl.off + 4;
    }
    h = Fnv(buf + pos, r.size - pos, h);
    if (h != r.hash) return 2;
    for (uint32_t i = 0; i < r.count; ++i) {
        const NqcPinHole& hl = kPinHoles[r.first + i];
        uint32_t v;
        memcpy(&v, buf + hl.off, 4);
        const uint32_t hole = (r.first + i) << 8;
        uint32_t want = hl.expect + delta;
        uint32_t got = v;
        uint32_t cls = 3;
        switch (hl.kind) {
        case kHoleAbs:
            break;
        case kHoleTable:
            if (clone) { *tableAddr = v; continue; }
            break;
        default:
            got = live + hl.off + 4 + v;   // rel32 target
            if (clone && hl.kind == kHoleGather) { want = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&nqc_gather_hook)); cls = 5; }
            if (clone && hl.kind == kHoleUnit) { want = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&nqc_unit_hook)); cls = 6; }
            break;
        }
        if (got != want) return cls | hole;
    }
    return 0;
}

uint32_t CheckImage(uint32_t delta) {
    uint8_t buf[0x940];
    for (uint32_t i = 0; i < 4; ++i) {
        const NqcPinRegion& r = kPinRegions[i];
        if (r.size > sizeof buf) return 0x1u | (0u << 4);
        if (!ReadBytes(r.va + delta, buf, r.size)) return (i + 1u) | (1u << 4);
        const uint32_t d = CheckBuf(r, buf, r.va + delta, delta, false, nullptr);
        if (d) return (i + 1u) | ((d & 0xFu) << 4) | (d & ~0xFFu);
    }
    uint32_t table[4];
    if (!ReadBytes(NQC_VA_TABLE + delta, table, sizeof table)) return 1u | (1u << 4);
    for (uint32_t i = 0; i < 4; ++i)
        if (table[i] != kTableTargets[i] + delta) return 1u | (4u << 4);
    return 0;
}

uint32_t CheckClone(uint32_t clone, uint32_t delta) {
    const NqcPinRegion& r = kPinRegions[0];
    uint8_t buf[0x940];
    if (!ExecOk(clone) || !ExecOk(clone + r.size - 1) || !ReadBytes(clone, buf, r.size)) return 1;
    uint32_t table = 0;
    const uint32_t d = CheckBuf(r, buf, clone, delta, true, &table);
    if (d) return d;
    uint32_t entries[4];
    if (!table || !ReadBytes(table, entries, sizeof entries)) return 4;
    for (uint32_t i = 0; i < 4; ++i)
        if (entries[i] != clone + (kTableTargets[i] - NQC_VA_QUERY)) return 4;
    return 0;
}

uint32_t CheckKernel(uint32_t index, uint32_t addr) {
    const NqcKernelPin& k = kPinKernels[index];
    uint8_t buf[24];
    if (!addr || !ExecOk(addr)) return 1;
    if (!ReadBytes(addr, buf, k.len) || memcmp(buf, k.bytes, k.len) != 0) return 2;
    return 0;
}

uint32_t CheckPool(const nqc_config& c) {
    if (c.pool & (NTW_POOL_ALIGN - 1u)) return 3;
    ntw_u32 hdr[3];
    if (!ReadBytes(c.pool, hdr, sizeof hdr)) return 1;
    if (hdr[1] != NTW_POOL_ABI) return 2;
    if (hdr[0] != NTW_POOL_S_READY) return 4;
    if (hdr[2] > NTW_POOL_MAX_WORKERS) return 5;
    if (!ExecOk(c.dispatch)) return 6;
    return 0;
}

}  // namespace

// ---- lifecycle -------------------------------------------------------------------------------------------------------------------
extern "C" uint32_t __stdcall nqc_initialize(void* config) {
    nqc_config c;
    if (!config || !ReadBytes(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(config)), &c, sizeof c)) return Err(NQC_E_ARG, 0);
    const uint32_t* w = reinterpret_cast<const uint32_t*>(&c);
    uint32_t bad = 0;
    if (c.abi != NQC_ABI) bad = 1;
    else if (c.size != NQC_CONFIG_BYTES) bad = 2;
    else if (c.imageDelta & 0xFFFFu) bad = 3;
    else if (!c.root) bad = 4;
    else if (!c.model) bad = 5;
    else if (c.capacity == 0 || c.capacity > NQC_MAX_CAPACITY) bad = 6;
    else if (c.minParallel == 0 || c.minParallel > NQC_MAX_MIN_PARALLEL) bad = 7;
    else {
        for (uint32_t i = 7; i < NQC_CONFIG_WORDS; ++i)
            if (!w[i]) { bad = i + 1; break; }
    }
    if (bad) return Err(NQC_E_ARG, bad);

    uint32_t from = kLifeNone;
    if (Cas(&g_life, kLifeInitializing, kLifeNone) != kLifeNone) {
        if (Cas(&g_life, kLifeInitializing, kLifeStopped) != kLifeStopped) return Err(NQC_E_STATE, 0);
        from = kLifeStopped;
    }
    if (from == kLifeStopped) {
        if (c.imageDelta != g_delta) { Xchg(&g_life, from); return Err(NQC_E_ARG, 0xFF); }
        if (nqc_state[NQC_S_ENABLED] != 0 || nqc_state[NQC_S_BUSY] != 0 || nqc_state[NQC_S_OWNER_THREAD] != 0 || g_owner != kStopToken) {
            Xchg(&g_life, from);
            return Err(NQC_E_STATE, 1);
        }
    }

    // Verification: nothing is published or allocated before every check passed.
    uint32_t d = CheckPool(c);
    if (d) { Xchg(&g_life, from); return Err(NQC_E_POOL, d); }
    d = CheckImage(c.imageDelta);
    if (d) { Xchg(&g_life, from); return Err(NQC_E_IMAGE, d); }
    d = CheckClone(c.queryClone, c.imageDelta);
    if (d) { Xchg(&g_life, from); return Err(NQC_E_CLONE, d); }
    const uint32_t* kern = &c.kPlane;
    for (uint32_t i = 0; i < 6; ++i) {
        d = CheckKernel(i, kern[i]);
        if (d) { Xchg(&g_life, from); return Err(NQC_E_KERNEL, (i + 1u) | (d << 4)); }
    }

    // Private storage: ONE block, zero filled at every session start (InvalidateCache relies on an all-zero map).  A restart whose
    // layout fits the held block reuses it in place (re-zeroed); a larger one allocates a replacement and frees the held block only
    // after the new session is fully built.  Nothing can still use the held block: g_owner holds the stop token (no scope, so no
    // gather / unit hook dereferences g_store and no dispatch is in flight; the shared pool's dispatch is synchronous), and no
    // pointer into the block is ever written to game memory.  A failed start frees only a block allocated here.
    uint32_t bits = 4;
    while ((1u << bits) < c.capacity * 2u) ++bits;
    auto up = [](size_t n) { return (n + 63u) & ~static_cast<size_t>(63u); };
    const size_t offRes = up(static_cast<size_t>(c.capacity) * sizeof(nbc_cand));
    const size_t offRec = offRes + up(static_cast<size_t>(c.capacity) * sizeof(nbc_result));
    const size_t offMap = offRec + up(static_cast<size_t>(c.capacity) * sizeof(Rec));
    const size_t bytes = offMap + up(sizeof(uint32_t) << bits);
    uint8_t* block = reinterpret_cast<uint8_t*>(g_store.cands);
    size_t held = g_store.bytes;
    const bool reuse = block != nullptr && held >= bytes;
    if (reuse) {
        memset(block, 0, bytes);
    } else {
        block = static_cast<uint8_t*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));   // zero filled
        held = bytes;
    }
    if (!block) {
        const uint32_t le = GetLastError();
        Xchg(&g_life, from);
        return Err(NQC_E_MEMORY, le);
    }
    if (!g_pinned) {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                reinterpret_cast<LPCWSTR>(&nqc_initialize), &self)) {
            const uint32_t le = GetLastError();
            if (!reuse) VirtualFree(block, 0, MEM_RELEASE);
            Xchg(&g_life, from);
            return Err(NQC_E_PIN, le);
        }
        g_pinned = true;
    }

    // Publish while exclusive and disabled (first session: nobody can own yet; later session: the stop token is still held).
    Store st;
    st.cands = reinterpret_cast<nbc_cand*>(block);
    st.results = reinterpret_cast<nbc_result*>(block + offRes);
    st.recs = reinterpret_cast<Rec*>(block + offRec);
    st.map = reinterpret_cast<uint32_t*>(block + offMap);
    st.mapBits = bits;
    st.capacity = c.capacity;
    st.bytes = static_cast<uint32_t>(held);
    memset(&g_cache, 0, sizeof g_cache);
    uint8_t* const oldBlock = reinterpret_cast<uint8_t*>(g_store.cands);
    g_store = st;
    if (!reuse && oldBlock) VirtualFree(oldBlock, 0, MEM_RELEASE);
    g_root = c.root;
    g_model = c.model;
    g_clone = c.queryClone;
    g_minParallel = c.minParallel;
    g_dispatch = c.dispatch;
    g_pool = c.pool;
    g_kernels.plane = c.kPlane;
    g_kernels.ring = c.kRing;
    g_kernels.box = c.kBox;
    g_kernels.wall = c.kWall;
    g_kernels.unit_hit = c.kUnitHit;
    g_kernels.unit_inside = c.kUnitInside;
    if (from == kLifeNone) {   // never rewritten later: fetched hooks call these addresses without any lock
        g_delta = c.imageDelta;
        g_origQuery = c.imageDelta + NQC_VA_QUERY;
        g_origUnit = c.imageDelta + NQC_VA_UNIT_HIT;
        g_nqcOrigGather = c.imageDelta + NQC_VA_GATHER;
    }
    for (uint32_t i = NQC_S_BUSY; i < NQC_STATE_WORDS; ++i) nqc_state[i] = 0;
    nqc_state[NQC_S_STORAGE_BYTES] = st.bytes;
    Xchg(&g_life, kLifeReady);
    Xchg(&nqc_state[NQC_S_ENABLED], 1);
    Xchg(&g_owner, 0);   // last: from here a query may claim the scope
    return NQC_OK;
}

extern "C" uint32_t __stdcall nqc_stop(void*) {
    for (;;) {
        const uint32_t life = g_life;
        if (life == kLifeNone) return Err(NQC_E_STATE, 0);
        if (life == kLifeStopped) return NQC_OK;
        if (life != kLifeReady) return Err(NQC_E_BUSY, 1);   // initialize or another stop is running
        if (Cas(&g_life, kLifeStopping, kLifeReady) == kLifeReady) break;
    }
    // 1. no new scope can start (a hook that already passed its first check re-checks after its CAS)
    Xchg(&nqc_state[NQC_S_ENABLED], 0);
    // 2. an active scope: report busy, change nothing else (it ends normally; call again later)
    if (Cas(&g_owner, kStopToken, 0) != 0) { Xchg(&g_life, kLifeReady); return Err(NQC_E_BUSY, 0); }
    // 3. exclusive: the shared pool is untouched; hooks fetched earlier see enabled == 0 / the stop token and run native code
    Xchg(&g_life, kLifeStopped);
    return NQC_OK;
}
