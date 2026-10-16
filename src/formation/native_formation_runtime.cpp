// native_formation_runtime.dll: in-process owner of the formation batching experiment (see native_formation_runtime.h for the
// ABI).  It wires the already differential-tested pieces together and adds NO numerics:
//   native_formation_batch.cpp   Prepare / Execute / Consume adapter (generator + assignment ports, snapshots, validation)
//   native_worker_dispatch.c     persistent worker team (import free; its Win32 entries are filled from the real kernel32)
//
// Per army-manager tick (nfr_manager_hook replaces the call 0x580640 inside the tick clone):
//   1. gate: enabled, exclusive owner thread (CAS), enabled re-checked after the CAS, configured model/root bound to the
//      manager ([model] == root, [model+0xB0] == manager).  Any failure runs the ORIGINAL 0x580640 untouched.
//   2. enumerate manager+0x84/0x88 armies -> army+0x20/0x24 containers -> container+0xF0/0xF4 units (vtable 0x1321298) ->
//      unit+0xACC/0xAD0 formation list; keep formations with vtable 0x13211D8 whose +0x510 backlink is the unit and whose
//      LAST queued command (formation+0x420 + 8 * (count-1), count at +0x460, at most 8) has one of the six command vtables
//      and [cmd+4] == formation.  Counts / pointers outside fixed bounds reject that candidate (never the native work); the
//      reads run under SEH (a fault keeps the candidates collected so far and is counted in `rejected`).
//   3. Batch.Begin, Batch.Prepare for every candidate (pure snapshot, own SEH), ONE Batch.Execute: the persistent team when at
//      least minJobs jobs were prepared, otherwise the caller alone.  No locks, no per-unit waits.
//   4. the ORIGINAL 0x580640 runs exactly once (try/finally: an exception from native code is never swallowed, the epoch is
//      closed and the owner released while it unwinds).  Inside it the assignment call site 0x555CEB (nfr_assign_hook) asks
//      Batch.Consume, which re-reads everything the original would read and commits the entry vector only when all of it
//      still matches; otherwise the original 0x18F0A00 runs.  Only the owner thread of an active epoch may Consume.
//   5. Batch.End, counters published into nfr_state, owner released.
//
// Lifecycle (serialized by one life word: initialize and stop never overlap): nfr_stop disables new epochs FIRST, then takes the
// owner slot with a CAS (fails with NFR_E_BUSY while an epoch is active), snapshots the counters (before the dispatcher clears
// them), shuts the pool down only while no epoch exists and keeps the owner slot (stop token) so nothing can use the pool.
// A NEW session (nfr_initialize after the stopped phase, same imageDelta, optional new root/model/sizes) is accepted only while
// that stopped, disabled, ownerless state holds; it builds new batch storage + a new team and replaces the batch state under
// the still-held token, releasing the token last.  The DLL is pinned and the pool storage is static.  The batch storage is ONE
// block owned by this module (g_storage): a restart whose storage fits reuses it in place, a larger one allocates a replacement
// and frees the old block only after the new session is fully built (a failed start frees only the block it allocated and leaves
// the published one untouched).  That is safe because no pointer into the block ever leaves the batch: workers touch it only
// inside a synchronous dispatch of an epoch (owner held; the dispatcher returns after every chunk, and stop shuts the team down
// before Stopped), Commit copies arena data into game-allocated vectors, and every hook entry that could reach g_batch needs
// g_owner == its own thread id, which cannot hold while the stop token is set.  The original addresses the hooks call never
// change, so a hook fetched by an earlier session reads the current enabled / owner / bound model and falls through natively.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

#include "native_formation_batch.h"
#include "native_formation_runtime.h"
#include "native_worker_dispatch.h"

extern "C" {
ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool);
void __stdcall ntw_pool_dispatch(ntw_u32 user, ntw_u32 body, ntw_u32 chunks, void* ctx);
ntw_u32 __stdcall ntw_pool_worker_start(void* param);
}

namespace nb = ntw_formation_batch;

static_assert(sizeof(void*) == 4, "x86 build required");

// ---- exports ----------------------------------------------------------------------------------------------------------------
#pragma comment(linker, "/EXPORT:nfr_initialize=_nfr_initialize@4")
#pragma comment(linker, "/EXPORT:nfr_stop=_nfr_stop@4")
#pragma comment(linker, "/EXPORT:nfr_manager_hook=@nfr_manager_hook@4")
#pragma comment(linker, "/EXPORT:nfr_assign_hook=_nfr_assign_hook")
#pragma comment(linker, "/EXPORT:nfr_diag=_nfr_diag,DATA")

extern "C" __declspec(dllexport) volatile uint32_t nfr_state[NFR_STATE_WORDS] = {NFR_ABI, NFR_STATE_BYTES};
static_assert(sizeof(nfr_state) == NFR_STATE_BYTES, "nfr_state is sixteen u32 words");
extern "C" volatile uint32_t nfr_diag[NFR_DIAG_WORDS] = {NFR_ABI, NFR_DIAG_BYTES};
static_assert(sizeof(nfr_diag) == NFR_DIAG_BYTES && NFR_D_CAPTURE_B + NFR_CAPTURE_WORDS <= NFR_DIAG_WORDS &&
              NFR_D_CAPTURE_A + NFR_CAPTURE_WORDS <= NFR_D_CAPTURE_B, "nfr_diag layout");

extern "C" {
// tail-jump target of nfr_assign_hook (referenced from the naked thunk)
volatile uint32_t g_nfrOrigAssign = 0;
uint32_t __cdecl nfr_assign_try(uint32_t formation, uint32_t slotVec, uint32_t flag, uint32_t assignVec, int32_t layoutIndex);
uint32_t __stdcall nfr_initialize(void* config);
uint32_t __stdcall nfr_stop(void* unused);
uint32_t __fastcall nfr_manager_hook(void* manager);
}

namespace {

constexpr uint32_t kLifeNone = 0, kLifeInitializing = 1, kLifeReady = 2, kLifeStopped = 3, kLifeStopping = 4;
constexpr uint32_t kMaxArmies = 64;
constexpr uint32_t kMaxContainersPerArmy = 1024;
constexpr uint32_t kMaxUnitsPerContainer = 8192;
constexpr uint32_t kMaxUnitsVisited = 65536;
constexpr uint32_t kMaxFormationsPerUnit = 64;
constexpr uint32_t kQueueSlots = 8;                   // formation+0x420 .. +0x460 (count at +0x460)
constexpr uint32_t kWorkerStackBytes = 0x100000;

constexpr uint32_t kUnitVtable = 0x1321298;
constexpr uint32_t kCommandVtables[6] = {0x13239B0, 0x13239F0, 0x1323A30, 0x1323A70, 0x1323AB0, 0x1323AF0};

inline volatile long* VL(volatile uint32_t* p) { return reinterpret_cast<volatile long*>(p); }
inline uint32_t Xchg(volatile uint32_t* p, uint32_t v) { return static_cast<uint32_t>(_InterlockedExchange(VL(p), static_cast<long>(v))); }
inline uint32_t Cas(volatile uint32_t* p, uint32_t desired, uint32_t expected) {
    return static_cast<uint32_t>(_InterlockedCompareExchange(VL(p), static_cast<long>(desired), static_cast<long>(expected)));
}
inline uint32_t Inc(volatile uint32_t* p) { return static_cast<uint32_t>(_InterlockedIncrement(VL(p))); }
inline void Store(uint32_t word, uint32_t v) { nfr_state[word] = v; }

// ---- runtime globals (all static: published addresses stay valid for the life of the process) ----------------------------------
volatile uint32_t g_life = kLifeNone;
volatile uint32_t g_owner = 0;          // 0 idle, thread id during an epoch, NFR_STOP_OWNER_TOKEN once stopping/stopped
volatile uint32_t g_origManager = 0;
volatile uint32_t g_extFallbacks = 0;   // assign-hook entries from non-owner contexts (any thread)
volatile uint32_t g_pubBatchFallbacks = 0;
bool g_poolLive = false;
bool g_pinned = false;

uint32_t g_delta = 0, g_root = 0, g_model = 0, g_minJobs = 1, g_maxUnits = 1;
uint32_t g_serialChunks = 0, g_inlineChunks = 0;
nb::Batch g_batch;
uint32_t g_cmds[NFR_MAX_UNITS];
__declspec(align(64)) uint8_t g_poolMem[NTW_POOL_BYTES];
void* g_storage = nullptr;              // the one batch storage block (VirtualAlloc'd, 64-byte aligned); freed only when replaced
size_t g_storageBytes = 0;              // its allocated size
ntw_pool* Pool() { return reinterpret_cast<ntw_pool*>(g_poolMem); }

inline uint32_t V(uint32_t preferred) { return preferred + g_delta; }
inline uint32_t R32(uint32_t a) { return *reinterpret_cast<const volatile uint32_t*>(static_cast<uintptr_t>(a)); }

// ---- statistics ----------------------------------------------------------------------------------------------------------------
// Owner (or the stop-token holder) only.  Counters are cumulative, so plain stores of the current totals are correct.
void PublishStats() {
    const nb::Stats& s = g_batch.GetStats();
    Store(NFR_S_EPOCHS, s.epochs);
    Store(NFR_S_PREPARED, s.prepared);
    Store(NFR_S_EXECUTED, s.executed);
    Store(NFR_S_COMMITTED, s.committed);
    g_pubBatchFallbacks = s.fallbacks;
    Store(NFR_S_FALLBACKS, s.fallbacks + g_extFallbacks);
    Store(NFR_S_UNUSED, s.unusedJobs);
    if (g_poolLive) {   // the pool is only read while it exists (shutdown re-zeroes it); nfr_stop publishes before shutting it down
        const ntw_pool* p = Pool();
        uint32_t worker = 0;
        for (uint32_t i = 0; i < p->workers && i < NTW_POOL_MAX_WORKERS; ++i) worker += p->slots[i].chunks;
        Store(NFR_S_TEAM_DISPATCHES, p->st_team);
        Store(NFR_S_WORKER_CHUNKS, worker);
        Store(NFR_S_CALLER_CHUNKS, p->st_main_chunks + g_serialChunks + g_inlineChunks);
    }
}

void Reject() { Inc(&nfr_state[NFR_S_REJECTED]); }

// ---- registry enumeration ---------------------------------------------------------------------------------------------------
// Plain data only (SEH function).  `*n` is advanced as candidates are collected so a fault keeps what was already validated.
struct GatherOut {
    volatile uint32_t n;
    volatile uint32_t rejectedLists;
    volatile uint32_t faulted;
};

// ---- raw captures (diagnostics only; every read has its own SEH guard, results never feed the gather) --------------------------
// Reads `n` consecutive dwords; stops at the first fault (the rest of `dst` stays as the caller zeroed it).  Plain data only.
bool ReadDwordsGuarded(uint32_t address, uint32_t* dst, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        __try {
            dst[i] = R32(address + 4 * i);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
    return true;
}

// Gather owner only.  Fills the capture block at nfr_diag[base ..] once; status word last.
void CaptureRaw(uint32_t base, uint32_t form, uint32_t queued, uint32_t cmd) {
    uint32_t w[NFR_CAPTURE_WORDS] = {};
    uint32_t faults = 0;
    w[NFR_C_EPOCH] = nfr_diag[NFR_D_EPOCH];
    w[NFR_C_FORMATION] = form;
    w[NFR_C_QUEUE_COUNT] = queued;
    w[NFR_C_ENTRY_POINTER] = cmd;
    w[NFR_C_QUEUE_INDEX] = queued - 1;
    if (!ReadDwordsGuarded(form + 0x420 + 8 * (queued - 1) + 4, &w[NFR_C_ENTRY_SECOND], 1)) faults |= 2u;
    if (!ReadDwordsGuarded(form + 0x400, &w[NFR_C_FORMATION_DUMP], 32)) faults |= 1u;
    if (!ReadDwordsGuarded(cmd, &w[NFR_C_COMMAND_DUMP], 16)) faults |= 4u;
    if (!ReadDwordsGuarded(w[NFR_C_COMMAND_DUMP], &w[NFR_C_VTABLE_DUMP], 16)) faults |= 8u;
    w[NFR_C_FAULTS] = faults;
    for (uint32_t i = 1; i < NFR_CAPTURE_WORDS; ++i) nfr_diag[base + i] = w[i];
    nfr_diag[base + NFR_C_STATUS] = 1;
}

void GatherImpl(uint32_t manager, uint32_t cap, uint32_t* out, GatherOut* g) {
    const uint32_t formationVtable = V(nb::va::kFormationVtable);
    const uint32_t unitVtable = V(kUnitVtable);
    uint32_t vts[6];
    for (int i = 0; i < 6; ++i) vts[i] = V(kCommandVtables[i]);
    uint32_t visited = 0;

    const uint32_t armyCount = R32(manager + 0x84);
    const uint32_t armyData = R32(manager + 0x88);
    if (armyCount == 0) return;
    if (armyCount > kMaxArmies || !armyData) { ++g->rejectedLists; return; }
    for (uint32_t a = 0; a < armyCount; ++a) {
        const uint32_t army = R32(armyData + 4 * a);
        if (!army) continue;
        ++nfr_diag[NFR_D_ARMIES_SEEN];
        const uint32_t contCount = R32(army + 0x20);
        const uint32_t contData = R32(army + 0x24);
        if (contCount == 0) continue;
        if (contCount > kMaxContainersPerArmy || !contData) { ++g->rejectedLists; continue; }
        for (uint32_t c = 0; c < contCount; ++c) {
            const uint32_t container = R32(contData + 4 * c);
            if (!container) continue;
            ++nfr_diag[NFR_D_CONTAINERS_SEEN];
            const uint32_t unitCount = R32(container + 0xF0);
            const uint32_t unitData = R32(container + 0xF4);
            if (unitCount == 0) continue;
            if (unitCount > kMaxUnitsPerContainer || !unitData) { ++g->rejectedLists; continue; }
            for (uint32_t u = 0; u < unitCount; ++u) {
                if (++visited > kMaxUnitsVisited) { ++g->rejectedLists; return; }
                const uint32_t unit = R32(unitData + 4 * u);
                if (!unit) continue;
                ++nfr_diag[NFR_D_UNITS_SEEN];
                const uint32_t unitVt = R32(unit);
                if (nfr_diag[NFR_D_UNITS_SEEN] == 1) nfr_diag[NFR_D_FIRST_UNIT_VTABLE] = unitVt - g_delta;
                if (unitVt != unitVtable) {
                    if (++nfr_diag[NFR_D_UNITS_WRONG_VTABLE] == 1)
                        nfr_diag[NFR_D_FIRST_WRONG_UNIT_VTABLE] = unitVt - g_delta;
                    continue;
                }
                const uint32_t formCount = R32(unit + 0xACC);
                const uint32_t formData = R32(unit + 0xAD0);
                if (formCount == 0) continue;
                if (formCount > kMaxFormationsPerUnit || !formData) { ++g->rejectedLists; continue; }
                for (uint32_t f = 0; f < formCount; ++f) {
                    const uint32_t form = R32(formData + 4 * f);
                    if (!form) continue;
                    ++nfr_diag[NFR_D_FORMATIONS_SEEN];
                    const uint32_t formVt = R32(form);
                    if (formVt != formationVtable) {
                        if (++nfr_diag[NFR_D_FORMATIONS_WRONG_VTABLE] == 1)
                            nfr_diag[NFR_D_FIRST_WRONG_FORMATION_VTABLE] = formVt - g_delta;
                        continue;
                    }
                    if (R32(form + 0x510) != unit) {
                        ++nfr_diag[NFR_D_FORMATIONS_BAD_BACKLINK];
                        continue;
                    }
                    const uint32_t queued = R32(form + 0x460);
                    if (queued == 0) { ++nfr_diag[NFR_D_FORMATIONS_QUEUE_EMPTY]; continue; }
                    if (queued > kQueueSlots) {
                        ++nfr_diag[NFR_D_FORMATIONS_QUEUE_OVERSIZE];
                        ++g->rejectedLists;
                        continue;
                    }
                    const uint32_t cmd = R32(form + 0x420 + 8 * (queued - 1));   // only the LAST queued command runs 581200 (vt+4)
                    if (!cmd) continue;
                    ++nfr_diag[NFR_D_COMMANDS_SEEN];
                    const uint32_t vt = R32(cmd);
                    bool supported = false;
                    for (int i = 0; i < 6; ++i) supported = supported || vt == vts[i];
                    if (!supported) {
                        ++nfr_diag[NFR_D_COMMANDS_WRONG_VTABLE];
                        // Compare raw pointers with relocated identities, exactly as for the handled command vtables above.
                        if (vt == V(NFR_CAPTURE_VTABLE_A)) {
                            if (nfr_diag[NFR_D_CAPTURE_A + NFR_C_STATUS] == 0) CaptureRaw(NFR_D_CAPTURE_A, form, queued, cmd);
                        } else if (nfr_diag[NFR_D_CAPTURE_B + NFR_C_STATUS] == 0 &&
                                   (vt == V(NFR_CAPTURE_VTABLE_B0) || vt == V(NFR_CAPTURE_VTABLE_B1))) {
                            CaptureRaw(NFR_D_CAPTURE_B, form, queued, cmd);
                        }
                        const uint32_t sampleCount = nfr_diag[NFR_D_COMMAND_VTABLE_COUNT];
                        if (sampleCount < 6) {
                            const uint32_t preferredVt = vt - g_delta;
                            uint32_t sample = 0;
                            while (sample < sampleCount && nfr_diag[NFR_D_COMMAND_VTABLE_0 + sample] != preferredVt) ++sample;
                            if (sample == sampleCount) {
                                nfr_diag[NFR_D_COMMAND_VTABLE_0 + sampleCount] = preferredVt;
                                nfr_diag[NFR_D_COMMAND_VTABLE_COUNT] = sampleCount + 1;
                            }
                        }
                        continue;
                    }
                    if (R32(cmd + 4) != form) continue;
                    if (g->n >= cap) { ++g->rejectedLists; return; }
                    out[g->n] = cmd;
                    g->n = g->n + 1;
                }
            }
        }
    }
}

void Gather(uint32_t manager, uint32_t cap, GatherOut* g) {
    nfr_diag[NFR_D_PHASE] = 1;
    nfr_diag[NFR_D_EPOCH] = g_batch.GetStats().epochs;
    for (uint32_t i = NFR_D_ARMIES_SEEN; i < NFR_D_RESERVED_0; ++i) nfr_diag[i] = 0;
    g->n = 0; g->rejectedLists = 0; g->faulted = 0;
    __try {
        GatherImpl(manager, cap, g_cmds, g);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g->faulted = 1;
    }
    nfr_diag[NFR_D_REJECTED_LISTS] = g->rejectedLists;
    nfr_diag[NFR_D_FAULTED] = g->faulted;
    nfr_diag[NFR_D_CANDIDATES] = g->n;
    nfr_diag[NFR_D_PHASE] = 2;
}

bool Bound(uint32_t manager) {
    bool ok = false;
    __try {
        ok = manager != 0 && R32(g_model) == g_root && R32(g_model + NFR_VA_MODEL_MANAGER_OFFSET) == manager;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

void __stdcall SerialDispatch(uint32_t, uint32_t body, uint32_t chunks, void* ctx) {
    const auto fn = reinterpret_cast<void(__fastcall*)(void*, uint32_t)>(static_cast<uintptr_t>(body));
    for (uint32_t i = 0; i < chunks; ++i) fn(ctx, i);
    g_serialChunks += chunks;
}

void ReleaseOwner() {
    Store(NFR_S_OWNER_THREAD, 0);
    Xchg(&g_owner, 0);
}

// Gate + Begin + Prepare + Execute.  Returns true when the epoch stays open (owner held) until EndEpoch().
bool BeginEpoch(uint32_t manager) {
    if (nfr_state[NFR_S_ENABLED] == 0) { Reject(); return false; }
    const uint32_t tid = GetCurrentThreadId();
    if (Cas(&g_owner, tid, 0) != 0) { Reject(); return false; }        // reentrant, another thread, or stopping
    if (nfr_state[NFR_S_ENABLED] == 0) { Xchg(&g_owner, 0); Reject(); return false; }   // stop raced the CAS: it will not see us
    if (!Bound(manager)) { Xchg(&g_owner, 0); Reject(); return false; }
    Store(NFR_S_OWNER_THREAD, tid);

    g_batch.Begin();
    GatherOut g;
    Gather(manager, g_maxUnits, &g);
    for (uint32_t i = 0; i < g.rejectedLists + g.faulted; ++i) Reject();
    for (uint32_t i = 0; i < g.n; ++i) g_batch.Prepare(g_cmds[i], nullptr);

    const uint32_t jobs = g_batch.JobCount();
    if (jobs == 0) {
        g_batch.End();
        PublishStats();
        ReleaseOwner();
        return false;
    }
    nb::Dispatcher d;
    const bool team = jobs >= g_minJobs;
    if (team) { d.dispatch = &ntw_pool_dispatch; d.user = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Pool())); }
    else { d.dispatch = &SerialDispatch; d.user = 0; }
    const uint32_t inlineBefore = Pool()->st_inline;
    uint32_t run = 0;
    g_batch.Execute(d, &run);                  // failure leaves the jobs kPrepared: Consume refuses them, the original runs
    if (team && Pool()->st_inline != inlineBefore) g_inlineChunks += run;   // the team was not ours: chunks ran serially here
    return true;
}

void EndEpoch() {
    g_batch.End();
    PublishStats();
    ReleaseOwner();
}

}  // namespace

// ---- hooks -----------------------------------------------------------------------------------------------------------------------
extern "C" uint32_t __fastcall nfr_manager_hook(void* manager) {
    const bool owned = BeginEpoch(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(manager)));
    uint32_t r = 0;
    __try {
        r = reinterpret_cast<uint32_t(__thiscall*)(void*)>(static_cast<uintptr_t>(g_origManager))(manager);
    } __finally {
        if (owned) EndEpoch();   // also while an exception unwinds: never leaves the owner slot or the epoch open
    }
    return r;
}

// Called by the naked thunk with every register and xmm0..7 saved.  Non-zero: the entry vector was committed.
extern "C" uint32_t __cdecl nfr_assign_try(uint32_t formation, uint32_t slotVec, uint32_t flag, uint32_t assignVec, int32_t layoutIndex) {
    if (g_owner != GetCurrentThreadId()) {
        Inc(&g_extFallbacks);
        Store(NFR_S_FALLBACKS, g_pubBatchFallbacks + g_extFallbacks);
        return 0;
    }
    nb::AssignCall call;
    call.formation = formation;
    call.slotVec = slotVec;
    call.flag = flag;
    call.assignVec = assignVec;
    call.layoutIndex = layoutIndex;
    return g_batch.Consume(call).outcome == nb::Outcome::kCommitted ? 1u : 0u;
}

// 0x18F0A00 replacement: ECX = formation, [esp+4]=slotVec, [esp+8]=flag, [esp+0xC]=assignVec, [esp+0x10]=layoutIndex, ret 0x10.
// Commit path: every GP register, EFLAGS and xmm0..7 are exactly as at entry (EAX/ECX/EDX included), 16 argument bytes popped.
// Fallback path: registers and stack are restored to the entry state and control jumps to the ORIGINAL 0x18F0A00.
extern "C" __declspec(naked) void __cdecl nfr_assign_hook() {
    __asm {
        pushfd
        pushad
        sub esp, 0x80
        movups xmmword ptr [esp], xmm0
        movups xmmword ptr [esp + 0x10], xmm1
        movups xmmword ptr [esp + 0x20], xmm2
        movups xmmword ptr [esp + 0x30], xmm3
        movups xmmword ptr [esp + 0x40], xmm4
        movups xmmword ptr [esp + 0x50], xmm5
        movups xmmword ptr [esp + 0x60], xmm6
        movups xmmword ptr [esp + 0x70], xmm7
        push dword ptr [esp + 0xB4]      // layoutIndex
        push dword ptr [esp + 0xB4]      // assignVec
        push dword ptr [esp + 0xB4]      // flag
        push dword ptr [esp + 0xB4]      // slotVec
        push ecx                         // formation
        call nfr_assign_try
        add esp, 0x14
        test eax, eax
        jz fallback
        movups xmm0, xmmword ptr [esp]
        movups xmm1, xmmword ptr [esp + 0x10]
        movups xmm2, xmmword ptr [esp + 0x20]
        movups xmm3, xmmword ptr [esp + 0x30]
        movups xmm4, xmmword ptr [esp + 0x40]
        movups xmm5, xmmword ptr [esp + 0x50]
        movups xmm6, xmmword ptr [esp + 0x60]
        movups xmm7, xmmword ptr [esp + 0x70]
        add esp, 0x80
        popad
        popfd
        ret 0x10
    fallback:
        movups xmm0, xmmword ptr [esp]
        movups xmm1, xmmword ptr [esp + 0x10]
        movups xmm2, xmmword ptr [esp + 0x20]
        movups xmm3, xmmword ptr [esp + 0x30]
        movups xmm4, xmmword ptr [esp + 0x40]
        movups xmm5, xmmword ptr [esp + 0x50]
        movups xmm6, xmmword ptr [esp + 0x60]
        movups xmm7, xmmword ptr [esp + 0x70]
        add esp, 0x80
        popad
        popfd
        jmp dword ptr [g_nfrOrigAssign]
    }
}

// ---- lifecycle -------------------------------------------------------------------------------------------------------------------
namespace {

bool ReadConfig(const void* p, nfr_config* out) {
    if (!p) return false;
    bool ok = true;
    __try {
        memcpy(out, p, sizeof *out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

uint32_t Err(uint32_t cls, uint32_t detail) { return cls | (detail << 8); }

}  // namespace

extern "C" uint32_t __stdcall nfr_initialize(void* config) {
    nfr_config c;
    if (!ReadConfig(config, &c)) return Err(NFR_E_ARG, 0);
    if (c.abi != NFR_ABI || c.size != NFR_CONFIG_BYTES || c.root == 0 || c.model == 0 || c.workers > NFR_MAX_WORKERS ||
        c.maxUnits == 0 || c.maxUnits > NFR_MAX_UNITS || c.maxMen == 0 || c.maxMen > NFR_MAX_MEN ||
        c.arenaBytes < NFR_MIN_ARENA_BYTES || c.arenaBytes > NFR_MAX_ARENA_BYTES || c.minJobs == 0)
        return Err(NFR_E_ARG, 0);

    // Lifecycle is serialized by g_life: initialize / stop never overlap.  A first session starts from None; a NEW session may
    // start only from Stopped (pool joined, enabled 0, no owner thread, stop token held) and replaces the batch / pool state
    // under that exclusive, disabled lifecycle.  Hooks fetched earlier keep working natively: they read enabled / owner and the
    // bound model under the owner CAS, and the original addresses they call never change (imageDelta must match).
    uint32_t from = kLifeNone;
    if (Cas(&g_life, kLifeInitializing, kLifeNone) != kLifeNone) {
        if (Cas(&g_life, kLifeInitializing, kLifeStopped) != kLifeStopped) return Err(NFR_E_STATE, 0);
        from = kLifeStopped;
    }
    if (from == kLifeStopped) {
        if (c.imageDelta != g_delta) { Xchg(&g_life, from); return Err(NFR_E_ARG, 1); }   // detail 1: differs from the published session
        if (nfr_state[NFR_S_PHASE] != NFR_PHASE_STOPPED || nfr_state[NFR_S_ENABLED] != 0 || nfr_state[NFR_S_OWNER_THREAD] != 0 ||
            g_owner != NFR_STOP_OWNER_TOKEN || g_poolLive) {
            Xchg(&g_life, from);
            return Err(NFR_E_STATE, 1);
        }
    }

    // Everything below is unpublished until the final stores: a failure frees only a block allocated here and leaves g_storage /
    // g_batch exactly as they were (Batch::Init verifies the image before it touches anything, so a failed Init keeps the old
    // pointers valid).  The published block is only released after the new session is live (see the header comment for why no
    // pointer into it can still be in use).  Order: storage, pin, pool, batch.
    nb::Config bcfg;
    bcfg.imageDelta = c.imageDelta;
    bcfg.maxUnits = c.maxUnits;
    bcfg.maxMen = c.maxMen;
    const size_t bytes = nb::Batch::StorageBytes(bcfg, c.arenaBytes);
    const bool reuse = g_storage != nullptr && g_storageBytes >= bytes;   // quiescent: stopped, joined, ownerless (checked above)
    void* storage = g_storage;
    size_t storageHeld = g_storageBytes;
    if (!reuse) {
        storage = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        storageHeld = bytes;
        if (!storage) { const uint32_t le = GetLastError(); Xchg(&g_life, from); return Err(NFR_E_MEMORY, le); }
    }
    auto dropNew = [&]() { if (!reuse) VirtualFree(storage, 0, MEM_RELEASE); };

    if (!g_pinned) {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, reinterpret_cast<LPCWSTR>(&nfr_initialize), &self)) {
            const uint32_t le = GetLastError();
            dropNew();
            Xchg(&g_life, from);
            return Err(NFR_E_PIN, le);
        }
        g_pinned = true;
    }

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
    const ntw_u32 pr = ntw_pool_init(Pool(), &pc);   // unwinds every thread / event it created on failure
    if (pr != NTW_POOL_OK) {
        dropNew();
        Xchg(&g_life, from);
        return Err(NFR_E_POOL, pr);
    }

    const nb::Reason br = g_batch.Init(storage, bytes, bcfg);   // verifies the pinned image bytes at imageDelta; resets the batch state
    if (br != nb::kOk) {
        // Unpublished team: no epoch exists, so no dispatch ever handed a worker a pointer into any storage.
        const ntw_u32 sr = ntw_pool_shutdown(Pool());
        (void)sr;
        dropNew();
        Xchg(&g_life, from);
        const uint32_t cls = (br == nb::kImageMismatch || br == nb::kAngleTableNotReady) ? NFR_E_IMAGE : NFR_E_BATCH;
        return Err(cls, static_cast<uint32_t>(br));
    }

    // publish: exclusive and disabled (first session: nobody can own; later session: the stop token is still held)
    g_root = c.root;
    g_model = c.model;
    g_minJobs = c.minJobs;
    g_maxUnits = c.maxUnits;
    g_serialChunks = 0;
    g_inlineChunks = 0;
    g_extFallbacks = 0;
    for (uint32_t w = NFR_D_CAPTURE_A; w < NFR_DIAG_WORDS; ++w) nfr_diag[w] = 0;   // new session: ownerless, no gather can run
    g_pubBatchFallbacks = 0;
    g_poolLive = true;
    if (from == kLifeNone) {   // never rewritten later: fetched hooks call these addresses without any lock
        g_delta = c.imageDelta;
        g_origManager = c.imageDelta + NFR_VA_MANAGER;
        g_nfrOrigAssign = c.imageDelta + NFR_VA_ASSIGN;
    }
    for (uint32_t w = NFR_S_EPOCHS; w < NFR_STATE_WORDS; ++w) Store(w, 0);
    void* const oldStorage = g_storage;
    g_storage = storage;
    g_storageBytes = storageHeld;
    if (!reuse && oldStorage) VirtualFree(oldStorage, 0, MEM_RELEASE);   // g_batch no longer refers to it; nothing else ever did
    Store(NFR_S_STORAGE_BYTES, static_cast<uint32_t>(storageHeld));
    Xchg(&g_life, kLifeReady);
    Xchg(&nfr_state[NFR_S_PHASE], NFR_PHASE_READY);
    Xchg(&nfr_state[NFR_S_ENABLED], 1);
    Xchg(&g_owner, 0);   // last: from here an entry may become the owner
    return NFR_OK;
}

extern "C" uint32_t __stdcall nfr_stop(void*) {
    for (;;) {
        const uint32_t life = g_life;
        if (life == kLifeNone) return Err(NFR_E_STATE, 0);
        if (life == kLifeStopped) return NFR_OK;
        if (life != kLifeReady) return Err(NFR_E_BUSY, 0);   // initialize or another stop is running
        if (Cas(&g_life, kLifeStopping, kLifeReady) == kLifeReady) break;
    }

    // 1. no new epoch can start from here on (an entry that already passed its first check re-checks after its CAS)
    Xchg(&nfr_state[NFR_S_ENABLED], 0);
    // 2. an active epoch owns the pool: report busy, change nothing else (the epoch ends normally; call again later)
    if (Cas(&g_owner, NFR_STOP_OWNER_TOKEN, 0) != 0) { Xchg(&g_life, kLifeReady); return Err(NFR_E_BUSY, 0); }
    // 3. exclusive: snapshot the counters BEFORE the dispatcher clears them, then join the team
    PublishStats();
    const ntw_u32 r = ntw_pool_shutdown(Pool());
    if (r != NTW_POOL_OK) {
        Xchg(&g_owner, 0);   // entries stay disabled; the pool is never used again (shutdown failures leave it unusable)
        Xchg(&g_life, kLifeReady);
        return Err(NFR_E_POOL, r);
    }
    g_poolLive = false;
    Xchg(&nfr_state[NFR_S_PHASE], NFR_PHASE_STOPPED);   // g_owner keeps the stop token until a new session is published
    Xchg(&g_life, kLifeStopped);
    return NFR_OK;
}
