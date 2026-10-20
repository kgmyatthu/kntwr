// In-process owner of source-checked native optimization hooks.
// Only the monitor publishes/restores slots and changes module lifetimes. The
// tick gate owns the complete private tick; stop waits for it before teardown.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dbghelp.h> // MiniDumpWriteDump types only: the function is resolved with LoadLibrary at start (no import)
#include <intrin.h>
#include <xmmintrin.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include <math.h>
#include <cmath>
#include "ntw2_runtime.h"
#include "clones/ntw2_clones.h"
#include "profile/ntw2_profile.h"
#include "ai/ntw2_ai_census.h"
#include "ai/ntw2_ai_async2.h"
#include "ai/ntw2_ai_ctrl_batch.h"
#include "ai/ntw2_ai_ctrl_geometry.h"
#include "ntw2_guard.h"
#include "native_workload.h"
#include "worker/native_worker_dispatch.h"
#include "ballistics/native_ballistics_abi.h"
#include "ballistics/native_ballistics_query_cache.h"
#include "brain2/native_brain2.h"
#include "brain2/native_brain_workers.h"
#include "brain2/native_unit_brain.h"
#include "army/native_army_unit.h"
#include "army/native_army_storm.h"
#include "army/native_army_solver.h"
#include "formation/native_formation_solver.h"
#include "brain2/native_brain_s0.h"
#include "brain2/native_brain_locality.h"
#include "brain2/native_unit_policy.h"
#include "brain2/native_unit_fatigue.h"
#include "brain2/native_unit_posture_engage.h"
#include "brain2/native_node.h"
#include "brain2/native_move_node.h"
#include "brain2/native_idle_node.h"
#include "brain2/native_action_node.h"
#include "brain2/native_node_projection.h"
#include "brain2/native_fire.h"
#include "collision/native_collision_solver.h"
#include "collision/native_contact.h"
#include "loco/native_loco.h"
#include "loco/native_grid_probation.h"
#include "loco/native_sweep.h"
#include "loco/native_resolve.h"
#include "loco/native_env.h"
#include "formation/native_formation_runtime.h"
#include "path/native_path_runtime.h"
#include "ai/ntw2_walk_memo.h"
#include "ai/ntw2_planner_search.h"
#include "ai/ntw2_record_test.h"
#include "ai/ntw2_planner_prepass.h"
#include "ai/ntw2_spiral.h"
#include "ai/ntw2_claim_once.h"
#include "ai/ntw2_group_formup.h"
#include "brain/ntw2_retarget_jitter.h"
#include "brain/ntw2_target_cull.h"
#include "army/ntw2_mounted_officer.h"
#include "ai/ntw2_engage_census.h"
#include "core/ntw2_alloc_census.h"
#include "render/ntw2_arena_release.h"

using U = uint32_t;
using Init = U (__stdcall *)(void*);
using Manager = U (__fastcall *)(void*);
using Scheduler = void (__fastcall *)(void*);
using Tick = U (__fastcall *)(void*, void*, U, U); // original 57DF40: ECX=model, ret 8

extern "C" {
__declspec(dllexport) volatile ntw2_status ntw2_state = {0, NTW2_ABI, sizeof(ntw2_status)};
__declspec(dllexport) ntw2_trace_ring ntw2_trace = {NTW2_TRACE_ABI, sizeof(ntw2_trace_ring), NTW2_TRACE_ENTRIES};
U __stdcall ntw2_start(void*);
U __stdcall ntw2_stop(void*);
U __stdcall ntw_pool_init(ntw_pool*, const ntw_pool_config*);
U __stdcall ntw_pool_shutdown(ntw_pool*);
U __stdcall ntw_pool_worker_start(void*);
void __stdcall ntw_pool_dispatch(U, U, U, void*);
void __fastcall bal_stage(void*, bal_job*);
void __fastcall bal_step(void*, bal_job*);
void __fastcall bal_worker(bal_job*, U);
}

namespace {
constexpr U kPreferred = 0x400000, kSimulation = NTW2_PATH | NTW2_FORMATION | NTW2_BALLISTICS | NTW2_AI_ASYNC | NTW2_BRAIN2 | NTW2_COLLIDE | NTW2_COLLIDE_LOD | NTW2_LOCO;
constexpr U kProjectileCapacity = 65536, kStopTimeoutMs = 15000;
enum Error : U { BadConfig=1, BadImage=2, MissingExport=3, CloneError=4, ModuleError=5,
                 SlotConflict=6, SlotProtection=7, StopTimeout=8, PoolError=9, ThreadError=10,
                 StorageError=12, VisualSlotCount=13, AllocatorError=NTW2_ERROR_ALLOCATOR,
                 VirtualAddressBudget=NTW2_ERROR_VA_BUDGET };
enum Life : LONG { Never, Running, Stopped, Failed };
struct World { U root, model, army, path, projectiles, tick; };
struct Module { Init init, stop; volatile U* state; U feature, busy; bool ready; };
struct Slot { U address, original, replacement; DWORD protection; bool owned, protectionDirty; };
HMODULE selfModule;
HANDLE stopEvent, budgetWakeEvent, monitorThread;
SRWLOCK apiLock=SRWLOCK_INIT;
volatile LONG life = Never, enabled = 0, tickOwner = 0, quiesced = 1;
U epochMask, imageBase, imageSize, delta, slotCount, generation;
U failure, failureDetail;
ntw2_config config;
ntw2_clone_set clones;
U cloneBindings[NTW2_BIND_COUNT]; // the exact table the primary clone set was built with (BRAIN2 Stage 2 rebuilds its worker family from it)
World world;
bool arenaKeepHooks; // set around the Deactivate() of a live-but-dormant world: ntw2_arena_release keeps its slots and frees nothing
Module formation, query, path;
volatile U* pathStorage;
volatile U* formationDiag;
constexpr U kBrainSlotCount = NTW2_BRAIN_SLOTS;
constexpr U kMaxSlots = 11 + kBrainSlotCount + ntw2_ai_census::kPinCount + ntw2_ai_async2::kPinCount + ntw2_prepass::kNodeThinkSlotCount + 2 + 2 + 2 + 1 + 1 + ntw2_alloc_census::kSlotCount; // batch64 + formation + task + planner walk + visual + brain vtables + ai census pins + ai_async2 pins + prepass node/presize slots + the PS observer slot, with margin + the spiral fallback/controller gates + the storm census R2/R1 route slots + the solver's second R1 slot + the --ai-record-test alternate delegate slot + alloc census provider slots
constexpr U kGroupSlots = 8; // --ai-formup-gate 4 (REFORM / MOVE_TO_FORMUP test + enter) + 4 reserved for --ai-standoff
Slot slots[kMaxSlots+kGroupSlots];
U censusSlotFirst, censusSlotEnd; // [first,end) of the AI census pins inside slots[] for the current generation
U allocCensusSlotFirst, allocCensusSlotEnd; // [first,end) of the alloc census provider slots inside slots[]
U allocCensusRequestedMode; // 0 = off, 1 = --alloc-census, 2 = --alloc-fix (captured at ntw2_start before status reset)
static_assert(1+6+1+1+1+kBrainSlotCount+ntw2_ai_census::kPinCount+ntw2_ai_async2::kPinCount+ntw2_prepass::kNodeThinkSlotCount+2+2+2+1+1+ntw2_alloc_census::kSlotCount<=kMaxSlots, "slot table holds every possible hook");
__declspec(align(64)) ntw_pool pool;
bool poolReady, poolOwned; // ownership also covers an init-unwind whose join needs retrying
bool collideSampleReady; // current runtime start has initialized solver counters; stop retains final samples
bool locoSampleReady, locoRunning; // locoSampleReady: current runtime start has initialized loco counters (stop retains final samples); locoRunning: module Start succeeded and Stop is pending
// Only the scene/catalog read is handed to the tick owner; large activation
// allocations and participant prefaults continue on the monitor without a gate.
struct ActivationCapture {
    volatile LONG state; // 0 idle/cancelled, 1 pending, 2 running, 3 completed
    U model;
    void (*capture)(void*);
    void* context;
} activationCapture = {};
bool CaptureAtTick(void (*capture)(void*), void* context);
bool NeedsActivationWorkload();
ntw2_workload::Capacity activationCapacity{};
U memoryWords[NTW2_MEMORY_WORDS]{}, defaultStackBytes, runtimeImageBytes;
ULONGLONG memoryNextSample, vaLastHoleWalk, vaCachedLargestHole;
U vaTotalFloorBytes=NTW2_MEMORY_MIN_AVAIL_VIRTUAL, vaHoleFloorBytes=NTW2_MEMORY_MIN_LARGEST_HOLE;
U vaBreachStreak, vaLastWalkUs;
volatile LONG budgetDisabledMask, budgetReleasePending;
bool budgetRetired;
void SampleMemoryStorage();
U allocatorWords[NTW2_ALLOCATOR_WORDS];
constexpr U kAiAllocatorRow=NTW2_ALLOCATOR_THREADS-1;
U __stdcall WorkerAllocatorInit(U context, U workerIndex);
__declspec(thread) U visualArenaIndex; // caller 0; runtime pool workers 1..31, assigned once at startup
bal_job ballistic;
bal_record* records;
U pathHook, formHook, privateTick, privateManager;

U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> U FnAddress(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
U V(U preferred) { return preferred + delta; }
U Export(const char* name) { return FnAddress(GetProcAddress(selfModule, name)); }
LONG Load(volatile LONG* value) { return _InterlockedCompareExchange(value, 0, 0); }
void PublishAllocatorStatus() { // caller holds the lifecycle sequence; result is published last by its worker
    for (U row=0;row<NTW2_ALLOCATOR_THREADS;++row) {
        const U at=row*NTW2_ALLOCATOR_ROW_WORDS;
        const U result=static_cast<U>(Load(reinterpret_cast<volatile LONG*>(&allocatorWords[at])));
        for (U i=1;i<NTW2_ALLOCATOR_ROW_WORDS;++i)
            ntw2_state.allocator_words[at+i]=result ? allocatorWords[at+i] : 0;
        ntw2_state.allocator_words[at]=result;
    }
}
bool Read(U address, void* out, size_t bytes) {
    if (address < 0x10000 || bytes > UINT32_MAX - address) return false;
    bool ok=false;
    ++ntw2::probeDepth; // an expected, caught fault: the crash capture (CrashVeh) must not treat it as a crash
    __try { memcpy(out, reinterpret_cast<const void*>(address), bytes); ok=true; }
    __except(EXCEPTION_EXECUTE_HANDLER) { ok=false; }
    --ntw2::probeDepth;
    return ok;
}
bool Word(U address, U& out) { return !(address & 3) && Read(address, &out, sizeof(out)); }
U WordOrZero(U address) { U out=0; Word(address,out); return out; }
void StateBegin() { _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&ntw2_state.sequence)); }
void StateEnd() { _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&ntw2_state.sequence)); }
void RecordError(U error, U detail) { if (!failure) { failure=error; failureDetail=detail; } }
void Memory64(U at,ULONGLONG value) {
    memoryWords[at]=static_cast<U>(value); memoryWords[at+1]=static_cast<U>(value>>32);
}
ULONGLONG Memory64(U at) {
    return static_cast<ULONGLONG>(memoryWords[at]) | (static_cast<ULONGLONG>(memoryWords[at+1])<<32);
}
struct VaWalk {
    ULONGLONG largestFree, reserved, committed, image, mapped;
    U freeRegions;
};
VaWalk WalkUserVirtualAddressSpace() {
    static LONGLONG freq=0;
    if(!freq) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); freq=f.QuadPart; }
    LARGE_INTEGER t0, t1; QueryPerformanceCounter(&t0);
    VaWalk w={};
    MEMORY_BASIC_INFORMATION info;
    for(U address=0; VirtualQuery(reinterpret_cast<const void*>(address),&info,sizeof(info))==sizeof(info); ) {
        const ULONGLONG size=info.RegionSize;
        if(info.State==MEM_FREE) { ++w.freeRegions; if(size>w.largestFree) w.largestFree=size; }
        else {
            if(info.State==MEM_COMMIT) w.committed+=size;
            w.reserved+=size;
            if(info.Type==MEM_IMAGE) w.image+=size; else if(info.Type==MEM_MAPPED) w.mapped+=size;
        }
        const ULONGLONG next=static_cast<ULONGLONG>(address)+size;
        if(next>0xFFFFFFFFull) break;
        address=static_cast<U>(next);
    }
    QueryPerformanceCounter(&t1);
    vaLastWalkUs=freq ? static_cast<U>((t1.QuadPart-t0.QuadPart)*1000000ll/freq) : 0u;
    return w;
}
// --va-watch (NTW2_VA_WATCH): opt-in process-VA sampler for load-time crash forensics. Runs on the monitor thread once
// per second in every phase (the ACTIVE-only memory_words sampler cannot see a battle load). GlobalMemoryStatusEx plus
// one VirtualQuery walk of user space (~1200 regions, ~0.54 ms mean / 0.71 ms max; shared with SampleVirtualMemory). Reads only; publishes under the status sequence.
U vaWords[NTW2_VA_WATCH_WORDS];
ULONGLONG vaNextSample=0, vaStart=0;
bool SampleVirtualMemory(bool force,ULONGLONG* available=nullptr,ULONGLONG* largestHoleOut=nullptr) {
    const ULONGLONG now=GetTickCount64();
    if(!force && now<memoryNextSample) return true;
    MEMORYSTATUSEX memory={}; memory.dwLength=sizeof(memory);
    if(!GlobalMemoryStatusEx(&memory)) { memoryWords[NTW2_MEM_ERROR]=GetLastError(); return false; }
    if(!memoryWords[NTW2_MEM_SAMPLES] || memory.ullAvailVirtual<Memory64(NTW2_MEM_MIN_AVAIL_LO))
        Memory64(NTW2_MEM_MIN_AVAIL_LO,memory.ullAvailVirtual);
    // Shared VirtualQuery walk: when --va-watch just walked in this monitor cycle (now == vaLastHoleWalk), reuse its result;
    // otherwise walk here (1 Hz, ~0.54 ms measured; if >1 ms on a slow host, walks every 5 s when avail > 2x total_floor
    // and every 1 s at or below).
    ULONGLONG largestHole=vaCachedLargestHole;
    const ULONGLONG walkIntervalMs=(vaLastWalkUs>1000u && memory.ullAvailVirtual>2ull*vaTotalFloorBytes) ? 5000ull : 1000ull;
    if(force || !vaLastHoleWalk || (now>vaLastHoleWalk && now-vaLastHoleWalk>=walkIntervalMs)) {
        const VaWalk w=WalkUserVirtualAddressSpace();
        largestHole=w.largestFree;
        vaCachedLargestHole=largestHole;
        vaLastHoleWalk=now;
    }
    const U holeBytes=largestHole>UINT32_MAX ? UINT32_MAX : static_cast<U>(largestHole);
    if(!memoryWords[NTW2_MEM_SAMPLES] || holeBytes<memoryWords[NTW2_MEM_MIN_LARGEST_HOLE])
        memoryWords[NTW2_MEM_MIN_LARGEST_HOLE]=holeBytes;
    ++memoryWords[NTW2_MEM_SAMPLES]; memoryNextSample=now+1000;
    const U owned=static_cast<U>(Load(&enabled))&(NTW2_LOCO|NTW2_COLLIDE);
    const bool lowTotal=memory.ullAvailVirtual<vaTotalFloorBytes;
    const bool lowHole=largestHole<vaHoleFloorBytes;
    if(owned && !Load(&budgetDisabledMask)) {
        // Require the breach on 2 consecutive periodic samples before latching to filter transient 1-sample dips.
        if(!force && (lowTotal || lowHole)) {
            if(++vaBreachStreak>=2) {
                // Stage entry observes this latch before touching either module. A stage
                // already in progress finishes; its tick owner protects the retained arenas.
                _InterlockedExchange(&budgetReleasePending,1);
                _InterlockedExchange(&budgetDisabledMask,static_cast<LONG>(owned));
                memoryWords[NTW2_MEM_BUDGET_DISABLED_MASK]=owned;
                memoryWords[NTW2_MEM_BUDGET_RELEASE_PENDING]=1;
                memoryWords[NTW2_MEM_LATCH_REASON]=lowTotal ? NTW2_LATCH_REASON_TOTAL : NTW2_LATCH_REASON_HOLE;
                ++memoryWords[NTW2_MEM_BUDGET_REFUSALS];
            }
        } else if(!force) {
            vaBreachStreak=0;
        }
    }
    if(available) *available=memory.ullAvailVirtual;
    if(largestHoleOut) *largestHoleOut=largestHole;
    return true;
}
bool VirtualBudget(ULONGLONG reservation=0,bool activation=false,bool post=false) {
    ULONGLONG available=0, largestHole=0;
    const bool measured=SampleVirtualMemory(true,&available,&largestHole);
    if(activation) Memory64(NTW2_MEM_ACTIVATION_AVAIL_LO,available);
    if(post) Memory64(NTW2_MEM_POST_ALLOC_AVAIL_LO,available);
    const bool lowTotal=!measured || available<reservation+NTW2_MEMORY_MIN_AVAIL_VIRTUAL;
    const bool lowHole=measured && largestHole<NTW2_MEMORY_MIN_LARGEST_HOLE;
    if(lowTotal || lowHole) {
        if(measured && !memoryWords[NTW2_MEM_LATCH_REASON])
            memoryWords[NTW2_MEM_LATCH_REASON]=lowTotal ? NTW2_LATCH_REASON_TOTAL : NTW2_LATCH_REASON_HOLE;
        ++memoryWords[NTW2_MEM_BUDGET_REFUSALS];
        RecordError(VirtualAddressBudget,measured ? static_cast<U>((lowTotal ? available : largestHole)>>20) : memoryWords[NTW2_MEM_ERROR]);
        return false;
    }
    return true;
}
void PublishMemory() { // lifecycle sequence is held by the monitor
    for(U i=0;i<NTW2_MEMORY_WORDS;++i) ntw2_state.memory_words[i]=memoryWords[i];
}
void VaWatchSample() {
    if(!(config.va_watch_flags&(NTW2_VA_WATCH|NTW2_HEAP_OPTIMIZE))) return;
    const ULONGLONG now=GetTickCount64();
    if(now<vaNextSample) return;
    vaNextSample=now+1000;
    if(!vaStart) vaStart=now;
    MEMORYSTATUSEX memory={}; memory.dwLength=sizeof(memory);
    if(!GlobalMemoryStatusEx(&memory)) return;
    if(!(config.va_watch_flags&NTW2_VA_WATCH)) {
        ntw2_arena_release::OnVaWatch(static_cast<U>(memory.ullAvailVirtual>>20));
        return;
    }
    const VaWalk w=WalkUserVirtualAddressSpace();
    vaCachedLargestHole=w.largestFree;
    vaLastHoleWalk=now;
    const U uptime=static_cast<U>((now-vaStart)/1000), phase=ntw2_state.phase;
    const U availMiB=static_cast<U>(memory.ullAvailVirtual>>20), largestMiB=static_cast<U>(w.largestFree>>20);
    vaWords[NTW2_VA_VERSION]=1;
    vaWords[NTW2_VA_AVAIL_LO]=static_cast<U>(memory.ullAvailVirtual); vaWords[NTW2_VA_AVAIL_HI]=static_cast<U>(memory.ullAvailVirtual>>32);
    if(!vaWords[NTW2_VA_SAMPLES] || memory.ullAvailVirtual<(static_cast<ULONGLONG>(vaWords[NTW2_VA_MIN_AVAIL_LO])|(static_cast<ULONGLONG>(vaWords[NTW2_VA_MIN_AVAIL_HI])<<32))) {
        vaWords[NTW2_VA_MIN_AVAIL_LO]=vaWords[NTW2_VA_AVAIL_LO]; vaWords[NTW2_VA_MIN_AVAIL_HI]=vaWords[NTW2_VA_AVAIL_HI];
        vaWords[NTW2_VA_MIN_PHASE]=phase; vaWords[NTW2_VA_MIN_UPTIME_S]=uptime;
    }
    vaWords[NTW2_VA_LARGEST_FREE]=largestMiB;
    if(!vaWords[NTW2_VA_SAMPLES] || largestMiB<vaWords[NTW2_VA_MIN_LARGEST_FREE]) vaWords[NTW2_VA_MIN_LARGEST_FREE]=largestMiB;
    vaWords[NTW2_VA_FREE_REGIONS]=w.freeRegions;
    vaWords[NTW2_VA_RESERVED_MIB]=static_cast<U>(w.reserved>>20); vaWords[NTW2_VA_COMMITTED_MIB]=static_cast<U>(w.committed>>20);
    vaWords[NTW2_VA_IMAGE_MIB]=static_cast<U>(w.image>>20); vaWords[NTW2_VA_MAPPED_MIB]=static_cast<U>(w.mapped>>20);
    U* ring=vaWords+NTW2_VA_RING_BASE+(vaWords[NTW2_VA_RING_NEXT]%NTW2_VA_RING_ENTRIES)*NTW2_VA_RING_WORDS;
    ring[0]=uptime; ring[1]=availMiB; ring[2]=largestMiB; ring[3]=phase;
    ++vaWords[NTW2_VA_RING_NEXT]; ++vaWords[NTW2_VA_SAMPLES];
    ntw2_arena_release::OnVaWatch(availMiB);
    StateBegin();
    for(U i=0;i<NTW2_VA_WATCH_WORDS;++i) ntw2_state.va_watch_words[i]=vaWords[i];
    StateEnd();
}
void Phase(U phase) {
    if (phase!=NTW2_ACTIVE) ntw2_profile_set_active(false);
    StateBegin(); ntw2_state.phase=phase; ntw2_state.error=failure; ntw2_state.error_detail=failureDetail;
    ntw2_state.active_mask=static_cast<U>(Load(&enabled)); StateEnd();
}

bool MainImage(U base) {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    if (base != Address(GetModuleHandleW(nullptr)) || !Read(base,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew<sizeof(dos) || dos.e_lfanew>0x100000 || !Read(base+dos.e_lfanew,&nt,sizeof(nt)) ||
        nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 ||
        nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        // The loader rewrites the mapped ImageBase to the actual base after relocation.
        (nt.OptionalHeader.ImageBase!=kPreferred && nt.OptionalHeader.ImageBase!=base) ||
        nt.OptionalHeader.SizeOfImage < 0x14f5000 || nt.OptionalHeader.SizeOfImage > 0x10000000) return false;
    imageBase=base; imageSize=nt.OptionalHeader.SizeOfImage; delta=base-kPreferred;
    defaultStackBytes=nt.OptionalHeader.SizeOfStackReserve;
    const auto selfDos=reinterpret_cast<const IMAGE_DOS_HEADER*>(selfModule);
    const auto selfNt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(Address(selfModule)+selfDos->e_lfanew);
    runtimeImageBytes=selfNt->OptionalHeader.SizeOfImage;
    return (delta & 0xffff)==0;
}

U probe;
bool Probe(U code) { probe=code; return false; }
bool FindWorld(World& out, bool& asynchronous) {
    out={}; asynchronous=false;
    U engine=0, back=0;
    if (!Word(V(0x14a418c),engine) || !engine) return Probe(1);
    if (!Word(engine+0xf8,out.root) || !out.root) return Probe(2);
    if (!Word(out.root+8,out.model) || !out.model) return Probe(3);
    if (!Word(out.model,back) || back!=out.root) return Probe(4);
    if (!Word(out.model+0x58,out.tick)) return Probe(5);
    if ((config.enabled_mask & (NTW2_FORMATION|NTW2_AI_ASYNC)) || NeedsActivationWorkload()) {
        // Workload-sized collision/LOD/owned-grid activation also binds this manager,
        // independently of whether formation, AI or LOCO is enabled.
        U armies=0;
        if (!Word(out.model+0xb0,out.army) || !out.army) return Probe(6);
        if ((config.enabled_mask & (NTW2_FORMATION|NTW2_AI_ASYNC)) && !Word(out.army+0x84,armies)) return Probe(7);
    }
    if (config.enabled_mask & NTW2_PATH)
        if (!Word(out.model+0xb4,out.path) || !out.path) return Probe(8);
    if (config.enabled_mask & NTW2_BALLISTICS) {
        U grid=0;
        if (!Word(out.model+0xe4,out.projectiles) || !out.projectiles) return Probe(9);
        if (!Word(out.projectiles,back) || back!=out.root) return Probe(10);
        if (!Word(out.model+0xa4,grid) || !grid) return Probe(11);
    }
    unsigned char flag=0;
    if (!Read(out.root+0x2829c,&flag,1)) return Probe(20);
    asynchronous=flag==1;
    probe=asynchronous ? 0x100 : 0;
    return true;
}
bool SameWorld(const World& a, const World& b) {
    return a.root==b.root && a.model==b.model && a.army==b.army && a.path==b.path &&
           a.projectiles==b.projectiles;
}
bool BoundModel(U model) {
    U engine=0, root=0, back=0, current=0;
    return model==world.model && Word(V(0x14a418c),engine) && engine && Word(engine+0xf8,root) && root==world.root &&
           Word(root+8,current) && current==model && Word(model,back) && back==root;
}

// Simulation tick timing measured at the gate (QPC). Words: 0 ticks, 1 sum duration us, 2 max duration us,
// 3..9 duration histogram (<=1,<=2,<=5,<=10,<=20,<=50,>50 ms), 10 sum interval us, 11 max interval us,
// 12 intervals >150 ms, 13 tick thread id, 14 intervals >250 ms, 15 ticks routed through the private clone.
volatile U simWords[16];
LONGLONG tickLastStart;
void SimRecord(LONGLONG start, LONGLONG end, U tid, bool routed) {
    static LONGLONG freq;
    if (!freq) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); freq=f.QuadPart; }
    const U dur=static_cast<U>((end-start)*1000000/freq);
    ++simWords[0]; simWords[1]+=dur; if (dur>simWords[2]) simWords[2]=dur;
    static const U bounds[6]={1000,2000,5000,10000,20000,50000};
    U bucket=6; for (U i=0;i<6;++i) if (dur<=bounds[i]) { bucket=i; break; }
    ++simWords[3+bucket];
    if (tickLastStart) {
        const U interval=static_cast<U>((start-tickLastStart)*1000000/freq);
        simWords[10]+=interval; if (interval>simWords[11]) simWords[11]=interval;
        if (interval>150000) ++simWords[12];
        if (interval>250000) ++simWords[14];
    }
    tickLastStart=start;
    simWords[13]=tid;
    if (routed) ++simWords[15];
}
// Tick cadence observed by the monitor (poll granularity): intervals between changes of the model tick word.
struct TickCadence { U words[16]; ULONGLONG lastChange; U lastTick; bool armed; };
TickCadence cadence;
volatile U tickInProgress;
volatile LONG gateDepth;
constexpr U kRouted = kSimulation | NTW2_PROFILE; // the clone route is also taken for profiling (sub-phase timing)
// Features whose sites live behind the MANAGER clone route (FORMATION takes its own hook; PATH and BALLISTICS are
// bound in the TICK clone). Every other routed feature must take the clone, or its site gates are never reached.
constexpr U kManagerRouted = NTW2_PROFILE | NTW2_BRAIN2 | NTW2_AI_ASYNC | NTW2_COLLIDE | NTW2_COLLIDE_LOD | NTW2_LOCO;
static_assert(kManagerRouted == (kRouted & ~(NTW2_FORMATION | NTW2_PATH | NTW2_BALLISTICS)),
              "every routed feature except formation/path/ballistics takes the MANAGER clone");
volatile U phaseUs[3];       // manager, ballistics, path: accumulated inside the current tick (single executor, depth <= 1)
// One tick executor at a time (gate depth <= 1); site calls nest because site 2
// encloses the ARMY sites. Host storage never changes any game's object layout.
struct SiteFrame { U site, returnAddress, outputList, family, brainAgent, brainState, brainUnit, brainActive; LARGE_INTEGER start; };
SiteFrame siteStack[64];
U siteDepth, siteUs[NTW2_TRACE_SITES], siteCalls[NTW2_TRACE_SITES], siteThis[NTW2_TRACE_SITES];
// Per-tick duration of the last completed call of a site (used to attribute the AI planner's round-robin think).
U siteLastUs[NTW2_TRACE_SITES];
// Sampler gate for --profile-site: the executing thread id while the selected site (index+1) is active, else 0.
volatile U siteInProgress; U siteGateIndex; U siteGateDepth;
volatile U brainScopeTid; // --brain-target-cull* / --brain-retarget-jitter: the tick thread's id while it executes site 6 (the soldier-brain stage), else 0
U siteCallees[NTW2_TIMED_SITES];
// Tick core census + placement (trace flags bits 3..31; NTW2_TICK_PCORE / NTW2_TICK_CORE_AB). The topology is read once per start
// from the CPU set information (group 0, processor numbers 0..31: a 32-bit affinity mask); the census state is tick-owner only.
unsigned char cpuECore[64]; // 1: processor number is in a lower efficiency class than the highest one present
DWORD_PTR cpuPMask, cpuEMask; // highest-class / lower-class processors, intersected with the process affinity
bool cpuTopology, cpuHybrid;  // topology read; both classes present and usable
struct CoreCensus { LONGLONG last, all, e, s6All, s6E; U lastE, changes, owner; bool inSite6, active; } coreCensus;
void CpuTopologyInit() {
    memset(cpuECore,0,sizeof(cpuECore)); cpuPMask=cpuEMask=0; cpuTopology=cpuHybrid=false;
    alignas(8) static unsigned char buffer[16384];
    ULONG length=0;
    if (!GetSystemCpuSetInformation(reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer),sizeof(buffer),&length,GetCurrentProcess(),0) ||
        length>sizeof(buffer)) return;
    BYTE minClass=0xff, maxClass=0;
    DWORD_PTR classMask[2]={}; // [0]: processors of the highest class (second pass), [1]: all lower classes
    for (int pass=0; pass<2; ++pass) {
        for (ULONG offset=0; offset+sizeof(DWORD)*2<=length;) {
            const auto* info=reinterpret_cast<const SYSTEM_CPU_SET_INFORMATION*>(buffer+offset);
            if (!info->Size || offset+info->Size>length) return;
            if (info->Type==CpuSetInformation && info->CpuSet.Group==0 && info->CpuSet.LogicalProcessorIndex<32) {
                const BYTE cls=info->CpuSet.EfficiencyClass;
                if (!pass) { if (cls<minClass) minClass=cls; if (cls>maxClass) maxClass=cls; }
                else {
                    const BYTE index=info->CpuSet.LogicalProcessorIndex;
                    classMask[cls==maxClass ? 0 : 1]|=static_cast<DWORD_PTR>(1)<<index;
                    cpuECore[index]=cls==maxClass ? 0 : 1;
                }
            }
            offset+=info->Size;
        }
        if (!pass && minClass>maxClass) return; // no group-0 processor reported
    }
    DWORD_PTR process=0, system=0;
    if (!GetProcessAffinityMask(GetCurrentProcess(),&process,&system)) return;
    cpuPMask=classMask[0]&process; cpuEMask=classMask[1]&process;
    cpuTopology=true;
    cpuHybrid=minClass!=maxClass && cpuPMask && cpuEMask;
}
// One census sample: the gap since the previous sample counts for their class (half each when they differ). Inert outside a
// census tick (CoreBegin .. CoreFlags) and on any other thread: the AI worker also reaches timed sites (e.g. site 40 under the
// prepass census / polygon modes) while the owner waits, and its processor must not enter the owner's census.
inline void CoreSample(LONGLONG now) {
    CoreCensus& c=coreCensus;
    if (!c.active || GetCurrentThreadId()!=c.owner) return;
    const U e=cpuECore[GetCurrentProcessorNumber()&63];
    const LONGLONG dt=now-c.last, eShare=(static_cast<LONGLONG>(e+c.lastE)*dt)>>1;
    c.all+=dt; c.e+=eShare;
    if (c.inSite6) { c.s6All+=dt; c.s6E+=eShare; }
    if (e!=c.lastE) ++c.changes;
    c.last=now; c.lastE=e;
}
inline void CoreBegin(LONGLONG now) {
    CoreCensus& c=coreCensus;
    c.owner=GetCurrentThreadId(); c.all=c.e=c.s6All=c.s6E=0; c.changes=0; c.inSite6=false; c.active=true;
    c.last=now; c.lastE=cpuECore[GetCurrentProcessorNumber()&63];
}
inline U CoreShare(LONGLONG part, LONGLONG all) { return all>0 ? static_cast<U>((part*255+all/2)/all) : 0u; }
// Ends the census tick. placed: 0 none, 1 pinned to P, 2 pinned to E. Layout: ntw2_trace_entry::flags.
U CoreFlags(U entryE, U placed) {
    CoreCensus& c=coreCensus;
    c.active=false;
    return 8u | (entryE<<4) | (c.lastE<<5) | (placed==1 ? 0x40u : placed==2 ? 0x80u : 0u) |
           (CoreShare(c.e,c.all)<<8) | (CoreShare(c.s6E,c.s6All)<<16) | ((c.changes>255u ? 255u : c.changes)<<24);
}
const U siteCalleeVas[]=NTW2_SITE_CALLEE_VAS;
static_assert(sizeof(siteCalleeVas)/sizeof(siteCalleeVas[0])==NTW2_TIMED_SITES, "one callee VA per timed site");
// NTW2_BRAIN accounting (tick-owner thread only; cumulative since the last activation, copied into ntw2_status::brain_words).
// Sites 46..50 are the class entry sites (family = site-46); 51..64 belong to their wrapper's family; 65..94 belong to the family
// whose entry site encloses them (brainFamily, saved and restored by the entry frames).
constexpr U kBrainFirst=NTW2_BRAIN_SITE_FIRST, kBrainEntries=NTW2_BRAIN_FAMILIES, kNoFamily=0xffffffffu;
volatile U brainWords[NTW2_BRAIN_WORDS];
U brainFamily=kNoFamily;
volatile U brainStateWords[NTW2_BRAIN_STATE_WORDS];
// Common battles use the inline table. Grow only when a new unit exceeds half capacity;
// retain the high-water allocation across ticks/activations. No locks or game allocations.
struct BrainUnit { U unit, destinations[2], transitioned; };
BrainUnit brainUnitsInline[1024];
BrainUnit* brainUnits=brainUnitsInline;
U brainUnitCapacity=1024, brainUnitCount;
U BrainUnitHash(U unit, U capacity) { return ((unit>>4)*2654435761u)&(capacity-1); }
BrainUnit* BrainFindUnit(U unit) {
    if (!unit) return nullptr;
    U slot=BrainUnitHash(unit,brainUnitCapacity);
    while (brainUnits[slot].unit && brainUnits[slot].unit!=unit) slot=(slot+1)&(brainUnitCapacity-1);
    if (brainUnits[slot].unit) return brainUnits+slot;
    if (brainUnitCount==brainUnitCapacity/2) {
        const U capacity=brainUnitCapacity*2;
        BrainUnit* grown=capacity>brainUnitCapacity && capacity<=0xffffffffu/sizeof(BrainUnit)
            ? static_cast<BrainUnit*>(calloc(capacity,sizeof(BrainUnit))) : nullptr;
        if (!grown) { ++brainStateWords[11]; return nullptr; }
        for (U i=0;i<brainUnitCapacity;++i) if (brainUnits[i].unit) {
            U at=BrainUnitHash(brainUnits[i].unit,capacity);
            while (grown[at].unit) at=(at+1)&(capacity-1);
            grown[at]=brainUnits[i];
        }
        if (brainUnits!=brainUnitsInline) free(brainUnits);
        brainUnits=grown; brainUnitCapacity=capacity;
        slot=BrainUnitHash(unit,capacity);
        while (brainUnits[slot].unit) slot=(slot+1)&(capacity-1);
    }
    brainUnits[slot].unit=unit;
    ++brainUnitCount; ++brainStateWords[7];
    return brainUnits+slot;
}
U BrainStateBucket(U state) { return state<62 ? state : state==0x4b ? 62u : 63u; }
bool BrainCoreSite(U site) { return site==46 || site==47 || site==55 || site==56 || site==59; }
void BrainStateBeginTick() {
    memset(brainUnits,0,brainUnitCapacity*sizeof(BrainUnit));
    brainUnitCount=0;
}
void BrainStateEnter(SiteFrame& frame, U agent) {
    const auto* bytes=reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(agent));
    frame.brainAgent=agent;
    frame.brainState=*reinterpret_cast<const volatile U*>(bytes+0x1b8);
    frame.brainUnit=*reinterpret_cast<const volatile U*>(bytes+0x1f0);
    frame.brainActive=bytes[0x30];
    const U substate=*reinterpret_cast<const volatile U*>(bytes+0x1d8);
    ++brainStateWords[1];
    ++brainStateWords[NTW2_BRAIN_STATE_COUNTS+BrainStateBucket(frame.brainState)];
    ++brainStateWords[NTW2_BRAIN_SUBSTATE_COUNTS+(substate<79 ? substate : 79)];
    if (!bytes[0xec] && frame.brainState==0x4b) ++brainStateWords[2];
    if (bytes[0xf0]) ++brainStateWords[4];
    if (frame.brainUnit) {
        // 0x66D55F: the brain requires unit+AA0!=0 before setting its engage byte.
        // This is a cheap engagement proxy, not the complete unit combat predicate.
        if (*reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(frame.brainUnit+0xaa0))) ++brainStateWords[5];
        BrainFindUnit(frame.brainUnit);
    } else ++brainStateWords[6];
}
void BrainStateLeave(const SiteFrame& frame) {
    const auto* bytes=reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(frame.brainAgent));
    if (frame.brainActive && !bytes[0x30]) ++brainStateWords[3];
    if (frame.brainState!=0x4b) return;
    const U state=*reinterpret_cast<const volatile U*>(bytes+0x1b8);
    if (state==0x4b) return;
    const U bucket=BrainStateBucket(state);
    ++brainStateWords[8];
    ++brainStateWords[NTW2_BRAIN_TRANSITION_COUNTS+bucket];
    if (!frame.brainUnit) { ++brainStateWords[10]; return; }
    BrainUnit* unit=BrainFindUnit(frame.brainUnit);
    if (!unit) return;
    if (!unit->transitioned) { unit->transitioned=1; ++brainStateWords[9]; }
    const U bit=1u<<(bucket&31);
    if (!(unit->destinations[bucket>>5]&bit)) {
        unit->destinations[bucket>>5]|=bit;
        ++brainStateWords[NTW2_BRAIN_TRANSITION_UNITS+bucket];
    }
}
U BrainOwner(U site) {
    if (site<kBrainFirst+kBrainEntries) return site-kBrainFirst;
    if (site<56) return 2;  // 0x6F4660 wrapper callees 51..55
    if (site<59) return 3;  // 0x602EB0 wrapper callees 56..58
    if (site<65) return 4;  // 0x5FCEB0 wrapper callees 59..64
    return brainFamily;     // brain callees 65..94
}
// The broadphase lists are per-query spatial scratch, NOT pending request queues.
// Count them only after 0x809110 has filled them, before gather resets the count.
volatile U plannerWalkWords[16];
U walkScopeDepth, walksInScope;
volatile U walkScopeThread;
// The scope belongs to the thread that EXECUTES the site-34 planner update: the tick thread without NTW2_AI_ASYNC (or when the
// dispatch is refused), the AI worker while it runs the dispatched original 0x7D99F0 (the tick thread only waits in AiBarrier).
extern volatile U aiThreadId;
extern volatile LONG aiBusy;
bool PlannerScopeThread(U tid) {
    // The AI worker joins the scope only for generations that asked for the prepass hooks (census or the sibling's poly modes); the
    // default ai/profile stack keeps the worker on the original code (no clone chain, walk memo or site frames on it).
    const bool workerRoute=(config.ai_prepass_flags&(NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY_SHADOW|NTW2_AI_POLY))!=0;
    return walkScopeThread && (walkScopeThread==tid || (workerRoute && tid==aiThreadId && Load(&aiBusy)));
}
// The PS_* observer chain's sibling rule: the same scope, but the worker also joins for the --ai-spiral-* bits (the planner's R2 walk
// routing via PlannerScopeThread stays unchanged for them).
bool PsScopeThread(U tid) {
    const bool workerRoute=(config.ai_prepass_flags&(NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY_SHADOW|NTW2_AI_POLY|NTW2_AI_SPIRAL_BITS))!=0 ||
                           (config.ai_ctrl_flags&NTW2_AI_CLAIM_BITS)!=0; // --ai-claim-once[-census]: the claim loop runs inside the worker's site-34 scope
    return walkScopeThread && (walkScopeThread==tid || (workerRoute && tid==aiThreadId && Load(&aiBusy)));
}
void BeginWalkScope(U planner) {
    if (walkScopeDepth++) return;
    walksInScope=0;
    walkScopeThread=GetCurrentThreadId();
    ntw2_walk_memo::begin();
    ntw2_prepass::ScopeBegin(planner);
}
void EndWalkScope(U us) {
    if (--walkScopeDepth) return;
    ntw2_walk_memo::end();
    ntw2_prepass::ScopeEnd(us);
    walkScopeThread=0;
    ++plannerWalkWords[0];
    if (walksInScope>plannerWalkWords[10]) plannerWalkWords[10]=walksInScope;
}
// This process-wide slot is a bridge only: unrelated threads/scopes stay native.
// NTW2_AI_ASYNC2: the AI worker inside a think enters its private walk family instead (Ai2WalkEntry); every entry is
// classified into the route matrix (ntw2_ai_async2::NoteGate, slot SlotWalk).
bool Ai2WalkRouted(U tid);
U Ai2WalkEntry();
extern volatile LONG ai2Armed;
extern "C" U __stdcall WalkStateRoute() {
    const U tid=GetCurrentThreadId();
    const bool routed=Ai2WalkRouted(tid);
    if (Load(&ai2Armed)) ntw2_ai_async2::NoteGate(ntw2_ai_async2::SlotWalk,routed);
    if (routed) return Ai2WalkEntry();
    return PlannerScopeThread(tid) ? clones.entries[NTW2_CLONE_AI_STATE_UPDATE] : V(0x702bb0);
}
__declspec(naked) void WalkStateGate() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call WalkStateRoute
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
U Micro(LONGLONG a, LONGLONG b);
void SiteExit();
bool Epoch(U feature);
// Pair-level collision census requires explicit --collide-census plus the PROFILE tick epoch.
// Accumulate raw QPC ticks before converting: per-contact durations are commonly below one microsecond.
volatile U collisionWords[NTW2_COLLISION_WORDS];
LONGLONG collisionQpc[6]; // stage, numeric region, callbacks, query, append, oriented-radius helper
LARGE_INTEGER collisionNumericStart;
bool collisionNumericActive;
U collisionCensusEnabled;
bool CollisionCensus() { return collisionCensusEnabled && Epoch(NTW2_PROFILE); }
extern "C" void __stdcall CollisionNumericBegin() {
    ++collisionWords[20];
    collisionNumericActive=true;
    QueryPerformanceCounter(&collisionNumericStart);
}
extern "C" void __stdcall CollisionNumericEnd() {
    if (!collisionNumericActive) return;
    LARGE_INTEGER end; QueryPerformanceCounter(&end);
    collisionQpc[1]+=end.QuadPart-collisionNumericStart.QuadPart;
    collisionNumericActive=false;
}
#define COLLISION_MARKER(name, offset) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm cmp dword ptr [collisionCensusEnabled], 0 \
        __asm je marker_done \
        __asm test dword ptr [epochMask], 0x20 \
        __asm jz marker_done \
        __asm inc dword ptr [collisionWords + offset] \
        __asm marker_done: \
        __asm popfd \
        __asm ret \
    }
COLLISION_MARKER(CollisionReuse, 8)
COLLISION_MARKER(CollisionRebuild, 12)
COLLISION_MARKER(CollisionAccept, 24)
#undef COLLISION_MARKER
// This seam executes once after the four redistribution writes, before either label store.
// An unequal pair changes exactly one label; equal pairs still perform both native stores.
__declspec(naked) void CollisionLabel() {
    __asm pushfd
    __asm push eax
    __asm inc dword ptr [collisionWords + 28]
    __asm inc dword ptr [collisionWords + 32]
    __asm mov eax, dword ptr [edi + 0x88]
    __asm cmp eax, dword ptr [esi + 0x58]
    __asm je equal_labels
    __asm inc dword ptr [collisionWords + 36]
equal_labels:
    __asm pop eax
    __asm popfd
    __asm ret
}
#define COLLISION_FP_MARKER(name, target) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm call target \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm ret \
    }
COLLISION_FP_MARKER(CollisionNumericBeginGate, CollisionNumericBegin)
COLLISION_FP_MARKER(CollisionNumericEndGate, CollisionNumericEnd)
#undef COLLISION_FP_MARKER
void CollideLodPrepare(void* manager);
U __fastcall CollisionStageGate(void* manager) {
    if (Epoch(NTW2_COLLIDE) && !(static_cast<U>(Load(&budgetDisabledMask))&NTW2_COLLIDE))
        return ntw2_collide::Stage(manager);
    if (Epoch(NTW2_COLLIDE_LOD)) CollideLodPrepare(manager);
    return reinterpret_cast<Manager>((Epoch(NTW2_PROFILE) || Epoch(NTW2_COLLIDE_LOD)) ? clones.entries[NTW2_CLONE_SOFT_ACTIVE] : V(0x57dc30))(manager);
}
// Timed site 13: the ACTIVE clone's call of the army movement loop 0x531AF0 (ECX = manager, plain ret; the result is unused by the caller).
// Only the tick-owner thread inside a LOCO epoch enters the module; every other caller, tick or generation runs the original loop.
U __fastcall LocoMoveGate(void* manager) {
    if (Epoch(NTW2_LOCO) && !(static_cast<U>(Load(&budgetDisabledMask))&NTW2_LOCO))
        return ntw2_loco::Stage(manager);
    return reinterpret_cast<Manager>(V(0x531af0))(manager);
}
static_assert(ntw2_army_unit::kWords==NTW2_ARMY_UNIT_WORDS, "army unit status word contract");
static_assert(ntw2_army_unit::kB0Words==NTW2_ARMY_B0_WORDS, "army B0 status word contract");
static_assert(ntw2_army_storm::kWords==NTW2_ARMY_STORM_WORDS, "army storm status word contract");
static_assert(ntw2_army_solver::kWords==NTW2_ARMY_SOLVER_WORDS, "army solver status word contract");
// --army-storm-census gate: the tick owner inside a routed epoch with the census bit (the bit is feature-independent, so it is not
// part of epochMask).
bool StormEpoch() { return (config.va_watch_flags&NTW2_ARMY_STORM_CENSUS)!=0 && Epoch(kRouted); }
// --army-solver-memo/-shadow gate: the tick owner inside a routed epoch with either solver bit and a started module.
bool SolverEpoch() { return (config.va_watch_flags&(NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW))!=0 && ntw2_army_solver::Started() && Epoch(kRouted); }
static_assert(ntw2_brain_s0::kWords==NTW2_BRAIN_S0_WORDS, "brain S0 status word contract");
static_assert(ntw2_brain_locality::kWords==NTW2_BRAIN_S0_WORDS && NTW2_BRAIN_LOC_WORDS==NTW2_BRAIN_S0_WORDS,
              "brain locality census reuses the S0 status row");
static_assert(ntw2_unit_policy::kWords==NTW2_BRAIN_UNIT_POLICY_WORDS && ntw2_unit_policy::kHeaderWords==32 &&
              ntw2_unit_policy::kFatigueBase==ntw2_unit_policy::kHeaderWords &&
              ntw2_unit_policy::kFatigueBase+ntw2_unit_fatigue::kWords==ntw2_unit_policy::kPolicyBase &&
              ntw2_unit_policy::kPolicyBase+ntw2_unit_posture_engage::kWords==ntw2_unit_policy::kWords &&
              ntw2_unit_fatigue::kWords==ntw2_unit_policy::kFatigueWords &&
              ntw2_unit_posture_engage::kWords==ntw2_unit_policy::kPolicyWords,
              "brain unit policy status word contract (header 0..31, fatigue 32..127, posture/engage 128..255)");
// NTW2_ARMY_UNIT_SHADOW (item 4 Stage A + B0): site 18 (ARMY clone's call of the ARMY_UPDATE clone, ECX = container) and
// sites 101/103 (that clone's calls of 0x581F30, ECX = unit). Only the tick owner inside an epoch with the feature
// enters the module; the unit update always runs exactly once and its EAX is returned. Inside the epoch it runs as the
// ARMY_UNIT clone (instruction-identical to 0x581F30 except its FSM update call 58202E, bound to ArmyFsmGate: B0).
U __fastcall ArmyStageGate(void* container) {
    const auto native=reinterpret_cast<ntw2_army_unit::Native>(clones.entries[NTW2_CLONE_ARMY_UPDATE]);
    return Epoch(NTW2_ARMY_UNIT_SHADOW) ? ntw2_army_unit::Stage(container,world.model,native) : native(container);
}
U __fastcall ArmyUnitGateMain(void* unit) {
    if (!Epoch(NTW2_ARMY_UNIT_SHADOW)) return reinterpret_cast<ntw2_army_unit::Native>(V(0x581f30))(unit);
    return ntw2_army_unit::Unit(unit,0,reinterpret_cast<ntw2_army_unit::Native>(clones.entries[NTW2_CLONE_ARMY_UNIT]));
}
U __fastcall ArmyUnitGateAlternate(void* unit) {
    if (!Epoch(NTW2_ARMY_UNIT_SHADOW)) return reinterpret_cast<ntw2_army_unit::Native>(V(0x581f30))(unit);
    return ntw2_army_unit::Unit(unit,1,reinterpret_cast<ntw2_army_unit::Native>(clones.entries[NTW2_CLONE_ARMY_UNIT]));
}
// ARMY_UNIT's call 58202E of 0x582530 (ECX = S = U+D68, no stack argument, plain return, AL result; EAX/ECX/EDX are
// caller-saved there). Forwards the original exactly once; the module only reads S around it.
U __fastcall ArmyFsmGate(void* fsm) {
    const auto native=reinterpret_cast<ntw2_army_unit::Native>(V(0x582530));
    if (Epoch(NTW2_ARMY_UNIT_SHADOW)) return ntw2_army_unit::Fsm(fsm,native);
    return StormEpoch() ? ntw2_army_storm::Call(ntw2_army_storm::BFsm,fsm,reinterpret_cast<ntw2_army_storm::Native>(native)) : native(fsm);
}
// --army-storm-census (src/army/native_army_storm.h): sites 101/103 enter the census on the tick owner inside a routed epoch, which
// runs the unit as the ARMY_UNIT clone; its preparation (581FFB -> 57F070) and formation update (5820DE -> 585D50) calls reach
// the inclusive brackets below (ECX = U, no stack argument, plain return). Outside the epoch every gate runs the original.
U __fastcall StormUnitGateMain(void* unit) {
    if (!StormEpoch()) return reinterpret_cast<ntw2_army_storm::Native>(V(0x581f30))(unit);
    return ntw2_army_storm::Unit(unit,siteThis[2],reinterpret_cast<ntw2_army_storm::Native>(clones.entries[NTW2_CLONE_ARMY_UNIT]));
}
U __fastcall StormUnitGateAlternate(void* unit) {
    if (!StormEpoch()) return reinterpret_cast<ntw2_army_storm::Native>(V(0x581f30))(unit);
    return ntw2_army_storm::Unit(unit,siteThis[2],reinterpret_cast<ntw2_army_storm::Native>(clones.entries[NTW2_CLONE_ARMY_UNIT]));
}
U __fastcall ArmyPrepGate(void* unit) {
    const auto native=reinterpret_cast<ntw2_army_storm::Native>(V(0x57f070));
    return StormEpoch() ? ntw2_army_storm::Call(ntw2_army_storm::BPrep,unit,native) : native(unit);
}
U __fastcall ArmyFormationGate(void* unit) {
    const auto native=reinterpret_cast<ntw2_army_storm::Native>(V(0x585d50));
    return StormEpoch() ? ntw2_army_storm::Call(ntw2_army_storm::BFormation,unit,native) : native(unit);
}
// R2 (slot 0x1325474, 0x581AE0: ECX = command C, plain ret) and R1 (slot 0x1331E74, 0x617510: ECX = state, one stack argument, ret 4).
// --army-solver-memo/-shadow: on the tick owner inside a routed epoch the same gates enter the dedicated SOLVER clone of the target instead
// of the original (same ABI), so its flag=1 solves reach ntw2_army_solver::SolveGate; the census (when also on) brackets whichever target runs.
U __fastcall StormRoute2Gate(void* command) {
    const bool solver=SolverEpoch();
    const auto native=reinterpret_cast<ntw2_army_storm::Native>(solver ? clones.entries[NTW2_CLONE_SOLVER_581AE0] : V(0x581ae0));
    if (solver) ntw2_army_solver::NoteRoute(ntw2_army_solver::RouteR2);
    return StormEpoch() ? ntw2_army_storm::Route2(command,native) : native(command);
}
U __fastcall StormRoute1Gate(void* state, void* edx, U arg) {
    const bool solver=SolverEpoch();
    const auto native=reinterpret_cast<ntw2_army_storm::Native3>(solver ? clones.entries[NTW2_CLONE_SOLVER_617510] : V(0x617510));
    if (solver) ntw2_army_solver::NoteRoute(ntw2_army_solver::RouteR1);
    return StormEpoch() ? ntw2_army_storm::Route1(state,edx,arg,native) : native(state,edx,arg);
}
// Second R1 state-enter (slot 0x1332110, 0x611CF0: ECX unused, one stack argument, ret 4): 611CF0 is `ecx = arg ? arg-0x1C : 0; call 65D7D0;
// ret 4` ([proven by disasm], pinned by the generator), so the gate performs that arithmetic and enters the SOLVER_65D7D0 clone (thiscall,
// plain ret, EAX returned unchanged). Only installed with a solver bit; outside a solver epoch it runs the original.
U __fastcall SolverRoute1bGate(void* state, void* edx, U arg) {
    if (!SolverEpoch()) return reinterpret_cast<ntw2_army_storm::Native3>(V(0x611cf0))(state,edx,arg);
    ntw2_army_solver::NoteRoute(ntw2_army_solver::RouteR1b);
    return reinterpret_cast<ntw2_army_storm::Native>(clones.entries[NTW2_CLONE_SOLVER_65D7D0])(reinterpret_cast<void*>(arg ? arg-0x1c : 0));
}
__declspec(naked) void CollisionSlot44() {
    __asm mov eax, dword ptr [ecx]
    __asm jmp dword ptr [eax + 0x44]
}
extern "C" __declspec(noinline) void __stdcall EnterSite(U site, U* returnSlot, U ecx) {
    // Brain sites live in clones/slots that also run on ticks and threads this runtime does not own: untimed pass-through there.
    if (site>=kBrainFirst && site<kBrainFirst+NTW2_BRAIN_SITES && !Epoch(NTW2_BRAIN)) return;
    if (site>=106 && site<=109 && !CollisionCensus()) return;
    if (site==40) { ++plannerWalkWords[1]; ++walksInScope; }
    if (siteDepth==64) {
        if (site>=106 && site<=109) ++collisionWords[23];
        return; // Plain tail jump, no matching exit; census explicitly reports this gap.
    }
    if (site==34) BeginWalkScope(ecx);
    SiteFrame& frame=siteStack[siteDepth++];
    frame.site=site;
    frame.returnAddress=*returnSlot;
    frame.outputList=(site==41 || site==44 || site==106) ? returnSlot[1] : 0; // 44: the polygon argument of the 0x80DCF0 predicate (census V)
    siteThis[site]=ecx;
    frame.family=brainFamily;
    if (site<kBrainFirst+kBrainEntries && site>=kBrainFirst) brainFamily=site-kBrainFirst;
    if (site==5 && CollisionCensus() && !Epoch(NTW2_COLLIDE)) ++collisionWords[21];
    if (site==106) ++collisionWords[1];
    if (site==109) {
        ++collisionWords[10];
        const U target=WordOrZero(WordOrZero(ecx)+0x44);
        if (target==V(0x64cc70)) {
            const U otherTarget=WordOrZero(WordOrZero(returnSlot[1])+0x40);
            ++collisionWords[otherTarget==V(0x64cad0) ? 11 : 24];
        } else ++collisionWords[target==V(0x808ef0) ? 12 : 25];
    }
    if (BrainCoreSite(site)) BrainStateEnter(frame,ecx);
    if (site+1==siteGateIndex && !siteGateDepth++) {
        if (ntw2_profile_storm_threshold_ms) { // --army-storm-sample-ms: entry QPC is published before the gate word
            LARGE_INTEGER entry;
            QueryPerformanceCounter(&entry);
            ntw2_profile_storm_entry(static_cast<uint64_t>(entry.QuadPart));
        }
        siteInProgress=GetCurrentThreadId();
    }
    // In-place pop/push of the return slot; stack arguments never move.
    if ((config.enabled_mask&(NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) || (config.loco_flags&NTW2_LOCO_GRID_PROBATION)) ntw2_grid_census_site=site+1;
    *returnSlot=FnAddress(&SiteExit);
    // Census (observation only): the covered walk's key is read before its frame timer starts.
    if (site==40) ntw2_prepass::WalkBegin(ecx,returnSlot[1],frame.returnAddress,0);
    QueryPerformanceCounter(&frame.start);
    CoreSample(frame.start.QuadPart); // tick core census (trace flags): the class sample costs one processor-number read
    if (site==6) { coreCensus.inSite6=true; brainScopeTid=GetCurrentThreadId(); }
}
extern "C" __declspec(noinline) U __stdcall LeaveSite(U eax) { // EAX of the exiting callee (SiteExit passes its saved EAX)
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    const SiteFrame& frame=siteStack[--siteDepth];
    CoreSample(end.QuadPart);
    if (frame.site==6) { coreCensus.inSite6=false; brainScopeTid=0; }
    if ((config.enabled_mask&(NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) || (config.loco_flags&NTW2_LOCO_GRID_PROBATION))
        ntw2_grid_census_site=siteDepth ? siteStack[siteDepth-1].site+1 : 0;
    const U us=Micro(frame.start.QuadPart,end.QuadPart);
    if (BrainCoreSite(frame.site)) BrainStateLeave(frame);
    siteUs[frame.site]+=us; siteLastUs[frame.site]=us;
    const LONGLONG elapsed=end.QuadPart-frame.start.QuadPart;
    if (frame.site==5 && CollisionCensus() && !Epoch(NTW2_COLLIDE)) {
        collisionQpc[0]+=elapsed;
        collisionWords[13]=Micro(0,collisionQpc[0]);
        collisionWords[15]=Micro(0,collisionQpc[1]);
        collisionWords[16]=Micro(0,collisionQpc[2]);
        collisionWords[14]=Micro(0,collisionQpc[0]-collisionQpc[1]-collisionQpc[2]);
        for (U i=3;i<6;++i) collisionWords[14+i]=Micro(0,collisionQpc[i]);
    }
    if (frame.site==106) {
        collisionQpc[3]+=elapsed;
        const U count=WordOrZero(frame.outputList+0x200c);
        collisionWords[4]+=count;
        if (count>collisionWords[22]) collisionWords[22]=count;
    }
    if (frame.site==107) { ++collisionWords[5]; collisionQpc[4]+=elapsed; }
    if (frame.site==108) { ++collisionWords[26]; collisionQpc[5]+=elapsed; }
    if (frame.site==109) collisionQpc[2]+=elapsed;
    ++siteCalls[frame.site];
    if (frame.site>=kBrainFirst && frame.site<kBrainFirst+NTW2_BRAIN_SITES) {
        const U family=BrainOwner(frame.site);
        if (family<kBrainEntries) {
            volatile U* w=brainWords+NTW2_BRAIN_HEADER_WORDS+2*(family*NTW2_BRAIN_SITES+(frame.site-kBrainFirst));
            w[0]+=us; ++w[1];
        }
        if (frame.site<kBrainFirst+kBrainEntries) brainFamily=frame.family;
    }
    if (frame.site==6 && (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX))) ntw2_alloc_census::ReclaimTick(world.model);
    if (frame.site==34) EndWalkScope(us);
    if (frame.site==40) { plannerWalkWords[7]+=us; ntw2_prepass::WalkEnd(eax,elapsed,end.QuadPart); }
    if (frame.site==41) {
        ntw2_prepass::WalkGathered(frame.outputList,elapsed,end.QuadPart);
        ++plannerWalkWords[2]; plannerWalkWords[8]+=us;
        const U count=WordOrZero(frame.outputList+8);
        plannerWalkWords[5]+=count;
        if (count>plannerWalkWords[15]) plannerWalkWords[15]=count;
    }
    if (frame.site==42) {
        const U count=WordOrZero(V(0x15bbf54));
        plannerWalkWords[3]+=count;
        if (count>plannerWalkWords[4]) plannerWalkWords[4]=count;
    }
    if (frame.site==43) ++plannerWalkWords[6];
    if (frame.site==44 || frame.site==45) { ++plannerWalkWords[11]; plannerWalkWords[9]+=us; ntw2_prepass::WalkPolygon(frame.site==44 ? frame.outputList : 0,eax,elapsed); }
    if (frame.site+1==siteGateIndex && siteGateDepth && !--siteGateDepth) siteInProgress=0;
    return frame.returnAddress;
}
// ESP here is the callee's POST-cleanup ESP: stdcall/thiscall have already
// removed their arguments; cdecl arguments remain for the original caller.
// Reserve a return slot and aligned temporary FP save area; preserve GPRs
// (including EAX/EDX), EFLAGS and x87/SSE results before returning to the caller.
__declspec(naked) void SiteExit() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm push dword ptr [ebp+28]
    __asm call LeaveSite
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
// pushfd + pushad place the original return slot at ESP+36. Replacing that
// slot is equivalent to popping the caller's address and pushing SiteExit,
// without disturbing registers/flags or thiscall/stdcall/cdecl argument layout.
// pushad layout at ESP0: EDI ESI EBP ESP EBX EDX ECX(+24) EAX(+28); the return slot is at ESP0+36.
// Host key copies/comparisons may use SSE: preserve the complete x87/SSE state
// around EnterSite as well as GPRs/EFLAGS, including callers' FP control modes.
#define SITE_THUNK(index, offset) \
    __declspec(naked) void SiteCall##index() { \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm lea eax, [ebp+36] \
        __asm push dword ptr [ebp+24] \
        __asm push eax \
        __asm push index \
        __asm call EnterSite \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [siteCallees + offset] \
    }
SITE_THUNK(0, 0)
SITE_THUNK(1, 4)
SITE_THUNK(2, 8)
SITE_THUNK(3, 12)
SITE_THUNK(4, 16)
SITE_THUNK(5, 20)
SITE_THUNK(6, 24)
SITE_THUNK(7, 28)
SITE_THUNK(8, 32)
SITE_THUNK(9, 36)
SITE_THUNK(10, 40)
SITE_THUNK(11, 44)
SITE_THUNK(12, 48)
SITE_THUNK(13, 52)
SITE_THUNK(14, 56)
SITE_THUNK(15, 60)
SITE_THUNK(16, 64)
SITE_THUNK(17, 68)
SITE_THUNK(18, 72)
SITE_THUNK(19, 76)
SITE_THUNK(20, 80)
SITE_THUNK(21, 84)
SITE_THUNK(22, 88)
SITE_THUNK(23, 92)
SITE_THUNK(24, 96)
SITE_THUNK(25, 100)
SITE_THUNK(26, 104)
SITE_THUNK(27, 108)
SITE_THUNK(28, 112)
SITE_THUNK(29, 116)
SITE_THUNK(30, 120)
SITE_THUNK(31, 124)
SITE_THUNK(32, 128)
SITE_THUNK(33, 132)
SITE_THUNK(34, 136)
SITE_THUNK(35, 140)
SITE_THUNK(36, 144)
SITE_THUNK(37, 148)
SITE_THUNK(38, 152)
SITE_THUNK(39, 156)
SITE_THUNK(40, 160)
SITE_THUNK(41, 164)
SITE_THUNK(42, 168)
SITE_THUNK(43, 172)
SITE_THUNK(44, 176)
SITE_THUNK(45, 180)
SITE_THUNK(46, 184)
SITE_THUNK(47, 188)
SITE_THUNK(48, 192)
SITE_THUNK(49, 196)
SITE_THUNK(50, 200)
SITE_THUNK(51, 204)
SITE_THUNK(52, 208)
SITE_THUNK(53, 212)
SITE_THUNK(54, 216)
SITE_THUNK(55, 220)
SITE_THUNK(56, 224)
SITE_THUNK(57, 228)
SITE_THUNK(58, 232)
SITE_THUNK(59, 236)
SITE_THUNK(60, 240)
SITE_THUNK(61, 244)
SITE_THUNK(62, 248)
SITE_THUNK(63, 252)
SITE_THUNK(64, 256)
SITE_THUNK(65, 260)
SITE_THUNK(66, 264)
SITE_THUNK(67, 268)
SITE_THUNK(68, 272)
SITE_THUNK(69, 276)
SITE_THUNK(70, 280)
SITE_THUNK(71, 284)
SITE_THUNK(72, 288)
SITE_THUNK(73, 292)
SITE_THUNK(74, 296)
SITE_THUNK(75, 300)
SITE_THUNK(76, 304)
SITE_THUNK(77, 308)
SITE_THUNK(78, 312)
SITE_THUNK(79, 316)
SITE_THUNK(80, 320)
SITE_THUNK(81, 324)
SITE_THUNK(82, 328)
SITE_THUNK(83, 332)
SITE_THUNK(84, 336)
SITE_THUNK(85, 340)
SITE_THUNK(86, 344)
SITE_THUNK(87, 348)
SITE_THUNK(88, 352)
SITE_THUNK(89, 356)
SITE_THUNK(90, 360)
SITE_THUNK(91, 364)
SITE_THUNK(92, 368)
SITE_THUNK(93, 372)
SITE_THUNK(94, 376)
SITE_THUNK(95, 380)
SITE_THUNK(96, 384)
SITE_THUNK(97, 388)
SITE_THUNK(98, 392)
SITE_THUNK(99, 396)
SITE_THUNK(100, 400)
SITE_THUNK(101, 404)
SITE_THUNK(102, 408)
SITE_THUNK(103, 412)
SITE_THUNK(104, 416)
SITE_THUNK(105, 420)
SITE_THUNK(106, 424)
SITE_THUNK(107, 428)
SITE_THUNK(108, 432)
SITE_THUNK(109, 436)
#undef SITE_THUNK
// The brain clone replaces `mov ecx,edi; call [eax+disp]` by `mov ecx,edi; call SiteCall; nop`. The site's callee is one of these
// trampolines: it loads the entity's vtable from ECX and tail-jumps through the same slot, so the callee sees the original
// register/stack state (ECX = entity, stack arguments and return address untouched; EAX is a scratch the callee ignores).
__declspec(naked) void VirtualSlot1A8() {
    __asm mov eax, dword ptr [ecx]
    __asm jmp dword ptr [eax + 0x1A8]
}
__declspec(naked) void VirtualSlot108() {
    __asm mov eax, dword ptr [ecx]
    __asm jmp dword ptr [eax + 0x108]
}
LONGLONG qpcFreq;
U Micro(LONGLONG a, LONGLONG b) {
    if (!qpcFreq) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); qpcFreq=f.QuadPart; }
    return static_cast<U>((b-a)*1000000/qpcFreq);
}
// AI planner attribution: site 34 (0x7D99F0) runs cheap passes over every planner object then ONE round-robin heavy
// think ([this+0xB8] % [this+0x9C] after the increment). Attribute the site's duration to that object's vtable.
// Words: 4 per row {vtable, sum us, calls, max us}, 16 rows; row 0 unused when no planner was seen.
constexpr U kPlannerSite=34;
volatile U plannerWords[64];
void AttributePlanner() {
    if (!siteCalls[kPlannerSite]) return;
    const U self=siteThis[kPlannerSite];
    U count=0, list=0, counter=0, object=0, vtable=0;
    if (!Word(self+0x9c,count) || !count || !Word(self+0xa0,list) || !Word(self+0xb8,counter) ||
        !Word(list+4*(counter%count),object) || !object || !Word(object,vtable)) return;
    const U us=siteLastUs[kPlannerSite];
    for (U row=0; row<16; ++row) {
        volatile U* w=plannerWords+4*row;
        if (w[0]==vtable || !w[0]) {
            w[0]=vtable; w[1]+=us; ++w[2]; if (us>w[3]) w[3]=us;
            return;
        }
    }
}
void TraceTick(ntw2_trace_entry& e, U tick, U tid, U duration, U interval, bool routed, LONGLONG start) {
    e.tick=tick; e.duration_us=duration; e.interval_us=interval; e.manager_us=phaseUs[0]; e.ballistics_us=phaseUs[1];
    e.path_us=phaseUs[2]; e.thread_id=tid; e.flags=routed ? 3u : 0u;
    e.qpc_start_lo=static_cast<U>(start); e.qpc_start_hi=static_cast<U>(static_cast<uint64_t>(start)>>32);
    e.qpc_end_lo=e.qpc_end_hi=0;
    for (U i=0;i<NTW2_TRACE_SITES;++i) {
        e.site_us[i]=routed ? siteUs[i] : 0;
        e.site_calls[i]=routed ? siteCalls[i] : 0;
        if (e.site_calls[i]) e.flags|=4u;
    }
    if (routed && (config.enabled_mask & NTW2_BRAIN)) {
        ++brainWords[0]; brainWords[1]+=duration; ++brainStateWords[0];
    }
    if (routed && collisionCensusEnabled && (config.enabled_mask & NTW2_PROFILE) && !(config.enabled_mask & NTW2_COLLIDE)) ++collisionWords[0];
    if (routed && !(config.enabled_mask & NTW2_AI_ASYNC)) AttributePlanner(); // with the async think, site 34 no longer contains it
    if (routed && (config.va_watch_flags & NTW2_ARMY_STORM_CENSUS)) { // slots 110/111 are not timed sites: four census words
        U census[4];
        ntw2_army_storm::TickEnd(e.tick,siteUs[18],siteUs[34],census);
        e.site_us[110]=census[0]; e.site_calls[110]=census[1]; e.site_us[111]=census[2]; e.site_calls[111]=census[3];
    }
    if (routed && (config.va_watch_flags & (NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW))) ntw2_army_solver::TickEnd(e.tick); // closes the solver's per-tick table with the same tick id
}
void PublishTrace(ntw2_trace_entry& e, LONGLONG end) {
    e.qpc_end_lo=static_cast<U>(end); e.qpc_end_hi=static_cast<U>(static_cast<uint64_t>(end)>>32);
    ntw2_trace.qpc_freq_lo=static_cast<U>(qpcFreq);
    ntw2_trace.qpc_freq_hi=static_cast<U>(static_cast<uint64_t>(qpcFreq)>>32);
    // Publish only after the tick body and final hold cleanup have completed.
    ntw2_trace.ring[ntw2_trace.head]=e;
    ntw2_trace.head=(ntw2_trace.head+1)%NTW2_TRACE_ENTRIES;
    ++ntw2_trace.written;
}
bool Epoch(U feature);
// ===================================================================================================================
// A single event-driven AI job belongs to the CURRENT tick. Native frames are never suspended,
// abandoned, or carried to another tick. The owner joins before site 34 returns to the native controller.
// The engine's flag is a full-walk boolean, not a time budget; its round-robin node can take arbitrarily
// long. No copied subordinate graph or top-level pointer check can make a suspended native stack safe.
enum AiJobKind : U { AiPlanner, AiController, AiPlannerAsync };
struct AiJob { U planner, method, flag, fpuControl, mxcsr, tlsEpoch, tlsValid, kind; };
volatile U aiWords[16], aiExtra[32], aiCtrlWords[16], aiParkWords[8], aiValidationWords[8];
enum AiSliceWord : U { AsSlices, AsUs, AsTimeouts, AsSpanning, AsMaxSlices, AsCancelled, AsParked, AsThread };
volatile U aiSliceWords[8], aiSliceSiteWords[2], aiBudgetWords[NTW2_AI_SLICE_BUDGET_WORDS];
volatile U aiCompletionWords[NTW2_AI_COMPLETION_WORDS];
enum AiCompletionWord : U { AtThinkCount, AtThinkUs, AtThinkMaxUs, AtBarrierCount, AtBarrierUs, AtBarrierMaxUs,
                            AtThinkHistogram, AtBarrierHistogram=AtThinkHistogram+9 };
static_assert(AtBarrierHistogram+9==NTW2_AI_COMPLETION_WORDS,"AI completion histogram layout");
volatile U aiThreadId;
volatile LONG aiBusy, aiRunning, aiInThink, aiStop;
HANDLE aiThread, aiWake, aiDone;
AiJob aiJob;
bool aiPending; // tick-owner only: a published job has not yet been joined, even if it already completed
U aiPlannerClone, aiControllerOriginal;

U AiFpuControl() {
    unsigned short control=0;
    __asm { fnstcw control }
    return control;
}
U AiPreferred(U address) { return (address>=imageBase && address-imageBase<imageSize) ? address-imageBase+kPreferred : address; }
// This thread's MSVC thread-safe-static epoch slot ([TLS block of the exe]+8), 0 when unavailable.
U AiTlsSlot() {
    U index=0, block=0;
    const U array=static_cast<U>(__readfsdword(0x2C));
    if (!array || !Word(V(0x1841bb8),index) || index>0x10000 || !Word(array+4*index,block) || !block) return 0;
    return block+8;
}
LONG AllocatorCapture(EXCEPTION_POINTERS* info,U* row) {
    const EXCEPTION_RECORD* record=info->ExceptionRecord;
    row[4]=record->ExceptionCode;
    row[5]=AiPreferred(Address(record->ExceptionAddress));
    if ((record->ExceptionCode==EXCEPTION_ACCESS_VIOLATION || record->ExceptionCode==EXCEPTION_IN_PAGE_ERROR) &&
        record->NumberParameters>=2) row[6]=static_cast<U>(record->ExceptionInformation[1]);
    return EXCEPTION_EXECUTE_HANDLER;
}
// FF7F20's TLS access is the executable CRT static epoch, NOT a TLS allocator:
// [1763C54] is a static guard; the allocator is its explicit second argument.
// Use the ordinary engine allocation path to run its lazy initialization on this thread,
// then free through the page-owner lookup. Do not manufacture an arena or copy another thread's TLS.
U __stdcall WorkerAllocatorInit(U, U workerIndex) {
    U* row=allocatorWords+workerIndex*NTW2_ALLOCATOR_ROW_WORDS;
    for (U i=0;i<NTW2_ALLOCATOR_ROW_WORDS;++i) row[i]=0;
    row[1]=GetCurrentThreadId();
    if (workerIndex<NTW_POOL_MAX_WORKERS) visualArenaIndex=workerIndex+1;
    U result=2, stage=2;
    ++ntw2::probeDepth; // startup failures are admission failures, not gameplay crash captures
    __try {
        const U slot=AiTlsSlot();
        if (slot && Word(V(0x1841bb8),row[7]) && Word(slot,row[2])) {
            stage=3; // includes FF7F20's normal lazy initialization
            void* allocation=reinterpret_cast<void* (__cdecl*)(U)>(V(0x444b40))(16);
            if (!allocation) result=4;
            else {
                stage=5;
                reinterpret_cast<void (__cdecl*)(void*)>(V(0xff7ef0))(allocation);
                result=1;
            }
            Word(slot,row[3]);
        }
    } __except(AllocatorCapture(GetExceptionInformation(),row)) {
        result=stage|0x100u;
    }
    --ntw2::probeDepth;
    _InterlockedExchange(reinterpret_cast<volatile LONG*>(row),static_cast<LONG>(result));
    return result==1 ? 0 : result;
}
void AiMirrorTlsEpoch(const AiJob& job) {
    if (!job.tlsValid) return;
    const U slot=AiTlsSlot();
    U own=0;
    if (slot && Word(slot,own) && static_cast<LONG>(job.tlsEpoch)>static_cast<LONG>(own))
        *reinterpret_cast<volatile U*>(slot)=job.tlsEpoch;
}
void AiHistogram(U first, U us) {
    U bucket=0, ceiling=8000;
    while (bucket<8 && us>ceiling) { ++bucket; ceiling*=2; }
    ++aiCompletionWords[first+bucket];
}
// Preserve the exact engine ABI: ECX=this, planner receives one unmodified full-walk flag.
// No SEH recovery or non-unwinding abort skips the engine's cleanup on a native fault.
void AiRunThink(const AiJob& job) {
    const unsigned short control=static_cast<unsigned short>(job.fpuControl);
    AiMirrorTlsEpoch(job);
    __asm {
        fninit
        fldcw control
    }
    _mm_setcsr(job.mxcsr);
    _InterlockedExchange(&aiInThink,1);
    if (job.kind==AiController)
        reinterpret_cast<void (__fastcall*)(void*,void*)>(job.method)(reinterpret_cast<void*>(job.planner),nullptr);
    else
        reinterpret_cast<void (__fastcall*)(void*,void*,U)>(job.method)(reinterpret_cast<void*>(job.planner),nullptr,job.flag);
    _InterlockedExchange(&aiInThink,0);
}
extern volatile LONG ai2Armed; // defined with the AI2 gates below; the worker reads it on every wake
void Ai2NoteScratch();         // AI worker: private-image witnesses after each async think
// Deferred slice bracket (AI worker): the same FPU entry state as AiRunThink, the think flag that routes the private
// walk/observer family, and the private-image witnesses after the slice.
void Ai2DeferEnter() {
    const unsigned short control=static_cast<unsigned short>(AiFpuControl());
    const U csr=_mm_getcsr();
    __asm {
        fninit
        fldcw control
    }
    _mm_setcsr(csr);
    _InterlockedExchange(&aiInThink,1);
}
void Ai2DeferLeave() { _InterlockedExchange(&aiInThink,0); Ai2NoteScratch(); }
DWORD WINAPI AiWorkerMain(void*) {
    aiThreadId=GetCurrentThreadId();
    const U startup=WorkerAllocatorInit(0,kAiAllocatorRow);
    SetEvent(aiDone);
    if (startup) return startup;
    for (;;) {
        if (WaitForSingleObject(aiWake,INFINITE)!=WAIT_OBJECT_0) return GetLastError();
        if (Load(&aiStop)) return 0;
        AiJob job=aiJob; // an async owner may publish the next job as soon as this one is released
        if (Load(&ai2Armed) && ntw2_ai_async2::Deferred()) { // deferred schedule: run the open count-budgeted slice
            while (ntw2_ai_async2::WorkerSlice(&Ai2DeferEnter,&Ai2DeferLeave)) {}
            if (!aiPending) { _InterlockedExchange(&aiBusy,0); continue; }
            job=aiJob; // a watchdog-fallback synchronous job uses the ordinary one-slot path below
        } else if (Load(&ai2Armed)) { // NTW2_AI_ASYNC2 boundary schedule: run every published whole call in FIFO order
            U planner=0, flag=0;
            while (ntw2_ai_async2::WorkerNext(&planner,&flag)) {
                AiJob next={planner,V(0x7D99F0),flag,AiFpuControl(),_mm_getcsr(),0,0,AiPlannerAsync};
                const U tls=AiTlsSlot();
                next.tlsValid=tls && Word(tls,next.tlsEpoch) ? 1u : 0u;
                ntw2_ai_async2::WorkerBegin();
                LARGE_INTEGER begin, finish;
                QueryPerformanceCounter(&begin);
                AiRunThink(next);
                QueryPerformanceCounter(&finish);
                Ai2NoteScratch();
                ntw2_ai_async2::WorkerEnd(Micro(begin.QuadPart,finish.QuadPart));
            }
            if (!aiPending) { _InterlockedExchange(&aiBusy,0); continue; }
            job=aiJob; // a watchdog-fallback synchronous job uses the ordinary one-slot path below
        }
        _InterlockedExchange(&aiRunning,1);
        LARGE_INTEGER begin, finish;
        QueryPerformanceCounter(&begin);
        AiRunThink(job);
        QueryPerformanceCounter(&finish);
        const U us=Micro(begin.QuadPart,finish.QuadPart);
        if (job.kind==AiController) {
            ++aiCtrlWords[1]; aiCtrlWords[4]+=us;
            if (us>aiCtrlWords[5]) aiCtrlWords[5]=us;
            aiCtrlWords[15]=0;
        } else {
            ++aiWords[1]; aiWords[7]+=us;
            if (us>aiWords[6]) aiWords[6]=us;
            ++aiCompletionWords[AtThinkCount]; aiCompletionWords[AtThinkUs]+=us;
            if (us>aiCompletionWords[AtThinkMaxUs]) aiCompletionWords[AtThinkMaxUs]=us;
            AiHistogram(AtThinkHistogram,us);
        }
        _InterlockedExchange(&aiRunning,0);
        _InterlockedExchange(&aiBusy,0);
        SetEvent(aiDone); // release all game frames and publish their writes before the owner continues
    }
}
// The owner must consume the completion event even if aiBusy already cleared; otherwise a new job
// could reset aiDone just before the previous job's SetEvent and mistake that stale event for completion.
void AiBarrier() {
    if (!aiPending) return;
    LARGE_INTEGER begin, finish;
    QueryPerformanceCounter(&begin);
    while (WaitForSingleObject(aiDone,INFINITE)!=WAIT_OBJECT_0) {
        ++aiWords[10];
        Sleep(1); // fail closed: a wait error is never permission to advance the world
    }
    aiPending=false;
    QueryPerformanceCounter(&finish);
    const U us=Micro(begin.QuadPart,finish.QuadPart);
    ++aiCompletionWords[AtBarrierCount]; aiCompletionWords[AtBarrierUs]+=us;
    if (us>aiCompletionWords[AtBarrierMaxUs]) aiCompletionWords[AtBarrierMaxUs]=us;
    AiHistogram(AtBarrierHistogram,us);
    aiSliceWords[AsUs]+=us;
}
bool AiDispatch(U object, U method, U flag, U kind) {
    AiBarrier(); // one slot; never replace, replay, or drop a previous native call
    aiJob={object,method,flag,AiFpuControl(),_mm_getcsr(),0,0,kind};
    const U tls=AiTlsSlot();
    aiJob.tlsValid=tls && Word(tls,aiJob.tlsEpoch) ? 1u : 0u;
    if (!ResetEvent(aiDone)) { ++aiWords[10]; return false; }
    aiPending=true;
    _InterlockedExchange(&aiBusy,1);
    if (kind==AiController) aiCtrlWords[15]=1;
    if (!SetEvent(aiWake)) {
        _InterlockedExchange(&aiBusy,0);
        if (kind==AiController) aiCtrlWords[15]=0;
        aiPending=false;
        ++aiWords[10];
        return false; // no worker was woken: the caller may execute the original exactly once
    }
    ++aiSliceWords[AsSlices]; aiSliceWords[AsMaxSlices]=1;
    if (kind==AiController) {
        ++aiCtrlWords[0]; aiCtrlWords[6]=1; ++aiCtrlWords[11];
    } else {
        ++aiWords[0]; ++aiExtra[11]; ++aiSliceSiteWords[0];
    }
    return true;
}
extern "C" __declspec(noinline) U __stdcall AiPlannerGate(U planner, U flag) {
    if (!aiThread || !Epoch(NTW2_AI_ASYNC)) return 0;
    if (!AiDispatch(planner,V(0x7D99F0),flag,AiPlanner)) return 0;
    // Site 35 immediately follows and invokes unit virtual/event callbacks whose
    // destruction closure is not proven. Join before ANY subsequent native phase.
    AiBarrier();
    return 1;
}
__declspec(naked) void PlannerGate() {
    __asm {
        push ecx
        push dword ptr [esp+8]
        push ecx
        call AiPlannerGate
        pop ecx
        test eax, eax
        jnz dispatched
        jmp dword ptr [aiPlannerClone]
    dispatched:
        ret 4
    }
}
extern "C" __declspec(noinline) U __stdcall AiControllerGate(U controller) {
    if (!aiThread || !Epoch(NTW2_AI_CTRL)) return 0;
    if (!AiDispatch(controller,aiControllerOriginal,0,AiController)) return 0;
    AiBarrier(); // controller rebuilds the planner arrays: join before the following planner call
    return 1;
}
__declspec(naked) void ControllerGate() {
    __asm {
        push ecx
        push ecx
        call AiControllerGate
        pop ecx
        test eax, eax
        jz original
        xor eax, eax
        ret
    original:
        jmp dword ptr [aiControllerOriginal]
    }
}
// ===================================================================================================================
// NTW2_AI_ASYNC2 (src/ai/ntw2_ai_async2.h): site 34 queues the whole planner call and returns; tick end publishes the batch;
// the worker runs it in the inter-tick window; the next tick start is the non-blocking effect seam; site 33, TICK 57DFDF
// and the tick-owner delegate gates are blocking structural joins.
volatile LONG ai2Armed; // generation has AI_ASYNC2; read by the TICK clone's quadtree gate before any other work
U ai2SpatialTarget, ai2ControllerTarget;
// Worker-private walk images (see ntw2_clones.h AI2_*_IMAGE), congruent mod 16 with the originals. Zero is the
// constructed state of the three vectors; the three search objects (walk images of 15AFBA8/15AFCA8, observer image of
// 150B5F8) are constructed by the engine's own 7E6C30 on the AI worker at its first private entry -- never at monitor
// activation, whose thread must not run the ctor's CRT allocation -- and live until process exit, like the clones.
__declspec(align(16)) uint8_t ai2WalkImage[0x220], ai2GatherImage[0x20], ai2LookupImage[0x20], ai2SpotImage[0x110];
constexpr U kAi2WalkBias=0x15AFBA8u&15u, kAi2GatherBias=0x15BBF4Cu&15u, kAi2LookupBias=0x14D0A6Cu&15u,
            kAi2SpotBias=0x150B5F8u&15u;
static_assert(kAi2WalkBias+(0x15AFDBCu-0x15AFBA8u)<=sizeof(ai2WalkImage) && kAi2SpotBias+0x100u<=sizeof(ai2SpotImage) &&
              kAi2GatherBias+0x14u<=sizeof(ai2GatherImage) && kAi2LookupBias+0x14u<=sizeof(ai2LookupImage),
              "AI2 images cover their generator ranges");
bool ai2ScratchReady; // worker only
bool Ai2WalkRouted(U tid) { return Load(&ai2Armed) && tid==aiThreadId && Load(&aiInThink); }
// AI worker only (Ai2WalkRouted): constructs the private search objects before the first private clone runs; the
// clones' static-init branches are NOPped, so this is their only construction.
void Ai2EnsureScratch() {
    if (!ai2ScratchReady) {
        const U base=Address(ai2WalkImage)+kAi2WalkBias;
        const auto construct=reinterpret_cast<U (__fastcall*)(U,U)>(V(0x7E6C30)); // thiscall, no stack argument
        construct(base,0);                          // image of search object 15AFBA8 (808040)
        construct(base+(0x15AFCA8u-0x15AFBA8u),0);  // image of search object 15AFCA8 (7FCA90)
        construct(Address(ai2SpotImage)+kAi2SpotBias,0); // image of search object 150B5F8 (6C71D0)
        ai2ScratchReady=true;
    }
    ntw2_ai_async2::NoteRoute(ai2ScratchReady);
}
U Ai2WalkEntry() {
    Ai2EnsureScratch();
    return clones.entries[NTW2_CLONE_AI2_STATE_UPDATE];
}
void Ai2NoteScratch() {
    const U walk=Address(ai2WalkImage)+kAi2WalkBias+(0x15AFDA8u-0x15AFBA8u);
    ntw2_ai_async2::NotePrivate(0,*reinterpret_cast<const U*>(Address(ai2LookupImage)+kAi2LookupBias+4));
    ntw2_ai_async2::NotePrivate(1,*reinterpret_cast<const U*>(Address(ai2GatherImage)+kAi2GatherBias+4));
    ntw2_ai_async2::NotePrivate(2,*reinterpret_cast<const U*>(walk+4));
    ntw2_ai_async2::NotePrivate(3,ai2ScratchReady ? 3u : 0u);
}
// Observer slot 16 of vtable 0x13376FC (0x133773C = 0x6A95A0, the LOS observer route of the triage): the AI worker
// inside a think enters AI2_6A95A0; every other caller (tick, main/render, worker outside a think) keeps the original.
extern "C" U __stdcall Ai2ObserverRoute() {
    const bool routed=Ai2WalkRouted(GetCurrentThreadId());
    ntw2_ai_async2::NoteGate(ntw2_ai_async2::SlotObserver,routed);
    if (!routed) return V(0x6A95A0);
    Ai2EnsureScratch();
    return clones.entries[NTW2_CLONE_AI2_6A95A0];
}
// Same transparent frame as WalkStateGate: registers, EFLAGS and x87/SSE state preserved; `ret` enters the target with
// the caller's exact stack (thiscall, ret 0xC).
__declspec(naked) void Ai2ObserverGate() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call Ai2ObserverRoute
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
// --ai-poly-shadow / --ai-poly (and the census' observer route): the SAME observer slot 16 of 0x13376FC, but routed to pure-retarget PS_* clones
// that run on the ORIGINAL scratch, only inside a site-34 scope on the executing thread (PsScopeThread: tick thread without `ai`,
// the AI worker under `ai`). Everyone else, including main/render, keeps the original. Excludes AI_ASYNC2, which owns the same slot.
U psWalkTarget; // target of PS_808040's 0x808492 call: poly -> the bare PS_WALK clone, census-only -> the timed SITE_CALL_40 thunk, spiral-only -> 0x7F1D40
__declspec(naked) void PsWalkCall() { __asm jmp dword ptr [psWalkTarget] }
extern "C" U __stdcall PsObserverRoute() {
    const bool routed=PsScopeThread(GetCurrentThreadId());
    ntw2_poly::NoteObserver(routed);
    return routed ? clones.entries[NTW2_CLONE_PS_6A95A0] : V(0x6A95A0);
}
__declspec(naked) void PsObserverGate() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call PsObserverRoute
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
// --ai-record-test*: slot 16 of the ALTERNATE placement delegate class 0x13376AC (0x13376EC = 0x6A99E0). Same transparent frame; the routed
// target is the integer-only scope forwarder ntw2_record_test::Entry (fastcall, ret 0xC like 0x6A99E0), which opens the alt scope around the
// PS_6A99E0 clone chain. Off the planner thread (main/render spotting, workers outside a think) the original is returned untouched.
extern "C" U __stdcall PsAltObserverRoute() {
    const bool routed=PsScopeThread(GetCurrentThreadId());
    ntw2_record_test::NoteSlot(routed);
    return routed ? FnAddress(&ntw2_record_test::Entry) : V(0x6A99E0);
}
__declspec(naked) void PsAltObserverGate() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call PsAltObserverRoute
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
// --brain-target-cull* / --brain-retarget-jitter: slot +8 of the combat node vtable 0x1333E3C (0x1333E44 = thunk 0x66D750: `cmp byte [ecx+0x71],0; je 0x676FD0;
// jmp 0x675710`). Integer-only (EAX and EFLAGS; ECX and the stack are the caller's untouched thiscall frame): on the tick thread inside site 6 the node runs the
// pure-retarget clone of 0x676FD0 (its tracker tick call bound to ntw2_retarget_jitter::TrackerTick), everywhere else (other threads, outside the stage) the
// original thunk. fs:[0x24] is TEB.ClientId.UniqueThread (GetCurrentThreadId); brainScopeTid is 0 outside site 6, so it never matches.
U nodeStepClone, nodeStepOriginal;
__declspec(naked) void NodeStepGate() {
    __asm {
        cmp byte ptr [ecx+0x71], 0
        jne original
        mov eax, dword ptr fs:[0x24]
        cmp eax, dword ptr [brainScopeTid]
        jne original
        jmp dword ptr [nodeStepClone]
    original:
        jmp dword ptr [nodeStepOriginal]
    }
}
// AI2_WALK 7F1D73: EAX = model in, ESI = static interest tree object (live root model+0xBC) out. A retained read
// generation replaces exactly this resolution; registers other than ESI and EFLAGS are untouched.
__declspec(naked) void Ai2RootInterest() {
    __asm mov esi, dword ptr [eax + 0xBC]
    __asm ret
}
extern "C" __declspec(noinline) U __stdcall Ai2PlannerGate(U planner, U flag) {
    if (!aiThread || !Epoch(NTW2_AI_ASYNC2)) return 0;
    if (ntw2_ai_async2::Admit(planner,flag)==ntw2_ai_async2::Synchronous)
        return AiPlannerGate(planner,flag); // sticky watchdog fallback: the same-call AI_ASYNC barrier
    return 1; // queued (a delayed think) or a deferred-schedule busy refusal: the native call is skipped
}
__declspec(naked) void Planner2Gate() {
    __asm {
        push ecx
        push dword ptr [esp+8]
        push ecx
        call Ai2PlannerGate
        pop ecx
        test eax, eax
        jnz dispatched
        jmp dword ptr [aiPlannerClone]
    dispatched:
        ret 4
    }
}
extern "C" void __stdcall Ai2TickJoin(U kind) { if (Epoch(NTW2_AI_ASYNC2)) ntw2_ai_async2::Join(kind); }
// Tick-end seam: publish the staged calls (never join). Tick start: non-blocking effect seam. Exceptional exit: drop the
// unpublished calls and drain what already ran, so no native frame outlives a failed tick.
void Ai2TickEnd() { ntw2_ai_async2::SetWake(Address(aiWake)); ntw2_ai_async2::PublishBatch(); }
void Ai2TickStart() { ntw2_ai_async2::SetWake(Address(aiWake)); ntw2_ai_async2::TickSeam(); }
void Ai2TickAbort() { ntw2_ai_async2::AbortBatch(); Ai2TickJoin(ntw2_ai_async2::KTickEnd); }
// Transparent join thunks: registers, EFLAGS and x87/SSE state preserved; the callee sees the caller's exact stack.
#define AI2_JOIN_THUNK(name, kind, target) \
    __declspec(naked) void name() { \
        __asm cmp dword ptr [ai2Armed], 0 \
        __asm je forward \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm push kind \
        __asm call Ai2TickJoin \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm forward: \
        __asm jmp dword ptr [target] \
    }
AI2_JOIN_THUNK(Ai2ControllerGate, 1, ai2ControllerTarget) // site 33: before the controller's 7492F0 planner rebuild
AI2_JOIN_THUNK(Ai2SpatialGate, 2, ai2SpatialTarget)       // TICK 57DFDF: before the dynamic quadtree update 817D20
#undef AI2_JOIN_THUNK
static_assert(ntw2_ai_async2::KController==1 && ntw2_ai_async2::KSpatial==2, "join thunk kinds");
static_assert(ntw2_ai_async2::kDeferWords==NTW2_AI_DEFERRED_WORDS && ntw2_ai_async2::kWords==NTW2_AI_ASYNC2_WORDS &&
              ntw2_ai_async2::kRouteWords==NTW2_AI_ASYNC2_ROUTE_WORDS, "ai_async2 rows match the status ABI");
bool AiStart() {
    if (aiThread) return true;
    if (!aiWake) aiWake=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if (!aiDone) aiDone=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!aiWake || !aiDone) { RecordError(ThreadError,GetLastError()); return false; }
    _InterlockedExchange(&aiStop,0);
    _InterlockedExchange(&aiBusy,0);
    _InterlockedExchange(&aiRunning,0);
    aiPending=false;
    ResetEvent(aiWake); ResetEvent(aiDone);
    DWORD tid=0;
    aiThread=CreateThread(nullptr,1u<<20,AiWorkerMain,nullptr,STACK_SIZE_PARAM_IS_A_RESERVATION,&tid);
    if (!aiThread) { RecordError(ThreadError,GetLastError()); return false; }
    aiThreadId=tid;
    if (WaitForSingleObject(aiDone,kStopTimeoutMs)!=WAIT_OBJECT_0) {
        RecordError(StopTimeout,NTW2_AI_ASYNC); return false;
    }
    const U startup=allocatorWords[kAiAllocatorRow*NTW2_ALLOCATOR_ROW_WORDS];
    if (startup!=1) { RecordError(AllocatorError,(kAiAllocatorRow<<16)|startup); return false; }
    return true;
}
void AiReset() {
    for (U i=0;i<16;++i) { aiWords[i]=0; aiCtrlWords[i]=0; }
    for (U i=0;i<32;++i) aiExtra[i]=0;
    for (U i=0;i<8;++i) { aiParkWords[i]=0; aiSliceWords[i]=0; aiValidationWords[i]=0; }
    for (U i=0;i<NTW2_AI_SLICE_BUDGET_WORDS;++i) aiBudgetWords[i]=0;
    for (U i=0;i<NTW2_AI_COMPLETION_WORDS;++i) aiCompletionWords[i]=0;
    for (U i=0;i<2;++i) aiSliceSiteWords[i]=0;
    aiJob={}; aiPending=false;
}
bool AiDrain() {
    if (!aiThread) return true;
    // Close tick admission before calling this. The owning tick, not the monitor, joins native work.
    const ULONGLONG deadline=GetTickCount64()+kStopTimeoutMs;
    if (!ntw2_ai_async2::Drain(kStopTimeoutMs)) { RecordError(StopTimeout,NTW2_AI_ASYNC2); return false; }
    while (Load(&tickOwner) || Load(&aiBusy) || aiPending) {
        if (GetTickCount64()>=deadline) { RecordError(StopTimeout,NTW2_AI_ASYNC); return false; }
        Sleep(1);
    }
    return true;
}
bool AiShutdown() {
    if (!aiThread) return true;
    if (!AiDrain()) return false;
    _InterlockedExchange(&aiStop,1);
    SetEvent(aiWake);
    if (WaitForSingleObject(aiThread,kStopTimeoutMs)!=WAIT_OBJECT_0) { RecordError(StopTimeout,NTW2_AI_ASYNC); return false; }
    CloseHandle(aiThread); aiThread=nullptr; aiThreadId=0;
    CloseHandle(aiWake); aiWake=nullptr;
    CloseHandle(aiDone); aiDone=nullptr;
    StateBegin();
    ntw2_state.ai_slice_words[AsParked]=0; ntw2_state.ai_slice_words[AsThread]=0;
    StateEnd();
    return true;
}
// ===================================================================================================================
// In-process crash capture (NTW2_AI_ASYNC runs). The game installs its own unhandled-exception filter and exits with the
// exception code, so WER and the event log see nothing. CrashVeh is a first-chance vectored handler (first in the chain) that, for
// the fatal-class exceptions (access violation, illegal instruction, stack overflow, in-page error, 0xC0000409), records what the
// faulting thread looked like into ntw2_status::crash_words (layout: ntw2_runtime.h), writes a minidump through a helper thread and
// returns EXCEPTION_CONTINUE_SEARCH, so every handler the game has still runs. Only deliberate guarded
// foreign-memory probes (Read, keyForGuarded, profiler sampling) bracket ntw2::probeDepth and are silent.
// AI worker faults are not suppressed or converted into successful partial thinks.
// First-chance exceptions that the game or a library catches itself cannot be told from fatal ones here; the record is overwritten
// by the next one (the fatal exception is always the last), a repeat of an already seen (code, EIP) signature is recorded
// without a dump or handshake, and at most kCrashDumps dumps are written per process.
// Re-entrancy: crashBusy is taken with an interlocked compare-exchange; a second exception (from another thread, or one raised by the
// handler's own guarded stack scan) passes through. The faulting thread allocates nothing: the dump path strings and the helper
// thread/events are created by CrashInstall, the dump itself runs on the helper thread (own stack, so a stack overflow can be dumped)
// against the faulting thread's EXCEPTION_POINTERS while that thread waits inside the handler.
// The launcher polls the status about every 200 ms and the process exits right after the handler returns, so the handler publishes
// the record, waits (bounded) for the launcher's acknowledgement in crash_words[31], dumps, publishes the dump result and waits again.
// ===================================================================================================================
enum CrashWord : U { CwCount, CwThread, CwCode, CwEip, CwRawEip, CwAddress, CwTick, CwState, CwStack, CwEsp=CwStack+16, CwEbp,
                     CwEax, CwEcx, CwEdx, CwEsi, CwEdi, CwAck };
static_assert(CwAck==31, "crash_words layout");
constexpr U kCrashDumps=2, kCrashSignatures=16, kCrashStackWords=1024, kCrashAckMs=750, kCrashDumpMs=60000;
constexpr U kCsRunning=1u<<4, kCsBusy=1u<<5, kCsSwapped=1u<<6, kCsParked=1u<<7, kCsInThink=1u<<8, kCsTickThread=1u<<9,
            kCsWorkerThread=1u<<10, kCsRepeat=1u<<11, kCsDumpShift=12, kCsDumpsShift=14, kCsErrorShift=16;
enum CrashDump : U { DumpNone, DumpRunning, DumpWritten, DumpFailed };
using MiniDumpFn = BOOL (WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
                                  PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
struct CrashSignature { U code, eip; };
PVOID crashHandler;
HANDLE crashThread, crashRequest, crashDone;
MiniDumpFn crashDumpFn;
wchar_t crashPaths[kCrashDumps][MAX_PATH];
volatile LONG crashBusy, crashStop;
U crashDumps, crashSetupError, crashSelfLo, crashSelfHi, crashSignatureCount;
CrashSignature crashSignatures[kCrashSignatures];
// hand-off to the dump thread (written by the faulting thread before it signals crashRequest)
EXCEPTION_POINTERS* volatile crashInfo;
volatile DWORD crashTid, crashSlot, crashResult;

// Which module a raw instruction address belongs to: 0 main image, 1 runtime DLL, 2 private clone, 3 other.
U CrashModule(U address) {
    if (address>=imageBase && address-imageBase<imageSize) return 0;
    if (crashSelfHi && address>=crashSelfLo && address<crashSelfHi) return 1;
    const U clone=Address(clones.allocation);
    if (clone && address>=clone && address-clone<clones.allocation_bytes) return 2;
    return 3;
}
// True when `address` (inside the main image) is preceded by a call instruction: the profiler's decoder (ntw2_profile.cpp
// FollowsCall): E8 rel32, FF /2 with reg, [reg], [reg+disp8], [reg+disp32], [disp32], SIB forms.
bool CrashFollowsCall(U address) {
    const U offset=address-imageBase;
    const auto p=reinterpret_cast<const volatile unsigned char*>(address);
    __try {
        if (offset>=5 && p[-5]==0xe8) return true;
        if (offset>=2 && p[-2]==0xff) {
            const U modrm=p[-1];
            if (modrm>=0xd0 && modrm<=0xd7) return true;
            if (modrm>=0x10 && modrm<=0x17 && modrm!=0x14 && modrm!=0x15) return true;
        }
        if (offset>=3 && p[-3]==0xff) {
            const U modrm=p[-2];
            if (modrm>=0x50 && modrm<=0x57 && modrm!=0x54) return true;
            if (modrm==0x14 && p[-1]==0x24) return true;
        }
        if (offset>=4 && p[-4]==0xff && p[-3]==0x54 && p[-2]==0x24) return true;
        if (offset>=6 && p[-6]==0xff) {
            const U modrm=p[-5];
            if (modrm==0x15 || (modrm>=0x90 && modrm<=0x97 && modrm!=0x94)) return true;
        }
        return offset>=7 && p[-7]==0xff && p[-6]==0x94 && p[-5]==0x24;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// The first 16 in-image words found scanning up to 1024 stack words upward from ESP that follow a call (return-address candidates,
// preferred-base VAs), bounded by the readable committed region, never touching a guard page. Returns how many were stored.
U CrashStack(U esp, volatile U* out) {
    MEMORY_BASIC_INFORMATION memory;
    esp&=~3u;
    if (!esp || !VirtualQuery(reinterpret_cast<void*>(static_cast<uintptr_t>(esp)),&memory,sizeof(memory)) ||
        memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
        !(memory.Protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))
        return 0;
    const SIZE_T available=memory.RegionSize-(esp-reinterpret_cast<uintptr_t>(memory.BaseAddress));
    const U words=available<kCrashStackWords*sizeof(U) ? static_cast<U>(available/sizeof(U)) : kCrashStackWords;
    U found=0;
    __try {
        const volatile U* stack=reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(esp));
        for (U i=0;i<words && found<16;++i) {
            const U value=stack[i];
            if (value>=imageBase && value-imageBase<imageSize && CrashFollowsCall(value)) out[found++]=AiPreferred(value);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return found;
}
U CrashTag(U count, U state) { return (count&0xFFFFu)|(((state>>kCsDumpShift)&3u)<<16)|0x80000000u; }
void CrashWaitAck(U tag) {
    const ULONGLONG deadline=GetTickCount64()+kCrashAckMs;
    while (ntw2_state.crash_words[CwAck]!=tag && GetTickCount64()<deadline) Sleep(5);
}
// Dump thread: one MiniDumpWriteDump per request, against the faulting thread's exception pointers.
DWORD WINAPI CrashDumpMain(void*) {
    ntw2::probeDepth=1; // nothing this thread catches is a crash
    for (;;) {
        WaitForSingleObject(crashRequest,INFINITE);
        if (Load(&crashStop)) break;
        DWORD error=0;
        const HANDLE file=CreateFileW(crashPaths[crashSlot],GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        if (file==INVALID_HANDLE_VALUE) { error=GetLastError(); if (!error) error=0xFFFF; }
        else {
            MINIDUMP_EXCEPTION_INFORMATION exception={crashTid,crashInfo,FALSE};
            const MINIDUMP_TYPE type=static_cast<MINIDUMP_TYPE>(MiniDumpWithIndirectlyReferencedMemory|MiniDumpWithDataSegs|
                                                                MiniDumpWithHandleData);
            if (!crashDumpFn(GetCurrentProcess(),GetCurrentProcessId(),file,type,&exception,nullptr,nullptr)) {
                error=GetLastError(); if (!error) error=0xFFFF; // dbghelp reports an HRESULT (e.g. ERROR_PARTIAL_COPY)
            }
            CloseHandle(file);
        }
        crashResult=error;
        SetEvent(crashDone);
    }
    return 0;
}
// Faulting thread, crashBusy held.
void CrashRecord(EXCEPTION_POINTERS* info, DWORD tid) {
    const EXCEPTION_RECORD* record=info->ExceptionRecord;
    const CONTEXT* context=info->ContextRecord;
    volatile U* w=ntw2_state.crash_words;
    const U code=record->ExceptionCode, raw=Address(record->ExceptionAddress);
    U access=3, address=0;
    if ((code==EXCEPTION_ACCESS_VIOLATION || code==EXCEPTION_IN_PAGE_ERROR) && record->NumberParameters>=2) {
        const U kind=static_cast<U>(record->ExceptionInformation[0]);
        access=kind==0 ? 0 : kind==1 ? 1 : kind==8 ? 2 : 3;
        address=static_cast<U>(record->ExceptionInformation[1]);
    }
    bool repeat=false;
    const U known=crashSignatureCount<kCrashSignatures ? crashSignatureCount : kCrashSignatures;
    for (U i=0;i<known;++i) if (crashSignatures[i].code==code && crashSignatures[i].eip==raw) repeat=true;
    if (!repeat) crashSignatures[crashSignatureCount++%kCrashSignatures]={code,raw};
    U dumpState=DumpNone, dumpError=0;
    if (!repeat && crashDumps<kCrashDumps) {
        if (crashDumpFn && crashThread) dumpState=DumpRunning;
        else { dumpState=DumpFailed; dumpError=crashSetupError; }
    }
    U state=CrashModule(raw)|(access<<2)|(dumpState<<kCsDumpShift)|(crashDumps<<kCsDumpsShift)|((dumpError&0xFFFFu)<<kCsErrorShift);
    if (Load(&aiRunning)) state|=kCsRunning;
    if (Load(&aiBusy)) state|=kCsBusy;
    state|=kCsSwapped; // original game scratch is always live; no suspended-stack scratch banks remain
    if (Load(&aiInThink)) state|=kCsInThink;
    if (tid==tickInProgress) state|=kCsTickThread;
    if (tid==aiThreadId) state|=kCsWorkerThread;
    if (repeat) state|=kCsRepeat;
    w[CwThread]=tid; w[CwCode]=code; w[CwEip]=AiPreferred(raw); w[CwRawEip]=raw; w[CwAddress]=address;
    w[CwTick]=world.model ? WordOrZero(world.model+0x58) : 0;
    w[CwEsp]=context->Esp; w[CwEbp]=context->Ebp; w[CwEax]=context->Eax; w[CwEcx]=context->Ecx;
    w[CwEdx]=context->Edx; w[CwEsi]=context->Esi; w[CwEdi]=context->Edi;
    for (U i=0;i<16;++i) w[CwStack+i]=0;
    CrashStack(context->Esp,w+CwStack);
    w[CwState]=state;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&w[CwCount])); // commit last (full barrier)
    if (repeat) return;
    CrashWaitAck(CrashTag(w[CwCount],state));
    if (dumpState!=DumpRunning) return;
    crashSlot=crashDumps; crashInfo=info; crashTid=tid; crashResult=0;
    ResetEvent(crashDone);
    SetEvent(crashRequest);
    const DWORD waited=WaitForSingleObject(crashDone,kCrashDumpMs);
    const U error=waited==WAIT_OBJECT_0 ? crashResult : (waited==WAIT_TIMEOUT ? 0x102u : 0xFFFFu);
    ++crashDumps;
    dumpState=error ? DumpFailed : DumpWritten;
    state=(state&~((3u<<kCsDumpShift)|(3u<<kCsDumpsShift)|(0xFFFFu<<kCsErrorShift)))|(dumpState<<kCsDumpShift)|
          (crashDumps<<kCsDumpsShift)|((error&0xFFFFu)<<kCsErrorShift);
    w[CwState]=state;
    CrashWaitAck(CrashTag(w[CwCount],state));
}
LONG CALLBACK CrashVeh(EXCEPTION_POINTERS* info) {
    const DWORD code=info->ExceptionRecord->ExceptionCode;
    if (code!=EXCEPTION_ACCESS_VIOLATION && code!=EXCEPTION_ILLEGAL_INSTRUCTION && code!=EXCEPTION_STACK_OVERFLOW &&
        code!=EXCEPTION_IN_PAGE_ERROR && code!=0xC0000409u) return EXCEPTION_CONTINUE_SEARCH;
    if (ntw2::probeDepth) return EXCEPTION_CONTINUE_SEARCH;
    // Grid probation traps are expected first-chance faults that its own handler resumes.
    if (code==EXCEPTION_ACCESS_VIOLATION && info->ExceptionRecord->NumberParameters>=2 &&
        ntw2_grid_probation::Owns(static_cast<U>(info->ExceptionRecord->ExceptionInformation[1]))) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD tid=GetCurrentThreadId();
    if (_InterlockedCompareExchange(&crashBusy,1,0)) return EXCEPTION_CONTINUE_SEARCH;
    CrashRecord(info,tid);
    _InterlockedExchange(&crashBusy,0);
    return EXCEPTION_CONTINUE_SEARCH;
}
// ntw2_start (NTW2_AI_ASYNC requested): everything the handler needs is created here, none of it on the faulting thread.
void CrashInstall() {
    if (crashHandler) return;
    StateBegin();
    for (U i=0;i<32;++i) ntw2_state.crash_words[i]=0;
    StateEnd();
    IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS32 nt;
    crashSelfLo=Address(selfModule); crashSelfHi=0;
    if (Read(crashSelfLo,&dos,sizeof(dos)) && dos.e_magic==IMAGE_DOS_SIGNATURE && dos.e_lfanew>=sizeof(dos) && dos.e_lfanew<0x100000 &&
        Read(crashSelfLo+dos.e_lfanew,&nt,sizeof(nt)) && nt.Signature==IMAGE_NT_SIGNATURE) crashSelfHi=crashSelfLo+nt.OptionalHeader.SizeOfImage;
    const DWORD pid=GetCurrentProcessId();
    CreateDirectoryW(L"F:\\NTW2\\translated_code\\analysis\\crashdumps",nullptr); // exists after the first run; failure surfaces as a dump error
    for (U slot=0;slot<kCrashDumps;++slot)
        _snwprintf_s(crashPaths[slot],MAX_PATH,_TRUNCATE,L"F:\\NTW2\\translated_code\\analysis\\crashdumps\\ntw2-%lu-%u.dmp",
                     static_cast<unsigned long>(pid),slot);
    if (!crashDumpFn) {
        crashSetupError=0;
        const HMODULE dbghelp=LoadLibraryExW(L"dbghelp.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
        crashDumpFn=dbghelp ? reinterpret_cast<MiniDumpFn>(GetProcAddress(dbghelp,"MiniDumpWriteDump")) : nullptr;
        if (!crashDumpFn) crashSetupError=GetLastError();
    }
    if (crashDumpFn && !crashThread) {
        if (!crashRequest) crashRequest=CreateEventW(nullptr,FALSE,FALSE,nullptr);
        if (!crashDone) crashDone=CreateEventW(nullptr,FALSE,FALSE,nullptr);
        _InterlockedExchange(&crashStop,0);
        if (crashRequest && crashDone) crashThread=CreateThread(nullptr,0,CrashDumpMain,nullptr,0,nullptr);
        if (!crashThread) crashSetupError=GetLastError();
    }
    crashHandler=AddVectoredExceptionHandler(1,CrashVeh);
}
// Monitor end / failed start: after this no new record can begin; a dump in flight is waited for (bounded).
void CrashRemove() {
    if (crashHandler) { RemoveVectoredExceptionHandler(crashHandler); crashHandler=nullptr; }
    if (crashThread) {
        _InterlockedExchange(&crashStop,1);
        SetEvent(crashRequest);
        WaitForSingleObject(crashThread,5000);
        CloseHandle(crashThread); crashThread=nullptr;
    }
}
struct BrainTable { U table, original, site; };
constexpr U kBrainSlotOffset=0x0c;
constexpr BrainTable kBrainTables[kBrainSlotCount]={
    {0x1333714,0x66ce00,46},{0x13473d0,0x66ce00,46},{0x13475e4,0x66ce00,46},{0x13477f8,0x66ce00,46},{0x13479b4,0x66ce00,46},
    {0x1347b70,0x66ce00,46},{0x1347d2c,0x66ce00,46},{0x134841c,0x66ce00,46},{0x1347ee8,0x66ce00,46},{0x13480a4,0x66ce00,46},
    {0x1348260,0x66ce00,46},
    {0x132b7d8,0x6f50f0,47},
    {0x13394c0,0x6f4660,48},{0x13396e4,0x6f4660,48},{0x1339924,0x6f4660,48},{0x1339b64,0x6f4660,48},{0x1339da4,0x6f4660,48},
    {0x133af78,0x6f4660,48},
    {0x132ba04,0x602eb0,49},
    {0x132be3c,0x5fceb0,50},{0x132c0c8,0x5fceb0,50},{0x132c2f0,0x5fceb0,50},{0x132c528,0x5fceb0,50}};

// R is the agent head, not an agent pointer embedded in the collision record: 0x585D10
// loads these same worklist pointers into ECX and invokes their brain slot +0x0C.
// Restrict +0x1F0 reads to its pinned agent vtables; unknown records always query.
constexpr U kLodUnits=512;
struct LodRecord { U pointer, unit, hashSlot; double x, z, radius; bool isFar; }; // `far` is a Windows macro
struct LodUnit { U pointer, side, count; double x, z, extent; bool isFar, mixed; };
LodRecord* lodRecords;
LodUnit lodUnits[kLodUnits];
U* lodHash;
U lodCapacity, lodHashCapacity, lodBytes, lodRecordCount, lodUnitCount, lodTick;
U lodUnitHash[2*kLodUnits];
U lodWords[NTW2_COLLIDE_LOD_WORDS];
bool lodReuse, lodReady, lodDisabled;
U LodWord(U p, U offset) { return *reinterpret_cast<const U*>(p+offset); }
U LodHash(U p) { return ((p>>4)*2654435761u)&(lodHashCapacity-1); }
void CollideLodReset() {
    if(lodHash) memset(lodHash,0,static_cast<size_t>(lodHashCapacity)*sizeof(U));
    memset(lodWords,0,sizeof(lodWords));
    memset(lodUnits,0,sizeof(lodUnits));
    memset(lodUnitHash,0,sizeof(lodUnitHash));
    lodRecordCount=lodUnitCount=lodTick=0;
    lodReuse=lodReady=lodDisabled=false;
}
bool CollideLodActivate() {
    if(!(config.enabled_mask&NTW2_COLLIDE_LOD)) return true;
    lodCapacity=activationCapacity.records;
    if(!lodCapacity) return false;
    lodHashCapacity=16;
    while(lodHashCapacity<2*lodCapacity) lodHashCapacity<<=1;
    const size_t bytes=static_cast<size_t>(lodCapacity)*sizeof(LodRecord)+static_cast<size_t>(lodHashCapacity)*sizeof(U);
    if(!VirtualBudget(bytes)) return false;
    lodRecords=static_cast<LodRecord*>(VirtualAlloc(nullptr,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!lodRecords) { RecordError(StorageError,GetLastError()); return false; }
    memset(lodRecords,0,bytes);
    lodHash=reinterpret_cast<U*>(lodRecords+lodCapacity);
    MEMORY_BASIC_INFORMATION memory={};
    lodBytes=VirtualQuery(lodRecords,&memory,sizeof(memory)) ? static_cast<U>(memory.RegionSize) :
        static_cast<U>((bytes+4095u)&~size_t(4095u));
    return true;
}
void CollideLodStop() {
    if(lodRecords) VirtualFree(lodRecords,0,MEM_RELEASE);
    lodRecords=nullptr; lodHash=nullptr;
    lodCapacity=lodHashCapacity=lodBytes=lodRecordCount=0;
    lodReady=false;
}
bool CollideLodGather(U manager) {
    if(!lodRecords || !lodHash) return false;
    // Clear only occupied record slots from the preceding stage.
    for (U i=0;i<lodRecordCount;++i) lodHash[lodRecords[i].hashSlot]=0;
    lodRecordCount=0;
    for (U i=0;i<lodUnitCount;++i) {
        LodUnit& u=lodUnits[i]; u.count=0; u.x=u.z=u.extent=0; u.isFar=true; u.mixed=false; u.side=0;
    }
    lodTick=LodWord(LodWord(LodWord(manager,0),8),0x58);
    lodReuse=*reinterpret_cast<const uint8_t*>(manager+0x268)!=1 && lodTick%100!=0;
    if (!lodReuse) { ++lodWords[5]; return true; } // BFS must receive every original query ID.
    ++lodWords[13];
    const U counts[2]={LodWord(manager,0x24c),LodWord(manager,0x278)};
    const U arrays[2]={LodWord(manager,0x250),LodWord(manager,0x27c)};
    if (counts[0]>lodCapacity || counts[1]>lodCapacity-counts[0]) return false;
    U firstArmy=0;
    bool multipleArmies=false;
    for (U domain=0;domain<2;++domain) for (U slot=0;slot<counts[domain];++slot) {
        const U r=LodWord(arrays[domain],4*slot);
        if (!r || !*reinterpret_cast<const uint8_t*>(r+0x30)) continue;
        U h=LodHash(r);
        while (lodHash[h] && lodRecords[lodHash[h]-1].pointer!=r) h=(h+1)&(lodHashCapacity-1);
        if (lodHash[h]) continue;
        const U table=LodWord(r,0);
        bool known=false;
        for (const BrainTable& t:kBrainTables) if (table==V(t.table)) { known=true; break; }
        if (!known) continue;
        const U army=LodWord(r,0x1f8);
        if (army) { if (firstArmy && firstArmy!=army) multipleArmies=true; else firstArmy=army; }
        const U unit=LodWord(r,0x1f0), side=LodWord(r,0x44);
        if (!unit) continue;
        U uh=LodHash(unit)&(2*kLodUnits-1);
        while (lodUnitHash[uh] && lodUnits[lodUnitHash[uh]-1].pointer!=unit) uh=(uh+1)&(2*kLodUnits-1);
        if (!lodUnitHash[uh]) {
            if (lodUnitCount==kLodUnits) return false;
            lodUnits[lodUnitCount]={unit,0,0,0,0,0,true,false};
            lodUnitHash[uh]=++lodUnitCount;
        }
        const U index=lodUnitHash[uh]-1;
        const double x=*reinterpret_cast<const float*>(r+0x48), z=*reinterpret_cast<const float*>(r+0x50);
        const double radius=*reinterpret_cast<const float*>(r+0x58);
        if (!std::isfinite(x) || !std::isfinite(z) || !std::isfinite(radius) || radius<0) return false;
        LodUnit& u=lodUnits[index];
        if (!side || (u.count && u.side!=side)) u.mixed=true;
        u.side=side; ++u.count; u.x+=x; u.z+=z;
        lodRecords[lodRecordCount]={r,index,h,x,z,radius,false};
        lodHash[h]=++lodRecordCount;
    }
    lodWords[3]=lodWords[4]=lodWords[15]=0;
    for (U i=0;i<lodUnitCount;++i) if (lodUnits[i].count) {
        LodUnit& u=lodUnits[i]; u.x/=u.count; u.z/=u.count; ++lodWords[3];
    }
    for (U i=0;i<lodRecordCount;++i) {
        const LodRecord& r=lodRecords[i]; LodUnit& u=lodUnits[r.unit];
        const double dx=r.x-u.x, dz=r.z-u.z, extent=sqrt(dx*dx+dz*dz)+r.radius;
        if (extent>u.extent) u.extent=extent;
    }
    for (U a=0;a<lodUnitCount;++a) if (lodUnits[a].count) {
        LodUnit& u=lodUnits[a];
        if (u.mixed) u.isFar=false;
        for (U b=0;b<a;++b) if (lodUnits[b].count) {
            LodUnit& v=lodUnits[b];
            // 0x81A889/890/897 compare DWORD R+44 with payload N+14 (= owner S+44), not army +1F8.
            if (u.mixed || v.mixed) { u.isFar=v.isFar=false; continue; }
            if (u.side==v.side) continue;
            ++lodWords[15];
            const double dx=u.x-v.x, dz=u.z-v.z, range=lodWords[6]+u.extent+v.extent;
            if (dx*dx+dz*dz<=range*range) u.isFar=v.isFar=false;
        }
    }
    for (U i=0;i<lodUnitCount;++i) if (lodUnits[i].count && lodUnits[i].isFar) ++lodWords[4];
    const bool refuseAllFar=multipleArmies && lodWords[3]>1 && lodWords[4]==lodWords[3];
    if (refuseAllFar) ++lodWords[14]; // tick-local refusal, not a sticky fault or an invented enemy identity
    for (U i=0;i<lodRecordCount;++i) lodRecords[i].isFar=!refuseAllFar && lodUnits[lodRecords[i].unit].isFar;
    return true;
}
void CollideLodPrepare(void* manager) {
    ++lodWords[0];
    const U metres=config.collide_lod_m&NTW2_COLLIDE_LOD_METRES_MASK;
    lodWords[6]=metres ? metres : 40;
    lodReady=false;
    if (lodDisabled) return;
    LARGE_INTEGER begin,end; QueryPerformanceCounter(&begin);
    bool ok=false;
    ++ntw2::probeDepth;
    __try { ok=CollideLodGather(Address(manager)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ok=false; }
    --ntw2::probeDepth;
    QueryPerformanceCounter(&end);
    const U us=Micro(begin.QuadPart,end.QuadPart);
    lodWords[8]+=us; if (us>lodWords[7]) lodWords[7]=us;
    if (!ok) { ++lodWords[9]; lodWords[10]=1; lodDisabled=true; }
    else lodReady=true;
}
// Original 0x81A790 ABI: ECX=R, one stack scratch pointer, ret 4; its caller ignores EAX.
// The unused EDX parameter preserves precisely that thiscall stack contract.
void __fastcall CollideQueryGate(void* record, void*, void* scratch) {
    if (Epoch(NTW2_COLLIDE_LOD)) {
        ++lodWords[1];
        if (lodReady && lodReuse) {
            const U r=Address(record);
            U h=LodHash(r);
            while (lodHash[h] && lodRecords[lodHash[h]-1].pointer!=r) h=(h+1)&(lodHashCapacity-1);
            if (!lodHash[h]) ++lodWords[12];
            else {
                const LodRecord& entry=lodRecords[lodHash[h]-1];
                if (entry.isFar) {
                    ++lodWords[11];
                    if ((lodTick+entry.unit)&1) { ++lodWords[2]; return; }
                }
            }
        }
    }
    using Query=void (__fastcall *)(void*,void*,void*);
    const U target=CollisionCensus() ? FnAddress(&SiteCall106) : V(0x81a790);
    reinterpret_cast<Query>(target)(record,nullptr,scratch);
}

// BRAIN2 v2 Stage 1 is owner-only. Preserve the native cursor (not an index into a
// snapshot), equality filter and end reload after EVERY occurrence, including
// skipped and duplicate entries. Services complete synchronously before advancing.
static_assert(ntw2_brain2::kWords==NTW2_BRAIN2_WORDS &&
              ntw2_brain2::kCensusWords==NTW2_BRAIN2_CENSUS_WORDS &&
              ntw2_brain2::kVersion==NTW2_BRAIN2_VERSION,"brain v2 status geometry");
static_assert(ntw2_node::kWords==NTW2_NODE_WORDS && ntw2_node::kEventWords==NTW2_NODE_EVENT_WORDS &&
              ntw2_fire::WordCount==NTW2_FIRE_WORDS && ntw2_fire::CommitWordCount==NTW2_FIRE_COMMIT_WORDS &&
              ntw2_brain2::kRouteWords==NTW2_BRAIN2_ROUTE_WORDS &&
              ntw2_brain2::kNodeTargetWords==NTW2_BRAIN2_NODE_TARGET_WORDS &&
              ntw2_brain2::kUnknownSiteWords==NTW2_BRAIN2_UNKNOWN_SITE_WORDS &&
              ntw2_move_node::kWords==NTW2_MOVE_NODE_WORDS && ntw2_move_node::kEventWords==NTW2_MOVE_NODE_EVENT_WORDS,
              "brain shadow status geometry");
static_assert(ntw2_brain_workers::kWords==NTW2_BRAIN_WORKER_WORDS, "brain worker status geometry");
static_assert(ntw2_brain_workers::kPhaseWords==NTW2_BRAIN_WORKER_PHASE_WORDS, "brain worker phase row geometry");
static_assert(ntw2_idle_node::kClassCount==NTW2_IDLE_NODE_CLASSES && ntw2_action_node::kClassCount==NTW2_ACTION_NODE_CLASSES &&
              ntw2_idle_node::kWords==NTW2_NODE_WORDS && ntw2_action_node::kWords==NTW2_NODE_WORDS &&
              ntw2_idle_node::kEventWords==NTW2_NODE_EVENT_WORDS && ntw2_action_node::kEventWords==NTW2_NODE_EVENT_WORDS,
              "concrete node family status geometry");
// --brain-s0: every site-6 occurrence runs through the BRAIN_S0 clone family (counting/timing gates, one native
// execution); validation allows only the unit bits next to it, so census is off and the runner is always taken.
const ntw2_brain2::OccurrenceRunner kS0Runner={&ntw2_brain_s0::BeginStage,&ntw2_brain_s0::EndStage,
                                               &ntw2_brain_s0::RunOccurrence};
// --brain-locality[-warm|-prefetch|-prefetch2]: the locality census owns the occurrence call (original step exactly once);
// validation excludes every other brain flag, so census is off and the runner is always taken.
const ntw2_brain2::OccurrenceRunner kLocalityRunner={&ntw2_brain_locality::BeginStage,&ntw2_brain_locality::EndStage,
                                                     &ntw2_brain_locality::RunOccurrence};
constexpr U kLocalityModifiers=NTW2_BRAIN_LOCALITY_WARM|NTW2_BRAIN_LOCALITY_PREFETCH|NTW2_BRAIN_LOCALITY_PREFETCH2|NTW2_BRAIN_LOCALITY_MARK;
constexpr U kLocalityBits=NTW2_BRAIN_LOCALITY|kLocalityModifiers;
U LocalityMode() {
    return (config.brain_flags&NTW2_BRAIN_LOCALITY_WARM) ? ntw2_brain_locality::ModeWarm :
           (config.brain_flags&NTW2_BRAIN_LOCALITY_PREFETCH) ? ntw2_brain_locality::ModePrefetch1 :
           (config.brain_flags&NTW2_BRAIN_LOCALITY_MARK) ? ntw2_brain_locality::ModeMark :
           (config.brain_flags&NTW2_BRAIN_LOCALITY_PREFETCH2) ? ntw2_brain_locality::ModePrefetch2 : ntw2_brain_locality::ModeCensus;
}
// --brain-unit-* without S0: the shared unit-policy module owns the occurrence call (routes admitted occurrences to BRAIN_U).
const ntw2_brain2::OccurrenceRunner kUnitRunner={&ntw2_unit_policy::BeginStage,&ntw2_unit_policy::EndStage,
                                                 &ntw2_unit_policy::RunOccurrence};
constexpr U kUnitBrainBits=NTW2_BRAIN_UNIT_FATIGUE|NTW2_BRAIN_UNIT_POSTURE|NTW2_BRAIN_UNIT_ENGAGE;
U UnitMode(U base, U shadow) {
    return !(config.brain_flags&base) ? ntw2_unit_policy::Off :
           (config.brain_flags&shadow) ? ntw2_unit_policy::Shadow : ntw2_unit_policy::Live;
}
// Per-unit brain slices: the mechanic modules first (their providers), then the shared admission module over them.
bool BrainUnitPolicyStart() {
    const U fatigue=UnitMode(NTW2_BRAIN_UNIT_FATIGUE,NTW2_BRAIN_UNIT_FATIGUE_SHADOW);
    const U posture=UnitMode(NTW2_BRAIN_UNIT_POSTURE,NTW2_BRAIN_UNIT_POSTURE_SHADOW);
    const U engage=UnitMode(NTW2_BRAIN_UNIT_ENGAGE,NTW2_BRAIN_UNIT_ENGAGE_SHADOW);
    ntw2_unit_policy::Config cfg={};
    cfg.imageBase=imageBase; cfg.cloneEntries=clones.entries; cfg.s0=(config.brain_flags&NTW2_BRAIN_S0)!=0;
    if (fatigue) {
        if (!ntw2_unit_fatigue::Start(imageBase,fatigue)) { RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x13); return false; }
        cfg.providers[ntw2_unit_policy::Fatigue]=ntw2_unit_fatigue::Provider();
    }
    if (posture || engage) {
        if (!ntw2_unit_posture_engage::Start(imageBase,posture,engage,clones.entries)) {
            RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x14); return false;
        }
        cfg.providers[ntw2_unit_policy::Posture]=ntw2_unit_posture_engage::PostureProvider();
        cfg.providers[ntw2_unit_policy::Engage]=ntw2_unit_posture_engage::EngageProvider();
    }
    if ((fatigue && !cfg.providers[ntw2_unit_policy::Fatigue]) || (posture && !cfg.providers[ntw2_unit_policy::Posture]) ||
        (engage && !cfg.providers[ntw2_unit_policy::Engage]) || !ntw2_unit_policy::Start(cfg)) {
        RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x15); return false;
    }
    return true;
}
bool Brain2Start() {
    ntw2_brain2::Configure(config.brain_flags&NTW2_BRAIN_CENSUS,
                           config.brain_flags&NTW2_BRAIN_TIMING,
                           config.brain_flags&NTW2_BRAIN_NODE_SHADOW,
                           config.brain_flags&NTW2_BRAIN_FIRE_SHADOW,
                           config.brain_flags&NTW2_BRAIN_FINALIZER_SHADOW);
    ntw2_brain2::SetOccurrenceRunner(nullptr);
    const bool units=(config.brain_flags&kUnitBrainBits)!=0;
    if (units && !BrainUnitPolicyStart()) return false;
    if (config.brain_flags&NTW2_BRAIN_S0) {
        if (!ntw2_brain_s0::Start(clones.entries,ntw2_brain_s0::kDefaultShift,cloneBindings,units)) {
            RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x12); return false;
        }
        ntw2_brain2::SetOccurrenceRunner(&kS0Runner);
    } else if (config.brain_flags&NTW2_BRAIN_LOCALITY) {
        if (!ntw2_brain_locality::Start(imageBase,LocalityMode())) { RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x16); return false; }
        ntw2_brain2::SetOccurrenceRunner(&kLocalityRunner);
    } else if (units) ntw2_brain2::SetOccurrenceRunner(&kUnitRunner);
    return true;
}
// Stage 2 (--brain-parallel). Started after the pool; the worker family is private to the dispatch and never published.
bool BrainWorkersStart() {
    ntw2_brain_workers::Binding binding={};
    binding.image_base=imageBase; binding.clones=&clones; binding.bindings=cloneBindings;
    binding.dispatch=&ntw_pool_dispatch; binding.pool=Address(&pool); binding.workers=config.workers;
    binding.min_entities=64; binding.defer_events=0; // event deferral needs per-site tail proofs that do not exist
    // --brain-quiet: Brain2Start configured ntw2_brain2 without census (validation refuses quiet with census/timing/
    // shadows), so owner-run occurrences execute the ORIGINAL step; workers skip guard-miss block checksums.
    binding.quiet=(config.brain_flags&NTW2_BRAIN_QUIET)!=0;
    if (!ntw2_brain_workers::Start(binding)) { RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x10); return false; }
    return true;
}
// Per-unit brain Stage A (--brain-unit-shadow): shadow only. One pool dispatch decides every known unit before the
// unchanged site-6 loop; ntw2_brain2::RunWorklist calls Observe after each occurrence. No native write anywhere.
const ntw2_brain2::StageObserver kUnitObserver={&ntw2_unit_brain::BeginStage,&ntw2_unit_brain::Observe,
                                                 &ntw2_unit_brain::EndStage};
bool BrainUnitStart() {
    ntw2_unit_brain::Binding binding={imageBase,&ntw_pool_dispatch,Address(&pool),config.workers};
    if (!ntw2_unit_brain::Start(binding)) { RecordError(ModuleError,(NTW2_BRAIN2<<24)|0x11); return false; }
    ntw2_brain2::SetStageObserver(&kUnitObserver);
    return true;
}
void Brain2Reset() {
    ntw2_brain2::Reset(); ntw2_brain_workers::Reset(); ntw2_unit_brain::Reset(); ntw2_brain_s0::Reset(); ntw2_brain_locality::Reset();
    ntw2_unit_policy::Reset(); ntw2_unit_fatigue::Reset(); ntw2_unit_posture_engage::Reset();
}
void Brain2Release() {
    ntw2_brain2::SetStageObserver(nullptr); ntw2_unit_brain::Stop();
    ntw2_brain2::SetOccurrenceRunner(nullptr); ntw2_brain_s0::Stop(); ntw2_brain_locality::Stop();
    ntw2_unit_policy::Stop(); ntw2_unit_fatigue::Stop(); ntw2_unit_posture_engage::Stop();
    ntw2_brain_workers::Stop(); ntw2_brain2::Release();
}
void __fastcall BrainKernelGate(void* g) {
    using Loop = void (__fastcall*)(void*);
    if (!Epoch(NTW2_BRAIN2) || !clones.allocation) {
        reinterpret_cast<Loop>(V(0x585d10))(g);
        return;
    }
    if (ntw2_brain_workers::Started() && ntw2_brain_workers::RunWorklist(Address(g),clones.entries)) return;
    ntw2_brain2::RunWorklist(Address(g),clones.entries);
}

// Main-thread visual apply, 0x779E60: ECX=this, one unused stack dword, void / ret 4.
// VISUAL_ENTRY retains the one-shot, status resize, post-pass and both remaining
// loops byte-for-byte; only loop 1 calls VisualLoop. It is NOT a tick-owner epoch.
// The owner is acquired before rechecking enabled, and teardown drains it before
// shutting down the shared pool. A delayed thunk after disable uses only original code.
enum VisualWord : U { VwCalls, VwSharded, VwInline, VwItems, VwChunks, VwShardUs, VwInlineUs,
                      VwMaxUs, VwFaults, VwFaultEip, VwFaultAddress, VwFaultItem, VwFaultIndex, VwSlot,
                      VwArenaEpochs, VwArenaBusy };
volatile U visualWords[32];
volatile LONG visualOwner, visualFaulted, visualFaultLock;
using VisualApply = void (__fastcall *)(void*, void*, U);
using VisualItem = U (__fastcall *)(void*, U);
struct VisualJob {
    void* self;
    U count, chunkSize, mxcsr, fpuControl, caller, lastByte;
    volatile LONG workerSeen;
};
VisualJob* visualJob; // only the acquired main-thread owner publishes/reads this stack pointer
// Mirror the game's TBB arena epoch (77083F..770888 / 770ACF..770B17), not its TBB TLS registry.
// 10E9DC0 uses provider->index() to select arena[+30][index]; only backing-chunk growth takes
// the native arena lock. Buffers stay game-owned until its ordinary arena reset, including escaped poses.
struct VisualArenaProvider;
using VisualArenaMethod=U (__fastcall *)(VisualArenaProvider*,void*);
struct VisualArenaProvider { const VisualArenaMethod* methods; U participants; };
U __fastcall VisualArenaCount(VisualArenaProvider* provider,void*) { return provider->participants; }
U __fastcall VisualArenaSlot(VisualArenaProvider*,void*) { return visualArenaIndex; }
const VisualArenaMethod kVisualArenaMethods[]={&VisualArenaCount,&VisualArenaSlot};
struct VisualArenas { U address[3], enabled; };
bool VisualArenaBegin(void* self,VisualArenaProvider& provider,VisualArenas& arenas) {
    const U context=*reinterpret_cast<const U*>(Address(self)+0xec);
    const U owner=*reinterpret_cast<const U*>(context+4);
    const U animation=reinterpret_cast<U (__fastcall*)(U)>(V(0x611a60))(owner);
    const U methods=*reinterpret_cast<const U*>(animation);
    arenas.address[0]=reinterpret_cast<U (__fastcall*)(U)>(*reinterpret_cast<const U*>(methods+4))(animation);
    arenas.address[1]=context+0x80+0x4c*(*reinterpret_cast<const U*>(context+0x164));
    arenas.address[2]=context+0x118;
    // An existing native epoch belongs to another owner; never replace its provider or active slots.
    for (U i=0;i<3;++i) {
        const U arena=arenas.address[i];
        if (*reinterpret_cast<const unsigned char*>(arena+0x1c) ||
            *reinterpret_cast<const U*>(arena+0x20) || *reinterpret_cast<const U*>(arena+0x2c)) return false;
    }
    // 7911E0 normally does this per item: concurrent first calls can reset another item's live buffers.
    reinterpret_cast<void (__fastcall*)(U)>(V(0x75d280))(context);
    for (U i=0;i<3;++i) {
        arenas.enabled=i+1; // includes a partially initialized arena if the native vector resize throws
        reinterpret_cast<void (__fastcall*)(U,void*,VisualArenaProvider*)>(V(0x7c9350))(arenas.address[i],nullptr,&provider);
    }
    return true;
}
void VisualArenaEnd(VisualArenas& arenas) {
    for (U i=0;i<arenas.enabled;++i) {
        const U arena=arenas.address[i];
        *reinterpret_cast<unsigned char*>(arena+0x1c)=0;
        *reinterpret_cast<U*>(arena+0x20)=0;
        *reinterpret_cast<U*>(arena+0x2c)=0;
    }
}

int VisualFilter(EXCEPTION_POINTERS* exception, U item, U index) {
    _InterlockedExchange(&visualFaulted,1);
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&visualWords[VwFaults]));
    while (_InterlockedCompareExchange(&visualFaultLock,1,0)) YieldProcessor();
    visualWords[VwFaultEip]=exception->ContextRecord->Eip;
    const EXCEPTION_RECORD* record=exception->ExceptionRecord;
    visualWords[VwFaultAddress]=(record->ExceptionCode==EXCEPTION_ACCESS_VIOLATION ||
        record->ExceptionCode==EXCEPTION_IN_PAGE_ERROR) && record->NumberParameters>=2 ?
        static_cast<U>(record->ExceptionInformation[1]) : Address(record->ExceptionAddress);
    visualWords[VwFaultItem]=item;
    visualWords[VwFaultIndex]=index;
    _InterlockedExchange(&visualFaultLock,0);
    return EXCEPTION_EXECUTE_HANDLER;
}
void __fastcall VisualChunk(void* context, U chunk) {
    VisualJob* job=static_cast<VisualJob*>(context);
    if (GetCurrentThreadId()!=job->caller) _InterlockedExchange(&job->workerSeen,1);
    const U first=chunk*job->chunkSize;
    const U end=job->count-first<job->chunkSize ? job->count : first+job->chunkSize;
    const U savedCsr=_mm_getcsr();
    unsigned short savedCw=0, wantedCw=static_cast<unsigned short>(job->fpuControl);
    __asm fnstcw word ptr [savedCw]
    _mm_setcsr(job->mxcsr);
    __asm fldcw word ptr [wantedCw]
    volatile U index=first, item=0;
    // A failed item is never replayed (it may already have changed game state).
    // Continue the rest of this chunk and join all chunks before the serial tail.
    while (index<end) {
        __try {
            for (;index<end;++index) {
                item=0;
                const U list=*reinterpret_cast<const U*>(Address(job->self)+0xec);
                const U data=*reinterpret_cast<const U*>(list+0x2c);
                item=*reinterpret_cast<const U*>(data+4*index);
                const U last=reinterpret_cast<VisualItem>(clones.entries[NTW2_CLONE_VISUAL_ITEM])(job->self,index);
                if (index==job->count-1) job->lastByte=last;
            }
        } __except(VisualFilter(GetExceptionInformation(),item,index)) {
            ++index;
            __asm fninit
            __asm fldcw word ptr [wantedCw]
            _mm_setcsr(job->mxcsr);
        }
    }
    __asm fldcw word ptr [savedCw]
    _mm_setcsr(savedCsr);
}
U __fastcall VisualLoop(void* self) {
    VisualJob* job=visualJob;
    job->self=self;
    job->count=*reinterpret_cast<const U*>(Address(self)+0xf8);
    visualWords[VwItems]+=job->count;
    U chunkSize=pool.workers ? job->count/(4*pool.workers) : job->count;
    if (chunkSize<32) chunkSize=32;
    job->chunkSize=chunkSize;
    const U chunks=job->count/chunkSize+(job->count%chunkSize!=0);
    // Nonblocking readiness test: another tick dispatcher may win the subsequent
    // pool CAS; the pool then executes inline. workerSeen records actual execution,
    // not a guessed success from a racy st_calls snapshot.
    if (job->count>=64 && poolReady && pool.workers &&
        Load(reinterpret_cast<volatile LONG*>(&pool.state))==NTW_POOL_S_READY) {
        VisualArenaProvider provider={kVisualArenaMethods,pool.workers+1};
        VisualArenas arenas={};
        const U savedIndex=visualArenaIndex;
        visualArenaIndex=0;
        __try {
            if (VisualArenaBegin(self,provider,arenas)) {
                ++visualWords[VwArenaEpochs];
                ntw_pool_dispatch(Address(&pool),FnAddress(&VisualChunk),chunks,job);
            } else {
                ++visualWords[VwArenaBusy];
                for (U c=0;c<chunks;++c) VisualChunk(job,c);
            }
        } __finally {
            // The dispatcher has joined every chunk, including SEH-failed items, before the native serial tail.
            VisualArenaEnd(arenas);
            visualArenaIndex=savedIndex;
        }
    } else {
        for (U c=0;c<chunks;++c) VisualChunk(job,c);
    }
    visualWords[VwChunks]+=chunks;
    return job->lastByte;
}
void __fastcall VisualApplyThunk(void* self, void* edx, U argument) {
    const VisualApply original=reinterpret_cast<VisualApply>(V(0x779e60));
    if (!(Load(&enabled)&NTW2_VISUAL) ||
        (config.main_thread_id && config.main_thread_id!=GetCurrentThreadId()) ||
        _InterlockedCompareExchange(&visualOwner,1,0)) {
        original(self,edx,argument);
        return;
    }
    __try {
        if (!(Load(&enabled)&NTW2_VISUAL)) {
            original(self,edx,argument);
        } else {
            LARGE_INTEGER begin, end;
            QueryPerformanceCounter(&begin);
            ++visualWords[VwCalls];
            const U count=*reinterpret_cast<const U*>(Address(self)+0xf8);
            VisualJob job={self,count,0,_mm_getcsr(),AiFpuControl(),GetCurrentThreadId(),0,0};
            visualJob=&job;
            if (count<64 || Load(&visualFaulted) || !poolReady || !pool.workers ||
                Load(reinterpret_cast<volatile LONG*>(&pool.state))!=NTW_POOL_S_READY) {
                if (!*reinterpret_cast<const unsigned char*>(Address(self)+0x130)) visualWords[VwItems]+=count;
                original(self,edx,argument);
            } else {
                reinterpret_cast<VisualApply>(clones.entries[NTW2_CLONE_VISUAL_ENTRY])(self,edx,argument);
            }
            QueryPerformanceCounter(&end);
            const U us=Micro(begin.QuadPart,end.QuadPart);
            if (Load(&job.workerSeen)) {
                ++visualWords[VwSharded]; visualWords[VwShardUs]+=us;
            } else {
                ++visualWords[VwInline]; visualWords[VwInlineUs]+=us;
            }
            if (us>visualWords[VwMaxUs]) visualWords[VwMaxUs]=us;
        }
    } __finally {
        visualJob=nullptr;
        _InterlockedExchange(&visualOwner,0);
    }
}
bool ActivationBoundary(void* model) {
    if (Load(&activationCapture.state)!=1 || Load(&gateDepth)>1 || Load(&enabled)) return false;
    const LONG tid=static_cast<LONG>(GetCurrentThreadId());
    if (_InterlockedCompareExchange(&tickOwner,tid,0)!=0) return false;
    bool captured=false;
    alignas(16) unsigned char fp[512];
    __asm { fxsave fp }
    __try {
        if (_InterlockedCompareExchange(&activationCapture.state,2,1)==1) {
            if (Address(model)==activationCapture.model && BoundModel(Address(model))) {
                activationCapture.capture(activationCapture.context);
                captured=true;
                _InterlockedExchange(&activationCapture.state,3);
            } else {
                _InterlockedExchange(&activationCapture.state,1);
            }
        }
    } __finally {
        __asm { fxrstor fp }
        _InterlockedExchange(&tickOwner,0);
    }
    return captured;
}
U __fastcall TickGate(void* model, void* edx, U a, U b) {
    const LONG depth=_InterlockedIncrement(&gateDepth);
    const U mask=static_cast<U>(Load(&enabled));
    if (!(mask&kRouted)) {
        ActivationBoundary(model);
        // The normal engine has one tick executor; a competing entry must not
        // enter native code during the short activation capture.
        while (Load(&activationCapture.state)==2) Sleep(0);
        U result=0;
        __try {
            result=reinterpret_cast<Tick>(V(0x57df40))(model,edx,a,b);
            if (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) ntw2_alloc_census::ReclaimTick(Address(model));
        } __finally { _InterlockedDecrement(&gateDepth); }
        return result;
    }
    const U tid=GetCurrentThreadId();
    LARGE_INTEGER start, end;
    ntw2_trace_entry trace;
    QueryPerformanceCounter(&start);
    if (mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) ntw2_profile_tick_start(start.QuadPart);
    tickInProgress=tid; // nonzero while the tick executes; identifies the executing thread for the profiler
    {   // Diagnostic: how many threads execute the hooked task entry concurrently (expected: one, the tick).
        // Depth was acquired before the activation boundary.
        if (static_cast<U>(depth)>cadence.words[13]) cadence.words[13]=static_cast<U>(depth);
        if (tid!=cadence.words[14]) { cadence.words[14]=tid; ++cadence.words[15]; }
    }
    const U modelTick=WordOrZero(Address(model)+0x58);
    const U interval=tickLastStart ? Micro(tickLastStart,start.QuadPart) : 0;
    phaseUs[0]=phaseUs[1]=phaseUs[2]=0;
    siteDepth=0; brainFamily=kNoFamily; brainScopeTid=0;
    memset(siteUs,0,sizeof(siteUs));
    memset(siteCalls,0,sizeof(siteCalls));
    if (_InterlockedCompareExchange(&tickOwner,static_cast<LONG>(tid),0)!=0) {
        const U r=reinterpret_cast<Tick>(V(0x57df40))(model,edx,a,b);
        QueryPerformanceCounter(&end);
        SimRecord(start.QuadPart,end.QuadPart,tid,false);
        TraceTick(trace,modelTick,tid,Micro(start.QuadPart,end.QuadPart),interval,false,start.QuadPart);
        _InterlockedDecrement(&gateDepth);
        QueryPerformanceCounter(&end);
        if (mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) ntw2_profile_tick_end(end.QuadPart);
        PublishTrace(trace,end.QuadPart);
        tickInProgress=0;
        return r;
    }
    const U currentMask=static_cast<U>(Load(&enabled));
    if (!(currentMask&kRouted) || !BoundModel(Address(model))) {
        _InterlockedExchange(&tickOwner,0);
        const U r=reinterpret_cast<Tick>(V(0x57df40))(model,edx,a,b);
        QueryPerformanceCounter(&end);
        SimRecord(start.QuadPart,end.QuadPart,tid,false);
        TraceTick(trace,modelTick,tid,Micro(start.QuadPart,end.QuadPart),interval,false,start.QuadPart);
        _InterlockedDecrement(&gateDepth);
        QueryPerformanceCounter(&end);
        if (mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) ntw2_profile_tick_end(end.QuadPart);
        PublishTrace(trace,end.QuadPart);
        tickInProgress=0;
        return r;
    }
    epochMask=currentMask;
    ntw2_grid_census_site=0;
    if (currentMask&NTW2_GRID_CENSUS) ntw2_grid_census_tick(modelTick);
    if (currentMask&NTW2_AI_CENSUS) ntw2_ai_census::Tick();
    if (currentMask&NTW2_BRAIN) BrainStateBeginTick();
    // Tick core census (trace flags bits 3..31) and opt-in placement (NTW2_TICK_PCORE / NTW2_TICK_CORE_AB): a hard affinity for the
    // tick body only, restored first thing in the __finally below. Placement never touches engine state or order.
    const bool census=cpuTopology;
    const U entryE=census ? cpuECore[GetCurrentProcessorNumber()&63] : 0u;
    U placed=0;
    DWORD_PTR priorAffinity=0;
    if (cpuHybrid && (config.va_watch_flags&(NTW2_TICK_PCORE|NTW2_TICK_CORE_AB))) {
        const bool toE=(config.va_watch_flags&NTW2_TICK_CORE_AB) && (modelTick&1u);
        priorAffinity=SetThreadAffinityMask(GetCurrentThread(),toE ? cpuEMask : cpuPMask);
        if (priorAffinity) placed=toE ? 2u : 1u;
    }
    if (census) { LARGE_INTEGER now; QueryPerformanceCounter(&now); CoreBegin(now.QuadPart); }
    U result=0;
    bool traced=false, ai2Published=false;
    __try {
        Ai2TickStart(); // one effect seam: service a posted worker call; join only an already-complete batch
        AiBarrier(); // no previous tick is permitted to retain native AI frames
        result=reinterpret_cast<Tick>(privateTick)(model,edx,a,b);
        if (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) ntw2_alloc_census::ReclaimTick(Address(model));
        Ai2TickEnd(); ai2Published=true; AiBarrier(); // normal completion is included in the tick duration
        QueryPerformanceCounter(&end);
        const U bodyUs=Micro(start.QuadPart,end.QuadPart);
        SimRecord(start.QuadPart,end.QuadPart,tid,true);
        TraceTick(trace,modelTick,tid,bodyUs,interval,true,start.QuadPart);
        if (census) { CoreSample(end.QuadPart); trace.flags|=CoreFlags(entryE,placed); }
        traced=true;
        if (config.va_watch_flags&NTW2_ENGAGE_CENSUS) ntw2_engage_census::Tick(Address(model),modelTick); // read-only observer, after the tick body is published
    } __finally {
        coreCensus.active=false;
        if (placed) SetThreadAffinityMask(GetCurrentThread(),priorAffinity);
        if (!ai2Published) Ai2TickAbort();
        AiBarrier(); epochMask=0; _InterlockedExchange(&tickOwner,0);
        if(Load(&budgetReleasePending)) {
            // Yield this completed tick to the monitor exactly once instead of
            // hoping a polling sample lands in a tiny gap between busy ticks.
            SetEvent(budgetWakeEvent);
            while(Load(&budgetReleasePending) && WaitForSingleObject(stopEvent,0)!=WAIT_OBJECT_0) Sleep(1);
        }
        _InterlockedDecrement(&gateDepth);
        QueryPerformanceCounter(&end);
        if (mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) ntw2_profile_tick_end(end.QuadPart);
        ntw2_grid_census_site=0;
        if (traced) PublishTrace(trace,end.QuadPart);
        tickInProgress=0;
    }
    return result;
}
bool Epoch(U feature) { return static_cast<U>(Load(&tickOwner))==GetCurrentThreadId() && (epochMask & feature)!=0; }
struct PhaseTimer {
    U index; LARGE_INTEGER begin;
    explicit PhaseTimer(U i) : index(i) { QueryPerformanceCounter(&begin); }
    ~PhaseTimer() { LARGE_INTEGER now; QueryPerformanceCounter(&now); phaseUs[index]+=Micro(begin.QuadPart,now.QuadPart); }
};
U __fastcall FormationGate(void* manager) {
    PhaseTimer timer(0);
    // The MANAGER clone route carries the timed sites, including the planner gate (site 34): every feature that lives behind a
    // site must take it, not only profiling. (Shipping `ai` without `profile` was inert before this line included NTW2_AI_ASYNC.)
    const U target=Epoch(NTW2_FORMATION) ? formHook :
        Epoch(kManagerRouted) ? clones.entries[NTW2_CLONE_MANAGER] : V(0x580640);
    return reinterpret_cast<Manager>(target)(manager);
}
void __fastcall PathGate(void* pf) {
    PhaseTimer timer(2);
    reinterpret_cast<Scheduler>(Epoch(NTW2_PATH) ? pathHook : V(0x81a2c0))(pf);
}
U __fastcall BallisticGate(void* manager) {
    PhaseTimer timer(1);
    return reinterpret_cast<Manager>(Epoch(NTW2_BALLISTICS) && Address(manager)==world.projectiles ? privateManager : V(0x6f6bc0))(manager);
}

bool LoadModule(Module& module, const char* init, const char* stop, const char* state, U feature, U busy) {
    module.init=reinterpret_cast<Init>(Export(init)); module.stop=reinterpret_cast<Init>(Export(stop));
    module.state=reinterpret_cast<volatile U*>(Export(state)); module.feature=feature; module.busy=busy;
    return module.init && module.stop && module.state;
}
bool LoadEntries() {
    if (!LoadModule(formation,"nfr_initialize","nfr_stop","nfr_state",NTW2_FORMATION,NFR_E_BUSY) ||
        !LoadModule(query,"nqc_initialize","nqc_stop","nqc_state",NTW2_BALLISTICS,NQC_E_BUSY) ||
        !LoadModule(path,"npr_initialize","npr_stop","npr_state",NTW2_PATH,NPR_E_BUSY)) return false;
    pathStorage=reinterpret_cast<volatile U*>(Export("npr_storage_bytes"));
    formationDiag=reinterpret_cast<volatile U*>(Export("nfr_diag"));
    pathHook=Export("npr_scheduler_hook"); formHook=Export("nfr_manager_hook");
    return pathStorage && pathHook && formHook;
}
// The S0 row is shared with --brain-locality (mutually exclusive): the configured feature's module fills it.
void SnapshotBrainRow() {
    U* row=const_cast<U*>(ntw2_state.brain_s0_words);
    if (config.brain_flags&NTW2_BRAIN_LOCALITY) ntw2_brain_locality::Snapshot(row);
    else ntw2_brain_s0::Snapshot(row);
}
// --brain-unit-*: the shared header, the fatigue half and the posture/engage half of brain_unit_policy_words. Only the halves
// whose feature is configured are published (every other word stays zero from the activation reset).
void SnapshotUnitPolicy() {
    if (!(config.brain_flags&kUnitBrainBits)) return;
    U words[NTW2_BRAIN_UNIT_POLICY_WORDS]={};
    ntw2_unit_policy::Snapshot(words);
    if (config.brain_flags&NTW2_BRAIN_UNIT_FATIGUE) ntw2_unit_fatigue::Snapshot(words+ntw2_unit_policy::kFatigueBase);
    if (config.brain_flags&(NTW2_BRAIN_UNIT_POSTURE|NTW2_BRAIN_UNIT_ENGAGE))
        ntw2_unit_posture_engage::Snapshot(words+ntw2_unit_policy::kPolicyBase);
    for (U i=0;i<NTW2_BRAIN_UNIT_POLICY_WORDS;++i) ntw2_state.brain_unit_policy_words[i]=words[i];
}
// --army-storm-census: the module row with the profile gate's admitted/rejected sampler counters; all zero without the census.
void SnapshotArmyStorm() {
    U words[NTW2_ARMY_STORM_WORDS];
    ntw2_army_storm::Snapshot(words,ntw2_profile_storm_admitted,ntw2_profile_storm_rejected);
    for (U i=0;i<NTW2_ARMY_STORM_WORDS;++i) ntw2_state.army_storm_words[i]=words[i];
}
// --army-solver-memo/-shadow: the module row (all zero without the bits).
void SnapshotArmySolver() {
    U words[NTW2_ARMY_SOLVER_WORDS];
    ntw2_army_solver::Snapshot(words);
    for (U i=0;i<NTW2_ARMY_SOLVER_WORDS;++i) ntw2_state.army_solver_words[i]=words[i];
}
// --ai-ctrl-*: A half (batch/histogram) and B half (geometry) of the status row; reads module counters only.
void SnapshotAiCtrl() {
    volatile U* row=ntw2_state.ai_ctrl_reuse_words;
    ntw2_ai_ctrl::Snapshot(row);
    U geometry[ntw2_ai_ctrl_geometry::kStatusWords];
    ntw2_ai_ctrl_geometry::FillStatus(geometry);
    for (U i=0;i<NTW2_AI_CTRL_REUSE_WORDS-16;++i) row[16+i]=i<ntw2_ai_ctrl_geometry::kStatusWords ? geometry[i] : 0;
    static_assert(ntw2_claim_once::kWords==NTW2_AI_CTRL_REUSE_WORDS-24 && ntw2_ai_ctrl_geometry::kStatusWords<=8, "claim-once words fill the B half after the geometry words");
    ntw2_claim_once::Snapshot(row+24); // --ai-claim-once: all zero without the bit
    static_assert(ntw2_group_formup::kWords<=NTW2_AI_GROUP_WORDS/2, "formup words fill the first half of ai_group_words");
    ntw2_group_formup::Snapshot(ntw2_state.ai_group_words); // --ai-formup-gate: words 0..15, all zero without the bit
    static_assert(ntw2_retarget_jitter::kWords==4, "retarget-jitter words fill words 20..23");
    if (config.ai_ctrl_flags&NTW2_AI_RETARGET_JITTER) ntw2_retarget_jitter::Snapshot(row+20); // --brain-retarget-jitter (exclusive with the geometry mode that owns 16..23)
    static_assert(ntw2_target_cull::kWords==4, "target-cull words fill words 16..19");
    if (config.ai_ctrl_flags&(NTW2_AI_TARGET_CULL_SHADOW|NTW2_AI_TARGET_CULL)) ntw2_target_cull::Snapshot(row+16); // --brain-target-cull* (exclusive with the geometry mode that owns 16..23)
    static_assert(ntw2_prepass::kCensusWords==NTW2_AI_PREPASS_CENSUS_WORDS, "census snapshot writes exactly the status row");
    ntw2_prepass::CensusSnapshot(ntw2_state.ai_prepass_census_words); // --ai-prepass-*: same three poll/stop sites; all zero without the flags
    static_assert(ntw2_poly::kWords==NTW2_AI_POLY_WORDS && ntw2_record_test::kWords==NTW2_AI_RECORD_TEST_WORDS, "poly + record-test rows fill the prepass status row");
    for (U i=0;i<NTW2_AI_POLY_WORDS;++i) ntw2_state.ai_prepass_words[i]=ntw2_poly::words[i]; // --ai-poly*: all zero without the bits
    for (U i=0;i<NTW2_AI_RECORD_TEST_WORDS;++i) ntw2_state.ai_prepass_words[NTW2_AI_POLY_WORDS+i]=ntw2_record_test::words[i]; // --ai-record-test*: all zero without the bits
    static_assert(ntw2_spiral::kWords==NTW2_AI_SPIRAL_WORDS, "spiral snapshot writes exactly the status row");
    for (U i=0;i<NTW2_AI_SPIRAL_WORDS;++i) ntw2_state.ai_spiral_words[i]=ntw2_spiral::words[i]; // --ai-spiral-*: all zero without the bits
}
bool clonesCensus; // resident private clones were emitted with reader edge gates (census cannot be added to a resident arena)
bool BuildClones() {
    if (clones.allocation) {
        if ((config.enabled_mask&NTW2_GRID_CENSUS) && !clonesCensus) { RecordError(CloneError,0x7f000001u); return false; }
        return true;
    }
    U bindings[NTW2_BIND_COUNT]={};
    bindings[NTW2_BIND_AI_CENSUS_REBUILD]=ntw2_ai_census::Gate(6);
    bindings[NTW2_BIND_PS_WALK_CALL]=FnAddress(&PsWalkCall);
    bindings[NTW2_BIND_PS_POLY]=FnAddress(&ntw2_poly::Gate);
    bindings[NTW2_BIND_RJ_TRACKER_TICK]=FnAddress(&ntw2_retarget_jitter::TrackerTick);
    bindings[NTW2_BIND_MO_GATE]=FnAddress(&ntw2_mounted_officer::Gate);
    bindings[NTW2_BIND_PS_LADDER]=FnAddress(&ntw2_spiral::Ladder);
    bindings[NTW2_BIND_PS_LADDER_PROBE]=FnAddress(&ntw2_spiral::LadderProbe);
    bindings[NTW2_BIND_PS_SPIRAL]=FnAddress(&ntw2_spiral::Spiral);
    bindings[NTW2_BIND_PS_SPIRAL_PROBE]=FnAddress(&ntw2_spiral::SpiralProbe);
    bindings[NTW2_BIND_ARMY_FSM_UPDATE]=FnAddress(&ArmyFsmGate);
    bindings[NTW2_BIND_ARMY_PREP]=FnAddress(&ArmyPrepGate);
    bindings[NTW2_BIND_ARMY_FORMATION]=FnAddress(&ArmyFormationGate);
    ntw2_army_solver::Bind(delta,bindings); // solver gates (inert until Start: they forward to the originals)
    bindings[NTW2_BIND_TICK_ENTRY]=FnAddress(&TickGate);
    bindings[NTW2_BIND_BAL_MANAGER]=FnAddress(&BallisticGate);
    bindings[NTW2_BIND_FORM_MANAGER]=FnAddress(&FormationGate);
    bindings[NTW2_BIND_FORM_ASSIGN]=Export("nfr_assign_hook");
    bindings[NTW2_BIND_BAL_STAGE]=FnAddress(&bal_stage);
    bindings[NTW2_BIND_BAL_STEP]=FnAddress(&bal_step);
    bindings[NTW2_BIND_BAL_JOB]=Address(&ballistic);
    bindings[NTW2_BIND_QUERY_GATHER]=Export("nqc_gather_hook");
    bindings[NTW2_BIND_QUERY_UNIT]=Export("nqc_unit_hook");
    bindings[NTW2_BIND_QUERY]=Export("nqc_query_hook");
    bindings[NTW2_BIND_BATCH_APPEND]=Export("append_vec3");
    bindings[NTW2_BIND_BATCH_FLUSH]=Export("flush_vec3");
    bindings[NTW2_BIND_PATH_HOOK]=FnAddress(&PathGate);
    bindings[NTW2_BIND_PATH_SOLVE]=Export("npr_solve");
    bindings[NTW2_BIND_VISUAL_LOOP]=FnAddress(&VisualLoop);
    bindings[NTW2_BIND_COLLISION_REUSE]=FnAddress(&CollisionReuse);
    bindings[NTW2_BIND_COLLISION_REBUILD]=FnAddress(&CollisionRebuild);
    bindings[NTW2_BIND_COLLISION_ACCEPT]=FnAddress(&CollisionAccept);
    bindings[NTW2_BIND_COLLISION_LABEL]=FnAddress(&CollisionLabel);
    bindings[NTW2_BIND_COLLISION_NUMERIC_BEGIN]=FnAddress(&CollisionNumericBeginGate);
    bindings[NTW2_BIND_COLLISION_NUMERIC_END]=FnAddress(&CollisionNumericEndGate);
    bindings[NTW2_BIND_COLLIDE_QUERY]=FnAddress(&CollideQueryGate);
    bindings[NTW2_BIND_AI2_SPATIAL_JOIN]=FnAddress(&Ai2SpatialGate);
    bindings[NTW2_BIND_AI2_WALK_IMAGE]=Address(ai2WalkImage)+kAi2WalkBias;
    bindings[NTW2_BIND_AI2_GATHER_IMAGE]=Address(ai2GatherImage)+kAi2GatherBias;
    bindings[NTW2_BIND_AI2_LOOKUP_IMAGE]=Address(ai2LookupImage)+kAi2LookupBias;
    bindings[NTW2_BIND_AI2_ROOT_INTEREST]=FnAddress(&Ai2RootInterest);
    bindings[NTW2_BIND_AI2_SPOT_IMAGE]=Address(ai2SpotImage)+kAi2SpotBias;
    bindings[NTW2_BIND_AI2_ROUTE_COUNTS]=ntw2_ai_async2::FunctionCounters();
    bindings[NTW2_BIND_AI2_UNROUTED_83FD00]=ntw2_ai_async2::Gate(ntw2_ai_async2::kUnroutedPin);
    ai2SpatialTarget=V(0x817D20); ai2ControllerTarget=V(0x7C8BD0);
    if (!ntw2_brain2::Bind(imageBase,bindings)) return false; // private scratch is initialized before clone publication
    if (!ntw2_brain_s0::Bind(imageBase,bindings)) return false; // S0 gates forward to the originals until Start routes them
    if (!ntw2_unit_policy::Bind(imageBase,bindings) || !ntw2_unit_fatigue::Bind(imageBase,bindings) ||
        !ntw2_unit_posture_engage::Bind(imageBase,bindings)) return false; // per-unit brain gates/data bindings (inert until Start)
    if (!ntw2_ai_ctrl::Bind(bindings) || !ntw2_ai_ctrl_geometry::Bind(imageBase,bindings)) return false; // gates are inert until Activate configures them
    bindings[NTW2_BIND_PP_CHILD_THINK]=ntw2_prepass::ChildThinkGateAddress(); // --ai-prepass-census / --ai-presize gates: inert until Activate configures them
    bindings[NTW2_BIND_PP_RESERVE]=ntw2_prepass::PresizeReserveGateAddress();
    bindings[NTW2_BIND_PP_EXIT]=ntw2_prepass::PresizeExitGateAddress();
    ntw2_loco::Bind(delta,bindings); // before ntw2_build_clones: the module owns its clone bindings
    const U siteThunks[NTW2_TIMED_SITES]={
        FnAddress(&SiteCall0), FnAddress(&SiteCall1), FnAddress(&SiteCall2), FnAddress(&SiteCall3),
        FnAddress(&SiteCall4), FnAddress(&SiteCall5), FnAddress(&SiteCall6), FnAddress(&SiteCall7),
        FnAddress(&SiteCall8), FnAddress(&SiteCall9), FnAddress(&SiteCall10), FnAddress(&SiteCall11),
        FnAddress(&SiteCall12), FnAddress(&SiteCall13), FnAddress(&SiteCall14), FnAddress(&SiteCall15),
        FnAddress(&SiteCall16), FnAddress(&SiteCall17), FnAddress(&SiteCall18), FnAddress(&SiteCall19),
        FnAddress(&SiteCall20), FnAddress(&SiteCall21), FnAddress(&SiteCall22), FnAddress(&SiteCall23),
        FnAddress(&SiteCall24), FnAddress(&SiteCall25), FnAddress(&SiteCall26), FnAddress(&SiteCall27),
        FnAddress(&SiteCall28), FnAddress(&SiteCall29), FnAddress(&SiteCall30), FnAddress(&SiteCall31),
        FnAddress(&SiteCall32), FnAddress(&SiteCall33), FnAddress(&SiteCall34), FnAddress(&SiteCall35),
        FnAddress(&SiteCall36), FnAddress(&SiteCall37), FnAddress(&SiteCall38), FnAddress(&SiteCall39),
        FnAddress(&SiteCall40), FnAddress(&SiteCall41), FnAddress(&SiteCall42), FnAddress(&SiteCall43),
        FnAddress(&SiteCall44), FnAddress(&SiteCall45),
        FnAddress(&SiteCall46), FnAddress(&SiteCall47), FnAddress(&SiteCall48), FnAddress(&SiteCall49),
        FnAddress(&SiteCall50), FnAddress(&SiteCall51), FnAddress(&SiteCall52), FnAddress(&SiteCall53),
        FnAddress(&SiteCall54), FnAddress(&SiteCall55), FnAddress(&SiteCall56), FnAddress(&SiteCall57),
        FnAddress(&SiteCall58), FnAddress(&SiteCall59), FnAddress(&SiteCall60), FnAddress(&SiteCall61),
        FnAddress(&SiteCall62), FnAddress(&SiteCall63), FnAddress(&SiteCall64), FnAddress(&SiteCall65),
        FnAddress(&SiteCall66), FnAddress(&SiteCall67), FnAddress(&SiteCall68), FnAddress(&SiteCall69),
        FnAddress(&SiteCall70), FnAddress(&SiteCall71), FnAddress(&SiteCall72), FnAddress(&SiteCall73),
        FnAddress(&SiteCall74), FnAddress(&SiteCall75), FnAddress(&SiteCall76), FnAddress(&SiteCall77),
        FnAddress(&SiteCall78), FnAddress(&SiteCall79), FnAddress(&SiteCall80), FnAddress(&SiteCall81),
        FnAddress(&SiteCall82), FnAddress(&SiteCall83), FnAddress(&SiteCall84), FnAddress(&SiteCall85),
        FnAddress(&SiteCall86), FnAddress(&SiteCall87), FnAddress(&SiteCall88), FnAddress(&SiteCall89),
        FnAddress(&SiteCall90), FnAddress(&SiteCall91), FnAddress(&SiteCall92), FnAddress(&SiteCall93),
        FnAddress(&SiteCall94), FnAddress(&SiteCall95), FnAddress(&SiteCall96), FnAddress(&SiteCall97),
        FnAddress(&SiteCall98), FnAddress(&SiteCall99), FnAddress(&SiteCall100), FnAddress(&SiteCall101),
        FnAddress(&SiteCall102), FnAddress(&SiteCall103), FnAddress(&SiteCall104), FnAddress(&SiteCall105),
        FnAddress(&SiteCall106), FnAddress(&SiteCall107), FnAddress(&SiteCall108), FnAddress(&SiteCall109)};
    for (U i=0;i<NTW2_TIMED_SITES;++i) {
        siteCallees[i]=siteCalleeVas[i]<kPreferred ? 0 : V(siteCalleeVas[i]); // virtual-slot sites get a host trampoline below
        bindings[NTW2_BIND_SITE_CALL_0+i]=siteThunks[i];
    }
    for (U i=0;i<NTW2_BIND_COUNT;++i) if (!bindings[i]) { RecordError(MissingExport,i); return false; }
    U detail=0;
    ntw2_clones_grid_callback((config.enabled_mask&NTW2_GRID_CENSUS) ? FnAddress(&ntw2_grid_census_call) : 0);
    const U error=ntw2_build_clones(imageBase,bindings,&clones,&detail);
    ntw2_clones_grid_callback(0);
    if (!error) memcpy(cloneBindings,bindings,sizeof(cloneBindings));
    clonesCensus=!error && (config.enabled_mask&NTW2_GRID_CENSUS);
    // ACTIVE site 2 is still timed inclusively; its callee is the ARMIES clone,
    // which in turn invokes the ARMY and AIPASS clones.
    siteCallees[2]=clones.entries[NTW2_CLONE_ARMIES];
    siteCallees[18]=clones.entries[NTW2_CLONE_ARMY_UPDATE];
    siteCallees[5]=V(0x57dc30); // bound to the feature/profile gate only for an active generation
    siteCallees[106]=V(0x81a790); // pair-level profiling is explicitly opt-in, not implied by PROFILE
    siteCallees[109]=FnAddress(&CollisionSlot44);
    // Site 24 remains inclusive of the conditional controller update and sites 26..39.
    siteCallees[24]=clones.entries[NTW2_CLONE_AIWRAP];
    siteCallees[40]=clones.entries[NTW2_CLONE_AI_WALK];
    siteCallees[41]=clones.entries[NTW2_CLONE_AI_GATHER];
    siteCallees[44]=FnAddress(&ntw2_walk_memo::kernel);
    // NTW2_BRAIN. The slot +0x0C targets are the entry thunks themselves; their callees are the family's clone. The wrappers' brain
    // calls (formerly the 0x6F50F0 jmp thunk) reach the brain clone, and the two timed vtable calls go through host trampolines.
    siteCallees[46]=siteCallees[47]=siteCallees[55]=siteCallees[56]=siteCallees[59]=clones.entries[NTW2_CLONE_BRAIN];
    siteCallees[48]=clones.entries[NTW2_CLONE_WRAP_6F4660];
    siteCallees[49]=clones.entries[NTW2_CLONE_WRAP_602EB0];
    siteCallees[50]=clones.entries[NTW2_CLONE_WRAP_5FCEB0];
    siteCallees[93]=FnAddress(&VirtualSlot1A8);
    siteCallees[94]=FnAddress(&VirtualSlot108);
    for (U i=kBrainFirst;i<NTW2_TIMED_SITES;++i) if (!siteCallees[i]) { RecordError(MissingExport,0x1000+i); return false; }
    ntw2_walk_memo::configure(reinterpret_cast<ntw2_walk_memo::Kernel>(V(0x80dcf0)),
        reinterpret_cast<const U*>(V(0x1318038)),reinterpret_cast<const U*>(V(0x1318048)));
    ntw2_prepass::PresizeConfigure(reinterpret_cast<ntw2_prepass::AllocFn>(V(0x449e10)));
    privateTick=clones.entries[NTW2_CLONE_TICK]; privateManager=clones.entries[NTW2_CLONE_BAL_MANAGER];
    return true;
}
bool StartPool() {
    if (poolReady) return true;
    if (poolOwned) { RecordError(PoolError,NTW_POOL_E_STATE); return false; }
    ntw_pool_config c={NTW_POOL_ABI,config.workers,0u,{FnAddress(&CreateEventW),FnAddress(&CloseHandle),
        FnAddress(&SetEvent),FnAddress(&WaitForSingleObject),FnAddress(&CreateThread),FnAddress(&ntw_pool_worker_start)},
        FnAddress(&WorkerAllocatorInit),0};
    const U error=ntw_pool_init(&pool,&c);
    poolOwned=error==NTW_POOL_OK || error==NTW_POOL_E_JOIN;
    if (error) {
        for (U i=0;i<config.workers;++i) {
            const U result=static_cast<U>(Load(reinterpret_cast<volatile LONG*>(&allocatorWords[i*NTW2_ALLOCATOR_ROW_WORDS])));
            if (result>1) { RecordError(AllocatorError,(i<<16)|result); break; }
        }
        RecordError(PoolError,error);
        return false;
    }
    poolReady=true; return true;
}
bool StartModule(Module& module, void* cfg) {
    const U error=module.init(cfg);
    if (error) { RecordError(ModuleError,(module.feature<<24)|(error&0xffffff)); return false; }
    module.ready=true; return true;
}
bool NeedsActivationWorkload() {
    return (config.enabled_mask&(NTW2_COLLIDE|NTW2_COLLIDE_LOD)) ||
        ((config.enabled_mask&NTW2_LOCO) && (config.loco_flags&(NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)));
}
// Every refusal leaves a reason in memoryWords[NTW2_MEM_ERROR] (0xCA000000 | code), published as the StorageError detail.
bool CaptureWorkloadImpl() {
    constexpr U maxRecords=131072, maxCells=1048576, maxMemberships=2097152;
    const U manager=world.army;
    auto refuse=[](U code,U value){ memoryWords[NTW2_MEM_ERROR]=0xCA000000u|(code<<16)|(value&0xFFFFu); return false; };
    if(!manager) return refuse(1,0);
    const U primary=LodWord(manager,0x24C), secondary=LodWord(manager,0x278), work=LodWord(manager,0x260);
    if(primary>maxRecords) return refuse(2,primary);
    if(secondary>maxRecords-primary) return refuse(3,secondary);
    if(work>maxRecords) return refuse(4,work);
    const U primaryNeed=primary>work ? primary : work;
    // Only allocation alignment headroom for records. Reinforcements beyond the
    // admitted generation run natively rather than expanding VA during a tick.
    activationCapacity.primary=((primaryNeed ? primaryNeed : 1u)+255u)&~255u;
    const U recordsNeed=primary+secondary>primaryNeed ? primary+secondary : primaryNeed;
    activationCapacity.records=((recordsNeed ? recordsNeed : 1u)+255u)&~255u;
    activationCapacity.cells=1;
    ULONGLONG memberships=0;
    const bool spatial=(config.enabled_mask&NTW2_COLLIDE) ||
        ((config.enabled_mask&NTW2_LOCO) && (config.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)));
    if(spatial) {
        const U grid=LodWord(world.model,0xA4);
        if(!grid) return refuse(5,0);
        const U shift=LodWord(grid,8), maximum=LodWord(grid,0x14);
        if(shift>20 || maximum>=(1u<<shift)) return refuse(6,shift|(maximum<<8));
        const ULONGLONG cells=(static_cast<ULONGLONG>(maximum)<<shift)+maximum+1;
        if(cells>maxCells) return refuse(7,static_cast<U>(cells>>8));
        activationCapacity.cells=static_cast<U>(cells);
        memoryWords[NTW2_MEM_NATIVE_GRID_SHIFT]=shift;
        memoryWords[NTW2_MEM_NATIVE_GRID_MAXIMUM]=maximum;
        memoryWords[NTW2_MEM_NATIVE_GRID_DIMENSION]=maximum+1;
        const U arrays[2]={LodWord(manager,0x250),LodWord(manager,0x27C)};
        const U counts[2]={primary,secondary};
        for(U domain=0;domain<2;++domain) {
            if(counts[domain] && !arrays[domain]) return refuse(8,domain);
            for(U i=0;i<counts[domain];++i) {
                const U record=LodWord(arrays[domain],4*i);
                if(record) memberships+=LodWord(record,0xAC);
                if(memberships>maxMemberships) return refuse(9,static_cast<U>(memberships>>8));
            }
        }
    }
    // cg-stagec2: 601701 candidates / 47877 primary records = 12.57 (open field). Dense borodino500 lines measure 1214308 / 56269
    // = 21.6 per primary. Pairs only bound a counter (no buffer is sized from them), so give 64 per primary, up to the solver's
    // 4194304 hard limit; a stage past it refuses natively before the first game write.
    activationCapacity.pairs=static_cast<U>((std::min<ULONGLONG>)(4194304ull,64ull*activationCapacity.primary));
    memberships=(memberships+(memberships+3)/4+255u)&~ULONGLONG(255u);
    if(!memberships) memberships=256;
    if(memberships>maxMemberships) return refuse(10,static_cast<U>(memberships>>8));
    activationCapacity.memberships=static_cast<U>(memberships);
    return true;
}
void CaptureWorkload(void* context) {
    bool& ready=*static_cast<bool*>(context);
    ++ntw2::probeDepth;
    __try { ready=CaptureWorkloadImpl(); }
    __except(EXCEPTION_EXECUTE_HANDLER) { memoryWords[NTW2_MEM_ERROR]=GetExceptionCode(); ready=false; }
    --ntw2::probeDepth;
}
bool PrepareActivationWorkload() {
    activationCapacity={};
    const U remaining=(config.enabled_mask&(NTW2_LOCO|NTW2_COLLIDE|NTW2_COLLIDE_LOD))&
        ~static_cast<U>(Load(&budgetDisabledMask));
    if(!NeedsActivationWorkload() || !remaining) return true;
    bool ready=false;
    if(!CaptureAtTick(&CaptureWorkload,&ready) || !ready) {
        if(WaitForSingleObject(stopEvent,0)!=WAIT_OBJECT_0) RecordError(StorageError,memoryWords[NTW2_MEM_ERROR]);
        return false;
    }
    memoryWords[NTW2_MEM_PRIMARY_CAPACITY]=activationCapacity.primary;
    memoryWords[NTW2_MEM_RECORD_CAPACITY]=activationCapacity.records;
    memoryWords[NTW2_MEM_CELL_CAPACITY]=activationCapacity.cells;
    memoryWords[NTW2_MEM_MEMBERSHIP_CAPACITY]=activationCapacity.memberships;
    memoryWords[NTW2_MEM_PAIR_CAPACITY]=activationCapacity.pairs;
    return true;
}
void SampleMemoryStorage() {
    memoryWords[NTW2_MEM_LOCO_BYTES]=ntw2_loco::StorageBytes();
    static_assert(ntw2_loco::StorageWordCount==11 &&
        NTW2_MEM_LOCO_TREE_ENTRIES-NTW2_MEM_LOCO_MOVEMENT_BYTES+1==ntw2_loco::StorageWordCount,
        "cached LOCO storage breakdown matches the appended memory row");
    static_assert(ntw2_loco::CatalogStorageWordCount==10 &&
        NTW2_MEM_LOCO_CATALOG_POLYGON_POINTS-NTW2_MEM_LOCO_CATALOG_RING_BYTES+1==ntw2_loco::CatalogStorageWordCount,
        "cached catalog storage breakdown matches the appended memory row");
    // Preserve the last allocation breakdown after a budget retirement, while
    // the module's current byte count below accurately becomes zero.
    if(memoryWords[NTW2_MEM_LOCO_BYTES] || !budgetRetired) {
        ntw2_loco::SampleStorage(memoryWords+NTW2_MEM_LOCO_MOVEMENT_BYTES);
        ntw2_loco::SampleCatalogStorage(memoryWords+NTW2_MEM_LOCO_CATALOG_RING_BYTES);
    }
    memoryWords[NTW2_MEM_COLLIDE_BYTES]=ntw2_collide::StorageBytes();
    memoryWords[NTW2_MEM_PROFILE_BYTES]=ntw2_profile_storage_bytes();
    memoryWords[NTW2_MEM_RUNTIME_IMAGE_BYTES]=runtimeImageBytes;
    memoryWords[NTW2_MEM_CLONE_BYTES]=clones.allocation_bytes;
    memoryWords[NTW2_MEM_POOL_STACK_BYTES]=poolOwned ? pool.workers*(pool.stack_bytes ? pool.stack_bytes : defaultStackBytes) : 0;
    memoryWords[NTW2_MEM_AI_STACK_BYTES]=aiThread ? 1u<<20 : 0;
    memoryWords[NTW2_MEM_OTHER_STACK_BYTES]=defaultStackBytes*((monitorThread ? 1u : 0u)+(crashThread ? 1u : 0u)+
        (memoryWords[NTW2_MEM_PROFILE_BYTES] ? 1u : 0u));
    memoryWords[NTW2_MEM_LOD_BYTES]=lodBytes;
    memoryWords[NTW2_MEM_BALLISTICS_BYTES]=records ? sizeof(bal_record)*kProjectileCapacity : 0;
    memoryWords[NTW2_MEM_OTHER_BYTES]=(formation.state ? formation.state[NFR_S_STORAGE_BYTES] : 0)+
        (query.state ? query.state[NQC_S_STORAGE_BYTES] : 0)+(pathStorage ? *pathStorage : 0)+
        ntw2_unit_policy::StorageBytes()+ // retained unit-policy storage (allocated once, kept for the process)
        static_cast<U>(ntw2_army_solver::StorageBytes())+ // solver workspace (allocated at ntw2_army_solver::Start, freed at Stop)
        ntw2_alloc_census::StorageBytes()+ // alloc census open-addressing tables (allocated at Start, freed at Stop)
        ntw2_brain_locality::StorageBytes(); // retained locality census storage (allocated once, kept for the process)
    ULONGLONG total=0;
    for(U i=NTW2_MEM_LOCO_BYTES;i<=NTW2_MEM_OTHER_BYTES;++i) total+=memoryWords[i];
    memoryWords[NTW2_MEM_TOTAL_BYTES]=total>UINT32_MAX ? UINT32_MAX : static_cast<U>(total);
}
// --grid-probation (NTW2_LOCO_GRID_PROBATION): native soft-grid head trap detector (src/loco/native_grid_probation.h).
// Pool worker ids are captured once at start (the pool is persistent for the generation); classifying a trapping
// thread is plain word compares (no locks, allocation or faults inside the vectored handler).
U probationWorkerIds[NTW_POOL_MAX_WORKERS]; U probationWorkers; bool probationRunning;
U ProbationThreadClass() {
    const U tid=GetCurrentThreadId();
    if (tid==tickInProgress) return ntw2_grid_probation::ThreadTick;
    for (U i=0;i<probationWorkers;++i) if (tid==probationWorkerIds[i]) return ntw2_grid_probation::ThreadPool;
    if (tid==aiThreadId) return ntw2_grid_probation::ThreadAi;
    if (tid==config.main_thread_id) return ntw2_grid_probation::ThreadMain;
    return ntw2_grid_probation::ThreadOther;
}
bool ProbationStart() {
    probationWorkers=0;
    if (poolOwned)
        for (U i=0;i<pool.workers && i<NTW_POOL_MAX_WORKERS;++i)
            if (pool.slots[i].thread) probationWorkerIds[probationWorkers++]=GetThreadId(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pool.slots[i].thread)));
    ntw2_grid_probation::Binding binding={imageBase,imageSize,Address(selfModule),Address(selfModule)+runtimeImageBytes,
        &clones,&ntw2_grid_census_site,&tickInProgress,&ProbationThreadClass};
    probationRunning=ntw2_grid_probation::Start(binding);
    return probationRunning;
}
// Tick owner drained (StopModules, budget retirement): restores the armed pages and removes the handler.
void ProbationStop() {
    if (!probationRunning) return;
    ntw2_grid_probation::Stop();
    probationRunning=false;
}
void RetireBudgetOwned() {
    const U stopped=static_cast<U>(Load(&budgetDisabledMask));
    if(!stopped || budgetRetired || Load(&tickOwner)) return;
    // No prior epoch can still reference a module. A new tick may start while
    // freeing, but both stage gates see the sticky latch and use only originals.
    memoryWords[NTW2_MEM_RELEASED_LOCO_BYTES]=ntw2_loco::StorageBytes();
    memoryWords[NTW2_MEM_RELEASED_COLLIDE_BYTES]=ntw2_collide::StorageBytes();
    if(stopped&NTW2_COLLIDE) { ntw2_collide::Stop(); collideSampleReady=false; }
    if((stopped&NTW2_LOCO) && locoRunning) {
        ntw2_loco::Stop(); locoRunning=false; locoSampleReady=false;
        ProbationStop(); // the native stage now relinks every tick: the detector has no owner window left
    }
    budgetRetired=true;
    _InterlockedExchange(&budgetReleasePending,0);
    memoryWords[NTW2_MEM_BUDGET_RELEASE_PENDING]=0;
    ++memoryWords[NTW2_MEM_BUDGET_RELEASES];
    SampleMemoryStorage();
    StateBegin(); PublishMemory(); StateEnd();
}
bool StartModules() {
    const U mask=config.enabled_mask&~static_cast<U>(Load(&budgetDisabledMask));
    const bool brainParallel=(mask&NTW2_BRAIN2) && (config.brain_flags&NTW2_BRAIN_PARALLEL);
    // The unit shadow's decision dispatch uses the pool when there are workers, else it runs on the tick owner.
    const bool brainUnit=(mask&NTW2_BRAIN2) && (config.brain_flags&NTW2_BRAIN_UNIT_SHADOW);
    const bool brainUnitPool=brainUnit && config.workers;
    const U poolMask=NTW2_PATH|NTW2_BALLISTICS|NTW2_VISUAL|NTW2_COLLIDE|NTW2_LOCO;
    const ULONGLONG stacks=(((mask&poolMask) || brainParallel || brainUnitPool) ? static_cast<ULONGLONG>(config.workers)*
        defaultStackBytes : 0)+((mask&NTW2_AI_ASYNC) ? 1u<<20 : 0);
    if(!VirtualBudget(stacks)) return false;
    if(!CollideLodActivate()) { RecordError(StorageError,NTW2_COLLIDE_LOD); return false; }
    if ((mask & NTW2_AI_ASYNC) && !AiStart()) return false;
    // The unit-policy storage is allocated once and retained for the process: budget it before the first allocation.
    if ((mask & NTW2_BRAIN2) && (config.brain_flags&kUnitBrainBits) && !ntw2_unit_policy::StorageBytes() &&
        !VirtualBudget(ntw2_unit_policy::RequiredStorageBytes())) return false;
    if ((mask & NTW2_BRAIN2) && (config.brain_flags&NTW2_BRAIN_LOCALITY) && !(config.brain_flags&NTW2_BRAIN_LOCALITY_MARK) &&
        !ntw2_brain_locality::StorageBytes() &&
        !VirtualBudget(ntw2_brain_locality::RequiredStorageBytes())) return false;
    if ((mask & NTW2_BRAIN2) && !Brain2Start()) return false;
    if (((mask & (NTW2_PATH|NTW2_BALLISTICS|NTW2_VISUAL|NTW2_COLLIDE|NTW2_LOCO)) || brainParallel || brainUnitPool) &&
        !StartPool()) return false;
    if (brainParallel && !BrainWorkersStart()) return false;
    if (brainUnit && !BrainUnitStart()) return false;
    if (mask & NTW2_ARMY_UNIT_SHADOW) {
        const ntw2_army_unit::Binding binding={imageBase,config.workers,
            (mask&NTW2_AI_CENSUS) ? &ntw2_ai_census::OwnerCalls : nullptr,(mask&NTW2_AI_ASYNC2) ? 1u : 0u};
        if (!ntw2_army_unit::Start(binding)) { RecordError(ModuleError,NTW2_ARMY_UNIT_SHADOW); return false; }
    }
    if (config.va_watch_flags & NTW2_ARMY_STORM_CENSUS) {
        const ntw2_army_storm::Binding binding={imageBase,(config.va_watch_flags&NTW2_ARMY_STORM_SAMPLE_MASK)>>NTW2_ARMY_STORM_SAMPLE_SHIFT};
        if (!ntw2_army_storm::Start(binding)) { RecordError(ModuleError,NTW2_ARMY_STORM_CENSUS); return false; }
    }
    if (config.va_watch_flags & (NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW)) { // clones are built: the solver forwards AssignGate to CLONE_SOLVER_18F0A00
        if (!VirtualBudget(ntw_solver::WorkspaceBytes())) return false; // the workspace is allocated by Start below, per activation
        const ntw2_army_solver::Binding binding={delta,(config.va_watch_flags&NTW2_ARMY_SOLVER_SHADOW) ? ntw2_army_solver::ModeShadow : ntw2_army_solver::ModeMemo,
                                                 clones.entries[NTW2_CLONE_SOLVER_18F0A00]};
        if (!ntw2_army_solver::Start(binding)) { RecordError(ModuleError,config.va_watch_flags&(NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW)); return false; }
    }
    if (config.va_watch_flags & (NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) {
        const U mode=allocCensusRequestedMode ? allocCensusRequestedMode : ntw2_alloc_census::kModeCensus;
        if (!VirtualBudget(ntw2_alloc_census::RequiredStorageBytes(mode))) return false;
        const ntw2_alloc_census::Binding binding={imageBase,imageSize,delta,mode,&clones};
        if (!ntw2_alloc_census::Start(binding)) { RecordError(ModuleError,config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)); return false; }
    }
    if (mask & NTW2_COLLIDE) {
        ntw2_collide::Binding binding={delta,&ntw_pool_dispatch,Address(&pool),config.workers};
        if ((mask&NTW2_LOCO) && (config.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)))
            binding.read_grid=&ntw2_loco::ReadGridForCollision;
        // Contact responses: shadow compares plans with the original callbacks; workers replay them.
        binding.contact_mode=(config.collide_flags&NTW2_COLLIDE_CONTACT_SHADOW) ? ntw2_contact::ModeShadow :
            (config.collide_flags&NTW2_COLLIDE_CONTACT_WORKERS) ? ntw2_contact::ModeWorkers : ntw2_contact::ModeOff;
        if (!ntw2_collide::Start(binding)) { RecordError(ModuleError,NTW2_COLLIDE); return false; }
        collideSampleReady=true;
        const U reservation=ntw2_collide::EstimateActivationBytes(activationCapacity);
        if(reservation==UINT32_MAX) { RecordError(StorageError,NTW2_COLLIDE); return false; }
        if(!VirtualBudget(reservation)) return false;
        if(!ntw2_collide::Activate(reinterpret_cast<void*>(world.army),activationCapacity)) {
            RecordError(ModuleError,NTW2_COLLIDE); return false;
        }
    }
    if (mask & NTW2_LOCO) {
        ntw2_loco::Binding binding={};
        binding.image_delta=delta;
        binding.wrap_clone=clones.entries[NTW2_CLONE_LOCO_WRAP];
        binding.move_clone=clones.entries[NTW2_CLONE_LOCO_MOVE];
        binding.selector_clone=clones.entries[NTW2_CLONE_LOCO_SELECT];
        binding.class_wrap_clone=clones.entries[NTW2_CLONE_LOCO_CLASS_WRAP];
        binding.use_clone=(config.loco_flags&NTW2_LOCO_CLONE)!=0;
        binding.clone_bytes=NTW2_LOCO_CLONE_BYTES;
        binding.use_parallel=(config.loco_flags&NTW2_LOCO_PARALLEL)!=0;
        // Quiet overrides owner shadow comparisons even when both flags are supplied; port initialization is owned-service driven.
        binding.use_quiet=(config.loco_flags&NTW2_LOCO_QUIET)!=0;
        binding.use_shadow=(config.loco_flags&NTW2_LOCO_SHADOW)!=0 && !binding.use_quiet;
        binding.use_owned_services=(config.loco_flags&NTW2_LOCO_OWNED_SERVICES)!=0;
        binding.use_grid=(config.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))!=0;
        binding.verify_grid=(config.loco_flags&NTW2_LOCO_GRID_VERIFY)!=0;
        binding.grid_incremental=(config.loco_flags&NTW2_LOCO_GRID_INCREMENTAL)!=0;
        binding.use_relink_shadow=(config.loco_flags&NTW2_LOCO_RELINK_SHADOW)!=0;
        binding.use_relink_workers=(config.loco_flags&NTW2_LOCO_RELINK_WORKERS)!=0;
        binding.use_cw_shadow=(config.loco_flags&NTW2_LOCO_CW_SHADOW)!=0;
        binding.use_cw_workers=(config.loco_flags&NTW2_LOCO_CW_WORKERS)!=0;
        binding.dispatch=&ntw_pool_dispatch;
        binding.pool=Address(&pool);
        binding.workers=config.workers;
        binding.capture_at_tick=&CaptureAtTick;
        // Probation: the owner's relink window brackets replay and grid publication; heads stay armed outside it.
        if (config.loco_flags&NTW2_LOCO_GRID_PROBATION) binding.grid_window=&ntw2_grid_probation::Window;
        if (!ntw2_loco::Start(binding)) { RecordError(ModuleError,NTW2_LOCO); return false; }
        locoRunning=true; locoSampleReady=true;
        if (binding.use_owned_services || binding.use_grid) {
            const U reservation=ntw2_loco::EstimateActivationBytes(activationCapacity);
            if(reservation==UINT32_MAX) { RecordError(StorageError,NTW2_LOCO); return false; }
            if(!VirtualBudget(reservation)) return false;
            // The disabled task route captures the immutable scene only; large
            // allocations and prefaults remain on this monitor thread.
            if(!ntw2_loco::ActivateOwned(reinterpret_cast<void*>(world.model),activationCapacity)) {
                if (WaitForSingleObject(stopEvent,0)!=WAIT_OBJECT_0) RecordError(ModuleError,NTW2_LOCO);
                return false;
            }
        }
        // After activation: the first arm happens at the first site-13 window close of this generation.
        if ((config.loco_flags&NTW2_LOCO_GRID_PROBATION) && !ProbationStart()) { RecordError(ModuleError,NTW2_LOCO); return false; }
    }
    if (mask & NTW2_FORMATION) {
        nfr_config c={NFR_ABI,sizeof(c),delta,world.root,world.model,config.workers,256,4096,64u<<20,4};
        if (!StartModule(formation,&c)) return false;
    }
    if (mask & NTW2_PATH) {
        npr_config c={NPR_ABI,sizeof(c),delta,world.root,world.model,world.path,
            clones.entries[NTW2_CLONE_PATH_SCHEDULER],config.workers,16,0,0,0,0,0,Address(&pool),4};
        if (!StartModule(path,&c)) return false;
    }
    if (mask & NTW2_BALLISTICS) {
        if (!records) records=static_cast<bal_record*>(VirtualAlloc(nullptr,sizeof(bal_record)*kProjectileCapacity,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if (!records) { RecordError(StorageError,GetLastError()); return false; }
        memset(&ballistic,0,sizeof(ballistic));
        ballistic.abi=BAL_ABI_VERSION; ballistic.capacity=kProjectileCapacity; ballistic.records=records;
        ballistic.prefix_entry=clones.entries[NTW2_CLONE_BAL_PREFIX];
        ballistic.orig_item=clones.entries[NTW2_CLONE_BAL_ITEM];
        ballistic.tail_va=ballistic.orig_item+NTW2_BAL_ITEM_TAIL_OFFSET;
        ballistic.one_ptr=V(0x1318048); ballistic.dispatch=FnAddress(&ntw_pool_dispatch);
        ballistic.dispatch_user=Address(&pool); ballistic.min_parallel=64; ballistic.chunk_items=32;
        ballistic.worker_entry=FnAddress(&bal_worker);
        nqc_config c={NQC_ABI,sizeof(c),delta,world.root,world.model,8192,32,FnAddress(&ntw_pool_dispatch),Address(&pool),
            clones.entries[NTW2_CLONE_QUERY],V(0x10e8500),V(0x10e7030),V(0x10e83e0),V(0x5db450),
            clones.entries[NTW2_CLONE_UNIT_HIT],V(0x809c00)};
        if (!StartModule(query,&c)) return false;
    }
    return true;
}

// NTW2_BRAIN: slot +0x0C of the 23 registry vtables (census: analysis/native-agent-loop-structure.md 2.1; every aligned table with
// [table+0x44]==0x64CC70). The loop 0x585D10 calls it once per active entity. Each slot publishes the entry site thunk of its family
// (the thunk times the call and runs the family clone); `original` is the exact value the slot must hold, or the install is refused.
U BrainEntryThunk(U site) {
    switch (site) {
    case 46: return FnAddress(&SiteCall46);
    case 47: return FnAddress(&SiteCall47);
    case 48: return FnAddress(&SiteCall48);
    case 49: return FnAddress(&SiteCall49);
    default: return FnAddress(&SiteCall50);
    }
}
void AddSlot(U address, U original, U replacement) { slots[slotCount++]={V(address),V(original),replacement,0,false,false}; }
bool FindVisualSlot(U& address) {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    if (!Read(imageBase,&dos,sizeof(dos)) || !Read(imageBase+dos.e_lfanew,&nt,sizeof(nt))) {
        RecordError(VisualSlotCount,0); return false;
    }
    const U sections=imageBase+dos.e_lfanew+offsetof(IMAGE_NT_HEADERS32,OptionalHeader)+nt.FileHeader.SizeOfOptionalHeader;
    U hits=0;
    for (U i=0;i<nt.FileHeader.NumberOfSections;++i) {
        IMAGE_SECTION_HEADER section;
        if (!Read(sections+i*sizeof(section),&section,sizeof(section))) {
            RecordError(VisualSlotCount,0); return false;
        }
        if (memcmp(section.Name,".rdata",7)!=0) continue;
        const U size=section.Misc.VirtualSize;
        if (section.VirtualAddress>imageSize || size>imageSize-section.VirtualAddress) {
            RecordError(VisualSlotCount,0); return false;
        }
        for (U offset=0;offset+4<=size;offset+=4) {
            U value=0;
            const U candidate=imageBase+section.VirtualAddress+offset;
            if (!Word(candidate,value)) { RecordError(SlotProtection,candidate); return false; }
            if (value==V(0x779e60)) { address=candidate; ++hits; }
        }
    }
    if (hits!=1) { RecordError(VisualSlotCount,hits); return false; }
    return true;
}
bool BuildSlots() {
    slotCount=0;
    if (config.enabled_mask & NTW2_BATCH64) AddSlot(0x1345374,0x78bac0,clones.entries[NTW2_CLONE_BATCH_WORKER]);
    if (config.enabled_mask & NTW2_FORMATION) {
        const U tables[]={0x13239b0,0x13239f0,0x1323a30,0x1323a70,0x1323ab0,0x1323af0};
        for (U table:tables) AddSlot(table+4,0x581200,clones.entries[NTW2_CLONE_FORM_COMMAND]);
    }
    if (config.enabled_mask & (kSimulation|NTW2_PROFILE)) AddSlot(0x132e954,0x5cc390,clones.entries[NTW2_CLONE_TASK]);
    if ((config.enabled_mask & (NTW2_PROFILE|NTW2_AI_ASYNC2)) || (config.ai_prepass_flags & (NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY_SHADOW|NTW2_AI_POLY))) AddSlot(0x133e2dc,0x702bb0,FnAddress(&WalkStateGate));
    // --ai-prepass-census: +0x10 of the ten node classes (pinned 0x7D7BF0) -> NodeThinkGate (clone only inside a site-34 scope on the
    // executing thread). --ai-presize: the only vtable word reaching 0x551FE0 (0x13247EC = 0x56A610) -> the PRESIZE clone chain.
    if (config.ai_prepass_flags & NTW2_AI_PREPASS_CENSUS)
        for (U i=0;i<ntw2_prepass::kNodeThinkSlotCount;++i)
            AddSlot(ntw2_prepass::kNodeThinkSlots[i],ntw2_prepass::kNodeThinkOriginal,ntw2_prepass::NodeThinkGateAddress());
    if (config.ai_prepass_flags & NTW2_AI_PRESIZE)
        AddSlot(ntw2_prepass::kPresizeSlot,ntw2_prepass::kPresizeSlotOriginal,clones.entries[NTW2_CLONE_PRESIZE_56A610]);
    // --army-storm-census route gates: the 0x581AE0 execute slot of the class-1325470 assignment command (R2) and the 0x617510 state-enter
    // that builds it (R1); both gates run the original unless the tick owner is inside a census epoch.
    if (config.va_watch_flags & (NTW2_ARMY_STORM_CENSUS|NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW)) {
        AddSlot(0x1325474,0x581ae0,FnAddress(&StormRoute2Gate));
        AddSlot(0x1331e74,0x617510,FnAddress(&StormRoute1Gate));
    }
    // --army-solver-memo/-shadow: the second R1 state-enter (0x1332110 = 0x611CF0), entered through SolverRoute1bGate (SOLVER_65D7D0 clone chain).
    if (config.va_watch_flags & (NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW)) AddSlot(0x1332110,0x611cf0,FnAddress(&SolverRoute1bGate));
    // NTW2_AI_ASYNC2 observer LOS route: slot 16 of 0x13376FC, routed by thread (Ai2ObserverRoute).
    if (config.enabled_mask & NTW2_AI_ASYNC2) AddSlot(0x13376fc+4*16,0x6a95a0,FnAddress(&Ai2ObserverGate));
    // --ai-poly* and --ai-prepass-census: the same slot, routed to the PS_* clone chain inside a site-34 scope (PsObserverRoute). Census-only
    // runs reach the AI_WALK clone through the timed SITE_CALL_40 thunk (PsWalkCall target), so the census observes the 0x808492 route.
    // --ai-spiral-*: the same PS_* route (its PS_LADDER/PS_SPIRAL forwarders count and cap), plus the fallback observer (0x7524A0) and
    // inline controller (0x826E80) counting gates; no other feature publishes those two words.
    if (config.ai_prepass_flags & (NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY_SHADOW|NTW2_AI_POLY|NTW2_AI_SPIRAL_BITS)) AddSlot(0x13376fc+4*16,0x6a95a0,FnAddress(&PsObserverGate));
    // --ai-record-test*: the alternate delegate class 0x13376AC, slot 16 (0x13376EC = 0x6A99E0), routed on the planner thread into PS_6A99E0.
    if (config.ai_prepass_flags & NTW2_AI_RECORD_TEST_BITS) AddSlot(0x13376ac+4*16,0x6a99e0,FnAddress(&PsAltObserverGate));
    // --ai-claim-once: the same fallback slot. With the spiral census the census gate stays in the slot and calls the claim-once gate as its native.
    if (config.ai_prepass_flags & NTW2_AI_SPIRAL_BITS) {
        AddSlot(ntw2_spiral::kFallbackSlot,ntw2_spiral::kFallbackOriginal,FnAddress(&ntw2_spiral::FallbackGate));
        AddSlot(ntw2_spiral::kControllerSlot,ntw2_spiral::kControllerOriginal,FnAddress(&ntw2_spiral::ControllerGate));
    } else if (config.ai_ctrl_flags & NTW2_AI_CLAIM_BITS) AddSlot(ntw2_claim_once::kFallbackSlot,ntw2_claim_once::kFallbackOriginal,FnAddress(&ntw2_claim_once::Gate));
    // --ai-formup-gate: the REFORM (2) / MOVE_TO_FORMUP (3) ATTACK_BATTLEGROUP state-class test + enter slots (mirror gates, pinned to the audited thunks; analysis/native-ai-formup-gate.md).
    if (config.ai_ctrl_flags & NTW2_AI_FORMUP_GATE) {
        AddSlot(ntw2_group_formup::kTest2Slot,ntw2_group_formup::kTest2Original,FnAddress(&ntw2_group_formup::TestGate2));
        AddSlot(ntw2_group_formup::kEnter2Slot,ntw2_group_formup::kEnter2Original,FnAddress(&ntw2_group_formup::EnterGate2));
        AddSlot(ntw2_group_formup::kTest3Slot,ntw2_group_formup::kTest3Original,FnAddress(&ntw2_group_formup::TestGate3));
        AddSlot(ntw2_group_formup::kEnter3Slot,ntw2_group_formup::kEnter3Original,FnAddress(&ntw2_group_formup::EnterGate3));
    }
    // --brain-target-cull* / --brain-retarget-jitter: the combat node step slot (0x1333E44 = 0x66D750) -> NodeStepGate (the clone runs only on the tick thread inside site 6).
    if (config.ai_ctrl_flags & NTW2_AI_BRAIN_STEP_BITS) AddSlot(ntw2_retarget_jitter::kVtableSlot,ntw2_retarget_jitter::kThunk,FnAddress(&NodeStepGate));
    // Keep original entry slots intact in BRAIN2 observe/census mode. Its optional
    // timing is independent of the older profiling-family slot publication.
    if ((config.enabled_mask & NTW2_BRAIN) && !(config.enabled_mask & NTW2_BRAIN2))
        for (const BrainTable& t:kBrainTables) AddSlot(t.table+kBrainSlotOffset,t.original,BrainEntryThunk(t.site));
    if (config.enabled_mask & NTW2_VISUAL) {
        U address=0;
        if (!FindVisualSlot(address)) return false;
        slots[slotCount++]={address,V(0x779e60),FnAddress(&VisualApplyThunk),0,false,false};
        visualWords[VwSlot]=address;
    }
    censusSlotFirst=censusSlotEnd=slotCount;
    if (config.enabled_mask & NTW2_AI_CENSUS) {
        // Observation-only vtable-slot gates: each word is pinned to its audited original, swapped atomically like every other slot.
        const ntw2_ai_census::Pin* pins=ntw2_ai_census::Pins();
        for (U i=0;i<ntw2_ai_census::kPinCount;++i)
            AddSlot(pins[i].vtable+4*pins[i].slot,pins[i].original,ntw2_ai_census::Gate(pins[i].target));
        censusSlotEnd=slotCount;
    }
    if (config.enabled_mask & NTW2_AI_ASYNC2) {
        // Join/marshal gates on the delegate replacement, destructor and command-callback slots (pinned originals).
        const ntw2_ai_async2::Pin* pins=ntw2_ai_async2::Pins();
        for (U i=0;i<ntw2_ai_async2::kPinCount;++i)
            if (pins[i].vtable) AddSlot(pins[i].vtable+4*pins[i].slot,pins[i].original,ntw2_ai_async2::Gate(i));
    }
    allocCensusSlotFirst=allocCensusSlotEnd=slotCount;
    if ((config.va_watch_flags & (NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) &&
        ((allocCensusRequestedMode ? allocCensusRequestedMode : ntw2_alloc_census::kModeCensus) & ntw2_alloc_census::kModeCensus)) {
        AddSlot(ntw2_alloc_census::kProviderAllocSlot,ntw2_alloc_census::kProviderAllocOriginal,ntw2_alloc_census::AllocGateAddress());
        AddSlot(ntw2_alloc_census::kProviderFreeSlot,ntw2_alloc_census::kProviderFreeOriginal,ntw2_alloc_census::FreeGateAddress());
        allocCensusSlotEnd=slotCount;
    }
    return true;
}
U CensusSlotsOwned() { // monitor thread only: census pins currently swapped in (slots are published/restored there)
    U owned=0;
    for (U i=censusSlotFirst;i<censusSlotEnd && i<slotCount;++i) if (slots[i].owned) ++owned;
    return owned;
}
U AllocCensusSlotsOwned() {
    U owned=0;
    for (U i=allocCensusSlotFirst;i<allocCensusSlotEnd && i<slotCount;++i) if (slots[i].owned) ++owned;
    return owned;
}
bool RestoreProtection(Slot& slot) {
    if (!slot.protectionDirty) return true;
    DWORD ignored=0;
    if (!VirtualProtect(reinterpret_cast<void*>(slot.address),4,slot.protection,&ignored)) {
        RecordError(SlotProtection,slot.address); return false;
    }
    slot.protectionDirty=false;
    return true;
}
bool SwapSlot(Slot& slot, bool install) {
    U current=0;
    if (!Word(slot.address,current)) { RecordError(SlotProtection,slot.address); return false; }
    const U expected=install ? slot.original : slot.replacement;
    const U replacement=install ? slot.replacement : slot.original;
    if (!install && current==slot.original) { slot.owned=false; return RestoreProtection(slot); }
    if (current!=expected) {
        if (!install) RestoreProtection(slot);
        RecordError(SlotConflict,slot.address); return false;
    }
    MEMORY_BASIC_INFORMATION memory={};
    if (!VirtualQuery(reinterpret_cast<void*>(slot.address),&memory,sizeof(memory)) || memory.State!=MEM_COMMIT ||
        memory.AllocationBase!=reinterpret_cast<void*>(imageBase) || (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS))) {
        RecordError(SlotProtection,slot.address); return false;
    }
    if (install && memory.Protect!=PAGE_READONLY) { RecordError(SlotProtection,slot.address); return false; }
    DWORD old=0;
    if (!VirtualProtect(reinterpret_cast<void*>(slot.address),4,PAGE_READWRITE,&old)) {
        RecordError(SlotProtection,slot.address); return false;
    }
    if (install) slot.protection=old;
    slot.protectionDirty=true;
    const U prior=static_cast<U>(_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(slot.address),
                                                           static_cast<LONG>(replacement),static_cast<LONG>(expected)));
    if (prior==expected) slot.owned=install;
    const bool protection=RestoreProtection(slot);
    if (prior!=expected) RecordError(SlotConflict,slot.address);
    return protection && prior==expected;
}
bool CaptureAtTick(void (*capture)(void*), void* context) {
    Slot* task=nullptr;
    for (U i=0;i<slotCount;++i) if (slots[i].address==V(0x132e954)) { task=&slots[i]; break; }
    if (!task || Load(&activationCapture.state) || WaitForSingleObject(stopEvent,0)==WAIT_OBJECT_0) return false;
    activationCapture.model=world.model;
    activationCapture.capture=capture;
    activationCapture.context=context;
    if (!task->owned && !SwapSlot(*task,true)) {
        activationCapture.capture=nullptr; activationCapture.context=nullptr; activationCapture.model=0;
        return false;
    }
    _InterlockedExchange(&activationCapture.state,1);
    const ULONGLONG deadline=GetTickCount64()+kStopTimeoutMs;
    bool completed=false;
    for (;;) {
        const LONG state=Load(&activationCapture.state);
        if (state==3) { completed=true; break; }
        if (state==1 && (GetTickCount64()>=deadline || WaitForSingleObject(stopEvent,0)==WAIT_OBJECT_0 ||
                         !BoundModel(world.model)) &&
            _InterlockedCompareExchange(&activationCapture.state,0,1)==1) break;
        // A running capture owns this stack context: it must complete before
        // cancellation/teardown can reclaim either the context or owned arenas.
        Sleep(1);
    }
    _InterlockedExchange(&activationCapture.state,0);
    activationCapture.capture=nullptr; activationCapture.context=nullptr; activationCapture.model=0;
    return completed;
}
void SampleCounters() {
    SampleVirtualMemory(false);
    SampleMemoryStorage();
    U chunks=0;
    if (poolReady) for (U i=0;i<pool.workers && i<NTW_POOL_MAX_WORKERS;++i) chunks+=pool.slots[i].chunks;
    StateBegin();
    PublishMemory();
    ntw2_state.active_mask=static_cast<U>(Load(&enabled))&~static_cast<U>(Load(&budgetDisabledMask));
    ntw2_state.tick=world.model ? WordOrZero(world.model+0x58) : 0;
    ntw2_state.path_completed=path.state ? path.state[NPR_S_CONSUMED] : 0;
    ntw2_state.formation_committed=formation.state ? formation.state[NFR_S_COMMITTED] : 0;
    ntw2_state.ballistic_committed=ballistic.st_committed;
    ntw2_state.collision_cache_hits=query.state ? query.state[NQC_S_CACHE_HITS] : 0;
    ntw2_state.worker_chunks=chunks+(formation.state ? formation.state[NFR_S_WORKER_CHUNKS] : 0);
    const U held=(formation.state ? formation.state[NFR_S_STORAGE_BYTES] : 0)+(query.state ? query.state[NQC_S_STORAGE_BYTES] : 0)+
        (pathStorage ? *pathStorage : 0)+
        (records ? sizeof(bal_record)*kProjectileCapacity : 0);
    ntw2_state.storage_bytes=held;
    ntw2_state.retained_bytes=held+clones.allocation_bytes;
    ntw2_state.path_fallbacks=path.state ? path.state[NPR_S_FALLBACKS] : 0;
    ntw2_state.path_refused=path.state ? path.state[NPR_S_REJECTED]+path.state[NPR_S_STALE] : 0;
    ntw2_state.formation_epochs=formation.state ? formation.state[NFR_S_EPOCHS] : 0;
    ntw2_state.formation_refused=formation.state ? formation.state[NFR_S_FALLBACKS]+formation.state[NFR_S_REJECTED] : 0;
    ntw2_state.ballistic_stages=ballistic.st_stages;
    for (U i=0;i<16;++i) {
        ntw2_state.formation_words[i]=formation.state ? formation.state[i] : 0;
        ntw2_state.query_words[i]=query.state ? query.state[i] : 0;
    }
    static_assert(NPR_STATE_WORDS<=24, "path words fit the status copy");
    for (U i=0;i<24;++i) ntw2_state.path_words[i]=(path.state && i<NPR_STATE_WORDS) ? path.state[i] : 0;
    const U balWords[8]={ballistic.st_stages,ballistic.st_items,ballistic.st_skip,ballistic.st_prefixed,
                         ballistic.st_committed,ballistic.st_rejected,ballistic.st_overflow,ballistic.st_unmatched};
    for (U i=0;i<8;++i) ntw2_state.ballistic_words[i]=balWords[i];
    static_assert(NFR_DIAG_WORDS==192 && sizeof(ntw2_state.formation_diag)==sizeof(U)*NFR_DIAG_WORDS,"formation_diag mirrors nfr_diag");
    for (U i=0;i<NFR_DIAG_WORDS;++i) ntw2_state.formation_diag[i]=formationDiag ? formationDiag[i] : 0;
    for (U i=0;i<16;++i) ntw2_state.sim_words[i]=simWords[i];
    for (U i=0;i<64;++i) ntw2_state.planner_words[i]=plannerWords[i];
    for (U i=0;i<3;++i) plannerWalkWords[12+i]=ntw2_walk_memo::counters[1+i];
    for (U i=0;i<16;++i) ntw2_state.planner_walk_words[i]=plannerWalkWords[i];
    for (U i=0;i<16;++i) ntw2_state.ai_words[i]=aiWords[i];
    for (U i=0;i<16;++i) ntw2_state.ai_ctrl_words[i]=aiCtrlWords[i];
    for (U i=0;i<32;++i) ntw2_state.ai_extra_words[i]=aiExtra[i];
    for (U i=0;i<8;++i) ntw2_state.ai_slice_words[i]=aiSliceWords[i];
    for (U i=0;i<2;++i) ntw2_state.ai_slice_site_words[i]=aiSliceSiteWords[i];
    for (U i=0;i<NTW2_AI_SLICE_BUDGET_WORDS;++i) ntw2_state.ai_slice_budget_words[i]=aiBudgetWords[i];
    for (U i=0;i<8;++i) ntw2_state.ai_park_words[i]=aiParkWords[i];
    for (U i=0;i<8;++i) ntw2_state.ai_validation_words[i]=aiValidationWords[i];
    for (U i=0;i<NTW2_AI_COMPLETION_WORDS;++i) ntw2_state.ai_completion_words[i]=aiCompletionWords[i];
    ntw2_ai_async2::Snapshot(ntw2_state.ai_async2_words);
    ntw2_ai_async2::RouteSnapshot(ntw2_state.ai_async2_route_words);
    ntw2_ai_async2::DeferredSnapshot(ntw2_state.ai_deferred_words);
    ntw2_state.ai_slice_words[AsParked]=0; // no OS suspension, including while idle
    ntw2_state.ai_slice_words[AsThread]=aiThreadId;
    for (U i=0;i<NTW2_BRAIN_WORDS;++i) ntw2_state.brain_words[i]=brainWords[i];
    for (U i=0;i<NTW2_BRAIN_STATE_WORDS;++i) ntw2_state.brain_state_words[i]=brainStateWords[i];
    for (U i=0;i<NTW2_COLLISION_WORDS;++i) ntw2_state.collision_words[i]=collisionWords[i];
    // Keep the last completed owned-stage counters after emergency retirement.
    if(!budgetRetired) {
        U collideWords[NTW2_COLLIDE_WORDS]={};
        static_assert(ntw2_collide::WordCount==NTW2_COLLIDE_WORDS, "solver status word contract");
        if ((config.enabled_mask&NTW2_COLLIDE) && collideSampleReady) ntw2_collide::Sample(collideWords);
        for (U i=0;i<NTW2_COLLIDE_WORDS;++i) ntw2_state.collide_words[i]=collideWords[i];
        U collideSourceWords[NTW2_COLLIDE_SOURCE_WORDS]={};
        static_assert(ntw2_collide::SourceWordCount==NTW2_COLLIDE_SOURCE_WORDS, "collision source status word contract");
        if ((config.enabled_mask&NTW2_COLLIDE) && collideSampleReady) ntw2_collide::SampleSource(collideSourceWords);
        for (U i=0;i<NTW2_COLLIDE_SOURCE_WORDS;++i) ntw2_state.collide_source_words[i]=collideSourceWords[i];
        U contactWords[NTW2_COLLIDE_CONTACT_WORDS]={};
        static_assert(ntw2_contact::WordCount==NTW2_COLLIDE_CONTACT_WORDS, "contact response status word contract");
        if ((config.enabled_mask&NTW2_COLLIDE) && config.collide_flags && collideSampleReady) ntw2_contact::Sample(contactWords);
        for (U i=0;i<NTW2_COLLIDE_CONTACT_WORDS;++i) ntw2_state.collide_contact_words[i]=contactWords[i];
        U locoWords[NTW2_LOCO_WORDS]={}, locoGateWords[NTW2_LOCO_GATE_WORDS]={};
        U locoServiceWords[NTW2_LOCO_SERVICE_WORDS]={};
        U locoGridWords[NTW2_LOCO_GRID_WORDS]={}, locoParallelWords[NTW2_LOCO_PARALLEL_WORDS]={};
        U sweepWords[NTW2_SWEEP_WORDS]={}, resolveWords[NTW2_RESOLVE_WORDS]={};
        U envWords[NTW2_ENV_WORDS]={}, envTargetWords[NTW2_ENV_TARGET_WORDS]={};
        U resolveFrameWords[NTW2_RESOLVE_FRAME_WORDS]={};
        U locoOwnedWords[NTW2_LOCO_OWNED_WORDS]={};
        U locoOwnedDetailWords[NTW2_LOCO_OWNED_DETAIL_WORDS]={};
        U locoOwnedPhaseWords[NTW2_LOCO_OWNED_PHASE_WORDS]={};
        U locoOwnedLoadWords[NTW2_LOCO_OWNED_LOAD_WORDS]={};
        U locoGridV2Words[NTW2_LOCO_GRID_V2_WORDS]={};
        U locoRelinkWords[NTW2_LOCO_RELINK_WORDS]={};
        U locoCwWords[NTW2_LOCO_CW_WORDS]={};
        U locoGridBuildWords[NTW2_LOCO_GRID_BUILD_WORDS]={};
        static_assert(ntw2_loco::GridBuildWordCount==NTW2_LOCO_GRID_BUILD_WORDS, "loco grid build status word contract");
        static_assert(ntw2_loco::WordCount==NTW2_LOCO_WORDS, "loco status word contract");
        static_assert(ntw2_loco::GateWordCount==NTW2_LOCO_GATE_WORDS, "loco all-gates status word contract");
        static_assert(ntw2_loco::ServiceWordCount==NTW2_LOCO_SERVICE_WORDS, "loco service timing status word contract");
        static_assert(ntw2_loco::GridWordCount==NTW2_LOCO_GRID_WORDS, "loco grid status word contract");
        static_assert(ntw2_loco::GridV2WordCount==NTW2_LOCO_GRID_V2_WORDS, "loco grid v2 status word contract");
        static_assert(ntw2_loco::RelinkWordCount==NTW2_LOCO_RELINK_WORDS, "loco relink status word contract");
        static_assert(ntw2_loco::CwWordCount==NTW2_LOCO_CW_WORDS, "loco class-wrapper census status word contract");
        static_assert(ntw2_loco::ParallelWordCount==NTW2_LOCO_PARALLEL_WORDS, "loco parallel status word contract");
        static_assert(ntw2_sweep::WordCount==NTW2_SWEEP_WORDS && ntw2_resolve::WordCount==NTW2_RESOLVE_WORDS, "shadow status word contract");
        static_assert(ntw2_env::WordCount==NTW2_ENV_WORDS && NTW2_ENV_TARGET_WORDS==64, "environment shadow status word contract");
        static_assert(ntw2_resolve::FrameWordCount==NTW2_RESOLVE_FRAME_WORDS, "resolve frame status word contract");
        static_assert(ntw2_loco::OwnedWordCount==NTW2_LOCO_OWNED_WORDS, "loco owned-service status word contract");
        static_assert(ntw2_loco::OwnedDetailWordCount==NTW2_LOCO_OWNED_DETAIL_WORDS, "loco owned-service detail status word contract");
        static_assert(ntw2_loco::OwnedPhaseWordCount==NTW2_LOCO_OWNED_PHASE_WORDS, "loco owned phase status word contract");
        static_assert(ntw2_loco::OwnedLoadWordCount==NTW2_LOCO_OWNED_LOAD_WORDS, "loco owned load status word contract");
        if ((config.enabled_mask&NTW2_LOCO) && locoSampleReady) {
            ntw2_loco::Sample(locoWords);
            ntw2_loco::SampleGates(locoGateWords);
            ntw2_loco::SampleServices(locoServiceWords);
            ntw2_loco::SampleGrid(locoGridWords);
            ntw2_loco::SampleGridV2(locoGridV2Words);
            ntw2_loco::SampleRelink(locoRelinkWords);
            ntw2_loco::SampleClassWrapper(locoCwWords);
            ntw2_loco::SampleParallel(locoParallelWords);
            ntw2_sweep::Sample(sweepWords);
            ntw2_resolve::Sample(resolveWords);
            ntw2_env::Sample(envWords, envTargetWords);
            ntw2_resolve::SampleFrames(resolveFrameWords);
            ntw2_loco::SampleOwned(locoOwnedWords);
            ntw2_loco::SampleOwnedDetails(locoOwnedDetailWords);
            ntw2_loco::SampleOwnedPhase(locoOwnedPhaseWords);
            ntw2_loco::SampleOwnedLoad(locoOwnedLoadWords);
        }
        for (U i=0;i<NTW2_LOCO_WORDS;++i) ntw2_state.loco_words[i]=locoWords[i];
        for (U i=0;i<NTW2_LOCO_GATE_WORDS;++i) ntw2_state.loco_gate_words[i]=locoGateWords[i];
        for (U i=0;i<NTW2_LOCO_SERVICE_WORDS;++i) ntw2_state.loco_service_words[i]=locoServiceWords[i];
        for (U i=0;i<NTW2_LOCO_GRID_WORDS;++i) ntw2_state.loco_grid_words[i]=locoGridWords[i];
        for (U i=0;i<NTW2_LOCO_PARALLEL_WORDS;++i) ntw2_state.loco_parallel_words[i]=locoParallelWords[i];
        for (U i=0;i<NTW2_SWEEP_WORDS;++i) ntw2_state.sweep_words[i]=sweepWords[i];
        for (U i=0;i<NTW2_RESOLVE_WORDS;++i) ntw2_state.resolve_words[i]=resolveWords[i];
        for (U i=0;i<NTW2_ENV_WORDS;++i) ntw2_state.env_words[i]=envWords[i];
        for (U i=0;i<NTW2_ENV_TARGET_WORDS;++i) ntw2_state.env_target_words[i]=envTargetWords[i];
        for (U i=0;i<NTW2_RESOLVE_FRAME_WORDS;++i) ntw2_state.resolve_frame_words[i]=resolveFrameWords[i];
        for (U i=0;i<NTW2_LOCO_OWNED_WORDS;++i) ntw2_state.loco_owned_words[i]=locoOwnedWords[i];
        for (U i=0;i<NTW2_LOCO_OWNED_DETAIL_WORDS;++i) ntw2_state.loco_owned_detail_words[i]=locoOwnedDetailWords[i];
        for (U i=0;i<NTW2_LOCO_OWNED_PHASE_WORDS;++i) ntw2_state.loco_owned_phase_words[i]=locoOwnedPhaseWords[i];
        for (U i=0;i<NTW2_LOCO_OWNED_LOAD_WORDS;++i) ntw2_state.loco_owned_load_words[i]=locoOwnedLoadWords[i];
        for (U i=0;i<NTW2_LOCO_GRID_V2_WORDS;++i) ntw2_state.loco_grid_v2_words[i]=locoGridV2Words[i];
        for (U i=0;i<NTW2_LOCO_RELINK_WORDS;++i) ntw2_state.loco_relink_words[i]=locoRelinkWords[i];
        for (U i=0;i<NTW2_LOCO_CW_WORDS;++i) ntw2_state.loco_cw_words[i]=locoCwWords[i];
        for (U i=0;i<NTW2_LOCO_GRID_BUILD_WORDS;++i) ntw2_state.loco_grid_build_words[i]=locoGridBuildWords[i];
    }
    ntw2_brain2::Snapshot(const_cast<U*>(ntw2_state.brain2_words));
    ntw2_brain2::CensusSnapshot(const_cast<U*>(ntw2_state.brain2_census_words));
    ntw2_node::Snapshot(const_cast<U*>(ntw2_state.node_words));
    ntw2_node::EventSnapshot(const_cast<U*>(ntw2_state.node_event_words));
    ntw2_fire::Sample(const_cast<U*>(ntw2_state.fire_words));
    ntw2_brain2::RouteSnapshot(const_cast<U*>(ntw2_state.brain2_route_words));
    ntw2_fire::SampleCommit(const_cast<U*>(ntw2_state.fire_commit_words));
    ntw2_move_node::Snapshot(const_cast<U*>(ntw2_state.move_node_words));
    ntw2_move_node::EventSnapshot(const_cast<U*>(ntw2_state.move_node_event_words));
    ntw2_brain2::NodeTargetSnapshot(const_cast<U*>(ntw2_state.brain2_node_target_words));
    ntw2_brain2::UnknownSiteSnapshot(const_cast<U*>(ntw2_state.brain2_unknown_site_words));
    ntw2_brain_workers::Snapshot(const_cast<U*>(ntw2_state.brain_worker_words));
    ntw2_brain_workers::PhaseSnapshot(const_cast<U*>(ntw2_state.brain_worker_phase_words));
    ntw2_unit_brain::Snapshot(const_cast<U*>(ntw2_state.brain_unit_words));
    ntw2_army_unit::Snapshot(const_cast<U*>(ntw2_state.army_unit_words));
    ntw2_army_unit::SnapshotB0(const_cast<U*>(ntw2_state.army_b0_words));
    SnapshotArmyStorm();
    SnapshotArmySolver();
    SnapshotBrainRow();
    SnapshotUnitPolicy();
    SnapshotAiCtrl();
    for (U cls=0;cls<NTW2_IDLE_NODE_CLASSES;++cls) {
        ntw2_idle_node::Snapshot(cls,const_cast<U*>(ntw2_state.idle_node_words[cls]));
        ntw2_idle_node::EventSnapshot(cls,const_cast<U*>(ntw2_state.idle_node_event_words[cls]));
    }
    for (U cls=0;cls<NTW2_ACTION_NODE_CLASSES;++cls) {
        ntw2_action_node::Snapshot(cls,const_cast<U*>(ntw2_state.action_node_words[cls]));
        ntw2_action_node::EventSnapshot(cls,const_cast<U*>(ntw2_state.action_node_event_words[cls]));
    }
    for (U i=0;i<NTW2_COLLIDE_LOD_WORDS;++i) ntw2_state.collide_lod_words[i]=lodWords[i];
    ntw2_brain2::DiagSnapshot(const_cast<U*>(ntw2_state.brain2_reason_words),const_cast<U*>(ntw2_state.brain2_gate_words));
    for (U i=0;i<32;++i) ntw2_state.visual_words[i]=visualWords[i];
    PublishAllocatorStatus();
    ntw2_arena_release::Sample(const_cast<U*>(ntw2_state.arena_words));
    if (config.va_watch_flags&NTW2_ENGAGE_CENSUS) ntw2_engage_census::Snapshot(ntw2_state.engage_census_words);
    // The tick-only histogram follows whichever thread currently executes the tick (gate word = that thread id).
    if (config.enabled_mask&NTW2_GRID_CENSUS) ntw2_grid_census_snapshot(&ntw2_state.grid_census);
    if (config.loco_flags&NTW2_LOCO_GRID_PROBATION) ntw2_grid_probation::Snapshot(const_cast<U*>(ntw2_state.grid_probation_words));
    if (config.enabled_mask&NTW2_AI_CENSUS) ntw2_ai_census::Snapshot(ntw2_state.ai_census_words,CensusSlotsOwned());
    if (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) ntw2_alloc_census::Snapshot(ntw2_state.alloc_census_words,AllocCensusSlotsOwned(),false);
    StateEnd();
    RetireBudgetOwned();
}
bool StopModules() {
    const ULONGLONG deadline=GetTickCount64()+kStopTimeoutMs;
    while (Load(&tickOwner) || Load(&visualOwner)) {
        if (GetTickCount64()>=deadline) { RecordError(StopTimeout,0); return false; }
        Sleep(1);
    }
    Module* modules[]={&path,&query,&formation};
    bool all=true;
    for (Module* module:modules) {
        while (module->ready) {
            const U error=module->stop(nullptr);
            if (!error) { module->ready=false; break; }
            if ((error&0xff)!=module->busy) { RecordError(ModuleError,(module->feature<<24)|(error&0xffffff)); all=false; break; }
            if (GetTickCount64()>=deadline) { RecordError(StopTimeout,module->feature); all=false; break; }
            Sleep(1);
        }
    }
    {   // Arena memory is freed only when the battle world is gone: a world that merely went dormant (the scheduler flag drops at >1x
        // playback) keeps rendering from the same pose/scene/scratch blocks and its live per-frame mesh items point into them.
        const U savedProbe=probe; World now; bool asynchronousNow=false;
        const bool worldAlive=FindWorld(now,asynchronousNow) && SameWorld(world,now);
        probe=savedProbe; // FindWorld records its failure reason; the monitor owns that word
        ntw2_arena_release::Stop(!worldAlive ? ntw2_arena_release::StopMode::Release :
                                 arenaKeepHooks ? ntw2_arena_release::StopMode::KeepHooks : ntw2_arena_release::StopMode::Detach);
    }
    SampleCounters();
    ntw2_collide::Stop(); // tick owner and every synchronous solver dispatch have drained; counters retained
    ntw2_army_unit::Stop(); // the tick owner has drained; counters are retained (sampled above)
    ntw2_army_storm::Stop();
    ntw2_army_solver::Stop(); // same drain: the final counters stay published
    if (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) {
        ntw2_alloc_census::ReclaimTick(world.model);
        ntw2_alloc_census::Stop();
        StateBegin(); ntw2_alloc_census::Snapshot(ntw2_state.alloc_census_words,0,true); StateEnd();
    }
    if (locoRunning) { ntw2_loco::Stop(); locoRunning=false; } // the single participant is the drained tick owner; final counters stay sampled
    if (probationRunning) { // pages restored and handler removed: publish the final detector totals
        ProbationStop();
        StateBegin(); ntw2_grid_probation::Snapshot(const_cast<U*>(ntw2_state.grid_probation_words)); StateEnd();
    }
    CollideLodStop();
    if (all && poolOwned) {
        poolReady=false;
        const U error=ntw_pool_shutdown(&pool);
        if (error) { RecordError(PoolError,error); all=false; }
        else poolOwned=false;
    }
    return all;
}
bool Ai2ReceiversValid() { return world.model && BoundModel(world.model); }
bool Deactivate() {
    // NTW2_AI_ASYNC2 first, while ticks are still routed: its tick-start join is the servicing path of a worker call
    // posted in the inter-tick window. Quiesce closes admission and drains (servicing or aborting on this thread when
    // no tick comes) before routing stops; otherwise the worker's borrowed frame would stay blocked forever.
    const bool ai2Quiet=ntw2_ai_async2::Quiesce(500,kStopTimeoutMs,&Ai2ReceiversValid);
    _InterlockedExchange(&enabled,0);
    Phase(NTW2_RESTORING);
    bool ok=true;
    if (!ai2Quiet) { RecordError(StopTimeout,NTW2_AI_ASYNC2); return false; }
    if (!AiDrain()) return false; // the tick's lifetime barrier must release every native AI frame first
    for (U i=slotCount;i;--i)
        if ((slots[i-1].owned || slots[i-1].protectionDirty) && !SwapSlot(slots[i-1],false)) ok=false;
    if (!StopModules()) ok=false;
    ntw2_poly::Release(); // --ai-poly*: slots are restored and the AI worker drained; a thread somehow still inside keeps its buffer (Release never frees an in-flight evaluation)
    if (ok) {
        siteCallees[6]=V(0x585d10); // drained: no dispatcher remains bound outside an active generation
        siteCallees[5]=V(0x57dc30);
        siteCallees[106]=V(0x81a790);
        siteCallees[33]=V(0x7C8BD0);
        siteCallees[13]=V(0x531af0);
        siteCallees[18]=clones.entries[NTW2_CLONE_ARMY_UPDATE];
        siteCallees[101]=siteCallees[103]=V(0x581f30);
        _InterlockedExchange(&ai2Armed,0);
        collisionCensusEnabled=0;
        world={};
        StateBegin(); ntw2_state.root=0; ntw2_state.model=0; ntw2_state.active_mask=0; StateEnd();
    }
    return ok;
}
bool Activate(const World& candidate) {
    world=candidate;
    // The planner site is timed through SiteCall34 either way; only its callee changes with the feature.
    aiPlannerClone=clones.entries[NTW2_CLONE_PLANNER];
    siteCallees[kPlannerSite]=(config.enabled_mask&NTW2_AI_ASYNC2) ? FnAddress(&Planner2Gate) :
        (config.enabled_mask&NTW2_AI_ASYNC) ? FnAddress(&PlannerGate) : aiPlannerClone;
    // --ai-ctrl-*: site 33 runs the AI_CONTROLLER clone, whose rebuild gate is retargeted to the AI_CTRL_REBUILD clone (the census
    // gate keeps counting). Reset -> geometry Configure (registers its retire) precede the first batch.
    const U aiCtrl=config.ai_ctrl_flags&NTW2_AI_CTRL_MODE_MASK; // bit 8 is --ai-claim-once, not an --ai-ctrl mode
    ntw2_ai_ctrl::Reset(aiCtrl,delta,clones.entries[NTW2_CLONE_AI_CTRL_SCORER]);
    ntw2_ai_ctrl_geometry::Reset();
    ntw2_ai_ctrl_geometry::Configure((aiCtrl&NTW2_AI_CTRL_CENSUS)!=0,(aiCtrl&NTW2_AI_CTRL_GEOMETRY)!=0,(aiCtrl&NTW2_AI_CTRL_VERIFY)!=0);
    ntw2_ai_census::Retarget(6,aiCtrl ? clones.entries[NTW2_CLONE_AI_CTRL_REBUILD] : V(0x7492F0));
    aiControllerOriginal=((config.enabled_mask&NTW2_AI_CENSUS) || aiCtrl) ? clones.entries[NTW2_CLONE_AI_CONTROLLER] : V(0x7C8BD0);
    siteCallees[33]=(config.enabled_mask&NTW2_AI_CTRL) ? FnAddress(&ControllerGate) :
        (config.enabled_mask&NTW2_AI_ASYNC2) ? FnAddress(&Ai2ControllerGate) : aiControllerOriginal;
    _InterlockedExchange(&ai2Armed,(config.enabled_mask&NTW2_AI_ASYNC2) ? 1 : 0);
    // --ai-prepass-*: counters and tables are cleared before BuildSlots publishes the node/presize slots.
    static_assert(ntw2_prepass::kFlagCensus==NTW2_AI_PREPASS_CENSUS && ntw2_prepass::kFlagPresize==NTW2_AI_PRESIZE, "prepass flag bits");
    {
        LARGE_INTEGER frequency; QueryPerformanceFrequency(&frequency);
        const ntw2_prepass::Targets targets={V(0x7d7bf0),clones.entries[NTW2_CLONE_AI_THINK],clones.entries[NTW2_CLONE_AI_SHAPE_SEARCH],&PlannerScopeThread,
                                             clones.entries[NTW2_CLONE_PS_808040]}; // the sibling's observer-route clone of 0x808040 (walk site 0x808492)
        ntw2_prepass::CensusReset(config.ai_prepass_flags&(NTW2_AI_PREPASS_CENSUS|NTW2_AI_PRESIZE),targets,frequency.QuadPart);
    }
    // --ai-poly*: configure/reset the row before BuildSlots publishes the observer slot. The kernel gate replaces the walk memo at the timed
    // site 44 (R2/R3 AI_WALK clones); the PS_WALK clone calls the same gate through the bare PS_POLY binding.
    {
        const U polyBits=config.ai_prepass_flags&(NTW2_AI_POLY_SHADOW|NTW2_AI_POLY);
        ntw2_poly::Configure(reinterpret_cast<ntw2_poly::Native>(V(0x80dcf0)),
                             polyBits==NTW2_AI_POLY ? ntw2_poly::ModeLive : polyBits ? ntw2_poly::ModeShadow : ntw2_poly::ModeOff);
        siteCallees[44]=polyBits ? FnAddress(&ntw2_poly::Gate) : FnAddress(&ntw2_walk_memo::kernel);
        // Spiral-only runs keep the native walk on the PS_808040 0x808492 call.
        psWalkTarget=polyBits ? clones.entries[NTW2_CLONE_PS_WALK] : (config.ai_prepass_flags&NTW2_AI_PREPASS_CENSUS) ? FnAddress(&SiteCall40) : V(0x7f1d40);
        // --ai-record-test*: arm after the poly Configure (it calibrates the TSC the record-test row copies); disarmed Entry forwards to 0x6A99E0.
        const U recordBits=config.ai_prepass_flags&NTW2_AI_RECORD_TEST_BITS;
        ntw2_record_test::Configure(recordBits==NTW2_AI_RECORD_TEST ? ntw2_record_test::ModeLive : recordBits ? ntw2_record_test::ModeShadow : ntw2_record_test::ModeOff,
                                    clones.entries[NTW2_CLONE_PS_6A99E0],V(0x6a99e0),ntw2_poly::words[31]);
    }
    // --ai-spiral-*: reset the row and point the forwarders/gates at their callees before BuildSlots publishes the slots.
    {
        const ntw2_spiral::Targets targets={clones.entries[NTW2_CLONE_PS_6C71D0],clones.entries[NTW2_CLONE_PS_6CC730],
                                            clones.entries[NTW2_CLONE_PS_7FCA40],clones.entries[NTW2_CLONE_PS_808040],
                                            (config.ai_ctrl_flags&NTW2_AI_CLAIM_BITS) ? FnAddress(&ntw2_claim_once::Gate) : V(ntw2_spiral::kFallbackOriginal),
                                            V(ntw2_spiral::kControllerOriginal),&PsScopeThread};
        ntw2_spiral::Configure((config.ai_prepass_flags&NTW2_AI_SPIRAL_BITS)!=0,config.ai_prepass_flags>>NTW2_AI_SPIRAL_CAP_SHIFT,targets);
    }
    {
        const ntw2_claim_once::Targets targets={V(ntw2_claim_once::kFallbackOriginal),V(ntw2_claim_once::kEligible),V(ntw2_claim_once::kClaim),V(ntw2_claim_once::kPost),
                                                V(ntw2_claim_once::kMemoState),V(ntw2_claim_once::kRecompute),V(ntw2_claim_once::kWorkingList),&PsScopeThread};
        ntw2_claim_once::Configure((config.ai_ctrl_flags&NTW2_AI_CLAIM_ONCE) ? ntw2_claim_once::ModeOnce :
                                   (config.ai_ctrl_flags&NTW2_AI_CLAIM_ONCE_CENSUS) ? ntw2_claim_once::ModeCensus : ntw2_claim_once::ModeOff,targets);
    }
    {
        // --ai-formup-gate: the four ATTACK_BATTLEGROUP REFORM / MOVE_TO_FORMUP state-class slots (tests + enters); the gate is armed here, the slots are published by BuildSlots.
        namespace gf=ntw2_group_formup;
        const gf::Targets targets={V(gf::kReformExit),V(gf::kReformAlt),V(gf::kFormupExit),V(gf::kFormupAlt),V(gf::kFormupAlt2),V(gf::kPoseToVec),V(gf::kMoveVtable),
                                   V(gf::kTest2Original),V(gf::kEnter2Original),V(gf::kTest3Original),V(gf::kEnter3Original),&PsScopeThread};
        const gf::Params params={config.ai_group_params&NTW2_AI_FORMUP_PCT_MASK,(config.ai_group_params&NTW2_AI_FORMUP_METRES_MASK)>>NTW2_AI_FORMUP_METRES_SHIFT,
                                 config.ai_group_params>>NTW2_AI_FORMUP_TIMEOUT_SHIFT};
        gf::Configure((config.ai_ctrl_flags&NTW2_AI_FORMUP_GATE)!=0,params,targets);
    }
    {
        // The mirror's search call: --brain-target-cull(-shadow) substitutes its 0x553420 replacement here (same ABI).
        const bool cull=(config.ai_ctrl_flags&(NTW2_AI_TARGET_CULL_SHADOW|NTW2_AI_TARGET_CULL))!=0;
        const ntw2_retarget_jitter::Targets targets={V(ntw2_retarget_jitter::kValid),V(ntw2_retarget_jitter::kClear),
                                                     cull ? FnAddress(&ntw2_target_cull::Search) : V(ntw2_retarget_jitter::kSearch),
                                                     V(ntw2_retarget_jitter::kSecond),V(ntw2_retarget_jitter::kThird),V(ntw2_retarget_jitter::kAssign)};
        namespace tc=ntw2_target_cull;
        const tc::Targets cullTargets={V(tc::kSearch),V(tc::kLoop),V(tc::kFlagState),V(tc::kAlive),V(tc::kReach),V(tc::kScore),V(tc::kKindDist),V(tc::kSettings),
                                       V(tc::kScratch),V(tc::kGuard),V(tc::kTlsIndex),V(tc::kInitHeader),V(tc::kAtexit),V(tc::kAtexitArg),V(tc::kInitFooter),
                                       V(tc::kU32Table),V(tc::kMaxFloat)};
        tc::Configure((config.ai_ctrl_flags&NTW2_AI_TARGET_CULL) ? tc::ModeLive : (config.ai_ctrl_flags&NTW2_AI_TARGET_CULL_SHADOW) ? tc::ModeShadow : tc::ModeOff,cullTargets);
        ntw2_retarget_jitter::Configure((config.ai_ctrl_flags&NTW2_AI_RETARGET_JITTER)!=0,targets);
        nodeStepClone=clones.entries[NTW2_CLONE_STEP_676FD0]; nodeStepOriginal=V(ntw2_retarget_jitter::kThunk);
    }
    // Site 6 (the ACTIVE clone's call of the entity loop 0x585D10) stays timed either way; only its callee changes with the feature.
    siteCallees[6]=(config.enabled_mask&NTW2_BRAIN2) ? FnAddress(&BrainKernelGate) : V(0x585d10);
    siteCallees[13]=(config.enabled_mask&NTW2_LOCO) ? FnAddress(&LocoMoveGate) : V(0x531af0);
    const bool armyUnit=(config.enabled_mask&NTW2_ARMY_UNIT_SHADOW)!=0;
    const bool armyStorm=(config.va_watch_flags&NTW2_ARMY_STORM_CENSUS)!=0; // exclusive with armyUnit (validated)
    siteCallees[18]=armyUnit ? FnAddress(&ArmyStageGate) : clones.entries[NTW2_CLONE_ARMY_UPDATE];
    siteCallees[101]=armyUnit ? FnAddress(&ArmyUnitGateMain) : armyStorm ? FnAddress(&StormUnitGateMain) : V(0x581f30);
    siteCallees[103]=armyUnit ? FnAddress(&ArmyUnitGateAlternate) : armyStorm ? FnAddress(&StormUnitGateAlternate) : V(0x581f30);
    CollideLodReset();
    siteCallees[5]=(config.enabled_mask&(NTW2_PROFILE|NTW2_COLLIDE|NTW2_COLLIDE_LOD)) ? FnAddress(&CollisionStageGate) : V(0x57dc30);
    collisionCensusEnabled=(config.collide_lod_m&NTW2_COLLIDE_CENSUS) &&
        (config.enabled_mask&NTW2_PROFILE) && !(config.enabled_mask&NTW2_COLLIDE);
    siteCallees[106]=collisionCensusEnabled ? clones.entries[NTW2_CLONE_COLLIDE_Q] : V(0x81a790);
    StateBegin(); ntw2_state.root=world.root; ntw2_state.model=world.model; ntw2_state.phase=NTW2_ACTIVATING; StateEnd();
    if (!BuildSlots() || !VirtualBudget(0,true) || !PrepareActivationWorkload() || !StartModules() ||
        !VirtualBudget(0,false,true)) { Deactivate(); return false; }
    SampleMemoryStorage();
    StateBegin();
    PublishMemory();
    // Selection metadata must be visible in the same publication as ACTIVE.
    ntw2_brain2::RouteSnapshot(const_cast<U*>(ntw2_state.brain2_route_words));
    ntw2_move_node::Snapshot(const_cast<U*>(ntw2_state.move_node_words));
    ntw2_move_node::EventSnapshot(const_cast<U*>(ntw2_state.move_node_event_words));
    ntw2_brain2::NodeTargetSnapshot(const_cast<U*>(ntw2_state.brain2_node_target_words));
    ntw2_brain2::UnknownSiteSnapshot(const_cast<U*>(ntw2_state.brain2_unknown_site_words));
    ntw2_brain_workers::Snapshot(const_cast<U*>(ntw2_state.brain_worker_words));
    ntw2_brain_workers::PhaseSnapshot(const_cast<U*>(ntw2_state.brain_worker_phase_words));
    ntw2_unit_brain::Snapshot(const_cast<U*>(ntw2_state.brain_unit_words));
    ntw2_army_unit::Snapshot(const_cast<U*>(ntw2_state.army_unit_words));
    ntw2_army_unit::SnapshotB0(const_cast<U*>(ntw2_state.army_b0_words));
    SnapshotArmyStorm();
    SnapshotArmySolver();
    SnapshotBrainRow();
    SnapshotUnitPolicy();
    SnapshotAiCtrl();
    for (U cls=0;cls<NTW2_IDLE_NODE_CLASSES;++cls) {
        ntw2_idle_node::Snapshot(cls,const_cast<U*>(ntw2_state.idle_node_words[cls]));
        ntw2_idle_node::EventSnapshot(cls,const_cast<U*>(ntw2_state.idle_node_event_words[cls]));
    }
    for (U cls=0;cls<NTW2_ACTION_NODE_CLASSES;++cls) {
        ntw2_action_node::Snapshot(cls,const_cast<U*>(ntw2_state.action_node_words[cls]));
        ntw2_action_node::EventSnapshot(cls,const_cast<U*>(ntw2_state.action_node_event_words[cls]));
    }
    for (U i=0;i<NTW2_COLLIDE_WORDS;++i) ntw2_state.collide_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_SOURCE_WORDS;++i) ntw2_state.collide_source_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_CONTACT_WORDS;++i) ntw2_state.collide_contact_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_LOD_WORDS;++i) ntw2_state.collide_lod_words[i]=0;
    for (U i=0;i<NTW2_ALLOC_CENSUS_WORDS;++i) ntw2_state.alloc_census_words[i]=0;
    if (config.va_watch_flags&(NTW2_ALLOC_CENSUS|NTW2_ALLOC_FIX)) {
        const U mode=allocCensusRequestedMode ? allocCensusRequestedMode : ntw2_alloc_census::kModeCensus;
        ntw2_alloc_census::Snapshot(ntw2_state.alloc_census_words,(mode&ntw2_alloc_census::kModeCensus) ? ntw2_alloc_census::kSlotCount : 0u,true);
    }
    for (U i=0;i<NTW2_ARENA_WORDS;++i) ntw2_state.arena_words[i]=0;
    for (U i=0;i<NTW2_OVERLAY_WORDS;++i) ntw2_state.overlay_words[i]=0;
    // Publish all LOCO row metadata with activation, not a later poll.
    if (locoRunning) {
        ntw2_loco::Sample(const_cast<U*>(ntw2_state.loco_words));
        ntw2_loco::SampleGates(const_cast<U*>(ntw2_state.loco_gate_words));
        ntw2_loco::SampleServices(const_cast<U*>(ntw2_state.loco_service_words));
        ntw2_loco::SampleGrid(const_cast<U*>(ntw2_state.loco_grid_words));
        ntw2_loco::SampleGridV2(const_cast<U*>(ntw2_state.loco_grid_v2_words));
        ntw2_loco::SampleRelink(const_cast<U*>(ntw2_state.loco_relink_words));
        ntw2_loco::SampleClassWrapper(const_cast<U*>(ntw2_state.loco_cw_words));
        ntw2_loco::SampleGridBuild(const_cast<U*>(ntw2_state.loco_grid_build_words));
        ntw2_loco::SampleParallel(const_cast<U*>(ntw2_state.loco_parallel_words));
        ntw2_sweep::Sample(const_cast<U*>(ntw2_state.sweep_words));
        ntw2_resolve::Sample(const_cast<U*>(ntw2_state.resolve_words));
        ntw2_env::Sample(const_cast<U*>(ntw2_state.env_words), const_cast<U*>(ntw2_state.env_target_words));
        ntw2_resolve::SampleFrames(const_cast<U*>(ntw2_state.resolve_frame_words));
        ntw2_loco::SampleOwned(const_cast<U*>(ntw2_state.loco_owned_words));
        ntw2_loco::SampleOwnedDetails(const_cast<U*>(ntw2_state.loco_owned_detail_words));
        ntw2_loco::SampleOwnedPhase(const_cast<U*>(ntw2_state.loco_owned_phase_words));
        ntw2_loco::SampleOwnedLoad(const_cast<U*>(ntw2_state.loco_owned_load_words));
    } else {
        for (U i=0;i<NTW2_LOCO_WORDS;++i) ntw2_state.loco_words[i]=0;
        for (U i=0;i<NTW2_LOCO_GATE_WORDS;++i) ntw2_state.loco_gate_words[i]=0;
        for (U i=0;i<NTW2_LOCO_SERVICE_WORDS;++i) ntw2_state.loco_service_words[i]=0;
        for (U i=0;i<NTW2_LOCO_GRID_WORDS;++i) ntw2_state.loco_grid_words[i]=0;
        for (U i=0;i<NTW2_LOCO_PARALLEL_WORDS;++i) ntw2_state.loco_parallel_words[i]=0;
        for (U i=0;i<NTW2_SWEEP_WORDS;++i) ntw2_state.sweep_words[i]=0;
        for (U i=0;i<NTW2_RESOLVE_WORDS;++i) ntw2_state.resolve_words[i]=0;
        for (U i=0;i<NTW2_ENV_WORDS;++i) ntw2_state.env_words[i]=0;
        for (U i=0;i<NTW2_ENV_TARGET_WORDS;++i) ntw2_state.env_target_words[i]=0;
        for (U i=0;i<NTW2_RESOLVE_FRAME_WORDS;++i) ntw2_state.resolve_frame_words[i]=0;
        for (U i=0;i<NTW2_LOCO_OWNED_WORDS;++i) ntw2_state.loco_owned_words[i]=0;
        for (U i=0;i<NTW2_LOCO_OWNED_DETAIL_WORDS;++i) ntw2_state.loco_owned_detail_words[i]=0;
        for (U i=0;i<NTW2_LOCO_OWNED_PHASE_WORDS;++i) ntw2_state.loco_owned_phase_words[i]=0;
        for (U i=0;i<NTW2_LOCO_OWNED_LOAD_WORDS;++i) ntw2_state.loco_owned_load_words[i]=0;
        for (U i=0;i<NTW2_LOCO_GRID_V2_WORDS;++i) ntw2_state.loco_grid_v2_words[i]=0;
        for (U i=0;i<NTW2_LOCO_RELINK_WORDS;++i) ntw2_state.loco_relink_words[i]=0;
        for (U i=0;i<NTW2_LOCO_CW_WORDS;++i) ntw2_state.loco_cw_words[i]=0;
        for (U i=0;i<NTW2_LOCO_GRID_BUILD_WORDS;++i) ntw2_state.loco_grid_build_words[i]=0;
    }
    for (U i=0;i<16;++i) ntw2_state.ai_ctrl_words[i]=0;
    for (U i=0;i<NTW2_AI_SLICE_BUDGET_WORDS;++i) ntw2_state.ai_slice_budget_words[i]=0;
    for (U i=0;i<8;++i) ntw2_state.ai_park_words[i]=0;
    StateEnd();
    for (U i=0;i<slotCount;++i)
        if (!slots[i].owned && !SwapSlot(slots[i],true)) { Deactivate(); return false; }
    if (!ntw2_arena_release::Start(imageBase,config.va_watch_flags,world.root,config.main_thread_id)) { RecordError(SlotConflict,0x1340aacu); Deactivate(); return false; }
    World now; bool asynchronous=false;
    if (!FindWorld(now,asynchronous) || !SameWorld(world,now) ||
        ((config.enabled_mask&kSimulation) && !asynchronous)) {
        arenaKeepHooks=FindWorld(now,asynchronous) && SameWorld(world,now); // dormant, not gone
        const bool clean=Deactivate();
        arenaKeepHooks=false;
        if (clean) Phase(NTW2_WAITING_BATTLE);
        return clean && !failure;
    }
    ++generation;
    _InterlockedExchange(&enabled,static_cast<LONG>(config.enabled_mask));
    StateBegin(); ntw2_state.generation=generation;
    ntw2_state.active_mask=config.enabled_mask&~static_cast<U>(Load(&budgetDisabledMask));
    ntw2_state.phase=NTW2_ACTIVE;
    ntw2_state.ai_slice_words[AsParked]=0; ntw2_state.ai_slice_words[AsThread]=aiThreadId;
    ntw2_state.visual_words[VwSlot]=visualWords[VwSlot]; // the slot is known at activation; counters follow at the next poll
    PublishAllocatorStatus();
    StateEnd();
    if (config.enabled_mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) ntw2_profile_set_active(true);
    return true;
}
void CadenceReset() { cadence={}; }
void CadenceSample(U tick) {
    const ULONGLONG now=GetTickCount64();
    if (!cadence.armed) { cadence.armed=true; cadence.lastChange=now; cadence.lastTick=tick; return; }
    if (tick==cadence.lastTick) return;
    const U advanced=tick-cadence.lastTick, interval=static_cast<U>(now-cadence.lastChange);
    U* w=cadence.words;
    ++w[0]; w[1]+=interval; if (interval>w[2]) w[2]=interval;
    static const U bounds[6]={20,50,100,200,500,1000};
    U bucket=6; for (U i=0;i<6;++i) if (interval<=bounds[i]) { bucket=i; break; }
    ++w[3+bucket];
    if (advanced>w[10]) w[10]=advanced;
    w[11]=interval; w[12]+=interval;
    cadence.lastChange=now; cadence.lastTick=tick;
    StateBegin(); for (U i=0;i<16;++i) ntw2_state.tick_words[i]=w[i]; StateEnd();
}
void PublishMountedOfficer() { // monitor thread: the row is zero without NTW2_MOUNTED_OFFICER
    if (!(config.va_watch_flags&NTW2_MOUNTED_OFFICER)) return;
    StateBegin(); ntw2_mounted_officer::Snapshot(ntw2_state.mounted_officer_words); StateEnd();
}
DWORD WINAPI Monitor(void*) {
    if (!LoadEntries()) RecordError(MissingExport,0);
    if (!failure) BuildClones();
    if (!failure && (config.enabled_mask&NTW2_AI_CENSUS)) ntw2_ai_census::SetController(clones.entries[NTW2_CLONE_AI_CONTROLLER],0xBC);
    if (!failure && (config.va_watch_flags&NTW2_MOUNTED_OFFICER)) {
        // --mounted-officer: the constructor clone is resident (BuildClones); redirect its single call now, before any battle loads.
        namespace mo=ntw2_mounted_officer;
        const mo::Targets targets={V(mo::kNative.alloc),V(mo::kNative.vecAlloc),V(mo::kNative.vecFree),V(mo::kNative.modelCtx),V(mo::kNative.animCtx),
                                   V(mo::kNative.pose),V(mo::kNative.ctor),V(mo::kNative.attach)};
        mo::Configure((config.va_watch_flags&NTW2_MOUNTED_OFFICER_WIDEN)!=0,targets);
        if (!mo::InstallRedirect(delta,clones.entries[NTW2_CLONE_UNIT_CTOR])) RecordError(SlotConflict,mo::kCallSite);
        PublishMountedOfficer();
    }
    ntw2_profile_storm_threshold_ms=(config.va_watch_flags&NTW2_ARMY_STORM_SAMPLE_MASK)>>NTW2_ARMY_STORM_SAMPLE_SHIFT; // 0 unless validated with the census
    if (!failure && (config.enabled_mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS))) {
        siteGateIndex=config.profile_site;
        ntw2_profile_tick_gate=config.profile_site ? &siteInProgress : &tickInProgress;
        ntw2_profile_main_tick_gate=&tickInProgress;
        const U error=ntw2_profile_start(config.main_thread_id,imageBase,imageSize,Address(selfModule),
                                        Address(clones.allocation),clones.allocation_bytes);
        if (error) RecordError(ThreadError,error);
    }
    U previousTick=0;
    if (!failure) Phase(NTW2_WAITING_BATTLE);
    HANDLE wakeEvents[2]={stopEvent,budgetWakeEvent};
    while (!failure) {
        const DWORD wake=WaitForMultipleObjects(2,wakeEvents,FALSE,config.poll_ms);
        if(wake==WAIT_OBJECT_0) break;
        if(wake!=WAIT_TIMEOUT && wake!=WAIT_OBJECT_0+1) { RecordError(ThreadError,GetLastError()); break; }
        World candidate; bool asynchronous=false;
        const bool found=FindWorld(candidate,asynchronous);
        StateBegin(); ntw2_state.probe=probe; StateEnd();
        VaWatchSample(); // no-op unless --va-watch; rate-limited to 1 Hz
        PublishMountedOfficer(); // the unit constructors run while loading: publish in every phase
        if (Load(&enabled)) {
            // 0x5EE050 recomputes +0x2829C from the playback/unit rate (0x5B3210), not battle lifetime.
            // At >1x the task route can go dormant while this same world keeps running synchronously.
            // BRAIN2 owns only the asynchronous task route: retain hooks/counters until that route returns.
            // AI is different: a pending think can outlive a tick, so retain its existing drain/teardown policy.
            const bool dormantBrain2=(config.enabled_mask&NTW2_BRAIN2) && !(config.enabled_mask&NTW2_AI_ASYNC);
            if (!found || !SameWorld(world,candidate) || candidate.tick<previousTick ||
                ((config.enabled_mask&kSimulation) && !asynchronous && !dormantBrain2)) {
                arenaKeepHooks=found && SameWorld(world,candidate) && candidate.tick>=previousTick; // the same live world went dormant: its arenas stay in use
                const bool clean=Deactivate();
                arenaKeepHooks=false;
                if (!clean) break;
                Phase(NTW2_WAITING_BATTLE);
            } else { previousTick=candidate.tick; CadenceSample(candidate.tick); SampleCounters(); continue; }
        }
        // A world whose scheduler flag is unset (loading, paused, or a route the hooks do not own) is simply not
        // activated; the monitor keeps waiting and re-activates once the asynchronous route is live again.
        if (!found || ((config.enabled_mask&kSimulation) && !asynchronous)) continue;
        previousTick=candidate.tick; CadenceReset();
        for (U i=0;i<16;++i) simWords[i]=0;
        for (U i=0;i<NTW2_BRAIN_WORDS;++i) brainWords[i]=0;
        for (U i=0;i<NTW2_BRAIN_STATE_WORDS;++i) brainStateWords[i]=0;
        for (U i=0;i<NTW2_COLLISION_WORDS;++i) collisionWords[i]=0;
        for (LONGLONG& ticks:collisionQpc) ticks=0;
        collisionNumericActive=false;
        Brain2Reset();
        AiReset();
        if (!ntw2_ai_async2::Reset((config.enabled_mask&NTW2_AI_ASYNC2)!=0,delta,&tickOwner,&aiThreadId,config.ai_deferred)) {
            RecordError(ThreadError,GetLastError()); break; // the generation's join events are unavailable
        }
        tickLastStart=0;
        if (!Activate(candidate)) break;
        SampleCounters();
    }
    bool clean=true;
    bool hooks=false;
    for (U i=0;i<slotCount;++i) hooks=hooks || slots[i].owned || slots[i].protectionDirty;
    if (hooks || Load(&enabled) || formation.ready || query.ready || path.ready || poolReady || ntw2_arena_release::HooksInstalled())
        clean=Deactivate();
    if (!AiShutdown()) clean=false;
    if (clean && (config.enabled_mask&NTW2_BRAIN2)) Brain2Release(); // dispatch drained; no owner occurrence can still use its context
    CrashRemove();
    ntw2_profile_stop();
    if (!ntw2_mounted_officer::RemoveRedirect(delta)) { RecordError(SlotConflict,ntw2_mounted_officer::kCallSite); clean=false; } // restore the constructor call before the final publish
    PublishMountedOfficer();
    if (config.enabled_mask&NTW2_AI_CENSUS) { // sampler joined, slots restored: publish the final totals
        StateBegin(); ntw2_ai_census::Snapshot(ntw2_state.ai_census_words,CensusSlotsOwned()); StateEnd();
    }
    StateBegin(); // worker joined: final totals
    ntw2_ai_async2::Snapshot(ntw2_state.ai_async2_words);
    ntw2_ai_async2::RouteSnapshot(ntw2_state.ai_async2_route_words);
    ntw2_ai_async2::DeferredSnapshot(ntw2_state.ai_deferred_words);
    SnapshotAiCtrl();
    StateEnd();
    _InterlockedExchange(&quiesced,clean ? 1 : 0);
    Phase(failure ? NTW2_FAILED : NTW2_STOPPED);
    _InterlockedExchange(&life,failure ? Failed : Stopped);
    return 0;
}
}

// --ai-formup-gate / --ai-standoff parameter words: each is zero unless the bit it belongs to is set, and valid (include/ntw2_runtime.h) when it is.
static bool GroupParamsValid(const ntw2_config& c) {
    if (!(c.ai_ctrl_flags&NTW2_AI_FORMUP_GATE)) { if (c.ai_group_params) return false; }
    else {
        const U pct=c.ai_group_params&NTW2_AI_FORMUP_PCT_MASK, timeout=c.ai_group_params>>NTW2_AI_FORMUP_TIMEOUT_SHIFT;
        if ((c.ai_group_params&~NTW2_AI_FORMUP_PARAMS_VALID) || pct>100 || !timeout) return false;
    }
    if (!(c.ai_ctrl_flags&NTW2_AI_STANDOFF)) return c.ai_group_params2==0;
    return !(c.ai_group_params2&~NTW2_AI_STANDOFF_PARAMS2_VALID) && (c.ai_group_params2&NTW2_AI_STANDOFF_K_MASK)!=0;
}

static U StartImpl(void* raw) {
    ntw2_config next;
    if (!Read(Address(raw),&next,sizeof(next)) || next.abi!=NTW2_ABI || next.size!=sizeof(next) ||
        !next.enabled_mask || (next.enabled_mask&~NTW2_VALID_MASK) || next.workers>16 || next.poll_ms<10 || next.poll_ms>1000 ||
        ((next.enabled_mask&NTW2_BRAIN) && !(next.enabled_mask&NTW2_PROFILE)) || // brain sites exist only inside the profiling epoch
        ((next.enabled_mask&NTW2_AI_CTRL) && !(next.enabled_mask&NTW2_AI_ASYNC)) ||
        (next.collide_lod_m&NTW2_COLLIDE_LOD_METRES_MASK)>100000 ||
        ((next.collide_lod_m&NTW2_COLLIDE_CENSUS) && !(next.enabled_mask&NTW2_PROFILE)) ||
        ((next.enabled_mask&NTW2_COLLIDE_LOD) && (next.enabled_mask&(NTW2_COLLIDE|NTW2_FORMATION))) ||
        (next.collide_flags&~NTW2_COLLIDE_FLAGS_VALID) || (next.collide_flags && !(next.enabled_mask&NTW2_COLLIDE)) ||
        ((next.collide_flags&NTW2_COLLIDE_CONTACT_SHADOW) && (next.collide_flags&NTW2_COLLIDE_CONTACT_WORKERS)) ||
        (next.brain_flags&~NTW2_BRAIN_FLAGS_VALID) || (next.brain_flags && !(next.enabled_mask&NTW2_BRAIN2)) ||
        ((next.brain_flags&NTW2_BRAIN_PARALLEL) && (!(next.brain_flags&(NTW2_BRAIN_CENSUS|NTW2_BRAIN_QUIET)) || !next.workers)) ||
        ((next.brain_flags&NTW2_BRAIN_QUIET) && (!(next.brain_flags&NTW2_BRAIN_PARALLEL) ||
         (next.brain_flags&(NTW2_BRAIN_CENSUS|NTW2_BRAIN_TIMING|NTW2_BRAIN_NODE_SHADOW|NTW2_BRAIN_FIRE_SHADOW|NTW2_BRAIN_FINALIZER_SHADOW)))) ||
        // The unit shadow observes ntw2_brain2::RunWorklist; the Stage 2 owner walk would bypass it.
        ((next.brain_flags&NTW2_BRAIN_UNIT_SHADOW) && (next.brain_flags&(NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET))) ||
        // --brain-s0 owns the occurrence call (BRAIN_S0 family, census off): it excludes every other brain flag except the
        // unit bits, which it routes (the unit seams ride its runner).
        ((next.brain_flags&NTW2_BRAIN_S0) && (next.brain_flags&~(NTW2_BRAIN_S0|kUnitBrainBits))) ||
        // --brain-locality owns the occurrence call and its status row: it excludes every other brain flag (S0 included);
        // exactly one of the warm / prefetch / prefetch2 modifiers may ride it, and they need the base bit.
        ((next.brain_flags&kLocalityBits) && ((next.brain_flags&~kLocalityBits) || !(next.brain_flags&NTW2_BRAIN_LOCALITY) ||
         ((next.brain_flags&kLocalityModifiers) & ((next.brain_flags&kLocalityModifiers)-1)))) ||
        // Per-unit brain slices: a shadow bit needs its base bit; every unit bit excludes the census/timing/shadow flags, the
        // Stage 2 worker walk (bypasses the runner) and --brain-unit-shadow (one observer owner).
        (next.brain_flags&NTW2_BRAIN_UNIT_FATIGUE_SHADOW && !(next.brain_flags&NTW2_BRAIN_UNIT_FATIGUE)) ||
        (next.brain_flags&NTW2_BRAIN_UNIT_POSTURE_SHADOW && !(next.brain_flags&NTW2_BRAIN_UNIT_POSTURE)) ||
        (next.brain_flags&NTW2_BRAIN_UNIT_ENGAGE_SHADOW && !(next.brain_flags&NTW2_BRAIN_UNIT_ENGAGE)) ||
        ((next.brain_flags&kUnitBrainBits) && (next.brain_flags&(NTW2_BRAIN_CENSUS|NTW2_BRAIN_TIMING|NTW2_BRAIN_NODE_SHADOW|
            NTW2_BRAIN_FIRE_SHADOW|NTW2_BRAIN_FINALIZER_SHADOW|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET|NTW2_BRAIN_UNIT_SHADOW))) ||
        (next.loco_flags&~NTW2_LOCO_FLAGS_VALID) || (next.loco_flags && !(next.enabled_mask&NTW2_LOCO)) ||
        ((next.loco_flags&(NTW2_LOCO_PARALLEL|NTW2_LOCO_SHADOW)) && !(next.loco_flags&NTW2_LOCO_CLONE)) ||
        ((next.loco_flags&NTW2_LOCO_OWNED_SERVICES) && !(next.loco_flags&NTW2_LOCO_PARALLEL)) ||
        ((next.loco_flags&NTW2_LOCO_QUIET) && !(next.loco_flags&NTW2_LOCO_OWNED_SERVICES)) ||
        // The relink apply replaces/verifies the owner's grid services in the owned-service replay and needs the grid; shadow and workers are exclusive.
        ((next.loco_flags&NTW2_LOCO_RELINK_SHADOW) && (next.loco_flags&NTW2_LOCO_RELINK_WORKERS)) ||
        // Class-wrapper phase 2 replays through the owned-service commit; shadow and live are exclusive.
        ((next.loco_flags&NTW2_LOCO_CW_SHADOW) && (next.loco_flags&NTW2_LOCO_CW_WORKERS)) ||
        ((next.loco_flags&(NTW2_LOCO_CW_SHADOW|NTW2_LOCO_CW_WORKERS)) && !(next.loco_flags&NTW2_LOCO_OWNED_SERVICES)) ||
        ((next.loco_flags&(NTW2_LOCO_RELINK_SHADOW|NTW2_LOCO_RELINK_WORKERS)) &&
         (!(next.loco_flags&NTW2_LOCO_OWNED_SERVICES) || !(next.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)))) ||
        // The incremental grid patches the owned grid v2 and needs it.
        ((next.loco_flags&NTW2_LOCO_GRID_INCREMENTAL) && !(next.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))) ||
        ((next.enabled_mask&NTW2_LOCO) && (next.enabled_mask&(NTW2_BRAIN|NTW2_COLLIDE_LOD))) ||
        ((next.enabled_mask&(NTW2_LOCO|NTW2_COLLIDE))==(NTW2_LOCO|NTW2_COLLIDE) &&
         ((next.loco_flags&(NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES))!=(NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES) ||
          !(next.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)))) ||
        // Probation arms the native heads outside the owner's relink window, published by the grid; the ballistics
        // query cache walks those heads in runtime code (its own reader would trip the detector), so it is refused.
        ((next.loco_flags&NTW2_LOCO_GRID_PROBATION) &&
         (!(next.loco_flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)) || (next.enabled_mask&NTW2_BALLISTICS))) ||
        ((next.enabled_mask&NTW2_GRID_CENSUS) && !(next.enabled_mask&NTW2_LOCO)) ||
        ((next.enabled_mask&NTW2_AI_CENSUS) && !(next.enabled_mask&NTW2_AI_ASYNC)) ||
        // ai_async2 shares the AI worker, site 33 and the delegate slots with ai_ctrl/ai_census.
        ((next.enabled_mask&NTW2_AI_ASYNC2) && (!(next.enabled_mask&NTW2_AI_ASYNC) || (next.enabled_mask&(NTW2_AI_CTRL|NTW2_AI_CENSUS)))) ||
        // The deferred schedule is an AI_ASYNC2 mode: K in 1..MAX_K, budget B >= 1, no other bits.
        (next.ai_deferred && (!(next.enabled_mask&NTW2_AI_ASYNC2) ||
                              (next.ai_deferred&~(NTW2_AI_DEFERRED_K_MASK|NTW2_AI_DEFERRED_BUDGET_MASK)) ||
                              !(next.ai_deferred&NTW2_AI_DEFERRED_K_MASK) ||
                              (next.ai_deferred&NTW2_AI_DEFERRED_K_MASK)>NTW2_AI_DEFERRED_MAX_K ||
                              !(next.ai_deferred&NTW2_AI_DEFERRED_BUDGET_MASK))) ||
        // The army unit shadow observes the cloned ARMY_UPDATE stage, reached only through a routed tick.
        ((next.enabled_mask&NTW2_ARMY_UNIT_SHADOW) && !(next.enabled_mask&kRouted)) ||
        // --ai-ctrl-*: the batch hooks live in the AI_CONTROLLER clone chain behind the routed MANAGER tick, on the tick owner;
        // CENSUS is shadow-only, VERIFY needs a live feature. The offload / async2 controller gates bypass the clone chain.
        (next.ai_ctrl_flags&~NTW2_AI_CTRL_FLAGS_VALID) || (next.ai_ctrl_flags&NTW2_AI_CLAIM_BITS)==NTW2_AI_CLAIM_BITS || !GroupParamsValid(next) ||
        // --brain-target-cull-shadow / --brain-target-cull exclude each other; the brain-step levers share the status words 16..23 with the geometry mode.
        (next.ai_ctrl_flags&(NTW2_AI_TARGET_CULL_SHADOW|NTW2_AI_TARGET_CULL))==(NTW2_AI_TARGET_CULL_SHADOW|NTW2_AI_TARGET_CULL) ||
        ((next.ai_ctrl_flags&NTW2_AI_BRAIN_STEP_BITS) && (next.ai_ctrl_flags&NTW2_AI_CTRL_GEOMETRY)) ||
        (next.ai_ctrl_flags && (!(next.enabled_mask&kManagerRouted) || (next.enabled_mask&(NTW2_AI_CTRL|NTW2_AI_ASYNC2)) ||
                                ((next.ai_ctrl_flags&NTW2_AI_CTRL_CENSUS) && (next.ai_ctrl_flags&(NTW2_AI_CTRL_HISTOGRAM|NTW2_AI_CTRL_GEOMETRY))) ||
                                ((next.ai_ctrl_flags&NTW2_AI_CTRL_VERIFY) && !(next.ai_ctrl_flags&(NTW2_AI_CTRL_HISTOGRAM|NTW2_AI_CTRL_GEOMETRY))))) ||
        // --ai-prepass-*: the census hooks live behind the routed MANAGER tick and run on the thread executing site 34; the async2
        // schedule (private clones, no site-34 scope on the executing thread) is excluded. CENSUS combines only with PRESIZE.
        (next.ai_prepass_flags&~NTW2_AI_PREPASS_FLAGS_VALID) ||
        (next.ai_prepass_flags && (!(next.enabled_mask&kManagerRouted) || (next.enabled_mask&NTW2_AI_ASYNC2) ||
                                   ((next.ai_prepass_flags&NTW2_AI_PREPASS_CENSUS) && (next.ai_prepass_flags&~(NTW2_AI_PREPASS_CENSUS|NTW2_AI_PRESIZE|NTW2_AI_SPIRAL_BITS))) ||
                                   // --ai-spiral-cap-m: the first ring (radius 20) always runs, so a cap below it is refused.
                                   ((next.ai_prepass_flags>>NTW2_AI_SPIRAL_CAP_SHIFT) && (next.ai_prepass_flags>>NTW2_AI_SPIRAL_CAP_SHIFT)<NTW2_AI_SPIRAL_CAP_MIN_M) ||
                                   ((next.ai_prepass_flags&NTW2_AI_POLY_SHADOW) && (next.ai_prepass_flags&NTW2_AI_POLY)) ||
                                   // --ai-record-test*: one mode, and the kernel/clones/walk-state scope are --ai-poly's, so a poly bit is required.
                                   ((next.ai_prepass_flags&NTW2_AI_RECORD_TEST_SHADOW) && (next.ai_prepass_flags&NTW2_AI_RECORD_TEST)) ||
                                   ((next.ai_prepass_flags&NTW2_AI_RECORD_TEST_BITS) && !(next.ai_prepass_flags&(NTW2_AI_POLY_SHADOW|NTW2_AI_POLY))))) ||
        // --va-watch / --army-storm-*: the VA watch sampler plus the storm census bit and its sampler threshold (bits 8..15).
        (next.va_watch_flags&~NTW2_VA_WATCH_FLAGS_VALID) ||
        // --mounted-officer-widen needs --mounted-officer (the gate it modifies).
        ((next.va_watch_flags&NTW2_MOUNTED_OFFICER_WIDEN) && !(next.va_watch_flags&NTW2_MOUNTED_OFFICER)) ||
        // --va-floor-mib (bits 22..26, 0=default 256 MiB, 2..16 = 64..512 MiB in 32 MiB units, 17 = 1024 MiB; 1 and 18..31 refused)
        // and --va-hole-mib (bits 27..31, 0=default 128 MiB, 1..16 = 32..512 MiB in 32 MiB units; 17..31 refused).
        (((next.va_watch_flags&NTW2_VA_FLOOR_MASK)>>NTW2_VA_FLOOR_SHIFT)==1u ||
         ((next.va_watch_flags&NTW2_VA_FLOOR_MASK)>>NTW2_VA_FLOOR_SHIFT)>17u ||
         ((next.va_watch_flags&NTW2_VA_HOLE_MASK)>>NTW2_VA_HOLE_SHIFT)>16u) ||
        // The storm census times the 0x581F30 calls on the tick owner behind a routed tick; it binds sites 101/103 like the shadow.
        ((next.va_watch_flags&NTW2_ARMY_STORM_CENSUS) && (!(next.enabled_mask&kManagerRouted) || !next.main_thread_id ||
                                                          (next.enabled_mask&NTW2_ARMY_UNIT_SHADOW))) ||
        // The gated sampler threshold needs the profile sampler and a selected site: 18 (profile_site 19, with the census)
        // or 34 (profile_site 35, planner think tails; the think must run on the gated thread, i.e. without AI_ASYNC).
        ((next.va_watch_flags&NTW2_ARMY_STORM_SAMPLE_MASK) && (!(next.enabled_mask&NTW2_PROFILE) ||
            (next.profile_site!=7 && next.profile_site!=19 && next.profile_site!=35) ||
            (next.profile_site==19 && !(next.va_watch_flags&NTW2_ARMY_STORM_CENSUS)) ||
            (next.profile_site==35 && (next.enabled_mask&NTW2_AI_ASYNC)))) ||
        // --engage-census observes after the routed native tick on the tick owner.
        ((next.va_watch_flags&NTW2_ENGAGE_CENSUS) && !(next.enabled_mask&kRouted)) ||
        // --tick-pcore / --tick-core-ab place the routed tick body (TickGate's routed path); one placement mode at a time.
        ((next.va_watch_flags&(NTW2_TICK_PCORE|NTW2_TICK_CORE_AB)) && (!(next.enabled_mask&kRouted) ||
                                                                       (next.va_watch_flags&(NTW2_TICK_PCORE|NTW2_TICK_CORE_AB))==(NTW2_TICK_PCORE|NTW2_TICK_CORE_AB))) ||
        // --army-solver-memo / --army-solver-shadow: like the census, a routed tick behind the MANAGER clone and main_thread_id; the two modes are exclusive.
        ((next.va_watch_flags&(NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW)) && (!(next.enabled_mask&kManagerRouted) || !next.main_thread_id ||
            (next.va_watch_flags&(NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW))==(NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW))) ||
        ((next.enabled_mask&(NTW2_PROFILE|NTW2_GRID_CENSUS|NTW2_AI_CENSUS)) && !next.main_thread_id) || next.profile_site>NTW2_TIMED_SITES) return BadConfig;
    const LONG before=Load(&life);
    if (before!=Never && before!=Stopped) return BadConfig;
    if (_InterlockedCompareExchange(&life,Running,before)!=before) return BadConfig;
    // Life is published just before the monitor returns. Join its actual thread
    // before resetting shared state; an event signal alone has a restart race.
    if (monitorThread) {
        if (WaitForSingleObject(monitorThread,kStopTimeoutMs+1000)!=WAIT_OBJECT_0) {
            _InterlockedExchange(&life,before); return ThreadError;
        }
        CloseHandle(monitorThread); monitorThread=nullptr;
    }
    failure=failureDetail=0;
    if (!MainImage(next.image_base)) { _InterlockedExchange(&life,before); return BadImage; }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&StartImpl),&selfModule)) {
        _InterlockedExchange(&life,before); return ThreadError;
    }
    config=next;
    const U preAllocMode=ntw2_state.alloc_census_words[NTW2_ALLOC_CENSUS_MODE];
    U reqAllocMode=((config.va_watch_flags&NTW2_ALLOC_CENSUS) ? ntw2_alloc_census::kModeCensus : 0u) |
                   ((config.va_watch_flags&NTW2_ALLOC_FIX) ? ntw2_alloc_census::kModeFix : 0u);
    if (reqAllocMode==ntw2_alloc_census::kModeCensus &&
        (preAllocMode>=ntw2_alloc_census::kModeCensus && preAllocMode<=ntw2_alloc_census::kModeFixCensus))
        reqAllocMode=preAllocMode;
    allocCensusRequestedMode=reqAllocMode;
    ntw2_alloc_census::Reset();
    ntw2_alloc_census::Configure(imageBase,imageSize,delta,allocCensusRequestedMode);
    CpuTopologyInit(); // tick core census + NTW2_TICK_PCORE / NTW2_TICK_CORE_AB masks; no tick is routed before activation
    ntw2_grid_census_reset((config.enabled_mask&NTW2_GRID_CENSUS)!=0); // sampler is stopped; disabled starts publish an all-zero row
    ntw2_engage_census::Reset((config.va_watch_flags&NTW2_ENGAGE_CENSUS)!=0,delta,imageBase,imageSize);
    ntw2_ai_census::Reset((config.enabled_mask&NTW2_AI_CENSUS)!=0,imageBase,imageSize,delta,config.main_thread_id,&tickInProgress,&aiThreadId,&ntw2_grid_census_site);
    ntw2_ai_async2::Reset(false,delta,&tickOwner,&aiThreadId); // zero row until a generation activates
    ntw2_ai_ctrl::Reset(0,delta,0); ntw2_ai_ctrl_geometry::Reset(); // zero rows until a generation activates (Activate configures)
    { const ntw2_prepass::Targets none={}; ntw2_prepass::CensusReset(0,none,1); } // zero row until a generation activates
    memset(memoryWords,0,sizeof(memoryWords));
    memoryWords[NTW2_MEM_VERSION]=4;
    _InterlockedExchange(&budgetDisabledMask,0); budgetRetired=false;
    _InterlockedExchange(&budgetReleasePending,0);
    const U floorCode=(config.va_watch_flags&NTW2_VA_FLOOR_MASK)>>NTW2_VA_FLOOR_SHIFT;
    const U holeCode=(config.va_watch_flags&NTW2_VA_HOLE_MASK)>>NTW2_VA_HOLE_SHIFT;
    vaTotalFloorBytes=floorCode ? ((floorCode==17u ? 32u : floorCode)*NTW2_VA_FLOOR_UNIT_MIB*1024u*1024u) : NTW2_MEMORY_MIN_AVAIL_VIRTUAL;
    vaHoleFloorBytes=holeCode ? (holeCode*NTW2_VA_FLOOR_UNIT_MIB*1024u*1024u) : NTW2_MEMORY_MIN_LARGEST_HOLE;
    memoryWords[NTW2_MEM_FLOOR_BYTES]=vaTotalFloorBytes;
    memoryWords[NTW2_MEM_HOLE_FLOOR_BYTES]=vaHoleFloorBytes;
    memoryNextSample=0; vaLastHoleWalk=0; vaCachedLargestHole=0; vaBreachStreak=0; vaLastWalkUs=0; activationCapacity={};
    memset(vaWords,0,sizeof(vaWords)); vaNextSample=0; vaStart=0;
    collideSampleReady=false; // retained solver words belong to the previous start until the next activation
    locoSampleReady=false; // retained loco words belong to the previous start until the next activation
    Brain2Reset(); ntw2_army_unit::Reset(); ntw2_army_storm::Reset(); ntw2_army_solver::Reset();
    CollideLodReset();
    memset(const_cast<U*>(visualWords),0,sizeof(visualWords));
    memset(allocatorWords,0,sizeof(allocatorWords));
    _InterlockedExchange(&visualFaulted,0);
    if (!stopEvent) stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if (!budgetWakeEvent) budgetWakeEvent=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if (!stopEvent || !budgetWakeEvent) {
        RecordError(ThreadError,GetLastError()); Phase(NTW2_FAILED); _InterlockedExchange(&life,Failed); return ThreadError;
    }
    ResetEvent(stopEvent);
    ResetEvent(budgetWakeEvent);
    if (config.enabled_mask&NTW2_AI_ASYNC) CrashInstall();
    StateBegin();
    PublishMemory();
    ntw2_state.requested_mask=config.enabled_mask; ntw2_state.active_mask=0; ntw2_state.error=0; ntw2_state.error_detail=0;
    ntw2_state.pid=GetCurrentProcessId(); ntw2_state.image_base=imageBase; ntw2_state.workers=config.workers;
    ntw2_state.phase=NTW2_VERIFYING;
    for (U i=0;i<32;++i) ntw2_state.visual_words[i]=0;
    for (U i=0;i<NTW2_ALLOCATOR_WORDS;++i) ntw2_state.allocator_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_WORDS;++i) ntw2_state.collide_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_SOURCE_WORDS;++i) ntw2_state.collide_source_words[i]=0;
    for (U i=0;i<NTW2_VA_WATCH_WORDS;++i) ntw2_state.va_watch_words[i]=0;
    for (U i=0;i<NTW2_BRAIN2_WORDS;++i) ntw2_state.brain2_words[i]=0;
    for (U i=0;i<32;++i) ntw2_state.brain2_reason_words[i]=0;
    for (U i=0;i<80;++i) ntw2_state.brain2_gate_words[i]=0;
    for (U i=0;i<NTW2_BRAIN2_CENSUS_WORDS;++i) ntw2_state.brain2_census_words[i]=0;
    for (U i=0;i<NTW2_NODE_WORDS;++i) ntw2_state.node_words[i]=0;
    for (U i=0;i<NTW2_NODE_EVENT_WORDS;++i) ntw2_state.node_event_words[i]=0;
    for (U i=0;i<NTW2_FIRE_WORDS;++i) ntw2_state.fire_words[i]=0;
    for (U i=0;i<NTW2_BRAIN2_ROUTE_WORDS;++i) ntw2_state.brain2_route_words[i]=0;
    for (U i=0;i<NTW2_FIRE_COMMIT_WORDS;++i) ntw2_state.fire_commit_words[i]=0;
    for (U i=0;i<NTW2_MOVE_NODE_WORDS;++i) ntw2_state.move_node_words[i]=0;
    for (U i=0;i<NTW2_MOVE_NODE_EVENT_WORDS;++i) ntw2_state.move_node_event_words[i]=0;
    for (U i=0;i<NTW2_BRAIN2_NODE_TARGET_WORDS;++i) ntw2_state.brain2_node_target_words[i]=0;
    for (U i=0;i<NTW2_BRAIN2_UNKNOWN_SITE_WORDS;++i) ntw2_state.brain2_unknown_site_words[i]=0;
    for (U i=0;i<NTW2_BRAIN_WORKER_WORDS;++i) ntw2_state.brain_worker_words[i]=0;
    for (U i=0;i<NTW2_BRAIN_WORKER_PHASE_WORDS;++i) ntw2_state.brain_worker_phase_words[i]=0;
    for (U i=0;i<NTW2_BRAIN_UNIT_WORDS;++i) ntw2_state.brain_unit_words[i]=0;
    for (U i=0;i<NTW2_COLLIDE_CONTACT_WORDS;++i) ntw2_state.collide_contact_words[i]=0;
    for (U i=0;i<NTW2_GRID_PROBATION_WORDS;++i) ntw2_state.grid_probation_words[i]=0;
    for (U i=0;i<NTW2_ARMY_UNIT_WORDS;++i) ntw2_state.army_unit_words[i]=0;
    for (U i=0;i<NTW2_ARMY_B0_WORDS;++i) ntw2_state.army_b0_words[i]=0;
    for (U i=0;i<NTW2_ARMY_STORM_WORDS;++i) ntw2_state.army_storm_words[i]=0;
    for (U i=0;i<NTW2_ARMY_SOLVER_WORDS;++i) ntw2_state.army_solver_words[i]=0;
    for (U i=0;i<NTW2_BRAIN_S0_WORDS;++i) ntw2_state.brain_s0_words[i]=0;
    for (U i=0;i<NTW2_BRAIN_UNIT_POLICY_WORDS;++i) ntw2_state.brain_unit_policy_words[i]=0;
    for (U i=0;i<NTW2_AI_CTRL_REUSE_WORDS;++i) ntw2_state.ai_ctrl_reuse_words[i]=0;
    for (U i=0;i<NTW2_AI_PREPASS_CENSUS_WORDS;++i) ntw2_state.ai_prepass_census_words[i]=0;
    for (U i=0;i<NTW2_AI_PREPASS_WORDS;++i) ntw2_state.ai_prepass_words[i]=0;
    for (U i=0;i<NTW2_AI_SPIRAL_WORDS;++i) ntw2_state.ai_spiral_words[i]=0;
    for (U i=0;i<NTW2_ALLOC_CENSUS_WORDS;++i) ntw2_state.alloc_census_words[i]=0;
    for (U i=0;i<NTW2_ARENA_WORDS;++i) ntw2_state.arena_words[i]=0;
    for (U i=0;i<NTW2_OVERLAY_WORDS;++i) ntw2_state.overlay_words[i]=0;
    ntw2_spiral::ResetRow(); // the poll copies the module row: a session that never activates must not republish the previous one
    ntw2_record_test::Reset();
    ntw2_claim_once::ResetRow();
    ntw2_group_formup::ResetRow();
    ntw2_retarget_jitter::ResetRow();
    ntw2_target_cull::ResetRow();
    ntw2_mounted_officer::ResetRow();
    for (U i=0;i<NTW2_MOUNTED_OFFICER_WORDS;++i) ntw2_state.mounted_officer_words[i]=0;
    ntw2_engage_census::Snapshot(ntw2_state.engage_census_words); // zero row (Reset above) or the armed header
    for (U cls=0;cls<NTW2_IDLE_NODE_CLASSES;++cls) {
        for (U i=0;i<NTW2_NODE_WORDS;++i) ntw2_state.idle_node_words[cls][i]=0;
        for (U i=0;i<NTW2_NODE_EVENT_WORDS;++i) ntw2_state.idle_node_event_words[cls][i]=0;
    }
    for (U cls=0;cls<NTW2_ACTION_NODE_CLASSES;++cls) {
        for (U i=0;i<NTW2_NODE_WORDS;++i) ntw2_state.action_node_words[cls][i]=0;
        for (U i=0;i<NTW2_NODE_EVENT_WORDS;++i) ntw2_state.action_node_event_words[cls][i]=0;
    }
    for (U i=0;i<NTW2_COLLIDE_LOD_WORDS;++i) ntw2_state.collide_lod_words[i]=0;
    for (U i=0;i<NTW2_LOCO_WORDS;++i) ntw2_state.loco_words[i]=0;
    for (U i=0;i<NTW2_LOCO_GATE_WORDS;++i) ntw2_state.loco_gate_words[i]=0;
    for (U i=0;i<NTW2_LOCO_SERVICE_WORDS;++i) ntw2_state.loco_service_words[i]=0;
    for (U i=0;i<NTW2_LOCO_GRID_WORDS;++i) ntw2_state.loco_grid_words[i]=0;
    for (U i=0;i<NTW2_LOCO_PARALLEL_WORDS;++i) ntw2_state.loco_parallel_words[i]=0;
    for (U i=0;i<NTW2_SWEEP_WORDS;++i) ntw2_state.sweep_words[i]=0;
    for (U i=0;i<NTW2_RESOLVE_WORDS;++i) ntw2_state.resolve_words[i]=0;
    for (U i=0;i<NTW2_ENV_WORDS;++i) ntw2_state.env_words[i]=0;
    for (U i=0;i<NTW2_ENV_TARGET_WORDS;++i) ntw2_state.env_target_words[i]=0;
    for (U i=0;i<NTW2_RESOLVE_FRAME_WORDS;++i) ntw2_state.resolve_frame_words[i]=0;
    for (U i=0;i<NTW2_LOCO_OWNED_WORDS;++i) ntw2_state.loco_owned_words[i]=0;
    for (U i=0;i<NTW2_LOCO_OWNED_DETAIL_WORDS;++i) ntw2_state.loco_owned_detail_words[i]=0;
    for (U i=0;i<NTW2_LOCO_OWNED_PHASE_WORDS;++i) ntw2_state.loco_owned_phase_words[i]=0;
    for (U i=0;i<NTW2_LOCO_OWNED_LOAD_WORDS;++i) ntw2_state.loco_owned_load_words[i]=0;
    for (U i=0;i<NTW2_LOCO_GRID_V2_WORDS;++i) ntw2_state.loco_grid_v2_words[i]=0;
    for (U i=0;i<NTW2_LOCO_RELINK_WORDS;++i) ntw2_state.loco_relink_words[i]=0;
    for (U i=0;i<NTW2_LOCO_CW_WORDS;++i) ntw2_state.loco_cw_words[i]=0;
    for (U i=0;i<NTW2_LOCO_GRID_BUILD_WORDS;++i) ntw2_state.loco_grid_build_words[i]=0;
    for (U i=0;i<16;++i) ntw2_state.ai_ctrl_words[i]=0;
    for (U i=0;i<NTW2_AI_SLICE_BUDGET_WORDS;++i) ntw2_state.ai_slice_budget_words[i]=0;
    for (U i=0;i<8;++i) ntw2_state.ai_park_words[i]=0;
    ntw2_grid_census_snapshot(&ntw2_state.grid_census);
    ntw2_ai_census::Snapshot(ntw2_state.ai_census_words,0);
    ntw2_ai_async2::Snapshot(ntw2_state.ai_async2_words);
    ntw2_ai_async2::RouteSnapshot(ntw2_state.ai_async2_route_words);
    ntw2_ai_async2::DeferredSnapshot(ntw2_state.ai_deferred_words);
    StateEnd();
    DWORD tid=0;
    HANDLE thread=CreateThread(nullptr,0,Monitor,nullptr,CREATE_SUSPENDED,&tid);
    if (!thread) { RecordError(ThreadError,GetLastError()); CrashRemove(); Phase(NTW2_FAILED); _InterlockedExchange(&life,Failed); return ThreadError; }
    StateBegin(); ntw2_state.monitor_thread=tid; StateEnd();
    _InterlockedExchange(&quiesced,0);
    if (ResumeThread(thread)==static_cast<DWORD>(-1)) {
        RecordError(ThreadError,GetLastError());
        CrashRemove();
        TerminateThread(thread,ThreadError); // suspended thread has never executed or acquired a lock
        CloseHandle(thread); _InterlockedExchange(&quiesced,1);
        Phase(NTW2_FAILED); _InterlockedExchange(&life,Failed); return ThreadError;
    }
    monitorThread=thread;
    return 0;
}
static U StopImpl() {
    const LONG current=Load(&life);
    if (current==Never) return 0;
    if (current==Running && (!stopEvent || !SetEvent(stopEvent))) return ThreadError;
    if (monitorThread && WaitForSingleObject(monitorThread,kStopTimeoutMs+1000)!=WAIT_OBJECT_0) return StopTimeout;
    return Load(&quiesced) ? 0 : (failure ? failure : ThreadError);
}
// Diagnostic export (lifecycle oracle): the callee currently behind timed site `site` (0 beyond the sites). Site 6 is the host
// BrainKernelGate exactly while a generation with NTW2_BRAIN2 is active, the original 0x585D10 otherwise.
extern "C" U __stdcall ntw2_site_callee(U site) { return site<NTW2_TIMED_SITES ? siteCallees[site] : 0; }
// Diagnostic export (lifecycle oracle): arms [base, base+bytes) of committed private PAGE_READWRITE memory through the
// --grid-probation handler (base=0 disarms). 1 on success; 0 when no probation generation runs or a game array is armed.
extern "C" U __stdcall ntw2_grid_probation_probe(void* base, U bytes) {
    return probationRunning && ntw2_grid_probation::Probe(base,bytes) ? 1u : 0u;
}
// Same short owner-only boundary used by TickGate. The mapped-image lifecycle
// oracle has no engine task scheduler and supplies that boundary explicitly.
extern "C" U __stdcall ntw2_activation_boundary(void* model) { return ActivationBoundary(model) ? 1u : 0u; }
// The mapped-image lifecycle oracle owns its fake model exclusively and has no engine scheduler.
// Exercise the production admission and tick-finally barrier without exposing an arbitrary callee.
extern "C" U __stdcall ntw2_ai_boundary(void* model, void* planner, U flag) {
    if (!BoundModel(Address(model)) || !(Load(&enabled)&NTW2_AI_ASYNC)) return 0;
    if (_InterlockedCompareExchange(&tickOwner,static_cast<LONG>(GetCurrentThreadId()),0)) return 0;
    U result=0;
    __try {
        if (BoundModel(Address(model)) && (Load(&enabled)&NTW2_AI_ASYNC)) {
            epochMask=static_cast<U>(Load(&enabled));
            result=AiPlannerGate(Address(planner),flag);
        }
    } __finally {
        AiBarrier(); epochMask=0; _InterlockedExchange(&tickOwner,0);
    }
    return result;
}
// NTW2_AI_ASYNC2 counterpart, one synthetic tick under tick ownership: the production tick-start seam, site-34 admission
// of `planner` (skipped when null), `mid(context)` on the tick thread while earlier batches may still run, optional
// second admission (options bit 0), the production TICK quadtree join (skipped with options bit 1, a tick without
// structural writers) and the tick-end publish.
extern "C" U __stdcall ntw2_ai_async2_boundary(void* model, void* planner, U flag, void (__stdcall* mid)(void*),
                                               void* context, U options) {
    if (!BoundModel(Address(model)) || !(Load(&enabled)&NTW2_AI_ASYNC2)) return 0;
    if (_InterlockedCompareExchange(&tickOwner,static_cast<LONG>(GetCurrentThreadId()),0)) return 0;
    U result=0;
    bool published=false;
    __try {
        if (BoundModel(Address(model)) && (Load(&enabled)&NTW2_AI_ASYNC2)) {
            epochMask=static_cast<U>(Load(&enabled));
            Ai2TickStart();
            result=planner ? Ai2PlannerGate(Address(planner),flag) : 1u;
            if (mid) mid(context);
            if (planner && (options&1u)) Ai2PlannerGate(Address(planner),flag);
            if (!(options&2u)) Ai2TickJoin(ntw2_ai_async2::KSpatial);
            Ai2TickEnd(); published=true;
        }
    } __finally {
        if (!published) Ai2TickAbort();
        AiBarrier(); epochMask=0; _InterlockedExchange(&tickOwner,0);
    }
    return result;
}
// Lifecycle diagnostic: the entry of AI2 private clone `clone` exactly as the routed slots hand it out. Only the AI
// worker inside a think of an AI_ASYNC2 generation receives it (after the same lazy worker-side scratch construction);
// every other caller, any other clone id and every other generation get 0.
extern "C" U __stdcall ntw2_ai_async2_private_entry(U clone) {
    const bool family=(clone>=NTW2_CLONE_AI2_STATE_UPDATE && clone<=NTW2_CLONE_AI2_67A790) ||
                      (clone>=NTW2_CLONE_AI2_6A95A0 && clone<=NTW2_CLONE_AI2_80DCF0);
    if (!family || !(Load(&enabled)&NTW2_AI_ASYNC2) || !Ai2WalkRouted(GetCurrentThreadId())) return 0;
    Ai2EnsureScratch();
    return clones.entries[clone];
}
extern "C" U __stdcall ntw2_start(void* raw) {
    AcquireSRWLockExclusive(&apiLock);
    __try { return StartImpl(raw); }
    __finally { ReleaseSRWLockExclusive(&apiLock); }
}
extern "C" U __stdcall ntw2_stop(void*) {
    AcquireSRWLockExclusive(&apiLock);
    __try { return StopImpl(); }
    __finally { ReleaseSRWLockExclusive(&apiLock); }
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID) {
    if (reason==DLL_PROCESS_ATTACH) selfModule=module;
    else if (reason==DLL_THREAD_DETACH) ntw2_alloc_census::OnThreadDetach();
    // Static CRT thread notifications stay enabled. Never do teardown under the loader lock.
    return TRUE;
}
