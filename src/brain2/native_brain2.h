#pragma once
#include <stdint.h>

// BRAIN2 v2 Stage 1 is owner-serial, not a worker/replay implementation.
// Each occurrence executes exactly one original or source-pinned clone against
// the live receiver. Gates forward synchronously, including UNKNOWN: a census
// refusal is never an inactive result or a second execution of the occurrence.
// No executable image bytes, vtables, outputs or native return ABI are changed.
namespace ntw2_brain2 {
using U = uint32_t;
constexpr U kVersion = 2, kWords = 48;
constexpr U kDiagReasonWords = 32, kDiagGateWords = 80;
constexpr U kRouteWords = 8;
enum RouteWord : U {
    RouteVersion, ConfiguredDriver, LastDriverClone, DriverCalls,
    VirtualBegins, VirtualSteps, ReferenceCtors, LastNodeTarget
};
// ConfiguredDriver: 0 original observation, 1 BRAIN_W_MOVEORDER. LastDriverClone
// records actual clone ID+1 (zero original), not an assumed LOCO/shared binding.
// VirtualBegins/Steps include every dynamic node class at the four holder seams;
// exact reference-node captures remain in ntw2_node's separate status.
constexpr U kNodeTargetWords = 36, kNodeTargetTop = 8;
// NodeTargetSnapshot: version, distinct targets, overflow calls, reserved;
// then eight (preferred target VA, calls) pairs for begin, and eight for step.
// Each list ranks by calls descending / VA ascending. Counts are modulo2^32;
// ranking uses full 64-bit counts. The fixed 512-target table never allocates
// on the hot path; nonzero overflow means only retained targets are ranked.
constexpr U kSiteTop = 16, kSiteTableWords = 4 + 3 * kSiteTop, kWitnessWords = 24;
constexpr U kUnknownSiteWords = 2 * kSiteTableWords + kWitnessWords;
// UnknownSiteSnapshot (append-only status tail), all LE uint32:
//  [0..51]   Unknown-row UNRESOLVED calls by (call-site VA, actual target):
//            version(1), distinct pairs, overflow calls, counted calls (mod 2^32),
//            then 16 x (site VA, target VA, calls) ranked calls desc / site asc.
//  [52..103] FIRST unresolved gate of each serial-clone occurrence (any row; the
//            leaf that made it not fully inactive): same header, 16 x (site VA,
//            target VA, occurrences). Observation points use target 0.
//  [104..127] dispatch witness (WitnessWord). Target VAs are preferred-base when
//            inside the image, else the raw runtime address (clone/foreign).
enum WitnessWord : U {
    WitnessDispatches, WitnessUnits, WitnessUnitOverflow, WitnessSnapshotFaults,
    WitnessUnitsChanged, WitnessUnitFieldMask, WitnessBattleChanged, WitnessBattleFieldMask,
    WitnessUnitMismatchCalls, WitnessUnitMissingCalls, WitnessBattleMismatchCalls,
    WitnessUnitInactiveCalls, WitnessBattleInactiveCalls, WitnessManagerMissing,
    WitnessSlotChanged, WitnessSlotFieldMask, WitnessSlotMismatchCalls, WitnessSlotSnapshots,
    WitnessArmyChanged, WitnessArmyMismatchCalls, WitnessArmySnapshots,
    // Finalizer closures (native_finalizer.h): accepted 819770 active-arm and 7F14C0 calls on the owner census
    // path; --brain-finalizer-shadow private-copy comparisons; their non-bit-exact outcomes (mismatch or fault).
    WitnessFinalizerInactiveCalls, WitnessFinalizerShadowCalls, WitnessFinalizerShadowMismatches
};
static_assert(WitnessFinalizerShadowMismatches + 1 == kWitnessWords, "witness tail is full");
// Dispatch witness: WitnessBegin snapshots, at site-6 start, each ==1 worklist
// soldier's unit read set (kUnitFields), battle manager read set, A+444 slot
// read set and, for soldiers without a unit, the A+1F8 army stat table
// ([army+218] and its first 8 entries with entry+10). Gates whose Inactive proof
// needs those fields require the live values to equal the snapshot; WitnessEnd
// re-reads every snapshot a proof consumed (used-only) at site-6 end. Nonzero
// WitnessUnitsChanged/BattleChanged/SlotChanged/ArmyChanged invalidates those
// dispatch-validated Inactive results (masks name the fields).

enum Service : U {
    Effects, SlotAcquire, TargetAcquire, ChargeCallback, MoveDriver, FireDriver,
    Finalize, FireSequence, PathRequest, RequestBuild, RequestCommit, Order,
    NodeFinish, NodeBegin, NodeStep, NodeDestroy, Animation, Parked,
    WrapperEffect, WrapperService, PosePosition, PoseHeading, ReferenceStep,
    Arrival, Unlink, Engage, Random, ReferenceConstruct, Watcher, HolderQuery,
    Timer, UnitWitness, AnimationLookup, ColdLookup, Idle, PreBattle, Exit,
    Projection, Crew, Descriptor, Wrapper610470, Wrapper60CAC0, Wrapper5E52F0,
    Wrapper607540, Wrapper5B9720, VirtualOrder, VirtualQuery, Unknown,
    FireCandidates, FireSubmit, FireGather, MeleeLabel, MutableRead, ServiceCount
};
// Inactive proves no shared mutation or unresolved dependency at this gate:
// the original writes nothing outside the occurrence soldier object (and the
// holders/nodes embedded in it) and caller-stack outputs, and reads only the
// receiver/args, image constants/CRT-initialised globals, or fields proven or
// dispatch-witnessed unchanged during site 6 (per-target proofs: native_brain2.cpp
// ClassifyTarget). Active requires a proved native shared-mutation branch.
// Mutable/foreign reads are Unresolved, not mutation-active. Cloned containers
// inherit reached child outcomes at return, rather than predicting activity.
enum Classification : U { Inactive, Active, Unresolved };
enum Class : U { Core, Thunk, Wrapper602EB0, Wrapper5FCEB0, Artillery, Other, ClassCount };
enum Word : U {
    Version = 0, CensusEnabled, TimingEnabled, Bound, Dispatches, Occurrences,
    OriginalOccurrences, CloneOccurrences, FullyInactive, AnyActive,
    AnyUnknown, RefusedOccurrences, ServiceCalls, ServiceActive, ServiceUnknown,
    ServiceInactive, PoseReads, LeaderPoseReads, TargetPoseReads, OtherPoseReads,
    SelfPoseReads, UnknownClass, MissingClone, AbandonedTiming, TimingOverflow,
    QpcFailures, OriginalTicksLo, OriginalTicksHi, QpcFrequencyLo,
    QpcFrequencyHi, LastEntity, LastClass, LastFirstActive, LastFirstUnknown,
    LastPoseReader, LastPoseSubject, LastPoseLeader, LastPoseTarget,
    LastUnknownTarget, LastUnknownService, ClassCounts = 40,
    CloneTicksLo = 46, CloneTicksHi
};
// Words40..45: Class occurrence counts. First reasons are Service+1, zero none.
// FullyInactive requires a completed clone with zero Active AND Unresolved
// gates. Observe mode (default) calls originals and counts occurrences/classes;
// those occurrences are not claimed inactive. Census enables gated clones.
// Artillery and unknown entry targets remain original at their exact ordinal.
// PoseReads/LeaderPoseReads/TargetPoseReads/OtherPoseReads/SelfPoseReads count
// occurrences, each category at most once. Service rows count raw getter calls.
// Identity words are native addresses. Timing is independent/opt-in; disabled
// means no QPC calls. Counters wrap modulo2^32; QPC totals/frequency are LE u64.
constexpr U kServiceStride = 8;
enum ServiceWord : U {
    Calls = 0, ActiveCalls, UnknownCalls, InactiveCalls,
    FirstActiveOccurrences, FirstUnknownOccurrences, TicksLo, TicksHi
};
constexpr U kCensusWords = ServiceCount * kServiceStride;
// CensusSnapshot: ServiceCount rows in enum order, kServiceStride words each.
// Calls count reached native service entries, or the single native inline region
// for Engage/MeleeLabel/MutableRead. Fire mutation points classify their enclosing
// call rather than adding calls; transparent core/candidate thunks are excluded.
// DiagSnapshot compatibility: reason[0..31] first-active services0..31;
// gate[0..47] calls services0..47; gate[48..79] first-unknown services0..31.
// Full service/first-reason histograms are in CensusSnapshot.

// Bind before clone construction. The image must remain mapped while resident
// clones exist. Writes only supplied NTW2_BIND_COUNT binding slots, never .text.
bool Bind(U imageBase, U* bindings);
// Shadow modes imply serial gated clones; none changes worker admission.
// finalizerShadow: --brain-finalizer-shadow (native_finalizer.h ShadowBefore/After on proved 819770 calls).
void Configure(bool census, bool timing, bool nodeShadow = false, bool fireShadow = false, bool finalizerShadow = false);
void BeginDispatch();
// The clone-entry array and its contents remain immutable until Reset/Release.
void RunOccurrence(U entity, const U* cloneEntries);
// Exact 585D10 pointer-cursor semantics, ==1 activation, live count/data reload
// after every occurrence, including duplicates; calls BeginDispatch once.
void RunWorklist(U manager, const U* cloneEntries);
// Read-only stage observer (per-unit brain Stage A shadow, native_unit_brain.h). When installed, RunWorklist calls
// begin(manager) after WitnessBegin and before the first occurrence, observe(entity) after every occurrence's step
// (same cursor, same ==1 filter, duplicates included) and end() after the last occurrence, before WitnessEnd.
// Owner thread only; an observer must not write native memory. Null uninstalls; Release uninstalls.
struct StageObserver { void (*begin)(U manager); void (*observe)(U entity); void (*end)(); };
void SetStageObserver(const StageObserver* observer);
// --brain-s0 / --brain-unit-* occurrence runner (native_brain_s0.h, native_unit_policy.h). When installed and census is off,
// RunWorklist calls begin(manager) before the first occurrence and end() after the last (inside any observer bracket), and
// RunOccurrence hands the call of the occurrence's step to run(entity, class, original vt+0C entry, clone entries), which
// executes it exactly once (the original or its instruction-identical/unit clone). Owner thread only. Null uninstalls; Release
// uninstalls.
struct OccurrenceRunner { void (*begin)(U manager); void (*end)(); void (*run)(U entity, U cls, U original, const U* cloneEntries); };
void SetOccurrenceRunner(const OccurrenceRunner* runner);
// Owner thread, inside an occurrence runner's run(): the address of the current worklist slot (cursor) and the live end of
// the array (cursor + 4 is the next entry when below end). False outside RunWorklist or when the cursor is not inside the
// manager's live array (the native loop keeps a stale cursor across a reallocation exactly like 585D10).
bool WorklistWindow(U* cursor, U* end);
// Site-6 dispatch witness (owner thread only; RunWorklist calls Begin/End).
// Begin snapshots the read sets of the current ==1 worklist (replacing any open
// snapshot); End re-checks only the rows (and slot rows / army entries) that a
// successful proof consumed, closes the snapshot and returns the number of those
// objects whose consumed values changed (0 = dispatch-validated proofs held).
// Abort closes an open snapshot without checking. With no open snapshot, every
// witness-dependent gate classifies Unresolved. Pool threads only read the
// snapshot (no lazy initialisation) between Begin and End/Abort.
void WitnessBegin(U manager);
U WitnessEnd();
void WitnessAbort();
// Cumulative VirtualQuery calls made by the witness readability probes (Begin/End/hash re-reads), modulo 2^32.
// Owner thread; native_brain_workers reports the per-stage delta.
U WitnessProbeQueries();
void Snapshot(U* words /*[kWords]*/);
void CensusSnapshot(U* words /*[kCensusWords]*/);
void DiagSnapshot(U* reason /*[kDiagReasonWords]*/, U* gate /*[kDiagGateWords]*/);
void RouteSnapshot(U* words /*[kRouteWords]*/);
void NodeTargetSnapshot(U* words /*[kNodeTargetWords]*/);
void UnknownSiteSnapshot(U* words /*[kUnknownSiteWords]*/);
// Reset zeros counters/context but retains bindings/config. Until a dispatch or
// occurrence, snapshots stay entirely zero. Release clears transient context
// and config, retaining final counters and immutable bindings for restart.
void Reset();
void Release();

// Real-original forwarding seam for mapped-native-image oracles. Original x86
// thiscall ABI, including RET n, AL-only and x87 results. Zero means a service
// has no canonical direct entry. No fake native implementation is provided.
U GateAddress(Service service);
Classification ClassifyService(Service service, U receiver);

// Worker-safe pure entries: no global/census writes; they read only the bound
// image delta, immutable tables and the current witness snapshot. `target` is
// the live (rebased) destination, `site` the preferred-VA call instruction as in
// the gate stack, `args` the REAL gate stack argument pointer (stack-output
// proofs require args <= p && p + size <= TEB StackBase), `entity` the occurrence
// soldier as addressed by the executing code (a private mirror on workers).
// Cloned targets: Active when WorkerSiteForced(site), else Inactive (classify
// the clone's descendants). WorkerForwardable: not cloned and Inactive under the
// contract above. WorkerWriteFree: register-only leaves (no memory access at all)
// and proven store-free leaves; a caller may forward these on any receiver.
// Witness dependencies: every witness-dependent Inactive proof reached through a
// Worker* entry with a non-null `deps` appends one de-duplicated entry naming the
// snapshot it consumed (unit read set, slot header + one row, battle read set).
// `deps` must be zeroed per occurrence; more than kWitnessDepCap distinct
// entries sets `overflow` and the caller must refuse the occurrence. A single
// `deps` may be passed to several calls (WorkerClassify then WorkerForwardable).
// Frame/Terrain (819770 active arm, 7F14C0, 80E9D0 with Frame aux 1 = 7F4950's transform words only;
// native_finalizer.h) carry the FNV-1a of the read set taken at classification time instead of a Begin snapshot;
// WitnessDepsHold recomputes it at the owner's ordinal. So do the foreign-object read sets added by GateClassify3
// (analysis/native-brain-unknowns.md §18):
//   Word    one dword at `key` (63F040: [R+1E8]+20; 66D2F3 on an own target: [A+670][0]), `frame` = its value;
//   Target  the reacquire block 66D2F3 on target T = [A+1EC] (T+628/+630/+634/+638/+66C/+670 and [T+670][0]);
//   Crew    6A7DD0's member array `key` = [A+670] with `aux` = count A+66C: the members and their vtables;
//   Anim    the posture animation set `key` = [R+218] with `aux` = AnimIndex (native_finalizer AnimHash).
// Keys are never addresses inside the occurrence soldier: those bytes are already digest-guarded.
enum WitnessDepKind : U {
    WitnessDepUnit = 1, WitnessDepSlot = 2, WitnessDepBattle = 3, WitnessDepArmy = 4,
    WitnessDepFrame = 5, WitnessDepTerrain = 6, WitnessDepWord = 7, WitnessDepTarget = 8,
    WitnessDepCrew = 9, WitnessDepAnim = 10
};
struct WitnessDep {
    U kind;
    U key   /*unit | slot record (A+444) | battle manager | army (A+1F8) | frame | root [A+28] | word address | target
              soldier | member array | animation set*/;
    U frame /*slot row or army stat index A+374 | read-set hash or word value, else 0*/;
    U aux   /*Crew: member count; Anim: AnimIndex; else 0*/;
};
constexpr U kWitnessDepCap = 16;
struct WitnessDeps { U count; U overflow; WitnessDep items[kWitnessDepCap]; };
Classification WorkerClassify(U target, U site, U receiver, const U* args, U entity, U* service,
                              WitnessDeps* deps = nullptr);
bool WorkerSiteForced(U site);
bool WorkerForwardable(U target, U site, U receiver, const U* args, U entity, WitnessDeps* deps = nullptr);
bool WorkerWriteFree(U target);
// NTW2_CLONE id of the BRAIN2 clone for a preferred VA, else ~0u.
U CloneIdFor(U originalVA);
// Observe() per-site result for a PUSHAD block exactly as ObserveGate passes.
Classification WorkerObserveClassify(U site, const U* registers, U entity, WitnessDeps* deps = nullptr);
// Owner thread, witness open (between WitnessBegin and WitnessEnd/Abort): true
// when every dependency's live values still equal the Begin snapshot, by the
// same pointer-identity-then-value comparison the proof used (no VirtualQuery).
// False when the witness is closed, `overflow` is set, or any value changed.
// Like the proofs, it assumes the witnessed objects are not freed mid-stage.
bool WitnessDepsHold(const WitnessDeps& deps);
// Witness memo (performance only; never changes a classification or a re-check result). A witness proof or
// read-set hash is a pure function of native memory, so while nothing writes native memory it needs computing once
// per object instead of once per gate/commit (live cy-quiet1: TerrainHash + UnitStatic were ~20% of the owner's
// site-6 runtime samples, the same model/unit hashed for every soldier). The caller owns one table per thread
// and binds it (BindWitnessMemo) only around Worker*/WitnessDepsHold calls; unbound threads (census owner runs,
// Begin/End) never consult a memo. `epoch` must change (BumpWitnessMemo) whenever native memory the memoized read
// sets cover may have changed: workers bump per dispatch (native memory is frozen during it: workers write only
// private copies), the owner after every owner-run occurrence or replayed event. `worldOnly` (the owner walk,
// where commits write soldier footprints/timers between re-checks) memoizes only the read sets that never lie in a
// soldier footprint or timer: unit, battle manager, army stat table, terrain (model/grid/field + image globals).
// Slot/Frame/Target/Crew/Anim are then recomputed. Only successful proofs are memoized (a failure refuses anyway).
// Keys inside [privateLo, privateHi) (the caller's private storage, reused per occurrence) are never memoized.
struct WitnessMemo {
    static constexpr U kSlots = 512;
    struct Entry { U kind, key, aux, epoch, value; };
    U epoch, worldOnly, privateLo, privateHi;
    U hits, misses; // cumulative since the table was zeroed
    Entry entries[kSlots];
};
void BindWitnessMemo(WitnessMemo* memo); // calling thread; null unbinds
void BumpWitnessMemo(WitnessMemo& memo); // new epoch: every entry is stale
// The receiver-, argument- and entity-independent part of WorkerClassify for a gate (target, site): StaticForward
// when every such call is Inactive and forwarded to `target` unchanged (stubs, register-only leaves, the
// unconditional own-field/pure leaf list), StaticClone when it always re-enters the worker family (a cloned
// container whose WorkerClassify result is Inactive by target and site alone), else StaticDynamic. The image and
// the bindings are immutable, so a gate may cache the verdict for the whole binding.
enum StaticVerdict : U { StaticDynamic, StaticForward, StaticClone };
StaticVerdict WorkerStaticVerdict(U target, U site);
// Worker RNG stream binding (native_brain_workers). `lcg` is the model LCG word model+0x50 (model =
// [[A+28]+8], advanced by 5FC070 and inline by 80E020) that the worker owner bound for the current stage;
// 0 unbinds. Owner thread only, set before the dispatch and cleared after it, so pool threads only read it.
// While bound, WorkerClassify classifies 5FC070 on exactly that receiver Inactive ("worker-safe stream"):
// the worker gate serves such a call from the occurrence's private stream word and never lets it reach
// the shared word. Every other 5FC070 call (unbound, or another receiver) is Active. WorkerForwardable
// is never true for 5FC070. The census/owner classification (Random: Active) is unchanged.
void SetWorkerRandomStream(U lcg);
bool WorkerRandomStream(U target, U receiver);
const char* ServiceName(Service service);
} // namespace ntw2_brain2
