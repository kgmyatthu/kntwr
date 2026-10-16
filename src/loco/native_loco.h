#pragma once
#include <stdint.h>
#include "../native_workload.h"

// Keep this order identical to ntw2_loco::Word and the append-only public status.
#define NTW2_LOCO_WORD_LABELS \
    "version", "calls", "entities", "admitted", "rejected", \
    "reject_class", "reject_lifetime", "reject_activity", "reject_target", "reject_parked", \
    "reject_pending", "reject_charge_fire", "reject_posture_order", "reject_node", "reject_environment", \
    "wrapper_battle", "wrapper_alternate", "direct", "staging", \
    "admitted_us", "admitted_max_us", "rejected_us", "rejected_max_us", \
    "dispatch_us", "dispatch_max_us", "max_entities", "filtered", "cloned", "native", \
    "service_calls", "max_entity_services", "serviced_entities", \
    "unlink_grid", "unlink_owner", "insert_owner", "insert_grid", "sweep", "resolve", "height_owner", "wrapper_query", \
    "trace_overflow", "class_wrapper", "clone_bytes", "generation", "clone_enabled", "owner_thread", "reentry_refusals", "reserved"

// Independent diagnostics at site 13; these buckets overlap and are not a
// partition. Only reasons selected by enforced_mask refuse serial MOVE.
#define NTW2_LOCO_GATE_LABELS \
    "version", "entities", "candidates", "admitted", "enforced_mask", \
    "class", "lifetime", "activity", "target", "parked", "pending", \
    "charge_fire", "posture_order", "node", "environment", \
    "charge_4e8", "fire_390", "fire_3bc", "fire_3c8", "posture_220", "order", \
    "slot_row", "reference_node", "holder_2cc", "holder_51c", \
    "activity_0", "activity_1", "activity_9", "activity_1d", "activity_23", "activity_0c", "activity_other", \
    "latch_618", "latch_619", "latch_f1", "latch_5ab", \
    "unclassified", "diagnostic_faults", "legacy_admitted", "newly_admitted", \
    "reserved_40", "reserved_41", "reserved_42", "reserved_43", \
    "reserved_44", "reserved_45", "reserved_46", "reserved_47"

#define NTW2_LOCO_SERVICE_LABELS \
    "version", "enabled", "timed_calls", "stack_overflows", "abandoned_frames", \
    "clone_wall_us", "services_union_us", "outside_services_us", "max_depth", "qpc_failures", \
    "reserved_10", "reserved_11", \
    "unlink_grid_us", "unlink_owner_us", "insert_owner_us", "insert_grid_us", \
    "sweep_us", "resolve_us", "height_owner_us", "wrapper_query_us", \
    "unlink_grid_max_us", "unlink_owner_max_us", "insert_owner_max_us", "insert_grid_max_us", \
    "sweep_max_us", "resolve_max_us", "height_owner_max_us", "wrapper_query_max_us", \
    "unlink_grid_calls", "unlink_owner_calls", "insert_owner_calls", "insert_grid_calls", \
    "sweep_calls", "resolve_calls", "height_owner_calls", "wrapper_query_calls", \
    "reserved_36", "reserved_37", "reserved_38", "reserved_39"

#define NTW2_LOCO_GRID_LABELS \
    "version", "captures", "records", "primary", "secondary", "memberships", "cells", "mismatches", \
    "sampled_records", "births", "removals", "reused_addresses", "capture_us", "csr_us", "faults", "refusals", \
    "generation", "epoch", "bytes", "max_records", "max_memberships", "native_order_cells", "unsupported_nodes", \
    "deactivations", "membership_removals", "reserved_25", "reserved_26", "reserved_27", "reserved_28", "reserved_29", "reserved_30", "reserved_31"
#define NTW2_LOCO_PARALLEL_LABELS \
    "version", "enabled", "chunks", "worker_entities", "owner_entities", "needs_env", "needs_sweep", "needs_resolve", \
    "needs_class_wrapper", "needs_relationship", "needs_staging", "needs_duplicate", "replayed_services", \
    "capture_us", "csr_us", "kernel_us", "replay_us", "staging_us", "faults", "sticky", "inline_chunks", \
    "invalidated", "last_exception", "max_worker_run", "committed", "native_fallbacks", "needs_admission", \
    "last_entity", "last_ordinal", "last_eip", "last_access", "last_serial"

// B2 diagnostics are a new status tail; never resize the original parallel block.
#define NTW2_LOCO_OWNED_LABELS \
    "version", "enabled", "worker_active_direct", "worker_active_battle", "worker_inactive", \
    "needs_class_wrapper", "needs_alternate_wrapper", "needs_pending", "needs_foreign_transform", \
    "needs_staging_oob", "needs_unit_dependency", "needs_sweep", "needs_resolve", "env_untested", \
    "needs_event", "needs_capacity", "needs_duplicate", \
    "replay_unlink_grid", "replay_unlink_owner", "replay_insert_owner", "replay_insert_grid", "replay_env", \
    "capture_us", "kernel_us", "replay_us", "worker_time_us", "max_chunk_us", "chunks", \
    "duplicate_refusals", "faults", "fallback_entities", "active_entities"

#define NTW2_LOCO_OWNED_DETAIL_LABELS \
    "version", "quiet_enabled", "staging_initial_a3_zero", "staging_result_a3_zero", \
    "staging_clamp_callback", "actual_class_wrapper", "other_class", "actual_alternate_wrapper", \
    "unit_blocked_class", "unit_blocked_staging", "unit_blocked_other", \
    "observed_f0", "worker_f0", "observed_initial_a3_zero", "reserved_14", "reserved_15"

// Per-stage B2 phase breakdown. `dispatches / loco_words.calls` must stay 1.0 per active stage.
// chunk_us histogram buckets are <=16, <=32, <=64, <=128, <=256, <=512, <=1024, >1024 microseconds.
// replay_commit_us/replay_fallback_us are x16 estimates from every 16th replayed/fallback occurrence.
#define NTW2_LOCO_OWNED_PHASE_LABELS \
    "version", "dispatches", "chunks", "list_entities", "max_chunk_entities", \
    "chunk_le16us", "chunk_le32us", "chunk_le64us", "chunk_le128us", "chunk_le256us", "chunk_le512us", "chunk_le1024us", "chunk_gt1024us", \
    "index_us", "scene_prepare_us", "catalog_prepare_us", "worker_prepare_us", "dispatch_wall_us", \
    "replay_loop_us", "replay_commit_est_us", "replay_fallback_est_us", "replay_samples", \
    "unprocessed", "validation_refusals", "chunk_time_sum_us", "computed", "worker_refused", \
    "participants_used", "chunk_size_last", "participant_overflow", "reserved_30", "reserved_31"

// One-time activation work and paired chunk wall/CPU evidence; appended status block.
#define NTW2_LOCO_OWNED_LOAD_LABELS \
    "version", "activation_calls", "activation_us", "scene_us", "catalog_us", "participants_us", "arena_us", \
    "model_changes", "capacity_refusals", "chunk_cpu_us", "chunk_wall_max_us", "chunk_cpu_at_wall_max_us", \
    "activation_failure_reason", "activation_exception", "activation_detail", "activation_actual"

// Stage C tail: old grid/status rows retain their original size and offsets. `dispatches` counts every
// separate pool dispatch of a publication: exactly two for a normal build (1: capture, identity, node validation,
// per-cell tally and strip totals; 2: row-run scan/scatter tasks plus the incarnation/accounting finish chunks), plus
// the optional native-chain verifier as its own final dispatch. Refusals before the first dispatch count none.
// `build_us` is the owner's whole entry-to-publication time (serial registry/identity construction and the owner
// plan between the dispatches included) and never includes verify_us.
#define NTW2_LOCO_GRID_V2_LABELS \
    "version", "enabled", "verify_enabled", "builds", "build_us", "max_build_us", "records", "memberships", \
    "verify_mismatches", "verify_us", "dispatches", "committed_records", "record_reads", \
    "refusals", "faults", "epoch"

#ifdef __cplusplus
#include "native_owned_grid.h"
namespace ntw2_loco {
enum Word : uint32_t {
    Version, Calls, Entities, Admitted, Rejected,
    RejectClass, RejectLifetime, RejectActivity, RejectTarget, RejectParked,
    RejectPending, RejectChargeFire, RejectPostureOrder, RejectNode, RejectEnvironment,
    WrapperBattle, WrapperAlternate, Direct, Staging,
    AdmittedUs, AdmittedMaxUs, RejectedUs, RejectedMaxUs,
    DispatchUs, DispatchMaxUs, MaxEntities, Filtered, Cloned, Native,
    ServiceCalls, MaxEntityServices, ServicedEntities,
    ServiceUnlinkGrid, ServiceUnlinkOwner, ServiceInsertOwner, ServiceInsertGrid,
    ServiceSweep, ServiceResolve, ServiceHeightOwner, ServiceWrapperQuery,
    TraceOverflow, ClassWrapper, CloneBytes, Generation, CloneEnabled, OwnerThread,
    ReentryRefusals, Reserved, WordCount
};
enum Reason : uint32_t {
    Eligible, Class, Lifetime, Activity, Target, Parked, Pending,
    ChargeFire, PostureOrder, Node, Environment
};
// Activity/order/node/fire constrain future owned NODE/worker kernels, not an
// instruction-identical mover whose services still run on the owner thread.
constexpr uint32_t kMoveGateMask = 0x233u; // bit(reason-1): class, lifetime, parked, pending, environment
enum GateWord : uint32_t {
    GateVersion, GateEntities, GateCandidates, GateAdmitted, GateEnforcedMask,
    GateClass, GateLifetime, GateActivity, GateTarget, GateParked, GatePending,
    GateChargeFire, GatePostureOrder, GateNode, GateEnvironment,
    GateCharge4E8, GateFire390, GateFire3BC, GateFire3C8, GatePosture220,
    GateOrder, GateSlotRow, GateReferenceNode, GateHolder2CC, GateHolder51C,
    GateActivity0, GateActivity1, GateActivity9, GateActivity1D, GateActivity23,
    GateActivity0C, GateActivityOther, GateLatch618, GateLatch619, GateLatchF1,
    GateLatch5AB, GateUnclassified, GateDiagnosticFaults, GateLegacyAdmitted,
    GateNewlyAdmitted, GateReserved40, GateReserved41, GateReserved42,
    GateReserved43, GateReserved44, GateReserved45, GateReserved46, GateReserved47,
    GateWordCount
};
enum Service : uint32_t {
    UnlinkGrid, UnlinkOwner, InsertOwner, InsertGrid, Sweep, Resolve, HeightOwner, WrapperQuery, ServiceCount
};
enum ServiceWord : uint32_t {
    TimingVersion, TimingEnabled, TimingCalls, TimingOverflows, TimingAbandoned,
    TimingCloneWallUs, TimingUnionUs, TimingOutsideUs, TimingMaxDepth, TimingQpcFailures,
    TimingReserved10, TimingReserved11,
    TimingServiceUs = 12, TimingServiceMaxUs = 20, TimingServiceCalls = 28,
    TimingReserved36 = 36, TimingReserved37, TimingReserved38, TimingReserved39,
    ServiceWordCount
};
enum GridWord : uint32_t {
    GridVersion, GridCaptures, GridRecords, GridPrimary, GridSecondary, GridMemberships, GridCells, GridMismatches,
    GridSampled, GridBirths, GridRemovals, GridReused, GridCaptureUs, GridCsrUs, GridFaults, GridRefusals,
    GridGeneration, GridEpoch, GridBytes, GridMaxRecords, GridMaxMemberships, GridNativeOrderCells, GridUnsupported,
    GridDeactivations, GridMembershipRemovals,
    GridWordCount = 32
};
enum ParallelWord : uint32_t {
    ParallelVersion, ParallelEnabled, ParallelChunks, ParallelWorkerEntities, ParallelOwnerEntities,
    ParallelNeedsEnv, ParallelNeedsSweep, ParallelNeedsResolve, ParallelNeedsClassWrapper,
    ParallelNeedsRelationship, ParallelNeedsStaging, ParallelNeedsDuplicate, ParallelReplayedServices,
    ParallelCaptureUs, ParallelCsrUs, ParallelKernelUs, ParallelReplayUs, ParallelStagingUs,
    ParallelFaults, ParallelSticky, ParallelInlineChunks, ParallelInvalidated, ParallelLastException,
    ParallelMaxWorkerRun, ParallelCommitted, ParallelNativeFallbacks, ParallelNeedsAdmission,
    ParallelLastEntity, ParallelLastOrdinal, ParallelLastEip, ParallelLastAccess, ParallelLastSerial,
    ParallelWordCount = 32
};
enum OwnedWord : uint32_t {
    OwnedVersion, OwnedEnabled, OwnedWorkerDirect, OwnedWorkerBattle, OwnedWorkerInactive,
    OwnedNeedsClassWrapper, OwnedNeedsAlternateWrapper, OwnedNeedsPending, OwnedNeedsForeignTransform,
    OwnedNeedsStaging, OwnedNeedsUnit, OwnedNeedsSweep, OwnedNeedsResolve, OwnedNeedsEnv,
    OwnedNeedsEvent, OwnedNeedsCapacity, OwnedNeedsDuplicate,
    OwnedReplayUnlinkGrid, OwnedReplayUnlinkOwner, OwnedReplayInsertOwner, OwnedReplayInsertGrid, OwnedReplayEnv,
    OwnedCaptureUs, OwnedKernelUs, OwnedReplayUs, OwnedWorkerTimeUs, OwnedMaxChunkUs, OwnedChunks,
    OwnedDuplicateRefusals, OwnedFaults, OwnedFallbackEntities, OwnedActiveEntities, OwnedWordCount
};
enum OwnedDetailWord : uint32_t {
    OwnedDetailVersion, OwnedDetailQuiet, OwnedDetailInitialA3, OwnedDetailResultA3,
    OwnedDetailClampCallback, OwnedDetailClassWrapper, OwnedDetailOtherClass, OwnedDetailAlternate,
    OwnedDetailUnitClass, OwnedDetailUnitStaging, OwnedDetailUnitOther,
    OwnedDetailObservedF0, OwnedDetailWorkerF0, OwnedDetailObservedInitialA3,
    OwnedDetailReserved14, OwnedDetailReserved15, OwnedDetailWordCount
};
enum OwnedPhaseWord : uint32_t {
    OwnedPhaseVersion, OwnedPhaseDispatches, OwnedPhaseChunks, OwnedPhaseListEntities, OwnedPhaseMaxChunkEntities,
    OwnedPhaseChunkLe16, OwnedPhaseChunkLe32, OwnedPhaseChunkLe64, OwnedPhaseChunkLe128,
    OwnedPhaseChunkLe256, OwnedPhaseChunkLe512, OwnedPhaseChunkLe1024, OwnedPhaseChunkGt1024,
    OwnedPhaseIndexUs, OwnedPhaseScenePrepareUs, OwnedPhaseCatalogPrepareUs, OwnedPhaseWorkerPrepareUs,
    OwnedPhaseDispatchWallUs, OwnedPhaseReplayLoopUs, OwnedPhaseReplayCommitEstUs, OwnedPhaseReplayFallbackEstUs,
    OwnedPhaseReplaySamples, OwnedPhaseUnprocessed, OwnedPhaseValidationRefusals, OwnedPhaseChunkTimeSumUs,
    OwnedPhaseComputed, OwnedPhaseWorkerRefused, OwnedPhaseParticipantsUsed, OwnedPhaseChunkSizeLast,
    OwnedPhaseParticipantOverflow, OwnedPhaseReserved30, OwnedPhaseReserved31, OwnedPhaseWordCount
};
enum OwnedLoadWord : uint32_t {
    OwnedLoadVersion, OwnedLoadCalls, OwnedLoadUs, OwnedLoadSceneUs, OwnedLoadCatalogUs,
    OwnedLoadParticipantsUs, OwnedLoadArenaUs, OwnedLoadModelChanges, OwnedLoadCapacityRefusals,
    OwnedLoadChunkCpuUs, OwnedLoadChunkWallMaxUs, OwnedLoadChunkCpuAtWallMaxUs,
    OwnedLoadFailureReason, OwnedLoadException, OwnedLoadDetail, OwnedLoadActual, OwnedLoadWordCount
};
// Cached allocation breakdown (SampleStorage). The first eight words are bytes and sum exactly to StorageBytes();
// Participants includes the arena object, participant/context structs, private clones and the legacy worker arena.
// The last three words are native counts (chain occurrences, owner closure, tree entries) of the captured scene.
enum StorageWord : uint32_t {
    StorageMovement, StorageGrid, StorageScene, StorageCatalog, StorageParticipants,
    StorageSweep, StorageResolve, StorageEnv, StorageSceneNodes, StorageSceneOwners, StorageTreeEntries,
    StorageWordCount
};
enum OwnedActivationFailure : uint32_t {
    ActivationOk, ActivationNotStarted, ActivationDisabled, ActivationBusy, ActivationBadModel,
    ActivationBadCapacity, ActivationModelMismatch, ActivationGridAllocation, ActivationAlreadyAttempted,
    ActivationSlotAllocation, ActivationWarmup, ActivationOwnerUnavailable, ActivationSceneCapture,
    ActivationSceneVerification, ActivationSceneIdentity, ActivationCatalog,
    ActivationSweepWorker, ActivationResolveWorker, ActivationEnvWorker
};
enum GridV2Word : uint32_t {
    GridV2Version, GridV2Enabled, GridV2VerifyEnabled, GridV2Builds, GridV2BuildUs, GridV2MaxBuildUs,
    GridV2Records, GridV2Memberships, GridV2VerifyMismatches, GridV2VerifyUs, GridV2Dispatches,
    GridV2CommittedRecords, GridV2RecordReads, GridV2Refusals, GridV2Faults, GridV2Epoch, GridV2WordCount
};
struct Binding {
    uint32_t image_delta;
    uint32_t wrap_clone;
    uint32_t move_clone;
    bool use_clone;
    uint32_t selector_clone;
    uint32_t class_wrap_clone;
    uint32_t clone_bytes;
    bool use_parallel;
    void (__stdcall* dispatch)(uint32_t, uint32_t, uint32_t, void*);
    uint32_t pool;
    uint32_t workers;
    bool use_shadow;
    bool use_owned_services;
    bool use_quiet;
    // Stage C publication after site-13 replay; verification alone also enables it.
    bool use_grid;
    bool verify_grid;
    // Synchronous owner-boundary handoff for live scene capture only. Null means
    // the caller already owns a quiescent model (standalone mapped-image oracles).
    bool (*capture_at_tick)(void (*capture)(void*), void* context);
    // Optional grid-probation relink window (ntw2_grid_probation::Window): the runtime opens the owner's native
    // relink window after PrepareOwned and closes it in Stage's finally (after grid publication). Null = disabled.
    void (__cdecl *grid_window)(void* manager, uint32_t open);
};
// Bind before clone emission. Scratch headers have stable addresses across starts.
void Bind(uint32_t image_delta, uint32_t* bindings);
// Workers receive private ABI-shaped state; native publication remains owner-only.
bool Start(const Binding& binding);
void Stop();
uint32_t __fastcall Stage(void* manager);
void Sample(uint32_t words[WordCount]);
void SampleGates(uint32_t words[GateWordCount]);
// Inclusive QPC time while Run/Stage owns a clone invocation. Outside-services
// time includes untapped helpers and instrumentation; it is NOT pure arithmetic.
void SampleServices(uint32_t words[ServiceWordCount]);
void SampleGrid(uint32_t words[GridWordCount]);
void SampleGridV2(uint32_t words[GridV2WordCount]);
void SampleParallel(uint32_t words[ParallelWordCount]);
void SampleOwned(uint32_t words[OwnedWordCount]);
void SampleOwnedDetails(uint32_t words[OwnedDetailWordCount]);
void SampleOwnedPhase(uint32_t words[OwnedPhaseWordCount]);
void SampleOwnedLoad(uint32_t words[OwnedLoadWordCount]);
// Allocation breakdown refreshed at Start/ActivateOwned/Stop only; O(1) copy, all zero when stopped.
void SampleStorage(uint32_t words[StorageWordCount]);
// Cached catalog geometry accounting (same refresh points and O(1) copy, all zero when stopped), in
// ntw2_resolve::SampleCatalogStorage order: capacity bytes of rings, capsules, walls, edges, polygon points (these five
// sum to the catalog bytes in StorageCatalog), then the five unique logical counts in the same order.
enum : uint32_t { CatalogStorageWordCount = 10 };
void SampleCatalogStorage(uint32_t words[CatalogStorageWordCount]);
// Battle activation only, after Start and before Stage. Allocation/prefault/warmup
// and participant preparation stay on the caller; only scene/catalog capture uses capture_at_tick.
// Capacity fixes every activation-sized buffer: movement slots use capacity.primary (never records),
// the owned grid uses records/cells/memberships. Nothing grows afterwards: a Stage whose worklist or a grid
// capture whose registries/cells/memberships exceed the capacity refuses before any publication or game write.
// A failed or mismatched activation leaves owned execution unavailable, never partially published.
bool ActivateOwned(void* model, const ntw2_workload::Capacity& capacity);
// Bytes owned by this module: movement slots/states/worklist, participant structs+clones+contexts,
// scene/catalog, owned grid block, legacy worker arena. Cached; O(1); zero when stopped.
uint32_t StorageBytes();
// Planned activation allocation for `capacity`, valid after Start and before ActivateOwned (no allocation, same
// layout arithmetic as ActivateOwned): page-rounded grid block + slots/states/worklist + one context struct per
// participant that has none yet. Scene/catalog/vector capacities (known only after capture) are NOT included;
// they are visible in StorageBytes() afterwards. UINT32_MAX = not started, incoherent capacity, or overflow.
uint32_t EstimateActivationBytes(const ntw2_workload::Capacity& capacity);
// Movement slot size (all primary-capacity slots are this wide): 448 bytes + 1 state byte + 4 worklist bytes.
// The slot stores only the proven live-in guard footprint and the proven write footprint of the mover closure.
constexpr uint32_t kOwnedSlotBytes = 448;
// Read-only geometry build seam; no native chain import. Requires ActivateOwned.
bool CaptureGrid(void* manager);
const GridView* ReadGrid();
const GridView* ReadGridForCollision(void* manager);
// No counters or mutation; evaluates the actual occurrence, not a cached cohort.
uint32_t Classify(void* entity);
// Executes precisely one wrapper/integrator, without selector latch/staging work.
// Also the mapped-original oracle seam. Run never retries a partially executed call.
void Run(void* entity, bool wrapper);
struct ServiceRecord { uint32_t service; uint32_t receiver; };
// Trace of the last Run/selector occurrence; bounded, with explicit overflow status.
// Records are copied by the caller before the next execution. No callback changes FP state.
const ServiceRecord* ServiceTrace(uint32_t* count);
void ResetServiceTrace();
#ifdef NTW2_LOCO_ORACLE
// Isolated ABI preservation probes only; absent from the runtime build.
uint32_t SetServiceTargetForTest(Service service, uint32_t address);
// Compact movement-slot footprint inspection (offsets are native receiver offsets, spans sorted/disjoint/dword aligned).
struct OwnedSpanForTest { uint32_t offset, bytes; };
struct OwnedLayoutForTest {
    uint32_t slotBytes, guardBytes, outputBytes, wrapperOutputBytes;
    uint32_t guardCount, outputCount, wrapperCount, alwaysWrittenCount;
    const OwnedSpanForTest *guard, *output, *wrapperOutput;
    const uint32_t* alwaysWritten; // dword offsets rewritten on every committed path and therefore not guarded
};
OwnedLayoutForTest OwnedLayout();
enum OwnedTestPhase { OwnedTestSerial, OwnedTestPort, OwnedTestReplay };
using OwnedServiceObserverForTest = void (*)(uint32_t original, Service service, uint32_t ordinal, OwnedTestPhase phase);
OwnedServiceObserverForTest SetOwnedServiceObserverForTest(OwnedServiceObserverForTest observer);
#endif
static_assert(WordCount == 48, "Stage 1 status is append-only");
static_assert(GateWordCount == 48, "independent gate diagnostics are append-only");
static_assert(ServiceWordCount == 40, "service timing diagnostics are append-only");
static_assert(GridWordCount == 32 && ParallelWordCount == 32, "owned-grid status is append-only");
static_assert(OwnedWordCount == 32, "owned service diagnostics are a separate append-only tail");
static_assert(OwnedDetailWordCount == 16, "owned admission details are a separate append-only tail");
static_assert(OwnedPhaseWordCount == 32, "owned phase diagnostics are a separate append-only tail");
static_assert(OwnedLoadWordCount == 16, "owned activation diagnostics are a separate append-only tail");
static_assert(StorageWordCount == 11, "storage breakdown is the published memory-row tail");
static_assert(GridV2WordCount == 16, "Stage C diagnostics are a separate append-only tail");
} // namespace ntw2_loco
#endif
