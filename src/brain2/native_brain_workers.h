#pragma once
#include <stdint.h>
#include "clones/ntw2_clones.h"

// BRAIN2 Stage 2: the per-soldier brain decision step (site 6: 0x585D10 -> vt+0x0C) on pool workers.
//
// Every soldier is still stepped exactly once, in native worklist order. A worker never writes native memory:
// it copies the soldier's footprint (kReceiverBytes, plus the separately allocated timer object behind +0x518)
// into participant-private storage, rebases the self/inline-object pointers onto that copy, and runs the
// source-pinned BRAIN_W clone family against it. Every service the clone reaches goes through a participant
// gate: cloned containers re-enter the worker family, services the GateClassify tables prove read-only are
// forwarded to the original, and EVERYTHING else (active, unresolved, unknown, forced sites) refuses the
// occurrence before anything is published. The owner then walks the live worklist cursor exactly like the
// native loop; for each soldier it validates a 128-bit digest of the live footprint against the one captured
// before the worker ran, publishes the exact differing byte spans, and replays recorded events (if any) at
// their checkpoint. A refused, invalidated, skipped-then-activated, desynchronized or unprocessed soldier runs
// through ntw2_brain2::RunOccurrence at its own ordinal instead. Faults before commit never touch native
// state, disable the feature stickily and leave the remaining soldiers to the owner.
//
// Admission is "no Active/Unresolved service reached". The worker proofs are the dispatch-level witness and
// service tables in native_brain2.cpp (WorkerClassify/WorkerForwardable); this module adds no proof of its own.
// Witness-dependent proofs record per-occurrence WitnessDeps; the owner re-validates them (WitnessDepsHold) at
// that soldier's ordinal, so a value changed by an earlier owner-run soldier sends the soldier to the owner.
//
// RNG streams (deliberate divergence from vanilla; determinism between runs is kept, vanilla draw order is not).
// The brain step draws the battle-wide model LCG word W = model+0x50 (model = [[A+28]+8]) through 5FC070
// (W = W*0x343FD + 0x269EC3; ST0 = float(W >> 16) * [0x131A7AC]) and 80E020 (same step inlined). At stage
// start the owner binds W from the first ==1 brain soldier and snapshots S = W. Ordinal k of the worklist walk
// draws from its own LCG word seeded StreamSeed(S, generation, k), whoever executes it: a worker serves 5FC070
// on W from a participant-private word through the ORIGINAL 5FC070 (identical output format), and the owner
// writes the seed into W itself before every owner-run occurrence. A committed occurrence is therefore
// byte-identical to the same occurrence run by the owner, so which ordinals commit (thread timing, capacity)
// never changes the outcome. At stage end W = LcgAdvance(S, walked occurrences). `generation` counts bound
// stages since Start/Reset (Reset runs at every battle activation). Not bound when event deferral is enabled
// (a replayed event could draw at a point the worker did not), when no ==1 brain soldier exists, or when W is
// not writable: then 5FC070 stays Active (refused) on workers and the real word is used serially as before.
// analysis/native-brain2-design.md "RNG streams" documents the draw sites and the compromise.
//
// Performance path (version 4, --brain-quiet). Quiet mode changes no admission or commit rule: workers run the same
// gates; the owner runs refused/stale soldiers through ntw2_brain2::RunOccurrence configured WITHOUT census (the
// original step, not the gated census clone: 3.7 -> 0.17 us per owner run in the oracle profile), and guard misses
// are counted without block checksums. In every mode: readability proofs use a per-stage granule table
// (native_region_table.h) instead of an 8-entry LRU; the capture is one fused pass (copy + digest + rebase);
// export + diff is one SIMD pass; a gate refusal leaves the clone through longjmp instead of RaiseException;
// a forwarded service is classified once; slots are stamped instead of cleared; the owner walk prefetches the
// footprints it will digest. Crew dependency: see the phase row. Phase telemetry: PhaseSnapshot.
#define NTW2_BRAIN_WORKER_WORD_LABELS \
 "version", "enabled", "participants", "workers", "dispatches", "handoffs", "occurrences", "skipped", \
 "speculated", "worker_computed", "worker_refused", "committed", "guard_misses", "owner_ran", \
 "desyncs", "faults", "sticky", "chunks", "max_chunk_entities", "participant_overflow", \
 "capacity_refusals", "unprocessed", "witness_violations", "worker_share_permille", \
 "events_order", "events_arrival", "events_request", "events_charge", \
 "replayed_order", "replayed_arrival", "replayed_request", "replayed_charge", \
 "diff_bytes", "diff_spans", "capture_us", "dispatch_us", "replay_us", "max_chunk_us", "chunk_time_sum_us", \
 "last_fault_code", "last_fault_eip", "last_fault_address", "last_fault_entity", \
 "last_refuse_service_plus1", "last_refuse_entity", "last_refuse_reason", "storage_bytes", "receiver_bytes"
#define NTW2_BRAIN_WORKER_REASON_LABELS \
 "none", "class", "lifetime", "escape", "service_active", "service_unresolved", "service_receiver", \
 "site_forced", "observe_active", "observe_unresolved", "hard_list", "event_capacity", "span_capacity", \
 "timer", "fp_install", "fault", "injected", "footprint_unreadable"
// Words 119..127 (after the 53 refusing-service rows).
#define NTW2_BRAIN_WORKER_TAIL_LABELS "speculated_unwalked", "late_activations", "region_queries", \
 "witness_dep_misses", "witness_dep_overflow", "rng_worker_draws", "rng_owner_draws", "rng_lcg_advance", \
 "rng_owner_unmatched"
// Words 128..143: guard-miss attribution (version 3).
#define NTW2_BRAIN_WORKER_GUARD_LABELS "guard_miss_unreadable", "guard_miss_timer", "guard_miss_soldier", \
 "guard_miss_duplicate", "guard_miss_unlocated", "guard_miss_last_offset", "guard_miss_last_entity", \
 "guard_miss_last_blocks", "guard_miss_top0_offset", "guard_miss_top0_count", "guard_miss_top1_offset", \
 "guard_miss_top1_count", "guard_miss_top2_offset", "guard_miss_top2_count", "guard_miss_top3_offset", \
 "guard_miss_top3_count"
// Phase row (version 4; ntw2_status::brain_worker_phase_words, PhaseSnapshot). Times are microseconds summed over
// stages: QPC at the five stage boundaries, RDTSC inside them (worker per-occurrence capture/clone/publish, owner
// commit/owner-run segments), converted with each stage's own QPC/TSC ratio. No per-service or per-chunk QPC.
//   capture_us = owner work before the dispatch (witness_begin_us is its WitnessBegin share), dispatch_us = pool wall
//   time, commit_us + owner_run_us + walk_other_us = owner walk (commit_us: validation + publication of computed
//   ordinals, owner_run_us: RunOccurrence of the rest; a failed validation's owner run counts as commit),
//   witness_end_us = WitnessEnd. worker_capture/clone/publish_us: per speculated ordinal on the workers (region
//   proof + copy + digest + rebase / clone run including gates, to the refusal point if refused / export + diff +
//   diff-pool publication). worker_busy_us: summed chunk time; worker_critical_us: per stage, the busiest
//   participant's chunk time. *_region_queries: VirtualQuery calls (witness probes, worker capture, owner commit).
//   guard_miss_prev_*: relation of a soldier guard miss X to the most recent owner-run soldier Y before it
//   (Y.target +1EC == X, Y.reference +5B8 == X, X.reference == Y, none); prev_service_top: most frequent worker
//   refusal service of that Y (brain2 Service + 1; 0 = Y was not refused by a worker) and its count.
//   last_stage_*: the most recent stage alone. tsc_khz: last calibration.
//   Crew dependency (guard-miss blocks +6B0/+6C0, GateClassify4): an owner-run soldier Y whose inline node at Y+22C
//   has vtable 0x133AE34 and an unset one-shot byte (node+78 = Y+2A4 == 0) steps 6F46A0, which stores into the crew
//   soldier S = [node+60] = [Y+28C] (+6AC..+6EC). Before running Y the owner marks S (crew_marks). A later computed
//   ordinal of a marked S is a crew dependency: quiet mode sends it to the owner without validation
//   (crew_refusals); otherwise it is still validated and the outcome counted (crew_marked_misses /
//   crew_marked_commits) to measure the rule. worker_gates: participant gate entries (service + observation gates)
//   of all worker runs; worker_clone_us / worker_gates bounds the per-gate cost.
#define NTW2_BRAIN_WORKER_PHASE_LABELS "phase_version", "quiet", "stages", "capture_us", "witness_begin_us", \
 "dispatch_us", "commit_us", "owner_run_us", "walk_other_us", "witness_end_us", "worker_capture_us", \
 "worker_clone_us", "worker_publish_us", "worker_busy_us", "worker_critical_us", "witness_region_queries", \
 "worker_region_queries", "owner_region_queries", "commit_attempts", "guard_miss_prev_target", \
 "guard_miss_prev_reference", "guard_miss_prev_follower", "guard_miss_prev_other", "guard_miss_prev_service_top", \
 "guard_miss_prev_service_count", "last_stage_capture_us", "last_stage_dispatch_us", "last_stage_commit_us", \
 "last_stage_owner_run_us", "last_stage_occurrences", "last_stage_total_us", "tsc_khz", "crew_marks", \
 "crew_refusals", "crew_marked_misses", "crew_marked_commits", "worker_gates", "reserved37", "reserved38", "reserved39"
#ifdef __cplusplus
namespace ntw2_brain_workers {
using U = uint32_t;
constexpr U kVersion = 4; // 2: RNG stream words 124..127; 3: guard-miss words 128..143; 4: phase row, --brain-quiet
// Bytes of each soldier copied/guarded. Covers every audited field through the pose-wrapper +0x698 word.
constexpr U kReceiverBytes = 0x700;
// Timer object behind soldier +0x518: the +0x00..+0x23 fields 602E00 reads and +0x08/+0x0C/+0x10/+0x18/+0x20
// it writes. Its full class size is not recovered (Unconfirmed); the mirror is the guarded extent.
constexpr U kTimerBytes = 0x40;
constexpr U kEventKinds = 4, kReasonCount = 18, kServiceRows = 53;
enum EventKind : U { EventOrder, EventArrival, EventRequest, EventCharge };
enum Reason : U {
    ReasonNone, ReasonClass, ReasonLifetime, ReasonEscape, ReasonServiceActive, ReasonServiceUnresolved,
    ReasonServiceReceiver, ReasonSiteForced, ReasonObserveActive, ReasonObserveUnresolved, ReasonHardList,
    ReasonEventCapacity, ReasonSpanCapacity, ReasonTimer, ReasonFpInstall, ReasonFault, ReasonInjected,
    // Footprint not provably committed+readable (VirtualQuery) before any byte is touched.
    ReasonFootprint
};
enum Word : U {
    Version, Enabled, Participants, Workers, Dispatches, Handoffs, Occurrences, Skipped,
    Speculated, WorkerComputed, WorkerRefused, Committed, GuardMisses, OwnerRan,
    Desyncs, Faults, Sticky, Chunks, MaxChunkEntities, ParticipantOverflow,
    CapacityRefusals, Unprocessed, WitnessViolations, SharePermille,
    EventsRecorded, EventsReplayed = EventsRecorded + kEventKinds,
    DiffBytes = EventsReplayed + kEventKinds, DiffSpans, CaptureUs, DispatchUs, ReplayUs, MaxChunkUs, ChunkTimeSumUs,
    LastFaultCode, LastFaultEip, LastFaultAddress, LastFaultEntity,
    LastRefuseServicePlus1, LastRefuseEntity, LastRefuseReason, StorageBytes, ReceiverBytes,
    ReasonCounts, ServiceRefusals = ReasonCounts + kReasonCount,
    // speculated - speculated_unwalked == occurrences that the owner walk reached with a worker slot:
    // unwalked = speculated at capture but deactivated by an earlier occurrence or cut off by a shrinking list.
    // late_activations = ==1 at the walk but inactive when captured (owner ran them).
    SpeculatedUnwalked = ServiceRefusals + kServiceRows, LateActivations, RegionQueries,
    // witness_dep_misses: committed-candidate soldiers sent to the owner because a consumed witness value had
    // changed by their ordinal. witness_dep_overflow: refused because the per-occurrence dependency record filled.
    WitnessDepMisses, WitnessDepOverflow,
    // RNG streams. rng_worker_draws: stream draws (5FC070 calls served privately) of COMMITTED occurrences.
    // rng_owner_draws: LCG steps the bound word took during owner-run occurrences of bound stages, recovered by
    // stepping from that ordinal's seed (at most kOwnerDrawScan steps). rng_lcg_advance: total steps the real word
    // was advanced at bound stage ends (per stage = walked occurrences). rng_owner_unmatched: owner-run
    // occurrences whose final word was not reachable from their seed within kOwnerDrawScan steps.
    RngWorkerDraws, RngOwnerDraws, RngLcgAdvance, RngOwnerUnmatched,
    // Guard-miss attribution. A soldier miss (live footprint digest != capture digest at the ordinal) is located
    // by per-16-byte-block checksums taken at capture: last_offset is the first changed block's offset (0xFFFFFFFF
    // when no block checksum differs: unlocated), last_blocks the number of changed blocks, top0..3 the most
    // frequent first-changed offsets (count desc, offset asc). duplicate: the entity also occupies an earlier
    // ordinal of the same captured list (its own earlier step changed it). timer: the +0x518 timer object changed.
    // unreadable: footprint/timer not provably readable at commit. Quiet mode takes no block checksums and does no
    // duplicate scan: soldier misses are counted only (offsets, blocks, duplicate and unlocated stay zero).
    GuardMissUnreadable, GuardMissTimer, GuardMissSoldier, GuardMissDuplicate, GuardMissUnlocated,
    GuardMissLastOffset, GuardMissLastEntity, GuardMissLastBlocks, GuardMissTop,
    WordCount = GuardMissTop + 8
};
constexpr U kTailWords = RngOwnerUnmatched - SpeculatedUnwalked + 1, kGuardTop = 4;
static_assert(RngOwnerUnmatched < WordCount && SpeculatedUnwalked == 119 && kTailWords == 9, "brain worker status row geometry");
static_assert(GuardMissUnreadable == 128 && WordCount == 144, "guard-miss words follow the RNG tail");
static_assert(ReceiverBytes + 1 == ReasonCounts && ReasonFootprint + 1 == kReasonCount, "brain worker status row is append-only");
constexpr U kWords = WordCount;
enum PhaseWord : U {
    PhaseVersion, PhaseQuiet, PhaseStages, PhaseCaptureUs, PhaseWitnessBeginUs, PhaseDispatchUs, PhaseCommitUs,
    PhaseOwnerRunUs, PhaseWalkOtherUs, PhaseWitnessEndUs, PhaseWorkerCaptureUs, PhaseWorkerCloneUs,
    PhaseWorkerPublishUs, PhaseWorkerBusyUs, PhaseWorkerCriticalUs, PhaseWitnessRegionQueries,
    PhaseWorkerRegionQueries, PhaseOwnerRegionQueries, PhaseCommitAttempts, PhaseMissPrevTarget,
    PhaseMissPrevReference, PhaseMissPrevFollower, PhaseMissPrevOther, PhaseMissPrevServiceTop,
    PhaseMissPrevServiceCount, PhaseLastCaptureUs, PhaseLastDispatchUs, PhaseLastCommitUs, PhaseLastOwnerRunUs,
    PhaseLastOccurrences, PhaseLastTotalUs, PhaseTscKhz, PhaseCrewMarks, PhaseCrewRefusals, PhaseCrewMarkedMisses,
    PhaseCrewMarkedCommits, PhaseWorkerGates, PhaseReserved37, PhaseWordCount = PhaseReserved37 + 3
};
constexpr U kPhaseWords = PhaseWordCount, kPhaseVersion = 1;
static_assert(kPhaseWords == 40, "phase row geometry (ntw2_status::brain_worker_phase_words)");
constexpr U kOwnerDrawScan = 1024;
// The stream contract (pure; the oracle builds its reference from these). StreamSeed: SplitMix64 finalizer of
// (S, generation, ordinal) folded to 32 bits. LcgAdvance: S after `steps` 5FC070 steps (O(log steps) jump).
U StreamSeed(U stageState, U generation, U ordinal);
U LcgAdvance(U state, U steps);

struct Binding {
    U image_base;
    // The census-enabled primary family the runtime built, and the exact binding table it was built with.
    const ntw2_clone_set* clones;
    const U* bindings;
    // ntw_pool_dispatch (or a compatible test dispatcher). Null runs every chunk inline on the caller.
    void (__stdcall* dispatch)(U, U, U, void*);
    U pool;
    U workers;
    // Worklists shorter than this go straight to the owner-serial loop.
    U min_entities;
    // Bit per EventKind admitted for deferral to owner replay at its checkpoint. Production leaves this zero:
    // deferring an event is only exact where nothing later in the same step reads what the service writes, and
    // no such per-site proof has been recovered.
    U defer_events;
    // --brain-quiet: no guard-miss block checksums or duplicate scans (counts only). Owner-run occurrences take
    // whatever path ntw2_brain2 is configured for; the runtime configures it without census (the ORIGINAL step).
    bool quiet;
};
// Builds the participant family and storage. False leaves the feature off (the owner keeps running Stage 1).
bool Start(const Binding& binding);
// Owner-only, with no dispatch in flight. Releases every allocation; later Start rebuilds.
void Stop();
// Zeroes the telemetry row; configuration and storage stay.
void Reset();
bool Started();
// Runs the whole site-6 loop for `manager`. Returns false, having executed NOTHING, when the feature is off,
// disabled stickily, or the list is too short; the caller then runs ntw2_brain2::RunWorklist.
bool RunWorklist(U manager, const U* cloneEntries);
void Snapshot(U* words /*[kWords]*/);
void PhaseSnapshot(U* words /*[kPhaseWords]*/);
const char* ReasonName(U reason);

#ifdef NTW2_BRAIN_WORKERS_ORACLE
// Oracle-only: called on the worker around the clone run. 1 raises a real access violation before the clone runs;
// 2 refuses the ordinal (ReasonInjected) after a complete worker run; 3 increments the bound model LCG word from
// the worker after its run (a forwarded original drawing the shared word); other values do nothing.
using FaultInjector = U (*)(U entity, U ordinal);
void SetFaultInjector(FaultInjector injector);
// Oracle-only: RunWorklist returns after the worker phase, before any owner commit (native memory must be unchanged).
void SetComputeOnly(bool computeOnly);
#endif
} // namespace ntw2_brain_workers
#endif
