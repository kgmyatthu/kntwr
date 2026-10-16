#pragma once
#include <stdint.h>

// Army per-unit update, Item 4 Stage A (--army-unit-shadow, NTW2_ARMY_UNIT_SHADOW): instrumentation only.
//
// Question measured: under the approved compromises (frozen foreign units per army stage, conflicts by unit ordinal,
// per-unit deterministic RNG streams; NOT delayed callbacks), which 0x581F30 occurrences could leave the owner, what
// they cost, and what a worker version of site 18 would cost. Stage B (not implemented) needs a go/no-go on this table.
//
// Hooks (runtime host data only, no code/game bytes): siteCallees[18] (ARMY clone's call 0x580342 of the ARMY_UPDATE
// clone, ECX = container C) -> Stage; siteCallees[101]/[103] (ARMY_UPDATE's 0x5804C2 main-list C+F0/F4 and 0x5804FF
// alternate-list C+1A4/1A8 calls of 0x581F30, ECX = unit U) -> Unit. The native call is unchanged and authoritative;
// this module only READS native memory (every range proven readable first, ntw2_region::Table) and writes its own rows.
//
// Per occurrence, on the tick owner around the native call:
//  * cost: QPC of the 0x581F30 call alone (instrumentation excluded; it is reported as observer_us).
//  * kinds (pre-state predicates; dispatch sites of analysis/native-army-update-per-unit.md section 8.2 whose class is
//    not closed): identity 57F109 (always), FSM query 10FBBDA (U+AE8==0), selected command +10 581F8F (U+AE8 && U+930;
//    55AC80 not replicated: upper bound), alternate +E0/+4 581FF3/582022 (U+AE8), command ring 582680/57F2A9 (U+930),
//    driver stack 582081/5820A7 (U+A60), formations 585D6B/585D9B + layout 5821DF (U+AB0/U+ACC/U+ADC), member getters
//    57F17B/57F18E (U+AA0 && U+2CC), 601500 (U+DC8), 600EF0 debug draws (U+DCC), attached removal 52E840 (an attached
//    member +6F8 != 0), formation command allocation 580B1F/580B60 (class 13211D8 formation with F+18, F+515,
//    F+508!=1||F+498, F+460==0; 586440 not replicated: upper bound).
//  * effects (pre/post deltas): A40 notification 585890 (U+AA0 0->1), 608/AB8 5858E0/585904 (U+AA0 ->2), BD0 57F0F8
//    (6011F0 returns old<new of byte U+D48), 601500 trigger 601622/60170D (R=[U+DC8], R+68 0->nonzero: 5CCA60 effect,
//    6A5CE0 counters, 69E4D0 publication and callback 69E66E), model+50 RNG (MSVC LCG 343FD/269EC3: bounded endpoint
//    inference, the number of LCG steps <= kRngBound from the pre to the post state; a reseed or more draws than the
//    bound count as rng_unresolved, and draws that return to the same state are invisible),
//    planner mutators (ntw2_ai_census owner-thread calls; only with --features ai_census), member/attached/driver
//    counts, command U+930/934, FSM state [U+D6C].
//  * reasons (owner-only under the approved compromises): notification (A40|608|BD0|trigger), planner, allocation/list
//    (member/attached/driver/command changes, attached removal, formation command), return-dependent (FSM transition,
//    or selected-command predicate followed by a command change), non-closed callee (any kind). Strict eligible: no
//    reason. Dynamic eligible: no reason other than non-closed, i.e. eligible once the reached classes are closed.
//    RNG draws are eligible under compromise 5 and only counted. An occurrence whose pre or post observation is not
//    complete (unit unreadable, or a fault caught while reading) is counted in unreadable/unreadable_us only: it is
//    neither eligible nor attributed to a reason, and its cost stays owner-only in the projection.
//  * observation safety: readability proofs are re-established before each pre and post observation (the native call
//    may free or decommit probed memory) and every load runs under SEH bracketed by ntw2::probeDepth.
//  * foreign witness: distinct foreign units in the lists the closure enumerates: 5821B0 candidates [[U+1EC]+D8]+44/48
//    (pre) and 53A9E0's [U+1EC]+F0/F4 (post state; its pure-read gates are replicated, 55AC40/55C480 and the U+1B0/1AF
//    command queries are not: upper bound). Pinned cells: 4 per aggregation unit (D9E, C00, +2704, C2C), 18 per
//    neighbour (ADC, F+670, pose 3, transform pointer, 12 transform floats).
// Per stage: one measured frozen-copy of the section 8.4 cells of every listed unit (snapshot_us), not used by anything.
#define NTW2_ARMY_UNIT_HEADER_LABELS "version", "enabled", "stages", "occurrences", "main_occurrences", \
 "alternate_occurrences", "ticks", "units_last_stage", "max_units_stage", "strict_eligible", "dynamic_eligible", \
 "rng_drawing", "rng_draws", "rng_unresolved", "planner_measured", "unreadable", "unit_us", "strict_eligible_us", \
 "dynamic_eligible_us", "stage_us", "observer_us", "snapshot_us", "snapshot_units", "quantile_ticks", \
 "tick_p50_sum_dus", "tick_p90_sum_dus", "last_tick_p50_dus", "last_tick_p90_dus", "max_tick_p90_dus", \
 "tick_buffer_overflow", "workers", "ai2_concurrent"
#define NTW2_ARMY_UNIT_REASON_LABELS "notification", "planner_write", "alloc_list", "return_dependent", "non_closed"
#define NTW2_ARMY_UNIT_DETAIL_LABELS "k_identity_57F109", "k_fsm_10FBBDA", "k_selected_581F8F", "k_alternate_581FF3", \
 "k_command_582680", "k_driver_582081", "k_formation_585D9B", "k_member_getters_57F17B", "k_601500", "k_600EF0", \
 "k_attached_remove_52E840", "k_formation_command_580B1F", "k_reserved12", "k_reserved13", "k_reserved14", \
 "k_reserved15", "e_notify_a40_585890", "e_notify_608_5858E0", "e_notify_bd0_57F0F8", "e_trigger_5CCA60", "e_rng", \
 "e_planner", "e_members", "e_attached", "e_drivers", "e_command", "e_fsm", "e_unreadable", "e_reserved28", \
 "e_reserved29", "e_reserved30", "e_reserved31"
#define NTW2_ARMY_UNIT_FOREIGN_LABELS "foreign_distinct_sum", "foreign_distinct_max", "foreign_aggregation_sum", \
 "foreign_neighbour_sum", "aggregation_skipped", "foreign_unreadable", "foreign_set_overflow", "pinned_cells_sum"
#define NTW2_ARMY_UNIT_COMMAND_LABELS "va", "occurrences", "dynamic_owner_only", "cost_us", "rng_drawing"

// B0 qualification (analysis/native-army-stage-b-plan.md section 7), same --army-unit-shadow activation, own row
// ntw2_status::army_b0_words (NTW2_ARMY_B0_WORDS). The Stage A row's spare words (188..191 and the eight reserved
// detail counters) are far too few for 160 words, so they keep their meaning and stay zero. Still observation only: no
// native write; every read VirtualQuery-proven and SEH-bracketed.
//  * unit occurrence: the runtime runs the generator-pinned ARMY_UNIT clone of 0x581F30 (identical instructions; only
//    its call 58202E of the unit FSM update 582530 is bound to Fsm below), so the occurrence cost is still its native
//    time; the FSM gate's own reads are subtracted from it and counted as instrumentation.
//  * FSM (plan 5.1): per 582530 call, [S+4] before/after (S = U+D68, FSM table 1320F28): a changed state is a nonzero
//    10FBBDA query (old leave + new enter ran: effectful transition, refuses the occurrence); an unchanged one is the
//    step 10FBBFB of that state. Closed steps (kClosedStepMask): only the sentinel's 44A780 (ret 4); the A..E step
//    bodies 585740/585910/584980/583D90/5859D0 are not closed. No query target returns its own state (section
//    10.2.2), so an unchanged state is exactly a zero query; a step that itself rewrote S+4 counts as a transition
//    (conservative: refused).
//  * formation (plan 5.2/2.4): infantry (13211D8) formations of U+ACC/AD0: aggregate N = [[F+62C+4]+C] (53C1D7/53C1DA),
//    members F+18, queue Q=F+20 count Q+440 and rows Q+400 (command class; secondary state [cmd+1C] of 1324B54), dirty
//    bytes F+2790/2791 (576EA0/57C9F0 command rebuilds: owner-only). Scratch headers 14A3ED8/14A3EC4 capacity/count/
//    backing before and after each occurrence: a capacity or backing change is a reached growth site (4FFD20/444B40:
//    game heap); a nonzero count at an observation is a non-reset scratch. Queue count increase = 522D70 reserve reached.
//  * recorder (plan 3): enable 1459B00, 1459DCC, manager [15F8BC0], provider [15F9054], comparator M+18, inhibit byte
//    M+1C at every stage start and before/after every occurrence. Tail appends per occurrence = delta(M+4) +
//    delta(M+20) (DACCD0 success / ring-full counters). Qualified: enabled, same non-null manager as the stage start,
//    provider = comparator = inhibit = 0 before and after.
//  * RNG (plan 4): Stage A's bounded LCG-step count against the member-loop bound sum over infantry formations of
//    F+18 * (1 + queued 1323B64 commands + dirty F+2790) (55F260 draws at most once per visited member per invocation).
//  * own state (plan 6, first order): bytes of U (E38, allocation 531320), each listed formation (infantry 0x2794 =
//    highest 580A30-closure field F+2791 rounded; other classes Stage A's 0x6F0) and the attached list data, copied
//    once per occurrence into module storage and timed. Member objects (F+18 counts) are reported, not copied.
//  * refusal: one mutually exclusive bucket per occurrence, in order unreadable, alloc_list (Stage A), FSM transition,
//    recorder not replayable (tail appended or unknown while unqualified), other refused (Stage A notification/
//    planner/return-dependent, dirty formation, unknown FSM table/state), completable.
#define NTW2_ARMY_B0_LABELS "b0_version", "b0_occurrences", "fsm_calls", "fsm_occurrences", "fsm_multi", \
 "fsm_transitions", "fsm_steps", "fsm_unreadable", "fsm_foreign_table", "fsm_us", "fsm_transition_us", "fsm_step_us", \
 "closed_step_mask", "b0_observer_us", "fsm_outside_unit", "fsm_not_reached_us", \
 "a_steps", "a_step_us", "a_step_occ_us", "a_from", "a_to", "b_steps", "b_step_us", "b_step_occ_us", "b_from", "b_to", \
 "c_steps", "c_step_us", "c_step_occ_us", "c_from", "c_to", "d_steps", "d_step_us", "d_step_occ_us", "d_from", "d_to", \
 "e_steps", "e_step_us", "e_step_occ_us", "e_from", "e_to", "sentinel_steps", "sentinel_step_us", \
 "sentinel_step_occ_us", "sentinel_from", "sentinel_to", "other_steps", "other_step_us", "other_step_occ_us", \
 "other_from", "other_to", \
 "formation_infantry", "formation_other", "formation_unreadable", "scratch_n_sum", "scratch_n_max", "members_sum", \
 "record_cap_max", "distance_cap_max", "record_growth", "distance_growth", "scratch_count_nonzero", \
 "scratch_unreadable", "queue_commands_sum", "queue_unreadable", "queue_reserved", "queue_truncated", \
 "sec_1450BDC", "sec_1450BE0", "sec_1450BE4", "sec_1450BE8", "sec_sentinel", "sec_other", \
 "queue_class_distinct", "queue_class_overflow", \
 "qc0_va", "qc0_commands", "qc0_occ_us", "qc1_va", "qc1_commands", "qc1_occ_us", "qc2_va", "qc2_commands", \
 "qc2_occ_us", "qc3_va", "qc3_commands", "qc3_occ_us", "qc4_va", "qc4_commands", "qc4_occ_us", "qc5_va", \
 "qc5_commands", "qc5_occ_us", \
 "alloc_growth", "alloc_growth_us", "alloc_reserve", "alloc_reserve_us", "alloc_list_change", "alloc_list_change_us", \
 "alloc_predicate_only", "alloc_predicate_only_us", \
 "rec_stages", "rec_stage_qualified", "rec_enable0", "rec_manager_null", "rec_manager_changes", "rec_provider_set", \
 "rec_comparator_set", "rec_inhibit", "rec_dcc_zero", "rec_unreadable", "rec_manager_last", "rec_provider_last", \
 "rec_comparator_last", "rec_observations", "rec_tails", "rec_tail_max", "rec_tail_occurrences", "rec_drops", \
 "rec_unqualified", "rec_tail_us", \
 "rng_member_bound_sum", "rng_within_bound", "rng_over_bound", "rng_draw_max", \
 "own_kb_sum", "own_bytes_max", "own_copy_us", "own_unreadable", "dirty_occurrences", "dirty_us", \
 "scratch_bytes_max", \
 "ref_unreadable", "ref_unreadable_us", "ref_alloc", "ref_alloc_us", "ref_transition", "ref_transition_us", \
 "ref_recorder", "ref_recorder_us", "ref_other", "ref_other_us", "ref_completable", "ref_completable_us", \
 "completable_step_unclosed", "completable_step_unclosed_us", "completable_no_step", "completable_no_step_us", \
 "other_stage_a", "other_stage_a_us", "other_dirty", "other_dirty_us", "other_fsm_unknown", "other_fsm_unknown_us", \
 "transition_occurrences", "transition_occurrences_us", "b0_reserved156", "b0_reserved157", "b0_reserved158", \
 "b0_reserved159"
#ifdef __cplusplus
namespace ntw2_region { struct Table; }
namespace ntw2_army_unit {
using U = uint32_t;
constexpr U kVersion = 1;
constexpr U kReasons = 5, kDetails = 32, kHistogram = 16, kCommands = 16, kCommandStride = 5;
constexpr U kRngBound = 4096; // LCG steps searched between the pre and post model+50 states
enum Reason : U { RNotification, RPlanner, RAllocList, RReturn, RNonClosed };
enum Detail : U {
    KIdentity, KFsm, KSelected, KAlternate, KCommand, KDriver, KFormation, KMemberGetters, K601500, K600EF0,
    KAttachedRemove, KFormationCommand,
    ENotifyA40 = 16, ENotify608, ENotifyBD0, ETrigger, ERng, EPlanner, EMembers, EAttached, EDrivers, ECommand, EFsm,
    EUnreadable
};
constexpr U kKindMask = 0xFFFFu;
enum Word : U {
    Version, Enabled, Stages, Occurrences, MainOccurrences, AlternateOccurrences, Ticks, UnitsLastStage,
    MaxUnitsStage, StrictEligible, DynamicEligible, RngDrawing, RngDraws, RngUnresolved, PlannerMeasured, Unreadable,
    UnitUs, StrictEligibleUs, DynamicEligibleUs, StageUs, ObserverUs, SnapshotUs, SnapshotUnits, QuantileTicks,
    TickP50SumDus, TickP90SumDus, LastTickP50Dus, LastTickP90Dus, MaxTickP90Dus, TickBufferOverflow, Workers,
    Ai2Concurrent,
    ReasonCount = 32, ReasonUs = ReasonCount + kReasons, SoleReason = ReasonUs + kReasons,
    DuplicateOccurrences = SoleReason + kReasons, // 47
    DetailCount = 48,
    ForeignDistinctSum = DetailCount + kDetails, ForeignDistinctMax, ForeignAggregationSum, ForeignNeighbourSum,
    AggregationSkipped, ForeignUnreadable, ForeignSetOverflow, PinnedCellsSum,
    CostHistogram = 88, // bucket b: cost in [2^(b-1), 2^b) us, bucket 0 below 1 us, bucket 15 at least 16384 us
    CommandDistinct = CostHistogram + kHistogram, CommandOverflow, RngDrawingUs, UnreadableUs,
    CommandRows = 108, // kCommands x (preferred vtable VA, 0 no command, ~0 unreadable; occurrences; dynamic owner-only;
                       //               cost us; RNG-drawing occurrences), first-seen order
    Reserved188 = CommandRows + kCommands * kCommandStride, Reserved189, Reserved190, Reserved191,
    WordCount
};
static_assert(DuplicateOccurrences == 47 && ForeignDistinctSum == 80 && PinnedCellsSum == 87 &&
              CommandDistinct == 104 && Reserved188 == 188 && WordCount == 192,
              "army unit status row geometry (NTW2_ARMY_UNIT_WORDS)");
constexpr U kWords = WordCount;

struct Binding {
    U image_base;            // relocation of the preferred-base class constant 13211D8
    U workers;               // reported for the projection only; Stage A never dispatches
    U (*planner_calls)();    // owner-thread planner-mutator call counter (ntw2_ai_census::OwnerCalls) or null
    U ai2_concurrent;        // 1 when the AI worker can run during the tick (model+50/planner deltas are then shared)
};
bool Start(const Binding& binding); // allocates the module storage; false leaves it off
void Stop();
void Reset();
bool Started();
using Native = U (__fastcall*)(void*);
// Tick owner. Stage wraps one 0x580390 container call (model = the bound battle model); Unit wraps one 0x581F30
// occurrence (list 0 main, 1 alternate). Both always run the native exactly once and return its EAX.
U Stage(void* container, U model, Native native);
U Unit(void* unit, U list, Native native);
void Snapshot(U* words /*[kWords]*/);

// Pure surface (oracle). Unreadable dependents read as 0.
struct Probe {
    U readable, aa0, d48, dc8, trigger /*byte R+68, ~0 unreadable*/, dcc, ae8, c930, c934, command /*vtable*/, a60,
      ab0, acc, adc, members /*U+2CC*/, attached /*[U+1F4]+10*/, attachedRemove, fsm /*[U+D6C]*/, formationCommand;
};
bool ReadProbe(U unit, U delta, ntw2_region::Table& table, U& queries, Probe& out);
// Steps of the model+50 LCG from `from` to `to` (0 when equal), ~0 when not reached within `bound` steps.
U RngSteps(U from, U to, U bound);
// Reason bitset (1 << Reason); `detail` receives the Detail bits.
U Classify(const Probe& pre, const Probe& post, U plannerDelta, U rngSteps, U& detail);

// ---- B0 qualification row (see the B0 comment above the labels).
constexpr U kB0Version = 1;
constexpr U kFsmStates = 7, kFsmStride = 5;              // A, B, C, D, E, sentinel, other
enum FsmState : U { SA, SB, SC, SD, SE, SSentinel, SOther };
constexpr U kClosedStepMask = 1u << SSentinel;           // closed step bodies: sentinel 131D38C+8 = 44A780 (ret 4) only
constexpr U kSecondaryStates = 6, kQueueClasses = 6, kQueueStride = 3, kQueueRows = 8, kQueueSample = 32;
constexpr U kInfantryFormationBytes = 0x2794, kOtherFormationBytes = 0x6F0, kUnitObjectBytes = 0xE38;
enum Refusal : U { RefUnreadable, RefAlloc, RefTransition, RefRecorder, RefOther, RefCompletable, kRefusals };
enum AllocSplitKind : U { AllocGrowth, AllocReserve, AllocListChange, AllocPredicateOnly, kAllocSplits };
enum OtherKind : U { OtherStageA, OtherDirty, OtherFsmUnknown, kOtherKinds };
enum B0Word : U {
    B0Version, B0Occurrences, FsmCalls, FsmOccurrences, FsmMulti, FsmTransitions, FsmSteps, FsmUnreadable,
    FsmForeignTable, FsmUs, FsmTransitionUs, FsmStepUs, ClosedStepMask, B0ObserverUs, FsmOutsideUnit, FsmNotReachedUs,
    FsmStateRows = 16, // kFsmStates x (steps, step native us, whole-occurrence us of occurrences stepping in this state,
                       //               transitions from, transitions to)
    FormationInfantry = FsmStateRows + kFsmStates * kFsmStride, // 51
    FormationOther, FormationUnreadable, ScratchNSum, ScratchNMax, MembersSum, RecordCapMax, DistanceCapMax,
    RecordGrowth, DistanceGrowth, ScratchCountNonzero, ScratchUnreadable, QueueCommandsSum, QueueUnreadable,
    QueueReserved, QueueTruncated,
    SecondaryStateCounts, // 67: 1450BDC, 1450BE0, 1450BE4, 1450BE8, sentinel 1466CC4, other (1324B54 commands only)
    QueueClassDistinct = SecondaryStateCounts + kSecondaryStates, QueueClassOverflow,
    QueueClassRows, // 75: kQueueClasses x (preferred vtable VA, commands seen, whole-occurrence us), first-seen order
    AllocRows = QueueClassRows + kQueueClasses * kQueueStride, // 93: kAllocSplits x (occurrences, us)
    RecorderStages = AllocRows + 2 * kAllocSplits,             // 101
    RecorderStageQualified, RecorderEnable0, RecorderManagerNull, RecorderManagerChanges, RecorderProviderSet,
    RecorderComparatorSet, RecorderInhibit, RecorderDccZero, RecorderUnreadable, RecorderManagerLast,
    RecorderProviderLast, RecorderComparatorLast, RecorderObservations, RecorderTails, RecorderTailMax,
    RecorderTailOccurrences, RecorderDrops, RecorderUnqualified, RecorderTailUs,
    RngMemberBoundSum, RngWithinBound, RngOverBound, RngDrawMax,                   // 121
    OwnKbSum, OwnBytesMax, OwnCopyUs, OwnUnreadable, DirtyOccurrences, DirtyUs, ScratchBytesMax, // 125
    RefusalRows,                                                // 132: kRefusals x (occurrences, us)
    CompletableStepUnclosed = RefusalRows + 2 * kRefusals,      // 144
    CompletableStepUnclosedUs, CompletableNoStep, CompletableNoStepUs,
    OtherRows,                                                  // 148: kOtherKinds x (occurrences, us)
    TransitionOccurrences = OtherRows + 2 * kOtherKinds, // 154: (count, us) of occurrences with any FSM transition,
    TransitionOccurrencesUs,                             //      regardless of the refusal order
    B0Reserved156,
    B0WordCount = 160
};
static_assert(FormationInfantry == 51 && SecondaryStateCounts == 67 && QueueClassRows == 75 && AllocRows == 93 &&
              RecorderStages == 101 && RecorderTailUs == 120 && RngMemberBoundSum == 121 && OwnKbSum == 125 &&
              RefusalRows == 132 && CompletableStepUnclosed == 144 && OtherRows == 148 && TransitionOccurrences == 154,
              "army B0 status row geometry (NTW2_ARMY_B0_WORDS)");
constexpr U kB0Words = B0WordCount;

// Tick owner, inside a Unit occurrence: wraps ARMY_UNIT's 582530 call (ECX = S = U+D68); runs the native once.
U Fsm(void* fsm, Native native);
void SnapshotB0(U* words /*[kB0Words]*/);

// Pure B0 surface (oracle).
U FsmStateIndex(U preferredState);       // FsmState of a preferred-base state object VA
U SecondaryStateIndex(U preferredState); // 0..5 as SecondaryStateCounts
struct Globals {
    U scratchOk, recCap, recCount, recBacking, distCap, distCount, distBacking;
    U recorderOk, enable, dcc, manager, provider, managerOk, m4, m20, comparator, inhibit;
};
void ReadGlobals(U delta, ntw2_region::Table& table, U& queries, Globals& out);
bool RecorderQualified(const Globals& g);
U RecorderAppends(const Globals& before, const Globals& after); // ~0 when not comparable
struct OwnSpan { U base, bytes; };
struct B0Probe {
    U readable, infantry, other, unreadable, nMax, members, bound, queue, queueBad, dirty, ownBytes, spans;
    OwnSpan span[2 + 8];
    U commands, commandClass[kQueueSample], commandState[kQueueSample]; // preferred VAs; state ~0 when not 1324B54
};
bool ReadB0Probe(U unit, U delta, ntw2_region::Table& table, U& queries, B0Probe& out);
U Refuse(bool observed, U reasons, bool transition, bool recorderRefused, bool otherRefused);
U AllocSplit(U detail, bool growth, bool reserved);
} // namespace ntw2_army_unit
#endif
