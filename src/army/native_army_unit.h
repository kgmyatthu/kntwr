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
//    6A5CE0 counters, 69E4D0 publication and callback 69E66E), model+50 RNG (MSVC LCG 343FD/269EC3 steps counted),
//    planner mutators (ntw2_ai_census owner-thread calls; only with --features ai_census), member/attached/driver
//    counts, command U+930/934, FSM state [U+D6C].
//  * reasons (owner-only under the approved compromises): notification (A40|608|BD0|trigger), planner, allocation/list
//    (member/attached/driver/command changes, attached removal, formation command), return-dependent (FSM transition,
//    or selected-command predicate followed by a command change), non-closed callee (any kind). Strict eligible: no
//    reason. Dynamic eligible: no reason other than non-closed, i.e. eligible once the reached classes are closed.
//    RNG draws are eligible under compromise 5 and only counted.
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
    CommandDistinct = CostHistogram + kHistogram, CommandOverflow, RngDrawingUs, Reserved107,
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
} // namespace ntw2_army_unit
#endif
