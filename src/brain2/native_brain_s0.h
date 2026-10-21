#pragma once
#include <stdint.h>
// S0 attribution timer (--brain-s0; analysis/native-unit-compromise-plan.md section 5.3 "Minimal sampled timer").
// Diagnostics only: measures where the per-man +0C brain step spends its time so that the per-unit compromise slices
// are funded or rejected on numbers. No game-state write, no change to what executes:
//  * every site-6 occurrence of a brain class runs a generator-pinned BRAIN_S0 clone of its +0C entry (66CE00 core,
//    602EB0/5FCEB0 wrappers) whose candidate decision calls reach the S0_* gates (src/clones/kntwr_clones.h); the gates and the
//    family are instruction-identical forwarding: each forwards exactly ONE original (or the next BRAIN_S0 clone) with
//    the original registers, EFLAGS, x87/SSE state, stack arguments and RET n. Artillery/other classes run their
//    original entry (timed as a whole, inner mechanics untimed).
//  * every gate call is counted (flag-free counter, ~4-8 cycles). An occurrence is timed when the deterministic stratum
//    hash(stage, unit ordinal, member ordinal) selects it (1 in 2^shift, shift 6 = 1/64; unit ordinal = first
//    appearance of A+1F0 in this stage's worklist, member ordinal = k-th occurrence of that unit in the stage; no time,
//    no address). Inside a timed occurrence the +0C step and every gate call are bracketed with RDTSCP...LFENCE and
//    pushed on a nesting stack: a frame's inclusive cycles are charged to its parent, so exclusive = inclusive minus
//    direct children (never double-charged).
//  * Start requires RDTSCP and an invariant TSC (CPUID 80000001.EDX[27], 80000007.EDX[8]), calibrates TSC against QPC,
//    and measures in this build: the empty-gate measurement floor o (gate around a RET), the nesting cost c a parent
//    sees for one child gate beyond the child's own measurement, the root floor r, the unsampled pass costs of a static
//    and a dispatch gate and the per-occurrence stratum decision. The launcher subtracts them:
//      gate excl = excl - sampled*o - children*c     gate incl = incl - sampled*o - descendants*(o+c)
//      step excl = excl - sampled*r - children*c     step incl = incl - sampled*r - descendants*(o+c)
//    and scales by occurrences/sampled occurrences (uniform occurrence sampling) to ms per stage.
// Node classes cloned for the order/stance/lookup gates: hot 816900/819310, idle step 66DD10, move 816080/818500,
// related 815FF0/818330 (the census top classes); other node classes, the 64DE80 driver and calls of 6631A0/662E70
// outside the cloned bodies run original and are counted only through their parents. Fire latch writers 660180/660230
// have no call site in the step bodies (their callers are unit/army code and 5FCEB0-class virtuals +1D8/+20C, none called
// from the step): the driver's inline latch stores 658DEF/658DFB and the engage policy stores 658C62/658FDE/6590FC are
// inside the driver's exclusive time. Animation selection 66B7E0/66B990 is reached only as fsm.vt+40/+44 from posture
// state callbacks: it is inside the posture row's exclusive time (exit/enter/update callbacks), not separately timed.
#define KNTWR_BRAIN_S0_HEADER_LABELS "s0_version", "s0_configured", "s0_state", "sample_shift", "stages", \
 "occurrences_lo", "occurrences_hi", "sampled_occurrences", "site6_cycles_lo", "site6_cycles_hi", "tsc_span_lo", \
 "tsc_span_hi", "qpc_span_lo", "qpc_span_hi", "qpc_freq_lo", "qpc_freq_hi", "cal_tsc_khz", "gate_floor_x16", \
 "gate_floor_spread_x16", "gate_nest_x16", "gate_nest_spread_x16", "root_floor_x16", "root_floor_spread_x16", \
 "pass_cost_x16", "dispatch_cost_x16", "occurrence_cost_x16", "depth_overflow", "abandoned", "max_depth", \
 "unit_overflow", "nested_root", "calibration_samples"
#define KNTWR_BRAIN_S0_ROW_LABELS "step_core", "step_wrapper", "step_other", "target_6718F0", "driver_658C50", \
 "driver_64DE80", "node_begin_hot_816900", "node_begin_move_816080", "node_begin_related_815FF0", "node_begin_other", \
 "node_step_hot_819310", "node_step_idle_66DD10", "node_step_move_818500", "node_step_related_818330", \
 "node_step_other", "finalize_6543D0", "finalize_other", "order_final_6631A0", "order_final_changed", \
 "order_node_662E70", "order_node_changed", "order_adjust_66AE10", "order_predicate_64F8F0", "unit_arrival_57E1F0", \
 "unit_modifier_649520", "stance_662E50", "path_819770", "posture_10FC370", "posture_next_10FBBDA", \
 "fatigue_670F40", "selector_other", "timer_602E00", "timer_provider"
/* Nominal nesting depth of each row (display indentation; the accounting uses the dynamic stack, not this table). */
#define KNTWR_BRAIN_S0_ROW_DEPTHS 0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, \
 5, 1, 1, 1, 2
#define KNTWR_BRAIN_S0_ROW_WORD_LABELS "calls_lo", "calls_hi", "sampled", "hit_occurrences", "children", \
 "descendants", "incl_lo", "incl_hi", "excl_lo", "excl_hi", "sq_incl_lo", "sq_incl_hi", "sq_excl_lo", "sq_excl_hi", \
 "max_stage_calls", "reserved"
#define KNTWR_BRAIN_S0_HEADER_WORDS 32u
#define KNTWR_BRAIN_S0_ROWS 33u
#define KNTWR_BRAIN_S0_ROW_WORDS 16u
#ifdef __cplusplus
namespace kntwr_brain_s0 {
using U = uint32_t;
constexpr U kVersion = 1, kHeaderWords = KNTWR_BRAIN_S0_HEADER_WORDS, kRowWords = KNTWR_BRAIN_S0_ROW_WORDS;
constexpr U kDefaultShift = 6; // 1/64
enum Row : U {
    StepCore, StepWrapper, StepOther, Target, Driver, DriverAlt,
    NodeBeginHot, NodeBeginMove, NodeBeginRelated, NodeBeginOther,
    NodeStepHot, NodeStepIdle, NodeStepMove, NodeStepRelated, NodeStepOther,
    Finalize, FinalizeOther, OrderFinal, OrderFinalChanged, OrderNode, OrderNodeChanged,
    OrderAdjust, OrderPredicate, UnitArrival, UnitModifier, Stance,
    Path, Posture, PostureNext, Fatigue, SelectorOther, Timer, TimerProvider, RowCount
};
static_assert(RowCount == KNTWR_BRAIN_S0_ROWS, "row labels");
constexpr U kWords = kHeaderWords + RowCount * kRowWords;
static_assert(kWords == 560, "brain_s0_words geometry");
// Header words. *_x16 are cycles in 1/16 units (medians); spreads are the robust sigma 0.7413*IQR of the calibration
// samples. state: 0 not started, 1 running/ran, 2 refused (no RDTSCP or no invariant TSC), 3 clone family missing.
enum Word : U {
    Version, Configured, State, SampleShift, Stages, OccurrencesLo, OccurrencesHi, SampledOccurrences,
    Site6Lo, Site6Hi, TscSpanLo, TscSpanHi, QpcSpanLo, QpcSpanHi, QpcFreqLo, QpcFreqHi, CalTscKhz,
    GateFloorX16, GateFloorSpreadX16, GateNestX16, GateNestSpreadX16, RootFloorX16, RootFloorSpreadX16,
    PassCostX16, DispatchCostX16, OccurrenceCostX16, DepthOverflow, Abandoned, MaxDepth, UnitOverflow,
    NestedRoot, CalibrationSamples
};
static_assert(CalibrationSamples + 1 == kHeaderWords, "header labels");
// Row words: calls = every gate call (all occurrences; the *Changed order rows carry only sampled calls, their calls
// stay in the base row). sampled/children/descendants/incl/excl cover timed occurrences only; hit_occurrences counts
// timed occurrences with at least one timed call of the row; sq_* are the sums over timed occurrences of the squared
// per-occurrence incl/excl cycle totals (IEEE double, lo/hi), for the sampling standard error; max_stage_calls is the
// largest call count of one stage.
enum RowWord : U {
    CallsLo, CallsHi, Sampled, HitOccurrences, Children, Descendants, InclLo, InclHi, ExclLo, ExclHi,
    SqInclLo, SqInclHi, SqExclLo, SqExclHi, MaxStageCalls, RowReserved
};
static_assert(RowReserved + 1 == kRowWords, "row word labels");

// Writes the KNTWR_BIND_S0_* gate addresses; gates forward to the originals until Start routes them into the clones.
bool Bind(U imageBase, U* bindings);
// Owner thread, before the first stage: verifies the CPU (state 2 on refusal), that every BRAIN_S0 clone exists (state 3),
// routes the gates into the family and calibrates. `sampleShift` 0..16 (0 times every occurrence: oracle use).
// `units` (--brain-unit-*, kntwr_unit_policy): the runner also drives the unit seams (BeginStage/EndStage, Begin/EndOccurrence)
// and the selector (fatigue), driver (engage) and posture gates route occurrences whose live unit mask admits them to the unit
// applies: `bindings` = the table the clone set was built with (KNTWR_BIND_U_FATIGUE, KNTWR_BIND_U_POSTURE; a zero entry keeps its
// route native), the engage route is the clone KNTWR_CLONE_BRAIN_US_DRIVER. The unsampled cost of an unrouted occurrence is two
// loads on the routed gates only.
bool Start(const U* cloneEntries, U sampleShift = kDefaultShift, const U* bindings = nullptr, bool units = false);
void Stop();   // routing retained (immutable clones), sampling off; counters retained for the final snapshot
void Reset();  // counters/calibration to zero (activation)
void Snapshot(U* words /*[kWords]*/);
// kntwr_brain2::OccurrenceRunner entries (owner thread, inside kntwr_brain2::RunWorklist).
void BeginStage(U manager);
void EndStage();
// Runs the occurrence's +0C step exactly once. `brainClass` is kntwr_brain2::Class of `original` (vt+0C).
void RunOccurrence(U entity, U brainClass, U original, const U* cloneEntries);

// Oracle seams (mapped-image tests only). The direct-call gate of `binding` (an KNTWR_BIND_S0_* direct gate) forwards to
// `target` instead of its routed callee until Start/Bind; false for virtual/dispatch gates.
bool OverrideGateTarget(U binding, U target);
// One timed root frame on row `row` (StepCore/StepWrapper/StepOther) around thiscall entry(receiver), exactly like a
// sampled occurrence (gates inside nest under it); the occurrence is flushed into the row totals. Returns its cycles.
uint64_t RunTimedRoot(U row, U entry, U receiver);
} // namespace kntwr_brain_s0
#endif
