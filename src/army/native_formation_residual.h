#pragma once
#include <stdint.h>

// Formation residual census (runs with --army-storm-census, kntwr_config::va_watch_flags KNTWR_ARMY_STORM_CENSUS): performance
// data gathering only, no behaviour change. Question measured: inside a site-18 storm tick, the storm census brackets the
// per-unit formation update call 5820DE -> 0x585D50 but 0x585D50 itself is only two vtable loops; the residual (its per-member
// [vtbl+0xC] callees) was invisible. This module replaces 0x585D50 inside the census epoch with an exact C++ port of the two
// loops (kntwr_runtime.cpp ArmyFormationGate) and brackets every callee: each [vtbl+0xC] call is timed and grouped by callee
// address (loop 1 = U+AB4/U+AB0, loop 2 = U+AD0/U+ACC), and the infantry formation update 0x580A30 (the dominant callee) runs
// as the private CLONE_FORM_UPDATE whose nine timed direct calls reach the KNTWR_BIND_FORM_* gates: dirty rebuilds 576EA0/
// 57C9F0, aggregate 53C180, FSM step 580990 (with R1/R1b inclusive us split out through the storm module's route gates),
// command predicate 586440, command constructor 51A3A0, command queue 581E80 (with R2 us inside split out), tail 551A40 and
// recorder DACDC0. Self/residue of 0x580A30 = form_us minus the nine gate buckets (computed offline).
//
// All native effects are unchanged and authoritative: the loops re-read the member count and array base after every callee
// exactly like 0x585D50, non-0x580A30 callees run the original, and every gate forwards exactly one original with the
// original register/stack/RET contract (verified by disassembly; the clone generator pins every call site's original bytes).
// The port runs only on the tick owner inside a storm-census Unit occurrence (kntwr_army_storm::InUnit); otherwise the gates
// forward the originals directly. No RNG, ordering, FP state, lifetime or notification path is touched.
//
// Row layout (kntwr_status::army_residual_words, KNTWR_FORMATION_RESIDUAL_WORDS == 320): header 12 words, callee table
// (kCalleeMax x 4: callee preferred VA, loop mask bit0 = loop 1 / bit1 = loop 2, calls, inclusive us; the 0x580A30 clone
// entry is included), storm aggregate at 36 and calm aggregate at 76 (kAggWords = 40 each, AggWord; the census's own storm
// classification is passed in by kntwr_runtime.cpp so the two rows agree), top-8 storm-tick table at 116 (kEntryWords = 24
// each, largest site-18 us first, EntryWord), 12 trailing zero words. All times are inclusive us of the bracket (children
// are included in their parent: fsm_us includes r1_us/r1b_us; queue_us includes queue_r2_us; form_us includes all nine
// gates). observer_us estimates the module's own QPC reads (2 per bracket) from the calibrated per-read cost
// (qpc_read_cost_q16, QPC ticks 16.16); it is also added to the storm module's occurrence observer so the census's unit cost
// subtraction stays consistent. Aggregate gate columns are calls then us; dirty_a = 576EA0 (flag F+2790), dirty_b = 57C9F0
// (flag F+2791).
#define KNTWR_FORMATION_RESIDUAL_LABELS \
 "version", "enabled", "ticks", "storm_ticks", "form_calls", "clone_forms", "other_forms", "member_calls", \
 "observer_us", "qpc_read_cost_q16", "gate_outside", "callee_overflow", \
 "callee0_va", "callee0_loop_mask", "callee0_calls", "callee0_us", \
 "callee1_va", "callee1_loop_mask", "callee1_calls", "callee1_us", \
 "callee2_va", "callee2_loop_mask", "callee2_calls", "callee2_us", \
 "callee3_va", "callee3_loop_mask", "callee3_calls", "callee3_us", \
 "callee4_va", "callee4_loop_mask", "callee4_calls", "callee4_us", \
 "callee5_va", "callee5_loop_mask", "callee5_calls", "callee5_us", \
 "storm_forms", "storm_form_us", "storm_max_form_us", "storm_max_form_members", \
 "storm_members_sum", "storm_forms_ge1ms", "storm_loop1_us", "storm_loop2_us", \
 "storm_loop_calls", "storm_dirty_a_calls", "storm_dirty_a_us", "storm_dirty_b_calls", \
 "storm_dirty_b_us", "storm_agg_calls", "storm_agg_us", "storm_fsm_calls", \
 "storm_fsm_us", "storm_cmdpred_calls", "storm_cmdpred_us", "storm_cmdctor_calls", \
 "storm_cmdctor_us", "storm_queue_calls", "storm_queue_us", "storm_tail_calls", \
 "storm_tail_us", "storm_rec_calls", "storm_rec_us", "storm_r1_us", \
 "storm_r1b_us", "storm_r2_us", "storm_queue_r2_us", "storm_max_form_gate_us", \
 "storm_pad32", "storm_pad33", "storm_pad34", "storm_pad35", \
 "storm_pad36", "storm_pad37", "storm_pad38", "storm_pad39", \
 "calm_forms", "calm_form_us", "calm_max_form_us", "calm_max_form_members", \
 "calm_members_sum", "calm_forms_ge1ms", "calm_loop1_us", "calm_loop2_us", \
 "calm_loop_calls", "calm_dirty_a_calls", "calm_dirty_a_us", "calm_dirty_b_calls", \
 "calm_dirty_b_us", "calm_agg_calls", "calm_agg_us", "calm_fsm_calls", \
 "calm_fsm_us", "calm_cmdpred_calls", "calm_cmdpred_us", "calm_cmdctor_calls", \
 "calm_cmdctor_us", "calm_queue_calls", "calm_queue_us", "calm_tail_calls", \
 "calm_tail_us", "calm_rec_calls", "calm_rec_us", "calm_r1_us", \
 "calm_r1b_us", "calm_r2_us", "calm_queue_r2_us", "calm_max_form_gate_us", \
 "calm_pad32", "calm_pad33", "calm_pad34", "calm_pad35", \
 "calm_pad36", "calm_pad37", "calm_pad38", "calm_pad39", \
 "top0_tick", "top0_site18_us", "top0_forms", "top0_form_us", \
 "top0_max_form_us", "top0_max_form_members", "top0_loop1_us", "top0_loop2_us", \
 "top0_member_calls", "top0_loop_calls", "top0_dirty_a_us", "top0_dirty_b_us", \
 "top0_agg_us", "top0_fsm_us", "top0_cmdpred_us", "top0_cmdctor_us", \
 "top0_queue_us", "top0_tail_us", "top0_rec_us", "top0_r1_us", \
 "top0_r1b_us", "top0_r2_us", "top0_queue_r2_us", "top0_dirty_ab_calls", \
 "top1_tick", "top1_site18_us", "top1_forms", "top1_form_us", \
 "top1_max_form_us", "top1_max_form_members", "top1_loop1_us", "top1_loop2_us", \
 "top1_member_calls", "top1_loop_calls", "top1_dirty_a_us", "top1_dirty_b_us", \
 "top1_agg_us", "top1_fsm_us", "top1_cmdpred_us", "top1_cmdctor_us", \
 "top1_queue_us", "top1_tail_us", "top1_rec_us", "top1_r1_us", \
 "top1_r1b_us", "top1_r2_us", "top1_queue_r2_us", "top1_dirty_ab_calls", \
 "top2_tick", "top2_site18_us", "top2_forms", "top2_form_us", \
 "top2_max_form_us", "top2_max_form_members", "top2_loop1_us", "top2_loop2_us", \
 "top2_member_calls", "top2_loop_calls", "top2_dirty_a_us", "top2_dirty_b_us", \
 "top2_agg_us", "top2_fsm_us", "top2_cmdpred_us", "top2_cmdctor_us", \
 "top2_queue_us", "top2_tail_us", "top2_rec_us", "top2_r1_us", \
 "top2_r1b_us", "top2_r2_us", "top2_queue_r2_us", "top2_dirty_ab_calls", \
 "top3_tick", "top3_site18_us", "top3_forms", "top3_form_us", \
 "top3_max_form_us", "top3_max_form_members", "top3_loop1_us", "top3_loop2_us", \
 "top3_member_calls", "top3_loop_calls", "top3_dirty_a_us", "top3_dirty_b_us", \
 "top3_agg_us", "top3_fsm_us", "top3_cmdpred_us", "top3_cmdctor_us", \
 "top3_queue_us", "top3_tail_us", "top3_rec_us", "top3_r1_us", \
 "top3_r1b_us", "top3_r2_us", "top3_queue_r2_us", "top3_dirty_ab_calls", \
 "top4_tick", "top4_site18_us", "top4_forms", "top4_form_us", \
 "top4_max_form_us", "top4_max_form_members", "top4_loop1_us", "top4_loop2_us", \
 "top4_member_calls", "top4_loop_calls", "top4_dirty_a_us", "top4_dirty_b_us", \
 "top4_agg_us", "top4_fsm_us", "top4_cmdpred_us", "top4_cmdctor_us", \
 "top4_queue_us", "top4_tail_us", "top4_rec_us", "top4_r1_us", \
 "top4_r1b_us", "top4_r2_us", "top4_queue_r2_us", "top4_dirty_ab_calls", \
 "top5_tick", "top5_site18_us", "top5_forms", "top5_form_us", \
 "top5_max_form_us", "top5_max_form_members", "top5_loop1_us", "top5_loop2_us", \
 "top5_member_calls", "top5_loop_calls", "top5_dirty_a_us", "top5_dirty_b_us", \
 "top5_agg_us", "top5_fsm_us", "top5_cmdpred_us", "top5_cmdctor_us", \
 "top5_queue_us", "top5_tail_us", "top5_rec_us", "top5_r1_us", \
 "top5_r1b_us", "top5_r2_us", "top5_queue_r2_us", "top5_dirty_ab_calls", \
 "top6_tick", "top6_site18_us", "top6_forms", "top6_form_us", \
 "top6_max_form_us", "top6_max_form_members", "top6_loop1_us", "top6_loop2_us", \
 "top6_member_calls", "top6_loop_calls", "top6_dirty_a_us", "top6_dirty_b_us", \
 "top6_agg_us", "top6_fsm_us", "top6_cmdpred_us", "top6_cmdctor_us", \
 "top6_queue_us", "top6_tail_us", "top6_rec_us", "top6_r1_us", \
 "top6_r1b_us", "top6_r2_us", "top6_queue_r2_us", "top6_dirty_ab_calls", \
 "top7_tick", "top7_site18_us", "top7_forms", "top7_form_us", \
 "top7_max_form_us", "top7_max_form_members", "top7_loop1_us", "top7_loop2_us", \
 "top7_member_calls", "top7_loop_calls", "top7_dirty_a_us", "top7_dirty_b_us", \
 "top7_agg_us", "top7_fsm_us", "top7_cmdpred_us", "top7_cmdctor_us", \
 "top7_queue_us", "top7_tail_us", "top7_rec_us", "top7_r1_us", \
 "top7_r1b_us", "top7_r2_us", "top7_queue_r2_us", "top7_dirty_ab_calls", \
 "pad0", "pad1", "pad2", "pad3", "pad4", "pad5", "pad6", "pad7", \
 "pad8", "pad9", "pad10", "pad11"
#ifdef __cplusplus
namespace kntwr_form_residual {
using U = uint32_t;
constexpr U kVersion = 1;
constexpr U kCalleeMax = 6;       // distinct [vtbl+0xC] callees tracked per loop (overflow counted in header)
constexpr U kTop = 8;             // top storm ticks kept
constexpr U kHeaderWords = 12, kCalleeWords = kCalleeMax * 4, kAggWords = 40, kEntryWords = 24;
constexpr U kMid = 1000;          // forms_ge1ms threshold, us
enum Word : U {
    Version, Enabled, Ticks, StormTicks, FormCalls, CloneForms, OtherForms, MemberCalls,
    ObserverUs, QpcReadCostQ16, GateOutside, CalleeOverflow,
    CalleeTable = kHeaderWords,                    // kCalleeMax x 4: va (preferred-base), loop mask, calls, us
    StormAggregate = CalleeTable + kCalleeWords,   // kAggWords, see AggWord
    CalmAggregate = StormAggregate + kAggWords,    // kAggWords
    TopTable = CalmAggregate + kAggWords,          // kTop x kEntryWords, see EntryWord
    WordCount = 320
};
enum AggWord : U {
    AForms, AFormUs, AMaxFormUs, AMaxFormMembers, AMembersSum, AFormsGe1ms, ALoop1Us, ALoop2Us,
    ALoopCalls, ADirtyACalls, ADirtyAUs, ADirtyBCalls, ADirtyBUs, AAggCalls, AAggUs, AFsmCalls,
    AFsmUs, ACmdPredCalls, ACmdPredUs, ACmdCtorCalls, ACmdCtorUs, AQueueCalls, AQueueUs, ATailCalls,
    ATailUs, ARecCalls, ARecUs, AR1Us, AR1bUs, AR2Us, AQueueR2Us, AMaxFormGateUs // 32..39 reserved
};
// dirty_ab_calls = dirty_a_calls bits 0..15 | dirty_b_calls bits 16..31 (saturating).
enum EntryWord : U {
    ETick, ESite18Us, EForms, EFormUs, EMaxFormUs, EMaxFormMembers, ELoop1Us, ELoop2Us,
    EMemberCalls, ELoopCalls, EDirtyAUs, EDirtyBUs, EAggUs, EFsmUs, ECmdPredUs, ECmdCtorUs,
    EQueueUs, ETailUs, ERecUs, ER1Us, ER1bUs, ER2Us, EQueueR2Us, EDirtyAbCalls
};
static_assert(WordCount == 320 && StormAggregate == 36 && CalmAggregate == 76 && TopTable == 116 &&
              TopTable + kTop * kEntryWords == 308, "formation residual status row geometry (KNTWR_FORMATION_RESIDUAL_WORDS)");
constexpr U kWords = WordCount;

// Clone bindings (called by the runtime before kntwr_build_clones): fills the nine KNTWR_BIND_FORM_* gates with this module's
// forwarding gates; the gates forward the original native when the census is not inside a Formation occurrence.
void Bind(U delta, uint32_t* bindings);
bool Start(U cloneFormUpdate); // relocated entry of KNTWR_CLONE_FORM_UPDATE (0 disables the clone path; callees run original)
void Stop();
void Reset();
// Exact port of 0x585D50 (disassembly-pinned: two member loops over U+AB4/U+AB0 and U+AD0/U+ACC calling [vtbl+0xC]; plain ret,
// EAX unused by the caller at 5820E3). ECX = U. Runs only through kntwr_army_storm::Call(BFormation, ...) in the census epoch.
U __fastcall Formation(void* unit);
// Tick owner, tick trace writer, immediately after kntwr_army_storm::TickEnd of the same tick: `storm` is the census's
// classification for this tick so the two rows agree.
void TickEnd(U tick, U site18Us, bool storm);
// Copies the row; all zero when the census never ran (enabled word 0).
void Snapshot(U* words /*[kWords]*/);
} // namespace kntwr_form_residual
#endif
