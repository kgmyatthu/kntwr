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
// Row layout (kntwr_status::army_residual_words, KNTWR_FORMATION_RESIDUAL_WORDS == 832): header 12 words, callee table
// (kCalleeMax x 4: callee preferred VA, loop mask bit0 = loop 1 / bit1 = loop 2, calls, inclusive us; the 0x580A30 clone
// entry is included), storm aggregate at 36 and calm aggregate at 76 (kAggWords = 40 each, AggWord; the census's own storm
// classification is passed in by kntwr_runtime.cpp so the two rows agree), top-8 storm-tick table at 116 (kEntryWords = 73
// each, largest site-18 us first, EntryWord), retention ledger at 700 (kLedgerWords = 29, LedgerWord), queue class table at 729
// (kQueueWords = 82, QueueWord), command-split route table at 811 (kRouteWords = 21, RouteWord). All times are
// inclusive us of the bracket (children
// are included in their parent: fsm_us includes r1_us/r1b_us; queue_us includes queue_r2_us; form_us includes all nine
// gates). observer_us estimates the module's own QPC reads (2 per bracket) from the calibrated per-read cost
// (qpc_read_cost_q16, QPC ticks 16.16); it is also added to the storm module's occurrence observer so the census's unit cost
// subtraction stays consistent. Aggregate gate columns are calls then us; dirty_a = 576EA0 (flag F+2790), dirty_b = 57C9F0
// (flag F+2791). Limited solves (version 2): the solver's limited (limit != 0) native calls are timed by the solver gate
// (2 QPC reads each, only while the census is wired) and folded per tick into the lim_* aggregate columns and top-row
// lim_* fields. lim_us is INCLUSIVE wall time of those exact native calls: it is contained in the tick duration, in site 18 and
// (when the call sits under a formation callee such as the FSM or queue gate) inside that bucket and form_us, so it must NEVER
// be added to any other parent field; it never enters the solver's own native/kernel accounting. The module's two QPC reads per
// limited call are counted in observer_us (and subtracted by the storm census only inside a Unit occurrence).
// Version history: 1 = 320 words, 24-word top rows; 2 = 507 words (unshipped layout): 36-word top rows with QPC identity,
// limited aggregates, queue-command fields, retention/abort ledger and the bounded queue class table; 3 = 696 words: the
// command-split route (see RouteWord / the route row fields below) is appended to every top row, the ledger and as a table;
// 4 = 832 words: the assignment split (assign_scope vs inner solver work, census only) is appended to the END of every top row
// (ERouteAssignScopeUs.. and the slow-row copy) and of the route table; every v3 index is unchanged except the regions after
// the top table (ledger, queue and route tables), which moved by +128.
// Queue commands: the command queue walk 0x581E80 runs as the exact port kntwr_formation_queue::Run inside the census
// (diagnostic only); each callback is bracketed by 2 QPC reads and reported through NoteQueueCommand; queue_us (the whole walk,
// inclusive) is unchanged.
//
// Command-split route (version 3, assignment split since version 4; census only, armed at Start when the private clone entries of 0x581CA0 and 0x4F84C0 exist, see
// route_armed): the observed storm outliers are formation command callbacks of vtable 0x1325428 slot +4 = native 0x581CA0
// (-> 10FC370 FSM wrapper -> 10FBBD0 FSM step -> state enter [state vtbl+4] -> 4F84C0 -> 5736B0 [57B000 assignment, then 55F160 per
// man]). When the queue port reads exactly that raw table value (the class identity is still the raw pre-call vtable/slot) it
// runs the private clone chain instead and the clone's enter / 57B000 / 55F160 calls go through timing gates that forward the
// untouched natives with the original register/stack/return contract. ALL actual work stays native (no solver change, 57B000 ->
// 555CA0 stays native). Nothing is assumed about the first command or guard [cmd+0x35] (they are read, never cached). A "routed"
// callback is one the private chain really executed; the others (other classes, refused routes) run the table value untouched.
// Per ROUTED callback the gates collect, in QPC ticks and call counts: matched enters (state enter == native 4F84C0 = the
// transition into the 5736B0 state, run through the private 4F84C0 clone; inclusive of the assignment and per-man calls inside),
// other enters (every other state's enter, forwarded native), 57B000 assignment calls and 55F160 per-man calls. `transitions` =
// enter + other_enter calls; a routed callback with zero matched enters legitimately shows the rest of its time elsewhere
// (FSM wrapper/step, predicate, native tail 557D80, other states) because only the gates are bracketed, never the glue. The us of
// a callback minus its enter/other-enter us is therefore the non-state-enter remainder (it also contains ~1 QPC read of
// observer cost per timed call). route_* row fields aggregate the routed callbacks of that invocation; route_slow_* is the
// slowest ROUTED callback (vtable/slot as pre-call identity) with ITS OWN nested counts, and flags bit 4 (EFlagSlowRouted)
// says that callback IS the row's slow_vtable/slot/us callback (same invocation, same callback). Without the bit the slowest
// callback of the row was not routed (other class or refused) and 0 in the route_slow block says nothing about its native work.
// route_calls == 0 means no routed callback in that invocation (not proof of zero native work). Every timed gate call costs 2 QPC
// reads (counted in observer_us at qpc_read_cost_q16 per read); that cost sits inside the callback's and every enclosing us.
// The row's version word is the layout identity for saved receipts; the live status object is additionally guarded by
// kntwr_status::size (launcher read_status refuses a DLL/launcher pair whose sizeof(kntwr_status) differs).
#define KNTWR_FORMATION_RESIDUAL_VERSION 4u
/* C-visible geometry for the launcher (asserted equal to the Word/EntryWord enums below). */
#define KNTWR_FORMATION_RESIDUAL_TOP_OFFSET 116u
#define KNTWR_FORMATION_RESIDUAL_TOP_ROWS 8u
#define KNTWR_FORMATION_RESIDUAL_ENTRY_WORDS 73u
#define KNTWR_FORMATION_RESIDUAL_LEDGER_OFFSET 700u
#define KNTWR_FORMATION_RESIDUAL_LEDGER_WORDS 29u
#define KNTWR_FORMATION_RESIDUAL_QUEUE_OFFSET 729u
#define KNTWR_FORMATION_RESIDUAL_QUEUE_CLASSES 16u
#define KNTWR_FORMATION_RESIDUAL_ROUTE_OFFSET 811u
#define KNTWR_FORMATION_RESIDUAL_ROUTE_WORDS 21u
#define KNTWR_FORMATION_RESIDUAL_LABELS \
 "version", "enabled", "ticks", "storm_ticks", \
 "form_calls", "clone_forms", "other_forms", "member_calls", \
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
 "storm_lim_ticks", "storm_lim_calls", "storm_lim_us", "storm_lim_max_call_us", \
 "storm_lim_max_tick_us", "storm_lim_only_ticks", "storm_lim_only_calls", "storm_lim_only_us", \
 "calm_forms", "calm_form_us", "calm_max_form_us", "calm_max_form_members", \
 "calm_members_sum", "calm_forms_ge1ms", "calm_loop1_us", "calm_loop2_us", \
 "calm_loop_calls", "calm_dirty_a_calls", "calm_dirty_a_us", "calm_dirty_b_calls", \
 "calm_dirty_b_us", "calm_agg_calls", "calm_agg_us", "calm_fsm_calls", \
 "calm_fsm_us", "calm_cmdpred_calls", "calm_cmdpred_us", "calm_cmdctor_calls", \
 "calm_cmdctor_us", "calm_queue_calls", "calm_queue_us", "calm_tail_calls", \
 "calm_tail_us", "calm_rec_calls", "calm_rec_us", "calm_r1_us", \
 "calm_r1b_us", "calm_r2_us", "calm_queue_r2_us", "calm_max_form_gate_us", \
 "calm_lim_ticks", "calm_lim_calls", "calm_lim_us", "calm_lim_max_call_us", \
 "calm_lim_max_tick_us", "calm_lim_only_ticks", "calm_lim_only_calls", "calm_lim_only_us", \
 "top0_tick", "top0_site18_us", "top0_forms", "top0_form_us", \
 "top0_max_form_us", "top0_max_form_members", "top0_loop1_us", "top0_loop2_us", \
 "top0_member_calls", "top0_loop_calls", "top0_dirty_a_us", "top0_dirty_b_us", \
 "top0_agg_us", "top0_fsm_us", "top0_cmdpred_us", "top0_cmdctor_us", \
 "top0_queue_us", "top0_tail_us", "top0_rec_us", "top0_r1_us", \
 "top0_r1b_us", "top0_r2_us", "top0_queue_r2_us", "top0_dirty_ab_calls", \
 "top0_qpc_start_lo", "top0_qpc_start_hi", "top0_tick_us", "top0_lim_calls", \
 "top0_lim_us", "top0_lim_max_us", "top0_flags", "top0_queue_cmd_calls", \
 "top0_queue_cmd_us", "top0_slow_vtable", "top0_slow_slot", "top0_slow_us", \
 "top0_route_calls", "top0_route_us", "top0_route_enter_calls", "top0_route_enter_us", \
 "top0_route_other_enter_calls", "top0_route_other_enter_us", "top0_route_assign_calls", "top0_route_assign_us", \
 "top0_route_perman_calls", "top0_route_perman_us", "top0_route_slow_vtable", "top0_route_slow_slot", \
 "top0_route_slow_us", "top0_route_slow_enter_calls", "top0_route_slow_enter_us", "top0_route_slow_other_enter_calls", \
 "top0_route_slow_other_enter_us", "top0_route_slow_assign_calls", "top0_route_slow_assign_us", "top0_route_slow_perman_calls", \
 "top0_route_slow_perman_us", \
 "top0_route_assign_scope_us", "top0_route_assign_scope_calls", "top0_route_inner_kernel_us", "top0_route_inner_solves", \
 "top0_route_inner_lim_us", "top0_route_inner_lim_calls", "top0_route_inner_suppressed", "top0_route_inner_assign_entries", \
 "top0_route_slow_assign_scope_us", "top0_route_slow_assign_scope_calls", "top0_route_slow_inner_kernel_us", "top0_route_slow_inner_solves", \
 "top0_route_slow_inner_lim_us", "top0_route_slow_inner_lim_calls", "top0_route_slow_inner_suppressed", "top0_route_slow_inner_assign_entries", \
 "top1_tick", "top1_site18_us", "top1_forms", "top1_form_us", \
 "top1_max_form_us", "top1_max_form_members", "top1_loop1_us", "top1_loop2_us", \
 "top1_member_calls", "top1_loop_calls", "top1_dirty_a_us", "top1_dirty_b_us", \
 "top1_agg_us", "top1_fsm_us", "top1_cmdpred_us", "top1_cmdctor_us", \
 "top1_queue_us", "top1_tail_us", "top1_rec_us", "top1_r1_us", \
 "top1_r1b_us", "top1_r2_us", "top1_queue_r2_us", "top1_dirty_ab_calls", \
 "top1_qpc_start_lo", "top1_qpc_start_hi", "top1_tick_us", "top1_lim_calls", \
 "top1_lim_us", "top1_lim_max_us", "top1_flags", "top1_queue_cmd_calls", \
 "top1_queue_cmd_us", "top1_slow_vtable", "top1_slow_slot", "top1_slow_us", \
 "top1_route_calls", "top1_route_us", "top1_route_enter_calls", "top1_route_enter_us", \
 "top1_route_other_enter_calls", "top1_route_other_enter_us", "top1_route_assign_calls", "top1_route_assign_us", \
 "top1_route_perman_calls", "top1_route_perman_us", "top1_route_slow_vtable", "top1_route_slow_slot", \
 "top1_route_slow_us", "top1_route_slow_enter_calls", "top1_route_slow_enter_us", "top1_route_slow_other_enter_calls", \
 "top1_route_slow_other_enter_us", "top1_route_slow_assign_calls", "top1_route_slow_assign_us", "top1_route_slow_perman_calls", \
 "top1_route_slow_perman_us", \
 "top1_route_assign_scope_us", "top1_route_assign_scope_calls", "top1_route_inner_kernel_us", "top1_route_inner_solves", \
 "top1_route_inner_lim_us", "top1_route_inner_lim_calls", "top1_route_inner_suppressed", "top1_route_inner_assign_entries", \
 "top1_route_slow_assign_scope_us", "top1_route_slow_assign_scope_calls", "top1_route_slow_inner_kernel_us", "top1_route_slow_inner_solves", \
 "top1_route_slow_inner_lim_us", "top1_route_slow_inner_lim_calls", "top1_route_slow_inner_suppressed", "top1_route_slow_inner_assign_entries", \
 "top2_tick", "top2_site18_us", "top2_forms", "top2_form_us", \
 "top2_max_form_us", "top2_max_form_members", "top2_loop1_us", "top2_loop2_us", \
 "top2_member_calls", "top2_loop_calls", "top2_dirty_a_us", "top2_dirty_b_us", \
 "top2_agg_us", "top2_fsm_us", "top2_cmdpred_us", "top2_cmdctor_us", \
 "top2_queue_us", "top2_tail_us", "top2_rec_us", "top2_r1_us", \
 "top2_r1b_us", "top2_r2_us", "top2_queue_r2_us", "top2_dirty_ab_calls", \
 "top2_qpc_start_lo", "top2_qpc_start_hi", "top2_tick_us", "top2_lim_calls", \
 "top2_lim_us", "top2_lim_max_us", "top2_flags", "top2_queue_cmd_calls", \
 "top2_queue_cmd_us", "top2_slow_vtable", "top2_slow_slot", "top2_slow_us", \
 "top2_route_calls", "top2_route_us", "top2_route_enter_calls", "top2_route_enter_us", \
 "top2_route_other_enter_calls", "top2_route_other_enter_us", "top2_route_assign_calls", "top2_route_assign_us", \
 "top2_route_perman_calls", "top2_route_perman_us", "top2_route_slow_vtable", "top2_route_slow_slot", \
 "top2_route_slow_us", "top2_route_slow_enter_calls", "top2_route_slow_enter_us", "top2_route_slow_other_enter_calls", \
 "top2_route_slow_other_enter_us", "top2_route_slow_assign_calls", "top2_route_slow_assign_us", "top2_route_slow_perman_calls", \
 "top2_route_slow_perman_us", \
 "top2_route_assign_scope_us", "top2_route_assign_scope_calls", "top2_route_inner_kernel_us", "top2_route_inner_solves", \
 "top2_route_inner_lim_us", "top2_route_inner_lim_calls", "top2_route_inner_suppressed", "top2_route_inner_assign_entries", \
 "top2_route_slow_assign_scope_us", "top2_route_slow_assign_scope_calls", "top2_route_slow_inner_kernel_us", "top2_route_slow_inner_solves", \
 "top2_route_slow_inner_lim_us", "top2_route_slow_inner_lim_calls", "top2_route_slow_inner_suppressed", "top2_route_slow_inner_assign_entries", \
 "top3_tick", "top3_site18_us", "top3_forms", "top3_form_us", \
 "top3_max_form_us", "top3_max_form_members", "top3_loop1_us", "top3_loop2_us", \
 "top3_member_calls", "top3_loop_calls", "top3_dirty_a_us", "top3_dirty_b_us", \
 "top3_agg_us", "top3_fsm_us", "top3_cmdpred_us", "top3_cmdctor_us", \
 "top3_queue_us", "top3_tail_us", "top3_rec_us", "top3_r1_us", \
 "top3_r1b_us", "top3_r2_us", "top3_queue_r2_us", "top3_dirty_ab_calls", \
 "top3_qpc_start_lo", "top3_qpc_start_hi", "top3_tick_us", "top3_lim_calls", \
 "top3_lim_us", "top3_lim_max_us", "top3_flags", "top3_queue_cmd_calls", \
 "top3_queue_cmd_us", "top3_slow_vtable", "top3_slow_slot", "top3_slow_us", \
 "top3_route_calls", "top3_route_us", "top3_route_enter_calls", "top3_route_enter_us", \
 "top3_route_other_enter_calls", "top3_route_other_enter_us", "top3_route_assign_calls", "top3_route_assign_us", \
 "top3_route_perman_calls", "top3_route_perman_us", "top3_route_slow_vtable", "top3_route_slow_slot", \
 "top3_route_slow_us", "top3_route_slow_enter_calls", "top3_route_slow_enter_us", "top3_route_slow_other_enter_calls", \
 "top3_route_slow_other_enter_us", "top3_route_slow_assign_calls", "top3_route_slow_assign_us", "top3_route_slow_perman_calls", \
 "top3_route_slow_perman_us", \
 "top3_route_assign_scope_us", "top3_route_assign_scope_calls", "top3_route_inner_kernel_us", "top3_route_inner_solves", \
 "top3_route_inner_lim_us", "top3_route_inner_lim_calls", "top3_route_inner_suppressed", "top3_route_inner_assign_entries", \
 "top3_route_slow_assign_scope_us", "top3_route_slow_assign_scope_calls", "top3_route_slow_inner_kernel_us", "top3_route_slow_inner_solves", \
 "top3_route_slow_inner_lim_us", "top3_route_slow_inner_lim_calls", "top3_route_slow_inner_suppressed", "top3_route_slow_inner_assign_entries", \
 "top4_tick", "top4_site18_us", "top4_forms", "top4_form_us", \
 "top4_max_form_us", "top4_max_form_members", "top4_loop1_us", "top4_loop2_us", \
 "top4_member_calls", "top4_loop_calls", "top4_dirty_a_us", "top4_dirty_b_us", \
 "top4_agg_us", "top4_fsm_us", "top4_cmdpred_us", "top4_cmdctor_us", \
 "top4_queue_us", "top4_tail_us", "top4_rec_us", "top4_r1_us", \
 "top4_r1b_us", "top4_r2_us", "top4_queue_r2_us", "top4_dirty_ab_calls", \
 "top4_qpc_start_lo", "top4_qpc_start_hi", "top4_tick_us", "top4_lim_calls", \
 "top4_lim_us", "top4_lim_max_us", "top4_flags", "top4_queue_cmd_calls", \
 "top4_queue_cmd_us", "top4_slow_vtable", "top4_slow_slot", "top4_slow_us", \
 "top4_route_calls", "top4_route_us", "top4_route_enter_calls", "top4_route_enter_us", \
 "top4_route_other_enter_calls", "top4_route_other_enter_us", "top4_route_assign_calls", "top4_route_assign_us", \
 "top4_route_perman_calls", "top4_route_perman_us", "top4_route_slow_vtable", "top4_route_slow_slot", \
 "top4_route_slow_us", "top4_route_slow_enter_calls", "top4_route_slow_enter_us", "top4_route_slow_other_enter_calls", \
 "top4_route_slow_other_enter_us", "top4_route_slow_assign_calls", "top4_route_slow_assign_us", "top4_route_slow_perman_calls", \
 "top4_route_slow_perman_us", \
 "top4_route_assign_scope_us", "top4_route_assign_scope_calls", "top4_route_inner_kernel_us", "top4_route_inner_solves", \
 "top4_route_inner_lim_us", "top4_route_inner_lim_calls", "top4_route_inner_suppressed", "top4_route_inner_assign_entries", \
 "top4_route_slow_assign_scope_us", "top4_route_slow_assign_scope_calls", "top4_route_slow_inner_kernel_us", "top4_route_slow_inner_solves", \
 "top4_route_slow_inner_lim_us", "top4_route_slow_inner_lim_calls", "top4_route_slow_inner_suppressed", "top4_route_slow_inner_assign_entries", \
 "top5_tick", "top5_site18_us", "top5_forms", "top5_form_us", \
 "top5_max_form_us", "top5_max_form_members", "top5_loop1_us", "top5_loop2_us", \
 "top5_member_calls", "top5_loop_calls", "top5_dirty_a_us", "top5_dirty_b_us", \
 "top5_agg_us", "top5_fsm_us", "top5_cmdpred_us", "top5_cmdctor_us", \
 "top5_queue_us", "top5_tail_us", "top5_rec_us", "top5_r1_us", \
 "top5_r1b_us", "top5_r2_us", "top5_queue_r2_us", "top5_dirty_ab_calls", \
 "top5_qpc_start_lo", "top5_qpc_start_hi", "top5_tick_us", "top5_lim_calls", \
 "top5_lim_us", "top5_lim_max_us", "top5_flags", "top5_queue_cmd_calls", \
 "top5_queue_cmd_us", "top5_slow_vtable", "top5_slow_slot", "top5_slow_us", \
 "top5_route_calls", "top5_route_us", "top5_route_enter_calls", "top5_route_enter_us", \
 "top5_route_other_enter_calls", "top5_route_other_enter_us", "top5_route_assign_calls", "top5_route_assign_us", \
 "top5_route_perman_calls", "top5_route_perman_us", "top5_route_slow_vtable", "top5_route_slow_slot", \
 "top5_route_slow_us", "top5_route_slow_enter_calls", "top5_route_slow_enter_us", "top5_route_slow_other_enter_calls", \
 "top5_route_slow_other_enter_us", "top5_route_slow_assign_calls", "top5_route_slow_assign_us", "top5_route_slow_perman_calls", \
 "top5_route_slow_perman_us", \
 "top5_route_assign_scope_us", "top5_route_assign_scope_calls", "top5_route_inner_kernel_us", "top5_route_inner_solves", \
 "top5_route_inner_lim_us", "top5_route_inner_lim_calls", "top5_route_inner_suppressed", "top5_route_inner_assign_entries", \
 "top5_route_slow_assign_scope_us", "top5_route_slow_assign_scope_calls", "top5_route_slow_inner_kernel_us", "top5_route_slow_inner_solves", \
 "top5_route_slow_inner_lim_us", "top5_route_slow_inner_lim_calls", "top5_route_slow_inner_suppressed", "top5_route_slow_inner_assign_entries", \
 "top6_tick", "top6_site18_us", "top6_forms", "top6_form_us", \
 "top6_max_form_us", "top6_max_form_members", "top6_loop1_us", "top6_loop2_us", \
 "top6_member_calls", "top6_loop_calls", "top6_dirty_a_us", "top6_dirty_b_us", \
 "top6_agg_us", "top6_fsm_us", "top6_cmdpred_us", "top6_cmdctor_us", \
 "top6_queue_us", "top6_tail_us", "top6_rec_us", "top6_r1_us", \
 "top6_r1b_us", "top6_r2_us", "top6_queue_r2_us", "top6_dirty_ab_calls", \
 "top6_qpc_start_lo", "top6_qpc_start_hi", "top6_tick_us", "top6_lim_calls", \
 "top6_lim_us", "top6_lim_max_us", "top6_flags", "top6_queue_cmd_calls", \
 "top6_queue_cmd_us", "top6_slow_vtable", "top6_slow_slot", "top6_slow_us", \
 "top6_route_calls", "top6_route_us", "top6_route_enter_calls", "top6_route_enter_us", \
 "top6_route_other_enter_calls", "top6_route_other_enter_us", "top6_route_assign_calls", "top6_route_assign_us", \
 "top6_route_perman_calls", "top6_route_perman_us", "top6_route_slow_vtable", "top6_route_slow_slot", \
 "top6_route_slow_us", "top6_route_slow_enter_calls", "top6_route_slow_enter_us", "top6_route_slow_other_enter_calls", \
 "top6_route_slow_other_enter_us", "top6_route_slow_assign_calls", "top6_route_slow_assign_us", "top6_route_slow_perman_calls", \
 "top6_route_slow_perman_us", \
 "top6_route_assign_scope_us", "top6_route_assign_scope_calls", "top6_route_inner_kernel_us", "top6_route_inner_solves", \
 "top6_route_inner_lim_us", "top6_route_inner_lim_calls", "top6_route_inner_suppressed", "top6_route_inner_assign_entries", \
 "top6_route_slow_assign_scope_us", "top6_route_slow_assign_scope_calls", "top6_route_slow_inner_kernel_us", "top6_route_slow_inner_solves", \
 "top6_route_slow_inner_lim_us", "top6_route_slow_inner_lim_calls", "top6_route_slow_inner_suppressed", "top6_route_slow_inner_assign_entries", \
 "top7_tick", "top7_site18_us", "top7_forms", "top7_form_us", \
 "top7_max_form_us", "top7_max_form_members", "top7_loop1_us", "top7_loop2_us", \
 "top7_member_calls", "top7_loop_calls", "top7_dirty_a_us", "top7_dirty_b_us", \
 "top7_agg_us", "top7_fsm_us", "top7_cmdpred_us", "top7_cmdctor_us", \
 "top7_queue_us", "top7_tail_us", "top7_rec_us", "top7_r1_us", \
 "top7_r1b_us", "top7_r2_us", "top7_queue_r2_us", "top7_dirty_ab_calls", \
 "top7_qpc_start_lo", "top7_qpc_start_hi", "top7_tick_us", "top7_lim_calls", \
 "top7_lim_us", "top7_lim_max_us", "top7_flags", "top7_queue_cmd_calls", \
 "top7_queue_cmd_us", "top7_slow_vtable", "top7_slow_slot", "top7_slow_us", \
 "top7_route_calls", "top7_route_us", "top7_route_enter_calls", "top7_route_enter_us", \
 "top7_route_other_enter_calls", "top7_route_other_enter_us", "top7_route_assign_calls", "top7_route_assign_us", \
 "top7_route_perman_calls", "top7_route_perman_us", "top7_route_slow_vtable", "top7_route_slow_slot", \
 "top7_route_slow_us", "top7_route_slow_enter_calls", "top7_route_slow_enter_us", "top7_route_slow_other_enter_calls", \
 "top7_route_slow_other_enter_us", "top7_route_slow_assign_calls", "top7_route_slow_assign_us", "top7_route_slow_perman_calls", \
 "top7_route_slow_perman_us", \
 "top7_route_assign_scope_us", "top7_route_assign_scope_calls", "top7_route_inner_kernel_us", "top7_route_inner_solves", \
 "top7_route_inner_lim_us", "top7_route_inner_lim_calls", "top7_route_inner_suppressed", "top7_route_inner_assign_entries", \
 "top7_route_slow_assign_scope_us", "top7_route_slow_assign_scope_calls", "top7_route_slow_inner_kernel_us", "top7_route_slow_inner_solves", \
 "top7_route_slow_inner_lim_us", "top7_route_slow_inner_lim_calls", "top7_route_slow_inner_suppressed", "top7_route_slow_inner_assign_entries", \
 "ledger_top_capacity", "ledger_entry_words", "ledger_top_offered", "ledger_top_retained", \
 "ledger_top_rejected", "ledger_top_evicted", "ledger_lim_ticks", "ledger_lim_ticks_retained", \
 "ledger_lim_ticks_omitted", "ledger_sink_calls", "ledger_sink_folded", "ledger_sink_aborted", \
 "ledger_sink_outside", "ledger_aborted_ticks", "ledger_aborted_lim_us", "ledger_aborted_form_calls", \
 "ledger_queue_calls", "ledger_queue_folded", "ledger_queue_aborted", "ledger_queue_outside", \
 "ledger_aborted_queue_us", "ledger_route_begun", "ledger_route_folded", "ledger_route_aborted", \
 "ledger_route_discarded", "ledger_route_refused_scope", "ledger_route_refused_depth", "ledger_route_unscoped_gates", \
 "ledger_aborted_route_us", "queue_overflow_calls", "queue_overflow_us", "queue0_vtable", \
 "queue0_slot", "queue0_calls", "queue0_us", "queue0_max_us", \
 "queue1_vtable", "queue1_slot", "queue1_calls", "queue1_us", \
 "queue1_max_us", "queue2_vtable", "queue2_slot", "queue2_calls", \
 "queue2_us", "queue2_max_us", "queue3_vtable", "queue3_slot", \
 "queue3_calls", "queue3_us", "queue3_max_us", "queue4_vtable", \
 "queue4_slot", "queue4_calls", "queue4_us", "queue4_max_us", \
 "queue5_vtable", "queue5_slot", "queue5_calls", "queue5_us", \
 "queue5_max_us", "queue6_vtable", "queue6_slot", "queue6_calls", \
 "queue6_us", "queue6_max_us", "queue7_vtable", "queue7_slot", \
 "queue7_calls", "queue7_us", "queue7_max_us", "queue8_vtable", \
 "queue8_slot", "queue8_calls", "queue8_us", "queue8_max_us", \
 "queue9_vtable", "queue9_slot", "queue9_calls", "queue9_us", \
 "queue9_max_us", "queue10_vtable", "queue10_slot", "queue10_calls", \
 "queue10_us", "queue10_max_us", "queue11_vtable", "queue11_slot", \
 "queue11_calls", "queue11_us", "queue11_max_us", "queue12_vtable", \
 "queue12_slot", "queue12_calls", "queue12_us", "queue12_max_us", \
 "queue13_vtable", "queue13_slot", "queue13_calls", "queue13_us", \
 "queue13_max_us", "queue14_vtable", "queue14_slot", "queue14_calls", \
 "queue14_us", "queue14_max_us", "queue15_vtable", "queue15_slot", \
 "queue15_calls", "queue15_us", "queue15_max_us", \
 "route_armed", "route_calls", "route_us", "route_max_us", \
 "route_no_enter_calls", "route_enter_calls", "route_enter_us", "route_other_enter_calls", \
 "route_other_enter_us", "route_assign_calls", "route_assign_us", "route_perman_calls", \
 "route_perman_us", \
 "route_assign_scope_us", "route_assign_scope_calls", "route_inner_kernel_us", "route_inner_solves", \
 "route_inner_lim_us", "route_inner_lim_calls", "route_inner_suppressed", "route_inner_assign_entries"
#ifdef __cplusplus
namespace kntwr_form_residual {
using U = uint32_t;
constexpr U kVersion = KNTWR_FORMATION_RESIDUAL_VERSION;
constexpr U kCalleeMax = 6;       // distinct [vtbl+0xC] callees tracked per loop (overflow counted in header)
constexpr U kTop = 8;             // top storm ticks kept
constexpr U kQueueClasses = 16;
constexpr U kHeaderWords = 12, kCalleeWords = kCalleeMax * 4, kAggWords = 40, kEntryWords = 73, kLedgerWords = 29,
            kQueueWords = 2 + kQueueClasses * 5, kRouteWords = 21;
constexpr U kRouteDepth = 8;      // private-route callbacks that may be in flight at once (reentrant walks nest strictly)
constexpr U kMid = 1000;          // forms_ge1ms threshold, us
enum Word : U {
    Version, Enabled, Ticks, StormTicks, FormCalls, CloneForms, OtherForms, MemberCalls,
    ObserverUs, QpcReadCostQ16, GateOutside, CalleeOverflow,
    CalleeTable = kHeaderWords,                    // kCalleeMax x 4: va (preferred-base), loop mask, calls, us
    StormAggregate = CalleeTable + kCalleeWords,   // kAggWords, see AggWord
    CalmAggregate = StormAggregate + kAggWords,    // kAggWords
    TopTable = CalmAggregate + kAggWords,          // kTop x kEntryWords, see EntryWord
    LedgerTable = TopTable + kTop * kEntryWords,   // kLedgerWords, see LedgerWord
    QueueTable = LedgerTable + kLedgerWords,       // kQueueWords, see QueueWord
    RouteTable = QueueTable + kQueueWords,         // kRouteWords, see RouteWord
    WordCount = RouteTable + kRouteWords
};
enum AggWord : U {
    AForms, AFormUs, AMaxFormUs, AMaxFormMembers, AMembersSum, AFormsGe1ms, ALoop1Us, ALoop2Us,
    ALoopCalls, ADirtyACalls, ADirtyAUs, ADirtyBCalls, ADirtyBUs, AAggCalls, AAggUs, AFsmCalls,
    AFsmUs, ACmdPredCalls, ACmdPredUs, ACmdCtorCalls, ACmdCtorUs, AQueueCalls, AQueueUs, ATailCalls,
    ATailUs, ARecCalls, ARecUs, AR1Us, AR1bUs, AR2Us, AQueueR2Us, AMaxFormGateUs,
    // Limited (limit != 0) solver calls: counted for every closed tick of the class, including ticks without formation calls.
    ALimTicks, ALimCalls, ALimUs, ALimMaxCallUs, ALimMaxTickUs, ALimOnlyTicks, ALimOnlyCalls, ALimOnlyUs
};
// dirty_ab_calls = dirty_a_calls bits 0..15 | dirty_b_calls bits 16..31 (saturating).
enum EntryWord : U {
    ETick, ESite18Us, EForms, EFormUs, EMaxFormUs, EMaxFormMembers, ELoop1Us, ELoop2Us,
    EMemberCalls, ELoopCalls, EDirtyAUs, EDirtyBUs, EAggUs, EFsmUs, ECmdPredUs, ECmdCtorUs,
    EQueueUs, ETailUs, ERecUs, ER1Us, ER1bUs, ER2Us, EQueueR2Us, EDirtyAbCalls,
    EQpcStartLo, EQpcStartHi,  // TraceTick `start` QPC of this tick: same-invocation identity (tick id alone repeats)
    ETickUs,                   // tick duration us as passed to TraceTick
    ELimCalls, ELimUs, ELimMaxUs,
    EFlags,                    // EFlagLimited: at least one limited call; EFlagLimitedOnly: no member/loop calls; EFlagSlowRouted
    EQueueCmdCalls, EQueueCmdUs,       // queue command callbacks of this invocation (count, inclusive us)
    ESlowVtable, ESlowSlot, ESlowUs,   // slowest single callback of this invocation: raw vtable, slot, inclusive us
    // Command-split route (see the header comment): the callbacks of this invocation the private 581CA0 chain really executed
    // ("routed"): count and inclusive us, then their nested gate totals (calls, inclusive us): matched enters (4F84C0 -> 5736B0,
    // i.e. the state transitions into the assignment state), other enters (every other state, native), 57B000 assignments and
    // 55F160 per-man calls. All zero together with route_calls == 0 means no routed callback, NOT zero native work.
    ERouteCalls, ERouteUs, ERouteEnterCalls, ERouteEnterUs, ERouteOtherEnterCalls, ERouteOtherEnterUs,
    ERouteAssignCalls, ERouteAssignUs, ERoutePerManCalls, ERoutePerManUs,
    // The slowest ROUTED callback (first of equal us) with its own pre-call vtable/slot, inclusive us and its OWN nested counts;
    // valid only when ERouteCalls != 0. EFlagSlowRouted set: it is the same callback as slow_vtable/slow_slot/slow_us.
    ERouteSlowVtable, ERouteSlowSlot, ERouteSlowUs, ERouteSlowEnterCalls, ERouteSlowEnterUs, ERouteSlowOtherEnterCalls,
    ERouteSlowOtherEnterUs, ERouteSlowAssignCalls, ERouteSlowAssignUs, ERouteSlowPerManCalls, ERouteSlowPerManUs,
    // Assignment split (version 4, census only). The routed 57B000 assignments' span is split by counter deltas around the
    // native call: assign_scope_us / assign_scope_calls = inclusive us / count of the OUTERMOST solver-clone scopes (the
    // 555CEB-gated chain: slot generation, phase-1 costing, overlay glue AND the inner solves) timed only inside the routed
    // GateAssign; inner_* = what the solver chain did meanwhile: kernel_us (memo/shadow kernel calls), solves (SolveGate entries),
    // lim_us / lim_calls (limit != 0 native solves; lim_us needs the census limited sink), suppressed (shim suppressions),
    // assign_entries (RunAssign entries, nested ones included). assign_scope - inner_kernel - inner_lim is the glue outside the
    // solves. All zero when the solver is not started (the forward is untimed) or the routed span saw no solver activity;
    // flag=1 solves that fall back native are inside assign_scope but in neither inner_* time. Aggregate over the routed
    // callbacks of the invocation, then the slowest routed callback's own copy (valid only when ERouteCalls != 0).
    ERouteAssignScopeUs, ERouteAssignScopeCalls, ERouteInnerKernelUs, ERouteInnerSolves, ERouteInnerLimUs, ERouteInnerLimCalls,
    ERouteInnerSuppressed, ERouteInnerAssignEntries,
    ERouteSlowAssignScopeUs, ERouteSlowAssignScopeCalls, ERouteSlowInnerKernelUs, ERouteSlowInnerSolves, ERouteSlowInnerLimUs,
    ERouteSlowInnerLimCalls, ERouteSlowInnerSuppressed, ERouteSlowInnerAssignEntries
};
enum EntryFlag : U { EFlagLimited = 1, EFlagLimitedOnly = 2, EFlagSlowRouted = 4 };
// Retention ledger. Every closed storm tick is ELIGIBLE and OFFERED to the bounded top-8 table: offered = retained-now +
// rejected + evicted. Bounded selection is by design (largest site-18 us), not transport loss: the aggregates (AggWord) cover
// every closed tick of the class. lim_ticks = total eligible closed ticks (storm and calm) with >= 1 limited call;
// lim_ticks_retained = those currently present as rows, lim_ticks_omitted = lim_ticks - retained (calm ticks and
// rejected/evicted storm ticks are never rows). Limited-call disposition: sink_calls = every NoteLimitedSolve received while
// the census runs = sink_folded (folded into a closed tick) + sink_aborted (discarded with an aborted invocation) +
// sink_outside (no open invocation owned by the calling thread: counted, never folded) + pending (calls of the currently open
// invocation, published live: sink_calls - folded - aborted - outside). Aborted invocations are never rows or aggregates;
// aborted_ticks counts open scopes that were aborted (with or without limited calls), aborted_lim_us their inclusive limited
// time and aborted_form_calls their discarded member+loop calls.
enum LedgerWord : U {
    LTopCapacity, LEntryWords, LTopOffered, LTopRetained, LTopRejected, LTopEvicted,
    LLimTicks, LLimTicksRetained, LLimTicksOmitted, LSinkCalls, LSinkFolded,
    LSinkAborted, LSinkOutside, LAbortedTicks, LAbortedLimUs, LAbortedFormCalls,
    // Queue command callbacks (NoteQueueCommand): queue_calls = every observation received while the census runs =
    // queue_folded (folded into a closed tick's row) + queue_aborted (discarded with an aborted invocation) + queue_outside
    // (no open owner-thread scope) + pending (calls of the open invocation, live). aborted_queue_us = inclusive callback time
    // of the aborted ones. The class table below is cumulative over ALL observed calls (folded, aborted, outside).
    LQueueCalls, LQueueFolded, LQueueAborted, LQueueOutside, LAbortedQueueUs,
    // Private command-split route. route_begun = private dispatches accepted = folded (ended normally, folded into a closed
    // tick) + aborted (ended normally, invocation aborted) + discarded (never ended: the callback or a gate native threw, or a
    // scope still open when its invocation closed) + pending (live: ended callbacks of the open invocation + in-flight scopes).
    // refused_scope: the callback matched the route but ran native (route disarmed by the scope: no open invocation of the calling
    // thread, foreign thread); refused_depth: the in-flight scope stack (kRouteDepth) was full. unscoped_gates: gate calls of the
    // private chain that found no live scope (forwarded native, not attributed). aborted_route_us = inclusive us of the routed
    // callbacks of aborted invocations.
    LRouteBegun, LRouteFolded, LRouteAborted, LRouteDiscarded, LRouteRefusedScope, LRouteRefusedDepth, LRouteUnscopedGates,
    LAbortedRouteUs
};
// Queue class table (QueueTable): [overflow_calls, overflow_us] then kQueueClasses x {vtable, slot, calls, us, max_us}. A class
// is a (vtable, slot) pair in first-seen order; calls whose pair does not fit once all kQueueClasses are used are counted only
// in overflow_calls/overflow_us (never dropped silently). Times are inclusive callback us.
enum QueueWord : U { QOverflowCalls, QOverflowUs, QClassBase };
enum QueueClassWord : U { QVtable, QSlot, QCalls, QUs, QMaxUs, QClassWords };
// Cumulative route table over EVERY routed callback that ended normally (folded, aborted, any invocation): armed (1 when the
// private 581CA0 and 4F84C0 clones are bound), calls, inclusive us, max single-callback us, calls without a matched enter,
// then the nested totals (calls, us) matched enter / other enter / 57B000 assignment / 55F160 per-man. Published at tick close/abort.
enum RouteWord : U { RArmed, RCalls, RUs, RMaxUs, RNoEnterCalls, REnterCalls, REnterUs, ROtherEnterCalls, ROtherEnterUs,
                     RAssignCalls, RAssignUs, RPerManCalls, RPerManUs,
                     RAssignScopeUs, RAssignScopeCalls, RInnerKernelUs, RInnerSolves, RInnerLimUs, RInnerLimCalls, RInnerSuppressed,
                     RInnerAssignEntries };
static_assert(StormAggregate == 36 && CalmAggregate == 76 && TopTable == 116 && LedgerTable == 700 && QueueTable == 729 &&
                  RouteTable == 811 && WordCount == 832,
              "formation residual status row geometry (KNTWR_FORMATION_RESIDUAL_WORDS)");
static_assert(KNTWR_FORMATION_RESIDUAL_TOP_OFFSET == TopTable && KNTWR_FORMATION_RESIDUAL_TOP_ROWS == kTop &&
                  KNTWR_FORMATION_RESIDUAL_ENTRY_WORDS == kEntryWords && KNTWR_FORMATION_RESIDUAL_LEDGER_OFFSET == LedgerTable &&
                  KNTWR_FORMATION_RESIDUAL_LEDGER_WORDS == kLedgerWords && KNTWR_FORMATION_RESIDUAL_QUEUE_OFFSET == QueueTable &&
                  KNTWR_FORMATION_RESIDUAL_QUEUE_CLASSES == kQueueClasses && KNTWR_FORMATION_RESIDUAL_ROUTE_OFFSET == RouteTable &&
                  KNTWR_FORMATION_RESIDUAL_ROUTE_WORDS == kRouteWords && EFlags == 30 && EQueueCmdCalls == 31 && ESlowUs == 35 &&
                  ERouteCalls == 36 && ERouteSlowPerManUs == 56 && ERouteAssignScopeUs == 57 && ERouteSlowAssignScopeUs == 65 &&
                  ERouteSlowInnerAssignEntries == 72 && RInnerAssignEntries == 20 && LAbortedQueueUs == 20 && LAbortedRouteUs == 28,
              "launcher geometry macros");
constexpr U kWords = WordCount;
namespace {
const char* const kLabelProbe[] = { KNTWR_FORMATION_RESIDUAL_LABELS };
static_assert(sizeof(kLabelProbe) / sizeof(kLabelProbe[0]) == WordCount, "KNTWR_FORMATION_RESIDUAL_LABELS must name every residual word");
} // namespace

// Clone bindings (called by the runtime before kntwr_build_clones): fills the nine KNTWR_BIND_FORM_* gates and the three
// KNTWR_BIND_CMD_{ENTER,ASSIGN,PERMAN} command-split gates of this module; every gate forwards the original native when the
// census is not inside a Formation occurrence / has no live private-route scope.
void Bind(U delta, uint32_t* bindings);
// cloneFormUpdate = relocated entry of KNTWR_CLONE_FORM_UPDATE (0 disables the clone path; callees run original).
// cloneCmd581CA0 / cloneCmd4F84C0 = relocated entries of KNTWR_CLONE_CMD_581CA0 / KNTWR_CLONE_CMD_4F84C0: the command-split
// route is armed only when BOTH are non-zero; otherwise every queue callback runs its native target (counted only by the
// queue class table). Arming adds no flag and no behaviour: the private chain executes the same native instructions.
bool Start(U cloneFormUpdate, U cloneCmd581CA0, U cloneCmd4F84C0);
void Stop();
void Reset();
// Exact port of 0x585D50 (disassembly-pinned: two member loops over U+AB4/U+AB0 and U+AD0/U+ACC calling [vtbl+0xC]; plain ret,
// EAX unused by the caller at 5820E3). ECX = U. Runs only through kntwr_army_storm::Call(BFormation, ...) in the census epoch.
U __fastcall Formation(void* unit);
// Invocation scope (owner thread only). TickBegin opens the per-invocation accumulators right before the owner's private tick
// body (after the owner/model guards); TickEnd closes it normally from TraceTick (routed owner path); TickAbort, called from the
// tick's __finally when TraceTick never ran, DISCARDS every per-invocation accumulator (formation brackets, limited solves) so a
// later invocation's QPC-identified row can never absorb them, while the cumulative history stays and the loss is accounted in
// the ledger (aborted_ticks / aborted_lim_us / aborted_form_calls, sink_aborted, queue_aborted). Only the thread that called
// TickBegin owns the open scope: a foreign thread's TickBegin/TickEnd/TickAbort are ignored while it is open (no abort, no
// takeover, no fold) and its limited/queue observations count as sink_outside/queue_outside. TickBegin by the owner itself
// while its scope is still open aborts that unclosed scope first. TickEnd without an open scope owned by the caller is a no-op.
void TickBegin();
void TickAbort();
// Tick owner, tick trace writer, immediately after kntwr_army_storm::TickEnd of the same tick: `storm` is the census's
// classification for this tick so the two rows agree. qpcStart = TraceTick's `start` (QPC ticks, identity of the invocation),
// tickUs = the tick duration passed to TraceTick. Folds the limited-solve calls noted since TickBegin and closes the scope.
void TickEnd(U tick, U site18Us, bool storm, unsigned long long qpcStart, U tickUs);
// Sink for kntwr_army_solver::Binding::limitedSink: one exact native limited (limit != 0) solve took `qpcTicks` QPC ticks.
// No-op unless the census runs. Counts its own two QPC reads into the observer accounting (NoteReads(2)).
void NoteLimitedSolve(unsigned long long qpcTicks);
// Observer for kntwr_formation_queue::Run: one command callback of the formation queue walk 0x581E80 returned normally. `vtable`
// is the RAW pre-call command vtable (command class, preferred or relocated VA as the image runs), `slot` kSlotLast(4) or
// kSlotOther(8), qpcTicks the inclusive QPC delta of that callback only. Updates the cumulative class x slot table immediately
// (it therefore INCLUDES observed calls of invocations that are later aborted) and, when an owner-thread scope is open, the
// per-invocation accumulator (otherwise counted as queue_outside). Counts 2 QPC reads (NoteReads(2)). No-op unless the census
// runs. A callback that exits by exception produces no observation: its time is in no queue_cmd/queue class field.
void NoteQueueCommand(U vtable, U slot, unsigned long long qpcTicks);
// Copies the row; all zero when the census never ran (enabled word 0).
void Snapshot(U* words /*[kWords]*/);
} // namespace kntwr_form_residual
#endif
