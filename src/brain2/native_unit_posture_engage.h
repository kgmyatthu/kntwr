#pragma once
#include <stdint.h>
// Per-unit posture (S2b) and engage/fire/lookup (S1c, S3, S1a/S2a lookups) providers of the shared unit-policy module
// (analysis/checkpoints/UnitBrainSlices.md Contract 1; analysis/checkpoints/UnitPostureEngage.md). This module never selects
// units and keeps no membership: it implements Provider{decide,end,retire,observe} for Mechanic Posture and Mechanic Engage
// and the generator-pinned binding bodies of the BRAIN_U_DRIVER / BRAIN_US_DRIVER / BRAIN_U_FINALIZE / BRAIN_U_PATH clones.
//
// POSTURE (slot[Posture]). Unit activity = the unit FSM state (U+D68, singleton [U+D6C] in 1450908..1450918 = A..E). A
//   (no target S+18, no unit command S+1C, no steering S+24, not P) maps to the posture REST state (singleton 1454198):
//   every member that runs the unit's 819A01 gets, with the native per-man effects, exit(old) -> [fsm+4]=rest -> enter(rest)
//   (only when old != rest) -> update(rest), AL = native result (0 after the update because the state is rest), the native
//   iteration budget [fsm+8]+1 honoured; 10FBBDA (next-state) is never called. B..E have no closed unit mapping: refused
//   (native) and measured in shadow (activity x command speed class x native member state, see the status labels).
// ENGAGE (slot[Engage], "EV" block words 0..8, lookups from word 16): inline gates in the driver clones read the occurrence's
//   EV pointer (kNative block for non-admitted occurrences): own phase 0 at 658C62, 6 at 658FDE, 7 at 6590FC, the frozen
//   unit D9D flag replaces the per-man [U+D9D] read at 658FB8, +F1 / +619 latch bytes at 658DEF / 658DFB are
//   (old & and) | or. Retained native: target+224 = 9 at 658F44 (pair), node ctor/dtor, 7E1ED0 RNG, watcher, setters 655B20/
//   643C90, 659600, every per-man node-state branch (+2C4/+234/+36C/+5B8/+5AB/+534). Unit-only lookups (64F8F0 =
//   55B0A0(U), 57E1F0(U), 649520 at 6544DB) are evaluated once per unit and stage and served from the slot.
#define NTW2_UNIT_POSTURE_ENGAGE_LABELS \
 "version", "posture_mode", "engage_mode", "stages", "p_decide_units", "p_admitted_last", \
 "p_admitted_unit_stages", "p_refused_unit_stages", "p_refuse_no_unit", "p_refuse_fsm", "p_refuse_state", \
 "p_refuse_active", "p_act_a", "p_act_b", "p_act_c", "p_act_d", "p_act_e", "p_applied", "p_transition", \
 "p_update_only", "p_null_state", "p_native_state", "p_native_table", "p_drains", "p_budget_stop", \
 "p_cmp_members", "p_cmp_agree", "p_cmp_disagree", "p_cmp_not_run", "p_cmp_null", "p_cmp_other", \
 "p_cmp_transitions", "p_cmp_pair0_native", "p_cmp_pair0_unit", "p_cmp_pair0_count", "p_cmp_pair1_native", \
 "p_cmp_pair1_unit", "p_cmp_pair1_count", "p_cmp_pair2_native", "p_cmp_pair2_unit", "p_cmp_pair2_count", \
 "p_cmp_pair3_native", "p_cmp_pair3_unit", "p_cmp_pair3_count", "p_cmp_pair4_native", "p_cmp_pair4_unit", \
 "p_cmp_pair4_count", "p_cmp_pair5_native", "p_cmp_pair5_unit", "p_cmp_pair5_count", "p_hist_members", \
 "p_hist_speed0", "p_hist_speed1", "p_hist_speed2", "p_hist_speed_other", "p_hist_act_a_state", \
 "p_hist_act_a_count", "p_hist_act_b_state", "p_hist_act_b_count", "p_hist_act_c_state", \
 "p_hist_act_c_count", "p_hist_act_d_state", "p_hist_act_d_count", "p_hist_act_e_state", \
 "p_hist_act_e_count", "p_hist_act_b_speed1_state", "p_hist_act_b_speed1_count", "p_hist_act_b_speed2_state", \
 "p_hist_act_b_speed2_count", "p_hist_act_c_speed1_state", "p_hist_act_c_speed1_count", \
 "p_hist_act_c_speed2_state", "p_hist_act_c_speed2_count", "p_hist_act_d_speed1_state", \
 "p_hist_act_d_speed1_count", "p_hist_act_d_speed2_state", "p_hist_act_d_speed2_count", \
 "p_hist_act_e_speed1_state", "p_hist_act_e_speed1_count", "p_hist_act_e_speed2_state", \
 "p_hist_act_e_speed2_count", "e_decide_units", "e_admitted_last", "e_admitted_unit_stages", \
 "e_refused_unit_stages", "e_refuse_no_unit", "e_refuse_read", "e_d9d_on_units", "e_d9d_off_units", \
 "e_site_unit_d9d", "e_alt_driver", "e_drains", "e_lk_native", "e_lk_pred_units", "e_lk_arrival_units", \
 "e_lk_modifier_units", "e_lk_served", "e_cmp_members", "e_cmp_phase0", "e_cmp_phase6", "e_cmp_phase7", \
 "e_cmp_phase9", "e_cmp_phase_other", "e_cmp_p6_native_unit_on", "e_cmp_p6_native_unit_off", \
 "e_cmp_p6_native_off_unit_on", "e_cmp_f1_native1", "e_cmp_f1_native0", "e_cmp_l619_native1", \
 "e_cmp_l619_native0", "e_order_units", "e_order_uniform_units", "e_order_mixed_units", \
 "e_stance_uniform_units", "e_stance_mixed_units", "e_unfolded_order_stance_units", "e_lk_pred_stale", \
 "e_lk_arrival_stale", "e_lk_modifier_stale", "e_d9d_stale", "e_stale_checked_units", "p_refuse_moving", "p_idle_units_checked", "p_moving_member_state", \
 "p_moving_member_request", "p_moving_member_fsm", "reserved126", "faults"
#ifdef __cplusplus
#include "native_unit_policy.h"
namespace ntw2_unit_posture_engage {
using U = uint32_t;
constexpr U kVersion = 1, kWords = 128;
// Slot layouts (ntw2_unit_policy::kSlotWords = 64 words per mechanic per unit). Asm contract: do not reorder.
enum PostureSlot : U {
    PsTarget,        // 0 absolute address of the target posture state singleton; 0 = native (shadow / not admitted)
    PsRest,          // 1 absolute address of the rest singleton (AL result)
    PsActivity,      // 2 unit FSM activity 0..4 = A..E, 5 other
    PsShadowTarget,  // 3 decided target state index 0..12, ~0 none
    PsSpeedClass,    // 4 U+D68+24 class: 0 none, 1, 2, 3 other
    PsStage          // 5 stage of the decision
};
enum EngageSlot : U {
    EvClear, EvP6, EvP7, EvD9dMode, EvD9dValue, EvF1And, EvF1Or, EvL619And, EvL619Or, // 0..8 (inline gates)
    EvUnit = 12, EvStage,                                                         // 12 unit handle, 13 stage
    LkPredicate = 16, LkArrival, LkModifier, LkValid,                             // 16..19 frozen lookups (+LkValid mask)
    ObOrder = 24, ObStance, ObMode                                                // shadow observation scratch
};
constexpr U kLkPredicate = 1, kLkArrival = 2, kLkModifier = 4;
// Status word bases (labels: NTW2_UNIT_POSTURE_ENGAGE_LABELS). Counters wrap modulo 2^32.
enum WordBase : U {
    WVersion = 0, WPostureMode, WEngageMode, WStages,
    WPDecide = 4,        // decide_units, admitted_last, admitted_unit_stages, refused_unit_stages, refuse x4, act A..E
    WPApply = 17,        // applied, transition, update_only, null_state, native_state, native_table, drains, budget_stop
    WPCompare = 25,      // members, agree, disagree, not_run, null, other, transitions
    WPPairs = 32,        // 6 x (native index, unit index, count); index 13 = null state, 14 = other pointer
    WPHist = 50,         // members, speed0..2/other, modal (state,count) per activity A..E, per (B..E x speed1,2)
    WEDecide = 81,       // decide_units, admitted_last, admitted_unit_stages, refused_unit_stages, no_unit, read, d9d on/off
    WESites = 89,        // site_unit_d9d, alt_driver, drains, lk_native
    WELookups = 93,      // pred/arrival/modifier unit-stages, lk_served
    WECompare = 97,      // members, phase 0/6/7/9/other, p6 x3, f1 x2, l619 x2
    WEOrder = 110,       // order_units, order uniform/mixed, stance uniform/mixed, unfolded
    WStale = 116,        // lk_pred_stale, lk_arrival_stale, lk_modifier_stale, d9d_stale, units checked (shadow end-of-stage re-evaluation)
    WMoving = 121,       // p_refuse_moving, idle units checked, causes: member state / sequencer request / fsm request fields (unit-stages)
    WFaults = 127
};
bool Bind(U imageBase, U* bindings);
// Owner, before the first stage. Modes are ntw2_unit_policy::Mode values (Off/Shadow/Live). Returns false when a mode is on
// but the pinned image tables do not match (the module then stays off).
bool Start(U imageBase, U postureMode, U engageMode, const U* cloneEntries);
const ntw2_unit_policy::Provider* PostureProvider();  // nullptr when posture mode is Off
const ntw2_unit_policy::Provider* EngageProvider();   // nullptr when engage mode is Off
void Stop();
void Reset();
void Snapshot(U* words /*[kWords]*/);
} // namespace ntw2_unit_posture_engage
#endif
