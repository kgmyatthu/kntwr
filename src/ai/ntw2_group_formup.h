#ifndef NTW2_GROUP_FORMUP_H
#define NTW2_GROUP_FORMUP_H
#include <stdint.h>

// --ai-formup-gate[=pct,metres[,ticks]] (ntw2_config::ai_ctrl_flags bit 13 NTW2_AI_FORMUP_GATE, parameters in ntw2_config::ai_group_params; analysis/native-ai-formup-gate.md).
// AI-ONLY GAMEPLAY DEVIATION (user-approved, opt-in, never implied by --features all): an AI ATTACK_BATTLEGROUP (tactic size 0x82C) leaves its REFORM state (2) and its
// MOVE_TO_FORMUP state (3) only when the group is actually formed.  The shared soldier/unit simulation is untouched; only the decision "this FSM state is finished" of the AI planner's
// own tactic object changes, for exactly the two exits below.  Player units have no tactic object, so they cannot reach the gate.
//
// Native structure [proven by disassembly + decompile, image 13fcab62]:
//   the FSM state classes are 5-slot tables [test][enter][update][stub][name]; the ATTACK_BATTLEGROUP states are REFORM (2) = table 0x133E184 and MOVE_TO_FORMUP (3) = table 0x133E2B0.  Every
//   slot is a __stdcall thunk taking the tactic's embedded FSM sub-object (tactic + 0x7C; NULL maps to NULL) and returning an FSM EVENT identity (EAX = the pointer returned by a tactic
//   vtable slot that is a constant-returning stub: +0x80 0x1453C24, +0x84 0x1453C28, +0x88 0x1453C2C, +0x8C 0x1453C30; 0 = no event).
//   test thunk 0x702A80 (REFORM):       if (0x7B5AF0(t)) return t.vt[+0x88](); if (0x7A5730(t)) return t.vt[+0x84](); return 0;
//   test thunk 0x702B20 (MOVE_TO_FORMUP): if (0x7A5A80(t)) return t.vt[+0x88](); if (0x7B5640(t)) return t.vt[+0x80](); if (0x7A5C80(t)) return t.vt[+0x8C](); return 0;
//   enter thunks 0x702A40 (REFORM -> 0x7B5910) / 0x702AE0 (MOVE_TO_FORMUP -> 0x7A5A30) run once when the state is entered.
//   0x7B5AF0 = [t+0x818] > 3 (re-issue counter) or heading to the target within 60 degrees; 0x7A5A80 = form-up waived ([t+0x81E] == 0) or the group move reports arrived + heading or the
//   oriented box fits the terrain.  Nothing in the native tests asks whether the member units reached their slots (the dump's Formed=%u%% is display only).  All four thunks are called
//   by nothing but the state-class tables (xref scan: the five natives have no other caller).
//
// Mechanism: the four table slots (vtable-slot gates, pinned to the audited originals) run a host MIRROR of the thunks.  The mirror calls the same native tests in the same order and
// returns the same event identity; the only difference is that an "exit" answer of 0x7B5AF0 / 0x7A5A80 is WITHHELD unless one of the passes below holds.  A withheld exit returns 0
// (no event this tick) at once: the alternate-event tests that follow a FALSE answer in the thunk (0x7A5730, 0x7B5640, 0x7A5C80; the last one sets [t+0x823]) are skipped because the
// native never reaches them after a TRUE answer.  With the switch off the gate tail-calls the original thunk.  The decision is made only when the native says "exit" (the common
// FALSE path costs two compares), so the per-tick cost is a handful of unit reads per exiting group.
//   pass waived:   [t+0x81E] == 0 (the engine itself waives form-up: single-unit group, region/tactic kinds 5/6/7, ...): native behaviour.
//   pass escape:   [t+0x80C] <= 140.0f (the engine's own 'no time' enemy distance, the same constant 0x7B5640 uses): native behaviour.
//   pass timeout:  model ticks since the state was entered >= timeoutTicks (entry recorded by the enter gates; default 2400 = 4 min).
//   pass formed:   formed% >= pct, where formed% = members whose unit centre ([[U+0xADC]+0x644/0x648]) is within `metres` of the destination of their active command (the slot position
//                  the group move gave them: row = U+0x398+0x90*[U+0x934], pose = row.vt[+0x38](), vec3 = 0x80E9D0(pose)), counted over the live members under group control
//                  ([U+0xAA0] != 2, [U+0x2CC] > 0, [U+0xB34] not 6/7, [U+0xB42] == 0).  A member with no active command ([U+0x930] == 0) is at its slot; a member whose active command is
//                  not the move command (vtable 0x1321CA4) or whose pose is unreadable is counted formed and reported as 'unmeasured' (a gate must never wait on what it cannot measure).
// Thread: the gates run wherever the FSM is serviced (the planner pass; the AI worker under NTW2_AI_ASYNC joins before the tick continues, so one thread touches the table at a time);
// calls outside the site-34 think scope are still gated and counted (high half of word 15).  All engine reads are pre-validated and wrapped in one SEH bracket (silent through ntw2::probeDepth):
// a fault lets the native answer through and is counted.
namespace ntw2_group_formup {
// ai_group_words[0..15] (NTW2_AI_FORMUP_LABELS):
//  0 gate_evals       test-slot calls routed through the gate (both states, mode on)
//  1 native_exit      evaluations in which the native test said "exit"
//  2 blocked          native exits withheld
//  3 pass_formed      native exits released because formed% >= pct
//  4 pass_timeout     ... released by the safety timeout
//  5 pass_escape      ... released because [t+0x80C] <= 140 m
//  6 pass_waived      ... released because the engine waived form-up ([t+0x81E] == 0)
//  7 blocked_entries  distinct state entries that were blocked at least once (blocked transitions)
//  8 wait_max_ticks   longest wait (ticks since state entry) seen on a blocked or a released-after-blocked evaluation
//  9 wait_sum_ticks   sum of waits of released entries that had been blocked (mean time groups spent forming = sum / released)
// 10..13 formed% histogram of every evaluation that measured it: <= 25, <= 50, <= 75, > 75
// 14 unmeasured      members counted formed because no destination could be read
// 15 faults          SEH faults / table-full fallbacks (native answer let through); bits 16..31 = gate calls outside the site-34 think scope
constexpr uint32_t kWords = 16;
enum Word : uint32_t { WEvals, WNativeExit, WBlocked, WPassFormed, WPassTimeout, WPassEscape, WPassWaived, WBlockedEntries, WWaitMax, WWaitSum,
                       WHist0, WHist1, WHist2, WHist3, WUnmeasured, WFaults };
extern volatile uint32_t words[kWords];

struct Params {
    uint32_t pct;          // 0..100: required share of formed members
    uint32_t metres;       // 0..255: a member is formed within this distance of its slot
    uint32_t timeoutTicks; // 1..65535: safety timeout since the state was entered
};
struct Targets {
    uint32_t reformExit, reformAlt;                      // 0x7B5AF0, 0x7A5730 (thiscall bool, ECX = tactic)
    uint32_t formupExit, formupAlt, formupAlt2;          // 0x7A5A80, 0x7B5640, 0x7A5C80
    uint32_t poseToVec;                                  // 0x80E9D0 (thiscall, ECX = pose, one stack argument = out vec3, callee pops 4)
    uint32_t moveVtable;                                 // 0x1321CA4: vtable of the move command row
    uint32_t test2, enter2, test3, enter3;               // original table slot targets 0x702A80, 0x702A40, 0x702B20, 0x702AE0 (__stdcall(sub))
    bool (*scope)(uint32_t tid);                         // thread inside the site-34 think (informational: counted, never required); may be null
};
// Arms the gate (enabled) or leaves it forwarding.  Zeroes the row and the wait table.
void Configure(bool enabled, const Params& params, const Targets& targets);
void ResetRow();
void Snapshot(volatile uint32_t* out); // out[kWords]

uint32_t __stdcall TestGate2(uint32_t sub);
uint32_t __stdcall EnterGate2(uint32_t sub);
uint32_t __stdcall TestGate3(uint32_t sub);
uint32_t __stdcall EnterGate3(uint32_t sub);

constexpr uint32_t kTest2Slot = 0x133E184u, kEnter2Slot = 0x133E188u, kTest3Slot = 0x133E2B0u, kEnter3Slot = 0x133E2B4u;
constexpr uint32_t kTest2Original = 0x702A80u, kEnter2Original = 0x702A40u, kTest3Original = 0x702B20u, kEnter3Original = 0x702AE0u;
constexpr uint32_t kReformExit = 0x7B5AF0u, kReformAlt = 0x7A5730u, kFormupExit = 0x7A5A80u, kFormupAlt = 0x7B5640u, kFormupAlt2 = 0x7A5C80u;
constexpr uint32_t kPoseToVec = 0x80E9D0u, kMoveVtable = 0x1321CA4u;
constexpr float kEscapeMetres = 140.0f;
}
#endif
