#ifndef NTW2_GROUP_HOLD_H
#define NTW2_GROUP_HOLD_H
#include <stdint.h>

// --ai-hold-slots[=infantry|all] (ntw2_config::ai_ctrl_flags NTW2_AI_HOLD_SLOTS = bit 15, NTW2_AI_HOLD_SLOTS_ALL = bit 16 (requires bit 15); lever 2 of the AI work).
// AI-ONLY GAMEPLAY DEVIATION (user-approved, opt-in, never implied by --features all): while an AI ATTACK_BATTLEGROUP is in MOVE_TO_TARGET (FSM state 4) and its group
// has not yet arrived at its destination, its eligible members keep the posture mark 4 instead of the native 1, so the per-unit missile/melee analyser gives them no NEW
// attack objective and the line advances together instead of peeling off piecemeal.  The shared soldier/unit simulation is untouched: only the AI planner's
// ATTACK_BATTLEGROUP member posture marking changes.  With the switch OFF nothing changes at all: the call-site redirect is not even installed.
//
// Native structure [proven by disassembly of Napoleon_patched.exe, preferred base 0x400000]:
//   0x7C8820 = the ATTACK_BATTLEGROUP posture marking (thiscall, ECX = tactic, no stack arguments, void, plain `ret` at 0x7C8924).  Single caller:
//   0x7D9223 `E8 F8 F5 FE FF  call 0x7C8820` inside the tactic update callback 0x7D91D0 (run once per planner pass per tactic by 0x7045B0, more when [t+0x828] changes),
//   right after the FSM service 0x10FBBD0 (state enter/update, incl. the state-4 update 0x7A6960).  Decompiled:
//     if ([t+0x828] == 5) mark = 1; else { cls = [[t+0x40]+0x48] (target class); cls 7: 0; cls 6 or (5 with [[t+0x40]+0x4C] == 6): (state 2 && |[t+0x7E0]| < 60 ? ([t+0x7BC] ? 1 : 4)
//       : (cls == 5 && float[t+0x80C] > 30 ? 1 : 0)); cls 5: 1; cls != 4: 4; else 1 }
//     for i < [t+0x6C]: U = [[t+0x70]+4i]; if ([U+0xB34] != 6 && != 7) [U+0xB34] = mark;     then artillery with guns (0x55AB90) is forced to 1.
//   The reader: the AI_MELEE_MISSILE_ANALYSER loop 0x7983FF (every 30 ticks via 0x7DB360) skips members whose [U+0xB34] is 4, 6 or 8 (no new per-unit attack objective).
//   So in state 4 against a class-4 target the native marks members 1 (eligible) and lines peel off one unit at a time.
//   Arrival (native 0x7A6960, state-4 update; reproduced exactly): B = [t+0xD8] (group box; centre B+8/B+0xC, width W = B+0x14, depth D = B+0x18, axis1 B+0x1C/B+0x20,
//   forward B+0x24/B+0x28), destination dest = float[t+0x7E8], float[t+0x7EC]; arrived = W > 0 && D > 0 && ( |ax1.z*dz + ax1.x*dx| <= W*0.5 && |fwd.z*dz + dx*fwd.x| <= D*0.5
//   || (dest.x - (D*fwd.x*0.5 + B.x))^2 + (dest.z - (D*fwd.z*0.5 + B.z))^2 < 2500 ), dx = dest.x - B.x, dz = dest.z - B.z.  With --ai-standoff the destination is already the
//   stand-off point (0x7C7DC0 writes it before this runs), so the same test means "arrived at the stand-off point": nothing else is needed.
//   Unit facts: live = [U+0xAA0] != 2 && [U+0x2CC] > 0; category [[U+0x2C]+0x1C] (0 cavalry, 1 artillery, 2 infantry, 3 dragoons, 4 elephants); subclass [[U+0x2C]+0x20]
//   (17 Light Infantry, 22 Skirmisher Infantry); fighting melee = dword [[U+0xADC]+0x764] != 0 (script condition "fighting_melee", 0x557430).
//
// Mechanism: the E8 rel32 of the call at 0x7D9223 is redirected (patch verified against the original bytes, restored at stop) to MarkGate, which calls the native 0x7C8820 FIRST
// (the native marks are always written) and then post-processes: for a tactic whose [t+0x828] == 4 that has NOT yet arrived, every eligible member whose native mark is 1 is
// re-marked 4.  Once the group has arrived the "arrived" flag latches for that tactic until it leaves state 4 (a call that sees [t+0x828] != 4 clears it) and the gate stops
// overriding: the native rewrites every member's mark on every call, so restoring the native behaviour is simply not overriding.
// Eligibility (a member is re-marked only when ALL hold): native mark == 1 (anything else is untouched: 0/5/6/7... stay native), live, not artillery (category 1; the native forces
// it to 1 and the 0x75C880 ammo selection reads it), not fighting melee, and in the default `infantry` mode also category 2 INFANTRY and not subclass 17 (Light Infantry) or
// 22 (Skirmisher Infantry), which are skirmish-capable.  `all` mode: every non-artillery member.  An unreadable class / formation record is treated as exempt (class / melee).
// A gate must never hold on what it cannot measure: an unreadable or invalid group box (not Sane, non-finite field, W <= 0 or D <= 0) or a non-finite destination counts
// "unmeasured" and the native marks stay.
//
// Latch table: one entry per tactic pointer {tactic, lastTick, arrived, used} keyed by tactic, with the model tick [[[t+4]+8]+0x58]; an entry is (re)initialised (arrived = 0) when
// the tactic is first seen, when it was not seen for > kStaleTicks model ticks, or whenever a call sees [t+0x828] != 4.  Arrival is evaluated on each state-4 call until latched.
// Engine memory is only read (members' marks are the one write) inside ONE SEH bracket per call (ntw2::probeDepth), pre-validated with Sane(); POD locals only inside __try.  A fault is
// counted and the rest of that call keeps the native marks (marks already re-marked in the same call stay 4: they are the intended override, and the next call re-asserts the native
// marks anyway).  Per-call cost: a few reads per member, no allocation.
namespace ntw2_group_hold {
// ntw2_status::ai_hold_words (labels NTW2_AI_HOLD_LABELS):
//  0 calls          gate calls (every redirected 0x7C8820 call, mode on)
//  1 state4         calls with [t+0x828] == 4
//  2 held_calls     state-4 calls of a not-yet-arrived group (override applied)
//  3 marked         member re-marks 1 -> 4 (sum over calls)
//  4 exempt_class   members left at the native mark by the class filter (artillery always; infantry mode: non-infantry, light, skirmisher)
//  5 exempt_melee   members left at the native mark because fighting melee
//  6 arrivals       arrival latches (state-4 group reached its destination; native marks from then on)
//  7 released_calls state-4 calls of an arrived (latched) group
//  8 groups         latch table entries created
//  9 table_full     latch table full (native marks kept)
// 10 skipped_mark   members whose native mark was not 1 (untouched)
// 11 dead_skipped   dead / non-live members skipped
// 12 max_members    largest member count seen
// 13 unmeasured     state-4 calls whose box/destination was unreadable or invalid (native marks kept)
// 14 out_of_scope   gate calls outside the site-34 planner think scope (informational; still gated)
// 15 faults         SEH faults (native marks kept for the rest of that call)
constexpr uint32_t kWords = 16;
enum Word : uint32_t { WCalls, WState4, WHeldCalls, WMarked, WExemptClass, WExemptMelee, WArrivals, WReleasedCalls,
                       WGroups, WTableFull, WSkippedMark, WDeadSkipped, WMaxMembers, WUnmeasured, WOutOfScope, WFaults };
extern volatile uint32_t words[kWords];

constexpr uint32_t kStaleTicks = 600;

enum Mode : uint32_t { ModeOff = 0, ModeInfantry = 1, ModeAll = 2 };
struct Targets {
    uint32_t marking;              // relocated 0x7C8820 (thiscall ECX = tactic, no stack args, void)
    bool (*scope)(uint32_t tid);   // site-34 think scope (informational), may be null
};
void Configure(Mode mode, const Targets& targets); // zeroes the row and the latch table
void ResetRow();
void Snapshot(volatile uint32_t* out);              // out[kWords]

// Replacement for `call 0x7C8820` at 0x7D9223: calls targets.marking(tactic) first, then post-processes (mode off: pure forward).
void __fastcall MarkGate(uint32_t tactic, uint32_t /*edx*/);

constexpr uint32_t kCallSite = 0x7D9223u, kMarking = 0x7C8820u, kStateOffset = 0x828u;
// Patch / restore the call site (delta = image delta from the preferred base; gate = FnAddress(&MarkGate)).
bool InstallRedirect(uint32_t delta, uint32_t gate); // verify E8 rel32 -> kMarking+delta at kCallSite+delta, patch to gate; false on mismatch, no partial change
bool RemoveRedirect(uint32_t delta);                 // restore the original rel32; true if already original
}
#endif
