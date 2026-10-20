#ifndef NTW2_GROUP_STANDOFF_H
#define NTW2_GROUP_STANDOFF_H
#include <stdint.h>

// --ai-standoff[=k] (ntw2_config::ai_ctrl_flags NTW2_AI_STANDOFF = bit 14, k x 100 in ntw2_config::ai_group_params2 bits 0..7; analysis/native-ai-standoff.md).
// AI-ONLY GAMEPLAY DEVIATION (user-approved, opt-in, never implied by --features all): an AI ATTACK_BATTLEGROUP in MOVE_TO_TARGET (FSM state 4) with at least one
// missile-capable member no longer drives its front at the enemy region CENTRE; it drives it to a stand-off point k x (the group's smallest member weapon range)
// short of the nearest enemy man on the approach line, and holds there while the per-unit missile objectives (0x798230) fire. Shared soldier/unit simulation is untouched.
//
// Native structure [proven, analysis/native-attack-group-fsm.md + native-ai-standoff.md]:
//   0x7A6910 (state-4 enter) and 0x7A6960 (state-4 update, every service) call 0x7C7DC0(this = tactic, param) which sets the destination +0x7E8/+0x7EC from
//   0x78B1C0(tactic, &out) = the target region centre R+8/R+0xC clamped into the play rect, derives heading +0x800 = atan2(dest - group centre), tests the oriented
//   group box at the destination against terrain and backs the destination off in 10 m steps; 0x83FD00 then (re-)issues the group move (de-dupe: moved <= 15 m and heading
//   inside its window).  0x7C7DC0 is called ONLY from those two sites, through 0x78B1C0 at two call sites inside it (0x7C7DD2 first computation, 0x7C82F6 the reset to the
//   region centre after a blocked back-off), 0x7A6960 treats the group as arrived when the destination is inside the group box or within 50 m of the group front (box centre
//   + D/2 x forward); a not-yet-arrived group keeps its move, an arrived one recomputes 0x7C7DC0 every service.
//
// Mechanism: both 0x78B1C0 call sites inside 0x7C7DC0 are redirected (E8 rel32 patch, restored at stop) to RegionGate, which calls the native 0x78B1C0 and, for a tactic
// whose dump slot ([[tactic]+0x68]) is the ATTACK_BATTLEGROUP dump 0x765540 and whose controller (tactic+0x88) holds a member with a weapon range, replaces the returned
// point by the stand-off point.  Everything downstream is native: the same heading/terrain back-off/re-issue/arrival code then works from the stand-off point, so the 10 m terrain
// back-off, the 15 m re-issue hysteresis and the 50 m arrival test are unchanged and the group simply "arrives" at the stand-off and keeps being served with the same destination
// (no region-centre advance, no re-issue).  Outflank (state 5), form-up (3), reform (2) never call 0x7C7DC0; any other tactic fails the dump-slot test and gets the native centre.
//
// Stand-off point [group box B = [tactic+0x88+0x50]: centre G = B+8/B+0xC, width W = B+0x14, depth D = B+0x18, forward B+0x24/0x28; C = native centre; h = (C - G)/|C - G|]:
//   range r = min over group members with a missile weapon (0x5646A0 > 0) of 0x5646A0(unit)  (metres; 0x5646A0 = 0 when the unit cannot shoot)
//   enemy men E = members (unit+0x2D0/0x2CC, position +0x48/+0x50) of the enemy units: the units of the target region (list R+0x60/+0x5C, R = 0x78B070(tactic)) that are not on the
//   group's side; when that list holds none, every enemy unit whose formation centre is within kSearchM of C (words: src_global).  The side of a unit is the side of
//   model -> M = [model+0xB0] -> sides [M+0x88] -> armies [side+0x24] -> units [army+0xF4] (the graph walk of the engage census); the group's side is the side holding its first member.
//   t(m) = (m - G).h, lat(m) = |(m - G) x h|; the enemy edge te = min t(m) over men with t >= 0 and lat <= W/2 + r (the muskets reach r sideways too).
//   front target  Pf = G + h x (te - k x r)   (0x83FD00 / 0x7A6960 treat the destination as the group's FRONT target: arrival is measured from box centre + D/2 x forward)
//   never behind the group: the destination is at least G + h x (D/2 x (fwd.h) + kLeadM) (counter holds), never beyond C.
// Cache: one entry per tactic pointer {point, centre at evaluation, evaluation tick}.  The front is re-evaluated every kRecheckTicks model ticks (or after kFastTicks when the
// native centre moved more than kHystM since the last evaluation); the issued point only changes when the new one is more than kHystM (15 m, the engine's re-issue threshold)
// away from the issued one, so a stable front produces an identical destination every service and the native de-dupe never re-issues.
//
// Engine memory is read under SEH (ntw2::probeDepth); a fault is counted and the native point is kept.  Gate cost: ~20 reads on a cached call; an evaluation walks the unit graph
// once and the men of the enemy units that can still improve te (formation-radius culled).
namespace ntw2_group_standoff {
// ntw2_status::ai_group_words[16..31] (labels NTW2_AI_STANDOFF_LABELS):
//  0 calls         gated calls (every 0x78B1C0 call site invocation inside 0x7C7DC0)
//  1 applied       calls that returned a stand-off point instead of the native centre
//  2 points        distinct stand-off points issued (a cache entry adopted a new point)
//  3 recomputes    front evaluations (graph walk + men loop)
//  4 kept          evaluations whose new point stayed within the hysteresis of the issued one (issued point kept)
//  5 holds         applied calls whose destination was lifted to the group front (target already inside k x range: hold)
//  6 fb_no_enemy   native centre kept: no enemy man in the approach corridor
//  7 fb_no_range   native centre kept: no member with a weapon range (melee-only group)
//  8 fb_tactic     native centre kept: not the ATTACK_BATTLEGROUP dump / no controller list / no group box / no target region
//  9 fb_unreadable native centre kept: unreadable or non-finite engine state, side not found, busy
// 10 fb_bounds     native centre kept: the stand-off point fell outside the play rect
// 11 groups        cache entries created
// 12 table_full    cache full (the call kept the native centre)
// 13 faults        SEH faults caught (native centre kept)
// 14 src_global    evaluations whose enemy set came from the radius search instead of the target region list
// 15 last_range_m  smallest member weapon range of the last evaluated group (whole metres)
constexpr uint32_t kWords = 16;
enum Word : uint32_t { WCalls, WApplied, WPoints, WRecomputes, WKept, WHolds, WFbNoEnemy, WFbNoRange, WFbTactic, WFbUnreadable, WFbBounds, WGroups, WTableFull, WFaults, WSrcGlobal, WLastRange };
extern volatile uint32_t words[kWords];

constexpr float kHystM = 15.0f, kLeadM = 2.0f, kSearchM = 300.0f;
constexpr uint32_t kRecheckTicks = 10, kFastTicks = 2, kStaleTicks = 2000;

struct Targets {
    uint32_t regionCentre; // relocated 0x78B1C0 (thiscall ECX = tactic, one stack argument = float[2] out, returns out, ret 4)
    uint32_t regionOf;     // relocated 0x78B070 (thiscall ECX = tactic, returns the target region or 0; pure)
    uint32_t range;        // relocated 0x5646A0 (thiscall ECX = unit, float in ST0, metres, 0 when the unit cannot shoot)
    uint32_t dump;         // relocated 0x765540 (the ATTACK_BATTLEGROUP dump, vtable slot +0x68)
};
// Arms the gate (k100 = k x 100, 1..255). Zeroes the row. Targets are image-relocated VAs.
void Configure(bool enabled, uint32_t k100, const Targets& targets);
void ResetRow();                        // runtime start: zero the row before any poll of the new session
void Snapshot(volatile uint32_t* out);  // out[kWords]

// Replacement for the two `call 0x78B1C0` sites inside 0x7C7DC0 (thiscall ECX = tactic, one stack argument, callee pops 4).
float* __fastcall RegionGate(uint32_t self, uint32_t, float* out);

constexpr uint32_t kSiteFirst = 0x7C7DD2u, kSiteReset = 0x7C82F6u, kRegionCentreOriginal = 0x78B1C0u, kRegionOf = 0x78B070u, kRange = 0x5646A0u, kDump = 0x765540u;
// Patch / restore the two call sites (delta = image delta from the preferred base; `gate` = FnAddress(&RegionGate)). Both return false on any mismatch without a partial change.
bool InstallRedirect(uint32_t delta, uint32_t gate);
bool RemoveRedirect(uint32_t delta);
}
#endif
