#ifndef KNTWR_RETARGET_JITTER_H
#define KNTWR_RETARGET_JITTER_H
#include <stdint.h>

// --brain-retarget-jitter (kntwr_config::ai_ctrl_flags bit 12, KNTWR_AI_RETARGET_JITTER; analysis/native-brain-retarget-jitter.md).  SHARED-SIMULATION
// GAMEPLAY DEVIATION (user-approved for measurement; both armies, the player included; replays desync vs vanilla; default OFF, never implied by
// --features all).  Also the host mirror of the combat node's tracker tick 0x6671A0 that --brain-target-cull (src/brain/kntwr_target_cull.h) plugs its
// replacement of the contact-list search 0x553420 into.
//
// Native structure [proven by disasm, Steam image 13fcab62...]:
//   Node step 0x676FD0 (vtable 0x1333E3C slot +8 = thunk 0x66D750: `cmp byte [node+0x71],0; je 0x676FD0; jmp 0x675710`; the vtable word is the only
//   reference, the thunk and 0x676FD0 have no direct caller) runs once per soldier per tick in the soldier-brain stage (site 6).  Its tracker lives at
//   node+0x48 {+0 target unit, +4, +8 secondary keys, +0xC flag byte, +0x10 current target agent, +0x14 search cooldown}.  After the neighbour loop
//   (agents within 3 m; EDI = the nearest valid one, 0 if none) it does: [periodic clear every 64 ticks per agent when node+0x24 == 0 and (node+0x28 == 0
//   or agent+0x390 == 7): 0x63CE00]; EDI != 0 -> 0x662960(tracker, EDI) (forced melee target, cooldown := 0); else node+0x1C == 0 -> 0x63CE00; then
//   `call 0x6671A0(tracker, agent)` at 0x6775C4 (its single caller), ESI = the returned target agent (0 = none -> the no-target branch 0x67813F).
//   Tracker tick 0x6671A0(tracker ECX, agent; ret 4):
//     if (+0x14) --+0x14;
//     if (0x6795A0(tracker, agent)) return +0x10;                  // target alive (0x679750) and reachable (0x679700): +0x10 != 0 && both predicates
//     0x63CE00(tracker);                                           // if (+0x10) { target->+0x474--; +0x10 = 0 }
//     if (+0x14 == 0) {                                            // cooldown over (it is 0 whenever a target is held: 0x662960 zeroes it)
//         if (+0) r = 0x553420(agent->+0x1F0 + 0xA80, agent, +0);  // contact-list search (the spike: every man that lost its target searches the same tick)
//         else if (+4) r = 0x553220(list, agent, +4);
//         else if (+8) r = 0x6C6910(+8, agent, (uint8_t)+0xC);
//         else goto fail;                                          // no search key: r is not consulted
//         if (r) 0x662960(tracker, r);                             // +0x10 = r, r->+0x474++, +0x14 = 0
//       fail: if (+0x10 == 0) +0x14 = (agent+0x2C & 0xF) + 0x28;   // FAILED search: 40..55 tick cooldown, the engine's own per-man jitter
//     }
//     return +0x10;
//   The cooldown is only ever set after a failed search, so a lost target (invalid this tick) searches IMMEDIATELY, every man the same tick: a wave
//   of searches when a target unit dies or routs.
//
// Lever (flag on): when the target was lost THIS tick (+0x10 != 0 before 0x63CE00, i.e. 0x6795A0 failed on a held target) and the cooldown is 0,
//   +0x14 := agent+0x2C & 0xF (0..15 ticks, the engine's own jitter field) instead of searching: the man is target-less for d ticks (no-target branch
//   0x67813F: walks to its slot or stands) and searches at tick t+d with the native tail (a failed search still sets the native 40..55 ticks).  d == 0
//   (1/16 of the men) searches immediately as native.  Not delayed: the forced melee target (EDI -> 0x662960 never reaches the loss branch, because EDI
//   passed the same 0x679750/0x679700 predicates this tick), the periodic 64-tick clear and the node+0x1C == 0 per-tick clear (both clear BEFORE the tick,
//   so +0x10 == 0 inside it: not a loss), a man that never had a target, and the native failed-search cooldown.
//
// Mechanism: the routed tick's vtable slot 0x1333E44 is a gate (runtime: NodeStepGate) that, on the tick thread inside the site-6 stage, enters the
// pure-retarget clone CLONE_STEP_676FD0 (the original bytes of 0x676FD0 with the single call 0x6775C4 bound to TrackerTick); everywhere else it enters the
// original thunk.  TrackerTick below is the exact mirror of 0x6671A0 with the same native callees; its search call goes through Targets::search so the
// TargetCull lever substitutes its own 0x553420 replacement.  Integer-only: no x87/SSE state is touched.
namespace kntwr_retarget_jitter {
// ai_ctrl_reuse_words[20..23] (published only with the flag):
//  0 tracker_calls  tracker ticks executed by the mirror (one per soldier per tick inside site 6)
//  1 losses         held target invalid this tick (0x6795A0 false while +0x10 != 0)
//  2 jittered       losses whose search was delayed (flag on, cooldown 0, d = agent+0x2C & 0xF != 0)
//  3 delay_sum      sum of the delays d applied (mean delay of a jittered loss = delay_sum / jittered)
constexpr uint32_t kWords = 4;
enum Word : uint32_t { WTrackerCalls, WLosses, WJittered, WDelaySum };
extern volatile uint32_t words[kWords];

constexpr uint32_t kCooldown = 0x14u, kTarget = 0x10u, kSearchKey = 0x0u, kSecondKey = 0x4u, kThirdKey = 0x8u, kFlag = 0xCu;
constexpr uint32_t kAgentUnit = 0x1F0u, kContactList = 0xA80u, kAgentId = 0x2Cu, kJitterMask = 0xFu, kFailCooldown = 0x28u;

struct Targets {
    uint32_t valid;   // 0x6795A0 (thiscall ECX = tracker, stack: agent, ret 4, bool in AL; reads only)
    uint32_t clear;   // 0x63CE00 (thiscall ECX = tracker, plain ret)
    uint32_t search;  // 0x553420 or a replacement with the same ABI (thiscall ECX = contact list, stack: agent, target unit, ret 8, EAX = candidate)
    uint32_t second;  // 0x553220 (same ABI as search; stack: agent, +4)
    uint32_t third;   // 0x6C6910 (thiscall ECX = +8, stack: agent, +0xC byte, ret 8)
    uint32_t assign;  // 0x662960 (thiscall ECX = tracker, stack: target, ret 4)
};
// Arms the mirror; `jitter` false = exact native behaviour (counters of tracker_calls/losses still run).
void Configure(bool jitter, const Targets& targets);
void ResetRow();                       // runtime start: zero the row before any poll of the new session
void Snapshot(volatile uint32_t* out); // out[kWords]
// The 0x6671A0 mirror (fastcall: ECX = tracker, stack: agent, callee pops 4, EAX = +0x10).
uint32_t __fastcall TrackerTick(uint32_t tracker, uint32_t, uint32_t agent);

constexpr uint32_t kVtableSlot = 0x1333E3Cu + 8u, kThunk = 0x66D750u, kStep = 0x676FD0u;
constexpr uint32_t kValid = 0x6795A0u, kClear = 0x63CE00u, kSearch = 0x553420u, kSecond = 0x553220u, kThird = 0x6C6910u, kAssign = 0x662960u;
}
#endif
