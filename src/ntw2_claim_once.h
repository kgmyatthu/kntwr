#ifndef NTW2_CLAIM_ONCE_H
#define NTW2_CLAIM_ONCE_H
#include <stdint.h>

// --ai-claim-once (ntw2_config::ai_ctrl_flags bit 8): one 0x82F3A0 placement recompute per fallback claim call instead of one per claimed
// unit (analysis/native-ai-claim-once.md).  AI-ONLY GAMEPLAY DEVIATION (user-approved): the placement score the controller publishes
// (+0x720 / +0x758) is no longer recomputed after every claimed unit of one think, only after the last one.  Every unit is still claimed
// in the same think, exactly as native, so no unit is ever left without an owner/order across a tick boundary.  (The earlier
// --ai-claim-chunk N variant, which deferred claims to later ticks, was retired: a deferred unit has no owner and therefore no order.)
//
// Native structure [proven by disasm]:
//   0x7524A0(obs, L): for each L row with row+8 == 0, !0x55AB90(unit), unit+0xB34 != 8 -> 0x74F430(obs, row, ctrl = obs+0x78); then
//   0x84B1D0(ctrl, 0).  0x74F430 = 0x74F400 (detach from the old observer, append to obs, row+8 = 1) + [ctrl]->vt+0x70 = 0x826E80(ctrl, unit):
//   unit+0xB34 in {6,7} -> return; membership append (0x69F860/0x483D40), planner (0x7CF3A0/0x7D9130), delegate rebuild (0x576220), unit+0xB30 = ctrl,
//   EAX = 0x82F3A0(ctrl, 30.0f) -> ctrl+0x758, and once (latch ctrl+0x75D) 0x5D9A20(ctrl).
//   0x82F3A0 [proven]: copies membership, 64-heading sweep, 20-slot heading-history ring (+0x6B4/+0x704/+0x708/+0x6B0), THEN the memo gate:
//   !0x55AD60([[[ctrl+8]+8]+0xB0]) && last != 0 && last != tick && last + 10 >= tick (last = ctrl+0x724, tick = [[[ctrl+8]+8]+0x58]) returns the
//   cached ctrl+0x720 without writing anything; otherwise ctrl+0x724 = tick and the placement query (ladder/spiral/polygon walks) runs, ctrl+0x720 = result.
//
// Mechanism: the memo gate is native, so a recompute is skipped by letting the native gate see a valid memo.  For a claimed unit that is NOT
// the last one that would run the tail (unit state not 6/7, a later row still eligible and tailing), when native would recompute (last == 0,
// last == tick or last + 10 < tick), the host writes ctrl+0x724 = tick-1 before 0x74F430 (a valid memo, not written by the hit path) and restores the
// original value before the last tailing unit (or at the end of the call).  Everything else is native: the heading ring still advances once per
// entry, membership/planner/delegate rebuild/backlinks/latch are untouched, the last entry runs the native recompute with the full membership and
// leaves ctrl+0x724/+0x720/+0x758 exactly as native's last entry would.  Masking is refused (native path) while 0x55AD60 is true (the gate cannot
// hit), while the first-use latch ctrl+0x75D is unset (0x5D9A20 runs after the first 0x82F3A0) and when the tick cannot be read.
//
// The gate is the vtable slot 0x1343318+0x40; it acts only on the thread executing the site-34 planner update (Targets::scope) and only when `list` is the
// working list 0x150F6A4 of the child pass.  The loop is a host mirror of 0x7524A0 with the same native callees, `[L+8]` re-read every iteration
// and the post-loop 0x84B1D0 once.  Integer-only: no x87/SSE state is touched.
namespace ntw2_claim_once {
// ai_ctrl_reuse_words[24..31] (NTW2_AI_CTRL_REUSE_LABELS "claim_*"):
//  0 calls         gated calls
//  1 entries       units claimed (0x74F430 calls)
//  2 masked        entries whose direct recompute was masked (0 in census mode)
//  3 calls_masked  calls with >= 1 masked entry
//  4 refused_state masking wanted but 0x55AD60 is true (the memo gate cannot hit)
//  5 refused_other masking wanted but the first-use latch is unset or the tick is unreadable
//  6 packed        bits 0..7 largest E of one call (saturating), bits 8..15 calls that masked entries but whose predicted last tailing entry
//                  did not run (the controller kept its previous score; saturating), bits 16..31 calls folded into the hash
//  7 hash          FNV-1a over the controller state at the end of the first kHashCalls calls with E >= 2: E, heading +0x6B0 (u16), ring index +0x704,
//                  ring sum +0x708, score cache +0x720, memo tick +0x724, published score +0x758 (read after the claim loop, before 0x84B1D0)
// Census mode (--ai-claim-once-census) runs the same loop WITHOUT masking and publishes the same hash: native and once runs of the same replay
// (the sim trajectory is deterministic; the claim calls are identical while the AI state is) can be compared hash against hash for the first
// kHashCalls multi-entry calls, a bit-exact check of every controller output the later code can read.
constexpr uint32_t kWords = 8;
enum Word : uint32_t { WCalls, WEntries, WMasked, WCallsMasked, WRefusedState, WRefusedOther, WPacked, WHash };
extern volatile uint32_t words[kWords];
constexpr uint32_t kHashCalls = 3000;
enum Mode : uint32_t { ModeOff, ModeOnce, ModeCensus };

constexpr uint32_t kWorkingList = 0x150F6A4u; // preferred-base address of the child pass's list L (relocated by the runtime)

struct Targets {
    uint32_t native;    // original 0x7524A0 (thiscall, one stack argument, ret 4)
    uint32_t eligible;  // 0x55AB90 (thiscall ECX = unit, bool in AL, pure getter)
    uint32_t claim;     // 0x74F430 (thiscall ECX = observer, stack: row, controller; ret 8)
    uint32_t post;      // 0x84B1D0 (thiscall ECX = controller, stack: 0; ret 4)
    uint32_t memoState; // 0x55AD60 (thiscall ECX = state object, bool in AL, pure getter)
    uint32_t list;      // relocated 0x150F6A4
    bool (*scope)(uint32_t tid); // thread executing the site-34 planner update
};
// Resets the row. ModeOff leaves the gate forwarding (nothing counted).
void Configure(Mode mode, const Targets& targets);
void ResetRow(); // runtime start: zero the row before any poll of the new session
void Snapshot(volatile uint32_t* out); // out[kWords]

uint32_t __fastcall Gate(uint32_t self, uint32_t, uint32_t list);

constexpr uint32_t kFallbackSlot = 0x1343318u + 4u * 16u, kFallbackOriginal = 0x7524A0u;
constexpr uint32_t kEligible = 0x55AB90u, kClaim = 0x74F430u, kPost = 0x84B1D0u, kMemoState = 0x55AD60u;
}
#endif
