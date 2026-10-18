#ifndef NTW2_CLAIM_CHUNK_H
#define NTW2_CLAIM_CHUNK_H
#include <stdint.h>

// --ai-claim-chunk N (ntw2_config::ai_ctrl_flags bits 8..15): the fallback strategy observer's claim loop (analysis/native-ai-claim-chunk.md).
// AI-ONLY GAMEPLAY DEVIATION (user-approved): when a planner think's fallback claim would take E > N eligible entries, only the first N are
// claimed; the other E - N stay unassigned and are offered again by the next think of the same child.
//
// Native structure [proven by disasm]: child pass 0x751800 builds the working list L = 0x150F6A4 (cap/count/data +4/+8/+0xC; 12-byte records
// {unit*, oldObserver*, assigned:u8}) as a COPY of the child's unassigned second-list rows (0x7518AA..0x751999), lets the strategy
// observers claim from it, then calls the fallback observer's slot +0x40 = 0x7524A0(obs, L) at 0x751E55 and reconciles L back into the
// child's real rows with 0x7D5AF0 (0x751E64), which writes row+8 = 1 / row+4 = observer ONLY for L records whose assigned byte is set.
// 0x7524A0 is `for (i = 0; i < [L+8]; ++i) { row = [L+0xC] + 12 i; if (row[8] == 0 && !0x55AB90(row->unit) && row->unit[0xB34] != 8)
// 0x74F430(obs, row, obs+0x78); } 0x84B1D0(obs+0x78, 0);` (count and data are reloaded every iteration). An unclaimed record therefore keeps
// assigned == 0 in the child's own row, exactly like the rows that native skips for unit state 8 / 0x55AB90, and the next 0x751800 pass
// copies it into L again. Every think of the planner node calls its child (0x7D99F0 -> 0x7D7BF0 -> child +0x28 -> 0x751800) once per
// site-34 call (measured 4477 fallback calls in 4477 think scopes on perf bad; one think on every tick from the first one on), so the
// continuation seam is the child's NEXT native pass: no private pending list, no extra entry point, no lifetime or revalidation hazard of
// its own (the native pass filters dead/ineligible rows with 0x55AB80, row+8, 0x55AB90 and unit+0xB34 exactly as for any row).
//
// Chunk path: a host re-implementation of the 0x7524A0 loop that calls the same native 0x55AB90 / 0x74F430 / 0x84B1D0 (integer-only, no
// x87/SSE state touched), claims the first N eligible entries, only counts the rest (0x55AB90 is a pure getter) and runs the post-loop
// 0x84B1D0 once, as native does after every call. With E <= N it performs exactly the native call sequence. The gate is the vtable slot
// 0x1343318+0x40; it chunks only on the thread executing the site-34 planner update (Targets::scope) and only when `list` is the working
// list 0x150F6A4 of the child pass; every other call is forwarded to the original.
//
// Counters (bookkeeping only; behaviour never depends on them) track the deferred entries per observer in a bounded table (kObservers x
// kPending unit pointers) to measure the continuation: entries deferred by the cap and later claimed (continuation claims) or no longer
// claimable by the fallback (revalidation drops: claimed by a strategy observer, state 8, unit gone from L, ...).
namespace ntw2_claim_chunk {
// ai_ctrl_reuse_words[24..31] (NTW2_AI_CTRL_REUSE_LABELS "claim_*"):
//  0 calls      gated chunk-path calls
//  1 claimed    entries claimed in the call that first saw them (direct claims)
//  2 deferred   distinct entries left unclaimed by the cap (entries_seen = claimed + deferred)
//  3 continuations        chunk-path calls that started with >= 1 pending entry of the same observer
//  4 continuation_claims  pending entries claimed by a later call
//  5 drops      pending entries that were not claimable any more at the next call (or lost with an evicted observer record)
//  6 untracked  deferred entries that did not fit the bounded table (counted in `deferred`, never resolved)
//  7 packed     bits 0..7 max pending entries of one observer after a call, bits 8..23 max ticks from first deferral to claim/drop
//               (saturating), bits 24..31 chunk size N
// pending at the end of the run = deferred - continuation_claims - drops - untracked.
constexpr uint32_t kWords = 8;
enum Word : uint32_t { WCalls, WClaimed, WDeferred, WContinuations, WContinuationClaims, WDrops, WUntracked, WPacked };
extern volatile uint32_t words[kWords];

constexpr uint32_t kMaxChunk = 255;
constexpr uint32_t kObservers = 8, kPending = 64;
constexpr uint32_t kWorkingList = 0x150F6A4u; // preferred-base address of the child pass's list L (relocated by the runtime)

struct Targets {
    uint32_t native;   // original 0x7524A0 (thiscall, one stack argument, ret 4)
    uint32_t eligible; // 0x55AB90 (thiscall ECX = unit, no stack argument, bool in AL, pure getter)
    uint32_t claim;    // 0x74F430 (thiscall ECX = observer, stack: row, controller; ret 8)
    uint32_t post;     // 0x84B1D0 (thiscall ECX = controller, stack: 0; ret 4)
    uint32_t list;     // relocated 0x150F6A4
    bool (*scope)(uint32_t tid); // thread executing the site-34 planner update
};
// Resets the row and the pending table. chunk = 0 leaves the gate forwarding (nothing counted).
void Configure(uint32_t chunk, const Targets& targets);
// Runtime start: zero the row before any poll of the new session.
void ResetRow();
void Snapshot(volatile uint32_t* out); // out[kWords]

uint32_t __fastcall Gate(uint32_t self, uint32_t, uint32_t list);

// Fallback fallback slot / original (the same slot --ai-spiral-census gates).
constexpr uint32_t kFallbackSlot = 0x1343318u + 4u * 16u, kFallbackOriginal = 0x7524A0u;
constexpr uint32_t kEligible = 0x55AB90u, kClaim = 0x74F430u, kPost = 0x84B1D0u;
}
#endif
