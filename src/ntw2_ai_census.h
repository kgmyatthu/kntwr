#ifndef NTW2_AI_CENSUS_H
#define NTW2_AI_CENSUS_H
// NTW2_AI_CENSUS: who runs the AI planner's mutating virtuals, from which tick site and thread class.
//
// Observation only. Vtable-slot gates are published as data-slot swaps by the runtime's ordinary Slot machinery (pinned
// original word, VirtualProtect RW around one interlocked store, protection restored, same Deactivate ordering). A gate
// saves the general-purpose registers and flags, records {target, return address} and tail-jumps to the unchanged original, so the
// callee sees exactly the caller's stack, registers and return address. One more gate is bound into the AI_CONTROLLER clone
// at its two 0x7492F0 calls. Nothing here modifies code bytes.
#include <stdint.h>

namespace ntw2_ai_census {
using U = uint32_t;

constexpr U kVersion = 1;
constexpr U kTargets = 7;
constexpr U kCallers = 256;      // distinct (target, return address) pairs tracked; further pairs only reach per-target totals
constexpr U kTop = 8;            // exported callers per target
constexpr U kClasses = 4;        // 0 tick owner, 1 AI worker, 2 main/render (not tick owner), 3 other
constexpr U kSiteCodes = 113;    // 0 outside tick, 1 inside tick with no timed site, 2+i timed site i (clamped to 112)
constexpr U kRanges = 3;
constexpr U kHeaderWords = 16, kTargetHeaderWords = 8, kCallerWords = 12, kRangeWords = 8;
constexpr U kTargetWords = kTargetHeaderWords + kTop * kCallerWords;
constexpr U kWords = kHeaderWords + kTargets * kTargetWords + kRanges * kRangeWords;

// Header word indices.
enum Header : U {
    HVersion, HTargets, HCallerCapacity, HCallersUsed, HTop, HCalls, HCallersDropped, HSlotsOwned,
    HSlotCount, HRanges, HSampleAttempts, HSampleOutside, HTicks, HCallsInTick, HCallsOutsideTick, HReserved
};
// Target header word indices (row base = kHeaderWords + target * kTargetWords).
enum TargetHeader : U { TOriginal, TSlots, TTotal, TClass0, TClass1, TClass2, TClass3, TDropped };
// Caller row word indices (row base = target base + kTargetHeaderWords + rank * kCallerWords).
// kind 0: caller = RVA in the main image; kind 1: caller = offset inside the AI_CONTROLLER clone (source VA = 0x7C8BD0 + offset,
// the clone has no insertions); kind 2: caller = raw return address.
// Class counts and the two most frequent site counts are separate marginals, not a joint class/site distribution.
// Site attribution is the ambient runtime tick site: a concurrent non-owner thread can observe the owner's active site.
enum Caller : U { CCaller, CKind, CCount, CClass0, CClass1, CClass2, CClass3, CTopSite, CTopSiteCount, COutside, CSecondSite, CSecondSiteCount };

// A pinned vtable slot: the slot address is vtable + 4 * slot (preferred-base VAs) and must hold `original` exactly.
struct Pin { U vtable, slot, original, target; };
constexpr U kPinCount = 12;
// Preferred-base VA of each target's original function (row order of every table).
extern const U kTargetOriginal[kTargets];
const Pin* Pins();
// Preferred-base [va,end) of each EIP sample range.
extern const U kRangeVa[kRanges];
extern const U kRangeEnd[kRanges];

// Clears every table; enabled arms recording. Only with gates unpublished and the sampler stopped.
// tickGate: word holding the tick owner's thread id (0 outside ticks). aiThread: word holding the AI worker's thread id.
// site: word holding timed-site index + 1 inside the tick (0 none), or null.
void Reset(bool enabled, U imageBase, U imageSize, U delta, U mainThread, volatile U* tickGate, volatile U* aiThread,
           volatile U* site);
// Clone arena of AI_CONTROLLER (entry, size) for caller classification; call after the clones are built.
void SetController(U entry, U size);
// Address of the naked gate for a target (published by the slot swap or bound as the clone callee).
U Gate(U target);
// Redirects what target's gate forwards to (default: the original VA + delta set by Reset). Used by --ai-ctrl-* to send the
// AI_CONTROLLER clone's rebuild gate (target 6) to the AI_CTRL_REBUILD clone; counting is unchanged.
void Retarget(U target, U entry);
void Tick();
// Planner-mutator gate calls made by the tick owner (class 0), summed over targets; only the owner increments them.
U OwnerCalls();
// Sampler thread only: classify one runtime-observed EIP (class as for gates).
void Sample(U eip, U cls);
// Publishes the full word block; `slotsOwned` is the runtime's count of census slots currently swapped in.
void Snapshot(volatile U* words, U slotsOwned);
}
#endif
