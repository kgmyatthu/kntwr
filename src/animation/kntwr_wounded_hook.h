// --wounded runtime hook (gameplay change via kntwr_config::gameplay_flags & KNTWR_WOUNDED + percent in KNTWR_WOUNDED_PCT_MASK;
// GAMEPLAY feature, implied by --features all unless --no-wounded). Policy: animation/kntwr_wounded.h. Evidence: analysis/FINDINGS.md
// "Wounded/corpse animation infrastructure census" (2026-10-31) and "--wounded crash at 0x121EAC0" (2026-11-01).
//
// Site A 0x653F1A (inside kill path 0x653A10; ECX = normalized death category, EBP = man anim FSM M): stock bytes
//   8B 15 C8 21 45 01     mov edx, [0x14521C8]
//   3B CA                 cmp ecx, edx
// are 8 bytes of COMPLETE displaced instructions - exactly one Swap8 window. The gate does NOT replay them: the host
// Decide() recomputes the whole state select (stock range test -> native 0x4B; else FACE-tagged clip + roll -> maybe 0x4B,
// default 0x2A), the gate writes the state into the saved-EAX slot and EDX = [0x14521C8 relocated] into the saved-EDX slot
// of its pushad frame (replicating the registers native code leaves at the resume point), and jumps g_resume = site+0x1F
// (0x653F39 relocated, the `mov [ebp+0x1B8], eax` state store). The bypassed stock select 0x653F22..0x653F38 becomes dead
// code while installed and is restored bit-exactly by Remove.
//
// Site B 0xE61020 (unique-clip builder entry, thiscall ECX = anim table; runs at animation-table load): the 8-byte
// prologue 83 EC 08 / 56 / 8B F1 / 33 C9 is displaced; the gate identity-writes the render pose-category remap
// [table+0x3C] for 0x330..0x33C BEFORE the builder's passes assign sampler slots, FACE-tags untagged men death clips
// (categories 0x293..0x311) from the generated orientation table (kntwr_wounded_orient.h, hashed clip path) so the
// wounded FSM can accept them, replays the prologue and resumes at site+8. Install patches both sites or neither;
// Remove restores site B first (remaining flips only freeze - safe).
//
// Thread-freeze / interior-IP refusal / 8-byte CAS policy is the shared core/kntwr_entry_patch.h. Remove refuses while any
// peer is inside either gate (EIP range or in-gate counter); a CAS mismatch writes NOTHING and reports failure.
#ifndef KNTWR_WOUNDED_HOOK_H
#define KNTWR_WOUNDED_HOOK_H
#include <stdint.h>

namespace kntwr_wounded_hook {
using U = uint32_t;

// wounded_words (kntwr_status::wounded_words, KNTWR_WOUNDED_LABELS). Hot-path counters are plain ++; reset at monitor start.
// WInstalled is sticky applied-this-run (set on a successful Install, cleared only by ResetRow), not live hook presence.
// WRemapFixes counts render pose-remap tables repaired (see hook .cpp: [table+0x3C] identity for wounded categories).
// WOrientTagged counts death clips FACE-tagged at table build from the orientation table (idempotent: presence bytes already set are left alone).
constexpr U kWords = 16, kVersion = 1;
constexpr U kCommitSite = 0x653F1Au;
enum Word : U {
    WVersion, WRequested, WInstalled, WCalls, WNativeKnockdown, WStaticCandidates, WEligible, WFlipped,
    WDeniedRoll, WUntagged, WNoClip, WFaults, WLastCat, WRemapFixes, WOrientTagged
};

void ResetRow();                        // monitor start: zero the row (including applied-this-run), set the version
void Snapshot(volatile U* out);         // out[kWords]; word 2 = applied this run
// `imageBase` = runtime load base of Napoleon.exe; `pct` = flip probability 1..100. True when the detour is in place.
bool Install(U imageBase, U pct);
bool Remove();                          // restores the 8 stock bytes; false if the bytes are not ours (module must stay loaded)
bool Installed();
} // namespace kntwr_wounded_hook
#endif
