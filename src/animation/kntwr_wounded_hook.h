// --wounded runtime hook (gameplay change via kntwr_config::gameplay_flags & KNTWR_WOUNDED + percent in KNTWR_WOUNDED_PCT_MASK;
// EXPERIMENTAL opt-in, NOT implied by --features all). Policy: animation/kntwr_wounded.h. Evidence: analysis/FINDINGS.md
// "Wounded/corpse animation infrastructure census" (2026-10-31).
//
// Native site 0x653F1A (inside kill path 0x653A10; ECX = normalized death category, EBP = man anim FSM M): stock bytes
//   8B 15 C8 21 45 01     mov edx, [0x14521C8]
//   3B CA                 cmp ecx, edx
// are 8 bytes of COMPLETE displaced instructions - exactly one Swap8 window. The gate does NOT replay them: the host
// Decide() recomputes the whole state select (stock range test -> native 0x4B; else FACE-tagged clip + roll -> maybe 0x4B,
// default 0x2A), the gate writes the state into the saved-EAX slot and EDX = [0x14521C8 relocated] into the saved-EDX slot
// of its pushad frame (replicating the registers native code leaves at the resume point), and jumps g_resume = site+0x1F
// (0x653F39 relocated, the `mov [ebp+0x1B8], eax` state store). The bypassed stock select 0x653F22..0x653F38 becomes dead
// code while installed and is restored bit-exactly by Remove.
//
// Thread-freeze / interior-IP refusal / 8-byte CAS policy is the shared core/kntwr_entry_patch.h. Remove refuses while any
// peer is inside the gate (EIP range or in-gate counter); a CAS mismatch writes NOTHING and reports failure.
#ifndef KNTWR_WOUNDED_HOOK_H
#define KNTWR_WOUNDED_HOOK_H
#include <stdint.h>

namespace kntwr_wounded_hook {
using U = uint32_t;

// wounded_words (kntwr_status::wounded_words, KNTWR_WOUNDED_LABELS). Hot-path counters are plain ++; reset at monitor start.
// WInstalled is sticky applied-this-run (set on a successful Install, cleared only by ResetRow), not live hook presence.
constexpr U kWords = 16, kVersion = 1;
constexpr U kCommitSite = 0x653F1Au;
enum Word : U {
    WVersion, WRequested, WInstalled, WCalls, WNativeKnockdown, WStaticCandidates, WEligible, WFlipped,
    WDeniedRoll, WUntagged, WNoClip, WFaults, WLastCat
};

void ResetRow();                        // monitor start: zero the row (including applied-this-run), set the version
void Snapshot(volatile U* out);         // out[kWords]; word 2 = applied this run
// `imageBase` = runtime load base of Napoleon.exe; `pct` = flip probability 1..100. True when the detour is in place.
bool Install(U imageBase, U pct);
bool Remove();                          // restores the 8 stock bytes; false if the bytes are not ours (module must stay loaded)
bool Installed();
} // namespace kntwr_wounded_hook
#endif
