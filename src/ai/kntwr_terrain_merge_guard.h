#ifndef KNTWR_TERRAIN_MERGE_GUARD_H
#define KNTWR_TERRAIN_MERGE_GUARD_H
#include <stdint.h>

// Fast rejection in front of the terrain-analyser merge predicate FUN_0063B470 (loading-time optimisation, analysis: "Default deployment" pass 0x62C330 spends ~40 s of the
// battle load in this predicate).  ALWAYS ON while the runtime is active (monitor start .. stop); no switch.  Every pair the native code answers is answered bit-identically:
// the guard only answers `false` itself when it can PROVE that the native answer is `false`, every other pair is tail-jumped into the untouched native function.
//
// Native predicate [disassembly of the Steam image, 44880ec1...; callers: ONE call site, 0x62CA2B `call 0x63B470` inside the O(N^2) merge loop of 0x62C330]:
//     thiscall, ECX = record i, stack (record j), `ret 4`, result AL; pure (reads the two records and the float constant [0x1318038] = 0.5, writes only its own frame).
//     if [i+0x24] != [j+0x24] return false;                                // record type dword, compared first
//     each record is an oriented rectangle: centre (+0,+4) = (cx,cy), lengths L0 = +0xC, L1 = +0x10, axis a = (+0x14,+0x18), axis b = (+0x1C,+0x20)
//     the predicate packs 4 edge segments per record (FUN_010D0900 = a plain 16-byte copy of two points), the corner coordinates computed with the float expressions
//     listed in Span() below (SSE single precision, one rounding per operation, the constant h = [0x1318038] = 0.5f);
//     return true  iff  one i-segment equals one j-segment: FUN_00654320 and the two inlined pre-tests compare the four floats with UCOMISS (ZF=1 and PF=0: NaN is never
//                       equal, -0.0 == +0.0), straight or with the two endpoints swapped.  There is no tolerance and no other source of `true`
//                       (the sixteen jumps to `mov al,1` at 0x63BCBC are exactly the 1 + 1 pre-test exits and the 15 FUN_00654320 results).
// Consequence: `true` requires a corner coordinate of i to be float-equal to a corner coordinate of j on BOTH axes.  If the set of every x (or every y) value the native
// code can produce for i lies strictly below the set for j (or the other way round), no equality is possible and the native result is false.  Rejects() evaluates the
// same float expressions (every variant the native code uses for either record, a superset of both roles), takes min/max per axis, and rejects ONLY on strict `<`
// between two ordered ranges; any NaN anywhere (or a non-strict relation, e.g. touching or equal values, signed zeros, infinities meeting) takes the native path.
// The type mismatch rejects exactly as native does.
//
// Mechanism: the 4-byte displacement of the `call rel32` at 0x62CA2B (aligned dword) is replaced by one expected-original interlocked compare-exchange with Entry() as
// target; the opcode stays E8.  The call-site context and the native prologue are pinned byte for byte before the swap and the displacement is read back; Remove restores
// the original displacement when the current one is ours.  The native address is published in `fallback` BEFORE the hook becomes visible and stays valid after Remove,
// so a thread still inside Entry() when the hook is removed finishes through the native function.
namespace kntwr_terrain_merge_guard {
constexpr uint32_t kCallSite = 0x62CA2Bu, kNative = 0x63B470u, kHalf = 0x1318038u;

// Native fallback address (kNative + delta); written before the redirect is installed.  Entry() jumps through it.
extern volatile uint32_t fallback;

uint32_t Entry();                       // address of the guard (naked, thiscall-compatible: ECX = record i, stack (record j), ret 4, result AL)
// Pure decision (stdcall, callee pops 8): 1 iff the native predicate provably returns false for these two records, 0 = ask the native function.
uint32_t __stdcall Rejects(const uint32_t* recordI, const uint32_t* recordJ);

// Call-site redirect; `delta` = image delta from the preferred base.  Install refuses (false, nothing changed) when any pinned byte differs or the displacement is not
// the stock one; Remove is a no-op success without a prior install, succeeds when the stock displacement is already back and refuses a foreign displacement.
bool InstallRedirect(uint32_t delta);
bool RemoveRedirect(uint32_t delta);
}
#endif
