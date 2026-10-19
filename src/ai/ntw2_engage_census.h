#ifndef NTW2_ENGAGE_CENSUS_H
#define NTW2_ENGAGE_CENSUS_H
#include <stdint.h>

// --engage-census (ntw2_config::va_watch_flags NTW2_ENGAGE_CENSUS, launcher --engage-census): READ-ONLY diagnostic that measures how deep AI-side infantry walk into
// their own missile range before they stop moving (HALT) or start firing (FIRE_START).  Opt-in, never implied by --features all, no engine write, no engine order or
// state change.  The census runs on the tick-owner thread inside TickGate, right after the native private tick returned and the tick bookkeeping is published
// (so its cost is not part of the recorded tick body duration); the whole body is one SEH bracket (a fault is counted and the census stays off until the next battle
// model).  Native engine functions are only CALLED (thiscall, ECX = unit, never hooked): 0x55C320 is_moving (AL), 0x55AFE0 is_firing (AL == 1), 0x5646A0 missile range
// (float in ST0, metres, 0 when the unit cannot shoot).
//
// Engine facts (preferred-base VAs of image 13fcab62, read from disassembly through REA/Ghidra):
//   model -> M = [model+0xB0]; sides: count [M+0x84], pointer array [M+0x88] (0x5832C0); side: [side+0xC] AI commander (NULL for a human side), [side+0x10] side index,
//   armies count [side+0x20] / array [side+0x24] (0x580320); army: units count [army+0xF0] / array [army+0xF4] (0x580390); model tick [model+0x58].
//   unit U: formation F = [U+0xADC], oriented-box centre x,z = [F+0x644],[F+0x648] and formation radius [F+0x670] (0x539D80/0x563C00/0x5821B0); members count
//   [U+0x2CC] / array [U+0x2D0], member position x,z = [m+0x48],[m+0x50] (0x5857A0); class [[U+0x2C]+0x1C] (1 = infantry, 0x55AB90/0x55C230); liveness
//   0x55CB50 = [U+0xAA0] != 2 && [U+0x2CC] > 0; AI state [U+0xB34]; command ring: count [U+0x930], index [U+0x934], rows of 0x90 bytes at U+0x398+0x90*idx, row[0] = vtable.
//
// ntw2_status::engage_census_words layout (NTW2_ENGAGE_CENSUS_WORDS = 2176 uint32 words):
//   header 0..31   (Word enum below; floats are stored as IEEE-754 bit patterns, -1.0f = unknown)
//   32..53         HALT dM/range histogram:  [0..19] bins of 0.1 (0.0..2.0), [20] overflow (>= 2.0), [21] dM unknown
//   54..75         HALT dM metres histogram: [0..19] bins of 10 m (0..200), [20] overflow (>= 200 m), [21] dM unknown
//   76..97         FIRE_START dM/range histogram (same layout as the first)
//   98..127        moving-in-range dM/range histogram, 30 bins of 0.05 (0..1.5), every (AI unit, tick) with moving && 0 <= dM < 1.5*range
//   128..157 / 158..187 / 188..217 / 218..247  the same histogram split by [U+0xB34] == 0 / == 1 / == 4 / other
//   248..255       reserved (zero)
//   256..895       first 32 HALT rows chronologically (20 words each; fill count in header word WFirstCount)
//   896..1535      the 32 deepest HALT rows (smallest dM/range with dM >= 0; unordered; count in WDeepCount)
//   1536..2175     ring of the last 32 events of any type (slot = (event ordinal) % 32; total events in WEventsTotal)
//   row words (20): 0 model tick, 1 unit pointer, 2 type (1 HALT, 2 FIRE_START), 3 dC (float bits), 4 dM (float bits, -1 unknown), 5 dMe (float bits, -1 unknown),
//                   6 range (float bits), 7 [U+0xB34], 8 [U+0x930], 9 [U+0x934], 10 active command row vtable normalised to the preferred base (0xFFFFFFFF = index out of
//                   range, 0 = null vtable), 11 unit class, 12 member count, 13 ticks stopped before the event (saturating), 14 nearest enemy unit pointer, 15 side index,
//                   16 destD = |unit centre - active-row destination| (float bits, -1 unknown), 17 destEnemyD = |destination - nearest enemy unit centre| (-1 unknown),
//                   18 flags: bit0 row vtable+0x2C predicate AL (melee attack order active), bit1 vtable+0x30 predicate AL (missile attack order active), bit2 destination
//                   valid; 19 reserved (0).  Destination (0x844F70): row = U+0x398+0x90*[U+0x934] (only if [U+0x930] != 0), pose = row.vtable[+0x38](), vec3 = 0x80E9D0(ECX = pose,
//                   one stack argument = out buffer, callee pops 4) -> x at [0], z at [8]
namespace ntw2_engage_census {
constexpr uint32_t kWords = 2176, kVersion = 1;
constexpr uint32_t kHistBins = 20, kHistWords = 22, kMovingBins = 30;
constexpr uint32_t kHaltRatio = 32, kHaltMetres = 54, kFireRatio = 76, kMovingAll = 98, kMovingB0 = 128, kMovingB1 = 158, kMovingB4 = 188, kMovingOther = 218;
constexpr uint32_t kRowWords = 20, kRowsPerSet = 32, kFirstRows = 256, kDeepRows = 896, kRingRows = 1536;
enum Word : uint32_t {
    WVersion, WFlags, WTicks, WAiUnits, WHalts, WFireStarts, WFaults, WBadMember, WEnemyless, WTableFull, WNativeCalls, WCostUsTotal, WCostUsMax, WLastModelTick,
    WAiSidesLast, WAiUnitsLast, WEnemyUnitsLast, WDmComputed, WMovingInRange, WInactiveUnits, WNoMissile, WBadGraph, WTableUsed, WFirstCount, WDeepCount,
    WEventsTotal, WModelChanges, WDelta
};
// WFlags: bit0 armed (Reset with enabled), bit1 disabled by a fault for the current battle model.
// Counter meanings: WTicks ticks observed; WAiUnits sum over ticks of AI units with missile range > 0 and members > 0; WHalts/WFireStarts events; WFaults SEH faults;
// WBadMember member/centre coordinates non-finite or |v| >= 16384 (the member/unit is skipped); WEnemyless ticks with an AI unit in range-eligible state but no enemy unit;
// WTableFull unit-state table (or per-tick scratch) overflow drops; WNativeCalls native predicate calls; WCostUsTotal/WCostUsMax census microseconds total/max per tick;
// WLastModelTick model tick of the last observed tick; WAiSidesLast/WAiUnitsLast/WEnemyUnitsLast last tick's AI sides, eligible AI units and enemy units;
// WDmComputed unit-ticks whose dM was computed (dC < 4*range+100); WMovingInRange samples added to the moving histograms; WInactiveUnits unit-ticks skipped by the
// liveness test; WNoMissile AI unit-ticks with range <= 0; WBadGraph object-graph reads rejected (counts/pointers out of range); WTableUsed occupied table entries;
// WModelChanges battle model changes seen; WDelta image delta from the preferred base.

// Zero the row and arm/disarm the census.  `delta` = image delta from the preferred base (V(va) = va + delta).
void Reset(bool enabled, uint32_t delta);
// Owner thread, right after the native private tick returned.  `model` = tick gate argument, `modelTick` = [model+0x58].
void Tick(uint32_t model, uint32_t modelTick);
void Snapshot(volatile uint32_t* out);  // out[kWords]
}
#endif
