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
// ntw2_status::engage_census_words layout (NTW2_ENGAGE_CENSUS_WORDS = 6832 uint32 words):
//   header 0..30   (Word enum below; floats are stored as IEEE-754 bit patterns, -1.0f = unknown)
//   32..53         HALT dM/range histogram:  [0..19] bins of 0.1 (0.0..2.0), [20] overflow (>= 2.0), [21] dM unknown
//   54..75         HALT dM metres histogram: [0..19] bins of 10 m (0..200), [20] overflow (>= 200 m), [21] dM unknown
//   76..97         FIRE_START dM/range histogram (same layout as the first)
//   98..127        moving-in-range dM/range histogram, 30 bins of 0.05 (0..1.5), every (AI unit, tick) with moving && 0 <= dM < 1.5*range
//   128..157 / 158..187 / 188..217 / 218..247  the same histogram split by [U+0xB34] == 0 / == 1 / == 4 / other
//   31 art_halts, 248 art_fire_starts, 249 trace_samples (total), 250 ever_firing_ai_nonart; 251..255 reserved (zero)
//   256..895       first 32 HALT rows chronologically (20 words each; fill count in header word WFirstCount)
//   896..1535      the 32 deepest HALT rows (smallest dM/range with dM >= 0; unordered; count in WDeepCount)
//   1536..2175     ring of the last 32 events of any type (slot = (event ordinal) % 32; total events in WEventsTotal)
//   2176..2205     "still stands": dM/range of non-artillery AI units that are NOT moving with 0 <= dM < 1.5*range, 30 bins of 0.05
//   2206..2235     same, restricted to units with firing == 1
//   2236..2267     per-class stats, classes 0..7 (others clamp to 7), 4 words each at 2236 + 4*class: [0] unit-ticks (AI units with range > 0 and an enemy), [1] min dC (float
//                  bits, -1 = none), [2] model tick of that minimum, [3] min dM (float bits, -1 = never computed)
//   2268..2331     per-side validation, 2 sides (index [side+0x10], clamped to 0/1) x 32 words at 2268 + 32*side:
//                    [0] side is AI ([side+0xC] != 0), [1] unit-ticks (live units, any class), [2] unit-ticks with is_moving == 1, [3] unit-ticks with is_firing == 1,
//                    [4] max over the run of simultaneously firing units, [5] live units at the last tick, [6] live members at the last tick, [7] firing units at the last tick,
//                    [8..15] unit-ticks by class, [16..23] moving unit-ticks by class, [24..31] firing unit-ticks by class
//   2332..2335     reserved (zero)
//   2336..6431     infantry trace ring: 512 samples x 8 words, slot = (trace_samples) % 512. Every non-artillery AI unit with range > 0 and dC < 3*range+200, on model ticks
//                  with tick % 5 == 0. Words: 0 model tick, 1 unit pointer, 2 dC (float), 3 dM (float, -1 unknown), 4 flags (bit0 moving, bit1 firing, bit2 side (0/1), bit3 AI flag, bit4 vt+0x30 active, bit5 vt+0x2C active, bits 8..15 [U+0xB34] low
//                  byte, bit16 [U+0x930] > 0, bits 17..31 this unit's trace sample count so far, saturating), 5 active command row vtable normalised (0xFFFFFFFF none,
//                  0 null vtable), 6 destD (float, -1 unknown), 7 destEnemyD (float, -1 unknown)
//   6432..6441     "why is firing false": histogram of [F+0x460] (F = [U+0xADC], the ACTIVE FORMATION; bins 0..8, [9] other) for non-artillery units (any side) with range > 0 and
//                  dC < 3*range
//   6442 diag_units, 6443 slot_obj_null (idx 1..8 but [F+0x418+idx*8] == 0), 6444 reject_idx (idx > 8), 6445 slot_obj_insane, 6446 slot_vt_not_image, 6447 slot_target_not_image
//   (the five sub-checks of the 0x55AFE0 pre-validation, counted over the diag units), 6448 firing_calls (0x55AFE0 calls, all units), 6449 firing_true, 6450 slot_vt_other (distinct
//   object-vtable table full), 6451 rowvt_other (distinct row-vtable table full), 6452 row_none ([U+0x930] == 0), 6453 row_bad_idx ([U+0x934] >= 10), 6454 row_vt_rejected
//   6456..6471     object-vtable table, 8 entries x {vtable normalised to the preferred base, count} for obj = [F+0x418+[F+0x460]*8] of the diag units
//   6472..6503     active-row vtable table, 8 entries x {vtable normalised, count while moving, count while not moving, flags}; flags bit0/1 = vt+0x2C returned true/false at least
//                  once, bit2/3 = vt+0x30 true/false, bit4/5 = vt+0x28 true/false (ECX = row)
//   6512..6831     per-side blocks, 2 x 160 words at 6512 + 160*side (side = [side+0x10] clamped to 0/1; EVERY side is observed, the AI flag is only a field):
//                    [0..21] HALT dM/range hist (as 32..53), [22..43] FIRE_START hist, [44..73] moving-in-range hist (30 x 0.05), [74..103] still-stands hist, [104..133] still-stands
//                    firing hist, [134] halts, [135] fire_starts, [136] atk30 events (type 3, within reach), [137] atk2C events (type 4, within reach), [138] atk30 transitions at any
//                    distance, [139] atk2C transitions at any distance, [140] distinct units ever firing (non-artillery), [141] distinct units ever atk30 active, [142] distinct units
//                    ever atk2C active, [143] raw [side+0x10] (last seen), [144] AI flag ([side+0xC] != 0), [145] observed unit-ticks (non-artillery, range > 0, an enemy exists)
//   6504..6511     reserved (zero)
//   row words (20): 0 model tick, 1 unit pointer, 2 type (1 HALT, 2 FIRE_START, 3 ATTACK30 = vt+0x30 (missile attack order active) false -> true, 4 ATTACK2C = vt+0x2C (melee attack order active) false -> true), 3 dC (float bits), 4 dM (float bits, -1 unknown), 5 dMe (float bits, -1 unknown),
//                   6 range (float bits), 7 [U+0xB34], 8 [U+0x930], 9 [U+0x934], 10 active command row vtable normalised to the preferred base (0xFFFFFFFF = index out of
//                   range, 0 = null vtable), 11 unit class, 12 member count, 13 ticks stopped before the event (saturating), 14 nearest enemy unit pointer, 15 side index,
//                   16 destD = |unit centre - active-row destination| (float bits, -1 unknown), 17 destEnemyD = |destination - nearest enemy unit centre| (-1 unknown),
//                   18 flags: bit0 row vtable+0x2C predicate AL (melee attack order active), bit1 vtable+0x30 predicate AL (missile attack order active), bit2 destination
//                   valid, bit3 vt+0x28 (moving fast); 19 = AI flag of the side | (side index clamped to 0/1) << 1.  Destination (0x844F70): row = U+0x398+0x90*[U+0x934] (only if [U+0x930] != 0), pose = row.vtable[+0x38](), vec3 = 0x80E9D0(ECX = pose,
//                   one stack argument = out buffer, callee pops 4) -> x at [0], z at [8]
namespace ntw2_engage_census {
constexpr uint32_t kWords = 6832, kVersion = 3;
constexpr uint32_t kHistBins = 20, kHistWords = 22, kMovingBins = 30;
constexpr uint32_t kHaltRatio = 32, kHaltMetres = 54, kFireRatio = 76, kMovingAll = 98, kMovingB0 = 128, kMovingB1 = 158, kMovingB4 = 188, kMovingOther = 218;
constexpr uint32_t kRowWords = 20, kRowsPerSet = 32, kFirstRows = 256, kDeepRows = 896, kRingRows = 1536;
constexpr uint32_t kStillAll = 2176, kStillFiring = 2206, kClassStats = 2236, kSideVal = 2268, kSideWords = 32, kTrace = 2336, kTraceWords = 8, kTraceRows = 512, kTraceEvery = 5;
constexpr uint32_t kFIdxHist = 6432, kDiagUnits = 6442, kObjVt = 6456, kRowVt = 6472, kSideDiag = 6512, kSideDiagWords = 160;
enum Word : uint32_t {
    WVersion, WFlags, WTicks, WAiUnits, WHalts, WFireStarts, WFaults, WBadMember, WEnemyless, WTableFull, WNativeCalls, WCostUsTotal, WCostUsMax, WLastModelTick,
    WAiSidesLast, WAiUnitsLast, WEnemyUnitsLast, WDmComputed, WMovingInRange, WInactiveUnits, WNoMissile, WBadGraph, WTableUsed, WFirstCount, WDeepCount,
    WEventsTotal, WModelChanges, WDelta, WNativeSkipped, WFaultsPerUnit, WBattleFaults,
    WArtHalts, WArtFireStarts = 248, WTraceSamples = 249, WEverFiring = 250, WAtk30Events = 251, WAtk2CEvents = 252,
    DSlotObjNull = 6443, DRejectIdx = 6444, DSlotObjInsane = 6445, DSlotVtNotImage = 6446, DSlotTargetNotImage = 6447, DFiringCalls = 6448, DFiringTrue = 6449, DSlotVtOther = 6450,
    DRowVtOther = 6451, DRowNone = 6452, DRowBadIdx = 6453, DRowVtRejected = 6454
};
// Per-side block offsets (relative to kSideDiag + kSideDiagWords * side).
enum SideWord : uint32_t { SdHaltHist = 0, SdFireHist = 22, SdMoving = 44, SdStill = 74, SdStillFiring = 104, SdHalts = 134, SdFires = 135, SdAtk30 = 136, SdAtk2C = 137, SdAtk30All = 138,
                           SdAtk2CAll = 139, SdEverFiring = 140, SdEverAtk30 = 141, SdEverAtk2C = 142, SdRawSide = 143, SdAi = 144, SdObserved = 145 };
// Artillery is class [[U+0x2C]+0x1C] == 1 (not infantry as the first spec assumed): it is excluded from WHalts/WFireStarts, every histogram and every row, and counted in
// WArtHalts/WArtFireStarts (same event definitions). WEverFiring: distinct unit-table entries of AI-side non-artillery units that were firing at least once (an entry unseen
// for 600 ticks is recycled, so a unit may count again).
// Every side is observed (AI flag is a field only): WAiUnits / WHalts / WFireStarts / histograms and WEverFiring cover units of both sides; the per-side blocks split them.
// WAtk30Events / WAtk2CEvents: type-3/4 events (within reach, as HALT).
// 0x55AFE0 is called with ECX = the FORMATION [U+0xADC] (0x57ECA0 'firing' branch), not the unit.
// WFlags: bit0 armed (Reset with enabled), bit1 disabled by a fault for the current battle model.
// Counter meanings: WTicks ticks observed; WAiUnits sum over ticks of AI units with missile range > 0 and members > 0; WHalts/WFireStarts events; WFaults SEH faults;
// WBadMember member/centre coordinates non-finite or |v| >= 16384 (the member/unit is skipped); WEnemyless ticks with an AI unit in range-eligible state but no enemy unit;
// WTableFull unit-state table (or per-tick scratch) overflow drops; WNativeCalls native predicate calls; WCostUsTotal/WCostUsMax census microseconds total/max per tick;
// WLastModelTick model tick of the last observed tick; WAiSidesLast/WAiUnitsLast/WEnemyUnitsLast last tick's AI sides, eligible AI units and enemy units;
// WDmComputed unit-ticks whose dM was computed (dC < 4*range+100); WMovingInRange samples added to the moving histograms; WInactiveUnits unit-ticks skipped by the
// liveness test; WNoMissile AI unit-ticks with range <= 0; WBadGraph object-graph reads rejected (counts/pointers out of range); WTableUsed occupied table entries;
// WModelChanges battle model changes seen; WDelta image delta from the preferred base; WNativeSkipped unit-ticks (or command rows) where pre-validation of what a native
// predicate dereferences failed, so the native function was NOT called; WFaultsPerUnit SEH faults caught around a single unit (the unit is skipped for the tick, the
// census stays armed); WBattleFaults faults in the current battle model (the census disables itself, flag bit1, once it exceeds 64; WFaults is the all-battles total
// and also counts graph-walk faults, which skip the tick).

// Zero the row and arm/disarm the census.  `delta` = image delta from the preferred base (V(va) = va + delta); [imageBase, imageBase+imageSize) is the live main image (vtable / slot-target validation).
void Reset(bool enabled, uint32_t delta, uint32_t imageBase, uint32_t imageSize);
// Owner thread, right after the native private tick returned.  `model` = tick gate argument, `modelTick` = [model+0x58].
void Tick(uint32_t model, uint32_t modelTick);
void Snapshot(volatile uint32_t* out);  // out[kWords]
}
#endif
