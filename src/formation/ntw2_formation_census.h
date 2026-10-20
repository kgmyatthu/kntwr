#ifndef NTW2_FORMATION_CENSUS_H
#define NTW2_FORMATION_CENSUS_H
#include <stdint.h>

// --formation-census (ntw2_config::va_watch_flags NTW2_FORMATION_CENSUS, launcher --formation-census[=EVERY] --formation-census-csv FILE): opt-in diagnostic that
// measures, for every live unit of both alliances every EVERY model ticks (default 30), how tightly the men stand relative to the formation the engine wants them
// in.  It runs on the tick-owner thread inside TickGate right after the routed native tick returned (like ntw2_engage_census), the whole per-unit body is one SEH
// bracket (a fault is counted; after 64 faults in one battle model the census stays off until the next model).  No engine state is written.  The only native code
// that is CALLED is exactly what the engine itself calls when a formation command refreshes its slots (src/formation/native_formation_slot.h):
//   layout->vtable[+0x24](out, container, f, men)   thiscall, ret 0x10: the slot GENERATOR (0x62FD60 line layout), filling a 36-byte-record vector `out`
//   0x80E9D0(ECX = record+4, out[3])                 thiscall, ret 4: slot position object -> world x,y,z
//   0xFF7EF0(out.data)                               cdecl: frees the generator vector
// Slots are generated only when the active command of the formation is one of the six formation-command classes whose execute slot is 0x581200 (the same gate the
// formation batch uses: vtables 0x13239B0..0x1323AF0, step 0x40; [cmd+4] == formation, container [cmd+0x18], f [cmd+0x1C]); otherwise the row carries nslots = 0.
// 0x55C320 (is_moving) is called after the same pre-validation as ntw2_engage_census.
//
// Engine facts (preferred-base VAs of image 13fcab62; verified against the stock image for every field outside the patch runs):
//   model -> M = [model+0xB0]; sides: count [M+0x84], array [M+0x88]; side: [side+0xC] AI commander (NULL for a human side), [side+0x10] side index,
//   armies [side+0x20]/[side+0x24]; army: units [army+0xF0]/[army+0xF4]; unit U: members [U+0x2CC], liveness [U+0xAA0] != 2, class [[U+0x2C]+0x1C],
//   spacing base [U+0x2F8]/[U+0x2FC] (= 2 x max member radius), AI state [U+0xB34], formation list [U+0xACC]/[U+0xAD0], main formation [U+0xADC],
//   selector [U+0xAE8] (0: main, 1/2: [U+0xADC+4*sel]);  formation F (vtable 0x13211D8 infantry): men [F+0x18] / man array [F+0x1C] (man k <-> slot k after
//   0x555CA0), queued commands count [F+0x460], command i at [F+0x420+8*i], layout object [F+0x628] (+8,+0xC,+0x10,+0x14 = the generator's spacing floats),
//   dirty byte [F+0x278C], cooldown [F+0x2788], unit backlink [F+0x510]; man position x,z = [m+0x48],[m+0x50].
//
// Output (all written by the DLL on the tick owner; the launcher only passes the paths through the environment):
//   NTW2_FORMATION_CENSUS_CSV    CSV file (required; the census is inert without it)
//   NTW2_FORMATION_CENSUS_EVERY  sampling period in model ticks (optional, 1..10000, default 30)
//   <csv>.summary.txt            rewritten after every pass: per-alliance counters, the collapse count and a ratio histogram
// CSV columns (one row per unit per sample, units with no formation men are skipped); ratio = men_rms / slot_rms; collapsed = moving && men >= 60 &&
// nslots > 0 && men_rms < 0.35 * slot_rms; see Columns() in the .cpp for the exact order.
namespace ntw2_formation_census {
void Reset(bool enable, uint32_t imageDelta, uint32_t imageBase, uint32_t imageSize);
void Tick(uint32_t model, uint32_t modelTick);  // tick-owner thread
void Stop();                                    // flush the buffered rows and rewrite the summary; the file is closed
}
#endif
