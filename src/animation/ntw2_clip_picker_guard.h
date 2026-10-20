#ifndef NTW2_CLIP_PICKER_GUARD_H
#define NTW2_CLIP_PICKER_GUARD_H
#include <stdint.h>

// Crash guard for the engine's animation clip picker FUN_00e5f760 (analysis/native-crash-divzero-anim.md).  ALWAYS ON while the runtime is active (monitor start ..
// stop); no switch.  Not a gameplay change: every request the native code answers is answered bit-identically, the only differing input is the one that crashes
// the game (#DE, 0xC0000094 at 0xE5F77A).
//
// Native function [proven by disassembly of the Steam image 13fcab62..., 53 bytes at 0xE5F760, 85 direct `call` sites, no jump into 0xE5F761..0xE5F767]:
//     thiscall, ECX = animation table object, stack (category, random), `ret 8`; clobbers EAX/ECX/EDX only (ESI/EDI saved).
//     table = [ECX+0x2C];  n = table[cat*6 + 5];                        // dword index: 24-byte record per category, 5 clip slots at +0x00..+0x10, clip count at +0x14
//     n != 0 : return table[random % n + cat*6]                         // EAX = a clip object pointer (callers dereference it, e.g. `[eax+0x44]`, mostly without a null test)
//     n == 0 : return table[random % table[5]]                          // the fallback is category 0 (MISSING_ANIM): #DE when category 0 is empty too
// The table object is built by the constructor at 0xE506D0 (0xE5072A..0xE50787): [obj+0x28] = [obj+0x24] = 0x360 categories, [obj+0x2C] = 0x360 * 0x18 bytes, every
// count zeroed first; the static category-name table (24-byte records) has 864 entries and the pose loop bounds are `cmp ebx,0x5100` (= 864 * 24).
// Tables whose category 0 is empty: mount_horse / mount_camel / mount_elephant / engine_* / empty (pack data), which a man stance (e.g. COMBAT_READY_KNEEL 0x6A)
// reaches once --mounted-officer made a horse the formation member of an infantry unit.
//
// Mechanism: a 5-byte `jmp rel32` at the entry 0xE5F760 (the 8 bytes 8B 44 24 08 33 D2 56 8B are swapped in ONE 8-byte interlocked compare-exchange: the entry is
// 16-byte aligned, so no thread can see a half-written jump) to Picker, installed at monitor start (verified original bytes), restored at stop.  Picker is the
// original instruction sequence (same instructions on the n != 0 path, no counter, no extra load); only the n == 0 branch leaves for Cold:
//     table[5] != 0 : the native result (rand % table[5]) - counted in calls_cold only;
//     table[5] == 0 : GUARDED.  Scan categories 1 .. 863 in order and return the clip (rand % n_k + k*6) of the first category with a non-zero count, so the caller
//                     receives a valid clip object (the man-stance request on a horse plays that category's clip).  The bound is the constructor's constant 0x360: the
//                     table header is not readable here (ECX is overwritten by the native sequence and keeping it would add an instruction to the hot path).
//     all 864 empty : return table[0], the first dword of the table.  A null clip is NOT tolerated by most of the 85 callers (they dereference the result at +0x44 /
//                     +0x1C ...), so no fabricated 0 is returned; table[0] is what the native code would have read for index 0, i.e. the very value the callers
//                     of a clip-less table already receive.  Counted in empty_tables.
namespace ntw2_clip_picker_guard {
// anim_guard_words (ntw2_status::anim_guard_words, NTW2_ANIM_GUARD_LABELS; interlocked counters, cold path only; reset at monitor start, retained after stop):
//  0 calls_cold (n == 0: category fell back to category 0)  1 guarded (category 0 empty too)  2 scanned_max (largest category index reached by a guarded scan)
//  3 empty_tables (every category empty)  4 table_last (last guarded table pointer)  5 cat_last (last guarded requested category)  6 patch_installed  7 version
constexpr uint32_t kWords = 8, kVersion = 1;
enum Word : uint32_t { WCallsCold, WGuarded, WScannedMax, WEmptyTables, WTableLast, WCatLast, WPatchInstalled, WVersion };
extern volatile uint32_t words[kWords];

constexpr uint32_t kEntry = 0xE5F760u, kCategories = 0x360u;

uint32_t Entry();                       // address of the guarded picker (naked, thiscall-compatible: ECX = table object, stack (category, random), ret 8)
void ResetRow();                        // monitor start: zero the row, set the version
void Snapshot(volatile uint32_t* out);  // out[kWords]
// The cold path alone (stdcall, callee pops 12): table = the category table ([obj+0x2C]), category, random.  Exposed for the oracle.
uint32_t __stdcall Cold(const uint32_t* table, uint32_t category, uint32_t random);

// Entry redirect; `delta` = image delta from the preferred base.  Install verifies the original 8 bytes, swaps them for `jmp Picker` + the three untouched original
// bytes with one 8-byte interlocked compare-exchange (lifting and restoring the page protection, flushing the instruction cache) and reads them back; Remove restores
// the original bytes when the current ones are ours.  Both return false on any mismatch/failure without a partial change.
bool InstallRedirect(uint32_t delta);
bool RemoveRedirect(uint32_t delta);
}
#endif
