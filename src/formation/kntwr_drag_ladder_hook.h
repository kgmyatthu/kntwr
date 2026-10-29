// --drag-ladder runtime hook (gameplay change via kntwr_config::gameplay_flags & KNTWR_DRAG_LADDER; implied by --features all, launcher --no-drag-ladder opts out).
// Policy: formation/kntwr_drag_ladder.h. Evidence: analysis/FINDINGS.md "drag ladder".
//
// v6 is one full-body detour of stock cdecl FilesPerRow 0x642C90 (args [esp+4]=width, [esp+8]=l8, [esp+0xC]=l10; EAX = files >= 1;
// caller cleans 0xC). Every files-from-width consumer reaches that function directly or through layout vtable 0x1333AA8 slot +0x10
// (0x642D00 = min(FilesPerRow, cap)), so men, markers and the solver agree by construction. WidthFromFiles 0x642B50 and the
// staggered-row copy 0x642D90 stay stock. 0x642EE0 also calls FilesPerRow on the ranks axis; that only matters above 60 ranks.
//
// Install verifies the stock 8 bytes (55 8B EC F3 0F 10 45 08) and Swap8-replaces them with E9 rel32 + 3 int3. Remove restores
// those bytes bit-exactly and refuses foreign bytes.
#ifndef KNTWR_DRAG_LADDER_HOOK_H
#define KNTWR_DRAG_LADDER_HOOK_H
#include <stdint.h>

namespace kntwr_drag_ladder_hook {
using U = uint32_t;

// drag_ladder_words (kntwr_status::drag_ladder_words, KNTWR_DRAG_LADDER_LABELS). Hot-path counters are plain ++; reset at monitor start.
// WInstalled is sticky applied-this-run (set on a successful Install, cleared only by ResetRow), not live hook presence.
constexpr U kWords = 16, kVersion = 6;
constexpr U kFilesPerRow = 0x642C90u;
enum Word : U {
    WVersion, WRequested, WInstalled, WCalls, WLaddered, WPassthrough, WFaults, WLastFilesBefore, WLastFilesAfter
};

void ResetRow();                        // monitor start: zero the row (including applied-this-run), set the version
void Snapshot(volatile U* out);         // out[kWords]; word 2 = applied this run
// `imageBase` = runtime load base of Napoleon.exe. True when the FilesPerRow detour is in place.
bool Install(U imageBase);
bool Remove();                          // restores the 8 stock bytes; false if the bytes are not ours (module must stay loaded)
bool Installed();
} // namespace kntwr_drag_ladder_hook
#endif
