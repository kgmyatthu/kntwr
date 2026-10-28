// --drag-ladder v6 (see kntwr_drag_ladder_hook.h).
// One detour: stock cdecl FilesPerRow 0x642C90. Its first 8 bytes are complete instructions
// (push ebp; mov ebp, esp; movss xmm0, [ebp+8]); Swap8 replaces them with E9 rel32 + 3 int3 (freeze, interior-IP refusal, one cmpxchg8b).
// Detour = naked thunk that preserves xmm1..xmm7 (stock clobbers only eax/ecx/edx/xmm0 and the x87 stack stays balanced; the engine is
// LTCG-built, so a caller may keep xmm1..7 live across the call), then calls the cdecl core: the layout port's FilesPerRow floored to a
// 60-multiple above 60. No memory is dereferenced beyond the three float args, so there is no SEH and no fault path (WFaults stays 0).
// Residual window on Remove: a peer parked inside the core/port (outside the 8 patched bytes) is not proven drained, the same as the
// always-on clip-picker guard; the runtime only unloads after every hook reports removal.
#include "formation/kntwr_drag_ladder_hook.h"

#include <cstring>

#include "core/kntwr_entry_patch.h"
#include "formation/kntwr_drag_ladder.h"
#include "formation/native_formation_layout.h"

namespace kntwr_drag_ladder_hook {
namespace {

constexpr U kPreferred = 0x400000u;
constexpr U kSpan = 8;
constexpr unsigned char kStock[8] = {0x55, 0x8B, 0xEC, 0xF3, 0x0F, 0x10, 0x45, 0x08};

volatile U g_words[kWords];
volatile LONG g_installed = 0;   // live detour: lifecycle only (Installed/Install/Remove)
volatile LONG g_wasInstalled = 0; // sticky applied-this-run; cleared only by ResetRow
U g_site = 0;
unsigned char g_patch[8];

// Hot path: plain increments (single-writer-per-call races lose at most a count; the row is diagnostic, never control flow).
unsigned __cdecl Core(float w, float l8, float l10) {
    const unsigned before = ntw_formation_layout::FilesPerRow(w, l8, l10);
    const unsigned after = kntwr_drag_ladder::LadderFiles(before);
    ++g_words[WCalls];
    g_words[WLastFilesBefore] = before;
    g_words[WLastFilesAfter] = after;
    if (after != before) ++g_words[WLaddered];
    else ++g_words[WPassthrough];
    return after;
}

// cdecl, caller cleans 0xC: [esp+4]=width [esp+8]=l8 [esp+0xC]=l10 on entry. Returns files in EAX.
__declspec(naked) unsigned __cdecl Detour(float, float, float) {
    __asm {
        sub esp, 0x70                // xmm1..xmm7 save area; entry args now at esp+0x74 (w), +0x78 (l8), +0x7C (l10)
        movups [esp + 0x00], xmm1
        movups [esp + 0x10], xmm2
        movups [esp + 0x20], xmm3
        movups [esp + 0x30], xmm4
        movups [esp + 0x40], xmm5
        movups [esp + 0x50], xmm6
        movups [esp + 0x60], xmm7
        push dword ptr [esp + 0x7C]  // l10
        push dword ptr [esp + 0x7C]  // l8  (esp moved by 4 above: original +0x78 is +0x7C again)
        push dword ptr [esp + 0x7C]  // w
        call Core
        add esp, 0xC
        movups xmm1, [esp + 0x00]
        movups xmm2, [esp + 0x10]
        movups xmm3, [esp + 0x20]
        movups xmm4, [esp + 0x30]
        movups xmm5, [esp + 0x40]
        movups xmm6, [esp + 0x50]
        movups xmm7, [esp + 0x60]
        add esp, 0x70
        ret
    }
}

void EncodeJmp(U site, unsigned char out[8]) {
    const U target = static_cast<U>(reinterpret_cast<uintptr_t>(&Detour));
    const U rel = target - (site + 5u);
    out[0] = 0xE9;
    std::memcpy(out + 1, &rel, 4);
    out[5] = out[6] = out[7] = 0xCC;
}

bool BytesAre(U site, const unsigned char* expect) {
    return std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(site)), expect, 8) == 0;
}

} // namespace

void ResetRow() {
    for (U i = 0; i < kWords; ++i) g_words[i] = 0;
    g_words[WVersion] = kVersion;
    _InterlockedExchange(&g_wasInstalled, 0);
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = g_words[i];
    // Word 2 is applied-this-run, not live presence: a clean Remove clears g_installed but the final receipt stays APPLIED.
    out[WInstalled] = _InterlockedCompareExchange(&g_wasInstalled, 0, 0) ? 1u : 0u;
}

bool Installed() { return _InterlockedCompareExchange(&g_installed, 0, 0) != 0; }

bool Install(U imageBase) {
    g_words[WRequested] = 1;
    if (!imageBase || Installed()) return Installed();
    const U site = imageBase + (kFilesPerRow - kPreferred);
    if (!BytesAre(site, kStock)) return false;           // foreign or modified bytes: patch nothing
    unsigned char patch[8];
    EncodeJmp(site, patch);
    const kntwr_entry_patch::Guard none;
    if (!kntwr_entry_patch::Swap8(site, kStock, patch, kSpan, none, [site, &patch] {
            g_site = site;
            std::memcpy(g_patch, patch, 8);
            _InterlockedExchange(&g_installed, 1);
            _InterlockedExchange(&g_wasInstalled, 1);
        }))
        return false;
    return true;
}

bool Remove() {
    if (!Installed()) return true;
    const kntwr_entry_patch::Guard none;
    // Swap8 compares the current 8 bytes with our patch: foreign bytes refuse without a write.
    if (!kntwr_entry_patch::Swap8(g_site, g_patch, kStock, kSpan, none, [] {
            _InterlockedExchange(&g_installed, 0);
        }))
        return false;
    g_site = 0;
    return true;
}

} // namespace kntwr_drag_ladder_hook
