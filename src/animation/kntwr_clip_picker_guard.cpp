// Clip picker crash guard and its entry redirect (contract and proof: kntwr_clip_picker_guard.h).  x86 MSVC host code: the picker is naked inline asm.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include "kntwr_clip_picker_guard.h"

namespace kntwr_clip_picker_guard {
using U = uint32_t;
volatile U words[kWords];

namespace {
// The original 8 bytes at the entry: 8B 44 24 08 | 33 | D2 56 8B  (mov eax,[esp+8]; xor edx,edx; push esi; mov ...).  Bytes 5..7 are kept in the patched image.
constexpr unsigned char kOriginal[8] = {0x8B, 0x44, 0x24, 0x08, 0x33, 0xD2, 0x56, 0x8B};

inline void Bump(Word w) { _InterlockedIncrement(reinterpret_cast<volatile long*>(&words[w])); }
inline void Set(Word w, U v) { _InterlockedExchange(reinterpret_cast<volatile long*>(&words[w]), static_cast<long>(v)); }
inline void Max(Word w, U v) {
    volatile long* p = reinterpret_cast<volatile long*>(&words[w]);
    for (long seen = *p; static_cast<U>(seen) < v;) {
        const long was = _InterlockedCompareExchange(p, static_cast<long>(v), seen);
        if (was == seen) break;
        seen = was;
    }
}
U patched[2];  // the 8 bytes this module wrote (as two dwords), valid while words[WPatchInstalled]
}

U __stdcall Cold(const U* table, U category, U random) {
    Bump(WCallsCold);
    const U category0 = table[5];
    if (category0) return table[random % category0];             // the native fallback, unchanged
    Bump(WGuarded);
    Set(WTableLast, static_cast<U>(reinterpret_cast<uintptr_t>(table)));
    Set(WCatLast, category);
    for (U k = 1; k < kCategories; ++k) {
        const U n = table[k * 6 + 5];
        if (n) { Max(WScannedMax, k); return table[random % n + k * 6]; }
    }
    Max(WScannedMax, kCategories - 1);
    Bump(WEmptyTables);
    return table[0];
}

namespace {
// ECX = table object, stack (category, random), ret 8.  The first nine instructions and the n != 0 tail are the original bytes of 0xE5F760..0xE5F792 verbatim; the
// original `div dword ptr [esi+0x14]` branch (n == 0) is replaced by the call of Cold with (table, category, random) and the same epilogue pops.
__declspec(naked) void Picker() {
    __asm {
        mov eax, [esp + 8]
        xor edx, edx
        push esi
        mov esi, [ecx + 0x2C]
        push edi
        mov edi, [esp + 0xC]
        lea ecx, [edi + edi*2]
        mov ecx, [esi + ecx*8 + 0x14]
        test ecx, ecx
        jne hot
        push eax
        push edi
        push esi
        call Cold
        pop edi
        pop esi
        ret 8
    hot:
        div ecx
        lea eax, [edi + edi*2]
        pop edi
        lea eax, [edx + eax*2]
        mov eax, [esi + eax*4]
        pop esi
        ret 8
    }
}
}

U Entry() { return static_cast<U>(reinterpret_cast<uintptr_t>(&Picker)); }
void ResetRow() {
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    words[WVersion] = kVersion;
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

namespace {
// One 8-byte interlocked swap of the entry (16-byte aligned image => one cache line).  `from` must match, `to` replaces it; the page is made writable around it.
bool Swap(U site, const unsigned char* from, const unsigned char* to) {
    if (site & 7u) return false;
    volatile LONG64* p = reinterpret_cast<volatile LONG64*>(static_cast<uintptr_t>(site));
    LONG64 expect, replacement;
    memcpy(&expect, from, 8);
    memcpy(&replacement, to, 8);
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)), 8, PAGE_EXECUTE_READWRITE, &old)) return false;
    const bool ok = _InterlockedCompareExchange64(p, replacement, expect) == expect;
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)), 8, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(static_cast<uintptr_t>(site)), 8);
    return ok;
}
bool Read8(U site, unsigned char* out) {
    __try { memcpy(out, reinterpret_cast<const void*>(static_cast<uintptr_t>(site)), 8); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}
}

bool InstallRedirect(U delta) {
    const U site = kEntry + delta;
    unsigned char current[8];
    if (!Read8(site, current) || memcmp(current, kOriginal, 8) != 0) return false;
    unsigned char replacement[8];
    memcpy(replacement, kOriginal, 8);
    replacement[0] = 0xE9;
    const U rel = Entry() - (site + 5);
    memcpy(replacement + 1, &rel, 4);       // bytes 5..7 stay the original ones
    if (!Swap(site, kOriginal, replacement)) return false;
    unsigned char check[8];
    if (!Read8(site, check) || memcmp(check, replacement, 8) != 0) { Swap(site, replacement, kOriginal); return false; }
    memcpy(patched, replacement, 8);
    Set(WPatchInstalled, 1);
    return true;
}

bool RemoveRedirect(U delta) {
    if (!words[WPatchInstalled]) return true;
    const U site = kEntry + delta;
    unsigned char current[8];
    if (!Read8(site, current)) return false;
    if (memcmp(current, kOriginal, 8) == 0) { Set(WPatchInstalled, 0); return true; }
    if (memcmp(current, patched, 8) != 0) return false;
    if (!Swap(site, current, kOriginal)) return false;
    Set(WPatchInstalled, 0);
    return true;
}
}
