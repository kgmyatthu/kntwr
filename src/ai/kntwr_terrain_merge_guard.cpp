// Terrain-analyser merge predicate fast rejection and its call-site redirect (contract and proof: kntwr_terrain_merge_guard.h).  x86 MSVC host code: the guard is naked inline asm.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include "kntwr_terrain_merge_guard.h"

namespace kntwr_terrain_merge_guard {
using U = uint32_t;
volatile U fallback = 0;

namespace {
volatile long installed = 0;
U replacement = 0;   // the displacement this module wrote, valid while `installed`

struct Range { float lo, hi; };

// The ordered extent of every value the native code can compute for one coordinate axis of a record (axis 0 = x, 1 = y).  The expressions are the ones of 0x63B496..0x63BACE
// in their native operation order (single precision, one rounding each; h = [0x1318038] = 0.5f, verified at install):
//   A = (a*L0)*h   C = (b*L1)*h   X = C + c   Xn = c - C
//   corner variants used by the eight segment endpoints:  X - A,  A + X,  Xn - A,  A + Xn,  (((L0*a) + (L1*b))*h) + c
// (record offsets: c = +0/+4, L0 = +0xC, L1 = +0x10, a = +0x14/+0x18, b = +0x1C/+0x20).  Returns false when any value is NaN.
inline bool Span(const float* r, U axis, Range& out) {
    const float h = 0.5f;
    const float c = r[axis], a = r[5 + axis], b = r[7 + axis], l0 = r[3], l1 = r[4];
    const float A = (a * l0) * h, C = (b * l1) * h;
    const float X = C + c, Xn = c - C;
    const float v[5] = {X - A, A + X, Xn - A, A + Xn, ((l0 * a) + (l1 * b)) * h + c};
    for (U k = 0; k < 5; ++k)
        if (v[k] != v[k]) return false;
    float lo = v[0], hi = v[0];
    for (U k = 1; k < 5; ++k) {
        if (v[k] < lo) lo = v[k];
        if (v[k] > hi) hi = v[k];
    }
    out.lo = lo;
    out.hi = hi;
    return true;
}
}

U __stdcall Rejects(const U* recordI, const U* recordJ) {
    if (recordI[9] != recordJ[9]) return 1;                      // [+0x24] type dword: native returns false first
    // Rejects() evaluates a superset of the native predicate's expressions (both role variants), so with any SSE exception unmasked it could fault where native would not: native.
    if ((_mm_getcsr() & 0x1F80u) != 0x1F80u) return 0;
    const float* i = reinterpret_cast<const float*>(recordI);
    const float* j = reinterpret_cast<const float*>(recordJ);
    for (U axis = 0; axis < 2; ++axis) {
        Range a, b;
        if (!Span(i, axis, a) || !Span(j, axis, b)) return 0;      // NaN: native decides
        if (a.hi < b.lo || b.hi < a.lo) return 1;                  // strictly separated: no corner coordinate can be equal
    }
    return 0;
}

namespace {
// ECX = record i, stack (record j), ret 4.  Rejects(i, j) is evaluated first; a non-rejected pair continues in the native predicate with ECX and the stack exactly as the
// caller built them (tail jump), so its result, register effects and `ret 4` are the stock ones.
__declspec(naked) void Guard() {
    __asm {
        push ecx
        push dword ptr [esp + 8]
        push ecx
        call Rejects
        pop ecx
        test eax, eax
        jnz reject
        jmp dword ptr [fallback]
    reject:
        xor eax, eax
        ret 4
    }
}
}

U Entry() { return static_cast<U>(reinterpret_cast<uintptr_t>(&Guard)); }

namespace {
// 0x62CA20..0x62CA33 (relocation free): mov ecx,[esp+0x24]; add eax,edi; push eax; mov [esp+0x20],eax; call rel32; test al,al; jne +0x73
constexpr unsigned char kContextHead[12] = {0x8B, 0x4C, 0x24, 0x24, 0x03, 0xC7, 0x50, 0x89, 0x44, 0x24, 0x20, 0xE8};
constexpr unsigned char kContextTail[4] = {0x84, 0xC0, 0x75, 0x73};
// 0x63B470.. : sub esp,0x90; push esi; push edi; mov edi,[esp+0x9C]; mov esi,ecx; mov eax,[esi+0x24]; cmp eax,[edi+0x24]; je +0x0D
constexpr unsigned char kPrologue[25] = {0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x56, 0x57, 0x8B, 0xBC, 0x24, 0x9C, 0x00, 0x00, 0x00, 0x8B, 0xF1, 0x8B, 0x46, 0x24, 0x3B, 0x47, 0x24, 0x74, 0x0D};
// 0x63B489: the type-mismatch exit  pop edi; xor al,al; pop esi; add esp,0x90; ret 4
constexpr unsigned char kFalseExit[13] = {0x5F, 0x32, 0xC0, 0x5E, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00};
constexpr U kHalfBits = 0x3F000000u;

bool Matches(U va, const unsigned char* expect, U n) {
    __try { return memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(va)), expect, n) == 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool Read32(U va, U& out) {
    __try { memcpy(&out, reinterpret_cast<const void*>(static_cast<uintptr_t>(va)), 4); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}
// One interlocked compare-exchange of the aligned displacement dword: `from` must match, `to` replaces it; the page is made writable around it, the protection is restored and the
// 5-byte instruction is flushed afterwards.  Refused = nothing was written and nothing is left unrestored; Unclean = the protection restore or the flush failed (whether or not the
// dword was swapped; the caller keeps the ownership and fails closed); Done = swapped and both succeeded.
// protectionDebt remembers the page's ORIGINAL protection while a restore is outstanding, independently of who owns the displacement, so a later attempt restores the true
// protection rather than the RWX it would read back then.
enum class Swap { Refused, Unclean, Done };
DWORD protectionDebt = 0;
Swap Swap32(U site, U from, U to) {
    const U field = site + 1;
    if (field & 3u) return Swap::Refused;
    void* p = reinterpret_cast<void*>(static_cast<uintptr_t>(field));
    DWORD old = 0;
    if (!VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &old)) return Swap::Refused;
    if (protectionDebt != 0) old = protectionDebt;
    const bool swapped = _InterlockedCompareExchange(reinterpret_cast<volatile long*>(p), static_cast<long>(to), static_cast<long>(from)) == static_cast<long>(from);
    DWORD ignored = 0;
    const bool restored = VirtualProtect(p, 4, old, &ignored) != 0;
    protectionDebt = restored ? 0 : old;
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(static_cast<uintptr_t>(site)), 5) != 0;
    if (!restored || !flushed) return Swap::Unclean;
    return swapped ? Swap::Done : Swap::Refused;
}
// Settles an outstanding protection restore left by Swap32.
bool Reprotect(U site) {
    if (protectionDebt == 0) return true;
    DWORD ignored = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site + 1)), 4, protectionDebt, &ignored)) return false;
    protectionDebt = 0;
    return true;
}
// Puts the stock displacement back when the current one is ours (or is already the stock one: the instruction is flushed again so that is verified too).  True only when the
// stock displacement is read back and every protection/flush step succeeded; a foreign displacement is never touched.
bool Restore(U site, U original) {
    U current = 0;
    if (!Read32(site + 1, current)) return false;
    if (current == original) return Reprotect(site) && FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(static_cast<uintptr_t>(site)), 5) != 0;
    if (current != replacement) { Reprotect(site); return false; }   // a foreign displacement is never written, but an outstanding protection restore is still paid
    if (Swap32(site, current, original) != Swap::Done) return false;
    U check = 0;
    return Read32(site + 1, check) && check == original;
}
}

bool InstallRedirect(U delta) {
    if (installed) return false;
    const U site = kCallSite + delta;
    const U original = kNative + delta - (site + 5);
    U current = 0, half = 0;
    if (!Matches(site - 11, kContextHead, sizeof kContextHead) || !Matches(site + 5, kContextTail, sizeof kContextTail)) return false;
    if (!Read32(site + 1, current) || current != original) return false;
    if (!Matches(kNative + delta, kPrologue, sizeof kPrologue) || !Matches(kNative + 0x19 + delta, kFalseExit, sizeof kFalseExit)) return false;
    if (!Read32(kHalf + delta, half) || half != kHalfBits) return false;
    const U target = Entry() - (site + 5);
    if (target == original) return false;
    replacement = target;
    _InterlockedExchange(reinterpret_cast<volatile long*>(&fallback), static_cast<long>(kNative + delta));   // published before the hook is visible
    const Swap swapped = Swap32(site, original, target);
    if (swapped == Swap::Refused) return false;                                                            // nothing was written
    _InterlockedExchange(&installed, 1);                                                                    // the displacement is ours from here on
    U check = 0;
    if (swapped == Swap::Done && Read32(site + 1, check) && check == target) return true;
    // Unclean swap or a bad readback: fail closed.  The ownership is released only when the stock displacement is verified back; otherwise `installed` stays set and the
    // monitor's stop path retries the removal.
    if (Restore(site, original)) _InterlockedExchange(&installed, 0);
    return false;
}

bool RemoveRedirect(U delta) {
    if (!installed) return true;
    const U site = kCallSite + delta;
    const U original = kNative + delta - (site + 5);
    if (!Restore(site, original)) return false;                                                            // ownership kept: still installed or unverified
    _InterlockedExchange(&installed, 0);
    return true;
}
}
