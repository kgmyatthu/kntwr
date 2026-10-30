// --wounded state-commit hook (contract: kntwr_wounded_hook.h; policy: kntwr_wounded.h; evidence: analysis/FINDINGS.md
// "Wounded/corpse animation infrastructure census" 2026-10-31).
//
// Native site 0x653F1A (kill path 0x653A10; ECX = normalized death category 1..0x35F, EBP = man anim FSM M): stock bytes
//   8B 15 C8 21 45 01     mov edx, [0x14521C8]      (knockdown range lo)
//   3B CA                 cmp ecx, edx
// = 8 bytes of complete displaced instructions, replaced by `jmp rel32` (gate) + 3 int3. The gate does NOT replay them:
// Decide() recomputes the full state select the stock code 0x653F1A..0x653F38 performs (range test -> 0x4B, else 0x2A)
// plus the opt-in flip, the gate writes the state into the saved-EAX slot and [0x14521C8] into the saved-EDX slot of its
// pushad frame (the exact registers stock code leaves at the resume point: EAX = state, ECX = category untouched,
// EDX = range lo), then jumps g_resume = site+0x1F (0x653F39 relocated: `mov [ebp+0x1B8], eax`). The bypassed stock
// select 0x653F22..0x653F38 is dead while installed and restored bit-exactly by Remove (those bytes are never written).
//
// Decide walks native memory read-only on the owner (simulation) thread that runs the kill path, exactly like the stock
// stepper 0x679300 does one frame later: holder [M+0x218] -> table -> records [table+0x2C] -> record cat*0x18 -> clip
// (rnd % count, rnd = [M+0x1E0] - the same deterministic re-pick the stepper performs, so the inspected FACE fields
// belong to the clip that is actually playing). Every dereference sits under SEH; a fault counts WFaults and commits the
// stock static state. No allocation, no native call, integer-only.
//
// Thread-freeze / interior-IP refusal / 8-byte CAS policy is the shared core/kntwr_entry_patch.h. Remove refuses while
// any peer is inside the gate (EIP in [gateBegin, gateEnd) or the in-gate counter); a CAS mismatch writes NOTHING.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include "core/kntwr_entry_patch.h"
#include "kntwr_wounded.h"
#include "kntwr_wounded_hook.h"

namespace kntwr_wounded_hook {
namespace {

constexpr U kPreferred = 0x400000u;      // Napoleon.exe preferred image base
constexpr U kSpan = 8;                   // complete displaced instructions: mov edx,[0x14521C8] / cmp ecx,edx
constexpr U kResumeOffset = 0x1Fu;       // site+0x1F = 0x653F39, the `mov [ebp+0x1B8], eax` state store
constexpr U kRangeLo = 0x14521C8u;       // preferred-VA of the knockdown category range {lo, count}
constexpr U kCategoryCount = 0x360u;     // anim category table size; normalized cat is always < this
// Preferred-base template: the disp32 at +2 carries a base relocation, so the live original is rebuilt per image base.
constexpr unsigned char kStock[kSpan] = {0x8B,0x15,0xC8,0x21,0x45,0x01,0x3B,0xCA};
// Gate tail marker (never executed): scanned at Install to bound the gate's code range, validated by requiring the
// absolute jmp immediately before it, so a coincidental earlier match cannot shrink the range.
constexpr unsigned char kTailMarker[8] = {0xD1,0x6E,0x3A,0x97,0xC4,0x08,0x5F,0xB2};
constexpr U kJmpBytes = 6;               // FF 25 <addr32>: jmp dword ptr [g_resume]
constexpr U kGateScanBytes = 192;

volatile U g_resume = 0;                 // site+0x1F; written only while no gate execution can be in flight
volatile U g_rangeLo = 0;                // relocated address of [0x14521C8]; written before the patch is reachable
volatile U g_pct = 0;                    // flip probability 1..100; written before the patch is reachable
volatile LONG g_inGate = 0;              // >0 while some thread is between the gate's inc and dec
volatile LONG g_installed = 0;
volatile LONG g_wasInstalled = 0;        // sticky applied-this-run, cleared only by ResetRow
volatile LONG g_lifecycle = 0;           // Install/Remove reentrancy guard (activation/teardown owner thread)
U g_site = 0;
unsigned char g_patch[8];
unsigned char g_stock[8];                // relocated original: 8B 15 <&rangeLo for this base> 3B CA
volatile U g_words[kWords];

bool BytesAre(U address, const unsigned char* expected, U bytes) {
    __try {
        return memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), expected, bytes) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Native-memory walk; every dereference may fault, the caller holds the SEH frame. Returns the committed state.
U DecideBody(U cat, U m) {
    const U lo = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(g_rangeLo));
    const U n = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(g_rangeLo + 4));
    if (kntwr_wounded::NativeKnockdown(cat, lo, n)) { ++g_words[WNativeKnockdown]; return kntwr_wounded::kStateWounded; }
    ++g_words[WStaticCandidates];
    const U pct = g_pct;
    if (!pct || cat >= kCategoryCount) return kntwr_wounded::kStateStatic;
    const U holder = *reinterpret_cast<const U*>(static_cast<uintptr_t>(m + 0x218));
    const U table = holder ? *reinterpret_cast<const U*>(static_cast<uintptr_t>(holder)) : 0;
    const U records = table ? *reinterpret_cast<const U*>(static_cast<uintptr_t>(table + 0x2C)) : 0;
    if (!records) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U record = records + cat * 0x18u;
    const U count = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + 0x14));
    if (!count) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U rnd = *reinterpret_cast<const U*>(static_cast<uintptr_t>(m + 0x1E0));
    const U clip = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + (rnd % count) * 4u));
    if (!clip) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U faceDownPresent = *reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(clip + 0x60));
    const U faceDownParam = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + 0x5C));
    const U faceUpParam = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + 0x54));
    if (!kntwr_wounded::ClipEligible(faceDownPresent, faceDownParam, faceUpParam)) {
        ++g_words[WUntagged];
        return kntwr_wounded::kStateStatic;
    }
    ++g_words[WEligible];
    if (!kntwr_wounded::Flip(rnd, m, pct)) { ++g_words[WDeniedRoll]; return kntwr_wounded::kStateStatic; }
    ++g_words[WFlipped];
    return kntwr_wounded::kStateWounded;
}

// The only code the gate runs: compute the state the store at 0x653F39 commits. stdcall so the gate's stack arithmetic
// is independent of any project calling-convention flag. Counters are diagnostic only, never control flow.
U __stdcall Decide(U cat, U m) {
    ++g_words[WCalls];
    g_words[WLastCat] = cat;
    U state = kntwr_wounded::kStateStatic;
    __try {
        state = DecideBody(cat, m);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_words[WFaults];
        state = kntwr_wounded::kStateStatic;
    }
    return state;
}

// Entry state at the jmp: ECX = normalized category, EBP = man anim FSM M, ESP/EFLAGS/other GPRs = native. pushad frame
// (after `mov ebp, esp`): [ebp+0]=EDI +4=ESI +8=EBP(=M) +12=ESP +16=EBX +20=EDX +24=ECX(=cat) +28=EAX, [ebp+32]=EFLAGS.
// The gate writes Decide's state into the saved-EAX slot and [g_rangeLo] into the saved-EDX slot, so popad materializes
// the exact registers the bypassed stock select leaves: EAX = state, EDX = range lo, ECX untouched. Resumes at site+0x1F.
__declspec(naked) void CommitGate() {
    __asm {
        pushfd
        pushad
        lock inc dword ptr [g_inGate]
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push dword ptr [ebp+8]       // m  (saved EBP)
        push dword ptr [ebp+24]      // cat (saved ECX)
        call Decide
        mov [ebp+28], eax            // saved EAX = committed state
        mov ecx, [g_rangeLo]
        mov ecx, [ecx]
        mov [ebp+20], ecx            // saved EDX = [0x14521C8], as the displaced mov left it
        fxrstor [esp]
        mov esp, ebp
        lock dec dword ptr [g_inGate]
        popad
        popfd
        jmp dword ptr [g_resume]     // 6 bytes: FF 25 <&g_resume>; target = site+0x1F (0x653F39 relocated)
        _emit 0xD1                   // tail marker (never executed)
        _emit 0x6E
        _emit 0x3A
        _emit 0x97
        _emit 0xC4
        _emit 0x08
        _emit 0x5F
        _emit 0xB2
    }
}

// Follows a jmp rel32 thunk if the toolchain emitted one for &CommitGate (the naked body itself starts 9C pushfd).
U Resolve(U fn) {
    for (U hop = 0; hop < 4; ++hop) {
        const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(fn));
        U displacement = 0, next = 0;
        __try {
            if (p[0] != 0xE9) return fn;
            memcpy(&displacement, p + 1, 4);
            next = fn + 5 + displacement;
        } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        if (next <= fn || next - fn > 0x10000u) return 0;
        fn = next;
    }
    return 0;
}

// [begin, end) covering every gate byte a frozen thread could still execute, including the final 6-byte jmp. begin==0 on
// failure. The candidate marker is accepted only when the FF 25 absolute jmp sits immediately before it.
bool GateRange(U& begin, U& end) {
    const U gate = Resolve(static_cast<U>(reinterpret_cast<uintptr_t>(&CommitGate)));
    if (!gate) return false;
    const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(gate));
    for (U offset = 0; offset + 8 <= kGateScanBytes; ++offset) {
        if (memcmp(p + offset, kTailMarker, 8) != 0) continue;
        if (offset < kJmpBytes) return false;
        if (p[offset - kJmpBytes] != 0xFF || p[offset - kJmpBytes + 1] != 0x25) continue;
        begin = gate;
        end = gate + offset;   // marker start: the whole final jmp lies in [end-6, end); a thread parked on it
                               // has already dec'd g_inGate, so only this EIP range catches it
        return true;
    }
    return false;
}

bool InstallLocked(U imageBase, U pct) {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) != 0) return false;
    if (!imageBase || !pct || pct > 100u) return false;
    U gateBegin = 0, gateEnd = 0;
    if (!GateRange(gateBegin, gateEnd)) return false;               // gate layout pinned before it is ever entered
    const U site = imageBase - kPreferred + kCommitSite;
    const U rangeLo = imageBase - kPreferred + kRangeLo;
    unsigned char stock[8];
    memcpy(stock, kStock, 8);
    memcpy(stock + 2, &rangeLo, 4);                                 // the loader relocated the disp32 with the image
    if (!BytesAre(site, stock, kSpan)) return false;                // exact pinned original, all 8 bytes
    memcpy(g_stock, stock, 8);
    unsigned char patch[8];
    memset(patch, 0xCC, 8);
    patch[0] = 0xE9;
    const U displacement = gateBegin - site - 5;
    memcpy(patch + 1, &displacement, 4);
    memcpy(g_patch, patch, 8);
    // Written BEFORE the patch is reachable and immutable afterwards: not installed (checked above), and a previous
    // successful Remove drained the gate, so no in-flight gate execution can read these.
    g_site = site;
    g_resume = site + kResumeOffset;                                // 0x653F39 relocated
    g_rangeLo = rangeLo;
    g_pct = pct;
    const kntwr_entry_patch::Guard drain{gateBegin, gateEnd, &g_inGate};  // cannot trip before the patch exists
    return kntwr_entry_patch::Swap8(site, g_stock, g_patch, kSpan, drain, [] {
        _InterlockedExchange(&g_installed, 1);
        _InterlockedExchange(&g_wasInstalled, 1);
        g_words[WInstalled] = 1;
    });
}

bool RemoveLocked() {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) == 0) return true;
    U gateBegin = 0, gateEnd = 0;
    if (!GateRange(gateBegin, gateEnd)) return false;   // cannot prove drain; keep the patch and the resources
    const kntwr_entry_patch::Guard drain{gateBegin, gateEnd, &g_inGate};
    // Refuses while a frozen peer is anywhere in the gate (EIP in the displaced span or the gate range, or the in-gate
    // counter non-zero); CAS mismatch (foreign bytes) writes nothing and reports failure — never claims success on a
    // mismatch. On success every peer was frozen outside the gate, so no thread can be in it again.
    const bool swapped = kntwr_entry_patch::Swap8(g_site, g_patch, g_stock, kSpan, drain, [] {
        _InterlockedExchange(&g_installed, 0);
    });
    if (swapped) g_site = 0;
    return swapped;
}
} // namespace

void ResetRow() {
    for (U i = 0; i < kWords; ++i) g_words[i] = 0;
    _InterlockedExchange(&g_wasInstalled, 0);
    g_words[WVersion] = kVersion;
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = g_words[i];
    out[WInstalled] = _InterlockedCompareExchange(&g_wasInstalled, 0, 0) != 0 ? 1u : 0u;
}

bool Install(U imageBase, U pct) {
    g_words[WRequested] = 1;
    if (_InterlockedCompareExchange(&g_lifecycle, 1, 0) != 0) return false;
    const bool ok = InstallLocked(imageBase, pct);
    _InterlockedExchange(&g_lifecycle, 0);
    return ok;
}

bool Remove() {
    if (_InterlockedCompareExchange(&g_lifecycle, 1, 0) != 0) return false;
    const bool ok = RemoveLocked();
    _InterlockedExchange(&g_lifecycle, 0);
    return ok;
}

bool Installed() {
    return _InterlockedCompareExchange(&g_installed, 0, 0) != 0;
}
} // namespace kntwr_wounded_hook
