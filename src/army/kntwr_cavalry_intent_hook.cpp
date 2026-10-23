// Cavalry attack-intent flush entry hook (contract: local://cavalry-retained-intent-contract.md, #Native authority / #Shared APIs).
//
// Native site 0x542AE0 (generic queue flush, thiscall ECX = U+0x390, no args): stock prologue bytes
//   56                    push esi
//   8B F1                 mov esi, ecx
//   83 BE A0 05 00 00 00  cmp dword ptr [esi+5A0h], 0
// are 10 bytes of COMPLETE displaced instructions. The patch swaps the first 8 bytes for `jmp rel32` (gate) + the 3 untouched
// original tail bytes; bytes 8..9 are never written. The gate replays all 10 bytes with the caller's registers/flags restored
// and jumps `g_resume` = site+10 (0x542AEA relocated) — g_resume/g_site are assigned BEFORE the patch becomes reachable and
// stay immutable while any gate execution may be in flight.
//
// Observer: kntwr_cavalry::ObserveFlush(ring) receives ECX as a VALUE. It must never dereference native memory, must be
// integer-only, and must not allocate; the gate still saves/restores EFLAGS, all GPRs and the full FXSAVE image (x87 + XMM +
// MXCSR) around the call, and no exception boundary exists inside the gate (the adapter's publication is atomic-only).
//
// Thread-freeze / interior-IP refusal / 8-byte CAS policy is the shared core/kntwr_entry_patch.h (extracted from the
// mounted-officer policy; no second copy). Remove refuses while any peer is unfrozen inside the gate (EIP in the gate range
// or the in-gate counter) and only then CASes the patch out; a CAS mismatch (foreign patch, or bytes already changed) writes
// NOTHING and reports failure — removal success is never claimed on a mismatch, and the caller must then keep the adapter
// state and this module loaded while it retries.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include "native_cavalry_runtime.h"
#include "core/kntwr_entry_patch.h"
#include "kntwr_cavalry_intent_hook.h"

namespace kntwr_cavalry_intent_hook {
namespace {

constexpr U kPreferred = 0x400000u;      // Napoleon.exe preferred image base (same convention as the runtime/adapter)
constexpr U kEntry = 0x542AE0u;          // preferred-VA of the flush entry
constexpr U kSpan = 10;                  // complete displaced instructions: push esi / mov esi,ecx / cmp [esi+5A0],0
constexpr unsigned char kStock[kSpan] = {0x56,0x8B,0xF1,0x83,0xBE,0xA0,0x05,0x00,0x00,0x00};
// Gate tail marker (never executed): scanned at Install to bound the gate's code range, validated by requiring the
// absolute jmp and the stock replay bytes right before it, so a coincidental earlier match cannot shrink the range.
constexpr unsigned char kTailMarker[8] = {0xC7,0x1C,0xA5,0x0F,0x9E,0x5B,0x63,0xD8};
constexpr U kJmpBytes = 6;               // FF 25 <addr32>: jmp dword ptr [g_resume]
constexpr U kGateScanBytes = 192;

volatile U g_resume = 0;                 // site+10; written only while no gate execution can be in flight
volatile LONG g_inGate = 0;              // >0 while some thread is between the gate's inc and dec
volatile LONG g_installed = 0;
volatile LONG g_lifecycle = 0;           // Install/Remove reentrancy guard (activation/teardown owner thread)
U g_site = 0;
unsigned char g_patch[8];

bool BytesAre(U address, const unsigned char* expected, U bytes) {
    __try {
        return memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), expected, bytes) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Follows a jmp rel32 thunk if the toolchain emitted one for &FlushGate (the naked body itself starts 9C pushfd).
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

// The only code the hook ever runs on a flush: forward ECX (the ring) by value. Integer-only, allocation-free, no native
// memory read, no exception. stdcall so the gate's stack arithmetic is independent of any project calling-convention flag.
void __stdcall Dispatch(U ring) {
    kntwr_cavalry::ObserveFlush(ring);
}

// Entry state at the jmp: ECX = ring, ESP = native entry ESP, EFLAGS = native entry flags (pushfd/pushad restored them
// before the replay), ESI/EDI/EBX/EBP/EDX/EAX = native. Layout follows the runtime's ObserveGate (fxsave gate family).
__declspec(naked) void FlushGate() {
    __asm {
        pushfd
        pushad
        lock inc dword ptr [g_inGate]
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push ecx
        call Dispatch
        fxrstor [esp]
        mov esp, ebp
        lock dec dword ptr [g_inGate]
        popad
        popfd
        _emit 0x56               // push esi
        _emit 0x8B               // mov esi, ecx (first byte)
        _emit 0xF1               // mov esi, ecx (second byte)
        _emit 0x83               // cmp dword ptr [esi+5A0h], 0
        _emit 0xBE
        _emit 0xA0
        _emit 0x05
        _emit 0x00
        _emit 0x00
        _emit 0x00
        jmp dword ptr [g_resume] // 6 bytes: FF 25 <g_resume>; target = site+10 (0x542AEA relocated)
        _emit 0xC7               // tail marker (never executed)
        _emit 0x1C
        _emit 0xA5
        _emit 0x0F
        _emit 0x9E
        _emit 0x5B
        _emit 0x63
        _emit 0xD8
    }
}

// [begin, end) covering every gate byte a frozen thread could still execute, including the final 6-byte jmp. begin==0 on
// failure. The candidate marker is accepted only when FF 25 and the 10 stock replay bytes sit immediately before it.
bool GateRange(U& begin, U& end) {
    const U gate = Resolve(static_cast<U>(reinterpret_cast<uintptr_t>(&FlushGate)));
    if (!gate) return false;
    const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(gate));
    for (U offset = 0; offset + 8 <= kGateScanBytes; ++offset) {
        if (memcmp(p + offset, kTailMarker, 8) != 0) continue;
        if (offset < kJmpBytes + kSpan) return false;               // replay+jmp cannot fit before the marker
        if (p[offset - kJmpBytes] != 0xFF || p[offset - kJmpBytes + 1] != 0x25) continue;
        if (memcmp(p + offset - kJmpBytes - kSpan, kStock, kSpan) != 0) continue;
        begin = gate;
        end = gate + offset;   // marker start: the whole final jmp lies in [end-6, end); a thread parked on it
                               // has already dec'd g_inGate, so only this EIP range catches it
        return true;
    }
    return false;
}

bool InstallLocked(U imageBase) {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) != 0) return false;
    if (!imageBase) return false;
    U gateBegin = 0, gateEnd = 0;
    if (!GateRange(gateBegin, gateEnd)) return false;               // gate layout pinned before it is ever entered
    const U site = imageBase - kPreferred + kEntry;
    if (!BytesAre(site, kStock, kSpan)) return false;               // exact pinned original, all 10 bytes
    // The 8-byte CAS below guards bytes 0..7; the untouched tail 8..9 is re-checked before Remove restores the patch.
    memcpy(g_patch, kStock, 8);
    g_patch[0] = 0xE9;
    const U displacement = gateBegin - site - 5;
    memcpy(g_patch + 1, &displacement, 4);
    // Written BEFORE the patch is reachable and immutable afterwards: not installed (checked above), and a previous
    // successful Remove drained the gate, so no in-flight gate execution can read these.
    g_site = site;
    g_resume = site + kSpan;                                        // 0x542AEA relocated
    const kntwr_entry_patch::Guard drain{gateBegin, gateEnd, &g_inGate};  // EIP range/counter cannot trip before the patch exists
    return kntwr_entry_patch::Swap8(site, kStock, g_patch, kSpan, drain, [] {
        _InterlockedExchange(&g_installed, 1);
    });
}

bool RemoveLocked() {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) == 0) return true;
    U gateBegin = 0, gateEnd = 0;
    if (!GateRange(gateBegin, gateEnd)) return false;   // cannot prove drain; keep the patch and the resources
    if (!BytesAre(g_site + 8, kStock + 8, 2)) return false;          // untouched tail drifted: nothing is restored
    const kntwr_entry_patch::Guard drain{gateBegin, gateEnd, &g_inGate};
    // Refuses while a frozen peer is anywhere in the gate (EIP in the displaced span or the gate range, or the in-gate
    // counter non-zero); CAS mismatch (foreign bytes) writes nothing and reports failure — never claims success on a
    // mismatch. On success every peer was frozen outside the gate, so no thread can be in it again.
    const bool swapped = kntwr_entry_patch::Swap8(g_site, g_patch, kStock, kSpan, drain, [] {
        _InterlockedExchange(&g_installed, 0);
    });
    return swapped;
}
} // namespace

bool Install(U imageBase) {
    if (_InterlockedCompareExchange(&g_lifecycle, 1, 0) != 0) return false;
    const bool ok = InstallLocked(imageBase);
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
} // namespace kntwr_cavalry_intent_hook
