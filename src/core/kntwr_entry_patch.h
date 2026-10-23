// Shared code-entry patch swap: kernel-enumerated thread freeze, interior-IP refusal and one atomic 8-byte compare-exchange.
// Extracted unchanged from kntwr_mounted_officer.cpp (PlacementThreads / SwapAdjust); every entry patch that replaces the first
// 8 bytes of a function with `jmp rel32` + the untouched original tail bytes goes through Swap8 (the mounted-officer slot adjust and
// the cavalry flush-entry hook). Header-only so no build target changes; x86-32 Windows, the injected module's process.
//
// Contract of Swap8(site, from, to, span, guard, onSwapped):
//   * Every other thread of the process is suspended first (NtGetNextThread enumeration: no heap, loader or CRT activity while
//     a peer is held; the handles live in the object on the caller's stack). Enumeration repeats until a full pass finds no new
//     thread, so a thread created during the freeze cannot escape.
//   * A frozen thread whose EIP is strictly inside the displaced span (site, site+span) is an interior instruction boundary the
//     rewrite would corrupt; the swap refuses instead of rewriting any thread context. `span` is the byte length of the COMPLETE
//     displaced instructions, not of the 8-byte store (the officer displaces 8 bytes, the flush hook 10).
//   * guard.begin/guard.end (optional): a frozen EIP in [begin, end) refuses too (used to prove a gate has drained before the
//     patch that routes into it is removed). guard.busy (optional): the swap refuses while *busy != 0 with every peer frozen.
//   * The 8 bytes at `site` change from `from` to `to` only when they are exactly `from` (cmpxchg8b). A mismatch (foreign patch,
//     already restored bytes) writes nothing and returns false. `onSwapped` runs after the cache flush while peers are still
//     frozen, and only when the exchange happened.
//   * A refusal before the exchange leaves code bytes untouched and resumes every suspended thread. Return value reports
//     the CAS outcome; the inherited mounted-officer policy does not report protection/cache-maintenance failures.
#ifndef KNTWR_ENTRY_PATCH_H
#define KNTWR_ENTRY_PATCH_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <intrin.h>

namespace kntwr_entry_patch {
using U = uint32_t;

struct Guard {
    U begin, end;                        // frozen EIP in [begin, end) refuses the swap; begin == end disables the range
    const volatile LONG* busy;           // non-null: refuse while *busy != 0 (read with every peer frozen)
    Guard() : begin(0), end(0), busy(nullptr) {}
    Guard(U b, U e, const volatile LONG* z) : begin(b), end(e), busy(z) {}
};

// Atomic code bytes do not protect a thread between displaced instructions.
// Enumerate through the kernel (no heap/loader activity while threads are held),
// freeze peers, and refuse an interior IP rather than rewriting its context.
struct FrozenThreads {
    HANDLE handles[512]{};
    DWORD ids[512]{};
    U count = 0;
    FrozenThreads() = default;
    FrozenThreads(const FrozenThreads&) = delete;
    FrozenThreads& operator=(const FrozenThreads&) = delete;
    ~FrozenThreads() {
        for (U i = count; i; --i) {
            ResumeThread(handles[i - 1]);
            CloseHandle(handles[i - 1]);
        }
    }
    bool Freeze(U site, U span, const Guard& guard) {
        using NextThread = LONG (NTAPI*)(HANDLE,HANDLE,ACCESS_MASK,ULONG,ULONG,PHANDLE);
        const auto nextThread = reinterpret_cast<NextThread>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
        if (!nextThread) return false;
        const DWORD self = GetCurrentThreadId();
        for (U pass = 0; pass < 16; ++pass) {
            const U previousCount = count;
            HANDLE cursor = nullptr;
            bool retained = false;
            for (;;) {
                HANDLE next = nullptr;
                const LONG status = nextThread(GetCurrentProcess(),cursor,
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    0,0,&next);
                if (cursor && !retained) CloseHandle(cursor);
                cursor = next; retained = false;
                if (status == static_cast<LONG>(0x8000001Au)) break;
                if (status < 0) return false;
                const DWORD id = GetThreadId(cursor);
                if (!id) { CloseHandle(cursor); return false; }
                bool known = id == self;
                for (U i = 0; !known && i < count; ++i) known = ids[i] == id;
                if (known) continue;
                if (count == 512 || SuspendThread(cursor) == static_cast<DWORD>(-1)) {
                    CloseHandle(cursor); return false;
                }
                handles[count] = cursor; ids[count++] = id; retained = true;
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(cursor,&context) ||
                    (context.Eip > site && context.Eip < site + span) ||
                    (guard.begin != guard.end && context.Eip >= guard.begin && context.Eip < guard.end)) return false;
            }
            if (count == previousCount) return guard.busy == nullptr ||
                _InterlockedCompareExchange(const_cast<volatile LONG*>(guard.busy),0,0) == 0;
        }
        return false;
    }
};

template <class OnSwapped>
inline bool Swap8(U site, const unsigned char* from, const unsigned char* to, U span, const Guard& guard, OnSwapped&& onSwapped) {
    LONG64 before, after;
    memcpy(&before,from,8); memcpy(&after,to,8);
    FrozenThreads peers;
    if (!peers.Freeze(site,span,guard)) return false;
    DWORD protection;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8,PAGE_EXECUTE_READWRITE,&protection)) return false;
    const bool changed = _InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(static_cast<uintptr_t>(site)),after,before) == before;
    DWORD ignored;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8,protection,&ignored);
    FlushInstructionCache(GetCurrentProcess(),reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8);
    if (changed) onSwapped();
    return changed;
}
} // namespace kntwr_entry_patch
#endif
