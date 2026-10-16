#include "native_grid_probation.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <intrin.h>
#include "../ntw2_clones.h"

namespace ntw2_grid_probation {
namespace {

Binding g_binding;
volatile LONG g_lock;        // caller-table updates and snapshots (bounded linear scan under a spinlock)
volatile LONG g_state;       // StateValue
PVOID g_handler;             // registered once; the pinned runtime keeps it for the process lifetime
U g_words[kHeaderWords];
U g_rows[kCallers][kRowWords];

// Active armed span [pageLo, pageHi) (page-aligned) and the logical array range inside it. Identity fields are
// mutated only by Retire(), which first moves them to the graveyard and drains in-flight handlers.
volatile U g_pageLo, g_pageHi;
U g_arrayLo, g_arrayBytes;
U g_allocBase;               // AllocationBase of the array's first page, recorded at arm time
volatile LONG g_epoch;       // bumped before every retire; handlers revalidate against it
volatile LONG g_inflight;    // handlers currently inside the active-span path
// Retired spans stay answerable: a fault raised while armed may be dispatched after retirement, and the
// restored instruction must still resume instead of dying as an unhandled access violation.
struct Graveyard { U lo, hi, alloc; };
volatile Graveyard g_graveyard[4];
volatile LONG g_graveyardNext;
volatile LONG g_probeActive; // the synthetic lifecycle range owns the active span instead of the game array

struct Layout {
    U base, bytes;
    U pageLo, pageHi;        // armable span: interior pages only (edge partial pages are never armed)
    U allocBase, allocBytes;
    U uncovered;             // array bytes on unarmed edge pages (head + tail partial pages)
};

void Bump(U word) { _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_words[word])); }
void Lock() {
    while (_InterlockedCompareExchange(&g_lock, 1, 0)) YieldProcessor();
}
void Unlock() { _InterlockedExchange(&g_lock, 0); }
U Pointer(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void* Address(U value) { return reinterpret_cast<void*>(static_cast<uintptr_t>(value)); }

bool Query(U address, MEMORY_BASIC_INFORMATION& m) {
    return VirtualQuery(Address(address), &m, sizeof(m)) == sizeof(m);
}
bool Protect(U lo, U hi, DWORD prot) {
    if (lo >= hi) return true;
    DWORD old = 0;
    return VirtualProtect(Address(lo), static_cast<SIZE_T>(hi - lo), prot, &old) != 0;
}
U Microseconds(const LARGE_INTEGER& begin) {
    LARGE_INTEGER end, freq;
    QueryPerformanceCounter(&end);
    QueryPerformanceFrequency(&freq);
    return static_cast<U>((end.QuadPart - begin.QuadPart) * 1000000 / freq.QuadPart);
}
void Toggle(U word, const LARGE_INTEGER& begin) {
    const U us = Microseconds(begin);
    _InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&g_words[word]), static_cast<LONG>(us));
    if (us > g_words[MaxToggleUs]) g_words[MaxToggleUs] = us;
}

// Committed extent of the allocation that owns `address`, walking one VirtualQuery run at a time (reporting only).
bool AllocationExtent(U address, U* allocBase, U* allocEnd) {
    MEMORY_BASIC_INFORMATION m = {};
    if (!Query(address, m) || m.State != MEM_COMMIT) return false;
    const U base = Pointer(m.AllocationBase);
    U end = Pointer(m.BaseAddress) + static_cast<U>(m.RegionSize);
    for (;;) {
        MEMORY_BASIC_INFORMATION next = {};
        if (!end || !Query(end, next) || Pointer(next.AllocationBase) != base || next.State != MEM_COMMIT) break;
        const U nextEnd = Pointer(next.BaseAddress) + static_cast<U>(next.RegionSize);
        if (nextEnd <= end) break;
        end = nextEnd;
    }
    *allocBase = base;
    *allocEnd = end;
    return true;
}

// Header chain [manager]->+8->+A4 (620AD0 layout: +0 cell-head array, +4 head count, +8 row shift, +C rows,
// +14 coordinate clamp). Any dangling pointer declines; nothing here touches the armed array itself.
bool ReadBase(void* manager, U* base, U* count) {
    __try {
        const U root = *static_cast<U*>(manager);
        const U model = root ? *reinterpret_cast<U*>(static_cast<uintptr_t>(root + 8)) : 0;
        const U grid = model ? *reinterpret_cast<U*>(static_cast<uintptr_t>(model + 0xA4)) : 0;
        if (!grid) return false;
        *base = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid));
        *count = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid + 4));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool ReadLayout(void* manager, Layout& out) {
    U count = 0, shift = 0, clamp = 0;
    __try {
        const U root = *static_cast<U*>(manager);
        const U model = root ? *reinterpret_cast<U*>(static_cast<uintptr_t>(root + 8)) : 0;
        const U grid = model ? *reinterpret_cast<U*>(static_cast<uintptr_t>(model + 0xA4)) : 0;
        if (!grid) return false;
        out.base = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid));
        count = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid + 4));
        shift = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid + 8));
        clamp = *reinterpret_cast<U*>(static_cast<uintptr_t>(grid + 0x14));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    // Every head index the engine forms is (clamped z << shift) + clamped x <= (clamp << shift) + clamp; the
    // allocation holds `count` heads (rows << 10 in 620AD0), which must cover that range.
    if (shift > 20 || clamp >= (1u << shift) || !count || count > 0x4000000u || !out.base) return false;
    const unsigned long long used = (static_cast<unsigned long long>(clamp) << shift) + clamp + 1;
    if (used > count) return false;
    out.bytes = count * 4;
    const U tail = out.base + out.bytes;
    if (tail < out.base) return false;
    // Only pages the array provably owns end to end are armed. VirtualQuery boundaries do not prove exclusive
    // ownership of an engine-heap block (metadata or a neighbour block may share an edge page), so partial
    // head/tail pages always stay unarmed and their bytes are reported as uncovered.
    out.pageLo = (out.base + 0xFFFu) & ~0xFFFu;
    out.pageHi = tail & ~0xFFFu;
    if (out.pageLo >= out.pageHi) return false;
    out.uncovered = (out.pageLo - out.base) + (tail - out.pageHi);
    U allocEnd = 0;
    if (!AllocationExtent(out.base, &out.allocBase, &allocEnd)) return false;
    out.allocBytes = allocEnd - out.allocBase;
    return true;
}

// Restores every page of [lo, hi) that is still this allocation's and still PAGE_NOACCESS. Memory that was
// freed or reallocated by anyone else is never given a protection it did not have.
void RestoreSpan(U lo, U hi, U alloc) {
    U at = lo;
    while (at < hi) {
        MEMORY_BASIC_INFORMATION m = {};
        if (!Query(at, m)) break;
        U next = Pointer(m.BaseAddress) + static_cast<U>(m.RegionSize);
        if (next > hi || next <= at) next = hi;
        if (m.State == MEM_COMMIT && Pointer(m.AllocationBase) == alloc && m.Protect == PAGE_NOACCESS &&
            !Protect(at, next, PAGE_READWRITE))
            Bump(RestoreFailures);
        at = next;
    }
}

// Waits until no handler is inside the active-span path. Handlers are bounded (query + protect + row write);
// a preempted one just costs the spin.
void DrainHandlers() {
    U spins = 0;
    while (g_inflight) {
        if (++spins > 100000) { Sleep(0); spins = 0; }
        else YieldProcessor();
    }
}

// Retires the active span: restores its pages, parks its identity in the graveyard ring so faults raised while
// armed stay resumable after retirement, then clears it. Safe against concurrent handlers on other threads.
void RetireSpan() {
    const U lo = g_pageLo, hi = g_pageHi, alloc = g_allocBase;
    if (lo >= hi) return;
    RestoreSpan(lo, hi, alloc);
    g_graveyard[g_graveyardNext & 3].lo = lo;
    g_graveyard[g_graveyardNext & 3].hi = hi;
    g_graveyard[g_graveyardNext & 3].alloc = alloc;
    _InterlockedIncrement(&g_graveyardNext);
    _InterlockedIncrement(&g_epoch); // handlers entering from here on revalidate and fall to the graveyard
    DrainHandlers();
    g_pageHi = 0; // the handler stops claiming the range before the span itself is cleared
    g_pageLo = 0;
    g_arrayLo = g_arrayBytes = 0;
    g_allocBase = 0;
}

// Module class of an instruction address.
U AddressModule(U address) {
    if (address >= g_binding.image_base && address - g_binding.image_base < g_binding.image_size) return ModuleImage;
    if (g_binding.runtime_hi && address >= g_binding.runtime_lo && address < g_binding.runtime_hi) return ModuleRuntime;
    if (g_binding.clones && g_binding.clones->allocation) {
        const U base = Pointer(g_binding.clones->allocation);
        if (address >= base && address - base < g_binding.clones->allocation_bytes) return ModuleClone;
    }
    return ModuleOther;
}

// True when `address` lies right after a call instruction in the image or the clone arena (same instruction
// inventory as the runtime's crash stack attribution). Reads stay inside the owning module's range.
bool FollowsCall(U address) {
    U offset = 0;
    const U module = AddressModule(address);
    if (module == ModuleImage) offset = address - g_binding.image_base;
    else if (module == ModuleClone) offset = address - Pointer(g_binding.clones->allocation);
    else return false;
    const volatile unsigned char* p = reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(address));
    if (offset >= 5 && p[-5] == 0xE8) return true;
    if (offset >= 2 && p[-2] == 0xFF) {
        const U modrm = p[-1];
        if (modrm >= 0xD0 && modrm <= 0xD7) return true;
        if (modrm >= 0x10 && modrm <= 0x17 && modrm != 0x14 && modrm != 0x15) return true;
    }
    if (offset >= 3 && p[-3] == 0xFF) {
        const U modrm = p[-2];
        if (modrm >= 0x50 && modrm <= 0x57 && modrm != 0x54) return true;
        if (modrm == 0x14 && p[-1] == 0x24) return true;
    }
    if (offset >= 4 && p[-4] == 0xFF && p[-3] == 0x54 && p[-2] == 0x24) return true;
    if (offset >= 6 && p[-6] == 0xFF) {
        const U modrm = p[-5];
        if (modrm == 0x15 || (modrm >= 0x90 && modrm <= 0x97 && modrm != 0x94)) return true;
    }
    return offset >= 7 && p[-7] == 0xFF && p[-6] == 0x94 && p[-5] == 0x24;
}

// Caller of the trapping instruction, bounded by this thread's committed stack [esp, TEB StackBase).
// Frame first: when EBP is a plausible frame pointer (4-aligned, esp <= ebp, [ebp+4] below the stack top) and
// [ebp+4] follows a call, that word is the return address of the innermost EBP-framed function: the trapping
// function itself when it sets up EBP (0x6392C0 does), otherwise the nearest framed ancestor. Only then the
// first stack word above esp that follows a call (at most 1024 words). The scan alone can return a stale local:
// run dc-diag1 attributed 1,822,745 0x6395D0 traps to 0x10E83CD, a word left in 0x6392C0's uninitialised
// locals, while its frame return is 0x53C0E8 (0x53C060). Zero when nothing plausible is found.
U CallerCandidate(U esp, U ebp) {
    const NT_TIB* tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    const U top = Pointer(tib->StackBase);
    esp &= ~3u;
    if (!esp || top <= esp) return 0;
    if (!(ebp & 3u) && ebp >= esp && ebp < top && top - ebp >= 8u) {
        const U ret = *reinterpret_cast<const U*>(static_cast<uintptr_t>(ebp + 4u));
        if (FollowsCall(ret)) return ret;
    }
    const U words = (top - esp) / 4 > 1024 ? 1024 : (top - esp) / 4;
    const U* stack = reinterpret_cast<const U*>(static_cast<uintptr_t>(esp));
    for (U i = 0; i < words; ++i)
        if (FollowsCall(stack[i])) return stack[i];
    return 0;
}

U SiteCode() {
    const U site = *g_binding.site;
    return (site & 0x7FFFu) | (*g_binding.tick ? 0x80000000u : 0);
}

void RecordRow(U eip, U caller, U address, U isWrite, U threadClass) {
    Bump(Traps);
    Bump(address >= g_arrayLo && address - g_arrayLo < g_arrayBytes ? CellTraps : EdgeTraps);
    if (isWrite) Bump(WriteTraps);
    Bump(TrapsTick + threadClass);
    const U site = SiteCode();
    Lock();
    U empty = kCallers;
    for (U i = 0; i < kCallers; ++i) {
        U* row = g_rows[i];
        if (!row[RowEip]) { if (empty == kCallers) empty = i; continue; }
        if (row[RowEip] != eip || row[RowCaller] != caller) continue;
        ++row[RowCount];
        row[RowWrites] += isWrite;
        row[RowWhere] |= (1u << threadClass) << 8;
        row[RowLastSite] = site;
        Unlock();
        return;
    }
    if (empty == kCallers) {
        Bump(CallersDropped);
        Unlock();
        return;
    }
    U* row = g_rows[empty];
    row[RowCaller] = caller;
    row[RowWhere] = AddressModule(eip) | (AddressModule(caller) << 4) | ((1u << threadClass) << 8);
    row[RowCloneVa] = 0;
    row[RowCount] = 1;
    row[RowWrites] = isWrite;
    row[RowFirstSite] = site;
    row[RowLastSite] = site;
    row[RowEip] = eip; // the row becomes visible to the scan last
    ++g_words[CallersUsed];
    Unlock();
}
// Handles one fault against span identity (alloc): restores a still-NOACCESS page of ours and resumes, resumes a
// delayed trap on an already-restored page, and passes everything foreign through. Never restores memory whose
// allocation or protection does not match what this span recorded.
LONG HandleFault(EXCEPTION_POINTERS* info, U address, U alloc) {
    const EXCEPTION_RECORD* record = info->ExceptionRecord;
    const U page = address & ~0xFFFu;
    MEMORY_BASIC_INFORMATION m = {};
    if (!Query(page, m) || m.State != MEM_COMMIT || Pointer(m.AllocationBase) != alloc) {
        Bump(ForeignFaults); // released or reused elsewhere: never restore foreign pages
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (m.Protect == PAGE_NOACCESS) {
        if (!Protect(page, page + 0x1000u, PAGE_READWRITE)) {
            Bump(RestoreFailures);
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } else if (m.Protect != PAGE_READWRITE) {
        Bump(ForeignFaults);
        return EXCEPTION_CONTINUE_SEARCH;
    } // PAGE_READWRITE: the trap was raised before the page was restored (dispatch was delayed); resume it
    const U threadClass = g_binding.thread_class();
    const CONTEXT* context = info->ContextRecord;
    RecordRow(Pointer(record->ExceptionAddress), CallerCandidate(static_cast<U>(context->Esp), static_cast<U>(context->Ebp)),
              address, record->ExceptionInformation[0] == 1 ? 1u : 0u,
              threadClass < ThreadClasses ? threadClass : ThreadOther);
    return EXCEPTION_CONTINUE_EXECUTION;
}

// First-chance: read/write access violations inside the active span, or a retired span still in the graveyard.
LONG CALLBACK ProbationVeh(EXCEPTION_POINTERS* info) {
    const EXCEPTION_RECORD* record = info->ExceptionRecord;
    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || record->NumberParameters < 2 ||
        record->ExceptionInformation[0] > 1)
        return EXCEPTION_CONTINUE_SEARCH;
    const U address = static_cast<U>(record->ExceptionInformation[1]);
    const U lo = g_pageLo, hi = g_pageHi, alloc = g_allocBase;
    if (alloc && address >= lo && address < hi) {
        const LONG epoch = g_epoch;
        _InterlockedIncrement(&g_inflight);
        // RetireSpan bumped the epoch and drained before clearing: either the snapshot still matches the active
        // span, or the span retired underfoot and the graveyard resolves the fault instead.
        if (g_epoch == epoch && g_pageLo == lo && g_pageHi == hi && g_allocBase == alloc) {
            const LONG result = HandleFault(info, address, alloc);
            _InterlockedDecrement(&g_inflight);
            return result;
        }
        _InterlockedDecrement(&g_inflight);
    }
    for (U i = 0; i < 4; ++i) {
        const U glo = g_graveyard[i].lo, ghi = g_graveyard[i].hi, galloc = g_graveyard[i].alloc;
        if (galloc && address >= glo && address < ghi) return HandleFault(info, address, galloc);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool Arm() {
    LARGE_INTEGER begin;
    QueryPerformanceCounter(&begin);
    if (!Protect(g_pageLo, g_pageHi, PAGE_NOACCESS)) {
        Bump(RestoreFailures);
        RestoreSpan(g_pageLo, g_pageHi, g_allocBase);
        _InterlockedExchange(&g_state, StateRefused);
        return false;
    }
    Bump(Arms);
    Toggle(ArmUs, begin);
    _InterlockedExchange(&g_state, StateArmed);
    return true;
}

// Image VAs are reported at the preferred base; clone addresses as their original instruction VA.
U Preferred(U address, U* clone) {
    *clone = UINT32_MAX;
    switch (AddressModule(address)) {
    case ModuleImage: return address - g_binding.image_base + 0x400000u;
    case ModuleClone: return ntw2_clone_origin(g_binding.clones, address, clone);
    default: return address;
    }
}
} // namespace

bool Start(const Binding& binding) {
    if (!binding.image_base || !binding.image_size || !binding.site || !binding.tick || !binding.thread_class)
        return false;
    if (g_handler && g_state != StateRetired) return false; // one live detector at a time
    memset(g_words, 0, sizeof(g_words));
    memset(g_rows, 0, sizeof(g_rows));
    g_binding = binding;
    g_pageLo = g_pageHi = 0;
    g_arrayLo = g_arrayBytes = g_allocBase = 0;
    g_probeActive = 0;
    g_words[Version] = 1;
    if (!g_handler) {
        g_handler = AddVectoredExceptionHandler(1, &ProbationVeh);
        if (!g_handler) return false;
    }
    // The handler stays registered for the process lifetime (the runtime module is pinned): faults raised while
    // a span was armed can still be dispatched after that span retired and must stay resumable.
    g_words[Enabled] = 1;
    _InterlockedExchange(&g_state, StateIdle);
    return true;
}

void Stop() {
    if (g_state == StateRetired) return;
    if (g_pageLo < g_pageHi) {
        RetireSpan();
        Bump(Disarms);
    }
    g_probeActive = 0;
    _InterlockedExchange(&g_state, StateRetired);
}

void __cdecl Window(void* manager, U open) {
    if (!g_handler || !manager || g_probeActive) return;
    if (open) {
        if (g_state != StateArmed) return; // nothing armed yet (first stage) or refused
        LARGE_INTEGER begin;
        QueryPerformanceCounter(&begin);
        // The array is alive while the header still points at it: one call restores the whole span. The identity
        // stays active (no retire): the same span is re-armed at window close and delayed traps stay resumable.
        U base = 0, count = 0;
        if (ReadBase(manager, &base, &count) && base == g_arrayLo && count * 4 == g_arrayBytes) {
            if (!Protect(g_pageLo, g_pageHi, PAGE_READWRITE)) {
                Bump(RestoreFailures);
                RestoreSpan(g_pageLo, g_pageHi, g_allocBase);
            }
        } else {
            RestoreSpan(g_pageLo, g_pageHi, g_allocBase);
        }
        Bump(WindowOpens);
        Toggle(OpenUs, begin);
        _InterlockedExchange(&g_state, StateWindowOpen);
        return;
    }
    if (g_state != StateWindowOpen && g_state != StateIdle) return; // already armed, refused, or retired
    Layout layout = {};
    if (!ReadLayout(manager, layout)) {
        Bump(Refusals);
        if (g_pageLo < g_pageHi) RetireSpan();
        _InterlockedExchange(&g_state, StateIdle); // retried at the next window close
        return;
    }
    if (layout.base != g_arrayLo || layout.bytes != g_arrayBytes || layout.pageLo != g_pageLo ||
        layout.pageHi != g_pageHi || layout.allocBase != g_allocBase) {
        if (g_arrayLo) Bump(LayoutChanges);
        if (g_pageLo < g_pageHi) RetireSpan();
        g_arrayLo = layout.base;
        g_arrayBytes = layout.bytes;
        g_allocBase = layout.allocBase;
        g_pageLo = layout.pageLo;
        g_pageHi = layout.pageHi;
        g_words[ArrayBase] = layout.base;
        g_words[ArrayBytes] = layout.bytes;
        g_words[AllocationBase] = layout.allocBase;
        g_words[AllocationBytes] = layout.allocBytes;
        g_words[ArmedPages] = (layout.pageHi - layout.pageLo) / 0x1000u;
        g_words[UncoveredBytes] = layout.uncovered;
        g_words[Isolated] = layout.uncovered ? 0 : 1;
    }
    Arm();
}

bool Owns(U address) {
    return g_handler && address >= g_pageLo && address < g_pageHi;
}

void Snapshot(U out[kWords]) {
    if (!out) return;
    memcpy(out, g_words, sizeof(g_words));
    out[State] = static_cast<U>(g_state);
    U* rows = out + kHeaderWords;
    Lock();
    memcpy(rows, g_rows, sizeof(g_rows));
    Unlock();
    for (U i = 0; i < kCallers; ++i) {
        U* row = rows + i * kRowWords;
        if (!row[RowEip]) continue;
        U clone = UINT32_MAX, callerClone = UINT32_MAX;
        const U raw = row[RowEip];
        row[RowEip] = Preferred(raw, &clone);
        if (clone != UINT32_MAX) {
            row[RowCloneVa] = raw;
            row[RowWhere] = (row[RowWhere] & 0xFFFFu) | ((clone + 1) << 16);
        }
        if (row[RowCaller]) row[RowCaller] = Preferred(row[RowCaller], &callerClone);
    }
}

bool Probe(void* base, U bytes) {
    if (!g_handler) return false;
    if (!base || !bytes) {
        if (!g_probeActive) return false;
        RetireSpan();
        Bump(Disarms);
        g_probeActive = 0;
        _InterlockedExchange(&g_state, StateIdle);
        return true;
    }
    if (g_probeActive || g_state != StateIdle || g_pageLo < g_pageHi) return false; // the game array owns the span
    const U lo = Pointer(base) & ~0xFFFu;
    const U hi = (Pointer(base) + bytes + 0xFFFu) & ~0xFFFu;
    MEMORY_BASIC_INFORMATION m = {};
    if (!Query(lo, m) || m.State != MEM_COMMIT || m.Protect != PAGE_READWRITE || m.Type != MEM_PRIVATE ||
        Pointer(m.BaseAddress) + static_cast<U>(m.RegionSize) < hi)
        return false;
    g_probeActive = 1;
    g_arrayLo = Pointer(base);
    g_arrayBytes = bytes;
    g_allocBase = Pointer(m.AllocationBase);
    g_pageLo = lo;
    g_pageHi = hi;
    g_words[ArrayBase] = g_arrayLo;
    g_words[ArrayBytes] = bytes;
    g_words[AllocationBase] = g_allocBase;
    g_words[AllocationBytes] = static_cast<U>(m.RegionSize);
    g_words[ArmedPages] = (hi - lo) / 0x1000u;
    g_words[UncoveredBytes] = 0;
    g_words[Isolated] = 1;
    if (!Arm()) {
        RetireSpan();
        g_probeActive = 0;
        _InterlockedExchange(&g_state, StateIdle);
        return false;
    }
    Bump(ProbeArms);
    return true;
}
} // namespace ntw2_grid_probation
