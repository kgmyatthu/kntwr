#pragma once
#include <windows.h>
#include <stdint.h>
#include <string.h>

// Readability proofs for the site-6 brain paths (dispatch witness, worker capture, owner commit).
//
// A range is proven committed and readable with VirtualQuery before any byte of it is touched, so a speculative
// read never raises a first-chance access violation (the runtime crash recorder is a first-chance vectored
// handler). Proven runs are kept as a sorted set of disjoint address intervals (adjacent runs merge): a lookup is
// the last hit or one binary search, and one VirtualQuery proves its whole run however large it is. The former
// per-64-KiB-granule hash registered up to 128 granules per query and cleared itself after 3072 insertions, so a
// few dozen multi-megabyte heap segments thrashed it (live cy-quiet1: 6.4k owner, 5.7k witness and 10.4k worker
// VirtualQuery calls per stage at ~0.5 us each); the interval set issues about one query per distinct run and stage.
//
// Single-threaded per table. Clear() at every stage start: region attributes only shrink through a native
// free/decommit, and a stale proof inside one stage is still backed by SEH where the callers read.
namespace ntw2_region {
using U = uint32_t;
constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
struct Table {
    static constexpr U kRuns = 4096;
    // Sorted by base, pairwise disjoint and non-adjacent; end > base (a run ending at 4 GiB is never stored).
    struct Run { U base, end; };
    Run runs[kRuns];
    U count, hint; // hint: index of the most recent hit or insertion
    void Clear() { count = 0; hint = 0; }
    // Index of the run containing `at`, else kRuns.
    U Find(U at) {
        if (hint < count && at - runs[hint].base < runs[hint].end - runs[hint].base) return hint;
        U lo = 0, hi = count; // first run whose base is above `at`
        while (lo < hi) { const U mid = (lo + hi) >> 1; if (runs[mid].base <= at) lo = mid + 1; else hi = mid; }
        if (lo && at < runs[lo - 1].end) return hint = lo - 1;
        return kRuns;
    }
    // Adds [base, end), merging every run it overlaps or touches. A full set starts over.
    void Insert(U base, U end) {
        U lo = 0, hi = count;
        while (lo < hi) { const U mid = (lo + hi) >> 1; if (runs[mid].end < base) lo = mid + 1; else hi = mid; }
        U last = lo; // runs [lo, last) overlap or touch [base, end)
        while (last < count && runs[last].base <= end) ++last;
        if (lo == last) {
            if (count == kRuns) { Clear(); lo = 0; }
            memmove(runs + lo + 1, runs + lo, (count - lo) * sizeof(Run));
            ++count;
        } else {
            if (runs[lo].base < base) base = runs[lo].base;
            if (runs[last - 1].end > end) end = runs[last - 1].end;
            memmove(runs + lo + 1, runs + last, (count - last) * sizeof(Run));
            count -= last - lo - 1;
        }
        runs[lo] = {base, end};
        hint = lo;
    }
    static bool ReadableInfo(const MEMORY_BASIC_INFORMATION& m) {
        return m.State == MEM_COMMIT && !(m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (m.Protect & kReadable);
    }
    // True when [address, address + bytes) lies in committed readable memory (several regions allowed).
    // `queries` counts VirtualQuery calls. VirtualQuery describes the run of equal pages starting at the QUERIED page,
    // so a proven run would not cover lower objects of the same allocation; one more query at the allocation base
    // recovers the run's true start when the whole prefix shares the attributes (the common heap-segment case).
    bool Readable(U address, U bytes, U& queries) {
        const U last = address + bytes;
        if (!address || last < address) return false;
        for (U at = address; at < last;) {
            const U i = Find(at);
            if (i != kRuns) { at = runs[i].end; continue; }
            MEMORY_BASIC_INFORMATION m;
            ++queries;
            if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(at)), &m, sizeof(m)) || !ReadableInfo(m)) return false;
            U base = static_cast<U>(reinterpret_cast<uintptr_t>(m.BaseAddress));
            const U end = base + static_cast<U>(m.RegionSize);
            if (end <= at) return false;
            const U allocation = static_cast<U>(reinterpret_cast<uintptr_t>(m.AllocationBase));
            if (allocation && allocation < base) {
                MEMORY_BASIC_INFORMATION head;
                ++queries;
                if (VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(allocation)), &head, sizeof(head)) &&
                    ReadableInfo(head) && static_cast<U>(reinterpret_cast<uintptr_t>(head.BaseAddress)) + static_cast<U>(head.RegionSize) == end)
                    base = allocation;
            }
            Insert(base, end);
            at = end;
        }
        return true;
    }
};
} // namespace ntw2_region
