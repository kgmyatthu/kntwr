// Pure decision rules for the tick placement topology and the worker-pool clamp (kntwr_runtime.cpp CpuTopologyInit / StartImpl).
// Header-only and free of Win32 so tests/native_topology_oracle.cpp exercises the exact code the runtime runs.
#pragma once
#include <cstdint>

namespace kntwr_topology {

// The runtime is a 32-bit WOW64 process: a DWORD_PTR affinity mask is 32 bits and only the process's own processor group can be
// addressed. CPU-set entries with Group != 0 or LogicalProcessorIndex >= kMaskBits therefore cannot be pinned to.
constexpr unsigned kMaskBits = 32;
constexpr unsigned kCensusSlots = 64; // census table width: group-0 processor numbers 0..63
// A tick hard-pinned to fewer P logical processors than this loses to the scheduler under contention: do not pin.
constexpr unsigned kMinPinnedP = 4;
// Workers kept free for the tick and render threads.
constexpr unsigned kReservedLps = 2;

inline unsigned PopCount(uint32_t mask) {
    unsigned n = 0;
    for (; mask; mask &= mask - 1) ++n;
    return n;
}

// Pool/contact/class-wrapper worker count: min(configured, max(1, usableLps - kReservedLps)). Zero stays zero (no pool requested);
// usableLps == 0 (affinity unreadable) leaves the request unchanged.
inline uint32_t ClampWorkers(uint32_t configured, uint32_t usableLps) {
    if (!configured || !usableLps) return configured;
    const uint32_t cap = usableLps > kReservedLps + 1 ? usableLps - kReservedLps : 1u;
    return configured < cap ? configured : cap;
}

// Partial coverage: some CPU-set entry lies outside the addressable 32-bit group-0 mask.
inline bool PartialCoverage(bool sawOtherGroup, bool sawHighIndex) { return sawOtherGroup || sawHighIndex; }

// The core-class census (cpuECore, indexed by GetCurrentProcessorNumber(), which is group-relative) is only meaningful when every
// entry belongs to group 0; any other group makes the current-processor number ambiguous, so the census stays off.
inline bool CensusUsable(bool sawGroup0, bool sawOtherGroup) { return sawGroup0 && !sawOtherGroup; }

// Pin decision: complete group-0 mask coverage, two efficiency classes, both usable under the process affinity, and at least
// kMinPinnedP logical processors in the usable P mask (also rejects an empty P mask explicitly).
inline bool PinUsable(bool partial, unsigned minClass, unsigned maxClass, uint32_t pMask, uint32_t eMask) {
    return !partial && minClass != maxClass && pMask != 0 && eMask != 0 && PopCount(pMask) >= kMinPinnedP;
}

} // namespace kntwr_topology
