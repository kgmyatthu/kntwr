// Process-heap allocation callsite census (--alloc-census) and leak fix (--alloc-fix).
// Hooks the Provider[0..3] vtable slots at 0x13EDE3C (0xFF8350 alloc) and 0x13EDE40 (0xFF7FB0 free),
// records (ptr -> callsite_id, size) in a VirtualAlloc open-addressing table (4M pointer slots, 8K callsite slots),
// and publishes the top 128 callsites by live_bytes growth since activation into alloc_census_words every 10 s.
#pragma once
#include <stdint.h>
#include "ntw2_runtime.h"
#include "clones/ntw2_clones.h"

namespace ntw2_alloc_census {

using U = uint32_t;

constexpr U kVersion = 1u;
constexpr U kModeOff = 0u;
constexpr U kModeCensus = 1u;
constexpr U kModeFix = 2u;

// Provider[0..3] vtable at 0x13EDE38 (.rdata):
//   +0x00 (0x13EDE38): 0x00FF7D30 scalar deleting dtor
//   +0x04 (0x13EDE3C): 0x00FF8350 alloc(out_pair*, size) -> __thiscall ret 8
//   +0x08 (0x13EDE40): 0x00FF7FB0 free(ptr) -> __thiscall ret 4
constexpr U kProviderVtable = 0x13EDE38u;
constexpr U kProviderAllocSlot = 0x13EDE3Cu;
constexpr U kProviderFreeSlot = 0x13EDE40u;
constexpr U kProviderAllocOriginal = 0x00FF8350u;
constexpr U kProviderFreeOriginal = 0x00FF7FB0u;
constexpr U kSlotCount = 2u;

// Table capacities: 4,194,304 live pointer slots (32 MiB) + 8,192 callsite slots (256 KiB).
constexpr U kPtrCapacity = 1u << 22;
constexpr U kPtrMask = kPtrCapacity - 1u;
constexpr U kCallsiteCapacity = 8192u;
constexpr U kCallsiteMask = kCallsiteCapacity - 1u;

enum HeaderWord : U {
    HVersion = 0,
    HEnabled = 1,
    HMode = 2,
    HPtrCapacity = 3,
    HPtrUsed = 4,
    HCallsiteCapacity = 5,
    HCallsiteUsed = 6,
    HOverflowCount = 7,
    HHookFaults = 8,
    HLiveBytes = 9,
    HLiveCount = 10,
    HBaselineBytes = 11,
    HDriftBytes = 12,
    HPeakLiveBytes = 13,
    HTotalAllocs = 14,
    HTotalFrees = 15,
    HUntrackedFrees = 16,
    HReentrantSkips = 17,
    HSamples = 18,
    HFixFreedBlocks = 19,
    HFixFreedBytes = 20,
    HFixActiveSites = 21,
    HStorageBytes = 22,
    HSlotsOwned = 23,
};

enum RowWord : U {
    RCallsiteVa = 0,
    RSizeClass = 1,
    RLiveBytes = 2,
    RLiveCount = 3,
    RAllocs = 4,
    RFrees = 5,
    RPeakLiveBytes = 6,
    RReserved = 7, // caller2_va (2nd return address up the stack, preferred base)
};

struct Binding {
    U image_base;
    U image_size;
    U delta;
    U mode; // kModeCensus (1) or kModeFix (2)
    const ntw2_clone_set* clones;
};

U RequiredStorageBytes();
U StorageBytes();
U AllocGateAddress();
U FreeGateAddress();

void Configure(U imageBase, U imageSize, U delta, U mode);
void Reset();
bool Start(const Binding& binding);
void Stop();
void Snapshot(volatile U* words, U slotsOwned, bool force = false);

// Phase B accounting helpers for --alloc-fix hooks/clones.
void RecordFixFreed(U blocks, U bytes, U siteBit = 1u);
void ReclaimTick(U model);
U CurrentMode();
} // namespace ntw2_alloc_census
