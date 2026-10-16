// Worker-safe port of the original Napoleon Total War (x86, SHA-256 13fcab62...cbad4) formation slotting.
//
// Recovered chain (static VAs at preferred base 0x400000):
//   0x555CA0 Formation::ApplySlots(layout, a, b, c, flag)
//     -> layout->vtable[+0x24] generator fills the slot vector (36-byte records)
//     -> 0x18F0A00 mod wrapper (pre-hook 0x18F0200, original 0x5373F0, post-hook 0x18F1200)
//        0x5373F0 builds the {man, slot, cost} entry vector and calls the pair-swap
//        solver 0x502770 (via the 0x18F0D00 shim, which suppresses it when the mod post-hook owns it)
//     -> formation+0x1C man array := entry order; 0x557C80 refreshes formation+0x2784.
//
// This file contains no globals, no allocation and no pointers into the game.  All inputs are
// contiguous per-unit snapshots; all outputs are written to caller-provided contiguous storage.
// Floating-point operations are written in the exact order of the x86 SSE code so results are
// bit-identical (build with /fp:strict or /fp:precise, /arch:SSE2, no FMA contraction).
#pragma once
#include <cstdint>

#include <cstddef>
namespace ntw_formation {

constexpr uint32_t kNone = 0xFFFFFFFFu;   // null man / null slot pointer

// Constants read from the pinned image (.rdata).  Addresses are preferred-base VAs.
struct Constants {
    float pairWeight = 0.5f;               // [0x1318038]
    float one = 1.0f;                      // [0x1318048]
    float zero = 0.0f;                     // [0x131A7A4]
    float thresholdFlag1 = 3.4028235e38f;  // [0x1325DB4] 0x7F7FFFFF
    float thresholdFlag0 = 16.0f;          // [0x1325D48]
    float noSlotCost = 3.4028235e38f;      // solver context [+4] built by 0x5373F0 / 0x18F1200
    float defaultCost = 0.0f;              // solver context [+0]
    float refreshDistance = 4.0f;          // 0x40800000 passed to 0x557C80 by 0x555CA0
    uint32_t maxModMen = 0x1000;           // pre-hook bound
    uint32_t markerBase = 0x57460000u;     // man+0x66C identifier base
};

// Snapshot of one unit's formation.  Man arrays are indexed in formation+0x1C order (man index i).
struct SlotInput {
    uint32_t men = 0;                      // formation+0x18
    uint32_t slots = 0;                    // generator vector count (slotVec+8)
    const float* manX = nullptr;           // man+0x48
    const float* manZ = nullptr;           // man+0x50
    const uint16_t* manAngle = nullptr;    // man+0x64
    const uint8_t* manAnchored = nullptr;  // man->vtable[+0xF4]() : vtable[+0xA8]() != 0
    const uint8_t* manMarker = nullptr;    // 0..2 when vtable==0x134841C and man+0x66C-0x57460000 in 0..2, else 0xFF
    const uint8_t* manSkipDistance = nullptr; // man+0x1A8 != 0 (excluded from the 0x557C80 average)
    // Slot records resolved to world coordinates through 0x80E9D0 (record+4 position object, +0x14 parent).
    const float* slotX = nullptr;
    const float* slotZ = nullptr;
    const uint16_t* slotAngle = nullptr;   // record+0x18
    const float* angleTable = nullptr;     // 65536 {sin,cos} float pairs at 0x176CFF8
    uint8_t unitFlag = 0;                  // 0x54C8B0(formation+0x510)  (bVar6 in 0x5373F0)
    uint8_t flagParam = 0;                 // 0x18F0A00 argument [ebp+0xC] / 0x5373F0 param_2
    int32_t layoutIndex = -1;              // 0x18F0A00 argument [ebp+0x14] / 0x5373F0 param_4
    uint8_t modEligible = 0;               // layoutIndex==-1 && layout vtable[+0x24]==0x18ED200 && unit+0x2C chain has [+0x1C]==2
};

struct Entry {                             // identical to the 12-byte records at formation+0x524
    uint32_t man;                          // man index or kNone
    uint32_t slot;                         // slot index or kNone (native: pointer = data + 0x24*idx)
    float cost;
};

enum Status : int {
    kOk = 0,
    kNoOp = 1,            // formation has no men: 0x5373F0 returns before touching the entry vector
    kBadInput = 2,        // slots < men, slot index out of range, etc.; run the original native path
};

struct SlotResult {
    uint32_t entryCount = 0;               // new formation+0x18 (= entry vector count)
    uint8_t modPreHook = 0;                // 0x18F0200 returned 1
    uint8_t solverRan = 0;
    uint8_t solverDone = 0;                // return value of the last solver call
    uint32_t solverIterations = 0;
    // 0x557C80 results
    uint32_t distanceCount = 0;
    float distanceSum = 0.0f;
    uint8_t refreshZero = 0;               // formation+0x2784 := 0 (else := unit tick)
};

// scratch must hold at least `men` uint32_t.  entries must hold at least `men` Entry.
// On kOk the entries are in final formation+0x524 order; entries[k].man is the new formation+0x1C[k].
int AssignUnit(const SlotInput& in, const Constants& c, Entry* entries, uint32_t* scratch, SlotResult* out);

// Exact port of 0x5281D0 (cost) for harness comparisons.
float PairCost(const SlotInput& in, const Constants& c, uint32_t man, uint32_t slot);

// Exact port of 0x502770.  `list` needs (end-begin) uint32_t.  Returns the native return value (done flag).
uint8_t Solver(const SlotInput& in, const Constants& c, float defaultCost, float noSlotCost,
               Entry* begin, Entry* end, uint32_t iterationLimit, float threshold, uint32_t* list,
               uint32_t* iterationsRun);

// Port of 0x557C80 (distance statistic that decides formation+0x2784).  `order` = final entry vector, or nullptr to use
// formation order (man k vs slot k) as the periodic path 0x557BC0 -> 0x557C20 does.  Fills distanceCount/Sum/refreshZero.
void RefreshStat(const SlotInput& in, const Constants& c, const Entry* order, uint32_t count, SlotResult* out);

// One contiguous, 16-byte aligned block per unit (SoA).  The main thread gathers into the views, a worker runs
// AssignUnit() on them, the main thread commits `entries`.  No other memory is touched by the kernel.
struct ArenaViews {
    float* manX; float* manZ; uint16_t* manAngle;
    uint8_t* manAnchored; uint8_t* manMarker; uint8_t* manSkipDistance;
    float* slotX; float* slotZ; uint16_t* slotAngle;
    Entry* entries; uint32_t* scratch;
};
size_t ArenaBytes(uint32_t men, uint32_t slots);
void BindArena(void* memory, uint32_t men, uint32_t slots, ArenaViews* views);   // memory: ArenaBytes() bytes, 16-aligned

}  // namespace ntw_formation
