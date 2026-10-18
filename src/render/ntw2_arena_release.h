// Levers 4a, 4b, and 7: render pose/scene 1 MB arena release + in-battle high-water trim
// + process/provider heap resource optimization (HeapOptimizeResources).
#pragma once
#include <stdint.h>
#include "ntw2_runtime.h"

namespace ntw2_arena_release {

enum Word : uint32_t {
    kWFlagsActive           = 0,
    kWFramesObserved        = 1,
    kWPosedMenLast          = 2,
    kWPosedMenPeak          = 3,
    kWWorklistMenLast       = 4,
    kWSceneBlocksCur        = 5,
    kWSceneBlocksUsed       = 6,
    kWSceneBlocksPeak       = 7,
    kWPose0BlocksCur        = 8,
    kWPose1BlocksCur        = 9,
    kWPoseBlocksUsed        = 10,
    kWPoseBlocksPeak        = 11,
    kWScratchBlocksCur      = 12,
    kWScratchBlocksUsed     = 13,
    kWScratchBlocksPeak     = 14,
    kWQuadtreeBlocksCur     = 15,
    kWTrimEvents            = 16,
    kWTrimBlocksFreed       = 17,
    kWTrimBytesFreed        = 18,
    kWTeardownReleases      = 19,
    kWTeardownSceneBlocks   = 20,
    kWTeardownPoseBlocks    = 21,
    kWTeardownScratchBlocks = 22,
    kWTeardownBlocksFreed   = 23,
    kWTeardownBytesFreed    = 24,
    kWHeapOptCalls          = 25,
    kWHeapOptWatermarkCalls = 26,
    kWHeapOptHeapsOk        = 27,
    kWHeapOptAvailBeforeMb  = 28,
    kWHeapOptAvailAfterMb   = 29,
    kWHeapOptReclaimedKb    = 30,
    kWHeapOptTotalUs        = 31,
};

static_assert(kWHeapOptTotalUs + 1u == NTW2_ARENA_WORDS, "arena_words enum matches NTW2_ARENA_WORDS");

// Arm hooks and reset per-generation counters on battle activation.
// Returns false only if vtable slot protection/patching fails when flags are active.
bool Start(uint32_t image_base, uint32_t va_watch_flags, uint32_t root, uint32_t main_thread_id);

// Execute battle-teardown arena release (Lever 4a) and HeapOptimizeResources (Lever 7),
// then restore vtable slots before StopModules() samples final counters.
void Stop();

// Copy current counters into ntw2_state.arena_words[0..31].
void Sample(uint32_t* out_words);

// Called from VaWatchSample() with current ullAvailVirtual in MiB; triggers Lever 7
// when avail_mib < 640 MiB (rate-limited to at most once per 60 s).
void OnVaWatch(uint32_t avail_mib);

} // namespace ntw2_arena_release
