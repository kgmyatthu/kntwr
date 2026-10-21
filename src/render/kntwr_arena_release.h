// Levers 4a, 4b, and 7: render pose/scene 1 MB arena release + in-battle high-water trim
// + process/provider heap resource optimization (HeapOptimizeResources).
#pragma once
#include <stdint.h>
#include "kntwr_runtime.h"

namespace kntwr_arena_release {

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

static_assert(kWHeapOptTotalUs + 1u == KNTWR_ARENA_WORDS, "arena_words enum matches KNTWR_ARENA_WORDS");

// Arm hooks and reset per-generation counters on battle activation (slots kept by Stop(KeepHooks) stay installed).
// Returns false only if vtable slot protection/patching fails when flags are active.
bool Start(uint32_t image_base, uint32_t va_watch_flags, uint32_t root, uint32_t main_thread_id);

// Why the runtime deactivates. Only Release frees arena memory, and only when the battle world is gone: the pose/scene/scratch blocks stay
// referenced by live render state (per-frame mesh-item containers, previous-frame poses) for as long as the world renders.
enum class StopMode : uint32_t {
    Release,    // the battle world is gone: teardown release (Lever 4a), restore the vtable slots, heap optimization
    KeepHooks,  // the same live world went dormant (the scheduler flag drops at >1x): stop trimming, keep the slots installed so the
                // render-root destructor gate (or a later Stop(Release)) still releases at the real battle end
    Detach      // the runtime shuts down with the world alive: restore the slots, free nothing
};

// Lever 4a teardown (Release only), HeapOptimizeResources (Lever 7), then restore vtable slots (Release, Detach) before
// StopModules() samples final counters.
void Stop(StopMode mode);

// True while Start's vtable slots are owned (no Release/Detach has restored them).
bool HooksInstalled();

// Copy current counters into kntwr_state.arena_words[0..31].
void Sample(uint32_t* out_words);

// Called from VaWatchSample() with current ullAvailVirtual in MiB; triggers Lever 7
// when avail_mib < 640 MiB (rate-limited to at most once per 60 s).
void OnVaWatch(uint32_t avail_mib);

} // namespace kntwr_arena_release
