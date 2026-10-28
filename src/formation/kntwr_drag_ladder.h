// --drag-ladder file-count policy (header-only). v6 floors the stock FilesPerRow return
// (ntw_formation_layout::FilesPerRow) with LadderFiles; it does not rewrite width.
#pragma once
#include <cstdint>

namespace kntwr_drag_ladder {

constexpr uint32_t kLadderStep = 60;
// float at [0x1318030] (0x3A83126F): the engine's file-count slack, identical to kFileSlack in native_formation_layout.cpp.
constexpr float kFileSlack = 0.001f;

// Snapped file count: <= kLadderStep unchanged, above it the largest multiple of kLadderStep not exceeding `files`.
inline uint32_t LadderFiles(uint32_t files) {
    return files <= kLadderStep ? files : kLadderStep * (files / kLadderStep);
}

} // namespace kntwr_drag_ladder
