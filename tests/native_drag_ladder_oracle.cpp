// --drag-ladder file-count policy (src/formation/kntwr_drag_ladder.h): pure integer arithmetic, no image, no live process.
// Checks LadderFiles against an independent reference. The FilesPerRow port the hook floors is covered by
// native_drag_ladder_hook_oracle.cpp (stock body == layout port == hooked-then-laddered).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "formation/kntwr_drag_ladder.h"

using namespace kntwr_drag_ladder;

static unsigned failures;
#define CHECK(cond) do { if (!(cond)) { ++failures; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } } while (0)

static bool Same(float a, float b) { return std::memcmp(&a, &b, sizeof a) == 0; }

// Reference snapped count, from the policy text: <= 60 keep; otherwise 60 * floor(files / 60).
static uint32_t RefSnap(uint32_t files) {
    if (files <= 60) return files;
    uint32_t k = 0;
    while ((k + 1) * 60 <= files) ++k;
    return k * 60;
}

int main() {
    CHECK(kLadderStep == 60u);
    CHECK(Same(kFileSlack, 0.001f));

    for (uint32_t f = 1; f <= 1000; ++f) CHECK(LadderFiles(f) == RefSnap(f));
    CHECK(LadderFiles(60) == 60 && LadderFiles(61) == 60 && LadderFiles(119) == 60 && LadderFiles(120) == 120 && LadderFiles(179) == 120 && LadderFiles(180) == 180);
    CHECK(LadderFiles(0) == 0);
    CHECK(LadderFiles(1) == 1 && LadderFiles(59) == 59);
    CHECK(LadderFiles(0xFFFFFFFFu) == 60u * (0xFFFFFFFFu / 60u));

    // Snapped count never exceeds the input, is a 60-multiple above 60, and loses less than one step.
    for (uint32_t f = 61; f <= 5000; ++f) {
        const uint32_t s = LadderFiles(f);
        CHECK(s >= 60 && s % 60 == 0 && s <= f && f - s < 60);
        CHECK(LadderFiles(s) == s);   // idempotent
    }

    if (failures) { std::printf("native_drag_ladder_oracle: %u failure(s)\n", failures); return 1; }
    std::printf("native_drag_ladder_oracle: ok\n");
    return 0;
}
