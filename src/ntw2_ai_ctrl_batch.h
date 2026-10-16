#ifndef NTW2_AI_CTRL_BATCH_H
#define NTW2_AI_CTRL_BATCH_H
// --ai-ctrl-*: the controller's node-scoring batch (analysis/native-ai-controller-plan.md sections 1-4).
//
// A batch is the interval inside the cloned assignment loop 0x749090 that starts right after one node's native refresh
// (N->vt+0x30 at 0x749137) and ends at the next refresh, the assignment publish (0x7CF3F0), a foreign scorer/callback or the
// function exit. Inside it nothing writes any input of the seven-counter histogram 0x749D90 (unit +B41/+B44, type class/subtype,
// the list P+0x74/+0x78): the known scorer/getter/eligibility helpers are read-only and the top-two updates are private scratch.
// ONE place detects the boundaries (the gates below); caches elsewhere (histogram here, geometry in ntw2_ai_ctrl_geometry) are
// valid only while `open` and the epoch is unchanged. Owner (tick) thread only: no worker ever calls into this module, native
// call order is preserved, nothing reads a clock.
#include <stdint.h>
#include "ntw2_runtime.h" // NTW2_AI_CTRL_{CENSUS,HISTOGRAM,GEOMETRY,VERIFY}

struct AiCtrlBatch {
    uint32_t epoch; // increments at every begin AND every end (odd = open)
    void* P;        // planner ([controller+0x2C])
    void* N;        // scorer node being scored
    void* C;        // scorer context (P+0x68; +0xC count, +0x10 unit array alias the planner unit list)
    void* R;        // resolved region/scoring object, published by the geometry slice (ai_ctrl_batch_set_region), else null
    int open;
};
enum AiCtrlEnd { AI_CTRL_END_ASSIGN = 1, AI_CTRL_END_REFRESH = 2, AI_CTRL_END_CALLBACK = 3, AI_CTRL_END_EXIT = 4 };
// Modes are ntw2_config::ai_ctrl_flags (NTW2_AI_CTRL_*): CENSUS is shadow-only, HISTOGRAM serves the seven counters from a private
// per-batch copy, GEOMETRY is the geometry slice, VERIFY recomputes native for every served value (mismatch -> native value, latch off).

const AiCtrlBatch* ai_ctrl_batch_current(void);
void ai_ctrl_batch_begin(void* P, void* N, void* C);
void ai_ctrl_batch_end(int reason);
// Retire callbacks run at every end of an open batch with the batch's BEGIN epoch (before the epoch increments).
void ai_ctrl_batch_register_retire(void (*fn)(uint32_t epoch));
void ai_ctrl_batch_set_region(void* R);
uint32_t ai_ctrl_batch_flags(void); // NTW2_AI_CTRL_* currently live (latched-off features removed)

namespace ntw2_ai_ctrl {
typedef uint32_t U;
// Status row words 0..15 (A half). Words 16..31 are the geometry half (ntw2_ai_ctrl_geometry::FillStatus).
enum Word : U {
    WBatches, WScorerCalls, WEligible, WHistCalls, WHistServed, WHistMismatch, WTransitions, WRepeatChanged,
    WEndAssign, WEndRefresh, WEndCallback, WEndExit, WMaxScorerBatch, WHistOutside, WHistFirst, WFlags,
    kAWords = 16, kWords = 32
};
// Exact port of the 181-byte leaf 0x749D90 (`ECX=out[7]`, stack C, stack byte filter, RET 8): out[0..6] = other(2), (2,4), (2,8),
// (2,13), other(0), (0,4), (0,8). `eligible` (optional) counts the list units that pass the filter (all when filter == 0).
void Histogram(U C, U filter, U out[7], U* eligible);
// Per-batch operation. `delta` is the image relocation; `scorerClone` the AI_CTRL_SCORER clone entry. Clears counters, the cache and
// the retire callbacks: runtime order is Reset -> geometry Configure (registers its retire) -> geometry Bind.
void Reset(U flags, U delta, U scorerClone);
bool Bind(U* bindings);                // NTW2_BIND_AI_CTRL_{REFRESH,SCORER,BATCH_ASSIGN,BATCH_EXIT,HISTOGRAM}
void Snapshot(volatile U* row);        // words 0..15 into row[0..15]
}
#endif
