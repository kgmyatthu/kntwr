#ifndef NTW2_PLANNER_SEARCH_H
#define NTW2_PLANNER_SEARCH_H
#include <stdint.h>

// Exact replacement of the kind-0 (OBB vs polygon) predicate 0x80DCF0 -> 0x10EC150 (analysis/native-ai-planner-search-spec.md).
// Evaluate() returns Served and the native AL, or a fallback reason; on any fallback the caller runs the ORIGINAL kernel on the
// same inputs. The guard/derivation that makes results AND floating-point sticky state identical to native is spec §10/§10.1.
namespace ntw2_poly {
enum Reason : uint32_t { Served = 0, FallKind, FallFp, FallDomain, FallWalkCap, ReasonCount };
constexpr uint32_t kMaxVertices = 1024;
// shape: 0x48-byte descriptor of 0x7E1BD0 ([shape]==0 selects the OBB at shape+4). polygon: circular vertex list, node +8 next,
// +0xC x, +0x10 z. `vertices` (optional) receives the walked vertex count when the walk completed (0 otherwise).
Reason Evaluate(const void* shape, const void* polygon, unsigned char* result, uint32_t* vertices);

// Runtime face (clone-bound host gate for the 0x7F1E5A call of 0x80DCF0 inside PS_WALK, bound as NTW2_BIND_PS_POLY).
using Native = unsigned char (__fastcall*)(void*, void*, void*);
enum Mode : uint32_t { ModeOff = 0, ModeShadow = 1, ModeLive = 2 };
// ai_prepass_words row (NTW2_AI_PREPASS_WORDS = 32), layout version 1:
//  0 version, 1 mode, 2 kernel calls, 3 served by Evaluate, 4 fallback kind!=0, 5 fallback FP state, 6 fallback domain, 7 fallback walk cap,
//  8 shadow compares (served calls), 9 AL mismatches, 10 x87 control/status/tag mismatches, 11 MXCSR mismatches, 12 true results served,
//  13 sum of walked vertices, 14 max vertices, 15 V<=16, 16 V<=64, 17 V<=256, 18 V>256, 19 observer slot entries routed to PS_6A95A0,
//  20 observer slot entries not routed, 21..31 reserved (zero).
constexpr uint32_t kWords = 32;
extern volatile uint32_t words[kWords];
void Configure(Native nativeKernel, uint32_t mode); // resets the row; mode ModeOff keeps it all-zero
void NoteObserver(bool routed);
// fastcall: ECX = shape, stack = polygon, `ret 4`; returns the AL of 0x80DCF0. Live: Evaluate, native on any refusal. Shadow: native
// answers, Evaluate is compared bit-for-bit (AL, x87 control/status/tag, MXCSR) from the identical initial FP state.
unsigned char __fastcall Gate(void* shape, void*, void* polygon);
}
#endif
