#ifndef KNTWR_RECORD_TEST_H
#define KNTWR_RECORD_TEST_H
#include <stdint.h>

// --ai-record-test-shadow / --ai-record-test (kntwr_config::ai_prepass_flags 0x20 / 0x40): the SSE OBB/polygon kernel of --ai-poly
// (kntwr_planner_search.cpp, bit-identical to 0x80DCF0 -> 0x10EC150) extended to the ALTERNATE placement delegate route that --ai-poly
// does not cover (analysis/native-ai-record-test-kernel.md).
//
// Route (every edge proven by disassembly, preferred-base VAs): controller slot +0x50 = 0x6B3010 can install a delegate of class
// 0x13376AC whose slot 16 (0x13376EC) is 0x6A99E0, not the 0x6A95A0 of 0x13376FC that --ai-poly routes. 0x6A99E0 -> 0x6A94B0 (call
// 0x6A9CDA; per-record loop over the 0x1C-byte interest records at [this+0x28]) -> 0x6C71D0 (call 0x6A9528, the same placement ladder)
// -> ... -> 0x808040 -> 0x7F1D40 -> 0x80DCF0 -> 0x10EC150. 0x6A99E0 also calls 0x7FCA40 (0x6A9AF4). Without this module that whole
// route runs the NATIVE x87-free scalar kernel (0x559C10 per polygon edge, one call + a 4-float copy 0x10D0900 per edge and pass).
//
// Mechanism: slot 0x13376EC is published with a naked gate (kntwr_runtime.cpp PsAltObserverGate). On the thread executing the site-34
// planner update (PsScopeThread) it hands the call to Entry(), a fastcall forwarder of 0x6A99E0 (ECX = delegate, three stack arguments,
// ret 0xC, returns EAX) that opens the alt scope around the pure-retarget clone PS_6A99E0 (-> PS_6A94B0 -> PS_6C71D0 / PS_7FCA40 ->
// the existing PS_* chain -> kntwr_poly::Gate). Every other thread (main/render spotting, workers outside a think) keeps 0x6A99E0.
// While the scope is open kntwr_poly::Gate accounts into THIS row and obeys THIS module's mode (shadow: native answers and the kernel is
// compared bit-for-bit incl. x87 control/status/tag and MXCSR; live: the kernel answers, native fallback by reason, every 32nd served
// call is also run natively from the identical FP state and compared), independent of the --ai-poly mode of the default route.
//
// Row: ai_prepass_words[32 .. 32+kWords) (the row grew 32 -> 60 words; words 0..31 are the unchanged kntwr_poly layout). Layout version 1:
//  0 version, 1 mode (1 shadow, 2 live), 2 slot 0x13376EC entries routed to PS_6A99E0, 3 slot entries not routed (original),
//  4 kernel calls inside the alt scope, 5 served by Evaluate, 6..10 fallback by reason (kind!=0, FP state, domain, walk cap, busy),
//  11 shadow compares (served calls compared against native), 12 AL mismatches, 13 x87 control/status/tag mismatches, 14 MXCSR mismatches,
//  15 true results served, 16 sum of walked polygon vertices ("records"), 17 max vertices, 18 served fast-path kilocycles (rdtsc>>10),
//  19 sampled native kilocycles, 20 sampled fast kilocycles (same calls), 21 sampled calls, 22 native kilocycles of fallback calls,
//  23 TSC ticks per microsecond (copied from the poly row), 24 inclusive kilocycles of all routed 0x6A99E0 entries (whole alt route, kernel
//  included), 25 longest single routed entry (microseconds), 26 served polygons with more than 256 vertices, 27 reserved.
//  Sums are uint64 internally, published modulo 2^32.
namespace kntwr_record_test {
enum Mode : uint32_t { ModeOff = 0, ModeShadow = 1, ModeLive = 2 };
enum Word : uint32_t {
    WVersion, WMode, WSlotRouted, WSlotUnrouted, WCalls, WServed, WFallKind, WFallFp, WFallDomain, WFallWalkCap, WFallBusy,
    WShadowCompares, WMismatchAl, WMismatchX87, WMismatchMxcsr, WTrue, WVerticesSum, WVerticesMax, WServedFastKc, WSampledNativeKc,
    WSampledFastKc, WSampledCalls, WFallbackNativeKc, WTscPerUs, WEntryKc, WEntryMaxUs, WVerticesOver256, WReserved, WordCount
};
constexpr uint32_t kWords = WordCount;
static_assert(kWords == 28, "row layout");
extern volatile uint32_t words[kWords];

// Resets the row and arms the module. `entry` = PS_6A99E0 clone entry (0 or ModeOff disarms: Entry then forwards to `original`),
// `original` = 0x6A99E0 in the live image, `tscPerUs` = the poly row's calibration (word 31).
void Configure(uint32_t mode, uint32_t entry, uint32_t original, uint32_t tscPerUs);
void Reset(); // runtime start: zero the row, disarm
void NoteSlot(bool routed);
// The alt scope (open only inside Entry on the executing thread; at most one think scope runs at a time).
extern volatile uint32_t scopeDepth;
inline bool InScope() { return scopeDepth != 0; }
bool Shadow(); // true when the alt route runs in shadow mode (native answers)

// Accounting hooks called by kntwr_poly::Gate while InScope(). `why` is the kntwr_poly::Reason value (0 served, 1..5 fallback).
void Account(uint32_t why, uint32_t vertices, unsigned char result);
uint32_t NextServedIndex(); // number of calls served so far (the live 1-in-32 sample is chosen by this count, never by time)
void NoteServed(uint64_t fastTicks);
void NoteFallbackNative(uint64_t nativeTicks);
void NoteCompare(bool al, bool x87, bool mxcsr, uint64_t nativeTicks, uint64_t fastTicks);
void Publish();

// fastcall: ECX = delegate (0x13376AC object), stack = three arguments, `ret 0xC`; returns the EAX of 0x6A99E0.
uint32_t __fastcall Entry(uint32_t self, uint32_t, uint32_t a1, uint32_t a2, uint32_t a3);
}
#endif
