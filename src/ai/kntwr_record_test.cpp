#include "kntwr_record_test.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>

// See kntwr_record_test.h. Integer-only: nothing here executes x87/SSE arithmetic, so the forwarder leaves FP control/status/MXCSR exactly as
// the native caller and callee see them. The row is written by the thread executing the think; a poll is a non-atomic snapshot.
namespace kntwr_record_test {
using U = uint32_t;
volatile U words[kWords];
volatile U scopeDepth;

namespace {
using Entry3 = U(__fastcall*)(U, U, U, U, U);
U gMode, gEntry, gOriginal, gTscPerUs;
bool gArmed;
uint64_t gServedFast, gSampledNative, gSampledFast, gFallbackNative, gEntryTicks;
U gSampled, gServedCount, gEntryMaxUs;
inline void Bump(Word w, U by = 1) { words[w] = words[w] + by; }
}

void Reset() {
    gArmed = false; gMode = ModeOff; gEntry = 0; gOriginal = 0;
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    gServedFast = gSampledNative = gSampledFast = gFallbackNative = gEntryTicks = 0;
    gSampled = gServedCount = gEntryMaxUs = 0;
    scopeDepth = 0;
}

void Configure(U mode, U entry, U original, U tscPerUs) {
    Reset();
    gOriginal = original;
    if (mode == ModeOff || !entry) return;
    gMode = mode; gEntry = entry; gTscPerUs = tscPerUs;
    words[WVersion] = 1; words[WMode] = mode; words[WTscPerUs] = tscPerUs;
    gArmed = true;
}

void NoteSlot(bool routed) { if (gArmed) Bump(routed ? WSlotRouted : WSlotUnrouted); }
bool Shadow() { return gMode == ModeShadow; }
U NextServedIndex() { return gServedCount; }

void Account(U why, U vertices, unsigned char result) {
    Bump(WCalls);
    if (why == 0) {
        Bump(WServed);
        if (result) Bump(WTrue);
        words[WVerticesSum] = words[WVerticesSum] + vertices;
        if (vertices > words[WVerticesMax]) words[WVerticesMax] = vertices;
        if (vertices > 256) Bump(WVerticesOver256);
    } else {
        Bump(static_cast<Word>(WFallKind + why - 1)); // Reason FallKind..FallBusy (1..5) -> words 6..10
    }
}
void NoteServed(uint64_t fastTicks) { ++gServedCount; gServedFast += fastTicks; }
void NoteFallbackNative(uint64_t nativeTicks) { gFallbackNative += nativeTicks; }
void NoteCompare(bool al, bool x87, bool mxcsr, uint64_t nativeTicks, uint64_t fastTicks) {
    Bump(WShadowCompares);
    if (al) Bump(WMismatchAl);
    if (x87) Bump(WMismatchX87);
    if (mxcsr) Bump(WMismatchMxcsr);
    gSampledNative += nativeTicks; gSampledFast += fastTicks; ++gSampled;
}
void Publish() {
    words[WServedFastKc] = static_cast<U>(gServedFast >> 10);
    words[WSampledNativeKc] = static_cast<U>(gSampledNative >> 10);
    words[WSampledFastKc] = static_cast<U>(gSampledFast >> 10);
    words[WSampledCalls] = gSampled;
    words[WFallbackNativeKc] = static_cast<U>(gFallbackNative >> 10);
    words[WEntryKc] = static_cast<U>(gEntryTicks >> 10);
    words[WEntryMaxUs] = gEntryMaxUs;
}

U __fastcall Entry(U self, U, U a1, U a2, U a3) {
    if (!gArmed) return reinterpret_cast<Entry3>(static_cast<uintptr_t>(gOriginal))(self, 0, a1, a2, a3);
    ++scopeDepth;
    const unsigned __int64 t0 = __rdtsc();
    const U result = reinterpret_cast<Entry3>(static_cast<uintptr_t>(gEntry))(self, 0, a1, a2, a3);
    const uint64_t ticks = __rdtsc() - t0;
    --scopeDepth;
    gEntryTicks += ticks;
    if (gTscPerUs) {
        const uint64_t us = ticks / gTscPerUs;
        if (us > gEntryMaxUs) gEntryMaxUs = us > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<U>(us);
    }
    Publish();
    return result;
}
}
