// --ai-spiral-cap-m / --ai-spiral-census: host forwarders inside the PS_* observer chain and the fallback/controller slot gates
// (layout and route: kntwr_spiral.h). Everything here is integer code: no x87/SSE arithmetic runs between the native caller and callee.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include "kntwr_spiral.h"

namespace kntwr_spiral {
using U = uint32_t;
volatile U words[kWords];

namespace {
using Ladder5 = U(__fastcall*)(U, U, U, U, U, U, U);
using Ladder1 = U(__fastcall*)(U, U, U);
using Spiral3 = U(__fastcall*)(U, U, U, U, U);
using Probe5 = U(__fastcall*)(U, U, U, U, U, U, U);

Targets target;
bool active;
U capMetres, capBits;

// Planner-thread state (the PS_* chain and the counted gate paths run only on the thread executing the site-34 update).
U fallbackDepth, fallbackEntries;
bool ladderOpen;
U ladderStage;       // WStageSpot/Clamp/Ring of the last 0x6CC730 call that returned true, 0 = none
U ladderSpiral;      // 0 = spiral not run, else WStageSpiral / WStageNone
bool spiralOpen;
U spiralCandidates, spiralRings, spiralRadiusBits, spiralMaxRadiusBits;
bool spiralLastFound, ringOuter, ringInner, spiralInnerRule;

inline void Bump(U word, U by = 1) { words[word] += by; }
inline void Max(U word, U value) { if (value > words[word]) words[word] = value; }

// floor() of a non-negative float given by bits, saturating; integer-only.
U FloorMetres(U bits) {
    if (bits >> 31) return 0;
    const U exponent = (bits >> 23) & 0xFFu;
    if (exponent < 127) return 0;
    if (exponent >= 127 + 31) return 0xFFFFFFFFu;
    const U mantissa = (bits & 0x7FFFFFu) | 0x800000u;
    const int shift = static_cast<int>(exponent) - 150;
    return shift >= 0 ? mantissa << shift : mantissa >> -shift;
}
// Exact float bits of an integer in 1..0xFFFF (24-bit mantissa holds it); integer-only.
U FloatBits(U value) {
    U exponent = 31;
    while (!(value >> exponent)) --exponent;
    return ((exponent + 127) << 23) | ((value << (23 - exponent)) & 0x7FFFFFu);
}
U ReadU(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }

// 0x82F3A0's current tick: [[[ctrl+8]+8]+0x58] (0x82F6EE..0x82F6F4); SEH-guarded so a census read can never fault the think.
bool ReadTick(U ctrl, U* tick) {
    __try {
        *tick = ReadU(ReadU(ReadU(ctrl + 8) + 8) + 0x58);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
} // namespace

void ResetRow() {
    active = false; // forwarders stay pure until the next Configure (their targets are kept)
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(bool on, U cap, const Targets& targets) {
    target = targets;
    active = on;
    capMetres = on ? cap : 0;
    capBits = capMetres ? FloatBits(capMetres) : 0;
    fallbackDepth = fallbackEntries = 0;
    ladderOpen = spiralOpen = false;
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    if (on) { words[WVersion] = 1; words[WCapMetres] = capMetres; }
}

U __fastcall Ladder(U self, U, U out, U point, U heading, U fa, U fb) {
    const Ladder5 native = reinterpret_cast<Ladder5>(static_cast<uintptr_t>(target.ladder));
    if (!active || ladderOpen) return native(self, 0, out, point, heading, fa, fb);
    ladderOpen = true; ladderStage = 0; ladderSpiral = 0;
    const U result = native(self, 0, out, point, heading, fa, fb);
    ladderOpen = false;
    Bump(WLadderCalls);
    if (fallbackDepth) Bump(WLadderInFallback);
    // First success wins and returns; the spiral is the unconditional last stage, so a spiral run decides the stage.
    Bump(ladderSpiral ? ladderSpiral : ladderStage ? ladderStage : WStageUnknown);
    return result;
}

U __fastcall LadderProbe(U self, U, U request) {
    const Ladder1 native = reinterpret_cast<Ladder1>(static_cast<uintptr_t>(target.ladderProbe));
    const U result = native(self, 0, request);
    if (ladderOpen && (result & 0xFFu)) {
        const U site = static_cast<U>(reinterpret_cast<uintptr_t>(_ReturnAddress())) - target.ladder;
        ladderStage = site == kSpotReturn ? WStageSpot : site == kClampReturn ? WStageClamp : site == kRingReturn ? WStageRing : 0;
    }
    return result;
}

U __fastcall Spiral(U self, U, U out, U spec, U flag) {
    const Spiral3 native = reinterpret_cast<Spiral3>(static_cast<uintptr_t>(target.spiral));
    if (!active || spiralOpen) return native(self, 0, out, spec, flag);
    unsigned char copy[0x40];
    U use = spec;
    const bool capped = capBits && ReadU(spec + 0x24) == kSpecSentinel;
    if (capped) {
        memcpy(copy, reinterpret_cast<const void*>(static_cast<uintptr_t>(spec)), sizeof copy);
        memcpy(copy + 0x24, &capBits, 4);
        use = static_cast<U>(reinterpret_cast<uintptr_t>(copy));
    }
    spiralOpen = true;
    spiralCandidates = spiralRings = spiralRadiusBits = spiralMaxRadiusBits = 0;
    spiralLastFound = ringOuter = ringInner = spiralInnerRule = false;
    const U result = native(self, 0, out, use, flag);
    spiralOpen = false;
    Bump(WSpiralEntries);
    if (fallbackDepth) Bump(WSpiralInFallback);
    Bump(WSpiralCandidates, spiralCandidates);
    Bump(WSpiralRings, spiralRings);
    Max(WMaxCandidates, spiralCandidates);
    Max(WMaxRadiusMetres, FloorMetres(spiralMaxRadiusBits));
    if (spiralLastFound) {
        Bump(WSpiralFound);
        if (ladderOpen) ladderSpiral = WStageSpiral;
    } else {
        // 0x7FCDC0..0x7FCDF4: a ring with no candidate inside the outer rectangle (or, under the inner-rect rule, the inner one)
        // exits first; otherwise the only remaining not-found exit is r+step > maxR, which exists only with the cap.
        const bool edge = !spiralCandidates || !ringOuter || (spiralInnerRule && !ringInner);
        Bump(capped && !edge ? WSpiralCapped : WSpiralEdge);
        if (ladderOpen) ladderSpiral = WStageNone;
    }
    return result;
}

U __fastcall SpiralProbe(U self, U, U spec, U point, U kind, U inOuter, U inInner) {
    const Probe5 native = reinterpret_cast<Probe5>(static_cast<uintptr_t>(target.spiralProbe));
    if (!spiralOpen) return native(self, 0, spec, point, kind, inOuter, inInner);
    // PS_7FCA90 frame at the call: [esp+0x58] = current radius (both call sites), read relative to the 5 pushed arguments.
    const unsigned char* frame = static_cast<const unsigned char*>(_AddressOfReturnAddress()) + 4 + 0x14;
    U radius;
    memcpy(&radius, frame + 0x58, 4);
    if (radius >> 31) radius = 0; // r <= 0: the single start-point test (0x7FCD47)
    if (!spiralCandidates || radius != spiralRadiusBits) {
        ++spiralRings; spiralRadiusBits = radius; ringOuter = ringInner = false;
        if (radius > spiralMaxRadiusBits) spiralMaxRadiusBits = radius; // non-negative floats order as unsigned integers
    }
    ++spiralCandidates;
    spiralInnerRule = (kind & 0xFFu) != 0; // 0x7FCA90's flag62 byte, passed as the 0x808040 kind
    const U result = native(self, 0, spec, point, kind, inOuter, inInner);
    if (*reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(inOuter)) == 1) ringOuter = true;
    if (*reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(inInner)) == 1) ringInner = true;
    spiralLastFound = (result & 0xFFu) == 1;
    return result;
}

U __fastcall FallbackGate(U self, U, U list) {
    const Ladder1 native = reinterpret_cast<Ladder1>(static_cast<uintptr_t>(target.fallback));
    if (!active) return native(self, 0, list);
    if (!target.scope(GetCurrentThreadId())) {
        _InterlockedIncrement(reinterpret_cast<volatile long*>(&words[WOffThread]));
        return native(self, 0, list);
    }
    const U outerEntries = fallbackEntries;
    ++fallbackDepth; fallbackEntries = 0;
    const U result = native(self, 0, list);
    const U e = fallbackEntries;
    --fallbackDepth; fallbackEntries = outerEntries;
    Bump(WFallbackCalls);
    Bump(e == 0 ? WEntries0 : e == 1 ? WEntries1 : e == 2 ? WEntries2 : e <= 4 ? WEntries3To4 : e <= 8 ? WEntries5To8 : WEntriesOver8);
    Bump(WEntries, e);
    Max(WMaxEntries, e);
    return result;
}

U __fastcall ControllerGate(U self, U, U unit) {
    const Ladder1 native = reinterpret_cast<Ladder1>(static_cast<uintptr_t>(target.controller));
    if (!active) return native(self, 0, unit);
    if (!target.scope(GetCurrentThreadId())) {
        _InterlockedIncrement(reinterpret_cast<volatile long*>(&words[WOffThread]));
        return native(self, 0, unit);
    }
    if (!fallbackDepth) return native(self, 0, unit);
    ++fallbackEntries;
    // 0x826E80 skips 0x82F3A0 for unit+0xB34 in {6,7}; 0x82F3A0 returns at once for ctrl+0x28 == 0. Otherwise the memo
    // (0x82F706..0x82F719) returns cached +0x720 only for lastTick != 0, != tick and lastTick+10 >= tick, without writing +0x724;
    // every recompute stores tick into +0x724 (0x82F736). Hence tail = (before == tick) || (after != before).
    const U state = ReadU(unit + 0xB34);
    const U before = ReadU(self + 0x724);
    const U result = native(self, 0, unit);
    U tick;
    if (state != 6 && state != 7 && ReadU(self + 0x28) && ReadTick(self, &tick)) {
        const U after = ReadU(self + 0x724);
        if (before == tick || after != before) {
            Bump(WTailRuns);
            if (before == tick && before) Bump(WTailSameTick);
        } else Bump(WTailMemo);
    }
    return result;
}
} // namespace kntwr_spiral
