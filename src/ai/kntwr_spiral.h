#ifndef KNTWR_SPIRAL_H
#define KNTWR_SPIRAL_H
#include <stdint.h>

// --ai-spiral-cap-m N / --ai-spiral-census (kntwr_config::ai_prepass_flags bits 16..31 / 0x10): placement-spiral cap and the fallback
// observer census on the planner's observer LOS route (analysis/native-ai-child-query-notes.md §3.3/§3.7, native-ai-child-think.md §2).
//
// Route: fallback strategy observer slot 0x1343318+0x40 (0x7524A0, ret 4) loops its qualifying assignment rows -> 0x74F430 -> inline
// controller slot 0x1349C18+0x70 (0x826E80, ret 4) -> 0x82F3A0 (10-tick memo on ctrl+0x724; a same-tick call always recomputes) ->
// 0x6DD340 -> observer slot 0x13376FC+0x40 -> PS_6A95A0 -> [PS_LADDER] -> PS_6C71D0 (placement ladder: spot 0x6C7316, clamp 0x6C7410,
// 8-direction ring 0x6C77E2, each via [PS_LADDER_PROBE] -> PS_6CC730) -> last resort [PS_SPIRAL] -> PS_7FCA40 -> PS_7FCA90 (spiral,
// start radius 20, step 20, spec+0x24 maxR = -1.0 sentinel) -> [PS_SPIRAL_PROBE] -> PS_808040.
//
// Cap: with N > 0 the PS_SPIRAL forwarder hands PS_7FCA40 a private copy of the 0x40-byte spec whose +0x24 holds (float)N instead of
// the -1.0 sentinel (any other incoming value is forwarded untouched). The native spiral then takes its own exit 0x7FCDC9..0x7FCDF4:
// after a ring of radius r, r+step > N -> not-found exit 0x7FCE01 (the same exit as "a whole ring outside the map/inner rectangle").
// 0x7FCA40 drops that flag; the ladder (0x6C79AD..0x6C7AAB) ALWAYS appends and returns the out record, which on not-found is the
// 0x7FCFF0 projection of the ORIGINAL requested point. So a capped spiral places the unit at its requested (possibly obstructed)
// point, exactly like native's map-edge outcome; it is never left unassigned. N = 0 forwards the caller's spec pointer unchanged.
//
// Forwarders are thiscall (ECX + stack, callee cleanup), integer-only (no x87/SSE arithmetic, so FP control/status/MXCSR are never
// touched) and call the same PS_* clone entries the generator used before. The fallback/controller slot gates count only on the thread
// executing the site-34 planner update (Targets::scope); every other caller is forwarded to the original.
namespace kntwr_spiral {
// ai_spiral_words row (KNTWR_AI_SPIRAL_WORDS = 32), layout version 1:
//  0 version, 1 cap metres (0 = native unlimited), 2 ladder calls (PS_6C71D0), 3..7 ladder stage that placed the entry: spot, clamp,
//  ring, spiral found, spiral not found (capped or map edge; the original point is placed), 8 ladder returns with no stage identified
//  (0 by construction), 9 spiral entries (ladder fallback 0x6C79A8), 10 spiral candidates (0x808040 calls), 11 rings, 12 spiral found,
//  13 capped (not found at the radius exit; only with N > 0), 14 not found at a whole-ring-outside exit (native), 15 max radius reached
//  (metres, floor), 16 max candidates in one spiral, 17 fallback calls (0x7524A0), 18..23 entries per call E = 0, 1, 2, 3-4, 5-8, >8,
//  24 entries (0x826E80 calls inside 0x7524A0), 25 max E, 26 0x82F3A0 query-tail runs, 27 of which with lastTick == tick (same-tick
//  recompute), 28 memo hits (cached ctrl+0x720), 29 ladder calls inside 0x7524A0, 30 spiral entries inside 0x7524A0, 31 fallback and
//  controller slot entries off the planner thread (forwarded, uncounted otherwise).
constexpr uint32_t kWords = 32;
enum Word : uint32_t {
    WVersion, WCapMetres, WLadderCalls, WStageSpot, WStageClamp, WStageRing, WStageSpiral, WStageNone, WStageUnknown,
    WSpiralEntries, WSpiralCandidates, WSpiralRings, WSpiralFound, WSpiralCapped, WSpiralEdge, WMaxRadiusMetres, WMaxCandidates,
    WFallbackCalls, WEntries0, WEntries1, WEntries2, WEntries3To4, WEntries5To8, WEntriesOver8, WEntries, WMaxEntries,
    WTailRuns, WTailSameTick, WTailMemo, WLadderInFallback, WSpiralInFallback, WOffThread, WordCount
};
static_assert(WordCount == kWords, "row layout");
extern volatile uint32_t words[kWords];

constexpr uint32_t kSpecSentinel = 0xBF800000u; // -1.0f at spec+0x24 (stored at 0x6C7933)
constexpr uint32_t kMinCapMetres = 20;          // the first ring (radius 20) always runs natively; smaller caps are refused
constexpr uint32_t kMaxCapMetres = 0xFFFFu;

struct Targets {
    uint32_t ladder;      // PS_6C71D0 entry (also the base of the three 0x6CC730 return sites)
    uint32_t ladderProbe; // PS_6CC730 entry
    uint32_t spiral;      // PS_7FCA40 entry
    uint32_t spiralProbe; // PS_808040 entry
    uint32_t fallback;    // original 0x7524A0
    uint32_t controller;  // original 0x826E80
    bool (*scope)(uint32_t tid); // thread executing the site-34 planner update
};
// Resets the row. active = census or cap requested (word 0 = 1); capMetres = 0 or kMinCapMetres..kMaxCapMetres. Forwarders and gates
// stay callable when inactive (pure forwarding, nothing counted).
void Configure(bool active, uint32_t capMetres, const Targets& targets);
// Runtime start: zero the row before any poll of the new session (Configure runs later, at activation).
void ResetRow();

uint32_t __fastcall Ladder(uint32_t self, uint32_t, uint32_t out, uint32_t point, uint32_t heading, uint32_t fa, uint32_t fb);
uint32_t __fastcall LadderProbe(uint32_t self, uint32_t, uint32_t request);
uint32_t __fastcall Spiral(uint32_t self, uint32_t, uint32_t out, uint32_t spec, uint32_t flag);
uint32_t __fastcall SpiralProbe(uint32_t self, uint32_t, uint32_t spec, uint32_t point, uint32_t kind, uint32_t inOuter, uint32_t inInner);
uint32_t __fastcall FallbackGate(uint32_t self, uint32_t, uint32_t list);
uint32_t __fastcall ControllerGate(uint32_t self, uint32_t, uint32_t unit);

// Fallback strategy observer vtable 0x1343318 slot 16 and inline controller vtable 0x1349C18 slot 28 (published with the spiral bits).
constexpr uint32_t kFallbackSlot = 0x1343318u + 4u * 16u, kFallbackOriginal = 0x7524A0u;
constexpr uint32_t kControllerSlot = 0x1349C18u + 4u * 28u, kControllerOriginal = 0x826E80u;
// Return sites of the three ladder 0x6CC730 calls, relative to the ladder entry (PS_6C71D0 is a byte-length copy of 0x6C71D0).
constexpr uint32_t kSpotReturn = 0x6C731Bu - 0x6C71D0u, kClampReturn = 0x6C7415u - 0x6C71D0u, kRingReturn = 0x6C77E7u - 0x6C71D0u;
}
#endif
