// --brain-target-cull[-shadow]: reordered mirror of the melee target search 0x553420 / 0x553590 (contract and proof: kntwr_target_cull.h).
// Every impure native step (static guard, vt+0xB4 scratch push, scratch reset, 0x659480 flag test) runs exactly as native; the pure conjuncts
// are reordered cheapest first.  The float arithmetic uses SSE intrinsics to match the native SSE2 sequence bit for bit.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include "kntwr_target_cull.h"

namespace kntwr_target_cull {
using U = uint32_t;
volatile U words[kWords];

namespace {
using U8 = unsigned char;
using NativeLoop = U(__stdcall*)(U, U, float, float*, U);
using NativeSearch = U(__fastcall*)(U, U, U, U);
using FlagState = U(__fastcall*)(U, U, U);
using Pred1 = U8(__fastcall*)(U, U);
using Pred2 = U8(__fastcall*)(U, U, U);
using Score = float(__cdecl*)(U, float);
using Kind = float(__cdecl*)(U);
using Getter = U(__fastcall*)(U, U);
using Push = U(__fastcall*)(U, U, U);
using GuardFn = U(__cdecl*)(U);

Targets t;
Mode mode;
NativeLoop nativeLoop;
FlagState flagState;
Pred1 alive;
Pred2 reach;
Score score;
Kind kindDist;

// Per-run census accumulators; published by Publish() once per Search so the hot loop touches only locals.
struct Census { U calls, candidates, predicates, flagCalls, mmResult, mmScore, mmScratch; };
Census census;
inline U Bits(float f) { return *reinterpret_cast<U*>(&f); }
inline U Rd(U address) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(address)); }
inline void Wr(U address, U value) { *reinterpret_cast<U*>(static_cast<uintptr_t>(address)) = value; }
inline U Sat(U a, U b) { const U s = a + b; return s < a ? 0xFFFFFFFFu : s; }
inline U Sat8(U v) { return v > 0xFF ? 0xFF : v; }
inline float F(U bits) { return *reinterpret_cast<float*>(&bits); }

void Publish() {
    words[WCalls] = census.calls;
    words[WCandidates] = census.candidates;
    words[WPredicates] = census.predicates;
    words[WPacked] = Sat8(census.mmResult) | (Sat8(census.mmScore) << 8) | (Sat8(census.mmScratch) << 16) | (Sat8(census.flagCalls) << 24);
}

// 0x5536B0..0x5536C9 / 0x55370B..0x553723: float(u32 v) = (float)((double)(int)v + table[v >> 31]).
inline float ToFloat(U v) {
    const double correction = *reinterpret_cast<const double*>(static_cast<uintptr_t>(t.u32Table) + 8u * (v >> 31));
    return _mm_cvtss_f32(_mm_cvtsd_ss(_mm_setzero_ps(), _mm_add_sd(_mm_cvtsi32_sd(_mm_setzero_pd(), static_cast<int>(v)), _mm_set_sd(correction))));
}
// 0x55364B..0x553686: sqrt((dy*dy + dx*dx) + dz*dz) with the native subtraction and addition order.
inline float Dist(U agent, U c) {
    const float ax = F(Rd(agent + 0x48)), ay = F(Rd(agent + 0x4C)), az = F(Rd(agent + 0x50));
    const __m128 dy = _mm_sub_ss(_mm_set_ss(ay), _mm_set_ss(F(Rd(c + 0x4C))));
    const __m128 dx = _mm_sub_ss(_mm_set_ss(ax), _mm_set_ss(F(Rd(c + 0x48))));
    const __m128 dz = _mm_sub_ss(_mm_set_ss(az), _mm_set_ss(F(Rd(c + 0x50))));
    __m128 sum = _mm_add_ss(_mm_mul_ss(dy, dy), _mm_mul_ss(dx, dx));
    sum = _mm_add_ss(sum, _mm_mul_ss(dz, dz));
    return _mm_cvtss_f32(_mm_sqrt_ss(sum));
}
// 0x5535BA..0x55375E: function-local static guard of 0x553590, checked once per man.
inline void Guard() {
    const U block = Rd(__readfsdword(0x2C) + 4u * Rd(t.tlsIndex));
    if (static_cast<int>(Rd(t.guard)) > static_cast<int>(Rd(block + 8))) {
        reinterpret_cast<GuardFn>(static_cast<uintptr_t>(t.initHeader))(t.guard);
        if (Rd(t.guard) == 0xFFFFFFFFu) {
            reinterpret_cast<GuardFn>(static_cast<uintptr_t>(t.atexitFn))(t.atexitArg);
            reinterpret_cast<GuardFn>(static_cast<uintptr_t>(t.initFooter))(t.guard);
        }
    }
}

struct Local { U candidates, predicates; };
U LoopImpl(U agent, U unit, float maxDist, float* outScore, bool flag, Local& local) {
    U best = 0, bestInt = 0;
    U flagOut[8];
    const U scratch = t.scratch;
    for (U i = 0; i < Rd(unit + 0x2CC); ++i) {
        const U man = Rd(Rd(unit + 0x2D0) + 4 * i);
        Guard();
        reinterpret_cast<Push>(static_cast<uintptr_t>(Rd(Rd(man) + 0xB4)))(man, 0, scratch);
        for (U j = 0; j < Rd(scratch + 0xC); ++j) {
            const U c = Rd(Rd(scratch + 0x10) + 4 * j);
            ++local.candidates;
            if (flag && Rd(flagState(c, 0, static_cast<U>(reinterpret_cast<uintptr_t>(flagOut))) + 0xC) == 0) continue;
            const float d = Dist(agent, c);
            if (!_mm_comigt_ss(_mm_set_ss(maxDist), _mm_set_ss(d))) continue; // native: jbe (maxDist <= d or unordered) skips
            const float s = score(c, d);
            if (best && !_mm_comigt_ss(_mm_set_ss(ToFloat(bestInt)), _mm_set_ss(s))) continue; // cannot replace the running best
            ++local.predicates;
            if (alive(c, 0) != 1) continue;
            if (reach(c, 0, agent) != 1) continue;
            best = c;
            bestInt = static_cast<U>(_mm_cvttss_si32(_mm_set_ss(s)));
        }
        Wr(scratch + 0xC, 0);
    }
    *outScore = ToFloat(bestInt);
    return best;
}

// Per-search candidate cache.  0x553420 hands 0x553590 the SAME unit for every list entry (only maxDist differs), the scratch push, the distance, the
// score and the pure predicates depend on nothing entry-specific, so one search gathers the candidates once and every entry scans the cached array.
struct Cached { U c; float d, s; U8 flagOk, state; };  // state: 1 score known, 2 predicate evaluated, 4 predicate passed
constexpr U kCacheMax = 4096;
Cached cache[kCacheMax];

// Same impure sequence as native per entry (guard, vt+0xB4 push, scratch reset), once.  False: more than kCacheMax candidates, entries fall back to LoopImpl.
bool Gather(U agent, U unit, bool flag, U& count) {
    U n = 0, flagOut[8];
    const U scratch = t.scratch;
    for (U i = 0; i < Rd(unit + 0x2CC); ++i) {
        const U man = Rd(Rd(unit + 0x2D0) + 4 * i);
        Guard();
        reinterpret_cast<Push>(static_cast<uintptr_t>(Rd(Rd(man) + 0xB4)))(man, 0, scratch);
        for (U j = 0; j < Rd(scratch + 0xC); ++j) {
            if (n == kCacheMax) { Wr(scratch + 0xC, 0); return false; }
            const U c = Rd(Rd(scratch + 0x10) + 4 * j);
            Cached& e = cache[n++];
            e.c = c; e.d = Dist(agent, c); e.s = 0.0f; e.state = 0;
            e.flagOk = !flag || Rd(flagState(c, 0, static_cast<U>(reinterpret_cast<uintptr_t>(flagOut))) + 0xC) != 0;
        }
        Wr(scratch + 0xC, 0);
    }
    count = n;
    return true;
}
// One entry over the cached candidates: the LoopImpl conjunction, cheapest first, with the score and the predicate memoised per candidate.
U ScanCached(U agent, U n, float maxDist, float* outScore, Local& local) {
    U best = 0, bestInt = 0;
    for (U k = 0; k < n; ++k) {
        Cached& e = cache[k];
        ++local.candidates;
        if (!e.flagOk) continue;
        if (!_mm_comigt_ss(_mm_set_ss(maxDist), _mm_set_ss(e.d))) continue;
        if (!(e.state & 1)) { e.s = score(e.c, e.d); e.state |= 1; }
        if (best && !_mm_comigt_ss(_mm_set_ss(ToFloat(bestInt)), _mm_set_ss(e.s))) continue;
        if (!(e.state & 2)) {
            ++local.predicates;
            e.state |= 2;
            if (alive(e.c, 0) == 1 && reach(e.c, 0, agent) == 1) e.state |= 4;
        }
        if (!(e.state & 4)) continue;
        best = e.c;
        bestInt = static_cast<U>(_mm_cvttss_si32(_mm_set_ss(e.s)));
    }
    *outScore = ToFloat(bestInt);
    return best;
}
} // namespace

U __stdcall Loop(U agent, U unit, float maxDist, float* outScore, U flag) {
    Local local = {0, 0};
    const U r = LoopImpl(agent, unit, maxDist, outScore, (flag & 0xFF) != 0, local);
    census.candidates = Sat(census.candidates, local.candidates);
    census.predicates = Sat(census.predicates, local.predicates);
    ++census.calls;
    Publish();
    return r;
}

namespace {
// One entry's search: live runs the mirror, shadow runs native then mirror and compares (the answer is native's).  cached >= 0: the search's candidate cache.
inline U Entry(U agent, U targetUnit, float maxDist, float* outScore, bool flag, int cached) {
    Local local = {0, 0};
    if (mode == ModeLive) {
        const U r = cached >= 0 ? ScanCached(agent, static_cast<U>(cached), maxDist, outScore, local) : LoopImpl(agent, targetUnit, maxDist, outScore, flag, local);
        census.candidates = Sat(census.candidates, local.candidates);
        census.predicates = Sat(census.predicates, local.predicates);
        ++census.calls;
        return r;
    }
    float nativeScore = F(0x7F7FFFFFu), mirrorScore = F(0x7F7FFFFFu);
    const U nativeResult = nativeLoop(agent, targetUnit, maxDist, &nativeScore, flag ? 1u : 0u);
    const U mirrorResult = cached >= 0 ? ScanCached(agent, static_cast<U>(cached), maxDist, &mirrorScore, local) : LoopImpl(agent, targetUnit, maxDist, &mirrorScore, flag, local);
    census.candidates = Sat(census.candidates, local.candidates);
    census.predicates = Sat(census.predicates, local.predicates);
    ++census.calls;
    if (nativeResult != mirrorResult) ++census.mmResult;
    if (Bits(nativeScore) != Bits(mirrorScore)) ++census.mmScore;
    if (Rd(t.scratch + 0xC) != 0) ++census.mmScratch;
    *outScore = nativeScore;
    return nativeResult;
}
}

U __fastcall Search(U list, U, U agent, U targetUnit) {
    if (mode == ModeOff) return reinterpret_cast<NativeSearch>(static_cast<uintptr_t>(t.search))(list, 0, agent, targetUnit);
    // 0x553423..0x553487: flag = settings.+0x231 && !(*(owner+0x40)+0xBC) for the agent's 0x659480 owner (the +0xC pointer).
    U bestCandidate = 0, bestInt = 0xFFFFFFFFu;
    bool flag = false;
    {
        U out[8];
        const U owner = Rd(flagState(agent, 0, static_cast<U>(reinterpret_cast<uintptr_t>(out))) + 0xC);
        if (owner) {
            const U v = reinterpret_cast<Getter>(static_cast<uintptr_t>(Rd(Rd(owner) + 0x20)))(owner, 0);
            if (v) {
                const U settings = reinterpret_cast<Getter>(static_cast<uintptr_t>(t.settings))(v, 0);
                if (*reinterpret_cast<const U8*>(static_cast<uintptr_t>(settings) + 0x231) != 0)
                    flag = *reinterpret_cast<const U8*>(static_cast<uintptr_t>(Rd(owner + 0x40)) + 0xBC) == 0;
            }
        }
    }
    if (flag) ++census.flagCalls;
    U entry = Rd(list + 0x10);
    if (entry == Rd(list + 0xC) * 16u + entry) { Publish(); return 0; }
    int cached = -2;       // -2 not gathered yet, -1 overflow (per-entry loops), >= 0 candidate count
    bool unlimitedSeen = false;
    do {
        const U kind = Rd(entry + 4);
        if (kind != 0 && kind != 4) {
            const U entryUnit = Rd(entry);
            const U targetId = reinterpret_cast<Getter>(static_cast<uintptr_t>(Rd(Rd(targetUnit + 0x10))))(targetUnit + 0x10, 0);
            const U entryId = reinterpret_cast<Getter>(static_cast<uintptr_t>(Rd(Rd(entryUnit + 0x10))))(entryUnit + 0x10, 0);
            const float maxDist = entryId == targetId ? F(Rd(t.maxFloat)) : kindDist(kind);
            if (cached == -2) { U n = 0; cached = Gather(agent, targetUnit, flag, n) ? static_cast<int>(n) : -1; }
            float entryScore = F(0x7F7FFFFFu);
            const U r = Entry(agent, targetUnit, maxDist, &entryScore, flag, cached);
            const bool replaced = r != 0 && _mm_comigt_ss(_mm_set_ss(ToFloat(bestInt)), _mm_set_ss(entryScore));
            if (unlimitedSeen && mode == ModeShadow && replaced) ++census.mmResult; // the skip theorem below must hold
            if (replaced) {
                bestInt = static_cast<U>(_mm_cvttss_si32(_mm_set_ss(entryScore)));
                bestCandidate = r;
            }
            // An entry with maxDist = FLT_MAX scans a superset of every later entry's candidates (kind ranges are <= 100) with identical per-candidate scores, so a later
            // entry's best score is >= this one's and can never pass `score < float(u32 trunc(best))`; live skips them, shadow runs and checks them.
            if (maxDist == F(Rd(t.maxFloat))) unlimitedSeen = true;
            if (unlimitedSeen && mode == ModeLive) break;
        }
        entry += 16;
    } while (entry != Rd(list + 0xC) * 16u + Rd(list + 0x10));
    Publish();
    return bestCandidate;
}

void ResetRow() {
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    census = Census{};
}
void Configure(Mode m, const Targets& targets) {
    t = targets;
    mode = m;
    nativeLoop = reinterpret_cast<NativeLoop>(static_cast<uintptr_t>(t.loop));
    flagState = reinterpret_cast<FlagState>(static_cast<uintptr_t>(t.flagState));
    alive = reinterpret_cast<Pred1>(static_cast<uintptr_t>(t.alive));
    reach = reinterpret_cast<Pred2>(static_cast<uintptr_t>(t.reach));
    score = reinterpret_cast<Score>(static_cast<uintptr_t>(t.score));
    kindDist = reinterpret_cast<Kind>(static_cast<uintptr_t>(t.kindDist));
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}
} // namespace kntwr_target_cull
