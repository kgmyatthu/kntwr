// Site-18 storm census (native_army_storm.h). Reads native memory only; writes only its row.
#include "native_army_storm.h"
#include "brain2/native_region_table.h"
#include <windows.h>
#include <string.h>
#include <algorithm>
#include <new>
#include "core/kntwr_guard.h"

namespace kntwr_army_storm {
namespace {
using u64 = unsigned long long;
constexpr U kRouteBytes = 0x40;             // C+3C
constexpr U kFlagBytes = 0x2790;            // F+2788 dword, F+278C byte
constexpr U kMaxAlliances = 32, kMaxArmies = 64;

U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }

struct Storage { kntwr_region::Table table; };
Storage* g_s;
U g_sampleMs, g_inUnit, g_queries, g_root;
LARGE_INTEGER g_frequency;
U g_words[kWords];

LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
U Sat(u64 v) { return v > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(v); }
U Us(u64 q) { return g_frequency.QuadPart ? Sat(q * 1000000ull / static_cast<u64>(g_frequency.QuadPart)) : 0; }
U Cap(u64 v, U bits) { const u64 m = (1ull << bits) - 1; return static_cast<U>(v > m ? m : v); }

// Aggregates, accumulated in QPC ticks and converted when published.
struct Aggregate {
    u64 maxQ, units, routeUnits, routeQ, unitQ, sumMaxQ, ge5, ge1, prepQ, fsmQ, fsmCalls, formQ, r2Q, r1Entries;
};
Aggregate g_agg[kAggregates]; // 0 storm, 1 calm
struct TickState {
    u64 units, routeUnits, unitQ, routeQ, maxQ, ge5, ge1, bracketQ[kBrackets], fsmCalls, r2Q, r2Full, r1Entries;
    U maxOrdinal, maxSide;
};
TickState g_t;
struct Occurrence { u64 bracketQ[kBrackets], bracketCalls[kBrackets], r2Q, r2Reached, r2Full, r1Entries, r1Q, r1bQ; LONGLONG observerQ; };
Occurrence g_occ;
u64 g_observerQ, g_unreadable;
// Median ring of the site-18 us of routed ticks that ran site 18.
U g_ring[kRing], g_ringCount, g_ringNext;
U g_ticks, g_stormTicks, g_median;
struct Entry { U word[kEntryWords]; };
Entry g_top[kTop];
U g_topCount;

U Median() {
    U copy[kRing];
    const U n = g_ringCount;
    memcpy(copy, g_ring, n * sizeof(U));
    std::nth_element(copy, copy + n / 2, copy + n);
    return copy[n / 2];
}

// R2 gate-entry evidence (native_army_storm.h): ok when C was readable; full needs F readable too.
struct RouteRead { bool ok, reach, full; };
RouteRead ReadRoute2(U c) {
    RouteRead r = {};
    kntwr_region::Table& t = g_s->table;
    t.Clear();
    ++kntwr::probeDepth;
    __try {
        if (c && t.Readable(c, kRouteBytes, g_queries)) {
            r.ok = true;
            if (!B(c + 0x3C)) r.reach = true;
            const U f = D(c + 4);
            if (f && t.Readable(f, kFlagBytes, g_queries)) {
                const bool flagged = B(f + 0x278C) != 0 && D(f + 0x2788) == 0;
                r.full = flagged;
                if (flagged) r.reach = true;
            } else r.ok = false; // F unreadable: reach is only partly known
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { r = {}; }
    --kntwr::probeDepth;
    return r;
}

// Alliance/army of unit U: A = [U+1EC]; H+84 count / H+88 array of alliances X, X+20 count / X+24 array of armies [proven, Decode].
U SideOf(U u) {
    U side = kSideUnproven;
    if (!g_root) return side;
    kntwr_region::Table& t = g_s->table;
    t.Clear();
    ++kntwr::probeDepth;
    __try {
        if (t.Readable(u + 0x1EC, 4, g_queries) && t.Readable(g_root + 0x84, 8, g_queries) && t.Readable(g_root + 0x2378, 4, g_queries)) {
            const U army = D(u + 0x1EC), n = D(g_root + 0x84), data = D(g_root + 0x88), special = D(g_root + 0x2378);
            if (army && n && n <= kMaxAlliances && t.Readable(data, n * 4, g_queries))
                for (U i = 0; i < n && side == kSideUnproven; ++i) {
                    const U x = D(data + 4 * i);
                    if (!x || !t.Readable(x + 0x20, 8, g_queries)) continue;
                    const U m = D(x + 0x20), list = D(x + 0x24);
                    if (!m || m > kMaxArmies || !t.Readable(list, m * 4, g_queries)) continue;
                    for (U j = 0; j < m; ++j)
                        if (D(list + 4 * j) == army) {
                            side = (special == i ? 0x8000u : 0u) | (i & 0x7Fu) << 8 | (j & 0xFFu);
                            break;
                        }
                }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { side = kSideUnproven; }
    --kntwr::probeDepth;
    return side;
}

void PublishAggregate(U base, const Aggregate& a) {
    U* w = g_words + base;
    w[AMaxUnitUs] = Us(a.maxQ); w[AUnits] = Sat(a.units); w[ARouteUnits] = Sat(a.routeUnits); w[ARouteUs] = Us(a.routeQ);
    w[AUnitUs] = Us(a.unitQ); w[ASumMaxUnitUs] = Us(a.sumMaxQ); w[AUnitsGe5ms] = Sat(a.ge5); w[AUnitsGe1ms] = Sat(a.ge1);
    w[APrepUs] = Us(a.prepQ); w[AFsmUs] = Us(a.fsmQ); w[AFsmCalls] = Sat(a.fsmCalls); w[AFormationUs] = Us(a.formQ);
    w[AR2Us] = Us(a.r2Q); w[AR1Entries] = Sat(a.r1Entries);
}
void PublishTop() {
    Entry sorted[kTop];
    memcpy(sorted, g_top, sizeof(g_top));
    std::sort(sorted, sorted + g_topCount, [](const Entry& a, const Entry& b) { return a.word[ESite18Us] > b.word[ESite18Us]; });
    memset(g_words + TopTable, 0, kTop * kEntryWords * sizeof(U));
    for (U i = 0; i < g_topCount; ++i) memcpy(g_words + TopTable + i * kEntryWords, sorted[i].word, sizeof(Entry));
}
} // namespace

bool Start(const Binding& binding) {
    Stop();
    void* memory = VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return false;
    g_s = new (memory) Storage; // zero-filled pages; trivially constructible
    g_sampleMs = binding.sample_ms;
    QueryPerformanceFrequency(&g_frequency);
    Reset();
    g_words[Version] = kVersion; g_words[Enabled] = 1; g_words[StormFactor] = kStormFactor; g_words[SampleThresholdMs] = g_sampleMs;
    return true;
}
void Stop() {
    if (g_s) VirtualFree(g_s, 0, MEM_RELEASE);
    g_s = nullptr; g_inUnit = 0;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    memset(g_agg, 0, sizeof(g_agg)); memset(&g_t, 0, sizeof(g_t)); memset(&g_occ, 0, sizeof(g_occ));
    memset(g_ring, 0, sizeof(g_ring)); memset(g_top, 0, sizeof(g_top));
    g_ringCount = g_ringNext = g_ticks = g_stormTicks = g_median = g_topCount = g_queries = 0;
    g_observerQ = g_unreadable = 0; g_inUnit = 0; g_root = 0;
    g_t.maxSide = kSideUnproven;
}
bool Started() { return g_s != nullptr; }

U Unit(void* unit, U root, Native native) {
    if (!g_s || g_inUnit) return native(unit);
    g_inUnit = 1;
    g_root = root;
    const LONGLONG t0 = Now();
    const U u = static_cast<U>(reinterpret_cast<uintptr_t>(unit));
    memset(&g_occ, 0, sizeof(g_occ));
    const LONGLONG a = Now();
    const U result = native(unit);
    const LONGLONG b = Now();
    const LONGLONG q = (b - a) - g_occ.observerQ; // gate QPC overhead of the brackets/route gates is instrumentation, not unit cost
    const u64 uq = q > 0 ? static_cast<u64>(q) : 0;
    TickState& t = g_t;
    const U ordinal = static_cast<U>(t.units);
    ++t.units; t.unitQ += uq;
    if (g_occ.r2Reached) { ++t.routeUnits; t.routeQ += uq; }
    const u64 freq = static_cast<u64>(g_frequency.QuadPart);
    if (uq >= freq * kBig / 1000000ull) ++t.ge5;
    if (uq >= freq * kMid / 1000000ull) ++t.ge1;
    if (ordinal == 0 || uq > t.maxQ) { t.maxQ = uq; t.maxOrdinal = ordinal; t.maxSide = SideOf(u); }
    for (U i = 0; i < kBrackets; ++i) t.bracketQ[i] += g_occ.bracketQ[i];
    t.fsmCalls += g_occ.bracketCalls[BFsm];
    t.r2Q += g_occ.r2Q; t.r2Full += g_occ.r2Full; t.r1Entries += g_occ.r1Entries;
    const LONGLONG t1 = Now();
    g_observerQ += static_cast<u64>((t1 - t0) - q);
    g_inUnit = 0;
    return result;
}

U Call(Bracket which, void* ecx, Native native) {
    if (!g_s || !g_inUnit) return native(ecx);
    const LONGLONG o0 = Now();
    const U result = native(ecx);
    const LONGLONG b = Now();
    g_occ.bracketQ[which] += static_cast<u64>(b - o0); ++g_occ.bracketCalls[which];
    g_occ.observerQ += Now() - b; // exit bookkeeping; the entry overhead (o0 is read inside the gate) is one QPC read
    return result;
}

U Route2(void* command, Native native) {
    if (!g_s) return native(command);
    if (!g_inUnit) { ++g_words[RouteOutside]; return native(command); }
    const LONGLONG o0 = Now();
    const RouteRead r = ReadRoute2(static_cast<U>(reinterpret_cast<uintptr_t>(command)));
    const LONGLONG a = Now();
    const U result = native(command);
    const LONGLONG b = Now();
    g_occ.r2Q += static_cast<u64>(b - a);
    if (!r.ok) ++g_unreadable;
    if (r.reach) ++g_occ.r2Reached;
    if (r.full) ++g_occ.r2Full;
    g_occ.observerQ += (a - o0) + (Now() - b);
    return result;
}

U Route1(void* state, void* edx, U arg, Native3 native) {
    if (!g_s) return native(state, edx, arg);
    if (!g_inUnit) { ++g_words[RouteOutside]; return native(state, edx, arg); }
    ++g_occ.r1Entries;
    const LONGLONG a = Now();
    const U result = native(state, edx, arg);
    const LONGLONG b = Now();
    g_occ.r1Q += static_cast<u64>(b - a);
    g_occ.observerQ += Now() - b; // exit bookkeeping; the entry overhead (a is read inside the gate) is one QPC read
    return result;
}

U Route1b(void* state, void* edx, U arg, Native3 native) {
    if (!g_s) return native(state, edx, arg);
    if (!g_inUnit) { ++g_words[RouteOutside]; return native(state, edx, arg); }
    const LONGLONG a = Now();
    const U result = native(state, edx, arg);
    const LONGLONG b = Now();
    g_occ.r1bQ += static_cast<u64>(b - a);
    g_occ.observerQ += Now() - b;
    return result;
}

bool InUnit() { return g_s && g_inUnit != 0; }
void OccurrenceRouteQ(unsigned long long* r1Q, unsigned long long* r1bQ, unsigned long long* r2Q) {
    if (r1Q) *r1Q = g_occ.r1Q;
    if (r1bQ) *r1bQ = g_occ.r1bQ;
    if (r2Q) *r2Q = g_occ.r2Q;
}
void AddObserverQ(unsigned long long q) { if (g_s && g_inUnit) g_occ.observerQ += static_cast<LONGLONG>(q); }

void TickEnd(U tick, U site18Us, U site34Us, U out[4], bool* stormOut) {
    TickState& t = g_t;
    ++g_ticks;
    const bool ran = site18Us != 0;
    const bool storm = ran && g_ringCount >= kWarmup && site18Us > kStormFactor * g_median;
    if (stormOut) *stormOut = storm;
    if (ran || t.units) {
        Aggregate& agg = g_agg[storm ? 0 : 1];
        if (t.maxQ > agg.maxQ) agg.maxQ = t.maxQ;
        agg.units += t.units; agg.routeUnits += t.routeUnits; agg.routeQ += t.routeQ; agg.unitQ += t.unitQ;
        agg.sumMaxQ += t.maxQ; agg.ge5 += t.ge5; agg.ge1 += t.ge1;
        agg.prepQ += t.bracketQ[BPrep]; agg.fsmQ += t.bracketQ[BFsm]; agg.fsmCalls += t.fsmCalls;
        agg.formQ += t.bracketQ[BFormation]; agg.r2Q += t.r2Q; agg.r1Entries += t.r1Entries;
    }
    if (storm) {
        ++g_stormTicks;
        Entry e = {};
        U* w = e.word;
        w[ETick] = tick; w[ESite18Us] = site18Us; w[ESite34Us] = site34Us;
        w[EUnitsRoute] = Cap(t.units, 16) | Cap(t.routeUnits, 16) << 16;
        w[EMaxUnitUs] = Us(t.maxQ);
        w[EMaxOrdSide] = Cap(t.maxOrdinal, 16) | (t.units ? t.maxSide & 0xFFFFu : kSideUnproven) << 16;
        w[EPrepUs] = Us(t.bracketQ[BPrep]); w[EFsmUs] = Us(t.bracketQ[BFsm]); w[EFormationUs] = Us(t.bracketQ[BFormation]);
        w[ER2Us] = Us(t.r2Q);
        w[ECounts] = Cap(t.ge5, 10) | Cap(t.r2Full, 10) << 10 | Cap(t.r1Entries, 10) << 20;
        U slot = g_topCount;
        if (g_topCount < kTop) ++g_topCount;
        else {
            slot = 0;
            for (U i = 1; i < kTop; ++i) if (g_top[i].word[ESite18Us] < g_top[slot].word[ESite18Us]) slot = i;
            if (g_top[slot].word[ESite18Us] >= site18Us) slot = kTop; // not larger than the smallest kept
        }
        if (slot < kTop) g_top[slot] = e;
    }
    if (ran) { // the ring and the running median advance only after this tick was classified against the previous ones
        g_ring[g_ringNext] = site18Us; g_ringNext = (g_ringNext + 1) % kRing;
        if (g_ringCount < kRing) ++g_ringCount;
        g_median = Median();
    }
    out[0] = Us(t.maxQ); out[1] = Sat(t.routeUnits); out[2] = Us(t.routeQ);
    out[3] = Cap(t.ge5, 16) | (t.units ? t.maxSide & 0xFFFFu : kSideUnproven) << 16;
    g_words[Ticks] = g_ticks; g_words[StormTicks] = g_stormTicks; g_words[MedianSite18Us] = g_median;
    g_words[ObserverUs] = Us(g_observerQ); g_words[Unreadable] = Sat(g_unreadable);
    PublishAggregate(StormAggregate, g_agg[0]); PublishAggregate(CalmAggregate, g_agg[1]);
    if (storm) PublishTop();
    memset(&t, 0, sizeof(t)); t.maxSide = kSideUnproven;
}

void Snapshot(U* words, U sampleAdmitted, U sampleRejected) {
    memcpy(words, g_words, sizeof(g_words));
    if (!g_words[Enabled]) return;
    words[SampleAdmitted] = sampleAdmitted; words[SampleRejected] = sampleRejected;
}
} // namespace kntwr_army_storm
