// Army per-unit update Stage A instrumentation (native_army_unit.h). Reads native memory only; writes only its rows.
#include "native_army_unit.h"
#include "brain2/native_region_table.h"
#include <windows.h>
#include <string.h>
#include <algorithm>
#include <new>
#include "ntw2_guard.h"

namespace ntw2_army_unit {
namespace {
constexpr U kUnitBytes = 0xE00;            // highest field read: U+DCC
constexpr U kFormationBytes = 0x6F0;       // F+18 .. F+6EC (pose transform pointer at F+62C+B0+10)
constexpr U kInfantryFormation = 0x13211D8; // formation class whose +C slot is 580A30 (analysis section 2.3)
constexpr U kSetSlots = 4096, kSetLimit = kSetSlots / 4 * 3;
constexpr U kTickCapacity = 16384;
constexpr U kSnapshotUnits = 2048, kSnapshotCells = 64;
constexpr U kListCap = 1024, kAttachedCap = 64, kFormationCap = 8;
constexpr U kFlagAggregation = 1, kFlagNeighbour = 2;
constexpr U kAggregationCells = 4, kNeighbourCells = 18;

U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }

struct Slot { U key, stamp, flags; };
struct Storage {
    ntw2_region::Table table;
    Slot foreign[kSetSlots]; // per occurrence (stamp = occurrence number)
    Slot seen[kSetSlots];    // per stage (stamp = stage number): repeated occurrences
    U tickCosts[kTickCapacity];
    U snapshot[kSnapshotUnits * kSnapshotCells];
};

Storage* g_s;
U g_words[kWords];
U g_delta, g_workers, g_ai2, g_inStage, g_inUnit, g_model, g_tick, g_haveTick, g_tickN;
U g_stageStamp, g_occurrenceStamp, g_stageOccurrences, g_distinct, g_seenUsed, g_queries;
U (*g_planner)();
LARGE_INTEGER g_frequency;
unsigned long long g_unitQ, g_strictQ, g_dynamicQ, g_stageQ, g_observerQ, g_snapshotQ, g_rngQ, g_unreadableQ,
                   g_reasonQ[kReasons], g_commandQ[kCommands];

LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
U Us(unsigned long long q) { return g_frequency.QuadPart ? static_cast<U>(q * 1000000ull / g_frequency.QuadPart) : 0; }
U Dus(unsigned long long q) { return g_frequency.QuadPart ? static_cast<U>(q * 10000000ull / g_frequency.QuadPart) : 0; }
U SlotOf(U key) { return ((key >> 3) * 2654435761u) >> 20; } // 12 bits: kSetSlots == 4096

// Returns the slot (claiming a stale one) or null when the set is full; `fresh` is set for a new key.
Slot* Insert(Slot* set, U stamp, U key, U& used, bool& fresh) {
    fresh = false;
    for (U probe = 0, at = SlotOf(key); probe < kSetSlots; ++probe, at = (at + 1) & (kSetSlots - 1)) {
        Slot& s = set[at];
        if (s.stamp != stamp) {
            if (used == kSetLimit) return nullptr;
            s.key = key; s.stamp = stamp; s.flags = 0; ++used; fresh = true;
            return &s;
        }
        if (s.key == key) return &s;
    }
    return nullptr;
}
void AddForeign(U key, U flag) {
    bool fresh;
    Slot* const s = Insert(g_s->foreign, g_occurrenceStamp, key, g_distinct, fresh);
    if (!s) { ++g_words[ForeignSetOverflow]; return; }
    if (s->flags & flag) return;
    s->flags |= flag;
    g_words[PinnedCellsSum] += flag == kFlagAggregation ? kAggregationCells : kNeighbourCells;
}
// Inserts the entries of a native pointer list except `self`; returns the entry count read, ~0 when unreadable.
U AddList(U count, U data, U self, U flag) {
    ntw2_region::Table& t = g_s->table;
    if (!count) return 0;
    if (count > kListCap || !t.Readable(data, count * 4, g_queries)) return ~0u;
    U n = 0;
    for (U i = 0; i < count; ++i) {
        const U other = D(data + 4 * i);
        if (!other || other == self) continue;
        AddForeign(other, flag); ++n;
    }
    return n;
}
// 5821B0 enumerates the candidate list 531E40(U) = [[U+1EC]+D8] (count +44, data +48) early in 57F070.
void NeighbourWitness(U u) {
    ntw2_region::Table& t = g_s->table;
    const U c = D(u + 0x1EC);
    const U list = c && t.Readable(c + 0xD8, 4, g_queries) ? D(c + 0xD8) : 0;
    const U n = list && t.Readable(list + 0x44, 8, g_queries) ? AddList(D(list + 0x44), D(list + 0x48), u, kFlagNeighbour) : ~0u;
    if (n == ~0u) ++g_words[ForeignUnreadable]; else g_words[ForeignNeighbourSum] += n;
}
// 53A9E0 (last but two in 581F30) enumerates [U+1EC]+F0/F4 behind gates; the pure-read ones are replayed on the
// post-call state, the 55AC40/55C480 predicates and the U+1B0/U+1AF command-query branch are not (upper bound).
void AggregationWitness(U u) {
    ntw2_region::Table& t = g_s->table;
    const U c = D(u + 0x1EC);
    if (!c || !t.Readable(c + 0xD8, 0x20, g_queries)) { ++g_words[ForeignUnreadable]; return; }
    const U p = D(c + 0xD8), count = D(c + 0xF0);
    const bool flag73 = p && t.Readable(p + 0x73, 1, g_queries) && B(p + 0x73);
    bool skip = flag73 || count == 1 || D(u + 0xD80);
    if (!skip && B(u + 0x1B0) != 1 && B(u + 0x1AF) != 1)
        skip = !(B(u + 0x1AB) | B(u + 0x1AC) | B(u + 0x1AD) | B(u + 0x1AE)) || D(u + 0x930) || B(u + 0xD7C) == 1;
    if (skip) { ++g_words[AggregationSkipped]; return; }
    const U n = AddList(count, D(c + 0xF4), u, kFlagAggregation);
    if (n == ~0u) ++g_words[ForeignUnreadable]; else g_words[ForeignAggregationSum] += n;
}
// Section 8.4 cells of one listed unit, copied into module storage (measures the frozen-view cost only).
U CopyCells(U u, U* out) {
    ntw2_region::Table& t = g_s->table;
    U n = 0;
    if (!t.Readable(u, kUnitBytes, g_queries)) return 0;
    out[n++] = B(u + 0xD9E); out[n++] = D(u + 0xC2C);
    const U context = D(u + 0xC00);
    const U model = context && t.Readable(context + 8, 4, g_queries) ? D(context + 8) : 0;
    const U manager = model && t.Readable(model + 0xB0, 4, g_queries) ? D(model + 0xB0) : 0;
    out[n++] = manager && t.Readable(manager + 0x2704, 1, g_queries) ? B(manager + 0x2704) : 0;
    const auto pose = [&](U p) { // 80E9D0: P+0/4/8 and transform [P+10]: +80/84/88, +9C..+BC
        out[n++] = D(p); out[n++] = D(p + 4); out[n++] = D(p + 8);
        const U x = D(p + 0x10);
        if (x && t.Readable(x + 0x80, 0x40, g_queries)) {
            for (U o = 0x80; o <= 0x88; o += 4) out[n++] = D(x + o);
            for (U o = 0x9C; o <= 0xBC; o += 4) out[n++] = D(x + o);
        }
    };
    pose(u + 0xB0);
    const U f = D(u + 0xADC);
    out[n++] = f;
    if (f && t.Readable(f, kFormationBytes, g_queries)) {
        out[n++] = D(f + 0x670);
        for (U o = 0x644; o <= 0x664; o += 4) out[n++] = D(f + o);
        pose(f + 0x62C + 0xB0);
    }
    return n;
}
void SnapshotList(U count, U data, U& units) {
    if (!count || count > kListCap || !g_s->table.Readable(data, count * 4, g_queries)) return;
    for (U i = 0; i < count && units < kSnapshotUnits; ++i) {
        const U u = D(data + 4 * i);
        if (u && CopyCells(u, g_s->snapshot + units * kSnapshotCells)) ++units;
    }
}
void FinalizeTick() {
    const U n = g_tickN;
    g_tickN = 0;
    if (!n) return;
    U* const v = g_s->tickCosts;
    const U i50 = (n + 1) / 2 - 1, i90 = (9 * n + 9) / 10 - 1;
    std::nth_element(v, v + i90, v + n);
    const U p90 = v[i90];
    std::nth_element(v, v + i50, v + i90 + 1);
    const U p50 = v[i50];
    ++g_words[QuantileTicks];
    g_words[TickP50SumDus] += p50; g_words[TickP90SumDus] += p90;
    g_words[LastTickP50Dus] = p50; g_words[LastTickP90Dus] = p90;
    if (p90 > g_words[MaxTickP90Dus]) g_words[MaxTickP90Dus] = p90;
}
void PublishTimes() {
    g_words[UnitUs] = Us(g_unitQ); g_words[StrictEligibleUs] = Us(g_strictQ); g_words[DynamicEligibleUs] = Us(g_dynamicQ);
    g_words[StageUs] = Us(g_stageQ); g_words[ObserverUs] = Us(g_observerQ); g_words[SnapshotUs] = Us(g_snapshotQ);
    g_words[RngDrawingUs] = Us(g_rngQ); g_words[UnreadableUs] = Us(g_unreadableQ);
    for (U r = 0; r < kReasons; ++r) g_words[ReasonUs + r] = Us(g_reasonQ[r]);
    for (U c = 0; c < kCommands; ++c) g_words[CommandRows + c * kCommandStride + 3] = Us(g_commandQ[c]);
}
void Census(U command, bool dynamicOwner, bool rng, LONGLONG q) {
    U row = kCommands;
    for (U i = 0; i < g_words[CommandDistinct]; ++i) if (g_words[CommandRows + i * kCommandStride] == command) { row = i; break; }
    if (row == kCommands && g_words[CommandDistinct] < kCommands) {
        row = g_words[CommandDistinct]++;
        g_words[CommandRows + row * kCommandStride] = command;
    }
    if (row == kCommands) { ++g_words[CommandOverflow]; return; }
    U* const w = g_words + CommandRows + row * kCommandStride;
    ++w[1]; w[2] += dynamicOwner; w[4] += rng;
    g_commandQ[row] += static_cast<unsigned long long>(q);
}
} // namespace

bool ReadProbe(U u, U delta, ntw2_region::Table& t, U& q, Probe& o) {
    memset(&o, 0, sizeof(o));
    if (!u || !t.Readable(u, kUnitBytes, q)) return false;
    o.readable = 1;
    o.aa0 = D(u + 0xAA0); o.d48 = B(u + 0xD48); o.dc8 = D(u + 0xDC8); o.dcc = D(u + 0xDCC); o.ae8 = D(u + 0xAE8);
    o.trigger = !o.dc8 ? 0 : t.Readable(o.dc8 + 0x68, 1, q) ? B(o.dc8 + 0x68) : ~0u;
    o.c930 = D(u + 0x930); o.c934 = D(u + 0x934);
    const U command = u + 0x398 + o.c934 * 0x90;
    o.command = !o.c930 ? 0 : o.c934 < 0x10000 && t.Readable(command, 4, q) && D(command) ? D(command) - delta : ~0u;
    o.a60 = D(u + 0xA60); o.ab0 = D(u + 0xAB0); o.acc = D(u + 0xACC); o.adc = D(u + 0xADC);
    o.members = D(u + 0x2CC); o.fsm = D(u + 0xD6C);
    const U attached = D(u + 0x1F4);
    if (attached && t.Readable(attached + 0x10, 8, q)) {
        o.attached = D(attached + 0x10);
        const U n = o.attached < kAttachedCap ? o.attached : kAttachedCap, data = D(attached + 0x14);
        if (n && t.Readable(data, n * 4, q))
            for (U i = 0; i < n && !o.attachedRemove; ++i) {
                const U m = D(data + 4 * i);
                o.attachedRemove = m && t.Readable(m + 0x6F8, 1, q) && B(m + 0x6F8);
            }
    }
    const U nf = o.acc < kFormationCap ? o.acc : kFormationCap, fdata = D(u + 0xAD0);
    if (nf && t.Readable(fdata, nf * 4, q))
        for (U i = 0; i < nf && !o.formationCommand; ++i) {
            const U f = D(fdata + 4 * i);
            o.formationCommand = f && t.Readable(f, kFormationBytes, q) && D(f) == kInfantryFormation + delta &&
                D(f + 0x18) && B(f + 0x515) && (B(f + 0x508) != 1 || B(f + 0x498)) && !D(f + 0x460);
        }
    return true;
}
U RngSteps(U from, U to, U bound) {
    if (from == to) return 0;
    U x = from;
    for (U i = 1; i <= bound; ++i) { x = x * 0x343FDu + 0x269EC3u; if (x == to) return i; }
    return ~0u;
}
U Classify(const Probe& a, const Probe& b, U plannerDelta, U rngSteps, U& detail) {
    if (!a.readable || !b.readable) { detail = 1u << EUnreadable; return 1u << RNonClosed; }
    U d = 1u << KIdentity;
    if (!a.ae8) d |= 1u << KFsm;
    else { d |= 1u << KAlternate; if (a.c930) d |= 1u << KSelected; }
    if (a.c930) d |= 1u << KCommand;
    if (a.a60) d |= 1u << KDriver;
    if (a.ab0 || a.acc || a.adc) d |= 1u << KFormation;
    if ((a.aa0 || b.aa0) && a.members) d |= 1u << KMemberGetters; // 57F147 tests AA0 after 5857A0 updated it
    if (a.dc8) d |= 1u << K601500;
    if (a.dcc) d |= 1u << K600EF0;
    if (a.attachedRemove) d |= 1u << KAttachedRemove;
    if (a.formationCommand) d |= 1u << KFormationCommand;
    if (a.aa0 == 0 && b.aa0 == 1) d |= 1u << ENotifyA40;
    if (a.aa0 != 2 && b.aa0 == 2) d |= 1u << ENotify608;
    if ((b.d48 & 0xFF) > (a.d48 & 0xFF)) d |= 1u << ENotifyBD0;
    if (a.dc8 && a.dc8 == b.dc8 && a.trigger == 0 && b.trigger && b.trigger != ~0u) d |= 1u << ETrigger;
    if (rngSteps) d |= 1u << ERng;
    if (plannerDelta) d |= 1u << EPlanner;
    if (a.members != b.members) d |= 1u << EMembers;
    if (a.attached != b.attached) d |= 1u << EAttached;
    if (a.a60 != b.a60) d |= 1u << EDrivers;
    if (a.c930 != b.c930 || a.c934 != b.c934) d |= 1u << ECommand;
    if (a.fsm != b.fsm) d |= 1u << EFsm;
    detail = d;
    const auto any = [d](U mask) { return (d & mask) != 0; };
    U r = 0;
    if (any(1u << ENotifyA40 | 1u << ENotify608 | 1u << ENotifyBD0 | 1u << ETrigger)) r |= 1u << RNotification;
    if (any(1u << EPlanner)) r |= 1u << RPlanner;
    if (any(1u << EMembers | 1u << EAttached | 1u << EDrivers | 1u << ECommand | 1u << KAttachedRemove |
            1u << KFormationCommand)) r |= 1u << RAllocList;
    if (any(1u << EFsm) || (any(1u << KSelected) && any(1u << ECommand))) r |= 1u << RReturn;
    if (any(kKindMask)) r |= 1u << RNonClosed;
    return r;
}

// Guarded observation. Proofs are re-established first: a native call (this unit's or an earlier occurrence's) may
// have freed or decommitted probed memory. Every load runs under SEH bracketed by ntw2::probeDepth, so a stale or
// racing range records an unreadable observation instead of faulting (and is not taken as a crash capture).
struct Reading { Probe probe; U rng, rngValid; };
static void Observe(U u, bool before, Reading& out) {
    ntw2_region::Table& t = g_s->table;
    t.Clear();
    bool ok = false;
    ++ntw2::probeDepth;
    __try {
        out.rngValid = g_model && t.Readable(g_model + 0x50, 4, g_queries) ? 1u : 0u;
        out.rng = out.rngValid ? D(g_model + 0x50) : 0;
        ok = ReadProbe(u, g_delta, t, g_queries, out.probe);
        if (ok) { if (before) NeighbourWitness(u); else AggregationWitness(u); }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    --ntw2::probeDepth;
    if (!ok) { out.probe.readable = 0; out.rngValid = 0; }
}
static U SnapshotContainer(U c) {
    ntw2_region::Table& t = g_s->table;
    U units = 0;
    ++ntw2::probeDepth;
    __try {
        if (c && t.Readable(c + 0xF0, 8, g_queries)) SnapshotList(D(c + 0xF0), D(c + 0xF4), units);
        if (c && t.Readable(c + 0x1A4, 8, g_queries)) SnapshotList(D(c + 0x1A4), D(c + 0x1A8), units);
    } __except (EXCEPTION_EXECUTE_HANDLER) { ++g_words[ForeignUnreadable]; }
    --ntw2::probeDepth;
    return units;
}

bool Start(const Binding& binding) {
    Stop();
    void* memory = VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return false;
    g_s = new (memory) Storage; // zero-filled pages; trivially constructible
    g_delta = binding.image_base - 0x400000;
    g_workers = binding.workers; g_planner = binding.planner_calls; g_ai2 = binding.ai2_concurrent;
    QueryPerformanceFrequency(&g_frequency);
    Reset();
    return true;
}
void Stop() {
    if (g_s) VirtualFree(g_s, 0, MEM_RELEASE);
    g_s = nullptr; g_inStage = g_inUnit = 0;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    g_unitQ = g_strictQ = g_dynamicQ = g_stageQ = g_observerQ = g_snapshotQ = g_rngQ = g_unreadableQ = 0;
    memset(g_reasonQ, 0, sizeof(g_reasonQ)); memset(g_commandQ, 0, sizeof(g_commandQ));
    g_haveTick = g_tickN = g_stageStamp = g_occurrenceStamp = g_stageOccurrences = 0;
    if (g_s) { memset(g_s->foreign, 0, sizeof(g_s->foreign)); memset(g_s->seen, 0, sizeof(g_s->seen)); }
}
bool Started() { return g_s != nullptr; }

U Stage(void* container, U model, Native native) {
    if (!g_s || g_inStage || g_inUnit) return native(container);
    g_inStage = 1;
    const LONGLONG s0 = Now();
    ntw2_region::Table& t = g_s->table;
    t.Clear();
    if (!g_words[Stages]) {
        g_words[Version] = kVersion; g_words[Enabled] = 1; g_words[Workers] = g_workers;
        g_words[PlannerMeasured] = g_planner ? 1 : 0; g_words[Ai2Concurrent] = g_ai2;
    }
    ++g_words[Stages];
    g_model = model && t.Readable(model + 0x50, 0xC, g_queries) ? model : 0;
    const U tick = g_model ? D(g_model + 0x58) : 0;
    if (!g_haveTick || tick != g_tick) { FinalizeTick(); g_haveTick = 1; g_tick = tick; ++g_words[Ticks]; }
    ++g_stageStamp; g_stageOccurrences = 0; g_seenUsed = 0;
    const U c = static_cast<U>(reinterpret_cast<uintptr_t>(container));
    const LONGLONG k0 = Now();
    const U units = SnapshotContainer(c);
    const LONGLONG k1 = Now();
    g_words[SnapshotUnits] += units;
    g_snapshotQ += static_cast<unsigned long long>(k1 - k0);
    const LONGLONG a = Now();
    const U result = native(container);
    const LONGLONG b = Now();
    g_words[UnitsLastStage] = g_stageOccurrences;
    if (g_stageOccurrences > g_words[MaxUnitsStage]) g_words[MaxUnitsStage] = g_stageOccurrences;
    const LONGLONG s1 = Now();
    g_stageQ += static_cast<unsigned long long>(s1 - s0);
    g_observerQ += static_cast<unsigned long long>((k0 - s0) + (a - k1) + (s1 - b));
    PublishTimes();
    g_inStage = 0;
    return result;
}

U Unit(void* unit, U list, Native native) {
    if (!g_s || !g_inStage || g_inUnit) return native(unit);
    g_inUnit = 1;
    const LONGLONG t0 = Now();
    const U u = static_cast<U>(reinterpret_cast<uintptr_t>(unit));
    ++g_occurrenceStamp; g_distinct = 0;
    Reading pre = {}, post = {};
    Observe(u, true, pre);
    const U planner0 = g_planner ? g_planner() : 0;
    const LONGLONG a = Now();
    const U result = native(unit);
    const LONGLONG b = Now();
    const U plannerDelta = g_planner ? g_planner() - planner0 : 0;
    Observe(u, false, post);

    const LONGLONG q = b - a;
    const unsigned long long uq = static_cast<unsigned long long>(q);
    // Only a complete pre+post observation is classified; an unreadable one is its own bucket, never eligible.
    const bool observed = pre.probe.readable && post.probe.readable;
    const U steps = observed && pre.rngValid && post.rngValid ? RngSteps(pre.rng, post.rng, kRngBound) : 0;
    U detail = 0;
    const U reasons = Classify(pre.probe, post.probe, plannerDelta, steps, detail);
    ++g_words[Occurrences]; ++g_words[list ? AlternateOccurrences : MainOccurrences]; ++g_stageOccurrences;
    g_unitQ += uq;
    bool dynamicOwner = true;
    if (!observed) { ++g_words[Unreadable]; g_unreadableQ += uq; }
    else {
        for (U r = 0; r < kReasons; ++r) if (reasons >> r & 1) {
            ++g_words[ReasonCount + r]; g_reasonQ[r] += uq;
            if (reasons == 1u << r) ++g_words[SoleReason + r];
        }
        if (!reasons) { ++g_words[StrictEligible]; g_strictQ += uq; }
        dynamicOwner = (reasons & ~(1u << RNonClosed)) != 0;
        if (!dynamicOwner) { ++g_words[DynamicEligible]; g_dynamicQ += uq; }
        if (steps) {
            ++g_words[RngDrawing]; g_rngQ += uq;
            if (steps == ~0u) ++g_words[RngUnresolved]; else g_words[RngDraws] += steps;
        }
    }
    for (U i = 0; i < kDetails; ++i) if (detail >> i & 1) ++g_words[DetailCount + i];
    const U us = Us(uq);
    U bucket = 0;
    while (bucket + 1 < kHistogram && us >= (1u << bucket)) ++bucket;
    ++g_words[CostHistogram + bucket];
    if (g_tickN < kTickCapacity) g_s->tickCosts[g_tickN++] = Dus(uq);
    else ++g_words[TickBufferOverflow];
    Census(pre.probe.readable ? pre.probe.command : ~0u, dynamicOwner, steps != 0, q);
    g_words[ForeignDistinctSum] += g_distinct;
    if (g_distinct > g_words[ForeignDistinctMax]) g_words[ForeignDistinctMax] = g_distinct;
    bool fresh = true;
    if (Insert(g_s->seen, g_stageStamp, u, g_seenUsed, fresh) && !fresh) ++g_words[DuplicateOccurrences];
    const LONGLONG t1 = Now();
    g_observerQ += static_cast<unsigned long long>((t1 - t0) - q);
    g_inUnit = 0;
    return result;
}

void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
} // namespace ntw2_army_unit
