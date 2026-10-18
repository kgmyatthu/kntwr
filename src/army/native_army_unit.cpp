// Army per-unit update Stage A instrumentation (native_army_unit.h). Reads native memory only; writes only its rows.
#include "native_army_unit.h"
#include "brain2/native_region_table.h"
#include <windows.h>
#include <string.h>
#include <algorithm>
#include <new>
#include "core/ntw2_guard.h"

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
    uint8_t own[kUnitObjectBytes + 8 * kInfantryFormationBytes + kListCap * 4]; // B0 first-order own-state copy
};

Storage* g_s;
U g_words[kWords];
U g_delta, g_workers, g_ai2, g_inStage, g_inUnit, g_model, g_tick, g_haveTick, g_tickN;
U g_stageStamp, g_occurrenceStamp, g_stageOccurrences, g_distinct, g_seenUsed, g_queries;
U (*g_planner)();
LARGE_INTEGER g_frequency;
unsigned long long g_unitQ, g_strictQ, g_dynamicQ, g_stageQ, g_observerQ, g_snapshotQ, g_rngQ, g_unreadableQ,
                   g_reasonQ[kReasons], g_commandQ[kCommands];
// B0 (native_army_unit.h): row, QPC accumulators per us word, per-occurrence FSM gate state, stage recorder manager.
U g_b0[kB0Words];
unsigned long long g_b0Q[kB0Words];
U g_inFsm, g_lastManager, g_haveManager, g_stageManager;
struct FsmOccurrence { U calls, transition, stepped, stepState, unknown; LONGLONG observerQ; };
FsmOccurrence g_occ;
// preferred-base VAs (analysis/native-army-update-per-unit.md 10.2, 10.3; native-army-stage-b-plan.md 2-4)
constexpr U kFsmTable = 0x1320F28, kStateA = 0x1450908, kSentinel = 0x1466CC4;
constexpr U kSecondaryFirst = 0x1450BDC, kFormationCommandClass = 0x1324B54, kDirtyCommandClass = 0x1323B64;
constexpr U kDistanceHeader = 0x14A3EC4, kRecordHeader = 0x14A3ED8;
constexpr U kRecorderEnable = 0x1459B00, kRecorderDcc = 0x1459DCC, kRecorderManager = 0x15F8BC0,
            kRecorderProvider = 0x15F9054;
constexpr U kScratchNCap = 1u << 20;

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
    for (U w = 0; w < kB0Words; ++w) if (g_b0Q[w]) g_b0[w] = Us(g_b0Q[w]); // only us words accumulate QPC ticks
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

// ---- B0 pure surface
U FsmStateIndex(U s) {
    if (s == kSentinel) return SSentinel;
    return s - kStateA < 5 * 4 && !((s - kStateA) & 3) ? (s - kStateA) / 4 : SOther; // A..E: 1450908 + 4*i
}
U SecondaryStateIndex(U s) {
    if (s == kSentinel) return 4;
    return s - kSecondaryFirst < 4 * 4 && !((s - kSecondaryFirst) & 3) ? (s - kSecondaryFirst) / 4 : 5;
}
void ReadGlobals(U delta, ntw2_region::Table& t, U& q, Globals& g) {
    memset(&g, 0, sizeof(g));
    if (t.Readable(kDistanceHeader + delta, kRecordHeader + 0x14 - kDistanceHeader, q)) {
        g.scratchOk = 1;
        g.distCap = D(kDistanceHeader + delta + 4); g.distCount = D(kDistanceHeader + delta + 8);
        g.distBacking = D(kDistanceHeader + delta + 0xC);
        g.recCap = D(kRecordHeader + delta + 4); g.recCount = D(kRecordHeader + delta + 8);
        g.recBacking = D(kRecordHeader + delta + 0xC);
    }
    if (t.Readable(kRecorderEnable + delta, 1, q) && t.Readable(kRecorderDcc + delta, 1, q) &&
        t.Readable(kRecorderManager + delta, 4, q) && t.Readable(kRecorderProvider + delta, 4, q)) {
        g.recorderOk = 1;
        g.enable = B(kRecorderEnable + delta); g.dcc = B(kRecorderDcc + delta);
        g.manager = D(kRecorderManager + delta); g.provider = D(kRecorderProvider + delta);
        if (g.manager && t.Readable(g.manager, 0x24, q)) { // DACCD0: M+4/+C counters, +18 comparator, +1C byte, +20 drops
            g.managerOk = 1;
            g.m4 = D(g.manager + 4); g.m20 = D(g.manager + 0x20); g.comparator = D(g.manager + 0x18);
            g.inhibit = B(g.manager + 0x1C);
        }
    }
}
bool RecorderQualified(const Globals& g) {
    return g.recorderOk && g.enable && g.manager && g.managerOk && !g.provider && !g.comparator && !g.inhibit;
}
U RecorderAppends(const Globals& a, const Globals& b) {
    if (!a.managerOk || !b.managerOk || a.manager != b.manager) return ~0u;
    return (b.m4 - a.m4) + (b.m20 - a.m20);
}
bool ReadB0Probe(U u, U delta, ntw2_region::Table& t, U& q, B0Probe& o) {
    memset(&o, 0, sizeof(o));
    if (!u || !t.Readable(u, kUnitObjectBytes, q)) return false;
    o.readable = 1;
    o.span[o.spans++] = {u, kUnitObjectBytes};
    const U attached = D(u + 0x1F4);
    if (attached && t.Readable(attached + 0x10, 8, q)) {
        const U n = D(attached + 0x10), data = D(attached + 0x14);
        if (n && n <= kListCap && t.Readable(data, n * 4, q)) o.span[o.spans++] = {data, n * 4};
    }
    const U nf = D(u + 0xACC), fdata = D(u + 0xAD0);
    if (nf > kFormationCap) ++o.unreadable; // beyond the observed cap (also a garbage count): one unreadable mark
    const U listed = nf < kFormationCap ? nf : kFormationCap;
    const bool listOk = !listed || t.Readable(fdata, listed * 4, q);
    if (!listOk) o.unreadable += listed;
    for (U i = 0; listOk && i < listed; ++i) {
        const U f = D(fdata + 4 * i);
        if (!f || !t.Readable(f, 4, q)) { ++o.unreadable; continue; }
        if (D(f) != kInfantryFormation + delta) {
            if (t.Readable(f, kOtherFormationBytes, q)) { ++o.other; o.span[o.spans++] = {f, kOtherFormationBytes}; }
            else ++o.unreadable;
            continue;
        }
        if (!t.Readable(f, kInfantryFormationBytes, q)) { ++o.unreadable; continue; }
        ++o.infantry;
        o.span[o.spans++] = {f, kInfantryFormationBytes};
        const U members = D(f + 0x18), dirty2790 = B(f + 0x2790) ? 1u : 0u;
        o.members += members;
        if (dirty2790 || B(f + 0x2791)) o.dirty = 1;
        const U agg = D(f + 0x62C + 4); // 53C1D7/53C1DA: N = [[C+4]+C], C = F+62C
        if (agg && t.Readable(agg + 0xC, 4, q)) { const U n = D(agg + 0xC); if (n > o.nMax) o.nMax = n < kScratchNCap ? n : kScratchNCap; }
        const U count = D(f + 0x20 + 0x440); // Q = F+20: count Q+440, {pointer,size} rows Q+400
        U dirtyCommands = 0;
        if (count > kQueueRows) ++o.queueBad;
        else {
            o.queue += count;
            for (U j = 0; j < count; ++j) {
                const U cmd = D(f + 0x20 + 0x400 + 8 * j);
                const U cls = cmd && t.Readable(cmd, 0x20, q) ? D(cmd) - delta : ~0u;
                if (cls == kDirtyCommandClass) ++dirtyCommands;
                if (o.commands < kQueueSample) {
                    o.commandClass[o.commands] = cls;
                    o.commandState[o.commands] = cls == kFormationCommandClass ? D(cmd + 0x1C) - delta : ~0u;
                    ++o.commands;
                }
            }
        }
        o.bound += members * (1 + dirtyCommands + dirty2790);
    }
    for (U i = 0; i < o.spans; ++i) o.ownBytes += o.span[i].bytes;
    return true;
}
U Refuse(bool observed, U reasons, bool transition, bool recorderRefused, bool otherRefused) {
    if (!observed) return RefUnreadable;
    if (reasons & 1u << RAllocList) return RefAlloc;
    if (transition) return RefTransition;
    if (recorderRefused) return RefRecorder;
    if (otherRefused || (reasons & (1u << RNotification | 1u << RPlanner | 1u << RReturn))) return RefOther;
    return RefCompletable;
}
U AllocSplit(U detail, bool growth, bool reserved) {
    if (growth) return AllocGrowth;
    if (reserved) return AllocReserve;
    if (detail & (1u << EMembers | 1u << EAttached | 1u << EDrivers | 1u << ECommand | 1u << KAttachedRemove))
        return AllocListChange;
    return AllocPredicateOnly;
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

// ---- B0 guarded reads (same discipline as Observe, which re-proved the table just before).
struct B0Reading { B0Probe probe; Globals globals; };
static void ObserveB0(U u, B0Reading& out) {
    ntw2_region::Table& t = g_s->table;
    bool ok = false;
    ++ntw2::probeDepth;
    __try {
        ReadGlobals(g_delta, t, g_queries, out.globals);
        ok = ReadB0Probe(u, g_delta, t, g_queries, out.probe);
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; memset(&out.globals, 0, sizeof(out.globals)); }
    --ntw2::probeDepth;
    if (!ok) out.probe.readable = 0;
}
static void ObserveGlobals(Globals& g) {
    ++ntw2::probeDepth;
    __try { ReadGlobals(g_delta, g_s->table, g_queries, g); }
    __except (EXCEPTION_EXECUTE_HANDLER) { memset(&g, 0, sizeof(g)); }
    --ntw2::probeDepth;
}
// First-order own-state copy into module storage: bytes copied, ~0 when a span faulted.
static U CopyOwn(const B0Probe& p) {
    U n = 0;
    bool ok = true;
    ++ntw2::probeDepth;
    __try {
        for (U i = 0; i < p.spans; ++i) {
            memcpy(g_s->own + n, reinterpret_cast<const void*>(static_cast<uintptr_t>(p.span[i].base)), p.span[i].bytes);
            n += p.span[i].bytes;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    --ntw2::probeDepth;
    return ok ? n : ~0u;
}
static bool ReadFsm(U s, U& table, U& state) {
    ntw2_region::Table& t = g_s->table;
    bool ok = false;
    ++ntw2::probeDepth;
    __try { if (s && t.Readable(s, 0x14, g_queries)) { table = D(s); state = D(s + 4); ok = true; } }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    --ntw2::probeDepth;
    return ok;
}
static void NoteRecorder(const Globals& g) {
    U* const w = g_b0;
    ++w[RecorderObservations];
    if (!g.recorderOk) { ++w[RecorderUnreadable]; return; }
    if (!g.enable) ++w[RecorderEnable0];
    if (!g.dcc) ++w[RecorderDccZero];
    if (!g.manager) ++w[RecorderManagerNull];
    else if (!g.managerOk) ++w[RecorderUnreadable];
    if (g.provider) ++w[RecorderProviderSet];
    if (g.comparator) ++w[RecorderComparatorSet];
    if (g.inhibit) ++w[RecorderInhibit];
    if (g_haveManager && g.manager != g_lastManager) ++w[RecorderManagerChanges];
    g_haveManager = 1; g_lastManager = g.manager;
    w[RecorderManagerLast] = g.manager; w[RecorderProviderLast] = g.provider; w[RecorderComparatorLast] = g.comparator;
}
static void NoteScratch(const Globals& g) {
    U* const w = g_b0;
    if (!g.scratchOk) { ++w[ScratchUnreadable]; return; }
    if (g.recCap > w[RecordCapMax]) w[RecordCapMax] = g.recCap;
    if (g.distCap > w[DistanceCapMax]) w[DistanceCapMax] = g.distCap;
    if (g.recCount || g.distCount) ++w[ScratchCountNonzero];
}
static void Add(U word, unsigned long long q) { ++g_b0[word]; g_b0Q[word + 1] += q; } // (count, us) pair
// One classified occurrence: FSM gate summary, pre/post B0 readings, own-state copy and the exclusive refusal bucket.
static void AccountB0(bool observed, U reasons, U detail, U steps, unsigned long long uq, const B0Reading& a,
                      const B0Reading& b, U copied, unsigned long long copyQ) {
    U* const w = g_b0;
    unsigned long long* const wq = g_b0Q;
    ++w[B0Occurrences];
    if (!g_occ.calls) wq[FsmNotReachedUs] += uq;
    else { ++w[FsmOccurrences]; if (g_occ.calls > 1) ++w[FsmMulti]; }
    if (g_occ.stepped) wq[FsmStateRows + g_occ.stepState * kFsmStride + 2] += uq;
    if (g_occ.transition) Add(TransitionOccurrences, uq);
    const B0Probe& p = a.probe;
    if (p.readable) {
        w[FormationInfantry] += p.infantry; w[FormationOther] += p.other; w[FormationUnreadable] += p.unreadable;
        w[ScratchNSum] += p.nMax; w[MembersSum] += p.members;
        if (p.nMax > w[ScratchNMax]) { w[ScratchNMax] = p.nMax; w[ScratchBytesMax] = p.nMax * (28 + 4); }
        w[QueueCommandsSum] += p.queue; w[QueueUnreadable] += p.queueBad;
        U seen = 0;
        for (U i = 0; i < p.commands; ++i) {
            if (p.commandState[i] != ~0u) ++w[SecondaryStateCounts + SecondaryStateIndex(p.commandState[i])];
            U row = kQueueClasses;
            for (U r = 0; r < w[QueueClassDistinct]; ++r) if (w[QueueClassRows + r * kQueueStride] == p.commandClass[i]) { row = r; break; }
            if (row == kQueueClasses && w[QueueClassDistinct] < kQueueClasses) {
                row = w[QueueClassDistinct]++;
                w[QueueClassRows + row * kQueueStride] = p.commandClass[i];
            }
            if (row == kQueueClasses) { ++w[QueueClassOverflow]; continue; }
            ++w[QueueClassRows + row * kQueueStride + 1];
            seen |= 1u << row;
        }
        for (U r = 0; r < kQueueClasses; ++r) if (seen >> r & 1) wq[QueueClassRows + r * kQueueStride + 2] += uq;
    }
    const bool probes = p.readable && b.probe.readable;
    const bool reserved = probes && b.probe.queue > p.queue;
    if (reserved) ++w[QueueReserved]; else if (probes && b.probe.queue < p.queue) ++w[QueueTruncated];
    NoteScratch(a.globals); NoteScratch(b.globals);
    bool growth = false;
    if (a.globals.scratchOk && b.globals.scratchOk) {
        if (a.globals.recCap != b.globals.recCap || a.globals.recBacking != b.globals.recBacking) { ++w[RecordGrowth]; growth = true; }
        if (a.globals.distCap != b.globals.distCap || a.globals.distBacking != b.globals.distBacking) { ++w[DistanceGrowth]; growth = true; }
    }
    NoteRecorder(a.globals); NoteRecorder(b.globals);
    const U tails = RecorderAppends(a.globals, b.globals);
    const bool qualified = RecorderQualified(a.globals) && RecorderQualified(b.globals) && a.globals.manager == g_stageManager;
    const bool tailed = tails == ~0u ? p.infantry != 0 : tails != 0; // unknown count: an infantry formation reaches 580C00
    if (tails != ~0u && tails) {
        w[RecorderTails] += tails; ++w[RecorderTailOccurrences]; wq[RecorderTailUs] += uq;
        if (tails > w[RecorderTailMax]) w[RecorderTailMax] = tails;
        w[RecorderDrops] += b.globals.m20 - a.globals.m20;
    }
    const bool recorderRefused = tailed && !qualified;
    if (recorderRefused) ++w[RecorderUnqualified];
    w[RngMemberBoundSum] += p.bound;
    if (steps) {
        if (steps != ~0u && steps <= p.bound) ++w[RngWithinBound]; else ++w[RngOverBound];
        if (steps != ~0u && steps > w[RngDrawMax]) w[RngDrawMax] = steps;
    }
    if (copied == ~0u) ++w[OwnUnreadable];
    else {
        w[OwnKbSum] += (copied + 1023) / 1024; wq[OwnCopyUs] += copyQ;
        if (copied > w[OwnBytesMax]) w[OwnBytesMax] = copied;
    }
    const bool dirty = p.readable && p.dirty;
    if (dirty) { ++w[DirtyOccurrences]; wq[DirtyUs] += uq; }
    const bool stageA = (reasons & (1u << RNotification | 1u << RPlanner | 1u << RReturn)) != 0;
    const U ref = Refuse(observed, reasons, g_occ.transition != 0, recorderRefused, dirty || g_occ.unknown);
    Add(RefusalRows + 2 * ref, uq);
    if (ref == RefAlloc) Add(AllocRows + 2 * AllocSplit(detail, growth, reserved), uq);
    if (ref == RefOther) Add(OtherRows + 2 * (stageA ? OtherStageA : dirty ? OtherDirty : OtherFsmUnknown), uq);
    if (ref == RefCompletable) {
        if (!g_occ.stepped) Add(CompletableNoStep, uq);
        else if (!(kClosedStepMask >> g_occ.stepState & 1)) Add(CompletableStepUnclosed, uq);
    }
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
    g_s = nullptr; g_inStage = g_inUnit = g_inFsm = 0;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    g_unitQ = g_strictQ = g_dynamicQ = g_stageQ = g_observerQ = g_snapshotQ = g_rngQ = g_unreadableQ = 0;
    memset(g_reasonQ, 0, sizeof(g_reasonQ)); memset(g_commandQ, 0, sizeof(g_commandQ));
    g_haveTick = g_tickN = g_stageStamp = g_occurrenceStamp = g_stageOccurrences = 0;
    if (g_s) { memset(g_s->foreign, 0, sizeof(g_s->foreign)); memset(g_s->seen, 0, sizeof(g_s->seen)); }
    memset(g_b0, 0, sizeof(g_b0)); memset(g_b0Q, 0, sizeof(g_b0Q)); g_occ = {};
    g_haveManager = g_lastManager = g_stageManager = 0;
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
    if (!g_b0[B0Version]) { g_b0[B0Version] = kB0Version; g_b0[ClosedStepMask] = kClosedStepMask; }
    Globals globals;
    ObserveGlobals(globals); // recorder qualification and manager identity at the stage start (plan 3.2)
    ++g_b0[RecorderStages];
    if (RecorderQualified(globals)) ++g_b0[RecorderStageQualified];
    NoteRecorder(globals); NoteScratch(globals);
    g_stageManager = globals.manager;
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
    B0Reading pre0 = {}, post0 = {};
    Observe(u, true, pre);
    const LONGLONG o0 = Now();
    ObserveB0(u, pre0);
    const LONGLONG c0 = Now();
    const U copied = pre0.probe.readable ? CopyOwn(pre0.probe) : ~0u;
    const LONGLONG c1 = Now();
    g_occ = {};
    const U planner0 = g_planner ? g_planner() : 0;
    const LONGLONG a = Now();
    const U result = native(unit);
    const LONGLONG b = Now();
    const U plannerDelta = g_planner ? g_planner() - planner0 : 0;
    Observe(u, false, post);
    const LONGLONG o1 = Now();
    ObserveB0(u, post0);
    const LONGLONG o2 = Now();

    const LONGLONG q = (b - a) - g_occ.observerQ; // the FSM gate's own reads are instrumentation, not unit cost
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
    AccountB0(observed, reasons, detail, steps, uq, pre0, post0, copied, static_cast<unsigned long long>(c1 - c0));
    const LONGLONG t1 = Now();
    g_b0Q[B0ObserverUs] += static_cast<unsigned long long>((a - o0) + (o2 - o1) + g_occ.observerQ);
    g_observerQ += static_cast<unsigned long long>((t1 - t0) - q);
    g_inUnit = 0;
    return result;
}

U Fsm(void* fsm, Native native) {
    if (!g_s || g_inFsm) return native(fsm);
    if (!g_inUnit) { ++g_b0[FsmOutsideUnit]; return native(fsm); }
    g_inFsm = 1;
    const LONGLONG o0 = Now();
    const U s = static_cast<U>(reinterpret_cast<uintptr_t>(fsm));
    U table = 0, before = 0, table1 = 0, after = 0;
    const bool okBefore = ReadFsm(s, table, before);
    const LONGLONG a = Now();
    const U result = native(fsm);
    const LONGLONG b = Now();
    const bool okAfter = ReadFsm(s, table1, after);
    U* const w = g_b0;
    unsigned long long* const wq = g_b0Q;
    const unsigned long long q = static_cast<unsigned long long>(b - a);
    ++w[FsmCalls]; ++g_occ.calls; wq[FsmUs] += q;
    if (!okBefore || !okAfter) { ++w[FsmUnreadable]; g_occ.unknown = 1; }
    else {
        if (table != kFsmTable + g_delta) { ++w[FsmForeignTable]; g_occ.unknown = 1; }
        const U from = FsmStateIndex(before - g_delta), to = FsmStateIndex(after - g_delta);
        U* const row = w + FsmStateRows;
        if (before != after) { // nonzero query: old leave + new enter ran (10FBBE8/10FBBF3)
            ++w[FsmTransitions]; wq[FsmTransitionUs] += q; g_occ.transition = 1;
            ++row[from * kFsmStride + 3]; ++row[to * kFsmStride + 4];
        } else {                // zero query: the step of the current state ran (10FBBFB)
            ++w[FsmSteps]; wq[FsmStepUs] += q;
            ++row[from * kFsmStride]; wq[FsmStateRows + from * kFsmStride + 1] += q;
            g_occ.stepped = 1; g_occ.stepState = from;
            if (from == SOther) g_occ.unknown = 1;
        }
    }
    const LONGLONG o1 = Now();
    g_occ.observerQ += (o1 - o0) - (b - a);
    g_inFsm = 0;
    return result;
}
void SnapshotB0(U* words) { memcpy(words, g_b0, sizeof(g_b0)); }

void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
} // namespace ntw2_army_unit
