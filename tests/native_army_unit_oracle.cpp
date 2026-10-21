// Army per-unit update Stage A + B0 oracle (src/army/native_army_unit.h): synthetic units and containers, no image.
// Covers the pure classifier, the probe reader, the LCG step counter and the module end to end (stage/unit
// gates around host "native" functions), including that the module never writes the observed memory; and the B0
// qualification observers: FSM gate (step/transition per state), formation/queue/scratch reader, recorder globals and
// tail counting, RNG member bound, own-state copy and the exclusive refusal buckets.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include "army/native_army_unit.h"
#include "kntwr_runtime.h"
static_assert(kntwr_army_unit::kWords == KNTWR_ARMY_UNIT_WORDS, "module row matches the status ABI tail");
static_assert(kntwr_army_unit::kB0Words == KNTWR_ARMY_B0_WORDS, "B0 row matches the status ABI tail");
#include "brain2/native_region_table.h"

using namespace kntwr_army_unit;
static unsigned checks, failures;
static void Check(bool ok, const char* what) { ++checks; if (!ok) { ++failures; fprintf(stderr, "FAIL %s\n", what); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static uint8_t* Page(U bytes = 0x1000) {
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
}
static void Put(uint8_t* p, U offset, U value) { memcpy(p + offset, &value, 4); }
static U Get(const uint8_t* p, U offset) { U v; memcpy(&v, p + offset, 4); return v; }
static U Step(U x) { return x * 0x343FDu + 0x269EC3u; }
static bool Has(U bits, U bit) { return (bits >> bit & 1) != 0; }

static void ClassifierCases() {
    Probe a = {}, b = {};
    a.readable = b.readable = 1;
    U detail = 0;
    U r = Classify(a, b, 0, 0, detail);
    Check(r == 1u << RNonClosed && Has(detail, KIdentity) && Has(detail, KFsm) && !Has(detail, KAlternate),
          "quiet unit: identity and FSM query only, dynamic eligible");
    b.aa0 = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RNotification) && Has(detail, ENotifyA40) && !Has(detail, ENotify608) && Has(detail, KMemberGetters) == false,
          "AA0 0->1 is the A40 notification (no members: no getters)");
    a.aa0 = 1; b.aa0 = 2; a.members = b.members = 3;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RNotification) && Has(detail, ENotify608) && !Has(detail, ENotifyA40) && Has(detail, KMemberGetters),
          "AA0 ->2 is the 608/AB8 pair; AA0!=0 with members reaches the member getters");
    a.aa0 = b.aa0 = 2;
    r = Classify(a, b, 0, 0, detail);
    Check(!Has(r, RNotification), "AA0 unchanged at 2: no notification");
    a.d48 = 3; b.d48 = 4;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RNotification) && Has(detail, ENotifyBD0), "U+D48 rise is the BD0 notification (6011F0 old<new)");
    a.d48 = 4; b.d48 = 3;
    r = Classify(a, b, 0, 0, detail);
    Check(!Has(r, RNotification), "U+D48 fall raises nothing");
    a.d48 = b.d48 = 0;
    a.dc8 = b.dc8 = 0x1000; a.trigger = 0; b.trigger = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RNotification) && Has(detail, ETrigger) && Has(detail, K601500), "601500 R+68 0->1 is the 5CCA60 trigger");
    b.dc8 = 0x2000;
    r = Classify(a, b, 0, 0, detail);
    Check(!Has(detail, ETrigger), "a replaced U+DC8 receiver is not a trigger");
    b.dc8 = 0x1000; b.trigger = ~0u;
    r = Classify(a, b, 0, 0, detail);
    Check(!Has(detail, ETrigger), "an unreadable trigger byte is not a trigger");
    a = Probe{}; b = Probe{}; a.readable = b.readable = 1;
    a.members = 5; b.members = 4;
    r = Classify(a, b, 0, 0, detail);
    Check(r == (1u << RAllocList | 1u << RNonClosed) && Has(detail, EMembers), "member count change is a list mutation");
    b.members = 5; a.c930 = b.c930 = 1; a.c934 = 0; b.c934 = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RAllocList) && !Has(r, RReturn) && Has(detail, ECommand) && Has(detail, KCommand),
          "command ring progression is a list mutation");
    a.ae8 = b.ae8 = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RReturn) && Has(detail, KSelected) && Has(detail, KAlternate) && !Has(detail, KFsm),
          "selected-command predicate followed by a command change is return-dependent");
    a = Probe{}; b = Probe{}; a.readable = b.readable = 1;
    a.fsm = 0x100; b.fsm = 0x200;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RReturn) && Has(detail, EFsm), "an FSM state change is a return-dependent transition");
    b.fsm = a.fsm;
    r = Classify(a, b, 2, 0, detail);
    Check(r == (1u << RPlanner | 1u << RNonClosed) && Has(detail, EPlanner), "planner mutator calls are planner writes");
    r = Classify(a, b, 0, 3, detail);
    Check(r == 1u << RNonClosed && Has(detail, ERng), "RNG draws alone stay dynamic eligible (compromise 5)");
    a.attachedRemove = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RAllocList) && Has(detail, KAttachedRemove), "attached member +6F8 predicts the 52E840 lifecycle transaction");
    a.attachedRemove = 0; a.formationCommand = 1;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(r, RAllocList) && Has(detail, KFormationCommand), "formation command predicate is an allocation");
    a.formationCommand = 0; a.a60 = 2; a.dcc = 1; a.adc = 0x10;
    r = Classify(a, b, 0, 0, detail);
    Check(Has(detail, KDriver) && Has(detail, K600EF0) && Has(detail, KFormation) && Has(r, RAllocList) && Has(detail, EDrivers),
          "driver count change and debug draw/formation kinds");
    Probe bad = {};
    r = Classify(bad, b, 0, 0, detail);
    Check(r == 1u << RNonClosed && detail == 1u << EUnreadable, "an unreadable unit is owner-only (non_closed) with only e_unreadable");
}

static void RngCases() {
    const U s = 0x12345678u;
    Check(RngSteps(s, s, kRngBound) == 0, "no draw");
    Check(RngSteps(s, Step(Step(Step(s))), kRngBound) == 3, "three LCG steps");
    Check(RngSteps(s, s ^ 0x5A5A5A5Au, 64) == ~0u, "unreachable state within the bound");
}

static void ProbeCases() {
    uint8_t* u = Page(); uint8_t* f = Page(); uint8_t* att = Page(); uint8_t* m = Page(); uint8_t* r = Page();
    kntwr_region::Table* t = new kntwr_region::Table(); t->Clear();
    U q = 0;
    Put(u, 0xAA0, 2); u[0xD48] = 7; Put(u, 0xDC8, A(r)); r[0x68] = 1; Put(u, 0xDCC, 0); Put(u, 0xAE8, 0);
    Put(u, 0x930, 1); Put(u, 0x934, 2); Put(u, 0x398 + 2 * 0x90, 0x1324B54u); // preferred command vtable at delta 0
    Put(u, 0xA60, 1); Put(u, 0xAB0, 0); Put(u, 0xACC, 1); Put(u, 0xAD0, A(att) + 0x100); Put(u, 0xADC, A(f));
    Put(u, 0x2CC, 9); Put(u, 0xD6C, 0xABCD);
    Put(u, 0x1F4, A(att)); Put(att, 0x10, 1); Put(att, 0x14, A(att) + 0x80); Put(att, 0x80, A(m)); m[0x6F8] = 1;
    Put(att, 0x100, A(f));
    Put(f, 0, 0x13211D8u); Put(f, 0x18, 3); f[0x515] = 1; f[0x508] = 0; Put(f, 0x460, 0);
    Probe p;
    Check(ReadProbe(A(u), 0, *t, q, p), "readable unit probed");
    Check(p.aa0 == 2 && p.d48 == 7 && p.dc8 == A(r) && p.trigger == 1 && p.c930 == 1 && p.c934 == 2 && p.command == 0x1324B54u &&
          p.a60 == 1 && p.acc == 1 && p.adc == A(f) && p.members == 9 && p.fsm == 0xABCD && p.attached == 1,
          "probe fields read at their pinned offsets");
    Check(p.attachedRemove == 1 && p.formationCommand == 1, "attached +6F8 and infantry formation command predicates");
    f[0x515] = 0;
    Check(ReadProbe(A(u), 0, *t, q, p) && p.formationCommand == 0, "F+515 clear: no formation command path");
    Put(u, 0x934, 0x20000);
    Check(ReadProbe(A(u), 0, *t, q, p) && p.command == ~0u, "out-of-range command index is unreadable, not dereferenced");
    Check(!ReadProbe(0x10, 0, *t, q, p) && !p.readable, "null-page unit refused without a fault");
    delete t;
}

// End to end: one container, three main units (unit 1 also on the alternate list), host natives.
struct World {
    uint8_t *c, *model, *candidates, *units[3];
    U mainList[3], altList[1];
    unsigned stageCalls, unitCalls[3];
};
static World w;
static U plannerCounter;
static U PlannerCalls() { return plannerCounter; }
static U __fastcall FakeUnit(void* unit) {
    for (U i = 0; i < 3; ++i) if (unit == w.units[i]) {
        ++w.unitCalls[i];
        if (i == 1) { // notification once, two RNG draws every occurrence
            Put(w.units[1], 0xAA0, 1);
            U s = Get(w.model, 0x50); s = Step(Step(s)); Put(w.model, 0x50, s);
        }
        if (i == 2) { ++plannerCounter; Put(w.units[2], 0x2CC, Get(w.units[2], 0x2CC) - 1); }
    }
    return 0x5A5Au;
}
static U __fastcall FakeStage(void* container) {
    ++w.stageCalls;
    for (U i = 0; i < 3; ++i) Check(Unit(w.units[i], 0, &FakeUnit) == 0x5A5Au, "unit gate returns the native EAX");
    Unit(w.units[1], 1, &FakeUnit);
    return A(container) ^ 1;
}
static void ModuleCases() {
    w = World{};
    w.c = Page(); w.model = Page(); w.candidates = Page();
    for (U i = 0; i < 3; ++i) {
        w.units[i] = Page();
        Put(w.units[i], 0x1EC, A(w.c)); w.units[i][0x1AB] = 1; Put(w.units[i], 0x2CC, 10);
        Put(w.units[i], 0xADC, 0); w.mainList[i] = A(w.units[i]);
    }
    w.altList[0] = A(w.units[1]);
    Put(w.c, 0xF0, 3); Put(w.c, 0xF4, A(w.mainList)); Put(w.c, 0x1A4, 1); Put(w.c, 0x1A8, A(w.altList));
    Put(w.c, 0xD8, A(w.candidates)); Put(w.candidates, 0x44, 3); Put(w.candidates, 0x48, A(w.mainList));
    Put(w.model, 0x50, 0xCAFEF00Du); Put(w.model, 0x58, 100);
    std::vector<uint8_t> before0(w.units[0], w.units[0] + 0x1000), beforeC(w.c, w.c + 0x1000);
    Binding binding = {0x400000u, 4, &PlannerCalls, 0};
    Check(Start(binding), "module starts");
    Check(Unit(w.units[0], 0, &FakeUnit) == 0x5A5Au && w.unitCalls[0] == 1, "outside a stage the unit gate only runs the native");
    U words[kWords];
    Snapshot(words);
    Check(words[Occurrences] == 0, "an occurrence outside a stage is not counted");
    w.unitCalls[0] = 0;
    Check(Stage(w.c, A(w.model), &FakeStage) == (A(w.c) ^ 1) && w.stageCalls == 1, "stage gate runs the native once, returns its EAX");
    Check(w.unitCalls[0] == 1 && w.unitCalls[1] == 2 && w.unitCalls[2] == 1, "every native occurrence ran exactly once");
    Check(before0 == std::vector<uint8_t>(w.units[0], w.units[0] + 0x1000), "untouched unit memory is byte-identical (no writes)");
    Check(beforeC == std::vector<uint8_t>(w.c, w.c + 0x1000), "container memory is byte-identical (no writes)");
    Snapshot(words);
    Check(words[Version] == kVersion && words[Enabled] == 1 && words[Stages] == 1 && words[Ticks] == 1 && words[Workers] == 4,
          "header");
    Check(words[Occurrences] == 4 && words[MainOccurrences] == 3 && words[AlternateOccurrences] == 1 &&
          words[DuplicateOccurrences] == 1 && words[UnitsLastStage] == 4, "occurrence counts and the repeated unit");
    Check(words[StrictEligible] == 0 && words[DynamicEligible] == 2, "strict none (identity always reached); dynamic unit0 + repeat");
    const U* reason = words + ReasonCount; const U* sole = words + SoleReason; const U* bit = words + DetailCount;
    Check(reason[RNotification] == 1 && reason[RPlanner] == 1 && reason[RAllocList] == 1 &&
          reason[RReturn] == 0 && reason[RNonClosed] == 4 && sole[RNonClosed] == 2,
          "reason counts and sole reasons");
    Check(words[RngDrawing] == 2 && words[RngDraws] == 4 && words[RngUnresolved] == 0 && words[PlannerMeasured] == 1,
          "RNG draws per occurrence and planner measurement");
    Check(bit[ENotifyA40] == 1 && bit[EPlanner] == 1 && bit[EMembers] == 1 && bit[KIdentity] == 4, "detail bits");
    Check(words[ForeignNeighbourSum] == 8 && words[ForeignAggregationSum] == 8 && words[ForeignDistinctSum] == 8 &&
          words[ForeignDistinctMax] == 2 && words[PinnedCellsSum] == 4 * 2 * 22 && words[AggregationSkipped] == 0,
          "foreign witness: two other units per occurrence in both lists");
    Check(words[SnapshotUnits] == 4 && words[CommandDistinct] == 1 && words[CommandRows] == 0 && words[CommandRows + 1] == 4 &&
          words[CommandRows + 2] == 2 && words[CommandRows + 4] == 2, "frozen copy units and the no-command census row");
    U histogram = 0;
    for (U i = 0; i < kHistogram; ++i) histogram += words[CostHistogram + i];
    Check(histogram == 4, "cost histogram covers every occurrence");
    // Gated predicate: 1AB..1AE clear means 53A9E0 returns before enumerating.
    for (U i = 0; i < 3; ++i) w.units[i][0x1AB] = 0;
    Put(w.model, 0x58, 101);
    Stage(w.c, A(w.model), &FakeStage);
    Snapshot(words);
    Check(words[Ticks] == 2 && words[QuantileTicks] == 1 && words[TickP90SumDus] >= words[TickP50SumDus],
          "the first tick's quantiles are finalized at the next tick");
    Check(words[AggregationSkipped] == 4 && words[ForeignAggregationSum] == 8, "replayed 53A9E0 gate skips the aggregation list");
    Stop();
    Check(!Started(), "stopped");
    Snapshot(words);
    Check(words[Occurrences] == 8, "counters retained after stop");
    Check(Stage(w.c, A(w.model), &FakeStage) == (A(w.c) ^ 1), "stopped module passes the stage through");
    Snapshot(words);
    Check(words[Occurrences] == 8, "nothing counted while stopped");
    Reset();
    Snapshot(words);
    Check(words[Occurrences] == 0 && words[Version] == 0, "reset zeroes the row");
}

// The native call frees/decommits probed memory: unit A's attached container, then unit B itself. The post
// observation must re-prove readability (no fault), and B must land in the unreadable bucket, never eligible.
static uint8_t *g_uA, *g_uB, *g_attA;
static U __fastcall DecommitUnit(void* unit) {
    if (unit == g_uA) VirtualFree(g_attA, 0x1000, MEM_DECOMMIT);
    if (unit == g_uB) VirtualFree(g_uB, 0x1000, MEM_DECOMMIT);
    return 7;
}
static U __fastcall DecommitStage(void*) {
    Check(Unit(g_uA, 0, &DecommitUnit) == 7 && Unit(g_uB, 0, &DecommitUnit) == 7, "natives run while memory is decommitted");
    return 0;
}
static void DecommitCases() {
    uint8_t* c = Page(); uint8_t* m = Page(); uint8_t* member = Page();
    g_uA = Page(); g_uB = Page(); g_attA = Page();
    U list[2] = {A(g_uA), A(g_uB)};
    Put(c, 0xF0, 2); Put(c, 0xF4, A(list));
    Put(m, 0x50, 0x1111u); Put(m, 0x58, 7);
    for (uint8_t* u : {g_uA, g_uB}) { Put(u, 0x1EC, A(c)); Put(u, 0x2CC, 4); }
    Put(g_uA, 0x1F4, A(g_attA)); Put(g_attA, 0x10, 1); Put(g_attA, 0x14, A(g_attA) + 0x80); Put(g_attA, 0x80, A(member));
    Put(g_uB, 0x1F4, A(g_attA)); // B's attached container is gone too by the time B runs
    Binding binding = {0x400000u, 8, nullptr, 0};
    Check(Start(binding), "module restarts");
    Stage(c, A(m), &DecommitStage);
    U words[kWords];
    Snapshot(words);
    const U* reason = words + ReasonCount; const U* bit = words + DetailCount;
    Check(words[Occurrences] == 2 && words[Unreadable] == 1 && bit[EUnreadable] == 1, "decommitted unit is one unreadable occurrence");
    Check(words[StrictEligible] == 0 && words[DynamicEligible] == 0, "unreadable occurrence is never eligible");
    Check(reason[RAllocList] == 1 && reason[RNonClosed] == 1 && bit[EAttached] == 1,
          "unit A: decommitted attached container re-proved unreadable, read as a list change (no fault)");
    Check(words[CommandRows + 1] == 2 && words[CommandRows + 2] == 2, "the unreadable occurrence counts as owner-only in the census");
    Check(words[PlannerMeasured] == 0 && words[RngDrawing] == 0, "no planner binding, no RNG draw");
    Stop(); Reset();
}

// ---- B0. Synthetic image globals: one allocation spanning preferred 1459000..15FA000, mapped by the delta.
struct Image { uint8_t* base; U delta; };
static Image MakeImage() { Image i; i.base = Page(0x1A2000); i.delta = A(i.base) - 0x1459000u; return i; }
static uint8_t* At(const Image& i, U va) { return i.base + (va - 0x1459000u); }
static const char* const kB0Labels[] = { KNTWR_ARMY_B0_LABELS };
static_assert(sizeof(kB0Labels) / sizeof(kB0Labels[0]) == kB0Words, "one B0 label per word");

static void B0PureCases() {
    Check(FsmStateIndex(0x1450908) == SA && FsmStateIndex(0x1450918) == SE && FsmStateIndex(0x1466CC4) == SSentinel &&
          FsmStateIndex(0x145091C) == SOther && FsmStateIndex(0x1450909) == SOther && FsmStateIndex(0) == SOther,
          "unit FSM state objects A..E (1450908 + 4i), sentinel, other");
    Check(SecondaryStateIndex(0x1450BDC) == 0 && SecondaryStateIndex(0x1450BE8) == 3 && SecondaryStateIndex(0x1466CC4) == 4 &&
          SecondaryStateIndex(0x1450BEC) == 5, "formation-command secondary states");
    Check(Refuse(false, 1u << RAllocList, true, true, true) == RefUnreadable, "unreadable first");
    Check(Refuse(true, 1u << RAllocList | 1u << RReturn, true, true, true) == RefAlloc, "alloc_list before transition");
    Check(Refuse(true, 1u << RReturn, true, true, false) == RefTransition, "transition before recorder");
    Check(Refuse(true, 1u << RNonClosed, false, true, true) == RefRecorder, "recorder before other");
    Check(Refuse(true, 1u << RNotification | 1u << RNonClosed, false, false, false) == RefOther &&
          Refuse(true, 1u << RNonClosed, false, false, true) == RefOther, "Stage A notification or dirty/unknown: other");
    Check(Refuse(true, 1u << RNonClosed, false, false, false) == RefCompletable, "non_closed alone is completable");
    Check(AllocSplit(1u << EMembers, true, true) == AllocGrowth && AllocSplit(1u << EMembers, false, true) == AllocReserve &&
          AllocSplit(1u << KAttachedRemove, false, false) == AllocListChange &&
          AllocSplit(1u << KFormationCommand, false, false) == AllocPredicateOnly, "alloc_list split order");
    Globals a = {}, b = {};
    a.recorderOk = b.recorderOk = 1; a.enable = b.enable = 1; a.manager = b.manager = 0x1000; a.managerOk = b.managerOk = 1;
    a.m4 = 10; b.m4 = 13; a.m20 = 1; b.m20 = 2;
    Check(RecorderQualified(a) && RecorderAppends(a, b) == 4, "qualified recorder; appends = dM+4 + dM+20");
    b.manager = 0x2000;
    Check(RecorderAppends(a, b) == ~0u, "manager switch: tail count not comparable");
    a.comparator = 1; Check(!RecorderQualified(a), "comparator set: not qualified"); a.comparator = 0;
    a.inhibit = 1; Check(!RecorderQualified(a), "inhibit set: not qualified"); a.inhibit = 0;
    a.provider = 1; Check(!RecorderQualified(a), "provider set: not qualified"); a.provider = 0;
    a.enable = 0; Check(!RecorderQualified(a), "disabled: not qualified");
}

static void B0GlobalsCases() {
    const Image img = MakeImage();
    uint8_t* m = Page();
    kntwr_region::Table* t = new kntwr_region::Table(); t->Clear();
    U q = 0;
    Put(At(img, 0x14A3EC4), 4, 16); Put(At(img, 0x14A3EC4), 8, 3); Put(At(img, 0x14A3EC4), 0xC, 0xAAAA0000u);
    Put(At(img, 0x14A3ED8), 4, 32); Put(At(img, 0x14A3ED8), 8, 0); Put(At(img, 0x14A3ED8), 0xC, 0xBBBB0000u);
    *At(img, 0x1459B00) = 1; *At(img, 0x1459DCC) = 1; Put(At(img, 0x15F8BC0), 0, A(m)); Put(At(img, 0x15F9054), 0, 0);
    Put(m, 4, 77); Put(m, 0x18, 0); m[0x1C] = 0; Put(m, 0x20, 5);
    Globals g;
    ReadGlobals(img.delta, *t, q, g);
    Check(g.scratchOk && g.distCap == 16 && g.distCount == 3 && g.distBacking == 0xAAAA0000u && g.recCap == 32 &&
          g.recCount == 0 && g.recBacking == 0xBBBB0000u, "scratch headers 14A3EC4/14A3ED8: capacity +4, count +8, backing +C");
    Check(g.recorderOk && g.enable == 1 && g.dcc == 1 && g.manager == A(m) && g.managerOk && g.m4 == 77 && g.m20 == 5 &&
          RecorderQualified(g), "recorder enable/manager/provider and M+4/+18/+1C/+20");
    m[0x1C] = 1;
    ReadGlobals(img.delta, *t, q, g);
    Check(g.inhibit == 1 && !RecorderQualified(g), "inhibit byte M+1C");
    Put(At(img, 0x15F8BC0), 0, 0);
    ReadGlobals(img.delta, *t, q, g);
    Check(g.recorderOk && !g.manager && !g.managerOk && !RecorderQualified(g), "null manager is read, not dereferenced");
    delete t;
    VirtualFree(img.base, 0, MEM_RELEASE);
    t = new kntwr_region::Table(); t->Clear(); // fresh proofs: the released image range must be re-proved unreadable
    ReadGlobals(img.delta, *t, q, g);
    Check(!g.scratchOk && !g.recorderOk, "released image globals refused without a fault");
    delete t;
}

// Infantry formation page (vtable 13211D8 at the given delta): N = [[F+630]+C], members F+18, queue Q=F+20.
static uint8_t* Formation(U delta, U n, U members) {
    uint8_t* f = Page(0x3000); uint8_t* agg = Page();
    Put(f, 0, 0x13211D8u + delta); Put(f, 0x18, members); Put(f, 0x630, A(agg)); Put(agg, 0xC, n);
    return f;
}
static void QueueCommand(uint8_t* f, U index, U delta, U cls, U state) {
    uint8_t* cmd = Page();
    Put(cmd, 0, cls + delta); Put(cmd, 0x1C, state ? state + delta : 0);
    Put(f, 0x420 + 8 * index, A(cmd)); Put(f, 0x424 + 8 * index, 0x34); Put(f, 0x460, index + 1);
}

static void B0ProbeCases() {
    uint8_t* u = Page(); uint8_t* att = Page(); uint8_t* list = Page(); uint8_t* other = Page();
    uint8_t* f = Formation(0, 5, 12);
    QueueCommand(f, 0, 0, 0x1324B54u, 0x1450BE4u);
    QueueCommand(f, 1, 0, 0x1323B64u, 0);
    f[0x2790] = 1;
    Put(other, 0, 0x1321000u);
    Put(u, 0x1F4, A(att)); Put(att, 0x10, 3); Put(att, 0x14, A(att) + 0x80);
    Put(u, 0xACC, 2); Put(u, 0xAD0, A(list)); Put(list, 0, A(f)); Put(list, 4, A(other));
    kntwr_region::Table* t = new kntwr_region::Table(); t->Clear();
    U q = 0;
    B0Probe p;
    Check(ReadB0Probe(A(u), 0, *t, q, p), "readable unit probed for B0");
    Check(p.infantry == 1 && p.other == 1 && p.unreadable == 0 && p.nMax == 5 && p.members == 12 && p.dirty == 1,
          "formation census: infantry/other, aggregate N, members, dirty F+2790");
    Check(p.queue == 2 && p.commands == 2 && p.commandClass[0] == 0x1324B54u && p.commandState[0] == 0x1450BE4u &&
          p.commandClass[1] == 0x1323B64u && p.commandState[1] == ~0u, "queue rows Q+400, classes and 1324B54 secondary state");
    Check(p.bound == 12 * (1 + 1 + 1), "RNG member bound: members x (1 + queued 1323B64 + dirty 2790)");
    Check(p.spans == 4 && p.ownBytes == kUnitObjectBytes + 12 + kInfantryFormationBytes + kOtherFormationBytes,
          "own spans: unit E38, attached data, infantry 0x2794, other 0x6F0");
    Put(f, 0x460, 9);
    Check(ReadB0Probe(A(u), 0, *t, q, p) && p.queueBad == 1 && p.queue == 0, "queue count above Q's 8 rows is unreadable");
    Put(u, 0xACC, 0x7FFFFFFF);
    Check(ReadB0Probe(A(u), 0, *t, q, p) && p.unreadable >= 1, "garbage formation count: one unreadable mark, bounded walk");
    Check(!ReadB0Probe(0x10, 0, *t, q, p) && !p.readable, "null-page unit refused");
    delete t;
}

// End to end with the FSM gate: six units in one stage, host natives standing in for the ARMY_UNIT clone.
struct B0World {
    Image img;
    uint8_t *c, *model, *manager, *units[6], *forms[6];
    U list[6];
    unsigned fsmCalls;
};
static B0World b;
static U Pref(U va) { return va + b.img.delta; }
static U __fastcall FsmStep(void*) { ++b.fsmCalls; return 0; }
static U __fastcall FsmToB(void* s) { ++b.fsmCalls; Put(static_cast<uint8_t*>(s), 4, Pref(0x145090C)); return 1; }
static U __fastcall B0Unit(void* unit) {
    uint8_t* const u = static_cast<uint8_t*>(unit);
    const U i = static_cast<U>(std::find(b.units, b.units + 6, u) - b.units);
    uint8_t* const s = u + 0xD68;
    Check(Fsm(s, i == 1 ? &FsmToB : &FsmStep) == (i == 1 ? 1u : 0u), "FSM gate returns the native AL/EAX");
    U r = Get(b.model, 0x50);
    if (i == 0) for (U k = 0; k < 5; ++k) r = Step(r);  // no formation: bound 0, five draws
    if (i == 2) for (U k = 0; k < 3; ++k) r = Step(r);  // bound 24, three draws
    Put(b.model, 0x50, r);
    if (i == 2 || i == 3) Put(b.manager, 4, Get(b.manager, 4) + 1);          // one recorder append each
    if (i == 3) { Put(b.manager, 0x18, 0xC0C0u); Put(At(b.img, 0x14A3ED8), 4, 64); } // comparator set; record growth
    if (i == 4) QueueCommand(b.forms[4], 0, b.img.delta, 0x1324B54u, 0x1450BDCu);       // 522D70 reserve reached
    return 0x77;
}
static U __fastcall B0Stage(void*) {
    static const U order[6] = {0, 1, 2, 4, 5, 3};
    for (U k = 0; k < 6; ++k) Check(Unit(b.units[order[k]], 0, &B0Unit) == 0x77, "unit gate returns the clone's EAX");
    return 0;
}
static void B0ModuleCases() {
    b = B0World{};
    b.img = MakeImage();
    b.c = Page(); b.model = Page(); b.manager = Page();
    *At(b.img, 0x1459B00) = 1; *At(b.img, 0x1459DCC) = 1; Put(At(b.img, 0x15F8BC0), 0, A(b.manager));
    Put(At(b.img, 0x14A3EC4), 4, 16); Put(At(b.img, 0x14A3ED8), 4, 16);
    static const U states[6] = {0x1450908, 0x1450908, 0x1450910, 0x1466CC4, 0x1450914, 0x1450918}; // A A C sentinel D E
    for (U i = 0; i < 6; ++i) {
        uint8_t* const u = b.units[i] = Page();
        Put(u, 0x1EC, A(b.c)); Put(u, 0x2CC, 10);
        Put(u, 0xD68, Pref(0x1320F28)); Put(u, 0xD6C, Pref(states[i]));
        b.list[i] = A(u);
        if (i < 2) continue;
        uint8_t* const f = b.forms[i] = Formation(b.img.delta, 5, 12);
        uint8_t* const fl = Page(); Put(fl, 0, A(f));
        Put(u, 0xACC, 1); Put(u, 0xAD0, A(fl));
        if (i == 2 || i == 3) { QueueCommand(f, 0, b.img.delta, 0x1324B54u, 0x1450BE4u); QueueCommand(f, 1, b.img.delta, 0x1323B64u, 0); }
        if (i == 4) { f[0x515] = 1; f[0x508] = 0; } // formation-command predicate with an empty queue (F+460 == 0)
        if (i == 5) f[0x2790] = 1;                    // dirty: 576EA0 command rebuild
    }
    Put(b.c, 0xF0, 6); Put(b.c, 0xF4, A(b.list));
    Put(b.model, 0x50, 0x1234u); Put(b.model, 0x58, 5);
    std::vector<uint8_t> beforeU0(b.units[0], b.units[0] + 0x1000), beforeF2(b.forms[2], b.forms[2] + 0x3000);
    Binding binding = {0x400000u + b.img.delta, 8, nullptr, 0};
    Check(Start(binding), "module starts for B0");
    Check(Fsm(b.units[0] + 0xD68, &FsmStep) == 0 && b.fsmCalls == 1, "FSM gate outside an occurrence only forwards");
    Stage(b.c, A(b.model), &B0Stage);
    Check(b.fsmCalls == 7, "every FSM native ran exactly once");
    Check(beforeU0 == std::vector<uint8_t>(b.units[0], b.units[0] + 0x1000) &&
          beforeF2 == std::vector<uint8_t>(b.forms[2], b.forms[2] + 0x3000), "observed unit/formation bytes unchanged");
    U x[kB0Words];
    SnapshotB0(x);
    const U* row = x + FsmStateRows;
    Check(x[B0Version] == kB0Version && x[B0Occurrences] == 6 && x[FsmOutsideUnit] == 1 && x[ClosedStepMask] == kClosedStepMask,
          "B0 header");
    Check(x[FsmCalls] == 6 && x[FsmOccurrences] == 6 && x[FsmMulti] == 0 && x[FsmTransitions] == 1 && x[FsmSteps] == 5 &&
          x[FsmUnreadable] == 0 && x[FsmForeignTable] == 0, "FSM calls: one transition, five steps");
    Check(row[SA * kFsmStride] == 1 && row[SA * kFsmStride + 3] == 1 && row[SB * kFsmStride + 4] == 1 &&
          row[SC * kFsmStride] == 1 && row[SD * kFsmStride] == 1 && row[SE * kFsmStride] == 1 &&
          row[SSentinel * kFsmStride] == 1 && row[SOther * kFsmStride] == 0, "per-state steps and A->B transition");
    Check(x[TransitionOccurrences] == 1, "one occurrence with an FSM transition");
    Check(x[FormationInfantry] == 4 && x[ScratchNMax] == 5 && x[ScratchNSum] == 20 && x[MembersSum] == 48 &&
          x[ScratchBytesMax] == 5 * 32, "formation census and scratch participant bound");
    Check(x[QueueCommandsSum] == 4 && x[QueueReserved] == 1 && x[QueueTruncated] == 0 && x[SecondaryStateCounts + 2] == 2 &&
          x[QueueClassDistinct] == 2 && x[QueueClassRows] == 0x1324B54u && x[QueueClassRows + 1] == 2 &&
          x[QueueClassRows + kQueueStride] == 0x1323B64u && x[QueueClassRows + kQueueStride + 1] == 2,
          "queue census (pre state) and the 522D70 reserve");
    Check(x[RecordGrowth] == 1 && x[DistanceGrowth] == 0 && x[RecordCapMax] == 64 && x[ScratchCountNonzero] == 0,
          "record scratch growth reached once");
    Check(x[RecorderStages] == 1 && x[RecorderStageQualified] == 1 && x[RecorderObservations] == 13 &&
          x[RecorderTails] == 2 && x[RecorderTailOccurrences] == 2 && x[RecorderTailMax] == 1 && x[RecorderUnqualified] == 1 &&
          x[RecorderComparatorSet] == 1 && x[RecorderManagerChanges] == 0 && x[RecorderManagerLast] == A(b.manager),
          "recorder: two tail appends, one after the comparator was set");
    Check(x[RngWithinBound] == 1 && x[RngOverBound] == 1 && x[RngDrawMax] == 5 && x[RngMemberBoundSum] == 24 + 24 + 12 + 24,
          "RNG draws against the member-loop bound (units 2, 3, 4, 5)");
    Check(x[OwnUnreadable] == 0 && x[OwnBytesMax] == kUnitObjectBytes + kInfantryFormationBytes, "own-state bytes copied");
    const U* ref = x + RefusalRows;
    Check(ref[2 * RefUnreadable] == 0 && ref[2 * RefAlloc] == 1 && ref[2 * RefTransition] == 1 && ref[2 * RefRecorder] == 1 &&
          ref[2 * RefOther] == 1 && ref[2 * RefCompletable] == 2, "exclusive refusal buckets");
    Check(x[AllocRows + 2 * AllocReserve] == 1 && x[OtherRows + 2 * OtherDirty] == 1 && x[DirtyOccurrences] == 1 &&
          x[CompletableStepUnclosed] == 2 && x[CompletableNoStep] == 0, "alloc split, dirty other, unclosed steps");
    U stageA[kWords];
    Snapshot(stageA);
    Check(stageA[Occurrences] == 6, "Stage A row counts the same occurrences");
    Stop(); Reset();
    SnapshotB0(x);
    Check(x[B0Occurrences] == 0 && x[B0Version] == 0, "reset zeroes the B0 row");
    VirtualFree(b.img.base, 0, MEM_RELEASE);
}

int main() {
    ClassifierCases();
    RngCases();
    ProbeCases();
    ModuleCases();
    DecommitCases();
    B0PureCases();
    B0GlobalsCases();
    B0ProbeCases();
    B0ModuleCases();
    printf("native_army_unit_oracle: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
