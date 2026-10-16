// Army per-unit update Stage A oracle (src/army/native_army_unit.h): synthetic units and containers, no image.
// Covers the pure classifier, the probe reader, the LCG step counter and the module end to end (stage/unit
// gates around host "native" functions), including that the module never writes the observed memory.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "army/native_army_unit.h"
#include "ntw2_runtime.h"
static_assert(ntw2_army_unit::kWords == NTW2_ARMY_UNIT_WORDS, "module row matches the status ABI tail");
#include "brain2/native_region_table.h"

using namespace ntw2_army_unit;
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
    ntw2_region::Table* t = new ntw2_region::Table(); t->Clear();
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

int main() {
    ClassifierCases();
    RngCases();
    ProbeCases();
    ModuleCases();
    DecommitCases();
    printf("native_army_unit_oracle: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
