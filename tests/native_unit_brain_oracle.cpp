// Per-unit brain Stage A (native_unit_brain.h) on synthetic soldiers and units: no game image is needed.
// Covers the decision extraction (unit-level inputs, signature, soldier fields, exception bits), readability proofs
// without first-chance faults, the ntw2_brain2::RunWorklist observer seam (after each native step, duplicates, ==1
// filter, no native write), held/tick/exception accounting over consecutive stages, signature changes, strict
// majority, the class vtable census and parallel-decide equivalence with inline decide.
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <thread>
#include <vector>
#include "native_unit_brain.h"
#include "native_region_table.h"
#include "native_brain2.h"
using namespace ntw2_unit_brain;

namespace {
U failures, checks;
void Check(bool ok, const char* what) {
    ++checks;
    if (!ok) { ++failures; printf("FAIL %s\n", what); }
}
U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
LONG g_avs;
LONG CALLBACK CountAv(EXCEPTION_POINTERS* e) {
    if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) InterlockedIncrement(&g_avs);
    return EXCEPTION_CONTINUE_SEARCH;
}

// Bump arena of committed memory; Reset restores a saved prefix so stages can be replayed from identical state.
struct Arena {
    uint8_t* base = nullptr; U size = 0, used = 0;
    Arena(U bytes) : size(bytes) {
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    U Alloc(U bytes, U align = 16) {
        used = (used + align - 1) & ~(align - 1);
        const U at = Addr(base) + used; used += bytes; return at;
    }
};
void W(U a, U v) { *reinterpret_cast<U*>(static_cast<uintptr_t>(a)) = v; }
void W8(U a, U v) { *reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(a)) = static_cast<uint8_t>(v); }
void WF(U a, float v) { memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(a)), &v, 4); }
U R(U a) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(a)); }

// The "native step": copies a per-soldier script (soldier +6F0..+6FF, outside every field the module reads) into
// the decided fields, so a correct observer sees the post-step values.
constexpr U kScriptActivity = 0x6F0, kScriptOrder = 0x6F4, kStepCount = 0x6F8, kScriptDeactivate = 0x6FC;
void __fastcall Step(void* self, void*) {
    const U a = Addr(self);
    W(a + 0x1B8, R(a + kScriptActivity)); W(a + 0x1D8, R(a + kScriptOrder));
    W(a + kStepCount, R(a + kStepCount) + 1);
    if (R(a + kScriptDeactivate)) W8(a + 0x30, 0);
}
U g_delta; // image_base - 0x400000 chosen so that Step sits at the preferred 0x66CE00 core entry
U Pref(U preferred) { return preferred + g_delta; }

struct World {
    Arena arena{8u << 20};
    U coreTable, coreTable2, noAccess;
    explicit World() {
        coreTable = arena.Alloc(16); W(coreTable + 0xC, Addr(reinterpret_cast<void*>(&Step)));
        coreTable2 = arena.Alloc(16); W(coreTable2 + 0xC, Addr(reinterpret_cast<void*>(&Step)));
        noAccess = Addr(VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS));
    }
    U Table(U entryPreferred) { const U t = arena.Alloc(16); W(t + 0xC, Pref(entryPreferred)); return t; }
    U Unit() {
        const U u = arena.Alloc(0xE00);
        const U desc = arena.Alloc(0x40), context = arena.Alloc(0x10), model = arena.Alloc(0xC0);
        const U manager = arena.Alloc(0x2710), ability = arena.Alloc(16 * 0x2C), group = arena.Alloc(0x470);
        W(u + 0x930, 1); W(u + 0x934, 2); W(u + 0x398 + 2 * 0x90, 0x01321CA4);
        W(u + 0xAA0, 3); W(u + 0x2C, desc); W(desc + 0x1C, 7);
        W8(u + 0xDA4, 1); W8(u + 0xD9E, 0); W8(u + 0xD9D, 1);
        W(u + 0xDA8, 5); W(u + 0xC2C, 6); W(u + 0x2CC, 40);
        W(u + 0xDB8, 3); W(u + 0xDBC, ability);
        for (U i = 0; i < 3 * 0x2C; ++i) W8(ability + i, i * 7 + 1);
        W(u + 0xC00, context); W(context + 8, model); W(model + 0xB0, manager);
        W(manager + 0x14, 3); W8(manager + 0x2704, 1);
        W(u + 0xADC, group); W(group + 0x460, 9);
        return u;
    }
    U Soldier(U table, U unit, U activity, U order) {
        const U a = arena.Alloc(0x700);
        W(a, table); W8(a + 0x30, 1); W(a + 0x1F0, unit);
        W(a + kScriptActivity, activity); W(a + kScriptOrder, order);
        W(a + 0x1B8, 0xEEEE); W(a + 0x1D8, 0xEEEE); // stale pre-step values: an early observer would see these
        return a;
    }
};

void __stdcall ThreadDispatch(U pool, U fn, U chunks, void* context) {
    std::atomic<U> next{0};
    std::vector<std::thread> threads;
    for (U t = 0; t < pool; ++t)
        threads.emplace_back([&] {
            for (U c; (c = next.fetch_add(1)) < chunks;)
                reinterpret_cast<void (__fastcall*)(void*, U)>(static_cast<uintptr_t>(fn))(context, c);
        });
    for (auto& t : threads) t.join();
}
const ntw2_brain2::StageObserver kObserver = {&BeginStage, &Observe, &EndStage};
U FieldWord(const U* w, U field, U column) { return w[FieldWords + field * kFieldStride + column]; }

void InputCases(World& w) {
    ntw2_region::Table* table = new ntw2_region::Table(); table->Clear();
    U q = 0, in[kInputs], again[kInputs];
    const U u = w.Unit();
    Check(ReadUnitInputs(u, *table, q, in), "unit inputs readable");
    Check(in[0] == 1 && in[1] == 2 && in[2] == 0x01321CA4 && in[3] == 3 && in[5] == 7 && in[6] == 0x010001 &&
          in[7] == 5 && in[8] == 6 && in[9] == 3 && in[10] != 0 && in[10] != ~0u && in[11] == 3 && in[12] == 1 &&
          in[14] == 9, "unit input record");
    const U base = Signature(in);
    struct Mut { U offset; bool byte; } muts[] = {
        {0x930, false}, {0x934, false}, {0x398 + 2 * 0x90, false}, {0xAA0, false}, {0xDA4, true}, {0xD9E, true},
        {0xD9D, true}, {0xDA8, false}, {0xC2C, false}, {0xDB8, false}};
    for (const Mut& m : muts) {
        const U old = m.byte ? *reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(u + m.offset)) : R(u + m.offset);
        if (m.byte) W8(u + m.offset, old ^ 1); else W(u + m.offset, old + 1);
        Check(ReadUnitInputs(u, *table, q, again) && Signature(again) != base, "each unit-level input changes the signature");
        if (m.byte) W8(u + m.offset, old); else W(u + m.offset, old);
    }
    const U ability = R(u + 0xDBC), desc = R(u + 0x2C), manager = R(R(R(u + 0xC00) + 8) + 0xB0), group = R(u + 0xADC);
    W8(ability + 5, 0x77);
    Check(ReadUnitInputs(u, *table, q, again) && Signature(again) != base, "ability bytes enter the signature");
    W8(ability + 5, 5 * 7 + 1);
    W(desc + 0x1C, 8); Check(ReadUnitInputs(u, *table, q, again) && Signature(again) != base, "descriptor type enters"); W(desc + 0x1C, 7);
    W(manager + 0x14, 4); Check(ReadUnitInputs(u, *table, q, again) && Signature(again) != base, "battle phase enters"); W(manager + 0x14, 3);
    W(group + 0x460, 1); Check(ReadUnitInputs(u, *table, q, again) && Signature(again) != base, "group word enters"); W(group + 0x460, 9);
    W(u + 0x930, 0);
    Check(ReadUnitInputs(u, *table, q, again) && again[2] == 0, "no command: Q vtable not read");
    W(u + 0x930, 1);
    W(u + 0x2CC, 39);
    Check(ReadUnitInputs(u, *table, q, again) && Signature(again) == base, "member count (casualties) is excluded");
    // Unreadable unit and dependents: refused or ~0, never dereferenced.
    const LONG avs = g_avs;
    Check(!ReadUnitInputs(w.noAccess, *table, q, again), "unreadable unit refused");
    W(u + 0x2C, w.noAccess); W(u + 0xADC, w.noAccess);
    Check(ReadUnitInputs(u, *table, q, again) && again[5] == ~0u && again[14] == ~0u, "unreadable dependents read as ~0");
    W(u + 0x2C, desc); W(u + 0xADC, group);
    W(u + 0xDBC, w.noAccess);
    Check(ReadUnitInputs(u, *table, q, again) && again[10] == ~0u, "unreadable ability table reads as ~0");
    W(u + 0xDBC, ability);
    Check(g_avs == avs, "no first-chance access violation in unit reads");
    delete table;
}

void SoldierCases(World& w) {
    ntw2_region::Table* table = new ntw2_region::Table(); table->Clear();
    U q = 0;
    Soldier s;
    const U unit = w.Unit(), other = w.Unit();
    const U a = w.Soldier(w.coreTable, unit, 9, 4);
    W(a + 0x1B8, 9); W(a + 0x1D8, 4);
    W8(a + 0x2C4, 1); W(a + 0x22C, Pref(0x1334180));
    W(a + 0xF8, Pref(0x1454168 + 4 * 12)); W(a + 0x220, 1);
    const U target = w.Soldier(w.coreTable, other, 0, 0);
    W(a + 0x1EC, target); W(a + 0x224, 7); W(a + 0x1BC, 0x360);
    W8(a + 0x5BC, 1); W8(a + 0x5AB, 2); W8(a + 0xF1, 3); W8(a + 0x619, 4);
    Check(ExtractSoldier(a, *table, q, s), "soldier readable");
    Check(s.values[Activity] == 9 && s.values[Order] == 4 && s.values[Holder] == 0x1334180 && s.values[PostureState] == 12 &&
          s.values[Stance] == 1 && s.values[TargetUnit] == other && s.values[EngagePhase] == 7 && s.values[AnimId] == 0x360 &&
          s.values[FireFlags] == 0x04030201 && s.unit == unit && s.vtable == w.coreTable - g_delta && !s.exceptions,
          "soldier decided fields");
    W8(a + 0x2C4, 0); ExtractSoldier(a, *table, q, s); Check(s.values[Holder] == 0, "disabled holder reads 0"); W8(a + 0x2C4, 1);
    W(a + 0xF8, 0); ExtractSoldier(a, *table, q, s); Check(s.values[PostureState] == 0xFF, "null posture state");
    W(a + 0xF8, Pref(0x1454168 + 4 * 13)); ExtractSoldier(a, *table, q, s); Check(s.values[PostureState] == 0xFE, "beyond the singletons");
    W(a + 0xF8, Pref(0x1454169)); ExtractSoldier(a, *table, q, s); Check(s.values[PostureState] == 0xFE, "misaligned posture pointer");
    W(a + 0xF8, Pref(0x1454168)); ExtractSoldier(a, *table, q, s); Check(s.values[PostureState] == 0, "first singleton");
    W(a + 0x1EC, 0); ExtractSoldier(a, *table, q, s); Check(s.values[TargetUnit] == 0 && !s.targetUnreadable, "no target");
    const LONG avs = g_avs;
    W(a + 0x1EC, w.noAccess); ExtractSoldier(a, *table, q, s);
    Check(s.values[TargetUnit] == ~0u && s.targetUnreadable, "unreadable target unit");
    W(a + 0x1EC, target);
    Check(!ExtractSoldier(w.noAccess, *table, q, s), "unreadable soldier refused");
    Check(g_avs == avs, "no first-chance access violation in soldier reads");
    // Exception bits, one at a time on a clean soldier.
    struct Bit { U bit; U offset; U value; bool byte; U table; } bits[] = {
        {ExEngage9, 0x224, 9, false, 0}, {ExMelee, 0x1B8, 0xD, false, 0}, {ExMelee, 0x220, 2, false, 0},
        {ExRouting, 0x1D8, 0x3C, false, 0}, {ExRouting, 0x1D8, 0x3D, false, 0}, {ExRouting, 0x1B8, 0x4B, false, 0},
        {ExParked, 0x628, 1, false, 0}, {ExDeactivated, 0x30, 0, true, 0}, {ExPendingRequest, 0x18, 1, false, 0},
        {ExCrew, 0x66C, 2, false, 0}, {ExCrew, 0x22C, Pref(0x133AE34), false, 0}, {ExNoUnit, 0x1F0, 0, false, 0},
        {ExArtillery, 0, 0, false, 0x6F4660}, {ExCavalryCharge, 0x4E8, 1, false, 0x602EB0}};
    for (const Bit& b : bits) {
        const U x = w.Soldier(b.table ? w.Table(b.table) : w.coreTable, unit, 0, 0);
        W(x + 0x1B8, 9); W(x + 0x1D8, 4);
        if (b.offset) { if (b.byte) W8(x + b.offset, b.value); else W(x + b.offset, b.value); }
        Check(ExtractSoldier(x, *table, q, s) && s.exceptions == 1u << b.bit, "single exception bit");
    }
    {
        const U x = w.Soldier(w.Table(0x602EB0), unit, 0, 0); W(x + 0x1B8, 9); W(x + 0x1D8, 4);
        Check(ExtractSoldier(x, *table, q, s) && !s.exceptions, "mounted class without a charge callback is no exception");
        const U p = w.Soldier(w.Table(0x5FCEB0), unit, 0, 0); W(p + 0x1B8, 9); W(p + 0x1D8, 4);
        Check(ExtractSoldier(p, *table, q, s) && !s.exceptions, "pose wrapper class is observed");
        const U o = w.Soldier(w.Table(0x123456), unit, 0, 0);
        Check(ExtractSoldier(o, *table, q, s) && s.exceptions == 1u << ExOtherClass && !s.values[Activity], "other class: no fields");
    }
    // Far from the sequencer destination: measured only with an active sequencer and an untransformed descriptor.
    {
        const U x = w.Soldier(w.coreTable, unit, 0, 0); W(x + 0x1B8, 9); W(x + 0x1D8, 4);
        WF(x + 0x48, 100.0f); WF(x + 0x50, 50.0f); WF(x + 0x3F4, 106.0f); WF(x + 0x3FC, 58.1f); // 10.06 planar
        ExtractSoldier(x, *table, q, s); Check(!s.farMeasured && !s.exceptions, "idle sequencer: unmeasured");
        W(x + 0x390, 3); ExtractSoldier(x, *table, q, s); Check(s.farMeasured && s.exceptions == 1u << ExFarFromSlot, "far from slot");
        WF(x + 0x3FC, 57.9f); ExtractSoldier(x, *table, q, s); Check(s.farMeasured && !s.exceptions, "within the radius");
        W(x + 0x404, 1); WF(x + 0x3FC, 90.0f); ExtractSoldier(x, *table, q, s); Check(!s.farMeasured && !s.exceptions, "transformed: unmeasured");
    }
    delete table;
}

U RunStage(U manager, std::vector<U>& list) {
    W(manager + 0x260, static_cast<U>(list.size())); W(manager + 0x264, Addr(list.data()));
    ntw2_brain2::RunWorklist(manager, nullptr);
    return 0;
}

void StageCases(World& w) {
    const U ua = w.Unit(), ub = w.Unit();
    std::vector<U> a, b;
    for (U i = 0; i < 6; ++i) a.push_back(w.Soldier(w.coreTable, ua, i == 4 ? 0x1D : 9, 4));
    W(a[5] + 0x628, 1); // parked exception
    const U acts[4] = {1, 1, 2, 2};
    for (U i = 0; i < 4; ++i) b.push_back(w.Soldier(i < 2 ? w.coreTable : w.coreTable2, ub, acts[i], 4));
    const U inactive = w.Soldier(w.coreTable, ua, 9, 4); W8(inactive + 0x30, 0);
    std::vector<U> list = a; list.insert(list.end(), b.begin(), b.end()); list.push_back(inactive); list.push_back(a[0]);
    const U manager = w.arena.Alloc(0x300);
    U words[kWords];

    Check(Start({g_delta + 0x400000, nullptr, 0, 0}), "start inline");
    Reset();
    Snapshot(words);
    bool zero = true; for (U x : words) zero = zero && !x;
    Check(zero, "row is zero before the first stage");
    // Observer seam: no native write. Same stage with and without the observer must leave identical memory.
    std::vector<uint8_t> before(w.arena.base, w.arena.base + w.arena.used), plain;
    RunStage(manager, list);
    plain.assign(w.arena.base, w.arena.base + w.arena.used);
    memcpy(w.arena.base, before.data(), before.size());
    ntw2_brain2::SetStageObserver(&kObserver);
    RunStage(manager, list); // stage 1
    Check(!memcmp(w.arena.base, plain.data(), plain.size()), "observer and decide write no native byte");
    Check(R(a[0] + kStepCount) == 2 && R(inactive + kStepCount) == 0, "==1 filter and duplicate occurrence");
    Snapshot(words);
    Check(words[Version] == kVersion && words[Stages] == 1 && words[Occurrences] == 11 && words[Observed] == 11 &&
          words[NewUnits] == 2 && words[UnitsLast] == 2 && words[DecisionsLast] == 0, "stage 1 header");
    Check(words[ExceptionWords + ExParked] == 2 - 1 && words[AnyException] == 1, "parked exception counted once per occurrence");
    Check(FieldWord(words, Activity, HeldNone) == 10 && FieldWord(words, Activity, HeldAgree) == 0, "stage 1 has no held decision");
    Check(FieldWord(words, Activity, TickAgree) == 5 + 2 && FieldWord(words, Activity, TickDisagree) == 1 &&
          words[TickNoneWords + Activity] == 0 && words[VoteExcluded] == 2 && words[UnresolvedRole] == 0,
          "tick majority over main-class voters (unit B 2:2 class tie: first-seen class votes, the other is excluded)");
    Check(FieldWord(words, Order, TickAgree) == 8 && FieldWord(words, Order, TickDisagree) == 0, "uniform order");
    Check(FieldWord(words, Activity, WorstStagePermille) == ~0u, "no held comparison yet");
    Check(words[VtablesDistinct] == 2 && words[VtableRows] == w.coreTable - g_delta && words[VtableRows + 1] == 9 &&
          words[VtableRows + 3] == 2 && words[VtableRows + 4] == w.coreTable2 - g_delta && words[VtableRows + 5] == 2 &&
          words[VtableRows + 7] == 1, "vtable census: occurrences and unit-stage appearances");

    RunStage(manager, list); // stage 2: unchanged signature, the held record applies
    Snapshot(words);
    Check(words[DecisionsLast] == 2 && words[SignatureChanges] == 0, "stage 2 decisions");
    Check(FieldWord(words, Activity, HeldAgree) == 5 + 2 && FieldWord(words, Activity, HeldDisagree) == 1 &&
          FieldWord(words, Activity, HeldNone) == 10, "activity held: unit A 5/1, unit B main class 2/0");
    Check(FieldWord(words, Order, HeldAgree) == 8 && FieldWord(words, Order, HeldNone) == 10, "order held");
    Check(words[UnresolvedRole] == 2 && FieldWord(words, Activity, ExceptionAgree) == 1 &&
          FieldWord(words, Activity, ExceptionDisagree) == 2 && FieldWord(words, Order, ExceptionAgree) == 3,
          "parked soldier and unresolved-role soldiers compared in the exception columns");
    Check(words[HeldAgreeAll] == 7 && words[HeldDisagreeAny] == 1 && words[LastStageAgreeAll] == 7 &&
          words[LastStageCompared] == 8, "all-field agreement");
    Check(FieldWord(words, Activity, WorstStagePermille) == 875, "worst stage permille");
    Check(words[VtableRows + 2] == 1 && words[VtableRows + 3] == 4 && words[VtableRows + 7] == 2,
          "disagreement attributed to the vtable; unit-stage appearances accumulate");

    W(a[1] + kScriptActivity, 0xC); // stage 3: one more dissenter in unit A
    RunStage(manager, list);
    Snapshot(words);
    Check(FieldWord(words, Activity, HeldAgree) == 7 + 6 && FieldWord(words, Activity, HeldDisagree) == 1 + 2,
          "stage 3 dissent");
    Check(FieldWord(words, Activity, WorstStagePermille) == 750, "worst stage permille drops");
    W(a[1] + kScriptActivity, 9);

    W(ua + 0x934, 3); W(ua + 0x398 + 3 * 0x90, 0x01321CA4); // stage 4: unit A command changes
    RunStage(manager, list);
    Snapshot(words);
    Check(words[SignatureChanges] == 1 && words[DecisionsLast] == 1, "signature change voids the unit decision");
    Check(FieldWord(words, Order, HeldNone) == 10 + 6 && FieldWord(words, Order, HeldAgree) == 8 + 8 + 2,
          "unit A undetermined, unit B held");
    RunStage(manager, list); // stage 5: re-formed under the new signature
    Snapshot(words);
    Check(words[DecisionsLast] == 2 && FieldWord(words, Order, HeldAgree) == 8 + 8 + 2 + 8, "record re-formed");
    Check(words[TickNoneWords + Activity] == 0, "every unit-stage so far had a strict majority");

    // Stage 6: a deactivating step is an exception seen after the step; a new unit C splits 1:1 on activity.
    const U uc = w.Unit();
    list.push_back(w.Soldier(w.coreTable, uc, 3, 4)); list.push_back(w.Soldier(w.coreTable, uc, 4, 4));
    U prior[kWords];
    memcpy(prior, words, sizeof(prior));
    W(a[2] + kScriptDeactivate, 1);
    RunStage(manager, list);
    Snapshot(words);
    Check(words[ExceptionWords + ExDeactivated] == 1, "deactivation observed after the native step");
    Check(words[TickNoneWords + Activity] == 2 && words[TickNoneWords + Order] == 0 &&
          FieldWord(words, Activity, TickAgree) - FieldWord(prior, Activity, TickAgree) == 4 + 2 &&
          FieldWord(words, Activity, TickDisagree) - FieldWord(prior, Activity, TickDisagree) == 1,
          "no-majority unit-stage counted as tick_none, neither agreement nor disagreement");
    Check(words[ObserveUs] >= prior[ObserveUs], "observe time accumulates");
    ntw2_brain2::SetStageObserver(nullptr);
    Reset();
    Snapshot(words);
    zero = true; for (U x : words) zero = zero && !x;
    Check(zero, "reset zeroes the row");
    Stop();
}

// Inline and pool decide produce identical rows (timing and chunk words excluded).
void ParallelCases(World& w) {
    std::vector<U> list;
    std::vector<U> units;
    for (U u = 0; u < 120; ++u) units.push_back(w.Unit());
    for (U i = 0; i < 480; ++i) {
        const U s = w.Soldier(i % 3 ? w.coreTable : w.coreTable2, units[(i * 7) % 120], (i % 5) ? 9 : 1, 4);
        if (i % 11 == 0) W(s + 0x18, 1);
        list.push_back(s);
    }
    const U manager = w.arena.Alloc(0x300);
    std::vector<uint8_t> before(w.arena.base, w.arena.base + w.arena.used);
    U inlineWords[kWords], poolWords[kWords];
    for (U mode = 0; mode < 2; ++mode) {
        memcpy(w.arena.base, before.data(), before.size());
        Check(Start({g_delta + 0x400000, mode ? &ThreadDispatch : nullptr, mode ? 3u : 0u, mode ? 3u : 0u}), "start");
        Reset();
        ntw2_brain2::SetStageObserver(&kObserver);
        for (U stage = 0; stage < 4; ++stage) {
            if (stage == 2) for (U u = 0; u < 120; u += 9) W(units[u] + 0xAA0, 4);
            RunStage(manager, list);
        }
        ntw2_brain2::SetStageObserver(nullptr);
        Snapshot(mode ? poolWords : inlineWords);
        Stop();
    }
    Check(poolWords[Chunks] == 3 * 4 && inlineWords[Chunks] == 3, "pool decide ran in four chunks per stage");
    bool same = true;
    for (U i = 0; i < kWords; ++i)
        if (i != DecideUs && i != FinalizeUs && i != ObserveUs && i != Chunks && inlineWords[i] != poolWords[i]) { same = false; printf("  word %u: %u vs %u\n", i, inlineWords[i], poolWords[i]); }
    Check(same, "pool decide equals inline decide");
    Check(inlineWords[SignatureChanges] == 14 && inlineWords[UnitsLast] == 120 && inlineWords[NewUnits] == 120,
          "signature changes on the touched units");
}
} // namespace

int main() {
    AddVectoredExceptionHandler(1, &CountAv);
    g_delta = Addr(reinterpret_cast<void*>(&Step)) - 0x66CE00;
    World w;
    Check(w.arena.base && w.noAccess, "fixture memory");
    Start({g_delta + 0x400000, nullptr, 0, 0});
    InputCases(w);
    SoldierCases(w);
    Stop();
    StageCases(w);
    ParallelCases(w);
    Check(g_avs == 0, "no first-chance access violation anywhere");
    printf("%s cases=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
