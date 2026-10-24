// Formation residual census (native_formation_residual.h). Reads native memory only through the same pointers the original
// 0x585D50/0x580A30 use; writes only its own row. Runs on the tick owner inside a storm-census Unit occurrence.
#include "native_formation_residual.h"
#include "native_army_storm.h"
#include "clones/kntwr_clones.h"
#include <windows.h>
#include <string.h>

namespace kntwr_form_residual {
namespace {
using u64 = unsigned long long;

U g_delta, g_cloneForm;
bool g_enabled;
LARGE_INTEGER g_frequency;
U g_readCostQ16; // QPC ticks per QueryPerformanceCounter read, 16.16 fixed point (calibrated at Start)
U g_words[kWords];

U V(U preferred) { return preferred + g_delta; }
U FnAddress(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
U Sat(u64 v) { return v > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(v); }
U Us(u64 q) { return g_frequency.QuadPart ? Sat(q * 1000000ull / static_cast<u64>(g_frequency.QuadPart)) : 0; }
U Cap(u64 v, U bits) { const u64 m = (1ull << bits) - 1; return static_cast<U>(v > m ? m : v); }

enum Gate : U { GDirtyA, GDirtyB, GAgg, GFsm, GCmdPred, GCmdCtor, GQueue, GTail, GRec, kGates };

// Per-formation state (valid while g_inForm). Filled around one CLONE_FORM_UPDATE call.
struct FormState {
    U members, reads;
    u64 gates[kGates], gateCalls[kGates];
    u64 r1q0, r1bq0, r2q0, queueR2Q, queueR2Q0;
};
FormState g_form;
U g_inForm;
u64 g_obsReads; // cumulative QPC reads of this module's brackets (observer estimate)

// Per-tick accumulators and the two class aggregates (storm / calm) share this shape.
struct Counts {
    u64 forms, formQ, maxFormQ, maxFormMembers, membersSum, ge1ms, loop1Q, loop2Q, loopCalls;
    u64 gateQ[kGates], gateCalls[kGates];
    u64 r1Q, r1bQ, r2Q, queueR2Q, maxFormGateQ;
    u64 memberCalls;
};
Counts g_t, g_agg[2];
U g_ticks, g_stormTicks;
struct Entry { U word[kEntryWords]; };
Entry g_top[kTop];
U g_topCount;

struct CalleeEntry { U va, loopMask; u64 calls, q; };
CalleeEntry g_callees[kCalleeMax];
U g_calleeCount, g_calleeOverflow, g_outside;

void NoteReads(U n) {
    g_form.reads += n;
    g_obsReads += n;
    kntwr_army_storm::AddObserverQ(((u64)n * g_readCostQ16) >> 16); // stays inside the storm census's observer subtraction
}

void CalleeRecord(U va, U loopIx, u64 q) {
    for (U i = 0; i < g_calleeCount; ++i)
        if (g_callees[i].va == va) { g_callees[i].loopMask |= 1u << loopIx; ++g_callees[i].calls; g_callees[i].q += q; return; }
    if (g_calleeCount < kCalleeMax) {
        g_callees[g_calleeCount++] = CalleeEntry{ va, 1u << loopIx, 1, q };
        return;
    }
    ++g_calleeOverflow;
}

// CLONE_FORM_UPDATE gates: each forwards its original exactly once (verified ABIs, see kntwr_clones.h KNTWR_BIND_FORM_*).
// Outside a Formation occurrence (must not happen: the clone is only entered by the port) the original runs directly.
U __fastcall GateDirtyA(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x576EA0)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    const LONGLONG a = Now();
    const U r = native(ecx);
    const LONGLONG b = Now();
    g_form.gates[GDirtyA] += static_cast<u64>(b - a); ++g_form.gateCalls[GDirtyA]; NoteReads(2);
    return r;
}
U __fastcall GateDirtyB(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x57C9F0)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    const LONGLONG a = Now();
    const U r = native(ecx);
    const LONGLONG b = Now();
    g_form.gates[GDirtyB] += static_cast<u64>(b - a); ++g_form.gateCalls[GDirtyB]; NoteReads(2);
    return r;
}
// 53C180: ECX = F+62C, one stack argument (byte F+514), callee pops 4 (ret 4).
U __fastcall GateAgg(void* ecx, void*, U arg) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*, void*, U)>(static_cast<uintptr_t>(V(0x53C180)));
    if (!g_inForm) { ++g_outside; return native(ecx, nullptr, arg); }
    const LONGLONG a = Now();
    const U r = native(ecx, nullptr, arg);
    const LONGLONG b = Now();
    g_form.gates[GAgg] += static_cast<u64>(b - a); ++g_form.gateCalls[GAgg]; NoteReads(2);
    return r;
}
// 580990: ECX = F+480, plain ret.
U __fastcall GateFsm(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x580990)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    const LONGLONG a = Now();
    const U r = native(ecx);
    const LONGLONG b = Now();
    g_form.gates[GFsm] += static_cast<u64>(b - a); ++g_form.gateCalls[GFsm]; NoteReads(2);
    return r;
}
// 586440: ECX = command target, one stack argument (0), callee pops 4; AL is the predicate result.
U __fastcall GateCmdPred(void* ecx, void*, U arg) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*, void*, U)>(static_cast<uintptr_t>(V(0x586440)));
    if (!g_inForm) { ++g_outside; return native(ecx, nullptr, arg); }
    const LONGLONG a = Now();
    const U r = native(ecx, nullptr, arg);
    const LONGLONG b = Now();
    g_form.gates[GCmdPred] += static_cast<u64>(b - a); ++g_form.gateCalls[GCmdPred]; NoteReads(2);
    return r;
}
// 51A3A0: ECX = new object (522D70 result), three stack arguments, callee pops 0xC.
U __fastcall GateCmdCtor(void* ecx, void*, U a1, U a2, U a3) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*, void*, U, U, U)>(static_cast<uintptr_t>(V(0x51A3A0)));
    if (!g_inForm) { ++g_outside; return native(ecx, nullptr, a1, a2, a3); }
    const LONGLONG a = Now();
    const U r = native(ecx, nullptr, a1, a2, a3);
    const LONGLONG b = Now();
    g_form.gates[GCmdCtor] += static_cast<u64>(b - a); ++g_form.gateCalls[GCmdCtor]; NoteReads(2);
    return r;
}
// 581E80: ECX = F+20 (command queue), plain ret. R2 us inside the queue = the storm census's R2 gate delta over this call.
U __fastcall GateQueue(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x581E80)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    u64 r2q0 = 0;
    kntwr_army_storm::OccurrenceRouteQ(nullptr, nullptr, &r2q0);
    const LONGLONG a = Now();
    const U r = native(ecx);
    const LONGLONG b = Now();
    u64 r2q1 = 0;
    kntwr_army_storm::OccurrenceRouteQ(nullptr, nullptr, &r2q1);
    g_form.gates[GQueue] += static_cast<u64>(b - a); ++g_form.gateCalls[GQueue]; g_form.queueR2Q += r2q1 - r2q0; NoteReads(2);
    return r;
}
// 551A40: ECX = F+74C, plain ret (ends in a tail jmp to 542AA0, plain rets there).
U __fastcall GateTail(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x551A40)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    const LONGLONG a = Now();
    const U r = native(ecx);
    const LONGLONG b = Now();
    g_form.gates[GTail] += static_cast<u64>(b - a); ++g_form.gateCalls[GTail]; NoteReads(2);
    return r;
}
// DACDC0: cdecl, five stack arguments (0x2CC, 0, 0, hash, 0x1324BD8), caller cleans.
U __cdecl GateRec(U a0, U a1, U a2, U a3, U a4) {
    const auto native = reinterpret_cast<U(__cdecl*)(U, U, U, U, U)>(static_cast<uintptr_t>(V(0xDACDC0)));
    if (!g_inForm) { ++g_outside; return native(a0, a1, a2, a3, a4); }
    const LONGLONG a = Now();
    const U r = native(a0, a1, a2, a3, a4);
    const LONGLONG b = Now();
    g_form.gates[GRec] += static_cast<u64>(b - a); ++g_form.gateCalls[GRec]; NoteReads(2);
    return r;
}

typedef U(__fastcall* MemberFn)(void*);
U MemberCallee(void* obj) { // mov eax, [ecx]; call [eax+0xC] — plain reads like the original
    const U vtbl = *reinterpret_cast<U*>(obj);
    return *reinterpret_cast<U*>(vtbl + 0xC);
}

// One CLONE_FORM_UPDATE call (the infantry formation update 0x580A30): brackets the clone and its nine gates, attributes the
// storm census's route-gate deltas (R1/R1b/R2) to the formation, and feeds the per-tick accumulators.
U RunClone(void* f) {
    memset(&g_form, 0, sizeof(g_form));
    g_form.members = *reinterpret_cast<const U*>(static_cast<U>(reinterpret_cast<uintptr_t>(f)) + 0x18);
    g_inForm = 1;
    kntwr_army_storm::OccurrenceRouteQ(&g_form.r1q0, &g_form.r1bq0, &g_form.r2q0);
    NoteReads(2);
    const LONGLONG a = Now();
    const U r = reinterpret_cast<MemberFn>(static_cast<uintptr_t>(g_cloneForm))(f);
    const LONGLONG b = Now();
    g_inForm = 0;
    u64 r1q = 0, r1bq = 0, r2q = 0;
    kntwr_army_storm::OccurrenceRouteQ(&r1q, &r1bq, &r2q);
    const u64 q = static_cast<u64>(b - a);
    Counts& t = g_t;
    ++t.forms; t.formQ += q; t.membersSum += g_form.members;
    const u64 freq = static_cast<u64>(g_frequency.QuadPart);
    if (q >= freq * kMid / 1000000ull) ++t.ge1ms;
    u64 gateSum = 0;
    for (U i = 0; i < kGates; ++i) { t.gateQ[i] += g_form.gates[i]; t.gateCalls[i] += g_form.gateCalls[i]; gateSum += g_form.gates[i]; }
    t.r1Q += r1q - g_form.r1q0; t.r1bQ += r1bq - g_form.r1bq0; t.r2Q += r2q - g_form.r2q0; t.queueR2Q += g_form.queueR2Q;
    if (q > t.maxFormQ) { t.maxFormQ = q; t.maxFormMembers = g_form.members; t.maxFormGateQ = gateSum; }
    return r;
}

void RunMember(U callee, void* obj, U loopIx) {
    NoteReads(2);
    const LONGLONG a = Now();
    const U result = (callee - g_delta == 0x580A30 && g_cloneForm && g_enabled)
        ? RunClone(obj)
        : reinterpret_cast<MemberFn>(static_cast<uintptr_t>(callee))(obj);
    (void)result; // the original ignores EAX (5820E3 reloads ECX)
    const LONGLONG b = Now();
    const u64 q = static_cast<u64>(b - a);
    ++g_t.memberCalls;
    CalleeRecord(callee - g_delta, loopIx, q);
}

// Exact port of one 0x585D50 member loop (disassembly-pinned): `esi = [u+list], eax = [u+count], end = esi + eax*4;
// while (esi != end) { ecx = [esi]; call [ecx's vtbl + 0xC]; ecx = [u+count]; esi += 4; eax = [u+list]; end = eax + ecx*4; }`.
void Loop(U u, U listOff, U countOff, U loopIx) {
    NoteReads(2);
    const LONGLONG l0 = Now();
    volatile U* p = *reinterpret_cast<U* volatile*>(u + listOff);
    U* end = const_cast<U*>(p) + *reinterpret_cast<const volatile U*>(u + countOff);
    while (const_cast<U*>(p) != end) {
        void* obj = reinterpret_cast<void*>(static_cast<uintptr_t>(*p));
        RunMember(MemberCallee(obj), obj, loopIx);
        const U count = *reinterpret_cast<const volatile U*>(u + countOff);
        ++p;
        end = *reinterpret_cast<U* volatile*>(u + listOff) + count;
    }
    const LONGLONG l1 = Now();
    (loopIx ? g_t.loop2Q : g_t.loop1Q) += static_cast<u64>(l1 - l0);
    ++g_t.loopCalls;
}

void PublishAggregate(U base, const Counts& a) {
    U* w = g_words + base;
    w[AForms] = Sat(a.forms); w[AFormUs] = Us(a.formQ); w[AMaxFormUs] = Us(a.maxFormQ);
    w[AMaxFormMembers] = Sat(a.maxFormMembers); w[AMembersSum] = Sat(a.membersSum); w[AFormsGe1ms] = Sat(a.ge1ms);
    w[ALoop1Us] = Us(a.loop1Q); w[ALoop2Us] = Us(a.loop2Q); w[ALoopCalls] = Sat(a.loopCalls);
    static const U gateWord[kGates] = { ADirtyACalls, ADirtyBCalls, AAggCalls, AFsmCalls, ACmdPredCalls, ACmdCtorCalls,
                                        AQueueCalls, ATailCalls, ARecCalls };
    for (U i = 0; i < kGates; ++i) { w[gateWord[i]] = Sat(a.gateCalls[i]); w[gateWord[i] + 1] = Us(a.gateQ[i]); }
    w[AR1Us] = Us(a.r1Q); w[AR1bUs] = Us(a.r1bQ); w[AR2Us] = Us(a.r2Q); w[AQueueR2Us] = Us(a.queueR2Q);
    w[AMaxFormGateUs] = Us(a.maxFormGateQ);
}

void PublishCallees() {
    U* w = g_words + CalleeTable;
    for (U i = 0; i < kCalleeMax; ++i) {
        w[0] = i < g_calleeCount ? g_callees[i].va : 0;
        w[1] = i < g_calleeCount ? g_callees[i].loopMask : 0;
        w[2] = i < g_calleeCount ? Sat(g_callees[i].calls) : 0;
        w[3] = i < g_calleeCount ? Us(g_callees[i].q) : 0;
        w += 4;
    }
}

void PublishTop() {
    // Largest site-18 us first (header contract); stable insertion sort over the kept slots, unused slots stay zero.
    U order[kTop];
    for (U i = 0; i < g_topCount; ++i) {
        U j = i;
        while (j > 0 && g_top[order[j - 1]].word[ESite18Us] < g_top[i].word[ESite18Us]) { order[j] = order[j - 1]; --j; }
        order[j] = i;
    }
    U* w = g_words + TopTable;
    for (U i = 0; i < kTop; ++i) {
        if (i < g_topCount) memcpy(w, g_top[order[i]].word, sizeof(g_top[0].word)); else memset(w, 0, sizeof(g_top[0].word));
        w += kEntryWords;
    }
}
} // namespace

void Bind(U delta, uint32_t* bindings) {
    g_delta = delta;
    bindings[KNTWR_BIND_FORM_DIRTY_A] = FnAddress(reinterpret_cast<const void*>(&GateDirtyA));
    bindings[KNTWR_BIND_FORM_DIRTY_B] = FnAddress(reinterpret_cast<const void*>(&GateDirtyB));
    bindings[KNTWR_BIND_FORM_AGG] = FnAddress(reinterpret_cast<const void*>(&GateAgg));
    bindings[KNTWR_BIND_FORM_FSM] = FnAddress(reinterpret_cast<const void*>(&GateFsm));
    bindings[KNTWR_BIND_FORM_CMD_PRED] = FnAddress(reinterpret_cast<const void*>(&GateCmdPred));
    bindings[KNTWR_BIND_FORM_CMD_CTOR] = FnAddress(reinterpret_cast<const void*>(&GateCmdCtor));
    bindings[KNTWR_BIND_FORM_QUEUE] = FnAddress(reinterpret_cast<const void*>(&GateQueue));
    bindings[KNTWR_BIND_FORM_TAIL] = FnAddress(reinterpret_cast<const void*>(&GateTail));
    bindings[KNTWR_BIND_FORM_REC] = FnAddress(reinterpret_cast<const void*>(&GateRec));
}

bool Start(U cloneFormUpdate) {
    Stop();
    QueryPerformanceFrequency(&g_frequency);
    g_cloneForm = cloneFormUpdate;
    Reset();
    // Calibrate the per-read QPC cost (16.16 QPC ticks): one read, then 4096 reads; the loop body is negligible next to QPC.
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    for (U i = 0; i < 4096; ++i) QueryPerformanceCounter(&b);
    const u64 span = static_cast<u64>(b.QuadPart - a.QuadPart);
    g_readCostQ16 = static_cast<U>((span << 16) / 4096);
    g_enabled = true;
    g_words[Version] = kVersion; g_words[Enabled] = 1; g_words[QpcReadCostQ16] = g_readCostQ16;
    return true;
}
void Stop() { g_enabled = false; g_cloneForm = 0; g_inForm = 0; }
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    memset(&g_t, 0, sizeof(g_t)); memset(g_agg, 0, sizeof(g_agg)); memset(g_top, 0, sizeof(g_top));
    memset(&g_form, 0, sizeof(g_form)); memset(g_callees, 0, sizeof(g_callees));
    g_ticks = g_stormTicks = g_topCount = g_calleeCount = g_calleeOverflow = g_outside = 0;
    g_obsReads = 0; g_inForm = 0;
}

U __fastcall Formation(void* unit) {
    if (!kntwr_army_storm::InUnit()) { // not inside a census occurrence: plain port, original callees, no accounting
        const U u = static_cast<U>(reinterpret_cast<uintptr_t>(unit));
        for (U loopIx = 0; loopIx < 2; ++loopIx) {
            const U listOff = loopIx ? 0xAD0u : 0xAB4u, countOff = loopIx ? 0xACCu : 0xAB0u;
            volatile U* p = *reinterpret_cast<U* volatile*>(u + listOff);
            U* end = const_cast<U*>(p) + *reinterpret_cast<const volatile U*>(u + countOff);
            while (const_cast<U*>(p) != end) {
                void* obj = reinterpret_cast<void*>(static_cast<uintptr_t>(*p));
                reinterpret_cast<MemberFn>(static_cast<uintptr_t>(MemberCallee(obj)))(obj);
                const U count = *reinterpret_cast<const volatile U*>(u + countOff);
                ++p;
                end = *reinterpret_cast<U* volatile*>(u + listOff) + count;
            }
        }
        return 0;
    }
    g_inForm = 0; // clears a stale flag if a previous clone call unwound
    ++g_words[FormCalls];
    const U u = static_cast<U>(reinterpret_cast<uintptr_t>(unit));
    Loop(u, 0xAB4, 0xAB0, 0);
    Loop(u, 0xAD0, 0xACC, 1);
    g_words[CloneForms] = Sat(g_agg[0].forms + g_agg[1].forms + g_t.forms);
    return 0;
}

void TickEnd(U tick, U site18Us, bool storm) {
    if (!g_enabled) return;
    Counts& t = g_t;
    ++g_ticks;
    if (t.memberCalls || t.loopCalls) {
        Counts& a = g_agg[storm ? 0 : 1];
        a.forms += t.forms; a.formQ += t.formQ; a.membersSum += t.membersSum; a.ge1ms += t.ge1ms;
        if (t.maxFormQ > a.maxFormQ || (t.maxFormQ == a.maxFormQ && t.maxFormMembers > a.maxFormMembers)) {
            a.maxFormQ = t.maxFormQ; a.maxFormMembers = t.maxFormMembers; a.maxFormGateQ = t.maxFormGateQ; // gate sum belongs to the winning form
        }
        a.loop1Q += t.loop1Q; a.loop2Q += t.loop2Q; a.loopCalls += t.loopCalls; a.memberCalls += t.memberCalls;
        for (U i = 0; i < kGates; ++i) { a.gateQ[i] += t.gateQ[i]; a.gateCalls[i] += t.gateCalls[i]; }
        a.r1Q += t.r1Q; a.r1bQ += t.r1bQ; a.r2Q += t.r2Q; a.queueR2Q += t.queueR2Q;
    }
    if (storm) {
        ++g_stormTicks;
        Entry e = {};
        U* w = e.word;
        w[ETick] = tick; w[ESite18Us] = site18Us; w[EForms] = Sat(t.forms); w[EFormUs] = Us(t.formQ);
        w[EMaxFormUs] = Us(t.maxFormQ); w[EMaxFormMembers] = Sat(t.maxFormMembers);
        w[ELoop1Us] = Us(t.loop1Q); w[ELoop2Us] = Us(t.loop2Q);
        w[EMemberCalls] = Sat(t.memberCalls); w[ELoopCalls] = Sat(t.loopCalls);
        w[EDirtyAUs] = Us(t.gateQ[GDirtyA]); w[EDirtyBUs] = Us(t.gateQ[GDirtyB]); w[EAggUs] = Us(t.gateQ[GAgg]);
        w[EFsmUs] = Us(t.gateQ[GFsm]); w[ECmdPredUs] = Us(t.gateQ[GCmdPred]); w[ECmdCtorUs] = Us(t.gateQ[GCmdCtor]);
        w[EQueueUs] = Us(t.gateQ[GQueue]); w[ETailUs] = Us(t.gateQ[GTail]); w[ERecUs] = Us(t.gateQ[GRec]);
        w[ER1Us] = Us(t.r1Q); w[ER1bUs] = Us(t.r1bQ); w[ER2Us] = Us(t.r2Q); w[EQueueR2Us] = Us(t.queueR2Q);
        w[EDirtyAbCalls] = Cap(t.gateCalls[GDirtyA], 16) | Cap(t.gateCalls[GDirtyB], 16) << 16;
        U slot = g_topCount;
        if (g_topCount < kTop) ++g_topCount;
        else {
            slot = 0;
            for (U i = 1; i < kTop; ++i) if (g_top[i].word[ESite18Us] < g_top[slot].word[ESite18Us]) slot = i;
            if (g_top[slot].word[ESite18Us] >= site18Us) slot = kTop; // not larger than the smallest kept
        }
        if (slot < kTop) g_top[slot] = e;
    }
    g_words[Ticks] = g_ticks; g_words[StormTicks] = g_stormTicks;
    g_words[MemberCalls] = Sat(g_agg[0].memberCalls + g_agg[1].memberCalls); // t is already folded into g_agg above
    g_words[OtherForms] = Sat(g_agg[0].memberCalls + g_agg[1].memberCalls - (g_agg[0].forms + g_agg[1].forms));
    g_words[ObserverUs] = Us((g_obsReads * g_readCostQ16) >> 16);
    g_words[GateOutside] = g_outside; g_words[CalleeOverflow] = g_calleeOverflow;
    PublishCallees();
    PublishAggregate(StormAggregate, g_agg[0]); PublishAggregate(CalmAggregate, g_agg[1]);
    PublishTop();
    memset(&t, 0, sizeof(t));
}

void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
} // namespace kntwr_form_residual
