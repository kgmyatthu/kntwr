// Formation residual census (native_formation_residual.h). Reads native memory only through the same pointers the original
// 0x585D50/0x580A30 use; writes only its own row. Runs on the tick owner inside a storm-census Unit occurrence.
#include "native_formation_residual.h"
#include "native_army_storm.h"
#include "native_army_solver.h"
#include "clones/kntwr_clones.h"
#include "native_formation_queue.h"
#include <windows.h>
#include <string.h>
#include <intrin.h>

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

// Limited (limit != 0) solver calls reported by the solver gate through NoteLimitedSolve: per-tick accumulator (g_lim, folded and
// cleared at every TickEnd) and per-class aggregates. Independent of Counts so ticks without formation calls still count.
struct Lim { u64 calls, q, maxCallQ; };
struct LimAgg { u64 ticks, calls, q, maxCallQ, maxTickQ, onlyTicks, onlyCalls, onlyQ; };
Lim g_lim;
LimAgg g_limAgg[2];
// Retention ledger (see LedgerWord): every offered storm tick is either a kept row, rejected on offer or evicted later.
struct Ledger {
    u64 offered, rejected, evicted, limTicks, sinkCalls, sinkFolded, sinkAborted, sinkOutside, abortedTicks, abortedLimQ, abortedFormCalls;
    u64 queueCalls, queueFolded, queueAborted, queueOutside, abortedQueueQ;
    u64 routeBegun, routeFolded, routeAborted, routeDiscarded, routeRefusedScope, routeRefusedDepth, routeUnscoped, abortedRouteQ;
};
Ledger g_ledger;
bool g_open;      // an invocation scope is open (TickBegin .. TickEnd/TickAbort)
U g_ownerTid;     // thread that opened it

// Formation queue command callbacks (queue probe / NoteQueueCommand). Per invocation: count, inclusive time and the slowest single
// callback (slowRouted: that very callback ran through the private command-split chain).
struct Que { u64 calls, q; U slowVtable, slowSlot; u64 slowQ; bool slowRouted; };
Que g_que;

// Command-split private route. A routed callback owns one Scope from the queue port's begin hook until its end hook; the three
// gates of the private chain add their inclusive time to the innermost live scope (matched state enter = the transition into the
// assignment state 4F84C0 -> 5736B0, other state enters, 57B000 assignments, 55F160 per-man calls). Scopes are keyed by the
// dispatching frame (`_AddressOfReturnAddress()` of the queue port's Dispatch): live enclosing scopes have strictly greater
// frames than anything running under them, so a scope whose frame is at or below a later caller's frame can only be one whose
// callback unwound by exception: it is discarded (route_discarded), never folded or attributed.
// Assignment split (version 4): scope = the solver clone's outermost assignment scopes inside the routed GateAssign (QPC ticks, count);
// the rest are the counter deltas of the solver chain over the same span (see EntryWord ERouteAssignScopeUs).
struct Nest { u64 enterCalls, enterQ, otherEnterCalls, otherEnterQ, assignCalls, assignQ, perManCalls, perManQ,
                  scopeQ, scopeCalls, kernelQ, solves, limQ, limCalls, suppressed, assignEntries; };
struct Scope { U frame; Nest n; };
constexpr U kNoScope = 0xFFFFFFFFu;
Scope g_scopes[kRouteDepth];
U g_depth;
U g_cmd581CA0, g_cmd4F84C0; // relocated private clone entries (set by Start, kept by Reset); the route is armed when both exist
struct Route { u64 calls, q; Nest n; U slowVtable, slowSlot; u64 slowQ; Nest slowN; };
Route g_route;                // per invocation: routed callbacks that ended normally, and the slowest of them with its own nested stats
struct RouteAgg { u64 calls, q, maxQ, noEnterCalls; Nest n; };
RouteAgg g_routeAgg;          // cumulative over every routed callback that ended normally inside an owner invocation
#define KNTWR_FRAME() static_cast<U>(reinterpret_cast<uintptr_t>(_AddressOfReturnAddress()))
// Cumulative (class = raw vtable x slot) table in first-seen order; observations that do not fit are counted as overflow.
struct QueueClass { U vtable, slot; u64 calls, q, maxQ; };
QueueClass g_qcls[kQueueClasses];
U g_qclsCount;
u64 g_qOverflowCalls, g_qOverflowQ;
void QueueClassRecord(U vtable, U slot, u64 q) {
    for (U i = 0; i < g_qclsCount; ++i) {
        QueueClass& c = g_qcls[i];
        if (c.vtable == vtable && c.slot == slot) { ++c.calls; c.q += q; if (q > c.maxQ) c.maxQ = q; return; }
    }
    if (g_qclsCount < kQueueClasses) { g_qcls[g_qclsCount++] = QueueClass{ vtable, slot, 1, q, q }; return; }
    ++g_qOverflowCalls; g_qOverflowQ += q;
}

struct CalleeEntry { U va, loopMask; u64 calls, q; };
CalleeEntry g_callees[kCalleeMax];
U g_calleeCount, g_calleeOverflow, g_outside;

void NoteReads(U n) {
    g_form.reads += n;
    g_obsReads += n;
    kntwr_army_storm::AddObserverQ(((u64)n * g_readCostQ16) >> 16); // stays inside the storm census's observer subtraction
}

bool Armed() { return g_enabled && g_cmd581CA0 && g_cmd4F84C0; }
void AddNest(Nest& d, const Nest& s) {
    d.enterCalls += s.enterCalls; d.enterQ += s.enterQ; d.otherEnterCalls += s.otherEnterCalls; d.otherEnterQ += s.otherEnterQ;
    d.assignCalls += s.assignCalls; d.assignQ += s.assignQ; d.perManCalls += s.perManCalls; d.perManQ += s.perManQ;
    d.scopeQ += s.scopeQ; d.scopeCalls += s.scopeCalls; d.kernelQ += s.kernelQ; d.solves += s.solves; d.limQ += s.limQ;
    d.limCalls += s.limCalls; d.suppressed += s.suppressed; d.assignEntries += s.assignEntries;
}
// Eight consecutive words: enter calls/us, other-enter calls/us, assign calls/us, per-man calls/us (row, slow and table order).
void NestWords(U* w, const Nest& n) {
    w[0] = Sat(n.enterCalls); w[1] = Us(n.enterQ); w[2] = Sat(n.otherEnterCalls); w[3] = Us(n.otherEnterQ);
    w[4] = Sat(n.assignCalls); w[5] = Us(n.assignQ); w[6] = Sat(n.perManCalls); w[7] = Us(n.perManQ);
}
// Eight consecutive words of the assignment split: assign_scope us/calls, inner kernel us, inner solves, inner lim us/calls,
// inner suppressed, inner assign entries (row, slow and table order).
void SplitWords(U* w, const Nest& n) {
    w[0] = Us(n.scopeQ); w[1] = Sat(n.scopeCalls); w[2] = Us(n.kernelQ); w[3] = Sat(n.solves);
    w[4] = Us(n.limQ); w[5] = Sat(n.limCalls); w[6] = Sat(n.suppressed); w[7] = Sat(n.assignEntries);
}
// Census probe bracket of the routed GateAssign: while alive, the solver's outermost assignment scopes of this thread are timed
// (kntwr_army_solver::CensusProbeEnter); Leave also on unwinding. The only code that arms the solver's scope timer.
struct SolverProbe {
    SolverProbe() { kntwr_army_solver::CensusProbeEnter(); }
    ~SolverProbe() { kntwr_army_solver::CensusProbeLeave(); }
};
u64 Delta(u64 after, u64 before) { return after >= before ? after - before : 0; } // a solver Reset inside the span yields 0, never a wrap
// Discards in-flight scopes whose dispatching frame is at or below `frame` (their callback unwound by exception).
void PopStale(U frame) {
    while (g_depth && g_scopes[g_depth - 1].frame <= frame) { --g_depth; ++g_ledger.routeDiscarded; }
}
void DropScopes() { g_ledger.routeDiscarded += g_depth; g_depth = 0; }
// Scope frames are stack addresses of the owner thread: only that thread, inside its open invocation, may compare or pop them.
bool ScopeThread() { return g_open && g_ownerTid == GetCurrentThreadId(); }
// Innermost live scope for a gate running at `gateFrame`, or kNoScope (the gate then forwards the native untimed).
U LiveScope(U gateFrame) {
    if (!ScopeThread()) return kNoScope;
    PopStale(gateFrame);
    return g_depth ? g_depth - 1 : kNoScope;
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
// Inside the census the walk runs as the exact port kntwr_formation_queue::Run (EAX is dead at the caller, 580B7A): the bracket,
// queue_us and queue_r2 accounting are unchanged (inclusive of the whole walk); each normally returned command callback is
// additionally timed by the port and reported through QueueEnd. When the private command-split clones exist, a callback whose
// live table value is the native 581CA0 runs the private chain instead (BeginRouted accepts it). Outside a Formation occurrence
// the original runs untouched.
bool BeginRouted(U vtable, U slot, U frame);
void QueueEnd(U vtable, U slot, unsigned long long qpcTicks, bool routed, U frame);
U __fastcall GateQueue(void* ecx) {
    const auto native = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(V(0x581E80)));
    if (!g_inForm) { ++g_outside; return native(ecx); }
    const auto erase = reinterpret_cast<kntwr_formation_queue::EraseFn>(static_cast<uintptr_t>(V(kntwr_formation_queue::kNativeEraseVa)));
    const U gqFrame = KNTWR_FRAME();
    const bool scopeThread = ScopeThread();
    if (scopeThread) PopStale(gqFrame); // scopes left by an exception caught below an earlier walk; enclosing live scopes have greater frames
    const kntwr_formation_queue::Probe probe{ V(0x581CA0), Armed() ? g_cmd581CA0 : 0, &BeginRouted, &QueueEnd };
    u64 r2q0 = 0;
    kntwr_army_storm::OccurrenceRouteQ(nullptr, nullptr, &r2q0);
    const LONGLONG a = Now();
    kntwr_formation_queue::Run(ecx, erase, &probe);
    const LONGLONG b = Now();
    if (scopeThread) PopStale(gqFrame);
    u64 r2q1 = 0;
    kntwr_army_storm::OccurrenceRouteQ(nullptr, nullptr, &r2q1);
    g_form.gates[GQueue] += static_cast<u64>(b - a); ++g_form.gateCalls[GQueue]; g_form.queueR2Q += r2q1 - r2q0; NoteReads(2);
    return 0;
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

// Command-split gates (clone seams of the private 581CA0 chain, see kntwr_clones.h KNTWR_BIND_CMD_*). Each forwards exactly one
// original with its register/stack contract: ECX as received, EDX as RECEIVED (forwarded verbatim), identical stack arguments,
// callee pop count, EAX return. With no live scope (never expected: the chain is entered only by the routed dispatch) the
// NATIVE target runs untimed and route_unscoped_gates counts it. Nested time is written only if the scope is still the same live
// scope when the native returns; a native that throws leaves no partial attribution (its scope is discarded as stale).
//
// 10FBBF3 enter: ECX = the new FSM state, one stack argument (the wrapper), callee pops 4. The gate performs the original's
// `mov eax,[ecx]; call [eax+4]` itself (EAX is dead after the call: 10FBBF6 sets AL). A state whose enter virtual is the native
// 4F84C0 (the assignment state) runs the private 4F84C0 -> 5736B0 clones; every other state runs its own native enter.
U __fastcall GateEnter(void* state, void* edx, U w) {
    typedef U(__fastcall* EnterFn)(void*, void*, U);
    const U vtbl = *reinterpret_cast<const U*>(state);
    const U target = *reinterpret_cast<const U*>(vtbl + 4);
    const U idx = LiveScope(KNTWR_FRAME());
    if (idx == kNoScope) { ++g_ledger.routeUnscoped; return reinterpret_cast<EnterFn>(static_cast<uintptr_t>(target))(state, edx, w); }
    const bool matched = g_cmd4F84C0 && target == V(0x4F84C0);
    const U sframe = g_scopes[idx].frame;
    const LONGLONG a = Now();
    const U r = reinterpret_cast<EnterFn>(static_cast<uintptr_t>(matched ? g_cmd4F84C0 : target))(state, edx, w);
    const LONGLONG b = Now();
    NoteReads(2);
    if (idx < g_depth && g_scopes[idx].frame == sframe) {
        Nest& n = g_scopes[idx].n;
        if (matched) { ++n.enterCalls; n.enterQ += static_cast<u64>(b - a); }
        else { ++n.otherEnterCalls; n.otherEnterQ += static_cast<u64>(b - a); }
    }
    return r;
}
// 5736E0: 57B000, ECX = command, four stack arguments, callee pops 0x10.
U __fastcall GateAssign(void* ecx, void* edx, U a1, U a2, U a3, U a4) {
    typedef U(__fastcall* AssignFn)(void*, void*, U, U, U, U);
    const auto native = reinterpret_cast<AssignFn>(static_cast<uintptr_t>(V(0x57B000)));
    const U idx = LiveScope(KNTWR_FRAME());
    if (idx == kNoScope) { ++g_ledger.routeUnscoped; return native(ecx, edx, a1, a2, a3, a4); }
    const U sframe = g_scopes[idx].frame;
    kntwr_army_solver::CensusSnapshot s0, s1;
    kntwr_army_solver::ReadCensus(&s0);
    LONGLONG a, b;
    U r;
    {
        SolverProbe probe;
        a = Now();
        r = native(ecx, edx, a1, a2, a3, a4);
        b = Now();
    }
    kntwr_army_solver::ReadCensus(&s1);
    NoteReads(2);
    if (idx < g_depth && g_scopes[idx].frame == sframe) {
        Nest& n = g_scopes[idx].n;
        ++n.assignCalls; n.assignQ += static_cast<u64>(b - a);
        const u64 scopes = Delta(s1.assignScopeCalls, s0.assignScopeCalls);
        n.scopeQ += Delta(s1.assignScopeQ, s0.assignScopeQ); n.scopeCalls += scopes;
        n.kernelQ += Delta(s1.kernelQ, s0.kernelQ); n.solves += Delta(s1.solvesSeen, s0.solvesSeen);
        n.limQ += Delta(s1.limitedQ, s0.limitedQ); n.limCalls += Delta(s1.flag0Native, s0.flag0Native);
        n.suppressed += Delta(s1.shimSuppressed, s0.shimSuppressed); n.assignEntries += Delta(s1.assignEntries, s0.assignEntries);
        NoteReads(static_cast<U>(2 * scopes)); // the solver's own scope reads, charged to the observer like this module's
    }
    return r;
}
// 573727: 55F160 once per man, ECX = command, five stack arguments, callee pops 0x14.
U __fastcall GatePerMan(void* ecx, void* edx, U a1, U a2, U a3, U a4, U a5) {
    typedef U(__fastcall* PerManFn)(void*, void*, U, U, U, U, U);
    const auto native = reinterpret_cast<PerManFn>(static_cast<uintptr_t>(V(0x55F160)));
    const U idx = LiveScope(KNTWR_FRAME());
    if (idx == kNoScope) { ++g_ledger.routeUnscoped; return native(ecx, edx, a1, a2, a3, a4, a5); }
    const U sframe = g_scopes[idx].frame;
    const LONGLONG a = Now();
    const U r = native(ecx, edx, a1, a2, a3, a4, a5);
    const LONGLONG b = Now();
    NoteReads(2);
    if (idx < g_depth && g_scopes[idx].frame == sframe) { Nest& n = g_scopes[idx].n; ++n.perManCalls; n.perManQ += static_cast<u64>(b - a); }
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

void PublishAggregate(U base, const Counts& a, const LimAgg& l) {
    U* w = g_words + base;
    w[AForms] = Sat(a.forms); w[AFormUs] = Us(a.formQ); w[AMaxFormUs] = Us(a.maxFormQ);
    w[AMaxFormMembers] = Sat(a.maxFormMembers); w[AMembersSum] = Sat(a.membersSum); w[AFormsGe1ms] = Sat(a.ge1ms);
    w[ALoop1Us] = Us(a.loop1Q); w[ALoop2Us] = Us(a.loop2Q); w[ALoopCalls] = Sat(a.loopCalls);
    static const U gateWord[kGates] = { ADirtyACalls, ADirtyBCalls, AAggCalls, AFsmCalls, ACmdPredCalls, ACmdCtorCalls,
                                        AQueueCalls, ATailCalls, ARecCalls };
    for (U i = 0; i < kGates; ++i) { w[gateWord[i]] = Sat(a.gateCalls[i]); w[gateWord[i] + 1] = Us(a.gateQ[i]); }
    w[AR1Us] = Us(a.r1Q); w[AR1bUs] = Us(a.r1bQ); w[AR2Us] = Us(a.r2Q); w[AQueueR2Us] = Us(a.queueR2Q);
    w[AMaxFormGateUs] = Us(a.maxFormGateQ);
    w[ALimTicks] = Sat(l.ticks); w[ALimCalls] = Sat(l.calls); w[ALimUs] = Us(l.q); w[ALimMaxCallUs] = Us(l.maxCallQ);
    w[ALimMaxTickUs] = Us(l.maxTickQ); w[ALimOnlyTicks] = Sat(l.onlyTicks); w[ALimOnlyCalls] = Sat(l.onlyCalls);
    w[ALimOnlyUs] = Us(l.onlyQ);
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

void PublishLedger() {
    U retainedLim = 0;
    for (U i = 0; i < g_topCount; ++i) if (g_top[i].word[ELimCalls]) ++retainedLim;
    U* w = g_words + LedgerTable;
    w[LTopCapacity] = kTop; w[LEntryWords] = kEntryWords;
    w[LTopOffered] = Sat(g_ledger.offered); w[LTopRetained] = g_topCount;
    w[LTopRejected] = Sat(g_ledger.rejected); w[LTopEvicted] = Sat(g_ledger.evicted);
    w[LLimTicks] = Sat(g_ledger.limTicks); w[LLimTicksRetained] = retainedLim;
    w[LLimTicksOmitted] = Sat(g_ledger.limTicks - retainedLim);
    w[LSinkCalls] = Sat(g_ledger.sinkCalls); w[LSinkFolded] = Sat(g_ledger.sinkFolded);
    w[LSinkAborted] = Sat(g_ledger.sinkAborted); w[LSinkOutside] = Sat(g_ledger.sinkOutside);
    w[LAbortedTicks] = Sat(g_ledger.abortedTicks); w[LAbortedLimUs] = Us(g_ledger.abortedLimQ);
    w[LAbortedFormCalls] = Sat(g_ledger.abortedFormCalls);
    w[LQueueCalls] = Sat(g_ledger.queueCalls); w[LQueueFolded] = Sat(g_ledger.queueFolded);
    w[LQueueAborted] = Sat(g_ledger.queueAborted); w[LQueueOutside] = Sat(g_ledger.queueOutside);
    w[LAbortedQueueUs] = Us(g_ledger.abortedQueueQ);
    w[LRouteBegun] = Sat(g_ledger.routeBegun); w[LRouteFolded] = Sat(g_ledger.routeFolded);
    w[LRouteAborted] = Sat(g_ledger.routeAborted); w[LRouteDiscarded] = Sat(g_ledger.routeDiscarded);
    w[LRouteRefusedScope] = Sat(g_ledger.routeRefusedScope); w[LRouteRefusedDepth] = Sat(g_ledger.routeRefusedDepth);
    w[LRouteUnscopedGates] = Sat(g_ledger.routeUnscoped); w[LAbortedRouteUs] = Us(g_ledger.abortedRouteQ);
}
// Cheap live update used on every observation (no row scan): only the monotonically growing received/outside counters; the
// disposition words (folded/aborted) and the rest of the ledger are published at tick close / abort, so pending stays derivable.
void PublishLedgerLive() {
    U* w = g_words + LedgerTable;
    w[LSinkCalls] = Sat(g_ledger.sinkCalls); w[LSinkOutside] = Sat(g_ledger.sinkOutside);
    w[LQueueCalls] = Sat(g_ledger.queueCalls); w[LQueueOutside] = Sat(g_ledger.queueOutside);
    w[LRouteBegun] = Sat(g_ledger.routeBegun); w[LRouteDiscarded] = Sat(g_ledger.routeDiscarded);
}
// Cumulative class x slot table, published at tick close / abort.
void PublishQueueTable() {
    U* w = g_words + QueueTable;
    w[QOverflowCalls] = Sat(g_qOverflowCalls); w[QOverflowUs] = Us(g_qOverflowQ);
    for (U i = 0; i < kQueueClasses; ++i) {
        U* c = w + QClassBase + i * QClassWords;
        if (i < g_qclsCount) {
            c[QVtable] = g_qcls[i].vtable; c[QSlot] = g_qcls[i].slot; c[QCalls] = Sat(g_qcls[i].calls);
            c[QUs] = Us(g_qcls[i].q); c[QMaxUs] = Us(g_qcls[i].maxQ);
        } else memset(c, 0, QClassWords * sizeof(U));
    }
}
// Cumulative route table, published at tick close / abort (and by Start/Reset for the armed word).
void PublishRouteTable() {
    U* w = g_words + RouteTable;
    w[RArmed] = Armed() ? 1u : 0u;
    w[RCalls] = Sat(g_routeAgg.calls); w[RUs] = Us(g_routeAgg.q); w[RMaxUs] = Us(g_routeAgg.maxQ);
    w[RNoEnterCalls] = Sat(g_routeAgg.noEnterCalls);
    NestWords(w + REnterCalls, g_routeAgg.n);
    SplitWords(w + RAssignScopeUs, g_routeAgg.n);
}
// Per-invocation state = everything TickEnd folds and clears: formation accumulators/bracket, the limited accumulator, the queue
// accumulator and the routed-callback accumulator (routed callbacks and in-flight scopes of a discarded invocation are accounted
// as route_aborted / route_discarded). Cumulative state (aggregates, top rows, ledger, callee table, observer reads, class and
// route tables) is never touched here.
void DiscardInvocation() {
    g_ledger.routeAborted += g_route.calls; g_ledger.abortedRouteQ += g_route.q;
    DropScopes();
    memset(&g_t, 0, sizeof(g_t)); memset(&g_lim, 0, sizeof(g_lim)); memset(&g_que, 0, sizeof(g_que)); memset(&g_route, 0, sizeof(g_route));
    memset(&g_form, 0, sizeof(g_form)); g_inForm = 0;
}
// Closes an open scope without a TraceTick: the discarded work is accounted in the ledger, never in a row or aggregate.
void AbortScope() {
    ++g_ledger.abortedTicks;
    g_ledger.sinkAborted += g_lim.calls; g_ledger.abortedLimQ += g_lim.q;
    g_ledger.queueAborted += g_que.calls; g_ledger.abortedQueueQ += g_que.q;
    g_ledger.abortedFormCalls += g_t.memberCalls + g_t.loopCalls;
    DiscardInvocation();
    g_open = false;
    PublishLedger();
    PublishQueueTable();
    PublishRouteTable();
}

// Queue port begin hook (runs before the callback's first QPC read, adds no QPC): accept the private route only inside an open
// invocation of the calling thread with a free scope slot; a refusal runs the native callback and is counted, never silent.
bool BeginRouted(U, U, U frame) {
    if (!Armed()) return false;
    if (!g_open || g_ownerTid != GetCurrentThreadId()) { ++g_ledger.routeRefusedScope; return false; }
    PopStale(frame);
    if (g_depth == kRouteDepth) { ++g_ledger.routeRefusedDepth; return false; }
    Scope& s = g_scopes[g_depth++];
    memset(&s, 0, sizeof(s));
    s.frame = frame;
    ++g_ledger.routeBegun;
    return true;
}
// One command callback returned normally (queue port end hook, or the public unrouted NoteQueueCommand with routed == false).
void QueueObserved(U vtable, U slot, u64 q, bool routed, U frame) {
    if (!g_enabled) return;
    NoteReads(2); // the queue port's two QPC reads around the callback
    ++g_ledger.queueCalls;
    QueueClassRecord(vtable, slot, q); // cumulative: includes calls of invocations that are later aborted
    Nest nest = {};
    bool scoped = false;
    if (routed) {
        // Scopes deeper than this callback's own dispatch frame belong to inner callbacks that unwound by exception.
        while (g_depth && g_scopes[g_depth - 1].frame < frame) { --g_depth; ++g_ledger.routeDiscarded; }
        if (g_depth && g_scopes[g_depth - 1].frame == frame) { nest = g_scopes[--g_depth].n; scoped = true; }
    }
    if (!g_open || g_ownerTid != GetCurrentThreadId()) {
        ++g_ledger.queueOutside;
        if (scoped) ++g_ledger.routeDiscarded;
        PublishLedgerLive();
        return;
    }
    ++g_que.calls; g_que.q += q;
    if (g_que.calls == 1 || q > g_que.slowQ) { g_que.slowVtable = vtable; g_que.slowSlot = slot; g_que.slowQ = q; g_que.slowRouted = scoped; }
    if (scoped) {
        ++g_route.calls; g_route.q += q; AddNest(g_route.n, nest);
        if (g_route.calls == 1 || q > g_route.slowQ) { g_route.slowVtable = vtable; g_route.slowSlot = slot; g_route.slowQ = q; g_route.slowN = nest; }
        ++g_routeAgg.calls; g_routeAgg.q += q; AddNest(g_routeAgg.n, nest);
        if (q > g_routeAgg.maxQ) g_routeAgg.maxQ = q;
        if (!nest.enterCalls) ++g_routeAgg.noEnterCalls;
    }
    PublishLedgerLive(); // pending (open-invocation) calls are visible live through queue_calls - folded - aborted - outside
}
void QueueEnd(U vtable, U slot, unsigned long long qpcTicks, bool routed, U frame) { QueueObserved(vtable, slot, qpcTicks, routed, frame); }
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
    bindings[KNTWR_BIND_CMD_ENTER] = FnAddress(reinterpret_cast<const void*>(&GateEnter));
    bindings[KNTWR_BIND_CMD_ASSIGN] = FnAddress(reinterpret_cast<const void*>(&GateAssign));
    bindings[KNTWR_BIND_CMD_PERMAN] = FnAddress(reinterpret_cast<const void*>(&GatePerMan));
}

bool Start(U cloneFormUpdate, U cloneCmd581CA0, U cloneCmd4F84C0) {
    Stop();
    QueryPerformanceFrequency(&g_frequency);
    g_cloneForm = cloneFormUpdate;
    g_cmd581CA0 = cloneCmd581CA0; g_cmd4F84C0 = cloneCmd4F84C0;
    Reset();
    // Calibrate the per-read QPC cost (16.16 QPC ticks): one read, then 4096 reads; the loop body is negligible next to QPC.
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    for (U i = 0; i < 4096; ++i) QueryPerformanceCounter(&b);
    const u64 span = static_cast<u64>(b.QuadPart - a.QuadPart);
    g_readCostQ16 = static_cast<U>((span << 16) / 4096);
    g_enabled = true;
    g_words[Version] = kVersion; g_words[Enabled] = 1; g_words[QpcReadCostQ16] = g_readCostQ16;
    PublishRouteTable();
    return true;
}
void Stop() {
    DropScopes();
    g_enabled = false; g_cloneForm = 0; g_cmd581CA0 = g_cmd4F84C0 = 0; g_inForm = 0; g_open = false;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    memset(&g_t, 0, sizeof(g_t)); memset(g_agg, 0, sizeof(g_agg)); memset(g_top, 0, sizeof(g_top));
    memset(&g_lim, 0, sizeof(g_lim)); memset(g_limAgg, 0, sizeof(g_limAgg)); memset(&g_ledger, 0, sizeof(g_ledger));
    memset(&g_form, 0, sizeof(g_form)); memset(g_callees, 0, sizeof(g_callees));
    g_ticks = g_stormTicks = g_topCount = g_calleeCount = g_calleeOverflow = g_outside = 0;
    g_obsReads = 0; g_inForm = 0; g_open = false; g_ownerTid = 0;
    memset(&g_que, 0, sizeof(g_que)); memset(g_qcls, 0, sizeof(g_qcls)); g_qclsCount = 0; g_qOverflowCalls = g_qOverflowQ = 0;
    memset(&g_route, 0, sizeof(g_route)); memset(&g_routeAgg, 0, sizeof(g_routeAgg)); memset(g_scopes, 0, sizeof(g_scopes)); g_depth = 0;
    if (g_enabled) { g_words[Version] = kVersion; g_words[Enabled] = 1; g_words[QpcReadCostQ16] = g_readCostQ16; PublishRouteTable(); }
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

void TickEnd(U tick, U site18Us, bool storm, u64 qpcStart, U tickUs) {
    // Only the thread that opened the still-open scope may close it: anything else is ignored before any state is touched.
    if (!g_enabled || !g_open || g_ownerTid != GetCurrentThreadId()) return;
    Counts& t = g_t;
    ++g_ticks;
    const bool formCalls = t.memberCalls || t.loopCalls;
    if (formCalls) {
        Counts& a = g_agg[storm ? 0 : 1];
        a.forms += t.forms; a.formQ += t.formQ; a.membersSum += t.membersSum; a.ge1ms += t.ge1ms;
        if (t.maxFormQ > a.maxFormQ || (t.maxFormQ == a.maxFormQ && t.maxFormMembers > a.maxFormMembers)) {
            a.maxFormQ = t.maxFormQ; a.maxFormMembers = t.maxFormMembers; a.maxFormGateQ = t.maxFormGateQ; // gate sum belongs to the winning form
        }
        a.loop1Q += t.loop1Q; a.loop2Q += t.loop2Q; a.loopCalls += t.loopCalls; a.memberCalls += t.memberCalls;
        for (U i = 0; i < kGates; ++i) { a.gateQ[i] += t.gateQ[i]; a.gateCalls[i] += t.gateCalls[i]; }
        a.r1Q += t.r1Q; a.r1bQ += t.r1bQ; a.r2Q += t.r2Q; a.queueR2Q += t.queueR2Q;
    }
    // Limited solves are folded for every closed tick (storm or calm), with or without formation calls.
    const Lim lim = g_lim;
    if (lim.calls) {
        LimAgg& l = g_limAgg[storm ? 0 : 1];
        ++l.ticks; l.calls += lim.calls; l.q += lim.q;
        if (lim.maxCallQ > l.maxCallQ) l.maxCallQ = lim.maxCallQ;
        if (lim.q > l.maxTickQ) l.maxTickQ = lim.q;
        if (!formCalls) { ++l.onlyTicks; l.onlyCalls += lim.calls; l.onlyQ += lim.q; }
        ++g_ledger.limTicks;
    }
    g_ledger.sinkFolded += lim.calls;
    memset(&g_lim, 0, sizeof(g_lim));
    const Que que = g_que; // per-invocation queue commands: folded into the row (storm) and the ledger, then cleared
    g_ledger.queueFolded += que.calls;
    memset(&g_que, 0, sizeof(g_que));
    const Route route = g_route; // per-invocation routed callbacks, folded the same way
    g_ledger.routeFolded += route.calls;
    memset(&g_route, 0, sizeof(g_route));
    DropScopes(); // an in-flight scope cannot outlive its invocation
    if (storm) {
        ++g_stormTicks;
        ++g_ledger.offered;
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
        w[EQpcStartLo] = static_cast<U>(qpcStart); w[EQpcStartHi] = static_cast<U>(qpcStart >> 32);
        w[ETickUs] = tickUs;
        w[ELimCalls] = Sat(lim.calls); w[ELimUs] = Us(lim.q); w[ELimMaxUs] = Us(lim.maxCallQ);
        w[EFlags] = (lim.calls ? EFlagLimited : 0u) | (lim.calls && !formCalls ? EFlagLimitedOnly : 0u) |
                    (que.calls && que.slowRouted ? EFlagSlowRouted : 0u);
        w[EQueueCmdCalls] = Sat(que.calls); w[EQueueCmdUs] = Us(que.q);
        if (que.calls) { w[ESlowVtable] = que.slowVtable; w[ESlowSlot] = que.slowSlot; w[ESlowUs] = Us(que.slowQ); }
        w[ERouteCalls] = Sat(route.calls); w[ERouteUs] = Us(route.q);
        NestWords(&w[ERouteEnterCalls], route.n);
        SplitWords(&w[ERouteAssignScopeUs], route.n);
        if (route.calls) {
            w[ERouteSlowVtable] = route.slowVtable; w[ERouteSlowSlot] = route.slowSlot; w[ERouteSlowUs] = Us(route.slowQ);
            NestWords(&w[ERouteSlowEnterCalls], route.slowN);
            SplitWords(&w[ERouteSlowAssignScopeUs], route.slowN);
        }
        U slot = g_topCount;
        bool evict = false;
        if (g_topCount < kTop) ++g_topCount;
        else {
            slot = 0;
            for (U i = 1; i < kTop; ++i) if (g_top[i].word[ESite18Us] < g_top[slot].word[ESite18Us]) slot = i;
            if (g_top[slot].word[ESite18Us] >= site18Us) slot = kTop; // not larger than the smallest kept
            else evict = true;
        }
        if (slot < kTop) { g_top[slot] = e; if (evict) ++g_ledger.evicted; }
        else ++g_ledger.rejected;
    }
    g_words[Ticks] = g_ticks; g_words[StormTicks] = g_stormTicks;
    g_words[MemberCalls] = Sat(g_agg[0].memberCalls + g_agg[1].memberCalls); // t is already folded into g_agg above
    g_words[OtherForms] = Sat(g_agg[0].memberCalls + g_agg[1].memberCalls - (g_agg[0].forms + g_agg[1].forms));
    g_words[ObserverUs] = Us((g_obsReads * g_readCostQ16) >> 16);
    g_words[GateOutside] = g_outside; g_words[CalleeOverflow] = g_calleeOverflow;
    PublishCallees();
    PublishAggregate(StormAggregate, g_agg[0], g_limAgg[0]); PublishAggregate(CalmAggregate, g_agg[1], g_limAgg[1]);
    PublishTop();
    PublishLedger();
    PublishQueueTable();
    PublishRouteTable();
    memset(&t, 0, sizeof(t));
    g_open = false; // the invocation closed normally; nothing carries over
}

void TickBegin() {
    if (!g_enabled) return;
    if (g_open) {
        if (g_ownerTid != GetCurrentThreadId()) return; // a foreign thread can neither abort nor take over the owner's open scope
        AbortScope(); // the owner's own scope never closed: account and discard it so it cannot bleed into this invocation
    }
    g_ledger.abortedFormCalls += g_t.memberCalls + g_t.loopCalls; // formation work accumulated outside any scope is discarded, but counted
    DiscardInvocation();
    kntwr_army_solver::CensusProbeReset(); // owner thread, outside any routed assignment: clears a depth leaked by an abnormal unwind
    g_open = true; g_ownerTid = GetCurrentThreadId();
}

void TickAbort() {
    if (!g_enabled || !g_open || g_ownerTid != GetCurrentThreadId()) return; // only the owner of the open scope may abort it
    AbortScope();
}

void NoteLimitedSolve(unsigned long long qpcTicks) {
    if (!g_enabled) return;
    NoteReads(2); // the solver gate's two QPC reads around the limited native call
    ++g_ledger.sinkCalls;
    if (!g_open || g_ownerTid != GetCurrentThreadId()) { ++g_ledger.sinkOutside; PublishLedgerLive(); return; } // not inside an open owner invocation: counted, never folded
    ++g_lim.calls; g_lim.q += qpcTicks;
    if (qpcTicks > g_lim.maxCallQ) g_lim.maxCallQ = qpcTicks;
    PublishLedgerLive(); // pending (open-invocation) calls are visible live through sink_calls - folded - aborted - outside
}

void NoteQueueCommand(U vtable, U slot, unsigned long long qpcTicks) { QueueObserved(vtable, slot, qpcTicks, false, 0); }

void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
} // namespace kntwr_form_residual
