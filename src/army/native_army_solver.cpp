// Bit-exact memoised flag=1 slot solver, runtime side (native_army_solver.h). Owner-thread only; writes only its own row and the entries /
// allocator state the kernel replicates (ntw_solver).
#include "native_army_solver.h"
#include "formation/native_formation_solver.h"
#include "clones/kntwr_clones.h"
#include "core/kntwr_entry_patch.h"
#include <windows.h>
#include <intrin.h>
#include <string.h>

namespace kntwr_army_solver {
namespace {
using u64 = unsigned long long;
using ntw_solver::Entry12;
constexpr U kZeroBits = 0x00000000u, kOneBits = 0x3F800000u, kPairWeightBits = 0x3F000000u; // [131A7A4] [1318048] [1318038] (image bytes, verified at Start)
constexpr U kMaxFormations = 256;                 // distinct formations tracked per tick (the count saturates)
constexpr U kMembersOffset = 0x18;                // F+0x18: member count ([proven by disasm] 5373F0 `cmp [ebx+18],0`)
using NativeSolve = U (__fastcall*)(const float* ctx, void* edx, Entry12* begin, Entry12* end, U limit, float thr);
using NativeCacheAssign = U (__fastcall*)(void* cache, void* edx, U slots, U flag, U entries);
using NativeFormation = void* (__fastcall*)(void* cache, void* edx);

bool g_started;
Mode g_mode;
U g_delta, g_nativeSolve, g_nativeAssign, g_cloneAssign, g_cacheCloneAssign;
LimitedSink g_limitedSink;   // nullable: set from Binding::limitedSink at Start, cleared at Stop
ntw_solver::Workspace* g_ws;
ntw_solver::Env g_env;
LARGE_INTEGER g_frequency;
u64 g_tscPerSecond;      // rdtsc ticks per second, calibrated against QPC at Start
U g_ownerTid, g_assignDepth, g_curFormation, g_curMembers;
enum class Origin : U { Ordinary, Cache, Command };
Origin g_origin;
volatile U g_shimExpected, g_shimSuppressed, g_shimForwarded, g_viaShim;
// Command route (57B021 rewrite): the gate's operands are plain 32-bit words so the naked gate can read them without a frame.
volatile U g_commandClone;     // CLONE_SOLVER_555CA0 entry; 0 = the gate runs the native 555CA0 (set LAST at install, cleared FIRST at stop)
volatile U g_commandNative;    // V(0x555CA0)
volatile U g_tickOwnerPtr, g_epochMaskPtr, g_routedMask;
volatile U g_pendingCommand;   // set by the gate on the tick owner right before the clone chain, consumed by AssignGate (555CEB)
volatile U g_cmdGateNative;    // gate entries that ran the native 555CA0
volatile LONG g_cmdInstalled;
U g_cmdSite;
unsigned char g_cmdPatch[8];
volatile U g_gateAddress;
Entry12 g_shadowCopy[ntw_solver::kMaxM];

struct Totals {
    u64 ticks, seen, flag1, kernel, flag0, foreign, fallback[8], compares, mismatchSolves, mismatchEntries, mismatchEax, assignCalls,
        r1, r1b, r2, nativeQ, kernelQ, evals, distinct, iterations, swaps, removals, observerQ, membersSum, hist[6],
        scans, gatherQ, profN, profCostQ, profLoopQ, profTotalQ, direct, empty, cacheAssignCalls, cacheSolvedKernel, cmdAssignCalls, cmdSolvedKernel;   // gather/cost/loop/total are raw rdtsc ticks
    u64 limitedQ, assignScopeQ, assignScopeCalls;   // census-only (CensusSnapshot): armed only under a limitedSink / CensusProbeEnter
    U maxM, maxMembers;
};
struct TickAcc {
    u64 solves, nativeQ, kernelQ, evals, distinct, iterations, swaps, solvedKernel, fallbacks;
    U maxM, formationCount, solveFormationCount;   // formationCount: distinct formations passing 555CEB (assign); solveFormationCount: distinct formations among the flag=1 solves
    U formations[kMaxFormations], solveFormations[kMaxFormations];
};
struct SolveRec { U tick, formation, m, evals, distinct, iterations, swaps, flags, members, eax, scans; u64 nativeQ, kernelQ, costQ, loopQ, key; };
struct TickRec { U tick, solves, formations, assignFormations, evals, distinct, iterations, maxM, solvedKernel, fallbacks, swaps; u64 nativeQ, kernelQ, key; };
Totals g_total;
TickAcc g_tick;
SolveRec g_curSolves[kTop];  U g_curCount;   // top solves of the open tick (tick id assigned at TickEnd)
SolveRec g_topSolves[kTop];  U g_topSolveCount;
TickRec g_topTicks[kTop];    U g_topTickCount;

__declspec(thread) U t_censusProbe;   // calling thread's CensusProbeEnter depth; non-zero only inside the residual's routed GateAssign (census)
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
U Sat(u64 v) { return v > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(v); }
U Us(u64 q) { return g_frequency.QuadPart ? Sat(q * 1000000ull / static_cast<u64>(g_frequency.QuadPart)) : 0; }
// rdtsc ticks -> us with the rate QPC-calibrated at Start (the kernel reports raw TSC ticks).
U TscUs(u64 ticks) { return g_tscPerSecond ? Sat(static_cast<u64>(static_cast<double>(ticks) * 1.0e6 / static_cast<double>(g_tscPerSecond))) : 0; }
U Bits(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
U V(U preferred) { return preferred + g_delta; }
U FnAddress(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }

template <class T> void InsertTop(T* table, U& count, const T& rec) {
    U at = count;
    if (count < kTop) ++count;
    else if (table[kTop - 1].key >= rec.key) return;
    else at = kTop - 1;
    while (at > 0 && table[at - 1].key < rec.key) { table[at] = table[at - 1]; --at; }
    table[at] = rec;
}
U Bucket(U m) { return m <= 16 ? 0 : m <= 64 ? 1 : m <= 128 ? 2 : m <= 256 ? 3 : m <= 512 ? 4 : 5; }
void NoteDistinct(U* list, U& count, U formation) {
    for (U i = 0; i < count && i < kMaxFormations; ++i) if (list[i] == formation) return;
    if (count < kMaxFormations) list[count] = formation;
    ++count; // keeps counting past the table (a saturated tick reports its formation count, not a distinct set)
}
void NoteFormation(U formation) { NoteDistinct(g_tick.formations, g_tick.formationCount, formation); }
// Folds one flag=1 solve into the totals, the tick accumulator and the open tick's top-solve list.
void Record(U m, const ntw_solver::Counters& c, u64 nativeQ, u64 kernelQ, U flags, U eax) {
    if (g_origin == Origin::Cache) {
        flags |= 0x200u;
        if (flags & 2u) ++g_total.cacheSolvedKernel;
    } else if (g_origin == Origin::Command) {
        flags |= 0x400u;
        if (flags & 2u) ++g_total.cmdSolvedKernel;
    }
    g_total.nativeQ += nativeQ; g_total.kernelQ += kernelQ;
    g_total.evals += c.evals; g_total.distinct += c.distinct; g_total.iterations += c.iterations;
    g_total.swaps += c.swaps; g_total.removals += c.removals;
    if (m) ++g_total.hist[Bucket(m)];
    if (m > g_total.maxM) g_total.maxM = m;
    NoteDistinct(g_tick.solveFormations, g_tick.solveFormationCount, g_curFormation);
    ++g_tick.solves; g_tick.nativeQ += nativeQ; g_tick.kernelQ += kernelQ;
    g_tick.evals += c.evals; g_tick.distinct += c.distinct; g_tick.iterations += c.iterations; g_tick.swaps += c.swaps;
    if (flags & 2u) ++g_tick.solvedKernel;
    if (flags & 8u) ++g_tick.fallbacks;
    if (m > g_tick.maxM) g_tick.maxM = m;
    // Kernel phases (default kSimd policy; the table fill is INCLUDED in loopTicks): cost phase = gather + table fill, loop phase = the rest of the loop.
    const u64 costQ = c.gatherTicks + c.fillTicks, loopQ = c.loopTicks > c.fillTicks ? c.loopTicks - c.fillTicks : 0;
    if ((flags & 2u) || (flags & 4u)) { // the kernel produced a result
        g_total.scans += c.scans; g_total.gatherQ += c.gatherTicks;
        ++g_total.profN; g_total.profCostQ += costQ; g_total.profLoopQ += loopQ; g_total.profTotalQ += c.totalTicks;
    }
    SolveRec r = {};
    r.formation = g_curFormation; r.m = m; r.evals = c.evals; r.distinct = c.distinct; r.iterations = c.iterations; r.swaps = c.swaps;
    r.flags = flags; r.members = g_curMembers; r.eax = eax; r.nativeQ = nativeQ; r.kernelQ = kernelQ;
    r.scans = ((flags & 6u) ? c.scans : 0);
    if (flags & 6u) { r.costQ = costQ; r.loopQ = loopQ; }
    r.key = (nativeQ ? nativeQ : kernelQ) | ((flags & 0x100u) ? (1ull << 63) : 0);
    InsertTop(g_curSolves, g_curCount, r);
}
void CountFallback(U reason) {
    if (reason >= 1 && reason <= 7) ++g_total.fallback[reason];
}
// The single exact native call of an eligible limited (limit != 0) solve. With a sink bound (storm census wired) it is timed with
// two local QPC reads and the elapsed QPC ticks are handed to the sink; without one it is the plain forward. Same arguments, same
// EAX; the time never enters Record / nativeQ / kernelQ or any other solver table.
U NativeLimited(NativeSolve native, const float* ctx, void* edx, Entry12* begin, Entry12* end, U limit, float thr) {
    const LimitedSink sink = g_limitedSink;
    if (!sink) return native(ctx, edx, begin, end, limit, thr);
    const LONGLONG t0 = Now();
    const U eax = native(ctx, edx, begin, end, limit, thr);
    const LONGLONG t1 = Now();
    g_total.limitedQ += static_cast<u64>(t1 - t0); // census-only: reached only with a bound sink
    sink(static_cast<u64>(t1 - t0));
    return eax;
}
} // namespace

// ---- host gates (bound into the SOLVER clones)
// 18F12AA / the shim's tail jump: the 0x502770 call (thiscall ECX = ctx, four stack arguments, ret 0x10, EAX = (iterations & ~0xFF) | done).
U __fastcall SolveGate(const float* ctx, void* edx, Entry12* begin, Entry12* end, U limit, float thr) {
    const NativeSolve native = reinterpret_cast<NativeSolve>(g_nativeSolve);
    const bool viaShim = g_viaShim != 0; // set by SolveShim's forward path just before it jumps here; 18F12AA's direct call leaves it clear
    g_viaShim = 0;
    if (!g_started || !g_assignDepth || GetCurrentThreadId() != g_ownerTid) {
        if (g_started) ++g_total.foreign;
        return native(ctx, edx, begin, end, limit, thr);
    }
    ++g_total.seen;
    if (!viaShim) ++g_total.direct;
    if (g_mode == ModeForward) { if (limit != 0) { ++g_total.flag0; return NativeLimited(native, ctx, edx, begin, end, limit, thr); } ++g_total.flag1; return native(ctx, edx, begin, end, limit, thr); } // oracle only: chain + shim live, every solve native
    if (limit != 0) { ++g_total.flag0; return NativeLimited(native, ctx, edx, begin, end, limit, thr); }
    ++g_total.flag1;
    if (begin == end) { ++g_total.empty; return native(ctx, edx, begin, end, limit, thr); } // empty range (data may be null): nothing to solve, no kernel call
    const uintptr_t b = reinterpret_cast<uintptr_t>(begin), e = reinterpret_cast<uintptr_t>(end);
    const bool rangeOk = e >= b && (e - b) % sizeof(Entry12) == 0;
    const U m = rangeOk ? static_cast<U>((e - b) / sizeof(Entry12)) : 0;
    ntw_solver::Counters c = {};
    c.profile = 0; // census mode forces the scalar loop; shadow and memo both run the shipping (kSimd) path, so distinct stays 0 (evals/scans/swaps/iterations are native-exact)
    c.telemetry = g_limitedSink ? 1u : 0u; // exact packed-loop evals/scans only when the storm census is wired; default ships the fast loop (both read 0)
    if (!rangeOk || m > ntw_solver::kMaxM) { // out of the kernel contract before any work: the native solver runs, counted
        c.fallback = rangeOk ? ntw_solver::kReasonTooLarge : ntw_solver::kReasonRange;
        CountFallback(c.fallback);
        const LONGLONG t0 = Now();
        const U eax = native(ctx, edx, begin, end, limit, thr);
        const u64 q = static_cast<u64>(Now() - t0);
        Record(m, c, q, 0, 1u | 8u | (c.fallback << 4), eax);
        return eax;
    }
    if (g_mode == ModeShadow) {
        const LONGLONG t0 = Now();
        memcpy(g_shadowCopy, begin, static_cast<size_t>(m) * sizeof(Entry12));
        const LONGLONG t1 = Now();
        const U eax = native(ctx, edx, begin, end, limit, thr);   // authoritative
        const LONGLONG t2 = Now();
        U kernelEax = 0;
        const ntw_solver::Outcome out = ntw_solver::SolveCopy(*g_ws, g_env, ctx, g_shadowCopy, g_shadowCopy + m, limit, thr, &kernelEax, &c);
        const LONGLONG t3 = Now();
        U flags = 1u | 4u;
        U mismatchEntries = 0;
        if (out != ntw_solver::kSolved) {
            flags = 1u | 8u | (c.fallback << 4);
            CountFallback(c.fallback);
        } else {
            ++g_total.compares;
            for (U i = 0; i < m; ++i)
                if (memcmp(&g_shadowCopy[i], &begin[i], sizeof(Entry12)) != 0) ++mismatchEntries;
            const bool eaxDiffers = kernelEax != eax;
            if (mismatchEntries || eaxDiffers) {
                flags |= 0x100u;
                ++g_total.mismatchSolves;
                g_total.mismatchEntries += mismatchEntries;
                if (eaxDiffers) ++g_total.mismatchEax;
            }
        }
        const LONGLONG t4 = Now();
        g_total.observerQ += static_cast<u64>((t1 - t0) + (t4 - t3));
        Record(m, c, static_cast<u64>(t2 - t1), static_cast<u64>(t3 - t2), flags, eax);
        return eax;
    }
    // memo: the kernel replaces the native solver; kFallback wrote nothing, so the native solver runs on pristine state
    U eax = 0;
    const LONGLONG t0 = Now();
    const ntw_solver::Outcome out = ntw_solver::Solve(*g_ws, g_env, ctx, begin, end, limit, thr, &eax, &c);
    const LONGLONG t1 = Now();
    if (out == ntw_solver::kSolved) {
        ++g_total.kernel;
        Record(m, c, 0, static_cast<u64>(t1 - t0), 1u | 2u, eax);
        return eax;
    }
    CountFallback(c.fallback);
    const LONGLONG t2 = Now();
    eax = native(ctx, edx, begin, end, limit, thr);
    const LONGLONG t3 = Now();
    Record(m, c, static_cast<u64>(t3 - t2), static_cast<u64>(t1 - t0), 1u | 8u | (c.fallback << 4), eax);
    return eax;
}
// Common assignment scope: both the ordinary 555CEB route and the formerly native cache assignment use the same solver gates.
U RunAssign(void* formation, void* edx, U a1, U a2, U a3, U a4, U target, Origin origin) {
    const U f = static_cast<U>(reinterpret_cast<uintptr_t>(formation));
    const U members = Bits(f + kMembersOffset);
    ++g_total.assignCalls; g_total.membersSum += members;
    if (origin == Origin::Cache) ++g_total.cacheAssignCalls;
    else if (origin == Origin::Command) ++g_total.cmdAssignCalls;
    if (members > g_total.maxMembers) g_total.maxMembers = members;
    NoteFormation(f);
    const U savedFormation = g_curFormation, savedMembers = g_curMembers;
    const Origin savedOrigin = g_origin;
    g_origin = origin;
    const bool censusTimed = t_censusProbe && !g_assignDepth; // census only: outermost scope inside the routed GateAssign (default: one TLS load + test, no QPC)
    if (!g_assignDepth++) g_ownerTid = GetCurrentThreadId();
    g_curFormation = f; g_curMembers = members;
    const LONGLONG scopeT0 = censusTimed ? Now() : 0;
    const U r = reinterpret_cast<NativeAssign>(target)(formation, edx, a1, a2, a3, a4);
    if (censusTimed) { g_total.assignScopeQ += static_cast<u64>(Now() - scopeT0); ++g_total.assignScopeCalls; }
    if (g_assignDepth) --g_assignDepth; // saturates: Stop()/Reset() may have cleared the depth while the occurrence was live
    g_curFormation = savedFormation; g_curMembers = savedMembers;
    g_origin = savedOrigin;
    return r;
}
// 555CEB: ECX = formation, four stack arguments, ret 0x10.
U __fastcall AssignGate(void* formation, void* edx, U a1, U a2, U a3, U a4) {
    const bool command = g_pendingCommand != 0;   // set by CommandAssignGate on this thread for exactly the 555CA0 that is entered next
    g_pendingCommand = 0;
    if (!g_started) return reinterpret_cast<NativeAssign>(g_nativeAssign)(formation, edx, a1, a2, a3, a4);
    return RunAssign(formation, edx, a1, a2, a3, a4, g_cloneAssign, command ? Origin::Command : Origin::Ordinary);
}
// 57AC3B: replay the fully pinned 539C90 wrapper. Run 15 selects its stock 5373F0 or overlaid 18F0A00 target.
// Keep the native 4B4A50 call and argument order; neither the cache vector nor its allocation/free lifetime is changed here.
U __fastcall CacheAssignGate(void* cache, void* edx, U slots, U flag, U entries) {
    if (!g_started) return reinterpret_cast<NativeCacheAssign>(V(0x539C90))(cache, edx, slots, flag, entries);
    void* formation = reinterpret_cast<NativeFormation>(V(0x4B4A50))(cache, edx);
    return RunAssign(formation, edx, slots, flag, entries, 0xFFFFFFFFu, g_cacheCloneAssign, Origin::Cache);
}
// 53765A: the call of the .aistbl trampoline 18F0D00, replayed instruction for instruction (same pushes, same frame offsets); only the
// compared return address differs: the SOLVER_18F0A00 clone's. Suppression returns with EAX and EFLAGS restored; otherwise the registers,
// flags and stack are exactly what the native `jmp 0x502770` leaves, and control passes to SolveGate.
__declspec(naked) void SolveShim() {
    __asm {
        pushfd
        push eax
        mov eax, dword ptr [g_shimExpected]
        cmp dword ptr [esp + 0x58], eax
        jne forward
        mov eax, dword ptr [esp + 0x24]
        cmp dword ptr [eax - 8], 1
        jne forward
        inc dword ptr [g_shimSuppressed]
        pop eax
        popfd
        ret 0x10
    forward:
        inc dword ptr [g_shimForwarded]
        mov dword ptr [g_viaShim], 1
        pop eax
        popfd
        jmp dword ptr [g_gateAddress]
    }
}

// 57B021 (rewritten call site inside the native 57B000): ECX = formation, five stack arguments (a0, a1, float, flag, -1), ret 0x14 to 57B026.
// Registers, flags and arguments are untouched on both paths: the gate only tail-jumps. Tick owner inside a routed epoch (the SolverEpoch test,
// supplied by the runtime) -> CLONE_SOLVER_555CA0 (its 555CEB AssignGate consumes g_pendingCommand); any other thread or epoch -> native 555CA0.
__declspec(naked) void CommandAssignGate() {
    __asm {
        cmp dword ptr [g_commandClone], 0
        je native
        push eax
        push edx
        mov eax, dword ptr [g_tickOwnerPtr]
        mov edx, dword ptr fs:[0x24]
        cmp edx, dword ptr [eax]
        jne foreign
        mov eax, dword ptr [g_epochMaskPtr]
        mov eax, dword ptr [eax]
        test eax, dword ptr [g_routedMask]
        jz foreign
        mov dword ptr [g_pendingCommand], 1
        pop edx
        pop eax
        jmp dword ptr [g_commandClone]
    foreign:
        pop edx
        pop eax
        lock inc dword ptr [g_cmdGateNative]
    native:
        jmp dword ptr [g_commandNative]   // 6 bytes: FF 25 <g_commandNative>
        _emit 0x4B                        // tail marker (never executed)
        _emit 0xD1
        _emit 0x92
        _emit 0x6E
        _emit 0x35
        _emit 0xA8
        _emit 0x07
        _emit 0xF2
    }
}

constexpr U kCmdSite = 0x57B021u, kCmdBody = 0x57B000u, kCmdSpan = 5;
constexpr unsigned char kCmdBodyBytes[0x29] = {   // 57B000..57B028: call 4B4A50; movss xmm0,[esp+c]; push -1; push [esp+14]; push ecx; movss [esp],xmm0; mov ecx,eax; push [esp+14] x2; call 555CA0; ret 0x10
    0xE8,0x4B,0x9A,0xF3,0xFF, 0xF3,0x0F,0x10,0x44,0x24,0x0C, 0x6A,0xFF, 0xFF,0x74,0x24,0x14, 0x51,
    0xF3,0x0F,0x11,0x04,0x24, 0x8B,0xC8, 0xFF,0x74,0x24,0x14, 0xFF,0x74,0x24,0x14,
    0xE8,0x7A,0xAC,0xFD,0xFF, 0xC2,0x10,0x00};
constexpr unsigned char kCmdTailMarker[8] = {0x4B,0xD1,0x92,0x6E,0x35,0xA8,0x07,0xF2};

U ResolveThunk(U fn) {
    for (U hop = 0; hop < 4; ++hop) {
        const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(fn));
        if (p[0] != 0xE9) return fn;
        U displacement; memcpy(&displacement, p + 1, 4);
        const U next = fn + 5 + displacement;
        if (next <= fn || next - fn > 0x10000u) return 0;
        fn = next;
    }
    return 0;
}
// [begin, end) = every gate byte a frozen thread could still execute, including the final 6-byte jmp; the marker is accepted only right behind
// `FF 25 &g_commandNative`. begin == 0 on failure.
bool CommandGateRange(U& begin, U& end) {
    begin = end = 0;
    const U gate = ResolveThunk(FnAddress(reinterpret_cast<const void*>(&CommandAssignGate)));
    if (!gate) return false;
    const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(gate));
    const U native = FnAddress(const_cast<const U*>(&g_commandNative));
    for (U offset = 6; offset + 8 <= 160; ++offset) {
        if (memcmp(p + offset, kCmdTailMarker, 8) != 0) continue;
        U target; memcpy(&target, p + offset - 4, 4);
        if (p[offset - 6] != 0xFF || p[offset - 5] != 0x25 || target != native) continue;
        begin = gate; end = gate + offset;
        return true;
    }
    return false;
}
bool BytesAre(U address, const unsigned char* want, U bytes) {
    __try { return memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), want, bytes) == 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Installs `call 555CA0` -> `call CommandAssignGate` at 57B021 (8 bytes swapped atomically; the three bytes of `ret 0x10` are rewritten with themselves).
// Everything is pinned first: the complete 57B000 body (including the call's original rel32, hence its 555CA0 target).
bool InstallCommandRoute(const Binding& b) {
    if (!b.cloneCommandAssign || !b.tickOwner || !b.epochMask || !b.routedMask) return false;
    const U body = V(kCmdBody), site = V(kCmdSite);
    if (!BytesAre(body, kCmdBodyBytes, sizeof(kCmdBodyBytes))) return false;
    U gateBegin, gateEnd;
    if (!CommandGateRange(gateBegin, gateEnd)) return false;
    unsigned char to[8];
    memcpy(to, kCmdBodyBytes + (kCmdSite - kCmdBody), 8);
    to[0] = 0xE8;
    const U rel = gateBegin - (site + 5);
    memcpy(to + 1, &rel, 4);
    memcpy(g_cmdPatch, to, 8);
    g_cmdSite = site;
    g_commandNative = V(0x555CA0);
    g_tickOwnerPtr = static_cast<U>(reinterpret_cast<uintptr_t>(b.tickOwner));
    g_epochMaskPtr = static_cast<U>(reinterpret_cast<uintptr_t>(b.epochMask));
    g_routedMask = b.routedMask;
    g_pendingCommand = 0; g_cmdGateNative = 0;
    const kntwr_entry_patch::Guard drain(gateBegin, gateEnd, nullptr);
    if (!kntwr_entry_patch::Swap8(site, kCmdBodyBytes + (kCmdSite - kCmdBody), to, kCmdSpan, drain, [] { _InterlockedExchange(&g_cmdInstalled, 1); })) return false;
    g_commandClone = b.cloneCommandAssign;   // armed last: until now the patched call ran the native 555CA0
    return true;
}
bool RemoveCommandRoute() {
    g_commandClone = 0;                      // disarmed first: a thread still inside the gate runs the native 555CA0
    if (!_InterlockedCompareExchange(&g_cmdInstalled, 0, 0)) return true;
    U gateBegin, gateEnd;
    if (!CommandGateRange(gateBegin, gateEnd)) return false;
    const kntwr_entry_patch::Guard drain(gateBegin, gateEnd, nullptr);
    return kntwr_entry_patch::Swap8(g_cmdSite, g_cmdPatch, kCmdBodyBytes + (kCmdSite - kCmdBody), kCmdSpan, drain, [] { _InterlockedExchange(&g_cmdInstalled, 0); });
}

void Bind(U delta, uint32_t* bindings) {
    g_delta = delta;
    g_nativeSolve = V(0x502770);
    g_nativeAssign = V(0x18f0a00);
    g_gateAddress = FnAddress(reinterpret_cast<const void*>(&SolveGate));
    bindings[KNTWR_BIND_SOLVER_ASSIGN] = FnAddress(reinterpret_cast<const void*>(&AssignGate));
    bindings[KNTWR_BIND_SOLVER_SOLVE] = g_gateAddress;
    bindings[KNTWR_BIND_SOLVER_SHIM] = FnAddress(reinterpret_cast<const void*>(&SolveShim));
    bindings[KNTWR_BIND_SOLVER_CACHE_ASSIGN] = FnAddress(reinterpret_cast<const void*>(&CacheAssignGate));
}

bool Start(const Binding& binding) {
    if (!Stop()) return false;   // a previous command route that could not be restored stays armed for the retry; never start over it
    if (binding.mode != ModeMemo && binding.mode != ModeShadow && binding.mode != ModeForward) return false; // ModeForward: oracle only (the runtime never passes it)
    g_delta = binding.delta;
    g_mode = binding.mode;
    // The native solver the gates replace/shadow is the original 0x502770 (prologue `mov eax, fs:[2C]`); refuse any other bytes there.
    static const uint8_t prologue[] = { 0x64, 0xA1, 0x2C, 0x00, 0x00, 0x00 };
    if (memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(V(0x502770))), prologue, sizeof(prologue)) != 0) return false;
    if (Bits(V(0x131a7a4)) != kZeroBits || Bits(V(0x1318048)) != kOneBits || Bits(V(0x1318038)) != kPairWeightBits) return false;
    // 539C90 has no relocations. Accept only the complete stock wrapper or its exact run-15 overlay.
    // This check is activation-only: filtered run 15 must not invalidate the always-built clone catalog.
    static const uint8_t cacheStock[] = {
        0xE8,0xBB,0xAD,0xF7,0xFF,0x6A,0xFF,0xFF,0x74,0x24,0x10,0x8B,0xC8,0xFF,0x74,
        0x24,0x10,0xFF,0x74,0x24,0x10,0xE8,0x46,0xD7,0xFF,0xFF,0xC2,0x0C,0x00
    };
    static const uint8_t cacheOverlay[] = {
        0xE8,0xBB,0xAD,0xF7,0xFF,0x6A,0xFF,0xFF,0x74,0x24,0x10,0x8B,0xC8,0xFF,0x74,
        0x24,0x10,0xFF,0x74,0x24,0x10,0xE8,0x56,0x6D,0x3B,0x01,0xC2,0x0C,0x00
    };
    const void* cacheWrapper = reinterpret_cast<const void*>(static_cast<uintptr_t>(V(0x539C90)));
    if (memcmp(cacheWrapper, cacheStock, sizeof(cacheStock)) == 0) g_cacheCloneAssign = binding.cloneStockAssign;
    else if (memcmp(cacheWrapper, cacheOverlay, sizeof(cacheOverlay)) == 0) g_cacheCloneAssign = binding.cloneAssign;
    else return false;
    if (!binding.cloneAssign || !binding.cloneStockAssign) return false;
    g_env = ntw_solver::Env();
    g_env.angleTable = reinterpret_cast<const float*>(static_cast<uintptr_t>(V(0x176cff8)));
    g_env.zero = *reinterpret_cast<const float*>(static_cast<uintptr_t>(V(0x131a7a4)));
    g_env.one = *reinterpret_cast<const float*>(static_cast<uintptr_t>(V(0x1318048)));
    g_env.pairWeight = *reinterpret_cast<const float*>(static_cast<uintptr_t>(V(0x1318038)));
    g_env.pose = reinterpret_cast<const float* (__fastcall*)(void*, void*, float*)>(static_cast<uintptr_t>(V(0x80e9d0)));
    g_env.listGlobal = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(V(0x14a40a4)));
    g_env.alloc = reinterpret_cast<void* (__cdecl*)(uint32_t, uint32_t)>(static_cast<uintptr_t>(V(0x444b40)));
    g_env.release = reinterpret_cast<void (__cdecl*)(void*)>(static_cast<uintptr_t>(V(0xff7ef0)));
    g_env.listGuard = reinterpret_cast<const int32_t*>(static_cast<uintptr_t>(V(0x14a40b0)));
    g_env.tlsIndex = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(V(0x1841bb8)));
    g_ws = ntw_solver::CreateWorkspace();
    if (!g_ws) return false;
    g_cloneAssign = binding.cloneAssign;
    g_limitedSink = binding.limitedSink;
    g_shimExpected = binding.cloneAssign + KNTWR_SOLVER_ASSIGN_RET_OFFSET;
    QueryPerformanceFrequency(&g_frequency);
    { // TSC rate: ~20 ms spin against QPC (the kernel's phase counters are raw rdtsc ticks)
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        const unsigned long long t0 = __rdtsc();
        const LONGLONG span = g_frequency.QuadPart / 50;
        do QueryPerformanceCounter(&b); while (b.QuadPart - a.QuadPart < span);
        const unsigned long long t1 = __rdtsc();
        g_tscPerSecond = static_cast<u64>(static_cast<double>(t1 - t0) * static_cast<double>(g_frequency.QuadPart) / static_cast<double>(b.QuadPart - a.QuadPart));
    }
    Reset();
    g_started = true;
    if (binding.cloneCommandAssign && !InstallCommandRoute(binding)) { Stop(); return false; }
    return true;
}
bool CommandRouteInstalled() { return _InterlockedCompareExchange(&g_cmdInstalled, 0, 0) != 0; }
bool Stop() {
    // Called from StopModules (src/core/kntwr_runtime.cpp), which first waits until tickOwner == 0, so no gate/assign occurrence is live here.
    const bool restored = RemoveCommandRoute();   // first: the native bytes return before the clone chain's gates are retired
    g_started = false;
    g_limitedSink = nullptr;
    if (g_ws) ntw_solver::DestroyWorkspace(g_ws);
    g_ws = nullptr;
    g_assignDepth = 0;
    g_origin = Origin::Ordinary;
    g_cacheCloneAssign = 0;
    g_pendingCommand = 0;
    return restored;
}
void Reset() {
    memset(&g_total, 0, sizeof(g_total));
    memset(&g_tick, 0, sizeof(g_tick));
    memset(g_curSolves, 0, sizeof(g_curSolves)); g_curCount = 0;
    memset(g_topSolves, 0, sizeof(g_topSolves)); g_topSolveCount = 0;
    memset(g_topTicks, 0, sizeof(g_topTicks)); g_topTickCount = 0;
    g_shimSuppressed = g_shimForwarded = g_viaShim = 0;
    g_curFormation = g_curMembers = 0;
    g_origin = Origin::Ordinary;
    g_pendingCommand = 0; g_cmdGateNative = 0;
}
bool Started() { return g_started; }
void ReadCensus(CensusSnapshot* out) {
    const Totals& t = g_total;
    out->assignEntries = t.assignCalls; out->solvesSeen = t.seen; out->solvedKernel = t.kernel; out->flag0Native = t.flag0;
    out->shimSuppressed = g_shimSuppressed; out->kernelQ = t.kernelQ; out->limitedQ = t.limitedQ;
    out->assignScopeQ = t.assignScopeQ; out->assignScopeCalls = t.assignScopeCalls;
}
void CensusProbeEnter() { ++t_censusProbe; }
void CensusProbeLeave() { if (t_censusProbe) --t_censusProbe; }
void CensusProbeReset() { t_censusProbe = 0; }
unsigned long long StorageBytes() { return g_ws ? ntw_solver::WorkspaceBytes() : 0ull; }
void NoteRoute(Route route) {
    if (!g_started) return;
    if (route == RouteR1) ++g_total.r1; else if (route == RouteR1b) ++g_total.r1b; else ++g_total.r2;
}
void TickEnd(U tick) {
    if (!g_started || !g_tick.solves) { if (g_started) { g_curCount = 0; memset(&g_tick, 0, sizeof(g_tick)); } return; }
    ++g_total.ticks;
    for (U i = 0; i < g_curCount; ++i) { g_curSolves[i].tick = tick; InsertTop(g_topSolves, g_topSolveCount, g_curSolves[i]); }
    TickRec r = {};
    r.tick = tick; r.solves = Sat(g_tick.solves); r.formations = g_tick.solveFormationCount; r.assignFormations = g_tick.formationCount; r.evals = Sat(g_tick.evals); r.distinct = Sat(g_tick.distinct);
    r.iterations = Sat(g_tick.iterations); r.maxM = g_tick.maxM; r.solvedKernel = Sat(g_tick.solvedKernel); r.fallbacks = Sat(g_tick.fallbacks);
    r.swaps = Sat(g_tick.swaps); r.nativeQ = g_tick.nativeQ; r.kernelQ = g_tick.kernelQ;
    r.key = g_tick.nativeQ ? g_tick.nativeQ : g_tick.kernelQ;
    InsertTop(g_topTicks, g_topTickCount, r);
    g_curCount = 0;
    memset(&g_tick, 0, sizeof(g_tick));
}
void Snapshot(U* w) {
    memset(w, 0, sizeof(U) * kWords);
    if (!g_started && !g_total.seen && !g_total.assignCalls) return;
    const Totals& t = g_total;
    w[Version] = kVersion; w[WMode] = g_mode; w[WStarted] = g_started ? 1 : 0; w[Ticks] = Sat(t.ticks);
    w[SolvesSeen] = Sat(t.seen); w[SolvesFlag1] = Sat(t.flag1); w[SolvedKernel] = Sat(t.kernel); w[Flag0Native] = Sat(t.flag0);
    w[ForeignNative] = Sat(t.foreign);
    w[FbTooLarge] = Sat(t.fallback[ntw_solver::kReasonTooLarge]); w[FbRange] = Sat(t.fallback[ntw_solver::kReasonRange]);
    w[FbListState] = Sat(t.fallback[ntw_solver::kReasonListState]); w[FbGuard] = Sat(t.fallback[ntw_solver::kReasonGuard]);
    w[FbEnv] = Sat(t.fallback[ntw_solver::kReasonEnv]); w[FbFpEnv] = Sat(t.fallback[ntw_solver::kReasonFpEnv]); w[FbCtx] = Sat(t.fallback[ntw_solver::kReasonCtx]); w[EmptyNative] = Sat(t.empty);
    w[ShadowCompares] = Sat(t.compares); w[ShadowMismatchSolves] = Sat(t.mismatchSolves); w[MismatchEntries] = Sat(t.mismatchEntries);
    w[MismatchEax] = Sat(t.mismatchEax); w[ShimSuppressed] = g_shimSuppressed; w[ShimForwarded] = g_shimForwarded;
    w[AssignCalls] = Sat(t.assignCalls); w[RouteR1Entries] = Sat(t.r1); w[RouteR1bEntries] = Sat(t.r1b); w[RouteR2Entries] = Sat(t.r2);
    w[NativeUs] = Us(t.nativeQ); w[KernelUs] = Us(t.kernelQ);
    w[EvalsLo] = static_cast<U>(t.evals); w[EvalsHi] = static_cast<U>(t.evals >> 32);
    w[DistinctLo] = static_cast<U>(t.distinct); w[DistinctHi] = static_cast<U>(t.distinct >> 32);
    w[IterationsLo] = static_cast<U>(t.iterations); w[IterationsHi] = static_cast<U>(t.iterations >> 32);
    w[Swaps] = Sat(t.swaps); w[Removals] = Sat(t.removals); w[MaxM] = t.maxM; w[MaxFormationMembers] = t.maxMembers;
    for (U i = 0; i < 6; ++i) w[MHist0 + i] = Sat(t.hist[i]);
    w[ObserverUs] = Us(t.observerQ); w[AssignMembersSum] = Sat(t.membersSum);
    w[ScansLo] = static_cast<U>(t.scans); w[ScansHi] = static_cast<U>(t.scans >> 32); w[CostUs] = TscUs(t.profCostQ); w[LoopUs] = TscUs(t.profLoopQ);
    w[TimedSolves] = Sat(t.profN); w[KernelTotalUs] = TscUs(t.profTotalQ); w[GatherUs] = TscUs(t.gatherQ); w[Direct18F12AA] = Sat(t.direct);
    w[CacheAssignCalls] = Sat(t.cacheAssignCalls); w[CacheSolvedKernel] = Sat(t.cacheSolvedKernel);
    w[CmdAssignCalls] = Sat(t.cmdAssignCalls); w[CmdSolvedKernel] = Sat(t.cmdSolvedKernel); w[CmdGateNative] = g_cmdGateNative;
    for (U i = 0; i < g_topTickCount; ++i) {
        const TickRec& r = g_topTicks[i];
        U* e = w + TickTable + i * kTickWords;
        e[TTick] = r.tick; e[TSolves] = r.solves; e[TFormations] = r.formations; e[TAssignFormations] = r.assignFormations; e[TNativeUs] = Us(r.nativeQ); e[TKernelUs] = Us(r.kernelQ);
        e[TEvals] = r.evals; e[TDistinct] = r.distinct; e[TIterations] = r.iterations; e[TMaxM] = r.maxM; e[TSolvedKernel] = r.solvedKernel;
        e[TFallbacks] = r.fallbacks; e[TSwaps] = r.swaps;
    }
    for (U i = 0; i < g_topSolveCount; ++i) {
        const SolveRec& r = g_topSolves[i];
        U* e = w + SolveTable + i * kSolveWords;
        e[STick] = r.tick; e[SFormation] = r.formation; e[SM] = r.m; e[SEvals] = r.evals; e[SDistinct] = r.distinct; e[SIterations] = r.iterations;
        e[SNativeUs] = Us(r.nativeQ); e[SKernelUs] = Us(r.kernelQ); e[SSwaps] = r.swaps; e[SFlags] = r.flags; e[SMembers] = r.members; e[SEax] = r.eax;
        e[SScans] = r.scans; e[SCostUs] = TscUs(r.costQ); e[SLoopUs] = TscUs(r.loopQ);
    }
}
} // namespace kntwr_army_solver
