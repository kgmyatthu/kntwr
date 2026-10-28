#pragma once
#include <stdint.h>

// Bit-exact memoised flag=1 slot solver, runtime side (--army-solver-memo / --army-solver-shadow, kntwr_config::va_watch_flags
// KNTWR_ARMY_SOLVER_MEMO / KNTWR_ARMY_SOLVER_SHADOW). Question: the rare ~1 s site-18 freezes are flag=1 (uncapped) assignment solves of the
// 0x502770 pair-swap solver reached from the R1 FSM state-enter (slots 0x1331E74 -> 0x617510, 0x1332110 -> 0x611CF0) and the R2 per-tick
// execute (slot 0x1325474 -> 0x581AE0) of the class-1325470 assignment command (analysis/native-army-storm-census.md, analysis/army-storm-route-decode.md).
//
// Route (runtime host data only; the executable is never modified): inside a routed tick on the tick owner the three route slots run a
// DEDICATED clone chain (generator tools/generate_clone_specs.py solver_configs, clones CLONE_SOLVER_*; every other call/jump is the original
// instruction):
//   617510 -> 65D740 -> 51A530 -> 576B30 ;  611CF0 (host gate) -> 65D7D0 -> 51A9A0 -> 57AFC0 ;  581AE0 -> 576B30
//   576B30 -> 57AFC0 -> 555CA0 -> [555CEB: AssignGate] -> 18F0A00 clone -> { 5373F0 clone -> [53765A: SolveShim],
//                                                                            18F1200 clone -> [18F12AA: SolveGate] }
//   51A530 / 581AE0 -> 584E10 -> 57AC10 -> [57AC3B: CacheAssignGate] -> the same assignment scope. The byte-pinned 539C90 wrapper selects
//   SOLVER_18F0A00 when gameplay overlay run 15 is present, or SOLVER_5373F0 when run 15 is filtered out; the cache vector writeback/free stays native.
// AssignGate records the formation (ECX = F, [F+0x18] = member count) and forwards to the SOLVER_18F0A00 clone. SolveGate replaces the 0x502770
// call: limit != 0 (flag = 0) always runs the native solver; flag = 1 either re-solves a pre-call copy with ntw_solver::SolveCopy and compares it
// with the authoritative native result (shadow) or runs ntw_solver::Solve (memo; kFallback runs the native solver, counted). SolveShim replays the
// .aistbl trampoline 0x18F0D00 exactly (`pushfd; push eax; [esp+0x58] == return address of 18F0A00's 5373F0 call && [[esp+0x24]-8] == 1` ->
// `pop eax; popfd; ret 0x10` suppression, else `pop eax; popfd; jmp 0x502770`), the return address being the SOLVER_18F0A00 CLONE's
// (KNTWR_SOLVER_ASSIGN_RET_OFFSET), else it tail-jumps to SolveGate with registers, flags and stack exactly as 0x502770 would see them.
//
// Not covered (native, exact): 0x581200 slot-command route (zero commands seen on perf bad), 57AFC0 callers 583185, the 648994 / 66E983 callers of
// 51A9A0 (slots 0x1333DA0 / 0x1333DA4), the formation runtime's own FORM_* chain. Any flag=0 solve is native.
//
// Command route (Binding::cloneCommandAssign != 0; version 3): the command assigns reach 555CA0 through the NATIVE 0x57B000 (`F = [this+4]` via
// 4B4A50; push -1; call 555CA0; ret 0x10), whose four E8 callers 56D08F / 573403 / 5734DB / 5736E0 (flag = 1) are formation command code, entered
// natively by 581CA0 -> ... -> 5736B0 (production) and by the census's private CMD_5736B0 chain alike. Start rewrites the single call
// 57B021 `e8 7a ac fd ff | c2 10 00` (call 555CA0; the eight bytes 57B021..57B028 are swapped atomically by kntwr_entry_patch::Swap8) to
// `e8 <rel32 CommandAssignGate> | c2 10 00`. The naked gate tail-jumps to CLONE_SOLVER_555CA0 when the calling thread is the tick owner inside
// a routed epoch (same gate as SolverEpoch), else to the native 555CA0 (`cmd_gate_native`); registers, flags, ECX = F and the five stack
// arguments (a0, a1, float, flag, -1) are untouched, so 57B000's frame, `ret 0x10` and every argument stay native. The clone's 555CEB
// AssignGate sees the pending-command flag and runs the SAME RunAssign scope with layoutIdx = -1 as the origin `Command` (solve flags bit10,
// cmd_assign_calls / cmd_solved_kernel). Stop restores the original bytes (a refusal is reported and retried); a failed Start leaves the
// native bytes.
//
// Row layout (kntwr_status::army_solver_words, KNTWR_ARMY_SOLVER_WORDS == 524), version 3: header 60 words (Word enum, labels
// KNTWR_ARMY_SOLVER_LABELS; scans = sum over outer iterations of the candidate-list length; for every solve the KERNEL produced (memo solves and
// shadow re-solves; timed_solves of them): cost_us = gather + table fill, loop_us = the rest of the loop, kernel_total_us = whole kernel call,
// gather_us = gather alone; rdtsc ticks are converted with a QPC-calibrated rate measured at Start). Counters.profile is always 0 (census mode
// would force the scalar loop), so the distinct-pair total stays 0; evals, scans, swaps and iterations are native-exact),
// top-16 tick table of 13 words (TickWord, labels KNTWR_ARMY_SOLVER_TICK_LABELS) and top-16 solve table of 16 words
// (SolveWord, KNTWR_ARMY_SOLVER_SOLVE_LABELS), both ordered by solver time (shadow: native us; memo: kernel us; a shadow mismatch sorts first).
// Tick id: the id the tick trace writer passes to TickEnd (the same id the storm census uses).
#ifdef __cplusplus
namespace kntwr_army_solver {
using U = uint32_t;
constexpr U kVersion = 3;
constexpr U kHeaderWords = 60, kTop = 16, kTickWords = 13, kSolveWords = 16;
constexpr U kWords = kHeaderWords + kTop * kTickWords + kSolveWords * kTop;
static_assert(kWords == 524, "army solver status row geometry (KNTWR_ARMY_SOLVER_WORDS)");
enum Mode : U { ModeOff = 0, ModeMemo = 1, ModeShadow = 2, ModeForward = 3 /* tests/native_army_solver_chain_oracle.cpp only: clone chain + shim active, every solve runs the native solver */ };
enum Route : U { RouteR1, RouteR1b, RouteR2 };
enum Word : U {
    Version, WMode, WStarted, Ticks, SolvesSeen, SolvesFlag1, SolvedKernel, Flag0Native, ForeignNative,
    FbTooLarge, FbRange, FbListState, FbGuard, FbEnv, ShadowCompares, ShadowMismatchSolves,
    MismatchEntries, MismatchEax, ShimSuppressed, ShimForwarded, AssignCalls, RouteR1Entries, RouteR1bEntries, RouteR2Entries,
    NativeUs, KernelUs, EvalsLo, EvalsHi, DistinctLo, DistinctHi, IterationsLo, IterationsHi,
    Swaps, Removals, MaxM, MaxFormationMembers, MHist0, MHist1, MHist2, MHist3,
    MHist4, MHist5, ObserverUs, AssignMembersSum, ScansLo, ScansHi, CostUs, LoopUs,
    TimedSolves, KernelTotalUs, GatherUs, Direct18F12AA,   // Direct18F12AA: gate entries from 18F12AA (seen - shim forwards)
    FbFpEnv, FbCtx, EmptyNative,   // EmptyNative: flag=1 solves over an empty entry range (begin == end, possibly null): nothing to solve, native runs
    CacheAssignCalls, CacheSolvedKernel, // assignments admitted through 57AC3B; their flag=1 solves completed by the memo kernel
    CmdAssignCalls, CmdSolvedKernel, CmdGateNative, // assignments admitted through the rewritten 57B021 (command route); their kernel solves; gate entries that ran native 555CA0 (foreign thread / outside the routed epoch)
    TickTable = kHeaderWords, SolveTable = kHeaderWords + kTop * kTickWords
};
enum TickWord : U { TTick, TSolves, TFormations, TNativeUs, TKernelUs, TEvals, TDistinct, TIterations, TMaxM, TSolvedKernel, TFallbacks, TSwaps, TAssignFormations };   // TAssignFormations includes ordinary and cache assignments.
// SolveWord::flags: bit0 flag=1 (limit 0), bit1 solved by the kernel (memo), bit2 shadow compared, bit3 kernel fallback, bit4..7 fallback reason,
// bit8 shadow mismatch (entries or EAX), bit9 cache-origin assignment (57AC3B), bit10 command-origin assignment (57B021).
enum SolveWord : U { STick, SFormation, SM, SEvals, SDistinct, SIterations, SNativeUs, SKernelUs, SSwaps, SFlags, SMembers, SEax,
                     SScans, SCostUs, SLoopUs, SSpare };

// Receives the QPC ticks one exact native limited (limit != 0) solve took. Called on the tick owner after the native call returned.
using LimitedSink = void (*)(unsigned long long qpcTicks);
struct Binding {
    U delta;               // relocation of the preferred-base image (V(a) = a + delta)
    Mode mode;             // ModeMemo or ModeShadow
    U cloneAssign;         // CLONE_SOLVER_18F0A00 entry: AssignGate's forward target and the SolveShim return-address base
    U cloneStockAssign;    // CLONE_SOLVER_5373F0 entry for the exact stock 539C90 wrapper (run 15 omitted)
    LimitedSink limitedSink; // nullable: bound only with --army-storm-census wired; null = no QPC reads on the limited path
    // Command route (all zero = not installed): CLONE_SOLVER_555CA0 entry and the runtime's tick-owner / epoch gate (same test as SolverEpoch()).
    U cloneCommandAssign;
    const volatile long* tickOwner;   // the runtime's `volatile LONG tickOwner` (LONG = long)
    const volatile U* epochMask;
    U routedMask;
};
// Fills KNTWR_BIND_SOLVER_ASSIGN / _SOLVE / _SHIM / _CACHE_ASSIGN with host gate addresses and records the native targets; the
// gates run the native originals until Start. Called before kntwr_build_clones.
void Bind(U delta, uint32_t* bindings /*[KNTWR_BIND_COUNT]*/);
// Verifies the constant bit patterns and the image symbols the kernel reads, allocates the workspace; false leaves the module off.
bool Start(const Binding& binding);
// Restores the native bytes of the command route first; false = the restore was refused (a thread sits inside the patched window), the route stays
// armed for CommandRouteInstalled()/Stop() retry and the rest of the module is stopped regardless.
bool Stop();
bool CommandRouteInstalled();
void Reset();
bool Started();
// Bytes of the solver workspace allocated by Start (ntw_solver::WorkspaceBytes(), 11,907,616 B ~ 11.4 MiB at kMaxM 1200); 0 while stopped.
unsigned long long StorageBytes();
// Tick owner, routed epoch: one route-slot entry (counters only).
void NoteRoute(Route route);
// Tick owner, tick trace writer: closes the tick (top tables) with the trace tick id.
void TickEnd(U tick);
void Snapshot(U* words /*[kWords]*/);
// Census-only read-only view (diagnostic; never influences any computation). Written by ReadCensus, a plain struct copy of
// accumulators that live next to the solver totals. ALWAYS-ON counters (kept by the gates in every mode, zero extra work for
// the census): assignEntries (RunAssign entries, ordinary + cache, nested ones included), solvesSeen (SolveGate entries by the
// owner inside an assignment scope), solvedKernel (flag=1 solves completed by the memo kernel), flag0Native (limit != 0
// forwards to the native solver), shimSuppressed (SolveShim suppressions), kernelQ (QPC ticks of the kernel calls, memo and
// shadow, taken by SolveGate's own existing reads). ARMED-ONLY accumulators (stay 0 unless the condition holds):
// limitedQ = QPC ticks of the limited native calls, timed only while a limitedSink is bound (--army-storm-census wired);
// assignScopeQ / assignScopeCalls = QPC ticks / count of the OUTERMOST RunAssign scopes (the forward to the solver clone, i.e.
// the 555CEB-gated chain: slot generation, phase-1 costing, overlay glue AND the inner solves) that began while the calling
// thread was inside CensusProbeEnter .. CensusProbeLeave; those two QPC reads are taken only then (see CensusProbeEnter).
struct CensusSnapshot {
    unsigned long long assignEntries, solvesSeen, solvedKernel, flag0Native, shimSuppressed;
    unsigned long long kernelQ, limitedQ, assignScopeQ, assignScopeCalls;
};
void ReadCensus(CensusSnapshot* out);
// Thread-local census probe depth. The formation residual's routed GateAssign (5736E0 -> 57B000) brackets the native call with
// Enter/Leave; only while the CALLING thread's depth is non-zero does RunAssign time an outermost assignment scope with two
// QPC reads. Default path cost: one thread-local load + test in RunAssign (`t_censusProbe` != 0), no QPC, no extra call.
// Leave never underflows. Reset clears the calling thread's depth (the owner thread, at invocation start/abort).
void CensusProbeEnter();
void CensusProbeLeave();
void CensusProbeReset();
// Host-gate ABI, exported for the runtime's own address checks and tests.
using NativeAssign = U (__fastcall*)(void* formation, void* edx, U a1, U a2, U a3, U a4);
} // namespace kntwr_army_solver
#endif
