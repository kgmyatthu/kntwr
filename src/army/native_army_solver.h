#pragma once
#include <stdint.h>

// Bit-exact memoised flag=1 slot solver, runtime side (--army-solver-memo / --army-solver-shadow, ntw2_config::va_watch_flags
// NTW2_ARMY_SOLVER_MEMO / NTW2_ARMY_SOLVER_SHADOW). Question: the rare ~1 s site-18 freezes are flag=1 (uncapped) assignment solves of the
// 0x502770 pair-swap solver reached from the R1 FSM state-enter (slots 0x1331E74 -> 0x617510, 0x1332110 -> 0x611CF0) and the R2 per-tick
// execute (slot 0x1325474 -> 0x581AE0) of the class-1325470 assignment command (analysis/native-army-storm-census.md, analysis/army-storm-route-decode.md).
//
// Route (runtime host data only; the executable is never modified): inside a routed tick on the tick owner the three route slots run a
// DEDICATED clone chain (generator tools/generate_clone_specs.py solver_configs, clones CLONE_SOLVER_*; every other call/jump is the original
// instruction):
//   617510 -> 65D740 -> 51A530 -> 576B30 ;  611CF0 (host gate) -> 65D7D0 -> 51A9A0 -> 57AFC0 ;  581AE0 -> 576B30
//   576B30 -> 57AFC0 -> 555CA0 -> [555CEB: AssignGate] -> 18F0A00 clone -> { 5373F0 clone -> [53765A: SolveShim],
//                                                                            18F1200 clone -> [18F12AA: SolveGate] }
// AssignGate records the formation (ECX = F, [F+0x18] = member count) and forwards to the SOLVER_18F0A00 clone. SolveGate replaces the 0x502770
// call: limit != 0 (flag = 0) always runs the native solver; flag = 1 either re-solves a pre-call copy with ntw_solver::SolveCopy and compares it
// with the authoritative native result (shadow) or runs ntw_solver::Solve (memo; kFallback runs the native solver, counted). SolveShim replays the
// .aistbl trampoline 0x18F0D00 exactly (`pushfd; push eax; [esp+0x58] == return address of 18F0A00's 5373F0 call && [[esp+0x24]-8] == 1` ->
// `pop eax; popfd; ret 0x10` suppression, else `pop eax; popfd; jmp 0x502770`), the return address being the SOLVER_18F0A00 CLONE's
// (NTW2_SOLVER_ASSIGN_RET_OFFSET), else it tail-jumps to SolveGate with registers, flags and stack exactly as 0x502770 would see them.
//
// Not covered (native, exact): 0x581200 slot-command route (zero commands seen on perf bad), 57AFC0 callers 583185, the 648994 / 66E983 callers of
// 51A9A0 (slots 0x1333DA0 / 0x1333DA4), the formation runtime's own FORM_* chain. Any flag=0 solve is native.
//
// Row layout (ntw2_status::army_solver_words, NTW2_ARMY_SOLVER_WORDS == 519), version 1: header 55 words (Word enum, labels
// NTW2_ARMY_SOLVER_LABELS; scans = sum over outer iterations of the candidate-list length; for every solve the KERNEL produced (memo solves and
// shadow re-solves; timed_solves of them): cost_us = gather + table fill, loop_us = the rest of the loop, kernel_total_us = whole kernel call,
// gather_us = gather alone; rdtsc ticks are converted with a QPC-calibrated rate measured at Start). Counters.profile is always 0 (census mode
// would force the scalar loop), so the distinct-pair total stays 0; evals, scans, swaps and iterations are native-exact),
// top-16 tick table of 13 words (TickWord, labels NTW2_ARMY_SOLVER_TICK_LABELS) and top-16 solve table of 16 words
// (SolveWord, NTW2_ARMY_SOLVER_SOLVE_LABELS), both ordered by solver time (shadow: native us; memo: kernel us; a shadow mismatch sorts first).
// Tick id: the id the tick trace writer passes to TickEnd (the same id the storm census uses).
#ifdef __cplusplus
namespace ntw2_army_solver {
using U = uint32_t;
constexpr U kVersion = 1;
constexpr U kHeaderWords = 55, kTop = 16, kTickWords = 13, kSolveWords = 16;
constexpr U kWords = kHeaderWords + kTop * kTickWords + kTop * kSolveWords;
static_assert(kWords == 519, "army solver status row geometry (NTW2_ARMY_SOLVER_WORDS)");
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
    TickTable = kHeaderWords, SolveTable = kHeaderWords + kTop * kTickWords
};
enum TickWord : U { TTick, TSolves, TFormations, TNativeUs, TKernelUs, TEvals, TDistinct, TIterations, TMaxM, TSolvedKernel, TFallbacks, TSwaps, TAssignFormations };   // TFormations: distinct formations among the flag=1 solves of the tick; TAssignFormations: distinct formations through 555CEB
// SolveWord::flags: bit0 flag=1 (limit 0), bit1 solved by the kernel (memo), bit2 shadow compared, bit3 kernel fallback, bit4..7 fallback reason,
// bit8 shadow mismatch (entries or EAX).
enum SolveWord : U { STick, SFormation, SM, SEvals, SDistinct, SIterations, SNativeUs, SKernelUs, SSwaps, SFlags, SMembers, SEax,
                     SScans, SCostUs, SLoopUs, SSpare };

struct Binding {
    U delta;               // relocation of the preferred-base image (V(a) = a + delta)
    Mode mode;             // ModeMemo or ModeShadow
    U cloneAssign;         // CLONE_SOLVER_18F0A00 entry: AssignGate's forward target and the SolveShim return-address base
};
// Fills the three bindings NTW2_BIND_SOLVER_ASSIGN / _SOLVE / _SHIM with the host gate addresses and records the native targets; the
// gates run the native originals until Start. Called before ntw2_build_clones.
void Bind(U delta, uint32_t* bindings /*[NTW2_BIND_COUNT]*/);
// Verifies the constant bit patterns and the image symbols the kernel reads, allocates the workspace; false leaves the module off.
bool Start(const Binding& binding);
void Stop();
void Reset();
bool Started();
// Tick owner, routed epoch: one route-slot entry (counters only).
void NoteRoute(Route route);
// Tick owner, tick trace writer: closes the tick (top tables) with the trace tick id.
void TickEnd(U tick);
void Snapshot(U* words /*[kWords]*/);
// Host-gate ABI, exported for the runtime's own address checks and tests.
using NativeAssign = U (__fastcall*)(void* formation, void* edx, U a1, U a2, U a3, U a4);
} // namespace ntw2_army_solver
#endif
