#ifndef NTW2_MARCH_SLOTS_H
#define NTW2_MARCH_SLOTS_H
#include <stdint.h>

// --ai-march-slots (ntw2_config::ai_ctrl_flags NTW2_AI_MARCH_SLOTS = bit 17; lever 3 of the AI work, analysis/native-march-collapse.md).
// AI-ONLY GAMEPLAY DEVIATION (user-approved, opt-in, never implied by --features all): a freshly created AI formation MOVE command gets its men assigned to the formation
// slots by a FULL (uncapped) pair-swap solve BEFORE the per-man move orders are issued, so the marching men keep their rank-and-file slots instead of crossing each other.
// The shared soldier / unit simulation is untouched; with the switch OFF nothing is installed at all.
//
// Native structure [proven by disassembly of Napoleon_patched.exe, preferred base 0x400000, and by the formation census men rows, analysis/native-march-collapse.md]:
//   The formation MOVE command (class vtable 0x1325470; execute slot 0x1325474 = 0x581AE0, ECX = command C, plain `ret`; F = [C+4] the formation, F+0x510 = its unit U,
//   U+0x1EC = its army) is built by the constructor 0x51A530 (called by 0x65D740 at 0x65D7C2). The constructor ends with
//        if ([[C+0x18]+0x8C]) { 0x576B30(1); [[C+0x18]+0x8C] = 0 }  ...  0x584E10(1)
//   0x584E10(C, flag) = the per-man order issue: it generates the slot vector from the route, then (flag != 0: every man; else only men whose order is not finished, i.e.
//   practically none on the march) issues man k of F+0x1C a MOVE node (0x6533E0 -> node 0x1348B44, begin 0x816900) to slot k. 0x576B30(C, p) = the slot assignment:
//   [C+0x7C] == 0 -> latch [C+0x7C] = 1 and solve flag -1 (low byte 0xFF); else solve flag [C+0x30] (the pacing index). 0x5373F0 turns the flag byte b into the solver
//   limit b ^ 1 and the threshold b == 0 ? 16.0 : FLT_MAX: the first assignment is a best-improvement solve CAPPED at 254 iterations, every later one at (cmd+0x30 ^ 1) (6..8), and only a
//   flag byte of exactly 1 is the uncapped first-improvement solve (0x502770 limit 0; native-formation-solver-memo.md). The path request object sets [[C+0x18]+0x8C] = 1 only when the route starts
//   behind the unit (0x8102F0: reverse move); every other command - all of them for a forward AI march - reaches 0x584E10(1) with the man array still in the OLD formation's slot order. The first execute
//   (0x581AE0: [C+0x3C] == 0 and [C+0x7C] == 0 -> 0x576B30) solves afterwards with the capped flag; the men already carry their orders, which are not reissued while the men are
//   moving (the refresh 0x584E10(C, 0) every second skips men with a live order, 0x63E290). When the new template faces away from the old one the old order k -> slot k is a 180 degree rotation of
//   the whole line: every man runs to the opposite flank, the 500 men funnel through each other into a 1 m wide strip (men s2 < 1 m, nearest neighbour 0.26 m), then spread again.
//   Player commands do not show it: the same constructor is run with an already solved array (the player's move arrives with its path and first slots near the men, or reverse-flagged).
//
// Mechanism: the R2 slot 0x1325474 (the runtime's StormRoute2Gate, installed for this bit as well) calls Pre(C, model) before the native execute and Post(C, solve) after it.
//   Pre: [C+0x7C] == 0 (this execute is the command's first one: the constructor did not solve) AND the command's unit belongs to an AI side ([side+0xC] != 0 of the side whose army list contains
//        U+0x1EC) -> true.  Everything else is untouched (no write, no call).
//   Post (only after Pre returned true, the native execute having run its own capped first solve): verifies the command is still F's last queued command (F+0x420+8*(F+0x460-1)) with
//        vtable 0x1325470 and [C+0x7C] != 0, then runs the native chain once more with the uncapped flag: [C+0x30] = 1; 0x576B30(C, p) (p = dirty && !cooldown as 0x581AE0 computes it; `solve` is the
//        SOLVER_576B30 clone while the solver epoch is on, so the memo kernel serves the flag=1 solve; else the original); 0x584E10(C, 1) reissues every man's move order to the re-solved slots
//        ([C+0x30] is rewritten by 0x584E10 itself). Cost: one uncapped solve + one full order issue per fresh AI march command.
// Engine memory is read inside ONE SEH bracket per call (ntw2::probeDepth), POD locals only inside __try. A fault is counted and nothing further is attempted for that command.
namespace ntw2_march_slots {
using U = uint32_t;
// ntw2_status::ai_march_words (labels NTW2_AI_MARCH_LABELS):
//  0 calls         Pre calls
//  1 first_exec    commands whose [C+0x7C] was 0 (constructor did not solve)
//  2 latched       commands whose [C+0x7C] was already 1 (constructor solved or later execute): untouched
//  3 ai_fresh      first executes of an AI unit's command (Post ran)
//  4 player_fresh  first executes of a non-AI unit's command (untouched)
//  5 unmeasured    first executes whose unit / army / side could not be resolved (untouched)
//  6 resolved      Post completed the uncapped solve + order issue
//  7 gone          Post found the command no longer queued / replaced (nothing done)
//  8 men_sum       sum of the men count over resolved commands
//  9 max_men       largest men count of a resolved command
// 10 solve_us      QPC microseconds inside the uncapped 0x576B30 call (sum)
// 11 issue_us      QPC microseconds inside 0x584E10(C, 1) (sum)
// 12 max_us        largest single Post (solve + issue) in microseconds
// 13 solver_clone  Post calls that ran the SOLVER_576B30 clone (memo / shadow chain) instead of the original
// 14 spare
// 15 faults        SEH faults (the command is left as the native execute made it)
constexpr U kWords = 16;
enum Word : U { WCalls, WFirstExec, WLatched, WAiFresh, WPlayerFresh, WUnmeasured, WResolved, WGone, WMenSum, WMaxMen, WSolveUs, WIssueUs, WMaxUs, WSolverClone, WSpare, WFaults };
extern volatile U words[kWords];

constexpr U kSlot = 0x1325474u, kExecuteOriginal = 0x581AE0u, kSolveOriginal = 0x576B30u, kIssueOriginal = 0x584E10u, kMoveVtable = 0x1325470u;

// delta = image delta from the preferred base; solveOriginal/issue = the relocated natives (thiscall, ECX = command, one stack dword, callee pops 4). Zeroes the row.
struct Targets { U delta; U solveOriginal; U issue; };
void Configure(const Targets& targets);
void ResetRow();
void Snapshot(volatile U* out); // out[kWords]

// Called from the R2 gate on the tick owner inside a routed epoch (any other call: do not call).  model = the battle model address ([model+0xB0] = the battle world).
bool Pre(U command, U model);
// After the native execute of a command Pre accepted.  solve = the 0x576B30 variant to run (clone or original), solverClone = whether it is the clone.
void Post(U command, U solve, bool solverClone);
}
#endif
