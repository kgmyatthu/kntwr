#ifndef NTW2_TARGET_CULL_H
#define NTW2_TARGET_CULL_H
#include <stdint.h>

// --brain-target-cull[-shadow] (ntw2_config::ai_ctrl_flags bits 11 / 10): bit-exact reorder of the melee target search's candidate loop
// 0x553590 (analysis/native-brain-target-cull.md).  NO gameplay change: same candidate, same score bits, same first-index tie-break.
//
// Native structure [proven by disasm]:
//   0x553420(list ECX, agent, targetUnit) (thiscall, ret 8) walks the unit contact list (16-byte entries {enemyUnit, kind, timer, seen}; count
//   list+0xC, data list+0x10).  Per entry with kind not in {0,4}: maxDist = (id(targetUnit+0x10) == id(entryUnit+0x10)) ? [0x1325DB4] (FLT_MAX)
//   : 0x5359E0(kind) (100 / 15 / 3 / 0); score = FLT_MAX; r = 0x553590(agent, targetUnit, maxDist, &score, flag).  NOTE: the unit passed is the
//   TARGET unit for every entry (the entry unit only feeds the id compare and the kind), so one search rescans the target unit's men once per
//   list entry.  r != 0 && score < float(u32 best) -> best = trunc(score), cand = r.  flag = 0x659480(agent).+0xC -> vt+0x20 -> 0x6ABC80().+0x231
//   && !(*(+0x40)+0xBC).
//   0x553590(agent, unit, maxDist, &outScore, flag) (stdcall, ret 0x14; ECX unused): for each man of `unit` (count unit+0x2CC, array unit+0x2D0,
//   both re-read per iteration): thread-safe-static guard 0x14A3E74 (slow path 0x126DF40/0x126E299(0x12E43E0)/0x126DEF6), man->vt+0xB4(&0x1450CE0)
//   appends the man's candidate agents to the scratch list (count 0x1450CEC, data 0x1450CF0), then for each candidate c in order:
//     (flag == 0 || 0x659480(c).+0xC != 0) && 0x679750(c) == 1 && 0x679700(c; agent) == 1 && dist3D(agent, c) < maxDist
//     -> s = 0x53E410(c, dist) = float(u32 c+0x474) * 10 + dist; if (best == 0 || float(u32 bestInt) > s) { best = c; bestInt = trunc(s); }
//   scratch count = 0 after each man; *outScore = float(u32 bestInt); returns best.
// The conjuncts are side-effect free: 0x679750/0x679700/0x62F750/0x579FE0/0x535AF0/0x62DF10/0x655200/0x6E9DA0/0x53E410/0x5359E0 only write
// their stack frame / out-parameters; every indirect call is an agent vtable stub (vt+0x94/+0x9C = 0x461180, vt+0xE8/+0xEC/+0xF0 = 0x462CB0 on
// all 11 agent vtables), a unit id getter (object+0x10 slot 0), or a path-object getter: vt+0x3C/+0x40 of the 25 path-object classes
// derived from 0x7E3A50 are 0x461180 (xor eax,eax) or 0x6DA680 (lea eax,[ecx+0x20]) [proven for those 25 constructors; that no other class is
// ever placed at agent+0x2D4 is an INFERENCE checked by the shadow compare].  Therefore the loop's result depends only on (which candidates pass,
// their scores and their order), and the cheap, pure conjuncts can run first.
//
// Mirror (this module): same native callees, same order of the impure steps (guard, vt+0xB4 push, scratch reset, flag test 0x659480), then
//   dist < maxDist  ->  score s  ->  (best == 0 || float(u32 bestInt) > s)  ->  0x679750  ->  0x679700.
// A candidate that cannot beat the running best (or lies beyond maxDist) never reaches the alive/reachability/FPATAN predicate; a candidate that
// would have failed the predicate was never accepted natively either, so the accepted sequence, best, bestInt and *outScore are identical.
// Search additionally exploits that 0x553420 passes the SAME unit to every entry (see above): the candidates are gathered ONCE per search (guard, vt+0xB4
// push, scratch reset; distance and flag test cached per candidate, score and predicate memoised lazily), every entry scans the cached array with its own
// maxDist and running best (more than 4096 candidates fall back to the per-entry loop), and once an entry with maxDist = FLT_MAX (entry unit id == target
// unit id) has been processed the remaining entries are skipped: their candidates are a subset with identical per-candidate scores, so their best score is >=
// that entry's and `score < float(u32 trunc(best))` can never hold for them (also for the cvttss2si overflow value 0x80000000 and for the retained best of an
// earlier entry: either the unlimited entry replaced it with trunc(s*) <= s*, or s* >= float(trunc(s1)) and s' >= s*).  Shadow runs those entries natively and
// counts any replacement after an unlimited entry as a result mismatch.  The predicates are pure, so memoising one result per candidate per search is exact.
// Shadow mode runs the native loop and the mirror on the same inputs per entry, answers with the native result and counts mismatches by kind.
// Search() is the mirror of the whole 0x553420 (its only caller is 0x6671DE inside 0x6671A0); it runs only inside the routed brain-stage clone chain
// on the tick owner thread, so it needs no thread gate.
namespace ntw2_target_cull {
// ai_ctrl_reuse_words[16..19] (NTW2_AI_CTRL_REUSE_LABELS "tc_*"):
//  0 calls       entry scans run (one per processed list entry; shadow: compares; live skips the entries after an unlimited one)
//  1 candidates  candidates visited (scratch entries; saturating)
//  2 predicates  candidates that reached 0x679750 (live/shadow mirror; saturating).  culled = candidates - predicates - flag skips
//  3 packed      bits 0..7 result-pointer mismatches, 8..15 score-bit mismatches, 16..23 scratch-residue mismatches (all saturating),
//                bits 24..31 searches with flag != 0 (saturating; the 0x659480 test then runs per candidate like native)
constexpr uint32_t kWords = 4;
enum Word : uint32_t { WCalls, WCandidates, WPredicates, WPacked };
extern volatile uint32_t words[kWords];
enum Mode : uint32_t { ModeOff, ModeShadow, ModeLive };

struct Targets {
    uint32_t search;     // 0x553420 original (Mode off forwards here)
    uint32_t loop;       // 0x553590 original (stdcall, 5 stack args, ret 0x14)
    uint32_t flagState;  // 0x659480 (thiscall ECX = agent/candidate, stack: out[20 bytes]; ret 4; EAX = out)
    uint32_t alive;      // 0x679750 (thiscall ECX = candidate, AL)
    uint32_t reach;      // 0x679700 (thiscall ECX = candidate, stack: agent; ret 4; AL)
    uint32_t score;      // 0x53E410 (cdecl: candidate, float dist; float in ST0)
    uint32_t kindDist;   // 0x5359E0 (cdecl: kind; float in ST0)
    uint32_t settings;   // 0x6ABC80 (thiscall, returns the settings object)
    uint32_t scratch;    // 0x1450CE0 scratch list header (+8 capacity, +0xC count, +0x10 data)
    uint32_t guard;      // 0x14A3E74 function-local static guard
    uint32_t tlsIndex;   // 0x1841BB8 CRT TLS index word
    uint32_t initHeader; // 0x126DF40 (cdecl: &guard)
    uint32_t atexitFn;   // 0x126E299 (cdecl: fn)
    uint32_t atexitArg;  // 0x12E43E0
    uint32_t initFooter; // 0x126DEF6 (cdecl: &guard)
    uint32_t u32Table;   // 0x1318130: {0.0, 4294967296.0} unsigned correction doubles
    uint32_t maxFloat;   // 0x1325DB4: the FLT_MAX constant (float)
};
constexpr uint32_t kSearch = 0x553420u, kLoop = 0x553590u, kFlagState = 0x659480u, kAlive = 0x679750u, kReach = 0x679700u, kScore = 0x53E410u,
                   kKindDist = 0x5359E0u, kSettings = 0x6ABC80u, kScratch = 0x1450CE0u, kGuard = 0x14A3E74u, kTlsIndex = 0x1841BB8u,
                   kInitHeader = 0x126DF40u, kAtexit = 0x126E299u, kAtexitArg = 0x12E43E0u, kInitFooter = 0x126DEF6u, kU32Table = 0x1318130u,
                   kMaxFloat = 0x1325DB4u;

void Configure(Mode mode, const Targets& targets);
void ResetRow();                       // runtime start: zero the row
void Snapshot(volatile uint32_t* out); // out[kWords]

// Mirror of 0x553420 (thiscall ECX = list, ret 8). Mode off forwards to the original; shadow answers natively.
uint32_t __fastcall Search(uint32_t list, uint32_t, uint32_t agent, uint32_t targetUnit);
// Mirror of 0x553590 (the reordered loop), also used directly by the oracle.
uint32_t __stdcall Loop(uint32_t agent, uint32_t unit, float maxDist, float* outScore, uint32_t flag);
}
#endif
