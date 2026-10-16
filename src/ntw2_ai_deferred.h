#ifndef NTW2_AI_DEFERRED_H
#define NTW2_AI_DEFERRED_H
// NTW2_AI_ASYNC2 deferred schedule (--ai-deferred): a private driver of the planner update 0x7D99F0 that runs it in
// count-budgeted slices at whole-node boundaries. Between two slices the AI worker holds no native frame: every slice
// returns to the scheduler (ntw2_ai_async2) after whole calls of the original per-node bodies.
//
// 0x7D99F0(P, flag) (analysis/tick-hot-7d99f0.asm) is reproduced unit by unit with the original bodies:
//   pass A: 0x7CD010(node) for each node of P+A0[0..P+9C)
//   pass B: 0x7CCF80(node) for each node
//   flag != 0: unless [[[P]+8]+64]+80 == 1, for each node: if !node->vt[+20]() think(node)
//   flag == 0: if P+9C: ++[P+B8]; think(P+A0[[P+B8] % P+9C]) unless current; then
//              if P+B0: node = P+B4[[P+B8] % P+B0]; if node, think(node) unless current
// think(T) is node->vt[+10]. When that slot is 0x7D7BF0 (analysis/tick-hot-planner.asm) it is decomposed too:
//   if T+48 == 0: T->vt[0]() (generate) then 0x7CCF80(T); then for each child C of T+4C[0..T+48):
//   if C+40 + C+30 != 0: C->vt[+28]()   (the child think, the query issuer)
// any other think slot runs whole as one unit.
//
// Node identity across slices (and across units, since a body may rebuild the arrays): the node list is snapshotted at
// think start and the child list at think(T) start. Before each unit the snapshot entry must be a member of the live
// array (fast path: the same index; else a full scan, counted as relocated); non-members are skipped and counted. A
// decomposed think's T is revalidated against its planner array before each child unit; if it is gone the remaining
// children are dropped (counted). A list longer than the snapshot capacity is walked by live index instead, exactly like
// the original loop (counted as an overflow).
//
// Budget: generate, child think and whole think calls cost one unit each (the query issuers); passes, the is-current
// checks and skips cost nothing. A unit that would cost is not started when the budget is 0: the slice ends there and
// the cursor resumes at the next slice. Everything here is a function of the live engine state at the unit and of
// the budget -- no clock decides anything (time is only measured).
#include <stdint.h>

namespace ntw2_ai_deferred {
using U = uint32_t;

constexpr U kMaxNodes = 4096, kMaxChildren = 1024;
enum Kind : U { KPassA, KPassB, KCurrent, KGenerate, KChild, KWhole, KKinds };

// Relocated originals: 0x7CD010, 0x7CCF80 and 0x7D7BF0 (compared with the think slot, never called).
struct Natives { U passA, passB, think; };

// Driver telemetry (single writer: the AI worker). Microseconds are QPC-measured around each native call.
struct Counters {
    U calls[KKinds], us[KKinds], unitMaxUs;
    U skipped, relocated, childSkipped, thinksDropped, overflows;
};

enum Phase : U { PIdle, PPassA, PPassB, PFlag, PFull, PRound1, PRound1Think, PRound2, PRound2Think, PDone };

// One think in progress. Single instance per AI worker: the scheduler runs thinks strictly in FIFO order.
struct Think {
    U planner, flag, phase, index;
    U nodeCount, nodes[kMaxNodes]; // nodeCount 0xFFFFFFFF: live index mode (overflow)
    // decomposed think(T) in progress (tActive): T, its planner array (1 = P+A0/P+9C, 2 = P+B4/P+B0) and index hint
    U tActive, t, tList, tHint, childIndex, childCount, children[kMaxChildren]; // childCount 0xFFFFFFFF: live index
};

void Begin(Think& think, U planner, U flag, Counters& counters);
// Runs units until the think is done (true) or a costed unit meets an exhausted budget (false). budget is decremented
// per costed unit. qpcFreq converts the per-call timing.
bool Step(Think& think, const Natives& natives, U& budget, Counters& counters, int64_t qpcFreq);
}
#endif
