#pragma once
// Cell-partitioned, order-preserving apply of a native soft-grid relink batch (RelinkProbation.md "Scope only",
// MovementSlices Contract 3). One kernel source, templated on a memory accessor, runs against live native memory
// (live mode), against a private mirror (shadow mode) and, in the oracle, against the same memory image the native
// services ran on.
//
// Equivalence with the serial native sequence (the oracle proves it bit for bit): every cell chain ends as
//   [ inserted nodes of the batch, newest first ] ++ [ batch-start nodes that were not unlinked, original order ],
// because removals of distinct nodes commute and 0x69E680 prepends. Phase U (all unlinks) and phase I (all prepends)
// are therefore separated by one join, and inside a phase each task walks the batch in log order and only touches the
// cell rows of its window. A node belongs to exactly one chain, so tasks never share a written word.
#include <stdint.h>
#include "native_move_delta.h"

namespace ntw2_loco {

constexpr uint32_t kRelinkMaxTasks = 32;

struct RelinkBatchView {        // the open batch of a MoveLog
    const MoveOp* ops; uint32_t count;
    const uint32_t* oldCells;
    uint32_t heads, shift, maximum;
};
RelinkBatchView RelinkViewOf(const MoveLog& log);

// ---- kernels (inline templates; M supplies `uint32_t Load(uint32_t address)` / `void Store(uint32_t address, uint32_t value)`) ----
struct LiveMemory {
    static uint32_t Load(uint32_t address) { return *reinterpret_cast<const volatile uint32_t*>(static_cast<uintptr_t>(address)); }
    static void Store(uint32_t address, uint32_t value) { *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(address)) = value; }
};
// 0x6E8400, instruction for instruction (including the re-read of node+0x14 after the neighbour store).
template <class M> inline void RelinkUnlinkNode(M& m, uint32_t node) {
    const uint32_t cell = m.Load(node + 0x18);
    if (!cell) return;
    const uint32_t next = m.Load(node + 0x14), prev = m.Load(node + 0x10);
    if (prev) m.Store(prev + 0x14, next); else m.Store(cell, next);
    const uint32_t after = m.Load(node + 0x14);
    if (after) m.Store(after + 0x10, m.Load(node + 0x10));
    m.Store(node + 0x18, 0); m.Store(node + 0x10, 0); m.Store(node + 0x14, 0);
}
// 0x69E680: prepend `node` to the chain whose head slot is `cell`. node+0x10 is deliberately not written (a node that is
// not linked has prev == 0).
template <class M> inline void RelinkPrependNode(M& m, uint32_t node, uint32_t cell) {
    const uint32_t head = m.Load(cell);
    m.Store(node + 0x14, head);
    if (head) m.Store(head + 0x10, node);
    m.Store(node + 0x18, cell); m.Store(cell, node);
}
// Phase U for the cell rows [rowLo, rowHi]: unlinks in log order. Returns the number of nodes whose chain cell word
// disagreed with the logged cell (an invariant violation; the splice still runs exactly as the native one would).
template <class M> uint32_t RelinkUnlinkRows(const RelinkBatchView& b, M& m, uint32_t rowLo, uint32_t rowHi) {
    uint32_t anomalies = 0;
    for (uint32_t i = 0; i < b.count; ++i) {
        const MoveOp& op = b.ops[i];
        if (op.kind != MoveUnlinkGrid) continue;
        const uint32_t lo = op.reserved[0] & 0xFFFFu, hi = op.reserved[0] >> 16;
        if (lo > rowHi || hi < rowLo) continue;
        const uint32_t* const cells = b.oldCells + op.nodeBase;
        for (uint32_t k = 0; k < op.nodes; ++k) {
            const uint32_t c = cells[k];
            if (c == kMoveNoCell) continue;
            const uint32_t row = c >> b.shift;
            if (row < rowLo || row > rowHi) continue;
            const uint32_t node = op.reserved[1] + k * 0x1C;
            anomalies += m.Load(node + 0x18) != b.heads + 4 * c;
            RelinkUnlinkNode(m, node);
        }
    }
    return anomalies;
}
// Phase I for the cell rows [rowLo, rowHi]: prepends in log order (rows ascending, columns ascending, node index
// ascending, like the native loops). Returns the number of inserted nodes that were still linked.
template <class M> uint32_t RelinkInsertRows(const RelinkBatchView& b, M& m, uint32_t rowLo, uint32_t rowHi) {
    uint32_t anomalies = 0;
    for (uint32_t i = 0; i < b.count; ++i) {
        const MoveOp& op = b.ops[i];
        if (op.kind != MoveInsertGrid) continue;
        const uint32_t lo = op.reserved[0] & 0xFFFFu, hi = op.reserved[0] >> 16;
        if (lo > rowHi || hi < rowLo) continue;
        const uint32_t width = op.right - op.left + 1u;
        const uint32_t first = lo > rowLo ? lo : rowLo, last = hi < rowHi ? hi : rowHi;
        for (uint32_t row = first; row <= last; ++row) {
            uint32_t node = op.reserved[1] + (op.nodeBase + (row - op.top) * width) * 0x1C;
            for (uint32_t col = op.left; col <= op.right; ++col, node += 0x1C) {
                anomalies += m.Load(node + 0x18) != 0;
                RelinkPrependNode(m, node, b.heads + 4 * ((row << b.shift) + col));
            }
        }
    }
    return anomalies;
}

// ---- partition + live apply ----
struct RelinkPlan {
    uint32_t tasks;                              // dispatch width
    uint32_t rowLo[2][kRelinkMaxTasks], rowHi[2][kRelinkMaxTasks]; // [phase][task]; lo > hi = idle task
    uint32_t unlinkCells, insertCells, active;   // cell operations of the batch; non-empty task windows over both phases
};
// Weight-balanced contiguous row windows over the open batch's per-bin weights (grid v2 strip weighting).
void RelinkPlanBatch(const MoveLog& log, uint32_t tasks, RelinkPlan& plan);

struct RelinkDispatcher { void (__stdcall* dispatch)(uint32_t pool, uint32_t body, uint32_t chunks, void* context); uint32_t pool, workers; };
struct RelinkApplyStats {
    uint32_t dispatches, partitions;   // pool dispatches; non-empty windows run
    uint32_t cpuUs;                    // summed per-task wall time
    uint32_t anomalies, faults;        // invariant violations seen by the kernels; SEH faults inside tasks
};
// Applies the open batch of `log` to native memory. Runs on the pool when a dispatcher with workers is given and the
// batch has at least `minCells` cell operations; otherwise serially on the calling thread with the same kernel.
// Does not close the batch. Returns true when it ran in parallel.
bool RelinkApplyLive(const MoveLog& log, const RelinkDispatcher* dispatcher, uint32_t minCells, RelinkApplyStats& stats);

// ---- shadow mirror ----
struct RelinkMirror {
    uint32_t* keys; uint32_t* values; uint32_t mask, used, limit;   // open-addressed word table: address -> private value
    uint32_t* slots;                   // used table slots (cheap reset)
    uint32_t* nodeList; uint32_t nodeCount, nodeLimit;    // snapshotted nodes (their three link words are mirrored)
    uint32_t* cellList; uint32_t cellCount, cellLimit;    // snapshotted cells (head slot + whole chain)
    uint32_t heads, shift, maximum;
    bool overflow;                     // a snapshot did not fit: the batch cannot be verified
    volatile long misses;              // kernel accesses to a word that was never snapshotted
    unsigned char* block; size_t blockBytes;
};
struct RelinkShadowResult {
    uint32_t cells, mismatchCells, mismatchNodes; // mirror cells compared; cells whose chain differs; nodes/records whose words differ
    uint32_t lastCell, lastRecord;                // valid when a mismatch was found (cell index / record VA)
    uint32_t refused;                             // batch not verifiable (mirror overflow or kernel misses)
};
bool RelinkMirrorInit(RelinkMirror& mirror, uint32_t wordCapacity);
void RelinkMirrorFree(RelinkMirror& mirror);
void RelinkMirrorReset(RelinkMirror& mirror, const MoveLog& log);
// Called BEFORE the native service of op `index` (the open batch's op) runs: snapshots, on first touch, the chains of
// every cell the op touches and the node words of the op's nodes.
void RelinkMirrorTouch(RelinkMirror& mirror, const MoveLog& log, uint32_t index);
// Runs the parallel (or serial) kernel on the mirror, then compares the mirror with native memory.
bool RelinkMirrorApply(RelinkMirror& mirror, const MoveLog& log, const RelinkDispatcher* dispatcher, uint32_t minCells,
                       RelinkApplyStats& stats, RelinkShadowResult& result);

} // namespace ntw2_loco
