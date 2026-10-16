#include <windows.h>
#include <intrin.h>
#include <string.h>
#include "native_relink.h"

static_assert(sizeof(void*) == 4, "native relink apply is a Win32 x86 adapter");

namespace ntw2_loco {
namespace {
using U = uint32_t;
inline U D(U address) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(address)); }
LONGLONG Frequency() {
    static LONGLONG frequency;
    if (!frequency) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); frequency = f.QuadPart > 0 ? f.QuadPart : 1; }
    return frequency;
}
inline U Us(LONGLONG ticks) { return static_cast<U>(static_cast<unsigned long long>(ticks) * 1000000ull / static_cast<unsigned long long>(Frequency())); }
unsigned long long Align(unsigned long long v) { return (v + 63) & ~63ull; }

// ---- mirror memory accessor: find-only (the table is fully populated before any kernel runs) ----
inline U MirrorHash(U address, U mask) { return (address * 2654435761u >> 11) & mask; }
inline U* MirrorFind(const RelinkMirror& m, U address) {
    for (U h = MirrorHash(address, m.mask);; h = (h + 1) & m.mask) {
        const U key = m.keys[h];
        if (key == address) return &m.values[h];
        if (!key) return nullptr;
    }
}
struct MirrorMemory {
    RelinkMirror& mirror;
    U Load(U address) const {
        const U* const v = MirrorFind(mirror, address);
        if (!v) { _InterlockedIncrement(&mirror.misses); return 0; }
        return *v;
    }
    void Store(U address, U value) const {
        U* const v = MirrorFind(mirror, address);
        if (!v) { _InterlockedIncrement(&mirror.misses); return; }
        *v = value;
    }
};

struct RelinkJob {
    RelinkBatchView batch;
    RelinkPlan plan;
    RelinkMirror* mirror;
    U phase;
    volatile LONG anomalies, faults, cpuUs, partitions;
};
void RelinkWindow(RelinkJob& job, U phase, U rowLo, U rowHi) {
    U anomalies;
    if (job.mirror) {
        MirrorMemory m = {*job.mirror};
        anomalies = phase == 0 ? RelinkUnlinkRows(job.batch, m, rowLo, rowHi) : RelinkInsertRows(job.batch, m, rowLo, rowHi);
    } else {
        LiveMemory m;
        anomalies = phase == 0 ? RelinkUnlinkRows(job.batch, m, rowLo, rowHi) : RelinkInsertRows(job.batch, m, rowLo, rowHi);
    }
    if (anomalies) _InterlockedExchangeAdd(&job.anomalies, static_cast<LONG>(anomalies));
}
void __fastcall RelinkChunk(void* context, U task) {
    RelinkJob& job = *static_cast<RelinkJob*>(context);
    if (task >= job.plan.tasks) return;
    const U lo = job.plan.rowLo[job.phase][task], hi = job.plan.rowHi[job.phase][task];
    if (lo > hi) return;
    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);
    __try { RelinkWindow(job, job.phase, lo, hi); }
    __except(EXCEPTION_EXECUTE_HANDLER) { _InterlockedIncrement(&job.faults); }
    QueryPerformanceCounter(&end);
    _InterlockedExchangeAdd(&job.cpuUs, static_cast<LONG>(Us(end.QuadPart - start.QuadPart)));
    _InterlockedIncrement(&job.partitions);
}
bool RunBatch(const MoveLog& log, RelinkMirror* mirror, const RelinkDispatcher* dispatcher, U minCells, RelinkApplyStats& stats) {
    RelinkJob job = {};
    job.batch = RelinkViewOf(log); job.mirror = mirror;
    const U cells = log.batchUnlinkCells + log.batchInsertCells;
    const bool parallel = dispatcher && dispatcher->dispatch && dispatcher->workers && cells >= minCells && log.geometryOk;
    if (!parallel) {
        const U maximum = log.geometry.maximum;
        RelinkWindow(job, 0, 0, maximum);
        RelinkWindow(job, 1, 0, maximum);
        stats.anomalies += static_cast<U>(job.anomalies);
        return false;
    }
    const U tasks = dispatcher->workers + 1 < kRelinkMaxTasks ? dispatcher->workers + 1 : kRelinkMaxTasks;
    RelinkPlanBatch(log, tasks, job.plan);
    for (U phase = 0; phase < 2; ++phase) {
        job.phase = phase;
        ++stats.dispatches;
        dispatcher->dispatch(dispatcher->pool, static_cast<U>(reinterpret_cast<uintptr_t>(&RelinkChunk)), job.plan.tasks, &job);
    }
    stats.partitions += static_cast<U>(job.partitions); stats.cpuUs += static_cast<U>(job.cpuUs);
    stats.anomalies += static_cast<U>(job.anomalies); stats.faults += static_cast<U>(job.faults);
    return true;
}

// Splits the weighted bins into `tasks` contiguous windows. Windows are closed at the first bin whose running total
// reaches the task's share of the total, so one hot bin can close several windows (the extra ones stay idle).
void PlanPhase(const MoveLog& log, const U* weights, U total, U tasks, U* rowLo, U* rowHi, U& active) {
    const U bins = (log.geometry.maximum >> log.binShift) + 1;
    for (U t = 0; t < tasks; ++t) { rowLo[t] = 1; rowHi[t] = 0; }
    if (!total) return;
    U task = 0, start = 0;
    unsigned long long cumulative = 0;
    for (U bin = 0; bin < bins && task + 1 < tasks; ++bin) {
        cumulative += log.binStamp[bin] == log.stamp ? weights[bin] : 0;
        if (cumulative * tasks < static_cast<unsigned long long>(total) * (task + 1)) continue;
        U hi = ((bin + 1) << log.binShift) - 1; // close the inclusive bin window [start, bin]
        if (hi > log.geometry.maximum) hi = log.geometry.maximum;
        rowLo[task] = start << log.binShift; rowHi[task] = hi; ++active; ++task; start = bin + 1;
        while (task + 1 < tasks && cumulative * tasks >= static_cast<unsigned long long>(total) * (task + 1)) ++task; // idle windows
    }
    if (start < bins) { rowLo[task] = start << log.binShift; rowHi[task] = log.geometry.maximum; ++active; }
}
} // namespace

RelinkBatchView RelinkViewOf(const MoveLog& log) {
    return {log.ops + log.batchBegin, log.count - log.batchBegin, log.oldCells, log.heads, log.shift, log.geometry.maximum};
}

void RelinkPlanBatch(const MoveLog& log, U tasks, RelinkPlan& plan) {
    if (tasks > kRelinkMaxTasks) tasks = kRelinkMaxTasks;
    if (!tasks) tasks = 1;
    plan = {};
    plan.tasks = tasks; plan.unlinkCells = log.batchUnlinkCells; plan.insertCells = log.batchInsertCells;
    PlanPhase(log, log.weightUnlink, log.batchUnlinkCells, tasks, plan.rowLo[0], plan.rowHi[0], plan.active);
    PlanPhase(log, log.weightInsert, log.batchInsertCells, tasks, plan.rowLo[1], plan.rowHi[1], plan.active);
}

bool RelinkApplyLive(const MoveLog& log, const RelinkDispatcher* dispatcher, U minCells, RelinkApplyStats& stats) {
    return RunBatch(log, nullptr, dispatcher, minCells, stats);
}

// ---- shadow mirror ----
bool RelinkMirrorInit(RelinkMirror& m, U wordCapacity) {
    RelinkMirrorFree(m);
    U size = 1u << 12;
    while (size < wordCapacity * 2ull && size < (1u << 26)) size <<= 1;
    const U limit = size / 2, nodeLimit = limit / 3, cellLimit = limit / 2;
    const unsigned long long bytes = Align(size * 4ull) * 2 + Align(limit * 4ull) + Align(nodeLimit * 4ull) + Align(cellLimit * 4ull);
    unsigned char* const block = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(bytes), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!block) return false;
    m = RelinkMirror{};
    m.block = block; m.blockBytes = static_cast<size_t>(bytes);
    size_t at = 0;
    m.keys = reinterpret_cast<U*>(block + at); at += static_cast<size_t>(Align(size * 4ull));
    m.values = reinterpret_cast<U*>(block + at); at += static_cast<size_t>(Align(size * 4ull));
    m.slots = reinterpret_cast<U*>(block + at); at += static_cast<size_t>(Align(limit * 4ull));
    m.nodeList = reinterpret_cast<U*>(block + at); at += static_cast<size_t>(Align(nodeLimit * 4ull));
    m.cellList = reinterpret_cast<U*>(block + at);
    m.mask = size - 1; m.limit = limit; m.nodeLimit = nodeLimit; m.cellLimit = cellLimit;
    return true;
}
void RelinkMirrorFree(RelinkMirror& m) {
    if (m.block) VirtualFree(m.block, 0, MEM_RELEASE);
    m = RelinkMirror{};
}
void RelinkMirrorReset(RelinkMirror& m, const MoveLog& log) {
    for (U i = 0; i < m.used; ++i) m.keys[m.slots[i]] = 0;
    m.used = m.nodeCount = m.cellCount = 0; m.overflow = false; m.misses = 0;
    m.heads = log.heads; m.shift = log.shift; m.maximum = log.geometry.maximum;
}
namespace {
bool MirrorHas(const RelinkMirror& m, U address) { return MirrorFind(m, address) != nullptr; }
void MirrorAdd(RelinkMirror& m, U address) { // snapshot of the live word, first touch only
    for (U h = MirrorHash(address, m.mask);; h = (h + 1) & m.mask) {
        if (m.keys[h] == address) return;
        if (!m.keys[h]) {
            if (m.used == m.limit) { m.overflow = true; return; }
            m.keys[h] = address; m.values[h] = D(address); m.slots[m.used++] = h;
            return;
        }
    }
}
void MirrorNode(RelinkMirror& m, U node) {
    if (MirrorHas(m, node + 0x18)) return;
    if (m.nodeCount == m.nodeLimit) { m.overflow = true; return; }
    m.nodeList[m.nodeCount++] = node;
    MirrorAdd(m, node + 0x10); MirrorAdd(m, node + 0x14); MirrorAdd(m, node + 0x18);
}
void MirrorCell(RelinkMirror& m, U cell) {
    const U head = m.heads + 4 * cell;
    if (MirrorHas(m, head)) return;
    if (m.cellCount == m.cellLimit) { m.overflow = true; return; }
    m.cellList[m.cellCount++] = cell;
    MirrorAdd(m, head);
    U node = D(head);
    for (U steps = 0; node && !m.overflow; ++steps) {
        if (steps > m.nodeLimit) { m.overflow = true; return; }
        MirrorNode(m, node);
        node = D(node + 0x14);
    }
}
} // namespace

void RelinkMirrorTouch(RelinkMirror& m, const MoveLog& log, U index) {
    if (m.overflow) return;
    m.heads = log.heads; m.shift = log.shift; m.maximum = log.geometry.maximum;
    const MoveOp& op = log.ops[index];
    if (op.kind == MoveUnlinkGrid) {
        for (U k = 0; k < op.nodes; ++k) {
            const U cell = log.oldCells[op.nodeBase + k];
            if (cell == kMoveNoCell) continue;
            MirrorCell(m, cell);
            MirrorNode(m, op.reserved[1] + k * 0x1C);
        }
        return;
    }
    if (op.reserved[0] == 0x0000FFFFu) return;
    U node = op.reserved[1] + op.nodeBase * 0x1C;
    for (U row = op.top; row <= op.bottom; ++row)
        for (U col = op.left; col <= op.right; ++col, node += 0x1C) { MirrorCell(m, (row << log.shift) + col); MirrorNode(m, node); }
}

bool RelinkMirrorApply(RelinkMirror& m, const MoveLog& log, const RelinkDispatcher* dispatcher, U minCells,
                       RelinkApplyStats& stats, RelinkShadowResult& result) {
    result.cells += m.cellCount;
    if (m.overflow) { ++result.refused; return false; }
    // Every node the batch writes was snapshotted by RelinkMirrorTouch before the native service ran.
    const bool parallel = RunBatch(log, &m, dispatcher, minCells, stats);
    if (m.misses) { ++result.refused; return parallel; }
    const MirrorMemory mirror = {m};
    const auto mismatch = [&](U cell, U node) {
        result.lastCell = cell; result.lastRecord = node ? D(node + 0xC) : 0;
    };
    for (U i = 0; i < m.cellCount; ++i) {
        const U cell = m.cellList[i], head = m.heads + 4 * cell;
        U nativeNode = D(head), mirrorNode = mirror.Load(head);
        bool equal = true;
        for (U steps = 0; (nativeNode || mirrorNode) && steps <= m.nodeLimit; ++steps) {
            if (nativeNode != mirrorNode) { equal = false; mismatch(cell, nativeNode ? nativeNode : mirrorNode); break; }
            nativeNode = D(nativeNode + 0x14); mirrorNode = mirror.Load(mirrorNode + 0x14);
        }
        if (!equal) ++result.mismatchCells;
    }
    for (U i = 0; i < m.nodeCount; ++i) {
        const U node = m.nodeList[i];
        if (D(node + 0x10) != mirror.Load(node + 0x10) || D(node + 0x14) != mirror.Load(node + 0x14) ||
            D(node + 0x18) != mirror.Load(node + 0x18)) {
            ++result.mismatchNodes;
            result.lastRecord = D(node + 0xC); result.lastCell = ~0u;
        }
    }
    for (U i = log.batchBegin; i < log.count; ++i) { // +AC: the one record word the batch writes
        U expected;
        if (!MoveLogExpectedCount(log, log.ops[i].record, expected)) continue;
        if (D(log.ops[i].record + 0xAC) != expected) { ++result.mismatchNodes; result.lastRecord = log.ops[i].record; result.lastCell = ~0u; }
    }
    return parallel;
}

} // namespace ntw2_loco
