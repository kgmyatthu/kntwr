#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <xmmintrin.h>
#include "native_move_delta.h"

static_assert(sizeof(void*) == 4, "native relink log is a Win32 x86 adapter");

namespace ntw2_loco {
namespace {
using U = uint32_t;
inline U D(U address) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(address)); }
inline uint8_t B(U address) { return *reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(address)); }
inline float F(U address) { return *reinterpret_cast<const float*>(static_cast<uintptr_t>(address)); }
inline void Store(U address, U value) { *reinterpret_cast<U*>(static_cast<uintptr_t>(address)) = value; }
inline float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline U Hash(U record, U mask) { return ((record >> 4) * 2654435761u >> 12) & mask; }
inline U Window(U lo, U hi) { return lo | (hi << 16); }
constexpr U kDeadWindow = 0x0000FFFFu; // low > high: writes nothing (maximum row is <= 0xFFFE)
const MoveDeltaView* g_published;
unsigned long long Align(unsigned long long v) { return (v + 63) & ~63ull; }
} // namespace

uint32_t CoverCoordinate(float value, const CoverGeometry& g) {
    float scaled = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(value), _mm_set_ss(g.scale))), half = -0.5f;
    int rounded;
    __asm { fld scaled }
    __asm { fadd st(0), st(0) }
    __asm { fadd half }
    __asm { fistp rounded }
    const U coordinate = static_cast<U>(rounded >> 1) + g.origin;
    return coordinate < g.maximum ? coordinate : g.maximum;
}

CoverRect CoverRecord(float x, float z, float radius, bool bump5c, const CoverGeometry& g) {
    const float r = bump5c ? Add(radius, g.bump) : radius;
    CoverRect rect;
    rect.left = CoverCoordinate(Sub(x, r), g);
    rect.right = CoverCoordinate(Add(x, r), g);
    rect.top = CoverCoordinate(Sub(z, r), g);
    rect.bottom = CoverCoordinate(Add(r, z), g);
    return rect;
}

const MoveDeltaView* ReadMoveDelta() { return g_published; }

namespace {
bool LoadGeometry(MoveLog& log, U grid) {
    log.grid = grid;
    log.heads = D(grid); log.shift = D(grid + 8);
    log.geometry.origin = D(grid + 0x10); log.geometry.maximum = D(grid + 0x14);
    log.geometry.scale = F(grid + 0x24); log.geometry.bump = F(log.bumpAddress);
    // Coordinates must fit the 16-bit MoveOp fields and every cell (z << shift) + x must be a valid head slot.
    log.geometryOk = log.heads && log.shift <= 20 && log.geometry.maximum < (1u << log.shift) && log.geometry.maximum <= 0xFFFEu;
    if (!log.geometryOk) return false;
    log.cells = (log.geometry.maximum << log.shift) + log.geometry.maximum + 1;
    log.binShift = 0;
    while ((log.geometry.maximum >> log.binShift) >= kMoveBins) ++log.binShift;
    return true;
}
// The soft grid of `record`'s model exactly as 7EFA80 reaches it: [[[record+28]+8]+A4].
bool EnsureGeometry(MoveLog& log, U record) {
    const U context = D(record + 0x28);
    if (context == log.lastContext && log.grid) return log.geometryOk;
    if (!context) return false;
    log.lastContext = context;
    const U model = D(context + 8);
    if (!model) return false;
    const U grid = D(model + 0xA4);
    if (!grid) return false;
    return grid == log.grid ? log.geometryOk : LoadGeometry(log, grid);
}
// The open batch's state of `record`; `found` tells whether the slot already belongs to it.
MoveRecordState* Find(MoveLog& log, U record, bool& found) {
    if (record == log.lastRecord && log.lastState && log.lastState->stamp == log.stamp && log.lastState->record == record) { found = true; return log.lastState; }
    log.lastRecord = record;
    for (U h = Hash(record, log.tableMask);; h = (h + 1) & log.tableMask) {
        MoveRecordState& s = log.table[h];
        if (s.stamp != log.stamp) { found = false; log.lastState = &s; return &s; }
        if (s.record == record) { found = true; log.lastState = &s; return &s; }
    }
}
void Claim(MoveLog& log, MoveRecordState& s, U record, U count) {
    s.record = record; s.count = s.memory = count; s.stamp = log.stamp; s.flags = 0;
    ++log.tableUsed;
}
inline void TouchBin(MoveLog& log, U bin) {
    if (log.binStamp[bin] != log.stamp) { log.binStamp[bin] = log.stamp; log.weightUnlink[bin] = log.weightInsert[bin] = 0; }
}

ExtractResult ExtractUnlink(MoveLog& log, U record, U ordinal, MoveOpSource source, bool applyLocal) {
    const U n = D(record + 0xAC);
    if (!n) return ExtractNoop; // the native loop is empty and +AC stays 0
    const U base = D(record + 0xA8);
    if (!base || n > 0xFFFFu || !EnsureGeometry(log, record)) return ExtractSerial;
    if (log.count == log.opCap || log.cellCount + n > log.cellCap) return ExtractSerial;
    bool found;
    MoveRecordState* const state = Find(log, record, found);
    if (!found && log.tableUsed >= log.tableLimit) return ExtractBatchFull;
    // Nodes [0, memory) still hold their batch-start chain state. The others were added by deferred inserts of this
    // batch: they are not linked in memory and are cancelled below, so there is nothing to unlink for them.
    const U memory = found ? (state->memory < n ? state->memory : n) : n;
    U* const cells = log.oldCells + log.cellCount;
    U lo = 0xFFFFu, hi = 0, linked = 0;
    for (U k = 0; k < n; ++k) {
        cells[k] = kMoveNoCell;
        if (k >= memory) continue;
        const U cell = D(base + k * 0x1C + 0x18);
        if (!cell) continue;
        const U offset = cell - log.heads;
        if ((offset & 3) || (offset >> 2) >= log.cells) return ExtractSerial;
        const U index = offset >> 2, row = index >> log.shift;
        cells[k] = index; ++linked;
        if (row < lo) lo = row;
        if (row > hi) hi = row;
    }
    for (U k = 0; k < memory; ++k) if (cells[k] != kMoveNoCell) {
        const U bin = (cells[k] >> log.shift) >> log.binShift;
        TouchBin(log, bin); ++log.weightUnlink[bin];
    }
    log.batchUnlinkCells += linked;
    if (!found) Claim(log, *state, record, n);
    else if (state->flags & 1) {
        // Cancel the live inserts of this record in the batch: the unlink removes the nodes they add.
        for (U j = log.batchBegin; j < log.count; ++j) {
            MoveOp& op = log.ops[j];
            if (op.record != record || op.kind != MoveInsertGrid || op.reserved[0] == kDeadWindow) continue;
            const U width = op.right - op.left + 1u;
            for (U row = op.top; row <= op.bottom; ++row) { const U bin = row >> log.binShift; log.weightInsert[bin] -= width; }
            log.batchInsertCells -= op.nodes;
            op.reserved[0] = kDeadWindow; ++log.collapsed;
        }
    }
    state->count = 0; state->memory = 0; state->flags &= ~1u;
    MoveOp& op = log.ops[log.count++];
    op.record = record; op.ordinal = ordinal; op.kind = MoveUnlinkGrid; op.source = source;
    op.nodes = static_cast<uint16_t>(n); op.nodeBase = log.cellCount;
    op.left = op.right = op.top = op.bottom = 0xFFFF;
    op.reserved[0] = linked ? Window(lo, hi) : kDeadWindow; op.reserved[1] = base;
    log.cellCount += n;
    if (applyLocal) Store(record + 0xAC, 0);
    return ExtractLogged;
}

ExtractResult ExtractInsert(MoveLog& log, U record, U ordinal, MoveOpSource source, bool applyLocal) {
    if (!EnsureGeometry(log, record)) return ExtractSerial;
    const CoverRect r = CoverRecord(F(record + 0x48), F(record + 0x50), F(record + 0x58), B(record + 0x5C) == 1, log.geometry);
    if (r.left > r.right || r.top > r.bottom) return ExtractNoop; // empty footprint: the native loops never write
    const U width = r.right - r.left + 1, height = r.bottom - r.top + 1;
    const unsigned long long area = static_cast<unsigned long long>(width) * height;
    const U base = D(record + 0xA8), ac = D(record + 0xAC);
    if (area > 0xFFFFu || !base || ac + static_cast<U>(area) > D(record + 0xB0) || log.count == log.opCap) return ExtractSerial;
    bool found;
    MoveRecordState* const state = Find(log, record, found);
    if (!found && log.tableUsed >= log.tableLimit) return ExtractBatchFull;
    if (!found) Claim(log, *state, record, ac);
    for (U row = r.top; row <= r.bottom; ++row) {
        const U bin = row >> log.binShift;
        TouchBin(log, bin); log.weightInsert[bin] += width;
    }
    log.batchInsertCells += static_cast<U>(area);
    state->count = ac + static_cast<U>(area); state->flags |= 1;
    MoveOp& op = log.ops[log.count++];
    op.record = record; op.ordinal = ordinal; op.kind = MoveInsertGrid; op.source = source;
    op.nodes = static_cast<uint16_t>(area); op.nodeBase = ac;
    op.left = static_cast<uint16_t>(r.left); op.right = static_cast<uint16_t>(r.right);
    op.top = static_cast<uint16_t>(r.top); op.bottom = static_cast<uint16_t>(r.bottom);
    op.reserved[0] = Window(r.top, r.bottom); op.reserved[1] = base;
    if (applyLocal) Store(record + 0xAC, ac + static_cast<U>(area));
    return ExtractLogged;
}
} // namespace

bool MoveLogInit(MoveLog& log, uint32_t records, uint32_t memberships, uint32_t recordsPerBatch, uint32_t bumpAddress) {
    MoveLogFree(log);
    if (!records || !memberships || !recordsPerBatch || !bumpAddress) return false;
    const unsigned long long opCap = 3ull * records + 1024, cellCap = 2ull * memberships;
    unsigned long long tableSize = 1024;
    while (tableSize < 2ull * recordsPerBatch) tableSize <<= 1;
    const unsigned long long bytes = Align(opCap * sizeof(MoveOp)) + Align(cellCap * 4) + Align(tableSize * sizeof(MoveRecordState));
    if (bytes > 0x7FFFFFFFull) return false;
    unsigned char* const block = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(bytes), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!block) return false;
    for (size_t at = 0; at < bytes; at += 4096) block[at] = 0; // commit every page before the first stage
    log = MoveLog{};
    log.block = block; log.blockBytes = static_cast<size_t>(bytes);
    size_t at = 0;
    log.ops = reinterpret_cast<MoveOp*>(block + at); at += static_cast<size_t>(Align(opCap * sizeof(MoveOp)));
    log.oldCells = reinterpret_cast<U*>(block + at); at += static_cast<size_t>(Align(cellCap * 4));
    log.table = reinterpret_cast<MoveRecordState*>(block + at);
    log.opCap = static_cast<U>(opCap); log.cellCap = static_cast<U>(cellCap);
    log.tableMask = static_cast<U>(tableSize - 1); log.tableLimit = recordsPerBatch;
    log.stamp = 1; log.bumpAddress = bumpAddress;
    return true;
}

void MoveLogFree(MoveLog& log) {
    if (g_published == &log.view) g_published = nullptr;
    if (log.block) VirtualFree(log.block, 0, MEM_RELEASE);
    log = MoveLog{};
}

void MoveLogBeginStage(MoveLog& log, uint32_t epoch) {
    log.count = log.cellCount = 0;
    log.grid = 0; log.lastContext = log.lastRecord = 0; log.lastState = nullptr; log.geometryOk = false; log.epoch = epoch; log.complete = 1; log.collapsed = 0;
    g_published = nullptr; // a view is invalid from Stage entry onward
    log.batchBegin = 0;
    MoveLogCloseBatch(log);
}

void MoveLogCloseBatch(MoveLog& log) {
    log.batchBegin = log.count;
    log.batchUnlinkCells = log.batchInsertCells = 0;
    log.tableUsed = 0; log.lastRecord = 0; log.lastState = nullptr;
    if (++log.stamp == 0xFFFFu) { // stamps wrapped: clear every stamped table
        memset(log.table, 0, static_cast<size_t>(log.tableMask + 1) * sizeof(MoveRecordState));
        memset(log.binStamp, 0, sizeof(log.binStamp));
        log.stamp = 1;
    }
}

ExtractResult ExtractMoveOp(MoveLog& log, uint32_t record, uint32_t ordinal, MoveOpKind kind, MoveOpSource source, bool applyLocal) {
    return kind == MoveUnlinkGrid ? ExtractUnlink(log, record, ordinal, source, applyLocal)
                                  : ExtractInsert(log, record, ordinal, source, applyLocal);
}

bool MoveLogExpectedCount(const MoveLog& log, uint32_t record, uint32_t& nodes) {
    for (U h = Hash(record, log.tableMask);; h = (h + 1) & log.tableMask) {
        const MoveRecordState& s = log.table[h];
        if (s.stamp != log.stamp) return false;
        if (s.record == record) { nodes = s.count; return true; }
    }
}

void MoveLogPublish(MoveLog& log) {
    log.view = {log.ops, log.count, log.oldCells, log.epoch, log.complete};
    g_published = &log.view;
}
void MoveLogUnpublish() { g_published = nullptr; }

} // namespace ntw2_loco
