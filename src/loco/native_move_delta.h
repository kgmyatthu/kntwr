#pragma once
// Site-13 soft-grid relink deltas (MovementSlices Contract 1). `ExtractMoveOp` is the only code that turns a native
// UnlinkGrid 0x811ED0 / InsertGrid 0x7EFA80 occurrence into data; `CoverRecord` is the one copy of the native insert
// coverage arithmetic and is shared with the owned-grid capture. Win32 x86 only (x87 FISTP rounding semantics).
#include <stdint.h>
#include <stddef.h>

namespace ntw2_loco {

enum MoveOpKind : uint8_t { MoveUnlinkGrid = 0, MoveInsertGrid = 1 };
enum MoveOpSource : uint8_t { MoveFromWorker = 0, MoveFromClone = 1 };
struct MoveOp {                 // 32 bytes, appended by the owner in exact native call order
    uint32_t record;            // receiver VA: nodes D(+A8), count D(+AC), pose +48..+5B, +5C bump byte
    uint32_t ordinal;           // worklist ordinal of the occurrence
    uint8_t  kind, source;      // MoveOpKind, MoveOpSource
    uint16_t nodes;             // unlink: D(+AC) before the call; insert: nodes added (= rect area)
    uint32_t nodeBase;          // insert: D(+AC) before the call (first node index); unlink: index into the old-cell side array
    uint16_t left, right, top, bottom; // insert: exact native coverage, inclusive; unlink: 0xFFFF
    // reserved[0]: apply row window, low half = first row, high half = last row (rows of the cells the op writes at
    //   apply; low > high = the op writes nothing: an unlink with no linked node, or an insert cancelled by a later
    //   unlink of the same record in the same batch). reserved[1]: node base address D(record+0xA8) at log time.
    uint32_t reserved[2];
};
static_assert(sizeof(MoveOp) == 32, "MoveOp ABI");

struct MoveDeltaView {
    const MoveOp* ops; uint32_t count;
    const uint32_t* oldCells;   // unlink side array: native cell index per removed node, read at log time from node+0x18
    uint32_t epoch;             // == loco Calls at the producing Stage
    uint32_t complete;          // 1 iff no untapped grid writer ran inside the window (no native-vtable/class-wrapper flush, no serial fallback)
};
// Valid from replay-loop end until the next Stage entry; null when relink mode is off.
// oldCells[op.nodeBase + k] is the cell index of unlink node k as it stood at the START of the op's batch, or
// kMoveNoCell when the node was not linked then (never linked, or already unlinked/relinked earlier in the batch).
const MoveDeltaView* ReadMoveDelta();
constexpr uint32_t kMoveNoCell = 0xFFFFFFFFu;

// ---- exact insert coverage (7EFA80: SSE scale, x87 `fadd st,st; fadd -0.5; fistp; sar 1`, origin, unsigned clamp) ----
// The arithmetic obeys the CALLER's current MXCSR rounding and x87 control word, like the native code does.
struct CoverGeometry {
    float scale;                // grid +0x24
    float bump;                 // [0x1318038] (+0.5): added to the radius when the record's +5C byte is 1
    uint32_t origin, maximum;   // grid +0x10, +0x14
};
struct CoverRect { uint32_t left, right, top, bottom; }; // inclusive; the native loops run rows top..bottom, columns left..right
// One coordinate: unsigned clamp(((fistp(2*(value*scale) - 0.5)) >> 1) + origin, maximum).
uint32_t CoverCoordinate(float value, const CoverGeometry& g);
// x/z = record +48/+50, radius = +58 and bump5c = (byte +5C == 1). left/right = x -/+ r, top = z - r, bottom = r + z with
// r = radius (+ bump when bump5c): the native operation order. Used by InsertGrid extraction AND the grid capture.
CoverRect CoverRecord(float x, float z, float radius, bool bump5c, const CoverGeometry& g);

// ---- the per-stage log ----
enum ExtractResult : uint8_t {
    ExtractLogged,      // appended to the open batch
    ExtractNoop,        // native would write nothing (no nodes / empty footprint); not logged
    ExtractBatchFull,   // open batch has no record-table room: close the batch (flush) and extract again
    ExtractSerial       // unsupported shape or log capacity: close the batch and run the native service serially
};
constexpr uint32_t kMoveBins = 1024;
struct MoveRecordState {        // one slot per record touched by the open batch (stamp-validated, never cleared)
    uint32_t record;
    uint32_t count;             // +AC the record has after the batch's ops
    uint32_t memory;            // nodes [0, memory) still hold their batch-start chain state
    uint16_t stamp, flags;      // flags & 1: the batch holds a live insert of this record
};
static_assert(sizeof(MoveRecordState) == 16, "record state is one quarter cache line");
struct MoveLog {
    MoveOp* ops; uint32_t opCap, count;
    uint32_t* oldCells; uint32_t cellCap, cellCount;
    MoveRecordState* table; uint32_t tableMask, tableLimit, tableUsed;
    uint16_t stamp;
    uint32_t batchBegin;                        // open batch = ops [batchBegin, count)
    // Per row-bin cell-operation weights of the open batch (valid where binStamp == stamp).
    uint32_t weightUnlink[kMoveBins], weightInsert[kMoveBins];
    uint16_t binStamp[kMoveBins];
    uint32_t batchUnlinkCells, batchInsertCells;
    // Grid geometry of the stage, cached by grid pointer (the grid header is immutable while a stage runs).
    uint32_t grid, heads, shift, cells, binShift, bumpAddress;
    uint32_t lastContext, lastRecord; MoveRecordState* lastState; // one-entry caches: the receiver's model context, the previous record's batch state
    CoverGeometry geometry;
    bool geometryOk;
    uint32_t epoch, complete;
    uint32_t collapsed;                         // inserts cancelled by a later unlink of the same record
    unsigned char* block; size_t blockBytes;
    MoveDeltaView view;
};
// Capacity: ops = 3*records + 1024, side array = 2*memberships, record table = 2 * recordsPerBatch slots.
// bumpAddress = VA of the +0.5 constant ([0x1318038] + image delta).
bool MoveLogInit(MoveLog& log, uint32_t records, uint32_t memberships, uint32_t recordsPerBatch, uint32_t bumpAddress);
void MoveLogFree(MoveLog& log);
// Stage entry: empties the log (storage kept), forgets cached geometry, complete = 1, unpublishes the view.
void MoveLogBeginStage(MoveLog& log, uint32_t epoch);
// Opens a new batch after the current one was applied.
void MoveLogCloseBatch(MoveLog& log);
inline uint32_t MoveLogBatchOps(const MoveLog& log) { return log.count - log.batchBegin; }
// Appends occurrence `kind` of `record` to the open batch (reads the record and the grid at their CURRENT native state;
// every earlier op of the batch is deferred). Unlink old cells come from batch-start memory for nodes no earlier op of
// the batch touched. With applyLocal the record-local side effect (+AC) is written exactly like the native service
// would; without it (shadow mode, where the native service still runs afterwards) memory is left untouched.
// Net effect rules:
//  * an unlink cancels every live insert of the same record in the open batch and leaves +AC = 0;
//  * an insert appends at nodeBase = +AC (newest-first prepend, node index = +AC++), with or without an earlier unlink.
ExtractResult ExtractMoveOp(MoveLog& log, uint32_t record, uint32_t ordinal, MoveOpKind kind, MoveOpSource source,
                            bool applyLocal);
// +AC that the open batch implies for `record` once applied (shadow comparison). False = not touched by the open batch.
bool MoveLogExpectedCount(const MoveLog& log, uint32_t record, uint32_t& nodes);
void MoveLogPublish(MoveLog& log);   // makes ReadMoveDelta() return this log's view
void MoveLogUnpublish();

} // namespace ntw2_loco
