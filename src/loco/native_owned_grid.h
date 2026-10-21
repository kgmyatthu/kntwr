#pragma once
#include <stdint.h>

namespace kntwr_loco {
// Borrowed immutable publication. Lifetime ends at the next Stage entry,
// CaptureGrid attempt (including refusal), or Stop: every array is rewritten in place by the next
// build (only record/serial/incarnation/active/inserted identity is double-buffered across epochs).
// Primary slots (including null holes) retain registry indices; unique secondary records follow.
// Bounds are inclusive and inserted==0 means absent. Compact rows are ordered by ascending native
// cell id; occupants of a row ascend by record slot. Collision captures mutable
// eligibility/numerics at its own stage entry.
struct GridView {
    uint32_t generation, epoch, count, cells, memberships;
    const uint32_t *record, *serial, *incarnation, *team, *flags;
    const float *x, *z, *y, *extent, *radius;
    const uint32_t *left, *right, *top, *bottom, *inserted;
    const uint32_t *cell_ids, *offsets, *occupants;
    const uint32_t* active;
    uint32_t manager, model, tick, primary_count, secondary_count;
    uint32_t primary_registry, secondary_registry;
    uint32_t grid, native_cells, cell_count, row_shift, origin, maximum;
    float inverse_scale;
    // Direct-address cell -> compact occupied-cell index + 1 (zero = empty), one word per native cell
    // (cell_count words). The build uses bit 31 of these words as a transient tally; published values never carry it.
    const uint32_t* cell_dense;
    const uint32_t* node_type;
};
}
