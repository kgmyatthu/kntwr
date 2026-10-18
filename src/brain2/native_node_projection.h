#ifndef NTW2_NATIVE_NODE_PROJECTION_H
#define NTW2_NATIVE_NODE_PROJECTION_H
#include <stdint.h>
#include "../clones/ntw2_clones.h"

// Participant-private reference-node path projection (original 0x7FD070 -> 0x81C080 -> 0x81C050 -> 0x67A790).
//
// Source of truth: analysis/native-loco-path-projection.md and tools/generate_clone_specs.py (NODE_PROJ_*). Each
// participant owns a private four-clone chain whose every original static operand -- the 0x15ADB74 query ring, the
// 0x15ADB90 visited bitset, the 0x15AFB90 visited-id vector and the 0x14D0A6C lookup candidate vector -- is rebased onto
// host storage owned here. Warm entry: the TLS epoch/static-init guards and cold atexit tails were removed by pinned
// rewrites, so the native "constructor" is the zero fill that Initialize performs (the originals are BSS).
//
// Participant ownership: one caller thread at a time per participant (index 0 = tick owner, 1..8 = pool workers); a
// participant MUST NOT re-enter its own chain. Participants are independent of each other. World objects (cells, grid,
// surfaces, transforms) are shared and are NOT protected by this scratch. The cell, edge and selected-surface
// dispatches use forwarding gates: ProjectCertified checks their reached closures; Entry alone preserves the old
// unrestricted owner behavior and is not a certificate for worker admission.
namespace ntw2_node {
namespace projection {

constexpr unsigned kParticipants = NTW2_NODE_PROJ_PARTICIPANTS;

// Allocates and zero-constructs the private storage on the first call and writes the NODE_PROJ_VISIT_p and
// NODE_PROJ_LOOKUP_p entries of `bindings` (a table of NTW2_BIND_COUNT entries) -- call before building clones.
// Idempotent while live: later calls with the same imageBase only rewrite the same binding values. A different
// imageBase while live, a null table or a null base returns false. imageBase locates the game allocator for Release.
bool Initialize(uint32_t imageBase, uint32_t* bindings);

// Frees the native backing arrays with the game's own free (0xFF7EF0, per the pinned atexit destructors: element dtor
// 0x444B60 is a pinned RET, then free(data)) and the private storage. Owner thread only, and only when no clone built
// from these bindings can run; published clones keep the binding addresses. Initialize may follow (restart).
void Release();

// Entry point (thiscall, ECX = query receiver, five stack dwords removed by `ret 0x14`, EAX = output):
//   (output descriptor*, desired planar point*, reference descriptor*, mode (3 for the reference node), fallback flag* or 0)
// The output is the 0x14-byte five-dword position descriptor. Returns 0 when not initialised, cloneEntries is null or
// participant >= kParticipants.
uint32_t Entry(const uint32_t* cloneEntries, unsigned participant = 0);

// True when the participant exists and is quiescent: ring and visited-id counts are zero, as every normal return of the
// original leaves them. A false result after an abandoned call means the scratch must not be reused.
bool Ready(unsigned participant = 0);
// Owner-shadow checked call. Only recognized store-free virtual leaves (and
// the recovered 7FF170 cell predicate closure) may execute. Unknown callbacks
// refuse before invocation; private scratch is restored to empty on refusal.
// Other native faults propagate. output is meaningful only on true.
bool ProjectCertified(const uint32_t* cloneEntries, uint32_t query,
                      uint32_t* output, const float* planar, const uint32_t* reference,
                      uint32_t mode, uint32_t* refusedTarget = nullptr, unsigned participant = 0);

// Original descriptor builder 0x7FCFF0 (thiscall ret 0x14; the same five stack dwords; mode 2 forwards to 0x7FD730). It
// touches none of the private projection storage -- its closure is 0x7EAE90, 0x57E870 and 0x7EAD80 -- so no clone exists;
// this is the live address for imageBase, or 0 for a null base.
uint32_t DescriptorEntry(uint32_t imageBase);

} // namespace projection
} // namespace ntw2_node

#endif
