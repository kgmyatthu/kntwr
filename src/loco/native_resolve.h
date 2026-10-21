#pragma once
#include <stdint.h>
#include <stddef.h>

#define KNTWR_RESOLVE_WORD_LABELS \
    "version", "enabled", "calls", "compared", "mismatches", "faults", "reentry", "shadow_us", \
    "dx", "dz", "flag_13c", "flag_174", "flag_175", "flag_176", "flag_199", "flag_1a8", \
    "return", "first_entity", "first_call", "first_field", "first_expected", "first_actual", \
    "first_candidate", "first_pass", "target0", "target0_calls", "target1", "target1_calls", \
    "target2", "target2_calls", "other_target_calls", "inout"

// Separate append-only status tail: do not enlarge the existing 32-word block.
#define KNTWR_RESOLVE_FRAME_LABELS \
    "owner_handoffs", "nested_calls", "max_depth", "overlapping_thread_calls"

#ifdef __cplusplus
#include <vector>
#include "native_sweep.h"
namespace kntwr_resolve {
struct Agent;
struct Scratch;
struct Aabb { float min_x, min_z, max_x, max_z; };
struct Binding { uint32_t image_delta, generation; bool enabled; };
enum Word : uint32_t {
    Version, Enabled, Calls, Compared, Mismatches, Faults, Reentry, ShadowUs,
    MismatchDx, MismatchDz, Mismatch13C, Mismatch174, Mismatch175, Mismatch176,
    Mismatch199, Mismatch1A8, MismatchReturn, FirstEntity, FirstCall, FirstField,
    FirstExpected, FirstActual, FirstCandidate, FirstPass,
    Target0, Target0Calls, Target1, Target1Calls, Target2, Target2Calls,
    OtherTargetCalls, MismatchInout, WordCount
};
enum FrameWord : uint32_t {
    OwnerHandoffs, NestedCalls, MaxDepth, OverlappingThreadCalls, FrameWordCount
};
// Arithmetic and flag updates use this owned snapshot. Shadow predicates remain
// owner-thread calls; workers admit only the recovered read-only closures.
struct AgentView {
    uint32_t entity, owner, state18, flags110, transform160, flag188, context1f0;
    float x, y, z, radius, dx, dy, dz, transformed_x, transformed_z;
    uint16_t heading;
    uint8_t radius_extra5c, flag117, flag13c, flag174, flag175, flag176;
    uint8_t flag199, flag1a8, result_b6;
    uint8_t inout, result, agent_predicate;
    bool has_shape;
    float shape_radii[256];
    // Worker-only borrowed table: shape construction is stable while the owner
    // is blocked. Shadow Capture keeps the owned array for later comparison.
    const float* live_shape_radii = nullptr;
    uint32_t candidate_index, pass;
    int32_t angle_limit;
    uint32_t output_candidate[10], output_pass[10]; // last value-changing step; ~0 if unchanged
};
struct Point { float x, z; };
struct Segment { Point a, b; };
struct Endpoint { Point point, normal; uint32_t type; uint8_t flag; };
struct PolygonPoint { Point point, normal; };
// A native +8 cycle is stored once. Each candidate retains its own starting
// node, so traversal and wraparound have exactly the original order. Offsets
// (not pointers) keep copied/moved snapshots independent of their source.
struct CycleRange {
    uint32_t offset = 0, count = 0, first = 0;
    uint32_t Index(uint32_t i) const {
        const uint32_t n = first + i;
        return offset + (n < count ? n : n - count);
    }
};
struct Capsule {
    uint32_t native, owner, eligible_target, secondary_target;
    Point point, tangent, normal, alternate_normal;
    Endpoint a, b;
    uint32_t type;
    uint8_t flag;
    CycleRange polygon;
    uint32_t endpoint_a, endpoint_b; // frozen identities; endpoint flags stay live
};
struct Edge {
    uint32_t native, predicate_target;
    Point point, next, tangent, normal, alternate_normal;
    float radius_cap;
    uint8_t blocking;
};
struct Ring { uint32_t native; float plane[4]; CycleRange edges; };
struct Wall { uint32_t native; Segment segment; };
struct Candidates {
    std::vector<Ring> rings;
    std::vector<Capsule> capsules;
    std::vector<Wall> walls;
    std::vector<Edge> edges;
    std::vector<PolygonPoint> polygon_points;
    uint32_t edge_cycles = 0, polygon_cycles = 0;
};
// Snapshot preserves native sweep order, duplicates, and ring boundaries.
void Capture(Agent* agent, Scratch* scratch, AgentView& view, Candidates& candidates);
// Mutates only the private view. Native predicates run on the owner thread;
// the return byte is also in view.result, not committed to agent+B6.
uint8_t Run(AgentView& view, const Candidates& candidates, const Aabb& box);
// Immutable geometry for every ring, capsule and wall reachable from one prepared
// sweep scene. Built by the owner and shared read-only by all worker contexts.
struct WorkerCatalog {
    uint32_t image_delta = 0, build = 0, generation = 0;
    size_t reserve[3]{}; // distinct-domain R0/R1 bounds; R2 preserves wall multiplicity
    bool attempted = false, prepared = false;
    const kntwr_sweep::WorkerScene* source = nullptr;
    Candidates geometry; // each list sorted by native address, duplicates removed
};
struct WorkerCandidates {
    std::vector<const Ring*> rings;
    std::vector<const Capsule*> capsules;
    std::vector<const Wall*> walls;
};
struct WorkerContext {
    const WorkerCatalog* catalog = nullptr;
    kntwr_sweep::FpState fp;
    uint32_t build = 0;
    bool fp_managed = false;
    // Off by default: 0x80E9D0 reads the +0x170 transform parent outside the copy.
    bool allow_foreign_transform = false;
    WorkerCandidates selected;
    AgentView view{};
};
// First call verifies the complete static catalog at activation. Same identity
// is O(1); mismatches refuse without rebuilding until the generation changes.
bool PrepareCatalog(WorkerCatalog&, const kntwr_sweep::WorkerScene&);
bool PrepareWorker(WorkerContext&, const WorkerCatalog&);
// Activation-cached diagnostic tail: five allocated byte totals followed by
// the five logical counts, in ring/capsule/wall/edge/polygon-point order.
enum : uint32_t { CatalogStorageWordCount = 10 };
void SampleCatalogStorage(const WorkerCatalog&, uint32_t out[CatalogStorageWordCount]);
size_t HeapBytes(const WorkerCatalog&);
size_t HeapBytes(const WorkerContext&);
// agent is the >=0x680-byte participant copy; originalIdentity is only recorded.
// nativeScratch is three pointers to the cloned R0/R1/R2 headers (read only).
// False leaves agent unchanged (unsupported); real faults propagate. On success writes D4/DC,
// 13C/174/175/176/199/1A8, and sets B6=1 only when the original would return 1.
bool WorkerResolve(WorkerContext&, void* agent, uint32_t originalIdentity,
    void* nativeScratch, const Aabb&, uint8_t& result);
bool Start(const Binding& binding);
void Stop();
void Sample(uint32_t words[WordCount]);
void SampleFrames(uint32_t words[FrameWordCount]);
void ShadowBefore(Agent* agent, Scratch* scratch, const Aabb* box);
void ShadowAfter(uint8_t originalReturn);
// Capture byte[original entry ESP+4] before the exit thunk reuses the stack.
void ObserveOriginalInout(uint8_t originalInout);
void Abandon();
static_assert(WordCount == 32, "resolve diagnostics are append-only");
static_assert(FrameWordCount == 4, "resolve frame diagnostics are append-only");
}
#endif
