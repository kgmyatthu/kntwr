#pragma once
#include <stdint.h>
#define NTW2_SWEEP_WORD_LABELS \
 "version", "enabled", "graph_compared", "calls", "compared", "r0_mismatches", "r1_mismatches", "r2_mismatches", \
 "faults", "first_entity", "first_call", "first_list", "first_index", "first_expected", "first_actual", "shadow_us", \
 "owner_target0", "owner_target0_calls", "owner_target1", "owner_target1_calls", \
 "edge_target0", "edge_target0_calls", "edge_target1", "edge_target1_calls", \
 "payload20_target0", "payload20_target0_calls", "payload20_target1", "payload20_target1_calls", \
 "other_owner_target0", "other_owner_target0_calls", "other_owner_target1", "other_owner_target1_calls"
#ifdef __cplusplus
#include <vector>
namespace ntw2_sweep {
using U = uint32_t;
constexpr U WordCount = 32;
struct Agent;
struct Scratch;
struct Aabb { float minX, minZ, maxX, maxZ; };
struct Binding { U image_delta, generation; bool enabled; };
struct AgentView { U identity, owner; float x, y, z, extent; };
// Immutable chains retain native order and multiplicity. Equal records and chain
// suffixes are interned; equal adjacent cell heads form runs, including sparse grids.
struct CellRun { U first, last, head; };
struct Scene {
    U generation = 0, model = 0, shift = 0, bias = 0, upper = 0;
    float scale = 0;
    U header[10] = {};
    U cellCount = 0, nativeNodes = 0;
    U gridOwners = 0, capsuleOwners = 0, treeCandidates = 0, wallCandidates = 0, hitCapacity = 0;
    std::vector<CellRun> cells;
    std::vector<U> type, payload, owner, linkNode, linkNext;
    std::vector<U> treeIdentity, treeHead, child[4];
    std::vector<Aabb> treeBounds;
};
// One Work per participant. Prepare resets outputs and reserves outside dispatch;
// Run appends without allocation (declare any seeded prefix in Prepare). This shadow
// adapter reads live owner/edge fields and invokes predicates: OWNER THREAD ONLY.
struct Work {
    U visited[3][2048] = {};
    std::vector<uint16_t> touched[3];
    U touchedCount[3] = {};
    std::vector<U> queue;
    std::vector<U> hits, output[3];
    void Prepare(const Scene& scene, size_t ownerCapacity = 65536, size_t prefixCapacity = 0);
};
// Topology/static geometry are cached per battle build; dynamic bytes are read
// live with the owner blocked during dispatch. Verification runs owner-side only.
struct WorkerOwner {
    U identity, firstEdge;
    float plane[4];
    Aabb bounds;
};
struct WorkerEdge {
    U identity, next;
    float point[2], nextPoint[2];
    std::vector<U> neighbors, neighborEdges;
};
struct VerificationWord { U address, value; };
enum SceneFailure : U { SceneOk, SceneCaptureFailure, SceneVerificationFailure, SceneIdentityFailure };
struct WorkerScene {
    Scene topology;
    U image_delta = 0;
    U grid = 0, tree = 0, root = 0;
    std::vector<WorkerOwner> owners;
    // First attempt pins the identity, even if preparation refuses. Only a new
    // generation may rebuild; a same-generation mismatch stays owner-only.
    bool attempted = false, built = false;
    U model = 0, generation = 0, build = 0;
    std::vector<WorkerEdge> edges;
    // Activation-only complete checks: topology, owner geometry, adjacency,
    // resolve geometry. No rotating verification or worker-side native scans.
    mutable std::vector<VerificationWord> verification[4];
    mutable SceneFailure failure = SceneOk;
    mutable U failureAddress = 0, failureActual = 0;
};
struct FpState { U mxcsr = 0; uint16_t control = 0; };
// Owner-side capture of the game's complete SSE/x87 control state. Per-port
// install/restore is bypassed only when WorkerContext::fp_managed is true.
FpState CaptureFp();
void ApplyFp(const FpState&);
// Adapter refusal (unsupported path/capacity) raises this and is converted to false;
// every other structured exception propagates to the orchestrator.
constexpr U WorkerRefusal = 0xE0425480;
int RefusalFilter(unsigned long code);
// Ready for WorkerSweep: reserves retained output capacity and captures owner FP state.
struct WorkerContext {
    const WorkerScene* scene = nullptr; U build = 0;
    bool fp_managed = false;
    FpState fp; Work work;
};
// First call per generation imports and verifies every static word. Later calls
// only check the pinned identity and fixed header/root; mismatch never rebuilds.
bool PrepareScene(WorkerScene&, U model, U imageDelta, U generation);
// Same scene/build: refresh FP only; reservation happens once per build.
bool PrepareWorker(WorkerContext&, const WorkerScene&);
// Retained dynamic bytes only; containing object storage is counted by its owner.
size_t HeapBytes(const WorkerScene&);
size_t HeapBytes(const WorkerContext&);
// Native chain occurrences (not interned records), owner closure, tree entries.
void SampleCounts(const WorkerScene&, U counts[3]);
// R0: grid low-u16 domain + un-deduped tree entries + graph low-u16 domain;
// R1: capsule low-u16 domain; R2: un-deduped wall occurrences.
void CandidateCapacities(const Scene&, size_t ownerCapacity, size_t output[3]);
// Owner-only: collect and verify all static words during activation.
void VerifyOnBuild(const WorkerScene&, U group, U address, size_t bytes);
bool VerifyBuild(const WorkerScene&, U firstGroup, U groupCount);
// Only after the complete scene+resolve activation check; no tick needs this tape.
void ReleaseBuildVerification(const WorkerScene&);
// False leaves all caller ABI headers unchanged. Scratch is three header pointers.
bool WorkerSweep(WorkerContext&, const void* agent, U originalIdentity,
    void* nativeScratch, const Aabb&, U mode);
// Closed no-argument byte getters only; no histogram, TLS or native scratch.
bool PureByteTarget(U target, U imageDelta);
bool PureAgentTarget(U agent, U target, U imageDelta);
uint8_t PureByte(U receiver, U target, U imageDelta);
bool Capture(Scene& scene, U model, U generation);
void Run(const Scene& scene, const AgentView& agent, const Aabb& bounds, U mode, Work& work);
bool Start(const Binding& binding);
void Stop();
void Sample(U* words);
void Abandon();
// Lazy owner activation: runtime Start has no battle model. First owner Stage captures it before MOVE.
void Activate(U model);
void ShadowBefore(Agent*, Scratch*, const Aabb*, U mode);
void ShadowAfter();
static_assert(WordCount == 32, "sweep diagnostics are append-only");
}
#endif
