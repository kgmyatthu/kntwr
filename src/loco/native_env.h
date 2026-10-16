#pragma once
#include <stdint.h>
#include <stddef.h>
#define NTW2_ENV_WORD_LABELS \
 "version", "enabled", "calls", "compared", "mismatches", "faults", "reentry", "shadow_us", \
 "owner", "flag_b4", "flag_b5", "event_inferred_mismatch", "callback_implied", "notification_unobserved", "events_predicted", "events_inferred", \
 "first_entity", "first_call", "first_field", "first_expected", "first_actual", "first_owner", "first_flags", "first_candidate", \
 "leave_predicted", "land_predicted", "secondary_predicted", "notification_predicted", "policy_calls", "policy_replay_faults", "generation", "owner_required"
#ifdef __cplusplus
#include <vector>
#include "native_sweep.h"
namespace ntw2_env {
struct Agent; struct Scratch;
struct Binding { uint32_t image_delta, generation; bool enabled, shadow; };
enum Word : uint32_t { Version, Enabled, Calls, Compared, Mismatches, Faults, Reentry, ShadowUs,
 MismatchOwner, MismatchB4, MismatchB5, MismatchEvent, CallbackImplied, NotificationUnobserved, EventsPredicted, EventsInferred,
 FirstEntity, FirstCall, FirstField, FirstExpected, FirstActual, FirstOwner, FirstFlags, FirstCandidate,
 LeavePredicted, LandPredicted, SecondaryPredicted, NotificationPredicted, PolicyCalls, PolicyReplayFaults, Generation, OwnerRequired, WordCount };
enum class EventKind : uint32_t { Leave = 0x66B0F0, Land = 0x66B2F0, Secondary = 0x66B200, Notification = 8 };
struct Event { EventKind kind; uint32_t receiver, target, args[4], owner; uint8_t b4, b5; };
struct AgentView {
 uint32_t entity, owner, terrain, notification, candidate_index;
 float x, y, z, scalar54, dx, dy, dz;
 uint8_t b4, b5;
 uint32_t transition_targets[3], policy_target, identity_target, notification_target;
};
// Shadow geometry addresses are borrowed views valid for this occurrence.
// Workers use generation-frozen owner planes/rings/adjacency and live pure
// policies, low-u16 visit IDs, and phase-stable read-only terrain.
struct PolicyRead { uint32_t receiver, target, value, position[3]; };
struct Scene { std::vector<uint32_t> candidates; std::vector<PolicyRead> policies; bool capture_policies = false; size_t policy_cursor = 0; };
// Exactly one queue entry per low-u16 ID; no allocation in graph traversal.
struct WorkerScratch {
 uint32_t visited[2048]{};
 std::vector<uint32_t> fifo;
 std::vector<uint16_t> touched;
 uint32_t count = 0, read = 0, touched_count = 0;
 // Exact min(distinct owner count,65536) storage; replaces prior-build capacity.
 void Prepare(size_t ownerCapacity);
 void Clear();
};
struct Result { Event events[2]{}; uint32_t event_count = 0; };
void Capture(Agent*, Scratch*, AgentView&, Scene&);
// Worker context: private scratch only; no scene tape, histogram or diagnostics.
struct WorkerContext {
 uint32_t image_delta = 0, build = 0;
 const ntw2_sweep::WorkerScene* scene = nullptr;
 bool fp_managed = false;
 ntw2_sweep::FpState fp; WorkerScratch scratch; AgentView view{};
};
// Activation only: initializes/prefaults the complete owner-domain traversal scratch.
bool PrepareWorker(WorkerContext&, const ntw2_sweep::WorkerScene&);
size_t HeapBytes(const WorkerContext&);
// agent is the >=0x680-byte participant copy; nativeScratch is three pointers to
// cloned headers, only R0 (count@+12,data@+16) is read. Writes copy +10,+B4,+B5
// only on success. Notification and unclassified policies/targets return false.
// Events carry originalIdentity as receiver and the call-site owner/B4/B5.
bool WorkerEnv(WorkerContext&, void* agent, uint32_t originalIdentity, void* nativeScratch, Result&);
// OWNER THREAD ONLY. Restores call-site owner/B4/B5 on liveAgent, invokes the
// recorded native callback (Leave/Land/Secondary; Notification via packet), then
// applies Leave's post-call B4=1/owner=0. Returns false for unknown target/kind.
bool ReplayEvent(const Event&, void* liveAgent);
void Run(AgentView&, Scene&, WorkerScratch&, Result&);
float SampleTerrain(uint32_t terrain, float x, float z, bool secondary);
bool Start(const Binding&); void Stop(); void Sample(uint32_t words[WordCount], uint32_t targets[64]);
void ShadowBefore(Agent*, Scratch*); void ShadowAfter(); void Abandon();
static_assert(WordCount == 32, "environment status ABI");
}
#endif
