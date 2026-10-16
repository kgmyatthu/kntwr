#pragma once
#include <stdint.h>
#define NTW2_ACTION_NODE_WORD_LABELS \
 "version", "enabled", "bound", "captures", "admitted", "refused", "begins", "steps", \
 "comparisons", "matches", "mismatches", "node_mismatches", "owner_mismatches", "event_mismatches", \
 "predicted_events", "observed_events", "phase_checkpoints", "needs_owner", "predicate_needs_owner", \
 "projection_needs_owner", "cold_adjustment_needs_owner", "reentrant_refusals", "last_node", \
 "last_operation", "last_mismatch_offset", "last_expected", "last_actual", "empty_begins", \
 "empty_steps", "private_projection_calls", "workers_blocked", "fake_table_installed"
#define NTW2_ACTION_NODE_EVENT_WORD_LABELS \
 "order_predicted", "order_observed", "setter_predicted", "setter_observed", \
 "request_predicted", "request_observed", "reset_predicted", "reset_observed", \
 "move_predicted", "move_observed", "pose_predicted", "pose_observed", \
 "event_mismatches", "missing_events", "reserved14", "reserved15"
#ifdef __cplusplus
namespace ntw2_action_node {
using U = uint32_t;
using B = unsigned char;
constexpr U kClassCount = 3, kWords = 32, kEventWords = 16;
// Behavioral labels only; the binary supplies no recovered C++ class names.
enum Class : U { DescriptorAction, RelatedStep, RelatedBegin };
enum Operation : U { Begin, Step };
enum Word : U {
 Version, Enabled, Bound, Captures, Admitted, Refused, Begins, Steps,
 Comparisons, Matches, Mismatches, NodeMismatches, OwnerMismatches, EventMismatches,
 PredictedEvents, ObservedEvents, PhaseCheckpoints, NeedsOwnerCount, PredicateNeedsOwner,
 ProjectionNeedsOwner, ColdAdjustmentNeedsOwner, ReentrantRefusals, LastNode,
 LastOperation, LastMismatchOffset, LastExpected, LastActual, EmptyBegins,
 EmptySteps, PrivateProjectionCalls, WorkersBlocked, FakeTableInstalled
};
void Bind(U imageBase);
void Configure(bool enabled);
void Reset();
void Release();
void Abandon();
void Snapshot(U classIndex, U* words /*[32]*/);
void EventSnapshot(U classIndex, U* words /*[16]*/);
// Observe precedes Before at each direct effect seam. The original transaction
// executes once, then After takes the successor checkpoint. No live writes.
U Before(U originalVA, U receiver, const U* args, const U* cloneEntries);
// Required for 444B60: the shared empty RET is a begin only for RelatedStep at
// the four begin sites, a step only for RelatedBegin at the four step sites.
// Never treat a deleting-dtor call to 444B60 as a node operation.
U BeforeSite(U originalVA, U callsiteVA, U receiver, const U* args, const U* cloneEntries);
void Observe(U originalVA, U receiver, const U* args);
void After(U token);
} // namespace ntw2_action_node
#endif
