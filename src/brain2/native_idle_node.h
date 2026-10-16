#pragma once
#include <stdint.h>
#define NTW2_IDLE_NODE_WORD_LABELS \
 "version", "enabled", "bound", "captures", "admitted", "refused", "constructors", "begins", \
 "steps", "destructors", "comparisons", "matches", "mismatches", "node_mismatches", \
 "owner_mismatches", "event_mismatches", "predicted_orders", "predicted_stops", \
 "predicted_actions", "observed_orders", "observed_stops", "observed_actions", \
 "phase_checkpoints", "needs_owner", "reentrant_refusals", "last_node", \
 "last_operation", "last_mismatch_offset", "last_expected", "last_actual", \
 "workers_blocked", "fake_table_installed"
#define NTW2_IDLE_NODE_EVENT_WORD_LABELS \
 "order_predicted", "order_observed", "order_mismatch", \
 "stop_predicted", "stop_observed", "stop_mismatch", \
 "action_predicted", "action_observed", "action_mismatch", \
 "predicate_needs_owner", "rng_draws", "weighted_draws", \
 "owner_write_checks", "reserved13", "reserved14", "reserved15"
#ifdef __cplusplus
namespace ntw2_idle_node {
using U = uint32_t;
using B = unsigned char;
// Stable class order: 133405C / 66DD10, then 1334028 / 66DCF0.
constexpr U kClassCount = 2, kWords = 32, kEventWords = 16;
enum Word : U {
    Version, Enabled, Bound, Captures, Admitted, Refused, Constructors, Begins,
    Steps, Destructors, Comparisons, Matches, Mismatches, NodeMismatches,
    OwnerMismatches, EventMismatches, PredictedOrders, PredictedStops,
    PredictedActions, ObservedOrders, ObservedStops, ObservedActions,
    PhaseCheckpoints, NeedsOwnerCount, ReentrantRefusals, LastNode,
    LastOperation, LastMismatchOffset, LastExpected, LastActual, WorkersBlocked,
    FakeTableInstalled
};
void Bind(U imageBase);
void Configure(bool enabled);
void Reset();
void Release();
void Abandon();
void Snapshot(U classIndex, U* words /*[32]*/);
void EventSnapshot(U classIndex, U* words /*[16]*/);
// Original transactions always execute once. Observe precedes Before at direct
// 662E70(node,order,mode,flag), 6669B0(owner,flag), 6666E0(owner,id,1,0,1.0f).
// Before/After bracket these transactions for successor owner checkpoints.
// Shared begin/destructor entrypoints silently ignore other concrete vtables.
U Before(U originalVA, U receiver, const U* args, const U* cloneEntries);
void Observe(U originalVA, U receiver, const U* args);
void After(U token);
} // namespace ntw2_idle_node
#endif
