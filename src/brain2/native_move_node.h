#pragma once
#include <stdint.h>
#define KNTWR_MOVE_NODE_WORD_LABELS \
 "version", "enabled", "bound", "captures", "admitted", "refused", "constructors", "begins", \
 "steps", "destructors", "comparisons", "matches", "mismatches", "node_mismatches", \
 "owner_mismatches", "event_mismatches", "predicted_orders", "predicted_setters", \
 "predicted_requests", "observed_orders", "observed_setters", "observed_requests", \
 "phase_checkpoints", "needs_owner", "reentrant_refusals", "last_node", \
 "last_operation", "last_mismatch_offset", "last_expected", "last_actual", \
 "workers_blocked", "fake_table_installed"
#define KNTWR_MOVE_NODE_EVENT_WORD_LABELS \
 "order_predicted", "order_observed", "order_mismatch", \
 "setter_predicted", "setter_observed", "setter_mismatch", \
 "request_predicted", "request_observed", "request_mismatch", \
 "projection_needs_owner", "predicate_needs_owner", "cold_adjustment_needs_owner", \
 "private_projection_calls", "last_projection_refusal_target", "reserved14", "reserved15"
#ifdef __cplusplus
#include <string.h>
namespace kntwr_move_node {
using U = uint32_t;
using B = unsigned char;
constexpr U kWords = 32, kEventWords = 16, kNodeBytes = 0x48;
enum Operation : U { Construct, Begin, Step, Destroy };
enum Phase : U { Entry, OrderReturned, SetterReturned, RequestReturned };
enum EventKind : U { Order, Setter, Request };
enum Reason : U { Ready, WrongNode, NeedsOwner, NeedsProjection, NeedsColdAdjustment };
// Recovered owner-side preparation shared by concrete node ports. Bind once
// before use; callers preserve the native FP environment around preparation.
bool First(U owner);
bool Second(U owner, B& value);
U AdjustOrder(U owner, U order, U mode);
bool AdjustmentScale(U group, float& scale);
Reason AdjustDescriptor(U owner, const U reference[5], const U* cloneEntries,
                        U output[5], U* projectionCalls = nullptr, U* refusedTarget = nullptr);
struct Event {
    EventKind kind;
    U receiver, argument[3], argumentMask[3];
    U descriptor[5];
    B options[0x1c], optionsDefined[0x1c];
};
// Each phase begins with a fresh owner-side checkpoint AFTER the preceding
// original effect. Run is pure: it never dereferences native addresses.
struct Input {
    B node[kNodeBytes], constructor[0x2a];
    U nodeAddress, ownerAddress, table, baseTable, holder, context, argument;
    U orderState, movementState, selectedOrder, descriptor[5];
    U ownerFlags[2], ownerRestore;
    uint16_t defaultHeading;
    B firstPredicate, secondPredicate;
    Operation operation;
    Phase phase;
    Reason reason;
};
struct OwnerWrite { U address, value, width; };
struct Result {
    B node[kNodeBytes];
    Event event;
    bool hasEvent;
    OwnerWrite ownerWrites[6];
    U ownerWriteCount;
};
enum Word : U {
    Version, Enabled, Bound, Captures, Admitted, Refused, Constructors, Begins,
    Steps, Destructors, Comparisons, Matches, Mismatches, NodeMismatches,
    OwnerMismatches, EventMismatches, PredictedOrders, PredictedSetters,
    PredictedRequests, ObservedOrders, ObservedSetters, ObservedRequests,
    PhaseCheckpoints, NeedsOwnerCount, ReentrantRefusals, LastNode,
    LastOperation, LastMismatchOffset, LastExpected, LastActual, WorkersBlocked,
    FakeTableInstalled
};
Reason Capture(U node, Operation operation, Phase phase, const U* args,
               const U* cloneEntries, Input& input);
void Run(const Input& input, Result& result);
bool EqualEvent(const Event& expected, const Event& actual);
void Bind(U imageBase);
void Configure(bool enabled);
void Reset();
void Release();
void Abandon();
void Snapshot(U* words /*[32]*/);
void EventSnapshot(U* words /*[16]*/);
// Hook hot ctor 7E2C80, begin 816900, step 819310, dtor 7EDD00.
// Also call Before/After for DIRECT hot effect seams 662E70, 662E50, 659520:
// their successor checkpoints are essential (order may change later inputs).
// Observe must run BEFORE Before at those three direct seams. Pass the original
// receiver (node for order/setter, owner for request), not a normalized owner.
// Descendants of an active effect are ignored; never observe the nested 6631A0
// a second time. Nonzero tokens must be paired once; originals always run once.
U Before(U originalVA, U receiver, const U* args, const U* cloneEntries);
void After(U token);
void Observe(U originalVA, U receiver, const U* args);
} // namespace kntwr_move_node
#endif
