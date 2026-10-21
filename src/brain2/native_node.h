#pragma once
#include <stdint.h>
#define KNTWR_NODE_WORD_LABELS \
 "version", "enabled", "bound", "captures", "admitted", "refused", "constructors", "begins", \
 "steps", "destructors", "comparisons", "matches", "mismatches", "node_mismatches", \
 "owner_mismatches", "event_mismatches", "predicted_arrivals", "predicted_orders", \
 "predicted_requests", "observed_arrivals", "observed_orders", "observed_requests", \
 "projection_calls", "preparation_failures", "reentrant_refusals", "last_owner", \
 "last_operation", "last_mismatch_offset", "last_expected", "last_actual", \
 "workers_blocked", "fake_table_installed"
#define KNTWR_NODE_EVENT_WORD_LABELS \
 "arrival_predicted", "arrival_observed", "arrival_mismatch", \
 "order_predicted", "order_observed", "order_mismatch", \
 "request_predicted", "request_observed", "request_mismatch", \
 "free_predicted", "free_observed", "free_mismatch", \
 "reserved12", "reserved13", "reserved14", "reserved15"
#ifdef __cplusplus
#include <string.h>

// Owner-only differential proof. No function installs the fake table, publishes
// detached bytes, or runs an arrival/order/request transaction a second time.
namespace kntwr_node {
using U = uint32_t;
using B = unsigned char;
constexpr U kWords = 32, kEventWords = 16, kAgentBytes = 0x620;
constexpr U kNodeOffset = 0x22c, kNodeBytes = 0x38, kVirtualSlots = 13;
struct AgentView {
    B* bytes;
    U address;
    template<class T> T Get(U offset) const { T v; memcpy(&v, bytes + offset, sizeof(v)); return v; }
    template<class T> void Set(U offset, T value) const { memcpy(bytes + offset, &value, sizeof(value)); }
};
enum Operation : U { Construct, Begin, Step, Destroy };
enum EventKind : U { Arrival, Order, Request, Free };
struct Event {
    EventKind kind;
    U owner, argument[3];
    U descriptor[5];
    B options[0x1c];
};
struct Services {
    void* context;
    // Every callback runs on the owner before the native occurrence. It must be
    // read-only for the live object graph. Returning false refuses comparison.
    bool (*pose)(void*, U reference, U owner, float planar[2], uint16_t* heading);
    bool (*descriptor)(void*, U reference, U descriptor[5]);
    bool (*materialize)(void*, const U descriptor[5], float xyz[3]);
    // Projection may mutate only its private workspace, never game scratch.
    bool (*project)(void*, U query, const float planar[2], const U reference[5], U output[5]);
};
struct Input {
    B owner[kAgentBytes];
    U ownerAddress, reference, context, argument;
    Operation operation;
    B referenceActive, hasRelated, contextFlag;
    U relatedValue, defaults[3], referenceTable, baseTable, requestSpeed;
    uint16_t defaultHeading, desiredHeading;
    float desired[2], cached[3], distanceThreshold;
    int arrivalThreshold, refreshThreshold;
    U projected[5], referenceDescriptor[5];
    U mxcsr;
    uint16_t fpControl;
    bool prepared;
};
struct Result {
    B owner[kAgentBytes];
    Event events[3];
    U eventCount;
    // One byte per owner byte; native stack/request padding is never compared.
    B defined[kAgentBytes];
};
enum Word : U {
    Version, Enabled, Bound, Captures, Admitted, Refused, Constructors, Begins,
    Steps, Destructors, Comparisons, Matches, Mismatches, NodeMismatches,
    OwnerMismatches, EventMismatches, PredictedArrivals, PredictedOrders,
    PredictedRequests, ObservedArrivals, ObservedOrders, ObservedRequests,
    ProjectionCalls, PreparationFailures, ReentrantRefusals, LastOwner,
    LastOperation, LastMismatchOffset, LastExpected, LastActual, WorkersBlocked,
    FakeTableInstalled
};
// Capture reads native addresses only on the owner at the exact original seam.
// Run touches only Result, using prepared values; it has no live-address reads.
// Construct argument is reference R; Destroy argument is native flags.
// Begin/Step argument is the exact 6758D0 byte argument (1/0 respectively).
bool Capture(U owner, Operation operation, U argument, const Services& services, Input& input);
void Run(const Input& input, Result& result);
bool Compare(const Result& result, const AgentView& originalAfter, U* firstOffset = nullptr);

// Bind supplies pure native preparation; SetServices overrides it for an oracle
// or an admitted owner-side adapter. nullptr restores native preparation.
void Bind(U imageBase);
void SetServices(const Services* services);
void Configure(bool enabled);
void Reset();
void Release();
void Snapshot(U* words /*[32]*/);
void EventSnapshot(U* words /*[16]: predicted/observed/mismatch per kind, reserved*/);
// args points to native stack arguments, NOT return/site/target words.
// Hook only 61DA90, 6758D0 and 624F80; begin/step wrappers naturally reach
// 6758D0 and MUST NOT create a second comparison. Other targets return zero.
// Nonzero token must be paired once with After; originals always run once.
U Before(U originalVA, U receiver, const U* args, const U* cloneEntries);
void After(U token);
void Abandon();
// Observe direct 655B20, 6631A0 and 659520 calls before executing originals.
// Generic gates may also call this for unrelated targets (ignored).
void Observe(U originalVA, U receiver, const U* args);
// Thirteen ABI-valid functions for detached/oracle objects only. The lifecycle
// entries operate on detached AgentView bytes using the currently bound services.
// The returned table address is NEVER written into a live holder by this module.
const U* FakeVtable();
} // namespace kntwr_node
#endif
