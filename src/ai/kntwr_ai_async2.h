#ifndef KNTWR_AI_ASYNC2_H
#define KNTWR_AI_ASYNC2_H
// KNTWR_AI_ASYNC2: whole native planner calls (0x7D99F0) run on the dedicated AI worker in the inter-tick window.
//
// Boundary schedule (analysis/native-ai-async2-fixed.md; contract analysis/native-ai-async-consistency.md §5.1):
//   * site 34 of tick N queues (planner, flag) in call order and returns without running the planner. The planner is
//     incremental: the delayed call is the approved AI-order latency. Every call is queued exactly once; nothing is
//     admitted or skipped on wall-clock timing. The queue cap is a deterministic function of call order, not of progress.
//   * the tick-end seam hands the staged batch to the worker. The worker runs the queued calls in order during the
//     inter-tick window with its private walk/observer clone family (no shared scratch).
//   * the next tick's START is a BLOCKING join (lifetime barrier): no think ever crosses into a tick, so every tick-side
//     owner teardown -- including the direct-call routes into 0x8254D0/0x69C720 that no slot can gate -- runs after the
//     think returned (the 0x7D99F0 _purecall class). The join services worker calls while it waits. Its stall is
//     reported separately (seam_stalls, seam_wait_sum_us, seam_wait_max_us): it is the cost of a think longer than the
//     inter-tick window. With this seam the schedule is deterministic with respect to tick boundaries.
//   * tick-side joins (site 33, TICK 57DFDF, tick-owner gates) remain as a second line; they find nothing in flight
//     except after a capacity drain.
//   * vtable-slot gates (pinned original words, the runtime's ordinary Slot machinery): delegate replacement
//     0x6EA520/0x6B3010, delegate destructors 0x69D710/0x69D750, command callbacks 0x805CE0/0x7DEC70, and the owner
//     deleting destructors that tear down an observer/operation graph (seven observer tables slot 2, the five
//     operation tables slot 26; list in kntwr_ai_async2.cpp).
//       - non-tick, non-worker thread (main/render UI), replacement: takes the admission lease (stop-admission
//         handshake), waits for the executing native call, then runs the original under the lease.
//       - non-tick, non-worker thread, destructor (owner teardown lease): waits until the whole published batch has
//         drained -- queued calls hold raw planner pointers, so waiting for the executing call alone is not enough --
//         then takes the lease (no new call starts) and runs the original before any byte of the owner is touched.
//       - every non-tick waiter services the mailbox: leaving the worker blocked on main would deadlock the next tick.
//       - tick owner: joins the published batch before the original runs (replacement/destructor); commands pass through.
//       - AI worker inside an async think: the call is MARSHALLED. It executes on the first servicing thread (tick start
//         join, a structural join, a main/render waiter or the stop quiesce), with the same ECX/stack arguments; the
//         worker's borrowed frame stays blocked until the original returns.
//       - thread currently executing a marshalled call: pass-through.
//       - 0x83FD00 is the same marshalled kind, reached by call gate AI2_UNROUTED_83FD00 from AI2_POSITION_UPDATE: its
//         23-function closure reaches original walk owners AND owner transactions, so it is never run on the worker.
//   * direct-call owner teardown (no vtable slot on the path): the inner destructor bodies 0x8254D0 (operation, vtable
//     0x1349C18; called from 0x739240 <- 0x73DCC3, 0x739460 <- 0x73930C/0x739344/0x7CB02E/0x7D31BE, 0x76B870, the
//     pinned 0x73E050/0x73E0E0/0x826290 bodies and 0x85DC1A) and 0x69C720 (delegate, vtable 0x1337C30; the 0x825AE0..
//     0x825D30 family, the pinned 0x69E170 body, and the tail jump inside 0x8254D0) are reached through 19 `E8/E9 rel32`
//     sites (10 + 9, a complete static census of the stock image: no absolute or vtable reference exists). Reset(true)
//     retargets each rel32 at the naked gate of pin 25 / pin 26 (vtable == 0 pins, kDirectPinFirst..), which runs the
//     same destructor protocol as the slot gates above (tick owner: staged calls of this tick are published first, then
//     the join; worker: marshalled; non-tick: owner teardown lease; serving/leased thread: pass-through). Quiesce/Drain
//     restore the sites. The gates bound their own range with an 8-byte tail marker so the restore can prove no peer is
//     inside them; every gate entry is counted by the busy counter the Swap8 guard reads.
//   * staged teardown order: a think staged at site 34 earlier in the same tick holds a raw pointer into the graph a
//     later same-tick owner teardown frees, and the batch is published only at tick end. The tick-owner destructor gate
//     therefore publishes the staged calls first and joins them (synchronous order: the think ran before the teardown),
//     counted in staged_teardown_publishes. This is a function of call order only, never of timing.
//   * stop (Quiesce, generation still enabled): admission closes (site 34 runs synchronously), the next tick start
//     drains the batch; if no tick comes within the grace period the stopping thread services each posted call itself
//     while the receivers are still bound, otherwise it aborts the call (EAX = 0, the original is NOT executed) so the
//     think can return. Native frames are never abandoned.
//   * watchdog: any blocking wait longer than 5 s records deadlock_suspected and sets a sticky synchronous fallback for
//     the generation; the tick index is logged. The wait itself is NOT aborted (a native frame cannot be cancelled
//     without SuspendThread/unwinding; both are excluded by design).
// Queue: single producer (tick owner: Admit/PublishBatch/AbortBatch), single consumer (AI worker: WorkerNext). Absolute
// indices head <= published <= tail; the publish and the worker's idle transition are serialized by one lock, so a join
// never observes "drained" while a published call is outstanding. The lease and the worker's call start use a
// store-then-check handshake on both sides (interlocked, sequentially consistent): no native call starts under a lease.
// Nothing here suspends a thread or copies native frames. The only .text bytes it writes are the rel32 of the 19
// direct-call owner-teardown sites (kntwr_entry_patch::Swap8: peers frozen, interior IP refused, 8-byte CAS), installed by
// Reset(true) and restored by Quiesce/Drain; the stock functions themselves are never modified.
//
// Deferred schedule (--ai-deferred, kntwr_config::ai_deferred = K | B << 8; analysis/native-ai-deferred-think.md):
//   * site 34 of tick N admits (planner, flag) as a deferred think unless that planner already has an outstanding
//     (staged, sliced or finished-but-unconsumed) think: then the call is a busy refusal (native call skipped, counted);
//     a refused nonzero full-walk flag is owed to the planner's next admitted think. Capacity: kMaxQueued outstanding.
//   * the tick-end seam opens ONE slice for the inter-tick window: the worker runs the outstanding thinks in FIFO order
//     through the private node driver (kntwr_ai_deferred) with a budget of B costed node units, then parks at a whole-node
//     boundary (no native frame survives the slice). A think whose planner was not presented at site 34 during the tick
//     that opens the slice is abandoned before the slice (its planner may be gone), never resumed.
//   * the next tick's start is a BLOCKING join of that slice only (bounded by B), servicing marshals while it waits; no
//     slice ever overlaps a tick. Then, in FIFO order, a finished think admitted at tick A is consumed at the first seam
//     with tick >= A + K: only then is its planner admitted again. "Finished" is decided by the slice count, so every
//     decision is a function of (tick index, site-34 order, live node counts, K, B), never of time.
//   * structural joins and destructor/replacement gates keep their protocol: "in flight" is the open slice, so a
//     non-tick owner teardown runs between slices, and the next slice revalidates every retained node by membership.
//   * stop/fallback: outstanding thinks are abandoned at the next tick end (no frame to unwind); stop waits for the
//     open slice exactly like a published batch.
#include <stdint.h>

namespace kntwr_ai_async2 {
using U = uint32_t;

constexpr U kVersion = 3, kWords = 96, kBuckets = 12, kKinds = 8, kPinCount = 27, kWatchdogMs = 5000;
constexpr U kDirectPinFirst = 25; // pins [kDirectPinFirst, kPinCount): call-site gates (vtable == 0), see the .cpp
constexpr U kRoutePins = 13, kUnroutedPin = 12; // pins with a route-row marshal counter; the 83FD00 clone-call gate
constexpr U kMaxQueued = 64; // staged + published-not-run + running native calls, FIFO across ticks
constexpr U kRouteWords = 65, kRouteFunctions = 21, kRouteSlots = 2, kRouteClasses = 4;
enum Kind : U { KSite34, KController, KSpatial, KTickEnd, KReplace, KDestroy, KCommand, KStop };
// Word indices of kntwr_status::ai_async2_words (labels KNTWR_AI_ASYNC2_LABELS).
enum Word : U {
    WVersion, WDispatches, WCompletions, WCapacityJoins, WLeaseWaits, WFallbackJoins, WDeadlock, WFallback,
    WFallbackThinks, WMarshalled, WMarshalledNested, WMarshalWaitSum, WMarshalWaitMax, WThinkSum, WThinkMax,
    WOverlapSum, WOverlapMax, WJoinWaitSum, WJoinWaitMax, WInFlight,
    WThinkHist = 20, WOverlapHist = WThinkHist + kBuckets, WJoinWaitHist = WOverlapHist + kBuckets,
    WKindWaits = WJoinWaitHist + kBuckets,      // per kind: {waits, max wait us}
    WKindEntries = WKindWaits + 2 * kKinds,     // gate/join entries per kind
    WKindMarshal = WKindEntries + kKinds,       // worker calls marshalled to the tick per kind
    WSpottingUnresolved = WKindMarshal + kKinds, WLeaseHolds, WRouteEntries, WScratchReady,
    WStopServed, WStopAborted, WOwnerLeases,
    WStagedTeardownPublishes // same-tick staged thinks published before a tick-owner owner teardown (blocking, deterministic)
};
static_assert(WSpottingUnresolved == 88 && WStopServed == 92 && WStagedTeardownPublishes == 95 && kWords == 96,
              "ai_async2 word layout");

// Appended route/boundary row kntwr_status::ai_async2_route_words (labels KNTWR_AI_ASYNC2_ROUTE_LABELS).
enum RouteWord : U {
    RVersion, RSchedule, RTicks, RQueued, RPublishedBatches, RQueuedMax, RCapacityJoins, RLeaseWaits,
    RSeamPolls, RSeamCompleteJoins, RSeamMarshalServes, RSeamStalls, RSeamWaitSum, RSeamWaitMax,
    RSeamStallLastTick, RFallbackTick, RMainServed, RMainMarshalWaits,
    RGateMatrix = 18,                    // kRouteSlots x kRouteClasses, slot-major (RouteSlot, RouteClass)
    RFunctionEntries = RGateMatrix + kRouteSlots * kRouteClasses, // generator AI2_ROUTE_ORDER: private-function entries
    RPinMarshal = RFunctionEntries + kRouteFunctions, // per-pin marshalled-call counters, pins 0..12
    RUnroutedEntries = RPinMarshal + kRoutePins, // worker calls reaching the unrouted 83FD00 gate inside an async think
    RLookupCapacity, RGatherCapacity, RWalkCapacity, // private vector capacities (word 1) after the last think
    RScratchMask,                        // bit 0: walk search objects constructed, bit 1: observer search object
};
static_assert(RFunctionEntries == 26 && RPinMarshal == 47 && RUnroutedEntries == 60 && RScratchMask == 64 &&
              kRouteWords == 65, "ai_async2 route word layout");
enum RouteSlot : U { SlotWalk, SlotObserver };      // 0x133E2DC (702BB0), 0x133773C (6A95A0)
enum RouteClass : U { CWorkerPrivate, CWorkerIdle, CTick, COther };

// Deferred schedule row kntwr_status::ai_deferred_words (labels KNTWR_AI_DEFERRED_LABELS). Histogram buckets of ticks
// spanned (admission tick -> consumption seam) and of slices per think: 1, 2, 3, 4, 5-8, 9-16, 17-32, >32.
constexpr U kDeferWords = 64, kDeferBuckets = 8, kDeferVersion = 1;
enum DeferWord : U {
    DVersion, DK, DBudget, DAdmitted, DBusyRefusals, DCapacityRefusals, DConsumed, DConsumedOnTime, DConsumedLate,
    DAbandonedUnseen, DAbandonedStop, DSlices, DBudgetHits, DNodesSkipped, DNodesRelocated, DChildrenSkipped,
    DThinksDropped, DSeamSliceWaits, DSeamSliceComplete, DSeamWaitSum, DSeamWaitMax, DSeamMarshalServes,
    DSliceMaxUs, DSliceSumUs, DFlagsCarried, DOverflows,
    DCalls = 26,                // per kntwr_ai_deferred::Kind: pass A, pass B, is-current, generate, child, whole think
    DUs = DCalls + 6,           // microseconds per kind
    DUnitMaxUs = DUs + 6,       // worst single costed unit (generate / child / whole think)
    DConsumeHash, DLastConsumeTick, DSpanMax, DSlicesMax, DOutstanding,
    DSpanHist = 44, DSliceHist = DSpanHist + kDeferBuckets,
    DSliceOver2ms = DSliceHist + kDeferBuckets, DSliceOver4ms, DReserved62, DReserved63
};
static_assert(DUnitMaxUs == 38 && DOutstanding == 43 && DSliceOver2ms == 60 && DReserved63 == 63 && kDeferWords == 64,
              "ai_deferred word layout");

// A pinned vtable slot: slot address vtable + 4 * slot (preferred VAs) must hold `original` exactly.
// vtable == 0 is a clone-call gate (no data slot): used for the unrouted 0x83FD00 call inside AI2_POSITION_UPDATE.
struct Pin { U vtable, slot, original, kind, argBytes; };
const Pin* Pins();

// Monitor, gates unpublished, worker idle. Creates the events once per process. False: event creation failed.
// deferred = kntwr_config::ai_deferred (0: the boundary schedule; otherwise K in bits 0..7, B in bits 8..23).
bool Reset(bool enabled, U delta, volatile long* tickOwner, volatile U* workerThread, U deferred = 0);
// Naked gate published into pin i's slot (or bound to a clone call for vtable == 0).
U Gate(U pin);

// Tick owner only.
enum Admission : U { Queued, Synchronous, Busy }; // Busy: deferred schedule refused it (planner outstanding / capacity)
U Admit(U planner, U flag = 0);
void PublishBatch();                // tick-end seam: hand the staged calls to the worker, do not join
void AbortBatch();                  // exceptional tick exit: drop the not-yet-published calls
void TickSeam();                    // next tick's start: blocking lifetime join; complete/stall accounting
void SetWake(U handle);             // runtime's AI wake event, signalled when queued work or a lease release needs it
void Join(U kind);                  // blocking structural-writer join; services worker calls while waiting
bool WorkerNext(U* planner, U* flag); // AI worker: pop the next published call; false = idle or a lease is held
bool Deferred();                      // the generation runs the deferred schedule
// AI worker, deferred schedule: run the open slice (FIFO, budget B) between enter() and leave(), which bracket the
// native work (FPU state, think flag). False: no slice is open or a lease is held (idle transition done).
bool WorkerSlice(void (*enter)(), void (*leave)());

// AI worker only, around the whole native call of an admitted think.
void WorkerBegin();
void WorkerEnd(U us);
void NoteRoute(bool scratchReady); // the worker entered the private walk family
void NotePrivate(U word, U value); // RLookupCapacity + word, word < 4
// Routed vtable slot entry: classify the calling thread (routedPrivate = the caller is sent to the private family).
void NoteGate(U slot, bool routedPrivate);
// Address of the kRouteFunctions entry counters (AI2_ROUTE_COUNTS binding; the private clones increment them).
U FunctionCounters();
// Stopping thread, BEFORE the generation stops routing ticks: close admission and drain (see the stop rule above), then
// restore every direct-call owner-teardown site (Swap8, refused while a peer is inside a site gate; a refusal that outlives
// the timeout returns false and leaves the generation resident). receiversValid() is re-evaluated before each
// self-serviced call. False: not drained / not restored within timeoutMs.
bool Quiesce(U graceMs, U timeoutMs, bool (*receiversValid)());
// Final drain (no published or staged call outstanding). Also restores the direct-call sites again: it is the one stop
// path every shutdown crosses, even when the generation never reached Quiesce. False: not drained / not restored.
bool Drain(U timeoutMs);
void Snapshot(volatile U* out);
void RouteSnapshot(volatile U* out);
void DeferredSnapshot(volatile U* out);
}
#endif
