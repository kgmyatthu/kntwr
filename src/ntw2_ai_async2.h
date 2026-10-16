#ifndef NTW2_AI_ASYNC2_H
#define NTW2_AI_ASYNC2_H
// NTW2_AI_ASYNC2: whole native planner calls (0x7D99F0) run on the dedicated AI worker in the inter-tick window.
//
// Boundary schedule (analysis/native-ai-async2-fixed.md; contract analysis/native-ai-async-consistency.md §5.1):
//   * site 34 of tick N queues (planner, flag) in call order and returns without running the planner. The planner is
//     incremental: the delayed call is the approved AI-order latency. Every call is queued exactly once; nothing is
//     admitted or skipped on wall-clock timing. The queue cap is a deterministic function of call order, not of progress.
//   * the tick-end seam hands the staged batch to the worker. The worker runs the queued calls in order during the
//     inter-tick window, when only main/render runs, with its private walk/observer clone family (no shared scratch).
//   * the next tick's START is the effect seam: it services one posted worker call and never blocks. A batch that has
//     completed by then is counted as joined; a think still running overlaps the new tick. That overlap is the one
//     remaining timing-dependent outcome and is counted as a divergence point (ticks and thinks, first/last tick index).
//     The structural-writer joins below still drain it before their mutation.
//   * tick-side joins: site 33 (controller 0x7C8BD0 entry, before its 0x7492F0 rebuild), TICK 57DFDF (dynamic quadtree
//     update 0x817D20) and the tick-owner delegate gates. They service the mailbox while waiting, so a spanning think
//     blocked on a marshal cannot deadlock the tick.
//   * vtable-slot gates (pinned original words, the runtime's ordinary Slot machinery): delegate replacement
//     0x6EA520/0x6B3010, delegate destructors 0x69D710/0x69D750, command callbacks 0x805CE0/0x7DEC70.
//       - non-tick, non-worker thread (main/render UI): takes the admission lease (stop-admission handshake), waits for
//         the executing native call, then runs the original under the lease. It also services the mailbox while waiting:
//         the tick cannot start until main returns, so leaving the worker blocked on main would deadlock. Commands pass.
//       - tick owner: joins the published batch before the original runs (replacement/destructor); commands pass through.
//       - AI worker inside an async think: the call is MARSHALLED. It executes on the first servicing thread (tick start
//         seam, a structural join, or a main/render lease waiter), with the same ECX/stack arguments; the worker's
//         borrowed frame stays blocked until the original returns. A worker marshal posted in the inter-tick window
//         therefore waits for the next tick start and makes its think span that tick.
//       - thread currently executing a marshalled call: pass-through.
//       - 0x83FD00 is the same marshalled kind, reached by call gate AI2_UNROUTED_83FD00 from AI2_POSITION_UPDATE: its
//         23-function closure reaches original walk owners AND owner transactions, so it is never run on the worker.
//   * watchdog: any blocking wait longer than 5 s records deadlock_suspected and sets a sticky synchronous fallback for
//     the generation; the tick index is logged as a divergence point. The wait itself is NOT aborted (a native frame cannot
//     be cancelled without SuspendThread/unwinding; both are excluded by design).
// Queue: single producer (tick owner: Admit/PublishBatch/AbortBatch), single consumer (AI worker: WorkerNext). Absolute
// indices head <= published <= tail; the publish and the worker's idle transition are serialized by one lock, so a join
// never observes "drained" while a published call is outstanding. The lease and the worker's call start use a
// store-then-check handshake on both sides (interlocked, sequentially consistent): no native call starts under a lease.
// Nothing here suspends a thread, patches .text or copies native frames.
#include <stdint.h>

namespace ntw2_ai_async2 {
using U = uint32_t;

constexpr U kVersion = 2, kWords = 96, kBuckets = 12, kKinds = 8, kPinCount = 13, kWatchdogMs = 5000;
constexpr U kMaxQueued = 64; // staged + published-not-run + running native calls, FIFO across ticks
constexpr U kRouteWords = 65, kRouteFunctions = 21, kRouteSlots = 2, kRouteClasses = 4;
enum Kind : U { KSite34, KController, KSpatial, KTickEnd, KReplace, KDestroy, KCommand, KStop };
// Word indices of ntw2_status::ai_async2_words (labels NTW2_AI_ASYNC2_LABELS).
enum Word : U {
    WVersion, WDispatches, WCompletions, WCapacityJoins, WLeaseWaits, WFallbackJoins, WDeadlock, WFallback,
    WFallbackThinks, WMarshalled, WMarshalledNested, WMarshalWaitSum, WMarshalWaitMax, WThinkSum, WThinkMax,
    WOverlapSum, WOverlapMax, WJoinWaitSum, WJoinWaitMax, WInFlight,
    WThinkHist = 20, WOverlapHist = WThinkHist + kBuckets, WJoinWaitHist = WOverlapHist + kBuckets,
    WKindWaits = WJoinWaitHist + kBuckets,      // per kind: {waits, max wait us}
    WKindEntries = WKindWaits + 2 * kKinds,     // gate/join entries per kind
    WKindMarshal = WKindEntries + kKinds,       // worker calls marshalled to the tick per kind
    WSpottingUnresolved = WKindMarshal + kKinds, WLeaseHolds, WRouteEntries, WScratchReady, WReserved
};
static_assert(WSpottingUnresolved == 88 && WReserved == 92 && kWords == 96, "ai_async2 word layout");

// Appended route/boundary row ntw2_status::ai_async2_route_words (labels NTW2_AI_ASYNC2_ROUTE_LABELS).
enum RouteWord : U {
    RVersion, RSchedule, RTicks, RQueued, RPublishedBatches, RQueuedMax, RCapacityJoins, RLeaseWaits,
    RSeamPolls, RSeamCompleteJoins, RSeamMarshalServes, RSpanningTicks, RSpanningThinks, RSpanningFirstTick,
    RSpanningLastTick, RFallbackTick, RMainServed, RMainMarshalWaits,
    RGateMatrix = 18,                    // kRouteSlots x kRouteClasses, slot-major (RouteSlot, RouteClass)
    RFunctionEntries = RGateMatrix + kRouteSlots * kRouteClasses, // generator AI2_ROUTE_ORDER: private-function entries
    RPinMarshal = RFunctionEntries + kRouteFunctions, // 13 per-pin marshalled-call counters
    RUnroutedEntries = RPinMarshal + kPinCount, // worker calls reaching the unrouted 83FD00 gate inside an async think
    RLookupCapacity, RGatherCapacity, RWalkCapacity, // private vector capacities (word 1) after the last think
    RScratchMask,                        // bit 0: walk search objects constructed, bit 1: observer search object
};
static_assert(RFunctionEntries == 26 && RPinMarshal == 47 && RUnroutedEntries == 60 && RScratchMask == 64 &&
              kRouteWords == 65, "ai_async2 route word layout");
enum RouteSlot : U { SlotWalk, SlotObserver };      // 0x133E2DC (702BB0), 0x133773C (6A95A0)
enum RouteClass : U { CWorkerPrivate, CWorkerIdle, CTick, COther };

// A pinned vtable slot: slot address vtable + 4 * slot (preferred VAs) must hold `original` exactly.
// vtable == 0 is a clone-call gate (no data slot): used for the unrouted 0x83FD00 call inside AI2_POSITION_UPDATE.
struct Pin { U vtable, slot, original, kind, argBytes; };
const Pin* Pins();

// Monitor, gates unpublished, worker idle. Creates the events once per process. False: event creation failed.
bool Reset(bool enabled, U delta, volatile long* tickOwner, volatile U* workerThread);
// Naked gate published into pin i's slot (or bound to a clone call for vtable == 0).
U Gate(U pin);

// Tick owner only.
enum Admission : U { Queued, Synchronous };
U Admit(U planner, U flag = 0);
void PublishBatch();                // tick-end seam: hand the staged calls to the worker, do not join
void AbortBatch();                  // exceptional tick exit: drop the not-yet-published calls
void TickSeam();                    // next tick's start: non-blocking service, completion and divergence accounting
void SetWake(U handle);             // runtime's AI wake event, signalled when queued work or a lease release needs it
void Join(U kind);                  // blocking structural-writer join; services worker calls while waiting
bool WorkerNext(U* planner, U* flag); // AI worker: pop the next published call; false = idle or a lease is held

// AI worker only, around the whole native call of an admitted think.
void WorkerBegin();
void WorkerEnd(U us);
void NoteRoute(bool scratchReady); // the worker entered the private walk family
void NotePrivate(U word, U value); // RLookupCapacity + word, word < 4
// Routed vtable slot entry: classify the calling thread (routedPrivate = the caller is sent to the private family).
void NoteGate(U slot, bool routedPrivate);
// Address of the kRouteFunctions entry counters (AI2_ROUTE_COUNTS binding; the private clones increment them).
U FunctionCounters();
bool Drain(U timeoutMs);
void Snapshot(volatile U* out);
void RouteSnapshot(volatile U* out);
}
#endif
