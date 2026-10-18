// NTW2_AI_ASYNC2 boundary schedule, join and marshalling protocol. See the header for the contract.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include "ntw2_ai_async2.h"
#include "ntw2_ai_deferred.h"

namespace ntw2_ai_async2 {
namespace {
// Slot 19 of the five replacement tables (0x6EA520, ret, no stack argument) and slot 20 of three (0x6B3010, ret 4) as
// audited for ai_census; destructor tables slot 0 (ret 4, deleting flag); command callbacks: vtable 0x1348838 slot 27
// = 0x805CE0 (thiscall, plain ret; 0x805EAE calls effect dispatch 0x80A4E0) and 0x1346B5C slot 21 = 0x7DEC70
// (ret 4; delegate trampoline to 0x805F40, whose 0x805FDC calls 0x80A4E0). Pin 12 has no data slot: it is the clone-call
// gate for AI2_POSITION_UPDATE -> 0x83FD00 (thiscall, ret 0x18), marshalled because its closure reaches original walk
// owners and owner transactions.
// Pins 13..24: owner deleting destructors (thiscall, ret 4, deleting flag) that tear down the observer/operation graph a
// planner walks, entered before any byte of the owner is touched. Observer tables (slot 0 = 0x44A780 ret 4, slot 1 =
// 0x7D32F0/0x7D3300, slot 2 = deleting destructor reaching the embedded-operation teardown 0x8254D0): 0x13430C8 ->
// 0x73DFD0, 0x1343164/0x1343208 -> 0x73E050, 0x1343318 -> 0x73E180 (-> 0x739590 -> 0x739670), 0x1344D38 -> 0x73E0E0,
// 0x1344DB0 -> 0x73E1B0, 0x134B48C -> 0x85E020. Operation tables slot 26 (the five replacement tables): 0x69CED0,
// 0x69DC70, 0x69CEF0 (-> 0x69A990), 0x69E170 (-> 0x69C720), 0x826290 (-> 0x8254D0).
const Pin kPins[kPinCount] = {
    {0x13378F8, 19, 0x6EA520, KReplace, 0}, {0x1337998, 19, 0x6EA520, KReplace, 0}, {0x1337BB8, 19, 0x6EA520, KReplace, 0},
    {0x1337C30, 19, 0x6EA520, KReplace, 0}, {0x1349C18, 19, 0x6EA520, KReplace, 0},
    {0x1337BB8, 20, 0x6B3010, KReplace, 4}, {0x1337C30, 20, 0x6B3010, KReplace, 4}, {0x1349C18, 20, 0x6B3010, KReplace, 4},
    {0x13376FC, 0, 0x69D710, KDestroy, 4}, {0x13376AC, 0, 0x69D750, KDestroy, 4},
    {0x1348838, 27, 0x805CE0, KCommand, 0}, {0x1346B5C, 21, 0x7DEC70, KCommand, 4},
    {0, 0, 0x83FD00, KCommand, 0x18},
    {0x13430C8, 2, 0x73DFD0, KDestroy, 4}, {0x1343164, 2, 0x73E050, KDestroy, 4}, {0x1343208, 2, 0x73E050, KDestroy, 4},
    {0x1343318, 2, 0x73E180, KDestroy, 4}, {0x1344D38, 2, 0x73E0E0, KDestroy, 4}, {0x1344DB0, 2, 0x73E1B0, KDestroy, 4},
    {0x134B48C, 2, 0x85E020, KDestroy, 4},
    {0x13378F8, 26, 0x69CED0, KDestroy, 4}, {0x1337998, 26, 0x69DC70, KDestroy, 4}, {0x1337BB8, 26, 0x69CEF0, KDestroy, 4},
    {0x1337C30, 26, 0x69E170, KDestroy, 4}, {0x1349C18, 26, 0x826290, KDestroy, 4},
};
static_assert(kUnroutedPin < kRoutePins && kRoutePins <= kPinCount, "route-row pin counters");
constexpr U kMaxArgs = 6;

volatile LONG g_words[kWords], g_route[kRouteWords];
volatile LONG g_on, g_inFlight, g_running, g_hold, g_fallback, g_workerAsync, g_measure, g_closing;
volatile U g_serving; // thread executing a marshalled call (0 none)
volatile long* g_tickOwner;
volatile U* g_worker;
U g_original[kPinCount], g_planner[kMaxQueued], g_flag[kMaxQueued];
// Absolute queue indices: [head, published) published to the worker, [published, tail) staged by the current tick.
// tail/published: tick owner writes; head: worker writes. Publish and the worker's idle transition hold g_queueLock.
volatile LONG g_head, g_published, g_tail;
U g_tick, g_joinPending; // tick owner only
SRWLOCK g_queueLock = SRWLOCK_INIT;
LONGLONG g_dispatchQpc, g_completeQpc, g_qpcFreq;
HANDLE g_idle, g_drained, g_posted, g_served, g_wake;
struct Mail { U target, self, count, args[kMaxArgs], result, kind, pin; };
Mail g_mail;
__declspec(thread) U t_leaseDepth; // this thread is executing an original under its own lease

// Deferred schedule. Records are absolute-indexed FIFO [dHead, dPublished) published, [dPublished, dTail) staged by the
// current tick. Tick owner: admission, publish, consumption (dHead) and the Abandoned state, always while no slice is
// open; AI worker: Begun/Done, slices, inside the open slice. The slice open/close holds g_queueLock like the batch.
enum RecordState : U { RStaged, RPublished, RBegun, RDone, RAbandoned };
struct Record { U planner, flag, admitTick, seenTick, slices, lastSlice, state, owed; };
Record g_records[kMaxQueued];
volatile LONG g_dHead, g_dPublished, g_dTail, g_sliceOpen;
bool g_deferred;
U g_deferK, g_deferB, g_sliceTick, g_sliceSeam; // g_sliceSeam: a slice was opened since the previous seam (tick owner)
U g_owed[kMaxQueued], g_owedCount;              // planners owed a refused full-walk flag (tick owner)
volatile LONG g_defer[kDeferWords];
// AI worker only: the think in progress and its record (kNoRecord: none), the driver counters, the relocated bodies.
constexpr U kNoRecord = 0xFFFFFFFFu;
ntw2_ai_deferred::Think g_think;
ntw2_ai_deferred::Counters g_driver;
ntw2_ai_deferred::Natives g_natives;
U g_thinkRecord = kNoRecord, g_dActive;

void Inc(U w) { _InterlockedIncrement(&g_words[w]); }
void Add(U w, U v) { _InterlockedExchangeAdd(&g_words[w], static_cast<LONG>(v)); }
void Max(U w, U v) {
    for (LONG old = g_words[w]; static_cast<U>(old) < v; old = g_words[w])
        if (_InterlockedCompareExchange(&g_words[w], static_cast<LONG>(v), old) == old) return;
}
void RInc(U w) { _InterlockedIncrement(&g_route[w]); }
void RAdd(U w, U v) { _InterlockedExchangeAdd(&g_route[w], static_cast<LONG>(v)); }
void RMax(U w, U v) {
    for (LONG old = g_route[w]; static_cast<U>(old) < v; old = g_route[w])
        if (_InterlockedCompareExchange(&g_route[w], static_cast<LONG>(v), old) == old) return;
}
void Hist(U first, U us) {
    U bucket = 0, ceiling = 125;
    while (bucket < kBuckets - 1 && us > ceiling) { ++bucket; ceiling *= 2; }
    Inc(first + bucket);
}
void DInc(U w) { _InterlockedIncrement(&g_defer[w]); }
void DAdd(U w, U v) { _InterlockedExchangeAdd(&g_defer[w], static_cast<LONG>(v)); }
void DMax(U w, U v) {
    for (LONG old = g_defer[w]; static_cast<U>(old) < v; old = g_defer[w])
        if (_InterlockedCompareExchange(&g_defer[w], static_cast<LONG>(v), old) == old) return;
}
void DHist(U first, U n) { // 1, 2, 3, 4, 5-8, 9-16, 17-32, >32
    U bucket = n <= 4 ? (n ? n - 1 : 0) : n <= 8 ? 4 : n <= 16 ? 5 : n <= 32 ? 6 : 7;
    DInc(first + bucket);
}
U Load(volatile LONG* p) { return static_cast<U>(_InterlockedCompareExchange(p, 0, 0)); }
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
U Micro(LONGLONG a, LONGLONG b) { return b > a ? static_cast<U>((b - a) * 1000000 / g_qpcFreq) : 0; }
U Tid() { return GetCurrentThreadId(); }
bool IsTick() { return g_tickOwner && static_cast<U>(*g_tickOwner) == Tid(); }
bool IsWorker() { return g_worker && *g_worker && *g_worker == Tid(); }

// Calls a thiscall/stdcall original with `count` stack words; the callee pops them.
U __stdcall Invoke(U target, U self, const U* args, U count) {
    U result;
    __asm {
        mov ecx, count
        mov esi, args
    push_args:
        test ecx, ecx
        jz call_target
        push dword ptr [esi + ecx * 4 - 4]
        dec ecx
        jmp push_args
    call_target:
        mov ecx, self
        call target
        mov result, eax
    }
    return result;
}

// Any servicing thread: execute the worker's posted call on its behalf, then release it. Main/render must be able to do
// this: the tick cannot start until main returns from its own lease wait, so leaving the call for the tick would deadlock.
void Serve(bool nested) {
    const U kind = g_mail.kind, pin = g_mail.pin;
    const bool main = !IsTick();
    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_serving), static_cast<LONG>(Tid()));
    g_mail.result = Invoke(g_mail.target, g_mail.self, g_mail.args, g_mail.count);
    _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_serving), 0);
    Inc(WMarshalled); Inc(WKindMarshal + kind); if (pin < kRoutePins) RInc(RPinMarshal + pin);
    if (nested) Inc(WMarshalledNested);
    if (main) RInc(RMainServed);
    SetEvent(g_served);
}

void Watchdog() {
    Inc(WDeadlock);
    _InterlockedExchange(&g_fallback, 1); g_words[WFallback] = 1;
    g_route[RFallbackTick] = g_tick; // divergence point: the schedule changes after this tick
}

// Waits until `drained` ? no published call is outstanding : no native call is executing. Every waiter services the
// mailbox (a main/render waiter is the only thread that can unblock the worker before the next tick). The watchdog
// records and falls back but never abandons the wait.
U WaitIdle(U kind, bool drained, bool nested) {
    const LONGLONG begin = Now();
    const ULONGLONG deadline = GetTickCount64() + kWatchdogMs;
    bool expired = false;
    for (;;) {
        if (!Load(drained ? &g_inFlight : &g_running)) break;
        DWORD timeout = INFINITE;
        if (!expired) {
            const ULONGLONG now = GetTickCount64();
            timeout = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
        }
        const HANDLE handles[2] = {drained ? g_drained : g_idle, g_posted};
        const DWORD r = WaitForMultipleObjects(2, handles, FALSE, timeout);
        if (r == WAIT_OBJECT_0 + 1) {
            Serve(nested);
            if (!IsTick()) RInc(RMainMarshalWaits);
            else if (kind == KTickEnd) { RInc(RSeamMarshalServes); if (g_deferred) DInc(DSeamMarshalServes); }
        }
        else if (r == WAIT_TIMEOUT) { expired = true; Watchdog(); }
        else if (r == WAIT_FAILED) Sleep(1); // fail closed: never treat a wait error as completion
    }
    const U us = Micro(begin, Now());
    Inc(WKindWaits + 2 * kind); Max(WKindWaits + 2 * kind + 1, us);
    return us;
}

// Worker inside an async think: hand the whole original call to the next servicing thread and block until it returns.
U Marshal(U pin, U* frame) {
    const LONGLONG begin = Now();
    g_mail.target = g_original[pin];
    g_mail.self = frame[6]; // pushad ECX
    g_mail.count = kPins[pin].argBytes / 4;
    for (U i = 0; i < g_mail.count; ++i) g_mail.args[i] = frame[10 + i]; // EFLAGS at +32, return at +36, args from +40
    g_mail.kind = kPins[pin].kind;
    g_mail.pin = pin;
    SetEvent(g_posted);
    while (WaitForSingleObject(g_served, INFINITE) != WAIT_OBJECT_0) Sleep(1);
    const U us = Micro(begin, Now());
    Add(WMarshalWaitSum, us); Max(WMarshalWaitMax, us);
    return g_mail.result;
}

// Tick owner: publish every staged call. The lock orders this against the worker's idle transition, so g_inFlight and
// g_drained can never report "drained" for a batch published here.
void PublishLocked() {
    const LONG tail = g_tail;
    AcquireSRWLockExclusive(&g_queueLock);
    const bool staged = g_published != tail;
    if (staged) {
        _InterlockedExchange(&g_published, tail);
        ResetEvent(g_drained);
        _InterlockedExchange(&g_inFlight, 1);
        g_words[WInFlight] = 1;
    }
    ReleaseSRWLockExclusive(&g_queueLock);
    if (!staged) return;
    g_joinPending = 1;
    g_dispatchQpc = Now();
    _InterlockedExchange(&g_measure, 1);
    RInc(RPublishedBatches);
    Inc(WDispatches);
    if (g_wake) SetEvent(g_wake);
}

// Per published batch (tick owner only): one overlap sample at its first seam or join (dispatch -> completion, or -> now
// while still running) and one join-wait sample: 0 when the batch had completed by then, otherwise how long that first
// seam or join stalled the tick.
bool TakeMeasure() { return _InterlockedExchange(&g_measure, 0) != 0; }
void Overlap(bool flying) {
    const U overlap = Micro(g_dispatchQpc, flying ? Now() : g_completeQpc);
    Add(WOverlapSum, overlap); Max(WOverlapMax, overlap); Hist(WOverlapHist, overlap);
}
void JoinSample(U waited) {
    g_joinPending = 0;
    Add(WJoinWaitSum, waited); Max(WJoinWaitMax, waited); Hist(WJoinWaitHist, waited);
}

void CompleteJoin(U kind) {
    Inc(WKindEntries + kind);
    const bool flying = Load(&g_inFlight) != 0;
    if (TakeMeasure()) Overlap(flying);
    U waited = 0;
    if (flying) waited = WaitIdle(kind, true, kind == KReplace || kind == KDestroy);
    if (g_joinPending) JoinSample(waited);
}
} // namespace

// Gate body. frame = pushad block (EDI ESI EBP ESP EBX EDX ECX EAX), then EFLAGS, return address, stack arguments.
// 0: tail-jump the original with the caller's exact stack; 1: handled here, frame EAX holds the result.
extern "C" U __stdcall Ntw2Ai2SlotGate(U pin, U* frame) {
    const U kind = kPins[pin].kind;
    if (!_InterlockedCompareExchange(&g_on, 0, 0)) return 0;
    const U tid = Tid();
    const bool worker = IsWorker();
    if (!worker && kind != KCommand && static_cast<U>(g_serving) != tid && IsTick()) {
        Join(kind); // counts the entry; the tick admits at site 34 only, so it needs no lease
        return 0;
    }
    Inc(WKindEntries + kind);
    if (worker) {
        if (!_InterlockedCompareExchange(&g_workerAsync, 0, 0)) return 0;
        if (pin == kUnroutedPin) RInc(RUnroutedEntries);
        frame[7] = Marshal(pin, frame);
        return 1;
    }
    if (static_cast<U>(g_serving) == tid) return 0; // inside a marshalled call executed on the worker's behalf
    if (kind == KCommand) return 0;                 // tick/main effects proceed; stale observation is admitted
    if (t_leaseDepth) return 0;                     // nested writer inside this thread's own lease: already exclusive
    if (kind == KDestroy) {
        // Owner teardown lease: queued calls hold raw planner pointers, so the whole published batch must drain before
        // the destructor touches the owner; then the lease keeps any later batch from starting until it returns. The
        // worker keeps running queued calls while this thread waits (no hold yet) and its marshals are serviced here.
        for (;;) {
            if (Load(&g_inFlight)) WaitIdle(kind, true, false);
            _InterlockedIncrement(&g_hold);
            if (!Load(&g_inFlight) && !Load(&g_running)) break;
            if (!_InterlockedDecrement(&g_hold) && g_wake) SetEvent(g_wake);
            Sleep(0);
        }
        Inc(WOwnerLeases);
    } else {
        // Replacement: stop new native calls first, then wait only for the one already executing. g_running is set under
        // the same interlocked handshake as the worker's hold check, so no new call starts here.
        _InterlockedIncrement(&g_hold);
        if (Load(&g_running)) WaitIdle(kind, false, false);
    }
    Inc(WLeaseHolds);
    ++t_leaseDepth;
    frame[7] = Invoke(g_original[pin], frame[6], frame + 10, kPins[pin].argBytes / 4);
    --t_leaseDepth;
    if (!_InterlockedDecrement(&g_hold) && g_wake) SetEvent(g_wake); // resume the worker at its next call boundary
    return 1;
}

#define NTW2_AI2_GATE(i, bytes) \
    __declspec(naked) void Gate##i() { \
        __asm pushfd \
        __asm pushad \
        __asm mov eax, esp \
        __asm push eax \
        __asm push i \
        __asm cld \
        __asm call Ntw2Ai2SlotGate \
        __asm test eax, eax \
        __asm jnz handled \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [g_original + 4 * i] \
        __asm handled: \
        __asm popad \
        __asm popfd \
        __asm ret bytes \
    }
NTW2_AI2_GATE(0, 0)
NTW2_AI2_GATE(1, 0)
NTW2_AI2_GATE(2, 0)
NTW2_AI2_GATE(3, 0)
NTW2_AI2_GATE(4, 0)
NTW2_AI2_GATE(5, 4)
NTW2_AI2_GATE(6, 4)
NTW2_AI2_GATE(7, 4)
NTW2_AI2_GATE(8, 4)
NTW2_AI2_GATE(9, 4)
NTW2_AI2_GATE(10, 0)
NTW2_AI2_GATE(11, 4)
NTW2_AI2_GATE(12, 0x18)
NTW2_AI2_GATE(13, 4)
NTW2_AI2_GATE(14, 4)
NTW2_AI2_GATE(15, 4)
NTW2_AI2_GATE(16, 4)
NTW2_AI2_GATE(17, 4)
NTW2_AI2_GATE(18, 4)
NTW2_AI2_GATE(19, 4)
NTW2_AI2_GATE(20, 4)
NTW2_AI2_GATE(21, 4)
NTW2_AI2_GATE(22, 4)
NTW2_AI2_GATE(23, 4)
NTW2_AI2_GATE(24, 4)
#undef NTW2_AI2_GATE

const Pin* Pins() { return kPins; }

U Gate(U pin) {
    static void (*const gates[kPinCount])() = {&Gate0, &Gate1, &Gate2, &Gate3, &Gate4, &Gate5, &Gate6, &Gate7,
                                               &Gate8, &Gate9, &Gate10, &Gate11, &Gate12, &Gate13, &Gate14, &Gate15,
                                               &Gate16, &Gate17, &Gate18, &Gate19, &Gate20, &Gate21, &Gate22, &Gate23,
                                               &Gate24};
    static_assert(kPinCount == 25, "one naked gate per pin");
    return pin < kPinCount ? static_cast<U>(reinterpret_cast<uintptr_t>(gates[pin])) : 0;
}


namespace {
// ---- deferred schedule (tick owner unless noted) ---------------------------------------------------------------------
constexpr U kFnvBasis = 2166136261u, kFnvPrime = 16777619u;
Record& At(LONG index) { return g_records[static_cast<U>(index) % kMaxQueued]; }
void Owe(U planner) {
    for (U i = 0; i < g_owedCount; ++i) if (g_owed[i] == planner) return;
    if (g_owedCount < kMaxQueued) g_owed[g_owedCount++] = planner;
}
// Determinism witness: FNV over (admission tick, consumption seam, slices, outcome) of every retired record.
void Witness(const Record& r, U outcome) {
    U h = static_cast<U>(g_defer[DConsumeHash]);
    const U values[4] = {r.admitTick, g_tick, r.slices, outcome};
    for (U v : values) h = (h ^ v) * kFnvPrime;
    g_defer[DConsumeHash] = static_cast<LONG>(h);
}

U DeferAdmit(U planner, U flag) {
    const LONG head = g_dHead, tail = g_dTail;
    for (LONG i = head; i != tail; ++i) {
        Record& r = At(i);
        if (r.planner != planner) continue;
        r.seenTick = g_tick; // presented this tick: the planner is live for the slice this tick opens
        if (flag & 0xFF) r.owed = 1;
        DInc(DBusyRefusals);
        return Busy;
    }
    if (static_cast<U>(tail - head) >= kMaxQueued) {
        if (flag & 0xFF) Owe(planner);
        DInc(DCapacityRefusals);
        return Busy;
    }
    for (U i = 0; i < g_owedCount; ++i)
        if (g_owed[i] == planner) { flag |= 1; g_owed[i] = g_owed[--g_owedCount]; DInc(DFlagsCarried); break; }
    At(tail) = {planner, flag, g_tick, g_tick, 0, 0, RStaged, 0};
    _InterlockedIncrement(&g_dTail); // full barrier: the record is written before the index that covers it
    DInc(DAdmitted); RInc(RQueued); RMax(RQueuedMax, static_cast<U>(tail + 1 - head));
    g_defer[DOutstanding] = tail + 1 - head;
    return Queued;
}

// Tick end: publish this tick's admissions, abandon thinks whose planner was not presented this tick (or every
// unfinished think on stop/fallback), then open one slice when any think is unfinished.
void DeferPublish() {
    if (Load(&g_inFlight)) WaitIdle(KTickEnd, true, false); // never two slices: the seam normally joined it already
    const bool stop = Load(&g_fallback) || Load(&g_closing);
    const LONG head = g_dHead, published = g_dPublished, tail = g_dTail;
    bool work = false;
    for (LONG i = head; i != tail; ++i) {
        Record& r = At(i);
        if (r.state == RDone || r.state == RAbandoned) continue;
        if (stop) { r.state = RAbandoned; DInc(DAbandonedStop); continue; }
        if (i - published >= 0) r.state = RPublished;
        else if (r.seenTick != g_tick) { r.state = RAbandoned; DInc(DAbandonedUnseen); continue; }
        work = true;
    }
    _InterlockedExchange(&g_dPublished, tail);
    if (!work) return;
    AcquireSRWLockExclusive(&g_queueLock);
    g_sliceTick = g_tick;
    _InterlockedExchange(&g_sliceOpen, 1);
    ResetEvent(g_drained);
    _InterlockedExchange(&g_inFlight, 1);
    g_words[WInFlight] = 1;
    ReleaseSRWLockExclusive(&g_queueLock);
    g_sliceSeam = 1; g_joinPending = 1;
    g_dispatchQpc = Now();
    _InterlockedExchange(&g_measure, 1);
    RInc(RPublishedBatches); Inc(WDispatches);
    if (g_wake) SetEvent(g_wake);
}

// Tick start (after ++g_tick): blocking join of the open slice (bounded by B), then FIFO consumption of the thinks
// that finished at least K ticks after their admission. Abandoned records retire at the first seam.
void DeferSeam() {
    const bool flying = Load(&g_inFlight) != 0;
    if (flying || g_sliceSeam) {
        RInc(RSeamPolls);
        Inc(WKindEntries + static_cast<U>(KTickEnd));
        if (TakeMeasure()) Overlap(flying);
    }
    if (flying) {
        const U waited = WaitIdle(KTickEnd, true, false);
        RInc(RSeamStalls); RAdd(RSeamWaitSum, waited); RMax(RSeamWaitMax, waited);
        g_route[RSeamStallLastTick] = g_tick;
        if (g_joinPending) JoinSample(waited);
        DInc(DSeamSliceWaits); DAdd(DSeamWaitSum, waited); DMax(DSeamWaitMax, waited);
    } else if (g_sliceSeam) {
        if (g_joinPending) { JoinSample(0); RInc(RSeamCompleteJoins); }
        DInc(DSeamSliceComplete);
    }
    g_sliceSeam = 0;
    LONG head = g_dHead;
    while (head != g_dPublished) {
        Record& r = At(head);
        if (r.state == RAbandoned) { Witness(r, 2); ++head; continue; }
        if (r.state != RDone) break;
        const U spanned = g_tick - r.admitTick;
        if (spanned < g_deferK) break; // FIFO: later records were admitted no earlier and finished no earlier
        DInc(DConsumed); DInc(spanned == g_deferK ? DConsumedOnTime : DConsumedLate);
        DHist(DSpanHist, spanned); DHist(DSliceHist, r.slices);
        DMax(DSpanMax, spanned); DMax(DSlicesMax, r.slices);
        Witness(r, 1);
        g_defer[DLastConsumeTick] = static_cast<LONG>(g_tick);
        if (r.owed) Owe(r.planner);
        ++head;
    }
    _InterlockedExchange(&g_dHead, head);
    g_defer[DOutstanding] = g_dTail - head;
}
bool Staged() { return g_deferred ? g_dTail != g_dPublished : g_tail != g_published; }
} // namespace

bool Reset(bool enabled, U delta, volatile long* tickOwner, volatile U* workerThread, U deferred) {
    _InterlockedExchange(&g_on, 0);
    if (!g_idle) g_idle = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (!g_drained) g_drained = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (!g_posted) g_posted = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_served) g_served = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_idle || !g_drained || !g_posted || !g_served) return false;
    if (!g_qpcFreq) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_qpcFreq = f.QuadPart; }
    for (U i = 0; i < kWords; ++i) g_words[i] = 0;
    for (U i = 0; i < kRouteWords; ++i) g_route[i] = 0;
    for (U i = 0; i < kDeferWords; ++i) g_defer[i] = 0;
    g_inFlight = g_running = g_hold = g_fallback = g_workerAsync = g_measure = g_closing = 0;
    g_head = g_published = g_tail = 0;
    g_dHead = g_dPublished = g_dTail = g_sliceOpen = 0;
    g_sliceTick = g_sliceSeam = g_owedCount = 0;
    g_thinkRecord = kNoRecord; g_dActive = 0; g_driver = {};
    g_deferred = enabled && deferred != 0;
    g_deferK = deferred & 0xFFu; g_deferB = (deferred >> 8) & 0xFFFFu;
    g_natives = {0x7CD010u + delta, 0x7CCF80u + delta, 0x7D7BF0u + delta};
    g_tick = g_joinPending = 0;
    g_dispatchQpc = g_completeQpc = 0;
    SetEvent(g_idle); SetEvent(g_drained); ResetEvent(g_posted); ResetEvent(g_served);
    g_tickOwner = tickOwner; g_worker = workerThread;
    for (U i = 0; i < kPinCount; ++i) g_original[i] = kPins[i].original + delta;
    if (enabled) {
        g_words[WVersion] = kVersion;
        g_route[RVersion] = kVersion;
        g_route[RSchedule] = g_deferred ? 3 : 2; // 3: deferred sliced thinks, 2: whole calls, blocking start join
        g_words[WSpottingUnresolved] = 1; // main spotting 0x6A94B0 route is not in a cloned source: no gate (see report)
        if (g_deferred) {
            g_defer[DVersion] = kDeferVersion; g_defer[DK] = g_deferK; g_defer[DBudget] = g_deferB;
            g_defer[DConsumeHash] = static_cast<LONG>(kFnvBasis);
        }
        _InterlockedExchange(&g_on, 1);
    }
    return true;
}
U Admit(U planner, U flag) {
    const bool fallback = Load(&g_fallback) != 0;
    if (fallback || Load(&g_closing)) { // sticky watchdog fallback, or a stop in progress: the same-call barrier
        Join(KSite34);
        Inc(WFallbackJoins);
        if (fallback) Inc(WFallbackThinks);
        return Synchronous;
    }
    if (g_deferred) return DeferAdmit(planner, flag);
    if (static_cast<U>(g_tail - Load(&g_head)) >= kMaxQueued) {
        // Deterministic emergency: the FIFO is full by call order. Publish now and drain before accepting more.
        PublishLocked();
        Join(KSite34);
        Inc(WCapacityJoins); RInc(RCapacityJoins);
    }
    if (Load(&g_hold)) {
        Inc(WLeaseWaits); RInc(RLeaseWaits);
        WaitIdle(KSite34, false, false);
    }
    const U slot = static_cast<U>(g_tail) % kMaxQueued;
    g_planner[slot] = planner;
    g_flag[slot] = flag;
    _InterlockedIncrement(&g_tail); // full barrier: the slot is written before the index that covers it
    RInc(RQueued); RMax(RQueuedMax, static_cast<U>(g_tail - Load(&g_head)));
    return Queued;
}

void PublishBatch() {
    if (!Load(&g_on)) return;
    if (g_deferred) DeferPublish();
    else PublishLocked();
}

void AbortBatch() {
    if (g_deferred) {
        const LONG staged = g_dTail - g_dPublished;
        if (staged <= 0) return;
        RAdd(RQueued, static_cast<U>(-staged)); DAdd(DAdmitted, static_cast<U>(-staged));
        _InterlockedExchange(&g_dTail, g_dPublished);
        return;
    }
    const LONG staged = g_tail - g_published;
    if (staged <= 0) return;
    RAdd(RQueued, static_cast<U>(-staged));
    _InterlockedExchange(&g_tail, g_published);
}

void TickSeam() {
    if (!Load(&g_on)) return;
    ++g_tick; g_route[RTicks] = g_tick;
    if (g_deferred) { DeferSeam(); return; }
    if (!g_measure && !Load(&g_inFlight)) return; // nothing published since the previous seam
    RInc(RSeamPolls);
    Inc(WKindEntries + static_cast<U>(KTickEnd));
    const bool flying = Load(&g_inFlight) != 0;
    if (TakeMeasure()) Overlap(flying);
    if (!flying) { // the batch finished inside the inter-tick window: no stall
        if (g_joinPending) { JoinSample(0); RInc(RSeamCompleteJoins); }
        return;
    }
    // Lifetime barrier: no think crosses into a tick (tick-side owner teardown, including direct-call routes, then
    // always runs after the think). The stall is the cost of a think longer than the window; it services marshals.
    const U waited = WaitIdle(KTickEnd, true, false);
    RInc(RSeamStalls); RAdd(RSeamWaitSum, waited); RMax(RSeamWaitMax, waited);
    g_route[RSeamStallLastTick] = g_tick;
    if (g_joinPending) JoinSample(waited);
}

void Join(U kind) { CompleteJoin(kind); }

bool WorkerNext(U* planner, U* flag) {
    if (!Load(&g_on)) return false;
    // Lease handshake: announce the call first, then check for a holder (the holder increments, then checks g_running).
    ResetEvent(g_idle);
    _InterlockedExchange(&g_running, 1);
    if (Load(&g_hold)) {
        _InterlockedExchange(&g_running, 0);
        SetEvent(g_idle);
        return false; // resumed by the lease release's wake
    }
    AcquireSRWLockExclusive(&g_queueLock);
    const LONG head = g_head;
    if (head == g_published) {
        _InterlockedExchange(&g_running, 0);
        SetEvent(g_idle);
        g_words[WInFlight] = 0;
        _InterlockedExchange(&g_inFlight, 0);
        SetEvent(g_drained);
        ReleaseSRWLockExclusive(&g_queueLock);
        return false;
    }
    ReleaseSRWLockExclusive(&g_queueLock);
    const U slot = static_cast<U>(head) % kMaxQueued;
    *planner = g_planner[slot];
    *flag = g_flag[slot];
    _InterlockedIncrement(&g_head);
    return true;
}

void WorkerBegin() { _InterlockedExchange(&g_workerAsync, 1); }

void WorkerEnd(U us) {
    _InterlockedExchange(&g_workerAsync, 0);
    Add(WThinkSum, us); Max(WThinkMax, us); Hist(WThinkHist, us);
    Inc(WCompletions);
    g_completeQpc = Now();
    _InterlockedExchange(&g_running, 0);
    SetEvent(g_idle);
}

bool Deferred() { return g_deferred; }

bool WorkerSlice(void (*enter)(), void (*leave)()) {
    if (!Load(&g_on) || !g_deferred) return false;
    // Lease handshake as in WorkerNext: no slice starts under a lease; the release wakes the worker.
    ResetEvent(g_idle);
    _InterlockedExchange(&g_running, 1);
    if (Load(&g_hold)) {
        _InterlockedExchange(&g_running, 0);
        SetEvent(g_idle);
        return false;
    }
    AcquireSRWLockExclusive(&g_queueLock);
    if (!g_sliceOpen) {
        _InterlockedExchange(&g_running, 0);
        SetEvent(g_idle);
        g_words[WInFlight] = 0;
        _InterlockedExchange(&g_inFlight, 0);
        SetEvent(g_drained);
        ReleaseSRWLockExclusive(&g_queueLock);
        return false;
    }
    ReleaseSRWLockExclusive(&g_queueLock);
    const LONGLONG begin = Now();
    const U slice = g_sliceTick;
    const LONG head = g_dHead, end = g_dPublished;
    LONG i = static_cast<LONG>(g_dActive);
    if (i - head < 0) i = head; // records before dHead were retired at a seam (abandoned before the worker saw them)
    U budget = g_deferB;
    bool blocked = false;
    enter();
    _InterlockedExchange(&g_workerAsync, 1); // worker calls of gated slots are marshalled from here on
    for (; i != end; ++i) {
        Record& r = At(i);
        if (r.state == RDone || r.state == RAbandoned) {
            if (g_thinkRecord == static_cast<U>(i)) g_thinkRecord = kNoRecord;
            continue;
        }
        if (g_thinkRecord != static_cast<U>(i)) {
            if (!budget) { blocked = true; break; } // its passes would run beyond B: the next slice begins it
            ntw2_ai_deferred::Begin(g_think, r.planner, r.flag, g_driver);
            g_thinkRecord = static_cast<U>(i);
            r.state = RBegun;
        }
        if (!r.slices || r.lastSlice != slice) { ++r.slices; r.lastSlice = slice; }
        if (!ntw2_ai_deferred::Step(g_think, g_natives, budget, g_driver, g_qpcFreq)) { blocked = true; break; }
        r.state = RDone;
        g_thinkRecord = kNoRecord;
    }
    g_dActive = static_cast<U>(i);
    _InterlockedExchange(&g_workerAsync, 0);
    leave();
    const U us = Micro(begin, Now());
    // Driver counters: single writer (this thread), published per slice.
    g_defer[DNodesSkipped] = g_driver.skipped; g_defer[DNodesRelocated] = g_driver.relocated;
    g_defer[DChildrenSkipped] = g_driver.childSkipped; g_defer[DThinksDropped] = g_driver.thinksDropped;
    g_defer[DOverflows] = g_driver.overflows; g_defer[DUnitMaxUs] = g_driver.unitMaxUs;
    for (U k = 0; k < ntw2_ai_deferred::KKinds; ++k) { g_defer[DCalls + k] = g_driver.calls[k]; g_defer[DUs + k] = g_driver.us[k]; }
    static_assert(ntw2_ai_deferred::KKinds == 6, "six driver kinds in the deferred row");
    DInc(DSlices); if (blocked) DInc(DBudgetHits);
    DAdd(DSliceSumUs, us); DMax(DSliceMaxUs, us);
    if (us > 2000) DInc(DSliceOver2ms);
    if (us > 4000) DInc(DSliceOver4ms);
    Add(WThinkSum, us); Max(WThinkMax, us); Hist(WThinkHist, us); Inc(WCompletions); // main row: one sample per slice
    AcquireSRWLockExclusive(&g_queueLock);
    g_completeQpc = Now();
    _InterlockedExchange(&g_sliceOpen, 0);
    _InterlockedExchange(&g_running, 0);
    SetEvent(g_idle);
    g_words[WInFlight] = 0;
    _InterlockedExchange(&g_inFlight, 0);
    SetEvent(g_drained);
    ReleaseSRWLockExclusive(&g_queueLock);
    return true;
}

void NoteRoute(bool scratchReady) {
    Inc(WRouteEntries);
    g_words[WScratchReady] = scratchReady ? 1 : 0;
}

void NotePrivate(U word, U value) { if (word < 4) g_route[RLookupCapacity + word] = static_cast<LONG>(value); }

void NoteGate(U slot, bool routedPrivate) {
    if (!Load(&g_on) || slot >= kRouteSlots) return;
    const U cls = IsWorker() ? (routedPrivate ? CWorkerPrivate : CWorkerIdle) : IsTick() ? CTick : COther;
    RInc(RGateMatrix + slot * kRouteClasses + cls);
}

U FunctionCounters() { return static_cast<U>(reinterpret_cast<uintptr_t>(&g_route[RFunctionEntries])); }

void SetWake(U handle) { g_wake = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(handle)); }

bool Quiesce(U graceMs, U timeoutMs, bool (*receiversValid)()) {
    if (!Load(&g_on)) return true;
    _InterlockedExchange(&g_closing, 1); // site 34 stops queueing: later calls use the same-call barrier
    const ULONGLONG begin = GetTickCount64(), grace = begin + graceMs, deadline = begin + timeoutMs;
    for (;;) {
        // Staged calls belong to a tick in progress: its end publishes them and the next tick start joins them.
        if (!Load(&g_inFlight) && !Staged()) return true;
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return false;
        const bool valid = receiversValid && receiversValid();
        if (valid && now < grace) { Sleep(1); continue; } // the routed tick-start join services and drains it
        // No tick came (paused, or the battle is gone): never leave the worker's borrowed frame blocked. Execute its
        // call here while the receivers are still bound; otherwise abort it (EAX = 0, the original is NOT executed).
        if (WaitForSingleObject(g_posted, 1) != WAIT_OBJECT_0) continue;
        if (receiversValid && receiversValid()) { Serve(false); Inc(WStopServed); }
        else { g_mail.result = 0; Inc(WStopAborted); SetEvent(g_served); }
    }
}

bool Drain(U timeoutMs) {
    const bool staged = Staged();
    if (!Load(&g_inFlight)) return !staged;
    const LONGLONG begin = Now();
    const bool ok = WaitForSingleObject(g_drained, timeoutMs) == WAIT_OBJECT_0 && !Load(&g_inFlight);
    const U us = Micro(begin, Now());
    Inc(WKindWaits + 2 * KStop); Max(WKindWaits + 2 * KStop + 1, us);
    return ok && !staged;
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = static_cast<U>(g_words[i]);
}

void RouteSnapshot(volatile U* out) {
    for (U i = 0; i < kRouteWords; ++i) out[i] = static_cast<U>(g_route[i]);
}

void DeferredSnapshot(volatile U* out) {
    for (U i = 0; i < kDeferWords; ++i) out[i] = static_cast<U>(g_defer[i]);
}
}
