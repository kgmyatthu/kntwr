#include "native_idle_node.h"
#include "native_move_node.h"
#include <string.h>
#include <intrin.h>
#include <xmmintrin.h>
#pragma fenv_access(on)

// Source-pinned Napoleon.exe SHA256
// 13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4.
// Owner-serial differential execution only: no live writes or replacement vtable.
namespace kntwr_idle_node {
namespace {
static_assert(sizeof(void*) == 4, "idle node ABI is Win32");
U imageBase, words[kClassCount][kWords], eventWords[kClassCount][kEventWords], sequence;
bool enabled, preparing;
U Native(U va) { return imageBase + va - 0x400000; }
template<class T> T Read(U address) { T value; memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value)); return value; }
template<class T> T Get(const B* bytes, U offset) { T value; memcpy(&value, bytes + offset, sizeof(value)); return value; }
template<class T> void Put(B* bytes, U offset, T value) { memcpy(bytes + offset, &value, sizeof(value)); }
struct FpGuard {
    __declspec(align(16)) B state[512];
    FpGuard() {
        _fxsave(state);
        unsigned short control; memcpy(&control, state, 2); control |= 0x3f;
        __asm fninit
        __asm fldcw word ptr [control]
        _mm_setcsr(_mm_getcsr() | 0x1f80);
    }
    ~FpGuard() { _fxrstor(state); }
};
// COMISS branch conditions deliberately include unordered in JB/JBE, unlike
// ordinary C++ comparisons. JA is ordered strict greater (646C20/664B40 paths).
bool Below(float a, float b) {
    B result;
    __asm { movss xmm0, a }
    __asm { comiss xmm0, b }
    __asm { setb result }
    return result != 0;
}
bool Above(float a, float b) {
    B result;
    __asm { movss xmm0, a }
    __asm { comiss xmm0, b }
    __asm { seta result }
    return result != 0;
}
enum Operation : U { Construct, Begin, Step, Destroy };
enum Kind : U { Order, Stop, Action };
enum Continuation : U { Entry, Finished, CommonTail, ClearThenTail, LatchThenFinish };
struct Store { U address, value, width; };
struct Event { Kind kind; U receiver, args[4], count; };
struct Frame {
    U cls, node, owner, size, token, effectToken;
    Operation operation;
    Continuation continuation;
    B expected[0x28];
    Store stores[8]; U storeCount;
    Event event;
    bool hasEvent, observed, busy, refused, special;
    bool nodeMismatch, ownerMismatch, eventMismatch;
};
Frame frame; bool active;
U Table(U cls) { return Native(cls ? 0x1334028 : 0x133405c); }
U Token() { sequence = (sequence + 1) & 0x7fffffffu; if (!sequence) ++sequence; return sequence; }
void Difference(U offset, B expected, B actual) {
    U* w = words[frame.cls]; w[LastMismatchOffset] = offset; w[LastExpected] = expected; w[LastActual] = actual;
}
void CheckNode() {
    const B* live = reinterpret_cast<const B*>(frame.node);
    for (U i = 0; i < frame.size; ++i) if (live[i] != frame.expected[i]) {
        frame.nodeMismatch = true; Difference(i, frame.expected[i], live[i]); break;
    }
}
void CheckOwner() {
    for (U i = 0; i < frame.storeCount; ++i) {
        const Store& s = frame.stores[i];
        const B* live = reinterpret_cast<const B*>(s.address);
        const B* expected = reinterpret_cast<const B*>(&s.value);
        ++eventWords[frame.cls][12];
        for (U j = 0; j < s.width; ++j) if (live[j] != expected[j]) {
            frame.ownerMismatch = true; Difference(s.address - frame.owner + j, expected[j], live[j]); break;
        }
    }
}
void StoreValue(U address, U value, U width = 4) {
    for (U i = 0; i < frame.storeCount; ++i) if (frame.stores[i].address == address) {
        frame.stores[i] = {address, value, width}; return;
    }
    frame.stores[frame.storeCount++] = {address, value, width};
}
U CurrentWord(U address) {
    for (U i = 0; i < frame.storeCount; ++i) if (frame.stores[i].address == address) return frame.stores[i].value;
    return Read<U>(address);
}
void Refuse() {
    frame.refused = true; ++words[frame.cls][Refused]; ++words[frame.cls][NeedsOwnerCount];
    ++eventWords[frame.cls][9];
}
// Concrete owner and related-owner tables sharing 64FA80 at +F4 use only
// these three byte getters at +E8/+EC/+F0. 461180 also returns EAX=0.
bool Getter(U object, U slot, B& value) {
    U target = Read<U>(Read<U>(object) + slot);
    if (target == Native(0x462cb0) || target == Native(0x461180)) value = 0;
    else if (target == Native(0x447880)) value = 1;
    else if (target == Native(0x5db820)) value = Read<U>(object + 0x67c) != 0;
    else return false;
    return true;
}
U ModeResult() {
    U model = Read<U>(Get<U>(frame.expected, 0x14) + 8);
    U mode = Read<U>(Read<U>(model + 0xb0) + 0x14);
    return (mode & 0xffffff00u) | U(mode == 0 || mode == 1);
}
bool Quiet() {
    if (Read<B>(frame.owner + 0x117) != 1) return false;
    U bits = Read<U>(frame.owner + 0x194) & 0x7fffffffu;
    float absolute; memcpy(&absolute, &bits, 4);
    return Above(Read<float>(Native(0x1318034)), absolute);
}
// 5FC070 advances one LCG word and returns an SSE-rounded float through ST0.
// Only the predicted write changes; the original helper advances live state.
float Draw(U seedAddress) {
    U seed = CurrentWord(seedAddress) * 0x343fdu + 0x269ec3u;
    StoreValue(seedAddress, seed); ++eventWords[frame.cls][10];
    return _mm_cvtss_f32(_mm_mul_ss(_mm_cvtsi32_ss(_mm_setzero_ps(), int(seed >> 16)),
        _mm_load_ss(reinterpret_cast<const float*>(Native(0x131a7ac)))));
}
float NodeDraw() { return Draw(Read<U>(Get<U>(frame.expected, 0x14) + 8) + 0x50); }
// 664B40's reached arguments 1,2,3 map to rows D0,D7,DE respectively.
bool Capability(U order) {
    const U row = 0xd0 + (order - 1) * 7;
    U database = Read<U>(Read<U>(frame.owner + 0x218));
    return Read<U>(Read<U>(database + 0x2c) + row * 24 + 0x14) != 0;
}
U WeightedDraw() {
    const U distribution = frame.owner + 0x45c;
    U model = Read<U>(Read<U>(distribution) + 8);
    float random = Draw(model + 0x50);
    ++eventWords[frame.cls][11];
    U high = Read<U>(distribution + 0xc);
    if (!high) return 0x360;
    float sample = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(random),
        _mm_load_ss(reinterpret_cast<const float*>(distribution + 0x14))));
    U rows = Read<U>(distribution + 0x10), low = 0;
    // Exact native cumulative-table search, including equality and unordered.
    for (;;) {
        U mid = (high + low) >> 1;
        if (Below(Read<float>(rows + mid * 8 + 4), sample)) low = mid;
        else {
            if (!mid || Above(sample, Read<float>(rows + mid * 8 - 4))) return Read<U>(rows + mid * 8);
            high = mid;
        }
        if (low == high) return Read<U>(rows + low * 8);
    }
}
U EffectVA(Kind kind) { return kind == Order ? 0x662e70 : kind == Stop ? 0x6669b0 : 0x6666e0; }
void Emit(Kind kind, Continuation next, U a = 0, U b = 0, U c = 0, U d = 0) {
    frame.hasEvent = true; frame.continuation = next;
    frame.event = {kind, kind == Order ? frame.node : frame.owner, {a, b, c, d}, kind == Action ? 4u : kind == Order ? 3u : 1u};
    ++words[frame.cls][U(PredictedOrders) + U(kind)]; ++eventWords[frame.cls][kind * 3];
}
void RandomAction() {
    if (Below(Read<float>(Native(0x1318034)), NodeDraw())) return;
    U action = WeightedDraw();
    if (action != 0x360) Emit(Action, Finished, action, 1, 0, 0x3f800000);
}
void Tail() {
    const U a = frame.owner;
    if ((Read<B>(a + 0x118) == 1 && ((Read<B>(a + 0x110) & 1) || !Read<B>(a + 0x117)))
        || Read<B>(a + 0x18c)) {
        if (B(ModeResult()) != 1) return;
    }
    if (Read<U>(a + 0x444)) return;
    U order = Get<U>(frame.expected, 0x20);
    B latched = Get<B>(frame.expected, 0x24);
    if (frame.special) { RandomAction(); return; }
    if (order != 0x49) {
        if (!latched) Emit(Order, LatchThenFinish, order);
        else RandomAction();
        return;
    }
    if (latched && Below(Read<float>(Native(0x1318030)), NodeDraw())) { RandomAction(); return; }
    if (Read<B>(a + 0x378)) {
        U current = Read<U>(a + 0x1d8);
        if (current == 0x14 || current == 0x16 || current == 0x15 || current == 6) Put(frame.expected, 0x24, B(1));
        else Emit(Order, LatchThenFinish, 7);
        return;
    }
    if (kntwr_move_node::AdjustOrder(a, 0, 0) == 4) { Emit(Order, LatchThenFinish, 4); return; }
    if (Read<U>(a + 0x1d8)) { Emit(Order, LatchThenFinish); return; }
    float random = NodeDraw();
    B related;
    if (!Getter(a, 0xf0, related)) { Refuse(); return; }
    U choice = 0;
    if (!related) {
        if (Above(Read<float>(Native(0x1325cac)), random) && Capability(1)) choice = 1;
        else if (Above(Read<float>(Native(0x1318038)), random) && Capability(2)) choice = 2;
        else if (Above(Read<float>(Native(0x1325ce0)), random) && Capability(3)) choice = 3;
    }
    Emit(Order, LatchThenFinish, choice);
}
void Predict(Continuation phase) {
    FpGuard guard;
    memcpy(frame.expected, reinterpret_cast<const void*>(frame.node), frame.size);
    frame.owner = Get<U>(frame.expected, 4);
    frame.storeCount = 0; frame.hasEvent = false; frame.observed = false;
    if (phase == Finished) return;
    if (phase == LatchThenFinish) { Put(frame.expected, 0x24, B(1)); return; }
    if (phase == ClearThenTail) Put(frame.expected, 0x24, B(0));
    if (phase == CommonTail || phase == ClearThenTail) { Tail(); return; }
    if (frame.operation == Begin) {
        if (frame.cls && Quiet()) Put(frame.expected, 8, B(1));
        else Emit(Stop, Finished);
        return;
    }
    if (frame.cls) { if (Quiet()) Put(frame.expected, 8, B(1)); return; }
    B answer;
    if (!Getter(frame.owner, 0xec, answer)) { Refuse(); return; }
    if (answer == 1) {
        Emit(Order, Finished, Read<U>(frame.owner + 0x1ec) ? 0x1d : 0, ModeResult()); return;
    }
    if (!Getter(frame.owner, 0xe8, answer)) { Refuse(); return; }
    if (answer == 1) return;
    U related = Read<U>(frame.owner + 0x1ec);
    if (related) {
        if (!Getter(related, 0xf0, answer)) { Refuse(); return; }
        if (answer == 1) return;
    }
    frame.special = false;
    if (kntwr_move_node::First(frame.owner)) {
        // Second reaches +F0 only after the already-certified false +EC.
        if (!related && !Getter(frame.owner, 0xf0, answer)) { Refuse(); return; }
        if (!kntwr_move_node::Second(frame.owner, answer)) { Refuse(); return; }
        frame.special = answer == 1;
    }
    if (frame.special) Emit(Order, CommonTail, 5);
    else if (Read<U>(frame.owner + 0x1d8) == 5) Emit(Order, ClearThenTail);
    else Tail();
}
void ConstructPrediction(const U* args) {
    memcpy(frame.expected, reinterpret_cast<const void*>(frame.node), frame.size);
    U holder = args[0]; frame.owner = Read<U>(holder);
    Put(frame.expected, 0, Table(frame.cls)); Put(frame.expected, 4, frame.owner);
    Put(frame.expected, 8, B(0)); Put(frame.expected, 0xc, U(0)); Put(frame.expected, 0x10, B(0));
    Put(frame.expected, 0x14, Read<U>(holder + 0xa0)); Put(frame.expected, 0x18, U(0));
    StoreValue(holder + 0x9c, 1, 1);
    if (!frame.cls) {
        memcpy(frame.expected + 0x1c, reinterpret_cast<const void*>(args[1]), 8);
        Put(frame.expected, 0x24, B(0)); StoreValue(frame.owner + 0x1d4, 1, 1);
    }
}
void DestroyPrediction() {
    memcpy(frame.expected, reinterpret_cast<const void*>(frame.node), frame.size);
    Put(frame.expected, 0, Native(0x1321188));
    StoreValue(frame.owner + 0x478, 1, 1); StoreValue(frame.owner + 0xee, 0, 1);
    StoreValue(frame.owner + 0x1e0, Read<U>(frame.owner + 0x5e4));
    StoreValue(frame.owner + 0x34, Read<U>(frame.owner + 0x34) & ~0x40u);
    StoreValue(frame.owner + 0x38, Read<U>(frame.owner + 0x38) & ~0x40u);
    StoreValue(frame.owner + 0x1d4, 0, 1);
}
} // namespace
void Bind(U base) { imageBase = base; }
void Configure(bool value) { enabled = value; }
void Abandon() { active = preparing = false; }
void Reset() { memset(words, 0, sizeof(words)); memset(eventWords, 0, sizeof(eventWords)); Abandon(); }
void Release() { enabled = false; Abandon(); }
void Snapshot(U cls, U* output) {
    if (cls >= kClassCount) { memset(output, 0, kWords * sizeof(U)); return; }
    memcpy(output, words[cls], kWords * sizeof(U)); output[Version] = 1; output[Enabled] = enabled;
    output[Bound] = imageBase != 0; output[WorkersBlocked] = 1; output[FakeTableInstalled] = 0;
}
void EventSnapshot(U cls, U* output) {
    if (cls >= kClassCount) { memset(output, 0, kEventWords * sizeof(U)); return; }
    memcpy(output, eventWords[cls], kEventWords * sizeof(U));
}
U Before(U va, U receiver, const U* args, const U*) {
    if (!enabled || !imageBase || preparing || !receiver) return 0;
    if (active && !frame.busy && !frame.refused && frame.hasEvent && va == EffectVA(frame.event.kind)
        && receiver == frame.event.receiver) {
        frame.busy = true; frame.effectToken = Token() | 0x80000000u;
        if (!frame.observed) frame.eventMismatch = true;
        return frame.effectToken;
    }
    Operation op; U cls;
    if (va == 0x61d910 || va == 0x61d8f0) { op = Construct; cls = va == 0x61d8f0; }
    else {
        if (va == 0x665e60 || va == 0x665e30) op = Begin;
        else if (va == 0x66dd10 || va == 0x66dcf0) op = Step;
        else if (va == 0x624ef0 || va == 0x5ac9d0) op = Destroy;
        else return 0;
        U table = Read<U>(receiver);
        if (table != Table(0) && table != Table(1)) return 0;
        cls = table == Table(1);
        const U expectedVA[2][3] = {{0x665e60, 0x66dd10, 0x624ef0}, {0x665e30, 0x66dcf0, 0x5ac9d0}};
        if (va != expectedVA[cls][U(op) - 1]) return 0;
    }
    U* w = words[cls]; ++w[Captures];
    if (active) { ++w[ReentrantRefusals]; ++w[Refused]; ++w[NeedsOwnerCount]; return 0; }
    frame = {}; frame.cls = cls; frame.node = receiver; frame.size = cls ? 0x20 : 0x28; frame.operation = op;
    if (op == Construct && (!args || !args[0] || (!cls && !args[1]))) { Refuse(); return 0; }
    preparing = true;
    if (op == Construct) ConstructPrediction(args);
    else {
        frame.owner = Read<U>(receiver + 4);
        if (!frame.owner) Refuse();
        else if (op == Destroy) DestroyPrediction();
        else Predict(Entry);
    }
    preparing = false;
    if (frame.refused) return 0;
    active = true; frame.token = Token(); ++w[Admitted]; ++w[Constructors + U(op)];
    w[LastNode] = receiver; w[LastOperation] = op; return frame.token;
}
void Observe(U va, U receiver, const U* args) {
    if (!active || preparing || frame.busy || frame.refused || !args) return;
    Kind kind;
    if (va == 0x662e70) kind = Order;
    else if (va == 0x6669b0) kind = Stop;
    else if (va == 0x6666e0) kind = Action;
    else return;
    if (receiver != (kind == Order ? frame.node : frame.owner)) return;
    ++words[frame.cls][U(ObservedOrders) + U(kind)]; ++eventWords[frame.cls][kind * 3 + 1];
    CheckNode(); CheckOwner();
    bool equal = frame.hasEvent && frame.event.kind == kind && !frame.observed;
    U count = kind == Action ? 4 : kind == Order ? 3 : 1;
    for (U i = 0; equal && i < count; ++i) equal = frame.event.args[i] == args[i];
    if (!equal) { frame.eventMismatch = true; ++eventWords[frame.cls][kind * 3 + 2]; }
    frame.observed = true;
}
void After(U token) {
    if (!active || !token) return;
    if (token & 0x80000000u) {
        if (!frame.busy || token != frame.effectToken) { ++words[frame.cls][ReentrantRefusals]; Abandon(); return; }
        preparing = true; Predict(frame.continuation); preparing = false;
        frame.busy = false; ++words[frame.cls][PhaseCheckpoints]; return;
    }
    if (frame.token != token || frame.busy) { ++words[frame.cls][ReentrantRefusals]; Abandon(); return; }
    if (!frame.refused) {
        CheckNode(); CheckOwner(); U* w = words[frame.cls];
        if (frame.hasEvent) { frame.eventMismatch = true; if (!frame.observed) ++eventWords[frame.cls][frame.event.kind * 3 + 2]; }
        ++w[Comparisons];
        if (frame.nodeMismatch) ++w[NodeMismatches];
        if (frame.ownerMismatch) ++w[OwnerMismatches];
        if (frame.eventMismatch) ++w[EventMismatches];
        ++w[frame.nodeMismatch || frame.ownerMismatch || frame.eventMismatch ? Mismatches : Matches];
    }
    active = false;
}
} // namespace kntwr_idle_node
