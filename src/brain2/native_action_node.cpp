#include "native_action_node.h"
#include "native_move_node.h"
#include <string.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#pragma fenv_access(on)

// Approved image SHA256 13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4.
// Concrete tables, not target addresses alone, identify the three classes.
namespace ntw2_action_node {
namespace {
static_assert(sizeof(void*) == 4, "action node ABI is Win32");
U imageBase, words[kClassCount][kWords], events[kClassCount][kEventWords], sequence;
bool enabled, preparing, active;
const U tables[kClassCount] = {0x1347270, 0x1348d2c, 0x1348cc4};
U Native(U va) { return imageBase + va - 0x400000; }
template<class T> T Read(U p) { T v; memcpy(&v, reinterpret_cast<const void*>(p), sizeof(v)); return v; }
template<class T> T Get(const B* p, U offset) { T v; memcpy(&v, p + offset, sizeof(v)); return v; }
template<class T> void Put(B* p, U offset, T v) { memcpy(p + offset, &v, sizeof(v)); }
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
enum Kind : U { Order, Setter, Request, ResetOrder, Move, Pose };
const U effectVA[] = {0x662e70, 0x662e50, 0x659520, 0x6669b0, 0x659d50, 0x66b9d0};
enum Pc : U { Entry, BeginSetter, BeginDecision, BeginNearOrder, BeginPose, StepState,
    StepSix, StepSeven, StepOther, StepTime, StepReset, StepMove, StepFinish, Done };
struct Event {
    Kind kind;
    U receiver, argument[4], mask[4];
    B payload[48], defined[48];
};
struct Frame {
    B node[0x58];
    U nodeAddress, owner, classIndex, size, token, effectToken;
    Operation operation;
    Pc pc;
    const U* entries;
    Event event;
    bool pending, observed, busy, refused, nodeMismatch, ownerMismatch, eventMismatch;
};
Frame frame;
U Token() { sequence = (sequence + 1) & 0x7fffffff; if (!sequence) ++sequence; return sequence; }
void Refuse(Frame& f, ntw2_move_node::Reason reason) {
    f.refused = true; U* w = words[f.classIndex];
    ++w[Refused]; ++w[NeedsOwnerCount];
    ++w[reason == ntw2_move_node::NeedsProjection ? ProjectionNeedsOwner :
        reason == ntw2_move_node::NeedsColdAdjustment ? ColdAdjustmentNeedsOwner : PredicateNeedsOwner];
}
void Difference(Frame& f, U offset, U expected, U actual) {
    U* w = words[f.classIndex]; w[LastMismatchOffset] = offset;
    w[LastExpected] = expected; w[LastActual] = actual;
}
void CheckNode(Frame& f) {
    const B* live = reinterpret_cast<const B*>(f.nodeAddress);
    for (U i = 0; i < f.size; ++i) if (f.node[i] != live[i]) {
        f.nodeMismatch = true; Difference(f, i, f.node[i], live[i]); break;
    }
}
// A straight-line leaf certificate, not a call to an arbitrary virtual. Only
// register loads, constants, address adds and RET are admitted. All memory
// reads are owner reads, and AL-only returns are never promoted to EAX getters.
// This covers concrete getters even when multiple unrelated tables share them.
bool Leaf(U target, U receiver, bool byteResult, U& result) {
    if (target < Native(0x401000) || target >= Native(0x13068e0)) return false;
    const B* code = reinterpret_cast<const B*>(target);
    U eax = 0; bool full = false, low = false;
    for (U n = 0, at = 0; n < 6 && at < 24; ++n) {
        const B* p = code + at;
        if (p[0] == 0xc3) { result = byteResult ? B(eax) : eax; return byteResult ? low : full; }
        if ((p[0] == 0x33 || p[0] == 0x31) && p[1] == 0xc0) { eax = 0; full = low = true; at += 2; continue; }
        if (p[0] == 0x32 && p[1] == 0xc0) { eax &= ~255u; low = true; at += 2; continue; }
        if (p[0] == 0xb0) { eax = (eax & ~255u) | p[1]; low = true; at += 2; continue; }
        if (p[0] == 0xb8) { eax = Get<U>(p, 1); full = low = true; at += 5; continue; }
        if (p[0] == 0x8b && p[1] == 0xc1) { eax = receiver; full = low = true; at += 2; continue; }
        if (p[0] == 0x83 && p[1] == 0xc0 && full) { eax += static_cast<signed char>(p[2]); at += 3; continue; }
        if (p[0] == 0x05 && full) { eax += Get<U>(p, 1); at += 5; continue; }
        U prefix = p[0] == 0x0f && (p[1] == 0xb6 || p[1] == 0xb7) ? 1 : 0;
        const B opcode = p[prefix], modrm = p[prefix + 1];
        if (!prefix && opcode != 0x8b && opcode != 0x8a) return false;
        if ((modrm & 0x38) || (modrm & 7) > 1 || (modrm & 0xc0) == 0xc0) return false;
        const bool fromEax = (modrm & 7) == 0;
        if (fromEax && !full) return false;
        U address = fromEax ? eax : receiver, length = prefix + 2;
        if ((modrm & 0xc0) == 0x40) { address += static_cast<signed char>(p[length]); ++length; }
        else if ((modrm & 0xc0) == 0x80) { address += Get<U>(p, length); length += 4; }
        if (opcode == 0x8a) { eax = (eax & ~255u) | Read<B>(address); low = true; }
        else { eax = opcode == 0xb6 ? Read<B>(address) : opcode == 0xb7 ? Read<uint16_t>(address) : Read<U>(address); full = low = true; }
        at += length;
    }
    return false;
}
bool Virtual(U object, U slot, bool byteResult, U& value) {
    return Leaf(Read<U>(Read<U>(object) + slot), object, byteResult, value);
}
void Emit(Frame& f, Kind kind, U receiver, Pc next) {
    f.event = {}; f.event.kind = kind; f.event.receiver = receiver;
    f.pending = true; f.pc = next;
    ++words[f.classIndex][PredictedEvents]; ++events[f.classIndex][kind * 2];
}
void OrderEvent(Frame& f, U order, U special, Pc next, bool byteSpecial = false) {
    Emit(f, Order, f.nodeAddress, next);
    f.event.argument[0] = order; f.event.argument[1] = special;
    f.event.mask[0] = f.event.mask[2] = ~0u; f.event.mask[1] = byteSpecial ? 255u : ~0u;
}
U AdjustedOrder(const Frame& f, U offset) {
    U order = Get<U>(f.node, offset);
    return Get<B>(f.node, 0x45) ? ntw2_move_node::AdjustOrder(f.owner, order, Get<U>(f.node, 0x38)) : order;
}
bool Descriptor(Frame& f, U descriptor[5]) {
    memcpy(descriptor, f.node + 0x1c, 20);
    if (!Get<B>(f.node, 0x45)) return true;
    U reference[5]; memcpy(reference, descriptor, 20);
    auto reason = ntw2_move_node::AdjustDescriptor(f.owner, reference, f.entries, descriptor,
        &words[f.classIndex][PrivateProjectionCalls]);
    if (reason == ntw2_move_node::Ready) return true;
    Refuse(f, reason); return false;
}
void Materialize(const U descriptor[5], float xyz[3]) {
    // 80E9D0 -> 7F4950 only: pure reference-to-world affine arithmetic.
    reinterpret_cast<U (__thiscall*)(const U*, float*)>(Native(0x80e9d0))(descriptor, xyz);
}
bool Near(Frame& f, bool& near) {
    near = false;
    if (Get<B>(f.node, 0x45) != 1) return true;
    if (Read<B>(f.owner + 0x118) == 1 &&
        ((Read<B>(f.owner + 0x110) & 1) || !Read<B>(f.owner + 0x117))) return true;
    U group = Read<U>(f.owner + 0x1f0); if (!group) return true;
    float scale;
    if (!ntw2_move_node::AdjustmentScale(group, scale)) { Refuse(f, ntw2_move_node::NeedsColdAdjustment); return false; }
    float square;
    __asm { fld scale }
    __asm { fmul scale }
    __asm { fstp square }
    U descriptor[5]; memcpy(descriptor, f.node + 0x1c, 20); float xyz[3]; Materialize(descriptor, xyz);
    __m128 x = _mm_sub_ss(_mm_set_ss(xyz[0]), _mm_set_ss(Read<float>(f.owner + 0x48)));
    __m128 z = _mm_sub_ss(_mm_set_ss(xyz[2]), _mm_set_ss(Read<float>(f.owner + 0x50)));
    __m128 distance = _mm_add_ss(_mm_mul_ss(z, z), _mm_mul_ss(x, x));
    near = _mm_comigt_ss(_mm_set_ss(square), distance) != 0; return true;
}
bool TimedAction(Frame& f, bool& ready) {
    ready = false;
    if (Get<B>(f.node, 8) || !Get<U>(f.node, 0x4c)) return true;
    U tick = Read<U>(Read<U>(Get<U>(f.node, 0x14) + 8) + 0x58);
    __m128d seconds = _mm_cvtepi32_pd(_mm_cvtsi32_si128(static_cast<int>(tick)));
    seconds = _mm_add_sd(seconds, _mm_load_sd(reinterpret_cast<const double*>(Native(0x1318130) + (tick >> 31) * 8)));
    __m128 elapsed = _mm_sub_ss(_mm_mul_ss(_mm_cvtpd_ps(seconds),
        _mm_set_ss(Read<float>(Native(0x131a7b0)))), _mm_set_ss(Get<float>(f.node, 0x50)));
    if (!_mm_comige_ss(elapsed, _mm_set_ss(Read<float>(Native(0x150fc2c))))) return true;
    U value, surface = Get<U>(f.node, 0x28);
    if (surface) {
        if (!Virtual(surface, 0x34, true, value)) return false;
        if (value) return true;
    }
    U first = Read<U>(f.owner + 0x10);
    if (first) {
        if (!Virtual(first, 0x20, false, value)) return false;
        if (value && Read<U>(Read<U>(value + 0x60) + 0x14) == Get<U>(f.node, 0x4c)) {
            if (!Virtual(first, 0x34, true, value)) return false;
            if (!value) { ready = true; return true; }
        }
    }
    U second = Read<U>(f.owner + 0x18);
    if (!second) return true;
    U bridge = Read<U>(second + 0x1c);
    if (!Virtual(bridge, 0x1c, false, value)) return false;
    if (!value) return true;
    if (!Virtual(value, 0x20, false, value)) return false;
    if (!value || Read<U>(Read<U>(value + 0x60) + 0x14) != Get<U>(f.node, 0x4c)) return true;
    if (!Virtual(second, 0x10, true, value)) return false;
    ready = value == 0; return true;
}
bool RelatedOrder(Frame& f, U& order) {
    U related = Read<U>(f.owner + 0x1ec), value;
    if (f.classIndex == RelatedStep) {
        U state = Read<U>(related + 0x220);
        if (state == 2) { order = 0x19; return true; }
        if (state == 3) { order = 0x18; return true; }
        U group = Read<U>(f.owner + 0x1f0);
        if (Read<U>(group + 0x930)) {
            U record = group + 0x398 + Read<U>(group + 0x934) * 0x90;
            if (!Virtual(record, 0x2c, true, value)) return false;
            if (value == 1) { order = 0x18; return true; }
        }
    }
    U object = Read<U>(related + 0x628);
    if (!object) { order = 0x17; return true; }
    if (!Virtual(object, 0, false, value)) return false;
    order = value ? 0x18 : 0x17; return true;
}
void Predict(Frame& f) {
    FpGuard fp;
    f.pending = f.observed = false;
    for (;;) switch (f.pc) {
    case Entry: {
        if (f.classIndex != DescriptorAction) {
            if ((f.classIndex == RelatedStep && f.operation == Begin) ||
                (f.classIndex == RelatedBegin && f.operation == Step)) { f.pc = Done; return; }
            U order;
            if (!RelatedOrder(f, order)) { Refuse(f, ntw2_move_node::NeedsOwner); return; }
            OrderEvent(f, order, 0, Done); return;
        }
        B second = 0;
        bool first = ntw2_move_node::First(f.owner);
        if (first && !ntw2_move_node::Second(f.owner, second)) { Refuse(f, ntw2_move_node::NeedsOwner); return; }
        bool special = first && second;
        if (special || f.operation == Begin || Read<U>(f.owner + 0x1d8) == 5) {
            OrderEvent(f, special ? 5 : AdjustedOrder(f, 0x30), special ? 1 : 0,
                f.operation == Begin ? BeginSetter : StepState, f.operation == Begin); return;
        }
        f.pc = StepState; break;
    }
    case BeginSetter:
        Emit(f, Setter, f.nodeAddress, BeginDecision);
        f.event.argument[0] = Get<U>(f.node, 0x38); f.event.mask[0] = ~0u; return;
    case BeginDecision: {
        bool near; if (!Near(f, near)) return;
        if (near) {
            if (Get<B>(f.node, 0x42) != 1) { OrderEvent(f, Get<U>(f.node, 0x34), 0, BeginNearOrder); return; }
            U descriptor[5]; memcpy(descriptor, f.node + 0x1c, 20); float xyz[3]; Materialize(descriptor, xyz);
            Emit(f, Pose, f.owner, BeginPose); f.event.mask[1] = ~0u;
            // 61E9A0 -> 7F6720 -> 7F6820/7F6770 writes only this local pose.
            reinterpret_cast<U (__thiscall*)(B*, const float*, U, U)>(Native(0x61e9a0))(
                f.event.payload, xyz, Get<uint16_t>(f.node, 0x40), Get<U>(f.node, 0x2c));
            memset(f.event.defined, 1, 14); memset(f.event.defined + 16, 1, 4); return;
        }
        U descriptor[5]; if (!Descriptor(f, descriptor)) return;
        Emit(f, Request, f.owner, Done);
        memcpy(f.event.payload, descriptor, 20); memset(f.event.defined, 1, 20);
        B* option = f.event.payload + 20; B* mask = f.event.defined + 20;
        if (Get<B>(f.node, 0x45)) { memcpy(option, descriptor, 20); memset(mask, 1, 20); }
        option[0] = Get<B>(f.node, 0x42) ? 1 : Get<B>(f.node, 0x44); mask[0] = 1;
        Put(option, 4, Get<U>(f.node, 0x3c)); Put(option, 8, U(0)); option[12] = 0;
        memset(mask + 4, 1, 9);
        Put(option, 14, Get<B>(f.node, 0x42) ? Get<uint16_t>(f.node, 0x40) : Read<uint16_t>(Native(0x150fb24)));
        Put(option, 16, Get<B>(f.node, 0x42) ? U(0x10100) | (U(Get<B>(f.node, 0x43)) << 24) : U(0x100));
        Put(option, 20, Get<U>(f.node, 0x48)); option[24] = 0; memset(mask + 14, 1, 11); return;
    }
    case BeginNearOrder: Put(f.node, 8, B(1)); f.pc = Done; return;
    case BeginPose: Put(f.node, 0x54, B(0)); f.pc = Done; return;
    case StepState:
        if (Get<B>(f.node, 0x54) == 1) {
            U state = Read<U>(f.owner + 0x390);
            if (state == 6 || state == 7) { OrderEvent(f, AdjustedOrder(f, 0x34), 0, state == 6 ? StepSix : StepSeven); return; }
        } else if (Read<B>(f.owner + 0x117) == 1) { OrderEvent(f, AdjustedOrder(f, 0x34), 0, StepOther); return; }
        f.pc = StepTime; break;
    case StepSix:
        Put(f.node, 8, B(1)); if (Read<B>(f.owner + 0x13c) == 1) Put(f.node, 0x18, U(1)); f.pc = StepTime; break;
    case StepSeven: Put(f.node, 0x18, U(1)); Put(f.node, 8, B(1)); f.pc = StepTime; break;
    case StepOther: Put(f.node, 8, B(1)); f.pc = StepTime; break;
    case StepTime: {
        bool ready; if (!TimedAction(f, ready)) { Refuse(f, ntw2_move_node::NeedsOwner); return; }
        if (!ready) { f.pc = Done; return; }
        Emit(f, ResetOrder, f.owner, StepReset); f.event.mask[0] = ~0u; return;
    }
    case StepReset: {
        U descriptor[5]; if (!Descriptor(f, descriptor)) return;
        float xyz[3]; Materialize(descriptor, xyz);
        Emit(f, Move, f.nodeAddress, StepMove);
        Put(f.event.payload, 0, xyz[0]); Put(f.event.payload, 4, xyz[2]); memset(f.event.defined, 1, 8);
        f.event.argument[1] = Get<B>(f.node, 0x42) == 1 ? Get<uint16_t>(f.node, 0x40) : Read<uint16_t>(f.owner + 0x64);
        f.event.argument[2] = descriptor[3]; f.event.argument[3] = 1;
        f.event.mask[1] = 0xffff; f.event.mask[2] = f.event.mask[3] = ~0u; return;
    }
    case StepMove: OrderEvent(f, AdjustedOrder(f, 0x34), 0, StepFinish); return;
    case StepFinish: Put(f.node, 8, B(1)); f.pc = Done; return;
    case Done: return;
    }
}
bool EmptySite(U site, Operation& op) {
    switch (site) {
    case 0x658f70: case 0x64df02: case 0x670f10: case 0x66c17d: op = Begin; return true;
    case 0x658f81: case 0x64df13: case 0x670f21: case 0x66c18e: op = Step; return true;
    default: return false;
    }
}
} // namespace
void Bind(U base) { imageBase = base; }
void Configure(bool value) { enabled = value; }
void Abandon() { active = preparing = false; }
void Reset() { memset(words, 0, sizeof(words)); memset(events, 0, sizeof(events)); Abandon(); }
void Release() { enabled = false; Abandon(); }
void Snapshot(U index, U* output) {
    if (index >= kClassCount) { memset(output, 0, kWords * sizeof(U)); return; }
    memcpy(output, words[index], sizeof(words[index])); output[Version] = 1;
    output[Enabled] = enabled; output[Bound] = imageBase != 0;
    output[WorkersBlocked] = 1; output[FakeTableInstalled] = 0;
}
void EventSnapshot(U index, U* output) {
    if (index >= kClassCount) { memset(output, 0, kEventWords * sizeof(U)); return; }
    memcpy(output, events[index], sizeof(events[index]));
}
U Before(U va, U receiver, const U* args, const U* entries) { return BeforeSite(va, 0, receiver, args, entries); }
U BeforeSite(U va, U site, U receiver, const U*, const U* entries) {
    if (!enabled || !imageBase || preparing) return 0;
    if (active) {
        Frame& f = frame;
        if (!f.busy && !f.refused && f.pending && va == effectVA[f.event.kind] && receiver == f.event.receiver) {
            f.busy = true; f.effectToken = Token() | 0x80000000u;
            if (!f.observed) { f.eventMismatch = true; ++events[f.classIndex][13]; }
            return f.effectToken;
        }
        // Descendants of original transactions are not node observations.
        return 0;
    }
    Operation op;
    if (va == 0x816080 || va == 0x815ff0) op = Begin;
    else if (va == 0x818500 || va == 0x818330) op = Step;
    else if (va != 0x444b60 || !EmptySite(site, op)) return 0;
    if (!receiver) return 0;
    U table = Read<U>(receiver), index;
    for (index = 0; index < kClassCount && table != Native(tables[index]); ++index) {}
    if (index == kClassCount) return 0;
    if (va != (index == DescriptorAction ? (op == Begin ? 0x816080u : 0x818500u) :
        index == RelatedStep ? (op == Begin ? 0x444b60u : 0x818330u) : (op == Begin ? 0x815ff0u : 0x444b60u))) return 0;
    Frame& f = frame; f = {}; f.classIndex = index; f.operation = op;
    f.nodeAddress = receiver; f.owner = Read<U>(receiver + 4); f.size = index == DescriptorAction ? 0x58 : 0x1c;
    f.entries = entries; f.pc = Entry; memcpy(f.node, reinterpret_cast<const void*>(receiver), f.size);
    U* w = words[index]; ++w[Captures]; w[LastNode] = receiver; w[LastOperation] = op;
    preparing = true; Predict(f); preparing = false;
    if (f.refused) return 0;
    ++w[Admitted]; ++w[op == Begin ? Begins : Steps];
    if (va == 0x444b60) ++w[op == Begin ? EmptyBegins : EmptySteps];
    f.token = Token(); active = true; return f.token;
}
void Observe(U va, U receiver, const U* args) {
    if (!active || preparing || !args) return;
    Frame& f = frame; if (f.busy || f.refused) return;
    U kind; for (kind = 0; kind < 6 && va != effectVA[kind]; ++kind) {}
    if (kind == 6 || receiver != ((kind == Request || kind == ResetOrder || kind == Pose) ? f.owner : f.nodeAddress)) return;
    Event actual{}; actual.kind = static_cast<Kind>(kind); actual.receiver = receiver;
    U count = kind == Order ? 3 : kind == Setter || kind == ResetOrder ? 1 : kind == Move ? 4 : 2;
    memcpy(actual.argument, args, count * sizeof(U));
    if (kind == Request) { memcpy(actual.payload, reinterpret_cast<const void*>(args[0]), 20); memcpy(actual.payload + 20, reinterpret_cast<const void*>(args[1]), 28); }
    else if (kind == Move || kind == Pose) memcpy(actual.payload, reinterpret_cast<const void*>(args[0]), kind == Move ? 8 : 20);
    ++words[f.classIndex][ObservedEvents]; ++events[f.classIndex][kind * 2 + 1]; CheckNode(f);
    bool equal = f.pending && !f.observed && f.event.kind == actual.kind && f.event.receiver == actual.receiver;
    for (U i = 0; i < 4; ++i) if ((actual.argument[i] ^ f.event.argument[i]) & f.event.mask[i]) equal = false;
    for (U i = 0; i < 48; ++i) if (f.event.defined[i] && actual.payload[i] != f.event.payload[i]) equal = false;
    if (!equal) { f.eventMismatch = true; ++events[f.classIndex][12]; }
    f.observed = true;
}
void After(U token) {
    if (!active || !token) return;
    Frame& f = frame; U* w = words[f.classIndex];
    if (token & 0x80000000u) {
        if (!f.busy || token != f.effectToken) { ++w[ReentrantRefusals]; Abandon(); return; }
        if (f.event.kind == Setter) {
            U value = Read<U>(f.owner + 0x220);
            if (value != f.event.argument[0]) { f.ownerMismatch = true; Difference(f, 0x220, f.event.argument[0], value); }
        }
        // The real effect owns its complete mutation. Independently predict
        // the successor from a fresh checkpoint, not the stale entry snapshot.
        memcpy(f.node, reinterpret_cast<const void*>(f.nodeAddress), f.size);
        f.owner = Get<U>(f.node, 4); f.busy = false; ++w[PhaseCheckpoints];
        preparing = true; Predict(f); preparing = false; return;
    }
    if (f.token != token || f.busy) { ++w[ReentrantRefusals]; Abandon(); return; }
    if (!f.refused) {
        CheckNode(f);
        if (f.pending) { f.eventMismatch = true; ++events[f.classIndex][13]; }
        ++w[Comparisons]; if (f.nodeMismatch) ++w[NodeMismatches];
        if (f.ownerMismatch) ++w[OwnerMismatches]; if (f.eventMismatch) ++w[EventMismatches];
        ++w[f.nodeMismatch || f.ownerMismatch || f.eventMismatch ? Mismatches : Matches];
    }
    active = false;
}
} // namespace ntw2_action_node
