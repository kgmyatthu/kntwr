#include "native_node.h"
#include "native_node_projection.h"
#include <intrin.h>
#include <xmmintrin.h>
#pragma fenv_access(on)

namespace ntw2_node {
namespace {
static_assert(sizeof(void*) == 4, "reference-node ABI is Win32");
U imageBase, words[kWords], eventWords[kEventWords];
bool enabled, customServices, preparing;
Services services{};
const U* currentEntries;
U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
U Native(U va) { return imageBase + va - 0x400000; }
template<class T> T Read(U p) { T v; memcpy(&v, reinterpret_cast<const void*>(p), sizeof(v)); return v; }
struct FpGuard {
    __declspec(align(16)) B state[512];
    FpGuard() {
        _fxsave(state);
        unsigned short control;
        memcpy(&control, state, sizeof(control));
        control |= 0x3f;
        __asm fninit
        __asm fldcw word ptr [control]
        _mm_setcsr(_mm_getcsr() | 0x1f80);
    }
    ~FpGuard() { _fxrstor(state); }
};
float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Mul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Abs(float a) {
    __asm {
        fld a
        fabs
        fstp a
    }
    return a;
}
// COMISS/JB rejects unordered as well as threshold < abs(diff).
bool Outside(float a, float b, float threshold) {
    float difference = Abs(Sub(a, b));
    B outside;
    __asm {
        movss xmm0, threshold
        comiss xmm0, difference
        setb outside
    }
    return outside != 0;
}
int Threshold(U bits) {
    int value;
    __asm {
        fld dword ptr [bits]
        fistp dword ptr [value]
    }
    uint16_t low = static_cast<uint16_t>(value);
    return low == 0x8000 ? 32768 : static_cast<int16_t>(low);
}
int HeadingDelta(uint16_t a, uint16_t b) {
    int value = static_cast<int16_t>(static_cast<uint16_t>(a - b));
    return value < 0 ? -value : value;
}
bool Arrived(const Input& in) {
    AgentView a{const_cast<B*>(in.owner), in.ownerAddress};
    return !a.Get<U>(0x18) && !Outside(a.Get<float>(0x48), in.desired[0], in.distanceThreshold)
        && !Outside(a.Get<float>(0x50), in.desired[1], in.distanceThreshold)
        && HeadingDelta(a.Get<uint16_t>(0x64), in.desiredHeading) < in.arrivalThreshold;
}
bool Forced(const Input& in) {
    AgentView a{const_cast<B*>(in.owner), in.ownerAddress};
    return static_cast<B>(in.argument) == 1 || a.Get<U>(0x390) == 6 || a.Get<U>(0x390) == 7;
}
bool Refresh(const Input& in) {
    AgentView a{const_cast<B*>(in.owner), in.ownerAddress};
    return Forced(in) || Outside(in.desired[0], in.cached[0], in.distanceThreshold)
        || Outside(in.desired[1], in.cached[2], in.distanceThreshold)
        || HeadingDelta(a.Get<uint16_t>(kNodeOffset + 0x34), in.desiredHeading) > in.refreshThreshold;
}
bool NativeProject(void*, U query, const float planar[2], const U reference[5], U out[5]) {
    U entry = projection::Entry(currentEntries);
    if (!entry || !query || !projection::Ready()) return false;
    ++words[ProjectionCalls];
    using Fn = U (__thiscall*)(U, U*, const float*, const U*, U, U);
    reinterpret_cast<Fn>(entry)(query, out, planar, reference, 3, 0);
    return true;
}
bool NativeDescriptor(void*, U reference, U out[5]) {
    if (Read<B>(reference + 0xb4) == 1) {
        memcpy(out, reinterpret_cast<const void*>(reference + 0x4f8), 20);
        return true;
    }
    // An arbitrary carrier virtual is not certified read-only. An injected
    // owner service can admit its recovered concrete implementation explicitly.
    if (Read<U>(reference + 0x18)) return false;
    U context = Read<U>(reference + 0x28);
    if (!context) return false;
    U model = Read<U>(context + 8);
    if (!model) return false;
    float planar[2] = {Read<float>(reference + 0x48), Read<float>(reference + 0x50)};
    U query = Read<U>(model + 0xb4);
    if (query) {
        U entry = projection::DescriptorEntry(imageBase);
        if (!entry) return false;
        using Fn = U (__thiscall*)(U, U*, const float*, U, U, U);
        reinterpret_cast<Fn>(entry)(query, out, planar, Read<U>(reference + 0x10), 3, 0);
    } else {
        // 5473B0's no-query branch uses the owner terrain sampler, not the
        // shared projection workspace (5473E1 -> 57E870 -> 7EAD80).
        using Fn = U (__thiscall*)(U, U*, const float*, U, U);
        reinterpret_cast<Fn>(Native(0x5473b0))(model, out, planar, Read<U>(reference + 0x10), 3);
    }
    return true;
}
bool NativeMaterialize(void*, const U descriptor[5], float xyz[3]) {
    using Fn = U (__thiscall*)(const U*, float*);
    reinterpret_cast<Fn>(Native(0x80e9d0))(descriptor, xyz);
    return true;
}
bool NativePose(void*, U reference, U owner, float planar[2], uint16_t* heading) {
    const bool alternate = Read<B>(reference + 0x674) == 1;
    const uint16_t offset = Read<uint16_t>(Native(0x14a519c));
    const uint16_t angle = Read<uint16_t>(reference + 0x64);
    *heading = static_cast<uint16_t>(alternate ? angle + offset : angle - offset);
    U link = Read<U>(owner + 0x218);
    if (!link) return false;
    U database = Read<U>(link);
    if (!database) return false;
    U table = Read<U>(database + 0x2c), row = alternate ? 0x23b : 0x23c;
    if (!table) return false;
    if (!Read<U>(table + row * 24 + 0x14)) {
        planar[0] = Read<float>(reference + 0x48);
        planar[1] = Read<float>(reference + 0x50);
        return true;
    }
    // Pure owner-side animation reads recovered in loco-node-animation-getters.asm.
    using RowFn = U (__thiscall*)(U, U, U);
    U record = reinterpret_cast<RowFn>(Native(0xe5f760))(database, row, Read<U>(reference + 0x1e0));
    if (!record) return false;
    float position[3];
    using PoseFn = float* (__thiscall*)(U, float*, U);
    float* value = reinterpret_cast<PoseFn>(Native(0x10f1160))(Read<U>(record + 0x44), position, 0);
    const float x = value[0], z = value[2];
    const int signedAngle = angle == 0x8000 ? 32768 : static_cast<int16_t>(angle);
    float radians = Mul(_mm_cvtss_f32(_mm_cvtsi32_ss(_mm_setzero_ps(), signedAngle)), Read<float>(Native(0x1325c60)));
    float cosine, sine;
    __asm {
        fld radians
        fsincos
        fstp cosine
        fstp sine
    }
    float desired[2] = {
        Add(Add(Mul(cosine, x), Mul(sine, z)), Read<float>(reference + 0x48)),
        Add(Sub(Mul(cosine, z), Mul(sine, x)), Read<float>(reference + 0x50))
    };
    U descriptor[5], projected[5]; float xyz[3];
    U context = Read<U>(reference + 0x28);
    if (!context) return false;
    U model = Read<U>(context + 8);
    if (!model || !NativeDescriptor(nullptr, reference, descriptor)
        || !NativeProject(nullptr, Read<U>(model + 0xb4), desired, descriptor, projected)
        || !NativeMaterialize(nullptr, projected, xyz)) return false;
    planar[0] = xyz[0]; planar[1] = xyz[2];
    return true;
}
Services NativeServices() { return {nullptr, NativePose, NativeDescriptor, NativeMaterialize, NativeProject}; }
template<class T> void Store(Result& result, U offset, T value) {
    memcpy(result.owner + offset, &value, sizeof(value));
    memset(result.defined + offset, 1, sizeof(value));
}
void ClearFlags(Result& result, U mask) {
    AgentView a{result.owner, 0};
    Store(result, 0x34, a.Get<U>(0x34) & ~mask);
    Store(result, 0x38, a.Get<U>(0x38) & ~mask);
}
Event& Emit(Result& result, EventKind kind, U owner) {
    Event& event = result.events[result.eventCount++];
    event = {}; event.kind = kind; event.owner = owner; return event;
}
struct Frame {
    Input input;
    Result predicted;
    Event actualEvents[3];
    B ownCheckpoint[kAgentBytes];
    U observed, token;
    bool eventMismatch, ownerChecked, ownerMismatch;
};
constexpr U kFrames = 8;
Frame frames[kFrames];
U depth, sequence;
void NoteDifference(U offset, B expected, B actual) {
    words[LastMismatchOffset] = offset; words[LastExpected] = expected; words[LastActual] = actual;
}
bool CompareOwn(Frame& frame) {
    const Result& r = frame.predicted;
    const B* live = frame.ownerChecked ? frame.ownCheckpoint : reinterpret_cast<const B*>(frame.input.ownerAddress);
    for (U i = 0; i < kAgentBytes; ++i) {
        if (i >= kNodeOffset && i < kNodeOffset + kNodeBytes) continue;
        if (r.defined[i] && r.owner[i] != live[i]) { NoteDifference(i, r.owner[i], live[i]); return false; }
    }
    return true;
}
bool EqualEvent(const Event& expected, const Event& actual) {
    if (expected.kind != actual.kind || expected.owner != actual.owner
        || memcmp(expected.argument, actual.argument, sizeof(expected.argument))) return false;
    if (expected.kind != Request) return true;
    // +19..1B are untouched native stack bytes. The first 20 bytes start as
    // the reference descriptor; +1..3/+D retain that defined residue.
    // The speed store follows PUSH options, so [ESP+38] addresses options+4.
    return !memcmp(expected.descriptor, actual.descriptor, 20)
        && !memcmp(expected.options, actual.options, 0x19);
}
void Detached(U node, Operation operation, U argument) {
    Input input; Result result;
    FpGuard fp;
    if (!Capture(node - kNodeOffset, operation, argument, services, input)) return;
    Run(input, result);
    for (U i = 0; i < kAgentBytes; ++i)
        if (result.defined[i]) reinterpret_cast<B*>(node - kNodeOffset)[i] = result.owner[i];
    for (U i = 0; i < result.eventCount; ++i) ++eventWords[result.events[i].kind * 3];
}
U __fastcall FakeDestroy(U node, U, U flags) { Detached(node, Destroy, flags); return node; }
void __fastcall FakeBegin(U node, U) { Detached(node, Begin, 1); }
void __fastcall FakeStep(U node, U) { Detached(node, Step, 0); }
U __fastcall NullQuery(U, U) { return 0; }
B __fastcall FalseQuery(U, U) { return 0; }
B __fastcall TrueQuery(U, U) { return 1; }
} // namespace

bool Capture(U owner, Operation operation, U argument, const Services& svc, Input& in) {
    in = {};
    in.mxcsr = _mm_getcsr();
    unsigned short control;
    __asm fnstcw word ptr [control]
    in.fpControl = control;
    if (!owner || !imageBase) return false;
    memcpy(in.owner, reinterpret_cast<const void*>(owner), kAgentBytes);
    in.ownerAddress = owner; in.operation = operation; in.argument = argument;
    AgentView a{in.owner, owner};
    in.referenceTable = Native(0x1334180); in.baseTable = Native(0x1321188);
    if (operation == Construct) {
        in.reference = argument; in.context = a.Get<U>(0x2c8);
        for (U i = 0; i < 3; ++i) in.defaults[i] = Read<U>(Native(0x150fca8) + 4 * i);
        in.defaultHeading = Read<uint16_t>(Native(0x14d05b0));
        in.prepared = true; return true;
    }
    const U table = a.Get<U>(kNodeOffset);
    if (table != in.referenceTable && table != Address(FakeVtable())) return false;
    if (a.Get<U>(kNodeOffset + 4) != owner) return false;
    in.context = a.Get<U>(kNodeOffset + 0x14);
    if (operation == Destroy) {
        if (!in.context || !Read<U>(in.context + 8)) return false;
        in.contextFlag = Read<B>(Read<U>(in.context + 8) + 0x54);
        in.prepared = true; return true;
    }
    in.reference = a.Get<U>(kNodeOffset + 0x1c);
    if (!in.reference) return false;
    in.referenceActive = Read<B>(in.reference + 0xec);
    if (!in.referenceActive) { in.prepared = true; return true; }
    // This read is skipped on the owner-flag branch, exactly as in 67590F.
    if (static_cast<B>(argument) || a.Get<B>(0x117) != 1) {
        U related = Read<U>(in.reference + 0x1ec);
        in.hasRelated = related != 0;
        if (related) in.relatedValue = Read<U>(related + 0x2c);
    }
    if (!svc.pose || !svc.pose(svc.context, in.reference, owner, in.desired, &in.desiredHeading)) return false;
    in.distanceThreshold = Read<float>(Native(0x131a7b0));
    in.arrivalThreshold = Threshold(0x44638e38); in.refreshThreshold = Threshold(0x43360b60);
    if (Arrived(in)) { in.prepared = true; return true; }
    if (!Forced(in)) {
        U cached[5]; memcpy(cached, in.owner + kNodeOffset + 0x20, 20);
        if (!svc.materialize || !svc.materialize(svc.context, cached, in.cached)) return false;
    }
    if (Refresh(in)) {
        if (!in.context) return false;
        U model = Read<U>(in.context + 8);
        if (!model || !a.Get<U>(0x1e8)) return false;
        if (!svc.descriptor || !svc.project
            || !svc.descriptor(svc.context, in.reference, in.referenceDescriptor)
            || !svc.project(svc.context, Read<U>(model + 0xb4), in.desired, in.referenceDescriptor, in.projected)) return false;
        in.requestSpeed = Read<U>(a.Get<U>(0x1e8) + 0x20);
    }
    in.prepared = true; return true;
}
void Run(const Input& in, Result& out) {
    memcpy(out.owner, in.owner, kAgentBytes);
    memset(out.defined, 0, sizeof(out.defined)); out.eventCount = 0;
    if (!in.prepared) return;
    FpGuard fp;
    unsigned short control = in.fpControl | 0x3f;
    __asm fldcw word ptr [control]
    _mm_setcsr(in.mxcsr | 0x1f80);
    memset(out.defined + kNodeOffset, 1, kNodeBytes);
    AgentView a{out.owner, in.ownerAddress};
    if (in.operation == Construct) {
        Store(out, kNodeOffset, in.referenceTable);
        Store(out, kNodeOffset + 4, a.Get<U>(0x228));
        Store(out, kNodeOffset + 8, B(0)); Store(out, kNodeOffset + 0xc, U(0));
        Store(out, kNodeOffset + 0x10, B(0)); Store(out, kNodeOffset + 0x14, in.context);
        Store(out, kNodeOffset + 0x18, U(0)); Store(out, kNodeOffset + 0x1c, in.reference);
        for (U i = 0; i < 3; ++i) Store(out, kNodeOffset + 0x20 + i * 4, in.defaults[i]);
        Store(out, kNodeOffset + 0x2c, U(0)); Store(out, kNodeOffset + 0x30, U(0));
        Store(out, kNodeOffset + 0x34, in.defaultHeading); Store(out, kNodeOffset + 0x36, B(0));
        Store(out, 0x2c4, B(1)); return;
    }
    if (in.operation == Destroy) {
        if (!in.contextFlag && a.Get<B>(kNodeOffset + 0x36) == 1 && !a.Get<U>(0x1ec) && a.Get<B>(0xec) == 1)
            Store(out, 0x34, a.Get<U>(0x34) | 3u);
        Store(out, 0x478, B(1)); Store(out, 0xee, B(0));
        Store(out, 0x1e0, a.Get<U>(0x5e4)); ClearFlags(out, 0x40);
        Store(out, 0x1d4, B(0)); Store(out, kNodeOffset, in.baseTable);
        if ((in.argument & 5) == 5) {
            Event& event = Emit(out, Free, in.ownerAddress);
            event.argument[0] = in.ownerAddress + kNodeOffset; event.argument[1] = kNodeBytes;
        }
        return;
    }
    if (!in.referenceActive) { Store(out, kNodeOffset + 8, B(1)); return; }
    if (!static_cast<B>(in.argument) && a.Get<B>(0x117) == 1) {
        ClearFlags(out, 3); Store(out, kNodeOffset + 0x36, B(1));
    } else if (in.hasRelated) Store(out, 0x3c, in.relatedValue);
    if (Arrived(in)) {
        Emit(out, Arrival, in.ownerAddress).argument[0] = in.reference;
        Event& order = Emit(out, Order, in.ownerAddress);
        order.argument[0] = 0x17; order.argument[1] = 1; order.argument[2] = 0;
        Store(out, kNodeOffset + 8, B(1)); return;
    }
    if (!Refresh(in)) return;
    Event& request = Emit(out, Request, in.ownerAddress);
    memcpy(request.descriptor, in.projected, 20);
    memcpy(request.options, in.referenceDescriptor, 20);
    request.options[0] = 1;
    memcpy(request.options + 4, &in.requestSpeed, 4);
    memset(request.options + 8, 0, 5);
    memcpy(request.options + 0xe, &in.desiredHeading, 2);
    U flags = 0x01010100; memcpy(request.options + 0x10, &flags, 4);
    memset(request.options + 0x14, 0, 5);
    for (U i = 0; i < 5; ++i) Store(out, kNodeOffset + 0x20 + i * 4, in.projected[i]);
    Store(out, kNodeOffset + 0x34, in.desiredHeading);
}
bool Compare(const Result& result, const AgentView& after, U* firstOffset) {
    for (U i = 0; i < kAgentBytes; ++i) if (result.defined[i] && result.owner[i] != after.bytes[i]) {
        if (firstOffset) *firstOffset = i; return false;
    }
    return true;
}
void Bind(U base) { imageBase = base; if (!customServices) services = NativeServices(); }
void SetServices(const Services* svc) { customServices = svc != nullptr; services = svc ? *svc : NativeServices(); }
void Configure(bool value) { enabled = value; }
void Reset() { memset(words, 0, sizeof(words)); memset(eventWords, 0, sizeof(eventWords)); Abandon(); }
void Abandon() { depth = 0; preparing = false; currentEntries = nullptr; }
void Release() { enabled = false; Abandon(); }
void Snapshot(U* output) {
    memcpy(output, words, sizeof(words)); output[Version] = 1; output[Enabled] = enabled;
    output[Bound] = imageBase != 0; output[WorkersBlocked] = 1; output[FakeTableInstalled] = 0;
}
void EventSnapshot(U* output) { memcpy(output, eventWords, sizeof(eventWords)); }
U Before(U va, U receiver, const U* args, const U* entries) {
    if (!enabled || !imageBase || !args) return 0;
    Operation operation;
    U argument;
    if (va == 0x61da90) { operation = Construct; argument = Read<U>(args[1]); }
    else if (va == 0x6758d0) { argument = static_cast<B>(args[0]); operation = argument ? Begin : Step; }
    else if (va == 0x624f80) { operation = Destroy; argument = args[0]; }
    else return 0;
    ++words[Captures];
    if (preparing || depth == kFrames || (operation == Destroy && (argument & 5) == 5)) {
        ++words[Refused]; ++words[ReentrantRefusals]; return 0;
    }
    FpGuard fp;
    preparing = true; currentEntries = entries;
    Frame& frame = frames[depth];
    bool ok = Capture(receiver - kNodeOffset, operation, argument, services, frame.input);
    preparing = false; currentEntries = nullptr;
    if (!ok) { ++words[Refused]; ++words[PreparationFailures]; return 0; }
    frame.observed = 0; frame.eventMismatch = frame.ownerChecked = frame.ownerMismatch = false;
    if (!++sequence) ++sequence;
    frame.token = sequence; ++depth;
    ++words[Admitted]; ++words[Constructors + operation];
    words[LastOwner] = frame.input.ownerAddress; words[LastOperation] = operation;
    return frame.token;
}
void Observe(U va, U receiver, const U* args) {
    if (!depth || preparing || !args) return;
    Event event{};
    if (va == 0x655b20) { event.kind = Arrival; event.argument[0] = args[0]; }
    else if (va == 0x6631a0) { event.kind = Order; memcpy(event.argument, args, 12); }
    else if (va == 0x659520) {
        event.kind = Request;
        memcpy(event.descriptor, reinterpret_cast<const void*>(args[0]), 20);
        memcpy(event.options, reinterpret_cast<const void*>(args[1]), 0x1c);
    } else return;
    Frame& frame = frames[depth - 1];
    if (receiver != frame.input.ownerAddress) return;
    event.owner = receiver;
    if (!frame.ownerChecked) {
        memcpy(frame.ownCheckpoint, reinterpret_cast<const void*>(receiver), kAgentBytes);
        frame.ownerChecked = true;
    }
    ++eventWords[event.kind * 3 + 1]; ++words[ObservedArrivals + event.kind];
    if (frame.observed < 3) frame.actualEvents[frame.observed] = event;
    else { frame.eventMismatch = true; ++eventWords[event.kind * 3 + 2]; }
    ++frame.observed;
}
void After(U token) {
    if (!depth || !token) return;
    Frame& frame = frames[depth - 1];
    if (frame.token != token) { ++words[ReentrantRefusals]; Abandon(); return; }
    Run(frame.input, frame.predicted);
    for (U i = 0; i < frame.predicted.eventCount; ++i) {
        EventKind kind = frame.predicted.events[i].kind;
        ++eventWords[kind * 3]; if (kind <= Request) ++words[PredictedArrivals + kind];
        if (i >= frame.observed || !EqualEvent(frame.predicted.events[i], frame.actualEvents[i])) {
            frame.eventMismatch = true; ++eventWords[kind * 3 + 2];
        }
    }
    for (U i = frame.predicted.eventCount; i < frame.observed && i < 3; ++i)
        ++eventWords[frame.actualEvents[i].kind * 3 + 2];
    ++words[Comparisons];
    bool nodeMismatch = false;
    const B* live = reinterpret_cast<const B*>(frame.input.ownerAddress);
    for (U i = kNodeOffset; i < kNodeOffset + kNodeBytes; ++i) if (frame.predicted.owner[i] != live[i]) {
        NoteDifference(i, frame.predicted.owner[i], live[i]); nodeMismatch = true; break;
    }
    frame.ownerMismatch = !CompareOwn(frame);
    frame.eventMismatch |= frame.observed != frame.predicted.eventCount;
    if (nodeMismatch) ++words[NodeMismatches];
    if (frame.ownerMismatch) ++words[OwnerMismatches];
    if (frame.eventMismatch) ++words[EventMismatches];
    ++words[nodeMismatch || frame.ownerMismatch || frame.eventMismatch ? Mismatches : Matches];
    --depth;
}
const U* FakeVtable() {
    static const U table[kVirtualSlots] = {
        Address(reinterpret_cast<const void*>(&FakeDestroy)), Address(reinterpret_cast<const void*>(&FakeBegin)),
        Address(reinterpret_cast<const void*>(&FakeStep)), Address(reinterpret_cast<const void*>(&NullQuery)),
        Address(reinterpret_cast<const void*>(&NullQuery)), Address(reinterpret_cast<const void*>(&NullQuery)),
        Address(reinterpret_cast<const void*>(&TrueQuery)), Address(reinterpret_cast<const void*>(&FalseQuery)),
        Address(reinterpret_cast<const void*>(&FalseQuery)), Address(reinterpret_cast<const void*>(&FalseQuery)),
        Address(reinterpret_cast<const void*>(&FalseQuery)), Address(reinterpret_cast<const void*>(&TrueQuery)),
        Address(reinterpret_cast<const void*>(&FalseQuery))
    };
    return table;
}
} // namespace ntw2_node
