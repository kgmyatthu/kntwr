#include "native_move_node.h"
#include "native_node_projection.h"
#include <intrin.h>
#include <xmmintrin.h>
#pragma fenv_access(on)

// Pinned Napoleon.exe SHA256 13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4.
// Class 1348B44: ctor 7E2C80..7E2CF1, begin 816900..816A4B,
// step 819310..819389, deleting dtor 7EDD00..7EDD24 (exclusive ends).
// All observations are owner-serial. No fake vtable, live writes, or duplicate
// order/request transaction is used by this differential implementation.
namespace ntw2_move_node {
namespace {
static_assert(sizeof(void*) == 4, "hot movement-node ABI is Win32");
U imageBase, words[kWords], eventWords[kEventWords], sequence;
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
} // namespace
// 64F8F0 -> 55B0A0 -> 55AD60. No virtual calls or mutable static state.
bool First(U owner) {
    U group = Read<U>(owner + 0x1f0);
    if (!group || Read<B>(group + 0xda4) == 1) return false;
    U model = Read<U>(Read<U>(group + 0x14) + 8);
    U mode = Read<U>(Read<U>(model + 0xb0) + 0x14);
    if (mode != 0 && mode != 1 && _mm_comigt_ss(
        _mm_load_ss(reinterpret_cast<const float*>(Native(0x1325d24))),
        _mm_load_ss(reinterpret_cast<const float*>(group + 0xda8)))) return false;
    return Read<B>(group + 0xd9e) != 0;
}
bool StubByte(U target, B& value) {
    if (target == Native(0x462cb0) || target == Native(0x461180)) { value = 0; return true; }
    if (target == Native(0x447880)) { value = 1; return true; }
    return false;
}
// 63B3E0 short-circuits at each virtual. Never invoke an unknown owner getter.
bool Second(U owner, B& value) {
    value = 0;
    if (Read<U>(owner + 0x1ec)) return true;
    const U slots[] = {0xec, 0xf0, 0xe8};
    for (U offset : slots) {
        B answer;
        const U target = Read<U>(Read<U>(owner) + offset);
        if (target == Native(0x5db820)) answer = Read<U>(owner + 0x67c) != 0;
        else if (!StubByte(target, answer)) return false;
        if (answer) return true;
    }
    value = 1; return true;
}
// 66AE10 -> 586400 uses signed group+194 comparisons, NOT unsigned.
U AdjustOrder(U owner, U order, U mode) {
    U group = Read<U>(owner + 0x1f0);
    if (!group || order) return order;
    const int rank = Read<int>(group + 0x194);
    if (!((mode == 0 && rank >= 3) || (mode == 1 && rank >= 4))) return order;
    U database = Read<U>(Read<U>(owner + 0x218));
    return Read<U>(Read<U>(database + 0x2c) + 0x59c) ? 4 : order;
}
// 57E1F0 -> 55C9A0 -> 57ACA0/57AC90/557450: first tag-4 row's byte+28.
// Otherwise E1BBD0 is a lazy owner loader. Only its ALREADY LOADED +6BC
// branch is pure; the cold loader (allocation/UI/file work) is never replayed.
bool AdjustmentScale(U group, float& scale) {
    U count = Read<U>(group + 0xdac + 0xc), data = Read<U>(group + 0xdac + 0x10);
    for (U i = 0; i < count; ++i) {
        U row = data + i * 0x2c;
        if (Read<U>(Read<U>(row + 4)) != 4) continue;
        if (Read<B>(row + 0x28)) { scale = Read<float>(Native(0x131a7b8)); return true; }
        break;
    }
    U root = Read<U>(group + 0x14);
    U manager = Read<U>(Read<U>(root + 0x2804c) + 0x10);
    U loaded = Read<U>(manager + 0x6bc);
    if (!loaded) return false;
    U row = Read<U>(loaded + 0x5c + Read<U>(group + 0x194) * 4);
    scale = Read<float>(row + 0xc); return true;
}
Reason AdjustDescriptor(U owner, const U reference[5], const U* entries, U output[5], U* projectionCalls, U* refusedTarget) {
    memcpy(output, reference, 20);
    U group = Read<U>(owner + 0x1f0);
    if (!group) return Ready; // the complete 66AD00 no-group branch
    float scale;
    if (!AdjustmentScale(group, scale)) return NeedsColdAdjustment;
    // Recover the exact x87-rounded distance, then separate SSE products/adds.
    const float multiplier = Read<float>(owner + 0x5d0);
    float distance;
    __asm {
        fld scale
        fmul multiplier
        fstp distance
    }
    uint16_t angle = static_cast<uint16_t>(Read<uint16_t>(owner + 0x5cc) + Read<uint16_t>(owner + 0x64));
    const __m128 length = _mm_set_ss(distance);
    float dx = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(Read<float>(Native(0x176cff8) + U(angle) * 8)), length));
    float dz = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(Read<float>(Native(0x176cffc) + U(angle) * 8)), length));
    U root = Read<U>(owner + 0x28), model = Read<U>(root + 8), query = Read<U>(model + 0xb4);
    // The private traversal certifies each REACHED world callback before it
    // executes; accepted cells and grid lookup no longer imply refusal.
    float xyz[3];
    using Materialize = U (__thiscall*)(const U*, float*);
    reinterpret_cast<Materialize>(Native(0x80e9d0))(reference, xyz);
    float planar[2] = {
        _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(dx), _mm_set_ss(xyz[0]))),
        _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(dz), _mm_set_ss(xyz[2])))
    };
    if (!ntw2_node::projection::ProjectCertified(entries, query, output, planar, reference, 3, refusedTarget))
        return NeedsProjection;
    if (projectionCalls) ++*projectionCalls;
    return Ready;
}
namespace {
void OwnerStore(Result& out, U address, U value, U width = 4) {
    out.ownerWrites[out.ownerWriteCount++] = {address, value, width};
}
void Emit(Result& out, EventKind kind, U receiver) {
    out.hasEvent = true; out.event.kind = kind; out.event.receiver = receiver;
}
struct Frame {
    Input input;
    Result predicted;
    U token, effectToken, effectVA, args[2];
    const U* entries;
    bool observed, busy, refused, nodeMismatch, ownerMismatch, eventMismatch;
};
Frame frames[8]; U depth;
U Token() { sequence = (sequence + 1) & 0x7fffffffu; if (!sequence) ++sequence; return sequence; }
void Difference(U offset, B expected, B actual) {
    words[LastMismatchOffset] = offset; words[LastExpected] = expected; words[LastActual] = actual;
}
void CheckNode(Frame& f) {
    const B* live = reinterpret_cast<const B*>(f.input.nodeAddress);
    for (U i = 0; i < kNodeBytes; ++i) if (live[i] != f.predicted.node[i]) {
        f.nodeMismatch = true; Difference(i, f.predicted.node[i], live[i]); break;
    }
}
void CheckOwner(Frame& f) {
    for (U i = 0; i < f.predicted.ownerWriteCount; ++i) {
        const auto& store = f.predicted.ownerWrites[i];
        const B* live = reinterpret_cast<const B*>(store.address);
        const B* expected = reinterpret_cast<const B*>(&store.value);
        for (U j = 0; j < store.width; ++j) if (live[j] != expected[j]) {
            f.ownerMismatch = true; Difference(store.address - f.input.ownerAddress + j, expected[j], live[j]); break;
        }
    }
}
void Refuse(Reason reason) {
    ++words[Refused];
    if (reason != WrongNode) {
        ++words[NeedsOwnerCount];
        ++eventWords[reason == NeedsProjection ? 9 : reason == NeedsColdAdjustment ? 11 : 10];
    }
}
void Predict(Frame& f) {
    Run(f.input, f.predicted); f.observed = false;
    if (f.predicted.hasEvent) {
        U kind = f.predicted.event.kind;
        ++words[PredictedOrders + kind]; ++eventWords[kind * 3];
    }
}
U EffectVA(EventKind kind) { return kind == Order ? 0x662e70 : kind == Setter ? 0x662e50 : 0x659520; }
} // namespace

Reason Capture(U node, Operation op, Phase phase, const U* args, const U* entries, Input& in) {
    in = {}; in.reason = WrongNode;
    if (!imageBase || !node) return in.reason;
    FpGuard fp;
    memcpy(in.node, reinterpret_cast<const void*>(node), kNodeBytes);
    in.nodeAddress = node; in.operation = op; in.phase = phase;
    in.table = Native(0x1348b44); in.baseTable = Native(0x1321188);
    if (op == Construct) {
        if (!args || !args[0] || !args[1]) return in.reason;
        in.holder = args[0]; in.ownerAddress = Read<U>(args[0]);
        in.context = Read<U>(args[0] + 0xa0);
        memcpy(in.constructor, reinterpret_cast<const void*>(args[1]), sizeof(in.constructor));
        return in.reason = Ready;
    }
    if (Get<U>(in.node, 0) != in.table || !Get<U>(in.node, 4)) return in.reason;
    in.ownerAddress = Get<U>(in.node, 4);
    if (op == Destroy) {
        in.argument = args ? args[0] : 0;
        in.ownerFlags[0] = Read<U>(in.ownerAddress + 0x34);
        in.ownerFlags[1] = Read<U>(in.ownerAddress + 0x38);
        in.ownerRestore = Read<U>(in.ownerAddress + 0x5e4);
        return in.reason = Ready;
    }
    if (op == Step) in.movementState = Read<U>(in.ownerAddress + 0x390);
    if (phase == Entry) {
        in.firstPredicate = First(in.ownerAddress);
        if (in.firstPredicate && !Second(in.ownerAddress, in.secondPredicate)) return in.reason = NeedsOwner;
        in.orderState = Read<U>(in.ownerAddress + 0x1d8);
        in.selectedOrder = Get<U>(in.node, 0x34);
        if (!(in.firstPredicate && in.secondPredicate) && (op == Begin || in.orderState == 5)
            && Get<B>(in.node, 0x45))
            in.selectedOrder = AdjustOrder(in.ownerAddress, in.selectedOrder, Get<U>(in.node, 0x38));
    } else if (op == Begin && phase == SetterReturned) {
        in.defaultHeading = Read<uint16_t>(Native(0x150fb24));
        memcpy(in.descriptor, in.node + 0x1c, 20);
        if (Get<B>(in.node, 0x45)) {
            U reference[5]; memcpy(reference, in.node + 0x1c, 20);
            Reason reason = AdjustDescriptor(in.ownerAddress, reference, entries, in.descriptor, eventWords + 12, eventWords + 13);
            if (reason != Ready) return in.reason = reason;
        }
    }
    return in.reason = Ready;
}
void Run(const Input& in, Result& out) {
    out = {}; memcpy(out.node, in.node, kNodeBytes);
    if (in.reason != Ready) return;
    if (in.operation == Construct) {
        Put(out.node, 0, in.table); Put(out.node, 4, in.ownerAddress);
        Put(out.node, 8, B(0)); Put(out.node, 0xc, U(0)); Put(out.node, 0x10, B(0));
        Put(out.node, 0x14, in.context); Put(out.node, 0x18, U(0));
        memcpy(out.node + 0x1c, in.constructor, 20);
        memcpy(out.node + 0x30, in.constructor + 0x14, 2);
        memcpy(out.node + 0x34, in.constructor + 0x18, 16);
        memcpy(out.node + 0x44, in.constructor + 0x28, 2);
        OwnerStore(out, in.holder + 0x9c, 1, 1); return;
    }
    if (in.operation == Destroy) {
        Put(out.node, 0, in.baseTable);
        OwnerStore(out, in.ownerAddress + 0x478, 1, 1);
        OwnerStore(out, in.ownerAddress + 0xee, 0, 1);
        OwnerStore(out, in.ownerAddress + 0x1e0, in.ownerRestore);
        OwnerStore(out, in.ownerAddress + 0x34, in.ownerFlags[0] & ~0x40u);
        OwnerStore(out, in.ownerAddress + 0x38, in.ownerFlags[1] & ~0x40u);
        OwnerStore(out, in.ownerAddress + 0x1d4, 0, 1);
        // Deleting branch calls 444B60(node,48): pinned empty RET, not a free.
        return;
    }
    if (in.phase == Entry) {
        const bool special = in.operation == Begin ? in.firstPredicate && in.secondPredicate
            : in.firstPredicate == 1 && in.secondPredicate == 1;
        if (special || in.operation == Begin || in.orderState == 5) {
            Emit(out, Order, in.nodeAddress);
            out.event.argument[0] = special ? 5 : in.selectedOrder;
            out.event.argument[1] = special ? 1 : 0;
            out.event.argumentMask[0] = out.event.argumentMask[2] = ~0u;
            // Begin writes just AL-sized [ESP+4], then PUSHes the dword.
            out.event.argumentMask[1] = in.operation == Begin ? 0xffu : ~0u;
            return;
        }
    }
    if (in.operation == Step) {
        if (in.movementState == 7) {
            Put(out.node, 0x18, U(1)); Put(out.node, 8, B(1));
        } else if (in.movementState == 6 && Get<B>(in.node, 0x44) == 1) Put(out.node, 8, B(1));
        return;
    }
    if (in.phase == OrderReturned) {
        Emit(out, Setter, in.nodeAddress);
        out.event.argument[0] = Get<U>(in.node, 0x38); out.event.argumentMask[0] = ~0u;
        OwnerStore(out, in.ownerAddress + 0x220, out.event.argument[0]);
    } else if (in.phase == SetterReturned) {
        Emit(out, Request, in.ownerAddress);
        memcpy(out.event.descriptor, in.descriptor, 20);
        // 81697F (or 66AD00) fills stack+1C with a descriptor before it is
        // reused as request options: +1..3 and +D retain defined descriptor
        // bytes. +19..1B are never initialized and MUST NOT be compared.
        memcpy(out.event.options, in.descriptor, 20);
        memset(out.event.optionsDefined, 1, 0x19);
        const bool heading = Get<B>(in.node, 0x44) == 1;
        out.event.options[0] = heading ? 1 : 0;
        memcpy(out.event.options + 4, in.node + 0x3c, 8);
        out.event.options[0xc] = 1;
        Put(out.event.options, 0xe, heading ? Get<uint16_t>(in.node, 0x30) : in.defaultHeading);
        Put(out.event.options, 0x10, heading ? U(0x10100) : U(0x100));
        Put(out.event.options, 0x14, U(0)); out.event.options[0x18] = 0;
    }
}
bool EqualEvent(const Event& expected, const Event& actual) {
    if (expected.kind != actual.kind || expected.receiver != actual.receiver) return false;
    for (U i = 0; i < 3; ++i)
        if ((expected.argument[i] ^ actual.argument[i]) & expected.argumentMask[i]) return false;
    if (expected.kind != Request) return true;
    if (memcmp(expected.descriptor, actual.descriptor, 20)) return false;
    for (U i = 0; i < 0x1c; ++i)
        if (expected.optionsDefined[i] && expected.options[i] != actual.options[i]) return false;
    return true;
}
void Bind(U base) { imageBase = base; }
void Configure(bool value) { enabled = value; }
void Abandon() { depth = 0; preparing = false; }
void Reset() { memset(words, 0, sizeof(words)); memset(eventWords, 0, sizeof(eventWords)); Abandon(); }
void Release() { enabled = false; Abandon(); }
void Snapshot(U* output) {
    memcpy(output, words, sizeof(words)); output[Version] = 1; output[Enabled] = enabled;
    output[Bound] = imageBase != 0; output[WorkersBlocked] = 1; output[FakeTableInstalled] = 0;
}
void EventSnapshot(U* output) { memcpy(output, eventWords, sizeof(eventWords)); }
U Before(U va, U receiver, const U* args, const U* entries) {
    if (!enabled || !imageBase || preparing) return 0;
    if (depth) {
        Frame& f = frames[depth - 1];
        if (!f.busy && !f.refused && f.predicted.hasEvent && va == EffectVA(f.predicted.event.kind)
            && receiver == f.predicted.event.receiver) {
            f.busy = true; f.effectVA = va; f.effectToken = Token() | 0x80000000u;
            if (!f.observed) f.eventMismatch = true;
            return f.effectToken;
        }
    }
    Operation op;
    if (va == 0x7e2c80) op = Construct;
    else if (va == 0x816900) op = Begin;
    else if (va == 0x819310) op = Step;
    else if (va == 0x7edd00) op = Destroy;
    else return 0;
    ++words[Captures];
    if (depth) { ++words[ReentrantRefusals]; Refuse(NeedsOwner); return 0; }
    Frame& f = frames[depth]; f = {}; f.entries = entries;
    if (args && (op == Construct || op == Destroy)) {
        f.args[0] = args[0]; if (op == Construct) f.args[1] = args[1];
    }
    preparing = true;
    Reason reason = Capture(receiver, op, Entry, f.args, entries, f.input);
    preparing = false;
    if (reason != Ready) { Refuse(reason); return 0; }
    f.token = Token(); Predict(f); ++depth;
    ++words[Admitted]; ++words[Constructors + static_cast<U>(op)];
    words[LastNode] = receiver; words[LastOperation] = op;
    return f.token;
}
void Observe(U va, U receiver, const U* args) {
    if (!depth || preparing || !args) return;
    Frame& f = frames[depth - 1];
    if (f.busy || f.refused) return;
    Event actual{};
    if (va == 0x662e70) { actual.kind = Order; memcpy(actual.argument, args, 12); }
    else if (va == 0x662e50) { actual.kind = Setter; actual.argument[0] = args[0]; }
    else if (va == 0x659520) {
        actual.kind = Request;
        memcpy(actual.descriptor, reinterpret_cast<const void*>(args[0]), 20);
        memcpy(actual.options, reinterpret_cast<const void*>(args[1]), 0x1c);
    } else return;
    if (receiver != (actual.kind == Request ? f.input.ownerAddress : f.input.nodeAddress)) return;
    actual.receiver = receiver;
    ++words[ObservedOrders + static_cast<U>(actual.kind)]; ++eventWords[actual.kind * 3 + 1];
    CheckNode(f);
    if (!f.predicted.hasEvent || f.observed || !EqualEvent(f.predicted.event, actual)) {
        f.eventMismatch = true; ++eventWords[actual.kind * 3 + 2];
    }
    f.observed = true;
}
void After(U token) {
    if (!depth || !token) return;
    Frame& f = frames[depth - 1];
    if (token & 0x80000000u) {
        if (!f.busy || token != f.effectToken) { ++words[ReentrantRefusals]; Abandon(); return; }
        if (f.effectVA == 0x662e50) CheckOwner(f);
        Phase next = f.effectVA == 0x662e70 ? OrderReturned : f.effectVA == 0x662e50 ? SetterReturned : RequestReturned;
        const U node = f.input.nodeAddress; const Operation op = f.input.operation;
        preparing = true;
        Reason reason = Capture(node, op, next, f.args, f.entries, f.input);
        preparing = false; f.busy = false; ++words[PhaseCheckpoints];
        if (reason != Ready) { f.refused = true; Refuse(reason); return; }
        Predict(f); return;
    }
    if (f.token != token || f.busy) { ++words[ReentrantRefusals]; Abandon(); return; }
    if (!f.refused) {
        CheckNode(f); CheckOwner(f);
        if (f.predicted.hasEvent) {
            f.eventMismatch = true;
            if (!f.observed) ++eventWords[f.predicted.event.kind * 3 + 2];
        }
        ++words[Comparisons];
        if (f.nodeMismatch) ++words[NodeMismatches];
        if (f.ownerMismatch) ++words[OwnerMismatches];
        if (f.eventMismatch) ++words[EventMismatches];
        ++words[f.nodeMismatch || f.ownerMismatch || f.eventMismatch ? Mismatches : Matches];
    }
    --depth;
}
} // namespace ntw2_move_node
