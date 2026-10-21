#include "native_idle_node.h"
// Included before RunOracle. Native node arithmetic and RNG helpers execute in
// source-pinned bodies; only world transactions are explicit event boundaries.
namespace idle_oracle {
namespace idle = kntwr_idle_node;
static kntwr_clone_set bank{};
struct Seen { U va, receiver, args[4]; };
static Seen seen[4];
static U seenCount;
static bool mutateFirst, corruptOrder;
static void RecordEffect(U va, U receiver, const U* args, U count) {
    Require(seenCount < 4, "idle event sequence bounded");
    Seen& e = seen[seenCount++]; e = {}; e.va = va; e.receiver = receiver;
    memcpy(e.args, args, count * sizeof(U));
}
static void __fastcall OrderBoundary(U node, U, U order, U mode, U flag) {
    U args[3] = {order, mode, flag}; RecordEffect(0x662e70, node, args, 3);
    U observedArgs[3] = {order ^ U(corruptOrder), mode, flag};
    idle::Observe(0x662e70, node, observedArgs);
    U token = idle::Before(0x662e70, node, args, bank.entries);
    Require(token != 0, "idle order successor armed");
    if (mutateFirst && seenCount == 1) {
        U owner = Get<U>(reinterpret_cast<void*>(node), 4);
        Put(reinterpret_cast<void*>(owner), 0x444, U(0));
        Put(reinterpret_cast<void*>(owner), 0x1d8, U(3));
        Put(reinterpret_cast<void*>(node), 0x20, U(0x12));
        Put(reinterpret_cast<void*>(node), 0x24, B(0xfe));
    }
    idle::After(token);
}
static void __fastcall StopBoundary(U owner, U, U flag) {
    RecordEffect(0x6669b0, owner, &flag, 1);
    idle::Observe(0x6669b0, owner, &flag);
    U token = idle::Before(0x6669b0, owner, &flag, bank.entries);
    Require(token != 0, "idle stop successor armed");
    Put(reinterpret_cast<void*>(owner), 0x390, U(0x10203040));
    idle::After(token);
}
static void __fastcall ActionBoundary(U owner, U, U action, U reset, U force, U scale) {
    U args[4] = {action, reset, force, scale}; RecordEffect(0x6666e0, owner, args, 4);
    idle::Observe(0x6666e0, owner, args);
    U token = idle::Before(0x6666e0, owner, args, bank.entries);
    Require(token != 0, "idle action successor armed");
    Put(reinterpret_cast<void*>(owner), 0x444, U(0x12345678));
    idle::After(token);
}
static void __stdcall SelectBoundary(U* stack) {
    switch (stack[0]) {
    case 0x665e65: case 0x665e4d: stack[1] = Fn(&StopBoundary); break;
    case 0x66e03f: stack[1] = Fn(&ActionBoundary); break;
    case 0x66dd52: case 0x66ddb3: case 0x66ddce: case 0x66de48:
    case 0x66debc: case 0x66dede: case 0x66df4f: case 0x66df89:
    case 0x66dfc3: case 0x66dfd7: case 0x66dfec:
        stack[1] = Fn(&OrderBoundary); break;
    }
}
__declspec(naked) static void Gate() {
    __asm pushfd
    __asm pushad
    __asm lea eax, [esp+36]
    __asm push eax
    __asm call SelectBoundary
    __asm popad
    __asm popfd
    __asm lea esp, [esp+4]
    __asm ret
}
struct IdleFixture : Fixture {
    U cls, descriptorWords[2] = {0x13572468, 0x49};
    std::array<B, 0x1600> capabilityRows{};
    std::array<U, 4> weightedRows{};
    std::array<B, 0x700> related{};
    explicit IdleFixture(U classIndex = 0) : cls(classIndex) {
        ownerVtable[0xe8 / 4] = ownerVtable[0xec / 4] = ownerVtable[0xf0 / 4] = Addr(At(0x462cb0));
        Put(owner.data(), 0x444, U(1)); Put(owner.data(), 0x45c, Addr(root.data()));
        Put(database.data(), 0x2c, Addr(capabilityRows.data()));
        Put(related.data(), 0, Addr(ownerVtable.data()));
        memset(Node(), 0xa5, 0x28);
        reinterpret_cast<U (__thiscall*)(U, U, U)>(At(cls ? 0x61d8f0 : 0x61d910))(
            NodeAddress(), Addr(owner.data()) + 0x228, Addr(descriptorWords));
    }
    void TailReady(U order = 0x49, B latch = 0) {
        Put(owner.data(), 0x444, U(0)); Put(Node(), 0x20, order); Put(Node(), 0x24, latch);
    }
    void Seed(U high) {
        // Multiplicative inverse of 343FD modulo 2^32: next word is high<<16.
        Put(model.data(), 0x50, U(((high << 16) - 0x269ec3u) * 0xb9b33155u));
    }
    void Capability(U order) { Put(capabilityRows.data(), (0xd0 + (order - 1) * 7) * 24 + 0x14, U(1)); }
    void Distribution(bool nonempty, bool second = false) {
        Put(owner.data(), 0x468, U(nonempty ? 2 : 0));
        Put(owner.data(), 0x46c, Addr(weightedRows.data())); Put(owner.data(), 0x470, 1.0f);
        weightedRows[0] = 0x21; weightedRows[2] = 0x43;
        Put(weightedRows.data(), 4, second ? 0.0f : 0.5f); Put(weightedRows.data(), 12, 1.0f);
    }
};
static void Status(U cls, U comparisons, U phases, bool mismatch = false) {
    U w[idle::kWords]; idle::Snapshot(cls, w);
    Require(w[idle::Comparisons] == comparisons && w[idle::Matches] == (mismatch ? 0u : comparisons)
        && w[idle::Mismatches] == U(mismatch), "idle complete node/owner/event comparison");
    Require(w[idle::PhaseCheckpoints] == phases && !w[idle::Refused], "idle exact successor phase count");
    Require(w[idle::WorkersBlocked] == 1 && !w[idle::FakeTableInstalled], "idle stays owner-only with native table");
}
static void Invoke(IdleFixture& f, U va, U clone, U events, bool original = false) {
    idle::Reset(); idle::Configure(true); seenCount = 0; ResetFp();
    U args[2] = {Addr(f.owner.data()) + 0x228, Addr(f.descriptorWords)};
    bool ctor = va == 0x61d910 || va == 0x61d8f0, dtor = va == 0x624ef0 || va == 0x5ac9d0;
    if (dtor) args[0] = 5;
    U token = idle::Before(va, f.NodeAddress(), args, bank.entries);
    Require(token != 0, "idle capture admitted");
    U entry = original ? Addr(At(va)) : bank.entries[clone];
    if (ctor) reinterpret_cast<U (__thiscall*)(U, U, U)>(entry)(f.NodeAddress(), args[0], args[1]);
    else if (dtor) reinterpret_cast<U (__thiscall*)(U, U)>(entry)(f.NodeAddress(), args[0]);
    else reinterpret_cast<void (__thiscall*)(U)>(entry)(f.NodeAddress());
    idle::After(token); Require(seenCount == events, "idle native event count");
    Status(f.cls, 1, events, corruptOrder); ++cases;
}
static void Step(IdleFixture& f, U events, bool original = false) {
    Invoke(f, f.cls ? 0x66dcf0 : 0x66dd10,
        f.cls ? KNTWR_CLONE_BRAIN_W_WAIT_STEP : KNTWR_CLONE_BRAIN_W_IDLE_STEP, events, original);
}
static void RequireOrder(U index, U order, U mode = 0) {
    Require(seen[index].va == 0x662e70 && seen[index].args[0] == order && seen[index].args[1] == mode
        && seen[index].args[2] == 0, "idle exact native order arguments");
}
static void Lifecycle() {
    for (U cls : {0u, 1u}) {
        label = "idle mapped original constructor preserves padding"; IdleFixture f(cls);
        memset(f.Node(), 0x6d, 0x28);
        Invoke(f, cls ? 0x61d8f0 : 0x61d910, cls ? KNTWR_CLONE_BRAIN_W_WAIT_CTOR : KNTWR_CLONE_BRAIN_W_IDLE_CTOR, 0, true);
        Require(Get<B>(f.Node(), 9) == 0x6d && Get<B>(f.Node(), 0x11) == 0x6d, "idle constructor padding retained");
        label = "idle mapped original destructor empty delete arm";
        Invoke(f, cls ? 0x5ac9d0 : 0x624ef0, cls ? KNTWR_CLONE_BRAIN_W_WAIT_DTOR : KNTWR_CLONE_BRAIN_W_IDLE_DTOR, 0, true);
    }
}
static void WaitCases() {
    const U values[] = {0, 0x80000000, 0x3a83126f, 0x3c23d70a, 0xbc23d70a, 0x3f800000, 0x7f800000, 0x7fc01234, 0x7f801234};
    for (B flag : {B(0), B(1), B(2)}) for (U bits : values) {
        label = "wait mapped predicate exact byte/fabs/threshold/NaN"; IdleFixture f(1);
        Put(f.owner.data(), 0x117, flag); Put(f.owner.data(), 0x194, bits);
        Step(f, 0, true);
        bool done = flag == 1 && (bits & 0x7fffffffu) < 0x3c23d70a;
        Require(Get<B>(f.Node(), 8) == B(done), "wait expected completion branch");
        Put(f.Node(), 8, B(0));
        Invoke(f, 0x665e30, KNTWR_CLONE_BRAIN_W_WAIT_BEGIN, done ? 0 : 1, done);
        Require(Get<B>(f.Node(), 8) == B(done), "wait begin matches predicate");
    }
    label = "idle begin stop transaction once"; IdleFixture f;
    Invoke(f, 0x665e60, KNTWR_CLONE_BRAIN_W_IDLE_BEGIN, 1);
    Require(seen[0].va == 0x6669b0 && !seen[0].args[0], "idle begin zero stop argument");
}
static void EntryBranches() {
    for (bool linked : {false, true}) for (U mode : {0u, 1u, 2u, 0x101u}) {
        label = "idle EC order uses exact full EAX model result"; IdleFixture f;
        f.ownerVtable[0xec / 4] = Addr(At(0x447880));
        Put(f.owner.data(), 0x1ec, linked ? Addr(f.related.data()) : U(0)); Put(f.mode.data(), 0x14, mode);
        Step(f, 1); RequireOrder(0, linked ? 0x1d : 0, (mode & 0xffffff00u) | U(mode < 2));
    }
    for (bool activeField : {false, true}) {
        label = "idle concrete field getter owner67C"; IdleFixture f;
        f.ownerVtable[0xec / 4] = Addr(At(0x5db820)); Put(f.owner.data(), 0x67c, U(activeField));
        Step(f, activeField ? 1 : 0, !activeField);
    }
    { label = "idle E8 early return"; IdleFixture f; f.ownerVtable[0xe8 / 4] = Addr(At(0x447880)); Step(f, 0, true); }
    { label = "idle related F0 early return"; IdleFixture f;
      Put(f.owner.data(), 0x1ec, Addr(f.related.data())); f.ownerVtable[0xf0 / 4] = Addr(At(0x447880)); Step(f, 0, true); }
    { label = "idle group order5 continuation"; IdleFixture f; f.Group(); Step(f, 1); RequireOrder(0, 5); }
    { label = "idle related false suppresses second predicate"; IdleFixture f; f.Group();
      Put(f.owner.data(), 0x1ec, Addr(f.related.data())); Step(f, 0, true); }
    { label = "idle order reset recaptures successor before second order"; IdleFixture f;
      Put(f.owner.data(), 0x1d8, U(5)); mutateFirst = true; Step(f, 2); mutateFirst = false;
      RequireOrder(0, 0); RequireOrder(1, 0x12); Require(Get<B>(f.Node(), 0x24) == 1, "reset clears latch after first effect then sets it after second"); }
    for (U mode : {0u, 2u}) for (U condition = 0; condition < 4; ++condition) {
        label = "idle owner/model tail gates"; IdleFixture f; f.TailReady(0x12); Put(f.mode.data(), 0x14, mode);
        if (condition == 0) { Put(f.owner.data(), 0x118, B(1)); Put(f.owner.data(), 0x110, B(1)); }
        if (condition == 1) { Put(f.owner.data(), 0x118, B(1)); Put(f.owner.data(), 0x117, B(0)); }
        if (condition == 2) Put(f.owner.data(), 0x18c, B(1));
        if (condition == 3) { Put(f.owner.data(), 0x118, B(2)); Put(f.owner.data(), 0x117, B(1)); }
        U events = mode == 0 || condition == 3 ? 1 : 0; Step(f, events, !events);
    }
}
static void TailBranches() {
    for (U current : {0x14u, 0x16u, 0x15u, 6u, 3u}) {
        label = "idle owner378 priority and latch"; IdleFixture f; f.TailReady();
        Put(f.owner.data(), 0x378, B(2)); Put(f.owner.data(), 0x1d8, current);
        Step(f, current == 3 ? 1 : 0, current != 3);
        Require(Get<B>(f.Node(), 0x24) == 1, "idle state suppression still latches");
        if (current == 3) RequireOrder(0, 7);
    }
    { label = "idle signed group rank adjustment"; IdleFixture f; f.TailReady(); f.Group();
      Put(f.group.data(), 0xda4, B(1)); Put(f.group.data(), 0x194, U(3)); Put(f.capabilityRows.data(), 0x59c, U(1));
      Step(f, 1); RequireOrder(0, 4); }
    { label = "idle nonzero current order falls back zero"; IdleFixture f; f.TailReady(); Step(f, 1); RequireOrder(0, 0); }
    for (U high : {0u, 10000u, 32768u, 65535u}) for (U mask = 0; mask < 8; ++mask) {
        label = "idle exact RNG thresholds and capability row cascade"; IdleFixture f; f.TailReady();
        Put(f.owner.data(), 0x1d8, U(0)); f.Seed(high);
        for (U k = 1; k <= 3; ++k) if (mask & (1u << (k - 1))) f.Capability(k);
        Step(f, 1);
        U expected = 0;
        if (high < 16384 && (mask & 1)) expected = 1;
        else if (high < 32768 && (mask & 2)) expected = 2;
        else if (high < 49152 && (mask & 4)) expected = 3;
        RequireOrder(0, expected); Require(Get<U>(f.model.data(), 0x50) == high << 16, "native RNG advanced exactly once");
    }
    { label = "idle F0 true bypasses capability lookup after RNG"; IdleFixture f; f.TailReady();
      Put(f.owner.data(), 0x1d8, U(0)); f.ownerVtable[0xf0 / 4] = Addr(At(0x447880)); f.Seed(0); f.Capability(1);
      Step(f, 1); RequireOrder(0, 0); }
    for (bool weighted : {false, true}) for (bool second : {false, true}) {
        label = "idle latched action weighted distribution and seed sequence"; IdleFixture f; f.TailReady(3, 2); f.Seed(0); f.Distribution(weighted, second);
        Step(f, weighted ? 1 : 0, !weighted);
        U e[idle::kEventWords]; idle::EventSnapshot(0, e);
        Require(e[10] == 2 && e[11] == 1, "both native RNG draws modeled without replay");
        if (weighted) Require(seen[0].va == 0x6666e0 && seen[0].args[0] == (second ? 0x43u : 0x21u)
            && seen[0].args[1] == 1 && !seen[0].args[2] && seen[0].args[3] == 0x3f800000, "idle action exact arguments");
    }
    { label = "idle latched49 first random rejects before action gate"; IdleFixture f; f.TailReady(0x49, 1); f.Seed(65535);
      Step(f, 0, true); U e[idle::kEventWords]; idle::EventSnapshot(0, e); Require(e[10] == 2, "latched49 performs separate retry and action draws"); }
    { label = "idle latched49 retry enters order branch"; IdleFixture f; f.TailReady(0x49, 1); f.Seed(0);
      Step(f, 1); RequireOrder(0, 0); }
    { label = "idle special order followed by random action"; IdleFixture f; f.Group(); f.TailReady(); f.Seed(0); f.Distribution(true);
      Step(f, 2); RequireOrder(0, 5); Require(seen[1].va == 0x6666e0, "special BL retained across order transaction"); }
}
static void Refusals() {
    { label = "idle shared begin ignores unrelated concrete table"; IdleFixture f;
      Put(f.Node(), 0, Addr(At(0x1333ff4))); idle::Reset(); idle::Configure(true);
      Require(!idle::Before(0x665e60, f.NodeAddress(), nullptr, bank.entries), "shared target does not admit wrong concrete class");
      U w[idle::kWords]; idle::Snapshot(0, w); Require(!w[idle::Captures] && !w[idle::Refused], "unrelated class is silent"); ++cases; }
    { label = "idle unknown reached owner callback refuses without execution"; IdleFixture f;
      f.ownerVtable[0xec / 4] = Fn(&Unexpected); idle::Reset(); idle::Configure(true);
      Require(!idle::Before(0x66dd10, f.NodeAddress(), nullptr, bank.entries), "unresolved getter refuses");
      U w[idle::kWords]; idle::Snapshot(0, w); Require(w[idle::Refused] == 1 && !w[idle::Comparisons], "refusal is not full comparison"); ++cases; }
    { label = "idle successor refusal does not claim whole-node comparison"; IdleFixture f;
      Put(f.owner.data(), 0x1d8, U(5)); idle::Reset(); idle::Configure(true);
      U token = idle::Before(0x66dd10, f.NodeAddress(), nullptr, bank.entries);
      Require(token != 0, "idle first order independently admitted");
      U args[3] = {}; idle::Observe(0x662e70, f.NodeAddress(), args);
      U effect = idle::Before(0x662e70, f.NodeAddress(), args, bank.entries);
      Require(effect != 0, "idle unresolved successor checkpoint armed");
      f.TailReady(); Put(f.owner.data(), 0x1d8, U(0)); f.ownerVtable[0xf0 / 4] = Fn(&Unexpected);
      idle::After(effect); idle::After(token);
      U w[idle::kWords]; idle::Snapshot(0, w);
      Require(w[idle::Refused] == 1 && w[idle::PhaseCheckpoints] == 1 && !w[idle::Comparisons]
          && !w[idle::Matches], "idle partial event retained without false comparison"); ++cases; }
    { label = "idle detects native RNG owner-write corruption"; IdleFixture f; f.TailReady(3, 1); f.Seed(65535);
      idle::Reset(); idle::Configure(true);
      U token = idle::Before(0x66dd10, f.NodeAddress(), nullptr, bank.entries);
      Require(token != 0, "idle RNG capture admitted");
      reinterpret_cast<void (__thiscall*)(U)>(At(0x66dd10))(f.NodeAddress());
      Put(f.model.data(), 0x50, Get<U>(f.model.data(), 0x50) ^ 1u);
      idle::After(token); U w[idle::kWords]; idle::Snapshot(0, w);
      Require(w[idle::Comparisons] == 1 && w[idle::OwnerMismatches] == 1 && w[idle::Mismatches] == 1,
          "idle RNG seed is a checked native owner write"); ++cases; }
    { label = "idle detects event corruption"; IdleFixture f; f.ownerVtable[0xec / 4] = Addr(At(0x447880));
      corruptOrder = true; Step(f, 1); corruptOrder = false; }
}
// Real production holder virtual dispatch, native vtables, and generic
// Observe/Before/After are retained. Only outer occurrence and stop are sinks.
static void __fastcall ProductionStop(U owner, U, U flag) { RecordEffect(0x6669b0, owner, &flag, 1); }
static void __fastcall HolderRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U)>(production.entries[KNTWR_CLONE_BRAIN_W_HOLDER_STEP])(owner + 0x228);
}
static void ProductionRoutes() {
    for (U cls : {0u, 1u}) for (bool started : {false, true}) {
        label = "production holder routes concrete idle/wait virtuals"; IdleFixture f(cls);
        Put(f.Node(), 0x10, B(started)); f.ownerVtable[0xc / 4] = Addr(At(0x66ce00));
        std::array<U, KNTWR_CLONE_COUNT> entries;
        std::copy(std::begin(production.entries), std::end(production.entries), entries.begin());
        entries[KNTWR_CLONE_BRAIN_W] = Fn(&HolderRoute);
        entries[KNTWR_CLONE_BRAIN_W_STOP] = Fn(&ProductionStop);
        seenCount = 0; brain::Reset(); brain::Configure(false, false, true, false);
        brain::RunOccurrence(Addr(f.owner.data()), entries.data());
        Status(cls, started ? 1 : 2, started ? 0 : 1);
        Require(Get<B>(f.Node(), 0x10) == 1 && Get<U>(f.Node(), 0xc) == 1, "production holder owns latch and counter");
        Require(Get<U>(f.Node(), 0) == Addr(At(cls ? 0x1334028 : 0x133405c)), "production retains concrete native table");
        Require(seenCount == U(!started), "production stop transaction occurs exactly once");
        brain::Configure(false, false, false, false); ++cases;
    }
}
} // namespace idle_oracle
static void RunIdleNodeCases() {
    using namespace idle_oracle;
    idle::Bind(Addr(image));
    std::array<U, KNTWR_BIND_COUNT> localBindings;
    std::copy(std::begin(bindings), std::end(bindings), localBindings.begin());
    localBindings[KNTWR_BIND_B2_SERVICE_GATE] = Fn(&Gate);
    U detail = 0;
    Require(kntwr_build_clones(Addr(image), localBindings.data(), &bank, &detail) == 0, "build idle source-pinned event bank");
    idle_oracle::Lifecycle(); idle_oracle::WaitCases(); idle_oracle::EntryBranches();
    idle_oracle::TailBranches(); idle_oracle::Refusals(); idle_oracle::ProductionRoutes();
    idle::Release(); VirtualFree(bank.allocation, 0, MEM_RELEASE); bank = {};
}
