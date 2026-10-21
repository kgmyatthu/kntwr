// Included by native_move_node_oracle.cpp before RunOracle. The source-pinned
// node bodies perform every branch/store/FP operation. Only world transactions
// are replaced, at their original direct-call seams, in this alternate bank.
#include "native_action_node.h"
namespace action_oracle {
namespace action = kntwr_action_node;
static kntwr_clone_set bank{};
static U eventCount, orderCount, kinds[8], orders[8];
static bool changeOrder, changeReset, changeMove, corrupt;
static U currentNode;
struct ActionFixture : Fixture {
    std::array<B, 0x38> actionDescriptor{};
    std::array<B, 0x700> related{};
    std::array<B, 0x80> object{}, bridge{}, second{}, recordValue{};
    std::array<U, 16> objectTable{}, bridgeTable{}, secondTable{}, recordTable{};
    ActionFixture(U index = 0) {
        Put(actionDescriptor.data(), 0, 2.0f); Put(actionDescriptor.data(), 4, 0.0f);
        Put(actionDescriptor.data(), 8, 3.0f);
        Put(actionDescriptor.data(), 0x14, U(3)); Put(actionDescriptor.data(), 0x18, U(4));
        Put(actionDescriptor.data(), 0x1c, U(1)); Put(actionDescriptor.data(), 0x20, 0.5f);
        Put(actionDescriptor.data(), 0x24, uint16_t(0x4321));
        memset(Node(), 0xa5, 0x58);
        U ctor = index == 0 ? 0x7e1f90 : index == 1 ? 0x7e1e10 : 0x7e1d90;
        reinterpret_cast<U (__thiscall*)(U, U, const B*)>(At(ctor))(
            NodeAddress(), Addr(owner.data()) + 0x228, actionDescriptor.data());
        objectTable.fill(Addr(At(0x461180))); bridgeTable = secondTable = recordTable = objectTable;
        Put(object.data(), 0, Addr(objectTable.data())); Put(bridge.data(), 0, Addr(bridgeTable.data()));
        Put(second.data(), 0, Addr(secondTable.data()));
        if (index) { Put(owner.data(), 0x1ec, Addr(related.data())); Group(); }
        Put(group.data(), 0x398, Addr(recordTable.data()));
    }
    void Related(U value, bool present = true) {
        objectTable[0] = Addr(At(0x4b4a50)); Put(object.data(), 4, value);
        Put(related.data(), 0x628, present ? Addr(object.data()) : U(0));
    }
    void Timed(bool fallback = false) {
        Put(Node(), 0x4c, U(19)); Put(Node(), 0x50, 0.0f);
        Put(model.data(), 0x58, U(1000)); Put(At(0x150fc2c), 0, 0.0f);
        Put(owner.data(), 0x18, U(0));
        Put(recordValue.data(), 0x60, Addr(rows.data())); Put(rows.data(), 0x14, U(19));
        objectTable[0x20 / 4] = Addr(At(0x4b4a50));
        Put(object.data(), 4, Addr(recordValue.data()));
        if (!fallback) Put(owner.data(), 0x10, Addr(object.data()));
        else {
            Put(owner.data(), 0x18, Addr(second.data())); Put(second.data(), 0x1c, Addr(bridge.data()));
            bridgeTable[0x1c / 4] = Addr(At(0x4b4a50)); Put(bridge.data(), 4, Addr(object.data()));
        }
    }
    void Near(bool heading) {
        Projection(); Put(Node(), 0x42, B(heading)); Put(Node(), 0x1c, 0.0f); Put(Node(), 0x24, 0.0f);
        Put(Node(), 0x28, U(0)); Put(Node(), 0x2c, U(0));
    }
};
static U Enter(U va, U receiver, const U* args, U kind) {
    Require(eventCount < 8, "bounded action transaction count"); kinds[eventCount++] = kind;
    action::Observe(va, receiver, args);
    U token = action::Before(va, receiver, args, bank.entries);
    Require(token != 0, "action successor checkpoint armed"); return token;
}
static void __fastcall Order(U node, U, U order, U first, U second) {
    U args[3] = {order, first, second}; orders[orderCount++] = order;
    U token = Enter(0x662e70, node, args, 0);
    if (changeOrder && orderCount == 1) {
        Put(reinterpret_cast<void*>(Get<U>(reinterpret_cast<void*>(node), 4)), 0x390, U(6));
        Put(reinterpret_cast<void*>(node), 0x34, U(0x24681357));
        Put(reinterpret_cast<void*>(node), 0x38, U(0x34567890));
    }
    action::After(token);
}
static void __fastcall Setter(U node, U, U value) {
    U token = Enter(0x662e50, node, &value, 1);
    reinterpret_cast<void (__thiscall*)(U, U)>(At(0x662e50))(node, value); action::After(token);
}
static void __fastcall Request(U owner, U, const U* descriptor, const B* option) {
    B changed[28]; memcpy(changed, option, 28); if (corrupt) changed[0x13] ^= 1;
    U args[2] = {Addr(descriptor), Addr(changed)};
    U token = Enter(0x659520, owner, args, 2); action::After(token);
}
static void __fastcall ResetOrder(U owner, U, U value) {
    U token = Enter(0x6669b0, owner, &value, 3);
    if (changeReset) { Put(reinterpret_cast<void*>(owner), 0x64, uint16_t(0xabcd));
        Put(reinterpret_cast<void*>(currentNode), 0x1c, 8.5f); }
    action::After(token);
}
static void __fastcall Move(U node, U, const float* planar, U heading, U surface, U mode) {
    U args[4] = {Addr(planar), heading, surface, mode}; U token = Enter(0x659d50, node, args, 4);
    if (changeMove) Put(reinterpret_cast<void*>(node), 0x34, U(0x12348765));
    action::After(token);
}
static void __fastcall Pose(U owner, U, const B* value, U option) {
    U args[2] = {Addr(value), option}; U token = Enter(0x66b9d0, owner, args, 5); action::After(token);
}
static void __stdcall Target(U* stack) {
    switch (stack[0]) {
    case 0x8160cf: case 0x8161c4: case 0x81854b: case 0x818586: case 0x8185ad:
    case 0x8185ee: case 0x8187ff: case 0x818353: case 0x8183b4: case 0x8183c7:
    case 0x81601f: stack[1] = Fn(&Order); break;
    case 0x8160d9: stack[1] = Fn(&Setter); break;
    case 0x8162c3: stack[1] = Fn(&Request); break;
    case 0x818714: stack[1] = Fn(&ResetOrder); break;
    case 0x8187de: stack[1] = Fn(&Move); break;
    case 0x8161aa: stack[1] = Fn(&Pose); break;
    }
}
__declspec(naked) static void Gate() {
    __asm pushfd
    __asm pushad
    __asm lea eax, [esp+36]
    __asm push eax
    __asm call Target
    __asm popad
    __asm popfd
    __asm lea esp, [esp+4]
    __asm ret
}
static void Invoke(ActionFixture& f, U index, action::Operation op, U count, bool original = false) {
    action::Reset(); action::Configure(true); eventCount = orderCount = 0; currentNode = f.NodeAddress(); ResetFp();
    U va = index == 0 ? (op == action::Begin ? 0x816080 : 0x818500) :
        index == 1 ? (op == action::Begin ? 0x444b60 : 0x818330) : (op == action::Begin ? 0x815ff0 : 0x444b60);
    U clone = index == 0 ? (op == action::Begin ? KNTWR_CLONE_BRAIN_ACTION_BEGIN : KNTWR_CLONE_BRAIN_ACTION_STEP) :
        index == 1 ? (op == action::Begin ? KNTWR_CLONE_BRAIN_ACTION_EMPTY : KNTWR_CLONE_BRAIN_ACTION_RELATED_STEP) :
        (op == action::Begin ? KNTWR_CLONE_BRAIN_ACTION_RELATED_BEGIN : KNTWR_CLONE_BRAIN_ACTION_EMPTY);
    U token = action::BeforeSite(va, op == action::Begin ? 0x66c17d : 0x66c18e, f.NodeAddress(), nullptr, bank.entries);
    Require(token != 0, "action concrete capture admitted");
    reinterpret_cast<void (__thiscall*)(U)>(original ? Addr(At(va)) : bank.entries[clone])(f.NodeAddress());
    action::After(token);
    U w[action::kWords]; action::Snapshot(index, w);
    Require(w[action::Comparisons] == 1 && w[action::Matches] == U(!corrupt) && w[action::Mismatches] == U(corrupt),
        "action complete node/event differential comparison");
    Require(!w[action::Refused] && w[action::PhaseCheckpoints] == count && eventCount == count,
        "action exact event checkpoints without refusal");
    Require(w[action::WorkersBlocked] == 1 && !w[action::FakeTableInstalled], "action owner-only no fake vtable");
    for (U other = 0; other < action::kClassCount; ++other) if (other != index) {
        action::Snapshot(other, w); Require(!w[action::Captures], "per-class action identity is exclusive");
    }
    ++cases;
}
static void Branches() {
    for (U index : {1u, 2u}) {
        label = "mapped original empty action slot"; ActionFixture f(index);
        Invoke(f, index, index == 1 ? action::Begin : action::Step, 0, true);
        Require(action::Before(0x444b60, f.NodeAddress(), nullptr, bank.entries) == 0, "unqualified empty delete target ignored");
        for (U site : {0x658f70u, 0x64df02u, 0x670f10u, 0x66c17du, 0x658f81u, 0x64df13u, 0x670f21u, 0x66c18eu}) {
            bool beginSite = site == 0x658f70 || site == 0x64df02 || site == 0x670f10 || site == 0x66c17d;
            U token = action::BeforeSite(0x444b60, site, f.NodeAddress(), nullptr, bank.entries);
            Require(bool(token) == (beginSite == (index == 1)), "empty target operation and table qualification");
            if (token) action::After(token);
        }
    }
    for (U state : {0u, 2u, 3u}) for (U current : {0u, 1u, 2u}) for (U value : {0u, 1u}) {
        label = "related-step complete state record and pointer predicate branches"; ActionFixture f(1);
        Put(f.related.data(), 0x220, state); f.Related(value);
        Put(f.group.data(), 0x930, U(current != 0)); Put(f.group.data(), 0x3e4, B(current));
        f.recordTable[0x2c / 4] = Addr(At(0x55c360));
        Invoke(f, 1, action::Step, 1);
        U expected = state == 2 ? 0x19 : state == 3 || current == 1 || value ? 0x18 : 0x17;
        Require(orders[0] == expected, "related-step exact native selected order");
    }
    for (bool present : {false, true}) for (U value : {0u, 1u, 0x12345678u}) {
        label = "related-begin null and full EAX getter branches"; ActionFixture f(2); f.Related(value, present);
        Invoke(f, 2, action::Begin, 1); Require(orders[0] == (present && value ? 0x18u : 0x17u), "related-begin exact order");
    }
    for (U index : {1u, 2u}) for (U table : {0x1334218u, 0x1334250u}) {
        label = "related callback native concrete table getters"; ActionFixture f(index); f.Related(0);
        Put(f.object.data(), 0, Addr(At(table)));
        Invoke(f, index, index == 1 ? action::Step : action::Begin, 1);
        Require(orders[0] == (table == 0x1334250 ? 0x18u : 0x17u),
            "native table 1334250 returns this, table1334218 returns full EAX zero");
    }
    for (U state : {0u, 6u, 7u}) for (B flag : {B(0), B(1), B(2)}) for (B done : {B(0), B(1), B(2)}) {
        label = "descriptor-step state selector and exact completion bytes"; ActionFixture f;
        Put(f.owner.data(), 0x390, state); Put(f.Node(), 0x54, flag);
        Put(f.owner.data(), 0x117, done); Put(f.owner.data(), 0x13c, done);
        U count = flag == 1 ? U(state == 6 || state == 7) : U(done == 1);
        Invoke(f, 0, action::Step, count, count == 0);
    }
    for (bool special : {false, true}) for (bool adjust : {false, true}) {
        label = "descriptor-step initial order and fresh post-order owner state"; ActionFixture f;
        if (special) f.Group(); Put(f.owner.data(), 0x1d8, U(5)); Put(f.Node(), 0x45, B(adjust));
        Put(f.Node(), 0x30, U(0)); Put(f.group.data(), 0x194, int(4));
        changeOrder = true; Invoke(f, 0, action::Step, 2); changeOrder = false;
        Require(orders[1] == 0x24681357, "second order reads first effect successor node");
    }
}
static void Begins() {
    for (B heading : {B(0), B(1), B(2)}) for (B adjust : {B(0), B(1), B(2)}) {
        label = "descriptor-begin request options and zero-group adjustment"; ActionFixture f;
        Put(f.Node(), 0x42, heading); Put(f.Node(), 0x43, B(0xfe)); Put(f.Node(), 0x44, B(2));
        Put(f.Node(), 0x45, adjust); Put(f.Node(), 0x48, U(0x89abcdef));
        Invoke(f, 0, action::Begin, 3);
    }
    for (bool heading : {false, true}) {
        label = "descriptor-begin near-distance original early branches"; ActionFixture f; f.Near(heading);
        Invoke(f, 0, action::Begin, 3);
        Require(kinds[2] == U(heading ? 5 : 0), "native near-distance selects pose or final order");
        Require(heading ? Get<B>(f.Node(), 0x54) == 0 : Get<B>(f.Node(), 8) == 1, "near successor node store");
    }
    { label = "descriptor near pose includes native affine and heading transforms"; ActionFixture f; f.Near(true);
      std::array<B, 0x200> transform{};
      Put(transform.data(), 0x9c, 1.0f); Put(transform.data(), 0xac, 1.0f); Put(transform.data(), 0xbc, 1.0f);
      Put(transform.data(), 0xc0, 1.0f); Put(transform.data(), 0xd0, 1.0f); Put(transform.data(), 0xe0, 1.0f);
      Put(transform.data(), 0x80, 0.25f); Put(transform.data(), 0x88, -0.5f);
      Put(transform.data(), 0x1e6, uint16_t(0x1234)); Put(f.Node(), 0x2c, Addr(transform.data()));
      Invoke(f, 0, action::Begin, 3); Require(kinds[2] == 5, "transformed near pose takes original pose branch"); }
    for (B inhibited : {B(0), B(1), B(2)}) {
        label = "descriptor-begin near eligibility and adjusted request"; ActionFixture f; f.Near(false);
        Put(f.Node(), 0x1c, 20.0f); Put(f.Node(), 0x28, Addr(f.surface.data()));
        Put(f.owner.data(), 0x118, B(1)); Put(f.owner.data(), 0x110, inhibited); Put(f.owner.data(), 0x117, B(1));
        Invoke(f, 0, action::Begin, 3); Require(kinds[2] == 2, "far descriptor takes request");
    }
    { label = "descriptor event corruption is detected"; ActionFixture f; Put(f.Node(), 0x42, B(1));
      corrupt = true; Invoke(f, 0, action::Begin, 3); corrupt = false; }
}
static void Timers() {
    for (bool fallback : {false, true}) for (B heading : {B(0), B(1), B(2)}) {
        label = "descriptor timed action both owner chains and successor mutations"; ActionFixture f; f.Timed(fallback);
        Put(f.Node(), 0x42, heading); changeReset = changeMove = true;
        Invoke(f, 0, action::Step, 3); changeReset = changeMove = false;
        Require(kinds[0] == 3 && kinds[1] == 4 && kinds[2] == 0 && orders[0] == 0x12348765,
            "timed reset move order transaction sequence and successor capture");
    }
    for (U tick : {0u, 1u, 0x7fffffffu, 0x80000000u, 0xffffffffu}) {
        label = "descriptor native unsigned tick conversion"; ActionFixture f; f.Timed();
        Put(f.model.data(), 0x58, tick); Put(At(0x150fc2c), 0, 0.0f); Invoke(f, 0, action::Step, 3);
    }
    for (U branch = 0; branch < 7; ++branch) {
        label = "descriptor timed no-action short circuits"; ActionFixture f; f.Timed();
        if (branch == 0) Put(f.Node(), 0x50, 1.0e30f);
        if (branch == 1) Put(f.Node(), 0x50, U(0x7fc00000));
        if (branch == 2) { Put(f.Node(), 0x28, Addr(f.object.data())); f.objectTable[0x34 / 4] = Addr(At(0x447880)); }
        if (branch == 3) Put(f.object.data(), 4, U(0));
        if (branch == 4) Put(f.rows.data(), 0x14, U(20));
        if (branch == 5) f.objectTable[0x34 / 4] = Addr(At(0x447880));
        if (branch == 6) Put(f.owner.data(), 0x10, U(0));
        Invoke(f, 0, action::Step, 0, true);
    }
    { label = "unknown virtual mutation cannot claim whole-node comparison"; ActionFixture f(2);
      f.Related(1); f.objectTable[0] = Addr(At(0x816060)); action::Reset();
      Require(action::Before(0x815ff0, f.NodeAddress(), nullptr, bank.entries) == 0, "uncertified callback refused before execution");
      U w[action::kWords]; action::Snapshot(2, w);
      Require(w[action::PredicateNeedsOwner] == 1 && !w[action::Comparisons], "explicit callback refusal counters"); ++cases; }
    { label = "late cold adjustment never claims complete comparison"; ActionFixture f; f.Near(false);
      Put(f.adjustmentRow.data(), 0x28, B(0)); Put(f.manager.data(), 0x6bc, U(0));
      action::Reset(); eventCount = orderCount = 0;
      U token = action::Before(0x816080, f.NodeAddress(), nullptr, bank.entries); Require(token != 0, "cold begin entry admitted");
      Order(f.NodeAddress(), 0, Get<U>(f.Node(), 0x30), 0, 0); Setter(f.NodeAddress(), 0, Get<U>(f.Node(), 0x38)); action::After(token);
      U w[action::kWords]; action::Snapshot(0, w);
      Require(w[action::Refused] == 1 && w[action::PhaseCheckpoints] == 2 && !w[action::Comparisons], "late refusal retains only completed checkpoints"); ++cases; }
}
static void __fastcall ProductionRequest(U, U, const U*, const B*) { ++eventCount; }
static void Routes() {
    for (U index = 0; index < action::kClassCount; ++index) for (bool started : {false, true}) {
        label = "production action concrete virtual routing including shared empty slots"; ActionFixture f(index);
        Put(f.Node(), 0x10, B(started)); if (index == 1) Put(f.related.data(), 0x220, U(2));
        f.ownerVtable[0xc / 4] = Addr(At(0x66ce00));
        std::array<U, KNTWR_CLONE_COUNT> entries;
        std::copy(std::begin(production.entries), std::end(production.entries), entries.begin());
        entries[KNTWR_CLONE_BRAIN_W] = Fn(&HolderRoute);
        entries[KNTWR_CLONE_BRAIN_W_REQUEST] = Fn(&ProductionRequest);
        eventCount = 0; brain::Reset(); brain::Configure(false, false, true, false);
        brain::RunOccurrence(Addr(f.owner.data()), entries.data());
        U w[action::kWords]; action::Snapshot(index, w);
        Require(w[action::Comparisons] == U(started ? 1 : 2) && w[action::Matches] == w[action::Comparisons]
            && !w[action::Refused], "production action begin/step all compared");
        Require(w[action::Begins] == U(!started) && w[action::Steps] == 1, "production empty and concrete operation attribution");
        Require(Get<U>(f.Node(), 0) == Addr(At(index == 0 ? 0x1347270 : index == 1 ? 0x1348d2c : 0x1348cc4)),
            "production dynamic table preserved");
        Require(Get<B>(f.Node(), 0x10) == 1 && Get<U>(f.Node(), 0xc) == 1, "production holder stores stay outside node shadow");
        brain::Configure(false, false, false, false); ++cases;
    }
}
} // namespace action_oracle
void RunActionNodeCases() {
    using namespace action_oracle;
    action::Bind(Addr(image)); U saved = bindings[KNTWR_BIND_B2_SERVICE_GATE], detail = 0;
    bindings[KNTWR_BIND_B2_SERVICE_GATE] = Fn(&Gate);
    Require(kntwr_build_clones(Addr(image), bindings, &bank, &detail) == 0, "build source-pinned action event-seam bank");
    bindings[KNTWR_BIND_B2_SERVICE_GATE] = saved;
    Branches(); Begins(); Timers(); Routes();
    action::Release(); VirtualFree(bank.allocation, 0, MEM_RELEASE); bank = {};
}
