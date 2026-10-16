// Mapped-image, owner-only hot-node differential oracle. No game execution,
// instruction patching, or replacement live vtable. Order/request sinks below
// are explicit event seams, not implementations of the world transactions.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <array>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_clones.h"
#include "native_brain2.h"
#include "native_move_node.h"
#include "native_node_projection.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace hot = ntw2_move_node;
namespace brain = ntw2_brain2;
namespace projection = ntw2_node::projection;
static_assert(sizeof(void*) == 4, "Win32 native ABI");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, cases, checks, bindings[NTW2_BIND_COUNT];
static ntw2_clone_set production{}, boundary{};
static const char* label = "map";
static hot::Event observed[3];
static U observedCount;
static bool mutateOrder, corruptRequest;
static U ringBacking[10][64], lookupBacking[10][64];
static uint16_t idBacking[10][64];
static U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T f) { return static_cast<U>(reinterpret_cast<uintptr_t>(f)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
template<class T> static T Get(const void* p, U offset) { T value; memcpy(&value, static_cast<const B*>(p) + offset, sizeof(value)); return value; }
template<class T> static void Put(void* p, U offset, T value) { memcpy(static_cast<B*>(p) + offset, &value, sizeof(value)); }
[[noreturn]] static void Fail(const char* what) { std::fprintf(stderr, "FAIL [%s]: %s\n", label, what); std::exit(1); }
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail(what); }
static void Equal(const void* a, const void* b, size_t size, const char* what) { Require(!memcmp(a, b, size), what); }
static void Unexpected() { Fail("unrelated clone binding reached"); }
static void ResetFp() {
    unsigned short control = 0x27f;
    __asm fninit
    __asm fldcw word ptr [control]
    _mm_setcsr(0x1f80);
}
static hot::Event& Record(hot::EventKind kind, U receiver) {
    Require(observedCount < 3, "bounded native event sequence");
    auto& event = observed[observedCount++]; event = {}; event.kind = kind; event.receiver = receiver;
    return event;
}
static void __fastcall OrderBoundary(U node, U, U order, U first, U second) {
    auto& event = Record(hot::Order, node);
    event.argument[0] = order; event.argument[1] = first; event.argument[2] = second;
    hot::Observe(0x662e70, node, event.argument);
    U token = hot::Before(0x662e70, node, event.argument, boundary.entries);
    Require(token != 0, "order successor checkpoint armed");
    if (mutateOrder) {
        U owner = Get<U>(reinterpret_cast<void*>(node), 4);
        Put(reinterpret_cast<void*>(owner), 0x390, U(7));
        Put(reinterpret_cast<void*>(node), 0x38, U(0x98765432));
        Put(reinterpret_cast<void*>(node), 0x3c, U(0x41234567));
        Put(reinterpret_cast<void*>(node), 0x44, B(2));
    }
    hot::After(token);
}
static void __fastcall SetterBoundary(U node, U, U value) {
    auto& event = Record(hot::Setter, node); event.argument[0] = value;
    hot::Observe(0x662e50, node, &value);
    U token = hot::Before(0x662e50, node, &value, boundary.entries);
    Require(token != 0, "setter successor checkpoint armed");
    reinterpret_cast<void (__thiscall*)(U, U)>(At(0x662e50))(node, value);
    hot::After(token);
}
static void __fastcall RequestBoundary(U owner, U, const U* descriptor, const B* options) {
    auto& event = Record(hot::Request, owner);
    memcpy(event.descriptor, descriptor, 20); memcpy(event.options, options, 0x1c);
    U args[2] = {Addr(descriptor), Addr(options)};
    if (corruptRequest) {
        event.options[0xd] ^= 1; args[1] = Addr(event.options);
    }
    hot::Observe(0x659520, owner, args);
    U token = hot::Before(0x659520, owner, args, boundary.entries);
    Require(token != 0, "request successor checkpoint armed");
    hot::After(token);
}
static void __stdcall BoundaryTarget(U* stack) {
    switch (stack[0]) {
    case 0x816951: case 0x819358: stack[1] = Fn(&OrderBoundary); break;
    case 0x81695b: stack[1] = Fn(&SetterBoundary); break;
    case 0x816a41: stack[1] = Fn(&RequestBoundary); break;
    }
}
__declspec(naked) static void BoundaryGate() {
    __asm pushfd
    __asm pushad
    __asm lea eax, [esp+36]
    __asm push eax
    __asm call BoundaryTarget
    __asm popad
    __asm popfd
    __asm lea esp, [esp+4]
    __asm ret
}
static void SeedBanks() {
    for (U p = 0; p < 10; ++p) {
        B* visit = p == 9 ? At(0x15adb74) : reinterpret_cast<B*>(bindings[NTW2_BIND_NODE_PROJ_VISIT_0 + p]);
        B* lookup = p == 9 ? At(0x14d0a6c) : reinterpret_cast<B*>(bindings[NTW2_BIND_NODE_PROJ_LOOKUP_0 + p]);
        memset(visit, 0, 0x2030); memset(lookup, 0, 20);
        Put(visit, 0, U(64)); Put(visit, 4, Addr(ringBacking[p]));
        Put(visit, 0x2020, U(64)); Put(visit, 0x2028, Addr(idBacking[p]));
        Put(visit, 0x14, U(0x80000000)); Put(visit, 0x202c, U(0x80000000));
        Put(lookup, 4, U(64)); Put(lookup, 0xc, Addr(lookupBacking[p])); Put(lookup, 0x10, U(0x80000000));
    }
}
static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open approved image read-only");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long size = std::ftell(f); std::rewind(f);
    Require(size > 0 && size < 256 * 1024 * 1024, "bounded image size");
    std::vector<B> bytes(static_cast<size_t>(size));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE algorithm = nullptr; B hash[32];
    Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(algorithm, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), hash, 32) == 0, "SHA image");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    Require(!std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"), "pinned Steam image");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private mapped image"); delta = Addr(image) - 0x400000;
    memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
            std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "relocate private image");
    Put(At(0x1841bb8), 0, U(_tls_index)); tlsPad[0] = 0;
    Put(At(0x150fb24), 0, uint16_t(0x7654));
    Put(At(0x131a7b8), 0, 1.25f); Put(At(0x1325d24), 0, 2.0f);
    std::fill(std::begin(bindings), std::end(bindings), Fn(&Unexpected));
    Require(brain::Bind(Addr(image), bindings), "bind production generic gates");
    Require(projection::Initialize(Addr(image), bindings), "initialize private projection banks");
    hot::Bind(Addr(image)); SeedBanks();
    U detail = 0;
    Require(ntw2_build_clones(Addr(image), bindings, &production, &detail) == 0, "build production source-pinned clones");
    bindings[NTW2_BIND_B2_SERVICE_GATE] = Fn(&BoundaryGate);
    Require(ntw2_build_clones(Addr(image), bindings, &boundary, &detail) == 0, "build source-pinned event-seam clones");
}
struct Fixture {
    std::array<B, 0x700> owner{};
    std::array<B, 0xe00> group{};
    std::array<B, 0x28060> root{};
    std::array<B, 0xc0> model{};
    std::array<B, 0x20> mode{}, query{};
    std::array<B, 0x600> rows{};
    std::array<B, 0x800> manager{};
    std::array<B, 0x40> database{}, adjustmentRow{}, tag{};
    std::array<B, 0x80> loaded{};
    std::array<B, 0x60> coefficient{}, surface{};
    std::array<B, 0xa0> cell{};
    std::array<U, 0x200 / 4> ownerVtable{};
    std::array<U, 1> cellVtable{};
    std::array<U, 7> surfaceVtable{};
    std::array<U, 1> surfaceReaderVtable{};
    std::array<B, 0x20> polygonRing{};
    std::array<B, 0x60> lookupGrid{}, polygons{};
    std::array<B, 32 * 32 * 8> lookupCells{};
    U polygonPointer{};
    std::array<B, 0x2a> descriptor{};
    U databaseLink;
    Fixture() {
        ownerVtable.fill(Addr(At(0x461180))); cellVtable[0] = Addr(At(0x462cb0));
        Put(owner.data(), 0, Addr(ownerVtable.data())); Put(owner.data(), 0x18, U(1));
        Put(owner.data(), 0x228, Addr(owner.data())); Put(owner.data(), 0x2c8, Addr(root.data()));
        Put(owner.data(), 0x28, Addr(root.data())); Put(owner.data(), 0x1d8, U(3));
        Put(owner.data(), 0x34, U(0x443)); Put(owner.data(), 0x38, U(0x843));
        Put(owner.data(), 0x5e4, U(0x31415926));
        Put(group.data(), 0x14, Addr(root.data())); Put(root.data(), 8, Addr(model.data()));
        Put(model.data(), 0xb0, Addr(mode.data())); Put(model.data(), 0xb4, Addr(query.data()));
        Put(query.data(), 0, Addr(root.data()));
        Put(group.data(), 0xda8, 3.0f); Put(group.data(), 0xd9e, B(1));
        databaseLink = Addr(database.data()); Put(owner.data(), 0x218, Addr(&databaseLink));
        Put(database.data(), 0x2c, Addr(rows.data())); Put(rows.data(), 0x59c, U(1));
        Put(surface.data(), 0x40, Addr(cell.data())); Put(cell.data(), 0xc, Addr(cellVtable.data()));
        Put(descriptor.data(), 0, U(0x3f123456)); Put(descriptor.data(), 4, U(0x40abcdef));
        Put(descriptor.data(), 8, U(0x41123456)); Put(descriptor.data(), 0xc, Addr(surface.data()));
        Put(descriptor.data(), 0x14, uint16_t(0x4321)); Put(descriptor.data(), 0x18, U(3));
        Put(descriptor.data(), 0x1c, U(1)); Put(descriptor.data(), 0x20, U(0x40234567));
        Put(descriptor.data(), 0x24, U(0x40fedcba));
        memset(Node(), 0xa5, hot::kNodeBytes);
        reinterpret_cast<U (__thiscall*)(U, U, const B*)>(At(0x7e2c80))(NodeAddress(), Addr(owner.data()) + 0x228, descriptor.data());
    }
    B* Node() { return owner.data() + 0x22c; }
    U NodeAddress() { return Addr(Node()); }
    void Group() { Put(owner.data(), 0x1f0, Addr(group.data())); }
    void Projection(bool warm = false) {
        Group(); Put(group.data(), 0xda4, B(1)); Put(Node(), 0x45, B(1));
        Put(group.data(), 0xdb8, U(1)); Put(group.data(), 0xdbc, Addr(adjustmentRow.data()));
        Put(adjustmentRow.data(), 4, Addr(tag.data())); Put(tag.data(), 0, U(4));
        Put(adjustmentRow.data(), 0x28, B(warm ? 0 : 2));
        Put(root.data(), 0x2804c, Addr(coefficient.data())); Put(coefficient.data(), 0x10, Addr(manager.data()));
        Put(manager.data(), 0x6bc, Addr(loaded.data())); Put(loaded.data(), 0x5c, Addr(coefficient.data()));
        Put(coefficient.data(), 0xc, 1.75f);
        Put(owner.data(), 0x5d0, 2.5f); Put(owner.data(), 0x5cc, uint16_t(0x20));
        Put(owner.data(), 0x64, uint16_t(0x30));
        Put(At(0x176cff8 + 0x50 * 8), 0, 0.75f); Put(At(0x176cffc + 0x50 * 8), 0, -0.5f);
    }
    void AcceptedCell(bool lookup, bool nativePredicate) {
        cellVtable[0] = Addr(At(nativePredicate ? 0x7ff170 : 0x447880));
        surfaceVtable.fill(Addr(At(0x461180)));
        surfaceReaderVtable[0] = Addr(At(0x447880));
        Put(surface.data(), 0, Addr(surfaceVtable.data()));
        Put(surface.data(), 0x1c, Addr(surfaceReaderVtable.data()));
        Put(surface.data(), 0x34, -1.0f); Put(surface.data(), 0x3c, 2.0f);
        Put(cell.data(), 8, Addr(polygonRing.data())); Put(cell.data(), 0x10, B(1));
        Put(cell.data(), 0x24, Addr(surface.data())); Put(polygonRing.data(), 8, Addr(polygonRing.data()));
        if (!lookup) return;
        Put(surface.data(), 0x40, U(0)); Put(model.data(), 0xb8, Addr(lookupGrid.data()));
        Put(model.data(), 0x74, -64.0f); Put(model.data(), 0x78, -64.0f);
        Put(model.data(), 0x7c, 64.0f); Put(model.data(), 0x80, 64.0f);
        Put(lookupGrid.data(), 0, Addr(lookupCells.data())); Put(lookupGrid.data(), 8, U(5));
        Put(lookupGrid.data(), 0xc, U(32)); Put(lookupGrid.data(), 0x10, U(16));
        Put(lookupGrid.data(), 0x14, U(31)); Put(lookupGrid.data(), 0x24, 0.25f);
        Put(lookupGrid.data(), 0x38, Addr(root.data())); Put(lookupGrid.data(), 0x3c, Addr(polygons.data()));
        polygonPointer = Addr(cell.data());
        Put(polygons.data(), 0x4c, U(1)); Put(polygons.data(), 0x50, Addr(&polygonPointer));
    }
};
static void Status(U comparisons, U phases, bool mismatch = false) {
    U words[hot::kWords]; hot::Snapshot(words);
    Require(words[hot::Comparisons] == comparisons && words[hot::Matches] == (mismatch ? 0 : comparisons)
        && words[hot::Mismatches] == U(mismatch), "complete phase comparisons and match status");
    Require(words[hot::PhaseCheckpoints] == phases && !words[hot::Refused], "exact owner checkpoint count");
    Require(words[hot::WorkersBlocked] == 1 && words[hot::FakeTableInstalled] == 0,
        "owner-only shadow never installs a fake node");
}
static void Invoke(Fixture& f, hot::Operation op, U events, bool useOriginal = false) {
    hot::Reset(); hot::Configure(true); observedCount = 0; ResetFp();
    U args[2] = {Addr(f.owner.data()) + 0x228, Addr(f.descriptor.data())};
    U va = op == hot::Begin ? 0x816900 : op == hot::Step ? 0x819310 : op == hot::Construct ? 0x7e2c80 : 0x7edd00;
    if (op == hot::Destroy) args[0] = 5;
    U token = hot::Before(va, f.NodeAddress(), args, boundary.entries);
    Require(token != 0, "capture admitted");
    U clone = op == hot::Begin ? NTW2_CLONE_BRAIN_W_HOT_BEGIN : op == hot::Step ? NTW2_CLONE_BRAIN_W_HOT_STEP
        : op == hot::Construct ? NTW2_CLONE_BRAIN_W_HOT_CTOR : NTW2_CLONE_BRAIN_W_HOT_DTOR;
    U entry = useOriginal ? Addr(At(va)) : boundary.entries[clone];
    if (op == hot::Construct) reinterpret_cast<U (__thiscall*)(U, U, U)>(entry)(f.NodeAddress(), args[0], args[1]);
    else if (op == hot::Destroy) reinterpret_cast<U (__thiscall*)(U, U)>(entry)(f.NodeAddress(), args[0]);
    else reinterpret_cast<void (__thiscall*)(U)>(entry)(f.NodeAddress());
    hot::After(token);
    Require(observedCount == events, "native event count");
    Status(1, events, corruptRequest);
    ++cases;
}
static void StepCases() {
    for (U state : {0u, 6u, 7u}) for (B flag : {B(0), B(1), B(2), B(255)}) {
        label = "mapped original no-order state/byte branches";
        Fixture f; Put(f.owner.data(), 0x390, state); Put(f.Node(), 0x44, flag);
        Invoke(f, hot::Step, 0, true);
        Require(Get<B>(f.Node(), 8) == U(state == 7 || (state == 6 && flag == 1)), "byte-exact done store");
        Require(Get<U>(f.Node(), 0x18) == U(state == 7), "state-seven result store");
        Require(Get<B>(f.Node(), 9) == 0xa5 && Get<uint16_t>(f.Node(), 0x32) == 0xa5a5,
            "untouched constructor/step padding retained");
    }
    { label = "both pure predicates select special order"; Fixture f; f.Group(); Invoke(f, hot::Step, 1);
      Require(observed[0].argument[0] == 5 && observed[0].argument[1] == 1, "special order arguments"); }
    for (U value : {0u, 1u, 0xffffffffu}) {
        label = "mapped own-field virtual 5DB820 preserves predicate short circuit";
        Fixture f; f.Group(); f.ownerVtable[0xec / 4] = Addr(At(0x5db820));
        Put(f.owner.data(), 0x67c, value);
        Invoke(f, hot::Step, value == 0 ? 1u : 0u, value != 0);
        if (!value) Require(observed[0].argument[0] == 5, "own-field predicate false continues to special order");
    }
    for (U mode : {0u, 1u, 2u}) for (int rank : {-1, 2, 3, 4}) {
        label = "66AE10 mode and signed rank closure"; Fixture f; f.Group();
        Put(f.group.data(), 0xda4, B(1)); Put(f.owner.data(), 0x1d8, U(5));
        Put(f.Node(), 0x34, U(0)); Put(f.Node(), 0x38, mode); Put(f.Node(), 0x45, B(2));
        Put(f.group.data(), 0x194, rank); Invoke(f, hot::Step, 1);
        U chosen = ((mode == 0 && rank >= 3) || (mode == 1 && rank >= 4)) ? 4 : 0;
        Require(observed[0].argument[0] == chosen && observed[0].argument[1] == 0, "adjusted order arguments");
    }
    { label = "order successor controls final state"; Fixture f; Put(f.owner.data(), 0x1d8, U(5));
      mutateOrder = true; Invoke(f, hot::Step, 1); mutateOrder = false;
      Require(Get<U>(f.Node(), 0x18) == 1 && Get<B>(f.Node(), 8) == 1, "post-order state-seven read"); }
    for (B disabled : {B(0), B(1), B(2)}) for (B active : {B(0), B(1), B(2)}) {
        label = "55B0A0 exact disabled byte and nonzero active byte"; Fixture f; f.Group();
        Put(f.group.data(), 0xda4, disabled); Put(f.group.data(), 0xd9e, active);
        U count = disabled != 1 && active != 0 ? 1 : 0; Invoke(f, hot::Step, count, count == 0);
    }
    for (U mode : {0u, 1u, 2u}) for (U speed : {0x3f800000u, 0x40000000u, 0x40400000u, 0x7fc00001u}) {
        label = "55B0A0 manager modes, threshold equality and unordered"; Fixture f; f.Group();
        Put(f.mode.data(), 0x14, mode); Put(f.group.data(), 0xda8, speed);
        U count = mode < 2 || speed != 0x3f800000u ? 1 : 0;
        Invoke(f, hot::Step, count, count == 0);
    }
    { label = "63B3E0 short circuit avoids unsupported later virtual"; Fixture f; f.Group();
      f.ownerVtable[0xec / 4] = Addr(At(0x447880)); f.ownerVtable[0xf0 / 4] = Fn(&Unexpected);
      Invoke(f, hot::Step, 0, true); }
    { label = "63B3E0 related owner skips all virtuals"; Fixture f; f.Group();
      Put(f.owner.data(), 0x1ec, U(1)); f.ownerVtable.fill(Fn(&Unexpected)); Invoke(f, hot::Step, 0, true); }
}
static void BeginCases() {
    for (B flag : {B(0), B(1), B(2), B(255)}) for (B adjust : {B(0), B(2)}) {
        label = "begin order/setter/request and descriptor stack residue";
        Fixture f; Put(f.Node(), 0x44, flag); Put(f.Node(), 0x45, adjust); Invoke(f, hot::Begin, 3);
        Require(observed[0].kind == hot::Order && observed[1].kind == hot::Setter && observed[2].kind == hot::Request,
            "ordered begin events");
        Require(observed[0].argument[0] == 3 && B(observed[0].argument[1]) == 0 && !observed[0].argument[2], "begin order");
        Require(Get<U>(f.owner.data(), 0x220) == 1, "original setter executed once");
        Equal(observed[2].descriptor, f.Node() + 0x1c, 20, "request descriptor five exact words");
        Equal(observed[2].options + 1, f.Node() + 0x1d, 3, "options +1..3 descriptor residue");
        Require(observed[2].options[0xd] == f.Node()[0x29], "options +D descriptor residue");
        Require(observed[2].options[0] == U(flag == 1) && Get<uint16_t>(observed[2].options, 0xe) == (flag == 1 ? 0x4321 : 0x7654),
            "flag is exactly one, not truthiness");
    }
    { label = "begin special order predicate"; Fixture f; f.Group(); Invoke(f, hot::Begin, 3);
      Require(observed[0].argument[0] == 5 && B(observed[0].argument[1]) == 1, "special begin order"); }
    { label = "begin successor node fields are captured after native order"; Fixture f;
      mutateOrder = true; Invoke(f, hot::Begin, 3); mutateOrder = false;
      Require(observed[1].argument[0] == 0x98765432 && Get<U>(observed[2].options, 4) == 0x41234567,
          "setter and request use successor values, not stale entry snapshot"); }
    for (bool warm : {false, true}) {
        label = "66AD00 recovered adjustment with private projection fallback"; Fixture f; f.Projection(warm);
        Invoke(f, hot::Begin, 3);
        U events[hot::kEventWords]; hot::EventSnapshot(events);
        Require(events[12] == 1 && !events[9] && !events[11], "exactly one private projection preparation");
        Require(projection::Ready(), "private scratch quiescent after adjustment");
    }
    for (bool lookup : {false, true}) for (bool nativePredicate : {false, true}) {
        label = "66AD00 accepted cells and lookup use certified world callbacks";
        Fixture f; f.Projection(); f.AcceptedCell(lookup, nativePredicate);
        Invoke(f, hot::Begin, 3);
        U events[hot::kEventWords]; hot::EventSnapshot(events);
        Require(events[12] == 1 && !events[9], "accepted projection completes rather than blanket refusal");
    }
    { label = "event masks exclude only genuinely undefined stack bytes"; Fixture f; hot::Input input;
      U args[2] = {}; hot::Result result;
      Require(hot::Capture(f.NodeAddress(), hot::Begin, hot::SetterReturned, args, boundary.entries, input) == hot::Ready, "request model input");
      hot::Run(input, result); hot::Event actual = result.event;
      actual.options[0x19] ^= 0xff; actual.options[0x1a] ^= 0xff; actual.options[0x1b] ^= 0xff;
      Require(hot::EqualEvent(result.event, actual), "uninitialized options tail is not compared");
      actual.options[0xd] ^= 1; Require(!hot::EqualEvent(result.event, actual), "defined descriptor residue is compared");
      Require(hot::Capture(f.NodeAddress(), hot::Begin, hot::Entry, args, boundary.entries, input) == hot::Ready, "order model input");
      hot::Run(input, result); actual = result.event; actual.argument[1] ^= 0xffffff00;
      Require(hot::EqualEvent(result.event, actual), "begin order high bytes are stack residue");
      actual.argument[1] ^= 1; Require(!hot::EqualEvent(result.event, actual), "begin order low byte compared"); ++cases; }
    { label = "defined residue corruption is visible"; Fixture f; corruptRequest = true;
      Invoke(f, hot::Begin, 3); corruptRequest = false; }
}
static void RefusalCases() {
    U args[2] = {};
    { label = "wrong node class refused"; Fixture f; Put(f.Node(), 0, Addr(At(0x1321188)));
      hot::Reset(); hot::Configure(true); Require(!hot::Before(0x819310, f.NodeAddress(), args, production.entries), "wrong class no token");
      U w[hot::kWords]; hot::Snapshot(w); Require(w[hot::Refused] == 1 && !w[hot::Comparisons], "wrong class not compared"); ++cases; }
    { label = "unsupported reached predicate refuses without virtual execution"; Fixture f; f.Group();
      f.ownerVtable[0xec / 4] = Fn(&Unexpected); hot::Reset(); hot::Configure(true);
      Require(!hot::Before(0x819310, f.NodeAddress(), args, production.entries), "unknown predicate no token");
      U e[hot::kEventWords]; hot::EventSnapshot(e); Require(e[10] == 1, "predicate refusal reason"); ++cases; }
    { label = "unknown world projection callback is never invoked"; Fixture f; f.Projection();
      f.cellVtable[0] = Fn(&Unexpected); hot::Input input;
      Require(hot::Capture(f.NodeAddress(), hot::Begin, hot::SetterReturned, args, production.entries, input) == hot::NeedsProjection,
          "world callback branch needs owner certificate"); ++cases; }
    { label = "cold owner adjustment loader not replayed"; Fixture f; f.Projection(true);
      Put(f.manager.data(), 0x6bc, U(0)); hot::Input input;
      Require(hot::Capture(f.NodeAddress(), hot::Begin, hot::SetterReturned, args, production.entries, input) == hot::NeedsColdAdjustment,
          "cold world loader refusal"); ++cases; }
    { label = "late projection refusal never claims a whole-node comparison"; Fixture f; f.Projection();
      f.cellVtable[0] = Fn(&Unexpected); hot::Reset(); hot::Configure(true); observedCount = 0;
      U token = hot::Before(0x816900, f.NodeAddress(), args, boundary.entries);
      Require(token != 0, "entry order independently admitted");
      OrderBoundary(f.NodeAddress(), 0, 3, 0, 0);
      SetterBoundary(f.NodeAddress(), 0, Get<U>(f.Node(), 0x38));
      hot::After(token);
      U w[hot::kWords], e[hot::kEventWords]; hot::Snapshot(w); hot::EventSnapshot(e);
      Require(w[hot::PhaseCheckpoints] == 2 && w[hot::Refused] == 1 && !w[hot::Comparisons]
          && !w[hot::Matches] && e[9] == 1, "partial events retained but unresolved phase not compared"); ++cases; }
    { label = "pure model distinguishes noncanonical begin/step predicate bytes"; Fixture f; hot::Input in;
      Require(hot::Capture(f.NodeAddress(), hot::Step, hot::Entry, args, production.entries, in) == hot::Ready, "pure input");
      in.firstPredicate = in.secondPredicate = 2; hot::Result out; hot::Run(in, out);
      Require(!out.hasEvent, "step requires exactly one"); in.operation = hot::Begin; hot::Run(in, out);
      Require(out.hasEvent && out.event.argument[0] == 5, "begin accepts nonzero"); ++cases; }
}
// Only the outer occurrence and request transaction are explicit oracle seams.
// Holder virtual dispatch, the hot node begin/step clones, actual native order
// (owner+18 early arm), setter, and all generic Before/After hooks are production.
static void __fastcall ProductionRequest(U owner, U, const U* descriptor, const B* options) {
    auto& event = Record(hot::Request, owner);
    memcpy(event.descriptor, descriptor, 20); memcpy(event.options, options, 0x1c);
}
static void __fastcall HolderRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U)>(production.entries[NTW2_CLONE_BRAIN_W_HOLDER_STEP])(owner + 0x228);
}
static void __fastcall InstallRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U, const B*)>(production.entries[NTW2_CLONE_BRAIN_W_HOT_INSTALL])(
        owner, reinterpret_cast<const B*>(Get<U>(reinterpret_cast<void*>(owner), 0x5b8)));
}
static void ProductionRoutes() {
    for (bool started : {false, true}) {
        label = "production holder virtual routes to hot class"; Fixture f;
        Put(f.Node(), 0x10, B(started)); Put(f.Node(), 0x44, B(1)); Put(f.owner.data(), 0x390, U(6));
        f.ownerVtable[0xc / 4] = Addr(At(0x66ce00));
        std::array<U, NTW2_CLONE_COUNT> entries;
        std::copy(std::begin(production.entries), std::end(production.entries), entries.begin());
        entries[NTW2_CLONE_BRAIN_W] = Fn(&HolderRoute);
        entries[NTW2_CLONE_BRAIN_W_REQUEST] = Fn(&ProductionRequest);
        observedCount = 0; brain::Reset(); brain::Configure(false, false, true, false);
        brain::RunOccurrence(Addr(f.owner.data()), entries.data());
        Status(started ? 1 : 2, started ? 0 : 3);
        U targets[brain::kNodeTargetWords]; brain::NodeTargetSnapshot(targets);
        Require(targets[0] == 1 && targets[1] == U(started ? 1 : 2) && !targets[2], "target histogram identity and exact distinct count");
        Require(targets[4] == (started ? 0u : 0x816900u) && targets[5] == U(!started)
            && targets[20] == 0x819310 && targets[21] == 1, "hot begin/step histogram exact targets");
        Require(Get<B>(f.Node(), 0x10) == 1 && Get<B>(f.Node(), 8) == 1 && Get<U>(f.Node(), 0xc) == 1,
            "production holder owns started latch and post-step counter");
        Require(Get<U>(f.Node(), 0) == Addr(At(0x1348b44)), "native dynamic vtable retained");
        Require(observedCount == U(!started), "only production request event sink reached");
        brain::Configure(false, false, false, false); ++cases;
    }
    for (bool installed : {false, true}) {
        label = "production replacement wrapper reaches hot lifecycle"; Fixture f;
        Put(f.owner.data(), 0x2c4, B(installed)); Put(f.owner.data(), 0x5b8, Addr(f.descriptor.data()));
        f.ownerVtable[0xc / 4] = Addr(At(0x66ce00));
        std::array<U, NTW2_CLONE_COUNT> entries;
        std::copy(std::begin(production.entries), std::end(production.entries), entries.begin());
        entries[NTW2_CLONE_BRAIN_W] = Fn(&InstallRoute);
        brain::Reset(); brain::Configure(false, false, true, false);
        brain::RunOccurrence(Addr(f.owner.data()), entries.data());
        Status(installed ? 2 : 1, 0);
        Require(Get<U>(f.Node(), 0) == Addr(At(0x1348b44)) && Get<B>(f.owner.data(), 0x2c4) == 1,
            "native replacement republishes constructed hot node");
        brain::Configure(false, false, false, false); ++cases;
    }
}
static void CertifiedProjectionCases() {
    const float planar[2] = {11.0f, -7.0f};
    using Original = U (__thiscall*)(U, U*, const float*, const U*, U, U);
    for (bool lookup : {false, true}) for (bool nativePredicate : {false, true}) {
        label = "certified projection matches mapped original on every private bank";
        Fixture f; f.AcceptedCell(lookup, nativePredicate);
        U reference[5], expected[5]; memcpy(reference, f.Node() + 0x1c, 20);
        reinterpret_cast<Original>(At(0x7fd070))(Addr(f.query.data()), expected, planar, reference, 3, 0);
        std::array<B, 0x2030> originalScratch;
        memcpy(originalScratch.data(), At(0x15adb74), originalScratch.size());
        for (U p = 0; p < projection::kParticipants; ++p) {
            U actual[5], refused = 0;
            Require(projection::ProjectCertified(production.entries, Addr(f.query.data()), actual, planar, reference, 3, &refused, p),
                "certified direct/lookup traversal completed");
            Equal(expected, actual, 20, "certified projection bit-exact descriptor");
            Equal(originalScratch.data(), At(0x15adb74), originalScratch.size(), "certified traversal keeps original scratch untouched");
            Require(!refused && projection::Ready(p), "certified bank drains normally"); ++cases;
        }
        label = "unknown selected surface callback refuses after enqueue and cleans private scratch";
        f.surfaceVtable[4] = Fn(&Unexpected);
        U actual[5], refused = 0;
        Require(!projection::ProjectCertified(production.entries, Addr(f.query.data()), actual, planar, reference, 3, &refused),
            "unknown selected surface getter not executed");
        Require(refused != 0 && projection::Ready(), "late callback refusal leaves reusable private scratch");
        f.surfaceVtable[4] = Addr(At(0x461180));
        Require(projection::ProjectCertified(production.entries, Addr(f.query.data()), actual, planar, reference, 3),
            "private traversal reusable after callback refusal");
        Equal(expected, actual, 20, "post-refusal reuse remains bit exact"); ++cases;
    }
}
#include "native_idle_node_oracle.inc"
#include "native_action_node_oracle.inc"
static int RunOracle(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_move_node_oracle <approved Napoleon.exe>\n"); return 2; }
    ResetFp(); Map(argv[1]);
    { label = "mapped original constructor"; Fixture f; memset(f.Node(), 0x6d, hot::kNodeBytes); Invoke(f, hot::Construct, 0, true); }
    { label = "mapped original destructor including empty delete branch"; Fixture f; Invoke(f, hot::Destroy, 0, true); }
    StepCases(); BeginCases(); RefusalCases(); ProductionRoutes();
    CertifiedProjectionCases(); RunIdleNodeCases(); RunActionNodeCases();
    hot::Release();
    for (U p = 0; p < projection::kParticipants; ++p) {
        Put(reinterpret_cast<void*>(bindings[NTW2_BIND_NODE_PROJ_VISIT_0 + p]), 4, U(0));
        Put(reinterpret_cast<void*>(bindings[NTW2_BIND_NODE_PROJ_VISIT_0 + p]), 0x2028, U(0));
        Put(reinterpret_cast<void*>(bindings[NTW2_BIND_NODE_PROJ_LOOKUP_0 + p]), 0xc, U(0));
    }
    projection::Release();
    VirtualFree(boundary.allocation, 0, MEM_RELEASE); VirtualFree(production.allocation, 0, MEM_RELEASE);
    VirtualFree(image, 0, MEM_RELEASE);
    std::printf("native_move_node_oracle: %u cases, %u checks (world transactions are event seams)\n", cases, checks);
    return 0;
}
static int ReportException(EXCEPTION_POINTERS* fault) {
    std::fprintf(stderr, "FAIL [%s]: exception=%08lx EIP=%08lx mappedVA=%08lx ECX=%08lx EDX=%08lx\n", label,
        fault->ExceptionRecord->ExceptionCode, fault->ContextRecord->Eip, fault->ContextRecord->Eip - delta,
        fault->ContextRecord->Ecx, fault->ContextRecord->Edx);
    return EXCEPTION_EXECUTE_HANDLER;
}
int main(int argc, char** argv) {
    __try { return RunOracle(argc, argv); }
    __except (ReportException(GetExceptionInformation())) { return 1; }
}
