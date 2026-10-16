// Win32 mapped-image oracle, following native_brain2_oracle.cpp's image identity,
// relocation, TLS and FP fixture. No game .text or mapped instruction is patched.
// Arrival/request event-boundary cases record the actual calls from the pinned
// 6758D0 clone. They do NOT claim ownership/validation of the 659600 sequencer.
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
#include "native_node.h"
#include "native_node_projection.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace node = ntw2_node;
namespace brain = ntw2_brain2;
static_assert(sizeof(void*) == 4, "Win32 native ABI");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, checks, cases;
static const char* label = "map";
static ntw2_clone_set production{}, boundary{};
static U bindings[NTW2_BIND_COUNT];
static U productionServiceGate, commonTarget;
static U ringBacking[10][64], lookupBacking[10][64];
static uint16_t idBacking[10][64];
static node::Event observed[3];
static U observedCount, attachedCalls;
static bool executeArrival;
static U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T f) { return static_cast<U>(reinterpret_cast<uintptr_t>(f)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
template<class T> static T Get(const void* p, U offset) { T v; memcpy(&v, static_cast<const B*>(p) + offset, sizeof(v)); return v; }
template<class T> static void Put(void* p, U offset, T value) { memcpy(static_cast<B*>(p) + offset, &value, sizeof(value)); }
[[noreturn]] static void Fail(const char* what) { std::fprintf(stderr, "FAIL [%s]: %s\n", label, what); std::exit(1); }
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail(what); }
static void Equal(const void* a, const void* b, size_t n, const char* what) { Require(!memcmp(a, b, n), what); }
static void ResetFp(unsigned short control = 0x27f) {
    __asm fninit
    __asm fldcw word ptr [control]
    _mm_setcsr(0x1f80);
}
struct FpState { U mxcsr; uint16_t control, status; };
static FpState CaptureFp() {
    unsigned short control, status;
    __asm fnstcw word ptr [control]
    __asm fnstsw word ptr [status]
    return {_mm_getcsr(), control, status};
}
static void CheckFp(const FpState& expected) {
    const FpState actual = CaptureFp();
    Require(actual.mxcsr == expected.mxcsr && actual.control == expected.control && actual.status == expected.status,
        "shadow preserves MXCSR and x87 control/status/stack depth");
}
static void Unexpected() { Fail("unrelated clone binding reached"); }
static node::Event& Record(node::EventKind kind, U owner) {
    Require(observedCount < 3, "bounded native event sequence");
    auto& event = observed[observedCount++]; event = {}; event.kind = kind; event.owner = owner; return event;
}
static void __fastcall RecordArrival(U owner, U, U reference) {
    Record(node::Arrival, owner).argument[0] = reference;
    node::Observe(0x655b20, owner, &reference);
    if (executeArrival) reinterpret_cast<void (__thiscall*)(U, U)>(At(0x655b20))(owner, reference);
}
static void __fastcall RecordOrder(U receiver, U, U order, U first, U second) {
    U owner = Get<U>(reinterpret_cast<void*>(receiver), 4);
    auto& event = Record(node::Order, owner);
    event.argument[0] = order; event.argument[1] = first; event.argument[2] = second;
    node::Observe(0x6631a0, owner, event.argument);
    if (executeArrival) reinterpret_cast<void (__thiscall*)(U, U, U, U)>(At(0x662e70))(receiver, order, first, second);
}
static void __fastcall RecordRequest(U owner, U, const U* descriptor, const B* options) {
    auto& event = Record(node::Request, owner);
    memcpy(event.descriptor, descriptor, 20); memcpy(event.options, options, 0x1c);
    U args[2] = {Addr(descriptor), Addr(options)};
    node::Observe(0x659520, owner, args);
    // This is an explicit event boundary, not a fake implementation of 659520.
    // The native node continuation still performs its real cache stores.
}
static void __stdcall BoundaryTarget(U* stack) {
    if (stack[0] == 0x6759de) stack[1] = Fn(&RecordArrival);
    else if (stack[0] == 0x6759eb) stack[1] = Fn(&RecordOrder);
    else if (stack[0] == 0x675b36) stack[1] = Fn(&RecordRequest);
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
        Put(lookup, 4, U(64)); Put(lookup, 0xc, Addr(lookupBacking[p]));
        Put(lookup, 0x10, U(0x80000000));
    }
}
static void UnseedBanks() {
    for (U p = 0; p < node::projection::kParticipants; ++p) {
        B* visit = reinterpret_cast<B*>(bindings[NTW2_BIND_NODE_PROJ_VISIT_0 + p]);
        B* lookup = reinterpret_cast<B*>(bindings[NTW2_BIND_NODE_PROJ_LOOKUP_0 + p]);
        Put(visit, 4, U(0)); Put(visit, 0x2028, U(0)); Put(lookup, 0xc, U(0));
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
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
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
    // Warm original projection guards as in the existing mapped oracles. These
    // are image DATA only; private projection clones do not read these guards.
    Put(At(0x1841bb8), 0, U(_tls_index)); tlsPad[0] = 0;
    Put(At(0x15adb88), 0, U(0x80000000)); Put(At(0x15afba0), 0, U(0x80000000));
    memset(At(0x15adb74), 0, 20); memset(At(0x15adb90), 0, 0x2010);
    Put(At(0x131a7b0), 0, 0.125f); Put(At(0x14a519c), 0, uint16_t(0x200));
    Put(At(0x150fca8), 0, 1.25f); Put(At(0x150fcac), 0, -2.5f); Put(At(0x150fcb0), 0, 3.75f);
    Put(At(0x14d05b0), 0, uint16_t(0x4321));
    std::fill(std::begin(bindings), std::end(bindings), Fn(&Unexpected));
    Require(brain::Bind(Addr(image), bindings), "bind production gates and private projection");
    productionServiceGate = bindings[NTW2_BIND_B2_SERVICE_GATE];
    commonTarget = Addr(At(0x670eb0));
    Require(node::projection::Initialize(Addr(image), bindings), "initialize private projection");
    node::Bind(Addr(image));
    SeedBanks();
    U detail = 0;
    Require(ntw2_build_clones(Addr(image), bindings, &production, &detail) == 0, "build production clones");
    bindings[NTW2_BIND_B2_SERVICE_GATE] = Fn(&BoundaryGate);
    Require(ntw2_build_clones(Addr(image), bindings, &boundary, &detail) == 0, "build event-boundary clones");
}
static void __fastcall Attach(U reference, U, U owner) {
    ++attachedCalls;
    Put(reinterpret_cast<void*>(reference), 0x680 + 4 * ((attachedCalls - 1) & 1), owner);
}
struct Fixture {
    std::array<B, 0x700> owner{}, reference{};
    std::array<B, 0x20> root{}, query{};
    std::array<B, 0xc0> model{};
    std::array<B, 0x40> database{}, movement{};
    std::array<B, 0xa0> cell{};
    std::array<B, 0x60> lookupGrid{}, polygons{};
    std::array<B, 32 * 32 * 8> lookupCells{};
    std::array<B, 0x20> polygonRing{};
    U polygonPointer;
    std::array<U, 6> surfaceVtable{};
    std::array<B, 0x60> surface{}, row{};
    std::array<B, 0x100> transform{};
    std::array<B, 0xa0> animation{};
    std::array<B, 0x20> animationFrame{};
    std::array<B, 24 * 0x23d> rows{};
    U databaseLink, framePointer;
    std::array<U, 0x200 / 4> ownerVtable{}, referenceVtable{};
    Fixture() {
        memcpy(ownerVtable.data(), At(0x1333714), sizeof(ownerVtable));
        referenceVtable = ownerVtable;
        ownerVtable[0xa8 / 4] = Addr(At(0x461180));
        referenceVtable[0x1b0 / 4] = Fn(&Attach); referenceVtable[0x1b8 / 4] = Fn(&Attach);
        Put(owner.data(), 0, Addr(ownerVtable.data())); Put(reference.data(), 0, Addr(referenceVtable.data()));
        Put(root.data(), 8, Addr(model.data())); Put(model.data(), 0xb4, Addr(query.data()));
        Put(query.data(), 0, Addr(root.data()));
        databaseLink = Addr(database.data()); Put(database.data(), 0x2c, Addr(rows.data()));
        Put(owner.data(), 0x218, Addr(&databaseLink));
        Put(owner.data(), 0x28, Addr(root.data())); Put(reference.data(), 0x28, Addr(root.data()));
        Put(owner.data(), 0x228, Addr(owner.data())); Put(owner.data(), 0x2c8, Addr(root.data()));
        Put(owner.data(), 0x1e8, Addr(movement.data())); Put(movement.data(), 0x20, 2.75f);
        Put(owner.data(), 0x34, U(0x443)); Put(owner.data(), 0x38, U(0x843));
        Put(owner.data(), 0xec, B(1)); Put(reference.data(), 0xec, B(1));
        Put(owner.data(), 0x1d8, U(0x17)); Put(owner.data(), 0x5e4, U(0x31415926));
        Put(owner.data(), 0x5b8, Addr(reference.data()));
        Put(owner.data(), 0x48, -20.0f); Put(owner.data(), 0x50, -30.0f);
        Put(reference.data(), 0x48, 4.0f); Put(reference.data(), 0x50, 8.0f);
        Put(reference.data(), 0x64, uint16_t(0x1234)); Put(reference.data(), 0x674, B(1));
        Put(reference.data(), 0xb4, B(1)); Put(reference.data(), 0xf4, U(0xdeadbeef));
        Put(surface.data(), 0x40, Addr(cell.data()));
        surfaceVtable.fill(Addr(At(0x461180)));
        Put(surface.data(), 0, Addr(surfaceVtable.data()));
        Put(surface.data(), 0x34, -1.0f); Put(surface.data(), 0x3c, 2.0f);
        Put(cell.data(), 8, Addr(polygonRing.data())); Put(cell.data(), 0x24, Addr(surface.data()));
        Put(polygonRing.data(), 8, Addr(polygonRing.data()));
        // Cell virtual false takes the real 7FD070 fallback, returning the
        // reference descriptor; no invented grid or allocator is needed.
        Put(cell.data(), 0xc, Addr(ownerVtable.data() + 0x1c / 4));
        ownerVtable[0x1c / 4] = Addr(At(0x462cb0));
        Descriptor(false);
        memset(owner.data() + node::kNodeOffset, 0xa5, node::kNodeBytes);
        U ref = Addr(reference.data());
        reinterpret_cast<U (__thiscall*)(U, U, U*)>(At(0x61da90))(Addr(owner.data()) + node::kNodeOffset,
            Addr(owner.data()) + 0x228, &ref);
        Cache();
    }
    void Descriptor(bool transformed) {
        Put(reference.data(), 0x4f8, 4.0f); Put(reference.data(), 0x4fc, 2.0f); Put(reference.data(), 0x500, 8.0f);
        Put(reference.data(), 0x504, Addr(surface.data())); Put(reference.data(), 0x508, transformed ? Addr(transform.data()) : U(0));
        if (transformed) {
            Put(transform.data(), 0x9c, 1.0f); Put(transform.data(), 0xac, 1.0f); Put(transform.data(), 0xbc, 1.0f);
            Put(transform.data(), 0x80, 3.0f); Put(transform.data(), 0x84, -1.0f); Put(transform.data(), 0x88, -2.0f);
        }
    }
    void Cache() {
        memcpy(owner.data() + node::kNodeOffset + 0x20, reference.data() + 0x4f8, 20);
        uint16_t heading;
        reinterpret_cast<U (__thiscall*)(U, uint16_t*)>(At(0x5e4af0))(Addr(reference.data()), &heading);
        Put(owner.data(), node::kNodeOffset + 0x34, heading);
    }
    void ComplexPose() {
        const U rowId = Get<B>(reference.data(), 0x674) == 1 ? 0x23b : 0x23c;
        Put(rows.data(), rowId * 24, Addr(row.data())); Put(rows.data(), rowId * 24 + 0x14, U(1));
        Put(row.data(), 0x44, Addr(animation.data()));
        Put(animation.data(), 0x48, 1.0f); Put(animation.data(), 0x88, U(1));
        framePointer = Addr(animationFrame.data()); Put(animation.data(), 0x8c, Addr(&framePointer));
        Put(animationFrame.data(), 0xc, 0.75f); Put(animationFrame.data(), 0x10, 0.5f); Put(animationFrame.data(), 0x14, -1.25f);
    }
    void AcceptedCell(bool lookup) {
        ownerVtable[0x1c / 4] = Addr(At(0x447880));
        if (!lookup) return;
        Put(surface.data(), 0x40, U(0));
        Put(model.data(), 0xb8, Addr(lookupGrid.data()));
        Put(model.data(), 0x74, -64.0f); Put(model.data(), 0x78, -64.0f);
        Put(model.data(), 0x7c, 64.0f); Put(model.data(), 0x80, 64.0f);
        Put(lookupGrid.data(), 0, Addr(lookupCells.data())); Put(lookupGrid.data(), 8, U(5));
        Put(lookupGrid.data(), 0xc, U(32)); Put(lookupGrid.data(), 0x10, U(16));
        Put(lookupGrid.data(), 0x14, U(31)); Put(lookupGrid.data(), 0x24, 0.25f);
        Put(lookupGrid.data(), 0x38, Addr(root.data())); Put(lookupGrid.data(), 0x3c, Addr(polygons.data()));
        polygonPointer = Addr(cell.data());
        Put(polygons.data(), 0x4c, U(1)); Put(polygons.data(), 0x50, Addr(&polygonPointer));
        // Every real 8-byte grid cell names polygon id 0. The original bucket
        // collector deduplicates its four samples into the private lookup bank.
    }
};
static bool Pose(void*, U reference, U owner, float xy[2], uint16_t* heading) {
    reinterpret_cast<U (__thiscall*)(U, float*, U)>(At(0x5e4b20))(reference, xy, owner);
    reinterpret_cast<U (__thiscall*)(U, uint16_t*)>(At(0x5e4af0))(reference, heading); return true;
}
static bool Descriptor(void*, U reference, U out[5]) {
    reinterpret_cast<U (__thiscall*)(U, U*)>(At(0x659480))(reference, out); return true;
}
static bool Materialize(void*, const U d[5], float xyz[3]) {
    reinterpret_cast<U (__thiscall*)(const U*, float*)>(At(0x80e9d0))(d, xyz); return true;
}
static bool Project(void*, U query, const float xy[2], const U reference[5], U out[5]) {
    using Call = U (__thiscall*)(U, U*, const float*, const U*, U, U);
    U entry = node::projection::Entry(boundary.entries);
    if (!entry) return false;
    reinterpret_cast<Call>(entry)(query, out, xy, reference, 3, 0); return true;
}
static node::Services FixtureServices() { return {nullptr, Pose, Descriptor, Materialize, Project}; }
static void CheckEvents(const node::Result& expected) {
    Require(expected.eventCount == observedCount, "native event count and order");
    for (U i = 0; i < observedCount; ++i) {
        const auto& a = expected.events[i]; const auto& b = observed[i];
        Require(a.kind == b.kind && a.owner == b.owner, "event receiver/kind");
        Equal(a.argument, b.argument, sizeof(a.argument), "event arguments");
        if (a.kind == node::Request) {
            Equal(a.descriptor, b.descriptor, 20, "projected request descriptor bits");
            Equal(a.options, b.options, 0x19, "defined options and descriptor residue bits");
        }
    }
}
static void StepCase(Fixture& f, B begin, U expectedEvents, bool fullArrival = false, unsigned short control = 0x27f) {
    ++cases; ResetFp(control); node::Reset(); node::Configure(true); node::SetServices(nullptr);
    const auto before = f.owner;
    node::Input input; node::Result expected;
    Require(node::Capture(Addr(f.owner.data()), begin ? node::Begin : node::Step, begin, FixtureServices(), input), "owner snapshot prepared");
    Equal(before.data(), f.owner.data(), before.size(), "capture does not write owner");
    U argument = begin;
    const FpState beforeShadow = CaptureFp();
    U token = node::Before(0x6758d0, Addr(f.owner.data()) + node::kNodeOffset, &argument, boundary.entries);
    CheckFp(beforeShadow);
    Require(token != 0, "native preparation admits fixture");
    observedCount = 0; executeArrival = fullArrival; attachedCalls = 0;
    ResetFp(control);
    reinterpret_cast<void (__thiscall*)(U, U)>(boundary.entries[NTW2_CLONE_BRAIN_W_REFERENCE])(
        Addr(f.owner.data()) + node::kNodeOffset, begin);
    const auto originalAfter = f.owner;
    const FpState nativeFp = CaptureFp();
    node::After(token);
    CheckFp(nativeFp);
    Equal(originalAfter.data(), f.owner.data(), originalAfter.size(), "shadow After does not publish bytes");
    ResetFp(control); node::Run(input, expected);
    CheckEvents(expected); Require(observedCount == expectedEvents, "independently specified branch event count");
    U offset = 0;
    Require(node::Compare(expected, {f.owner.data(), Addr(f.owner.data())}, &offset), "defined own fields and all 0x38 node bytes match");
    U status[node::kWords]; node::Snapshot(status);
    Require(status[node::Comparisons] == 1 && status[node::Matches] == 1 && !status[node::Mismatches], "production Capture/original/Run/Compare shadow matches");
    Require(status[node::WorkersBlocked] == 1 && !status[node::FakeTableInstalled], "owner proof never enables workers or installs table");
    if (fullArrival) {
        Require(attachedCalls == 2, "original attachment virtuals run once each");
        Require(Get<U>(f.owner.data(), 0x1ec) == Addr(f.reference.data()) && !Get<U>(f.owner.data(), 0x5b8), "actual arrival attachment publication");
    }
}
static void Lifecycle() {
    label = "ctor preserves unknown padding and holder identity";
    Fixture f;
    memset(f.owner.data() + node::kNodeOffset, 0x6d, node::kNodeBytes);
    node::Input input; node::Result expected;
    U reference = Addr(f.reference.data());
    Require(node::Capture(Addr(f.owner.data()), node::Construct, reference, FixtureServices(), input), "capture constructor");
    reinterpret_cast<U (__thiscall*)(U, U, U*)>(At(0x61da90))(Addr(f.owner.data()) + node::kNodeOffset,
        Addr(f.owner.data()) + 0x228, &reference);
    node::Run(input, expected);
    Require(node::Compare(expected, {f.owner.data(), Addr(f.owner.data())}), "entire constructor node and enabled byte");
    for (U offset : {9u, 10u, 11u, 17u, 18u, 19u, 55u})
        Require(Get<B>(f.owner.data(), node::kNodeOffset + offset) == 0x6d, "constructor leaves padding intact");
    ++cases;
    for (B contextFlag : {B(0), B(1)}) for (B active : {B(0), B(1), B(2)}) for (B restore : {B(0), B(1)}) {
        label = "destructor exact byte widths and flag restoration";
        Fixture d;
        Put(d.model.data(), 0x54, contextFlag); Put(d.owner.data(), 0xec, active);
        Put(d.owner.data(), node::kNodeOffset + 0x36, restore);
        Put(d.owner.data(), 0x1d4, U(0xabcdef01)); Put(d.owner.data(), 0x478, U(0x33445500));
        Require(node::Capture(Addr(d.owner.data()), node::Destroy, 1, FixtureServices(), input), "capture inline destruction");
        U returned = reinterpret_cast<U (__thiscall*)(U, U)>(At(0x624f80))(Addr(d.owner.data()) + node::kNodeOffset, 1);
        node::Run(input, expected);
        Require(returned == Addr(d.owner.data()) + node::kNodeOffset, "native dtor returns N");
        Require(node::Compare(expected, {d.owner.data(), Addr(d.owner.data())}), "native destructor local stores match");
        ++cases;
    }
    label = "thirteen detached virtual query slots";
    const U* table = node::FakeVtable();
    for (U slot = 3; slot < node::kVirtualSlots; ++slot) {
        const U native = Get<U>(At(0x1334180), slot * 4);
        if (slot <= 5) {
            Require(reinterpret_cast<U (__thiscall*)(U)>(native)(0) == reinterpret_cast<U (__thiscall*)(U)>(table[slot])(0), "null query full EAX");
        } else {
            Require(reinterpret_cast<B (__thiscall*)(U)>(native)(0) == reinterpret_cast<B (__thiscall*)(U)>(table[slot])(0), "boolean query AL");
        }
    }
    Require(Get<U>(f.owner.data(), node::kNodeOffset) == Addr(At(0x1334180)), "fake table never installed");
}
static void ProjectionCases() {
    label = "mapped original projection success/fallback/lookup and bank reuse";
    using Call = U (__thiscall*)(U, U*, const float*, const U*, U, B*);
    float planar[2] = {11.0f, -7.0f};
    for (U mode = 0; mode < 3; ++mode) for (bool transformed : {false, true}) {
        Fixture f;
        f.Descriptor(transformed);
        if (mode) f.AcceptedCell(mode == 2);
        U reference[5], expected[5]; memcpy(reference, f.reference.data() + 0x4f8, 20);
        B fallback = 0;
        reinterpret_cast<Call>(At(0x7fd070))(Addr(f.query.data()), expected, planar, reference, 3, &fallback);
        Require(fallback == (mode == 0), "independently selected fallback or accepted-cell success");
        if (mode) {
            Require(Get<float>(expected, 0) == planar[0] && Get<float>(expected, 8) == planar[1],
                "accepted cell returns projected destination, not reference fallback");
        }
        std::array<B, 0x2030> originalVisit;
        std::array<B, 20> originalLookup;
        memcpy(originalVisit.data(), At(0x15adb74), originalVisit.size());
        memcpy(originalLookup.data(), At(0x14d0a6c), originalLookup.size());
        for (unsigned p = 0; p < node::projection::kParticipants; ++p) for (U repeat = 0; repeat < 3; ++repeat) {
            U actual[5]; B privateFallback = 0;
            Require(node::projection::Ready(p), "private bank starts quiescent");
            U entry = node::projection::Entry(boundary.entries, p);
            Require(entry != 0, "private projection clone exists");
            U result = reinterpret_cast<Call>(entry)(Addr(f.query.data()), actual, planar, reference, 3, &privateFallback);
            Require(result == Addr(actual) && privateFallback == fallback, "projection ABI and fallback output");
            Equal(actual, expected, sizeof(actual), "projection descriptor bit parity");
            Equal(originalVisit.data(), At(0x15adb74), originalVisit.size(), "private ring/bitset/id bank never writes original");
            Equal(originalLookup.data(), At(0x14d0a6c), originalLookup.size(), "private lookup never writes original");
            Require(node::projection::Ready(p), "private ring/id list drained for reuse");
            Require(Get<U>(reinterpret_cast<void*>(bindings[NTW2_BIND_NODE_PROJ_LOOKUP_0 + p]), 8) == 0,
                "private candidate list drained for reuse");
            ++cases;
        }
    }
}
static void GenericGates() {
    label = "production generic ctor/reference-step/dtor gates";
    Fixture f;
    brain::Configure(true, false, true, false); brain::Reset(); node::Reset(); node::Configure(true);
    U reference = Addr(f.reference.data());
    reinterpret_cast<U (__thiscall*)(U, U, U*)>(brain::GateAddress(brain::ReferenceConstruct))(
        Addr(f.owner.data()) + node::kNodeOffset, Addr(f.owner.data()) + 0x228, &reference);
    Put(f.reference.data(), 0xec, B(0));
    reinterpret_cast<void (__thiscall*)(U, U)>(brain::GateAddress(brain::ReferenceStep))(
        Addr(f.owner.data()) + node::kNodeOffset, 0);
    reinterpret_cast<U (__thiscall*)(U, U)>(brain::GateAddress(brain::NodeDestroy))(
        Addr(f.owner.data()) + node::kNodeOffset, 1);
    U status[node::kWords]; node::Snapshot(status);
    Require(status[node::Comparisons] == 3 && status[node::Matches] == 3 && !status[node::Mismatches], "generic gates execute original once and compare all three operations");
    brain::Configure(false, false, false, false); ++cases;
}
// Only the outer occurrence is substituted. Every driver, holder, node and
// reference arithmetic entry below is the production clone or mapped original.
static void __fastcall MoveRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U, U)>(brain::GateAddress(brain::MoveDriver))(owner, 1);
}
static void __fastcall HolderRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U)>(production.entries[NTW2_CLONE_BRAIN_W_HOLDER_STEP])(owner + 0x228);
}
static void __fastcall HolderGateRoute(U owner, U) {
    reinterpret_cast<void (__thiscall*)(U)>(brain::GateAddress(brain::PreBattle))(owner + 0x228);
}
__declspec(naked) static void CommonRoute() {
    __asm push dword ptr [commonTarget]
    __asm push 0
    __asm jmp dword ptr [productionServiceGate]
}
// Explicit outer effects boundary: 81AC80 still performs its native multiply
// and stores; only the owner's virtual scale query is supplied by the fixture.
static float __fastcall EffectScale(U, U) { return 2.0f; }
static int ReportException(EXCEPTION_POINTERS* fault) {
    const U pc = fault->ContextRecord->Eip;
    std::fprintf(stderr, "FAIL [%s]: exception=%08lx EIP=%08x mappedVA=%08x ECX=%08lx EDX=%08lx\n",
        label, fault->ExceptionRecord->ExceptionCode, pc, pc - delta,
        fault->ContextRecord->Ecx, fault->ContextRecord->Edx);
    if (fault->ExceptionRecord->NumberParameters >= 2)
        std::fprintf(stderr, "  access=%lu address=%08lx preferred=%08lx\n",
            fault->ExceptionRecord->ExceptionInformation[0], fault->ExceptionRecord->ExceptionInformation[1],
            fault->ExceptionRecord->ExceptionInformation[1] - delta);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
static void ScopedRoute(Fixture& f, U outer) {
    static std::array<U, NTW2_CLONE_COUNT> entries;
    std::copy(std::begin(production.entries), std::end(production.entries), entries.begin());
    entries[NTW2_CLONE_BRAIN_W] = outer;
    f.ownerVtable[0xc / 4] = Addr(At(0x66ce00));
    brain::RunOccurrence(Addr(f.owner.data()), entries.data());
}
static void RouteCases() {
    for (U outer : {Fn(&MoveRoute), Fn(&HolderRoute), Fn(&HolderGateRoute), Fn(&CommonRoute)}) {
        for (bool referenceClass : {false, true}) for (bool started : {false, true}) {
            char routeLabel[128];
            const char* routeName = outer == Fn(&MoveRoute) ? "move" :
                outer == Fn(&HolderRoute) ? "holder-direct" :
                outer == Fn(&HolderGateRoute) ? "holder-gate" : "common-gate";
            std::snprintf(routeLabel, sizeof(routeLabel), "production %s reference=%u started=%u",
                routeName, U(referenceClass), U(started));
            label = routeLabel;
            Fixture f;
            // The inactive reference executes genuine 6758D0 and completes
            // without requesting a path. A started node reaches step directly.
            Put(f.reference.data(), 0xec, B(0));
            Put(f.owner.data(), 0x5b8, U(0));
            Put(f.owner.data(), 0x10, U(0)); // no borrowed surface in driver tail
            Put(f.owner.data(), 0xb4, B(1));
            Put(f.owner.data(), 0x1d8, U(0xffffffff)); // native commit default return
            f.ownerVtable[0xec / 4] = Addr(At(0x461180));
            Put(f.owner.data(), 0x2c4, B(1));
            Put(f.owner.data(), node::kNodeOffset + 8, B(0));
            Put(f.owner.data(), node::kNodeOffset + 0xc, U(0));
            Put(f.owner.data(), node::kNodeOffset + 0x10, B(started));
            if (!referenceClass)
                Put(f.owner.data(), node::kNodeOffset, Addr(At(0x1321188)));
            Put(f.owner.data(), 0x18, U(1)); // native common effects nongrid arm
            Put(f.owner.data(), 0xa4, 3.0f);
            f.ownerVtable[0x74 / 4] = Fn(&EffectScale);
            brain::Reset(); brain::Configure(false, false, true, false);
            node::SetServices(nullptr); ResetFp();
            ScopedRoute(f, outer);
            U status[node::kWords], route[8];
            node::Snapshot(status); brain::RouteSnapshot(route);
            U brainStatus[brain::kWords]; brain::Snapshot(brainStatus);
            Require(brainStatus[brain::CensusEnabled] == 1 && brainStatus[brain::CloneOccurrences] == 1
                && !brainStatus[brain::OriginalOccurrences], "shadow alone enables census and scoped clone dispatch");
            Require(route[0] == 1 && route[1] == 1, "shadow alone selects move-driver clone configuration");
            Require(route[4] == U(!started) && route[5] == U(started || !referenceClass),
                "virtual route counters include real reference and unrelated base nodes");
            Require(status[node::Captures] == U(referenceClass) && status[node::Comparisons] == U(referenceClass)
                && status[node::Matches] == U(referenceClass) && !status[node::Mismatches]
                && !status[node::Refused], "only actual reference-node arithmetic is captured and matched");
            Require(Get<B>(f.owner.data(), node::kNodeOffset + 0x10) == 1,
                "native retained holder publishes started latch");
            Require(Get<U>(f.owner.data(), node::kNodeOffset + 0xc) == U(started || !referenceClass),
                "native retained holder increments only executed step");
            Require(Get<U>(f.owner.data(), node::kNodeOffset) ==
                Addr(At(referenceClass ? 0x1334180 : 0x1321188)), "native dynamic node identity retained");
            Require(route[6] == 0, "retained-node fixture does not construct a reference");
            if (outer == Fn(&MoveRoute))
                Require(route[2] == NTW2_CLONE_BRAIN_W_MOVEORDER + 1 && route[3] == 1,
                    "actual move driver is production clone, not original fallback");
            if (outer == Fn(&CommonRoute))
                Require(Get<float>(f.owner.data(), 0x54) == 6.0f && Get<U>(f.owner.data(), 0x19c) == 0x15,
                    "common wrapper retains native outer effects");
            ++cases;
        }
    }
    label = "production move-driver reference constructor tail";
    Fixture f;
    Put(f.owner.data(), 0xb4, B(1)); Put(f.owner.data(), 0x1d8, U(0xffffffff));
    f.ownerVtable[0xec / 4] = Addr(At(0x461180));
    Put(f.owner.data(), 0x2c4, B(0)); // no live node to destroy
    Put(f.owner.data(), 0x10, U(0));
    memset(f.owner.data() + node::kNodeOffset, 0x6d, node::kNodeBytes);
    brain::Reset(); brain::Configure(false, false, true, false);
    ScopedRoute(f, Fn(&MoveRoute));
    U status[node::kWords], route[8];
    node::Snapshot(status); brain::RouteSnapshot(route);
    Require(route[2] == NTW2_CLONE_BRAIN_W_MOVEORDER + 1 && route[3] == 1
        && !route[4] && !route[5] && route[6] == 1, "driver ctor tail route counts");
    Require(status[node::Captures] == 1 && status[node::Comparisons] == 1
        && status[node::Matches] == 1 && !status[node::Refused] && !status[node::Mismatches],
        "actual driver constructor tail captured and matched");
    Require(Get<U>(f.owner.data(), 0x224) == 7 && Get<B>(f.owner.data(), 0x2c4) == 1
        && Get<U>(f.owner.data(), node::kNodeOffset) == Addr(At(0x1334180))
        && Get<U>(f.owner.data(), node::kNodeOffset + 0x1c) == Addr(f.reference.data()),
        "native driver publishes reference identity and phase");
    brain::Configure(false, false, false, false); ++cases;
}
static void ThresholdCases() {
    for (unsigned short control : {0x27f, 0x67f, 0xa7f, 0xe7f}) {
        label = "FISTP refresh threshold follows x87 rounding control";
        Fixture f;
        Put(f.owner.data(), node::kNodeOffset + 0x34,
            uint16_t(Get<uint16_t>(f.owner.data(), node::kNodeOffset + 0x34) + 183));
        StepCase(f, 0, control == 0xa7f ? 0 : 1, false, control);
        label = "arrival heading strict threshold follows x87 rounding control";
        Fixture a;
        Put(a.owner.data(), 0x48, 4.0f); Put(a.owner.data(), 0x50, 8.0f);
        Put(a.owner.data(), 0x64, uint16_t(Get<uint16_t>(a.owner.data(), node::kNodeOffset + 0x34) + 910));
        StepCase(a, 1, control == 0xa7f ? 2 : 1, false, control);
    }
    label = "planar threshold equality suppresses refresh";
    Fixture tie; Put(tie.owner.data(), node::kNodeOffset + 0x20, 3.875f); StepCase(tie, 0, 0);
    label = "one ULP outside planar threshold refreshes";
    Fixture outside;
    U bits; float value = 3.875f; memcpy(&bits, &value, 4);
    Put(outside.owner.data(), node::kNodeOffset + 0x20, bits - 1); StepCase(outside, 0, 1);
}
static void MismatchCases() {
    label = "mismatch evidence does not repair native node bytes";
    Fixture f; Put(f.reference.data(), 0xec, B(0));
    node::Reset(); node::Configure(true);
    U argument = 0;
    U token = node::Before(0x6758d0, Addr(f.owner.data()) + node::kNodeOffset, &argument, production.entries);
    Require(token != 0, "mismatch fixture admitted");
    reinterpret_cast<void (__thiscall*)(U, U)>(At(0x6758d0))(Addr(f.owner.data()) + node::kNodeOffset, 0);
    Put(f.owner.data(), node::kNodeOffset + 9, B(0x3c));
    U unexpectedReference = Addr(f.reference.data());
    node::Observe(0x655b20, Addr(f.owner.data()), &unexpectedReference);
    const auto actual = f.owner;
    node::After(token);
    Equal(actual.data(), f.owner.data(), actual.size(), "mismatch leaves original-after untouched");
    U status[node::kWords]; node::Snapshot(status);
    Require(status[node::Mismatches] == 1 && status[node::NodeMismatches] == 1
        && status[node::EventMismatches] == 1 && !status[node::Matches], "byte/event differences remain visible");
    ++cases;
}
static int RunOracle(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_node_oracle <approved Empire.exe>\n"); return 2; }
    ResetFp(); Map(argv[1]);
    Lifecycle(); ProjectionCases();
    { label = "inactive reference completes without reading getter graph"; Fixture f; Put(f.reference.data(), 0xec, B(0)); StepCase(f, 1, 0); }
    { label = "stable follower suppresses refresh"; Fixture f; StepCase(f, 0, 0); }
    { label = "noncanonical nonzero begin byte is not forced refresh"; Fixture f; StepCase(f, 2, 0); }
    { label = "reference active byte two remains valid"; Fixture f; Put(f.reference.data(), 0xec, B(2)); StepCase(f, 0, 0); }
    { label = "nonbegin owner flag clears both masks"; Fixture f; Put(f.owner.data(), 0x117, B(1)); StepCase(f, 0, 0); }
    { label = "related reference value copied"; Fixture f; Put(f.reference.data(), 0x1ec, Addr(f.surface.data())); Put(f.surface.data(), 0x2c, U(0x76543210)); StepCase(f, 0, 0); }
    { label = "begin emits request event and cache stores"; Fixture f; StepCase(f, 1, 1); }
    for (U state : {6u, 7u}) { label = "state forces request refresh"; Fixture f; Put(f.owner.data(), 0x390, state); StepCase(f, 0, 1); }
    { label = "transformed cache materialization"; Fixture f; f.Descriptor(true); f.Cache(); StepCase(f, 0, 1); }
    { label = "descriptor built from pose and surface, not F4"; Fixture f; Put(f.reference.data(), 0xb4, B(0)); Put(f.reference.data(), 0x10, Addr(f.surface.data())); StepCase(f, 1, 1); }
    { label = "complex animated follower uses accepted private pose projection"; Fixture f; f.AcceptedCell(false); f.ComplexPose(); StepCase(f, 1, 1); }
    { label = "alternate heading complex row and private lookup"; Fixture f; Put(f.reference.data(), 0x674, B(0)); f.AcceptedCell(true); f.ComplexPose(); StepCase(f, 1, 1); }
    { label = "wrapped 8000 heading requests refresh"; Fixture f; Put(f.owner.data(), node::kNodeOffset + 0x34, uint16_t(Get<uint16_t>(f.owner.data(), node::kNodeOffset + 0x34) + 0x8000)); StepCase(f, 0, 1); }
    { label = "unordered planar difference requests refresh"; Fixture f; Put(f.owner.data(), node::kNodeOffset + 0x20, U(0x7fc00001)); StepCase(f, 0, 1); }
    { label = "arrival event ordering"; Fixture f; Put(f.owner.data(), 0x48, 4.0f); Put(f.owner.data(), 0x50, 8.0f); Put(f.owner.data(), 0x64, Get<uint16_t>(f.owner.data(), node::kNodeOffset + 0x34)); StepCase(f, 1, 2); }
    { label = "actual native attachment and order executed once"; Fixture f; Put(f.owner.data(), 0x48, 4.0f); Put(f.owner.data(), 0x50, 8.0f); Put(f.owner.data(), 0x64, Get<uint16_t>(f.owner.data(), node::kNodeOffset + 0x34)); StepCase(f, 1, 2, true); }
    ThresholdCases(); MismatchCases(); GenericGates(); RouteCases();
    node::Release(); UnseedBanks(); node::projection::Release();
    VirtualFree(boundary.allocation, 0, MEM_RELEASE); VirtualFree(production.allocation, 0, MEM_RELEASE);
    VirtualFree(image, 0, MEM_RELEASE);
    std::printf("native_node_oracle: %u cases, %u checks (request event boundary; sequencer not replaced)\n", cases, checks);
    return 0;
}
int main(int argc, char** argv) {
    __try {
        return RunOracle(argc, argv);
    } __except (ReportException(GetExceptionInformation())) {
        return 1;
    }
}
