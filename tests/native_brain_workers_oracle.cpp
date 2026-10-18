// BRAIN2 Stage 2 oracle: the untouched mapped original loop 0x585D10 against ntw2_brain_workers on synthetic
// populations, with 1/4/8 participants. Whatever mix of committed, refused, invalidated and owner-run occurrences
// a population produces, the final soldier/world/staging bytes and the ordered callback sequence must equal the
// serial reference exactly. Real clones, real originals, real gates: nothing is mocked and no image byte is patched.
// RNG streams: the reference is RunStreamReference (the 585D10 loop with per-ordinal model LCG seeds, built from
// the original steps); with no draws it is anchored to the untouched 585D10 except for the LCG word itself.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "clones/ntw2_clones.h"
#include "native_brain2.h"
#include "native_brain_workers.h"
#include "native_region_table.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace brain = ntw2_brain2;
namespace bw = ntw2_brain_workers;
static_assert(sizeof(void*) == 4, "x86 native ABI");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, checks, cases, ownerThread;
static const char* currentCase = "mapping";
static ntw2_clone_set clones{};
static U bindings[NTW2_BIND_COUNT];
[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fprintf(stderr, "FAIL [%s]: ", currentCase);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::exit(1);
}
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail("%s", what); }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static T Get(const void* p, size_t off) { T v; std::memcpy(&v, static_cast<const B*>(p) + off, sizeof(v)); return v; }
template<class T> static void Put(void* p, size_t off, T v) { std::memcpy(static_cast<B*>(p) + off, &v, sizeof(v)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
struct FpMode { const char* name; unsigned short cw; U csr; };
static const FpMode fpModes[] = {
    {"default 27F/1F80", 0x27f, 0x1f80},
    {"x87 extended + round down", 0x37f, 0x3f80},
    {"x87 truncate + FTZ/DAZ", 0xe7f, 0x9fc0},
};
static void SetFp(const FpMode& mode) {
    unsigned short cw = mode.cw;
    __asm fninit
    __asm fldcw word ptr [cw]
    _mm_setcsr(mode.csr);
}
struct FpState { U csr; unsigned short control, status; };
static FpState CaptureFp() {
    unsigned short control, status;
    __asm fnstcw word ptr [control]
    __asm fnstsw word ptr [status]
    return {_mm_getcsr(), control, status};
}
static void CompareFp(const FpState& e, const char* what) {
    const FpState a = CaptureFp();
    Require(((a.csr ^ e.csr) & 0xffc0u) == 0 && a.control == e.control && (a.status & 0x3800) == (e.status & 0x3800), what);
}
static void UnexpectedBinding() { Fail("unrelated clone binding executed"); }
static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open image read-only");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long n = std::ftell(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image size"); std::rewind(f);
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr; B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "SHA image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(!std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"), "supported image identity");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred image base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
            std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "image relocation");
    std::fill(std::begin(bindings), std::end(bindings), Fn(&UnexpectedBinding));
    brain::Bind(A(image), bindings);
    U detail = 0;
    const U error = ntw2_build_clones(A(image), bindings, &clones, &detail);
    if (error) Fail("clone construction error=%u detail=%u", error, detail);
}

// ---- callbacks observed in native order ----
enum ObservationKind : U { ChargeCallback, AnimationCallback };
struct Observed { U type, entity, receiver, argument; };
static std::vector<Observed>* observations;
static B* callbackTarget;
static void MutateList();
static void MutateWitness();
static void __fastcall Charge(void* receiver, void*, void* entity) {
    Require(GetCurrentThreadId() == ownerThread, "charge executes only on the owner");
    observations->push_back({ChargeCallback, Get<U>(entity, 0x2c), Get<U>(receiver, 4), Get<U>(entity, 0x2c)});
    if (callbackTarget) Put(callbackTarget, 0x1d8, U(5));
    MutateList();
    MutateWitness();
}
static void __fastcall Vcc(void* entity, void*) {
    Require(GetCurrentThreadId() == ownerThread, "animation callback executes only on the owner");
    observations->push_back({AnimationCallback, Get<U>(entity, 0x2c), Get<U>(entity, 0x2c), 0});
}
struct World {
    std::array<B, 0x28100> root{};
    std::array<B, 0x100> model{};
    std::array<B, 0x200> manager{};
    std::array<B, 0x80> state{};
    std::array<B, 0x40> terrain{};
    std::array<B, 0x20> animationOwner{};
    std::array<B, 0x700> animation{};
    std::array<B, 0xc40> warmStats{};
    std::array<B, 0x40> warmClasses{};
    std::array<B, 0xb40> stats{};
    std::array<U, 16> nodeMethods{};
    std::array<U, 2> chargeMethods{};
    std::array<U, 2> charge{};
    std::array<U, 4> stateTable{};
    std::array<B, 0x40> stateEntry{};
    std::array<std::array<U, 4>, 2> effectRecipients{};
    // Army stat table for 649520's army branch: [[A+1F8]+218 + A+374*4 + E4] -> entry, entry+10 consumed by 6544EE.
    std::array<B, 0x220> army{};
    std::array<B, 0x100> armyTable{};
    std::array<B, 0x20> armyStat{};
    // Idle RNG soldiers: A+218 -> [database], database+2C -> capability rows (664B40 reads row+14, all zero).
    std::array<U, 1> databaseRef{};
    std::array<B, 0x40> database{};
    std::array<B, 0x1600> capabilityRows{};
    // A+21C order-animation table read by 817BB0 (6631A0 at 663393): row (old*0x49+new)*0x1C, count at +0x18.
    // All counts zero: 817BB0 returns its default row without drawing.
    std::array<B, 0x26000> orderTable{};
    void Setup() {
        databaseRef[0] = A(database.data()); Put(database.data(), 0x2c, A(capabilityRows.data()));
        Put(root.data(), 8, A(model.data())); Put(root.data(), 0x2804c, A(animationOwner.data()));
        Put(model.data(), 0, A(root.data())); Put(model.data(), 0x58, U(100));
        Put(model.data(), 0x64, A(terrain.data())); Put(model.data(), 0xb0, A(manager.data()));
        Put(manager.data(), 0x198, A(state.data()));
        Put(state.data(), 0x10, A(stateTable.data())); Put(state.data(), 0x24, U(0));
        stateTable[0] = A(stateEntry.data()); Put(stateEntry.data(), 0x10, U(1));
        Put(animationOwner.data(), 0x10, A(animation.data()));
        Put(animation.data(), 0x6c0, A(warmStats.data())); Put(animation.data(), 0x2c0, A(warmClasses.data()));
        for (U i = 0; i + 4 <= stats.size(); i += 4) Put(stats.data(), i, U(4));
        Put(stats.data(), 0x850 + 0x5c, U(0)); Put(stats.data(), 0xa90 + 0x5c, U(100000));
        nodeMethods.fill(A(At(0x444b60))); nodeMethods[0x20 / 4] = A(At(0x462cb0));
        chargeMethods[1] = Fn(&Charge); charge = {A(chargeMethods.data()), 0xc001};
        Put(At(0x176cff8), 0, 1.0f); Put(At(0x176cffc), 0, 0.0f);
    }
};
struct Spec {
    U order, posture, expectedState;
    U frame = 0, rowCount = 0, slotAnimation = 0x20;
    B gate = 1, start = 0, end = 0;
    bool charge = false;
};
struct Fixture {
    std::array<B, 0x800> agent{};
    std::array<B, 0x40> timer{};
    std::array<U, 3> slot{};
    std::array<B, 0x60> animation{};
    std::array<B, 0x40> slotHeader{};
    std::array<B, 28 * 4> rows{};
    void Init(World& w, const Spec& s, U id) {
        Put(agent.data(), 0, A(At(0x1333714)));
        Put(agent.data(), 0x28, A(w.root.data())); Put(agent.data(), 0x2c, id);
        Put(agent.data(), 0x30, B(1)); Put(agent.data(), 0x34, U(0x401)); Put(agent.data(), 0x38, U(0x800));
        Put(agent.data(), 0x6c, 1.0f); Put(agent.data(), 0xec, B(1));
        Put(agent.data(), 0x118, s.gate); Put(agent.data(), 0x114, s.start); Put(agent.data(), 0x115, s.end);
        Put(agent.data(), 0x18c, B(1)); Put(agent.data(), 0x19c, U(25)); Put(agent.data(), 0x1a4, 0.75f);
        Put(agent.data(), 0x1b8, U(1)); Put(agent.data(), 0x1bc, U(0x20)); Put(agent.data(), 0x1c0, s.frame);
        Put(agent.data(), 0x1d8, s.order); Put(agent.data(), 0x1e4, 1.25f); Put(agent.data(), 0x220, s.posture);
        Put(agent.data(), 0x228, A(agent.data()));
        Put(agent.data(), 0x228 + 0xa0, A(w.root.data()));
        Put(agent.data(), 0x22c, A(w.nodeMethods.data()));
        Put(agent.data(), 0x514, A(w.stats.data())); Put(agent.data(), 0x518, A(timer.data()));
        Put(agent.data(), 0x619, B(1)); Put(agent.data(), 0x5ab, B(0)); Put(agent.data(), 0x364, B(1));
        Put(agent.data(), 0xd4, 0.5f); Put(agent.data(), 0xd8, -0.25f); Put(agent.data(), 0xdc, 0.75f);
        Put(agent.data(), 0xe0, uint16_t(17)); Put(agent.data(), 0x448, 0.625f);
        Put(timer.data(), 0, A(At(0x132b308))); Put(timer.data(), 4, A(w.root.data()));
        Put(timer.data(), 0x14, 0.25f); Put(timer.data(), 0x1c, 0.125f);
        if (s.rowCount) {
            slot = {s.slotAnimation, A(animation.data()), A(slotHeader.data())};
            Put(animation.data(), 0x50, s.rowCount); Put(slotHeader.data(), 0x14, uint16_t(123));
            Put(slotHeader.data(), 0x38, A(rows.data()));
            for (U row = 0; row < 4; ++row) {
                Put(rows.data(), 28 * row + 0xc, uint16_t(511 + row * 127));
                Put(rows.data(), 28 * row + 0x10, 0.125f * (row + 1));
                Put(rows.data(), 28 * row + 0x14, -0.0625f * (row + 1));
                Put(rows.data(), 28 * row + 0x18, 0.25f * (row + 1));
            }
            Put(agent.data(), 0x444, A(slot.data())); Put(agent.data(), 0x1b8, U(0x1d));
        }
        if (s.charge) {
            Put(agent.data(), 0x4e8, A(w.charge.data())); Put(agent.data(), 0x4ec, 100000.0f);
            Put(agent.data(), 0x1c8, -1.0f);
        }
    }
};
static const Spec kSpecs[] = {
    {4,0,9}, {4,1,0xc}, {0,0,8}, {5,0,0xa}, {4,3,0xb},
    {4,0,1,0,0,0x20,0}, {5,0,2,0,0,0x20,0}, {0x17,0,0x23},
    {4,0,0x17,2,0,0x20,1,1}, {4,0,0x18,2,0,0x20,1,0,1},
    {4,0,0x1d,0,3}, {4,0,0x1d,1,3}, {4,0,0x1d,2,3},
    {4,0,0x1d,0,3,0x5d}, {4,1,0xc,0,0,0x20,1,0,0,true},
    {5,0,0x1d,0,2,0x5e,1,0,0,true}
};
constexpr U kSpecCount = sizeof(kSpecs) / sizeof(kSpecs[0]);

// ---- population + native worklist manager ----
constexpr U kMaxSoldiers = 256;
struct Population {
    std::vector<Fixture> soldiers;
    std::array<B, 0x268> manager{};
    std::array<U, kMaxSoldiers + 16> list{};
    U count = 0;
    Population() : soldiers(kMaxSoldiers) {}
};
static World world;
static Population pop;
// Soldiers whose [vt+0xC] is not a brain step (unsupported class: the owner runs the original) and one whose
// footprint copy would run off the end of a mapped page (lifetime refusal before any clone executes).
constexpr U kAliens = 4;
struct Alien { std::array<B, 0x800> bytes{}; std::array<U, 4> methods{}; };
static Alien aliens[kAliens];
static B* pageEdge;
static void __fastcall AlienStep(void* entity, void*) {
    Require(GetCurrentThreadId() == ownerThread, "alien step executes only on the owner");
    observations->push_back({2, Get<U>(entity, 0x2c), A(entity), 0});
}
static U g_mutate, g_mutateAt;
static bool g_mutateFired;
// Crew writer (live guard-miss blocks +6B0/+6C0): an owner-run soldier Y whose inline node at Y+22C has vtable
// 0x133AE34 steps 6F46A0, which writes the crew soldier S = [Y+28C] at +6AC..+6EC once (one-shot byte Y+2A4).
// The fixture is a non-brain class (workers refuse it, the owner runs it) whose step performs that one-shot write,
// so the runtime's crew rule sees the exact native layout it keys on.
constexpr U kCrewIndex = 3000;
static Alien crewAlien;
static void __fastcall CrewStep(void* entity, void*) {
    Require(GetCurrentThreadId() == ownerThread, "crew step executes only on the owner");
    observations->push_back({3, Get<U>(entity, 0x2c), A(entity), 0});
    void* const crew = reinterpret_cast<void*>(Get<U>(entity, 0x28c));
    if (crew && Get<B>(entity, 0x2a4) == 0) {
        Put(crew, 0x6b0, Get<U>(crew, 0x6b0) + 0x101u);
        Put(entity, 0x2a4, B(1));
    }
}
static void MutateList() {
    if (!g_mutate || g_mutateFired) return;
    g_mutateFired = true;
    if (g_mutate == 1) Put(pop.manager.data(), 0x260, Get<U>(pop.manager.data(), 0x260) - 3);
    else pop.list[g_mutateAt] = A(pop.soldiers[3].agent.data());
}
struct Shape {
    const char* name; std::vector<U> order; bool fire, duplicates; U chargeTarget;
    U mutate = 0, mutateAt = 0; bool sharedTimer = false;
    // Every soldier is army-witnessed; the first charge callback changes the consumed army entry+10.
    bool armyWitness = false;
    // RNG soldiers: an idle node (61D910) on soldier i with i % 4 != 3, whose 66DD10 step draws the model LCG at
    // 66DE62/66DF04/66E002 (and 80E020 at 66E023, which workers refuse). `seed` is the model+0x50 start word.
    bool idle = false; U seed = 0;
    // Crew writer fixture (kCrewIndex in `order`) whose one-shot step writes soldier `crewTarget` at +6B0.
    bool crew = false; U crewTarget = 0;
};
static void MakeIdle(Fixture& f, U i) {
    B* const a = f.agent.data();
    static const U orders[3] = {0x10, 0x49, 0x49};
    static const B latches[3] = {1, 1, 0};
    const U descriptor[2] = {0x13572468, orders[i % 4]};
    reinterpret_cast<U (__thiscall*)(U, U, U)>(At(0x61d910))(A(a + 0x22c), A(a + 0x228), A(descriptor));
    Put(a + 0x22c, 0x24, latches[i % 4]);
    // Already begun (node+10): the move driver 658F66 skips vt+4 (begin -> 6669B0 stop) and steps vt+8 (66DD10).
    Put(a + 0x22c, 0x10, B(1));
    // Empty weighted distribution (80E020 returns 0x360 after its draw), no foreign slot, capability database.
    Put(a, 0x444, U(0)); Put(a, 0x45c, A(world.root.data())); Put(a, 0x468, U(0));
    Put(a, 0x218, A(world.databaseRef.data())); Put(a, 0x21c, A(world.orderTable.data()));
}
static bool g_armyWitness, g_witnessFired;
static void MutateWitness() {
    if (!g_armyWitness || g_witnessFired) return;
    g_witnessFired = true;
    Put(world.armyStat.data(), 0x10, 2.5f);
}
constexpr U kAlienBase = 1000;
static void SetupAliens() {
    for (U i = 0; i < kAliens; ++i) {
        aliens[i] = Alien{};
        aliens[i].methods[3] = Fn(&AlienStep);
        Put(aliens[i].bytes.data(), 0, A(aliens[i].methods.data()));
        Put(aliens[i].bytes.data(), 0x2c, U(900 + i)); Put(aliens[i].bytes.data(), 0x30, B(1));
    }
    if (!pageEdge) {
        pageEdge = static_cast<B*>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(pageEdge != nullptr, "page-edge allocation");
        DWORD old; Require(VirtualProtect(pageEdge + 0x1000, 0x1000, PAGE_NOACCESS, &old) != 0, "guard page");
    }
    // Only +0x00..+0x3F readable: vtable and activation byte. The 0x700 worker footprint and the Stage-1 witness
    // unit pointer +0x1F0 lie in the NOACCESS page; both must be refused/skipped by region proof, never by a fault.
    B* object = pageEdge + 0x1000 - 0x40;
    std::memset(object, 0, 0x40);
    static std::array<U, 4> edgeMethods;
    edgeMethods = {0, 0, 0, Fn(&AlienStep)};
    Put(object, 0, A(edgeMethods.data())); Put(object, 0x2c, U(950)); Put(object, 0x30, B(1));
}
// Fire-sequencer states and the request-release latch layered over the base specs (state 3 releases a request).
static void Build(const Shape& shape) {
    world = World{}; world.Setup();
    SetupAliens();
    U id = 100;
    for (U i = 0; i < kMaxSoldiers; ++i) pop.soldiers[i] = Fixture{};
    for (U i = 0; i < kMaxSoldiers; ++i) {
        const Spec& spec = kSpecs[i % kSpecCount];
        pop.soldiers[i].Init(world, spec, ++id);
        if (shape.fire) {
            static const U states[] = {0, 6, 7, 3};
            Put(pop.soldiers[i].agent.data(), 0x390, states[(i / kSpecCount) % 4]);
            if ((i / kSpecCount) % 4 == 3) Put(pop.soldiers[i].agent.data(), 0x3a4, B(1));
        }
        // Pairs share one timer object: the later soldier's private copy goes stale once the earlier one publishes.
        if (shape.sharedTimer && (i & 1)) Put(pop.soldiers[i].agent.data(), 0x518, A(pop.soldiers[i - 1].timer.data()));
        if (shape.armyWitness) {
            Put(pop.soldiers[i].agent.data(), 0x1f8, A(world.army.data()));
            Put(pop.soldiers[i].agent.data(), 0x374, U(2));
        }
        if (shape.idle && i % 4 != 3) MakeIdle(pop.soldiers[i], i);
    }
    Put(world.model.data(), 0x50, shape.seed);
    crewAlien = Alien{};
    crewAlien.methods[3] = Fn(&CrewStep);
    Put(crewAlien.bytes.data(), 0, A(crewAlien.methods.data()));
    Put(crewAlien.bytes.data(), 0x2c, U(990)); Put(crewAlien.bytes.data(), 0x30, B(1));
    if (shape.crew) {
        Put(crewAlien.bytes.data(), 0x22c, A(At(0x133ae34)));
        Put(crewAlien.bytes.data(), 0x28c, A(pop.soldiers[shape.crewTarget].agent.data()));
    }
    pop.count = 0;
    for (U index : shape.order) {
        if (index == kCrewIndex) pop.list[pop.count++] = A(crewAlien.bytes.data());
        else if (index >= kAlienBase + kAliens) pop.list[pop.count++] = A(pageEdge + 0x1000 - 0x40);
        else if (index >= kAlienBase) pop.list[pop.count++] = A(aliens[index - kAlienBase].bytes.data());
        else pop.list[pop.count++] = A(pop.soldiers[index].agent.data());
    }
    if (shape.duplicates && pop.count > 8) pop.list[pop.count - 3] = pop.list[1];
    pop.list[pop.count] = 0;
    std::memset(pop.manager.data(), 0, pop.manager.size());
    Put(pop.manager.data(), 0x264, A(pop.list.data())); Put(pop.manager.data(), 0x260, pop.count);
    g_mutate = shape.mutate; g_mutateAt = shape.mutateAt; g_mutateFired = false;
    g_armyWitness = shape.armyWitness; g_witnessFired = false;
    if (shape.armyWitness) {
        Put(world.army.data(), 0x218, A(world.armyTable.data()));
        Put(world.armyTable.data(), 0xe4 + 2 * 4, A(world.armyStat.data()));
        Put(world.armyStat.data(), 0x10, 1.25f);
    }
}
static void Build(const std::vector<U>& order, bool fire, bool duplicates) {
    Build(Shape{"population", order, fire, duplicates, ~0u});
}
static std::vector<U> Sequential(U n) { std::vector<U> v(n); for (U i = 0; i < n; ++i) v[i] = i; return v; }

struct Snapshot {
    std::vector<Fixture> soldiers;
    World world;
    std::array<B, 0x70> staging;
    std::array<B, 0x14> gather;
    std::array<U, kMaxSoldiers + 16> list;
    std::array<B, 0x268> manager;
    Alien crew;
};
static void Take(Snapshot& s) {
    s.soldiers = pop.soldiers; s.world = world; s.list = pop.list; s.manager = pop.manager; s.crew = crewAlien;
    std::memcpy(s.staging.data(), At(0x14ded30), s.staging.size());
    std::memcpy(s.gather.data(), At(0x14514c0), s.gather.size());
}
static void Restore(const Snapshot& s) {
    pop.soldiers = s.soldiers; world = s.world; pop.list = s.list; pop.manager = s.manager; crewAlien = s.crew;
    std::memcpy(At(0x14ded30), s.staging.data(), s.staging.size());
    std::memcpy(At(0x14514c0), s.gather.data(), s.gather.size());
}
static void CompareBytes(const void* expected, const void* actual, size_t size, const char* what) {
    const B* e = static_cast<const B*>(expected);
    const B* a = static_cast<const B*>(actual);
    ++checks;
    for (size_t i = 0; i < size; ++i)
        if (e[i] != a[i]) Fail("%s +%zX original=%02X workers=%02X", what, i, e[i], a[i]);
    checks += size / 64;
}
static void CompareSnapshots(const Snapshot& e, const Snapshot& a) {
    for (U i = 0; i < kMaxSoldiers; ++i) {
        currentCase = "soldier bytes";
        char label[64]; std::snprintf(label, sizeof label, "soldier %u complete footprint and nested objects", i);
        CompareBytes(&e.soldiers[i], &a.soldiers[i], sizeof(Fixture), label);
    }
    CompareBytes(&e.world, &a.world, sizeof(World), "shared world and RNG");
    CompareBytes(e.staging.data(), a.staging.data(), e.staging.size(), "shared effect staging");
    CompareBytes(e.gather.data(), a.gather.data(), e.gather.size(), "shared wrapper gather publication");
    CompareBytes(e.list.data(), a.list.data(), sizeof(e.list), "worklist data after native mutation");
    CompareBytes(e.manager.data(), a.manager.data(), e.manager.size(), "worklist count after native mutation");
    CompareBytes(e.crew.bytes.data(), a.crew.bytes.data(), e.crew.bytes.size(), "crew writer fixture");
}
static void CompareObservations(const std::vector<Observed>& e, const std::vector<Observed>& a) {
    Require(e.size() == a.size(), "same ordered callback count");
    for (size_t i = 0; i < e.size(); ++i) CompareBytes(&e[i], &a[i], sizeof(Observed), "callback identity/order/arguments");
}
static LONG ReportFault(EXCEPTION_POINTERS* info, const char* what) {
    const EXCEPTION_RECORD* r = info->ExceptionRecord;
    std::fprintf(stderr, "FAULT [%s] code=%08lX eip=%08X (image VA %08X) access=%08X case=%s\n", what, r->ExceptionCode,
        A(r->ExceptionAddress), A(r->ExceptionAddress) - delta, r->NumberParameters >= 2 ? static_cast<U>(r->ExceptionInformation[1]) : 0, currentCase);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
static void RunOriginal() {
    __try { reinterpret_cast<void (__thiscall*)(void*)>(At(0x585d10))(pop.manager.data()); }
    __except (ReportFault(GetExceptionInformation(), "original worklist")) { std::exit(3); }
}
static void CallStep(U step, void* entity) {
    __try { reinterpret_cast<void (__thiscall*)(void*)>(step)(entity); }
    __except (ReportFault(GetExceptionInformation(), "stream reference step")) { std::exit(3); }
}
// The RNG stream contract executed with the ORIGINAL per-soldier steps: the 585D10 loop (live cursor, ==1
// filter, end reloaded after every entry) where walk ordinal k's model LCG word is seeded with
// StreamSeed(S, generation, k) before its step, and the word ends at LcgAdvance(S, walked). Independent of
// ntw2_brain_workers except for the two pure contract functions.
struct RefStats { U occurrences, draws, unmatched; };
static RefStats RunStreamReference(U generation) {
    RefStats r{};
    B* const word = world.model.data() + 0x50;
    const U s = Get<U>(word, 0);
    U cursor = Get<U>(pop.manager.data(), 0x264);
    const U origin = cursor;
    U end = cursor + 4 * Get<U>(pop.manager.data(), 0x260);
    while (cursor != end) {
        void* const entity = reinterpret_cast<void*>(*reinterpret_cast<const U*>(cursor));
        if (Get<B>(entity, 0x30) == 1) {
            const U seed = bw::StreamSeed(s, generation, (cursor - origin) >> 2);
            Put(word, 0, seed);
            CallStep(Get<U>(reinterpret_cast<void*>(Get<U>(entity, 0)), 0xc), entity);
            U x = seed, n = 0;
            while (x != Get<U>(word, 0) && n <= bw::kOwnerDrawScan) { x = x * 0x343fdu + 0x269ec3u; ++n; }
            if (n > bw::kOwnerDrawScan) ++r.unmatched; else r.draws += n;
            ++r.occurrences;
        }
        cursor += 4;
        end = Get<U>(pop.manager.data(), 0x264) + 4 * Get<U>(pop.manager.data(), 0x260);
    }
    Put(word, 0, bw::LcgAdvance(s, r.occurrences));
    return r;
}

// ---- test dispatcher: the caller plus (participants-1) threads claim chunks atomically ----
struct DispatchJob { U fn; void* context; volatile LONG next; U chunks; };
static DWORD WINAPI DispatchThread(void* p) {
    DispatchJob& job = *static_cast<DispatchJob*>(p);
    for (;;) {
        const U i = static_cast<U>(_InterlockedIncrement(&job.next)) - 1;
        if (i >= job.chunks) break;
        reinterpret_cast<void (__fastcall*)(void*, U)>(job.fn)(job.context, i);
    }
    return 0;
}
static U g_threads = 1;
static void __stdcall TestDispatch(U, U fn, U chunks, void* context) {
    DispatchJob job = {fn, context, 0, chunks};
    HANDLE threads[16]; U n = 0;
    for (; n + 1 < g_threads && n < 15; ++n) {
        threads[n] = CreateThread(nullptr, 0, &DispatchThread, &job, 0, nullptr);
        Require(threads[n] != nullptr, "dispatch thread created");
    }
    DispatchThread(&job);
    if (n) WaitForMultipleObjects(n, threads, TRUE, INFINITE);
    for (U i = 0; i < n; ++i) CloseHandle(threads[i]);
}

using Words = std::array<U, bw::kWords>;
using PhaseWords = std::array<U, bw::kPhaseWords>;
static Words WorkerWords() { Words w{}; bw::Snapshot(w.data()); return w; }
static PhaseWords WorkerPhases() { PhaseWords p{}; bw::PhaseSnapshot(p.data()); return p; }
// --brain-quiet configuration of the next StartWorkers (the quiet sections also configure ntw2_brain2 without census).
static bool g_quiet;
static void StartWorkers(U participants, U deferMask = 0, U minEntities = 1) {
    g_threads = participants;
    bw::Binding b = {};
    b.image_base = A(image); b.clones = &clones; b.bindings = bindings;
    b.dispatch = participants > 1 ? &TestDispatch : nullptr; b.pool = 0; b.workers = participants - 1;
    b.min_entities = minEntities; b.defer_events = deferMask; b.quiet = g_quiet;
    Require(bw::Start(b), "worker family and participants built");
    bw::Reset();
}
// First-chance access violations on ANY thread while the worker path runs. The runtime's crash recorder is a
// first-chance vectored handler, so a handled read fault is still a recorded crash: the count must stay zero.
static volatile LONG g_firstChanceAv;
static U g_avEip, g_avAddress;
static LONG CALLBACK CountAccessViolations(EXCEPTION_POINTERS* info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && _InterlockedIncrement(&g_firstChanceAv) == 1) {
        g_avEip = A(info->ExceptionRecord->ExceptionAddress);
        g_avAddress = static_cast<U>(info->ExceptionRecord->ExceptionInformation[1]);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static bool RunWorkers() {
    void* handler = AddVectoredExceptionHandler(1, &CountAccessViolations);
    Require(handler != nullptr, "vectored first-chance counter installed");
    g_firstChanceAv = 0;
    bool handled = false;
    __try {
        handled = bw::RunWorklist(A(pop.manager.data()), clones.entries);
        if (!handled) brain::RunWorklist(A(pop.manager.data()), clones.entries);
    } __except (ReportFault(GetExceptionInformation(), "worker worklist")) { std::exit(3); }
    RemoveVectoredExceptionHandler(handler);
    return handled;
}
static void CheckInvariants(const Words& w, U occurrencesExpected) {
    if (occurrencesExpected != ~0u) Require(w[bw::Occurrences] == occurrencesExpected, "every ==1 worklist entry is exactly one occurrence");
    // Every walked ==1 ordinal is exactly one of: a speculated slot, a late activation, an unprocessed slot, a desync.
    Require(w[bw::Occurrences] == w[bw::Speculated] - w[bw::SpeculatedUnwalked] + w[bw::LateActivations] +
        w[bw::Unprocessed] + w[bw::Desyncs], "occurrence accounting identity (speculated - unwalked + late + unprocessed + desync)");
    Require(w[bw::Committed] + w[bw::OwnerRan] == w[bw::Occurrences], "committed + owner-run partition the occurrences");
    Require(w[bw::WorkerComputed] + w[bw::WorkerRefused] == w[bw::Speculated], "speculation partitions into computed and refused");
    Require(w[bw::Committed] <= w[bw::WorkerComputed], "only computed occurrences can commit");
    Require(w[bw::Dispatches] == 1 && w[bw::Handoffs] == 0, "one dispatch per stage, no handoff");
    U reasons = 0;
    for (U r = 0; r < bw::kReasonCount; ++r) reasons += w[bw::ReasonCounts + r];
    Require(reasons >= w[bw::WorkerRefused], "every refusal has a reason");
    U replayed = 0, recorded = 0;
    for (U k = 0; k < bw::kEventKinds; ++k) { replayed += w[bw::EventsReplayed + k]; recorded += w[bw::EventsRecorded + k]; }
    Require(replayed <= recorded, "replayed events were recorded");
}

static std::vector<Shape> Shapes() {
    std::vector<Shape> shapes;
    shapes.push_back({"every spec once", Sequential(kSpecCount), false, false, ~0u});
    shapes.push_back({"repeated mixed population", Sequential(192), false, false, ~0u});
    shapes.push_back({"fire sequencer states", Sequential(256), true, false, ~0u});
    shapes.push_back({"duplicate worklist entries", Sequential(96), false, true, ~0u});
    // Charging soldier 14 rewrites the order of soldier 15 after its worker already computed it.
    shapes.push_back({"cross-soldier callback invalidation", {14, 15, 0, 1, 2, 3, 14, 15}, false, false, 15});
    std::vector<U> reversed = Sequential(160); std::reverse(reversed.begin(), reversed.end());
    shapes.push_back({"reverse worklist order", reversed, true, false, ~0u});
    // The native loop reloads count and data after every occurrence; a callback mid-list changes both.
    shapes.push_back({"worklist shrinks mid-stage", Sequential(48), false, false, ~0u, 1});
    shapes.push_back({"worklist entry replaced mid-stage", Sequential(48), false, false, ~0u, 2, 20});
    shapes.push_back({"soldiers sharing one timer object", Sequential(64), false, false, ~0u, 0, 0, true});
    // Owner-run charging soldiers (14, 15) change the army stat every worker computed against.
    shapes.push_back({"witnessed army stat changed mid-stage", {0, 1, 14, 2, 3, 4, 5, 15, 6, 7, 8, 9}, false, false, ~0u,
        0, 0, false, true});
    std::vector<U> mixed = Sequential(40);
    mixed.insert(mixed.begin() + 5, kAlienBase); mixed.insert(mixed.begin() + 11, kAlienBase + 1);
    mixed.insert(mixed.begin() + 20, kAlienBase + kAliens); mixed.push_back(kAlienBase + 2);
    shapes.push_back({"unsupported class and unreadable footprint", mixed, false, false, ~0u});
    // An owner-run crew-node step (vtable 0x133AE34 at +22C) writes soldier 20 at +6B0 before its ordinal.
    std::vector<U> crewed = Sequential(48);
    crewed.insert(crewed.begin() + 4, kCrewIndex);
    Shape crew{"crew writer changes a later soldier", crewed, false, false, ~0u};
    crew.crew = true; crew.crewTarget = 20;
    shapes.push_back(crew);
    return shapes;
}
struct Totals { U occurrences, committed, ownerRan, guard, refused, draws, workerDraws, ownerDraws; };
// The stream reference with NO draws must be the untouched native loop except for the model LCG word itself:
// this anchors RunStreamReference (and so every worker comparison) to 585D10.
static void AnchorToVanilla(const Snapshot& vanilla, const Snapshot& reference,
                            const std::vector<Observed>& vanillaEvents, const std::vector<Observed>& referenceEvents) {
    static Snapshot patched;
    patched = reference;
    std::memcpy(patched.world.model.data() + 0x50, vanilla.world.model.data() + 0x50, 4);
    CompareSnapshots(vanilla, patched);
    CompareObservations(vanillaEvents, referenceEvents);
}
// Oracle refusal pattern (FaultInjector mode 2): ordinal % every == phase is refused after a full worker run.
static U g_refuseEvery, g_refusePhase;
static U RefuseInjector(U, U ordinal) { return g_refuseEvery && ordinal % g_refuseEvery == g_refusePhase ? 2u : 0u; }
static Totals EquivalenceCase(const Shape& shape, U participants, const FpMode& fp, U deferMask,
                              U refuseEvery = 0, U refusePhase = 0) {
    currentCase = shape.name;
    Build(shape);
    callbackTarget = shape.chargeTarget == ~0u ? nullptr : pop.soldiers[shape.chargeTarget].agent.data();
    static Snapshot before, vanilla, expected, actual;
    Take(before);
    std::vector<Observed> vanillaEvents, expectedEvents, actualEvents;
    U activations = 0;
    for (U i = 0; i < pop.count; ++i) activations += Get<B>(reinterpret_cast<void*>(pop.list[i]), 0x30) == 1;
    observations = &vanillaEvents; SetFp(fp); RunOriginal();
    const FpState expectedFp = CaptureFp();
    Take(vanilla);
    // Without event deferral the worker path binds the model LCG (generation 1 after Start/Reset): the expected
    // result is the stream reference. A deferring configuration keeps 5FC070 refused: the expected result is vanilla.
    const bool streams = deferMask == 0;
    RefStats ref{};
    if (streams) {
        Restore(before); g_mutateFired = false; g_witnessFired = false;
        observations = &expectedEvents; SetFp(fp); ref = RunStreamReference(1);
        CompareFp(expectedFp, "stream reference leaves the FP environment as the native loop does");
        Take(expected);
        if (!ref.draws) AnchorToVanilla(vanilla, expected, vanillaEvents, expectedEvents);
        currentCase = shape.name;
    } else { expected = vanilla; expectedEvents = vanillaEvents; }
    Restore(before); g_mutateFired = false; g_witnessFired = false;
    StartWorkers(participants, deferMask);
    g_refuseEvery = refuseEvery; g_refusePhase = refusePhase;
    if (refuseEvery) bw::SetFaultInjector(&RefuseInjector);
    observations = &actualEvents; SetFp(fp);
    U brainBefore[brain::kWords], brainAfter[brain::kWords];
    brain::Snapshot(brainBefore);
    const bool handled = RunWorkers();
    brain::Snapshot(brainAfter);
    bw::SetFaultInjector(nullptr); g_refuseEvery = 0;
    Require(handled, "worker path handles the stage");
    if (g_firstChanceAv) {
        const B* runtime = reinterpret_cast<const B*>(&bw::RunWorklist);
        Fail("%ld first-chance access violation(s); first eip=%08X (image VA %08X, worker module offset %d) address=%08X",
            g_firstChanceAv, g_avEip, g_avEip - delta, static_cast<int>(g_avEip - A(runtime)), g_avAddress);
    }
    CompareFp(expectedFp, "owner MXCSR control, x87 control word and stack depth preserved");
    Take(actual);
    CompareSnapshots(expected, actual);
    CompareObservations(expectedEvents, actualEvents);
    const Words w = WorkerWords();
    CheckInvariants(w, shape.mutate ? ~0u : activations);
    if (shape.sharedTimer) Require(w[bw::GuardMisses] > 0, "a stale shared-timer copy fails its guard");
    // Guard-miss attribution (version 3): every miss has exactly one class; a duplicated entity's second ordinal
    // was changed by its own first step, so a soldier miss on it is attributed as a duplicate.
    Require(w[bw::GuardMisses] == w[bw::GuardMissUnreadable] + w[bw::GuardMissTimer] + w[bw::GuardMissSoldier] &&
            w[bw::GuardMissDuplicate] <= w[bw::GuardMissSoldier] && w[bw::GuardMissUnlocated] <= w[bw::GuardMissSoldier],
            "guard misses partition into unreadable / timer / soldier");
    if (shape.sharedTimer) Require(w[bw::GuardMissTimer] > 0, "a shared timer object is attributed as a timer miss");
    if (g_quiet) {
        // Quiet: misses are counted without block checksums or duplicate scans.
        U topSum = 0;
        for (U t = 0; t < 2 * bw::kGuardTop; ++t) topSum += w[bw::GuardMissTop + t];
        Require(!w[bw::GuardMissUnlocated] && !w[bw::GuardMissDuplicate] && !w[bw::GuardMissLastOffset] &&
                !w[bw::GuardMissLastBlocks] && !topSum, "quiet mode takes no guard-miss block attribution");
        // Owner-run occurrences execute the ORIGINAL step: ntw2_brain2 is configured without census.
        Require(brainAfter[brain::CloneOccurrences] == brainBefore[brain::CloneOccurrences] &&
                brainAfter[brain::OriginalOccurrences] - brainBefore[brain::OriginalOccurrences] == w[bw::OwnerRan],
                "quiet owner-run occurrences run the original step, never the gated census clone");
    } else {
        if (w[bw::GuardMissSoldier] > w[bw::GuardMissUnlocated]) {
            U topSum = 0;
            for (U t = 0; t < bw::kGuardTop; ++t) topSum += w[bw::GuardMissTop + 2 * t + 1];
            Require(topSum > 0 && w[bw::GuardMissLastEntity] != 0 && w[bw::GuardMissTop] < bw::kReceiverBytes &&
                    w[bw::GuardMissTop] % 16 == 0, "a located soldier miss names a 16-byte block offset");
        }
        if (shape.duplicates && w[bw::GuardMissSoldier])
            Require(w[bw::GuardMissDuplicate] > 0, "duplicated worklist entities are attributed as duplicates");
    }
    // Phase row: one stage, consistent counts, the stage's own last_* words.
    const PhaseWords ph = WorkerPhases();
    Require(ph[bw::PhaseVersion] == bw::kPhaseVersion && ph[bw::PhaseQuiet] == (g_quiet ? 1u : 0u) && ph[bw::PhaseStages] == 1 &&
            ph[bw::PhaseLastOccurrences] == w[bw::Occurrences] && ph[bw::PhaseCommitAttempts] >= w[bw::Committed] &&
            ph[bw::PhaseCommitAttempts] + ph[bw::PhaseCrewRefusals] <= w[bw::WorkerComputed] &&
            ph[bw::PhaseMissPrevTarget] + ph[bw::PhaseMissPrevReference] + ph[bw::PhaseMissPrevFollower] +
            ph[bw::PhaseMissPrevOther] <= w[bw::GuardMissSoldier] && ph[bw::PhaseCaptureUs] == w[bw::CaptureUs] &&
            ph[bw::PhaseDispatchUs] == w[bw::DispatchUs] && ph[bw::PhaseLastTotalUs] >= ph[bw::PhaseCaptureUs],
            "phase row accounts one stage consistently with the summary words");
    if (shape.crew) {
        Require(ph[bw::PhaseCrewMarks] > 0, "the owner-run crew writer marks its crew soldier");
        if (g_quiet) Require(ph[bw::PhaseCrewRefusals] > 0 && !ph[bw::PhaseCrewMarkedMisses] && !ph[bw::PhaseCrewMarkedCommits],
                             "quiet: the marked crew soldier goes to the owner without validation");
        else Require(!ph[bw::PhaseCrewRefusals] && ph[bw::PhaseCrewMarkedMisses] > 0 && w[bw::GuardMissTop] == 0x6b0,
                     "census: the marked crew soldier is validated, misses, and locates block +6B0");
    }
    if (shape.armyWitness) {
        if (participants == 4 && fp.cw == fpModes[0].cw)
            std::printf("army witness shape: committed=%u owner_ran=%u witness_dep_misses=%u witness_end_changes=%u\n",
                w[bw::Committed], w[bw::OwnerRan], w[bw::WitnessDepMisses], w[bw::WitnessViolations]);
        Require(w[bw::WitnessViolations] > 0, "the consumed army entry changed during the stage");
        Require(w[bw::WitnessDepMisses] > 0, "workers that consumed the old army entry are sent to the owner");
        Require(!w[bw::Sticky], "a consumed-value change is handled per soldier, not by disabling workers");
    }
    if (shape.mutate == 2) Require(w[bw::Desyncs] > 0, "a replaced worklist entry is detected as a desync");
    if (shape.order.size() > 40 && shape.order[5] == kAlienBase)
        Require(w[bw::ReasonCounts + bw::ReasonClass] > 0 && w[bw::ReasonCounts + bw::ReasonFootprint] > 0 &&
            w[bw::ReasonCounts + bw::ReasonLifetime] == 0 && w[bw::RegionQueries] > 0,
            "unsupported class and page-edge footprint are refused by region proof before any byte is touched");
    if (shape.mutate == 1) Require(w[bw::SpeculatedUnwalked] > 0 && w[bw::Speculated] > w[bw::Occurrences],
        "a shrinking list leaves speculated-but-unwalked slots, which explains speculated > occurrences");
    Require(!w[bw::Faults] && !w[bw::Sticky] && (shape.armyWitness || !w[bw::WitnessViolations]),
        "no fault, sticky disable or witness violation");
    if (streams) {
        Require(!ref.unmatched && !w[bw::RngOwnerUnmatched], "every owner-run draw sequence is reachable from its ordinal seed");
        Require(w[bw::RngLcgAdvance] == ref.occurrences, "stage-end advance is one LCG step per walked occurrence");
        Require(w[bw::RngWorkerDraws] + w[bw::RngOwnerDraws] == ref.draws,
            "each reference draw is exactly one committed stream draw or one owner draw");
    } else Require(!w[bw::RngWorkerDraws] && !w[bw::RngOwnerDraws] && !w[bw::RngLcgAdvance], "deferral leaves the stream unbound");
    if (refuseEvery) Require(w[bw::ReasonCounts + bw::ReasonInjected] > 0, "injected refusals sent ordinals to the owner");
    Totals t = {w[bw::Occurrences], w[bw::Committed], w[bw::OwnerRan], w[bw::GuardMisses], w[bw::WorkerRefused],
        ref.draws, w[bw::RngWorkerDraws], w[bw::RngOwnerDraws]};
    bw::Stop();
    SetFp(fpModes[0]);
    ++cases;
    return t;
}
static void Equivalence() {
    const std::vector<Shape> shapes = Shapes();
    Totals grand = {};
    for (const Shape& shape : shapes) for (U participants : {1u, 4u, 8u}) for (const FpMode& fp : fpModes) {
        const Totals t = EquivalenceCase(shape, participants, fp, 0);
        grand.occurrences += t.occurrences; grand.committed += t.committed; grand.ownerRan += t.ownerRan;
        grand.guard += t.guard; grand.refused += t.refused;
        grand.draws += t.draws; grand.workerDraws += t.workerDraws; grand.ownerDraws += t.ownerDraws;
    }
    std::printf("equivalence: %u occurrences, %u committed by workers (%.2f%%), %u owner-run, %u worker refusals, %u guard misses, "
        "%u RNG draws (%u worker stream, %u owner)\n",
        grand.occurrences, grand.committed, grand.occurrences ? 100.0 * grand.committed / grand.occurrences : 0.0,
        grand.ownerRan, grand.refused, grand.guard, grand.draws, grand.workerDraws, grand.ownerDraws);
}
static void ReasonReport() {
    currentCase = "reason histogram";
    Build(Sequential(192), true, false);
    callbackTarget = nullptr;
    static Snapshot before; Take(before);
    std::vector<Observed> sink; observations = &sink; SetFp(fpModes[0]); RunOriginal(); Restore(before);
    StartWorkers(4);
    RunWorkers();
    const Words w = WorkerWords();
    std::printf("refusal reasons (192 soldiers, fire states, 4 participants):");
    for (U r = 0; r < bw::kReasonCount; ++r) if (w[bw::ReasonCounts + r]) std::printf(" %s=%u", bw::ReasonName(r), w[bw::ReasonCounts + r]);
    std::printf("\nrefusing services:");
    for (U s = 0; s < bw::kServiceRows; ++s) if (w[bw::ServiceRefusals + s])
        std::printf(" %s=%u", brain::ServiceName(static_cast<brain::Service>(s)), w[bw::ServiceRefusals + s]);
    std::printf("\ncomputed=%u refused=%u committed=%u guard_misses=%u diff_bytes=%u diff_spans=%u\n",
        w[bw::WorkerComputed], w[bw::WorkerRefused], w[bw::Committed], w[bw::GuardMisses], w[bw::DiffBytes], w[bw::DiffSpans]);
    bw::Stop();
}
// Deferred-event mechanism: the charge callback only reads the soldier, so replaying it at its checkpoint is exact.
static void DeferredEvents() {
    U recordedTotal = 0, replayedTotal = 0;
    for (U participants : {1u, 4u}) {
        const std::vector<Shape> shapes = Shapes();
        for (const Shape& shape : shapes) {
            // Deferral is exact only when nothing later in the step reads what the callback writes. The army-witness
            // callback writes a value the same soldier's finalizer reads (6544EE), so deferring it MUST diverge;
            // that is why the runtime never defers events.
            if (shape.chargeTarget != ~0u || shape.armyWitness) continue;
            EquivalenceCase(shape, participants, fpModes[0], 1u << bw::EventCharge);
        }
        static Snapshot before; Take(before);
    }
    // One explicit run to read the event counters through the same path.
    currentCase = "deferred charge events";
    Build(Sequential(kSpecCount * 4), false, false);
    callbackTarget = nullptr;
    static Snapshot before, expected, actual; Take(before);
    std::vector<Observed> expectedEvents, actualEvents;
    observations = &expectedEvents; SetFp(fpModes[0]); RunOriginal(); Take(expected); Restore(before);
    StartWorkers(4, 1u << bw::EventCharge);
    observations = &actualEvents; RunWorkers();
    Take(actual);
    CompareSnapshots(expected, actual); CompareObservations(expectedEvents, actualEvents);
    const Words w = WorkerWords();
    recordedTotal = w[bw::EventsRecorded + bw::EventCharge]; replayedTotal = w[bw::EventsReplayed + bw::EventCharge];
    Require(replayedTotal <= recordedTotal, "replayed charge events were recorded");
    std::printf("deferred charge events: recorded=%u replayed=%u (callbacks observed %zu)\n", recordedTotal, replayedTotal, actualEvents.size());
    bw::Stop();
    ++cases;
}
// Fault injection: a real access violation inside a worker occurrence, before anything is published. The
// population draws RNG, so the owner-run remainder must reproduce the stream reference from reseeded words.
static U g_faultOrdinal;
static U Injector(U, U ordinal) { return ordinal == g_faultOrdinal; }
static void FaultInjection() {
    for (U participants : {1u, 4u, 8u}) for (U ordinal : {0u, 37u, 150u}) {
        currentCase = "worker fault before commit";
        Shape shape{"worker fault before commit", Sequential(192), true, false, ~0u};
        shape.idle = true; shape.seed = 0x0badf00du + ordinal;
        Build(shape);
        callbackTarget = nullptr;
        static Snapshot before, expected, actual; Take(before);
        std::vector<Observed> expectedEvents, actualEvents;
        observations = &expectedEvents; SetFp(fpModes[0]);
        Require(RunStreamReference(1).draws > 0, "faulting population draws RNG");
        Take(expected); Restore(before);
        StartWorkers(participants);
        g_faultOrdinal = ordinal; bw::SetFaultInjector(&Injector);
        observations = &actualEvents;
        Require(RunWorkers(), "faulting stage is still handled");
        bw::SetFaultInjector(nullptr);
        Take(actual);
        CompareSnapshots(expected, actual); CompareObservations(expectedEvents, actualEvents);
        const Words w = WorkerWords();
        Require(w[bw::Faults] == 1 && w[bw::Sticky] == 1, "one real fault disables workers stickily");
        Require(w[bw::LastFaultCode] == EXCEPTION_ACCESS_VIOLATION, "fault code recorded");
        Require(w[bw::Occurrences] == w[bw::Committed] + w[bw::OwnerRan], "owner finished every occurrence at its ordinal");
        CheckInvariants(w, ~0u);
        Require(w[bw::Unprocessed] > 0 || ordinal >= 150u || w[bw::OwnerRan] > 0, "remaining ordinals ran on the owner");
        // A later stage must hand back untouched: sticky disable.
        Restore(before);
        static Snapshot rerun; Take(rerun);
        const bool handled = bw::RunWorklist(A(pop.manager.data()), clones.entries);
        Require(!handled, "sticky disable refuses later stages");
        Take(actual); CompareSnapshots(before, actual);
        bw::Stop();
        ++cases;
    }
}

// ---- RNG streams ----
static std::vector<Shape> RngShapes() {
    std::vector<Shape> shapes;
    Shape a{"rng: idle soldiers", Sequential(192), false, false, ~0u}; a.idle = true; a.seed = 0x2468ace1u;
    Shape b{"rng: idle soldiers with fire states", Sequential(256), true, false, ~0u}; b.idle = true; b.seed = 0x9e3779b9u;
    std::vector<U> reversed = Sequential(160); std::reverse(reversed.begin(), reversed.end());
    Shape c{"rng: reverse order with duplicates", reversed, false, true, ~0u}; c.idle = true; c.seed = 0xffffffffu;
    shapes.push_back(a); shapes.push_back(b); shapes.push_back(c);
    return shapes;
}
static void RngContract() {
    currentCase = "rng: stream contract";
    for (U x : {0u, 1u, 0x12345678u, 0xffffffffu}) {
        U step = x;
        for (U n = 0; n <= 1000; ++n) {
            if (n == 0 || n == 1 || n == 2 || n == 3 || n == 64 || n == 999 || n == 1000)
                Require(bw::LcgAdvance(x, n) == step, "LcgAdvance equals n sequential 5FC070 steps");
            step = step * 0x343fdu + 0x269ec3u;
        }
    }
    // The seed depends on every input (ordinal, generation, stage state); collisions are not expected here.
    std::vector<U> seeds;
    for (U s : {0u, 1u}) for (U g : {1u, 2u}) for (U k = 0; k < 64; ++k) seeds.push_back(bw::StreamSeed(s, g, k));
    std::sort(seeds.begin(), seeds.end());
    Require(std::adjacent_find(seeds.begin(), seeds.end()) == seeds.end(), "distinct seeds per (S, generation, ordinal)");
    Require(bw::StreamSeed(0x1234u, 7u, 9u) == bw::StreamSeed(0x1234u, 7u, 9u), "seed is a pure function");
    ++cases;
}
static void RngClassification() {
    currentCase = "rng: 5FC070 worker classification";
    Build(Sequential(8), false, false);
    const U random = A(At(0x5fc070)), lcg = A(world.model.data() + 0x50), entity = A(pop.soldiers[0].agent.data());
    U gate[4] = {};
    brain::SetWorkerRandomStream(0);
    Require(brain::WorkerClassify(random, 0x66e002, lcg, gate, entity, nullptr) == brain::Active &&
            !brain::WorkerRandomStream(random, lcg), "unbound: 5FC070 is a shared store");
    brain::SetWorkerRandomStream(lcg);
    Require(brain::WorkerClassify(random, 0x66e002, lcg, gate, entity, nullptr) == brain::Inactive &&
            brain::WorkerRandomStream(random, lcg), "bound receiver: worker-safe (stream)");
    Require(brain::WorkerClassify(random, 0x66e002, lcg + 4, gate, entity, nullptr) == brain::Active &&
            !brain::WorkerRandomStream(random, lcg + 4), "another receiver stays Active");
    Require(!brain::WorkerForwardable(random, 0x66e002, lcg, gate, entity), "5FC070 is never forwarded to the shared word");
    Require(!brain::WorkerRandomStream(A(At(0x80e020)), lcg), "80E020 (inline LCG on [[esi]+8]+50) is not a stream service");
    brain::SetWorkerRandomStream(0);
    ++cases;
}
// Three consecutive stages (generations 1..3) per participant count, each twice: once plain, once with an
// injected refusal pattern that changes which ordinals commit. Every run must equal the reference chain, so all
// runs are byte-identical to each other: run-to-run and across 1/4/8 workers, whatever the partition.
static void RngRunToRun() {
    const Shape shape = RngShapes()[1];
    static Snapshot reference, first, run;
    currentCase = "rng: multi-stage reference";
    Build(shape); callbackTarget = nullptr;
    std::vector<Observed> events; observations = &events; SetFp(fpModes[0]);
    U referenceDraws = 0, referenceWalked = 0;
    for (U generation = 1; generation <= 3; ++generation) {
        const RefStats r = RunStreamReference(generation);
        referenceDraws += r.draws; referenceWalked += r.occurrences;
    }
    Take(reference);
    bool haveFirst = false;
    for (U participants : {1u, 4u, 8u}) for (U repeat = 0; repeat < 2; ++repeat) {
        currentCase = "rng: run-to-run identity across 1/4/8 workers and three stages";
        Build(shape); events.clear(); SetFp(fpModes[0]);
        StartWorkers(participants);
        if (repeat) { g_refuseEvery = 5; g_refusePhase = participants % 5; bw::SetFaultInjector(&RefuseInjector); }
        for (U stage = 0; stage < 3; ++stage) Require(RunWorkers(), "every stage takes the worker path");
        bw::SetFaultInjector(nullptr); g_refuseEvery = 0;
        Take(run);
        CompareSnapshots(reference, run);
        if (!haveFirst) { first = run; haveFirst = true; } else CompareSnapshots(first, run);
        const Words w = WorkerWords();
        Require(w[bw::Dispatches] == 3 && w[bw::RngLcgAdvance] == referenceWalked, "three bound stages advanced by walked occurrences");
        Require(w[bw::RngWorkerDraws] + w[bw::RngOwnerDraws] == referenceDraws && w[bw::RngWorkerDraws] > 0,
            "all reference draws accounted, some on worker streams");
        bw::Stop();
        ++cases;
    }
    std::printf("rng run-to-run: 3 stages x {1,4,8} workers x 2 partitions identical to the reference (%u draws, %u walked)\n",
        referenceDraws, referenceWalked);
}
// A worker that touched the shared word (a forwarded original drawing it) must be detected after the dispatch:
// every worker result is dropped, the owner reruns all ordinals from their seeds (still the reference) and the
// feature disables stickily.
static U TouchInjector(U, U ordinal) { return ordinal >= 10 && ordinal < 30 ? 3u : 0u; }
static void RngRaceGuard() {
    for (U participants : {1u, 4u, 8u}) {
        currentCase = "rng: shared word touched during the dispatch";
        Build(RngShapes()[0]); callbackTarget = nullptr;
        static Snapshot before, expected, actual; Take(before);
        std::vector<Observed> events; observations = &events; SetFp(fpModes[0]);
        const RefStats ref = RunStreamReference(1);
        Take(expected); Restore(before);
        StartWorkers(participants);
        bw::SetFaultInjector(&TouchInjector);
        Require(RunWorkers(), "touched stage is still handled");
        bw::SetFaultInjector(nullptr);
        Take(actual);
        CompareSnapshots(expected, actual);
        const Words w = WorkerWords();
        Require(w[bw::Sticky] == 1 && w[bw::LastFaultCode] == 0xE042B302u && w[bw::LastFaultAddress] == A(world.model.data() + 0x50),
            "a changed shared word disables workers stickily and names the word");
        Require(w[bw::Committed] == 0 && w[bw::OwnerRan] == w[bw::Occurrences] && !w[bw::RngWorkerDraws] &&
            w[bw::RngOwnerDraws] == ref.draws, "every worker result was dropped and rerun from its seed");
        CheckInvariants(w, ~0u);
        bw::Stop();
        ++cases;
    }
}
static void RngStreams() {
    RngContract();
    RngClassification();
    Totals grand = {};
    struct Pattern { U every, phase; };
    for (const Shape& shape : RngShapes()) for (U participants : {1u, 4u, 8u}) {
        for (const FpMode& fp : fpModes) {
            const Totals t = EquivalenceCase(shape, participants, fp, 0);
            Require(t.draws > 0 && t.workerDraws > 0, "RNG soldiers draw, and committed worker occurrences drew from streams");
            grand.occurrences += t.occurrences; grand.committed += t.committed; grand.draws += t.draws;
            grand.workerDraws += t.workerDraws; grand.ownerDraws += t.ownerDraws;
        }
        for (const Pattern p : {Pattern{3, 1}, Pattern{2, 0}}) {
            const Totals t = EquivalenceCase(shape, participants, fpModes[0], 0, p.every, p.phase);
            Require(t.workerDraws > 0 && t.ownerDraws > 0, "mixed population: drawing soldiers both committed and owner-run");
            grand.occurrences += t.occurrences; grand.committed += t.committed; grand.draws += t.draws;
            grand.workerDraws += t.workerDraws; grand.ownerDraws += t.ownerDraws;
        }
    }
    std::printf("rng streams: %u occurrences, %u committed, %u draws (%u worker stream, %u owner reseeded)\n",
        grand.occurrences, grand.committed, grand.draws, grand.workerDraws, grand.ownerDraws);
    RngRunToRun();
    RngRaceGuard();
}
// The worker phase alone must leave every native byte (soldiers, timers, world, staging, and the bound model LCG
// word while workers draw from their streams) exactly as it found it.
static void WorkersNeverWriteNative() {
    U computed = 0, recorded = 0;
    std::vector<Shape> shapes = Shapes();
    for (const Shape& shape : RngShapes()) shapes.push_back(shape);
    for (const Shape& shape : shapes) for (U participants : {1u, 4u, 8u}) for (U mask : {0u, 1u << bw::EventCharge}) {
        currentCase = shape.name;
        Build(shape);
        callbackTarget = shape.chargeTarget == ~0u ? nullptr : pop.soldiers[shape.chargeTarget].agent.data();
        static Snapshot before, after; Take(before);
        std::vector<Observed> events; observations = &events; SetFp(fpModes[0]);
        StartWorkers(participants, mask);
        bw::SetComputeOnly(true);
        Require(bw::RunWorklist(A(pop.manager.data()), clones.entries), "worker phase ran");
        bw::SetComputeOnly(false);
        Take(after);
        CompareSnapshots(before, after);
        Require(events.empty(), "no callback executed during the worker phase");
        const Words w = WorkerWords();
        Require(w[bw::Speculated] > 0 && w[bw::Committed] == 0, "worker phase computed without committing");
        computed += w[bw::WorkerComputed]; recorded += w[bw::EventsRecorded + bw::EventCharge];
        bw::Stop();
        ++cases;
    }
    std::printf("worker phase left native memory untouched (%u computed occurrences, %u deferred charge events recorded)\n", computed, recorded);
}
static void Lifecycle() {
    currentCase = "start stop and short worklists";
    Build(Sequential(8), false, false);
    callbackTarget = nullptr;
    StartWorkers(4, 0, 64);
    static Snapshot before, after; Take(before);
    Require(!bw::RunWorklist(A(pop.manager.data()), clones.entries), "a worklist below min_entities is handed back");
    Take(after); CompareSnapshots(before, after);
    Require(WorkerWords()[bw::Handoffs] == 1 && WorkerWords()[bw::Occurrences] == 0, "hand-back executed nothing");
    Require(!bw::RunWorklist(A(pop.manager.data()), nullptr), "no clone entries means no worker path");
    bw::Stop();
    Require(!bw::Started(), "stop clears the started state");
    StartWorkers(2);
    Require(bw::Started() && WorkerWords()[bw::Enabled] == 1 && WorkerWords()[bw::ReceiverBytes] == bw::kReceiverBytes, "restart rebuilds");
    bw::Stop();
    ++cases;
}
// --brain-quiet: ntw2_brain2 without census (owner-run soldiers execute the original step), workers without
// guard-miss block checksums. Every shape, RNG shape, participant count and FP mode must still equal the reference.
static void QuietEquivalence() {
    g_quiet = true;
    brain::Configure(false, false); brain::Reset();
    std::vector<Shape> shapes = Shapes();
    for (const Shape& shape : RngShapes()) shapes.push_back(shape);
    Totals grand = {};
    for (const Shape& shape : shapes) for (U participants : {1u, 4u, 8u}) for (const FpMode& fp : fpModes) {
        const Totals t = EquivalenceCase(shape, participants, fp, 0);
        grand.occurrences += t.occurrences; grand.committed += t.committed; grand.ownerRan += t.ownerRan;
        grand.guard += t.guard; grand.draws += t.draws;
    }
    for (U participants : {4u, 8u}) EquivalenceCase(RngShapes()[0], participants, fpModes[0], 0, 3, 1);
    std::printf("quiet equivalence: %u occurrences, %u committed (%.2f%%), %u owner-run (original step), %u guard misses, %u draws\n",
        grand.occurrences, grand.committed, grand.occurrences ? 100.0 * grand.committed / grand.occurrences : 0.0,
        grand.ownerRan, grand.guard, grand.draws);
    g_quiet = false;
    brain::Configure(true, false); brain::Reset();
}

// ---- profile (printed evidence for the runtime estimate; no timing assertions) ----
static double Ms(LONGLONG ticks) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return 1000.0 * ticks / f.QuadPart; }
static LONGLONG Qpc() { LARGE_INTEGER v; QueryPerformanceCounter(&v); return v.QuadPart; }
// Region proofs over a population scattered across many allocations, in shuffled (not address) order: VirtualQuery
// cost, the former 8-entry LRU and the granule table (native_region_table.h).
static void ProfileRegions() {
    currentCase = "profile: region proofs";
    constexpr U kRegions = 1536, kPerRegion = 32, kObjects = kRegions * kPerRegion;
    std::vector<B*> regions(kRegions);
    for (B*& r : regions) { r = static_cast<B*>(VirtualAlloc(nullptr, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)); Require(r != nullptr, "region"); }
    std::vector<U> objects(kObjects);
    for (U i = 0; i < kObjects; ++i) objects[i] = A(regions[i / kPerRegion] + 0x800 * (i % kPerRegion));
    U seed = 12345;
    for (U i = kObjects - 1; i > 0; --i) { seed = seed * 1103515245u + 12345u; std::swap(objects[i], objects[(seed >> 8) % (i + 1)]); }
    MEMORY_BASIC_INFORMATION m;
    LONGLONG t = Qpc();
    for (U i = 0; i < kObjects; ++i) VirtualQuery(reinterpret_cast<const void*>(objects[i]), &m, sizeof(m));
    const double vq = Ms(Qpc() - t);
    // The former cache (8 LRU regions, cleared per stage), verbatim in behaviour.
    struct Lru { U base[8], end[8], next; } lru{};
    U lruQueries = 0;
    t = Qpc();
    for (U i = 0; i < kObjects; ++i) {
        const U a = objects[i], last = a + 0x700;
        bool hit = false;
        for (U k = 0; k < 8 && !hit; ++k) hit = a - lru.base[k] < lru.end[k] - lru.base[k] && last <= lru.end[k];
        if (hit) continue;
        ++lruQueries; VirtualQuery(reinterpret_cast<const void*>(a), &m, sizeof(m));
        lru.base[lru.next] = A(m.BaseAddress); lru.end[lru.next] = A(m.BaseAddress) + static_cast<U>(m.RegionSize); lru.next = (lru.next + 1) & 7;
    }
    const double lruMs = Ms(Qpc() - t);
    static ntw2_region::Table table;
    table.Clear();
    U tableQueries = 0, proven = 0;
    t = Qpc();
    for (U i = 0; i < kObjects; ++i) proven += table.Readable(objects[i], 0x700, tableQueries);
    const double tableMs = Ms(Qpc() - t);
    std::printf("profile regions: %u objects in %u allocations, shuffled: VirtualQuery %.0f ns/call; LRU8 %u queries %.2f ms; "
        "granule table %u queries %.2f ms (%u proven)\n", kObjects, kRegions, vq * 1e6 / kObjects, lruQueries, lruMs, tableQueries,
        tableMs, proven);
    Require(proven == kObjects && tableQueries <= 2 * kRegions, "the granule table proves every object with at most two queries per allocation");
    for (B* r : regions) VirtualFree(r, 0, MEM_RELEASE);
    ++cases;
}
// Per-occurrence phase costs on the synthetic population (cache-hot, 256 soldiers): original step, quiet and census
// worker/owner phases. Absolute values are not battle values; the report scales them with live counts.
static void ProfilePhases() {
    const Shape shape = RngShapes()[1];
    constexpr U kStages = 40;
    Build(shape); callbackTarget = nullptr;
    static Snapshot before; Take(before);
    std::vector<Observed> sink; observations = &sink; SetFp(fpModes[0]);
    LONGLONG original = 0; U originalOccurrences = 0;
    for (U s = 0; s < kStages; ++s) {
        Restore(before); sink.clear();
        for (U i = 0; i < pop.count; ++i) originalOccurrences += Get<B>(reinterpret_cast<void*>(pop.list[i]), 0x30) == 1;
        const LONGLONG t = Qpc(); RunOriginal(); original += Qpc() - t;
    }
    std::printf("profile original step: %.3f us/occurrence (%u occurrences)\n", 1000.0 * Ms(original) / originalOccurrences, originalOccurrences);
    for (const bool quiet : {true, false}) {
        currentCase = quiet ? "profile: quiet phases" : "profile: census phases";
        g_quiet = quiet;
        brain::Configure(!quiet, false); brain::Reset();
        StartWorkers(4);
        for (U s = 0; s < kStages; ++s) { Restore(before); sink.clear(); Require(RunWorkers(), "profile stage handled"); }
        const Words w = WorkerWords();
        const PhaseWords p = WorkerPhases();
        const double spec = w[bw::Speculated] ? w[bw::Speculated] : 1, computed = w[bw::WorkerComputed] ? w[bw::WorkerComputed] : 1;
        const double attempts = p[bw::PhaseCommitAttempts] ? p[bw::PhaseCommitAttempts] : 1, owner = w[bw::OwnerRan] ? w[bw::OwnerRan] : 1;
        std::printf("profile %s (4 participants, %u stages, %u occurrences, %u committed, %u owner-run): per stage capture %.3f ms "
            "(witness %.3f), dispatch %.3f ms, commit %.3f ms, owner_run %.3f ms; worker us/speculated capture %.3f clone %.3f, "
            "publish us/computed %.3f; owner us/commit attempt %.3f, us/owner-run %.3f; gates/speculated %.1f, clone us/gate %.3f\n",
            quiet ? "quiet" : "census", p[bw::PhaseStages], w[bw::Occurrences], w[bw::Committed], w[bw::OwnerRan],
            p[bw::PhaseCaptureUs] / 1000.0 / kStages, p[bw::PhaseWitnessBeginUs] / 1000.0 / kStages,
            p[bw::PhaseDispatchUs] / 1000.0 / kStages, p[bw::PhaseCommitUs] / 1000.0 / kStages, p[bw::PhaseOwnerRunUs] / 1000.0 / kStages,
            p[bw::PhaseWorkerCaptureUs] / spec, p[bw::PhaseWorkerCloneUs] / spec, p[bw::PhaseWorkerPublishUs] / computed,
            p[bw::PhaseCommitUs] / attempts, p[bw::PhaseOwnerRunUs] / owner, p[bw::PhaseWorkerGates] / spec,
            p[bw::PhaseWorkerGates] ? p[bw::PhaseWorkerCloneUs] / static_cast<double>(p[bw::PhaseWorkerGates]) : 0.0);
        Require(p[bw::PhaseStages] == kStages && !w[bw::Faults], "profile stages ran without faults");
        bw::Stop();
        ++cases;
    }
    g_quiet = false;
    brain::Configure(true, false); brain::Reset();
}
int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_brain_workers_oracle Napoleon.exe\n"); return 2; }
    ownerThread = GetCurrentThreadId(); Map(argv[1]);
    Put(At(0x1841bb8), 0, U(_tls_index)); tlsPad[0] = 0;
    Put(At(0x14deda0), 0, U(0x80000000));
    std::memset(At(0x14ded30), 0, 0x70);
    Put(At(0x14ded30), 0x14, U(4)); Put(At(0x14ded30), 0x1c, A(world.effectRecipients[0].data()));
    Put(At(0x14ded30), 0x64, U(4)); Put(At(0x14ded30), 0x6c, A(world.effectRecipients[1].data()));
    U* vcc = reinterpret_cast<U*>(At(0x1333714) + 0xcc); const U saved = *vcc; *vcc = Fn(&Vcc);
    brain::Configure(true, false); brain::Reset();
    Equivalence();
    RngStreams();
    ReasonReport();
    brain::Configure(true, false); brain::Reset();
    DeferredEvents();
    FaultInjection();
    Lifecycle();
    WorkersNeverWriteNative();
    QuietEquivalence();
    ProfileRegions();
    ProfilePhases();
    *vcc = saved; brain::Release();
    std::printf("PASS brain workers oracle cases=%u checks=%u\n", cases, checks);
    return 0;
}
