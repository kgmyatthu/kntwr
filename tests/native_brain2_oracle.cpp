// Execute untouched mapped originals against BRAIN2 v2 owner-serial forwarding.
// Synthetic real-layout soldiers and fixture-owned callback receivers supply data;
// no service is mocked and no mapped instruction is patched.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <intrin.h>
#include <algorithm>
#include <cmath>
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "clones/kntwr_clones.h"
#include "native_brain2.h"
#include "native_finalizer.h"
#include "native_brain_s0.h"
#include "native_brain_locality.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace brain = kntwr_brain2;
static_assert(sizeof(void*) == 4, "x86 native ABI");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];
static B* image;
static U delta, checks, cases, ownerThread;
static const char* currentCase = "mapping";
static kntwr_clone_set clones{};
static U bindings[KNTWR_BIND_COUNT];
[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fprintf(stderr, "FAIL [%s]: ", currentCase);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::exit(1);
}
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail("%s", what); }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static T Get(const void* p, size_t off) {
    T v; std::memcpy(&v, static_cast<const B*>(p) + off, sizeof(v)); return v;
}
template<class T> static void Put(void* p, size_t off, T v) {
    std::memcpy(static_cast<B*>(p) + off, &v, sizeof(v));
}
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static void ResetFp() {
    unsigned short cw = 0x27f;
    __asm fninit
    __asm fldcw word ptr [cw]
    _mm_setcsr(0x1f80);
}
struct FpState { U mxcsr; unsigned short control, status; };
static FpState CaptureFp() {
    unsigned short control, status;
    __asm fnstcw word ptr [control]
    __asm fnstsw word ptr [status]
    return {_mm_getcsr(), control, status};
}
static void CompareFp(const FpState& expected) {
    const FpState actual = CaptureFp();
    Require(actual.mxcsr == expected.mxcsr && actual.control == expected.control && actual.status == expected.status,
        "original MXCSR and x87 control/status/stack depth preserved");
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
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
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
    Require(kntwr_brain_s0::Bind(A(image), bindings), "S0 gates bind with collision-free dispatch tables");
    U detail = 0;
    const U error = kntwr_build_clones(A(image), bindings, &clones, &detail);
    if (error) Fail("clone construction error=%u detail=%u", error, detail);
}
enum ObservationKind : U { ChargeCallback, AnimationCallback };
struct Observed { U type, entity, receiver, argument; };
static std::vector<Observed>* observations;
static B* callbackTarget;
static void __fastcall Charge(void* receiver, void*, void* entity) {
    Require(GetCurrentThreadId() == ownerThread, "charge executes immediately on owner");
    observations->push_back({ChargeCallback, Get<U>(entity, 0x2c), Get<U>(receiver, 4), Get<U>(entity, 0x2c)});
    if (callbackTarget) Put(callbackTarget, 0x1d8, U(5));
}
static void __fastcall Vcc(void* entity, void*) {
    Require(GetCurrentThreadId() == ownerThread, "animation callback executes immediately on owner");
    observations->push_back({AnimationCallback, Get<U>(entity, 0x2c), Get<U>(entity, 0x2c), 0});
}
// Real root/model/animation-manager chains followed by the originals. The oracle
// snapshots all bytes, including shared RNG and effect-recipient storage.
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
    World() {
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
        // Only heading zero is used by charge fixtures. Slot integration uses
        // original fsincos, not this lookup table.
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
        // Native inline-node constructors copy the holder's soldier and world.
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
static void CompareBytes(const void* expected, const void* actual, size_t size, const char* what) {
    const B* e = static_cast<const B*>(expected);
    const B* a = static_cast<const B*>(actual);
    for (size_t i = 0; i < size; ++i) {
        ++checks;
        if (e[i] != a[i]) Fail("%s +%zX native=%02X forwarded=%02X", what, i, e[i], a[i]);
    }
}
static void CompareObservations(const std::vector<Observed>& expected, const std::vector<Observed>& actual) {
    Require(expected.size() == actual.size(), "same immediate callback count");
    for (size_t i = 0; i < expected.size(); ++i)
        CompareBytes(&expected[i], &actual[i], sizeof(Observed), "callback identity/order/arguments");
}
using Status = std::array<U, brain::kWords>;
using Census = std::array<U, brain::kCensusWords>;
static Status StatusNow() { Status words{}; brain::Snapshot(words.data()); return words; }
static Census CensusNow() { Census words{}; brain::CensusSnapshot(words.data()); return words; }
static LONG ReportFault(EXCEPTION_POINTERS* info, const char* what, U index) {
    const EXCEPTION_RECORD* r = info->ExceptionRecord;
    const U eip = A(r->ExceptionAddress);
    const bool inImage = eip >= delta + 0x400000 && eip < delta + 0x400000 + 0x2000000;
    std::fprintf(stderr, "FAULT [%s] index=%u code=%08lX eip=%08X (image VA %08X) access=%08X\n", what, index, r->ExceptionCode, eip,
        inImage ? eip - delta : 0, r->NumberParameters >= 2 ? static_cast<U>(r->ExceptionInformation[1]) : 0);
    std::fprintf(stderr, "case: %s; entry image VA=%08X\n", currentCase, index >= delta ? index - delta : 0);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
static void NativeStep(Fixture& f, U index) {
    __try {
        const U entry = Get<U>(reinterpret_cast<void*>(Get<U>(f.agent.data(), 0)), 0xc);
        reinterpret_cast<void (__thiscall*)(void*)>(entry)(f.agent.data());
    } __except (ReportFault(GetExceptionInformation(), "original brain", index)) { std::exit(3); }
}
static void SerialStep(U entity, const U* entries, U index) {
    __try { brain::RunOccurrence(entity, entries); }
    __except (ReportFault(GetExceptionInformation(), "owner serial brain", index)) { std::exit(3); }
}
enum class CallAbi { Void0, Byte0, Word0, Word2, Float0, Void1, WrapperEffect };
static U CallService(U entry, U receiver, CallAbi abi, U argument = 0, U argument2 = 0) {
    __try {
        void* object = reinterpret_cast<void*>(receiver);
        switch (abi) {
        case CallAbi::Void0:
            reinterpret_cast<void (__thiscall*)(void*)>(entry)(object); return 0;
        case CallAbi::Byte0:
            return reinterpret_cast<B (__thiscall*)(void*)>(entry)(object);
        case CallAbi::Word0:
            return reinterpret_cast<U (__thiscall*)(void*)>(entry)(object);
        case CallAbi::Word2:
            return reinterpret_cast<U (__thiscall*)(void*, U, U)>(entry)(object, argument, argument2);
        case CallAbi::Float0: {
            const float result = reinterpret_cast<float (__thiscall*)(void*)>(entry)(object);
            U bits; std::memcpy(&bits, &result, sizeof(bits)); return bits;
        }
        case CallAbi::Void1:
            reinterpret_cast<void (__thiscall*)(void*, U)>(entry)(object, argument); return 0;
        case CallAbi::WrapperEffect:
            reinterpret_cast<void (__thiscall*)(void*, U, float, U, float)>(entry)(object, argument, 5.0f, 0, 0.5f); return 0;
        }
    } __except (ReportFault(GetExceptionInformation(), "original service or forwarding gate", entry)) { std::exit(3); }
    Fail("unknown service ABI");
}
static void ServiceOracle(World& world, Fixture& fixture, brain::Service service,
    brain::Classification classification, U originalVa, U receiver, CallAbi abi, U argument = 0, U argument2 = 0,
    int callClassification = -1) {
    brain::Configure(true, false); brain::Reset();
    const Fixture before = fixture;
    std::vector<World> worlds(2, world);
    std::array<B, 0x70> stagingBefore{}, stagingExpected{};
    std::memcpy(stagingBefore.data(), At(0x14ded30), stagingBefore.size());
    std::array<B, 0x14> gatherBefore{}, gatherExpected{};
    std::memcpy(gatherBefore.data(), At(0x14514c0), gatherBefore.size());
    const U gate = brain::GateAddress(service);
    Require(gate != 0, "direct service has a forwarding entry");
    Require(brain::ClassifyService(service, receiver) == classification, "independently specified service classification");
    CompareBytes(&before, &fixture, sizeof(Fixture), "classification leaves soldier unchanged");
    CompareBytes(&worlds[0], &world, sizeof(World), "classification leaves world unchanged");
    Require(StatusNow()[brain::ServiceCalls] == 0, "classification does not execute or count a service");
    std::vector<Observed> nativeEvents, actualEvents;
    observations = &nativeEvents; ResetFp();
    const U expectedResult = CallService(A(At(originalVa)), receiver, abi, argument, argument2);
    const FpState expectedFp = CaptureFp();
    const Fixture expected = fixture; worlds[1] = world;
    std::memcpy(stagingExpected.data(), At(0x14ded30), stagingExpected.size());
    std::memcpy(gatherExpected.data(), At(0x14514c0), gatherExpected.size());
    fixture = before; world = worlds[0];
    std::memcpy(At(0x14ded30), stagingBefore.data(), stagingBefore.size());
    std::memcpy(At(0x14514c0), gatherBefore.data(), gatherBefore.size());
    observations = &actualEvents; ResetFp();
    const U actualResult = CallService(gate, receiver, abi, argument, argument2);
    CompareFp(expectedFp);
    Require(actualResult == expectedResult, "original return value and return width preserved");
    CompareBytes(&expected, &fixture, sizeof(Fixture), "service complete soldier/nested outputs");
    CompareBytes(&worlds[1], &world, sizeof(World), "service shared outputs and RNG");
    CompareBytes(stagingExpected.data(), At(0x14ded30), stagingExpected.size(), "shared effect staging");
    CompareBytes(gatherExpected.data(), At(0x14514c0), gatherExpected.size(), "shared wrapper gather publication");
    CompareObservations(nativeEvents, actualEvents);
    const Census rows = CensusNow();
    const U row = service * brain::kServiceStride;
    Require(rows[row + brain::Calls] == 1, "service forwards exactly once");
    const brain::Classification outcome = callClassification < 0 ? classification :
        static_cast<brain::Classification>(callClassification);
    Require(rows[row + brain::InactiveCalls] == U(outcome == brain::Inactive) &&
        rows[row + brain::ActiveCalls] == U(outcome == brain::Active) &&
        rows[row + brain::UnknownCalls] == U(outcome == brain::Unresolved), "exclusive argument-aware service classification counters");
    Require(rows[row + brain::FirstActiveOccurrences] == 0 && rows[row + brain::FirstUnknownOccurrences] == 0,
        "isolated gate is not attributed to a stale occurrence");
    ++cases;
}
static void ServiceCases(World& world) {
    // Native Effects uses static TLS epochs and two preallocated staging vectors.
    // All initialization is image data, never an import/code/service replacement.
    Put(At(0x1841bb8), 0, U(_tls_index)); tlsPad[0] = 0;
    Put(At(0x14deda0), 0, U(0x80000000));
    std::memset(At(0x14ded30), 0, 0x70);
    Put(At(0x14ded30), 0x14, U(4)); Put(At(0x14ded30), 0x1c, A(world.effectRecipients[0].data()));
    Put(At(0x14ded30), 0x64, U(4)); Put(At(0x14ded30), 0x6c, A(world.effectRecipients[1].data()));
    for (U branch = 0; branch < 7; ++branch) {
        currentCase = "effects native early-outs and active shared staging";
        Fixture f; f.Init(world, Spec{4,0,9}, 301);
        Put(f.agent.data(), 0xc8, 3.0f);
        // Native speed class boundaries are 4,16,36,121; x=3 is class one.
        if (branch == 0) Put(f.agent.data(), 0xc8, 0.0f);
        if (branch == 1) Put(f.agent.data(), 0xc8, 2.0f);
        if (branch == 2) Put(f.agent.data(), 0x1b8, U(0xd));
        if (branch == 3) Put(f.agent.data(), 0x18, U(1));
        if (branch == 4) Put(f.agent.data(), 0xc8, U(0x7fc00000));
        if (branch == 5) Put(f.agent.data(), 0xc8, -2.0f);
        ServiceOracle(world, f, brain::Effects, branch == 6 ? brain::Active : brain::Inactive,
            0x62dff0, A(f.agent.data()), CallAbi::Void0);
        if (branch == 6) Require(world.effectRecipients[0][0] == A(f.agent.data()) &&
            world.effectRecipients[1][0] == A(f.agent.data()), "original active effects enumerates soldier into shared staging");
    }
    for (U branch = 0; branch < 5; ++branch) {
        currentCase = "target acquisition inactive and unresolved native transition";
        Fixture f; f.Init(world, Spec{4,0,9}, 302);
        if (branch == 1) Put(f.agent.data(), 0x224, U(1));
        if (branch == 2) Put(f.agent.data(), 0x224, U(0x20));
        if (branch == 3) {
            Put(f.agent.data(), 0x224, U(0xc));
            Put(f.agent.data(), 0x35b, B(1));
            // A live secondary node selects native phase-C cleanup directly.
            Put(f.agent.data(), 0x2e4, B(1));
        }
        if (branch == 4) { Put(f.agent.data(), 0x5c0, B(1)); Put(f.agent.data(), 0x35b, B(1)); }
        ServiceOracle(world, f, brain::TargetAcquire, branch >= 3 ? brain::Unresolved : brain::Inactive,
            0x6718f0, A(f.agent.data()), CallAbi::Void0);
        if (branch == 3) Require(Get<U>(f.agent.data(), 0x224) == 0 &&
            Get<B>(f.agent.data(), 0x364) == 0, "unresolved gate really forwards native reset and phase clear");
    }
    for (B active : {B(0), B(2), B(1)}) {
        currentCase = "watcher exact active byte and synchronous begin step";
        Fixture f; f.Init(world, Spec{4,0,9}, 303);
        Put(f.agent.data(), 0x2cc + 8, A(At(0x13336b0)));
        Put(f.agent.data(), 0x2cc + 0x8f, active);
        ServiceOracle(world, f, brain::Watcher, active == 1 ? brain::Unresolved : brain::Inactive,
            0x66e780, A(f.agent.data() + 0x2cc), CallAbi::Byte0);
        Require(Get<B>(f.agent.data(), 0x2cc + 0x90) == B(active == 1), "watcher begin publication is synchronous");
        Require(Get<U>(f.agent.data(), 0x2cc + 0x1c) == U(active == 1), "watcher original steps once");
    }
    for (U branch = 0; branch < 4; ++branch) {
        currentCase = "wrapper effect entry classification preserves unresolved";
        Fixture f; f.Init(world, Spec{4,0,9}, 304);
        Put(f.agent.data(), 0x1e8, A(f.slotHeader.data()));
        Put(f.slotHeader.data(), 0x18, branch ? U(3) : U(1));
        if (branch == 2) Put(f.agent.data(), 0x1b8, U(0xd));
        if (branch == 3) {
            // The real gather helper skips a soldier with no low flag bits.
            // A pre-existing self recipient has zero relative distance, so the
            // real effect still traverses and clears the process-global list.
            Put(f.agent.data(), 0x34, U(0)); Put(f.agent.data(), 0x8c, 1.0f);
            Put(At(0x14a7d7c), 0, U(0x80000000));
            world.effectRecipients[0][0] = A(f.agent.data());
            Put(At(0x14514cc), 0, U(1));
            Put(At(0x14514d0), 0, A(world.effectRecipients[0].data()));
        }
        ServiceOracle(world, f, brain::WrapperEffect, brain::Unresolved,
            0x5cb830, A(f.agent.data()), CallAbi::WrapperEffect, A(f.agent.data() + 0x8c), 0,
            branch == 3 ? brain::Active : brain::Inactive);
        if (branch == 3) Require(Get<U>(At(0x14514cc), 0) == 0, "active original wrapper clears the shared recipient list");
    }
    for (U branch = 0; branch < 3; ++branch) {
        currentCase = "wrapper service inactive and unresolved forwarding";
        Fixture f; f.Init(world, Spec{4,0,9}, 305);
        if (branch == 0) Put(f.agent.data(), 0xec, B(0));
        if (branch == 1) Put(f.agent.data(), 0x1ec, U(1));
        Put(f.agent.data(), 0x694, 100000.0f);
        ServiceOracle(world, f, brain::WrapperService, branch == 2 ? brain::Unresolved : brain::Inactive,
            0x5b7b20, A(f.agent.data()), CallAbi::Void0);
    }
    for (U seed : {0u, 0x12345678u, 0xffffffffu}) {
        currentCase = "random service x87 return and exactly one state transition";
        Fixture f; f.Init(world, Spec{4,0,9}, 306);
        Put(world.model.data(), 0x50, seed);
        ServiceOracle(world, f, brain::Random, brain::Active, 0x5fc070,
            A(world.model.data() + 0x50), CallAbi::Float0);
        Require(Get<U>(world.model.data(), 0x50) != seed, "mapped RNG advances real model state");
    }
    for (B active : {B(0), B(2), B(1)}) {
        currentCase = "holder query forwards AL with exact active-byte classification";
        Fixture f; f.Init(world, Spec{4,0,9}, 307);
        Put(f.agent.data(), 0x2cc + 8, A(At(0x13336b0)));
        Put(f.agent.data(), 0x2cc + 0x8f, active);
        ServiceOracle(world, f, brain::HolderQuery, active == 1 ? brain::Unresolved : brain::Inactive,
            0x805880, A(f.agent.data() + 0x2cc), CallAbi::Byte0);
    }
    {
        // 7EAE90 stores only the caller-supplied default vector (receiver is a
        // fixture on this stack). The service-level classifier stays unresolved
        // (no occurrence context); the gate classifies the call itself inactive.
        currentCase = "own descriptor returns original receiver";
        Fixture f; f.Init(world, Spec{4,0,9}, 308);
        f.slotHeader.fill(0xa5);
        ServiceOracle(world, f, brain::Descriptor, brain::Unresolved, 0x7eae90,
            A(f.slotHeader.data()), CallAbi::Word0, 0, 0, brain::Inactive);
        for (U i = 0; i < 0x14; ++i) Require(f.slotHeader[i] == 0, "default descriptor words 0..13 stored from the zero BSS defaults");
        Require(f.slotHeader[0x14] == 0xa5, "default descriptor never writes past +13");
    }
    {
        currentCase = "reference constructor publishes real inline node and holder lifetime";
        Fixture f; f.Init(world, Spec{4,0,9}, 309);
        Put(f.agent.data(), 0x228, A(f.agent.data()));
        Put(f.agent.data(), 0x228 + 0xa0, A(world.root.data()));
        f.slot[0] = A(f.agent.data());
        ServiceOracle(world, f, brain::ReferenceConstruct, brain::Unresolved, 0x61da90,
            A(f.agent.data() + 0x22c), CallAbi::Word2, A(f.agent.data() + 0x228), A(f.slot.data()));
        Require(Get<U>(f.agent.data(), 0x22c) == A(At(0x1334180)) &&
            Get<B>(f.agent.data(), 0x2c4) == 1, "original reference node vtable and enabled holder are published");
    }
    {
        currentCase = "animation lookup preserves original pointer return";
        Fixture f; f.Init(world, Spec{4,0,9}, 310);
        Put(f.animation.data(), 0x2c, A(f.rows.data()));
        Put(f.rows.data(), 0, A(f.slotHeader.data())); Put(f.rows.data(), 0x14, U(1));
        ServiceOracle(world, f, brain::AnimationLookup, brain::Inactive, 0xe5f760,
            A(f.animation.data()), CallAbi::Word2);
    }
    struct QuietService { brain::Service service; U va; CallAbi abi; };
    const QuietService quiet[] = {
        {brain::MoveDriver, 0x658c50, CallAbi::Void1},
        {brain::FireDriver, 0x64de80, CallAbi::Void0},
        {brain::Finalize, 0x6543d0, CallAbi::Void0},
        {brain::Animation, 0x670f40, CallAbi::Void0}
    };
    for (const QuietService& service : quiet) {
        currentCase = brain::ServiceName(service.service);
        Fixture f; f.Init(world, Spec{4,0,9}, 311);
        ServiceOracle(world, f, service.service, brain::Unresolved, service.va, A(f.agent.data()), service.abi);
    }
    {
        currentCase = "dual timer forwards original nested-object updates";
        Fixture f; f.Init(world, Spec{4,0,9}, 312);
        ServiceOracle(world, f, brain::Timer, brain::Unresolved, 0x602e00, A(f.timer.data()), CallAbi::Void0);
    }
    for (U state : {0u, 6u, 7u, 3u}) {
        currentCase = "fire sequencer inactive and unresolved request release";
        Fixture f; f.Init(world, Spec{4,0,9}, 313);
        Put(f.agent.data(), 0x390, state);
        if (state == 3) Put(f.agent.data(), 0x3a4, B(1));
        ServiceOracle(world, f, brain::FireSequence, state == 3 ? brain::Unresolved : brain::Inactive,
            0x659600, A(f.agent.data()), CallAbi::Void0);
        if (state == 3) Require(Get<U>(f.agent.data(), 0x390) == 6, "original unresolved fire branch completes request release");
    }
    for (B enabled : {B(0), B(2), B(1)}) {
        currentCase = "node finish preserves native inline destruction lifecycle";
        Fixture f; f.Init(world, Spec{4,0,9}, 314);
        Put(f.agent.data(), 0x228, A(f.agent.data()));
        Put(f.agent.data(), 0x228 + 0xa0, A(world.root.data()));
        f.slot[0] = A(f.agent.data());
        CallService(A(At(0x61da90)), A(f.agent.data() + 0x22c), CallAbi::Word2,
            A(f.agent.data() + 0x228), A(f.slot.data()));
        Put(f.agent.data(), 0x2c4, enabled);
        ServiceOracle(world, f, brain::NodeFinish, enabled == 1 ? brain::Unresolved : brain::Inactive,
            0x63cdd0, A(f.agent.data() + 0x228), CallAbi::Void0);
        if (enabled == 1) Require(Get<B>(f.agent.data(), 0x2c4) == 0 &&
            Get<B>(f.agent.data(), 0x478) == 1, "native node destructor publishes cleanup before return");
    }
    // Services with no receiver-only proof must not become inactive simply
    // because a synthetic soldier happens to contain zero or nonzero fields.
    const brain::Service unresolved[] = {
        brain::Descriptor, brain::ReferenceConstruct,
        brain::SlotAcquire, brain::ChargeCallback, brain::MoveDriver, brain::FireDriver,
        brain::Finalize, brain::PathRequest, brain::RequestBuild,
        brain::RequestCommit, brain::Order, brain::NodeBegin,
        brain::NodeStep, brain::NodeDestroy, brain::Animation, brain::Parked,
        brain::WrapperEffect, brain::PosePosition, brain::PoseHeading, brain::ReferenceStep,
        brain::Arrival, brain::Unlink, brain::Engage, brain::Timer, brain::UnitWitness,
        brain::ColdLookup, brain::Idle, brain::PreBattle, brain::Exit, brain::Projection,
        brain::Crew, brain::Wrapper610470, brain::Wrapper60CAC0, brain::Wrapper5E52F0,
        brain::Wrapper607540, brain::Wrapper5B9720, brain::VirtualOrder, brain::VirtualQuery,
        brain::Unknown, brain::FireCandidates, brain::FireGather, brain::MeleeLabel, brain::MutableRead
    };
    currentCase = "conservative classification catalogue";
    Fixture zero, nonzero;
    nonzero.agent.fill(0xa5);
    for (brain::Service service : unresolved) {
        Require(brain::ClassifyService(service, A(zero.agent.data())) == brain::Unresolved,
            "unproved zero receiver remains unresolved");
        Require(brain::ClassifyService(service, A(nonzero.agent.data())) == brain::Unresolved,
            "unproved nonzero receiver remains unresolved");
    }
    Require(brain::ClassifyService(brain::FireSubmit, A(zero.agent.data())) == brain::Active &&
        brain::ClassifyService(brain::FireSubmit, A(nonzero.agent.data())) == brain::Active,
        "fire submit is active regardless of receiver values because its shared counter increments unconditionally");
    for (U i = 0; i < brain::ServiceCount; ++i)
        Require(brain::ClassifyService(static_cast<brain::Service>(i), 0) == brain::Unresolved,
            "null receiver never proves an inactive or active service");
}

// ===== Inactive-proof oracle ================================================
// Every Inactive classification is executed against the mapped ORIGINAL with a
// write-set probe: every byte of every region not declared writable (soldier
// fixtures, shared world, units/battle state, and the whole image .data/.bss)
// must be identical afterwards. Both branches of the mapped original are driven
// where the original offers them; non-inactive branches are classified only
// (their originals reach opaque helpers or deliberate shared mutation).
struct Region { const char* name; void* p; size_t n; bool writable; };
static constexpr U kDataBegin = 0x144e000, kDataSize = 0x3f5ed8;
template<class F> static void Safe(F&& f) {
    __try { f(); } __except (ReportFault(GetExceptionInformation(), "proof original", 0)) { std::exit(3); }
}
// noinline: `gate` must sit BELOW every caller buffer, like the real gate frame.
template<class F> __declspec(noinline) static void Probe(const char* what, U va, U site, U receiver,
        std::initializer_list<U> argv, U entity, brain::Classification expect,
        std::initializer_list<Region> regions, bool execute, F&& call) {
    currentCase = what;
    if (std::getenv("KNTWR_ORACLE_TRACE")) { std::fprintf(stderr, "probe %s %X\n", what, va); std::fflush(stderr); }
    U gate[8] = {};
    { size_t k = 0; for (U v : argv) gate[k++] = v; }
    U service = 0;
    const U target = A(At(va));
    const brain::Classification got = brain::WorkerClassify(target, site, receiver, gate, entity, &service);
    if (got != expect) Fail("%s: target %X expected class %u got %u", what, va, expect, got);
    ++checks;
    Require(brain::WorkerForwardable(target, site, receiver, gate, entity) ==
            (expect == brain::Inactive && brain::CloneIdFor(va) == ~0u),
        "WorkerForwardable is Inactive and not cloned");
    ++cases;
    if (expect != brain::Inactive || !execute) return;
    std::vector<std::vector<B>> before;
    for (const Region& r : regions) before.emplace_back(static_cast<B*>(r.p), static_cast<B*>(r.p) + r.n);
    std::vector<B> data(At(kDataBegin), At(kDataBegin) + kDataSize);
    ResetFp(); Safe(call);
    size_t i = 0;
    for (const Region& r : regions) {
        if (!r.writable) CompareBytes(before[i].data(), r.p, r.n, r.name);
        ++i;
    }
    CompareBytes(data.data(), At(kDataBegin), kDataSize, "inactive original wrote image .data/.bss");
}
static brain::Classification ObserveAt(U site, U entity, const U* registers) {
    return brain::WorkerObserveClassify(site, registers, entity);
}
struct BattleBlock {
    std::array<B, 0x2800> manager{};
    std::array<B, 0x100> state{}, model{}, root{}, entry{};
    std::array<U, 8> table{};
};
struct UnitBlock {
    std::array<B, 0xe00> unit{};
    std::array<B, 0x200> desc{};
    std::array<B, 0x40> attached{};
    std::array<B, 0x500> group{};
    std::array<B, 16 * 0x2c> abilities{};
    std::array<U, 16> abilityKeys{};
    std::array<B, 0x40> statrec{};
    std::array<B, 0x220> army{};       // A+1F8 object: +218 stat table base
    std::array<B, 0x110> armyTable{};  // +E4 entries indexed by A+374
    std::array<B, 0x40> armyStat{};    // entry: caller reads +10
};
static void ProofCases(World& world) {
    using brain::Inactive; using brain::Active; using brain::Unresolved;
    brain::Configure(true, false); brain::Reset();
    const U site = 0x66d638;
    // ---- register-only leaves (pinned by exact bytes, no memory access)
    {
        Fixture f; f.Init(world, Spec{4,0,9}, 400);
        const Region rs[] = {{"fixture", &f, sizeof f, false}, {"world", &world, sizeof(World), false}};
        for (U va : {0x461180u, 0x462cb0u, 0x447880u, 0x62df00u, 0x444b60u, 0x47af90u, 0x4cdc40u, 0x4cdc50u,
                     0x4cdc60u, 0x4cdc70u, 0x4cdc80u, 0x4cdc90u, 0x66ba90u, 0x4470b0u}) {
            Require(brain::WorkerWriteFree(A(At(va))), "register-only leaf is write free");
            Probe("register-only leaf", va, site, A(f.agent.data()), {}, A(f.agent.data()), Inactive, {rs[0], rs[1]}, true,
                [&] { CallService(A(At(va)), A(f.agent.data()), CallAbi::Word0); });
        }
        Require(CallService(A(At(0x4470b0)), A(f.agent.data()), CallAbi::Word0) == A(f.agent.data()), "4470B0 returns this");
        Require(!brain::WorkerWriteFree(A(At(0x7ee750))) && !brain::WorkerWriteFree(A(At(0x66b080))),
            "own-writing leaves are not write free");
        Probe("non-leaf virtual is not accepted by byte pattern", 0x57e1f0, site, A(f.agent.data()), {}, A(f.agent.data()),
            Unresolved, {rs[0]}, false, [] {});
    }
    // ---- holder dispatchers (disabled / done / actual leaf method / non-leaf)
    {
        struct Disp { U va; U slot; int abi; };
        const Disp disp[] = {{0x811870, 0xc, 0}, {0x805880, 0x14, 1}, {0x8058c0, 0x28, 2}, {0x805900, 0x24, 1}};
        std::array<U, 16> badTable{};
        for (const Disp& d : disp) {
            for (int mode = 0; mode < 6; ++mode) {
                Fixture f; f.Init(world, Spec{4,0,9}, 401);
                const U h = A(f.agent.data() + 0x2cc);
                const Region rs[] = {{"fixture", &f, sizeof f, false}, {"world", &world, sizeof(World), false}};
                // 0 disabled; 1 stub table; 2 reference-node table; 3 non-leaf slot; 4 done byte + non-leaf slot; 5 foreign holder
                badTable.fill(A(At(0x444b60)));
                if (mode == 3 || mode == 4) badTable[d.slot / 4] = A(At(0x57e1f0));
                U table = A(At(0x13336b0));
                if (mode == 2) table = A(At(0x1334180));
                if (mode == 3 || mode == 4) table = A(badTable.data());
                Put(f.agent.data(), 0x2cc + 0x8f, B(mode == 0 ? 0 : 1));
                Put(f.agent.data(), 0x2cc + 8, table);
                if (mode == 4) Put(f.agent.data(), 0x2cc + 0x18, B(1));
                const bool inactive = mode == 0 || mode == 1 || mode == 2 || (mode == 4 && d.va == 0x805880);
                const U entity = mode == 5 ? 0 : A(f.agent.data());
                // 8058C0 enabled would tail into a plain-RET leaf with a pushed argument: classify only.
                const bool exec = mode == 0 || (d.abi != 2 && mode != 4) || (mode == 4 && d.va == 0x805880);
                Probe("holder dispatcher", d.va, site, h, {}, entity,
                    mode == 5 ? Unresolved : inactive ? Inactive : Unresolved, {rs[0], rs[1]}, exec, [&] {
                    if (d.abi == 0) CallService(A(At(d.va)), h, CallAbi::Word0);
                    else if (d.abi == 1) CallService(A(At(d.va)), h, CallAbi::Byte0);
                    else reinterpret_cast<B (__thiscall*)(void*, U)>(At(d.va))(f.agent.data() + 0x2cc, 5);
                });
            }
        }
    }
    // ---- dispatch witness: battle manager and unit predicates
    static BattleBlock bb; static UnitBlock ub; static std::array<B, 0x268> manager;
    static std::array<U, 4> list; static UnitBlock other;
    bb = BattleBlock{}; ub = UnitBlock{}; other = UnitBlock{}; manager.fill(0);
    {
        Put(bb.root.data(), 8, A(bb.model.data())); Put(bb.model.data(), 0xb0, A(bb.manager.data()));
        Put(bb.manager.data(), 0x198, A(bb.state.data()));
        Put(bb.state.data(), 0x10, A(bb.table.data())); Put(bb.state.data(), 0x24, U(0));
        bb.table[0] = A(bb.entry.data());
        Fixture f; f.Init(world, Spec{4,0,9}, 402);
        Put(f.agent.data(), 0x28, A(bb.root.data())); Put(f.agent.data(), 0x1f0, A(ub.unit.data()));
        list[0] = A(f.agent.data());
        Put(manager.data(), 0x260, U(1)); Put(manager.data(), 0x264, A(list.data()));
        const U agent = A(f.agent.data()), unit = A(ub.unit.data()), M = A(bb.manager.data());
        auto Setup = [&](U aa0, U c2c, B m2704, U type, U count, U n2cc, U c930) {
            Put(ub.unit.data(), 0xaa0, aa0); Put(ub.unit.data(), 0xc2c, c2c); Put(bb.manager.data(), 0x2704, m2704);
            Put(ub.desc.data(), 0x1c, type); Put(ub.attached.data(), 0x10, count); Put(ub.unit.data(), 0x2cc, n2cc);
            Put(ub.unit.data(), 0x930, c930);
            Put(ub.unit.data(), 0x16c, U(3)); Put(ub.unit.data(), 0xc70, U(1));
            Put(ub.desc.data(), 0xe4 + 4, A(ub.statrec.data()));
            Put(ub.unit.data(), 0xdb8, U(2)); Put(ub.unit.data(), 0xdbc, A(ub.abilities.data()));
            ub.abilityKeys[0] = 0x11; ub.abilityKeys[1] = 0xf;
            for (U i = 0; i < 2; ++i) {
                Put(ub.abilities.data(), i * 0x2c + 4, A(&ub.abilityKeys[i]));
                Put(ub.abilities.data(), i * 0x2c + 0x28, B(i == 1));
            }
            Put(ub.unit.data(), 0x2c, A(ub.desc.data())); Put(ub.unit.data(), 0x1f4, A(ub.attached.data()));
            Put(ub.unit.data(), 0xc00, A(bb.root.data())); Put(ub.unit.data(), 0x14, A(bb.root.data()));
            Put(ub.unit.data(), 0xadc, A(ub.group.data()));
            brain::WitnessBegin(A(manager.data()));
        };
        const Region unitRegions[] = {{"fixture", &f, sizeof f, false}, {"world", &world, sizeof(World), false},
            {"unit", &ub, sizeof ub, false}, {"battle", &bb, sizeof bb, false}};
        auto Unit0 = [&](const char* what, U va, brain::Classification expect, bool exec = true) {
            Probe(what, va, 0x66d550, unit, {}, agent, expect,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, exec,
                [&] { CallService(A(At(va)), unit, CallAbi::Byte0); });
        };
        // Witness open, nothing mutated: every branch of 53EEE0's inline path.
        for (U aa0 : {0u, 1u, 2u, 3u}) for (B m : {B(0), B(1)}) for (U c2c : {2u, 3u, 4u, 5u}) for (U n2cc : {0u, 5u}) {
            Setup(aa0, c2c, m, 1, 0, n2cc, 0);
            Unit0("53EEE0 count zero path", 0x53eee0, Inactive);
        }
        Setup(1, 4, 1, 1, 0, 0, 3); Unit0("53EEE0 nonzero member count dispatches Q.vt+34", 0x53eee0, Unresolved, false);
        // GateClassify3: Q = U+398 + U+934*90, Q.vt+34 a register-only stub. AL=0 (462CB0) continues into the
        // witnessed 55C480 path, AL=1 (447880) returns at once. U+934 and Q.vt are unit fields 26/27.
        {
            const U q = 0x398 + 0x90;
            for (U slotVa : {0x1312328u /*462CB0*/, 0x131224cu /*447880*/, 0x13121c8u /*461180*/}) {
                Put(ub.unit.data(), 0x934, U(1)); Put(ub.unit.data(), q, A(At(slotVa)) - 0x34);
                for (U aa0 : {0u, 1u, 3u}) {
                    Setup(aa0, 4, 1, 1, 0, 0, 3);
                    U got = 9;
                    Probe("53EEE0 Q.vt+34 register-only stub", 0x53eee0, 0x66d550, unit, {}, agent, Inactive,
                        {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                        [&] { got = CallService(A(At(0x53eee0)), unit, CallAbi::Byte0) & 0xff; });
                    if (slotVa == 0x131224cu) Require(got == 1, "447880 makes 53EEE0 return 1");
                }
            }
            Put(ub.unit.data(), q, A(At(0x132b880)) - 0x34); // Q.vt+34 = 6A7DD0: not a leaf
            Setup(1, 4, 1, 1, 0, 0, 3); Unit0("53EEE0 Q.vt+34 non-leaf", 0x53eee0, Unresolved, false);
            Put(ub.unit.data(), q, A(At(0x1312328)) - 0x34);
            Setup(1, 4, 1, 1, 0, 0, 3);
            Put(ub.unit.data(), 0x934, U(0));
            Unit0("53EEE0 refused after U+934 changed", 0x53eee0, Unresolved, false);
            Require(brain::WitnessEnd() == 0, "an unconsumed unit change is not a violation");
            Put(ub.unit.data(), 0x934, U(1)); Setup(1, 4, 1, 1, 0, 0, 3);
            Put(ub.unit.data(), q, A(At(0x131224c)) - 0x34);
            Unit0("53EEE0 refused after Q.vt changed", 0x53eee0, Unresolved, false);
            Put(ub.unit.data(), 0x934, U(0)); Put(ub.unit.data(), q, U(0));
        }
        // Type predicates over every descriptor type and attached-count branch.
        for (U type = 0; type < 7; ++type) for (U count : {0u, 2u}) {
            Setup(1, 4, 1, type, count, 0, 0);
            Unit0("55AB90 type/attached predicate", 0x55ab90, Inactive);
            Unit0("55ABF0 with ability table witnessed", 0x55abf0, Inactive);
            Unit0("55C1C0 with ability table witnessed", 0x55c1c0, Inactive);
            Unit0("55C2A0 with ability table witnessed", 0x55c2a0, Inactive);
            Unit0("55C4B0 with ability table witnessed", 0x55c4b0, Inactive);
            if (type == 3 && count == 0) {
                Put(ub.abilities.data(), 0x2c + 0x28, B(0)); brain::WitnessBegin(A(manager.data()));
                Unit0("55C2A0 with ability present but disabled", 0x55c2a0, Inactive);
                Put(ub.abilities.data(), 0x2c + 0x28, B(1));
            }
            Put(ub.unit.data(), 0x16c, U(type)); brain::WitnessBegin(A(manager.data()));
            Unit0("55C4B0 with U+16C variant", 0x55c4b0, Inactive);
        }
        // 55C2E0 on the soldier's active-entry group: empty group returns 0 without dispatch.
        Setup(1, 4, 1, 1, 0, 0, 0); Put(ub.group.data(), 0x460, U(0)); brain::WitnessBegin(A(manager.data()));
        Probe("55C2E0 empty group", 0x55c2e0, 0x66d699, A(ub.group.data()), {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
            [&] { Require(!CallService(A(At(0x55c2e0)), A(ub.group.data()), CallAbi::Byte0), "empty group returns false"); });
        Put(ub.group.data(), 0x460, U(1)); brain::WitnessBegin(A(manager.data()));
        Probe("55C2E0 nonempty group dispatches a virtual", 0x55c2e0, 0x66d699, A(ub.group.data()), {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Probe("55C2E0 foreign group", 0x55c2e0, 0x66d699, A(other.group.data()), {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Put(ub.group.data(), 0x460, U(0)); brain::WitnessBegin(A(manager.data()));
        // Battle manager predicates: every phase.
        for (U phase = 0; phase < 8; ++phase) {
            Setup(1, 4, 1, 1, 0, 0, 0); Put(bb.manager.data(), 0x14, phase); brain::WitnessBegin(A(manager.data()));
            U r1 = 0, r2 = 0;
            Probe("55AC60 battle phase predicate", 0x55ac60, 0x66d62b, M, {}, agent, Inactive,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                [&] { r1 = CallService(A(At(0x55ac60)), M, CallAbi::Byte0) & 0xff; });
            Probe("55AD60 battle phase predicate", 0x55ad60, 0x66dd47, M, {}, agent, Inactive,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                [&] { r2 = CallService(A(At(0x55ad60)), M, CallAbi::Byte0) & 0xff; });
            Require(r1 == U(phase >= 2 && phase <= 5) && r2 == U(phase <= 1), "native predicate tables match the pinned reading");
            // Mutation after the snapshot: per-call validation refuses, End counts it.
            Put(bb.manager.data(), 0x14, phase + 1);
            Probe("55AC60 refused after the phase changed", 0x55ac60, 0x66d62b, M, {}, agent, Unresolved,
                {unitRegions[0]}, false, [] {});
            Require(brain::WitnessEnd() != 0, "witness end reports the changed battle phase");
            Probe("witness closed refuses witness-dependent gates", 0x55ac60, 0x66d62b, M, {}, agent, Unresolved,
                {unitRegions[0]}, false, [] {});
        }
        // Animation manager predicates 5DBB30/5DBD60 (S = M+198, entry+10 in {0,1,2}).
        for (U value = 0; value < 3; ++value) {
            Setup(1, 4, 1, 1, 0, 0, 0); Put(bb.entry.data(), 0x10, value); brain::WitnessBegin(A(manager.data()));
            const U S = A(bb.state.data());
            U r1 = 9, r2 = 9;
            Probe("5DBB30 animation state", 0x5dbb30, 0x670fac, S, {}, agent, Inactive,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                [&] { r1 = CallService(A(At(0x5dbb30)), S, CallAbi::Byte0) & 0xff; });
            Probe("5DBD60 animation state", 0x5dbd60, 0x670fda, S, {}, agent, Inactive,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                [&] { r2 = CallService(A(At(0x5dbd60)), S, CallAbi::Byte0) & 0xff; });
            Require(r1 == U(value == 0) && r2 == U(value == 1), "native animation predicates match the pinned reading");
            Probe("animation predicate on a foreign state object", 0x5dbb30, 0x670fac, A(other.group.data()), {}, agent,
                Unresolved, {unitRegions[0]}, false, [] {});
            Put(bb.entry.data(), 0x10, value + 1);
            Probe("animation predicate refused after the state changed", 0x5dbb30, 0x670fac, S, {}, agent, Unresolved,
                {unitRegions[0]}, false, [] {});
            Require(brain::WitnessEnd() != 0, "witness end reports the changed animation state");
        }
        // 64F8F0: null unit / DA4==1 short path / battle-witnessed 55B0A0 path.
        for (int mode = 0; mode < 4; ++mode) {
            Setup(1, 4, 1, 1, 0, 0, 0);
            Put(ub.unit.data(), 0xda4, B(mode == 1 ? 1 : 0)); Put(ub.unit.data(), 0xd9e, B(mode == 2 ? 1 : 0));
            Put(f.agent.data(), 0x1f0, mode == 0 ? U(0) : unit); Put(bb.manager.data(), 0x14, U(mode == 3 ? 3 : 0));
            brain::WitnessBegin(A(manager.data()));
            Probe("64F8F0 unit active predicate", 0x64f8f0, 0x66dd94, agent, {}, agent, Inactive,
                {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true,
                [&] { CallService(A(At(0x64f8f0)), agent, CallAbi::Byte0); });
        }
        // A unit not captured at dispatch start is refused.
        Put(f.agent.data(), 0x1f0, unit);
        Setup(1, 4, 1, 1, 0, 0, 0);
        Put(f.agent.data(), 0x1f0, A(other.unit.data()));
        Probe("unit outside the witnessed worklist", 0x64f8f0, 0x66dd94, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Put(f.agent.data(), 0x1f0, unit);
        Probe("unit predicate on an unwitnessed unit", 0x55ab90, 0x654465, A(other.unit.data()), {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        // 649520 unit stat getter: unit branch, null branch, army branch, foreign receiver.
        Setup(1, 4, 1, 1, 0, 0, 0);
        Put(f.agent.data(), 0x1f0, unit); Put(f.agent.data(), 0x1f8, U(0));
        Probe("649520 unit stat getter", 0x649520, 0x6544db, agent, {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true, [&] {
                Require(CallService(A(At(0x649520)), agent, CallAbi::Word0) == A(ub.statrec.data()),
                    "unit stat table entry returned");
            });
        Put(ub.desc.data(), 0xe4 + 4, A(ub.statrec.data() + 8));
        Probe("649520 after the descriptor table changed", 0x649520, 0x6544db, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Put(ub.desc.data(), 0xe4 + 4, A(ub.statrec.data()));
        Put(f.agent.data(), 0x1f0, U(0)); Put(f.agent.data(), 0x1f8, U(0));
        Probe("649520 null unit and army", 0x649520, 0x6544db, agent, {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true, [&] {
                Require(!CallService(A(At(0x649520)), agent, CallAbi::Word0), "null unit and army returns zero");
            });
        // Army branch (null unit): [[A+1F8]+218 + A+374*4 + E4] with the caller's
        // entry+10, army-witnessed. Index 2 -> live entry, 3 -> null entry.
        Put(ub.army.data(), 0x218, A(ub.armyTable.data()));
        Put(ub.armyTable.data(), 0xe4 + 2 * 4, A(ub.armyStat.data()));
        Put(ub.armyStat.data(), 0x10, 1.25f);
        Put(f.agent.data(), 0x1f8, A(ub.army.data())); Put(f.agent.data(), 0x374, U(2));
        brain::WitnessBegin(A(manager.data()));
        Probe("649520 army stat getter", 0x649520, 0x6544db, agent, {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true, [&] {
                Require(CallService(A(At(0x649520)), agent, CallAbi::Word0) == A(ub.armyStat.data()),
                    "army stat table entry returned");
            });
        Put(f.agent.data(), 0x374, U(3));
        Probe("649520 army null entry", 0x649520, 0x6544db, agent, {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true, [&] {
                Require(!CallService(A(At(0x649520)), agent, CallAbi::Word0), "null army entry returns zero");
            });
        Put(f.agent.data(), 0x374, U(8));
        Probe("649520 army index outside the snapshot", 0x649520, 0x6544db, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Put(f.agent.data(), 0x374, U(2));
        Probe("649520 army foreign receiver", 0x649520, 0x6544db, agent, {}, 0, Unresolved,
            {unitRegions[0]}, false, [] {});
        Put(ub.armyStat.data(), 0x10, 2.5f);
        Probe("649520 army entry+10 changed", 0x649520, 0x6544db, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Require(brain::WitnessEnd() != 0, "witness end reports the changed consumed army entry");
        Put(ub.armyStat.data(), 0x10, 1.25f);
        Put(ub.army.data(), 0x218, U(0)); brain::WitnessBegin(A(manager.data()));
        Probe("649520 army with a null table", 0x649520, 0x6544db, agent, {}, agent, Inactive,
            {unitRegions[0], unitRegions[1], unitRegions[2], unitRegions[3]}, true, [&] {
                Require(!CallService(A(At(0x649520)), agent, CallAbi::Word0), "null army table returns zero");
            });
        Put(ub.army.data(), 0x218, A(ub.armyTable.data()));
        Probe("649520 army table installed after Begin", 0x649520, 0x6544db, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        Require(brain::WitnessEnd() != 0, "witness end reports the installed army table");
        brain::WitnessBegin(A(manager.data()));
        Put(f.agent.data(), 0x1f8, U(0x1000));
        Probe("649520 unwitnessed army", 0x649520, 0x6544db, agent, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        // Worker witness dependencies: recorded per proof, de-duplicated, rechecked.
        {
            Put(f.agent.data(), 0x1f0, unit); Put(f.agent.data(), 0x1f8, U(0));
            Setup(1, 4, 1, 1, 0, 0, 0);
            U gate[8] = {};
            const U stat = A(At(0x649520)), phase = A(At(0x55ac60));
            brain::WitnessDeps deps{};
            Require(brain::WorkerClassify(stat, 0x6544db, agent, gate, agent, nullptr, &deps) == Inactive &&
                    deps.count == 1 && !deps.overflow && deps.items[0].kind == brain::WitnessDepUnit &&
                    deps.items[0].key == unit, "unit proof records one unit dependency");
            Require(brain::WorkerForwardable(stat, 0x6544db, agent, gate, agent, &deps) && deps.count == 1,
                "repeated proofs are de-duplicated");
            Require(brain::WorkerClassify(phase, 0x66d62b, M, gate, agent, nullptr, &deps) == Inactive &&
                    deps.count == 2 && deps.items[1].kind == brain::WitnessDepBattle && deps.items[1].key == M,
                "battle proof records the manager");
            brain::WitnessDeps none{};
            Require(brain::WorkerClassify(stat, 0x6544db, agent, gate, agent, nullptr, nullptr) == Inactive &&
                    brain::WorkerClassify(stat, 0x6544db, agent, gate, agent, nullptr, &none) == Inactive &&
                    none.count == 1 && deps.count == 2, "a null sink records nothing and sinks do not leak");
            Require(brain::WitnessDepsHold(deps), "unchanged dependencies hold");
            Put(ub.unit.data(), 0xc2c, U(5));
            Require(!brain::WitnessDepsHold(deps), "a changed unit field breaks the dependency");
            Put(ub.unit.data(), 0xc2c, U(4));
            U phase0; std::memcpy(&phase0, bb.manager.data() + 0x14, sizeof phase0);
            Put(bb.manager.data(), 0x14, phase0 + 1);
            Require(!brain::WitnessDepsHold(deps), "a changed battle phase breaks the dependency");
            Put(bb.manager.data(), 0x14, phase0);
            Require(brain::WitnessDepsHold(deps), "restored values hold");
            brain::WitnessDeps full{};
            for (U i = 0; i < brain::kWitnessDepCap; ++i) full.items[i] = brain::WitnessDep{brain::WitnessDepBattle, 0x100 + i, 0};
            full.count = brain::kWitnessDepCap;
            Require(brain::WorkerClassify(stat, 0x6544db, agent, gate, agent, nullptr, &full) == Inactive &&
                    full.overflow && full.count == brain::kWitnessDepCap, "a ninth dependency overflows");
            Require(!brain::WitnessDepsHold(full), "an overflowed set never holds");
            Put(f.agent.data(), 0x1f0, U(0)); Put(f.agent.data(), 0x1f8, A(ub.army.data()));
            brain::WitnessBegin(A(manager.data()));
            brain::WitnessDeps army{};
            Require(brain::WorkerClassify(stat, 0x6544db, agent, gate, agent, nullptr, &army) == Inactive &&
                    army.count == 1 && army.items[0].kind == brain::WitnessDepArmy &&
                    army.items[0].key == A(ub.army.data()) && army.items[0].frame == 2, "army proof records army and index");
            Put(ub.armyStat.data(), 0x10, 3.0f);
            Require(!brain::WitnessDepsHold(army), "a changed army entry breaks the dependency");
            Put(ub.armyStat.data(), 0x10, 1.25f);
            Require(brain::WitnessDepsHold(army), "restored army entry holds");
            brain::WitnessAbort();
            Require(!brain::WitnessDepsHold(army), "a closed witness never holds");
            Put(f.agent.data(), 0x1f8, U(0));
        }
        Setup(1, 4, 1, 1, 0, 0, 0);
        Put(f.agent.data(), 0x1f0, unit); Put(f.agent.data(), 0x1f8, U(0));
        Probe("649520 foreign receiver", 0x649520, 0x6544db, agent, {}, 0, Unresolved,
            {unitRegions[0]}, false, [] {});
        // 66EE30 live slot: slot record/header/rows witnessed, vt+CC=660020.
        Setup(1, 4, 1, 1, 0, 0, 0);
        Fixture sf; sf.Init(world, Spec{4,0,9,0,4,0x20}, 409);
        const U sa = A(sf.agent.data());
        Put(sf.agent.data(), 0x28, A(bb.root.data())); Put(sf.agent.data(), 0x1f0, unit);
        std::array<U, 0x80> svt;
        std::memcpy(svt.data(), At(0x1333714), sizeof(svt)); svt[0xcc / 4] = A(At(0x660020));
        Put(sf.agent.data(), 0, A(svt.data()));
        list[0] = sa; brain::WitnessBegin(A(manager.data()));
        const Region slotRegions[] = {{"soldier", &sf, sizeof sf, true}, {"world", &world, sizeof(World), false},
            {"unit", &ub, sizeof ub, false}, {"battle", &bb, sizeof bb, false}};
        Probe("66EE30 live slot with witnessed rows", 0x66ee30, 0x654740, sa, {}, sa, Inactive,
            {slotRegions[0], slotRegions[1], slotRegions[2], slotRegions[3]}, true, [&] {
                CallService(A(At(0x66ee30)), sa, CallAbi::Void0);
            });
        Put(sf.agent.data(), 0x1c0, U(0)); Put(sf.rows.data(), 0xc, uint16_t(999));
        Probe("66EE30 refused after a slot row changed", 0x66ee30, 0x654740, sa, {}, sa, Unresolved,
            {slotRegions[0]}, false, [] {});
        Require(brain::WitnessEnd() != 0, "witness end reports the changed slot row");
        svt[0xcc / 4] = A(At(0x5aa400)); Put(sf.rows.data(), 0xc, uint16_t(123));
        brain::WitnessBegin(A(manager.data()));
        Probe("66EE30 foreign vt+CC callback", 0x66ee30, 0x654740, sa, {}, sa, Unresolved,
            {slotRegions[0]}, false, [] {});
        {
            // GateClassify3: frame indices beyond the former 64-row snapshot (kSlotRows is now 256).
            static std::array<B, 28 * 100> longRows; static std::array<B, 0x60> longAnim; static std::array<B, 0x40> longHeader;
            static std::array<U, 3> longSlot;
            for (U row = 0; row < 100; ++row) {
                Put(longRows.data(), 28 * row + 0xc, uint16_t(511 + row));
                Put(longRows.data(), 28 * row + 0x10, 0.125f * (row % 7 + 1));
                Put(longRows.data(), 28 * row + 0x14, -0.0625f * (row % 5 + 1));
                Put(longRows.data(), 28 * row + 0x18, 0.25f * (row % 3 + 1));
            }
            Put(longAnim.data(), 0x50, U(100)); Put(longHeader.data(), 0x14, uint16_t(123));
            Put(longHeader.data(), 0x38, A(longRows.data()));
            longSlot = {0x20, A(longAnim.data()), A(longHeader.data())};
            svt[0xcc / 4] = A(At(0x660020));
            Put(sf.agent.data(), 0x444, A(longSlot.data())); Put(sf.agent.data(), 0x1c0, U(70));
            brain::WitnessBegin(A(manager.data()));
            const Region longRegions[] = {{"soldier", &sf, sizeof sf, true}, {"world", &world, sizeof(World), false},
                {"rows", &longRows, sizeof longRows, false}, {"animation", &longAnim, sizeof longAnim, false}};
            Probe("66EE30 frame 70 of a 100-row animation", 0x66ee30, 0x654740, sa, {}, sa, Inactive,
                {longRegions[0], longRegions[1], longRegions[2], longRegions[3]}, true, [&] {
                    CallService(A(At(0x66ee30)), sa, CallAbi::Void0);
                });
            Put(sf.agent.data(), 0x1c0, U(70));
            brain::WitnessDeps deps{};
            U gate[4] = {};
            Require(brain::WorkerClassify(A(At(0x66ee30)), 0x654740, sa, gate, sa, nullptr, &deps) == Inactive &&
                    deps.count == 1 && deps.items[0].kind == brain::WitnessDepSlot && deps.items[0].frame == 70 &&
                    brain::WitnessDepsHold(deps), "row 70 is a slot dependency that holds");
            Put(longRows.data(), 28 * 70 + 0x10, 9.0f);
            Require(!brain::WitnessDepsHold(deps), "a changed row 70 breaks it");
            Put(longRows.data(), 28 * 70 + 0x10, 0.125f * (70 % 7 + 1));
            // §19.3: the dependency is exactly 66EE30/66EEB0's read set. Row 70 bytes +0..+B, other rows, the high
            // word of H+14 and (off frame 0) its low word are not read: changing them keeps the proof.
            Put(longRows.data(), 28 * 70 + 0x4, 0xabcdu); Put(longRows.data(), 28 * 71 + 0x10, 5.0f);
            Put(longHeader.data(), 0x16, uint16_t(0x7777)); Put(longHeader.data(), 0x14, uint16_t(77));
            Require(brain::WitnessDepsHold(deps), "unread row bytes and the off-frame H+14 do not break the slot");
            Require(brain::WitnessEnd() == 0, "witness end ignores unread slot bytes");
            Put(longHeader.data(), 0x14, uint16_t(123)); Put(longHeader.data(), 0x16, uint16_t(0));
            Put(longRows.data(), 28 * 70 + 0x4, 0u); Put(longRows.data(), 28 * 71 + 0x10, 0.125f * (71 % 7 + 1));
            brain::WitnessBegin(A(manager.data()));
            // Frame 0 reads the H+14 word: a changed low word refuses with the turn reason; the high word does not.
            Put(sf.agent.data(), 0x1c0, U(0)); deps = brain::WitnessDeps{};
            Require(brain::WorkerClassify(A(At(0x66ee30)), 0x654740, sa, gate, sa, nullptr, &deps) == Inactive &&
                    brain::WitnessDepsHold(deps), "frame 0 records the slot with H+14");
            Put(longHeader.data(), 0x16, uint16_t(0x5555)); Require(brain::WitnessDepsHold(deps), "H+16 is not read");
            Put(longHeader.data(), 0x14, uint16_t(124)); Require(!brain::WitnessDepsHold(deps), "frame 0: H+14 breaks it");
            Put(longHeader.data(), 0x14, uint16_t(123)); Put(longHeader.data(), 0x16, uint16_t(0));
            // A changed header pointer, rows pointer or animation id still refuses.
            longSlot[2] = A(sf.slotHeader.data()); Require(!brain::WitnessDepsHold(deps), "changed header pointer refuses");
            longSlot[2] = A(longHeader.data()); longSlot[0] = 0x21; Require(!brain::WitnessDepsHold(deps), "changed id refuses");
            longSlot[0] = 0x20; Require(brain::WitnessDepsHold(deps), "restored slot holds");
            brain::WitnessAbort(); brain::WitnessBegin(A(manager.data()));
            Put(sf.agent.data(), 0x444, A(sf.slot.data())); Put(sf.agent.data(), 0x1c0, U(0));
        }
        // 8196B0: embedded node + holder byte copy; foreign holder refused.
        Setup(1, 4, 1, 1, 0, 0, 0);
        Fixture nf; nf.Init(world, Spec{4,0,9}, 410);
        const U na = A(nf.agent.data());
        const Region nodeRegions[] = {{"node fixture", &nf, sizeof nf, true}, {"world", &world, sizeof(World), false}};
        Put(nf.agent.data(), 0x2d4 + 0xc, na + 0x228);
        Put(nf.agent.data(), 0x228 + 0x9c, B(1)); Put(nf.agent.data(), 0x228 + 0xc, B(0x7f));
        Probe("8196B0 embedded holder completion copy", 0x8196b0, 0x66e7d4, na + 0x2d4, {}, na, Inactive,
            {nodeRegions[0], nodeRegions[1]}, true, [&] {
                CallService(A(At(0x8196b0)), na + 0x2d4, CallAbi::Void0);
                Require(Get<B>(nf.agent.data(), 0x2d4 + 0x10) == 0x7f, "completion byte copied");
            });
        Put(nf.agent.data(), 0x228 + 0x9c, B(0));
        Probe("8196B0 embedded holder not complete", 0x8196b0, 0x66e7d4, na + 0x2d4, {}, na, Inactive,
            {nodeRegions[0], nodeRegions[1]}, true, [&] {
                CallService(A(At(0x8196b0)), na + 0x2d4, CallAbi::Void0);
                Require(Get<B>(nf.agent.data(), 0x2d4 + 0x10) == 1, "incomplete holder stores 1");
            });
        // 8196D0 -> 805710 -> 8056D0(X+4): X+C==1 selects X+1C in {0: own+1C=0, 1: own+1C=1,
        // other: unchanged}, then own+10=1; X+C!=1 returns untouched. Own node + own holder only.
        for (U mode = 0; mode < 4; ++mode) {
            Put(nf.agent.data(), 0x2d4 + 0xc, na + 0x228);
            Put(nf.agent.data(), 0x228 + 0xc, B(mode == 3 ? 0 : 1)); Put(nf.agent.data(), 0x228 + 0x1c, U(mode));
            Put(nf.agent.data(), 0x2d4 + 0x10, B(0)); Put(nf.agent.data(), 0x2d4 + 0x1c, U(7));
            Probe("8196D0 embedded holder state copy", 0x8196d0, 0x66e7d4, na + 0x2d4, {}, na, Inactive,
                {nodeRegions[0], nodeRegions[1]}, true, [&] {
                    CallService(A(At(0x8196d0)), na + 0x2d4, CallAbi::Void0);
                    Require(Get<B>(nf.agent.data(), 0x2d4 + 0x10) == (mode == 3 ? 0 : 1) &&
                            Get<U>(nf.agent.data(), 0x2d4 + 0x1c) == (mode < 2 ? mode : 7), "8196D0 own-node outputs");
                });
        }
        Put(nf.agent.data(), 0x2d4 + 0xc, A(f.agent.data() + 0x228));
        Probe("8196B0 holder in another soldier", 0x8196b0, 0x66e7d4, na + 0x2d4, {}, na, Unresolved,
            {nodeRegions[0]}, false, [] {});
        Probe("8196D0 holder in another soldier", 0x8196d0, 0x66e7d4, na + 0x2d4, {}, na, Unresolved,
            {nodeRegions[0]}, false, [] {});
        Probe("8196D0 foreign node", 0x8196d0, 0x66e7d4, A(f.agent.data() + 0x2d4), {}, na, Unresolved,
            {nodeRegions[0]}, false, [] {});
        // §19.2 watcher-node begins (cloned BRAIN_W containers): node N = A+22C, holder H = [N+8] = A+224, X = [H] = A.
        {
            for (U va : {0x7ff9e0u, 0x80a190u, 0x7ff5c0u, 0x809d80u})
                Require(brain::CloneIdFor(va) != ~0u, "watcher-node begin/dispatch is a BRAIN_W clone");
            const U saved224 = Get<U>(nf.agent.data(), 0x224), saved22c = Get<U>(nf.agent.data(), 0x22c),
                    saved234 = Get<U>(nf.agent.data(), 0x234);
            Put(nf.agent.data(), 0x22c + 8, na + 0x224); Put(nf.agent.data(), 0x224, na);
            for (U va : {0x7ff9e0u, 0x80a190u, 0x7ff5c0u, 0x809d80u}) {
                Probe("watcher-node begin on own node/holder", va, 0x66e7bf, na + 0x22c, {}, na, Inactive, {nodeRegions[0]}, false, [] {});
                Put(nf.agent.data(), 0x224, A(f.agent.data()));
                Probe("watcher-node begin dispatching another soldier", va, 0x66e7bf, na + 0x22c, {}, na, Unresolved,
                    {nodeRegions[0]}, false, [] {});
                Put(nf.agent.data(), 0x224, na); Put(nf.agent.data(), 0x22c + 8, A(f.agent.data() + 0x224));
                Probe("watcher-node begin with a foreign holder", va, 0x66e7bf, na + 0x22c, {}, na, Unresolved,
                    {nodeRegions[0]}, false, [] {});
                Put(nf.agent.data(), 0x22c + 8, na + 0x224);
                Probe("watcher-node begin on a foreign node", va, 0x66e7bf, A(f.agent.data() + 0x22c), {}, na, Unresolved,
                    {nodeRegions[0]}, false, [] {});
            }
            // Their destructors at 650DE4/650624 (`push 1`): own node, store [N] = 1321210 only, no free.
            for (U va : {0x7edf70u, 0x7ede80u}) {
                Put(nf.agent.data(), 0x22c, 0xdeadbeefu);
                Probe("watcher-node destructor without free", va, 0x650de4, na + 0x22c, {1}, na, Inactive,
                    {nodeRegions[0], nodeRegions[1]}, true, [&] {
                        reinterpret_cast<U (__thiscall*)(void*, U)>(At(va))(nf.agent.data() + 0x22c, 1);
                    });
                Require(Get<U>(nf.agent.data(), 0x22c) == A(At(0x1321210)), "destructor resets the node vtable");
                Probe("watcher-node destructor that frees", va, 0x650de4, na + 0x22c, {5}, na, Unresolved, {nodeRegions[0]}, false, [] {});
                Probe("watcher-node destructor on a foreign node", va, 0x650de4, A(f.agent.data() + 0x22c), {1}, na, Unresolved,
                    {nodeRegions[0]}, false, [] {});
            }
            Put(nf.agent.data(), 0x224, saved224); Put(nf.agent.data(), 0x22c, saved22c); Put(nf.agent.data(), 0x234, saved234);
        }
        // §19.4 80B080 (parked 67A4E0): own soldier, caller-stack vector; stores only own D4..E0/148/18C.
        {
            float vec[2] = {3.0f, -2.0f};
            Put(nf.agent.data(), 0x18, U(0)); Put(nf.agent.data(), 0x48, 1.0f); Put(nf.agent.data(), 0x50, 2.0f);
            Put(nf.agent.data(), 0x18c, B(0));
            Probe("80B080 parked motion output", 0x80b080, 0x67a4e0, na, {A(vec), 0x1234}, na, Inactive,
                {nodeRegions[0], nodeRegions[1]}, true, [&] {
                    reinterpret_cast<void (__thiscall*)(void*, U, U)>(At(0x80b080))(nf.agent.data(), A(vec), 0x1234);
                });
            Require(Get<B>(nf.agent.data(), 0x18c) == 1 && Get<float>(nf.agent.data(), 0xd4) == 2.0f &&
                    Get<float>(nf.agent.data(), 0xdc) == -4.0f, "80B080 own motion outputs");
            static float staticVector[2] = {3.0f, -2.0f};
            Probe("80B080 static vector", 0x80b080, 0x67a4e0, na, {A(staticVector)}, na, Unresolved, {nodeRegions[0]}, false, [] {});
            Put(nf.agent.data(), 0x18, A(f.agent.data()));
            Probe("80B080 attached early-out", 0x80b080, 0x67a4e0, na, {A(staticVector)}, na, Inactive, {nodeRegions[0], nodeRegions[1]}, false, [] {});
            Put(nf.agent.data(), 0x18, U(0));
            Probe("80B080 on another soldier", 0x80b080, 0x67a4e0, A(f.agent.data()), {A(vec)}, na, Unresolved,
                {nodeRegions[0]}, false, [] {});
        }
        // §19.4 805880 (66D541) on holder A+2CC whose node table 13472A4 holds 55C3E0 (`mov al,[ecx+48]`) at +14.
        {
            const U h = na + 0x2cc;
            const U savedNode = Get<U>(nf.agent.data(), 0x2cc + 8), saved8f = Get<B>(nf.agent.data(), 0x2cc + 0x8f),
                    saved18 = Get<B>(nf.agent.data(), 0x2cc + 0x18), saved50 = Get<B>(nf.agent.data(), 0x2cc + 0x50);
            Put(nf.agent.data(), 0x2cc + 0x8f, B(1)); Put(nf.agent.data(), 0x2cc + 0x18, B(0));
            Put(nf.agent.data(), 0x2cc + 8, A(At(0x13472a4))); Put(nf.agent.data(), 0x2cc + 8 + 0x48, B(1));
            U got = 0;
            Probe("805880 node query 55C3E0", 0x805880, 0x66d541, h, {}, na, Inactive, {nodeRegions[0], nodeRegions[1]}, true,
                [&] { got = CallService(A(At(0x805880)), h, CallAbi::Byte0) & 0xff; });
            Require(got == 1, "805880 returns node+48 through 55C3E0");
            Put(nf.agent.data(), 0x2cc + 8, savedNode); Put(nf.agent.data(), 0x2cc + 0x8f, B(saved8f));
            Put(nf.agent.data(), 0x2cc + 0x18, B(saved18)); Put(nf.agent.data(), 0x2cc + 0x50, B(saved50));
        }
        // 8120F0: empty request reset vs release/new-request/member-list arms.
        Fixture rf; rf.Init(world, Spec{4,0,9}, 411);
        const U ra = A(rf.agent.data());
        const Region reqRegions[] = {{"request fixture", &rf, sizeof rf, true}, {"world", &world, sizeof(World), false}};
        Probe("8120F0 empty request reset", 0x8120f0, 0x6595bf, ra + 0x394, {0}, ra, Inactive,
            {reqRegions[0], reqRegions[1]}, true, [&] {
                reinterpret_cast<U (__thiscall*)(void*, U)>(At(0x8120f0))(rf.agent.data() + 0x394, 0);
            });
        Put(rf.agent.data(), 0x394 + 0x28, U(1));
        Probe("8120F0 nonempty member list", 0x8120f0, 0x6595bf, ra + 0x394, {0}, ra, Unresolved,
            {reqRegions[0]}, false, [] {});
        Put(rf.agent.data(), 0x394 + 0x28, U(0)); Put(rf.agent.data(), 0x394 + 8, U(0x1000));
        Probe("8120F0 releases a shared request", 0x8120f0, 0x6595bf, ra + 0x394, {0}, ra, Unresolved,
            {reqRegions[0]}, false, [] {});
        Put(rf.agent.data(), 0x394 + 8, U(0));
        Probe("8120F0 new request argument", 0x8120f0, 0x6595bf, ra + 0x394, {0x1000}, ra, Unresolved,
            {reqRegions[0]}, false, [] {});
        list[0] = A(f.agent.data());
        brain::WitnessEnd();
        // Mutating a unit field after Begin: counted and refused.
        Setup(0, 4, 1, 1, 0, 0, 0);
        Unit0("53EEE0 consumes the unit proof", 0x53eee0, Inactive);
        Put(ub.unit.data(), 0xaa0, U(1));
        Unit0("53EEE0 refused after U+AA0 changed", 0x53eee0, Unresolved, false);
        Require(brain::WitnessEnd() != 0, "witness end reports the changed consumed unit");
        brain::WitnessBegin(A(manager.data())); brain::WitnessAbort();
        Require(brain::WitnessEnd() == 0, "aborted witness reports nothing");
        Probe("aborted witness refuses unit gates", 0x53eee0, 0x66d550, unit, {}, agent, Unresolved,
            {unitRegions[0]}, false, [] {});
        U words[brain::kUnknownSiteWords]; brain::UnknownSiteSnapshot(words);
        const U* w = words + 2 * brain::kSiteTableWords;
        Require(w[brain::WitnessDispatches] > 20 && w[brain::WitnessUnitsChanged] > 0 && w[brain::WitnessBattleChanged] > 0 &&
            w[brain::WitnessSnapshotFaults] == 0 && w[brain::WitnessUnits] == 1, "witness counters are published");
    }
    // ---- own-soldier leaves
    {
        Fixture f; f.Init(world, Spec{4,0,9}, 403);
        const U a = A(f.agent.data());
        const Region own[] = {{"fixture", &f, sizeof f, true}, {"world", &world, sizeof(World), false}};
        const Region ro[] = {{"fixture", &f, sizeof f, false}, {"world", &world, sizeof(World), false}};
        Probe("62DF10 own slot test", 0x62df10, 0x67a202, a, {}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { CallService(A(At(0x62df10)), a, CallAbi::Byte0); });
        Probe("62DF10 foreign receiver", 0x62df10, 0x67a202, a, {}, 0, Unresolved, {ro[0]}, false, [] {});
        Probe("66EE30 null slot clears A+444 only", 0x66ee30, 0x654740, a, {}, a, Inactive, {own[0], own[1]}, true,
            [&] { CallService(A(At(0x66ee30)), a, CallAbi::Void0); });
        Put(f.agent.data(), 0x444, A(f.slot.data()));
        Probe("66EE30 live slot advances animation", 0x66ee30, 0x654740, a, {}, a, Unresolved, {own[0]}, false, [] {});
        Put(f.agent.data(), 0x444, U(0));
        Put(f.agent.data(), 0x1ec, U(1));
        Probe("63B3E0 target present", 0x63b3e0, 0x66dda0, a, {}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { Require(!CallService(A(At(0x63b3e0)), a, CallAbi::Byte0), "63B3E0 returns false with a target"); });
        Put(f.agent.data(), 0x1ec, U(0));
        Probe("63B3E0 stub query slots", 0x63b3e0, 0x66dda0, a, {}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { CallService(A(At(0x63b3e0)), a, CallAbi::Byte0); });
        std::array<U, 0x80> vt;
        std::memcpy(vt.data(), At(0x1333714), sizeof(vt)); vt[0xec / 4] = A(At(0x57e1f0));
        Put(f.agent.data(), 0, A(vt.data()));
        Probe("63B3E0 non-leaf query slot", 0x63b3e0, 0x66dda0, a, {}, a, Unresolved, {ro[0]}, false, [] {});
        Put(f.agent.data(), 0, A(At(0x1333714)));
        Put(f.agent.data(), 0x66c, U(0));
        Probe("6A7DD0 empty crew list", 0x6a7dd0, 0x66d638, a, {}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { Require(!CallService(A(At(0x6a7dd0)), a, CallAbi::Word0), "empty crew returns null"); });
        Put(f.agent.data(), 0x66c, U(1));
        Probe("6A7DD0 crew virtuals", 0x6a7dd0, 0x66d638, a, {}, a, Unresolved, {ro[0]}, false, [] {});
        Put(f.agent.data(), 0x66c, U(0));
        Put(f.agent.data(), 0x1f0, U(0));
        Probe("66AE10 null unit returns arg0", 0x66ae10, 0x66decd, a, {7, 9}, a, Inactive, {ro[0], ro[1]}, true, [&] {
            Require(reinterpret_cast<U (__thiscall*)(void*, U, U)>(At(0x66ae10))(f.agent.data(), 7, 9) == 7, "returns arg0");
        });
        Put(f.agent.data(), 0x1f0, A(ub.unit.data()));
        Probe("66AE10 unit with nonzero arg0 returns arg0", 0x66ae10, 0x66decd, a, {7, 9}, a, Inactive, {ro[0], ro[1]}, true, [&] {
            Require(reinterpret_cast<U (__thiscall*)(void*, U, U)>(At(0x66ae10))(f.agent.data(), 7, 9) == 7, "returns arg0");
        });
        Probe("66AE10 unit with zero arg0 queries the unit", 0x66ae10, 0x66decd, a, {0, 9}, a, Unresolved, {ro[0]}, false, [] {});
        Put(f.agent.data(), 0x117, B(0));
        Probe("646C20 own cdecl predicate", 0x646c20, 0x665e36, 0xdeadbeef, {a}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { reinterpret_cast<B (__cdecl*)(void*)>(At(0x646c20))(f.agent.data()); });
        Put(f.agent.data(), 0x117, B(1));
        Probe("646C20 own cdecl predicate (live flag branch)", 0x646c20, 0x665e36, 0xdeadbeef, {a}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { reinterpret_cast<B (__cdecl*)(void*)>(At(0x646c20))(f.agent.data()); });
        Probe("646C20 foreign argument", 0x646c20, 0x665e36, 0xdeadbeef, {a + 1}, a, Unresolved, {ro[0]}, false, [] {});
        // Node construction on embedded holders: write set is the soldier only.
        Fixture g; g.Init(world, Spec{4,0,9}, 404);
        const U ga = A(g.agent.data());
        Put(g.agent.data(), 0x228, ga); Put(g.agent.data(), 0x228 + 0xa0, A(world.root.data())); g.slot[0] = ga;
        const Region gr[] = {{"fixture", &g, sizeof g, true}, {"world", &world, sizeof(World), false}};
        Probe("61DA90 reference constructor on own holder", 0x61da90, 0x6590f6, ga + 0x22c, {ga + 0x228, A(g.slot.data())}, ga,
            Inactive, {gr[0], gr[1]}, true, [&] {
                reinterpret_cast<U (__thiscall*)(void*, U, U)>(At(0x61da90))(g.agent.data() + 0x22c, ga + 0x228, A(g.slot.data()));
                Require(Get<U>(g.agent.data(), 0x22c) == A(At(0x1334180)), "reference node vtable published");
            });
        Probe("61DA90 foreign holder", 0x61da90, 0x6590f6, ga + 0x22c, {A(f.agent.data() + 0x228), A(g.slot.data())}, ga,
            Unresolved, {gr[0]}, false, [] {});
        Probe("61DA90 slot cell off the caller stack", 0x61da90, 0x6590f6, ga + 0x22c, {ga + 0x228, A(&world)}, ga,
            Unresolved, {gr[0]}, false, [] {});
        Fixture h; h.Init(world, Spec{4,0,9}, 405);
        const U ha = A(h.agent.data());
        Put(h.agent.data(), 0x228, ha); Put(h.agent.data(), 0x228 + 0xa0, A(world.root.data()));
        const Region hr[] = {{"fixture", &h, sizeof h, true}, {"world", &world, sizeof(World), false}};
        Probe("61D3B0 node base constructor", 0x61d3b0, 0x61d919, ha + 0x22c, {ha + 0x228}, ha, Inactive, {hr[0], hr[1]}, true,
            [&] { reinterpret_cast<U (__thiscall*)(void*, U, U)>(At(0x61d3b0))(h.agent.data() + 0x22c, ha + 0x228, 0); });
        Probe("61D3B0 foreign holder", 0x61d3b0, 0x61d919, ha + 0x22c, {A(f.agent.data() + 0x228)}, ha, Unresolved, {hr[0]}, false, [] {});
        Put(h.agent.data(), 0x22c + 4, ha);
        Probe("662E50 owner store", 0x662e50, 0x81695b, ha + 0x22c, {5}, ha, Inactive, {hr[0], hr[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*, U)>(At(0x662e50))(h.agent.data() + 0x22c, 5);
            Require(Get<U>(h.agent.data(), 0x220) == 5, "owner phase stored through the node link");
        });
        Put(h.agent.data(), 0x22c + 4, A(f.agent.data()));
        Probe("662E50 node linked to another soldier", 0x662e50, 0x81695b, ha + 0x22c, {5}, ha, Unresolved, {hr[0]}, false, [] {});
    }
    // ---- descriptor / request-build copy-only arms (caller-stack outputs)
    {
        Fixture f; f.Init(world, Spec{4,0,9}, 406);
        const U a = A(f.agent.data());
        const Region ro[] = {{"fixture", &f, sizeof f, false}, {"world", &world, sizeof(World), false}};
        alignas(4) B src[0x40], dst[0x40], req[0x40], out[0x40];
        for (U i = 0; i < sizeof src; ++i) { src[i] = B(0x11 + i * 7); dst[i] = B(0xe0 - i); }
        std::vector<B> heap(0x40, 0x5a);
        const Region sd[] = {{"src", src, sizeof src, false}, {"dst", dst, sizeof dst, true}};
        // 7E2040: exact repack with non-identical offsets.
        Probe("7E2040 stack repack", 0x7e2040, 0x658dc9, A(dst), {A(src)}, a, Inactive, {sd[0], sd[1], ro[0], ro[1]}, true, [&] {
            B before[0x40]; std::memcpy(before, dst, sizeof before);
            reinterpret_cast<U (__thiscall*)(void*, void*)>(At(0x7e2040))(dst, src);
            for (U i : {0u, 4u, 8u, 0xcu, 0x10u, 0x14u, 0x18u, 0x1cu, 0x20u}) Require(!std::memcmp(dst + i, src + i, 4), "dword copy");
            Require(!std::memcmp(dst + 0x24, src + 0x24, 2) && dst[0x26] == src[0x26] && dst[0x27] == src[0x27], "word and bytes copy");
            Require(dst[0x28] == src[0x30] && dst[0x29] == src[0x29] && !std::memcmp(dst + 0x2c, src + 0x2c, 4), "moved and kept bytes");
            Require(!std::memcmp(dst + 0x30, src + 0x34, 4) && !std::memcmp(dst + 0x34, src + 0x38, 4), "shifted dwords");
            for (U i = 0x38; i < 0x40; ++i) Require(dst[i] == before[i], "repack never writes past +37");
        });
        Probe("7E2040 heap destination", 0x7e2040, 0x658dc9, A(heap.data()), {A(src)}, a, Unresolved, {ro[0]}, false, [] {});
        Probe("7E2040 heap source", 0x7e2040, 0x658dc9, A(dst), {A(heap.data())}, a, Unresolved, {ro[0]}, false, [] {});
        // 6460E0: both early arms, then the unit-dependent arm (classification only).
        std::memset(req, 0, sizeof req); req[0x26] = 0;
        const Region rq[] = {{"request", req, sizeof req, true}};
        Probe("6460E0 zero heading flag", 0x6460e0, 0x658db4, A(req), {a}, a, Inactive, {rq[0], ro[0], ro[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*, U)>(At(0x6460e0))(req, a); Require(req[0x29] == 1, "request+29 stored");
        });
        req[0x26] = 1; Put(f.agent.data(), 0x1f0, U(0));
        Probe("6460E0 null unit", 0x6460e0, 0x658db4, A(req), {a}, a, Inactive, {rq[0], ro[0], ro[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*, U)>(At(0x6460e0))(req, a); Require(req[0x29] == 1, "request+29 stored");
        });
        Put(f.agent.data(), 0x1f0, U(0x1000));
        Probe("6460E0 unit heading arm", 0x6460e0, 0x658db4, A(req), {a}, a, Unresolved, {rq[0]}, false, [] {});
        Probe("6460E0 heap request", 0x6460e0, 0x658db4, A(heap.data()), {a}, a, Unresolved, {rq[0]}, false, [] {});
        Put(f.agent.data(), 0x1f0, U(0));
        // 659480: prebattle copy arm vs unit/pending arms.
        for (U i = 0; i < 5; ++i) Put(f.agent.data(), 0x4f8 + 4 * i, U(0x3f800000 + i * 0x10000 + 0x77));
        Put(f.agent.data(), 0xb4, B(1)); std::memset(out, 0xcd, sizeof out);
        const Region ot[] = {{"out", out, sizeof out, true}};
        Probe("659480 prebattle copy", 0x659480, 0x66d14a, a, {A(out)}, a, Inactive, {ot[0], ro[0], ro[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*, void*)>(At(0x659480))(f.agent.data(), out);
            Require(!std::memcmp(out, f.agent.data() + 0x4f8, 0x14) && out[0x14] == 0xcd, "five dwords copied exactly");
        });
        Probe("659480 heap output", 0x659480, 0x66d14a, a, {A(heap.data())}, a, Unresolved, {ot[0]}, false, [] {});
        Put(f.agent.data(), 0xb4, B(0));
        Probe("659480 query arm", 0x659480, 0x66d14a, a, {A(out)}, a, Unresolved, {ot[0]}, false, [] {});
        // 66AD00: copy-only null-unit arm.
        Put(f.agent.data(), 0x1f0, U(0));
        for (U i = 0; i < 0x14; ++i) Put(f.agent.data(), 0x5fc + i, B(0x40 + i));
        std::memset(out, 0xcd, sizeof out);
        Probe("66AD00 null-unit copy", 0x66ad00, 0x658ccc, a, {A(out), a + 0x5fc}, a, Inactive, {ot[0], ro[0], ro[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*, void*, void*)>(At(0x66ad00))(f.agent.data(), out, f.agent.data() + 0x5fc);
            Require(!std::memcmp(out, f.agent.data() + 0x5fc, 0x14) && out[0x14] == 0xcd, "five words copied exactly");
        });
        Put(f.agent.data(), 0x1f0, U(0x1000));
        Probe("66AD00 formation arm", 0x66ad00, 0x658ccc, a, {A(out), a + 0x5fc}, a, Unresolved, {ot[0]}, false, [] {});
        // 7EAE90 zero-initialised static defaults; stack and heap destinations.
        std::memset(out, 0xcd, sizeof out);
        Probe("7EAE90 default descriptor", 0x7eae90, 0x64debd, A(out), {}, a, Inactive, {ot[0], ro[0], ro[1]}, true, [&] {
            reinterpret_cast<U (__thiscall*)(void*)>(At(0x7eae90))(out);
            for (U i = 0; i < 0x14; ++i) Require(out[i] == 0, "static defaults are zero in the pinned image");
            Require(out[0x14] == 0xcd, "no write past +13");
        });
        Probe("7EAE90 heap destination", 0x7eae90, 0x64debd, A(heap.data()), {}, a, Unresolved, {ot[0]}, false, [] {});
        // 80E020 draws the shared model RNG; 807490 nonempty compares live member labels.
        Probe("80E020 advances the model LCG", 0x80e020, 0x66e023, a, {}, a, Active, {}, false, [] {});
        Put(f.agent.data(), 0x394 + 0x28, U(1));
        Probe("807490 nonempty label list", 0x807490, 0x659612, a + 0x394, {}, a, Unresolved, {}, false, [] {});
        Put(f.agent.data(), 0x394 + 0x28, U(0));
        Probe("807490 empty label list", 0x807490, 0x659612, a + 0x394, {}, a, Inactive, {ro[0], ro[1]}, true,
            [&] { CallService(A(At(0x807490)), a + 0x394, CallAbi::Byte0); });
    }
    if (std::getenv("KNTWR_ORACLE_TRACE")) std::fprintf(stderr, "block observe\n");
    // ---- observation points
    {
        Fixture f; f.Init(world, Spec{4,0,9}, 407);
        const U a = A(f.agent.data());
        U regs[8] = {};
        for (U s : {0x66d00eu, 0x66d4bbu, 0x66d4d9u, 0x64dec2u, 0x66d5d4u})
            Require(ObserveAt(s, a, regs) == Inactive, "CRT-initialised / zero-BSS globals and the melee label are static");
        for (U s : {0x66d2f3u, 0x658e93u, 0x66d443u, 0x65909fu}) {
            const U offset = s == 0x66d2f3u || s == 0x658e93u ? 0x1ec : 0x5b8;
            Put(f.agent.data(), offset, U(0));
            Require(ObserveAt(s, a, regs) == Inactive, "null target/reference reads nothing");
            if (s == 0x66d2f3u) {
                // The fixture table's vt+F0 is 462CB0 (AL=0): the block reads nothing of the target (GateClassify3).
                Put(f.agent.data(), offset, a);
                Require(ObserveAt(s, a, regs) == Inactive, "AL=0 target predicate ends the reacquire block");
            } else {
                Put(f.agent.data(), offset, U(0x1000));
                Require(ObserveAt(s, a, regs) == Unresolved, "live foreign subject is not static");
            }
            Put(f.agent.data(), offset, U(0));
        }
        U node[0x10] = {};
        regs[0] = A(node);
        Require(ObserveAt(0x6758d6, a, regs) == Inactive, "null reference-follow subject");
        node[0x1c / 4] = 0x1000; Require(ObserveAt(0x6758d6, a, regs) == Unresolved, "live reference-follow subject");
        Require(ObserveAt(0x658f44, a, regs) == Active, "engage is a proved shared store");
        for (U s : {0x62ec97u, 0x62efb3u, 0x80c328u, 0x80da8au})
            Require(ObserveAt(s, a, regs) == Active, "fire candidate/gather stores are active");
        Require(ObserveAt(0x123456, a, regs) == Unresolved, "unknown observation site never proves anything");
        // 658FAE reads U+D9D through the unit witness.
        Put(f.agent.data(), 0x1f0, U(0));
        Require(ObserveAt(0x658fae, a, regs) == Inactive, "null unit");
        Put(f.agent.data(), 0x1f0, A(ub.unit.data())); list[0] = a;
        Put(f.agent.data(), 0x28, A(bb.root.data()));
        brain::WitnessBegin(A(manager.data()));
        Require(ObserveAt(0x658fae, a, regs) == Inactive, "witnessed unit D9D");
        Put(ub.unit.data(), 0xd9d, B(1));
        Require(ObserveAt(0x658fae, a, regs) == Unresolved, "changed unit D9D is refused");
        Require(brain::WitnessEnd() != 0, "end reports the D9D change");
    }
    // ---- 819770 finalizer active arm and 7F14C0 terrain lookahead (native_finalizer.h)
    {
        struct FinalizerWorld {
            std::array<B, 0x10> root{};
            std::array<B, 0x100> model{};
            std::array<B, 0x28> grid{};
            std::array<U, 16 * 16> cells{};
            std::array<B, 0x28> field{};
            std::array<U, 2 * 16 * 16> samples{};   // 64C5F0 reads float [data + index*8]
            std::array<B, 0x200> frame{};
        };
        static FinalizerWorld fw; fw = FinalizerWorld{};
        Put(fw.root.data(), 8, A(fw.model.data()));
        Put(fw.model.data(), 0x58, U(33));
        Put(fw.model.data(), 0x84, -7.0f); Put(fw.model.data(), 0x88, -7.0f);
        Put(fw.model.data(), 0x8c, 7.0f); Put(fw.model.data(), 0x90, 7.0f);
        Put(fw.model.data(), 0x9c, A(fw.field.data())); Put(fw.model.data(), 0xa0, A(fw.grid.data()));
        Put(fw.grid.data(), 0, A(fw.cells.data())); Put(fw.grid.data(), 8, U(4));
        Put(fw.grid.data(), 0x10, U(8)); Put(fw.grid.data(), 0x14, U(15)); Put(fw.grid.data(), 0x24, 1.0f);
        for (U i = 0; i < fw.cells.size(); ++i) fw.cells[i] = (i * 37 & 0xff) | (i % 7 == 0 ? 0x100u : 0u);
        Put(fw.field.data(), 0, A(fw.samples.data())); Put(fw.field.data(), 8, U(4));
        Put(fw.field.data(), 0x10, U(8)); Put(fw.field.data(), 0x14, U(15));
        Put(fw.field.data(), 0x1c, -8.0f); Put(fw.field.data(), 0x20, 1.0f); Put(fw.field.data(), 0x24, 1.0f);
        for (U i = 0; i < 256; ++i) { const float h = 0.125f * (i % 13); std::memcpy(&fw.samples[2 * i], &h, 4); }
        const float frameValues[12] = {1.5f, 0.25f, -2.0f, 0.8f, 0.0f, -0.6f, 0.0f, 1.0f, 0.0f, 0.6f, 0.0f, 0.8f};
        for (U i = 0; i < 3; ++i) Put(fw.frame.data(), 0x80 + 4 * i, frameValues[i]);
        for (U i = 0; i < 9; ++i) Put(fw.frame.data(), 0x9c + 4 * i, frameValues[3 + i]);
        Put(fw.frame.data(), 0x1e4, uint16_t(0x1234));
        Fixture f; f.Init(world, Spec{4,0,9}, 412);
        Fixture foreign; foreign.Init(world, Spec{4,0,9}, 413);
        B* ag = f.agent.data();
        const U a = A(ag), terminal = A(At(0x1454198)), fin = A(At(0x819770)), probe = A(At(0x7f14c0));
        auto Base = [&](U state, U frame) {
            Put(ag, 0x28, A(fw.root.data()));
            Put(ag, 0x18c, B(0)); Put(ag, 0x18, U(0)); Put(ag, 0x10, U(0));
            Put(ag, 0xf4, A(At(0x13338c4))); Put(ag, 0xf8, state); Put(ag, 0xfc, U(3));
            Put(ag, 0x48, 1.25f); Put(ag, 0x4c, 0.5f); Put(ag, 0x50, -2.5f); Put(ag, 0x64, uint16_t(0));
            Put(ag, 0x160, 3.0f); Put(ag, 0x164, 0.0f); Put(ag, 0x168, -1.0f); Put(ag, 0x16c, uint16_t(0x2000));
            Put(ag, 0x170, frame);
            Put(ag, 0x58, 2.0f); Put(ag, 0x8c, 0.3f); Put(ag, 0x94, -0.4f); Put(ag, 0x100, 0.2f);
            Put(ag, 0x10c, 1.5f); Put(ag, 0x128, 0.75f); Put(ag, 0x138, 0.01f); Put(ag, 0x158, 0.5f);
            Put(ag, 0x194, 0.9f); Put(ag, 0xb8, 0.4f); Put(ag, 0xbc, 0.6f);
        };
        list[0] = a; Put(manager.data(), 0x260, U(1)); Put(manager.data(), 0x264, A(list.data()));
        brain::WitnessBegin(A(manager.data()));
        const Region finRegions[] = {
            {"agent head", ag, 0xd4, false}, {"agent finalizer fields", ag + 0xd4, 0x1a8 - 0xd4, true},
            {"agent tail", ag + 0x1a8, f.agent.size() - 0x1a8, false}, {"foreign soldier", &foreign, sizeof foreign, false},
            {"finalizer world", &fw, sizeof fw, false}, {"world", &world, sizeof(World), false}};
        auto Fin = [&](const char* what, brain::Classification expect, bool exec, U receiver = 0) {
            Probe(what, 0x819770, 0x654513, receiver ? receiver : a, {}, a, expect,
                {finRegions[0], finRegions[1], finRegions[2], finRegions[3], finRegions[4], finRegions[5]}, exec,
                [&] { CallService(fin, receiver ? receiver : a, CallAbi::Void0); });
        };
        // Every branch of the closed arm: FSM null/rest state, flag bits, 116 tail, foreign/own/no frame, the
        // 659220 write, 117/119/B6 selectors and the 55AF80 byte.
        U iteration = 0;
        for (U state : {0u, terminal}) for (U flags = 0; flags < 4; ++flags) for (B b116 : {B(0), B(1)})
        for (int frameKind = 0; frameKind < 3; ++frameKind) for (U s1b8 : {1u, 0x19u}) {
            const U frame = frameKind == 0 ? 0 : frameKind == 1 ? A(fw.frame.data()) : a + 0x600;
            Base(state, frame);
            if (frameKind == 2) {
                for (U i = 0; i < 12; ++i) Put(ag, 0x600 + (i < 3 ? 0x80 + 4 * i : 0x9c + 4 * (i - 3)), frameValues[i]);
                Put(ag, 0x600 + 0x1e4, uint16_t(0x777));
            }
            Put(ag, 0x110, flags); Put(ag, 0x116, b116); Put(ag, 0x1b8, s1b8);
            Put(ag, 0x117, B(iteration & 1)); Put(ag, 0x118, B(iteration >> 1 & 1)); Put(ag, 0x119, B(iteration >> 2 & 1));
            Put(ag, 0xb6, B(iteration >> 3 & 1)); Put(ag, 0xec, B(iteration % 3 == 0));
            ++iteration;
            Fin("819770 closed active arm", Inactive, true);
            if (state == terminal) Require(Get<U>(ag, 0xf8) == terminal, "rest state stays installed after one update");
        }
        // --brain-finalizer-shadow mechanism: private-copy original vs live original, bit-exact; an input changed
        // between the two runs must be reported.
        kntwr_finalizer::Configure(true); kntwr_finalizer::Reset();
        for (U state : {0u, terminal}) {
            Base(state, A(fw.frame.data())); Put(ag, 0x110, U(1)); Put(ag, 0x118, B(1));
            kntwr_finalizer::ShadowBefore(a); CallService(fin, a, CallAbi::Void0); kntwr_finalizer::ShadowAfter();
        }
        Require(kntwr_finalizer::Counter(kntwr_finalizer::ShadowCalls) == 2 &&
                kntwr_finalizer::Counter(kntwr_finalizer::ShadowMismatches) == 0 &&
                kntwr_finalizer::Counter(kntwr_finalizer::ShadowFaults) == 0, "shadow copy equals the live original");
        Base(terminal, A(fw.frame.data()));
        kntwr_finalizer::ShadowBefore(a); Put(ag, 0x58, 9.0f); CallService(fin, a, CallAbi::Void0); kntwr_finalizer::ShadowAfter();
        Require(kntwr_finalizer::Counter(kntwr_finalizer::ShadowMismatches) == 1, "shadow reports a diverged live run");
        kntwr_finalizer::Configure(false); kntwr_finalizer::Reset();
        // Dependencies: foreign frame + world, own-part frame needs only the world.
        U gate[4] = {};
        Base(terminal, A(fw.frame.data()));
        brain::WitnessDeps deps{};
        Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 2 &&
                brain::WitnessDepsHold(deps), "819770 records frame and terrain dependencies that hold");
        Put(fw.frame.data(), 0xa0, 0.5f);
        Require(!brain::WitnessDepsHold(deps), "changed frame rotation breaks the frame dependency");
        Put(fw.frame.data(), 0xa0, frameValues[4]); Require(brain::WitnessDepsHold(deps), "restored frame holds");
        Put(fw.frame.data(), 0x1e4, uint16_t(0x1235));
        Require(!brain::WitnessDepsHold(deps), "changed frame heading breaks the frame dependency");
        Put(fw.frame.data(), 0x1e4, uint16_t(0x1234));
        Put(fw.model.data(), 0x58, U(34)); Require(!brain::WitnessDepsHold(deps), "changed model+58 breaks the terrain dependency");
        Put(fw.model.data(), 0x58, U(33));
        Put(fw.grid.data(), 0x24, 2.0f); Require(!brain::WitnessDepsHold(deps), "changed grid scale breaks the terrain dependency");
        Put(fw.grid.data(), 0x24, 1.0f);
        Put(fw.field.data(), 0x20, 2.0f); Require(!brain::WitnessDepsHold(deps), "changed heightfield breaks the terrain dependency");
        Put(fw.field.data(), 0x20, 1.0f);
        const B option = *At(0x150fba4);
        *At(0x150fba4) = B(option ^ 1); Require(!brain::WitnessDepsHold(deps), "changed options byte breaks the terrain dependency");
        *At(0x150fba4) = option; Require(brain::WitnessDepsHold(deps), "restored world holds");
        Base(0, a + 0x600); deps = brain::WitnessDeps{};
        Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 1 &&
                deps.items[0].kind == brain::WitnessDepTerrain, "own-part frame lies in the guarded footprint");
        // Refusals (classification only).
        Base(0, 0); Put(ag, 0x18, A(foreign.agent.data())); Fin("819770 attached object dispatches virtuals", Unresolved, false);
        Base(0, 0); Put(ag, 0x10, A(foreign.agent.data())); Fin("819770 support surface", Unresolved, false);
        Base(A(At(0x1454168)), 0); Fin("819770 non-rest posture state without an animation set", Unresolved, false);
        static std::array<U, 0x50> fsmTable, soldierTable;
        std::memcpy(fsmTable.data(), At(0x13338c4), sizeof fsmTable);
        fsmTable[0x3c / 4] = A(At(0x5d6f60));
        Base(terminal, 0); Put(ag, 0xf4, A(fsmTable.data())); Fin("819770 posture table with another rest state", Unresolved, false);
        Base(0, 0); Put(ag, 0xf4, A(fsmTable.data())); Fin("819770 null posture state ignores the table", Inactive, true);
        std::memcpy(soldierTable.data(), At(0x1333714), sizeof soldierTable);
        soldierTable[0x84 / 4] = A(At(0x57e1f0));
        Base(0, 0); Put(ag, 0, A(soldierTable.data())); Fin("819770 unknown heading virtual", Unresolved, false);
        Put(ag, 0, A(At(0x1333714)));
        Base(0, 0); Put(fw.model.data(), 0x9c, U(0)); Fin("819770 missing heightfield", Unresolved, false);
        Put(fw.model.data(), 0x9c, A(fw.field.data()));
        Base(0, 0); Put(foreign.agent.data(), 0x18c, B(0));
        Fin("819770 on another soldier", Unresolved, false, A(foreign.agent.data()));
        Put(foreign.agent.data(), 0x18c, B(1));
        Base(0, 0); brain::WitnessAbort(); Fin("819770 without an open witness", Unresolved, false);
        brain::WitnessBegin(A(manager.data()));
        Base(0, 0); Put(ag, 0x18c, B(1)); Put(ag, 0x18, A(foreign.agent.data()));
        Fin("819770 parked early-out", Inactive, true);
        Require(Get<U>(ag, 0x154) == 1 && Get<U>(ag, 0x1a0) == 0, "early-out stores own 154/1A0 only");
        // 7F14C0: count = trunc(arg * [1325CAC]); every step samples the grid inside the model bounds.
        const float k = Get<float>(At(0x1325cac), 0);
        Require(k > 0.0f, "7F14C0 sample density constant");
        const Region probeRegions[] = {{"agent", &f, sizeof f, false}, {"finalizer world", &fw, sizeof fw, false},
                                       {"world", &world, sizeof(World), false}};
        for (float steps : {0.0f, 3.5f}) for (int inside = 0; inside < 2; ++inside) for (int blocked = 0; blocked < 2; ++blocked) {
            Base(0, 0);
            if (!inside) Put(ag, 0x48, 30.0f);
            for (U i = 0; i < fw.cells.size(); ++i) fw.cells[i] = (i * 37 & 0xff) | (blocked ? 0x100u : 0u);
            const float arg = steps / k;
            U argBits; std::memcpy(&argBits, &arg, 4);
            B got = 0xcc;
            Probe("7F14C0 terrain lookahead", 0x7f14c0, 0x62e946, a, {argBits}, a, Inactive,
                {probeRegions[0], probeRegions[1], probeRegions[2]}, true,
                [&] { got = reinterpret_cast<B (__thiscall*)(void*, float)>(At(0x7f14c0))(ag, arg); });
            Require(got == B(steps > 0.0f && inside && blocked), "7F14C0 reports a blocked in-bounds cell only");
        }
        Base(0, 0); deps = brain::WitnessDeps{};
        Require(brain::WorkerClassify(probe, 0x62e946, a, gate, a, nullptr, &deps) == Inactive && deps.count == 1 &&
                brain::WitnessDepsHold(deps), "7F14C0 records the terrain dependency");
        Put(fw.model.data(), 0x8c, 6.0f); Require(!brain::WitnessDepsHold(deps), "changed model bounds break 7F14C0's dependency");
        Put(fw.model.data(), 0x8c, 7.0f);
        Probe("7F14C0 on another soldier", 0x7f14c0, 0x62e946, A(foreign.agent.data()), {}, a, Unresolved,
            {probeRegions[0]}, false, [] {});
        brain::WitnessAbort();
        Probe("7F14C0 without an open witness", 0x7f14c0, 0x62e946, a, {}, a, Unresolved, {probeRegions[0]}, false, [] {});
        // ======== GateClassify3 (analysis/native-brain-unknowns.md §18) ========
        brain::WitnessBegin(A(manager.data()));
        // Animation set S = [R+218]: database [S] (+2C row table), slot table [S+10] of kAnimEntries entries;
        // entry +4 -> animation, +44 -> data (+4C / +70 floats).
        struct AnimSet {
            std::array<U, 8> set{};
            std::array<B, 0x40> database{};
            std::array<U, 0x900 / 4> rows{};
            std::array<U, 0x360> table{};
            std::array<std::array<U, 4>, 8> entries{};
            std::array<std::array<U, 0x48 / 4>, 8> animations{};
            std::array<std::array<U, 0x80 / 4>, 8> data{};
            std::array<U, 0x48 / 4> reachHolder{};   // [[S]+1C]: +44 -> reachBlock
            std::array<U, 0x18 / 4> reachBlock{};    // +14: the reach float (10F1200 +0C, then +8)
        };
        static AnimSet as; as = AnimSet{};
        as.set[0] = A(as.database.data()); Put(as.database.data(), 0x2c, A(as.rows.data()));
        as.set[4] = A(as.table.data());
        for (U i = 0; i < 8; ++i) {
            as.entries[i][1] = A(as.animations[i].data());
            as.animations[i][0x44 / 4] = A(as.data[i].data());
            Put(as.data[i].data(), 0x4c, 1.0f + 0.5f * i); Put(as.data[i].data(), 0x70, 0.25f + 0.125f * i);
        }
        Put(as.database.data(), 0x1c, A(as.reachHolder.data()));
        as.reachHolder[0x44 / 4] = A(as.reachBlock.data()); Put(as.reachBlock.data(), 0x14, 1.75f);
        as.table[0] = A(as.entries[0].data());
        for (U i = 0x2f; i <= 0x34; ++i) as.table[i] = A(as.entries[1 + (i - 0x2f)].data());
        as.table[0x20] = A(as.entries[7].data());
        const U rowWords[] = {0x4ac, 0x4c4, 0x4dc, 0x4f4, 0x50c, 0x524, 0x53c, 0x554, 0x56c, 0x584,
                              0x7c4, 0x7dc, 0x7f4, 0x80c, 0x824, 0x83c};
        const Region postureRegions[] = {
            {"agent head", ag, 0xd4, false}, {"agent finalizer fields", ag + 0xd4, 0x1a8 - 0xd4, true},
            {"agent middle", ag + 0x1a8, 0x44c - 0x1a8, false}, {"agent posture animation", ag + 0x44c, 0xc, true},
            {"agent tail", ag + 0x458, f.agent.size() - 0x458, false}, {"foreign soldier", &foreign, sizeof foreign, false},
            {"finalizer world", &fw, sizeof fw, false}, {"world", &world, sizeof(World), false},
            {"animation set", &as, sizeof as, false}};
        // 819770 with every posture state: all 13 singletons, the 66B7E0 slot-index arm on and off, and varied
        // FSM fields so next/enter/update/exit and the animation selection run. Write set: R+D4..+1A7 and
        // R+44C..+457 only; the image .data/.bss (Probe) and the animation set are unchanged.
        U variant = 0, transitions = 0, animated = 0, reached = 0;
        for (U state = 0; state < 13; ++state) for (B b458 : {B(0), B(1)}) for (U k = 0; k < 8; ++k) {
            const U s = A(At(0x1454168 + 4 * state));
            Base(s, k & 1 ? A(fw.frame.data()) : 0);
            Put(ag, 0x218, A(as.set.data())); Put(ag, 0x458, b458); Put(ag, 0x1bc, U(0x20)); Put(ag, 0x1c0, U(k));
            Put(ag, 0x44c, 0xdeadbeefu); Put(ag, 0x454, 0xdeadbeefu);
            const U v = (variant++ * 2654435761u) >> 7;
            for (U i = 0; i < 16; ++i) as.rows[rowWords[i] / 4] = (v >> i) & 1;
            Put(ag, 0x108, U(v % 3));
            Put(ag, 0x110, U((v & 0x1f1) | (v & 0x200 ? 0x400u : 0u) | (v & 0x800 ? 0x4000u : 0u)));
            for (U o = 0x116; o <= 0x11a; ++o) Put(ag, o, B(v >> (o - 0x100) & 1));
            Put(ag, 0x124, uint16_t(v & 0xffff)); Put(ag, 0x126, uint16_t(v >> 9));
            Put(ag, 0x128, 0.5f * (v % 5)); Put(ag, 0x130, B(v >> 3 & 1));
            Put(ag, 0x13c, B(v >> 4 & 1)); Put(ag, 0x13d, B(v >> 5 & 1)); Put(ag, 0x13e, B(v >> 6 & 1));
            Put(ag, 0x142, B(v >> 7 & 1)); Put(ag, 0x144, 1.5f * (v % 4)); Put(ag, 0xfc, U(3));
            // 6616C0/6618D0 select only for R+1D8 <= 3; 66B990 only with R+98 == 0.
            Put(ag, 0x1d8, U(v % 5)); Put(ag, 0x98, U(v >> 13 & 1));
            Probe("819770 posture state closure", 0x819770, 0x654513, a, {}, a, Inactive,
                {postureRegions[0], postureRegions[1], postureRegions[2], postureRegions[3], postureRegions[4],
                 postureRegions[5], postureRegions[6], postureRegions[7], postureRegions[8]}, true,
                [&] { CallService(fin, a, CallAbi::Void0); });
            const U after = Get<U>(ag, 0xf8);
            Require(!after || (after - A(At(0x1454168)) <= 0x30 && (after - A(At(0x1454168))) % 4 == 0),
                "the posture FSM stays on a singleton state");
            if (after != s) ++transitions;
            if (after) reached |= 1u << ((after - A(At(0x1454168))) / 4);
            if (Get<U>(ag, 0x44c) != 0xdeadbeefu || Get<U>(ag, 0x454) != 0xdeadbeefu) ++animated;
        }
        if (std::getenv("KNTWR_ORACLE_TRACE"))
            std::fprintf(stderr, "posture: transitions=%u animated=%u reached=%04X\n", transitions, animated, reached);
        U distinct = 0;
        for (U bits = reached; bits; bits &= bits - 1) ++distinct;
        Require(transitions > 0 && animated > 0 && distinct >= 4,
            "the posture runs cover transitions and the 66B7E0/66B990 selection");
        {
            Base(A(At(0x145416c)), 0); Put(ag, 0x218, A(as.set.data())); Put(ag, 0x458, B(1)); Put(ag, 0x1bc, U(0x20));
            Put(ag, 0x1d8, U(4));
            brain::WitnessDeps deps{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 2 &&
                    deps.items[1].kind == brain::WitnessDepAnim && deps.items[1].key == A(as.set.data()) &&
                    deps.items[1].aux == 0x20 && brain::WitnessDepsHold(deps), "posture state 145416C records the animation set");
            Put(as.data[7].data(), 0x70, 7.0f); Require(!brain::WitnessDepsHold(deps), "changed R+1BC duration breaks Anim");
            Put(as.data[7].data(), 0x70, 0.25f + 0.125f * 7); Require(brain::WitnessDepsHold(deps), "restored animation holds");
            Put(as.data[3].data(), 0x70, 7.0f); Require(brain::WitnessDepsHold(deps), "R+1D8 > 3: ids 2F..34 are not read");
            Put(as.data[3].data(), 0x70, 0.25f + 0.125f * 3);
            as.table[0x20] = A(as.entries[6].data()); Require(!brain::WitnessDepsHold(deps), "changed R+1BC entry breaks Anim");
            as.table[0x20] = A(as.entries[7].data());
            as.rows[0x56c / 4] ^= 1; Require(!brain::WitnessDepsHold(deps), "changed database row count breaks Anim");
            as.rows[0x56c / 4] ^= 1;
            Put(ag, 0x1d8, U(2)); deps = brain::WitnessDeps{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 2 &&
                    deps.items[1].aux == (0x20 | kntwr_finalizer::kAnimSelects) && brain::WitnessDepsHold(deps),
                    "R+1D8 <= 3: the 6616C0 ids join the read set");
            Put(as.data[3].data(), 0x70, 7.0f); Require(!brain::WitnessDepsHold(deps), "changed id 31 duration breaks Anim");
            Put(as.data[3].data(), 0x70, 0.25f + 0.125f * 3);
            Put(ag, 0x1d8, U(4));
            Put(ag, 0x458, B(0)); deps = brain::WitnessDeps{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 2 &&
                    deps.items[1].aux == kntwr_finalizer::kNoAnimIndex, "R+458 != 1: no R+1BC entry in the read set");
            as.table[0x20] = 0; Require(brain::WitnessDepsHold(deps), "R+1BC entry is outside that read set");
            as.table[0x20] = A(as.entries[7].data());
            Base(terminal, 0); Put(ag, 0x218, A(as.set.data())); deps = brain::WitnessDeps{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps) == Inactive && deps.count == 1,
                "the rest state needs no animation dependency");
            Base(A(At(0x145416c)), 0); Put(ag, 0x218, A(as.set.data()));
            const U savedVt = Get<U>(At(0x145417c), 0);
            Put(At(0x145417c), 0, A(At(0x1346994)));
            Fin("819770 with a re-tabled posture singleton", Unresolved, false);
            Put(At(0x145417c), 0, savedVt);
            Base(A(At(0x145416c)) + 2, 0); Fin("819770 with a non-singleton posture state", Unresolved, false);
            Base(A(At(0x145416c)), 0); Put(ag, 0x218, A(as.set.data())); Put(ag, 0xf4, A(At(0x132c298)));
            Fin("819770 with the unrecovered 132C298 posture table", Unresolved, false);
            // Tables are accepted by their reached slots: 132B9AC (66B7E0 selection) animates; 134706C (462E90 /
            // 47BA10 at +40/+44) never reaches the animation set, so no set is needed and none is recorded.
            for (U state = 0; state < 13; ++state) {
                Base(A(At(0x1454168 + 4 * state)), 0); Put(ag, 0xf4, A(At(0x134706c)));
                Fin("819770 posture table without animation selection", Inactive, true);
                Base(A(At(0x1454168 + 4 * state)), 0); Put(ag, 0xf4, A(At(0x134706c)));
                brain::WitnessDeps deps2{};
                Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &deps2) == Inactive && deps2.count == 1 &&
                        deps2.items[0].kind == brain::WitnessDepTerrain, "no animation dependency without 66B7E0/66B990");
            }
            Base(A(At(0x145416c)), 0); Put(ag, 0xf4, A(At(0x132b9ac)));
            Put(ag, 0x218, U(0)); Fin("819770 animating table without an animation set", Unresolved, false);
            Put(ag, 0x218, A(as.set.data())); Fin("819770 animating table 132B9AC", Inactive, false);
            // §19.1: 132BBC0 (0x602EB0-wrapper soldiers) = 132B9AC with +40 5FB920 (66B7E0, then R+E8 = reach),
            // +48 5F8190, +4C 5EE220 (reach float [[[[S]+1C]+44]+14]). Every state on the mapped original: write
            // set R+D4..+1A7 / R+44C..+457 only; the classification records Anim with kAnimReach.
            U reachVariant = 0, reachMoves = 0, reachE8 = 0;
            for (U state = 0; state < 13; ++state) for (U k = 0; k < 6; ++k) {
                Base(A(At(0x1454168 + 4 * state)), 0);
                Put(ag, 0xf4, A(At(0x132bbc0))); Put(ag, 0x218, A(as.set.data()));
                Put(ag, 0x458, B(k & 1)); Put(ag, 0x1bc, U(0x20)); Put(ag, 0x1c0, U(k));
                const U v = (reachVariant++ * 2654435761u) >> 7;
                Put(ag, 0x108, U(v % 3)); Put(ag, 0x110, U((v & 0x1f1) | (v & 0x200 ? 0x400u : 0u)));
                Put(ag, 0x11c, 0.5f * (v % 7)); Put(ag, 0x120, 0.25f * (v % 5));
                Put(ag, 0x128, 0.5f * (v % 5)); Put(ag, 0x144, 1.5f * (v % 4)); Put(ag, 0x1d8, U(v % 5));
                Put(ag, 0x98, U(v >> 13 & 1)); Put(ag, 0xe8, 0xdeadbeefu);
                Probe("819770 posture table 132BBC0", 0x819770, 0x654513, a, {}, a, Inactive,
                    {postureRegions[0], postureRegions[1], postureRegions[2], postureRegions[3], postureRegions[4],
                     postureRegions[5], postureRegions[6], postureRegions[7], postureRegions[8]}, true,
                    [&] { CallService(fin, a, CallAbi::Void0); });
                if (Get<U>(ag, 0xf8) != A(At(0x1454168 + 4 * state))) ++reachMoves;
                if (Get<U>(ag, 0xe8) != 0xdeadbeefu) { ++reachE8; Require(Get<float>(ag, 0xe8) == 1.75f, "5FB920 stores the reach float"); }
            }
            if (std::getenv("KNTWR_ORACLE_TRACE")) std::fprintf(stderr, "132BBC0: moves=%u e8=%u\n", reachMoves, reachE8);
            Require(reachMoves > 0, "the 132BBC0 posture runs cover transitions");
            Base(A(At(0x145416c)), 0); Put(ag, 0xf4, A(At(0x132bbc0))); Put(ag, 0x218, A(as.set.data()));
            Put(ag, 0x458, B(1)); Put(ag, 0x1bc, U(0x20)); Put(ag, 0x1d8, U(4));
            brain::WitnessDeps reach{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &reach) == Inactive && reach.count == 2 &&
                    reach.items[1].kind == brain::WitnessDepAnim && reach.items[1].aux == (0x20 | kntwr_finalizer::kAnimReach) &&
                    brain::WitnessDepsHold(reach), "132BBC0 records the animation set with the reach float");
            Put(as.reachBlock.data(), 0x14, 2.5f); Require(!brain::WitnessDepsHold(reach), "changed reach float breaks Anim");
            Put(as.reachBlock.data(), 0x14, 1.75f); Require(brain::WitnessDepsHold(reach), "restored reach float holds");
            as.reachHolder[0x44 / 4] = 0; Require(!brain::WitnessDepsHold(reach), "null reach block breaks Anim");
            Fin("819770 132BBC0 without a reach block", Unresolved, false);
            as.reachHolder[0x44 / 4] = A(as.reachBlock.data());
            Base(terminal, 0); Put(ag, 0xf4, A(At(0x132bbc0))); Put(ag, 0x218, A(as.set.data())); reach = brain::WitnessDeps{};
            Require(brain::WorkerClassify(fin, 0x654513, a, gate, a, nullptr, &reach) == Inactive && reach.count == 1,
                "132BBC0 rest state needs no animation dependency");
        }
        // 80B6E0 (659B1F): own stores R+F4..+1AB (fsm exit + state-0 enter included); the [R+178] unlink refused.
        {
            std::array<B, 0x200> listOwner{};
            const Region commitRegions[] = {{"agent head", ag, 0xf4, false}, {"agent commit fields", ag + 0xf4, 0x1ac - 0xf4, true},
                {"agent tail", ag + 0x1ac, f.agent.size() - 0x1ac, false}, {"foreign soldier", &foreign, sizeof foreign, false},
                {"list owner", &listOwner, sizeof listOwner, false}, {"world", &world, sizeof(World), false}};
            auto Commit = [&](const char* what, U flags, brain::Classification expect, bool exec, U desc = 0) {
                if (!desc) desc = a + 0x424;
                Probe(what, 0x80b6e0, 0x659b1f, a, {desc, 0x3fc00000u, flags}, a, expect,
                    {commitRegions[0], commitRegions[1], commitRegions[2], commitRegions[3], commitRegions[4], commitRegions[5]},
                    exec, [&] { reinterpret_cast<void (__thiscall*)(void*, U, float, U)>(At(0x80b6e0))(ag, desc, 1.5f, flags); });
            };
            for (U state : {0u, 0x1454168u, 0x145416cu, 0x1454198u}) for (U flags : {0x4u, 0x204u, 0x8004u}) for (U r18 : {0u, 1u}) {
                Base(state ? A(At(state)) : 0, 0);
                Put(ag, 0x424, 2.0f); Put(ag, 0x428, 0.0f); Put(ag, 0x42c, -1.0f); Put(ag, 0x430, uint16_t(0x1000));
                Put(ag, 0x178, U(0)); Put(ag, 0x18, r18 ? A(foreign.agent.data()) : 0u);
                Commit("80B6E0 own commit without a list", flags, Inactive, true);
                Require(Get<U>(ag, 0xf8) == A(At(0x1454168)), "commit resets the posture FSM to state 0");
                Put(ag, 0x178, A(listOwner.data()));
                const bool unlinks = r18 && !(flags & 0x8000);
                Base(state ? A(At(state)) : 0, 0); Put(ag, 0x178, A(listOwner.data())); Put(ag, 0x18, r18 ? A(foreign.agent.data()) : 0u);
                Commit("80B6E0 with a list owner", flags, unlinks ? Unresolved : Inactive, !unlinks);
                Put(ag, 0x18, U(0));
            }
            Base(0, 0); Put(ag, 0x178, A(listOwner.data()));
            Commit("80B6E0 unlinking from [R+178]", 0, Unresolved, false);
            Put(ag, 0x178, U(0));
            // Static (non-stack) memory: the fixtures themselves live on the caller stack, which the rule accepts.
            Commit("80B6E0 foreign descriptor", 4, Unresolved, false, A(fw.frame.data()));
            Probe("80B6E0 on another soldier", 0x80b6e0, 0x659b1f, A(foreign.agent.data()), {a + 0x424, 0, 4}, a, Unresolved,
                {commitRegions[0]}, false, [] {});
            Base(A(At(0x145416c)), 0); Put(ag, 0xf4, A(At(0x132c298)));
            Commit("80B6E0 unrecovered posture table", 4, Unresolved, false);
            // §19.1: the 132BBC0 reach slots are outside every exit's and 7DE0B0's closure; all states commit.
            for (U state = 0; state < 13; ++state) {
                Base(A(At(0x1454168 + 4 * state)), 0); Put(ag, 0xf4, A(At(0x132bbc0))); Put(ag, 0x178, U(0));
                Put(ag, 0x424, 2.0f); Put(ag, 0x428, 0.0f); Put(ag, 0x42c, -1.0f); Put(ag, 0x430, uint16_t(0x1000));
                Commit("80B6E0 with posture table 132BBC0", 4, Inactive, true);
                Require(Get<U>(ag, 0xf8) == A(At(0x1454168)), "132BBC0 commit resets the posture FSM to state 0");
            }
        }
        // 80E9D0 (659A80) / 63F040 (659ACF) / 63AF40 (659AE6): the sequencer's commit-tail helpers.
        {
            float out[3] = {9.0f, 9.0f, 9.0f};
            const U desc = a + 0x3f4;
            const Region ro[] = {{"agent", &f, sizeof f, false}, {"foreign soldier", &foreign, sizeof foreign, false},
                {"finalizer world", &fw, sizeof fw, false}, {"world", &world, sizeof(World), false}};
            auto Project = [&](const char* what, U receiver, U output, brain::Classification expect, bool exec) {
                Probe(what, 0x80e9d0, 0x659a80, receiver, {output}, a, expect, {ro[0], ro[1], ro[2], ro[3]}, exec, [&] {
                    reinterpret_cast<U (__thiscall*)(U, U)>(At(0x80e9d0))(receiver, output); });
            };
            Base(0, 0);
            Put(ag, 0x3f4, 3.0f); Put(ag, 0x3f8, 0.5f); Put(ag, 0x3fc, -1.0f); Put(ag, 0x404, U(0));
            Project("80E9D0 own descriptor without a frame", desc, A(out), Inactive, true);
            Require(out[0] == 3.0f && out[1] == 0.5f && out[2] == -1.0f, "null frame copies the descriptor");
            Put(ag, 0x404, A(fw.frame.data()));
            Project("80E9D0 own descriptor in a foreign frame", desc, A(out), Inactive, true);
            Put(ag, 0x404, a + 0x600);
            for (U i = 0; i < 12; ++i) Put(ag, 0x600 + (i < 3 ? 0x80 + 4 * i : 0x9c + 4 * (i - 3)), frameValues[i]);
            Project("80E9D0 own-part frame", desc, A(out), Inactive, true);
            brain::WitnessDeps deps{};
            Require(brain::WorkerClassify(A(At(0x80e9d0)), 0x659a80, desc, gate, a, nullptr, &deps) == Unresolved,
                "80E9D0 output outside the caller stack and soldier");
            Put(ag, 0x404, A(fw.frame.data()));
            {
                // Classification-only: an own-part output (the stack rule needs the caller frame above the gate).
                U frameGate[4] = {a + 0x500};
                Require(brain::WorkerClassify(A(At(0x80e9d0)), 0x659a80, desc, frameGate, a, nullptr, &deps) == Inactive &&
                        deps.count == 1 && deps.items[0].kind == brain::WitnessDepFrame && deps.items[0].aux == 1 &&
                        brain::WitnessDepsHold(deps), "foreign frame: transform-only Frame dependency");
                Put(fw.frame.data(), 0x1e4, uint16_t(0x4321)); Require(brain::WitnessDepsHold(deps), "F+1E4 is not 7F4950's");
                Put(fw.frame.data(), 0x1e4, uint16_t(0x1234));
                Put(fw.frame.data(), 0xb8, 0.5f); Require(!brain::WitnessDepsHold(deps), "changed transform breaks it");
                Put(fw.frame.data(), 0xb8, frameValues[10]);
                Put(ag, 0x404, a + 0x600); deps = brain::WitnessDeps{};
                Require(brain::WorkerClassify(A(At(0x80e9d0)), 0x659a80, desc, frameGate, a, nullptr, &deps) == Inactive &&
                        deps.count == 0, "own-part frame needs no dependency");
                Require(brain::WorkerClassify(A(At(0x80e9d0)), 0x659a80, A(fw.frame.data()) + 0x100, frameGate, a,
                        nullptr, nullptr) == Unresolved, "foreign descriptor");
                Put(ag, 0x404, A(fw.frame.data())); brain::WitnessAbort();
                Require(brain::WorkerClassify(A(At(0x80e9d0)), 0x659a80, desc, frameGate, a, nullptr, nullptr) == Unresolved,
                    "foreign frame without an open witness");
                brain::WitnessBegin(A(manager.data()));
            }
            std::array<B, 0x40> params{};
            Put(params.data(), 0x20, 2.5f); Put(ag, 0x1e8, A(params.data()));
            Probe("63F040 foreign parameter block", 0x63f040, 0x659acf, a, {}, a, Inactive, {ro[0], ro[1], ro[2], ro[3]}, true,
                [&] { CallService(A(At(0x63f040)), a, CallAbi::Float0); });
            deps = brain::WitnessDeps{};
            Require(brain::WorkerClassify(A(At(0x63f040)), 0x659acf, a, gate, a, nullptr, &deps) == Inactive && deps.count == 1 &&
                    deps.items[0].kind == brain::WitnessDepWord && deps.items[0].key == A(params.data()) + 0x20 &&
                    brain::WitnessDepsHold(deps), "63F040 records the speed word");
            Put(params.data(), 0x20, 3.5f); Require(!brain::WitnessDepsHold(deps), "changed speed word breaks it");
            Put(ag, 0x1e8, U(0));
            Probe("63F040 null parameter block", 0x63f040, 0x659acf, a, {}, a, Unresolved, {ro[0]}, false, [] {});
            Put(ag, 0x1e8, a + 0x600);
            Probe("63F040 own-part parameter block", 0x63f040, 0x659acf, a, {}, a, Inactive, {ro[0], ro[1], ro[2], ro[3]}, true,
                [&] { CallService(A(At(0x63f040)), a, CallAbi::Float0); });
            Probe("63F040 on another soldier", 0x63f040, 0x659acf, A(foreign.agent.data()), {}, a, Unresolved, {ro[0]}, false, [] {});
            Put(ag, 0x1e8, U(0));
            for (B clamp : {B(0), B(1)}) {
                float r = 0;
                Probe("63AF40 stack-only arithmetic", 0x63af40, 0x659ae6, 0, {0x3f800000u, 0x40000000u, 0x40400000u, 0x3f000000u, clamp},
                    a, Inactive, {ro[0], ro[1], ro[2], ro[3]}, true, [&] {
                        r = reinterpret_cast<float (__cdecl*)(float, float, float, float, U)>(At(0x63af40))(1.0f, 2.0f, 3.0f, 0.5f, clamp); });
                (void)r;
            }
        }
        // 6A7DD0 (66D638): crew members whose vt+A8 is 461180.
        {
            Fixture m1, m2; m1.Init(world, Spec{4,0,9}, 414); m2.Init(world, Spec{4,0,9}, 415);
            std::array<U, 20> crew{};
            crew[0] = A(m1.agent.data()); crew[1] = A(m2.agent.data());
            const Region ro[] = {{"agent", &f, sizeof f, false}, {"member 1", &m1, sizeof m1, false},
                {"member 2", &m2, sizeof m2, false}, {"crew", &crew, sizeof crew, false}};
            Base(0, 0); Put(ag, 0x66c, U(2)); Put(ag, 0x670, A(crew.data()));
            Probe("6A7DD0 crew members answer 461180", 0x6a7dd0, 0x66d638, a, {}, a, Inactive, {ro[0], ro[1], ro[2], ro[3]}, true,
                [&] { Require(!CallService(A(At(0x6a7dd0)), a, CallAbi::Word0), "every member returns null"); });
            brain::WitnessDeps deps{};
            Require(brain::WorkerClassify(A(At(0x6a7dd0)), 0x66d638, a, gate, a, nullptr, &deps) == Inactive && deps.count == 1 &&
                    deps.items[0].kind == brain::WitnessDepCrew && deps.items[0].aux == 2 && brain::WitnessDepsHold(deps),
                    "crew array dependency");
            crew[1] = A(foreign.agent.data()); Require(!brain::WitnessDepsHold(deps), "a replaced member breaks it");
            crew[1] = A(m2.agent.data());
            Put(m2.agent.data(), 0, A(At(0x13473d0))); // vt+A8 = 4470B0 (returns this)
            Probe("6A7DD0 member returning nonzero", 0x6a7dd0, 0x66d638, a, {}, a, Unresolved, {ro[0]}, false, [] {});
            Put(m2.agent.data(), 0, A(At(0x1333714)));
            Put(ag, 0x66c, U(17));
            Probe("6A7DD0 crew beyond the bound", 0x6a7dd0, 0x66d638, a, {}, a, Unresolved, {ro[0]}, false, [] {});
            Put(ag, 0x66c, U(2)); brain::WitnessAbort();
            Probe("6A7DD0 crew without an open witness", 0x6a7dd0, 0x66d638, a, {}, a, Unresolved, {ro[0]}, false, [] {});
            brain::WitnessBegin(A(manager.data()));
            Put(ag, 0x66c, U(0)); Put(ag, 0x670, U(0));
        }
        // 66D2F3 reacquire block: T.vt+F0 a register-only leaf.
        {
            Fixture t; t.Init(world, Spec{4,0,9}, 416);
            B* tg = t.agent.data();
            std::array<U, 4> members{};
            U regs[8] = {};
            Base(0, 0); Put(ag, 0x1ec, A(tg));
            auto Table = [&](U slotVa) { Put(tg, 0, A(At(slotVa)) - 0xf0); };
            Table(0x1312328); Require(ObserveAt(0x66d2f3, a, regs) == Inactive, "462CB0: AL=0");
            Table(0x13121c8); Require(ObserveAt(0x66d2f3, a, regs) == Inactive, "461180: EAX=0");
            Table(0x132b880); Require(ObserveAt(0x66d2f3, a, regs) == Unresolved, "non-leaf vt+F0");
            Table(0x131224c);
            Put(tg, 0x628, U(1)); Put(tg, 0x66c, U(1)); Put(tg, 0x670, A(members.data())); members[0] = a;
            Put(tg, 0x630, U(3)); Put(tg, 0x634, U(0x20)); Put(tg, 0x638, U(0));
            brain::WitnessDeps deps{};
            Require(brain::WorkerObserveClassify(0x66d2f3, regs, a, &deps) == Inactive && deps.count == 1 &&
                    deps.items[0].kind == brain::WitnessDepTarget && deps.items[0].key == A(tg) &&
                    brain::WitnessDepsHold(deps), "447880: the target read set is a dependency");
            Put(tg, 0x634, U(0x21)); Require(!brain::WitnessDepsHold(deps), "changed target +634 breaks it");
            Put(tg, 0x634, U(0x20)); Require(brain::WitnessDepsHold(deps), "restored target holds");
            members[0] = A(foreign.agent.data()); Require(!brain::WitnessDepsHold(deps), "changed first member breaks it");
            members[0] = a;
            brain::WitnessAbort();
            Require(ObserveAt(0x66d2f3, a, regs) == Unresolved, "447880 without an open witness");
            brain::WitnessBegin(A(manager.data()));
            // Own target: own fields are guarded, its member array is a Word dependency.
            Put(ag, 0x1ec, a); Put(ag, 0, A(At(0x131224c)) - 0xf0);
            Put(ag, 0x628, U(1)); Put(ag, 0x66c, U(1)); Put(ag, 0x670, A(members.data()));
            deps = brain::WitnessDeps{};
            Require(brain::WorkerObserveClassify(0x66d2f3, regs, a, &deps) == Inactive && deps.count == 1 &&
                    deps.items[0].kind == brain::WitnessDepWord && deps.items[0].key == A(members.data()) &&
                    brain::WitnessDepsHold(deps), "own target: member word dependency");
            members[0] = 0; Require(!brain::WitnessDepsHold(deps), "changed own first member breaks it");
            Put(ag, 0, A(At(0x1333714))); Put(ag, 0x1ec, U(0)); Put(ag, 0x628, U(0)); Put(ag, 0x66c, U(0)); Put(ag, 0x670, U(0));
        }
    }
    if (std::getenv("KNTWR_ORACLE_TRACE")) std::fprintf(stderr, "block api\n");
    // ---- worker API shape
    {
        Require(brain::CloneIdFor(0x66ce00) == KNTWR_CLONE_BRAIN_W && brain::CloneIdFor(0x66e780) == KNTWR_CLONE_BRAIN_W_WATCHER &&
            brain::CloneIdFor(0x123456) == ~0u && brain::CloneIdFor(0x7ee750) == ~0u, "clone id map");
        Require(brain::WorkerSiteForced(0x658f39) && brain::WorkerSiteForced(0x658bd3) && brain::WorkerSiteForced(0x66bf95) &&
            !brain::WorkerSiteForced(0x66d638), "site-forced rules");
        Fixture f; f.Init(world, Spec{4,0,9}, 408);
        const U a = A(f.agent.data());
        U gate[4] = {};
        U service = 0;
        Require(brain::WorkerClassify(A(At(0x66e780)), 0x658e1f, a + 0x2cc, gate, a, &service) == Inactive &&
            service == brain::Watcher, "cloned container classifies descendants, not its entry");
        Require(brain::WorkerClassify(A(At(0x66e780)), 0x658f39, a + 0x2cc, gate, a, &service) == Active,
            "cloned container at a site-forced call is active");
        Require(!brain::WorkerForwardable(A(At(0x66e780)), 0x658e1f, a + 0x2cc, gate, a), "clones are never forwarded original");
        Put(f.agent.data(), 0xec, B(0));
        Require(brain::WorkerClassify(A(At(0x5b7b20)), 0x66d4fd, a, gate, a, nullptr) == Inactive, "wrapper service disabled early-out");
        Put(f.agent.data(), 0xec, B(1)); Put(f.agent.data(), 0x1ec, U(0));
        Require(brain::WorkerClassify(A(At(0x5b7b20)), 0x66d4fd, a, gate, a, nullptr) == Unresolved, "wrapper service body is refused at workers");
        Put(f.agent.data(), 0x1ec, U(5));
        Require(brain::WorkerClassify(A(At(0x5b7b20)), 0x66d4fd, a, gate, a, nullptr) == Inactive, "wrapper service target early-out");
        Require(brain::WorkerForwardable(A(At(0x462cb0)), site, a, gate, a) && brain::WorkerWriteFree(A(At(0x462cb0))) &&
                brain::WorkerWriteFree(A(At(0x444b60))), "stub");
        float vec[3] = {0.0f, 0.0f, 0.0f}; gate[0] = A(vec);
        Require(brain::WorkerClassify(A(At(0x5cb830)), site, a, gate, a, nullptr) == Inactive, "wrapper effect zero vector");
        vec[0] = 1.0f;
        Require(brain::WorkerClassify(A(At(0x5cb830)), site, a, gate, a, nullptr) == Active, "wrapper effect nonzero vector");
    }
    if (std::getenv("KNTWR_ORACLE_TRACE")) std::fprintf(stderr, "block done\n");
    brain::Reset();
}
static void SiteHistogramChecks() {
    U words[brain::kUnknownSiteWords]; brain::UnknownSiteSnapshot(words);
    const Census rows = CensusNow();
    const U* unknown = words;
    const U* first = words + brain::kSiteTableWords;
    Require(unknown[0] == 1 && first[0] == 1, "site table versions");
    U firsts = 0;
    for (U s = 0; s < brain::ServiceCount; ++s) firsts += rows[s * brain::kServiceStride + brain::FirstUnknownOccurrences];
    Require(unknown[3] == rows[brain::Unknown * brain::kServiceStride + brain::UnknownCalls],
        "unknown-row histogram counts every unresolved unknown call");
    Require(first[3] == firsts, "first-gate histogram counts exactly one gate per refused occurrence");
    for (const U* t : {unknown, first}) {
        ULONGLONG sum = 0; U prev = ~0u;
        for (U i = 0; i < brain::kSiteTop; ++i) {
            const U calls = t[6 + 3 * i];
            if (!calls) break;
            Require(calls <= prev, "site table ranks by calls descending");
            prev = calls; sum += calls;
        }
        Require(sum <= t[3] && (!t[2] || sum < t[3]), "retained site rows never exceed the counted calls");
    }
}
// Real-step fixture specs (order, posture, expected activity, ...): shared by the census/observe and S0 runs.
static const Spec kRunSpecs[] = {
    {4,0,9}, {4,1,0xc}, {0,0,8}, {5,0,0xa}, {4,3,0xb},
    {4,0,1,0,0,0x20,0}, {5,0,2,0,0,0x20,0}, {0x17,0,0x23},
    {4,0,0x17,2,0,0x20,1,1}, {4,0,0x18,2,0,0x20,1,0,1},
    {4,0,0x1d,0,3}, {4,0,0x1d,1,3}, {4,0,0x1d,2,3},
    {4,0,0x1d,0,3,0x5d}, {4,1,0xc,0,0,0x20,1,0,0,true},
    {5,0,0x1d,0,2,0x5e,1,0,0,true}
};
static void RunCases(World& world, bool census, bool timing, bool missingClone = false) {
    currentCase = missingClone ? "missing clone forwards original once" :
        census ? "owner serial census" : "owner serial observe";
    brain::Configure(census, timing); brain::Reset(); brain::BeginDispatch();
    std::vector<World> worldBefore(1), worldExpected(1);
    U count = 0;
    for (const Spec& spec : kRunSpecs) {
        Fixture fixture; fixture.Init(world, spec, ++count);
        const Fixture before = fixture;
        worldBefore[0] = world;
        std::vector<Observed> expectedEvents, actualEvents;
        observations = &expectedEvents; ResetFp(); NativeStep(fixture, count);
        const FpState expectedFp = CaptureFp();
        const Fixture expected = fixture; worldExpected[0] = world;
        Require(Get<U>(fixture.agent.data(), 0x1b8) == spec.expectedState, "original reaches specified activity");
        fixture = before; world = worldBefore[0];
        observations = &actualEvents; ResetFp();
        SerialStep(A(fixture.agent.data()), missingClone ? nullptr : clones.entries, count);
        CompareFp(expectedFp);
        CompareBytes(&expected, &fixture, sizeof(Fixture), "complete soldier and nested objects");
        CompareBytes(&worldExpected[0], &world, sizeof(World), "shared world");
        CompareObservations(expectedEvents, actualEvents);
        ++cases;
    }
    const Status status = StatusNow();
    Require(status[brain::Version] == 2 && status[brain::Bound] == 1, "v2 bound status");
    Require(status[brain::Dispatches] == 1 && status[brain::Occurrences] == count, "one dispatch, one execution per occurrence");
    Require(status[brain::OriginalOccurrences] == ((!census || missingClone) ? count : 0), "original routing count");
    Require(status[brain::CloneOccurrences] == ((census && !missingClone) ? count : 0), "clone routing count");
    Require(status[brain::MissingClone] == (missingClone ? count : 0), "missing clone is explicit");
    Require(status[brain::CensusEnabled] == U(census) && status[brain::TimingEnabled] == U(timing), "independent mode configuration");
    if (!census || missingClone) Require(status[brain::FullyInactive] == 0, "original execution never claims inactive proof");
    if (!timing) {
        Require(status[brain::QpcFrequencyLo] == 0 && status[brain::QpcFrequencyHi] == 0, "disabled timing never initializes QPC frequency");
        Require(status[brain::OriginalTicksLo] == 0 && status[brain::OriginalTicksHi] == 0 &&
            status[brain::CloneTicksLo] == 0 && status[brain::CloneTicksHi] == 0, "disabled timing does not accumulate");
        const Census rows = CensusNow();
        for (U service = 0; service < brain::ServiceCount; ++service) {
            Require(rows[service * brain::kServiceStride + brain::TicksLo] == 0 &&
                rows[service * brain::kServiceStride + brain::TicksHi] == 0, "disabled service timing stays zero");
        }
    }
}
static void RunOrderedDuplicates(World& world) {
    currentCase = "duplicate occurrences observe preceding callbacks immediately";
    std::array<Fixture, 3> soldiers;
    for (U i = 0; i < soldiers.size(); ++i) {
        Spec spec{4,0,9}; spec.charge = i == 0;
        soldiers[i].Init(world, spec, 101 + i);
    }
    callbackTarget = soldiers[1].agent.data();
    const auto before = soldiers;
    const U order[] = {0, 1, 0, 2, 1};
    std::vector<std::array<Fixture, 3>> expected;
    std::vector<size_t> eventCounts;
    std::vector<Observed> nativeEvents, actualEvents;
    std::vector<World> worldBefore(1, world);
    observations = &nativeEvents; ResetFp();
    for (U index : order) {
        NativeStep(soldiers[index], index);
        expected.push_back(soldiers); eventCounts.push_back(nativeEvents.size());
    }
    Require(Get<U>(expected[0][1].agent.data(), 0x1d8) == 5, "earlier callback changes later soldier order");
    Require(Get<U>(expected[1][1].agent.data(), 0x1b8) == 0xa, "later original consumes callback-updated order");
    Require(nativeEvents.size() == 1, "duplicate consumes cleared charge receiver, not a stale snapshot");
    soldiers = before; world = worldBefore[0];
    observations = &actualEvents; ResetFp();
    brain::Configure(true, false); brain::Reset(); brain::BeginDispatch();
    U ordinal = 0;
    for (U index : order) {
        SerialStep(A(soldiers[index].agent.data()), clones.entries, ordinal);
        CompareBytes(&expected[ordinal], &soldiers, sizeof(soldiers), "ordinal publication and cross-soldier writes");
        Require(actualEvents.size() == eventCounts[ordinal], "callbacks complete before occurrence returns");
        ++ordinal; ++cases;
    }
    CompareObservations(nativeEvents, actualEvents);
    const Status status = StatusNow();
    Require(status[brain::Occurrences] == 5 && status[brain::CloneOccurrences] == 5, "duplicates are five executions, not three entities");
    const Census beforeDetachedGate = CensusNow();
    CallService(brain::GateAddress(brain::Random), A(world.model.data() + 0x50), CallAbi::Float0);
    const Census afterDetachedGate = CensusNow();
    const U randomRow = brain::Random * brain::kServiceStride;
    Require(afterDetachedGate[randomRow + brain::Calls] == beforeDetachedGate[randomRow + brain::Calls] + 1,
        "a direct service remains callable after occurrence completion");
    Require(afterDetachedGate[randomRow + brain::FirstActiveOccurrences] ==
        beforeDetachedGate[randomRow + brain::FirstActiveOccurrences],
        "completed occurrence context cannot capture a later detached service");
    Require(StatusNow()[brain::Occurrences] == 5, "detached service never invents an occurrence");
    callbackTarget = nullptr;
}
enum class ListMutation { None, Grow, Shrink, MoveEnd, Activation };
struct LoopFixture {
    std::array<B, 0x268> manager{};
    std::array<std::array<B, 0x40>, 4> soldiers{};
    std::array<U, 8> list{};
    std::array<U, 4> methods{};
    std::array<U, 16> trace{};
    U calls = 0;
    ListMutation mutation = ListMutation::None;
};
static LoopFixture* loopFixture;
static void __fastcall LoopOccurrence(void* receiver, void*) {
    Require(GetCurrentThreadId() == ownerThread, "worklist callback remains on owner");
    LoopFixture& f = *loopFixture;
    Require(f.calls < f.trace.size(), "native cursor terminates without repeating an occurrence");
    f.trace[f.calls++] = Get<U>(receiver, 0x2c);
    if (f.calls != 1) return;
    switch (f.mutation) {
    case ListMutation::None: break;
    case ListMutation::Grow: Put(f.manager.data(), 0x260, U(4)); break;
    case ListMutation::Shrink: Put(f.manager.data(), 0x260, U(2)); break;
    case ListMutation::MoveEnd:
        Put(f.manager.data(), 0x264, A(f.list.data() + 2));
        Put(f.manager.data(), 0x260, U(2));
        break;
    case ListMutation::Activation:
        Put(f.soldiers[1].data(), 0x30, B(2));
        Put(f.soldiers[2].data(), 0x30, B(1));
        break;
    }
}
static void ExecuteWorklist(LoopFixture& fixture, bool native) {
    __try {
        if (native) reinterpret_cast<void (__thiscall*)(void*)>(At(0x585d10))(fixture.manager.data());
        else brain::RunWorklist(A(fixture.manager.data()), clones.entries);
    } __except (ReportFault(GetExceptionInformation(), "native or owner worklist", 0)) { std::exit(3); }
}
static void WorklistOracle(ListMutation mutation, bool filtered, bool duplicates) {
    currentCase = "mapped original worklist cursor and owner ordering";
    LoopFixture fixture;
    loopFixture = &fixture;
    fixture.mutation = mutation; fixture.methods[3] = Fn(&LoopOccurrence);
    for (U i = 0; i < fixture.soldiers.size(); ++i) {
        Put(fixture.soldiers[i].data(), 0, A(fixture.methods.data()));
        Put(fixture.soldiers[i].data(), 0x2c, 201 + i);
        Put(fixture.soldiers[i].data(), 0x30, B(1));
        fixture.list[i] = A(fixture.soldiers[i].data());
    }
    if (filtered) {
        Put(fixture.soldiers[0].data(), 0x30, B(0));
        Put(fixture.soldiers[1].data(), 0x30, B(2));
        Put(fixture.soldiers[2].data(), 0x30, B(255));
    }
    if (duplicates) fixture.list[2] = fixture.list[0];
    if (mutation == ListMutation::Activation) Put(fixture.soldiers[2].data(), 0x30, B(0));
    Put(fixture.manager.data(), 0x264, A(fixture.list.data()));
    Put(fixture.manager.data(), 0x260, mutation == ListMutation::Grow ? U(1) :
        mutation == ListMutation::MoveEnd ? U(2) : U(4));
    const LoopFixture before = fixture;
    ResetFp(); ExecuteWorklist(fixture, true);
    const LoopFixture expected = fixture;
    const U expectedCalls = filtered ? 1 : mutation == ListMutation::Shrink ? 2 :
        mutation == ListMutation::Activation ? 3 : 4;
    Require(expected.calls == expectedCalls, "mapped original exercises requested list mutation");
    if (filtered) Require(expected.trace[0] == 204, "only activation byte exactly one executes");
    if (duplicates) Require(expected.trace[0] == 201 && expected.trace[2] == 201, "original repeats duplicate entry");
    if (mutation == ListMutation::MoveEnd)
        Require(expected.trace[1] == 202 && expected.trace[3] == 204, "data reload changes end, never rebases native cursor");
    for (bool census : {false, true}) {
        fixture = before;
        brain::Configure(census, false); brain::Reset();
        ResetFp(); ExecuteWorklist(fixture, false);
        CompareBytes(&expected, &fixture, sizeof(fixture), "exact original live worklist semantics");
        const Status status = StatusNow();
        Require(status[brain::Dispatches] == 1 && status[brain::Occurrences] == expected.calls,
            "worklist records only active occurrences in one dispatch");
        Require(status[brain::OriginalOccurrences] == expected.calls && status[brain::CloneOccurrences] == 0,
            "unknown fixture virtuals run original at their own ordinal");
        ++cases;
    }
    loopFixture = nullptr;
}
static void WorklistCases() {
    WorklistOracle(ListMutation::None, true, false);
    WorklistOracle(ListMutation::None, false, true);
    WorklistOracle(ListMutation::Grow, false, false);
    WorklistOracle(ListMutation::Shrink, false, false);
    WorklistOracle(ListMutation::MoveEnd, false, false);
    WorklistOracle(ListMutation::Activation, false, false);
    currentCase = "empty mapped original worklist";
    LoopFixture empty;
    loopFixture = &empty;
    ExecuteWorklist(empty, true);
    brain::Configure(true, false); brain::Reset();
    ExecuteWorklist(empty, false);
    Require(StatusNow()[brain::Occurrences] == 0 && empty.calls == 0, "empty null worklist never dereferences an entity");
    loopFixture = nullptr;
}
static void CheckLifecycle() {
    currentCase = "reset release rebind lifecycle";
    brain::Configure(true, false); brain::Reset();
    for (U value : StatusNow()) Require(value == 0, "reset clears every status word until next dispatch");
    for (U value : CensusNow()) Require(value == 0, "reset clears every service census word");
    U reasons[brain::kDiagReasonWords], gates[brain::kDiagGateWords];
    brain::DiagSnapshot(reasons, gates);
    for (U value : reasons) Require(value == 0, "reset clears compatibility reasons");
    for (U value : gates) Require(value == 0, "reset clears compatibility gates");
    brain::BeginDispatch();
    Status status = StatusNow();
    Require(status[brain::Version] == 2 && status[brain::Bound] == 1 && status[brain::CensusEnabled] == 1,
        "next dispatch publishes retained binding and configuration");
    const Census rows = CensusNow();
    brain::Release(); brain::Release();
    Require(StatusNow() == status && CensusNow() == rows, "release preserves final receipt and is idempotent");
    brain::BeginDispatch();
    status = StatusNow();
    Require(status[brain::Bound] == 1 && status[brain::CensusEnabled] == 0 && status[brain::TimingEnabled] == 0,
        "release disables modes while retaining immutable native bindings");
    brain::Reset();
    for (U value : StatusNow()) Require(value == 0, "reset remains legal after release");
    brain::Bind(A(image), bindings); brain::BeginDispatch();
    status = StatusNow();
    Require(status[brain::Bound] == 1 && status[brain::Occurrences] == 0, "rebind starts a fresh activation");
}
// ---- --brain-s0 attribution timer (native_brain_s0.h) ----------------------------------------------------------
namespace s0 = kntwr_brain_s0;
using S0Words = std::array<U, s0::kWords>;
static S0Words S0Now() { S0Words w{}; s0::Snapshot(w.data()); return w; }
static const U* S0Row(const S0Words& w, U row) { return w.data() + s0::kHeaderWords + row * s0::kRowWords; }
static uint64_t S0Pair(const U* p) { return (static_cast<uint64_t>(p[1]) << 32) | p[0]; }
static int64_t S0Excl(const S0Words& w, U row) { return static_cast<int64_t>(S0Pair(S0Row(w, row) + s0::ExclLo)); }
static uint64_t S0Incl(const S0Words& w, U row) { return S0Pair(S0Row(w, row) + s0::InclLo); }
static const brain::OccurrenceRunner kS0Runner = {&s0::BeginStage, &s0::EndStage, &s0::RunOccurrence};
static bool S0StepRow(U row) { return row <= s0::StepOther; }
// Exact accounting identities of any set of timed occurrences: every timed frame is either a root (step row) or the
// child of exactly one frame, and every frame's exclusive cycles are its inclusive minus its direct children's, so the
// exclusive cycles of all rows sum to the roots' inclusive cycles.
static void S0Identities(const S0Words& w, const char* what) {
    int64_t excl = 0; uint64_t roots = 0, children = 0, nonRoot = 0;
    for (U r = 0; r < s0::RowCount; ++r) {
        excl += S0Excl(w, r); children += S0Row(w, r)[s0::Children];
        if (S0StepRow(r)) roots += S0Incl(w, r); else nonRoot += S0Row(w, r)[s0::Sampled];
    }
    Require(excl == static_cast<int64_t>(roots), what);
    Require(children == nonRoot, "every timed gate frame is charged to exactly one parent");
}
// Register/EFLAGS/stack/RET-n contract probe: the caller loads patterns, pushes two arguments and calls the gate; the
// target records what it received, loads output patterns and returns with RET 8.
static U probeGate, probeEaxIn, probeEntry[9], probeExit[8], probeEspBefore, probeEspAfter;
__declspec(naked) static void ProbeTarget() {
    __asm pushfd
    __asm mov dword ptr [probeEntry + 0], eax
    __asm mov dword ptr [probeEntry + 4], ecx
    __asm mov dword ptr [probeEntry + 8], edx
    __asm mov dword ptr [probeEntry + 12], ebx
    __asm mov dword ptr [probeEntry + 16], esi
    __asm mov dword ptr [probeEntry + 20], edi
    __asm mov dword ptr [probeEntry + 24], ebp
    __asm pop eax
    __asm mov dword ptr [probeEntry + 28], eax
    __asm mov eax, dword ptr [esp + 4]
    __asm mov dword ptr [probeEntry + 32], eax
    __asm mov eax, 0x11111111
    __asm mov ecx, 0x22222222
    __asm mov edx, 0x33333333
    __asm push 0x0097
    __asm popfd
    __asm ret 8
}
static void RunProbe() {
    __asm {
        pushad
        pushfd
        push ebp
        push 0xBBBB0002
        push 0xAAAA0001
        mov dword ptr [probeEspBefore], esp
        mov eax, dword ptr [probeEaxIn]
        mov ecx, 0xC1C1C1C1
        mov edx, 0xD2D2D2D2
        mov ebx, 0xB3B3B3B3
        mov esi, 0x5E5E5E5E
        mov edi, 0xD1D1D1D1
        mov ebp, 0xEBEBEBEB
        push 0x0847
        popfd
        call dword ptr [probeGate]
        pushfd
        mov dword ptr [probeExit + 0], eax
        mov dword ptr [probeExit + 4], ecx
        mov dword ptr [probeExit + 8], edx
        mov dword ptr [probeExit + 12], ebx
        mov dword ptr [probeExit + 16], esi
        mov dword ptr [probeExit + 20], edi
        mov dword ptr [probeExit + 24], ebp
        pop eax
        mov dword ptr [probeExit + 28], eax
        mov dword ptr [probeEspAfter], esp
        pop ebp
        popfd
        popad
    }
}
static void __fastcall ProbeRoot(void*, void*) { RunProbe(); }
static void CheckProbe(U ecxAtTarget, const char* what) {
    const U arithmetic = 0x8D5, df = 0x400;
    Require(probeEntry[0] == probeEaxIn && probeEntry[1] == ecxAtTarget && probeEntry[2] == 0xD2D2D2D2 &&
            probeEntry[3] == 0xB3B3B3B3 && probeEntry[4] == 0x5E5E5E5E && probeEntry[5] == 0xD1D1D1D1 &&
            probeEntry[6] == 0xEBEBEBEB, what);
    Require((probeEntry[7] & (arithmetic | df)) == 0x845 && probeEntry[8] == 0xAAAA0001,
            "gate delivers the caller's EFLAGS (DF clear) and stack arguments");
    Require(probeExit[0] == 0x11111111 && probeExit[1] == 0x22222222 && probeExit[2] == 0x33333333 &&
            probeExit[3] == 0xB3B3B3B3 && probeExit[4] == 0x5E5E5E5E && probeExit[5] == 0xD1D1D1D1 &&
            probeExit[6] == 0xEBEBEBEB && (probeExit[7] & (arithmetic | df)) == 0x095,
            "gate returns the callee's registers and EFLAGS");
    Require(probeEspAfter == probeEspBefore + 8, "callee RET 8 removes exactly its arguments through the gate");
}
static void S0Start(U shift) {
    s0::Reset();
    Require(s0::Start(clones.entries, shift), "S0 starts: RDTSCP, invariant TSC, complete BRAIN_S0 family");
}
static void S0Probe() {
    currentCase = "S0 gate register/EFLAGS/RET-n contract";
    S0Start(0);
    Require(s0::OverrideGateTarget(KNTWR_BIND_S0_TARGET, Fn(&ProbeTarget)), "direct gate accepts an oracle target");
    Require(!s0::OverrideGateTarget(KNTWR_BIND_S0_SELECTOR, Fn(&ProbeTarget)), "dispatch gates are table-routed only");
    probeGate = bindings[KNTWR_BIND_S0_TARGET]; probeEaxIn = 0xA0A0A0A0;
    RunProbe(); CheckProbe(0xC1C1C1C1, "unsampled direct gate delivers every register");
    s0::RunTimedRoot(s0::StepOther, Fn(&ProbeRoot), 0);
    CheckProbe(0xC1C1C1C1, "timed direct gate delivers every register");
    // Selector gate (66D43B keeps `mov ecx,edi`): EAX = vtable, target [vt+108]; an unknown class is its miss row.
    static U vtable[0x110 / 4];
    vtable[0x108 / 4] = Fn(&ProbeTarget);
    probeGate = bindings[KNTWR_BIND_S0_SELECTOR]; probeEaxIn = A(vtable);
    RunProbe(); CheckProbe(0xC1C1C1C1, "unsampled dispatch gate delivers every register");
    s0::RunTimedRoot(s0::StepOther, Fn(&ProbeRoot), 0);
    CheckProbe(0xC1C1C1C1, "timed dispatch gate delivers every register");
    // Node-step gate performs the replaced `mov ecx,edi` itself.
    vtable[8 / 4] = Fn(&ProbeTarget);
    probeGate = bindings[KNTWR_BIND_S0_NODE_STEP];
    RunProbe(); CheckProbe(0xD1D1D1D1, "node gate performs the replaced mov ecx,edi");
    const S0Words w = S0Now();
    Require(S0Pair(S0Row(w, s0::SelectorOther)) == 2 && S0Row(w, s0::SelectorOther)[s0::Sampled] == 1 &&
            S0Pair(S0Row(w, s0::Target)) == 2 && S0Row(w, s0::Target)[s0::Sampled] == 1 &&
            S0Pair(S0Row(w, s0::NodeStepOther)) == 1 && S0Row(w, s0::NodeStepOther)[s0::Sampled] == 0,
            "every gate call counted once, timed only inside a timed occurrence, unknown targets on the miss row");
    S0Identities(w, "probe roots: exclusive cycles sum to root inclusive cycles");
    ++cases;
}
// Synthetic call tree through four direct gates: root{spin A; Target{spin E}; Driver{spin B; Path{spin C; Posture{D}}}}.
static U treeGate[4];
static uint64_t treeSpin[5];
static void Spin(uint64_t cycles) { const uint64_t s = __rdtsc(); while (__rdtsc() - s < cycles) {} }
static void __cdecl TreePosture() { Spin(treeSpin[4]); }
static void __cdecl TreePath() { Spin(treeSpin[3]); reinterpret_cast<void (*)()>(treeGate[3])(); }
static void __cdecl TreeDriver() { Spin(treeSpin[2]); reinterpret_cast<void (*)()>(treeGate[2])(); }
static void __cdecl TreeTarget() { Spin(treeSpin[1]); }
static void __fastcall TreeRoot(void*, void*) {
    Spin(treeSpin[0]);
    reinterpret_cast<void (*)()>(treeGate[0])();
    reinterpret_cast<void (*)()>(treeGate[1])();
}
static void S0Nesting() {
    currentCase = "S0 nesting accounting on a synthetic call tree";
    treeGate[0] = bindings[KNTWR_BIND_S0_TARGET]; treeGate[1] = bindings[KNTWR_BIND_S0_DRIVER];
    treeGate[2] = bindings[KNTWR_BIND_S0_PATH]; treeGate[3] = bindings[KNTWR_BIND_S0_POSTURE];
    const uint64_t spins[5] = {400000, 100000, 300000, 200000, 150000};
    std::copy(std::begin(spins), std::end(spins), treeSpin);
    const U rows[5] = {s0::StepOther, s0::Target, s0::Driver, s0::Path, s0::Posture};
    bool close = false;
    for (U attempt = 0; attempt < 8 && !close; ++attempt) {
        S0Start(0);
        Require(s0::OverrideGateTarget(KNTWR_BIND_S0_TARGET, Fn(&TreeTarget)) &&
                s0::OverrideGateTarget(KNTWR_BIND_S0_DRIVER, Fn(&TreeDriver)) &&
                s0::OverrideGateTarget(KNTWR_BIND_S0_PATH, Fn(&TreePath)) &&
                s0::OverrideGateTarget(KNTWR_BIND_S0_POSTURE, Fn(&TreePosture)), "tree gates take oracle targets");
        const uint64_t measured = s0::RunTimedRoot(s0::StepOther, Fn(&TreeRoot), 0);
        const S0Words w = S0Now();
        // Exact structure: sampled / direct children / descendants per frame.
        const U expect[5][3] = {{1, 2, 4}, {1, 0, 0}, {1, 1, 2}, {1, 1, 1}, {1, 0, 0}};
        for (U i = 0; i < 5; ++i) {
            const U* row = S0Row(w, rows[i]);
            Require(row[s0::Sampled] == expect[i][0] && row[s0::Children] == expect[i][1] &&
                    row[s0::Descendants] == expect[i][2], "tree frame counts (sampled, children, descendants)");
        }
        Require(S0Incl(w, s0::StepOther) == measured, "root inclusive is the measured occurrence");
        S0Identities(w, "tree: exclusive cycles sum to root inclusive cycles");
        Require(S0Incl(w, s0::StepOther) == static_cast<uint64_t>(S0Excl(w, s0::StepOther)) + S0Incl(w, s0::Target) +
                S0Incl(w, s0::Driver), "root inclusive = root exclusive + direct children inclusive");
        Require(S0Incl(w, s0::Driver) == static_cast<uint64_t>(S0Excl(w, s0::Driver)) + S0Incl(w, s0::Path) &&
                S0Incl(w, s0::Path) == static_cast<uint64_t>(S0Excl(w, s0::Path)) + S0Incl(w, s0::Posture),
                "inner timers subtract from their parent, never double-charged");
        // Calibrated corrections recover the bodies (spin loops) within 3% + 2000 cycles (interrupts: best of 8).
        const double o = w[s0::GateFloorX16] / 16.0, c = w[s0::GateNestX16] / 16.0, r = w[s0::RootFloorX16] / 16.0;
        close = true;
        for (U i = 0; i < 5; ++i) {
            const U* row = S0Row(w, rows[i]);
            const double corrected = S0Excl(w, rows[i]) - (i ? o : r) - row[s0::Children] * c;
            close = close && std::fabs(corrected - static_cast<double>(spins[i])) <= 0.03 * spins[i] + 2000.0;
        }
        const double inclDriver = static_cast<double>(S0Incl(w, s0::Driver)) - o - 2 * (o + c);
        close = close && std::fabs(inclDriver - static_cast<double>(spins[2] + spins[3] + spins[4])) <=
                         0.03 * (spins[2] + spins[3] + spins[4]) + 2000.0;
    }
    Require(close, "calibrated exclusive/inclusive cycles recover each synthetic body");
    S0Start(0); // restores the routed targets
    ++cases;
}
static void S0Calibration() {
    currentCase = "S0 calibration sanity";
    S0Start(s0::kDefaultShift);
    const S0Words w = S0Now();
    std::printf("S0 calibration: tsc %u kHz, gate floor %.1f (spread %.1f), nest %.1f (spread %.1f), root %.1f, "
                "pass %.2f, dispatch %.2f, occurrence %.2f cycles\n", w[s0::CalTscKhz], w[s0::GateFloorX16] / 16.0,
                w[s0::GateFloorSpreadX16] / 16.0, w[s0::GateNestX16] / 16.0, w[s0::GateNestSpreadX16] / 16.0,
                w[s0::RootFloorX16] / 16.0, w[s0::PassCostX16] / 16.0, w[s0::DispatchCostX16] / 16.0,
                w[s0::OccurrenceCostX16] / 16.0);
    Require(w[s0::Version] == s0::kVersion && w[s0::State] == 1 && w[s0::SampleShift] == s0::kDefaultShift &&
            w[s0::CalibrationSamples] == 2048, "S0 running with 1/64 sampling and a full calibration");
    Require(w[s0::CalTscKhz] > 100000 && w[s0::CalTscKhz] < 10000000, "TSC rate against QPC is a CPU clock");
    Require(w[s0::GateFloorX16] > 0 && w[s0::GateFloorX16] < 3000 * 16, "empty-gate floor is positive and bounded");
    Require(w[s0::GateNestX16] < 3000 * 16 && w[s0::RootFloorX16] > 0 && w[s0::RootFloorX16] < 3000 * 16,
            "nesting and root floors bounded");
    Require(w[s0::PassCostX16] < 100 * 16 && w[s0::DispatchCostX16] < 200 * 16 && w[s0::OccurrenceCostX16] < 400 * 16,
            "unsampled gate and stratum costs are cheap");
    for (U r = 0; r < s0::RowCount; ++r) {
        const U* row = S0Row(w, r);
        for (U k = 0; k < s0::kRowWords; ++k) Require(row[k] == 0, "calibration never leaks into the attribution rows");
    }
    ++cases;
}
// The real step through the BRAIN_S0 family: bit-exact soldier/world/FP/callbacks against the original, every
// occurrence timed (shift 0); then deterministic 1/64 strata.
static void S0Fixtures(World& world) {
    currentCase = "S0 clone family executes each original exactly once";
    S0Start(0);
    brain::Configure(false, false); brain::Reset(); brain::SetOccurrenceRunner(&kS0Runner); brain::BeginDispatch();
    s0::BeginStage(0);
    std::vector<World> worldBefore(1), worldExpected(1);
    U count = 0;
    for (const Spec& spec : kRunSpecs) {
        Fixture fixture; fixture.Init(world, spec, ++count);
        const Fixture before = fixture;
        worldBefore[0] = world;
        std::vector<Observed> expectedEvents, actualEvents;
        observations = &expectedEvents; ResetFp(); NativeStep(fixture, count);
        const FpState expectedFp = CaptureFp();
        const Fixture expected = fixture; worldExpected[0] = world;
        fixture = before; world = worldBefore[0];
        observations = &actualEvents; ResetFp();
        SerialStep(A(fixture.agent.data()), clones.entries, count);
        CompareFp(expectedFp);
        CompareBytes(&expected, &fixture, sizeof(Fixture), "S0 family: complete soldier and nested objects");
        CompareBytes(&worldExpected[0], &world, sizeof(World), "S0 family: shared world");
        CompareObservations(expectedEvents, actualEvents);
        ++cases;
    }
    s0::EndStage();
    const S0Words w = S0Now();
    std::printf("S0 fixture rows:");
    for (U r = 0; r < s0::RowCount; ++r)
        if (S0Pair(S0Row(w, r)) || S0Row(w, r)[s0::Sampled]) std::printf(" %u:%u/%u", r, S0Row(w, r)[0], S0Row(w, r)[s0::Sampled]);
    std::printf("\n");
    Require(w[s0::Stages] == 1 && w[s0::OccurrencesLo] == count && w[s0::SampledOccurrences] == count,
            "one stage, every occurrence timed at shift 0");
    Require(S0Pair(S0Row(w, s0::StepCore)) == count && S0Row(w, s0::StepCore)[s0::Sampled] == count,
            "core-class occurrences are the step_core row");
    for (U r = s0::Target; r < s0::RowCount; ++r) {
        if (r == s0::OrderFinalChanged || r == s0::OrderNodeChanged) continue;
        const U changed = (r == s0::OrderFinal || r == s0::OrderNode) ? S0Row(w, r + 1)[s0::Sampled] : 0;
        Require(S0Pair(S0Row(w, r)) == S0Row(w, r)[s0::Sampled] + changed, "shift 0: every gate call is timed once");
    }
    Require(S0Pair(S0Row(w, s0::Target)) == count && S0Pair(S0Row(w, s0::Fatigue)) == count,
            "every fixture step reaches target acquisition 6718F0 and the fatigue selector 670F40");
    S0Identities(w, "fixtures: exclusive cycles sum to step inclusive cycles");
    Require(w[s0::DepthOverflow] == 0 && w[s0::Abandoned] == 0 && w[s0::NestedRoot] == 0, "no overflow/abandon");
    // Deterministic strata: the same stage sequence samples the same occurrences.
    currentCase = "S0 deterministic 1/64 strata";
    std::array<S0Words, 2> runs;
    for (S0Words& run : runs) {
        S0Start(s0::kDefaultShift);
        for (U stage = 0; stage < 4; ++stage) {
            s0::BeginStage(0);
            for (U i = 0; i < 64; ++i) {
                Fixture fixture; fixture.Init(world, kRunSpecs[i % 5], 500 + i);
                observations = nullptr; std::vector<Observed> ignored; observations = &ignored;
                SerialStep(A(fixture.agent.data()), clones.entries, i);
            }
            s0::EndStage();
        }
        run = S0Now();
    }
    std::printf("S0 strata: %u of %u occurrences timed\n", runs[0][s0::SampledOccurrences], runs[0][s0::OccurrencesLo]);
    Require(runs[0][s0::OccurrencesLo] == 256 && runs[0][s0::SampledOccurrences] < 256, "1/64 strata sample a subset");
    for (U r = 0; r < s0::RowCount; ++r)
        Require(S0Row(runs[0], r)[s0::Sampled] == S0Row(runs[1], r)[s0::Sampled] &&
                S0Pair(S0Row(runs[0], r)) == S0Pair(S0Row(runs[1], r)), "identical strata and counts across runs");
    Require(runs[0][s0::SampledOccurrences] == runs[1][s0::SampledOccurrences], "identical sampled occurrences");
    brain::SetOccurrenceRunner(nullptr); s0::Stop(); s0::Reset();
    ++cases;
}
// ---- --brain-locality census (native_brain_locality.h) -----------------------------------------------------------
// The runner calls the original step exactly once per occurrence and only reads/prefetches: every case compares the
// complete soldier, nested objects, shared world, FP state and callbacks bit-for-bit against the native step.
namespace loc = kntwr_brain_locality;
using LocWords = std::array<U, loc::kWords>;
static LocWords LocNow() { LocWords w{}; loc::Snapshot(w.data()); return w; }
static const brain::OccurrenceRunner kLocRunner = {&loc::BeginStage, &loc::EndStage, &loc::RunOccurrence};
static uint64_t LocPair(const U* p) { return (static_cast<uint64_t>(p[1]) << 32) | p[0]; }
static const U* LocType(const LocWords& w, U row) { return w.data() + KNTWR_BRAIN_LOC_TYPE_BASE + row * KNTWR_BRAIN_LOC_TYPE_WORDS; }
static const U* LocArm(const LocWords& w, U arm) { return w.data() + KNTWR_BRAIN_LOC_ARM_BASE + arm * KNTWR_BRAIN_LOC_ARM_WORDS; }
static const U* LocScalars(const LocWords& w) { return w.data() + KNTWR_BRAIN_LOC_SCALAR_BASE; }
static void LocalityInversions() {
    currentCase = "locality merge-sort inversion count against brute force";
    uint32_t seed = 12345;
    const U sizes[] = {0, 1, 2, 3, 7, 64, 1000, 4099};
    for (U n : sizes) {
        std::vector<U> v(n), a, b(n);
        for (U i = 0; i < n; ++i) { seed = seed * 1664525u + 1013904223u; v[i] = (seed >> 16) % 50 + 0x1000; } // many duplicates
        uint64_t brute = 0;
        for (U i = 0; i < n; ++i) for (U j = i + 1; j < n; ++j) brute += v[i] > v[j];
        a = v;
        Require(loc::InversionCount(a.data(), b.data(), n) == brute, "merge-sort inversions equal the O(n^2) count");
        ++cases;
    }
}
static void LocalityStart(U mode) {
    loc::Reset();
    Require(loc::Start(A(image), mode, 0, 0), "locality census starts: RDTSCP, invariant TSC, storage (every occurrence timed, every stage deep)");
    brain::Configure(false, false); brain::Reset(); brain::SetOccurrenceRunner(&kLocRunner);
}
static void LocalityStop() { brain::SetOccurrenceRunner(nullptr); loc::Stop(); loc::Reset(); }
static void LocalityFixtures(World& world) {
    const char* names[] = {"census", "warm-touch", "prefetch1", "prefetch2"};
    for (U mode = loc::ModeCensus; mode <= loc::ModePrefetch2; ++mode) {
        currentCase = names[mode];
        LocalityStart(mode);
        brain::BeginDispatch();
        loc::BeginStage(0);
        std::vector<World> worldBefore(1), worldExpected(1);
        U count = 0;
        for (const Spec& spec : kRunSpecs) {
            Fixture fixture; fixture.Init(world, spec, ++count);
            const Fixture before = fixture;
            worldBefore[0] = world;
            std::vector<Observed> expectedEvents, actualEvents;
            observations = &expectedEvents; ResetFp(); NativeStep(fixture, count);
            const FpState expectedFp = CaptureFp();
            const Fixture expected = fixture; worldExpected[0] = world;
            fixture = before; world = worldBefore[0];
            observations = &actualEvents; ResetFp();
            SerialStep(A(fixture.agent.data()), clones.entries, count);
            CompareFp(expectedFp);
            CompareBytes(&expected, &fixture, sizeof(Fixture), "locality runner: complete soldier and nested objects");
            CompareBytes(&worldExpected[0], &world, sizeof(World), "locality runner: shared world");
            CompareObservations(expectedEvents, actualEvents);
            ++cases;
        }
        loc::EndStage();
        const LocWords w = LocNow();
        Require(w[loc::Version] == loc::kVersion && w[loc::State] == 1 && w[loc::CalibrationSamples] == 2048 &&
                w[loc::BracketFloorX16] > 0 && w[loc::CalTscKhz] > 100000, "census running, calibrated");
        Require(w[loc::Stages] == 1 && w[loc::DeepStages] == 1 && LocPair(w.data() + loc::OccurrencesLo) == count &&
                LocPair(w.data() + loc::MembersLo) == count && w[loc::Timed] == count && w[loc::Unreadable] == 0 && w[loc::Faults] == 0,
                "one stage, every occurrence a timed member of a deep stage, executed once");
        Require(LocType(w, 0)[loc::DeepValid] == count && LocType(w, 0)[loc::TimedValid] == count && LocType(w, 16)[loc::TimedValid] == count &&
                LocType(w, 0)[loc::TimedLinesSum] >= count * 16 && LocType(w, 0)[loc::StageLinesSum] >= 16,
                "entity hot set covers at least 16 distinct lines per soldier");
        const U* c0 = LocArm(w, 0); const U* c1 = LocArm(w, 1);
        if (mode == loc::ModeCensus) Require(c0[0] == count && c1[0] == 0, "census times every occurrence on the single arm");
        else if (mode == loc::ModeWarm) Require(c0[0] + c1[0] == count && c0[0] > 0 && c1[0] > 0, "A/B arms partition the timed occurrences");
        if (mode == loc::ModeWarm) Require(LocPair(c1 + 5) > 0 && LocPair(c0 + 5) == 0, "touch cycles recorded on the warm arm only");
        Require(w[loc::PrefetchIssued] == 0, "no worklist window outside RunWorklist: nothing prefetched");
        LocalityStop();
        ++cases;
    }
}
static void NativeWorklist(U manager, U stage) {
    __try { reinterpret_cast<void (__thiscall*)(U)>(At(0x585d10))(manager); }
    __except (ReportFault(GetExceptionInformation(), "native worklist", stage)) { std::exit(3); }
}
static void OwnerWorklist(U manager, U stage) {
    __try { brain::RunWorklist(manager, clones.entries); }
    __except (ReportFault(GetExceptionInformation(), "locality worklist", stage)) { std::exit(3); }
}
static void LocalityWorklist(World& world) {
    const char* names[] = {"census", "warm-touch", "prefetch1", "prefetch2"};
    static std::array<B, 0x268> manager;
    static World worldBefore, worldExpected;
    constexpr U kN = 6, kStages = 6;
    for (U mode = loc::ModeCensus; mode <= loc::ModePrefetch2; ++mode) {
        currentCase = names[mode];
        LocalityStart(mode);
        for (U stage = 0; stage < kStages; ++stage) {
            std::array<Fixture, kN> fx;
            for (U i = 0; i < kN; ++i) fx[i].Init(world, kRunSpecs[i % 5], 700 + stage * 8 + i);
            std::array<U, kN> list;
            // even stages walk ascending addresses, odd stages descending
            for (U i = 0; i < kN; ++i) list[i] = A(fx[(stage & 1) ? kN - 1 - i : i].agent.data());
            manager.fill(0); Put(manager.data(), 0x260, kN); Put(manager.data(), 0x264, A(list.data()));
            const std::array<Fixture, kN> before = fx;
            worldBefore = world;
            std::vector<Observed> expectedEvents, actualEvents;
            observations = &expectedEvents; ResetFp();
            NativeWorklist(A(manager.data()), stage);
            const FpState expectedFp = CaptureFp();
            const std::array<Fixture, kN> expected = fx; worldExpected = world;
            fx = before; world = worldBefore;
            observations = &actualEvents; ResetFp();
            OwnerWorklist(A(manager.data()), stage);
            CompareFp(expectedFp);
            CompareBytes(&expected, &fx, sizeof(fx), "locality worklist: every soldier and nested object");
            CompareBytes(&worldExpected, &world, sizeof(World), "locality worklist: shared world");
            CompareObservations(expectedEvents, actualEvents);
            ++cases;
        }
        const LocWords w = LocNow();
        const U* sc = LocScalars(w);
        Require(w[loc::Stages] == kStages && w[loc::DeepStages] == kStages && LocPair(w.data() + loc::MembersLo) == kN * kStages &&
                w[loc::Timed] == kN * kStages && w[loc::Unreadable] == 0 && w[loc::Faults] == 0, "worklist stages: every member timed once");
        Require(LocPair(sc + loc::PairsLo) == (kN - 1) * kStages && sc[loc::Ascending] == (kN - 1) * kStages / 2 &&
                sc[loc::Descending] == (kN - 1) * kStages / 2 && sc[loc::Equal] == 0,
                "adjacent pairs: ascending stages and descending stages split evenly");
        Require(LocPair(sc + loc::InversionsLo) == (kStages / 2) * (kN * (kN - 1) / 2) &&
                LocPair(sc + loc::InversionPairsLo) == kStages * (kN * (kN - 1) / 2),
                "inversions: descending stages invert every pair, ascending stages none");
        Require(LocType(w, 0)[loc::DeepValid] == kN * kStages, "every deep-stage member has an entity row");
        if (mode >= loc::ModePrefetch1) {
            Require(w[loc::BlocksA] + w[loc::BlocksB] == kStages, "one 64-occurrence block per stage");
            Require(w[loc::BlocksA] == 0 || w[loc::PrefetchIssued] > 0, "armed blocks prefetch the next worklist entries");
        } else Require(w[loc::PrefetchIssued] == 0 && w[loc::BlocksA] == 0 && w[loc::BlocksB] == 0, "no prefetch outside the prefetch modes");
        LocalityStop();
        ++cases;
    }
}
// --brain-locality-mark: pure pass-through (ETW stage markers only): every real-step fixture is bit-exact against the native step
// and the module counts nothing but completed stages.
static void LocalityMark(World& world) {
    currentCase = "locality mark pass-through";
    LocalityStart(loc::ModeMark);
    brain::BeginDispatch();
    loc::BeginStage(0);
    std::vector<World> worldBefore(1), worldExpected(1);
    U count = 0;
    for (const Spec& spec : kRunSpecs) {
        Fixture fixture; fixture.Init(world, spec, ++count);
        const Fixture before = fixture;
        worldBefore[0] = world;
        std::vector<Observed> expectedEvents, actualEvents;
        observations = &expectedEvents; ResetFp(); NativeStep(fixture, count);
        const FpState expectedFp = CaptureFp();
        const Fixture expected = fixture; worldExpected[0] = world;
        fixture = before; world = worldBefore[0];
        observations = &actualEvents; ResetFp();
        SerialStep(A(fixture.agent.data()), clones.entries, count);
        CompareFp(expectedFp);
        CompareBytes(&expected, &fixture, sizeof(Fixture), "mark runner: complete soldier and nested objects");
        CompareBytes(&worldExpected[0], &world, sizeof(World), "mark runner: shared world");
        CompareObservations(expectedEvents, actualEvents);
        ++cases;
    }
    loc::EndStage();
    const LocWords w = LocNow();
    Require(w[loc::State] == 1 && w[loc::Configured] == 17 && w[loc::Stages] == 1 && w[loc::CalibrationSamples] == 0,
            "mark mode running: one completed stage, no calibration");
    Require(LocPair(w.data() + loc::OccurrencesLo) == 0 && LocPair(w.data() + loc::MembersLo) == 0 && w[loc::Timed] == 0 &&
            w[loc::Faults] == 0, "pass-through runner counts no occurrence and takes no sample");
    LocalityStop();
    ++cases;
}
// Diagnostic reads are protected by cached region proofs, which go stale when native code decommits memory mid-stage: prime
// the proof, decommit the pages, then every diagnostic operation must fault, be contained and be counted (no step runs here).
static void LocalityFaults() {
    currentCase = "locality diagnostic reads are fault-contained";
    LocalityStart(loc::ModeWarm);
    loc::BeginStage(0);   // clears the region table
    B* region = static_cast<B*>(VirtualAlloc(nullptr, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Require(region != nullptr, "oracle region");
    const U entity = A(region);
    Require(loc::GuardedForTest(0, entity, 0x3000), "region proof primed while committed");
    Require(loc::GuardedForTest(1, entity, 0) && loc::GuardedForTest(2, entity, 0) && loc::GuardedForTest(3, entity, 0),
            "diagnostics run clean on live memory");
    Require(LocNow()[loc::Faults] == 0, "no fault on live memory");
    Require(VirtualFree(region, 0x3000, MEM_DECOMMIT) != 0, "decommit the proven region");
    Require(!loc::GuardedForTest(1, entity, 0), "touch of a stale proof faults and is contained");
    Require(!loc::GuardedForTest(2, entity, 0), "post-step census of a stale proof faults and is contained");
    Require(!loc::GuardedForTest(3, entity, 0), "chain prefetch of a stale proof faults and is contained");
    Require(LocNow()[loc::Faults] == 3, "each contained fault is counted once");
    VirtualFree(region, 0, MEM_RELEASE);
    loc::EndStage();
    LocalityStop();
    ++cases;
}
int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_brain2_oracle Napoleon.exe\n"); return 2; }
    ownerThread = GetCurrentThreadId(); Map(argv[1]);
    static World world;
    // Data-only fixture virtual: original callees and their instructions stay real.
    U* vcc = reinterpret_cast<U*>(At(0x1333714) + 0xcc); const U saved = *vcc; *vcc = Fn(&Vcc);
#define STAGE(call) do { if (std::getenv("KNTWR_ORACLE_TRACE")) { std::fprintf(stderr, "stage %s\n", #call); std::fflush(stderr); } call; } while (0)
    STAGE(ServiceCases(world));
    STAGE(ProofCases(world));
    STAGE(WorklistCases());
    STAGE(RunCases(world, false, false));
    STAGE(RunCases(world, true, false));
    STAGE(SiteHistogramChecks());
    STAGE(RunCases(world, false, true));
    STAGE(RunCases(world, true, true));
    STAGE(RunCases(world, true, false, true));
    STAGE(RunOrderedDuplicates(world));
    STAGE(S0Calibration());
    STAGE(S0Probe());
    STAGE(S0Nesting());
    STAGE(S0Fixtures(world));
    STAGE(LocalityInversions());
    STAGE(LocalityFixtures(world));
    STAGE(LocalityFaults());
    STAGE(LocalityMark(world));
    STAGE(LocalityWorklist(world));
    STAGE(CheckLifecycle());
    STAGE(RunCases(world, true, false));
    *vcc = saved; brain::Release();
    std::printf("PASS brain2 v2 owner serial oracle cases=%u checks=%u\n", cases, checks);
    return 0;
}
