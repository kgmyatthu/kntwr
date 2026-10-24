// Differential oracle for the 585D50 hand-port, not the 580A30 formation-update closure.
// Executes the untouched pinned image's two loops against controlled member objects, then
// replays the identical fixture through the product port (plain and real census Unit/Call).
// Vtable children record receivers/order and mutate observable state, counts, bases and
// upcoming members. They are controlled inputs, not an emulation of the loop under test.
// No game process, installed-file writes, code detours, import calls or TLS setup are needed.
// Usage: native_formation_residual_oracle.exe <pinned Napoleon.exe>
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "army/native_formation_residual.h"
#include "army/native_army_storm.h"
#include "clones/kntwr_clones.h"

static_assert(sizeof(void*) == 4, "native formation oracle requires x86");
namespace {
using U = uint32_t;
using B = uint8_t;
using Native = U (__fastcall*)(void*);
B* image;
U delta, checks, cases;
const char* current = "mapping";
const char* mode = "native";
U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void Require(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        std::fprintf(stderr, "FAIL [%s/%s] %s\n", current, mode, what);
        std::exit(1);
    }
}

void Map(const char* path) {
    FILE* f = std::fopen(path, "rb");
    Require(f != nullptr, "open image read-only");
    Require(std::fseek(f, 0, SEEK_END) == 0, "seek image");
    const long n = std::ftell(f);
    std::rewind(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image size");
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image");
    std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr;
    B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "hash image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4") == 0,
            "supported image identity");
    // The exact digest authenticates the PE headers before they are interpreted.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred image base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image allocation");
    delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
                               reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta),
            "loader relocations");
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD old;
        Require(VirtualProtect(image + sections[i].VirtualAddress, sections[i].Misc.VirtualSize,
                               PAGE_EXECUTE_READ, &old) != 0, "protect original code read-only");
    }
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0,
            "flush private image");
}

constexpr U kSlots = 16;
constexpr U kCount[2] = {0xAB0 / 4, 0xACC / 4};
constexpr U kBase[2] = {0xAB4 / 4, 0xAD0 / 4};
enum Action : U { None, Shrink, Grow, Forward, Backward, Empty, ReplaceNext, RetargetNext,
                  EnableSecond, DisableSecond };
struct Member { U vtable, id, calls, effect, action; };
struct Fixture {
    U unit[0xB00 / 4];
    U list[2][kSlots];
    Member member[2][kSlots];
    U vtable[2][4];
    U effect;
};
struct Event {
    U receiver, id, callee, effectBefore, counts[2], bases[2];
};
struct Trace { U count; Event events[64]; };
Fixture fixture;
Trace trace;

U __fastcall ChildA(void* receiver);
U __fastcall ChildB(void* receiver);
U Child(void* receiver, U callee) {
    // Bound a broken traversal rather than allowing an accidental cycle to hang CTest.
    Require(trace.count < 64, "bounded child trace");
    const U address = A(receiver), first = A(&fixture.member[0][0]);
    Require(address >= first && address - first < sizeof(fixture.member) &&
            (address - first) % sizeof(Member) == 0, "receiver is a fixture member");
    auto& m = *static_cast<Member*>(receiver);
    const U loop = m.id / kSlots;
    Require(loop < 2, "member identity");
    Event& e = trace.events[trace.count++];
    e.receiver = address; e.id = m.id; e.callee = callee; e.effectBefore = fixture.effect;
    for (U i = 0; i < 2; ++i) {
        e.counts[i] = fixture.unit[kCount[i]];
        e.bases[i] = fixture.unit[kBase[i]];
    }
    ++m.calls;
    fixture.effect = fixture.effect * 33u + m.id + callee * 101u;
    m.effect ^= fixture.effect;
    fixture.unit[0x100 / 4] += fixture.effect;
    // Every mutation leaves the native cursor a finite path through this same backing
    // array. Reallocation/free semantics of 580A30 are deliberately not claimed here.
    switch (m.action) {
    case None: break;
    case Shrink: fixture.unit[kCount[loop]] = 1; break;
    case Grow: fixture.unit[kCount[loop]] = 4; break;
    case Forward:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][6]);
        fixture.unit[kCount[loop]] = 1;
        break;
    case Backward:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][2]);
        fixture.unit[kCount[loop]] = 4;
        break;
    case Empty:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][5]);
        fixture.unit[kCount[loop]] = 0;
        break;
    case ReplaceNext: fixture.list[loop][5] = A(&fixture.member[loop][10]); break;
    case RetargetNext: fixture.member[loop][5].vtable = A(fixture.vtable[0]); break;
    case EnableSecond:
        fixture.unit[kBase[1]] = A(&fixture.list[1][6]);
        fixture.unit[kCount[1]] = 2;
        break;
    case DisableSecond:
        fixture.unit[kBase[1]] = 0;
        fixture.unit[kCount[1]] = 0;
        break;
    default: Require(false, "known mutation");
    }
    m.action = None;
    return fixture.effect; // EAX is intentionally ignored: native caller 5820E3 reloads ECX.
}
U __fastcall ChildA(void* receiver) { return Child(receiver, 1); }
U __fastcall ChildB(void* receiver) { return Child(receiver, 2); }

void Setup(U count0, U count1) {
    std::memset(&fixture, 0, sizeof(fixture));
    fixture.effect = 0x12345678;
    fixture.vtable[0][3] = Fn(&ChildA);
    fixture.vtable[1][3] = Fn(&ChildB);
    for (U loop = 0; loop < 2; ++loop) {
        fixture.unit[kCount[loop]] = loop ? count1 : count0;
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][4]);
        for (U i = 0; i < kSlots; ++i) {
            Member& m = fixture.member[loop][i];
            m.vtable = A(fixture.vtable[i & 1]);
            m.id = loop * kSlots + i;
            m.effect = 0xA5A50000u + m.id;
            fixture.list[loop][i] = A(&m);
        }
    }
}
U __fastcall CensusFormation(void* unit) {
    Require(kntwr_army_storm::InUnit(), "real census occurrence entered");
    return kntwr_army_storm::Call(kntwr_army_storm::BFormation, unit, &kntwr_form_residual::Formation);
}
void Execute(Native fn) {
    // Keep SEH in this POD-only frame; do not mask an oracle/native fault as a skipped case.
    __try { fn(fixture.unit); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "FAIL [%s/%s] exception=%08lX\n", current, mode, GetExceptionCode());
        std::exit(3);
    }
}
U __fastcall Census(void* unit) { return kntwr_army_storm::Unit(unit, 0, &CensusFormation); }
void Compare(const char* name, const std::vector<U>& expected) {
    current = name;
    const Fixture initial = fixture; // same addresses in both runs; copies are snapshots only
    std::memset(&trace, 0, sizeof(trace));
    mode = "native";
    Execute(reinterpret_cast<Native>(static_cast<uintptr_t>(0x585D50 + delta)));
    const Fixture nativeState = fixture;
    const Trace nativeTrace = trace;
    Require(trace.count == expected.size(), "native reference child count");
    for (U i = 0; i < trace.count; ++i) Require(trace.events[i].id == expected[i], "native reference order");
    for (U census = 0; census < 2; ++census) {
        mode = census ? "census port" : "plain port";
        fixture = initial;
        std::memset(&trace, 0, sizeof(trace));
        kntwr_army_storm::Reset();
        kntwr_form_residual::Reset();
        Require(!kntwr_army_storm::InUnit(), "outside occurrence before entry");
        Execute(census ? &Census : &kntwr_form_residual::Formation);
        Require(!kntwr_army_storm::InUnit(), "occurrence exited");
        Require(std::memcmp(&nativeTrace, &trace, sizeof(trace)) == 0,
                "child order, receivers, dispatch and intermediate observations equal native");
        Require(std::memcmp(&nativeState, &fixture, sizeof(fixture)) == 0,
                "all unit, list, member, vtable and observable effects equal native");
        ++cases;
    }
}

void Cases() {
    Setup(0, 0); Compare("both empty with allocated bases", {});
    Setup(0, 0); fixture.unit[kBase[0]] = fixture.unit[kBase[1]] = 0;
    Compare("both empty with null bases", {});
    Setup(1, 0); Compare("first loop only", {4});
    Setup(0, 1); Compare("second loop only", {20});
    Setup(3, 2); Compare("both loops ordered", {4, 5, 6, 20, 21});
    Setup(16, 16);
    fixture.unit[kBase[0]] = A(fixture.list[0]);
    fixture.unit[kBase[1]] = A(fixture.list[1]);
    std::vector<U> all;
    for (U i = 0; i < 32; ++i) all.push_back(i);
    Compare("full backing arrays", all);
    const char* names[] = {"", "shrink count", "grow count", "forward base and count", "backward base and count",
                           "zero count at advanced cursor", "replace next receiver", "replace next vtable"};
    for (U loop = 0; loop < 2; ++loop) {
        for (U action = Shrink; action <= RetargetNext; ++action) {
            const U count = action == Grow ? 1 : (action == Forward ? 4 : 3);
            Setup(loop ? 0 : count, loop ? count : 0);
            fixture.member[loop][4].action = action;
            std::vector<U> ids;
            switch (action) {
            case Shrink: case Empty: ids = {4}; break;
            case Grow: ids = {4, 5, 6, 7}; break;
            case Backward: ids = {4, 5}; break;
            case ReplaceNext: ids = {4, 10, 6}; break;
            default: ids = {4, 5, 6}; break;
            }
            for (U& id : ids) id += loop * kSlots;
            char name[96];
            std::snprintf(name, sizeof(name), "loop %u %s", loop + 1, names[action]);
            Compare(name, ids);
        }
    }
    Setup(3, 0); fixture.member[0][4].action = EnableSecond;
    Compare("first child enables and rebases second loop", {4, 5, 6, 22, 23});
    Setup(3, 3); fixture.member[0][4].action = DisableSecond;
    Compare("first child disables second loop", {4, 5, 6});
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: native_formation_residual_oracle <pinned Napoleon.exe>\n");
        return 2;
    }
    Map(argv[1]);
    U bindings[KNTWR_BIND_COUNT] = {};
    kntwr_form_residual::Bind(delta, bindings);
    Require(kntwr_form_residual::Start(0), "start residual with original child dispatch");
    Require(kntwr_army_storm::Start({A(image), 0}), "start real storm census");
    Cases();
    kntwr_form_residual::Stop();
    kntwr_army_storm::Stop();
    Require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release private image");
    std::printf("PASS formation residual native-equivalence cases=%u checks=%u (585D50 plain+census)\n", cases, checks);
    return 0;
}
