// Puppet probe stage 1 oracle on the mapped approved image (no game process, no .text patch). Every native body runs
// from the private relocated copy; fixtures are plain soldier/unit/manager records.
//  1. Install transaction: ntw2_puppet::Install(A) versus the native path that installs a wait node, i.e. the
//     watcher-node begin 0x7FF5C0 -> 0x809D80 -> A.vt+134 (0x650600) followed by the real common step 0x670EB0
//     (whose holder block runs begin/step), compared byte-for-byte over the whole 0x700-byte soldier (self pointers
//     checked by identity) for quiet/not-quiet owners, with/without an enabled prior node, and repark.
//  2. Gated common step: CommonStep(A) versus 0x670EB0 on a byte copy of a parked member.
//  3. Stage: selection (unit refusal, rejected officer), admission, site-6 skip, external nodes at the seam and at the
//     common step (repark / ineligible handback), dying and departed members, stop handback without native writes.
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
#include "puppet/native_puppet.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace pp = ntw2_puppet;
static_assert(sizeof(void*) == 4, "Win32 native ABI");
constexpr U NTW2_PUPPET_TEST_BIT = 0x80000u; // the runtime's NTW2_PUPPET epoch bit (the oracle does not link the runtime)
static B* image;
static U delta, checks, cases;
static const char* label = "map";
static U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T f) { return static_cast<U>(reinterpret_cast<uintptr_t>(f)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
template<class T> static T Get(const void* p, U offset) { T v; memcpy(&v, static_cast<const B*>(p) + offset, sizeof(v)); return v; }
template<class T> static void Put(void* p, U offset, T value) { memcpy(static_cast<B*>(p) + offset, &value, sizeof(value)); }
[[noreturn]] static void Fail(const char* what) { std::fprintf(stderr, "FAIL [%s]: %s\n", label, what); std::exit(1); }
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail(what); }
static void ResetFp() {
    unsigned short control = 0x27f;
    __asm fninit
    __asm fldcw word ptr [control]
    _mm_setcsr(0x1f80);
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
}

// Shared fixture objects (identical pointer values on both sides of every comparison).
static std::array<B, 0x40> context{}, target{};
static std::array<B, 0x100> transform{}; // 0x81AC80 reads [A+10]+5C
// Tick-owner epoch bound into the module: the oracle thread is the owner unless a case clears it.
static volatile long ownerTid;
static U epochMask = NTW2_PUPPET_TEST_BIT;
static pp::Binding Bind() { return {Addr(image), 1, &ownerTid, &epochMask, NTW2_PUPPET_TEST_BIT}; }
static U Caller() { return Addr(At(0x58395e)); } // a native slot-+08 return address (0x583940 loop)
static void __fastcall Detach(U, U, U) {}
static std::array<U, 4> requestTable{}, attachTable{};
static std::array<B, 0x20> attached{};
static U makeCalls, attachCalls, stubSteps;
static U __fastcall MakeAttached(U, U) { ++makeCalls; return Addr(attached.data()); }
static void __fastcall Attach(U, U, U) { ++attachCalls; }
static void __fastcall StubStep(U, U) { ++stubSteps; }
static U descriptor[2] = {0x13572468, 0x49};
static std::array<U, 0x200 / 4> otherTable{}, artilleryTable{};

using Soldier = std::array<B, 0x700>;
static U A(Soldier& s) { return Addr(s.data()); }
static void InitSoldier(Soldier& s, U serial, U unit, bool quiet = true) {
    s.fill(0);
    Put(s.data(), 0, Addr(At(0x1333714)));               // the real infantry class table (pinned +0C/+134)
    Put(s.data(), 0x10, Addr(transform.data()));         // 0x81AC80: +19C from [+10]+5C
    Put(s.data(), 0x2c, serial); Put(s.data(), 0x30, B(1));
    Put(s.data(), 0xa4, 1.5f);
    Put(s.data(), 0xf4, Addr(requestTable.data()));      // inline request owner reached by 0x816F10 (stop transaction)
    Put(s.data(), 0x117, B(quiet ? 1 : 0)); Put(s.data(), 0x194, 0.0f);
    Put(s.data(), 0x1f0, unit); Put(s.data(), 0x224, U(7)); // phase is preserved by the install path
    Put(s.data(), 0x228, A(s)); Put(s.data(), 0x2c8, Addr(context.data()));
}
static void Native(U va, U self) { ResetFp(); reinterpret_cast<void (__thiscall*)(U)>(Addr(At(va)))(self); }
static void Warm(Soldier& s) { Native(0x81ac80, A(s)); Native(0x663730, A(s)); } // fixed points of the non-node parts
static void PriorIdle(Soldier& s) {
    ResetFp();
    reinterpret_cast<U (__thiscall*)(U, U, U)>(Addr(At(0x61d910)))(A(s) + 0x22c, A(s) + 0x228, Addr(descriptor));
}
// A native installer's own pattern: destroy the enabled node through its table, clear, construct in place.
static void ForeignIdle(Soldier& s) {
    const U node = A(s) + 0x22c;
    ResetFp();
    if (s[0x2c4] == 1) reinterpret_cast<U (__thiscall*)(U, U)>(Get<U>(reinterpret_cast<void*>(Get<U>(s.data(), 0x22c)), 0))(node, 1);
    s[0x2c4] = 0;
    PriorIdle(s);
}
static void NativeInstallPath(Soldier& s) {
    U holder = A(s); std::array<U, 4> watcher{}; watcher[2] = Addr(&holder);
    Native(0x7ff5c0, Addr(watcher.data()));  // watcher begin -> 0x809D80 -> A.vt+134 = 0x650600
    Native(0x670eb0, A(s));                  // common step: holder block begins/steps the new node
}
static void CompareSoldiers(Soldier& ours, Soldier& native, const char* what) {
    Require(Get<U>(ours.data(), 0x228) == A(ours) && Get<U>(native.data(), 0x228) == A(native), "holder owner is the soldier");
    Require(Get<U>(ours.data(), 0x230) == A(ours) && Get<U>(native.data(), 0x230) == A(native), "node owner is the soldier");
    for (U i = 0; i < 0x700; ++i) {
        if ((i >= 0x228 && i < 0x22c) || (i >= 0x230 && i < 0x234)) continue;
        if (ours[i] != native[i]) {
            std::fprintf(stderr, "offset +%03X ours %02X native %02X\n", i, ours[i], native[i]);
            Fail(what);
        }
    }
}
struct Stubs { U make, attach; };
static Stubs Calls() { return {makeCalls, attachCalls}; }
static void InstallCase(const char* name, bool quiet, float speed, bool prior, bool repark) {
    label = name; ++cases;
    Soldier ours, native;
    InitSoldier(ours, 1, 0, quiet); Put(ours.data(), 0x194, speed);
    if (prior) PriorIdle(ours);
    Warm(ours);
    native = ours; Put(native.data(), 0x228, A(native));
    if (prior) Put(native.data(), 0x230, A(native));
    bool stopped = false;
    if (repark) {
        Require(pp::Install(A(ours), stopped), "first install postcondition");
        NativeInstallPath(native);
        CompareSoldiers(ours, native, "first install bytes equal the native watcher-install + common-step path");
    }
    const Stubs before = Calls();
    Require(pp::Install(A(ours), stopped), "install postcondition: enabled wait node, owner and context");
    const Stubs mid = Calls();
    NativeInstallPath(native);
    const Stubs after = Calls();
    Require(mid.make - before.make == after.make - mid.make && mid.attach - before.attach == after.attach - mid.attach,
            "same native stop-transaction callbacks on both paths");
    CompareSoldiers(ours, native, "install bytes equal the native watcher-install + common-step path");
    const bool isQuiet = quiet && speed < 0.01f && speed > -0.01f;
    Require(stopped == !isQuiet, "stop transaction reported exactly when begin found the owner not quiet");
    Require(Get<U>(ours.data(), 0x22c) == Addr(At(0x1334028)) && ours[0x2c4] == 1, "real wait-node table, enabled");
    Require(Get<U>(ours.data(), 0x240) == Addr(context.data()), "context from holder +A0 preserved");
    Require(ours[0x234] == B(isQuiet) && ours[0x23c] == 1 && Get<U>(ours.data(), 0x238) == U(isQuiet ? 0 : 1),
            "holder bookkeeping: begun latch, done only when quiet, one counted step otherwise");
    Require(Get<U>(ours.data(), 0x224) == 7 && !Get<U>(ours.data(), 0x628), "phase untouched, no +628 park");
    if (!isQuiet) Require(Get<U>(ours.data(), 0x108) == 2 && Get<U>(ours.data(), 0x1c4) == 1 && !Get<U>(ours.data(), 0x390),
                          "stop transaction effects present");
}

// ---- Stage scenario -------------------------------------------------------------------------------------------
struct World {
    std::array<B, 0xe00> unit{}, rejectedUnit{};
    std::array<B, 0x40> armyP{}, armyQ{};
    std::array<B, 0x300> manager{};
    Soldier s[6], officer, other, gunner, rejectedInfantry;
    std::array<U, 16> members{}, rejectedMembers{}, registry{}, worklist{};
    U registryCount = 0, worklistCount = 0;
    void Lists() {
        Put(manager.data(), 0x24c, registryCount); Put(manager.data(), 0x250, Addr(registry.data()));
        Put(manager.data(), 0x260, worklistCount); Put(manager.data(), 0x264, Addr(worklist.data()));
    }
    World() {
        Put(unit.data(), 0, U(0x0b1e55ed)); Put(rejectedUnit.data(), 0, U(0x0b1e55ed));
        for (U i = 0; i < 6; ++i) {
            InitSoldier(s[i], 100 + i, Addr(unit.data())); Put(s[i].data(), 0x1f8, Addr(armyQ.data()));
            Put(s[i].data(), 0x48, 120.5f + i); Put(s[i].data(), 0x50, -42.25f); Warm(s[i]); members[i] = A(s[i]);
        }
        otherTable.fill(0); memcpy(otherTable.data(), At(0x1333714), sizeof(otherTable));
        otherTable[0xc / 4] = Fn(&StubStep);
        InitSoldier(officer, 200, Addr(unit.data())); Put(officer.data(), 0, Addr(otherTable.data()));
        members[6] = A(officer);
        Put(unit.data(), 0x2cc, U(7)); Put(unit.data(), 0x2d0, Addr(members.data()));
        InitSoldier(other, 300, 0); Put(other.data(), 0, Addr(otherTable.data()));
        // A unit examined first and refused: it contains an artillery-class member.
        memcpy(artilleryTable.data(), At(0x13394c0), sizeof(artilleryTable));
        InitSoldier(rejectedInfantry, 400, Addr(rejectedUnit.data())); Put(rejectedInfantry.data(), 0x1f8, Addr(armyP.data()));
        InitSoldier(gunner, 401, Addr(rejectedUnit.data())); Put(gunner.data(), 0, Addr(artilleryTable.data()));
        rejectedMembers[0] = A(rejectedInfantry); rejectedMembers[1] = A(gunner);
        Put(rejectedUnit.data(), 0x2cc, U(2)); Put(rejectedUnit.data(), 0x2d0, Addr(rejectedMembers.data()));
        const U reg[] = {A(other), A(rejectedInfantry), A(gunner), A(s[0]), A(s[1]), A(s[2]), A(s[3]), A(s[4]), A(s[5]), A(officer)};
        for (U r : reg) registry[registryCount++] = r;
        const U work[] = {A(officer), A(s[0]), A(s[1]), A(s[2]), A(s[3]), A(s[4]), A(s[5]), A(other)};
        for (U w : work) worklist[worklistCount++] = w;
        Lists();
    }
};
static std::array<U, pp::kWords> Words() { std::array<U, pp::kWords> w{}; pp::Snapshot(w.data()); return w; }
static void StageCase() {
    label = "stage: selection, admission and skip"; ++cases;
    static World w;
    Require(pp::Start(Bind()), "start on the mapped image (class/node pins hold)");
    stubSteps = 0; ResetFp();
    pp::Stage(Addr(w.manager.data()));
    auto v = Words();
    Require(v[pp::UnitsExamined] == 2 && v[pp::UnitsRejected] == 1 && v[pp::UnitsSelected] == 1,
            "first unit refused (artillery member), second selected in registry order");
    Require(NTW2_PUPPET_UNIT_ORDINAL(v[pp::UnitRows]) == 1 && NTW2_PUPPET_UNIT_MEN(v[pp::UnitRows]) == 6 &&
            NTW2_PUPPET_UNIT_ARMY(v[pp::UnitRows]) == 1 && v[pp::UnitRows + 1] == 6 &&
            Get<float>(&v[pp::UnitRows + 2], 0) == 120.5f && Get<float>(&v[pp::UnitRows + 3], 0) == -42.25f,
            "unit identity: examined ordinal 1, army 1 (registry order), six men, six parked, first member's start XZ");
    Require(v[pp::MembersSelected] == 6 && v[pp::MembersRejected] == 1 && v[pp::MembersAdmitted] == 6 &&
            v[pp::MembersParked] == 6 && v[pp::InstallQuiet] == 6 && !v[pp::InstallStopped], "six quiet admissions, officer native");
    Require(v[pp::SkippedNativeSteps] == 6 && v[pp::ParkedMemberTicks] == 6 && stubSteps == 2 && v[pp::LoopOccurrences] == 8,
            "site-6 loop skips the six parked members and runs the two native occurrences");
    Require(!v[pp::Faults] && v[pp::Enabled] == 1, "no fault");
    for (auto& s : w.s) Require(pp::WaitNodeInstalled(A(s)) && s[0x234] == 1 && Get<U>(s.data(), 0x224) == 7, "wait node, done, phase kept");

    label = "gated common step equals the native step on a parked member"; ++cases;
    Soldier copy = w.s[5];
    Require(pp::CommonStep(A(w.s[5]), Caller()), "parked member takes the gated step");
    Native(0x670eb0, Addr(copy.data()));
    Require(!memcmp(copy.data(), w.s[5].data(), copy.size()), "terrain/extent and activity publication identical when nothing advances");
    Require(!pp::CommonStep(A(w.officer), Caller()) && !pp::CommonStep(A(w.other), Caller()), "non-members forward to the original");
    v = Words();
    Require(v[pp::GatedCommonSteps] == 1 && v[pp::CommonMemberCalls] == 1 && v[pp::MemberCallerVa] == 0x58395e &&
            !v[pp::CommonParkedForwarded] && v[pp::CommonCalls] == 3, "member call counted with its native call site");

    label = "common step outside the tick-owner epoch is untouched"; ++cases;
    ownerTid = 0;
    Require(!pp::CommonStep(A(w.s[5]), Caller()) && Words()[pp::CommonCalls] == 3, "foreign thread: forwarded, not counted");
    ownerTid = static_cast<long>(GetCurrentThreadId()); epochMask = 0;
    Require(!pp::CommonStep(A(w.s[5]), Caller()) && Words()[pp::CommonCalls] == 3, "closed epoch: forwarded, not counted");
    epochMask = NTW2_PUPPET_TEST_BIT;

    label = "sampled dispatch cost covers every call"; ++cases;
    const U samplesBefore = Words()[pp::DispatchSamples];
    for (U i = 0; i < 128; ++i) pp::CommonStep(A(w.other), Caller());
    v = Words();
    Require(v[pp::DispatchSamples] - samplesBefore == 2 && v[pp::CommonCallerVa] == 0x58395e, "one sample per 64 calls");

    label = "stage: external nodes, deaths, departures"; ++cases;
    ForeignIdle(w.s[0]);                                        // e.g. a formation/order install: repark at the seam
    Put(w.s[1].data(), 0x628, U(1)); w.s[1][0x30] = 0;          // divert controller: handed back, not a death
    w.members[2] = w.members[6]; Put(w.unit.data(), 0x2cc, U(6)); w.s[2][0x30] = 0; // left the unit list
    ForeignIdle(w.s[3]); Put(w.s[3].data(), 0x1ec, Addr(target.data())); w.s[3][0x30] = 0; // engaged: hand back
    ForeignIdle(w.s[4]);
    Put(w.s[5].data(), 0x48, Get<float>(w.s[5].data(), 0x48) + 3.0f); Put(w.s[5].data(), 0xd4, 0.25f); // moved while parked
    Require(!pp::CommonStep(A(w.s[4]), Caller()), "a replaced node is not gated at the common step");
    v = Words();
    Require(v[pp::ExternalSeenCommon] == 1 && v[pp::ExternalNodesSeen] == 1 && v[pp::CommonParkedForwarded] == 1 &&
            v[pp::CommonMemberCalls] == 2, "common-step detection counted once; parked call forwarded");
    stubSteps = 0;
    pp::Stage(Addr(w.manager.data()));
    v = Words();
    Require(v[pp::Reparks] == 2 && v[pp::ExternalSeenSeam] == 2 && v[pp::ExternalNodesSeen] == 3,
            "two reparks (seam + common-step detection), engaged member seen at the seam");
    Require(v[pp::DivertedHandbacks] == 1 && v[pp::DepartedMembers] == 1 && v[pp::DeathsImported] == 1 &&
            v[pp::IneligibleHandbacks] == 1 && v[pp::Handbacks] == 2, "membership import and handbacks");
    Require(v[pp::ParkedNoCommonTicks] == 4, "four parked members had no common step in the closed window (s5, s4 had)");
    {
        U m[pp::kMotionWords]; pp::SnapshotMotion(m);
        Require(m[pp::MotionVersion] == 1 && m[pp::MotionDivertFirst] == 2 && m[pp::MotionDivertLast] == 2 &&
                m[pp::MotionDivertPeak] == 1 && m[pp::MotionDivertPeakStage] == 2 && m[pp::MotionDivertHist + 1] == 1,
                "divert timing: one +628 handback at stage 2 (bucket 2-3)");
        Require(m[pp::MotionIntentLast] == 1 && m[pp::MotionMovedLast] == 1 && m[pp::MotionFirstMoveStage] == 2 &&
                m[pp::MotionDispMaxCm] == 300 && m[pp::MotionDispMeanCm] == 60 && !m[pp::MotionSlotMembers],
                "parked motion: one man with intent moved 3 m of five measured; no slot node");
    }
    Require(v[pp::MembersParked] == 3 && v[pp::SkippedNativeSteps] == 9 && v[pp::ParkedMemberTicks] == 9 && stubSteps == 2,
            "three parked members skipped; handed-back members are native");
    Require(pp::WaitNodeInstalled(A(w.s[0])) && pp::WaitNodeInstalled(A(w.s[4])) &&
            Get<U>(w.s[3].data(), 0x22c) == Addr(At(0x133405c)), "reparked wait nodes; handed-back member keeps its node");
    Require(!v[pp::Faults], "no fault");

    label = "stop hands back without native writes"; ++cases;
    Soldier snapshot = w.s[5];
    pp::Stop();
    v = Words();
    Require(v[pp::StopHandbacks] == 3 && v[pp::Handbacks] == 5 && v[pp::MembersParked] == 0 && !v[pp::Enabled], "stop handback");
    Require(!memcmp(snapshot.data(), w.s[5].data(), snapshot.size()), "no byte written at stop");
    Require(!pp::CommonStep(A(w.s[5]), Caller()), "stopped module gates nothing");
}

int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_puppet_oracle <approved Napoleon.exe>\n"); return 2; }
    ResetFp(); Map(argv[1]); ownerTid = static_cast<long>(GetCurrentThreadId());
    // A native fault inside a case names the case and the faulting VA (preferred base) instead of a bare exit code.
    AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* e) -> LONG {
        const U code = e->ExceptionRecord->ExceptionCode;
        if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
        const U ip = Addr(e->ExceptionRecord->ExceptionAddress);
        std::fprintf(stderr, "FAULT [%s]: code %08X at %08X (VA %08X), address %08X\n", label, code, ip, ip - delta,
                     static_cast<U>(e->ExceptionRecord->ExceptionInformation[1]));
        std::exit(3);
    });
    requestTable[1] = Fn(&MakeAttached); attachTable[1] = Fn(&Attach); attachTable[3] = Fn(&Detach);
    Put(attached.data(), 0, Addr(attachTable.data())); Put(transform.data(), 0x5c, U(0x2468));
    label = "start"; Require(pp::Start(Bind()), "class and node table pins hold on the mapped image");
    { pp::Binding b = Bind(); b.tick_owner = nullptr; Require(!pp::Start(b), "start refuses a binding without an epoch"); }
    Require(pp::Start(Bind()), "restart");
    InstallCase("quiet owner, no prior node", true, 0.0f, false, false);
    InstallCase("quiet owner, enabled prior idle node destroyed", true, 0.0f, true, false);
    InstallCase("not quiet (+117=0): begin runs the stop transaction, then one step", false, 0.0f, true, false);
    InstallCase("not quiet by speed (+194=0.5)", true, 0.5f, false, false);
    InstallCase("speed exactly at threshold is not quiet", true, 0.01f, false, false);
    InstallCase("repark over a done wait node", true, 0.0f, false, true);
    StageCase();
    std::printf("native_puppet_oracle: %u cases, %u checks passed\n", cases, checks);
    return 0;
}
