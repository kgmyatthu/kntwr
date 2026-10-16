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
#include <cmath>
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
static pp::Binding Bind(bool stats = true) { return {Addr(image), 1, &ownerTid, &epochMask, NTW2_PUPPET_TEST_BIT, stats}; }
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
    std::array<B, 0x2100> armyP{}, armyQ{}; // the mech census reads army +20F8
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
static std::array<U, pp::kDivertWords> Diverts() { std::array<U, pp::kDivertWords> d{}; pp::SnapshotDivert(d.data()); return d; }
// +628 controller fixtures: slot 0 of the real tables 0x1334250 / 0x1334218, and a foreign table.
static std::array<U, 4> controllerSelf{}, controllerNull{}, controllerOther{}, controllerTable{};
// The engine's registration 0x662E90 fields; +30 cleared so the site-6 loop does not run the real brain step on the
// fixture (the controller branch itself is the engine's 0x67A050, not exercised here).
static void Divert(Soldier& s, U* controller, U kind, U activity, float x, float z) {
    Put(s.data(), 0x628, Addr(controller)); Put(s.data(), 0x62c, kind); Put(s.data(), 0x630, activity);
    Put(s.data(), 0x63c, x); Put(s.data(), 0x640, 0.0f); Put(s.data(), 0x644, z); s[0x30] = 0;
}
static void Release(Soldier& s) { Put(s.data(), 0x628, U(0)); s[0x30] = 1; } // 0x65FEE0 -> 0x63CE20
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

    label = "stage: external nodes, divert, deaths, departures"; ++cases;
    ForeignIdle(w.s[0]);                                        // e.g. a formation/order install: repark at the seam
    Divert(w.s[1], controllerSelf.data(), 4, 0x1d, 130.5f, -42.25f); // controller registration: kept, not handed back
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
    Require(!v[pp::DivertedHandbacks] && v[pp::DepartedMembers] == 1 && v[pp::DeathsImported] == 1 &&
            v[pp::IneligibleHandbacks] == 1 && v[pp::Handbacks] == 1, "membership import; the diverted member stays");
    Require(v[pp::ParkedNoCommonTicks] == 4, "four parked members had no common step in the closed window (s5, s4 had)");
    {
        U m[pp::kMotionWords]; pp::SnapshotMotion(m);
        Require(m[pp::MotionVersion] == 1 && m[pp::MotionDivertFirst] == 2 && m[pp::MotionDivertLast] == 2 &&
                m[pp::MotionDivertHist + 1] == 1, "divert timing: one event at stage 2 (bucket 2-3)");
        Require(m[pp::MotionIntentLast] == 1 && m[pp::MotionMovedLast] == 1 && m[pp::MotionFirstMoveStage] == 2 &&
                m[pp::MotionDispMaxCm] == 300 && m[pp::MotionDispMeanCm] == 75 && !m[pp::MotionSlotMembers],
                "parked motion: one man with intent moved 3 m of four measured (diverted member excluded); no slot node");
        const auto d = Diverts();
        Require(d[pp::DivertVersion] == 1 && d[pp::DivertEvents] == 1 && d[pp::DivertActive] == 1 &&
                d[pp::DivertKind + 4] == 1 && d[pp::DivertTableSelf] == 1 && d[pp::DivertLastKind] == 4 &&
                d[pp::DivertLastActivity] == 0x1d && Get<float>(&d[pp::DivertLastTargetX], 0) == 130.5f &&
                Get<float>(&d[pp::DivertLastTargetZ], 0) == -42.25f && d[pp::DivertLastTable] == 0x1334250 &&
                d[pp::DivertTargetMaxCm] == 900 && d[pp::DivertFirstStage] == 2 && !d[pp::DivertReleased],
                "divert event: kind 4, controller table 0x1334250, activity and target recorded, 9 m from the man");
    }
    Require(v[pp::MembersParked] == 4 && v[pp::SkippedNativeSteps] == 9 && stubSteps == 2,
            "three parked members skipped (the diverted one is not an occurrence here); handed-back members are native");
    Require(pp::WaitNodeInstalled(A(w.s[0])) && pp::WaitNodeInstalled(A(w.s[4])) && pp::WaitNodeInstalled(A(w.s[1])) &&
            Get<U>(w.s[3].data(), 0x22c) == Addr(At(0x133405c)), "reparked wait nodes; diverted member keeps his; handed-back member keeps its node");
    Require(!v[pp::Faults], "no fault");

    label = "stage: divert release resumes, reparks or hands back"; ++cases;
    Release(w.s[1]);                                            // wait node intact: resume skipping
    Divert(w.s[4], controllerNull.data(), 0, 0x1d, 125.0f, -42.25f); ForeignIdle(w.s[4]); // node replaced during divert
    pp::Stage(Addr(w.manager.data()));                          // stage 3
    {
        const auto d = Diverts(); U m[pp::kMotionWords]; pp::SnapshotMotion(m);
        Require(d[pp::DivertReleased] == 1 && d[pp::DivertResumed] == 1 && d[pp::DivertDurationMax] == 1 &&
                d[pp::DivertEvents] == 2 && d[pp::DivertKind] == 1 && d[pp::DivertTableNull] == 1 && d[pp::DivertActive] == 1,
                "s1 resumed after one stage; s4 diverted by a null-slot controller (kind 0)");
        Require(m[pp::MotionDivertPeak] == 1 && m[pp::MotionDivertPeakStage] == 2, "stage-2 divert window closed at stage 3");
    }
    Require(Words()[pp::SkippedNativeSteps] == 12, "s0, s1 (resumed) and s5 skipped; diverted s4 is not an occurrence");
    Divert(w.s[5], controllerOther.data(), 9, 0x2a, 121.0f, -42.25f);
    Release(w.s[4]);                                            // foreign node, eligible: repark transaction
    pp::Stage(Addr(w.manager.data()));                          // stage 4
    {
        const auto d = Diverts();
        Require(d[pp::DivertReleased] == 2 && d[pp::DivertReparked] == 1 && Words()[pp::Reparks] == 3 &&
                pp::WaitNodeInstalled(A(w.s[4])) && d[pp::DivertKind + 5] == 1 && d[pp::DivertTableOther] == 1 &&
                d[pp::DivertTableOtherVa] == Addr(controllerTable.data()) - delta,
                "s4 reparked after its divert; s5 diverted by a foreign controller table (kind other)");
    }
    Require(!pp::CommonStep(A(w.s[5]), Caller()) && Diverts()[pp::DivertCommonForwarded] == 1,
            "a diverted member's common step forwards to the original");
    Put(w.s[5].data(), 0x48, Get<float>(w.s[5].data(), 0x48) + 1.0f); // the controller moves him
    ForeignIdle(w.s[5]); Put(w.s[5].data(), 0x1ec, Addr(target.data())); // replaced node, engaged: no repark
    Release(w.s[5]); w.s[5][0x30] = 0;
    pp::Stage(Addr(w.manager.data()));                          // stage 5
    v = Words();
    {
        const auto d = Diverts();
        Require(d[pp::DivertReleased] == 3 && d[pp::DivertHandedBack] == 1 && v[pp::DivertedHandbacks] == 1 &&
                d[pp::DivertMovedTicks] == 1 && !d[pp::DivertActive] && d[pp::DivertActivePeak] == 1 &&
                d[pp::DivertDurationMean] == 1 && !d[pp::DivertNativeSteps],
                "s5 handed back at release (ineligible); his move while diverted counted");
    }
    Require(v[pp::MembersParked] == 3 && v[pp::Handbacks] == 2 && !v[pp::Faults], "s0, s1, s4 parked");

    label = "stop hands back without native writes"; ++cases;
    Soldier snapshot = w.s[0];
    pp::Stop();
    v = Words();
    Require(v[pp::StopHandbacks] == 3 && v[pp::Handbacks] == 5 && v[pp::MembersParked] == 0 && !v[pp::Enabled], "stop handback");
    Require(!memcmp(snapshot.data(), w.s[0].data(), snapshot.size()), "no byte written at stop");
    Require(!pp::CommonStep(A(w.s[0]), Caller()), "stopped module gates nothing");
}

// --puppet-probe all: six qualifying two-man units; identity rows only for the first four, aggregates for all.
static void AllUnitsCase() {
    label = "stage: all units"; ++cases;
    static std::array<std::array<B, 0xe00>, 6> units{};
    static Soldier men[12];
    static std::array<U, 2> lists[6];
    static std::array<B, 0x300> manager{};
    static std::array<U, 12> registry{};
    static std::array<B, 0x2100> army{};
    for (U u = 0; u < 6; ++u) {
        Put(units[u].data(), 0, U(0x0b1e55ed));
        for (U k = 0; k < 2; ++k) {
            Soldier& s = men[2 * u + k];
            InitSoldier(s, 500 + 2 * u + k, Addr(units[u].data())); Put(s.data(), 0x1f8, Addr(army.data()));
            Put(s.data(), 0x48, 10.0f * u); Put(s.data(), 0x50, 1.0f * k); Warm(s);
            lists[u][k] = A(s); registry[2 * u + k] = A(s);
        }
        Put(units[u].data(), 0x2cc, U(2)); Put(units[u].data(), 0x2d0, Addr(lists[u].data()));
    }
    Put(manager.data(), 0x24c, U(12)); Put(manager.data(), 0x250, Addr(registry.data()));
    Put(manager.data(), 0x260, U(12)); Put(manager.data(), 0x264, Addr(registry.data()));
    pp::Binding b = Bind(); b.units = pp::kMaxUnits;
    Require(pp::Start(b), "start for every qualifying unit");
    pp::Binding over = Bind(); over.units = pp::kMaxUnits + 1;
    Require(!pp::Start(over), "beyond the unit capacity refused");
    Require(pp::Start(b), "restart for every qualifying unit");
    ResetFp();
    pp::Stage(Addr(manager.data()));
    const auto v = Words();
    Require(v[pp::UnitsRequested] == pp::kMaxUnits && v[pp::UnitsExamined] == 6 && v[pp::UnitsSelected] == 6 &&
            v[pp::MembersAdmitted] == 12 && v[pp::MembersParked] == 12 && v[pp::SkippedNativeSteps] == 12,
            "all six units admitted and skipped");
    for (U u = 0; u < pp::kRowUnits; ++u)
        Require(NTW2_PUPPET_UNIT_ORDINAL(v[pp::UnitRows + 4 * u]) == u && NTW2_PUPPET_UNIT_MEN(v[pp::UnitRows + 4 * u]) == 2 &&
                v[pp::UnitRows + 4 * u + 1] == 2 && Get<float>(&v[pp::UnitRows + 4 * u + 2], 0) == 10.0f * u,
                "identity rows for the first four units");
    Require(!v[pp::ParkedNoCommonTicks] && v[pp::ParkedPeak] == 12 && !v[pp::Faults],
            "rows past the fourth unit do not spill into the following words");
    pp::Stop();
    Require(Words()[pp::StopHandbacks] == 12, "stop hands back every member");
}

// ---- Stage 2 ---------------------------------------------------------------------------------------------------
// PointMove(A) versus the engine's own 0x67A050 (vt+1A8) on byte copies of a battle-active soldier whose live
// controller fields select the point-move domain (kinds 0/1, controller table 0x1334218). Boundary fixtures cover the
// +63C..+654 domain edges; out-of-domain fixtures must be refused with no write.
struct MoveParams {
    U kind; float x, z, d4, dc, speed; U heading; float tx, tz; U targetHeading; float cap, accel, turn; bool pending;
    U activity = 9, row = 5, frame = 7, bits34 = 0, field658 = 0x10000;
};
static void MoveFixture(Soldier& s, const MoveParams& p) {
    InitSoldier(s, 1, 0);
    Put(s.data(), 0xec, B(1)); Put(s.data(), 0xd0, B(1));
    Put(s.data(), 0x34, p.bits34); Put(s.data(), 0x38, p.bits34 | 0x40); Put(s.data(), 0x3c, U(0x777));
    Put(s.data(), 0x48, p.x); Put(s.data(), 0x4c, 3.0f); Put(s.data(), 0x50, p.z);
    Put(s.data(), 0xd4, p.d4); Put(s.data(), 0xdc, p.dc); Put(s.data(), 0x194, p.speed);
    Put(s.data(), 0x64, static_cast<uint16_t>(p.heading));
    Put(s.data(), 0x1b8, U(0x23)); Put(s.data(), 0x1bc, U(2)); Put(s.data(), 0x1c0, U(4));
    Put(s.data(), 0x444, Addr(target.data())); Put(s.data(), 0x458, static_cast<uint16_t>(0x0101));
    if (p.pending) Put(s.data(), 0x18, Addr(target.data()));
    Put(s.data(), 0x628, Addr(controllerNull.data())); Put(s.data(), 0x62c, p.kind); Put(s.data(), 0x630, p.activity);
    Put(s.data(), 0x634, p.row); Put(s.data(), 0x638, p.frame); Put(s.data(), 0x63c, p.tx); Put(s.data(), 0x640, 0.0f);
    Put(s.data(), 0x644, p.tz); Put(s.data(), 0x648, static_cast<uint16_t>(p.targetHeading));
    Put(s.data(), 0x64c, p.cap); Put(s.data(), 0x650, p.accel); Put(s.data(), 0x654, p.turn);
    Put(s.data(), 0x658, p.field658);
}
static void PointMoveCase(const char* name, const MoveParams& p) {
    label = name; ++cases;
    Soldier ours, native;
    MoveFixture(ours, p);
    native = ours; Put(native.data(), 0x228, A(native));
    B out = 0xcc;
    ResetFp();
    reinterpret_cast<void (__thiscall*)(U, U)>(Addr(At(0x67a050)))(A(native), Addr(&out));
    ResetFp();
    const bool written = pp::PointMove(A(ours));
    Require(written == !p.pending && out == 0, "intent written exactly when nothing is pending; native branch returned +65D");
    for (U i = 0; i < 0x700; ++i) {
        if (i >= 0x228 && i < 0x22c) continue; // holder self pointer
        if (ours[i] != native[i]) { std::fprintf(stderr, "offset +%03X ours %02X native %02X\n", i, ours[i], native[i]); Fail("PointMove bytes equal 0x67A050"); }
    }
    Require(!Get<U>(ours.data(), 0x444) && !Get<uint16_t>(ours.data(), 0x458) && !ours[0xd0], "presentation and clamp writes");
    Require(ours[0x18c] == (p.pending ? 0 : 1), "direct-move flag +18C set by the native writer");
    Require(Get<U>(ours.data(), 0x1b8) == (p.kind ? 0 : p.activity) && Get<U>(ours.data(), 0x1bc) == (p.kind ? 1 : p.row),
            "kind 1 labels none/1, kind 0 labels from +630/+634");
}
static void PointMoveRefused(const char* name, const MoveParams& p, void (*mutate)(Soldier&)) {
    label = name; ++cases;
    Soldier ours, before;
    MoveFixture(ours, p);
    if (mutate) mutate(ours);
    before = ours;
    Require(!pp::PointMove(A(ours)) && !memcmp(before.data(), ours.data(), ours.size()), "outside the domain: refused, no write");
}
static void PointMoveCases() {
    // turn 3.0 rad/s -> 0.3 rad per tick -> 3129 heading words.
    PointMoveCase("point move k0: far target, turn-limited heading", {0, 10, 20, 0, 0, 1.0f, 0, 30, 25, 0x2000, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: far target, labels none/1", {1, 10, 20, 0, 0, 1.0f, 0, 30, 25, 0x2000, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: controller labels differ from current", {0, 1, 2, 0, 0, 0.5f, 0, 9, 9, 0x100, 2.0f, 4.0f, 3.0f, false, 0x17, 3, 11});
    PointMoveCase("point move k0: target inside one step", {0, 10, 20, 0, 0, 1.0f, 0x100, 10.05f, 20.02f, 0x80, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: speed above cap, pending intent offsets", {1, -4, 7, 0.1f, -0.05f, 5.0f, 0xf000, -9, 3, 0x1000, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: negative speed state, zero step", {0, 1, 1, 0, 0, 0.5f, 0x4000, 5, 5, 0x3000, 2.0f, -30.0f, 3.0f, false});
    PointMoveCase("point move k1: heading diff exactly +max turn", {1, 0, 0, 0, 0, 0.0f, 0, 3, 3, 3129, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: heading diff max turn + 1", {1, 0, 0, 0, 0, 0.0f, 0, 3, 3, 3130, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: heading diff exactly -max turn", {0, 0, 0, 0, 0, 0.0f, 0, 3, 3, 0x10000 - 3129, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: heading diff -max turn - 1", {0, 0, 0, 0, 0, 0.0f, 0, 3, 3, 0x10000 - 3130, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: heading diff 0x8000", {1, 0, 0, 0, 0, 0.0f, 0, 0, 3, 0x8000, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: heading word 0x8000 current", {0, 0, 0, 0, 0, 0.0f, 0x8000, 0, 3, 0x1000, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: turn rate above the 3.11 rad cap", {1, 0, 0, 0, 0, 0.0f, 0xc000, 3, 0, 0x2000, 2.0f, 4.0f, 40.0f, false});
    PointMoveCase("point move k0: zero turn rate", {0, 0, 0, 0, 0, 0.0f, 0x100, 3, 0, 0x2000, 2.0f, 4.0f, 0.0f, false});
    PointMoveCase("point move k1: speed reaches the cap exactly", {1, 0, 0, 0, 0, 1.6f, 0, 0, 9, 0, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k0: zero cap", {0, 0, 0, 0, 0, 1.0f, 0, 0, 9, 0, 0.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: zero accel and speed", {1, 0, 0, 0, 0, 0.0f, 0, 0, 9, 0, 2.0f, 0.0f, 3.0f, false});
    PointMoveCase("point move k0: target on the man", {0, 4, 5, 0, 0, 1.0f, 0x200, 4, 5, 0x200, 2.0f, 4.0f, 3.0f, false});
    PointMoveCase("point move k1: +658 below 0x10000 sets +3C, bit 0x20 cleared",
                  {1, 0, 0, 0, 0, 1.0f, 0, 3, 3, 0, 2.0f, 4.0f, 3.0f, false, 9, 5, 7, 0x21, 0x1234});
    PointMoveCase("point move k0: pending request refuses the intent", {0, 2, 2, 0, 0, 1.0f, 0, 6, 6, 0x2000, 2.0f, 4.0f, 3.0f, true});
    const MoveParams base = {0, 2, 2, 0, 0, 1.0f, 0, 6, 6, 0x2000, 2.0f, 4.0f, 3.0f, false};
    MoveParams kind2 = base; kind2.kind = 2;
    PointMoveRefused("point move refused: kind 2", kind2, nullptr);
    MoveParams row = base; row.activity = 0x1d;
    PointMoveRefused("point move refused: kind 0 activity 0x1D (row path)", row, nullptr);
    PointMoveRefused("point move refused: not battle-active", base, [](Soldier& s) { s[0xec] = 0; });
    PointMoveRefused("point move refused: controller table 0x1334250", base,
                     [](Soldier& s) { Put(s.data(), 0x628, Addr(controllerSelf.data())); });
    PointMoveRefused("point move refused: +65C order issue", base, [](Soldier& s) { s[0x65c] = 1; });
    PointMoveRefused("point move refused: controller vt+4 phase callback", base,
                     [](Soldier& s) { Put(s.data(), 0x224, U(0)); s[0x478] = 1; });
}

// Site 13 machinery on a parked unit: no intent is written (no owned motion policy), parked men holding a delivered,
// unbegun slot are counted, and two worlds at different addresses produce the same determinism hash chain.
struct MoverWorld {
    std::array<B, 0xe00> unit{};
    Soldier men[4];
    std::array<U, 4> list{}, registry{};
    std::array<B, 0x300> manager{};
    std::array<B, 0x2100> army{};
    void Init() {
        Put(unit.data(), 0, U(0x0b1e55ed));
        for (U k = 0; k < 4; ++k) {
            Soldier& s = men[k];
            InitSoldier(s, 700 + k, Addr(unit.data())); Put(s.data(), 0x1f8, Addr(army.data()));
            Put(s.data(), 0x48, 50.0f + 2.0f * k); Put(s.data(), 0x4c, 1.0f); Put(s.data(), 0x50, -10.0f); Warm(s);
            Put(s.data(), 0xec, B(1)); Put(s.data(), 0x58, 0.5f); Put(s.data(), 0x1b8, U(9));
            list[k] = A(s); registry[k] = A(s);
        }
        Put(unit.data(), 0x2cc, U(4)); Put(unit.data(), 0x2d0, Addr(list.data()));
        Put(manager.data(), 0x24c, U(4)); Put(manager.data(), 0x250, Addr(registry.data()));
        Put(manager.data(), 0x260, U(4)); Put(manager.data(), 0x264, Addr(registry.data()));
    }
    void Slot(U k, float x, float z, U heading) { // what 0x6529B0 -> 0x7E3D50 leaves on the man
        Soldier& s = men[k];
        Put(s.data(), 0x2d4, Addr(At(0x13472a4))); s[0x35b] = 1;
        Put(s.data(), 0x2f4, x); Put(s.data(), 0x2f8, 1.0f); Put(s.data(), 0x2fc, z); Put(s.data(), 0x318, static_cast<uint16_t>(heading));
    }
};
static std::array<U, pp::kMoverWords> Mover() { std::array<U, pp::kMoverWords> m{}; pp::SnapshotMover(m.data()); return m; }
static std::array<U, pp::kMoverWords> RunMoverWorld(MoverWorld& w) {
    w.Init();
    pp::Binding b = Bind(); b.units = pp::kMaxUnits;
    Require(pp::Start(b), "start the mover world");
    ResetFp();
    pp::Stage(Addr(w.manager.data()));
    Require(Words()[pp::MembersParked] == 4, "four parked members");
    w.Slot(0, 50.0f, -5.0f, 0);          // delivered 5 m ahead, unbegun
    w.Slot(1, 52.0f, -10.0f, 0);         // delivered on his position
    w.Slot(2, 54.0f, -6.0f, 0); w.men[2][0x2e4] = 1; // begun slot node (native watcher ran): not waiting
    pp::Move();
    return Mover();
}
static void MoverCase() {
    label = "site 13: slot-waiting census, no intent"; ++cases;
    static MoverWorld first, second;
    const auto m = RunMoverWorld(first);
    Require(m[pp::MoverVersion] == 3 && m[pp::MoverStatsMode] == 1 && m[pp::MoverStages] == 1 && m[pp::MoverParkedHashed] == 4 && !m[pp::MoverDiverted] &&
            m[pp::MoverSlotWaiting] == 2 && m[pp::MoverSlotWaitingMaxCm] == 500 && m[pp::MoverSlotWaitingMeanCm] == 250,
            "two parked men hold a delivered unbegun slot (5 m and 0 m)");
    for (const Soldier& s : first.men)
        Require(!s[0x18c] && !Get<U>(s.data(), 0xd4) && !Get<U>(s.data(), 0xdc), "no intent written for parked men");
    pp::Stage(Addr(first.manager.data())); pp::Move();
    pp::Stage(Addr(first.manager.data())); pp::Move();
    const U chainFirst = Mover()[pp::MoverHashChain];
    Require(Mover()[pp::MoverSlotWaitingTicks] == 6 && !Words()[pp::Faults], "slot-waiting member-ticks accumulate");
    {   // Skipped brain mechanics census (stats mode): parked at the seams of stages 2 and 3; fixtures have +EC=1,
        // their unit present, +A1=0, no reference, army without +20F8.
        const auto v = Mover();
        Require(v[pp::MechMemberTicks] == 8 && v[pp::Mech61C] == 8 && v[pp::Mech63C440] == 8 && v[pp::Mech639200] == 8 &&
                v[pp::MechFatigueFrozen] == 8 && !v[pp::MechF0] && !v[pp::MechRefHeading],
                "mech census over 4 parked men x 2 seams; +370 frozen while parked");
    }
    pp::Stop();

    label = "site 13: determinism across record addresses"; ++cases;
    const auto c = RunMoverWorld(second);
    Require(m[pp::MoverHashLast] == c[pp::MoverHashLast] && m[pp::MoverHashChain] == c[pp::MoverHashChain] &&
            m[pp::MoverHashLast] != 0, "same state hash for the same world at different addresses");
    pp::Stage(Addr(second.manager.data())); pp::Move();
    pp::Stage(Addr(second.manager.data())); pp::Move();
    Require(Mover()[pp::MoverHashChain] == chainFirst, "same chained hash after the same three stages");
    pp::Stop();

    label = "production stats: gates and seam without per-man diagnostics; serial out of range refused"; ++cases;
    static MoverWorld third;
    third.Init();
    Put(third.men[3].data(), 0x2c, U(0x100000)); // beyond the parked bitset
    Put(third.manager.data(), 0x260, U(3));       // site-6 worklist: the parked three (the fixture cannot run a native brain)
    pp::Binding b = Bind(false); b.units = pp::kMaxUnits;
    Require(pp::Start(b), "start in production-stats mode");
    ResetFp();
    pp::Stage(Addr(third.manager.data()));
    std::array<U, pp::kSelectWords> s{}; pp::SnapshotSelect(s.data());
    auto w = Words();
    Require(s[pp::SerialOutOfRange] == 1 && w[pp::MembersParked] == 3 && w[pp::SkippedNativeSteps] == 3,
            "serial >= 2^20 refused at selection; three parked and skipped");
    Require(pp::CommonStep(A(third.men[0]), Caller()) && !pp::CommonStep(A(third.men[3]), Caller()),
            "gate: parked member gated, out-of-range serial forwarded");
    pp::Move();
    w = Words();
    const auto v = Mover();
    Require(!w[pp::CommonCalls] && !w[pp::DispatchSamples] && !w[pp::CommonMemberCalls] && !v[pp::MoverStages] &&
            !v[pp::MechMemberTicks] && !v[pp::MoverStatsMode] && !w[pp::Faults],
            "no per-call counters, sampling, hash pass or mech census");
    pp::Stop();
}

// Relaxed qualification: an alternative infantry table member and an attached-entry unit are admitted, a crew member
// stays native, an artillery unit is rejected with its reason and majority table.
static void SelectionCase() {
    label = "selection: reasons, alternative table, crew, attached"; ++cases;
    static std::array<B, 0xe00> unit{}, guns{};
    static std::array<B, 0x20> attachedList{};
    static Soldier men[3], gunners[2];
    static std::array<U, 3> list{};
    static std::array<U, 2> gunList{};
    static std::array<U, 5> registry{};
    static std::array<B, 0x300> manager{};
    Put(unit.data(), 0, U(0x0b1e55ed)); Put(guns.data(), 0, U(0x0b1e55ed));
    for (U k = 0; k < 3; ++k) {
        InitSoldier(men[k], 900 + k, Addr(unit.data())); Warm(men[k]); list[k] = A(men[k]); registry[k] = A(men[k]);
    }
    Put(men[1].data(), 0, Addr(At(0x13473d0)));          // alternative infantry table
    Put(men[2].data(), 0x66c, U(1));                       // crew list: stays native
    Put(attachedList.data(), 0x10, U(1)); Put(unit.data(), 0x1f4, Addr(attachedList.data()));
    Put(unit.data(), 0x2cc, U(3)); Put(unit.data(), 0x2d0, Addr(list.data()));
    for (U k = 0; k < 2; ++k) {
        InitSoldier(gunners[k], 950 + k, Addr(guns.data())); gunList[k] = A(gunners[k]);
    }
    Put(gunners[1].data(), 0, Addr(At(0x13394c0)));
    Put(guns.data(), 0x2cc, U(2)); Put(guns.data(), 0x2d0, Addr(gunList.data()));
    registry[3] = A(gunners[0]); registry[4] = A(gunners[1]);
    Put(manager.data(), 0x24c, U(5)); Put(manager.data(), 0x250, Addr(registry.data()));
    Put(manager.data(), 0x260, U(2)); Put(manager.data(), 0x264, Addr(registry.data())); // the parked two only
    pp::Binding b = Bind(); b.units = pp::kMaxUnits;
    Require(pp::Start(b), "start");
    ResetFp();
    pp::Stage(Addr(manager.data()));
    std::array<U, pp::kSelectWords> s{}; pp::SnapshotSelect(s.data());
    const auto v = Words();
    Require(s[pp::SelectVersion] == 1 && s[pp::TablesPinned] == 11 && s[pp::RejectArtillery] == 1 &&
            s[pp::UnitsAttached] == 1 && s[pp::MemberCrew] == 1 && s[pp::MemberAltTable] == 1 &&
            s[pp::RegistryInfantry] == 4 && s[pp::TopTables] == 0x1333714 && s[pp::TopTables + 1] == 1,
            "artillery unit rejected (majority 0x1333714 by first maximum), attached unit admitted, crew refused");
    Require(v[pp::UnitsSelected] == 1 && v[pp::UnitsRejected] == 1 && v[pp::MembersAdmitted] == 2 &&
            v[pp::MembersParked] == 2 && v[pp::SkippedNativeSteps] == 2, "two admitted (one on the alternative table)");
    Require(!pp::CommonStep(A(men[2]), Caller()) && Words()[pp::CommonMemberCalls] == 0,
            "a refused crew member is not a parked member at the common-step gate");
    pp::Stop();
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
    controllerSelf[0] = Addr(At(0x1334250)); controllerNull[0] = Addr(At(0x1334218));
    controllerOther[0] = Addr(controllerTable.data());
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
    AllUnitsCase();
    PointMoveCases();
    SelectionCase();
    MoverCase();
    std::printf("native_puppet_oracle: %u cases, %u checks passed\n", cases, checks);
    return 0;
}
