// S4 per-unit fatigue oracle on the mapped approved image (no game process, no .text patch). Every native body runs from the
// private relocated copy; fixtures are plain soldier/unit/manager/stat-record memory.
//  1. Arithmetic: kntwr_unit_fatigue::Step (Rate, ActivityClass, hysteresis, clamp) byte-equal to the native 0x670F40 -> 0x671230
//     on randomized homogeneous fixtures: every activity code incl. > 0x4E, node virtual +20 results, environment entries,
//     speed band gate and thresholds, negative rates, hysteresis boundaries and clamp edges, wrap, A+1F0 == 0.
//  2. Unit model: ResolveUnit admission/refusal (FSM states A..E, unknown FSM, engaged, class variance, band invariance, cold
//     records, null row) and the native step for every code of each model on the image.
//  3. Gate ABI (KNTWR_BIND_U_FATIGUE): apply / native fallback / entity mismatch; callee-saved registers and ESP preserved.
//  4. Provider through the shared module (kntwr_unit_policy on a manager/registry fixture): selection equals
//     kntwr_unit_select::Scan, serial-bit routing, one advance per stage, idempotent duplicate occurrences, out-of-worklist
//     publication, generation re-init, inactive reset, stance refusal, shadow divergence tallies, Drain cooldown, and
//     determinism of two runs on worlds at different addresses. The unit pair is compared with the native 670F40 run on a
//     reference man of a homogeneous unit stage by stage.
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
#include <memory>
#include <vector>
#include "native_image_relocation.h"
#include "brain2/native_unit_fatigue.h"
#include "brain2/native_unit_policy.h"
#include "brain2/native_unit_select.h"
#include "clones/kntwr_clones.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace uf = kntwr_unit_fatigue;
namespace up = kntwr_unit_policy;
static_assert(sizeof(void*) == 4, "Win32 native ABI");
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

struct Rng {
    uint64_t s;
    U Next() { s = s * 6364136223846793005ull + 1442695040888963407ull; return static_cast<U>(s >> 33); }
    int32_t Range(int32_t lo, int32_t hi) { return lo + static_cast<int32_t>(Next() % static_cast<U>(hi - lo + 1)); }
    bool Chance(U n) { return Next() % n == 0; }
};

// ---- fixture memory shared by every man/unit of a world ---------------------------------------------------------------
static U node20Value;
static U cov[10];
static U __fastcall Node20Stub(U, U) { return node20Value; }
struct Pack {
    int32_t e[uf::EntryCount];
    U envField;
    int32_t ctrlB, ctrlC;
    U rowCount;
    int32_t rowAdd[8];
};
struct Fix {
    std::array<B, 0x28100> root{};
    std::array<B, 0x100> holder{}, model{}, g{}, p{}, record{};
    std::array<B, 0x800> mg{};
    std::array<B, 0x1000> stat{};
    std::array<B, 0x40> table{};
    std::array<U, 8> rowPtrs{};
    std::array<std::array<B, 0x40>, 8> rows{};
    std::array<U, 16> list{};
    std::array<U, 16> nodeVt{};
};
static Pack DefaultPack() {
    Pack k{};
    const int32_t v[uf::EntryCount] = {5, 0, 2, 2, 2, 5, 3, 4, 6, 7, 9, 110, 105, 100, 0, 500, 1000, 2500, 5000, 7500, 15000};
    for (U e = 0; e < uf::EntryCount; ++e) k.e[e] = v[e];
    k.envField = 3; k.ctrlB = 0; k.ctrlC = 0; k.rowCount = 4;
    const int32_t r[8] = {-1, 2, 0, -3, 0, 0, 0, 0};
    for (U i = 0; i < 8; ++i) k.rowAdd[i] = r[i];
    return k;
}
static void Wire(Fix& f, const Pack& k) {
    Put(f.root.data(), 8, Addr(f.model.data())); Put(f.root.data(), 0x2804c, Addr(f.holder.data()));
    Put(f.holder.data(), 0x10, Addr(f.mg.data()));
    Put(f.mg.data(), 0x6c0, Addr(f.stat.data())); Put(f.mg.data(), 0x2c0, Addr(f.table.data()));
    for (U e = 0; e < uf::EntryCount; ++e) Put(f.stat.data(), uf::kEntryOffset[e] + 0x5c, k.e[e]);
    Put(f.table.data(), 0xc, k.rowCount); Put(f.table.data(), 0x10, Addr(f.rowPtrs.data()));
    for (U i = 0; i < 8; ++i) { f.rowPtrs[i] = Addr(f.rows[i].data()); Put(f.rows[i].data(), 0x20, k.rowAdd[i]); }
    Put(f.model.data(), 0, Addr(f.root.data())); Put(f.model.data(), 0xb0, Addr(f.g.data()));
    Put(f.g.data(), 0x198, Addr(f.p.data()));
    Put(f.p.data(), 0x10, Addr(f.list.data())); Put(f.p.data(), 0x24, U(3));
    f.list[6] = Addr(f.record.data());                                   // [[P+10] + 8*[P+24]]
    Put(f.p.data(), 0x2c, k.ctrlB); Put(f.p.data(), 0x30, k.ctrlC);
    Put(f.record.data(), 0x10, k.envField);
    f.nodeVt[8] = Fn(&Node20Stub);                                       // node virtual +20
}
using Soldier = std::array<B, 0x700>;
using Unit = std::array<B, 0xe00>;
static U A(Soldier& s) { return Addr(s.data()); }
static void InitMan(Fix& f, Soldier& s, U serial, U unit) {
    s.fill(0);
    Put(s.data(), 0, Addr(At(0x1333714)));                               // the real infantry class table (slot +108 = 0x670F40)
    Put(s.data(), 0x28, Addr(f.root.data())); Put(s.data(), 0x2c, serial);
    Put(s.data(), 0x514, Addr(f.stat.data())); Put(s.data(), 0x1f0, unit);
    Put(s.data(), 0x22c, Addr(f.nodeVt.data()));
    Put(s.data(), 0x1b8, U(1));
}
static void InitUnit(Fix& f, Unit& u, U state) {
    u.fill(0);
    Put(u.data(), 0, U(0x0b1e55ed)); Put(u.data(), 0x14, Addr(f.root.data()));
    Put(u.data(), 0xd68, Addr(At(0x1320f28))); Put(u.data(), 0xd6c, Addr(At(state)));
    Put(u.data(), 0xaa0, U(1));
}
static void Native(U va, U self) { ResetFp(); reinterpret_cast<void (__thiscall*)(U)>(Addr(At(va)))(self); }

// ---- 1. arithmetic vs the native 670F40 -------------------------------------------------------------------------------
static Pack RandomPack(Rng& rng, U n) {
    Pack k{};
    for (U e = uf::E10; e <= uf::EMulSlow; ++e) k.e[e] = rng.Range(-14, 40);
    for (U e = uf::EMulFast; e <= uf::EMulSlow; ++e) k.e[e] = rng.Range(-50, 300);
    const bool ordered = n % 5 != 4;
    int32_t t[7];
    for (U i = 0; i < 7; ++i) t[i] = rng.Range(-3000, 20000);
    if (ordered) std::sort(t, t + 7);
    for (U i = 0; i < 7; ++i) k.e[uf::ELow + i] = t[i];
    if (n % 7 == 3) { k.e[uf::ELow] = -100000; k.e[uf::EHigh] = 100000; }      // wide clamp so wrap/edges are reached
    k.envField = rng.Chance(3) ? static_cast<U>(rng.Range(0, 1)) : static_cast<U>(rng.Range(2, 5));
    k.ctrlB = rng.Range(-6, 6); k.ctrlC = rng.Range(-6, 6);
    k.rowCount = 5;
    for (U i = 0; i < 8; ++i) k.rowAdd[i] = rng.Range(-20, 20);
    return k;
}
static void CompareStep(Fix& f, Soldier& man, Unit& unit, Rng& rng, const Pack& k) {
    static const float kThr[3] = {Get<float>(At(0x1325c88), 0), Get<float>(At(0x131a7b0), 0), Get<float>(At(0x1325ca8), 0)};
    const U activity = rng.Chance(4) ? static_cast<U>(rng.Range(0x4f, 0x70)) : static_cast<U>(rng.Range(0, 0x4e));
    node20Value = rng.Chance(6) ? 1 : (rng.Chance(12) ? 2 : (rng.Chance(9) ? 0x101 : 0));
    const B f118 = rng.Chance(5) ? static_cast<B>(rng.Range(0, 2)) : 1, f110 = static_cast<B>(rng.Next()), f117 = rng.Chance(3);
    float speed;
    switch (rng.Range(0, 13)) {
    case 0: speed = 0.0f; break;
    case 1: speed = std::nextafter(kThr[0], -1e9f); break;
    case 2: speed = kThr[0]; break;
    case 3: speed = std::nextafter(kThr[0], 1e9f); break;
    case 4: speed = kThr[1]; break;
    case 5: speed = std::nextafter(kThr[1], 1e9f); break;
    case 6: speed = kThr[2]; break;
    case 7: speed = std::nextafter(kThr[2], 1e9f); break;
    case 8: speed = kThr[2] * 3.0f; break;
    case 9: speed = std::nanf(""); break;
    case 10: speed = -1.0f; break;
    default: speed = kThr[static_cast<U>(rng.Range(0, 2))] * (0.5f + 0.001f * rng.Range(0, 1500)); break;
    }
    const bool gate = f118 == 1 && ((f110 & 1) || f117 == 0);
    Put(unit.data(), 0xd48, static_cast<B>(rng.Range(0, static_cast<int>(k.rowCount) - 1)));
    Put(unit.data(), 0x18e, static_cast<B>(rng.Range(0, 2))); Put(unit.data(), 0x18f, static_cast<B>(rng.Range(0, 2)));
    Put(unit.data(), 0x190, static_cast<B>(rng.Range(0, 2)));
    const bool hasUnit = !rng.Chance(9);
    Put(man.data(), 0x1f0, hasUnit ? Addr(unit.data()) : U(0));
    Put(man.data(), 0x1b8, activity); Put(man.data(), 0x118, f118); Put(man.data(), 0x110, f110); Put(man.data(), 0x117, f117);
    Put(man.data(), 0x1a0, speed);
    uf::Inputs in; U reason = 0;
    Require(uf::ResolveInputs(Addr(unit.data()), activity, gate, speed, in, reason), "ResolveInputs on the fixture chain");
    in.node20 = node20Value & 0xff; in.hasUnit = hasUnit;
    const int32_t rate = uf::Rate(in);
    int32_t target;
    switch (rng.Range(0, 9)) {
    case 0: case 1: target = k.e[uf::ET1 + static_cast<U>(rng.Range(0, 4))] + rng.Range(-1, 1); break;
    case 2: target = k.e[uf::ELow] + rng.Range(-1, 1); break;
    case 3: target = k.e[uf::EHigh] + rng.Range(-1, 1); break;
    case 4: target = INT32_MAX - rng.Range(0, 12); break;
    case 5: target = INT32_MIN + rng.Range(0, 12); break;
    default: target = rng.Range(-4000, 22000); break;
    }
    const int32_t acc0 = static_cast<int32_t>(static_cast<uint32_t>(target) - static_cast<uint32_t>(rate));
    const U level0 = rng.Chance(10) ? static_cast<U>(rng.Range(6, 9)) : static_cast<U>(rng.Range(0, 5));
    Put(man.data(), 0x370, acc0); Put(man.data(), 0x374, level0);
    Native(0x670f40, A(man));
    const uf::State ported = uf::Step(in, {acc0, level0});
    ++cases;
    if (Get<int32_t>(man.data(), 0x370) != ported.acc || Get<U>(man.data(), 0x374) != ported.level) {
        std::fprintf(stderr, "activity %u node20 %u gate %d speed %g acc0 %d level0 %u rate %d: native (%d,%u) port (%d,%u)\n",
                     activity, node20Value, gate, static_cast<double>(speed), acc0, level0, rate,
                     Get<int32_t>(man.data(), 0x370), Get<U>(man.data(), 0x374), ported.acc, ported.level);
        Fail("Step differs from the native 670F40");
    }
    Require(Get<U>(man.data(), 0x1b8) == activity, "native leaves the activity alone");
    const int32_t nativeAcc = Get<int32_t>(man.data(), 0x370); const U nativeLevel = Get<U>(man.data(), 0x374);
    const int32_t raw = static_cast<int32_t>(static_cast<uint32_t>(acc0) + static_cast<uint32_t>(rate));
    cov[0] += nativeLevel > level0 && level0 <= 5; cov[1] += nativeLevel < level0 && level0 <= 5;
    cov[2] += level0 <= 5 && raw < k.e[uf::ELow]; cov[3] += level0 <= 5 && raw > k.e[uf::EHigh];
    cov[4] += gate && (speed > kThr[0]) && uf::ClassRate(in) != uf::ClassRate([&] { uf::Inputs b = in; b.speedGate = false; return b; }());
    cov[5] += uf::ActivityClass(in) == 0 && (k.envField == 0 || k.envField == 1) && (in.entry[k.envField == 0 ? uf::EEnv0 : uf::EEnv1] != 0);
    cov[6] += in.node20 == 1; cov[7] += activity > uf::kActivityLimit; cov[8] += !hasUnit;
    cov[9] += (acc0 > 0 && rate > 0 && raw < 0) || (acc0 < 0 && rate < 0 && raw > 0);
}
static void TestArithmetic() {
    label = "arithmetic";
    auto f = std::make_unique<Fix>(); auto man = std::make_unique<Soldier>(); auto unit = std::make_unique<Unit>();
    Rng rng{0x6a09e667f3bcc908ull};
    for (U n = 0; n < 60; ++n) {
        const Pack k = n == 0 ? DefaultPack() : RandomPack(rng, n);
        Wire(*f, k); InitUnit(*f, *unit, 0x1450908); InitMan(*f, *man, 1, Addr(unit->data()));
        for (U i = 0; i < 1500; ++i) CompareStep(*f, *man, *unit, rng, k);
    }
    // Entry table and activity table versus the image.
    for (U a = 0; a <= uf::kActivityLimit; ++a) Require(At(0x6711d8)[a] == uf::kActivityClass[a], "activity byte table");
}

// ---- 2. unit model ----------------------------------------------------------------------------------------------------
static void TestUnitModel() {
    label = "unit model";
    auto f = std::make_unique<Fix>(); auto man = std::make_unique<Soldier>(); auto unit = std::make_unique<Unit>();
    Pack k = DefaultPack();
    Wire(*f, k); InitUnit(*f, *unit, 0x1450908); InitMan(*f, *man, 1, Addr(unit->data()));
    uf::Inputs in; U model = 9;
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted && model == uf::ActivityRest && in.activity == 1,
            "state A not engaged = rest, first code 1");
    U n = 0; const uint8_t* codes = uf::ActivityCodes(uf::ActivityRest, n);
    Require(n == 2 && codes[0] == 1 && codes[1] == 9, "rest codes");
    codes = uf::ActivityCodes(uf::ActivityMarch, n);
    Require(n == 4 && codes[0] == 2 && codes[1] == 10 && codes[2] == 23 && codes[3] == 24, "march codes");
    for (U state = 0x1450908; state <= 0x1450918; state += 4) {
        Put(unit->data(), 0xd6c, Addr(At(state)));
        Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted &&
                model == (state == 0x1450908 ? uf::ActivityRest : uf::ActivityMarch), "states A..E");
    }
    const U bad[] = {0x1450904, 0x145091c, 0x1450909, 0};
    for (U s : bad) {
        Put(unit->data(), 0xd6c, s ? Addr(At(s)) : 0);
        Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseFsmUnknown, "unrecognized FSM state refuses");
    }
    Put(unit->data(), 0xd6c, Addr(At(0x1450908))); Put(unit->data(), 0xd68, Addr(At(0x1320f2c)));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseFsmUnknown, "wrong FSM object refuses");
    Put(unit->data(), 0xd68, Addr(At(0x1320f28)));
    Put(unit->data(), 0xd9e, B(1));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseEngaged, "U+D9E engaged refuses");
    Put(unit->data(), 0xd9e, B(0)); Put(unit->data(), 0xda4, B(1));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseEngaged, "U+DA4 engaged refuses");
    Put(unit->data(), 0xda4, B(0));
    // Closure rule on the pack: class variance, environment entries, speed band.
    Pack v = k; v.e[uf::E10] = 6;                                             // E10 + env(3: none) != E3D0
    Wire(*f, v);
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseClassVariance, "rest codes disagree: class variance");
    v = k; v.envField = 0; v.e[uf::E10] = 2; v.e[uf::EEnv0] = 3; v.e[uf::E3D0] = 5; Wire(*f, v);
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted && uf::ClassRate(in) == 5, "env entry joins E10");
    v.envField = 1; v.e[uf::EEnv1] = 3; Wire(*f, v);
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted, "environment entry 1");
    v = k; v.e[uf::E10] = v.e[uf::E3D0] = 20; Wire(*f, v);                    // 110% of 20 = 22
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseSpeedBand, "speed band changes the rate: refuse");
    v.e[uf::EMulFast] = v.e[uf::EMulMed] = v.e[uf::EMulSlow] = 100; Wire(*f, v);
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted, "identity band admits");
    Wire(*f, k);
    // Cold records.
    const U root = Get<U>(unit->data(), 0x14);
    Put(unit->data(), 0x14, U(0));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseColdRecords, "no root");
    Put(unit->data(), 0x14, root);
    Put(f->mg.data(), 0x6c0, U(0));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseColdRecords, "no stat record");
    Wire(*f, k);
    Put(unit->data(), 0xd48, B(200));
    Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::RefuseNoRow, "row index out of table");
    Put(unit->data(), 0xd48, B(0));
    // Every code of each model gives the SAME native step for the default pack on the image (homogeneous unit).
    for (U m = 0; m < uf::ActivityCount; ++m) {
        Put(unit->data(), 0xd6c, Addr(At(m == uf::ActivityRest ? 0x1450908 : 0x1450918)));
        Require(uf::ResolveUnit(Addr(unit->data()), in, model) == uf::Admitted, "model resolves");
        const uint8_t* cs = uf::ActivityCodes(static_cast<uf::UnitActivity>(m), n);
        for (U c = 0; c < n; ++c) {
            Put(man->data(), 0x1b8, static_cast<U>(cs[c])); Put(man->data(), 0x370, int32_t(497)); Put(man->data(), 0x374, U(0));
            node20Value = 0;
            Native(0x670f40, A(*man));
            uf::Inputs one = in; one.activity = cs[c];
            const uf::State s = uf::Step(one, {497, 0});
            Require(Get<int32_t>(man->data(), 0x370) == s.acc && Get<U>(man->data(), 0x374) == s.level, "model code step = native");
            Require(s.acc == uf::Step(in, {497, 0}).acc && s.level == uf::Step(in, {497, 0}).level, "codes agree with each other");
        }
    }
}

// ---- 3. gate ABI ------------------------------------------------------------------------------------------------------
__declspec(naked) static void __cdecl CallGateRaw(U gate, U a, U* out) {
    __asm {
        push ebx
        push esi
        push edi
        push ebp
        mov eax, dword ptr [esp + 20]
        mov ecx, dword ptr [esp + 24]
        mov edx, dword ptr [esp + 28]
        push edx
        mov dword ptr [edx + 20], esp
        mov ebx, 0xB1B1B1B1
        mov esi, 0xC2C2C2C2
        mov edi, 0xD3D3D3D3
        mov ebp, 0xE4E4E4E4
        call eax
        mov edx, dword ptr [esp]
        mov dword ptr [edx], ebx
        mov dword ptr [edx + 4], esi
        mov dword ptr [edx + 8], edi
        mov dword ptr [edx + 12], ebp
        mov dword ptr [edx + 16], esp
        add esp, 4
        pop ebp
        pop edi
        pop esi
        pop ebx
        ret
    }
}
static U stubCalls, stubSelf;
static void __fastcall ForwardStub(U self, U) { ++stubCalls; stubSelf = self; }
static void CheckAbi(const U (&out)[6], const char* what) {
    Require(out[0] == 0xB1B1B1B1 && out[1] == 0xC2C2C2C2 && out[2] == 0xD3D3D3D3 && out[3] == 0xE4E4E4E4, what);
    Require(out[4] == out[5], what);
}
static void TestGate() {
    label = "gate abi";
    U bindings[KNTWR_BIND_COUNT] = {};
    Require(uf::Bind(Addr(image), bindings) && bindings[KNTWR_BIND_U_FATIGUE] == uf::GateAddress(), "Bind writes the gate");
    Require(up::Bind(Addr(image), bindings) && bindings[KNTWR_BIND_U_OCC] == Addr(&up::g_occ), "policy Bind writes g_occ");
    std::array<U, 0x80> vt{}; vt[0x108 / 4] = Fn(&ForwardStub);
    Soldier a{}, other{};
    Put(a.data(), 0, Addr(vt.data())); Put(other.data(), 0, Addr(vt.data()));
    U slot[up::kSlotWords] = {};
    slot[uf::SlotAcc] = static_cast<U>(-1234); slot[uf::SlotLevel] = 3;
    up::g_occ = up::Occurrence{}; up::g_occ.unitIndex = ~0u;
    U out[6] = {};
    // live apply: entity == A and mask bit set
    up::g_occ.entity = A(a); up::g_occ.mask = 1; up::g_occ.slot[0] = slot;
    Put(a.data(), 0x370, U(7)); Put(a.data(), 0x374, U(7)); stubCalls = 0;
    CallGateRaw(uf::GateAddress(), A(a), out);
    CheckAbi(out, "apply: callee-saved registers and ESP preserved");
    Require(Get<int32_t>(a.data(), 0x370) == -1234 && Get<U>(a.data(), 0x374) == 3 && stubCalls == 0, "apply writes the pair, no native call");
    // repeated occurrence of the same man: idempotent
    CallGateRaw(uf::GateAddress(), A(a), out);
    Require(Get<int32_t>(a.data(), 0x370) == -1234 && Get<U>(a.data(), 0x374) == 3 && stubCalls == 0, "apply is idempotent");
    // no mask: native fallback through [[A]+108]
    up::g_occ.mask = 0; Put(a.data(), 0x370, U(9)); Put(a.data(), 0x374, U(9));
    CallGateRaw(uf::GateAddress(), A(a), out);
    CheckAbi(out, "fallback: registers and ESP preserved");
    Require(stubCalls == 1 && stubSelf == A(a) && Get<U>(a.data(), 0x370) == 9 && Get<U>(a.data(), 0x374) == 9,
            "no mask forwards to the native selector with ECX = A, no write");
    // another man while a live mask is open: contract miss, native forward, counted
    U words[uf::kWords]; uf::Snapshot(words); const U before = words[uf::ContractMisses];
    up::g_occ.mask = 1; up::g_occ.entity = A(a); stubCalls = 0;
    CallGateRaw(uf::GateAddress(), A(other), out);
    CheckAbi(out, "miss: registers and ESP preserved");
    uf::Snapshot(words);
    Require(stubCalls == 1 && stubSelf == A(other) && words[uf::ContractMisses] == before + 1 && Get<U>(other.data(), 0x370) == 0,
            "entity mismatch with a live mask: native forward + contract miss counted");
    // not an occurrence at all (entity 0, mask 0): native
    up::g_occ = up::Occurrence{}; up::g_occ.unitIndex = ~0u; stubCalls = 0;
    CallGateRaw(uf::GateAddress(), A(other), out);
    uf::Snapshot(words);
    Require(stubCalls == 1 && words[uf::ContractMisses] == before + 1, "outside an occurrence: native, not a miss");
}

// ---- 4. provider through the shared module ----------------------------------------------------------------------------
struct World {
    Fix fix;
    Unit unit{};
    Soldier men[4];
    Soldier ref;                                     // the native reference man (homogeneous unit, same activity)
    std::array<U, 8> members{}, registry{};
    std::array<B, 0x300> manager{};
    void Lists(U count) {
        Put(unit.data(), 0x2cc, count); Put(unit.data(), 0x2d0, Addr(members.data()));
        Put(manager.data(), 0x24c, U(4)); Put(manager.data(), 0x250, Addr(registry.data()));
        Put(manager.data(), 0x260, U(4)); Put(manager.data(), 0x264, Addr(registry.data()));
    }
    void Init() {
        Wire(fix, DefaultPack());
        InitUnit(fix, unit, 0x1450908);
        Put(unit.data(), 0xc74, U(495)); Put(unit.data(), 0xc70, U(0)); Put(unit.data(), 0xd48, B(0));
        for (U k = 0; k < 4; ++k) {
            InitMan(fix, men[k], 100 + k, Addr(unit.data())); members[k] = registry[k] = A(men[k]);
            Put(men[k].data(), 0x370, U(495)); Put(men[k].data(), 0x374, U(0));
        }
        InitMan(fix, ref, 900, Addr(unit.data()));
        Put(ref.data(), 0x370, U(495)); Put(ref.data(), 0x374, U(0));
        Lists(4);
    }
    void Native(Soldier& s) { ::Native(0x670f40, A(s)); }
};
static uint64_t Mix(uint64_t h, U v) { return (h ^ v) * 1099511628211ull; }
static U RefuseWord(uf::Reason r) { return static_cast<U>(uf::RefuseBase) + r - 1; }
static bool StartModule(World& w, U mode) {
    up::Reset();
    if (!uf::Start(Addr(image), mode)) return false;
    up::Config cfg{};
    cfg.imageBase = Addr(image); cfg.providers[up::Fatigue] = uf::Provider(); cfg.s0 = true;
    U bindings[KNTWR_BIND_COUNT] = {};
    uf::Bind(Addr(image), bindings);                  // the gate reads &g_occ through this
    return up::Start(cfg);
}
// One stage: `ran` men run their occurrence through the gate (apply when admitted live, else the image's native selector).
static void Stage(World& w, U ran, U mode) {
    up::BeginStage(Addr(w.manager.data()));
    for (U k = 0; k < ran; ++k) {
        const U mask = up::BeginOccurrence(A(w.men[k]));
        U out[6] = {};
        if (mode == up::Live) CallGateRaw(uf::GateAddress(), A(w.men[k]), out);
        else ::Native(0x670f40, A(w.men[k]));
        up::EndOccurrence();
        (void)mask;
    }
    up::EndStage();
}
static uint64_t Scenario(World& w, bool verify) {
    uint64_t h = 1469598103934665603ull;
    label = "provider live";
    w.Init();
    Require(StartModule(w, up::Live), "start live module on the mapped image");
    // selection equals the shared scan
    kntwr_unit_select::Rules rules{};
    Require(rules.Pin(Addr(image)), "rules pin");
    struct Ctx { World* w; U count, handle, ord; } ctx = {&w, 0, 0, 0};
    kntwr_unit_select::Scan(rules, Addr(w.manager.data()), [](void* c, U unit, U ord, U) {
        Ctx& x = *static_cast<Ctx*>(c); ++x.count; x.handle = unit; x.ord = ord; return true; }, &ctx, 16);
    // (the scan above is read-only: it only looks at the registry)
    // stage 1: three of four men run (man 3 is out of the worklist)
    Stage(w, 3, up::Live);
    if (verify) {
        Require(up::UnitCount() == ctx.count && ctx.count == 1 && up::View(0)->handle == ctx.handle, "module selection = shared scan");
        Require(up::View(0)->memberCount == 4, "all four admissible men selected");
        Require(up::UnitIndexOf(Addr(w.unit.data())) == 0, "UnitIndexOf");
    }
    w.Native(w.ref);                                  // the native step of the homogeneous reference man
    const int32_t refAcc = Get<int32_t>(w.ref.data(), 0x370); const U refLevel = Get<U>(w.ref.data(), 0x374);
    for (U k = 0; k < 4; ++k) {
        const int32_t acc = Get<int32_t>(w.men[k].data(), 0x370); const U level = Get<U>(w.men[k].data(), 0x374);
        if (verify) Require(acc == refAcc && level == refLevel, "stage 1: unit pair = native step (running men and the published out-of-worklist man)");
        h = Mix(Mix(h, static_cast<U>(acc)), level);
    }
    if (verify) Require(Get<U>(w.unit.data(), 0xc74) == 495 && Get<U>(w.unit.data(), 0xc70) == 0, "U+C70/C74 never written");
    U words[uf::kWords]; uf::Snapshot(words);
    if (verify) Require(words[uf::Advances] == 1 && words[uf::Inits] == 1 && words[uf::OutOfWorklistWrites] == 1 &&
                        words[uf::Applies] == 3 && words[uf::RestUnitStages] == 1, "one advance, one init, one published man");
    // stages 2..40: all men, duplicate occurrence of man 0 inside the stage: still one advance
    for (U s = 2; s <= 40; ++s) {
        up::BeginStage(Addr(w.manager.data()));
        for (U pass = 0; pass < 2; ++pass)
            for (U k = 0; k < 4; ++k) {
                if (pass && k) continue;
                up::BeginOccurrence(A(w.men[k])); U out[6] = {}; CallGateRaw(uf::GateAddress(), A(w.men[k]), out); up::EndOccurrence();
            }
        up::EndStage();
        w.Native(w.ref);
        for (U k = 0; k < 4; ++k) {
            const int32_t acc = Get<int32_t>(w.men[k].data(), 0x370); const U level = Get<U>(w.men[k].data(), 0x374);
            if (verify) Require(acc == Get<int32_t>(w.ref.data(), 0x370) && level == Get<U>(w.ref.data(), 0x374),
                                "stages: unit pair = native step of a homogeneous unit");
            h = Mix(Mix(h, static_cast<U>(acc)), level);
        }
    }
    uf::Snapshot(words);
    if (verify) Require(words[uf::Advances] == 40 && words[uf::Inits] == 1, "one advance per stage, no re-init within a generation");
    if (verify) Require(Get<U>(w.men[0].data(), 0x374) >= 1, "the level climbed across a hysteresis threshold");
    // non-member occurrence stays native (a serial that is not selected)
    {
        const U mask = up::BeginOccurrence(A(w.ref));
        if (verify) Require(mask == 0 && up::g_occ.unitIndex == ~0u && up::g_occ.unit == nullptr, "serial not selected: native, no unit");
        up::EndOccurrence();
    }
    // generation re-init: the member list changes -> state re-initialised from the native means
    Put(w.unit.data(), 0xc74, U(1234)); Put(w.unit.data(), 0xc70, U(1));
    w.members[3] = 0; w.Lists(3);
    Stage(w, 3, up::Live);
    uf::Snapshot(words);
    Put(w.ref.data(), 0x370, U(1234)); Put(w.ref.data(), 0x374, U(1)); w.Native(w.ref);
    if (verify) {
        Require(words[uf::Inits] == 2 && words[uf::GenerationInits] == 1, "membership change re-initialises from U+C74/U+C70");
        Require(Get<int32_t>(w.men[1].data(), 0x370) == Get<int32_t>(w.ref.data(), 0x370) &&
                Get<U>(w.men[1].data(), 0x374) == Get<U>(w.ref.data(), 0x374), "re-init pair = native step from the means");
        Require(up::View(0)->memberCount == 3, "departed member left the unit");
    }
    h = Mix(Mix(h, static_cast<U>(Get<int32_t>(w.men[1].data(), 0x370))), Get<U>(w.men[1].data(), 0x374));
    // refusals: inactive reset (never resurrected), engaged -> native selector, stance at generation init
    Put(w.unit.data(), 0xaa0, U(0));
    Stage(w, 1, up::Live);
    uf::Snapshot(words);
    if (verify) Require(words[RefuseWord(uf::RefuseInactive)] == 1 && words[uf::Resets] == 1, "inactive reset refuses and counts");
    Put(w.unit.data(), 0xaa0, U(1)); Put(w.unit.data(), 0xc74, U(0)); Put(w.unit.data(), 0xc70, U(0));
    Stage(w, 3, up::Live);
    uf::Snapshot(words);
    if (verify) Require(words[uf::Inits] == 3 && words[uf::GenerationInits] == 2,
                        "re-admission initialises again from the (reset) means, never from the dropped state");
    Put(w.unit.data(), 0xd9e, B(1));
    Stage(w, 1, up::Live);
    uf::Snapshot(words);
    if (verify) Require(words[RefuseWord(uf::RefuseEngaged)] == 1 && up::View(0)->admitted == 0, "engaged unit is refused");
    Put(w.unit.data(), 0xd9e, B(0));
    Put(w.men[2].data(), 0x220, U(1)); w.members[3] = A(w.men[3]); w.Lists(4);    // join with a stance != 0
    Stage(w, 3, up::Live);
    uf::Snapshot(words);
    if (verify) Require(words[RefuseWord(uf::RefuseStance)] == 1, "a member with stance != 0 refuses at generation init");
    Put(w.men[2].data(), 0x220, U(0));
    Stage(w, 4, up::Live);
    // Drain cooldown: drained at stage s -> native until the generation changed AND 64 stages passed
    up::Drain(0, up::Fatigue, 1);
    U admittedBefore = 0;
    { U hw[up::kHeaderWords]; up::Snapshot(hw); admittedBefore = hw[up::AdmittedFatigue]; }
    w.members[3] = 0; w.Lists(3);                                                  // generation changes right after the drain
    for (U s = 0; s < 63; ++s) {                                                   // stages drain+1 .. drain+63
        Stage(w, 3, up::Live);
        U hw[up::kHeaderWords]; up::Snapshot(hw);
        if (verify) Require(hw[up::AdmittedFatigue] == 0 && up::View(0)->admitted == 0, "drained: native until the cooldown ends");
    }
    Stage(w, 3, up::Live);                                                         // stage = drain stage + 64
    { U hw[up::kHeaderWords]; up::Snapshot(hw); if (verify) Require(hw[up::AdmittedFatigue] == 1 && admittedBefore == 1, "re-admitted after the cooldown"); }
    uf::Snapshot(words);
    for (U w32 : {uf::Advances, uf::Inits, uf::RestUnitStages, uf::OutOfWorklistWrites, uf::Retires, uf::Applies}) h = Mix(h, words[w32]);
    up::Stop(); uf::Stop();
    return h;
}
static void TestShadow() {
    label = "provider shadow";
    auto w = std::make_unique<World>();
    w->Init();
    Require(StartModule(*w, up::Shadow), "start shadow module");
    for (U s = 1; s <= 6; ++s) {
        if (s == 4) Put(w->men[2].data(), 0x370, Get<int32_t>(w->men[2].data(), 0x370) + 5);   // a heterogeneous straggler
        up::BeginStage(Addr(w->manager.data()));
        for (U k = 0; k < 4; ++k) {
            Require(up::BeginOccurrence(A(w->men[k])) == 0, "a shadow provider never sets a mask bit");
            ::Native(0x670f40, A(w->men[k]));
            up::EndOccurrence();
        }
        up::EndStage();
        if (s == 4) Put(w->men[2].data(), 0x370, Get<int32_t>(w->men[2].data(), 0x370) - 5);  // (unit pair continues from means)
    }
    U words[uf::kWords]; uf::Snapshot(words);
    Require(words[uf::ShadowMen] == 24 && words[uf::ShadowAccEqual] + words[uf::ShadowAccDiff] == 24, "every occurrence observed");
    Require(words[uf::ShadowAccDiff] >= 1 && words[uf::DAccBase + 3] >= 1, "the straggler shows as a 4..7 accumulator divergence");
    Require(words[uf::ClassBase + 0] == 24, "the men's native class is class 0 (activity 1)");
    Require(words[uf::Advances] == 6, "six unit advances");
    up::Stop(); uf::Stop();
}
static void TestDeterminism() {
    label = "determinism";
    auto a = std::make_unique<World>(); auto b = std::make_unique<World>();
    const uint64_t ha = Scenario(*a, true);
    const uint64_t hb = Scenario(*b, false);
    Require(ha == hb, "two worlds at different addresses give the same decision chain");
    Require(a.get() != b.get(), "distinct worlds");
}
// Microbench (informational, never a pass/fail criterion): ns per occurrence of the policy runner's own work. The step is a
// no-op stub (thiscall-compatible), so the numbers are the runner overhead admitted vs non-admitted.
static void __fastcall StubStep(void*, void*) {}
static void Bench() {
    label = "bench";
    auto w = std::make_unique<World>();
    w->Init();
    Require(StartModule(*w, up::Live), "start live module (bench)");
    up::BeginStage(Addr(w->manager.data()));
    Require(up::View(0) && up::View(0)->admitted, "bench unit admitted");
    U entries[KNTWR_CLONE_COUNT] = {};
    const U stub = static_cast<U>(reinterpret_cast<uintptr_t>(&StubStep));
    entries[KNTWR_CLONE_BRAIN_U] = stub;
    const U core = Addr(image) + (0x66CE00 - 0x400000);
    constexpr U kIters = 2000000;
    LARGE_INTEGER f, t0, t1; QueryPerformanceFrequency(&f);
    auto ns = [&](LARGE_INTEGER a, LARGE_INTEGER b) { return (b.QuadPart - a.QuadPart) * 1e9 / f.QuadPart / kIters; };
    const U man = A(w->men[0]), ref = A(w->ref);
    QueryPerformanceCounter(&t0);
    for (U i = 0; i < kIters; ++i) { up::BeginOccurrence(man); up::EndOccurrence(); }
    QueryPerformanceCounter(&t1); const double seamAdm = ns(t0, t1);
    QueryPerformanceCounter(&t0);
    for (U i = 0; i < kIters; ++i) { up::BeginOccurrence(ref); up::EndOccurrence(); }
    QueryPerformanceCounter(&t1); const double seamNat = ns(t0, t1);
    QueryPerformanceCounter(&t0);
    for (U i = 0; i < kIters; ++i) up::RunOccurrence(man, 0, core, entries);
    QueryPerformanceCounter(&t1); const double runAdm = ns(t0, t1);
    QueryPerformanceCounter(&t0);
    for (U i = 0; i < kIters; ++i) up::RunOccurrence(ref, 1, stub, entries);
    QueryPerformanceCounter(&t1); const double runNat = ns(t0, t1);
    QueryPerformanceCounter(&t0);
    for (U i = 0; i < kIters; ++i) StubStep(reinterpret_cast<void*>(ref), nullptr);
    QueryPerformanceCounter(&t1); const double bare = ns(t0, t1);
    up::EndStage();
    std::printf("bench ns/occurrence: begin+end admitted %.2f non-member %.2f | run admitted %.2f non-core %.2f | bare call %.2f\n",
                seamAdm, seamNat, runAdm, runNat, bare);
    up::Stop(); uf::Stop();
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: native_unit_fatigue_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    label = "start";
    Require(uf::Start(Addr(image), up::Live), "fatigue Start pins the image tables and the unit model codes");
    Require(!uf::Start(0, up::Live) && !uf::Start(Addr(image), 0), "Start refuses a missing base / mode");
    Require(uf::Start(Addr(image), up::Live), "restart");
    TestArithmetic();
    TestUnitModel();
    TestGate();
    TestDeterminism();
    TestShadow();
    Bench();
    std::printf("native_unit_fatigue_oracle OK: %u step cases vs 0x670F40 (level up %u, level down %u, clamp low %u, clamp high %u, "
                "band applied %u, env added %u, node20==1 %u, activity>0x4E %u, no unit %u, wrapped %u), %u checks\n",
                cases, cov[0], cov[1], cov[2], cov[3], cov[4], cov[5], cov[6], cov[7], cov[8], cov[9], checks);
    return 0;
}
