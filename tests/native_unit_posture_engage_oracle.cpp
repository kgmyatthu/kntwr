// Per-unit posture / engage oracle (mapped original image). The BRAIN_U_DRIVER / BRAIN_US_DRIVER / BRAIN_U_FINALIZE /
// BRAIN_U_PATH clones and the bound gate bodies run next to the untouched originals on identical synthetic real-layout
// soldiers; nothing is mocked in the image and no live process is touched. Contracts checked:
//  * mask 0 (and every mismatching occurrence): each retargeted body is bit-exact against its original (soldier, unit, world,
//    shared staging, return value, MXCSR/x87 control state);
//  * posture apply: write set == the native exit -> store -> enter -> update sequence for the same chosen state over every
//    (old, target) state pair and every iteration budget, AL as native, the next-state slots (10FBBDA) trapped; native
//    single-step transitions found by brute force match the apply bit-exactly; unsupported state / fsm table -> native + Drain;
//  * engage gates: the inline stores write exactly the unit's EV values at 658C62 / 658FDE / 6590FC / 658DEF / 658DFB, the
//    frozen D9D replaces the per-man read at 658FB8, target+224 = 9 / node / RNG effects untouched (native-equal values are
//    bit-exact against the original);
//  * lookups served from the unit's frozen slot equal the native results, ABI (callee-saved registers, stack, x87) of every gate.
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
#include "native_unit_posture_engage.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace policy = ntw2_unit_policy;
namespace ue = ntw2_unit_posture_engage;
static_assert(sizeof(void*) == 4, "x86 native ABI");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile U tlsPad[32];

// The oracle owns the occurrence record and the drain sink (native_unit_policy.cpp is not linked).
namespace ntw2_unit_policy {
Occurrence g_occ;
static U drainCalls, drainMechanic, drainCode;
void Drain(U, U mechanic, U code) { ++drainCalls; drainMechanic = mechanic; drainCode = code; }
} // namespace ntw2_unit_policy

static B* image;
static U delta, checks, cases;
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
static void UnexpectedBinding() { Fail("unrelated clone binding executed"); }
static void __stdcall TrapNext(U) { Fail("native next-state virtual (10FBBDA) executed by an apply"); }
__declspec(naked) static void Ret4() { __asm ret 4 }
// --brain-s0 gates of BRAIN_US_DRIVER: pure forwarders (the oracle checks the unit gates, not the timer).
__declspec(naked) static void S0NodeBegin() { __asm { mov ecx, edi
                                                      jmp dword ptr [eax + 4] } }
__declspec(naked) static void S0NodeStep() { __asm { mov ecx, edi
                                                     jmp dword ptr [eax + 8] } }
__declspec(naked) static void S0Finalize() { __asm jmp dword ptr [eax + 0x1A4] }

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
    Put(At(0x1841bb8), 0, U(_tls_index)); tlsPad[0] = 0;
    std::fill(std::begin(bindings), std::end(bindings), Fn(&UnexpectedBinding));
    Require(ue::Bind(A(image), bindings), "unit posture/engage gates bind");
    bindings[NTW2_BIND_U_OCC] = A(&policy::g_occ);
    bindings[NTW2_BIND_S0_NODE_BEGIN] = Fn(&S0NodeBegin);
    bindings[NTW2_BIND_S0_NODE_STEP] = Fn(&S0NodeStep);
    bindings[NTW2_BIND_S0_FINALIZE] = Fn(&S0Finalize);
    U detail = 0;
    const U error = ntw2_build_clones(A(image), bindings, &clones, &detail);
    if (error) Fail("clone construction error=%u detail=%u", error, detail);
}

// ---- soldier / world fixtures (the real-layout fixtures of native_brain2_oracle.cpp) ----------------------------------
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
        chargeMethods[1] = 0; charge = {A(chargeMethods.data()), 0xc001};
        Put(At(0x176cff8), 0, 1.0f); Put(At(0x176cffc), 0, 0.0f);
    }
};
// Unit record fields the three unit-only lookups read: controller chain [[U+14]+8]+B0 (mode word +14 = 1), U+D9E/+DA8,
// the ability table (one entry whose id is 4 and whose +28 flag is set -> 57E1F0 returns the 131A7B8 constant) and the
// modifier row table [[U+2C]+E4+4*[U+C70]] (index 2 -> 0x5151). `scratch` is a 0x100-byte zero buffer for the root.
static void FillLookups(B* unit, U root) {
    Put(unit, 0x14, root);
    B* rootBytes = reinterpret_cast<B*>(root);
    Put(rootBytes, 8, A(unit + 0x900)); Put(unit + 0x900, 0xB0, A(unit + 0xA00));
    Put(unit + 0xA00, 0x14, U(1)); Put(unit, 0xD9E, B(1)); Put(unit, 0xDA8, 9.0f);
    Put(unit, 0xDAC + 0xC, U(1)); Put(unit, 0xDAC + 0x10, A(unit + 0xB00));
    Put(unit + 0xB00, 4, A(unit + 0xB80)); Put(unit + 0xB80, 0, U(4)); Put(unit + 0xB00, 0x28, B(1));
    Put(unit, 0x2C, A(unit + 0xC00)); Put(unit, 0xC70, U(2)); Put(unit + 0xC00, 0xE4 + 8, U(0x5151));
}
struct Case {
    std::array<B, 0x800> agent{};
    std::array<B, 0x40> timer{};
    std::array<U, 3> slot{};
    std::array<B, 0x60> animation{};
    std::array<B, 0x40> slotHeader{};
    std::array<B, 28 * 4> rows{};
    std::array<B, 0x1000> unit{};
    std::array<B, 0x100> reference{};
    std::array<U, 0x80> classTable{};
    std::array<B, 0x100> mode{};
    // 819770's active-arm terrain world (native_brain2_oracle.cpp FinalizerWorld): swapped in as A+28 where a case needs it.
    std::array<B, 0x10> fwRoot{};
    std::array<B, 0x100> fwModel{};
    std::array<B, 0x28> fwGrid{};
    std::array<U, 16 * 16> fwCells{};
    std::array<B, 0x28> fwField{};
    std::array<U, 2 * 16 * 16> fwSamples{};
    std::array<B, 0x200> fwFrame{};
    void Init(World& w, U id) {
        Put(fwRoot.data(), 8, A(fwModel.data()));
        Put(fwModel.data(), 0x58, U(33));
        Put(fwModel.data(), 0x84, -7.0f); Put(fwModel.data(), 0x88, -7.0f);
        Put(fwModel.data(), 0x8c, 7.0f); Put(fwModel.data(), 0x90, 7.0f);
        Put(fwModel.data(), 0x9c, A(fwField.data())); Put(fwModel.data(), 0xa0, A(fwGrid.data()));
        Put(fwGrid.data(), 0, A(fwCells.data())); Put(fwGrid.data(), 8, U(4));
        Put(fwGrid.data(), 0x10, U(8)); Put(fwGrid.data(), 0x14, U(15)); Put(fwGrid.data(), 0x24, 1.0f);
        for (U i = 0; i < fwCells.size(); ++i) fwCells[i] = (i * 37 & 0xff) | (i % 7 == 0 ? 0x100u : 0u);
        Put(fwField.data(), 0, A(fwSamples.data())); Put(fwField.data(), 8, U(4));
        Put(fwField.data(), 0x10, U(8)); Put(fwField.data(), 0x14, U(15));
        Put(fwField.data(), 0x1c, -8.0f); Put(fwField.data(), 0x20, 1.0f); Put(fwField.data(), 0x24, 1.0f);
        for (U i = 0; i < 256; ++i) { const float h = 0.125f * (i % 13); std::memcpy(&fwSamples[2 * i], &h, 4); }

        B* ag = agent.data();
        std::memcpy(classTable.data(), At(0x1333714), sizeof(classTable));
        for (U slotOffset : {0x128u, 0x12cu, 0x138u, 0x150u}) classTable[slotOffset / 4] = Fn(&Ret4);
        Put(ag, 0, A(classTable.data()));
        Put(ag, 0x28, A(w.root.data())); Put(ag, 0x2c, id);
        Put(ag, 0x30, B(1)); Put(ag, 0x34, U(0x401)); Put(ag, 0x38, U(0x800));
        Put(ag, 0x6c, 1.0f); Put(ag, 0xec, B(1));
        Put(ag, 0x118, B(1)); Put(ag, 0x114, B(0)); Put(ag, 0x115, B(0));
        Put(ag, 0x18c, B(1)); Put(ag, 0x19c, U(25)); Put(ag, 0x1a4, 0.75f);
        Put(ag, 0x1b8, U(1)); Put(ag, 0x1bc, U(0x20)); Put(ag, 0x1c0, U(0));
        Put(ag, 0x1d8, U(4)); Put(ag, 0x1e4, 1.25f); Put(ag, 0x220, U(0));
        Put(ag, 0x228, A(ag)); Put(ag, 0x228 + 0xa0, A(w.root.data()));
        Put(ag, 0x22c, A(w.nodeMethods.data()));
        Put(ag, 0x514, A(w.stats.data())); Put(ag, 0x518, A(timer.data()));
        Put(ag, 0x619, B(1)); Put(ag, 0x5ab, B(0)); Put(ag, 0x364, B(1));
        Put(ag, 0xd4, 0.5f); Put(ag, 0xd8, -0.25f); Put(ag, 0xdc, 0.75f);
        Put(ag, 0xe0, uint16_t(17)); Put(ag, 0x448, 0.625f);
        Put(timer.data(), 0, A(At(0x132b308))); Put(timer.data(), 4, A(w.root.data()));
        Put(timer.data(), 0x14, 0.25f); Put(timer.data(), 0x1c, 0.125f);
        Put(mode.data(), 0x14, U(0));
        Put(unit.data(), 0x14, A(w.root.data())); Put(unit.data(), 0x2c, A(unit.data() + 0x800));
        Put(w.model.data(), 0xb0, A(mode.data()));
        Put(reference.data(), 0, A(ag)); Put(reference.data(), 0xec, B(1));
        Put(ag, 0x1f4, A(unit.data() + 0x800));
        FillLookups(unit.data(), A(unit.data() + 0xF00));
    }
};

// ---- calling helpers -----------------------------------------------------------------------------------------------
static U gEsp0, gEsp1, gEbx, gEsi, gEdi, gEbp, gFlags;
static unsigned short gFsw;
// thiscall(ecx) with sentinel callee-saved registers; records stack pointer, saved registers, flags and the x87 status.
__declspec(naked) static U __cdecl CallChecked(U entry, U ecxIn) {
    __asm {
        push ebx
        push esi
        push edi
        push ebp
        mov eax, dword ptr [esp + 20]
        mov ecx, dword ptr [esp + 24]
        mov ebx, 11111111h
        mov esi, 22222222h
        mov edi, 33333333h
        mov ebp, 44444444h
        mov dword ptr [gEsp0], esp
        cld
        call eax
        mov dword ptr [gEsp1], esp
        mov dword ptr [gEbx], ebx
        mov dword ptr [gEsi], esi
        mov dword ptr [gEdi], edi
        mov dword ptr [gEbp], ebp
        fnstsw word ptr [gFsw]
        pushfd
        pop edx
        mov dword ptr [gFlags], edx
        pop ebp
        pop edi
        pop esi
        pop ebx
        ret
    }
}

static U gNodeEcx;
__declspec(naked) static void NodeProbe() { __asm { mov dword ptr [gNodeEcx], ecx
                                                     ret } }
// eax = [edi] = vtable, edi = node, as at the driver's node virtual runs; every callee-saved register but edi is checked.
__declspec(naked) static void __cdecl CallNodeGate(U gate, U vtable, U node) {
    __asm {
        push ebx
        push esi
        push edi
        push ebp
        mov eax, dword ptr [esp + 24]
        mov edi, dword ptr [esp + 28]
        mov ecx, dword ptr [esp + 20]
        mov ebx, 11111111h
        mov esi, 22222222h
        mov ebp, 44444444h
        mov dword ptr [gEsp0], esp
        call ecx
        mov dword ptr [gEsp1], esp
        mov dword ptr [gEbx], ebx
        mov dword ptr [gEsi], esi
        mov dword ptr [gEdi], 33333333h
        mov dword ptr [gEbp], ebp
        fnstsw word ptr [gFsw]
        pushfd
        pop edx
        mov dword ptr [gFlags], edx
        pop ebp
        pop edi
        pop esi
        pop ebx
        ret
    }
}
static LONG ReportFault(EXCEPTION_POINTERS* info, const char* what) {
    const EXCEPTION_RECORD* r = info->ExceptionRecord;
    const U eip = A(r->ExceptionAddress);
    const bool inImage = eip >= delta + 0x400000 && eip < delta + 0x400000 + 0x2000000;
    std::fprintf(stderr, "FAULT [%s] case=%s code=%08lX eip=%08X (image VA %08X) access=%08X\n", what, currentCase, r->ExceptionCode,
        eip, inImage ? eip - delta : 0, r->NumberParameters >= 2 ? static_cast<U>(r->ExceptionInformation[1]) : 0);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
static U V(U va);
static float NativeArrival(U unit) {
    __try { return reinterpret_cast<float (__thiscall*)(U)>(V(0x57E1F0))(unit); }
    __except (ReportFault(GetExceptionInformation(), "57E1F0")) { std::exit(3); }
}
static U Thiscall0(U entry, U receiver) {
    __try { return reinterpret_cast<U (__thiscall*)(U)>(entry)(receiver); }
    __except (ReportFault(GetExceptionInformation(), "thiscall0")) { std::exit(3); }
}
static void Thiscall1(U entry, U receiver, U arg) {
    __try { reinterpret_cast<void (__thiscall*)(U, U)>(entry)(receiver, arg); }
    __except (ReportFault(GetExceptionInformation(), "thiscall1")) { std::exit(3); }
}
static U Checked(U entry, U receiver) {
    __try { return CallChecked(entry, receiver); }
    __except (ReportFault(GetExceptionInformation(), "checked call")) { std::exit(3); }
}
static void RequireCleanAbi(const char* what, bool x87Result = false) {
    ++checks;
    if (gEsp0 != gEsp1) Fail("%s: stack pointer changed %08X -> %08X", what, gEsp0, gEsp1);
    if (gEbx != 0x11111111 || gEsi != 0x22222222 || gEdi != 0x33333333 || gEbp != 0x44444444)
        Fail("%s: callee-saved register clobbered ebx=%08X esi=%08X edi=%08X ebp=%08X", what, gEbx, gEsi, gEdi, gEbp);
    if (gFlags & 0x400) Fail("%s: direction flag set", what);
    if (((gFsw >> 11) & 7) != (x87Result ? 7u : 0u)) Fail("%s: x87 stack depth (fsw %04X)", what, gFsw);
}
static void CompareBytes(const void* expected, const void* actual, size_t size, const char* what) {
    const B* e = static_cast<const B*>(expected);
    const B* a = static_cast<const B*>(actual);
    for (size_t i = 0; i < size; ++i) {
        ++checks;
        if (e[i] != a[i]) Fail("%s +%zX expected=%02X actual=%02X", what, i, e[i], a[i]);
    }
}
static void SetOcc(U entity, U mask, U* postureSlot, U* engageSlot, const policy::UnitView* view, U unitIndex = 0) {
    policy::g_occ = {};
    policy::g_occ.entity = entity; policy::g_occ.unitIndex = unitIndex; policy::g_occ.mask = mask; policy::g_occ.unit = view;
    policy::g_occ.slot[policy::Posture] = postureSlot; policy::g_occ.slot[policy::Engage] = engageSlot;
}
static void ClearOcc() { policy::g_occ = {}; }
static U gDummySlot[2][64];
static const U kRest = 0x1454198, kFirst = 0x1454168;
static U V(U va) { return va + delta; }

// ---- posture fixtures ------------------------------------------------------------------------------------------------
// One soldier whose fsm sub-object (A+F4) uses table 134706C (no animation selection: the callbacks only touch fsm-relative
// fields), a pseudo-random but deterministic field block, and a guard region to catch stray writes.
using Soldier = std::array<B, 0x800>;
static void MakePosture(Soldier& s, U state, U budget, U seed, U table = 0x134706c) {
    s.fill(0);
    U x = seed * 2654435761u + 12345u;
    auto Rnd = [&] { x = x * 1664525u + 1013904223u; return x >> 8; };
    for (U o = 0x100; o < 0x150; o += 4) {
        const U r = Rnd();
        if (o & 4) Put(s.data(), o, static_cast<float>(static_cast<int>(r % 2000) - 700) / 64.0f);
        else Put(s.data(), o, r % 7 == 0 ? 0u : r);
    }
    Put(s.data(), 0x108, U(Rnd() % 3)); Put(s.data(), 0x10c, U(Rnd() % 2));
    Put(s.data(), 0xf4, V(table)); Put(s.data(), 0xf8, state ? V(kFirst + 4 * (state - 1)) : 0u);
    Put(s.data(), 0xfc, budget);
    for (U o = 0x600; o < 0x800; o += 4) Put(s.data(), o, 0xA5A5A5A5u ^ o);
}
static U StateAddr(U index) { return V(kFirst + 4 * index); }
// The native step effects of one 10FBBD0 iteration, performed by hand with the image callbacks: exit(old), store, enter(new).
static void CallState(U state, U slotOffset, U fsm) {
    const U table = Get<U>(reinterpret_cast<void*>(state), 0);
    const U target = Get<U>(reinterpret_cast<void*>(table), slotOffset);
    Thiscall1(target, state, fsm);
}
static U ReferenceApply(B* agent, U target, bool restAllowsAl = true) {
    (void)restAllowsAl;
    const U fsm = A(agent + 0xF4);
    const U cur = Get<U>(agent, 0xF8);
    if (!cur) return 1;
    const U budget = Get<U>(agent, 0xFC);
    if (cur != target) {
        CallState(cur, 0xC, fsm);
        Put(agent, 0xF8, target);
        CallState(target, 4, fsm);
        if (budget == 0) return 1;
    }
    CallState(Get<U>(agent, 0xF8), 8, fsm);
    return Get<U>(agent, 0xF8) != V(kRest) ? 1u : 0u;
}
static U PostureSlotFor(U targetIndex) {
    static U slot[64];
    std::memset(slot, 0, sizeof(slot));
    slot[ue::PsTarget] = targetIndex < 13 ? StateAddr(targetIndex) : 0;
    slot[ue::PsRest] = V(kRest); slot[ue::PsActivity] = 0; slot[ue::PsShadowTarget] = targetIndex;
    return A(slot);
}
static U savedNext[13];
static void SetNextTrap(bool on) {
    for (U i = 0; i < 13; ++i) {
        U* slot = reinterpret_cast<U*>(At(0x1346994 + 0x14 * i));
        if (on) { savedNext[i] = *slot; *slot = Fn(&TrapNext); }
        else *slot = savedNext[i];
    }
}
static U gNativeMatches, gNativePairs[13][13];
static void PostureGateCases() {
    const U gate = bindings[NTW2_BIND_U_POSTURE];
    const U original = A(At(0x10fc370));
    // --- mask 0 / mismatching entity / no target: native pass-through, bit-exact against the original 10FC370.
    currentCase = "posture gate pass-through";
    for (U state = 0; state <= 13; ++state) for (U budget : {0u, 1u, 3u}) for (U seed = 1; seed <= 6; ++seed) {
        for (U variant = 0; variant < 4; ++variant) {
            Soldier a, b;
            MakePosture(a, state, budget, seed); b = a;
            U* slot = reinterpret_cast<U*>(PostureSlotFor(12));
            U shadowSlot[64] = {};
            if (variant == 0) ClearOcc();
            else if (variant == 1) SetOcc(A(a.data()) + 8, policy::kMaskPosture, slot, slot, nullptr);   // another soldier
            else if (variant == 2) SetOcc(A(a.data()), policy::kMaskFatigue | policy::kMaskEngage, slot, slot, nullptr); // no posture bit
            else SetOcc(A(a.data()), policy::kMaskPosture, shadowSlot, shadowSlot, nullptr);             // posture slot without a target
            ResetFp(); const U wantAl = Thiscall0(original, A(a.data() + 0xF4)) & 0xFF;
            if (variant == 1) SetOcc(A(b.data()) + 8, policy::kMaskPosture, slot, slot, nullptr);
            else if (variant == 2) SetOcc(A(b.data()), policy::kMaskFatigue | policy::kMaskEngage, slot, slot, nullptr);
            else if (variant == 3) SetOcc(A(b.data()), policy::kMaskPosture, shadowSlot, shadowSlot, nullptr);
            ResetFp(); const U gotAl = Checked(gate, A(b.data() + 0xF4)) & 0xFF;
            RequireCleanAbi("posture gate pass-through");
            CompareBytes(a.data(), b.data(), a.size(), "pass-through leaves the soldier as the original 10FC370");
            Require(wantAl == gotAl, "pass-through returns the original AL");
            ++cases;
        }
    }
    ClearOcc();
    // --- apply: every (old, target) pair, budgets 0/1/3: write set == the native exit/store/enter/update sequence.
    currentCase = "posture apply write set";
    SetNextTrap(true);
    U transitions = 0, updates = 0;
    for (U old = 0; old <= 13; ++old) for (U target = 0; target < 13; ++target) for (U budget : {0u, 1u, 3u}) {
        Soldier a, b;
        MakePosture(a, old, budget, old * 17 + target * 5 + budget + 1); b = a;
        ResetFp(); const U wantAl = ReferenceApply(a.data(), StateAddr(target)) & 0xFF;
        U* slot = reinterpret_cast<U*>(PostureSlotFor(target));
        SetOcc(A(b.data()), policy::kMaskPosture, slot, slot, nullptr);
        const U before = ue::kWords;   // silence unused
        (void)before;
        ResetFp(); const U gotAl = Checked(gate, A(b.data() + 0xF4)) & 0xFF;
        RequireCleanAbi("posture apply");
        CompareBytes(a.data(), b.data(), a.size(), "apply writes exactly the native exit/store/enter/update effects");
        if (old == 0) Require(wantAl == 1 && gotAl == 1 && Get<U>(b.data(), 0xF8) == 0, "null state: native no-op, AL 1");
        else Require(Get<U>(b.data(), 0xF8) == StateAddr(target), "unit target state installed");
        Require(wantAl == gotAl, "AL is the native result (0 only when the state ends as rest)");
        if (old >= 1 && old - 1 != target) ++transitions; else if (old >= 1) ++updates;
        ++cases;
    }
    ClearOcc();
    Require(transitions > 0 && updates > 0, "apply covered transitions and update-only runs");
    // The same pairs against the ORIGINAL 10FC370: brute-force fsm inputs; every run whose native result is one
    // iteration toward the final state (reference == native bytes) counts as a native single-step match.
    SetNextTrap(false);
    currentCase = "posture native single-step cross-check";
    std::memset(gNativePairs, 0, sizeof(gNativePairs)); gNativeMatches = 0;
    U nativeRuns = 0;
    for (U old = 1; old <= 13; ++old) for (U seed = 1; seed <= 600; ++seed) {
        Soldier native, ref;
        MakePosture(native, old, 3, seed * 31 + old); ref = native;
        ResetFp(); const U nativeAl = Thiscall0(original, A(native.data() + 0xF4)) & 0xFF;
        ++nativeRuns;
        const U finalState = Get<U>(native.data(), 0xF8);
        if (finalState < StateAddr(0) || finalState > StateAddr(12) || ((finalState - StateAddr(0)) & 3)) continue;
        const U target = (finalState - StateAddr(0)) / 4;
        ResetFp(); const U refAl = ReferenceApply(ref.data(), finalState) & 0xFF;
        if (std::memcmp(native.data(), ref.data(), native.size()) || refAl != nativeAl) continue;
        // native == reference: the apply must equal it as well
        Soldier mine; MakePosture(mine, old, 3, seed * 31 + old);
        U* slot = reinterpret_cast<U*>(PostureSlotFor(target));
        SetOcc(A(mine.data()), policy::kMaskPosture, slot, slot, nullptr);
        SetNextTrap(true);
        ResetFp(); const U mineAl = Checked(gate, A(mine.data() + 0xF4)) & 0xFF;
        SetNextTrap(false);
        ClearOcc();
        RequireCleanAbi("posture apply vs native");
        CompareBytes(native.data(), mine.data(), native.size(), "apply equals the original 10FC370 where native took one step");
        Require(mineAl == nativeAl, "AL equals the original");
        ++gNativeMatches; ++gNativePairs[old - 1][target]; ++cases;
    }
    U distinct = 0, intoRest = 0;
    for (U i = 0; i < 13; ++i) for (U j = 0; j < 13; ++j) if (gNativePairs[i][j]) { ++distinct; if (j == 12) ++intoRest; }
    if (std::getenv("NTW2_ORACLE_TRACE"))
        std::fprintf(stderr, "posture native cross-check: runs=%u matches=%u distinct pairs=%u into rest=%u\n", nativeRuns, gNativeMatches, distinct, intoRest);
    Require(gNativeMatches >= 20 && distinct >= 4, "native single-step runs cover several (old, new) pairs");
    // --- unsupported contexts: the original runs and the unit drains (a state that is not one of the 13 singletons, an fsm
    // table outside the recovered set).
    currentCase = "posture unsupported contexts";
    for (U kind = 0; kind < 2; ++kind) {
        Soldier a, b;
        MakePosture(a, 3, 3, 77);
        static U fakeVt[5]; static U fakeState[1];
        fakeVt[0] = V(0x44c230); fakeVt[1] = V(0x44a780); fakeVt[2] = V(0x44a780); fakeVt[3] = V(0x44a780); fakeVt[4] = V(0x44a780);
        fakeState[0] = A(fakeVt);
        static std::array<U, 0x50> badTable;
        std::memcpy(badTable.data(), At(0x134706c), sizeof(badTable));
        if (kind == 0) Put(a.data(), 0xF8, A(fakeState));
        else { badTable[2] = V(0x4470b0); Put(a.data(), 0xF4, A(badTable.data())); }
        b = a;
        U* slot = reinterpret_cast<U*>(PostureSlotFor(12));
        SetOcc(A(b.data()), policy::kMaskPosture, slot, slot, nullptr);
        policy::drainCalls = 0;
        ResetFp(); const U wantAl = Thiscall0(original, A(a.data() + 0xF4)) & 0xFF;
        ResetFp(); const U gotAl = Checked(gate, A(b.data() + 0xF4)) & 0xFF;
        ClearOcc();
        Require(policy::drainCalls == 1 && policy::drainMechanic == policy::Posture, "unsupported context drains the unit for posture");
        CompareBytes(a.data(), b.data(), a.size(), "unsupported context runs the original 10FC370");
        Require(gotAl == wantAl, "unsupported context returns the original AL");
        ++cases;
    }
}

// ---- providers -----------------------------------------------------------------------------------------------------
struct UnitRig {
    std::array<B, 0x1000> unit{};
    std::array<U, 8> members{}, ran{};
    std::array<Soldier, 8> soldiers;
    policy::UnitView view{};
    void Setup(U activity, U speed, U count) {
        std::memset(unit.data(), 0, unit.size());
        Put(unit.data(), 0xD68, V(0x1320F28)); Put(unit.data(), 0xD6C, V(0x1450908 + 4 * activity));
        Put(unit.data(), 0xD68 + 0x24, speed);
        view = {}; view.handle = A(unit.data()); view.stage = 5; view.memberCount = count; view.members = members.data();
        view.ran = ran.data(); view.generation = 1;
        for (U i = 0; i < count; ++i) { members[i] = A(soldiers[i].data()); ran[i] = 5; soldiers[i].fill(0); }
    }
};
static void ProviderCases() {
    currentCase = "provider start";
    Require(ue::Start(A(image), 0, 0, clones.entries) && !ue::PostureProvider() && !ue::EngageProvider(), "off modes register nothing");
    Require(ue::Start(A(image), policy::Live, policy::Live, clones.entries), "live start on the pinned image");
    Require(ue::PostureProvider() && ue::EngageProvider() && ue::PostureProvider()->mechanic == policy::Posture &&
            ue::EngageProvider()->mechanic == policy::Engage && ue::PostureProvider()->mode == policy::Live, "providers describe themselves");
    // posture decide over the five unit FSM activities
    static UnitRig rig;
    ue::Reset();
    for (U activity = 0; activity < 5; ++activity) for (U speed : {0u, 1u, 2u, 7u}) {
        currentCase = "posture decide";
        rig.Setup(activity, speed, 3);
        U slot[64]; std::memset(slot, 0xCC, sizeof(slot));
        const U code = ue::PostureProvider()->decide(0, rig.view, slot);
        Require(slot[ue::PsActivity] == activity, "unit FSM activity read");
        Require(slot[ue::PsSpeedClass] == (speed == 0 ? 0 : speed == 1 ? 1 : speed == 2 ? 2 : 3), "command speed class");
        if (activity == 0) {
            Require(code == 0 && slot[ue::PsTarget] == V(kRest) && slot[ue::PsShadowTarget] == 12, "idle unit: rest target");
        } else {
            Require(code != 0 && slot[ue::PsTarget] == 0, "unit activity B..E has no closed mapping: refused, no target");
        }
        ++cases;
    }
    {
        currentCase = "posture decide refusals";
        rig.Setup(0, 0, 1); U slot[64];
        Put(rig.unit.data(), 0xD68, V(0x1320F28) + 4);
        Require(ue::PostureProvider()->decide(0, rig.view, slot) != 0, "unit FSM vtable mismatch refused");
        rig.Setup(0, 0, 1); Put(rig.unit.data(), 0xD6C, V(0x1450908) + 0x14);
        Require(ue::PostureProvider()->decide(0, rig.view, slot) != 0, "unit FSM state outside A..E refused");
        rig.Setup(0, 0, 1); rig.view.handle = 0;
        Require(ue::PostureProvider()->decide(0, rig.view, slot) != 0, "no unit refused");
        ++cases;
    }
    // engage decide: EV block, frozen D9D, lookups equal the native functions on the unit
    for (B d9d : {B(0), B(1)}) {
        currentCase = "engage decide";
        rig.Setup(0, 0, 2);
        Put(rig.unit.data(), 0xD9D, d9d);
        FillLookups(rig.unit.data(), A(rig.unit.data() + 0x1000 - 0x100));
        U slot[64]; std::memset(slot, 0xCC, sizeof(slot));
        Require(ue::EngageProvider()->decide(0, rig.view, slot) == 0, "engage admits a unit with a readable record");
        Require(slot[ue::EvClear] == 0 && slot[ue::EvP6] == 6 && slot[ue::EvP7] == 7 && slot[ue::EvD9dMode] == 1 &&
                slot[ue::EvD9dValue] == d9d && (slot[ue::EvF1And] & 0xFF) == 0 && (slot[ue::EvF1Or] & 0xFF) == 1 &&
                (slot[ue::EvL619And] & 0xFF) == 0 && (slot[ue::EvL619Or] & 0xFF) == 1, "EV block: native-equal phase/latch values, frozen D9D");
        Require(slot[ue::LkValid] == 7, "all three lookups evaluated");
        const U predicate = Thiscall0(V(0x55B0A0), A(rig.unit.data())) & 0xFF;
        Require(slot[ue::LkPredicate] == predicate && predicate == 1, "frozen 64F8F0 predicate == 55B0A0(U)");
        float arrival; std::memcpy(&arrival, &slot[ue::LkArrival], 4);
        const float native = NativeArrival(A(rig.unit.data()));
        Require(std::memcmp(&arrival, &native, 4) == 0 && (slot[ue::LkValid] & ue::kLkArrival), "frozen 57E1F0 arrival == native x87 result");
        Require(slot[ue::LkModifier] == 0x5151, "frozen 649520 row == [[U+2C]+E4+4*U+C70]");
        ++cases;
    }
}

static void ShadowCases() {
    currentCase = "shadow posture compare";
    Require(ue::Start(A(image), policy::Shadow, policy::Shadow, clones.entries), "shadow start");
    static UnitRig rig;
    ue::Reset();
    rig.Setup(0, 1, 4);
    U pslot[64]; 
    Require(ue::PostureProvider()->decide(0, rig.view, pslot) == 0 && pslot[ue::PsTarget] == 0 && pslot[ue::PsShadowTarget] == 12,
            "shadow decides but never publishes an apply target");
    rig.view.admitted = policy::kMaskPosture;
    const U states[4] = {12, 1, 0xFFFFFFFFu, 5};   // rest, state 1, null, state 5
    for (U i = 0; i < 4; ++i) Put(rig.soldiers[i].data(), 0xF8, states[i] == 0xFFFFFFFFu ? 0u : StateAddr(states[i]));
    rig.ran[3] = 4;                                   // member 3 did not run this stage
    ue::PostureProvider()->end(0, rig.view, pslot);
    U words[ue::kWords]; ue::Snapshot(words);
    Require(words[ue::WPCompare] == 3 && words[ue::WPCompare + 1] == 1 && words[ue::WPCompare + 2] == 1 &&
            words[ue::WPCompare + 3] == 1 && words[ue::WPCompare + 4] == 1, "compare: 3 run (1 agree, 1 disagree, 1 null), 1 not run");
    Require(words[ue::WPPairs] == 1 && words[ue::WPPairs + 1] == 12 && words[ue::WPPairs + 2] == 1 || words[ue::WPPairs] == 12,
            "the confusion matrix names the (native, unit) pairs");
    Require(words[ue::WPHist] == 3, "histogram counts the members that ran");
    // a moving unit is refused but still measured
    currentCase = "shadow posture histogram of a refused unit";
    rig.Setup(3, 2, 2); for (U i = 0; i < 2; ++i) Put(rig.soldiers[i].data(), 0xF8, StateAddr(7));
    Require(ue::PostureProvider()->decide(0, rig.view, pslot) != 0, "activity D refused");
    ue::PostureProvider()->end(0, rig.view, pslot);
    ue::Snapshot(words);
    Require(words[ue::WPHist + 5 + 2 * 3] == 7 && words[ue::WPHist + 6 + 2 * 3] == 2, "modal posture state of activity D = 7 (2 members)");
    Require(words[ue::WPHist + 15 + 4 * 2 + 2 * 1] == 7, "modal state of (D, speed 2)");
    currentCase = "shadow engage compare";
    rig.Setup(0, 0, 3);
    for (U i = 0; i < 3; ++i) { Put(rig.soldiers[i].data(), 0x224, U(i == 0 ? 6 : i == 1 ? 0 : 9)); Put(rig.soldiers[i].data(), 0xF1, B(i == 0));
                                Put(rig.soldiers[i].data(), 0x619, B(i != 0)); Put(rig.soldiers[i].data(), 0x1D8, U(i < 2 ? 4 : 5)); }
    Put(rig.unit.data(), 0xD9D, B(1));
    U eslot[64];
    FillLookups(rig.unit.data(), A(rig.unit.data() + 0xF00));
    Require(ue::EngageProvider()->decide(0, rig.view, eslot) == 0 && eslot[ue::EvD9dMode] == 0 && eslot[ue::LkValid] == 7,
            "shadow engage evaluates the lookups exactly as live does and keeps the native read mode");
    rig.view.admitted = policy::kMaskEngage;
    ue::EngageProvider()->end(0, rig.view, eslot);
    ue::Snapshot(words);
    Require(words[ue::WECompare] == 3 && words[ue::WECompare + 2] == 1 && words[ue::WECompare + 1] == 1 && words[ue::WECompare + 4] == 1 &&
            words[ue::WECompare + 6] == 1 && words[ue::WECompare + 9] == 1 && words[ue::WECompare + 10] == 2 &&
            words[ue::WECompare + 11] == 2 && words[ue::WECompare + 12] == 1, "engage compare tables");
    Require(words[ue::WEOrder] == 1 && words[ue::WEOrder + 2] == 1 && words[ue::WEOrder + 3] == 1, "order mixed, stance uniform");
    // freeze validation: what live freezes at the seam is re-evaluated natively at the end of the stage
    currentCase = "shadow freeze validation";
    ue::Reset();
    for (U kind = 0; kind < 6; ++kind) {
        rig.Setup(0, 0, 2);
        Put(rig.unit.data(), 0xD9D, B(1));
        FillLookups(rig.unit.data(), A(rig.unit.data() + 0xF00));
        U fslot[64];
        Require(ue::EngageProvider()->decide(0, rig.view, fslot) == 0 && fslot[ue::LkValid] == 7, "freeze: seam evaluation");
        rig.view.admitted = policy::kMaskEngage;
        float savedConst = Get<float>(At(0x131a7b8), 0);
        if (kind == 1) Put(rig.unit.data(), 0xD9D, B(0));
        if (kind == 2) Put(rig.unit.data(), 0xD9E, B(0));
        if (kind == 3) Put(rig.unit.data(), 0xC70, U(0));
        if (kind == 4) Put(At(0x131a7b8), 0, savedConst + 1.0f);
        if (kind == 5) { Put(rig.unit.data(), 0xD9D, B(0)); Put(rig.unit.data(), 0xD9E, B(0)); }
        U before[ue::kWords]; ue::Snapshot(before);
        ue::EngageProvider()->end(0, rig.view, fslot);
        Put(At(0x131a7b8), 0, savedConst);
        U after[ue::kWords]; ue::Snapshot(after);
        const U d[5] = {after[ue::WStale] - before[ue::WStale], after[ue::WStale + 1] - before[ue::WStale + 1],
                        after[ue::WStale + 2] - before[ue::WStale + 2], after[ue::WStale + 3] - before[ue::WStale + 3],
                        after[ue::WStale + 4] - before[ue::WStale + 4]};
        Require(d[4] == 1, "one admitted unit-stage validated");
        const U want[5][4] = {{0, 0, 0, 0}, {0, 0, 0, 1}, {1, 0, 0, 0}, {0, 0, 1, 0}, {0, 1, 0, 0}};
        if (kind <= 4) for (U f = 0; f < 4; ++f) Require(d[f] == want[kind][f], "stale counters name exactly the changed lookup");
        else Require(d[0] == 1 && d[3] == 1, "stale: predicate and D9D changed together");
        ++cases;
    }
    // posture admission over members: a member in the locomotion domain refuses the idle unit
    currentCase = "posture moving refusal";
    for (U kind = 0; kind < 7; ++kind) {
        rig.Setup(0, 1, 3);
        B* m = rig.soldiers[1].data();
        if (kind == 1) Put(m, 0xF8, StateAddr(3));
        if (kind == 2) Put(m, 0xF8, StateAddr(12));          // rest is not moving
        if (kind == 3) Put(m, 0x390, U(1));
        if (kind == 4) Put(m, 0x108, U(1));
        if (kind == 5) Put(m, 0x110, U(0x10));
        if (kind == 6) Put(m, 0x100, 1.5f);
        U before[ue::kWords]; ue::Snapshot(before);
        U mslot[64];
        const U code = ue::PostureProvider()->decide(0, rig.view, mslot);
        U after[ue::kWords]; ue::Snapshot(after);
        const bool moving = kind != 0 && kind != 2;
        Require((code == 0) == !moving, "moving members refuse the idle unit; quiet and rest members admit it");
        Require(mslot[ue::PsTarget] == 0 && mslot[ue::PsShadowTarget] == (moving ? ~0u : 12u), "shadow publishes no apply target; a refused unit has no decided target");
        Require(after[ue::WMoving + 1] - before[ue::WMoving + 1] == 1 && after[ue::WMoving] - before[ue::WMoving] == (moving ? 1u : 0u),
                "idle units checked / refused counters");
        const U cause = kind == 1 ? 2 : kind == 3 ? 3 : kind >= 4 ? 4 : 0;
        if (moving) Require(after[ue::WMoving + cause - 0] - before[ue::WMoving + cause] == 1 || cause == 0, "cause counter");
        ++cases;
    }
    Require(ue::Start(A(image), policy::Live, policy::Live, clones.entries), "back to live");
    ++cases;
}

// ---- driver / finalizer / path ---------------------------------------------------------------------------------
struct Memo {
    std::vector<B> bytes; FpState fp;
    void Take(Case& c, World& w) {
        bytes.assign(reinterpret_cast<B*>(&c), reinterpret_cast<B*>(&c) + sizeof(c));
        bytes.insert(bytes.end(), reinterpret_cast<B*>(&w), reinterpret_cast<B*>(&w) + sizeof(w));
        bytes.insert(bytes.end(), At(0x14ded30), At(0x14ded30) + 0x70);
        bytes.insert(bytes.end(), At(0x14514c0), At(0x14514c0) + 0x14);
        fp = CaptureFp();
    }
    void Restore(Case& c, World& w) const {
        std::memcpy(&c, bytes.data(), sizeof(c)); std::memcpy(&w, bytes.data() + sizeof(c), sizeof(w));
        std::memcpy(At(0x14ded30), bytes.data() + sizeof(c) + sizeof(w), 0x70);
        std::memcpy(At(0x14514c0), bytes.data() + sizeof(c) + sizeof(w) + 0x70, 0x14);
    }
};
static void CompareMemo(const Memo& expected, const Memo& actual, const char* what) {
    Require(expected.fp.mxcsr == actual.fp.mxcsr && expected.fp.control == actual.fp.control && expected.fp.status == actual.fp.status,
            "MXCSR and x87 control/status preserved");
    CompareBytes(expected.bytes.data(), actual.bytes.data(), expected.bytes.size(), what);
}
// d9d: the unit record's D9D byte the scenario installs (-1: no unit / not read).
struct Scenario { const char* name; U gate; void (*apply)(Case&); int d9d; };
static void ScDefault(Case&) {}
static void ScL619(Case& c) { B* a = c.agent.data(); Put(a, 0x619, B(0)); Put(a, 0x618, B(1)); Put(a, 0x2c4, B(1)); Put(a, 0x234, B(1)); }
static void ScF1(Case& c) { B* a = c.agent.data(); Put(a, 0x619, B(0)); Put(a, 0x618, B(1)); Put(a, 0x2c4, B(1)); Put(a, 0x234, B(0)); Put(a, 0xF1, B(0x5A)); }
static void ScL619Node(Case& c) { B* a = c.agent.data(); Put(a, 0x619, B(0)); Put(a, 0x618, B(1)); Put(a, 0x2c4, B(0)); Put(a, 0x5A0 + 0, B(0)); }
static void ScP6(Case& c) { B* a = c.agent.data(); Put(a, 0x1f0, A(c.unit.data())); Put(c.unit.data(), 0xD9D, B(1)); Put(a, 0x36c, B(0)); }
static void ScP6Off(Case& c) { ScP6(c); Put(c.unit.data(), 0xD9D, B(0)); }
static void ScP7(Case& c) { B* a = c.agent.data(); Put(a, 0x1f0, A(c.unit.data())); Put(c.unit.data(), 0xD9D, B(0)); Put(a, 0x5b8, A(c.reference.data())); Put(a, 0x2c4, B(0)); }
enum { ScIndexDefault, ScIndexGate1, ScIndexL619, ScIndexF1, ScIndexL619Node, ScIndexP6, ScIndexP6Off, ScIndexP7 };
static const Scenario kScenarios[] = {
    {"default (no unit, alternate engage block)", 0, ScDefault, -1}, {"gate 1", 1, ScDefault, -1},
    {"+619 latch (node finished)", 0, ScL619, -1}, {"+F1 latch", 0, ScF1, -1}, {"+619 latch behind the node tests", 0, ScL619Node, -1},
    {"phase 6 (D9D on)", 0, ScP6, 1}, {"D9D off", 0, ScP6Off, 0}, {"phase 7 (reference node)", 0, ScP7, 0}};
enum Body { Driver, DriverUS, Finalizer, Path };
static U BodyOriginal(Body b) { return A(At(b <= DriverUS ? 0x658c50 : b == Finalizer ? 0x6543d0 : 0x819770)); }
static U BodyClone(Body b) {
    return clones.entries[b == Driver ? NTW2_CLONE_BRAIN_U_DRIVER : b == DriverUS ? NTW2_CLONE_BRAIN_US_DRIVER :
                          b == Finalizer ? NTW2_CLONE_BRAIN_U_FINALIZE : NTW2_CLONE_BRAIN_U_PATH];
}
static void RunBody(Body b, U entry, Case& c, U gate) {
    ResetFp();
    if (b <= DriverUS) Thiscall1(entry, A(c.agent.data()), gate); else Thiscall0(entry, A(c.agent.data()));
}
static void MakeEv(U* slot, U clear = 0, U p6 = 6, U p7 = 7, U mode = 0, U value = 0, U f1And = 0, U f1Or = 1, U l619And = 0, U l619Or = 1) {
    std::memset(slot, 0, 64 * sizeof(U));
    slot[ue::EvClear] = clear; slot[ue::EvP6] = p6; slot[ue::EvP7] = p7; slot[ue::EvD9dMode] = mode; slot[ue::EvD9dValue] = value;
    slot[ue::EvF1And] = f1And; slot[ue::EvF1Or] = f1Or; slot[ue::EvL619And] = l619And; slot[ue::EvL619Or] = l619Or;
}
static size_t Offset(const Case& c, const void* field) { return static_cast<size_t>(static_cast<const B*>(field) - reinterpret_cast<const B*>(&c)); }
// Original body on `expected`'s fixture, then the clone on `clone`'s fixture under occurrence (entity + entityDelta, mask,
// EV slot); patch(expectedMemo, case layout) adjusts the expectation by exactly the unit-policy difference being tested.
template<class Patch>
static void Differential(Body body, const Scenario& clone, const Scenario& expected, U mask, U* evSlot, U entityDelta, Patch patch,
                         const char* what, U gateOverride = ~0u) {
    static World* world = new World;
    static Case* c = new Case;
    currentCase = what;
    const U gate = gateOverride != ~0u ? gateOverride : clone.gate;
    *world = World(); *c = Case(); c->Init(*world, 900); expected.apply(*c);
    RunBody(body, BodyOriginal(body), *c, gate);
    Memo want; want.Take(*c, *world);
    *world = World(); *c = Case(); c->Init(*world, 900); clone.apply(*c);
    U postureSlot[64] = {};
    SetOcc(A(c->agent.data()) + entityDelta, mask, postureSlot, evSlot, nullptr);
    RunBody(body, BodyClone(body), *c, gate);
    ClearOcc();
    Memo got; got.Take(*c, *world);
    patch(want, *c);
    CompareMemo(want, got, what);
    ++cases;
}
static void NoPatch(Memo&, const Case&) {}
static const Scenario& Sc(U i) { return kScenarios[i]; }
static void DriverCases() {
    U ev[64];
    // 1. mask 0 / no occurrence / another soldier / mask without Engage: bit-exact against the originals, whatever the slot holds.
    for (Body body : {Driver, DriverUS, Finalizer, Path}) for (const Scenario& sc : kScenarios) {
        if (body >= Finalizer && sc.gate) continue;
        MakeEv(ev, 0x33, 0x66, 0x77, 1, 1, 0xFF, 0, 0xFF, 0);
        Differential(body, sc, sc, 0, ev, 0, NoPatch, sc.name);
        Differential(body, sc, sc, policy::kMaskFatigue | policy::kMaskPosture, ev, 0, NoPatch, sc.name);
        Differential(body, sc, sc, policy::kMaskEngage | policy::kMaskPosture, ev, 8, NoPatch, sc.name);
    }
    // 2. admitted with native-equal EV values: bit-exact too (the unit's D9D mirrors the record).
    for (Body body : {Driver, DriverUS}) for (const Scenario& sc : kScenarios) {
        MakeEv(ev, 0, 6, 7, 0, 0);
        Differential(body, sc, sc, policy::kMaskEngage, ev, 0, NoPatch, sc.name);
        if (sc.d9d >= 0) {
            MakeEv(ev, 0, 6, 7, 1, static_cast<U>(sc.d9d));
            Differential(body, sc, sc, policy::kMaskEngage, ev, 0, NoPatch, "frozen D9D equal to the record");
        }
    }
    // 3. the unit values land exactly at the original sites; everything else is the original's effect.
    for (Body body : {Driver, DriverUS}) {
        MakeEv(ev, 0x33);
        Differential(body, Sc(ScIndexDefault), Sc(ScIndexDefault), policy::kMaskEngage, ev, 0,
                     [](Memo& m, const Case&) { Put(m.bytes.data(), 0x224, U(0x33)); }, "own phase clear value (658C62)");
        MakeEv(ev, 0, 0x66);
        Differential(body, Sc(ScIndexP6), Sc(ScIndexP6), policy::kMaskEngage, ev, 0,
                     [](Memo& m, const Case&) { Put(m.bytes.data(), 0x224, U(0x66)); }, "own phase 6 value (658FDE)");
        MakeEv(ev, 0, 6, 0x77);
        Differential(body, Sc(ScIndexP7), Sc(ScIndexP7), policy::kMaskEngage, ev, 0,
                     [](Memo& m, const Case&) { Put(m.bytes.data(), 0x224, U(0x77)); }, "own phase 7 value (6590FC)");
        for (U variant = 0; variant < 3; ++variant) {
            const U andMask = variant == 0 ? 0xFF : variant == 1 ? 0 : 0x0F, orMask = variant == 0 ? 0 : variant == 1 ? 0xA5 : 0x30;
            MakeEv(ev, 0, 6, 7, 0, 0, andMask, orMask, 0, 1);
            Differential(body, Sc(ScIndexF1), Sc(ScIndexF1), policy::kMaskEngage, ev, 0,
                         [=](Memo& m, const Case&) { Put(m.bytes.data(), 0xF1, B((0x5A & andMask) | orMask)); }, "latch +F1 and/or (658DEF)");
            MakeEv(ev, 0, 6, 7, 0, 0, 0, 1, andMask, orMask);
            Differential(body, Sc(ScIndexL619), Sc(ScIndexL619), policy::kMaskEngage, ev, 0,
                         [=](Memo& m, const Case&) { Put(m.bytes.data(), 0x619, B((0 & andMask) | orMask)); }, "latch +619 and/or (658DFB)");
            Differential(body, Sc(ScIndexL619Node), Sc(ScIndexL619Node), policy::kMaskEngage, ev, 0,
                         [=](Memo& m, const Case&) { Put(m.bytes.data(), 0x619, B((0 & andMask) | orMask)); }, "latch +619 behind the node tests");
        }
        // frozen D9D replaces the per-man read: unit off over a record that says on (no phase 6), and the reverse.
        MakeEv(ev, 0, 6, 7, 1, 0);
        Differential(body, Sc(ScIndexP6), Sc(ScIndexP6Off), policy::kMaskEngage, ev, 0,
                     [](Memo& m, const Case& c) { Put(m.bytes.data(), Offset(c, &c.unit[0xD9D]), B(1)); }, "frozen D9D off over a record that says on");
        MakeEv(ev, 0, 6, 7, 1, 1);
        Differential(body, Sc(ScIndexP6Off), Sc(ScIndexP6), policy::kMaskEngage, ev, 0,
                     [](Memo& m, const Case& c) { Put(m.bytes.data(), Offset(c, &c.unit[0xD9D]), B(0)); }, "frozen D9D on over a record that says off");
    }
    // 4. target phase 9 (658F44), node construction and RNG are untouched: the pair scenario is the original's, bit-exact.
    // (covered by the equal-values runs above; the pair path itself is outside the fixture and stays native.)
    {
        static World* world = new World; static Case* c = new Case;
        *world = World(); *c = Case(); c->Init(*world, 901); ScP6(*c);
        U words0[ue::kWords], words1[ue::kWords];
        ue::Snapshot(words0);
        MakeEv(ev, 0, 6, 7, 1, 1);
        SetOcc(A(c->agent.data()), policy::kMaskEngage, ev, ev, nullptr);
        RunBody(Driver, BodyClone(Driver), *c, 0);
        ClearOcc();
        ue::Snapshot(words1);
        Require(words1[ue::WESites] == words0[ue::WESites] + 1, "the unit D9D branch is counted once per man");
        ++cases;
    }
}

// ---- lookup gates, alternate driver, ABI -----------------------------------------------------------------------
static void GateCases() {
    static World* world = new World; static Case* c = new Case;
    *world = World(); *c = Case(); c->Init(*world, 902);
    B* agent = c->agent.data(); const U a = A(agent);
    Put(agent, 0x1f0, A(c->unit.data())); Put(c->unit.data(), 0xD9E, B(1)); Put(c->unit.data() + 0xC00, 0xE4, U(0x777));
    policy::UnitView view{}; view.handle = A(c->unit.data());
    U ev[64]; MakeEv(ev);
    ev[ue::LkPredicate] = 0; ev[ue::LkModifier] = 0xDEADBEEF; ev[ue::LkValid] = ue::kLkPredicate | ue::kLkModifier | ue::kLkArrival;
    const float arrival = 3.5f; std::memcpy(&ev[ue::LkArrival], &arrival, 4);
    U postureSlot[64] = {};
    // admitted: the frozen values; every ABI contract holds
    SetOcc(a, policy::kMaskEngage, postureSlot, ev, &view);
    currentCase = "649520 gate";
    ResetFp(); U got = Checked(bindings[NTW2_BIND_U_UNIT_MODIFIER], a); RequireCleanAbi("649520 gate");
    Require(got == 0xDEADBEEF, "modifier row served from the unit slot");
    currentCase = "64F8F0 gate";
    ResetFp(); got = Checked(bindings[NTW2_BIND_U_ORDER_PREDICATE], a); RequireCleanAbi("64F8F0 gate");
    Require((got & 0xFF) == 0, "predicate served from the unit slot (native would be 1)");
    currentCase = "57E1F0 gate";
    ResetFp(); Checked(bindings[NTW2_BIND_U_UNIT_ARRIVAL], A(c->unit.data())); RequireCleanAbi("57E1F0 gate", true);
    float arrived; __asm fstp dword ptr [arrived]
    Require(arrived == 3.5f, "arrival served from the unit slot as an x87 float");
    // not admitted / not this soldier / lookup not valid: the original function
    for (U variant = 0; variant < 3; ++variant) {
        currentCase = "lookup gates native";
        U mask = variant == 0 ? 0 : policy::kMaskEngage, entity = variant == 1 ? a + 8 : a;
        const U validBefore = ev[ue::LkValid];
        if (variant == 2) ev[ue::LkValid] = 0;
        SetOcc(entity, mask, postureSlot, ev, &view);
        ResetFp(); const U nativeRow = Thiscall0(V(0x649520), a); ResetFp(); got = Checked(bindings[NTW2_BIND_U_UNIT_MODIFIER], a);
        RequireCleanAbi("649520 gate native"); Require(got == nativeRow && nativeRow == 0x5151, "original 649520 result");
        ResetFp(); const U nativePredicate = Thiscall0(V(0x64F8F0), a) & 0xFF; ResetFp(); got = Checked(bindings[NTW2_BIND_U_ORDER_PREDICATE], a) & 0xFF;
        RequireCleanAbi("64F8F0 gate native"); Require(got == nativePredicate && nativePredicate == 1, "original 64F8F0 result");
        const float nativeArrival = NativeArrival(A(c->unit.data()));
        ResetFp(); Checked(bindings[NTW2_BIND_U_UNIT_ARRIVAL], A(c->unit.data())); RequireCleanAbi("57E1F0 gate native", true);
        __asm fstp dword ptr [arrived]
        if (variant == 1) Require(arrived == 3.5f, "the arrival lookup is keyed by the unit, not the soldier: served for any soldier of the admitted unit");
        else Require(std::memcmp(&arrived, &nativeArrival, 4) == 0, "original 57E1F0 result");
        ev[ue::LkValid] = validBefore;
        ++cases;
    }
    ClearOcc();
    // 66D402 gate: an admitted Engage occurrence reaching the alternate driver drains its unit, then 64DE80 runs natively.
    currentCase = "alternate driver gate";
    for (U variant = 0; variant < 2; ++variant) {
        *world = World(); *c = Case(); c->Init(*world, 903);
        Memo before; before.Take(*c, *world);
        ResetFp(); Thiscall0(A(At(0x64de80)), A(c->agent.data())); Memo want; want.Take(*c, *world);
        before.Restore(*c, *world);
        policy::drainCalls = 0;
        SetOcc(A(c->agent.data()), variant ? policy::kMaskEngage : 0, postureSlot, ev, &view, 5);
        ResetFp(); Checked(bindings[NTW2_BIND_U_DRIVER_ALT], A(c->agent.data())); RequireCleanAbi("alternate driver gate");
        ClearOcc();
        Memo got2; got2.Take(*c, *world);
        CompareMemo(want, got2, "the alternate driver runs the original exactly");
        Require(policy::drainCalls == (variant ? 1u : 0u) && (!variant || (policy::drainMechanic == policy::Engage)), "admitted occurrence drains Engage");
        ++cases;
    }
    // Node dispatch gates: an unknown target runs the original with ECX = node; callee-saved registers survive.
    currentCase = "node dispatch gates";
    static U fakeVtable[4];
    for (U kind = 0; kind < 2; ++kind) {
        fakeVtable[1] = fakeVtable[2] = Fn(&NodeProbe);
        gNodeEcx = 0;
        CallNodeGate(bindings[kind ? NTW2_BIND_U_NODE_STEP : NTW2_BIND_U_NODE_BEGIN], A(fakeVtable), 0x5000);
        RequireCleanAbi("node dispatch gate");
        Require(gNodeEcx == 0x5000, "unknown node class runs the original target with ECX = node");
        ++cases;
    }
}
// BRAIN_U_PATH with the posture gate admitted: 819770's motion code after the posture call sees exactly what it sees after
// the native sequence for the same state (reference: the hand-applied sequence, then the ORIGINAL 819770 whose own 10FC370
// call is replaced by `mov al,1; ret` in the private image copy).
static void PathPostureCases() {
    static World* world = new World; static Case* c = new Case;
    SetNextTrap(true);
    for (U old = 1; old <= 13; ++old) for (U budget : {0u, 3u}) {
        currentCase = "BRAIN_U_PATH posture apply";
        *world = World(); *c = Case(); c->Init(*world, 910);
        B* ag = c->agent.data();
        Put(ag, 0x28, A(c->fwRoot.data())); Put(ag, 0x18c, B(0)); Put(ag, 0x18, U(0)); Put(ag, 0x10, U(0));
        Put(ag, 0xf4, V(0x134706c)); Put(ag, 0xf8, StateAddr(old - 1)); Put(ag, 0xfc, budget);
        Put(ag, 0x48, 1.25f); Put(ag, 0x4c, 0.5f); Put(ag, 0x50, -2.5f); Put(ag, 0x64, uint16_t(0));
        Put(ag, 0x160, 3.0f); Put(ag, 0x164, 0.0f); Put(ag, 0x168, -1.0f); Put(ag, 0x16c, uint16_t(0x2000)); Put(ag, 0x170, U(0));
        Put(ag, 0x58, 2.0f); Put(ag, 0x8c, 0.3f); Put(ag, 0x94, -0.4f); Put(ag, 0x100, 0.2f);
        Put(ag, 0x10c, 1.5f); Put(ag, 0x128, 0.75f); Put(ag, 0x138, 0.01f); Put(ag, 0x158, 0.5f);
        Put(ag, 0x194, 0.9f); Put(ag, 0xb8, 0.4f); Put(ag, 0xbc, 0.6f);
        Memo start; start.Take(*c, *world);
        // reference
        U saved = 0; std::memcpy(&saved, At(0x10fc370), 4);
        const B stub[4] = {0xB0, 0x01, 0xC3, B(saved >> 24)};
        ReferenceApply(ag, StateAddr(12));
        std::memcpy(At(0x10fc370), stub, 3);
        RunBody(Path, BodyOriginal(Path), *c, 0);
        std::memcpy(At(0x10fc370), &saved, 3);
        Memo want; want.Take(*c, *world);
        start.Restore(*c, *world);
        U slot[64] = {}; slot[ue::PsTarget] = StateAddr(12); slot[ue::PsRest] = StateAddr(12);
        U engage[64] = {};
        SetOcc(A(ag), policy::kMaskPosture, slot, engage, nullptr);
        RunBody(Path, BodyClone(Path), *c, 0);
        ClearOcc();
        Memo got; got.Take(*c, *world);
        CompareMemo(want, got, "819770 after the posture apply equals the native sequence for the same state");
        ++cases;
    }
    SetNextTrap(false);
}
static int RunOracle(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_unit_posture_engage_oracle <approved Napoleon.exe>\n"); return 2; }
    ResetFp(); Map(argv[1]);
    ProviderCases();
    PostureGateCases();
    ShadowCases();
    DriverCases();
    PathPostureCases();
    GateCases();
    VirtualFree(clones.allocation, 0, MEM_RELEASE);
    VirtualFree(image, 0, MEM_RELEASE);
    std::printf("native_unit_posture_engage_oracle: %u cases, %u checks\n", cases, checks);
    return 0;
}
int main(int argc, char** argv) {
    __try { return RunOracle(argc, argv); }
    __except (ReportFault(GetExceptionInformation(), "oracle")) { return 1; }
}
