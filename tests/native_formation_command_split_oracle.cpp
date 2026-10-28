// Native-twin oracle for the private command-split route of the 0x581CA0 formation command callback (census feature, not shipped).
// Drives the untouched pinned image's 581E80 queue walk over controlled commands whose [vtbl+4] callback is the native 581CA0,
// with the FSM states, the state-enter virtuals, the assignment state enter 4F84C0 and the 5736B0 work controls, then replays the
// identical fixture through the real census path (storm Unit -> Formation -> RunClone -> GateQueue -> port Run probe) with the
// private chain disarmed / refused / armed. The chain's leaf natives (57B000 assignment, 55F160 per-man, 4B4A50 container,
// 557D80 tail) are replaced in the private image by recording fakes; both routes therefore execute the same real 581CA0 /
// 10FC370 / 10FBBD0 logic (native bytes or private clones) and the same fakes, and every case compares the exception outcome,
// the full event log and the entire fixture byte for byte. The routed path additionally checks nested assignment/per-man counts,
// the same-callback slowest attribution, refused/abort/exception ledger semantics and the cumulative route table.
// Registers, EDX seeds and callee-pop ABIs are asserted per call; the unarmed image bytes at the enter site stay unpatched.
// No game process, installed-file writes, import calls or TLS setup are needed.
// Usage: native_formation_command_split_oracle.exe <pinned Napoleon.exe>
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <float.h>
#include <intrin.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "army/native_formation_queue.h"
#include "army/native_formation_residual.h"
#include "army/native_army_storm.h"
#include "army/native_army_solver.h"
#include "clones/kntwr_clones.h"

static_assert(sizeof(void*) == 4, "command-split oracle requires x86");
namespace fr = kntwr_form_residual;
namespace fq = kntwr_formation_queue;
namespace {
using U = uint32_t;
using B = uint8_t;
using Native = U (__fastcall*)(void*);

B* image;
U delta, checks, cases;
const char* current = "mapping";
const char* mode = "native";
U bindings[KNTWR_BIND_COUNT];
kntwr_clone_set g_clones;

U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
U NativeAddress(U preferred) { return preferred + delta; }
template <class T> U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
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

// Patch a leaf native entry in the private image to a recording fake (mov eax, imm32 ; jmp eax). Done only after
// kntwr_build_clones has hashed the original spans, so the clone pins and this glue never disagree about the source bytes.
void PatchJump(U va, const void* target) {
    uint8_t* p = image + (va - 0x400000);
    DWORD old;
    Require(VirtualProtect(p, 7, PAGE_EXECUTE_READWRITE, &old) != 0, "patch page writable");
    p[0] = 0xB8;
    const U t = A(target);
    std::memcpy(p + 1, &t, 4);
    p[5] = 0xFF; p[6] = 0xE0;
    Require(VirtualProtect(p, 7, old, &old) != 0, "restore patch protection");
    Require(FlushInstructionCache(GetCurrentProcess(), p, 7) != 0, "flush patch");
}

// ---- Fixture ------------------------------------------------------------------------------------------------------------------
constexpr U kQueueBytes = 0x460;
constexpr U kEntriesOff = 0x400, kCountOff = 0x440, kTotalOff = 0x444, kFreeOff = 0x448, kSpareOff = 0x44C,
            kIterOff = 0x450, kDirtyOff = 0x451, kIndexOff = 0x454;
constexpr U kStates = 6, kMen = 8, kRecWords = 9, kRecStride = 0x24;
constexpr U kNull = 0xFF, kNone = 0xFF;
// Command object (581CA0/5736B0 layout): +0x00 vtable, +0x0C erase byte, +0x10 progress, +0x18 FSM wrapper W
// (W+0 = W vtable, W+4 = current state, W+8 = max transitions), +0x24/+0x28/+0x2C assignment args, +0x35 guard byte,
// +0x44 per-man record array.
constexpr U kCmdBytes = 0x50;

struct Fixture {
    U q[kQueueBytes / 4];
    U qB[kQueueBytes / 4];
    B cmdA[kCmdBytes], cmdB[kCmdBytes], cmdOther[kCmdBytes];
    U vtCmd[4], vtOther[4], vtW[4], vtS[kStates][4];
    U st[kStates];
    U cont[8];          // +0x18 count, +0x1C array (the 4B4A50 result)
    U men[kMen];
    B recs[kMen * kRecStride];
    U manObjs[kMen][4]; // just stable pointers for the per-man arguments
    U unit[0xB00 / 4];
    U memberList[2];
    B member[0x20];
    U memberVtbl[4];
    U guard[8];
};
Fixture fx;

U& Dw(void* q, U off) { return static_cast<U*>(q)[off / 4]; }
U CmdU(const B* c, U off) { U v; std::memcpy(&v, c + off, 4); return v; }
B CmdB(const B* c, U off) { return c[off]; }
void CmdSetU(B* c, U off, U v) { std::memcpy(c + off, &v, 4); }
void CmdSetB(B* c, U off, B v) { c[off] = v; }
U CmdId(const void* p) {
    const U address = A(p);
    const B* first = fx.cmdA;
    Require(address >= A(first) && address - A(first) < 3 * kCmdBytes && (address - A(first)) % kCmdBytes == 0,
            "receiver is a fixture command");
    return (address - A(first)) / kCmdBytes;
}
B* CmdById(U id) { return id == 0 ? fx.cmdA : id == 1 ? fx.cmdB : fx.cmdOther; }
U StateId(const void* p) {
    const U address = A(p);
    Require(address >= A(fx.st) && address - A(fx.st) < kStates * 4 && (address - A(fx.st)) % 4 == 0,
            "receiver is a fixture state");
    return (address - A(fx.st)) / 4;
}

// ---- Event log -----------------------------------------------------------------------------------------------------------------
// Kinds in chain order; the log plus the fixture byte compare is the twin proof. dtor EDX is deliberately not logged (native erase
// leaves a different leftover EDX than the port erase call).
enum Kind : U { KNext, KLeave, KEnterOther, KUpdate, KWCur, KAssign, KPerMan, KCont, KTail, KDtor, KOtherCb };
struct Event { U kind, a, b, c, d; };
constexpr U kMaxEvents = 512;
struct Log { U count; Event e[kMaxEvents]; };
Log gLog;
Event& NewEvent(U kind, U a, U b = 0, U c = 0, U d = 0) {
    Require(gLog.count < kMaxEvents, "bounded event log");
    Event& e = gLog.e[gLog.count++];
    e.kind = kind; e.a = a; e.b = b; e.c = c; e.d = d;
    return e;
}

// EDX seeds (0xED0000xx): each trampoline sets EDX after its fake returns, so the next fake proves what the chain forwarded.
constexpr U SEED_NEXT = 0xED0000A1, SEED_LEAVE = 0xED0000A2, SEED_ENTER = 0xED0000A3, SEED_UPDATE = 0xED0000A4,
            SEED_WCUR = 0xED0000A5, SEED_ASSIGN = 0xED0000A6, SEED_PERMAN = 0xED0000A7, SEED_CONT = 0xED0000A8,
            SEED_OTHER = 0xED0000A9, SEED_TAIL = 0xED0000AA;
constexpr U KFLOAT_BITS = 0x44638E38; // 910.222: the 5736B0 prologue's fld/fistp constant (image global, also stored at [cmd+0x2C])
U FistpBits(U bits) {
    U v;
    __asm {
        fld dword ptr [bits]
        fistp dword ptr [v]
    }
    return v;
}
unsigned long long g_frequency;
unsigned long long frequencyTicksPerUs() { return g_frequency / 1000000ull ? g_frequency / 1000000ull : 1; }
void Spin(unsigned us) {
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    do QueryPerformanceCounter(&b);
    while (static_cast<unsigned long long>(b.QuadPart - a.QuadPart) <
           static_cast<unsigned long long>(us) * (frequencyTicksPerUs()));
    (void)0;
}

// ---- Case configuration --------------------------------------------------------------------------------------------------------
struct Cfg {
    const char* name;
    U cur;            // current state id, kNull = null state
    U next[kStates];  // scripted next-state id (kNull = null)
    U matched;        // state id whose enter virtual is the native 4F84C0 (kNull = no matched state)
    U maxIter;        // W+8 transition budget
    U guard35;        // command +0x35 byte (assignment guard)
    U men;            // container count at entry
    U shrinkAt, shrinkTo; // per-man index that shrinks the container count
    U throwAt;        // per-man index that raises 0xE0000051
    U nestAt;         // per-man index that drives the nested command queue
    U spinCbUs, spinPerManUs, otherSpinUs;
    bool twoCommands; // slot-8 other-class callback precedes the routed command
    bool rcUp;        // run under _RC_UP (the clone's fld/fistp must honor it)
};
struct Profile {
    U callbacks, routed, enters, others, assigns, permans, noEnter;
    U slowVtable, slowSlot;
    bool slowRouted;
    U otherCalls;     // callbacks dispatched through the (vtOther,8) class (two-commands cases only)
    U snEnter, snOther, snAssign, snPerMan; // the slowest ROUTED callback's own nested counts (same-callback attribution)
};
const Cfg* g_cfg;
U g_modeKind; // 0 native, 1 disarmed, 2 refused, 3 armed, 4 armed+abort
bool g_nextSeen[3]; // per command: its callback already made its first next-state call (reset by Build; not part of the twin)

// ---- Fakes (recording twins of the leaf natives) --------------------------------------------------------------------------------
U __fastcall NextImpl(void* self, void* edx, U w) {
    const U id = StateId(self);
    const U cmd = CmdId(reinterpret_cast<const void*>(static_cast<uintptr_t>(w - 0x18)));
    // Only the FIRST next-state call of a callback carries the dispatch EDX (the class vtable): 581CA0/10FC370/10FBBD0 never
    // write EDX, so later iterations see the previous enter's leftover, which the enter gate legitimately does not preserve.
    if (!g_nextSeen[cmd]) {
        Require(edx == reinterpret_cast<void*>(A(fx.vtCmd)), "first next-state EDX is the dispatching class vtable");
        g_nextSeen[cmd] = true;
    }
    if (g_cfg->spinCbUs) Spin(g_cfg->spinCbUs);
    const U target = g_cfg->next[id];
    NewEvent(KNext, id, target, cmd);
    return target == kNull ? 0 : A(&fx.st[target]);
}
U __fastcall LeaveImpl(void* self, void* edx, U /*w*/) {
    Require(edx == reinterpret_cast<void*>(SEED_NEXT), "leave EDX forwarded from the next-state call");
    NewEvent(KLeave, StateId(self));
    return 0;
}
U __fastcall EnterOtherImpl(void* self, void* edx, U /*w*/) {
    Require(edx == reinterpret_cast<void*>(SEED_LEAVE), "enter EDX forwarded from the leave call");
    NewEvent(KEnterOther, StateId(self));
    return 0;
}
U __fastcall UpdateImpl(void* self, void* edx, U /*w*/) {
    Require(edx == reinterpret_cast<void*>(SEED_NEXT), "update EDX forwarded from the next-state call");
    NewEvent(KUpdate, StateId(self));
    return 0;
}
U __fastcall WCurImpl(void* self, void* edx) {
    Require(edx == reinterpret_cast<void*>(SEED_UPDATE), "wrapper-current EDX forwarded from the update call");
    NewEvent(KWCur, 0);
    return static_cast<U*>(self)[1]; // [W+4]: the current state, unchanged by the null-next branch
}
// ---- Solver census stubs -----------------------------------------------------------------------------------------------------
// With g_solverStub set, every fake 57B000 assignment forwards into the REAL kntwr_army_solver AssignGate (what the 555CEB gate does
// inside the native 57B000): ModeForward, the private image's 0x502770 patched to FakeSolveImpl, and a stub clone target
// (CloneAssignStub) that spins kStubSpinScopeUs, enters one NESTED AssignGate and runs kStubFlag0 limited + kStubFlag1 unlimited
// SolveGate calls (each fake solve spins kStubSpinSolveUs). So per fake assignment the solver counters advance by exactly
// kStubEntriesPerAssign assignment entries (outer + nested), kStubSolvesPerAssign solves and kStubFlag0 limited solves, and the
// outermost scope is timed only when the route probe armed it. No event, no fixture byte is touched (the native twin runs the same stub).
namespace as = kntwr_army_solver;
constexpr U kStubSpinScopeUs = 300, kStubSpinSolveUs = 200, kStubFlag0 = 2, kStubFlag1 = 1;
constexpr U kStubEntriesPerAssign = 2, kStubSolvesPerAssign = kStubFlag0 + kStubFlag1;
constexpr U kStubAssignRet = 0xC10E0000u;
using GateAssignFn = U (__fastcall*)(void*, void*, U, U, U, U);
using GateSolveFn = U (__fastcall*)(const float*, void*, void*, void*, U, float);
bool g_solverStub;
U g_assignGate, g_solveGate, g_stubDepth, g_stubSolveCalls, g_sinkCalls;
unsigned long long g_sinkQ;
U g_stubFormation[0x20], g_stubNested[0x20], g_stubEntries[8];
U __fastcall FakeSolveImpl(const float*, void*, void*, void*, U limit, float) { // stands for 0x502770
    ++g_stubSolveCalls;
    Spin(kStubSpinSolveUs);
    return 0x50270000u + limit;
}
U __fastcall CloneAssignStub(void*, void* edx, U a1, U a2, U a3, U a4) { // stands for the SOLVER_18F0A00 clone chain
    if (g_stubDepth++ == 0) {
        Spin(kStubSpinScopeUs);
        reinterpret_cast<GateAssignFn>(g_assignGate)(g_stubNested, edx, a1, a2, a3, a4); // nested scope: counted, never timed
        const auto solve = reinterpret_cast<GateSolveFn>(g_solveGate);
        for (U i = 0; i < kStubFlag0; ++i) solve(nullptr, edx, g_stubEntries, g_stubEntries + 3, 5, 1.0f);
        for (U i = 0; i < kStubFlag1; ++i) solve(nullptr, edx, g_stubEntries, g_stubEntries + 3, 0, 1.0f);
    }
    --g_stubDepth;
    return kStubAssignRet;
}
void __cdecl SinkImpl(unsigned long long q) { ++g_sinkCalls; g_sinkQ += q; }
as::CensusSnapshot ReadSolver() { as::CensusSnapshot s; as::ReadCensus(&s); return s; }

U __fastcall AssignImpl(void* self, void* edx, U a1, U a2, U a3, U a4) {
    const U id = CmdId(self);
    Require(edx == reinterpret_cast<void*>(SEED_LEAVE), "assignment EDX forwarded from the leave call");
    Require(a1 == CmdU(CmdById(id), 0x24) && a2 == CmdU(CmdById(id), 0x28) && a3 == CmdU(CmdById(id), 0x2C) && a4 == 1,
            "assignment receives [cmd+0x24] [cmd+0x28] [cmd+0x2C] bits and the flag 1");
    NewEvent(KAssign, id);
    if (g_solverStub) {
        const U r = reinterpret_cast<GateAssignFn>(g_assignGate)(g_stubFormation, edx, a1, a2, a3, a4);
        Require(r == kStubAssignRet, "solver assignment gate forwarded the stub clone's EAX");
    }
    return 0xA5510000u + id;
}
U __fastcall PerManImpl(void* self, void* edx, U a1, U a2, U a3, U a4, U a5) {
    const U id = CmdId(self);
    Require(edx == reinterpret_cast<void*>(CmdU(CmdById(id), 0x44)), "per-man EDX is the command's record array");
    U i = kNone;
    for (U k = 0; k < kMen; ++k) if (a1 == A(&fx.manObjs[k])) { i = k; break; }
    Require(i != kNone, "per-man member argument is a fixture member pointer");
    const U recs = CmdU(CmdById(id), 0x44);
    Require(a2 == recs + 4 + i * kRecStride, "per-man record argument (recs+4+i*0x24)");
    U word = 0;
    std::memcpy(&word, fx.recs + i * kRecStride + 0x18, 2);
    Require(a3 == word, "per-man word argument (recs[i]+0x18)");
    Require(a4 == 0x3D800000u, "per-man constant argument 0.0625f");
    Require(a5 == FistpBits(KFLOAT_BITS), "per-man last argument is the prologue fistp value under the current rounding mode");
    if (g_cfg->rcUp) Require(a5 == 911, "fistp rounded up under _RC_UP");
    else Require(a5 == 910, "fistp rounded to nearest by default");
    if (g_cfg->spinPerManUs) Spin(g_cfg->spinPerManUs);
    NewEvent(KPerMan, id, i);
    if (i == g_cfg->shrinkAt) fx.cont[0x18 / 4] = g_cfg->shrinkTo;
    if (i == g_cfg->nestAt) {
        if (g_modeKind == 0) {
            const auto walk = reinterpret_cast<Native>(static_cast<uintptr_t>(NativeAddress(0x581E80)));
            walk(fx.qB);
        } else {
            const auto gate = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(bindings[KNTWR_BIND_FORM_QUEUE]));
            gate(fx.qB);
        }
    }
    if (i == g_cfg->throwAt) {
        RaiseException(0xE0000051u, 0, 0, nullptr);
    }
    return 0xBEEF0000u + id * 256 + i;
}
U __fastcall ContImpl(void* self, void* edx) {
    (void)edx; // leftover EDX after a gate return is not part of the twin contract (callers never read it)
    const U id = CmdId(self);
    NewEvent(KCont, id, fx.cont[0x18 / 4]);
    return A(fx.cont);
}
U __fastcall TailImpl(void* self, void* edx) {
    Require(edx == reinterpret_cast<void*>(SEED_CONT), "tail EDX forwarded from the container call");
    Require(self == reinterpret_cast<void*>(A(fx.cont)), "tail receiver is the 4B4A50 container (581CA0: mov ecx,eax)");
    NewEvent(KTail, 0);
    return 0;
}
U __fastcall DtorImpl(void* self, void* edx, U flag) {
    (void)edx; // native erase and the port erase leave different leftover EDX: not part of the twin contract
    Require(flag == 1, "deleting destructor receives the erase flag 1");
    NewEvent(KDtor, CmdId(self), flag);
    return 0;
}
U __fastcall OtherCbImpl(void* self, void* edx) {
    Require(edx == reinterpret_cast<void*>(A(fx.vtOther)), "other-class callback EDX is its class vtable");
    if (g_cfg->otherSpinUs) Spin(g_cfg->otherSpinUs);
    NewEvent(KOtherCb, CmdId(self));
    return 0;
}
U __fastcall TrapImpl() {
    Require(false, "poisoned vtable slot never runs");
    return 0;
}

// Trampolines reproduce the replaced native's calling convention exactly: ECX/EDX pass through untouched, the N stack arguments
// are re-pushed for the __fastcall fake (which pops its copies), EDX is then seeded for the next fake, and `ret 4*N` pops the
// caller's arguments like the native (57B000 ret 0x10, 55F160 ret 0x14, state virtuals and deleting destructor ret 4, 4B4A50/
// 557D80/WCur/queue callbacks plain ret). Each `push dword ptr [esp+4*N]` reads the next lower argument because ESP moves by 4.
// Seeds are MASM hex immediates here (inline asm does not reliably resolve constexpr names); they must match the SEED_* constants.
#define TRAMP0(NAME, IMPL, SEEDHEX)                                              \
    __declspec(naked) static void NAME() {                                       \
        __asm { call IMPL }                                                      \
        __asm { mov edx, SEEDHEX }                                               \
        __asm { ret }                                                            \
    }
#define TRAMP1(NAME, IMPL, SEEDHEX)                                              \
    __declspec(naked) static void NAME() {                                       \
        __asm { push dword ptr [esp + 4] }                                       \
        __asm { call IMPL }                                                      \
        __asm { mov edx, SEEDHEX }                                               \
        __asm { ret 4 }                                                          \
    }
#define TRAMP4(NAME, IMPL, SEEDHEX)                                              \
    __declspec(naked) static void NAME() {                                       \
        __asm { push dword ptr [esp + 16] }                                      \
        __asm { push dword ptr [esp + 16] }                                      \
        __asm { push dword ptr [esp + 16] }                                      \
        __asm { push dword ptr [esp + 16] }                                      \
        __asm { call IMPL }                                                      \
        __asm { mov edx, SEEDHEX }                                               \
        __asm { ret 16 }                                                         \
    }
#define TRAMP5(NAME, IMPL, SEEDHEX)                                              \
    __declspec(naked) static void NAME() {                                       \
        __asm { push dword ptr [esp + 20] }                                      \
        __asm { push dword ptr [esp + 20] }                                      \
        __asm { push dword ptr [esp + 20] }                                      \
        __asm { push dword ptr [esp + 20] }                                      \
        __asm { push dword ptr [esp + 20] }                                      \
        __asm { call IMPL }                                                      \
        __asm { mov edx, SEEDHEX }                                               \
        __asm { ret 20 }                                                         \
    }
TRAMP1(NextT, NextImpl, 0ED0000A1h)   // SEED_NEXT; state slot 0, one argument (the wrapper W)
TRAMP1(LeaveT, LeaveImpl, 0ED0000A2h) // SEED_LEAVE; state slot 3
TRAMP1(EnterOtherT, EnterOtherImpl, 0ED0000A9h) // SEED_OTHER; state slot 1 of every non-matched state
TRAMP1(UpdateT, UpdateImpl, 0ED0000A4h) // SEED_UPDATE; state slot 2
TRAMP0(WCurT, WCurImpl, 0ED0000A5h)   // SEED_WCUR; wrapper slot 2, no argument
TRAMP4(AssignT, AssignImpl, 0ED0000A6h) // SEED_ASSIGN; 57B000
TRAMP5(PerManT, PerManImpl, 0ED0000A7h) // SEED_PERMAN; 55F160
TRAMP0(ContT, ContImpl, 0ED0000A8h)   // SEED_CONT; 4B4A50
TRAMP0(TailT, TailImpl, 0ED0000AAh)   // SEED_TAIL; 557D80
TRAMP1(DtorT, DtorImpl, 0ED0000A3h)   // any deterministic value; dtor EDX is not compared; erase passes the flag 1
TRAMP0(OtherCbT, OtherCbImpl, 0ED0000AAh) // queue callback: ECX = command, EDX = class vtable, no argument
#undef TRAMP0
#undef TRAMP1
#undef TRAMP4
#undef TRAMP5
__declspec(naked) static void TrapT() {
    __asm { call TrapImpl }
    __asm { ret }
}

// ---- Fixture construction ------------------------------------------------------------------------------------------------------
void QueueInit(void* q, U entries, const B* c0, U s0, const B* c1, U s1) {
    std::memset(q, 0, kQueueBytes);
    std::memset(q, 0xA5, kQueueBytes);
    for (U e = 0; e < 8; ++e) {
        const B* c = e == 0 ? c0 : e == 1 ? c1 : fx.cmdA;
        std::memcpy(static_cast<B*>(q) + kEntriesOff + 8 * e, &c, 4);
        const U size = e == 0 ? s0 : e == 1 ? s1 : 0x10 + 4 * e;
        std::memcpy(static_cast<B*>(q) + kEntriesOff + 8 * e + 4, &size, 4);
    }
    Dw(q, kCountOff) = entries;
    Dw(q, kTotalOff) = 0x1000;
    Dw(q, kFreeOff) = 0x200;
    Dw(q, kSpareOff) = 0x5A5A5A5Au;
    reinterpret_cast<B*>(q)[kIterOff] = 0x77;
    reinterpret_cast<B*>(q)[kDirtyOff] = 1;
    Dw(q, kIndexOff) = 0x1234;
}
void Build(const Cfg& cfg) {
    std::memset(&fx, 0, sizeof(fx));
    for (U& g : fx.guard) g = 0xFEEDFACEu;
    fx.vtCmd[0] = Fn(&DtorT); fx.vtCmd[1] = NativeAddress(0x581CA0); fx.vtCmd[2] = Fn(&TrapT); fx.vtCmd[3] = 0xDEAD0000u;
    fx.vtOther[0] = Fn(&DtorT); fx.vtOther[1] = Fn(&TrapT); fx.vtOther[2] = Fn(&OtherCbT); fx.vtOther[3] = 0xDEADBEEFu;
    fx.vtW[2] = Fn(&WCurT);
    for (U i = 0; i < kStates; ++i) { // 10FBBD0 slots: +0 next, +4 enter, +8 update, +0xC leave
        fx.vtS[i][0] = Fn(&NextT);
        fx.vtS[i][1] = (i == cfg.matched) ? NativeAddress(0x4F84C0) : Fn(&EnterOtherT);
        fx.vtS[i][2] = Fn(&UpdateT);
        fx.vtS[i][3] = Fn(&LeaveT);
        fx.st[i] = A(&fx.vtS[i]);
    }
    for (U i = 0; i < kMen; ++i) {
        fx.men[i] = A(&fx.manObjs[i]);
        const U word = 0x1800u + i;
        std::memcpy(fx.recs + i * kRecStride + 0x18, &word, 2);
    }
    fx.cont[0x18 / 4] = cfg.men;
    fx.cont[0x1C / 4] = A(fx.men);
    QueueInit(fx.q, cfg.twoCommands ? 2u : 1u, cfg.twoCommands ? fx.cmdOther : fx.cmdA, 0x40, fx.cmdA, 0x44);
    QueueInit(fx.qB, 1u, fx.cmdB, 0x48, fx.cmdB, 0x4C);
    auto cmd = [&](B* c, U cur) {
        CmdSetU(c, 0x00, A(fx.vtCmd));
        CmdSetU(c, 0x18, A(fx.vtW));
        CmdSetU(c, 0x1C, cur == kNull ? 0u : A(&fx.st[cur]));
        CmdSetU(c, 0x20, cfg.maxIter);
        CmdSetU(c, 0x24, 0xAA242424u);
        CmdSetU(c, 0x28, 0xAA282828u);
        CmdSetU(c, 0x2C, KFLOAT_BITS);
        CmdSetB(c, 0x35, static_cast<B>(cfg.guard35));
        CmdSetU(c, 0x44, A(fx.recs));
    };
    cmd(fx.cmdA, cfg.cur);
    cmd(fx.cmdB, 3); // nested command: state 3 -> state 4 (other enter) -> null
    CmdSetU(fx.cmdOther, 0x00, A(fx.vtOther));
    // Census unit fixture (only the census path reads it): one member whose member virtual is the native 580A30.
    fx.memberList[0] = A(fx.member);
    const U memberVtable = A(fx.memberVtbl);
    std::memcpy(fx.member, &memberVtable, sizeof(memberVtable));
    const U members = 1;
    std::memcpy(fx.member + 0x18, &members, 4);
    fx.memberVtbl[3] = NativeAddress(0x580A30);
    fx.unit[0xAB0 / 4] = 1;
    fx.unit[0xAB4 / 4] = A(fx.memberList);
    fx.unit[0xACC / 4] = 0;
    fx.unit[0xAD0 / 4] = A(&fx.memberList[1]);
    gLog.count = 0;
    for (bool& s : g_nextSeen) s = false;
}

// ---- Run entry points ----------------------------------------------------------------------------------------------------------
U s_ecx, s_fn, s_eax, s_ebx, s_esi, s_edi, s_ebp, s_esp0, s_esp1;
__declspec(naked) void SentinelCall() {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov s_esp0, esp
        mov ebx, 0BADB001h
        mov esi, 0BADBEE5h
        mov edi, 0BADD00Dh
        mov ebp, 0BADFACEh
        mov edx, 0DEDEDEDh
        mov ecx, s_ecx
        call dword ptr [s_fn]
        mov s_eax, eax
        mov s_ebx, ebx
        mov s_esi, esi
        mov s_edi, edi
        mov s_ebp, ebp
        mov s_esp1, esp
        mov esp, s_esp0
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret
    }
}
U __fastcall FormStub(void* member) { // stands in for the 580A30 formation-update clone: drive the real queue gate
    (void)member;
    const auto gate = reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(bindings[KNTWR_BIND_FORM_QUEUE]));
    gate(fx.q);
    return 0;
}
U __fastcall CensusFormation(void* unit) {
    Require(kntwr_army_storm::InUnit(), "real census occurrence entered");
    return kntwr_army_storm::Call(kntwr_army_storm::BFormation, unit, &kntwr_form_residual::Formation);
}
U __fastcall Census(void* unit) { return kntwr_army_storm::Unit(unit, 0, &CensusFormation); }

DWORD GuardedRun() {
    __try { SentinelCall(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    return 0;
}

// ---- Comparison and assertions --------------------------------------------------------------------------------------------------
struct Result { Fixture fx; Log log; DWORD code; };
Result nat;
U g_tick = 1000;
unsigned long long g_qpc = 0x200000000ull;

as::CensusSnapshot g_c0, g_c1; // solver census snapshots around the last Exec
void Exec(Result& r) {
    gLog.count = 0;
    s_ecx = g_modeKind == 0 ? A(fx.q) : A(fx.unit);
    s_fn = g_modeKind == 0 ? NativeAddress(0x581E80) : Fn(&Census);
    g_c0 = ReadSolver();
    r.code = GuardedRun();
    g_c1 = ReadSolver();
    r.fx = fx;
    r.log = gLog;
}
// Exact solver-counter deltas of the last Exec for `assigns` fake assignments: the always-on counters advance by the stub's
// constants in EVERY mode; the census-only scope accumulators advance only when the route probe armed them (scopes == assigns),
// and never outside it (scopes == 0). The kernel and shim-suppression counters are not reachable by the stub (stay 0).
void CheckSolverDelta(U assigns, U scopes) {
    Require(g_c1.assignEntries - g_c0.assignEntries == assigns * kStubEntriesPerAssign, "solver counted outer and nested assignment entries");
    Require(g_c1.solvesSeen - g_c0.solvesSeen == assigns * kStubSolvesPerAssign, "solver counted every stub solve");
    Require(g_c1.flag0Native - g_c0.flag0Native == assigns * kStubFlag0, "solver counted the limited native solves");
    Require(g_c1.solvedKernel == g_c0.solvedKernel && g_c1.kernelQ == g_c0.kernelQ, "stub run never entered the memo kernel");
    Require(g_c1.shimSuppressed == g_c0.shimSuppressed, "stub run never suppressed through the shim");
    Require(g_c1.assignScopeCalls - g_c0.assignScopeCalls == scopes, "assign-scope timer ran exactly for the armed outermost scopes");
    if (scopes == 0) Require(g_c1.assignScopeQ == g_c0.assignScopeQ, "no assign-scope time accumulated outside the route probe");
    else Require(g_c1.assignScopeQ > g_c0.assignScopeQ, "armed assign scopes accumulated time");
}
void Same(const Result& a, const Result& b) {
    Require(a.code == b.code, "same exception outcome as native");
    Require(a.log.count == b.log.count && std::memcmp(a.log.e, b.log.e, a.log.count * sizeof(Event)) == 0,
            "callback/destructor event log equal native");
    Require(std::memcmp(&a.fx, &b.fx, sizeof(Fixture)) == 0, "entire fixture (queues, commands, states, guards) equal native");
}
// Eight consecutive split words (assign_scope_us/calls, inner_kernel_us, inner_solves, inner_lim_us/calls, inner_suppressed,
// inner_assign_entries) of `n` fake assignments: counts are exact; times are bounded below by the stub's spins (90% slack for the
// QPC-to-us floor) and the scope brackets its limited solves.
void CheckSplitWords(const U* s, U n) {
    Require(s[1] == n, "split: assign-scope calls == routed assignments");
    Require(s[2] == 0, "split: inner kernel us == 0 (stub never enters the memo kernel)");
    Require(s[3] == n * kStubSolvesPerAssign, "split: inner solves");
    Require(s[5] == n * kStubFlag0, "split: inner limited calls");
    Require(s[6] == 0, "split: inner suppressed == 0 (stub never suppresses through the shim)");
    Require(s[7] == n * kStubEntriesPerAssign, "split: inner assign entries (outer + nested)");
    Require(s[4] >= n * kStubFlag0 * kStubSpinSolveUs * 9 / 10, "split: inner limited us covers the spun limited solves");
    Require(s[0] >= n * (kStubSpinScopeUs + kStubSolvesPerAssign * kStubSpinSolveUs) * 9 / 10, "split: assign-scope us covers the stub spins");
    Require(s[0] >= s[4], "split: assign-scope time brackets the limited solves");
    if (n == 0) for (U i = 0; i < 8; ++i) Require(s[i] == 0, "split: no assignments, all words zero");
}
const U* Row(const U* w, U tick) {
    for (U i = 0; i < fr::kTop; ++i) {
        const U* r = w + fr::TopTable + i * fr::kEntryWords;
        if (r[fr::ETick] == tick) return r;
    }
    return nullptr;
}
void CheckDisarmed(const U* w, U tick, const Profile& p) {
    Require(w[fr::Version] == fr::kVersion, "residual version");
    const U* r = Row(w, tick);
    Require(r != nullptr, "storm row published");
    Require(r[fr::EQueueCmdCalls] == p.callbacks, "disarmed row counts every queue callback");
    for (U i = fr::ERouteCalls; i <= fr::ERouteSlowInnerAssignEntries; ++i) Require(r[i] == 0, "disarmed row has no route words");
    Require((r[fr::EFlags] & fr::EFlagSlowRouted) == 0, "disarmed row flags no routed slow callback");
    Require(w[fr::RouteTable + fr::RArmed] == 0, "route table reports disarmed");
    for (U i = fr::RCalls; i <= fr::RInnerAssignEntries; ++i) Require(w[fr::RouteTable + i] == 0, "disarmed route table is empty");
    const U* ld = w + fr::LedgerTable;
    Require(ld[fr::LRouteBegun] == 0 && ld[fr::LRouteRefusedScope] == 0 && ld[fr::LRouteUnscopedGates] == 0,
            "disarmed ledger has no route activity");
    Require(ld[fr::LQueueFolded] == p.callbacks, "disarmed ledger folded every callback");
}
void CheckRefused(const U* w, const Profile& p) {
    const U* ld = w + fr::LedgerTable;
    Require(ld[fr::LRouteRefusedScope] == p.routed, "every route-matching callback refused with no open invocation");
    Require(ld[fr::LRouteBegun] == 0 && ld[fr::LRouteDiscarded] == 0, "no routed scope ever began");
    Require(ld[fr::LQueueOutside] == p.callbacks, "every callback counted outside an open invocation");
    Require(ld[fr::LRouteUnscopedGates] == 0, "native callbacks never enter the private gates");
    Require(w[fr::RouteTable + fr::RArmed] == 1 && w[fr::RouteTable + fr::RCalls] == 0,
            "route table armed but empty after refusals");
    Require(ld[fr::LTopOffered] == 0, "the publishing abort added no storm row");
}
void CheckArmed(const U* w, U tick, const Profile& p) {
    Require(w[fr::Version] == fr::kVersion, "residual version");
    const U* r = Row(w, tick);
    Require(r != nullptr, "storm row published");
    Require(r[fr::EQueueCmdCalls] == p.callbacks, "row counts every queue callback (outer and nested)");
    Require(r[fr::ERouteCalls] == p.routed, "row counts every routed callback");
    Require(r[fr::ERouteEnterCalls] == p.enters && r[fr::ERouteOtherEnterCalls] == p.others,
            "row nested enter counts (matched and other)");
    Require(r[fr::ERouteAssignCalls] == p.assigns && r[fr::ERoutePerManCalls] == p.permans,
            "row nested assignment and per-man counts");
    if (p.routed) Require(r[fr::ERouteUs] >= r[fr::ERouteEnterUs] + r[fr::ERouteOtherEnterUs],
                          "route time brackets the nested enter time");
    if (p.enters) Require(r[fr::ERouteEnterUs] >= r[fr::ERouteAssignUs] + r[fr::ERoutePerManUs],
                          "enter time brackets the assignment and per-man time");
    // Inclusive times are floored to whole microseconds per published word: only spun fakes are guaranteed a nonzero reading.
    if (p.permans && g_cfg->spinPerManUs) Require(r[fr::ERoutePerManUs] > 0, "spun per-man calls took measurable time");
    Require(r[fr::ESlowVtable] == p.slowVtable && r[fr::ESlowSlot] == p.slowSlot, "slowest callback identity");
    Require(((r[fr::EFlags] & fr::EFlagSlowRouted) != 0) == p.slowRouted, "slowest-callback routed flag");
    // Every routed callback in this fixture uses vtCmd/slot 4, independently of the slowest OVERALL callback (which may be
    // vtOther/slot 8). Nested routed callbacks also use this class, while retaining their own nested counts below.
    const U routedSlowVtable = A(fx.vtCmd), routedSlowSlot = 4;
    Require(r[fr::ERouteSlowVtable] == routedSlowVtable && r[fr::ERouteSlowSlot] == routedSlowSlot,
            "slowest routed callback identity");
    Require(r[fr::ERouteSlowEnterCalls] == p.snEnter && r[fr::ERouteSlowOtherEnterCalls] == p.snOther,
            "slowest routed callback's own enter counts");
    Require(r[fr::ERouteSlowAssignCalls] == p.snAssign && r[fr::ERouteSlowPerManCalls] == p.snPerMan,
            "slowest routed callback's own assignment and per-man counts");
    CheckSplitWords(&r[fr::ERouteAssignScopeUs], p.assigns);
    CheckSplitWords(&r[fr::ERouteSlowAssignScopeUs], p.snAssign);
    const U* ld = w + fr::LedgerTable;
    Require(ld[fr::LRouteBegun] == p.routed && ld[fr::LRouteFolded] == p.routed, "every begun scope folded");
    Require(ld[fr::LRouteAborted] == 0 && ld[fr::LRouteDiscarded] == 0 && ld[fr::LQueueOutside] == 0,
            "no aborted, discarded or outside callbacks");
    Require(ld[fr::LRouteRefusedScope] == 0 && ld[fr::LRouteRefusedDepth] == 0 && ld[fr::LRouteUnscopedGates] == 0,
            "no refusals and no unscoped gates");
    Require(ld[fr::LRouteBegun] == ld[fr::LRouteFolded] + ld[fr::LRouteAborted] + ld[fr::LRouteDiscarded],
            "scope identity begun = folded + aborted + discarded");
    Require(ld[fr::LQueueFolded] == p.callbacks, "every callback folded into the queue ledger");
    Require(w[fr::RouteTable + fr::RArmed] == 1, "route table reports armed");
    Require(w[fr::RouteTable + fr::RCalls] == p.routed, "cumulative route table counts every routed callback");
    Require(w[fr::RouteTable + fr::RNoEnterCalls] == p.noEnter, "cumulative route table counts no-enter routed callbacks");
    Require(w[fr::RouteTable + fr::REnterCalls] == p.enters && w[fr::RouteTable + fr::ROtherEnterCalls] == p.others,
            "cumulative route table enter counts");
    Require(w[fr::RouteTable + fr::RAssignCalls] == p.assigns && w[fr::RouteTable + fr::RPerManCalls] == p.permans,
            "cumulative route table assignment and per-man counts");
    CheckSplitWords(&w[fr::RouteTable + fr::RAssignScopeUs], p.assigns);
    if (p.routed) Require(w[fr::RouteTable + fr::RUs] >= w[fr::RouteTable + fr::RMaxUs], "cumulative route table keeps a maximum");
    if (p.routed && (g_cfg->spinCbUs || g_cfg->spinPerManUs))
        Require(w[fr::RouteTable + fr::RMaxUs] > 0, "spun routed callback took measurable time");
    // Cumulative queue class table: the (vtCmd,4) class ran once per routed callback, the (vtOther,8) class once per other call.
    U cmdCls = 0, otherCls = 0;
    for (U i = 0; i < fr::kQueueClasses; ++i) {
        const U* c = w + fr::QueueTable + 2 + i * 5;
        if (c[0] == A(fx.vtCmd) && c[1] == 4) cmdCls = c[2];
        if (c[0] == A(fx.vtOther) && c[1] == 8) otherCls = c[2];
    }
    Require(cmdCls == p.routed, "queue class table counts the routed command class");
    Require(otherCls == p.otherCalls, "queue class table counts the other class");
}
void CheckAborted(const U* w, const Profile& p) {
    const U* ld = w + fr::LedgerTable;
    Require(ld[fr::LRouteBegun] == p.routed && ld[fr::LRouteAborted] == p.routed && ld[fr::LRouteFolded] == 0,
            "every begun scope aborted with its invocation");
    Require(ld[fr::LQueueAborted] == p.callbacks, "every ended callback aborted with its invocation");
    Require(ld[fr::LAbortedRouteUs] > 0, "aborted route time recorded");
    Require(ld[fr::LRouteBegun] == ld[fr::LRouteFolded] + ld[fr::LRouteAborted] + ld[fr::LRouteDiscarded],
            "scope identity holds after abort");
    Require(ld[fr::LTopOffered] == 0, "the abort added no storm row");
    Require(w[fr::RouteTable + fr::RCalls] == p.routed, "route table still counts the callbacks that ended");
}
void CheckException(const U* w, bool armed) {
    const U* ld = w + fr::LedgerTable;
    Require(ld[fr::LTopOffered] == 0, "the aborted tick added no storm row");
    if (armed) {
        Require(ld[fr::LRouteBegun] == 1 && ld[fr::LRouteDiscarded] == 1 && ld[fr::LRouteFolded] == 0 &&
                ld[fr::LRouteAborted] == 0, "the in-flight routed scope was discarded as stale, not folded or aborted");
        Require(ld[fr::LRouteBegun] == ld[fr::LRouteFolded] + ld[fr::LRouteAborted] + ld[fr::LRouteDiscarded],
                "scope identity holds after the exception");
        Require(w[fr::RouteTable + fr::RCalls] == 0, "the callback never ended so the route table stays empty");
    } else {
        Require(ld[fr::LRouteBegun] == 0, "no routed scope without the private route");
    }
}

// ---- Case engine ----------------------------------------------------------------------------------------------------------------
void RunCase(const Cfg& cfg, const Profile& p) {
    current = cfg.name;
    g_cfg = &cfg;

    mode = "native";
    g_modeKind = 0;
    Build(cfg);
    Exec(nat);
    CheckSolverDelta(p.assigns, 0);
    Require(nat.code == 0 || cfg.throwAt != kNone, "only the scripted case throws");
    if (nat.code == 0)
        Require(s_esp0 == s_esp1 && s_ebx == 0xBADB001 && s_esi == 0xBADBEE5 && s_edi == 0xBADD00D && s_ebp == 0xBADFACE,
                "native walk preserved callee-saved registers and balanced the stack");

    mode = "disarmed";
    g_modeKind = 1;
    Require(fr::Start(Fn(&FormStub), 0, 0), "start census observer off (no private route)");
    fr::Reset();
    Build(cfg);
    kntwr_army_storm::Reset();
    fr::TickBegin();
    Result dis;
    Exec(dis);
    CheckSolverDelta(p.assigns, 0);
    const U tick = g_tick++;
    if (dis.code) {
        kntwr_army_storm::Reset();
        fr::TickAbort();
        U w[fr::kWords];
        fr::Snapshot(w);
        CheckException(w, false);
    } else {
        fr::TickEnd(tick, 5000, true, g_qpc += 0x110000001ull, 6000);
        U w[fr::kWords];
        fr::Snapshot(w);
        CheckDisarmed(w, tick, p);
    }
    Same(nat, dis);

    mode = "refused";
    g_modeKind = 2;
    Require(fr::Start(Fn(&FormStub), g_clones.entries[KNTWR_CLONE_CMD_581CA0], g_clones.entries[KNTWR_CLONE_CMD_4F84C0]),
            "start census armed with the private clones");
    fr::Reset();
    Build(cfg);
    kntwr_army_storm::Reset();
    Result ref;
    Exec(ref); // no TickBegin: every route attempt is refused
    CheckSolverDelta(p.assigns, 0);
    fr::TickBegin();
    fr::TickAbort();
    {
        U w[fr::kWords];
        fr::Snapshot(w);
        if (ref.code) CheckException(w, false);
        else CheckRefused(w, p);
    }
    Same(nat, ref);

    mode = cfg.throwAt != kNone ? "armed-exception" : "armed";
    g_modeKind = 3;
    Require(fr::Start(Fn(&FormStub), g_clones.entries[KNTWR_CLONE_CMD_581CA0], g_clones.entries[KNTWR_CLONE_CMD_4F84C0]),
            "start census armed with the private clones");
    fr::Reset();
    Build(cfg);
    kntwr_army_storm::Reset();
    fr::TickBegin();
    Result arm;
    Exec(arm);
    CheckSolverDelta(p.assigns, p.assigns);
    const U tick2 = g_tick++;
    if (arm.code) {
        kntwr_army_storm::Reset();
        fr::TickAbort();
        U w[fr::kWords];
        fr::Snapshot(w);
        CheckException(w, true);
    } else {
        fr::TickEnd(tick2, 5000, true, g_qpc += 0x110000001ull, 6000);
        U w[fr::kWords];
        fr::Snapshot(w);
        CheckArmed(w, tick2, p);
    }
    Same(nat, arm);
    if (arm.code == 0) Require(s_esp0 == s_esp1 && s_ebx == 0xBADB001 && s_esi == 0xBADBEE5 && s_edi == 0xBADD00D &&
                               s_ebp == 0xBADFACE, "private chain preserved callee-saved registers and balanced the stack");
    fr::Stop();
    ++cases;
}

void RunAbortCase(const Cfg& cfg, const Profile& p) {
    current = cfg.name;
    g_cfg = &cfg;
    for (U kind = 0; kind < 2; ++kind) { // 0: disarmed + abort, 1: armed + abort
        mode = kind ? "armed-abort" : "disarmed-abort";
        g_modeKind = kind ? 3 : 1;
        Require(fr::Start(Fn(&FormStub), kind ? g_clones.entries[KNTWR_CLONE_CMD_581CA0] : 0,
                          kind ? g_clones.entries[KNTWR_CLONE_CMD_4F84C0] : 0), "start census for the abort case");
        fr::Reset();
        Build(cfg);
        kntwr_army_storm::Reset();
        fr::TickBegin();
        Result r;
        Exec(r);
        Require(r.code == 0, "abort case completes normally");
        fr::TickAbort();
        U w[fr::kWords];
        fr::Snapshot(w);
        if (kind) CheckAborted(w, p);
        else {
            const U* ld = w + fr::LedgerTable;
            Require(ld[fr::LQueueAborted] == p.callbacks, "disarmed abort counts every callback");
            Require(w[fr::RouteTable + fr::RCalls] == 0, "disarmed abort keeps the route table empty");
            Require(ld[fr::LTopOffered] == 0, "the abort added no storm row");
        }
        fr::Stop();
    }
    ++cases;
}

void Cases() {
    Cfg c = {};
    auto blank = [&](const char* name) {
        c = Cfg{};
        c.name = name;
        c.cur = kNull;
        for (U& n : c.next) n = kNull;
        c.matched = kNull;
        c.maxIter = 7;
        c.men = 2;
        c.shrinkAt = kNone; c.throwAt = kNone; c.nestAt = kNone;
        c.guard35 = 0;
    };
    Profile p = {};

    // 1. Null current state: 581CA0/10FC370 return without entering the chain at all.
    blank("null state");
    p = {}; p.callbacks = 1; p.routed = 1; p.noEnter = 1; p.slowSlot = 4; p.slowRouted = true;
    p.slowVtable = A(fx.vtCmd); // vtCmd address is stable across builds
    RunCase(c, p);

    // 2. No transition: next-state null, update leaves the state unchanged -> al = 0 -> erase + tail, no leave/enter.
    blank("no transition");
    c.cur = 0; c.next[0] = kNull;
    p = {}; p.callbacks = 1; p.routed = 1; p.noEnter = 1; p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    RunCase(c, p);

    // 3. Guard off: one matched enter, assignment skipped, two per-man calls.
    blank("guard off");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 0; p.snPerMan = 2;
    RunCase(c, p);

    // 4. Guard on: one matched enter with the assignment call, two per-man calls.
    blank("guard on");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 5. Multiple transitions: S0 -> S1 (matched enter) -> S2 (other enter) -> null.
    blank("multiple transitions");
    c.cur = 0; c.next[0] = 1; c.next[1] = 2; c.next[2] = kNull; c.matched = 1; c.guard35 = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.others = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 1; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 6. Transition budget reached: al = 1, no erase, no tail; the chain still ran its matched enter.
    blank("transition budget reached");
    c.cur = 0; c.next[0] = 1; c.next[1] = 2; c.matched = 1; c.guard35 = 1; c.maxIter = 0;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 7. Other-state enter only: no matched enter (route counted as no-enter), one other enter.
    blank("other-state enter only");
    c.cur = 0; c.next[0] = 2; c.next[2] = kNull; c.matched = kNull; c.guard35 = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.others = 1; p.noEnter = 1;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 0; p.snOther = 1; p.snAssign = 0; p.snPerMan = 0;
    RunCase(c, p);

    // 8. Empty container: the assignment runs, the per-man loop is empty.
    blank("empty container");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1; c.men = 0;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 0;
    RunCase(c, p);

    // 9. Count shrink: five men at entry, the second per-man shrinks the container to two (count re-read bounds the loop).
    blank("count shrink");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 0; c.men = 5; c.shrinkAt = 1; c.shrinkTo = 2;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 0; p.snPerMan = 2;
    RunCase(c, p);

    // 10. Two commands, other-class callback slowest: the slowest callback is NOT the routed one.
    blank("two commands other slowest");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1;
    c.twoCommands = true; c.otherSpinUs = 2000; c.spinCbUs = 50; c.spinPerManUs = 20;
    p = {}; p.callbacks = 2; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2; p.otherCalls = 1;
    p.slowVtable = A(fx.vtOther); p.slowSlot = 8; p.slowRouted = false;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 11. Two commands, routed callback slowest: the routed flag marks the slowest callback and its own nest.
    blank("two commands routed slowest");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1;
    c.twoCommands = true; c.otherSpinUs = 20; c.spinCbUs = 50; c.spinPerManUs = 1000;
    p = {}; p.callbacks = 2; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2; p.otherCalls = 1;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 12. Exception in the per-man fake: the in-flight routed scope is discarded as stale.
    blank("exception discards scope");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1; c.throwAt = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // Recovery after the exception: the same case again proves a clean run follows.
    blank("recovery after exception");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 13. Reentrant nested queue from a per-man fake: two routed callbacks, the outer one inclusive-slowest;
    // its own nest (enter 1, other 0, assign 1, per-man 2) differs from the row aggregate (other enter 1) -> same-callback proof.
    blank("reentrant nested callbacks");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1; c.nestAt = 0;
    c.next[3] = 4; c.next[4] = kNull; // nested command chain: state 3 -> state 4 (other enter) -> null
    p = {}; p.callbacks = 2; p.routed = 2; p.enters = 1; p.others = 1; p.assigns = 1; p.permans = 2; p.noEnter = 1;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunCase(c, p);

    // 14. Rounding control: the clone's fld/fistp honors _RC_UP exactly like the native bytes (910 instead of 909).
    blank("fistp honors rounding mode");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1; c.rcUp = true;
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    _control87(_RC_UP, _MCW_RC);
    RunCase(c, p);
    _control87(_RC_NEAR, _MCW_RC);

    // 15. Abort with ended callbacks: the invocation aborts after the routed callback returned; scope aborted, row omitted.
    blank("abort after routed callback");
    c.cur = 0; c.next[0] = 1; c.next[1] = kNull; c.matched = 1; c.guard35 = 1; c.spinPerManUs = 20; // aborted us must be nonzero
    p = {}; p.callbacks = 1; p.routed = 1; p.enters = 1; p.assigns = 1; p.permans = 2;
    p.slowVtable = A(fx.vtCmd); p.slowSlot = 4; p.slowRouted = true;
    p.snEnter = 1; p.snOther = 0; p.snAssign = 1; p.snPerMan = 2;
    RunAbortCase(c, p);
}

// ---- Clone wiring pins ---------------------------------------------------------------------------------------------------------
bool CloneCall(U entry, U srcVa, U siteVa, U target) { // entry: absolute clone address; target: absolute destination
    const U at = entry + (siteVa - srcVa);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(at));
    if (p[0] != 0xE8) return false;
    int32_t rel;
    std::memcpy(&rel, p + 1, 4);
    return at + 5 + static_cast<U>(rel) == target;
}
void CheckWiring() {
    const U e581 = g_clones.entries[KNTWR_CLONE_CMD_581CA0], e370 = g_clones.entries[KNTWR_CLONE_CMD_10FC370],
            eBD0 = g_clones.entries[KNTWR_CLONE_CMD_10FBBD0], e4f8 = g_clones.entries[KNTWR_CLONE_CMD_4F84C0],
            e736 = g_clones.entries[KNTWR_CLONE_CMD_5736B0];
    Require(e581 && e370 && eBD0 && e4f8 && e736, "all five private chain clones built");
    Require(CloneCall(e581, 0x581CA0, 0x581CA6, e370), "581CA0 clone -> 10FC370 clone");
    Require(CloneCall(e370, 0x10FC370, 0x10FC389, eBD0), "10FC370 clone -> 10FBBD0 clone");
    Require(CloneCall(eBD0, 0x10FBBD0, 0x10FBBF1, bindings[KNTWR_BIND_CMD_ENTER]), "10FBBD0 clone -> enter gate");
    Require(CloneCall(e4f8, 0x4F84C0, 0x4F84CD, e736), "4F84C0 clone -> 5736B0 clone");
    Require(CloneCall(e736, 0x5736B0, 0x5736E0, bindings[KNTWR_BIND_CMD_ASSIGN]), "5736B0 clone -> assignment gate");
    Require(CloneCall(e736, 0x5736B0, 0x573727, bindings[KNTWR_BIND_CMD_PERMAN]), "5736B0 clone -> per-man gate");
    Require(bindings[KNTWR_BIND_CMD_ENTER] && bindings[KNTWR_BIND_CMD_ASSIGN] && bindings[KNTWR_BIND_CMD_PERMAN],
            "command-split gates bound");
    // image holds preferred VA 0x400000 at offset 0 (mapped at 0x400000 + delta): index by preferred VA - 0x400000.
    auto at = [](U va) { return image[va - 0x400000]; };
    Require(at(0x581CA0) == 0x56 && at(0x581CC7) == 0xC3, "581CA0 clone copies the native prologue and return");
    // The private image's indirect enter site is untouched: only the clone performs the redirect, never the image.
    Require(at(0x10FBBF3) == 0xFF && at(0x10FBBF4) == 0x50 && at(0x10FBBF5) == 0x04,
            "image bytes at the 10FBBF3 state-enter virtual call stay unpatched");
    U thunk;
    std::memcpy(&thunk, image + (0x4F84C0 - 0x400000), 4);
    Require(thunk == 0x04244C8Bu, "image bytes at 4F84C0 stay the native thunk (mov ecx,[esp+4])");
}

// ---- Solver census wiring ------------------------------------------------------------------------------------------------------
B g_orig502770[7];
void RestoreBytes(U va, const B* bytes) {
    B* p = image + (va - 0x400000);
    DWORD old;
    Require(VirtualProtect(p, 7, PAGE_EXECUTE_READWRITE, &old) != 0, "restore page writable");
    std::memcpy(p, bytes, 7);
    Require(VirtualProtect(p, 7, old, &old) != 0, "restore protection");
    Require(FlushInstructionCache(GetCurrentProcess(), p, 7) != 0, "flush restore");
}
as::Binding StubBinding(as::LimitedSink sink) {
    as::Binding b = {};
    b.delta = delta; b.mode = as::ModeForward; b.cloneAssign = b.cloneStockAssign = Fn(&CloneAssignStub); b.limitedSink = sink;
    return b;
}
// Solver started WITHOUT a limited sink (the default, non-census runtime): the always-on counters advance, nothing is timed outside
// an armed probe, and an armed probe times exactly the outermost scope. Leaves the solver stopped and 0x502770 restored.
void SolverDefaultPath() {
    current = "solver default path";
    mode = "no sink";
    std::memcpy(g_orig502770, image + (0x502770 - 0x400000), sizeof(g_orig502770));
    Require(as::Start(StubBinding(nullptr)), "start the army solver in forward mode against the private image (no limited sink)");
    PatchJump(0x502770, reinterpret_cast<const void*>(&FakeSolveImpl));
    const auto gate = reinterpret_cast<GateAssignFn>(g_assignGate);
    const as::CensusSnapshot a = ReadSolver();
    const U solves0 = g_stubSolveCalls;
    Require(gate(g_stubFormation, nullptr, 1, 2, 3, 1) == kStubAssignRet, "default path forwards the stub EAX");
    const as::CensusSnapshot b = ReadSolver();
    Require(g_stubSolveCalls - solves0 == kStubSolvesPerAssign, "every stub solve ran the fake native");
    Require(b.assignEntries - a.assignEntries == kStubEntriesPerAssign && b.solvesSeen - a.solvesSeen == kStubSolvesPerAssign &&
            b.flag0Native - a.flag0Native == kStubFlag0, "always-on counters advance by the stub constants");
    Require(b.limitedQ == 0 && b.assignScopeQ == 0 && b.assignScopeCalls == 0 && b.kernelQ == 0,
            "default path (no sink, no probe) accumulates no time anywhere");
    as::CensusProbeEnter();
    Require(gate(g_stubFormation, nullptr, 1, 2, 3, 1) == kStubAssignRet, "probed path forwards the stub EAX");
    as::CensusProbeLeave();
    const as::CensusSnapshot c = ReadSolver();
    Require(c.assignScopeCalls == 1 && c.assignScopeQ > 0, "armed probe times exactly the outermost scope (nested entry untimed)");
    Require(c.assignEntries - b.assignEntries == kStubEntriesPerAssign, "probed path counts the same entries");
    Require(c.limitedQ == 0, "no sink bound: limited solves stay untimed even while probed");
    as::CensusProbeEnter();
    as::CensusProbeReset();
    Require(gate(g_stubFormation, nullptr, 1, 2, 3, 1) == kStubAssignRet, "reset probe path forwards the stub EAX");
    Require(ReadSolver().assignScopeCalls == 1, "CensusProbeReset disarms the scope timer");
    as::Stop();
    RestoreBytes(0x502770, g_orig502770);
}

void Coverage() {
    current = "coverage";
    Require(cases >= 15, "every case ran");
    Require(nat.log.count > 0, "the native reference recorded chain events");
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: native_formation_command_split_oracle <pinned Napoleon.exe>\n");
        return 2;
    }
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_frequency = static_cast<unsigned long long>(f.QuadPart);
    Map(argv[1]);
    for (U& b : bindings) b = NativeAddress(0x6DCA08); // unreached bindings: valid image addresses, never executed here
    fr::Bind(delta, bindings);
    U detail = 0;
    const U rc = kntwr_build_clones(A(image), bindings, &g_clones, &detail);
    if (rc != 0) {
        std::fprintf(stderr, "kntwr_build_clones failed: error %u detail %#x\n", rc, detail);
        return 2;
    }
    CheckWiring();
    // Leaf natives of the assignment path become recording fakes (AFTER the clone build hashed the original bytes).
    PatchJump(0x57B000, reinterpret_cast<const void*>(&AssignT));
    PatchJump(0x55F160, reinterpret_cast<const void*>(&PerManT));
    PatchJump(0x557D80, reinterpret_cast<const void*>(&TailT));
    PatchJump(0x4B4A50, reinterpret_cast<const void*>(&ContT));
    Require(kntwr_army_storm::Start({A(image), 0}), "start real storm census");
    U solverBindings[KNTWR_BIND_COUNT] = {}; // private array: the clone build above keeps its dummy solver bindings
    as::Bind(delta, solverBindings);
    g_assignGate = solverBindings[KNTWR_BIND_SOLVER_ASSIGN];
    g_solveGate = solverBindings[KNTWR_BIND_SOLVER_SOLVE];
    SolverDefaultPath();
    std::memcpy(g_orig502770, image + (0x502770 - 0x400000), sizeof(g_orig502770));
    Require(as::Start(StubBinding(&SinkImpl)), "start the army solver in forward mode with a limited sink (census wiring)");
    PatchJump(0x502770, reinterpret_cast<const void*>(&FakeSolveImpl));
    g_solverStub = true;
    Cases();
    Coverage();
    g_solverStub = false;
    Require(g_sinkCalls > 0 && g_sinkQ > 0, "the limited sink saw the stub's limited solves");
    as::Stop();
    fr::Stop();
    kntwr_army_storm::Stop();
    VirtualFree(g_clones.allocation, 0, MEM_RELEASE);
    Require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release private image");
    std::printf("PASS command-split native-twin cases=%u checks=%u (581CA0 chain native vs private clones: observer off/refused/"
                "armed, guard, transitions, other enter, per-man, nested, abort, exception, rounding)\n", cases, checks);
    return 0;
}
