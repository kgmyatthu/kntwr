// NTW2_LOCO Stage 1 oracle. Three independent executions of the same mapped-real-image synthetic graph:
//   A  untouched original bytes of the private image copy (0x7F0260 / 0x7F08F0, selector 0x62A290, class wrapper 0x5B2CA0,
//      or the 0x531AF0 stage loop);
//   B  the emitted LOCO clone family rebound to the ORIGINAL scratch globals, calling the module's service taps
//      (an "original-equivalent clone with only service taps": the only way to observe the original-side service
//      sequence without editing a single original instruction);
//   C  the module-owned family (private scratch, ntw2_loco::Run / ntw2_loco::Stage / the emitted selector + class wrapper).
// The fixture is real engine data: genuine candidate vtables 0x1333714 and 0x132BA04, real soft-grid cells + 0x7EFA80 nodes, a
// real (populated) obstacle grid, real terrain sampler 0x64C5F0 / 0x679C50 table, real owner/pending list helpers, and the
// real native allocator FF7F20/FF7EF0 reached through its tag object (data seam). Only data slots (vtable copies, plane,
// owner, ring, pending, height, event and allocator tag objects) are host functions; they record calls and return fixed
// data, they never replace mover execution. No instruction of the image is patched.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <initializer_list>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_clones.h"
#include "native_loco.h"
#include "native_move_delta.h"
#include "native_sweep.h"
#include "native_resolve.h"
#include "native_env.h"
#include "collision/native_collision_solver.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace loco = ntw2_loco;
static_assert(sizeof(void*) == 4, "x86 oracle");
static_assert(loco::WordCount == 48, "Stage 1 status is 48 words");
static_assert(loco::GateWordCount == 48, "independent gate status is 48 words");
static_assert(loco::ServiceWordCount == 40, "independent service timing status is 40 words");
static_assert(loco::ServiceCount == 8 && loco::TimingServiceUs == 12 &&
    loco::TimingServiceMaxUs == 20 && loco::TimingServiceCalls == 28, "service timing slot layout");
static_assert(loco::kMoveGateMask == 0x233u, "serial MOVE enforces only class/lifetime/parked/pending/environment");
static_assert(loco::GridWordCount == 32 && loco::ParallelWordCount == 32, "owned grid and parallel status are 32 words");
static_assert(loco::OwnedWordCount == 32 && loco::OwnedDetailWordCount == 16, "owned admission detail is a separate tail");
extern "C" unsigned long _tls_index;
static constexpr U kFixtureSlots = 512;
__declspec(thread) static volatile U tlsPad[32];

static B* image;
static U delta, checks, cases;
static const char* currentCase = "mapping";
static ntw2_clone_set privateClones{}, globalClones{};
static U privateBindings[NTW2_BIND_COUNT];

[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fprintf(stderr, "FAIL [%s]: ", currentCase);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::fflush(stderr); std::exit(1);
}
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail("%s", what); }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static T Get(const void* p, size_t off) { T v; std::memcpy(&v, static_cast<const B*>(p) + off, sizeof(v)); return v; }
template<class T> static void Put(void* p, size_t off, T v) { std::memcpy(static_cast<B*>(p) + off, &v, sizeof(v)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static float KF(U va) { return Get<float>(At(va), 0); }
static U Bits(float f) { U u; std::memcpy(&u, &f, 4); return u; }
static void ResetFp() {
    unsigned short cw = 0x27f;
    __asm fninit
    __asm fldcw word ptr [cw]
    _mm_setcsr(0x1f80);
}
static void UnexpectedBinding() { Fail("unrelated clone binding executed"); }

// ---------------------------------------------------------------------------------------------------------------------
// Native allocator seam (data only). FF7F20 warm path: tag = [1462CFC]; calls [tag.vt + 4](tag, out{ptr, owner}, size)
// RET 8; FF7D50 then records owner id byte 4B4A50(owner) = [owner + 4] at 165F508 + (ptr >> 12). FF7EF0 maps that byte to
// the row 17639F8 + 12 * id and calls [row.vt + 8](row, ptr) RET 4. Allocation/free instructions stay REAL.
// ---------------------------------------------------------------------------------------------------------------------
static std::vector<U> g_allocs, g_frees;
static U g_allocVt[4];
static void __fastcall HostAlloc(void* self, void*, void* out, U size) {
    void* p = std::calloc(1, size ? size : 1);
    Put<U>(out, 0, A(p)); Put<U>(out, 4, A(self)); g_allocs.push_back(A(p));
}
static void __fastcall HostFree(void*, void*, void* ptr) { g_frees.push_back(A(ptr)); std::free(ptr); }

// ---------------------------------------------------------------------------------------------------------------------
// Private image
// ---------------------------------------------------------------------------------------------------------------------
static void BuildClones(const U* bindings, ntw2_clone_set* out, const char* what) {
    U detail = 0;
    const U error = ntw2_build_clones(A(image), bindings, out, &detail);
    if (error) Fail("%s clone construction error=%u detail=%u", what, error, detail);
}
static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open supported image read-only");
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
    // Data only (no instruction is patched): this process' TLS index so the original thread-safe-static epoch reads hit a
    // committed TLS block, and every guard the original mover/sweep/allocator touches pre-published as initialized.
    Put<U>(At(0x1841bb8), 0, _tls_index); tlsPad[0] = 0;
    // 801140 mode-bit guards: 15A5934/15A794C obstacle sweep, 15A7960 mode-2 tree query, 15A997C/15A9994 mode-8 owner gather.
    for (U guard : {0x15a1884u, 0x15a1898u, 0x15a18acu, 0x15a5934u, 0x15a794cu, 0x15a7960u, 0x15a997cu, 0x15a9994u, 0x1763c54u})
        Put<U>(At(guard), 0, 0x80000000u);
    g_allocVt[1] = Fn(&HostAlloc); g_allocVt[2] = Fn(&HostFree);
    Put<U>(At(0x17639f8), 0, A(g_allocVt)); Put<U>(At(0x17639f8), 4, 0); Put<U>(At(0x17639f8), 8, 0);
    Put<U>(At(0x1462cfc), 0, A(At(0x17639f8)));
    // Game heading table (BSS in the file): a deterministic full 65536-entry table. Hx = +0, Hz = +4 of each 8-byte entry.
    for (U h = 0; h < 65536; ++h) {
        const float angle = static_cast<float>(h) * 6.2831853f / 65536.0f;
        Put<float>(At(0x176cff8), 8 * h, std::sin(angle)); Put<float>(At(0x176cff8), 8 * h + 4, std::cos(angle));
    }
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0, "flush private image");
    U bindings[NTW2_BIND_COUNT]; std::fill(std::begin(bindings), std::end(bindings), Fn(&UnexpectedBinding));
    loco::Bind(delta, bindings); // the module takes the image DELTA; ntw2_build_clones below takes the image BASE
    std::memcpy(privateBindings, bindings, sizeof(bindings));
    BuildClones(bindings, &privateClones, "private");
    // Tapped-original-global family: identical specs, but scratch/guards bound to the original image globals.
    const U originalScratch[] = {0x14543b4, 0x15a1888, 0x15a189c, 0x15a1884, 0x15a1898, 0x15a18ac};
    const U ids[] = {NTW2_BIND_LOCO_SCRATCH_14543B4, NTW2_BIND_LOCO_SCRATCH_15A1888, NTW2_BIND_LOCO_SCRATCH_15A189C,
                     NTW2_BIND_LOCO_GUARD_15A1884, NTW2_BIND_LOCO_GUARD_15A1898, NTW2_BIND_LOCO_GUARD_15A18AC};
    for (U i = 0; i < 6; ++i) bindings[ids[i]] = A(At(originalScratch[i]));
    BuildClones(bindings, &globalClones, "original-global");
    for (U id : {NTW2_CLONE_LOCO_WRAP, NTW2_CLONE_LOCO_MOVE, NTW2_CLONE_LOCO_SELECT, NTW2_CLONE_LOCO_CLASS_WRAP})
        Require(privateClones.entries[id] != globalClones.entries[id] && privateClones.entries[id] && globalClones.entries[id],
            "two distinct clone families");
}

// ---------------------------------------------------------------------------------------------------------------------
// Fault reporting and guarded entries
// ---------------------------------------------------------------------------------------------------------------------
static LONG ReportFault(EXCEPTION_POINTERS* info, const char* what) {
    const EXCEPTION_RECORD* r = info->ExceptionRecord;
    const U eip = A(r->ExceptionAddress);
    const bool inImage = eip >= delta + 0x400000 && eip < delta + 0x400000 + 0x2000000;
    std::fprintf(stderr, "FAULT [%s] [%s] code=%08lX eip=%08X (image VA %08X) access=%08X\n", currentCase, what, r->ExceptionCode, eip,
        inImage ? eip - delta : 0, r->NumberParameters >= 2 ? static_cast<U>(r->ExceptionInformation[1]) : 0);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
static void CallEntry(U entry, void* agent, const char* what) {
    __try { reinterpret_cast<void(__fastcall*)(void*)>(entry)(agent); }
    __except (ReportFault(GetExceptionInformation(), what)) { std::exit(3); }
}
static void CallRun(void* agent, bool wrapper) {
    __try { loco::Run(agent, wrapper); }
    __except (ReportFault(GetExceptionInformation(), "module Run")) { std::exit(3); }
}
static U CallStageOriginal(void* manager) {
    __try { return reinterpret_cast<U(__fastcall*)(void*)>(At(0x531af0))(manager); }
    __except (ReportFault(GetExceptionInformation(), "original 531AF0")) { std::exit(3); }
}
static U CallStageModule(void* manager) {
    __try { return loco::Stage(manager); }
    __except (ReportFault(GetExceptionInformation(), "module Stage")) { std::exit(3); }
}
static void CallStop() {
    __try { loco::Stop(); }
    __except (ReportFault(GetExceptionInformation(), "module Stop (private scratch destruction)")) { std::exit(3); }
}

// ---------------------------------------------------------------------------------------------------------------------
// Fixture description
// ---------------------------------------------------------------------------------------------------------------------
enum Vt : U { VtGenuine, VtRec, VtStage, VtClass };
enum Rec : U { RecAgent64 = 1, RecAgent70, RecPendAlive, RecNull14, RecSegment, RecHeight, RecStageCb, RecOwnerGet, RecPlane24,
               RecSub, RecAgent68, RecAgent6C, RecEvent, RecRing, RecStaging, RecClampHolder, RecClassHeading, RecClassMutate };
struct VRec { U id, recv, a, b; };
struct Spec {
    const char* name = "";
    float pos[3] = {20.0f, 1.0f, 24.0f};
    float disp[3] = {1.5f, 0.25f, -0.75f};     // +D4/+D8/+DC
    float push[4] = {0.25f, -0.125f, 0.5f, 0.25f}; // +70/+74/+78/+7C
    float v80 = 0.5f, v84 = -0.25f, c0 = 0.3f, c4 = 0.2f, mass = 2.0f, acc6c = 1.0f, radius = 0.75f, a4 = 1.0f;
    float v8c = 0.125f, v90 = 0.0625f, v94 = -0.25f, e4 = 0, e8 = 0, f12c = 0, f20 = 0.5f, target[3] = {0, 0, 0};
    U cd = 0, flags34 = 0x407, flags110 = 0, pending = 0, x1f0 = 0; // pending: 0 none, 1 alive, 2 dead (+EC==0)
    B a1 = 1, a3 = 1, b4 = 0, b5 = 0, d0 = 1, f0 = 0, ec = 1, active = 1, b116 = 0, b13d = 0, b18c = 0, f1 = 0, f2 = 0, f3 = 0;
    B owner = 0;   // 0 none; 1 plane P is the initial owner; 2 plane P is found in the obstacle grid and becomes owner
    B plane24 = 1; // owner virtual +24 result
    B group = 0, b66 = 0, sel = 0; // agent group object (+44), +66, 0 mover / 1 selector 62A290 / 2 class wrapper 5B2CA0
    B b628 = 0, b62c = 0;
    B unit = 0;    // nonzero: +1F0 names a read-only World::units[unit - 1] context, never a scheduling dependency
    B xform = 0;   // nonzero: +170 names World::xforms[xform - 1], a zeroed foreign +80..BC transform source (descriptor owner)
    U b688 = 0;
    uint16_t heading = 0x2000, e0 = 0;
    Vt vt = VtGenuine; U action = 0, arg = 0;
    // expectations that are properties of the case, not recomputed from the mover
    bool oob = false, rotation = false, f0Call = false;
    float fx = NAN, fz = NAN; // expected F0 clamp results
    bool clampHolder = false; // real 63D5B0 reaches holder virtual +44, whose nonzero result safely terminates the callback
    bool classMutate = false; // genuine 5B2CA0 child traversal mutates the later entity named by arg
    bool admitted = true;     // Classify must return Eligible (supported vtable, no pending/parked)
};
struct Scenario {
    std::vector<Spec> agents; std::vector<U> list;
    float mn[2] = {-10000, -10000}, mx[2] = {10000, 10000}, cmn[2] = {-10000, -10000}, cmx[2] = {10000, 10000};
    float height = 12.5f, seg[6] = {1, 2, 3, 4, 6, 8}, h1 = 3.0f, h2 = 3.0f;
    bool plane = false; // the obstacle grid holds the owner plane
};
static Scenario Move(const Spec& subject) {
    Scenario s; s.agents.push_back(subject); s.plane = subject.owner == 2;
    // Bystanders sharing the subject's grid cells: head order and unlink splice parity.
    const float offsets[3][2] = {{1.0f, 1.0f}, {-1.0f, 0.0f}, {3.0f, -2.0f}};
    for (U i = 0; i < 3; ++i) {
        Spec b = subject; b.name = "bystander"; b.pos[0] += offsets[i][0]; b.pos[2] += offsets[i][1];
        b.disp[0] = b.disp[1] = b.disp[2] = 0; b.a1 = 0; b.cd = 0; b.vt = VtGenuine; b.pending = subject.pending ? 1 : 0;
        b.f0 = 0; b.oob = false; b.action = 0; b.owner = 0; b.sel = 0; b.b628 = 0; b.b688 = 0; s.agents.push_back(b);
    }
    return s;
}

// Host data slots. Shared by every world; they only record calls.
struct World;
static World* cur;
static std::vector<VRec>* vlog;
static float g_height = 12.5f;
static B g_plane24 = 1, g_ringRet = 0;
static U g_vtRec[128], g_vtStage[128], g_hvt[4], g_pvt[4], g_qvt[32], g_svt[32], g_planeVt[64], g_subVt[4], g_evvt[4], g_ringVt[32];
static U g_clampHolderVt[18];
static U __fastcall ClampHolder(void* self, void*);
static U g_classChildVt[55];
static void* __fastcall ClassChildHeading(void* self, void*, void* out);
static void __fastcall ClassChildPose(void* self, void*, const void* pose, U flags);
static void __fastcall Agent64(void* self, void*) { vlog->push_back({RecAgent64, A(self), 0, 0}); }
static void __fastcall Agent68(void* self, void*) { vlog->push_back({RecAgent68, A(self), 0, 0}); }
static void __fastcall Agent6C(void* self, void*) { vlog->push_back({RecAgent6C, A(self), 0, 0}); }
static void __fastcall Agent70(void* self, void*) { vlog->push_back({RecAgent70, A(self), 0, 0}); }
static U __fastcall PendAlive(void* self, void*) { vlog->push_back({RecPendAlive, A(self), 0, 0}); return 1; }
static U __fastcall Null14(void* self, void*) { vlog->push_back({RecNull14, A(self), 0, 0}); return 0; }
// Polygon-ring vertex virtual +14: 6B7F50 finds no edge neighbours, so the owner gather (mode 8) asks each vertex; a nonzero
// answer for every vertex keeps the owner out of the candidate list, a zero answer (80F290 walk) lets the ring pass.
static U __fastcall RingVirt(void* self, void*) { vlog->push_back({RecRing, A(self), g_ringRet, 0}); return g_ringRet; }
static U __fastcall SubVirt(void* self, void*) { vlog->push_back({RecSub, A(self), 0, 0}); return 1; }
static U __fastcall Plane24(void* self, void*) { vlog->push_back({RecPlane24, A(self), g_plane24, 0}); return g_plane24; }
static U __fastcall OwnerGet(void* self, void*);
static float* __fastcall Segment(void* self, void*, float arg);
static float __fastcall HeightV(void* self, void*, void* arg) {
    vlog->push_back({RecHeight, A(self), Get<U>(arg, 0), Get<U>(arg, 4)}); return g_height;
}
static void __fastcall EventV(void* self, void*, void* arg) {
    vlog->push_back({RecEvent, A(self), Get<U>(arg, 4), Get<U>(arg, 8)});
}
static void __fastcall StageCb(void* self, void*);

struct Range { U base, size, id; };
struct Blob {
    std::vector<B> v; explicit Blob(size_t n) : v(n) {}
    B* p() { return v.data(); } const B* p() const { return v.data(); } U size() const { return U(v.size()); }
};
struct Agent { Blob b{0x700}; Blob nodes{256 * 0x1c}; };
struct TraceRec { U service, token; };
struct World {
    Scenario sc;
    Blob root{0x40}, model{0x100}, soft{0x40}, softCells{4096}, obs{0x40}, obsCells{4096}, terr{0x40}, terrTable{1100 * 8},
         hobj{0x20}, pend{0x40}, qo{0x20}, ro{0x20}, so{0x20}, mgr{0x300},
         plane{0x200}, ring{0x50}, o2{0x100}, grp{0x200}, group{0x20}, ev{0x1100}, node{0x20}, kd{0x80}, tree{0x40};
    std::vector<std::unique_ptr<Blob>> units, xforms;
    std::vector<std::unique_ptr<Agent>> agents;
    std::vector<U> list = std::vector<U>(kFixtureSlots);
    std::vector<Range> ranges;
    std::vector<VRec> log, discard;
    std::vector<TraceRec> trace;
    float seg[6];
    void Reg(const void* p, U size) { ranges.push_back({A(p), size, U(ranges.size() + 1)}); }
    U Token(U v) const {
        for (const Range& r : ranges) if (v >= r.base && v - r.base < r.size) return 0xC0000000u | (r.id << 16) | (v - r.base);
        return v;
    }
    explicit World(const Scenario& s);
    World(const World&) = delete; World& operator=(const World&) = delete;
};
static float* __fastcall Segment(void* self, void*, float arg) {
    vlog->push_back({RecSegment, A(self), Bits(arg), 0}); return cur->seg;
}
static U __fastcall OwnerGet(void* self, void*) {
    vlog->push_back({RecOwnerGet, A(self), 0, 0}); return A(cur->o2.p());
}

static void InitAgent(World& w, Agent& a, const Spec& s, U id) {
    B* p = a.b.p();
    U vt = A(At(0x1333714));
    if (s.vt == VtRec) vt = A(g_vtRec); else if (s.vt == VtStage) vt = A(g_vtStage); else if (s.vt == VtClass) vt = A(At(0x132ba04));
    Put(p, 0, vt); Put(p, 0x10, s.owner == 1 ? A(w.plane.p()) : U(0)); Put(p, 0x18, s.pending ? A(w.pend.p()) : U(0));
    Put(p, 0x20, s.f20); Put(p, 0x28, A(w.root.p())); Put(p, 0x2c, id); Put(p, 0x30, s.active);
    Put(p, 0x34, s.flags34); Put(p, 0x38, U(0xdeadbeef)); Put(p, 0x40, B(1)); Put(p, 0x44, s.group ? A(w.group.p()) : U(0));
    Put(p, 0x48, s.pos[0]); Put(p, 0x4c, s.pos[1]); Put(p, 0x50, s.pos[2]); Put(p, 0x54, 0.0f); Put(p, 0x58, s.radius);
    Put(p, 0x5c, B(0)); Put(p, 0x64, s.heading); Put(p, 0x66, s.b66); Put(p, 0x68, s.mass); Put(p, 0x6c, s.acc6c);
    for (U i = 0; i < 4; ++i) Put(p, 0x70 + 4 * i, s.push[i]);
    Put(p, 0x80, s.v80); Put(p, 0x84, s.v84); Put(p, 0x88, s.cd);
    Put(p, 0x8c, s.v8c); Put(p, 0x90, s.v90); Put(p, 0x94, s.v94); Put(p, 0x98, U(0x1234));
    Put(p, 0xa1, s.a1); Put(p, 0xa3, s.a3); Put(p, 0xa4, s.a4);
    Put(p, 0xa8, A(a.nodes.p())); Put(p, 0xac, U(0)); Put(p, 0xb0, U(256));
    Put(p, 0xb4, s.b4); Put(p, 0xb5, s.b5); Put(p, 0xb6, B(0));
    Put(p, 0xb8, 7.0f); Put(p, 0xbc, 8.0f); Put(p, 0xc0, s.c0); Put(p, 0xc4, s.c4); Put(p, 0xc8, 9.0f); Put(p, 0xcc, 10.0f);
    Put(p, 0xd0, s.d0); Put(p, 0xd4, s.disp[0]); Put(p, 0xd8, s.disp[1]); Put(p, 0xdc, s.disp[2]); Put(p, 0xe0, s.e0);
    Put(p, 0xe4, s.e4); Put(p, 0xe8, s.e8); Put(p, 0xec, s.pending == 2 ? B(0) : s.ec); Put(p, 0xf0, s.f0);
    Put(p, 0xf1, s.f1); Put(p, 0xf2, s.f2); Put(p, 0xf3, s.f3);
    Put(p, 0x110, s.flags110); Put(p, 0x116, s.b116); Put(p, 0x12c, s.f12c); Put(p, 0x13d, s.b13d);
    Put(p, 0x14c, 77.0f); Put(p, 0x150, 66.0f);
    for (U i = 0; i < 3; ++i) Put(p, 0x160 + 4 * i, s.target[i]);
    Put(p, 0x170, U(0)); Put(p, 0x174, uint16_t(0x0505)); Put(p, 0x176, B(5)); Put(p, 0x18c, s.b18c);
    Put(p, 0x190, 55.0f); Put(p, 0x194, 44.0f); Put(p, 0x199, B(1)); Put(p, 0x1a4, 0.5f);
    Put(p, 0x1b8, U(1)); Put(p, 0x1d8, U(4)); Put(p, 0x5ec, B(1)); Put(p, 0x5ed, B(0));
    Put(p, 0x628, U(s.b628)); Put(p, 0x62c, U(s.b62c)); Put(p, 0x688, s.b688);
    Put(p, 0x6f0, s.action); Put(p, 0x6f4, s.arg);
    if (s.clampHolder) { Put(p, 0x35b, B(1)); Put(p, 0x2d4, A(g_clampHolderVt)); }
    if (s.classMutate) {
        Put(p, 0x66c, U(1)); Put(p, 0x670, A(p + 0x6b0));
        Put(p, 0x6b0, A(p + 0x6a0)); Put(p, 0x6a0, A(g_classChildVt)); Put(p, 0x6a4, s.arg);
    }
    B* n = a.nodes.p();
    for (U i = 0; i < 256; ++i) {
        Put(n, 0x1c * i, U(1)); Put(n, 0x1c * i + 4, id); Put(n, 0x1c * i + 8, A(p + 0x30)); Put(n, 0x1c * i + 12, A(p));
    }
}

World::World(const Scenario& s) : sc(s) {
    cur = this; vlog = &discard; g_plane24 = sc.agents.empty() ? B(1) : sc.agents[0].plane24;
    g_ringRet = (!sc.agents.empty() && sc.agents[0].owner == 1) ? B(1) : B(0); ResetFp();
    std::copy(sc.seg, sc.seg + 6, seg);
    Put(root.p(), 8, A(model.p()));
    B* m = model.p();
    Put(m, 0x74, sc.mn[0]); Put(m, 0x78, sc.mn[1]); Put(m, 0x7c, sc.mx[0]); Put(m, 0x80, sc.mx[1]);
    Put(m, 0x84, sc.cmn[0]); Put(m, 0x88, sc.cmn[1]); Put(m, 0x8c, sc.cmx[0]); Put(m, 0x90, sc.cmx[1]);
    Put(m, 0x94, A(ev.p())); Put(m, 0x9c, A(terr.p())); Put(m, 0xa4, A(soft.p())); Put(m, 0xa8, A(obs.p())); Put(m, 0xc0, A(kd.p()));
    Put(m, 0xe0, A(hobj.p()));
    // Mode-2 tree query (809110): root node at [kd+4C] + 0xC. Bounds straddle every swept box, so the walk takes the partial
    // path (no items at +1C, no children at +20) and returns an empty candidate vector.
    Put(kd.p(), 0x4c, A(tree.p()));
    Put(tree.p(), 0x10, -1.0e9f); Put(tree.p(), 0x18, -1.0e9f); Put(tree.p(), 0x1c, 1.0e9f); Put(tree.p(), 0x24, 1.0e9f);
    // Soft grid (insertion) and obstacle grid (sweep): same real shape, cells base/shift/origin/clamp/scale.
    for (B* g : {soft.p(), obs.p()}) {
        Put(g, 8, U(5)); Put(g, 0x10, U(16)); Put(g, 0x14, U(31)); Put(g, 0x24, 0.25f);
    }
    Put(soft.p(), 0, A(softCells.p())); Put(obs.p(), 0, A(obsCells.p()));
    // Terrain sampled by the original 0x64C5F0 (first float of each 8-byte cell) and 0x679C50 (second float): constant planes
    // so bilinear weights sum to the exact expectation.
    B* t = terr.p();
    Put(t, 0, A(terrTable.p())); Put(t, 8, U(5)); Put(t, 0x10, U(16)); Put(t, 0x14, U(31));
    Put(t, 0x1c, 64.0f); Put(t, 0x20, 4.0f); Put(t, 0x24, 0.25f);
    for (U i = 0; i < 1100; ++i) { Put(terrTable.p(), 8 * i, sc.h1); Put(terrTable.p(), 8 * i + 4, sc.h2); }
    Put(hobj.p(), 0, A(g_hvt));
    Put(ev.p(), 0xfe0, A(g_evvt));
    Put(pend.p(), 0, A(g_pvt)); Put(pend.p(), 0x18, A(qo.p())); Put(pend.p(), 0x1c, A(ro.p())); Put(pend.p(), 0x24, A(so.p()));
    Put(qo.p(), 0, A(g_qvt)); Put(ro.p(), 0, A(g_qvt)); Put(so.p(), 0, A(g_svt));
    // Owner plane P: vtable (+C owner group, +24), polygon ring at +8, embedded sub-object vptr at +1C, member list head at
    // +28, id at +2C, plane a*x+... at +30/+34/+38/+3C: y = ((+38*z + +30*x) + +3C) * (-1 / +34) = 1.25.
    B* pl = plane.p();
    Put(pl, 0, A(g_planeVt)); Put(pl, 8, A(ring.p())); Put(pl, 0x1c, A(g_subVt)); Put(pl, 0x2c, uint16_t(0x1234));
    Put(pl, 0x30, 0.0f); Put(pl, 0x34, -1.0f); Put(pl, 0x38, 0.0f); Put(pl, 0x3c, 1.25f);
    Put(ring.p(), 0, A(g_ringVt)); Put(ring.p(), 8, A(ring.p())); // single-vertex ring: the point is never outside an edge
    Put(o2.p(), 0x80, A(grp.p()));
    Put(grp.p(), 0x1f0, sc.agents.empty() ? U(0) : sc.agents[0].x1f0); Put(grp.p(), 0x1f4, U(0x100000));
    Put(group.p(), 0x10, U(3));
    Put(node.p(), 0, U(0x40)); Put(node.p(), 4, U(1)); Put(node.p(), 0xc, A(pl));
    if (sc.plane) for (U i = 0; i < 1024; ++i) Put(obsCells.p(), 4 * i, A(node.p()));
    for (U i = 0; i < sc.agents.size(); ++i) {
        agents.push_back(std::make_unique<Agent>());
        InitAgent(*this, *agents[i], sc.agents[i], i);
    }
    // Unit context / foreign transform objects: zeroed, registered, referenced by A+1F0 / A+170 (never the +44 team).
    for (const Spec& s : sc.agents) {
        while (units.size() < s.unit) {
            // 62A620 -> 532320 reads an actual unit/order graph. The unit occupies 0xDC0 bytes; order and descriptor
            // are separate 0x20-byte regions in the same registered allocation. Empty embedded ability table at +DAC
            // (count +DB8/data +DBC) and order type 4 make the real read-only predicate return false.
            auto unit = std::make_unique<Blob>(0xe00);
            Put(unit->p(), 0x2c, A(unit->p() + 0xdc0));
            Put(unit->p(), 0x1f4, A(unit->p() + 0xde0));
            Put(unit->p(), 0xdc0 + 0x1c, U(4));
            units.push_back(std::move(unit));
        }
        while (xforms.size() < s.xform) xforms.push_back(std::make_unique<Blob>(0x100));
    }
    for (U i = 0; i < sc.agents.size(); ++i) {
        if (sc.agents[i].unit) Put(agents[i]->b.p(), 0x1f0, A(units[sc.agents[i].unit - 1]->p()));
        if (sc.agents[i].xform) Put(agents[i]->b.p(), 0x170, A(xforms[sc.agents[i].xform - 1]->p()));
    }
    for (auto& u : units) Reg(u->p(), u->size());
    for (auto& x : xforms) Reg(x->p(), x->size());
    Reg(root.p(), root.size()); Reg(model.p(), model.size()); Reg(soft.p(), soft.size()); Reg(softCells.p(), softCells.size());
    Reg(obs.p(), obs.size()); Reg(obsCells.p(), obsCells.size()); Reg(terr.p(), terr.size()); Reg(terrTable.p(), terrTable.size());
    Reg(hobj.p(), hobj.size()); Reg(pend.p(), pend.size()); Reg(qo.p(), qo.size()); Reg(ro.p(), ro.size()); Reg(so.p(), so.size());
    Reg(mgr.p(), mgr.size()); Reg(list.data(), U(list.size() * 4));
    Reg(plane.p(), plane.size()); Reg(ring.p(), ring.size()); Reg(o2.p(), o2.size()); Reg(grp.p(), grp.size());
    Reg(group.p(), group.size()); Reg(ev.p(), ev.size()); Reg(node.p(), node.size()); Reg(kd.p(), kd.size()); Reg(tree.p(), tree.size());
    for (auto& a : agents) { Reg(a->b.p(), a->b.size()); Reg(a->nodes.p(), a->nodes.size()); }
    // Genuine insertion by the original helpers, bystanders around the subject so it sits mid-chain.
    using Insert = void(__fastcall*)(void*);
    std::vector<U> order;
    for (U i : {1u, 2u, 0u, 3u}) if (i < agents.size()) order.push_back(i);
    for (U i = 4; i < agents.size(); ++i) order.push_back(i);
    for (U i : order) {
        ResetFp();
        if (sc.agents[i].pending || sc.agents[i].owner == 1) reinterpret_cast<Insert>(At(0x7efdd0))(agents[i]->b.p());
        reinterpret_cast<Insert>(At(0x7efa80))(agents[i]->b.p());
        Require(Get<U>(agents[i]->b.p(), 0xac) <= 256, "real insertion fits node capacity");
    }
    for (U i = 0; i < sc.list.size(); ++i) list[i] = A(agents[sc.list[i]]->b.p());
    Put(mgr.p(), 0x260, U(sc.list.size())); Put(mgr.p(), 0x264, A(list.data()));
}

static void __fastcall StageCb(void* self, void*) {
    World& w = *cur;
    const U id = Get<U>(self, 0x2c), count = Get<U>(w.mgr.p(), 0x260), base = Get<U>(w.mgr.p(), 0x264);
    w.log.push_back({RecStageCb, id, count, (base - A(w.list.data())) / 4});
    U* arr = reinterpret_cast<U*>(static_cast<uintptr_t>(base));
    const U act = Get<U>(self, 0x6f0), arg = Get<U>(self, 0x6f4);
    if (act == 1) { arr[count] = A(w.agents[arg]->b.p()); Put(w.mgr.p(), 0x260, count + 1); }
    else if (act == 2) Put(w.mgr.p(), 0x260, arg);
    else if (act == 3) { std::memmove(arr + arg, arr + arg + 1, (count - arg - 1) * 4); Put(w.mgr.p(), 0x260, count - 1); }
    else if (act == 4) Put(w.agents[arg]->b.p(), 0x30, B(0));
    else if (act == 5) { Put(w.mgr.p(), 0x264, base + 4); Put(w.mgr.p(), 0x260, count - 1); }
}
static void InstallHostSlots() {
    std::memcpy(g_vtRec, At(0x1333714), sizeof(g_vtRec));
    std::memcpy(g_vtStage, At(0x1333714), sizeof(g_vtStage));
    for (U* t : {g_vtRec, g_vtStage}) {
        t[0x64 / 4] = Fn(&Agent64); t[0x68 / 4] = Fn(&Agent68); t[0x6c / 4] = Fn(&Agent6C); t[0x70 / 4] = Fn(&Agent70);
    }
    g_vtStage[0x10 / 4] = Fn(&StageCb);
    g_hvt[2] = Fn(&HeightV); g_pvt[0] = Fn(&PendAlive); g_qvt[0x14 / 4] = Fn(&Null14); g_svt[0x2c / 4] = Fn(&Segment);
    g_ringVt[0x14 / 4] = Fn(&RingVirt);
    g_planeVt[0xc / 4] = Fn(&OwnerGet); g_planeVt[0x24 / 4] = Fn(&Plane24); g_subVt[0] = Fn(&SubVirt); g_evvt[2] = Fn(&EventV);
    for (U off : {0xcu, 0x14u, 0x24u, 0x28u}) g_clampHolderVt[off / 4] = A(At(0x461180));
    g_clampHolderVt[0x44 / 4] = Fn(&ClampHolder);
    g_classChildVt[0xd8 / 4] = Fn(&ClassChildHeading); g_classChildVt[1] = Fn(&ClassChildPose);
}

// ---------------------------------------------------------------------------------------------------------------------
// Canonical state: every word of every agent / node / cell / owner object with pointers replaced by (object, offset) tokens.
// ---------------------------------------------------------------------------------------------------------------------
static std::vector<U> Canon(const World& w) {
    std::vector<U> out;
    // A scalar can numerically fall inside any registered allocation (notably A+A0 == 0x01000100).
    // Normalize only ABI pointer slots; never infer a word's type from its value.
    auto words = [&](const B* p, U n, std::initializer_list<U> pointers) {
        for (U i = 0; i + 4 <= n; i += 4) {
            const U value = Get<U>(p, i);
            out.push_back(std::find(pointers.begin(), pointers.end(), i) != pointers.end() ? w.Token(value) : value);
        }
    };
    auto pointerWords = [&](const B* p, U n) {
        for (U i = 0; i + 4 <= n; i += 4) out.push_back(w.Token(Get<U>(p, i)));
    };
    for (const auto& a : w.agents) {
        words(a->b.p(), a->b.size(), {0, 4, 8, 0x10, 0x18, 0x28, 0x44, 0x98, 0xa8, 0x170, 0x1ec, 0x1f0, 0x2d4, 0x444, 0x670, 0x6a0, 0x6b0});
        for (U i = 0; i < 256; ++i) words(a->nodes.p() + i * 0x1c, 0x1c, {8, 0xc, 0x10, 0x14, 0x18});
    }
    pointerWords(w.softCells.p(), w.softCells.size()); pointerWords(w.obsCells.p(), w.obsCells.size());
    words(w.pend.p(), w.pend.size(), {0, 0xc, 0x18, 0x1c, 0x24});
    words(w.mgr.p(), w.mgr.size(), {0, 0x250, 0x264, 0x27c});
    words(w.plane.p(), w.plane.size(), {0, 8, 0x1c, 0x28});
    words(w.ring.p(), w.ring.size(), {0, 8}); words(w.o2.p(), w.o2.size(), {0x80});
    words(w.grp.p(), w.grp.size(), {}); words(w.node.p(), w.node.size(), {0xc});
    for (const auto& u : w.units) words(u->p(), u->size(), {0x2c, 0x1f4});
    for (const auto& x : w.xforms) words(x->p(), x->size(), {});
    pointerWords(reinterpret_cast<const B*>(w.list.data()), U(w.list.size() * 4));
    return out;
}
static void CanonicalScalarCase() {
    currentCase = "canonical scalar equal to a registered pointer";
    Spec s; World a(Move(s)), b(Move(s));
    const U scalar = A(a.agents[0]->nodes.p()) + 0x100;
    Put(a.agents[0]->b.p(), 0xa0, scalar); Put(b.agents[0]->b.p(), 0xa0, scalar);
    const auto ca = Canon(a), cb = Canon(b);
    Require(a.Token(scalar) != scalar, "scalar fixture deliberately aliases a registered range");
    Require(ca[0xa0 / 4] == scalar && cb[0xa0 / 4] == scalar, "canonicalizer preserves all scalar flag bits");
    Require(ca == cb, "only actual pointers are normalized across independently allocated graphs");
    ++cases;
}
static std::vector<U> CanonLog(const World& w) {
    std::vector<U> out;
    for (const VRec& r : w.log) {
        out.push_back(r.id); out.push_back(r.id == RecStageCb ? r.recv : w.Token(r.recv));
        out.push_back(r.a); out.push_back(r.b);
    }
    return out;
}
static void Same(const World& x, const World& y, const char* what) {
    const auto a = Canon(x), b = Canon(y);
    Require(a.size() == b.size(), "canonical state size");
    ++checks;
    for (size_t i = 0; i < a.size(); ++i) if (a[i] != b[i]) {
        U word = U(i), agent = 0xffffffffu, offset = 0, nodeIndex = 0;
        for (U k = 0; k < x.agents.size() && agent == 0xffffffffu; ++k) {
            const U bw = x.agents[k]->b.size() / 4, nw = x.agents[k]->nodes.size() / 4;
            if (word < bw) { agent = k; offset = word * 4; }
            else if (word < bw + nw) { agent = k; offset = 0xffff; nodeIndex = (word - bw) / 7; }
            else word -= bw + nw;
        }
        Fail("%s: canonical state differs at word %zu (agent %d +%X node %u): %08X vs %08X", what, i,
            static_cast<int>(agent), offset, nodeIndex, a[i], b[i]);
    }
}
static void SameLog(const World& x, const World& y, const char* what) {
    const auto a = CanonLog(x), b = CanonLog(y);
    ++checks;
    if (a != b) Fail("%s: virtual/data-slot call sequence differs (%zu vs %zu words)", what, a.size(), b.size());
}

// ---------------------------------------------------------------------------------------------------------------------
// Independent expectations (re-derived from the mover listing, not from the clone or module)
// ---------------------------------------------------------------------------------------------------------------------
struct Pred { float d[3]; bool moving, crowd; float c8, cc; };
static Pred Predict(const Spec& s) {
    const float k = KF(0x131a7b0), one = KF(0x1318048), thr = KF(0x1325d1c), c7 = KF(0x1325cdc), big = KF(0x1325d20);
    Pred p{}; float d4 = s.disp[0], d8 = s.disp[1], dz = s.disp[2];
    p.c8 = KF(0x150fca0); p.cc = KF(0x150fca4);
    if (s.cd && s.ec == 1 && s.pending != 2) { p.c8 = s.v80 - s.c0; p.cc = s.v84 - s.c4; }
    if (s.a1) {
        if (s.b4 == 0) {
            const float x70 = s.push[0], z74 = s.push[1];
            dz = z74 * k + dz; d4 = x70 * k + d4;
            const float sq = z74 * z74 + x70 * x70;
            if (sq > 0.0f) {
                const float m1 = std::sqrt(sq);
                if (m1 > 0.0f) {
                    const float m2 = std::sqrt(s.push[2] * s.push[2] + s.push[3] * s.push[3]);
                    const float r = m2 * (one / m1);
                    if (r > thr) {
                        if (s.d0 == 1) {
                            const float q = thr / r, k2 = q > k ? q : k;
                            d4 = k2 * d4; dz = dz * k2;
                        }
                        p.crowd = true; p.c8 = KF(0x150fca0); p.cc = KF(0x150fca4);
                    }
                }
            }
            const float u = s.acc6c * k;
            const float t2 = u * p.cc * c7, t1 = u * p.c8 * c7;
            dz = dz + t2; d4 = t1 + d4;
        } else if (s.b5 == 0) {
            // Mode 7 (B4 set, B5 clear): the previous tick's velocity feeds the displacement.
            const float t1 = s.v90 - KF(0x133bbf8);
            d4 = s.v8c * k + d4; dz = s.v94 * k + dz; d8 = d8 + t1 * k;
        }
        if (s.rotation) { p.moving = true; return p; } // rotation fix uses x87 FSINCOS: only parity/tail are asserted
        p.moving = (d4 * d4 + d8 * d8 + dz * dz) > 0.0f;
        if (p.moving) {
            const float dd = d4 * d4 + dz * dz;
            if (dd > big) { float f = one / std::sqrt(dd); f = f + f; d4 *= f; d8 *= f; dz *= f; }
        }
    }
    p.d[0] = d4; p.d[1] = d8; p.d[2] = dz;
    return p;
}
// Final state of the environment transitions reached through 0x81AE40.
struct Out { bool ev, v6c, v68, ownerFinal; U b4, b5; };
static Out Outcome(const Scenario& sc, const Spec& s, const Pred& pr) {
    Out o{}; o.b4 = s.b4; o.b5 = s.b5;
    if (!s.a1) return o;
    if (s.pending == 2) o.b4 = 1;
    if (s.owner == 1) o.ownerFinal = true;
    if (s.owner == 2 && !s.oob && !s.pending) o.ownerFinal = true;
    if (!s.oob && !s.pending && s.b4 && s.b5 == 0 && !s.owner) {
        const float y81 = pr.moving ? s.pos[1] + pr.d[1] : s.pos[1], h1 = sc.h1, h2 = sc.h2;
        bool flag = false;
        if (h2 > h1 && !(h2 < y81)) {
            const float t = y81 - pr.d[1]; flag = true;
            if (t > h2) o.ev = true;
        }
        const float ext = 1.0f * s.a4;
        if (flag && h2 > ext * KF(0x1325ce0) + h1) { o.v6c = true; o.b5 = 1; }
        else if (!(h1 < y81)) { o.v68 = true; o.b4 = 0; }
    }
    return o;
}
static bool WrapperBranch(const Spec& s, bool wrapperArg) {
    if (!s.sel) return wrapperArg;
    return s.ec == 1 || (s.b628 && s.b62c == 4);
}
static std::vector<U> ExpectedServices(const Spec& s, const Pred& p, bool wrapper) {
    std::vector<U> v;
    if (s.a1) {
        v.push_back(loco::UnlinkGrid); v.push_back(loco::UnlinkOwner);
        if (p.moving) { v.push_back(loco::Sweep); if (!s.pending) v.push_back(loco::Resolve); }
        if (!s.oob) {
            if (!s.pending) v.push_back(loco::HeightOwner);
            v.push_back(loco::InsertOwner); v.push_back(loco::InsertGrid);
        }
    }
    if (wrapper && s.pending != 1 && !s.b13d && !s.b18c) v.push_back(loco::WrapperQuery);
    return v;
}
static std::vector<U> ExpectedVirtuals(const Spec& s, const Pred& pr, const Out& o, bool wrapper) {
    std::vector<U> v;
    if (s.a1) {
        if (s.b4 == 0 && s.owner == 1) v.push_back(RecOwnerGet);          // mode 0xD probe
        if (s.owner == 1) v.push_back(RecSub);                            // moving test on the owner sub-object
        if (s.owner == 1 && pr.moving) v.push_back(RecRing);              // mode-8 owner gather: one vertex query, no candidate
        if (s.owner == 2) { v.push_back(RecSub); v.push_back(RecRing); }  // sweep candidate predicate(s), then 80F290 ring walk
        if (s.f0Call) v.push_back(RecAgent70);
        if (!s.oob && !s.pending) {
            if (s.owner == 1) v.push_back(RecSub);                        // 81AE40 owner arm
            if (s.owner == 2) v.push_back(RecPlane24);                    // 81AE40 plane candidate
            if (s.b4 && s.b5 == 0 && !s.owner) {
                if (o.ev) v.push_back(RecEvent);
                v.push_back(o.v6c ? RecAgent6C : RecAgent68);
                if (!o.v6c && !o.v68) v.pop_back();
            }
            if (o.b4 && o.b5 == 1 && !o.ownerFinal) v.push_back(RecHeight);
        }
        if (s.pending == 1) { v.push_back(RecPendAlive); v.push_back(RecNull14); v.push_back(RecNull14); }
        if (s.pending == 2) v.push_back(RecAgent64);
        if (o.ownerFinal && !s.oob) v.push_back(RecOwnerGet);             // 7EFDD0 owner arm
        if (o.ownerFinal) { v.push_back(RecPlane24); v.push_back(RecOwnerGet); } // tail flag masks
    }
    if (wrapper && s.pending == 1) v.push_back(RecSegment);
    return v;
}
static void Eq(const char* what, float actual, float expected) {
    ++checks;
    if (std::isnan(actual) && std::isnan(expected)) return;
    if (Bits(actual) != Bits(expected)) Fail("%s: %.9g (%08X) != expected %.9g (%08X)", what, actual, Bits(actual), expected, Bits(expected));
}
static void EqU(const char* what, U actual, U expected) {
    ++checks; if (actual != expected) Fail("%s: %08X != expected %08X", what, actual, expected);
}
static void CheckSemantics(const World& w, const Spec& s, const Pred& pr, const Out& o, bool wrapper) {
    const B* p = w.agents[0]->b.p();
    const float c60 = KF(0x1318060);
    const float t = s.mass * c60, c0 = s.disp[0] * t, c4 = s.disp[2] * t;
    if (!s.a1) EqU("phase A +34->+38 copy", Get<U>(p, 0x38), s.flags34);
    Eq("phase A +54 extent = virtual +74 (1.0) * +A4", Get<float>(p, 0x54), 1.0f * s.a4);
    Eq("phase A +C0", Get<float>(p, 0xc0), c0); Eq("phase A +C4", Get<float>(p, 0xc4), c4);
    Eq("phase A +80", Get<float>(p, 0x80), c0); Eq("phase A +84", Get<float>(p, 0x84), c4);
    EqU("countdown +88", Get<U>(p, 0x88), s.cd ? s.cd - 1 : 0);
    if (!pr.crowd) { Eq("history +B8", Get<float>(p, 0xb8), s.v80); Eq("history +BC", Get<float>(p, 0xbc), s.v84); }
    else { Eq("crowd +B8", Get<float>(p, 0xb8), KF(0x150fca0)); Eq("crowd +BC", Get<float>(p, 0xbc), KF(0x150fca4)); }
    Eq("accel +C8", Get<float>(p, 0xc8), pr.c8); Eq("accel +CC", Get<float>(p, 0xcc), pr.cc);
    if (!s.a1) {
        // Early return after phase A: nothing else may change.
        Eq("inactive x", Get<float>(p, 0x48), s.pos[0]); Eq("inactive y", Get<float>(p, 0x4c), s.pos[1]);
        Eq("inactive z", Get<float>(p, 0x50), s.pos[2]);
        Eq("inactive +D4", Get<float>(p, 0xd4), s.disp[0]); Eq("inactive +DC", Get<float>(p, 0xdc), s.disp[2]);
        for (U i = 0; i < 4; ++i) Eq("inactive push preserved", Get<float>(p, 0x70 + 4 * i), s.push[i]);
        EqU("inactive +64", Get<uint16_t>(p, 0x64), s.heading);
        EqU("inactive +A3", Get<B>(p, 0xa3), s.a3);
    } else {
        for (U i = 0; i < 4; ++i) Eq("tail clears +70..+7C", Get<float>(p, 0x70 + 4 * i), 0.0f);
        EqU("tail +40", Get<B>(p, 0x40), 0); EqU("tail +D0", Get<B>(p, 0xd0), 1); EqU("tail +F0", Get<B>(p, 0xf0), 0);
        EqU("tail +F1", Get<uint16_t>(p, 0xf1), 0); EqU("tail +F3", Get<B>(p, 0xf3), 0);
        EqU("tail +D4", Get<U>(p, 0xd4), Get<U>(At(0x150fca8), 0)); EqU("tail +D8", Get<U>(p, 0xd8), Get<U>(At(0x150fca8), 4));
        EqU("tail +DC", Get<U>(p, 0xdc), Get<U>(At(0x150fcb0), 0));
        EqU("tail +E0", Get<uint16_t>(p, 0xe0), Get<uint16_t>(At(0x150fb24), 0));
        EqU("tail +E4", Get<U>(p, 0xe4), Get<U>(At(0x150fca0), 0)); EqU("tail +E8", Get<U>(p, 0xe8), Get<U>(At(0x150fca4), 0));
        EqU("heading += +E0", Get<uint16_t>(p, 0x64), uint16_t(s.heading + s.e0));
        EqU("bounds +A3", Get<B>(p, 0xa3), s.oob ? 0 : s.a3);
        EqU("final +B4", Get<B>(p, 0xb4), o.b4); EqU("final +B5", Get<B>(p, 0xb5), o.b5);
        EqU("owner +10", Get<U>(p, 0x10), o.ownerFinal ? A(w.plane.p()) : 0);
        EqU("owner group handle +98", Get<U>(p, 0x98), (o.ownerFinal && !s.oob) ? A(w.grp.p()) : 0);
        if (o.ownerFinal && !s.oob) {
            const U bit = (s.group ? 3u : 8u) + (s.b66 == 1 ? 9u : 0u);
            Require((Get<U>(w.grp.p(), 0x1f4) >> bit & 1) != 0, "814950 sets the group bit in the owner group mask");
        }
        if (pr.crowd) EqU("crowd latch +B6", Get<B>(p, 0xb6), 1);
        // Collision-flag masks (+38).
        U mask = s.flags34;
        if (o.ownerFinal) {
            if (!s.plane24 && !(s.flags34 & 0x40)) mask &= ~1u;
            bool al = true;
            if (s.group) al = (s.x1f0 & ~((1u << 12) + (1u << 3))) != 0; // 80DBF0 with group index 3
            if (!al) mask &= ~2u;
        } else if (s.pending == 1) mask &= ~3u; // pending stays after a live call
        if (o.b5 == 1) mask &= ~3u;
        if (s.f1 == 1) mask &= ~1u; if (s.f2 == 1) mask &= ~2u; if (s.f3 == 1) mask &= ~4u;
        EqU("collision-flag masks +38", Get<U>(p, 0x38), mask);
        if (pr.crowd) { /* B6 asserted above */ }
        if (!s.rotation) {
            Eq("+8C = D4*[1318060]", Get<float>(p, 0x8c), pr.d[0] * c60);
            Eq("+90 = D8*[1318060]", Get<float>(p, 0x90), pr.d[1] * c60);
            Eq("+94 = DC*[1318060]", Get<float>(p, 0x94), pr.d[2] * c60);
            float x = s.pos[0], y = s.pos[1], z = s.pos[2];
            if (pr.moving) { x += pr.d[0]; y += pr.d[1]; z += pr.d[2]; }
            if (!std::isnan(s.fx)) x = s.fx;
            if (!std::isnan(s.fz)) z = s.fz;
            Eq("integrated x", Get<float>(p, 0x48), x); Eq("integrated z", Get<float>(p, 0x50), z);
            ++checks;
            const float actualY = Get<float>(p, 0x4c);
            if (s.oob || s.pending) Eq("integrated y", actualY, y);
            else if (o.ownerFinal) Eq("owner plane y", actualY, ((0.0f * z + 0.0f * x) + 1.25f) * (KF(0x1318068) / -1.0f));
            else if (o.b4 == 0) { if (std::fabs(actualY - w.sc.h1) > 1e-5f) Fail("terrain height %.9g != %.9g", actualY, w.sc.h1); }
            else if (o.b5 == 1) Eq("height object y", actualY, w.sc.height - KF(0x1318038));
            else Eq("integrated y", actualY, y);
        }
    }
    if (!wrapper) return;
    // Wrapper post arithmetic.
    const float vx = Get<float>(p, 0x8c), vy = Get<float>(p, 0x90), vz = Get<float>(p, 0x94);
    const uint16_t h = Get<uint16_t>(p, 0x64), oldH = s.heading;
    const uint16_t dh = uint16_t(h - oldH);
    const int delta16 = dh == 0x8000 ? 0x8000 : static_cast<int16_t>(dh);
    Eq("wrapper heading delta +150", Get<float>(p, 0x150), static_cast<float>(delta16) * KF(0x1349564));
    EqU("wrapper +174", Get<uint16_t>(p, 0x174), 0); EqU("wrapper +176", Get<B>(p, 0x176), 0);
    EqU("wrapper +199", Get<B>(p, 0x199), 0); Eq("wrapper +1A4", Get<float>(p, 0x1a4), 1.0f);
    Eq("wrapper +190 = old +194", Get<float>(p, 0x190), 44.0f); EqU("wrapper +18C", Get<B>(p, 0x18c), 0);
    const float hx = Get<float>(At(0x176cff8), 8 * U(h)), hz = Get<float>(At(0x176cff8), 8 * U(h) + 4);
    float v194 = NAN, v14c = NAN; bool known = true;
    if (s.pending == 1) {
        const float* e = w.seg; const float ex = e[3] - e[0], ey = e[4] - e[1], ez = e[5] - e[2];
        const float sum = ex * ex + ey * ey + ez * ez;
        if (sum > 0.0f) {
            const float n = KF(0x1318048) / std::sqrt(sum), ny = n * ey, nx = n * ex, nz = n * ez;
            float r = vy * ny; r = r + vx * nx; r = r + vz * nz; v194 = v14c = r;
        } else { float r = vx * vx + vy * vy; r = r + vz * vz; v194 = v14c = std::sqrt(r); }
    } else if (s.b13d) v194 = v14c = s.f12c;
    else if (s.b18c) { v194 = std::sqrt(vz * vz + vx * vx); v14c = hz * vz + hx * vx; }
    else if ((s.flags110 & 0x40) || s.b116 == 1) known = false; // 814AA0 true: FPATAN arm is asserted by parity only
    else { v14c = v194 = hz * vz + hx * vx; }
    if (known) {
        Eq("wrapper +194 (clamped >0)", Get<float>(p, 0x194), v194 > 0.0f ? v194 : 0.0f);
        Eq("wrapper +14C (clamped >0)", Get<float>(p, 0x14c), v14c > 0.0f ? v14c : 0.0f);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------------------------------------
static void FpOk() {
    unsigned short cw, sw;
    __asm fnstcw word ptr [cw]
    __asm fnstsw word ptr [sw]
    Require(cw == 0x27f, "x87 control word preserved");
    Require(((sw >> 11) & 7) == 0, "x87 stack balanced");
    Require((_mm_getcsr() & 0xffc0) == 0x1f80, "MXCSR control bits preserved");
}
using ServiceWords = std::array<U, loco::ServiceWordCount>;
static ServiceWords Services() {
    ServiceWords words{};
    loco::SampleServices(words.data());
    return words;
}
static void CheckServices(const ServiceWords& words, bool enabled) {
    EqU("service timing version", words[loco::TimingVersion], 1);
    EqU("service timing enabled", words[loco::TimingEnabled], enabled ? 1u : 0u);
    for (U i : {10u, 11u, 36u, 37u, 38u, 39u}) EqU("reserved service timing word", words[i], 0);
    EqU("bounded fixture has no timing overflow", words[loco::TimingOverflows], 0);
    EqU("normal return abandons no service frame", words[loco::TimingAbandoned], 0);
    EqU("QPC succeeds in mapped oracle", words[loco::TimingQpcFailures], 0);
    uint64_t inclusive = 0, calls = 0;
    for (U i = 0; i < loco::ServiceCount; ++i) {
        inclusive += words[loco::TimingServiceUs + i];
        calls += words[loco::TimingServiceCalls + i];
        Require(words[loco::TimingServiceMaxUs + i] <= words[loco::TimingServiceUs + i],
            "service maximum does not exceed inclusive total");
    }
    Require(calls == words[loco::TimingCalls], "eight service call counters sum to timing calls");
    Require(words[loco::TimingCloneWallUs] >= words[loco::TimingUnionUs], "clone wall contains service union");
    EqU("outside is the published wall minus union", words[loco::TimingOutsideUs],
        words[loco::TimingCloneWallUs] - words[loco::TimingUnionUs]);
    // These mapped fixtures do not recursively enter a tapped service. Conversion
    // floors eight independently accumulated tick totals, not each individual call.
    Require(inclusive <= words[loco::TimingUnionUs] &&
        words[loco::TimingUnionUs] - inclusive < loco::ServiceCount,
        "non-nested inclusive totals equal union within aggregate conversion rounding");
    EqU("non-nested service depth", words[loco::TimingMaxDepth], calls ? 1u : 0u);
    if (!enabled)
        for (U i = loco::TimingCalls; i < loco::ServiceWordCount; ++i)
            EqU("observe-only accumulates no service timing", words[i], 0);
}
static void CheckServiceReset(bool enabled) {
    const auto words = Services();
    CheckServices(words, enabled);
    for (U i = loco::TimingCalls; i < loco::ServiceWordCount; ++i)
        EqU("Start clears every timing counter", words[i], 0);
}
static void CheckServiceDelta(const ServiceWords& before, const ServiceWords& after,
                              const U* censusBefore, const U* censusAfter) {
    CheckServices(after, true);
    EqU("timed calls match service census delta", after[loco::TimingCalls] - before[loco::TimingCalls],
        censusAfter[loco::ServiceCalls] - censusBefore[loco::ServiceCalls]);
    U traceCount = 0;
    const auto* trace = loco::ServiceTrace(&traceCount);
    std::array<U, loco::ServiceCount> traced{};
    for (U i = 0; i < traceCount; ++i) {
        Require(trace[i].service < loco::ServiceCount, "trace service index is valid");
        ++traced[trace[i].service];
    }
    for (U i = 0; i < loco::ServiceCount; ++i) {
        const U count = after[loco::TimingServiceCalls + i] - before[loco::TimingServiceCalls + i];
        EqU("individual timed calls match census delta", count,
            censusAfter[loco::ServiceUnlinkGrid + i] - censusBefore[loco::ServiceUnlinkGrid + i]);
        // Stage resets the bounded trace for each occurrence; it is a suffix of
        // the stage-wide census, whereas Run exposes its entire service sequence.
        Require(count >= traced[i], "timing census contains the last occurrence trace");
    }
}
static std::array<U, 16> ImageScratch() {
    std::array<U, 16> r{}; U n = 0;
    for (U i = 0; i < 5; ++i) r[n++] = Get<U>(At(0x14543b4), 4 * i);
    for (U i = 0; i < 4; ++i) r[n++] = Get<U>(At(0x15a1888), 4 * i);
    for (U i = 0; i < 4; ++i) r[n++] = Get<U>(At(0x15a189c), 4 * i);
    r[n++] = Get<U>(At(0x15a1884), 0); r[n++] = Get<U>(At(0x15a1898), 0); r[n++] = Get<U>(At(0x15a18ac), 0);
    return r;
}
static U PrivateWord(U binding, U index) { return Get<U>(reinterpret_cast<const void*>(static_cast<uintptr_t>(privateBindings[binding])), 4 * index); }
// mode 0 untouched original, 1 tapped-original-global clone family, 2 module-owned (private scratch)
static void Exec(World& w, int mode, bool wrapper) {
    cur = &w; vlog = &w.log; w.log.clear(); w.trace.clear(); g_height = w.sc.height; g_plane24 = w.sc.agents[0].plane24;
    g_ringRet = w.sc.agents[0].owner == 1 ? B(1) : B(0); ResetFp();
    loco::ResetServiceTrace();
    void* agent = w.agents[0]->b.p();
    const B sel = w.sc.agents[0].sel;
    if (sel == 0) {
        if (mode == 0) CallEntry(A(At(wrapper ? 0x7f0260 : 0x7f08f0)), agent, "original mover");
        else if (mode == 1) CallEntry(globalClones.entries[wrapper ? NTW2_CLONE_LOCO_WRAP : NTW2_CLONE_LOCO_MOVE], agent, "tapped-global clone");
        else CallRun(agent, wrapper);
    } else {
        const U original = sel == 1 ? 0x62a290 : 0x5b2ca0;
        const U clone = sel == 1 ? NTW2_CLONE_LOCO_SELECT : NTW2_CLONE_LOCO_CLASS_WRAP;
        if (mode == 0) CallEntry(A(At(original)), agent, sel == 1 ? "original selector 62A290" : "original class wrapper 5B2CA0");
        else if (mode == 1) CallEntry(globalClones.entries[clone], agent, "tapped-global selector/class clone");
        else CallEntry(privateClones.entries[clone], agent, "private selector/class clone");
    }
    FpOk();
    U n = 0; const loco::ServiceRecord* t = loco::ServiceTrace(&n);
    if (mode == 0) Require(n == 0, "untouched original bytes never reach a service tap");
    Require(n < 256, "service trace is bounded");
    for (U i = 0; i < n; ++i) w.trace.push_back({t[i].service, w.Token(t[i].receiver)});
}
static void CheckTrace(const World& w, const std::vector<U>& expected, const char* what) {
    ++checks;
    bool ok = w.trace.size() == expected.size();
    for (size_t i = 0; ok && i < expected.size(); ++i) {
        const U receiver = A(w.agents[0]->b.p()) + (expected[i] == loco::WrapperQuery ? 0xF4u : 0u);
        ok = w.trace[i].service == expected[i] && w.trace[i].token == w.Token(receiver);
    }
    if (ok) return;
    std::fprintf(stderr, "%s trace:", what);
    for (const TraceRec& r : w.trace) std::fprintf(stderr, " %u", r.service);
    std::fprintf(stderr, " | expected:"); for (U s : expected) std::fprintf(stderr, " %u", s);
    std::fputc('\n', stderr);
    Fail("%s: owner-service sequence differs from the recovered mover order", what);
}
// Plane candidate predicates repeat once per swept cell: consecutive RecSub entries collapse for owner==2 cases only.
static std::vector<U> Ids(const World& w, bool collapse) {
    std::vector<U> v;
    for (const VRec& r : w.log) {
        if (collapse && r.id == RecSub && !v.empty() && v.back() == RecSub) continue;
        v.push_back(r.id);
    }
    return v;
}
static void RunMove(const Scenario& sc, bool wrapperArg) {
    static char label[160];
    const Spec& s = sc.agents[0];
    const char* kind = s.sel == 1 ? "selector" : s.sel == 2 ? "class-wrapper" : (wrapperArg ? "wrapper" : "direct");
    std::snprintf(label, sizeof(label), "%s/%s", s.name, kind); currentCase = label;
    World a(sc), b(sc), c(sc);
    Same(a, b, "identical pre-run graphs"); Same(a, c, "identical pre-run graphs");
    const Pred pr = Predict(s);
    const Out out = Outcome(sc, s, pr);
    const bool branch = WrapperBranch(s, wrapperArg);
    // Admission on the module, before anything runs: no mutation, expected verdict.
    const auto beforeClassify = Canon(c);
    const U reason = loco::Classify(c.agents[0]->b.p());
    Require(Canon(c) == beforeClassify, "Classify mutates nothing");
    const bool supportedVt = s.vt == VtGenuine || s.vt == VtClass;
    if (s.admitted && supportedVt && !s.pending && !s.b628) EqU("Classify admits the real state", reason, loco::Eligible);
    else Require(reason != loco::Eligible, "Classify refuses unsupported state");
    Exec(a, 0, wrapperArg);
    if (s.a1) {
        EqU("original scratch count 14543C0 reset", Get<U>(At(0x14543c0), 0), 0);
        EqU("original scratch count 15A1890 reset", Get<U>(At(0x15a1890), 0), 0);
        EqU("original scratch count 15A18A4 reset", Get<U>(At(0x15a18a4), 0), 0);
    }
    Exec(b, 1, wrapperArg);
    const auto scratchBefore = ImageScratch();
    U censusBefore[loco::WordCount], censusAfter[loco::WordCount];
    loco::Sample(censusBefore);
    const auto timingBefore = Services();
    Exec(c, 2, wrapperArg);
    const auto timingAfter = Services();
    loco::Sample(censusAfter);
    if (!s.sel) CheckServiceDelta(timingBefore, timingAfter, censusBefore, censusAfter);
    Require(ImageScratch() == scratchBefore, "module run never touches the original scratch globals or guards");
    if (s.a1) {
        EqU("private count 14543B4+C reset", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 3), 0);
        EqU("private count 15A1888+8 reset", PrivateWord(NTW2_BIND_LOCO_SCRATCH_15A1888, 2), 0);
        EqU("private count 15A189C+8 reset", PrivateWord(NTW2_BIND_LOCO_SCRATCH_15A189C, 2), 0);
    }
    if (s.owner == 2 && s.a1) {
        Require(PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 2) >= 1 && PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4) != 0,
            "private scratch grew its backing store through the native allocator");
        Require(std::find(g_allocs.begin(), g_allocs.end(), PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4)) != g_allocs.end(),
            "private scratch backing came from the allocator seam");
        Require(PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4) != Get<U>(At(0x14543b4), 16), "private and original backing stores are distinct");
    }
    const auto services = ExpectedServices(s, pr, branch);
    CheckTrace(b, services, "tapped original-global clone"); CheckTrace(c, services, "module-owned clone");
    const auto virtuals = ExpectedVirtuals(s, pr, out, branch);
    for (const World* w : {&a, &b, &c}) {
        ++checks;
        const auto ids = Ids(*w, s.owner == 2);
        if (ids != virtuals) {
            std::fprintf(stderr, "virtuals:"); for (U i : ids) std::fprintf(stderr, " %u", i);
            std::fprintf(stderr, " | expected:"); for (U i : virtuals) std::fprintf(stderr, " %u", i);
            std::fputc('\n', stderr);
            Fail("data-slot virtual call sequence differs from the recovered mover");
        }
    }
    Same(a, b, "original vs tapped original-global clone"); Same(a, c, "original vs module-owned clone");
    if (s.owner != 2) { SameLog(a, b, "original vs tapped clone"); SameLog(a, c, "original vs module clone"); }
    CheckSemantics(a, s, pr, out, branch); CheckSemantics(c, s, pr, out, branch);
    if (s.sel) {
        for (const World* w : {&a, &b, &c}) {
            EqU("selector latch +5ED = old +5EC", Get<B>(w->agents[0]->b.p(), 0x5ed), 1);
            EqU("selector latch +5EC cleared", Get<B>(w->agents[0]->b.p(), 0x5ec), 0);
            if (s.sel == 2) EqU("class wrapper pre-step state +688", Get<U>(w->agents[0]->b.p(), 0x688), s.ec == 0 ? 0 : s.b688);
        }
    }
    ++cases;
}
static void Run(const Scenario& sc) { for (bool wrapper : {false, true}) RunMove(sc, wrapper); }
static void Run1(const Scenario& sc) { RunMove(sc, false); }

static void MoveCases() {
    Spec s; s.name = "basic"; Run(Move(s));
    s = Spec(); s.name = "non-candidate-vtable"; s.vt = VtRec; Run(Move(s));
    s = Spec(); s.name = "accel-countdown"; s.cd = 3; Run(Move(s));
    s = Spec(); s.name = "countdown-ec0"; s.cd = 2; s.ec = 0; Run(Move(s));
    s = Spec(); s.name = "crowd-clamp"; s.push[0] = 0.1f; s.push[1] = 0.05f; s.push[2] = 3.0f; s.push[3] = 4.0f; Run(Move(s));
    s.name = "crowd-clamp-disabled"; s.d0 = 0; Run(Move(s));
    s = Spec(); s.name = "displacement-clamp"; s.disp[0] = 10; s.disp[1] = 1; s.disp[2] = 8;
    for (float& v : s.push) v = 0; Run(Move(s));
    s = Spec(); s.name = "not-moving"; for (float& v : s.disp) v = 0; for (float& v : s.push) v = 0; Run(Move(s));
    s = Spec(); s.name = "inactive-a1"; s.a1 = 0; Run(Move(s));
    s = Spec(); s.name = "b4b5-2"; s.b4 = 1; s.b5 = 2; Run(Move(s));
    s = Spec(); s.name = "b4b5-1-height-object"; s.b4 = 1; s.b5 = 1; Run(Move(s));
    s = Spec(); s.name = "out-of-bounds"; s.oob = true; { Scenario sc = Move(s); sc.mx[0] = 20.5f; Run(sc); }
    s = Spec(); s.name = "f0-clamp-x"; s.f0 = 1; s.vt = VtRec; s.f0Call = true; s.fx = 30.0f;
    { Scenario sc = Move(s); sc.cmn[0] = 30.0f; Run(sc); }
    s = Spec(); s.name = "f0-clamp-z"; s.f0 = 1; s.vt = VtRec; s.f0Call = true; s.fz = 20.0f;
    { Scenario sc = Move(s); sc.cmx[1] = 20.0f; Run(sc); }
    s = Spec(); s.name = "f0-inside"; s.f0 = 1; s.vt = VtRec; Run(Move(s));
    s = Spec(); s.name = "heading-8000"; s.heading = 0x1000; s.e0 = 0x8000; Run(Move(s));
    s = Spec(); s.name = "heading-negative"; s.heading = 0x4000; s.e0 = 0xF000; Run(Move(s));
    s = Spec(); s.name = "rotation-offset"; s.e4 = 0.5f; s.e8 = -0.25f; s.e0 = 0x2000; s.rotation = true; Run(Move(s));
    s.name = "rotation-offset-8000"; s.e0 = 0x8000; s.heading = 0x8000; Run(Move(s));
    s.name = "rotation-offset-negative"; s.e0 = 0xF000; s.heading = 0x0800; Run(Move(s));
    s = Spec(); s.name = "nan-displacement"; s.disp[0] = NAN; Run(Move(s));
    s = Spec(); s.name = "wrapper-13d"; s.b13d = 1; s.f12c = 2.5f; Run(Move(s));
    s.name = "wrapper-13d-negative-clamps-to-zero"; s.f12c = -1.0f; Run(Move(s));
    s = Spec(); s.name = "wrapper-18c-sqrt"; s.b18c = 1; Run(Move(s));
    s = Spec(); s.name = "wrapper-814aa0-true-target"; s.b116 = 1; s.target[0] = 40.0f; s.target[1] = 0.0f; s.target[2] = 10.0f; Run(Move(s));
    s.name = "wrapper-814aa0-true-same-position"; s.target[0] = 21.5f; s.target[2] = 23.25f; Run(Move(s));
    s = Spec(); s.name = "wrapper-814aa0-flag-40"; s.flags110 = 0x40; s.target[0] = 5.0f; s.target[2] = 5.0f; Run(Move(s));
    s = Spec(); s.name = "pending-alive"; s.pending = 1; Run(Move(s));
    s.name = "pending-alive-zero-segment"; { Scenario sc = Move(s); for (U i = 0; i < 6; ++i) sc.seg[i] = 2.0f; Run(sc); }
    s = Spec(); s.name = "pending-dead"; s.pending = 2; s.vt = VtRec; Run(Move(s));
    s = Spec(); s.name = "grid-clamp-high"; s.pos[0] = 120.0f; Run(Move(s));
    s = Spec(); s.name = "grid-clamp-negative"; s.pos[0] = -100.0f; Run(Move(s));
    s = Spec(); s.name = "wide-footprint"; s.radius = 6.0f; Run(Move(s));
    s = Spec(); s.name = "a3-already-clear"; s.a3 = 0; Run(Move(s));
    // Mode 7 (B4 set, B5 clear): 81AE40 ground contact tests against the real 0x64C5F0/0x679C50 samplers.
    s = Spec(); s.name = "mode7-lands"; s.b4 = 1; s.vt = VtRec; Run(Move(s));
    s = Spec(); s.name = "mode7-airborne"; s.b4 = 1; s.vt = VtRec; s.pos[1] = 10.0f; Run(Move(s));
    s = Spec(); s.name = "mode7-event-and-b5"; s.b4 = 1; s.vt = VtRec; s.pos[1] = 6.0f; s.disp[1] = -2.0f;
    { Scenario sc = Move(s); sc.h1 = 1.0f; sc.h2 = 5.0f; Run(sc); }
    s = Spec(); s.name = "mode7-event-no-b5"; s.b4 = 1; s.vt = VtRec; s.pos[1] = 6.0f; s.disp[1] = -2.0f;
    { Scenario sc = Move(s); sc.h1 = 4.9f; sc.h2 = 5.0f; Run(sc); }
    // Owner plane: ground/owner transitions through the real 811D50 / 7EFDD0 owner arms and the 10E73F0 ring test.
    s = Spec(); s.name = "owner-plane-inside"; s.owner = 1; Run(Move(s));
    s.name = "owner-plane24-false"; s.plane24 = 0; Run(Move(s));
    s = Spec(); s.name = "owner-group-clears-bit1"; s.owner = 1; s.group = 1; s.x1f0 = 0; Run(Move(s));
    s.name = "owner-group-keeps-bit1"; s.x1f0 = 0x40; Run(Move(s));
    s.name = "owner-group-b66"; s.b66 = 1; Run(Move(s));
    s = Spec(); s.name = "owner-plane-not-moving"; s.owner = 1; for (float& v : s.disp) v = 0; for (float& v : s.push) v = 0; Run(Move(s));
    s = Spec(); s.name = "owner-plane-out-of-bounds"; s.owner = 1; s.oob = true; { Scenario sc = Move(s); sc.mx[0] = 20.5f; Run(sc); }
    s = Spec(); s.name = "plane-candidate-becomes-owner"; s.owner = 2; Run(Move(s));
    s.name = "plane-candidate-group"; s.group = 1; s.x1f0 = 0; Run(Move(s));
    s = Spec(); s.name = "plane-candidate-out-of-bounds"; s.owner = 2; s.oob = true; { Scenario sc = Move(s); sc.mx[0] = 20.5f; Run(sc); }
    // Selector 0x62A290 and class wrapper 0x5B2CA0 (empty subordinate list) against their emitted clones.
    s = Spec(); s.name = "selector-battle-branch"; s.sel = 1; s.ec = 1; Run1(Move(s));
    s = Spec(); s.name = "selector-direct-branch"; s.sel = 1; s.ec = 0; Run1(Move(s));
    s = Spec(); s.name = "selector-alternate-wrapper-branch"; s.sel = 1; s.ec = 0; s.b628 = 1; s.b62c = 4; Run1(Move(s));
    s = Spec(); s.name = "selector-parked-other-direct"; s.sel = 1; s.ec = 0; s.b628 = 1; s.b62c = 3; Run1(Move(s));
    s = Spec(); s.name = "selector-owner-plane"; s.sel = 1; s.owner = 1; Run1(Move(s));
    s = Spec(); s.name = "class-wrapper-battle"; s.sel = 2; s.vt = VtClass; s.ec = 1; Run1(Move(s));
    s = Spec(); s.name = "class-wrapper-direct"; s.sel = 2; s.vt = VtClass; s.ec = 0; Run1(Move(s));
    s = Spec(); s.name = "class-wrapper-pre-step"; s.sel = 2; s.vt = VtClass; s.ec = 0; s.b688 = 2; Run1(Move(s));
    s = Spec(); s.name = "class-wrapper-inactive-a1"; s.sel = 2; s.vt = VtClass; s.ec = 1; s.a1 = 0; Run1(Move(s));
}

// ---------------------------------------------------------------------------------------------------------------------
// Admission verdicts on real graphs
// ---------------------------------------------------------------------------------------------------------------------
static void ClassifyOne(const char* name, U expected, void (*mutate)(World&, Agent&)) {
    currentCase = name;
    Spec s; s.name = name; Scenario sc = Move(s); World w(sc);
    Agent& a = *w.agents[0];
    mutate(w, a);
    const auto before = Canon(w);
    EqU(name, loco::Classify(a.b.p()), expected);
    Require(Canon(w) == before, "Classify mutates nothing");
}
static void ClassifyCases() {
    currentCase = "classify";
    EqU("null entity", loco::Classify(nullptr), loco::Lifetime);
    ClassifyOne("baseline eligible", loco::Eligible, [](World&, Agent&) {});
    ClassifyOne("non-candidate vtable", loco::Class, [](World&, Agent& a) { Put(a.b.p(), 0, A(g_vtRec)); });
    ClassifyOne("class wrapper table 132BA04", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0, A(At(0x132ba04))); });
    ClassifyOne("model pointer absent", loco::Lifetime, [](World& w, Agent&) { Put(w.root.p(), 8, U(0)); });
    ClassifyOne("root pointer absent", loco::Lifetime, [](World&, Agent& a) { Put(a.b.p(), 0x28, U(0)); });
    ClassifyOne("activity 8", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(8)); });
    ClassifyOne("activity 0", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0)); });
    ClassifyOne("activity 23", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0x23)); });
    ClassifyOne("activity 0C", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0x0c)); });
    ClassifyOne("activity 9 order 4", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(9)); });
    ClassifyOne("activity 9 order 5", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(9)); Put(a.b.p(), 0x1d8, U(5)); });
    ClassifyOne("activity 1 order 3C (serial MOVE only)", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1d8, U(0x3c)); });
    ClassifyOne("target reference +1EC", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x1ec, U(1)); });
    ClassifyOne("parked +628", loco::Parked, [](World&, Agent& a) { Put(a.b.p(), 0x628, U(1)); });
    ClassifyOne("pending +18", loco::Pending, [](World& w, Agent& a) { Put(a.b.p(), 0x18, A(w.pend.p())); });
    ClassifyOne("charge +4E8", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x4e8, U(1)); });
    ClassifyOne("fire +390", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x390, U(1)); });
    ClassifyOne("fire-active +390 state 6", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x390, U(6)); });
    ClassifyOne("fire-active +390 state 7", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x390, U(7)); });
    ClassifyOne("fire +3BC", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x3bc, U(1)); });
    ClassifyOne("fire +3C8", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x3c8, U(1)); });
    ClassifyOne("posture +220", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x220, U(1)); });
    ClassifyOne("reference node of foreign type", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x2c4, B(1)); });
    ClassifyOne("watcher holder with unknown table", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x2cc + 0x8f, B(1)); });
    ClassifyOne("second watcher holder with unknown table", loco::Eligible, [](World&, Agent& a) { Put(a.b.p(), 0x51c + 0x8f, B(1)); });
    ClassifyOne("active without node storage", loco::Environment, [](World&, Agent& a) { Put(a.b.p(), 0xa8, U(0)); });
    ClassifyOne("node count above capacity", loco::Environment, [](World&, Agent& a) { Put(a.b.p(), 0xac, U(257)); });
    ClassifyOne("zero node capacity", loco::Environment, [](World&, Agent& a) { Put(a.b.p(), 0xb0, U(0)); });
    ClassifyOne("model without soft grid", loco::Environment, [](World& w, Agent&) { Put(w.model.p(), 0xa4, U(0)); });
    ClassifyOne("model without obstacle grid", loco::Environment, [](World& w, Agent&) { Put(w.model.p(), 0xa8, U(0)); });
    ClassifyOne("inactive A1 needs no node storage", loco::Eligible, [](World& w, Agent& a) {
        Put(a.b.p(), 0xa1, B(0)); Put(a.b.p(), 0xa8, U(0)); Put(w.model.p(), 0xa4, U(0)); });
    ClassifyOne("owner plane present", loco::Eligible, [](World& w, Agent& a) { Put(a.b.p(), 0x10, A(w.plane.p())); });
    // Slot-run activity 0x1D: real row/backing decode.
    static std::array<U, 4> row; static std::array<B, 0x100> backing;
    Put(backing.data(), 0x50, U(10));
    row = {0x20, A(backing.data()), 0, 0};
    ClassifyOne("activity 1D live row", loco::Eligible, [](World&, Agent& a) {
        Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(0)); Put(a.b.p(), 0x444, A(row.data())); Put(a.b.p(), 0x1c0, U(3)); });
    ClassifyOne("activity 1D underlying order 4", loco::Eligible, [](World&, Agent& a) {
        Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(4)); Put(a.b.p(), 0x444, A(row.data())); Put(a.b.p(), 0x1c0, U(3)); });
    ClassifyOne("activity 1D other order", loco::Eligible, [](World&, Agent& a) {
        Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(0x3d)); Put(a.b.p(), 0x444, A(row.data())); Put(a.b.p(), 0x1c0, U(3)); });
    ClassifyOne("activity 1D exhausted frame", loco::Eligible, [](World&, Agent& a) {
        Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(0)); Put(a.b.p(), 0x444, A(row.data())); Put(a.b.p(), 0x1c0, U(10)); });
    ClassifyOne("activity 1D without row", loco::Eligible, [](World&, Agent& a) {
        Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(0)); });
    ClassifyOne("activity 1D foreign continuation animation", loco::Eligible, [](World&, Agent& a) {
        row[0] = 0x5d; Put(a.b.p(), 0x1b8, U(0x1d)); Put(a.b.p(), 0x1d8, U(0)); Put(a.b.p(), 0x444, A(row.data())); Put(a.b.p(), 0x1c0, U(3)); });
    row[0] = 0x20;
}

// ---------------------------------------------------------------------------------------------------------------------
// Stage traversal against the original 0x531AF0 loop
// ---------------------------------------------------------------------------------------------------------------------
struct StageExp {
    U entities, filtered, admitted, rejected, wrapperBattle, direct, end, classWrapper;
    std::vector<VRec> log;
};
static Spec Genuine(U index, B ec, B active = 1) {
    Spec g; g.name = "stage-genuine"; g.pos[0] = 10.0f + 4.0f * index; g.pos[2] = 12.0f + 2.0f * index; g.ec = ec; g.active = active;
    g.disp[0] = 0.5f; g.disp[1] = 0.0f; g.disp[2] = 0.25f; g.a1 = 1;
    return g;
}
static Spec Callback(U index, U action, U arg) {
    Spec c = Genuine(index, 1); c.name = "stage-callback"; c.vt = VtStage; c.action = action; c.arg = arg;
    return c;
}
static Spec ClassAgent(U index, B ec) { Spec c = Genuine(index, ec); c.name = "stage-class-wrapper"; c.vt = VtClass; return c; }
static void RunStage(const char* name, const std::vector<Spec>& agents, const std::vector<U>& list, const StageExp& e) {
    currentCase = name;
    Scenario sc; sc.agents = agents; sc.list = list;
    World a(sc), b(sc);
    Same(a, b, "identical pre-run stage graphs");
    cur = &a; vlog = &a.log; ResetFp();
    const U endA = CallStageOriginal(a.mgr.p()); FpOk();
    U before[loco::WordCount], after[loco::WordCount];
    U gatesBefore[loco::GateWordCount], gatesAfter[loco::GateWordCount];
    loco::SampleGates(gatesBefore);
    loco::Sample(before);
    const auto timingBefore = Services();
    cur = &b; vlog = &b.log; ResetFp(); loco::ResetServiceTrace();
    const U endB = CallStageModule(b.mgr.p()); FpOk();
    loco::Sample(after);
    loco::SampleGates(gatesAfter);
    CheckServiceDelta(timingBefore, Services(), before, after);
    EqU("original loop returns final end pointer", endA - A(a.list.data()), e.end);
    EqU("module Stage returns final end pointer", endB - A(b.list.data()), e.end);
    Same(a, b, "original stage loop vs module Stage");
    SameLog(a, b, "stage callback order");
    ++checks;
    bool ok = a.log.size() == e.log.size();
    for (size_t i = 0; ok && i < e.log.size(); ++i)
        ok = a.log[i].id == e.log[i].id && a.log[i].recv == e.log[i].recv && a.log[i].a == e.log[i].a && a.log[i].b == e.log[i].b;
    if (!ok) Fail("callback sequence/count/base differs from the native absolute-cursor reload semantics (%zu vs %zu)", a.log.size(), e.log.size());
    auto d = [&](loco::Word w) { return after[w] - before[w]; };
    EqU("Stage calls", d(loco::Calls), 1);
    EqU("Stage entities (active occurrences)", d(loco::Entities), e.entities);
    EqU("Stage filtered (A+30 != 1)", d(loco::Filtered), e.filtered);
    EqU("Stage admitted", d(loco::Admitted), e.admitted);
    EqU("Stage rejected", d(loco::Rejected), e.rejected);
    EqU("Stage class rejections", d(loco::RejectClass), e.rejected);
    EqU("Stage cloned executions", d(loco::Cloned), e.admitted);
    EqU("Stage native executions", d(loco::Native), e.rejected);
    EqU("Stage wrapper-battle selector branch", d(loco::WrapperBattle), e.wrapperBattle);
    EqU("Stage direct selector branch", d(loco::Direct), e.direct);
    EqU("Stage class-wrapper table occurrences", d(loco::ClassWrapper), e.classWrapper);
    EqU("Stage staging (no out-of-bounds occurrence)", d(loco::Staging), 0);
    Require(d(loco::ServiceCalls) >= 2 * e.admitted, "admitted active occurrences reached owner services");
    Require(after[loco::Version] == 1 && after[loco::Generation] != 0 && after[loco::CloneEnabled] == 1, "status header");
    auto g = [&](loco::GateWord w) { return gatesAfter[w] - gatesBefore[w]; };
    EqU("all-gates active occurrences", g(loco::GateEntities), e.entities);
    EqU("all-gates candidate occurrences", g(loco::GateCandidates), e.admitted);
    EqU("all-gates admitted occurrences", g(loco::GateAdmitted), e.admitted);
    EqU("all-gates class failures", g(loco::GateClass), e.rejected);
    EqU("unknown classes remain unclassified", g(loco::GateUnclassified), e.rejected);
    EqU("unknown classes avoid soldier diagnostic reads", g(loco::GateDiagnosticFaults), 0);
    EqU("gate status version", gatesAfter[loco::GateVersion], 1);
    EqU("exact enforced MOVE mask", gatesAfter[loco::GateEnforcedMask], 0x233);
    for (loco::Word w : {loco::RejectActivity, loco::RejectTarget, loco::RejectChargeFire, loco::RejectPostureOrder, loco::RejectNode})
        EqU("removed first-fail bucket stays zero", after[w], 0);
    ++cases;
}
static void StageCases() {
    {   // append within capacity, erase-shift behind the cursor, duplicate occurrence, filtered entry
        std::vector<Spec> a = {Genuine(0, 1), Genuine(1, 1, 0), Callback(2, 1, 6), Genuine(3, 0), Callback(4, 3, 1),
                               Callback(5, 2, 1), Genuine(6, 0)};
        RunStage("stage append/erase-shift/duplicate/filter", a, {0, 1, 2, 0, 3, 4, 5},
            {6, 1, 4, 2, 2, 2, 28, 0, {{RecStageCb, 2, 7, 0}, {RecStageCb, 4, 8, 0}}});
    }
    {   // callback truncates the list: end is reloaded, remaining entries are never visited
        std::vector<Spec> a = {Callback(0, 2, 2), Genuine(1, 1), Genuine(2, 1), Genuine(3, 0)};
        RunStage("stage truncation reloads end", a, {0, 1, 2, 3}, {2, 0, 1, 1, 1, 0, 8, 0, {{RecStageCb, 0, 4, 0}}});
    }
    {   // callback moves the base up and shrinks the count: the absolute cursor continues, end is unchanged
        std::vector<Spec> a = {Callback(0, 5, 0), Genuine(1, 1), Genuine(2, 0)};
        RunStage("stage base reload", a, {0, 1, 2}, {3, 0, 2, 1, 1, 1, 12, 0, {{RecStageCb, 0, 3, 0}}});
    }
    {   // a callback deactivates a later entry before its visit: the active byte is tested at the visit
        std::vector<Spec> a = {Callback(0, 4, 2), Genuine(1, 1), Genuine(2, 1)};
        RunStage("stage activity tested at visit", a, {0, 1, 2}, {2, 1, 1, 1, 1, 0, 12, 0, {{RecStageCb, 0, 3, 0}}});
    }
    {   // duplicates of the same genuine entity: the second occurrence sees the first one's results
        std::vector<Spec> a = {Genuine(0, 1), Genuine(1, 0)};
        RunStage("stage duplicate genuine occurrences", a, {0, 0, 0, 1, 1}, {5, 0, 5, 0, 3, 2, 20, 0, {}});
    }
    {   // the class wrapper table is routed to the emitted class wrapper, the others to the emitted selector
        std::vector<Spec> a = {Genuine(0, 1), ClassAgent(1, 0), Genuine(2, 0)};
        RunStage("stage class wrapper routing", a, {0, 1, 2}, {3, 0, 3, 0, 1, 2, 12, 1, {}});
    }
    {   // all filtered / empty list
        std::vector<Spec> a = {Genuine(0, 1, 0)};
        RunStage("stage all filtered", a, {0, 0, 0}, {0, 3, 0, 0, 0, 0, 12, 0, {}});
        RunStage("stage empty list", a, {}, {0, 0, 0, 0, 0, 0, 0, 0, {}});
    }
}

struct OwnerHandoff {
    void* manager;
    U end = 0;
};
static DWORD WINAPI HandoffStage(void* context) {
    auto& handoff = *static_cast<OwnerHandoff*>(context);
    handoff.end = CallStageModule(handoff.manager);
    return 0;
}
static void OwnerHandoffCases() {
    // Runtime Epoch authorizes each tick's serial owner; a quiescent module must
    // not permanently pin the first thread. No active entries means no image TLS
    // or original entity methods are needed on the temporary host thread.
    for (U filtered = 0; filtered != 2; ++filtered) {
        currentCase = filtered ? "quiescent owner handoff filtered list" : "quiescent owner handoff empty list";
        Scenario sc; sc.agents = {Genuine(0, 0, 0)};
        if (filtered) sc.list = {0};
        World w(sc);
        U before[loco::WordCount], after[loco::WordCount];
        loco::Sample(before);
        const auto timingBefore = Services();
        const U expectedEnd = A(w.list.data()) + filtered * sizeof(U);
        EqU("first owner Stage completes", CallStageModule(w.mgr.p()), expectedEnd);
        loco::Sample(after);
        EqU("first owner thread recorded", after[loco::OwnerThread], GetCurrentThreadId());
        OwnerHandoff handoff{w.mgr.p()};
        DWORD threadId = 0;
        HANDLE thread = CreateThread(nullptr, 0, &HandoffStage, &handoff, 0, &threadId);
        Require(thread != nullptr, "owner handoff host thread created");
        Require(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, "owner handoff host thread joined");
        Require(CloseHandle(thread) != 0, "owner handoff thread handle closed");
        EqU("handoff owner Stage completes", handoff.end, expectedEnd);
        loco::Sample(after);
        EqU("handoff owner thread recorded", after[loco::OwnerThread], threadId);
        EqU("handoff executes Stage instead of refusing", after[loco::Calls] - before[loco::Calls], 2);
        EqU("returning owner Stage completes", CallStageModule(w.mgr.p()), expectedEnd);
        loco::Sample(after);
        EqU("returning owner thread recorded", after[loco::OwnerThread], GetCurrentThreadId());
        EqU("all three quiescent owner calls execute", after[loco::Calls] - before[loco::Calls], 3);
        EqU("quiescent owner changes are not reentry", after[loco::ReentryRefusals] - before[loco::ReentryRefusals], 0);
        EqU("handoff retains active-entry filter", after[loco::Filtered] - before[loco::Filtered], 3 * filtered);
        EqU("handoff has no active entities", after[loco::Entities] - before[loco::Entities], 0);
        Require(Services() == timingBefore, "empty/filtered owner handoff leaves service timing unchanged");
        ++cases;
    }
}

// Diagnostic fixtures use the real direct selector and inactive A1 mover path.
// Their graph/layout stays valid for the original call: pending is a real object,
// +62C stays zero (parked must not select the alternate wrapper), and A3 stays one.
// This isolates admission/telemetry without invoking unrelated node/holder methods.
static void RunGateStage(const char* name, void (*mutate)(World&, Agent&),
                         const std::vector<loco::GateWord>& nonzero, U reason = loco::Eligible) {
    currentCase = name;
    Spec s = Genuine(0, 0); s.a1 = 0;
    Scenario sc; sc.agents = {s}; sc.list = {0};
    World a(sc), b(sc);
    mutate(a, *a.agents[0]); mutate(b, *b.agents[0]);
    Same(a, b, "identical pre-run diagnostic graphs");
    const auto beforeClassify = Canon(b);
    EqU("diagnostic fixture admission", loco::Classify(b.agents[0]->b.p()), reason);
    Require(Canon(b) == beforeClassify, "diagnostic Classify mutates nothing");
    U before[loco::WordCount], after[loco::WordCount];
    U gatesBefore[loco::GateWordCount], gatesAfter[loco::GateWordCount];
    loco::Sample(before); loco::SampleGates(gatesBefore);
    cur = &a; vlog = &a.log; ResetFp();
    const U endA = CallStageOriginal(a.mgr.p()); FpOk();
    cur = &b; vlog = &b.log; ResetFp(); loco::ResetServiceTrace();
    const U endB = CallStageModule(b.mgr.p()); FpOk();
    loco::Sample(after); loco::SampleGates(gatesAfter);
    EqU("diagnostic original loop end", endA - A(a.list.data()), 4);
    EqU("diagnostic module loop end", endB - A(b.list.data()), 4);
    Same(a, b, "original vs module diagnostic stage graph");
    SameLog(a, b, "original vs module diagnostic stage callbacks");
    const U admitted = reason == loco::Eligible ? 1u : 0u;
    EqU("diagnostic Stage calls", after[loco::Calls] - before[loco::Calls], 1);
    EqU("diagnostic Stage entities", after[loco::Entities] - before[loco::Entities], 1);
    EqU("diagnostic Stage admitted", after[loco::Admitted] - before[loco::Admitted], admitted);
    EqU("diagnostic Stage rejected", after[loco::Rejected] - before[loco::Rejected], 1 - admitted);
    EqU("diagnostic clone dispatch", after[loco::Cloned] - before[loco::Cloned], admitted);
    EqU("diagnostic native dispatch", after[loco::Native] - before[loco::Native], 1 - admitted);
    for (U r = loco::Class; r <= loco::Environment; ++r)
        EqU("exact first-fail histogram", after[loco::RejectClass + r - 1] - before[loco::RejectClass + r - 1], reason == r ? 1u : 0u);
    for (loco::Word w : {loco::RejectActivity, loco::RejectTarget, loco::RejectChargeFire, loco::RejectPostureOrder, loco::RejectNode})
        EqU("removed first-fail bucket remains ABI-visible zero", after[w], 0);
    std::array<U, loco::GateWordCount> expected{};
    expected[loco::GateEntities] = 1;
    expected[loco::GateCandidates] = 1;
    expected[loco::GateAdmitted] = admitted;
    for (loco::GateWord w : nonzero) ++expected[w];
    EqU("diagnostic gate version", gatesAfter[loco::GateVersion], 1);
    EqU("diagnostic exact enforced mask", gatesAfter[loco::GateEnforcedMask], 0x233);
    for (U i = 1; i < loco::GateWordCount; ++i) {
        if (i == loco::GateEnforcedMask) continue;
        ++checks;
        const U actual = gatesAfter[i] - gatesBefore[i];
        if (actual != expected[i]) Fail("all-gates word %u: got %u expected %u", i, actual, expected[i]);
    }
    ++cases;
}
static void GateStageCases() {
    RunGateStage("legacy eligible diagnostic baseline", [](World&, Agent&) {},
        {loco::GateActivity1, loco::GateLegacyAdmitted});
    RunGateStage("activity 0 diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0)); },
        {loco::GateActivity, loco::GateActivity0, loco::GateNewlyAdmitted});
    RunGateStage("activity 23 diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0x23)); },
        {loco::GateActivity, loco::GateActivity23, loco::GateNewlyAdmitted});
    RunGateStage("activity 0C diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0x0c)); },
        {loco::GateActivity, loco::GateActivity0C, loco::GateNewlyAdmitted});
    RunGateStage("activity other diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(8)); },
        {loco::GateActivity, loco::GateActivityOther, loco::GateNewlyAdmitted});
    RunGateStage("activity 9 legacy admitted", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(9)); },
        {loco::GateActivity9, loco::GateLegacyAdmitted});
    RunGateStage("fire-active 6 diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x390, U(6)); },
        {loco::GateActivity1, loco::GateChargeFire, loco::GateFire390, loco::GateNewlyAdmitted});
    RunGateStage("fire-active 7 diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x390, U(7)); },
        {loco::GateActivity1, loco::GateChargeFire, loco::GateFire390, loco::GateNewlyAdmitted});
    RunGateStage("nonreference node diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x2c4, B(1)); },
        {loco::GateActivity1, loco::GateNode, loco::GateReferenceNode, loco::GateNewlyAdmitted});
    RunGateStage("overlapping removed gates all counted", [](World& w, Agent& a) {
        B* p = a.b.p();
        Put(p, 0x1ec, A(w.pend.p()));
        Put(p, 0x4e8, U(1)); Put(p, 0x390, U(7)); Put(p, 0x3bc, U(1)); Put(p, 0x3c8, U(1));
        Put(p, 0x220, U(1)); Put(p, 0x1d8, U(0x3c)); Put(p, 0x2c4, B(1));
        Put(p, 0x2cc + 0x8f, B(1)); Put(p, 0x51c + 0x8f, B(1));
        Put(p, 0x618, B(1)); Put(p, 0x619, B(1)); Put(p, 0xf1, B(1));
    }, {loco::GateActivity1, loco::GateTarget, loco::GateChargeFire, loco::GatePostureOrder, loco::GateNode,
        loco::GateCharge4E8, loco::GateFire390, loco::GateFire3BC, loco::GateFire3C8, loco::GatePosture220, loco::GateOrder,
        loco::GateReferenceNode, loco::GateHolder2CC, loco::GateHolder51C,
        loco::GateLatch618, loco::GateLatch619, loco::GateLatchF1, loco::GateLatch5AB, loco::GateNewlyAdmitted});
    RunGateStage("parked first-fail does not hide pending or diagnostics", [](World& w, Agent& a) {
        B* p = a.b.p();
        Put(p, 0x628, U(1)); Put(p, 0x18, A(w.pend.p()));
        Put(p, 0x390, U(6)); Put(p, 0x3bc, U(1)); Put(p, 0x3c8, U(1)); Put(p, 0x4e8, U(1));
        Put(p, 0x220, U(1)); Put(p, 0x1d8, U(5)); Put(p, 0x2c4, B(1));
    }, {loco::GateActivity1, loco::GateParked, loco::GatePending, loco::GateChargeFire, loco::GatePostureOrder, loco::GateNode,
        loco::GateFire390, loco::GateFire3BC, loco::GateFire3C8, loco::GateCharge4E8,
        loco::GatePosture220, loco::GateOrder, loco::GateReferenceNode}, loco::Parked);
    RunGateStage("slot-run missing row diagnostic only", [](World&, Agent& a) { Put(a.b.p(), 0x1b8, U(0x1d)); },
        {loco::GateActivity1D, loco::GateNode, loco::GateSlotRow, loco::GateNewlyAdmitted});
    RunGateStage("latch618 is independent", [](World&, Agent& a) { Put(a.b.p(), 0x618, B(2)); },
        {loco::GateActivity1, loco::GateLatch618, loco::GateLegacyAdmitted});
    RunGateStage("latch619 is independent of latch618", [](World&, Agent& a) { Put(a.b.p(), 0x619, B(2)); },
        {loco::GateActivity1, loco::GateLatch619, loco::GateLegacyAdmitted});
    RunGateStage("latchF1 is independent", [](World&, Agent& a) { Put(a.b.p(), 0xf1, B(2)); },
        {loco::GateActivity1, loco::GateLatchF1, loco::GateLegacyAdmitted});
    RunGateStage("latch5AB nonzero is not holder-active equality", [](World&, Agent& a) { Put(a.b.p(), 0x5ab, B(2)); },
        {loco::GateActivity1, loco::GateLatch5AB, loco::GateLegacyAdmitted});
    RunGateStage("byte latches ignore neighboring high bytes", [](World&, Agent& a) {
        Put(a.b.p(), 0x61a, B(1)); Put(a.b.p(), 0xf2, B(1)); Put(a.b.p(), 0x5ac, B(1));
    }, {loco::GateActivity1, loco::GateLegacyAdmitted});
}

// ---------------------------------------------------------------------------------------------------------------------
// Private scratch lifecycle: backing grown through the real allocator is destroyed by the real FF7EF0 at Stop.
// ---------------------------------------------------------------------------------------------------------------------
static loco::Binding MakeBinding() {
    loco::Binding binding{};
    binding.image_delta = delta; binding.use_clone = true;
    binding.wrap_clone = privateClones.entries[NTW2_CLONE_LOCO_WRAP]; binding.move_clone = privateClones.entries[NTW2_CLONE_LOCO_MOVE];
    binding.selector_clone = privateClones.entries[NTW2_CLONE_LOCO_SELECT];
    binding.class_wrap_clone = privateClones.entries[NTW2_CLONE_LOCO_CLASS_WRAP];
    binding.clone_bytes = privateClones.allocation_bytes;
    return binding;
}

// ---------------------------------------------------------------------------------------------------------------------
// Owned-grid public seam. Every expected membership comes from the untouched native insertion helper's nodes/head slots,
// not a second implementation of its floating-point cell conversion. Registry storage is synthetic native engine data.
// ---------------------------------------------------------------------------------------------------------------------
struct GridRegistry {
    World& world;
    std::array<U, kFixtureSlots> primary{}, secondary{};
    std::vector<U> records;
    explicit GridRegistry(World& w) : world(w) {
        w.Reg(primary.data(), U(sizeof(primary))); w.Reg(secondary.data(), U(sizeof(secondary)));
        Put(w.mgr.p(), 0, A(w.root.p()));
        Put(w.mgr.p(), 0x250, A(primary.data())); Put(w.mgr.p(), 0x27c, A(secondary.data()));
        for (U i = 0; i < w.agents.size(); ++i) Serial(i, 0x10001u + i * 0x10000u);
    }
    void Serial(U index, U serial) {
        Agent& a = *world.agents[index];
        Put(a.b.p(), 0x2c, serial);
        for (U n = 0; n < 256; ++n) {
            Put(a.nodes.p(), n * 0x1c, U(8)); Put(a.nodes.p(), n * 0x1c + 4, serial);
        }
    }
    void Set(const std::vector<U>& p, const std::vector<U>& s) {
        Require(p.size() <= primary.size() && s.size() <= secondary.size(), "fixture registries fit");
        primary.fill(0); secondary.fill(0); records.clear();
        auto copy = [&](const std::vector<U>& ids, std::array<U, kFixtureSlots>& dst, bool isPrimary) {
            for (U i = 0; i < ids.size(); ++i) {
                if (ids[i] == UINT32_MAX) { if (isPrimary) records.push_back(0); continue; }
                Require(ids[i] < world.agents.size(), "fixture registry index");
                const U ptr = A(world.agents[ids[i]]->b.p()); dst[i] = ptr;
                if (isPrimary || std::find(records.begin(), records.end(), ptr) == records.end()) records.push_back(ptr);
            }
        };
        copy(p, primary, true); copy(s, secondary, false);
        Put(world.mgr.p(), 0x24c, U(p.size())); Put(world.mgr.p(), 0x278, U(s.size()));
    }
};
static void NativeGridCall(Agent& a, bool insert) {
    CallEntry(A(At(insert ? 0x7efa80 : 0x811ed0)), a.b.p(), insert ? "native grid insertion" : "native grid removal");
    Require(Get<U>(a.b.p(), 0xac) <= 256, "native grid fixture node capacity");
}
static std::array<U, loco::GridWordCount> GridStatus() {
    std::array<U, loco::GridWordCount> words{}; loco::SampleGrid(words.data()); return words;
}
static std::array<U, loco::GridV2WordCount> GridV2Status() {
    std::array<U, loco::GridV2WordCount> words{}; loco::SampleGridV2(words.data()); return words;
}
static std::array<U, loco::ParallelWordCount> ParallelStatus() {
    std::array<U, loco::ParallelWordCount> words{}; loco::SampleParallel(words.data()); return words;
}
// Capacities for one fixture world, derived from its own native structures instead of constants: cells from the real
// soft-grid header, records from the two fixed registry arrays, memberships from the per-agent node arrays.
// `primary` is the movement-slot capacity under test (primary registry only, never primary+secondary).
static ntw2_workload::Capacity FixtureCapacity(World& w, U primary) {
    const U shift = Get<U>(w.soft.p(), 8), maximum = Get<U>(w.soft.p(), 0x14);
    ntw2_workload::Capacity c{};
    c.primary = primary;
    c.records = std::max<U>(primary, 2 * kFixtureSlots);
    c.cells = (maximum << shift) + maximum + 1;
    c.memberships = U(w.agents.size()) * 256u + 256u;
    c.pairs = primary * 14u;
    return c;
}
// A normal build is exactly two dispatches (capture, build); the optional native verifier is a third.
static U ExpectedGridDispatches(bool verify) { return 2u + (verify ? 1u : 0u); }
static void CheckCsrOrder(const loco::GridView& v) {
    U dense = 0;
    for (U c = 0; c < v.cell_count; ++c) dense += v.cell_dense[c] != 0;
    EqU("direct-address map holds exactly the occupied rows", dense, v.cells);
    for (U row = 0; row < v.cells; ++row) {
        if (row) Require(v.cell_ids[row] > v.cell_ids[row - 1], "compact rows ascend by native cell id");
        Require(v.offsets[row + 1] > v.offsets[row], "every compact row is non-empty");
        for (U n = v.offsets[row] + 1; n < v.offsets[row + 1]; ++n)
            Require(v.occupants[n] > v.occupants[n - 1], "row occupants ascend by record slot");
    }
    EqU("last offset closes the membership array", v.offsets[v.cells], v.memberships);
}
static std::vector<U> GridCanonical(const World& w, const loco::GridView& v, bool includeIncarnation = true) {
    std::vector<U> out{v.count, v.cells, v.memberships};
    for (U i = 0; i < v.count; ++i) {
        out.insert(out.end(), {w.Token(v.record[i]), v.serial[i], includeIncarnation ? v.incarnation[i] : 0u, w.Token(v.team[i]), v.flags[i],
            Bits(v.x[i]), Bits(v.z[i]), Bits(v.y[i]), Bits(v.extent[i]), Bits(v.radius[i]),
            v.left[i], v.right[i], v.top[i], v.bottom[i], v.inserted[i], v.active[i]});
    }
    for (U c = 0; c < v.cells; ++c) out.insert(out.end(), {v.cell_ids[c], v.offsets[c]});
    out.push_back(v.offsets[v.cells]);
    for (U n = 0; n < v.memberships; ++n) out.push_back(v.occupants[n]);
    return out;
}
static void CheckGrid(const GridRegistry& r) {
    const World& w = r.world;
    const loco::GridView* view = loco::ReadGrid();
    Require(view != nullptr, "successful capture publishes immutable grid");
    const auto& v = *view;
    EqU("dense imported record count", v.count, U(r.records.size()));
    Require(v.generation != 0 && v.epoch != 0, "grid identity has generation and phase epoch");
    U total = 0;
    for (U i = 0; i < v.count; ++i) {
        EqU("primary then secondary dense record order", v.record[i], r.records[i]);
        if (!v.record[i]) { EqU("null primary slot has no memberships", v.inserted[i], 0); continue; }
        const B* p = reinterpret_cast<const B*>(static_cast<uintptr_t>(v.record[i]));
        EqU("snapshot flags are the native payload flags", v.flags[i], Get<U>(p, 0x38));
        EqU("snapshot native activity byte", v.active[i], Get<B>(p, 0x30));
        EqU("full serial survives low-u16 collisions", v.serial[i], Get<U>(p, 0x2c));
        Require(v.incarnation[i] != 0, "record incarnation is assigned");
        EqU("snapshot x bits", Bits(v.x[i]), Get<U>(p, 0x48));
        EqU("snapshot y bits", Bits(v.y[i]), Get<U>(p, 0x4c));
        EqU("snapshot z bits", Bits(v.z[i]), Get<U>(p, 0x50));
        EqU("snapshot extent bits", Bits(v.extent[i]), Get<U>(p, 0x54));
        EqU("snapshot radius bits", Bits(v.radius[i]), Get<U>(p, 0x58));
        EqU("A1 does not erase retained native membership", v.inserted[i], Get<U>(p, 0xac));
        const B* nodes = reinterpret_cast<const B*>(static_cast<uintptr_t>(Get<U>(p, 0xa8)));
        U left = UINT32_MAX, right = 0, top = UINT32_MAX, bottom = 0;
        for (U n = 0; n < v.inserted[i]; ++n) {
            const U head = Get<U>(nodes, n * 0x1c + 0x18);
            Require(head >= A(w.softCells.p()) && head < A(w.softCells.p()) + w.softCells.size() &&
                (head - A(w.softCells.p())) % 4 == 0, "native node points to a fixture cell");
            const U cell = (head - A(w.softCells.p())) / 4, x = cell & 31u, z = cell >> 5;
            left = std::min(left, x); right = std::max(right, x); top = std::min(top, z); bottom = std::max(bottom, z);
        }
        if (!v.inserted[i]) left = right = top = bottom = 0;
        EqU("left bound from real inserted nodes", v.left[i], left);
        EqU("right bound from real inserted nodes", v.right[i], right);
        EqU("top bound from real inserted nodes", v.top[i], top);
        EqU("bottom bound from real inserted nodes", v.bottom[i], bottom);
        total += v.inserted[i];
    }
    EqU("CSR population equals native inserted nodes", v.memberships, total);
    EqU("CSR first offset", v.offsets[0], 0);
    U occupied = 0, cursor = 0;
    std::array<bool, 1024> seen{};
    for (U row = 0; row < v.cells; ++row) {
        const U cell = v.cell_ids[row];
        Require(cell < seen.size() && !seen[cell], "compact CSR cell IDs are in range and unique");
        seen[cell] = true;
        U node = Get<U>(w.softCells.p(), 4 * cell);
        Require(node != 0, "every compact CSR row names an occupied native cell");
        EqU("CSR row begins at native chain cursor", v.offsets[row], cursor);
        U walked = 0;
        std::vector<U> nativeSlots;
        for (; node; node = Get<U>(reinterpret_cast<const void*>(static_cast<uintptr_t>(node)), 0x14)) {
            Require(++walked <= total, "native fixture chain is acyclic");
            const B* p = reinterpret_cast<const B*>(static_cast<uintptr_t>(node));
            const U owner = Get<U>(p, 0xc);
            const auto slot = std::find(r.records.begin(), r.records.end(), owner);
            Require(slot != r.records.end(), "native node owner belongs to imported registries");
            Require(cursor < v.memberships, "native chain fits CSR");
            nativeSlots.push_back(U(slot - r.records.begin())); ++cursor;
        }
        std::sort(nativeSlots.begin(), nativeSlots.end());
        Require(std::equal(nativeSlots.begin(), nativeSlots.end(), v.occupants + v.offsets[row]),
            "CSR membership set equals native insertion (order may differ)");
        EqU("direct cell map names compact row", v.cell_dense[cell], row + 1);
        EqU("CSR row ends after complete native chain", v.offsets[row + 1], cursor);
    }
    for (U cell = 0; cell < seen.size(); ++cell) {
        const bool nativeOccupied = Get<U>(w.softCells.p(), 4 * cell) != 0;
        Require(seen[cell] == nativeOccupied, "compact CSR covers every native occupied cell exactly once");
        if (nativeOccupied) ++occupied;
    }
    EqU("all CSR rows correspond to native occupied cells", v.cells, occupied);
    EqU("all CSR memberships correspond to native chain nodes", v.memberships, cursor);
    CheckCsrOrder(v);
}
static U dispatchCalls, dispatchedChunks, dispatchMaxChunks, dispatchLanes;
static std::vector<U> dispatchSizes; // chunk count of every dispatch, in order
static void CaptureChecked(GridRegistry& r) {
    const auto before = Canon(r.world);
    const auto primary = r.primary, secondary = r.secondary;
    const auto header = r.world.soft.v;
    const auto stats = GridStatus();
    const auto v2Before = GridV2Status();
    const size_t sizesBefore = dispatchSizes.size();
    const bool captured = loco::CaptureGrid(r.world.mgr.p());
    if (!captured) {
        const auto failed = GridStatus();
        const auto parallel = ParallelStatus();
        unsigned short cw;
        __asm fnstcw word ptr [cw]
        std::fprintf(stderr, "CaptureGrid control: x87=%04x MXCSR=%08x\n", cw, _mm_getcsr());
        std::fprintf(stderr, "CaptureGrid refusal: refusals=%u faults=%u mismatches=%u unsupported=%u sampled=%u "
            "first-fault exception=%08x entity=%08x ordinal=%u eip=%08x access=%08x serial=%08x\n",
            failed[loco::GridRefusals] - stats[loco::GridRefusals], failed[loco::GridFaults] - stats[loco::GridFaults],
            failed[loco::GridMismatches] - stats[loco::GridMismatches],
            failed[loco::GridUnsupported] - stats[loco::GridUnsupported], failed[loco::GridSampled] - stats[loco::GridSampled],
            parallel[loco::ParallelLastException], parallel[loco::ParallelLastEntity], parallel[loco::ParallelLastOrdinal],
            parallel[loco::ParallelLastEip], parallel[loco::ParallelLastAccess], parallel[loco::ParallelLastSerial]);
    }
    Require(captured, "CaptureGrid accepts native synthetic registries");
    Require(Canon(r.world) == before && r.primary == primary && r.secondary == secondary && r.world.soft.v == header,
        "CaptureGrid imports read-only without repairing native state");
    CheckGrid(r);
    const auto after = GridStatus();
    EqU("capture status version", after[loco::GridVersion], 1);
    EqU("one public capture counted", after[loco::GridCaptures] - stats[loco::GridCaptures], 1);
    EqU("no native membership mismatch", after[loco::GridMismatches] - stats[loco::GridMismatches], 0);
    EqU("no capture faults", after[loco::GridFaults] - stats[loco::GridFaults], 0);
    EqU("no capture refusal", after[loco::GridRefusals] - stats[loco::GridRefusals], 0);
    const auto v2 = GridV2Status();
    EqU("grid v2 version", v2[loco::GridV2Version], 2);
    EqU("a normal build is exactly two dispatches", v2[loco::GridV2Dispatches] - v2Before[loco::GridV2Dispatches],
        ExpectedGridDispatches(v2[loco::GridV2VerifyEnabled] != 0));
    const size_t made = dispatchSizes.size() - sizesBefore;
    if (made) { // a pool dispatcher is bound: the chunk shape of each dispatch is part of the contract
        const bool verified = v2[loco::GridV2VerifyEnabled] != 0;
        EqU("the dispatcher saw exactly the grid's dispatches", U(made), ExpectedGridDispatches(verified));
        const U gridChunks = std::min<U>(32, 3 * dispatchLanes); // three record chunks per participant, at most 32
        EqU("capture dispatch spans three record chunks per participant", dispatchSizes[sizesBefore], gridChunks);
        const U build = dispatchSizes[sizesBefore + 1];
        Require(build >= gridChunks && build <= gridChunks + 2 * gridChunks,
            "build dispatch is one finish chunk per record chunk plus at most two row-run tasks per chunk");
        if (loco::ReadGrid()->memberships) Require(build > gridChunks, "a populated grid has at least one build task");
        if (verified) EqU("verification spans every record chunk", dispatchSizes[sizesBefore + 2], gridChunks);
    }
    EqU("one successful grid v2 build", v2[loco::GridV2Builds] - v2Before[loco::GridV2Builds], 1);
    EqU("grid v2 verifier has zero mismatches", v2[loco::GridV2VerifyMismatches] - v2Before[loco::GridV2VerifyMismatches], 0);
    const auto snapshot = GridCanonical(r.world, *loco::ReadGrid());
    Require(GridCanonical(r.world, *loco::ReadGrid()) == snapshot, "repeated ReadGrid is immutable");
}
static void GridLifecycleCases() {
    currentCase = "owned grid registry lifecycle and full serial";
    Require(loco::ReadGrid() == nullptr, "stopped module exposes no grid");
    auto binding = MakeBinding(); binding.use_grid = binding.verify_grid = true;
    Require(loco::Start(binding), "grid oracle starts");
    Require(loco::ReadGrid() == nullptr, "Start does not publish an uncaptured grid");
    Scenario sc;
    for (U i = 0; i < 5; ++i) { Spec s; s.a1 = 0; s.pos[0] += float(i) * 0.25f; sc.agents.push_back(s); }
    World w(sc); GridRegistry r(w);
    Require(!loco::CaptureGrid(w.mgr.p()), "grid capture cannot allocate before activation");
    Require(loco::ActivateOwned(w.model.p(), FixtureCapacity(w, kFixtureSlots)), "grid-only activation succeeds");
    NativeGridCall(*w.agents[4], false); // Not born in either registry yet.
    r.Set({2, UINT32_MAX, 0, 1}, {3, 1, 2}); // secondary aliases do not create new slots
    CaptureChecked(r);
    const auto* v = loco::ReadGrid();
    const U oldIncarnation = v->incarnation[3], oldGeneration = v->generation, oldEpoch = v->epoch;
    const auto original = GridCanonical(w, *v);
    CaptureChecked(r);
    Require(GridCanonical(w, *loco::ReadGrid()) == original, "unchanged capture preserves identity and CSR order");
    Require(loco::ReadGrid()->epoch > oldEpoch, "capture advances phase epoch");
    // A surviving pointer with a changed full serial is a new identity, despite identical low 16 bits.
    const auto reuseBefore = GridStatus();
    NativeGridCall(*w.agents[1], false); r.Serial(1, 0x90020001u); NativeGridCall(*w.agents[1], true);
    CaptureChecked(r);
    Require(loco::ReadGrid()->incarnation[3] != oldIncarnation, "pointer/full-serial reuse receives a new incarnation");
    Require(GridStatus()[loco::GridReused] > reuseBefore[loco::GridReused], "pointer reuse is reported");
    EqU("capture keeps battle generation", loco::ReadGrid()->generation, oldGeneration);
    // StageCb action 4 above already models the native +30 deactivation write. Activity is not registry ownership:
    // preserve identity and memberships until an actual native unlink, rather than treating +30==0 as destruction.
    const auto inactiveBefore = GridStatus();
    const U inactiveIdentity = loco::ReadGrid()->incarnation[4], inactiveMembers = loco::ReadGrid()->inserted[4];
    Put(w.agents[3]->b.p(), 0x30, B(0)); CaptureChecked(r);
    EqU("deactivation preserves registry population including primary holes", loco::ReadGrid()->count, 5);
    EqU("deactivation preserves incarnation", loco::ReadGrid()->incarnation[4], inactiveIdentity);
    EqU("activity zero alone preserves native memberships", loco::ReadGrid()->inserted[4], inactiveMembers);
    EqU("activity transition is counted separately", GridStatus()[loco::GridDeactivations] - inactiveBefore[loco::GridDeactivations], 1);
    EqU("activity zero is not registry removal", GridStatus()[loco::GridRemovals] - inactiveBefore[loco::GridRemovals], 0);
    NativeGridCall(*w.agents[3], false); CaptureChecked(r);
    Require(GridStatus()[loco::GridMembershipRemovals] > inactiveBefore[loco::GridMembershipRemovals],
        "native unlink is counted separately from registry removal");
    EqU("inactive unlinked record remains imported", loco::ReadGrid()->count, 5);
    Put(w.agents[3]->b.p(), 0x30, B(1)); NativeGridCall(*w.agents[3], true); CaptureChecked(r);
    // Real native removal plus registry deletion, followed by reinforcement and then resurrection at a prior address.
    const U removedIncarnation = loco::ReadGrid()->incarnation[0];
    const auto removalBefore = GridStatus();
    NativeGridCall(*w.agents[2], false); r.Set({0, 1}, {3}); CaptureChecked(r);
    Require(GridStatus()[loco::GridRemovals] > removalBefore[loco::GridRemovals], "registry removal is reported");
    const auto birthBefore = GridStatus();
    NativeGridCall(*w.agents[4], true); r.Set({0, 1}, {3, 4}); CaptureChecked(r);
    Require(GridStatus()[loco::GridBirths] > birthBefore[loco::GridBirths], "secondary reinforcement is reported");
    NativeGridCall(*w.agents[2], true); r.Set({2, 0, 1}, {3, 4}); CaptureChecked(r);
    Require(loco::ReadGrid()->incarnation[0] != removedIncarnation, "removed address cannot retain its old incarnation");
    // Present but unlinked is distinct from absent: A1==0 alone must never imply either state.
    NativeGridCall(*w.agents[0], false); CaptureChecked(r);
    EqU("unlinked registry record has zero membership", loco::ReadGrid()->inserted[1], 0);
    for (auto& a : w.agents) NativeGridCall(*a, false);
    r.Set({}, {}); CaptureChecked(r);
    EqU("empty native registries publish an empty view", loco::ReadGrid()->count, 0);
    CallStop(); Require(loco::ReadGrid() == nullptr, "Stop invalidates borrowed view");
    ++cases;
}
static void GridNumericCases() {
    struct Numeric { const char* name; float x, z, radius; B bump; };
    const Numeric numeric[] = {
        {"grid exact cell boundary", 0.0f, 4.0f, 0.0f, 0},
        {"grid below cell boundary", std::nextafter(4.0f, 0.0f), -4.0f, 0.0f, 0},
        {"grid above cell boundary", std::nextafter(4.0f, 8.0f), 4.0f, 0.0f, 0},
        {"grid fractional signed boundary", -0.5f, 0.5f, 0.75f, 0},
        {"grid unsigned clamp", -100.0f, 100.0f, 0.75f, 0},
        {"grid wide footprint", 20.0f, 24.0f, 6.0f, 0},
        {"grid radius bump enabled", 3.75f, 4.25f, 0.25f, 1},
        {"grid radius bump equality not truthiness", 3.75f, 4.25f, 0.25f, 2},
        {"grid NaN coordinate", NAN, 24.0f, 0.75f, 0},
        {"grid NaN radius", 20.0f, 24.0f, NAN, 1}
    };
    auto binding = MakeBinding(); binding.use_grid = binding.verify_grid = true;
    for (const Numeric& n : numeric) for (U rounding = 0; rounding < 4; ++rounding) {
        currentCase = n.name;
        Spec s; s.a1 = 0; World w(Move(s)); GridRegistry r(w); r.Set({0, 1}, {2, 3});
        Require(loco::Start(binding), "numeric grid oracle starts");
        Require(loco::ActivateOwned(w.model.p(), FixtureCapacity(w, kFixtureSlots)), "numeric grid arena activates");
        // World inserts every record with round-to-nearest. Native FISTP cell bounds depend on the caller's
        // rounding mode, so rebuild the whole registry, not just the subject, under the mode being captured.
        for (auto& agent : w.agents) NativeGridCall(*agent, false);
        Agent& a = *w.agents[0];
        Put(a.b.p(), 0x48, n.x); Put(a.b.p(), 0x50, n.z); Put(a.b.p(), 0x58, n.radius); Put(a.b.p(), 0x5c, n.bump);
        const unsigned short cw = static_cast<unsigned short>(0x27f | (rounding << 10));
        const U mxcsr = 0x1f80 | (rounding << 13);
        __asm fldcw word ptr [cw]
        _mm_setcsr(mxcsr);
        for (auto& agent : w.agents) NativeGridCall(*agent, true);
        CaptureChecked(r);
        unsigned short afterCw;
        __asm fnstcw word ptr [afterCw]
        EqU("capture preserves caller x87 rounding control", afterCw, cw);
        EqU("capture preserves caller MXCSR control", _mm_getcsr() & 0xffc0, mxcsr);
        ResetFp(); CallStop(); ++cases;
    }
}

// A deterministic host dispatcher changes chunk execution order, never mover semantics. Each body must operate only on
// private per-occurrence prefixes; native graphs, service scratch and selector/staging effects stay on the owner.
static bool reverseChunks, concurrentChunks;
static bool relinkRun; // the relink apply mutates native chains inside its dispatches: skip the "dispatch body mutates nothing" audit
struct DispatchGroup {
    HANDLE start, ready; volatile LONG waiting, next;
    U threads, chunks; bool reversed;
};
struct DispatchThread {
    DispatchGroup* group;
    U body, chunk;
    void* context;
    U waitResult, afterMxcsr, executed;
    unsigned short seedCw, afterCw;
    U seedMxcsr, startMxcsr;
    unsigned short startCw;
};
static void DispatchClaimed(DispatchThread& job) {
    U ticket = job.chunk;
    while (ticket < job.group->chunks) {
        const U chunk = job.group->reversed ? job.group->chunks - ticket - 1 : ticket;
        reinterpret_cast<void(__fastcall*)(void*, U)>(job.body)(job.context, chunk);
        ++job.executed;
        ticket = static_cast<U>(InterlockedIncrement(&job.group->next) - 1);
    }
}
static DWORD WINAPI DispatchThreadBody(void* context) {
    auto& job = *static_cast<DispatchThread*>(context);
    ResetFp(); tlsPad[0] = 0;
    const unsigned short cw = job.seedCw;
    __asm fldcw word ptr [cw]
    _mm_setcsr(job.seedMxcsr);
    {
        unsigned short start;
        __asm fnstcw word ptr [start]
        job.startCw = start; job.startMxcsr = _mm_getcsr();
    }
    if (static_cast<U>(InterlockedIncrement(&job.group->waiting)) == job.group->threads) SetEvent(job.group->ready);
    job.waitResult = WaitForSingleObject(job.group->start, INFINITE);
    if (job.waitResult == WAIT_OBJECT_0) DispatchClaimed(job);
    unsigned short after;
    __asm fnstcw word ptr [after]
    job.afterCw = after; job.afterMxcsr = _mm_getcsr();
    return 0;
}
static std::vector<U> ScratchSnapshot() {
    std::vector<U> words;
    auto append = [&](const void* p, U size) {
        for (U off = 0; off < size; off += 4) words.push_back(Get<U>(p, off));
    };
    append(At(0x14543b4), 20);
    append(At(0x15a1880), 0x8120); // Native query headers, visited bitsets and touched-ID/owner queues.
    append(At(0x14dcb30), 0x70);   // Shared selector staging object.
    for (U id : {NTW2_BIND_LOCO_SCRATCH_14543B4, NTW2_BIND_LOCO_SCRATCH_15A1888, NTW2_BIND_LOCO_SCRATCH_15A189C})
        append(reinterpret_cast<const void*>(static_cast<uintptr_t>(privateBindings[id])),
            id == NTW2_BIND_LOCO_SCRATCH_14543B4 ? 20u : 16u);
    return words;
}
static void __stdcall OracleDispatch(U pool, U body, U chunks, void* context) {
    EqU("dispatcher receives configured pool", pool, 0xc0111deu);
    Require(body != 0 && context != nullptr && chunks != 0 && dispatchLanes != 0, "dispatcher receives chunks and participant capacity");
    ++dispatchCalls; dispatchedChunks += chunks; dispatchMaxChunks = std::max(dispatchMaxChunks, chunks);
    dispatchSizes.push_back(chunks);
    const auto graph = Canon(*cur), scratch = ScratchSnapshot(), log = CanonLog(*cur);
    const auto services = Services();
    auto registries = [&]() {
        std::vector<U> values;
        for (U offset : {0x250u, 0x27cu}) {
            const auto* data = reinterpret_cast<const U*>(static_cast<uintptr_t>(Get<U>(cur->mgr.p(), offset)));
            if (data) values.insert(values.end(), data, data + kFixtureSlots);
        }
        return values;
    };
    const auto registry = registries();
    auto globals = [&]() {
        std::array<U, loco::WordCount + loco::GateWordCount + loco::GridWordCount> v{};
        loco::Sample(v.data()); loco::SampleGates(v.data() + loco::WordCount);
        loco::SampleGrid(v.data() + loco::WordCount + loco::GateWordCount); return v;
    };
    const auto diagnostics = globals();
    auto unchanged = [&]() {
        Require(globals() == diagnostics, "worker body cannot mutate global census, gate or grid diagnostics");
        Require(Canon(*cur) == graph, "worker body cannot mutate live native prefix, nodes, cells or registries");
        Require(registries() == registry, "worker body cannot mutate primary or secondary native registry entries");
        Require(ScratchSnapshot() == scratch, "worker body cannot touch shared native or owner-clone scratch");
        Require(CanonLog(*cur) == log, "worker body cannot invoke owner virtuals or selector staging");
        Require(Services() == services, "worker body cannot invoke owner-only native service taps");
    };
    if (concurrentChunks) {
        const U threadsUsed = std::min(dispatchLanes, chunks);
        DispatchGroup group{CreateEvent(nullptr, TRUE, FALSE, nullptr), CreateEvent(nullptr, TRUE, FALSE, nullptr),
            0, static_cast<LONG>(threadsUsed), threadsUsed, chunks, reverseChunks};
        Require(group.start != nullptr && group.ready != nullptr, "concurrent dispatcher start barriers created");
        std::vector<DispatchThread> jobs(threadsUsed);
        std::vector<HANDLE> threads(threadsUsed);
        for (U n = 0; n < threadsUsed; ++n) {
            auto& job = jobs[n]; job.group = &group; job.body = body; job.chunk = n; job.context = context;
            const U rounding = (n % 3) + 1;
            job.seedCw = static_cast<unsigned short>(0x27f | (rounding << 10));
            job.seedMxcsr = 0x1f80 | (rounding << 13) | 0x8040;
            threads[n] = CreateThread(nullptr, 0, &DispatchThreadBody, &job, 0, nullptr);
            Require(threads[n] != nullptr, "real dispatcher worker thread created");
        }
        Require(WaitForSingleObject(group.ready, INFINITE) == WAIT_OBJECT_0, "all dispatcher workers reach shared start barrier");
        Require(SetEvent(group.start) != 0, "dispatcher releases real workers together");
        for (HANDLE thread : threads) Require(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, "real dispatcher worker joined");
        if (!relinkRun) unchanged();
        U executed = 0;
        for (U n = 0; n < threadsUsed; ++n) {
            EqU("worker passed its start barrier", jobs[n].waitResult, WAIT_OBJECT_0);
            Require(jobs[n].executed != 0, "each distinct dispatch thread executes its seed chunk");
            executed += jobs[n].executed;
            EqU("chunk restores worker x87 control", jobs[n].afterCw, jobs[n].seedCw);
            EqU("chunk restores worker MXCSR control", jobs[n].afterMxcsr & 0xffc0, jobs[n].seedMxcsr);
            EqU("pool worker starts with FTZ|DAZ set", jobs[n].startMxcsr & 0x8040, 0x8040);
            EqU("pool worker starts with 53-bit x87 precision", jobs[n].startCw & 0x300, 0x200);
            Require(CloseHandle(threads[n]) != 0, "real dispatcher worker handle closed");
        }
        EqU("atomic claims execute every chunk exactly once", executed, chunks);
        Require(CloseHandle(group.start) != 0 && CloseHandle(group.ready) != 0, "dispatcher barrier handles closed");
    } else {
        DispatchGroup group{nullptr, nullptr, 0, 1, 1, chunks, reverseChunks};
        DispatchThread job{}; job.group = &group; job.body = body; job.chunk = 0; job.context = context;
        DispatchClaimed(job);
        EqU("inline claims execute every chunk exactly once", job.executed, chunks);
        if (!relinkRun) unchanged();
    }
}
static void GridV2Scenario(Scenario& sc, std::vector<U>& primary, std::vector<U>& secondary) {
    for (U i = 0; i < 48; ++i) {
        Spec s; s.a1 = 0; s.pos[0] += float(i % 8) * 0.375f; s.pos[2] += float(i / 8) * 0.25f;
        sc.agents.push_back(s);
    }
    for (U i = 0; i < sc.agents.size(); ++i) (i < 32 ? primary : secondary).push_back(i);
    primary.insert(primary.begin() + 7, UINT32_MAX); secondary.push_back(0);
}
static void GridV2Cases() {
    std::vector<U> reference;
    // Lanes 1/4/8 under serial and concurrent claiming: a normal build is two dispatches, the verifier one more, and the
    // published CSR is bit-identical for every lane count, schedule and verification mode.
    for (U lanes : {1u, 4u, 8u}) for (bool concurrent : {false, true}) {
        U unverifiedDispatches = 0;
        for (bool verify : {false, true}) {
            currentCase = "grid v2 two-dispatch tally/scan/scatter and optional native verifier pass";
            Scenario sc; std::vector<U> primary, secondary;
            GridV2Scenario(sc, primary, secondary);
            World w(sc); GridRegistry registry(w);
            registry.Set(primary, secondary);
            auto binding = MakeBinding(); binding.use_grid = true; binding.verify_grid = verify;
            binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
            dispatchLanes = lanes; reverseChunks = true; concurrentChunks = concurrent;
            dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0; dispatchSizes.clear();
            Require(loco::Start(binding), "v2 synthetic grid starts");
            Require(loco::ActivateOwned(w.model.p(), FixtureCapacity(w, kFixtureSlots)), "v2 prefaults at activation");
            cur = &w; vlog = &w.log; ResetFp();
            CaptureChecked(registry);
            const auto v2 = GridV2Status();
            EqU("telemetry counts the pool's actual separate dispatches", v2[loco::GridV2Dispatches], dispatchCalls);
            EqU("normal build is two dispatches, verification one more", dispatchCalls, ExpectedGridDispatches(verify));
            Require(dispatchedChunks >= dispatchCalls * lanes, "every dispatch spans at least every lane's chunk");
            if (!verify) {
                unverifiedDispatches = dispatchCalls;
                EqU("normal build reports no verification work", v2[loco::GridV2VerifyUs] + v2[loco::GridV2VerifyEnabled], 0);
            } else {
                EqU("verification is exactly one additional independent pass", dispatchCalls, unverifiedDispatches + 1);
                EqU("verified build mismatch free", v2[loco::GridV2VerifyMismatches], 0);
            }
            const auto canonical = GridCanonical(w, *loco::ReadGrid(), false);
            if (reference.empty()) reference = canonical;
            else Require(canonical == reference, "v2 CSR is deterministic across lanes, schedules and verification modes");
            Require(loco::ReadGridForCollision(w.mgr.p()) == loco::ReadGrid(), "matching published manager exposes collision input");
            const U count = Get<U>(w.mgr.p(), 0x278);
            Put(w.mgr.p(), 0x278, count - 1);
            Require(loco::ReadGridForCollision(w.mgr.p()) == nullptr, "registry layout mutation refuses stale collision view");
            Put(w.mgr.p(), 0x278, count);
            if (verify) {
                const auto& view = *loco::ReadGrid();
                const U cell = view.cell_ids[0], head = Get<U>(w.softCells.p(), cell * 4);
                Put(w.softCells.p(), cell * 4, U(0)); // retained node headers alone cannot prove actual membership
                Require(!loco::CaptureGrid(w.mgr.p()), "verifier rejects a missing native chain");
                Require(loco::ReadGrid() == nullptr, "failed verification publishes no partial view");
                Require(GridV2Status()[loco::GridV2VerifyMismatches] != 0, "native membership mismatch is reported");
                EqU("verification does not repair the native head", Get<U>(w.softCells.p(), cell * 4), 0);
                Put(w.softCells.p(), cell * 4, head);
                CaptureChecked(registry);
                const U secondaryEntry = registry.secondary[0];
                registry.secondary[0] = 0; // foreign/orphan chain node, not a disappearing native membership
                Require(!loco::CaptureGrid(w.mgr.p()), "verifier rejects chain owners absent from both registries");
                registry.secondary[0] = secondaryEntry;
                CaptureChecked(registry);
            }
            const U primaryEntry = registry.primary[1];
            registry.primary[1] = registry.primary[0];
            const U beforeDuplicate = dispatchCalls;
            Require(!loco::CaptureGrid(w.mgr.p()), "duplicate primary registry identity refuses before dispatch");
            EqU("a refused registry dispatches nothing", dispatchCalls, beforeDuplicate);
            registry.primary[1] = primaryEntry;
            CaptureChecked(registry);
            CallStop(); Require(loco::ReadGridForCollision(w.mgr.p()) == nullptr, "stop invalidates collision input");
            ++cases;
        }
    }
}
// A populated map: 192 records of varying radius spread over the whole 32x32 native grid, so every chunk, row run and
// strip task sees many distinct cells. Output must be identical for every lane/schedule and match the
// untouched native chains (membership SETS, row order and occupant order) with the verifier pass enabled.
static void GridSpreadCases() {
    std::vector<U> reference;
    for (U lanes : {1u, 4u, 8u}) for (bool concurrent : {false, true}) {
        currentCase = "grid two-dispatch build over a populated native map";
        Scenario sc;
        for (U i = 0; i < 192; ++i) {
            Spec s; s.a1 = 0;
            s.pos[0] = -56.0f + float(i % 16) * 7.5f; s.pos[2] = -56.0f + float(i / 16) * 7.5f;
            s.radius = 0.5f + float(i % 7) * 1.5f;
            sc.agents.push_back(s);
        }
        World w(sc); GridRegistry registry(w);
        std::vector<U> primary, secondary;
        for (U i = 0; i < sc.agents.size(); ++i) (i < 150 ? primary : secondary).push_back(i);
        secondary.push_back(3); // alias of a primary: no new record
        registry.Set(primary, secondary);
        auto binding = MakeBinding(); binding.use_grid = binding.verify_grid = true;
        binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
        dispatchLanes = lanes; reverseChunks = lanes == 4; concurrentChunks = concurrent;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0; dispatchSizes.clear();
        Require(loco::Start(binding), "spread grid starts");
        Require(loco::ActivateOwned(w.model.p(), FixtureCapacity(w, kFixtureSlots)), "spread grid activates");
        cur = &w; vlog = &w.log; ResetFp();
        CaptureChecked(registry);
        const auto& view = *loco::ReadGrid();
        Require(view.cells > 100 && view.memberships > view.cells, "fixture really populates many cells");
        EqU("spread build is two dispatches plus verification", dispatchCalls, ExpectedGridDispatches(true));
        const auto canonical = GridCanonical(w, view, false);
        if (reference.empty()) reference = canonical;
        else Require(canonical == reference, "populated CSR is identical across lanes and schedules");
        // A second publication reuses the dense map in place: identical input, identical output.
        CaptureChecked(registry);
        Require(GridCanonical(w, *loco::ReadGrid(), false) == reference, "rebuilt CSR is identical after in-place dense reuse");
        // Move every record to a different z band: stale rows of the previous publication must be zeroed (CheckGrid
        // requires the dense map to hold exactly the occupied rows), then moving back restores the reference exactly.
        for (auto& agent : w.agents) NativeGridCall(*agent, false);
        for (auto& agent : w.agents) { Put(agent->b.p(), 0x50, Get<float>(agent->b.p(), 0x50) + 24.0f); }
        for (auto& agent : w.agents) NativeGridCall(*agent, true);
        CaptureChecked(registry);
        EqU("shifted population keeps every record's memberships", loco::ReadGrid()->memberships,
            [&]() { U total = 0; for (auto& agent : w.agents) total += Get<U>(agent->b.p(), 0xac); return total; }());
        for (auto& agent : w.agents) NativeGridCall(*agent, false);
        for (auto& agent : w.agents) { Put(agent->b.p(), 0x50, Get<float>(agent->b.p(), 0x50) - 24.0f); }
        for (auto& agent : w.agents) NativeGridCall(*agent, true);
        CaptureChecked(registry);
        Require(GridCanonical(w, *loco::ReadGrid(), false) == reference, "returning population reproduces the reference CSR");
        CallStop(); ++cases;
    }
}
// Exact byte formula of the single grid block (each array padded to 64 bytes), recomputed independently of the module.
static unsigned long long GridPad(unsigned long long words) { return (words * 4 + 63) & ~63ull; }
static unsigned long long ExpectedGridBytes(const ntw2_workload::Capacity& c, U participants) {
    const U chunks = std::min<U>(32, 3 * participants); // the grid carves three record chunks per participant
    U hash = 16; while (hash < c.records + c.records / 2 + 1) hash <<= 1;
    const U rows = std::min(c.cells, c.memberships);
    // identity 2*4R | registry 2*(R+H) | rawSecondary R | view 12R | committed R | dense C | cellIds Q | offsets Q+1 |
    // occupants M | fill Q | stripMembers chunks*64 | stripRows chunks*64 | bucketSingle+bucketMulti 2*chunks*ceil(R/chunks) |
    // bucketStart chunks*65 | stats chunks*64B
    const unsigned long long bucket = (c.records + chunks - 1ull) / chunks;
    return 2 * (5 * GridPad(c.records) + GridPad(hash)) + GridPad(c.records) + 12 * GridPad(c.records) + GridPad(c.records) +
        GridPad(c.cells) + GridPad(rows) + GridPad(rows + 1ull) + GridPad(c.memberships) + GridPad(rows) +
        2 * GridPad(static_cast<unsigned long long>(chunks) * 64) + 2 * GridPad(chunks * bucket) +
        GridPad(static_cast<unsigned long long>(chunks) * 65) + chunks * 64ull;
}
static void GridCapacityCases() {
    Scenario sc; std::vector<U> primary, secondary;
    GridV2Scenario(sc, primary, secondary);
    World w(sc); GridRegistry registry(w);
    registry.Set(primary, secondary);
    U live = 0;
    for (auto& agent : w.agents) live += Get<U>(agent->b.p(), 0xac);
    ntw2_workload::Capacity base = {40, 80, 1024, live + 8, 0}; // 33 primary entries, 49 unique records
    auto begin = [&](U lanes) {
        auto binding = MakeBinding(); binding.use_grid = true;
        binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
        dispatchLanes = lanes; reverseChunks = false; concurrentChunks = false;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        dispatchSizes.clear();
        Require(loco::Start(binding), "capacity grid starts");
        cur = &w; vlog = &w.log; ResetFp();
    };
    currentCase = "grid storage is exactly the activation capacity";
    for (U lanes : {1u, 4u, 8u}) {
        begin(lanes);
        EqU("Start alone reserves no grid storage", loco::StorageBytes(), 0);
        const unsigned long long expected = ExpectedGridBytes(base, lanes), allocation = (expected + 4095) & ~4095ull;
        EqU("estimate before activation is exactly the page-rounded grid block", loco::EstimateActivationBytes(base), U(allocation));
        Require(loco::EstimateActivationBytes(ntw2_workload::Capacity{}) == UINT32_MAX, "incoherent capacity has no estimate");
        Require(loco::ActivateOwned(w.model.p(), base), "capacity grid activates");
        EqU("grid bytes status equals the byte formula", GridStatus()[loco::GridBytes], U(expected));
        EqU("module storage is exactly the page-rounded grid block", loco::StorageBytes(), U(allocation));
        Require(allocation < 512 * 1024, "a 49-record capacity reserves far below the old fixed worst-case grid");
        CaptureChecked(registry);
        MEMORY_BASIC_INFORMATION region{};
        Require(VirtualQuery(loco::ReadGrid()->record, &region, sizeof(region)) == sizeof(region), "grid allocation is queryable");
        Require(VirtualQuery(region.AllocationBase, &region, sizeof(region)) == sizeof(region), "grid allocation base is queryable");
        EqU("the real allocation is the capacity-sized block", U(region.RegionSize), U(allocation));
        EqU("publication allocates nothing", loco::StorageBytes(), U(allocation));
        CallStop();
        EqU("Stop releases all storage", loco::StorageBytes(), 0);
        ++cases;
    }
    {   // Storage tracks each capacity field.
        auto bigger = base; bigger.records *= 2; bigger.memberships *= 2;
        begin(4); Require(loco::ActivateOwned(w.model.p(), bigger), "larger grid activates");
        Require(ExpectedGridBytes(bigger, 4) > ExpectedGridBytes(base, 4), "formula grows with capacity");
        EqU("larger capacity is reflected exactly", GridStatus()[loco::GridBytes], U(ExpectedGridBytes(bigger, 4)));
        CallStop(); ++cases;
    }
    // Fixed capacities refuse before publication or any game write, and never grow.
    currentCase = "grid fixed-capacity refusal";
    struct Case { const char* name; ntw2_workload::Capacity capacity; U dispatches; };
    auto small = [&](auto edit) { auto c = base; edit(c); return c; };
    const Case refusals[] = {
        {"records", small([](auto& c) { c.records = 40; }), 0},
        {"primary", small([](auto& c) { c.primary = 32; }), 0},
        {"cells", small([](auto& c) { c.cells = 512; }), 0},
        {"memberships", small([&](auto& c) { c.memberships = live - 1; }), 1},
    };
    for (const Case& refusal : refusals) {
        begin(4);
        Require(loco::ActivateOwned(w.model.p(), refusal.capacity), "undersized grid activation itself succeeds");
        const U bytes = loco::StorageBytes();
        const auto before = Canon(w);
        const auto registryBefore = std::make_pair(registry.primary, registry.secondary);
        for (U attempt = 0; attempt < 2; ++attempt) {
            Require(!loco::CaptureGrid(w.mgr.p()), refusal.name);
            Require(loco::ReadGrid() == nullptr, "a refused capture publishes no view");
            Require(Canon(w) == before, "a refused capture leaves native state untouched");
            Require(registryBefore == std::make_pair(registry.primary, registry.secondary), "a refused capture leaves registries untouched");
            EqU("refused capture dispatches at most the bounds pass", dispatchCalls, refusal.dispatches * (attempt + 1));
            EqU("a refused capture never grows storage", loco::StorageBytes(), bytes);
        }
        const auto grid = GridStatus();
        EqU("each refusal is counted", grid[loco::GridRefusals], 2);
        EqU("no refusal builds", grid[loco::GridCaptures] + GridV2Status()[loco::GridV2Builds], 0);
        CallStop(); ++cases;
    }
}
static U stagingOwner;
static U __fastcall ClampHolder(void* self, void*) {
    // 63D5B0 -> 7FF390 -> holder+8 virtual +44. Keep the genuine +70 slot and callback instructions intact.
    if (GetCurrentThreadId() != stagingOwner) Fail("native clamp callback reached holder on a worker");
    vlog->push_back({RecClampHolder, A(self), 0, 0});
    return 1;
}
static void* __fastcall ClassChildHeading(void* self, void*, void* out) {
    if (GetCurrentThreadId() != stagingOwner) Fail("class child heading callback reached worker");
    Put(out, 0, uint16_t(0));
    vlog->push_back({RecClassHeading, A(self), 0, 0});
    return out;
}
// The genuine class-wrapper child rewrites this dword of a LATER entity (default: the +D4 displacement the mover reads).
static U classMutateOffset = 0xd4, classMutateBits = 0x40800000u;
static void __fastcall ClassChildPose(void* self, void*, const void*, U) {
    if (GetCurrentThreadId() != stagingOwner) Fail("class child pose callback reached worker");
    const U target = Get<U>(self, 4);
    Require(target < cur->agents.size(), "class child mutation target exists");
    Put(cur->agents[target]->b.p(), classMutateOffset, classMutateBits);
    vlog->push_back({RecClassMutate, A(self), target, 0});
}
static void __fastcall StageGather(void* self, void*, void* staging, U mode) {
    EqU("staging callback executes on owner thread", GetCurrentThreadId(), stagingOwner);
    EqU("native staging callback mode", mode, 1);
    EqU("native staging receiver is shared object", A(staging), A(At(0x14dcb30)));
    vlog->push_back({RecStaging, A(self), mode, 0});
    // Empty native category lists are fixture data; real 7FC120/8057F0 still perform their traversal and reset.
    for (U off : {0x18u, 0x2cu, 0x40u, 0x54u, 0x68u}) EqU("staging fixture category is empty", Get<U>(staging, off), 0);
}
static void PrepareStagingFixture() {
    CallEntry(A(At(0x7e3980)), At(0x14dcb30), "native staging constructor");
    Put(At(0x14dcba0), 0, U(0x80000000));
}
struct QueryFpRecord { U thread, mxcsr; unsigned short cw; };
static std::array<QueryFpRecord, 24> queryFp;
static U queryFpTarget;
static volatile LONG queryFpInvalid;
static U __fastcall ObserveQueryFp(void* descriptor, void*) {
    const U serial = Get<U>(static_cast<const B*>(descriptor) - 0xf4, 0x2c);
    const U index = (serial >> 16) - 1;
    unsigned short cw;
    __asm fnstcw word ptr [cw]
    if (index < queryFp.size()) {
        // Distinct occurrences own distinct slots; the owner reads them only after every dispatch thread has joined.
        queryFp[index] = {GetCurrentThreadId(), _mm_getcsr(), cw};
    } else InterlockedIncrement(&queryFpInvalid);
    return reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(queryFpTarget))(descriptor);
}
static std::vector<U> ParallelStageOnce(const Scenario& sc, U lanes, bool reversed,
    const std::vector<loco::ParallelWord>& ownerReasons, bool pureWorker, bool concurrent = false, bool observeFp = false) {
    auto binding = MakeBinding(); binding.use_parallel = true; binding.dispatch = &OracleDispatch;
    binding.use_grid = binding.verify_grid = true;
    binding.pool = 0xc0111deu; binding.workers = lanes - 1; // Dispatch participants include the caller.
    reverseChunks = reversed; dispatchLanes = lanes; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
    concurrentChunks = concurrent;
    Require(loco::Start(binding), "parallel oracle starts through public binding");
    if (observeFp) {
        queryFp.fill(QueryFpRecord{}); queryFpInvalid = 0;
        queryFpTarget = loco::SetServiceTargetForTest(loco::WrapperQuery, Fn(&ObserveQueryFp));
        Require(queryFpTarget != 0, "public query seam observes worker FP without replacing native arithmetic");
    }
    const auto initial = ParallelStatus();
    EqU("parallel status version", initial[loco::ParallelVersion], 1);
    EqU("parallel status enabled", initial[loco::ParallelEnabled], 1);
    EqU("parallel starts without sticky failure", initial[loco::ParallelSticky], 0);
    World original(sc), owned(sc);
    GridRegistry originalRegistry(original), ownedRegistry(owned);
    std::vector<U> primary, secondary;
    for (U i = 0; i < sc.agents.size(); ++i) (i & 1 ? secondary : primary).push_back(i);
    originalRegistry.Set(primary, secondary); ownedRegistry.Set(primary, secondary);
    Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, kFixtureSlots)), "parallel fixture activates grid storage");
    // A nonnull descriptor owner must be rejected even with a null mover owner.
    for (U i = 0; i < sc.agents.size(); ++i) if (sc.agents[i].arg == 0x170) {
        Put(original.agents[i]->b.p(), 0x170, A(original.plane.p()));
        Put(owned.agents[i]->b.p(), 0x170, A(owned.plane.p()));
    }
    Same(original, owned, "identical parallel native graphs before execution");
    PrepareStagingFixture();
    cur = &original; vlog = &original.log; ResetFp();
    const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
    PrepareStagingFixture();
    cur = &owned; vlog = &owned.log; ResetFp();
    const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
    EqU("parallel Stage returns exact native end pointer", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
    Same(original, owned, "parallel Stage bit-exact native state including private-prefix copyback and selector latches");
    SameLog(original, owned, "parallel owner callback and staging order");
    CheckGrid(ownedRegistry);
    const auto status = ParallelStatus(), grid = GridStatus();
    EqU("parallel has no worker faults", status[loco::ParallelFaults], 0);
    EqU("parallel has no sticky failure", status[loco::ParallelSticky], 0);
    EqU("parallel has no exception", status[loco::ParallelLastException], 0);
    EqU("parallel has no invalidated output", status[loco::ParallelInvalidated], 0);
    Require(status[loco::ParallelWorkerEntities] >= 24, "safe A1==0 direct-selector cohort executes on worker seam");
    EqU("all worker outputs are committed", status[loco::ParallelCommitted], status[loco::ParallelWorkerEntities]);
    EqU("Stage builds exactly one final publication", grid[loco::GridCaptures], 1);
    EqU("Stage captures preserve native membership", grid[loco::GridMismatches], 0);
    EqU("Stage captures have no faults", grid[loco::GridFaults], 0);
    EqU("Stage captures have no refusals", grid[loco::GridRefusals], 0);
    Require(dispatchCalls != 0 && dispatchedChunks >= lanes, "configured dispatcher executes even with one lane");
    Require(dispatchMaxChunks >= lanes && dispatchMaxChunks <= 9 * lanes,
        "full safe cohort uses every configured lane; only the grid build dispatch (three record chunks per lane plus row-run tasks) may exceed it");
    if (pureWorker) {
        EqU("all pure worker occurrences execute", status[loco::ParallelWorkerEntities], U(sc.list.size()));
        EqU("pure cohort has no owner fallback", status[loco::ParallelOwnerEntities], 0);
        EqU("pure cohort replays no owner service", status[loco::ParallelReplayedServices], 0);
    } else if (!ownerReasons.empty()) {
        Require(status[loco::ParallelOwnerEntities] != 0, "unsafe occurrences stay on owner");
        for (auto reason : ownerReasons) Require(status[reason] != 0, "unsafe occurrence has the expected owner reason");
    }
    // Include the live native state and immutable CSR in the cross-lane/cross-order deterministic comparison.
    auto result = Canon(owned); const auto csr = GridCanonical(owned, *loco::ReadGrid(), false);
    result.insert(result.end(), csr.begin(), csr.end());
    if (observeFp) {
        EqU("worker FP probe received expected private occurrences", U(queryFpInvalid), 0);
        U foreignThreads = 0;
        for (const auto& fp : queryFp) {
            Require(fp.thread != 0, "each wrapper occurrence reaches real native query through FP observer");
            EqU("worker installs owner's captured x87 control", fp.cw, 0x27f);
            EqU("worker installs owner's captured MXCSR control", fp.mxcsr & 0xffc0, 0x1f80);
            if (fp.thread != GetCurrentThreadId()) ++foreignThreads;
        }
        if (concurrent && lanes > 1) Require(foreignThreads != 0, "native wrappers execute on real non-owner threads");
        EqU("FP observer restores real native service target",
            loco::SetServiceTargetForTest(loco::WrapperQuery, queryFpTarget), Fn(&ObserveQueryFp));
    }
    CallStop(); Require(loco::ReadGrid() == nullptr, "parallel Stop invalidates view");
    ++cases; return result;
}

static U faultQueryTarget, faultQuerySerial, injectedQueryFaults;
static U __fastcall FaultPrivateQuery(void* descriptor, void*) {
    const B* record = static_cast<const B*>(descriptor) - 0xf4;
    if (Get<U>(record, 0x2c) == faultQuerySerial) {
        ++injectedQueryFaults;
        RaiseException(0xe0424c4fu, 0, 0, nullptr);
    }
    return reinterpret_cast<U(__fastcall*)(void*)>(static_cast<uintptr_t>(faultQueryTarget))(descriptor);
}
static void ParallelFaultCases() {
    currentCase = "parallel private wrapper-query fault discards wave and resumes native ordinal";
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        auto binding = MakeBinding(); binding.use_parallel = true; binding.dispatch = &OracleDispatch;
        binding.use_grid = binding.verify_grid = true;
        binding.pool = 0xc0111deu; binding.workers = lanes - 1;
        dispatchLanes = lanes; reverseChunks = reversed; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        concurrentChunks = false;
        Require(loco::Start(binding), "fault-injection oracle starts");
        Scenario sc;
        for (U i = 0; i < 27; ++i) {
            Spec s = Genuine(i, 1); s.a1 = 0;
            // After fallback reaches this native ordinal, erase-shift behind its absolute cursor. The original loop's
            // end reload and skipped shifted entry must be preserved, not replaced by replay of a frozen stage list.
            if (i == 24) s = Callback(i, 3, 0);
            sc.agents.push_back(s); sc.list.push_back(i);
        }
        World original(sc), owned(sc);
        GridRegistry originalRegistry(original), ownedRegistry(owned);
        std::vector<U> ids;
        for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
        originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
        Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, kFixtureSlots)), "fault fixture activates grid storage");
        faultQuerySerial = Get<U>(owned.agents[8]->b.p(), 0x2c); injectedQueryFaults = 0;
        faultQueryTarget = loco::SetServiceTargetForTest(loco::WrapperQuery, Fn(&FaultPrivateQuery));
        Require(faultQueryTarget != 0, "public oracle seam installs faulting wrapper-query target");
        for (U tick = 0; tick < 2; ++tick) {
            cur = &original; vlog = &original.log; ResetFp();
            const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
            cur = &owned; vlog = &owned.log; ResetFp();
            const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
            EqU("fault fallback preserves original absolute cursor/end", ownedEnd - A(owned.list.data()),
                originalEnd - A(original.list.data()));
            Same(original, owned, "fault fallback publishes only original-native ordinal results");
            SameLog(original, owned, "fault fallback preserves native erase-shift callback order");
            CheckGrid(ownedRegistry);
            const auto status = ParallelStatus();
            EqU("one private occurrence injects one fault", injectedQueryFaults, 1);
            EqU("private worker fault is reported", status[loco::ParallelFaults], 1);
            EqU("worker exception makes parallel failure sticky", status[loco::ParallelSticky], 1);
            EqU("worker exception code is retained", status[loco::ParallelLastException], 0xe0424c4fu);
            EqU("faulted wave commits no computed prefix", status[loco::ParallelCommitted], 0);
            EqU("discarded private computations are not published workers", status[loco::ParallelWorkerEntities], 0);
            Require(status[loco::ParallelNativeFallbacks] >= (tick + 1) * 24,
                "faulted wave and subsequent sticky stage execute original native occurrences");
            U census[loco::WordCount]; loco::Sample(census);
            EqU("sticky fallback never executes owner clone", census[loco::Cloned], 0);
            Require(census[loco::Native] >= (tick + 1) * 24, "native fallback is counted for every continued stage");
        }
        EqU("fault target restores through public oracle seam",
            loco::SetServiceTargetForTest(loco::WrapperQuery, faultQueryTarget), Fn(&FaultPrivateQuery));
        CallStop(); ++cases;
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Stage B2: module-owned services (use_owned_services, requires use_parallel). Three executions of one synthetic graph of
// ACTIVE (A1 != 0) direct and battle-wrapper occurrences, all through the real image, real ports and real native services:
//   original  the untouched 0x531AF0 stage loop (final-state oracle);
//   serial    the serial clone Stage with per-occurrence service observation (recovered service-sequence oracle);
//   owned     Stage with use_parallel + use_owned_services at 1/4/8 participants, reversed and real-thread dispatch.
// Observer records are written to disjoint absolute-ordinal slots, so duplicate entities in different chunks never race.
// The owner reads records only after every participant has joined.
// ---------------------------------------------------------------------------------------------------------------------
struct OwnedRec { U service, ordinal, thread, cw, mxcsr; };
static constexpr U kOwnedSlots = kFixtureSlots, kOwnedRecs = 16, kOwnedFaultCode = 0xe0424f32u;
struct OwnedLog { OwnedRec rec[kOwnedSlots][kOwnedRecs]; U count[kOwnedSlots]; std::vector<U> order; };
static OwnedLog ownedLogs[3]; // 0 serial RecordService, 1 worker port entry, 2 owner replay
static volatile LONG ownedBad, ownedInjected;
static bool ownedFaultOn;
static U ownedFaultSerial, ownedFaultService;
static std::array<U, loco::OwnedWordCount> OwnedStatus() {
    std::array<U, loco::OwnedWordCount> words{}; loco::SampleOwned(words.data()); return words;
}
static std::array<U, loco::OwnedDetailWordCount> OwnedDetails() {
    std::array<U, loco::OwnedDetailWordCount> words{}; loco::SampleOwnedDetails(words.data()); return words;
}
static std::array<U, loco::OwnedPhaseWordCount> OwnedPhase() {
    std::array<U, loco::OwnedPhaseWordCount> words{}; loco::SampleOwnedPhase(words.data()); return words;
}
static std::array<U, loco::OwnedLoadWordCount> OwnedLoad() {
    std::array<U, loco::OwnedLoadWordCount> words{}; loco::SampleOwnedLoad(words.data()); return words;
}
// Activation is the only place scene/catalog/participant/arena storage is prepared: a Stage must never rebuild or grow it.
static void CheckOwnedLoad(const std::array<U, loco::OwnedLoadWordCount>& activated) {
    const auto load = OwnedLoad();
    const auto phase = OwnedPhase();
    EqU("owned load version", load[loco::OwnedLoadVersion], 1);
    EqU("exactly one activation per generation", load[loco::OwnedLoadCalls], 1);
    for (U i = loco::OwnedLoadUs; i <= loco::OwnedLoadArenaUs; ++i)
        EqU("Stage adds no scene/catalog/participant/arena preparation after activation", load[i], activated[i]);
    EqU("matching model never counts a model change", load[loco::OwnedLoadModelChanges], 0);
    EqU("sized arena never counts a capacity refusal", load[loco::OwnedLoadCapacityRefusals], 0);
    for (U i = loco::OwnedLoadFailureReason; i <= loco::OwnedLoadActual; ++i)
        EqU("successful activation has no failure diagnostics", load[i], 0);
    EqU("catalog preparation never runs on a tick", phase[loco::OwnedPhaseCatalogPrepareUs], 0);
}
static void CheckGridMode(const GridRegistry& registry, bool enabled) {
    const auto grid = GridStatus();
    if (enabled) {
        CheckGrid(registry);
        EqU("explicit grid option publishes only after replay", grid[loco::GridCaptures], 1);
        EqU("explicit grid option preserves native membership", grid[loco::GridMismatches] + grid[loco::GridFaults] +
            grid[loco::GridRefusals] + grid[loco::GridUnsupported], 0);
        const auto v2 = GridV2Status();
        EqU("grid publication is two dispatches plus the optional verifier", v2[loco::GridV2Dispatches],
            ExpectedGridDispatches(v2[loco::GridV2VerifyEnabled] != 0));
        EqU("grid publication uses one build", v2[loco::GridV2Builds], 1);
        EqU("grid publication verification mismatches", v2[loco::GridV2VerifyMismatches], 0);
    } else {
        Require(loco::ReadGrid() == nullptr, "grid-off owned execution publishes no grid");
        EqU("disabled grid retains version metadata", grid[loco::GridVersion], 1);
        for (U i = 1; i < loco::GridWordCount; ++i) EqU("disabled grid performs no import or CSR work", grid[i], 0);
    }
}
static void CheckRelinkStage(U mode) {
    std::array<U, loco::RelinkWordCount> w{}; loco::SampleRelink(w.data());
    EqU("relink version", w[loco::RelinkVersion], 1); EqU("relink mode", w[loco::RelinkMode], mode);
    if (!mode) {
        for (U i = 2; i < loco::RelinkWordCount; ++i) EqU("relink off leaves every counter zero", w[i], 0);
        Require(loco::ReadMoveDelta() == nullptr, "relink off publishes no delta view");
        return;
    }
    EqU("relink counts the stage", w[loco::RelinkStages], 1);
    const U ops = w[loco::RelinkOpsUnlink] + w[loco::RelinkOpsInsert];
    Require(ops != 0 && w[loco::RelinkBatches] != 0, "relink logs and applies batches");
    EqU("batch histogram partitions the batches", w[loco::RelinkBatchesLe16] + w[loco::RelinkBatchesLe256] + w[loco::RelinkBatchesLe2048] + w[loco::RelinkBatchesGt2048], w[loco::RelinkBatches]);
    EqU("flush causes partition the batches", w[loco::RelinkFlushFallback] + w[loco::RelinkFlushClassWrapper] + w[loco::RelinkFlushEnd] + w[loco::RelinkFlushOther], w[loco::RelinkBatches]);
    Require(w[loco::RelinkMaxBatchOps] != 0 && w[loco::RelinkMaxBatchOps] <= ops, "largest batch is bounded by the logged ops");
    EqU("relink refusals", w[loco::RelinkRefusals], 0); EqU("relink faults", w[loco::RelinkFaults], 0);
    EqU("relink serial fallbacks", w[loco::RelinkSerialFallbacks], 0);
    const loco::MoveDeltaView* view = loco::ReadMoveDelta();
    Require(view != nullptr && view->count == ops && view->epoch == 1, "relink publishes this stage's delta view");
    if (mode == 1) {
        EqU("shadow verifies every batch", w[loco::RelinkShadowBatches], w[loco::RelinkBatches]);
        EqU("shadow cell mismatches", w[loco::RelinkShadowMismatchCells], 0); EqU("shadow node mismatches", w[loco::RelinkShadowMismatchNodes], 0);
        EqU("shadow attributes no untapped writer", w[loco::RelinkUntappedWriters], 0);
        EqU("shadow applies nothing live", w[loco::RelinkApplyWallUs], 0);
    } else {
        for (U i : {loco::RelinkShadowBatches, loco::RelinkShadowCells, loco::RelinkShadowMismatchCells, loco::RelinkShadowMismatchNodes, loco::RelinkShadowUs})
            EqU("live mode has no shadow work", w[i], 0);
    }
}
static void CheckOwnedPhase(U count, U lanes, U refused, U validation = 0, bool overflow = false) {
    const auto phase = OwnedPhase(), owned = OwnedStatus();
    EqU("owned phase version", phase[loco::OwnedPhaseVersion], 1);
    EqU("exactly one owned dispatch per Stage", phase[loco::OwnedPhaseDispatches], 1);
    const bool gridDispatches = GridStatus()[loco::GridCaptures] != 0;
    std::array<U, loco::RelinkWordCount> relinkWords{}; loco::SampleRelink(relinkWords.data());
    EqU("one mover dispatch plus the grid publication's and relink apply's separate dispatches", dispatchCalls,
        1u + (gridDispatches ? GridV2Status()[loco::GridV2Dispatches] : 0u) + relinkWords[loco::RelinkDispatches]);
    EqU("phase counts every worklist occurrence", phase[loco::OwnedPhaseListEntities], count);
    const U size = phase[loco::OwnedPhaseChunkSizeLast];
    Require(size >= 32 && size <= 256, "contiguous chunk size stays within the public scheduling bounds");
    const U chunks = (count + size - 1) / size;
    EqU("phase chunks cover the worklist exactly", phase[loco::OwnedPhaseChunks], chunks);
    EqU("owned chunks agree with phase diagnostics", owned[loco::OwnedChunks], chunks);
    if (!gridDispatches) EqU("dispatcher receives all chunks, not one chunk per lane", dispatchedChunks, chunks);
    EqU("largest chunk has the expected entity count", phase[loco::OwnedPhaseMaxChunkEntities], std::min(size, count));
    U histogram = 0;
    for (U i = loco::OwnedPhaseChunkLe16; i <= loco::OwnedPhaseChunkGt1024; ++i) histogram += phase[i];
    // Chunks claimed by a thread without a participant (overflow) are returned untimed and unprocessed.
    if (OwnedDetails()[loco::OwnedDetailQuiet]) { // --loco-quiet reads no clock per chunk: timing words stay zero, counters stay exact
        EqU("quiet chunk histogram is not measured", histogram, 0);
        EqU("quiet chunk time sum is not measured", phase[loco::OwnedPhaseChunkTimeSumUs], 0);
        EqU("quiet chunk time is not measured", owned[loco::OwnedWorkerTimeUs] + owned[loco::OwnedMaxChunkUs], 0);
    } else EqU("chunk histogram partitions every executed chunk", histogram, chunks - phase[loco::OwnedPhaseParticipantOverflow]);
    Require(phase[loco::OwnedPhaseParticipantsUsed] > 0 && phase[loco::OwnedPhaseParticipantsUsed] <= lanes,
        "participant scratch is bounded by the binding capacity");
    EqU("validation refusals are explicit", phase[loco::OwnedPhaseValidationRefusals], validation);
    EqU("duplicate counter is commit-validation refusal count", owned[loco::OwnedDuplicateRefusals], validation);
    EqU("worker outcomes account for every occurrence", phase[loco::OwnedPhaseComputed] +
        phase[loco::OwnedPhaseWorkerRefused] + phase[loco::OwnedPhaseUnprocessed], count);
    if (overflow) {
        Require(phase[loco::OwnedPhaseParticipantOverflow] != 0 && phase[loco::OwnedPhaseUnprocessed] != 0,
            "extra dispatch threads leave their chunks unprocessed for native fallback");
    } else {
        EqU("normal pool has no participant overflow", phase[loco::OwnedPhaseParticipantOverflow], 0);
        EqU("normal pool leaves no occurrence unprocessed", phase[loco::OwnedPhaseUnprocessed], 0);
        EqU("only independently refused entities leave the worker closure", phase[loco::OwnedPhaseWorkerRefused], refused);
        EqU("computed includes later validation refusals", phase[loco::OwnedPhaseComputed], count - refused);
    }
    if (owned[loco::OwnedWorkerDirect] + owned[loco::OwnedWorkerBattle] >= 16)
        Require(phase[loco::OwnedPhaseReplaySamples] != 0, "large replay cohorts retain sampled phase timing");
    EqU("phase reserved word 30", phase[loco::OwnedPhaseReserved30], 0);
    EqU("phase reserved word 31", phase[loco::OwnedPhaseReserved31], 0);
}
struct ShadowSnapshot {
    std::array<U, ntw2_sweep::WordCount> sweep{};
    std::array<U, ntw2_resolve::WordCount> resolve{};
    std::array<U, ntw2_env::WordCount> env{};
    std::array<U, 64> targets{};
};
static ShadowSnapshot Shadows() {
    ShadowSnapshot s;
    ntw2_sweep::Sample(s.sweep.data()); ntw2_resolve::Sample(s.resolve.data()); ntw2_env::Sample(s.env.data(), s.targets.data());
    return s;
}
static void OwnedClear() {
    for (OwnedLog& l : ownedLogs) { std::memset(l.rec, 0, sizeof(l.rec)); std::memset(l.count, 0, sizeof(l.count)); l.order.clear(); }
    ownedBad = 0; ownedInjected = 0;
}
static U OwnedPhaseIndex(loco::OwnedTestPhase phase) {
    switch (phase) {
    case loco::OwnedTestSerial: return 0;
    case loco::OwnedTestPort: return 1;
    case loco::OwnedTestReplay: return 2;
    }
    return 3;
}
static void ObserveOwned(U original, loco::Service service, U ordinal, loco::OwnedTestPhase phase) {
    const U p = OwnedPhaseIndex(phase);
    const U serial = Get<U>(reinterpret_cast<const void*>(static_cast<uintptr_t>(original)), 0x2c);
    const U slot = ordinal; // occurrence-owned slots remain race-free when one entity appears in multiple chunks
    if (p > 2 || slot >= kOwnedSlots || ownedLogs[p].count[slot] >= kOwnedRecs) { InterlockedIncrement(&ownedBad); return; }
    OwnedLog& log = ownedLogs[p];
    unsigned short cw;
    __asm fnstcw word ptr [cw]
    log.rec[slot][log.count[slot]++] = {static_cast<U>(service), ordinal, GetCurrentThreadId(), cw, _mm_getcsr()};
    if (p != 1 && (log.order.empty() || log.order.back() != serial)) log.order.push_back(serial); // owner thread only
    // Fault injection happens at the real port entry, before the port computes or commits anything.
    if (p == 1 && ownedFaultOn && serial == ownedFaultSerial && static_cast<U>(service) == ownedFaultService &&
        InterlockedCompareExchange(&ownedInjected, 1, 0) == 0)
        RaiseException(kOwnedFaultCode, 0, 0, nullptr);
}
static bool PurePort(U service) {
    return service == loco::Sweep || service == loco::Resolve || service == loco::HeightOwner || service == loco::WrapperQuery;
}
static std::vector<U> OwnedSeq(U phase, U slot, bool pureOnly = false) {
    std::vector<U> v;
    for (U n = 0; n < ownedLogs[phase].count[slot]; ++n) {
        const U s = ownedLogs[phase].rec[slot][n].service;
        if (!pureOnly || PurePort(s)) v.push_back(s);
    }
    return v;
}
static void OwnedOrdinals(U phase, U slot, U position, const char* what) {
    for (U n = 0; n < ownedLogs[phase].count[slot]; ++n) EqU(what, ownedLogs[phase].rec[slot][n].ordinal, position);
}
static U OwnedPortTotal() {
    U total = 0; for (U s = 0; s < kOwnedSlots; ++s) total += ownedLogs[1].count[s]; return total;
}
static U OwnerCwFor(U rounding, U precision) { return 0x7fu | (precision << 8) | (rounding << 10); }
static U OwnerMxcsrFor(U rounding, bool ftzDaz) { return 0x1f80u | (rounding << 13) | (ftzDaz ? 0x8040u : 0u); }
static void SetOwnerFp(U rounding, U precision, bool ftzDaz) {
    const unsigned short cw = static_cast<unsigned short>(OwnerCwFor(rounding, precision));
    __asm fninit
    __asm fldcw word ptr [cw]
    _mm_setcsr(OwnerMxcsrFor(rounding, ftzDaz));
}
static void FpOkRounded(U rounding, U precision, bool ftzDaz) {
    unsigned short cw, sw;
    __asm fnstcw word ptr [cw]
    __asm fnstsw word ptr [sw]
    EqU("owner x87 control preserved", cw, OwnerCwFor(rounding, precision));
    Require(((sw >> 11) & 7) == 0, "x87 stack balanced");
    EqU("owner MXCSR control preserved", _mm_getcsr() & 0xffc0, OwnerMxcsrFor(rounding, ftzDaz));
}
struct StageGatherPatch {
    const U savedGather = Get<U>(At(0x1333714), 0xb0), savedGuard = Get<U>(At(0x14dcba0), 0);
    StageGatherPatch() { Put(At(0x1333714), 0xb0, Fn(&StageGather)); stagingOwner = GetCurrentThreadId(); }
    ~StageGatherPatch() { Put(At(0x1333714), 0xb0, savedGather); Put(At(0x14dcba0), 0, savedGuard); }
};

// Active A1 occurrence that the real mover walks end to end without leaving the ownerless terrain closure: B4 = 0, ownerless,
// pending-free, height equal to the constant terrain plane (3.0), no vertical motion, so the original sequence is
// unlink/unlink/sweep/resolve/height/insert/insert (+ the wrapper query for battle).
static Spec OwnedActive(U i, bool wrapper) {
    Spec s = Genuine(i, wrapper ? 1 : 0); s.name = "owned-active";
    s.pos[1] = 3.0f; s.disp[0] = 0.5f + 0.015625f * float(i); s.disp[1] = 0.0f; s.disp[2] = 0.25f - 0.0078125f * float(i & 7);
    s.push[0] = 0.25f + 0.03125f * float(i & 7); s.heading = static_cast<uint16_t>(0x2000 + 0x111 * i);
    s.v80 = 0.1234567f + 0.03125f * float(i); s.v84 = -0.7654321f + 0.015625f * float(i & 3);
    return s;
}
static Scenario OwnedScenario(U count, bool wrapper) {
    Scenario sc; sc.h1 = sc.h2 = 3.0f;
    for (U i = 0; i < count; ++i) {
        Spec s = OwnedActive(i, wrapper);
        // Large scheduling fixtures reuse in-bounds positions, not out-of-range terrain reads. Serial identities remain unique.
        if (count > 32) { s.pos[0] = 10.0f + 4.0f * (i % 24); s.pos[2] = 12.0f + 2.0f * (i % 24); }
        sc.agents.push_back(s); sc.list.push_back(i);
    }
    return sc;
}
static std::vector<U> OwnedExpected(const Spec& s) {
    // Unsupported class callbacks and parked alternate selectors execute untouched native entries, not service taps.
    if (s.vt == VtStage || s.b628) return {};
    const auto v = ExpectedServices(s, Predict(s), s.ec == 1);
    if (!s.oob)
        for (U service : {loco::UnlinkGrid, loco::UnlinkOwner, loco::Sweep, loco::Resolve, loco::HeightOwner, loco::InsertOwner,
                          loco::InsertGrid})
            Require(std::find(v.begin(), v.end(), service) != v.end(), "active fixture reaches every B2 service");
    return v;
}
struct OwnedPlan {
    U lanes = 1, rounding = 0, precision = 2; bool reversed = false, concurrent = false, ftzDaz = false;
    U envRefusals = 0;                     // occurrences refused as env_untested (OwnedNeedsEnv == this)
    std::array<bool, kOwnedSlots> owner{}; // only this occurrence stays on the serial owner path
    U foreignTransforms = 0;
    bool quiet = false, grid = false;
    U relink = 0, relinkMin = 1; // 0 off / 1 shadow / 2 live; parallel-apply threshold in cell operations
    U stagingRefusals = 0, classRefusals = 0, alternateRefusals = 0, unitRefusals = 0;
    std::array<bool, kOwnedSlots> attempted{}; // this occurrence entered private ports before refusing
    std::array<U, loco::OwnedDetailWordCount> details{};
};
static std::vector<U> OwnedStageOnce(const Scenario& sc, const OwnedPlan& plan) {
    const U n = static_cast<U>(sc.list.size());
    Require(n <= kOwnedSlots && sc.agents.size() == n, "owned fixture fits per-entity observer slots");
    for (U i = 0; i < n; ++i) EqU("owned worklist is the identity order without duplicates", sc.list[i], i);
    U ownerCount = 0, workerDirect = 0, workerBattle = 0;
    U activeCandidates = 0, stagingCalls = 0, clampCalls = 0;
    auto expectedDetails = plan.details;
    expectedDetails[loco::OwnedDetailVersion] = 1;
    expectedDetails[loco::OwnedDetailQuiet] = plan.quiet ? 1u : 0u;
    for (U i = 0; i < n; ++i) {
        if (plan.owner[i]) ++ownerCount; else (sc.agents[i].ec == 1 ? workerBattle : workerDirect)++;
        const Spec& s = sc.agents[i];
        if (s.vt == VtGenuine || s.vt == VtClass) {
            activeCandidates += s.a1 != 0;
            expectedDetails[loco::OwnedDetailObservedF0] += s.f0 != 0;
            expectedDetails[loco::OwnedDetailObservedInitialA3] += s.a3 == 0;
            if (!plan.owner[i]) expectedDetails[loco::OwnedDetailWorkerF0] += s.f0 != 0;
            stagingCalls += !s.a3 || s.oob;
        }
        clampCalls += s.clampHolder;
    }
    World original(sc), serial(sc), owned(sc);
    GridRegistry originalRegistry(original), serialRegistry(serial), ownedRegistry(owned);
    std::vector<U> ids; for (U i = 0; i < n; ++i) ids.push_back(i);
    originalRegistry.Set(ids, {}); serialRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
    // World seeds native memberships under ResetFp (round-to-nearest). As in GridNumericCases, rebuild EVERY
    // fixture record under the tested owner controls; untouched memberships retain their original insertion rounding.
    // Doing this for original/serial/owned alike keeps the oracle inputs identical, including native chain order.
    SetOwnerFp(plan.rounding, plan.precision, plan.ftzDaz);
    for (World* w : {&original, &serial, &owned}) {
        cur = w; vlog = &w->discard;
        for (auto& agent : w->agents) NativeGridCall(*agent, false);
        for (auto& agent : w->agents) NativeGridCall(*agent, true);
    }
    ResetFp();
    Same(original, serial, "identical owned pre-run graphs"); Same(original, owned, "identical owned pre-run graphs");
    const U ownerThread = GetCurrentThreadId();

    // A: untouched original bytes under the owner's FP controls.
    PrepareStagingFixture(); cur = &original; vlog = &original.log; SetOwnerFp(plan.rounding, plan.precision, plan.ftzDaz);
    const U originalEnd = CallStageOriginal(original.mgr.p()); FpOkRounded(plan.rounding, plan.precision, plan.ftzDaz); ResetFp();

    // B: serial clone Stage; the observer sees every serial service in recovered order, with the absolute Stage ordinal.
    auto serialBinding = MakeBinding();
    serialBinding.use_grid = serialBinding.verify_grid = plan.grid;
    Require(loco::Start(serialBinding), "owned oracle serial baseline starts");
    if (plan.grid) Require(loco::ActivateOwned(serial.model.p(), FixtureCapacity(serial, n)), "serial baseline activates grid storage");
    OwnedClear();
    Require(loco::SetOwnedServiceObserverForTest(&ObserveOwned) == nullptr, "no stale owned observer");
    PrepareStagingFixture(); cur = &serial; vlog = &serial.log; SetOwnerFp(plan.rounding, plan.precision, plan.ftzDaz);
    const U serialEnd = CallStageModule(serial.mgr.p()); FpOkRounded(plan.rounding, plan.precision, plan.ftzDaz); ResetFp();
    CheckGridMode(serialRegistry, plan.grid);
    EqU("owned observer restores", Fn(loco::SetOwnedServiceObserverForTest(nullptr)), Fn(&ObserveOwned));
    CallStop();
    EqU("serial observer sees no bad records", ownedBad, 0);
    std::vector<std::vector<U>> baseline(n);
    for (U i = 0; i < n; ++i) {
        baseline[i] = OwnedSeq(0, i);
        Require(baseline[i] == OwnedExpected(sc.agents[i]), "serial service sequence equals the recovered mover order");
        OwnedOrdinals(0, i, i, "serial ordinal is the absolute Stage ordinal");
        if (!baseline[i].empty()) EqU("serial sequence is replay-safe owner-thread data", ownedLogs[0].rec[i][0].thread, ownerThread);
    }
    EqU("serial clone Stage returns exact end", serialEnd - A(serial.list.data()), originalEnd - A(original.list.data()));
    Same(original, serial, "serial clone Stage equals untouched original on active A1");
    SameLog(original, serial, "serial clone owner-virtual order");

    // C: owned services.
    auto binding = MakeBinding(); binding.use_parallel = true; binding.use_owned_services = true;
    binding.use_grid = binding.verify_grid = plan.grid;
    binding.use_quiet = plan.quiet; binding.use_shadow = plan.quiet; // quiet must override even an explicit shadow request
    binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = plan.lanes - 1;
    binding.use_relink_shadow = plan.relink == 1; binding.use_relink_workers = plan.relink == 2;
    reverseChunks = plan.reversed; dispatchLanes = plan.lanes; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
    concurrentChunks = plan.concurrent;
    Require(loco::Start(binding), "owned-services oracle starts through public binding");
    loco::SetRelinkMinCellsForTest(plan.relinkMin); relinkRun = plan.relink != 0;
    Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, n)), "owned arena activates for the Stage's own World.model");
    const auto activated = OwnedLoad();
    EqU("activation ran once", activated[loco::OwnedLoadCalls], 1);
    const auto initial = OwnedStatus();
    // Cached catalog accounting of this non-empty owned scene: capacity bytes sum to the catalog storage word, every
    // unique logical count fits its element-sized capacity, and Stage neither refreshes nor changes either cache.
    std::array<U, loco::StorageWordCount> storageBefore{}; loco::SampleStorage(storageBefore.data());
    std::array<U, loco::CatalogStorageWordCount> catalogBefore{}; loco::SampleCatalogStorage(catalogBefore.data());
    EqU("cached catalog capacity bytes sum to the catalog storage word",
        catalogBefore[0] + catalogBefore[1] + catalogBefore[2] + catalogBefore[3] + catalogBefore[4], storageBefore[loco::StorageCatalog]);
    {
        static const U elementBytes[5] = {32, 124, 20, 56, 16}; // ring, capsule, wall, edge, polygon point
        for (U i = 0; i < 5; ++i)
            Require(U(catalogBefore[i]) >= catalogBefore[5 + i] * elementBytes[i], "catalog capacity covers its unique logical count");
    }
    EqU("owned status version", initial[loco::OwnedVersion], 1);
    EqU("owned status enabled", initial[loco::OwnedEnabled], 1);
    const auto shadowBefore = Shadows();
    const auto timingBefore = Services();
    std::array<U, loco::GateWordCount> gatesBefore{}, gatesAfter{};
    loco::SampleGates(gatesBefore.data());
    OwnedClear();
    Require(loco::SetOwnedServiceObserverForTest(&ObserveOwned) == nullptr, "owned observer installs");
    PrepareStagingFixture(); cur = &owned; vlog = &owned.log; SetOwnerFp(plan.rounding, plan.precision, plan.ftzDaz);
    const U ownedEnd = CallStageModule(owned.mgr.p()); FpOkRounded(plan.rounding, plan.precision, plan.ftzDaz); ResetFp();
    loco::SetOwnedServiceObserverForTest(nullptr);
    EqU("owned Stage returns exact native end pointer", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
    Same(original, owned, "owned services bit-exact native state including private-prefix copyback");
    SameLog(original, owned, "owned owner callback and staging order");
    CheckGridMode(ownedRegistry, plan.grid);
    CheckRelinkStage(plan.relink); relinkRun = false;
    {
        std::array<U, loco::StorageWordCount> storageAfter{}; loco::SampleStorage(storageAfter.data());
        std::array<U, loco::CatalogStorageWordCount> catalogAfter{}; loco::SampleCatalogStorage(catalogAfter.data());
        Require(catalogAfter == catalogBefore && storageAfter == storageBefore,
            "Stage leaves the cached catalog counts, bytes and storage breakdown unchanged");
    }
    EqU("owned observer has no bad records", ownedBad, 0);
    for (const World* w : {&original, &serial, &owned}) {
        U staged = 0, clamped = 0;
        for (const VRec& r : w->log) { staged += r.id == RecStaging; clamped += r.id == RecClampHolder; }
        EqU("native selector stages exactly when resulting A3 is zero", staged, stagingCalls);
        EqU("genuine native clamp callback reaches its safe holder exactly once per clamp", clamped, clampCalls);
        for (U i = 0; i < n; ++i) {
            EqU("initial or OOB-cleared A3 remains zero; in-bounds A3 stays set", Get<B>(w->agents[i]->b.p(), 0xa3),
                (!sc.agents[i].a3 || sc.agents[i].oob) ? 0u : 1u);
            if (sc.agents[i].clampHolder) Eq("genuine native F0 clamp writes exact bound", Get<float>(w->agents[i]->b.p(), 0x48), sc.agents[i].fx);
        }
    }
    const auto detail = OwnedDetails();
    static const char* const detailLabels[] = {NTW2_LOCO_OWNED_DETAIL_LABELS};
    static_assert(sizeof(detailLabels) / sizeof(detailLabels[0]) == loco::OwnedDetailWordCount, "detail labels cover status");
    for (U i = 0; i < loco::OwnedDetailWordCount; ++i) EqU(detailLabels[i], detail[i], expectedDetails[i]);
    if (plan.quiet) {
        loco::SampleGates(gatesAfter.data());
        Require(gatesAfter == gatesBefore, "quiet performs no all-gates histogram census");
        for (U i = 1; i < loco::GateWordCount; ++i)
            if (i != loco::GateEnforcedMask) EqU("quiet histogram stays empty", gatesAfter[i], 0);
        CheckServices(Services(), false);
        Require(Services() == timingBefore, "quiet performs no per-service timing");
        const auto shadowAfter = Shadows();
        // Owned services still initialize the ports (Enabled==1); quiet means no shadow comparison ever ran.
        EqU("quiet runs no sweep shadow calls", shadowAfter.sweep[3], 0);
        EqU("quiet runs no resolve shadow calls", shadowAfter.resolve[ntw2_resolve::Calls], 0);
        EqU("quiet runs no environment shadow calls", shadowAfter.env[ntw2_env::Calls], 0);
        Require(shadowAfter.sweep == shadowBefore.sweep && shadowAfter.resolve == shadowBefore.resolve &&
            shadowAfter.env == shadowBefore.env && shadowAfter.targets == shadowBefore.targets,
            "quiet performs no shadow comparisons or callback histogram observation");
    }

    const auto ps = ParallelStatus(), os = OwnedStatus(), grid = GridStatus();
    if (grid[loco::GridMismatches] || grid[loco::GridFaults] || grid[loco::GridRefusals])
        std::fprintf(stderr, "Owned grid: mismatches=%u faults=%u refusals=%u unsupported=%u captures=%u "
            "lanes=%u reversed=%u concurrent=%u rounding=%u precision=%u ftz_daz=%u\n",
            grid[loco::GridMismatches], grid[loco::GridFaults], grid[loco::GridRefusals], grid[loco::GridUnsupported],
            grid[loco::GridCaptures], plan.lanes, plan.reversed, plan.concurrent, plan.rounding, plan.precision, plan.ftzDaz);
    EqU("owned has no parallel worker faults", ps[loco::ParallelFaults], 0);
    EqU("owned has no owned faults", os[loco::OwnedFaults], 0);
    EqU("owned has no sticky failure", ps[loco::ParallelSticky], 0);
    EqU("owned has no exception", ps[loco::ParallelLastException], 0);
    EqU("owned has no invalidated output", ps[loco::ParallelInvalidated], 0);
    CheckOwnedPhase(n, plan.lanes, ownerCount);
    CheckOwnedLoad(activated);
    // B2 is genuinely exercised: active A1 occurrences execute on workers, nothing is refused for env/sweep/resolve.
    EqU("worker entities are the supported active cohort", ps[loco::ParallelWorkerEntities], n - ownerCount);
    EqU("every worker output is committed", ps[loco::ParallelCommitted], n - ownerCount);
    EqU("only individually refused occurrences stay on owner", ps[loco::ParallelOwnerEntities], ownerCount);
    EqU("active direct workers", os[loco::OwnedWorkerDirect], workerDirect);
    EqU("active battle workers", os[loco::OwnedWorkerBattle], workerBattle);
    EqU("no inactive occurrence in the active cohort", os[loco::OwnedWorkerInactive], 0);
    EqU("active-share denominator counts actual active candidates", os[loco::OwnedActiveEntities], activeCandidates);
    EqU("owner fallback share remains visible", os[loco::OwnedFallbackEntities], ownerCount);
    if (!plan.envRefusals)
        for (loco::ParallelWord w : {loco::ParallelNeedsEnv, loco::ParallelNeedsSweep, loco::ParallelNeedsResolve})
            EqU("legacy A1 environment/sweep/resolve owner reasons stay zero", ps[w], 0);
    for (loco::OwnedWord w : {loco::OwnedNeedsSweep, loco::OwnedNeedsResolve, loco::OwnedNeedsEvent,
                              loco::OwnedNeedsCapacity, loco::OwnedNeedsDuplicate, loco::OwnedNeedsPending})
        EqU("no unrelated owner refusal", os[w], 0);
    EqU("only genuine class-wrapper occurrences get the class reason", os[loco::OwnedNeedsClassWrapper], plan.classRefusals);
    {   // class-wrapper census: one observation per refused 0x132BA04 occurrence; the fixture's wrappers have an empty or one-entry child list
        std::array<U, loco::CwWordCount> cw{}; loco::SampleClassWrapper(cw.data());
        EqU("census version", cw[loco::CwVersion], 1);
        EqU("census observes exactly the class-wrapper refusals", cw[loco::CwOccurrences], plan.classRefusals);
        EqU("census children histogram partitions the occurrences", cw[loco::CwKids0] + cw[loco::CwKids1] + cw[loco::CwKids2Plus] + cw[loco::CwUnreadable], plan.classRefusals);
        EqU("census aim-state histogram partitions the occurrences", cw[loco::CwState9] + cw[loco::CwState8] + cw[loco::CwStateOther], plan.classRefusals);
        EqU("census children total", cw[loco::CwChildrenTotal], cw[loco::CwKids1] + 2 * cw[loco::CwKids2Plus]);
        Require(cw[loco::CwKids2Plus] == 0 && cw[loco::CwVtOverflow] == 0, "fixture wrappers carry at most one child");
        U byVtable = 0; for (U k = 0; k < 8; ++k) byVtable += cw[loco::CwVtBase + 2 * k + 1];
        EqU("census child vtable table accounts for every non-null child", byVtable + cw[loco::CwNullChildren], cw[loco::CwChildrenTotal]);
    }
    EqU("alternate wrapper is not battle or class wrapper", os[loco::OwnedNeedsAlternateWrapper], plan.alternateRefusals);
    EqU("only actual staging or clamp refusals get the staging reason", os[loco::OwnedNeedsStaging], plan.stagingRefusals);
    EqU("env_untested counts exactly the unvalidated environment occurrences", os[loco::OwnedNeedsEnv], plan.envRefusals);
    EqU("only the unproven transform occurrence gets the transform reason", os[loco::OwnedNeedsForeignTransform], plan.foreignTransforms);
    EqU("own classification refusals never spread to siblings", os[loco::OwnedNeedsUnit], plan.unitRefusals);

    // Per-entity replay sequence, absolute ordinals and the owner-side order.
    std::array<U, loco::ServiceCount> replayCounts{}, expectedCounts{};
    std::vector<U> workerSerials;
    U foreignThreads = 0;
    for (U i = 0; i < n; ++i) {
        if (plan.owner[i]) {
            EqU("refused occurrence never replays a computed prefix", ownedLogs[2].count[i], 0);
            EqU("only attempted private computations enter worker ports", ownedLogs[1].count[i] != 0, plan.attempted[i] ? 1u : 0u);
            if (plan.quiet) EqU("quiet owner fallback skips diagnostic serial observation", ownedLogs[0].count[i], 0);
            else Require(OwnedSeq(0, i) == baseline[i], "refused entity executes the serial owner path with the original sequence");
            OwnedOrdinals(0, i, i, "refused serial ordinal");
            OwnedOrdinals(1, i, i, "refused private computation keeps the absolute ordinal");
            continue;
        }
        workerSerials.push_back(Get<U>(owned.agents[i]->b.p(), 0x2c));
        Require(ownedLogs[0].count[i] == 0, "worker entity never executes a serial service");
        Require(OwnedSeq(2, i) == baseline[i], "per-entity owner replay sequence equals the serial original sequence");
        OwnedOrdinals(2, i, i, "replay ordinal is the absolute Stage ordinal");
        EqU("replay is owner-side", ownedLogs[2].rec[i][0].thread, ownerThread);
        for (U s : baseline[i]) ++expectedCounts[s];
        for (U s : OwnedSeq(2, i)) ++replayCounts[s];
        Require(!OwnedSeq(1, i).empty(), "worker reaches its real ports");
        Require(OwnedSeq(1, i, true) == [&] { std::vector<U> v; for (U s : baseline[i]) if (PurePort(s)) v.push_back(s); return v; }(),
            "worker port entries follow the serial pure-service order");
        OwnedOrdinals(1, i, i, "worker port ordinal is the absolute Stage ordinal");
        for (U r = 0; r < ownedLogs[1].count[i]; ++r) {
            const OwnedRec& rec = ownedLogs[1].rec[i][r];
            EqU("worker installs owner's full x87 control", rec.cw, OwnerCwFor(plan.rounding, plan.precision));
            EqU("worker installs owner's full MXCSR control bits", rec.mxcsr & 0xffc0, OwnerMxcsrFor(plan.rounding, plan.ftzDaz));
            if (rec.thread != ownerThread) ++foreignThreads;
        }
    }
    Require(ownedLogs[2].order == workerSerials, "owner replay publishes whole occurrences in Stage order");
    EqU("replayed unlink-grid", os[loco::OwnedReplayUnlinkGrid], expectedCounts[loco::UnlinkGrid]);
    EqU("replayed unlink-owner", os[loco::OwnedReplayUnlinkOwner], expectedCounts[loco::UnlinkOwner]);
    EqU("replayed insert-owner", os[loco::OwnedReplayInsertOwner], expectedCounts[loco::InsertOwner]);
    EqU("replayed insert-grid", os[loco::OwnedReplayInsertGrid], expectedCounts[loco::InsertGrid]);
    Require(replayCounts == expectedCounts, "replay emitted every serial service exactly once");
    Require(ps[loco::ParallelReplayedServices] != 0 || n == ownerCount, "workers replay owner services");
    if (plan.concurrent && plan.lanes > 1 && !ownerCount)
        Require(foreignThreads != 0, "owned ports execute on real non-owner threads");
    auto result = Canon(owned);
    if (plan.grid) {
        const auto v2 = GridV2Status();
        EqU("every published record has an explicit result/live read source",
            v2[loco::GridV2CommittedRecords] + v2[loco::GridV2RecordReads], U(ids.size()));
        if (!ownerCount) EqU("fully committed cohort publishes result-buffer geometry",
            v2[loco::GridV2CommittedRecords], n);
        const auto csr = GridCanonical(owned, *loco::ReadGrid(), false);
        result.insert(result.end(), csr.begin(), csr.end());
    }
    CallStop(); Require(loco::ReadGrid() == nullptr, "owned Stop invalidates view");
    {
        std::array<U, loco::CatalogStorageWordCount> released{}; loco::SampleCatalogStorage(released.data());
        for (U word : released) EqU("Stop clears the cached catalog breakdown", word, 0);
    }
    ++cases; return result;
}

// A worker port faults at its real entry (before computing or committing). The whole wave is discarded, the original
// native loop resumes at the faulting ordinal's wave start with identical state, and the failure is sticky.
static void OwnedFaultOnce(U lanes, bool reversed, bool concurrent, bool wrapper, loco::Service service, bool quiet = false) {
    static char label[128];
    std::snprintf(label, sizeof(label), "owned port fault service=%u wrapper=%d lanes=%u rev=%d rt=%d quiet=%d",
        static_cast<U>(service), wrapper, lanes, reversed, concurrent, quiet);
    currentCase = label;
    Scenario sc = OwnedScenario(27, wrapper);
    sc.agents[24] = Callback(24, 3, 0); // erase-shift behind the absolute cursor once fallback reaches this ordinal
    constexpr U kFaultIndex = 8;
    World original(sc), owned(sc);
    GridRegistry originalRegistry(original), ownedRegistry(owned);
    std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
    originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
    auto binding = MakeBinding(); binding.use_parallel = true; binding.use_owned_services = true;
    binding.use_quiet = quiet;
    binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
    reverseChunks = reversed; dispatchLanes = lanes; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
    concurrentChunks = concurrent;
    Require(loco::Start(binding), "owned fault oracle starts");
    Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, U(sc.list.size()))), "owned fault arena activates for its World.model");
    OwnedClear();
    ownedFaultOn = true; ownedFaultService = static_cast<U>(service); ownedFaultSerial = Get<U>(owned.agents[kFaultIndex]->b.p(), 0x2c);
    Require(loco::SetOwnedServiceObserverForTest(&ObserveOwned) == nullptr, "fault observer installs");
    U portsAfterFirst = 0;
    for (U tick = 0; tick < 2; ++tick) {
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        EqU("owned fault fallback preserves original absolute cursor/end", ownedEnd - A(owned.list.data()),
            originalEnd - A(original.list.data()));
        Same(original, owned, "owned fault fallback publishes only original-native ordinal results");
        SameLog(original, owned, "owned fault fallback preserves native erase-shift callback order");
        CheckGridMode(ownedRegistry, false);
        const auto ps = ParallelStatus(), os = OwnedStatus();
        EqU("fault run retains quiet setting", OwnedDetails()[loco::OwnedDetailQuiet], quiet ? 1u : 0u);
        if (quiet) CheckServices(Services(), false);
        EqU("owned observer has no bad records", ownedBad, 0);
        EqU("exactly one port entry injects", ownedInjected, 1);
        EqU("port fault is reported", ps[loco::ParallelFaults], 1);
        EqU("port fault is reported in owned status", os[loco::OwnedFaults], 1);
        EqU("port fault makes owned failure sticky", ps[loco::ParallelSticky], 1);
        EqU("port exception code is retained", ps[loco::ParallelLastException], kOwnedFaultCode);
        EqU("fault reports the original ordinal", ps[loco::ParallelLastOrdinal], kFaultIndex);
        EqU("fault reports the original identity", ps[loco::ParallelLastEntity], A(owned.agents[kFaultIndex]->b.p()));
        EqU("fault reports the original serial", ps[loco::ParallelLastSerial], ownedFaultSerial);
        EqU("faulted wave commits no computed prefix", ps[loco::ParallelCommitted], 0);
        EqU("discarded private computations are not published workers", ps[loco::ParallelWorkerEntities], 0);
        EqU("no occurrence of the discarded wave replays services", U(ownedLogs[2].order.size()), 0);
        for (U s = 0; s < kOwnedSlots; ++s) EqU("owner replay log stays empty", ownedLogs[2].count[s], 0);
        EqU("fallback executes only untouched native occurrences", U(ownedLogs[0].order.size()), 0);
        const auto faulted = OwnedSeq(1, kFaultIndex);
        Require(!faulted.empty() && faulted.back() == static_cast<U>(service), "fault entity stops exactly at the injected port");
        Require(ps[loco::ParallelNativeFallbacks] >= (tick + 1) * 24, "fallback stage executes original native occurrences");
        U census[loco::WordCount]; loco::Sample(census);
        EqU("sticky fallback never executes owner clone", census[loco::Cloned], 0);
        Require(census[loco::Native] >= (tick + 1) * 24, "native fallback is counted for every continued stage");
        if (!tick) portsAfterFirst = OwnedPortTotal();
        else EqU("sticky stage reaches no worker port", OwnedPortTotal(), portsAfterFirst);
    }
    ownedFaultOn = false;
    loco::SetOwnedServiceObserverForTest(nullptr);
    CallStop(); ++cases;
}
static void OwnedFaultCases() {
    StageGatherPatch gather;
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) for (bool concurrent : {false, true}) {
        if (concurrent && lanes == 1) continue;
        for (bool wrapper : {false, true}) {
            for (loco::Service s : {loco::Sweep, loco::Resolve, loco::HeightOwner}) OwnedFaultOnce(lanes, reversed, concurrent, wrapper, s);
            if (wrapper) OwnedFaultOnce(lanes, reversed, concurrent, true, loco::WrapperQuery);
        }
    }
    // Quiet removes diagnostics, not the real private-port fault boundary or sticky native recovery.
    for (U lanes : {1u, 4u, 8u}) for (bool wrapper : {false, true})
        OwnedFaultOnce(lanes, false, lanes > 1, wrapper, loco::Sweep, true);
}

static void OwnedServiceCases() {
    StageGatherPatch gather;
    currentCase = "owned services require parallel";
    { auto bad = MakeBinding(); bad.use_owned_services = true; Require(!loco::Start(bad), "use_owned_services without use_parallel is refused"); }
    // Active A1 direct and battle wrappers across participants, reversed chunks and real foreign FP controls.
    for (bool wrapper : {false, true}) {
        const Scenario sc = OwnedScenario(24, wrapper);
        static char label[96];
        std::snprintf(label, sizeof(label), "owned active A1 %s serial vs owned 1/4/8", wrapper ? "battle" : "direct"); currentCase = label;
        std::vector<U> baseline;
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) for (bool concurrent : {false, true}) {
            if (concurrent && lanes == 1) continue;
            OwnedPlan plan; plan.lanes = lanes; plan.reversed = reversed; plan.concurrent = concurrent;
            const auto output = OwnedStageOnce(sc, plan);
            if (baseline.empty()) baseline = output;
            else Require(output == baseline, "owned native outputs and CSR are deterministic across lanes, order and threads");
        }
        // Worker FP install/restore on real foreign threads that START with FTZ|DAZ and 53-bit x87 (dispatcher seeds), against
        // owner controls with every rounding mode, 53/64-bit x87 precision and FTZ|DAZ on or off.
        struct Fp { U rounding, precision; bool ftz; };
        for (const Fp fp : {Fp{1, 2, false}, Fp{2, 2, true}, Fp{3, 2, false}, Fp{0, 3, false}, Fp{0, 3, true}, Fp{1, 3, true}, Fp{0, 2, true}}) {
            std::vector<U> rbaseline;
            for (U lanes : {1u, 4u, 8u}) {
                OwnedPlan plan; plan.lanes = lanes; plan.rounding = fp.rounding; plan.precision = fp.precision; plan.ftzDaz = fp.ftz;
                plan.concurrent = lanes > 1; plan.reversed = fp.rounding & 1;
                const auto output = OwnedStageOnce(sc, plan);
                if (rbaseline.empty()) rbaseline = output;
                else Require(output == rbaseline, "owner x87/MXCSR controls are installed on every worker and restored");
            }
        }
        // The current owner (+10 != 0) reaches the unclosed owner/ring environment: env_untested keeps only that occurrence
        // serial (index 0 keeps the fixture's global ring/plane data slots those of an owner-1 mover); the rest still run on workers.
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            currentCase = "owned env_untested refusal for a current owner";
            Scenario env = sc; env.agents[0].owner = 1;
            OwnedPlan plan; plan.lanes = lanes; plan.reversed = reversed; plan.concurrent = lanes > 1;
            plan.owner[0] = true; plan.envRefusals = 1;
            OwnedStageOnce(env, plan);
        }
    }
    // Shared A+1F0 contexts are read-only. Interleaving them must not merge independent entities into a refusal unit.
    auto unitScenario = [](bool battleMix) {
        Scenario sc = OwnedScenario(24, false);
        for (U i = 0; i < 24; ++i) {
            if (battleMix && (i % 4) == 3) sc.agents[i] = OwnedActive(i, true);
            sc.agents[i].unit = i < 18 ? static_cast<B>(1 + i % 3) : B(0);
        }
        return sc;
    };
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        currentCase = "owned interleaved read-only contexts do not constrain worker scheduling";
        OwnedPlan plan; plan.lanes = lanes; plan.reversed = reversed; plan.concurrent = lanes > 1;
        OwnedStageOnce(unitScenario(true), plan);
    }
    // A+170 is the unproven foreign transform: only its own entity is refused, including when it has shared-context siblings.
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        currentCase = "owned foreign transform refuses only its own entity";
        Scenario sc = unitScenario(true);
        sc.agents[4].xform = 1;
        OwnedPlan plan; plan.lanes = lanes; plan.reversed = reversed; plan.concurrent = lanes > 1;
        plan.owner[4] = true; plan.foreignTransforms = 1;
        OwnedStageOnce(sc, plan);
        currentCase = "owned singleton foreign transform refusal";
        sc = unitScenario(false);
        sc.agents[20].xform = 1; // null context: only itself leaves the worker run
        OwnedPlan single; single.lanes = lanes; single.reversed = reversed; single.concurrent = lanes > 1;
        single.owner[20] = true; single.foreignTransforms = 1;
        OwnedStageOnce(sc, single);
        currentCase = "owned parked context member leaves siblings on workers";
        sc = unitScenario(true); sc.agents[4].b628 = 1; sc.agents[4].b62c = 3;
        OwnedPlan parked; parked.lanes = lanes; parked.reversed = reversed; parked.concurrent = lanes > 1;
        parked.owner[4] = true; parked.unitRefusals = 1;
        OwnedStageOnce(sc, parked);
    }
}

static void OwnedAdmissionCases() {
    StageGatherPatch gather;
    for (bool wrapper : {false, true}) {
        Scenario inside = OwnedScenario(24, wrapper);
        for (Spec& s : inside.agents) s.f0 = 1;
        currentCase = wrapper ? "owned F0 in-bounds active battle remains worker" : "owned F0 in-bounds active direct remains worker";
        std::vector<U> baseline;
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            OwnedPlan plan; plan.lanes = lanes; plan.reversed = reversed; plan.concurrent = lanes > 1;
            const auto output = OwnedStageOnce(inside, plan);
            if (baseline.empty()) baseline = output;
            else Require(output == baseline, "F0 no-clamp native fields, memberships and service sequence are lane/order exact");
        }
        for (U lanes : {1u, 4u, 8u}) {
            currentCase = wrapper ? "quiet owned active F0 battle and owner fallback" : "quiet owned active F0 direct and owner fallback";
            Scenario quiet = inside;
            quiet.agents[0].xform = 1; // admitted serial clone fallback reaches real service taps, not only worker/replay ports
            OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.quiet = true;
            plan.owner[0] = true; plan.foreignTransforms = 1;
            OwnedStageOnce(quiet, plan);
        }
        for (U kind = 0; kind < 3; ++kind) for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            Scenario sc = OwnedScenario(24, wrapper);
            OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed;
            // Earlier and later same-context siblings must both commit despite this entity's dynamic refusal.
            for (U i : {1u, 4u, 7u}) sc.agents[i].unit = 1;
            plan.owner[4] = true; plan.attempted[4] = true; plan.stagingRefusals = 1;
            Spec& culprit = sc.agents[4];
            if (kind == 0) {
                currentCase = "owned initial A3-zero stages on owner, distinct from resulting OOB";
                culprit.a3 = 0;
                plan.details[loco::OwnedDetailInitialA3] = 1;
            } else if (kind == 1) {
                currentCase = "owned initially in-bounds A3-one crosses map bound and stages on owner";
                culprit.pos[0] = 999.75f; culprit.disp[0] = 4.0f; culprit.oob = true; sc.mx[0] = 1000.0f;
                plan.details[loco::OwnedDetailResultA3] = 1;
            } else {
                currentCase = "owned actual F0 clamp refuses before genuine native callback on worker";
                culprit.f0 = 1; culprit.clampHolder = true; culprit.fx = 30.0f; sc.cmn[0] = 30.0f;
                plan.details[loco::OwnedDetailClampCallback] = 1;
            }
            OwnedStageOnce(sc, plan);
        }
    }
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        currentCase = "owned known class, unknown class, battle and alternate reasons stay distinct";
        Scenario sc = OwnedScenario(24, false);
        for (U i = 0; i < sc.agents.size(); ++i) if (i & 1) sc.agents[i] = OwnedActive(i, true);
        sc.agents[3].vt = VtClass; sc.agents[3].ec = 0; sc.agents[3].b688 = 2; // exact 132BA04 route with the 0x5F3040 pre-step active: refused (an empty wrapper is admitted)
        sc.agents[12] = Callback(12, 0, 0); // unknown vtable: genuine native stage loop calls its data-slot callback
        sc.agents[15].ec = 0; sc.agents[15].b628 = 1; sc.agents[15].b62c = 4; // native alternate wrapper
        OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed;
        for (U i : {0u, 3u, 6u}) sc.agents[i].unit = 1;
        plan.owner[3] = plan.owner[12] = plan.owner[15] = true;
        plan.classRefusals = 1; plan.alternateRefusals = 1; plan.unitRefusals = 1;
        plan.details[loco::OwnedDetailClassWrapper] = 1;
        plan.details[loco::OwnedDetailOtherClass] = 1;
        plan.details[loco::OwnedDetailAlternate] = 1;
        OwnedStageOnce(sc, plan);
    }
    currentCase = "owned and explicit grid option coexist";
    OwnedPlan grid; grid.lanes = 4; grid.concurrent = true; grid.grid = true;
    OwnedStageOnce(OwnedScenario(24, true), grid);
    for (bool wrapper : {false, true}) {
        std::vector<U> baseline;
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            currentCase = "owned many contiguous chunks per bounded participant pool";
            OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed;
            Scenario sc = OwnedScenario(320, wrapper);
            for (U i = 0; i < sc.agents.size(); ++i) { sc.agents[i].unit = B(1 + i % 3); sc.agents[i].f0 = 1; }
            const auto output = OwnedStageOnce(sc, plan);
            Require(dispatchedChunks > lanes, "large worklist dispatches more chunks than participants");
            if (baseline.empty()) baseline = output;
            else Require(output == baseline, "many-chunk native state is exact across claim order and participant count");
        }
    }
}

static void OwnedValidationCases() {
    StageGatherPatch gather;
    for (U variant : {0u, 1u, 2u}) for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true})
        for (bool quiet : {false, true}) {
        const bool duplicate = variant == 1; // 2: the mutated later entity is an admitted empty class wrapper whose +688 the child callback sets
        currentCase = duplicate ? "owned duplicate across chunk boundaries validates at replay" :
            "owned genuine class child mutates later computed entity before replay";
        Scenario sc = OwnedScenario(96, false);
        constexpr U staleOrdinal = 64;
        if (duplicate) sc.list.insert(sc.list.begin() + staleOrdinal, 2);
        else {
            sc.agents[0].vt = VtClass; sc.agents[0].classMutate = true; sc.agents[0].arg = staleOrdinal;
            sc.agents[0].unit = sc.agents[staleOrdinal].unit = 1;
            if (variant == 2) { sc.agents[staleOrdinal].vt = VtClass; classMutateOffset = 0x688; classMutateBits = 2; }
        }
        const U count = U(sc.list.size()), preRefused = duplicate ? 0u : 1u;
        World original(sc), serial(sc), owned(sc);
        GridRegistry originalRegistry(original), serialRegistry(serial), ownedRegistry(owned);
        std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
        originalRegistry.Set(ids, {}); serialRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
        Same(original, owned, "validation fixture starts with identical native graphs");
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        Require(loco::Start(MakeBinding()), "validation serial baseline starts without grid");
        OwnedClear(); loco::SetOwnedServiceObserverForTest(&ObserveOwned);
        PrepareStagingFixture(); cur = &serial; vlog = &serial.log; ResetFp();
        const U serialEnd = CallStageModule(serial.mgr.p()); FpOk();
        loco::SetOwnedServiceObserverForTest(nullptr);
        EqU("validation serial end matches original", serialEnd - A(serial.list.data()), originalEnd - A(original.list.data()));
        Same(original, serial, "validation serial state matches untouched original");
        SameLog(original, serial, "validation serial class child callback order");
        CheckGridMode(serialRegistry, false);
        std::vector<std::vector<U>> baseline(count);
        for (U i = 0; i < count; ++i) baseline[i] = OwnedSeq(0, i);
        EqU("serial validation observer has no invalid records", ownedBad, 0);
        CallStop();
        auto binding = MakeBinding(); binding.use_parallel = binding.use_owned_services = true;
        binding.use_quiet = quiet; binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
        dispatchLanes = lanes; reverseChunks = reversed; concurrentChunks = lanes > 1;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        Require(loco::Start(binding), "per-occurrence validation oracle starts");
        Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, count)), "validation arena activates for its World.model");
        OwnedClear(); loco::SetOwnedServiceObserverForTest(&ObserveOwned);
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        loco::SetOwnedServiceObserverForTest(nullptr);
        EqU("validation preserves the native cursor/end", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
        Same(original, owned, "stale speculative result is discarded and native ordinal state is bit-exact");
        SameLog(original, owned, "class child traversal executes once on the owner in native order");
        CheckGridMode(ownedRegistry, false);
        CheckOwnedPhase(count, lanes, preRefused, 1);
        const auto phase = OwnedPhase(), os = OwnedStatus(), ps = ParallelStatus();
        const auto detail = OwnedDetails();
        if (duplicate)
            Require(2 / phase[loco::OwnedPhaseChunkSizeLast] != staleOrdinal / phase[loco::OwnedPhaseChunkSizeLast],
                "duplicate occurrences are in distinct worker chunks");
        else {
            U calls = 0; for (const auto& r : owned.log) calls += r.id == RecClassMutate;
            EqU("genuine class wrapper child performs one later-input mutation", calls, 1);
        }
        EqU("validation is not a worker fault", os[loco::OwnedFaults] + ps[loco::ParallelFaults] + ps[loco::ParallelSticky], 0);
        EqU("only stale output and class culprit stay on owner", ps[loco::ParallelOwnerEntities], preRefused + 1);
        EqU("all other ordinals still commit", ps[loco::ParallelCommitted], count - preRefused - 1);
        EqU("one stale occurrence has an own validation refusal", os[loco::OwnedNeedsUnit], 1);
        EqU("one actual class wrapper, never its sibling", os[loco::OwnedNeedsClassWrapper], preRefused);
        EqU("detail counts observed class wrappers (variant 2: the stale class target is observed again natively)", detail[loco::OwnedDetailClassWrapper], preRefused + (variant == 2 ? 1u : 0u));
        for (U w : {loco::OwnedDetailUnitClass, loco::OwnedDetailUnitStaging, loco::OwnedDetailUnitOther})
            EqU("obsolete unit-blocked detail remains zero", detail[w], 0);
        EqU("ordinal-keyed observer is race-free for duplicate identities", ownedBad, 0);
        Require(ownedLogs[1].count[staleOrdinal] != 0, "stale entity actually computed before owner replay");
        for (U i = 0; i < count; ++i) {
            const bool fallback = i == staleOrdinal || (!duplicate && i == 0);
            if (fallback) {
                EqU("stale/class output never replays", ownedLogs[2].count[i], 0);
                if (quiet) EqU("quiet stale fallback skips serial diagnostics", ownedLogs[0].count[i], 0);
                else Require(OwnedSeq(0, i) == baseline[i], "fallback consumes current native inputs with original service sequence");
            } else {
                Require(OwnedSeq(2, i) == baseline[i], "independent ordinal replays its exact original service sequence");
                EqU("independent ordinal does not run serial services", ownedLogs[0].count[i], 0);
            }
            OwnedOrdinals(1, i, i, "speculative service has absolute ordinal");
            OwnedOrdinals(2, i, i, "validated replay service has absolute ordinal");
        }
        CallStop(); ++cases;
        classMutateOffset = 0xd4; classMutateBits = 0x40800000u;
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Compact movement-slot footprint. The guard covers exactly the audited live-in bytes of the mover closure, the commit
// writes exactly the audited output dwords, and nothing else of the receiver is ever copied, compared or written.
// ---------------------------------------------------------------------------------------------------------------------
static bool SpanCovers(const loco::OwnedSpanForTest* spans, U count, U offset) {
    for (U i = 0; i < count; ++i) if (offset >= spans[i].offset && offset < spans[i].offset + spans[i].bytes) return true;
    return false;
}
static void RequireOrderedSpans(const char* what, const loco::OwnedSpanForTest* spans, U count, U prefixSpans) {
    U end = 0;
    for (U i = 0; i < count; ++i) {
        Require(spans[i].bytes != 0 && ((spans[i].offset | spans[i].bytes) & 3) == 0, what);
        Require(spans[i].offset >= end, what);
        end = spans[i].offset + spans[i].bytes;
        Require(end <= (i < prefixSpans ? 0x200u : 0x680u), what);
    }
}
static void OwnedFootprintLayoutCases() {
    currentCase = "compact movement slot footprint layout";
    const loco::OwnedLayoutForTest l = loco::OwnedLayout();
    EqU("published slot width", l.slotBytes, loco::kOwnedSlotBytes);
    Require(l.slotBytes <= 512, "slot stays inside the 512-byte budget (was 960)");
    EqU("slot = 24 metadata + guard + common output + wrapper output", l.slotBytes, 24 + l.guardBytes + l.outputBytes + l.wrapperOutputBytes);
    EqU("guard footprint bytes", l.guardBytes, 248);
    EqU("common output bytes", l.outputBytes, 160);
    EqU("wrapper-only output bytes", l.wrapperOutputBytes, 16);
    RequireOrderedSpans("guard spans ascend, are dword aligned and only +628 lies beyond the copied prefix", l.guard, l.guardCount, l.guardCount - 1);
    RequireOrderedSpans("output spans ascend and stay inside the copied prefix", l.output, l.outputCount, l.outputCount);
    RequireOrderedSpans("wrapper spans ascend and stay inside the copied prefix", l.wrapperOutput, l.wrapperCount, l.wrapperCount);
    // Independent audit lists (mover 7F08F0/7F0260 operands, vf+74 -> +1D8, 80DBF0 -> +44, 80E9D0 -> +160/+170, 814AA0 -> +110/+116,
    // sweep/resolve/env port views and the OwnedReason admission reads).
    static const U reads[] = {
        0x00, 0x10, 0x18, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x58, 0x5C, 0x60, 0x64, 0x68, 0x6C,
        0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90, 0x94, 0xA0, 0xA4, 0xA8, 0xB0, 0xB4, 0xC0, 0xC4,
        0xD0, 0xD4, 0xD8, 0xDC, 0xE0, 0xE4, 0xE8, 0xEC, 0xF0, 0x110, 0x114, 0x12C, 0x13C, 0x160, 0x164, 0x168, 0x170, 0x174,
        0x188, 0x18C, 0x194, 0x198, 0x1A8, 0x1D8, 0x1F0, 0x628
    };
    for (U offset : reads) Require(SpanCovers(l.guard, l.guardCount, offset), "every audited live-in dword is guarded");
    static const U writes[] = {
        0x10, 0x38, 0x40, 0x48, 0x4C, 0x50, 0x54, 0x64, 0x70, 0x74, 0x78, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90, 0x94, 0xA0,
        0xB4, 0xB8, 0xBC, 0xC0, 0xC4, 0xC8, 0xCC, 0xD0, 0xD4, 0xD8, 0xDC, 0xE0, 0xE4, 0xE8, 0xF0, 0x13C, 0x174, 0x18C, 0x194, 0x198, 0x1A8
    };
    for (U offset : writes) Require(SpanCovers(l.output, l.outputCount, offset), "every audited written dword is committed");
    for (U offset : {0x14Cu, 0x150u, 0x190u, 0x1A4u}) {
        Require(SpanCovers(l.wrapperOutput, l.wrapperCount, offset), "wrapper writes are committed in their own group");
        Require(!SpanCovers(l.output, l.outputCount, offset), "wrapper-only dwords never ride the common group");
        Require(!SpanCovers(l.guard, l.guardCount, offset), "wrapper-only dwords are neither read nor guarded");
    }
    // Replay-service fields and unread padding are never copied, compared or written.
    for (U offset : {0x04u, 0x08u, 0x0Cu, 0x14u, 0x1Cu, 0x20u, 0x3Cu, 0x98u, 0x9Cu, 0xACu, 0xF4u, 0x100u, 0x124u, 0x1E0u, 0x1FCu, 0x5ECu, 0x5EDu, 0x67Cu}) {
        Require(!SpanCovers(l.guard, l.guardCount, offset), "links, caches, node count, latches and padding are outside the guard");
        Require(!SpanCovers(l.output, l.outputCount, offset) && !SpanCovers(l.wrapperOutput, l.wrapperCount, offset),
                "links, caches, node count, latches and padding are outside every output group");
    }
    // A committed dword is either guarded (writing back an unchanged value is exact) or rewritten on every committed path.
    for (U i = 0; i < l.outputCount; ++i) for (U at = l.output[i].offset; at < l.output[i].offset + l.output[i].bytes; at += 4) {
        bool always = false; for (U n = 0; n < l.alwaysWrittenCount; ++n) always |= l.alwaysWritten[n] == at;
        Require(SpanCovers(l.guard, l.guardCount, at) || always, "every committed dword is guarded or unconditionally rewritten");
    }
    for (U n = 0; n < l.alwaysWrittenCount; ++n) {
        Require(SpanCovers(l.output, l.outputCount, l.alwaysWritten[n]) && !SpanCovers(l.guard, l.guardCount, l.alwaysWritten[n]),
                "unconditional dwords are committed but their stale pre-values are not guarded");
    }
    // Worst-case movement storage at the replay-sized primary capacity: 48,128 * (448 + 4 + 1) bytes.
    const unsigned long long movement = 48128ull * (loco::kOwnedSlotBytes + 5ull);
    EqU("replay-sized movement block is exactly 21,801,984 bytes (about 20.8 MiB, was 44.3 MiB)", U(movement), 21801984u);
    ++cases;
}
struct MutationCase { const char* name; U offset, bits; int kind; }; // 0 = audited read, 1 = read by WRAP only, 2 = unread/write-only
// A later entity's byte changes between the worker's snapshot and the owner's commit (class-wrapper child callback):
// an audited read must refuse that occurrence to the native path; every other byte must neither refuse nor be overwritten.
static void OwnedFootprintMutationCases() {
    StageGatherPatch gather;
    static const MutationCase mutations[] = {
        {"read +68", 0x68, 0x40800000u, 0}, {"read +6C", 0x6c, 0x40800000u, 0}, {"read +80", 0x80, 0x40800000u, 0},
        {"read +A4", 0xa4, 0x40800000u, 0}, {"read +D4", 0xd4, 0x40800000u, 0}, {"read +34", 0x34, 0x447u, 0},
        {"read +1D8 (vf+74)", 0x1d8, 9u, 0}, {"read +628 (admission)", 0x628, 1u, 0}, {"read +194 (WRAP)", 0x194, 0x40800000u, 1},
        {"unread padding +100", 0x100, 0x5A5A5A5Au, 2}, {"unread padding +124", 0x124, 0x5A5A5A5Au, 2},
        {"unread padding +1E0", 0x1e0, 0x5A5A5A5Au, 2}, {"unread padding +1FC", 0x1fc, 0x5A5A5A5Au, 2},
        {"unread tail +400", 0x400, 0x5A5A5A5Au, 2},
        {"write-first +54", 0x54, 0x5A5A5A5Au, 2}, {"write-first +B8", 0xb8, 0x5A5A5A5Au, 2}, {"write-first +BC", 0xbc, 0x5A5A5A5Au, 2},
        {"write-first +C8", 0xc8, 0x5A5A5A5Au, 2}, {"write-first +CC", 0xcc, 0x5A5A5A5Au, 2},
        {"wrapper-only +14C", 0x14c, 0x5A5A5A5Au, 2}, {"wrapper-only +150", 0x150, 0x5A5A5A5Au, 2},
        {"wrapper-only +190", 0x190, 0x5A5A5A5Au, 2}, {"wrapper-only +1A4", 0x1a4, 0x5A5A5A5Au, 2},
    };
    for (bool wrapper : {false, true}) for (const MutationCase& m : mutations) for (U lanes : {1u, 4u, 8u}) {
        if (m.kind == 1 && !wrapper) continue;
        static char label[96];
        std::snprintf(label, sizeof(label), "owned footprint %s %s lanes=%u", wrapper ? "battle" : "direct", m.name, lanes); currentCase = label;
        classMutateOffset = m.offset; classMutateBits = m.bits;
        constexpr U staleOrdinal = 64, count = 96;
        const U guarded = m.kind == 2 ? 0u : 1u;
        Scenario sc = OwnedScenario(count, wrapper);
        sc.agents[0].vt = VtClass; sc.agents[0].classMutate = true; sc.agents[0].arg = staleOrdinal;
        sc.agents[0].unit = sc.agents[staleOrdinal].unit = 1;
        World original(sc), owned(sc);
        GridRegistry originalRegistry(original), ownedRegistry(owned);
        std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
        originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        auto binding = MakeBinding(); binding.use_parallel = binding.use_owned_services = true;
        binding.use_grid = binding.verify_grid = true;
        binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
        dispatchLanes = lanes; reverseChunks = false; concurrentChunks = lanes > 1;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        Require(loco::Start(binding), "footprint oracle starts");
        Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, count)), "footprint arena activates");
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        EqU("footprint stage preserves the native cursor/end", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
        Same(original, owned, "footprint mutation leaves native state bit-exact (refused -> native, unread -> preserved, never clobbered)");
        CheckGridMode(ownedRegistry, true);
        CheckOwnedPhase(count, lanes, 1, guarded);
        const auto os = OwnedStatus();
        const auto ps = ParallelStatus();
        const auto v2 = GridV2Status();
        EqU("an audited read refuses exactly its own occurrence; unread bytes never refuse", os[loco::OwnedNeedsUnit], guarded);
        EqU("class wrapper plus a stale occurrence stay on the owner", ps[loco::ParallelOwnerEntities], 1 + guarded);
        EqU("every other ordinal commits", ps[loco::ParallelCommitted], count - 1 - guarded);
        EqU("grid records read from a committed result exclude owner-run occurrences", v2[loco::GridV2CommittedRecords], count - 1 - guarded);
        EqU("grid records read from the live receiver are exactly the owner-run occurrences", v2[loco::GridV2RecordReads], 1 + guarded);
        EqU("grid publication has no mismatch", v2[loco::GridV2VerifyMismatches], 0);
        EqU("mutated dword survives in the owned world", Get<U>(owned.agents[staleOrdinal]->b.p(), m.offset),
            Get<U>(original.agents[staleOrdinal]->b.p(), m.offset));
        EqU("footprint run has no faults", os[loco::OwnedFaults] + ps[loco::ParallelFaults] + ps[loco::ParallelSticky], 0);
        CallStop(); ++cases;
    }
    classMutateOffset = 0xd4; classMutateBits = 0x40800000u;
}
static void OwnedParticipantOverflowCases() {
    StageGatherPatch gather;
    for (bool reversed : {false, true}) {
        currentCase = "owned excess distinct dispatch threads fall back without sharing participant scratch";
        Scenario sc = OwnedScenario(320, false);
        World original(sc), owned(sc);
        GridRegistry originalRegistry(original), ownedRegistry(owned);
        std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
        originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        auto binding = MakeBinding(); binding.use_parallel = binding.use_owned_services = true;
        binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = 0;
        dispatchLanes = 4; concurrentChunks = true; reverseChunks = reversed;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        Require(loco::Start(binding), "overflow oracle starts with one participant scratch slot");
        Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, U(sc.list.size()))), "overflow arena activates for its World.model");
        OwnedClear(); loco::SetOwnedServiceObserverForTest(&ObserveOwned);
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        loco::SetOwnedServiceObserverForTest(nullptr);
        EqU("participant overflow preserves native end", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
        Same(original, owned, "unprocessed chunks fall back at native ordinals with bit-exact fields and links");
        SameLog(original, owned, "overflow does not invoke native callbacks on workers");
        CheckGridMode(ownedRegistry, false);
        CheckOwnedPhase(U(sc.list.size()), 1, 0, 0, true);
        const auto phase = OwnedPhase(), ps = ParallelStatus(), os = OwnedStatus();
        EqU("overflow is not a worker fault or sticky failure", ps[loco::ParallelFaults] + os[loco::OwnedFaults] + ps[loco::ParallelSticky], 0);
        EqU("overflow leaves only unprocessed entities on owner", ps[loco::ParallelOwnerEntities], phase[loco::OwnedPhaseUnprocessed]);
        EqU("all successfully computed entities commit", ps[loco::ParallelCommitted], phase[loco::OwnedPhaseComputed]);
        EqU("overflow refuses no otherwise safe worker entity", phase[loco::OwnedPhaseWorkerRefused], 0);
        EqU("overflow does not corrupt service observation", ownedBad, 0);
        for (U i = 0; i < sc.list.size(); ++i) {
            const auto expected = OwnedExpected(sc.agents[i]);
            if (ownedLogs[1].count[i]) {
                Require(OwnedSeq(2, i) == expected, "processed chunk replays native service order");
                EqU("processed chunk avoids serial execution", ownedLogs[0].count[i], 0);
            } else {
                EqU("unprocessed chunk has no replay", ownedLogs[2].count[i], 0);
                Require(OwnedSeq(0, i) == expected, "unprocessed entity falls back through the ordinary native-equivalent selector");
            }
        }
        CallStop(); ++cases;
    }
}

// Activation is mandatory and per generation. A missing activation, an undersized arena or a different World.model makes the owned
// path refuse the whole Stage to the owner: native-equivalent state, no dispatch, no rebuild/growth, and never a sticky failure.
enum class Refusal { NotActivated, Capacity, ForeignModel };
static void OwnedRefusalOnce(Refusal kind, bool wrapper) {
    static char label[96];
    std::snprintf(label, sizeof(label), "owned activation refusal kind=%d wrapper=%d", static_cast<int>(kind), wrapper);
    currentCase = label;
    const Scenario sc = OwnedScenario(24, wrapper);
    const U n = static_cast<U>(sc.list.size());
    World original(sc), owned(sc), foreign(sc);
    GridRegistry originalRegistry(original), ownedRegistry(owned);
    std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
    originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
    auto binding = MakeBinding(); binding.use_parallel = binding.use_owned_services = true;
    binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = 3;
    reverseChunks = false; dispatchLanes = 4; concurrentChunks = false; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
    Require(loco::Start(binding), "owned refusal oracle starts");
    if (kind == Refusal::Capacity) Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, n - 1)), "an undersized activation itself succeeds");
    if (kind == Refusal::ForeignModel) {
        Require(loco::ActivateOwned(foreign.model.p(), FixtureCapacity(foreign, n)), "activation binds the foreign World.model");
        Require(!loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, n)), "a different model is refused after activation without a rebuild");
    }
    const auto activated = OwnedLoad();
    constexpr U ticks = 2;
    for (U tick = 0; tick < ticks; ++tick) {
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        EqU("refused owned Stage keeps the exact native end", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
        Same(original, owned, "refused owned Stage is native-equivalent");
        SameLog(original, owned, "refused owned Stage keeps native callback order");
        CheckGridMode(ownedRegistry, false);
        const auto load = OwnedLoad();
        const auto phase = OwnedPhase(), ps = ParallelStatus(), os = OwnedStatus();
        for (U i = loco::OwnedLoadUs; i <= loco::OwnedLoadArenaUs; ++i)
            EqU("a refused Stage prepares and grows nothing", load[i], activated[i]);
        EqU("model changes count exactly the foreign-model Stages", load[loco::OwnedLoadModelChanges] - activated[loco::OwnedLoadModelChanges],
            kind == Refusal::ForeignModel ? tick + 1 : 0);
        EqU("capacity refusals count exactly the unactivated/undersized Stages", load[loco::OwnedLoadCapacityRefusals] - activated[loco::OwnedLoadCapacityRefusals],
            kind == Refusal::ForeignModel ? 0 : tick + 1);
        EqU("refusal is never a worker fault or sticky failure", ps[loco::ParallelFaults] + os[loco::OwnedFaults] + ps[loco::ParallelSticky], 0);
        EqU("refused Stage dispatches nothing", phase[loco::OwnedPhaseDispatches] + dispatchCalls, 0);
        EqU("refused Stage commits no worker output", ps[loco::ParallelCommitted] + ps[loco::ParallelWorkerEntities], 0);
        EqU("refused Stage runs no worker occurrence", os[loco::OwnedWorkerDirect] + os[loco::OwnedWorkerBattle], 0);
        EqU("catalog preparation never runs on a tick", phase[loco::OwnedPhaseCatalogPrepareUs], 0);
    }
    CallStop(); ++cases;
}
// A correctly activated generation never prepares again on any later tick, whatever the participant count.
static void OwnedNoTickPreparationOnce(U lanes, bool wrapper) {
    static char label[96];
    std::snprintf(label, sizeof(label), "owned no per-tick preparation lanes=%u wrapper=%d", lanes, wrapper);
    currentCase = label;
    const Scenario sc = OwnedScenario(24, wrapper);
    const U n = static_cast<U>(sc.list.size());
    World original(sc), owned(sc);
    GridRegistry originalRegistry(original), ownedRegistry(owned);
    std::vector<U> ids; for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
    originalRegistry.Set(ids, {}); ownedRegistry.Set(ids, {});
    auto binding = MakeBinding(); binding.use_parallel = binding.use_owned_services = true;
    binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
    reverseChunks = false; dispatchLanes = lanes; concurrentChunks = lanes > 1; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
    Require(loco::Start(binding), "no-tick-preparation oracle starts");
    Require(loco::ActivateOwned(owned.model.p(), FixtureCapacity(owned, n)), "no-tick-preparation arena activates");
    const auto activated = OwnedLoad();
    EqU("activation ran once", activated[loco::OwnedLoadCalls], 1);
    for (U tick = 0; tick < 3; ++tick) {
        PrepareStagingFixture(); cur = &original; vlog = &original.log; ResetFp();
        const U originalEnd = CallStageOriginal(original.mgr.p()); FpOk();
        PrepareStagingFixture(); cur = &owned; vlog = &owned.log; ResetFp();
        const U ownedEnd = CallStageModule(owned.mgr.p()); FpOk();
        EqU("activated owned Stage keeps the exact native end", ownedEnd - A(owned.list.data()), originalEnd - A(original.list.data()));
        Same(original, owned, "activated owned Stage stays bit-exact on every tick");
        CheckGridMode(ownedRegistry, false);
        CheckOwnedLoad(activated);
        const auto phase = OwnedPhase(), ps = ParallelStatus(), os = OwnedStatus();
        EqU("one owned dispatch per tick", phase[loco::OwnedPhaseDispatches], tick + 1);
        EqU("no worker fault or sticky failure", ps[loco::ParallelFaults] + os[loco::OwnedFaults] + ps[loco::ParallelSticky], 0);
        Require(os[loco::OwnedWorkerDirect] + os[loco::OwnedWorkerBattle] != 0, "activated Stage really runs worker occurrences");
    }
    CallStop(); ++cases;
}
struct ActivationBoundaryFixture {
    World* world;
    U grid, tree, caller;
    void (*capture)(void*) = nullptr;
    void* context = nullptr;
};
static ActivationBoundaryFixture* activationBoundaryFixture;
static DWORD WINAPI CaptureFixtureOnOwner(void* raw) {
    auto& f = *static_cast<ActivationBoundaryFixture*>(raw);
    EqU("capture leaves the allocation caller", GetCurrentThreadId() == f.caller, 0);
    Put(f.world->model.p(), 0xA8, f.grid); Put(f.world->model.p(), 0xC0, f.tree);
    ResetFp();
    f.capture(f.context);
    // Participant preparation after the owner returns must only read owned data.
    Put(f.world->model.p(), 0xA8, U(0)); Put(f.world->model.p(), 0xC0, U(0));
    return 0;
}
static bool CaptureFixtureAtBoundary(void (*capture)(void*), void* context) {
    auto& f = *activationBoundaryFixture;
    f.capture = capture; f.context = context;
    const auto load = OwnedLoad();
    EqU("large arena and clone warmup precede owner handoff", load[loco::OwnedLoadFailureReason], loco::ActivationOwnerUnavailable);
    EqU("participant preparation follows owner handoff", load[loco::OwnedLoadParticipantsUs], 0);
    HANDLE thread = CreateThread(nullptr, 0, &CaptureFixtureOnOwner, &f, 0, nullptr);
    Require(thread != nullptr, "create distinct activation owner");
    const bool ready = WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0;
    Require(ready, "activation owner returns before participant preparation");
    CloseHandle(thread);
    return ready;
}
static void OwnedCombinedRestartCase() {
    StageGatherPatch gather;
    currentCase = "grid owned collide staged generation restart";
    // Keep both models alive: generation two cannot accidentally reuse the first
    // model address and conceal a stale generation/model latch.
    const Scenario sc = OwnedScenario(24, false);
    World first(sc), second(sc);
    GridRegistry firstRegistry(first), secondRegistry(second);
    std::vector<U> ids;
    for (U i = 0; i < sc.agents.size(); ++i) ids.push_back(i);
    firstRegistry.Set(ids, {}); secondRegistry.Set(ids, {});
    U previousGeneration = 0;
    for (World* world : {&first, &second}) {
        auto binding = MakeBinding();
        binding.use_parallel = binding.use_owned_services = binding.use_quiet = true;
        binding.use_grid = binding.verify_grid = true;
        binding.dispatch = &OracleDispatch; binding.pool = 0xc0111deu; binding.workers = 3;
        binding.capture_at_tick = &CaptureFixtureAtBoundary;
        ActivationBoundaryFixture boundary{world, Get<U>(world->model.p(), 0xA8),
            Get<U>(world->model.p(), 0xC0), GetCurrentThreadId()};
        activationBoundaryFixture = &boundary;
        // An unsafe pre-boundary scene read now faults deterministically.
        Put(world->model.p(), 0xA8, U(0)); Put(world->model.p(), 0xC0, U(0));
        dispatchLanes = 4; reverseChunks = concurrentChunks = false;
        dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        ntw2_collide::Binding collision{delta, &OracleDispatch, binding.pool, binding.workers, &loco::ReadGridForCollision};
        Require(ntw2_collide::Start(collision), "combined generation collision starts");
        Require(ntw2_collide::Activate(world->mgr.p(), FixtureCapacity(*world, kFixtureSlots)), "combined generation collision storage activates");
        Require(loco::Start(binding), "combined generation movement starts");
        Require(loco::ActivateOwned(world->model.p(), FixtureCapacity(*world, kFixtureSlots)), "combined generation activates");
        Put(world->model.p(), 0xA8, boundary.grid); Put(world->model.p(), 0xC0, boundary.tree);
        activationBoundaryFixture = nullptr;
        const auto load = OwnedLoad();
        EqU("new generation performs one activation", load[loco::OwnedLoadCalls], 1);
        EqU("restarted activation succeeds without a stale failure", load[loco::OwnedLoadFailureReason], loco::ActivationOk);
        EqU("activation never faults outside the owner capture", load[loco::OwnedLoadException], 0);
        PrepareStagingFixture(); cur = world; vlog = &world->log; ResetFp();
        Put(world->model.p(), 0x58, U(1));
        CallStageModule(world->mgr.p()); FpOk();
        const auto* view = loco::ReadGrid();
        Require(view && view->generation > previousGeneration, "new generation publishes its own grid");
        previousGeneration = view->generation;
        MEMORY_BASIC_INFORMATION gridAllocation{};
        Require(VirtualQuery(view->record, &gridAllocation, sizeof(gridAllocation)) == sizeof(gridAllocation),
            "published grid has an owned allocation");
        const void* const gridBase = gridAllocation.AllocationBase;
        // Exercise the real collision pipeline without unrelated native combat
        // virtuals, which are outside the mover fixture's native graph.
        for (auto& agent : world->agents) Put(agent->b.p(), 0x38, U(0));
        ntw2_collide::Stage(world->mgr.p());
        U source[ntw2_collide::SourceWordCount]{};
        ntw2_collide::SampleSource(source);
        EqU("combined stage uses published owned CSR", source[ntw2_collide::Source], ntw2_collide::SourceOwned);
        EqU("combined stage has no owned input refusal", source[ntw2_collide::OwnedRefusals], 0);
        ntw2_collide::Stop(); CallStop();
        Require(loco::ReadGrid() == nullptr, "stop invalidates published grid");
        MEMORY_BASIC_INFORMATION released{};
        Require(VirtualQuery(gridBase, &released, sizeof(released)) == sizeof(released) && released.State == MEM_FREE,
            "stop releases the generation's grid allocation without retention");
        ++cases;
    }
}
// Movement slots follow capacity.primary exactly (448+5 bytes each, independent of records); participant storage is
// linear in the ACTUAL workers+caller count (no embedded worst-case participant array); every activation-sized
// allocation exists only after ActivateOwned.
static void OwnedCapacityStorageCases() {
    StageGatherPatch gather;
    currentCase = "owned storage follows primary capacity and actual participants";
    const Scenario sc = OwnedScenario(24, false);
    struct Bytes { U started, activated; };
    auto measure = [&](U lanes, U primary, U records) {
        World w(sc);
        auto b = MakeBinding(); b.use_parallel = b.use_owned_services = true;
        b.dispatch = &OracleDispatch; b.pool = 0xc0111deu; b.workers = lanes - 1;
        reverseChunks = false; dispatchLanes = lanes; concurrentChunks = false; dispatchCalls = dispatchedChunks = dispatchMaxChunks = 0;
        Require(loco::Start(b), "capacity storage oracle starts");
        Bytes bytes{loco::StorageBytes(), 0};
        auto capacity = FixtureCapacity(w, primary); capacity.records = records;
        const U estimate = loco::EstimateActivationBytes(capacity);
        Require(loco::ActivateOwned(w.model.p(), capacity), "capacity storage oracle activates");
        bytes.activated = loco::StorageBytes();
        std::array<U, loco::StorageWordCount> storage{}; loco::SampleStorage(storage.data());
        U byteSum = 0; for (U i = 0; i < loco::StorageSceneNodes; ++i) byteSum += storage[i];
        EqU("storage breakdown bytes sum to StorageBytes", byteSum, bytes.activated);
        EqU("movement bytes follow capacity.primary", storage[loco::StorageMovement], capacity.primary * (loco::kOwnedSlotBytes + 5u));
        EqU("no grid bytes without a grid binding", storage[loco::StorageGrid], 0);
        Require(storage[loco::StorageParticipants] != 0, "participants and arena are accounted");
        // Estimate = movement block + one context struct per participant: a strict lower bound of what activation added
        // (scene/catalog/vector capacities are only known after capture).
        Require(estimate >= capacity.primary * (loco::kOwnedSlotBytes + 5u) && estimate <= bytes.activated - bytes.started,
            "activation estimate is a tight lower bound of the actual activation allocation");
        CallStop();
        EqU("Stop releases every owned allocation", loco::StorageBytes(), 0);
        { std::array<U, loco::StorageWordCount> released{}; loco::SampleStorage(released.data());
          for (U word : released) EqU("Stop clears the storage breakdown", word, 0); }
        ++cases;
        return bytes;
    };
    const Bytes one = measure(1, 24, 1024), four = measure(4, 24, 1024), eight = measure(8, 24, 1024);
    EqU("participant storage is linear in actual lanes (no unused embedded participants)",
        (eight.activated - four.activated) * 3, (four.activated - one.activated) * 4);
    Require(four.activated > one.activated && eight.activated > four.activated, "each extra lane adds exactly one participant");
    Require(eight.activated < 32u * 1024 * 1024, "eight lanes stay far below the old fixed 32-participant arena");
    for (const Bytes& b : {one, four, eight}) Require(b.activated > b.started, "heavy contexts are created by activation, not Start");
    Require(four.activated - four.started >= 4u * 16 * 1024, "activation adds one scratch context per actual participant");
    const Bytes doubled = measure(4, 48, 1024), wideRecords = measure(4, 24, 8192);
    EqU("movement slots are exactly capacity.primary * (slot + state + worklist entry)",
        doubled.activated - four.activated, 24u * (loco::kOwnedSlotBytes + 1u + 4u));
    EqU("movement storage is independent of the grid record capacity", wideRecords.activated, four.activated);
    EqU("Start is independent of every capacity", doubled.started, four.started);
    {
        currentCase = "replay-sized combined allocation accounting";
        World w(sc);
        auto b = MakeBinding(); b.use_parallel = b.use_owned_services = b.use_grid = true;
        b.dispatch = &OracleDispatch; b.pool = 0xc0111deu; b.workers = 8;
        dispatchLanes = 9; reverseChunks = concurrentChunks = false;
        const ntw2_workload::Capacity capacity{48128,74752,1048576,160256,770048};
        ntw2_collide::Binding collision{delta,&OracleDispatch,b.pool,b.workers,&loco::ReadGridForCollision};
        Require(ntw2_collide::Start(collision), "replay-sized collision binding starts");
        Require(ntw2_collide::Activate(w.mgr.p(),capacity), "replay-sized collision arena activates");
        Require(loco::Start(b), "replay-sized owned binding starts");
        Require(loco::ActivateOwned(w.model.p(),capacity), "replay-sized owned arena activates");
        const U locoBytes=loco::StorageBytes(), collisionBytes=ntw2_collide::StorageBytes();
        Require(locoBytes+collisionBytes<96u*1024*1024, "combined arenas alone fit below the aggregate memory target");
        std::array<U, loco::StorageWordCount> storage{}; loco::SampleStorage(storage.data());
        U byteSum = 0; for (U i = 0; i < loco::StorageSceneNodes; ++i) byteSum += storage[i];
        EqU("breakdown bytes sum to StorageBytes", byteSum, locoBytes);
        EqU("movement bytes are exactly capacity.primary * (slot + state + worklist entry)", storage[loco::StorageMovement],
            capacity.primary * (loco::kOwnedSlotBytes + 5u));
        EqU("grid bytes are the page-rounded capacity block", storage[loco::StorageGrid],
            U((ExpectedGridBytes(capacity, 9) + 4095) & ~4095ull));
        Require(storage[loco::StorageMovement] < 22u * 1024 * 1024, "replay-sized movement slots are about 20.8 MiB, not 44.3 MiB");
        Require(storage[loco::StorageMovement] + storage[loco::StorageGrid] < 48u * 1024 * 1024 - 8u * 1024 * 1024,
                "movement + grid leave at least 8 MiB of the 48 MiB budget for scene, catalog and participants");
        std::printf("replay-capacity fixture bytes: loco=%u collision=%u combined=%u (small captured scene; excludes image/profile/stacks)\n",
                    locoBytes,collisionBytes,locoBytes+collisionBytes);
        ntw2_collide::Stop(); CallStop();
        EqU("combined collision arena releases",ntw2_collide::StorageBytes(),0);
        EqU("combined owned arena releases",loco::StorageBytes(),0);
        ++cases;
    }
}
static void OwnedActivationCases() {
    StageGatherPatch gather;
    currentCase = "owned activation argument validation";
    { Scenario sc = OwnedScenario(4, false); World w(sc);
      auto b = MakeBinding(); b.use_parallel = b.use_owned_services = true; b.dispatch = &OracleDispatch; b.pool = 0xc0111deu; b.workers = 1;
      Require(loco::Start(b), "activation validation oracle starts");
      Require(!loco::ActivateOwned(nullptr, FixtureCapacity(w, 4)), "null model is refused");
      Require(!loco::ActivateOwned(w.model.p(), ntw2_workload::Capacity{}), "zero capacity is refused");
      for (int field = 0; field < 4; ++field) {
          auto c = FixtureCapacity(w, 4);
          if (field == 0) c.primary = 0; else if (field == 1) c.records = 3; else if (field == 2) c.cells = 0; else c.memberships = 0;
          Require(!loco::ActivateOwned(w.model.p(), c), "every incoherent capacity field is refused");
      }
      { auto c = FixtureCapacity(w, 4); c.cells = 1u << 21; Require(!loco::ActivateOwned(w.model.p(), c), "capacity beyond the sanity ceiling is refused"); }
      EqU("refused arguments never count an activation attempt", OwnedLoad()[loco::OwnedLoadCalls], 0);
      CallStop(); }
    for (bool wrapper : {false, true}) {
        for (Refusal kind : {Refusal::NotActivated, Refusal::Capacity, Refusal::ForeignModel}) OwnedRefusalOnce(kind, wrapper);
        for (U lanes : {1u, 4u}) OwnedNoTickPreparationOnce(lanes, wrapper);
    }
}

static void ParallelStageCases() {
    const U savedGather = Get<U>(At(0x1333714), 0xb0), savedGuard = Get<U>(At(0x14dcba0), 0);
    Put(At(0x1333714), 0xb0, Fn(&StageGather)); // Data slot only: original mover/selector/staging instructions remain intact.
    stagingOwner = GetCurrentThreadId();
    Scenario pure;
    for (U i = 0; i < 24; ++i) {
        Spec s = Genuine(i, 0); s.a1 = 0; s.f1 = B(i & 1); s.f2 = B((i >> 1) & 1);
        s.v80 = float(i) * 0.125f; s.v84 = -float(i) * 0.25f; pure.agents.push_back(s); pure.list.push_back(i);
    }
    currentCase = "parallel A1-zero direct-selector 1/4/8 lanes and reverse dispatch";
    std::vector<U> baseline;
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        const auto output = ParallelStageOnce(pure, lanes, reversed, {}, true);
        if (baseline.empty()) baseline = output;
        else Require(output == baseline, "native outputs and CSR are deterministic across lanes and reversed chunks");
    }
    currentCase = "parallel real-thread direct selector 1/4/8 participants";
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        const auto output = ParallelStageOnce(pure, lanes, reversed, {}, true, true);
        Require(output == baseline, "real-thread direct-selector output matches inline native baseline");
    }
    Scenario wrappers = pure;
    for (auto& s : wrappers.agents) {
        s.ec = 1; s.v80 = 0.1234567f; s.v84 = -0.7654321f; s.heading = 0x2345;
    }
    currentCase = "parallel real-thread wrappers install and restore FP 1/4/8 participants";
    const auto wrapperBaseline = ParallelStageOnce(wrappers, 1, false, {}, true, false, true);
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        const auto output = ParallelStageOnce(wrappers, lanes, reversed, {}, true, true, true);
        Require(output == wrapperBaseline, "real-thread wrappers match original and inline outputs despite foreign FP controls");
    }
    Scenario duplicate = pure; duplicate.list.insert(duplicate.list.begin() + 12, 0);
    currentCase = "parallel duplicate occurrence preserves prior occurrence output";
    baseline.clear();
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        const auto output = ParallelStageOnce(duplicate, lanes, reversed, {}, false);
        if (baseline.empty()) baseline = output;
        else Require(output == baseline, "duplicate occurrence output is deterministic across scheduling order");
    }
    // Each unsafe occurrence follows a substantial safe run, so owner services cannot accidentally overlap that run.
    struct OwnerCase { const char* name; Spec agent; std::vector<loco::ParallelWord> reasons; };
    std::vector<OwnerCase> owner;
    Spec s = Genuine(24, 0);
    owner.push_back({"parallel active A1 needs owner environment/sweep/resolve", s,
        {loco::ParallelNeedsEnv, loco::ParallelNeedsSweep, loco::ParallelNeedsResolve}});
    s.a1 = 0; s.owner = 1;
    owner.push_back({"parallel mover owner stays serial", s, {loco::ParallelNeedsRelationship}});
    s.owner = 0; s.pending = 1;
    owner.push_back({"parallel pending stays serial", s, {loco::ParallelNeedsAdmission}});
    s.pending = 0; s.arg = 0x170;
    owner.push_back({"parallel descriptor owner stays serial", s, {loco::ParallelNeedsRelationship}});
    s.arg = 0; s.a3 = 0;
    owner.push_back({"parallel A3-zero uses original owner staging", s, {loco::ParallelNeedsStaging}});
    s.a3 = 1; s.vt = VtClass;
    owner.push_back({"parallel class wrapper stays serial", s, {loco::ParallelNeedsClassWrapper}});
    for (const auto& c : owner) {
        currentCase = c.name; Scenario mixed = pure; mixed.agents.push_back(c.agent); mixed.list.push_back(24);
        baseline.clear();
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            const auto output = ParallelStageOnce(mixed, lanes, reversed, c.reasons, false);
            if (baseline.empty()) baseline = output;
            else Require(output == baseline, "owner fallback is deterministic across lanes and chunk order");
        }
    }
    Put(At(0x1333714), 0xb0, savedGather); Put(At(0x14dcba0), 0, savedGuard);
}

static void ScratchLifecycle() {
    currentCase = "private scratch lifecycle";
    const U backing = PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4);
    Require(backing != 0 && PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 2) >= 1, "plane candidate runs left a grown private backing store");
    Require(std::find(g_allocs.begin(), g_allocs.end(), backing) != g_allocs.end(), "backing store was allocated by the native allocator");
    const size_t freesBefore = g_frees.size();
    const auto retained = Services();
    CheckServices(retained, true);
    for (U i = 0; i < loco::ServiceCount; ++i)
        Require(retained[loco::TimingServiceCalls + i] != 0, "mapped Run/Stage exercise every timed service");
    CallStop();
    Require(Services() == retained, "Stop retains the complete service timing snapshot");
    Require(g_frees.size() == freesBefore + 1 && g_frees.back() == backing, "Stop frees exactly the private backing store through native FF7EF0");
    EqU("scratch header tag restored", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 0), A(At(0x1312358)));
    for (U i = 1; i < 5; ++i) EqU("scratch header empty after Stop", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, i), 0);
    for (U i = 0; i < 4; ++i) {
        EqU("second scratch empty after Stop", PrivateWord(NTW2_BIND_LOCO_SCRATCH_15A1888, i), 0);
        EqU("third scratch empty after Stop", PrivateWord(NTW2_BIND_LOCO_SCRATCH_15A189C, i), 0);
    }
    Require(loco::Start(MakeBinding()), "module restarts after Stop");
    CheckServiceReset(true);
    EqU("restart reconstructs the scratch header", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 0), A(At(0x1312358)));
    Spec s; s.name = "owner transition after restart"; s.owner = 2; Run(Move(s));
    Require(PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4) != 0, "restarted scratch grows again");
    CallStop();
}
static void ObserveOnlyServices() {
    currentCase = "observe-only service timing";
    auto binding = MakeBinding(); binding.use_clone = false;
    Require(loco::Start(binding), "observe-only module starts");
    CheckServiceReset(false);
    Spec s; s.name = "observe-only Run";
    World original(Move(s)), cloned(Move(s));
    Exec(original, 0, true); Exec(cloned, 2, true);
    Same(original, cloned, "observe-only oracle Run preserves native graph");
    U census[loco::WordCount]; loco::Sample(census);
    Require(census[loco::ServiceCalls] != 0, "observe-only oracle Run still reaches census taps");
    CheckServiceReset(false);
    Scenario sc; sc.agents = {Genuine(0, 1), Genuine(1, 0)}; sc.list = {0, 1};
    World a(sc), b(sc);
    cur = &a; vlog = &a.log; ResetFp();
    const U endA = CallStageOriginal(a.mgr.p()); FpOk();
    cur = &b; vlog = &b.log; ResetFp();
    const U endB = CallStageModule(b.mgr.p()); FpOk();
    EqU("observe-only Stage end matches native", endB - A(b.list.data()), endA - A(a.list.data()));
    Same(a, b, "observe-only Stage preserves native graph");
    loco::Sample(census);
    EqU("observe-only Stage never clones", census[loco::Cloned], 0);
    EqU("observe-only Stage executes both native occurrences", census[loco::Native], 2);
    CheckServiceReset(false);
    const auto retained = Services();
    CallStop();
    Require(Services() == retained, "observe-only Stop retains disabled timing metadata");
    ++cases;
}
// Controlled service targets exercise the real timing taps through Run. Unlike
// whole-mover comparisons, every register and live x87/XMM lane has a defined
// value at both edges; original service code is never patched.
__declspec(align(16)) static B abiSeed[512], abiReturnSeed[512], abiHostFp[512];
__declspec(align(16)) static B abiEntryFp[512], abiExitFp[512];
__declspec(align(16)) static U abiLanes[32];
static U abiEntryRegs[8], abiExitRegs[8], abiEntryFlags, abiExitFlags, abiTarget, abiReturnEax;
static void __declspec(naked) AbiServiceTarget() {
    __asm {
        pushfd
        pushad
        mov esi, esp
        lea edi, abiEntryRegs
        mov ecx, 8
        rep movsd
        mov eax, dword ptr [esp + 32]
        mov abiEntryFlags, eax
        fxsave abiEntryFp
        popad
        popfd
        fxrstor abiReturnSeed
        mov eax, 7fffffffh
        add eax, 1
        mov eax, dword ptr [abiReturnEax]
        mov ecx, 012345678h
        mov edx, 087654321h
        mov ebx, 0badc0ffeh
        mov ebp, 0decafbadh
        mov esi, 013579bdfh
        mov edi, 02468ace0h
        ret
    }
}
static void __declspec(naked) AbiCapture() {
    __asm {
        pushfd
        pushad
        fxsave abiHostFp
        fxrstor abiSeed
        mov eax, 0f1e2d3c4h
        mov ecx, 011223344h
        mov edx, 055667788h
        mov ebx, 099aabbcch
        mov ebp, 0ddeeff00h
        mov esi, 013246578h
        mov edi, 09bacdfe0h
        push 02d7h
        popfd
        call dword ptr [abiTarget]
        pushfd
        pushad
        mov esi, esp
        lea edi, abiExitRegs
        mov ecx, 8
        rep movsd
        mov eax, dword ptr [esp + 32]
        mov abiExitFlags, eax
        fxsave abiExitFp
        add esp, 36
        fxrstor abiHostFp
        popad
        popfd
        ret
    }
}
static void __fastcall AbiCloneEntry(void*) { AbiCapture(); }
static void PrepareAbiState() {
    for (U i = 0; i < 32; ++i) abiLanes[i] = 0x10203040u + 0x01010101u * i;
    ResetFp();
    _mm_setcsr(0x3fa0); // nondefault rounding and sticky precision flag
    unsigned short cw = 0x67f;
    __asm {
        fldcw word ptr [cw]
        fld1
        fldpi
        movdqu xmm0, xmmword ptr [abiLanes]
        movdqu xmm1, xmmword ptr [abiLanes + 16]
        movdqu xmm2, xmmword ptr [abiLanes + 32]
        movdqu xmm3, xmmword ptr [abiLanes + 48]
        movdqu xmm4, xmmword ptr [abiLanes + 64]
        movdqu xmm5, xmmword ptr [abiLanes + 80]
        movdqu xmm6, xmmword ptr [abiLanes + 96]
        movdqu xmm7, xmmword ptr [abiLanes + 112]
        fxsave abiSeed
        fldl2e
        pcmpeqd xmm0, xmm0
        pcmpeqd xmm1, xmm1
        pcmpeqd xmm2, xmm2
        pcmpeqd xmm3, xmm3
        pcmpeqd xmm4, xmm4
        pcmpeqd xmm5, xmm5
        pcmpeqd xmm6, xmm6
        pcmpeqd xmm7, xmm7
        fxsave abiReturnSeed
    }
    Put<U>(abiReturnSeed, 24, 0x5f81); // different rounding and sticky invalid flag
    ResetFp();
}
static void SameAbiFp(const B* original, const B* tapped) {
    EqU("timing thunk preserves x87 control/status/tag/opcode",
        std::memcmp(original, tapped, 8) == 0, 1);
    EqU("timing thunk preserves MXCSR including sticky status",
        Get<U>(tapped, 24), Get<U>(original, 24));
    for (U i = 0; i < 8; ++i)
        Require(std::memcmp(original + 32 + i * 16, tapped + 32 + i * 16, 10) == 0,
            "timing thunk preserves every x87 register payload");
    Require(std::memcmp(original + 160, tapped + 160, 128) == 0,
        "timing thunk preserves all eight complete XMM registers");
}
static void ServiceAbiCases() {
    currentCase = "transparent timed service ABI";
    PrepareAbiState();
    auto binding = MakeBinding(); binding.move_clone = Fn(&AbiCloneEntry);
    Require(loco::Start(binding), "ABI oracle starts with controlled private-family entry");
    CheckServiceReset(true);
    const U ids[loco::ServiceCount] = {
        NTW2_BIND_LOCO_SERVICE_811ED0, NTW2_BIND_LOCO_SERVICE_811D50,
        NTW2_BIND_LOCO_SERVICE_7EFDD0, NTW2_BIND_LOCO_SERVICE_7EFA80,
        NTW2_BIND_LOCO_SERVICE_801140, NTW2_BIND_LOCO_SERVICE_80F290,
        NTW2_BIND_LOCO_SERVICE_81AE40, NTW2_BIND_LOCO_SERVICE_814AA0
    };
    for (U probe = 0; probe < 2 * loco::ServiceCount; ++probe) {
        const U i = probe / 2;
        abiReturnEax = 0xa1b2c300u | (probe & 1u);
        abiTarget = Fn(&AbiServiceTarget);
        AbiCapture();
        B entryFp[512], exitFp[512];
        U entryRegs[8], exitRegs[8];
        std::memcpy(entryFp, abiEntryFp, sizeof(entryFp)); std::memcpy(exitFp, abiExitFp, sizeof(exitFp));
        std::memcpy(entryRegs, abiEntryRegs, sizeof(entryRegs)); std::memcpy(exitRegs, abiExitRegs, sizeof(exitRegs));
        const U entryFlags = abiEntryFlags, exitFlags = abiExitFlags;
        const auto service = static_cast<loco::Service>(i);
        const U nativeTarget = loco::SetServiceTargetForTest(service, Fn(&AbiServiceTarget));
        Require(nativeTarget != 0, "idle oracle can replace native service target");
        abiTarget = privateBindings[ids[i]];
        U before[loco::WordCount], after[loco::WordCount];
        loco::Sample(before); const auto timingBefore = Services();
        CallRun(nullptr, false);
        loco::Sample(after); const auto timingAfter = Services();
        EqU("restore native service target", loco::SetServiceTargetForTest(service, nativeTarget), Fn(&AbiServiceTarget));
        for (U reg = 0; reg < 8; ++reg) {
            if (reg == 3) continue; // ESP differs with the enclosing Run frame.
            EqU("timing entry preserves every GPR", abiEntryRegs[reg], entryRegs[reg]);
            EqU("timing return preserves every GPR", abiExitRegs[reg], exitRegs[reg]);
        }
        EqU("timing return preserves native stack cleanup",
            abiExitRegs[3] - abiEntryRegs[3], exitRegs[3] - entryRegs[3]);
        EqU("native EAX return is retained", abiExitRegs[7], abiReturnEax);
        EqU("native zero/nonzero AL return is retained", abiExitRegs[7] & 0xffu, probe & 1u);
        EqU("timing entry preserves EFLAGS", abiEntryFlags, entryFlags);
        EqU("timing return preserves EFLAGS", abiExitFlags, exitFlags);
        SameAbiFp(entryFp, abiEntryFp); SameAbiFp(exitFp, abiExitFp);
        EqU("ABI probe reaches exactly one timed service",
            timingAfter[loco::TimingServiceCalls + i] - timingBefore[loco::TimingServiceCalls + i], 1);
        CheckServiceDelta(timingBefore, timingAfter, before, after);
        ++cases;
    }
    const auto retained = Services(); CallStop();
    Require(Services() == retained, "ABI probe Stop retains completed timing");
}

#include "native_loco_grid_bulk.h"
#include "native_loco_relink_cases.h"
#include "native_loco_classwrap_cases.h"

namespace ntw2_loco { void DebugGrid(long long*); } // per-phase chunk CPU accumulators, compiled only into this oracle
static U gBenchMoving = 100;
static void __fastcall NullChunk(void*, U) {}
static void GridBench(U lanes, U stages) {
    std::printf("grid build bench: realistic fixture, %u participants (workers+caller), %u stages\n", lanes, stages);
    { // fixed cost of the pool: an empty 2-dispatch build right after an idle gap (workers asleep on their events) vs back to back
        bulk::g_pool.Start(lanes - 1); LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f);
        std::vector<double> idle, hot;
        for (U i = 0; i < 300; ++i) {
            Sleep(3);
            QueryPerformanceCounter(&a);
            bulk::g_pool.Dispatch(Fn(&NullChunk), lanes * 3, nullptr); bulk::g_pool.Dispatch(Fn(&NullChunk), lanes * 3, nullptr);
            QueryPerformanceCounter(&b); idle.push_back(double(b.QuadPart - a.QuadPart) * 1e6 / double(f.QuadPart));
        }
        for (U i = 0; i < 300; ++i) {
            QueryPerformanceCounter(&a);
            bulk::g_pool.Dispatch(Fn(&NullChunk), lanes * 3, nullptr); bulk::g_pool.Dispatch(Fn(&NullChunk), lanes * 3, nullptr);
            QueryPerformanceCounter(&b); hot.push_back(double(b.QuadPart - a.QuadPart) * 1e6 / double(f.QuadPart));
        }
        bulk::g_pool.Shutdown();
        std::sort(idle.begin(), idle.end()); std::sort(hot.begin(), hot.end());
        std::printf("  empty 2-dispatch build: after a 3 ms idle gap p50 %.1f p90 %.1f us; back to back p50 %.1f us\n",
            idle[idle.size() / 2], idle[idle.size() * 9 / 10], hot[hot.size() / 2]);
    }
    for (const bool cold : {false, true}) for (const bool incremental : {false, true}) {
        bulk::Config cfg;
        bulk::World world(cfg);
        long long dbg[8]; ntw2_loco::DebugGrid(dbg);
        const bulk::PhaseRow r = bulk::Bench(world, lanes, incremental, stages, 8, gBenchMoving, cold);
        ntw2_loco::DebugGrid(dbg);
        LARGE_INTEGER f; QueryPerformanceFrequency(&f);
        std::printf("  %-4s %-11s registry %7.1f  capture %7.1f  plan %7.1f  build %7.1f  total %7.1f us  (call %7.1f)  full=%u inc=%u changed=%u reuse=%u\n",
            cold ? "cold" : "warm", incremental ? "incremental" : "full", r.registry, r.capture, r.plan, r.build, r.total, r.call,
            r.full, r.incremental, r.changed, r.reuses);
        std::printf("       chunk cpu us/stage: capture records %.0f, committed map %.0f, strip scan %.0f, scatter %.0f\n",
            dbg[0] * 1e6 / f.QuadPart / (stages + 8), dbg[1] * 1e6 / f.QuadPart / (stages + 8), dbg[2] * 1e6 / f.QuadPart / (stages + 8), dbg[3] * 1e6 / f.QuadPart / (stages + 8));
    }
}
int main(int argc, char** argv) {
    if (argc < 2 || argc > 6) { std::fprintf(stderr, "usage: native_loco_oracle Napoleon.exe [--owned-restart | --movement-cases | --grid-bench [lanes [stages [moving%]]] | --relink-bench [lanes [movers]]]\n"); return 2; }
    Map(argv[1]); InstallHostSlots();
    if (argc >= 3 && !std::strcmp(argv[2], "--relink-bench")) {
        const U lanes = argc >= 4 ? static_cast<U>(std::atoi(argv[3])) : 9u, movers = argc >= 5 ? static_cast<U>(std::atoi(argv[4])) : 32768u;
        for (const bool clustered : {true, false}) for (const U perBatch : {4096u, 32768u}) for (const U minCells : {2048u, 1u << 30})
            relinkcase::BenchFixture(lanes, movers, 40, clustered, perBatch, minCells);
        return 0;
    }
    if (argc == 3 && !std::strcmp(argv[2], "--grid-cases")) { // the multi-stage bulk grid equality cases alone
        bulk::GridSequenceCases(); bulk::GridRealisticEquality();
        std::printf("PASS bulk grid cases=%u checks=%u\n", cases, checks);
        return 0;
    }
    if (argc >= 3 && !std::strcmp(argv[2], "--grid-bench")) {
        if (argc >= 6) gBenchMoving = static_cast<U>(std::atoi(argv[5]));
        GridBench(argc >= 4 ? static_cast<U>(std::atoi(argv[3])) : 9u, argc >= 5 ? static_cast<U>(std::atoi(argv[4])) : 200u);
        return 0;
    }
    if (argc == 3 && !std::strcmp(argv[2], "--movement-cases")) { // slices B/C only (relink apply, class-wrapper admission) plus the owned admission/validation suites they extend
        relinkcase::RelinkCases(); relinkcase::RelinkStubAbiCase(); relinkcase::OwnedRelinkCases();
        classwrap::ClassWrapperCases(); OwnedServiceCases(); OwnedAdmissionCases(); OwnedValidationCases(); OwnedParticipantOverflowCases(); OwnedFaultCases(); OwnedActivationCases();
        std::printf("PASS movement cases=%u checks=%u\n", cases, checks);
        return 0;
    }
    if (argc == 3) {
        Require(!std::strcmp(argv[2], "--owned-restart"), "known oracle selection");
        OwnedCombinedRestartCase();
        std::printf("PASS owned restart cases=%u checks=%u\n", cases, checks);
        return 0;
    }
    currentCase = "lifecycle";
    EqU("Classify before Start refuses", loco::Classify(nullptr), loco::Lifetime);
    Require(loco::Start(MakeBinding()), "module starts");
    Require(!loco::Start(MakeBinding()), "a second participant is refused");
    CheckServiceReset(true);
    U initialGates[loco::GateWordCount];
    loco::SampleGates(initialGates);
    EqU("Start initializes gate version synchronously", initialGates[loco::GateVersion], 1);
    EqU("Start initializes enforced mask synchronously", initialGates[loco::GateEnforcedMask], 0x233);
    for (U i = 1; i < loco::GateWordCount; ++i)
        if (i != loco::GateEnforcedMask) EqU("Start clears gate counters and reserved words", initialGates[i], 0);
    EqU("private scratch header constructed", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 0), A(At(0x1312358)));
    EqU("private scratch capacity empty", PrivateWord(NTW2_BIND_LOCO_SCRATCH_14543B4, 4), 0);
    CanonicalScalarCase(); ClassifyCases(); MoveCases(); StageCases(); GateStageCases(); OwnerHandoffCases();
    ScratchLifecycle();
    ObserveOnlyServices();
    ServiceAbiCases();
    GridLifecycleCases(); GridNumericCases(); GridV2Cases(); GridSpreadCases(); GridCapacityCases(); ParallelStageCases(); ParallelFaultCases();
    OwnedServiceCases(); OwnedAdmissionCases(); OwnedValidationCases(); OwnedParticipantOverflowCases(); OwnedFaultCases(); OwnedActivationCases();
    OwnedCapacityStorageCases(); OwnedFootprintLayoutCases(); OwnedFootprintMutationCases();
    OwnedCombinedRestartCase();
    relinkcase::RelinkCases(); relinkcase::RelinkStubAbiCase(); relinkcase::OwnedRelinkCases();
    bulk::GridSequenceCases(); bulk::GridRealisticEquality();
    classwrap::ClassWrapperCases();
    std::printf("PASS native loco oracle cases=%u checks=%u allocations=%zu frees=%zu\n", cases, checks, g_allocs.size(), g_frees.size());
    return 0;
}
