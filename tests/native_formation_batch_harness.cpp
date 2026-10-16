#define _CRT_SECURE_NO_WARNINGS
// Owned-process differential smoke for native_formation_batch (prepare / execute / consume adapter).
//
// The ORIGINAL machine code of the approved image (Napoleon.exe, SHA-256 13fcab62...cbad4) is mapped privately inside THIS
// process (VirtualAlloc + loader relocations, native_image_relocation.h).  Nothing touches a running game, the installed EXE,
// a debugger or an injector.  Glue patches exist only in the private copy:
//   * 0xFF7F20 / 0xFF7EF0 (game heap allocate / free) -> host malloc / free thunks
//   * data: [0x14A40B0] = INT_MIN (thread-safe-static guard of 0x502770), [0x1841BB8] = this process' _tls_index,
//           angle table copied to 0x176CFF8.
// Everything else (generator 0x62FD60 / mod 0x18ED200, assignment wrapper 0x18F0A00 with 0x18F0200 / 0x5373F0 / 0x502770 /
// 0x5281D0 / 0x18F1200, 0x557C80, the unit predicate 0x54C8B0, 0x80E9D0, 0x6B7F50, 0x445A50) is original bytes.
// Surface-cell frame getter (cell vtable slot 4) and ring-link virtual 0 fixtures use the image's REAL leaves (0x461180 xor eax,eax;
// 0x4470B0 mov eax,ecx; link objects with the real vtable 0x132B5D8 whose slot 0 is 0x54E920 mov al,[ecx+4]) plus a harness
// this-relative load leaf (8B 41 40 C3).  Prepare evaluates these leaves from their bytes and never executes them.  After every
// Prepare the job's ring-link flags and frames are compared with what the ORIGINAL 0x6B7F50 / the cell getter return on the
// same fixture (VerifyPrepared).  Regression gates give Prepare callbacks with side effects (counter increment + writes into the
// fixture): it must decline with kUnsupportedCellGetter / kUnsupportedLinkGetter, leave every object untouched, and the global
// hazard counter must be 0 at the end of the whole run.
//
// Per unit a TWIN fixture pair is built from one specification (formation 0x2800 bytes at the native offsets, layout object with
// its vtable copy, container with class-A / class-B children, optional surface cell + frame + terrain chain, men with native
// vtables, unit with the 0x54C8B0 entry table and the side object).  Then, for batches of units:
//   A (adapter)   : Prepare -> one Execute dispatch on the persistent pool (ntw_pool_dispatch, caller participates) ->
//                   original generator -> Consume at the original assignment call -> (fallback: original 0x18F0A00)
//   B (native)    : original generator -> original 0x18F0A00
//   and compares the entry vector (cap, count, man, slot, cost bits), formation+0x1C order after the 0x555CA0 tail and the
//   0x557C80 decision bit-for-bit.  A second Batch executed serially on the same fixtures must equal the pooled one bit-for-bit.
// Mutations applied between Prepare and Consume (both twins) must make Consume refuse with the expected Reason and the
// original path must still equal the native twin.  Gate tests cover the Prepare refusals and the Consume lifecycle.
//
//   native_formation_batch_harness.exe --image "<Napoleon.exe>" --table native-formation-angle-table-28252.bin
//       [--cases N] [--seed S] [--workers W]
// Exit 0 only when every comparison and plumbing assertion holds and the required classes were observed.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <malloc.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "native_formation_batch.h"
#include "native_image_relocation.h"
#include "native_worker_dispatch.h"
#ifdef NFR_RUNTIME_SMOKE
#include <tlhelp32.h>
#include <atomic>
#include <cstdarg>
#include "native_formation_runtime.h"
#endif

#pragma comment(lib, "bcrypt.lib")
static_assert(sizeof(void*) == 4, "x86 build required: the native code is 32-bit");

extern "C" {
ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool);
void __stdcall ntw_pool_dispatch(ntw_u32 user, ntw_u32 body, ntw_u32 chunks, void* ctx);
ntw_u32 __stdcall ntw_pool_worker_start(void* param);
}
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile int g_tlsPad[32];

namespace nb = ntw_formation_batch;
namespace ns = ntw_formation;
namespace nf = ntw_formation_layout;

namespace {

constexpr uint32_t kImageBase = 0x400000;
constexpr const char* kImageSha = "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4";
constexpr const char* kTableSha = "405383e324f986ad1972b9da231b2bb6d1d496c23067af8de60faf359e2a3581";
uintptr_t g_delta;
uint32_t NA(uint32_t preferred) { return preferred + static_cast<uint32_t>(g_delta); }

template <class T> void Put(uint8_t* base, uint32_t off, T v) { std::memcpy(base + off, &v, sizeof(T)); }
template <class T> T Get(const uint8_t* base, uint32_t off) { T v; std::memcpy(&v, base + off, sizeof(T)); return v; }
uint32_t PtrU(const void* p) { return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p)); }
uint32_t FBits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }

uint16_t GetCw() { uint16_t w = 0; __asm { fnstcw w } return w; }
void SetCw(uint16_t w) { __asm { fldcw w } }

std::string Sha256(const void* data, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    uint8_t out[32] = {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCryptHash(alg, nullptr, 0, static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), out, 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (int i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", out[i]);
    return hex;
}
bool ReadAll(const std::string& path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize(static_cast<size_t>(n));
    const bool ok = n == 0 || std::fread(out.data(), 1, static_cast<size_t>(n), f) == static_cast<size_t>(n);
    std::fclose(f);
    return ok;
}
uint64_t Fnv(const uint8_t* p, size_t n, uint64_t h = 1469598103934665603ull) {
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

extern "C" void* __cdecl HostAlloc(size_t size, void*) { return std::malloc(size ? size : 1); }
extern "C" void __cdecl HostFree(void* p) { std::free(p); }
void PatchJump(uint32_t va, const void* target) {   // mov eax, imm32 ; jmp eax   (private copy only)
    uint8_t* p = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(NA(va)));
    p[0] = 0xB8;
    const uint32_t t = PtrU(target);
    std::memcpy(p + 1, &t, 4);
    p[5] = 0xFF;
    p[6] = 0xE0;
}

bool MapImage(const std::vector<uint8_t>& file, const std::vector<uint8_t>& table) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(file.data() + dos->e_lfanew);
    if (nt->OptionalHeader.ImageBase != kImageBase) return false;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto* base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!base) return false;
    g_delta = reinterpret_cast<uintptr_t>(base) - kImageBase;
    std::memcpy(base, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const uint32_t n = std::min<uint32_t>(sec[i].SizeOfRawData, sec[i].Misc.VirtualSize);
        std::memcpy(base + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    auto* loadedNt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (!RelocateNativeImage(base, size, loadedNt, g_delta)) { VirtualFree(base, 0, MEM_RELEASE); return false; }
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(NA(ntw_formation_batch::va::kAngleTable))), table.data(), table.size());
    PatchJump(0x00FF7F20, reinterpret_cast<const void*>(&HostAlloc));
    PatchJump(0x00FF7EF0, reinterpret_cast<const void*>(&HostFree));
    *reinterpret_cast<int32_t*>(static_cast<uintptr_t>(NA(0x14A40B0))) = static_cast<int32_t>(0x80000000);
    *reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NA(0x1841BB8))) = _tls_index;
    g_tlsPad[0] = 0;
    std::printf("image mapped at %p (delta %08x), sha256 verified, pid %lu\n", static_cast<void*>(base), static_cast<unsigned>(g_delta),
                GetCurrentProcessId());
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}

// ---- original entry points ---------------------------------------------------------------------------------------------
using GenFn = void*(__thiscall*)(void* layout, void* out, void* container, float f, uint32_t men);
using WrapperFn = void(__thiscall*)(void* formation, void* slotVec, uint32_t flag, void* assignVec, int32_t layoutIdx);
using StatFn = void(__thiscall*)(void* formation, void* slotVec, float distance);
using EdgeFn = uint32_t(__thiscall*)(void* node, float* pos, float margin);

bool CallGen(uint32_t fn, void* layout, void* out, void* container, float f, uint32_t men) {
    __try { reinterpret_cast<GenFn>(static_cast<uintptr_t>(fn))(layout, out, container, f, men); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallWrapper(void* formation, void* slotVec, uint32_t flag, int32_t layoutIdx) {
    __try {
        reinterpret_cast<WrapperFn>(static_cast<uintptr_t>(NA(0x18F0A00)))(formation, slotVec, flag,
                                                                           static_cast<uint8_t*>(formation) + 0x518, layoutIdx);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallStat(void* formation, void* slotVec) {
    __try { reinterpret_cast<StatFn>(static_cast<uintptr_t>(NA(0x557C80)))(formation, slotVec, 4.0f); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Cell vtable slot 4 (vtable+0x10) variants.  G_HOST_LOAD / G_RETURN0 / G_RETURN_THIS are pure leaves Prepare may evaluate;
// G_HAZARD / G_LOAD_THEN_WRITE write the world and must never be executed by Prepare (decoded form is rejected).
enum Getter : uint8_t { G_HOST_LOAD = 0, G_RETURN0, G_RETURN_THIS, G_HAZARD, G_LOAD_THEN_WRITE, G__END };
// Ring link entry sets (on ring node 1 of a cell): flag byte of the real 0x54E920 leaf, a return-0 leaf, or a hazard virtual.
enum Link : uint8_t { L_NONE = 0, L_FLAG0, L_FLAG1, L_FLAG0_THEN_1, L_ZERO_THEN_1, L_FLAG1_THEN_HAZARD, L_FLAG0_THEN_HAZARD, L_HAZARD, L__END };
bool LinkExpected(uint8_t l) { return l == L_FLAG1 || l == L_FLAG0_THEN_1 || l == L_ZERO_THEN_1 || l == L_FLAG1_THEN_HAZARD; }   // 0x6B7F50 != 0

volatile long g_hazardCalls = 0;
__declspec(naked) void HostCellVfn10() { __asm { mov eax, [ecx + 0x40]   // 8B 41 40 C3: a decoded this-relative load leaf
                                                 ret } }
__declspec(naked) void HostTrap() { __asm { int 3 } }
// Side-effecting callbacks: count the call and write into the receiver.  Prepare must never get here.
__declspec(naked) void HostHazardLeaf() { __asm { lock inc dword ptr [g_hazardCalls]
                                                  mov dword ptr [ecx + 4], 0xBAD0BAD0
                                                  mov eax, 1
                                                  ret } }
// starts like the pure load leaf but is not one (a write follows before the RET)
__declspec(naked) void HostLoadThenWrite() { __asm { mov eax, [ecx + 0x40]
                                                     lock inc dword ptr [g_hazardCalls]
                                                     ret } }
void* g_cellVtbl[G__END][16];     // slot 4 = the getter under test, every other slot traps
void* g_linkVtblZero[1];          // slot 0 = 0x461180
void* g_linkVtblHazard[1];        // slot 0 = HostHazardLeaf

alignas(16) uint8_t g_edgeScratch[2][0x60];
bool EdgeOutside(float ax, float az, float bx, float bz, float px, float pz) {
    std::memset(g_edgeScratch, 0, sizeof g_edgeScratch);
    Put<uint32_t>(g_edgeScratch[0], 8, PtrU(g_edgeScratch[1]));
    Put<float>(g_edgeScratch[0], 0xC, ax); Put<float>(g_edgeScratch[0], 0x10, az);
    Put<float>(g_edgeScratch[1], 0xC, bx); Put<float>(g_edgeScratch[1], 0x10, bz);
    alignas(16) float pos[2] = {px, pz};
    const uint32_t r = reinterpret_cast<EdgeFn>(static_cast<uintptr_t>(NA(0x10F9A40)))(g_edgeScratch[0], pos, 0.0f);
    return (r & 0xFF) == 1;
}
bool g_ccwInside = true;   // ring orientation for which interior points are inside every edge (calibrated with the original)
void CalibrateOrientation() {
    const float xs[4] = {0, 10, 10, 0}, zs[4] = {0, 0, 10, 10};
    bool inside = true;
    for (int i = 0; i < 4; ++i) {
        const int j = (i + 1) & 3;
        if (EdgeOutside(xs[i], zs[i], xs[j], zs[j], 5, 5)) { inside = false; break; }
    }
    g_ccwInside = inside;
}

// ---- random -----------------------------------------------------------------------------------------------------------
struct Rng {
    std::mt19937_64 g;
    explicit Rng(uint64_t s) : g(s) {}
    uint32_t u(uint32_t n) { return n ? static_cast<uint32_t>(g() % n) : 0u; }
    uint32_t r(uint32_t a, uint32_t b) { return a + u(b - a + 1); }
    float f(float a, float b) { return std::uniform_real_distribution<float>(a, b)(g); }
    double d(double a, double b) { return std::uniform_real_distribution<double>(a, b)(g); }
    bool p(double pr) { return std::uniform_real_distribution<double>(0.0, 1.0)(g) < pr; }
};
uint64_t Mix64(uint64_t x) { x += 0x9E3779B97F4A7C15ull; x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull; x = (x ^ (x >> 27)) * 0x94D049BB133111EBull; return x ^ (x >> 31); }

// ---- specification of one formation -------------------------------------------------------------------------------------
struct PieceSpec {
    bool arc = false;
    int32_t mode = 0;
    uint16_t angle = 0;
    float p0[2]{}, p1[2]{}, step[2]{}, width = 0, arcStart[2]{}, dir[2]{}, center[2]{}, arcWidth = 0;
    std::vector<uint32_t> cells;      // indices into Spec::cells
};
struct FrameSpec { float t[3], fwd[9], inv[9]; };
struct CellSpec { float plane[4]; int32_t frame; bool nullG; float nx[4], nz[4]; uint8_t getter = G_HOST_LOAD, link = L_NONE; };
struct ManSpec { uint32_t vt; float x, z; uint16_t ang; uint32_t id; uint8_t skip; };
struct Spec {
    uint32_t men = 0;
    float f = 0, layout[4]{};
    uint32_t owner = 0;
    float origin[3]{};
    int32_t originFrame = -1;
    std::vector<PieceSpec> pieces;
    std::vector<CellSpec> cells;
    std::vector<FrameSpec> frames;
    uint32_t tShift = 0; int32_t tBase = 0, tLimit = 0; float tHalf = 0, tCell = 0, tScale = 0;
    std::vector<float> samples;       // 2 floats per entry
    std::vector<ManSpec> mans;
    bool mod = true;
    uint8_t unitFlag = 0;
    uint32_t side = 2;                // +0x1C of the side object; 0xFFFFFFFF = unit+0x2C is null
    uint16_t cw = 0x27F;
};

// ---- fixture: every native object at its native offsets ------------------------------------------------------------------
struct Mock {
    std::vector<uint8_t*> blocks;
    std::vector<size_t> sizes;
    std::vector<uint8_t*> men;
    std::unordered_map<uint32_t, uint32_t> manIdx;
    uint8_t* formation = nullptr;
    uint8_t* unit = nullptr;
    uint8_t* side = nullptr;
    uint8_t* layout = nullptr;
    uint8_t* container = nullptr;
    uint8_t* cmd = nullptr;
    uint8_t* menArray = nullptr;
    uint8_t* predEntry = nullptr;
    uint8_t* hdr = nullptr;           // generator vector header of the current run (heap block owned by the harness)
    uint32_t* layoutVtbl = nullptr;
    std::vector<uint8_t*> cellPtr;    // surface cell objects in Spec::cells order
    Mock() = default;
    Mock(const Mock&) = delete;
    Mock& operator=(const Mock&) = delete;
    ~Mock() {
        for (uint8_t* b : blocks) _aligned_free(b);
        _aligned_free(formation);
        std::free(layoutVtbl);
    }
    uint8_t* Alloc(size_t n) {
        uint8_t* p = static_cast<uint8_t*>(_aligned_malloc(n + 16, 16));
        std::memset(p, 0, n + 16);
        blocks.push_back(p);
        sizes.push_back(n);
        return p;
    }
    uint64_t HashBlocks() const {
        uint64_t h = 1469598103934665603ull;
        for (size_t i = 0; i < blocks.size(); ++i) h = Fnv(blocks[i], std::min<size_t>(sizes[i], 0x40), h);   // object heads: cheap, catches stray writes
        for (const uint8_t* m : men) h = Fnv(m, 0x700, h);
        return h;
    }
};

// Ring-link entries of one ring node (0x6B7F50 layout): node+0x44 = entry count, node+0x48 = array of 8-byte entries whose first
// dword is a link object; the object's embedded object sits at +0x1C (vtable pointer, flag byte at embedded+4 for the real
// 0x54E920 leaf).  Real leaves: vtable 0x132B5D8 (slot 0 = 0x54E920) and a vtable whose slot 0 is 0x461180.
void BuildLinks(Mock& k, uint8_t* node, uint8_t link) {
    struct Entry { uint32_t vtable; uint8_t flag; };
    const uint32_t real = NA(0x132B5D8), zero = PtrU(g_linkVtblZero), hazard = PtrU(g_linkVtblHazard);
    Entry e[2];
    uint32_t n = 0;
    switch (link) {
        case L_FLAG0: e[n++] = {real, 0}; break;
        case L_FLAG1: e[n++] = {real, 1}; break;
        case L_FLAG0_THEN_1: e[n++] = {real, 0}; e[n++] = {real, 1}; break;
        case L_ZERO_THEN_1: e[n++] = {zero, 0}; e[n++] = {real, 1}; break;
        case L_FLAG1_THEN_HAZARD: e[n++] = {real, 1}; e[n++] = {hazard, 0}; break;
        case L_FLAG0_THEN_HAZARD: e[n++] = {real, 0}; e[n++] = {hazard, 0}; break;
        case L_HAZARD: e[n++] = {hazard, 0}; break;
        default: return;
    }
    uint8_t* entries = k.Alloc(8u * n);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* object = k.Alloc(0x40);
        Put<uint32_t>(object, 0x1C, e[i].vtable);
        Put<uint8_t>(object, 0x20, e[i].flag);
        Put<uint32_t>(entries, 8 * i, PtrU(object));
    }
    Put<uint32_t>(node, 0x44, n);
    Put<uint32_t>(node, 0x48, PtrU(entries));
}

void Build(const Spec& s, Mock& k) {
    // frames
    std::vector<uint8_t*> framePtr(s.frames.size());
    for (size_t i = 0; i < s.frames.size(); ++i) {
        uint8_t* F = k.Alloc(0x100);
        framePtr[i] = F;
        for (int q = 0; q < 3; ++q) Put<float>(F, 0x80 + 4 * q, s.frames[i].t[q]);
        for (int q = 0; q < 9; ++q) Put<float>(F, 0x9C + 4 * q, s.frames[i].fwd[q]);
        for (int q = 0; q < 9; ++q) Put<float>(F, 0xC0 + 4 * q, s.frames[i].inv[q]);
    }
    // terrain chain X -> T -> U -> Q -> H (the native generator reads it for terrain-resident records)
    uint8_t* X = k.Alloc(0xC0);
    uint8_t* T = k.Alloc(8);
    uint8_t* U = k.Alloc(0x10);
    uint8_t* Q = k.Alloc(0xA0);
    uint8_t* H = k.Alloc(0x28);
    Put<uint32_t>(X, 0xB4, PtrU(T)); Put<uint32_t>(T, 0, PtrU(U)); Put<uint32_t>(U, 8, PtrU(Q)); Put<uint32_t>(Q, 0x9C, PtrU(H));
    {
        const size_t n8 = s.samples.size() * 4;
        uint8_t* smp = k.Alloc(n8 ? n8 : 8);
        std::memcpy(smp, s.samples.data(), n8);
        Put<uint32_t>(H, 0, PtrU(smp));
        Put<uint32_t>(H, 8, s.tShift);
        Put<int32_t>(H, 0x10, s.tBase);
        Put<int32_t>(H, 0x14, s.tLimit);
        Put<float>(H, 0x1C, s.tHalf); Put<float>(H, 0x20, s.tCell); Put<float>(H, 0x24, s.tScale);
    }
    // surface cells: ring of 4 nodes (link entries on node 1, see BuildLinks), plane, vtable slot 4 = the getter under test, and
    // the frame object G the getter yields: HOST_LOAD reads it from E+0x40, RETURN0 has none, RETURN_THIS yields E itself (its +0x80)
    std::vector<uint8_t*> cellPtr(s.cells.size());
    for (size_t i = 0; i < s.cells.size(); ++i) {
        const CellSpec& c = s.cells[i];
        uint8_t* nd[4];
        for (int q = 0; q < 4; ++q) nd[q] = k.Alloc(0x50);
        for (int q = 0; q < 4; ++q) {
            Put<uint32_t>(nd[q], 8, PtrU(nd[(q + 1) & 3]));
            Put<float>(nd[q], 0xC, c.nx[q]); Put<float>(nd[q], 0x10, c.nz[q]);
            Put<uint32_t>(nd[q], 0x44, 0);
        }
        BuildLinks(k, nd[1], c.link);
        uint8_t* E = k.Alloc(0x90);
        Put<uint32_t>(E, 0, PtrU(g_cellVtbl[c.getter]));
        Put<uint32_t>(E, 8, PtrU(nd[0]));
        for (int q = 0; q < 4; ++q) Put<float>(E, 0x30 + 4 * q, c.plane[q]);
        if (c.getter == G_RETURN_THIS) {
            Put<uint32_t>(E, 0x80, c.frame >= 0 ? PtrU(framePtr[static_cast<size_t>(c.frame)]) : 0);
        } else {
            uint8_t* G = nullptr;
            if (c.frame >= 0) { G = k.Alloc(0x90); Put<uint32_t>(G, 0x80, PtrU(framePtr[static_cast<size_t>(c.frame)])); }
            else if (!c.nullG) { G = k.Alloc(0x90); Put<uint32_t>(G, 0x80, 0); }
            Put<uint32_t>(E, 0x40, G ? PtrU(G) : 0);
        }
        cellPtr[i] = E;
    }
    k.cellPtr = cellPtr;
    // children + container
    std::vector<uint8_t*> childPtr(s.pieces.size());
    for (size_t i = 0; i < s.pieces.size(); ++i) {
        const PieceSpec& p = s.pieces[i];
        uint8_t* C = k.Alloc(0xB0);
        childPtr[i] = C;
        Put<uint32_t>(C, 0, NA(p.arc ? nb::va::kChildClassB : nb::va::kChildClassA));
        Put<int32_t>(C, 4, p.mode);
        Put<uint16_t>(C, 8, p.angle);
        Put<float>(C, 0xC, p.p0[0]); Put<float>(C, 0x10, p.p0[1]);
        Put<float>(C, 0x14, p.p1[0]); Put<float>(C, 0x18, p.p1[1]);
        Put<float>(C, 0x60, p.step[0]); Put<float>(C, 0x64, p.step[1]);
        Put<float>(C, 0x70, p.width);
        Put<float>(C, 0x7C, p.arcStart[0]); Put<float>(C, 0x80, p.arcStart[1]);
        Put<float>(C, 0x8C, p.dir[0]); Put<float>(C, 0x90, p.dir[1]);
        if (p.arc) { Put<float>(C, 0x98, p.center[0]); Put<float>(C, 0x9C, p.center[1]); Put<float>(C, 0xA0, p.arcWidth); }
        Put<uint32_t>(C, 0x1C, PtrU(X));
        const uint32_t n = static_cast<uint32_t>(p.cells.size());
        const uint32_t c1 = std::min<uint32_t>(n, 10), c2 = n - c1;
        Put<uint32_t>(C, 0x48, c1);
        Put<uint32_t>(C, 0x54, c2);
        for (uint32_t q = 0; q < c1; ++q) Put<uint32_t>(C, 0x20 + 4 * q, PtrU(cellPtr[p.cells[q]]));
        if (c2) {
            uint8_t* ov = k.Alloc(4u * c2);
            for (uint32_t q = 0; q < c2; ++q) Put<uint32_t>(ov, 4 * q, PtrU(cellPtr[p.cells[c1 + q]]));
            Put<uint32_t>(C, 0x58, PtrU(ov));
        }
    }
    k.container = k.Alloc(0x3C);
    Put<uint32_t>(k.container, 0x10, static_cast<uint32_t>(s.pieces.size()));
    uint8_t* arr = k.Alloc(4u * std::max<size_t>(s.pieces.size(), 1));
    for (size_t i = 0; i < s.pieces.size(); ++i) Put<uint32_t>(arr, 4 * static_cast<uint32_t>(i), PtrU(childPtr[i]));
    Put<uint32_t>(k.container, 0x14, PtrU(arr));
    Put<float>(k.container, 0x18, s.origin[0]); Put<float>(k.container, 0x1C, s.origin[1]); Put<float>(k.container, 0x20, s.origin[2]);
    Put<uint32_t>(k.container, 0x28, s.originFrame >= 0 ? PtrU(framePtr[static_cast<size_t>(s.originFrame)]) : 0);
    // layout object: pointer at formation+0x628, vtable = copy of the Line vtable with [+0x24] = the generator in use
    k.layout = k.Alloc(0x40);
    k.layoutVtbl = static_cast<uint32_t*>(std::calloc(0x40, 4));
    for (int q = 0; q < 0x12; ++q) k.layoutVtbl[q] = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(NA(0x1333AA8)))[q];
    k.layoutVtbl[0x24 / 4] = NA(s.mod ? nb::va::kGeneratorMod : nb::va::kGeneratorStock);
    Put<uint32_t>(k.layout, 0, PtrU(k.layoutVtbl));
    Put<uint32_t>(k.layout, 4, s.owner);
    for (int q = 0; q < 4; ++q) Put<float>(k.layout, 8 + 4 * q, s.layout[q]);
    // men
    const uint32_t n = static_cast<uint32_t>(s.mans.size());
    k.men.resize(n);
    k.menArray = k.Alloc(4u * (n + 1));
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* m = k.Alloc(0x700);
        const ManSpec& ms = s.mans[i];
        Put<uint32_t>(m, 0, NA(ms.vt));
        Put<float>(m, 0x48, ms.x); Put<float>(m, 0x50, ms.z);
        Put<uint16_t>(m, 0x64, ms.ang);
        Put<uint32_t>(m, 0x66C, ms.id);
        Put<uint8_t>(m, 0x1A8, ms.skip);
        k.men[i] = m;
        k.manIdx[PtrU(m)] = i;
        Put<uint32_t>(k.menArray, 4 * i, PtrU(m));
    }
    // unit: side object at +0x2C, 0x54C8B0 entry table at +0xDAC (count +0xC, data +0x10, stride 0x2C, [[e+4]] == 1, flag at e+0x28)
    k.unit = k.Alloc(0x1000);
    if (s.side != 0xFFFFFFFFu) {
        k.side = k.Alloc(0x100);
        Put<uint32_t>(k.side, 0x1C, s.side);
        Put<uint32_t>(k.unit, 0x2C, PtrU(k.side));
    }
    k.predEntry = k.Alloc(0x2C);
    uint8_t* idObj = k.Alloc(8);
    Put<uint32_t>(idObj, 0, 1);
    Put<uint32_t>(k.predEntry, 4, PtrU(idObj));
    Put<uint8_t>(k.predEntry, 0x28, s.unitFlag);
    Put<uint32_t>(k.unit, 0xDAC + 0xC, 1);
    Put<uint32_t>(k.unit, 0xDAC + 0x10, PtrU(k.predEntry));
    // formation (infantry vtable), tick chain for 0x557C80
    k.formation = static_cast<uint8_t*>(_aligned_malloc(0x2800, 16));
    std::memset(k.formation, 0, 0x2800);
    uint8_t* tickObj = k.Alloc(0x100);
    uint8_t* tickObj2 = k.Alloc(0x100);
    Put<uint32_t>(tickObj2, 0x58, 777);
    Put<uint32_t>(tickObj, 8, PtrU(tickObj2));
    Put<uint32_t>(k.formation, 0, NA(nb::va::kFormationVtable));
    Put<uint32_t>(k.formation, 4, PtrU(tickObj));
    Put<uint32_t>(k.formation, 0x14, n);
    Put<uint32_t>(k.formation, 0x18, n);
    Put<uint32_t>(k.formation, 0x1C, PtrU(k.menArray));
    Put<uint32_t>(k.formation, 0x510, PtrU(k.unit));
    Put<uint32_t>(k.formation, 0x628, PtrU(k.layout));
    Put<uint8_t>(k.formation, 0x278C, 1);
    Put<uint32_t>(k.formation, 0x2788, 0);
    // command object: formation [+4], container [+0x18], f [+0x1C]
    k.cmd = k.Alloc(0x80);
    Put<uint32_t>(k.cmd, 4, PtrU(k.formation));
    Put<uint32_t>(k.cmd, 0x18, PtrU(k.container));
    Put<float>(k.cmd, 0x1C, s.f);
}

// ---- running the original ------------------------------------------------------------------------------------------------------
struct Ent { uint32_t man, slot, costBits; };
struct Extracted {
    uint32_t cap = 0, count = 0;
    std::vector<Ent> e;
    std::vector<uint32_t> order;      // formation+0x1C after the 0x555CA0 tail
    uint32_t stat = 0;
    bool faulted = false;
};

bool RunGenerator(Mock& k, const Spec& s) {
    k.hdr = static_cast<uint8_t*>(_aligned_malloc(0x40, 16));
    std::memset(k.hdr, 0x5A, 0x40);
    const uint32_t gen = Get<uint32_t>(reinterpret_cast<const uint8_t*>(k.layoutVtbl), 0x24);
    uint32_t* flag = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NA(0x18ED160)));
    *flag = 0;
    const bool ok = CallGen(gen, k.layout, k.hdr, k.container, s.f, Get<uint32_t>(k.formation, 0x18));
    *flag = 0;
    return ok;
}
// The original allocates men*36 bytes and fills only `count` records; a path that reads past the count (slots < men) would
// see uninitialised heap.  Both twins get identical zeros so the comparison stays deterministic.
void ZeroTail(Mock& k) {
    const uint32_t cap = Get<uint32_t>(k.hdr, 4), cnt = Get<uint32_t>(k.hdr, 8), data = Get<uint32_t>(k.hdr, 0xC);
    if (data && cnt < cap) std::memset(reinterpret_cast<void*>(static_cast<uintptr_t>(data + 36u * cnt)), 0, 36u * (cap - cnt));
}
void FreeGenerator(Mock& k) {
    if (k.hdr) {
        const uint32_t data = Get<uint32_t>(k.hdr, 0xC);
        if (data) std::free(reinterpret_cast<void*>(static_cast<uintptr_t>(data)));
        _aligned_free(k.hdr);
        k.hdr = nullptr;
    }
}

Extracted ExtractAndTail(Mock& k) {
    Extracted x;
    x.cap = Get<uint32_t>(k.formation, 0x51C);
    x.count = Get<uint32_t>(k.formation, 0x520);
    const uint32_t data = Get<uint32_t>(k.formation, 0x524);
    const uint32_t slotData = Get<uint32_t>(k.hdr, 0xC);
    for (uint32_t i = 0; i < x.count; ++i) {
        Ent e;
        const uint32_t man = Get<uint32_t>(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(data)), 12 * i);
        const uint32_t slot = Get<uint32_t>(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(data)), 12 * i + 4);
        e.costBits = Get<uint32_t>(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(data)), 12 * i + 8);
        if (man == 0) e.man = 0xFFFFFFFFu;
        else { auto it = k.manIdx.find(man); e.man = it == k.manIdx.end() ? 0xFFFFFFFEu : it->second; }
        if (slot == 0) e.slot = 0xFFFFFFFFu;
        else if (slot < slotData || (slot - slotData) % 36 != 0) e.slot = 0xFFFFFFFEu;
        else e.slot = (slot - slotData) / 36;
        x.e.push_back(e);
    }
    // 0x555CA0 tail: formation+0x1C := entry men, +0x18 := count, then 0x557C80
    Put<uint32_t>(k.formation, 0x18, x.count);
    for (uint32_t i = 0; i < x.count && i < k.men.size(); ++i) {
        const Ent& e = x.e[i];
        Put<uint32_t>(k.menArray, 4 * i, e.man < k.men.size() ? PtrU(k.men[e.man]) : 0u);
    }
    Put<uint32_t>(k.formation, 0x2784, 0xDEADBEEFu);
    if (!CallStat(k.formation, k.hdr)) x.faulted = true;
    x.stat = Get<uint32_t>(k.formation, 0x2784);
    for (uint32_t i = 0; i < x.count; ++i) {
        const uint32_t p = Get<uint32_t>(k.menArray, 4 * i);
        auto it = k.manIdx.find(p);
        x.order.push_back(it == k.manIdx.end() ? 0xFFFFFFFFu : it->second);
    }
    return x;
}

bool SameExtracted(const Extracted& a, const Extracted& b, std::string* why) {
    char buf[200];
    if (a.faulted || b.faulted) { *why = "0x557C80 faulted"; return false; }
    if (a.cap != b.cap || a.count != b.count) {
        std::snprintf(buf, sizeof buf, "vector cap/count adapter %u/%u native %u/%u", a.cap, a.count, b.cap, b.count);
        *why = buf; return false;
    }
    for (uint32_t i = 0; i < a.count; ++i)
        if (a.e[i].man != b.e[i].man || a.e[i].slot != b.e[i].slot || a.e[i].costBits != b.e[i].costBits) {
            std::snprintf(buf, sizeof buf, "entry %u adapter(man %u slot %u cost %08x) native(man %u slot %u cost %08x)", i, a.e[i].man,
                          a.e[i].slot, a.e[i].costBits, b.e[i].man, b.e[i].slot, b.e[i].costBits);
            *why = buf; return false;
        }
    if (a.order != b.order) { *why = "formation+0x1C order differs"; return false; }
    if (a.stat != b.stat) { *why = "formation+0x2784 differs"; return false; }
    return true;
}

// ---- case generation ------------------------------------------------------------------------------------------------------
FrameSpec MakeFrame(Rng& r) {
    FrameSpec F;
    const double th = r.d(0, 6.283185307179586), c = std::cos(th), sn = std::sin(th);
    const float fw[9] = {float(c), 0, float(sn), 0, 1, 0, float(-sn), 0, float(c)};
    const float iv[9] = {float(c), 0, float(-sn), 0, 1, 0, float(sn), 0, float(c)};
    std::memcpy(F.fwd, fw, sizeof fw);
    std::memcpy(F.inv, iv, sizeof iv);
    for (int q = 0; q < 3; ++q) F.t[q] = r.f(-50, 50);
    return F;
}

void MakeTerrain(Rng& r, Spec& s) {
    const uint32_t k = r.r(3, 6);
    s.tShift = k;
    s.tLimit = static_cast<int32_t>(r.r(3, (1u << k) - 1));
    s.tBase = s.tLimit / 2;
    s.tCell = r.f(2.0f, 10.0f);
    s.tScale = 1.0f / s.tCell;
    s.tHalf = s.tCell * static_cast<float>(s.tBase > 0 ? s.tBase : 1);
    const size_t entries = (static_cast<size_t>(s.tLimit) << k) + static_cast<size_t>(s.tLimit) + 1;
    s.samples.resize(entries * 2);
    for (size_t i = 0; i < entries; ++i) { s.samples[2 * i] = r.f(0.0f, 100.0f); s.samples[2 * i + 1] = r.f(-1000.0f, 1000.0f); }
}

// Wiring of a cover cell: which getter yields its frame object and which link entries sit on its ring node 1.  Derived from the
// cell's own plane (no RNG draw, so the random stream of the original scenario is unchanged).  Only side-effect free kinds are
// chosen here: the native twin runs the ORIGINAL generator on these objects.  RETURN0 needs "no frame object", RETURN_THIS needs one.
void ChooseWiring(CellSpec& c) {
    const uint64_t h = Mix64((static_cast<uint64_t>(FBits(c.plane[0])) << 32) ^ FBits(c.plane[1]) ^ (static_cast<uint64_t>(FBits(c.plane[3])) << 17) ^
                             (c.nullG ? 0x5A5Aull : 0ull) ^ static_cast<uint64_t>(c.frame + 1));
    const bool hasG = c.frame >= 0 || !c.nullG;
    c.getter = hasG ? ((h & 1) ? G_RETURN_THIS : G_HOST_LOAD) : ((h & 1) ? G_RETURN0 : G_HOST_LOAD);
    static const uint8_t pool[8] = {L_NONE, L_NONE, L_FLAG0, L_FLAG1, L_FLAG0_THEN_1, L_ZERO_THEN_1, L_FLAG1_THEN_HAZARD, L_FLAG1};
    c.link = pool[(h >> 8) & 7];
}

// optional huge cover cell (so records become cell-resident: plane height, optional frame); ring orientation calibrated
CellSpec MakeCoverCell(Rng& r, const Spec& s) {
    CellSpec c{};
    const float xs[4] = {-1e5f, 1e5f, 1e5f, -1e5f}, zs[4] = {-1e5f, -1e5f, 1e5f, 1e5f};
    for (int q = 0; q < 4; ++q) {
        const int qq = g_ccwInside ? q : 3 - q;
        c.nx[q] = xs[qq]; c.nz[q] = zs[qq];
    }
    const float a = r.f(-0.5f, 0.5f), b = r.f(0.3f, 1.5f), cc = r.f(-0.5f, 0.5f), y0 = r.f(0.0f, 60.0f);
    c.plane[0] = a; c.plane[1] = b; c.plane[2] = cc; c.plane[3] = -(cc * 0.0f + a * 0.0f + b * y0);
    c.frame = (!s.frames.empty() && r.p(0.5)) ? static_cast<int32_t>(r.u(static_cast<uint32_t>(s.frames.size()))) : -1;
    c.nullG = r.p(0.5);
    ChooseWiring(c);
    return c;
}

Spec MakeSpec(Rng& r) {
    Spec s;
    s.men = r.p(0.1) ? r.r(2, 12) : r.r(20, 420);
    s.mod = r.p(0.7);
    s.layout[0] = r.f(0.5f, 1.0f); s.layout[1] = s.layout[0]; s.layout[2] = r.f(0.3f, 0.5f); s.layout[3] = r.f(5.0f, 12.0f);   // live-like
    s.f = r.f(30.0f, 90.0f);
    s.owner = static_cast<uint32_t>(r.g());
    const bool useFrames = r.p(0.35);
    if (useFrames) { const uint32_t nf = r.r(1, 2); for (uint32_t i = 0; i < nf; ++i) s.frames.push_back(MakeFrame(r)); }
    s.origin[0] = r.f(-100, 100); s.origin[1] = r.f(-5, 5); s.origin[2] = r.f(-100, 100);
    s.originFrame = (useFrames && r.p(0.3)) ? 0 : -1;
    MakeTerrain(r, s);
    const uint32_t np = 1u + (r.p(0.4) ? 1u : 0u) + (r.p(0.15) ? 1u : 0u);
    float cx = s.origin[0], cz = s.origin[2];
    const bool garbage = r.p(0.5);
    auto g = [&]() { return garbage ? r.f(-100, 100) : 0.0f; };
    for (uint32_t i = 0; i < np; ++i) {
        PieceSpec p;
        p.arc = i > 0 && r.p(0.5);
        p.mode = static_cast<int32_t>(p.arc ? r.r(0, 2) : r.r(0, 3));
        p.angle = static_cast<uint16_t>(r.u(65536));
        const float sx = cx, sz = cz;
        const float width = s.f - r.f(0.0f, 1.0f);
        if (!p.arc) {
            const float len = i == 0 ? r.f(300.0f, 900.0f) : r.f(100.0f, 400.0f);
            const float h = r.f(0.0f, 6.2831853f);
            p.p0[0] = sx; p.p0[1] = sz;
            p.p1[0] = sx + len * std::cos(h); p.p1[1] = sz + len * std::sin(h);
            p.dir[0] = (p.p1[0] - p.p0[0]) / len; p.dir[1] = (p.p1[1] - p.p0[1]) / len;
            const float sg = r.p(0.5) ? 1.0f : -1.0f;
            p.step[0] = -p.dir[1] * sg; p.step[1] = p.dir[0] * sg;
            p.width = width;
            p.arcStart[0] = g(); p.arcStart[1] = g();
            cx = p.p1[0]; cz = p.p1[1];
        } else {
            const float R = r.f(5.0f, 60.0f), a0 = r.f(0.0f, 6.2831853f);
            const float sweep = r.f(0.3f, 2.5f) * (r.p(0.5) ? 1.0f : -1.0f);
            p.arcStart[0] = sx; p.arcStart[1] = sz;
            p.center[0] = sx - R * std::cos(a0); p.center[1] = sz - R * std::sin(a0);
            p.p1[0] = p.center[0] + R * std::cos(a0 + sweep); p.p1[1] = p.center[1] + R * std::sin(a0 + sweep);
            const float sg = sweep > 0 ? 1.0f : -1.0f;
            p.dir[0] = -std::sin(a0) * sg; p.dir[1] = std::cos(a0) * sg;
            p.arcWidth = width;
            p.p0[0] = g(); p.p0[1] = g();
            p.step[0] = g(); p.step[1] = g();
            p.width = g();
            cx = p.p1[0]; cz = p.p1[1];
        }
        if (r.p(0.4)) {
            p.cells.push_back(static_cast<uint32_t>(s.cells.size()));
            s.cells.push_back(MakeCoverCell(r, s));
        }
        s.pieces.push_back(p);
    }
    // men
    static const uint32_t kAnchoredVt[3] = {0x13477F8, 0x13479B4, 0x1347B70};
    s.mans.resize(s.men);
    for (uint32_t i = 0; i < s.men; ++i) {
        ManSpec& m = s.mans[i];
        m.vt = 0x1333714;
        m.x = s.origin[0] + r.f(-60.0f, 60.0f);
        m.z = s.origin[2] + r.f(-40.0f, 40.0f);
        m.ang = static_cast<uint16_t>(r.u(65536));
        m.id = r.p(0.2) ? 0x57460000u + r.r(0, 2) : static_cast<uint32_t>(r.g());
        m.skip = r.p(0.08) ? 1 : 0;
    }
    const uint32_t extra = r.r(0, 6);
    for (uint32_t a = 0; a < extra && a < s.men; ++a) s.mans[r.u(s.men)].vt = kAnchoredVt[r.u(3)];
    if (s.men >= 12 && r.p(0.7)) {
        uint32_t idx[3] = {r.u(s.men), r.u(s.men), r.u(s.men)};
        if (idx[0] != idx[1] && idx[0] != idx[2] && idx[1] != idx[2])
            for (uint32_t q = 0; q < 3; ++q) { s.mans[idx[q]].vt = nb::va::kOfficerVtable; s.mans[idx[q]].id = 0x57460000u + q; }
    }
    s.unitFlag = r.p(0.25) ? 1 : 0;
    s.side = r.p(0.05) ? 0xFFFFFFFFu : (r.p(0.85) ? 2u : 1u);
    static const uint16_t kCw[3] = {0x27F, 0x37F, 0x7F};
    s.cw = kCw[r.u(3)];
    return s;
}

enum Mut : int {
    M_NONE = 0, M_X, M_Z, M_ANGLE, M_SWAP, M_COUNT, M_CLASS, M_SKIP, M_MARKER, M_SLOTX, M_SLOTCOUNT, M_PRED, M_SIDE,
    M_GENERATOR, M_CW, M_FLAG, M_LAYOUTIDX, M__END
};
const char* MutName(int m) {
    static const char* n[M__END] = {"none", "man-x", "man-z", "man-angle", "man-swap", "men-count", "man-class", "man-skip", "man-marker",
                                    "slot-x", "slot-count", "unit-predicate", "side", "generator", "fpu-cw", "flag-arg", "layout-index"};
    return m >= 0 && m < M__END ? n[m] : "?";
}

struct UnitCase {
    Spec spec;
    Mock a, b;
    int mutation = M_NONE;
    uint32_t i1 = 0, i2 = 0;
    uint32_t unitIndex = 0xFFFFFFFFu, unitIndexSerial = 0xFFFFFFFFu;
    uint16_t consumeCw = 0x27F;
    uint32_t flagArg = 1;
    int32_t layoutArg = -1;
};

// returns the reason Consume must report when the job was executed; M_NONE -> kOk
nb::Reason ExpectedReason(int m) {
    switch (m) {
        case M_X: case M_Z: case M_ANGLE: case M_SKIP: case M_MARKER: case M_CLASS: return nb::kMenState;
        case M_SWAP: return nb::kMenMembership;
        case M_COUNT: return nb::kMenCount;
        case M_SLOTX: return nb::kSlotGeometry;
        case M_SLOTCOUNT: return nb::kSlotCount;
        case M_PRED: return nb::kUnitPredicate;
        case M_SIDE: return nb::kModEligibility;
        case M_GENERATOR: return nb::kLayoutChanged;
        case M_CW: return nb::kFpuControlWord;
        case M_FLAG: case M_LAYOUTIDX: return nb::kCallArguments;
        default: return nb::kOk;
    }
}

// Applies the post-Prepare change to ONE twin (called for both with identical indices).  Returns false if the mutation does not
// apply to this unit (then it behaves as M_NONE).
bool ApplyMutation(UnitCase& u, Mock& k, int m) {
    const uint32_t n = static_cast<uint32_t>(k.men.size());
    switch (m) {
        case M_X: { auto* p = k.men[u.i1 % n]; Put<float>(p, 0x48, Get<float>(p, 0x48) + 0.015625f); return true; }
        case M_Z: { auto* p = k.men[u.i1 % n]; Put<float>(p, 0x50, Get<float>(p, 0x50) + 0.015625f); return true; }
        case M_ANGLE: { auto* p = k.men[u.i1 % n]; Put<uint16_t>(p, 0x64, static_cast<uint16_t>(Get<uint16_t>(p, 0x64) + 1)); return true; }
        case M_SKIP: { auto* p = k.men[u.i1 % n]; Put<uint8_t>(p, 0x1A8, Get<uint8_t>(p, 0x1A8) ? 0 : 1); return true; }
        case M_SWAP: {
            if (n < 2) return false;
            const uint32_t a = u.i1 % n, b = (a + 1 + u.i2 % (n - 1)) % n;
            const uint32_t pa = Get<uint32_t>(k.menArray, 4 * a), pb = Get<uint32_t>(k.menArray, 4 * b);
            Put<uint32_t>(k.menArray, 4 * a, pb); Put<uint32_t>(k.menArray, 4 * b, pa);
            return true;
        }
        case M_COUNT:
            if (n < 2) return false;
            Put<uint32_t>(k.formation, 0x18, n - 1);
            return true;
        case M_CLASS: {
            auto* p = k.men[u.i1 % n];
            Put<uint32_t>(p, 0, Get<uint32_t>(p, 0) == NA(0x1333714) ? NA(0x13477F8) : NA(0x1333714));
            return true;
        }
        case M_MARKER:
            for (uint32_t i = 0; i < n; ++i)
                if (u.spec.mans[i].vt == nb::va::kOfficerVtable) {
                    const uint32_t id = Get<uint32_t>(k.men[i], 0x66C);
                    Put<uint32_t>(k.men[i], 0x66C, 0x57460000u + ((id - 0x57460000u + 1u) % 3u));
                    return true;
                }
            return false;
        case M_SLOTX: {
            const uint32_t cnt = Get<uint32_t>(k.hdr, 8), data = Get<uint32_t>(k.hdr, 0xC);
            if (!cnt) return false;
            uint8_t* rec = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(data)) + 36u * (u.i1 % cnt);
            Put<float>(rec, 4, Get<float>(rec, 4) + 0.5f);
            return true;
        }
        case M_SLOTCOUNT: {
            const uint32_t cnt = Get<uint32_t>(k.hdr, 8);
            if (cnt < 2) return false;
            Put<uint32_t>(k.hdr, 8, cnt - 1);
            return true;
        }
        case M_PRED: Put<uint8_t>(k.predEntry, 0x28, Get<uint8_t>(k.predEntry, 0x28) ? 0 : 1); return true;
        case M_SIDE:
            if (!k.side || !u.spec.mod) return false;
            Put<uint32_t>(k.side, 0x1C, Get<uint32_t>(k.side, 0x1C) == 2 ? 1u : 2u);
            return true;
        case M_GENERATOR:
            k.layoutVtbl[0x24 / 4] = k.layoutVtbl[0x24 / 4] == NA(nb::va::kGeneratorMod) ? NA(nb::va::kGeneratorStock) : NA(nb::va::kGeneratorMod);
            return true;
        default: return false;
    }
}

// ---- pool / dispatchers ---------------------------------------------------------------------------------------------------
void __stdcall SerialDispatch(uint32_t, uint32_t body, uint32_t chunks, void* ctx) {
    auto fn = reinterpret_cast<void(__fastcall*)(void*, uint32_t)>(static_cast<uintptr_t>(body));
    for (uint32_t i = 0; i < chunks; ++i) fn(ctx, i);
}

ntw_pool* g_pool = nullptr;
bool StartPool(uint32_t workers) {
    g_pool = static_cast<ntw_pool*>(_aligned_malloc(NTW_POOL_BYTES, NTW_POOL_ALIGN));
    std::memset(g_pool, 0, NTW_POOL_BYTES);
    ntw_pool_config cfg;
    std::memset(&cfg, 0, sizeof cfg);
    cfg.abi = NTW_POOL_ABI;
    cfg.workers = workers;
    cfg.stack_bytes = 0;
    cfg.api.create_event = reinterpret_cast<uint32_t>(&CreateEventW);
    cfg.api.close_handle = reinterpret_cast<uint32_t>(&CloseHandle);
    cfg.api.set_event = reinterpret_cast<uint32_t>(&SetEvent);
    cfg.api.wait_single = reinterpret_cast<uint32_t>(&WaitForSingleObject);
    cfg.api.create_thread = reinterpret_cast<uint32_t>(&CreateThread);
    cfg.api.worker_entry = reinterpret_cast<uint32_t>(&ntw_pool_worker_start);
    const ntw_u32 r = ntw_pool_init(g_pool, &cfg);
    if (r != NTW_POOL_OK) { std::printf("ntw_pool_init failed %u\n", r); return false; }
    return true;
}

// ---- statistics ----------------------------------------------------------------------------------------------------------------
struct Tally {
    uint32_t units = 0, preparedOk = 0, executed = 0, committedCompared = 0, fallbackCompared = 0, mismatches = 0, plumbing = 0;
    uint32_t mutApplied[M__END] = {}, mutRefused[M__END] = {};
    uint32_t mod = 0, stock = 0, withCell = 0, withFrame = 0, withArc = 0, officers = 0, serialEqual = 0, nativeFaults = 0, jobsFailed = 0;
    uint32_t cwDistinct[3] = {};
    uint32_t slotsNoHeightUnits = 0;
    uint32_t cellsVerified = 0, framesVerified = 0, linkNodes = 0, linkNodesSet = 0, hazardGates = 0;
    uint32_t getterRuns[G__END] = {}, linkKinds[L__END] = {};
};
void Fail(Tally& t, const char* tag, uint32_t unit, const std::string& why, bool plumbing) {
    if (plumbing) ++t.plumbing; else ++t.mismatches;
    if (t.mismatches + t.plumbing <= 20) std::printf("%s [%s unit %u]: %s\n", plumbing ? "PLUMBING" : "MISMATCH", tag, unit, why.c_str());
}

bool SameJob(const nb::UnitJob& a, const nb::UnitJob& b) {
    if (a.state != b.state || a.reason != b.reason || a.layoutStatus != b.layoutStatus || a.assignStatus != b.assignStatus ||
        a.slotCount != b.slotCount || a.layoutResult.count != b.layoutResult.count || a.layoutResult.mark != b.layoutResult.mark ||
        a.men != b.men)
        return false;
    if (a.state != nb::kExecuted) return true;
    if (a.assign.entryCount != b.assign.entryCount || a.assign.refreshZero != b.assign.refreshZero ||
        a.assign.solverIterations != b.assign.solverIterations)
        return false;
    if (std::memcmp(a.views.entries, b.views.entries, sizeof(ns::Entry) * a.assign.entryCount) != 0) return false;
    if (std::memcmp(a.views.slotX, b.views.slotX, 4u * a.slotCount) != 0 || std::memcmp(a.views.slotZ, b.views.slotZ, 4u * a.slotCount) != 0 ||
        std::memcmp(a.views.slotAngle, b.views.slotAngle, 2u * a.slotCount) != 0)
        return false;
    return true;
}

nb::Batch g_batchPool, g_batchSerial;
void* g_storageA = nullptr; void* g_storageB = nullptr;
size_t g_storageBytes = 0;
nb::Config MakeConfig() {
    nb::Config c;
    c.imageDelta = static_cast<uint32_t>(g_delta);
    c.maxUnits = 128;
    c.maxMen = 4096;
    c.maxPieces = 16;
    c.maxNodes = 512;
    c.maxCooldown = 0;
    return c;
}

bool InitBatches() {
    const nb::Config cfg = MakeConfig();
    g_storageBytes = nb::Batch::StorageBytes(cfg, 24u << 20);
    g_storageA = VirtualAlloc(nullptr, g_storageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    g_storageB = VirtualAlloc(nullptr, g_storageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_storageA || !g_storageB) return false;
    const nb::Reason a = g_batchPool.Init(g_storageA, g_storageBytes, cfg);
    const nb::Reason b = g_batchSerial.Init(g_storageB, g_storageBytes, cfg);
    if (a != nb::kOk || b != nb::kOk) {
        std::printf("Batch::Init failed: %s / %s\n", nb::ReasonName(a), nb::ReasonName(b));
        return false;
    }
    return true;
}

// ---- Prepare against the ORIGINAL callbacks ------------------------------------------------------------------------------------
// Calls original (or pure fixture) code on twin A's objects, only after Prepare ran: the ring-link flag of every node (0x6B7F50), the
// cell frame receiver (vtable+0x10) and the frame matrices behind them must equal what Prepare copied without executing anything.
uint32_t M32(uint32_t a) { return Get<uint32_t>(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(a)), 0); }
bool NativeThis(uint32_t fn, uint32_t ecx, uint32_t* eax) {
    __try { *eax = reinterpret_cast<uint32_t(__thiscall*)(void*)>(static_cast<uintptr_t>(fn))(reinterpret_cast<void*>(static_cast<uintptr_t>(ecx))); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool SameFrame(const nf::Frame& f, uint32_t fp) {
    for (uint32_t q = 0; q < 3; ++q) if (FBits(f.t[q]) != M32(fp + 0x80 + 4 * q)) return false;
    for (uint32_t q = 0; q < 9; ++q) if (FBits(f.fwd[q]) != M32(fp + 0x9C + 4 * q) || FBits(f.inv[q]) != M32(fp + 0xC0 + 4 * q)) return false;
    return true;
}
void VerifyPrepared(Tally& t, uint32_t unit, const nb::UnitJob& job, const Spec& s, const Mock& k) {
    char buf[200];
    const uint32_t ofp = Get<uint32_t>(k.container, 0x28);
    if (ofp ? (job.in.origin.frame < 0 || !SameFrame(job.frames[job.in.origin.frame], ofp)) : job.in.origin.frame != -1)
        Fail(t, "prepare-origin-frame", unit, "origin frame differs from the container's", false);
    uint32_t ci = 0;
    for (const PieceSpec& p : s.pieces) {
        for (const uint32_t idx : p.cells) {
            if (ci >= job.in.cellCount) { Fail(t, "prepare-cells", unit, "fewer prepared cells than the fixture has", false); return; }
            const CellSpec& cs = s.cells[idx];
            const uint32_t E = PtrU(k.cellPtr[idx]);
            const nf::SurfaceCell& c = job.cells[ci++];
            ++t.cellsVerified;
            ++t.getterRuns[cs.getter];
            ++t.linkKinds[cs.link];
            uint32_t G = 0;
            if (!NativeThis(M32(M32(E) + 0x10), E, &G)) { Fail(t, "prepare-native-getter", unit, "native cell getter faulted", true); continue; }
            const uint32_t fp = G ? M32(G + 0x80) : 0;
            if (fp ? (c.frame < 0 || !SameFrame(job.frames[c.frame], fp)) : c.frame != -1) {
                std::snprintf(buf, sizeof buf, "cell %u getter %u frame index %d, native frame object %08x", idx, cs.getter, c.frame, fp);
                Fail(t, "prepare-cell-frame", unit, buf, false);
            } else if (fp) {
                ++t.framesVerified;
            }
            uint32_t node = M32(E + 8);
            const uint32_t head = node;
            uint32_t q = 0;
            do {
                if (q >= c.nodeCount) { ++q; break; }   // native ring longer than the prepared one: reported below
                uint32_t nat = 0;
                if (!NativeThis(NA(nb::va::kRingLink), node, &nat)) { Fail(t, "prepare-native-ring", unit, "native 0x6B7F50 faulted", true); break; }
                const uint8_t has = job.nodes[c.nodeBegin + q].hasLink;
                const uint8_t spec = (q == 1 && LinkExpected(cs.link)) ? 1 : 0;
                if (has != (nat != 0 ? 1 : 0) || has != spec) {
                    std::snprintf(buf, sizeof buf, "cell %u node %u link kind %u: job %u native %u fixture %u", idx, q, cs.link, has, nat != 0 ? 1u : 0u, spec);
                    Fail(t, "prepare-ring-link", unit, buf, false);
                }
                ++t.linkNodes;
                t.linkNodesSet += has;
                node = M32(node + 8);
                ++q;
            } while (node != head);
            if (q != c.nodeCount) Fail(t, "prepare-ring-length", unit, "prepared ring length differs from the fixture's", false);
        }
    }
    if (ci != job.in.cellCount) Fail(t, "prepare-cells", unit, "prepared cell count differs from the fixture's", false);
}

// ---- one batch round: build -> prepare -> execute (pool, serial) -> per-unit original generator + Consume ------------------------
void RunRound(uint32_t round, uint32_t unitsPerRound, uint64_t seed, Tally& t, uint32_t* mutRotor) {
    std::vector<std::unique_ptr<UnitCase>> us;
    for (uint32_t i = 0; i < unitsPerRound; ++i) {
        Rng r(Mix64(seed ^ Mix64(round * 4099ull + i + 1)));
        auto u = std::make_unique<UnitCase>();
        u->spec = MakeSpec(r);
        // mutation plan: half the units stay clean, the others rotate through every mutation so each is hit repeatedly
        u->mutation = r.p(0.45) ? M_NONE : 1 + static_cast<int>((*mutRotor)++ % (M__END - 1));
        u->i1 = r.u(1u << 20); u->i2 = r.u(1u << 20);
        u->consumeCw = u->spec.cw;
        Build(u->spec, u->a);
        Build(u->spec, u->b);
        us.push_back(std::move(u));
    }
    g_batchPool.Begin();
    g_batchSerial.Begin();
    for (uint32_t i = 0; i < us.size(); ++i) {
        UnitCase& u = *us[i];
        SetCw(u.spec.cw);
        const nb::Reason ra = g_batchPool.Prepare(PtrU(u.a.cmd), &u.unitIndex);
        const nb::Reason rb = g_batchSerial.Prepare(PtrU(u.a.cmd), &u.unitIndexSerial);
        if (ra != nb::kOk || rb != nb::kOk) {
            Fail(t, "prepare", i, std::string("Prepare refused a valid unit: ") + nb::ReasonName(ra) + "/" + nb::ReasonName(rb), true);
            u.unitIndex = 0xFFFFFFFFu;
        } else {
            ++t.preparedOk;
            VerifyPrepared(t, i, *g_batchPool.Job(u.unitIndex), u.spec, u.a);
        }
    }
    SetCw(0x27F);
    uint32_t runA = 0, runB = 0;
    const nb::Dispatcher pool{&ntw_pool_dispatch, PtrU(g_pool)};
    const nb::Dispatcher serial{&SerialDispatch, 0};
    const nb::Reason ea = g_batchPool.Execute(pool, &runA);
    const nb::Reason eb = g_batchSerial.Execute(serial, &runB);
    if ((ea != nb::kOk && ea != nb::kNothingPrepared) || (eb != nb::kOk && eb != nb::kNothingPrepared) || runA != runB)
        Fail(t, "execute", round, std::string("Execute: ") + nb::ReasonName(ea) + "/" + nb::ReasonName(eb), true);
    t.executed += runA;
    for (uint32_t i = 0; i < us.size(); ++i) {
        UnitCase& u = *us[i];
        if (u.unitIndex == 0xFFFFFFFFu) continue;
        const nb::UnitJob* ja = g_batchPool.Job(u.unitIndex);
        const nb::UnitJob* jb = g_batchSerial.Job(u.unitIndexSerial);
        if (!ja || !jb || !SameJob(*ja, *jb)) Fail(t, "serial-vs-pool", i, "pooled and serial Execute differ", false);
        else ++t.serialEqual;
        if (ja && ja->state == nb::kFailed) ++t.jobsFailed;
    }

    // ---- the tick: units in original order ----
    for (uint32_t i = 0; i < us.size(); ++i) {
        UnitCase& u = *us[i];
        ++t.units;
        const Spec& s = u.spec;
        if (s.mod) ++t.mod; else ++t.stock;
        if (!s.cells.empty()) ++t.withCell;
        if (!s.frames.empty()) ++t.withFrame;
        for (const auto& p : s.pieces) if (p.arc) { ++t.withArc; break; }
        for (const auto& m : s.mans) if (m.vt == nb::va::kOfficerVtable) { ++t.officers; break; }
        ++t.cwDistinct[s.cw == 0x27F ? 0 : s.cw == 0x37F ? 1 : 2];
        SetCw(s.cw);
        if (!RunGenerator(u.a, s) || !RunGenerator(u.b, s)) { Fail(t, "generator", i, "original generator faulted", true); ++t.nativeFaults; FreeGenerator(u.a); FreeGenerator(u.b); SetCw(0x27F); continue; }
        ZeroTail(u.a);   // records past the generated count are uninitialised heap in the original; make them identical in both twins
        ZeroTail(u.b);
        if (u.unitIndex == 0xFFFFFFFFu) { FreeGenerator(u.a); FreeGenerator(u.b); continue; }

        const nb::UnitJob* job = g_batchPool.Job(u.unitIndex);
        const bool jobExecuted = job->state == nb::kExecuted;
        const nb::Reason jobReason = static_cast<nb::Reason>(job->reason);
        for (uint32_t q = 0; q < job->slotCount; ++q) if (!job->slots[q].yValid) { ++t.slotsNoHeightUnits; break; }

        int mut = u.mutation;
        if (mut != M_NONE) {
            const bool a1 = ApplyMutation(u, u.a, mut);
            const bool a2 = ApplyMutation(u, u.b, mut);
            if (a1 != a2) Fail(t, "mutation", i, "mutation applied to one twin only", true);
            if (!a1 && mut != M_CW && mut != M_FLAG && mut != M_LAYOUTIDX) mut = M_NONE;
        }
        uint32_t flagArg = 1;
        int32_t layoutArg = -1;
        uint16_t cwConsume = s.cw;
        if (mut == M_CW) cwConsume = s.cw == 0x27F ? 0x37F : 0x27F;
        if (mut == M_FLAG) flagArg = 0;
        if (mut == M_LAYOUTIDX) layoutArg = static_cast<int32_t>(std::min<uint32_t>(2, static_cast<uint32_t>(s.men) - 1));
        ++t.mutApplied[mut];

        // the adapter must never write the generator vector or any object but the entry vector
        const uint64_t before = u.a.HashBlocks();
        const uint32_t slotCnt = Get<uint32_t>(u.a.hdr, 8), slotData = Get<uint32_t>(u.a.hdr, 0xC);
        const uint64_t slotBefore = Fnv(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(slotData)), 36u * slotCnt);
        nb::AssignCall call;
        call.formation = PtrU(u.a.formation);
        call.slotVec = PtrU(u.a.hdr);
        call.flag = flagArg;
        call.assignVec = PtrU(u.a.formation) + 0x518;
        call.layoutIndex = layoutArg;
        SetCw(cwConsume);
        const nb::ConsumeResult cr = g_batchPool.Consume(call);
        SetCw(s.cw);
        if (u.a.HashBlocks() != before || slotBefore != Fnv(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(slotData)), 36u * slotCnt))
            Fail(t, "consume", i, "Consume modified a game object or the generator vector", true);

        nb::Reason expect = ExpectedReason(mut);
        if (!jobExecuted) expect = jobReason;
        const bool wantCommit = expect == nb::kOk;
        if (cr.reason != expect || (cr.outcome == nb::Outcome::kCommitted) != wantCommit) {
            Fail(t, MutName(mut), i,
                 std::string("Consume returned ") + nb::ReasonName(cr.reason) + (cr.outcome == nb::Outcome::kCommitted ? " (committed)" : " (fallback)") +
                     ", expected " + nb::ReasonName(expect) + " men=" + std::to_string(s.men) + " mod=" + std::to_string(s.mod),
                 false);
        }
        if (mut != M_NONE) { if (cr.outcome == nb::Outcome::kFallback) ++t.mutRefused[mut]; }

        bool ok = true;
        if (cr.outcome == nb::Outcome::kFallback) ok = CallWrapper(u.a.formation, u.a.hdr, flagArg, layoutArg);   // the original call the hook would run
        const bool okB = CallWrapper(u.b.formation, u.b.hdr, flagArg, layoutArg);
        if (!ok || !okB) { Fail(t, "native", i, "original 0x18F0A00 faulted", true); ++t.nativeFaults; FreeGenerator(u.a); FreeGenerator(u.b); continue; }
        const Extracted xa = ExtractAndTail(u.a);
        const Extracted xb = ExtractAndTail(u.b);
        std::string why;
        if (!SameExtracted(xa, xb, &why)) Fail(t, MutName(mut), i, "adapter state != native twin: " + why, false);
        else if (cr.outcome == nb::Outcome::kCommitted) ++t.committedCompared;
        else ++t.fallbackCompared;
        if (*reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NA(0x18ED160))) != 0) Fail(t, "flag", i, "process flag 0x18ED160 left set", true);
        // a second consume of the same job must be refused (single use)
        if (cr.outcome == nb::Outcome::kCommitted) {
            const nb::ConsumeResult again = g_batchPool.Consume(call);
            if (again.outcome != nb::Outcome::kFallback || again.reason != nb::kNotPrepared) Fail(t, "single-use", i, "second Consume was not refused", false);
        }
        FreeGenerator(u.a);
        FreeGenerator(u.b);
        SetCw(0x27F);
    }
    g_batchPool.End();
    g_batchSerial.End();
}

// ---- gate tests --------------------------------------------------------------------------------------------------------------------
struct GateCase { const char* name; nb::Reason expect; };
void RunGates(uint64_t seed, Tally& t) {
    auto check = [&](const char* name, nb::Reason got, nb::Reason want) {
        if (got != want) Fail(t, name, 0, std::string("got ") + nb::ReasonName(got) + " expected " + nb::ReasonName(want), false);
    };
    auto fresh = [&](uint32_t salt) {
        Rng r(Mix64(seed ^ Mix64(0xABCD0000ull + salt)));
        auto u = std::make_unique<UnitCase>();
        do { u->spec = MakeSpec(r); } while (u->spec.men < 12);
        u->spec.cw = 0x27F;
        Build(u->spec, u->a);
        return u;
    };
    nb::Batch& B = g_batchPool;
    uint32_t idx = 0;
    SetCw(0x27F);
    {   // lifecycle before Begin
        auto u = fresh(1);
        B.End();
        check("prepare-no-epoch", B.Prepare(PtrU(u->a.cmd), &idx), nb::kNoEpoch);
    }
    struct Gate { const char* name; nb::Reason want; void (*mutate)(UnitCase&); };
    static const Gate gates[] = {
        {"not-dirty", nb::kNotDirty, [](UnitCase& u) { Put<uint8_t>(u.a.formation, 0x278C, 0); }},
        {"cooldown", nb::kCooldown, [](UnitCase& u) { Put<uint32_t>(u.a.formation, 0x2788, 2); }},
        {"not-infantry-formation", nb::kNotInfantryFormation, [](UnitCase& u) { Put<uint32_t>(u.a.formation, 0, NA(0x1333AA8)); }},
        {"unsupported-generator", nb::kUnsupportedGenerator, [](UnitCase& u) { u.a.layoutVtbl[0x24 / 4] = NA(0x62FDC0); }},
        {"unknown-man-class", nb::kUnknownManClass, [](UnitCase& u) { Put<uint32_t>(u.a.men[3], 0, NA(0x1333AA8)); }},
        {"null-man", nb::kNullMan, [](UnitCase& u) { Put<uint32_t>(u.a.menArray, 8, 0); }},
        {"no-men", nb::kNoMen, [](UnitCase& u) { Put<uint32_t>(u.a.formation, 0x18, 0); }},
        {"too-many-men", nb::kTooManyMen, [](UnitCase& u) { Put<uint32_t>(u.a.formation, 0x18, 10000); }},
        {"bad-container", nb::kBadContainer, [](UnitCase& u) { Put<uint32_t>(u.a.cmd, 0x18, 0); }},
        {"zero-children", nb::kBadContainer, [](UnitCase& u) { Put<uint32_t>(u.a.container, 0x10, 0); }},
        {"unsupported-child", nb::kUnsupportedChild, [](UnitCase& u) { Put<uint32_t>(reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(Get<uint32_t>(
                                                                         reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(Get<uint32_t>(u.a.container, 0x14))), 0))), 0, NA(0x1333AA8)); }},
        {"surface-limit", nb::kSurfaceLimit, [](UnitCase& u) { Put<uint32_t>(reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(Get<uint32_t>(
                                                                         reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(Get<uint32_t>(u.a.container, 0x14))), 0))), 0x48, 11); }},
        {"bad-command", nb::kBadCommand, [](UnitCase& u) { Put<uint32_t>(u.a.cmd, 4, 0); }},
    };
    uint32_t salt = 10;
    for (const Gate& g : gates) {
        auto u = fresh(salt++);
        g.mutate(*u);
        B.Begin();
        check(g.name, B.Prepare(PtrU(u->a.cmd), &idx), g.want);
        B.End();
    }
    {   // duplicate formation, lifecycle of Consume
        auto u = fresh(100);
        B.Begin();
        check("prepare-first", B.Prepare(PtrU(u->a.cmd), &idx), nb::kOk);
        check("duplicate-formation", B.Prepare(PtrU(u->a.cmd), &idx), nb::kDuplicateFormation);
        nb::AssignCall call;
        call.formation = PtrU(u->a.formation); call.slotVec = 0; call.flag = 1; call.assignVec = PtrU(u->a.formation) + 0x518; call.layoutIndex = -1;
        check("consume-before-execute", B.Consume(call).reason, nb::kNotExecuted);
        check("consume-single-use-after-reject", B.Consume(call).reason, nb::kNotPrepared);
        nb::AssignCall other = call;
        other.formation = 0x1000;
        check("consume-unknown-formation", B.Consume(other).reason, nb::kNotPrepared);
        B.End();
        check("consume-after-end", B.Consume(call).reason, nb::kNoEpoch);
    }
    {   // arena exhaustion on a deliberately tiny batch
        nb::Batch tiny;
        nb::Config cfg = MakeConfig();
        const size_t bytes = nb::Batch::StorageBytes(cfg, 8192);
        void* mem = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        check("tiny-init", tiny.Init(mem, bytes, cfg), nb::kOk);
        // a fixture that needs far more than the 8 KB arena: build a big one explicitly
        Rng r(Mix64(seed ^ 0x7777));
        Spec big = MakeSpec(r);
        while (big.men < 300) big = MakeSpec(r);
        UnitCase bigCase;
        bigCase.spec = big;
        Build(bigCase.spec, bigCase.a);
        tiny.Begin();
        check("arena-full", tiny.Prepare(PtrU(bigCase.a.cmd), &idx), nb::kArenaFull);
        tiny.End();
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    {   // wrong image delta must be refused by the image-byte checks without touching anything
        nb::Batch wrong;
        nb::Config cfg = MakeConfig();
        cfg.imageDelta = static_cast<uint32_t>(g_delta) + 0x10000u;
        const size_t bytes = nb::Batch::StorageBytes(cfg, 1u << 16);
        void* mem = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        check("wrong-delta", wrong.Init(mem, bytes, cfg), nb::kImageMismatch);
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    {   // Prepare must never execute a callback it cannot prove pure: the unit is declined BEFORE the callback would run
        auto freshCell = [&](uint32_t salt, uint8_t getter, uint8_t link) {
            Rng r(Mix64(seed ^ Mix64(0xCE110000ull + salt)));
            auto u = std::make_unique<UnitCase>();
            do { u->spec = MakeSpec(r); } while (u->spec.men < 12);
            u->spec.cw = 0x27F;
            CellSpec c = MakeCoverCell(r, u->spec);
            if (getter == G_RETURN0) { c.frame = -1; c.nullG = true; }
            if (getter == G_RETURN_THIS && c.frame < 0) c.nullG = false;
            c.getter = getter;
            c.link = link;
            u->spec.pieces[0].cells.push_back(static_cast<uint32_t>(u->spec.cells.size()));
            u->spec.cells.push_back(c);
            Build(u->spec, u->a);
            return u;
        };
        struct Hazard { const char* name; uint8_t getter, link; nb::Reason want; };
        static const Hazard hazards[] = {
            {"cell-getter-with-side-effect", G_HAZARD, L_NONE, nb::kUnsupportedCellGetter},
            {"cell-getter-load-then-write", G_LOAD_THEN_WRITE, L_NONE, nb::kUnsupportedCellGetter},
            {"link-getter-with-side-effect", G_HOST_LOAD, L_HAZARD, nb::kUnsupportedLinkGetter},
            {"link-hazard-reached-after-flag0", G_HOST_LOAD, L_FLAG0_THEN_HAZARD, nb::kUnsupportedLinkGetter},
            {"link-hazard-unreached-after-first-match", G_RETURN_THIS, L_FLAG1_THEN_HAZARD, nb::kOk},
        };
        uint32_t hs = 200;
        for (const Hazard& h : hazards) {
            auto u = freshCell(hs++, h.getter, h.link);
            const long calls = g_hazardCalls;
            const uint64_t before = u->a.HashBlocks();
            B.Begin();
            check(h.name, B.Prepare(PtrU(u->a.cmd), &idx), h.want);
            if (g_hazardCalls != calls) Fail(t, h.name, 0, "Prepare executed a side-effecting callback", false);
            if (u->a.HashBlocks() != before) Fail(t, h.name, 0, "Prepare modified a game object", false);
            if (h.want == nb::kOk) VerifyPrepared(t, 0, *B.Job(idx), u->spec, u->a);
            else if (B.JobCount() != 0) Fail(t, h.name, 0, "a declined unit left a job behind", false);
            ++t.hazardGates;
            B.End();
        }
    }
}

#ifdef NFR_RUNTIME_SMOKE
#include "native_formation_runtime_smoke.inc"
#endif

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::string image, tablePath;
    uint32_t cases = 400, workers = 0;
    std::string runtimeDll;
    uint64_t seed = 20261013;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string a = argv[i];
        if (a == "--image") image = argv[i + 1];
        else if (a == "--table") tablePath = argv[i + 1];
        else if (a == "--cases") cases = static_cast<uint32_t>(std::strtoul(argv[i + 1], nullptr, 10));
        else if (a == "--seed") seed = std::strtoull(argv[i + 1], nullptr, 10);
        else if (a == "--workers") workers = static_cast<uint32_t>(std::strtoul(argv[i + 1], nullptr, 10));
#ifdef NFR_RUNTIME_SMOKE
        else if (a == "--runtime-dll") runtimeDll = argv[i + 1];
#endif
    }
    std::vector<uint8_t> file, table;
    if (image.empty() || tablePath.empty() || !ReadAll(image, file) || !ReadAll(tablePath, table)) {
        std::fprintf(stderr, "usage: --image Napoleon.exe --table angle-table.bin [--cases N] [--seed S] [--workers W]\n");
        return 2;
    }
    if (Sha256(file.data(), file.size()) != kImageSha) { std::fprintf(stderr, "REFUSING: image SHA-256 differs from the approved image\n"); return 2; }
    if (table.size() != 65536u * 8u || Sha256(table.data(), table.size()) != kTableSha) { std::fprintf(stderr, "angle table mismatch\n"); return 2; }
    if (!MapImage(file, table)) { std::fprintf(stderr, "cannot map image\n"); return 2; }
    for (auto& vt : g_cellVtbl) for (void*& slot : vt) slot = reinterpret_cast<void*>(&HostTrap);
    g_cellVtbl[G_HOST_LOAD][4] = reinterpret_cast<void*>(&HostCellVfn10);
    g_cellVtbl[G_RETURN0][4] = reinterpret_cast<void*>(static_cast<uintptr_t>(NA(nb::va::kReturnZero)));
    g_cellVtbl[G_RETURN_THIS][4] = reinterpret_cast<void*>(static_cast<uintptr_t>(NA(nb::va::kReturnThis)));
    g_cellVtbl[G_HAZARD][4] = reinterpret_cast<void*>(&HostHazardLeaf);
    g_cellVtbl[G_LOAD_THEN_WRITE][4] = reinterpret_cast<void*>(&HostLoadThenWrite);
    g_linkVtblZero[0] = reinterpret_cast<void*>(static_cast<uintptr_t>(NA(nb::va::kReturnZero)));
    g_linkVtblHazard[0] = reinterpret_cast<void*>(&HostHazardLeaf);
    CalibrateOrientation();
#ifdef NFR_RUNTIME_SMOKE
    if (!runtimeDll.empty()) {
        if (workers == 0) workers = std::min<uint32_t>(7, std::max<uint32_t>(1, std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency() - 1 : 1));
        return RunRuntimeSmoke(runtimeDll, cases, seed, workers) ? 0 : 1;
    }
#endif
    if (workers == 0) workers = std::min<uint32_t>(7, std::max<uint32_t>(1, std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency() - 1 : 1));
    if (!StartPool(workers)) return 2;
    if (!InitBatches()) return 2;
    std::printf("pool: %u workers + caller; arena %zu bytes per batch\n", workers, g_storageBytes);

    Tally t;
    RunGates(seed, t);
    const uint32_t perRound = 48;
    const uint32_t rounds = std::max<uint32_t>(1, (cases + perRound - 1) / perRound);
    uint32_t rotor = 0;
    for (uint32_t r = 0; r < rounds; ++r) RunRound(r, perRound, seed, t, &rotor);

    // worker participation: exact-once is asserted by Execute (SameJob/serial equality); report the team statistics
    uint32_t workerChunks = 0;
    for (uint32_t i = 0; i < g_pool->workers; ++i) workerChunks += g_pool->slots[i].chunks;
    std::printf("pool dispatches %u (team %u, caller-only %u, inline %u); chunks: workers %u, caller %u\n", g_pool->st_calls, g_pool->st_team,
                g_pool->st_serial, g_pool->st_inline, workerChunks, g_pool->st_main_chunks);
    const nb::Stats& st = g_batchPool.GetStats();
    std::printf("batch: epochs %u prepared %u executed %u execute-failed %u committed %u fallbacks %u unused %u slotsWithoutHeight %u\n",
                st.epochs, st.prepared, st.executed, st.executeFailed, st.committed, st.fallbacks, st.unusedJobs, st.slotsWithoutHeight);
    for (uint32_t r = 0; r < nb::kReasonCount; ++r)
        if (st.reasons[r]) std::printf("  reason %-24s %u\n", nb::ReasonName(static_cast<nb::Reason>(r)), st.reasons[r]);
    std::printf("units %u prepared %u executed %u | committed-and-equal %u, fallback-and-equal %u | serial==pool %u | jobs failed %u\n", t.units, t.preparedOk,
                t.executed, t.committedCompared, t.fallbackCompared, t.serialEqual, t.jobsFailed);
    std::printf("classes: mod %u stock %u cell %u frame %u arc %u officers %u | cw 27F:%u 37F:%u 7F:%u | units with unknown-height slots %u\n", t.mod,
                t.stock, t.withCell, t.withFrame, t.withArc, t.officers, t.cwDistinct[0], t.cwDistinct[1], t.cwDistinct[2], t.slotsNoHeightUnits);
    for (int m = 1; m < M__END; ++m) std::printf("  mutation %-16s applied %u refused %u\n", MutName(m), t.mutApplied[m], t.mutRefused[m]);
    std::printf("prepare vs original callbacks: cells %u frames %u ring nodes %u (linked %u) | getters host-load %u return0 %u return-this %u | link sets none %u flag0 %u flag1 %u 0-then-1 %u zero-then-1 %u 1-then-hazard %u | hazard gates %u, hazard calls %ld\n",
                t.cellsVerified, t.framesVerified, t.linkNodes, t.linkNodesSet, t.getterRuns[G_HOST_LOAD], t.getterRuns[G_RETURN0], t.getterRuns[G_RETURN_THIS],
                t.linkKinds[L_NONE], t.linkKinds[L_FLAG0], t.linkKinds[L_FLAG1], t.linkKinds[L_FLAG0_THEN_1], t.linkKinds[L_ZERO_THEN_1],
                t.linkKinds[L_FLAG1_THEN_HAZARD], t.hazardGates, static_cast<long>(g_hazardCalls));

    bool coverage = t.committedCompared > 0 && t.fallbackCompared > 0 && t.mod > 0 && t.stock > 0 && t.withCell > 0 && t.withFrame > 0 &&
                    t.withArc > 0 && t.officers > 0 && t.serialEqual > 0 && t.slotsNoHeightUnits > 0 && workerChunks + g_pool->st_main_chunks > 0;
    for (int m = 1; m < M__END; ++m) coverage = coverage && t.mutRefused[m] > 0;
    coverage = coverage && t.cellsVerified > 0 && t.framesVerified > 0 && t.linkNodesSet > 0 && t.getterRuns[G_HOST_LOAD] > 0 && t.getterRuns[G_RETURN0] > 0 &&
               t.getterRuns[G_RETURN_THIS] > 0 && t.linkKinds[L_ZERO_THEN_1] > 0 && t.linkKinds[L_FLAG1_THEN_HAZARD] > 0 && t.linkKinds[L_FLAG0_THEN_1] > 0 &&
               t.hazardGates >= 5;
    if (!coverage) std::printf("FAIL: a required class was never observed\n");
    if (g_hazardCalls != 0) { std::printf("FAIL: a side-effecting callback was executed %ld time(s)\n", static_cast<long>(g_hazardCalls)); ++t.plumbing; }
    const bool pass = coverage && t.mismatches == 0 && t.plumbing == 0 && t.nativeFaults == 0;
    ntw_pool_shutdown(g_pool);
    std::printf("%s: native_formation_batch differential smoke (mismatches %u, plumbing %u, native faults %u)\n", pass ? "PASS" : "FAIL", t.mismatches,
                t.plumbing, t.nativeFaults);
    return pass ? 0 : 1;
}
