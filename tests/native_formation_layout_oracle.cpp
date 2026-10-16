#define _CRT_SECURE_NO_WARNINGS
// Differential oracle for the formation SLOT GENERATOR (layout vtable[+0x24]).
//
// It executes the ORIGINAL bytes of the approved image (Napoleon.exe, SHA-256 13fcab62...cbad4, read from the installed
// file into a PRIVATE relocated mapping inside THIS test process) on randomised but structurally faithful host fixtures
// (layout object, container, class A/B children, surface sets with ring nodes / cells / frames, the height-field chain)
// and compares the out vector record-for-record, bit-for-bit, with ntw_formation_layout::Generate on the same snapshot.
// Nothing touches the running game, the installed EXE, a debugger or an injector.  The only patches are inside the private
// copy: the game allocator 0xFF7F20 / 0xFF7EF0 are redirected to a host heap with canary red zones.
//
//   native_formation_layout_oracle.exe <Napoleon.exe> [cases=N] [seed=S] [family=name] [case=K] [verbose=1]
//
// Exit 0 only if every comparison is bit-identical, every plumbing assertion holds and no family has zero cases.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>
#include "native_formation_layout.h"
#include "native_image_relocation.h"

#pragma comment(lib, "bcrypt.lib")
#ifndef _M_IX86
#error x86 only
#endif

namespace nf = ntw_formation_layout;

// ---------------------------------------------------------------------------------------------------------------------
// original addresses (preferred base 0x400000)
static const uintptr_t VA_GEN_STOCK = 0x62FD60;   // thiscall(layout; out, container, f, men) ret 0x10
static const uintptr_t VA_GEN_MOD = 0x18ED200;    // same ABI, sets flag 0x18ED160 := 1 around the stock generator
static const uintptr_t VA_FLAG = 0x18ED160;
static const uintptr_t VA_ALLOC = 0xFF7F20;       // cdecl(size, tag) -> ptr
static const uintptr_t VA_FREE = 0xFF7EF0;        // cdecl(ptr)
static const uintptr_t VA_RESOLVE = 0x80E9D0;     // thiscall(posobj; out3) ret 4
static const uintptr_t VA_EDGE_OUTSIDE = 0x10F9A40;  // thiscall(node; pos*, float margin) ret 8 -> al (1 == pos is outside the edge)
static const uintptr_t VA_FILES = 0x642C90;       // cdecl(float width, float, float) -> files per row
static const uintptr_t VA_VT_A = 0x1333944, VA_VT_B = 0x133396C, VA_VT_LAYOUT = 0x1333AA8;
static const uintptr_t VA_K_MARGIN2 = 0x13359F8;  // pass-2 margin used for ring nodes with a link

static uintptr_t g_image_delta;
static uintptr_t native_address(uintptr_t preferred) { return preferred + g_image_delta; }

static const uint16_t kCW[3] = {0x27F, 0x37F, 0x7F};

static inline uint32_t bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static inline float fbits(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }
template <class T> static void wr(void* p, size_t off, T v) { std::memcpy(static_cast<uint8_t*>(p) + off, &v, sizeof(T)); }
template <class T> static T rd(const void* p, size_t off) { T v; std::memcpy(&v, static_cast<const uint8_t*>(p) + off, sizeof(T)); return v; }
static void wptr(void* p, size_t off, const void* v) { wr<uint32_t>(p, off, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(v))); }

// ---------------------------------------------------------------------------------------------------------------------
// x87 control word
static uint16_t get_cw() { uint16_t w = 0; __asm { fnstcw w } return w; }
static void set_cw(uint16_t w) { __asm { fldcw w } }

// ---------------------------------------------------------------------------------------------------------------------
// naked thiscall / cdecl wrappers into the original
#pragma warning(push)
#pragma warning(disable : 4100)   // naked functions read their stack arguments directly
__declspec(naked) static uint32_t __cdecl call_gen(uintptr_t fn, void* layout, void* out, void* container, uint32_t fbits_, uint32_t men) {
    __asm {
        mov eax, [esp + 4]
        mov ecx, [esp + 8]
        push dword ptr[esp + 24]
        push dword ptr[esp + 24]
        push dword ptr[esp + 24]
        push dword ptr[esp + 24]
        call eax
        ret
    }
}
__declspec(naked) static uint32_t __cdecl call_this1(uintptr_t fn, void* ecx_, uint32_t a1) {
    __asm {
        mov eax, [esp + 4]
        mov ecx, [esp + 8]
        push dword ptr[esp + 12]
        call eax
        ret
    }
}
__declspec(naked) static uint32_t __cdecl call_this2(uintptr_t fn, void* ecx_, uint32_t a1, uint32_t a2) {
    __asm {
        mov eax, [esp + 4]
        mov ecx, [esp + 8]
        push dword ptr[esp + 16]
        push dword ptr[esp + 16]
        call eax
        ret
    }
}
#pragma warning(pop)

// ---------------------------------------------------------------------------------------------------------------------
// host stand-ins for game objects OUTSIDE the generator code (documented semantics only)
//   cell E: vtable slot [+0x10] (thiscall, no args) returns G (object whose +0x80 holds the frame pointer) or null
//   ring-node link object: vtable[0] (thiscall, returns al) at obj+0x1C; here it returns the flag byte stored at obj+0x20
__declspec(naked) static void host_cell_vfn10() { __asm { mov eax, [ecx + 0x40]
                                                        ret } }
__declspec(naked) static void host_link_fn() { __asm { movzx eax, byte ptr[ecx + 4]
                                                      ret } }
__declspec(naked) static void host_trap() { __asm { int 3 } }
static void* g_cellVtbl[16];
static void* g_linkVtbl[16];
static void init_host_vtables() {
    for (int i = 0; i < 16; ++i) { g_cellVtbl[i] = reinterpret_cast<void*>(&host_trap); g_linkVtbl[i] = reinterpret_cast<void*>(&host_trap); }
    g_cellVtbl[4] = reinterpret_cast<void*>(&host_cell_vfn10);
    g_linkVtbl[0] = reinterpret_cast<void*>(&host_link_fn);
}

// ---------------------------------------------------------------------------------------------------------------------
// host heap that replaces the game allocator inside the private image; canary red zones around every block
static uint8_t* g_heap;
static size_t g_heapOff, g_heapCap = 64u << 20;
struct Blk { size_t user, size, rounded; };
static std::vector<Blk> g_blk;
static unsigned g_frees;
static bool g_heapBroken;
static const size_t kRed = 32;
static void* __cdecl host_alloc(size_t size, void*) {
    size_t off = (g_heapOff + 15) & ~size_t(15);
    size_t rounded = (size + 15) & ~size_t(15);
    if (off + kRed + rounded + kRed > g_heapCap) { std::fputs("host heap exhausted\n", stderr); std::exit(3); }
    std::memset(g_heap + off, 0xAB, kRed);
    std::memset(g_heap + off + kRed, 0xCD, size);                                  // poison: unwritten bytes stay visible
    std::memset(g_heap + off + kRed + size, 0xAB, rounded - size + kRed);          // tail pad + back canary
    g_blk.push_back({off + kRed, size, rounded});
    g_heapOff = off + kRed + rounded + kRed;
    return g_heap + off + kRed;
}
static void __cdecl host_free(void* p) {
    ++g_frees;
    (void)p;
}
static void heap_reset() { g_heapOff = 0; g_blk.clear(); g_frees = 0; }
static bool heap_canaries_ok() {
    for (const Blk& b : g_blk) {
        const uint8_t* f = g_heap + b.user - kRed;
        for (size_t i = 0; i < kRed; ++i) if (f[i] != 0xAB) return false;
        const uint8_t* t = g_heap + b.user + b.size;
        for (size_t i = 0; i < b.rounded - b.size + kRed; ++i) if (t[i] != 0xAB) return false;
    }
    return true;
}

static void patch_jmp(uintptr_t at, void* target) {
    uint8_t* p = reinterpret_cast<uint8_t*>(at);
    p[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target) - (at + 5));
    std::memcpy(p + 1, &rel, 4);
}

// ---------------------------------------------------------------------------------------------------------------------
// image identity + private mapping
static const uint8_t kSha256[32] = {0x13, 0xfc, 0xab, 0x62, 0x98, 0xcd, 0x5e, 0x00, 0x72, 0xb3, 0x59, 0x8a, 0x83, 0xcf, 0x02, 0x62,
                                    0x7c, 0x58, 0xf9, 0x44, 0xed, 0xbe, 0xe5, 0x25, 0x8b, 0x63, 0x76, 0x55, 0xc8, 0x2c, 0xba, 0xd4};
static bool sha256(const uint8_t* d, size_t n, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const NTSTATUS st = BCryptHash(h, nullptr, 0, const_cast<PUCHAR>(d), static_cast<ULONG>(n), out, 32);
    BCryptCloseAlgorithmProvider(h, 0);
    return st >= 0;
}

static bool map_image(const char* path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { std::fprintf(stderr, "open failed %lu\n", GetLastError()); return false; }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (256ll << 20)) { CloseHandle(f); return false; }
    std::vector<uint8_t> file(static_cast<size_t>(sz.QuadPart));
    DWORD got = 0;
    const bool okRead = ReadFile(f, file.data(), static_cast<DWORD>(file.size()), &got, nullptr) && got == file.size();
    CloseHandle(f);
    if (!okRead) { std::fputs("read failed\n", stderr); return false; }
    uint8_t dig[32];
    if (!sha256(file.data(), file.size(), dig)) { std::fputs("sha256 failed\n", stderr); return false; }
    if (std::memcmp(dig, kSha256, 32) != 0) { std::fputs("REFUSING: image SHA-256 differs from the approved image\n", stderr); return false; }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (file.size() < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0
        || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > file.size()) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != 0x14c) return false;
    const uintptr_t base = nt->OptionalHeader.ImageBase;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto m = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!m) { std::fprintf(stderr, "cannot map native image (err %lu)\n", GetLastError()); return false; }
    if (nt->OptionalHeader.SizeOfHeaders > size || nt->OptionalHeader.SizeOfHeaders > file.size()) return false;
    std::memcpy(m, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto loaded_nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(m + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(loaded_nt);
    for (unsigned i = 0; i < loaded_nt->FileHeader.NumberOfSections; ++i) {
        const DWORD n = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (sec[i].VirtualAddress > size || n > size - sec[i].VirtualAddress
            || sec[i].PointerToRawData > file.size() || n > file.size() - sec[i].PointerToRawData) { VirtualFree(m, 0, MEM_RELEASE); return false; }
        std::memcpy(m + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    g_image_delta = reinterpret_cast<uintptr_t>(m) - base;
    if (!RelocateNativeImage(m, size, loaded_nt, g_image_delta)) { VirtualFree(m, 0, MEM_RELEASE); return false; }
    std::printf("image mapped at %p (delta %08x), sha256 verified\n", static_cast<void*>(m), static_cast<unsigned>(g_image_delta));
    return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// random helpers
struct Rng {
    std::mt19937_64 g;
    explicit Rng(uint64_t s) : g(s) {}
    uint32_t u(uint32_t n) { return n ? static_cast<uint32_t>(g() % n) : 0u; }          // [0,n)
    uint32_t r(uint32_t a, uint32_t b) { return a + u(b - a + 1); }                     // [a,b]
    float f(float a, float b) { return std::uniform_real_distribution<float>(a, b)(g); }
    double d(double a, double b) { return std::uniform_real_distribution<double>(a, b)(g); }
    bool p(double pr) { return std::uniform_real_distribution<double>(0.0, 1.0)(g) < pr; }
};
static uint64_t mix64(uint64_t x) { x += 0x9E3779B97F4A7C15ull; x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull; x = (x ^ (x >> 27)) * 0x94D049BB133111EBull; return x ^ (x >> 31); }

// ---------------------------------------------------------------------------------------------------------------------
// fixture arena (all game objects live here; poisoned with 0xFF so an unexpected read shows up as NaN / bad pointer)
struct Arena {
    uint8_t* base = nullptr;
    size_t cap = 0, off = 0;
    void init(size_t n) {
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, n + 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!base) { std::fputs("arena alloc failed\n", stderr); std::exit(3); }
        DWORD old;
        VirtualProtect(base + n, 0x10000, PAGE_NOACCESS, &old);   // guard pages behind the arena
        cap = n;
    }
    uint8_t* alloc(size_t n, size_t al = 16) {
        off = (off + al - 1) & ~(al - 1);
        if (off + n + 16 > cap) { std::fputs("fixture arena exhausted\n", stderr); std::exit(3); }
        uint8_t* p = base + off;
        std::memset(p, 0xFF, n + 16);
        off += n + 16;
        return p;
    }
    void reset() { off = 0; }
};
static Arena g_arena;
static uint64_t fnv(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

// ---------------------------------------------------------------------------------------------------------------------
// scenario = Input snapshot + the host-only side information the fixture needs
struct NodeX { uint8_t n; uint8_t flag[3]; uint8_t pos; };   // link entries of one ring node (hasLink == any flag == 1)
struct Scenario {
    std::vector<nf::Piece> pieces;
    std::vector<nf::SurfaceCell> cells;
    std::vector<nf::SurfaceNode> nodes;
    std::vector<nf::Frame> frames;
    std::vector<float> samples;       // 2 floats per entry (8-byte stride; the second dword is garbage)
    nf::HeightField hf{};
    bool hasTerrain = true;
    std::vector<uint8_t> cellNullG;   // for frame == -1: 1 => E->vfn10() returns null, 0 => returns G with *(G+0x80) == 0
    std::vector<NodeX> nodeX;
    nf::Input in{};
    uint32_t owner = 0;
    std::vector<uint32_t> inlineCount;   // per piece: how many of its cells sit in the inline array
    // phase-1 observation (positions fed to the surface lookup, owner piece), only for stats / plumbing checks
    std::vector<std::pair<float, float>> seqPos;
    std::vector<int> seqPiece;
    bool mod = false;
    std::vector<uint32_t> rowLens;
    const char* family = "";
    uint32_t caseIdx = 0;
    uint64_t caseSeed = 0;
    void finalize() {
        in.pieces = pieces.data(); in.pieceCount = static_cast<uint32_t>(pieces.size());
        in.cells = cells.data(); in.cellCount = static_cast<uint32_t>(cells.size());
        in.nodes = nodes.data(); in.nodeCount = static_cast<uint32_t>(nodes.size());
        in.frames = frames.data(); in.frameCount = static_cast<uint32_t>(frames.size());
        hf.samples = samples.data();
        in.terrain = hasTerrain ? &hf : nullptr;
    }
};

struct Fixture {
    uint8_t* layout = nullptr;
    uint8_t* container = nullptr;
    std::unordered_map<uint32_t, int> cellIdx, frameIdx;
    uint64_t hash = 0;
    size_t used = 0;
};

static Fixture build_fixture(Scenario& S) {
    S.finalize();
    g_arena.reset();
    Fixture fx;
    const nf::Input& in = S.in;
    // ---- frames ----
    std::vector<uint8_t*> framePtr(S.frames.size());
    for (size_t i = 0; i < S.frames.size(); ++i) {
        uint8_t* F = g_arena.alloc(0x100);
        framePtr[i] = F;
        for (int k = 0; k < 3; ++k) wr<float>(F, 0x80 + 4 * k, S.frames[i].t[k]);
        for (int k = 0; k < 9; ++k) wr<float>(F, 0x9C + 4 * k, S.frames[i].fwd[k]);
        for (int k = 0; k < 9; ++k) wr<float>(F, 0xC0 + 4 * k, S.frames[i].inv[k]);
        fx.frameIdx[static_cast<uint32_t>(reinterpret_cast<uintptr_t>(F))] = static_cast<int>(i);
    }
    // ---- terrain chain X -> T -> U -> Q -> H ----
    uint8_t* X = g_arena.alloc(0xC0);
    uint8_t* T = g_arena.alloc(8);
    uint8_t* U = g_arena.alloc(0x10);
    uint8_t* Q = g_arena.alloc(0xA0);
    uint8_t* H = g_arena.alloc(0x28);
    wptr(X, 0xB4, T); wptr(T, 0, U); wptr(U, 8, Q); wptr(Q, 0x9C, H);
    if (S.hasTerrain) {
        const size_t n8 = S.samples.size() * 4;
        uint8_t* smp = g_arena.alloc(n8 ? n8 : 8);
        std::memcpy(smp, S.samples.data(), n8);
        wptr(H, 0, smp);
        wr<uint32_t>(H, 8, S.hf.shift);
        wr<int32_t>(H, 0x10, S.hf.base);
        wr<int32_t>(H, 0x14, S.hf.limit);
        wr<float>(H, 0x1C, S.hf.half);
        wr<float>(H, 0x20, S.hf.cell);
        wr<float>(H, 0x24, S.hf.scale);
    } else {   // an in-range but NaN-poisoned grid: any read shows up as a NaN height
        uint8_t* smp = g_arena.alloc(64 * 8);
        wptr(H, 0, smp);
        wr<uint32_t>(H, 8, 1); wr<int32_t>(H, 0x10, 0); wr<int32_t>(H, 0x14, 1);
        wr<float>(H, 0x1C, 1.0f); wr<float>(H, 0x20, 1.0f); wr<float>(H, 0x24, 1.0f);
    }
    // ---- cells ----
    std::vector<uint8_t*> cellPtr(S.cells.size());
    for (size_t i = 0; i < S.cells.size(); ++i) {
        const nf::SurfaceCell& c = S.cells[i];
        std::vector<uint8_t*> nd(c.nodeCount);
        for (uint32_t k = 0; k < c.nodeCount; ++k) nd[k] = g_arena.alloc(0x50);
        for (uint32_t k = 0; k < c.nodeCount; ++k) {
            const nf::SurfaceNode& sn = S.nodes[c.nodeBegin + k];
            const NodeX& nx = S.nodeX[c.nodeBegin + k];
            uint8_t* n = nd[k];
            wptr(n, 8, nd[(k + 1) % c.nodeCount]);
            wr<float>(n, 0xC, sn.x); wr<float>(n, 0x10, sn.z);
            wr<uint32_t>(n, 0x44, nx.n);
            if (nx.n) {
                uint8_t* ent = g_arena.alloc(8u * nx.n);
                for (uint32_t j = 0; j < nx.n; ++j) {
                    uint8_t* obj = g_arena.alloc(0x30);
                    wptr(obj, 0x1C, g_linkVtbl);
                    wr<uint8_t>(obj, 0x20, nx.flag[j]);
                    wptr(ent, 8 * j, obj);
                    wr<uint32_t>(ent, 8 * j + 4, 0xA5A5A5A5u);
                }
                wptr(n, 0x48, ent);
            }
        }
        uint8_t* E = g_arena.alloc(0x60);
        wptr(E, 0, g_cellVtbl);
        wptr(E, 8, nd[0]);
        for (int k = 0; k < 4; ++k) wr<float>(E, 0x30 + 4 * k, c.plane[k]);
        uint8_t* G = nullptr;
        if (c.frame >= 0) {
            G = g_arena.alloc(0x90);
            wptr(G, 0x80, framePtr[static_cast<size_t>(c.frame)]);
        } else if (!S.cellNullG[i]) {
            G = g_arena.alloc(0x90);
            wr<uint32_t>(G, 0x80, 0);
        }
        if (G) wptr(E, 0x40, G); else wr<uint32_t>(E, 0x40, 0);
        cellPtr[i] = E;
        fx.cellIdx[static_cast<uint32_t>(reinterpret_cast<uintptr_t>(E))] = static_cast<int>(i);
    }
    // ---- children ----
    std::vector<uint8_t*> childPtr(in.pieceCount);
    for (uint32_t i = 0; i < in.pieceCount; ++i) {
        const nf::Piece& p = S.pieces[i];
        uint8_t* C = g_arena.alloc(p.isArc ? 0xA4 : 0x98);
        childPtr[i] = C;
        wptr(C, 0, reinterpret_cast<const void*>(native_address(p.isArc ? VA_VT_B : VA_VT_A)));
        wr<int32_t>(C, 4, p.mode);
        wr<uint16_t>(C, 8, p.angle);
        wr<float>(C, 0xC, p.p0[0]); wr<float>(C, 0x10, p.p0[1]);
        wr<float>(C, 0x14, p.p1[0]); wr<float>(C, 0x18, p.p1[1]);
        wr<float>(C, 0x60, p.step[0]); wr<float>(C, 0x64, p.step[1]);
        wr<float>(C, 0x70, p.width);
        wr<float>(C, 0x7C, p.arcStart[0]); wr<float>(C, 0x80, p.arcStart[1]);
        wr<float>(C, 0x8C, p.dir[0]); wr<float>(C, 0x90, p.dir[1]);
        if (p.isArc) {
            wr<float>(C, 0x98, p.center[0]); wr<float>(C, 0x9C, p.center[1]);
            wr<float>(C, 0xA0, p.arcWidth);
        }
        // O = embedded surface set at child+0x1C: [+0]=X, inline cells at +4.., count1 at +0x2C, count2 at +0x38, overflow ptr at +0x3C
        wptr(C, 0x1C, X);
        const uint32_t n = p.cellCount, c1 = S.inlineCount[i], c2 = n - c1;
        wr<uint32_t>(C, 0x48, c1);
        wr<uint32_t>(C, 0x54, c2);
        for (uint32_t k = 0; k < c1; ++k) wptr(C, 0x20 + 4 * k, cellPtr[p.cellBegin + k]);
        if (c2) {
            uint8_t* ov = g_arena.alloc(4u * c2);
            for (uint32_t k = 0; k < c2; ++k) wptr(ov, 4 * k, cellPtr[p.cellBegin + c1 + k]);
            wptr(C, 0x58, ov);
        }
    }
    // ---- container ----
    uint8_t* C0 = g_arena.alloc(0x3C);
    wr<uint32_t>(C0, 0x10, in.pieceCount);
    uint8_t* arr = g_arena.alloc(4u * (in.pieceCount ? in.pieceCount : 1));
    for (uint32_t i = 0; i < in.pieceCount; ++i) wptr(arr, 4 * i, childPtr[i]);
    wptr(C0, 0x14, arr);
    wr<float>(C0, 0x18, in.origin.x); wr<float>(C0, 0x1C, in.origin.y); wr<float>(C0, 0x20, in.origin.z);
    if (in.origin.frame >= 0) wptr(C0, 0x28, framePtr[static_cast<size_t>(in.origin.frame)]); else wr<uint32_t>(C0, 0x28, 0);
    // ---- layout ----
    uint8_t* L = g_arena.alloc(0x18);
    wptr(L, 0, reinterpret_cast<const void*>(native_address(VA_VT_LAYOUT)));
    wr<uint32_t>(L, 4, S.owner);
    wr<float>(L, 8, in.layout8); wr<float>(L, 0xC, in.layoutC); wr<float>(L, 0x10, in.layout10); wr<float>(L, 0x14, in.layout14);
    fx.layout = L; fx.container = C0;
    fx.used = g_arena.off;
    fx.hash = fnv(g_arena.base, fx.used);
    return fx;
}

// ---------------------------------------------------------------------------------------------------------------------
// running the ORIGINAL
struct OrigRec {
    uint8_t flag; float x, y, z; int cell, frame; uint16_t angle; float wx, wy, wz; uint32_t z1c, z20;
    uint32_t cellPtr, framePtr;
};
struct OrigOut {
    bool crashed = false;
    DWORD exc = 0;
    uint32_t ret = 0, hdrCap = 0, count = 0, mark = 0, data = 0, flagAfter = 0;
    uint16_t cwAfter = 0;
    size_t allocs = 0, frees = 0, firstAlloc = 0;
    std::vector<OrigRec> rec;
    std::vector<std::string> plumbing;   // plumbing assertion failures
};

static bool seh_call(uintptr_t fn, void* layout, void* out, void* container, uint32_t f, uint32_t men, uint16_t cw, uint32_t* ret, DWORD* code) {
    const uint16_t old = get_cw();
    __try {
        set_cw(cw);
        *ret = call_gen(fn, layout, out, container, f, men);
        set_cw(old);
        return true;
    } __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        _fpreset();
        set_cw(old);
        return false;
    }
}

static void resolve_world(const void* rec, float out[3]) {
    out[0] = out[1] = out[2] = 0;
    call_this1(native_address(VA_RESOLVE), const_cast<uint8_t*>(static_cast<const uint8_t*>(rec)) + 4, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(out)));
}

static OrigOut run_original(const Scenario& S, const Fixture& fx, uint16_t cw, bool mod) {
    OrigOut o;
    heap_reset();
    alignas(16) uint8_t hdr[0x40];
    std::memset(hdr, 0x5A, sizeof hdr);
    uint32_t* flag = reinterpret_cast<uint32_t*>(native_address(VA_FLAG));
    *flag = 0;
    const uintptr_t fn = native_address(mod ? VA_GEN_MOD : VA_GEN_STOCK);
    const uint32_t men = S.in.men;
    o.crashed = !seh_call(fn, fx.layout, hdr, fx.container, bits(S.in.f), men, cw, &o.ret, &o.exc);
    o.cwAfter = get_cw();
    o.flagAfter = *flag;
    *flag = 0;
    if (o.crashed) return o;
    auto P = [&](const char* m) { o.plumbing.push_back(m); };
    if (o.ret != static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hdr))) P("generator did not return the out pointer in eax");
    if (o.flagAfter != 0) P("flag 0x18ED160 not cleared after the call");
    for (size_t i = 0; i < 4; ++i) if (hdr[i] != 0x5A) P("out+0..3 modified");
    for (size_t i = 0x14; i < sizeof hdr; ++i) if (hdr[i] != 0x5A) { P("out header written beyond +0x13"); break; }
    o.hdrCap = rd<uint32_t>(hdr, 4);
    o.count = rd<uint32_t>(hdr, 8);
    o.data = rd<uint32_t>(hdr, 0xC);
    o.mark = rd<uint32_t>(hdr, 0x10);
    o.allocs = g_blk.size(); o.frees = g_frees;
    o.firstAlloc = g_blk.empty() ? 0 : g_blk[0].size;
    if (o.hdrCap != men) P("out+4 (capacity) != men");
    if (!heap_canaries_ok()) P("host heap canary corrupted (write outside an allocation)");
    if (fnv(g_arena.base, fx.used) != fx.hash) P("fixture memory modified by the original (generation must be read-only)");
    if (men > 0) {
        if (o.allocs != 1 || o.firstAlloc != static_cast<size_t>(men) * 36u) P("expected exactly one allocation of men*36 bytes");
        if (o.frees != 0) P("unexpected free (vector grew)");
        if (!g_blk.empty() && o.data != static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g_heap + g_blk[0].user))) P("out+0xC is not the allocated block");
    } else {
        if (o.allocs != 0 || o.data != 0) P("men == 0 must not allocate");
    }
    if (o.count > men) { P("count > men"); return o; }
    if (!(o.allocs >= 1)) return o;
    const uint8_t* base = g_heap + g_blk[0].user;
    o.rec.resize(o.count);
    for (uint32_t i = 0; i < o.count; ++i) {
        const uint8_t* r = base + 36u * i;
        OrigRec& q = o.rec[i];
        q.flag = r[0];
        q.x = rd<float>(r, 4); q.y = rd<float>(r, 8); q.z = rd<float>(r, 0xC);
        q.cellPtr = rd<uint32_t>(r, 0x10); q.framePtr = rd<uint32_t>(r, 0x14);
        q.angle = rd<uint16_t>(r, 0x18);
        q.z1c = rd<uint32_t>(r, 0x1C); q.z20 = rd<uint32_t>(r, 0x20);
        q.cell = -1; q.frame = -1;
        if (q.cellPtr) { auto it = fx.cellIdx.find(q.cellPtr); if (it == fx.cellIdx.end()) P("record cell pointer is not a fixture cell"); else q.cell = it->second; }
        if (q.framePtr) { auto it = fx.frameIdx.find(q.framePtr); if (it == fx.frameIdx.end()) P("record frame pointer is not a fixture frame"); else q.frame = it->second; }
        if (q.z1c != 0 || q.z20 != 0) P("record +0x1C/+0x20 not zero");
        float w[3];
        resolve_world(r, w);
        q.wx = w[0]; q.wy = w[1]; q.wz = w[2];
    }
    return o;
}

// ---------------------------------------------------------------------------------------------------------------------
// host predicate built on the ORIGINAL 0x10F9A40 (edge test), used to construct boundary fixtures and a replica of the pass logic
alignas(16) static uint8_t g_scratch[2][0x60];
static bool edge_outside(float ax, float az, float bx, float bz, float px, float pz, float margin) {
    std::memset(g_scratch, 0, sizeof g_scratch);
    wptr(g_scratch[0], 8, g_scratch[1]);
    wr<float>(g_scratch[0], 0xC, ax); wr<float>(g_scratch[0], 0x10, az);
    wr<float>(g_scratch[1], 0xC, bx); wr<float>(g_scratch[1], 0x10, bz);
    alignas(16) float pos[2] = {px, pz};
    const uint32_t r = call_this2(native_address(VA_EDGE_OUTSIDE), g_scratch[0], static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pos)), bits(margin));
    return (r & 0xFF) == 1;
}
static float g_margin2;       // [0x13359F8], read from the image
static bool g_insideCCW;      // ring orientation (in x,z) for which interior points are inside every edge (calibrated with the original)

struct Poly {
    int n = 0;
    float x[8], z[8];
    bool link[8];
};
static bool poly_inside(const Poly& p, float px, float pz, int pass) {
    for (int i = 0; i < p.n; ++i) {
        const int j = (i + 1) % p.n;
        const float m = (pass == 2 && p.link[i]) ? g_margin2 : 0.0f;
        if (edge_outside(p.x[i], p.z[i], p.x[j], p.z[j], px, pz, m)) return false;
    }
    return true;
}
static void calibrate_orientation() {
    // square (0,0),(10,0),(10,10),(0,10) is counter-clockwise in (x,z) with x right / z up; probe the centre
    Poly p; p.n = 4;
    const float xs[4] = {0, 10, 10, 0}, zs[4] = {0, 0, 10, 10};
    for (int i = 0; i < 4; ++i) { p.x[i] = xs[i]; p.z[i] = zs[i]; p.link[i] = false; }
    const bool ccwInside = poly_inside(p, 5, 5, 1);
    Poly q = p;
    for (int i = 0; i < 4; ++i) { q.x[i] = xs[3 - i]; q.z[i] = zs[3 - i]; }
    const bool cwInside = poly_inside(q, 5, 5, 1);
    if (ccwInside == cwInside) { std::fputs("orientation calibration failed\n", stderr); std::exit(3); }
    g_insideCCW = ccwInside;
}

// replica of 0x80DE00's cell selection (iteration order = cell range order); returns cell index or -1, pass = 1/2/0
static int expected_cell(const Scenario& S, int piece, float px, float pz, int* pass) {
    const nf::Piece& pc = S.pieces[static_cast<size_t>(piece)];
    for (int ps = 1; ps <= 2; ++ps) {
        for (uint32_t k = 0; k < pc.cellCount; ++k) {
            const nf::SurfaceCell& c = S.cells[pc.cellBegin + k];
            bool inside = true;
            for (uint32_t i = 0; i < c.nodeCount && inside; ++i) {
                const nf::SurfaceNode& a = S.nodes[c.nodeBegin + i];
                const nf::SurfaceNode& b = S.nodes[c.nodeBegin + (i + 1) % c.nodeCount];
                const float m = (ps == 2 && a.hasLink) ? g_margin2 : 0.0f;
                if (edge_outside(a.x, a.z, b.x, b.z, px, pz, m)) inside = false;
            }
            if (inside) { *pass = ps; return static_cast<int>(pc.cellBegin + k); }
        }
    }
    *pass = 0;
    return -1;
}

// ---------------------------------------------------------------------------------------------------------------------
// scenario generation
enum CellPlan { PL_NONE, PL_COVER, PL_MISS, PL_EDGE1, PL_EDGE2LINK, PL_EDGE2NOLINK, PL_MIXED, PL_HUGE };
struct Cfg {
    const char* name;
    int pMin, pMax; double pArc;
    uint32_t menMin, menMax;
    float lenMin, lenMax, wMin, wMax;
    double chained;
    CellPlan plan; double frameP; double originFrameP;
    int mod;        // 0 stock, 1 modActive, 2 both
    int rowReq;     // 0 none, 1 rowLen>60, 2 rowLen>60 even, 3 rowLen>60 odd, 4 rowLen<=60
    bool noTerrain; bool degenerate;
    int special;          // 0 none, 1 live-like parameters (values seen in the live capture), 2 live replay of captured commands
};


static uint32_t files_per_row(float w, float f, float l8, float l10, uint16_t cw) {
    const uint16_t old = get_cw();
    set_cw(cw);
    typedef int(__cdecl * Fn)(float, float, float);
    const int v = reinterpret_cast<Fn>(native_address(VA_FILES))(std::min(w, f), l8, l10);
    set_cw(old);
    return static_cast<uint32_t>(v);
}

static void rot_matrix(Rng& r, int kind, double m[9]) {
    // row-major 3x3 rotation
    double ax, ay, az;
    if (kind == 0) { ax = 0; ay = 1; az = 0; }
    else { ax = r.d(-1, 1); ay = r.d(-1, 1); az = r.d(-1, 1); const double l = std::sqrt(ax * ax + ay * ay + az * az); if (l < 1e-3) { ax = 0; ay = 1; az = 0; } else { ax /= l; ay /= l; az /= l; } }
    const double th = r.d(-3.14159, 3.14159), c = std::cos(th), s = std::sin(th), t = 1 - c;
    m[0] = t * ax * ax + c;      m[1] = t * ax * ay - s * az; m[2] = t * ax * az + s * ay;
    m[3] = t * ax * ay + s * az; m[4] = t * ay * ay + c;      m[5] = t * ay * az - s * ax;
    m[6] = t * ax * az - s * ay; m[7] = t * ay * az + s * ax; m[8] = t * az * az + c;
}
static nf::Frame make_frame(Rng& r) {
    nf::Frame F;
    double m[9];
    rot_matrix(r, r.p(0.5) ? 0 : 1, m);
    for (int i = 0; i < 9; ++i) F.fwd[i] = static_cast<float>(m[i]);
    for (int i = 0; i < 3; ++i) for (int j = 0; j < 3; ++j) F.inv[i * 3 + j] = static_cast<float>(m[j * 3 + i]);   // transpose
    if (r.p(0.15)) for (int i = 0; i < 9; ++i) F.inv[i] = r.f(-1.2f, 1.2f);                                        // not an exact inverse
    if (r.p(0.15)) for (int i = 0; i < 9; ++i) F.fwd[i] = r.f(-1.2f, 1.2f);
    for (int i = 0; i < 3; ++i) F.t[i] = r.f(-60, 60);
    return F;
}

static void gen_terrain(Rng& r, const Cfg& c, Scenario& S) {
    S.hasTerrain = !c.noTerrain;
    const uint32_t k = r.r(3, 6);
    S.hf.shift = k;
    S.hf.limit = static_cast<int32_t>(r.r(3, (1u << k) - 1));
    S.hf.base = r.p(0.05) ? -static_cast<int32_t>(r.r(1, 5)) : static_cast<int32_t>(S.hf.limit / 2);
    S.hf.cell = r.f(2.0f, 10.0f);
    S.hf.scale = 1.0f / S.hf.cell;
    S.hf.half = S.hf.cell * static_cast<float>(S.hf.base > 0 ? S.hf.base : 1);
    const size_t entries = (static_cast<size_t>(S.hf.limit) << k) + static_cast<size_t>(S.hf.limit) + 1;
    S.hf.sampleCount = static_cast<uint32_t>(entries);
    S.samples.resize(entries * 2);
    for (size_t i = 0; i < entries; ++i) { S.samples[2 * i] = r.f(0.0f, 100.0f); S.samples[2 * i + 1] = r.f(-1000.0f, 1000.0f); }
}

static void gen_geometry(Rng& r, const Cfg& c, Scenario& S) {
    nf::Input& in = S.in;
    const bool rows = c.rowReq != 0;
    if (c.special == 1) {   // values seen in the live capture: layout ~ 0.7/0.7/0.39/8.8, f ~ 35..80
        in.layout8 = r.f(0.5f, 1.0f);
        in.layoutC = in.layout8;
        in.layout10 = r.f(0.3f, 0.5f);
        in.layout14 = r.f(5.0f, 12.0f);
        in.f = r.f(30.0f, 90.0f);
    } else {
        in.layout8 = r.f(0.0f, 3.0f);
        in.layoutC = r.f(-5.0f, 5.0f);
        in.layout10 = rows ? r.f(0.4f, 1.0f) : r.f(0.3f, 3.0f);
        in.layout14 = r.f(0.3f, 3.0f);
        in.f = rows ? 500.0f : r.f(10.0f, 150.0f);
    }
    S.owner = static_cast<uint32_t>(r.g());
    // frames
    uint32_t nFrames = 0;
    if (c.frameP > 0 || c.originFrameP > 0) nFrames = r.r(1, 5);
    for (uint32_t i = 0; i < nFrames; ++i) S.frames.push_back(make_frame(r));
    in.origin.x = r.f(-100, 100); in.origin.y = r.f(-5, 5); in.origin.z = r.f(-100, 100);
    in.origin.frame = (nFrames && r.p(c.originFrameP)) ? static_cast<int32_t>(r.u(nFrames)) : -1;
    // terrain
    gen_terrain(r, c, S);
    // origin xz after the frame (approximate, only used to chain the geometry)
    double ox = in.origin.x, oz = in.origin.z;
    if (in.origin.frame >= 0) {
        const nf::Frame& F = S.frames[static_cast<size_t>(in.origin.frame)];
        const double x = in.origin.x, y = in.origin.y, z = in.origin.z;
        ox = F.fwd[0] * x + F.fwd[1] * y + F.fwd[2] * z + F.t[0];
        oz = F.fwd[6] * x + F.fwd[7] * y + F.fwd[8] * z + F.t[2];
    }
    // pieces
    const uint32_t np = static_cast<uint32_t>(c.degenerate ? r.r(0, 3) : r.r(static_cast<uint32_t>(c.pMin), static_cast<uint32_t>(c.pMax)));
    float cx = static_cast<float>(ox), cz = static_cast<float>(oz);
    const bool garbage = r.p(0.5);
    auto g = [&]() { return garbage ? r.f(-100, 100) : 0.0f; };
    for (uint32_t i = 0; i < np; ++i) {
        nf::Piece p{};
        const bool arc = r.p(c.pArc);
        p.isArc = arc ? 1 : 0;
        p.mode = static_cast<int32_t>(arc ? r.r(0, 2) : r.r(0, 3));
        p.angle = static_cast<uint16_t>(r.u(65536));
        const bool chain = r.p(c.chained);
        float sx = chain ? cx : r.f(-120, 120), sz = chain ? cz : r.f(-120, 120);
        if (i == 0 && !chain) { sx = r.f(-120, 120); sz = r.f(-120, 120); }
        // width, tuned with the ORIGINAL 0x642C90 for the row-length families
        float width = c.special == 1 ? in.f - r.f(0.0f, 1.0f) : r.f(c.wMin, c.wMax);
        if (rows) {
            for (int t = 0; t < 80; ++t) {
                const uint32_t rl = files_per_row(width, in.f, in.layout8, in.layout10, 0x27F);
                const bool okRow = (c.rowReq == 4) ? (rl <= 60 && rl >= 1) : (rl > 60 && (c.rowReq == 1 || (c.rowReq == 2 ? rl % 2 == 0 : rl % 2 == 1)));
                if (okRow) break;
                width = r.f(c.wMin, c.wMax);
            }
            S.rowLens.push_back(files_per_row(width, in.f, in.layout8, in.layout10, 0x27F));
        }
        const float len = (c.degenerate && r.p(0.4)) ? 0.0f : r.f(c.lenMin, c.lenMax);
        if (!arc) {
            const float h = r.f(0.0f, 6.2831853f);
            p.p0[0] = sx; p.p0[1] = sz;
            p.p1[0] = sx + len * std::cos(h); p.p1[1] = sz + len * std::sin(h);
            if (len > 0) { p.dir[0] = (p.p1[0] - p.p0[0]) / len; p.dir[1] = (p.p1[1] - p.p0[1]) / len; }
            else { p.dir[0] = std::cos(h); p.dir[1] = std::sin(h); }
            const float sg = r.p(0.5) ? 1.0f : -1.0f;
            p.step[0] = -p.dir[1] * sg; p.step[1] = p.dir[0] * sg;
            p.width = width;
            p.arcStart[0] = g(); p.arcStart[1] = g();
            p.center[0] = g(); p.center[1] = g();
            p.arcWidth = g();
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
        S.pieces.push_back(p);
    }
    // men
    if (c.degenerate) in.men = (r.p(0.3)) ? 0u : r.r(1, 40);
    else if (rows && !S.rowLens.empty()) {
        uint32_t mx = 0;
        for (uint32_t v : S.rowLens) mx = std::max(mx, v);
        in.men = std::min<uint32_t>(r.r(2 * mx + 1, 7 * mx + 5), 3000u);
    } else if (c.special == 1) in.men = r.r(100, 500);
    else in.men = r.r(c.menMin, c.menMax);
    S.inlineCount.assign(S.pieces.size(), 0);
    for (auto& p : S.pieces) { p.cellBegin = 0; p.cellCount = 0; }
    switch (c.mod) { case 0: S.mod = false; break; case 1: S.mod = true; break; default: S.mod = r.p(0.5); }
    in.modActive = S.mod;
}

// ---- polygons / cells ----
static bool make_ring(Rng& r, int n, double cx, double cz, double R, double maxGap, Poly& out) {
    std::vector<double> gap(static_cast<size_t>(n));
    bool ok = false;
    for (int t = 0; t < 200 && !ok; ++t) {
        double sum = 0;
        for (double& v : gap) { v = r.d(0.2, 1.0); sum += v; }
        ok = true;
        for (double& v : gap) { v = v / sum * 6.283185307179586; if (v > maxGap) ok = false; }
    }
    if (!ok) for (double& v : gap) v = 6.283185307179586 / n;
    double a = r.d(0, 6.283185307179586);
    out.n = n;
    for (int i = 0; i < n; ++i) {
        out.x[i] = static_cast<float>(cx + R * std::cos(a));
        out.z[i] = static_cast<float>(cz + R * std::sin(a));
        a += gap[static_cast<size_t>(i)];
    }
    // vertices were generated with increasing angle == counter-clockwise in (x,z); reverse for the other calibrated orientation
    if (!g_insideCCW) {
        for (int i = 0; i < n / 2; ++i) { std::swap(out.x[i], out.x[n - 1 - i]); std::swap(out.z[i], out.z[n - 1 - i]); }
    }
    return true;
}

struct PlannedCell { Poly poly; int frame; uint8_t nullG; float plane[4]; };

static void set_links(Rng& r, Poly& p, int mode /*0 none, 1 all, 2 random*/) {
    for (int i = 0; i < p.n; ++i) p.link[i] = mode == 1 ? true : mode == 0 ? false : r.p(0.5);
}

static PlannedCell make_cover(Rng& r, float px, float pz, int linkMode) {
    PlannedCell pc{};
    const double R = r.d(3, 25);
    const int n = static_cast<int>(r.r(3, 7));
    const double off = R * 0.2;
    make_ring(r, n, px + r.d(-off, off), pz + r.d(-off, off), R, 2.2, pc.poly);
    set_links(r, pc.poly, linkMode);
    return pc;
}
static PlannedCell make_miss(Rng& r, float px, float pz, int linkMode) {
    PlannedCell pc{};
    const double R = r.d(3, 25);
    const double dist = R + r.d(2, 40), a = r.d(0, 6.283185307179586);
    make_ring(r, static_cast<int>(r.r(3, 7)), px + dist * std::cos(a), pz + dist * std::sin(a), R, 2.2, pc.poly);
    set_links(r, pc.poly, linkMode);
    return pc;
}
static PlannedCell make_wrong_orientation(Rng& r, float px, float pz, int linkMode) {
    PlannedCell pc = make_cover(r, px, pz, linkMode);
    for (int i = 0; i < pc.poly.n / 2; ++i) { std::swap(pc.poly.x[i], pc.poly.x[pc.poly.n - 1 - i]); std::swap(pc.poly.z[i], pc.poly.z[pc.poly.n - 1 - i]); }
    return pc;
}
// polygon whose edge e passes exactly through the float-resolution boundary of the original edge predicate at P
static bool make_edge(Rng& r, float px, float pz, int linkMode, int pass, PlannedCell& out) {
    PlannedCell pc{};
    const double R = r.d(4, 20);
    make_ring(r, static_cast<int>(r.r(3, 7)), px, pz, R, 2.2, pc.poly);
    set_links(r, pc.poly, linkMode);
    Poly& poly = pc.poly;
    const int e = static_cast<int>(r.u(static_cast<uint32_t>(poly.n))), e2 = (e + 1) % poly.n;
    double dx = static_cast<double>(poly.x[e2]) - poly.x[e], dz = static_cast<double>(poly.z[e2]) - poly.z[e];
    const double len = std::sqrt(dx * dx + dz * dz);
    if (len < 1e-3) return false;
    double nx = dz / len, nz = -dx / len;                       // a normal; make it point away from P
    const double mx = 0.5 * (poly.x[e] + poly.x[e2]) - px, mz = 0.5 * (poly.z[e] + poly.z[e2]) - pz;
    if (nx * mx + nz * mz < 0) { nx = -nx; nz = -nz; }
    const double d0 = nx * mx + nz * mz;                         // distance of P from the edge line
    Poly base = poly;
    auto shifted = [&](double t) {
        Poly q = base;
        for (int i = 0; i < q.n; ++i) { q.x[i] = static_cast<float>(base.x[i] + t * nx); q.z[i] = static_cast<float>(base.z[i] + t * nz); }
        return q;
    };
    double lo = -d0 - 2.0, hi = -d0 + 2.0;
    if (poly_inside(shifted(lo), px, pz, pass) || !poly_inside(shifted(hi), px, pz, pass)) return false;
    for (int it = 0; it < 70; ++it) {
        const double mid = 0.5 * (lo + hi);
        if (poly_inside(shifted(mid), px, pz, pass)) hi = mid; else lo = mid;
    }
    pc.poly = shifted(r.p(0.5) ? hi : lo);
    out = pc;
    return true;
}

static void add_plane_and_frame(Rng& r, const Cfg& c, Scenario& S, PlannedCell& pc, float px, float pz) {
    const float a = r.f(-0.5f, 0.5f), b = r.f(0.3f, 1.5f), cc = r.f(-0.5f, 0.5f), y0 = r.f(0.0f, 60.0f);
    pc.plane[0] = a; pc.plane[1] = (r.p(0.03) ? -b : b); pc.plane[2] = cc;
    pc.plane[3] = -(a * px + cc * pz + pc.plane[1] * y0);
    pc.frame = (!S.frames.empty() && r.p(c.frameP)) ? static_cast<int>(r.u(static_cast<uint32_t>(S.frames.size()))) : -1;
    pc.nullG = r.p(0.5) ? 1 : 0;
}

static void commit_cells(Rng& r, Scenario& S, int piece, std::vector<PlannedCell>& cells) {
    nf::Piece& p = S.pieces[static_cast<size_t>(piece)];
    p.cellBegin = static_cast<uint32_t>(S.cells.size());
    p.cellCount = static_cast<uint32_t>(cells.size());
    const uint32_t n = p.cellCount;
    S.inlineCount[static_cast<size_t>(piece)] = r.r(0, std::min<uint32_t>(n, 10));
    for (auto& pc : cells) {
        nf::SurfaceCell sc{};
        sc.nodeBegin = static_cast<uint32_t>(S.nodes.size());
        sc.nodeCount = static_cast<uint32_t>(pc.poly.n);
        for (int k = 0; k < 4; ++k) sc.plane[k] = pc.plane[k];
        sc.frame = pc.frame;
        for (int i = 0; i < pc.poly.n; ++i) {
            nf::SurfaceNode sn{};
            sn.x = pc.poly.x[i]; sn.z = pc.poly.z[i]; sn.hasLink = pc.poly.link[i] ? 1 : 0;
            NodeX nx{};
            if (sn.hasLink) {
                nx.n = static_cast<uint8_t>(r.r(1, 3));
                nx.pos = static_cast<uint8_t>(r.u(nx.n));
                for (int j = 0; j < 3; ++j) nx.flag[j] = (j == nx.pos) ? 1 : static_cast<uint8_t>(r.p(0.5) ? 0 : (r.p(0.5) ? 2 : 0xFF));
            } else {
                nx.n = static_cast<uint8_t>(r.r(0, 3));
                for (int j = 0; j < 3; ++j) nx.flag[j] = static_cast<uint8_t>(r.p(0.5) ? 0 : (r.p(0.5) ? 2 : 0xFF));
            }
            S.nodes.push_back(sn); S.nodeX.push_back(nx);
        }
        S.cells.push_back(sc);
        S.cellNullG.push_back(pc.nullG);
    }
}

static void clear_cells(Scenario& S) {
    S.cells.clear(); S.nodes.clear(); S.nodeX.clear(); S.cellNullG.clear();
    for (size_t i = 0; i < S.pieces.size(); ++i) { S.pieces[i].cellBegin = 0; S.pieces[i].cellCount = 0; S.inlineCount[i] = 0; }
}

static PlannedCell make_huge(Rng& r, bool framed, Scenario& S, const Cfg& c) {
    PlannedCell pc{};
    pc.poly.n = 4;
    const float xs[4] = {-1e5f, 1e5f, 1e5f, -1e5f}, zs[4] = {-1e5f, -1e5f, 1e5f, 1e5f};
    for (int i = 0; i < 4; ++i) {
        const int k = g_insideCCW ? i : 3 - i;
        pc.poly.x[i] = xs[k]; pc.poly.z[i] = zs[k]; pc.poly.link[i] = r.p(0.5);
    }
    add_plane_and_frame(r, c, S, pc, 0, 0);
    if (!framed) pc.frame = -1;
    return pc;
}

// phase 1: one huge cell per piece (owner identification + positions fed to the surface lookup)
static bool phase1(Rng& r, const Cfg& c, Scenario& S) {
    clear_cells(S);
    for (size_t i = 0; i < S.pieces.size(); ++i) {
        std::vector<PlannedCell> v;
        v.push_back(make_huge(r, false, S, c));
        v[0].frame = -1; v[0].nullG = 1;
        commit_cells(r, S, static_cast<int>(i), v);
        S.inlineCount[i] = 1;
    }
    Fixture fx = build_fixture(S);
    OrigOut o = run_original(S, fx, 0x27F, false);
    S.seqPos.clear(); S.seqPiece.clear();
    if (o.crashed || !o.plumbing.empty()) { std::printf("phase-1 failure in %s case %u (seed %016llx)\n", S.family, S.caseIdx, static_cast<unsigned long long>(S.caseSeed)); return false; }
    for (const OrigRec& q : o.rec) {
        if (q.cell < 0 || q.cell >= static_cast<int>(S.pieces.size())) { std::puts("phase-1 record without owner cell"); return false; }
        S.seqPos.push_back({q.x, q.z});
        S.seqPiece.push_back(q.cell);
    }
    return true;
}

static void build_cells(Rng& r, const Cfg& c, Scenario& S) {
    clear_cells(S);
    std::vector<std::vector<std::pair<float, float>>> pos(S.pieces.size());
    for (size_t i = 0; i < S.seqPos.size(); ++i) pos[static_cast<size_t>(S.seqPiece[i])].push_back(S.seqPos[i]);
    for (size_t k = 0; k < S.pieces.size(); ++k) {
        const auto& P = pos[k];
        std::vector<PlannedCell> cells;
        if (P.empty()) { commit_cells(r, S, static_cast<int>(k), cells); continue; }
        auto anchor = [&]() { return P[r.u(static_cast<uint32_t>(P.size()))]; };
        auto push = [&](PlannedCell pc, float px, float pz) { add_plane_and_frame(r, c, S, pc, px, pz); cells.push_back(pc); };
        auto addEdge = [&](int linkMode, int pass) {
            for (int attempt = 0; attempt < 6; ++attempt) {
                auto a = anchor();
                PlannedCell pc;
                if (make_edge(r, a.first, a.second, linkMode, pass, pc)) { push(pc, a.first, a.second); return; }
            }
            auto a = anchor(); push(make_miss(r, a.first, a.second, linkMode), a.first, a.second);
        };
        switch (c.plan) {
        case PL_COVER: {
            const uint32_t n = r.r(1, 6);
            for (uint32_t i = 0; i < n; ++i) { auto a = anchor(); push(r.p(0.7) ? make_cover(r, a.first, a.second, 2) : make_miss(r, a.first, a.second, 2), a.first, a.second); }
            break;
        }
        case PL_MISS: {
            const uint32_t n = r.r(1, 5);
            for (uint32_t i = 0; i < n; ++i) { auto a = anchor(); push(make_miss(r, a.first, a.second, 2), a.first, a.second); }
            break;
        }
        case PL_EDGE1: {
            const uint32_t n = r.r(2, 8);
            for (uint32_t i = 0; i < n; ++i) {
                const double q = r.d(0, 1);
                if (q < 0.6) addEdge(2, 1);
                else if (q < 0.8) { auto a = anchor(); push(make_wrong_orientation(r, a.first, a.second, 2), a.first, a.second); }
                else { auto a = anchor(); push(make_miss(r, a.first, a.second, 2), a.first, a.second); }
            }
            break;
        }
        case PL_EDGE2LINK: {
            const uint32_t n = r.r(2, 8);
            for (uint32_t i = 0; i < n; ++i) {
                if (r.p(0.75)) addEdge(1, 2); else { auto a = anchor(); push(make_miss(r, a.first, a.second, 1), a.first, a.second); }
            }
            break;
        }
        case PL_EDGE2NOLINK: {
            const uint32_t n = r.r(2, 8);
            for (uint32_t i = 0; i < n; ++i) {
                if (r.p(0.75)) addEdge(0, 2); else { auto a = anchor(); push(make_miss(r, a.first, a.second, 0), a.first, a.second); }
            }
            break;
        }
        case PL_MIXED: {
            const uint32_t n = r.r(1, 14);
            for (uint32_t i = 0; i < n; ++i) {
                const double q = r.d(0, 1);
                auto a = anchor();
                if (q < 0.25) push(make_cover(r, a.first, a.second, 2), a.first, a.second);
                else if (q < 0.45) push(make_miss(r, a.first, a.second, 2), a.first, a.second);
                else if (q < 0.65) addEdge(2, 1);
                else if (q < 0.85) addEdge(2, 2);
                else if (q < 0.90) push(make_wrong_orientation(r, a.first, a.second, 2), a.first, a.second);
                else { PlannedCell h = make_huge(r, true, S, c); cells.push_back(h); }
            }
            break;
        }
        case PL_HUGE: {
            const uint32_t n = r.r(1, 3);
            for (uint32_t i = 0; i < n; ++i) {
                if (i == 0 || r.p(0.5)) cells.push_back(make_huge(r, c.frameP > 0, S, c));
                else { auto a = anchor(); push(make_cover(r, a.first, a.second, 2), a.first, a.second); }
            }
            break;
        }
        case PL_NONE: break;
        }
        // no-terrain family: the last cell of every piece is a huge cover so that no record ever falls back to the terrain
        if (c.noTerrain) cells.push_back(make_huge(r, c.frameP > 0, S, c));
        commit_cells(r, S, static_cast<int>(k), cells);
    }
}

static bool build_case(Rng& r, const Cfg& c, Scenario& S) {
    gen_geometry(r, c, S);
    if (c.plan != CellPlan::PL_NONE || c.noTerrain) {
        if (!phase1(r, c, S)) return false;
        build_cells(r, c, S);
    } else clear_cells(S);
    S.finalize();
    return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// comparison
struct Fam {
    const Cfg* cfg;
    uint64_t cases = 0, runs = 0, records = 0, cellRecs = 0, terrainRecs = 0, framedRecs = 0, exhausted = 0, partial = 0;
    uint64_t mismatches = 0, plumbing = 0, modDiff = 0, modRuns = 0, replicaChecked = 0, replicaBad = 0;
    uint64_t pass1 = 0, pass2 = 0, nonOverlap = 0, rowsOver60 = 0, oddRowCases = 0, evenRowCases = 0, noRecords = 0, hookCasesChecked = 0;
    uint64_t perCw[3] = {0, 0, 0};
    uint64_t cwDiff = 0, rowPiecesOdd = 0, rowPiecesEven = 0, rowPieces60 = 0, skipped = 0;
    uint64_t printed = 0;
};

static bool g_verbose;
static int g_mutate;   // self-test: perturb the snapshot handed to the PORT only; the oracle must then report mismatches
static void dump_scenario(const Scenario& S) {
    const nf::Input& in = S.in;
    std::printf("  INPUT men=%u f=%08x layout8=%08x layoutC=%08x layout10=%08x layout14=%08x origin=(%08x %08x %08x frame %d) terrain=%d owner=%08x\n", in.men,
                bits(in.f), bits(in.layout8), bits(in.layoutC), bits(in.layout10), bits(in.layout14), bits(in.origin.x), bits(in.origin.y), bits(in.origin.z),
                in.origin.frame, S.hasTerrain ? 1 : 0, S.owner);
    for (size_t i = 0; i < S.pieces.size(); ++i) {
        const nf::Piece& p = S.pieces[i];
        std::printf("  PIECE %zu isArc=%d mode=%d angle=%04x p0=(%08x %08x) p1=(%08x %08x) step=(%08x %08x) width=%08x arcStart=(%08x %08x) dir=(%08x %08x) center=(%08x %08x) arcWidth=%08x cells=%u+%u\n",
                    i, p.isArc, p.mode, p.angle, bits(p.p0[0]), bits(p.p0[1]), bits(p.p1[0]), bits(p.p1[1]), bits(p.step[0]), bits(p.step[1]), bits(p.width),
                    bits(p.arcStart[0]), bits(p.arcStart[1]), bits(p.dir[0]), bits(p.dir[1]), bits(p.center[0]), bits(p.center[1]), bits(p.arcWidth), p.cellBegin, p.cellCount);
    }
}
static void fam_fail(Fam& F, const Scenario& S, uint16_t cw, bool mod, const char* what, bool plumbing) {
    if (plumbing) ++F.plumbing; else ++F.mismatches;
    if (F.printed < 12) {
        ++F.printed;
        std::printf("%s [%s case=%u seed=%016llx cw=%03X mod=%d men=%u pieces=%u]: %s\n", plumbing ? "PLUMBING" : "MISMATCH", S.family, S.caseIdx,
                    static_cast<unsigned long long>(S.caseSeed), cw, mod ? 1 : 0, S.in.men, S.in.pieceCount, what);
        if (g_verbose) dump_scenario(S);
    }
}

#define NO_PORT_MSG "native_formation_layout.cpp not linked (built with /DNTW_ORACLE_NO_PORT)"

static void compare_run(Fam& F, const Scenario& S, uint16_t cw, bool mod, const OrigOut& o) {
    ++F.runs;
    char buf[400];
    if (o.crashed) { std::snprintf(buf, sizeof buf, "ORIGINAL crashed with exception %08lx", static_cast<unsigned long>(o.exc)); fam_fail(F, S, cw, mod, buf, true); return; }
    for (const std::string& m : o.plumbing) fam_fail(F, S, cw, mod, m.c_str(), true);
    if (!o.plumbing.empty()) return;
    F.records += o.rec.size();
    for (const OrigRec& q : o.rec) {
        if (q.cell >= 0) ++F.cellRecs; else ++F.terrainRecs;
        if (q.frame >= 0) ++F.framedRecs;
    }
    if (o.count == S.in.men && S.in.men > 0) ++F.exhausted; else if (o.count > 0) ++F.partial; else ++F.noRecords;
    if (!S.hasTerrain) for (const OrigRec& q : o.rec) if (q.cell < 0) { fam_fail(F, S, cw, mod, "record fell back to terrain in the no-terrain family", true); return; }
#ifdef NTW_ORACLE_NO_PORT
    (void)NO_PORT_MSG;
    return;
#else
    nf::Input in = S.in;
    in.fpuControlWord = cw;
    in.modActive = mod ? 1 : 0;
    std::vector<nf::SurfaceNode> nodesM;
    std::vector<nf::Frame> framesM;
    nf::HeightField hfM{};
    switch (g_mutate) {
    case 1: in.layout14 = std::nextafter(in.layout14, 1e9f); break;
    case 2: nodesM.assign(S.nodes.begin(), S.nodes.end()); for (auto& n : nodesM) n.hasLink ^= 1; in.nodes = nodesM.data(); break;
    case 3: in.fpuControlWord = (cw == 0x27F) ? 0x7F : 0x27F; break;
    case 4: if (in.terrain) { hfM = *in.terrain; hfM.scale = std::nextafter(hfM.scale, 1e9f); in.terrain = &hfM; } break;
    case 5: framesM.assign(S.frames.begin(), S.frames.end()); for (auto& f : framesM) f.inv[0] = std::nextafter(f.inv[0], 1e9f); in.frames = framesM.data(); break;
    case 6: in.origin.x = std::nextafter(in.origin.x, 1e9f); break;
    case 7: in.modActive = in.modActive ? 0 : 1; break;
    default: break;
    }
    std::vector<nf::Slot> slots(S.in.men + 1);
    for (nf::Slot& s : slots) std::memset(&s, 0xEE, sizeof s);
    nf::Result res{0xDEAD, 0xBEEF};
    const uint16_t cwBefore = get_cw();
    const int st = nf::Generate(in, slots.data(), S.in.men, &res);
    const uint16_t cwAfter = get_cw();
    if (cwAfter != cwBefore) { std::snprintf(buf, sizeof buf, "port did not restore the x87 control word (%04X -> %04X)", cwBefore, cwAfter); fam_fail(F, S, cw, mod, buf, false); set_cw(cwBefore); }
    ++F.perCw[cw == 0x27F ? 0 : cw == 0x37F ? 1 : 2];
    if (st != nf::kOk) { std::snprintf(buf, sizeof buf, "Generate returned status %d", st); fam_fail(F, S, cw, mod, buf, false); return; }
    if (res.count != o.count) { std::snprintf(buf, sizeof buf, "count orig=%u port=%u", o.count, res.count); fam_fail(F, S, cw, mod, buf, false); return; }
    if (res.mark != o.mark) { std::snprintf(buf, sizeof buf, "mark orig=%u port=%u", o.mark, res.mark); fam_fail(F, S, cw, mod, buf, false); }
    for (uint32_t i = 0; i < o.count; ++i) {
        const OrigRec& q = o.rec[i];
        const nf::Slot& s = slots[i];
        const char* bad = nullptr;
        char det[200];
        det[0] = 0;
        if (s.flag != q.flag) { bad = "flag"; std::snprintf(det, sizeof det, "orig=%u port=%u", q.flag, s.flag); }
        else if (bits(s.x) != bits(q.x)) { bad = "x"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.x), q.x, bits(s.x), s.x); }
        else if (bits(s.z) != bits(q.z)) { bad = "z"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.z), q.z, bits(s.z), s.z); }
        else if (s.cell != q.cell) { bad = "cell"; std::snprintf(det, sizeof det, "orig=%d port=%d", q.cell, s.cell); }
        else if (s.frame != q.frame) { bad = "frame"; std::snprintf(det, sizeof det, "orig=%d port=%d", q.frame, s.frame); }
        else if (s.angle != q.angle) { bad = "angle"; std::snprintf(det, sizeof det, "orig=%04x port=%04x", q.angle, s.angle); }
        else if (s.yValid != (S.hasTerrain || q.cell >= 0 ? 1 : 0)) { bad = "yValid"; std::snprintf(det, sizeof det, "orig-expected=%d port=%d", (S.hasTerrain || q.cell >= 0) ? 1 : 0, s.yValid); }
        else if (s.yValid) {
            if (bits(s.y) != bits(q.y)) { bad = "y"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.y), q.y, bits(s.y), s.y); }
            else if (bits(s.worldX) != bits(q.wx)) { bad = "worldX"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.wx), q.wx, bits(s.worldX), s.worldX); }
            else if (bits(s.worldY) != bits(q.wy)) { bad = "worldY"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.wy), q.wy, bits(s.worldY), s.worldY); }
            else if (bits(s.worldZ) != bits(q.wz)) { bad = "worldZ"; std::snprintf(det, sizeof det, "orig=%08x(%g) port=%08x(%g)", bits(q.wz), q.wz, bits(s.worldZ), s.worldZ); }
        }
        if (bad) {
            std::snprintf(buf, sizeof buf, "record %u/%u field %s %s (cell=%d frame=%d)", i, o.count, bad, det, q.cell, q.frame);
            fam_fail(F, S, cw, mod, buf, false);
            if (g_verbose && F.printed <= 12) {
                for (uint32_t j = (i > 4 ? i - 4 : 0); j <= i && j < o.count; ++j)
                    std::printf("    rec %u orig flag=%u x=%08x y=%08x z=%08x cell=%d frame=%d | port flag=%u x=%08x y=%08x z=%08x cell=%d frame=%d\n", j, o.rec[j].flag,
                                bits(o.rec[j].x), bits(o.rec[j].y), bits(o.rec[j].z), o.rec[j].cell, o.rec[j].frame, slots[j].flag, bits(slots[j].x), bits(slots[j].y),
                                bits(slots[j].z), slots[j].cell, slots[j].frame);
            }
            return;   // one report per run
        }
    }
#endif
}

static bool slots_equal_orig(const OrigOut& a, const OrigOut& b) {
    if (a.count != b.count) return false;
    for (uint32_t i = 0; i < a.count; ++i) {
        const OrigRec& p = a.rec[i];
        const OrigRec& q = b.rec[i];
        if (bits(p.x) != bits(q.x) || bits(p.z) != bits(q.z) || bits(p.y) != bits(q.y) || p.cell != q.cell || p.frame != q.frame) return false;
    }
    return true;
}

// plumbing checks that use the phase-1 observation (cells never change the position sequence; replica of the cell selection)
static void phase1_checks(Fam& F, const Scenario& S, const OrigOut& o) {
    if (S.seqPos.empty() && o.count == 0) return;
    if (o.count != S.seqPos.size()) { fam_fail(F, S, 0x27F, false, "record count with cells differs from the phase-1 huge-cell run (positions must not depend on cells)", true); return; }
    for (uint32_t i = 0; i < o.count; ++i) {
        const OrigRec& q = o.rec[i];
        if (q.frame < 0 && (bits(q.x) != bits(S.seqPos[i].first) || bits(q.z) != bits(S.seqPos[i].second))) {
            fam_fail(F, S, 0x27F, false, "unframed record xz differs from the phase-1 position", true);
            return;
        }
        int pass = 0;
        const int e = expected_cell(S, S.seqPiece[i], S.seqPos[i].first, S.seqPos[i].second, &pass);
        ++F.replicaChecked;
        if (pass == 1) ++F.pass1; else if (pass == 2) ++F.pass2;
        if (e != q.cell) {
            ++F.replicaBad;
            char buf[200];
            std::snprintf(buf, sizeof buf, "cell selection replica disagrees with the original at record %u: replica=%d (pass %d) orig=%d", i, e, pass, q.cell);
            fam_fail(F, S, 0x27F, false, buf, true);
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
static const Cfg kFamilies[] = {
    // name                pMin pMax pArc  menMin menMax lenMin lenMax wMin wMax chained plan            frameP origF mod rowReq noTer degen
    {"A_only",             1, 4,  0.0, 5,   400,  5,   120, 3,   60,  0.7, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"B_only",             1, 4,  1.0, 5,   400,  5,   120, 3,   60,  0.7, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"mixed_pieces",       2, 8,  0.5, 20,  800,  5,   100, 3,   60,  0.6, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"many_pieces_to_zero",15, 40, 0.4, 10,  150,  3,   12,  2,   20,  0.7, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"exhausted_mid_piece",1, 3,  0.4, 1,   40,   30,  120, 3,   40,  0.7, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"carry_across_pieces",4, 12, 0.4, 300, 1500, 2.1f,9.3f,2,   12,  1.0, PL_NONE,        0.0, 0.0, 0, 0, false, false, 0},
    {"surf_cover",         1, 4,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_COVER,       0.0, 0.0, 0, 0, false, false, 0},
    {"surf_outside_terrain",1,4,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_MISS,        0.0, 0.0, 0, 0, false, false, 0},
    {"surf_edge_pass1",    1, 3,  0.4, 10,  300,  8,   60,  3,   30,  0.7, PL_EDGE1,       0.3, 0.0, 0, 0, false, false, 0},
    {"surf_edge_pass2_link",1,3,  0.4, 10,  300,  8,   60,  3,   30,  0.7, PL_EDGE2LINK,   0.3, 0.0, 0, 0, false, false, 0},
    {"surf_edge_pass2_nolink",1,3,0.4, 10,  300,  8,   60,  3,   30,  0.7, PL_EDGE2NOLINK, 0.3, 0.0, 0, 0, false, false, 0},
    {"surf_mixed_overflow",1, 4,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_MIXED,       0.4, 0.2, 0, 0, false, false, 0},
    {"cells_without_frames",1,4,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_COVER,       0.0, 0.0, 0, 0, false, false, 0},
    {"cells_with_frames",  1, 4,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_COVER,       1.0, 0.0, 0, 0, false, false, 0},
    {"origin_frame",       1, 5,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_COVER,       0.5, 1.0, 0, 0, false, false, 0},
    {"origin_frame_terrain",1,5,  0.4, 10,  400,  8,   100, 3,   40,  0.7, PL_NONE,        0.0, 1.0, 0, 0, false, false, 0},
    {"rows60_stock",       1, 3,  0.4, 0,   0,    20,  150, 30,  130, 0.7, PL_COVER,       0.3, 0.0, 0, 1, false, false, 0},
    {"rows60_mod_even",    1, 3,  0.4, 0,   0,    20,  150, 30,  130, 0.7, PL_COVER,       0.3, 0.0, 2, 2, false, false, 0},
    {"rows60_mod_odd",     1, 3,  0.4, 0,   0,    20,  150, 30,  130, 0.7, PL_COVER,       0.3, 0.0, 2, 3, false, false, 0},
    {"rows_le60_mod",      1, 3,  0.4, 0,   0,    20,  150, 8,   30,  0.7, PL_COVER,       0.3, 0.0, 1, 4, false, false, 0},
    {"no_terrain_cells",   1, 4,  0.4, 10,  300,  8,   100, 3,   40,  0.7, PL_MIXED,       0.5, 0.3, 2, 0, true,  false, 0},
    {"degenerate",         0, 3,  0.4, 0,   40,   0,   20,  0,   30,  0.5, PL_NONE,        0.0, 0.0, 2, 0, false, true,  0},
    {"stress_random",      1, 10, 0.5, 1,   1200, 2,   150, 2,   130, 0.5, PL_MIXED,       0.4, 0.3, 2, 0, false, false, 0},
    {"live_like",          1, 1,  0.0, 100, 500,  20,  120, 25,  90,  0.7, PL_NONE,        0.0, 0.0, 2, 0, false, false, 1},
    {"live_replay",        0, 0,  0.0, 0,   0,    0,   0,   0,   0,   0.0, PL_NONE,        0.0, 0.0, 2, 0, false, false, 2},
};
static const size_t kNumFamilies = sizeof(kFamilies) / sizeof(kFamilies[0]);

// ---- live replay: commands captured passively from the running game (analysis/native-formation-layout-live-28252.json),
// converted by the .py wrapper into a small binary file.  Each record is one real command: layout floats, men, f, the raw
// container head and the raw class-A/B child object.  Host-only fields (child+0x1C surface-set pointer, container child array
// pointer) are replaced by fixture objects; the surface counts of the captured commands are (0,0), so the terrain lookup is used
// and the (uncaptured) height field is synthesised.
#pragma pack(push, 1)
struct LiveRec { uint32_t men; uint32_t fbits; uint8_t layout[0x18]; uint8_t container[0x3C]; uint8_t child[0xA4]; uint8_t kind, mod; uint16_t pad; };
#pragma pack(pop)
static std::vector<LiveRec> g_live;
static bool load_live(const char* path) {
    FILE* fp = std::fopen(path, "rb");
    if (!fp) { std::fprintf(stderr, "cannot open live file %s\n", path); return false; }
    uint32_t hdr[2] = {0, 0};
    bool ok = std::fread(hdr, 4, 2, fp) == 2 && hdr[0] == 0x4C57544Eu;   // 'NTWL'
    if (ok) {
        g_live.resize(hdr[1]);
        ok = hdr[1] == 0 || std::fread(g_live.data(), sizeof(LiveRec), hdr[1], fp) == hdr[1];
    }
    std::fclose(fp);
    if (!ok) { std::fprintf(stderr, "bad live file %s\n", path); g_live.clear(); }
    return ok;
}
// returns 1 = built, 0 = skipped (not replayable), -1 = failure
static int build_live_case(const Cfg& c, uint32_t caseIdx, Rng& r, Scenario& S) {
    if (g_live.empty()) return 0;
    const LiveRec& L = g_live[caseIdx % g_live.size()];
    if (rd<uint32_t>(L.container, 0x10) != 1 || rd<uint32_t>(L.container, 0x28) != 0) return 0;   // only single-child, frame-less origins
    gen_terrain(r, c, S);
    nf::Input& in = S.in;
    in.men = L.men;
    in.f = fbits(L.fbits);
    in.layout8 = rd<float>(L.layout, 8); in.layoutC = rd<float>(L.layout, 0xC); in.layout10 = rd<float>(L.layout, 0x10); in.layout14 = rd<float>(L.layout, 0x14);
    S.owner = rd<uint32_t>(L.layout, 4);
    in.origin.x = rd<float>(L.container, 0x18); in.origin.y = rd<float>(L.container, 0x1C); in.origin.z = rd<float>(L.container, 0x20);
    in.origin.frame = -1;
    nf::Piece p{};
    p.isArc = L.kind == 1 ? 1 : 0;
    p.mode = rd<int32_t>(L.child, 4);
    p.angle = rd<uint16_t>(L.child, 8);
    p.p0[0] = rd<float>(L.child, 0xC); p.p0[1] = rd<float>(L.child, 0x10);
    p.p1[0] = rd<float>(L.child, 0x14); p.p1[1] = rd<float>(L.child, 0x18);
    p.step[0] = rd<float>(L.child, 0x60); p.step[1] = rd<float>(L.child, 0x64);
    p.width = rd<float>(L.child, 0x70);
    p.arcStart[0] = rd<float>(L.child, 0x7C); p.arcStart[1] = rd<float>(L.child, 0x80);
    p.dir[0] = rd<float>(L.child, 0x8C); p.dir[1] = rd<float>(L.child, 0x90);
    if (p.isArc) { p.center[0] = rd<float>(L.child, 0x98); p.center[1] = rd<float>(L.child, 0x9C); p.arcWidth = rd<float>(L.child, 0xA0); }
    S.pieces.push_back(p);
    S.inlineCount.assign(1, 0);
    S.mod = L.mod != 0;
    in.modActive = L.mod;
    S.rowLens.push_back(files_per_row(p.isArc ? p.arcWidth : p.width, in.f, in.layout8, in.layout10, 0x27F));
    S.finalize();
    return 1;
}

static void run_case(Fam& F, const Cfg& c, uint32_t caseIdx, uint64_t seed) {
    Scenario S;
    S.family = c.name;
    S.caseIdx = caseIdx;
    S.caseSeed = mix64(seed ^ mix64(0x1000193ull * (static_cast<uint64_t>(&c - kFamilies) + 1)) ^ mix64(caseIdx + 1));
    Rng r(S.caseSeed);
    if (c.special == 2) {
        const int lr = build_live_case(c, caseIdx, r, S);
        if (lr == 0) { ++F.skipped; return; }
        if (lr < 0) { fam_fail(F, S, 0x27F, false, "live case construction failed", true); return; }
    } else if (!build_case(r, c, S)) { fam_fail(F, S, 0x27F, false, "case construction failed (phase-1 plumbing)", true); return; }
    Fixture fx = build_fixture(S);
    ++F.cases;
    for (uint32_t v : S.rowLens) { ++((v & 1) ? F.rowPiecesOdd : F.rowPiecesEven); if (v > 60) ++F.rowPieces60; }
    std::vector<OrigOut> modOuts;
    const int nModes = c.mod == 2 ? 2 : 1;
    for (int mi = 0; mi < nModes; ++mi) {
        const bool mod = c.mod == 2 ? (mi == 1) : (c.mod == 1);
        for (uint16_t cw : kCW) {
            OrigOut o = run_original(S, fx, cw, mod);
            compare_run(F, S, cw, mod, o);
            if (mod && !o.crashed && o.plumbing.empty()) modOuts.push_back(o);
            if (!o.crashed && o.plumbing.empty()) {
                if (!mod && cw == 0x27F && !S.seqPos.empty()) phase1_checks(F, S, o);
                if (mod) {
                    OrigOut base = run_original(S, fx, cw, false);
                    ++F.modRuns;
                    if (!base.crashed && base.plumbing.empty() && !slots_equal_orig(o, base)) ++F.modDiff;
                }
            }
            if (o.crashed) return;
        }
    }
    if (modOuts.size() == 3 || modOuts.size() == 6) {
        const size_t b = modOuts.size() - 3;
        if (!slots_equal_orig(modOuts[b], modOuts[b + 1]) || !slots_equal_orig(modOuts[b], modOuts[b + 2])) ++F.cwDiff;   // original output depends on the x87 control word
    }
}

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (argc < 2) { std::fputs("usage: native_formation_layout_oracle <Napoleon.exe> [cases=N] [seed=S] [family=name] [case=K] [verbose=1]\n", stderr); return 2; }
    uint32_t cases = 300, onlyCase = 0xFFFFFFFFu;
    uint64_t seed = 20240601;
    std::string onlyFam;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        const size_t eq = a.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = a.substr(0, eq), v = a.substr(eq + 1);
        if (k == "cases") cases = static_cast<uint32_t>(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "seed") seed = std::strtoull(v.c_str(), nullptr, 10);
        else if (k == "family") onlyFam = v;
        else if (k == "case") onlyCase = static_cast<uint32_t>(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "verbose") g_verbose = v != "0";
        else if (k == "live") { if (!load_live(v.c_str())) return 2; }
        else if (k == "mutate") g_mutate = std::atoi(v.c_str());
    }
    if (!map_image(argv[1])) return 2;
    g_heap = static_cast<uint8_t*>(VirtualAlloc(nullptr, g_heapCap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    g_arena.init(32u << 20);
    if (!g_heap) return 2;
    init_host_vtables();
    patch_jmp(native_address(VA_ALLOC), reinterpret_cast<void*>(&host_alloc));
    patch_jmp(native_address(VA_FREE), reinterpret_cast<void*>(&host_free));
    if (!FlushInstructionCache(GetCurrentProcess(), nullptr, 0)) return 2;
    g_margin2 = rd<float>(reinterpret_cast<const void*>(native_address(VA_K_MARGIN2)), 0);
    std::printf("CONST 0x13359F8 pass2-margin=%08x(%g)\n", bits(g_margin2), g_margin2);
    static const uintptr_t kConsts[] = {0x1318038, 0x1318048, 0x131A7A4, 0x1318150, 0x1318030, 0x1318034, 0x131A7B0};
    for (uintptr_t a : kConsts) { const float v = rd<float>(reinterpret_cast<const void*>(native_address(a)), 0); std::printf("CONST 0x%X=%08x(%g)\n", static_cast<unsigned>(a), bits(v), v); }
    std::printf("CONST 0x1318130 (2^32 table) lo=%016llx hi=%016llx\n",
                static_cast<unsigned long long>(rd<uint64_t>(reinterpret_cast<const void*>(native_address(0x1318130)), 0)),
                static_cast<unsigned long long>(rd<uint64_t>(reinterpret_cast<const void*>(native_address(0x1318130)), 8)));
    calibrate_orientation();
    std::printf("edge-predicate orientation: interior is inside for %s rings\n", g_insideCCW ? "counter-clockwise" : "clockwise");

    std::vector<Fam> fams(kNumFamilies);
    for (size_t i = 0; i < kNumFamilies; ++i) fams[i].cfg = &kFamilies[i];
    const uint16_t cw0 = get_cw();
    for (size_t fi = 0; fi < kNumFamilies; ++fi) {
        const Cfg& c = kFamilies[fi];
        if (!onlyFam.empty() && onlyFam != c.name) continue;
        for (uint32_t k = 0; k < cases; ++k) {
            if (onlyCase != 0xFFFFFFFFu && k != onlyCase) continue;
            run_case(fams[fi], c, k, seed);
        }
        if (get_cw() != cw0) { std::printf("x87 control word leaked (%04X != %04X) after family %s\n", get_cw(), cw0, c.name); set_cw(cw0); ++fams[fi].plumbing; }
    }

    uint64_t bad = 0;
    bool zero = false;
    uint64_t totRecords = 0;
    for (size_t i = 0; i < kNumFamilies; ++i) {
        const Fam& F = fams[i];
        if (!onlyFam.empty() && onlyFam != F.cfg->name) continue;
        const bool isMod = std::strncmp(F.cfg->name, "rows60_mod", 10) == 0;
        std::printf("FAMILY %-24s cases=%llu runs=%llu records=%llu cell=%llu terrain=%llu framed=%llu exhausted=%llu partial=%llu empty=%llu "
                    "modRuns=%llu modGapDiff=%llu cwDiff=%llu replica=%llu replicaBad=%llu pass1=%llu pass2=%llu rowPiecesOdd=%llu rowPiecesEven=%llu rowPieces60=%llu skipped=%llu "
                    "cw27F=%llu cw37F=%llu cw7F=%llu mismatches=%llu plumbing=%llu\n",
                    F.cfg->name, (unsigned long long)F.cases, (unsigned long long)F.runs, (unsigned long long)F.records, (unsigned long long)F.cellRecs,
                    (unsigned long long)F.terrainRecs, (unsigned long long)F.framedRecs, (unsigned long long)F.exhausted, (unsigned long long)F.partial,
                    (unsigned long long)F.noRecords, (unsigned long long)F.modRuns, (unsigned long long)F.modDiff, (unsigned long long)F.cwDiff,
                    (unsigned long long)F.replicaChecked, (unsigned long long)F.replicaBad, (unsigned long long)F.pass1, (unsigned long long)F.pass2,
                    (unsigned long long)F.rowPiecesOdd, (unsigned long long)F.rowPiecesEven, (unsigned long long)F.rowPieces60, (unsigned long long)F.skipped,
                    (unsigned long long)F.perCw[0], (unsigned long long)F.perCw[1], (unsigned long long)F.perCw[2], (unsigned long long)F.mismatches,
                    (unsigned long long)F.plumbing);
        bad += F.mismatches + F.plumbing;
        totRecords += F.records;
        if (F.cases == 0) { zero = true; std::printf("FAIL: family %s ran zero cases\n", F.cfg->name); }
        if (isMod && F.modDiff == 0) { zero = true; std::printf("FAIL: family %s never observed the mod gap insertion (hook did not fire)\n", F.cfg->name); }
        if (F.cfg->special == 2 && F.cases == 0) std::printf("note: live_replay needs live=<native-formation-layout-live.bin> (see native_formation_layout_oracle_run.py)\n");
    }
#ifdef NTW_ORACLE_NO_PORT
    std::printf("TOTAL records=%llu\nRESULT NO-PORT (" NO_PORT_MSG "): original-call plumbing %s\n", (unsigned long long)totRecords, bad == 0 ? "ok" : "FAILED");
    return 3;
#else
    std::printf("TOTAL records=%llu mismatches+plumbing=%llu\n", (unsigned long long)totRecords, (unsigned long long)bad);
    if (g_mutate) {
        std::printf("MUTATE mode=%d detected=%llu (self-test only; exit code is forced non-zero)\n", g_mutate, (unsigned long long)bad);
        return 4;
    }
    const bool pass = bad == 0 && !zero;
    std::puts(pass ? "RESULT PASS (bit-identical)" : "RESULT FAIL");
    return pass ? 0 : 1;
#endif
}
