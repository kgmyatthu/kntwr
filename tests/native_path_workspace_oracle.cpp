#define _CRT_SECURE_NO_WARNINGS
// Differential oracle for the private native-path search workspace (native_path_workspace.h/.cpp).
//
// It executes the ORIGINAL machine code of the approved image (Napoleon.exe, SHA-256 13fcab62...cbad4, read from the installed
// file into a PRIVATE relocated mapping inside THIS test process) and compares, structure for structure, with the port:
//     native:  7EB020 (G constructor)  ->  8026F0 (driver)  ->  802A80 / 7E04D0 (engine)  ->  7DF8B0, 8113E0, 807AF0,
//              814270, 7F70B0, 807620, 7ED270, 7EFF60, 808D20, 80B0F0/79AE00, 448B90, 7FE320/809C40 (ALL original bytes)
//     port:    ntw_path_workspace::Workspace (Init / Begin / Advance / Run) on caller-owned storage
// The ONLY replaced pieces are the ones that belong to the world, not to the engine (query results are explicit bounded
// input fixtures; no battle is replayed):
//     0x800210  neighbour generator  -> host fixture generator (it allocates nodes through the ORIGINAL 0x80B0F0 on arena B,
//                                       pushes through the ORIGINAL 0x448B90, and de-duplicates through the ORIGINAL 0x807AF0)
//     0x7EB210  via-seed node builder -> host fixture (writes the seed node fields)
//     0xFF7F20/0xFF7EF0/0x1271290/0x1271276  game / CRT allocators -> canary host heap;  0x4C3920 (CRITICAL_SECTION init) -> ret
// All patches are inside the private copy; nothing touches the running game, the installed EXE, a debugger or an injector.
//
// Compared after every solve (canonicalised: pointers become (arena, block, offset) ids, fixture object pointers are shared):
//   result byte, expansion counter / total / limit, goal+query+goalPos+segment+flags, start pointer, output vector,
//   open heap order, neighbour vector, EVERY node and entry allocated in the live arena blocks (all fields), arena `used`
//   per live block, hash bucket count / count / head / every occupied row (key, value, intrusive next).
// Families: small medium dense collide marker via bare overwrite reuse hostile region.  Extra suites: equality (7ED270 and
// 7FE320 vs port, epsilon / NaN / marker boundaries), capacity/error behaviour, lifecycle misuse, parallel independent
// workspaces (threads, own storage each), and a resumable round-robin owner-thread seam driver.
//
//   native_path_workspace_oracle.exe <Napoleon.exe> [cases=N] [seed=S] [family=name] [case=K] [threads=T] [verbose=1]
// Exit 0 only if every comparison is identical, every plumbing assertion holds and no family has zero solves.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include "native_image_relocation.h"
#include "native_path_workspace.h"

#pragma comment(lib, "bcrypt.lib")
#ifndef _M_IX86
#error x86 only
#endif

namespace pw = ntw_path_workspace;
using pw::Entry;
using pw::Graph;
using pw::Node;

// ---------------------------------------------------------------------------------------------------------------------
// original addresses (preferred base 0x400000)
static const uintptr_t VA_CTOR = 0x7EB020;        // thiscall(G; &root) ret 4
static const uintptr_t VA_SOLVE = 0x8026F0;       // thiscall(G; query, start, goal, via, flag) ret 0x14
static const uintptr_t VA_ENGINE = 0x802A80;      // thiscall(S=G+8; out, start, goal, float limit) ret 0x10
static const uintptr_t VA_SUCC = 0x800210;        // thiscall(G; node, neighbours, arenaB) ret 0xC
static const uintptr_t VA_SEED = 0x7EB210;        // thiscall(node; &root, G, query, posobj, float) ret 0x14
static const uintptr_t VA_EQ = 0x7ED270;          // thiscall(a; b) ret 4 -> al
static const uintptr_t VA_REGION = 0x7FE320;      // stdcall(query, a, b) -> al
static const uintptr_t VA_ARENA_ALLOC = 0x80B0F0; // thiscall(arena; size, shift) ret 8
static const uintptr_t VA_FIND = 0x807AF0;        // thiscall(hash; &keyPtr) ret 4 -> &row.value | 0
static const uintptr_t VA_PUSHVEC = 0x448B90;     // thiscall(vec; &value) ret 4
static const uintptr_t VA_ALLOC = 0xFF7F20, VA_FREE = 0xFF7EF0, VA_AALLOC = 0x1271290, VA_AFREE = 0x1271276, VA_CSINIT = 0x4C3920;
static const uintptr_t VA_GRAPH_VTABLE = 0x1347250;

static uintptr_t g_image_delta;
static void* native_ptr(uintptr_t preferred) { return reinterpret_cast<void*>(preferred + g_image_delta); }

// thiscall == fastcall with an ignored edx (callee pops the stack arguments in both)
typedef void*(__fastcall* ThisFn1)(void*, void*, uint32_t);
typedef void*(__fastcall* ThisFn2)(void*, void*, uint32_t, uint32_t);
typedef uint32_t(__fastcall* SolveFn)(void*, void*, const void*, void*, void*, void*, uint32_t);
typedef uint8_t(__stdcall* RegionFn)(const void*, const void*, const void*);

static inline uint32_t bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static inline float fbits(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }

// ---------------------------------------------------------------------------------------------------------------------
// host heap replacing the game / CRT allocators inside the private image; canary red zones around every block
static uint8_t* g_heap;
static size_t g_heapOff, g_heapCap = 192u << 20;
struct Blk { size_t user, size, rounded; };
static std::vector<Blk> g_blk;
static const size_t kRed = 32;
static void* __cdecl host_alloc(size_t size, void*) {
    size_t off = (g_heapOff + 15) & ~size_t(15);
    size_t rounded = (size + 15) & ~size_t(15);
    if (off + kRed + rounded + kRed > g_heapCap) { std::fputs("host heap exhausted\n", stderr); std::exit(3); }
    std::memset(g_heap + off, 0xAB, kRed);
    std::memset(g_heap + off + kRed, 0xCD, size);
    std::memset(g_heap + off + kRed + size, 0xAB, rounded - size + kRed);
    g_blk.push_back({off + kRed, size, rounded});
    g_heapOff = off + kRed + rounded + kRed;
    return g_heap + off + kRed;
}
static void __cdecl host_free(void*) {}
static void* __cdecl host_aligned_alloc(size_t size, size_t) { return host_alloc(size, nullptr); }
static void heap_reset() { g_heapOff = 0; g_blk.clear(); }
static bool heap_canaries_ok() {
    for (const Blk& b : g_blk) {
        const uint8_t* f = g_heap + b.user - kRed;
        for (size_t i = 0; i < kRed; ++i) if (f[i] != 0xAB) return false;
        const uint8_t* t = g_heap + b.user + b.size;
        for (size_t i = 0; i < b.rounded - b.size + kRed; ++i) if (t[i] != 0xAB) return false;
    }
    return true;
}
static void patch_jmp(uintptr_t preferred, void* target) {
    uint8_t* p = static_cast<uint8_t*>(native_ptr(preferred));
    p[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target) - (reinterpret_cast<uintptr_t>(p) + 5));
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
struct Rng {
    std::mt19937_64 g;
    explicit Rng(uint64_t s) : g(s) {}
    uint32_t u(uint32_t n) { return n ? static_cast<uint32_t>(g() % n) : 0u; }
    uint32_t r(uint32_t a, uint32_t b) { return a + u(b - a + 1); }
    float f(float a, float b) { return std::uniform_real_distribution<float>(a, b)(g); }
    bool p(double pr) { return std::uniform_real_distribution<double>(0.0, 1.0)(g) < pr; }
};
static uint64_t mix64(uint64_t x) { x += 0x9E3779B97F4A7C15ull; x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull; x = (x ^ (x >> 27)) * 0x94D049BB133111EBull; return x ^ (x >> 31); }

// ---------------------------------------------------------------------------------------------------------------------
// host stand-ins for the borrowed game objects the engine reads (offsets per instruction evidence)
struct FxRegionT { uint8_t pad0[0x30]; uint32_t count; const uint32_t* data; uint8_t pad1[0x10]; };      // 809C40: count @+0x30, data @+0x34
struct FxObjectT { uint8_t pad0[0x1C]; uint32_t id; const FxRegionT* region; uint8_t pad1[0x1C]; uint32_t index; uint8_t pad2[0x1C]; };  // hash id @+0x1C, region @+0x20
struct FxSpecialT { uint8_t pad[0xC]; uint32_t token; uint8_t pad2[0x20]; };                                 // 7FE320 uses &special->token (= special+0xC)
struct FxQueryT { uint8_t pad0[0x2C]; float radius; uint32_t pad30; const FxSpecialT* special; uint8_t pad2[0x40]; };   // special @+0x34
static_assert(offsetof(FxRegionT, count) == 0x30 && offsetof(FxRegionT, data) == 0x34, "region");
static_assert(offsetof(FxObjectT, id) == 0x1C && offsetof(FxObjectT, region) == 0x20, "object");
static_assert(offsetof(FxSpecialT, token) == 0xC, "special");
static_assert(offsetof(FxQueryT, special) == 0x34, "query");

struct FxEdge {
    uint32_t target;
    float pos[3];
    float aux14, scale, acc;
    uint32_t aux28;
    uint8_t flag18, flag19, marker, special;
};
struct FxWorld {
    std::vector<FxObjectT> objects;
    std::vector<FxRegionT> regions;
    std::vector<std::vector<uint32_t>> tokens;
    std::vector<std::vector<FxEdge>> edges;
    FxQueryT query{};
    FxSpecialT special{};
    std::vector<std::array<float, 3>> centres;
    bool querySpecial = false;
};

static void fill_node(Node* n, Graph* g, const FxObjectT* o, const float* pos, uint32_t tag, float aux14, uint8_t f18, uint8_t f19,
                      uint8_t marker, uint32_t aux28, float scale, float acc, const void* q) {
    std::memset(n, 0, sizeof(*n));
    n->object = o;
    n->x = pos[0]; n->y = pos[1]; n->z = pos[2];
    n->tag = tag;
    n->aux14 = aux14;
    n->flag18 = f18;
    n->flag19 = f19;
    n->graph = g;
    n->query = q;
    n->goalMarker = marker;
    n->aux28 = aux28;
    n->scale = scale;
    n->accumulated = acc;
}

// The neighbour generator, same behavioural contract as the shape of 0x800210 (direct-goal node, back-edge skip, region and
// flag gating, node allocation from arena B, duplicate suppression only once [G+0xE4] >= 500, push into G+0x20).  Ops binds it
// either to the ORIGINAL native helpers (native side) or to the Workspace API (port side).
template <class Ops>
static void fixture_successor(Graph* g, Node* parent, Ops& ops, const FxWorld& W) {
    const uint32_t counter = g->expansions;
    const FxObjectT* po = static_cast<const FxObjectT*>(parent->object);
    Node* goal = g->goal;
    if (goal != nullptr && parent->object == goal->object) {
        Node* n = ops.alloc();
        if (!n) return;
        fill_node(n, g, po, g->goalPos, 0, 0.0f, goal->flag18 == 1 ? 1 : 0, 0, 0, 0, parent->scale, 0.0f, parent->query);
        ops.push(n);
        return;
    }
    for (const FxEdge& e : W.edges[po->index]) {
        if (!(g->flag124 == 1 || e.special == 1)) continue;
        if (parent->tag != 0 && e.target == parent->tag - 1) continue;
        const FxObjectT* to = &W.objects[e.target];
        if (!(po->region == to->region || g->regionFlag == 1)) continue;
        Node* n = ops.alloc();
        if (!n) return;
        fill_node(n, g, to, e.pos, po->index + 1, e.aux14, e.flag18, e.flag19, e.marker, e.aux28, e.scale, e.acc, parent->query);
        if (counter < pw::kHeuristicSwitch || ops.find(n) == nullptr) ops.push(n);
    }
}

// native side ops: ORIGINAL 0x80B0F0 (arena B), 0x807AF0, 0x448B90
struct NativeOps {
    Graph* g;
    Node* alloc() { return static_cast<Node*>(reinterpret_cast<ThisFn2>(native_ptr(VA_ARENA_ALLOC))(&g->nodes, nullptr, pw::kNodeBytes, pw::kArenaShift)); }
    Entry* find(Node* n) {
        Node* key = n;
        void* p = reinterpret_cast<ThisFn1>(native_ptr(VA_FIND))(&g->hash, nullptr, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&key)));
        return p ? *static_cast<Entry**>(p) : nullptr;
    }
    void push(Node* n) {
        Node* v = n;
        reinterpret_cast<ThisFn1>(native_ptr(VA_PUSHVEC))(&g->neighbors, nullptr, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&v)));
    }
};
struct PortOps {
    pw::Workspace& ws;
    Node* alloc() { return ws.AllocNode(); }
    Entry* find(Node* n) { return ws.FindEntry(n); }
    void push(Node* n) { ws.PushNeighbor(n); }
};

static const FxWorld* g_hostWorld;
static float g_viaPos[3], g_viaScale;
static void __fastcall host_successor(Graph* g, void*, Node* node, void* /*neighbours (== &g->neighbors)*/, void* /*arena B (== &g->nodes)*/) {
    NativeOps ops{g};
    fixture_successor(g, node, ops, *g_hostWorld);
}
static Node* __fastcall host_seed(Node* node, void*, void* /*&G.root*/, Graph* g, const void* q, const void* posobj, float /*query radius*/) {
    fill_node(node, g, static_cast<const FxObjectT*>(posobj), g_viaPos, 0, 0.0f, 0, 0, 0, 0, g_viaScale, 0.0f, q);
    return node;
}

// ---------------------------------------------------------------------------------------------------------------------
// scenarios
struct SolveSpec {
    uint32_t start = 0, goal = 0;
    int32_t via = -1;
    float spos[3]{}, gpos[3]{}, vpos[3]{};
    float sscale = 1.0f, sacc = 0.0f, gscale = 1.0f, vscale = 1.0f;
    uint8_t goalMarker = 0, flag124 = 0, overwrite = 0;
    float costLimit = 0.0f;
    bool bare = false;
    uint32_t expLimit = pw::kDefaultExpansionLimit;
};
struct CaseSpec {
    const char* family = "";
    uint32_t index = 0;
    uint64_t seed = 0;
    std::unique_ptr<FxWorld> world;
    std::vector<SolveSpec> solves;
};

struct WorldParams {
    uint32_t n = 20, maxDeg = 3, regions = 1, idRange = 0;   // idRange 0 = unique ids, 1 = all equal, k>1 = random in [0,k)
    float box = 200.0f, pSpecial = 0.8f, pMarker = 0.0f, pDup = 0.0f, pNear = 0.0f, pBack = 0.0f, pToken = 0.5f;
    bool chain = true, querySpecial = false, hostile = false;
};

static void build_world(FxWorld& W, Rng& rng, const WorldParams& P) {
    const uint32_t n = P.n + 1;                   // last object: isolated (no incoming edge) for unreachable goals
    W.objects.assign(n, FxObjectT{});
    W.regions.assign(P.regions, FxRegionT{});
    W.tokens.assign(P.regions, {});
    W.edges.assign(n, {});
    W.centres.assign(n, {});
    W.querySpecial = P.querySpecial;
    std::memset(&W.query, 0, sizeof(W.query));
    std::memset(&W.special, 0, sizeof(W.special));
    W.special.token = 0xC0FFEE;
    W.query.radius = 1.0f;
    W.query.special = P.querySpecial ? &W.special : nullptr;
    const uint32_t token = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&W.special.token));
    for (uint32_t r = 0; r < P.regions; ++r)
        if (P.querySpecial && rng.p(P.pToken)) W.tokens[r].push_back(token);
        else W.tokens[r].push_back(0x1000u + r);
    for (uint32_t r = 0; r < P.regions; ++r) {
        W.regions[r].count = static_cast<uint32_t>(W.tokens[r].size());
        W.regions[r].data = W.tokens[r].data();
    }
    for (uint32_t i = 0; i < n; ++i) {
        FxObjectT& o = W.objects[i];
        o.index = i;
        o.id = P.idRange == 0 ? static_cast<uint32_t>(mix64(i * 7919ull + 13)) : (P.idRange == 1 ? 7u : rng.u(P.idRange));
        o.region = &W.regions[rng.u(P.regions)];
        W.centres[i] = {rng.f(0, P.box), rng.f(0, 5), rng.f(0, P.box)};
    }
    for (uint32_t i = 0; i < P.n; ++i) {
        const uint32_t deg = rng.r(1, P.maxDeg);
        for (uint32_t d = 0; d < deg; ++d) {
            uint32_t t;
            if (P.chain && d == 0) t = (i + 1) % P.n;
            else if (rng.p(0.6)) t = (i + rng.r(1, 20)) % P.n;
            else t = rng.u(P.n);
            if (t == i) t = (i + 1) % P.n;
            FxEdge e{};
            e.target = t;
            for (int k = 0; k < 3; ++k) {
                const float a = W.centres[i][k], b = W.centres[t][k];
                e.pos[k] = a + (b - a) * rng.f(0.3f, 0.7f);
            }
            e.aux14 = rng.f(0.0f, 4.0f);
            e.scale = rng.f(0.5f, 3.0f);
            e.acc = rng.f(0.0f, 4.0f);
            if (P.hostile) {
                if (rng.p(0.25)) e.scale = rng.f(-1.0f, 0.2f);
                if (rng.p(0.03)) e.acc = std::numeric_limits<float>::quiet_NaN();
                if (rng.p(0.02)) e.scale = std::numeric_limits<float>::infinity();
            }
            e.aux28 = rng.u(1000);
            e.flag18 = rng.p(0.2) ? 1 : 0;
            e.flag19 = rng.p(0.1) ? 1 : 0;
            e.marker = rng.p(P.pMarker) ? 1 : 0;
            e.special = rng.p(P.pSpecial) ? 1 : 0;
            W.edges[i].push_back(e);
            if (rng.p(P.pDup)) {
                FxEdge d2 = e;
                for (int k = 0; k < 3; ++k) d2.pos[k] += rng.f(-0.004f, 0.004f);
                W.edges[i].push_back(d2);
            }
            if (rng.p(P.pNear)) {
                FxEdge d3 = e;
                d3.pos[0] += rng.f(0.011f, 0.03f);
                W.edges[i].push_back(d3);
            }
            if (rng.p(P.pBack) && t != i) {
                FxEdge b = e;
                b.target = i;
                W.edges[t].push_back(b);
            }
        }
    }
}

static void pick_solve(SolveSpec& s, const FxWorld& W, Rng& rng, uint32_t n, bool unreachable) {
    s.start = rng.u(n);
    do { s.goal = rng.u(n); } while (s.goal == s.start);
    if (unreachable) s.goal = n;                 // the isolated object
    for (int k = 0; k < 3; ++k) {
        s.spos[k] = W.centres[s.start][k];
        s.gpos[k] = W.centres[s.goal][k];
    }
    s.sscale = rng.f(0.5f, 2.5f);
    s.sacc = rng.p(0.5) ? 0.0f : rng.f(0.0f, 3.0f);
    s.gscale = 1.0f;
}

struct FamilyDef { const char* name; };
static const FamilyDef kFamilies[] = {{"small"}, {"medium"}, {"dense"}, {"collide"}, {"marker"}, {"via"}, {"bare"}, {"overwrite"}, {"reuse"}, {"hostile"}, {"region"}};

static bool make_case(CaseSpec& C, const char* family, uint32_t index, uint64_t seed) {
    C.family = family;
    C.index = index;
    C.solves.clear();
    C.seed = mix64(seed ^ (std::hash<std::string>()(family) * 31ull + index));
    Rng rng(C.seed);
    C.world.reset(new FxWorld());
    WorldParams P;
    const std::string f = family;
    uint32_t nSolves = 1;
    bool unreachable = false;
    if (f == "small") { P.n = rng.r(4, 30); P.maxDeg = 3; P.regions = rng.r(1, 3); P.pBack = 0.2f; }
    else if (f == "medium") { P.n = rng.r(60, 250); P.maxDeg = 5; P.regions = 2; P.idRange = rng.p(0.5) ? 40 : 0; P.pDup = 0.1f; P.pNear = 0.05f; P.pBack = 0.3f; unreachable = rng.p(0.2); }
    else if (f == "dense") { P.n = rng.r(400, 1200); P.maxDeg = 6; P.regions = 2; P.chain = rng.p(0.5); P.pBack = 0.3f; unreachable = rng.p(0.4); }
    else if (f == "collide") { P.n = rng.r(80, 300); P.maxDeg = 5; P.idRange = rng.p(0.5) ? 1 : 3; P.pDup = 0.2f; P.pNear = 0.1f; P.pBack = 0.3f; unreachable = rng.p(0.3); }
    else if (f == "marker") { P.n = rng.r(10, 120); P.maxDeg = 4; P.regions = 3; P.querySpecial = true; P.pMarker = 0.15f; P.pBack = 0.3f; }
    else if (f == "via") { P.n = rng.r(10, 200); P.maxDeg = 4; P.regions = rng.r(1, 3); P.pBack = 0.3f; P.pDup = 0.05f; }
    else if (f == "bare") { P.n = rng.r(30, 400); P.maxDeg = 5; P.regions = 2; P.pBack = 0.3f; P.idRange = rng.p(0.4) ? 25 : 0; }
    else if (f == "overwrite") { P.n = rng.r(30, 200); P.maxDeg = 5; P.pDup = 0.3f; P.pNear = 0.1f; P.idRange = 10; P.pBack = 0.3f; }
    else if (f == "reuse") { P.n = rng.r(100, 500); P.maxDeg = 5; P.regions = 2; P.pBack = 0.3f; nSolves = 3; }
    else if (f == "hostile") { P.n = rng.r(10, 80); P.maxDeg = 4; P.hostile = true; P.pBack = 0.4f; P.idRange = rng.p(0.5) ? 5 : 0; }
    else if (f == "region") { P.n = rng.r(20, 150); P.maxDeg = 4; P.regions = 4; P.querySpecial = true; P.pMarker = 0.1f; P.pBack = 0.3f; P.pSpecial = 0.5f; }
    else return false;
    build_world(*C.world, rng, P);
    if (P.hostile) {
        // Negative cycles make native 0x807620 follow cyclic parents until its output allocation exhausts memory.
        // Keep negative/NaN/infinite numeric coverage, but use a DAG so the reference has a finite path to compare.
        for (uint32_t i = 0; i < C.world->edges.size(); ++i) {
            auto& edges = C.world->edges[i];
            edges.erase(std::remove_if(edges.begin(), edges.end(),
                                      [i](const FxEdge& edge) { return edge.target <= i; }), edges.end());
        }
    }
    for (uint32_t k = 0; k < nSolves; ++k) {
        SolveSpec s;
        pick_solve(s, *C.world, rng, P.n, unreachable && k == 0);
        s.flag124 = (f == "small" || f == "region") ? static_cast<uint8_t>(rng.u(2)) : static_cast<uint8_t>(rng.p(0.8) ? 1 : 0);
        if (P.querySpecial && rng.p(0.5)) s.goalMarker = 1;
        if (f == "via" || (f == "region" && rng.p(0.5)) || (f == "marker" && rng.p(0.3))) {
            do { s.via = static_cast<int32_t>(rng.u(P.n)); } while (static_cast<uint32_t>(s.via) == s.start || static_cast<uint32_t>(s.via) == s.goal);
            for (int q = 0; q < 3; ++q) s.vpos[q] = C.world->centres[s.via][q];
            s.vscale = rng.f(0.5f, 2.0f);
        }
        if (f == "bare") {
            s.bare = true;
            s.via = -1;
            static const float limits[] = {-3.0f, 0.0f, 25.0f, 60.0f, 120.0f, 300.0f, 1e9f};
            s.costLimit = limits[rng.u(7)];
            s.expLimit = rng.p(0.5) ? rng.r(5, 400) : pw::kDefaultExpansionLimit;
        }
        if (f == "overwrite") s.overwrite = 1;
        if (f == "dense" && rng.p(0.3)) s.expLimit = rng.r(300, 3000);
        C.solves.push_back(s);
    }
    return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// canonical snapshot of a Graph (identical for native memory and for a Workspace)
struct Rec { const char* tag; uint32_t a, v; };
struct Snap {
    std::vector<Rec> r;
    void add(const char* t, uint32_t a, uint32_t v) { r.push_back({t, a, v}); }
    uint64_t digest() const {
        uint64_t h = 1469598103934665603ull;
        for (const Rec& x : r) {
            h = (h ^ x.v) * 1099511628211ull;
            h = (h ^ x.a) * 1099511628211ull;
            h = (h ^ static_cast<uint8_t>(x.tag[0])) * 1099511628211ull;
        }
        return h;
    }
};
struct IdMap {
    const Graph* g;
    const Node* goal;
    const Node* start;
    std::vector<const uint8_t*> nb, eb;
    IdMap(const Graph* gr, const Node* go, const Node* st) : g(gr), goal(go), start(st) {
        for (const pw::ArenaBlock* b = g->nodes.head; b; b = b->next) { nb.push_back(b->data); if (b == g->nodes.current) break; }
        for (const pw::ArenaBlock* b = g->entries.head; b; b = b->next) { eb.push_back(b->data); if (b == g->entries.current) break; }
    }
    static uint32_t find(const std::vector<const uint8_t*>& v, const void* p) {
        const uint8_t* q = static_cast<const uint8_t*>(p);
        for (size_t i = 0; i < v.size(); ++i)
            if (q >= v[i] && q < v[i] + pw::kBlockData) return static_cast<uint32_t>((i << 16) | static_cast<uint32_t>(q - v[i])) + 1;
        return 0xF00000FFu;
    }
    uint32_t node(const Node* p) const {
        if (!p) return 0;
        if (p == goal) return 0xF0000001u;
        if (p == start) return 0xF0000003u;
        return find(nb, p);
    }
    uint32_t entry(const Entry* p) const { return p ? find(eb, p) : 0; }
};
static void dump_node(Snap& s, const IdMap& m, uint32_t id, const Node* n) {
    s.add("node.object", id, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(n->object)));
    s.add("node.x", id, bits(n->x)); s.add("node.y", id, bits(n->y)); s.add("node.z", id, bits(n->z));
    s.add("node.tag", id, n->tag);
    s.add("node.aux14", id, bits(n->aux14));
    s.add("node.flags", id, n->flag18 | (n->flag19 << 8) | (n->goalMarker << 16) | ((n->graph == m.g ? 1u : 0u) << 24));
    s.add("node.query", id, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(n->query)));
    s.add("node.aux28", id, n->aux28);
    s.add("node.scale", id, bits(n->scale));
    s.add("node.acc", id, bits(n->accumulated));
}
static Snap take(const Graph* g, const Node* goalRole, const Node* startRole, uint32_t resultByte) {
    Snap s;
    IdMap m(g, goalRole, startRole);
    s.add("result", 0, resultByte);
    s.add("g.expansions", 0, g->expansions);
    s.add("g.total", 0, g->totalExpansions);
    s.add("g.limit", 0, g->expansionLimit);
    s.add("g.overwrite", 0, g->overwriteNode);
    s.add("g.goal", 0, m.node(g->goal));
    s.add("g.query", 0, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g->query)));
    for (int i = 0; i < 3; ++i) s.add("g.goalPos", i, bits(g->goalPos[i]));
    for (int i = 0; i < 4; ++i) s.add("g.segment", i, bits(g->segment[i]));
    s.add("g.flags", 0, g->flag124 | (g->regionFlag << 8));
    s.add("g.start", 0, m.node(g->start));
    // arenas: used per live block, then every allocation
    uint32_t bi = 0;
    for (const pw::ArenaBlock* b = g->nodes.head; b; b = b->next, ++bi) {
        s.add("arenaB.used", bi, b->used);
        for (uint32_t k = 0; k < b->used / (pw::kNodeBytes + 4); ++k) {
            const Node* n = reinterpret_cast<const Node*>(b->data + k * (pw::kNodeBytes + 4));
            dump_node(s, m, IdMap::find(m.nb, n), n);
        }
        if (b == g->nodes.current) break;
    }
    s.add("arenaB.live", 0, bi);
    bi = 0;
    for (const pw::ArenaBlock* b = g->entries.head; b; b = b->next, ++bi) {
        s.add("arenaA.used", bi, b->used);
        for (uint32_t k = 0; k < b->used / (pw::kEntryBytes + 4); ++k) {
            const Entry* e = reinterpret_cast<const Entry*>(b->data + k * (pw::kEntryBytes + 4));
            const uint32_t id = IdMap::find(m.eb, e);
            s.add("entry.node", id, m.node(e->node));
            s.add("entry.state", id, e->state);
            s.add("entry.parent", id, m.entry(e->parent));
            s.add("entry.g", id, bits(e->g));
            s.add("entry.h", id, bits(e->h));
        }
        if (b == g->entries.current) break;
    }
    s.add("arenaA.live", 0, bi);
    s.add("open.size", 0, g->open.size);
    for (uint32_t i = 0; i < g->open.size; ++i) s.add("open", i, m.entry(static_cast<Entry* const*>(g->open.data)[i]));
    s.add("neigh.size", 0, g->neighbors.size);
    for (uint32_t i = 0; i < g->neighbors.size; ++i) s.add("neigh", i, m.node(static_cast<Node* const*>(g->neighbors.data)[i]));
    s.add("out.size", 0, g->output.size);
    for (uint32_t i = 0; i < g->output.size; ++i) s.add("out", i, m.node(static_cast<Node* const*>(g->output.data)[i]));
    s.add("hash.buckets", 0, g->hash.buckets);
    s.add("hash.count", 0, g->hash.count);
    s.add("hash.empty", 0, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g->hash.emptyKey)));
    s.add("hash.head", 0, g->hash.head ? static_cast<uint32_t>(g->hash.head - g->hash.rows) : 0xFFFFFFFFu);
    for (uint32_t i = 0; i < g->hash.buckets; ++i) {
        const pw::HashRow& r = g->hash.rows[i];
        if (!r.key) continue;
        s.add("hrow.key", i, m.node(r.key));
        s.add("hrow.val", i, m.entry(r.value));
        s.add("hrow.next", i, r.next ? static_cast<uint32_t>(r.next - g->hash.rows) : 0xFFFFFFFFu);
    }
    return s;
}
static uint32_t compare_snaps(const Snap& a, const Snap& b, std::string& why) {
    const size_t n = std::min(a.r.size(), b.r.size());
    for (size_t i = 0; i < n; ++i) {
        const Rec &x = a.r[i], &y = b.r[i];
        if (std::strcmp(x.tag, y.tag) != 0 || x.a != y.a || x.v != y.v) {
            char buf[256];
            std::snprintf(buf, sizeof(buf), "record %zu: native %s[%u]=%08x  port %s[%u]=%08x", i, x.tag, x.a, x.v, y.tag, y.a, y.v);
            why = buf;
            return 1;
        }
    }
    if (a.r.size() != b.r.size()) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "record count native %zu port %zu", a.r.size(), b.r.size());
        why = buf;
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------------------------------
// native runner
struct NativeCtx {
    Graph* g = nullptr;
    uint32_t rootVar = 0;
    Node* start = nullptr;
    Node* goal = nullptr;
    bool init() {
        uint8_t* gm = static_cast<uint8_t*>(host_alloc(sizeof(Graph), nullptr));
        g = reinterpret_cast<Graph*>(gm);
        start = static_cast<Node*>(host_alloc(sizeof(Node), nullptr));
        goal = static_cast<Node*>(host_alloc(sizeof(Node), nullptr));
        rootVar = 0x12345678;
        reinterpret_cast<ThisFn1>(native_ptr(VA_CTOR))(g, nullptr, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&rootVar)));
        return g->self == g && g->vtable == VA_GRAPH_VTABLE + g_image_delta && g->expansionLimit == pw::kDefaultExpansionLimit
               && g->hash.buckets == pw::kHashLevel0Buckets && g->open.capacity == 0x80 && g->neighbors.capacity == 8
               && g->entries.threadMode == 0 && g->nodes.threadMode == 0;
    }
};
struct NativeCall {
    NativeCtx* c;
    const FxWorld* w;
    const SolveSpec* s;
    uint32_t result;
};
static void do_native_solve(NativeCall* a) {
    NativeCtx& c = *a->c;
    const SolveSpec& s = *a->s;
    const FxWorld& W = *a->w;
    Graph* g = c.g;
    g_hostWorld = &W;
    g->expansionLimit = s.expLimit;
    g->overwriteNode = s.overwrite;
    fill_node(c.start, g, &W.objects[s.start], s.spos, 0, 0.0f, 0, 0, 0, 0, s.sscale, s.sacc, &W.query);
    fill_node(c.goal, g, &W.objects[s.goal], s.gpos, 0, 0.0f, 0, 0, s.goalMarker, 0, s.gscale, 0.0f, &W.query);
    g_viaPos[0] = s.vpos[0]; g_viaPos[1] = s.vpos[1]; g_viaPos[2] = s.vpos[2];
    g_viaScale = s.vscale;
    if (!s.bare) {
        void* via = s.via >= 0 ? static_cast<void*>(const_cast<FxObjectT*>(&W.objects[s.via])) : nullptr;
        a->result = reinterpret_cast<SolveFn>(native_ptr(VA_SOLVE))(g, nullptr, &W.query, c.start, c.goal, via, s.flag124) & 0xFF;
    } else {
        // 8026F0 direct-branch prologue, then the bare engine 802A80
        g->expansions = 0;
        g->output.size = 0;
        g->flag124 = s.flag124;
        g->goal = c.goal;
        g->query = &W.query;
        g->goalPos[0] = c.goal->x; g->goalPos[1] = c.goal->y; g->goalPos[2] = c.goal->z;
        g->segment[0] = c.start->x; g->segment[1] = c.start->z; g->segment[2] = c.goal->x; g->segment[3] = c.goal->z;
        g->regionFlag = reinterpret_cast<RegionFn>(native_ptr(VA_REGION))(&W.query, c.start, c.goal);
        // 802A80 returns the 7E04D0 result in al
        typedef uint32_t(__fastcall * EngineFnRet)(void*, void*, void*, void*, void*, float);
        a->result = reinterpret_cast<EngineFnRet>(native_ptr(VA_ENGINE))(reinterpret_cast<uint8_t*>(g) + 8, nullptr, &g->output, c.start, c.goal, s.costLimit) & 0xFF;
    }
}
static bool guarded_native_solve(NativeCall* a) {
    __try { do_native_solve(a); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------------------------------------------------------------------------------------------------------------
// port runner
static pw::Config big_config() {
    pw::Config c;
    c.openCapacity = 40000;
    c.neighborCapacity = 512;
    c.outputCapacity = 8192;
    c.entryBlocks = 128;
    c.nodeBlocks = 512;
    c.hashLevels = 9;
    return c;
}
struct PortCtx { const FxWorld* w; uint32_t maxNeigh = 0; uint32_t maxOpen = 0; };
static pw::Result port_successor(void* user, pw::Workspace& ws, Node* parent) {
    PortCtx* c = static_cast<PortCtx*>(user);
    PortOps ops{ws};
    fixture_successor(&ws.graph(), parent, ops, *c->w);
    c->maxNeigh = std::max(c->maxNeigh, ws.graph().neighbors.size);
    return pw::Result::kOk;
}
struct PortRunner {
    void* mem = nullptr;
    size_t bytes = 0;
    pw::Workspace ws;
    pw::Config cfg;
    ~PortRunner() { ws.Shutdown(); if (mem) _aligned_free(mem); }
    bool init(const pw::Config& c) {
        ws.Shutdown();
        if (mem) { _aligned_free(mem); mem = nullptr; }
        cfg = c;
        bytes = pw::Workspace::RequiredBytes(c);
        if (!bytes) return false;
        mem = _aligned_malloc(bytes, 64);
        return mem && ws.Init(mem, bytes, c) == pw::Result::kOk;
    }
    bool reinit() { ws.Shutdown(); return ws.Init(mem, bytes, cfg) == pw::Result::kOk; }
    pw::Result begin(const FxWorld& W, const SolveSpec& s) {
        Graph& g = ws.graph();
        g.expansionLimit = s.expLimit;
        g.overwriteNode = s.overwrite;
        Node* st = ws.StartSeed();
        Node* go = ws.GoalSeed();
        fill_node(st, &g, &W.objects[s.start], s.spos, 0, 0.0f, 0, 0, 0, 0, s.sscale, s.sacc, &W.query);
        fill_node(go, &g, &W.objects[s.goal], s.gpos, 0, 0.0f, 0, 0, s.goalMarker, 0, s.gscale, 0.0f, &W.query);
        Node* via = nullptr;
        if (s.via >= 0) {
            via = ws.ViaSeed();
            fill_node(via, &g, &W.objects[s.via], s.vpos, 0, 0.0f, 0, 0, 0, 0, s.vscale, 0.0f, &W.query);
        }
        pw::SolveRequest r;
        r.query = &W.query;
        r.start = st;
        r.goal = go;
        r.via = via;
        r.flag124 = s.flag124;
        r.regionFlagLeg1 = pw::RegionCrossFlag(&W.query, st, via ? via : go);
        r.regionFlagLeg2 = via ? pw::RegionCrossFlag(&W.query, via, go) : 0;
        r.costLimit = s.costLimit;
        r.bareEngine = s.bare;
        return ws.Begin(r);
    }
    pw::Result run(const FxWorld& W, PortCtx* ctx) {
        ctx->w = &W;
        return ws.Run(&port_successor, ctx);
    }
    Snap snap() {
        const uint32_t res = ws.LastResult() == pw::Result::kFound ? 1u : 0u;
        return take(&ws.graph(), ws.GoalSeed(), ws.StartSeed(), res);
    }
};

// ---------------------------------------------------------------------------------------------------------------------
struct Stats {
    uint32_t cases = 0, solves = 0, mismatches = 0, plumbing = 0, found = 0, limited = 0, nopath = 0, records = 0, skipped = 0, regrown = 0, vias = 0;
};
static bool g_verbose;

static void run_case_diff(const CaseSpec& C, Stats& st) {
    ++st.cases;
    heap_reset();
    NativeCtx nc;
    if (!nc.init()) { std::printf("PLUMBING %s #%u: native ctor produced an unexpected G\n", C.family, C.index); ++st.plumbing; return; }
    PortRunner pr;
    if (!pr.init(big_config())) { std::printf("PLUMBING %s #%u: port init failed\n", C.family, C.index); ++st.plumbing; return; }
    for (size_t k = 0; k < C.solves.size(); ++k) {
        const SolveSpec& s = C.solves[k];
        ++st.solves;
        if (s.via >= 0) ++st.vias;
        NativeCall nat{&nc, C.world.get(), &s, 0};
        if (!guarded_native_solve(&nat)) { std::printf("PLUMBING %s #%u/%zu: native code faulted\n", C.family, C.index, k); ++st.plumbing; return; }
        const bool canaryOk = heap_canaries_ok();
        const Snap sn = take(nc.g, nc.goal, nc.start, nat.result);
        PortCtx pctx;
        pw::Result pr0 = pr.begin(*C.world, s);
        pw::Result res = pr0 == pw::Result::kOk ? pr.run(*C.world, &pctx) : pr0;
        if (pw::IsError(res)) {
            std::printf("MISMATCH %s #%u/%zu seed=%016llx: port reported %s (native result %u)\n", C.family, C.index, k, (unsigned long long)C.seed, pw::ResultName(res), nat.result);
            ++st.mismatches;
            return;
        }
        const char* why = nullptr;
        if (!pr.ws.Validate(&why)) { std::printf("PLUMBING %s #%u/%zu: port Validate failed: %s\n", C.family, C.index, k, why ? why : "?"); ++st.plumbing; return; }
        if (!canaryOk) {
            // native touched memory outside its own buffers (UB inside the original on hostile numeric input): not comparable
            if (std::strcmp(C.family, "hostile") == 0) { ++st.skipped; continue; }
            std::printf("PLUMBING %s #%u/%zu: native heap canary violated\n", C.family, C.index, k);
            ++st.plumbing;
            return;
        }
        const Snap sp = pr.snap();
        std::string reason;
        if (compare_snaps(sn, sp, reason)) {
            std::printf("MISMATCH %s #%u/%zu seed=%016llx: %s\n", C.family, C.index, k, (unsigned long long)C.seed, reason.c_str());
            ++st.mismatches;
            return;
        }
        st.records += static_cast<uint32_t>(sn.r.size());
        if (res == pw::Result::kFound) ++st.found;
        else if (res == pw::Result::kExpansionLimit) ++st.limited;
        else ++st.nopath;
        if (pr.ws.HashLevel() > 0) ++st.regrown;
        if (g_verbose)
            std::printf("  %s #%u/%zu: %s expansions=%u out=%u hashLevel=%u records=%zu\n", C.family, C.index, k, pw::ResultName(res),
                        pr.ws.Expansions(), pr.ws.OutputCount(), pr.ws.HashLevel(), sn.r.size());
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// equality unit suite: 7ED270 and 7FE320 (original bytes) vs the port helpers
static void run_equality(Stats& st, uint64_t seed, uint32_t count) {
    Rng rng(mix64(seed ^ 0xE0));
    ++st.cases;
    FxWorld W;
    WorldParams P;
    P.n = 12; P.regions = 4; P.querySpecial = true; P.pToken = 0.5f;
    build_world(W, rng, P);
    FxQueryT qPlain{};
    const float eps = pw::kNodeEqualityEpsilon;
    const float base[] = {0.0f, 1.0f, 123.456f, -500.25f, 3000.0f};
    for (uint32_t i = 0; i < count; ++i) {
        Node a, b;
        const float pa[3] = {base[rng.u(5)], base[rng.u(5)], base[rng.u(5)]};
        float pb[3] = {pa[0], pa[1], pa[2]};
        for (int k = 0; k < 3; ++k) {
            switch (rng.u(9)) {
                case 0: break;
                case 1: pb[k] = pa[k] + eps; break;
                case 2: pb[k] = pa[k] - eps; break;
                case 3: pb[k] = std::nextafter(pa[k] + eps, 1e30f); break;
                case 4: pb[k] = std::nextafter(pa[k] - eps, -1e30f); break;
                case 5: pb[k] = pa[k] + 0.02f; break;
                case 6: pb[k] = pa[k] + rng.f(-0.004f, 0.004f); break;
                case 7: pb[k] = std::numeric_limits<float>::quiet_NaN(); break;
                default: pb[k] = std::numeric_limits<float>::infinity(); break;
            }
        }
        const FxObjectT* oa = &W.objects[rng.u(13)];
        const FxObjectT* ob = rng.p(0.7) ? oa : &W.objects[rng.u(13)];
        const FxQueryT* q = rng.p(0.5) ? &W.query : &qPlain;
        fill_node(&a, nullptr, oa, pa, 0, 0, 0, 0, static_cast<uint8_t>(rng.u(2)), 0, 1.0f, 0.0f, q);
        fill_node(&b, nullptr, ob, pb, 0, 0, 0, 0, static_cast<uint8_t>(rng.u(2)), 0, 1.0f, 0.0f, q);
        const uint32_t nat = reinterpret_cast<uint32_t(__fastcall*)(void*, void*, void*)>(native_ptr(VA_EQ))(&a, nullptr, &b) & 0xFF;
        const uint32_t por = pw::NodesEqual(&a, &b) ? 1u : 0u;
        ++st.solves;
        if (nat != por) { std::printf("MISMATCH equality #%u: native %u port %u\n", i, nat, por); ++st.mismatches; return; }
        const uint8_t rn = reinterpret_cast<RegionFn>(native_ptr(VA_REGION))(q, &a, &b);
        const uint8_t rp = pw::RegionCrossFlag(q, &a, &b);
        if (rn != rp) { std::printf("MISMATCH region-flag #%u: native %u port %u\n", i, rn, rp); ++st.mismatches; return; }
        if (nat) ++st.found; else ++st.nopath;
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// path-only digest used where full state is not comparable (after a capacity failure the hash level / arena state differ)
static uint64_t path_digest(pw::Workspace& ws) {
    Snap s;
    const Graph& g = ws.graph();
    IdMap m(&g, ws.GoalSeed(), ws.StartSeed());
    for (uint32_t i = 0; i < ws.OutputCount(); ++i) dump_node(s, m, i, ws.Output()[i]);
    s.add("n", 0, ws.OutputCount());
    return s.digest();
}

struct ManualDrive {
    pw::Result result = pw::Result::kBadState;
    uint32_t peakOpen = 0, peakNeigh = 0, entries = 0, nodes = 0, outCount = 0, hashLevel = 0;
};
// drives Advance() / owner successor by hand through the NeedSuccessors seam, recording peak usage
static ManualDrive manual_drive(PortRunner& pr, const FxWorld& W) {
    ManualDrive d;
    PortCtx ctx;
    ctx.w = &W;
    for (;;) {
        const pw::Result r = pr.ws.Advance();
        // the peak is reached after the relax pushes, i.e. one above the size left by the pop that precedes NeedSuccessors
        d.peakOpen = std::max(d.peakOpen, pr.ws.graph().open.size + (r == pw::Result::kNeedSuccessors ? 1u : 0u));
        if (r != pw::Result::kNeedSuccessors) { d.result = r; break; }
        PortOps ops{pr.ws};
        fixture_successor(&pr.ws.graph(), pr.ws.PendingNode(), ops, W);
        d.peakNeigh = std::max(d.peakNeigh, pr.ws.graph().neighbors.size);
        const pw::Result sealed = pr.ws.SealSuccessors();
        if (sealed != pw::Result::kOk) { d.result = sealed; break; }
    }
    const Graph& g = pr.ws.graph();
    for (const pw::ArenaBlock* b = g.nodes.head; b; b = b->next) { d.nodes += b->used / (pw::kNodeBytes + 4); if (b == g.nodes.current) break; }
    for (const pw::ArenaBlock* b = g.entries.head; b; b = b->next) { d.entries += b->used / (pw::kEntryBytes + 4); if (b == g.entries.current) break; }
    d.outCount = pr.ws.OutputCount();
    d.hashLevel = pr.ws.HashLevel();
    return d;
}

static uint32_t run_capacity(Stats& st, uint64_t seed) {
    uint32_t bad = 0;
    auto fail = [&](const char* what) { std::printf("MISMATCH capacity: %s\n", what); ++bad; };
    // a reachable dense world whose path is long and which exercises every resource
    CaseSpec C;
    for (uint32_t idx = 0;; ++idx) {
        make_case(C, "dense", 9000 + idx, seed);
        PortRunner probe;
        probe.init(big_config());
        probe.begin(*C.world, C.solves[0]);
        const ManualDrive d = manual_drive(probe, *C.world);
        if ((d.result == pw::Result::kFound && d.outCount > 4 && d.entries > 2 * pw::kEntriesPerBlock && d.nodes > 2 * pw::kNodesPerBlock && d.hashLevel >= 2 && d.peakNeigh > 2) || idx > 200) {
            if (d.result != pw::Result::kFound) { fail("could not find a reachable dense case"); return bad; }
            break;
        }
    }
    PortRunner ref;
    ref.init(big_config());
    ref.begin(*C.world, C.solves[0]);
    const ManualDrive refd = manual_drive(ref, *C.world);
    const uint64_t refPath = path_digest(ref.ws);
    struct V { const char* name; pw::Config cfg; pw::Result expect; bool exceeded; };
    std::vector<V> vars;
    { pw::Config c = big_config(); c.openCapacity = std::max(1u, refd.peakOpen - 1); vars.push_back({"open", c, pw::Result::kCapacityOpen, true}); }
    { pw::Config c = big_config(); c.neighborCapacity = 2; vars.push_back({"neighbors", c, pw::Result::kCapacityNeighbors, refd.peakNeigh > 2}); }
    { pw::Config c = big_config(); c.outputCapacity = refd.outCount - 1; vars.push_back({"output", c, pw::Result::kCapacityOutput, true}); }
    { pw::Config c = big_config(); c.entryBlocks = 1; vars.push_back({"entries", c, pw::Result::kCapacityEntries, refd.entries > pw::kEntriesPerBlock}); }
    { pw::Config c = big_config(); c.nodeBlocks = 1; vars.push_back({"nodes", c, pw::Result::kCapacityNodes, refd.nodes > pw::kNodesPerBlock}); }
    { pw::Config c = big_config(); c.hashLevels = 1; vars.push_back({"hash", c, pw::Result::kCapacityHash, refd.hashLevel >= 1}); }
    { pw::Config c = big_config(); c.entryBlocks = (refd.entries + pw::kEntriesPerBlock - 1) / pw::kEntriesPerBlock; c.nodeBlocks = (refd.nodes + pw::kNodesPerBlock - 1) / pw::kNodesPerBlock;
      c.hashLevels = refd.hashLevel + 1; c.neighborCapacity = refd.peakNeigh; c.outputCapacity = refd.outCount; c.openCapacity = refd.peakOpen;
      vars.push_back({"exact-fit", c, pw::Result::kFound, false}); }
    // tiny recovery solve on the same (possibly failed) workspace
    CaseSpec T;
    make_case(T, "small", 1, seed);
    PortRunner tref;
    tref.init(big_config());
    tref.begin(*T.world, T.solves[0]);
    PortCtx tctx;
    tref.run(*T.world, &tctx);
    const pw::Result tinyRes = tref.ws.LastResult();
    const uint64_t tinyPath = path_digest(tref.ws);
    for (const V& v : vars) {
        ++st.solves;
        PortRunner pr;
        if (!pr.init(v.cfg)) { fail("config rejected"); continue; }
        pr.begin(*C.world, C.solves[0]);
        const ManualDrive d = manual_drive(pr, *C.world);
        char msg[160];
        if (v.exceeded) {
            if (d.result != v.expect) { std::snprintf(msg, sizeof(msg), "%s: expected %s got %s", v.name, pw::ResultName(v.expect), pw::ResultName(d.result)); fail(msg); }
            if (pw::IsError(d.result) && pr.ws.Solving()) fail("workspace still solving after a capacity failure");
        } else {
            if (d.result != pw::Result::kFound || path_digest(pr.ws) != refPath) { std::snprintf(msg, sizeof(msg), "%s: within capacity but result %s / path differs", v.name, pw::ResultName(d.result)); fail(msg); }
        }
        const char* why = nullptr;
        if (!pr.ws.Validate(&why)) { std::snprintf(msg, sizeof(msg), "%s: Validate failed after run: %s", v.name, why ? why : "?"); fail(msg); }
        // recovery: the failed workspace accepts a new solve; any pools that fit give the reference path
        if (std::strcmp(v.name, "exact-fit") != 0) {
            const pw::Result b = pr.begin(*T.world, T.solves[0]);
            if (b != pw::Result::kOk && b != pw::Result::kCapacityNodes && b != pw::Result::kCapacityEntries && b != pw::Result::kCapacityOpen && b != pw::Result::kCapacityHash)
                fail("Begin after failure returned unexpected result");
            else if (b == pw::Result::kOk) {
                PortCtx c2;
                const pw::Result r2 = pr.run(*T.world, &c2);
                if (r2 == tinyRes && path_digest(pr.ws) != tinyPath) fail("recovery solve path differs from reference");
                if (pw::IsError(r2) && r2 != pw::Result::kCapacityNeighbors && r2 != pw::Result::kCapacityOutput && r2 != pw::Result::kCapacityOpen
                    && r2 != pw::Result::kCapacityNodes && r2 != pw::Result::kCapacityEntries && r2 != pw::Result::kCapacityHash) fail("recovery solve hit a non-capacity error");
                if (!pw::IsError(r2) && r2 != tinyRes) fail("recovery solve result differs from reference");
            }
        }
        if (g_verbose) std::printf("  capacity %-9s -> %s (expected %s)\n", v.name, pw::ResultName(d.result), v.exceeded ? pw::ResultName(v.expect) : "Found");
    }
    // ---- configuration / lifecycle misuse -----------------------------------------------------------------------------
    { pw::Config c = big_config(); c.openCapacity = 0; if (pw::Workspace::RequiredBytes(c) != 0) fail("zero open capacity accepted"); }
    { pw::Config c = big_config(); c.hashLevels = 0; if (pw::Workspace::RequiredBytes(c) != 0) fail("zero hash levels accepted"); }
    { pw::Config c = big_config(); c.hashLevels = 40; if (pw::Workspace::RequiredBytes(c) != 0) fail("absurd hash levels accepted"); }
    {
        pw::Workspace ws;
        const pw::Config c = big_config();
        alignas(64) static uint8_t tiny[256];
        if (ws.Init(tiny, sizeof(tiny), c) != pw::Result::kBadArgument) fail("undersized storage accepted");
        if (ws.Init(nullptr, 0, c) != pw::Result::kBadArgument) fail("null storage accepted");
        if (ws.Begin(pw::SolveRequest{}) != pw::Result::kBadState) fail("Begin on uninitialised workspace");
        if (ws.Advance() != pw::Result::kBadState) fail("Advance on uninitialised workspace");
        PortRunner pr;
        pr.init(c);
        void* mis = static_cast<uint8_t*>(pr.mem) + 8;
        pw::Workspace ws2;
        if (ws2.Init(mis, pr.bytes - 8, c) != pw::Result::kBadArgument) fail("misaligned storage accepted");
        if (pr.ws.Advance() != pw::Result::kBadState) fail("Advance before Begin");
        if (pr.ws.Init(pr.mem, pr.bytes, c) != pw::Result::kBadState) fail("double Init accepted");
        pw::SolveRequest r;
        if (pr.ws.Begin(r) != pw::Result::kBadArgument) fail("Begin without nodes accepted");
        // foreign node: a seed that belongs to ANOTHER workspace must be rejected
        PortRunner other;
        other.init(c);
        pr.begin(*C.world, C.solves[0]);
        if (pr.ws.Begin(pw::SolveRequest{}) != pw::Result::kBadState) fail("Begin while solving accepted");
        pr.ws.Shutdown();
        if (pr.ws.Advance() != pw::Result::kBadState) fail("Advance after Shutdown");
        if (pr.ws.Initialized()) fail("Initialized after Shutdown");
        PortRunner a2;
        a2.init(c);
        const SolveSpec& s = C.solves[0];
        Node* st0 = other.ws.StartSeed();
        fill_node(st0, &other.ws.graph(), &C.world->objects[s.start], s.spos, 0, 0, 0, 0, 0, 0, 1.0f, 0.0f, &C.world->query);
        Node* go0 = a2.ws.GoalSeed();
        fill_node(go0, &a2.ws.graph(), &C.world->objects[s.goal], s.gpos, 0, 0, 0, 0, 0, 0, 1.0f, 0.0f, &C.world->query);
        pw::SolveRequest fr;
        fr.query = &C.world->query; fr.start = st0; fr.goal = go0;
        if (a2.ws.Begin(fr) != pw::Result::kBadNode) fail("foreign-graph start node accepted");
        // successor failure is reported and preserved, never turned into a path
        PortRunner b2;
        b2.init(c);
        b2.begin(*C.world, C.solves[0]);
        struct F { static pw::Result fn(void*, pw::Workspace&, Node*) { return pw::Result::kBadArgument; } };
        if (b2.ws.Run(&F::fn, nullptr) != pw::Result::kSuccessorFailed || b2.ws.LastCallbackResult() != pw::Result::kBadArgument) fail("callback failure not reported");
        if (b2.ws.LastResult() == pw::Result::kFound) fail("callback failure produced a path");
        // sticky node push error: foreign node pushed from the callback
        PortRunner b3;
        b3.init(c);
        b3.begin(*C.world, C.solves[0]);
        struct G2 { static pw::Result fn(void*, pw::Workspace& ws, Node*) { Node bogus{}; ws.PushNeighbor(&bogus); return pw::Result::kOk; } };
        if (b3.ws.Run(&G2::fn, nullptr) != pw::Result::kBadNode) fail("foreign neighbour push accepted");
    }
    return bad;
}

// ---------------------------------------------------------------------------------------------------------------------
// parallel independent workspaces: every thread owns its workspace; reference digests come from the original native code
struct ParCase { std::unique_ptr<CaseSpec> c; uint64_t nativeDigest = 0; uint64_t portDigest = 0; };

static uint64_t port_digest_for(PortRunner& pr, const CaseSpec& C) {
    pr.reinit();
    uint64_t h = 1469598103934665603ull;
    for (const SolveSpec& s : C.solves) {
        PortCtx ctx;
        pw::Result b = pr.begin(*C.world, s);
        pw::Result r = b == pw::Result::kOk ? pr.run(*C.world, &ctx) : b;
        if (pw::IsError(r)) return 0;
        h = (h ^ pr.snap().digest()) * 1099511628211ull;
    }
    return h;
}

static uint32_t run_parallel(Stats& st, uint64_t seed, uint32_t threads, uint32_t rounds) {
    uint32_t bad = 0;
    std::vector<ParCase> cases;
    static const char* fams[] = {"dense", "collide", "via", "medium", "reuse", "marker"};
    for (uint32_t i = 0; i < 18; ++i) {
        ParCase pc;
        pc.c.reset(new CaseSpec());
        make_case(*pc.c, fams[i % 6], 7000 + i, seed);
        cases.push_back(std::move(pc));
    }
    // native reference digests (sequential, main thread)
    for (ParCase& pc : cases) {
        heap_reset();
        NativeCtx nc;
        nc.init();
        uint64_t h = 1469598103934665603ull;
        bool ok = true;
        for (const SolveSpec& s : pc.c->solves) {
            NativeCall nat{&nc, pc.c->world.get(), &s, 0};
            if (!guarded_native_solve(&nat)) { ok = false; break; }
            h = (h ^ take(nc.g, nc.goal, nc.start, nat.result).digest()) * 1099511628211ull;
        }
        pc.nativeDigest = ok ? h : 0;
    }
    PortRunner seq;
    seq.init(big_config());
    for (ParCase& pc : cases) {
        pc.portDigest = port_digest_for(seq, *pc.c);
        ++st.solves;
        if (pc.nativeDigest == 0 || pc.portDigest != pc.nativeDigest) { std::printf("MISMATCH parallel-reference %s #%u: native %016llx port %016llx\n", pc.c->family, pc.c->index, (unsigned long long)pc.nativeDigest, (unsigned long long)pc.portDigest); ++bad; }
    }
    std::atomic<uint32_t> mism{0}, done{0};
    std::vector<std::thread> pool;
    for (uint32_t t = 0; t < threads; ++t) {
        pool.emplace_back([&, t]() {
            PortRunner pr;                              // own storage, own graph, own arenas: nothing mutable is shared
            if (!pr.init(big_config())) { ++mism; return; }
            for (uint32_t r = 0; r < rounds; ++r)
                for (size_t k = 0; k < cases.size(); ++k) {
                    const ParCase& pc = cases[(k + t * 5 + r) % cases.size()];
                    const uint64_t d = port_digest_for(pr, *pc.c);
                    if (d != pc.nativeDigest) ++mism;
                    ++done;
                }
        });
    }
    for (auto& th : pool) th.join();
    st.solves += done.load();
    if (mism.load()) { std::printf("MISMATCH parallel: %u of %u concurrent runs differ from the native reference\n", mism.load(), done.load()); bad += mism.load(); }
    // resumable owner-thread seam: K workspaces interleaved on ONE thread through Advance()/NeedSuccessors
    {
        std::vector<std::unique_ptr<PortRunner>> rs;
        std::vector<int> state(cases.size(), 0);
        std::vector<uint64_t> acc(cases.size(), 1469598103934665603ull);
        std::vector<size_t> solveIdx(cases.size(), 0);
        for (size_t i = 0; i < cases.size(); ++i) { rs.emplace_back(new PortRunner()); rs.back()->init(big_config()); }
        size_t live = cases.size();
        std::vector<char> started(cases.size(), 0);
        while (live) {
            for (size_t i = 0; i < cases.size(); ++i) {
                if (state[i] == 2) continue;
                const CaseSpec& C = *cases[i].c;
                PortRunner& pr = *rs[i];
                if (!started[i]) {
                    if (pr.begin(*C.world, C.solves[solveIdx[i]]) != pw::Result::kOk) { state[i] = 2; --live; ++bad; continue; }
                    started[i] = 1;
                }
                const pw::Result r = pr.ws.Advance();
                if (r == pw::Result::kNeedSuccessors) {
                    PortOps ops{pr.ws};
                    fixture_successor(&pr.ws.graph(), pr.ws.PendingNode(), ops, *C.world);
                    if (pr.ws.SealSuccessors() != pw::Result::kOk) { state[i] = 2; --live; ++bad; }
                    continue;
                }
                if (pw::IsError(r)) { state[i] = 2; --live; ++bad; continue; }
                acc[i] = (acc[i] ^ pr.snap().digest()) * 1099511628211ull;
                started[i] = 0;
                if (++solveIdx[i] >= C.solves.size()) { state[i] = 2; --live; }
            }
        }
        for (size_t i = 0; i < cases.size(); ++i)
            if (acc[i] != cases[i].nativeDigest) { std::printf("MISMATCH interleaved %s #%u\n", cases[i].c->family, cases[i].c->index); ++bad; }
        st.solves += static_cast<uint32_t>(cases.size());
    }
    return bad;
}

// Borrowed object/query pages are inaccessible during every engine step. This catches accidental reads during
// relaxation, hash growth, goal comparison and leg-2 reseeding; steps run on another thread after the owner seals.
static uint32_t run_snapshot_isolation() {
    constexpr size_t pageBytes = 0x10000;
    auto borrowed = static_cast<uint8_t*>(VirtualAlloc(nullptr, pageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!borrowed) return 1;
    PortRunner pr;
    pw::Config cfg;
    cfg.neighborCapacity = 768;
    if (!pr.init(cfg)) { VirtualFree(borrowed, 0, MEM_RELEASE); return 1; }
    uint32_t bad = 0, steps = 0;
    auto query = borrowed + pageBytes - 64;
    auto make = [&](Node* n, uint32_t index, uint8_t marker) {
        pr.ws.ClearSeed(n);
        n->object = borrowed + index * 64;
        n->query = query;
        n->x = static_cast<float>(index);
        n->scale = index ? 2.0f : 1.0f;
        n->goalMarker = marker;
    };
    for (uint32_t pass = 0; pass < 4 && !bad; ++pass) {
        const uint32_t special = pass & 1;
        std::memcpy(query + pw::kQuerySpecialGoalOffset, &special, 4);
        for (uint32_t i = 0; i <= 602; ++i) {
            const uint32_t hash = i * 257 + pass;
            std::memcpy(borrowed + i * 64 + pw::kObjectHashOffset, &hash, 4);
        }
        make(pr.ws.StartSeed(), 0, 0);
        make(pr.ws.ViaSeed(), 600, 0);
        make(pr.ws.GoalSeed(), 601, 1);
        // With the special rule enabled the final node deliberately has a different object identity from the goal.
        if (special) pr.ws.GoalSeed()->object = borrowed + 602 * 64;
        pw::SolveRequest req;
        req.query = query;
        req.start = pr.ws.StartSeed();
        req.via = pr.ws.ViaSeed();
        req.goal = pr.ws.GoalSeed();
        if (pr.ws.Begin(req) != pw::Result::kOk) { ++bad; break; }
        pw::Result result = pw::Result::kBadState;
        for (uint32_t wave = 0; wave < 4; ++wave) {
            DWORD previous = 0;
            if (!VirtualProtect(borrowed, pageBytes, PAGE_NOACCESS, &previous)) { ++bad; break; }
            std::thread worker([&] { result = pr.ws.Advance(); });
            worker.join();
            ++steps;
            DWORD ignored = 0;
            if (!VirtualProtect(borrowed, pageBytes, previous, &ignored)) { ++bad; break; }
            if (result != pw::Result::kNeedSuccessors) break;
            const float parent = pr.ws.PendingNode()->x;
            if (parent != 0.0f && parent != 600.0f) { ++bad; break; }
            const uint32_t first = parent == 0.0f ? 1 : 601;
            const uint32_t last = parent == 0.0f ? 600 : 601;
            for (uint32_t i = first; i <= last; ++i) {
                Node* n = pr.ws.AllocNode();
                if (!n) { ++bad; break; }
                make(n, i, i == 601 ? 1 : 0);
                if (!pr.ws.PushNeighbor(n)) { ++bad; break; }
            }
            // An unsealed batch must not run or silently borrow game memory.
            if (pr.ws.Advance() != pw::Result::kBadState) { ++bad; break; }
            if (pr.ws.SealSuccessors() != pw::Result::kOk) { ++bad; break; }
            if (bad) break;
        }
        if (result != pw::Result::kFound || pr.ws.OutputCount() != 3 || pr.ws.HashLevel() < 3
            || pr.ws.graph().entries.current == pr.ws.graph().entries.head
            || !pr.ws.Validate()) { ++bad; break; }
        const float expected[] = {0.0f, 600.0f, 601.0f};
        for (uint32_t i = 0; i < 3; ++i) if (pr.ws.Output()[i]->x != expected[i]) ++bad;
    }
    VirtualFree(borrowed, 0, MEM_RELEASE);
    std::printf("ISOLATION protected-source solves=4 worker-steps=%u failures=%u storage=%zu\n", steps, bad, pr.bytes);
    return bad;
}

// ---------------------------------------------------------------------------------------------------------------------
static bool check_constants() {
    bool ok = true;
    const float eps = *static_cast<const float*>(native_ptr(0x1318034));
    const float lin = *static_cast<const float*>(native_ptr(0x131A7B8));
    ok &= bits(eps) == bits(pw::kNodeEqualityEpsilon);
    ok &= bits(lin) == bits(pw::kHeuristicLinearScale);
    const pw::Constants k;
    const float* s = static_cast<const float*>(native_ptr(0x150FCA0));
    ok &= bits(s[0]) == bits(k.sentinelPair[0]) && bits(s[1]) == bits(k.sentinelPair[1]);
    ok &= bits(s[2]) == bits(k.sentinelPos[0]) && bits(s[3]) == bits(k.sentinelPos[1]) && bits(s[4]) == bits(k.sentinelPos[2]);
    std::printf("CONST epsilon=%08x linear=%08x sentinels=%08x,%08x,%08x,%08x,%08x -> %s\n", bits(eps), bits(lin), bits(s[0]), bits(s[1]), bits(s[2]), bits(s[3]), bits(s[4]), ok ? "match" : "DIFFER");
    return ok;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fputs("usage: native_path_workspace_oracle <Napoleon.exe> [cases=N] [seed=S] [family=name] [case=K] [threads=T] [verbose=1]\n", stderr); return 2; }
    uint32_t cases = 40, onlyCase = 0xFFFFFFFFu, threads = 0;
    uint64_t seed = 20261013;
    std::string only;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind("cases=", 0) == 0) cases = static_cast<uint32_t>(std::strtoul(a.c_str() + 6, nullptr, 10));
        else if (a.rfind("seed=", 0) == 0) seed = std::strtoull(a.c_str() + 5, nullptr, 10);
        else if (a.rfind("family=", 0) == 0) only = a.substr(7);
        else if (a.rfind("case=", 0) == 0) onlyCase = static_cast<uint32_t>(std::strtoul(a.c_str() + 5, nullptr, 10));
        else if (a.rfind("threads=", 0) == 0) threads = static_cast<uint32_t>(std::strtoul(a.c_str() + 8, nullptr, 10));
        else if (a == "verbose=1") g_verbose = true;
    }
    if (!threads) threads = std::max(2u, std::min(8u, std::thread::hardware_concurrency()));
    g_heap = static_cast<uint8_t*>(VirtualAlloc(nullptr, g_heapCap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!g_heap) { std::fputs("host heap alloc failed\n", stderr); return 3; }
    if (!map_image(argv[1])) return 2;
    // private-copy patches only
    patch_jmp(VA_ALLOC, reinterpret_cast<void*>(&host_alloc));
    patch_jmp(VA_FREE, reinterpret_cast<void*>(&host_free));
    patch_jmp(VA_AALLOC, reinterpret_cast<void*>(&host_aligned_alloc));
    patch_jmp(VA_AFREE, reinterpret_cast<void*>(&host_free));
    {
        uint8_t* cs = static_cast<uint8_t*>(native_ptr(VA_CSINIT));
        cs[0] = 0x8B; cs[1] = 0xC1; cs[2] = 0xC3;       // mov eax, ecx ; ret  (InitializeCriticalSectionAndSpinCount via the IAT is not available)
    }
    patch_jmp(VA_SUCC, reinterpret_cast<void*>(&host_successor));
    patch_jmp(VA_SEED, reinterpret_cast<void*>(&host_seed));
    const bool constsOk = check_constants();

    Stats total;
    uint32_t failures = constsOk ? 0 : 1;
    std::vector<std::pair<std::string, Stats>> fams;
    for (const FamilyDef& fd : kFamilies) {
        if (!only.empty() && only != fd.name) continue;
        Stats st;
        for (uint32_t k = 0; k < cases; ++k) {
            if (onlyCase != 0xFFFFFFFFu && k != onlyCase) continue;
            CaseSpec C;
            if (!make_case(C, fd.name, k, seed)) continue;
            run_case_diff(C, st);
        }
        std::printf("FAMILY %s cases=%u solves=%u found=%u limited=%u nopath=%u regrown=%u vias=%u records=%u skipped=%u mismatches=%u plumbing=%u\n", fd.name,
                    st.cases, st.solves, st.found, st.limited, st.nopath, st.regrown, st.vias, st.records, st.skipped, st.mismatches, st.plumbing);
        if (st.solves == 0 || st.mismatches || st.plumbing) ++failures;
        fams.emplace_back(fd.name, st);
    }
    if (only.empty()) {
        Stats se;
        run_equality(se, seed, 20000);
        std::printf("FAMILY equality cases=%u solves=%u found=%u limited=0 nopath=%u regrown=0 vias=0 records=0 skipped=0 mismatches=%u plumbing=0\n", se.cases, se.solves, se.found, se.nopath, se.mismatches);
        if (se.mismatches || se.solves == 0) ++failures;
        Stats sp;
        const uint32_t pbad = run_parallel(sp, seed, threads, 3);
        std::printf("FAMILY parallel cases=18 solves=%u found=0 limited=0 nopath=0 regrown=0 vias=0 records=0 skipped=0 mismatches=%u plumbing=0 threads=%u\n", sp.solves, pbad, threads);
        if (pbad) ++failures;
        Stats sc;
        const uint32_t cbad = run_capacity(sc, seed);
        std::printf("FAMILY capacity cases=1 solves=%u found=0 limited=0 nopath=0 regrown=0 vias=0 records=0 skipped=0 mismatches=%u plumbing=0\n", sc.solves, cbad);
        if (cbad) ++failures;
        if (run_snapshot_isolation()) ++failures;
    }
    std::printf("RESULT %s failures=%u seed=%llu\n", failures ? "FAIL" : "PASS", failures, static_cast<unsigned long long>(seed));
    return failures ? 1 : 0;
}
