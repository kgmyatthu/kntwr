#define _CRT_SECURE_NO_WARNINGS
// Owned-process differential oracle for the native path RUNTIME (src/path/native_path_runtime.{h,cpp}) against the ORIGINAL
// pathfinder driver 0x8026F0 of the approved image (Napoleon.exe, SHA-256 13fcab62...cbad4).
//
// What runs where (everything inside THIS process, on a private relocated copy of the image; the installed EXE, the running
// game, debuggers and injectors are never touched):
//   * the production runtime objects (npr_initialize / npr_stop / npr_prepass / npr_scheduler_hook / npr_end / npr_solve)
//     are linked directly into this executable.  They verify the pinned image spans, plan private searches on a worker
//     team (ntw_pool) with the real ntw_path_workspace engine, run the ORIGINAL successor 0x800210 on private memory
//     after the footprint gate, and materialise consumed results into the real G with the ORIGINAL 0x80B0F0 / 0x448B90.
//   * a REAL native game world is synthesised in caller memory with the exact object shapes the original code reads
//     (battle root/model, height field, topology objects with gateway/plane objects whose virtual tables are the REAL
//     image tables, edges, portal segments, region records, query + request objects, unit locator blocks).  Nothing in
//     the image is patched except the allocator entry points / critical-section initialiser (same private-copy patches
//     as native_path_workspace_oracle), so every pinned span of the runtime's source pin table is pristine.
//   * the reference is the ORIGINAL 0x8026F0 (ctor 0x7EB020, seed builder 0x7EB210, start position 0x816CA0, engine 0x802A80
//     / 0x7E04D0, successor 0x800210 and every helper) running on a second, identically constructed G with identical request
//     bytes.  The original request prefix of the stepper 0x80F5E0 (0x80FF1B..0x8101F5) is reproduced instruction for
//     instruction (see do_prefix) because the real stepper cannot be driven without a complete battle; the generated clone
//     routing (0x57DFEA / 0x81A361 / 0x8101F5 -> npr_*) is NOT exercised here.
//
// Consumer-visible comparison after every solve (canonicalised: node.graph / node.query become roles):
//   result byte, G+4/+8/+0xC, expansions G+0xE4, limit G+0xE8, total G+0x120, G+0xFC/+0x100..+0x11C epilogue words, G+0x124/5,
//   output vector size and EVERY output node field, start/goal seed nodes after the solve.
// Invariants checked around every tick: the prepass never writes a byte of the synthesised world, of pf/G/request memory
// or of the host heap; the query object [q, q+0x58) is bit-identical after the solve; host heap canaries survive.
//
// Scenario families (see make_spec): plain mixed gated via limit overwrite multi (3 requests, inline small batch, hook path),
// stale (readset / start id / edge width / query bytes / flag / start position / sentinel / G limit between prepass and solve),
// sentinel (drift before planning), refuse (special goal, non-allow-listed iface receiver, non-allow-listed gateway receiver,
// kind-1 query, neighbour-capacity miss: all refused BEFORE any original-callback), unused (planned, never consumed),
// persist-cross-tick / persist-cross-stale / persist-evict / persist-cap / persist-reuse / persist-stop / persist-noninputs:
// results held across ticks, consumed bit-identically later, stale inputs fall back, capacity/world-gate refusals retry,
// deterministic query refusals are remembered, bookkeeping changes preserve identity, bounded-walk/queue removals invalidate.
// lifecycle (argument / image / state errors, stop, restart, stopped hooks fall back, shared pool, busy stop, exception unwinding).
// scale: 16 independent requests over a 16x16 serpentine lattice (hundreds of expansions each) in ONE tick, solved by the original
// (timed reference) and by the runtime without workers and then three times on a shared worker team; every consumed result is
// compared with the original, native-vs-runtime times and worker/pool counters are printed (no timing threshold), and worker
// participation (chunks executed off the owner thread) is required on multi-CPU machines.
// Semantic acceptance includes consumption (CONSUMED), stale refusal (STALE), original fallback (FALLBACKS), no successor
// callback for refused requests, and exact persistence/cap/eviction counters in the dedicated multi-tick families.
//
//   native_path_runtime_oracle.exe <Napoleon.exe> [cases=N] [seed=S] [family=name] [verbose=1]
// Exit 0 only if every comparison is identical, every semantic counter expectation holds, no family has zero consumed solves where
// consumption is required and no plumbing assertion failed.
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
#include <cstdarg>
#include <functional>
#include <type_traits>
#include <string>
#include <vector>
#include "native_image_relocation.h"
#include "native_path_runtime.h"
#include "native_path_workspace.h"
#include "native_worker_dispatch.h"

#pragma comment(lib, "bcrypt.lib")
#ifndef _M_IX86
#error x86 only
#endif

namespace pw = ntw_path_workspace;

extern "C" {
uint32_t __stdcall npr_initialize(void* config);
uint32_t __stdcall npr_stop(void* unused);
void __fastcall npr_scheduler_hook(void* pf);
void __fastcall npr_prepass(void* pf);
void __fastcall npr_end(void* pf);
uint32_t __fastcall npr_solve(void* g, void* edx, const void* query, const void* start, void* goal, void* via, uint32_t flag);
extern volatile uint32_t npr_state[NPR_STATE_WORDS];
extern volatile uint32_t npr_storage_bytes;
#ifdef NPR_TIMING
// Diagnostic-only runtime ABI: native callback, footprint gate+record, seal, owner/worker advance,
// unsuccessful owner handoff polls, prepass setup, validate+materialize. Production has no timers.
extern uint64_t npr_timing_ticks[8];
#endif
ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool);
ntw_u32 __stdcall ntw_pool_worker_start(void* param);
}

// ---------------------------------------------------------------------------------------------------------------------
// original addresses (preferred base 0x400000)
static const uintptr_t VA_CTOR = 0x7EB020, VA_SOLVE = 0x8026F0, VA_SEED = 0x7EB210, VA_STARTPOS = 0x816CA0, VA_MARK = 0x814990;
static const uintptr_t VA_RESET = 0x7F71C0;
static const uintptr_t VA_ALLOC = 0xFF7F20, VA_FREE = 0xFF7EF0, VA_AALLOC = 0x1271290, VA_AFREE = 0x1271276, VA_CSINIT = 0x4C3920;
static const uintptr_t VA_SENTINEL = 0x150FCA0;
// real image tables (pinned data words of the runtime's kWords)
static const uintptr_t VA_TOPO_VT = 0x1347260, VA_IFACE_VT = 0x1347248, VA_GATE_VT = 0x133ADD0, VA_EMBED_VT = 0x132B5D8;
static const uintptr_t VA_GW_ZERO = 0x461180, VA_GW_SELF = 0x4470B0;

static uintptr_t g_delta;
static uint32_t N(uintptr_t preferred) { return static_cast<uint32_t>(preferred + g_delta); }

typedef void*(__fastcall* CtorFn)(void*, void*, const void*);
typedef pw::Node*(__fastcall* SeedFn)(void*, void*, const void*, void*, const void*, const void*, float);
typedef void*(__fastcall* StartPosFn)(const void*, void*, void*, void*, void*);
typedef uint32_t(__fastcall* SolveFn)(void*, void*, const void*, void*, void*, void*, uint32_t);
typedef void(__fastcall* Fn0)(void*);

// ---------------------------------------------------------------------------------------------------------------------
// raw 32-bit memory helpers: the synthesised game lives at real 32-bit addresses
static inline void* P(uint32_t a) { return reinterpret_cast<void*>(static_cast<uintptr_t>(a)); }
static inline uint32_t A32(const void* p) { return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p)); }
static inline uint32_t rd32(uint32_t a) { return *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(a)); }
static inline void wr32(uint32_t a, uint32_t v) { *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(a)) = v; }
static inline uint8_t rd8(uint32_t a) { return *reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(a)); }
static inline void wr8(uint32_t a, uint8_t v) { *reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(a)) = v; }
static inline float rdf(uint32_t a) { const uint32_t v = rd32(a); float f; std::memcpy(&f, &v, 4); return f; }
static inline void wrf(uint32_t a, float f) { uint32_t v; std::memcpy(&v, &f, 4); wr32(a, v); }
static inline uint32_t bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }

// ---------------------------------------------------------------------------------------------------------------------
// host heap replacing the game / CRT allocators inside the private image (same patches and canaries as the workspace oracle)
static uint8_t* g_heap;
static size_t g_heapOff, g_heapCap = 48u << 20;
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
    uint8_t* p = static_cast<uint8_t*>(P(N(preferred)));
    p[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target) - (reinterpret_cast<uintptr_t>(p) + 5));
    std::memcpy(p + 1, &rel, 4);
}

// ---------------------------------------------------------------------------------------------------------------------
// image identity + private mapping (identical conventions to native_path_workspace_oracle)
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
    g_delta = reinterpret_cast<uintptr_t>(m) - base;
    if (!RelocateNativeImage(m, size, loaded_nt, g_delta)) { VirtualFree(m, 0, MEM_RELEASE); return false; }
    std::printf("image mapped at %p (delta %08x), sha256 verified\n", static_cast<void*>(m), static_cast<unsigned>(g_delta));
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
// guarded execution: a fault inside original / runtime code is reported as PLUMBING, never as a crash
static DWORD g_excCode;
static uintptr_t g_excAddr;
static int exc_filter(EXCEPTION_POINTERS* ep) {
    g_excCode = ep->ExceptionRecord->ExceptionCode;
    g_excAddr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}
static bool guard_raw(void (*fn)(void*), void* ctx) {
    __try { fn(ctx); return true; }
    __except (exc_filter(GetExceptionInformation())) { return false; }
}
template <class F> static void thunk(void* p) { (*static_cast<F*>(p))(); }
template <class F> static bool guarded(F&& f) { return guard_raw(&thunk<typename std::remove_reference<F>::type>, &f); }
static std::string fault_text() {
    char b[160];
    const uintptr_t img = g_excAddr - g_delta;
    std::snprintf(b, sizeof b, "fault %08lx at %p (preferred-base VA %08x)", g_excCode, reinterpret_cast<void*>(g_excAddr), static_cast<unsigned>(img));
    return b;
}

// ---------------------------------------------------------------------------------------------------------------------
// synthesised game memory.  Two arenas: the IMMUTABLE world (digested; no code may write it unless the test says so) and the
// MUTABLE arena (pathfinders pfA / pfB, requests).
static uint8_t* g_wa; static size_t g_waUsed, g_waFixed;
static uint8_t* g_ma; static size_t g_maUsed, g_maFixed;
static const size_t kWaCap = 4u << 20, kMaCap = 1u << 20;
static uint32_t wnew(size_t n) {
    const size_t off = (g_waUsed + 15) & ~size_t(15);
    if (off + n > kWaCap) { std::fputs("world arena exhausted\n", stderr); std::exit(3); }
    std::memset(g_wa + off, 0, n);
    g_waUsed = off + n;
    return A32(g_wa + off);
}
static uint32_t mnew(size_t n) {
    const size_t off = (g_maUsed + 15) & ~size_t(15);
    if (off + n > kMaCap) { std::fputs("mutable arena exhausted\n", stderr); std::exit(3); }
    std::memset(g_ma + off, 0, n);
    g_maUsed = off + n;
    return A32(g_ma + off);
}
static uint64_t digest(const uint8_t* p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ull;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) { uint64_t v; std::memcpy(&v, p + i, 8); h = (h ^ v) * 0x100000001B3ull; h ^= h >> 29; }
    for (; i < n; ++i) h = (h ^ p[i]) * 0x100000001B3ull;
    return h;
}
struct Digests { uint64_t world, mut, heap; };
static Digests take_digests() { return {digest(g_wa, g_waUsed), digest(g_ma, g_maUsed), digest(g_heap, g_heapOff)}; }

// fixed objects (allocated once): battle root R, model M, height field, region records, query-chain token, two pathfinders
static uint32_t R, M, HF, REGION[4], TOKEN, PFA, PFB;
static const uint32_t kPfBytes = 0x800;

// fake (host) receivers used by the refusal scenarios: slots the runtime's allow list does not know
static uint8_t __fastcall fake_iface_slot0(void*) { return 1; }
static uint8_t __fastcall fake_gate_flag(void*) { return 1; }

static void build_fixed() {
    R = wnew(0x100);
    M = wnew(0x400);
    HF = wnew(0x40);
    const uint32_t table = wnew(128u * 128u * 8u);
    for (uint32_t r = 0; r < 128; ++r)
        for (uint32_t c = 0; c < 128; ++c) {
            wrf(table + (r * 128 + c) * 8, 0.05f * static_cast<float>((r * 7 + c * 3) % 17));
            wrf(table + (r * 128 + c) * 8 + 4, 0.0f);
        }
    wr32(HF + 0x00, table);
    wr32(HF + 0x08, 7);          // columns = 1 << 7
    wr32(HF + 0x10, 64);         // index offset
    wr32(HF + 0x14, 127);        // max index
    wrf(HF + 0x1C, 40.0f);       // clamp limit
    wrf(HF + 0x20, 1.0f);
    wrf(HF + 0x24, 1.0f);        // scale
    wr32(M + 0x9C, HF);
    wrf(M + 0x84, -1.0e6f); wrf(M + 0x88, -1.0e6f); wrf(M + 0x8C, 1.0e6f); wrf(M + 0x90, 1.0e6f);
    wr32(R + 8, M);
    TOKEN = wnew(0x40);
    wr32(TOKEN + 0x10, 3);
    for (int i = 0; i < 4; ++i) REGION[i] = wnew(0x200);
    wr32(REGION[1] + 0x180, TOKEN);          // query-chain value equals the unit's token: accepted
    wr32(REGION[2] + 0x180, TOKEN + 0x20);   // different value: edge skipped
    g_waFixed = g_waUsed;
    PFA = mnew(kPfBytes);
    PFB = mnew(kPfBytes);
    g_maFixed = g_maUsed;
    wr32(M + 0xB4, PFA);
    wr32(PFA, R);
    wr32(PFB, R);
}

// ---------------------------------------------------------------------------------------------------------------------
// world generation
struct WP {
    uint32_t n = 8, maxDeg = 3, nreg = 1, idMode = 0;   // idMode 0 unique ids, 1 heavy collisions
    float pAcc = 0.9f, pGate = 0.0f, pUsable = 0.9f, pRec = 0.3f;
    bool chain = true;
    uint32_t startDeg = 0;                               // force the start object's edge count (capacity refusal)
};
struct ReqW {                                            // per-request immutable data
    uint32_t U, BASE, startCell, goalCell, viaCell;
    uint32_t startObj, goalObj, viaObj;
    float spos[3], gpos[3], vpos[3];
};
struct World {
    std::vector<uint32_t> obj, cell;
    std::vector<std::vector<uint32_t>> edges;            // edge addresses per object
    std::vector<ReqW> req;
    uint32_t startForce = 0xFFFFFFFFu;
};

static uint32_t make_gate(Rng& rng, uint32_t vtable, uint8_t accept, uint8_t flagByte) {
    const uint32_t g = wnew(0x80);
    wr32(g + 0x00, vtable);
    wr32(g + 0x1C, N(VA_EMBED_VT));
    wr8(g + 0x20, accept);
    wrf(g + 0x30, rng.f(0.05f, 0.4f)); wrf(g + 0x34, 1.0f); wrf(g + 0x38, rng.f(0.05f, 0.4f)); wrf(g + 0x3C, rng.f(-0.5f, 0.5f));
    const uint32_t x = wnew(0x40), y = wnew(0x260);
    wr32(g + 0x60, x);
    wr32(x + 0x14, y);
    wr8(y + 0x232, flagByte);
    return g;
}

static void build_world(World& W, Rng& rng, const WP& P) {
    const uint32_t n = P.n, tot = n + 1;                 // object n is isolated (no incoming edge): unreachable goals
    W.obj.assign(tot, 0); W.cell.assign(tot, 0); W.edges.assign(tot, {});
    for (uint32_t i = 0; i < tot; ++i) {
        const uint32_t o = wnew(0xB0), c = wnew(0x60);
        W.obj[i] = o; W.cell[i] = c;
        wr32(c + 0x40, o);
        wr32(o + 0x00, N(VA_TOPO_VT));
        wr32(o + 0x0C, N(VA_IFACE_VT));
        wr8(o + 0x10, rng.p(P.pAcc) ? 1 : 0);
        wr32(o + 0x1C, P.idMode == 0 ? static_cast<uint32_t>(mix64(i * 7919ull + rng.u(1000000))) | 1u : 1u + rng.u(3));
        wr32(o + 0x20, REGION[rng.u(P.nreg)]);
        if (P.pGate > 0.0f && rng.p(P.pGate)) wr32(o + 0x24, make_gate(rng, N(VA_GATE_VT), rng.p(0.8) ? 1 : 0, rng.p(0.7) ? 1 : 0));
    }
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t deg = rng.r(1, P.maxDeg);
        if (i == 0 && P.startDeg) deg = P.startDeg;
        std::vector<uint32_t> edges;
        for (uint32_t d = 0; d < deg; ++d) {
            uint32_t t;
            if (P.chain && d == 0) t = (i + 1) % n;
            else t = rng.u(n);
            if (t == i) t = (i + 1) % n;
            const uint32_t e = wnew(0x60), s = wnew(0x20), pt = wnew(0x20);
            wr32(e + 0x00, R);
            wr32(e + 0x04, 1);
            wr32(e + 0x14, W.obj[t]);
            wr32(e + 0x1C, s);
            wr32(e + 0x20, rng.p(P.pRec) ? REGION[rng.u(3)] : 0);
            wrf(e + 0x24, rng.f(0.0f, 0.3f));
            wrf(e + 0x28, rng.f(0.0f, 0.3f));
            wrf(e + 0x30, rng.f(1.0f, 4.0f));
            wr8(e + 0x4C, rng.p(P.pUsable) ? 1 : 0);
            // portal: from A = [S+8]->(+0xC,+0x10) to B = (S+0xC, S+0x10); never degenerate
            const float ax = rng.f(-12.0f, 12.0f), az = rng.f(-12.0f, 12.0f);
            wr32(s + 0x08, pt);
            wrf(pt + 0x0C, ax); wrf(pt + 0x10, az);
            wrf(s + 0x0C, ax + rng.f(2.0f, 6.0f)); wrf(s + 0x10, az + rng.f(-3.0f, 3.0f));
            edges.push_back(e);
        }
        const uint32_t arr = wnew(4 * edges.size());
        for (size_t k = 0; k < edges.size(); ++k) wr32(arr + 4 * static_cast<uint32_t>(k), edges[k]);
        wr32(W.obj[i] + 0x34, static_cast<uint32_t>(edges.size()));
        wr32(W.obj[i] + 0x38, arr);
        W.edges[i] = edges;
    }
}

// shared tail of every request builder: unit, locator block holding the start position object at BASE+0x6C8, hint cells
static void finish_reqw(World& W, ReqW& r, bool via) {
    r.U = wnew(0xB00);
    r.BASE = wnew(0x800);
    const uint32_t X = wnew(0x100);
    wr32(r.U + 0x2CC, 1);
    wr32(r.U + 0xADC, r.BASE);
    wr32(r.U + 0x1EC, X);
    wr32(X + 0xD8, TOKEN);
    r.startCell = W.cell[r.startObj];
    r.goalCell = W.cell[r.goalObj];
    r.viaCell = via ? W.cell[r.viaObj] : 0;
    const uint32_t pos = r.BASE + 0x6C8;                  // [[q+0xC]+0xADC]+0x62C+0x9C: 53FBD0 = this+0x9C
    wrf(pos, r.spos[0]); wrf(pos + 4, r.spos[1]); wrf(pos + 8, r.spos[2]);
    wr32(pos + 0xC, r.startCell);
    W.req.push_back(r);
}

// one request's immutable part: unit, locator block (start position object at BASE+0x6C8), hint cells
static void build_reqw(World& W, Rng& rng, bool unreachable, bool via, uint32_t nObjs) {
    ReqW r{};
    r.startObj = (W.startForce != 0xFFFFFFFFu && W.req.empty()) ? W.startForce : rng.u(nObjs);
    do { r.goalObj = rng.u(nObjs); } while (r.goalObj == r.startObj);
    if (unreachable) r.goalObj = nObjs;
    r.viaObj = 0xFFFFFFFFu;
    if (via) {
        do { r.viaObj = rng.u(nObjs); } while (r.viaObj == r.startObj || r.viaObj == r.goalObj);
    }
    for (int k = 0; k < 3; ++k) {
        r.spos[k] = k == 1 ? rng.f(0.0f, 2.0f) : rng.f(-12.0f, 12.0f);
        r.gpos[k] = k == 1 ? rng.f(0.0f, 2.0f) : rng.f(-12.0f, 12.0f);
    }
    if (via) {                                            // between start and goal on the straight line (the original keeps it)
        const float t = rng.f(0.3f, 0.7f);
        for (int k = 0; k < 3; ++k) r.vpos[k] = r.spos[k] + t * (r.gpos[k] - r.spos[k]);
        r.vpos[0] += rng.f(-0.2f, 0.2f);
    }
    finish_reqw(W, r, via);
}

// substantial supported scene: a side x side lattice of topology objects (4-neighbourhood, plain edges, one region, every receiver is
// a real pinned target) folded by wall rows into a serpentine corridor, so an end-to-end request has to expand most of the lattice
static float grid_c(uint32_t side, float pitch, uint32_t i) { return (static_cast<float>(i) - 0.5f * static_cast<float>(side - 1)) * pitch; }
static void build_grid(World& W, uint32_t side, float pitch) {
    const uint32_t n = side * side;
    W.obj.assign(n, 0); W.cell.assign(n, 0); W.edges.assign(n, {});
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t o = wnew(0xB0), c = wnew(0x60);
        W.obj[i] = o; W.cell[i] = c;
        wr32(c + 0x40, o);
        wr32(o + 0x00, N(VA_TOPO_VT));
        wr32(o + 0x0C, N(VA_IFACE_VT));
        wr8(o + 0x10, 1);
        wr32(o + 0x1C, static_cast<uint32_t>(mix64(i * 7919ull + 13)) | 1u);
        wr32(o + 0x20, REGION[0]);
    }
    struct Nb { int dx, dy; };
    static const Nb nbs[4] = {{1, 0}, {-1, 0}, {0, 1}, {0, -1}};
    const float h = 0.4f * pitch;
    for (uint32_t y = 0; y < side; ++y)
        for (uint32_t x = 0; x < side; ++x) {
            const uint32_t i = y * side + x;
            std::vector<uint32_t> edges;
            for (const Nb& d : nbs) {
                const int nx = static_cast<int>(x) + d.dx, ny = static_cast<int>(y) + d.dy;
                if (nx < 0 || ny < 0 || nx >= static_cast<int>(side) || ny >= static_cast<int>(side)) continue;
                if (d.dy != 0) {
                    const uint32_t lo = d.dy > 0 ? y : static_cast<uint32_t>(ny);   // lower row of the pair
                    const uint32_t gap = (((lo >> 1) & 1u) == 0) ? side - 1 : 0;      // alternating end of the wall row
                    if ((lo & 1u) != 0 && x != gap) continue;
                }
                const uint32_t j = static_cast<uint32_t>(ny) * side + static_cast<uint32_t>(nx);
                const float mx = 0.5f * (grid_c(side, pitch, x) + grid_c(side, pitch, static_cast<uint32_t>(nx)));
                const float mz = 0.5f * (grid_c(side, pitch, y) + grid_c(side, pitch, static_cast<uint32_t>(ny)));
                const uint32_t e = wnew(0x60), s = wnew(0x20), pt = wnew(0x20);
                wr32(e + 0x00, R);
                wr32(e + 0x04, 1);
                wr32(e + 0x14, W.obj[j]);
                wr32(e + 0x1C, s);
                wrf(e + 0x24, 0.1f);
                wrf(e + 0x28, 0.1f);
                wrf(e + 0x30, 2.0f);
                wr8(e + 0x4C, 1);
                float ax, az, bx, bz;
                if (d.dy == 0) { ax = mx; az = mz - h; bx = mx + 0.3f; bz = mz + h; }   // vertical portal between horizontal neighbours
                else { ax = mx - h; az = mz; bx = mx + h; bz = mz + 0.3f; }              // horizontal portal between vertical neighbours
                wr32(s + 0x08, pt);
                wrf(pt + 0x0C, ax); wrf(pt + 0x10, az);
                wrf(s + 0x0C, bx); wrf(s + 0x10, bz);
                edges.push_back(e);
            }
            const uint32_t arr = wnew(4 * edges.size() + 4);
            for (size_t k = 0; k < edges.size(); ++k) wr32(arr + 4 * static_cast<uint32_t>(k), edges[k]);
            wr32(W.obj[i] + 0x34, static_cast<uint32_t>(edges.size()));
            wr32(W.obj[i] + 0x38, arr);
            W.edges[i] = edges;
        }
}
static void build_grid_req(World& W, Rng& rng, uint32_t side, float pitch, uint32_t k) {
    ReqW r{};
    auto pick = [&](uint32_t rowLo, uint32_t rowHi) { return rng.r(rowLo, rowHi) * side + rng.u(side); };
    switch (k % 4) {
        case 0: r.startObj = pick(0, 1); r.goalObj = pick(side - 2, side - 1); break;   // across the whole serpentine
        case 2: r.startObj = pick(side - 2, side - 1); r.goalObj = pick(0, 1); break;   // and back
        default:
            r.startObj = pick(0, side - 1);
            do { r.goalObj = pick(0, side - 1); } while (r.goalObj == r.startObj);
            break;
    }
    r.viaObj = 0xFFFFFFFFu;
    const uint32_t s = r.startObj, g = r.goalObj;
    r.spos[0] = grid_c(side, pitch, s % side) + rng.f(-0.3f, 0.3f) * pitch; r.spos[1] = 0.5f; r.spos[2] = grid_c(side, pitch, s / side) + rng.f(-0.3f, 0.3f) * pitch;
    r.gpos[0] = grid_c(side, pitch, g % side) + rng.f(-0.3f, 0.3f) * pitch; r.gpos[1] = 0.5f; r.gpos[2] = grid_c(side, pitch, g / side) + rng.f(-0.3f, 0.3f) * pitch;
    finish_reqw(W, r, false);
}

struct ReqOpt { bool useSub = false; bool special = false; bool kind1 = false; bool via = false; uint8_t q50 = 0; uint8_t flagByte = 1; float radius = 1.0f; };
// request object (0x100) + query at +0x28 (0x58 bytes); the queue link [req+0x24] is set by the caller
static uint32_t make_req(const ReqW& w, const ReqOpt& o) {
    const uint32_t req = mnew(0x100), q = req + 0x28;
    wr32(req + 0x10, 1);                                  // active
    wr32(req + 0x14, 0);                                  // state 0
    wr32(q + 0x00, o.kind1 ? 1u : 0u);
    wr32(q + 0x04, o.via ? 2u : 0u);
    wr32(q + 0x0C, w.U);
    wr32(q + 0x10, o.useSub ? w.BASE : 0u);
    wrf(q + 0x18, w.gpos[0]); wrf(q + 0x1C, w.gpos[1]); wrf(q + 0x20, w.gpos[2]);
    wr32(q + 0x24, w.goalCell);
    wrf(q + 0x2C, o.radius);
    if (o.special) wr32(q + 0x34, wnew(0x40));
    if (o.via) {
        wrf(q + 0x3C, w.vpos[0]); wrf(q + 0x40, w.vpos[1]); wrf(q + 0x44, w.vpos[2]);
        wr32(q + 0x48, w.viaCell);
    }
    wr8(q + 0x50, o.q50);
    wr8(req + 0xDA, o.flagByte);
    return req;
}

// ---------------------------------------------------------------------------------------------------------------------
// ORIGINAL code drivers
static bool construct_g(uint32_t pf) {
    std::memset(P(pf + 0x1BC), 0, 0x128);
    wr32(pf, R);
    const uint32_t g = pf + 0x1BC;
    bool ok = guarded([&] { reinterpret_cast<CtorFn>(P(N(VA_CTOR)))(P(g), nullptr, P(pf)); });
    return ok && rd32(g + 4) == R && rd32(g + 8) == g && rd32(g) == N(0x1347250) && rd32(g + 0xE8) == pw::kDefaultExpansionLimit;
}

struct Inputs { uint32_t g = 0, q = 0, start = 0, goal = 0, via = 0, flag = 0; };

// The request prefix of the stepper 0x80F5E0 (type-0 body 0x80FF1B..0x8101F5), reproduced from its instructions:
//   7F71C0(pf+0x2E4); [pf+0x2E4] = req; 816CA0(q; startPos, pf, &via); start = 7EB210(pf+0x314; pf, G, q, startPos, r);
//   goal = 7EB210(pf+0x348; pf, G, q, q+0x18, r); special -> 814990(goal); world-rect test of both nodes (comiss form):
//   inside -> flag = [req+0xDA] else flag = 1 and [req+0xDA] = 1.   Then 8026F0(G; q, start, goal, via, flag).
static void do_prefix(uint32_t pf, uint32_t req, Inputs* in) {
    const uint32_t q = req + 0x28, g = pf + 0x1BC, model = rd32(rd32(pf) + 8);
    reinterpret_cast<Fn0>(P(N(VA_RESET)))(P(pf + 0x2E4));
    wr32(pf + 0x2E4, req);
    alignas(16) uint8_t startPos[0x20];
    std::memset(startPos, 0, sizeof startPos);
    uint32_t viaPtr = 0;
    reinterpret_cast<StartPosFn>(P(N(VA_STARTPOS)))(P(q), nullptr, startPos, P(pf), &viaPtr);
    const float radius = rdf(q + 0x2C);
    SeedFn seed = reinterpret_cast<SeedFn>(P(N(VA_SEED)));
    pw::Node* start = seed(P(pf + 0x314), nullptr, P(pf), P(g), P(q), startPos, radius);
    pw::Node* goal = seed(P(pf + 0x348), nullptr, P(pf), P(g), P(q), P(q + 0x18), radius);
    if (rd32(q + 0x34) != 0) reinterpret_cast<Fn0>(P(N(VA_MARK)))(goal);
    const float x0 = rdf(model + 0x84), z0 = rdf(model + 0x88), x1 = rdf(model + 0x8C), z1 = rdf(model + 0x90);
    auto inside = [&](const pw::Node* n) { return n->x >= x0 && n->z >= z0 && x1 > n->x && z1 > n->z; };
    uint32_t flag;
    if (inside(start) && inside(goal)) flag = rd8(req + 0xDA);
    else { flag = 1; wr8(req + 0xDA, 1); }
    in->g = g; in->q = q; in->start = A32(start); in->goal = A32(goal); in->via = viaPtr; in->flag = flag;
}

// ---------------------------------------------------------------------------------------------------------------------
// consumer-visible snapshot of a G after a solve (canonical: pointers -> roles)
struct Rec { const char* tag; uint32_t a, v; };
struct Snap { std::vector<Rec> r; void add(const char* t, uint32_t a, uint32_t v) { r.push_back({t, a, v}); } };
static void snap_node(Snap& s, const char* tag, uint32_t idx, uint32_t n, uint32_t g, uint32_t q) {
    s.add(tag, idx * 16 + 0, rd32(n));
    for (uint32_t k = 0; k < 3; ++k) s.add(tag, idx * 16 + 1 + k, rd32(n + 4 + 4 * k));
    s.add(tag, idx * 16 + 4, rd32(n + 0x10));
    s.add(tag, idx * 16 + 5, rd32(n + 0x14));
    s.add(tag, idx * 16 + 6, rd8(n + 0x18) | (static_cast<uint32_t>(rd8(n + 0x19)) << 8) | (static_cast<uint32_t>(rd8(n + 0x24)) << 16));
    s.add(tag, idx * 16 + 7, (rd32(n + 0x1C) == g ? 1u : 0u) | (rd32(n + 0x20) == q ? 2u : 0u));
    s.add(tag, idx * 16 + 8, rd32(n + 0x28));
    s.add(tag, idx * 16 + 9, rd32(n + 0x2C));
    s.add(tag, idx * 16 + 10, rd32(n + 0x30));
}
static Snap take_snap(uint32_t pf, uint32_t req, uint32_t result) {
    Snap s;
    const uint32_t g = pf + 0x1BC, q = req + 0x28;
    s.add("result", 0, result & 0xFF);
    s.add("G+4", 0, rd32(g + 4));
    s.add("G+8", 0, rd32(g + 8) == g ? 1u : 0u);
    s.add("G+C", 0, rd8(g + 0xC));
    s.add("G+E4 expansions", 0, rd32(g + 0xE4));
    s.add("G+E8 limit", 0, rd32(g + 0xE8));
    s.add("G+120 total", 0, rd32(g + 0x120));
    for (uint32_t off = 0xFC; off <= 0x11C; off += 4) s.add("G epilogue word", off, rd32(g + off));
    s.add("G+124", 0, *reinterpret_cast<volatile uint16_t*>(static_cast<uintptr_t>(g + 0x124)));
    const uint32_t size = rd32(g + 0xF4), data = rd32(g + 0xF8);
    s.add("output.size", 0, size);
    if (size <= 4096 && (size == 0 || data != 0))
        for (uint32_t i = 0; i < size; ++i) snap_node(s, "output", i, rd32(data + 4 * i), g, q);
    snap_node(s, "start seed", 0, pf + 0x314, g, q);
    snap_node(s, "goal seed", 0, pf + 0x348, g, q);
    return s;
}
static bool compare_snaps(const Snap& a, const Snap& b, std::string& why) {
    const size_t n = std::min(a.r.size(), b.r.size());
    for (size_t i = 0; i < n; ++i) {
        const Rec &x = a.r[i], &y = b.r[i];
        if (std::strcmp(x.tag, y.tag) != 0 || x.a != y.a || x.v != y.v) {
            char buf[256];
            std::snprintf(buf, sizeof buf, "record %zu: runtime %s[%x]=%08x  original %s[%x]=%08x", i, x.tag, x.a, x.v, y.tag, y.a, y.v);
            why = buf;
            return false;
        }
    }
    if (a.r.size() != b.r.size()) {
        char buf[128];
        std::snprintf(buf, sizeof buf, "record count runtime %zu original %zu", a.r.size(), b.r.size());
        why = buf;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// runtime sessions
struct Stats {
    uint32_t cases = 0, solves = 0, consumed = 0, fallbacks = 0, found = 0, nopath = 0, vias = 0, stale = 0;
    uint32_t teamSteps = 0, workerChunks = 0, mismatches = 0, plumbing = 0, records = 0;
};
static bool g_verbose;
static uint32_t g_totalFailures;

static npr_config base_cfg(uint32_t workers, uint32_t slots);
static uint32_t g_sched;   // address of the stub scheduler
static void __fastcall stub_scheduler(void* pf);

static npr_config base_cfg(uint32_t workers, uint32_t slots) {
    npr_config c;
    std::memset(&c, 0, sizeof c);
    c.abi = NPR_ABI;
    c.size = NPR_CONFIG_BYTES;
    c.imageDelta = static_cast<uint32_t>(g_delta);
    c.root = R; c.model = M; c.pf = PFA;
    c.scheduler = g_sched;
    c.workers = workers; c.slots = slots;
    c.openCapacity = 2048; c.neighborCapacity = 16; c.nodeBlocks = 8; c.entryBlocks = 8; c.hashLevels = 8;
    return c;
}
static uint32_t rt_init(const npr_config& c) {
    wr32(PFA, R);                      // [pf] = root: the binding key npr_initialize reads (run_case re-zeroes pf between cases)
    npr_config t = c;
    uint32_t r = 0;
    if (!guarded([&] { r = npr_initialize(&t); })) return 0xDEAD0001u;
    return r;
}
static uint32_t rt_stop() { uint32_t r = 0; if (!guarded([&] { r = npr_stop(nullptr); })) return 0xDEAD0002u; return r; }

// Each generated case owns different game objects, even when the arena recycles the same addresses. Retire the old queue
// before recycling those arenas so persistence cannot turn an unrelated fixture into a cache hit.
static bool retire_queue() {
    return guarded([&] {
        wr32(PFA + 0x130, 0);
        npr_prepass(P(PFA));
        npr_end(P(PFA));
    });
}

struct Cnt { uint32_t v[NPR_STATE_WORDS]; };
static Cnt snapc() { Cnt c; for (uint32_t i = 0; i < NPR_STATE_WORDS; ++i) c.v[i] = npr_state[i]; return c; }
static uint32_t dc(const Cnt& a, const Cnt& b, uint32_t w) { return b.v[w] - a.v[w]; }

static void report(Stats& st, bool plumbing, const char* family, uint32_t idx, const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    std::printf("%s %s #%u: %s\n", plumbing ? "PLUMBING" : "MISMATCH", family, idx, buf);
    if (plumbing) ++st.plumbing; else ++st.mismatches;
}

// ---------------------------------------------------------------------------------------------------------------------
// scenarios
enum Cls { C_CONSUME, C_STALE, C_REJECT, C_NOSOLVE, C_UNUSED };
enum Mut { M_NONE, M_ID, M_WIDTH, M_QUERY, M_FLAG, M_SENT, M_LIMIT, M_START };
enum Pre { P_NONE, P_SENT, P_SPECIAL, P_IFACE, P_GATE, P_KIND1, P_CAPACITY };
struct Spec {
    const char* family = "";
    uint32_t idx = 0;
    uint64_t seed = 0;
    WP wp;
    uint32_t nreq = 1;
    bool hook = true, via = false, unreachable = false, smallRect = false, useSub = false;
    uint32_t limit = 0;
    uint8_t overwrite = 0, q50 = 0, flagByte = 1;
    Mut mut = M_NONE; uint32_t mutReq = 0;
    Pre pre = P_NONE; uint32_t preReq = 0;
    bool skipLast = false, throwAfter = false, busyStop = false;
};

struct TickCtx {
    const Spec* sp = nullptr;
    World* W = nullptr;
    std::vector<uint32_t> reqA, reqB;
    std::vector<Cls> cls;
    std::vector<Snap> snapA;
    std::vector<uint32_t> resA, solved;
    std::vector<std::vector<uint8_t>> querySnap;
    Digests before{};
    uint32_t sentinelSaved = 0;
    bool prepassDirty = false, faulted = false, ownerOk = true, expectOwner = false, busyDone = false;
    uint32_t busyResult = 0;
    std::string fault;
    uint32_t viaKept = 0;
};
static TickCtx* g_tc;

static void apply_mutation(TickCtx& t, uint32_t k) {
    const Spec& sp = *t.sp;
    const World& W = *t.W;
    const ReqW& rw = W.req[k];
    switch (sp.mut) {
        case M_ID: wr32(W.obj[rw.startObj] + 0x1C, rd32(W.obj[rw.startObj] + 0x1C) ^ 0x5A5A5A5Au); break;
        case M_WIDTH: wrf(W.edges[rw.startObj][0] + 0x30, rdf(W.edges[rw.startObj][0] + 0x30) + 0.75f); break;
        case M_QUERY: wrf(t.reqA[k] + 0x28 + 0x2C, rdf(t.reqA[k] + 0x28 + 0x2C) + 1.0f); break;
        case M_FLAG: wr8(t.reqA[k] + 0xDA, rd8(t.reqA[k] + 0xDA) ^ 1); break;
        case M_SENT: {
            const uint32_t a = N(VA_SENTINEL);
            t.sentinelSaved = rd32(a);
            wrf(a, 1.0f);
            break;
        }
        case M_LIMIT: wr32(PFA + 0x1BC + 0xE8, rd32(PFA + 0x1BC + 0xE8) - 1); break;
        case M_START: wrf(rw.BASE + 0x6C8, rdf(rw.BASE + 0x6C8) + 0.5f); break;
        case M_NONE: break;
    }
}

// scheduler body shared by the hook stub and the manual driver: for every queued request in state 0 run the original request
// prefix and the solve call (npr_solve = the generated clone's call target), recording the G state after each
static void solve_all_impl(uint32_t pf) {
    TickCtx& t = *g_tc;
    const Digests d = take_digests();
    if (d.world != t.before.world || d.mut != t.before.mut || d.heap != t.before.heap) t.prepassDirty = true;
    if (t.expectOwner && t.sp->hook && npr_state[NPR_S_OWNER_THREAD] != GetCurrentThreadId()) t.ownerOk = false;
    uint32_t k = 0;
    for (uint32_t req = rd32(pf + 0x130); req != 0; req = rd32(req + 0x24), ++k) {
        if (k >= t.cls.size()) break;
        if (rd32(req + 0x10) == 0 || rd32(req + 0x14) != 0) continue;
        const uint32_t q = req + 0x28;
        if (!(rd32(q) != 0 || rd32(rd32(q + 0xC) + 0x2CC) != 0)) continue;       // 0x81B7B0 viability
        if (t.cls[k] == C_NOSOLVE || t.cls[k] == C_UNUSED) continue;              // stepper never reaches the solve for this one
        if (t.sp->mut != M_NONE && t.sp->mutReq == k) {
            apply_mutation(t, k);
            const Digests d2 = take_digests();                                   // the mutation is deliberate: new baseline
            t.before = d2;
        }
        Inputs in;
        do_prefix(pf, req, &in);
        if (in.via != 0) ++t.viaKept;
        t.resA.push_back(npr_solve(P(in.g), nullptr, P(in.q), P(in.start), P(in.goal), P(in.via), in.flag) & 0xFF);
        t.snapA.push_back(take_snap(pf, req, t.resA.back()));
        t.solved.push_back(k);
        if (t.sp->busyStop && !t.busyDone) {                                      // npr_stop while the owner holds the tick
            t.busyDone = true;
            t.busyResult = npr_stop(nullptr);
        }
    }
    // solves write only G / seed nodes / the [req+0xDA] flag byte; the end-of-tick digest checks the world itself
}
static void solve_all(uint32_t pf) {
    TickCtx& t = *g_tc;
    if (!guarded([&] { solve_all_impl(pf); })) { t.faulted = true; t.fault = fault_text(); }
}
static void __fastcall stub_scheduler(void* pf) {
    solve_all(A32(pf));
    if (g_tc != nullptr && g_tc->sp->throwAfter) RaiseException(0xE0A10001u, 0, 0, nullptr);
}


static bool run_case(const Spec& sp, Stats& st, uint32_t* viaOut = nullptr) {
    ++st.cases;
    if (!retire_queue()) { report(st, true, sp.family, sp.idx, "retiring previous fixture faulted: %s", fault_text().c_str()); return false; }
    heap_reset();
    g_waUsed = g_waFixed;
    g_maUsed = g_maFixed;
    std::memset(P(PFA), 0, kPfBytes);
    std::memset(P(PFB), 0, kPfBytes);
    if (!construct_g(PFA) || !construct_g(PFB)) { report(st, true, sp.family, sp.idx, "G constructor produced an unexpected object"); return false; }
    for (uint32_t pf : {PFA, PFB}) {
        if (sp.limit) wr32(pf + 0x1BC + 0xE8, sp.limit);
        wr8(pf + 0x1BC + 0xC, sp.overwrite);
    }
    wrf(M + 0x84, sp.smallRect ? -1.0f : -1.0e6f);   // tiny rect -> start outside -> flag forced to 1 (and [req+0xDA] := 1)
    wrf(M + 0x90, sp.smallRect ? 1.0f : 1.0e6f);

    Rng rng(mix64(sp.seed ^ (std::hash<std::string>()(sp.family) * 31ull + sp.idx)));
    World W;
    build_world(W, rng, sp.wp);
    if (sp.wp.startDeg) W.startForce = 0;               // the object whose edge count was forced is the start of request 0
    for (uint32_t k = 0; k < sp.nreq; ++k) build_reqw(W, rng, sp.unreachable && k == 0, sp.via, sp.wp.n);

    TickCtx t;
    t.sp = &sp; t.W = &W;
    t.cls.assign(sp.nreq, C_CONSUME);
    for (uint32_t k = 0; k < sp.nreq; ++k) {
        if (sp.pre == P_SPECIAL && sp.preReq == k) t.cls[k] = C_REJECT;
        if (sp.pre == P_KIND1 && sp.preReq == k) t.cls[k] = C_NOSOLVE;
        if (sp.pre == P_SENT || (sp.pre == P_IFACE && sp.preReq == k) || (sp.pre == P_GATE && sp.preReq == k) || (sp.pre == P_CAPACITY && sp.preReq == k)) t.cls[k] = C_REJECT;
        if (sp.mut != M_NONE && sp.mutReq == k) t.cls[k] = C_STALE;
        if (sp.skipLast && k + 1 == sp.nreq) t.cls[k] = C_UNUSED;
    }
    // requests A (queue) and B (reference copies) with identical bytes
    g_maUsed = g_maFixed;
    for (int side = 0; side < 2; ++side) {
        std::vector<uint32_t>& v = side == 0 ? t.reqA : t.reqB;
        for (uint32_t k = 0; k < sp.nreq; ++k) {
            ReqOpt o;
            o.useSub = sp.useSub; o.via = sp.via; o.q50 = sp.q50; o.flagByte = sp.flagByte; o.radius = 0.5f + 0.25f * static_cast<float>(k % 4);
            o.special = (sp.pre == P_SPECIAL && sp.preReq == k);
            o.kind1 = (sp.pre == P_KIND1 && sp.preReq == k);
            v.push_back(make_req(W.req[k], o));
        }
        for (uint32_t k = 0; k + 1 < sp.nreq; ++k) wr32(v[k] + 0x24, v[k + 1]);
    }
    wr32(PFA + 0x130, t.reqA[0]);
    wr32(PFB + 0x130, t.reqB[0]);

    // refusal worlds: shape the start object's first expansion
    if (sp.pre == P_IFACE || sp.pre == P_GATE) {
        const ReqW& rw = W.req[sp.preReq];
        const uint32_t e0 = W.edges[rw.startObj][0];
        const uint32_t d = rd32(e0 + 0x14);
        wr8(e0 + 0x4C, 1);
        wr32(W.obj[rw.startObj] + 0x20, REGION[0]);
        wr32(d + 0x20, REGION[0]);
        wr32(d + 0x24, 0);
        if (sp.pre == P_IFACE) {
            const uint32_t fv = wnew(0x20);
            wr32(fv, A32(reinterpret_cast<void*>(&fake_iface_slot0)));
            wr32(d + 0x0C, fv);
        } else {
            const uint32_t vt = wnew(0x40);
            wr32(vt + 0x18, N(VA_GW_ZERO));
            wr32(vt + 0x20, N(VA_GW_SELF));
            wr32(vt + 0x28, A32(reinterpret_cast<void*>(&fake_gate_flag)));
            wr32(d + 0x24, make_gate(rng, vt, 1, 1));
        }
    }

    // (query snapshots: the bytes the runtime must never see change except where a scenario mutates them on purpose)
    for (uint32_t k = 0; k < sp.nreq; ++k) t.querySnap.emplace_back(static_cast<const uint8_t*>(P(t.reqA[k] + 0x28)), static_cast<const uint8_t*>(P(t.reqA[k] + 0x28)) + 0x58);

    // pre-plan drift of the sentinel constants (the runtime captured them at initialize time)
    uint32_t sentinelRestore = 0;
    bool drifted = false;
    if (sp.pre == P_SENT) { sentinelRestore = rd32(N(VA_SENTINEL)); wrf(N(VA_SENTINEL), 1.0f); drifted = true; }

    t.before = take_digests();
    g_tc = &t;
    for (Cls c : t.cls) if (c == C_CONSUME || c == C_STALE || c == C_UNUSED) t.expectOwner = true;
    const Cnt c0 = snapc();
    bool fault = false;
    DWORD exCode = 0;
    if (sp.hook) {
        fault = !guarded([&] { npr_scheduler_hook(P(PFA)); });
        exCode = g_excCode;
    } else {
        fault = !guarded([&] { npr_prepass(P(PFA)); });
        if (!fault) {
            const Digests d = take_digests();
            if (d.world != t.before.world || d.mut != t.before.mut || d.heap != t.before.heap) t.prepassDirty = true;
            solve_all(PFA);
            if (!guarded([&] { npr_end(P(PFA)); })) fault = true;
        }
    }
    g_tc = nullptr;
    const Cnt c1 = snapc();
    const bool thrown = sp.hook && sp.throwAfter && fault && exCode == 0xE0A10001u;
    if (sp.hook && sp.throwAfter) {
        if (!thrown) { report(st, true, sp.family, sp.idx, "scheduler exception did not propagate out of npr_scheduler_hook (fault=%d code=%08lx)", fault, exCode); }
        else fault = false;
    }
    bool ok = true;
    if (fault) { report(st, true, sp.family, sp.idx, "runtime faulted: %s", fault_text().c_str()); ok = false; }
    if (t.faulted) { report(st, true, sp.family, sp.idx, "tick body faulted: %s", t.fault.c_str()); ok = false; }
    if (t.prepassDirty) { report(st, false, sp.family, sp.idx, "prepass wrote game memory (world / pf / request / host heap digest changed before the first solve)"); ok = false; }
    if (!t.ownerOk) { report(st, false, sp.family, sp.idx, "NPR_S_OWNER_THREAD is not the hook thread while the scheduler runs"); ok = false; }
    if (npr_state[NPR_S_OWNER_THREAD] != 0) { report(st, false, sp.family, sp.idx, "owner thread still published after the tick"); ok = false; }

    // semantic acceptance: consumption, stale refusal, original fallback, and no successor callback for refused requests
    uint32_t planned = 0, consumed = 0, fallbacks = 0, stale = 0, refusedAll = 0;
    for (Cls c : t.cls) {
        if (c == C_CONSUME) { ++planned; ++consumed; }
        else if (c == C_STALE) { ++planned; ++stale; ++fallbacks; }
        else if (c == C_REJECT) { ++fallbacks; ++refusedAll; }
        else if (c == C_NOSOLVE) { ++refusedAll; }
        else if (c == C_UNUSED) { ++planned; }
    }
    auto expect = [&](const char* name, uint32_t w, uint32_t want) {
        const uint32_t got = dc(c0, c1, w);
        if (got != want) { report(st, false, sp.family, sp.idx, "counter %s delta %u, expected %u", name, got, want); ok = false; }
    };
    if (!fault || thrown) {
        expect("CONSUMED", NPR_S_CONSUMED, consumed);
        expect("STALE", NPR_S_STALE, stale);
        expect("FALLBACKS", NPR_S_FALLBACKS, fallbacks);
        const uint32_t cb = dc(c0, c1, NPR_S_CALLBACKS);
        if (refusedAll == sp.nreq && cb != 0) { report(st, false, sp.family, sp.idx, "an original callback ran (%u) although every request is refused before any callback", cb); ok = false; }
        if (planned > 0 && cb == 0) { report(st, false, sp.family, sp.idx, "no original successor callback ran for planned requests"); ok = false; }
    }
    if (sp.busyStop) {
        if (t.busyResult != 6u) { report(st, false, sp.family, sp.idx, "npr_stop during an active tick returned %08x, expected NPR_E_BUSY(6)", t.busyResult); ok = false; }
        if (npr_state[NPR_S_ENABLED] != 0 || npr_state[NPR_S_PHASE] != 1) { report(st, false, sp.family, sp.idx, "busy stop did not disable the hook while keeping phase 1"); ok = false; }
    }

    // reference: the ORIGINAL 0x8026F0 on the identically built second G, same order, same (post-mutation) world
    if (ok && t.solved.size() != 0) {
        if (sp.mut == M_QUERY) wrf(t.reqB[sp.mutReq] + 0x28 + 0x2C, rdf(t.reqB[sp.mutReq] + 0x28 + 0x2C) + 1.0f);
        if (sp.mut == M_FLAG) wr8(t.reqB[sp.mutReq] + 0xDA, rd8(t.reqB[sp.mutReq] + 0xDA) ^ 1);
        if (sp.mut == M_LIMIT) wr32(PFB + 0x1BC + 0xE8, rd32(PFB + 0x1BC + 0xE8) - 1);
        for (size_t i = 0; i < t.solved.size(); ++i) {
            const uint32_t k = t.solved[i];
            Inputs in;
            uint32_t res = 0;
            bool f2 = !guarded([&] {
                do_prefix(PFB, t.reqB[k], &in);
                res = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(in.g), nullptr, P(in.q), P(in.start), P(in.goal), P(in.via), in.flag) & 0xFF;
            });
            if (f2) { report(st, true, sp.family, sp.idx, "ORIGINAL 0x8026F0 reference faulted on the synthesised world: %s", fault_text().c_str()); ok = false; break; }
            const Snap sb = take_snap(PFB, t.reqB[k], res);
            std::string why;
            ++st.solves;
            if (!compare_snaps(t.snapA[i], sb, why)) { report(st, false, sp.family, sp.idx, "request %u (%s): %s", k, t.cls[k] == C_CONSUME ? "consumed" : "fallback", why.c_str()); ok = false; break; }
            st.records += static_cast<uint32_t>(sb.r.size());
            if (res) ++st.found; else ++st.nopath;
            if (g_verbose) std::printf("  %s #%u/%u: %s result=%u out=%u records=%zu\n", sp.family, sp.idx, k, t.cls[k] == C_CONSUME ? "consumed" : "fallback", res, rd32(PFB + 0x1BC + 0xF4), sb.r.size());
        }
    }
    // post invariants
    if (!heap_canaries_ok()) { report(st, true, sp.family, sp.idx, "host heap canary violated"); ok = false; }
    for (uint32_t k = 0; k < sp.nreq && ok; ++k) {
        if (sp.mut != M_NONE && sp.mutReq == k && sp.mut == M_QUERY) continue;
        if (std::memcmp(P(t.reqA[k] + 0x28), t.querySnap[k].data(), 0x58) != 0) { report(st, false, sp.family, sp.idx, "request %u query bytes changed during the tick", k); ok = false; }
    }
    const Digests dEnd = take_digests();
    if (ok && dEnd.world != t.before.world) { report(st, false, sp.family, sp.idx, "synthesised world bytes changed during the tick (runtime / original wrote game data)"); ok = false; }
    if (drifted) wr32(N(VA_SENTINEL), sentinelRestore);
    if (sp.mut == M_SENT) wr32(N(VA_SENTINEL), t.sentinelSaved);
    st.consumed += dc(c0, c1, NPR_S_CONSUMED); st.fallbacks += dc(c0, c1, NPR_S_FALLBACKS); st.stale += dc(c0, c1, NPR_S_STALE);
    st.vias += t.viaKept;
    st.teamSteps += dc(c0, c1, NPR_S_TEAM_STEPS);
    st.workerChunks += dc(c0, c1, NPR_S_WORKER_CHUNKS);
    if (viaOut) *viaOut = t.viaKept;
    return ok;
}

// ---------------------------------------------------------------------------------------------------------------------
static Spec make_spec(const char* family, uint32_t idx, uint64_t seed) {
    Spec s;
    s.family = family; s.idx = idx; s.seed = seed;
    Rng rng(mix64(seed ^ 0x51 ^ (std::hash<std::string>()(family) + idx)));
    const std::string f = family;
    s.wp.n = rng.r(5, 12); s.wp.maxDeg = rng.r(2, 4); s.wp.nreg = rng.r(1, 2);
    s.hook = (idx & 1) == 0;
    s.flagByte = static_cast<uint8_t>(rng.u(2));
    s.q50 = static_cast<uint8_t>(rng.u(2));
    s.useSub = rng.p(0.3);
    s.overwrite = static_cast<uint8_t>(rng.p(0.2) ? 1 : 0);
    s.smallRect = rng.p(0.15);
    if (f == "plain") { s.wp.pAcc = 1.0f; s.wp.pRec = 0.0f; }
    else if (f == "mixed") { s.unreachable = rng.p(0.4); s.wp.idMode = rng.p(0.3) ? 1 : 0; s.wp.pAcc = 0.8f; s.wp.pRec = 0.4f; }
    else if (f == "gated") { s.wp.pGate = 0.4f; s.wp.pRec = 0.3f; s.unreachable = rng.p(0.2); }
    else if (f == "via") { s.via = true; s.wp.n = rng.r(6, 12); s.wp.pRec = 0.0f; }
    else if (f == "limit") { s.wp.n = rng.r(8, 12); s.wp.maxDeg = 2; s.limit = rng.r(2, 5); s.wp.pAcc = 1.0f; s.wp.pRec = 0.0f; s.wp.pUsable = 1.0f; s.flagByte = 1; s.smallRect = false; }
    else if (f == "overwrite") { s.overwrite = 1; s.wp.idMode = 1; s.wp.maxDeg = 4; }
    else if (f == "multi") { s.nreq = 3; s.hook = true; s.wp.n = rng.r(8, 12); s.wp.pAcc = 0.9f; s.unreachable = rng.p(0.3); }
    else if (f == "inline") { s.wp.maxDeg = 2; s.wp.nreg = 1; s.wp.pRec = 0.0f; s.wp.pUsable = 1.0f; s.wp.pAcc = 1.0f; s.flagByte = 1; s.smallRect = false; s.unreachable = rng.p(0.3); }
    else if (f == "stale") {
        static const Mut ms[] = {M_ID, M_WIDTH, M_QUERY, M_FLAG, M_SENT, M_LIMIT, M_START};
        s.mut = ms[idx % 7];
        s.wp.pAcc = 1.0f; s.wp.pRec = 0.0f;
        s.smallRect = false;                                           // M_FLAG needs the flag to come from [req+0xDA]
        s.hook = true;
    }
    else if (f == "stale-multi") {                                     // only request 1 of 3 goes stale (private fields only)
        static const Mut ms[] = {M_QUERY, M_FLAG, M_START};
        s.nreq = 3; s.mut = ms[idx % 3]; s.mutReq = 1; s.hook = true; s.smallRect = false; s.wp.n = rng.r(8, 12);
    }
    else if (f == "sentinel") { s.pre = P_SENT; s.nreq = 1 + (idx % 2); s.hook = (idx & 2) == 0; }
    else if (f == "refuse-special") { s.pre = P_SPECIAL; s.nreq = 2; s.preReq = idx % 2; s.wp.n = rng.r(6, 10); }
    else if (f == "refuse-iface") { s.pre = P_IFACE; s.wp.n = rng.r(6, 10); s.wp.nreg = 1; s.wp.pRec = 0.0f; s.flagByte = 1; s.smallRect = false; }
    else if (f == "refuse-gate") { s.pre = P_GATE; s.wp.n = rng.r(6, 10); s.wp.nreg = 1; s.wp.pRec = 0.0f; s.flagByte = 1; s.smallRect = false; }
    else if (f == "refuse-kind1") { s.pre = P_KIND1; s.nreq = 3; s.preReq = idx % 3; s.hook = true; s.wp.n = rng.r(6, 10); }
    else if (f == "unused") { s.nreq = 2; s.skipLast = true; s.hook = (idx & 1) == 0; }
    else if (f == "refuse-capacity") { s.pre = P_CAPACITY; s.wp.n = rng.r(6, 10); s.wp.startDeg = 5; s.wp.maxDeg = 2; }
    else if (f == "busy") { s.busyStop = true; s.nreq = 2; s.hook = true; }
    else if (f == "exception") { s.throwAfter = true; s.nreq = 2; s.hook = true; }
    return s;
}

static const char* kSessionAFamilies[] = {"plain", "mixed", "gated", "via", "limit", "overwrite", "multi", "stale", "stale-multi", "sentinel",
                                          "refuse-special", "refuse-iface", "refuse-gate", "refuse-kind1", "unused"};

// ---------------------------------------------------------------------------------------------------------------------
// lifecycle suite
static uint32_t g_lifeFailures;
static void life_fail(const char* what, uint32_t got = 0, uint32_t want = 0) {
    std::printf("MISMATCH lifecycle: %s (got %08x, expected %08x)\n", what, got, want);
    ++g_lifeFailures;
}
#define LIFE_EXPECT(cond, what) do { if (!(cond)) life_fail(what); } while (0)
static void life_expect_eq(const char* what, uint32_t got, uint32_t want) { if (got != want) life_fail(what, got, want); }

alignas(64) static uint8_t g_sharedPoolMem[NTW_POOL_BYTES];
static ntw_u32 shared_pool_start(uint32_t workers) {
    std::memset(g_sharedPoolMem, 0, sizeof g_sharedPoolMem);
    ntw_pool_config pc;
    std::memset(&pc, 0, sizeof pc);
    pc.abi = NTW_POOL_ABI;
    pc.workers = workers;
    pc.stack_bytes = 0x100000;
    pc.api.create_event = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CreateEventW));
    pc.api.close_handle = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CloseHandle));
    pc.api.set_event = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&SetEvent));
    pc.api.wait_single = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&WaitForSingleObject));
    pc.api.create_thread = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&CreateThread));
    pc.api.worker_entry = static_cast<ntw_u32>(reinterpret_cast<uintptr_t>(&ntw_pool_worker_start));
    return ntw_pool_init(reinterpret_cast<ntw_pool*>(g_sharedPoolMem), &pc);
}

static uint32_t run_lifecycle_pre() {
    const uint32_t before = g_lifeFailures;
    life_expect_eq("npr_stop before any initialize", rt_stop(), NPR_E_STATE);
    life_expect_eq("phase before initialize", npr_state[NPR_S_PHASE], 0);
    uint32_t r = 0;
    guarded([&] { r = npr_initialize(nullptr); });
    life_expect_eq("initialize(null)", r, NPR_E_ARG);
    struct Bad { const char* name; void (*mutate)(npr_config&); };
    static const Bad bad[] = {
        {"abi", [](npr_config& c) { c.abi = 2; }},
        {"size", [](npr_config& c) { c.size = 60; }},
        {"slots 0", [](npr_config& c) { c.slots = 0; }},
        {"slots > max", [](npr_config& c) { c.slots = NPR_MAX_SLOTS + 1; }},
        {"workers > max", [](npr_config& c) { c.workers = NPR_MAX_WORKERS + 1; }},
        {"maxNewPerTick > max", [](npr_config& c) { c.maxNewPerTick = NPR_MAX_SLOTS + 1; }},
        {"neighborCapacity 1", [](npr_config& c) { c.neighborCapacity = 1; }},
        {"hashLevels 13", [](npr_config& c) { c.hashLevels = 13; }},
        {"null root", [](npr_config& c) { c.root = 0; }},
    };
    for (const Bad& b : bad) {
        npr_config c = base_cfg(0, 1);
        b.mutate(c);
        const uint32_t e = rt_init(c);
        if (NPR_ERR_CLASS(e) != NPR_E_ARG) { char buf[96]; std::snprintf(buf, sizeof buf, "bad config '%s' accepted / wrong class", b.name); life_fail(buf, e, NPR_E_ARG); }
        life_expect_eq("phase unchanged after refused initialize", npr_state[NPR_S_PHASE], 0);
        life_expect_eq("storage unchanged after refused initialize", npr_storage_bytes, 0);
    }
    {   // binding keys: a model that does not point back at pf
        const uint32_t m2 = wnew(0x400);
        npr_config c = base_cfg(0, 1);
        c.model = m2;
        const uint32_t e = rt_init(c);
        life_expect_eq("unbound model class", NPR_ERR_CLASS(e), NPR_E_ARG);
        life_expect_eq("unbound model detail", NPR_ERR_DETAIL(e), 1);
    }
    {   // image drift: one byte of a pinned code span, then one pinned data word
        uint8_t* code = static_cast<uint8_t*>(P(N(VA_GW_SELF)));
        const uint8_t keep = code[0];
        code[0] ^= 0xFF;
        const uint32_t e = rt_init(base_cfg(0, 1));
        code[0] = keep;
        life_expect_eq("pinned code drift class", NPR_ERR_CLASS(e), NPR_E_IMAGE);
        life_expect_eq("pinned code drift detail (span index 1)", NPR_ERR_DETAIL(e), 1);
        life_expect_eq("phase after image error", npr_state[NPR_S_PHASE], 0);
        const uint32_t wa = N(0x1347264);
        const uint32_t kw = rd32(wa);
        wr32(wa, kw + 4);
        const uint32_t e2 = rt_init(base_cfg(0, 1));
        wr32(wa, kw);
        life_expect_eq("pinned data word drift class", NPR_ERR_CLASS(e2), NPR_E_IMAGE);
        LIFE_EXPECT(NPR_ERR_DETAIL(e2) >= 0x1000, "pinned data word drift detail is a word index");
    }
    return g_lifeFailures - before;
}

// session A of lifecycle: double initialize, storage accounting
static void lifecycle_session_a_checks() {
    life_expect_eq("phase ready", npr_state[NPR_S_PHASE], 1);
    life_expect_eq("enabled", npr_state[NPR_S_ENABLED], 1);
    life_expect_eq("abi word", npr_state[NPR_S_ABI], NPR_ABI);
    life_expect_eq("size word", npr_state[NPR_S_SIZE], NPR_STATE_BYTES);
    LIFE_EXPECT(npr_storage_bytes >= 4u * (1u << 20), "storage covers four 1 MiB footprints");
    LIFE_EXPECT(npr_storage_bytes < 0x60000000u, "storage below the runtime cap");
    life_expect_eq("second initialize while ready", rt_init(base_cfg(0, 1)), NPR_E_STATE);
    life_expect_eq("phase kept by refused second initialize", npr_state[NPR_S_PHASE], 1);
}

// inert state (stopped, or disabled by a busy stop): hooks plan nothing, npr_solve falls back to the ORIGINAL 0x8026F0 and the
// answer equals the reference on a second G; only FALLBACKS moves
static void inert_checks(Stats& st, const char* label) {
    Spec sp = make_spec("plain", 5, 99);
    heap_reset();
    g_waUsed = g_waFixed; g_maUsed = g_maFixed;
    std::memset(P(PFA), 0, kPfBytes); std::memset(P(PFB), 0, kPfBytes);
    if (!construct_g(PFA) || !construct_g(PFB)) { life_fail("inert: G constructor"); return; }
    Rng rng(mix64(99));
    World W;
    build_world(W, rng, sp.wp);
    build_reqw(W, rng, false, false, sp.wp.n);
    ReqOpt o;
    const uint32_t ra = make_req(W.req[0], o), rb = make_req(W.req[0], o);
    wr32(PFA + 0x130, ra); wr32(PFB + 0x130, rb);
    const Cnt c0 = snapc();
    Inputs ia, ib;
    uint32_t resA = 0, resB = 0;
    const bool f = !guarded([&] {
        npr_prepass(P(PFA));
        do_prefix(PFA, ra, &ia);
        resA = npr_solve(P(ia.g), nullptr, P(ia.q), P(ia.start), P(ia.goal), P(ia.via), ia.flag) & 0xFF;
        npr_end(P(PFA));
        do_prefix(PFB, rb, &ib);
        resB = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(ib.g), nullptr, P(ib.q), P(ib.start), P(ib.goal), P(ib.via), ib.flag) & 0xFF;
    });
    if (f) { std::printf("PLUMBING lifecycle(%s): inert solve faulted: %s\n", label, fault_text().c_str()); ++st.plumbing; return; }
    const Cnt c1 = snapc();
    char what[96];
    std::snprintf(what, sizeof what, "%s: ticks", label);       life_expect_eq(what, dc(c0, c1, NPR_S_TICKS), 0);
    std::snprintf(what, sizeof what, "%s: planned", label);     life_expect_eq(what, dc(c0, c1, NPR_S_PLANNED), 0);
    std::snprintf(what, sizeof what, "%s: consumed", label);    life_expect_eq(what, dc(c0, c1, NPR_S_CONSUMED), 0);
    std::snprintf(what, sizeof what, "%s: fallbacks", label);   life_expect_eq(what, dc(c0, c1, NPR_S_FALLBACKS), 1);
    std::snprintf(what, sizeof what, "%s: callbacks", label);   life_expect_eq(what, dc(c0, c1, NPR_S_CALLBACKS), 0);
    std::string why;
    if (!compare_snaps(take_snap(PFA, ra, resA), take_snap(PFB, rb, resB), why)) { std::printf("MISMATCH lifecycle(%s): fallback differs from the original: %s\n", label, why.c_str()); ++g_lifeFailures; }
    ++st.solves;
}

// Outside an active owner tick a solve must still fall back, even though the private result survives npr_end.
static void outlive_check(Stats& st) {
    Spec sp = make_spec("plain", 7, 123);
    if (!retire_queue()) { life_fail("outlive: retire previous fixture"); return; }
    heap_reset();
    g_waUsed = g_waFixed; g_maUsed = g_maFixed;
    std::memset(P(PFA), 0, kPfBytes); std::memset(P(PFB), 0, kPfBytes);
    if (!construct_g(PFA) || !construct_g(PFB)) { life_fail("outlive: G constructor"); return; }
    Rng rng(mix64(123));
    World W;
    build_world(W, rng, sp.wp);
    build_reqw(W, rng, false, false, sp.wp.n);
    ReqOpt o;
    const uint32_t ra = make_req(W.req[0], o), rb = make_req(W.req[0], o);
    wr32(PFA + 0x130, ra); wr32(PFB + 0x130, rb);
    Inputs ia, ib;
    uint32_t resA = 0, resB = 0;
    TickCtx t; t.sp = &sp; t.W = &W; t.cls.assign(1, C_CONSUME);
    g_tc = &t;
    const Cnt c0 = snapc();
    const bool f = !guarded([&] {
        npr_prepass(P(PFA));
        npr_end(P(PFA));
        do_prefix(PFA, ra, &ia);
        resA = npr_solve(P(ia.g), nullptr, P(ia.q), P(ia.start), P(ia.goal), P(ia.via), ia.flag) & 0xFF;
        do_prefix(PFB, rb, &ib);
        resB = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(ib.g), nullptr, P(ib.q), P(ib.start), P(ib.goal), P(ib.via), ib.flag) & 0xFF;
    });
    g_tc = nullptr;
    if (f) { std::printf("PLUMBING lifecycle: outlive check faulted: %s\n", fault_text().c_str()); ++st.plumbing; return; }
    const Cnt c1 = snapc();
    life_expect_eq("outlive: planned", dc(c0, c1, NPR_S_PLANNED), 1);
    life_expect_eq("outlive: carried at npr_end", dc(c0, c1, NPR_S_CARRIED), 1);
    life_expect_eq("outlive: consumed after npr_end", dc(c0, c1, NPR_S_CONSUMED), 0);
    life_expect_eq("outlive: fallbacks", dc(c0, c1, NPR_S_FALLBACKS), 1);
    std::string why;
    if (!compare_snaps(take_snap(PFA, ra, resA), take_snap(PFB, rb, resB), why)) { std::printf("MISMATCH lifecycle: post-tick fallback differs from original: %s\n", why.c_str()); ++g_lifeFailures; }
    ++st.solves;
}

// ---------------------------------------------------------------------------------------------------------------------
// scale scene: kScaleRequests independent requests over a 16x16 serpentine lattice (hundreds of expansions each), solved by the
// ORIGINAL 0x8026F0 (reference, timed) and by the runtime in one tick: once with no worker threads, then kTeamPasses times on a
// shared worker team.  Every consumed result is compared bit for bit with the original; time observations are printed, never
// thresholded. Actual off-owner engine advances (NPR_S_WORKER_CHUNKS, not merely pool body entries) are REQUIRED on multi-CPU hosts.
static const uint32_t kScaleSide = 16, kScaleRequests = 16, kTeamPasses = 3;
static const float kScalePitch = 4.0f;
static LARGE_INTEGER qpc() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t; }
static double ms_between(LARGE_INTEGER a, LARGE_INTEGER b) {
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    return 1000.0 * static_cast<double>(b.QuadPart - a.QuadPart) / static_cast<double>(f.QuadPart);
}
struct ScaleRef {
    std::vector<Snap> snap;
    uint32_t expansions = 0, outNodes = 0, found = 0;
    double prefixMs = 0, solveMs = 0;
};

static void run_scale(Stats& st, uint64_t seed) {
    const char* fam = "scale";
    ++st.cases;
    heap_reset();
    g_waUsed = g_waFixed;
    g_maUsed = g_maFixed;
    std::memset(P(PFA), 0, kPfBytes);
    std::memset(P(PFB), 0, kPfBytes);
    wrf(M + 0x84, -1.0e6f); wrf(M + 0x88, -1.0e6f); wrf(M + 0x8C, 1.0e6f); wrf(M + 0x90, 1.0e6f);
    Rng rng(mix64(seed ^ 0x5CA1Eull));
    World W;
    build_grid(W, kScaleSide, kScalePitch);
    for (uint32_t k = 0; k < kScaleRequests; ++k) build_grid_req(W, rng, kScaleSide, kScalePitch, k);
    std::vector<uint32_t> reqA, reqB;
    for (int side = 0; side < 2; ++side) {
        std::vector<uint32_t>& v = side == 0 ? reqA : reqB;
        for (uint32_t k = 0; k < kScaleRequests; ++k) {
            ReqOpt o;
            o.radius = 0.5f + 0.25f * static_cast<float>(k % 4);
            v.push_back(make_req(W.req[k], o));
        }
        for (uint32_t k = 0; k + 1 < kScaleRequests; ++k) wr32(v[k] + 0x24, v[k + 1]);
    }
    wr32(PFA + 0x130, reqA[0]);
    wr32(PFB + 0x130, reqB[0]);

    // reference: the ORIGINAL driver, same prefix, sequential (first run warms pages / caches, second one is recorded)
    ScaleRef ref;
    for (int rep = 0; rep < 2; ++rep) {
        if (!construct_g(PFB)) { report(st, true, fam, 0, "G constructor produced an unexpected object"); return; }
        ref = ScaleRef();
        const bool f = !guarded([&] {
            for (uint32_t k = 0; k < kScaleRequests; ++k) {
                Inputs in;
                const LARGE_INTEGER a = qpc();
                do_prefix(PFB, reqB[k], &in);
                const LARGE_INTEGER b = qpc();
                const uint32_t res = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(in.g), nullptr, P(in.q), P(in.start), P(in.goal), P(in.via), in.flag) & 0xFF;
                const LARGE_INTEGER c = qpc();
                ref.prefixMs += ms_between(a, b);
                ref.solveMs += ms_between(b, c);
                ref.snap.push_back(take_snap(PFB, reqB[k], res));
                ref.expansions += rd32(PFB + 0x1BC + 0xE4);
                ref.outNodes += rd32(PFB + 0x1BC + 0xF4);
                ref.found += res ? 1u : 0u;
            }
        });
        if (f) { report(st, true, fam, 0, "ORIGINAL 0x8026F0 reference faulted on the scale scene: %s", fault_text().c_str()); return; }
    }
    if (!heap_canaries_ok()) { report(st, true, fam, 0, "host heap canary violated by the reference run"); return; }
    std::printf("SCALE scene lattice=%ux%u requests=%u found=%u expansions=%u (%.1f per request) output_nodes=%u native_prefix_ms=%.3f native_solve_ms=%.3f\n",
                kScaleSide, kScaleSide, kScaleRequests, ref.found, ref.expansions, static_cast<double>(ref.expansions) / kScaleRequests, ref.outNodes, ref.prefixMs, ref.solveMs);
    if (ref.found == 0 || ref.expansions < 32u * kScaleRequests) {
        report(st, true, fam, 0, "the scale scene did not reach its intended size (found=%u, expansions=%u): synthesised geometry is not a supported substantial search", ref.found, ref.expansions);
        return;
    }
    const Digests dWorld = take_digests();

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uint32_t cpus = si.dwNumberOfProcessors;
    const uint32_t teamWorkers = cpus > 1 ? std::min(cpus - 1, 4u) : 0u;
    uint32_t teamChunks = 0, teamPassesRun = 0;

    const uint32_t nPasses = 1 + (teamWorkers ? kTeamPasses : 0);
    for (uint32_t pass = 0; pass < nPasses; ++pass) {
        const bool team = pass > 0;
        const char* label = team ? "team" : "inline";
        if (!construct_g(PFA)) { report(st, true, fam, pass, "G constructor produced an unexpected object"); return; }
        npr_config c = base_cfg(0, kScaleRequests);
        c.maxNewPerTick = kScaleRequests;   // this family deliberately exercises one large, same-tick worker batch
        c.nodeBlocks = 40; c.entryBlocks = 16; c.hashLevels = 6; c.neighborCapacity = 16; c.openCapacity = 2048;
        if (team) {
            const ntw_u32 pr = shared_pool_start(teamWorkers);
            if (pr != NTW_POOL_OK) { report(st, true, fam, pass, "shared pool init failed (%u)", pr); return; }
            c.pool = A32(g_sharedPoolMem);
        }
        const uint32_t e = rt_init(c);
        if (e != 0) { report(st, true, fam, pass, "runtime initialize returned %08x", e); if (team) ntw_pool_shutdown(reinterpret_cast<ntw_pool*>(g_sharedPoolMem)); return; }
        const Digests d0 = take_digests();
        const Cnt c0 = snapc();
#ifdef NPR_TIMING
        uint64_t timingBefore[8];
        for (uint32_t i = 0; i < 8; ++i) timingBefore[i] = npr_timing_ticks[i];
#endif
        double prepassMs = 0, prefixMs = 0, solveMs = 0;
        uint32_t compared = 0;
        bool pass_ok = true;
        bool f = !guarded([&] {
            const LARGE_INTEGER a = qpc();
            npr_prepass(P(PFA));
            prepassMs = ms_between(a, qpc());
        });
        if (!f) {
            const Digests d1 = take_digests();
            if (d1.world != d0.world || d1.mut != d0.mut || d1.heap != d0.heap) { report(st, false, fam, pass, "prepass wrote game memory"); pass_ok = false; }
            f = !guarded([&] {
                uint32_t k = 0;
                for (uint32_t req = rd32(PFA + 0x130); req != 0 && k < kScaleRequests; req = rd32(req + 0x24), ++k) {
                    Inputs in;
                    const LARGE_INTEGER a = qpc();
                    do_prefix(PFA, req, &in);
                    const LARGE_INTEGER b = qpc();
                    const uint32_t res = npr_solve(P(in.g), nullptr, P(in.q), P(in.start), P(in.goal), P(in.via), in.flag) & 0xFF;
                    const LARGE_INTEGER d = qpc();
                    prefixMs += ms_between(a, b);
                    solveMs += ms_between(b, d);
                    const Snap sa = take_snap(PFA, req, res);
                    std::string why;
                    if (!compare_snaps(sa, ref.snap[k], why)) { report(st, false, fam, pass, "%s request %u: %s", label, k, why.c_str()); pass_ok = false; }
                    else { st.records += static_cast<uint32_t>(sa.r.size()); ++compared; if (res) ++st.found; else ++st.nopath; }
                }
            });
            if (!f) f = !guarded([&] { npr_end(P(PFA)); });
        }
        const Cnt c1 = snapc();
        const ntw_pool* pl = reinterpret_cast<const ntw_pool*>(g_sharedPoolMem);
        uint32_t poolCalls = 0, poolTeam = 0, poolWoken = 0, poolMain = 0, slotChunks = 0, slotWakes = 0;
        if (team) {
            poolCalls = pl->st_calls; poolTeam = pl->st_team; poolWoken = pl->st_woken; poolMain = pl->st_main_chunks;
            for (uint32_t i = 0; i < pl->workers && i < NTW_POOL_MAX_WORKERS; ++i) { slotChunks += pl->slots[i].chunks; slotWakes += pl->slots[i].wakes; }
        }
        if (f) { report(st, true, fam, pass, "scale pass faulted: %s", fault_text().c_str()); pass_ok = false; }
        st.solves += compared;
        if (compared != kScaleRequests && !f) { report(st, false, fam, pass, "%u of %u requests were compared", compared, kScaleRequests); pass_ok = false; }
        const uint32_t consumed = dc(c0, c1, NPR_S_CONSUMED), fallbacks = dc(c0, c1, NPR_S_FALLBACKS), callbacks = dc(c0, c1, NPR_S_CALLBACKS);
        st.consumed += consumed; st.fallbacks += fallbacks;
        if (consumed != kScaleRequests || fallbacks != 0) { report(st, false, fam, pass, "%s: consumed %u fallbacks %u, expected %u / 0 (every request is within the supported subset and capacities)", label, consumed, fallbacks, kScaleRequests); pass_ok = false; }
        if (callbacks == 0) { report(st, false, fam, pass, "%s: no original successor callback ran", label); pass_ok = false; }
        const uint32_t wchunks = dc(c0, c1, NPR_S_WORKER_CHUNKS), rounds = dc(c0, c1, NPR_S_TEAM_STEPS);
        const double rtMs = prepassMs + prefixMs + solveMs, natMs = ref.prefixMs + ref.solveMs;
        std::printf("SCALE pass=%s workers=%u prepass_ms=%.3f prefix_ms=%.3f solve_ms=%.3f runtime_total_ms=%.3f native_total_ms=%.3f runtime_over_native=%.2f callbacks=%u team_batches=%u worker_chunks=%u pool_calls=%u pool_team_dispatches=%u pool_woken=%u pool_main_chunks=%u pool_slot_chunks=%u pool_slot_wakes=%u\n",
                    label, team ? teamWorkers : 0u, prepassMs, prefixMs, solveMs, rtMs, natMs, natMs > 0 ? rtMs / natMs : 0.0, callbacks, rounds, wchunks,
                    poolCalls, poolTeam, poolWoken, poolMain, slotChunks, slotWakes);
#ifdef NPR_TIMING
        LARGE_INTEGER frequency;
        QueryPerformanceFrequency(&frequency);
        double timingMs[8];
        for (uint32_t i = 0; i < 8; ++i)
            timingMs[i] = 1000.0 * static_cast<double>(npr_timing_ticks[i] - timingBefore[i]) / static_cast<double>(frequency.QuadPart);
        // Worker advance is aggregate CPU time, overlapping the owner's work: never add it to prepass wall time.
        // Footprint includes the branch safety gate and post-callback node/domain checks, not just memcpy.
        // Wait covers unsuccessful scan/claim/pause iterations; productive handoff overhead is in residual.
        const double ownerAccounted = timingMs[0] + timingMs[1] + timingMs[2] + timingMs[3] + timingMs[5] + timingMs[6];
        std::printf("SCALE timing pass=%s callback_ms=%.3f footprint_gate_record_ms=%.3f seal_ms=%.3f owner_advance_ms=%.3f worker_advance_cpu_ms=%.3f handoff_wait_ms=%.3f setup_ms=%.3f validate_materialize_ms=%.3f prepass_residual_ms=%.3f instrumentation=QPC (timer overhead not subtracted)\n",
                    label, timingMs[0], timingMs[1], timingMs[2], timingMs[3], timingMs[4], timingMs[5], timingMs[6], timingMs[7], prepassMs - ownerAccounted);
#else
        std::printf("SCALE timing pass=%s validate_materialize_outer_ms=%.3f detail=disabled (define NPR_TIMING for runtime and oracle; diagnostic QPC overhead is not subtracted)\n",
                    label, solveMs);
#endif
        if (team) { teamChunks += wchunks; ++teamPassesRun; }
        const uint32_t sr = rt_stop();
        if (sr != NPR_OK) { report(st, true, fam, pass, "npr_stop returned %08x", sr); pass_ok = false; }
        if (team) {
            const ntw_u32 pr = ntw_pool_shutdown(reinterpret_cast<ntw_pool*>(g_sharedPoolMem));
            if (pr != NTW_POOL_OK) { report(st, true, fam, pass, "shared pool shutdown returned %u", pr); pass_ok = false; }
        }
        if (!pass_ok) break;
    }
    if (!heap_canaries_ok()) report(st, true, fam, 0, "host heap canary violated");
    const Digests dEnd = take_digests();
    if (dEnd.world != dWorld.world) report(st, false, fam, 0, "synthesised world bytes changed during the scale scene");
    st.workerChunks += teamChunks;
    if (teamWorkers == 0) std::printf("INFO scale: single-CPU machine, team passes skipped\n");
    else if (teamPassesRun == kTeamPasses && teamChunks == 0)
        report(st, false, fam, 0, "the worker team executed no chunk in %u passes of %u requests (%u workers): no parallel execution observed", kTeamPasses, kScaleRequests, teamWorkers);
    else if (teamPassesRun == kTeamPasses) std::printf("PARALLEL scale: workers executed %u chunks over %u team passes\n", teamChunks, kTeamPasses);
}

// ---------------------------------------------------------------------------------------------------------------------
static bool check_constants() {
    bool ok = true;
    const pw::Constants k;
    const float* s = static_cast<const float*>(P(N(VA_SENTINEL)));
    ok &= bits(s[0]) == bits(k.sentinelPair[0]) && bits(s[1]) == bits(k.sentinelPair[1]);
    ok &= bits(s[2]) == bits(k.sentinelPos[0]) && bits(s[3]) == bits(k.sentinelPos[1]) && bits(s[4]) == bits(k.sentinelPos[2]);
    std::printf("CONST sentinels=%08x,%08x,%08x,%08x,%08x -> %s\n", bits(s[0]), bits(s[1]), bits(s[2]), bits(s[3]), bits(s[4]), ok ? "match workspace defaults" : "DIFFER");
    return ok;
}

static void print_family(const char* name, const Stats& st) {
    std::printf("FAMILY %s cases=%u solves=%u consumed=%u fallbacks=%u found=%u nopath=%u vias=%u stale=%u records=%u skipped=0 mismatches=%u plumbing=%u\n",
                name, st.cases, st.solves, st.consumed, st.fallbacks, st.found, st.nopath, st.vias, st.stale, st.records, st.mismatches, st.plumbing);
}

// ---------------------------------------------------------------------------------------------------------------------
// cross-tick persistence families (own sessions; every solve is compared bit for bit with the ORIGINAL 0x8026F0 on PFB, run in
// lockstep after the runtime's solve so mutations made between ticks reach both sides identically).
//   persist-cross-tick   plan in tick N (one new request per tick), consume in tick N+k: no re-plan, no callback while cached
//   persist-cross-stale  world / request inputs change between ticks: STALE + original fallback, still bit-identical
//   persist-evict        capacity eviction (oldest planning tick outside the scheduler-order window), no churn when the
//                        window is full of live results, evicted request falls back and is planned again later
//   persist-cap          at most maxNewPerTick NEW plans per tick, queue (scheduler) order, refusal memory keeps a refused
//                        head request from burning the budget every tick
//   persist-reuse        request identity: query bytes changed / request left the queue -> result dropped, re-planned
//   persist-stop         npr_stop disposes carried results (UNUSED) and counts no eviction
struct PQ {
    World W;
    std::vector<uint32_t> A, B;   // runtime-side and reference-side request objects (identical bytes)
};
struct PqDelta { uint32_t v[NPR_STATE_WORDS]; };

static bool pq_open(Stats& st, const char* fam, uint32_t slots, uint32_t maxNew) {
    npr_config c = base_cfg(0, slots);
    c.maxNewPerTick = maxNew;
    const uint32_t e = rt_init(c);
    if (e != NPR_OK) { report(st, true, fam, 0, "initialize returned %08x", e); return false; }
    return true;
}
static void pq_close(Stats& st, const char* fam) {
    const uint32_t e = rt_stop();
    if (e != NPR_OK) report(st, true, fam, 0, "stop returned %08x", e);
}

static bool pq_setup(PQ& q, Stats& st, const char* fam, uint32_t idx, uint64_t seed, uint32_t nreq, uint32_t pendingMask, uint32_t specialMask) {
    ++st.cases;
    if (!retire_queue()) { report(st, true, fam, idx, "retiring the previous fixture faulted: %s", fault_text().c_str()); return false; }
    heap_reset();
    g_waUsed = g_waFixed;
    g_maUsed = g_maFixed;
    std::memset(P(PFA), 0, kPfBytes);
    std::memset(P(PFB), 0, kPfBytes);
    if (!construct_g(PFA) || !construct_g(PFB)) { report(st, true, fam, idx, "G constructor produced an unexpected object"); return false; }
    wrf(M + 0x84, -1.0e6f);
    wrf(M + 0x90, 1.0e6f);
    Rng rng(mix64(seed ^ (std::hash<std::string>()(fam) * 31ull + idx)));
    WP wp;
    wp.n = rng.r(8, 12); wp.maxDeg = rng.r(2, 4); wp.nreg = 1; wp.pAcc = 1.0f; wp.pRec = 0.0f;
    q.W = World();
    build_world(q.W, rng, wp);
    for (uint32_t k = 0; k < nreq; ++k) build_reqw(q.W, rng, false, false, wp.n);
    g_maUsed = g_maFixed;
    q.A.clear(); q.B.clear();
    for (int side = 0; side < 2; ++side) {
        std::vector<uint32_t>& v = side == 0 ? q.A : q.B;
        for (uint32_t k = 0; k < nreq; ++k) {
            ReqOpt o;
            o.flagByte = 1;
            o.radius = 0.5f + 0.25f * static_cast<float>(k % 4);
            o.special = ((specialMask >> k) & 1u) != 0;
            v.push_back(make_req(q.W.req[k], o));
        }
        for (uint32_t k = 0; k + 1 < nreq; ++k) wr32(v[k] + 0x24, v[k + 1]);
    }
    wr32(PFA + 0x130, q.A[0]);
    wr32(PFB + 0x130, q.B[0]);
    for (uint32_t k = 0; k < nreq; ++k)
        if (((pendingMask >> k) & 1u) == 0) { wr32(q.A[k] + 0x14, 3); wr32(q.B[k] + 0x14, 3); }
    return true;
}

// one scheduler tick: prepass, then the listed requests are solved (runtime, then ORIGINAL in lockstep), then npr_end.
static bool pq_tick(PQ& q, Stats& st, const char* fam, uint32_t idx, const char* label, const std::vector<uint32_t>& solves, PqDelta* out) {
    bool ok = true;
    const Digests d0 = take_digests();
    const Cnt c0 = snapc();
    if (!guarded([&] { npr_prepass(P(PFA)); })) { report(st, true, fam, idx, "%s: prepass faulted: %s", label, fault_text().c_str()); return false; }
    const Digests d1 = take_digests();
    if (d1.world != d0.world || d1.mut != d0.mut || d1.heap != d0.heap) { report(st, false, fam, idx, "%s: prepass wrote game memory", label); ok = false; }
    for (uint32_t k : solves) {
        Inputs ia, ib;
        uint32_t ra = 0, rb = 0;
        if (!guarded([&] {
                do_prefix(PFA, q.A[k], &ia);
                ra = npr_solve(P(ia.g), nullptr, P(ia.q), P(ia.start), P(ia.goal), P(ia.via), ia.flag) & 0xFF;
            })) { report(st, true, fam, idx, "%s: runtime solve of request %u faulted: %s", label, k, fault_text().c_str()); return false; }
        const Snap sa = take_snap(PFA, q.A[k], ra);
        if (!guarded([&] {
                do_prefix(PFB, q.B[k], &ib);
                rb = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(ib.g), nullptr, P(ib.q), P(ib.start), P(ib.goal), P(ib.via), ib.flag) & 0xFF;
            })) { report(st, true, fam, idx, "%s: ORIGINAL 0x8026F0 reference of request %u faulted: %s", label, k, fault_text().c_str()); return false; }
        const Snap sb = take_snap(PFB, q.B[k], rb);
        std::string why;
        ++st.solves;
        if (!compare_snaps(sa, sb, why)) { report(st, false, fam, idx, "%s: request %u: %s", label, k, why.c_str()); ok = false; }
        else { st.records += static_cast<uint32_t>(sb.r.size()); if (rb) ++st.found; else ++st.nopath; }
        wr32(q.A[k] + 0x14, 3);   // the scheduler marks a solved request terminal (state 3)
        wr32(q.B[k] + 0x14, 3);
    }
    if (!guarded([&] { npr_end(P(PFA)); })) { report(st, true, fam, idx, "%s: npr_end faulted: %s", label, fault_text().c_str()); return false; }
    const Cnt c1 = snapc();
    if (!heap_canaries_ok()) { report(st, true, fam, idx, "%s: host heap canary violated", label); ok = false; }
    if (take_digests().world != d0.world) { report(st, false, fam, idx, "%s: synthesised world bytes changed during the tick", label); ok = false; }
    if (npr_state[NPR_S_OWNER_THREAD] != 0) { report(st, false, fam, idx, "%s: owner thread still published after the tick", label); ok = false; }
    for (uint32_t w = 0; w < NPR_STATE_WORDS; ++w) out->v[w] = dc(c0, c1, w);
    st.consumed += out->v[NPR_S_CONSUMED];
    st.fallbacks += out->v[NPR_S_FALLBACKS];
    st.stale += out->v[NPR_S_STALE];
    return ok;
}

static void pq_eq(Stats& st, const char* fam, uint32_t idx, const char* label, const PqDelta& d, uint32_t w, const char* name, uint32_t want) {
    if (d.v[w] != want) report(st, false, fam, idx, "%s: %s delta %u, expected %u", label, name, d.v[w], want);
}
// Scenario bodies are functions (st, fam, idx, seed in scope) that return at the first failed tick.
#define PQ_EQ(label, w, want) pq_eq(st, fam, idx, label, d, w, #w, want)
// Callbacks only run while planning: positive in a tick that planned, exactly zero in a tick that planned nothing.
#define PQ_CB(label, positive) do { if ((d.v[NPR_S_CALLBACKS] != 0) != (positive)) report(st, false, fam, idx, "%s: NPR_S_CALLBACKS delta %u, expected %s", label, d.v[NPR_S_CALLBACKS], (positive) ? "> 0" : "0"); } while (0)
#define PQ_TICK(label, ...) do { if (!pq_tick(q, st, fam, idx, label, std::vector<uint32_t>{__VA_ARGS__}, &d)) return; } while (0)

static void scn_cross_tick(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 0)) return;
    PQ_TICK("t1");
    PQ_EQ("t1", NPR_S_PLANNED, 1); PQ_EQ("t1", NPR_S_CARRIED, 1); PQ_EQ("t1", NPR_S_UNUSED, 0); PQ_EQ("t1", NPR_S_CONSUMED, 0); PQ_CB("t1", true);
    PQ_TICK("t2");
    PQ_EQ("t2", NPR_S_PLANNED, 1); PQ_EQ("t2", NPR_S_CARRIED, 2); PQ_EQ("t2", NPR_S_UNUSED, 0); PQ_CB("t2", true);   // request 0 is not planned again
    PQ_TICK("t3");
    PQ_EQ("t3", NPR_S_PLANNED, 1); PQ_EQ("t3", NPR_S_CARRIED, 3); PQ_CB("t3", true);
    PQ_TICK("t4", 1);                                                                                              // planned in tick 2, consumed in tick 4
    PQ_EQ("t4", NPR_S_PLANNED, 0); PQ_CB("t4", false); PQ_EQ("t4", NPR_S_CONSUMED, 1); PQ_EQ("t4", NPR_S_FALLBACKS, 0); PQ_EQ("t4", NPR_S_STALE, 0); PQ_EQ("t4", NPR_S_CARRIED, 2);
    PQ_TICK("t5", 0, 2);                                                                                           // planned in ticks 1 and 3, consumed in tick 5
    PQ_EQ("t5", NPR_S_PLANNED, 0); PQ_CB("t5", false); PQ_EQ("t5", NPR_S_CONSUMED, 2); PQ_EQ("t5", NPR_S_FALLBACKS, 0); PQ_EQ("t5", NPR_S_STALE, 0);
    PQ_EQ("t5", NPR_S_CARRIED, 0); PQ_EQ("t5", NPR_S_UNUSED, 0); PQ_EQ("t5", NPR_S_EVICTED, 0);
}

// The request prefix writes bookkeeping outside Q (810035 req+1C, 81003C req+14,
// 8101C5 req+DA and pf counters). Q padding/non-input fields must not become identity.
// State must remain 0 while pending; terminal states still invalidate at prepass.
static void mutate_noninputs(uint32_t req, uint32_t pf, uint32_t salt) {
    const uint32_t q = req + 0x28;
    wr32(req + 0x1C, salt);
    wr32(pf + 0x6C4, rd32(pf + 0x6C4) + 1);
    wr8(req + 0xDA, 0); // the noninputs family forces the outside-rect branch, whose solve flag is always 1
    // Q+0x28 is the goal-position transform POINTER (7EB210 -> 80E9D0 -> 7F4950 dereferences it): never a padding field.
    wr32(q + 0x30, salt ^ 0x12345678u);
    wr32(q + 0x38, salt ^ 0x87654321u); // special goal is zero: this field is not read
    for (uint32_t j = 0x51; j < 0x58; ++j) wr8(q + j, static_cast<uint8_t>(salt + j));
}

static void scn_noninputs(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 0)) return;
    wrf(M + 0x84, 1.0e6f); // outside rect: native prefix normalizes req+DA to 1 before solve
    PQ_TICK("n-t1");
    PQ_EQ("n-t1", NPR_S_PLANNED, 3);
    for (uint32_t t = 0; t < 3; ++t) {
        for (uint32_t k = 0; k < 3; ++k) {
            mutate_noninputs(q.A[k], PFA, 17 + t + k);
            mutate_noninputs(q.B[k], PFB, 17 + t + k);
        }
        PQ_TICK("n-held");
        PQ_EQ("n-held", NPR_S_PLANNED, 0); PQ_EQ("n-held", NPR_S_UNUSED, 0);
        PQ_EQ("n-held", NPR_S_INVALID_QUERY, 0); PQ_CB("n-held", false);
    }
    // A second mutation after prepass exercises consume equality and the footprint,
    // not just the queue-identity comparison.
    const Cnt before = snapc();
    if (!guarded([&] { npr_prepass(P(PFA)); })) {
        report(st, true, fam, idx, "n-consume: prepass faulted: %s", fault_text().c_str()); return;
    }
    for (uint32_t k = 0; k < 3; ++k) {
        mutate_noninputs(q.A[k], PFA, 91 + k);
        mutate_noninputs(q.B[k], PFB, 91 + k);
        Inputs ia, ib; uint32_t ra = 0, rb = 0;
        if (!guarded([&] {
            do_prefix(PFA, q.A[k], &ia);
            ra = npr_solve(P(ia.g), nullptr, P(ia.q), P(ia.start), P(ia.goal), P(ia.via), ia.flag) & 0xFF;
            do_prefix(PFB, q.B[k], &ib);
            rb = reinterpret_cast<SolveFn>(P(N(VA_SOLVE)))(P(ib.g), nullptr, P(ib.q), P(ib.start), P(ib.goal), P(ib.via), ib.flag) & 0xFF;
        })) {
            report(st, true, fam, idx, "n-consume faulted: %s", fault_text().c_str());
            npr_end(P(PFA)); return;
        }
        std::string why;
        ++st.solves;
        if (!compare_snaps(take_snap(PFA, q.A[k], ra), take_snap(PFB, q.B[k], rb), why))
            report(st, false, fam, idx, "n-consume request %u: %s", k, why.c_str());
        else if (rb) ++st.found; else ++st.nopath;
        wr32(q.A[k] + 0x14, 3); wr32(q.B[k] + 0x14, 3);
    }
    npr_end(P(PFA));
    const Cnt after = snapc();
    for (uint32_t w = 0; w < NPR_STATE_WORDS; ++w) d.v[w] = dc(before, after, w);
    st.consumed += d.v[NPR_S_CONSUMED]; st.fallbacks += d.v[NPR_S_FALLBACKS]; st.stale += d.v[NPR_S_STALE];
    PQ_EQ("n-consume", NPR_S_CONSUMED, 3); PQ_EQ("n-consume", NPR_S_FALLBACKS, 0);
    PQ_EQ("n-consume", NPR_S_STALE, 0); PQ_EQ("n-consume", NPR_S_UNUSED, 0); PQ_CB("n-consume", false);
    if (!heap_canaries_ok()) report(st, true, fam, idx, "n-consume: host heap canary violated");
}

// request-private inputs change between ticks: exactly those results go STALE (flag byte of request 1, start position of request 2)
static void scn_stale_private(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 0)) return;
    PQ_TICK("a-t1");
    PQ_EQ("a-t1", NPR_S_PLANNED, 3); PQ_EQ("a-t1", NPR_S_CARRIED, 3);
    wr8(q.A[1] + 0xDA, rd8(q.A[1] + 0xDA) ^ 1); wr8(q.B[1] + 0xDA, rd8(q.B[1] + 0xDA) ^ 1);
    wrf(q.W.req[2].BASE + 0x6C8, rdf(q.W.req[2].BASE + 0x6C8) + 0.5f);
    PQ_TICK("a-t2", 0, 1, 2);
    PQ_EQ("a-t2", NPR_S_PLANNED, 0); PQ_CB("a-t2", false); PQ_EQ("a-t2", NPR_S_CONSUMED, 1); PQ_EQ("a-t2", NPR_S_STALE, 2); PQ_EQ("a-t2", NPR_S_FALLBACKS, 2);
    PQ_EQ("a-t2", NPR_S_UNUSED, 0);
}

// shared world data changes between ticks: every result that read it must fall back; the rest are consumed
static void scn_stale_world(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 0)) return;
    PQ_TICK("b-t1");
    PQ_EQ("b-t1", NPR_S_PLANNED, 3);
    const uint32_t e0 = q.W.edges[q.W.req[1].startObj][0];
    wrf(e0 + 0x30, rdf(e0 + 0x30) + 0.75f);
    PQ_TICK("b-t2", 0, 1, 2);
    if (d.v[NPR_S_STALE] < 1) report(st, false, fam, idx, "b-t2: no private result went stale although a recorded edge changed");
    PQ_EQ("b-t2", NPR_S_CONSUMED, 3 - d.v[NPR_S_STALE]); PQ_EQ("b-t2", NPR_S_FALLBACKS, d.v[NPR_S_STALE]); PQ_CB("b-t2", false);
}

// results planned for requests 2,3 are evicted when requests 0,1 become the first two eligible (window = slots)
static void scn_evict(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 4, 0xC, 0)) return;
    PQ_TICK("a-t1");
    PQ_EQ("a-t1", NPR_S_PLANNED, 2); PQ_EQ("a-t1", NPR_S_CARRIED, 2); PQ_EQ("a-t1", NPR_S_EVICTED, 0); PQ_EQ("a-t1", NPR_S_UNUSED, 0);
    for (uint32_t k = 0; k < 2; ++k) { wr32(q.A[k] + 0x14, 0); wr32(q.B[k] + 0x14, 0); }
    PQ_TICK("a-t2", 0, 1, 2);
    PQ_EQ("a-t2", NPR_S_PLANNED, 2); PQ_EQ("a-t2", NPR_S_EVICTED, 2); PQ_EQ("a-t2", NPR_S_UNUSED, 2);
    PQ_EQ("a-t2", NPR_S_CONSUMED, 2); PQ_EQ("a-t2", NPR_S_FALLBACKS, 1); PQ_EQ("a-t2", NPR_S_STALE, 0); PQ_EQ("a-t2", NPR_S_CARRIED, 0);   // request 2 lost its result -> original
    PQ_TICK("a-t3", 3);                                                                                                                       // request 3 is planned again, then consumed
    PQ_EQ("a-t3", NPR_S_PLANNED, 1); PQ_EQ("a-t3", NPR_S_CONSUMED, 1); PQ_EQ("a-t3", NPR_S_FALLBACKS, 0); PQ_EQ("a-t3", NPR_S_EVICTED, 0); PQ_EQ("a-t3", NPR_S_UNUSED, 0);
}

// all four pending: the two live results stay protected (no churn); requests 2,3 are planned only after 0,1 are gone
static void scn_no_churn(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 4, 0xF, 0)) return;
    PQ_TICK("b-t1");
    PQ_EQ("b-t1", NPR_S_PLANNED, 2); PQ_EQ("b-t1", NPR_S_CARRIED, 2);
    PQ_TICK("b-t2");
    PQ_EQ("b-t2", NPR_S_PLANNED, 0); PQ_CB("b-t2", false); PQ_EQ("b-t2", NPR_S_EVICTED, 0); PQ_EQ("b-t2", NPR_S_UNUSED, 0); PQ_EQ("b-t2", NPR_S_CARRIED, 2);
    PQ_TICK("b-t3");
    PQ_EQ("b-t3", NPR_S_PLANNED, 0); PQ_CB("b-t3", false); PQ_EQ("b-t3", NPR_S_EVICTED, 0); PQ_EQ("b-t3", NPR_S_CARRIED, 2);
    PQ_TICK("b-t4", 0, 1);
    PQ_EQ("b-t4", NPR_S_PLANNED, 0); PQ_EQ("b-t4", NPR_S_CONSUMED, 2); PQ_EQ("b-t4", NPR_S_FALLBACKS, 0);
    PQ_TICK("b-t5");
    PQ_EQ("b-t5", NPR_S_PLANNED, 2); PQ_EQ("b-t5", NPR_S_CARRIED, 2);
    PQ_TICK("b-t6", 2, 3);
    PQ_EQ("b-t6", NPR_S_PLANNED, 0); PQ_EQ("b-t6", NPR_S_CONSUMED, 2); PQ_EQ("b-t6", NPR_S_FALLBACKS, 0); PQ_EQ("b-t6", NPR_S_EVICTED, 0);
}

// maxNewPerTick = 2: queue order, two new plans per tick
static void scn_cap(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 4, 0xF, 0)) return;
    PQ_TICK("t1", 0, 1, 2);                                                  // 0,1 planned (consumed); 2 was not planned yet -> original
    PQ_EQ("t1", NPR_S_PLANNED, 2); PQ_EQ("t1", NPR_S_CONSUMED, 2); PQ_EQ("t1", NPR_S_FALLBACKS, 1); PQ_EQ("t1", NPR_S_STALE, 0);
    PQ_TICK("t2", 3);
    PQ_EQ("t2", NPR_S_PLANNED, 1); PQ_EQ("t2", NPR_S_CONSUMED, 1); PQ_EQ("t2", NPR_S_FALLBACKS, 0);
}

// maxNewPerTick = 1 with a refused head request (special goal): it is refused once, then costs no budget
static void scn_refusal(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 1)) return;
    PQ_TICK("r-t1");
    PQ_EQ("r-t1", NPR_S_REJECTED, 1); PQ_EQ("r-t1", NPR_S_PLANNED, 0); PQ_CB("r-t1", false);
    PQ_TICK("r-t2");
    PQ_EQ("r-t2", NPR_S_REJECTED, 0); PQ_EQ("r-t2", NPR_S_PLANNED, 1); PQ_EQ("r-t2", NPR_S_CARRIED, 1);   // request 1 planned, request 0 is not retried
    PQ_TICK("r-t3");
    PQ_EQ("r-t3", NPR_S_REJECTED, 0); PQ_EQ("r-t3", NPR_S_PLANNED, 1); PQ_EQ("r-t3", NPR_S_CARRIED, 2);
    PQ_TICK("r-t4", 0, 1, 2);
    PQ_EQ("r-t4", NPR_S_REJECTED, 0); PQ_EQ("r-t4", NPR_S_PLANNED, 0); PQ_EQ("r-t4", NPR_S_CONSUMED, 2); PQ_EQ("r-t4", NPR_S_FALLBACKS, 1);
    PQ_EQ("r-t4", NPR_S_REFUSAL_MEMORY, 1);
}

// Capacity is transient even with identical query bytes; a failed attempt must not
// leave a refusal-memory entry when the world's edge count subsequently shrinks.
static void scn_transient_refusal(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 1, 1, 0)) return;
    const uint32_t countAddr = q.W.obj[q.W.req[0].startObj] + 0x34;
    const uint32_t saved = rd32(countAddr);
    wr32(countAddr, 0x10000); // gate rejects before touching the edge array
    PQ_TICK("capacity-t1");
    PQ_EQ("capacity-t1", NPR_S_REJECTED, 1); PQ_EQ("capacity-t1", NPR_S_REFUSAL_MEMORY, 0); PQ_CB("capacity-t1", false);
    PQ_TICK("capacity-t2");
    PQ_EQ("capacity-t2", NPR_S_REJECTED, 1); PQ_EQ("capacity-t2", NPR_S_REFUSAL_MEMORY, 0); PQ_CB("capacity-t2", false);
    if (NPR_REJECT_COUNT(npr_state[NPR_S_REJECT_KINDS], NPR_REJECT_CAPACITY) == 0)
        report(st, false, fam, idx, "capacity refusal kind was not exported");
    wr32(countAddr, saved);
    PQ_TICK("capacity-t3", 0);
    PQ_EQ("capacity-t3", NPR_S_PLANNED, 1); PQ_EQ("capacity-t3", NPR_S_CONSUMED, 1);
    PQ_EQ("capacity-t3", NPR_S_FALLBACKS, 0); PQ_EQ("capacity-t3", NPR_S_REFUSAL_MEMORY, 0);
}

static void scn_refusal_changed(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 1, 1, 1)) return;
    PQ_TICK("changed-t1");
    PQ_EQ("changed-t1", NPR_S_REJECTED, 1);
    mutate_noninputs(q.A[0], PFA, 13); mutate_noninputs(q.B[0], PFB, 13);
    PQ_TICK("changed-t2");
    PQ_EQ("changed-t2", NPR_S_REJECTED, 0); PQ_EQ("changed-t2", NPR_S_REFUSAL_MEMORY, 1);
    wr32(q.A[0] + 0x28 + 0x34, 0); wr32(q.B[0] + 0x28 + 0x34, 0);
    PQ_TICK("changed-t3", 0);
    PQ_EQ("changed-t3", NPR_S_PLANNED, 1); PQ_EQ("changed-t3", NPR_S_CONSUMED, 1);
    PQ_EQ("changed-t3", NPR_S_REFUSAL_MEMORY, 0); PQ_EQ("changed-t3", NPR_S_FALLBACKS, 0);
    if (NPR_REJECT_COUNT(npr_state[NPR_S_REJECT_KINDS], NPR_REJECT_INPUT) == 0)
        report(st, false, fam, idx, "input refusal kind was not exported");
}

// A world-dependent gate refusal is not deterministic from query bytes alone.
static void scn_gate_retry(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 1, 1, 0)) return;
    const uint32_t e = q.W.edges[q.W.req[0].startObj][0];
    const uint32_t dst = rd32(e + 0x14);
    const uint32_t saved = rd32(dst + 0xC);
    wr8(e + 0x4C, 1);
    wr32(dst + 0x24, 0);
    const uint32_t vt = wnew(0x20);
    wr32(vt, A32(reinterpret_cast<void*>(&fake_iface_slot0)));
    wr32(dst + 0xC, vt);
    PQ_TICK("gate-t1");
    PQ_EQ("gate-t1", NPR_S_REJECTED, 1); PQ_EQ("gate-t1", NPR_S_REFUSAL_MEMORY, 0); PQ_CB("gate-t1", false);
    if (NPR_REJECT_COUNT(npr_state[NPR_S_REJECT_KINDS], NPR_REJECT_GATE) == 0)
        report(st, false, fam, idx, "callback gate refusal kind was not exported");
    wr32(dst + 0xC, saved);
    PQ_TICK("gate-t2", 0);
    PQ_EQ("gate-t2", NPR_S_PLANNED, 1); PQ_EQ("gate-t2", NPR_S_CONSUMED, 1);
    PQ_EQ("gate-t2", NPR_S_FALLBACKS, 0); PQ_EQ("gate-t2", NPR_S_REFUSAL_MEMORY, 0);
}

static void scn_walk_incomplete(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 2, 3, 0)) return;
    PQ_TICK("walk-t1");
    PQ_EQ("walk-t1", NPR_S_PLANNED, 2);
    wr32(q.A[0] + 0x24, q.A[0]); // bounded queue walk cannot prove request 1 is still present
    PQ_TICK("walk-t2", 0);
    PQ_EQ("walk-t2", NPR_S_INVALID_WALK, 1); PQ_EQ("walk-t2", NPR_S_INVALID_PENDING, 0);
    PQ_EQ("walk-t2", NPR_S_UNUSED, 1); PQ_EQ("walk-t2", NPR_S_CONSUMED, 1); PQ_CB("walk-t2", false);
    wr32(q.A[0] + 0x24, q.A[1]);
    PQ_TICK("walk-t3", 1);
    PQ_EQ("walk-t3", NPR_S_PLANNED, 1); PQ_EQ("walk-t3", NPR_S_CONSUMED, 1);
    PQ_EQ("walk-t3", NPR_S_FALLBACKS, 0); PQ_EQ("walk-t3", NPR_S_INVALID_WALK, 0);
}

// request identity: query bytes of request 1 change, request 0 leaves the queue
static void scn_reuse(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 3, 7, 0)) return;
    PQ_TICK("t1");
    PQ_EQ("t1", NPR_S_PLANNED, 3); PQ_EQ("t1", NPR_S_CARRIED, 3);
    wrf(q.A[1] + 0x28 + 0x2C, rdf(q.A[1] + 0x28 + 0x2C) + 1.0f);
    wrf(q.B[1] + 0x28 + 0x2C, rdf(q.B[1] + 0x28 + 0x2C) + 1.0f);
    wr32(PFA + 0x130, q.A[1]);
    wr32(PFB + 0x130, q.B[1]);
    PQ_TICK("t2", 1, 2);
    PQ_EQ("t2", NPR_S_UNUSED, 2); PQ_EQ("t2", NPR_S_EVICTED, 0); PQ_EQ("t2", NPR_S_PLANNED, 1); PQ_CB("t2", true);
    PQ_EQ("t2", NPR_S_INVALID_QUERY, 1); PQ_EQ("t2", NPR_S_INVALID_PENDING, 1);
    PQ_EQ("t2", NPR_S_CONSUMED, 2); PQ_EQ("t2", NPR_S_FALLBACKS, 0); PQ_EQ("t2", NPR_S_STALE, 0); PQ_EQ("t2", NPR_S_CARRIED, 0);
}

// npr_stop disposes the carried results (UNUSED) and counts no eviction
static void scn_stop(Stats& st, const char* fam, uint32_t idx, uint64_t seed) {
    PQ q; PqDelta d;
    if (!pq_setup(q, st, fam, idx, seed, 2, 3, 0)) return;
    PQ_TICK("t1");
    PQ_EQ("t1", NPR_S_PLANNED, 2); PQ_EQ("t1", NPR_S_CARRIED, 2);
    const Cnt c0 = snapc();
    const uint32_t e = rt_stop();
    const Cnt c1 = snapc();
    if (e != NPR_OK) report(st, true, fam, idx, "stop returned %08x", e);
    if (dc(c0, c1, NPR_S_UNUSED) != 2) report(st, false, fam, idx, "stop: NPR_S_UNUSED delta %u, expected 2", dc(c0, c1, NPR_S_UNUSED));
    if (dc(c0, c1, NPR_S_EVICTED) != 0) report(st, false, fam, idx, "stop: NPR_S_EVICTED delta %u, expected 0", dc(c0, c1, NPR_S_EVICTED));
}

// Each family owns its session(s); scenario(s) repeat over `reps` generated worlds.  scn_stop ends its own session.
static void persist_family(const char* fam, Stats& st, uint64_t seed, uint32_t reps) {
    typedef void (*Scn)(Stats&, const char*, uint32_t, uint64_t);
    struct Part { uint32_t slots, maxNew; Scn fn; uint32_t base; };
    std::vector<Part> parts;
    const std::string f = fam;
    if (f == "persist-cross-tick") parts = {{3, 1, scn_cross_tick, 0}};
    else if (f == "persist-cross-stale") parts = {{3, 3, scn_stale_private, 0}, {3, 3, scn_stale_world, 1000}};
    else if (f == "persist-evict") parts = {{2, 4, scn_evict, 0}, {2, 4, scn_no_churn, 1000}};
    else if (f == "persist-cap") parts = {{4, 2, scn_cap, 0}, {3, 1, scn_refusal, 1000}, {1, 1, scn_transient_refusal, 2000}, {1, 1, scn_refusal_changed, 3000}, {1, 1, scn_gate_retry, 4000}};
    else if (f == "persist-reuse") parts = {{3, 3, scn_reuse, 0}, {2, 2, scn_walk_incomplete, 1000}};
    else if (f == "persist-stop") parts = {{2, 4, scn_stop, 0}};
    else if (f == "persist-noninputs") parts = {{3, 3, scn_noninputs, 0}};
    for (const Part& p : parts) {
        if (p.fn == scn_stop) {
            for (uint32_t i = 0; i < reps; ++i) {
                if (!pq_open(st, fam, p.slots, p.maxNew)) return;
                p.fn(st, fam, p.base + i, seed);
                if (npr_state[NPR_S_PHASE] == 1) pq_close(st, fam);
            }
            continue;
        }
        if (!pq_open(st, fam, p.slots, p.maxNew)) return;
        for (uint32_t i = 0; i < reps; ++i) p.fn(st, fam, p.base + i, seed);
        pq_close(st, fam);
    }
}
static const char* kPersistFamilies[] = {"persist-cross-tick", "persist-cross-stale", "persist-evict", "persist-cap", "persist-reuse", "persist-stop", "persist-noninputs"};

int main(int argc, char** argv) {
    if (argc < 2) { std::fputs("usage: native_path_runtime_oracle <Napoleon.exe> [cases=N] [seed=S] [family=name] [verbose=1]\n", stderr); return 2; }
    uint32_t cases = 16;
    uint64_t seed = 20261013;
    std::string only;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind("cases=", 0) == 0) cases = static_cast<uint32_t>(std::strtoul(a.c_str() + 6, nullptr, 10));
        else if (a.rfind("seed=", 0) == 0) seed = std::strtoull(a.c_str() + 5, nullptr, 10);
        else if (a.rfind("family=", 0) == 0) only = a.substr(7);
        else if (a == "verbose=1") g_verbose = true;
    }
    g_heap = static_cast<uint8_t*>(VirtualAlloc(nullptr, g_heapCap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    g_wa = static_cast<uint8_t*>(VirtualAlloc(nullptr, kWaCap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    g_ma = static_cast<uint8_t*>(VirtualAlloc(nullptr, kMaCap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!g_heap || !g_wa || !g_ma) { std::fputs("arena allocation failed\n", stderr); return 3; }
    if (!map_image(argv[1])) return 2;
    patch_jmp(VA_ALLOC, reinterpret_cast<void*>(&host_alloc));
    patch_jmp(VA_FREE, reinterpret_cast<void*>(&host_free));
    patch_jmp(VA_AALLOC, reinterpret_cast<void*>(&host_aligned_alloc));
    patch_jmp(VA_AFREE, reinterpret_cast<void*>(&host_free));
    {
        uint8_t* cs = static_cast<uint8_t*>(P(N(VA_CSINIT)));
        cs[0] = 0x8B; cs[1] = 0xC1; cs[2] = 0xC3;       // mov eax, ecx ; ret
    }
    g_sched = A32(reinterpret_cast<void*>(&stub_scheduler));
    build_fixed();
    uint32_t failures = check_constants() ? 0 : 1;

    // ---- lifecycle: argument / image / binding errors before the first successful initialize ----
    run_lifecycle_pre();

    Stats total;
    auto run_families = [&](const char* const* fams, size_t nf, uint32_t n) {
        for (size_t fi = 0; fi < nf; ++fi) {
            if (!only.empty() && only != fams[fi]) continue;
            Stats st;
            for (uint32_t k = 0; k < n; ++k) run_case(make_spec(fams[fi], k, seed), st);
            print_family(fams[fi], st);
            if (st.mismatches || st.plumbing) ++failures;
            const std::string f = fams[fi];
            const bool needsConsume = f == "plain" || f == "mixed" || f == "gated" || f == "via" || f == "limit" || f == "overwrite" || f == "multi" || f == "stale-multi" || f == "inline";
            if (needsConsume && st.consumed == 0) { std::printf("FAIL %s: no solve was consumed from a private result\n", fams[fi]); ++failures; }
            if ((f == "plain" || f == "mixed" || f == "gated") && st.found == 0) { std::printf("FAIL %s: no found path was compared\n", fams[fi]); ++failures; }
            if (f == "mixed" && st.nopath == 0) { std::printf("FAIL mixed: no unreachable-goal solve was compared\n"); ++failures; }
            if (f == "via" && st.vias == 0) { std::printf("FAIL via: the original dropped every via leg (none compared)\n"); ++failures; }
            if (f == "stale" && st.stale == 0) { std::printf("FAIL stale: no stale refusal observed\n"); ++failures; }
            if (f == "multi") std::printf("INFO multi: small scene (3 requests, ~10 objects): team batches=%u worker advances=%u; small batches stay inline, worker participation is judged by the scale scene\n", st.teamSteps, st.workerChunks);
            total.cases += st.cases; total.solves += st.solves;
        }
    };

    // ---- session A: own pool (2 workers), 4 slots ----
    {
        const uint32_t e = rt_init(base_cfg(2, 4));
        if (e != 0) { std::printf("FAIL session A initialize returned %08x\n", e); return 1; }
        life_expect_eq("session A phase before checks", npr_state[NPR_S_PHASE], 1);
        lifecycle_session_a_checks();
        run_families(kSessionAFamilies, sizeof kSessionAFamilies / sizeof kSessionAFamilies[0], cases);
        if (only.empty() || only == "lifecycle") {
            Stats sl;
            outlive_check(sl);
            run_case(make_spec("busy", 0, seed), sl);
            inert_checks(sl, "busy-disabled");   // the busy stop disabled the hook: no tick plans, the original answers
            print_family("lifecycle-busy", sl);
            if (sl.mismatches || sl.plumbing) ++failures;
        }
        // stop (own pool joined, storage freed), idempotent, inert hooks, original answers
        life_expect_eq("stop returns ok", rt_stop(), NPR_OK);
        life_expect_eq("phase stopped", npr_state[NPR_S_PHASE], 2);
        life_expect_eq("disabled", npr_state[NPR_S_ENABLED], 0);
        life_expect_eq("storage released", npr_storage_bytes, 0);
        life_expect_eq("second stop idempotent", rt_stop(), NPR_OK);
    }
    // ---- stopped checks + restart with a different shape ----
    {
        Stats st;
        inert_checks(st, "stopped");
        if (st.plumbing) ++failures;
        {   // wrong delta / bad binding on restart must be refused and keep the stopped state
            npr_config c = base_cfg(0, 1);
            c.imageDelta += 0x1000;
            const uint32_t e = rt_init(c);
            life_expect_eq("restart with another image delta class", NPR_ERR_CLASS(e), NPR_E_ARG);
            life_expect_eq("restart with another image delta detail", NPR_ERR_DETAIL(e), 1);
            life_expect_eq("phase after refused restart", npr_state[NPR_S_PHASE], 2);
        }
        // restart: inline worker (workers 0), 2 slots, neighbour capacity 3 (capacity refusal before any callback)
        npr_config c = base_cfg(0, 2);
        c.neighborCapacity = 3;
        const uint32_t e = rt_init(c);
        life_expect_eq("restart initialize", e, NPR_OK);
        life_expect_eq("restart phase", npr_state[NPR_S_PHASE], 1);
        life_expect_eq("restart reset ticks", npr_state[NPR_S_TICKS], 0);
        life_expect_eq("restart reset fallbacks", npr_state[NPR_S_FALLBACKS], 0);
        if (e == 0) {
            static const char* fams[] = {"refuse-capacity", "inline"};
            run_families(fams, 2, std::max(1u, cases / 2));
            LIFE_EXPECT(npr_state[NPR_S_TEAM_STEPS] == 0 && npr_state[NPR_S_WORKER_CHUNKS] == 0, "workers=0 session never uses the team");
            life_expect_eq("second stop ok", rt_stop(), NPR_OK);
        }
    }
    // ---- shared pool session ----
    {
        const ntw_u32 pr = shared_pool_start(3);
        life_expect_eq("shared pool init", pr, NTW_POOL_OK);
        if (pr == NTW_POOL_OK) {
            npr_config c = base_cfg(0, 3);
            c.pool = A32(g_sharedPoolMem);
            const uint32_t e = rt_init(c);
            life_expect_eq("shared pool session initialize", e, NPR_OK);
            if (e == 0) {
                static const char* fams[] = {"multi"};
                run_families(fams, 1, std::max(1u, cases / 2));
                life_expect_eq("shared pool session stop", rt_stop(), NPR_OK);
                life_expect_eq("shared pool survives npr_stop (ready)", reinterpret_cast<ntw_pool*>(g_sharedPoolMem)->state, NTW_POOL_S_READY);
            }
            life_expect_eq("shared pool shutdown", ntw_pool_shutdown(reinterpret_cast<ntw_pool*>(g_sharedPoolMem)), NTW_POOL_OK);
        }
    }
    // ---- exception unwinding through npr_scheduler_hook ----
    {
        const uint32_t e = rt_init(base_cfg(1, 2));
        life_expect_eq("exception session initialize", e, NPR_OK);
        if (e == 0) {
            Stats se;
            for (uint32_t k = 0; k < std::max(1u, cases / 4); ++k) run_case(make_spec("exception", k, seed), se);
            Stats sp2;
            run_case(make_spec("plain", 2, seed), sp2);   // the owner slot must be free again: this tick plans and consumes
            if (sp2.consumed == 0) life_fail("tick after an unwound exception did not consume");
            print_family("exception", se);
            if (se.mismatches || se.plumbing || sp2.mismatches || sp2.plumbing) ++failures;
            life_expect_eq("exception session stop", rt_stop(), NPR_OK);
        }
    }
    // ---- cross-tick persistence: planned in tick N, consumed / invalidated / evicted in later ticks (each family owns its sessions) ----
    for (const char* fam : kPersistFamilies) {
        if (!only.empty() && only != "persist" && only != fam) continue;
        Stats sp;
        persist_family(fam, sp, seed, std::max(1u, cases / 4));
        print_family(fam, sp);
        if (sp.mismatches || sp.plumbing) ++failures;
        if (std::strcmp(fam, "persist-stop") != 0 && sp.consumed == 0) { std::printf("FAIL %s: no solve was consumed from a private result\n", fam); ++failures; }
        if (std::strcmp(fam, "persist-cross-stale") == 0 && sp.stale == 0) { std::printf("FAIL %s: no stale refusal observed\n", fam); ++failures; }
        if (sp.solves != 0 && sp.found + sp.nopath == 0) { std::printf("FAIL %s: no solve was compared\n", fam); ++failures; }
    }
    // ---- substantial supported scene: worker-team participation, differential outputs, native-vs-runtime time observations ----
    if (only.empty() || only == "scale") {
        Stats ss;
        run_scale(ss, seed);
        print_family("scale", ss);
        if (ss.mismatches || ss.plumbing) ++failures;
    }
    failures += g_lifeFailures;
    std::printf("FAMILY lifecycle cases=1 solves=0 consumed=0 fallbacks=0 found=0 nopath=0 vias=0 stale=0 records=0 skipped=0 mismatches=%u plumbing=0\n", g_lifeFailures);
    std::printf("RESULT %s failures=%u seed=%llu\n", failures ? "FAIL" : "PASS", failures, static_cast<unsigned long long>(seed));
    return failures ? 1 : 0;
}
