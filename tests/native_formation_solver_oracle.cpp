// x86 mapped-image oracle for ntw_solver::Solve / SolveCopy (src/formation/native_formation_solver.*).
//
// The ORIGINAL machine code of the pinned Napoleon.exe (SHA-256 13fcab62...cbad4) is mapped privately inside THIS process
// (VirtualAlloc + loader relocations, native_image_relocation.h).  Nothing touches a running game, the installed EXE, a
// debugger or an injector.  The original 0x502770 (with the original 0x5281D0 / 0x57CBC0 / 0x80E9D0 / 0x7F4950 bytes) is
// run on generated fixtures and its result is compared BYTE FOR BYTE with ntw_solver::Solve (default policy), Solve with
// the other cost policy and SolveCopy:
//   entries (man, slot, cost bits), EAX ((iterations & ~0xFF) | done), the global list cap/count/data-presence, the
//   allocator call sequence (sizes and order, which block each free releases), MXCSR control bits and the x87 environment
//   (sticky exception flags are excluded, FINDINGS.md line ~111).
// Glue patches applied to the private copy (everything else is original bytes):
//   * 0xFF7F20 / 0xFF7EF0 (game heap allocate / free)    -> recording host malloc / free thunks
//   * data: [0x14A40B0] = INT_MIN (thread-safe-static guard of 0x502770 never takes the init path),
//           [0x1841BB8] = this process' _tls_index; angle table copied to 0x176CFF8.
//   * 0x5281D0 entry (first 7 bytes) -> trampoline that records every (man, slot) call pair, then runs the original bytes
//     (observation only; removed again for the timing runs).
// Build: CMake target native_formation_solver_oracle (MSVC x86, /MT).
// Run:   native_formation_solver_oracle.exe --image "<Napoleon.exe>" --table native-formation-angle-table-28252.bin
//            [--cases 2000] [--seed 20261018] [--bench 1]
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <malloc.h>
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_set>
#include <vector>
#include "native_formation_solver.h"
#include "native_image_relocation.h"

#pragma comment(lib, "bcrypt.lib")
static_assert(sizeof(void*) == 4, "x86 build required: the native code is 32-bit");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile int g_tlsPad[32];

namespace {

using ntw_solver::Entry12;

constexpr uint32_t kImageBase = 0x400000;
constexpr const char* kImageSha = "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4";
constexpr const char* kTableSha = "405383e324f986ad1972b9da231b2bb6d1d496c23067af8de60faf359e2a3581";
constexpr uint32_t kAngleTableVa = 0x176CFF8;
constexpr uint32_t kListVa = 0x14A40A4;       // cap, count, data
constexpr uint32_t kGuardVa = 0x14A40B0;
constexpr uint32_t kTlsIndexVa = 0x1841BB8;
constexpr uint32_t kPreBlock = 0xFFFFFFFEu;   // "the block that existed before the call" in the allocator log
uintptr_t g_image_delta;
uint32_t NativeAddress(uint32_t preferred) { return preferred + static_cast<uint32_t>(g_image_delta); }
uint32_t* ListWords() { return reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NativeAddress(kListVa))); }

std::string Sha256(const void* data, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    uint8_t out[32] = {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCryptHash(alg, nullptr, 0, (PUCHAR)data, (ULONG)len, out, 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (int i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", out[i]);
    return hex;
}

bool ReadAll(const std::string& path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize((size_t)n);
    bool ok = n == 0 || std::fread(out.data(), 1, (size_t)n, f) == (size_t)n;
    std::fclose(f);
    return ok;
}

// ---- allocator log ---------------------------------------------------------------------------------------------------
struct Ev {
    char kind;        // 'A' alloc, 'F' free
    uint32_t value;   // alloc: byte size; free: index of the allocation it releases (kPreBlock / 0xFFFFFFFF unknown)
    bool operator==(const Ev& o) const { return kind == o.kind && value == o.value; }
};
std::vector<Ev> g_events;
std::vector<void*> g_blocks;
void* g_preBlock = nullptr;

extern "C" void* __cdecl HostAlloc(size_t size, void*) {
    void* p = std::malloc(size ? size : 1);
    g_events.push_back({'A', (uint32_t)size});
    g_blocks.push_back(p);
    return p;
}
extern "C" void __cdecl HostFree(void* p) {
    uint32_t id = 0xFFFFFFFFu;
    for (size_t i = g_blocks.size(); i-- > 0;) if (g_blocks[i] == p) { id = (uint32_t)i; break; }
    if (id == 0xFFFFFFFFu && p == g_preBlock) id = kPreBlock;
    g_events.push_back({'F', id});
    std::free(p);
}

// ---- 0x5281D0 observation hook -----------------------------------------------------------------------------------------
uint32_t g_hookEvals = 0;
std::unordered_set<uint64_t> g_hookPairs;
extern "C" void __cdecl RecordPair(uint32_t man, uint32_t slot) {
    ++g_hookEvals;
    g_hookPairs.insert(((uint64_t)man << 32) | slot);
}
uint8_t g_savedCost[7];
bool g_hookOn = false;
uint8_t* g_tramp = nullptr;

bool InstallHook() {
    if (g_hookOn) return true;
    uint8_t* fn = (uint8_t*)(uintptr_t)NativeAddress(0x5281D0);
    static const uint8_t expect[7] = {0x83, 0xEC, 0x10, 0x8B, 0x4C, 0x24, 0x18};   // sub esp,10 ; mov ecx,[esp+18]
    if (std::memcmp(fn, expect, 7) != 0) return false;
    if (!g_tramp) g_tramp = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!g_tramp) return false;
    uint8_t* t = g_tramp;
    const uint8_t head[] = {0x60, 0x9C, 0xFF, 0x74, 0x24, 0x2C, 0xFF, 0x74, 0x24, 0x2C, 0xB8};
    std::memcpy(t, head, sizeof head);
    t += sizeof head;
    uint32_t rec = (uint32_t)(uintptr_t)&RecordPair;
    std::memcpy(t, &rec, 4); t += 4;
    const uint8_t mid[] = {0xFF, 0xD0, 0x83, 0xC4, 0x08, 0x9D, 0x61, 0x83, 0xEC, 0x10, 0x8B, 0x4C, 0x24, 0x18, 0xE9};
    std::memcpy(t, mid, sizeof mid);
    t += sizeof mid;
    int32_t rel = (int32_t)((uintptr_t)(fn + 7) - ((uintptr_t)t + 4));
    std::memcpy(t, &rel, 4);
    std::memcpy(g_savedCost, fn, 7);
    uint8_t patch[7] = {0xE9, 0, 0, 0, 0, 0x90, 0x90};
    int32_t jrel = (int32_t)((uintptr_t)g_tramp - ((uintptr_t)fn + 5));
    std::memcpy(patch + 1, &jrel, 4);
    std::memcpy(fn, patch, 7);
    FlushInstructionCache(GetCurrentProcess(), fn, 7);
    FlushInstructionCache(GetCurrentProcess(), g_tramp, 64);
    g_hookOn = true;
    return true;
}
void RemoveHook() {
    if (!g_hookOn) return;
    uint8_t* fn = (uint8_t*)(uintptr_t)NativeAddress(0x5281D0);
    std::memcpy(fn, g_savedCost, 7);
    FlushInstructionCache(GetCurrentProcess(), fn, 7);
    g_hookOn = false;
}

void PatchJump(uint32_t va, const void* target) {
    uint8_t* p = (uint8_t*)(uintptr_t)NativeAddress(va);
    p[0] = 0xB8;
    uint32_t t = (uint32_t)(uintptr_t)target;
    std::memcpy(p + 1, &t, 4);
    p[5] = 0xFF;
    p[6] = 0xE0;
}

bool MapImage(const std::vector<uint8_t>& file, const std::vector<uint8_t>& table) {
    auto* dos = (const IMAGE_DOS_HEADER*)file.data();
    auto* nt = (const IMAGE_NT_HEADERS32*)(file.data() + dos->e_lfanew);
    if (nt->OptionalHeader.ImageBase != kImageBase) return false;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto* base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!base) return false;
    g_image_delta = reinterpret_cast<uintptr_t>(base) - kImageBase;
    std::memcpy(base, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t n = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        std::memcpy((uint8_t*)base + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    if (!RelocateNativeImage(base, size, nt, g_image_delta)) { VirtualFree(base, 0, MEM_RELEASE); return false; }
    std::memcpy((void*)(uintptr_t)NativeAddress(kAngleTableVa), table.data(), table.size());
    PatchJump(0x00FF7F20, (const void*)&HostAlloc);
    PatchJump(0x00FF7EF0, (const void*)&HostFree);
    *(int32_t*)(uintptr_t)NativeAddress(kGuardVa) = (int32_t)0x80000000;
    *(uint32_t*)(uintptr_t)NativeAddress(kTlsIndexVa) = _tls_index;
    g_tlsPad[0] = 0;
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}

using SolverFn = uint32_t(__thiscall*)(void* ctx, void* begin, void* end, uint32_t limit, float threshold);
SolverFn g_solver;

bool CallNative(void* ctx, void* b, void* e, uint32_t lim, float thr, uint32_t* ret) {
    __try { *ret = g_solver(ctx, b, e, lim, thr); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---- floating-point environment capture ------------------------------------------------------------------------------
struct Fp {
    uint32_t mxcsr = 0;
    uint16_t cw = 0, topTag = 0;
};
Fp CaptureFp() {
    Fp f;
    f.mxcsr = _mm_getcsr();
    uint8_t env[28];
    uint8_t* p = env;
    __asm {
        mov eax, p
        fnstenv [eax]
        fldenv [eax]
    }
    uint16_t cw, sw, tag;
    std::memcpy(&cw, env + 0, 2);
    std::memcpy(&sw, env + 4, 2);
    std::memcpy(&tag, env + 8, 2);
    f.cw = cw;
    f.topTag = (uint16_t)(((sw >> 11) & 7) | (tag == 0xFFFF ? 0x100 : 0));   // TOP + "all 8 registers empty"
    return f;
}
bool SameFp(const Fp& a, const Fp& b) {
    return ((a.mxcsr ^ b.mxcsr) & 0xFFC0u) == 0 && a.cw == b.cw && a.topTag == b.topTag;
}

// ---- RNG -------------------------------------------------------------------------------------------------------------------
struct Rng {
    uint32_t s;
    uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    uint32_t below(uint32_t n) { return n ? next() % n : 0; }
    float unit() { return (float)(next() >> 8) / 16777216.0f; }
};

float FromBits(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }

// ---- fixtures ---------------------------------------------------------------------------------------------------------------
struct ParentXf { float t[3]; float rotC, rotS; float scale; };

struct Fixture {
    std::string label;
    uint32_t m = 0;
    std::vector<int32_t> entMan, entSlot;              // entry -> man index / slot record index, -1 null
    std::vector<float> mx, mz;                         // men
    std::vector<uint16_t> mang;
    std::vector<float> px, py, pz;                     // slot record pose (local to its parent when it has one)
    std::vector<int32_t> parent;                       // slot record -> parent index, -1 none
    std::vector<ParentXf> parents;
    float def = 0.0f, nos = FLT_MAX, thr = FLT_MAX;
    uint32_t limit = 0;
    uint32_t mxcsrMode = 0;
    uint32_t cap0 = 0;
    bool dupPtrs = false;                              // entries share man / slot objects: distinct-pair count not comparable
};

void ApplyMxcsr(uint32_t mode) {
    static const uint32_t csr[] = {0x1F80, 0x9FC0, 0x7F80, 0x5F80, 0x3F80, 0xFFC0};   // nearest, FTZ|DAZ, trunc, up, down, all
    _mm_setcsr(csr[mode % 6]);
}

struct World {
    std::vector<uint8_t*> men;
    uint8_t* recs = nullptr;
    std::vector<uint8_t*> parents;
    std::vector<Entry12> init;
    ~World() {
        for (auto* p : men) _aligned_free(p);
        for (auto* p : parents) _aligned_free(p);
        std::free(recs);
    }
};
template <typename T> void Put(uint8_t* base, uint32_t off, T v) { std::memcpy(base + off, &v, sizeof(T)); }

void BuildWorld(const Fixture& f, World& w) {
    const size_t nMen = f.mx.size(), nRec = f.px.size();
    for (size_t i = 0; i < nMen; ++i) {
        uint8_t* m = (uint8_t*)_aligned_malloc(0x700, 16);
        std::memset(m, 0, 0x700);
        Put<float>(m, 0x48, f.mx[i]);
        Put<float>(m, 0x50, f.mz[i]);
        Put<uint16_t>(m, 0x64, f.mang[i]);
        w.men.push_back(m);
    }
    for (const ParentXf& p : f.parents) {
        uint8_t* o = (uint8_t*)_aligned_malloc(0x100, 16);
        std::memset(o, 0, 0x100);
        Put<float>(o, 0x80, p.t[0]); Put<float>(o, 0x84, p.t[1]); Put<float>(o, 0x88, p.t[2]);
        Put<float>(o, 0x9C, p.rotC * p.scale); Put<float>(o, 0xA4, p.rotS * p.scale);
        Put<float>(o, 0xAC, p.scale);
        Put<float>(o, 0xB4, -p.rotS * p.scale); Put<float>(o, 0xBC, p.rotC * p.scale);
        w.parents.push_back(o);
    }
    w.recs = (uint8_t*)std::calloc(nRec ? nRec : 1, 36);
    for (size_t i = 0; i < nRec; ++i) {
        uint8_t* r = w.recs + 36 * i;
        Put<float>(r, 4, f.px[i]);
        Put<float>(r, 8, f.py[i]);
        Put<float>(r, 0xC, f.pz[i]);
        Put<uint32_t>(r, 0x14, f.parent[i] >= 0 ? (uint32_t)(uintptr_t)w.parents[(size_t)f.parent[i]] : 0u);
    }
    w.init.resize(f.m);
    for (uint32_t i = 0; i < f.m; ++i) {
        w.init[i].man = f.entMan[i] >= 0 ? (uint32_t)(uintptr_t)w.men[(size_t)f.entMan[i]] : 0u;
        w.init[i].slot = f.entSlot[i] >= 0 ? (uint32_t)(uintptr_t)(w.recs + 36 * (size_t)f.entSlot[i]) : 0u;
        w.init[i].cost = FromBits(0x7FC0DEADu ^ (i * 2654435761u));   // garbage: the solver overwrites every cost
    }
}

// ---- fixture generation -----------------------------------------------------------------------------------------------------
float PickSpecial(Rng& r, bool allowNan) {
    switch (r.below(allowNan ? 10 : 8)) {
        case 0: return 0.0f;
        case 1: return -0.0f;
        case 2: return 1e-30f;      // squares underflow to denormal / zero
        case 3: return 1e-40f;      // denormal operand (DAZ)
        case 4: return 3e38f;       // squares overflow to inf
        case 5: return FromBits(0x7F800000u);   // +inf
        case 6: return FromBits(0xFF800000u);   // -inf
        case 7: return 1.0f;
        case 8: return FromBits(0x7FC00000u);   // qNaN
        default: return FromBits(0xFFC12345u);  // qNaN with payload
    }
}

Fixture MakeFixture(Rng& r, uint32_t idx, int forceM = -1) {
    Fixture f;
    uint32_t cls = r.below(100);
    uint32_t m;
    if (forceM >= 0) m = (uint32_t)forceM;
    else if (cls < 8) m = r.below(4);
    else if (cls < 30) m = 4 + r.below(24);
    else if (cls < 75) m = 28 + r.below(100);
    else if (cls < 95) m = 128 + r.below(160);
    else m = 288 + r.below(113);
    f.m = m;
    const uint32_t style = r.below(7);   // 0,1 lattice 2 continuous 3 coincident 4 clustered 5 far 6 storm (grid -> rotated grid)
    f.label = "rand#" + std::to_string(idx) + "/m" + std::to_string(m) + "/s" + std::to_string(style);
    const bool lattice = style <= 1 || style == 3 || style == 6;
    const uint32_t files = 2 + r.below(40);
    const float spacing = lattice ? 1.0f : 0.8f + 0.6f * r.unit();
    const float ox = lattice ? (float)((int)r.below(200) - 100) : (r.unit() - 0.5f) * 300.0f;
    const float oz = lattice ? (float)((int)r.below(200) - 100) : (r.unit() - 0.5f) * 300.0f;
    const float farOff = style == 5 ? (r.below(2) ? 1e4f : 1e7f) : 0.0f;
    f.mx.resize(m); f.mz.resize(m); f.mang.resize(m);
    f.px.resize(m); f.py.resize(m); f.pz.resize(m); f.parent.assign(m, -1);
    const uint16_t a0 = (uint16_t)r.next();
    const uint32_t angMode = r.below(3);
    for (uint32_t i = 0; i < m; ++i) {
        float gx, gz;
        if (style == 6) { gx = (float)(i % files); gz = (float)(i / files); }
        else if (lattice) { gx = (float)r.below(40); gz = (float)r.below(8); }
        else if (style == 4) { gx = (float)(r.below(3) * 12) + r.unit() * 4.0f; gz = (float)(r.below(3) * 6) + r.unit() * 4.0f; }
        else { gx = r.unit() * 40.0f; gz = r.unit() * 12.0f; }
        f.mx[i] = gx + farOff;
        f.mz[i] = gz;
        f.mang[i] = angMode == 0 ? a0 : (angMode == 1 ? (uint16_t)(a0 + r.below(5)) : (uint16_t)r.next());
        float fx = (float)(i % files) - 0.5f * (float)(files - 1);
        float fz = (float)(i / files);
        if (style == 6) { fx = (float)(i / files) + 3.0f; fz = (float)(i % files); }   // quarter turn
        f.px[i] = ox + fx * spacing;
        f.py[i] = 0.0f;
        f.pz[i] = oz - fz * spacing;
        if (style == 3 && r.below(3) != 0) { f.px[i] = f.mx[i]; f.pz[i] = f.mz[i]; }     // d2 == 0
    }
    if (r.below(4) == 0) {                                      // parented slot poses (0x80E9D0 -> 0x7F4950 path)
        const uint32_t np = 1 + r.below(4);
        for (uint32_t p = 0; p < np; ++p) {
            ParentXf x;
            const float th = (r.unit() - 0.5f) * 6.2831853f;
            x.t[0] = r.unit() * 40.0f; x.t[1] = 0.0f; x.t[2] = r.unit() * 12.0f;
            x.rotC = std::cos(th); x.rotS = std::sin(th);
            x.scale = r.below(3) ? 1.0f : 0.5f + r.unit();
            f.parents.push_back(x);
        }
        for (uint32_t i = 0; i < m; ++i)
            if (r.below(5) != 0) f.parent[i] = (int32_t)r.below(np);
        // keep local coordinates small so the parented poses land near the men
        for (uint32_t i = 0; i < m; ++i) if (f.parent[i] >= 0) { f.px[i] = (f.px[i] - ox) * 0.5f; f.pz[i] = (f.pz[i] - oz) * 0.5f; }
    }
    if (r.below(14) == 0) {                                     // special floats (inf, NaN, denormals, zeros)
        const bool nan = r.below(2) != 0;
        const uint32_t k = 1 + r.below(6);
        for (uint32_t q = 0; q < k && m; ++q) {
            const uint32_t i = r.below(m);
            switch (r.below(4)) {
                case 0: f.mx[i] = PickSpecial(r, nan); break;
                case 1: f.mz[i] = PickSpecial(r, nan); break;
                case 2: f.px[i] = PickSpecial(r, nan); break;
                default: f.pz[i] = PickSpecial(r, nan); break;
            }
        }
        f.label += "/special";
    }
    // entries: man i -> slot i through a random initial permutation, with null men / null slots
    std::vector<uint32_t> perm(m);
    for (uint32_t i = 0; i < m; ++i) perm[i] = i;
    const uint32_t shuffle = r.below(3);   // 0 identity, 1 partial, 2 full
    if (shuffle == 2) for (uint32_t i = m; i > 1; --i) std::swap(perm[i - 1], perm[r.below(i)]);
    if (shuffle == 1) for (uint32_t k = 0; k < m / 8 + 1 && m > 1; ++k) std::swap(perm[r.below(m)], perm[r.below(m)]);
    const uint32_t nullMode = r.below(6);
    const uint32_t nullMan = nullMode == 1 ? 3 : (nullMode == 2 ? 30 : (nullMode == 3 ? 2 : 0));
    const uint32_t nullSlot = nullMode == 4 ? 3 : (nullMode == 5 ? 30 : (nullMode == 3 ? 3 : 0));
    f.entMan.resize(m); f.entSlot.resize(m);
    for (uint32_t i = 0; i < m; ++i) {
        f.entMan[i] = (nullMan && r.below(nullMan) == 0) ? -1 : (int32_t)perm[i];
        f.entSlot[i] = (nullSlot && r.below(nullSlot) == 0) ? -1 : (int32_t)i;
    }
    if (r.below(40) == 0 && m > 2) {                           // shared man / slot objects between entries
        f.dupPtrs = true;
        for (uint32_t k = 0; k < 1 + m / 20; ++k) {
            f.entMan[r.below(m)] = (int32_t)r.below(m);
            if (r.below(2)) f.entSlot[r.below(m)] = (int32_t)r.below(m);
        }
        f.label += "/dup";
    }
    static const float defs[] = {0.0f, 0.0f, 0.5f, 0.25f, 3.0f};
    static const float noss[] = {FLT_MAX, FLT_MAX, 9.0f, 0.0f, 100.0f};
    f.def = defs[r.below(5)];
    f.nos = noss[r.below(5)];
    switch (r.below(7)) {
        case 0: case 1: case 2: f.thr = FLT_MAX; break;   // 0x1325DB4
        case 3: case 4: f.thr = 16.0f; break;             // 0x1325D48
        case 5: f.thr = 1.0f + r.unit() * 40.0f; break;
        default: f.thr = (r.below(2) ? 2.5f : 1.0f); break;
    }
    static const uint32_t limits[] = {0, 0, 0, 0, 0, 0, 1, 2, 3, 5, 17, 100, 0x10000};
    f.limit = limits[r.below(13)];
    f.mxcsrMode = r.below(8) == 0 ? 1 + r.below(5) : 0;
    static const uint32_t caps[] = {0, 0, 0, 1, 2, 3, 8, 64, 100, 128, 256, 512, 1024};
    f.cap0 = caps[r.below(13)];
    return f;
}

// Storm-like fixture for the benchmark: men on a grid, slots on a transformed grid, identity initial pairing.
Fixture MakeStorm(Rng& r, uint32_t m, int scenario) {
    Fixture f;
    f.m = m;
    static const char* const kNames[] = {"turn", "shift", "random", "rev", "col2line", "cloud", "ring", "mirror"};
    f.label = std::string("bench/") + kNames[scenario] + "/m" + std::to_string(m);
    const uint32_t files = (uint32_t)std::ceil(std::sqrt((double)m * 3.0));
    f.mx.resize(m); f.mz.resize(m); f.mang.resize(m);
    f.px.resize(m); f.py.assign(m, 0.0f); f.pz.resize(m); f.parent.assign(m, -1);
    for (uint32_t i = 0; i < m; ++i) {
        const float gx = (float)(i % files), gz = (float)(i / files);
        if (scenario == 2) {
            f.mx[i] = r.unit() * 40.0f; f.mz[i] = r.unit() * 12.0f;
            f.px[i] = r.unit() * 40.0f; f.pz[i] = r.unit() * 12.0f;
        } else if (scenario == 3) {          // same grid, reversed assignment (set below): every man starts at the far end
            f.mx[i] = gx * 0.9f; f.mz[i] = gz * 0.9f;
            f.px[i] = gx * 0.9f; f.pz[i] = gz * 0.9f;
        } else if (scenario == 4) {          // 4-deep column -> one-deep line
            f.mx[i] = (float)(i % 4) * 0.9f + r.unit() * 0.2f; f.mz[i] = (float)(i / 4) * 0.9f + r.unit() * 0.2f;
            f.px[i] = (float)i * 0.45f + 30.0f; f.pz[i] = 5.0f + r.unit() * 0.2f;
        } else if (scenario == 5) {          // random cloud -> compact grid
            f.mx[i] = r.unit() * 120.0f; f.mz[i] = r.unit() * 120.0f;
            f.px[i] = 40.0f + gx * 0.9f; f.pz[i] = 40.0f + gz * 0.9f;
        } else if (scenario == 6) {          // ring -> grid
            const float th = (float)i * 6.2831853f / (float)m;
            f.mx[i] = 40.0f + 30.0f * std::cos(th); f.mz[i] = 40.0f + 30.0f * std::sin(th);
            f.px[i] = 25.0f + gx * 0.9f; f.pz[i] = 25.0f + gz * 0.9f;
        } else if (scenario == 7) {          // mirrored in x
            f.mx[i] = gx * 0.9f + r.unit() * 0.3f; f.mz[i] = gz * 0.9f + r.unit() * 0.3f;
            f.px[i] = ((float)files - 1.0f - gx) * 0.9f; f.pz[i] = gz * 0.9f;
        } else {
            f.mx[i] = gx * 0.9f + r.unit() * 0.3f; f.mz[i] = gz * 0.9f + r.unit() * 0.3f;
            if (scenario == 0) { f.px[i] = 20.0f + gz * 0.9f; f.pz[i] = -gx * 0.9f + 30.0f; }   // quarter turn + move
            else { f.px[i] = gx * 0.9f + 8.0f; f.pz[i] = gz * 0.9f + 3.0f; }
        }
        f.mang[i] = (uint16_t)(r.next() % 7 == 0 ? r.next() : 1000);
    }
    f.entMan.resize(m); f.entSlot.resize(m);
    for (uint32_t i = 0; i < m; ++i) { f.entMan[i] = (int32_t)(scenario == 3 ? m - 1 - i : i); f.entSlot[i] = (int32_t)i; }
    f.def = 0.0f; f.nos = FLT_MAX; f.thr = FLT_MAX; f.limit = 0; f.cap0 = 0;
    return f;
}

// ---- one run -----------------------------------------------------------------------------------------------------------------
enum Kind { kNative, kSolveCensus, kSolveDirect, kSolveSimd, kSolveDefault, kCopyCensus, kCopyDirect, kCopySimd, kCopyDefault };
const char* KindName(Kind k) {
    static const char* n[] = {"native", "Solve/direct+census", "Solve/direct", "Solve/simd", "Solve/default",
                              "SolveCopy/direct+census", "SolveCopy/direct", "SolveCopy/simd", "SolveCopy/default"};
    return n[k];
}
bool Replicates(Kind k) { return k == kSolveCensus || k == kSolveDirect || k == kSolveSimd || k == kSolveDefault; }
bool Census(Kind k) { return k == kSolveCensus || k == kCopyCensus; }      // Counters.profile = 1
bool HasDistinct(Kind k) { return Census(k); }

struct Run {
    std::vector<Entry12> entries;
    uint32_t eax = 0;
    bool faulted = false;
    uint32_t cap = 0, count = 0, data = 0, preData = 0;
    std::vector<Ev> events;
    Fp fpBefore, fpAfter;
    uint32_t hookEvals = 0, hookDistinct = 0;
    ntw_solver::Counters ctr{};
    ntw_solver::Outcome outcome = ntw_solver::kSolved;
};

ntw_solver::Env MakeEnv() {
    ntw_solver::Env env{};
    env.angleTable = (const float*)(uintptr_t)NativeAddress(kAngleTableVa);
    env.zero = *(const float*)(uintptr_t)NativeAddress(0x131A7A4);
    env.one = *(const float*)(uintptr_t)NativeAddress(0x1318048);
    env.pairWeight = *(const float*)(uintptr_t)NativeAddress(0x1318038);
    env.pose = (const float*(__fastcall*)(void*, void*, float*))(uintptr_t)NativeAddress(0x80E9D0);
    env.listGlobal = ListWords();
    env.alloc = (void*(__cdecl*)(uint32_t, uint32_t))(uintptr_t)NativeAddress(0x444B40);
    env.release = (void(__cdecl*)(void*))(uintptr_t)NativeAddress(0xFF7EF0);
    env.listGuard = (const int32_t*)(uintptr_t)NativeAddress(kGuardVa);
    env.tlsIndex = (const uint32_t*)(uintptr_t)NativeAddress(kTlsIndexVa);
    return env;
}

void SetupList(uint32_t cap0) {
    uint32_t* L = ListWords();
    L[0] = cap0;
    L[1] = 0;
    g_preBlock = cap0 ? std::malloc((size_t)cap0 * 4) : nullptr;
    L[2] = (uint32_t)(uintptr_t)g_preBlock;
}
void TeardownList() {
    uint32_t* L = ListWords();
    if (L[2]) std::free((void*)(uintptr_t)L[2]);
    L[0] = L[1] = L[2] = 0;
    g_preBlock = nullptr;
}

void Execute(Kind k, const Fixture& f, const World& w, ntw_solver::Workspace& ws, Run& out, bool hook) {
    const ntw_solver::Env env = MakeEnv();
    out.entries = w.init;
    out.entries.reserve(w.init.size() + 1);   // data() must be non-null even for m == 0
    float ctx[2] = {f.def, f.nos};
    Entry12* b = out.entries.data();
    Entry12* e = b + f.m;
    g_events.clear();
    g_blocks.clear();
    g_hookEvals = 0;
    g_hookPairs.clear();
    SetupList(f.cap0);
    out.preData = ListWords()[2];
    const uint32_t csr0 = _mm_getcsr();
    ApplyMxcsr(f.mxcsrMode);
    out.fpBefore = CaptureFp();
    if (k == kNative) {
        if (hook) InstallHook();
        out.faulted = !CallNative(ctx, b, e, f.limit, f.thr, &out.eax);
        if (hook) RemoveHook();
    } else {
        const bool replicate = Replicates(k);
        out.ctr.profile = Census(k) ? 1u : 0u;
        if (k == kSolveDefault) {
            out.outcome = ntw_solver::Solve(ws, env, ctx, b, e, f.limit, f.thr, &out.eax, &out.ctr);
        } else if (k == kCopyDefault) {
            out.outcome = ntw_solver::SolveCopy(ws, env, ctx, b, e, f.limit, f.thr, &out.eax, &out.ctr);
        } else {
            const ntw_solver::Policy pol = (k == kSolveSimd || k == kCopySimd) ? ntw_solver::kSimd : ntw_solver::kDirect;
            out.outcome = ntw_solver::SolveWith(pol, replicate, ws, env, ctx, b, e, f.limit, f.thr, &out.eax, &out.ctr);
        }
    }
    out.fpAfter = CaptureFp();
    _mm_setcsr(csr0);
    uint32_t* L = ListWords();
    out.cap = L[0];
    out.count = L[1];
    out.data = L[2] == out.preData ? 1u : (L[2] ? 2u : 0u);   // 1 = still the pre block, 2 = another block, 0 = none
    out.events = g_events;
    out.hookEvals = g_hookEvals;
    out.hookDistinct = (uint32_t)g_hookPairs.size();
    TeardownList();
}

std::string Describe(const Fixture& f) {
    char buf[256];
    std::snprintf(buf, sizeof buf, "%s limit=%u thr=%g def=%g nos=%g csr=%u cap0=%u dup=%d", f.label.c_str(), f.limit, f.thr,
                  f.def, f.nos, f.mxcsrMode, f.cap0, f.dupPtrs ? 1 : 0);
    return buf;
}

// Returns number of mismatches (0 = identical).  Also folds statistics.
struct Stats {
    uint64_t cases = 0, runs = 0, evals = 0, distinct = 0, swaps = 0, removals = 0, selfChecked = 0, distinctChecked = 0;
    uint32_t maxM = 0;
};

int CompareCase(const Fixture& f, ntw_solver::Workspace& ws, Stats& st, int& printed) {
    World w;
    BuildWorld(f, w);
    Run nat;
    Execute(kNative, f, w, ws, nat, true);
    int bad = 0;
    auto fail = [&](const char* what) {
        ++bad;
        if (printed < 12) { ++printed; std::fprintf(stderr, "FAIL %s: %s\n", Describe(f).c_str(), what); }
    };
    if (nat.faulted) { fail("native faulted"); return bad; }
    if (!SameFp(nat.fpBefore, nat.fpAfter)) fail("native changed the FP environment (harness assumption)");
    Run first;
    for (Kind k : {kSolveCensus, kSolveDirect, kSolveSimd, kSolveDefault, kCopyCensus, kCopyDirect, kCopySimd, kCopyDefault}) {
        Run r;
        Execute(k, f, w, ws, r, false);
        ++st.runs;
        const bool replicate = Replicates(k);
        char msg[200];
        if (r.outcome != ntw_solver::kSolved) { std::snprintf(msg, sizeof msg, "%s: kFallback reason %u", KindName(k), r.ctr.fallback); fail(msg); continue; }
        if (std::memcmp(r.entries.data(), nat.entries.data(), f.m * sizeof(Entry12)) != 0) {
            uint32_t at = 0;
            for (; at < f.m; ++at) if (std::memcmp(&r.entries[at], &nat.entries[at], sizeof(Entry12)) != 0) break;
            std::snprintf(msg, sizeof msg, "%s: entry %u differs native(man %08x slot %08x cost %08x) kernel(man %08x slot %08x cost %08x)",
                          KindName(k), at, nat.entries[at].man, nat.entries[at].slot, *(uint32_t*)&nat.entries[at].cost,
                          r.entries[at].man, r.entries[at].slot, *(uint32_t*)&r.entries[at].cost);
            fail(msg);
        }
        if (r.eax != nat.eax) { std::snprintf(msg, sizeof msg, "%s: eax native %08x kernel %08x", KindName(k), nat.eax, r.eax); fail(msg); }
        if (!SameFp(r.fpBefore, r.fpAfter)) { std::snprintf(msg, sizeof msg, "%s: FP environment changed", KindName(k)); fail(msg); }
        if (replicate) {
            if (r.cap != nat.cap || r.count != nat.count || r.data != nat.data) {
                std::snprintf(msg, sizeof msg, "%s: list native(cap %u count %u data %u) kernel(cap %u count %u data %u)", KindName(k),
                              nat.cap, nat.count, nat.data, r.cap, r.count, r.data);
                fail(msg);
            }
            if (!(r.events == nat.events)) {
                std::snprintf(msg, sizeof msg, "%s: allocator sequence differs (native %zu events, kernel %zu)", KindName(k),
                              nat.events.size(), r.events.size());
                fail(msg);
            }
        } else {
            if (r.cap != f.cap0 || r.count != 0 || r.data != 1u || !r.events.empty())
                fail("SolveCopy touched the global list / allocator");
        }
        // counters self-check against the instrumented native 0x5281D0 calls: every policy is native-exact in `evals`
        if (r.ctr.evals != nat.hookEvals) {
            std::snprintf(msg, sizeof msg, "%s: counters: evals kernel %u native hook %u", KindName(k), r.ctr.evals, nat.hookEvals);
            fail(msg);
        }
        if (HasDistinct(k) && !f.dupPtrs) {
            if (k == kSolveCensus) ++st.distinctChecked;
            if (r.ctr.distinct != nat.hookDistinct) {
                std::snprintf(msg, sizeof msg, "%s: counters: distinct kernel %u native hook %u", KindName(k), r.ctr.distinct, nat.hookDistinct);
                fail(msg);
            }
        }
        if (!HasDistinct(k) && r.ctr.distinct != 0) fail("counters: distinct reported without census");
        if (r.ctr.m != f.m) fail("counters: m");
        {
            const uint32_t doneIter = (r.eax & 1u) ? 1u : 0u;   // terminal iteration counts in `iterations` but is neither swap nor removal
            if (r.ctr.iterations != r.ctr.swaps + r.ctr.removals + doneIter) fail("counters: iterations != swaps + removals + done");
            if (r.ctr.distinct > r.ctr.evals) fail("counters: distinct > evals");
            if (((r.ctr.iterations & 0xFFFFFF00u) | (r.eax & 0xFFu)) != r.eax) fail("counters: iterations vs eax");
        }
        if (k == kSolveCensus) {
            ++st.selfChecked;
            st.evals += r.ctr.evals; st.distinct += r.ctr.distinct; st.swaps += r.ctr.swaps; st.removals += r.ctr.removals;
        }
        if (k != kSolveCensus && first.ctr.m == f.m && first.ctr.evals != 0 &&
            (r.ctr.evals != first.ctr.evals || r.ctr.scans != first.ctr.scans || r.ctr.swaps != first.ctr.swaps ||
             r.ctr.removals != first.ctr.removals || r.ctr.iterations != first.ctr.iterations ||
             (HasDistinct(k) && r.ctr.distinct != first.ctr.distinct)))
            fail("counters: policy disagrees with the census run");
        if (r.ctr.totalTicks < r.ctr.gatherTicks + r.ctr.loopTicks) fail("counters: totalTicks < gather + loop");
        const bool fills = k == kSolveSimd || k == kCopySimd || k == kSolveDefault || k == kCopyDefault;   // default policy = kSimd
        if (!fills && r.ctr.fillTicks != 0) fail("counters: fillTicks set outside kSimd / default");
        if (r.ctr.fillTicks > r.ctr.loopTicks) fail("counters: fillTicks > loopTicks");
        if (r.ctr.scans > r.ctr.iterations * f.m) fail("counters: scans > iterations * m");
        if (k == kSolveCensus) first = r;
    }
    ++st.cases;
    if (f.m > st.maxM) st.maxM = f.m;
    return bad;
}

// ---- fallback behaviour ---------------------------------------------------------------------------------------------------------
int FallbackTests(Rng& r, ntw_solver::Workspace& ws) {
    int bad = 0;
    auto check = [&](bool ok, const char* what) { if (!ok) { ++bad; std::fprintf(stderr, "FAIL fallback: %s\n", what); } };
    const ntw_solver::Env env = MakeEnv();
    float ctx[2] = {0.0f, FLT_MAX};
    uint32_t eax = 0x5A5A5A5Au;
    ntw_solver::Counters c{};
    auto untouched = [&](const std::vector<Entry12>& a, const std::vector<Entry12>& b, uint32_t cap, uint32_t count, uint32_t data) {
        const uint32_t* L = ListWords();
        return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size() * sizeof(Entry12)) == 0 && L[0] == cap && L[1] == count && L[2] == data &&
               g_events.empty() && eax == 0x5A5A5A5Au;
    };
    // 1. m > kMaxM
    {
        Fixture f = MakeFixture(r, 900000, (int)ntw_solver::kMaxM + 1);
        World w; BuildWorld(f, w);
        std::vector<Entry12> e = w.init;
        g_events.clear(); SetupList(64);
        const uint32_t d = ListWords()[2];
        auto o = ntw_solver::Solve(ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonTooLarge && untouched(e, w.init, 64, 0, d), "m > kMaxM must fall back untouched");
        o = ntw_solver::SolveCopy(ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonTooLarge && untouched(e, w.init, 64, 0, d), "SolveCopy m > kMaxM must fall back untouched");
        TeardownList();
    }
    // 2. non-empty global list
    {
        Fixture f = MakeFixture(r, 900001, 20);
        World w; BuildWorld(f, w);
        std::vector<Entry12> e = w.init;
        g_events.clear(); SetupList(8);
        ListWords()[1] = 1;
        const uint32_t d = ListWords()[2];
        auto o = ntw_solver::Solve(ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonListState && untouched(e, w.init, 8, 1, d), "count != 0 must fall back untouched");
        ListWords()[1] = 0;
        TeardownList();
    }
    // 3. guard not initialised
    {
        Fixture f = MakeFixture(r, 900002, 20);
        World w; BuildWorld(f, w);
        std::vector<Entry12> e = w.init;
        g_events.clear(); SetupList(8);
        const uint32_t d = ListWords()[2];
        int32_t* guard = (int32_t*)(uintptr_t)NativeAddress(kGuardVa);
        const int32_t keep = *guard;
        *guard = 0x7FFFFFFF;
        check(!ntw_solver::ListInitialized(env), "ListInitialized must report false for guard INT_MAX");
        auto o = ntw_solver::Solve(ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonGuard && untouched(e, w.init, 8, 0, d), "uninitialised guard must fall back untouched");
        *guard = keep;
        check(ntw_solver::ListInitialized(env), "ListInitialized must report true for guard INT_MIN");
        TeardownList();
    }
    // 4. malformed ranges / null arguments
    {
        Fixture f = MakeFixture(r, 900003, 20);
        World w; BuildWorld(f, w);
        std::vector<Entry12> e = w.init;
        g_events.clear(); SetupList(8);
        const uint32_t d = ListWords()[2];
        auto o = ntw_solver::Solve(ws, env, ctx, e.data(), (Entry12*)((uint8_t*)e.data() + 13), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonRange && untouched(e, w.init, 8, 0, d), "misaligned range must fall back untouched");
        o = ntw_solver::Solve(ws, env, ctx, e.data() + 4, e.data(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonRange && untouched(e, w.init, 8, 0, d), "end < begin must fall back untouched");
        o = ntw_solver::Solve(ws, env, nullptr, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonEnv && untouched(e, w.init, 8, 0, d), "null ctx must fall back untouched");
        ntw_solver::Env badEnv = env;
        badEnv.alloc = nullptr;
        o = ntw_solver::Solve(ws, badEnv, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonEnv && untouched(e, w.init, 8, 0, d), "null Env::alloc must fall back untouched");
        TeardownList();
    }
    // 5. kSimd preconditions (checked before anything is written)
    {
        Fixture f = MakeFixture(r, 900004, 24);
        World w; BuildWorld(f, w);
        std::vector<Entry12> e = w.init;
        g_events.clear(); SetupList(8);
        const uint32_t d = ListWords()[2];
        // unmasked MXCSR exception (invalid-operation): packed garbage lanes could trap -> kFallback, nothing written
        const uint32_t csr0 = _mm_getcsr();
        _mm_setcsr(csr0 & ~0x0080u);
        auto o = ntw_solver::SolveWith(ntw_solver::kSimd, true, ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        _mm_setcsr(csr0);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonFpEnv && untouched(e, w.init, 8, 0, d), "kSimd with an unmasked MXCSR exception must fall back untouched");
        o = ntw_solver::SolveWith(ntw_solver::kSimd, false, ws, env, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kSolved, "kSimd with the default MXCSR must solve");
        e = w.init; eax = 0x5A5A5A5Au;
        float ctxBad[2] = {-std::numeric_limits<float>::infinity(), FLT_MAX};
        o = ntw_solver::SolveWith(ntw_solver::kSimd, true, ws, env, ctxBad, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonCtx && untouched(e, w.init, 8, 0, d), "kSimd with def = -inf must fall back untouched");
        ctxBad[0] = FromBits(0x7FC00000u);
        o = ntw_solver::SolveWith(ntw_solver::kSimd, true, ws, env, ctxBad, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonCtx && untouched(e, w.init, 8, 0, d), "kSimd with def = NaN must fall back untouched");
        ntw_solver::Env negPw = env;
        negPw.pairWeight = -0.5f;
        o = ntw_solver::SolveWith(ntw_solver::kSimd, true, ws, negPw, ctx, e.data(), e.data() + e.size(), 0, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kFallback && c.fallback == ntw_solver::kReasonCtx && untouched(e, w.init, 8, 0, d), "kSimd with pairWeight < 0 must fall back untouched");
        // limit != 0 and census mode are not fallbacks: they run the scalar loop
        o = ntw_solver::SolveWith(ntw_solver::kSimd, false, ws, negPw, ctx, e.data(), e.data() + e.size(), 3, FLT_MAX, &eax, &c);
        check(o == ntw_solver::kSolved, "kSimd with limit != 0 must run the scalar loop (no fallback)");
        TeardownList();
    }
    return bad;
}

// ---- micro-benchmark (report only) --------------------------------------------------------------------------------------------
double NowUs() {
    static LARGE_INTEGER freq = [] { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f; }();
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1e6 / (double)freq.QuadPart;
}
double Median(std::vector<double>& v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; }

double TscPerUs() {
    static const double rate = [] {
        const double a = NowUs();
        const uint64_t t0 = __rdtsc();
        while (NowUs() - a < 30000.0) {}
        const uint64_t t1 = __rdtsc();
        return (double)(t1 - t0) / (NowUs() - a);
    }();
    return rate;
}

// Hybrid CPUs: the timing loop must not hop between P and E cores.  Pin to one logical processor of the highest
// efficiency class (Windows: higher = faster) and raise the thread priority; reports which one.
std::string PinToBestCore() {
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
    std::vector<uint8_t> buf(len ? len : 1);
    if (!len || !GetLogicalProcessorInformationEx(RelationProcessorCore, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) return "not pinned";
    int bestClass = -1;
    KAFFINITY bestMask = 0;
    for (DWORD off = 0; off < len;) {
        auto* e = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(buf.data() + off);
        if (e->Relationship == RelationProcessorCore && (int)e->Processor.EfficiencyClass > bestClass) {
            bestClass = (int)e->Processor.EfficiencyClass;
            bestMask = e->Processor.GroupMask[0].Mask;
        }
        off += e->Size;
    }
    if (!bestMask) return "not pinned";
    const KAFFINITY one = bestMask & (~bestMask + 1);
    SetThreadAffinityMask(GetCurrentThread(), one);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    unsigned long idx = 0;
    _BitScanForward(&idx, (unsigned long)one);
    return "pinned to logical CPU " + std::to_string(idx) + " (efficiency class " + std::to_string(bestClass) + ")";
}

void Bench(Rng& r, ntw_solver::Workspace& ws) {
    const ntw_solver::Env env = MakeEnv();
    const std::string pin = PinToBestCore();
    const double tsc = TscPerUs();
    std::printf("\nmicro-benchmark (us per solve, median; limit 0; flag=1 uncapped storm shapes; TSC %.0f MHz; %s; Release x86 /O2 /fp:strict)\n", tsc, pin.c_str());
    std::printf("%-16s %9s %9s %9s | %7s %7s %9s | %9s %8s %9s %7s %7s %6s\n", "scenario", "native", "direct", "simd", "x direct", "x simd",
                "simd/dir", "evals", "distinct", "W(scans)", "swaps", "iters", "it/m");
    for (uint32_t m : {240u, 400u}) {   // live capture 28252: 88 units, median 238 men, p90 399, max 404
        for (int scenario : {6, 4, 0}) {   // ring, col2line, turn
            Fixture f = MakeStorm(r, m, scenario);
            World w; BuildWorld(f, w);
            float ctx[2] = {f.def, f.nos};
            {   // warm caches / the global list's growth path
                Run warm; Execute(kNative, f, w, ws, warm, false);
            }
            SetupList(2048);   // final capacity: no timing run includes list growth
            auto timeIt = [&](auto&& fn, int reps) {
                std::vector<double> t;
                for (int i = 0; i < reps; ++i) {
                    std::vector<Entry12> e = w.init;
                    const double a = NowUs();
                    fn(e);
                    t.push_back(NowUs() - a);
                }
                return Median(t);
            };
            uint32_t eax = 0;
            ntw_solver::Counters ctr{};
            const int natReps = m >= 320 ? 5 : 9;
            const int kReps = m >= 320 ? 21 : 41;
            auto kern = [&](ntw_solver::Policy p, ntw_solver::Counters* c) {
                return [&, p, c](std::vector<Entry12>& e) { ntw_solver::SolveWith(p, true, ws, env, ctx, e.data(), e.data() + m, 0, FLT_MAX, &eax, c); };
            };
            const double tn = timeIt([&](std::vector<Entry12>& e) { CallNative(ctx, e.data(), e.data() + m, 0, FLT_MAX, &eax); }, natReps);
            const double td = timeIt(kern(ntw_solver::kDirect, nullptr), kReps);
            const double ts = timeIt(kern(ntw_solver::kSimd, nullptr), kReps);
            {   // one census solve (not timed): counters of the solve
                std::vector<Entry12> e = w.init;
                ctr.profile = 1;
                ntw_solver::SolveWith(ntw_solver::kDirect, true, ws, env, ctx, e.data(), e.data() + m, 0, FLT_MAX, &eax, &ctr);
            }
            TeardownList();
            std::printf("%-16s %9.1f %9.1f %9.1f | %6.1fx %6.1fx %8.2fx | %9u %8u %9u %7u %7u %6.1f\n", f.label.c_str() + 6, tn, td, ts, tn / td, tn / ts,
                        td / ts, ctr.evals, ctr.distinct, ctr.scans, ctr.swaps, ctr.iterations, (double)ctr.iterations / (double)m);
        }
    }
}

// ---- hand-built deterministic cases ----------------------------------------------------------------------------------------------
// Geometry is translation-invariant (men on x = 100 * i or a line) and every man uses an angle whose table sine/cosine pair has
// t0 == 0 exactly, so entries with identical (dx, dz) have BIT-IDENTICAL costs: that makes ties in the worst-cost scan exact.
Fixture Blank(uint32_t m, const std::string& label, uint16_t angle) {
    Fixture f;
    f.m = m;
    f.label = label;
    f.mx.assign(m, 0.0f); f.mz.assign(m, 0.0f); f.mang.assign(m, angle);
    f.px.assign(m, 0.0f); f.py.assign(m, 0.0f); f.pz.assign(m, 0.0f); f.parent.assign(m, -1);
    f.entMan.resize(m); f.entSlot.resize(m);
    for (uint32_t i = 0; i < m; ++i) { f.entMan[i] = (int32_t)i; f.entSlot[i] = (int32_t)i; }
    f.def = 0.0f; f.nos = FLT_MAX; f.thr = FLT_MAX; f.limit = 0; f.mxcsrMode = 0; f.cap0 = 0;
    return f;
}

int DeterministicCases(ntw_solver::Workspace& ws, Stats& st, int& printed) {
    int bad = 0, cases = 0;
    auto expect = [&](bool ok, const std::string& label, const char* what) {
        if (!ok) { ++bad; std::fprintf(stderr, "FAIL deterministic %s: %s\n", label.c_str(), what); }
    };
    const float* tab = MakeEnv().angleTable;
    int angle = -1;
    for (int a = 0; a < 65536 && angle < 0; ++a) if (tab[2 * a] == 0.0f) angle = a;
    expect(angle >= 0, "setup", "no angle with an exactly zero table sine found");
    if (angle < 0) angle = 0;
    std::printf("deterministic cases: angle index %d (t0 = %g, t1 = %g)\n", angle, tab[2 * angle], tab[2 * angle + 1]);
    const float nanv = FromBits(0x7FC00000u);

    // (1) a NaN pair lane BEFORE the first improving lane inside one 4-lane group, worst in another group.
    //     type 0: man with NaN x and no slot  -> nA = NaN;   type 1: no man and a slot at NaN x -> nB = NaN.
    //     Candidate lanes are "act" (thr > cB) but their pair sum is NaN, so they must be rejected without ending the scan.
    for (int type = 0; type < 2; ++type)
        for (uint32_t nanLane = 0; nanLane < 3; ++nanLane)
            for (uint32_t impLane = nanLane + 1; impLane < 4; ++impLane)
                for (uint32_t groupBase : {0u, 4u}) {
                    const uint32_t m = 16;
                    char buf[96];
                    std::snprintf(buf, sizeof buf, "nan-lane/t%d/nan%u/imp%u/g%u", type, nanLane, impLane, groupBase);
                    Fixture f = Blank(m, buf, (uint16_t)angle);
                    for (uint32_t i = 0; i < m; ++i) { f.mx[i] = 100.0f * (float)i; f.px[i] = 100.0f * (float)i; }
                    const uint32_t wp = groupBase == 0 ? 9 : 2;            // the worst: man at Xw, slot at Xw + 10 (cost 100.5)
                    const float xw = 100.0f * (float)wp;
                    f.px[wp] = xw + 10.0f;
                    const uint32_t ip = groupBase + impLane;               // improving partner: man near W's slot, slot at W's man
                    f.mx[ip] = xw + 9.0f; f.px[ip] = xw;
                    const uint32_t np = groupBase + nanLane;
                    if (type == 0) { f.mx[np] = nanv; f.entSlot[np] = -1; }
                    else { f.entMan[np] = -1; f.px[np] = nanv; }
                    bad += CompareCase(f, ws, st, printed);
                    ++cases;
                    World w; BuildWorld(f, w);
                    Run r; Execute(kSolveCensus, f, w, ws, r, false);
                    expect(r.outcome == ntw_solver::kSolved && r.ctr.swaps >= 1, f.label, "the improving lane behind the NaN lane was never accepted");
                }

    // (2) exact ties in the worst-cost scan at lane (3/4, 7/8) and tournament-node boundaries and at the odd tail; no swap is
    //     possible, so every entry is removed and the list length visits every value m .. 1 (including 7 .. 1) after removals.
    static const uint32_t sizes[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 31, 32, 33, 63, 64, 65};
    for (uint32_t m : sizes) {
        std::vector<std::vector<uint32_t>> sets = {{}, {3, 4}, {7, 8}, {m - 2, m - 1}, {m - 1}, {0, m - 1}, {3, 4, 7, 8}, {m - 3, m - 2, m - 1}, {15, 16}, {31, 32}};
        for (const auto& set : sets) {
            bool valid = true;
            for (uint32_t p : set) if (p >= m) valid = false;
            for (size_t a = 0; a < set.size(); ++a) for (size_t b = a + 1; b < set.size(); ++b) if (set[a] == set[b]) valid = false;
            if (!valid) continue;
            std::string label = "tie/m" + std::to_string(m) + "/set";
            for (uint32_t p : set) label += "." + std::to_string(p);
            Fixture f = Blank(m, label, (uint16_t)angle);
            std::vector<bool> hi(m, false);
            for (uint32_t p : set) hi[p] = true;
            for (uint32_t i = 0; i < m; ++i) {
                f.mx[i] = 100.0f * (float)i;
                f.px[i] = f.mx[i] + (hi[i] ? 3.0f : 1.0f);
                f.pz[i] = hi[i] ? 4.0f : 0.0f;
            }
            bad += CompareCase(f, ws, st, printed);
            ++cases;
            World w; BuildWorld(f, w);
            Run r; Execute(kSolveCensus, f, w, ws, r, false);
            expect(r.outcome == ntw_solver::kSolved && r.ctr.swaps == 0 && r.ctr.removals == m && r.ctr.iterations == m + 1, f.label,
                   "tie fixture must remove every entry without a swap (list length m .. 1)");
            uint32_t hiBits = 0, loBits = 0;
            bool haveHi = false, haveLo = false, equal = true;
            for (uint32_t i = 0; i < m; ++i) {
                uint32_t b;
                std::memcpy(&b, &r.entries[i].cost, 4);
                if (hi[i]) { if (haveHi && b != hiBits) equal = false; hiBits = b; haveHi = true; }
                else { if (haveLo && b != loBits) equal = false; loBits = b; haveLo = true; }
            }
            expect(equal, f.label, "tie fixture costs are not bit-identical inside a class");
            if (haveHi && haveLo) expect(hiBits != loBits, f.label, "tie fixture classes must differ");
        }
    }

    // (3) reversed line (men x = sp*i, slot i at x = sp*(m-1-i)): costs tie in mirror pairs (i, m-1-i), swaps are accepted and the
    //     ties walk through the lane / tree-node boundaries as pairs are fixed from the outside in.
    static const uint32_t rsizes[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 20, 31, 32, 33, 63, 64, 65, 127, 128, 129};
    for (uint32_t m : rsizes)
        for (float sp : {10.0f, 3.0f}) {
            Fixture f = Blank(m, "revline/m" + std::to_string(m) + "/sp" + std::to_string((int)sp), (uint16_t)angle);
            for (uint32_t i = 0; i < m; ++i) { f.mx[i] = sp * (float)i; f.px[i] = sp * (float)(m - 1 - i); }
            bad += CompareCase(f, ws, st, printed);
            ++cases;
            if (m >= 4) {
                World w; BuildWorld(f, w);
                Run r; Execute(kSolveCensus, f, w, ws, r, false);
                expect(r.outcome == ntw_solver::kSolved && r.ctr.swaps >= 1, f.label, "reversed line must accept swaps");
            }
        }
    std::printf("deterministic cases: %d fixtures (NaN-lane, worst-scan ties, reversed line) compared\n", cases);
    return bad;
}

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::string image, tablePath;
    int cases = 2000, bench = 1;
    uint32_t seed = 20261018;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i];
        if (a == "--image") image = argv[i + 1];
        else if (a == "--table") tablePath = argv[i + 1];
        else if (a == "--cases") cases = std::atoi(argv[i + 1]);
        else if (a == "--seed") seed = (uint32_t)std::strtoul(argv[i + 1], nullptr, 10);
        else if (a == "--bench") bench = std::atoi(argv[i + 1]);
    }
    std::vector<uint8_t> file, table;
    if (image.empty() || tablePath.empty() || !ReadAll(image, file) || !ReadAll(tablePath, table)) {
        std::fprintf(stderr, "usage: --image Napoleon.exe --table angle-table.bin [--cases N] [--seed S] [--bench 0|1]\n");
        return 2;
    }
    if (Sha256(file.data(), file.size()) != kImageSha) { std::fprintf(stderr, "image SHA-256 mismatch\n"); return 2; }
    if (table.size() != 65536 * 8 || Sha256(table.data(), table.size()) != kTableSha) { std::fprintf(stderr, "angle table mismatch\n"); return 2; }
    if (!MapImage(file, table)) { std::fprintf(stderr, "image mapping failed\n"); return 2; }
    g_solver = (SolverFn)(uintptr_t)NativeAddress(0x502770);
    ntw_solver::Workspace* ws = ntw_solver::CreateWorkspace();
    if (!ws) { std::fprintf(stderr, "workspace allocation failed\n"); return 2; }
    {   // the constants the Env carries must be the pinned bit patterns (the production caller verifies the same at Start)
        const ntw_solver::Env e = MakeEnv();
        uint32_t z, o, p;
        std::memcpy(&z, &e.zero, 4); std::memcpy(&o, &e.one, 4); std::memcpy(&p, &e.pairWeight, 4);
        std::printf("Env constants: zero %08x one %08x pairWeight %08x\n", z, o, p);
    }
    std::printf("solver oracle: seed=%u cases=%d kMaxM=%u workspace=%llu bytes\n", seed, cases, ntw_solver::kMaxM,
                (unsigned long long)ntw_solver::WorkspaceBytes());
    Rng rng{seed ? seed : 1};
    Stats st;
    int failures = 0, printed = 0;
    {   // fixed edge fixtures first
        const int fixed[] = {0, 1, 2, 3, 7, 60};
        for (int m : fixed)
            for (int k = 0; k < 6; ++k) {
                Fixture f = MakeFixture(rng, 800000 + m * 10 + k, m);
                failures += CompareCase(f, *ws, st, printed);
            }
    }
    {   // live-capture sized formations (median 238, p90 399, max 404 men): uncapped first-improvement, capped best-improvement
        const int big[] = {240, 320, 361, 400, 404};
        for (int m : big)
            for (int k = 0; k < 4; ++k) {
                Fixture f = MakeFixture(rng, 600000 + m * 10 + k, m);
                f.limit = k < 2 ? 0u : (k == 2 ? 1u : 5u);
                f.mxcsrMode = 0;
                failures += CompareCase(f, *ws, st, printed);
            }
    }
    {   // storm-shaped: men on a grid, slots on a turned / shifted / random grid, identity initial pairing, many swaps
        const uint32_t sizes[] = {60, 160, 240, 400};
        for (uint32_t m : sizes)
            for (int scenario = 0; scenario < 8; ++scenario) {
                Fixture f = MakeStorm(rng, m, scenario);
                failures += CompareCase(f, *ws, st, printed);
            }
    }
    for (int i = 0; i < cases; ++i) {
        Fixture f = MakeFixture(rng, (uint32_t)i);
        failures += CompareCase(f, *ws, st, printed);
    }
    failures += DeterministicCases(*ws, st, printed);
    {   // small formations: every list length 1..16 (partial 4-lane blocks, improving lane 0..3, ties, NaN / inf / denormal lanes), limit 0
        for (int i = 0; i < 3000; ++i) {
            Fixture f = MakeFixture(rng, 500000 + (uint32_t)i, 1 + (i % 16));
            f.limit = 0;
            if (i % 4 == 0 && f.m) {
                const bool nan = (i % 8) == 0;
                const uint32_t k = 1 + rng.below(3);
                for (uint32_t q = 0; q < k; ++q) {
                    const uint32_t j = rng.below(f.m);
                    switch (rng.below(4)) {
                        case 0: f.mx[j] = PickSpecial(rng, nan); break;
                        case 1: f.mz[j] = PickSpecial(rng, nan); break;
                        case 2: f.px[j] = PickSpecial(rng, nan); break;
                        default: f.pz[j] = PickSpecial(rng, nan); break;
                    }
                }
                f.label += "/injected";
            }
            failures += CompareCase(f, *ws, st, printed);
        }
    }
    {   // near kMaxM: first-improvement uncapped (heavy) and capped passes
        const uint32_t sizes[] = {ntw_solver::kMaxM, ntw_solver::kMaxM - 1, ntw_solver::kMaxM - 3};
        for (uint32_t m : sizes)
            for (int k = 0; k < 2; ++k) {
                Fixture f = MakeFixture(rng, 700000 + m + k, (int)m);
                f.limit = k == 0 ? 0u : 40u;
                if (k == 0) { f.mxcsrMode = 0; f.cap0 = 0; }
                failures += CompareCase(f, *ws, st, printed);
            }
    }
    failures += FallbackTests(rng, *ws);
    std::printf("native-vs-kernel: cases=%llu kernel-runs=%llu skipped=0 failures=%d maxM=%u counters(evals/distinct/swaps/removals)=%llu/%llu/%llu/%llu "
                "self-checked=%llu distinct-checked=%llu hit-rate=%.1f%%\n",
                (unsigned long long)st.cases, (unsigned long long)st.runs, failures, st.maxM, (unsigned long long)st.evals,
                (unsigned long long)st.distinct, (unsigned long long)st.swaps, (unsigned long long)st.removals,
                (unsigned long long)st.selfChecked, (unsigned long long)st.distinctChecked,
                st.evals ? 100.0 * (1.0 - (double)st.distinct / (double)st.evals) : 0.0);
    if (bench && failures == 0) Bench(rng, *ws);
    ntw_solver::DestroyWorkspace(ws);
    return failures ? 1 : 0;
}
