// x86 comparison harness: executes the ORIGINAL machine code of the pinned Napoleon.exe formation slotting
// (0x18F0A00 wrapper -> 0x18F0200 / 0x5373F0 / 0x18F0D00 / 0x502770 / 0x18F1200, plus 0x5281D0 and 0x557C80)
// inside a private relocated image, and compares the result bit-for-bit
// with native_formation_slot.cpp.  It never touches a game process or the installed files.
//
// Build: CMake target native_formation_slot_harness (MSVC x86, /MT).
// Run:    native_formation_slot_harness.exe --image "<Napoleon.exe>" --table native-formation-angle-table-28252.bin
//             [--fixture native-formation-fixture-28252.bin] [--cases 2000] [--seed 1]
//
// Glue patches applied to the private copy (everything else is original bytes):
//   * 0x00FF7F20 / 0x00FF7EF0 (game heap allocate/free)  -> host malloc/free thunks
//   * 0x0054C8B0 (unit predicate used by 0x5373F0)        -> "mov eax, <case flag>; ret"
//   * data: [0x14A40B0] = INT_MIN (thread-safe-static guard of 0x502770 never takes the init path),
//           [0x1841BB8] = this process' _tls_index; angle table copied to 0x176CFF8.
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <malloc.h>
#include <algorithm>
#include <utility>
#include <vector>
#include <limits>
#include "native_formation_slot.h"
#include "native_image_relocation.h"

#pragma comment(lib, "bcrypt.lib")
static_assert(sizeof(void*) == 4, "x86 build required: the native code is 32-bit");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile int g_tlsPad[32];

namespace {

using namespace ntw_formation;

constexpr uint32_t kImageBase = 0x400000;
constexpr const char* kImageSha = "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4";
constexpr const char* kTableSha = "405383e324f986ad1972b9da231b2bb6d1d496c23067af8de60faf359e2a3581";
constexpr uint32_t kAngleTableVa = 0x176CFF8;
uintptr_t g_image_delta;
uint32_t NativeAddress(uint32_t preferred) { return preferred + static_cast<uint32_t>(g_image_delta); }

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

extern "C" void* __cdecl HostAlloc(size_t size, void*) { return std::malloc(size ? size : 1); }
extern "C" void __cdecl HostFree(void* p) { std::free(p); }

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
    auto* base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!base) return false;
    g_image_delta = reinterpret_cast<uintptr_t>(base) - kImageBase;
    std::memcpy(base, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t n = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        std::memcpy((uint8_t*)base + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    if (!RelocateNativeImage(base, size, nt, g_image_delta)) {
        VirtualFree(base, 0, MEM_RELEASE); return false;
    }
    std::memcpy((void*)(uintptr_t)NativeAddress(kAngleTableVa), table.data(), table.size());
    PatchJump(0x00FF7F20, (const void*)&HostAlloc);
    PatchJump(0x00FF7EF0, (const void*)&HostFree);
    *(int32_t*)(uintptr_t)NativeAddress(0x14A40B0) = (int32_t)0x80000000;
    *(uint32_t*)(uintptr_t)NativeAddress(0x1841BB8) = _tls_index;
    g_tlsPad[0] = 0;
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}

void SetUnitPredicate(uint32_t v) {                  // 0x54C8B0: mov eax, imm32 ; ret
    uint8_t* p = (uint8_t*)(uintptr_t)NativeAddress(0x54C8B0);
    p[0] = 0xB8;
    std::memcpy(p + 1, &v, 4);
    p[5] = 0xC3;
    if (!FlushInstructionCache(GetCurrentProcess(), p, 6)) std::exit(2);
}

using WrapperFn = void(__thiscall*)(void* formation, void* slotVec, uint32_t flag, void* assignVec, int32_t layoutIdx);
using CostFn = float(__stdcall*)(const void* man, const void* slot);
using SolverFn = uint32_t(__thiscall*)(void* ctx, void* begin, void* end, uint32_t limit, float threshold);
using StatFn = void(__thiscall*)(void* formation, void* slotVec, float distance);

WrapperFn g_wrapper;
CostFn g_cost;
SolverFn g_solver;
StatFn g_stat;

struct Rng {
    uint32_t s;
    uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    uint32_t below(uint32_t n) { return n ? next() % n : 0; }
    float unit() { return (float)(next() >> 8) / 16777216.0f; }
};

enum ManClass : uint8_t { kNormal = 0, kAnchored = 1, kOfficer = 2 };

struct Case {
    uint32_t n = 0, m = 0;
    uint8_t unitFlag = 0, flagParam = 0;
    int32_t layoutIndex = -1;
    uint8_t modEligible = 0;
    uint32_t modBreak = 0;                           // 0 none, 1 layout vtable, 2 side!=2, 3 no side object
    std::vector<float> x, z;
    std::vector<uint16_t> ang;
    std::vector<uint8_t> cls, skip;
    std::vector<uint32_t> id;
    std::vector<float> sx, sz;
    std::vector<uint16_t> sang;
    std::string label;
};

void ManArrays(const Case& c, std::vector<uint8_t>& anchored, std::vector<uint8_t>& marker) {
    anchored.assign(c.n, 0);
    marker.assign(c.n, 0xFF);
    for (uint32_t i = 0; i < c.n; ++i) {
        anchored[i] = c.cls[i] != kNormal;
        uint32_t k = c.id[i] - 0x57460000u;
        if (c.cls[i] == kOfficer && k <= 2) marker[i] = (uint8_t)k;
    }
}

// Mock objects with the exact native offsets (formation, men, unit, layout, slot vector/records).
struct Mock {
    std::vector<uint8_t*> men;
    uint8_t* menArray = nullptr;
    uint8_t* formation = nullptr;
    uint8_t* unit = nullptr;
    uint8_t* side = nullptr;
    uint8_t* layout = nullptr;
    uint32_t* layoutVtbl = nullptr;
    uint8_t* slotRecs = nullptr;
    uint32_t slotVec[6] = {};
    uint32_t assignVec[4] = {};
    uint8_t* tickObj = nullptr;
    uint8_t* tickObj2 = nullptr;
    ~Mock() {
        for (auto* p : men) _aligned_free(p);
        std::free(menArray);
        _aligned_free(formation);
        _aligned_free(unit);
        _aligned_free(side);
        _aligned_free(layout);
        std::free(layoutVtbl);
        std::free(slotRecs);
        _aligned_free(tickObj);
        _aligned_free(tickObj2);
        if (assignVec[3]) std::free((void*)(uintptr_t)assignVec[3]);
    }
};

uint8_t* Alloc(size_t n) {
    uint8_t* p = (uint8_t*)_aligned_malloc(n, 16);
    std::memset(p, 0, n);
    return p;
}
template <typename T> void Put(uint8_t* base, uint32_t off, T v) { std::memcpy(base + off, &v, sizeof(T)); }
template <typename T> T Get(const uint8_t* base, uint32_t off) { T v; std::memcpy(&v, base + off, sizeof(T)); return v; }

void Build(const Case& c, Mock& k) {
    k.men.resize(c.n);
    k.menArray = (uint8_t*)std::malloc(c.n * 4 + 4);
    for (uint32_t i = 0; i < c.n; ++i) {
        uint8_t* m = Alloc(0x700);
        uint32_t vt = c.cls[i] == kOfficer ? 0x134841Cu : (c.cls[i] == kAnchored ? 0x13477F8u : 0x1333714u);
        Put<uint32_t>(m, 0, NativeAddress(vt));
        Put<float>(m, 0x48, c.x[i]);
        Put<float>(m, 0x50, c.z[i]);
        Put<uint16_t>(m, 0x64, c.ang[i]);
        Put<uint32_t>(m, 0x66C, c.id[i]);
        Put<uint8_t>(m, 0x1A8, c.skip[i]);
        k.men[i] = m;
        Put<uint32_t>(k.menArray, i * 4, (uint32_t)(uintptr_t)m);
    }
    k.formation = Alloc(0x2800);
    k.unit = Alloc(0x1000);
    k.side = Alloc(0x100);
    k.layout = Alloc(0x40);
    k.layoutVtbl = (uint32_t*)std::calloc(0x40, 4);
    k.tickObj = Alloc(0x100);
    k.tickObj2 = Alloc(0x100);
    Put<uint32_t>(k.tickObj2, 0x58, 777);
    Put<uint32_t>(k.tickObj, 8, (uint32_t)(uintptr_t)k.tickObj2);
    Put<uint32_t>(k.formation, 4, (uint32_t)(uintptr_t)k.tickObj);
    Put<uint32_t>(k.formation, 0x18, c.n);
    Put<uint32_t>(k.formation, 0x1C, (uint32_t)(uintptr_t)k.menArray);
    Put<uint32_t>(k.formation, 0x510, (uint32_t)(uintptr_t)k.unit);
    Put<uint32_t>(k.formation, 0x628, (uint32_t)(uintptr_t)k.layout);
    Put<uint32_t>(k.layout, 0, (uint32_t)(uintptr_t)k.layoutVtbl);
    k.layoutVtbl[0x24 / 4] = NativeAddress((c.modBreak == 1) ? 0x62FD60u : 0x18ED200u);
    if (c.modBreak != 3) Put<uint32_t>(k.unit, 0x2C, (uint32_t)(uintptr_t)k.side);
    Put<uint32_t>(k.side, 0x1C, c.modBreak == 2 ? 1u : 2u);
    k.slotRecs = (uint8_t*)std::calloc(c.m ? c.m : 1, 36);
    for (uint32_t i = 0; i < c.m; ++i) {
        uint8_t* r = k.slotRecs + 36 * i;
        Put<float>(r, 4, c.sx[i]);
        Put<float>(r, 8, 0.0f);
        Put<float>(r, 0xC, c.sz[i]);
        Put<uint32_t>(r, 0x14, 0);
        Put<uint16_t>(r, 0x18, c.sang[i]);
    }
    k.slotVec[1] = c.m;
    k.slotVec[2] = c.m;
    k.slotVec[3] = (uint32_t)(uintptr_t)k.slotRecs;
}

struct NativeResult {
    std::vector<Entry> entries;
    float statZeroed = 0;
    bool stat0 = false;
    bool faulted = false;
};

uint32_t ManIndex(const Mock& k, uint32_t ptr) {
    if (ptr == 0) return kNone;
    for (uint32_t i = 0; i < k.men.size(); ++i)
        if ((uint32_t)(uintptr_t)k.men[i] == ptr) return i;
    return 0xFFFFFFFEu;
}

bool CallWrapper(Mock& k, const Case& c) {
    __try {
        g_wrapper(k.formation, k.slotVec, c.flagParam, k.assignVec, c.layoutIndex);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool CallStat(Mock& k) {
    __try {
        g_stat(k.formation, k.slotVec, 4.0f);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

NativeResult RunNative(const Case& c) {
    NativeResult r;
    Mock k;
    Build(c, k);
    SetUnitPredicate(c.unitFlag);
    if (!CallWrapper(k, c)) { r.faulted = true; return r; }
    uint32_t cnt = k.assignVec[2];
    uint8_t* data = (uint8_t*)(uintptr_t)k.assignVec[3];
    for (uint32_t i = 0; i < cnt; ++i) {
        uint32_t man = Get<uint32_t>(data, 12 * i), slot = Get<uint32_t>(data, 12 * i + 4);
        Entry e;
        e.man = ManIndex(k, man);
        e.slot = slot ? (slot - (uint32_t)(uintptr_t)k.slotRecs) / 36 : kNone;
        e.cost = Get<float>(data, 12 * i + 8);
        r.entries.push_back(e);
    }
    // 0x555CA0 copies the entry men into formation+0x1C and sets +0x18 before calling 0x557C80.
    Put<uint32_t>(k.formation, 0x18, cnt);
    for (uint32_t i = 0; i < cnt && i < c.n; ++i) Put<uint32_t>(k.menArray, 4 * i, Get<uint32_t>(data, 12 * i));
    Put<uint32_t>(k.formation, 0x2784, 0xDEADBEEFu);
    if (!CallStat(k)) { r.faulted = true; return r; }
    r.stat0 = Get<uint32_t>(k.formation, 0x2784) == 0;
    return r;
}

struct Verdict {
    bool ok = true;
    std::string why;
};

Verdict Compare(const Case& c, const Constants& k, const float* table) {
    Verdict v;
    NativeResult nat = RunNative(c);
    std::vector<uint8_t> anchored, marker;
    ManArrays(c, anchored, marker);
    std::vector<uint8_t> skip = c.skip;
    SlotInput in;
    in.men = c.n; in.slots = c.m;
    in.manX = c.x.data(); in.manZ = c.z.data(); in.manAngle = c.ang.data();
    in.manAnchored = anchored.data(); in.manMarker = marker.data(); in.manSkipDistance = skip.data();
    in.slotX = c.sx.data(); in.slotZ = c.sz.data(); in.slotAngle = c.sang.data();
    in.angleTable = table;
    in.unitFlag = c.unitFlag; in.flagParam = c.flagParam; in.layoutIndex = c.layoutIndex;
    in.modEligible = (c.layoutIndex == -1 && c.modBreak == 0) ? 1 : 0;
    std::vector<Entry> ent(c.n ? c.n : 1);
    std::vector<uint32_t> scratch(c.n ? c.n : 1);
    SlotResult res;
    int st = AssignUnit(in, k, ent.data(), scratch.data(), &res);
    char buf[256];
    if (nat.faulted) { v.ok = false; v.why = "native code faulted"; return v; }
    if (st == kBadInput) {
        // Native reads out of range or loops indefinitely for such inputs; not a comparable case.
        v.why = "bad-input (not compared)";
        return v;
    }
    if (st == kNoOp) {
        if (!nat.entries.empty()) { v.ok = false; v.why = "port no-op but native produced entries"; }
        return v;
    }
    if (nat.entries.size() != res.entryCount) {
        std::snprintf(buf, sizeof buf, "entry count native %zu port %u", nat.entries.size(), res.entryCount);
        v.ok = false; v.why = buf; return v;
    }
    for (uint32_t i = 0; i < res.entryCount; ++i) {
        uint32_t nb, pb;
        std::memcpy(&nb, &nat.entries[i].cost, 4);
        std::memcpy(&pb, &ent[i].cost, 4);
        if (nat.entries[i].man != ent[i].man || nat.entries[i].slot != ent[i].slot || nb != pb) {
            std::snprintf(buf, sizeof buf, "entry %u native(man %u slot %u cost %08x) port(man %u slot %u cost %08x)", i,
                          nat.entries[i].man, nat.entries[i].slot, nb, ent[i].man, ent[i].slot, pb);
            v.ok = false; v.why = buf; return v;
        }
    }
    if (nat.stat0 != (res.refreshZero != 0)) {
        v.ok = false; v.why = "0x557C80 refresh decision differs"; return v;
    }
    return v;
}

// ---- case generation ---------------------------------------------------------------------------------------
void MakeSlots(Case& c, Rng& r, bool sameAngle, bool lattice) {
    c.m = c.n + (r.below(4) == 0 ? r.below(5) : 0);
    uint32_t files = 2 + r.below(40);
    float spacing = lattice ? 1.0f : 0.8f + 0.6f * r.unit();
    float ox = (r.unit() - 0.5f) * 300.0f, oz = (r.unit() - 0.5f) * 300.0f;
    uint16_t a0 = (uint16_t)r.next();
    for (uint32_t i = 0; i < c.m; ++i) {
        float fx = (float)(i % files) - 0.5f * (float)(files - 1);
        float fz = (float)(i / files);
        c.sx.push_back(ox + fx * spacing);
        c.sz.push_back(oz - fz * spacing);
        c.sang.push_back(sameAngle ? a0 : (uint16_t)(a0 + (r.below(25) == 0 ? 1 : 0)));
    }
}

Case MakeRandom(Rng& r, uint32_t idx) {
    Case c;
    c.n = 2 + r.below(r.below(5) == 0 ? 320 : 90);
    bool lattice = r.below(3) == 0;
    for (uint32_t i = 0; i < c.n; ++i) {
        float gx = lattice ? (float)(r.below(40)) : r.unit() * 40.0f;
        float gz = lattice ? (float)(r.below(8)) : r.unit() * 12.0f;
        c.x.push_back(gx);
        c.z.push_back(gz);
        c.ang.push_back(r.below(3) == 0 ? (uint16_t)r.next() : (uint16_t)(idx * 977));
        c.cls.push_back(kNormal);
        c.skip.push_back(r.below(40) == 0);
        c.id.push_back(0);
    }
    uint32_t anchored = r.below(3) == 0 ? 0 : r.below(10);
    for (uint32_t a = 0; a < anchored && a < c.n; ++a) c.cls[r.below(c.n)] = kAnchored;
    uint32_t officers = r.below(5);
    for (uint32_t a = 0; a < officers; ++a) {
        uint32_t i = r.below(c.n);
        c.cls[i] = kOfficer;
        c.id[i] = 0x57460000u + (r.below(6) == 0 ? 3 + r.below(3) : r.below(3));
    }
    c.unitFlag = r.below(4) == 0;
    c.flagParam = (uint8_t)(r.below(8) == 0 ? 2 + r.below(3) : r.below(2));
    c.layoutIndex = r.below(5) == 0 ? (int32_t)r.below(c.n) : -1;
    c.modBreak = r.below(4) == 0 ? 1u + r.below(3) : 0u;
    c.modEligible = c.modBreak == 0;
    MakeSlots(c, r, r.below(8) != 0, lattice);
    c.label = "random#" + std::to_string(idx);
    return c;
}

// ---- isolated cost / solver comparison ---------------------------------------------------------------------
bool CallCost(const void* man, const void* slot, float* out) {
    __try { *out = g_cost(man, slot); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallSolver(void* ctx, void* b, void* e, uint32_t lim, float thr, uint32_t* ret) {
    __try { *ret = g_solver(ctx, b, e, lim, thr); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

int CompareCost(Rng& r, const float* table, int count, const Constants& k) {
    int bad = 0;
    for (int t = 0; t < count; ++t) {
        Case c = MakeRandom(r, 100000 + t);
        Mock m; Build(c, m);
        std::vector<uint8_t> anch, mark; ManArrays(c, anch, mark);
        SlotInput in;
        in.men = c.n; in.slots = c.m; in.manX = c.x.data(); in.manZ = c.z.data(); in.manAngle = c.ang.data();
        in.slotX = c.sx.data(); in.slotZ = c.sz.data(); in.slotAngle = c.sang.data(); in.angleTable = table;
        for (int q = 0; q < 8; ++q) {
            uint32_t a = r.below(c.n), b = r.below(c.m);
            float nat = 0;
            if (!CallCost(m.men[a], m.slotRecs + 36 * b, &nat)) { ++bad; continue; }
            float port = PairCost(in, k, a, b);
            if (std::memcmp(&nat, &port, 4) != 0) {
                ++bad;
                std::fprintf(stderr, "cost mismatch man %u slot %u native %.9g port %.9g\n", a, b, nat, port);
            }
        }
    }
    return bad;
}

int CompareSolver(Rng& r, const float* table, int count, const Constants& k) {
    int bad = 0;
    for (int t = 0; t < count; ++t) {
        Case c = MakeRandom(r, 200000 + t);
        Mock m; Build(c, m);
        std::vector<uint8_t> anch, mark; ManArrays(c, anch, mark);
        SlotInput in;
        in.men = c.n; in.slots = c.m; in.manX = c.x.data(); in.manZ = c.z.data(); in.manAngle = c.ang.data();
        in.slotX = c.sx.data(); in.slotZ = c.sz.data(); in.slotAngle = c.sang.data(); in.angleTable = table;
        uint32_t cnt = c.n;
        std::vector<uint32_t> perm(cnt);
        for (uint32_t i = 0; i < cnt; ++i) perm[i] = i;
        for (uint32_t i = cnt; i > 1; --i) std::swap(perm[i - 1], perm[r.below(i)]);
        std::vector<Entry> pe(cnt);
        std::vector<uint8_t> raw(cnt * 12 + 12, 0);
        for (uint32_t i = 0; i < cnt; ++i) {
            bool nullMan = r.below(30) == 0, nullSlot = r.below(30) == 0;
            pe[i].man = nullMan ? kNone : perm[i];
            pe[i].slot = nullSlot ? kNone : i;
            pe[i].cost = 0.0f;
            Put<uint32_t>(raw.data(), 12 * i, nullMan ? 0 : (uint32_t)(uintptr_t)m.men[perm[i]]);
            Put<uint32_t>(raw.data(), 12 * i + 4, nullSlot ? 0 : (uint32_t)(uintptr_t)(m.slotRecs + 36 * i));
            Put<float>(raw.data(), 12 * i + 8, 0.0f);
        }
        static const uint32_t limits[] = {0, 1, 2, 5};
        static const float thresholds[] = {3.4028235e38f, 16.0f, 2.5f, 1.0f};
        uint32_t lim = limits[r.below(4)];
        float thr = thresholds[r.below(4)];
        float ctx[2] = {r.below(3) == 0 ? 0.5f : 0.0f, r.below(2) ? 3.4028235e38f : 9.0f};
        uint32_t nret = 0;
        if (!CallSolver(ctx, raw.data(), raw.data() + cnt * 12, lim, thr, &nret)) { ++bad; continue; }
        std::vector<uint32_t> list(cnt + 1);
        uint32_t iters = 0;
        uint8_t pret = Solver(in, k, ctx[0], ctx[1], pe.data(), pe.data() + cnt, lim, thr, list.data(), &iters);
        bool same = ((nret & 0xFF) == pret);
        for (uint32_t i = 0; same && i < cnt; ++i) {
            uint32_t nm = Get<uint32_t>(raw.data(), 12 * i), ns = Get<uint32_t>(raw.data(), 12 * i + 4);
            uint32_t nbits = Get<uint32_t>(raw.data(), 12 * i + 8), pbits;
            std::memcpy(&pbits, &pe[i].cost, 4);
            uint32_t pm = pe[i].man == kNone ? 0 : (uint32_t)(uintptr_t)m.men[pe[i].man];
            uint32_t ps = pe[i].slot == kNone ? 0 : (uint32_t)(uintptr_t)(m.slotRecs + 36 * pe[i].slot);
            same = nm == pm && ns == ps && nbits == pbits;
        }
        if (!same) {
            ++bad;
            std::fprintf(stderr, "solver mismatch case %d (n=%u limit=%u thr=%g)\n", t, cnt, lim, thr);
        }
    }
    return bad;
}

// ---- captured fixtures ------------------------------------------------------------------------------------
bool LoadFixture(const std::string& path, std::vector<Case>& out) {
    std::vector<uint8_t> b;
    if (!ReadAll(path, b) || b.size() < 12 || std::memcmp(b.data(), "NTWFSLT1", 8) != 0) return false;
    size_t o = 8;
    uint32_t units = Get<uint32_t>(b.data(), (uint32_t)o); o += 4;
    for (uint32_t u = 0; u < units; ++u) {
        Case c;
        c.n = Get<uint32_t>(b.data(), (uint32_t)o); c.m = Get<uint32_t>(b.data(), (uint32_t)o + 4);
        c.unitFlag = (uint8_t)Get<uint32_t>(b.data(), (uint32_t)o + 8);
        c.flagParam = (uint8_t)Get<uint32_t>(b.data(), (uint32_t)o + 12);
        c.modEligible = (uint8_t)Get<uint32_t>(b.data(), (uint32_t)o + 16);
        c.layoutIndex = Get<int32_t>(b.data(), (uint32_t)o + 20);
        c.modBreak = c.modEligible ? 0u : 1u;
        o += 24;
        for (uint32_t i = 0; i < c.n; ++i) {
            c.x.push_back(Get<float>(b.data(), (uint32_t)o));
            c.z.push_back(Get<float>(b.data(), (uint32_t)o + 4));
            c.ang.push_back(Get<uint16_t>(b.data(), (uint32_t)o + 8));
            c.cls.push_back(Get<uint8_t>(b.data(), (uint32_t)o + 10));
            c.id.push_back(Get<uint32_t>(b.data(), (uint32_t)o + 11));
            c.skip.push_back(Get<uint8_t>(b.data(), (uint32_t)o + 15));
            o += 16;
        }
        for (uint32_t i = 0; i < c.m; ++i) {
            c.sx.push_back(Get<float>(b.data(), (uint32_t)o));
            c.sz.push_back(Get<float>(b.data(), (uint32_t)o + 4));
            c.sang.push_back(Get<uint16_t>(b.data(), (uint32_t)o + 8));
            o += 10;
        }
        c.label = "fixture#" + std::to_string(u);
        out.push_back(std::move(c));
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::string image, tablePath, fixture;
    int cases = 2000;
    uint32_t seed = 1;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i];
        if (a == "--image") image = argv[i + 1];
        else if (a == "--table") tablePath = argv[i + 1];
        else if (a == "--fixture") fixture = argv[i + 1];
        else if (a == "--cases") cases = std::atoi(argv[i + 1]);
        else if (a == "--seed") seed = (uint32_t)std::strtoul(argv[i + 1], nullptr, 10);
    }
    std::vector<uint8_t> file, table;
    if (image.empty() || tablePath.empty() || !ReadAll(image, file) || !ReadAll(tablePath, table)) {
        std::fprintf(stderr, "usage: --image Napoleon.exe --table angle-table.bin [--fixture f.bin] [--cases N] [--seed S]\n");
        return 2;
    }
    if (Sha256(file.data(), file.size()) != kImageSha) { std::fprintf(stderr, "image SHA-256 mismatch\n"); return 2; }
    if (table.size() != 65536 * 8 || Sha256(table.data(), table.size()) != kTableSha) {
        std::fprintf(stderr, "angle table mismatch\n");
        return 2;
    }
    if (!MapImage(file, table)) return 2;
    g_wrapper = (WrapperFn)(uintptr_t)NativeAddress(0x18F0A00);
    g_cost = (CostFn)(uintptr_t)NativeAddress(0x5281D0);
    g_solver = (SolverFn)(uintptr_t)NativeAddress(0x502770);
    g_stat = (StatFn)(uintptr_t)NativeAddress(0x557C80);
    const float* tab = (const float*)(uintptr_t)NativeAddress(kAngleTableVa);
    Constants k;
    // The constants are read from the mapped image so the port cannot drift from the pinned bytes.
    k.pairWeight = *(const float*)(uintptr_t)NativeAddress(0x1318038);
    k.one = *(const float*)(uintptr_t)NativeAddress(0x1318048);
    k.zero = *(const float*)(uintptr_t)NativeAddress(0x131A7A4);
    k.thresholdFlag1 = *(const float*)(uintptr_t)NativeAddress(0x1325DB4);
    k.thresholdFlag0 = *(const float*)(uintptr_t)NativeAddress(0x1325D48);

    Rng rng{seed ? seed : 1};
    int failures = 0, compared = 0, skipped = 0;
    failures += CompareCost(rng, tab, 200, k);
    failures += CompareSolver(rng, tab, cases, k);
    std::vector<Case> all;
    for (int i = 0; i < cases; ++i) all.push_back(MakeRandom(rng, (uint32_t)i));
    if (!fixture.empty()) {
        std::vector<Case> fx;
        if (!LoadFixture(fixture, fx)) { std::fprintf(stderr, "bad fixture\n"); return 2; }
        for (auto& c : fx) all.push_back(std::move(c));
    }
    for (auto& c : all) {
        Verdict v = Compare(c, k, tab);
        if (!v.ok) {
            ++failures;
            std::fprintf(stderr, "FAIL %s n=%u m=%u unit=%u flag=%u idx=%d mod=%u: %s\n", c.label.c_str(), c.n, c.m, c.unitFlag,
                         c.flagParam, c.layoutIndex, c.modEligible, v.why.c_str());
        } else if (!v.why.empty()) {
            ++skipped;
        } else {
            ++compared;
        }
    }
    std::printf("native-vs-port: compared=%d skipped=%d failures=%d\n", compared, skipped, failures);
    return failures ? 1 : 0;
}
