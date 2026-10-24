// Chain oracle for the --army-solver-memo / --army-solver-shadow SOLVER_* clone family (src/army/native_army_solver.{h,cpp}).
//
// Maps the SHA-pinned STOCK Napoleon.exe and applies the REAL production gameplay overlay (ALL or SKIP{15}) before
// building the REAL production clone set (kntwr_build_clones, same source-hash pins). Binds the real host gates through
// kntwr_army_solver::Bind and activated through kntwr_army_solver::Start with the private image's delta), and runs twin fixtures:
//   twin A: the ORIGINAL 0x18F0A00 (+ 0x18F0200 / 0x5373F0 / 0x18F0D00 trampoline / 0x502770 / 0x18F1200) of the same image;
//   twin B: AssignGate -> CLONE_SOLVER_18F0A00 -> {CLONE_SOLVER_5373F0 -> SolveShim, CLONE_SOLVER_18F1200 -> SolveGate} in the module modes
//           forward (every solve native; oracle-only mode), memo (kernel replaces the solver) and shadow (native authoritative, kernel compared).
// Compared per case and mode: the normalised byte image of every mock object the chain can touch (formation 0x2800, unit, side, layout, men
// 0x700 each, member array, slot vector/records, tick objects, the assignment vector header and its entries; object pointers are replaced
// by (object, offset) tags because the twins live at different heap addresses), the global list 0x14A40A4/A8 (cap, count; data pointer
// non-null iff cap; the list CONTENTS are dead data the kernel does not replicate), the allocator call sequence (sizes, free ordinals),
// EBX/ESI/EDI/EBP/ESP, MXCSR control and the x87 control word. The SolveShim's suppress/forward counts are checked EXACTLY, per case and
// per mode, against the counts of the ORIGINAL trampoline 0x18F0D00 observed in the native twin: observation-only hooks replace its two
// exits (`pop eax; popfd; ret 0x10` at 0x18F0D1D = suppress, `pop eax; popfd; jmp 0x502770` at 0x18F0D22 = forward) by a jump to a host stub
// that counts and then performs the identical exit (the call/pop PIC test above them is untouched). No heuristic expectation is used: the
// pre-step result alone does NOT decide suppression, because 0x5373F0 only reaches the trampoline (call at 0x53765A) when it left men
// unpushed (0x537613 `cmp eax, edx; jbe 0x537779`), e.g. never when every man is pushed by its first pass (unit predicate set / anchored men).
//
// Glue patches of the private copy (everything else is original bytes; clones are built BEFORE the patches): 0x00FF7F20 / 0x00FF7EF0
// (game heap) -> logging host malloc/free, 0x0054C8B0 (unit predicate used by 0x5373F0) -> `mov eax, <case flag>; ret`, [0x14A40B0] = INT_MIN,
// [0x1841BB8] = this process' _tls_index, angle table at 0x176CFF8.
// Not covered: slot records with a parent pose (0x7F4950 transform path), covered by the kernel oracle (native_formation_solver_oracle).
// Cache extension: native 57AC10 vs CLONE_SOLVER_57AC10 includes the real 539C90/4B4A50 assignment
// path and native map writeback/free, in off/forward/memo/shadow. Direct 539C90 twins test finite flags.
// 584E10's enclosing update is not executed: it needs the wider live cache/update object graph. Its
// incoming calls and 585269 -> 57AC10 edge are checked below and its production clone hash is pinned.
// Cache solver context is natively fixed to {0, FLT_MAX}; hostile-context kernel fallback coverage
// remains in native_formation_solver_oracle, not a patched/artificial cache instruction stream.
//
// Run: native_army_solver_chain_oracle.exe --image "<stock Napoleon.exe>" --table native-formation-angle-table-28252.bin [--cases 300] [--seed 1] [--skip-cache-overlay 1]
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <float.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <malloc.h>
#include <algorithm>
#include <vector>
#include "army/native_army_solver.h"
#include "formation/native_formation_solver.h"
#include "clones/kntwr_clones.h"
#include "native_image_relocation.h"
#include "core/kntwr_gameplay_patch.h"

#pragma comment(lib, "bcrypt.lib")
static_assert(sizeof(void*) == 4, "x86 build required: the native code is 32-bit");
extern "C" unsigned long _tls_index;
__declspec(thread) static volatile int g_tlsPad[32];

namespace {
namespace as = kntwr_army_solver;
using U = uint32_t;

constexpr U kImageBase = 0x400000;
constexpr const char* kImageSha = "44880ec1770f600163a336eec83b4366901484c5cceec83dc326e2932f02a054";
constexpr const char* kTableSha = "405383e324f986ad1972b9da231b2bb6d1d496c23067af8de60faf359e2a3581";
constexpr U kAngleTableVa = 0x176CFF8;
uintptr_t g_delta;
uint8_t* g_base;
bool g_skipCacheOverlay;
U NativeAddress(U preferred) { return preferred + static_cast<U>(g_delta); }
U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }

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

// ---- logging game heap
struct HeapEvent { int kind; U value; };       // kind 0 allocate (value = size), 1 free (value = allocation ordinal in this run, or 0xFFFFFFFF)
std::vector<HeapEvent> g_heapLog;
std::map<void*, U> g_heapOrdinal;
U g_heapNext;
extern "C" void* __cdecl HostAlloc(size_t size, void*) {
    void* p = std::malloc(size ? size : 1);
    g_heapLog.push_back({0, (U)size});
    g_heapOrdinal[p] = g_heapNext++;
    return p;
}
extern "C" void __cdecl HostFree(void* p) {
    auto it = g_heapOrdinal.find(p);
    g_heapLog.push_back({1, it == g_heapOrdinal.end() ? 0xFFFFFFFFu : it->second});
    if (it != g_heapOrdinal.end()) g_heapOrdinal.erase(it);
    std::free(p);
}
void PatchJump(U va, const void* target) {
    uint8_t* p = (uint8_t*)(uintptr_t)NativeAddress(va);
    p[0] = 0xB8;
    U t = Addr(target);
    std::memcpy(p + 1, &t, 4);
    p[5] = 0xFF;
    p[6] = 0xE0;
}

// ---- mapped image + production clones
U g_bindings[KNTWR_BIND_COUNT];
kntwr_clone_set g_clones;

bool CheckCall(U site, U target) {
    const uint8_t* p = (const uint8_t*)(uintptr_t)NativeAddress(site);
    int32_t rel = 0;
    std::memcpy(&rel, p + 1, 4);
    if (p[0] == 0xE8 && NativeAddress(site + 5) + rel == NativeAddress(target)) return true;
    std::fprintf(stderr, "call identity mismatch at %#x (expected %#x)\n", site, target);
    return false;
}
bool MapImage(const std::vector<uint8_t>& file, const std::vector<uint8_t>& table) {
    auto* dos = (const IMAGE_DOS_HEADER*)file.data();
    auto* nt = (const IMAGE_NT_HEADERS32*)(file.data() + dos->e_lfanew);
    if (nt->OptionalHeader.ImageBase != kImageBase) return false;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    constexpr U patchedSize = 0x14F5000;
    const U tailOffset = (static_cast<U>(size) + 0xFFFFu) & ~0xFFFFu;
    const U reservedSize = (patchedSize + 0xFFFFu) & ~0xFFFFu;
    if (tailOffset >= reservedSize) return false;
    // Keep the appended extent owned throughout relocation and overlay preparation. Merely probing
    // then releasing it allows this process's later allocations to occupy the remapper's required tail.
    void* probe = VirtualAlloc(nullptr, reservedSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!probe) return false;
    if (!VirtualFree(probe, 0, MEM_RELEASE)) return false;
    void* tailAddress = static_cast<uint8_t*>(probe) + tailOffset;
    const U tailSize = reservedSize - tailOffset;
    void* tail = VirtualAlloc(tailAddress, tailSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!tail) return false; // No retries and no release of somebody else's reservation.
    g_base = static_cast<uint8_t*>(VirtualAlloc(probe, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!g_base) { VirtualFree(tail, 0, MEM_RELEASE); return false; }
    g_delta = reinterpret_cast<uintptr_t>(g_base) - kImageBase;
    std::memcpy(g_base, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const U mapped = (sec[i].Misc.VirtualSize + 0xFFFu) & ~0xFFFu;
        U n = sec[i].SizeOfRawData < mapped ? sec[i].SizeOfRawData : mapped;
        std::memcpy(g_base + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    if (!RelocateNativeImage(g_base, size, nt, g_delta)) return false;
    if (!CheckCall(0x539CA5, 0x5373F0) || !CheckCall(0x53765A, 0x502770)) return false;
    U blobSize = 0;
    const uint8_t* blob = kntwr_gp_napoleon_blob(&blobSize);
    kntwr_gp_blob_info info{};
    if (kntwr_gp_blob_describe(blob, blobSize, &info) != 0 || std::strcmp(info.stock_sha256, kImageSha) != 0) return false;
    kntwr_gp_pm pm;
    kntwr_gp_pm_init(&pm, GetCurrentProcess());
    // Same guarded owned-reservation contract as native_gameplay_patch_oracle's process fixture.
    // The backend rechecks ownership and releases it only at the actual remap, never at preflight.
    MEMORY_BASIC_INFORMATION tailInfo{};
    if (VirtualQuery(tail, &tailInfo, sizeof(tailInfo)) != sizeof(tailInfo) ||
        tail != tailAddress || tailInfo.BaseAddress != tail || tailInfo.AllocationBase != tail ||
        tailInfo.RegionSize != tailSize || tailInfo.State != MEM_RESERVE || tailInfo.Type != MEM_PRIVATE) return false;
    pm.owned_reserve_base = Addr(tail);
    pm.owned_reserve_size = tailSize;
    kntwr_gp_memory memory = kntwr_gp_pm_memory(&pm);
    kntwr_gp_filter filter{};
    if (g_skipCacheOverlay) { filter.mode = KNTWR_GP_SKIP; filter.runs[0] = 1u << 15; }
    kntwr_gp_report report{};
    if (kntwr_gp_apply_filtered(&memory, Addr(g_base), kImageBase, blob, blobSize, &filter, &report) != 0) {
        std::fprintf(stderr, "production overlay failed: %s (run %u va %#x)\n", report.error, report.fail_run, report.fail_va);
        return false;
    }
    if (pm.owned_reserve_base != 0 || pm.owned_reserve_size != 0) return false;
    if (report.runs_skipped != (g_skipCacheOverlay ? 1u : 0u) ||
        !CheckCall(0x539CA5, g_skipCacheOverlay ? 0x5373F0 : 0x18F0A00) ||
        !CheckCall(0x53765A, 0x18F0D00) || !CheckCall(0x555CEB, 0x18F0A00) ||
        !CheckCall(0x57AC3B, 0x539C90) || !CheckCall(0x585269, 0x57AC10) ||
        !CheckCall(0x51A8FD, 0x584E10) || !CheckCall(0x581B81, 0x584E10)) return false;
    static const uint8_t getter[] = {0x8B, 0x41, 0x04, 0xC3};
    if (std::memcmp((const void*)(uintptr_t)NativeAddress(0x4B4A50), getter, sizeof(getter)) != 0) return false;
    DWORD oldProtect;
    // The production remapper replaces the reservation with a SEC_IMAGE view; glue writes must be COW.
    if (!VirtualProtect(g_base, patchedSize, PAGE_EXECUTE_WRITECOPY, &oldProtect)) return false;
    std::printf("baseline: stock SHA %s + production overlay (%s); cache assignment target %#x\n",
                kImageSha, g_skipCacheOverlay ? "SKIP{15}" : "ALL", g_skipCacheOverlay ? 0x5373F0 : 0x18F0A00);
    std::memcpy((void*)(uintptr_t)NativeAddress(kAngleTableVa), table.data(), table.size());
    // Production clones from the pristine relocated image (all source-span hash pins), BEFORE any glue patch.
    for (U& b : g_bindings) b = NativeAddress(0x6dca08); // unreached bindings: valid image addresses, never executed here
    as::Bind(static_cast<U>(g_delta), g_bindings);
    U detail = 0;
    const U rc = kntwr_build_clones(Addr(g_base), g_bindings, &g_clones, &detail);
    if (rc != 0) { std::fprintf(stderr, "kntwr_build_clones failed: error %u detail %#x\n", rc, detail); return false; }
    PatchJump(0x00FF7F20, (const void*)&HostAlloc);
    PatchJump(0x00FF7EF0, (const void*)&HostFree);
    *(int32_t*)(uintptr_t)NativeAddress(0x14A40B0) = (int32_t)0x80000000;
    *(U*)(uintptr_t)NativeAddress(0x1841BB8) = _tls_index;
    g_tlsPad[0] = 0;
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}
void SetUnitPredicate(U v) {                  // 0x54C8B0: mov eax, imm32 ; ret
    uint8_t* p = (uint8_t*)(uintptr_t)NativeAddress(0x54C8B0);
    p[0] = 0xB8;
    std::memcpy(p + 1, &v, 4);
    p[5] = 0xC3;
    if (!FlushInstructionCache(GetCurrentProcess(), p, 6)) std::exit(2);
}
void ResetList() {                            // global list 0x14A40A4 cap / A8 count / AC data: every run starts from the empty list
    U* l = (U*)(uintptr_t)NativeAddress(0x14A40A4);
    l[0] = 0; l[1] = 0; l[2] = 0;
    g_heapLog.clear(); g_heapOrdinal.clear(); g_heapNext = 0;
}

// ---- observation hooks on the ORIGINAL trampoline 0x18F0D00 (native twin only; clones were built before and never call it)
volatile U g_nativeSuppress, g_nativeForward, g_native502770, g_native502776, g_nativeSolverEntries;
__declspec(naked) void NativeSuppressStub() {
    __asm {
        inc dword ptr [g_nativeSuppress]
        pop eax
        popfd
        ret 0x10
    }
}
__declspec(naked) void NativeForwardStub() {
    __asm {
        inc dword ptr [g_nativeForward]
        pop eax
        popfd
        jmp dword ptr [g_native502770]
    }
}
__declspec(naked) void NativeSolverEntryStub() {          // 0x502770: count the entry, run the displaced `mov eax, fs:[2C]`, resume at 0x502776
    __asm {
        inc dword ptr [g_nativeSolverEntries]
        mov eax, dword ptr fs:[0x2C]
        jmp dword ptr [g_native502776]
    }
}
// Hooks are applied only around the native twin runs and removed again before any chain mode (kntwr_army_solver::Start verifies the pristine
// 0x502770 prologue, and the chain must run against the unhooked image).
struct HookSite { U va; size_t len; uint8_t original[8]; };
HookSite g_hookSites[3] = {{0x18F0D1D, 5, {}}, {0x18F0D22, 7, {}}, {0x502770, 6, {}}};
bool InstallHooks(bool on) {
    static const uint8_t expect[3][8] = {{0x58, 0x9D, 0xC2, 0x10, 0x00},                      // pop eax; popfd; ret 0x10            (suppress exit)
                                         {0x58, 0x9D, 0xE9, 0x47, 0x1A, 0xC1, 0xFE},           // pop eax; popfd; jmp 0x502770       (forward exit)
                                         {0x64, 0xA1, 0x2C, 0x00, 0x00, 0x00}};                // mov eax, fs:[2C]                   (0x502770 entry)
    const void* const stubs[3] = {(const void*)&NativeSuppressStub, (const void*)&NativeForwardStub, (const void*)&NativeSolverEntryStub};
    g_native502770 = NativeAddress(0x502770);
    g_native502776 = NativeAddress(0x502776);
    for (int k = 0; k < 3; ++k) {
        uint8_t* at = (uint8_t*)(uintptr_t)NativeAddress(g_hookSites[k].va);
        const size_t len = g_hookSites[k].len;
        if (on) {
            if (std::memcmp(at, expect[k], len) != 0) return false;
            std::memcpy(g_hookSites[k].original, at, len);
            at[0] = 0xE9;
            const U rel = Addr(stubs[k]) - (Addr(at) + 5);
            std::memcpy(at + 1, &rel, 4);
            for (size_t i = 5; i < len; ++i) at[i] = 0x90;
        } else {
            std::memcpy(at, g_hookSites[k].original, len);
        }
    }
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}

// ---- fixtures (the slot harness' mock objects with the exact native offsets)
struct Rng {
    U s;
    U next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    U below(U n) { return n ? next() % n : 0; }
    float unit() { return (float)(next() >> 8) / 16777216.0f; }
};
enum ManClass : uint8_t { kNormal = 0, kAnchored = 1, kOfficer = 2 };
struct Case {
    U n = 0, m = 0;
    uint8_t unitFlag = 0, flagParam = 0;
    int32_t layoutIndex = -1;
    U modBreak = 0;                           // 0 none, 1 layout vtable, 2 side!=2, 3 no side object
    std::vector<float> x, z;
    std::vector<uint16_t> ang;
    std::vector<uint8_t> cls, skip;
    std::vector<U> id;
    std::vector<float> sx, sz;
    std::vector<uint16_t> sang;
    std::string label;
};
uint8_t* AllocZ(size_t n) {
    uint8_t* p = (uint8_t*)_aligned_malloc(n, 16);
    std::memset(p, 0, n);
    return p;
}
template <typename T> void Put(uint8_t* base, U off, T v) { std::memcpy(base + off, &v, sizeof(T)); }
template <typename T> T Get(const uint8_t* base, U off) { T v; std::memcpy(&v, base + off, sizeof(T)); return v; }

struct Mock {
    std::vector<uint8_t*> men;
    uint8_t* menArray = nullptr;
    uint8_t* formation = nullptr;
    uint8_t* unit = nullptr;
    uint8_t* side = nullptr;
    uint8_t* layout = nullptr;
    U* layoutVtbl = nullptr;
    uint8_t* slotRecs = nullptr;
    U slotVec[6] = {};
    U assignVec[4] = {};
    uint8_t* tickObj = nullptr;
    uint8_t* tickObj2 = nullptr;
    uint8_t cache[0x80] = {};
    std::vector<U> cacheMap;
    U n = 0, m = 0;
    Mock() = default;
    Mock(const Mock&) = delete;
    ~Mock() {
        for (auto* p : men) _aligned_free(p);
        std::free(menArray);
        _aligned_free(formation); _aligned_free(unit); _aligned_free(side); _aligned_free(layout);
        std::free(layoutVtbl); std::free(slotRecs); _aligned_free(tickObj); _aligned_free(tickObj2);
        if (assignVec[3]) std::free((void*)(uintptr_t)assignVec[3]);
    }
};
void Build(const Case& c, Mock& k) {
    k.n = c.n; k.m = c.m;
    k.men.resize(c.n);
    k.menArray = (uint8_t*)std::malloc(c.n * 4 + 4);
    for (U i = 0; i < c.n; ++i) {
        uint8_t* m = AllocZ(0x700);
        U vt = c.cls[i] == kOfficer ? 0x134841Cu : (c.cls[i] == kAnchored ? 0x13477F8u : 0x1333714u);
        Put<U>(m, 0, NativeAddress(vt));
        Put<float>(m, 0x48, c.x[i]);
        Put<float>(m, 0x50, c.z[i]);
        Put<uint16_t>(m, 0x64, c.ang[i]);
        Put<U>(m, 0x66C, c.id[i]);
        Put<uint8_t>(m, 0x1A8, c.skip[i]);
        k.men[i] = m;
        Put<U>(k.menArray, i * 4, Addr(m));
    }
    k.formation = AllocZ(0x2800);
    k.unit = AllocZ(0x1000);
    k.side = AllocZ(0x100);
    k.layout = AllocZ(0x40);
    k.layoutVtbl = (U*)std::calloc(0x40, 4);
    k.tickObj = AllocZ(0x100);
    k.tickObj2 = AllocZ(0x100);
    Put<U>(k.tickObj2, 0x58, 777);
    Put<U>(k.tickObj, 8, Addr(k.tickObj2));
    Put<U>(k.formation, 4, Addr(k.tickObj));
    Put<U>(k.formation, 0x18, c.n);
    Put<U>(k.formation, 0x1C, Addr(k.menArray));
    Put<U>(k.formation, 0x510, Addr(k.unit));
    Put<U>(k.formation, 0x628, Addr(k.layout));
    Put<U>(k.layout, 0, Addr(k.layoutVtbl));
    k.layoutVtbl[0x24 / 4] = NativeAddress((c.modBreak == 1) ? 0x62FD60u : 0x18ED200u);
    if (c.modBreak != 3) Put<U>(k.unit, 0x2C, Addr(k.side));
    Put<U>(k.side, 0x1C, c.modBreak == 2 ? 1u : 2u);
    k.slotRecs = (uint8_t*)std::calloc(c.m ? c.m : 1, 36);
    for (U i = 0; i < c.m; ++i) {
        uint8_t* r = k.slotRecs + 36 * i;
        Put<float>(r, 4, c.sx[i]);
        Put<float>(r, 8, 0.0f);
        Put<float>(r, 0xC, c.sz[i]);
        Put<U>(r, 0x14, 0);
        Put<uint16_t>(r, 0x18, c.sang[i]);
    }
    k.slotVec[1] = c.m; k.slotVec[2] = c.m;
    k.slotVec[3] = Addr(k.slotRecs);
    k.cacheMap.assign(c.n + 2, 0xCACECAFEu);
    Put<U>(k.cache, 4, Addr(k.formation));
    std::memcpy(k.cache + 0x48, k.slotVec, sizeof(k.slotVec));
    Put<U>(k.cache, 0x68, Addr(k.cacheMap.data() + 1));
    for (U i = 0; i < c.n; ++i) Put<U>(k.men[i], 0x1F4, i);
}

// ---- normalised dump: object pointers become (region, offset) tags, everything else raw
struct Region { U base, size; U id; };
struct Dumper {
    std::vector<Region> regions;
    std::string firstTag;
    void Add(const void* p, U size, U id) { regions.push_back({Addr(p), size, id}); }
    uint64_t Norm(U w) const {
        for (const Region& r : regions) if (w >= r.base && w < r.base + r.size) return (1ull << 63) | ((uint64_t)r.id << 32) | (w - r.base);
        for (const Region& r : regions) if (w == r.base + r.size) return (1ull << 62) | ((uint64_t)r.id << 32) | (w - r.base);
        return w;
    }
};
struct DumpResult {
    std::vector<std::pair<std::string, uint64_t>> hashes;   // region label -> FNV-1a over the normalised 32-bit words
    std::vector<uint64_t> entries;                           // assignment entries, normalised words (man, slot, cost bits)
    uint64_t eax = 0;
    U listCap = 0, listCount = 0; bool listData = false;
    size_t liveAllocations = 0;
    std::vector<HeapEvent> heap;
    U ebx = 0, esi = 0, edi = 0, ebp = 0, espDelta = 0, csr = 0, cw = 0;
    bool faulted = false;
};
uint64_t HashWords(const Dumper& d, const uint8_t* p, U bytes) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (U i = 0; i + 4 <= bytes; i += 4) {
        const uint64_t w = d.Norm(Get<U>(p, i));
        h = (h ^ w) * 0x100000001B3ull;
        h = (h ^ (w >> 32)) * 0x100000001B3ull;
    }
    return h;
}
void MakeDumper(const Mock& k, Dumper& d) {
    for (U i = 0; i < k.men.size(); ++i) d.Add(k.men[i], 0x700, 1000 + i);
    d.Add(k.menArray, k.n * 4 + 4, 1); d.Add(k.formation, 0x2800, 2); d.Add(k.unit, 0x1000, 3); d.Add(k.side, 0x100, 4);
    d.Add(k.layout, 0x40, 5); d.Add(k.layoutVtbl, 0x100, 6); d.Add(k.slotRecs, (k.m ? k.m : 1) * 36, 7);
    d.Add(k.tickObj, 0x100, 8); d.Add(k.tickObj2, 0x100, 9); d.Add(k.slotVec, sizeof(k.slotVec), 10); d.Add(k.assignVec, sizeof(k.assignVec), 11);
    if (k.assignVec[3]) d.Add((void*)(uintptr_t)k.assignVec[3], std::max<U>(k.assignVec[1], k.assignVec[2]) * 12 + 4, 12);
    d.Add(k.cache, sizeof(k.cache), 13);
    d.Add(k.cacheMap.data(), static_cast<U>(k.cacheMap.size() * sizeof(U)), 14);
}
void Capture(const Mock& k, DumpResult& r) {
    Dumper d; MakeDumper(k, d);
    for (U i = 0; i < k.men.size(); ++i) r.hashes.push_back({"man" + std::to_string(i), HashWords(d, k.men[i], 0x700)});
    r.hashes.push_back({"menArray", HashWords(d, k.menArray, k.n * 4)});
    r.hashes.push_back({"formation", HashWords(d, k.formation, 0x2800)});
    r.hashes.push_back({"unit", HashWords(d, k.unit, 0x1000)});
    r.hashes.push_back({"side", HashWords(d, k.side, 0x100)});
    r.hashes.push_back({"layout", HashWords(d, k.layout, 0x40)});
    r.hashes.push_back({"layoutVtbl", HashWords(d, (uint8_t*)k.layoutVtbl, 0x100)});
    r.hashes.push_back({"slotRecs", HashWords(d, k.slotRecs, k.m * 36)});
    r.hashes.push_back({"tickObj", HashWords(d, k.tickObj, 0x100)});
    r.hashes.push_back({"tickObj2", HashWords(d, k.tickObj2, 0x100)});
    r.hashes.push_back({"slotVec", HashWords(d, (const uint8_t*)k.slotVec, sizeof(k.slotVec))});
    r.hashes.push_back({"assignVec", HashWords(d, (const uint8_t*)k.assignVec, sizeof(k.assignVec))});
    r.hashes.push_back({"cache", HashWords(d, k.cache, sizeof(k.cache))});
    r.hashes.push_back({"cacheMap", HashWords(d, reinterpret_cast<const uint8_t*>(k.cacheMap.data()), static_cast<U>(k.cacheMap.size() * sizeof(U)))});
    const U cnt = k.assignVec[2];
    const uint8_t* data = (const uint8_t*)(uintptr_t)k.assignVec[3];
    for (U i = 0; data && i < cnt; ++i) {
        r.entries.push_back(d.Norm(Get<U>(data, 12 * i)));
        r.entries.push_back(d.Norm(Get<U>(data, 12 * i + 4)));
        r.entries.push_back(Get<U>(data, 12 * i + 8));
    }
    const U* l = (const U*)(uintptr_t)NativeAddress(0x14A40A4);
    r.listCap = l[0]; r.listCount = l[1]; r.listData = l[2] != 0;
    r.heap = g_heapLog;
    r.liveAllocations = g_heapOrdinal.size();
}

// ---- call stub: callee-saved sentinels, four stack arguments, callee pops 16
U s_fn, s_F, s_a[4], s_eax, s_ebx, s_esi, s_edi, s_ebp, s_espBefore, s_espAfter;
U s_argCount = 4;
__declspec(naked) void ChainStub() {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov dword ptr [s_espBefore], esp
        mov ebx, 0x0BADB001
        mov esi, 0x0BADBEE5
        mov edi, 0x0BADD00D
        mov ebp, 0x0BADFACE
        cmp dword ptr [s_argCount], 0
        je arguments_done
        cmp dword ptr [s_argCount], 3
        je three_arguments
        push dword ptr [s_a + 12]
    three_arguments:
        push dword ptr [s_a + 8]
        push dword ptr [s_a + 4]
        push dword ptr [s_a]
    arguments_done:
        mov ecx, dword ptr [s_F]
        mov edx, 0x0DEDEDED
        call dword ptr [s_fn]
        mov dword ptr [s_eax], eax
        mov dword ptr [s_ebx], ebx
        mov dword ptr [s_esi], esi
        mov dword ptr [s_edi], edi
        mov dword ptr [s_ebp], ebp
        mov dword ptr [s_espAfter], esp
        mov esp, dword ptr [s_espBefore]
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret
    }
}
bool GuardedStub() {                    // no C++ objects here: __try needs a function without unwinding
    __try { ChainStub(); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// route 0: ordinary assignment; 1: complete cache writeback; 2: the cache assignment wrapper alone.
bool RunStub(U fn, Mock& k, const Case& c, DumpResult& r, U route = 0) {
    s_fn = fn; s_F = Addr(k.formation);
    s_a[0] = Addr(k.slotVec); s_a[1] = c.flagParam; s_a[2] = Addr(k.assignVec); s_a[3] = (U)c.layoutIndex;
    s_argCount = route == 1 ? 0 : route == 2 ? 3 : 4;
    if (route) { s_F = Addr(k.cache); s_a[0] = Addr(k.cache + 0x48); }
    const U csrBefore = _mm_getcsr() & ~0x3Fu, cwBefore = _control87(0, 0);
    const bool ok = GuardedStub();
    if (!ok) { r.faulted = true; return false; }
    r.ebx = s_ebx; r.esi = s_esi; r.edi = s_edi; r.ebp = s_ebp; r.espDelta = s_espBefore - s_espAfter;
    r.csr = (_mm_getcsr() & ~0x3Fu) ^ csrBefore; r.cw = _control87(0, 0) ^ cwBefore;   // net change of the control state (must be zero)
    Dumper d; MakeDumper(k, d);
    r.eax = d.Norm(s_eax);
    Capture(k, r);
    return true;
}
bool CallPre(void* formation, void* slotVec, void* scratch, U* v) {
    typedef U(__thiscall* PreFn)(void*, void*, void*);
    PreFn fn = (PreFn)(uintptr_t)NativeAddress(0x18F0200);
    __try { *v = fn(formation, slotVec, scratch); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool ProbePrestep(const Case& c, int* out) {       // original 0x18F0200 on its own fixture: thiscall(F; slotVec, scratch), returns the pre-step flag
    Mock k; Build(c, k);
    uint8_t scratch[0x80] = {};
    U v = 0;
    if (!CallPre(k.formation, k.slotVec, scratch, &v)) return false;
    *out = (int)(v & 0xFF);
    return true;
}

// ---- cases
void MakeSlots(Case& c, Rng& r, bool sameAngle, bool lattice) {
    c.m = c.n + (r.below(4) == 0 ? r.below(5) : 0);
    U files = 2 + r.below(40);
    float spacing = lattice ? 1.0f : 0.8f + 0.6f * r.unit();
    float ox = (r.unit() - 0.5f) * 300.0f, oz = (r.unit() - 0.5f) * 300.0f;
    uint16_t a0 = (uint16_t)r.next();
    for (U i = 0; i < c.m; ++i) {
        float fx = (float)(i % files) - 0.5f * (float)(files - 1);
        float fz = (float)(i / files);
        c.sx.push_back(ox + fx * spacing);
        c.sz.push_back(oz - fz * spacing);
        c.sang.push_back(sameAngle ? a0 : (uint16_t)(a0 + (r.below(25) == 0 ? 1 : 0)));
    }
}
Case MakeCase(Rng& r, U idx, U forcedN, int forcedFlag, int forcedLayout, int forcedMod) {
    Case c;
    c.n = forcedN ? forcedN : 2 + r.below(r.below(5) == 0 ? 320 : 90);
    bool lattice = r.below(3) == 0;
    for (U i = 0; i < c.n; ++i) {
        float gx = lattice ? (float)(r.below(40)) : r.unit() * 40.0f;
        float gz = lattice ? (float)(r.below(8)) : r.unit() * 12.0f;
        c.x.push_back(gx); c.z.push_back(gz);
        c.ang.push_back(r.below(3) == 0 ? (uint16_t)r.next() : (uint16_t)(idx * 977));
        c.cls.push_back(kNormal);
        c.skip.push_back(r.below(40) == 0);
        c.id.push_back(0);
    }
    U anchored = r.below(3) == 0 ? 0 : r.below(10);
    for (U a = 0; a < anchored && a < c.n; ++a) c.cls[r.below(c.n)] = kAnchored;
    U officers = r.below(5);
    for (U a = 0; a < officers; ++a) {
        U i = r.below(c.n);
        c.cls[i] = kOfficer;
        c.id[i] = 0x57460000u + (r.below(6) == 0 ? 3 + r.below(3) : r.below(3));
    }
    c.unitFlag = r.below(4) == 0;
    c.flagParam = (uint8_t)(r.below(8) == 0 ? 2 + r.below(3) : r.below(2));
    c.layoutIndex = r.below(5) == 0 ? (int32_t)r.below(c.n) : -1;
    c.modBreak = r.below(4) == 0 ? 1u + r.below(3) : 0u;
    if (forcedFlag >= 0) c.flagParam = (uint8_t)forcedFlag;
    if (forcedLayout != -2) c.layoutIndex = forcedLayout == -3 ? (int32_t)(c.n - 1) : forcedLayout;
    if (forcedMod >= 0) c.modBreak = (U)forcedMod;
    MakeSlots(c, r, r.below(8) != 0, lattice);
    c.label = "case#" + std::to_string(idx) + " n=" + std::to_string(c.n) + " flag=" + std::to_string(c.flagParam) + " idx=" +
              std::to_string(c.layoutIndex) + " mod=" + std::to_string(c.modBreak) + " unit=" + std::to_string(c.unitFlag);
    return c;
}

// Hand-built deterministic case (no RNG): n men on a line, m == n slots (the pre-step 0x18F0200 requires slot count == member count, a layout
// vtable [+0x24] == 0x18ED200, side [+0x1C] == 2, at least one officer 0x134841C with id k in {1,2}, and distinct left/right extreme slots).
struct Named { int pre, suppress, forward, direct; const char* why; };
Case HandCase(const char* name, std::vector<uint8_t> cls, uint8_t unitFlag, uint8_t flag, int32_t layoutIndex, U modBreak) {
    Case c;
    c.n = c.m = (U)cls.size();
    c.cls = cls;
    for (U i = 0; i < c.n; ++i) {
        c.x.push_back(1.5f * (float)i); c.z.push_back(0.25f * (float)i); c.ang.push_back((uint16_t)(1000 + 37 * i));
        c.skip.push_back(0); c.id.push_back(c.cls[i] == kOfficer ? 0x57460001u : 0u);   // officer id k = 1: the pre-step 0x18F0200 needs one with k in {1, 2}
        c.sx.push_back(1.5f * (float)(c.n - 1 - i)); c.sz.push_back(0.0f); c.sang.push_back(0);   // slots on one line perpendicular to the slot angle, first slot at one end
    }
    c.unitFlag = unitFlag; c.flagParam = flag; c.layoutIndex = layoutIndex; c.modBreak = modBreak;
    c.label = std::string("hand:") + name;
    return c;
}

// ---- comparison
std::string Diff(const DumpResult& a, const DumpResult& b) {
    char buf[256];
    if (a.hashes.size() != b.hashes.size()) return "region count differs";
    for (size_t i = 0; i < a.hashes.size(); ++i)
        if (a.hashes[i].second != b.hashes[i].second) return "object image differs: " + a.hashes[i].first;
    if (a.entries != b.entries) {
        size_t at = 0;
        while (at < a.entries.size() && at < b.entries.size() && a.entries[at] == b.entries[at]) ++at;
        std::snprintf(buf, sizeof buf, "assignment entries differ (native %zu words, chain %zu words, first diff word %zu)", a.entries.size(), b.entries.size(), at);
        return buf;
    }
    // EAX of the wrapper 0x18F0A00 is NOT compared: it is the leftover EAX of 0x5373F0's tail (stale heap-pointer bits of the solver's list
    // growth, different per heap state even native-vs-native) and 0x555CEB's continuation overwrites it first (`mov ebp,[esi+524]; ...
    // mov eax,[esi+520]`). Each kernel solve's own EAX is compared against native inside the shadow gate (mismatch_eax must stay 0).
    if (a.ebx != b.ebx || a.esi != b.esi || a.edi != b.edi || a.ebp != b.ebp) return "callee-saved register differs";
    if (a.ebx != 0x0BADB001 || a.esi != 0x0BADBEE5 || a.edi != 0x0BADD00D || a.ebp != 0x0BADFACE) return "native callee-saved sentinel not preserved";
    if (b.ebx != 0x0BADB001 || b.esi != 0x0BADBEE5 || b.edi != 0x0BADD00D || b.ebp != 0x0BADFACE) return "chain callee-saved sentinel not preserved";
    if (a.espDelta != 0 || b.espDelta != 0) return "ESP not balanced (callee pops 0x10)";
    if (a.csr || b.csr || a.cw || b.cw) return "MXCSR control or x87 control word changed";
    if (a.listCap != b.listCap || a.listCount != b.listCount || a.listData != b.listData) {
        std::snprintf(buf, sizeof buf, "global list native cap/count %u/%u data %d, chain %u/%u data %d", a.listCap, a.listCount, a.listData, b.listCap, b.listCount, b.listData);
        return buf;
    }
    if (a.liveAllocations != b.liveAllocations) return "native allocation lifetime differs";
    if (a.heap.size() != b.heap.size()) return "allocator call sequence length differs";
    for (size_t i = 0; i < a.heap.size(); ++i)
        if (a.heap[i].kind != b.heap[i].kind || a.heap[i].value != b.heap[i].value) {
            std::snprintf(buf, sizeof buf, "allocator call %zu differs (native %d/%u chain %d/%u)", i, a.heap[i].kind, a.heap[i].value, b.heap[i].kind, b.heap[i].value);
            return buf;
        }
    return "";
}

struct Stats { int cases = 0, runs = 0, failures = 0, suppressed = 0, forwarded = 0, kernel = 0, shadowCompares = 0, fallbacks = 0, flag0 = 0, flag1 = 0, direct = 0, skipped = 0; };

const char* ModeName(as::Mode m) { return m == as::ModeForward ? "forward" : m == as::ModeMemo ? "memo" : "shadow"; }

struct NativeRun { DumpResult r; int pre = -1; bool preOk = true; U sup = 0, fwd = 0, solverEntries = 0; };   // sup/fwd: exits of the ORIGINAL trampoline 0x18F0D00 observed in the native twin

bool CheckCounters(const Case& c, as::Mode mode, const NativeRun& nat, const U* w, std::string& why, Stats& st, bool cache = false) {
    char buf[320];
    const U seen = w[as::SolvesSeen], flag1 = w[as::SolvesFlag1], flag0 = w[as::Flag0Native], sup = w[as::ShimSuppressed], fwd = w[as::ShimForwarded];
    const U direct = w[as::Direct18F12AA];
    st.suppressed += sup; st.forwarded += fwd; st.kernel += w[as::SolvedKernel]; st.shadowCompares += w[as::ShadowCompares];
    st.flag0 += flag0; st.flag1 += flag1; st.direct += direct;
    const U fb = w[as::FbTooLarge] + w[as::FbRange] + w[as::FbListState] + w[as::FbGuard] + w[as::FbEnv] + w[as::FbFpEnv] + w[as::FbCtx];
    st.fallbacks += fb;
    if (w[as::AssignCalls] != 1) { why = "assign_calls != 1"; return false; }
    if (w[as::CacheAssignCalls] != (cache ? 1u : 0u) ||
        w[as::CacheSolvedKernel] != (cache ? w[as::SolvedKernel] : 0u)) { why = "cache-origin counters disagree with assignment/solve scope"; return false; }
    if (w[as::ForeignNative] != 0) { why = "foreign_native != 0 inside the occurrence"; return false; }
    if (seen != flag0 + flag1 || seen != direct + fwd) {
        std::snprintf(buf, sizeof buf, "gate entry accounting: seen %u flag0 %u flag1 %u direct %u forwarded %u", seen, flag0, flag1, direct, fwd);
        why = buf; return false;
    }
    if (sup + fwd > 1) { why = "shim saw the trampoline call more than once"; return false; }
    // Exact expectation: the shim must take the same exit as the original trampoline in the native twin (observation hooks on 0x18F0D00).
    if (sup != nat.sup || fwd != nat.fwd) {
        std::snprintf(buf, sizeof buf, "shim exits (suppressed %u, forwarded %u) != original trampoline exits (suppressed %u, forwarded %u); pre-step %d, n=%u unit=%u", sup, fwd, nat.sup, nat.fwd, nat.pre, c.n, c.unitFlag);
        why = buf; return false;
    }
    if (nat.sup && nat.pre != 1) { why = "native suppressed although the pre-step did not return 1 (oracle fixture bug)"; return false; }
    // Every native entry of 0x502770 is either the trampoline's forward exit or the direct 18F12AA call, and the gate sees exactly those.
    if (seen != nat.solverEntries || direct != nat.solverEntries - nat.fwd) {
        std::snprintf(buf, sizeof buf, "gate entries (seen %u, direct %u) != native 0x502770 entries %u (of which %u via the trampoline)", seen, direct, nat.solverEntries, nat.fwd);
        why = buf; return false;
    }
    if (direct && nat.pre != 1) { why = "post-step 18F1200 solved without a pre-step result of 1"; return false; }
    const U empty = w[as::EmptyNative];
    if (mode == as::ModeForward) {
        if (w[as::SolvedKernel] != 0 || w[as::ShadowCompares] != 0 || fb != 0) { why = "forward mode used the kernel"; return false; }
    } else {
        // every flag=1 solve is exactly one of: solved by the kernel (shadow: compared), kernel fallback, or empty range (native)
        const U solved = mode == as::ModeMemo ? w[as::SolvedKernel] : w[as::ShadowCompares];
        if (solved + fb + empty != flag1) {
            std::snprintf(buf, sizeof buf, "flag=1 accounting: kernel/compared %u + fallbacks %u + empty %u != %u", solved, fb, empty, flag1);
            why = buf; return false;
        }
        // m = the entry rows of a solve (men without a row, e.g. anchored ones, make m < n): max_m decides whether a too_large fallback is due
        if (w[as::MaxM] > ntw_solver::kMaxM) {
            if (w[as::FbTooLarge] == 0 || w[as::FbTooLarge] != fb) { why = "max_m > kMaxM must fall back (too_large) and only that"; return false; }
        } else if (fb != 0) {
            std::snprintf(buf, sizeof buf, "unexpected kernel fallback (tl %u range %u list %u guard %u env %u fpenv %u ctx %u)", w[as::FbTooLarge], w[as::FbRange], w[as::FbListState], w[as::FbGuard], w[as::FbEnv], w[as::FbFpEnv], w[as::FbCtx]);
            why = buf; return false;
        }
        if (mode == as::ModeShadow && (w[as::ShadowMismatchSolves] != 0 || w[as::MismatchEntries] != 0 || w[as::MismatchEax] != 0)) { why = "shadow: kernel disagrees with native"; return false; }
    }
    return true;
}

bool RefuseUnknownCacheWrapper() {
    // Both accepted forms are tested by the two ctest invocations. Every byte of the 29-byte wrapper is
    // admission-critical, not only the call displacement. No fixture or native allocation is allowed here.
    auto* wrapper = (uint8_t*)(uintptr_t)NativeAddress(0x539C90);
    const as::Binding b = {static_cast<U>(g_delta), as::ModeMemo,
                          g_clones.entries[KNTWR_CLONE_SOLVER_18F0A00], g_clones.entries[KNTWR_CLONE_SOLVER_5373F0]};
    for (U i = 0; i < 0x1D; ++i) {
        const uint8_t saved = wrapper[i];
        wrapper[i] ^= 0x80;
        const bool admitted = as::Start(b);
        wrapper[i] = saved;
        if (admitted || as::Started() || as::StorageBytes() != 0) {
            as::Stop();
            std::fprintf(stderr, "FAIL unknown cache wrapper byte +%#x was admitted or retained workspace\n", i);
            return false;
        }
    }
    return FlushInstructionCache(GetCurrentProcess(), wrapper, 0x1D) != 0;
}
// Complete native cache consumer: stack-local assignment vector, indexed writeback and final free.
// Wrapper-only cases exercise finite flags that 57AC10 (always flag 1) cannot supply.
int RunCacheCases() {
    struct Scenario { Case c; U route; bool duplicateIndex; };
    std::vector<Scenario> scenarios;
    scenarios.push_back({HandCase("cache-normal", {kNormal, kNormal, kNormal}, 0, 1, -1, 0), 1, false});
    scenarios.push_back({HandCase("cache-overlay-prestep", {kOfficer, kNormal, kNormal}, 0, 1, -1, 0), 1, false});
    scenarios.push_back({HandCase("cache-duplicate-index", {kNormal, kNormal, kNormal}, 0, 1, -1, 0), 1, true});
    scenarios.push_back({HandCase("cache-all-anchored", {kOfficer, kAnchored}, 0, 1, -1, 0), 1, false});
    scenarios.push_back({HandCase("cache-empty", {}, 0, 1, -1, 1), 1, false});
    scenarios.push_back({HandCase("cache-wrapper-finite", {kNormal, kNormal, kNormal}, 0, 0, -1, 0), 2, false});
    scenarios.push_back({HandCase("cache-wrapper-nonboolean-finite", {kNormal, kNormal, kNormal}, 0, 2, -1, 0), 2, false});
    // No officers or anchored rows: all kMaxM+1 entries reach the native unlimited solver.
    // Broken pre-step eligibility keeps the overlay and SKIP{15} cases on the same full-size solve.
    scenarios.push_back({HandCase("cache-overbound-native", std::vector<uint8_t>(ntw_solver::kMaxM + 1, kNormal),
                                  0, 1, -1, 1), 1, false});
    auto build = [](const Scenario& s, Mock& k) {
        Build(s.c, k);
        if (s.duplicateIndex) for (auto* man : k.men) Put<U>(man, 0x1F4, 0);
        SetUnitPredicate(s.c.unitFlag);
        ResetList();
    };
    std::vector<NativeRun> native(scenarios.size());
    int failures = 0;
    if (!InstallHooks(true)) return 1;
    for (size_t i = 0; i < scenarios.size(); ++i) {
        const Scenario& s = scenarios[i];
        NativeRun& n = native[i];
        if (!g_skipCacheOverlay && !ProbePrestep(s.c, &n.pre)) {
            n.r.faulted = true; ++failures; continue;
        }
        Mock k; build(s, k);
        g_nativeSuppress = g_nativeForward = g_nativeSolverEntries = 0;
        if (!RunStub(NativeAddress(s.route == 1 ? 0x57AC10 : 0x539C90), k, s.c, n.r, s.route)) {
            ++failures; std::fprintf(stderr, "FAIL native %s faulted\n", s.c.label.c_str()); continue;
        }
        n.sup = g_nativeSuppress; n.fwd = g_nativeForward; n.solverEntries = g_nativeSolverEntries;
        if (s.route == 1) {
            const bool guards = k.cacheMap.front() == 0xCACECAFEu && k.cacheMap.back() == 0xCACECAFEu;
            U writes = 0;
            for (U j = 1; j <= k.n; ++j) writes += k.cacheMap[j] != 0xCACECAFEu;
            const bool freed = n.r.liveAllocations == (n.r.listData ? 1u : 0u);
            if (!guards || !freed || (k.n && !writes) || (s.duplicateIndex && writes != 1)) {
                ++failures;
                std::fprintf(stderr, "FAIL native %s: cache guards=%d writes=%u assignment freed=%d\n", s.c.label.c_str(), guards, writes, freed);
            }
        }
    }
    if (!InstallHooks(false)) return failures + 1;
    for (as::Mode mode : {as::ModeOff, as::ModeForward, as::ModeMemo, as::ModeShadow}) {
        if (mode != as::ModeOff) {
            const as::Binding binding{static_cast<U>(g_delta), mode, g_clones.entries[KNTWR_CLONE_SOLVER_18F0A00],
                                      g_clones.entries[KNTWR_CLONE_SOLVER_5373F0]};
            if (!as::Start(binding)) return failures + 1;
        }
        Stats st;
        U finite = 0;
        for (size_t i = 0; i < scenarios.size(); ++i) {
            if (native[i].r.faulted) continue;
            const Scenario& s = scenarios[i];
            Mock k; build(s, k);
            as::Reset();
            DumpResult result;
            const U fn = s.route == 1 ? g_clones.entries[KNTWR_CLONE_SOLVER_57AC10] : g_bindings[KNTWR_BIND_SOLVER_CACHE_ASSIGN];
            if (!RunStub(fn, k, s.c, result, s.route)) {
                ++failures; std::fprintf(stderr, "FAIL cache mode %u %s faulted\n", static_cast<U>(mode), s.c.label.c_str()); continue;
            }
            std::string why = Diff(native[i].r, result);
            as::TickEnd(777); // publish top-solve rows before checking their cache-origin flags
            U w[as::kWords]; as::Snapshot(w);
            if (mode == as::ModeOff) {
                if (w[as::AssignCalls] || w[as::CacheAssignCalls] || w[as::SolvesSeen] || w[as::CacheSolvedKernel] || as::StorageBytes())
                    why = "off-state cache passthrough acquired counters or workspace";
            } else if (why.empty()) {
                if (!CheckCounters(s.c, mode, native[i], w, why, st, true)) why = "counters: " + why;
                if (s.route == 2) {
                    finite += w[as::Flag0Native];
                    if (!w[as::Flag0Native] || w[as::SolvesFlag1] || w[as::SolvedKernel] || w[as::ShadowCompares])
                        why = "finite-limit cache wrapper did not stay entirely native";
                }
                if (s.route == 1 && s.c.n > ntw_solver::kMaxM) {
                    const U expectedFallback = mode == as::ModeForward ? 0u : 1u;
                    if (w[as::CacheAssignCalls] != 1 || w[as::CacheSolvedKernel] != 0 ||
                        w[as::SolvedKernel] != 0 || w[as::ShadowCompares] != 0 ||
                        w[as::SolvesFlag1] != 1 || w[as::FbTooLarge] != expectedFallback ||
                        (mode != as::ModeForward && w[as::MaxM] != s.c.n))
                        why = "overbound cache assignment did not preserve native-only solve/fallback accounting";
                }
                if ((w[as::SolvedKernel] || w[as::ShadowCompares] || w[as::FbTooLarge]) && !(w + as::SolveTable)[as::SFlags])
                    why = "cache solve missing from published receipt";
                for (U row = 0; row < as::kTop; ++row) {
                    const U* e = w + as::SolveTable + row * as::kSolveWords;
                    if (e[as::SFlags] && !(e[as::SFlags] & (1u << 9))) why = "cache solve lacks origin bit 9";
                }
            }
            if (!why.empty()) {
                ++failures; std::fprintf(stderr, "FAIL cache mode %u %s: %s\n", static_cast<U>(mode), s.c.label.c_str(), why.c_str());
            }
        }
        if (mode != as::ModeOff && finite != 2) { ++failures; std::fprintf(stderr, "FAIL cache finite-limit cases were not exercised\n"); }
        if ((mode == as::ModeMemo && !st.kernel) || (mode == as::ModeShadow && !st.shadowCompares)) {
            ++failures; std::fprintf(stderr, "FAIL cache kernel coverage is vacuous in mode %u\n", static_cast<U>(mode));
        }
        std::printf("cache mode %u: kernel=%d shadow_compares=%d fallbacks=%d finite_native=%u\n",
                    static_cast<U>(mode), st.kernel, st.shadowCompares, st.fallbacks, finite);
        as::Stop();
    }
    std::printf("cache chain: %zu scenarios x off/forward/memo/shadow, overlay=%s, failures=%d\n",
                scenarios.size(), g_skipCacheOverlay ? "SKIP{15}" : "ALL", failures);
    return failures;
}

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::string image, tablePath;
    int cases = 300;
    U seed = 1;
    U overbound = 0;                       // 0: kMaxM + 100; a value reproduces an older case list (the size of the two 'm > kMaxM' cases)
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i];
        if (a == "--image") image = argv[i + 1];
        else if (a == "--table") tablePath = argv[i + 1];
        else if (a == "--cases") cases = std::atoi(argv[i + 1]);
        else if (a == "--seed") seed = (U)std::strtoul(argv[i + 1], nullptr, 10);
        else if (a == "--skip-cache-overlay") g_skipCacheOverlay = std::atoi(argv[i + 1]) != 0;
        else if (a == "--overbound") overbound = (U)std::strtoul(argv[i + 1], nullptr, 10);
    }
    std::vector<uint8_t> file, table;
    if (image.empty() || tablePath.empty() || !ReadAll(image, file) || !ReadAll(tablePath, table)) {
        std::fprintf(stderr, "usage: --image <stock Napoleon.exe> --table angle-table.bin [--cases N] [--seed S] [--overbound N] [--skip-cache-overlay 1]\n");
        return 2;
    }
    if (Sha256(file.data(), file.size()) != kImageSha) { std::fprintf(stderr, "image SHA-256 mismatch\n"); return 2; }
    if (table.size() != 65536 * 8 || Sha256(table.data(), table.size()) != kTableSha) { std::fprintf(stderr, "angle table mismatch\n"); return 2; }
    if (!MapImage(file, table)) return 2;
    if (!RefuseUnknownCacheWrapper()) return 2;

    // case list: a size/flag/layout/mod matrix (including m > kMaxM) plus random cases
    Rng rng{seed ? seed : 1};
    std::vector<Case> all;
    U idx = 0;
    static const U sizes[] = {2, 3, 4, 5, 8, 17, 33, 64, 129, 257, 404, ntw_solver::kMaxM, ntw_solver::kMaxM + 1};
    for (U n : sizes)
        for (int flag = 0; flag <= 1; ++flag)
            for (int layout : {-1, 0, -3})
                for (int mod : {0, 1}) all.push_back(MakeCase(rng, idx++, n, flag, layout, mod));
    for (int flag = 0; flag <= 1; ++flag) all.push_back(MakeCase(rng, idx++, overbound ? overbound : ntw_solver::kMaxM + 100, flag, -1, 0));    // m > kMaxM: kernel fallback
    for (int i = 0; i < cases; ++i) all.push_back(MakeCase(rng, idx++, 0, -1, -2, -1));
    // Hand-built permanent cases (appended after the random ones, so the seeded stream above is unchanged). The expectation is the behaviour of the
    // ORIGINAL code, pinned from disassembly: 0x5373F0 calls the trampoline at 0x53765A only when men remain unpushed after its first pass
    // (0x537613), the trampoline suppresses iff the call came from 0x18F0A00's return address AND the pre-step flag [ebp-8] == 1, and the post-step
    // 0x18F1200 runs iff the pre-step returned 1 and makes its direct 0x18F12AA solver call only when unpushed rows remain.
    std::vector<Named> named(all.size(), Named{-9, 0, 0, 0, nullptr});
    auto addHand = [&](Case c, Named e) { all.push_back(std::move(c)); named.push_back(e); };
    const uint8_t A = kAnchored, N = kNormal, O = kOfficer;
    addHand(HandCase("n2-all-anchored-pre1-no-trampoline", {O, A}, 0, 1, -1, 0), {1, 0, 0, 0, "every man pushed by the first pass: 0x5373F0 never calls the trampoline (0x537613) and the post-step 0x18F1200 finds no unpushed rows (`cmp edi, [ebp-1C]; jae 0x18F12AF`), so 0x502770 is never entered although the pre-step returned 1 (the case that broke the pre-step-based expectation)"});
    addHand(HandCase("n3-one-anchored-pre1-suppressed", {O, N, N}, 0, 1, -1, 0), {1, 1, 0, 1, "men left unpushed: trampoline entered, suppressed by the pre-step flag, post-step solves"});
    addHand(HandCase("n4-unit-predicate-pre1-suppressed", {O, N, N, N}, 1, 1, -1, 0), {1, 1, 0, 1, "unit predicate set: first pass skipped, trampoline entered and suppressed"});
    addHand(HandCase("n3-layout-vtable-broken-pre0-forwarded", {O, N, N}, 0, 1, -1, 1), {0, 0, 1, 0, "pre-step returns 0: trampoline forwards to 0x502770, no post-step"});
    addHand(HandCase("n3-layout-index-forwarded", {O, N, N}, 0, 1, 1, 0), {-1, 0, 1, 0, "layout index >= 0: pre-step not run, flag byte 0: forwarded"});

    // twin A: the ORIGINAL 0x18F0A00 once per case, plus the native pre-step probe
    std::vector<NativeRun> nat(all.size());
    int failures = 0;
    if (!InstallHooks(true)) { std::fprintf(stderr, "original trampoline 0x18F0D00 / solver 0x502770 do not have the pinned bytes\n"); return 2; }
    for (size_t i = 0; i < all.size(); ++i) {
        const Case& c = all[i];
        NativeRun& n = nat[i];
        if (c.layoutIndex == -1) {
            int pre = 0; n.preOk = ProbePrestep(c, &pre); n.pre = n.preOk ? pre : -1;
            if (!n.preOk) { ++failures; std::fprintf(stderr, "FAIL pre-step probe faulted: %s\n", c.label.c_str()); n.r.faulted = true; continue; }
        }
        Mock k; Build(c, k);
        SetUnitPredicate(c.unitFlag);
        ResetList();
        g_nativeSuppress = 0; g_nativeForward = 0; g_nativeSolverEntries = 0;
        const bool ranNative = RunStub(NativeAddress(0x18F0A00), k, c, n.r);
        n.sup = g_nativeSuppress; n.fwd = g_nativeForward; n.solverEntries = g_nativeSolverEntries;
        if (!ranNative) { ++failures; std::fprintf(stderr, "FAIL native twin faulted: %s\n", c.label.c_str()); }
    }
    if (!InstallHooks(false)) return 2;
    for (size_t i = 0; i < all.size(); ++i) {
        if (!named[i].why) continue;
        const NativeRun& n = nat[i];
        const U direct = n.solverEntries - n.fwd;
        if (n.r.faulted || n.pre != named[i].pre || (int)n.sup != named[i].suppress || (int)n.fwd != named[i].forward || (int)direct != named[i].direct) {
            ++failures;
            std::fprintf(stderr, "FAIL %s: native twin pre %d suppress %u forward %u direct %u, expected pre %d suppress %d forward %d direct %d (%s)\n", all[i].label.c_str(), n.pre, n.sup, n.fwd, direct,
                         named[i].pre, named[i].suppress, named[i].forward, named[i].direct, named[i].why);
        }
    }
    int expectedSuppress = 0, expectedForward = 0, pre1NoTrampoline = 0, pre1 = 0;
    for (size_t i = 0; i < nat.size(); ++i) {
        const NativeRun& n = nat[i];
        expectedSuppress += n.sup; expectedForward += n.fwd;
        if (n.pre == 1) {
            ++pre1;
            if (!n.sup && !n.fwd) {
                ++pre1NoTrampoline;
                U anchored = 0;
                for (uint8_t cl : all[i].cls) anchored += cl != kNormal;
                std::printf("  pre-step 1 without a trampoline entry: %s (men %u, anchored/officer %u): every man was pushed by 0x5373F0's first pass, so 0x537613 (`cmp eax, edx; jbe 0x537779`) skips the call at 0x53765A\n", all[i].label.c_str(), all[i].n, anchored);
            }
        }
    }

    for (as::Mode mode : {as::ModeForward, as::ModeMemo, as::ModeShadow}) {
        as::Binding b = {static_cast<U>(g_delta), mode, g_clones.entries[KNTWR_CLONE_SOLVER_18F0A00],
                         g_clones.entries[KNTWR_CLONE_SOLVER_5373F0]};
        if (!as::Start(b)) { std::fprintf(stderr, "kntwr_army_solver::Start refused (%s)\n", ModeName(mode)); return 2; }
        Stats st;
        for (size_t i = 0; i < all.size(); ++i) {
            const Case& c = all[i];
            if (nat[i].r.faulted) continue;
            ++st.cases;
            Mock k; Build(c, k);
            SetUnitPredicate(c.unitFlag);
            ResetList();
            as::Reset();
            DumpResult r;
            ++st.runs;
            if (!RunStub(g_bindings[KNTWR_BIND_SOLVER_ASSIGN], k, c, r)) { ++st.failures; std::fprintf(stderr, "FAIL [%s] chain faulted: %s\n", ModeName(mode), c.label.c_str()); continue; }
            std::string why = Diff(nat[i].r, r);
            U w[as::kWords];
            as::Snapshot(w);
            if (why.empty()) { std::string cw; if (!CheckCounters(c, mode, nat[i], w, cw, st)) why = "counters: " + cw; }
            if (!why.empty()) { ++st.failures; std::fprintf(stderr, "FAIL [%s] %s: %s\n", ModeName(mode), c.label.c_str(), why.c_str()); }
        }
        as::Stop();
        std::printf("%-7s: cases=%d failures=%d suppressed=%d forwarded=%d direct_18f12aa=%d solves flag1=%d flag0=%d kernel=%d shadow_compares=%d fallbacks=%d\n",
                    ModeName(mode), st.cases, st.failures, st.suppressed, st.forwarded, st.direct, st.flag1, st.flag0, st.kernel, st.shadowCompares, st.fallbacks);
        failures += st.failures;
        if (st.suppressed != expectedSuppress || st.forwarded != expectedForward) {
            ++failures;
            std::fprintf(stderr, "FAIL [%s] total shim exits (suppressed %d, forwarded %d) != original trampoline exits (suppressed %d, forwarded %d)\n", ModeName(mode), st.suppressed, st.forwarded, expectedSuppress, expectedForward);
        }
        if (mode != as::ModeForward && st.fallbacks == 0 && (!overbound || overbound > ntw_solver::kMaxM)) { ++failures; std::fprintf(stderr, "FAIL [%s] no too_large fallback was exercised (n=kMaxM+100 case)\n", ModeName(mode)); }
        if (mode == as::ModeMemo && st.kernel == 0) { ++failures; std::fprintf(stderr, "FAIL memo never reached the kernel (oracle would be vacuous)\n"); }
        if (mode == as::ModeShadow && st.shadowCompares == 0) { ++failures; std::fprintf(stderr, "FAIL shadow never compared a solve\n"); }
        if (st.suppressed == 0 || st.forwarded == 0 || st.direct == 0) { ++failures; std::fprintf(stderr, "FAIL [%s] suppression/forward/direct paths not all exercised\n", ModeName(mode)); }
    }
    std::printf("original trampoline 0x18F0D00 in the native twin: %d suppress exits, %d forward exits over %zu cases; pre-step returned 1 in %d cases, %d of them never entered the trampoline; image delta %#llx\n",
                expectedSuppress, expectedForward, all.size(), pre1, pre1NoTrampoline, (unsigned long long)g_delta);
    failures += RunCacheCases();
    std::printf("army solver chain oracle: failures=%d\n", failures);
    return failures ? 1 : 0;
}
