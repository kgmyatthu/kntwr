// Owned-process differential harness: ORIGINAL full ballistic grid query 0x6392C0 of the approved Napoleon.exe versus the HOOKED
// private query clone (native_ballistics_query_cache.dll + native_ballistics_query_clones.py clones).
//
// WHAT RUNS (everything native, nothing emulated)
//   * the approved image (SHA-256 13fcab62...cbad4) is mapped privately in THIS process (VirtualAlloc + loader relocations,
//     native_image_relocation.h).  Glue exists only in that private copy: game heap allocate/free -> host thunks, the TLS index,
//     the IAT slot of GetCurrentThreadId, and the function-local statics of 0x6392C0 (and of the wrapper path) are built with the
//     image's OWN constructors 0x61A760 / 0x4549F0 and their thread-safe-static guards are published as "initialized".
//   * ORIGINAL 0x6392C0 (cell gather 0x10EED80/0x10D5610, predicate 0x6DC9A0, visited writes 0x56EE80, unit hit 0x809620,
//     appends 0x5EF540, clears 0x542AA0, ...) runs on fixtures laid out at the native offsets: grid (+0 heads +8 shift +0xC dim
//     +0x10 origin +0x14 limit +0x20/+0x24 cell scale +0x28 box +0x38 thread object), kind-8 entries (kind +0, id +4, object +0xC,
//     next +0x14), unit objects (vtable +0, predicate byte +0x30, flags +0x34, capsule floats +0x48..+0x58) with REAL machine-code
//     getters (pure leaves written as bytes, real image leaves 0x461180 / 0x4470B0, byte-only / load-then-write / C++ callbacks).
//   * the hooked run goes through nqc_query_hook -> PRIVATE clone of 0x6392C0 (call 0x639581 -> nqc_gather_hook, call 0x639699 ->
//     nqc_unit_hook, jump table private) -> persistent worker team of the existing dispatcher.
//   Other entry kinds (planes 0x40, boxes 0x400, walls 0x800) need scene fixtures that are not available here: they are only
//   present as entries the ORIGINAL code rejects by the type mask / by the default predicate / the kind chain (kind 0x1000).  No
//   composed or mocked result replaces any original branch.  Wrapper 0x53C060 is exercised with mask 8 (see --wrapper).
//
// WHAT IS ASSERTED, per query (original run A vs hooked run B on the very same restored fixture memory)
//   return byte, every appended result record (entry, x, y, z, t), the whole fixture arena (units' getter side effects, segments),
//   the unit-getter call sequence with, at every getter call, the hash of the unit visited bitset + dirty list + gathered cell vector
//   and the output count (visited bits / cell vector must evolve exactly as native), cleanup of all static visited bitsets and
//   cell vectors, x87 control word / MXCSR control bits / x87 stack depth after the call, SEH propagation of an original fault with
//   scope release, and the module counters (cache hits only when expected, fallback / changed / unsupported / capacity, actual
//   persistent worker chunks from the pool slots).
// Scenarios: hit / miss, repeated entries and cells, visited ids (also caller-owned visited), stop-first-cell / non-stop,
//   extra, mode, alt segment types 1/2/3/4 and alt == NULL, long lists, capacity bounds, x87 + MXCSR matrices, mutations of unit
//   floats / radius / ray / vtable / leaf bytes / selector / x87 CW / MXCSR between preparation and the original call, side-effect
//   getters reached ONLY by the original caller, getter fault, module stop during a scope, foreign thread + reentrant queries and
//   unit hooks, wrong model / grid identity, disabled module, the clone called without scope, unit hooks outside any scope.
//
//   build (parent):  cl /nologo /std:c++20 /EHsc /O2 /MT /arch:SSE2 /fp:strict /W4 native_ballistics_query_cache_harness.cpp
//                       /Fenative_ballistics_query_cache_harness.exe /link bcrypt.lib
//   run   (parent):  python native_ballistics_collision_kit.py ; python native_ballistics_query_clones.py   (once)
//        native_ballistics_query_cache_harness.exe --image "E:\steam\steamapps\common\Napoleon Total War\Napoleon.exe"
//          --cache-dll native_ballistics_query_cache.dll --clones native-ballistics-query-clones.bin
//          --worker-kit native-ballistics-collision-worker-kit.bin --pool-dll native_worker_dispatch.dll
//          [--worlds 240] [--seed 6392] [--workers 3] [--wrapper 1] [--strict-wrapper 0]
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <emmintrin.h>
#include <malloc.h>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "native_ballistics_query_cache.h"
#include "native_image_relocation.h"
#include "native_worker_dispatch.h"

#pragma comment(lib, "bcrypt.lib")
#pragma fenv_access(on)
static_assert(sizeof(void*) == 4, "x86 build required: the native code is 32-bit");

extern "C" unsigned long _tls_index;
__declspec(thread) static volatile int g_tlsPad[32];   // the image's TLS reads (+8) must hit committed thread-local storage

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ------------------------------------------------------------------------------------------------ small utilities
static std::string F(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return buf;
}
[[noreturn]] static void fail(const std::string& m) {
    std::printf("FAIL: %s\n", m.c_str());
    std::fflush(stdout);
    std::exit(1);
}
#define REQ(cond, ...) \
    do { if (!(cond)) fail(std::string("line ") + std::to_string(__LINE__) + ": (" #cond ") " + F(__VA_ARGS__)); } while (0)

template <class T> static T rd(const u8* b, u32 off) { T v; std::memcpy(&v, b + off, sizeof v); return v; }
template <class T> static void wr(u8* b, u32 off, T v) { std::memcpy(b + off, &v, sizeof v); }
static u32 PtrU(const void* p) { return static_cast<u32>(reinterpret_cast<uintptr_t>(p)); }
static u32 FBits(float f) { u32 b; std::memcpy(&b, &f, 4); return b; }
static float BitsF(u32 b) { float f; std::memcpy(&f, &b, 4); return f; }
static u64 Fnv(const void* p, size_t n, u64 h = 1469598103934665603ull) {
    const u8* b = static_cast<const u8*>(p);
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

static std::string Sha256(const void* data, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    u8 out[32] = {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCryptHash(alg, nullptr, 0, static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), out, 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (int i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", out[i]);
    return hex;
}
static bool ReadAll(const std::string& path, std::vector<u8>& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize(static_cast<size_t>(n));
    const bool ok = n == 0 || std::fread(out.data(), 1, out.size(), f) == out.size();
    std::fclose(f);
    return ok;
}

// ---- FP control state ------------------------------------------------------------------------------------------------
static u16 get_cw() { u16 w = 0; __asm { fnstcw w } return w; }
static void set_cw(u16 w) { __asm { fldcw w } }
static u16 get_sw() { u16 w = 0; __asm { fnstsw w } return w; }
struct Fp { u16 cw; u32 csr; };
static Fp fp_get() { return Fp{get_cw(), _mm_getcsr()}; }
static void fp_set(const Fp& f) { set_cw(f.cw); _mm_setcsr(f.csr); }
static const Fp kFpDefault = {0x27F, 0x1F80};

// ------------------------------------------------------------------------------------------------ private image
static const u32 kImageBase = 0x400000;
static const char* const kImageSha = "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4";
static u32 g_delta;
static u8* g_imageBase;
static u32 NA(u32 va) { return va + g_delta; }
static u8* NP(u32 va) { return reinterpret_cast<u8*>(static_cast<uintptr_t>(va + g_delta)); }

extern "C" void* __cdecl HostAlloc(size_t size, void*) { return _aligned_malloc(size ? size : 1, 16); }
extern "C" void __cdecl HostFree(void* p) { _aligned_free(p); }
static void PatchJump(u32 va, const void* target) {   // private copy only: mov eax, imm32 ; jmp eax
    u8* p = NP(va);
    p[0] = 0xB8;
    const u32 t = PtrU(target);
    std::memcpy(p + 1, &t, 4);
    p[5] = 0xFF;
    p[6] = 0xE0;
}

static bool MapImage(const std::vector<u8>& file) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(file.data() + dos->e_lfanew);
    if (nt->OptionalHeader.ImageBase != kImageBase) return false;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto* base = static_cast<u8*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!base) return false;
    g_imageBase = base;
    g_delta = static_cast<u32>(reinterpret_cast<uintptr_t>(base) - kImageBase);
    std::memcpy(base, file.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const u32 n = std::min<u32>(sec[i].SizeOfRawData, sec[i].Misc.VirtualSize);
        std::memcpy(base + sec[i].VirtualAddress, file.data() + sec[i].PointerToRawData, n);
    }
    auto* loadedNt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (!RelocateNativeImage(base, size, loadedNt, g_delta)) return false;
    PatchJump(0x00FF7F20, reinterpret_cast<const void*>(&HostAlloc));       // game heap allocate
    PatchJump(0x00FF7EF0, reinterpret_cast<const void*>(&HostFree));        // game heap free
    wr<u32>(NP(0x1841BB8), 0, _tls_index);                                  // image TLS index word -> this process' index
    wr<u32>(NP(0x1307178), 0, PtrU(reinterpret_cast<const void*>(&GetCurrentThreadId)));   // IAT: kernel32!GetCurrentThreadId (0x5F3550)
    g_tlsPad[0] = 0;
    return FlushInstructionCache(GetCurrentProcess(), nullptr, 0) != 0;
}

// Static (function-local) objects of 0x6392C0 / the wrapper path: built by the image's own constructors, guards published.
typedef void*(__thiscall* CtorFn)(void*);
static const u32 kBitsetBase[3] = {0x14D0A80, 0x14D4AB0, 0x14D8AE0};     // unit / plane+ring / box visited bitsets, [2] x 0x2014
static const u32 kCellVec = 0x14DCB0C;                                     // [2] x 16: gathered cell vector
static const u32 kWrapBitsetBase[3] = {0x15AFEC0, 0x15B3EF0, 0x15B7F20};
static const u32 kWrapVec = 0x15AFE98;
static const u32 kInitGuards[] = {0x14D4AA8, 0x14D8AD8, 0x14DCB08, 0x14DCB2C, 0x15AFEB8, 0x15B3EE8, 0x15B7F18, 0x15BBF48, 0x15AFE94};
static void InitStatics() {
    const CtorFn bitsetCtor = reinterpret_cast<CtorFn>(NP(0x61A760)), vecCtor = reinterpret_cast<CtorFn>(NP(0x4549F0));
    for (int b = 0; b < 2; ++b) {
        for (u32 base : kBitsetBase) bitsetCtor(NP(base) + b * 0x2014);
        vecCtor(NP(kCellVec) + b * 16);
        for (u32 base : kWrapBitsetBase) bitsetCtor(NP(base) + b * 0x2014);
        vecCtor(NP(kWrapVec) + b * 16);
    }
    for (u32 g : kInitGuards) wr<u32>(NP(g), 0, 0x80000000u);   // "initialized": jg (guard > tls epoch) is never taken
}

static bool StaticsClean(std::string& why) {
    for (int b = 0; b < 2; ++b) {
        for (int s = 0; s < 3; ++s) {
            const u8* bs = NP(kBitsetBase[s]) + b * 0x2014;
            for (u32 o = 0; o < 0x2004; o += 4)
                if (rd<u32>(bs, o)) { why = F("bitset %d bucket %d word at +0x%X not cleared", s, b, o); return false; }
            if (rd<u32>(bs, 0x200C)) { why = F("bitset %d bucket %d dirty count %u", s, b, rd<u32>(bs, 0x200C)); return false; }
        }
        if (rd<u32>(NP(kCellVec) + b * 16, 8)) { why = F("cell vector bucket %d count %u", b, rd<u32>(NP(kCellVec) + b * 16, 8)); return false; }
    }
    return true;
}
static void RecoverStatics() {   // after a propagated fault the original never reached its clears: run the image's own clear routine
    typedef void(__thiscall * ClearFn)(void*);
    for (int b = 0; b < 2; ++b) {
        for (int s = 0; s < 3; ++s) reinterpret_cast<ClearFn>(NP(0x542AA0))(NP(kBitsetBase[s]) + b * 0x2014);
        wr<u32>(NP(kCellVec) + b * 16, 8, 0);
    }
}
static u64 SnapHash(int bucket) {
    u64 h = 1469598103934665603ull;
    const u8* bs = NP(kBitsetBase[0]) + bucket * 0x2014;
    h = Fnv(bs, 0x2004, h);
    const u32 cnt = rd<u32>(bs, 0x200C);
    h = Fnv(&cnt, 4, h);
    const u8* data = reinterpret_cast<const u8*>(static_cast<uintptr_t>(rd<u32>(bs, 0x2010)));
    if (cnt <= 0x10000 && data) h = Fnv(data, cnt * 2, h);
    const u8* cv = NP(kCellVec) + bucket * 16;
    const u32 cc = rd<u32>(cv, 8);
    h = Fnv(&cc, 4, h);
    const u8* cd = reinterpret_cast<const u8*>(static_cast<uintptr_t>(rd<u32>(cv, 0xC)));
    if (cc <= 0x100000 && cd) h = Fnv(cd, cc * 8, h);
    return h;
}

// ------------------------------------------------------------------------------------------------ kits / pool (as the collision harness)
struct Kit { u8* base = nullptr; u32 plane = 0, ring = 0, box = 0, wall = 0, unit_hit = 0, unit_inside = 0; };
static Kit LoadWorkerKit(const std::string& path) {
    std::vector<u8> blob;
    REQ(ReadAll(path, blob), "read worker kit %s", path.c_str());
    REQ(blob.size() > 32, "kit size");
    u32 hdr[8];
    std::memcpy(hdr, blob.data(), 32);
    REQ(hdr[0] == 0x4B43424Eu && hdr[1] == 1 && hdr[6] == 1, "worker kit header");
    const u32 nf = hdr[2], codeBytes = hdr[3], poolBytes = hdr[4], nrel = hdr[5];
    const size_t tableOff = 32, codeOff = tableOff + 16u * nf, poolOff = codeOff + codeBytes, relOff = poolOff + poolBytes;
    REQ(relOff + 12u * nrel == blob.size(), "kit layout");
    Kit k;
    const u32 total = codeBytes + poolBytes;
    k.base = static_cast<u8*>(VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    REQ(k.base != nullptr, "kit allocation");
    std::memcpy(k.base, blob.data() + codeOff, codeBytes);
    std::memcpy(k.base + codeBytes, blob.data() + poolOff, poolBytes);
    const u32* rel = reinterpret_cast<const u32*>(blob.data() + relOff);
    for (u32 i = 0; i != nrel; ++i) {
        const u32 kind = rel[3 * i], field = rel[3 * i + 1], target = rel[3 * i + 2];
        REQ(field + 4 <= codeBytes, "kit reloc field");
        u32 v;
        if (kind == 0) {
            REQ(target < poolBytes, "kit pool reloc");
            v = PtrU(k.base + codeBytes + target);
        } else {
            REQ(kind == 1 && target < codeBytes, "kit call reloc");
            v = (PtrU(k.base) + target) - (PtrU(k.base) + field + 4);
        }
        std::memcpy(k.base + field, &v, 4);
    }
    FlushInstructionCache(GetCurrentProcess(), k.base, total);
    const u32* tab = reinterpret_cast<const u32*>(blob.data() + tableOff);
    std::map<u32, u8*> fn;
    for (u32 i = 0; i != nf; ++i) fn[tab[4 * i]] = k.base + tab[4 * i + 1];
    auto get = [&](u32 va) { auto it = fn.find(va); REQ(it != fn.end(), "kit function 0x%08X missing", va); return PtrU(it->second); };
    k.plane = get(0x010E8500);
    k.ring = get(0x010E7030);
    k.box = get(0x010E83E0);
    k.wall = get(0x005DB450);
    k.unit_hit = get(0x00809620);
    k.unit_inside = get(0x00809C00);
    return k;
}

typedef u32(__stdcall* PoolInitFn)(ntw_pool*, const ntw_pool_config*);
typedef u32(__stdcall* PoolShutdownFn)(ntw_pool*);
struct Pool { u8* text = nullptr; void* dispatch = nullptr; PoolInitFn init = nullptr; PoolShutdownFn shutdown = nullptr; void* worker = nullptr; };
static Pool LoadPool(const std::string& dll) {
    Pool p;
    HMODULE m = LoadLibraryA(dll.c_str());
    REQ(m != nullptr, "LoadLibrary dispatcher %s", dll.c_str());
    auto* dispatch = reinterpret_cast<u8*>(GetProcAddress(m, "ntw_pool_dispatch"));
    auto* init = reinterpret_cast<u8*>(GetProcAddress(m, "ntw_pool_init"));
    auto* shutdown = reinterpret_cast<u8*>(GetProcAddress(m, "ntw_pool_shutdown"));
    auto* worker = reinterpret_cast<u8*>(GetProcAddress(m, "ntw_pool_worker_start"));
    REQ(dispatch && init && shutdown && worker, "dispatcher exports");
    auto* image = reinterpret_cast<u8*>(m);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* text = nullptr;
    const u32 rva = static_cast<u32>(dispatch - image);
    for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i)
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) text = &sec[i];
    REQ(text && (text->Characteristics & IMAGE_SCN_MEM_EXECUTE), "dispatcher code section");
    REQ(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0, "dispatcher must be import free");
    p.text = static_cast<u8*>(VirtualAlloc(nullptr, text->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    REQ(p.text != nullptr, "dispatcher allocation");
    std::memcpy(p.text, image + text->VirtualAddress, text->Misc.VirtualSize);
    FlushInstructionCache(GetCurrentProcess(), p.text, text->Misc.VirtualSize);
    const auto at = [&](u8* fn) { return p.text + (fn - image - text->VirtualAddress); };
    p.dispatch = at(dispatch);
    p.init = reinterpret_cast<PoolInitFn>(at(init));
    p.shutdown = reinterpret_cast<PoolShutdownFn>(at(shutdown));
    p.worker = at(worker);
    FreeLibrary(m);
    return p;
}
static DWORD WINAPI worker_default_fp(void* param) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    _mm_setcsr(0x1F80u);   // workers start with the default MXCSR: the batch must install the caller's
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(pool->api.worker_entry)(param);
}
static HANDLE WINAPI create_worker(LPSECURITY_ATTRIBUTES a, SIZE_T stack, LPTHREAD_START_ROUTINE entry, void* param, DWORD flags, LPDWORD id) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    REQ(PtrU(reinterpret_cast<const void*>(entry)) == pool->api.worker_entry, "relocated worker entry");
    return CreateThread(a, stack, worker_default_fp, param, flags, id);
}
alignas(64) static ntw_pool g_pool;
static Pool g_poolCode;
static u32 PoolWorkerChunks() {
    u32 s = 0;
    for (u32 i = 0; i < g_pool.workers && i < NTW_POOL_MAX_WORKERS; ++i) s += g_pool.slots[i].chunks;
    return s;
}

// ------------------------------------------------------------------------------------------------ clones (blob of native_ballistics_query_clones.py)
struct CloneInfo { u32 id, src, size, codeOff, tableVA, tableOff, tableBytes; };
struct Clones {
    u8* area = nullptr;
    u32 bytes = 0;
    std::vector<CloneInfo> c;
    u32 query = 0, wrapper = 0;
    u32 hookGatherField = 0, hookUnitField = 0;   // area offsets
};
static Clones g_clones;
enum { FIX_IMAGE_ABS = 1, FIX_IMAGE_REL = 2, FIX_HOOK_REL = 3, FIX_TABLE_ABS = 4, FIX_TABLE_ENTRY = 5 };

static void LoadClones(const std::vector<u8>& blob, const u32 hooks[4]) {
    REQ(blob.size() >= 0x60, "clone blob size");
    u32 h[16];
    std::memcpy(h, blob.data(), sizeof h);
    REQ(h[0] == 0x4B43514Eu && h[1] == 1 && h[2] == 0x60, "clone blob magic/version");
    u8 sha[32];
    std::memcpy(sha, blob.data() + 0x40, 32);
    char hex[65];
    for (int i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", sha[i]);
    REQ(std::string(hex) == kImageSha, "clone blob is bound to another image");
    const u32 nclones = h[3], nfix = h[4], cloneOff = h[5], codeOff = h[6], codeBytes = h[7], fixOff = h[8];
    REQ(h[9] == kImageBase, "clone blob image base");
    REQ(nclones == 2 && cloneOff + 32u * nclones <= blob.size() && codeOff + codeBytes <= blob.size() && fixOff + 16ull * nfix <= blob.size(), "clone blob layout");
    g_clones.bytes = codeBytes;
    const u32 alloc = (codeBytes + 0xFFFu) & ~0xFFFu;
    g_clones.area = static_cast<u8*>(VirtualAlloc(nullptr, alloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    REQ(g_clones.area != nullptr, "clone area allocation");
    std::memcpy(g_clones.area, blob.data() + codeOff, codeBytes);
    for (u32 i = 0; i < nclones; ++i) {
        u32 v[8];
        std::memcpy(v, blob.data() + cloneOff + 32 * i, 32);
        g_clones.c.push_back(CloneInfo{v[0], v[1], v[2], v[3], v[4], v[5], v[6]});
    }
    REQ(g_clones.c[0].id == 1 && g_clones.c[0].src == 0x6392C0 && g_clones.c[0].size == 0x93C, "query clone descriptor");
    REQ(g_clones.c[1].id == 2 && g_clones.c[1].src == 0x53C060 && g_clones.c[1].size == 0x117, "wrapper clone descriptor");
    const u32 area = PtrU(g_clones.area);
    std::vector<u8> pristine(g_clones.area, g_clones.area + codeBytes);
    std::vector<u32> kinds(codeBytes, 0), cloneOf(codeBytes, 0);
    std::vector<u8> fieldStart(codeBytes, 0);
    u32 kindCount[6] = {};
    for (u32 i = 0; i < nfix; ++i) {
        u32 f[4];
        std::memcpy(f, blob.data() + fixOff + 16 * i, 16);
        const u32 kind = f[0], cid = f[1], off = f[2], arg = f[3];
        REQ(off + 4 <= codeBytes && kind >= 1 && kind <= 5 && cid >= 1 && cid <= 2, "fixup record %u", i);
        u32 v = 0;
        switch (kind) {
            case FIX_IMAGE_ABS: v = rd<u32>(g_clones.area, off) + g_delta; break;
            case FIX_IMAGE_REL: v = (arg + g_delta) - (area + off + 4); break;
            case FIX_HOOK_REL: REQ(arg >= 1 && arg <= 3 && hooks[arg], "hook %u address", arg); v = hooks[arg] - (area + off + 4);
                if (arg == 1) g_clones.hookGatherField = off;
                if (arg == 2) g_clones.hookUnitField = off;
                break;
            case FIX_TABLE_ABS: v = area + arg; break;
            default: v = area + arg; break;
        }
        for (u32 b = 0; b < 4; ++b) { REQ(kinds[off + b] == 0, "fixups overlap at 0x%X", off + b); kinds[off + b] = kind; cloneOf[off + b] = cid; }
        fieldStart[off] = 1;
        wr<u32>(g_clones.area, off, v);
        ++kindCount[kind];
    }
    FlushInstructionCache(GetCurrentProcess(), g_clones.area, codeBytes);
    g_clones.query = area + g_clones.c[0].codeOff;
    g_clones.wrapper = area + g_clones.c[1].codeOff;
    REQ(kindCount[FIX_IMAGE_ABS] == 30 && kindCount[FIX_HOOK_REL] == 3 && kindCount[FIX_TABLE_ABS] == 1 && kindCount[FIX_TABLE_ENTRY] == 4,
        "fixup census abs %u rel %u hook %u tabs %u tent %u", kindCount[1], kindCount[2], kindCount[3], kindCount[4], kindCount[5]);

    // ---- source guards: the clone IS the private image's code except at the claimed fields ----------------------------------
    for (const CloneInfo& ci : g_clones.c) {
        const u8* src = NP(ci.src);
        for (u32 k = 0; k < ci.size; ++k) {
            const u32 o = ci.codeOff + k;
            if (kinds[o] == 0) REQ(g_clones.area[o] == src[k], "clone %u byte +0x%X differs from the private image", ci.id, k);
        }
        // abs operands equal what the loader produced in the image, rel32 calls resolve to the same absolute targets
        for (u32 o = ci.codeOff; o + 4 <= ci.codeOff + ci.size; ++o) {
            if (fieldStart[o] && kinds[o] == FIX_IMAGE_ABS)
                REQ(rd<u32>(g_clones.area, o) == rd<u32>(src, o - ci.codeOff), "clone abs operand +0x%X != relocated image operand", o - ci.codeOff);
            if (fieldStart[o] && kinds[o] == FIX_IMAGE_REL) {
                const u32 want = PtrU(src) + (o - ci.codeOff) + 4 + rd<u32>(src, o - ci.codeOff);
                const u32 got = area + o + 4 + rd<u32>(g_clones.area, o);
                REQ(want == got, "clone rel call +0x%X target 0x%08X != image target 0x%08X", o - ci.codeOff, got, want);
            }
        }
    }
    const CloneInfo& q = g_clones.c[0];
    REQ(q.tableVA == 0x639BFC && q.tableBytes == 16 && q.tableOff + 16 <= codeBytes, "query clone table descriptor");
    static const u32 want[4] = {0x639668, 0x639670, 0x639670, 0x639668};
    for (u32 i = 0; i < 4; ++i)
        REQ(rd<u32>(g_clones.area, q.tableOff + 4 * i) == area + q.codeOff + (want[i] - 0x6392C0), "private table entry %u", i);
    const u8* jmp = g_clones.area + q.codeOff + (0x639661 - 0x6392C0);
    REQ(jmp[0] == 0xFF && jmp[1] == 0x24 && jmp[2] == 0x85 && rd<u32>(jmp, 3) == area + q.tableOff, "computed jump references the private table");
    REQ(q.tableOff >= q.codeOff + q.size, "table is separate from the code");
    const u8* gcall = g_clones.area + q.codeOff + (0x639581 - 0x6392C0);
    const u8* ucall = g_clones.area + q.codeOff + (0x639699 - 0x6392C0);
    REQ(gcall[0] == 0xE8 && PtrU(gcall) + 5 + rd<u32>(gcall, 1) == hooks[1], "gather call site -> nqc_gather_hook");
    REQ(ucall[0] == 0xE8 && PtrU(ucall) + 5 + rd<u32>(ucall, 1) == hooks[2], "unit call site -> nqc_unit_hook");
    const u8* qcall = g_clones.area + g_clones.c[1].codeOff + (0x53C0E3 - 0x53C060);
    REQ(qcall[0] == 0xE8 && PtrU(qcall) + 5 + rd<u32>(qcall, 1) == hooks[3], "wrapper call site -> nqc_query_hook");
}

// ------------------------------------------------------------------------------------------------ module under test
typedef u32(__stdcall* NqcInitFn)(void*);
typedef u32(__stdcall* NqcStopFn)(void*);
struct Seg { u32 type; float p[6]; };
static_assert(sizeof(Seg) == 28, "segment");
typedef u8(__thiscall* QueryFn)(void* grid, void* out, const Seg* seg, u32 stop, u32 mask, const Seg* alt, u32 mode, void* visited, u32 arg8, float extra);
typedef u8(__fastcall* HookQueryFn)(void* grid, void* edx, void* out, const Seg* seg, u32 stop, u32 mask, const Seg* alt, u32 mode, void* visited, u32 arg8, float extra);
typedef u8(__fastcall* UnitFn)(void* unit, void* edx, const float* ray, u32 mode, float* outT, u32 sel, float extra);
typedef void(__thiscall* WrapFn)(void* holder, void* out, const Seg* seg, u32 mode, u32 stop, u32 mask, u32 arg6);

static NqcInitFn g_nqcInit;
static NqcStopFn g_nqcStop;
static HookQueryFn g_hookQuery;
static UnitFn g_hookUnit;
static volatile u32* g_state;
static u32 g_hookGather;

struct St { u32 w[16]; };
static St g_stCarry, g_stBase;   // counters are cumulative per session: carry the sessions that ended
static St st_read() {
    St s;
    for (int i = 0; i < 16; ++i) s.w[i] = (i >= 5 && i <= 14) ? g_stCarry.w[i] + (g_state[i] - g_stBase.w[i]) : g_state[i];
    return s;
}
static St st_sub(const St& a, const St& b) { St d; for (int i = 0; i < 16; ++i) d.w[i] = a.w[i] - b.w[i]; return d; }

// persistent objects outside the fixture arenas
alignas(16) static u8 g_model[0x200];     // [model] == root, [model+0xA4] == grid of the current fixture, +0xBC / +0xC0 managers (wrapper)
alignas(16) static u8 g_rootObj[0x40];    // wrapper: [holder] -> root object, [root+8] -> model
alignas(16) static u8 g_mgr1[0x40], g_mgr2[0x40];
static const u32 kRoot = 0x13579BD0u;

static u32 g_capacity = 4096, g_minParallel = 1;
static Kit g_workerKit;
static nqc_config MakeCfg(u32 capacity, u32 minParallel) {
    nqc_config c;
    std::memset(&c, 0, sizeof c);
    c.abi = NQC_ABI;
    c.size = NQC_CONFIG_BYTES;
    c.imageDelta = g_delta;
    c.root = kRoot;
    c.model = PtrU(g_model);
    c.capacity = capacity;
    c.minParallel = minParallel;
    c.dispatch = PtrU(g_poolCode.dispatch);
    c.pool = PtrU(&g_pool);
    c.queryClone = g_clones.query;
    c.kPlane = g_workerKit.plane;
    c.kRing = g_workerKit.ring;
    c.kBox = g_workerKit.box;
    c.kWall = g_workerKit.wall;
    c.kUnitHit = g_workerKit.unit_hit;
    c.kUnitInside = g_workerKit.unit_inside;
    return c;
}
static void ModuleStart(u32 capacity, u32 minParallel) {
    nqc_config c = MakeCfg(capacity, minParallel);
    const u32 e = g_nqcInit(&c);
    REQ(e == 0, "nqc_initialize failed: class %u detail 0x%X", e & 0xFF, e >> 8);
    REQ(g_state[NQC_S_ENABLED] == 1 && g_state[NQC_S_BUSY] == 0 && g_state[NQC_S_OWNER_THREAD] == 0, "state after initialize");
    for (int i = 5; i <= 14; ++i) g_stBase.w[i] = g_state[i];
    g_capacity = capacity;
    g_minParallel = minParallel;
}
static void ModuleStop() {
    for (int i = 5; i <= 14; ++i) { g_stCarry.w[i] += g_state[i] - g_stBase.w[i]; g_stBase.w[i] = g_state[i]; }
    const u32 e = g_nqcStop(nullptr);
    REQ(e == 0, "nqc_stop failed: class %u detail 0x%X", e & 0xFF, e >> 8);
    REQ(g_state[NQC_S_ENABLED] == 0 && g_state[NQC_S_BUSY] == 0, "state after stop");
}

// ------------------------------------------------------------------------------------------------ arena + random
static std::mt19937 rng(6392);
static float uf(float lo, float hi) { return lo + (hi - lo) * (static_cast<float>(rng() & 0xFFFFFF) / 16777215.0f); }
static bool coin(u32 pct) { return rng() % 100 < pct; }

struct Arena {
    u8* mem;
    size_t used = 0, cap;
    std::vector<u8> snap;
    Arena() : cap(48u << 20) {
        mem = static_cast<u8*>(VirtualAlloc(nullptr, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        REQ(mem != nullptr, "arena");
    }
    void reset() { std::memset(mem, 0, used); used = 0; }
    u8* alloc(size_t n, size_t align = 16) {
        used = (used + align - 1) & ~(align - 1);
        u8* p = mem + used;
        used += n;
        REQ(used <= cap, "arena full");
        return p;
    }
    void snapshot() { snap.assign(mem, mem + used); }
    void restore() { std::memcpy(mem, snap.data(), snap.size()); }
};
static Arena arenaA, arenaB;

// ------------------------------------------------------------------------------------------------ getters (real machine code)
enum G : u32 { G_ZERO, G_THIS, G_LOAD, G_LEA, G_IMGZERO, G_IMGTHIS, G_INC, G_BYTE, G_IMGBYTE, G_CB, G__N };
static const bool kGPure[G__N] = {true, true, true, true, true, true, false, false, false, false};
static u8* g_leaf;                      // RWX page, 0x20 per leaf slot
static u32 g_vt[G__N][16];              // vtables: slot 6 (+0x18) = the getter, every other slot traps
static std::vector<u8> g_leafSnap;
static void __declspec(naked) trap_stub() { __asm int 3 }
static u32 __fastcall getter_cb(u8* u, void*);

static void InitGetters() {
    g_leaf = static_cast<u8*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    REQ(g_leaf != nullptr, "leaf page");
    std::memset(g_leaf, 0xCC, 0x1000);
    static const u8 zero[] = {0x33, 0xC0, 0xC3};                  // xor eax,eax ; ret
    static const u8 self[] = {0x8B, 0xC1, 0xC3};                  // mov eax,ecx ; ret
    static const u8 load[] = {0x8B, 0x41, 0x60, 0xC3};            // mov eax,[ecx+60h] ; ret
    static const u8 lea[] = {0x8D, 0x41, 0x10, 0xC3};             // lea eax,[ecx+10h] ; ret
    static const u8 inc[] = {0x8B, 0x41, 0x60, 0xFF, 0x41, 0x64, 0xC3};   // mov eax,[ecx+60h] ; inc dword [ecx+64h] ; ret  (load THEN write)
    static const u8 byt[] = {0x8A, 0x41, 0x60, 0xC3};             // mov al,[ecx+60h] ; ret (byte-only form)
    std::memcpy(g_leaf + 0x00, zero, sizeof zero);
    std::memcpy(g_leaf + 0x20, self, sizeof self);
    std::memcpy(g_leaf + 0x40, load, sizeof load);
    std::memcpy(g_leaf + 0x60, lea, sizeof lea);
    std::memcpy(g_leaf + 0x80, inc, sizeof inc);
    std::memcpy(g_leaf + 0xA0, byt, sizeof byt);
    FlushInstructionCache(GetCurrentProcess(), g_leaf, 0x1000);
    const u32 target[G__N] = {PtrU(g_leaf + 0x00), PtrU(g_leaf + 0x20), PtrU(g_leaf + 0x40), PtrU(g_leaf + 0x60), NA(0x461180) /* xor eax,eax */,
                              NA(0x4470B0) /* mov eax,ecx */, PtrU(g_leaf + 0x80), PtrU(g_leaf + 0xA0), NA(0x54E920) /* mov al,[ecx+4] */,
                              PtrU(reinterpret_cast<const void*>(&getter_cb))};
    for (u32 g = 0; g < G__N; ++g) {
        for (u32 s = 0; s < 16; ++s) g_vt[g][s] = PtrU(reinterpret_cast<const void*>(&trap_stub));
        g_vt[g][6] = target[g];
    }
    g_leafSnap.assign(g_leaf, g_leaf + 0x100);
}
static void LeafRestore() { std::memcpy(g_leaf, g_leafSnap.data(), g_leafSnap.size()); }

// ------------------------------------------------------------------------------------------------ fixture
enum Act : u32 { ACT_NONE = 0, ACT_X, ACT_R, ACT_RAY, ACT_VTBL, ACT_LEAF, ACT_SEL, ACT_CW, ACT_MXCSR, ACT_PRED, ACT_FLAGS, ACT_FAULT, ACT_STOP, ACT_PROBE, ACT__N };
static const char* const kActName[ACT__N] = {"none", "unit-x", "unit-radius", "ray", "vtable", "leaf-bytes", "selector", "x87-cw", "mxcsr", "predicate", "flags", "fault", "stop", "probe"};
static const u32 kFaultCode = 0xE0715001u;

struct Knobs {
    u32 nUnits = 40;
    u32 altKind = 1;          // 0 alt == NULL, 1 type 2, 2 type 1, 3 type 3, 4 type 4
    u32 mode = 0, stop = 1, mask = 8 | 0x1000;
    float extra = 0;
    bool callerVisited = false;
    u32 action = ACT_NONE, nCb = 0;
    bool pureOnly = false;
    u32 longList = 0;
    u32 shift = 4, org = 0, limitExtra = 0;
    u32 threadId = 0;
    u32 hitPct = 55;
    bool wrapper = false;
};
struct Entry { u32 kind; u16 id; u16 pad; u32 aux; u32 obj; u32 pad2; u32 next; };
static_assert(sizeof(Entry) == 0x18, "entry layout");

struct World {
    Arena* arena = nullptr;
    Knobs k;
    u8* grid = nullptr;
    u8* threadObj = nullptr;
    Seg* seg = nullptr;
    Seg* alt = nullptr;     // may be NULL
    Seg* ray = nullptr;     // alt or seg: what the unit hit sees
    u8* visited = nullptr;  // caller visited struct or NULL
    u8* holder = nullptr;   // wrapper holder
    std::vector<u8*> units;
    std::vector<u32> nearUnits;
    std::vector<u8> unitG;
    u32 cbCount = 0;
};

static u32 PickGetter(const Knobs& k) {
    static const u32 pure[] = {G_ZERO, G_THIS, G_LOAD, G_LEA, G_IMGZERO, G_IMGTHIS};
    u32 g = pure[rng() % 6];
    if (!k.pureOnly) {
        const u32 r = rng() % 100;
        if (r >= 70 && r < 78) g = G_INC;
        else if (r >= 78 && r < 84) g = G_BYTE;
        else if (r >= 84 && r < 88) g = G_IMGBYTE;
        else if (r >= 88) g = G_CB;
    }
    if (k.altKind == 3) {   // selector 3 would call 0x5B77A0 for a non-null getter value: keep every getter result zero
        if (g == G_THIS || g == G_LEA || g == G_IMGTHIS) g = G_ZERO;
        if (g == G_BYTE || g == G_IMGBYTE) g = G_LOAD;
    }
    return g;
}

static World BuildWorld(Arena& A, const Knobs& kn) {
    A.reset();
    World w;
    w.arena = &A;
    w.k = kn;
    const u32 shift = kn.shift, dim = 1u << shift, org = kn.org;
    const float cs = 4.0f, inv = 0.25f;
    const float ext = static_cast<float>(dim - org) * cs;
    w.grid = A.alloc(0x60);
    u32* heads = reinterpret_cast<u32*>(A.alloc(4u * dim * dim));
    w.threadObj = A.alloc(0x20);
    wr<u32>(w.threadObj, 4, kn.threadId ? kn.threadId : GetCurrentThreadId());
    wr<u32>(w.grid, 0, PtrU(heads));
    wr<u32>(w.grid, 8, shift);
    wr<u32>(w.grid, 0xC, dim);
    wr<u32>(w.grid, 0x10, org);
    wr<u32>(w.grid, 0x14, dim - 1 + kn.limitExtra);
    wr<float>(w.grid, 0x20, cs);
    wr<float>(w.grid, 0x24, inv);
    wr<float>(w.grid, 0x28, -1e5f);   // clip box {xmin, zmin, xmax, zmax} for the wrapper (10DAD10)
    wr<float>(w.grid, 0x2C, -1e5f);
    wr<float>(w.grid, 0x30, 1e5f);
    wr<float>(w.grid, 0x34, 1e5f);
    wr<u32>(w.grid, 0x38, PtrU(w.threadObj));

    // segments: source (clipped) and the alternate original
    w.seg = reinterpret_cast<Seg*>(A.alloc(sizeof(Seg)));
    w.seg->type = 2;
    float len = uf(12.0f, 40.0f), ang = uf(0.0f, 6.2831853f);
    w.seg->p[0] = uf(6.0f, ext - 6.0f);
    w.seg->p[2] = uf(6.0f, ext - 6.0f);
    w.seg->p[1] = uf(0.0f, 3.0f);
    w.seg->p[3] = std::min(std::max(w.seg->p[0] + len * std::cos(ang), 1.0f), ext - 1.0f);
    w.seg->p[5] = std::min(std::max(w.seg->p[2] + len * std::sin(ang), 1.0f), ext - 1.0f);
    w.seg->p[4] = uf(0.0f, 3.0f);
    if (kn.altKind != 0) {
        w.alt = reinterpret_cast<Seg*>(A.alloc(sizeof(Seg)));
        *w.alt = *w.seg;
        static const u32 types[5] = {2, 2, 1, 3, 4};
        w.alt->type = types[kn.altKind];
        for (int i = 0; i < 6; ++i) w.alt->p[i] += uf(-0.8f, 0.8f);
        w.ray = w.alt;
    } else {
        w.ray = w.seg;
    }

    // units
    std::vector<u16> ids;
    {
        static const u16 special[] = {0, 1, 31, 32, 33, 63, 64, 0x7FFF, 0x8000, 0xFFFF, 0x0400, 0x03FF};
        std::vector<u16> all;
        for (u16 s : special) all.push_back(s);
        std::vector<u32> pool;
        for (u32 i = 0; i < 0x10000; ++i) pool.push_back(i);
        std::shuffle(pool.begin(), pool.end(), rng);
        for (u32 v : pool) {
            bool dup = false;
            for (u16 s : special) if (s == v) dup = true;
            if (!dup) all.push_back(static_cast<u16>(v));
            if (all.size() > kn.nUnits + kn.longList + 64) break;
        }
        std::vector<u16> head(all.begin(), all.begin() + std::min<size_t>(12, all.size()));
        std::shuffle(head.begin(), head.end(), rng);
        std::copy(head.begin(), head.end(), all.begin());
        ids = all;
    }
    u32 nextId = 0;
    const auto takeId = [&]() { return ids[nextId++ % ids.size()]; };
    std::vector<u16> unitId;
    const u32 cellsTotal = dim * dim;
    std::vector<std::vector<Entry*>> cells(cellsTotal);
    const auto cellOf = [&](float x, float z, u32* idx) {
        const int cx = static_cast<int>(org) + static_cast<int>(std::floor(x * inv)), cz = static_cast<int>(org) + static_cast<int>(std::floor(z * inv));
        if (cx < 0 || cz < 0 || cx >= static_cast<int>(dim) || cz >= static_cast<int>(dim)) return false;
        *idx = (static_cast<u32>(cz) << shift) + static_cast<u32>(cx);
        return true;
    };
    const auto newEntry = [&](u32 kind, u16 id, u8* obj, u32 cell) {
        Entry* e = reinterpret_cast<Entry*>(A.alloc(sizeof(Entry)));
        e->kind = kind;
        e->id = id;
        e->obj = PtrU(obj);
        cells[cell].push_back(e);
        return e;
    };
    for (u32 i = 0; i < kn.nUnits; ++i) {
        u32 g = PickGetter(kn);
        const bool nearRay = coin(kn.hitPct);
        const float r = uf(0.5f, 1.5f), h = uf(1.0f, 3.0f);
        float x, y, z;
        if (nearRay) {
            const float t = uf(0.0f, 1.0f);
            const float px = w.ray->p[0] + t * (w.ray->p[3] - w.ray->p[0]), pz = w.ray->p[2] + t * (w.ray->p[5] - w.ray->p[2]);
            const float py = w.ray->p[1] + t * (w.ray->p[4] - w.ray->p[1]);
            x = px + uf(-0.8f * r, 0.8f * r);
            z = pz + uf(-0.8f * r, 0.8f * r);
            y = py - uf(0.0f, h);
        } else {
            x = uf(1.0f, ext - 1.0f);
            z = uf(1.0f, ext - 1.0f);
            y = uf(-1.0f, 3.0f);
        }
        x = std::min(std::max(x, 0.5f), ext - 0.5f);
        z = std::min(std::max(z, 0.5f), ext - 0.5f);
        u8* u = A.alloc(0x80);
        w.units.push_back(u);
        w.unitG.push_back(static_cast<u8>(g));
        wr<u32>(u, 0, PtrU(&g_vt[g][0]));
        wr<u32>(u, 4, 0x4000u + i);
        wr<u8>(u, 0x30, coin(94) ? 1 : 0);
        const u32 fr = rng() % 100;
        wr<u32>(u, 0x34, fr < 88 ? 0x18u : (fr < 94 ? 0x10u : 0x08u));
        wr<float>(u, 0x48, x);
        wr<float>(u, 0x4C, y);
        wr<float>(u, 0x50, z);
        wr<float>(u, 0x54, h);
        wr<float>(u, 0x58, r);
        wr<u32>(u, 0x60, kn.altKind == 3 ? 0u : (coin(50) ? 0u : 0x1000u + 16u * (rng() % 64)));
        wr<u32>(u, 0x74, i);
        const u16 id = takeId();
        unitId.push_back(id);
        if (nearRay) w.nearUnits.push_back(i);
        u32 c0;
        if (cellOf(x, z, &c0)) {
            newEntry(8, id, u, c0);
            if (coin(8)) newEntry(8, id, u, c0);                                   // twin entry in the same cell: visited skips it
            if (coin(30)) {                                                         // repeated across neighbouring cells
                u32 c1;
                if (cellOf(x + uf(-4.0f, 4.0f), z + uf(-4.0f, 4.0f), &c1) && c1 != c0) newEntry(8, id, u, c1);
            }
            if (coin(4)) newEntry(8, takeId(), u, c0);                              // same object, another id
        }
    }
    // id collisions: another object entered under an existing id
    for (u32 i = 0; i + 1 < kn.nUnits; ++i) {
        if (!coin(4)) continue;
        float x = rd<float>(w.units[i + 1], 0x48), z = rd<float>(w.units[i + 1], 0x50);
        u32 c;
        if (cellOf(x, z, &c)) newEntry(8, unitId[i], w.units[i + 1], c);
    }
    // entries the ORIGINAL code rejects by the type mask / the kind chain (never reads the object)
    for (u32 c = 0; c < cellsTotal; ++c) {
        if (coin(15)) newEntry(0x1000, 0, nullptr, c);
        if (coin(12)) newEntry(2, 0, nullptr, c);
        if (coin(6)) newEntry(0x40, 0, nullptr, c);
        if (coin(6)) newEntry(0x400, 0, nullptr, c);
        if (coin(6)) newEntry(0x800, 0, nullptr, c);
    }
    // long list in the start cell of the source segment (entries beyond any module bound; distinct ids; shared objects)
    if (kn.longList && !w.units.empty()) {
        u32 c;
        if (cellOf(w.seg->p[0], w.seg->p[2], &c))
            for (u32 i = 0; i < kn.longList; ++i) newEntry(8, takeId(), w.units[rng() % w.units.size()], c);
    }
    for (u32 c = 0; c < cellsTotal; ++c) {
        std::vector<Entry*>& v = cells[c];
        if (v.empty()) continue;
        std::shuffle(v.begin(), v.end(), rng);
        heads[c] = PtrU(v[0]);
        for (size_t i = 0; i + 1 < v.size(); ++i) v[i]->next = PtrU(v[i + 1]);
    }
    // callback units carrying an action (always near the ray so that they are reached)
    if (kn.action && !w.nearUnits.empty()) {
        std::vector<u32> cand = w.nearUnits;
        std::shuffle(cand.begin(), cand.end(), rng);
        const u32 n = std::min<u32>(kn.nCb, static_cast<u32>(cand.size()));
        for (u32 j = 0; j < n; ++j) {
            const u32 ui = cand[j];
            u8* u = w.units[ui];
            wr<u32>(u, 0, PtrU(&g_vt[G_CB][0]));
            w.unitG[ui] = G_CB;
            wr<u8>(u, 0x30, 1);
            wr<u32>(u, 0x34, 0x18);
            wr<u32>(u, 0x60, 0);
            // targets: a pure, near, distinct unit
            u32 tgt = cand[(j + 1 + rng() % std::max<u32>(1, static_cast<u32>(cand.size()))) % cand.size()];
            for (u32 tries = 0; tries < 8 && (tgt == ui || !kGPure[w.unitG[tgt]]); ++tries) tgt = cand[rng() % cand.size()];
            wr<u32>(u, 0x68, kn.action);
            wr<u32>(u, 0x6C, tgt);
            u32 prm = 0;
            switch (kn.action) {
                case ACT_X: case ACT_R: prm = FBits(uf(0.2f, 0.9f)); break;
                case ACT_RAY: prm = FBits(uf(0.2f, 1.2f)); break;
                case ACT_VTBL: prm = (w.unitG[tgt] == G_THIS || w.unitG[tgt] == G_IMGTHIS) ? G_ZERO : G_LEA; break;
                case ACT_SEL: prm = coin(50) ? 4 : 1; break;
                case ACT_CW: prm = coin(50) ? 0xE7F : 0x37F; break;
                case ACT_MXCSR: prm = coin(50) ? 0x9FC0 : 0x3F80; break;
                default: break;
            }
            wr<u32>(u, 0x70, prm);
            if (kn.action == ACT_LEAF) wr<u32>(w.units[tgt], 0, PtrU(&g_vt[G_ZERO][0])), w.unitG[tgt] = G_ZERO;   // the leaf all ZERO units share
            ++w.cbCount;
        }
    }
    // caller-owned visited bitsets with preset ids (dirty list in arena memory, no growth)
    if (kn.callerVisited) {
        w.visited = A.alloc(0x10);
        for (int s = 0; s < 3; ++s) {
            u8* bs = A.alloc(0x2014);
            u8* data = A.alloc(0x20000);
            wr<u32>(bs, 0x2008, 0x10000);
            wr<u32>(bs, 0x2010, PtrU(data));
            wr<u32>(w.visited, 4 * s, PtrU(bs));
            if (s == 0) {
                for (u32 j = 0; j < kn.nUnits / 4; ++j) {
                    const u16 id = unitId[rng() % unitId.size()];
                    if (rd<u32>(bs, (id >> 5) * 4) >> (id & 31) & 1) continue;
                    wr<u32>(bs, (id >> 5) * 4, rd<u32>(bs, (id >> 5) * 4) | (1u << (id & 31)));
                    wr<u16>(data, 2 * rd<u32>(bs, 0x200C), id);
                    wr<u32>(bs, 0x200C, rd<u32>(bs, 0x200C) + 1);
                }
            }
        }
    }
    if (kn.wrapper) {
        w.holder = A.alloc(0x2900);
        wr<u32>(w.holder, 0, PtrU(g_rootObj));
    }
    return w;
}

// ------------------------------------------------------------------------------------------------ run machinery
enum Route { R_ORIG, R_HOOK, R_CLONE, R_WRAP_ORIG, R_WRAP_CLONE };
struct QArgs { void* grid; void* out; const Seg* seg; u32 stop, mask; const Seg* alt; u32 mode; void* visited; u32 arg8; float extra; };
struct OutVec { u32 w[4]; };    // {?, capacity, count, data}: the layout 0x5EF540 appends to
static OutVec g_outv;
static OutVec* g_curOut = &g_outv;

static Route g_route = R_ORIG;
static World* g_world = nullptr;
static u32 g_ownerTid = 0;
static int g_bucket = 0;
static std::vector<u32>* g_log = nullptr;
static u32 g_actSeen = 0;
static u32 g_stopRes = 0xFFFFFFFFu;
static volatile long g_foreignCb = 0;
static unsigned long g_excCode;
static void* g_excAddr;
static int exc_filter(EXCEPTION_POINTERS* p) {
    g_excCode = p->ExceptionRecord->ExceptionCode;
    g_excAddr = p->ExceptionRecord->ExceptionAddress;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void rec(u32 v) { if (g_log) g_log->push_back(v); }

static void RunProbe();   // ACT_PROBE body (scope conflicts), defined with the scenarios

static u32 __fastcall getter_cb(u8* u, void*) {
    const u32 obj2 = rd<u32>(u, 0x60);
    if (GetCurrentThreadId() != g_ownerTid) { InterlockedIncrement(&g_foreignCb); return obj2; }
    rec(0x40000000u | rd<u32>(u, 0x74));
    rec(g_curOut->w[2]);
    const u64 h = SnapHash(g_bucket);
    rec(static_cast<u32>(h));
    rec(static_cast<u32>(h >> 32));
    const u32 act = rd<u32>(u, 0x68);
    if (!act || !g_world) return obj2;
    World* w = g_world;
    const u32 ti = rd<u32>(u, 0x6C), prm = rd<u32>(u, 0x70);
    u8* T = ti < w->units.size() ? w->units[ti] : nullptr;
    g_actSeen |= 1u << act;
    switch (act) {
        case ACT_X: if (T) wr<float>(T, 0x48, rd<float>(T, 0x48) + BitsF(prm)); break;
        case ACT_R: if (T) wr<float>(T, 0x58, rd<float>(T, 0x58) + BitsF(prm)); break;
        case ACT_RAY: w->ray->p[3] += BitsF(prm); break;
        case ACT_VTBL: if (T) wr<u32>(T, 0, PtrU(&g_vt[prm][0])); break;
        case ACT_LEAF: g_leaf[0] = 0x8B; g_leaf[1] = 0xC1; g_leaf[2] = 0xC3; FlushInstructionCache(GetCurrentProcess(), g_leaf, 16); break;   // zero leaf -> "this" leaf
        case ACT_SEL: w->ray->type = prm; break;
        case ACT_CW: set_cw(static_cast<u16>(prm)); break;
        case ACT_MXCSR: _mm_setcsr(prm); break;
        case ACT_PRED: if (T) wr<u8>(T, 0x30, 0); break;
        case ACT_FLAGS: if (T) wr<u32>(T, 0x34, 0); break;
        case ACT_FAULT: RaiseException(kFaultCode, 0, 0, nullptr); break;
        case ACT_STOP: if (g_route == R_HOOK) g_stopRes = g_nqcStop(nullptr); break;
        case ACT_PROBE: if (g_route == R_HOOK) RunProbe(); break;
        default: break;
    }
    return obj2;
}

static u32 call_query(Route r, const QArgs& a, u8* ret) {
    __try {
        if (r == R_ORIG) *ret = reinterpret_cast<QueryFn>(NP(0x6392C0))(a.grid, a.out, a.seg, a.stop, a.mask, a.alt, a.mode, a.visited, a.arg8, a.extra);
        else if (r == R_HOOK) *ret = g_hookQuery(a.grid, nullptr, a.out, a.seg, a.stop, a.mask, a.alt, a.mode, a.visited, a.arg8, a.extra);
        else *ret = reinterpret_cast<HookQueryFn>(static_cast<uintptr_t>(g_clones.query))(a.grid, nullptr, a.out, a.seg, a.stop, a.mask, a.alt, a.mode, a.visited, a.arg8, a.extra);
        return 0;
    } __except (exc_filter(GetExceptionInformation())) {
        return g_excCode;
    }
}
static u32 call_wrapper(Route r, void* holder, void* out, const Seg* seg, u32 mode, u32 stop, u32 mask) {
    __try {
        const u32 fn = r == R_WRAP_ORIG ? NA(0x53C060) : g_clones.wrapper;
        reinterpret_cast<WrapFn>(static_cast<uintptr_t>(fn))(holder, out, seg, mode, stop, mask, 0);
        return 0;
    } __except (exc_filter(GetExceptionInformation())) {
        return g_excCode;
    }
}

struct OutRec { u8 b[0x1C]; };
struct RunOut {
    u32 exc = 0;
    u8 ret = 0;
    std::vector<OutRec> out;
    std::vector<u32> log;
    std::vector<u8> arena, leaf;
    u16 cw = 0, sw = 0;
    u32 csr = 0;
    u64 faultHash[2] = {0, 0};
    St delta;
    u32 actSeen = 0;
    u32 stopRes = 0xFFFFFFFFu;
    long foreignCb = 0;
};
static void HarvestOut(RunOut& r) {
    const u32 count = g_outv.w[2];
    REQ(count <= 0x100000, "implausible output count %u", count);
    const u8* data = reinterpret_cast<const u8*>(static_cast<uintptr_t>(g_outv.w[3]));
    for (u32 i = 0; i < count; ++i) {
        OutRec o;
        std::memset(&o, 0, sizeof o);
        std::memcpy(o.b, data + 0x1C * i, 0x19);   // +0x19..0x1B are never written by 0x5EF540
        r.out.push_back(o);
    }
    if (data) HostFree(const_cast<u8*>(data));
    std::memset(&g_outv, 0, sizeof g_outv);
}

enum Ctx { CTX_OK, CTX_BADGRID, CTX_BADROOT };
static RunOut RunOne(World& w, Route route, const Fp& fp, Ctx ctx = CTX_OK) {
    RunOut r;
    w.arena->restore();
    LeafRestore();
    std::memset(&g_outv, 0, sizeof g_outv);
    std::memset(g_model, 0, sizeof g_model);
    wr<u32>(g_model, 0, ctx == CTX_BADROOT ? kRoot ^ 1u : kRoot);
    wr<u32>(g_model, 0xA4, ctx == CTX_BADGRID ? PtrU(w.grid) ^ 0x10u : PtrU(w.grid));
    wr<u32>(g_model, 0xBC, PtrU(g_mgr1));
    wr<u32>(g_model, 0xC0, PtrU(g_mgr2));
    wr<u32>(g_rootObj, 8, PtrU(g_model));
    std::memset(g_mgr1, 0, sizeof g_mgr1);
    std::memset(g_mgr2, 0, sizeof g_mgr2);
    wr<u32>(g_mgr1, 0, PtrU(w.threadObj));
    g_route = route;
    g_world = &w;
    g_ownerTid = GetCurrentThreadId();
    g_bucket = rd<u32>(w.threadObj, 4) == g_ownerTid ? 0 : 1;
    g_log = &r.log;
    g_actSeen = 0;
    g_stopRes = 0xFFFFFFFFu;
    g_curOut = &g_outv;
    const long fcb = g_foreignCb;
    QArgs a = {w.grid, &g_outv, w.seg, w.k.stop, w.k.mask, w.alt, w.k.mode, w.visited, 0x5A5A, w.k.extra};
    const St before = st_read();
    fp_set(fp);
    if (route == R_WRAP_ORIG || route == R_WRAP_CLONE) r.exc = call_wrapper(route, w.holder, &g_outv, w.alt ? w.alt : w.seg, w.k.mode, w.k.stop, w.k.mask);
    else r.exc = call_query(route, a, &r.ret);
    const Fp after = fp_get();
    r.sw = get_sw();
    fp_set(kFpDefault);
    r.cw = after.cw;
    r.csr = after.csr;
    r.delta = st_sub(st_read(), before);
    g_log = nullptr;
    g_world = nullptr;
    r.actSeen = g_actSeen;
    r.stopRes = g_stopRes;
    r.foreignCb = g_foreignCb - fcb;
    if (r.exc) {
        for (int b = 0; b < 2; ++b) r.faultHash[b] = SnapHash(b);
        RecoverStatics();
    } else {
        std::string why;
        REQ(StaticsClean(why), "statics not clean after %s run: %s", route == R_ORIG ? "original" : "hooked", why.c_str());
    }
    HarvestOut(r);
    r.arena.assign(w.arena->mem, w.arena->mem + w.arena->used);
    r.leaf.assign(g_leaf, g_leaf + 0x100);
    return r;
}

static void ExpectEqual(const RunOut& a, const RunOut& b, const std::string& tag) {
    REQ(a.exc == b.exc, "%s: exception %08X vs %08X", tag.c_str(), a.exc, b.exc);
    if (!a.exc) REQ(a.ret == b.ret, "%s: return %u vs %u", tag.c_str(), a.ret, b.ret);
    REQ(a.out.size() == b.out.size(), "%s: result count %zu vs %zu", tag.c_str(), a.out.size(), b.out.size());
    for (size_t i = 0; i < a.out.size(); ++i)
        REQ(std::memcmp(a.out[i].b, b.out[i].b, 0x19) == 0, "%s: result record %zu differs", tag.c_str(), i);
    REQ(a.log.size() == b.log.size(), "%s: getter log length %zu vs %zu", tag.c_str(), a.log.size(), b.log.size());
    for (size_t i = 0; i < a.log.size(); ++i) REQ(a.log[i] == b.log[i], "%s: getter log[%zu] %08X vs %08X", tag.c_str(), i, a.log[i], b.log[i]);
    REQ(a.arena.size() == b.arena.size(), "%s: arena size", tag.c_str());
    if (std::memcmp(a.arena.data(), b.arena.data(), a.arena.size()) != 0) {
        size_t i = 0;
        while (a.arena[i] == b.arena[i]) ++i;
        fail(F("%s: fixture memory differs at arena+0x%zX (%02X vs %02X)", tag.c_str(), i, a.arena[i], b.arena[i]));
    }
    REQ(a.leaf == b.leaf, "%s: leaf code bytes differ", tag.c_str());
    if (!a.exc) {
        REQ(a.cw == b.cw, "%s: x87 CW %04X vs %04X", tag.c_str(), a.cw, b.cw);
        REQ(((a.csr ^ b.csr) & 0xFFC0u) == 0, "%s: MXCSR control %08X vs %08X", tag.c_str(), a.csr, b.csr);
        REQ(((a.sw ^ b.sw) & 0x3800u) == 0 && (a.sw & 0x3800u) == 0, "%s: x87 stack depth sw %04X vs %04X", tag.c_str(), a.sw, b.sw);
    } else {
        for (int i = 0; i < 2; ++i) REQ(a.faultHash[i] == b.faultHash[i], "%s: static state at fault differs (bucket %d)", tag.c_str(), i);
    }
}

// ------------------------------------------------------------------------------------------------ totals
struct Tot {
    u32 worlds = 0, hitWorlds = 0, missWorlds = 0, results = 0, faults = 0, stopWorlds = 0, nonStopWorlds = 0, altNull = 0, altOther = 0, callerVisited = 0,
        fpNonNearest = 0, fpOther = 0, longLists = 0, stopInScope = 0, probes = 0, directUnits = 0, directClones = 0, wrongCtx = 0, disabled = 0, wrapperRuns = 0,
        wrapperHits = 0, wrapperGate = 0, twoQuery = 0, impureReached = 0;
    u32 st[16] = {};
    u32 changedBy[ACT__N] = {};
    u32 actWorlds[ACT__N] = {};
    u32 poolTeam = 0, poolWoken = 0, poolMain = 0, poolWorker = 0;
};
static void Merge(Tot& d, const Tot& s) {
    d.worlds += s.worlds; d.hitWorlds += s.hitWorlds; d.missWorlds += s.missWorlds; d.results += s.results; d.faults += s.faults;
    d.stopWorlds += s.stopWorlds; d.nonStopWorlds += s.nonStopWorlds; d.altNull += s.altNull; d.altOther += s.altOther;
    d.callerVisited += s.callerVisited; d.fpNonNearest += s.fpNonNearest; d.fpOther += s.fpOther; d.longLists += s.longLists;
    d.stopInScope += s.stopInScope; d.directUnits += s.directUnits; d.twoQuery += s.twoQuery;
    for (int i = 0; i < 16; ++i) d.st[i] += s.st[i];
    for (int a = 0; a < ACT__N; ++a) { d.changedBy[a] += s.changedBy[a]; d.actWorlds[a] += s.actWorlds[a]; }
    d.poolTeam += s.poolTeam; d.poolWoken += s.poolWoken; d.poolMain += s.poolMain; d.poolWorker += s.poolWorker;
}

static const Fp kFpList[] = {
    {0x27F, 0x1F80}, {0x37F, 0x1F80}, {0x07F, 0x1F80}, {0x27F, 0x9FC0}, {0x27F, 0x3F80}, {0x27F, 0x5F80}, {0x27F, 0x7F80},
    {0xE7F, 0x1F80}, {0xA7F, 0x1F80}, {0x67F, 0x1F80}, {0x37F, 0x9FC0},
};
static bool FpNonNearest(const Fp& f) { return (f.cw & 0xC00) != 0 || (f.csr & 0x6000) != 0; }

// One world: original run A, hooked run B (+ optional direct clone run C), full comparison and expectations.
static void ExerciseWorld(World& w, const Fp& fp, Tot& tot, const char* label, bool allowModuleExpect = true) {
    w.arena->snapshot();
    RunOut A = RunOne(w, R_ORIG, fp);
    RunOut B = RunOne(w, R_HOOK, fp);
    const std::string tag = F("%s [units %u alt %u act %s stop %u mode %u extra %g visited %d mask %X fp %04X/%08X]", label, w.k.nUnits, w.k.altKind,
                              kActName[w.k.action], w.k.stop, w.k.mode, w.k.extra, w.visited != nullptr, w.k.mask, fp.cw, fp.csr);
    ExpectEqual(A, B, tag);
    REQ(g_state[NQC_S_BUSY] == 0 && g_state[NQC_S_OWNER_THREAD] == 0, "%s: scope not released (busy %u owner %u)", tag.c_str(), g_state[NQC_S_BUSY], g_state[NQC_S_OWNER_THREAD]);
    const St& d = B.delta;
    if (B.stopRes != 0xFFFFFFFFu) {   // the module was stopped from inside the scope: BUSY, then fully disabled; restart for the next world
        REQ((B.stopRes & 0xFF) == NQC_E_BUSY, "%s: nqc_stop inside a scope returned %08X", tag.c_str(), B.stopRes);
        REQ(g_state[NQC_S_ENABLED] == 0, "%s: entries must be disabled after a busy stop", tag.c_str());
        ++tot.stopInScope;
        ModuleStop();
        ModuleStart(g_capacity, g_minParallel);
    } else {
        REQ(g_state[NQC_S_ENABLED] == 1, "%s: module disabled itself", tag.c_str());
    }
    ++tot.worlds;
    tot.results += static_cast<u32>(A.out.size());
    if (A.exc) ++tot.faults;
    else if (A.out.empty()) ++tot.missWorlds;
    else ++tot.hitWorlds;
    if (w.k.stop) ++tot.nonStopWorlds; else ++tot.stopWorlds;
    if (w.k.altKind == 0) ++tot.altNull;
    if (w.k.altKind >= 2) ++tot.altOther;
    if (w.visited) ++tot.callerVisited;
    if (FpNonNearest(fp)) ++tot.fpNonNearest;
    else if (fp.cw != kFpDefault.cw || fp.csr != kFpDefault.csr) ++tot.fpOther;
    if (w.k.longList) ++tot.longLists;
    if (allowModuleExpect && B.stopRes == 0xFFFFFFFFu) {
        (void)d;
        REQ(d.w[NQC_S_FALLBACKS] >= d.w[NQC_S_CHANGED], "%s: changed %u exceeds fallbacks %u", tag.c_str(), d.w[NQC_S_CHANGED], d.w[NQC_S_FALLBACKS]);
        if (w.k.altKind >= 2) REQ(d.w[NQC_S_CACHE_HITS] == 0, "%s: a non selector-2 query was served from the cache (%u)", tag.c_str(), d.w[NQC_S_CACHE_HITS]);
        if (FpNonNearest(fp)) REQ(d.w[NQC_S_CACHE_HITS] == 0, "%s: cache used under non-nearest rounding (%u)", tag.c_str(), d.w[NQC_S_CACHE_HITS]);
        if (w.k.action >= ACT_X && w.k.action <= ACT_MXCSR && (B.actSeen & (1u << w.k.action))) {
            ++tot.actWorlds[w.k.action];
            if (d.w[NQC_S_CHANGED] > 0) ++tot.changedBy[w.k.action];
        }
        (void)0;
    }
    REQ(B.foreignCb == 0 && A.foreignCb == 0, "%s: callbacks ran on foreign threads", tag.c_str());
}

// ------------------------------------------------------------------------------------------------ out-of-scope unit hooks
static u8 OrigUnit(u8* u, const float* ray, u32 mode, float* t, u32 sel, float extra) {
    return reinterpret_cast<UnitFn>(NP(0x809620))(u, nullptr, ray, mode, t, sel, extra);
}
static void DirectUnitTest(World& w, Tot& tot) {
    w.arena->restore();
    LeafRestore();
    const u32 sel = w.ray->type;
    if (sel == 3) return;
    u32 tested = 0;
    for (u32 i = 0; i < w.units.size() && tested < 14; ++i) {
        if (w.unitG[i] == G_CB) continue;
        u8* u = w.units[i];
        w.arena->restore();
        float t1 = BitsF(0x7FC00001u), t2 = BitsF(0x7FC00001u);
        const St s0 = st_read();
        const u8 r1 = OrigUnit(u, w.ray->p, w.k.mode, &t1, sel, w.k.extra);
        const u32 c1 = rd<u32>(u, 0x64);
        w.arena->restore();
        const u8 r2 = g_hookUnit(u, nullptr, w.ray->p, w.k.mode, &t2, sel, w.k.extra);
        const u32 c2 = rd<u32>(u, 0x64);
        const St d = st_sub(st_read(), s0);
        REQ(r1 == r2, "unit hook outside a scope: %u vs %u (unit %u)", r1, r2, i);
        if (r1 == 1) REQ(FBits(t1) == FBits(t2), "unit hook outside a scope: t %08X vs %08X", FBits(t1), FBits(t2));
        REQ(c1 == c2, "unit getter executed %u vs %u times (unit %u, getter %u): the original must run exactly once", c1, c2, i, w.unitG[i]);
        REQ(d.w[NQC_S_CACHE_HITS] == 0 && d.w[NQC_S_FALLBACKS] >= 1, "unit hook outside any scope: hits %u fallbacks %u", d.w[NQC_S_CACHE_HITS], d.w[NQC_S_FALLBACKS]);
        ++tested;
        ++tot.directUnits;
    }
}

// ------------------------------------------------------------------------------------------------ scope conflicts (foreign thread, reentrant)
struct Probe {
    bool armed = false, done = false;
    World* A = nullptr;
    World* B = nullptr;
    RunOut refA, refB;
    u8* U = nullptr;
    u8 refHit = 0;
    float refT = 0;
    // results
    St reentrantDelta, foreignDelta;
    u32 foreignExc = 0;
    std::vector<OutRec> foreignOut, reentrantOut;
    u8 foreignRet = 0, reentrantRet = 0, unitHit = 0;
    float unitT = 0;
    u32 reentrantExc = 0;
};
static Probe g_probe;
struct ForeignJob { u32 exc = 0; u8 ret = 0; std::vector<OutRec>* out = nullptr; u8 unitHit = 0; float unitT = 0; };
static OutVec g_foreignOutv;
static void HarvestVec(OutVec& v, std::vector<OutRec>& out) {
    const u32 count = v.w[2];
    REQ(count <= 0x100000, "implausible output count");
    const u8* data = reinterpret_cast<const u8*>(static_cast<uintptr_t>(v.w[3]));
    for (u32 i = 0; i < count; ++i) {
        OutRec o;
        std::memset(&o, 0, sizeof o);
        std::memcpy(o.b, data + 0x1C * i, 0x19);
        out.push_back(o);
    }
    if (data) HostFree(const_cast<u8*>(data));
    std::memset(&v, 0, sizeof v);
}
static DWORD WINAPI foreign_proc(LPVOID p) {
    ForeignJob* j = static_cast<ForeignJob*>(p);
    World& A = *g_probe.A;
    std::memset(&g_foreignOutv, 0, sizeof g_foreignOutv);
    QArgs a = {A.grid, &g_foreignOutv, A.seg, A.k.stop, A.k.mask, A.alt, A.k.mode, A.visited, 0x5A5A, A.k.extra};
    j->exc = call_query(R_HOOK, a, &j->ret);
    HarvestVec(g_foreignOutv, *j->out);
    float t = BitsF(0x7FC00001u);
    j->unitHit = g_hookUnit(g_probe.U, nullptr, A.ray->p, A.k.mode, &t, 2, A.k.extra);
    j->unitT = t;
    return 0;
}
static void RunProbe() {
    Probe& P = g_probe;
    if (!P.armed || P.done) return;
    P.done = true;
    REQ(g_state[NQC_S_BUSY] == 1 && g_state[NQC_S_OWNER_THREAD] == GetCurrentThreadId(), "scope owner during the callback: busy %u owner %u", g_state[NQC_S_BUSY], g_state[NQC_S_OWNER_THREAD]);
    // (1) reentrant: another grid (other thread-bucket) queried on the SAME thread inside the scope -> ORIGINAL 0x6392C0
    {
        World& B = *P.B;
        B.arena->restore();
        std::memset(&g_foreignOutv, 0, sizeof g_foreignOutv);
        QArgs a = {B.grid, &g_foreignOutv, B.seg, B.k.stop, B.k.mask, B.alt, B.k.mode, B.visited, 0x5A5A, B.k.extra};
        const St s0 = st_read();
        P.reentrantExc = call_query(R_HOOK, a, &P.reentrantRet);
        P.reentrantDelta = st_sub(st_read(), s0);
        HarvestVec(g_foreignOutv, P.reentrantOut);
        REQ(g_state[NQC_S_BUSY] == 1 && g_state[NQC_S_OWNER_THREAD] == GetCurrentThreadId(), "reentrant query must not release / steal the scope");
    }
    // (2) foreign thread: same grid (identity matches) while the owner scope is active: ORIGINAL query + ORIGINAL unit hit
    {
        ForeignJob job;
        job.out = &P.foreignOut;
        const St s0 = st_read();
        HANDLE h = CreateThread(nullptr, 0, foreign_proc, &job, 0, nullptr);
        REQ(h != nullptr, "CreateThread");
        REQ(WaitForSingleObject(h, 60000) == WAIT_OBJECT_0, "foreign thread did not finish");
        CloseHandle(h);
        P.foreignDelta = st_sub(st_read(), s0);
        P.foreignExc = job.exc;
        P.foreignRet = job.ret;
        P.unitHit = job.unitHit;
        P.unitT = job.unitT;
    }
}

static void ScopeConflictTest(Tot& tot) {
    Knobs ka;
    ka.nUnits = 60;
    ka.pureOnly = true;
    ka.action = ACT_PROBE;
    ka.nCb = 3;
    ka.stop = 1;
    ka.hitPct = 70;
    World A = BuildWorld(arenaA, ka);
    Knobs kb;
    kb.nUnits = 40;
    kb.pureOnly = true;
    kb.stop = 1;
    kb.threadId = 0xFFFFFFF0u;    // other bucket: its statics are independent from the active scope's
    World B = BuildWorld(arenaB, kb);
    arenaA.snapshot();
    arenaB.snapshot();
    // references: original queries on the pristine fixtures
    Probe& P = g_probe;
    P = Probe();
    P.A = &A;
    P.B = &B;
    P.refB = RunOne(B, R_ORIG, kFpDefault);
    P.refA = RunOne(A, R_ORIG, kFpDefault);
    P.U = nullptr;
    for (u32 i = 0; i < A.units.size(); ++i)
        if (kGPure[A.unitG[i]] && rd<u8>(A.units[i], 0x30)) { P.U = A.units[i]; break; }
    REQ(P.U != nullptr, "probe unit");
    arenaA.restore();
    P.refT = BitsF(0x7FC00001u);
    P.refHit = OrigUnit(P.U, A.ray->p, A.k.mode, &P.refT, 2, A.k.extra);
    P.armed = true;
    RunOut H = RunOne(A, R_HOOK, kFpDefault);
    P.armed = false;
    REQ(P.done, "probe callback never ran in the hooked query");
    ExpectEqual(P.refA, H, "scope conflicts (owner query)");
    REQ(g_state[NQC_S_BUSY] == 0 && g_state[NQC_S_OWNER_THREAD] == 0, "scope not released after the probe");
    // reentrant result == original query on the other grid
    REQ(!P.reentrantExc && P.reentrantRet == P.refB.ret && P.reentrantOut.size() == P.refB.out.size(), "reentrant query result differs: ret %u/%u count %zu/%zu", P.reentrantRet,
        P.refB.ret, P.reentrantOut.size(), P.refB.out.size());
    for (size_t i = 0; i < P.refB.out.size(); ++i) REQ(std::memcmp(P.refB.out[i].b, P.reentrantOut[i].b, 0x19) == 0, "reentrant record %zu", i);
    REQ(P.reentrantDelta.w[NQC_S_CACHE_HITS] == 0 && P.reentrantDelta.w[NQC_S_PREPARATIONS] == 0 && P.reentrantDelta.w[NQC_S_FALLBACKS] >= 1,
        "reentrant query used the cache: hits %u prep %u fallbacks %u", P.reentrantDelta.w[NQC_S_CACHE_HITS], P.reentrantDelta.w[NQC_S_PREPARATIONS], P.reentrantDelta.w[NQC_S_FALLBACKS]);
    // foreign thread: identical grid, scope busy -> ORIGINAL query equal to the owner's expected result
    REQ(!P.foreignExc && P.foreignRet == P.refA.ret && P.foreignOut.size() == P.refA.out.size(), "foreign query result differs: ret %u/%u count %zu/%zu", P.foreignRet, P.refA.ret,
        P.foreignOut.size(), P.refA.out.size());
    for (size_t i = 0; i < P.refA.out.size(); ++i) REQ(std::memcmp(P.refA.out[i].b, P.foreignOut[i].b, 0x19) == 0, "foreign record %zu", i);
    REQ(P.foreignDelta.w[NQC_S_CACHE_HITS] == 0 && P.foreignDelta.w[NQC_S_PREPARATIONS] == 0 && P.foreignDelta.w[NQC_S_FALLBACKS] >= 2,
        "foreign thread used the cache: hits %u prep %u fallbacks %u", P.foreignDelta.w[NQC_S_CACHE_HITS], P.foreignDelta.w[NQC_S_PREPARATIONS], P.foreignDelta.w[NQC_S_FALLBACKS]);
    REQ(P.unitHit == P.refHit && (P.refHit != 1 || FBits(P.unitT) == FBits(P.refT)), "foreign unit hook %u/%u t %08X/%08X", P.unitHit, P.refHit, FBits(P.unitT), FBits(P.refT));
    ++tot.probes;
    std::printf("scope conflicts: reentrant results %zu foreign results %zu (hits during foreign window 0, fallbacks %u)\n", P.reentrantOut.size(), P.foreignOut.size(),
                P.foreignDelta.w[NQC_S_FALLBACKS]);
}

// ------------------------------------------------------------------------------------------------ knob schedule
static Knobs MakeKnobs(u32 i, u32 phase) {
    Knobs k;
    k.nUnits = (i % 7 == 0) ? 3 + rng() % 6 : 24 + rng() % 80;
    k.shift = (i % 5 == 0) ? 3 : (i % 5 == 1 ? 5 : 4);
    k.org = rng() % 2;
    k.limitExtra = (rng() % 3 == 0) ? 2 : 0;
    const u32 r = i % 20;
    k.altKind = r <= 13 ? 1 : (r <= 15 ? 0 : (r == 16 ? 2 : (r == 17 ? 3 : (r == 18 ? 4 : 1))));
    k.mode = rng() % 4;
    k.stop = rng() % 2;
    static const float extras[] = {0.0f, 0.0f, 0.0f, 0.25f, 1.5f};
    k.extra = extras[rng() % 5];
    k.callerVisited = (i % 9) == 4;
    if (i % 11 == 5) k.mask = 8;
    if (i % 13 == 6) k.mask = 0x1000;
    static const u32 acts[] = {ACT_NONE, ACT_NONE, ACT_NONE, ACT_X, ACT_R, ACT_RAY, ACT_VTBL, ACT_LEAF, ACT_SEL, ACT_CW, ACT_MXCSR, ACT_PRED, ACT_FLAGS, ACT_FAULT, ACT_STOP};
    k.action = acts[(i + phase) % 15];
    if (k.action == ACT_SEL && k.altKind != 1) k.action = ACT_X;
    if (k.action == ACT_STOP && (((i + phase) / 15) % 2) != 0) k.action = ACT_NONE;    // stops are rare: each restarts the module
    if (k.action == ACT_FAULT && (((i + phase) / 15) % 3) != 0) k.action = ACT_NONE;
    k.nCb = k.action ? 3 : 0;
    if (k.action == ACT_STOP || k.action == ACT_FAULT) k.nCb = 2;
    k.longList = (i % 17 == 3) ? 400 + rng() % 1500 : 0;
    k.hitPct = 55;
    return k;
}

static void RunWorlds(const char* name, u32 count, u32 phase, Tot& tot, bool fpMix) {
    const St s0 = st_read();
    const u32 team0 = g_pool.st_team, woken0 = g_pool.st_woken, main0 = g_pool.st_main_chunks, wc0 = PoolWorkerChunks();
    for (u32 i = 0; i < count; ++i) {
        Knobs k = MakeKnobs(i, phase);
        World w = BuildWorld(arenaA, k);
        Fp fp = kFpDefault;
        if (fpMix && i % 10 == 0) fp = kFpList[1 + (i / 10) % (sizeof(kFpList) / sizeof(kFpList[0]) - 1)];
        ExerciseWorld(w, fp, tot, name);
        if (i % 5 == 0) DirectUnitTest(w, tot);
        if (i % 6 == 2) {   // a second query on the same module life: a stale cache must never leak between queries
            RunOut A2 = RunOne(w, R_ORIG, kFpDefault);
            RunOut B2 = RunOne(w, R_HOOK, kFpDefault);
            if (B2.stopRes != 0xFFFFFFFFu) { ModuleStop(); ModuleStart(g_capacity, g_minParallel); }
            ExpectEqual(A2, B2, F("%s second query", name));
            ++tot.twoQuery;
        }
    }
    const St d = st_sub(st_read(), s0);
    const u32 team = g_pool.st_team - team0, woken = g_pool.st_woken - woken0, mainc = g_pool.st_main_chunks - main0, wc = PoolWorkerChunks() - wc0;
    for (int i = 0; i < 16; ++i) tot.st[i] += d.w[i];
    tot.poolTeam += team;
    tot.poolWoken += woken;
    tot.poolMain += mainc;
    tot.poolWorker += wc;
    std::printf("%-22s worlds %3u | prep %u cand %u hits %u fallbacks %u changed %u unsupported %u capSkip %u | team %u workerChunks %u callerChunks %u | pool team %u worker %u main %u\n", name, count,
                d.w[5], d.w[6], d.w[7], d.w[8], d.w[9], d.w[10], d.w[11], d.w[12], d.w[13], d.w[14], team, wc, mainc);
}

// ------------------------------------------------------------------------------------------------ wrapper (opt-in smoke of the real 0x53C060 clone)
static void WrapperSmoke(u32 count, bool strict, Tot& tot) {
    for (u32 i = 0; i < count; ++i) {
        Knobs k = MakeKnobs(i * 3, 1);
        k.altKind = 1;
        k.mask = 8;
        k.action = ACT_NONE;
        k.nCb = 0;
        k.wrapper = true;
        k.pureOnly = (i % 2) != 0;
        k.longList = 0;
        World w = BuildWorld(arenaA, k);
        w.arena->snapshot();
        RunOut A = RunOne(w, R_WRAP_ORIG, kFpDefault);
        if (A.exc) {
            ++tot.wrapperGate;
            REQ(!strict, "original wrapper 0x53C060 faulted (code %08X): the wrapper fixture is insufficient (--strict-wrapper)", A.exc);
            continue;
        }
        RunOut B = RunOne(w, R_WRAP_CLONE, kFpDefault);
        ExpectEqual(A, B, F("wrapper clone world %u", i));
        ++tot.wrapperRuns;
        if (!A.out.empty()) ++tot.wrapperHits;
        (void)B;
    }
}

// ------------------------------------------------------------------------------------------------ main scenarios
int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::string image, cacheDll, clonesPath, kitPath, poolDll = "native_worker_dispatch.dll";
    u32 worlds = 240, seed = 6392, workers = 3, wrapperOn = 1, strictWrapper = 0;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string a = argv[i], v = argv[i + 1];
        if (a == "--image") image = v;
        else if (a == "--cache-dll") cacheDll = v;
        else if (a == "--clones") clonesPath = v;
        else if (a == "--worker-kit") kitPath = v;
        else if (a == "--pool-dll") poolDll = v;
        else if (a == "--worlds") worlds = static_cast<u32>(std::atoi(v.c_str()));
        else if (a == "--seed") seed = static_cast<u32>(std::atoi(v.c_str()));
        else if (a == "--workers") workers = static_cast<u32>(std::atoi(v.c_str()));
        else if (a == "--wrapper") wrapperOn = static_cast<u32>(std::atoi(v.c_str()));
        else if (a == "--strict-wrapper") strictWrapper = static_cast<u32>(std::atoi(v.c_str()));
        else { std::printf("unknown option %s\n", a.c_str()); return 2; }
    }
    if (image.empty() || cacheDll.empty() || clonesPath.empty() || kitPath.empty()) {
        std::printf("usage: harness --image Napoleon.exe --cache-dll native_ballistics_query_cache.dll --clones native-ballistics-query-clones.bin "
                    "--worker-kit native-ballistics-collision-worker-kit.bin [--pool-dll native_worker_dispatch.dll] [--worlds N] [--seed S] [--workers W] [--wrapper 0|1] [--strict-wrapper 0|1]\n");
        return 2;
    }
    rng.seed(seed);

    // ---- approved image, private mapping, native glue ---------------------------------------------------------------------------
    std::vector<u8> file, clonesBlob;
    REQ(ReadAll(image, file), "read image %s", image.c_str());
    REQ(Sha256(file.data(), file.size()) == kImageSha, "image is not the approved Napoleon.exe (SHA-256 mismatch)");
    REQ(MapImage(file), "private image mapping");
    InitStatics();
    std::printf("image mapped at %p (delta %08X), sha256 verified, pid %lu\n", static_cast<void*>(g_imageBase), g_delta, GetCurrentProcessId());
    REQ((g_delta & 0xFFFF) == 0, "image delta must be 64 KB aligned");

    // ---- module DLL, kit, dispatcher team ---------------------------------------------------------------------------------------
    HMODULE dll = LoadLibraryA(cacheDll.c_str());
    REQ(dll != nullptr, "LoadLibrary %s (error %lu)", cacheDll.c_str(), GetLastError());
    g_nqcInit = reinterpret_cast<NqcInitFn>(GetProcAddress(dll, "nqc_initialize"));
    g_nqcStop = reinterpret_cast<NqcStopFn>(GetProcAddress(dll, "nqc_stop"));
    g_hookQuery = reinterpret_cast<HookQueryFn>(GetProcAddress(dll, "nqc_query_hook"));
    g_hookUnit = reinterpret_cast<UnitFn>(GetProcAddress(dll, "nqc_unit_hook"));
    g_hookGather = PtrU(reinterpret_cast<const void*>(GetProcAddress(dll, "nqc_gather_hook")));
    g_state = reinterpret_cast<volatile u32*>(GetProcAddress(dll, "nqc_state"));
    REQ(g_nqcInit && g_nqcStop && g_hookQuery && g_hookUnit && g_hookGather && g_state, "module exports");
    REQ(g_state[0] == NQC_ABI && g_state[1] == NQC_STATE_BYTES, "nqc_state header");
    g_workerKit = LoadWorkerKit(kitPath);
    g_poolCode = LoadPool(poolDll);
    {
        ntw_pool_config cfg{};
        cfg.abi = NTW_POOL_ABI;
        cfg.workers = workers;
        cfg.api.create_event = PtrU(reinterpret_cast<const void*>(&CreateEventW));
        cfg.api.close_handle = PtrU(reinterpret_cast<const void*>(&CloseHandle));
        cfg.api.set_event = PtrU(reinterpret_cast<const void*>(&SetEvent));
        cfg.api.wait_single = PtrU(reinterpret_cast<const void*>(&WaitForSingleObject));
        cfg.api.create_thread = PtrU(reinterpret_cast<const void*>(&create_worker));
        cfg.api.worker_entry = PtrU(g_poolCode.worker);
        REQ(g_poolCode.init(&g_pool, &cfg) == NTW_POOL_OK, "persistent worker init");
    }
    REQ(ReadAll(clonesPath, clonesBlob), "read clone blob %s", clonesPath.c_str());
    {
        const u32 hooks[4] = {0, g_hookGather, PtrU(reinterpret_cast<const void*>(g_hookUnit)), PtrU(reinterpret_cast<const void*>(g_hookQuery))};
        LoadClones(clonesBlob, hooks);
    }
    std::printf("clones: query clone %08X (%u B + private table), wrapper clone %08X, area %p/%u B; source guards passed (30 abs, rel calls, 3 hooks, table)\n", g_clones.query,
                g_clones.c[0].size, g_clones.wrapper, static_cast<void*>(g_clones.area), g_clones.bytes);
    InitGetters();

    Tot tot;
    // ---- configuration gates ---------------------------------------------------------------------------------------------------------
    {
        struct Bad { const char* what; nqc_config c; };
        std::vector<Bad> bad;
        auto add = [&](const char* what, nqc_config c) { bad.push_back(Bad{what, c}); };
        nqc_config c = MakeCfg(64, 1); c.abi = NQC_ABI + 1; add("abi", c);
        c = MakeCfg(64, 1); c.size = 60; add("size", c);
        c = MakeCfg(0, 1); add("capacity 0", c);
        c = MakeCfg(NQC_MAX_CAPACITY + 1, 1); add("capacity max+1", c);
        c = MakeCfg(64, 0); add("minParallel 0", c);
        c = MakeCfg(64, 1); c.queryClone = 0; add("queryClone null", c);
        c = MakeCfg(64, 1); c.queryClone = g_clones.query + 3; add("queryClone misaligned into the code", c);
        c = MakeCfg(64, 1); c.pool = 0; add("pool null", c);
        c = MakeCfg(64, 1); c.dispatch = 0; add("dispatch null", c);
        c = MakeCfg(64, 1); c.kUnitHit = 0; add("kernel null", c);
        c = MakeCfg(64, 1); c.kUnitHit = g_workerKit.plane; add("kernel mismatch", c);
        c = MakeCfg(64, 1); c.imageDelta += 0x10000; add("imageDelta wrong", c);
        for (Bad& b : bad) {
            const u32 e = g_nqcInit(&b.c);
            REQ(e != 0, "nqc_initialize accepted a bad configuration: %s", b.what);
            REQ(g_state[NQC_S_ENABLED] == 0, "bad configuration (%s) left the module enabled", b.what);
        }
        REQ(g_nqcInit(nullptr) != 0, "nqc_initialize(NULL)");
        std::printf("configuration gates: %zu rejected configurations + NULL, module stays disabled\n", bad.size());
    }

    // ---- phase 1: large capacity, every non-empty batch may use the persistent team ----------------------------------------------------
    ModuleStart(4096, 1);
    std::printf("module started: imageDelta %08X, storage %u B\n", g_delta, g_state[NQC_S_STORAGE_BYTES]);
    RunWorlds("phase1 team", worlds, 0, tot, true);
    REQ(tot.st[NQC_S_CACHE_HITS] > 50, "cache never served 0x809620 (%u)", tot.st[NQC_S_CACHE_HITS]);
    REQ(tot.st[NQC_S_WORKER_CHUNKS] > 0 && tot.poolWorker > 0 && tot.poolTeam > 0 && tot.poolWoken > 0, "persistent workers never took chunks (module %u pool %u team %u)",
        tot.st[NQC_S_WORKER_CHUNKS], tot.poolWorker, tot.poolTeam);
    REQ(tot.st[NQC_S_WORKER_CHUNKS] == tot.poolWorker && tot.st[NQC_S_TEAM_DISPATCHES] == tot.poolTeam,
        "module counters (workers %u team %u) do not equal the pool slot deltas (workers %u team %u)", tot.st[NQC_S_WORKER_CHUNKS], tot.st[NQC_S_TEAM_DISPATCHES], tot.poolWorker, tot.poolTeam);
    REQ(tot.st[NQC_S_CALLER_CHUNKS] >= tot.poolMain, "caller chunks %u < pool main chunks %u", tot.st[NQC_S_CALLER_CHUNKS], tot.poolMain);

    // ---- phase 2: below minParallel nobody is woken --------------------------------------------------------------------------------------
    {
        ModuleStop();
        ModuleStart(4096, 0x40000000u);
        Tot t2;
        RunWorlds("phase2 inline", std::max<u32>(worlds / 4, 20), 3, t2, false);
        REQ(t2.poolTeam == 0 && t2.poolWoken == 0 && t2.st[NQC_S_TEAM_DISPATCHES] == 0, "workers woken below minParallel (pool team %u woken %u)", t2.poolTeam, t2.poolWoken);
        REQ(t2.st[NQC_S_CACHE_HITS] > 0, "inline mode never served the cache");
        Merge(tot, t2);
    }
    // ---- phase 3: tiny capacity: further candidates stay native ----------------------------------------------------------------------------
    {
        ModuleStop();
        ModuleStart(5, 1);
        Tot t3;
        RunWorlds("phase3 capacity 5", std::max<u32>(worlds / 4, 20), 7, t3, false);
        REQ(t3.st[NQC_S_CAPACITY_SKIPPED] > 0, "capacity bound never hit");
        REQ(t3.st[NQC_S_CACHE_HITS] > 0, "capacity-limited queries never served the cache");
        Merge(tot, t3);
        ModuleStop();
        ModuleStart(1, 1);
        Tot t4;
        RunWorlds("phase4 capacity 1", std::max<u32>(worlds / 8, 10), 11, t4, false);
        REQ(t4.st[NQC_S_CAPACITY_SKIPPED] > 0, "capacity-1 bound never hit");
        Merge(tot, t4);
        ModuleStop();
        ModuleStart(4096, 1);
    }
    // ---- mutation top-up: every mutation class must have forced a consume-time refusal at least once ----------------------------------------------
    {
        static const u32 need[] = {ACT_X, ACT_R, ACT_RAY, ACT_VTBL, ACT_LEAF, ACT_SEL, ACT_CW, ACT_MXCSR};
        for (u32 a : need) {
            for (u32 tries = 0; tries < 400 && tot.changedBy[a] == 0; ++tries) {
                Knobs k = MakeKnobs(tries * 20 + 1, 0);   // altKind 1
                k.action = a;
                k.nCb = 4;
                k.hitPct = 80;
                k.altKind = 1;
                k.mask = 8 | 0x1000;
                k.nUnits = 60;
                World w = BuildWorld(arenaA, k);
                ExerciseWorld(w, kFpDefault, tot, "mutation top-up");
            }
            REQ(tot.changedBy[a] > 0, "mutation class '%s' never produced a consume-time refusal (worlds %u)", kActName[a], tot.actWorlds[a]);
        }
    }
    // ---- fixed scenarios ---------------------------------------------------------------------------------------------------------------------------------
    ScopeConflictTest(tot);
    {
        // wrong model identity -> ORIGINAL query, no preparation
        for (int c = 0; c < 2; ++c) {
            Knobs k = MakeKnobs(2, 0);
            k.altKind = 1;
            k.nUnits = 40;
            k.action = ACT_NONE;
            World w = BuildWorld(arenaA, k);
            w.arena->snapshot();
            RunOut A = RunOne(w, R_ORIG, kFpDefault), B = RunOne(w, R_HOOK, kFpDefault, c ? CTX_BADROOT : CTX_BADGRID);
            ExpectEqual(A, B, c ? "wrong root" : "wrong grid");
            REQ(B.delta.w[NQC_S_CACHE_HITS] == 0 && B.delta.w[NQC_S_PREPARATIONS] == 0 && B.delta.w[NQC_S_FALLBACKS] >= 1, "wrong context used the cache (%s)", c ? "root" : "grid");
            ++tot.wrongCtx;
        }
        // the clone without a scope (nobody claimed one): gather/unit hooks degrade to the originals
        for (int i = 0; i < 4; ++i) {
            Knobs k = MakeKnobs(30 + i, 0);
            k.altKind = 1;
            k.action = i == 3 ? ACT_X : ACT_NONE;
            k.nCb = i == 3 ? 3 : 0;
            World w = BuildWorld(arenaA, k);
            w.arena->snapshot();
            RunOut A = RunOne(w, R_ORIG, kFpDefault), C = RunOne(w, R_CLONE, kFpDefault);
            ExpectEqual(A, C, "clone called without a scope");
            REQ(C.delta.w[NQC_S_CACHE_HITS] == 0 && C.delta.w[NQC_S_PREPARATIONS] == 0, "unscoped clone cached (hits %u prep %u)", C.delta.w[NQC_S_CACHE_HITS], C.delta.w[NQC_S_PREPARATIONS]);
            ++tot.directClones;
        }
        // stopped module: hooks pass through
        ModuleStop();
        Knobs k = MakeKnobs(3, 0);
        k.altKind = 1;
        World w = BuildWorld(arenaA, k);
        w.arena->snapshot();
        RunOut A = RunOne(w, R_ORIG, kFpDefault), B = RunOne(w, R_HOOK, kFpDefault);
        ExpectEqual(A, B, "stopped module");
        REQ(B.delta.w[NQC_S_CACHE_HITS] == 0 && B.delta.w[NQC_S_PREPARATIONS] == 0, "stopped module cached");
        ++tot.disabled;
        // an unsupported-shape restart is allowed (same imageDelta), then continue
        ModuleStart(4096, 1);
    }
    if (wrapperOn) {
        WrapperSmoke(std::max<u32>(worlds / 6, 24), strictWrapper != 0, tot);
        std::printf("wrapper 0x53C060 clone (mask 8): runs %u with results %u, fixture gate declined %u\n", tot.wrapperRuns, tot.wrapperHits, tot.wrapperGate);
        if (strictWrapper) REQ(tot.wrapperRuns > 0 && tot.wrapperHits > 0, "wrapper produced no results");
    }

    // ---- final coverage / evidence ---------------------------------------------------------------------------------------------------------------------------
    std::printf("worlds %u: hit-worlds %u miss-worlds %u results %u faults %u | stop-first-cell %u non-stop %u | alt NULL %u alt-type!=2 %u caller-visited %u long-lists %u |"
                " fp non-nearest %u fp other %u | stop-in-scope %u two-query %u direct-unit-calls %u direct-clone %u wrong-ctx %u disabled %u\n",
                tot.worlds, tot.hitWorlds, tot.missWorlds, tot.results, tot.faults, tot.stopWorlds, tot.nonStopWorlds, tot.altNull, tot.altOther, tot.callerVisited, tot.longLists,
                tot.fpNonNearest, tot.fpOther, tot.stopInScope, tot.twoQuery, tot.directUnits, tot.directClones, tot.wrongCtx, tot.disabled);
    std::printf("module counters (phase 1): candidates %u cache-hits %u fallbacks %u changed %u unsupported %u | pool: team %u woken %u worker-chunks %u main-chunks %u\n",
                tot.st[NQC_S_CANDIDATES], tot.st[NQC_S_CACHE_HITS], tot.st[NQC_S_FALLBACKS], tot.st[NQC_S_CHANGED], tot.st[NQC_S_UNSUPPORTED], tot.poolTeam, tot.poolWoken, tot.poolWorker,
                tot.poolMain);
    for (u32 a = ACT_X; a <= ACT_MXCSR; ++a) std::printf("  mutation %-12s worlds %3u refusals %3u\n", kActName[a], tot.actWorlds[a], tot.changedBy[a]);
    REQ(tot.hitWorlds > tot.worlds / 5 && tot.missWorlds > 2, "coverage: hit-worlds %u miss-worlds %u of %u", tot.hitWorlds, tot.missWorlds, tot.worlds);
    REQ(tot.stopWorlds > 5 && tot.nonStopWorlds > 5 && tot.altNull > 3 && tot.altOther > 3 && tot.callerVisited > 3 && tot.longLists > 1, "coverage: shapes");
    REQ(tot.fpNonNearest > 2 && tot.fpOther > 1, "coverage: fp matrix");
    REQ(tot.faults > 0 && tot.stopInScope > 0, "coverage: fault %u / stop-in-scope %u worlds", tot.faults, tot.stopInScope);
    REQ(tot.st[NQC_S_UNSUPPORTED] > 0 && tot.st[NQC_S_CHANGED] > 0 && tot.st[NQC_S_FALLBACKS] > 0, "coverage: module counters");
    ModuleStop();
    REQ(g_poolCode.shutdown(&g_pool) == NTW_POOL_OK, "persistent worker shutdown");
    std::printf("PASS: ORIGINAL 0x6392C0 == hooked private clone (real native gather/predicates/visited/appends, original unit hit or exact cached value) on every case; "
                "persistent workers took %u chunks.\n", tot.poolWorker);
    return 0;
}
