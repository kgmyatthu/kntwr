// Differential oracle for native_animation_render_batch.cpp.  It executes the ORIGINAL 0x11FF470 / 0x11FF750 (and
// everything they call: 0x10DF440, 0x10DEAC0, 0x10F4860, 0x1221480 ...) from the user's installed image, read into a
// private PE-relocated mapping inside THIS test process, and compares bit-for-bit with the batch adapter
// (prepare / persistent-dispatcher compute / ordered publish).  Nothing touches the running game, the installed EXE,
// or any debugger/injection API.  Patches exist only in the private copy:
//   0xFF7F20 (TLS heap alloc)  -> owned heap region bump allocator, logged, poisoned 0xCD
//   0xFF7EF0 (heap free)       -> no-op (so every retired vector buffer stays comparable)
//   0x10E9DC0 (arena alloc)    -> owned arena region bump allocator, logged, poisoned 0xCD
// The two regions are separate so that the arena layout depends only on the arena allocation sequence.
//
// Checks per scenario (deterministic mt19937 fixtures, both quaternion decode branches, partial/looping clips,
// 1..64 bones, vector growth, denormal inputs, MXCSR 0x1F80/FTZ+DAZ x x87 CW 0x27F/0x37F/0x7F, 1..64-entry windows,
// persistent 4-worker pool vs inline vs serial threshold):
//   * EXACT mode (no fallback entries): arena region (all L objects, pos/quat arrays after the group 3 transform,
//     output objects, matrices, accessors), heap region (all vector buffers), allocation logs, and the 0x18-byte
//     vector headers are byte-identical to the original run at identical addresses.
//   * CANONICAL mode (getters return null for some entries -> the port must hand those to the original builder):
//     every published record (flag, extra, object flag/count, matrices, accessors with relocated matrix pointers) equal.
//   * Stats (native / fallback / skipped / published) equal the values predicted from the fixtures; MXCSR and the x87
//     control word of the calling thread are unchanged by run().
//
//   native_animation_render_batch_oracle.exe <path-to-Napoleon.exe> [trials] [seed]
// Exit 0 only if every comparison matches.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#include <xmmintrin.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include "native_animation_render_batch.h"
#include "native_image_relocation.h"
#include "native_worker_dispatch.h"

#ifndef _M_IX86
#error x86 only
#endif

extern "C" {
ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg);
ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool);
ntw_u32 __stdcall ntw_pool_worker_start(void* slot);
void __stdcall ntw_pool_dispatch(ntw_u32 user, ntw_u32 body, ntw_u32 chunks, void* ctx);
}

// ---- original VAs (preferred base 0x400000) --------------------------------------------------------------
static const uintptr_t VA_G3 = 0x11FF470;       // thiscall ret 0x14
static const uintptr_t VA_G4 = 0x11FF750;       // thiscall ret 0x14
static const uintptr_t VA_APPEND = 0x1221480;   // thiscall ret 4
static const uintptr_t VA_ALLOC = 0xFF7F20;     // cdecl(size, tag) -> ptr
static const uintptr_t VA_FREE = 0xFF7EF0;      // cdecl(ptr)
static const uintptr_t VA_ARENA = 0x10E9DC0;    // thiscall(arena; size, align) ret 8
static const uintptr_t VA_ACOS = 0x128448C;     // xmm0 -> xmm0
static const uintptr_t VA_SSE2FN = 0x10D5510;   // al = [0x176CBF5] after lazy init
static const uintptr_t VA_ACC_VT = 0x1402998;   // accessor vtable (a relocated data pointer)
static const uintptr_t VA_FLAG_INIT = 0x176CBF4;
static const uintptr_t VA_FLAG_SSE2 = 0x176CBF5;
static uintptr_t g_image_delta;
static uintptr_t native_address(uintptr_t preferred) { return preferred + g_image_delta; }

template <class T> static T rdp(const void* p, size_t off) { T v; std::memcpy(&v, (const uint8_t*)p + off, sizeof(T)); return v; }
template <class T> static void wrp(void* p, size_t off, T v) { std::memcpy((uint8_t*)p + off, &v, sizeof(T)); }
static inline uint32_t bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static inline float bit_cast_f(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }

// ---- owned allocators (patched into the private image) ------------------------------------------------------
struct AllocRec { size_t off, size, align; bool operator==(const AllocRec& o) const { return off == o.off && size == o.size && align == o.align; } };
static uint8_t* g_arenaPool; static size_t g_arenaOff, g_arenaSize = 48u << 20;
static uint8_t* g_heapPool;  static size_t g_heapOff, g_heapSize = 48u << 20;
static std::vector<AllocRec> g_arenaLog, g_heapLog;

static void* bump(uint8_t* pool, size_t& off, size_t cap, std::vector<AllocRec>& log, size_t size, size_t align) {
    const size_t a = align < 16 ? 16 : align;
    const size_t o = (off + a - 1) & ~(a - 1);
    if (o > cap || size > cap - o) { std::fputs("pool exhausted\n", stderr); std::exit(3); }
    off = o + size;
    log.push_back({o, size, align});
    std::memset(pool + o, 0xCD, size);  // poison: any unwritten byte is visible in the exact compare
    return pool + o;
}
static void* __cdecl heap_alloc(size_t size, void*) { return bump(g_heapPool, g_heapOff, g_heapSize, g_heapLog, size, 16); }
static void __cdecl heap_free(void*) {}
static void* __cdecl arena_helper(void*, size_t size, size_t align) { return bump(g_arenaPool, g_arenaOff, g_arenaSize, g_arenaLog, size, align); }
__declspec(naked) static void arena_stub() {
    __asm {
        mov eax, [esp + 4]
        mov edx, [esp + 8]
        push edx
        push eax
        push ecx
        call arena_helper
        add esp, 12
        ret 8
    }
}
static uintptr_t g_acosVa;
__declspec(naked) static float __cdecl orig_acos(float) {
    __asm {
        movss xmm0, dword ptr[esp + 4]
        call dword ptr[g_acosVa]
        sub esp, 4
        movss dword ptr[esp], xmm0
        fld dword ptr[esp]
        add esp, 4
        ret
    }
}
static void patch_jmp(uintptr_t at, void* target) {
    uint8_t* p = (uint8_t*)at;
    p[0] = 0xE9;
    int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target) - (at + 5));
    std::memcpy(p + 1, &rel, 4);
}

static bool map_image(const char* path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { std::fprintf(stderr, "open failed %lu\n", GetLastError()); return false; }
    const DWORD sz = GetFileSize(f, nullptr);
    auto read_range = [f, sz](DWORD offset, void* output, DWORD bytes) {
        if (offset > sz || bytes > sz - offset) return false;
        LARGE_INTEGER position{};
        position.QuadPart = offset;
        DWORD got = 0;
        return SetFilePointerEx(f, position, nullptr, FILE_BEGIN) && ReadFile(f, output, bytes, &got, nullptr) && got == bytes;
    };
    alignas(4) uint8_t header[4096];
    if (!read_range(0, header, sizeof(header))) { CloseHandle(f); return false; }
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(header);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<size_t>(dos->e_lfanew) > sizeof(header) - sizeof(IMAGE_NT_HEADERS32)) { CloseHandle(f); return false; }
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(header + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != 0x14c) { CloseHandle(f); return false; }
    const uintptr_t base = nt->OptionalHeader.ImageBase;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto m = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!m) { std::fprintf(stderr, "cannot map native image (err %lu)\n", GetLastError()); CloseHandle(f); return false; }
    if (nt->OptionalHeader.SizeOfHeaders > size || !read_range(0, m, nt->OptionalHeader.SizeOfHeaders)) {
        CloseHandle(f); VirtualFree(m, 0, MEM_RELEASE); return false;
    }
    auto loaded_nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(m + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(loaded_nt);
    for (unsigned i = 0; i < loaded_nt->FileHeader.NumberOfSections; ++i) {
        const DWORD n = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (sec[i].VirtualAddress > size || n > size - sec[i].VirtualAddress ||
            !read_range(sec[i].PointerToRawData, m + sec[i].VirtualAddress, n)) { CloseHandle(f); VirtualFree(m, 0, MEM_RELEASE); return false; }
    }
    CloseHandle(f);
    g_image_delta = reinterpret_cast<uintptr_t>(m) - base;
    if (!RelocateNativeImage(m, size, loaded_nt, g_image_delta)) { VirtualFree(m, 0, MEM_RELEASE); return false; }
    g_acosVa = native_address(VA_ACOS);
    return true;
}

// ---- synthetic native-layout animation data (same raw layout the pose-kernel oracle proved) ------------------------------
struct World {
    std::vector<uint8_t> skel, table, ref, holder, clip, framesArr;
    std::vector<std::vector<uint8_t>> frames, framePos, frameQuat;
    std::vector<uint8_t> refPos;
    uint32_t n = 0, nframes = 0;
};
static int16_t enc(float v) { long l = std::lrint(v * 32767.0f); if (l > 32767) l = 32767; if (l < -32767) l = -32767; return (int16_t)l; }

static void make_quat(std::mt19937& rng, const float* ref, float* q, int style) {
    std::uniform_real_distribution<float> u(-1, 1);
    float v[4];
    if (style == 0 || !ref) { for (float& c : v) c = u(rng); }
    else {
        float noise = style == 1 ? 0.01f : style == 2 ? 0.3f : 1.0f;
        for (int i = 0; i < 4; ++i) v[i] = ref[i] + noise * u(rng);
        if (style == 3) for (float& c : v) c = -c;
    }
    float l = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2] + v[3] * v[3]);
    if (l < 1e-6f) { v[0] = 0; v[1] = 0; v[2] = 0; v[3] = 1; l = 1; }
    for (int i = 0; i < 4; ++i) q[i] = v[i] / l;
}

static void build_world(World& w, std::mt19937& rng, uint32_t n, uint32_t nframes, bool loop, bool partial, bool sse2) {
    w.n = n; w.nframes = nframes;
    w.skel.assign(0x20, 0); w.table.assign(n * 0x14 + 0x20, 0);
    wrp<uint32_t>(w.skel.data(), 8, n);
    wrp<uintptr_t>(w.skel.data(), 0xC, (uintptr_t)w.table.data());
    for (uint32_t i = 0; i < n; ++i) {
        int32_t parent = -1;
        if (i > 0 && (rng() % 10) != 0) parent = (int32_t)(rng() % i);  // parents precede children
        wrp<int32_t>(w.table.data(), 0x10 + i * 0x14, parent);
    }
    std::uniform_real_distribution<float> up(-5, 5);
    w.refPos.assign(n * 12 + 16, 0);
    for (uint32_t i = 0; i < n * 3; ++i) wrp<float>(w.refPos.data(), i * 4, up(rng));
    w.ref.assign(0x60, 0);
    wrp<uintptr_t>(w.ref.data(), 0x0, (uintptr_t)w.skel.data());
    wrp<uint32_t>(w.ref.data(), 0x30, n);
    wrp<uintptr_t>(w.ref.data(), 0x34, (uintptr_t)w.refPos.data());
    w.holder.assign(0x60, 0);
    wrp<uintptr_t>(w.holder.data(), 0x44, (uintptr_t)w.ref.data());
    w.frames.assign(nframes, {}); w.framePos.assign(nframes, {}); w.frameQuat.assign(nframes, {});
    std::vector<float> prevQ(n * 4, 0.f);
    for (uint32_t f = 0; f < nframes; ++f) {
        w.framePos[f].assign(n * 12 + 16, 0);
        w.frameQuat[f].assign(n * 8 + 16, 0);
        for (uint32_t i = 0; i < n * 3; ++i) wrp<float>(w.framePos[f].data(), i * 4, up(rng));
        for (uint32_t i = 0; i < n; ++i) {
            float q[4];
            int style = f == 0 ? 0 : (int)(rng() % 4);
            make_quat(rng, f == 0 ? nullptr : &prevQ[i * 4], q, style);
            for (int k = 0; k < 4; ++k) prevQ[i * 4 + k] = q[k];
            for (int k = 0; k < 4; ++k) {
                if (sse2) wrp<int16_t>(w.frameQuat[f].data(), i * 8 + k * 2, enc(q[k]));
                else wrp<uint16_t>(w.frameQuat[f].data(), i * 8 + k * 2, (uint16_t)std::lrint((q[k] + 1.0f) * 32767.0f));
            }
        }
        w.frames[f].assign(0x60, 0);
        uint8_t* fr = w.frames[f].data();
        wrp<uintptr_t>(fr, 0x0, (uintptr_t)w.skel.data());
        for (int k = 0; k < 3; ++k) wrp<float>(fr, 0xC + 4 * k, up(rng));
        uint32_t lim = partial ? (uint32_t)(rng() % (n + 1)) : n;
        wrp<uint32_t>(fr, 0x30, lim);
        wrp<uintptr_t>(fr, 0x34, (uintptr_t)w.framePos[f].data());
        wrp<uintptr_t>(fr, 0x44, (uintptr_t)w.frameQuat[f].data());
    }
    w.framesArr.assign(nframes * 4 + 16, 0);
    for (uint32_t f = 0; f < nframes; ++f) wrp<uintptr_t>(w.framesArr.data(), f * 4, (uintptr_t)w.frames[f].data());
    w.clip.assign(0xA0, 0);
    uint8_t* c = w.clip.data();
    wrp<uintptr_t>(c, 0x4, (uintptr_t)w.holder.data());
    wrp<uint8_t>(c, 0x30, partial ? 1 : 0);
    wrp<uint32_t>(c, 0x44, loop ? 2u : 0u);
    std::uniform_real_distribution<float> ufps(5, 40);
    wrp<float>(c, 0x48, ufps(rng));
    wrp<uint32_t>(c, 0x88, nframes);
    wrp<uintptr_t>(c, 0x8C, (uintptr_t)w.framesArr.data());
    wrp<float>(c, 0x4C, (float)(nframes - 1) / rdp<float>(c, 0x48));
}

// ---- fake render object ------------------------------------------------------------------------------------------------------
struct Holder { uintptr_t vtbl; uint32_t id; uint32_t world; };
struct ArenaObj { uintptr_t vtbl; };
static uintptr_t g_holderVt[32];
static uintptr_t g_arenaVt[8];
static std::vector<std::unique_ptr<World>> g_worlds;
static std::vector<uint8_t> g_nullMask;  // by holder id: bit0 = first arena getter null, bit1 = second
static uint32_t g_cur, g_calls;
static uint8_t g_tokenByte;
static uint64_t g_holderCalls, g_arenaCalls;
static void* __fastcall holder_getter(void* self) {
    const Holder* h = static_cast<const Holder*>(self);
    g_cur = h->id; g_calls = 0; ++g_holderCalls;
    return g_worlds[h->world]->clip.data();
}
static void* __fastcall arena_getter(void*) {
    const uint32_t c = g_calls++;
    ++g_arenaCalls;
    return ((g_nullMask[g_cur] >> c) & 1u) ? nullptr : static_cast<void*>(&g_tokenByte);
}

static const uint32_t E3 = 0x90, E4 = 0x60, VECSZ = 0x18;
struct Fixture {
    uint32_t nvec3 = 0, nvec4 = 0, c3 = 0, c4 = 0;
    std::vector<Holder> h3, h4;
    std::vector<uint8_t> v3, v4, e3, e4;
    std::vector<uint8_t> R;
    ArenaObj arenaObj{};
};

static void bind_render(Fixture& fx) {
    fx.R.assign(0x200, 0xAB);
    fx.arenaObj.vtbl = (uintptr_t)g_arenaVt;
    uint8_t* R = fx.R.data();
    wrp<uintptr_t>(R, 0x50, (uintptr_t)&fx.arenaObj);
    wrp<uint32_t>(R, 0x8C, fx.c3); wrp<uintptr_t>(R, 0x90, (uintptr_t)fx.e3.data());
    wrp<uint32_t>(R, 0x9C, fx.c4); wrp<uintptr_t>(R, 0xA0, (uintptr_t)fx.e4.data());
    wrp<uintptr_t>(R, 0x100, (uintptr_t)fx.v3.data());
    wrp<uintptr_t>(R, 0x110, (uintptr_t)fx.v4.data());
}
static void reset_vectors(Fixture& fx) {
    for (uint32_t i = 0; i < fx.nvec3; ++i) { uint8_t* v = fx.v3.data() + i * VECSZ; std::memset(v, 0, 0x10); wrp<uintptr_t>(v, 0x10, (uintptr_t)&fx.h3[i]); }
    for (uint32_t i = 0; i < fx.nvec4; ++i) { uint8_t* v = fx.v4.data() + i * VECSZ; std::memset(v, 0, 0x10); wrp<uintptr_t>(v, 0x10, (uintptr_t)&fx.h4[i]); }
}
static void reset_pools() {
    std::memset(g_arenaPool, 0, g_arenaOff); g_arenaOff = 0; g_arenaLog.clear();
    std::memset(g_heapPool, 0, g_heapOff); g_heapOff = 0; g_heapLog.clear();
}

// ---- running the original / the port ---------------------------------------------------------------------------------------
typedef ntw_render::OrigBuilderFn OrigFn;
static bool run_original_seh(OrigFn o3, OrigFn o4, uint8_t* R, uint32_t mask, uint8_t* e3, uint32_t c3, uint8_t* e4, uint32_t c4) {
    __try {
        if (mask & 1u) for (uint32_t i = 0; i < c3; ++i) {
            uint8_t* e = e3 + (size_t)i * E3;
            o3(R, nullptr, rdp<int32_t>(e, 0), (const float*)(e + 4), (const float*)(e + 0x44), rdp<float>(e, 0x84), e + 0x88);
        }
        if (mask & 2u) for (uint32_t i = 0; i < c4; ++i) {
            uint8_t* e = e4 + (size_t)i * E4;
            o4(R, nullptr, rdp<int32_t>(e, 0), (const float*)(e + 4), (const float*)(e + 0x44), rdp<float>(e, 0x54), e + 0x58);
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
static bool run_port_seh(const ntw_render::Binding& b, const ntw_render::Workspace& ws, uint8_t* R, uint32_t mask, ntw_render::Stats* st, bool* ok) {
    __try {
        *ok = ntw_render::run(b, ws, R, mask, st);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static uint16_t get_cw() { uint16_t w = 0; __asm { fnstcw w } return w; }
static void set_cw(uint16_t w) { __asm { fldcw w } }

// ---- snapshots / comparisons -------------------------------------------------------------------------------------------------
struct Snap {
    std::vector<uint8_t> arena, heap, v3, v4;
    std::vector<AllocRec> alog, hlog;
};
static Snap take_snap(const Fixture& fx) {
    Snap s;
    s.arena.assign(g_arenaPool, g_arenaPool + g_arenaOff);
    s.heap.assign(g_heapPool, g_heapPool + g_heapOff);
    s.v3 = fx.v3; s.v4 = fx.v4;
    s.alog = g_arenaLog; s.hlog = g_heapLog;
    return s;
}

static void canon_object(std::vector<uint8_t>& out, const uint8_t* obj) {
    const uint32_t n = rdp<uint32_t>(obj, 4);
    const uint8_t* mats = (const uint8_t*)rdp<uintptr_t>(obj, 8);
    const uint8_t* acc = (const uint8_t*)rdp<uintptr_t>(obj, 0xC);
    out.push_back(obj[0]);
    out.insert(out.end(), (const uint8_t*)&n, (const uint8_t*)&n + 4);
    out.insert(out.end(), mats, mats + (size_t)n * 0x30);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t e[0x24];
        std::memcpy(e, acc + (size_t)i * 0x24, 0x24);
        const int32_t rel = (int32_t)(rdp<uintptr_t>(e, 8) - (uintptr_t)(mats + (size_t)i * 0x30));
        std::memset(e + 5, 0, 3);  // padding bytes of the accessor are never written
        wrp<int32_t>(e, 8, rel);
        out.insert(out.end(), e, e + 0x24);
    }
}
static std::vector<uint8_t> canon_vec(const uint8_t* v) {
    std::vector<uint8_t> out;
    const uint32_t cap = rdp<uint32_t>(v, 4), size = rdp<uint32_t>(v, 8);
    const uint8_t* data = (const uint8_t*)rdp<uintptr_t>(v, 0xC);
    out.insert(out.end(), (const uint8_t*)&cap, (const uint8_t*)&cap + 4);
    out.insert(out.end(), (const uint8_t*)&size, (const uint8_t*)&size + 4);
    for (uint32_t k = 0; k < size; ++k) {
        const uint8_t* rec = data + (size_t)k * 12;
        const uint32_t extra = rdp<uint32_t>(rec, 8);
        out.push_back(rec[4]);
        out.insert(out.end(), (const uint8_t*)&extra, (const uint8_t*)&extra + 4);
        canon_object(out, (const uint8_t*)rdp<uintptr_t>(rec, 0));
    }
    return out;
}
typedef std::vector<std::vector<uint8_t>> Canon;
static Canon canon_all(const Fixture& fx) {
    Canon c;
    for (uint32_t i = 0; i < fx.nvec3; ++i) c.push_back(canon_vec(fx.v3.data() + i * VECSZ));
    for (uint32_t i = 0; i < fx.nvec4; ++i) c.push_back(canon_vec(fx.v4.data() + i * VECSZ));
    return c;
}

struct Totals {
    uint64_t scenarios = 0, exact = 0, canonical = 0, entries = 0, native = 0, fallback = 0, skipped = 0, published = 0;
    uint64_t dispatches = 0, chunks = 0, bones = 0, windows = 0, bytesCompared = 0, portRuns = 0, bad = 0;
    uint64_t holderCalls = 0, arenaCalls = 0, rcMode = 0;
};

static void fail(Totals& T, uint32_t trial, const char* what) {
    ++T.bad;
    if (T.bad <= 12) std::printf("MISMATCH trial=%u %s\n", trial, what);
}
static size_t first_diff(const std::vector<uint8_t>& a, const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) return i;
    return (size_t)-1;
}

// ---- fixture generation -------------------------------------------------------------------------------------------------------
static void fill_matrix(std::mt19937& rng, float* m16, int kind) {
    std::uniform_real_distribution<float> u(-2.0f, 2.0f);
    for (int i = 0; i < 16; ++i) m16[i] = u(rng);
    if (kind == 1) {  // identity rows
        const float id[12] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0};
        std::memcpy(m16, id, sizeof(id));
    } else if (kind == 2) {  // denormals mixed in: FTZ/DAZ must be honoured by every worker
        for (int i = 0; i < 12; ++i) if (rng() % 3 == 0) m16[i] = bit_cast_f(1u + (uint32_t)(rng() % 0x7FFFFF));
    } else if (kind == 3) {  // zeros and negative zeros
        for (int i = 0; i < 12; ++i) { const uint32_t r = rng() % 4; if (r == 0) m16[i] = 0.0f; else if (r == 1) m16[i] = -0.0f; }
    } else if (kind == 4) {  // large but finite
        for (int i = 0; i < 12; ++i) m16[i] *= 1.0e7f;
    }
}

static void build_fixture(Fixture& fx, std::mt19937& rng, bool fallbackTrial, uint32_t mask) {
    fx.nvec3 = 1 + rng() % 5; fx.nvec4 = 1 + rng() % 5;
    fx.c3 = (rng() % 8 == 0) ? 0 : rng() % 40;
    fx.c4 = (rng() % 8 == 0) ? 0 : rng() % 40;
    if (!(mask & 1)) fx.c3 = (rng() & 1) ? fx.c3 : 0;  // unselected group data may still exist
    fx.h3.assign(fx.nvec3, {}); fx.h4.assign(fx.nvec4, {});
    g_nullMask.assign(2 * 8 + 8, 0);
    for (uint32_t i = 0; i < fx.nvec3; ++i) {
        fx.h3[i] = {(uintptr_t)g_holderVt, i, (uint32_t)(i % g_worlds.size())};
        if (fallbackTrial && rng() % 3 == 0) g_nullMask[i] = (uint8_t)(1 + rng() % 3);
    }
    for (uint32_t i = 0; i < fx.nvec4; ++i) {
        fx.h4[i] = {(uintptr_t)g_holderVt, 8 + i, (uint32_t)((i + 1) % g_worlds.size())};
        if (fallbackTrial && rng() % 3 == 0) g_nullMask[8 + i] = (uint8_t)(1 + rng() % 3);
    }
    fx.v3.assign(fx.nvec3 * VECSZ, 0); fx.v4.assign(fx.nvec4 * VECSZ, 0);
    fx.e3.assign((size_t)fx.c3 * E3, 0); fx.e4.assign((size_t)fx.c4 * E4, 0);
    std::uniform_real_distribution<float> u01(0, 1);
    auto pick_time = [&](float dur) -> float {
        switch (rng() % 6) {
        case 0: return 0.0f;
        case 1: return dur;
        case 2: return -0.0f;
        case 3: return dur * 1.5f * u01(rng);
        case 4: return -1.0f + (dur * 2.5f) * u01(rng);
        default: return dur * u01(rng);
        }
    };
    for (uint32_t i = 0; i < fx.c3; ++i) {
        uint8_t* e = fx.e3.data() + (size_t)i * E3;
        const uint32_t vi = rng() % fx.nvec3;
        wrp<int32_t>(e, 0, (int32_t)vi);
        fill_matrix(rng, (float*)(e + 4), (int)(rng() % 5));
        fill_matrix(rng, (float*)(e + 0x44), (int)(rng() % 5));
        const float dur = rdp<float>(g_worlds[fx.h3[vi].world]->clip.data(), 0x4C);
        wrp<float>(e, 0x84, pick_time(dur));
        wrp<uint8_t>(e, 0x88, (uint8_t)rng());
        wrp<uint32_t>(e, 0x8C, (uint32_t)rng());
    }
    for (uint32_t i = 0; i < fx.c4; ++i) {
        uint8_t* e = fx.e4.data() + (size_t)i * E4;
        const uint32_t vi = rng() % fx.nvec4;
        wrp<int32_t>(e, 0, (int32_t)vi);
        fill_matrix(rng, (float*)(e + 4), (int)(rng() % 5));
        std::uniform_real_distribution<float> u(-50.0f, 50.0f);
        float v[3] = {u(rng), u(rng), u(rng)};
        const uint32_t r = rng() % 8;
        if (r == 0) { v[0] = 0.0f; v[1] = -0.0f; v[2] = 1.0f; }       // equals the accessor default except w: still differs
        else if (r == 1) v[1] = bit_cast_f(0x7FC00000u);              // NaN is "different" for ucomiss
        std::memcpy(e + 0x44, v, sizeof(v));
        wrp<uint32_t>(e, 0x50, 0xDEADBEEFu);
        const float dur = rdp<float>(g_worlds[fx.h4[vi].world]->clip.data(), 0x4C);
        float t = pick_time(dur);
        if (rng() % 5 == 0) t = dur * 1.5f + 0.25f;  // beyond the duration guard
        wrp<float>(e, 0x54, t);
        wrp<uint8_t>(e, 0x58, (uint8_t)rng());
        wrp<uint32_t>(e, 0x5C, (uint32_t)rng());
    }
    bind_render(fx);
    reset_vectors(fx);
}

struct Expect { uint32_t entries = 0, native = 0, fallback = 0, skipped = 0; };
static Expect predict(const Fixture& fx, uint32_t mask) {
    Expect x;
    if (mask & 1) for (uint32_t i = 0; i < fx.c3; ++i) {
        const uint8_t* e = fx.e3.data() + (size_t)i * E3;
        ++x.entries;
        (g_nullMask[rdp<int32_t>(e, 0)] ? x.fallback : x.native)++;
    }
    if (mask & 2) for (uint32_t i = 0; i < fx.c4; ++i) {
        const uint8_t* e = fx.e4.data() + (size_t)i * E4;
        const uint32_t vi = (uint32_t)rdp<int32_t>(e, 0);
        const float dur = rdp<float>(g_worlds[fx.h4[vi].world]->clip.data(), 0x4C);
        ++x.entries;
        if (!(dur >= rdp<float>(e, 0x54))) { ++x.skipped; continue; }
        (g_nullMask[8 + vi] ? x.fallback : x.native)++;
    }
    return x;
}

// ---- persistent pool --------------------------------------------------------------------------------------------------------------
static ntw_pool* g_pool;
static bool pool_start(uint32_t workers) {
    g_pool = static_cast<ntw_pool*>(_aligned_malloc(NTW_POOL_BYTES, NTW_POOL_ALIGN));
    if (!g_pool) return false;
    std::memset(g_pool, 0, NTW_POOL_BYTES);
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    ntw_pool_config cfg{};
    cfg.abi = NTW_POOL_ABI; cfg.workers = workers; cfg.stack_bytes = 0;
    cfg.api.create_event = (ntw_u32)(uintptr_t)GetProcAddress(k, "CreateEventW");
    cfg.api.close_handle = (ntw_u32)(uintptr_t)GetProcAddress(k, "CloseHandle");
    cfg.api.set_event = (ntw_u32)(uintptr_t)GetProcAddress(k, "SetEvent");
    cfg.api.wait_single = (ntw_u32)(uintptr_t)GetProcAddress(k, "WaitForSingleObject");
    cfg.api.create_thread = (ntw_u32)(uintptr_t)GetProcAddress(k, "CreateThread");
    cfg.api.worker_entry = (ntw_u32)(uintptr_t)&ntw_pool_worker_start;
    const ntw_u32 r = ntw_pool_init(g_pool, &cfg);
    if (r != NTW_POOL_OK) { std::fprintf(stderr, "pool init failed %u\n", r); return false; }
    return true;
}

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (argc < 2) { std::fputs("usage: native_animation_render_batch_oracle <Napoleon.exe> [trials] [seed]\n", stderr); return 2; }
    const uint32_t trials = argc > 2 ? (uint32_t)std::atoi(argv[2]) : 1500;
    const uint32_t seed = argc > 3 ? (uint32_t)std::atoi(argv[3]) : 20260513;
    if (!map_image(argv[1])) return 2;
    g_arenaPool = (uint8_t*)VirtualAlloc(nullptr, g_arenaSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    g_heapPool = (uint8_t*)VirtualAlloc(nullptr, g_heapSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_arenaPool || !g_heapPool) return 2;
    patch_jmp(native_address(VA_ALLOC), (void*)&heap_alloc);
    patch_jmp(native_address(VA_FREE), (void*)&heap_free);
    patch_jmp(native_address(VA_ARENA), (void*)&arena_stub);
    *(uint8_t*)native_address(VA_FLAG_INIT) = 1;  // 0x10D5510 skips the CPUID initialiser and reads the flag byte
    if (!FlushInstructionCache(GetCurrentProcess(), nullptr, 0)) return 2;
    if (!pool_start(4)) return 2;
    g_holderVt[0x3C / 4] = (uintptr_t)&holder_getter;
    g_arenaVt[8 / 4] = (uintptr_t)&arena_getter;

    const OrigFn o3 = (OrigFn)native_address(VA_G3);
    const OrigFn o4 = (OrigFn)native_address(VA_G4);
    ntw_render::Binding bind{};
    bind.arena_alloc = (ntw_render::ArenaAllocFn)native_address(VA_ARENA);
    bind.append = (ntw_render::AppendFn)native_address(VA_APPEND);
    bind.orig_group3 = o3;
    bind.orig_group4 = o4;
    bind.sse2_decode_flag = (ntw_render::Sse2FlagFn)native_address(VA_SSE2FN);
    bind.acos_fn = orig_acos;
    bind.accessor_vtable = (uint32_t)native_address(VA_ACC_VT);
    bind.dispatch_user = g_pool;

    std::mt19937 rng(seed);
    Totals T;
    const uint32_t counts[] = {1, 2, 5, 17, 41, 64};
    const uint32_t caps[] = {1, 2, 5, 16, 64};
    const uint32_t minPar[] = {1, 64, 1000000};
    const uint32_t chunkB[] = {1, 8, 64, 0};
    const uint16_t cws[] = {0x27F, 0x37F, 0x7F};
    const uint32_t csrs[] = {0x1F80u, 0x9FC0u};
    const uint16_t defCw = get_cw();
    const uint32_t defCsr = _mm_getcsr();
    uint32_t sseCases = 0;

    for (uint32_t trial = 0; trial < trials; ++trial) {
        const bool sse2 = (trial & 1) != 0;
        *(uint8_t*)native_address(VA_FLAG_SSE2) = sse2 ? 1 : 0;
        sseCases += sse2;
        g_worlds.clear();
        for (int wi = 0; wi < 3; ++wi) {
            auto w = std::make_unique<World>();
            const uint32_t n = counts[rng() % 6];
            build_world(*w, rng, n, 2 + (rng() % 20), (rng() & 1) != 0, (rng() % 3) == 0, sse2);
            g_worlds.push_back(std::move(w));
        }
        const bool fallbackTrial = (trial % 4) == 3;
        const uint32_t mask = (rng() % 5 == 0) ? (1u + rng() % 2) : 3u;
        Fixture fx;
        build_fixture(fx, rng, fallbackTrial, mask);
        uint16_t cw = cws[rng() % 3];
        uint32_t csr = csrs[rng() % 2];
        // every 16th trial: a non-nearest rounding state -> the adapter must run every entry through the original builders
        const bool rcMode = (trial % 16) == 5;
        if (rcMode) { if (rng() & 1) csr = 0x7F80u; else cw = (uint16_t)(cw | 0x0C00u); }
        Expect ex = predict(fx, mask);
        if (rcMode) { ex.native = 0; ex.skipped = 0; ex.fallback = ex.entries; }
        bool anyNull = false;
        for (uint8_t m : g_nullMask) anyNull |= (m != 0);
        const bool exact = !anyNull || rcMode;
        ++T.scenarios; ++(exact ? T.exact : T.canonical); T.rcMode += rcMode;

        // ---- original ----
        reset_pools(); reset_vectors(fx);
        _mm_setcsr(csr); set_cw(cw);
        const bool okOrig = run_original_seh(o3, o4, fx.R.data(), mask, fx.e3.data(), fx.c3, fx.e4.data(), fx.c4);
        _mm_setcsr(defCsr); set_cw(defCw);
        if (!okOrig) { fail(T, trial, "ORIGINAL builder faulted (fixture invalid)"); continue; }
        const Snap ref = take_snap(fx);
        const Canon refCanon = canon_all(fx);

        // ---- port, several configurations per fixture ----
        const uint32_t reps = (trial % 8 == 0) ? 3 : 1;
        for (uint32_t rep = 0; rep < reps; ++rep) {
            ntw_render::Workspace ws{};
            const uint32_t cap = caps[rng() % 5];
            const size_t bytes = ntw_render::workspace_bytes(cap);
            void* mem = _aligned_malloc(bytes, 16);
            if (!mem || !ntw_render::workspace_init(ws, mem, bytes) || ws.capacity != cap) { fail(T, trial, "workspace_init"); if (mem) _aligned_free(mem); continue; }
            const bool usePool = (rng() % 4) != 0;
            bind.dispatch = usePool ? (ntw_render::DispatchFn)&ntw_pool_dispatch : nullptr;
            bind.min_parallel_bones = minPar[rng() % 3];
            bind.chunk_bones = chunkB[rng() % 4];

            reset_pools(); reset_vectors(fx);
            g_holderCalls = g_arenaCalls = 0;
            ntw_render::Stats st{};
            bool ok = false;
            _mm_setcsr(csr); set_cw(cw);
            const bool noFault = run_port_seh(bind, ws, fx.R.data(), mask, &st, &ok);
            const uint32_t csrAfter = _mm_getcsr();
            const uint16_t cwAfter = get_cw();
            _mm_setcsr(defCsr); set_cw(defCw);
            _aligned_free(mem);
            ++T.portRuns;
            if (!noFault || !ok) { fail(T, trial, noFault ? "run() rejected a valid call" : "port faulted"); continue; }
            // Native arithmetic itself sets sticky exception flags (bits 0..5); they are not FP control state.
            if ((csrAfter & ~0x3Fu) != (csr & ~0x3Fu)) fail(T, trial, "run() changed MXCSR controls");
            if (cwAfter != cw) fail(T, trial, "run() changed the x87 control word");
            if (st.entries != ex.entries || st.native != ex.native || st.fallback != ex.fallback || st.skipped != ex.skipped ||
                st.published != ex.native || st.serial_original != (rcMode ? ex.entries : 0u)) {
                char buf[200];
                std::snprintf(buf, sizeof buf, "stats entries %u/%u native %u/%u fallback %u/%u skipped %u/%u published %u",
                              st.entries, ex.entries, st.native, ex.native, st.fallback, ex.fallback, st.skipped, ex.skipped, st.published);
                fail(T, trial, buf);
            }
            T.entries += st.entries; T.native += st.native; T.fallback += st.fallback; T.skipped += st.skipped;
            T.published += st.published; T.dispatches += st.dispatches; T.chunks += st.chunks; T.bones += st.bones; T.windows += st.windows;
            T.holderCalls += g_holderCalls; T.arenaCalls += g_arenaCalls;

            // canonical: every published record, relocation-independent
            const Canon got = canon_all(fx);
            if (got.size() != refCanon.size()) fail(T, trial, "canonical vector count");
            else for (size_t i = 0; i < got.size(); ++i) {
                T.bytesCompared += got[i].size();
                if (got[i] != refCanon[i]) {
                    char buf[160];
                    std::snprintf(buf, sizeof buf, "published records differ in vector %zu (size %zu vs %zu) rep=%u cap=%u pool=%d", i, got[i].size(), refCanon[i].size(), rep, cap, (int)usePool);
                    fail(T, trial, buf);
                    break;
                }
            }
            if (exact) {
                if (g_arenaLog != ref.alog) fail(T, trial, "arena allocation log (size/align/order) differs");
                if (g_heapLog != ref.hlog) fail(T, trial, "heap allocation log differs");
                if (g_arenaOff != ref.arena.size() || g_heapOff != ref.heap.size()) fail(T, trial, "region size differs");
                else {
                    size_t d = first_diff(ref.arena, g_arenaPool, ref.arena.size());
                    if (d != (size_t)-1) {
                        size_t blk = 0;
                        for (size_t i = 0; i < ref.alog.size(); ++i) if (ref.alog[i].off <= d) blk = i;
                        char buf[200];
                        std::snprintf(buf, sizeof buf, "arena byte %zu differs (block %zu off=%zu size=%zu align=%zu: orig=%02x port=%02x) rep=%u cap=%u pool=%d",
                                      d, blk, ref.alog[blk].off, ref.alog[blk].size, ref.alog[blk].align, ref.arena[d], g_arenaPool[d], rep, cap, (int)usePool);
                        fail(T, trial, buf);
                    }
                    d = first_diff(ref.heap, g_heapPool, ref.heap.size());
                    if (d != (size_t)-1) {
                        char buf[120]; std::snprintf(buf, sizeof buf, "heap byte %zu differs", d); fail(T, trial, buf);
                    }
                    T.bytesCompared += ref.arena.size() + ref.heap.size();
                }
                if (std::memcmp(ref.v3.data(), fx.v3.data(), ref.v3.size()) != 0 || std::memcmp(ref.v4.data(), fx.v4.data(), ref.v4.size()) != 0)
                    fail(T, trial, "vector headers differ");
            }
        }
    }

    // ---- informational timing (not an acceptance criterion): original loops vs inline batch vs pooled batch ----
    {
        g_worlds.clear();
        *(uint8_t*)native_address(VA_FLAG_SSE2) = 1;
        for (int wi = 0; wi < 3; ++wi) {
            auto w = std::make_unique<World>();
            build_world(*w, rng, 41, 12, true, false, true);
            g_worlds.push_back(std::move(w));
        }
        Fixture fx;
        fx.nvec3 = 8; fx.nvec4 = 8; fx.c3 = 300; fx.c4 = 300;
        fx.h3.assign(8, {}); fx.h4.assign(8, {});
        g_nullMask.assign(32, 0);
        for (uint32_t i = 0; i < 8; ++i) { fx.h3[i] = {(uintptr_t)g_holderVt, i, i % 3}; fx.h4[i] = {(uintptr_t)g_holderVt, 8 + i, (i + 1) % 3}; }
        fx.v3.assign(8 * VECSZ, 0); fx.v4.assign(8 * VECSZ, 0);
        fx.e3.assign((size_t)fx.c3 * E3, 0); fx.e4.assign((size_t)fx.c4 * E4, 0);
        for (uint32_t i = 0; i < fx.c3; ++i) {
            uint8_t* e = fx.e3.data() + (size_t)i * E3;
            wrp<int32_t>(e, 0, (int32_t)(i % 8)); fill_matrix(rng, (float*)(e + 4), 0); fill_matrix(rng, (float*)(e + 0x44), 0);
            wrp<float>(e, 0x84, 0.05f * (float)(i % 17));
        }
        for (uint32_t i = 0; i < fx.c4; ++i) {
            uint8_t* e = fx.e4.data() + (size_t)i * E4;
            wrp<int32_t>(e, 0, (int32_t)(i % 8)); fill_matrix(rng, (float*)(e + 4), 0);
            wrp<float>(e, 0x54, 0.04f * (float)(i % 19));
        }
        bind_render(fx);
        const uint32_t cap = 640;
        const size_t bytes = ntw_render::workspace_bytes(cap);
        void* mem = _aligned_malloc(bytes, 16);
        ntw_render::Workspace ws{};
        ntw_render::workspace_init(ws, mem, bytes);
        LARGE_INTEGER fq, a, b2;
        QueryPerformanceFrequency(&fq);
        const int iters = 12;
        double tOrig = 0, tInline = 0, tPool = 0;
        for (int it = 0; it < iters; ++it) {
            reset_pools(); reset_vectors(fx);
            QueryPerformanceCounter(&a);
            run_original_seh(o3, o4, fx.R.data(), 3, fx.e3.data(), fx.c3, fx.e4.data(), fx.c4);
            QueryPerformanceCounter(&b2);
            tOrig += (double)(b2.QuadPart - a.QuadPart) * 1e6 / (double)fq.QuadPart;
            reset_pools(); reset_vectors(fx);
            bind.dispatch = nullptr; bind.min_parallel_bones = 0; bind.chunk_bones = 0;
            ntw_render::Stats s1{};
            QueryPerformanceCounter(&a);
            ntw_render::run(bind, ws, fx.R.data(), 3, &s1);
            QueryPerformanceCounter(&b2);
            tInline += (double)(b2.QuadPart - a.QuadPart) * 1e6 / (double)fq.QuadPart;
            reset_pools(); reset_vectors(fx);
            bind.dispatch = (ntw_render::DispatchFn)&ntw_pool_dispatch; bind.min_parallel_bones = 1; bind.chunk_bones = 256;
            ntw_render::Stats s2{};
            QueryPerformanceCounter(&a);
            ntw_render::run(bind, ws, fx.R.data(), 3, &s2);
            QueryPerformanceCounter(&b2);
            tPool += (double)(b2.QuadPart - a.QuadPart) * 1e6 / (double)fq.QuadPart;
            if (it == iters - 1) std::printf("timing: 600 entries x 41 bones: original %.0f us, port inline %.0f us, port 4 workers+caller %.0f us (dispatches=%u chunks=%u native=%u)\n",
                                             tOrig / iters, tInline / iters, tPool / iters, s2.dispatches, s2.chunks, s2.native);
        }
        _aligned_free(mem);
    }
    ntw_pool_shutdown(g_pool);

    std::printf("trials=%u scenarios=%llu exact=%llu canonical=%llu sse2-decode-cases=%u seed=%u port-runs=%llu\n", trials,
                (unsigned long long)T.scenarios, (unsigned long long)T.exact, (unsigned long long)T.canonical, sseCases, seed, (unsigned long long)T.portRuns);
    std::printf("entries=%llu native=%llu fallback=%llu skipped=%llu published=%llu windows=%llu dispatches=%llu chunks=%llu bones=%llu\n",
                (unsigned long long)T.entries, (unsigned long long)T.native, (unsigned long long)T.fallback, (unsigned long long)T.skipped,
                (unsigned long long)T.published, (unsigned long long)T.windows, (unsigned long long)T.dispatches, (unsigned long long)T.chunks, (unsigned long long)T.bones);
    std::printf("bytes-compared=%llu getter-calls holder=%llu arena=%llu rounding-guard-scenarios=%llu mismatches=%llu\n", (unsigned long long)T.bytesCompared,
                (unsigned long long)T.holderCalls, (unsigned long long)T.arenaCalls, (unsigned long long)T.rcMode, (unsigned long long)T.bad);
    std::puts(T.bad == 0 ? "RESULT PASS (bit-identical)" : "RESULT FAIL");
    return T.bad == 0 ? 0 : 1;
}
