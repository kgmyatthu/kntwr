// Differential oracle: executes the ORIGINAL Napoleon.exe pose kernels (read from the user's
// installed image into a private relocated mapping inside THIS test process) and compares them
// bit-for-bit with native_animation_pose_kernel.cpp.  Nothing touches the running game, the installed EXE, or
// any debugger/injection API.  The only patches are in the private copy: allocator entries are redirected to
// a bump allocator.
//
//   native_animation_oracle_smoke.exe <path-to-Napoleon.exe> [trials] [seed]
//
// Exit 0 only if every comparison is bit-identical.
#define WIN32_LEAN_AND_MEAN
#include <cmath>
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include "native_animation_pose_kernel.h"
#include "native_image_relocation.h"

#ifndef _M_IX86
#error x86 only
#endif

// ---- original VAs (preferred base 0x400000) -------------------------------------------------------
static const uintptr_t VA_LOCATE = 0x10DA030;   // thiscall, ret 0x14
static const uintptr_t VA_BLEND = 0x10CE290;    // thiscall, ret 0x20
static const uintptr_t VA_COMPOSE = 0x10DF020;  // thiscall, ret 8
static const uintptr_t VA_SAMPLE = 0x10DF440;   // thiscall, ret 0x10   (locate + alloc + blend)
static const uintptr_t VA_ROOTMOTION = 0x10F1160;
static const uintptr_t VA_ALLOC = 0xFF7F20;     // cdecl(size, tag) -> ptr
static const uintptr_t VA_ARENA = 0x10E9DC0;    // thiscall(arena; size, align) ret 8
static const uintptr_t VA_ACOS = 0x128448C;     // xmm0 -> xmm0
static const uintptr_t VA_FLAG_INIT = 0x176CBF4;
static const uintptr_t VA_FLAG_SSE2 = 0x176CBF5;
static uintptr_t g_image_delta;
static uintptr_t native_address(uintptr_t preferred) { return preferred + g_image_delta; }

// ---- test allocator ---------------------------------------------------------------------------------
static uint8_t* g_pool;
static size_t g_poolOff, g_poolSize = 256u << 20;
static void* __cdecl test_alloc(size_t size, void*) {
    size_t off = (g_poolOff + 15) & ~(size_t)15;
    if (off + size > g_poolSize) { std::fputs("pool exhausted\n", stderr); std::exit(3); }
    g_poolOff = off + size;
    std::memset(g_pool + off, 0xCD, size);  // poison: unwritten bone slots become visible in the compare
    return g_pool + off;
}
static void* __cdecl arena_helper(void*, size_t size, size_t align) {
    size_t a = align < 16 ? 16 : align;  // stricter than the game; satisfies movaps users
    size_t off = (g_poolOff + a - 1) & ~(a - 1);
    if (off > g_poolSize || size > g_poolSize - off) {
        std::fputs("arena pool exhausted\n", stderr); std::exit(3);
    }
    g_poolOff = off + size;
    std::memset(g_pool + off, 0xCD, size);
    return g_pool + off;
}
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
        return SetFilePointerEx(f, position, nullptr, FILE_BEGIN)
            && ReadFile(f, output, bytes, &got, nullptr) && got == bytes;
    };
    // Read headers on the stack and copy sections directly into the owned image mapping.
    alignas(4) uint8_t header[4096];
    if (!read_range(0, header, sizeof(header))) { CloseHandle(f); return false; }
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(header);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0
        || static_cast<size_t>(dos->e_lfanew) > sizeof(header) - sizeof(IMAGE_NT_HEADERS32)) {
        CloseHandle(f); return false;
    }
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(header + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != 0x14c) {
        CloseHandle(f); return false;
    }
    const uintptr_t base = nt->OptionalHeader.ImageBase;
    const SIZE_T size = nt->OptionalHeader.SizeOfImage;
    auto m = static_cast<uint8_t*>(VirtualAlloc(nullptr, size,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!m) {
        std::fprintf(stderr, "cannot map native image (err %lu)\n", GetLastError());
        CloseHandle(f); return false;
    }
    if (nt->OptionalHeader.SizeOfHeaders > size
        || !read_range(0, m, nt->OptionalHeader.SizeOfHeaders)) {
        CloseHandle(f); VirtualFree(m, 0, MEM_RELEASE); return false;
    }
    auto loaded_nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(m + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(loaded_nt);
    for (unsigned i = 0; i < loaded_nt->FileHeader.NumberOfSections; ++i) {
        const DWORD n = sec[i].SizeOfRawData < sec[i].Misc.VirtualSize
            ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (sec[i].VirtualAddress > size || n > size - sec[i].VirtualAddress
            || !read_range(sec[i].PointerToRawData, m + sec[i].VirtualAddress, n)) {
            CloseHandle(f); VirtualFree(m, 0, MEM_RELEASE); return false;
        }
    }
    CloseHandle(f);
    g_image_delta = reinterpret_cast<uintptr_t>(m) - base;
    if (!RelocateNativeImage(m, size, loaded_nt, g_image_delta)) {
        VirtualFree(m, 0, MEM_RELEASE); return false;
    }
    g_acosVa = native_address(VA_ACOS);
    return true;
}

// ---- calling the originals ----------------------------------------------------------------------------
typedef void(__fastcall* LocateFn)(void* clip, void* edx, float t, uint32_t* i0, uint32_t* i1, float* frac, int noWrap);
typedef void(__fastcall* BlendFn)(void* L, void* edx, uint32_t maxb, const uint8_t* A, const uint8_t* B, float t, uint32_t mode, const uint8_t* holder, const uint8_t* header, void* arena);
typedef uint8_t*(__fastcall* ComposeFn)(void* L, void* edx, uint32_t* pmax, void* arena);
typedef uint8_t*(__fastcall* SampleFn)(void* clip, void* edx, uint32_t maxb, float t, uint32_t mode, void* arena);
typedef void(__fastcall* RootFn)(void* clip, void* edx, float* out, float t);

template <class T> static T rdp(const void* p, size_t off) { T v; std::memcpy(&v, (const uint8_t*)p + off, sizeof(T)); return v; }
template <class T> static void wrp(void* p, size_t off, T v) { std::memcpy((uint8_t*)p + off, &v, sizeof(T)); }

// ---- synthetic native-layout data -------------------------------------------------------------------------
struct World {
    std::vector<uint8_t> skel, table, ref, holder, clip, framesArr;
    std::vector<std::vector<uint8_t>> frames, framePos, frameQuat;
    std::vector<uint8_t> refPos;
    uint32_t n = 0, nframes = 0;
};
static inline uint32_t bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static inline float bit_cast_f(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }

static int16_t enc(float v) { long l = std::lrint(v * 32767.0f); if (l > 32767) l = 32767; if (l < -32767) l = -32767; return (int16_t)l; }

static void make_quat(std::mt19937& rng, const float* ref, float* q, int style) {
    std::uniform_real_distribution<float> u(-1, 1);
    float v[4];
    if (style == 0 || !ref) { for (float& c : v) c = u(rng); }
    else {
        float noise = style == 1 ? 0.01f : style == 2 ? 0.3f : 1.0f;
        for (int i = 0; i < 4; ++i) v[i] = ref[i] + noise * u(rng);
        if (style == 3) for (float& c : v) c = -c;  // opposite hemisphere -> negation path
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
        if (i > 0 && (rng() % 10) != 0) parent = (int32_t)(rng() % i);
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
    wrp<uint8_t>(c, 0x30, partial ? 1 : 0);  // header(clip+8) + 0x28
    wrp<uint32_t>(c, 0x44, loop ? 2u : 0u);
    std::uniform_real_distribution<float> ufps(5, 40);
    wrp<float>(c, 0x48, ufps(rng));
    wrp<uint32_t>(c, 0x88, nframes);
    wrp<uintptr_t>(c, 0x8C, (uintptr_t)w.framesArr.data());
    wrp<float>(c, 0x4C, (float)(nframes - 1) / rdp<float>(c, 0x48));
}

struct Stats { uint64_t cmp = 0, bad = 0; };
static void report_bad(const char* what, uint32_t trial, uint32_t bone, uint32_t a, uint32_t b, Stats& s) {
    ++s.bad;
    if (s.bad <= 8) std::printf("MISMATCH %s trial=%u bone=%u orig=%08x ours=%08x\n", what, trial, bone, a, b);
}

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (argc < 2) { std::fputs("usage: native_animation_oracle_smoke <Napoleon.exe> [trials] [seed]\n", stderr); return 2; }
    const uint32_t trials = argc > 2 ? (uint32_t)std::atoi(argv[2]) : 4000;
    const uint32_t seed = argc > 3 ? (uint32_t)std::atoi(argv[3]) : 12345;
    if (!map_image(argv[1])) return 2;
    g_pool = (uint8_t*)VirtualAlloc(nullptr, g_poolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_pool) return 2;
    patch_jmp(native_address(VA_ALLOC), (void*)&test_alloc);
    patch_jmp(native_address(VA_ARENA), (void*)&arena_stub);
    *(uint8_t*)native_address(VA_FLAG_INIT) = 1;  // skip the CPUID initialiser 0x10D5400
    if (!FlushInstructionCache(GetCurrentProcess(), nullptr, 0)) return 2;

    auto oLocate = (LocateFn)native_address(VA_LOCATE);
    auto oBlend = (BlendFn)native_address(VA_BLEND);
    auto oCompose = (ComposeFn)native_address(VA_COMPOSE);
    auto oSample = (SampleFn)native_address(VA_SAMPLE);
    auto oRoot = (RootFn)native_address(VA_ROOTMOTION);
    std::mt19937 rng(seed);
    Stats locS, blendS[5], compS, jobS, rootS;
    const uint32_t counts[] = {1, 2, 5, 17, 41, 64};
    uint32_t sseCases = 0;
    for (uint32_t trial = 0; trial < trials; ++trial) {
        const bool sse2 = (trial & 1) != 0;
        *(uint8_t*)native_address(VA_FLAG_SSE2) = sse2 ? 1 : 0;
        const uint32_t n = counts[rng() % 6];
        const uint32_t nframes = 2 + (rng() % 20);
        const bool loop = (rng() & 1) != 0, partial = (rng() % 3) == 0;
        World w; build_world(w, rng, n, nframes, loop, partial, sse2);
        const uint8_t* clip = w.clip.data();
        sseCases += sse2;

        // ---- locate -----
        std::uniform_real_distribution<float> ut(-3.0f, 12.0f);
        for (int k = 0; k < 6; ++k) {
            float t = k == 0 ? 0.0f : k == 1 ? -0.0f : k == 2 ? rdp<float>(clip, 0x4C) : ut(rng);
            for (int nw = 0; nw < 2; ++nw) {
                uint32_t a0 = 0xDEAD, a1 = 0xBEEF, b0 = 0, b1 = 0; float af = 0, bf = 0;
                oLocate((void*)clip, nullptr, t, &a0, &a1, &af, nw);
                bool ok = ntw_anim::locate_frames(clip, t, nw != 0, &b0, &b1, &bf);
                ++locS.cmp;
                if (!ok || a0 != b0 || a1 != b1 || bits(af) != bits(bf)) { ++locS.bad; if (locS.bad <= 8) std::printf("MISMATCH locate t=%g nw=%d orig=(%u,%u,%08x) ours=(%u,%u,%08x)\n", t, nw, a0, a1, bits(af), b0, b1, bits(bf)); }
            }
        }
        // ---- root motion ----
        for (int k = 0; k < 3; ++k) {
            float t = ut(rng), a[3] = {1, 2, 3}, b[3] = {4, 5, 6};
            oRoot((void*)clip, nullptr, a, t);
            bool ok = ntw_anim::root_motion(clip, t, b);
            ++rootS.cmp;
            if (!ok || bits(a[0]) != bits(b[0]) || bits(a[1]) != bits(b[1]) || bits(a[2]) != bits(b[2])) ++rootS.bad;
        }

        // ---- direct blend (all modes, random t) + compose from the ORIGINAL local pose ----
        const uint32_t maxb = (rng() % 4 == 0) ? (rng() % (n + 2)) : 0;
        for (uint32_t mode = 0; mode < 5; ++mode) {  // 4 is the unhandled mode: nothing written
            for (int rep = 0; rep < 3; ++rep) {
                const bool useArena = (rng() & 1) != 0;
                float t = rep == 0 ? 0.0f : rep == 1 ? 0.5f : std::uniform_real_distribution<float>(0, 1)(rng);
                const uint8_t* A = w.frames[rng() % nframes].data();
                const uint8_t* B = w.frames[rng() % nframes].data();
                size_t save = g_poolOff;
                uint8_t L[0x20] = {};
                oBlend(L, nullptr, maxb, A, B, t, mode, w.holder.data(), w.clip.data() + 8, useArena ? (void*)g_pool : nullptr);
                const uint32_t on = rdp<uint32_t>(L, 0x10);
                const float* op = (const float*)rdp<uintptr_t>(L, 8);
                const float* oq = (const float*)rdp<uintptr_t>(L, 0xC);
                std::vector<float> np(on * 3 + 4, bit_cast_f(0xCDCDCDCDu)), nq(on * 4 + 4, bit_cast_f(0xCDCDCDCDu));
                ntw_anim::BlendArgs ba{};
                ba.frame_a = A; ba.frame_b = B; ba.t = t; ba.mode = mode; ba.clip_holder = w.holder.data();
                ba.clip_header = w.clip.data() + 8; ba.max_bones = maxb; ba.sse2_quat_decode = sse2; ba.acos_fn = orig_acos;
                uint32_t nn = ntw_anim::blend_local(ba, np.data(), nq.data());
                Stats& S = blendS[mode];
                ++S.cmp;
                if (nn != on) { report_bad("bone-count", trial, 0, on, nn, S); }
                for (uint32_t i = 0; i < on; ++i) {
                    for (int k = 0; k < 3; ++k) if (bits(op[i * 3 + k]) != bits(np[i * 3 + k])) report_bad("pos", trial, i, bits(op[i * 3 + k]), bits(np[i * 3 + k]), S);
                    for (int k = 0; k < 4; ++k) if (bits(oq[i * 4 + k]) != bits(nq[i * 4 + k])) report_bad("quat", trial, i, bits(oq[i * 4 + k]), bits(nq[i * 4 + k]), S);
                }
                if (mode == 4) { g_poolOff = save; continue; }  // poisoned slots: NaN payload order is not a semantic
                // compose from the original's own local pose
                uint32_t pm[2] = {0, 0};
                uint8_t* O = oCompose(L, nullptr, pm, useArena ? (void*)g_pool : nullptr);
                const float* om = (const float*)rdp<uintptr_t>(O, 8);
                std::vector<float> nm(on * 12 + 4);
                ntw_anim::compose_global(w.table.data(), on, op, oq, nm.data());
                ++compS.cmp;
                for (uint32_t i = 0; i < on * 12; ++i) if (bits(om[i]) != bits(nm[i])) report_bad("mat", trial, i / 12, bits(om[i]), bits(nm[i]), compS);
                g_poolOff = save;
            }
        }

        // ---- full job == original 0x10DF440 + 0x10DF020 ----
        for (uint32_t mode = 0; mode < 4; ++mode) {
            const bool useArena = (rng() & 1) != 0;
            const float t = ut(rng);
            const bool nw = (rng() & 1) != 0;
            size_t save = g_poolOff;
            uint8_t* L = oSample((void*)clip, nullptr, maxb, t, mode, useArena ? (void*)g_pool : nullptr);
            // 0x10DF440 has no no_wrap argument (it passes 0): only compare no_wrap=false
            (void)nw;
            uint32_t pm[2] = {0, 0};
            uint8_t* O = oCompose(L, nullptr, pm, useArena ? (void*)g_pool : nullptr);
            const uint32_t on = rdp<uint32_t>(L, 0x10);
            const float* om = (const float*)rdp<uintptr_t>(O, 8);
            std::vector<float> jp(n * 3 + 4), jq(n * 4 + 4), jm(n * 12 + 4);
            ntw_anim::PoseJob j{};
            j.clip = clip; j.time = t; j.mode = mode; j.no_wrap = false; j.max_bones = maxb; j.sse2_quat_decode = sse2;
            j.acos_fn = orig_acos; j.out_pos = jp.data(); j.out_quat = jq.data(); j.out_mats = jm.data();
            ntw_anim::run_pose_job(j);
            ++jobS.cmp;
            if (!j.ok || j.out_bones != on) { report_bad("job-bones", trial, 0, on, j.out_bones, jobS); }
            else for (uint32_t i = 0; i < on * 12; ++i) if (bits(om[i]) != bits(jm[i])) report_bad("job-mat", trial, i / 12, bits(om[i]), bits(jm[i]), jobS);
            g_poolOff = save;
        }
        g_poolOff = 0;
    }
    const char* names[] = {"step", "nlerp", "slerp>=0.993", "slerp>=0.3", "mode4-noop"};
    uint64_t bad = locS.bad + compS.bad + jobS.bad + rootS.bad;
    std::printf("trials=%u sse2-decode-cases=%u seed=%u\n", trials, sseCases, seed);
    std::printf("locate   cmp=%llu bad=%llu\n", (unsigned long long)locS.cmp, (unsigned long long)locS.bad);
    std::printf("rootmot  cmp=%llu bad=%llu\n", (unsigned long long)rootS.cmp, (unsigned long long)rootS.bad);
    for (int m = 0; m < 5; ++m) { std::printf("blend[%s] cmp=%llu bad=%llu\n", names[m], (unsigned long long)blendS[m].cmp, (unsigned long long)blendS[m].bad); bad += blendS[m].bad; }
    std::printf("compose  cmp=%llu bad=%llu\n", (unsigned long long)compS.cmp, (unsigned long long)compS.bad);
    std::printf("job      cmp=%llu bad=%llu\n", (unsigned long long)jobS.cmp, (unsigned long long)jobS.bad);
    std::puts(bad == 0 ? "RESULT PASS (bit-identical)" : "RESULT FAIL");
    return bad == 0 ? 0 : 1;
}
