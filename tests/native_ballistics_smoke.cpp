// Differential smoke harness for the NTW ballistics prefix stage (x86 only).
//
//   native_ballistics_smoke.exe HELPER.dll TESTKIT.bin [LIVE_CORPUS.bin]
//
// Executes the SHIPPED position-independent helper code (the DLL's .text is copied into an owned RWX
// region exactly like the payload does) and the SHIPPED prefix clone (testkit = original bytes
// 0x6F54E0..0x6F5935 of the pinned image, absolute constants redirected to a pool) against:
//   * an independent C++ model of the prefix written from the instruction stream (bit exact, SSE ops),
//   * a fake tail that verifies the exact continuation register/frame contract and the epilogue,
//   * a fake original per-item function that records fallbacks.
// No game process, no game memory.  The model, clone and pipeline must agree bit for bit.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "native_ballistics_abi.h"
#include "native_worker_dispatch.h"

#pragma fp_contract(off)

static void require(bool ok, const char* what, unsigned long long detail = 0) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s (%llu)\n", what, detail);
        std::exit(1);
    }
}

static float bits_f(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }
static float ss_sqrt(float x) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(x))); }
static int32_t ss_cvtt(float x) { return _mm_cvttss_si32(_mm_set_ss(x)); }

// .rdata constants of the pinned image in testkit pool order (native_ballistics_payload.py testkit).
static const uint32_t kBits[14] = {0x3dcccccd, 0x3f800000, 0x7f7fffff, 0x41200000, 0x40a00000, 0x409ccccd, 0x411ccccd,
                                   0xc09ccccd, 0x3d48b43a, 0x3f7ae148, 0x3f13ce56, 0x3d4ccccd, 0x3f4b5918, 0x3f7d5122};

enum Cov : uint32_t {
    C_SKIP41 = 1, C_E4 = 2, C_E4DEC = 4, C_F49 = 8, C_AGE5 = 16, C_S0 = 32, C_AGTB = 64, C_TLE0 = 128, C_ARC = 256,
    C_ALEB = 512, C_HOMING = 1024, C_F54 = 2048, C_RANGE = 4096, C_D91 = 8192, C_D91UP = 16384, C_D40 = 32768,
    C_PLAIN = 65536
};
static const char* kCovNames[] = {"skip41", "def.e4", "e4-decrement", "flag49", "age>5", "hspeed<=0", "A>B", "t<=0",
                                  "arc-correct", "A<=B", "homing", "f54>f90", "range", "def91==1", "def91&vy>0",
                                  "flag40-drag", "plain"};

#define MF(o) (*reinterpret_cast<float*>(it + (o)))
#define MU(o) (*reinterpret_cast<uint32_t*>(it + (o)))
#define MB(o) (*(it + (o)))

// Independent model of 0x6F54E0..0x6F5935 written from the machine code, not from the clone.
static uint32_t model_prefix(uint8_t* it, uint32_t d_e4, uint32_t d_60, uint32_t d_91, uint32_t& cov) {
    const float K01 = bits_f(kBits[0]), ONE = bits_f(kBits[1]), FLTMAX = bits_f(kBits[2]), TEN = bits_f(kBits[3]),
                FIVE = bits_f(kBits[4]), K49 = bits_f(kBits[5]), K98 = bits_f(kBits[6]), KN49 = bits_f(kBits[7]),
                K0049 = bits_f(kBits[8]), K098 = bits_f(kBits[9]), K0577 = bits_f(kBits[10]),
                K005 = bits_f(kBits[11]), K0794 = bits_f(kBits[12]), K0990 = bits_f(kBits[13]);
    MU(0x58) = MU(0x64);
    MU(0x5C) = MU(0x68);
    MU(0x60) = MU(0x6C);
    if (MB(0x41) != 0) {
        cov |= C_SKIP41;
        return 0;
    }
    if ((d_e4 & 0xFF) != 0) {
        cov |= C_E4;
        const float f = MF(0x8C);
        if (!(f == FLTMAX)) {
            MF(0x8C) = f - K01;
            cov |= C_E4DEC;
        }
    }
    bool homing = false;
    if (MB(0x49) != 0) {
        cov |= C_F49;
        if (MF(0x88) > FIVE) {
            MB(0x49) = 0;
            cov |= C_AGE5;
        } else {
            const float vx = MF(0x70), vz = MF(0x78);
            const float s = ss_sqrt(vx * vx + vz * vz);
            if (!(s > 0.0f)) {
                cov |= C_S0;
                homing = true;
            } else {
                const float inv = ONE / s;
                const float a = MF(0x4C) - MF(0x94);
                const float vy = MF(0x74), py = MF(0x68), ty = MF(0x50);
                const float t0 = (inv * a) * TEN;
                const float t = static_cast<float>(ss_cvtt(t0)) * K01;
                float x1 = vy - t * K49;
                const float x3 = vy - t * K98;
                x1 = x1 * t;
                const float A = py + x1;
                const float B = ty - x3 * K01;
                if (!(A > B)) {
                    cov |= C_ALEB;
                    homing = true;
                } else {
                    cov |= C_AGTB;
                    MB(0x49) = 0;
                    if (t > 0.0f) {
                        const float invt = ONE / t;
                        const float tp = ty - MF(0x68);
                        const float q = invt * a;
                        const float nvz = (MF(0x78) * q) * inv;
                        const float nvx = (q * MF(0x70)) * inv;
                        MF(0x70) = nvx;
                        const float w = (t * KN49) * t;
                        const float nvy = (tp - w) * invt;
                        MF(0x74) = nvy;
                        MF(0x78) = nvz;
                        cov |= C_ARC;
                    } else {
                        cov |= C_TLE0;
                    }
                }
            }
        }
    }
    if (!homing) {
        cov |= C_PLAIN;
        float x0 = MF(0x70) * K01;
        float x1 = MF(0x74) * K01;
        x0 += MF(0x64);
        float x2 = MF(0x78) * K01;
        x1 += MF(0x68);
        x2 += MF(0x6C);
        MF(0x64) = x0;
        MF(0x68) = x1;
        const float y = MF(0x68) - K0049;
        MF(0x6C) = x2;
        MF(0x68) = y;
        MF(0x74) = MF(0x74) - K098;
    } else {
        cov |= C_HOMING;
        float x7 = MF(0x98), x6 = MF(0x9C), x5 = MF(0xA0);
        if (MF(0x54) > MF(0x90)) {
            cov |= C_F54;
            float t1 = x5 * x5;
            const float t0 = x7 * x7;
            t1 += t0;
            x6 = ss_sqrt(t1) * K0577;
        }
        x7 *= K01;
        x5 *= K01;
        x7 += MF(0x70);
        x6 *= K01;
        x5 += MF(0x78);
        x6 += MF(0x74);
        float p2 = x7 + MF(0x70);
        float s5 = x5 + MF(0x78);
        float p1 = x6 + MF(0x74);
        p2 *= K005;
        s5 *= K005;
        p2 += MF(0x64);
        p1 *= K005;
        s5 += MF(0x6C);
        p1 += MF(0x68);
        MF(0x64) = p2;
        MF(0x6C) = s5;
        MF(0x68) = p1;
        MF(0x70) = x7;
        MF(0x74) = x6;
        MF(0x78) = x5;
    }
    {
        float dx = MF(0x64) - MF(0x58);
        float dy = MF(0x68) - MF(0x5C);
        float dz = MF(0x6C) - MF(0x60);
        dx = dx * dx;
        dy = dy * dy;
        dz = dz * dz;
        float d3 = ss_sqrt((dy + dx) + dz);
        float dxz = ss_sqrt(dz + dx);
        d3 += MF(0x90);
        dxz += MF(0x94);
        MF(0x90) = d3;
        MF(0x94) = dxz;
        if (dxz > static_cast<float>(static_cast<int32_t>(d_60))) {
            MB(0x40) = 1;
            cov |= C_RANGE;
        }
    }
    if ((d_91 & 0xFF) == 1) {
        cov |= C_D91;
        MF(0x70) = MF(0x70) * K0794;
        MF(0x78) = MF(0x78) * K0794;
        const float vy = MF(0x74);
        float m = K0794;
        if (!(vy > 0.0f)) m = K0990; else cov |= C_D91UP;
        MF(0x74) = vy * m;
    } else if (MB(0x40) == 1) {
        cov |= C_D40;
        MF(0x70) = MF(0x70) * K0990;
        MF(0x74) = MF(0x74) * K0990;
        MF(0x78) = MF(0x78) * K0990;
    }
    {
        const float vx = MF(0x70), vy = MF(0x74), vz = MF(0x78);
        float s = vy * vy + vx * vx;
        s = s + vz * vz;
        const float inv = ONE / ss_sqrt(s);
        MF(0x7C) = inv * vx;
        MF(0x80) = inv * vy;
        MF(0x84) = inv * vz;
    }
    return 1;
}

// ---------------------------------------------------------------------------------------- fake game code
static volatile uint32_t g_t_edi, g_t_ebx, g_t_ecx, g_t_edx, g_t_esp, g_t_s24, g_t_s28, g_t_xmm6, g_t_calls;
static volatile uint32_t g_orig_calls, g_orig_last;

// Stand-in for 0x6F5936 that proves the continuation contract and returns through the original epilogue.
__declspec(naked) static void fake_tail() {
    __asm {
        mov g_t_edi, edi
        mov g_t_ebx, ebx
        mov g_t_ecx, ecx
        mov g_t_edx, edx
        mov g_t_esp, esp
        mov eax, dword ptr [esp + 24h]
        mov g_t_s24, eax
        mov eax, dword ptr [esp + 28h]
        mov g_t_s28, eax
        movd eax, xmm6
        mov g_t_xmm6, eax
        inc g_t_calls
        pop edi
        pop esi
        pop ebx
        mov esp, ebp
        pop ebp
        ret
    }
}

// Stand-in for the original 0x6F54E0 (thiscall ECX=item).
__declspec(naked) static void fake_orig() {
    __asm {
        mov g_orig_last, ecx
        inc g_orig_calls
        ret
    }
}

// stdcall(fn, item, job) -> 1 when EBX/ESI/EDI survived the fastcall(ECX=item, EDX=job).
__declspec(naked) static int __stdcall call_step(void* fn, void* item, bal_job* job) {
    __asm {
        push ebp
        mov ebp, esp
        push ebx
        push esi
        push edi
        mov ebx, 11111111h
        mov esi, 22222222h
        mov edi, 33333333h
        mov ecx, dword ptr [ebp + 12]
        mov edx, dword ptr [ebp + 16]
        call dword ptr [ebp + 8]
        xor eax, eax
        cmp ebx, 11111111h
        jne done
        cmp esi, 22222222h
        jne done
        cmp edi, 33333333h
        jne done
        mov eax, 1
    done:
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 12
    }
}

// ---------------------------------------------------------------------------------------- loaded code
typedef uint32_t(__fastcall* prefix_fn)(void*);
typedef void(__fastcall* stage_fn)(void*, bal_job*);
typedef void(__fastcall* worker_fn)(bal_job*, uint32_t);
typedef uint32_t(__stdcall* pool_init_fn)(ntw_pool*, const ntw_pool_config*);
typedef uint32_t(__stdcall* pool_shutdown_fn)(ntw_pool*);

struct Code {
    unsigned char* prefix = nullptr;
    unsigned char* helper = nullptr;
    stage_fn stage = nullptr;
    void* step = nullptr;
    worker_fn worker = nullptr;
    void* dispatch = nullptr;
    pool_init_fn pool_init = nullptr;
    pool_shutdown_fn pool_shutdown = nullptr;
    void* pool_worker = nullptr;
};

static std::vector<unsigned char> read_file(const wchar_t* path) {
    FILE* f = nullptr;
    require(_wfopen_s(&f, path, L"rb") == 0 && f, "open file");
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> v(static_cast<size_t>(n));
    require(std::fread(v.data(), 1, v.size(), f) == v.size(), "read file");
    std::fclose(f);
    return v;
}

static Code load_code(const wchar_t* dll, const wchar_t* kit) {
    Code c;
    HMODULE module = LoadLibraryW(dll);
    require(module != nullptr, "LoadLibraryW helper");
    auto* contract = reinterpret_cast<const uint32_t*>(GetProcAddress(module, "bal_contract"));
    auto* stage = reinterpret_cast<unsigned char*>(GetProcAddress(module, "bal_stage"));
    auto* step = reinterpret_cast<unsigned char*>(GetProcAddress(module, "bal_step"));
    auto* worker = reinterpret_cast<unsigned char*>(GetProcAddress(module, "bal_worker"));
    auto* dispatch = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_dispatch"));
    auto* init = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_init"));
    auto* shutdown = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_shutdown"));
    auto* poolWorker = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_worker_start"));
    require(dispatch && init && shutdown && poolWorker, "persistent worker exports");
    require(contract && stage && step && worker, "helper exports");
    require(contract[0] == BAL_ABI_VERSION && contract[1] == BAL_RECORD_BYTES && contract[2] == BAL_JOB_BYTES &&
                contract[3] == BAL_SHADOW_BYTES && contract[4] == 0x6F5936 && contract[5] == 0x6F54E0 &&
                contract[6] == 0x6F6BC0 && contract[7] == 0x57DFF5,
            "helper ABI words");
    auto* image = reinterpret_cast<unsigned char*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew);
    auto* sections = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* text = nullptr;
    const uint32_t rva = static_cast<uint32_t>(stage - image);
    for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i) {
        if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) text = &sections[i];
    }
    require(text && (text->Characteristics & IMAGE_SCN_MEM_EXECUTE), "helper code section");
    require(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0, "helper must be import free");
    c.helper = static_cast<unsigned char*>(VirtualAlloc(nullptr, text->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    require(c.helper != nullptr, "helper allocation");
    std::memcpy(c.helper, image + text->VirtualAddress, text->Misc.VirtualSize);
    FlushInstructionCache(GetCurrentProcess(), c.helper, text->Misc.VirtualSize);
    const auto at = [&](unsigned char* fn) { return c.helper + (fn - image - text->VirtualAddress); };
    c.stage = reinterpret_cast<stage_fn>(at(stage));
    c.step = at(step);
    c.worker = reinterpret_cast<worker_fn>(at(worker));
    c.dispatch = at(dispatch);
    c.pool_init = reinterpret_cast<pool_init_fn>(at(init));
    c.pool_shutdown = reinterpret_cast<pool_shutdown_fn>(at(shutdown));
    c.pool_worker = at(poolWorker);
    FreeLibrary(module);  // the owned copy is the only code executed from here on

    const auto blob = read_file(kit);
    require(blob.size() > 32, "testkit size");
    uint32_t hdr[8];
    std::memcpy(hdr, blob.data(), 32);
    require(hdr[0] == 0x4B54424E && hdr[1] == 1, "testkit magic");
    const uint32_t codeBytes = hdr[2], poolOff = hdr[3], poolCount = hdr[4], relocCount = hdr[5];
    require(poolOff >= codeBytes && poolOff + poolCount * 4 + relocCount * 8 + 32 == blob.size(), "testkit layout");
    require(poolCount == 14, "testkit pool count");
    c.prefix = static_cast<unsigned char*>(VirtualAlloc(nullptr, poolOff + poolCount * 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    require(c.prefix != nullptr, "prefix allocation");
    std::memcpy(c.prefix, blob.data() + 32, poolOff + poolCount * 4);
    const uint32_t* pool = reinterpret_cast<const uint32_t*>(blob.data() + 32 + poolOff);
    for (uint32_t i = 0; i != poolCount; ++i) require(pool[i] == kBits[i], "testkit constants differ from the model constants", i);
    const uint32_t* relocs = reinterpret_cast<const uint32_t*>(blob.data() + 32 + poolOff + poolCount * 4);
    for (uint32_t i = 0; i != relocCount; ++i) {
        const uint32_t off = relocs[2 * i], idx = relocs[2 * i + 1];
        require(off + 4 <= codeBytes && idx < poolCount, "testkit reloc");
        const uint32_t target = reinterpret_cast<uint32_t>(c.prefix + poolOff + idx * 4);
        std::memcpy(c.prefix + off, &target, 4);
    }
    FlushInstructionCache(GetCurrentProcess(), c.prefix, poolOff + poolCount * 4);
    return c;
}

// ---------------------------------------------------------------------------------------- test data
struct Sample {
    alignas(16) uint8_t item[BAL_SHADOW_BYTES];
    alignas(16) uint8_t def[0x100];
};

static std::mt19937 rng(0x6F54E0u);
static float rf(float lo, float hi) { return lo + (hi - lo) * (static_cast<float>(rng() & 0xFFFFFF) / 16777215.0f); }
static bool coin(unsigned percent) { return rng() % 100 < percent; }

static void random_sample(Sample& s) {
    std::memset(&s, 0, sizeof(s));
    uint8_t* it = s.item;
    MU(0x08) = reinterpret_cast<uint32_t>(s.def);
    MB(0x41) = coin(3) ? 1 : 0;
    MB(0x40) = coin(30) ? 1 : 0;
    MB(0x49) = coin(55) ? 1 : 0;
    MF(0x4C) = rf(0, 500);
    MF(0x50) = rf(-20, 200);
    MF(0x54) = rf(0, 300);
    for (int k = 0; k != 3; ++k) MF(0x64 + 4 * k) = rf(-1000, 1000);
    MF(0x68) = rf(0, 200);
    MF(0x70) = rf(-150, 150);
    MF(0x74) = rf(-60, 60);
    MF(0x78) = rf(-150, 150);
    if (coin(8)) { MF(0x70) = 0.0f; MF(0x78) = 0.0f; }
    MF(0x88) = coin(25) ? rf(5.0f, 9.0f) : rf(0.0f, 5.0f);
    MF(0x8C) = coin(40) ? bits_f(0x7f7fffff) : rf(0, 2);
    MF(0x90) = rf(0, 400);
    MF(0x94) = coin(40) ? rf(0, MF(0x4C)) : rf(0, 600);
    MF(0x98) = rf(-120, 120);
    MF(0x9C) = rf(-60, 60);
    MF(0xA0) = rf(-120, 120);
    MU(0x58) = 0xDEADBEEF; MU(0x5C) = 0xDEADBEEF; MU(0x60) = 0xDEADBEEF;   // outputs, must be overwritten
    MU(0x7C) = 0xCAFEF00D; MU(0x80) = 0xCAFEF00D; MU(0x84) = 0xCAFEF00D;
    *reinterpret_cast<uint32_t*>(s.def + 0x60) = static_cast<uint32_t>(rng() % 600);
    s.def[0x91] = static_cast<uint8_t>(rng() % 3);
    s.def[0xE4] = static_cast<uint8_t>(rng() % 2);
}

// ---------------------------------------------------------------------------------------- dispatch
static DWORD WINAPI worker_start_with_different_fp(void* param) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    _mm_setcsr(0x7F80u); // round toward zero: ballistic chunks must install the stage's MXCSR
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(pool->api.worker_entry)(param);
}

static HANDLE WINAPI create_smoke_worker(LPSECURITY_ATTRIBUTES attrs, SIZE_T stack,
                                        LPTHREAD_START_ROUTINE entry, void* param, DWORD flags, LPDWORD id) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    require(reinterpret_cast<uint32_t>(entry) == pool->api.worker_entry, "relocated worker entry");
    return CreateThread(attrs, stack, worker_start_with_different_fp, param, flags, id);
}

static void init_pool(Code& code, ntw_pool& pool, uint32_t workers) {
    ntw_pool_config cfg{};
    cfg.abi = NTW_POOL_ABI;
    cfg.workers = workers;
    cfg.api.create_event = reinterpret_cast<uint32_t>(&CreateEventW);
    cfg.api.close_handle = reinterpret_cast<uint32_t>(&CloseHandle);
    cfg.api.set_event = reinterpret_cast<uint32_t>(&SetEvent);
    cfg.api.wait_single = reinterpret_cast<uint32_t>(&WaitForSingleObject);
    cfg.api.create_thread = reinterpret_cast<uint32_t>(&create_smoke_worker);
    cfg.api.worker_entry = reinterpret_cast<uint32_t>(code.pool_worker);
    require(code.pool_init(&pool, &cfg) == NTW_POOL_OK, "persistent worker initialization");
}

// ---------------------------------------------------------------------------------------- tests
struct Fixture {
    std::vector<Sample> samples;
    std::vector<uint32_t> ptrs;
    uint32_t mgr[16];
    std::vector<bal_record> records;
    bal_job job;
    Code code;

    void init(Code& c, size_t n, size_t capacity) {
        code = c;
        samples.resize(n);
        ptrs.resize(n);
        records.assign(capacity, bal_record{});
        std::memset(&job, 0, sizeof(job));
        job.abi = BAL_ABI_VERSION;
        job.capacity = static_cast<uint32_t>(capacity);
        job.records = records.data();
        job.prefix_entry = reinterpret_cast<uint32_t>(c.prefix);
        job.orig_item = reinterpret_cast<uint32_t>(&fake_orig);
        job.tail_va = reinterpret_cast<uint32_t>(&fake_tail);
        static const float one = 1.0f;
        job.one_ptr = reinterpret_cast<uint32_t>(&one);
        job.chunk_items = 32;
        job.min_parallel = 64;
        job.worker_entry = reinterpret_cast<uint32_t>(c.worker);
        std::memset(mgr, 0, sizeof(mgr));
        mgr[4] = static_cast<uint32_t>(n);
        mgr[5] = reinterpret_cast<uint32_t>(ptrs.data());
    }
    void bind() {
        for (size_t i = 0; i != samples.size(); ++i) ptrs[i] = reinterpret_cast<uint32_t>(samples[i].item);
        mgr[4] = static_cast<uint32_t>(samples.size());
    }
    void stage() { code.stage(mgr, &job); }
    bool step(size_t i) { return call_step(code.step, samples[i].item, &job) == 1; }
};

static void differential_prefix(Code& c, std::vector<Sample>& corpus, uint32_t& allCov, const char* label) {
    for (Sample& s : corpus) {
        Sample a = s, b = s;   // item.def pointers must stay on the original definition block
        reinterpret_cast<uint32_t&>(a.item[8]) = reinterpret_cast<uint32_t>(s.def);
        reinterpret_cast<uint32_t&>(b.item[8]) = reinterpret_cast<uint32_t>(s.def);
        uint32_t cov = 0;
        const uint32_t m = model_prefix(a.item, a.def[0xE4], *reinterpret_cast<uint32_t*>(a.def + 0x60), a.def[0x91], cov);
        const uint32_t r = reinterpret_cast<prefix_fn>(c.prefix)(b.item);
        require(r == m, "prefix clone and model disagree on the exit", r);
        require(std::memcmp(a.item, b.item, BAL_SHADOW_BYTES) == 0, label);
        allCov |= cov;
    }
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    require(argc >= 3, "usage: native_ballistics_smoke HELPER.dll TESTKIT.bin [LIVE_CORPUS.bin]");
    Code code = load_code(argv[1], argv[2]);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    alignas(64) ntw_pool pool{};
    const uint32_t workers = 4;
    init_pool(code, pool, workers);

    // 1. clone vs model, random + structured corpus
    std::vector<Sample> corpus(60000);
    for (Sample& s : corpus) random_sample(s);
    uint32_t cov = 0;
    differential_prefix(code, corpus, cov, "random: cloned original prefix differs from the independent model");

    // 2. live corpus (read-only capture of real projectiles), if supplied
    size_t liveCount = 0;
    if (argc >= 4) {
        const auto blob = read_file(argv[3]);
        uint32_t magic, version, count;
        require(blob.size() >= 16, "live corpus size");
        std::memcpy(&magic, blob.data(), 4);
        std::memcpy(&version, blob.data() + 4, 4);
        std::memcpy(&count, blob.data() + 8, 4);
        require(magic == 0x434C424E && version == 1, "live corpus magic");
        const size_t stride = BAL_SHADOW_BYTES + 12;
        require(blob.size() == 16 + stride * count, "live corpus layout");
        std::vector<Sample> live(count);
        for (uint32_t i = 0; i != count; ++i) {
            std::memset(&live[i], 0, sizeof(Sample));
            const unsigned char* p = blob.data() + 16 + stride * i;
            std::memcpy(live[i].item, p, BAL_SHADOW_BYTES);
            uint32_t d[3];
            std::memcpy(d, p + BAL_SHADOW_BYTES, 12);
            live[i].def[0xE4] = static_cast<uint8_t>(d[0]);
            *reinterpret_cast<uint32_t*>(live[i].def + 0x60) = d[1];
            live[i].def[0x91] = static_cast<uint8_t>(d[2]);
        }
        differential_prefix(code, live, cov, "live: cloned original prefix differs from the independent model");
        liveCount = count;
    }
    std::printf("coverage:");
    for (unsigned b = 0; b != sizeof(kCovNames) / sizeof(kCovNames[0]); ++b) {
        if (!(cov & (1u << b))) std::printf(" MISSING(%s)", kCovNames[b]);
    }
    std::printf(" %08x\n", cov);

    // 3. pipeline: stage -> threads -> ordered steps, committed state vs the model, bit for bit
    const size_t n = 5000;
    std::vector<uint8_t> origBytes(n * BAL_SHADOW_BYTES), wantBytes(n * BAL_SHADOW_BYTES);
    std::vector<uint8_t> skipped(n, 0);
    Fixture f;
    f.init(code, n, n);
    for (Sample& s : f.samples) random_sample(s);
    f.bind();
    size_t nonSkip = 0;
    for (size_t i = 0; i != n; ++i) {
        std::memcpy(&origBytes[i * BAL_SHADOW_BYTES], f.samples[i].item, BAL_SHADOW_BYTES);
        Sample t = f.samples[i];
        uint32_t c2 = 0;
        const uint32_t m = model_prefix(t.item, t.def[0xE4], *reinterpret_cast<uint32_t*>(t.def + 0x60), t.def[0x91], c2);
        skipped[i] = (m == 0);
        nonSkip += (m != 0);
        std::memcpy(&wantBytes[i * BAL_SHADOW_BYTES], skipped[i] ? f.samples[i].item : t.item, BAL_SHADOW_BYTES);
    }
    const auto restore = [&](Fixture& fx) {
        for (size_t i = 0; i != n; ++i) std::memcpy(fx.samples[i].item, &origBytes[i * BAL_SHADOW_BYTES], BAL_SHADOW_BYTES);
        fx.job.cursor = 0;
    };
    const auto run_ordered = [&](Fixture& fx, const std::vector<uint8_t>* mutated) {
        for (size_t i = 0; i != n; ++i) {
            const uint32_t calls = g_t_calls, origCalls = g_orig_calls;
            const uint8_t* item = fx.samples[i].item;
            std::vector<uint8_t> before(item, item + BAL_SHADOW_BYTES);
            require(fx.step(i), "bal_step clobbered EBX/ESI/EDI", i);
            const bool fallback = skipped[i] || (mutated && (*mutated)[i]);
            if (fallback) {
                require(g_orig_calls == origCalls + 1 && g_t_calls == calls, "fallback must run the original function only", i);
                require(g_orig_last == reinterpret_cast<uint32_t>(item), "fallback item", i);
                require(std::memcmp(item, before.data(), BAL_SHADOW_BYTES) == 0, "fallback must not touch the item", i);
            } else {
                const uint32_t it32 = reinterpret_cast<uint32_t>(item);
                require(g_orig_calls == origCalls && g_t_calls == calls + 1, "commit must enter the tail exactly once", i);
                require(g_t_edi == it32 && g_t_ebx == it32 + 0x64 && g_t_edx == it32 + 0x7C, "tail EDI/EBX/EDX contract", i);
                require(g_t_ecx == *reinterpret_cast<const uint32_t*>(item + 8), "tail ECX == definition", i);
                require((g_t_esp & 15) == 0 && g_t_s24 == 0x18 && g_t_s28 == it32, "tail frame contract", i);
                require(g_t_xmm6 == 0x3F800000u, "tail XMM6 == 1.0f", i);
                require(std::memcmp(item, &wantBytes[i * BAL_SHADOW_BYTES], BAL_SHADOW_BYTES) == 0,
                        "committed item differs from the original-order model", i);
            }
        }
    };
    const auto clear_stats = [](Fixture& fx) {
        std::memset(&fx.job.st_stages, 0, sizeof(bal_job) - offsetof(bal_job, st_stages));
    };

    // 3a. persistent four-worker team plus caller; workers start with round-toward-zero MXCSR
    f.job.dispatch = reinterpret_cast<uint32_t>(code.dispatch);
    f.job.dispatch_user = reinterpret_cast<uint32_t>(&pool);
    const unsigned mainCsr = _mm_getcsr();
    f.stage();
    require(_mm_getcsr() == mainCsr, "stage must restore MXCSR");
    require(f.job.count == n && f.job.st_dispatched == 1 && f.job.st_chunks == (n + 31) / 32, "stage accounting");
    run_ordered(f, nullptr);
    require(f.job.st_committed == nonSkip && f.job.st_rejected == 0 && f.job.st_skip == n - nonSkip &&
                f.job.st_unmatched == 0, "committed/skip counters");

    // 3b. inline (dispatch == 0) with ordered re-execution verification
    restore(f);
    f.job.dispatch = 0;
    f.job.flags = BAL_FLAG_VERIFY;
    clear_stats(f);
    f.stage();
    run_ordered(f, nullptr);
    require(f.job.st_verify_bad == 0 && f.job.st_dispatched == 0 && f.job.st_committed == nonSkip, "inline verify");

    // 3c. snapshot invalidation: mutate inputs after the stage (what an earlier hit handler could do)
    restore(f);
    f.job.dispatch = reinterpret_cast<uint32_t>(code.dispatch);
    f.job.flags = 0;
    clear_stats(f);
    f.stage();
    std::vector<uint8_t> mutated(n, 0);
    size_t mutatedNonSkip = 0;
    for (size_t i = 0; i != n; ++i) {
        if (rng() % 10 != 0) continue;
        uint8_t* it = f.samples[i].item;
        switch (rng() % 8) {
            case 0: MF(0x70) += 1.0f; break;
            case 1: MF(0x88) += 0.5f; break;
            case 2: f.samples[i].def[0xE4] ^= 1; break;
            case 3: MB(0x40) ^= 1; break;
            case 4: MF(0x64) += 3.0f; break;
            case 5: MF(0x94) += 1.0f; break;
            case 6: *reinterpret_cast<uint32_t*>(f.samples[i].def + 0x60) += 7; break;
            default: MF(0xA0) += 2.0f; break;
        }
        mutated[i] = 1;
        mutatedNonSkip += !skipped[i];
    }
    run_ordered(f, &mutated);
    require(f.job.st_rejected == mutatedNonSkip && f.job.st_committed == nonSkip - mutatedNonSkip, "rejection counters");

    // 3d. capacity overflow: the whole stage declines, every item takes the original function
    Fixture g;
    g.init(code, n, n / 2);
    for (size_t i = 0; i != n; ++i) {
        std::memcpy(g.samples[i].item, &origBytes[i * BAL_SHADOW_BYTES], BAL_SHADOW_BYTES);
        std::memcpy(g.samples[i].def, f.samples[i].def, sizeof(g.samples[i].def));
        reinterpret_cast<uint32_t&>(g.samples[i].item[8]) = reinterpret_cast<uint32_t>(g.samples[i].def);
    }
    g.bind();
    g.stage();
    require(g.job.st_overflow == 1 && g.job.count == 0, "overflow accounting");
    {
        const uint32_t origCalls = g_orig_calls, calls = g_t_calls;
        for (size_t i = 0; i != n; ++i) require(g.step(i), "overflow step", i);
        require(g_orig_calls == origCalls + n && g_t_calls == calls && g.job.st_unmatched == n && g.job.st_committed == 0,
                "overflow must use the original function only");
    }

    // 3e. disabled stage
    g.job.flags = BAL_FLAG_DISABLE;
    g.stage();
    require(g.job.count == 0, "disable flag");

    // 4. timing (informational): the clone on shadows, serial vs threads
    {
        const size_t big = 60000;
        Fixture h;
        h.init(code, big, big);
        for (Sample& s : h.samples) random_sample(s);
        h.bind();
        double serialMs = 0, parallelMs = 0;
        for (int round = 0; round != 2; ++round) {
            h.job.dispatch = round ? reinterpret_cast<uint32_t>(code.dispatch) : 0;
            h.job.dispatch_user = reinterpret_cast<uint32_t>(&pool);
            h.job.chunk_items = 256;
            h.job.min_parallel = 64;
            const auto t0 = std::chrono::steady_clock::now();
            for (int rep = 0; rep != 10; ++rep) h.stage();
            const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count() / 10;
            (round ? parallelMs : serialMs) = ms;
        }
        std::printf("timing: %zu projectiles, stage serial %.3f ms, %u persistent workers + caller %.3f ms (snapshot copy included)\n", big,
                    serialMs, workers, parallelMs);
    }
    require(code.pool_shutdown(&pool) == NTW_POOL_OK, "persistent worker shutdown");
    std::printf("PASS: clone==model on %zu random + %zu live samples; %zu-item pipeline committed %zu, rejected %zu mutated, "
                "overflow/disable paths, callee-saved + tail contract, MXCSR install, persistent 4-worker dispatch bit-identical.\n",
                corpus.size(), liveCount, n, nonSkip, mutatedNonSkip);
    return 0;
}
