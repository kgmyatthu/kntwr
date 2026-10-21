// Native process oracle for the NTW ballistics collision seam (native_ballistics_collision.{h,cpp}).
//
// WHAT RUNS WHERE
//   * ORIGINAL machine code: native-ballistics-collision-kit.bin (bytes copied from the pinned Napoleon.exe by
//     native_ballistics_collision_kit.py) is mapped into RWX memory of THIS process and executed natively on
//     objects the harness builds in the exact layouts the original code reads.  It never touches a game process.
//   * BATCH: native_ballistics_collision.cpp (direct worker-kit calls, batch/merge interface), driven through the
//     persistent dispatcher (native_worker_dispatch.dll code copy, 3 workers + caller) and inline.
//
// WHAT IS COMPARED (bit exact: entry, position, t, found, order, owner-side event log)
//   a reference walk of a synthetic collision grid that performs the per-entry blocks of 0x6392C0 in the original
//   order, calling the ORIGINAL clones for every narrow-phase function, versus the owner/worker/merge pipeline of
//   the port, for hit / miss / edge / duplicate / stop-after-first-cell / full-query / serial-stage cases, with
//   denormal inputs and with a caller MXCSR (FTZ|DAZ) that workers must install.
//
// OWNER-COMPUTED RESULTS (ABI 3, nbc_add_owner_result)
//   Mixed worlds let the owner run the ORIGINAL clones (RefSink) at the add point of selected entries and record only the
//   outcome; the remaining entries go to workers by value/borrowed pointer.  Selection is per game object, so a duplicate
//   entry that shares topology with an owner-computed one is never handed to a worker.  After every record the harness
//   overwrites the float topology of that entry (ring nodes, terrain heightfield, wall segment, plane, unit, box) and
//   again across nbc_run/nbc_merge, restoring it before the next owner leaf.  The merged hits, found flag, cells
//   processed and (without worker BOX stages) the owner-side event log must still equal the reference walk, owner slots
//   must be bit-identical after nbc_run, owner-only batches must not wake the pool, and the leaf re-run on the mutated
//   topology must be able to disagree (mutated-topology-disagrees counter), which proves the test sees late reads.
//
//   CMake target native_ballistics_collision_harness (x86, C++20 /EHsc /O2 /arch:SSE2 /fp:precise /W4) linked with the shipped
//      import-free object kntwr_ballistics_collision (native_ballistics_collision.cpp)
//   native_ballistics_collision_harness.exe reference-kit.bin worker-kit.bin native_worker_dispatch.dll [cases]
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <emmintrin.h>
#include <malloc.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "native_ballistics_collision.h"
#include "native_worker_dispatch.h"

using std::uint32_t;
using std::uint8_t;

static void fail(const char* what, const std::string& detail = std::string()) {
    std::printf("FAIL: %s %s\n", what, detail.c_str());
    std::fflush(stdout);
    std::exit(1);
}
static void require(bool ok, const char* what, const std::string& detail = std::string()) {
    if (!ok) fail(what, detail);
}

// ----------------------------------------------------------------------------------------------- original code
typedef uint8_t(__fastcall* F_plane)(const float* seg, void*, const float* plane, uint32_t mode, float* t);
typedef uint8_t(__fastcall* F_ring)(const void* ring, void*, const float* pt);
typedef uint8_t(__fastcall* F_box)(const float* seg, void*, const float* box, uint32_t mode, float* o1, float* o2);
typedef uint8_t(__fastcall* F_wall)(void* wall, void*, const void* arg1, const void* seg, uint32_t mode, float* t);
typedef uint8_t(__fastcall* F_unit_hit)(void* unit, void*, const float* s, uint32_t mode, float* t, uint32_t sel, float extra);
typedef uint8_t(__fastcall* F_unit_inside)(void* unit, void*, const float* p);
typedef uint8_t(__fastcall* F_b5b77)(void* obj2, void*);

struct Kit {
    uint8_t* base = nullptr;
    F_plane plane = nullptr;       // 0x10E8500
    F_ring ring = nullptr;         // 0x10E7030
    F_box box = nullptr;           // 0x10E83E0
    F_wall wall = nullptr;         // 0x5DB450
    F_unit_hit unit_hit = nullptr; // 0x809620
    F_unit_inside unit_inside = nullptr; // 0x809C00
    F_b5b77 b5b77 = nullptr;       // 0x5B77A0
};

static std::vector<uint8_t> read_file(const char* path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) fail("open file", path);
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> v(static_cast<size_t>(n));
    if (std::fread(v.data(), 1, v.size(), f) != v.size()) fail("read file", path);
    std::fclose(f);
    return v;
}

static Kit load_kit(const char* path, bool worker) {
    const std::vector<uint8_t> blob = read_file(path);
    require(blob.size() > 32, "kit size");
    uint32_t hdr[8];
    std::memcpy(hdr, blob.data(), 32);
    require(hdr[0] == 0x4B43424Eu && hdr[1] == 1, "kit magic");
    require(hdr[6] == static_cast<uint32_t>(worker), "reference/worker kit role");
    const uint32_t nf = hdr[2], codeBytes = hdr[3], poolBytes = hdr[4], nrel = hdr[5];
    const size_t tableOff = 32, codeOff = tableOff + 16u * nf, poolOff = codeOff + codeBytes, relOff = poolOff + poolBytes;
    require(relOff + 12u * nrel == blob.size(), "kit layout");
    Kit k;
    const uint32_t total = codeBytes + poolBytes;
    k.base = static_cast<uint8_t*>(VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    require(k.base != nullptr, "kit allocation");
    std::memcpy(k.base, blob.data() + codeOff, codeBytes);
    std::memcpy(k.base + codeBytes, blob.data() + poolOff, poolBytes);
    const uint32_t* rel = reinterpret_cast<const uint32_t*>(blob.data() + relOff);
    for (uint32_t i = 0; i != nrel; ++i) {
        const uint32_t kind = rel[3 * i], field = rel[3 * i + 1], target = rel[3 * i + 2];
        require(field + 4 <= codeBytes, "kit reloc field");
        uint32_t v;
        if (kind == 0) {
            require(target < poolBytes, "kit pool reloc");
            v = reinterpret_cast<uint32_t>(k.base + codeBytes + target);
        } else {
            require(kind == 1 && target < codeBytes, "kit call reloc");
            v = static_cast<uint32_t>((reinterpret_cast<uint32_t>(k.base) + target) - (reinterpret_cast<uint32_t>(k.base) + field + 4));
        }
        std::memcpy(k.base + field, &v, 4);
    }
    FlushInstructionCache(GetCurrentProcess(), k.base, total);
    const uint32_t* tab = reinterpret_cast<const uint32_t*>(blob.data() + tableOff);
    std::map<uint32_t, uint8_t*> fn;
    for (uint32_t i = 0; i != nf; ++i) fn[tab[4 * i]] = k.base + tab[4 * i + 1];
    auto get = [&](uint32_t va) {
        auto it = fn.find(va);
        require(it != fn.end(), "kit function missing");
        return it->second;
    };
    k.plane = reinterpret_cast<F_plane>(get(0x010E8500));
    k.ring = reinterpret_cast<F_ring>(get(0x010E7030));
    k.box = reinterpret_cast<F_box>(get(0x010E83E0));
    k.wall = reinterpret_cast<F_wall>(get(0x005DB450));
    k.unit_hit = reinterpret_cast<F_unit_hit>(get(0x00809620));
    k.unit_inside = reinterpret_cast<F_unit_inside>(get(0x00809C00));
    if (!worker) k.b5b77 = reinterpret_cast<F_b5b77>(get(0x005B77A0));
    return k;
}
static Kit K;
static Kit WorkerK;
static nbc_kernels WorkerBindings;

// ----------------------------------------------------------------------------------------------- dispatcher
typedef uint32_t(__stdcall* pool_init_fn)(ntw_pool*, const ntw_pool_config*);
typedef uint32_t(__stdcall* pool_shutdown_fn)(ntw_pool*);
struct Pool {
    unsigned char* text = nullptr;
    void* dispatch = nullptr;
    pool_init_fn init = nullptr;
    pool_shutdown_fn shutdown = nullptr;
    void* worker = nullptr;
};

static Pool load_pool(const wchar_t* dll) {
    Pool p;
    HMODULE m = LoadLibraryW(dll);
    require(m != nullptr, "LoadLibraryW dispatcher");
    auto* dispatch = reinterpret_cast<unsigned char*>(GetProcAddress(m, "ntw_pool_dispatch"));
    auto* init = reinterpret_cast<unsigned char*>(GetProcAddress(m, "ntw_pool_init"));
    auto* shutdown = reinterpret_cast<unsigned char*>(GetProcAddress(m, "ntw_pool_shutdown"));
    auto* worker = reinterpret_cast<unsigned char*>(GetProcAddress(m, "ntw_pool_worker_start"));
    require(dispatch && init && shutdown && worker, "dispatcher exports");
    auto* image = reinterpret_cast<unsigned char*>(m);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* text = nullptr;
    const uint32_t rva = static_cast<uint32_t>(dispatch - image);
    for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i)
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) text = &sec[i];
    require(text && (text->Characteristics & IMAGE_SCN_MEM_EXECUTE), "dispatcher code section");
    require(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0, "dispatcher must be import free");
    p.text = static_cast<unsigned char*>(VirtualAlloc(nullptr, text->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    require(p.text != nullptr, "dispatcher allocation");
    std::memcpy(p.text, image + text->VirtualAddress, text->Misc.VirtualSize);
    FlushInstructionCache(GetCurrentProcess(), p.text, text->Misc.VirtualSize);
    const auto at = [&](unsigned char* fn) { return p.text + (fn - image - text->VirtualAddress); };
    p.dispatch = at(dispatch);
    p.init = reinterpret_cast<pool_init_fn>(at(init));
    p.shutdown = reinterpret_cast<pool_shutdown_fn>(at(shutdown));
    p.worker = at(worker);
    FreeLibrary(m);
    return p;
}

static DWORD WINAPI worker_default_fp(void* param) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    _mm_setcsr(0x1F80u);  // workers start with the default MXCSR: the batch must install the caller's
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(pool->api.worker_entry)(param);
}
static HANDLE WINAPI create_worker(LPSECURITY_ATTRIBUTES a, SIZE_T stack, LPTHREAD_START_ROUTINE entry, void* param,
                                   DWORD flags, LPDWORD id) {
    auto* slot = static_cast<ntw_pool_slot*>(param);
    auto* pool = reinterpret_cast<ntw_pool*>(slot->pool);
    require(reinterpret_cast<uint32_t>(entry) == pool->api.worker_entry, "relocated worker entry");
    return CreateThread(a, stack, worker_default_fp, param, flags, id);
}

// ----------------------------------------------------------------------------------------------- random data
static std::mt19937 rng(0x6392C0u);
static float bits_f(uint32_t b) { float f; std::memcpy(&f, &b, 4); return f; }
static uint32_t f_bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static float rf(float lo, float hi) { return lo + (hi - lo) * (static_cast<float>(rng() & 0xFFFFFF) / 16777215.0f); }
static bool coin(unsigned percent) { return rng() % 100 < percent; }
static float special_or(float lo, float hi, unsigned pct = 6) {
    static const uint32_t pool[] = {0x00000000, 0x80000000, 0x3F800000, 0xBF800000, 0x3F000000, 0x00000001, 0x007FFFFF,
                                    0x80000001, 0x7F7FFFFF, 0x3F266666, 0x41A00000, 0x40000000, 0x358637BD, 0x0DA24260};
    if (coin(pct)) return bits_f(pool[rng() % (sizeof(pool) / sizeof(pool[0]))]);
    if (coin(25)) return std::floor(rf(lo, hi));
    return rf(lo, hi);
}

// bump arena: stable addresses, zeroed
struct Arena {
    uint8_t* mem;
    size_t used = 0, cap;
    Arena() : cap(64u << 20) { mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)); require(mem != nullptr, "arena"); }
    void reset() { std::memset(mem, 0, used); used = 0; }
    void* alloc(size_t n, size_t align = 16) {
        used = (used + align - 1) & ~(align - 1);
        void* p = mem + used;
        used += n;
        require(used <= cap, "arena full");
        return p;
    }
    template <class T> T* make(size_t count = 1) { return static_cast<T*>(alloc(sizeof(T) * count)); }
};
static Arena arena;

// ----------------------------------------------------------------------------------------------- world
static std::vector<uint32_t>* g_log = nullptr;
static void ev(uint32_t code) { if (g_log) g_log->push_back(code); }

struct Node { uint32_t p0, p1; Node* next; float x, z; };           // 0x14: +8 next, +0xC x, +0x10 z
struct Entry { uint32_t type; uint16_t id; uint16_t pad; uint32_t aux; uint32_t obj; uint32_t pad2; Entry* next; };
static_assert(sizeof(Entry) == 0x18, "entry layout");

enum { T_UNIT = 8, T_PLANE = 0x40, T_BOX = 0x400, T_WALL = 0x800 };

// virtual stubs (thiscall -> __fastcall with a dummy edx)
struct Obj2 { uint32_t* vt; uint32_t bit[3]; uint32_t id; };
static uint32_t __fastcall vt_get_ec(Obj2* o, void*) { ev(0x30000000u | o->id); return o->bit[0]; }
static uint32_t __fastcall vt_get_f0(Obj2* o, void*) { ev(0x31000000u | o->id); return o->bit[1]; }
static uint32_t __fastcall vt_get_e8(Obj2* o, void*) { ev(0x32000000u | o->id); return o->bit[2]; }
// unit object raw bytes: +0 vtable, +0x30 predicate byte, +0x48.. floats, +0x60 obj2, +0x64 id
static uint32_t __fastcall vt_get_obj2(uint8_t* unit, void*) {
    ev(0x20000000u | *reinterpret_cast<uint32_t*>(unit + 0x64));
    return *reinterpret_cast<uint32_t*>(unit + 0x60);
}

static uint8_t* make_terrain(const float* ylo_hi) {
    const uint32_t shift = 2 + rng() % 4, dim = 1u << shift, n = dim * dim;
    float* data = arena.make<float>(2 * n);
    for (uint32_t i = 0; i != 2 * n; ++i) data[i] = ylo_hi ? (coin(90) ? rf(ylo_hi[0], ylo_hi[1]) : special_or(-5, 30)) : special_or(-5, 30, 2);
    uint8_t* g = static_cast<uint8_t*>(arena.alloc(0x30));
    const uint32_t origin = coin(50) ? 0 : (coin(50) ? 1 : 3);
    const uint32_t limit = std::min(dim - 2, 2 + rng() % (dim - 3) + origin);
    static const float cells[] = {1.0f, 2.0f, 4.0f, 0.5f};
    static const float offs[] = {0.0f, 3.0f, -7.0f};
    const float cell = cells[rng() % 4], off = offs[rng() % 3];
    *reinterpret_cast<uint32_t*>(g + 0) = reinterpret_cast<uint32_t>(data);
    *reinterpret_cast<uint32_t*>(g + 8) = shift;
    *reinterpret_cast<uint32_t*>(g + 0x10) = origin;
    *reinterpret_cast<uint32_t*>(g + 0x14) = limit;
    *reinterpret_cast<float*>(g + 0x1C) = off;
    *reinterpret_cast<float*>(g + 0x20) = cell;
    *reinterpret_cast<float*>(g + 0x24) = 1.0f / cell;
    return g;
}

struct World {
    uint32_t dim = 0;
    std::vector<Entry*> cells;            // dim*dim list heads
    std::vector<uint32_t> visit_order;    // cell indices in query order
    uint32_t next_id = 1;
};

static uint8_t* new_obj() { return static_cast<uint8_t*>(arena.alloc(0x200)); }

static Entry* make_entry(World& w, uint32_t type, const nbc_segment& alt) {
    Entry* e = arena.make<Entry>();
    e->type = type;
    e->id = static_cast<uint16_t>(w.next_id++);
    uint8_t* obj = new_obj();
    e->obj = reinterpret_cast<uint32_t>(obj);
    obj[0x30] = coin(92) ? 1 : 0;  // predicate byte (stand-in for 0x6DC9A0), kept at obj+0x30
    const float cx = alt.p0[0] + (alt.p1[0] - alt.p0[0]) * rf(0, 1) + rf(-3, 3);
    const float cy = alt.p0[1] + (alt.p1[1] - alt.p0[1]) * rf(0, 1) + rf(-3, 3);
    const float cz = alt.p0[2] + (alt.p1[2] - alt.p0[2]) * rf(0, 1) + rf(-3, 3);
    if (type == T_PLANE) {
        // plane through a point near the segment, ring polygon around it in (x,z)
        float n[3] = {special_or(-1, 1, 3), special_or(-1, 1, 3), special_or(-1, 1, 3)};
        if (coin(10)) { n[0] = 0; n[2] = 0; n[1] = 1; }
        float* pl = reinterpret_cast<float*>(obj + 0x30);  // plane at +0x30: the predicate byte of this type lives at +0x2F
        obj[0x2F] = coin(92) ? 1 : 0;
        pl[0] = n[0]; pl[1] = n[1]; pl[2] = n[2];
        pl[3] = -(n[0] * cx + n[1] * cy + n[2] * cz) + (coin(20) ? 0.0f : rf(-0.5f, 0.5f));
        const uint32_t k = 3 + rng() % 6;
        Node* nodes = arena.make<Node>(k);
        const float rad = rf(0.5f, 12.0f);
        std::vector<float> angs;
        for (uint32_t i = 0; i != k; ++i) angs.push_back(rf(0, 6.2831853f));
        std::sort(angs.begin(), angs.end());
        const bool snap = coin(40);
        for (uint32_t i = 0; i != k; ++i) {
            float px = cx + rad * std::cos(angs[i]), pz = cz + rad * std::sin(angs[i]);
            if (snap) { px = std::round(px); pz = std::round(pz); }
            nodes[i].x = px; nodes[i].z = pz;
            nodes[i].next = &nodes[(i + 1) % k];
        }
        *reinterpret_cast<uint32_t*>(obj + 8) = reinterpret_cast<uint32_t>(&nodes[0]);
    } else if (type == T_UNIT) {
        obj[0x30] = coin(92) ? 1 : 0;
        *reinterpret_cast<uint32_t*>(obj + 0x34) = (coin(80) ? 0x18u : 8u * (rng() % 3));
        *reinterpret_cast<float*>(obj + 0x48) = cx;
        *reinterpret_cast<float*>(obj + 0x4C) = std::fabs(special_or(0, 3, 3));
        *reinterpret_cast<float*>(obj + 0x50) = cz;
        *reinterpret_cast<float*>(obj + 0x54) = std::fabs(special_or(0, 3, 3));
        *reinterpret_cast<float*>(obj + 0x58) = std::fabs(special_or(0, 6, 3));
        *reinterpret_cast<float*>(obj + 0x5C) = 0;
        uint32_t* vt = arena.make<uint32_t>(0x10);
        vt[6] = reinterpret_cast<uint32_t>(&vt_get_obj2);
        *reinterpret_cast<uint32_t*>(obj) = reinterpret_cast<uint32_t>(vt);
        *reinterpret_cast<uint32_t*>(obj + 0x64) = e->id;
        Obj2* o2 = nullptr;
        if (coin(70)) {
            o2 = arena.make<Obj2>();
            uint32_t* vt2 = arena.make<uint32_t>(0x50);
            vt2[0xEC / 4] = reinterpret_cast<uint32_t>(&vt_get_ec);
            vt2[0xF0 / 4] = reinterpret_cast<uint32_t>(&vt_get_f0);
            vt2[0xE8 / 4] = reinterpret_cast<uint32_t>(&vt_get_e8);
            o2->vt = vt2;
            for (int i = 0; i != 3; ++i) o2->bit[i] = coin(25) ? 1 : 0;
            o2->id = e->id;
        }
        *reinterpret_cast<uint32_t*>(obj + 0x60) = reinterpret_cast<uint32_t>(o2);
    } else if (type == T_WALL) {
        const float ylohi[2] = {std::min(alt.p0[1], alt.p1[1]) - 2.0f, std::max(alt.p0[1], alt.p1[1]) + 2.0f};
        uint8_t* terrain = make_terrain(coin(70) ? ylohi : nullptr);
        uint8_t* ygrid = static_cast<uint8_t*>(arena.alloc(0xA8));
        *reinterpret_cast<uint32_t*>(ygrid + 0x9C) = reinterpret_cast<uint32_t>(terrain);
        uint8_t* x = static_cast<uint8_t*>(arena.alloc(0x10));
        *reinterpret_cast<uint32_t*>(x + 8) = reinterpret_cast<uint32_t>(ygrid);
        *reinterpret_cast<uint32_t*>(obj + 0xC) = reinterpret_cast<uint32_t>(x);
        *reinterpret_cast<float*>(obj + 0x64) = std::fabs(special_or(0, 6, 4));
        float* P = arena.make<float>(4);
        // wall segment crossing the projected query segment most of the time
        const float u = coin(20) ? (coin(50) ? 0.0f : 1.0f) : rf(0, 1);
        const float px = alt.p0[0] + u * (alt.p1[0] - alt.p0[0]), pz = alt.p0[2] + u * (alt.p1[2] - alt.p0[2]);
        const float dx = rf(-1, 1), dz = rf(-1, 1), ln = rf(0.5f, 6.0f);
        if (coin(85)) { P[0] = px - dx * ln; P[1] = pz - dz * ln; P[2] = px + dx * ln; P[3] = pz + dz * ln; }
        else { P[0] = special_or(-20, 20); P[1] = special_or(-20, 20); P[2] = special_or(-20, 20); P[3] = special_or(-20, 20); }
        uint32_t* cellp = arena.make<uint32_t>(2);
        cellp[0] = reinterpret_cast<uint32_t>(P);
        e->aux = reinterpret_cast<uint32_t>(cellp);
    } else if (type == T_BOX) {
        float* box = reinterpret_cast<float*>(obj + 0xA4);
        const float hx = rf(0.2f, 5), hy = rf(0.2f, 5), hz = rf(0.2f, 5);
        box[0] = cx - hx; box[1] = cy - hy; box[2] = cz - hz;
        box[3] = cx + hx; box[4] = cy + hy; box[5] = cz + hz;
        if (coin(6)) std::swap(box[0], box[3]);
        float* hp = reinterpret_cast<float*>(obj + 0x100);  // plane used by the stand-in serial stage
        hp[0] = special_or(-1, 1, 3); hp[1] = special_or(-1, 1, 3); hp[2] = special_or(-1, 1, 3);
        hp[3] = -(hp[0] * cx + hp[1] * cy + hp[2] * cz);
    }
    return e;
}

// ----------------------------------------------------------------------------------------------- queries
struct Query {
    nbc_segment seg;     // arg2: type used by the inside test
    nbc_segment alt;     // arg5: coordinates
    uint32_t mask = 0xC4B;  // unit | plane | box | wall (+1,2 ignored here)
    uint32_t mode = 0;
    bool stop = true;
    float extra = 0.0f;
};

struct Hit { uint32_t entry; float pos[3]; float t; };
static bool same_hit(const Hit& a, const Hit& b) {
    return a.entry == b.entry && f_bits(a.pos[0]) == f_bits(b.pos[0]) && f_bits(a.pos[1]) == f_bits(b.pos[1]) &&
           f_bits(a.pos[2]) == f_bits(b.pos[2]) && f_bits(a.t) == f_bits(b.t);
}

struct Result {
    std::vector<Hit> hits;
    bool found = false;
    uint32_t cells_done = 0;
    std::vector<uint32_t> log;
};

static inline float lerp_plain(float a, float b, float t) { float d = b - a; float m = d * t; return a + m; }

// stand-in for the serial stage 0x6F06A0: deterministic, uses the original plane_clip clone
static bool heavy_stage(const Query& q, uint32_t entry_addr, Hit* h) {
    const Entry* e = reinterpret_cast<const Entry*>(entry_addr);
    const uint8_t* obj = reinterpret_cast<const uint8_t*>(e->obj);
    ev(0x40000000u | e->id);
    float t = 0;
    alignas(16) float seg6[6] = {q.alt.p0[0], q.alt.p0[1], q.alt.p0[2], q.alt.p1[0], q.alt.p1[1], q.alt.p1[2]};
    if (K.plane(seg6, nullptr, reinterpret_cast<const float*>(obj + 0x100), 3, &t) != 1) return false;
    h->entry = entry_addr;
    h->t = t;
    for (int i = 0; i != 3; ++i) h->pos[i] = lerp_plain(seg6[i], seg6[3 + i], t);
    return true;
}

// owner-side walk shared by both implementations.  Sink methods are called exactly where the original performs
// the narrow phase for that entry type.
template <class Sink>
static void walk(const World& w, const Query& q, Sink& sink, std::vector<uint32_t>& bits8, std::vector<uint32_t>& bits40,
                 std::vector<uint32_t>& bits400, Result& res) {
    auto test_set = [](std::vector<uint32_t>& bits, uint32_t id) {
        const uint32_t word = id >> 5, mask = 1u << (id & 31);
        if (bits[word] & mask) return true;
        bits[word] |= mask;
        return false;
    };
    sink.begin_query();
    for (uint32_t cell : w.visit_order) {
        sink.begin_cell(cell);
        for (Entry* e = w.cells[cell]; e; e = e->next) {
            if (!(e->type & q.mask)) continue;
            const uint8_t* obj = reinterpret_cast<const uint8_t*>(e->obj);
            ev(0x10000000u | e->id);                           // 0x6DC9A0
            const uint8_t alive = (e->type == T_PLANE) ? obj[0x2F] : obj[0x30];
            if (!alive) continue;
            if (e->type == T_UNIT) {
                if (test_set(bits8, e->id)) continue;
                ev(0x11000000u | e->id);
                if (!nbc_unit_flag_ok(e, q.alt.type)) continue;  // 0x639661: obj+0x34 flag test per selector
                sink.unit(e);
            } else if (e->type == T_PLANE) {
                if (test_set(bits40, e->id)) continue;
                ev(0x12000000u | e->id);
                sink.plane(e);
            } else if (e->type == T_BOX) {
                if (test_set(bits400, e->id)) continue;
                ev(0x13000000u | e->id);
                sink.box(e);
            } else if (e->type == T_WALL) {
                sink.wall(e);
            }
        }
        sink.end_cell(cell);
        res.cells_done += 1;
        if (q.stop && sink.found) break;
    }
    sink.end_query();
    res.found = sink.found;
}

// -------------------- reference sink: original clones, immediate, exactly the per-entry blocks of 0x6392C0
struct RefSink {
    const Query& q;
    Result& res;
    bool found = false;
    alignas(16) float seg6[6];
    RefSink(const Query& qq, Result& r) : q(qq), res(r) {
        seg6[0] = q.alt.p0[0]; seg6[1] = q.alt.p0[1]; seg6[2] = q.alt.p0[2];
        seg6[3] = q.alt.p1[0]; seg6[4] = q.alt.p1[1]; seg6[5] = q.alt.p1[2];
    }
    void begin_query() {}
    void end_query() {}
    void begin_cell(uint32_t) {}
    void end_cell(uint32_t) {}
    void append(const Entry* e, float x, float y, float z, float t) {
        Hit h;
        h.entry = reinterpret_cast<uint32_t>(e);
        h.pos[0] = x; h.pos[1] = y; h.pos[2] = z; h.t = t;
        res.hits.push_back(h);
        found = true;
    }
    void plane(const Entry* e) {
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        float t = 0;
        if (K.plane(seg6, nullptr, reinterpret_cast<const float*>(obj + 0x30), q.mode, &t) == 0) return;
        const float x = lerp_plain(seg6[0], seg6[3], t), y = lerp_plain(seg6[1], seg6[4], t), z = lerp_plain(seg6[2], seg6[5], t);
        alignas(16) float pt[2] = {x, z};
        if (K.ring(reinterpret_cast<const void*>(*reinterpret_cast<uint32_t*>(obj + 8)), nullptr, pt) == 0) return;
        append(e, x, y, z, t);
    }
    void unit(const Entry* e) {
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        float t = 0;
        if (K.unit_hit(obj, nullptr, seg6, q.mode, &t, q.alt.type, q.extra) != 1) return;
        const float x = lerp_plain(seg6[0], seg6[3], t), y = lerp_plain(seg6[1], seg6[4], t), z = lerp_plain(seg6[2], seg6[5], t);
        if (q.seg.type == 1) {
            if (K.unit_inside(obj, nullptr, seg6) != 0) return;
        }
        append(e, x, y, z, t);
    }
    void wall(const Entry* e) {
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        float t = 0;
        nbc_segment altc = q.alt;
        if (K.wall(obj, nullptr, reinterpret_cast<const void*>(e->aux), &altc, q.mode, &t) != 1) return;
        append(e, lerp_plain(seg6[0], seg6[3], t), lerp_plain(seg6[1], seg6[4], t), lerp_plain(seg6[2], seg6[5], t), t);
    }
    void box(const Entry* e) {
        found = true;  // set when visited
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        float o1[2] = {0, 0}, o2[2] = {0, 0};
        if (K.box(seg6, nullptr, reinterpret_cast<const float*>(obj + 0xA4), q.mode, o1, o2) == 0) return;
        Hit h;
        if (heavy_stage(q, reinterpret_cast<uint32_t>(e), &h)) { res.hits.push_back(h); found = true; }
    }
};

// -------------------- topology mutation with undo.  The harness changes the world AFTER an owner result was recorded
// (right after the record, and again for the whole interval between record, nbc_run and nbc_merge) and puts it back
// before the next owner leaf runs, so the owner-side loop always sees the pristine game state at its own point while a
// late reader of the borrowed topology would see garbage.
struct Poison {
    struct Span { uint8_t* p; uint32_t bytes; size_t off; };
    std::vector<Span> spans;
    std::vector<uint8_t> saved;
    uint32_t fill = 0;
    void floats(void* p, uint32_t n) {
        Span s{static_cast<uint8_t*>(p), n * 4u, saved.size()};
        saved.insert(saved.end(), s.p, s.p + s.bytes);
        spans.push_back(s);
        for (uint32_t i = 0; i != n; ++i) std::memcpy(s.p + 4u * i, &fill, 4);
    }
    void restore() {
        for (size_t i = spans.size(); i-- != 0;) std::memcpy(spans[i].p, saved.data() + spans[i].off, spans[i].bytes);
        spans.clear();
        saved.clear();
    }
    // every float the narrow-phase leaf of this entry type reads: plane + ring nodes, unit capsule, wall segment + band +
    // terrain heightfield, box + the plane of the stand-in serial stage
    void topology(const Entry* e) {
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        if (e->type == T_PLANE) {
            floats(obj + 0x30, 4);
            Node* head = reinterpret_cast<Node*>(*reinterpret_cast<uint32_t*>(obj + 8));
            Node* n = head;
            do { floats(&n->x, 2); n = n->next; } while (n != head);
        } else if (e->type == T_UNIT) {
            floats(obj + 0x48, 5);
        } else if (e->type == T_WALL) {
            floats(obj + 0x64, 1);
            floats(reinterpret_cast<void*>(*reinterpret_cast<const uint32_t*>(e->aux)), 4);
            const uint8_t* x = reinterpret_cast<const uint8_t*>(*reinterpret_cast<const uint32_t*>(obj + 0xC));
            const uint8_t* y = reinterpret_cast<const uint8_t*>(*reinterpret_cast<const uint32_t*>(x + 8));
            const uint8_t* g = reinterpret_cast<const uint8_t*>(*reinterpret_cast<const uint32_t*>(y + 0x9C));
            const uint32_t shift = *reinterpret_cast<const uint32_t*>(g + 8);
            floats(reinterpret_cast<void*>(*reinterpret_cast<const uint32_t*>(g)), 2u << (2u * shift));
        } else {
            floats(obj + 0xA4, 6);
            floats(obj + 0x100, 4);
        }
    }
};

static Hit to_hit(const nbc_hit& h) {
    Hit r;
    r.entry = h.entry;
    for (int i = 0; i != 3; ++i) r.pos[i] = h.pos[i];
    r.t = h.t;
    return r;
}
static nbc_hit to_nbc(const Hit& h) {
    nbc_hit r;
    r.entry = h.entry;
    for (int i = 0; i != 3; ++i) r.pos[i] = h.pos[i];
    r.t = h.t;
    return r;
}

// which candidates the owner computes itself:  NONE = all go to workers (ABI 2 behaviour), MIXED = per game object (so
// duplicate entries sharing topology never feed a worker from memory the harness mutates), ALL = no worker job at all
enum Own { OWN_NONE, OWN_MIXED, OWN_ALL };

// -------------------- port sink: owner adds candidates; end of cell / query runs workers and merges in order.
// Owner-computed entries run the ORIGINAL clones (RefSink) right at the add point and record only the outcome.
struct PortSink {
    const Query& q;
    Result& res;
    bool whole_query;
    uint32_t pool_dispatch;
    uint32_t pool_user;
    uint32_t chunk_items;
    uint32_t min_parallel;
    bool allow_box;
    Own own;
    bool found = false;
    std::vector<nbc_cand> cands;
    std::vector<nbc_result> results;
    nbc_batch* batch;
    uint32_t cell_ordinal = 0;
    Result scratch;  // owner-computed leaves append here
    RefSink ref;     // original machine code, owner side
    std::map<uint32_t, bool> owner_obj;
    struct Owned { const Entry* e; uint32_t slot; bool hit; nbc_hit h; };
    std::vector<Owned> owned;  // owner results recorded in the current batch
    Poison poison;
    uint32_t fills = 0;
    uint32_t owner_hits = 0, owner_misses = 0, pure_added = 0, poison_effective = 0, empty_pure_runs = 0;
    PortSink(const Query& qq, Result& r, bool whole, uint32_t disp, uint32_t user, uint32_t chunk, uint32_t minpar, bool allow,
             Own own_mode)
        : q(qq), res(r), whole_query(whole), pool_dispatch(disp), pool_user(user), chunk_items(chunk), min_parallel(minpar),
          allow_box(allow), own(own_mode), ref(qq, scratch) {
        cands.resize(4096);
        results.resize(4096);
        batch = static_cast<nbc_batch*>(_aligned_malloc(sizeof(nbc_batch), 16));
        uint32_t flags = 0;
        if (q.stop && !whole) flags |= NBC_BF_STOP_FIRST_CELL;
        if (allow_box) flags |= NBC_BF_ALLOW_SERIAL_REORDER;
        require(nbc_batch_init(batch, cands.data(), results.data(), 4096, &q.seg, &q.alt, flags, &WorkerBindings) == NBC_OK, "batch init");
        batch->body_entry = pool_dispatch ? reinterpret_cast<uint32_t>(&nbc_chunk_body) : 0u;
        batch->dispatch = pool_dispatch;
        batch->dispatch_user = pool_user;
        batch->chunk_items = chunk_items;
        batch->min_parallel = min_parallel;
    }
    ~PortSink() { _aligned_free(batch); }
    void begin_query() {}
    void begin_cell(uint32_t) { if (!whole_query) nbc_batch_reset(batch); ++cell_ordinal; }
    static nbc_u32 NBC_CALL serial_cb(void* user, nbc_u32 index, nbc_hit* hit) {
        PortSink* self = static_cast<PortSink*>(user);
        Hit h;
        if (!heavy_stage(self->q, self->batch->cands[index].entry, &h)) return 0;
        hit->entry = h.entry;
        hit->pos[0] = h.pos[0]; hit->pos[1] = h.pos[1]; hit->pos[2] = h.pos[2];
        hit->t = h.t;
        return 1;
    }
    uint32_t next_fill() {
        static const uint32_t fills_bits[] = {0x4E6E6B28u, 0u, 0xBF800000u, 0x41200000u};
        return fills_bits[fills++ % 4];
    }
    void run_leaf(const Entry* e) {
        if (e->type == T_PLANE) ref.plane(e);
        else if (e->type == T_UNIT) ref.unit(e);
        else if (e->type == T_WALL) ref.wall(e);
        else ref.box(e);
    }
    bool owner_computed(const Entry* e) {
        if (own == OWN_NONE) return false;
        if (own == OWN_ALL) return true;
        auto it = owner_obj.find(e->obj);
        if (it != owner_obj.end()) return it->second;
        const bool v = (e->type == T_BOX && !allow_box) || coin(50);  // strict boxes can only be owner computed
        owner_obj.emplace(e->obj, v);
        return v;
    }
    // The original loop computes this entry's narrow phase NOW: run the original leaf on the pristine topology, hand the
    // batch only the outcome, then let the world change under it.
    void record_owner(const Entry* e) {
        poison.restore();
        scratch.hits.clear();
        run_leaf(e);
        Owned o{};
        o.e = e;
        o.slot = batch->count;
        o.hit = !scratch.hits.empty();
        if (o.hit) o.h = to_nbc(scratch.hits.back());
        add(nbc_add_owner_result(batch, reinterpret_cast<uint32_t>(e), cell_ordinal,
                                 e->type == T_BOX ? NBC_CF_FOUND_ON_VISIT : 0u, o.hit ? &o.h : nullptr));
        (o.hit ? owner_hits : owner_misses) += 1;
        owned.push_back(o);
        poison.fill = next_fill();
        poison.topology(e);
    }
    void flush() {
        // the world is mutated between record and run/merge
        poison.restore();
        for (const Owned& o : owned) { poison.fill = next_fill(); poison.topology(o.e); }
        {   // sensitivity: the original leaf on the mutated topology must be able to disagree with the stored outcome
            std::vector<uint32_t>* log = g_log;
            g_log = nullptr;
            for (const Owned& o : owned) {
                scratch.hits.clear();
                run_leaf(o.e);
                bool same = (!scratch.hits.empty()) == o.hit;
                if (same && o.hit) same = same_hit(scratch.hits.back(), to_hit(o.h));
                if (!same) ++poison_effective;
            }
            g_log = log;
        }
        const uint32_t pure = batch->count - static_cast<uint32_t>(owned.size());
        std::vector<nbc_result> before;
        before.reserve(owned.size());
        for (const Owned& o : owned) before.push_back(batch->results[o.slot]);
        ntw_pool* pm = reinterpret_cast<ntw_pool*>(pool_user);
        const uint32_t calls0 = pm->st_calls, disp0 = batch->st_dispatched;
        require(nbc_run(batch) == NBC_OK, "nbc_run");
        if (!pure) {
            require(batch->st_dispatched == disp0, "owner-only batch was dispatched");
            require(pm->st_calls == calls0, "owner-only batch woke the worker team");
            ++empty_pure_runs;
        }
        for (size_t i = 0; i != owned.size(); ++i)
            require(std::memcmp(&before[i], &batch->results[owned[i].slot], sizeof(nbc_result)) == 0,
                    "nbc_run overwrote an owner-computed result");
        std::vector<nbc_hit> out(batch->count + 1);
        nbc_merge_info info;
        require(nbc_merge(batch, out.data(), static_cast<uint32_t>(out.size()), &serial_cb, this, &info) == NBC_OK, "nbc_merge");
        for (uint32_t i = 0; i != info.hits; ++i) res.hits.push_back(to_hit(out[i]));
        if (info.found) found = true;
        for (uint32_t i = 0; i != batch->count; ++i) {
            require(batch->results[i].status != NBC_R_FAULT, "port reported FAULT");
        }
        poison.restore();
        owned.clear();
    }
    void end_cell(uint32_t) { if (!whole_query) { if (batch->count) flush(); nbc_batch_reset(batch); } }
    void end_query() { if (whole_query && batch->count) flush(); }
    void add(uint32_t rc) { require(rc == NBC_OK, "nbc_add", std::to_string(rc)); }
    void plane(const Entry* e) {
        if (owner_computed(e)) { record_owner(e); return; }
        ++pure_added;
        add(nbc_add_plane_ring_entry(batch, e, cell_ordinal, q.mode));
    }
    void wall(const Entry* e) {
        if (owner_computed(e)) { record_owner(e); return; }
        ++pure_added;
        add(nbc_add_wall_entry(batch, e, cell_ordinal, q.mode));
    }
    void box(const Entry* e) {
        if (owner_computed(e)) { record_owner(e); return; }
        ++pure_added;
        add(nbc_add_box_entry(batch, e, cell_ordinal, q.mode));
    }
    void unit(const Entry* e) {
        if (owner_computed(e)) { record_owner(e); return; }
        ++pure_added;
        // owner-side of 0x809620: virtual slot +0x18 always; 0x5B77A0 only for selector 3 with a non-null result
        uint8_t* obj = reinterpret_cast<uint8_t*>(e->obj);
        uint32_t* vt = *reinterpret_cast<uint32_t**>(obj);
        typedef uint32_t(__fastcall * vfn)(void*, void*);
        uint32_t obj2 = reinterpret_cast<vfn>(vt[6])(obj, nullptr);
        uint32_t b5 = 0;
        if (obj2 != 0 && q.alt.type == 3) b5 = K.b5b77(reinterpret_cast<void*>(obj2), nullptr);
        add(nbc_add_unit_entry(batch, e, cell_ordinal, q.mode, obj2, b5 & 0xFF, q.alt.type, q.extra));
    }
};

static Query make_query(bool stop) {
    Query q;
    const uint32_t types[] = {1, 1, 2, 3, 3, 4};
    q.seg.type = types[rng() % 6];
    for (int i = 0; i != 3; ++i) { q.seg.p0[i] = rf(-12, 12); q.seg.p1[i] = q.seg.p0[i] + rf(-20, 20); }
    q.seg.p0[1] = rf(0, 18); q.seg.p1[1] = q.seg.p0[1] + rf(-6, 6);
    if (coin(8)) { q.seg.p1[0] = q.seg.p0[0]; q.seg.p1[2] = q.seg.p0[2]; }
    if (coin(5)) for (int i = 0; i != 3; ++i) q.seg.p0[i] = special_or(-3, 3);
    q.alt = q.seg;
    q.mode = rng() % 4;
    q.stop = stop;
    q.extra = coin(50) ? 0.0f : rf(0, 2);
    return q;
}

static void populate(World& w, const Query& q, bool with_box, uint32_t per_cell_max) {
    w.dim = 5;
    w.cells.assign(w.dim * w.dim, nullptr);
    std::vector<uint32_t> order;
    for (uint32_t i = 0; i != w.dim * w.dim; ++i) order.push_back(i);
    std::shuffle(order.begin(), order.end(), rng);
    order.resize(3 + rng() % 8);
    w.visit_order = order;
    const uint32_t kinds[4] = {T_PLANE, T_UNIT, T_WALL, T_BOX};
    for (uint32_t c = 0; c != w.dim * w.dim; ++c) {
        const uint32_t n = rng() % (per_cell_max + 1);
        Entry* tail = nullptr;
        for (uint32_t i = 0; i != n; ++i) {
            uint32_t type = kinds[rng() % (with_box ? 4 : 3)];
            Entry* e = make_entry(w, type, q.alt);
            // duplicate an existing entry in another cell sometimes (visited bit / non-deduplicated walls)
            if (coin(8) && c != 0 && w.cells[0]) {
                Entry* d = arena.make<Entry>();
                *d = *w.cells[0];
                d->next = nullptr;
                e = d;
            }
            if (!tail) w.cells[c] = e; else tail->next = e;
            tail = e;
        }
    }
}

static std::string describe(const std::vector<Hit>& v) {
    std::string s;
    char buf[96];
    for (const Hit& h : v) {
        std::snprintf(buf, sizeof(buf), "[%08x %08x %08x %08x t=%08x]", h.entry, f_bits(h.pos[0]), f_bits(h.pos[1]), f_bits(h.pos[2]), f_bits(h.t));
        s += buf;
    }
    return s;
}

struct Totals {
    uint32_t worlds = 0, hits = 0, found = 0, cells = 0, entries = 0, box_serial = 0;
    uint32_t owner_hits = 0, owner_misses = 0, pure = 0, poison_effective = 0, empty_pure_runs = 0;
};

static void run_world(Pool& pool, ntw_pool* poolmem, Totals& tot, bool stop, bool whole, bool with_box, bool dispatch,
                      uint32_t chunk, uint32_t minpar, uint32_t per_cell_max, Own own = OWN_NONE, bool allow_reorder = true) {
    arena.reset();
    Query q = make_query(stop);
    World w;
    populate(w, q, with_box, per_cell_max);
    const uint32_t ids = w.next_id + 8;
    std::vector<uint32_t> b1((ids >> 5) + 2), b2(b1.size()), b3(b1.size());
    Result ref, got;
    {
        std::vector<uint32_t> l;
        g_log = &l;
        RefSink sink(q, ref);
        walk(w, q, sink, b1, b2, b3, ref);
        ref.log = l;
        g_log = nullptr;
    }
    std::fill(b1.begin(), b1.end(), 0u); std::fill(b2.begin(), b2.end(), 0u); std::fill(b3.begin(), b3.end(), 0u);
    {
        std::vector<uint32_t> l;
        g_log = &l;
        PortSink sink(q, got, whole, dispatch ? reinterpret_cast<uint32_t>(pool.dispatch) : 0u, reinterpret_cast<uint32_t>(poolmem),
                      chunk, minpar, with_box && allow_reorder, own);
        walk(w, q, sink, b1, b2, b3, got);
        got.log = l;
        g_log = nullptr;
        tot.box_serial += sink.batch->st_serial;
        tot.owner_hits += sink.owner_hits;
        tot.owner_misses += sink.owner_misses;
        tot.pure += sink.pure_added;
        tot.poison_effective += sink.poison_effective;
        tot.empty_pure_runs += sink.empty_pure_runs;
    }
    const std::string ctx = std::string(" stop=") + (stop ? "1" : "0") + " whole=" + (whole ? "1" : "0") + " box=" + (with_box ? "1" : "0") +
                            " reorder=" + (allow_reorder ? "1" : "0") + " own=" + std::to_string(static_cast<int>(own)) + " dispatch=" + (dispatch ? "1" : "0");
    require(ref.found == got.found, "found flag differs", ctx);
    require(ref.cells_done == got.cells_done, "cells processed differ", ctx);
    require(ref.hits.size() == got.hits.size(), "hit count differs", ctx + " ref=" + describe(ref.hits) + " got=" + describe(got.hits));
    for (size_t i = 0; i != ref.hits.size(); ++i) require(same_hit(ref.hits[i], got.hits[i]), "hit differs", ctx + " ref=" + describe(ref.hits) + " got=" + describe(got.hits));
    // worker BOX candidates run their serial stage at merge, after later owner steps: the owner-side log differs by design
    if (!with_box || !allow_reorder || own == OWN_ALL) require(ref.log == got.log, "owner-side event order differs", ctx);
    tot.worlds += 1;
    tot.hits += static_cast<uint32_t>(ref.hits.size());
    tot.found += ref.found ? 1 : 0;
    tot.cells += ref.cells_done;
    for (uint32_t c = 0; c != w.dim * w.dim; ++c) for (Entry* e = w.cells[c]; e; e = e->next) tot.entries += 1;
}

// -------- API contract tests (order rules)
static void api_tests() {
    arena.reset();
    nbc_segment seg{};
    seg.type = 1; seg.p0[0] = seg.p0[1] = seg.p0[2] = 0; seg.p1[0] = seg.p1[1] = seg.p1[2] = 1;
    nbc_cand cands[4];
    nbc_result res[4];
    nbc_batch* b = static_cast<nbc_batch*>(_aligned_malloc(sizeof(nbc_batch), 16));
    require(nbc_batch_init(b, cands, res, 2, &seg, nullptr, NBC_BF_STOP_FIRST_CELL, &WorkerBindings) == NBC_OK, "init");
    const float box[6] = {0, 0, 0, 1, 1, 1};
    require(nbc_add_box(b, 1, 1, 0, box) == NBC_E_STRICT, "box needs the reorder flag");
    const float plane[4] = {0, 1, 0, 0};
    require(nbc_add_plane_ring(b, 1, 1, 0, plane, nullptr) == NBC_OK, "add plane");
    require(nbc_add_plane_ring(b, 2, 2, 0, plane, nullptr) == NBC_E_CELL, "second cell in stop mode");
    require(nbc_add_plane_ring(b, 3, 1, 0, plane, nullptr) == NBC_OK, "same cell again");
    require(nbc_add_plane_ring(b, 4, 1, 0, plane, nullptr) == NBC_E_FULL, "capacity");
    nbc_hit out[2];
    nbc_merge_info info;
    res[0].status = NBC_R_SERIAL; res[1].status = NBC_R_MISS;
    require(nbc_merge(b, out, 2, nullptr, nullptr, &info) == NBC_E_SERIAL, "serial stage needs a callback");
    _aligned_free(b);
    // owner-side flag test truth table (selector 1/4 -> bit 0x10, 2/3 -> bit 8, else skip)
    uint8_t* uo = static_cast<uint8_t*>(arena.alloc(0x100));
    Entry* ue = arena.make<Entry>();
    ue->obj = reinterpret_cast<uint32_t>(uo);
    for (uint32_t sel = 0; sel != 6; ++sel)
        for (uint32_t fl = 0; fl != 0x20; fl += 8) {
            *reinterpret_cast<uint32_t*>(uo + 0x34) = fl;
            const bool expect = (sel == 1 || sel == 4) ? (fl & 0x10) != 0 : (sel == 2 || sel == 3) ? (fl & 8) != 0 : false;
            require((nbc_unit_flag_ok(ue, sel) != 0) == expect, "unit flag truth table");
        }
    std::printf("api contract: ok\n");
}

// -------- owner-computed result API contract (ABI 3): slot/cell/capacity rules, merge order, stop rules, dispatcher use,
// and that nbc_run neither recomputes nor overwrites a recorded outcome
static uint32_t g_stub_calls = 0;
static void NBC_CALL stub_dispatch(void*, nbc_body_fn body, nbc_u32 chunks, void* ctx) {
    ++g_stub_calls;
    for (nbc_u32 c = 0; c != chunks; ++c) body(ctx, c);
}

struct TestBatch {
    std::vector<nbc_cand> cands;
    std::vector<nbc_result> results;
    nbc_batch* b;
    TestBatch(uint32_t cap, const nbc_segment& seg, uint32_t flags) : cands(cap), results(cap) {
        std::memset(results.data(), 0xCD, results.size() * sizeof(nbc_result));  // garbage: only the code may define a slot
        b = static_cast<nbc_batch*>(_aligned_malloc(sizeof(nbc_batch), 16));
        require(nbc_batch_init(b, cands.data(), results.data(), cap, &seg, nullptr, flags, &WorkerBindings) == NBC_OK, "owner test init");
        b->dispatch = reinterpret_cast<uint32_t>(&stub_dispatch);
        b->body_entry = reinterpret_cast<uint32_t>(&nbc_chunk_body);
        b->chunk_items = 1;
        b->min_parallel = 2;
    }
    ~TestBatch() { _aligned_free(b); }
    TestBatch(const TestBatch&) = delete;
    TestBatch& operator=(const TestBatch&) = delete;
};

// plane y = 0.5 crossed by (0,0,0)->(0,1,0) at t = 0.5; ring = unit square around (cx, cz): hit when it holds (0, 0)
struct PureFix { float plane[4]; Node* ring; Entry* entry; };
static PureFix make_pure_fix(float cx, float cz) {
    PureFix f;
    const float plane[4] = {0.0f, 1.0f, 0.0f, -0.5f};
    std::memcpy(f.plane, plane, sizeof(plane));
    Node* n = arena.make<Node>(4);
    static const float xs[4] = {-1, 1, 1, -1}, zs[4] = {-1, -1, 1, 1};
    for (int i = 0; i != 4; ++i) { n[i].x = cx + xs[i]; n[i].z = cz + zs[i]; n[i].next = &n[(i + 1) % 4]; }
    f.ring = n;
    Entry* e = arena.make<Entry>();
    e->type = T_PLANE;
    uint8_t* obj = new_obj();
    e->obj = reinterpret_cast<uint32_t>(obj);
    std::memcpy(obj + 0x30, plane, sizeof(plane));
    *reinterpret_cast<uint32_t*>(obj + 8) = reinterpret_cast<uint32_t>(n);
    f.entry = e;
    return f;
}
static bool ref_pure(RefSink& ref, Result& scratch, const PureFix& f, Hit* out) {
    scratch.hits.clear();
    ref.plane(f.entry);
    if (scratch.hits.empty()) return false;
    *out = scratch.hits.back();
    return true;
}

static void owner_api_tests() {
    arena.reset();
    nbc_segment seg{};
    seg.type = 2;
    seg.p1[1] = 1.0f;
    Query q;
    q.seg = seg;
    q.alt = seg;
    q.mode = 0;
    Result scratch;
    RefSink ref(q, scratch);
    const PureFix near1 = make_pure_fix(0, 0), near2 = make_pure_fix(0, 0), far1 = make_pure_fix(50, 50);
    Hit h_near1, h_near2, tmp;
    require(ref_pure(ref, scratch, near1, &h_near1) && ref_pure(ref, scratch, near2, &h_near2), "owner fixture: reference plane/ring must hit");
    require(!ref_pure(ref, scratch, far1, &tmp), "owner fixture: far ring must miss");
    const auto add_pure = [&](nbc_batch* b, const PureFix& f, uint32_t cell) {
        return nbc_add_plane_ring(b, reinterpret_cast<uint32_t>(f.entry), cell, 0, f.plane, f.ring);
    };
    const auto same_nbc = [](const nbc_hit& a, const nbc_hit& b) { return std::memcmp(&a, &b, sizeof(nbc_hit)) == 0; };
    // owner outcomes with awkward bit patterns (quiet NaN payload, -0, denormals) must round-trip untouched
    const nbc_hit oh1 = {0xA201u, {1.5f, -0.0f, bits_f(0x7FC12345u)}, 0.25f};
    const nbc_hit oh2 = {0xA202u, {bits_f(0x00000001u), 3.0e30f, -2.5f}, bits_f(0x80000001u)};
    nbc_hit out[64];
    nbc_merge_info info;

    {   // A: owner and worker candidates interleaved over three cells; the dispatcher runs (3 worker jobs, 1 per chunk)
        TestBatch t(16, seg, 0);
        nbc_batch* b = t.b;
        require(add_pure(b, near1, 1) == NBC_OK, "A pure 0");
        require(nbc_add_owner_result(b, 0xA101u, 1, 0, nullptr) == NBC_OK, "A owner miss");
        require(nbc_add_owner_result(b, oh1.entry, 1, 0, &oh1) == NBC_OK, "A owner hit");
        require(add_pure(b, far1, 1) == NBC_OK, "A pure miss");
        require(nbc_add_owner_result(b, 0xA102u, 2, NBC_CF_FOUND_ON_VISIT, nullptr) == NBC_OK, "A owner found-on-visit");
        require(add_pure(b, near2, 2) == NBC_OK, "A pure 5");
        require(nbc_add_owner_result(b, oh2.entry, 3, 0, &oh2) == NBC_OK, "A owner hit 2");
        require(b->count == 7 && b->pure == 3, "A counts");
        const uint32_t owner_slots[4] = {1, 2, 4, 6};
        nbc_result before[4];
        for (int i = 0; i != 4; ++i) before[i] = t.results[owner_slots[i]];
        const uint32_t calls = g_stub_calls;
        require(nbc_run(b) == NBC_OK, "A run");
        require(g_stub_calls == calls + 1 && b->st_dispatched == 1 && b->st_chunks == 3 && b->st_owner == 4,
                "A: one dispatch over the three worker candidates only");
        for (int i = 0; i != 4; ++i)
            require(std::memcmp(&before[i], &t.results[owner_slots[i]], sizeof(nbc_result)) == 0, "A: run overwrote an owner result");
        for (uint32_t i = 0; i != 7; ++i)
            require(t.results[i].pad[0] == 0 && t.results[i].pad[1] == 0 && t.results[i].pad[2] == 0, "A: work index left behind");
        require(nbc_merge(b, out, 8, nullptr, nullptr, &info) == NBC_OK, "A merge");
        require(info.hits == 4 && info.found == 1 && info.consumed == 7 && info.serial == 0, "A merge counters");
        require(same_nbc(out[0], to_nbc(h_near1)) && same_nbc(out[1], oh1) && same_nbc(out[2], to_nbc(h_near2)) && same_nbc(out[3], oh2),
                "A: merge order / values");
        require(nbc_merge(b, out, 3, nullptr, nullptr, &info) == NBC_E_FULL && info.overflow == 1 && info.hits == 3, "A: output capacity");
    }
    {   // B: merge applies first-found-cell stopping to owner results (flag set after the adds so every cell is present)
        TestBatch t(8, seg, 0);
        nbc_batch* b = t.b;
        require(nbc_add_owner_result(b, 0xB1u, 1, 0, nullptr) == NBC_OK, "B 0");
        require(nbc_add_owner_result(b, oh1.entry, 2, 0, &oh1) == NBC_OK, "B 1");
        require(nbc_add_owner_result(b, 0xB3u, 2, NBC_CF_FOUND_ON_VISIT, nullptr) == NBC_OK, "B 2");
        require(nbc_add_owner_result(b, oh2.entry, 3, 0, &oh2) == NBC_OK, "B 3");
        const uint32_t calls = g_stub_calls;
        require(nbc_run(b) == NBC_OK, "B run");
        require(g_stub_calls == calls && b->st_dispatched == 0 && b->st_chunks == 0 && b->st_owner == 4,
                "B: an owner-only batch must not reach the dispatcher");
        b->flags |= NBC_BF_STOP_FIRST_CELL;
        require(nbc_merge(b, out, 4, nullptr, nullptr, &info) == NBC_OK, "B merge");
        require(info.hits == 1 && info.consumed == 3 && info.found == 1 && same_nbc(out[0], oh1), "B: stop after the first found cell");
        b->flags &= ~NBC_BF_STOP_FIRST_CELL;
        require(nbc_merge(b, out, 4, nullptr, nullptr, &info) == NBC_OK, "B merge all");
        require(info.hits == 2 && info.consumed == 4 && same_nbc(out[0], oh1) && same_nbc(out[1], oh2), "B: full query keeps going");
    }
    {   // C: found-on-visit alone (a miss) makes the cell the stop cell; a plain owner miss does not
        TestBatch t(4, seg, 0);
        nbc_batch* b = t.b;
        require(nbc_add_owner_result(b, 0xC1u, 1, NBC_CF_FOUND_ON_VISIT, nullptr) == NBC_OK, "C 0");
        require(nbc_add_owner_result(b, oh1.entry, 2, 0, &oh1) == NBC_OK, "C 1");
        require(nbc_run(b) == NBC_OK, "C run");
        b->flags |= NBC_BF_STOP_FIRST_CELL;
        require(nbc_merge(b, out, 4, nullptr, nullptr, &info) == NBC_OK && info.hits == 0 && info.consumed == 1 && info.found == 1,
                "C: found-on-visit miss stops the query");
        b->flags &= ~NBC_BF_STOP_FIRST_CELL;
        require(nbc_merge(b, out, 4, nullptr, nullptr, &info) == NBC_OK && info.hits == 1 && info.consumed == 2 && info.found == 1,
                "C: without stop the next cell is consumed");
        TestBatch u(2, seg, NBC_BF_STOP_FIRST_CELL);
        require(nbc_add_owner_result(u.b, 0xC2u, 5, 0, nullptr) == NBC_OK, "C plain miss");
        require(nbc_run(u.b) == NBC_OK, "C plain run");
        require(nbc_merge(u.b, out, 2, nullptr, nullptr, &info) == NBC_OK && info.hits == 0 && info.consumed == 1 && info.found == 0,
                "C: a plain owner miss does not set found");
    }
    {   // D: stop-mode add rules and refusals consume no slot
        TestBatch t(4, seg, NBC_BF_STOP_FIRST_CELL);
        nbc_batch* b = t.b;
        require(nbc_add_owner_result(b, oh1.entry, 7, NBC_CF_FOUND_ON_VISIT, &oh1) == NBC_OK, "D first");
        require(nbc_add_owner_result(b, 0xD2u, 8, 0, nullptr) == NBC_E_CELL, "D: owner result in a second cell");
        require(add_pure(b, near1, 8) == NBC_E_CELL, "D: worker candidate in a second cell");
        require(nbc_add_owner_result(b, 0xD3u, 7, 0, nullptr) == NBC_OK, "D same cell");
        require(nbc_add_owner_result(b, 0xD4u, 7, 2u, nullptr) == NBC_E_ARG, "D: unknown flag");
        require(nbc_add_owner_result(b, 0xD5u, 7, 0, &oh1) == NBC_E_ARG, "D: hit identity mismatch");
        require(nbc_add_owner_result(nullptr, oh1.entry, 7, 0, &oh1) == NBC_E_ARG, "D: null batch");
        require(b->count == 2 && b->pure == 0, "D: refused adds consumed a slot");
        nbc_batch_reset(b);
        require(b->count == 0 && b->pure == 0, "D reset");
        require(nbc_add_owner_result(b, 0xD6u, 9, 0, nullptr) == NBC_OK && add_pure(b, near1, 9) == NBC_OK && b->pure == 1, "D reuse after reset");
    }
    {   // E: capacity boundary shared by owner results and worker candidates
        TestBatch t(3, seg, 0);
        nbc_batch* b = t.b;
        require(add_pure(b, near1, 1) == NBC_OK, "E 0");
        require(nbc_add_owner_result(b, oh1.entry, 1, 0, &oh1) == NBC_OK, "E 1");
        require(nbc_add_owner_result(b, 0xE3u, 1, 0, nullptr) == NBC_OK, "E 2");
        const nbc_result snap = t.results[1];
        require(nbc_add_owner_result(b, oh2.entry, 1, 0, &oh2) == NBC_E_FULL, "E: owner result over capacity");
        require(add_pure(b, near2, 1) == NBC_E_FULL, "E: worker candidate over capacity");
        require(std::memcmp(&snap, &t.results[1], sizeof(snap)) == 0 && b->count == 3 && b->pure == 1, "E: refusal changed the batch");
        require(nbc_run(b) == NBC_OK, "E run");
        require(nbc_merge(b, out, 2, nullptr, nullptr, &info) == NBC_OK && info.hits == 2 && same_nbc(out[0], to_nbc(h_near1)) &&
                    same_nbc(out[1], oh1),
                "E merge");
    }
    {   // F: two worker jobs hidden among 46 owner results: chunks follow the real work and never touch the owner slots
        TestBatch t(48, seg, 0);
        nbc_batch* b = t.b;
        std::vector<nbc_hit> expect;
        std::vector<uint32_t> slots;
        for (uint32_t i = 0; i != 48; ++i) {
            const uint32_t cell = 1 + i / 16;
            if (i == 30 || i == 47) {
                require(add_pure(b, i == 30 ? near1 : near2, cell) == NBC_OK, "F pure");
                expect.push_back(to_nbc(i == 30 ? h_near1 : h_near2));
            } else if (i % 3 == 0) {
                nbc_hit h = oh1;
                h.entry = 0xF000u + i;
                h.t = static_cast<float>(i);
                require(nbc_add_owner_result(b, h.entry, cell, 0, &h) == NBC_OK, "F owner hit");
                expect.push_back(h);
                slots.push_back(i);
            } else {
                require(nbc_add_owner_result(b, 0xF000u + i, cell, (i & 1) ? NBC_CF_FOUND_ON_VISIT : 0u, nullptr) == NBC_OK, "F owner miss");
                slots.push_back(i);
            }
        }
        require(b->count == 48 && b->pure == 2, "F counts");
        std::vector<nbc_result> before;
        for (uint32_t s : slots) before.push_back(t.results[s]);
        const uint32_t calls = g_stub_calls;
        require(nbc_run(b) == NBC_OK, "F run");
        require(g_stub_calls == calls + 1 && b->st_chunks == 2 && b->st_owner == 46, "F: two chunks for two worker jobs");
        for (size_t i = 0; i != slots.size(); ++i)
            require(std::memcmp(&before[i], &t.results[slots[i]], sizeof(nbc_result)) == 0, "F: run overwrote an owner result");
        for (uint32_t i = 0; i != 48; ++i)
            require(t.results[i].pad[0] == 0 && t.results[i].pad[1] == 0 && t.results[i].pad[2] == 0, "F: work index left behind");
        require(nbc_merge(b, out, 64, nullptr, nullptr, &info) == NBC_OK && info.hits == expect.size() && info.found == 1 && info.consumed == 48,
                "F merge");
        for (size_t i = 0; i != expect.size(); ++i) require(same_nbc(out[i], expect[i]), "F: merge order / values");
    }
    {   // G: empty and below-threshold batches stay on the owner thread
        TestBatch t(8, seg, 0);
        nbc_batch* b = t.b;
        const uint32_t calls = g_stub_calls;
        require(nbc_run(b) == NBC_OK && b->st_dispatched == 0 && b->st_chunks == 0, "G empty");
        require(nbc_add_owner_result(b, oh1.entry, 1, 0, &oh1) == NBC_OK, "G owner");
        require(add_pure(b, near1, 1) == NBC_OK, "G pure");
        require(nbc_add_owner_result(b, 0x61u, 1, 0, nullptr) == NBC_OK, "G owner miss");
        require(nbc_run(b) == NBC_OK, "G run");
        require(g_stub_calls == calls && b->st_dispatched == 0 && b->st_chunks == 1 && b->st_owner == 2, "G: one worker job runs inline");
        require(nbc_merge(b, out, 4, nullptr, nullptr, &info) == NBC_OK && info.hits == 2 && same_nbc(out[0], oh1) &&
                    same_nbc(out[1], to_nbc(h_near1)),
                "G merge");
    }
    {   // H: an owner slot that is not MISS/HIT was overwritten behind the batch's back: the merge refuses it
        TestBatch t(2, seg, 0);
        nbc_batch* b = t.b;
        require(nbc_add_owner_result(b, oh1.entry, 1, 0, &oh1) == NBC_OK, "H add");
        t.results[0].status = NBC_R_SERIAL;
        require(nbc_merge(b, out, 2, nullptr, nullptr, &info) == NBC_E_ARG && info.hits == 0, "H: tampered owner result");
    }
    std::printf("owner result api: ok\n");
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 4) {
        std::printf("usage: harness reference-kit.bin worker-kit.bin native_worker_dispatch.dll [worlds]\n");
        return 2;
    }
    char kitPath[MAX_PATH], workerPath[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, argv[1], -1, kitPath, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, workerPath, MAX_PATH, nullptr, nullptr);
    const uint32_t worlds = argc > 4 ? static_cast<uint32_t>(_wtoi(argv[4])) : 600u;
    K = load_kit(kitPath, false);
    WorkerK = load_kit(workerPath, true);
    WorkerBindings = {reinterpret_cast<uint32_t>(WorkerK.plane), reinterpret_cast<uint32_t>(WorkerK.ring),
                      reinterpret_cast<uint32_t>(WorkerK.box), reinterpret_cast<uint32_t>(WorkerK.wall),
                      reinterpret_cast<uint32_t>(WorkerK.unit_hit), reinterpret_cast<uint32_t>(WorkerK.unit_inside)};
    Pool pool = load_pool(argv[3]);
    alignas(64) static ntw_pool poolmem;
    ntw_pool_config cfg{};
    cfg.abi = NTW_POOL_ABI;
    cfg.workers = 3;
    cfg.api.create_event = reinterpret_cast<uint32_t>(&CreateEventW);
    cfg.api.close_handle = reinterpret_cast<uint32_t>(&CloseHandle);
    cfg.api.set_event = reinterpret_cast<uint32_t>(&SetEvent);
    cfg.api.wait_single = reinterpret_cast<uint32_t>(&WaitForSingleObject);
    cfg.api.create_thread = reinterpret_cast<uint32_t>(&create_worker);
    cfg.api.worker_entry = reinterpret_cast<uint32_t>(pool.worker);
    require(pool.init(&poolmem, &cfg) == NTW_POOL_OK, "persistent worker init");

    api_tests();
    owner_api_tests();

    Totals tot;
    // 1. stop-after-first-cell, per-cell batches, inline and dispatched, without serial stages (strict)
    for (uint32_t i = 0; i != worlds; ++i) run_world(pool, &poolmem, tot, true, false, false, (i & 1) != 0, 1 + i % 3, 1, 9);
    // 2. full query (arg3 != 0): one batch for the whole query
    for (uint32_t i = 0; i != worlds; ++i) run_world(pool, &poolmem, tot, false, true, false, (i & 1) != 0, 2, 1, 9);
    // 3. with the serial 0x400 stage (owner accepts the reorder assumption)
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, tot, (i & 1) != 0, (i & 1) == 0, true, true, 1 + i % 4, 1, 7);
    std::printf("worlds %u entries %u cells %u hits %u found-worlds %u serial-stages %u\n", tot.worlds, tot.entries, tot.cells,
                tot.hits, tot.found, tot.box_serial);
    require(tot.hits > 50 && tot.found > 20, "coverage too low: no hits");

    // 3b. owner-computed results (ABI 3): the ORIGINAL leaves run at the add point, only outcomes enter the batch, the world
    //     is mutated after every record (and across nbc_run / nbc_merge) and put back before the next owner leaf
    Totals own;
    for (uint32_t i = 0; i != worlds; ++i) run_world(pool, &poolmem, own, true, false, false, (i & 1) != 0, 1 + i % 3, 1 + i % 3, 9, OWN_MIXED);
    for (uint32_t i = 0; i != worlds; ++i) run_world(pool, &poolmem, own, false, true, false, (i & 1) != 0, 2, 1 + i % 3, 9, OWN_MIXED);
    // 0x400 entries: strict batch (no reorder flag: every box is owner computed, the owner-side log must be exact),
    // reorder allowed (box candidates split between owner and worker), and nothing left for workers at all
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, own, (i & 1) != 0, (i & 1) == 0, true, true, 1 + i % 4, 1, 7, OWN_MIXED, false);
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, own, (i & 1) != 0, (i & 1) == 0, true, true, 1 + i % 4, 1, 7, OWN_MIXED, true);
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, own, (i & 1) != 0, (i & 1) == 0, true, true, 1 + i % 4, 1, 7, OWN_ALL, false);
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, own, (i & 1) != 0, (i & 1) == 0, false, (i & 2) != 0, 2, 1, 9, OWN_ALL);
    std::printf("owner results: worlds %u hits %u owner-hits %u owner-misses %u worker-candidates %u mutated-topology-disagrees %u owner-only-runs %u\n",
                own.worlds, own.hits, own.owner_hits, own.owner_misses, own.pure, own.poison_effective, own.empty_pure_runs);
    require(own.hits > 50 && own.owner_hits > 20 && own.owner_misses > 20 && own.pure > 20 && own.poison_effective > 0 &&
                own.empty_pure_runs > 0,
            "owner-result coverage too low");
    // 4. denormal / FTZ-DAZ caller MXCSR must be installed by the workers
    const uint32_t savedCsr = _mm_getcsr();
    _mm_setcsr(savedCsr | 0x8040u);
    Totals tot2;
    for (uint32_t i = 0; i != worlds / 2; ++i) run_world(pool, &poolmem, tot2, false, true, false, true, 2, 1, 9);
    _mm_setcsr(savedCsr);
    std::printf("ftz/daz caller: worlds %u hits %u\n", tot2.worlds, tot2.hits);

    // Native leaf calls must inherit x87 precision as well as SSE control state.
    unsigned short savedCw;
    __asm fnstcw word ptr[savedCw]
    Totals precision;
    const unsigned short words[] = {0x27F, 0x37F, 0x7F};
    for (unsigned short cw : words) {
        __asm fldcw word ptr[cw]
        for (uint32_t i = 0; i != worlds / 6; ++i)
            run_world(pool, &poolmem, precision, false, true, false, true, 2, 1, 9);
        unsigned short after;
        __asm fnstcw word ptr[after]
        require(after == cw, "caller x87 control changed");
    }
    __asm fldcw word ptr[savedCw]
    std::printf("x87 precision: words 27F/37F/7F worlds %u hits %u\n", precision.worlds, precision.hits);

    // 5. pool statistics: chunks ran on workers, persistent (no per-query thread creation)
    std::printf("pool: calls %u team %u woken %u main-chunks %u inline %u\n", poolmem.st_calls, poolmem.st_team, poolmem.st_woken,
                poolmem.st_main_chunks, poolmem.st_inline);
    require(poolmem.st_team > 0 && poolmem.st_woken > 0, "dispatcher never used the team");
    require(pool.shutdown(&poolmem) == NTW_POOL_OK, "persistent worker shutdown");
    std::printf("PASS: port == original machine code (native clones) on every hit/miss/edge/order case; dispatcher team used.\n");
    return 0;
}
