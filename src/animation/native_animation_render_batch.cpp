// See native_animation_render_batch.h.  Build: CMake target kntwr_animation_render_batch (x86, /O2 /fp:precise /arch:SSE2).
//
// Every floating-point expression keeps the instruction order of the original scalar SSE code (mulss/addss/subss, no
// reassociation, no FMA).  Sources, all in native-animation-render-batch-*.asm:
//   0x10CAD70  quaternion + translation -> 3x4 (4-float rows), exact operation order below
//   0x10DEAC0  per bone: world = parentOrRoot * local, three rows, ((a*b + c*d) + e*f) [+ translation of the parent]
//   0x11FF470  group 3 position transform (in place, original values of px/py/pz for all three outputs)
//   0x10F4860  group 4 accessor broadcast, ucomiss equality semantics
#include "native_animation_render_batch.h"

#include <cstring>
#include <xmmintrin.h>

namespace ntw_render {

namespace {

// ---- raw layouts (proven by the disassembly of 0x1200A30 / 0x11FF470 / 0x11FF750 / 0x10DF440) --------------------------
constexpr uint32_t R_ARENA_OBJ = 0x50;  // [R+0x50] -> object whose vtable slot +8 returns the arena
constexpr uint32_t R_G3_COUNT = 0x8C, R_G3_DATA = 0x90, R_G3_VECS = 0x100;
constexpr uint32_t R_G4_COUNT = 0x9C, R_G4_DATA = 0xA0, R_G4_VECS = 0x110;
constexpr uint32_t VEC_STRIDE = 0x18;   // per-index record vectors: {+4 cap, +8 size, +0xC data} + holder at +0x10
constexpr uint32_t VEC_HOLDER = 0x10;
constexpr uint32_t VT_ARENA_GETTER = 8;   // byte offset into the vtable
constexpr uint32_t VT_CLIP_GETTER = 0x3C;

constexpr uint32_t G3_STRIDE = 0x90, G3_P = 0x04, G3_M = 0x44, G3_TIME = 0x84, G3_P5 = 0x88;
constexpr uint32_t G4_STRIDE = 0x60, G4_P = 0x04, G4_V3 = 0x44, G4_TIME = 0x54, G4_P5 = 0x58;

constexpr uint32_t CLIP_HOLDER = 0x04, CLIP_HEADER = 0x08, CLIP_DURATION = 0x4C;
constexpr uint32_t CLIP_FRAMES = 0x88, CLIP_FRAME_ARRAY = 0x8C;
constexpr uint32_t FRAME_SKELETON = 0x00;
constexpr uint32_t SKEL_TABLE = 0x0C, BONE_STRIDE = 0x14, BONE_PARENT = 0x10;

constexpr uint32_t L_BYTES = 0x14;        // pose object of 0x10DF440 (skeleton, flag, pos, quat, count)
constexpr uint32_t OUT_BYTES = 0x10;      // matrix object of 0x10DEAC0 (flag, count, matrices, accessors)
constexpr uint32_t MAT_BYTES = 0x30;      // 3 rows x 4 floats
constexpr uint32_t ACC_BYTES = 0x24;
constexpr float kGroup4W = 1000.0f;       // 0x447A0000, passed through the fist/fisub idiom of 0x11FF7E1 (exact)

template <class T> inline T rd(const void* base, uint32_t off) {
    T v;
    std::memcpy(&v, static_cast<const uint8_t*>(base) + off, sizeof(T));
    return v;
}
template <class T> inline void wr(void* base, uint32_t off, T v) {
    std::memcpy(static_cast<uint8_t*>(base) + off, &v, sizeof(T));
}

struct Record {  // the 12-byte element appended by 0x1221480 (dword, byte, dword; padding is not copied)
    uint32_t object;
    uint8_t flag;
    uint8_t pad[3];
    uint32_t extra;
};
static_assert(sizeof(Record) == 12, "record");

enum : uint8_t { JK_NATIVE = 0, JK_ORIGINAL = 1, JK_SKIP = 2 };

}  // namespace

struct EntryJob {
    uint8_t kind;
    uint8_t group;  // 3 or 4
    uint16_t pad;
    int32_t idx;
    uint8_t* entry;   // original input entry (fallback executes it; p5 is read at publish like the original)
    uint8_t* render;  // R
    uint8_t* vec;     // 0x1221480 `this`
    // native inputs (immutable once prepare returns)
    const uint8_t* frame_a;
    const uint8_t* frame_b;
    const uint8_t* holder;
    const uint8_t* header;
    const uint8_t* table;  // bone table, stride 0x14, signed parent at +0x10
    float frac;
    uint32_t n;
    // arena blocks owned by this job
    float* pos;
    float* quat;
    uint8_t* out;
    float* mats;
    uint8_t* acc;
    // snapshots of the render-group inputs read by the numerical kernel
    float P[12];
    float M[12];  // group 3 transform
    float V[4];   // group 4 broadcast vector (v3, 1000.0f)
};

namespace {

// ---- numerical core ---------------------------------------------------------------------------------------------------

// 0x10CAD70.  q = {x,y,z,w}, t = {tx,ty,tz}; out rows have 4 floats.
inline void quat_pos_to_3x4(float* o, const float* q, const float* t) {
    const float x = q[0], y = q[1], z = q[2], w = q[3];
    const float y2 = y + y;
    const float w2 = w + w;
    const float x2 = x + x;
    const float yy = y2 * y;
    const float x2y = x2 * y;
    const float w2y = w2 * y;
    const float w2z = w2 * z;
    const float y2z = y2 * z;
    const float z2 = z + z;
    const float z2z = z2 * z;
    const float x2z = x2 * z;
    const float w2x = w2 * x;
    const float one = 1.0f;  // [0x1318048]
    const float xx = x2 * x;
    const float b = one - xx;
    o[0] = (one - yy) - z2z;
    o[4] = w2z + x2y;
    o[8] = x2z - w2y;
    o[1] = x2y - w2z;
    o[5] = b - z2z;
    o[9] = w2x + y2z;
    o[2] = w2y + x2z;
    o[6] = y2z - w2x;
    o[10] = b - yy;
    std::memcpy(o + 3, t + 0, 4);
    std::memcpy(o + 7, t + 1, 4);
    std::memcpy(o + 11, t + 2, 4);
}

// 0x10DEAC0 product: out = P * M (P, M, out are 3x4 with 4-float rows; the 4th column of P is the translation).
inline void mul_world(float* out, const float* P, const float* M) {
    float r[12];
    for (int i = 0; i < 3; ++i) {
        const float p0 = P[i * 4 + 0], p1 = P[i * 4 + 1], p2 = P[i * 4 + 2], p3 = P[i * 4 + 3];
        r[i * 4 + 0] = (p0 * M[0] + p1 * M[4]) + p2 * M[8];
        r[i * 4 + 1] = (p0 * M[1] + p1 * M[5]) + p2 * M[9];
        r[i * 4 + 2] = (p0 * M[2] + p1 * M[6]) + p2 * M[10];
        r[i * 4 + 3] = ((p0 * M[3] + p1 * M[7]) + p2 * M[11]) + p3;
    }
    std::memcpy(out, r, sizeof(r));
}

// 0x11FF470 loop body: p = M * p + translation with the original values of all three inputs.
inline void transform_positions(float* pos, uint32_t n, const float* M) {
    for (uint32_t i = 0; i < n; ++i) {
        float* p = pos + (size_t)i * 3;
        const float px = p[0], py = p[1], pz = p[2];
        p[0] = ((py * M[1] + px * M[0]) + pz * M[2]) + M[3];
        p[1] = ((M[5] * py + px * M[4]) + M[6] * pz) + M[7];
        p[2] = ((py * M[9] + px * M[8]) + M[10] * pz) + M[11];
    }
}

// 0x10CD420 loop: accessor constructor 0x10D0930 per bone.
inline void init_accessors(uint8_t* acc, const float* mats, uint32_t n, uint32_t vtable) {
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* e = acc + (size_t)i * ACC_BYTES;
        wr<uint32_t>(e, 0x00, vtable);
        wr<uint8_t>(e, 0x04, 0);
        wr<uint32_t>(e, 0x08, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mats + (size_t)i * 12)));
        wr<uint32_t>(e, 0x0C, 0);
        wr<uint32_t>(e, 0x10, 0);
        wr<uint32_t>(e, 0x14, 0);
        wr<uint32_t>(e, 0x18, 0x3F800000u);
        wr<uint32_t>(e, 0x1C, 0);
        wr<uint32_t>(e, 0x20, 0);
    }
}

// 0x10F4860: skip when the first accessor already equals the vector (ucomiss: NaN is "different"), else copy to all.
inline void broadcast_vec4(uint8_t* acc, uint32_t n, const float* v) {
    if (n == 0) return;
    const float e0 = rd<float>(acc, 0x10), e1 = rd<float>(acc, 0x14), e2 = rd<float>(acc, 0x18), e3 = rd<float>(acc, 0x1C);
    if (e0 == v[0] && e1 == v[1] && e2 == v[2] && e3 == v[3]) return;
    for (uint32_t i = 0; i < n; ++i) std::memcpy(acc + (size_t)i * ACC_BYTES + 0x10, v, 16);
}

struct Run {
    const Binding* b;
    EntryJob* jobs;
    const uint32_t* chunk_begin;
    uint32_t mxcsr;
    uint16_t cw;
    bool sse2;
};

void compute_job(const Run& r, EntryJob& j) {
    if (j.kind != JK_NATIVE) return;
    ntw_anim::BlendArgs a{};
    a.frame_a = j.frame_a;
    a.frame_b = j.frame_b;
    a.t = j.frac;
    a.mode = 2;
    a.clip_holder = j.holder;
    a.clip_header = j.header;
    a.max_bones = 0;
    a.sse2_quat_decode = r.sse2;
    a.acos_fn = r.b->acos_fn;
    ntw_anim::blend_local(a, j.pos, j.quat);
    const uint32_t n = j.n;
    if (j.group == 3) transform_positions(j.pos, n, j.M);
    for (uint32_t i = 0; i < n; ++i) {
        float local[12];
        quat_pos_to_3x4(local, j.quat + (size_t)i * 4, j.pos + (size_t)i * 3);
        const int32_t parent = rd<int32_t>(j.table, i * BONE_STRIDE + BONE_PARENT);
        const float* P = parent < 0 ? j.P : j.mats + (size_t)static_cast<uint32_t>(parent) * 12;
        mul_world(j.mats + (size_t)i * 12, P, local);
    }
    init_accessors(j.acc, j.mats, n, r.b->accessor_vtable);
    if (j.group == 4) broadcast_vec4(j.acc, n, j.V);
}

__declspec(noinline) void compute_range(const Run& r, uint32_t begin, uint32_t end) {
    for (uint32_t k = begin; k < end; ++k) compute_job(r, r.jobs[k]);
}

// Dispatcher body (fastcall ECX = ctx, EDX = chunk).  Installs the owning thread's FP state, restores the worker's.
void __fastcall chunk_body(void* ctx, uint32_t chunk) {
    const Run* r = static_cast<const Run*>(ctx);
    const uint32_t savedCsr = _mm_getcsr();
    uint16_t savedCw = 0;
    uint16_t wantCw = r->cw;
    __asm { fnstcw word ptr[savedCw] }
    if (savedCsr != r->mxcsr) _mm_setcsr(r->mxcsr);
    if (savedCw != wantCw) { __asm { fldcw word ptr[wantCw] } }
    compute_range(*r, r->chunk_begin[chunk], r->chunk_begin[chunk + 1]);
    if (savedCw != wantCw) { __asm { fldcw word ptr[savedCw] } }
    _mm_setcsr(savedCsr);
}

// ---- prepare (owning thread; original side-effect order) ----------------------------------------------------------------
inline void* call_slot(void* object, uint32_t vtable_byte_offset) {
    const uintptr_t vt = rd<uintptr_t>(object, 0);
    const GetterFn fn = reinterpret_cast<GetterFn>(rd<uintptr_t>(reinterpret_cast<const void*>(vt), vtable_byte_offset));
    return fn(object);
}

inline void* alloc(const Binding& b, void* arena, uint32_t size, uint32_t align) {
    return b.arena_alloc(arena, nullptr, size, align);
}

void prepare_job(const Binding& b, uint8_t* R, uint8_t group, uint8_t* entry, EntryJob& j) {
    j.kind = JK_ORIGINAL;
    j.group = group;
    j.entry = entry;
    j.render = R;
    j.idx = rd<int32_t>(entry, 0);
    const uint32_t vecs_off = group == 3 ? R_G3_VECS : R_G4_VECS;
    const uint32_t p_off = group == 3 ? G3_P : G4_P;
    const uint32_t time_off = group == 3 ? G3_TIME : G4_TIME;
    uint8_t* const base = rd<uint8_t*>(R, vecs_off);
    // `lea edx,[eax+eax*2]; ... [eax+edx*8]`: 32-bit index arithmetic.
    j.vec = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(base) + static_cast<uint32_t>(j.idx) * VEC_STRIDE);

    void* const holder_obj = rd<void*>(j.vec, VEC_HOLDER);
    const uint8_t* const clip = static_cast<const uint8_t*>(call_slot(holder_obj, VT_CLIP_GETTER));
    if (!clip) return;
    const float time = rd<float>(entry, time_off);
    if (group == 4) {
        // 0x11FF77A: comiss duration,time ; jb skip  (unordered also skips)
        if (!(rd<float>(clip, CLIP_DURATION) >= time)) { j.kind = JK_SKIP; return; }
    }
    void* const arena_obj = rd<void*>(R, R_ARENA_OBJ);
    void* const arena1 = call_slot(arena_obj, VT_ARENA_GETTER);
    if (!arena1) return;
    uint32_t i0 = 0, i1 = 0;
    float frac = 0.0f;
    if (!ntw_anim::locate_frames(clip, time, false, &i0, &i1, &frac)) return;
    const uint32_t frame_count = rd<uint32_t>(clip, CLIP_FRAMES);
    if (frame_count == 0 || i0 >= frame_count || i1 >= frame_count) return;
    const uint8_t* const* frames = rd<const uint8_t* const*>(clip, CLIP_FRAME_ARRAY);
    const uint8_t* const frame_a = frames[i0];
    const uint8_t* const frame_b = frames[i1];
    const uint8_t* const skeleton = rd<const uint8_t*>(frame_a, FRAME_SKELETON);
    const uint32_t n = ntw_anim::blend_bone_count(frame_a, 0);

    // 0x10DF440 / 0x10CE290, arena path: obj(0x14,4), pos(n*12,4), quat(n*16,4)
    uint8_t* const L = static_cast<uint8_t*>(alloc(b, arena1, L_BYTES, 4));
    float* const pos = static_cast<float*>(alloc(b, arena1, n * 12u, 4));
    float* const quat = static_cast<float*>(alloc(b, arena1, n * 16u, 4));
    wr<const uint8_t*>(L, 0x00, skeleton);
    wr<uint8_t>(L, 0x04, 1);
    wr<float*>(L, 0x08, pos);
    wr<float*>(L, 0x0C, quat);
    wr<uint32_t>(L, 0x10, n);

    // second arena getter, then 0x10DEAC0 -> 0x10D3170(0x10,arena) + 0x10CD420: mats(n*0x30,4), accessors(n*0x24,2)
    void* const arena2 = call_slot(arena_obj, VT_ARENA_GETTER);
    if (!arena2) return;  // L stays an unreferenced arena block; the original builder runs at publish
    uint8_t* const out = static_cast<uint8_t*>(alloc(b, arena2, OUT_BYTES, 4));
    float* const mats = static_cast<float*>(alloc(b, arena2, n * MAT_BYTES, 4));
    uint8_t* const acc = static_cast<uint8_t*>(alloc(b, arena2, n * ACC_BYTES, 2));
    wr<uint8_t>(out, 0x00, 1);
    wr<uint32_t>(out, 0x04, n);
    wr<float*>(out, 0x08, mats);
    wr<uint8_t*>(out, 0x0C, acc);

    j.frame_a = frame_a;
    j.frame_b = frame_b;
    j.holder = rd<const uint8_t*>(clip, CLIP_HOLDER);
    j.header = clip + CLIP_HEADER;
    j.table = rd<const uint8_t*>(skeleton, SKEL_TABLE);
    j.frac = frac;
    j.n = n;
    j.pos = pos;
    j.quat = quat;
    j.out = out;
    j.mats = mats;
    j.acc = acc;
    std::memcpy(j.P, entry + p_off, sizeof(j.P));
    if (group == 3) {
        std::memcpy(j.M, entry + G3_M, sizeof(j.M));
        std::memset(j.V, 0, sizeof(j.V));
    } else {
        std::memset(j.M, 0, sizeof(j.M));
        std::memcpy(j.V, entry + G4_V3, 3 * sizeof(float));
        j.V[3] = kGroup4W;
    }
    j.kind = JK_NATIVE;
}

void publish_job(const Binding& b, EntryJob& j, Stats& st) {
    if (j.kind == JK_SKIP) { ++st.skipped; return; }
    uint8_t* const entry = j.entry;
    if (j.kind == JK_ORIGINAL) {
        if (j.group == 3)
            b.orig_group3(j.render, nullptr, j.idx, reinterpret_cast<const float*>(entry + G3_P),
                          reinterpret_cast<const float*>(entry + G3_M), rd<float>(entry, G3_TIME), entry + G3_P5);
        else
            b.orig_group4(j.render, nullptr, j.idx, reinterpret_cast<const float*>(entry + G4_P),
                          reinterpret_cast<const float*>(entry + G4_V3), rd<float>(entry, G4_TIME), entry + G4_P5);
        ++st.fallback;
        return;
    }
    const uint32_t p5 = j.group == 3 ? G3_P5 : G4_P5;
    Record rec;
    rec.object = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(j.out));
    rec.flag = rd<uint8_t>(entry, p5);
    rec.pad[0] = rec.pad[1] = rec.pad[2] = 0;
    rec.extra = rd<uint32_t>(entry, p5 + 4);
    b.append(j.vec, nullptr, &rec);
    ++st.native;
    ++st.published;
}

}  // namespace

size_t job_bytes() { return sizeof(EntryJob); }

static size_t align16(size_t v) { return (v + 15u) & ~static_cast<size_t>(15u); }

size_t workspace_bytes(uint32_t capacity) {
    return align16(static_cast<size_t>(capacity) * sizeof(EntryJob)) + align16((static_cast<size_t>(capacity) + 2u) * 4u);
}

bool workspace_init(Workspace& ws, void* memory, size_t bytes) {
    ws = Workspace{};
    if (!memory || (reinterpret_cast<uintptr_t>(memory) & 15u) != 0) return false;
    // capacity from bytes: largest c with workspace_bytes(c) <= bytes (bytes / per is an upper bound)
    const size_t per = sizeof(EntryJob) + 4u;
    uint32_t c = static_cast<uint32_t>(bytes / per);
    while (c != 0 && workspace_bytes(c) > bytes) --c;
    if (c == 0) return false;
    uint8_t* p = static_cast<uint8_t*>(memory);
    ws.jobs = reinterpret_cast<EntryJob*>(p);
    ws.chunk_begin = reinterpret_cast<uint32_t*>(p + align16(static_cast<size_t>(c) * sizeof(EntryJob)));
    ws.capacity = c;
    return true;
}

bool run(const Binding& binding, const Workspace& ws, void* render, uint32_t group_mask, Stats* stats) {
    Stats local{};
    Stats& st = stats ? *stats : local;
    const Binding& b = binding;
    if (!b.arena_alloc || !b.append || !b.orig_group3 || !b.orig_group4 || !b.sse2_decode_flag || !b.acos_fn ||
        b.accessor_vtable == 0 || !ws.jobs || !ws.chunk_begin || ws.capacity == 0 || !render || group_mask == 0 ||
        (group_mask & ~(kGroup3 | kGroup4)) != 0)
        return false;
    uint8_t* const R = static_cast<uint8_t*>(render);
    const uint32_t c3 = (group_mask & kGroup3) ? rd<uint32_t>(R, R_G3_COUNT) : 0u;
    uint8_t* const d3 = (c3 != 0) ? rd<uint8_t*>(R, R_G3_DATA) : nullptr;
    const uint32_t c4 = (group_mask & kGroup4) ? rd<uint32_t>(R, R_G4_COUNT) : 0u;
    uint8_t* const d4 = (c4 != 0) ? rd<uint8_t*>(R, R_G4_DATA) : nullptr;
    const uint64_t total64 = static_cast<uint64_t>(c3) + c4;
    if (total64 == 0) return true;

    const uint32_t min_parallel = b.min_parallel_bones ? b.min_parallel_bones : 384u;
    const uint32_t chunk_bones = b.chunk_bones ? b.chunk_bones : 192u;

    Run r{};
    r.b = &b;
    r.jobs = ws.jobs;
    r.chunk_begin = ws.chunk_begin;
    r.mxcsr = _mm_getcsr();
    {
        uint16_t cw = 0;
        __asm { fnstcw word ptr[cw] }
        r.cw = cw;
    }
    if ((r.mxcsr & 0x6000u) != 0 || (r.cw & 0x0C00u) != 0) {
        // Not round-to-nearest: the kernel's locate would diverge from x87 `fist`.  Original builders, original order.
        for (uint32_t k = 0; k < c3; ++k) {
            uint8_t* e = d3 + static_cast<size_t>(k) * G3_STRIDE;
            b.orig_group3(R, nullptr, rd<int32_t>(e, 0), reinterpret_cast<const float*>(e + G3_P),
                          reinterpret_cast<const float*>(e + G3_M), rd<float>(e, G3_TIME), e + G3_P5);
        }
        for (uint32_t k = 0; k < c4; ++k) {
            uint8_t* e = d4 + static_cast<size_t>(k) * G4_STRIDE;
            b.orig_group4(R, nullptr, rd<int32_t>(e, 0), reinterpret_cast<const float*>(e + G4_P),
                          reinterpret_cast<const float*>(e + G4_V3), rd<float>(e, G4_TIME), e + G4_P5);
        }
        st.entries += c3 + c4;
        st.fallback += c3 + c4;
        st.serial_original += c3 + c4;
        return true;
    }
    bool sse2_known = false;

    uint64_t pos = 0;
    while (pos < total64) {
        const uint32_t cnt = static_cast<uint32_t>(total64 - pos < ws.capacity ? total64 - pos : ws.capacity);
        uint32_t native_bones = 0;
        // 1. prepare, original order (all group 3, then all group 4)
        for (uint32_t k = 0; k < cnt; ++k) {
            const uint64_t g = pos + k;
            EntryJob& j = ws.jobs[k];
            if (g < c3) prepare_job(b, R, 3, d3 + static_cast<size_t>(g) * G3_STRIDE, j);
            else prepare_job(b, R, 4, d4 + static_cast<size_t>(g - c3) * G4_STRIDE, j);
            ++st.entries;
            if (j.kind == JK_NATIVE) native_bones += j.n;
        }
        ++st.windows;
        // 2. compute
        if (native_bones != 0) {
            if (!sse2_known) {  // 0x10D5510: lazy CPUID init on the owning thread, then the flag byte
                r.sse2 = b.sse2_decode_flag() != 0;
                sse2_known = true;
            }
            uint32_t chunks = 1;
            ws.chunk_begin[0] = 0;
            uint32_t acc = 0;
            for (uint32_t k = 0; k < cnt; ++k) {
                if (ws.jobs[k].kind == JK_NATIVE) acc += ws.jobs[k].n;
                if (acc >= chunk_bones && k + 1 < cnt) {
                    ws.chunk_begin[chunks++] = k + 1;
                    acc = 0;
                }
            }
            ws.chunk_begin[chunks] = cnt;
            st.bones += native_bones;
            if (b.dispatch && native_bones >= min_parallel && chunks > 1) {
                ++st.dispatches;
                st.chunks += chunks;
                b.dispatch(b.dispatch_user, reinterpret_cast<void*>(&chunk_body), chunks, &r);
            } else {
                compute_range(r, 0, cnt);
            }
        }
        // 3. ordered publish
        for (uint32_t k = 0; k < cnt; ++k) publish_job(b, ws.jobs[k], st);
        pos += cnt;
    }
    return true;
}

}  // namespace ntw_render
