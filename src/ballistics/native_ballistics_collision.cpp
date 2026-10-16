/* NTW ballistics: parallel numeric narrow phase inside one projectile collision query.  See the header for the
 * seam, the owner protocol and the order rules.
 *
 * Build (CRT-free, import-free, no globals; same flags as native_worker_dispatch.c):
 *   cl /nologo /c /O2 /GS- /Gy /Zl /EHs-c- /GR- /arch:SSE2 /fp:precise /W4 native_ballistics_collision.cpp
 * The per-candidate working memory is a private scratch block on the executing thread's own stack; nothing is
 * allocated and no shared state is written except results[i] of the chunk's own candidates.
 */
#include "native_ballistics_collision.h"

#include <emmintrin.h>
#include <intrin.h>
#include <stdint.h>

#pragma intrinsic(__stosd)

/* /Zl + /NODEFAULTLIB builds (import-free DLL) have no CRT to define the symbol the compiler references whenever
 * a translation unit uses float/double.  In the CRT harness the linker simply never pulls the CRT member. */
extern "C" int _fltused = 0x9875;

typedef nbc_u32 u32;
typedef nbc_u8 u8;

typedef u8(__fastcall* nbc_plane_fn)(const float*, void*, const float*, u32, float*);
typedef u8(__fastcall* nbc_ring_fn)(const void*, void*, const float*);
typedef u8(__fastcall* nbc_box_fn)(const float*, void*, const float*, u32, float*, float*);
typedef u8(__fastcall* nbc_wall_fn)(void*, void*, const void*, const nbc_segment*, u32, float*);
typedef u8(__fastcall* nbc_unit_fn)(void*, void*, const float*, u32, float*, u32, float);
typedef u8(__fastcall* nbc_inside_fn)(void*, void*, const float*);

extern "C" const nbc_u32 nbc_contract[8] = {NBC_ABI, NBC_CAND_BYTES, NBC_RESULT_BYTES, NBC_BATCH_BYTES,
                                           sizeof(nbc_kernels), 6u, 0u, 0u};

static inline u32 nbc_fbits(float f) {
    union { float f; u32 u; } v;
    v.f = f;
    return v.u;
}
static inline float nbc_bitsf(u32 u) {
    union { float f; u32 u; } v;
    v.u = u;
    return v.f;
}

/* p0 + (p1 - p0) * t, in the operation order of the original (subss, mulss, addss) */
static inline float nbc_lerp(float a, float b, float t) {
    return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_mul_ss(_mm_sub_ss(_mm_set_ss(b), _mm_set_ss(a)), _mm_set_ss(t))));
}

/* rep stosd: an explicit intrinsic so the optimiser can never turn a clearing loop into a CRT memset call */
static inline void nbc_zero(void* p, u32 bytes) { __stosd((unsigned long*)p, 0ul, bytes / 4u); }


static inline void nbc_hit_point(nbc_result* r, const float* seg6, float t) {
    r->t = t;
    r->pos[0] = nbc_lerp(seg6[0], seg6[3], t);
    r->pos[1] = nbc_lerp(seg6[1], seg6[4], t);
    r->pos[2] = nbc_lerp(seg6[2], seg6[5], t);
}

/* ----------------------------------------------------------------------------------------------------------- */
/* One candidate.  Mirrors the per-entry blocks of 0x6392C0 (0x6395F7..0x639A72) from the narrow-phase call on. */
static void nbc_compute(const nbc_batch* b, const nbc_cand* cd, nbc_result* r) {
    const nbc_kernels* k = &b->kernels;
    const float* seg = b->alt->p0;
    const float* values = (const float*)cd->p;
    float t = 0;
    r->status = NBC_R_MISS;
    r->t = 0;
    r->pos[0] = r->pos[1] = r->pos[2] = 0;
    /* pad[] is owned by nbc_run (compact work index while dispatching, zeroed before it returns): never written here */

    if (cd->kind == NBC_K_PLANE_RING) {
        if (!((nbc_plane_fn)(uintptr_t)k->plane)(seg, 0, values, cd->mode, &t)) return;
        nbc_hit_point(r, seg, t);
        const float pt[2] = {r->pos[0], r->pos[2]};
        if (((nbc_ring_fn)(uintptr_t)k->ring)((const void*)(uintptr_t)cd->p[4], 0, pt))
            r->status = NBC_R_HIT;
        return;
    }
    if (cd->kind == NBC_K_WALL) {
        // Native 5DB450 reads only wall+C/+64 and the X+8 -> Y+9C terrain chain.
        __declspec(align(16)) u8 wall[0x68], x[0x10], y[0xA0];
        *(u32*)(wall + 0xC) = (u32)(uintptr_t)x;
        *(u32*)(wall + 0x64) = cd->p[5];
        *(u32*)(x + 8) = (u32)(uintptr_t)y;
        *(u32*)(y + 0x9C) = cd->p[4];
        const float* plane = values;
        if (((nbc_wall_fn)(uintptr_t)k->wall)(wall, 0, &plane, b->alt, cd->mode, &t) != 1u) return;
        nbc_hit_point(r, seg, t);
        r->status = NBC_R_HIT;
        return;
    }
    if (cd->kind == NBC_K_UNIT) {
        __declspec(align(16)) u8 unit[0x68];
        *(u32*)unit = 0; // Native prologue loads the vtable before the replaced getter call.
        for (u32 i = 0; i < 5; ++i) *(u32*)(unit + 0x48 + 4u * i) = cd->p[i];
        *(u32*)(unit + 0x60) = cd->p[5] ? (u32)(uintptr_t)(unit + 0x64) : 0;
        *(u32*)(unit + 0x64) = cd->aux0;
        if (((nbc_unit_fn)(uintptr_t)k->unit_hit)(unit, 0, seg, cd->mode, &t, cd->p[6],
                                                nbc_bitsf(cd->p[7])) != 1u) return;
        if (b->seg->type == 1u && ((nbc_inside_fn)(uintptr_t)k->unit_inside)(unit, 0, seg)) return;
        nbc_hit_point(r, seg, t);
        r->status = NBC_R_HIT;
        return;
    }
    if (cd->kind == NBC_K_BOX) {
        float o1[2] = {}, o2[2] = {};
        if (((nbc_box_fn)(uintptr_t)k->box)(seg, 0, values, cd->mode, o1, o2))
            r->status = NBC_R_SERIAL;
        return;
    }
    r->status = NBC_R_FAULT;
}

extern "C" void __fastcall nbc_chunk_body(void* ctx, nbc_u32 chunk) {
    const nbc_batch* b = (const nbc_batch*)ctx;
    const u32 step = b->chunk_items ? b->chunk_items : 8u;
    const u32 lo = chunk * step;
    u32 hi = lo + step;
    if (hi > b->pure) hi = b->pure;
    /* chunks range over the worker-computed candidates only; a mixed batch reaches them through the work index
     * nbc_run left in results[k].pad[0] (distinct words from the status/t/pos every chunk writes) */
    const bool mapped = b->pure != b->count;
    u32 saved = _mm_getcsr();
    unsigned short saved_cw, wanted_cw = (unsigned short)b->x87_cw;
    __asm fnstcw word ptr[saved_cw]
    _mm_setcsr(b->mxcsr);
    __asm fldcw word ptr[wanted_cw]
    for (u32 k = lo; k < hi; ++k) {
        const u32 i = mapped ? b->results[k].pad[0] : k;
        nbc_compute(b, &b->cands[i], &b->results[i]);
    }
    __asm fldcw word ptr[saved_cw]
    _mm_setcsr(saved);
}

/* ----------------------------------------------------------------------------------------------------------- */
extern "C" nbc_u32 NBC_CALL nbc_batch_init(nbc_batch* b, nbc_cand* cands, nbc_result* results, nbc_u32 capacity,
                                           const nbc_segment* seg, const nbc_segment* alt, nbc_u32 flags,
                                           const nbc_kernels* kernels) {
    if (!b || !cands || !results || !capacity || !seg || !kernels || !kernels->plane || !kernels->ring ||
        !kernels->box || !kernels->wall || !kernels->unit_hit || !kernels->unit_inside) return NBC_E_ARG;
    nbc_zero(b, sizeof(*b));
    b->abi = NBC_ABI;
    b->flags = flags;
    b->capacity = capacity;
    b->cands = cands;
    b->results = results;
    b->seg = seg;
    b->alt = alt ? alt : seg;
    b->min_parallel = 32u;
    b->chunk_items = 8u;
    b->mxcsr = _mm_getcsr();
    b->kernels = *kernels;
    return NBC_OK;
}

extern "C" void NBC_CALL nbc_batch_reset(nbc_batch* b) {
    b->count = 0;
    b->pure = 0;
    b->have_cell = 0;
    b->cur_cell = 0;
}

static nbc_cand* nbc_slot(nbc_batch* b, nbc_u32 kind, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, nbc_u32* err) {
    if (!b || b->abi != NBC_ABI) { *err = NBC_E_ARG; return 0; }
    if (b->count >= b->capacity) { *err = NBC_E_FULL; return 0; }
    if ((b->flags & NBC_BF_STOP_FIRST_CELL) && b->have_cell && b->cur_cell != cell) { *err = NBC_E_CELL; return 0; }
    if (kind == NBC_K_BOX && !(b->flags & NBC_BF_ALLOW_SERIAL_REORDER)) { *err = NBC_E_STRICT; return 0; }
    nbc_cand* cd = &b->cands[b->count];
    nbc_zero(cd, sizeof(*cd));
    cd->kind = kind;
    cd->mode = mode;
    cd->entry = entry;
    cd->cell = cell;
    *err = NBC_OK;
    return cd;
}

static inline void nbc_commit(nbc_batch* b, const nbc_cand* cd) {
    b->have_cell = 1;
    b->cur_cell = cd->cell;
    if (cd->kind != NBC_K_OWNER) b->pure += 1;
    b->count += 1;
}

extern "C" nbc_u32 NBC_CALL nbc_add_plane_ring(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode,
                                               const float plane[4], const void* ring) {
    nbc_u32 err;
    nbc_cand* cd = nbc_slot(b, NBC_K_PLANE_RING, entry, cell, mode, &err);
    if (!cd) return err;
    for (u32 i = 0; i < 4; ++i) cd->p[i] = nbc_fbits(plane[i]);
    cd->p[4] = (u32)(uintptr_t)ring;
    nbc_commit(b, cd);
    return NBC_OK;
}

extern "C" nbc_u32 NBC_CALL nbc_add_wall(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float p2d[4],
                                         const void* terrain, float band) {
    nbc_u32 err;
    nbc_cand* cd = nbc_slot(b, NBC_K_WALL, entry, cell, mode, &err);
    if (!cd) return err;
    for (u32 i = 0; i < 4; ++i) cd->p[i] = nbc_fbits(p2d[i]);
    cd->p[4] = (u32)(uintptr_t)terrain;
    cd->p[5] = nbc_fbits(band);
    nbc_commit(b, cd);
    return NBC_OK;
}

extern "C" nbc_u32 NBC_CALL nbc_add_box(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float box[6]) {
    nbc_u32 err;
    nbc_cand* cd = nbc_slot(b, NBC_K_BOX, entry, cell, mode, &err);
    if (!cd) return err;
    for (u32 i = 0; i < 6; ++i) cd->p[i] = nbc_fbits(box[i]);
    cd->flags = NBC_CF_FOUND_ON_VISIT;
    nbc_commit(b, cd);
    return NBC_OK;
}

extern "C" nbc_u32 NBC_CALL nbc_add_unit(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float unit5[5],
                                         nbc_u32 obj2, nbc_u32 b5b77, nbc_u32 sel, float extra) {
    nbc_u32 err;
    nbc_cand* cd = nbc_slot(b, NBC_K_UNIT, entry, cell, mode, &err);
    if (!cd) return err;
    for (u32 i = 0; i < 5; ++i) cd->p[i] = nbc_fbits(unit5[i]);
    cd->p[5] = obj2;
    cd->p[6] = sel;
    cd->p[7] = nbc_fbits(extra);
    cd->aux0 = b5b77;
    nbc_commit(b, cd);
    return NBC_OK;
}

extern "C" nbc_u32 NBC_CALL nbc_add_owner_result(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 flags,
                                                 const nbc_hit* hit) {
    if ((flags & ~NBC_CF_FOUND_ON_VISIT) || (hit && hit->entry != entry)) return NBC_E_ARG;
    nbc_u32 err;
    nbc_cand* cd = nbc_slot(b, NBC_K_OWNER, entry, cell, 0, &err);
    if (!cd) return err;
    cd->flags = flags;
    nbc_result* r = &b->results[b->count];
    nbc_zero(r, sizeof(*r));
    if (hit) {
        r->status = NBC_R_HIT;
        r->t = hit->t;
        r->pos[0] = hit->pos[0];
        r->pos[1] = hit->pos[1];
        r->pos[2] = hit->pos[2];
    }
    nbc_commit(b, cd);
    return NBC_OK;
}

/* ---- raw entry readers: list node {+0 type, +4 id(u16), +8 aux, +0xC object, +0x14 next} -------------------- */
extern "C" nbc_u32 NBC_CALL nbc_add_plane_ring_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode) {
    const u8* e = (const u8*)entry;
    const u8* obj = (const u8*)(uintptr_t) * (const u32*)(e + 0xC);
    const float* plane = (const float*)(obj + 0x30);
    const void* ring = (const void*)(uintptr_t) * (const u32*)(obj + 8);
    return nbc_add_plane_ring(b, (u32)(uintptr_t)entry, cell, mode, plane, ring);
}

extern "C" nbc_u32 NBC_CALL nbc_add_wall_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode) {
    const u8* e = (const u8*)entry;
    const u8* arg1 = (const u8*)(uintptr_t) * (const u32*)(e + 8);
    const float* p2d = (const float*)(uintptr_t) * (const u32*)arg1; /* 0x5DB450 pushes [arg1] as the 2-D segment */
    const u8* obj = (const u8*)(uintptr_t) * (const u32*)(e + 0xC);
    float band = *(const float*)(obj + 0x64);
    const u8* x = (const u8*)(uintptr_t) * (const u32*)(obj + 0xC);
    const u8* y = (const u8*)(uintptr_t) * (const u32*)(x + 8);
    const void* terrain = (const void*)(uintptr_t) * (const u32*)(y + 0x9C);
    return nbc_add_wall(b, (u32)(uintptr_t)entry, cell, mode, p2d, terrain, band);
}

extern "C" nbc_u32 NBC_CALL nbc_add_box_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode) {
    const u8* e = (const u8*)entry;
    const u8* obj = (const u8*)(uintptr_t) * (const u32*)(e + 0xC);
    return nbc_add_box(b, (u32)(uintptr_t)entry, cell, mode, (const float*)(obj + 0xA4));
}

extern "C" nbc_u32 NBC_CALL nbc_add_unit_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode,
                                               nbc_u32 obj2, nbc_u32 b5b77, nbc_u32 sel, float extra) {
    const u8* e = (const u8*)entry;
    const u8* obj = (const u8*)(uintptr_t) * (const u32*)(e + 0xC);
    float u5[5];
    for (u32 i = 0; i < 5; ++i) u5[i] = *(const float*)(obj + 0x48 + 4u * i);
    return nbc_add_unit(b, (u32)(uintptr_t)entry, cell, mode, u5, obj2, b5b77, sel, extra);
}

extern "C" nbc_u32 NBC_CALL nbc_unit_flag_ok(const void* entry, nbc_u32 selector) {
    const u8* e = (const u8*)entry;
    const u8* obj = (const u8*)(uintptr_t) * (const u32*)(e + 0xC);
    const u32 flags = *(const u32*)(obj + 0x34);
    if (selector == 1u || selector == 4u) return (flags & 0x10u) != 0u;
    if (selector == 2u || selector == 3u) return (flags & 0x08u) != 0u;
    return 0u;
}

/* ----------------------------------------------------------------------------------------------------------- */
extern "C" nbc_u32 NBC_CALL nbc_run(nbc_batch* b) {
    if (!b || b->abi != NBC_ABI) return NBC_E_ARG;
    unsigned short cw = 0;
    __asm fnstcw word ptr[cw]
    if (((cw >> 10) & 3u) != 0u) return NBC_E_FPCW;
    b->x87_cw = cw;
    b->mxcsr = _mm_getcsr();
    if (((b->mxcsr >> 13) & 3u) != 0u) return NBC_E_FPCW;
    const u32 pure = b->pure;
    if (pure > b->count) return NBC_E_ARG;

    u32 step = b->chunk_items ? b->chunk_items : 8u;
    u32 chunks = (pure + step - 1u) / step;
    b->st_runs += 1;
    b->st_cands += b->count;
    b->st_owner += b->count - pure;
    b->st_chunks += chunks;
    /* No worker-computed candidate (empty batch or only owner results): nothing to compute and no team to wake. */
    if (!pure) return NBC_OK;
    if (pure != b->count) {
        /* Mixed batch: results[k].pad[0] = index of the k-th worker-computed candidate (k < pure <= count), so chunks
         * cover only real work.  Written here by the owner before any worker starts, zeroed below after the barrier. */
        u32 k = 0;
        for (u32 i = 0; i < b->count; ++i)
            if (b->cands[i].kind != NBC_K_OWNER) b->results[k++].pad[0] = i;
    }
    if (b->dispatch && b->body_entry && pure >= b->min_parallel && chunks > 1u && chunks <= NBC_MAX_CHUNKS) {
        /* The body address comes from the loader (b->body_entry): taking &nbc_chunk_body here would put an absolute
         * address into the code section.  Without it the chunks run inline (never an error). */
        nbc_dispatch_fn d = (nbc_dispatch_fn)(uintptr_t)b->dispatch;
        d((void*)(uintptr_t)b->dispatch_user, (nbc_body_fn)(uintptr_t)b->body_entry, chunks, b);
        b->st_dispatched += 1;
    } else {
        for (u32 ch = 0; ch < chunks; ++ch) nbc_chunk_body(b, ch);
    }
    for (u32 i = 0; i < b->count; ++i) {
        nbc_result* r = &b->results[i];
        if (r->status == NBC_R_FAULT) b->st_faults += 1;
        else if (r->status == NBC_R_SERIAL) b->st_serial += 1;
        r->pad[0] = r->pad[1] = r->pad[2] = 0;
    }
    return NBC_OK;
}

extern "C" nbc_u32 NBC_CALL nbc_merge(const nbc_batch* b, nbc_hit* out, nbc_u32 out_capacity, nbc_serial_fn serial,
                                      void* serial_user, nbc_merge_info* info) {
    nbc_merge_info local;
    nbc_merge_info* inf = info ? info : &local;
    inf->consumed = inf->found = inf->hits = inf->serial = inf->overflow = 0;
    if (!b || b->abi != NBC_ABI || (!out && out_capacity)) return NBC_E_ARG;
    u32 i = 0;
    while (i < b->count) {
        u32 cell = b->cands[i].cell;
        for (; i < b->count && b->cands[i].cell == cell; inf->consumed = ++i) {
            const nbc_cand* cd = &b->cands[i];
            if (cd->kind == NBC_K_OWNER && b->results[i].status > NBC_R_HIT) return NBC_E_ARG;
            const nbc_result* r = &b->results[i];
            if (cd->flags & NBC_CF_FOUND_ON_VISIT) inf->found = 1;
            nbc_hit h;
            if (r->status == NBC_R_HIT) {
                h.entry = cd->entry;
                h.pos[0] = r->pos[0];
                h.pos[1] = r->pos[1];
                h.pos[2] = r->pos[2];
                h.t = r->t;
            } else if (r->status == NBC_R_SERIAL || r->status == NBC_R_FAULT) {
                if (!serial) return NBC_E_SERIAL;
                inf->serial += 1;
                h.entry = cd->entry;
                h.pos[0] = h.pos[1] = h.pos[2] = h.t = nbc_bitsf(0);
                if (!serial(serial_user, i, &h)) continue;
            } else {
                continue;
            }
            if (inf->hits >= out_capacity) {
                inf->overflow += 1;
                return NBC_E_FULL;
            }
            out[inf->hits++] = h;
            inf->found = 1;
        }
        if ((b->flags & NBC_BF_STOP_FIRST_CELL) && inf->found) break;
    }
    return NBC_OK;
}
