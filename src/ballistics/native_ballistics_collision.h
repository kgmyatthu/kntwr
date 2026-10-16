/* NTW ballistics: parallel numeric narrow phase INSIDE one projectile collision query (pinned Napoleon.exe,
 * SHA-256 13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4).
 *
 * C and C++ compatible header, 32-bit x86 only.  The implementation (native_ballistics_collision.cpp) is CRT-free,
 * import-free, allocation-free and keeps no global; every worker uses only its own stack (job scratch).
 *
 * ---------------------------------------------------------------------------------------------------------------
 * WHERE THE SEAM IS (evidence: native-ballistics-collision.json, native_ballistics_collision_verify.py)
 * ---------------------------------------------------------------------------------------------------------------
 * One projectile query is 0x53C060 -> 0x6392C0 (grid walk over the cells the segment sweeps).  For every list entry
 * of a cell the ORIGINAL code does, in this order,
 *      owner side : type/mask filter, 0x6DC9A0 predicate (virtual), visited-bit test + set (+0x56EE80 dirty list),
 *                   per type: virtual getters / flag tests,
 *      numeric    : one narrow-phase function that reads only its arguments and read-only game memory,
 *      owner side : append {entry, x, y, z, t, 0, 0} to the result vector (0x5EF540), set "found".
 * The numeric functions are pure (no store outside their own outputs/locals, no allocation, no TLS, no globals
 * except read-only .rdata constants), so they can be computed ahead of the owner-side effects of LATER candidates and
 * their results consumed in the original order:
 *
 *      entry type 0x40  : 0x10E8500 (ray/plane) + 0x10E7030 (point in ring)             -> NBC_K_PLANE_RING
 *      entry type 0x08  : 0x809620 (capsule: 0x7FA000, 0x10DB090) + 0x809C00           -> NBC_K_UNIT
 *      entry type 0x800 : 0x5DB450 (0x559C10, 0x64C5F0 terrain height)                 -> NBC_K_WALL
 *      entry type 0x400 : 0x10E83E0 (box prefilter, 0x8FCA30) only; the second stage 0x6F06A0 -> 0x6B5C70 allocates
 *                         (0x48DF30), calls virtual leaf collectors and reads debug globals, so it stays SERIAL
 *                         and is executed by the owner at merge time through the callback (NBC_K_BOX).
 * Everything else of the query (cell rasterisation 0x10EED80, 0x7F4B50/0x7F4A10 other-manager scans, 0x64DFE0,
 * the result sort 0x4FF3B0, hit callbacks, RNG, effects) is untouched and stays on the owner thread.
 *
 * ---------------------------------------------------------------------------------------------------------------
 * OWNER PROTOCOL (the owner is the battle thread that runs the original 0x6392C0 loop)
 * ---------------------------------------------------------------------------------------------------------------
 *   nbc_batch_init(...)                         once per query (or per cell, see below)
 *   for each entry, in ORIGINAL list order, doing every owner-side step of the original loop (predicate, visited
 *   bit, flag tests, virtual getters) exactly where the original does:
 *        nbc_add_*(...)                         copies the immutable numeric inputs (no game call, no write), or
 *        nbc_add_owner_result(...)              records an outcome the owner computed right here (rule 6)
 *   nbc_run(b)                                   workers (persistent pool, caller participates) fill b->results[]
 *   nbc_merge(b, out, ..., serial)               in original order: append hits, run serial stages, apply the
 *                                                "stop after the first cell that found something" rule
 *   owner appends out[] with the original 0x5EF540 and continues the original loop / sort / hit handlers
 *
 * ORDER RULES (what makes the result identical to the serial original):
 *   1. The query is stop-after-first-found-cell (53C060 passes arg3 == 0).  Owner-side effects of cells after that
 *      cell must NEVER have run.  Therefore in stop mode a batch holds exactly ONE cell (the owner runs
 *      nbc_run/nbc_merge per cell); nbc_batch_init(..., NBC_BF_STOP_FIRST_CELL) makes nbc_add_* reject a second cell.
 *      Without the flag (arg3 != 0 callers) one batch may span the whole query.
 *   2. Pure kinds (PLANE_RING, UNIT, WALL) reorder only pure arithmetic and appends: always exact.
 *   3. NBC_K_BOX candidates schedule a serial stage that the original ran BEFORE the owner-side effects of the next
 *      entries.  Exactness then needs the assumption that those later owner-side effects (0x6DC9A0 virtual
 *      predicates, visited bits, unit getters) do not observe anything the serial stage of an earlier candidate
 *      changes.  That is not proven statically (the virtual targets are unresolved), so nbc_add_box refuses unless
 *      the owner explicitly passed NBC_BF_ALLOW_SERIAL_REORDER.  Without it BOX entries must stay on the original path.
 *   4. 0x800 entries are NOT deduplicated by the original (no visited bit): the owner adds them every time.
 *   5. 0x400 entries set "found" the moment they pass the visited-bit test, before any numeric test:
 *      pass NBC_CF_FOUND_ON_VISIT for them (nbc_add_box does).
 *   6. OWNER-COMPUTED RESULTS (ABI 3).  Topology-dependent work that cannot be proven immutable until the barrier ends
 *      (ring nodes, terrain heightfield, anything the later owner-side steps or other systems could change) is NOT
 *      handed to workers by pointer.  The owner runs the original leaf at its ORIGINAL point of the loop (before the
 *      owner-side steps of later entries, with the game's own code) and records only the outcome with
 *      nbc_add_owner_result(b, entry, cell, flags, hit-or-NULL).  The record takes the candidate slot / cell ordinal
 *      the corresponding nbc_add_* would have taken, so capacity (NBC_E_FULL), the one-cell rule of stop mode
 *      (NBC_E_CELL), found-on-visit, first-found-cell stopping and the merge order are those of the original loop.
 *      Nothing is read from the game later: the candidate carries no pointer, nbc_run never recomputes it and never
 *      writes its results[] slot, nbc_merge only copies the stored hit/miss.  An owner-computed BOX candidate
 *      (prefilter + serial stage already executed at the original point) needs no NBC_BF_ALLOW_SERIAL_REORDER.
 *      nbc_run counts the worker-computed ("pure") candidates: a batch without any (all owner results, or empty)
 *      never calls the dispatcher, and a mixed batch is split into chunks over its pure candidates only.
 *
 * Bit-exactness: workers call version-pinned native leaf-code copies from native_ballistics_collision_kit.py.
 * The worker kit replaces the two unit virtual calls with reads of owner-snapshotted values; no game callback
 * executes on a worker. The unmodified reference kit remains the differential oracle.
 * The nbc_add_* value/entry adders borrow ring and terrain pointers as immutable inputs for the duration of the barrier:
 * use them only for caller-owned fixtures or topology the owner has itself proven immutable until nbc_merge returns.
 * Game-owned topology that is not proven so MUST go through nbc_add_owner_result (rule 6); no adder snapshots it.
 * MXCSR and x87 control word are captured by nbc_run, installed per chunk and restored afterwards; rounding
 * must be nearest. No register-file or instruction emulation occurs in the hot path.
 */
#ifndef NATIVE_BALLISTICS_COLLISION_H
#define NATIVE_BALLISTICS_COLLISION_H

#ifndef _M_IX86
#error This ABI describes 32-bit x86 pointers; compile as x86.
#endif
#include <stddef.h>

typedef unsigned int nbc_u32;
typedef unsigned char nbc_u8;

#define NBC_ABI 3u
#define NBC_CAND_BYTES 80u
#define NBC_RESULT_BYTES 32u
#define NBC_BATCH_BYTES 0xA0u
#define NBC_MAX_CHUNKS 0x40000000u
#define NBC_CALL __stdcall

/* kernels (the narrow phase selected by the original entry type) */
#define NBC_K_NONE 0u
#define NBC_K_PLANE_RING 1u /* entry type 0x40  */
#define NBC_K_UNIT 2u       /* entry type 0x08  */
#define NBC_K_WALL 3u       /* entry type 0x800 */
#define NBC_K_BOX 4u        /* entry type 0x400, prefilter only */
#define NBC_K_OWNER 5u      /* no leaf: hit/miss already computed by the owner (nbc_add_owner_result); never a worker job */

/* nbc_cand.flags */
#define NBC_CF_FOUND_ON_VISIT 1u /* the original sets "found" when the entry is visited, whatever the test says */

/* nbc_result.status */
#define NBC_R_MISS 0u   /* narrow phase rejected                                                                   */
#define NBC_R_HIT 1u    /* t / pos valid: append {entry, pos, t, 0, 0}                                              */
#define NBC_R_SERIAL 2u /* BOX prefilter passed: the owner must run the original serial stage (callback)           */
#define NBC_R_FAULT 3u  /* private stack canary hit / frame mismatch: the owner must run the original function    */

/* nbc_batch.flags */
#define NBC_BF_STOP_FIRST_CELL 1u        /* arg3 == 0 of the original: stop after the first cell that found something */
#define NBC_BF_ALLOW_SERIAL_REORDER 2u   /* owner accepts rule 3 above (BOX candidates allowed)                       */

/* return codes */
#define NBC_OK 0u
#define NBC_E_ARG 1u
#define NBC_E_FULL 2u      /* candidate array full                                                        */
#define NBC_E_KIND 3u
#define NBC_E_CELL 4u      /* second cell in a NBC_BF_STOP_FIRST_CELL batch (rule 1)                        */
#define NBC_E_STRICT 5u    /* BOX candidate without NBC_BF_ALLOW_SERIAL_REORDER (rule 3)                    */
#define NBC_E_FPCW 6u      /* MXCSR / x87 rounding is not round-to-nearest                                  */
#define NBC_E_SERIAL 7u    /* a serial/fault candidate needs a callback and none was supplied              */

/* The query segment exactly as built by 0x6F5AF7..: {type, p0 xyz, p1 xyz}. */
typedef struct nbc_segment {
    nbc_u32 type;
    float p0[3];
    float p1[3];
} nbc_segment;

/* One candidate: 80 bytes, contiguous array, written only by the owner.  payload[] meaning per kernel:
 *   PLANE_RING  p[0..3]=plane (obj+0x30: nx,ny,nz,d)   p[4]=ring head (obj[+8]; game memory, read-only)
 *   UNIT        p[0..4]=obj floats at +0x48,+0x4C,+0x50,+0x54,+0x58   p[5]=value of virtual +0x18 (0 / cookie)
 *               p[6]=type selector (arg4: type of the segment)  p[7]=float extra (arg5 param_9)  aux0=0x5B77A0 result
 *   WALL        p[0..3]=2-D segment P (x0,z0,x1,z1)   p[4]=terrain grid pointer ([[[obj+0xC]+8]+0x9C])   p[5]=float band (obj+0x64)
 *   BOX         p[0..5]=box min xyz, max xyz (obj+0xA4)
 *   OWNER       mode=0, p[] and aux* all zero; the outcome lives in results[i] (status MISS/HIT, t, pos).  flags may carry
 *               NBC_CF_FOUND_ON_VISIT.  No pointer: nothing to borrow, nothing a worker could read.                  */
typedef struct nbc_cand {
    nbc_u32 kind;   /* 0x00 NBC_K_*                                                            */
    nbc_u32 mode;   /* 0x04 range flags of the original (arg6 of 0x6392C0: bit0 allow t<0, bit1 allow t>1) */
    nbc_u32 entry;  /* 0x08 opaque: grid entry address, returned in hits                         */
    nbc_u32 cell;   /* 0x0C owner cell ordinal                                                   */
    nbc_u32 flags;  /* 0x10 NBC_CF_*                                                             */
    nbc_u32 aux0;   /* 0x14                                                                     */
    nbc_u32 aux1;   /* 0x18 reserved, zero                                                      */
    nbc_u32 aux2;   /* 0x1C reserved, zero                                                      */
    nbc_u32 p[12];  /* 0x20                                                                     */
} nbc_cand;

/* results[i] belongs to cands[i].  nbc_run uses pad[0] of results[0 .. pure) as the compact work index of a mixed batch
 * (index of the k-th worker-computed candidate) while workers run and zeroes pad[] of every result before it returns;
 * workers write only status/t/pos of their own candidates.  An NBC_K_OWNER slot is written once, by
 * nbc_add_owner_result, and holds only status (MISS/HIT), t and pos. */
typedef struct nbc_result {
    nbc_u32 status; /* NBC_R_*                                                */
    float t;        /* parameter along the segment (the +0x10 sort key)      */
    float pos[3];   /* hit point                                              */
    nbc_u32 pad[3];
} nbc_result;

/* Relocated addresses from the worker kit (not the unmodified oracle kit). Code and constants must remain
 * mapped and immutable through every dispatch. unit_hit requires the snapshot hooks from that kit. */
typedef struct nbc_kernels {
    nbc_u32 plane, ring, box, wall, unit_hit, unit_inside;
} nbc_kernels;

typedef void(__fastcall* nbc_body_fn)(void* ctx, nbc_u32 chunk);
typedef void(NBC_CALL* nbc_dispatch_fn)(void* user, nbc_body_fn body, nbc_u32 chunks, void* ctx);

/* Per query / per cell state.  Owned by the battle thread, workers only read it and write results[]. */
typedef struct nbc_batch {
    nbc_u32 abi;            /* 0x00 NBC_ABI                                                         */
    nbc_u32 flags;          /* 0x04 NBC_BF_*                                                        */
    nbc_u32 capacity;       /* 0x08                                                                 */
    nbc_u32 count;          /* 0x0C                                                                 */
    nbc_cand* cands;        /* 0x10                                                                 */
    nbc_result* results;    /* 0x14                                                                 */
    const nbc_segment* seg; /* 0x18 arg2 of 0x6392C0 (type used by the "inside" test)                */
    const nbc_segment* alt; /* 0x1C arg5-or-arg2: coordinates the hit point is interpolated on      */
    nbc_u32 dispatch;       /* 0x20 0 or stdcall dispatch(user, body, chunks, ctx) (ntw_pool_dispatch) */
    nbc_u32 dispatch_user;  /* 0x24                                                                 */
    nbc_u32 body_entry;     /* 0x28 address of nbc_chunk_body in the loaded code copy; 0 = run inline (no dispatch) */
    nbc_u32 min_parallel;   /* 0x2C fewer candidates run inline on the caller                       */
    nbc_u32 chunk_items;    /* 0x30 candidates per chunk (0 = 8)                                    */
    nbc_u32 mxcsr;          /* 0x34 caller MXCSR, installed by every chunk                          */
    nbc_u32 cur_cell;       /* 0x38                                                                 */
    nbc_u32 have_cell;      /* 0x3C                                                                 */
    nbc_u32 st_runs;        /* 0x40 owner-written statistics                                        */
    nbc_u32 st_cands;       /* 0x44                                                                 */
    nbc_u32 st_chunks;      /* 0x48                                                                 */
    nbc_u32 st_dispatched;  /* 0x4C                                                                 */
    nbc_u32 st_faults;      /* 0x50 NBC_R_FAULT results                                             */
    nbc_u32 st_serial;      /* 0x54 serial stages requested                                         */
    nbc_u32 x87_cw;         /* 0x58 caller x87 control word                                         */
    nbc_u32 pure;           /* 0x5C worker-computed candidates in the batch (count minus NBC_K_OWNER)  */
    nbc_u32 st_owner;       /* 0x60 owner-computed results seen by nbc_run (owner-written statistics) */
    nbc_u32 pad[7];         /* 0x64 reserved, zero (these two words were reserved zero in ABI 2)      */
    nbc_kernels kernels;    /* 0x80 immutable leaf entry points                                    */
    nbc_u32 pad2[2];        /* 0x98 .. 0xA0                                                         */
} nbc_batch;

/* One appended query result entry = the first five dwords of the original 7-dword entry (rest is 0). */
typedef struct nbc_hit {
    nbc_u32 entry;
    float pos[3];
    float t;
} nbc_hit;

/* Owner callback for NBC_R_SERIAL / NBC_R_FAULT candidates: run the ORIGINAL code for candidate `index`
 * (b->cands[index], b->seg/alt) right now, in original order, and return 1 with *hit filled if it produced a hit. */
typedef nbc_u32(NBC_CALL* nbc_serial_fn)(void* user, nbc_u32 index, nbc_hit* hit);

typedef struct nbc_merge_info {
    nbc_u32 consumed;  /* candidates consumed (stops after the first found cell in stop mode)  */
    nbc_u32 found;     /* the original "found" byte                                              */
    nbc_u32 hits;      /* entries written to out[]                                               */
    nbc_u32 serial;    /* serial callbacks executed                                              */
    nbc_u32 overflow;  /* hits that did not fit in out[] (merge stops, owner must enlarge)       */
} nbc_merge_info;

#ifdef __cplusplus
extern "C" {
#endif

/* Zero-initialises the batch (no allocation), copies kernel bindings and captures MXCSR. */
nbc_u32 NBC_CALL nbc_batch_init(nbc_batch* b, nbc_cand* cands, nbc_result* results, nbc_u32 capacity,
                                const nbc_segment* seg, const nbc_segment* alt, nbc_u32 flags,
                                const nbc_kernels* kernels);
void NBC_CALL nbc_batch_reset(nbc_batch* b); /* drops the candidates, keeps configuration */

/* Raw-entry adders: read the original entry/object fields (offsets recovered in the json), copy immutable inputs. */
nbc_u32 NBC_CALL nbc_add_plane_ring_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode);
nbc_u32 NBC_CALL nbc_add_wall_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode);
nbc_u32 NBC_CALL nbc_add_box_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode);
/* obj2 / b5b77 are what the owner got from the virtual slot +0x18 and 0x5B77A0 at this very point of its loop
 * (b5b77 only matters when sel == 3 and obj2 != 0, exactly as in 0x809620). */
nbc_u32 NBC_CALL nbc_add_unit_entry(nbc_batch* b, const void* entry, nbc_u32 cell, nbc_u32 mode, nbc_u32 obj2,
                                    nbc_u32 b5b77, nbc_u32 sel, float extra);

/* Owner-side flag test that precedes 0x809620 in 0x6392C0 (0x639661..0x63967A): selector 1/4 needs obj+0x34 & 0x10,
 * 2/3 needs obj+0x34 & 8, anything else skips the entry.  Returns 1 when the entry goes on to the unit test. */
nbc_u32 NBC_CALL nbc_unit_flag_ok(const void* entry, nbc_u32 selector);

/* Value adders (same thing without touching game memory; used by the oracle harness and by the entry adders). */
nbc_u32 NBC_CALL nbc_add_plane_ring(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float plane[4],
                                    const void* ring);
nbc_u32 NBC_CALL nbc_add_wall(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float p2d[4],
                              const void* terrain, float band);
nbc_u32 NBC_CALL nbc_add_box(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float box[6]);
nbc_u32 NBC_CALL nbc_add_unit(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 mode, const float unit5[5],
                              nbc_u32 obj2, nbc_u32 b5b77, nbc_u32 sel, float extra);

/* Records a narrow-phase outcome the owner computed itself, at the original point of its loop (rule 6).  It consumes one
 * candidate slot exactly like the nbc_add_* of the same entry and applies the same checks (NBC_E_ARG, NBC_E_FULL,
 * NBC_E_CELL; never NBC_E_STRICT: the stage has already run in order).  hit == NULL records a miss; otherwise hit->entry
 * MUST equal `entry` (NBC_E_ARG otherwise) and hit->pos/t are stored by value.  flags is 0 or NBC_CF_FOUND_ON_VISIT
 * (the entry set "found" when visited, hit or not); any other bit is NBC_E_ARG.  No game memory is read or kept. */
nbc_u32 NBC_CALL nbc_add_owner_result(nbc_batch* b, nbc_u32 entry, nbc_u32 cell, nbc_u32 flags, const nbc_hit* hit);

/* Computes every worker-computed candidate (independent jobs; persistent dispatcher when b->dispatch != 0 and the number
 * of such candidates >= min_parallel, else inline).  NBC_K_OWNER slots are never recomputed or overwritten; a batch
 * with no worker-computed candidate never reaches the dispatcher.  Returns NBC_OK / NBC_E_FPCW / NBC_E_ARG. */
nbc_u32 NBC_CALL nbc_run(nbc_batch* b);

/* Ordered merge (see header comment).  serial may be 0 only if no result needs it (otherwise NBC_E_SERIAL). */
nbc_u32 NBC_CALL nbc_merge(const nbc_batch* b, nbc_hit* out, nbc_u32 out_capacity, nbc_serial_fn serial,
                           void* serial_user, nbc_merge_info* info);

/* One worker chunk (exposed for the oracle harness and for dispatchers that need the address). */
void __fastcall nbc_chunk_body(void* ctx, nbc_u32 chunk);

/* Contract words: abi, cand bytes, result bytes, batch bytes, binding bytes, leaf entry count, 0, 0. */
extern const nbc_u32 nbc_contract[8];

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
static_assert(sizeof(nbc_segment) == 28, "segment");
static_assert(sizeof(nbc_cand) == NBC_CAND_BYTES, "candidate size");
static_assert(sizeof(nbc_result) == NBC_RESULT_BYTES, "result size");
static_assert(sizeof(nbc_kernels) == 24, "kernel bindings size");
static_assert(sizeof(nbc_batch) == NBC_BATCH_BYTES, "batch size");
static_assert(offsetof(nbc_batch, kernels) == 0x80, "kernels offset");
static_assert(offsetof(nbc_batch, pure) == 0x5C, "pure offset");
static_assert(offsetof(nbc_batch, st_owner) == 0x60, "owner statistics offset");
static_assert(offsetof(nbc_cand, p) == 0x20, "payload offset");
#else
typedef char nbc_assert_cand[(sizeof(nbc_cand) == NBC_CAND_BYTES) ? 1 : -1];
typedef char nbc_assert_result[(sizeof(nbc_result) == NBC_RESULT_BYTES) ? 1 : -1];
typedef char nbc_assert_batch[(sizeof(nbc_batch) == NBC_BATCH_BYTES) ? 1 : -1];
#endif

#endif
