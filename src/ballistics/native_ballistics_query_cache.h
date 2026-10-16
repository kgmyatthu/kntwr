// Shared ABI of native_ballistics_query_cache.dll: in-process owner of the ballistic unit narrow-phase precomputation for the
// pinned Napoleon.exe (SHA-256 13fcab62...cbad4, preferred base 0x400000).  The DLL contains no patching code.  Every call
// site that reaches it is a PRIVATE CLONE of original code:
//   * a clone of 0x6392C0..0x639BFC (the ORIGINAL grid query, code only, 2364 bytes) together with a private copy of its
//     four entry computed-jump table 0x639BFC..0x639C0C.  Instruction 0x639661 (FF 24 85 disp32) references the PRIVATE table
//     whose entries retarget 0x639668 / 0x639670 / 0x639670 / 0x639668 into the clone.
//   * call 0x639581 (original 0x10EED80, cell gather)   -> nqc_gather_hook
//   * call 0x639699 (original 0x809620, unit capsule)   -> nqc_unit_hook
//   * the projectile clone of 0x53C060 replaces ONLY its call of 0x6392C0 with nqc_query_hook.
// Nothing else of the query changes: cell enumeration, predicates, visited-bit writes, flag tests, hit positions, 0x5EF540
// appends, RNG and effects stay the original instructions in the original order.  This module only precomputes the PURE
// numeric result of 0x809620 for unit candidates (type 8 entries) on private snapshots (existing nbc ABI 3 + worker kit +
// persistent dispatcher) and hands it back when the original asks for exactly that numeric result.
//
// Exports (link names undecorated for C use; the .cpp carries the /EXPORT pragmas for the decorated symbols):
//   nqc_initialize(void* config)  __stdcall, 0 or an NQC_E_* error.  Reads exactly the sixteen config words below.
//   nqc_stop(void* unused)        __stdcall, 0 (stopped) or an NQC_E_* error.
//   nqc_query_hook                __fastcall(ECX = grid, EDX ignored) + NINE stack dwords, `ret 0x24`:
//                                 out, segment, stop, mask, alt, mode, visited, arg8, extra  (frame +8 .. +0x28 of 0x6392C0).
//                                 Runs the private query clone inside one exclusive scope, or the ORIGINAL 0x6392C0.
//   nqc_gather_hook               naked, ECX = cell vector, FIVE stack dwords, `ret 0x14`.  Runs the ORIGINAL 0x10EED80 exactly
//                                 once with a copy of the arguments, then (inside the owner scope only) prepares, and returns
//                                 with EAX/ECX/EDX/EBX/ESI/EDI/EBP/ESP/EFLAGS, x87 control/status/tag and MXCSR, xmm0..7 exactly
//                                 as the original call left them.
//   nqc_unit_hook                 __fastcall(object, ignored, ray6*, mode, float* outT, selector, float extra), `ret 0x14`:
//                                 serves the cached numeric result or runs the ORIGINAL 0x809620 exactly once.
//   nqc_state                     exported DATA, NQC_STATE_WORDS u32 words (below).
#pragma once

#ifndef _M_IX86
#error native_ballistics_query_cache is a 32-bit x86 ABI.
#endif

#include <stdint.h>

#define NQC_ABI 1u
#define NQC_CONFIG_WORDS 16u
#define NQC_CONFIG_BYTES 64u
#define NQC_STATE_WORDS 16u
#define NQC_STATE_BYTES 64u

// Configuration limits enforced by nqc_initialize.
#define NQC_MAX_CAPACITY 0x10000u      // distinct unit candidates cached per query (unit ids are 16 bit)
#define NQC_MAX_MIN_PARALLEL 0x40000000u

// nqc_initialize(config): exactly sixteen u32 words (NQC_CONFIG_BYTES).
struct nqc_config {
    uint32_t abi;          // NQC_ABI
    uint32_t size;         // NQC_CONFIG_BYTES
    uint32_t imageDelta;   // live image base - 0x400000 (multiple of 0x10000).  Every pinned VA below is VA + imageDelta
    uint32_t root;         // expected [model]            (model identity: [model] == root)
    uint32_t model;        // address of the world model object; the query grid must equal [model + 0xA4]
    uint32_t capacity;     // 1 .. NQC_MAX_CAPACITY distinct candidates per query; further ones simply stay native
    uint32_t minParallel;  // >= 1: fewer worker-computed candidates than this run inline on the owner (no wake-up)
    uint32_t dispatch;     // address of ntw_pool_dispatch (stdcall(user, body, chunks, ctx)) of the EXISTING persistent pool
    uint32_t pool;         // address of that ntw_pool (NTW_POOL_ALIGN aligned, state READY).  Never initialised/shut down here
    uint32_t queryClone;   // address of the PRIVATE clone of 0x6392C0 (fastcall, nine stack dwords, ret 0x24)
    uint32_t kPlane;       // relocated WORKER-kit leaf entries, nbc_kernels order: plane, ring, box, wall, unit_hit, unit_inside.
    uint32_t kRing;        // Code and constants must stay mapped and immutable for the life of the process.
    uint32_t kBox;
    uint32_t kWall;
    uint32_t kUnitHit;
    uint32_t kUnitInside;
};
static_assert(sizeof(nqc_config) == NQC_CONFIG_BYTES, "nqc_config is sixteen u32 words");

// Error codes: low byte = class, bits 8.. = detail.  Success is exactly 0.
//   ARG     detail = 1 + index of the offending config word (0: config unreadable); 0xFF: restart with an imageDelta that differs
//           from the published session.
//   STATE   initialize: initializing / ready / stopping, or a restart whose stopped, ownerless precondition does not hold
//           (detail 1).  stop: never initialized.
//   IMAGE   a pinned original code region differs from the approved image at imageDelta.  detail bits 0..3 = 1 + region index
//           (0 query, 1 unit_hit, 2 gather, 3 predicate), bits 4..7 = failure (1 unreadable, 2 bytes differ from the pinned
//           hash, 3 an operand is not at its expected value, 4 original jump table), bits 8.. = hole index.  Nothing was published.
//   MEMORY  VirtualAlloc of the private storage failed; detail = GetLastError().
//   KERNEL  detail bits 0..3 = 1 + kernel index (nbc_kernels order), bits 4..7 = failure (1 not executable committed memory,
//           2 first bytes are not the pinned original bytes).
//   POOL    the pool/dispatch is not a ready persistent pool (detail 1: unreadable, 2: abi, 3: not aligned, 4: state not READY,
//           5: workers out of range, 6: dispatch not executable).
//   BUSY    stop: a query scope is active (entries are already disabled; call again later).
//   PIN     GetModuleHandleExW(PIN) failed (detail = GetLastError()): the DLL could not be pinned.
//   CLONE   the private clone is not the pinned query code (detail 1: unreadable/not executable, 2: bytes differ from the
//           pinned hash, 3: an operand is not at its expected value, 4: jump-table entry/reference wrong, 5: gather seam not
//           redirected to nqc_gather_hook, 6: unit seam not redirected to nqc_unit_hook).  Detail bits 8.. = hole index.
#define NQC_OK 0u
#define NQC_E_ARG 1u
#define NQC_E_STATE 2u
#define NQC_E_IMAGE 3u
#define NQC_E_MEMORY 4u
#define NQC_E_KERNEL 5u
#define NQC_E_POOL 6u
#define NQC_E_BUSY 7u
#define NQC_E_PIN 8u
#define NQC_E_CLONE 9u
#define NQC_ERR_CLASS(e) ((e) & 0xFFu)
#define NQC_ERR_DETAIL(e) ((e) >> 8)

// nqc_state words.  `enabled`, `busy` and `ownerThread` change only with Interlocked operations; counters are cumulative since
// the last successful nqc_initialize and updated with Interlocked increments.  Readable by anybody.
enum nqc_state_word {
    NQC_S_ABI = 0,              // NQC_ABI
    NQC_S_SIZE = 1,             // NQC_STATE_BYTES
    NQC_S_ENABLED = 2,          // 1 while hooks may claim a scope
    NQC_S_BUSY = 3,             // 1 while a query scope is active
    NQC_S_OWNER_THREAD = 4,     // thread id of the scope owner, else 0
    NQC_S_PREPARATIONS = 5,     // gather preparations that reached the walk
    NQC_S_CANDIDATES = 6,       // unit candidates computed (cumulative, after dedupe)
    NQC_S_CACHE_HITS = 7,       // 0x809620 calls answered from the cache
    NQC_S_FALLBACKS = 8,        // calls that ran the ORIGINAL 0x809620 (any reason) or the ORIGINAL 0x6392C0 (busy / wrong context)
    NQC_S_CHANGED = 9,          // consume-time validation mismatches (subset of the unit fallbacks)
    NQC_S_UNSUPPORTED = 10,     // declined query shapes / FP controls / malformed lists / candidates with a non-pure getter
    NQC_S_CAPACITY_SKIPPED = 11,  // candidates left native because the cache was full
    NQC_S_TEAM_DISPATCHES = 12,   // pool st_team delta over our synchronous runs
    NQC_S_WORKER_CHUNKS = 13,     // sum of worker slot chunks delta over our runs
    NQC_S_CALLER_CHUNKS = 14,     // chunks run on the owner: pool st_main_chunks delta + chunks run inline / serially
    NQC_S_STORAGE_BYTES = 15,     // bytes of the current private storage block
};

// Pinned original addresses (preferred base) the DLL relies on.
#define NQC_VA_QUERY 0x6392C0u
#define NQC_VA_QUERY_END 0x639BFCu
#define NQC_VA_TABLE 0x639BFCu
#define NQC_VA_GATHER 0x10EED80u
#define NQC_VA_UNIT_HIT 0x809620u
#define NQC_VA_GATHER_CALL 0x639581u
#define NQC_VA_UNIT_CALL 0x639699u
#define NQC_VA_MODEL_GRID 0xA4u    // [model + 0xA4] == query grid

// Eligible query (everything else runs completely native): source segment type 2, alt segment type 2 (selector 2), candidate
// entries kind 8 whose object has byte [obj+0x30] != 0 (0x6DC9A0), whose id bit is clear in the unit visited bitset and whose
// [obj+0x34] has bit 8 set; the unit vtable slot +0x18 must be one of the pure leaves recognised by the module.
