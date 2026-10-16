/* Shared ABI for the NTW ballistics prefix stage (pinned x86 Napoleon.exe, SHA-256 13fcab62...2cbad4).
 *
 * C and C++ compatible, import-free, no CRT.  Offsets are byte offsets inside one projectile
 * ("item", the object manager 0x6F6BC0 iterates and 0x6F54E0 updates).
 *
 * Contract summary (see native_ballistics_payload.py for the full integration contract):
 *   bal_stage(mgr, job)           serial O(1), before the per-item loop: publish the item array, dispatch chunks
 *   bal_worker(job, chunk)        parallel body: snapshots its items and runs the cloned ORIGINAL prefix
 *                                 machine code on private shadows (writes only its own records)
 *   bal_step(item, job)           serial, replaces `call 0x6F54E0`: validate + commit + enter the original tail
 *   bal_tail_enter(item, job)     continuation into the original 0x6F5936 with the exact register/frame contract
 */
#ifndef NATIVE_BALLISTICS_ABI_H
#define NATIVE_BALLISTICS_ABI_H

#ifndef _M_IX86
#error This ABI describes 32-bit x86 pointers; compile as x86.
#endif
#include <stddef.h>

typedef unsigned char bal_u8;
typedef unsigned int bal_u32;

#define BAL_ABI_VERSION 1u
#define BAL_RECORD_BYTES 0x100u
#define BAL_SHADOW_BYTES 0xB0u
#define BAL_JOB_BYTES 0x100u

/* record status */
#define BAL_ST_EMPTY 0u
#define BAL_ST_SKIP 1u      /* item +0x41 != 0 or null definition: original path only        */
#define BAL_ST_PENDING 2u   /* snapshot taken, prefix not yet computed                         */
#define BAL_ST_READY 3u     /* prefix computed on the shadow, awaiting ordered commit         */
#define BAL_ST_BADPREFIX 4u /* cloned prefix reported the skip exit unexpectedly: not committed */

/* job flags */
#define BAL_FLAG_VERIFY 1u  /* serial step re-runs the clone on a live copy and compares with the worker result */
#define BAL_FLAG_DISABLE 2u /* stage snapshots nothing: every item takes the original function */

/* One contiguous worker-owned record per live projectile, in manager-array order.  256 bytes. */
typedef struct bal_record {
    bal_u32 item;        /* 0x00 projectile address                                                  */
    bal_u32 status;      /* 0x04 BAL_ST_*                                                            */
    bal_u32 def_e4;      /* 0x08 definition(+0xE4) byte read by the prefix (zero extended)           */
    bal_u32 def_60;      /* 0x0C definition(+0x60) dword                                             */
    bal_u32 def_91;      /* 0x10 definition(+0x91) byte (zero extended)                              */
    bal_u32 pad0[3];     /* 0x14                                                                    */
    bal_u32 in_pos[3];   /* 0x20 item +0x64..+0x6F before the prefix (input and output)              */
    bal_u32 in_vel[3];   /* 0x2C item +0x70..+0x7B before the prefix (input and output)              */
    bal_u32 in_40;       /* 0x38 item +0x40 byte before                                              */
    bal_u32 in_49;       /* 0x3C item +0x49 byte before                                              */
    bal_u32 in_8c;       /* 0x40 item +0x8C before                                                   */
    bal_u32 in_90;       /* 0x44 item +0x90 before                                                   */
    bal_u32 in_94;       /* 0x48 item +0x94 before                                                   */
    bal_u32 pad1;        /* 0x4C                                                                    */
    bal_u8 shadow[BAL_SHADOW_BYTES]; /* 0x50 copy of item[0..0xB0); the cloned prefix runs on it with ECX=&shadow */
} bal_record;

/* Per-tick job; lives in the payload data page.  Counters are written only by the ordered main thread. */
typedef struct bal_job {
    bal_u32 abi;          /* 0x00 BAL_ABI_VERSION                                                    */
    bal_u32 capacity;     /* 0x04 records available; stage with more items leaves the original path  */
    bal_u32 count;        /* 0x08 records valid this tick                                            */
    bal_u32 cursor;       /* 0x0C next record the ordered step expects                               */
    bal_record* records;  /* 0x10                                                                    */
    bal_u32 prefix_entry; /* 0x14 cloned original 0x6F54E0..0x6F5935 (ECX=&shadow, EAX=1 ready/0 skip) */
    bal_u32 orig_item;    /* 0x18 live 0x6F54E0 (thiscall ECX=item)                                  */
    bal_u32 tail_va;      /* 0x1C live 0x6F5936                                                      */
    bal_u32 one_ptr;      /* 0x20 live address of the 1.0f constant at 0x1318048                     */
    bal_u32 dispatch;     /* 0x24 0 or stdcall void dispatch(user, body, chunks, ctx); must not return early */
    bal_u32 dispatch_user;/* 0x28                                                                    */
    bal_u32 min_parallel; /* 0x2C minimum item count for dispatch; below it chunks run inline        */
    bal_u32 chunk_items;  /* 0x30 items per chunk (>0)                                               */
    bal_u32 mxcsr;        /* 0x34 MXCSR of the stage thread, installed by every worker chunk         */
    bal_u32 flags;        /* 0x38 BAL_FLAG_*                                                         */
    bal_u32 worker_entry; /* 0x3C live address of bal_worker (fastcall ECX=job, EDX=chunk)           */
    bal_u32 st_stages;    /* 0x40 */
    bal_u32 st_items;     /* 0x44 items seen by the stage                                            */
    bal_u32 st_skip;      /* 0x48 ordered steps whose record was SKIP (+0x41 set / null definition)  */
    bal_u32 st_prefixed;  /* 0x4C ordered steps that found a READY worker result                     */
    bal_u32 st_committed; /* 0x50 ordered steps that committed the worker result and entered the tail */
    bal_u32 st_rejected;  /* 0x54 snapshot no longer matched at the ordered turn: original function  */
    bal_u32 st_overflow;  /* 0x58 stages with more items than capacity                               */
    bal_u32 st_unmatched; /* 0x5C ordered steps with no matching record (original function)          */
    bal_u32 st_verify_bad;/* 0x60 BAL_FLAG_VERIFY mismatches between worker and ordered re-execution */
    bal_u32 st_chunks;    /* 0x64 chunks executed                                                    */
    bal_u32 st_dispatched;/* 0x68 stages that used the dispatch callback                             */
    bal_u32 items;        /* 0x6C item pointer array published by the stage (manager+0x14)           */
    bal_u32 pad[(BAL_JOB_BYTES - 0x70) / 4];
} bal_job;

/* Exported contract words (bal_contract[]): abi, record bytes, job bytes, shadow bytes. */
#define BAL_CONTRACT_WORDS 8u

#ifdef __cplusplus
static_assert(sizeof(bal_record) == BAL_RECORD_BYTES, "record size");
static_assert(sizeof(bal_job) == BAL_JOB_BYTES, "job size");
static_assert(offsetof(bal_record, shadow) == 0x50, "shadow offset");
#else
typedef char bal_assert_record_size[(sizeof(bal_record) == BAL_RECORD_BYTES) ? 1 : -1];
typedef char bal_assert_job_size[(sizeof(bal_job) == BAL_JOB_BYTES) ? 1 : -1];
#endif

#endif
