/* ABI of the NTW persistent worker dispatcher (x86, import-free, CRT-free, position independent).
 *
 * C and C++ compatible.  One pool = one bounded team of persistent Win32 worker threads plus the calling
 * (battle) thread, which participates in every dispatch.  All pool state lives in caller-owned storage
 * (NTW_POOL_BYTES, NTW_POOL_ALIGN-aligned, zero-filled before the first ntw_pool_init); the helpers
 * allocate nothing, create no thread after init and keep no global.
 *
 * Exports (all __stdcall; the code section is copied verbatim, every Win32 entry is passed in the init table):
 *   ntw_pool_dispatch(user, body, chunks, ctx)   void; user = ntw_pool*; body = void(__fastcall*)(void* ctx, u32 chunk)
 *       Runs body(ctx, i) exactly once for every i in [0, chunks) and returns only after ALL of them have
 *       returned (caller's thread claims chunks too).  Matches bal_job.dispatch of native_ballistics_abi.h.
 *   ntw_pool_init(pool, cfg)                      waits for worker startup, returns NTW_POOL_OK or NTW_POOL_E_*
 *   ntw_pool_shutdown(pool)                       wakes + joins every worker, closes every handle, re-zeroes the storage
 *   ntw_pool_worker_start(slot)                   thread entry; ONLY its relocated address is used (cfg->api.worker_entry)
 *   ntw_pool_contract[NTW_POOL_CONTRACT_WORDS]    exported data (link '/EXPORT:ntw_pool_contract,DATA')
 *
 * Optional startup: cfg->thread_init is ntw_u32(__stdcall*)(ntw_u32 context, ntw_u32 worker_index).
 * It runs exactly once on each created worker, before any body, with cfg->thread_init_context and its
 * zero-based index; 0 means success, any other value is recorded verbatim in slot.init_result. It must
 * return normally (no exceptions), must not dispatch or change pool state, and must remain callable until
 * init returns. All created workers finish startup before init returns, including partial-create unwind.
 * READY is published only after every worker succeeds; any failure returns NTW_POOL_E_INIT after joining
 * and closing all resources. init_completed, init_failed and every slot.init_result survive failed init
 * with a callback (state UNINIT); the next init resets them. E_JOIN instead retains handles/state BROKEN
 * when a thread cannot be joined; caller must keep pool storage and callback context alive, and may call
 * ntw_pool_shutdown again to retry the join (BROKEN is accepted there; a retried teardown with a callback
 * keeps init_completed/init_failed/init_result and leaves state UNINIT). Do not read slot rows or free
 * storage while workers may still run.
 * A null callback preserves the default thread environment and failed-init zeroing behavior.
 *
 * Contract of bodies: pure numerical work on the ctx they are given. Without a startup callback workers
 * have the default thread FP environment (MXCSR 0x1F80, x87 CW 0x27F). Bodies must install any other FP
 * state they need themselves and restore it; they must not call game TLS-dependent routines unless the
 * startup callback established the required state. Bodies must not throw and must return before dispatch
 * can return. Bodies of different chunk indices run concurrently. The calling thread's MXCSR is saved
 * and restored around dispatch; the startup callback is NOT run on the calling thread.
 *
 * Lifecycle misuse is never reported as completion.  A dispatch that cannot own the team (called from inside
 * a body, from a second thread while a dispatch is in flight, on an uninitialised / shut down / failed pool,
 * or with chunks > NTW_POOL_MAX_CHUNKS) executes all of its chunks serially on the calling thread, so the
 * exact-once / returns-after-completion guarantee holds in every case (st_inline counts them).
 * ntw_pool_init on a live pool returns NTW_POOL_E_STATE without touching it; ntw_pool_shutdown during a
 * dispatch returns NTW_POOL_E_BUSY without touching it.  A dispatch with body == 0 and chunks != 0 is a
 * caller bug (it faults); pool storage freed while a dispatch is in flight is a caller bug.
 */
#ifndef NATIVE_WORKER_DISPATCH_H
#define NATIVE_WORKER_DISPATCH_H

#ifndef _M_IX86
#error This ABI describes 32-bit x86 pointers; compile as x86.
#endif
#include <stddef.h>

typedef unsigned int ntw_u32;

#define NTW_POOL_ABI 2u
#define NTW_POOL_MAX_WORKERS 31u        /* worker threads besides the caller: at most 32 participants      */
#define NTW_POOL_MAX_CHUNKS 0x40000000u /* larger counts run serially (claim counter must never wrap)     */
#define NTW_POOL_ALIGN 64u              /* pool storage alignment (cache line)                             */
#define NTW_POOL_BYTES 0x540u
#define NTW_POOL_CONFIG_BYTES 0x2Cu
#define NTW_POOL_CONTRACT_WORDS 8u

/* ntw_pool_init / ntw_pool_shutdown results */
#define NTW_POOL_OK 0u
#define NTW_POOL_E_ARG 1u     /* null pointer, wrong cfg->abi, workers > max, missing api entry          */
#define NTW_POOL_E_ALIGN 2u   /* pool not NTW_POOL_ALIGN aligned                                         */
#define NTW_POOL_E_STATE 3u   /* init: pool not in the zeroed state; shutdown: pool not initialised      */
#define NTW_POOL_E_EVENT 4u   /* CreateEvent failed (everything created so far was released)             */
#define NTW_POOL_E_THREAD 5u  /* CreateThread failed (every started thread was joined and released)      */
#define NTW_POOL_E_BUSY 6u    /* shutdown while a dispatch is running: nothing changed                   */
#define NTW_POOL_E_JOIN 7u    /* a wait on a worker failed: handles kept, state BROKEN, shutdown retries   */
#define NTW_POOL_E_INIT 8u    /* worker startup callback failed; diagnostic fields survive safe unwind */

/* pool.state */
#define NTW_POOL_S_UNINIT 0u
#define NTW_POOL_S_INIT 1u
#define NTW_POOL_S_READY 2u
#define NTW_POOL_S_BUSY 3u
#define NTW_POOL_S_STOPPING 4u
#define NTW_POOL_S_BROKEN 5u

/* Win32 entry points, copied from the real kernel32 by the loader (stdcall, 32-bit HANDLE/BOOL/DWORD as u32).
 *   create_event  HANDLE CreateEventW(0, bManualReset, bInitialState, 0)   (called as (0,0,0,0): auto-reset, unsignalled, unnamed)
 *   close_handle  BOOL   CloseHandle(h)
 *   set_event     BOOL   SetEvent(h)
 *   wait_single   DWORD  WaitForSingleObject(h, ms)                        (only INFINITE is used)
 *   create_thread HANDLE CreateThread(0, stack, start, param, flags, 0)
 *   worker_entry  relocated address of ntw_pool_worker_start inside the loaded code copy               */
typedef struct ntw_pool_api {
    ntw_u32 create_event;  /* 0x00 */
    ntw_u32 close_handle;  /* 0x04 */
    ntw_u32 set_event;     /* 0x08 */
    ntw_u32 wait_single;   /* 0x0C */
    ntw_u32 create_thread; /* 0x10 */
    ntw_u32 worker_entry;  /* 0x14 */
} ntw_pool_api;

typedef struct ntw_pool_config {
    ntw_u32 abi;           /* 0x00 NTW_POOL_ABI                                                       */
    ntw_u32 workers;       /* 0x04 worker threads besides the caller, 0..NTW_POOL_MAX_WORKERS (0: caller-only) */
    ntw_u32 stack_bytes;   /* 0x08 worker stack reservation; 0 = process default                      */
    ntw_pool_api api;      /* 0x0C copied into the pool; the config may be freed after init           */
    ntw_u32 thread_init;   /* 0x24 optional stdcall callback(context, worker_index), 0 success         */
    ntw_u32 thread_init_context; /* 0x28 opaque callback context; copied, not owned                    */
} ntw_pool_config;

/* One per worker; 32 bytes. `dead`, `chunks`, `wakes`, `init_result` are written by the owning worker. */
typedef struct ntw_pool_slot {
    ntw_u32 pool;    /* 0x00 owning pool (thread parameter is &slot)                                    */
    ntw_u32 index;   /* 0x04                                                                            */
    ntw_u32 thread;  /* 0x08 thread HANDLE, 0 once joined and closed                                    */
    ntw_u32 wake;    /* 0x0C auto-reset unnamed event the worker sleeps on                              */
    ntw_u32 dead;    /* 0x10 set by a worker whose wait failed (it exits; dispatch no longer wakes it)  */
    ntw_u32 chunks;  /* 0x14 chunks executed by this worker                                             */
    ntw_u32 wakes;   /* 0x18 dispatches this worker took part in                                        */
    ntw_u32 init_result; /* 0x1C startup callback return value (0 also when no callback)                */
} ntw_pool_slot;

typedef struct ntw_pool {
    /* line 0: lifecycle, constant between init and shutdown */
    ntw_u32 state;         /* 0x00 NTW_POOL_S_*; 0 = zero-filled storage                                */
    ntw_u32 abi;           /* 0x04                                                                      */
    ntw_u32 workers;       /* 0x08 running worker threads (published when init succeeds)                */
    ntw_u32 created;       /* 0x0C slots whose events/thread init touched (teardown range)              */
    ntw_u32 stop;          /* 0x10 shutdown / init-unwind flag the workers test after every wake        */
    ntw_u32 done;          /* 0x14 auto-reset barrier event                                             */
    ntw_u32 stack_bytes;   /* 0x18                                                                      */
    ntw_pool_api api;      /* 0x1C..0x33                                                                */
    ntw_u32 thread_init;   /* 0x34 optional startup callback address                                   */
    ntw_u32 thread_init_context; /* 0x38 opaque startup context                                        */
    ntw_u32 init_completed;/* 0x3C workers whose startup completed (atomic)                            */
    /* line 1: the published job (written by the dispatching thread before it wakes anybody) */
    ntw_u32 body;          /* 0x40                                                                      */
    ntw_u32 ctx;           /* 0x44                                                                      */
    ntw_u32 chunks;        /* 0x48                                                                      */
    ntw_u32 init_failed;   /* 0x4C workers whose startup callback returned nonzero (atomic)             */
    ntw_u32 pad1[12];      /* 0x50                                                                      */
    /* line 2: atomic chunk claim counter */
    ntw_u32 next;          /* 0x80 next unclaimed chunk (may exceed chunks by < participants)           */
    ntw_u32 pad2[15];
    /* line 3: barrier: 1 token for the dispatching thread + 1 per woken worker */
    ntw_u32 outstanding;   /* 0xC0                                                                      */
    ntw_u32 pad3[15];
    /* line 4: statistics (dispatching thread only, except st_inline which is atomic) */
    ntw_u32 st_calls;      /* 0x100 dispatches that owned the pool                                      */
    ntw_u32 st_team;       /* 0x104 ... that took the team path (chunks > 1 and workers > 0)            */
    ntw_u32 st_serial;     /* 0x108 ... that ran every chunk on the caller (1 chunk, 0 workers)         */
    ntw_u32 st_woken;      /* 0x10C workers signalled in total                                          */
    ntw_u32 st_wake_fail;  /* 0x110 SetEvent failures (the chunks were then taken by the others)        */
    ntw_u32 st_main_chunks;/* 0x114 chunks executed by the dispatching thread of owning dispatches      */
    ntw_u32 st_inline;     /* 0x118 dispatches that could not own the pool and ran serially (atomic)    */
    ntw_u32 pad4[9];
    ntw_pool_slot slots[NTW_POOL_MAX_WORKERS]; /* 0x140 */
    ntw_u32 pad5[8];       /* 0x520 */
} ntw_pool;

/* Exported contract words: abi, pool bytes, pool alignment, max workers, config bytes, max chunks, state READY, 0. */
#ifdef __cplusplus
static_assert(sizeof(ntw_pool) == NTW_POOL_BYTES, "pool size");
static_assert(sizeof(ntw_pool_config) == NTW_POOL_CONFIG_BYTES, "config size");
static_assert(sizeof(ntw_pool_slot) == 0x20, "slot size");
static_assert(offsetof(ntw_pool_config, thread_init) == 0x24, "startup config");
static_assert(offsetof(ntw_pool, thread_init) == 0x34, "startup callback");
static_assert(offsetof(ntw_pool, init_completed) == 0x3C, "startup completions");
static_assert(offsetof(ntw_pool, init_failed) == 0x4C, "startup failures");
static_assert(offsetof(ntw_pool_slot, init_result) == 0x1C, "startup result");
static_assert(offsetof(ntw_pool, body) == 0x40, "job line");
static_assert(offsetof(ntw_pool, next) == 0x80, "claim line");
static_assert(offsetof(ntw_pool, outstanding) == 0xC0, "barrier line");
static_assert(offsetof(ntw_pool, st_calls) == 0x100, "stats line");
static_assert(offsetof(ntw_pool, slots) == 0x140, "slots");
#else
typedef char ntw_assert_pool_size[(sizeof(ntw_pool) == NTW_POOL_BYTES) ? 1 : -1];
typedef char ntw_assert_config_size[(sizeof(ntw_pool_config) == NTW_POOL_CONFIG_BYTES) ? 1 : -1];
typedef char ntw_assert_slot_size[(sizeof(ntw_pool_slot) == 0x20) ? 1 : -1];
typedef char ntw_assert_init_config[(offsetof(ntw_pool_config, thread_init) == 0x24) ? 1 : -1];
typedef char ntw_assert_init_callback[(offsetof(ntw_pool, thread_init) == 0x34) ? 1 : -1];
typedef char ntw_assert_init_completed[(offsetof(ntw_pool, init_completed) == 0x3C) ? 1 : -1];
typedef char ntw_assert_init_failed[(offsetof(ntw_pool, init_failed) == 0x4C) ? 1 : -1];
typedef char ntw_assert_init_result[(offsetof(ntw_pool_slot, init_result) == 0x1C) ? 1 : -1];
typedef char ntw_assert_job_line[(offsetof(ntw_pool, body) == 0x40) ? 1 : -1];
typedef char ntw_assert_claim_line[(offsetof(ntw_pool, next) == 0x80) ? 1 : -1];
typedef char ntw_assert_barrier_line[(offsetof(ntw_pool, outstanding) == 0xC0) ? 1 : -1];
typedef char ntw_assert_stats_line[(offsetof(ntw_pool, st_calls) == 0x100) ? 1 : -1];
typedef char ntw_assert_slots[(offsetof(ntw_pool, slots) == 0x140) ? 1 : -1];
#endif

#endif
