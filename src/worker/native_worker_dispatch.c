/* Import-free, CRT-free, position-independent x86 persistent worker dispatcher (see native_worker_dispatch.h).
 *
 * Team model: `workers` persistent Win32 threads sleep on one private auto-reset event each (no spinning).  A
 * dispatch publishes {body, ctx, chunks}, resets the atomic claim counter, signals min(workers, chunks-1)
 * events and then claims chunks itself.  Every participant claims the next unclaimed chunk with one
 * interlocked increment, so each index in [0, chunks) runs exactly once.  The barrier is a counter holding one
 * token for the dispatching thread plus one per woken worker; a worker releases its token only after it
 * stopped claiming, and the dispatching thread returns only when the counter is zero, so no worker can still
 * be inside the job (or read stale job fields) when the next dispatch re-publishes it.  Interlocked operations
 * are full barriers, so every body store is visible to the caller after the barrier.
 *
 * No heap, no globals, no string/jump-table data, no CRT calls (zeroing uses __stosd): the .text section is
 * copied verbatim into the game.  Every Win32 function arrives through the init table.
 *
 * Build (x86 MSVC; CMake target ntw2_worker_dispatch, flags recorded in the top-level CMakeLists.txt):
 *   cl /nologo /c /TC /O2 /GS- /Gy /Zl /W4 native_worker_dispatch.c
 *   standalone payload DLL: CMake target ntw2_payload_worker_dispatch (/DLL /NOENTRY /NODEFAULTLIB /MACHINE:X86 /OPT:REF)
 */
#include <intrin.h>
#include <xmmintrin.h>
#include "native_worker_dispatch.h"

#pragma intrinsic(__stosd)

#define NTW_INFINITE 0xFFFFFFFFu
#define NTW_WAIT_OBJECT_0 0u
#define NTW_STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000u

typedef ntw_u32(__stdcall* ntw_fn_create_event)(ntw_u32 attrs, ntw_u32 manual, ntw_u32 initial, ntw_u32 name);
typedef ntw_u32(__stdcall* ntw_fn_handle)(ntw_u32 handle);
typedef ntw_u32(__stdcall* ntw_fn_wait)(ntw_u32 handle, ntw_u32 ms);
typedef ntw_u32(__stdcall* ntw_fn_create_thread)(ntw_u32 attrs, ntw_u32 stack, ntw_u32 start, ntw_u32 param,
                                                 ntw_u32 flags, ntw_u32 id);
typedef void(__fastcall* ntw_fn_body)(void* ctx, ntw_u32 chunk);
typedef ntw_u32(__stdcall* ntw_fn_thread_init)(ntw_u32 context, ntw_u32 worker_index);

#define LONGP(x) ((volatile long*)&(x))
#define RD(x) (*(volatile ntw_u32*)&(x))
#define AINC(x) ((ntw_u32)_InterlockedIncrement(LONGP(x)))
#define ADEC(x) ((ntw_u32)_InterlockedDecrement(LONGP(x)))
#define AXCHG(x, v) ((ntw_u32)_InterlockedExchange(LONGP(x), (long)(v)))
#define ACAS(x, nv, cmp) ((ntw_u32)_InterlockedCompareExchange(LONGP(x), (long)(nv), (long)(cmp)))

/* Claim and run chunks until none is left; returns how many this thread ran. */
static ntw_u32 ntw_run(ntw_pool* p)
{
    ntw_fn_body fn = (ntw_fn_body)RD(p->body);
    void* ctx = (void*)RD(p->ctx);
    ntw_u32 chunks = RD(p->chunks);
    ntw_u32 n = 0;
    ntw_u32 i;

    for (;;) {
        i = AINC(p->next) - 1u;
        if (i >= chunks) {
            break;
        }
        fn(ctx, i);
        ++n;
    }
    return n;
}

/* Persistent worker.  Parameter = the worker's own slot inside the pool storage. */
ntw_u32 __stdcall ntw_pool_worker_start(void* param)
{
    ntw_pool_slot* s = (ntw_pool_slot*)param;
    ntw_pool* p = (ntw_pool*)s->pool;
    ntw_u32 result = 0u;

    if (p->thread_init != 0u) {
        result = ((ntw_fn_thread_init)p->thread_init)(p->thread_init_context, s->index);
    }
    s->init_result = result;
    if (result != 0u) {
        AINC(p->init_failed);
    }
    AINC(p->init_completed);
    if (ADEC(p->outstanding) == 0u) {
        ((ntw_fn_handle)p->api.set_event)(p->done);
    }
    if (result != 0u) {
        return 0u; /* startup failed normally; init joins us and preserves the callback result */
    }

    for (;;) {
        if (((ntw_fn_wait)p->api.wait_single)(s->wake, NTW_INFINITE) != NTW_WAIT_OBJECT_0) {
            AXCHG(s->dead, 1u); /* unwaitable handle: leave; dispatch stops waking this slot */
            return 1u;
        }
        if (RD(p->stop) != 0) {
            return 0u;
        }
        s->chunks += ntw_run(p);
        s->wakes++;
        if (ADEC(p->outstanding) == 0u) {
            ((ntw_fn_handle)p->api.set_event)(p->done); /* last token: release the dispatching thread */
        }
    }
}

/* Join and release everything init created (range slots[0..created)) and zero the storage, optionally
 * retaining startup diagnostics after failed init. No storage is cleared until every worker is joined.
 * Returns 0 on success; nonzero (nothing closed for the unjoinable thread) when a join wait failed. */
static ntw_u32 ntw_teardown(ntw_pool* p, ntw_u32 preserve_init)
{
    ntw_fn_handle set_event = (ntw_fn_handle)p->api.set_event;
    ntw_fn_handle close_handle = (ntw_fn_handle)p->api.close_handle;
    ntw_fn_wait wait = (ntw_fn_wait)p->api.wait_single;
    ntw_u32 created = p->created;
    ntw_u32 bad = 0u;
    ntw_u32 i;

    AXCHG(p->stop, 1u);
    for (i = 0; i < created; ++i) {
        if (p->slots[i].thread != 0u) {
            set_event(p->slots[i].wake);
        }
    }
    for (i = 0; i < created; ++i) {
        if (p->slots[i].thread != 0u) {
            if (wait(p->slots[i].thread, NTW_INFINITE) == NTW_WAIT_OBJECT_0) {
                close_handle(p->slots[i].thread);
                p->slots[i].thread = 0u;
            } else {
                bad = 1u;
            }
        }
    }
    if (bad != 0u) {
        return 1u;
    }
    for (i = 0; i < created; ++i) {
        if (p->slots[i].wake != 0u) {
            close_handle(p->slots[i].wake);
        }
    }
    if (p->done != 0u) {
        close_handle(p->done);
    }
    if (preserve_init != 0u) {
        ntw_u32 completed = p->init_completed;
        ntw_u32 failed = p->init_failed;
        __stosd((unsigned long*)p, 0ul, offsetof(ntw_pool, slots) / 4u);
        p->init_completed = completed;
        p->init_failed = failed;
        for (i = 0; i < NTW_POOL_MAX_WORKERS; ++i) {
            __stosd((unsigned long*)&p->slots[i], 0ul, offsetof(ntw_pool_slot, init_result) / 4u);
        }
        __stosd((unsigned long*)p->pad5, 0ul, sizeof(p->pad5) / 4u);
    } else {
        __stosd((unsigned long*)p, 0ul, NTW_POOL_BYTES / 4u);
    }
    return 0u;
}

ntw_u32 __stdcall ntw_pool_init(ntw_pool* pool, const ntw_pool_config* cfg)
{
    ntw_fn_create_event create_event;
    ntw_fn_create_thread create_thread;
    ntw_u32 i;
    ntw_u32 err;

    if (pool == 0 || cfg == 0) {
        return NTW_POOL_E_ARG;
    }
    if (((ntw_u32)pool & (NTW_POOL_ALIGN - 1u)) != 0u) {
        return NTW_POOL_E_ALIGN;
    }
    if (cfg->abi != NTW_POOL_ABI || cfg->workers > NTW_POOL_MAX_WORKERS || cfg->api.create_event == 0u ||
        cfg->api.close_handle == 0u || cfg->api.set_event == 0u || cfg->api.wait_single == 0u ||
        cfg->api.create_thread == 0u || cfg->api.worker_entry == 0u) {
        return NTW_POOL_E_ARG;
    }
    if (ACAS(pool->state, NTW_POOL_S_INIT, NTW_POOL_S_UNINIT) != NTW_POOL_S_UNINIT) {
        return NTW_POOL_E_STATE;
    }
    /* The state word was claimed; a never-initialised or shut-down pool may carry statistics bumped by
     * serial fallbacks, so start every other word from zero (workers, created and stop included). */
    __stosd((unsigned long*)pool + 1, 0ul, NTW_POOL_BYTES / 4u - 1u);
    pool->abi = NTW_POOL_ABI;
    pool->stack_bytes = cfg->stack_bytes;
    pool->api.create_event = cfg->api.create_event;
    pool->api.close_handle = cfg->api.close_handle;
    pool->api.set_event = cfg->api.set_event;
    pool->api.wait_single = cfg->api.wait_single;
    pool->api.create_thread = cfg->api.create_thread;
    pool->api.worker_entry = cfg->api.worker_entry;
    pool->thread_init = cfg->thread_init;
    pool->thread_init_context = cfg->thread_init_context;
    create_event = (ntw_fn_create_event)pool->api.create_event;
    create_thread = (ntw_fn_create_thread)pool->api.create_thread;

    pool->done = create_event(0u, 0u, 0u, 0u);
    if (pool->done == 0u) {
        err = NTW_POOL_E_EVENT;
        goto fail;
    }
    AXCHG(pool->outstanding, 1u); /* startup token: workers cannot finish the barrier while we create */
    for (i = 0; i < cfg->workers; ++i) {
        ntw_pool_slot* s = &pool->slots[i];

        pool->created = i + 1u;
        s->pool = (ntw_u32)pool;
        s->index = i;
        s->wake = create_event(0u, 0u, 0u, 0u);
        if (s->wake == 0u) {
            err = NTW_POOL_E_EVENT;
            goto fail;
        }
        AINC(pool->outstanding);
        s->thread = create_thread(0u, pool->stack_bytes, pool->api.worker_entry, (ntw_u32)s,
                                  pool->stack_bytes != 0u ? NTW_STACK_SIZE_PARAM_IS_A_RESERVATION : 0u, 0u);
        if (s->thread == 0u) {
            ADEC(pool->outstanding); /* no worker exists to release this startup token */
            err = NTW_POOL_E_THREAD;
            goto fail;
        }
    }
    ADEC(pool->outstanding); /* release init's startup token */
    while (RD(pool->outstanding) != 0u) {
        if (((ntw_fn_wait)pool->api.wait_single)(pool->done, NTW_INFINITE) != NTW_WAIT_OBJECT_0) {
            err = NTW_POOL_E_JOIN;
            goto fail;
        }
    }
    if (pool->init_failed != 0u) {
        err = NTW_POOL_E_INIT;
        goto fail;
    }
    pool->workers = cfg->workers;
    AXCHG(pool->state, NTW_POOL_S_READY); /* publish */
    return NTW_POOL_OK;

fail:
    if (ntw_teardown(pool, pool->thread_init != 0u) != 0u) {
        AXCHG(pool->state, NTW_POOL_S_BROKEN);
        return NTW_POOL_E_JOIN;
    }
    return err;
}

ntw_u32 __stdcall ntw_pool_shutdown(ntw_pool* pool)
{
    ntw_u32 prev;
    ntw_u32 retry = 0u;

    if (pool == 0) {
        return NTW_POOL_E_ARG;
    }
    prev = ACAS(pool->state, NTW_POOL_S_STOPPING, NTW_POOL_S_READY);
    if (prev == NTW_POOL_S_BUSY) {
        return NTW_POOL_E_BUSY;
    }
    if (prev == NTW_POOL_S_BROKEN) { /* retry a teardown that could not join every worker */
        prev = ACAS(pool->state, NTW_POOL_S_STOPPING, NTW_POOL_S_BROKEN);
        retry = 1u;
    }
    if (prev != NTW_POOL_S_READY && !(retry != 0u && prev == NTW_POOL_S_BROKEN)) {
        return NTW_POOL_E_STATE;
    }
    if (ntw_teardown(pool, retry != 0u && pool->thread_init != 0u) != 0u) {
        AXCHG(pool->state, NTW_POOL_S_BROKEN);
        return NTW_POOL_E_JOIN;
    }
    return NTW_POOL_OK;
}

/* stdcall void dispatch(user, body, chunks, ctx): user = ntw_pool*, body = fastcall void(void* ctx, u32 chunk). */
void __stdcall ntw_pool_dispatch(ntw_u32 user, ntw_u32 body, ntw_u32 chunks, void* ctx)
{
    ntw_pool* pool = (ntw_pool*)user;
    ntw_fn_body fn = (ntw_fn_body)body;
    ntw_u32 i;
    ntw_u32 k;
    ntw_u32 woken = 0u;
    ntw_u32 csr;

    if (chunks == 0u) {
        return;
    }
    csr = (ntw_u32)_mm_getcsr();
    if (pool == 0 || chunks > NTW_POOL_MAX_CHUNKS ||
        ACAS(pool->state, NTW_POOL_S_BUSY, NTW_POOL_S_READY) != NTW_POOL_S_READY) {
        /* The team is not ours (reentrant, concurrent, not ready, oversize): still honour the contract. */
        if (pool != 0) {
            AINC(pool->st_inline);
        }
        for (i = 0; i < chunks; ++i) {
            fn(ctx, i);
        }
        _mm_setcsr(csr);
        return;
    }

    pool->st_calls++;
    k = chunks - 1u;
    if (k > pool->workers) {
        k = pool->workers;
    }
    if (k == 0u) {
        pool->st_serial++;
        for (i = 0; i < chunks; ++i) {
            fn(ctx, i);
        }
        pool->st_main_chunks += chunks;
    } else {
        pool->body = body;
        pool->ctx = (ntw_u32)ctx;
        pool->chunks = chunks;
        AXCHG(pool->next, 0u);
        AXCHG(pool->outstanding, 1u); /* dispatching thread's token */
        for (i = 0; i < pool->workers && woken < k; ++i) {
            ntw_pool_slot* s = &pool->slots[i];

            if (RD(s->dead) != 0u) {
                continue;
            }
            AINC(pool->outstanding); /* before the wake: a fast worker may release it at once */
            if (((ntw_fn_handle)pool->api.set_event)(s->wake) != 0u) {
                ++woken;
            } else {
                ADEC(pool->outstanding);
                pool->st_wake_fail++;
            }
        }
        pool->st_woken += woken;
        pool->st_team++;
        pool->st_main_chunks += ntw_run(pool);
        if (ADEC(pool->outstanding) != 0u) {
            /* Barrier.  Re-test after every wake: a late SetEvent of an earlier dispatch may leave the
             * event signalled, the counter is the truth. */
            while (RD(pool->outstanding) != 0u) {
                ((ntw_fn_wait)pool->api.wait_single)(pool->done, NTW_INFINITE);
            }
        }
    }
    _mm_setcsr(csr);
    AXCHG(pool->state, NTW_POOL_S_READY);
}

/* Exported data contract: abi, pool bytes, pool alignment, max workers, config bytes, max chunks, ready state, 0. */
const ntw_u32 ntw_pool_contract[NTW_POOL_CONTRACT_WORDS] = {
    NTW_POOL_ABI, NTW_POOL_BYTES, NTW_POOL_ALIGN, NTW_POOL_MAX_WORKERS,
    NTW_POOL_CONFIG_BYTES, NTW_POOL_MAX_CHUNKS, NTW_POOL_S_READY, 0u};
