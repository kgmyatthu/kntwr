/* Import-free, CRT-free, position-independent x86 helpers for the pinned NTW ballistics prefix stage.
 *
 * The numeric work is NOT re-implemented here: workers execute a clone of the original machine code
 * 0x6F54E0..0x6F5935 (built by native_ballistics_payload.py) on contiguous shadow copies of the
 * projectiles.  This file only snapshots, schedules, validates and commits.  No heap, no globals, no
 * absolute addresses (the code section is copied verbatim into the game process).
 *
 * Build (x86 MSVC; see native_ballistics_payload.py --help for the exact commands):
 *   cl /nologo /c /TC /O2 /GS- /Gy /Zl /W4 native_ballistics_helpers.c
 *   link /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X86 /OPT:REF /FIXED:NO ...
 */
#include <intrin.h>
#include <xmmintrin.h>
#include "native_ballistics_abi.h"

#pragma intrinsic(__movsd)

#define F32(p, o) (*(bal_u32*)((bal_u8*)(p) + (o)))
#define F8(p, o) (*((bal_u8*)(p) + (o)))

/* ABI words consumed by the payload builder: abi, record, job, shadow bytes; continuation, per-item,
 * manager and call-site addresses (preferred-base VAs) these helpers were written against. */
const bal_u32 bal_contract[BAL_CONTRACT_WORDS] = {
    BAL_ABI_VERSION, BAL_RECORD_BYTES, BAL_JOB_BYTES, BAL_SHADOW_BYTES,
    0x006F5936u, 0x006F54E0u, 0x006F6BC0u, 0x0057DFF5u};

/* Continuation into the ORIGINAL 0x6F5936 with the exact frame and register state the original prefix
 * leaves there (proved by liveness analysis of the tail, see native-ballistics-recovery.json):
 *   EBP frame, ESP 16-aligned minus 0xE4 minus three saved registers (EBX, ESI, EDI),
 *   EDI=item, EBX=&item[0x64], ECX=item->definition, EDX=&item[0x7C], XMM6=1.0f,
 *   [ESP+0x24]=0x18 (hit-effect default), [ESP+0x28]=item.
 * The original epilogue returns to the caller of this function with ebx/esi/edi/ebp restored. */
__declspec(naked) void __fastcall bal_tail_enter(void* item, bal_job* job)
{
    __asm {
        push ebp
        mov ebp, esp
        and esp, 0FFFFFFF0h
        sub esp, 0E4h
        push ebx
        push esi
        push edi
        mov edi, ecx
        mov eax, dword ptr [edx + 1Ch]
        mov ebx, dword ptr [edx + 20h]
        movss xmm6, dword ptr [ebx]
        lea ebx, [edi + 64h]
        lea edx, [edi + 7Ch]
        mov dword ptr [esp + 24h], 18h
        mov dword ptr [esp + 28h], edi
        mov ecx, dword ptr [edi + 8]
        jmp eax
    }
}

/* Parallel body: ECX=job, EDX=chunk index.  While the stage runs the battle thread is blocked and nobody
 * writes projectiles or definitions, so each worker snapshots ITS OWN items, then runs the cloned original
 * prefix on the private shadow.  Writes only the records of its own chunk; reads only the projectiles of its
 * chunk, their definitions and the .rdata constants the original prefix reads.  Never writes the job. */
void __fastcall bal_worker(bal_job* job, bal_u32 chunk)
{
    bal_u32 begin = chunk * job->chunk_items;
    bal_u32 end = begin + job->chunk_items;
    bal_u32 saved = (bal_u32)_mm_getcsr();
    const bal_u32* items = (const bal_u32*)job->items;
    bal_record* r;

    if (end > job->count) {
        end = job->count;
    }
    _mm_setcsr(job->mxcsr);
    r = job->records + begin;
    for (; begin < end; ++begin, ++r) {
        bal_u8* it = (bal_u8*)items[begin];
        bal_u32 def = F32(it, 8);

        r->item = (bal_u32)it;
        if (F8(it, 0x41) != 0 || def == 0) {
            r->status = BAL_ST_SKIP;
            continue;
        }
        r->def_e4 = F8(def, 0xE4);
        r->def_60 = F32(def, 0x60);
        r->def_91 = F8(def, 0x91);
        r->in_pos[0] = F32(it, 0x64);
        r->in_pos[1] = F32(it, 0x68);
        r->in_pos[2] = F32(it, 0x6C);
        r->in_vel[0] = F32(it, 0x70);
        r->in_vel[1] = F32(it, 0x74);
        r->in_vel[2] = F32(it, 0x78);
        r->in_40 = F8(it, 0x40);
        r->in_49 = F8(it, 0x49);
        r->in_8c = F32(it, 0x8C);
        r->in_90 = F32(it, 0x90);
        r->in_94 = F32(it, 0x94);
        __movsd((unsigned long*)r->shadow, (unsigned long*)it, BAL_SHADOW_BYTES / 4);
        r->status = ((bal_u32(__fastcall*)(void*))job->prefix_entry)(r->shadow) ? BAL_ST_READY : BAL_ST_BADPREFIX;
    }
    _mm_setcsr(saved);
}

/* Serial, O(1) apart from the dispatch.  ECX=manager (model+0xE4), EDX=job.  Called after the dead-item
 * swap-removal and before the per-item loop of 0x6F6BC0.  Returns only after every chunk has finished. */
void __fastcall bal_stage(void* mgr, bal_job* job)
{
    bal_u32 n, chunks, c;

    job->st_stages++;
    job->cursor = 0;
    job->count = 0;
    if (job->flags & BAL_FLAG_DISABLE) {
        return;
    }
    n = F32(mgr, 0x10);
    if (n == 0) {
        return;
    }
    if (n > job->capacity) {
        job->st_overflow++;
        return;
    }
    if (job->chunk_items == 0) {
        job->chunk_items = 64;
    }
    job->items = F32(mgr, 0x14);
    job->mxcsr = (bal_u32)_mm_getcsr();
    job->count = n;
    job->st_items += n;
    chunks = (n + job->chunk_items - 1) / job->chunk_items;
    job->st_chunks += chunks;
    if (job->dispatch != 0 && n >= job->min_parallel && chunks > 1) {
        job->st_dispatched++;
        ((void(__stdcall*)(bal_u32, bal_u32, bal_u32, bal_job*))job->dispatch)(
            job->dispatch_user, job->worker_entry, chunks, job);
    } else {
        for (c = 0; c < chunks; ++c) {
            bal_worker(job, c);
        }
    }
}

/* The snapshot is valid iff everything the original prefix reads still has the value the worker saw:
 * the item's own inputs, and the three definition fields.  Constants live in .rdata. */
static int bal_validate(const bal_record* r, const bal_u8* it)
{
    const bal_u8* sh = r->shadow;
    bal_u32 def = F32(sh, 8);

    if (F32(it, 8) != def || F8(it, 0x41) != sh[0x41]) return 0;
    if (F32(it, 0x4C) != F32(sh, 0x4C) || F32(it, 0x50) != F32(sh, 0x50) || F32(it, 0x54) != F32(sh, 0x54)) return 0;
    if (F32(it, 0x88) != F32(sh, 0x88)) return 0;
    if (F32(it, 0x98) != F32(sh, 0x98) || F32(it, 0x9C) != F32(sh, 0x9C) || F32(it, 0xA0) != F32(sh, 0xA0)) return 0;
    if (F32(it, 0x64) != r->in_pos[0] || F32(it, 0x68) != r->in_pos[1] || F32(it, 0x6C) != r->in_pos[2]) return 0;
    if (F32(it, 0x70) != r->in_vel[0] || F32(it, 0x74) != r->in_vel[1] || F32(it, 0x78) != r->in_vel[2]) return 0;
    if (F8(it, 0x40) != (bal_u8)r->in_40 || F8(it, 0x49) != (bal_u8)r->in_49) return 0;
    if (F32(it, 0x8C) != r->in_8c || F32(it, 0x90) != r->in_90 || F32(it, 0x94) != r->in_94) return 0;
    if (F8(def, 0xE4) != (bal_u8)r->def_e4 || F32(def, 0x60) != r->def_60 || F8(def, 0x91) != (bal_u8)r->def_91) return 0;
    return 1;
}

/* Exactly the item bytes the original prefix writes: +0x40, +0x49, +0x58..+0x87, +0x8C, +0x90, +0x94. */
static void bal_commit(const bal_u8* src, bal_u8* it)
{
    __movsd((unsigned long*)(it + 0x58), (unsigned long*)(src + 0x58), 12);
    F8(it, 0x40) = src[0x40];
    F8(it, 0x49) = src[0x49];
    F32(it, 0x8C) = F32(src, 0x8C);
    F32(it, 0x90) = F32(src, 0x90);
    F32(it, 0x94) = F32(src, 0x94);
}

static int bal_same_outputs(const bal_u8* a, const bal_u8* b)
{
    bal_u32 i;
    for (i = 0x58; i < 0x88; i += 4) {
        if (F32(a, i) != F32(b, i)) return 0;
    }
    return F8(a, 0x40) == F8(b, 0x40) && F8(a, 0x49) == F8(b, 0x49) && F32(a, 0x8C) == F32(b, 0x8C) &&
           F32(a, 0x90) == F32(b, 0x90) && F32(a, 0x94) == F32(b, 0x94);
}

/* Serial, original order.  ECX=item, EDX=job; replaces `call 0x6F54E0` in the manager clone.
 * Preserves EBX/ESI/EDI/EBP (compiler ABI).  Either commits the worker prefix and enters the original
 * tail (collision query, RNG, hit effects, terrain, trail: untouched original code in original order) or
 * runs the complete original per-item function. */
void __fastcall bal_step(void* item, bal_job* job)
{
    bal_u8* it = (bal_u8*)item;
    bal_u32 c = job->cursor;
    bal_record* r = 0;

    if (c < job->count && job->records[c].item == (bal_u32)it) {
        r = job->records + c;
        job->cursor = c + 1;
    } else {
        job->st_unmatched++;
    }
    if (r != 0 && r->status == BAL_ST_SKIP) {
        job->st_skip++;
    }
    if (r != 0 && r->status == BAL_ST_READY) {
        job->st_prefixed++;
        if (bal_validate(r, it)) {
            const bal_u8* src = r->shadow;
            bal_u32 scratch[BAL_SHADOW_BYTES / 4];

            if (job->flags & BAL_FLAG_VERIFY) {
                __movsd((unsigned long*)scratch, (unsigned long*)it, BAL_SHADOW_BYTES / 4);
                if (((bal_u32(__fastcall*)(void*))job->prefix_entry)(scratch) == 0 ||
                    !bal_same_outputs((const bal_u8*)scratch, src)) {
                    job->st_verify_bad++;
                    src = (const bal_u8*)scratch;
                }
            }
            bal_commit(src, it);
            job->st_committed++;
            bal_tail_enter(it, job);
            return;
        }
        job->st_rejected++;
    }
    ((void(__fastcall*)(void*))job->orig_item)(it);
}
