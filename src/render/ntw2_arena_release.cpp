// Levers 4a, 4b, and 7: render pose/scene 1 MB arena release + in-battle high-water trim
// + process/provider heap resource optimization (HeapOptimizeResources).
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include "render/ntw2_arena_release.h"

namespace ntw2_arena_release {
namespace {

using U = uint32_t;
using EngineFree = void (__cdecl *)(void*);
using CtxPassFn = void (__fastcall *)(void*, void*, U);
using SceneResetFn = U (__fastcall *)(void*, void*);
using ResolveSceneFn = U (__fastcall *)(U);
using RenderRootDtorFn = void* (__fastcall *)(void*, void*, U);

// Proven Napoleon.exe (preferred base 0x400000) VAs:
constexpr U kPreferredBase             = 0x00400000u;
constexpr U kEngineFreeVa              = 0x00FF7EF0u; // cdecl free(ptr)
constexpr U kSceneSingletonPtrVa       = 0x0182EB14u; // global render device singleton; [mgr + 0x18] = scene
constexpr U kProviderVtableVa          = 0x013EDE38u; // Provider[0..3] vtable; [provider + 8] = HANDLE
constexpr U kProviderBaseVas[3]        = { 0x017639F8u, 0x01763A04u, 0x01763A10u };

// Vtable slots hooked when NTW2_ARENA_RELEASE or NTW2_HEAP_OPTIMIZE is enabled:
constexpr U kCtxPassSlotVa             = 0x01340AACu; // ctx->vtbl[1] = 0x00770450
constexpr U kCtxPassOrigVa             = 0x00770450u;
constexpr U kSceneResetSlotVa          = 0x0140ABDCu; // scene->vtbl[2] = 0x01148020 (called by 0x01157140 before rewind)
constexpr U kSceneResetOrigVa          = 0x01148020u;
constexpr U kResolveSceneVa            = 0x00611A60u; // __fastcall(root) -> scene (vtable 0x0140ABD4)
constexpr U kRenderRootDtorSlotVa      = 0x0134010Cu; // renderRoot->vtbl[2] = 0x0073E300
constexpr U kRenderRootDtorOrigVa      = 0x0073E300u;

// Arena block geometry (0x61A700 / 0x79AF00 / 0x10E9DC0):
constexpr U kArenaBlockAllocBytes      = 0x000F4248u; // 1,000,008 bytes per block
constexpr U kArenaBlockNextOffset      = 0x000F4240u; // uint32_t next pointer
constexpr U kArenaBlockUsedOffset      = 0x000F4244u; // uint32_t used byte offset

// Lever 4b high-water trim configuration:
constexpr U kTrimMarginBlocks          = 2u;          // keep high_water + 2 blocks (min 1 in battle)
constexpr U kTrimWindowFrames          = 600u;        // ~10 s at 60 FPS for per-frame arenas (A0, A3)
constexpr U kTrimWindowPingPongEvals   = 300u;        // 300 evals * 2 frames/eval = 600 frames for A1, A2

// Lever 7 watermark configuration:
constexpr U kWatermarkAvailMib         = 640u;        // trigger when ullAvailVirtual < 640 MiB
constexpr ULONGLONG kWatermarkCooldownMs = 60000ull;  // at most once per 60 s

struct ArenaSlot {
    U address;
    U original;
    U replacement;
    DWORD protection;
    bool owned;
    bool protection_dirty;
};

U g_base = 0u;
U g_delta = 0u;
U g_flags = 0u;
U g_root = 0u;
U g_main_tid = 0u;
U g_last_ctx = 0u;
U g_last_scene = 0u;
LONGLONG g_qpc_freq = 0;

volatile LONG g_active = 0;
volatile LONG g_teardown_req = 0;
volatile LONG g_teardown_done = 0;
volatile LONG g_heap_opt_teardown_done = 0;
volatile LONG g_heap_opt_lock = 0;
ULONGLONG g_last_watermark_ms = 0ull;

U g_words[NTW2_ARENA_WORDS] = {};
U g_trim_under[4] = {}; // 0: scene+0x2D8, 1: ctx+0x80, 2: ctx+0xCC, 3: ctx+0x118
U g_trim_hw[4] = {};

ArenaSlot g_slots[3] = {};

inline U V(U va) { return va + g_delta; }

bool ReadWordSafe(U address, U& out) {
    __try {
        out = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out = 0u;
        return false;
    }
}

bool RestoreSlotProtection(ArenaSlot& slot) {
    if (!slot.protection_dirty) return true;
    DWORD ignored = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(slot.address)), 4, slot.protection, &ignored))
        return false;
    slot.protection_dirty = false;
    return true;
}

bool SwapArenaSlot(ArenaSlot& slot, bool install) {
    U current = 0u;
    if (!ReadWordSafe(slot.address, current)) return false;
    const U expected = install ? slot.original : slot.replacement;
    const U replacement = install ? slot.replacement : slot.original;
    if (!install && current == slot.original) {
        slot.owned = false;
        return RestoreSlotProtection(slot);
    }
    if (current != expected) {
        if (!install) RestoreSlotProtection(slot);
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(slot.address)), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT ||
        mbi.AllocationBase != reinterpret_cast<void*>(static_cast<uintptr_t>(g_base)) ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
        return false;
    }
    if (install && mbi.Protect != PAGE_READONLY) return false;
    DWORD old_prot = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(slot.address)), 4, PAGE_READWRITE, &old_prot))
        return false;
    if (install) slot.protection = old_prot;
    slot.protection_dirty = true;
    const U prior = static_cast<U>(_InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(static_cast<uintptr_t>(slot.address)),
        static_cast<LONG>(replacement),
        static_cast<LONG>(expected)));
    if (prior == expected) slot.owned = install;
    const bool prot_ok = RestoreSlotProtection(slot);
    return prot_ok && (prior == expected);
}

U GetGlobalScene() {
    if (g_last_scene) {
        U vtbl = 0u;
        if (ReadWordSafe(g_last_scene, vtbl) && vtbl == V(0x0140ABD4u)) return g_last_scene;
    }
    return 0u;
}

U ValidateLiveCtx() {
    if (!g_root) return 0u;
    U rr = 0u;
    if (!ReadWordSafe(g_root + 0x28200u, rr) || !rr) return 0u;
    U ctx = 0u;
    if (!ReadWordSafe(rr + 0x70u, ctx) || !ctx) return 0u;
    U vtbl = 0u;
    if (!ReadWordSafe(ctx, vtbl) || vtbl != V(0x01340AA8u)) return 0u;
    return ctx;
}

U CountQuadtreeBlocks() {
    if (!g_root) return 0u;
    U rr = 0u;
    if (ReadWordSafe(g_root + 0x28200u, rr) && rr) {
        U c1 = 0u;
        if (ReadWordSafe(rr + 0x28u, c1)) return c1;
    }
    return 0u;
}

U ReadVisualWorklistCount() {
    if (!g_root) return 0u;
    U rr = 0u;
    if (!ReadWordSafe(g_root + 0x28200u, rr) || !rr) return 0u;
    U vis = 0u;
    if (!ReadWordSafe(rr + 0x6Cu, vis) || !vis) return 0u;
    U cnt = 0u;
    if (ReadWordSafe(vis + 0xF8u, cnt)) return cnt;
    return 0u;
}

U CountUsedBlocks(U arena) {
    if (!arena) return 0u;
    const U head = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena));
    const U cur  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 4u));
    const U cnt  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 8u));
    if (!head || !cur || !cnt) return 0u;
    if (cur == head && *reinterpret_cast<const U*>(static_cast<uintptr_t>(head + kArenaBlockUsedOffset)) == 0u)
        return 0u;
    U b = head;
    U used = 1u;
    const U limit = cnt + 4u;
    while (b && b != cur && used < limit) {
        b = *reinterpret_cast<const U*>(static_cast<uintptr_t>(b + kArenaBlockNextOffset));
        ++used;
    }
    return (b == cur) ? used : cnt;
}

U CountBatchedPosedMen(U ctx) {
    if (!ctx) return 0u;
    U total = 0u;
    for (U off = 0x1E8u; off <= 0x1ECu; off += 4u) {
        const U mgr = *reinterpret_cast<const U*>(static_cast<uintptr_t>(ctx + off));
        if (!mgr) continue;
        const U group_count = *reinterpret_cast<const U*>(static_cast<uintptr_t>(mgr + 0x18u));
        const U groups_ptr  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(mgr + 0x1Cu));
        if (!groups_ptr || group_count > 16384u) continue;
        for (U i = 0u; i < group_count; ++i) {
            const U grp = *reinterpret_cast<const U*>(static_cast<uintptr_t>(groups_ptr + i * 4u));
            if (grp) total += *reinterpret_cast<const U*>(static_cast<uintptr_t>(grp + 8u));
        }
    }
    return total;
}

U TrimArenaTail(U arena, U keep_blocks) {
    if (!arena || keep_blocks == 0u) return 0u;
    // Never touch an arena while a worker slot provider is attached.
    if (*reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 0x20u)) != 0u) return 0u;
    const U head = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena));
    const U cur  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 4u));
    const U cnt  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 8u));
    if (!head || cnt <= keep_blocks) return 0u;

    U b = head;
    bool cur_in_kept = (cur == 0u || cur == head);
    for (U i = 1u; i < keep_blocks && b != 0u; ++i) {
        b = *reinterpret_cast<const U*>(static_cast<uintptr_t>(b + kArenaBlockNextOffset));
        if (b == cur) cur_in_kept = true;
    }
    if (!b || !cur_in_kept) return 0u;

    U tail = *reinterpret_cast<const U*>(static_cast<uintptr_t>(b + kArenaBlockNextOffset));
    if (!tail) return 0u;
    *reinterpret_cast<U*>(static_cast<uintptr_t>(b + kArenaBlockNextOffset)) = 0u;

    const EngineFree fn_free = reinterpret_cast<EngineFree>(static_cast<uintptr_t>(V(kEngineFreeVa)));
    U freed = 0u;
    const U max_steps = (cnt - keep_blocks) + 4u;
    while (tail && freed < max_steps) {
        const U next = *reinterpret_cast<const U*>(static_cast<uintptr_t>(tail + kArenaBlockNextOffset));
        fn_free(reinterpret_cast<void*>(static_cast<uintptr_t>(tail)));
        ++freed;
        tail = next;
    }
    *reinterpret_cast<U*>(static_cast<uintptr_t>(arena + 8u)) = (cnt > freed) ? (cnt - freed) : keep_blocks;
    return freed;
}

void CheckTrimArena(U arena, U slot_idx, U used_blocks, U window_evals) {
    if (!(g_flags & NTW2_ARENA_RELEASE) || !arena || slot_idx >= 4u) return;
    const U cnt = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 8u));
    if (used_blocks + kTrimMarginBlocks < cnt) {
        if (used_blocks > g_trim_hw[slot_idx]) g_trim_hw[slot_idx] = used_blocks;
        if (++g_trim_under[slot_idx] >= window_evals) {
            U keep = g_trim_hw[slot_idx] + kTrimMarginBlocks;
            if (keep < 1u) keep = 1u;
            if (keep < used_blocks) keep = used_blocks;
            const U freed = TrimArenaTail(arena, keep);
            if (freed) {
                ++g_words[kWTrimEvents];
                g_words[kWTrimBlocksFreed] += freed;
                g_words[kWTrimBytesFreed]  += freed * kArenaBlockAllocBytes;
            }
            g_trim_under[slot_idx] = 0u;
            g_trim_hw[slot_idx] = used_blocks;
        }
    } else {
        g_trim_under[slot_idx] = 0u;
        g_trim_hw[slot_idx] = 0u;
    }
}

U FreeAllArenaBlocks(U arena) {
    if (!arena) return 0u;
    if (*reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 0x20u)) != 0u) return 0u;
    const U head = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena));
    const U cnt  = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena + 8u));
    *reinterpret_cast<U*>(static_cast<uintptr_t>(arena))      = 0u;
    *reinterpret_cast<U*>(static_cast<uintptr_t>(arena + 4u)) = 0u;
    *reinterpret_cast<U*>(static_cast<uintptr_t>(arena + 8u)) = 0u;
    if (!head) return 0u;

    const EngineFree fn_free = reinterpret_cast<EngineFree>(static_cast<uintptr_t>(V(kEngineFreeVa)));
    U freed = 0u;
    U cur = head;
    const U max_steps = cnt ? (cnt + 4u) : 512u;
    while (cur && freed < max_steps) {
        const U next = *reinterpret_cast<const U*>(static_cast<uintptr_t>(cur + kArenaBlockNextOffset));
        fn_free(reinterpret_cast<void*>(static_cast<uintptr_t>(cur)));
        ++freed;
        cur = next;
    }
    return freed;
}

void ExecuteTeardown(U scene, U ctx) {
    if (!(g_flags & NTW2_ARENA_RELEASE)) {
        _InterlockedExchange(&g_teardown_done, 1);
        return;
    }
    if (_InterlockedCompareExchange(&g_teardown_done, 1, 0) != 0) return;

    U scene_freed = 0u, pose_freed = 0u, scratch_freed = 0u;
    if (scene) {
        scene_freed = FreeAllArenaBlocks(scene + 0x2D8u);
        g_words[kWSceneBlocksCur] = 0u;
    }
    if (ctx) {
        pose_freed += FreeAllArenaBlocks(ctx + 0x80u);
        pose_freed += FreeAllArenaBlocks(ctx + 0xCCu);
        scratch_freed += FreeAllArenaBlocks(ctx + 0x118u);
        // Advance [ctx + 0xC] (visual frame counter) by +2 and clear [ctx + 0x16C] so that if any
        // extra frame runs before process close, 0x7725D0 sees [esi + 0] != [ctx + 0xC] - 1 on every
        // soldier and zeroes [esi + 0x18] and [esi + 0x14] at 0x772620 before any dereference.
        *reinterpret_cast<U*>(static_cast<uintptr_t>(ctx + 0x0Cu)) += 2u;
        *reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(ctx + 0x16Cu)) = 0u;
        g_words[kWPose0BlocksCur] = 0u;
        g_words[kWPose1BlocksCur] = 0u;
        g_words[kWScratchBlocksCur] = 0u;
    }
    const U total_freed = scene_freed + pose_freed + scratch_freed;
    ++g_words[kWTeardownReleases];
    g_words[kWTeardownSceneBlocks]   += scene_freed;
    g_words[kWTeardownPoseBlocks]    += pose_freed;
    g_words[kWTeardownScratchBlocks] += scratch_freed;
    g_words[kWTeardownBlocksFreed]   += total_freed;
    g_words[kWTeardownBytesFreed]    += total_freed * kArenaBlockAllocBytes;
}

void RunHeapOptimize(bool is_watermark) {
    if (!(g_flags & NTW2_HEAP_OPTIMIZE)) return;
    if (_InterlockedCompareExchange(&g_heap_opt_lock, 1, 0) != 0) return;

    struct HeapOptimizeInfo {
        DWORD version;
        DWORD flags;
    };

    MEMORYSTATUSEX mem_before = {};
    mem_before.dwLength = sizeof(mem_before);
    const BOOL have_before = GlobalMemoryStatusEx(&mem_before);

    LARGE_INTEGER t0 = {}, t1 = {};
    QueryPerformanceCounter(&t0);

    U heaps_ok = 0u;
    const HEAP_INFORMATION_CLASS opt_class = static_cast<HEAP_INFORMATION_CLASS>(3); // HeapOptimizeResources
    HeapOptimizeInfo info = { 1u, 0u };

    const HANDLE proc_heap = GetProcessHeap();
    if (proc_heap && HeapSetInformation(proc_heap, opt_class, &info, sizeof(info)))
        ++heaps_ok;

    if (g_base) {
        for (U i = 0u; i < 3u; ++i) {
            const U prov = V(kProviderBaseVas[i]);
            U vtbl = 0u, h_val = 0u;
            if (ReadWordSafe(prov, vtbl) && vtbl == V(kProviderVtableVa) &&
                ReadWordSafe(prov + 8u, h_val) && h_val != 0u) {
                const HANDLE h = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(h_val));
                if (h != proc_heap) {
                    HeapOptimizeInfo pinfo = { 1u, 0u };
                    if (HeapSetInformation(h, opt_class, &pinfo, sizeof(pinfo)))
                        ++heaps_ok;
                }
            }
        }
    }

    QueryPerformanceCounter(&t1);
    MEMORYSTATUSEX mem_after = {};
    mem_after.dwLength = sizeof(mem_after);
    const BOOL have_after = GlobalMemoryStatusEx(&mem_after);

    const U us = (g_qpc_freq > 0 && t1.QuadPart > t0.QuadPart)
        ? static_cast<U>(((t1.QuadPart - t0.QuadPart) * 1000000ll) / g_qpc_freq)
        : 0u;

    ++g_words[kWHeapOptCalls];
    if (is_watermark) ++g_words[kWHeapOptWatermarkCalls];
    g_words[kWHeapOptHeapsOk] += heaps_ok;
    g_words[kWHeapOptTotalUs] += us;

    if (have_before && have_after) {
        g_words[kWHeapOptAvailBeforeMb] = static_cast<U>(mem_before.ullAvailVirtual >> 20);
        g_words[kWHeapOptAvailAfterMb]  = static_cast<U>(mem_after.ullAvailVirtual >> 20);
        if (mem_after.ullAvailVirtual > mem_before.ullAvailVirtual) {
            const U delta_kb = static_cast<U>((mem_after.ullAvailVirtual - mem_before.ullAvailVirtual) >> 10);
            g_words[kWHeapOptReclaimedKb] += delta_kb;
        }
    }

    _InterlockedExchange(&g_heap_opt_lock, 0);
}

void __fastcall CtxPassGate(void* ctx_ptr, void* edx, U arg) {
    const U ctx = static_cast<U>(reinterpret_cast<uintptr_t>(ctx_ptr));
    if (ctx) {
        g_last_ctx = ctx;
        const U owner = *reinterpret_cast<const U*>(static_cast<uintptr_t>(ctx + 4u));
        if (owner) {
            const ResolveSceneFn resolve_scene = reinterpret_cast<ResolveSceneFn>(static_cast<uintptr_t>(V(kResolveSceneVa)));
            const U sc = resolve_scene(owner);
            if (sc) g_last_scene = sc;
        }
    }

    const CtxPassFn orig = reinterpret_cast<CtxPassFn>(static_cast<uintptr_t>(V(kCtxPassOrigVa)));
    orig(ctx_ptr, edx, arg);

    if (_InterlockedCompareExchange(&g_teardown_req, 0, 0) != 0) {
        ExecuteTeardown(GetGlobalScene(), ctx ? ctx : ValidateLiveCtx());
        _InterlockedExchange(&g_teardown_req, 0);
        return;
    }

    if (!ctx || _InterlockedCompareExchange(&g_active, 0, 0) == 0) return;

    const U posed_men = CountBatchedPosedMen(ctx);
    const U vis_men = ReadVisualWorklistCount();
    ++g_words[kWFramesObserved];
    if (posed_men > 0u || g_words[kWPosedMenLast] == 0u) g_words[kWPosedMenLast] = posed_men;
    if (posed_men > g_words[kWPosedMenPeak]) g_words[kWPosedMenPeak] = posed_men;
    if (vis_men > 0u || g_words[kWWorklistMenLast] == 0u) g_words[kWWorklistMenLast] = vis_men;

    // At exit of 0x770450, [ctx + 0x168] holds the ping-pong index (0 or 1) that was just used in this frame.
    const U slot_used = *reinterpret_cast<const U*>(static_cast<uintptr_t>(ctx + 0x168u)) & 1u;
    const U arena_p0  = ctx + 0x80u;
    const U arena_p1  = ctx + 0xCCu;
    const U arena_used = ctx + 0x80u + slot_used * 0x4Cu;
    const U pose_used = CountUsedBlocks(arena_used);

    CheckTrimArena(arena_used, 1u + slot_used, pose_used, kTrimWindowPingPongEvals);

    const U cnt0 = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena_p0 + 8u));
    const U cnt1 = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena_p1 + 8u));
    g_words[kWPose0BlocksCur] = cnt0;
    g_words[kWPose1BlocksCur] = cnt1;
    g_words[kWPoseBlocksUsed] = pose_used;
    if (cnt0 + cnt1 > g_words[kWPoseBlocksPeak]) g_words[kWPoseBlocksPeak] = cnt0 + cnt1;

    const U arena_scr = ctx + 0x118u;
    const U scr_used  = CountUsedBlocks(arena_scr);
    CheckTrimArena(arena_scr, 3u, scr_used, kTrimWindowFrames);

    const U cnt_scr = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena_scr + 8u));
    g_words[kWScratchBlocksCur]  = cnt_scr;
    g_words[kWScratchBlocksUsed] = scr_used;
    if (cnt_scr > g_words[kWScratchBlocksPeak]) g_words[kWScratchBlocksPeak] = cnt_scr;

    const U sc = GetGlobalScene();
    if (sc) {
        const U arena_sc = sc + 0x2D8u;
        const U cnt_sc = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena_sc + 8u));
        g_words[kWSceneBlocksCur] = cnt_sc;
        if (cnt_sc > g_words[kWSceneBlocksPeak]) g_words[kWSceneBlocksPeak] = cnt_sc;
    }

    g_words[kWQuadtreeBlocksCur] = CountQuadtreeBlocks();
}

U __fastcall SceneResetGate(void* scene_ptr, void* edx) {
    (void)edx;
    const U scene = static_cast<U>(reinterpret_cast<uintptr_t>(scene_ptr));
    if (scene) g_last_scene = scene;
    const U arena_scene = scene ? (scene + 0x2D8u) : 0u;

    if (_InterlockedCompareExchange(&g_teardown_req, 0, 0) != 0) {
        ExecuteTeardown(scene, ValidateLiveCtx());
        _InterlockedExchange(&g_teardown_req, 0);
        return arena_scene;
    }

    if (arena_scene && _InterlockedCompareExchange(&g_active, 0, 0) != 0) {
        const U sc_used = CountUsedBlocks(arena_scene);
        CheckTrimArena(arena_scene, 0u, sc_used, kTrimWindowFrames);
        const U cnt_sc = *reinterpret_cast<const U*>(static_cast<uintptr_t>(arena_scene + 8u));
        g_words[kWSceneBlocksCur]  = cnt_sc;
        g_words[kWSceneBlocksUsed] = sc_used;
        if (cnt_sc > g_words[kWSceneBlocksPeak]) g_words[kWSceneBlocksPeak] = cnt_sc;
    }

    return arena_scene;
}

void* __fastcall RenderRootDtorGate(void* render_root, void* edx, U flags) {
    const U rr = static_cast<U>(reinterpret_cast<uintptr_t>(render_root));
    const U ctx = rr ? *reinterpret_cast<const U*>(static_cast<uintptr_t>(rr + 0x70u)) : 0u;
    ExecuteTeardown(GetGlobalScene(), ctx);

    const RenderRootDtorFn orig = reinterpret_cast<RenderRootDtorFn>(static_cast<uintptr_t>(V(kRenderRootDtorOrigVa)));
    void* const ret = orig(render_root, edx, flags);

    if ((g_flags & NTW2_HEAP_OPTIMIZE) && _InterlockedCompareExchange(&g_heap_opt_teardown_done, 1, 0) == 0) {
        RunHeapOptimize(false);
    }
    return ret;
}

} // namespace

bool Start(uint32_t image_base, uint32_t va_watch_flags, uint32_t root, uint32_t main_thread_id) {
    g_base = image_base;
    g_delta = image_base - kPreferredBase;
    g_flags = va_watch_flags & (NTW2_ARENA_RELEASE | NTW2_HEAP_OPTIMIZE);
    g_root = root;
    g_main_tid = main_thread_id;
    g_last_ctx = 0u;
    g_last_scene = 0u;

    LARGE_INTEGER freq = {};
    if (QueryPerformanceFrequency(&freq)) g_qpc_freq = freq.QuadPart;

    memset(g_words, 0, sizeof(g_words));
    memset(g_trim_under, 0, sizeof(g_trim_under));
    memset(g_trim_hw, 0, sizeof(g_trim_hw));

    _InterlockedExchange(&g_teardown_req, 0);
    _InterlockedExchange(&g_teardown_done, 0);
    _InterlockedExchange(&g_heap_opt_teardown_done, 0);
    _InterlockedExchange(&g_heap_opt_lock, 0);
    g_last_watermark_ms = 0ull;

    if (!g_flags) {
        _InterlockedExchange(&g_active, 0);
        return true;
    }

    g_words[kWFlagsActive] = g_flags;

    // Slots kept installed by Stop(KeepHooks) keep their recorded protection; only fresh slots are initialised and swapped.
    const ArenaSlot fresh[3] = {
        { V(kCtxPassSlotVa),        V(kCtxPassOrigVa),        static_cast<U>(reinterpret_cast<uintptr_t>(&CtxPassGate)),        0, false, false },
        { V(kSceneResetSlotVa),     V(kSceneResetOrigVa),     static_cast<U>(reinterpret_cast<uintptr_t>(&SceneResetGate)),     0, false, false },
        { V(kRenderRootDtorSlotVa), V(kRenderRootDtorOrigVa), static_cast<U>(reinterpret_cast<uintptr_t>(&RenderRootDtorGate)), 0, false, false },
    };
    for (U i = 0u; i < 3u; ++i)
        if (!g_slots[i].owned) g_slots[i] = fresh[i];

    for (U i = 0u; i < 3u; ++i) {
        if (g_slots[i].owned) continue;
        if (!SwapArenaSlot(g_slots[i], true)) {
            for (U j = i; j > 0u; --j) SwapArenaSlot(g_slots[j - 1u], false);
            _InterlockedExchange(&g_active, 0);
            return false;
        }
    }

    _InterlockedExchange(&g_active, 1);
    return true;
}

bool HooksInstalled() {
    for (U i = 0u; i < 3u; ++i)
        if (g_slots[i].owned || g_slots[i].protection_dirty) return true;
    return false;
}

void Stop(StopMode mode) {
    _InterlockedExchange(&g_active, 0);
    if (!g_flags) return;
    if (mode == StopMode::KeepHooks) return;

    if (mode == StopMode::Release && (g_flags & NTW2_ARENA_RELEASE) && _InterlockedCompareExchange(&g_teardown_done, 0, 0) == 0) {
        const U scene = GetGlobalScene();
        if (scene) {
            if (g_main_tid != 0u && GetCurrentThreadId() == g_main_tid) {
                ExecuteTeardown(scene, ValidateLiveCtx());
            } else {
                _InterlockedExchange(&g_teardown_req, 1);
                const ULONGLONG deadline = GetTickCount64() + 500ull;
                while (_InterlockedCompareExchange(&g_teardown_done, 0, 0) == 0 && GetTickCount64() < deadline) {
                    Sleep(1);
                }
                _InterlockedExchange(&g_teardown_req, 0);
            }
        }
    }

    for (U i = 3u; i > 0u; --i) {
        ArenaSlot& s = g_slots[i - 1u];
        if (s.owned || s.protection_dirty) SwapArenaSlot(s, false);
    }

    if ((g_flags & NTW2_HEAP_OPTIMIZE) && _InterlockedCompareExchange(&g_heap_opt_teardown_done, 1, 0) == 0) {
        RunHeapOptimize(false);
    }
}

void Sample(uint32_t* out_words) {
    if (!out_words) return;
    if (!g_flags) {
        for (U i = 0u; i < NTW2_ARENA_WORDS; ++i) out_words[i] = 0u;
        return;
    }
    for (U i = 0u; i < NTW2_ARENA_WORDS; ++i) out_words[i] = g_words[i];
}

void OnVaWatch(uint32_t avail_mib) {
    if (!(g_flags & NTW2_HEAP_OPTIMIZE)) return;
    if (avail_mib >= kWatermarkAvailMib) return;
    const ULONGLONG now = GetTickCount64();
    if (g_last_watermark_ms != 0ull && (now - g_last_watermark_ms) < kWatermarkCooldownMs) return;
    g_last_watermark_ms = now;
    RunHeapOptimize(true);
}

} // namespace ntw2_arena_release
