// Naval render-pose groups 3 and 4 of 0x1200A30, run as prepare / parallel-compute / ordered-publish.
//
// Constructor 0x11D5F00 names this module "Naval". It was absent from the captured land-battle renderer;
// offline parity/timing does not establish infantry-animation coverage (native-render-constructor-correction.json).
//
// Recovered from F:/.../Napoleon.exe (SHA256 13fcab62...2cbad4, preferred base 0x400000):
//   0x1200A30  render-route driver, six serial input loops (zero-based 0..5).  THIS MODULE REPLACES ONLY
//                group 3: count [R+0x8C], data [R+0x90], stride 0x90 -> 0x11FF470   (call site 0x1200B09)
//                group 4: count [R+0x9C], data [R+0xA0], stride 0x60 -> 0x11FF750   (call site 0x1200B53)
//              Loops 0,1,2 (0x11FF870 / 0x11FF6D0 / 0x11FF600) run BEFORE and loop 5 (0x11FF940) AFTER; they stay
//              original and ordered (the adapter is called where loops 3 and 4 were).
//   0x11FF470  thiscall(R; idx, P*, M*, time, p5*) ret 0x14      group 3 builder
//   0x11FF750  thiscall(R; idx, P*, v3*, time, p5*) ret 0x14, al=published   group 4 builder
//   0x10DF440  thiscall(clip; maxBones=0, time, mode=2, arena) ret 0x10   locate + alloc L + blend   (pose kernel)
//   0x10DEAC0  thiscall(L; pmax*, P*, arena) ret 0xC          local pose -> world matrices (this module)
//   0x10CAD70  thiscall(out3x4; quat*, pos*) ret 8            quaternion+translation -> 3x4 (this module)
//   0x10CD420 / 0x10D0930  matrix-object constructor / 0x24-byte accessor constructor (this module)
//   0x10F4860  thiscall(M; vec4*) ret 4                       group 4 accessor broadcast (this module)
//   0x1221480  thiscall(vec; rec*) ret 4                      UNSYNCHRONISED 12-byte record append (heap growth)
//   0x10E9DC0  thiscall(arena; size, align) ret 8             arena allocator (thread/slot dependent!)
// Evidence: native-animation-render-batch-*.asm, native-animation-render-batch-recovery.json,
//           native-animation-render-batch-emu-check.json (Unicorn execution of the original machine code).
//
// Execution model (per window of <= workspace capacity entries, original group/entry order throughout)
//   1. PREPARE (owning render thread only, serial): for every entry replay exactly the original's side-effecting
//      calls in the original order: holder->vtbl[+0x3C] (clip), [group 4 duration guard], [R+0x50]->vtbl[+8]
//      (arena), locate, arena allocations for L (0x14B object, pos n*12, quat n*16), [R+0x50]->vtbl[+8] again,
//      arena allocations for the output (0x10B object, n*0x30 matrices align 4, n*0x24 accessors align 2).
//      Allocation sizes, alignments and order are those of 0x10DF440/0x10CE290/0x10DEAC0/0x10CD420.
//      Inputs that the numerical kernel reads from the render group arrays (P, M, v3) are SNAPSHOT into the job.
//   2. COMPUTE (parallel through the persistent dispatcher, or inline when small): blend (pose kernel), group 3
//      position transform, world matrices, accessor initialisation, group 4 accessor broadcast.  No allocation,
//      no append, no game TLS, no locks.  Each job writes only its own arena blocks.  Workers install the owning
//      thread's MXCSR and x87 control word and restore their own.
//   3. PUBLISH (owning thread, serial, after the barrier): 0x1221480 per entry in original group + entry order.
//
// Anything the port cannot reproduce byte-for-byte (null clip/arena getter result, locate precondition failure,
// zero frame count) is NOT approximated: that entry is executed by the ORIGINAL 0x11FF470/0x11FF750 at its
// ordered publish position (its arena allocations then happen after the window's other entries; only arena
// addresses, never values or record order, differ).  See "Immutability" below.
//
// Rounding-mode guard: the pose kernel's frame locate emulates x87 `fist` with SSE rounding (valid when both the x87
// control word and MXCSR round to nearest).  If the owning thread's MXCSR RC bits (0x6000) or x87 RC bits (0x0C00)
// are not zero, run() executes the whole selection through the ORIGINAL builders in order (Stats::serial_original).
//
// Immutability evidence (what is and is not proven)
//   * PROVEN (from the code): between prepare and publish the owning thread is blocked inside the dispatcher or
//     running the compute itself, so it cannot mutate anything the workers read.  Workers write only to arena
//     blocks that prepare allocated for that job and that nothing references before publish.
//   * NOT PROVEN: cross-thread clip/frame/skeleton immutability, absence of concurrent arena reset,
//     getter purity (fallback entries call getters again), and arena thread/slot dependence.
//     Allocations remain on the owning thread, but reading the original resources does not by itself
//     prove a safe worker lifetime or a shorter exposure window.
#pragma once
#include <cstddef>
#include <cstdint>
#include "native_animation_pose_kernel.h"

#ifndef _M_IX86
#error The render batch reproduces x86 SSE/x87 behaviour and calls x86 native code; build as x86.
#endif

namespace ntw_render {

// ---- native entry points, bound once at setup (preferred VA + image delta; version bound) ----------------
typedef void*(__fastcall* GetterFn)(void* object);                                   // vtable slot, thiscall, no args
typedef void*(__fastcall* ArenaAllocFn)(void* arena, void* edx, uint32_t size, uint32_t align);  // 0x10E9DC0, ret 8
typedef void(__fastcall* AppendFn)(void* vec, void* edx, const void* record);        // 0x1221480, ret 4
typedef uint32_t(__fastcall* OrigBuilderFn)(void* render, void* edx, int32_t idx, const float* p,
                                            const float* m_or_v3, float time, const uint8_t* p5);  // 0x11FF470/0x11FF750, ret 0x14
typedef uint8_t(__cdecl* Sse2FlagFn)();                                              // 0x10D5510, al
typedef void(__stdcall* DispatchFn)(void* user, void* body, uint32_t chunks, void* ctx);  // ntw_pool_dispatch

struct Binding {
    ArenaAllocFn arena_alloc;       // 0x10E9DC0 + delta                       (required)
    AppendFn append;                // 0x1221480 + delta                       (required)
    OrigBuilderFn orig_group3;      // 0x11FF470 + delta                       (required)
    OrigBuilderFn orig_group4;      // 0x11FF750 + delta                       (required)
    Sse2FlagFn sse2_decode_flag;    // 0x10D5510 + delta (lazy-inits 0x176CBF4) (required)
    ntw_anim::AcosFn acos_fn;       // cdecl thunk to 0x128448C                  (required)
    uint32_t accessor_vtable;       // 0x1402998 + delta, stored at accessor+0   (required)
    DispatchFn dispatch;            // ntw_pool_dispatch, or null for inline compute
    void* dispatch_user;            // ntw_pool*
    uint32_t min_parallel_bones;    // dispatch only when a window has at least this many native bones (0 -> 384)
    uint32_t chunk_bones;           // target bones per chunk (0 -> 192)
};

// ---- workspace (caller owned; nothing is allocated here) -----------------------------------------------------
struct EntryJob;
struct Workspace {
    EntryJob* jobs;          // capacity entries
    uint32_t* chunk_begin;   // capacity + 2 entries
    uint32_t capacity;
};
size_t job_bytes();                                             // sizeof(EntryJob)
size_t workspace_bytes(uint32_t capacity);                      // bytes to give workspace_init (16-byte aligned block)
bool workspace_init(Workspace& ws, void* memory, size_t bytes); // false if too small / misaligned / capacity 0

struct Stats {
    uint32_t entries;     // entries seen (both groups)
    uint32_t native;      // entries computed and published by the port
    uint32_t fallback;    // entries executed by the original builder
    uint32_t skipped;     // group 4 entries rejected by the duration guard (original publishes nothing too)
    uint32_t published;   // records appended through 0x1221480 by the port
    uint32_t windows;
    uint32_t dispatches;
    uint32_t chunks;
    uint32_t bones;       // native bones computed
    uint32_t serial_original;  // entries executed by the original builders because the FP rounding state is not round-to-nearest
};

// Group selection for run().
enum : uint32_t { kGroup3 = 1, kGroup4 = 2 };

// Runs the selected groups of render object R (the `this` of 0x1200A30) in original order: all of group 3, then all
// of group 4.  The selected groups of one window share a single dispatch.  Returns false (and does nothing) only
// for an invalid binding/workspace/mask.  Safe to call with zero counts.  Owning render thread only.  `stats` (optional)
// is ACCUMULATED into, never reset.  Must not be called from a dispatcher body or while another dispatch is in flight on
// the same pool (the dispatcher then runs the chunks inline, which stays correct but not parallel).
bool run(const Binding& binding, const Workspace& ws, void* render, uint32_t group_mask, Stats* stats);

}  // namespace ntw_render
