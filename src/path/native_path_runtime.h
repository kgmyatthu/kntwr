// Native path runtime ABI for the pinned Napoleon.exe (SHA-256 13fcab62...cbad4, preferred base 0x400000), x86 only.
//
// WHAT IT ROUTES (the ORIGINAL request chain, nothing else):
//   battle tick 0x57DF40:  0x57DFEA  mov ecx,[esi+0xB4] ; call 0x81A2C0            pf = [model+0xB4] (alloc 0x71C, ctor 0x7E6920)
//   scheduler   0x81A2C0   (fastcall ecx = pf, no stack args)  queue head [pf+0x130], next [req+0x24], state [req+0x14]
//     0x81A361  push req ; mov ecx,esi ; call 0x80F5E0                            direct call, ret 4, one site only
//   stepper     0x80F5E0   type-0 (state 0) body 0x80FF1B..0x8102B1
//     0x8101F5  lea ecx,[edi+0x1BC] ; call 0x8026F0                               G = pf+0x1BC, thiscall, 5 stack args, ret 0x14
//   original 0x8026F0 -> 0x802A80 -> 0x7E04D0 -> successor 0x800210 (callback) ...
//
// ROUTING (all through PRIVATE CLONES emitted by the clone generator; nothing in the live image is patched):
//   tick clone         call at 0x57DFEA   -> npr_scheduler_hook         (fastcall, ecx = pf)
//   0x81A2C0 clone     call at 0x81A361   -> 0x80F5E0 CLONE             (so the next clone below is the one that runs)
//   0x80F5E0 clone     call at 0x8101F5   -> npr_solve                  (thiscall-equivalent, see below)
//   npr_scheduler_hook calls config.scheduler (entry of the 0x81A2C0 clone; 0 -> the ORIGINAL 0x81A2C0, which never reaches
//   npr_solve, i.e. no cached solve is consumed) between npr_prepass and npr_end. The prepass/end entries are also
//   exported separately; the production host uses the scheduler hook to own the complete bracket.
//
// EXPORTS (undecorated names; the .cpp carries /EXPORT pragmas for the decorated symbols)
//   uint32_t __stdcall  npr_initialize(void* config)           returns 0 or NPR_E_*; reads npr_config (64 bytes)
//   uint32_t __stdcall  npr_stop(void* unused)                 returns 0 or NPR_E_*
//   void     __fastcall npr_scheduler_hook(void* pf)           prepass -> scheduler (clone or original) -> end; any exception from
//                                                              the scheduler propagates after npr_end ran (try/finally)
//   void     __fastcall npr_prepass(void* pf)                  owner only; read-only planning for queued requests (see below)
//   void     __fastcall npr_end(void* pf)                      retains unconsumed private results; closes the owner-only tick
//   uint32_t __fastcall npr_solve(void* G, void* edx, const void* query, const void* start, void* goal, void* viaObject,
//                                 uint32_t flag)               stack args pop 0x14 (callee cleanup) == original 0x8026F0
//   volatile uint32_t npr_state[NPR_STATE_WORDS]               exported DATA
//   volatile uint32_t npr_storage_bytes                         exported DATA: bytes this module holds via its own allocation
//                                                              (slots + workspaces + footprints); 0 when stopped / not started
//
// SEMANTICS (the contract the runtime keeps; every violation falls back to the ORIGINAL 0x8026F0 untouched):
//   * npr_solve is entered from the real 0x80F5E0 prefix on the game (owner) thread with the real, native-built inputs.
//     It returns exactly what 0x8026F0 would: al = found, and the same G state (G.output = nodes+pointers in G's own arena B
//     via the original 0x80B0F0 / 0x448B90, G+0xE4/+0x120/+0xFC/+0x100/+0x104/+0x110/+0x124/+0x125 epilogue state).
//   * A private result is consumed only if its recorded inputs equal the actual inputs bit for bit AND the navigation
//     read-set captured when it was computed still reads identical (see native_path_runtime.cpp, "validation").
//     This proof is independent of tick age: every successor-read byte is in the footprint, and solve-relevant query fields,
//     sentinel and native-built inputs are compared again at consume. Changed/unreadable inputs fall back to the original.
//   * Completed results survive tick boundaries without re-planning. Queue membership, request address and solve-relevant
//     query fields identify a pending request; disappearance/reuse invalidates it. Byte-identical address reuse remains safe
//     by the full consume proof, not by assumed object lifetime. Scheduler bookkeeping and query padding are not identity.
//     Prefix-built start/goal/via inputs and navigation footprint remain immutable snapshots, validated at consume.
//   * At most maxNewPerTick NEW requests (including refused attempts) are planned per tick, in native queue order. The first
//     slots eligible requests form the priority window; cached requests in that window are protected from eviction. A new
//     priority request evicts the oldest planning-tick result outside that window if no free workspace remains.
//   * Only query-local deterministic shape refusals (unsupported kind / special goal) are remembered (address + solve-relevant
//     query fields, 64 entries, 64 ticks, dropped when no longer pending). Memory hits spend no budget or callbacks.
//     Capacity/budget, faults and world-dependent gate refusals NEVER enter that memory and may be retried next tick.
//   * Successor callbacks (original 0x800210) run ONLY on the owner thread, only after an allow-list gate proved every
//     virtual receiver / null chain reachable from the popped topology object, and only against private fixed-capacity memory.
//   * Workers run ntw_path_workspace::Workspace::Advance only (engine steps); they never dereference game memory.
//     Searches start with eight inline rounds. A batch still holding >=4 runnable requests and >=16 sealed neighbors
//     then uses one pool dispatch for the remaining solve, not one wake/barrier per expansion. Smaller/shorter searches
//     remain inline. Worker bodies repeatedly claim ready private slots; the owner body alone gates callbacks and seals
//     successors, and also advances ready slots when no callbacks need servicing. Interlocked per-slot handoffs exclude
//     simultaneous owner/worker access to a workspace; the pool barrier joins all bodies before consume/materialize.
//     Workers pause only while awaiting sealed input. No per-tick allocations, extra threads or event handles are needed.
//     A busy/unavailable shared team retains the dispatcher's inline fallback: the owner body can finish every slot alone.
//
// SUPPORTED SUBSET (everything else is refused before any callback ran and left to the original 0x8026F0; see NPR_S_REJECTED):
//   * query kind 0 ([Q+0] == 0) with no special goal ([Q+0x34] == 0) whose position source is the pure branch of 0x816CA0
//     ([[Q+0x10] or [[Q+0xC]+0xADC]] + 0x62C has [+0xEC] == 0);  kind 1 (agent virtual position getter, target not pinned) is refused.
//   * successor shapes: direct-goal node and plain edges (no door edge reached, no kind-4 edge) whose every virtual receiver is one of
//     the pinned targets 0x4470B0 / 0x461180 / 0x6B7F90 / 0x7FF170 / 0x54E920 (see native_path_footprint.h).
//   * every node / edge count must fit the fixed private capacities (neighborCapacity, nodeBlocks, entryBlocks, openCapacity, hashLevels,
//     footprint 24576 ranges / 1 MiB); a capacity miss poisons only that private result, never fabricates a path.
//   Memory: one VirtualAlloc of slots * (sizeof(Slot) + workspace + ~1.6 MiB footprint).  Defaults for zero fields: openCapacity 8192,
//   neighborCapacity 64, nodeBlocks 96, entryBlocks 24, hashLevels 8 (output capacity fixed 2048), maxNewPerTick 4.
#pragma once

#ifndef _M_IX86
#error native_path_runtime is a 32-bit x86 ABI.
#endif

#include <stdint.h>

#define NPR_ABI 1u
#define NPR_CONFIG_WORDS 16u
#define NPR_CONFIG_BYTES 64u
#define NPR_STATE_WORDS 24u
#define NPR_STATE_BYTES 96u

#define NPR_MAX_WORKERS 31u
#define NPR_MAX_SLOTS 64u       // persistent private result/workspace capacity

struct npr_config {
    uint32_t abi;               // NPR_ABI
    uint32_t size;              // NPR_CONFIG_BYTES
    uint32_t imageDelta;        // live image base - 0x400000
    uint32_t root;              // battle root; binding key
    uint32_t model;             // [root+8]; binding key; pf == [model+0xB4]
    uint32_t pf;                // live pathfinder (alloc 0x71C); binding key checked on every hook entry
    uint32_t scheduler;         // entry of the 0x81A2C0 clone (0: original 0x81A2C0, runtime inert)
    uint32_t workers;           // persistent worker threads besides the owner, 0..NPR_MAX_WORKERS (ignored when pool != 0)
    uint32_t slots;             // private workspaces 1..NPR_MAX_SLOTS (persistent result capacity)
    uint32_t openCapacity;      // 0 = default (see .cpp)
    uint32_t neighborCapacity;  // 0 = default; must exceed the largest edge count + 1 the gate accepts
    uint32_t nodeBlocks;        // 0 = default  (blocks of 0x2808 bytes, 182 nodes each)
    uint32_t entryBlocks;       // 0 = default  (426 entries each)
    uint32_t hashLevels;        // 0 = default
    uint32_t pool;              // optional initialised ntw_pool* shared with other modules (its lifetime belongs to the caller)
    uint32_t maxNewPerTick;     // NEW planning attempts per tick; 0 = 4, otherwise 1..NPR_MAX_SLOTS
};
#ifdef __cplusplus
static_assert(sizeof(npr_config) == NPR_CONFIG_BYTES, "npr_config is sixteen u32 words");
#endif

#define NPR_OK 0u
#define NPR_E_ARG 1u        // null/unreadable config, abi, size, or a limit; detail 1: image delta/root/model/pf unreadable
#define NPR_E_STATE 2u      // initialize while not stopped/uninitialised; stop while never initialised
#define NPR_E_IMAGE 3u      // live image bytes of a pinned span differ from the approved image (detail = span index)
#define NPR_E_MEMORY 4u
#define NPR_E_POOL 5u       // pool creation failed (detail = NTW_POOL_E_*)
#define NPR_E_BUSY 6u       // stop: a tick is active (hook disabled, call again later)
#define NPR_ERR_CLASS(e) ((e) & 0xFFu)
#define NPR_ERR_DETAIL(e) ((e) >> 8)

enum npr_state_word {
    NPR_S_ABI = 0,
    NPR_S_SIZE = 1,
    NPR_S_PHASE = 2,            // 0 uninitialised, 1 ready, 2 stopped
    NPR_S_ENABLED = 3,
    NPR_S_OWNER_THREAD = 4,     // thread id inside npr_scheduler_hook, 0 idle
    NPR_S_TICKS = 5,            // scheduler hook entries that took the planning path
    NPR_S_PLANNED = 6,          // requests a private solve was completed for (found / no path / limit)
    NPR_S_CONSUMED = 7,         // npr_solve calls answered from a private result (original 0x8026F0 skipped)
    NPR_S_FALLBACKS = 8,        // npr_solve calls that ran the original 0x8026F0
    NPR_S_REJECTED = 9,         // failed planning attempts (input shape, callback gate, capacity, budget or fault)
    NPR_S_STALE = 10,           // private results dropped at consume (inputs or read-set changed)
    NPR_S_UNUSED = 11,          // completed results dropped unconsumed on invalidation, eviction or stop (not tick end)
    NPR_S_CALLBACKS = 12,       // original 0x800210 invocations (owner thread)
    NPR_S_TEAM_STEPS = 13,      // substantial search batches dispatched to the persistent team (not per-expansion rounds)
    NPR_S_WORKER_CHUNKS = 14,   // private Advance calls actually executed off-owner (excludes idle/late worker bodies)
    NPR_S_FAULTS = 15,          // guarded faults (SEH) while reading/executing borrowed game memory
    NPR_S_CARRIED = 16,         // result/tick boundaries retained unconsumed (one result can count repeatedly)
    NPR_S_EVICTED = 17,         // capacity evictions; subset of UNUSED (legacy index retained)
    NPR_S_REFUSAL_MEMORY = 18,  // planning skips proved by deterministic refusal memory (no budget/callbacks)
    NPR_S_REJECT_KINDS = 19,    // four SATURATING u8 lanes: input shape, callback gate, bad shape/fault, capacity/budget
    NPR_S_INVALID_QUERY = 20,   // completed results dropped for changed solve-relevant query fields
    NPR_S_INVALID_PENDING = 21, // completed results dropped for no longer pending / absent from a complete walk
    NPR_S_INVALID_WALK = 22,    // completed results not proved present by a truncated/faulted queue walk
    NPR_S_INVALID_EVICTED = 23  // capacity evictions, identical to NPR_S_EVICTED
};

// NPR_S_REJECT_KINDS is diagnostic, not an arithmetic total: lanes never carry into one another.
// Read each lane with NPR_REJECT_COUNT; 255 means "at least 255" since initialization.
#define NPR_REJECT_INPUT 0u
#define NPR_REJECT_GATE 1u
#define NPR_REJECT_BAD_SHAPE 2u
#define NPR_REJECT_CAPACITY 3u
#define NPR_REJECT_COUNT(word, kind) (((word) >> (8u * (kind))) & 0xFFu)

// Pinned addresses (preferred base).
#define NPR_VA_TICK_CALL 0x57DFEAu     // call 0x81A2C0 inside the battle tick
#define NPR_VA_SCHEDULER 0x81A2C0u
#define NPR_VA_STEPPER_CALL 0x81A361u  // call 0x80F5E0 inside the scheduler
#define NPR_VA_STEPPER 0x80F5E0u
#define NPR_VA_SOLVE_CALL 0x8101F5u    // call 0x8026F0 inside the stepper (return address 0x8101FA)
#define NPR_VA_SOLVE 0x8026F0u
#define NPR_VA_SUCCESSOR 0x800210u
#define NPR_VA_MODEL_PF_OFFSET 0xB4u   // [model + 0xB4] = pf
