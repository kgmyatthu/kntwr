// Shared ABI of native_formation_runtime.dll: the in-process owner of the formation batching experiment for the pinned
// Napoleon.exe (SHA-256 13fcab62...cbad4, preferred base 0x400000).  The DLL is loaded into the game by the controller; it
// contains no patching code of its own.  Every call site that reaches it is a PRIVATE CLONE of original code (tick clone with
// its call 0x580640 redirected to nfr_manager_hook, command clone 0x581200..0x58123C with call 0x581235 redirected to a
// clone of 0x57AFC0, clone of 0x555CA0 with call 0x555CEB redirected to nfr_assign_hook).  All exports are x86.
//
// Exports (link names are undecorated; the .cpp carries /EXPORT pragmas for the decorated symbols):
//   nfr_initialize(void* config)  stdcall, returns 0 or an NFR_E_* error; reads the ten config words below.
//   nfr_stop(void* unused)        stdcall, returns 0 (stopped) or an NFR_E_* error.
//   nfr_manager_hook              __fastcall(ECX = army manager [model+0xB0], EDX ignored), zero stack arguments; replaces the
//                                 call 0x580640 inside the tick clone.  Runs the ORIGINAL 0x580640 exactly once on every
//                                 path and returns its EAX.
//   nfr_assign_hook               naked, ECX = formation, four stack arguments (slotVec, flag, assignVec, layoutIndex),
//                                 `ret 0x10`.  Replaces the call 0x18F0A00 inside the 0x555CA0 clone.  Preserves every
//                                 general register, EFLAGS and xmm0..xmm7 on the commit path (0x18F0A00 itself saves them
//                                 around its hooks) and tail-jumps to the ORIGINAL 0x18F0A00 (arguments untouched) on every
//                                 other path.
//   nfr_state                     exported DATA, NFR_STATE_WORDS u32 words (below).
//   nfr_diag                      exported DATA, NFR_DIAG_WORDS u32 words: latest owner-thread gather diagnostics (below).
#pragma once

#ifndef _M_IX86
#error native_formation_runtime is a 32-bit x86 ABI.
#endif

#include <stdint.h>

#define NFR_ABI 1u
#define NFR_CONFIG_WORDS 10u
#define NFR_CONFIG_BYTES 40u
#define NFR_STATE_WORDS 16u
#define NFR_STATE_BYTES 64u
#define NFR_DIAG_WORDS 192u
#define NFR_DIAG_BYTES 768u

// Configuration limits enforced by nfr_initialize.
#define NFR_MAX_WORKERS 31u        // NTW_POOL_MAX_WORKERS
#define NFR_MAX_UNITS 4096u        // prepared formations per epoch (Batch::Config::maxUnits)
#define NFR_MAX_MEN 4096u          // 0x18F0200 bound
#define NFR_MIN_ARENA_BYTES 0x10000u
#define NFR_MAX_ARENA_BYTES 0x40000000u

// nfr_initialize(config): exactly ten u32 words (NFR_CONFIG_BYTES).
struct nfr_config {
    uint32_t abi;          // == NFR_ABI
    uint32_t size;         // == NFR_CONFIG_BYTES
    uint32_t imageDelta;   // actual image base - 0x400000
    uint32_t root;         // battle root (engine[+0xF8]); binding key
    uint32_t model;        // battle model ([root+8]); binding key; the army manager is [model+0xB0]
    uint32_t workers;      // persistent worker threads besides the caller, 0..NFR_MAX_WORKERS (0: caller only)
    uint32_t maxUnits;     // 1..NFR_MAX_UNITS
    uint32_t maxMen;       // 1..NFR_MAX_MEN
    uint32_t arenaBytes;   // per-epoch unit arena, NFR_MIN_ARENA_BYTES..NFR_MAX_ARENA_BYTES
    uint32_t minJobs;      // prepared jobs needed to use the team; fewer run caller-only (>= 1)
};
#ifdef __cplusplus
static_assert(sizeof(nfr_config) == NFR_CONFIG_BYTES, "nfr_config is ten u32 words");
#endif

// Error codes: the low byte is the class; for NFR_E_BATCH / NFR_E_POOL / NFR_E_IMAGE the bits 8.. carry the detail
// (ntw_formation_batch::Reason, NTW_POOL_E_*, GetLastError() of the failing pin).  Success is exactly 0.
#define NFR_OK 0u
#define NFR_E_ARG 1u         // null / unreadable config, abi, size, root, model, or a limit above; detail 1: restart with a different imageDelta
#define NFR_E_STATE 2u       // initialize: initializing / ready / stopping, or a restart whose stopped precondition does not hold (detail 1);
                             // stop: never initialized
#define NFR_E_IMAGE 3u       // Batch::Init refused the image at imageDelta (kImageMismatch / kAngleTableNotReady; detail = Reason)
#define NFR_E_MEMORY 4u      // VirtualAlloc of the batch storage failed
#define NFR_E_BATCH 5u       // Batch::Init failed for another reason (detail = Reason)
#define NFR_E_POOL 6u        // ntw_pool_init / ntw_pool_shutdown failed (detail = NTW_POOL_E_*)
#define NFR_E_PIN 7u         // GetModuleHandleExW(PIN) failed: the DLL could not be pinned (detail = GetLastError)
#define NFR_E_BUSY 8u        // stop: an epoch is active (entries are already disabled; call again later)
#define NFR_ERR_CLASS(e) ((e) & 0xFFu)
#define NFR_ERR_DETAIL(e) ((e) >> 8)

// nfr_state words.  Counters are written with plain 32-bit stores by the owner at the end of every epoch and read by
// anybody; `enabled`, `ownerThread` and `phase` change only with Interlocked operations.
enum nfr_state_word {
    NFR_S_ABI = 0,            // NFR_ABI
    NFR_S_SIZE = 1,           // NFR_STATE_BYTES
    NFR_S_PHASE = 2,          // NFR_PHASE_*; a new session (nfr_initialize while STOPPED) goes STOPPED -> READY and resets words 5..15
    NFR_S_ENABLED = 3,        // 1: new epochs may start; 0 after nfr_stop began
    NFR_S_OWNER_THREAD = 4,   // thread id owning the active epoch, 0 when idle
    NFR_S_EPOCHS = 5,         // epochs started (manager entries that took the batch path)
    NFR_S_PREPARED = 6,       // formations prepared
    NFR_S_EXECUTED = 7,       // prepared formations whose job executed successfully
    NFR_S_COMMITTED = 8,      // assignments committed from the batch (the original 0x18F0A00 was skipped)
    NFR_S_FALLBACKS = 9,      // every nfr_assign_hook entry that ran the original 0x18F0A00 (owner misses + non-owner contexts)
    NFR_S_UNUSED = 10,        // jobs prepared/executed that nobody consumed before the epoch ended
    NFR_S_REJECTED = 11,      // manager entries that ran native without an epoch (stopped/unbound/not exclusive) plus
                              // registry lists / commands rejected by gather bounds or a guarded read fault
    NFR_S_TEAM_DISPATCHES = 12,   // dispatches that took the persistent team path
    NFR_S_WORKER_CHUNKS = 13,     // chunks executed by worker threads (sum of the pool slots)
    NFR_S_CALLER_CHUNKS = 14,     // chunks executed by the game thread (team dispatches, caller-only dispatches, serial runs)
    NFR_S_STORAGE_BYTES = 15      // bytes of the batch storage block currently held; a restart reuses it when it fits, else replaces (and frees) it
};
enum nfr_phase { NFR_PHASE_UNINITIALIZED = 0, NFR_PHASE_READY = 1, NFR_PHASE_STOPPED = 2 };

// nfr_diag: reset for each accepted owner-thread epoch, not cumulative. Only the gather owner writes these words.
// Phase is 0 before the first gather, 1 while gathering/resetting, 2 after gather (including a caught SEH fault).
// Readers can see partial data during phase 1; this is diagnostic telemetry, not an atomic snapshot.
// "Seen" counts non-null pointers reached, before inspecting the object's fields; duplicate registry entries count again.
// Later-stage counters only include objects passing all earlier filters. All vtable samples subtract imageDelta (u32),
// including the first observed unit vtable. A zero sample can be a real value: use its corresponding count for validity.
// Command samples retain the FIRST six distinct unsupported vtables in encounter order; the six-slot sample ring does
// not overwrite those first samples when full. Count is capped at six. Reserved words stay zero.
enum nfr_diag_word {
    NFR_D_ABI = 0,                    // NFR_ABI
    NFR_D_BYTES = 1,                  // NFR_DIAG_BYTES
    NFR_D_EPOCH = 2,                  // Batch::Stats::epochs for this gather (session-local)
    NFR_D_PHASE = 3,
    NFR_D_ARMIES_SEEN = 4,
    NFR_D_CONTAINERS_SEEN = 5,
    NFR_D_UNITS_SEEN = 6,
    NFR_D_UNITS_WRONG_VTABLE = 7,
    NFR_D_FIRST_WRONG_UNIT_VTABLE = 8,
    NFR_D_FIRST_UNIT_VTABLE = 9,
    NFR_D_FORMATIONS_SEEN = 10,
    NFR_D_FORMATIONS_WRONG_VTABLE = 11,
    NFR_D_FIRST_WRONG_FORMATION_VTABLE = 12,
    NFR_D_FORMATIONS_BAD_BACKLINK = 13,
    NFR_D_FORMATIONS_QUEUE_EMPTY = 14,
    NFR_D_FORMATIONS_QUEUE_OVERSIZE = 15,
    NFR_D_COMMANDS_SEEN = 16,
    NFR_D_COMMANDS_WRONG_VTABLE = 17,
    NFR_D_COMMAND_VTABLE_COUNT = 18,
    NFR_D_COMMAND_VTABLE_0 = 19,       // words 19..24: first six distinct unsupported command vtables
    NFR_D_REJECTED_LISTS = 25,         // existing gather bound/list rejections (not vtable mismatches)
    NFR_D_FAULTED = 26,                // 1 if gather's existing SEH handler caught a fault, otherwise 0
    NFR_D_CANDIDATES = 27,             // commands accepted by the unchanged gather
    NFR_D_RESERVED_0 = 28             // words 28..31: reserved
};

// Sticky raw captures (words 32..175; ABI growth: words 0..31 keep their meaning).  Unlike the counters above they are NOT reset
// per epoch: each is written ONCE per session (nfr_initialize zeroes them when a session starts), by the gather owner, and
// status word 0 is stored LAST (1 = complete, every value below is final).  Values are RAW live values (no imageDelta
// subtracted).  Purely diagnostic: nothing here influences which commands are accepted.
//   capture A (word 32): the FIRST formation whose last queued command has [cmd] == imageDelta + NFR_CAPTURE_VTABLE_A.
//   capture B (word 104): the FIRST formation whose last queued command has [cmd] == imageDelta + either NFR_CAPTURE_VTABLE_B*.
// The preferred-base identities below come from the receipt's decimal samples, not from their former incorrect hex conversion.
// Both fire only for commands that are not one of the six handled vtables.  Layout of one capture (NFR_CAPTURE_WORDS words):
enum nfr_capture_word {
    NFR_C_STATUS = 0,          // 0 empty, 1 complete
    NFR_C_FAULTS = 1,          // bit0 formation dump faulted, bit1 entry second dword, bit2 command object dump, bit3 [cmd] dump
                               // (a faulted block is zero from the faulting dword on)
    NFR_C_EPOCH = 2,           // NFR_D_EPOCH when captured
    NFR_C_FORMATION = 3,       // formation address
    NFR_C_QUEUE_COUNT = 4,     // dword at formation+0x460
    NFR_C_ENTRY_POINTER = 5,   // dword at formation+0x420+8*(count-1): the queue entry value read as the command pointer
    NFR_C_ENTRY_SECOND = 6,    // dword at formation+0x424+8*(count-1)
    NFR_C_QUEUE_INDEX = 7,     // count-1
    NFR_C_FORMATION_DUMP = 8,  // 32 dwords: formation+0x400 .. +0x47C
    NFR_C_COMMAND_DUMP = 40,   // 16 dwords at the entry pointer (the command object): cmd+0 .. +0x3C
    NFR_C_VTABLE_DUMP = 56,    // 16 dwords at [cmd] (the object's vtable pointer): vt+0 .. +0x3C
    NFR_CAPTURE_WORDS = 72
};
#define NFR_D_CAPTURE_A 32u
#define NFR_D_CAPTURE_B 104u    // words 176..191 are reserved and stay zero
#define NFR_CAPTURE_VTABLE_A 0x1324B54u   // receipt sample 20073300; execute slot 0x5819D0
#define NFR_CAPTURE_VTABLE_B0 0x1325470u  // receipt sample 20075632; execute slot 0x581AE0
#define NFR_CAPTURE_VTABLE_B1 0x1325428u  // receipt sample 20075560; execute slot 0x581CA0

#define NFR_STOP_OWNER_TOKEN 0xFFFFFFFFu   // internal owner value while/after nfr_stop; never visible in nfr_state

// Pinned native addresses (preferred base) the DLL relies on; the controller routes through the clones listed above.
#define NFR_VA_MANAGER 0x580640u           // army manager tick (thiscall, no stack arguments)
#define NFR_VA_ASSIGN 0x18F0A00u           // assignment wrapper (thiscall formation + 4 stack args, ret 0x10)
#define NFR_VA_MODEL_MANAGER_OFFSET 0xB0u  // [model + 0xB0] = army manager
