// Bit-exact, faster replacement of ONE call of the original slot pair-swap solver 0x502770
// (Napoleon.exe, SHA-256 13fcab62...cbad4; the 0x18F1200 post-step call at 18F12AA and the 0x18F0D00 -> 0x502770 jump).
//
// Native contract being replaced (all [proven by disasm], REA evidence in analysis/native-formation-solver-memo.md):
//   __thiscall 0x502770, ECX = ctx {float def @+0, float nos @+4}, stack: Entry12* begin, Entry12* end, uint32 limit,
//   float thr, ret 0x10.  Entry = {man ptr, slot ptr, float cost} (12 bytes).  limit == 0: first-improvement pass (0x502910),
//   limit != 0: best-improvement pass (0x502A43) capped at `limit` outer iterations.  EAX on return =
//   (iteration count & ~0xFF) | done.  The original appends every entry pointer to the process-global list at
//   0x14A40A4 (cap) / 0x14A40A8 (count) / 0x14A40AC (data) with doubling growth through 0x444B40 / 0xFF7EF0 and sets
//   count back to 0 on exit; nothing but 0x502770 (and the atexit destructor 0x12E44D0, which frees `data`) reads or
//   writes it, so the list CONTENTS are dead data; only cap/data (and so the allocator call sequence) are replicated.
//
// What Solve does: gathers every man's (x, z, angle-table sin/cos) and every slot's world (x, z) ONCE (the slot through the
// native 0x80E9D0 pose function, Env::pose), then runs the identical outer-iteration / first- or best-improvement /
// swap-remove algorithm with the exact 0x5281D0 SSE operation order (man index = entry position at solve start, carried
// along swaps; slot index = entry position, slots never move).  Two loops exist:
//   kSimd   (default; limit == 0, i.e. flag = 1 storms): two eager cost tables, list-order SoA arrays scanned four lanes at
//           a time and a tournament tree for the worst-cost scan.
//   kDirect (limit != 0, census mode, and the oracle's reference): scalar loop recomputing each cost from the gathered SoA.
//
// Preconditions (the caller owns them; violating the first three crashes the native solver too):
//   * every non-null man pointer in the entries addresses a live man object (+0x48 x, +0x50 z, +0x64 u16 angle);
//   * every non-null slot pointer addresses a live 36-byte slot record (pose object at +4, parent at +0x14);
//   * nothing writes those objects while Solve runs (single owner thread, as for the native call);
//   * the gather poses every non-null slot once and kSimd costs all m^2 pairs, which is legal because 0x5281D0 -> 0x80E9D0 -> 0x7F4950
//     write only their out buffer / stack and read read-only constants [proven by disasm: ev_896a7a082aa65e98 (5281D0),
//     ev_e8f472cc7abb8379 (80E9D0), ev_2b9a08f879b9c890 (7F4950)]; slot pose objects are generator records valid for the whole solve;
//   * Env constants are the bit patterns the caller verified at Start.
// Anything else (m > kMaxM, count != 0 list, guard not initialised, malformed range, bad Env; kSimd: unmasked MXCSR
// exceptions or an out-of-contract ctx/pairWeight) returns kFallback BEFORE any write: entries, the global list and the heap
// are untouched and the caller runs the native 0x502770.
//
// No allocation inside Solve (the only allocator traffic is the replicated list growth through Env::alloc/release),
// no MXCSR / x87 control-word change, no x87 arithmetic, no global state besides Env::listGlobal.
#pragma once
#include <cstdint>

namespace ntw_solver {

// Largest m (entries per solve) the workspace holds; above it Solve returns kFallback (kReasonTooLarge, native runs).
// Live capture 28252: 88 units, max 404 men; user battles have units of 500-800 men, so the bound is 800 (user decision
// 2026-10-18; larger formations fall back to the exact native solver). The workspace is allocated ONCE (CreateWorkspace at
// activation, never per solve) and is ~5.2 MiB (see WorkspaceBytes(); the two eager cost tables of (kMaxM+4) x (kMaxM+4)
// floats dominate).
constexpr uint32_t kMaxM = 800;

struct Entry12 {               // live 12-byte entry; 0 = null pointer
    uint32_t man;
    uint32_t slot;
    float cost;
};
static_assert(sizeof(Entry12) == 12, "native entry layout");

struct Env {                   // every address already relocated
    const float* angleTable;   // 0x176CFF8: 65536 {sin, cos} float pairs
    float zero, one, pairWeight;   // [0x131A7A4] [0x1318048] [0x1318038]
    // 0x80E9D0: thiscall(this = slot+4) ret 4, writes out3[0..2], returns out3.  __fastcall shape: ECX = this, EDX unused.
    const float* (__fastcall* pose)(void* pose, void* edx, float* out3);
    uint32_t* listGlobal;      // &[0x14A40A4]: [0] cap, [1] count, [2] data
    void* (__cdecl* alloc)(uint32_t count, uint32_t zero);   // 0x444B40 (count*4 bytes through the game heap)
    void (__cdecl* release)(void* p);                        // 0xFF7EF0
    const int32_t* listGuard;  // &[0x14A40B0]  thread-safe-static guard of the list (native init path when > epoch)
    const uint32_t* tlsIndex;  // &[0x1841BB8]  the image's _tls_index slot (epoch = [[fs:2C] + index*4] + 8)
};

struct Counters {              // all per call; evals = native-equivalent 0x5281D0 calls
    uint32_t m;                // entries
    uint32_t evals;            // 0x5281D0 calls the native solver would make
    uint32_t distinct;         // distinct (man index, slot index) pairs among them; census mode (profile != 0) only, else 0
    uint32_t iterations;       // native `iter` at exit (outer iterations incl. the terminal "done" one)
    uint32_t swaps;            // accepted swaps
    uint32_t removals;         // swap-removed worst entries (outer iterations without a swap)
    uint32_t fallback;         // FallbackReason when Solve returned kFallback, else 0
    uint32_t scans;            // W = sum over outer iterations of the list length scanned in the worst-candidate pass
    uint32_t profile;          // INPUT (preserved): non-zero = census mode: count `distinct` pairs (bitset, ~10-15% slower)
                               // and run the scalar kDirect loop even for limit == 0, so census solves do NOT exercise kSimd
    uint32_t spare;            // keeps the u64 block 8-byte aligned
    uint64_t gatherTicks;      // rdtsc: man gather + per-slot native pose calls
    uint64_t fillTicks;        // rdtsc: kSimd eager cost-table fill (INCLUDED in loopTicks), else 0
    uint64_t loopTicks;        // rdtsc: the solver loop (kSimd: including its table fill)
    uint64_t totalTicks;       // rdtsc: whole call (checks, gather, loop, list growth, commit)
};

enum FallbackReason : uint32_t {
    kReasonNone = 0,
    kReasonTooLarge = 1,       // m > kMaxM
    kReasonRange = 2,          // end < begin or (end - begin) not a multiple of 12
    kReasonListState = 3,      // global list count != 0 on entry (the native solver always leaves it 0; only count is checked)
    kReasonGuard = 4,          // list thread-safe-static not initialised: native init path must run
    kReasonEnv = 5,            // null Env member / null argument
    kReasonFpEnv = 6,          // kSimd only: MXCSR exception masks are not all set (a packed lane could trap)
    kReasonCtx = 7,            // kSimd only: ctx def/nos < -FLT_MAX or NaN, or Env::pairWeight < 0 (the -inf key / cost >= 0 assumptions)
};

struct Workspace;              // owner-private buffers (capacity kMaxM); one per solving thread
Workspace* CreateWorkspace();  // nullptr if the allocation fails
void DestroyWorkspace(Workspace*);
uint64_t WorkspaceBytes();     // sizeof(Workspace) (~11.4 MiB)

enum Outcome : int { kSolved = 0, kFallback = 1 };   // kFallback: nothing written, caller runs native 0x502770

// Same test the native prologue makes (0x502783..0x502793): true when the list static is initialised for this thread.
bool ListInitialized(const Env&);

// Bit-exact replacement of one 0x502770 call (loop policy kSimd; limit != 0 and census mode run the scalar loop).  Writes the
// entries (man pointers + cost bits; slots never change) and replicates the global list growth (cap/data) with the same
// allocator calls in the same order, count left 0.  *eax receives the native return value ((iterations & ~0xFF) | done).
// counters may be null.
Outcome Solve(Workspace&, const Env&, const float* ctx, Entry12* begin, Entry12* end, uint32_t limit, float thr,
              uint32_t* eax, Counters*);

// Shadow/census: identical algorithm on a caller-owned COPY of the pre-call entries; does NOT touch the global list
// (no Env::alloc/release traffic, no list guard / count check); counters + resulting copy + eax.
Outcome SolveCopy(Workspace&, const Env&, const float* ctx, Entry12* copyBegin, Entry12* copyEnd, uint32_t limit, float thr,
                  uint32_t* eax, Counters*);

// Oracle/benchmark hook: force the loop policy.  kDirect = scalar loop (any limit), kSimd = packed loop for limit == 0
// (limit != 0 and census mode still run the scalar loop).  Results are bit-identical by construction; only speed differs.
enum Policy : int { kDirect = 0, kSimd = 1 };
Outcome SolveWith(Policy, bool replicateList, Workspace&, const Env&, const float* ctx, Entry12* begin, Entry12* end,
                  uint32_t limit, float thr, uint32_t* eax, Counters*);

}  // namespace ntw_solver
