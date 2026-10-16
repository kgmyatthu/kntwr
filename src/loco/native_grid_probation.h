#pragma once
#include <stdint.h>

struct ntw2_clone_set;

// --grid-probation (NTW2_LOCO_GRID_PROBATION): native soft-grid reader detector for relink retirement.
//
// The engine keeps dual-writing its own cell chains; nothing native is skipped or rerouted. The model+A4
// header (620AD0: +0 cell-head array, +4 head count = rows << 10, +8 row shift, +C rows, +14 clamp) owns one
// array of head dwords allocated through the engine heap (10D3140 -> FF7F20 -> heap object [1462CFC] vtable+4).
// The array is held PAGE_NOACCESS outside the owner's site-13 window: the window opens after the owned movement
// preparation, covers the owner's relink replay, native fallbacks and the grid v2 publication (including
// optional verification), and its close re-derives the layout and re-arms every page. A first-chance vectored
// handler logs each trapping instruction {EIP, first stack return-address candidate, thread class, tick site},
// restores PAGE_READWRITE for that one page and resumes the same instruction. Data, order and timing-independent
// outcomes are untouched: the only effect is the trap latency (a page stays open until the next re-arm).
//
// Page isolation: interior pages are always armed; the head/tail partial pages only when VirtualQuery shows a
// dedicated allocation (AllocationBase == the first page with at most kHeadSlack bytes of allocator header before
// the array; nothing committed past the last array page). Otherwise those edge pages stay unarmed and are
// reported as uncovered_bytes (they hold only heads of row 0 / the last row, i.e. the clamped map border).
// Relocating the array through the header +0 slot is NOT done: the engine releases header+0 through its own heap
// (same-layout free/re-allocate sequences of the 620AD0 family at 61E4CB/61E7BB/61F13F and the release at 623C34
// [INFERENCE: receiver class not pinned]; free path FF7EF0 -> owner lookup FF8950 -> heap vtable+8). A private copy
// in the slot would reach the engine heap's free with no in-process seam to swap it back first (the monitor only
// notices a destroyed battle afterwards), so isolation is measured instead (isolated / uncovered_bytes words).
namespace ntw2_grid_probation {
using U = uint32_t;

constexpr U kHeaderWords = 32, kCallers = 256, kRowWords = 8, kWords = kHeaderWords + kCallers * kRowWords;
constexpr U kHeadSlack = 64;

// Header words (NTW2_GRID_PROBATION_LABELS in ntw2_runtime.h has the same order).
enum Word : U {
    Version, Enabled, State, Isolated, Arms, WindowOpens, Traps, CellTraps,
    EdgeTraps, WriteTraps, RestoreFailures, ForeignFaults, CallersUsed, CallersDropped, ArmedPages, UncoveredBytes,
    ArrayBase, ArrayBytes, AllocationBase, AllocationBytes, ArmUs, OpenUs, MaxToggleUs, LayoutChanges,
    Refusals, TrapsTick, TrapsPool, TrapsAi, TrapsMain, TrapsOther, ProbeArms, Disarms,
};
static_assert(Disarms + 1 == kHeaderWords, "header width");
// State values.
enum StateValue : U { StateIdle, StateArmed, StateWindowOpen, StateRefused, StateRetired };
// Row words (one row per distinct {EIP, caller}). RowEip: preferred-base image VA, or for clone code the original
// instruction VA (0 for emitted literals) with the raw clone address in RowCloneVa; RowCaller likewise (first
// stack word that follows a call in the image or clone arena; 0 = none). `Where` packs bits 0..3 EIP module,
// 4..7 caller module, 8..15 thread-class mask (1 << ThreadClass), 16..31 clone id + 1 (0 = not clone code).
// First/last site = tick site + 1 (0 outside every timed site) | 0x80000000 while a routed tick executes.
enum RowWord : U { RowEip, RowCaller, RowWhere, RowCloneVa, RowCount, RowWrites, RowFirstSite, RowLastSite };
enum Module : U { ModuleImage, ModuleRuntime, ModuleClone, ModuleOther };
enum ThreadClass : U { ThreadTick, ThreadPool, ThreadAi, ThreadMain, ThreadOther, ThreadClasses };

struct Binding {
    U image_base, image_size;          // live image; image rows report preferred-base VAs (0x400000 + rva)
    U runtime_lo, runtime_hi;          // this DLL's image range
    const ntw2_clone_set* clones;      // primary clone arena (lives until process exit once published)
    volatile U* site;                  // timed-site tracker: site + 1, 0 outside sites
    volatile U* tick;                  // nonzero while a routed tick executes
    U (*thread_class)();               // ThreadClass of the calling thread; must not fault or block
};

// Monitor thread, with no tick in flight. Start resets every word and installs the first-chance handler.
bool Start(const Binding& binding);
// Monitor thread, after the tick owner drained: restores every armed page that is still this allocation's and
// removes the handler. Counters stay for the final snapshot.
void Stop();
// Owner thread inside ntw2_loco::Stage. open=1 lifts protection for the owner's relink window; open=0 re-derives
// the [manager]->+8->+A4 layout and re-arms. Never faults outward; refusals are counted and retried next close.
void __cdecl Window(void* manager, U open);
// True when a first-chance access violation lies in the currently armed span (crash capture must ignore it).
bool Owns(U address);
// Monitor thread: header plus rows (addresses resolved as described for RowWord).
void Snapshot(U out[kWords]);
// Synthetic arming for the runtime lifecycle test: arms [base, base + bytes) (page-granular, committed
// PAGE_READWRITE private memory inside one region) through the same handler path, only while no game array is
// armed; the owner window then leaves it alone. Probe(0, 0) disarms the synthetic range.
bool Probe(void* base, U bytes);
}
