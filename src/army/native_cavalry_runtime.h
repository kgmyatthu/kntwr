#ifndef KNTWR_NATIVE_CAVALRY_RUNTIME_H
#define KNTWR_NATIVE_CAVALRY_RUNTIME_H
#include <stdint.h>

// --cavalry-orbit native adapter (KNTWR_CAVALRY_ORBIT, explicit opt-in GAMEPLAY feature; policy: native_cavalry_orbit.h).
// A mounted unit with an accepted attack order (row vtable 0x1324080) starts circling when its target is
// already square or forms square later. Native approach descriptors are retained under that exact order;
// late activation is bounded to 16 movement installs per tick. After acquisition, enemy stance changes do
// not cancel circling. New orders, routing, invalid/dead targets and an orbit that cannot fit hand back.
// Small staggered waves (up to 4 mounts per unit, 16 admissions per tick) attempt native melee, then rejoin.
// Both alliances follow the same rule. Radius uses the target's actual member extremes plus loaded member
// clearance, never the cavalry formation's spread. Terrain Y comes only from native 0x57E870.
// Riders stream around BOTH sides of the square: the charge line (own centre -> target centre at first square acquisition) is frozen per order,
// each rider's approach side picks an odd ("+", native direction -1) or even ("-", direction +1) lane of a paired band (2..16 lanes, per-side capacity reserved
// against all live members, outer envelope hard-capped at 100 units incl. horse clearance). If the two streams cannot fit, the WHOLE order is handed back.
//
// Native facts are byte-verified against the stock executable; the patched analysis image is 13fcab62...
//   * 0x5DD450 (agent vtable +0x188, thiscall ECX = mount, one stack argument = a 0x2A-byte movement descriptor, ret 4) -> 0x650DC0 -> movement node 0x1348B44
//     constructor 0x7E2C80 at mount+0x22C, then installs native rider follower nodes (count +0x66C, array +0x670).
//     Captures stay byte-exact; orbit copies use canonical world XYZ/frame fields, resolve the pending native order adjust and recompute leg time.
//   * 0x5DCDE0 (agent vtable +0x110, ECX = mount, one stack argument) is the combat-node installer; the brain driver 0x64DE80 calls it at 0x64DED4 (return
//     0x64DED6) in phase 2 with an all-zero descriptor, sets phase 1 and then steps whatever node is installed.  An orbiting mount's phase-2 call is diverted to
//     0x5DD450 without direct phase/activity/attachment writes; native destructors retain their own side effects. Probers use native combat.
//   * The combat node tracker (node+0x48; ctor 0x61DB90: +0 = unit key, +4/+8 secondary keys, +0xC flag, +0x10 held target agent, +0x14 cooldown) is ticked by
//     0x6671A0 (src/brain/kntwr_retarget_jitter.h); the contact search 0x553420/0x553590 is restricted to the unit named by tracker+0.
//
// Threading and scope: every entry point except Bind/Reset/ObserveFlush is a no-op (the original runs) unless the tick owner opened an epoch with BeginTick on THIS thread and
// has not yet closed it with EndTick. No allocation after Bind; the major fixed arrays total 7,104,256 bytes on x86, including the 1 MiB frozen-class table.
namespace kntwr_cavalry {
using U = uint32_t;
using NativeOrder = void(__fastcall*)(U, U, const void*);
using NativeTracker = U(__fastcall*)(U, U, U);

void Bind(U imageBase);  // activation, before any calls; (re)initialises every table
void Reset();            // discard all state (world teardown / dormancy); never dereferences native memory

// Tick owner, after the AI join and before the native tick: opens the epoch, rebuilds the unit table (eligibility, footprints, orbit decisions, probe waves).
void BeginTick(U model, U tick);
// Tick owner, after the native tick and every AI join: closes the epoch after bounded, staggered waypoint renewals, probe returns and handbacks.
void EndTick();

// 0x5DD450 slot (+0x188).  Copies the descriptor (the caller's buffer is never written); runs `original` exactly once (with the copy when a waypoint replaces the
// destination, otherwise with the caller's descriptor).
void Move(U mount, const void* descriptor, NativeOrder original);
// 0x5DCDE0 slot (+0x110).  Only the calls whose return address is 0x64DED6 (driver phase 2) or 0x7FF4AF (attack-command begin 0x7FF490 via 0x809CC0), both relocated, are
// decided; every other call runs `original` untouched.  Decision (shared with Go): native (original exactly once), replace (one 0x5DD450 install of the normalized orbit copy
// of the captured descriptor, no original), or keep (nothing is called: the adapter's own orbit node is still installed, valid and unfinished).
void Combat(U mount, const void* descriptor, U returnAddress, NativeOrder original);
// 0x5DCE70 slot (0x132BA04+0x118, the go-to-entity/point command begin reached through the 0x809CE0 tail jump).  Decided only for return addresses 0x7FF51A / 0x7FF53D (relocated);
// same decision as Combat.  The go descriptor {entity-or-0, x, z} is never reinterpreted as movement.
void Go(U mount, const void* descriptor, U returnAddress, NativeOrder original);
// A native order install this adapter cannot decide (outside the epoch, any thread): voids that mount's orbit-install authority.  Lock-free, never dereferences native memory.
void NoteForeignOrder(U mount);
// Existing shared tracker-tick seam (0x6671A0 mirror).  Only the agents of an active probe wave are touched; everything else runs `original` unchanged.
U Tracker(U tracker, U agent, NativeTracker original);
// Destructor-gate observation (tick owner only, called with the row BEFORE the native 0x529D80 runs, so the
// row is still intact).  Classifies the completion by return address: the byte-proven normal class
// (0x582738, or 0x56D8D8 with outer 0x58275C) retains the already-accepted attack identity across the
// emptied queue; every other class (flush, formation-abort pop, clone-shifted caller) cancels it.  A row
// for a superseded identity cancels conservatively and never revives a cancelled one.
void ObserveRowEnd(U row, U returnAddress, U outerReturnAddress);
// Flush-entry observation at 0x542AE0 (ANY thread, also outside an epoch and before Bind): atomics only,
// never dereferences native memory.  A flush of this ring cancels every retained identity published for
// it, even when the ring is already empty (user Halt).
void ObserveFlush(U ring);
}  // namespace kntwr_cavalry
#endif
