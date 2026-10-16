#pragma once
#include <stdint.h>
// Site-6 finalizer closures (analysis/native-brain-unknowns.md §17, §18).
//
// 0x819770 (called from finalize 0x6543D0 at 0x654513, parked 0x67A050 at 0x67A268) with B(R+0x18C)!=1, R = the
// soldier. Every store of the active arm goes to R+0xD4..R+0x1A7 (including the R+0xF4 posture FSM sub-object
// fields R+0xF8, R+0x110..R+0x14B and the R+0x104 heading slot written by R.vt+0x84), to R+0x44C..R+0x457 (posture
// animation selection 0x66B7E0/0x66B990, non-rest states only) or to the caller stack. Its reads outside R, and
// the conditions under which the closure is exactly that set, are:
//   * R+0x18 == 0: skips [[R+0x18]+0x24].vt+0x30 (0x8198AE) and .vt+0x2C (0x819F96) — dynamic, not recovered.
//   * R+0x10 == 0: skips the support-surface reads [R+0x10]+0x5C (0x819B67) and the 0x5574A0 plane arm
//     ([R+0x10]+0x30..+0x3C); 0x5574A0 then tails 0x64C5F0 on the heightfield [model+0x9C].
//   * R.vt+0x84 == 0x659220 (every brain soldier table): reads own R+0x1B8, may store the constant 2*pi to R+0x104.
//   * Posture FSM R+0xF4 (0x10FC370 -> 0x10FBBD0), state = R+0xF8 (analysis/native-brain-unknowns.md §18): null
//     returns at once. Otherwise every state is accepted when the FSM table is 0x13338C4 or 0x134758C (slots
//     +0x0C..+0x3C: the 13 singleton getters 0x5D6F60..0x5D7080; +0x40 0x66B7E0, +0x44 0x66B990, +0x48 0x462E90,
//     +0x4C 0x5EE210, +0x50 0x447880) and the 13 singletons 0x1454168..0x1454198 still carry their image vtables
//     0x1346994 + 0x14*i (next/enter/update/exit). The closure of those 52 methods and 43 helpers stores only to
//     fsm-relative fields (R+0x114..R+0x14B, R+0x44C/+0x450/+0x454 through 0x66B7E0/0x66B990) and caller-stack
//     outputs. Beyond own fields it reads .rdata, the CRT/never-written globals 0x145438C, 0x14D05A4/A8/B0,
//     0x150FB20/24, 0x150FBA4 (0x45C190), the CRT heading table 0x176CFFC, and the animation set S = [R+0x218]:
//     database [S] row counts [[S]+0x2C]+{4AC,4C4,4DC,4F4,50C,524,53C,554,56C,584,7C4,7DC,7F4,80C,824,83C}
//     (0x6616C0/0x6618D0) and the slot table T = [S+0x10] at index R+0x1BC (only when byte R+0x458 == 1) and
//     0x2F..0x34 (0x6616C0 results; only when R+0x1D8 <= 3), falling back to T[0]; per entry E: [E+4]+0x44 -> X,
//     X+0x4C, X+0x70 (0x7F1730, 0x817CA0, 0x7F16C0). AnimHash covers exactly that read set (WitnessDepAnim). The rest state
//     0x1454198 never leaves its one update (0x806A80), so it needs no animation dependency. The FSM table 0x132BBC0
//     (installed by the 0x602EB0-wrapper soldier constructor 0x59EED0, table 0x132BA04) differs in three slots:
//     +0x40 0x5FB920 (0x66B7E0 with the same arguments, then on AL==1 stores R+0xE8 = the reach float),
//     +0x48 0x5F8190 (store-free: own R+0x48/+0x50/+0x64, its R+0x11C argument, .rdata 0x1325C60/0x1325CF8) and
//     +0x4C 0x5EE220 (store-free); all three read the reach float [[[[S]+0x1C]+0x44]+0x14] (0x10F1200), hashed
//     under kAnimReach. They are called only from 0x8070A0/0x806C20/0x8069C0/0x806D40 (+0x40), 0x807410 (+0x48)
//     and 0x8067F0 (+0x4C), none of which is in any exit's or 0x7DE0B0's closure (0x80B6E0 needs no dependency).
//   * Descriptor R+0x160 (0x80E9D0, 0x7F2220): frame F = R+0x170; null copies own fields, otherwise 0x7F4950 reads
//     F+0x80..+0x8B, F+0x9C..+0xBF and 0x7F48A0 reads word F+0x1E4 (FrameHash).
//   * World: model = [[R+0x28]+8]: model+0x58 (0x8199C4), the occupancy grid [model+0xA0] header +0..+0x27 and one
//     cell (0x819B8B), the heightfield [model+0x9C] header +0..+0x27 and four samples (0x64C5F0), plus the static
//     options byte 0x150FBA4 (0x814AA0 -> 0x45C190) and the default vector 0x150FCA0/A4 (TerrainHash).
//     0x150FB24 is written only by its CRT initialiser 0x4181F0; 0x176CFF8 is the CRT-built heading table.
// The grid cells and heightfield samples are world terrain data treated as unchanged during site 6
// (Unconfirmed: no writer scan of those heap arrays; same claim as native_fire's 0x7F14C0 TerrainProbe).
//
// 0x7F14C0 (fire candidates 0x62E910 at 0x62E946, thiscall soldier, one float): store-free. Reads own +0x48/+0x50/
// +0x64, model+0x84..+0x93 and the grid header/cells, .rdata 0x1325CAC/0x1325D20 and the heading table.
//
// 0x80B6E0 (sequencer commit, 0x659B1F) reaches the posture FSM only through 0x10F6820 (current state exit, state
// = 0) and 0x10F5C60 (fsm.vt+4 = 0x5562A0 -> getter +0x0C = state 0x1454168, its enter 0x7DE0B0): PostureClosure
// covers both, and neither reaches 0x66B7E0. Its foreign store is 0x7F7380 -> 0x811C60 (unlink from [R+0x178]).
#ifdef __cplusplus
namespace ntw2_finalizer {
using U = uint32_t;
constexpr U kReceiverBytes = 0x700;   // ntw2_brain_workers::kReceiverBytes
enum Refusal : U { Closed, Attached, Surface, Heading, FsmTable, FsmState, World, Animation };
// Histogram detail for a refused 819770: FSM state / heading target VA, else kDetailBase + Refusal.
constexpr U kDetailBase = 0xF1A10000u;
void Bind(U imageBase);
// Structural closure of 819770's active arm on soldier `receiver` (caller checked ownership and B(R+18C)!=1).
// Closed (0) or the first refusal; `detail` receives the histogram key.
U FinalizeClosure(U receiver, U* detail);
// Posture FSM structure alone (R+0xF4 table, R+0xF8 state, the 13 singleton vtables): Closed, FsmTable or
// FsmState (`detail`: the state VA). A null state is Closed without looking at the table.
U PostureClosure(U receiver, U* detail);
// The posture state is neither null nor the rest state 0x1454198: its loop may reach 0x66B7E0/0x66B990.
bool PostureAnimates(U receiver);
// The 0x66B7E0 slot-table read set selector, packed: low 16 bits the entry read through R+0x1BC (R+0x1BC when byte
// R+0x458 == 1, else kNoAnimIndex), kAnimSelects when R+0x1D8 <= 3 (signed: only then can 0x6616C0 return the ids
// 0x2F..0x34 whose entries 0x66B7E0 then reads). ~0u when R+0x1BC is not an animation id (< kAnimEntries).
// None of R+0x1BC/+0x1D8/+0x458 is stored by 0x819770's closure, so the key at classification is the key in use.
// kAnimReach: the FSM table reads the reach float (0x5FB920/0x5F8190/0x5EE220) — only with a non-null state.
constexpr U kNoAnimIndex = 0xFFFF, kAnimSelects = 0x10000, kAnimReach = 0x20000, kAnimEntries = 0x360;
U AnimKey(U receiver);
// FNV-1a over the animation-set read set listed above for S = [R+0x218] and an AnimKey. False when S, its
// database, row table or slot table is null, or the key is invalid.
bool AnimHash(U set, U key, U& hash);
// FNV-1a over the world read set listed above for root = R+0x28. False when root/model/grid is null.
bool TerrainHash(U root, U& hash);
// FNV-1a over F+0x80..+0x8B, F+0x9C..+0xBF and word F+0x1E4.
U FrameHash(U frame);
// 0x7F4950's read set alone (F+0x80..+0x8B, F+0x9C..+0xBF): 0x80E9D0's foreign-frame dependency (aux 1).
U TransformHash(U frame);
// --brain-finalizer-shadow (owner only): before the owner runs the original 819770 on the live soldier, the
// original runs on a private 0x700-byte copy; after the live call the copy must equal the live soldier byte for
// byte. Only called for proved (Inactive) active-arm calls, whose closure has no store outside R.
void Configure(bool shadow);
bool ShadowEnabled();
void ShadowBefore(U receiver);
void ShadowAfter();
void Reset();
enum Word : U { ShadowCalls, ShadowMismatches, ShadowFaults, ShadowFirstOffset, ShadowSkippedUnreadable, WordCount };
U Counter(Word word);
} // namespace ntw2_finalizer
#endif
