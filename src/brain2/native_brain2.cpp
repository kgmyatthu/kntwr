#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <stdint.h>
#include <string.h>
#include "../ntw2_clones.h"
#include "native_brain2.h"
#include "native_node.h"
#include "native_move_node.h"
#include "native_idle_node.h"
#include "native_action_node.h"
#include "native_node_projection.h"
#include "native_fire.h"
#include "native_finalizer.h"
#include "native_region_table.h"

static_assert(sizeof(void*) == 4, "BRAIN_W is the pinned Win32 x86 native closure");
namespace ntw2_brain2 {
namespace {
U g_delta, g_words[kWords], g_census[kCensusWords], g_route[kRouteWords];
constexpr U kNodeTargetCapacity = 512;
struct NodeTargetCount { U target; ULONGLONG begins, steps; };
NodeTargetCount g_nodeTargets[kNodeTargetCapacity];
U g_nodeTargetDistinct, g_nodeTargetOverflow;
void CountNodeTarget(U target, bool begin) {
    U slot = ((target >> 4) * 2654435761u) & (kNodeTargetCapacity - 1);
    for (U probe = 0; probe != kNodeTargetCapacity; ++probe) {
        NodeTargetCount& row = g_nodeTargets[slot];
        if (!row.target) { row.target = target; ++g_nodeTargetDistinct; }
        if (row.target == target) {
            if (begin) ++row.begins; else ++row.steps;
            return;
        }
        slot = (slot + 1) & (kNodeTargetCapacity - 1);
    }
    ++g_nodeTargetOverflow;
}
bool g_bound, g_censusEnabled, g_timingEnabled, g_nodeShadow, g_fireShadow, g_finalizerShadow;
const U* g_clones;
const U* g_readyClones;
U g_entity, g_firstActive, g_firstUnknown, g_poseMask;
U g_activeSequence, g_unknownSequence;
constexpr U kFrameCapacity = 1024;
struct Frame {
    U returnAddress, service, site, target, activeBefore, unknownBefore, nodeToken, moveNodeToken, idleNodeToken, actionNodeToken;
    bool container, timed, fireShadow, finalizerShadow;
    LARGE_INTEGER start;
};
Frame g_frames[kFrameCapacity];
U g_depth;
U g_targets[ServiceCount];
inline U V(U address) { return address + g_delta; }
inline U D(U address) { return *reinterpret_cast<const U*>(address); }
inline uint8_t B(U address) { return *reinterpret_cast<const uint8_t*>(address); }
inline const float* F(U address) { return reinterpret_cast<const float*>(address); }
inline U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
inline U* Row(Service s) { return g_census + s * kServiceStride; }
void AddTicks(U* pair, ULONGLONG ticks) {
    const ULONGLONG sum = (static_cast<ULONGLONG>(pair[1]) << 32 | pair[0]) + ticks;
    pair[0] = static_cast<U>(sum); pair[1] = static_cast<U>(sum >> 32);
}
bool Clock(LARGE_INTEGER& value) {
    if (QueryPerformanceCounter(&value)) return true;
    ++g_words[QpcFailures]; return false;
}
void Metadata() {
    g_words[Version] = kVersion;
    g_words[CensusEnabled] = g_censusEnabled;
    g_words[TimingEnabled] = g_timingEnabled;
    g_words[Bound] = g_bound;
    if (g_timingEnabled && !g_words[QpcFrequencyLo] && !g_words[QpcFrequencyHi]) {
        LARGE_INTEGER frequency;
        if (QueryPerformanceFrequency(&frequency)) {
            g_words[QpcFrequencyLo] = frequency.LowPart;
            g_words[QpcFrequencyHi] = static_cast<U>(frequency.HighPart);
        } else ++g_words[QpcFailures];
    }
}
bool Stub(U target) {
    return target == V(0x444B60) || target == V(0x461180) ||
           target == V(0x462CB0) || target == V(0x447880) || target == V(0x62DF00);
}
// ---- Exact register-only leaves ------------------------------------------
// The first bytes fully determine these bodies: no memory operand, no call, a
// RET/RET imm16 terminator. Read only inside the mapped image .text (0x401000,
// size 0xF058FC). Covers the soldier constant getters 47AF90/4CDC40..4CDC90/
// 66BA90 (`mov eax,imm32; ret`), 4470B0 (`mov eax,ecx; ret`), 62DF00 (`lea
// eax,[ecx+1C]; ret`) and the Stub() table. Such a call writes no memory at all.
constexpr U kTextBegin = 0x401000, kTextEnd = 0x401000 + 0xF058FC;
bool RetAt(U p) { const uint8_t op = B(p); return op == 0xC3 || (op == 0xC2 && B(p + 2) == 0); }
bool PureLeaf(U target) {
    if (!g_bound || target < V(kTextBegin) || target > V(kTextEnd) - 8) return false;
    const uint8_t b0 = B(target), b1 = B(target + 1);
    if (RetAt(target)) return true;
    if ((b0 == 0x32 || b0 == 0x33) && b1 == 0xC0) return RetAt(target + 2); // xor al,al / xor eax,eax
    if (b0 == 0x8B && b1 == 0xC1) return RetAt(target + 2);                 // mov eax,ecx
    if (b0 == 0xB0) return RetAt(target + 2);                               // mov al,imm8
    if (b0 == 0xB8) return RetAt(target + 5);                               // mov eax,imm32
    if (b0 == 0x8D && b1 == 0x41) return RetAt(target + 3);                 // lea eax,[ecx+disp8]
    return false;
}
// Soldier query slots (+E8/+EC/+F0): register-only leaves or 5DB820, which
// reads only receiver+67C (`cmp [ecx+67C],0; setne al; ret`).
bool OwnQuery(U target) { return PureLeaf(target) || target == V(0x5DB820); }
// Holders/nodes embedded in the occurrence soldier (2CC/51C/228/394 ...).
constexpr U kOwnSpan = 0x700;
bool OwnPart(U p, U entity) { return entity && p - entity < kOwnSpan; }
// A caller frame of this occurrence: at/above the gate's argument block and
// below the executing thread's stack base (owner or worker stack alike).
bool StackLocal(U p, U size, const U* args) {
    if (!args) return false;
    const U high = Address(reinterpret_cast<const NT_TIB*>(NtCurrentTeb())->StackBase);
    return p >= Address(args) && p + size >= p && p + size <= high;
}

// ---- Site-6 dispatch witness --------------------------------------------
// Unit read set (index: field):
//   0 U+930 count, 1 U+AA0, 2 U+C00 context, 3 byte [[[U+C00]+8]+B0]+2704,
//   4 U+C2C, 5 U+2CC, 6 X=U+ADC, 7 X+460, 8 D=U+2C, 9 D+1C type,
//   10 T=U+1F4, 11 T+10, 12 bytes DA4|D9E<<8|D9D<<16, 13 U+DA8,
//   14 C=U+14, 15 [[C+8]+B0], 16 model=[context+8], 17 manager=[model+B0],
//   18 ctxModel=[C+8], 19 U+C70, 20 [D+C70*4+E4], 21 U+16C,
//   22 ability count [U+DB8], 23 ability data [U+DBC], 24 FNV1a of count*44
//   bytes (count capped at 16) of the ability entries, 25 [entry20+10] (the
//   stat multiplier the 649520 caller reads at 6544EE), 26 U+934 mode index,
//   27 Q.vt = [U+398+U+934*90] (53EEE0 dispatches Q.vt+34 when U+930 != 0; ~0
//   when Begin could not read Q, which no proof then accepts).
// Missing pointer => ~0 for dependents; per-call equality compares pointers
// and only then the derived values, so no unreadable memory is chased.
// Writer evidence (approved image, linear sweep + .reloc): U+AA0 direct stores
// 51BAEC/585893/5858BC/5B9DA9/875F6D/11C998A/11CBDB1/11CFF0B and U+C2C stores
// 11C3AA7/11CB101/11D01DB all lie outside the 3161-function direct-call closure
// of the BRAIN_W sources + soldier/node vtable slots; U+930 has no direct store
// (written through an unrecovered container base). The snapshot/recheck below
// is therefore the proof of record, not the static scan.
// Battle read set (M = model+B0): 0 M+14 phase, 1 S=M+198, 2 S+24, 3 S+10,
// 4 E=[S+10+8*(S+24)], 5 E+10, 6 byte M+2704, 7 reserved.
// Slot read set (S = A+444): 0 S[0] animation id, 1 A=S[4], 2 H=S[8],
// 3 A+50 row count, 4 the WORD H+14 (66EED9: read only at frame 0), 5 R=H+38.
// Separately, up to kSlotRows per-row FNV-1a hashes of the 16 bytes R+28*i+0C..+1B
// 66EEB0 reads at frame index i (no whole-array hash on the hot path; a frame
// index >= kSlotRows is refused).
constexpr U kUnitFields = 28, kBattleFields = 8, kSlotFields = 6, kSlotRows = 256;
constexpr U kUnitCapacity = 2048, kSlotCapacity = 2048;
struct UnitSnapshot { U unit; U values[kUnitFields]; U used; };
struct SlotSnapshot { U record; U values[kSlotFields]; U rowHashes[kSlotRows]; U used, usedRows[kSlotRows / 32]; };
UnitSnapshot g_units[kUnitCapacity];
SlotSnapshot g_slots[kSlotCapacity];
// Army stat read set (soldiers with null A+1F0): 649520's army branch returns
// [base+A+374*4+E4], base=[army+218], army=A+1F8; its caller (6544EE) reads
// entry+10. Snapshot: base, the first 8 entries and each entry+10 (A+374 is
// written only on the soldier itself: own selector 670F40 at 67126A..6713A6,
// own method 660AB0 at 660C02, and unit update 57F070 at 57F1E7 in stage A
// before site 6). An index >= 8 is refused.
constexpr U kArmyEntries = 8, kArmyCapacity = 256;
struct ArmySnapshot { U army; U base; U entries[kArmyEntries]; U mults[kArmyEntries]; U used, usedEntries; };
ArmySnapshot g_armies[kArmyCapacity];
U g_battleManager, g_battleValues[kBattleFields], g_witness[kWitnessWords];
bool g_witnessOpen, g_battleValid, g_battleUsed;
enum Note : U {
    NoteUnitOk = 1, NoteUnitMismatch = 2, NoteUnitMissing = 4,
    NoteBattleOk = 8, NoteBattleMismatch = 16, NoteManagerMissing = 32,
    NoteSlotMismatch = 64, NoteSlotMissing = 128, NoteArmyMismatch = 256
};

// Readability probes are used at dispatch Begin/End, never by a native call:
// the first-chance recorder must not see a speculative dereference. The proven
// regions (native_region_table.h, cleared at every Begin) cover the soldier,
// unit and slot heaps; every derived pointer is probed before it is dereferenced.
// Per-call equality (UnitStatic/SlotStatic) only compares pointer identities and
// already-snapshotted objects, so it needs no probe.
ntw2_region::Table g_probe;
U g_probeQueries;
bool ProbeRegionContains(U address, U size) { return g_probe.Readable(address, size, g_probeQueries); }
U HashBytes(U address, U count) {
    U hash = 2166136261u;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(address);
    for (U i = 0; i < count; ++i) { hash ^= p[i]; hash *= 16777619u; }
    return hash;
}
U Fn1a(U address, U count) {
    return !count ? 0 : !ProbeRegionContains(address, count) ? ~0u : HashBytes(address, count);
}
U AbilityBytes(U count) { return (count > 16 ? 16 : count) * 0x2C; }
U AbilityHashProbed(U data, U count) { return count ? Fn1a(data, AbilityBytes(count)) : 0; }
U AbilityHash(U data, U count) { return count ? HashBytes(data, AbilityBytes(count)) : 0; }

// Full probed read (dispatch Begin/End only). ~0 marks an unreadable dependent.
bool ReadUnit(U u, U* v) {
    if (!ProbeRegionContains(u, 0xE00)) return false;
    v[0] = D(u + 0x930); v[1] = D(u + 0xAA0); v[4] = D(u + 0xC2C); v[5] = D(u + 0x2CC);
    v[12] = B(u + 0xDA4) | U(B(u + 0xD9E)) << 8 | U(B(u + 0xD9D)) << 16;
    v[13] = D(u + 0xDA8); v[19] = D(u + 0xC70); v[21] = D(u + 0x16C);
    const U context = D(u + 0xC00); v[2] = context;
    const U model = context && ProbeRegionContains(context + 8, 4) ? D(context + 8) : 0;
    v[16] = model;
    const U manager = model && ProbeRegionContains(model + 0xB0, 4) ? D(model + 0xB0) : 0;
    v[17] = manager;
    v[3] = manager && ProbeRegionContains(manager + 0x2704, 1) ? B(manager + 0x2704) : ~0u;
    const U group = D(u + 0xADC); v[6] = group;
    v[7] = group && ProbeRegionContains(group + 0x460, 4) ? D(group + 0x460) : ~0u;
    const U desc = D(u + 0x2C); v[8] = desc;
    if (desc && ProbeRegionContains(desc + 0x1C, 0x10)) {
        v[9] = D(desc + 0x1C);
        v[20] = v[19] == ~0u || !ProbeRegionContains(desc + v[19] * 4 + 0xE4, 4) ? ~0u : D(desc + v[19] * 4 + 0xE4);
    } else { v[9] = ~0u; v[20] = ~0u; }
    const U attached = D(u + 0x1F4); v[10] = attached;
    v[11] = attached && ProbeRegionContains(attached + 0x10, 4) ? D(attached + 0x10) : ~0u;
    const U ctx = D(u + 0x14); v[14] = ctx;
    const U ctxModel = ctx && ProbeRegionContains(ctx + 8, 4) ? D(ctx + 8) : 0;
    v[18] = ctxModel;
    v[15] = ctxModel && ProbeRegionContains(ctxModel + 0xB0, 4) ? D(ctxModel + 0xB0) : ~0u;
    v[22] = D(u + 0xDB8); v[23] = D(u + 0xDBC);
    v[24] = v[22] <= 0x1000000 ? AbilityHashProbed(v[23], v[22]) : ~0u;
    v[25] = v[20] == ~0u ? ~0u : !v[20] ? 0 : ProbeRegionContains(v[20] + 0x10, 4) ? D(v[20] + 0x10) : ~0u;
    v[26] = D(u + 0x934);
    const U q = u + 0x398 + v[26] * 0x90;
    v[27] = v[26] < 0x10000 && ProbeRegionContains(q, 4) ? D(q) : ~0u;
    return true;
}
bool ReadBattle(U m, U* v) {
    if (!ProbeRegionContains(m, 0x2708)) return false;
    v[0] = D(m + 0x14); v[6] = B(m + 0x2704); v[7] = 0;
    const U state = D(m + 0x198); v[1] = state;
    if (!state || !ProbeRegionContains(state + 0x10, 0x18)) {
        v[2] = v[3] = v[4] = v[5] = ~0u; return true;
    }
    const U index = D(state + 0x24), table = D(state + 0x10);
    v[2] = index; v[3] = table;
    const U entry = table && ProbeRegionContains(table + index * 8, 4) ? D(table + index * 8) : 0;
    v[4] = table ? entry : ~0u;
    v[5] = entry && ProbeRegionContains(entry + 0x10, 4) ? D(entry + 0x10) : ~0u;
    return true;
}
bool ReadSlot(U s, SlotSnapshot& out) {
    U* v = out.values;
    if (!ProbeRegionContains(s, 0xC)) return false;
    v[0] = D(s); v[1] = D(s + 4); v[2] = D(s + 8);
    const U header = v[2];
    if (header && ProbeRegionContains(header + 0x14, 4) && ProbeRegionContains(header + 0x38, 4)) {
        v[4] = D(header + 0x14) & 0xFFFF; v[5] = D(header + 0x38);
    } else v[4] = v[5] = ~0u;
    v[3] = v[1] && ProbeRegionContains(v[1] + 0x50, 4) ? D(v[1] + 0x50) : ~0u;
    for (U i = 0; i < kSlotRows; ++i)
        out.rowHashes[i] = v[3] > i && v[5] ? Fn1a(v[5] + i * 28 + 0xC, 16) : 0;
    return true;
}
bool ReadArmy(U army, ArmySnapshot& out) {
    if (!ProbeRegionContains(army + 0x218, 4)) return false;
    out.base = D(army + 0x218);
    for (U i = 0; i < kArmyEntries; ++i) {
        U entry = 0, mult = 0;
        if (out.base) {
            entry = ProbeRegionContains(out.base + 0xE4 + i * 4, 4) ? D(out.base + 0xE4 + i * 4) : ~0u;
            mult = entry == ~0u ? ~0u : !entry ? 0 : ProbeRegionContains(entry + 0x10, 4) ? D(entry + 0x10) : ~0u;
        }
        out.entries[i] = entry; out.mults[i] = mult;
    }
    return true;
}
U UnitSlot(U unit) { return ((unit >> 3) * 2654435761u) & (kUnitCapacity - 1); }
UnitSnapshot* FindUnit(U unit) {
    for (U probe = 0, slot = UnitSlot(unit); probe != kUnitCapacity; ++probe, slot = (slot + 1) & (kUnitCapacity - 1)) {
        if (g_units[slot].unit == unit) return &g_units[slot];
        if (!g_units[slot].unit) return nullptr;
    }
    return nullptr;
}
SlotSnapshot* FindSlot(U record) {
    for (U probe = 0, slot = UnitSlot(record); probe != kSlotCapacity; ++probe, slot = (slot + 1) & (kSlotCapacity - 1)) {
        if (g_slots[slot].record == record) return &g_slots[slot];
        if (!g_slots[slot].record) return nullptr;
    }
    return nullptr;
}
U ArmySlot(U army) { return ((army >> 3) * 2654435761u) & (kArmyCapacity - 1); }
ArmySnapshot* FindArmy(U army) {
    for (U probe = 0, slot = ArmySlot(army); probe != kArmyCapacity; ++probe, slot = (slot + 1) & (kArmyCapacity - 1)) {
        if (g_armies[slot].army == army) return &g_armies[slot];
        if (!g_armies[slot].army) return nullptr;
    }
    return nullptr;
}
// A dependent pointer is dereferenced only when it is IDENTICAL to the pointer
// read at Begin and Begin obtained a usable value. A different pointer, or a
// dependent Begin could not read, sets mismatch and is never chased: no
// speculative access and no VirtualQuery on a worker thread.
U ChainPtr(U pointer, U snapshotPointer, U snapshotValue, U offset, bool& mismatch) {
    if (pointer != snapshotPointer) { mismatch = true; return 0; }
    if (!pointer) return 0;
    if (!snapshotValue) { mismatch = true; return 0; } // Begin read nothing usable
    return D(pointer + offset);
}
U ChainVal(U pointer, U snapshotPointer, U snapshotValue, U offset, bool& mismatch) {
    if (pointer != snapshotPointer) { mismatch = true; return 0; }
    if (!pointer) return snapshotValue;                 // same null parent, same sentinel
    if (snapshotValue == ~0u) { mismatch = true; return 0; }
    return D(pointer + offset);
}
U ChainValB(U pointer, U snapshotPointer, U snapshotValue, U offset, bool& mismatch) {
    if (pointer != snapshotPointer) { mismatch = true; return 0; }
    if (!pointer) return snapshotValue;
    if (snapshotValue == ~0u) { mismatch = true; return 0; }
    return B(pointer + offset);
}
// Worker dependency sink (null on the owner census path). Each successful
// witness comparison records the snapshot it consumed, de-duplicated.
__declspec(thread) WitnessDeps* t_deps;
void RecordDep(U kind, U key, U frame, U aux = 0) {
    WitnessDeps* deps = t_deps;
    if (!deps) return;
    const U count = deps->count < kWitnessDepCap ? deps->count : kWitnessDepCap;
    for (U i = 0; i < count; ++i) {
        const WitnessDep& d = deps->items[i];
        if (d.kind == kind && d.key == key && d.frame == frame && d.aux == aux) return;
    }
    if (count == kWitnessDepCap) { deps->overflow = 1; return; }
    deps->items[count] = WitnessDep{kind, key, frame, aux};
    deps->count = count + 1;
}
// Witness memo (native_brain2.h WitnessMemo). Kinds up to MemoTerrain are the world read sets `worldOnly` keeps.
enum MemoKind : U {
    MemoUnit = 1, MemoBattle, MemoArmy, MemoTerrain, MemoSlot, MemoAnim, MemoFrame, MemoTransform, MemoTarget, MemoCrew
};
static_assert(WitnessMemo::kSlots == 512, "MemoEntry indexes with the top 9 hash bits");
__declspec(thread) WitnessMemo* t_memo;
// The direct-mapped entry for (kind, key, aux) in the bound table, or null when this lookup may not be memoized.
WitnessMemo::Entry* MemoEntry(U kind, U key, U aux) {
    WitnessMemo* const m = t_memo;
    if (!m || (m->worldOnly && kind > MemoTerrain) || key - m->privateLo < m->privateHi - m->privateLo) return nullptr;
    return &m->entries[((key >> 2) ^ kind * 0x9E3779B1u ^ aux * 0x85EBCA77u) * 2654435761u >> 23];
}
bool MemoHit(const WitnessMemo::Entry* e, U kind, U key, U aux, U& value) {
    if (!e) return false;
    WitnessMemo& m = *t_memo;
    if (e->epoch == m.epoch && e->kind == kind && e->key == key && e->aux == aux) { ++m.hits; value = e->value; return true; }
    ++m.misses;
    return false;
}
void MemoStore(WitnessMemo::Entry* e, U kind, U key, U aux, U value) {
    if (e) *e = WitnessMemo::Entry{kind, key, aux, t_memo->epoch, value};
}
// Live unit read set equals the snapshot row `v`.
bool UnitMatches(U unit, const U* v) {
    bool mismatch = false;
    U o[kUnitFields];
    o[0] = D(unit + 0x930); o[1] = D(unit + 0xAA0); o[4] = D(unit + 0xC2C); o[5] = D(unit + 0x2CC);
    o[12] = B(unit + 0xDA4) | U(B(unit + 0xD9E)) << 8 | U(B(unit + 0xD9D)) << 16;
    o[13] = D(unit + 0xDA8); o[19] = D(unit + 0xC70); o[21] = D(unit + 0x16C);
    const U context = D(unit + 0xC00); o[2] = context;
    const U model = ChainPtr(context, v[2], v[16], 8, mismatch); o[16] = model;
    const U manager = ChainPtr(model, v[16], v[17], 0xB0, mismatch); o[17] = manager;
    o[3] = ChainValB(manager, v[17], v[3], 0x2704, mismatch);
    const U group = D(unit + 0xADC); o[6] = group; o[7] = ChainVal(group, v[6], v[7], 0x460, mismatch);
    const U desc = D(unit + 0x2C); o[8] = desc;
    o[9] = ChainVal(desc, v[8], v[9], 0x1C, mismatch);
    if (desc != v[8]) { mismatch = true; o[20] = 0; }
    else if (!desc) o[20] = v[20];
    else if (v[19] == ~0u || v[20] == ~0u) { mismatch = true; o[20] = 0; }
    else o[20] = D(desc + v[19] * 4 + 0xE4);
    const U attached = D(unit + 0x1F4); o[10] = attached; o[11] = ChainVal(attached, v[10], v[11], 0x10, mismatch);
    const U ctx = D(unit + 0x14); o[14] = ctx;
    const U ctxModel = ChainPtr(ctx, v[14], v[18], 8, mismatch); o[18] = ctxModel;
    o[15] = ChainPtr(ctxModel, v[18], v[15], 0xB0, mismatch);
    o[22] = D(unit + 0xDB8); o[23] = D(unit + 0xDBC);
    if (o[22] != v[22] || o[23] != v[23]) { mismatch = true; o[24] = 0; }
    else if (!v[22]) o[24] = 0;
    else if (v[24] == ~0u || !v[23]) { mismatch = true; o[24] = 0; }
    else o[24] = AbilityHash(v[23], v[22]);
    o[25] = ChainVal(o[20], v[20], v[25], 0x10, mismatch);
    // Q is re-read only at the Begin-probed address (same U+934); an unreadable Begin Q stays ~0.
    o[26] = D(unit + 0x934);
    if (o[26] != v[26]) { mismatch = true; o[27] = 0; }
    else o[27] = v[27] == ~0u ? ~0u : D(unit + 0x398 + v[26] * 0x90);
    return !mismatch && !memcmp(o, v, sizeof(o));
}
// Pure: live unit read set equals the open snapshot. `values` receives it.
bool UnitStatic(U unit, U* values, U* note) {
    UnitSnapshot* row = g_witnessOpen && unit ? FindUnit(unit) : nullptr;
    if (!row) { if (note) *note |= NoteUnitMissing; return false; }
    WitnessMemo::Entry* const memo = MemoEntry(MemoUnit, unit, 0);
    U memoValue;
    if (!MemoHit(memo, MemoUnit, unit, 0, memoValue)) {
        if (!UnitMatches(unit, row->values)) { if (note) *note |= NoteUnitMismatch; return false; }
        MemoStore(memo, MemoUnit, unit, 0, 1);
    }
    if (values) memcpy(values, row->values, sizeof(row->values));
    if (!row->used) row->used = 1;
    RecordDep(WitnessDepUnit, unit, 0);
    if (note) *note |= NoteUnitOk;
    return true;
}
// Live battle read set of `manager` equals the snapshot.
bool BattleMatches(U manager) {
    const U* v = g_battleValues;
    bool mismatch = false;
    U o[kBattleFields];
    o[0] = D(manager + 0x14); o[6] = B(manager + 0x2704); o[7] = 0;
    const U state = D(manager + 0x198); o[1] = state;
    U table = 0, entry = 0;
    if (state != v[1]) { mismatch = true; o[2] = o[3] = o[4] = o[5] = 0; }
    else if (!state) { o[2] = v[2]; o[3] = v[3]; o[4] = v[4]; o[5] = v[5]; }
    else if (v[2] == ~0u) { mismatch = true; o[2] = o[3] = o[4] = o[5] = 0; }
    else {
        o[2] = D(state + 0x24); table = D(state + 0x10); o[3] = table;
        if (o[2] != v[2] || table != v[3]) mismatch = true;
        if (!table) o[4] = v[4];
        else if (!v[4]) { mismatch = true; o[4] = 0; }
        else {
            entry = D(table + o[2] * 8); o[4] = entry;
            if (entry != v[4]) mismatch = true;
        }
        o[5] = ChainVal(entry, v[4], v[5], 0x10, mismatch);
    }
    return !mismatch && !memcmp(o, v, sizeof(o));
}
bool BattleStatic(U manager, U* note) {
    if (!g_witnessOpen || !g_battleValid || !manager || manager != g_battleManager) {
        if (note) *note |= NoteManagerMissing; return false;
    }
    WitnessMemo::Entry* const memo = MemoEntry(MemoBattle, manager, 0);
    U memoValue;
    if (!MemoHit(memo, MemoBattle, manager, 0, memoValue)) {
        if (!BattleMatches(manager)) { if (note) *note |= NoteBattleMismatch; return false; }
        MemoStore(memo, MemoBattle, manager, 0, 1);
    }
    if (!g_battleUsed) g_battleUsed = true;
    RecordDep(WitnessDepBattle, manager, 0);
    if (note) *note |= NoteBattleOk;
    return true;
}
// Pure: A+444's slot record and its header/rows equal the snapshot, field by field as 66EE30/66EEB0 read them: the
// id, animation pointer and its row count, the header pointer and its row pointer always; the header word H+14 only
// at frame 0; of the row at the CURRENT frame index only +0C..+1B (66EEB0 reads no other row or byte). Frame >= count
// reads no row, frame >= kSlotRows is outside the snapshot and refused. `why` (optional) receives the SlotRefusal of a
// false result (header = the H pointer or H+38 changed, record = id/animation/count, turn = H+14 at frame 0,
// unprobed = Begin could not read A+50 or H+14/H+38 of an unchanged pointer: a snapshot gap, not a write).
enum SlotRefusal : U { SlotMissing = 1, SlotHeaderChanged, SlotFrameBeyond, SlotRowChanged, SlotRecordChanged, SlotTurnChanged,
                       SlotUnprobed };
constexpr U kSlotDetailBase = 0xF1A20000u; // 66EE30 histogram detail: base + SlotRefusal
// The slot record proof below without its bookkeeping: SlotRefusal of a mismatch, 0 when the live values match.
U SlotMismatch(const SlotSnapshot& row, U record, U frame) {
    const U* v = row.values;
    bool chain = false, mismatch = true;
    const U id = D(record), anim = D(record + 4), header = D(record + 8);
    const U count = ChainVal(anim, v[1], v[3], 0x50, chain);
    U reason = SlotRecordChanged;
    if (id == v[0] && anim == v[1] && !chain && count == v[3]) {
        U turn = ChainVal(header, v[2], v[4], 0x14, chain);
        if (header && !chain) turn &= 0xFFFF;
        const U rows = ChainPtr(header, v[2], v[5], 0x38, chain);
        reason = SlotHeaderChanged;
        if (header == v[2] && !chain && rows == v[5]) {
            if (frame >= v[3]) mismatch = false;
            else if (frame == 0 && turn != v[4]) reason = SlotTurnChanged;
            else if (frame >= kSlotRows || !rows) reason = SlotFrameBeyond;
            else {
                const U expect = row.rowHashes[frame];
                if (expect == ~0u || HashBytes(rows + frame * 28 + 0xC, 16) != expect) reason = SlotRowChanged;
                else mismatch = false;
            }
        }
    }
    if (!mismatch) return 0;
    if ((reason == SlotRecordChanged && anim && anim == v[1] && v[3] == ~0u) ||
        (reason == SlotHeaderChanged && header && header == v[2] && (v[4] == ~0u || v[5] == ~0u)))
        reason = SlotUnprobed;
    return reason;
}
bool SlotStatic(U record, U frame, U* note, U* why = nullptr) {
    SlotSnapshot* row = g_witnessOpen && record ? FindSlot(record) : nullptr;
    if (!row) { if (note) *note |= NoteSlotMissing; if (why) *why = SlotMissing; return false; }
    WitnessMemo::Entry* const memo = MemoEntry(MemoSlot, record, frame);
    U memoValue;
    if (!MemoHit(memo, MemoSlot, record, frame, memoValue)) {
        if (const U reason = SlotMismatch(*row, record, frame)) {
            if (note) *note |= NoteSlotMismatch; if (why) *why = reason; return false;
        }
        MemoStore(memo, MemoSlot, record, frame, 1);
    }
    if (!row->used) row->used = 1;
    RecordDep(WitnessDepSlot, record, frame);
    // Atomic OR: several workers may consume different rows of one slot.
    if (frame < kSlotRows && !(row->usedRows[frame / 32] & (1u << (frame % 32))))
        InterlockedOr(reinterpret_cast<volatile LONG*>(&row->usedRows[frame / 32]), LONG(1u << (frame % 32)));
    return true;
}
// Pure: the army stat table base and the indexed entry (with entry+10) equal
// the snapshot. Dereferences only the Begin-probed army and entries.
bool ArmyStatic(U army, U index, U* note) {
    ArmySnapshot* row = g_witnessOpen && army ? FindArmy(army) : nullptr;
    U base = 0;
    WitnessMemo::Entry* const memo = row ? MemoEntry(MemoArmy, army, index) : nullptr;
    if (!MemoHit(memo, MemoArmy, army, index, base)) {
        bool mismatch = !row;
        if (row) {
            base = D(army + 0x218);
            if (base != row->base) mismatch = true;
            else if (base) {
                if (index >= kArmyEntries || row->entries[index] == ~0u) mismatch = true;
                else {
                    const U entry = D(base + 0xE4 + index * 4);
                    if (entry != row->entries[index]) mismatch = true;
                    else if (entry && (row->mults[index] == ~0u || D(entry + 0x10) != row->mults[index])) mismatch = true;
                }
            }
        }
        if (mismatch) { if (note) *note |= NoteArmyMismatch; return false; }
        MemoStore(memo, MemoArmy, army, index, base);
    }
    if (!row->used) row->used = 1;
    if (base && !(row->usedEntries & (1u << index)))
        InterlockedOr(reinterpret_cast<volatile LONG*>(&row->usedEntries), LONG(1u << index));
    RecordDep(WitnessDepArmy, army, index);
    return true;
}
void CountNote(U note) {
    if (note & NoteUnitOk) ++g_witness[WitnessUnitInactiveCalls];
    if (note & NoteUnitMismatch) ++g_witness[WitnessUnitMismatchCalls];
    if (note & NoteUnitMissing) ++g_witness[WitnessUnitMissingCalls];
    if (note & NoteBattleOk) ++g_witness[WitnessBattleInactiveCalls];
    if (note & NoteBattleMismatch) ++g_witness[WitnessBattleMismatchCalls];
    if (note & NoteManagerMissing) ++g_witness[WitnessManagerMissing];
    if (note & (NoteSlotMismatch | NoteSlotMissing)) ++g_witness[WitnessSlotMismatchCalls];
    if (note & NoteArmyMismatch) ++g_witness[WitnessArmyMismatchCalls];
}

// ---- (site, target) histograms ---------------------------------------------
constexpr U kSiteCapacity = 2048;
struct SiteCount { U site, target; ULONGLONG calls; };
struct SiteTable { SiteCount rows[kSiteCapacity]; U distinct; ULONGLONG overflow, counted; };
SiteTable g_unknownSites, g_firstSites;
U PreferredVA(U target) {
    return target >= V(0x400000) && target < V(0x400000) + 0x1600000 ? target - g_delta : target;
}
void CountSite(SiteTable& table, U site, U target) {
    ++table.counted;
    target = PreferredVA(target);
    U slot = ((site ^ (target * 0x9E3779B1u)) * 2654435761u) & (kSiteCapacity - 1);
    for (U probe = 0; probe != kSiteCapacity; ++probe, slot = (slot + 1) & (kSiteCapacity - 1)) {
        SiteCount& row = table.rows[slot];
        if (!row.calls) { row.site = site; row.target = target; ++table.distinct; }
        if (row.site == site && row.target == target) { ++row.calls; return; }
    }
    ++table.overflow;
}
void SiteTop(const SiteTable& table, U* words) {
    words[0] = 1; words[1] = table.distinct;
    words[2] = static_cast<U>(table.overflow); words[3] = static_cast<U>(table.counted);
    const SiteCount* top[kSiteTop] = {};
    U count = 0;
    for (const SiteCount& row : table.rows) {
        if (!row.calls) continue;
        U position = 0;
        while (position < count && (top[position]->calls > row.calls ||
               (top[position]->calls == row.calls && top[position]->site <= row.site))) ++position;
        if (position == kSiteTop) continue;
        if (count < kSiteTop) ++count;
        for (U j = count - 1; j > position; --j) top[j] = top[j - 1];
        top[position] = &row;
    }
    for (U i = 0; i < count; ++i) {
        words[4 + 3 * i] = top[i]->site; words[5 + 3 * i] = top[i]->target;
        words[6 + 3 * i] = static_cast<U>(top[i]->calls);
    }
}
void Result(Service service, Classification result, U target, U site, U histTarget = ~0u) {
    if (histTarget == ~0u) histTarget = target;
    U* row = Row(service);
    if (result == Active) {
        ++row[ActiveCalls]; ++g_words[ServiceActive]; ++g_activeSequence;
        if (g_entity && !g_firstActive) {
            g_firstActive = service + 1; ++row[FirstActiveOccurrences];
        }
    } else if (result == Unresolved) {
        ++row[UnknownCalls]; ++g_words[ServiceUnknown]; ++g_unknownSequence;
        g_words[LastUnknownTarget] = target;
        g_words[LastUnknownService] = service;
        if (service == Unknown) CountSite(g_unknownSites, site, histTarget);
        if (g_entity && !g_firstUnknown) {
            g_firstUnknown = service + 1; ++row[FirstUnknownOccurrences];
            CountSite(g_firstSites, site, histTarget);
        }
    } else { ++row[InactiveCalls]; ++g_words[ServiceInactive]; }
}
void ReadPose(U reader, U subject) {
    if (!reader || !subject) return;
    const U leader = D(reader + 0x5B8), target = D(reader + 0x1EC);
    g_words[LastPoseReader] = reader; g_words[LastPoseSubject] = subject;
    g_words[LastPoseLeader] = leader; g_words[LastPoseTarget] = target;
    if (!g_entity) return;
    U mask = 1;
    if (subject == reader) mask |= 16;
    else {
        if (subject == leader) mask |= 2;
        if (subject == target) mask |= 4;
        if (subject != leader && subject != target) mask |= 8;
    }
    const U added = mask & ~g_poseMask;
    g_poseMask |= mask;
    for (U bit = 0; bit != 5; ++bit)
        if (added & (1u << bit)) ++g_words[PoseReads + bit];
}

// Native entry -> census row. Unlisted actual targets use Unknown, retaining
// LastUnknownTarget. This table is NOT an admission allow-list: all are called.
Service Identify(U target, U site) {
    if (site == 0x63C4D3) return ChargeCallback;
    if (site == 0x658F16 || site == 0x658F39) return Engage;
    switch (target - g_delta) {
    case 0x62DFF0: return Effects; case 0x6666E0: return SlotAcquire;
    case 0x6718F0: return TargetAcquire; case 0x63C440: return ChargeCallback;
    case 0x658C50: return MoveDriver; case 0x64DE80: return FireDriver;
    case 0x6543D0: return Finalize; case 0x659600: return FireSequence;
    case 0x7FD070: return PathRequest; case 0x659480: case 0x66AD00: return RequestBuild;
    case 0x659520: return RequestCommit; case 0x6631A0: case 0x662E70: return Order;
    case 0x63CDD0: return NodeFinish;
    case 0x6666B0: case 0x816900: case 0x665E60: case 0x665E30:
    case 0x816080: case 0x815FF0: case 0x7FF9E0: case 0x80A190: case 0x7FF5C0: case 0x809D80: return NodeBegin;
    case 0x66E670: case 0x819310: case 0x66DD10: case 0x66DCF0:
    case 0x818500: case 0x818330: return NodeStep;
    case 0x624F80: case 0x7EDD00: case 0x624EF0: case 0x5AC9D0: case 0x7EDF70: case 0x7EDE80: return NodeDestroy;
    case 0x670F40: return Animation; case 0x67A050: return Parked;
    case 0x5CB830: return WrapperEffect; case 0x5B7B20: return WrapperService;
    case 0x5E4B20: return PosePosition; case 0x5E4AF0: return PoseHeading;
    case 0x6758D0: return ReferenceStep; case 0x655B20: return Arrival;
    case 0x643C90: return Unlink; case 0x7E1ED0: return Engage;
    case 0x5FC070: return Random; case 0x61DA90: return ReferenceConstruct;
    case 0x66E780: return Watcher;
    case 0x811870: case 0x805880: case 0x8058C0: case 0x805900: return HolderQuery;
    case 0x7FF390: case 0x807490: return HolderQuery;
    case 0x602E00: return Timer; case 0x53EEE0: case 0x55C2E0: return UnitWitness;
    case 0xE5F760: return AnimationLookup; case 0x10F1160: return ColdLookup;
    case 0xE202F0: case 0xE31490: return ColdLookup;
    case 0x5B77A0: return Idle; case 0x66C160: return PreBattle; case 0x679300: return Exit;
    case 0x80E9D0: return Projection; case 0x6C4FE0: return Crew;
    case 0x7EAE90: case 0x7E2040: case 0x6460E0: return Descriptor;
    case 0x610470: return Wrapper610470; case 0x60CAC0: return Wrapper60CAC0;
    case 0x5E52F0: return Wrapper5E52F0; case 0x607540: return Wrapper607540;
    case 0x5B9720: return Wrapper5B9720;
    case 0x63C4F0: case 0x62E910: return FireCandidates;
    case 0x8021E0: return FireSubmit; case 0x80BF70: return FireGather;
    case 0x5AA400: return NodeDestroy;
    case 0x658BA0: case 0x66BF80: case 0x487E20: case 0x6F3C00: return TargetAcquire;
    default: break;
    }
    // Gate site metadata is the call-instruction VA: driver `call esi` 64DED4
    // (slot +110 loaded at 64DEB7) and `call [eax+130]` 64DFA7 in the image.
    if (site == 0x658DD7 || site == 0x658E69 || site == 0x658FF3 ||
        site == 0x659090 || site == 0x64DFA7 || site == 0x64DED4) return VirtualOrder;
    if (Stub(target) || target == V(0x5DB820)) return VirtualQuery;
    return Unknown;
}
U CloneIdForVA(U originalVA) {
    U id;
    switch (originalVA) {
    case 0x66CE00: case 0x6F50F0: id = NTW2_CLONE_BRAIN_W; break;
    case 0x63C440: id = NTW2_CLONE_BRAIN_W_TRIGGER; break;
    case 0x658C50: id = NTW2_CLONE_BRAIN_W_MOVEORDER; break;
    case 0x64DE80: id = NTW2_CLONE_BRAIN_W_DRIVER; break;
    case 0x66E780: id = NTW2_CLONE_BRAIN_W_WATCHER; break;
    case 0x6543D0: id = NTW2_CLONE_BRAIN_W_FINALIZE; break;
    case 0x659600: id = NTW2_CLONE_BRAIN_W_FIRE; break;
    case 0x6758D0: id = NTW2_CLONE_BRAIN_W_REFERENCE; break;
    case 0x6666B0: id = NTW2_CLONE_BRAIN_W_BEGIN; break;
    case 0x66E670: id = NTW2_CLONE_BRAIN_W_STEP; break;
    case 0x670EB0: id = NTW2_CLONE_BRAIN_W_COMMON_STEP; break;
    case 0x66C160: id = NTW2_CLONE_BRAIN_W_HOLDER_STEP; break;
    case 0x7E2C80: id = NTW2_CLONE_BRAIN_W_HOT_CTOR; break;
    case 0x816900: id = NTW2_CLONE_BRAIN_W_HOT_BEGIN; break;
    case 0x819310: id = NTW2_CLONE_BRAIN_W_HOT_STEP; break;
    case 0x7EDD00: id = NTW2_CLONE_BRAIN_W_HOT_DTOR; break;
    case 0x650DC0: id = NTW2_CLONE_BRAIN_W_HOT_INSTALL; break;
    case 0x61D910: id = NTW2_CLONE_BRAIN_W_IDLE_CTOR; break;
    case 0x665E60: id = NTW2_CLONE_BRAIN_W_IDLE_BEGIN; break;
    case 0x66DD10: id = NTW2_CLONE_BRAIN_W_IDLE_STEP; break;
    case 0x624EF0: id = NTW2_CLONE_BRAIN_W_IDLE_DTOR; break;
    case 0x650650: id = NTW2_CLONE_BRAIN_W_IDLE_INSTALL; break;
    case 0x61D8F0: id = NTW2_CLONE_BRAIN_W_WAIT_CTOR; break;
    case 0x665E30: id = NTW2_CLONE_BRAIN_W_WAIT_BEGIN; break;
    case 0x66DCF0: id = NTW2_CLONE_BRAIN_W_WAIT_STEP; break;
    case 0x5AC9D0: id = NTW2_CLONE_BRAIN_W_WAIT_DTOR; break;
    case 0x650600: id = NTW2_CLONE_BRAIN_W_WAIT_INSTALL; break;
    case 0x6669B0: id = NTW2_CLONE_BRAIN_W_STOP; break;
    case 0x816080: id = NTW2_CLONE_BRAIN_ACTION_BEGIN; break;
    case 0x818500: id = NTW2_CLONE_BRAIN_ACTION_STEP; break;
    case 0x818330: id = NTW2_CLONE_BRAIN_ACTION_RELATED_STEP; break;
    case 0x815FF0: id = NTW2_CLONE_BRAIN_ACTION_RELATED_BEGIN; break;
    case 0x444B60: id = NTW2_CLONE_BRAIN_ACTION_EMPTY; break;
    case 0x659520: id = NTW2_CLONE_BRAIN_W_REQUEST; break;
    case 0x63C4F0: id = NTW2_CLONE_BRAIN_W_CANDIDATES; break;
    case 0x62E910: id = NTW2_CLONE_BRAIN_W_CANDIDATE_BODY; break;
    case 0x80BF70: id = NTW2_CLONE_BRAIN_W_GATHER; break;
    case 0x6718F0: id = NTW2_CLONE_BRAIN_W_TARGET; break;
    case 0x5B7B20: id = NTW2_CLONE_BRAIN_W_WRAPPER_SERVICE; break;
    case 0x63CDD0: id = NTW2_CLONE_BRAIN_W_FINISH; break;
    case 0x5AA400: id = NTW2_CLONE_BRAIN_W_RECYCLE; break;
    case 0x658BA0: id = NTW2_CLONE_BRAIN_W_BACKLINK; break;
    case 0x66BF80: id = NTW2_CLONE_BRAIN_W_BACKUNLINK; break;
    case 0x602E00: id = NTW2_CLONE_BRAIN_W_TIMER; break;
    case 0x670F40: id = NTW2_CLONE_BRAIN_W_ANIMATION; break;
    case 0x6666E0: id = NTW2_CLONE_BRAIN_W_SLOT; break;
    case 0x6595A0: id = NTW2_CLONE_BRAIN_W_RESET_REQUEST; break;
    case 0x67A050: id = NTW2_CLONE_BRAIN_W_PARKED; break;
    case 0x6631A0: id = NTW2_CLONE_BRAIN_W_ORDER; break;
    case 0x662E70: id = NTW2_CLONE_BRAIN_W_NODE_ORDER; break;
    case 0x655B20: id = NTW2_CLONE_BRAIN_W_ARRIVAL; break;
    case 0x643C90: id = NTW2_CLONE_BRAIN_W_UNLINK; break;
    case 0x7FF9E0: id = NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF9E0; break;
    case 0x80A190: id = NTW2_CLONE_BRAIN_W_NODE_DISPATCH_80A190; break;
    case 0x7FF5C0: id = NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF5C0; break;
    case 0x809D80: id = NTW2_CLONE_BRAIN_W_NODE_DISPATCH_809D80; break;
    default: return ~0u;
    }
    return id;
}
U CloneFor(U target) {
    if (!g_clones) return 0;
    const U id = CloneIdForVA(target - g_delta);
    return id == ~0u ? 0 : g_clones[id];
}
// Exact SSE sequence of 62DFF0 through 62E093. Passing the final threshold
// reaches process-global staging 7FC120 at 62E0C5 before any later service gate.
bool EffectsActive(U a) {
    const __m128 scale = _mm_load_ss(F(a + 0x6C));
    const __m128 x = _mm_mul_ss(_mm_load_ss(F(a + 0xC8)), scale);
    const __m128 z = _mm_mul_ss(_mm_load_ss(F(a + 0xCC)), scale);
    const __m128 speed = _mm_add_ss(_mm_mul_ss(x, x), _mm_mul_ss(z, z));
    return _mm_comigt_ss(speed, _mm_setzero_ps()) &&
           _mm_comigt_ss(speed, _mm_load_ss(F(V(0x1325D20))));
}
// Actual method a holder dispatcher would tail-call: N = H+8, slot of N.vt.
U HolderMethod(U holder, U slot) { const U table = D(holder + 8); return table ? D(table + slot) : 0; }
bool SiteForced(U site) { return site == 0x658F39 || site == 0x658BD3 || site == 0x66BF95; }
// 7FF9E0/7FF5C0 (node vt+4) and 80A190/809D80: node N (receiver; 7FF9E0 copies N+20..+49 to its stack), holder
// H = [N+8], X = [H] must be the occurrence soldier and N, H parts of it. The installer reached through X.vt is gated.
bool NodeInstallOwn(U node, U entity) {
    if (!OwnPart(node, entity) || !OwnPart(node + 0x49, entity)) return false;
    const U holder = D(node + 8);
    return OwnPart(holder, entity) && OwnPart(holder + 3, entity) && D(holder) == entity;
}
// ---- Foreign read-set hashes (GateClassify3; native_brain2.h WitnessDepKind) --------------------------
// Every pointer is dereferenced only where the native code itself dereferences it on the same path.
inline void MixWord(U& h, U value) { for (U i = 0; i < 4; ++i) { h ^= (value >> (8 * i)) & 0xFF; h *= 16777619u; } }
// A vtable pointer inside the image's .rdata (soldier/member tables live there); never chase anything else.
bool InRdata(U p) { return g_bound && p >= V(0x1307000) && p + 4 <= V(0x1307000) + 0x146236; }
// The 66D2F3 reacquire block's reads of target T after T.vt+F0 returned 1: T+628, T+66C, T+670 and its first
// member [T+670][0] (only when T+628 != 0, T+66C != 0 and the array is non-null, as 66D31D..66D339), then
// T+630/+634/+638. Hashing all of T+630..+638 regardless of the short-circuit is a superset (more refusals only).
U TargetHash(U target) {
    U h = 2166136261u;
    MixWord(h, target);
    const U active = D(target + 0x628), count = D(target + 0x66C), members = D(target + 0x670);
    MixWord(h, active); MixWord(h, count); MixWord(h, members);
    if (active && count && members) MixWord(h, D(members));
    MixWord(h, D(target + 0x630)); MixWord(h, D(target + 0x634)); MixWord(h, D(target + 0x638));
    return h;
}
// 6A7DD0's member array (A+670, A+66C entries): each member pointer and its vtable pointer.
constexpr U kCrewMax = 16;
U CrewHash(U members, U count) {
    U h = 2166136261u;
    MixWord(h, members); MixWord(h, count);
    for (U i = 0; i < count && i < kCrewMax; ++i) {
        const U member = D(members + 4 * i);
        MixWord(h, member);
        if (member) MixWord(h, D(member));
    }
    return h;
}
// Read-set hashes through the bound witness memo (MemoEntry decides which kinds a table may keep).
template <class Compute> bool MemoHash(U kind, U key, U aux, U& hash, Compute compute) {
    WitnessMemo::Entry* const memo = MemoEntry(kind, key, aux);
    if (MemoHit(memo, kind, key, aux, hash)) return true;
    if (!compute(hash)) return false;
    MemoStore(memo, kind, key, aux, hash);
    return true;
}
bool TerrainHashMemo(U root, U& hash) {
    return MemoHash(MemoTerrain, root, 0, hash, [&](U& h) { return ntw2_finalizer::TerrainHash(root, h); });
}
bool AnimHashMemo(U set, U key, U& hash) {
    return MemoHash(MemoAnim, set, key, hash, [&](U& h) { return ntw2_finalizer::AnimHash(set, key, h); });
}
U FrameHashMemo(U frame, bool transform) {
    U hash = 0;
    MemoHash(transform ? MemoTransform : MemoFrame, frame, 0, hash, [&](U& h) {
        h = transform ? ntw2_finalizer::TransformHash(frame) : ntw2_finalizer::FrameHash(frame); return true; });
    return hash;
}
U TargetHashMemo(U target) {
    U hash = 0;
    MemoHash(MemoTarget, target, 0, hash, [&](U& h) { h = TargetHash(target); return true; });
    return hash;
}
U CrewHashMemo(U members, U count) {
    U hash = 0;
    MemoHash(MemoCrew, members, count, hash, [&](U& h) { h = CrewHash(members, count); return true; });
    return hash;
}
// Stub vt+F0 / crew vt+A8 targets that leave EAX (and so AL) exactly zero.
bool ReturnsZero(U method) { return method == V(0x461180); }
bool ReturnsZeroAl(U method) { return method == V(0x461180) || method == V(0x462CB0); }
// Recovered own-field/pure leaves (not an unknown vtable) and 63AF40 (659AE6: cdecl float arithmetic on its five
// stack arguments; no store, no other read): Inactive for every receiver, argument and entity.
bool StaticInactiveLeaf(U va) {
    switch (va) {
    case 0x7EE750: case 0x7FD9E0: case 0x66B080: case 0x663730:
    case 0x662E40: case 0x639200: case 0x6E9DA0:
    case 0x5DB820: case 0x586430:
    case 0x7FF390: case 0x671230: case 0x5B7F20: case 0x5B6B30:
    case 0x5B6B40: case 0x5B7010: case 0x63AF40:
        return true;
    default: return false;
    }
}
// Pure (no global writes): `entity` is the occurrence soldier as addressed by
// the running code; `note` (optional) receives witness outcomes for counters.
Classification ClassifyTarget(Service service, U receiver, U target, U site, const U* args, U entity, U* note, U* detail) {
    if (detail) *detail = target;
    if (Stub(target) || PureLeaf(target)) return Inactive;
    // This constructor always draws model RNG. The recycler itself may merely
    // return its inline slot; the actual foreign phase store is observed later.
    if (site == 0x658F39) return Active;
    if (site == 0x658BD3 || site == 0x66BF95) return Active; // foreign backlink +24 store
    if (StaticInactiveLeaf(target - g_delta)) return Inactive;
    const bool own = receiver && receiver == entity;
    U values[kUnitFields];
    switch (target - g_delta) {
    // Battle-manager predicates (M = [[A+28]+8]+B0): 55AC60 tests M+14 in
    // {2,3,4,5}, 55AD60 tests M+14 in {0,1}; store-free, dispatch-witnessed.
    case 0x55AC60: case 0x55AD60:
        return BattleStatic(receiver, note) ? Inactive : Unresolved;
    // Animation state predicates 5DBB30/5DBD60: S = M+198, 5B9510 returns
    // [[S+10]+8*[S+24]], tested at +10 (==0 / ==1). Store-free, witnessed.
    case 0x5DBB30: case 0x5DBD60:
        return g_witnessOpen && g_battleValid && receiver == g_battleValues[1] &&
               BattleStatic(g_battleManager, note) ? Inactive : Unresolved;
    // Own-soldier leaves. 62DF10: `cmp [ecx+444],0; sete al`. 66EE30 with a
    // null slot (A+444) only stores own A+444=0 (66EEA0). 63B3E0: A+1EC nonzero
    // returns 0, else the +EC/+F0/+E8 queries. 66AE10: null unit or nonzero
    // first argument returns that argument (66AE4A). 6A7DD0 (crew +A8): an
    // empty A+66C/+670 member list returns 0. 646C20 (cdecl) reads only
    // arg+117/+194 and the .rdata constant 1318034.
    case 0x62DF10: return own ? Inactive : Unresolved;
    case 0x66EE30: {
        // Slot-follow: null A+444 stores only own A+444=0. Otherwise 66EE30 and
        // 66EEB0 read S=A+444, anim S[4]+50, header S[8]+14/+38 and the 28-byte
        // rows (witnessed), write only own fields, and the 5D/5E arm calls the
        // soldier's vt+CC (660020: own A+368 update) on every known soldier table.
        if (!own) return Unresolved;
        const U record = D(receiver + 0x444);
        if (!record) return Inactive;
        const U callback = D(D(receiver) + 0xCC);
        if (detail) *detail = callback;
        if (callback != V(0x660020)) return Unresolved;
        // Histogram key for a refused live slot: kSlotDetailBase + SlotRefusal (missing / header / frame / row).
        U why = 0;
        if (SlotStatic(record, D(receiver + 0x1C0), note, &why)) return Inactive;
        if (detail) *detail = kSlotDetailBase + why;
        return Unresolved;
    }
    case 0x63B3E0: {
        if (!own) return Unresolved;
        if (D(receiver + 0x1EC)) return Inactive;
        const U table = D(receiver);
        return OwnQuery(D(table + 0xEC)) && OwnQuery(D(table + 0xF0)) && OwnQuery(D(table + 0xE8)) ?
               Inactive : Unresolved;
    }
    case 0x66AE10: return own && (!D(receiver + 0x1F0) || args[0]) ? Inactive : Unresolved;
    case 0x6A7DD0: {
        // Member list A+66C (count) / A+670 (array): every member's vt+A8 must be 461180 (`xor eax,eax`), so
        // the loop calls each once and returns 0. The array and the member vtables are foreign: Crew dependency.
        if (!own) return Unresolved;
        const U count = D(receiver + 0x66C);
        if (!count) return Inactive;
        const U members = D(receiver + 0x670);
        if (!members || count > kCrewMax) { if (detail) *detail = 0; return Unresolved; }
        for (U i = 0; i < count; ++i) {
            const U member = D(members + 4 * i);
            const U table = member ? D(member) : 0;
            const U method = InRdata(table + 0xA8) ? D(table + 0xA8) : 0;
            if (!ReturnsZero(method)) { if (detail) *detail = method; return Unresolved; }
        }
        if (!g_witnessOpen) return Unresolved;
        if (!OwnPart(members, entity)) RecordDep(WitnessDepCrew, members, CrewHashMemo(members, count), count);
        return Inactive;
    }
    case 0x646C20: return entity && args[0] == entity ? Inactive : Unresolved;
    // 64F8F0: null A+1F0 returns 0; else tail 55B0A0(U): U+DA4==1 returns 1,
    // otherwise 55AD60([[U+14]+8]+B0), U+DA8 vs .rdata 1325D24, U+D9E.
    case 0x64F8F0: {
        if (!own) return Unresolved;
        const U unit = D(receiver + 0x1F0);
        if (!unit) return Inactive;
        if (!UnitStatic(unit, values, note)) return Unresolved;
        return (values[12] & 0xFF) == 1 || BattleStatic(values[15], note) ? Inactive : Unresolved;
    }
    // Unit predicates (receiver U). 53EEE0 with U+930==0 skips the Q.vt+34
    // dispatch: 55C480 -> 55C440 reads U+AA0, then (AA0 not 0/2) [[U+C00]+8]+B0
    // +2704, U+C2C, U+2CC (55AB80); then U+AA0 again. 55C2E0 on X=[U+ADC]
    // with X+460==0 returns 0 without dispatch. 55AB90/55ABF0/55C1C0/55C2A0 read
    // [U+2C]+1C and [U+1F4]+10; they avoid the 55C9A0 ability helper exactly when
    // type!=3 (55ABF0), type==2 or type==1 with empty [U+1F4]+10 (55C1C0), and
    // type not in {0,3,5} (55C2A0). All direct bodies are store-free.
    case 0x53EEE0: {
        const bool match = UnitStatic(receiver, values, note);
        if (match && !values[0]) return Inactive;
        if (!match) return Unresolved;
        // U+930 != 0: Q.vt+34 (Q = U+398 + U+934*90; U+934 and Q.vt are unit fields 26/27). A register-only leaf
        // writes nothing; AL=1 returns 1 at once, AL=0 continues into the 55C480 path the U+930==0 proof covers.
        const U table = values[27];
        const U method = table != ~0u && InRdata(table + 0x34) ? D(table + 0x34) : 0;
        if (detail) *detail = method; // histogram key: the dispatched Q.vt+34 method
        return method && (Stub(method) || PureLeaf(method)) ? Inactive : Unresolved;
    }
    case 0x55C2E0: {
        const U unit = entity ? D(entity + 0x1F0) : 0;
        const bool match = unit && UnitStatic(unit, values, note) && receiver == values[6];
        if (match && !values[7]) return Inactive;
        if (match && detail) {
            const U entry = D(receiver + values[7] * 8 + 0x418);
            *detail = entry ? D(D(entry) + 0xC) : 0;
        }
        return Unresolved;
    }
    case 0x55AB90: case 0x55ABF0: case 0x55C1C0: case 0x55C2A0: case 0x55C4B0:
        // 55C9A0(U+DAC,0F) is also closed: 57ACA0 scans min(count,16) 0x2C-byte
        // entries for the key (57AC90 reads [entry+4][0]) and 557450 returns
        // [entry+28]; all store-free. The unit witness hashes those entries and
        // records [U+DB8]/[U+DBC], so every branch, not only the early-outs, is
        // classified. 55C4B0 additionally reads U+16C (field 21).
        return UnitStatic(receiver, values, note) ? Inactive : Unresolved;
    // Holder dispatchers. The disabled (H+8F!=1) and done (805880: H+18!=0)
    // early-outs keep the existing holder-byte acceptance; resolving the actual
    // N.vt method (N = H+8) additionally requires a holder embedded in this
    // soldier (every site-6 caller passes A+2CC) and a register-only leaf. Every
    // node table (01334180, 01348B44, 0133405C, 01334028, 01347270, 01348D2C,
    // 01348CC4, 013336B0) holds 461180/462CB0 in slots +0C/+14/+24/+28. Of the 74
    // tables installed after the node base constructors 61D3B0/7E3A50, one holds a
    // memory-reading +14: 13472A4 (begin 7FF680) has 55C3E0 `mov al,[ecx+48]; ret`,
    // a read of node N+48 = H+50, inside the soldier when H is.
    case 0x811870: case 0x805880: case 0x8058C0: case 0x805900: {
        if (B(receiver + 0x8F) != 1) return Inactive;
        const U va = target - g_delta;
        if (va == 0x805880 && B(receiver + 0x18)) return Inactive;
        if (!OwnPart(receiver, entity)) return Unresolved;
        const U slot = va == 0x811870 ? 0xC : va == 0x805880 ? 0x14 : va == 0x8058C0 ? 0x28 : 0x24;
        const U method = HolderMethod(receiver, slot);
        if (detail) *detail = method;
        return PureLeaf(method) || (method == V(0x55C3E0) && OwnPart(receiver + 0x50, entity)) ? Inactive : Unresolved;
    }
    // 80B080 (parked 67A4E0, `ret 8`): R+18 != 0 returns at once; else reads [arg0]/[arg0+4] (caller-stack vector),
    // own R+48/+50/+64 and the word arg1, and stores only own R+D4/+D8/+DC/+E0/+148 and byte R+18C. No call.
    case 0x80B080:
        return own && (D(receiver + 0x18) || StackLocal(args[0], 8, args) ||
                       (OwnPart(args[0], entity) && OwnPart(args[0] + 7, entity))) ? Inactive : Unresolved;
    // Caller-stack descriptor helpers. 7E2040 repacks [arg0] (reads +0..+3B)
    // into ECX (writes +0..+37). 6460E0 always stores request+29; a zero
    // request+26 or null soldier(arg0)+1F0 returns before 57E230. 659480 with
    // A+B4==1 copies own A+4F8..+50B to arg0. 66AD00 copies arg1 to arg0 and
    // returns on a null A+1F0. 7EAE90 stores the zero-initialised BSS default
    // 150FCA8..150FCB3 (no image writer: only read-only escapes 7EB5C0/7EAD50/
    // 7E4190/808EB0) into ECX+0..+13.
    case 0x7E2040:
        return StackLocal(receiver, 0x38, args) && StackLocal(args[0], 0x3C, args) ? Inactive : Unresolved;
    case 0x6460E0:
        return StackLocal(receiver, 0x2A, args) &&
               (!B(receiver + 0x26) || (entity && args[0] == entity && !D(entity + 0x1F0))) ? Inactive : Unresolved;
    case 0x659480:
        return own && B(receiver + 0xB4) == 1 && StackLocal(args[0], 0x14, args) ? Inactive : Unresolved;
    case 0x66AD00:
        return own && !D(receiver + 0x1F0) && StackLocal(args[0], 0x14, args) &&
               (args[1] == receiver + 0x5FC || StackLocal(args[1], 0x14, args)) ? Inactive : Unresolved;
    case 0x7EAE90:
        return StackLocal(receiver, 0x14, args) ? Inactive : Unresolved;
    // Node construction on holders embedded in this soldier. 61DA90 (this =
    // node A+22C, arg0 = holder A+228, arg1 = stack slot cell) writes only the
    // node (+0..+36) through 61D3B0 / 7EAE90, holder+9C, and reads arg1[0] and
    // the CRT-initialised static heading 14D05B0. 61D3B0 itself writes node
    // +0..+18 and holder+9C. 662E50 stores owner+220 through node+4.
    case 0x61DA90:
        return OwnPart(receiver, entity) && OwnPart(args[0], entity) && StackLocal(args[1], 4, args) ?
               Inactive : Unresolved;
    case 0x61D3B0:
        return OwnPart(receiver, entity) && OwnPart(args[0], entity) ? Inactive : Unresolved;
    case 0x662E50:
        return OwnPart(receiver, entity) && D(receiver + 4) == entity ? Inactive : Unresolved;
    // Watcher-node destructors (vt+0 of 13493B8 / 1349054, reached at 650DE4/650624 with `push 1`): 7EDF70 calls
    // 5226E0 (`mov [ecx],1321210`), 7EDE80 stores [ecx]=1321210 itself; both free (444B60) only when (arg0&5)==5.
    case 0x7EDF70: case 0x7EDE80:
        return OwnPart(receiver, entity) && OwnPart(receiver + 3, entity) && (args[0] & 5) != 5 ? Inactive : Unresolved;
    case 0x80E020: return Active;
    case 0x6649C0:
        return D(receiver + 4) ? Unresolved : Inactive; // optional foreign pointer
    case 0x646BB0:
        return D(receiver + 0x5B4) ? Unresolved : Inactive;
    case 0x649520: {
        // Store-free stat getter. Unit branch: [D+C70*4+E4], D=[U+2C] (unit witness
        // fields 8/19/20, caller's entry+10 is field 25). Army branch (null unit):
        // [[A+1F8]+218 + A+374*4 + E4]; A+374 is an own field (see ArmySnapshot),
        // the table base/entry/entry+10 are army-witnessed. Null table returns 0.
        const U unit = D(receiver + 0x1F0), army = D(receiver + 0x1F8);
        if (!unit && !army) return Inactive;
        if (!own) return Unresolved;
        if (unit) return UnitStatic(unit, values, note) ? Inactive : Unresolved;
        return ArmyStatic(army, D(receiver + 0x374), note) ? Inactive : Unresolved;
    }
    // 8196B0 (watcher step): if X=node+C has X+9C==1, copies X+0C into own+10.
    // Both objects are embedded in the occurrence soldier for these node classes.
    // 8196D0 (sibling step, jmp 805710 -> 8056D0(X+4)) reads X+0C/X+1C and
    // writes only own+10/+1C; same ownership rule.
    case 0x8196B0: case 0x8196D0: case 0x805710:
        return OwnPart(receiver, entity) && OwnPart(D(receiver + 0xC), entity) ? Inactive : Unresolved;
    // 8120F0 (request reset): with no previous shared request (R+8==0), no new
    // request (arg0==0) and an empty member list (R+28+R+34==0), 811970 makes no
    // 6E8810 member calls and only trims own counters. Any release/list work is
    // a shared mutation and stays unresolved.
    case 0x8120F0:
        return OwnPart(receiver, entity) && !D(receiver + 8) && !args[0] &&
               D(receiver + 0x28) + D(receiver + 0x34) == 0 ? Inactive : Unresolved;
    // Nonempty lists compare member+88 labels: a cross-soldier read whose field
    // is written in site 6 by each member's own brain (66D5D9), never static.
    case 0x807490:
        return D(receiver + 0x28) + D(receiver + 0x34) == 0 ? Inactive : Unresolved;
    // 819770 active arm: own-soldier stores only when the structural closure holds (native_finalizer.h); the
    // foreign descriptor frame and the world read set are recorded as hash dependencies. An own-part frame lies
    // in the guarded soldier footprint and needs none. A posture state other than null/rest may reach the
    // animation selection 66B7E0/66B990: its animation-set read set is the Anim dependency.
    case 0x819770: {
        if (B(receiver + 0x18C) == 1) return Inactive;
        if (!own || !g_witnessOpen) return Unresolved;
        U why = 0, hash = 0, animHash = 0;
        if (ntw2_finalizer::FinalizeClosure(receiver, &why)) { if (detail) *detail = why; return Unresolved; }
        const U root = D(receiver + 0x28), frame = D(receiver + 0x170);
        if (!TerrainHashMemo(root, hash)) {
            if (detail) *detail = ntw2_finalizer::kDetailBase + ntw2_finalizer::World; return Unresolved;
        }
        const bool animates = ntw2_finalizer::PostureAnimates(receiver);
        const U set = D(receiver + 0x218), index = ntw2_finalizer::AnimKey(receiver);
        if (animates && (OwnPart(set, entity) || !AnimHashMemo(set, index, animHash))) {
            if (detail) *detail = ntw2_finalizer::kDetailBase + ntw2_finalizer::Animation; return Unresolved;
        }
        if (frame && !OwnPart(frame, entity)) RecordDep(WitnessDepFrame, frame, FrameHashMemo(frame, false));
        RecordDep(WitnessDepTerrain, root, hash);
        if (animates) RecordDep(WitnessDepAnim, set, animHash, index);
        return Inactive;
    }
    // ---- Sequencer 659600 commit tail (659A80..659B1F) -------------------------------------------------
    // 80E9D0 (descriptor materialisation): frame F = desc+10; null copies desc+0..+B to [arg0], else 7F4950
    // writes the affine transform of desc+0..+B by F+80..+8B / F+9C..+BF to [arg0]. Its only store is the
    // 12-byte [arg0]. Accepted for an own-part or caller-stack descriptor and output; a foreign F is a Frame
    // dependency with aux 1 (TransformHash: exactly 7F4950's reads), an own-part F lies in the guarded footprint.
    case 0x80E9D0: {
        const bool descOwn = (OwnPart(receiver, entity) && OwnPart(receiver + 0x13, entity)) || StackLocal(receiver, 0x14, args);
        const U out = args[0];
        const bool outOwn = (OwnPart(out, entity) && OwnPart(out + 0xB, entity)) || StackLocal(out, 0xC, args);
        if (!descOwn || !outOwn) return Unresolved;
        const U frame = D(receiver + 0x10);
        if (!frame || (OwnPart(frame, entity) && OwnPart(frame + 0xBF, entity))) return Inactive;
        if (!g_witnessOpen) return Unresolved;
        RecordDep(WitnessDepFrame, frame, FrameHashMemo(frame, true), 1);
        return Inactive;
    }
    // 63F040 (659ACF): `fld [[R+1E8]+20]; fmul [1335A24]`, store-free. A foreign parameter block is a Word
    // dependency on that one dword; a null block would fault natively and is refused.
    case 0x63F040: {
        if (!own) return Unresolved;
        const U block = D(receiver + 0x1E8);
        if (!block) return Unresolved;
        if (OwnPart(block, entity) && OwnPart(block + 0x23, entity)) return Inactive;
        if (!g_witnessOpen) return Unresolved;
        RecordDep(WitnessDepWord, block + 0x20, D(block + 0x20));
        return Inactive;
    }
    // 80B6E0 (659B1F, commit): stores own R+108..+188, R+13C, R+1A8 and the R+160..+170 descriptor copy from
    // [arg0] (compared by 7ED1D0), then 10F6820/10F5C60 (posture exit + state-0 enter, native_finalizer.h) and
    // 7F7380(flags). With R+18 != 0 and no arg2 bit 0x8000 the 816F10 arm runs the same tail with flags 0.
    // 7F7380 unlinks R from the list [R+178] (811C60 writes both neighbours and the list head) unless flags
    // bit 4 is set or R+178 is null: that is the shared store, so it is the refusal.
    case 0x80B6E0: {
        if (!own) return Unresolved;
        const U desc = args[0], flags = args[2];
        if (!((OwnPart(desc, entity) && OwnPart(desc + 0x13, entity)) || StackLocal(desc, 0x14, args))) return Unresolved;
        const bool reset = D(receiver + 0x18) && !(flags & 0x8000);
        const bool unlinks = D(receiver + 0x178) && (reset || !(flags & 4));
        if (unlinks) { if (detail) *detail = V(0x811C60); return Unresolved; }
        U why = 0;
        if (ntw2_finalizer::PostureClosure(receiver, &why)) { if (detail) *detail = why; return Unresolved; }
        return Inactive;
    }
    // 7F14C0 (fire candidates, 62E946): store-free terrain lookahead on the own soldier's +48/+50/+64; the
    // model bounds and grid header are the Terrain dependency (cells: native_finalizer.h world claim).
    case 0x7F14C0: {
        if (!own || !g_witnessOpen) return Unresolved;
        const U root = D(receiver + 0x28);
        U hash = 0;
        if (!TerrainHashMemo(root, hash)) return Unresolved;
        RecordDep(WitnessDepTerrain, root, hash);
        return Inactive;
    }
    case 0xE202F0:
        return D(receiver + 0x6C0) ? Inactive : Active;
    case 0xE31490:
        return D(receiver + 0x2C0) ? Inactive : Active;
    case 0x5CB830: {
        // The real callee takes a vector, not the outer wrapper's record/state
        // guards. Nonzero length guarantees the shared 14514CC reset at 5CBB17.
        const __m128 x = _mm_load_ss(F(args[0])), z = _mm_load_ss(F(args[0] + 8));
        const __m128 length = _mm_add_ss(_mm_mul_ss(z, z), _mm_mul_ss(x, x));
        return _mm_comigt_ss(length, _mm_setzero_ps()) ? Active : Inactive;
    }
    case 0x487E20: case 0x6F3C00:
        return Unresolved; // not the canonical TargetAcquire receiver
    default: return ClassifyService(service, receiver);
    }
}
void ServiceExit();

// Stack at entry: [source site, actual target, native return address, args...].
// Saved registers use PUSHAD layout: EDI,ESI,EBP,ESP,EBX,EDX,ECX,EAX,EFLAGS.
void __stdcall EnterService(U* stack, const U* registers) {
    if (!g_censusEnabled) return;
    const U site = stack[0], target = stack[1], receiver = registers[6];
    const U clone = CloneFor(target);
    // Transparent core/thunk and candidate wrapper do not inflate the called
    // service's census. Their actual descendants already have dedicated gates.
    if (clone && (target == V(0x66CE00) || target == V(0x6F50F0) || target == V(0x63C4F0))) {
        stack[1] = clone; return;
    }
    const Service service = Identify(target, site);
    const U originalVA = target - g_delta;
    if (originalVA == 0x658C50) {
        ++g_route[DriverCalls];
        g_route[LastDriverClone] = clone ? NTW2_CLONE_BRAIN_W_MOVEORDER + 1u : 0;
    }
    if (originalVA == 0x61DA90) ++g_route[ReferenceCtors];
    // Count reached virtual slots independently of their concrete class. Generic
    // descriptor materialization (80E9D0) is not a reference-node occurrence.
    if (site == 0x658F70 || site == 0x64DF02 || site == 0x670F10 || site == 0x66C17D) {
        ++g_route[VirtualBegins]; g_route[LastNodeTarget] = originalVA;
        CountNodeTarget(originalVA, true);
    }
    if (site == 0x658F81 || site == 0x64DF13 || site == 0x670F21 || site == 0x66C18E) {
        ++g_route[VirtualSteps]; g_route[LastNodeTarget] = originalVA;
        CountNodeTarget(originalVA, false);
    }
    if (g_nodeShadow) ntw2_move_node::Observe(originalVA, receiver, stack + 3);
    if (g_nodeShadow) {
        ntw2_idle_node::Observe(originalVA, receiver, stack + 3);
        ntw2_action_node::Observe(originalVA, receiver, stack + 3);
    }
    if (g_nodeShadow && (site == 0x6759DE || site == 0x675B36))
        ntw2_node::Observe(originalVA, receiver, stack + 3);
    if (g_nodeShadow && site == 0x6759EB)
        ntw2_node::Observe(0x6631A0, D(receiver + 4), stack + 3);
    if (g_fireShadow && target == V(0x80BF70)) ntw2_fire::ObserveGather(receiver, stack + 3);
    if (g_fireShadow && target == V(0x8021E0)) ntw2_fire::ObserveRequest(receiver);
    ++Row(service)[Calls]; ++g_words[ServiceCalls];
    if (service == PosePosition) ReadPose(stack[4], receiver); // native second argument is the reader
    if (service == PoseHeading)
        ReadPose(g_words[LastPoseSubject] == receiver ? g_words[LastPoseReader] : g_entity, receiver);
    const bool container = clone != 0;
    bool finalizerShadow = false;
    if (!container) {
        U note = 0, detail = 0;
        const Classification result = ClassifyTarget(service, receiver, target, site, stack + 3, g_entity, &note, &detail);
        Result(service, result, detail, site);
        if (result == Inactive && ((originalVA == 0x819770 && B(receiver + 0x18C) != 1) || originalVA == 0x7F14C0)) {
            ++g_witness[WitnessFinalizerInactiveCalls];
            finalizerShadow = originalVA == 0x819770 && ntw2_finalizer::ShadowEnabled();
        }
        CountNote(note);
    }
    if (clone) stack[1] = clone;
    const bool shadowCall = (g_nodeShadow &&
        (originalVA == 0x61DA90 || originalVA == 0x6758D0 || originalVA == 0x624F80 ||
         originalVA == 0x7E2C80 || originalVA == 0x816900 || originalVA == 0x819310 ||
         originalVA == 0x7EDD00 || originalVA == 0x662E70 || originalVA == 0x662E50 ||
         originalVA == 0x659520 || originalVA == 0x61D910 || originalVA == 0x665E60 ||
         originalVA == 0x66DD10 || originalVA == 0x624EF0 || originalVA == 0x61D8F0 ||
         originalVA == 0x665E30 || originalVA == 0x66DCF0 || originalVA == 0x5AC9D0 ||
         originalVA == 0x816080 || originalVA == 0x818500 || originalVA == 0x818330 ||
         originalVA == 0x815FF0 || originalVA == 0x444B60 || originalVA == 0x6669B0 ||
         originalVA == 0x6666E0 || originalVA == 0x659D50 || originalVA == 0x66B9D0)) ||
        (g_fireShadow && originalVA == 0x659600) || finalizerShadow;
    if (!container && !g_timingEnabled && !shadowCall) return;
    if (g_depth == kFrameCapacity) {
        ++g_words[TimingOverflow];
        if (container) Result(service, Unresolved, target, site);
        return;
    }
    Frame& frame = g_frames[g_depth++];
    frame.returnAddress = stack[2]; frame.service = service; frame.site = site; frame.target = target;
    frame.activeBefore = g_activeSequence; frame.unknownBefore = g_unknownSequence;
    frame.container = container;
    frame.timed = g_timingEnabled && Clock(frame.start);
    frame.nodeToken = g_nodeShadow ? ntw2_node::Before(originalVA, receiver, stack + 3, g_clones) : 0;
    frame.moveNodeToken = g_nodeShadow ? ntw2_move_node::Before(originalVA, receiver, stack + 3, g_clones) : 0;
    frame.idleNodeToken = g_nodeShadow ? ntw2_idle_node::Before(originalVA, receiver, stack + 3, g_clones) : 0;
    frame.actionNodeToken = g_nodeShadow ? ntw2_action_node::BeforeSite(originalVA, site, receiver, stack + 3, g_clones) : 0;
    frame.fireShadow = g_fireShadow && originalVA == 0x659600;
    if (frame.fireShadow) ntw2_fire::ShadowBefore(receiver);
    frame.finalizerShadow = finalizerShadow;
    if (finalizerShadow) ntw2_finalizer::ShadowBefore(receiver);
    stack[2] = Address(reinterpret_cast<const void*>(&ServiceExit));
}
U __stdcall LeaveService() {
    const Frame& frame = g_frames[--g_depth];
    const Service service = static_cast<Service>(frame.service);
    if (frame.nodeToken) ntw2_node::After(frame.nodeToken);
    if (frame.moveNodeToken) ntw2_move_node::After(frame.moveNodeToken);
    if (frame.idleNodeToken) ntw2_idle_node::After(frame.idleNodeToken);
    if (frame.actionNodeToken) ntw2_action_node::After(frame.actionNodeToken);
    if (frame.fireShadow) ntw2_fire::ShadowAfter();
    if (frame.finalizerShadow) ntw2_finalizer::ShadowAfter();
    if (frame.timed) {
        LARGE_INTEGER end;
        if (Clock(end)) {
            if (end.QuadPart >= frame.start.QuadPart)
                AddTicks(Row(service) + TicksLo, static_cast<ULONGLONG>(end.QuadPart - frame.start.QuadPart));
            else ++g_words[QpcFailures];
        }
    }
    if (frame.container) {
        Result(service, g_activeSequence != frame.activeBefore ? Active :
               g_unknownSequence != frame.unknownBefore ? Unresolved : Inactive, frame.target, frame.site);
    }
    return frame.returnAddress;
}
__declspec(naked) void ServiceGate() {
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    // Classification must not add FP exceptions; retain native rounding/DAZ/FTZ.
    __asm mov eax, [esp+24]
    __asm or eax, 01F80h
    __asm mov [esp+512], eax
    __asm ldmxcsr [esp+512]
    __asm cld
    __asm push ebp
    __asm lea eax, [ebp+36]
    __asm push eax
    __asm call EnterService
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm lea esp, [esp+4]
    __asm ret
}
__declspec(naked) void ServiceExit() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call LeaveService
    __asm mov [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
// Pure per-site observation result (false: not an observation point).
// Global subjects are static for the process lifetime (approved image, every
// .reloc reference enumerated): 14D0848/14D084C are zero BSS with no image
// store (sole escape 622400 -> 10D0900 reads its argument); 14D05AC, 14D0844,
// 14D05B0 and 14D060C are stored only by CRT dynamic initialisers 4109C0,
// 410A00, 410A20, 4105F0 (referenced solely from the __xc table 1308668..
// 1308688). MeleeLabel copies that static 14D060C into own A+88.
bool ObserveClassify(U site, const U* registers, U entity, Service& service, Classification& result,
                     U& subject, U& detail, U* note) {
    service = MutableRead; result = Unresolved; subject = 0; detail = 0;
    switch (site) {
    case 0x66D00E: subject = V(0x14D0848); result = Inactive; return true;
    case 0x66D4BB: subject = V(0x14D05AC); result = Inactive; return true;
    case 0x66D4D9: subject = V(0x14D0844); result = Inactive; return true;
    case 0x64DEC2: subject = V(0x14D05B0); result = Inactive; return true;
    case 0x66D5D4: service = MeleeLabel; subject = V(0x14D060C); result = Inactive; return true;
    case 0x66D2F3: {
        // Histogram key: the +F0 method the native block calls on the target,
        // never the heap object address (which flooded the site table).
        subject = D(entity + 0x1EC);
        if (!subject) break;
        const U table = D(subject);
        detail = InRdata(table + 0xF0) ? D(table + 0xF0) : 0;
        // A register-only T.vt+F0 writes nothing. AL=0 (461180/462CB0) ends the block's reads of T; any other
        // leaf may return 1, after which 66D313..66D360 read T+628/+66C/+670->[0]/+630/+634/+638 (TargetHash).
        // The rest of the block (database row, E5F760, 6666E0) is gated or own.
        if (!detail || !(Stub(detail) || PureLeaf(detail))) break;
        if (ReturnsZeroAl(detail)) { result = Inactive; return true; }
        if (!g_witnessOpen) break;
        if (!OwnPart(subject, entity)) RecordDep(WitnessDepTarget, subject, TargetHashMemo(subject));
        else if (D(subject + 0x628) && D(subject + 0x66C)) {
            // Own target: its fields are digest-guarded, its member array is not.
            const U members = D(subject + 0x670);
            if (members && !OwnPart(members, entity)) RecordDep(WitnessDepWord, members, D(members));
        }
        result = Inactive;
        return true;
    }
    case 0x66D443: subject = D(entity + 0x5B8); break;
    case 0x658F44: service = Engage; result = Active; return true;
    case 0x658E93: subject = D(entity + 0x1EC); break;
    case 0x65909F: subject = D(entity + 0x5B8); break;
    case 0x658FAE: {
        // Unit+D9D (writers 54DB56/54E8E6) is field 12 of the unit witness.
        subject = D(entity + 0x1F0);
        U values[kUnitFields];
        if (subject && UnitStatic(subject, values, note)) result = Inactive;
        break;
    }
    case 0x6758D6: subject = D(registers[0] + 0x1C); break;
    case 0x62EC97: case 0x62EFB3: case 0x62EFBD: case 0x62F0C0:
    case 0x62F0CC: case 0x62F0DF: case 0x62F0E9: case 0x62F106:
        service = FireCandidates; result = Active; return true;
    case 0x80C328: case 0x80C340: case 0x80C35B: case 0x80C37C:
    case 0x80C3C9: case 0x80CD61: case 0x80D3F5: case 0x80DA8A:
        service = FireGather; result = Active; return true;
    default: return false;
    }
    if (!subject) result = Inactive;
    return true;
}
void __stdcall Observe(U site, const U* registers) {
    if (!g_censusEnabled || !g_entity) return;
    Service service; Classification result; U subject, detail, note = 0;
    if (!ObserveClassify(site, registers, g_entity, service, result, subject, detail, &note)) return;
    CountNote(note);
    if (site == 0x66D443 && subject && (B(subject + 0x34) & 3)) ReadPose(g_entity, subject);
    if (service == FireCandidates || service == FireGather) {
        // A reached store is evidence for the enclosing real service call,
        // not an additional call. Classify that call exactly once at return.
        ++g_activeSequence;
        if (!g_firstActive) {
            g_firstActive = service + 1; ++Row(service)[FirstActiveOccurrences];
        }
        return;
    }
    ++Row(service)[Calls]; ++g_words[ServiceCalls];
    Result(service, result, subject, site, detail);
}
__declspec(naked) void ObserveGate() {
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm push ebp
    __asm push dword ptr [ebp+40]
    __asm call Observe
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret 4
}

// Canonical real-original entries for isolated gate/oracle calls. Their stack
// cleanup and result widths remain those of the originals, not C++ substitutes.
#define DIRECT_GATE(name, index) \
    __declspec(naked) void name##Gate() { \
        __asm push dword ptr [g_targets + index * 4] \
        __asm push 0 \
        __asm jmp ServiceGate \
    }
DIRECT_GATE(Effects, 0) DIRECT_GATE(SlotAcquire, 1) DIRECT_GATE(TargetAcquire, 2)
DIRECT_GATE(MoveDriver, 4) DIRECT_GATE(FireDriver, 5) DIRECT_GATE(Finalize, 6)
DIRECT_GATE(FireSequence, 7) DIRECT_GATE(PathRequest, 8) DIRECT_GATE(RequestBuild, 9)
DIRECT_GATE(RequestCommit, 10) DIRECT_GATE(Order, 11) DIRECT_GATE(NodeFinish, 12)
DIRECT_GATE(NodeBegin, 13) DIRECT_GATE(NodeStep, 14) DIRECT_GATE(NodeDestroy, 15)
DIRECT_GATE(Animation, 16) DIRECT_GATE(Parked, 17) DIRECT_GATE(WrapperEffect, 18)
DIRECT_GATE(WrapperService, 19) DIRECT_GATE(PosePosition, 20) DIRECT_GATE(PoseHeading, 21)
DIRECT_GATE(ReferenceStep, 22) DIRECT_GATE(Arrival, 23) DIRECT_GATE(Unlink, 24)
DIRECT_GATE(Engage, 25) DIRECT_GATE(Random, 26) DIRECT_GATE(ReferenceConstruct, 27)
DIRECT_GATE(Watcher, 28) DIRECT_GATE(HolderQuery, 29) DIRECT_GATE(Timer, 30)
DIRECT_GATE(UnitWitness, 31) DIRECT_GATE(AnimationLookup, 32) DIRECT_GATE(ColdLookup, 33)
DIRECT_GATE(Idle, 34) DIRECT_GATE(PreBattle, 35) DIRECT_GATE(Exit, 36)
DIRECT_GATE(Projection, 37) DIRECT_GATE(Crew, 38) DIRECT_GATE(Descriptor, 39)
DIRECT_GATE(Wrapper610470, 40) DIRECT_GATE(Wrapper60CAC0, 41) DIRECT_GATE(Wrapper5E52F0, 42)
DIRECT_GATE(Wrapper607540, 43) DIRECT_GATE(Wrapper5B9720, 44)
DIRECT_GATE(FireCandidates, 48) DIRECT_GATE(FireSubmit, 49) DIRECT_GATE(FireGather, 50)
#undef DIRECT_GATE
struct Entry { U va; void (*gate)(); };
const Entry kEntries[ServiceCount] = {
    {0x62DFF0, EffectsGate}, {0x6666E0, SlotAcquireGate}, {0x6718F0, TargetAcquireGate}, {0, nullptr},
    {0x658C50, MoveDriverGate}, {0x64DE80, FireDriverGate}, {0x6543D0, FinalizeGate}, {0x659600, FireSequenceGate},
    {0x7FD070, PathRequestGate}, {0x659480, RequestBuildGate}, {0x659520, RequestCommitGate}, {0x6631A0, OrderGate},
    {0x63CDD0, NodeFinishGate}, {0x6666B0, NodeBeginGate}, {0x66E670, NodeStepGate}, {0x624F80, NodeDestroyGate},
    {0x670F40, AnimationGate}, {0x67A050, ParkedGate}, {0x5CB830, WrapperEffectGate}, {0x5B7B20, WrapperServiceGate},
    {0x5E4B20, PosePositionGate}, {0x5E4AF0, PoseHeadingGate}, {0x6758D0, ReferenceStepGate}, {0x655B20, ArrivalGate},
    {0x643C90, UnlinkGate}, {0x7E1ED0, EngageGate}, {0x5FC070, RandomGate}, {0x61DA90, ReferenceConstructGate},
    {0x66E780, WatcherGate}, {0x805880, HolderQueryGate}, {0x602E00, TimerGate}, {0x53EEE0, UnitWitnessGate},
    {0xE5F760, AnimationLookupGate}, {0x10F1160, ColdLookupGate}, {0x5B77A0, IdleGate}, {0x66C160, PreBattleGate},
    {0x679300, ExitGate}, {0x80E9D0, ProjectionGate}, {0x6C4FE0, CrewGate}, {0x7EAE90, DescriptorGate},
    {0x610470, Wrapper610470Gate}, {0x60CAC0, Wrapper60CAC0Gate}, {0x5E52F0, Wrapper5E52F0Gate},
    {0x607540, Wrapper607540Gate}, {0x5B9720, Wrapper5B9720Gate}, {0, nullptr}, {0, nullptr}, {0, nullptr},
    {0x62E910, FireCandidatesGate}, {0x8021E0, FireSubmitGate}, {0x80BF70, FireGatherGate}, {0, nullptr}, {0, nullptr}
};
Class EntryClass(U entry) {
    if (!g_bound) return Other;
    switch (entry - g_delta) {
    case 0x66CE00: return Core; case 0x6F50F0: return Thunk;
    case 0x602EB0: return Wrapper602EB0; case 0x5FCEB0: return Wrapper5FCEB0;
    case 0x6F4660: return Artillery; default: return Other;
    }
}
bool ClonesReady(const U* clones) {
    if (!clones) return false;
    if (clones == g_readyClones) return true;
    // Every dynamic destination is ready before native execution starts. No
    // mid-occurrence failure ever requests replay or re-executes prior writes.
    for (U id = NTW2_CLONE_BRAIN_W; id <= NTW2_CLONE_BRAIN_W_UNLINK; ++id)
        if (!clones[id]) return false;
    if (!clones[NTW2_CLONE_BRAIN_W_COMMON_STEP] || !clones[NTW2_CLONE_BRAIN_W_HOLDER_STEP]) return false;
    if (!clones[NTW2_CLONE_BRAIN_W_HOT_CTOR] || !clones[NTW2_CLONE_BRAIN_W_HOT_BEGIN] ||
        !clones[NTW2_CLONE_BRAIN_W_HOT_STEP] || !clones[NTW2_CLONE_BRAIN_W_HOT_DTOR] ||
        !clones[NTW2_CLONE_BRAIN_W_HOT_INSTALL]) return false;
    for (U id = NTW2_CLONE_BRAIN_W_IDLE_CTOR; id <= NTW2_CLONE_BRAIN_ACTION_EMPTY; ++id)
        if (!clones[id]) return false;
    for (U id = NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF9E0; id <= NTW2_CLONE_BRAIN_W_NODE_DISPATCH_809D80; ++id)
        if (!clones[id]) return false;
    g_readyClones = clones;
    return true;
}
} // namespace

Classification ClassifyService(Service service, U receiver) {
    if (!g_bound || !receiver) return Unresolved;
    switch (service) {
    case Effects:
        if (D(receiver + 0x1B8) == 0xD || D(receiver + 0x18)) return Inactive;
        return EffectsActive(receiver) ? Active : Inactive;
    case TargetAcquire: {
        const U phase = D(receiver + 0x224);
        if ((phase != 0 && phase != 0xC) || (!phase && !B(receiver + 0x5C0))) return Inactive;
        return Unresolved; // 6649C0/node virtuals and backlink transaction not guessed
    }
    case Watcher: case HolderQuery:
        return B(receiver + 0x8F) != 1 ? Inactive : Unresolved;
    case WrapperEffect:
        return Unresolved; // the vector is a stack argument; Enter classifies it
    case WrapperService:
        return !B(receiver + 0xEC) || D(receiver + 0x1EC) ? Inactive : Unresolved;
    case NodeFinish:
        return B(receiver + 0x9C) != 1 ? Inactive : Unresolved;
    case FireSequence: {
        const U state = D(receiver + 0x390);
        return state != 1 && state != 2 && state != 3 && state != 4 && state != 5 &&
               D(receiver + 0x3BC) + D(receiver + 0x3C8) == 0 ? Inactive : Unresolved;
    }
    case Random: case FireSubmit:
        return Active; // 5FC071..7C LCG store; 8021F4 shared subsystem counter increment
    case ReferenceConstruct: case Descriptor:
        // 61DAB5 reads shared heading 14D05B0; 7EAE90 reads the shared default
        // vector 150FCA8..150FCB0. Neither is proved immutable owner-private.
        return Unresolved;
    case AnimationLookup:
        return Inactive; // canonical E5F760 readonly lookup
    default:
        return Unresolved;
    }
}
bool Bind(U imageBase, U* bindings) {
    g_delta = imageBase - 0x400000; g_bound = imageBase != 0;
    ntw2_node::Bind(imageBase);
    ntw2_move_node::Bind(imageBase);
    ntw2_finalizer::Bind(imageBase);
    ntw2_idle_node::Bind(imageBase); ntw2_action_node::Bind(imageBase);
    if (!ntw2_node::projection::Initialize(imageBase, bindings)) { g_bound = false; return false; }
    for (U i = 0; i < ServiceCount; ++i) g_targets[i] = kEntries[i].va ? V(kEntries[i].va) : 0;
    bindings[NTW2_BIND_B2_SERVICE_GATE] = Address(reinterpret_cast<const void*>(&ServiceGate));
    bindings[NTW2_BIND_B2_OBSERVE] = Address(reinterpret_cast<const void*>(&ObserveGate));
    return true;
}
void Configure(bool census, bool timing, bool nodeShadow, bool fireShadow, bool finalizerShadow) {
    g_nodeShadow = nodeShadow; g_fireShadow = fireShadow; g_finalizerShadow = finalizerShadow;
    g_censusEnabled = census || nodeShadow || fireShadow || finalizerShadow; g_timingEnabled = timing;
    ntw2_finalizer::Configure(finalizerShadow);
    ntw2_node::Configure(nodeShadow);
    ntw2_move_node::Configure(nodeShadow);
    ntw2_idle_node::Configure(nodeShadow); ntw2_action_node::Configure(nodeShadow);
    ntw2_fire::Start({g_delta, fireShadow});
    g_route[RouteVersion] = 1;
    g_route[ConfiguredDriver] = g_censusEnabled ? 1u : 0u;
}
void BeginDispatch() { Metadata(); ++g_words[Dispatches]; }
void RunOccurrence(U entity, const U* cloneEntries) {
    Metadata(); ++g_words[Occurrences];
    const U original = D(D(entity) + 0xC);
    const Class cls = EntryClass(original);
    ++g_words[ClassCounts + static_cast<U>(cls)]; g_words[LastClass] = cls; g_words[LastEntity] = entity;
    const bool supported = cls <= Wrapper5FCEB0;
    const bool ready = g_bound && g_censusEnabled && supported && ClonesReady(cloneEntries);
    U entry = original;
    if (ready) {
        const U id = cls == Wrapper602EB0 ? NTW2_CLONE_BRAIN_W_602EB0 :
                     cls == Wrapper5FCEB0 ? NTW2_CLONE_BRAIN_W_5FCEB0 : NTW2_CLONE_BRAIN_W;
        entry = cloneEntries[id]; ++g_words[CloneOccurrences];
    } else {
        ++g_words[OriginalOccurrences];
        if (g_censusEnabled) {
            ++g_words[RefusedOccurrences];
            if (!supported) ++g_words[UnknownClass]; else ++g_words[MissingClone];
        }
    }
    const U previousEntity = g_entity, previousActive = g_firstActive, previousUnknown = g_firstUnknown;
    const U previousPose = g_poseMask, depth = g_depth;
    const U* previousClones = g_clones;
    g_entity = entity; g_firstActive = g_firstUnknown = g_poseMask = 0;
    g_clones = ready ? cloneEntries : nullptr;
    LARGE_INTEGER start = {};
    const bool timed = g_timingEnabled && Clock(start);
    bool completed = false;
    __try {
        reinterpret_cast<void (__thiscall*)(void*)>(entry)(reinterpret_cast<void*>(entity));
        completed = true;
    } __finally {
        if (timed) {
            LARGE_INTEGER end;
            if (Clock(end)) {
                if (end.QuadPart >= start.QuadPart)
                    AddTicks(g_words + (ready ? CloneTicksLo : OriginalTicksLo),
                             static_cast<ULONGLONG>(end.QuadPart - start.QuadPart));
                else ++g_words[QpcFailures];
            }
        }
        if (g_depth > depth) { g_words[AbandonedTiming] += g_depth - depth; g_depth = depth; }
        if (!completed) {
            ntw2_node::Abandon(); ntw2_move_node::Abandon(); ntw2_fire::Abandon();
            ntw2_idle_node::Abandon(); ntw2_action_node::Abandon();
        }
        if (ready && completed) {
            if (g_firstActive) ++g_words[AnyActive];
            if (g_firstUnknown) { ++g_words[AnyUnknown]; ++g_words[RefusedOccurrences]; }
            if (!g_firstActive && !g_firstUnknown) ++g_words[FullyInactive];
        }
        g_words[LastFirstActive] = g_firstActive; g_words[LastFirstUnknown] = g_firstUnknown;
        g_entity = previousEntity; g_firstActive = previousActive; g_firstUnknown = previousUnknown;
        g_poseMask = previousPose; g_clones = previousClones;
    }
}
void WitnessBegin(U manager) {
    g_witnessOpen = false; g_battleValid = false; g_battleManager = 0; g_battleUsed = false;
    memset(g_units, 0, sizeof(g_units)); memset(g_armies, 0, sizeof(g_armies));
    // Slot rows are large (kSlotRows hashes): clear only the keys; an inserted row is fully rewritten below.
    for (SlotSnapshot& row : g_slots) row.record = 0;
    g_probe.Clear();
    ++g_witness[WitnessDispatches];
    U stored = 0, slotStored = 0, armyStored = 0;
    if (!ProbeRegionContains(manager + 0x260, 8)) {
        ++g_witness[WitnessSnapshotFaults]; g_witnessOpen = true; return;
    }
    const U data = D(manager + 0x264), count = D(manager + 0x260);
    if (count > 0x1000000 || (count && !ProbeRegionContains(data, count * 4))) {
        ++g_witness[WitnessSnapshotFaults]; g_witnessOpen = true; return;
    }
    for (U i = 0; i < count; ++i) {
        // The walk reads three cache lines per soldier (+0/+30, +1F0, +444) in worklist order; a prefetch never
        // faults, so the soldier eight ordinals ahead is requested before its readability is proven.
        if (i + 8 < count) {
            const char* ahead = reinterpret_cast<const char*>(static_cast<uintptr_t>(D(data + 4 * (i + 8))));
            _mm_prefetch(ahead, _MM_HINT_T0); _mm_prefetch(ahead + 0x1F0, _MM_HINT_T0); _mm_prefetch(ahead + 0x444, _MM_HINT_T0);
        }
        const U entity = D(data + 4 * i);
        if (!entity || !ProbeRegionContains(entity, 0x44C)) { if (entity) ++g_witness[WitnessSnapshotFaults]; continue; }
        if (B(entity + 0x30) != 1) continue;
        // Same class check RunOccurrence performs before touching any brain field:
        // non-brain worklist objects must never be dereferenced at +1F0/+444.
        const U table = D(entity);
        if (!ProbeRegionContains(table + 0xC, 4)) { ++g_witness[WitnessSnapshotFaults]; continue; }
        if (EntryClass(D(table + 0xC)) > Wrapper5FCEB0) continue;
        if (!g_battleManager) {
            const U root = D(entity + 0x28);
            const U model = root && ProbeRegionContains(root + 8, 4) ? D(root + 8) : 0;
            g_battleManager = model && ProbeRegionContains(model + 0xB0, 4) ? D(model + 0xB0) : 0;
        }
        const U unit = ProbeRegionContains(entity + 0x1F0, 4) ? D(entity + 0x1F0) : 0;
        if (unit) {
            U slot = UnitSlot(unit);
            while (g_units[slot].unit && g_units[slot].unit != unit) slot = (slot + 1) & (kUnitCapacity - 1);
            if (g_units[slot].unit != unit) {
                // Keep a quarter of the table empty so failed lookups stay short.
                if (stored == kUnitCapacity / 4 * 3) ++g_witness[WitnessUnitOverflow];
                else if (!ReadUnit(unit, g_units[slot].values)) ++g_witness[WitnessSnapshotFaults];
                else { g_units[slot].unit = unit; ++stored; }
            }
        } else if (const U army = ProbeRegionContains(entity + 0x1F8, 4) ? D(entity + 0x1F8) : 0) {
            U slot = ArmySlot(army);
            while (g_armies[slot].army && g_armies[slot].army != army) slot = (slot + 1) & (kArmyCapacity - 1);
            if (g_armies[slot].army != army) {
                if (armyStored == kArmyCapacity / 4 * 3) ++g_witness[WitnessUnitOverflow];
                else if (!ReadArmy(army, g_armies[slot])) ++g_witness[WitnessSnapshotFaults];
                else { g_armies[slot].army = army; ++armyStored; }
            }
        }
        const U record = ProbeRegionContains(entity + 0x444, 4) ? D(entity + 0x444) : 0;
        if (record) {
            U slot = UnitSlot(record);
            while (g_slots[slot].record && g_slots[slot].record != record) slot = (slot + 1) & (kSlotCapacity - 1);
            if (g_slots[slot].record != record) {
                if (slotStored == kSlotCapacity / 4 * 3) ++g_witness[WitnessUnitOverflow];
                else if (!ReadSlot(record, g_slots[slot])) ++g_witness[WitnessSnapshotFaults];
                else {
                    SlotSnapshot& row = g_slots[slot];
                    row.record = record; row.used = 0; memset(row.usedRows, 0, sizeof(row.usedRows));
                    ++slotStored;
                }
            }
        }
    }
    if (g_battleManager) {
        g_battleValid = ReadBattle(g_battleManager, g_battleValues);
        if (!g_battleValid) ++g_witness[WitnessSnapshotFaults];
    }
    g_witness[WitnessUnits] = stored; g_witness[WitnessSlotSnapshots] = slotStored;
    g_witness[WitnessArmySnapshots] = armyStored;
    g_witnessOpen = true;
}
U WitnessEnd() {
    if (!g_witnessOpen) return 0;
    U units = 0, battle = 0, slots = 0, armies = 0, unitMask = 0, battleMask = 0, slotMask = 0, values[kUnitFields];
    // Only values a successful proof actually consumed this stage can break a
    // proof. Unused units/slots, and unused rows of a used slot, may legitimately
    // change during site 6 and are not re-read at all.
    for (const UnitSnapshot& row : g_units) {
        if (!row.unit || !row.used) continue;
        if (!ReadUnit(row.unit, values)) { ++units; unitMask = ~0u; continue; }
        U mask = 0;
        for (U i = 0; i < kUnitFields; ++i) if (values[i] != row.values[i]) mask |= 1u << i;
        if (mask) { ++units; unitMask |= mask; }
    }
    for (const SlotSnapshot& row : g_slots) {
        if (!row.record || !row.used) continue;
        SlotSnapshot now;
        if (!ReadSlot(row.record, now)) { ++slots; slotMask = ~0u; continue; }
        U mask = 0;
        for (U i = 0; i < kSlotFields; ++i) if (now.values[i] != row.values[i]) mask |= 1u << i;
        if (!(row.usedRows[0] & 1)) mask &= ~(1u << 4); // H+14 is read only by a frame-0 proof
        for (U i = 0; i < kSlotRows; ++i)
            if ((row.usedRows[i / 32] >> (i % 32) & 1) && now.rowHashes[i] != row.rowHashes[i]) mask |= 1u << 6;
        if (mask) { ++slots; slotMask |= mask; }
    }
    for (const ArmySnapshot& row : g_armies) {
        if (!row.army || !row.used) continue;
        ArmySnapshot now;
        bool changed = !ReadArmy(row.army, now) || now.base != row.base;
        for (U i = 0; !changed && i < kArmyEntries; ++i)
            if ((row.usedEntries & (1u << i)) && (now.entries[i] != row.entries[i] || now.mults[i] != row.mults[i])) changed = true;
        if (changed) ++armies;
    }
    if (g_battleValid && g_battleUsed) {
        U now[kBattleFields];
        if (!ReadBattle(g_battleManager, now)) { battle = 1; battleMask = ~0u; }
        else {
            for (U i = 0; i < kBattleFields; ++i) if (now[i] != g_battleValues[i]) battleMask |= 1u << i;
            battle = battleMask != 0;
        }
    }
    g_witness[WitnessUnitsChanged] += units; g_witness[WitnessUnitFieldMask] |= unitMask;
    g_witness[WitnessBattleChanged] += battle; g_witness[WitnessBattleFieldMask] |= battleMask;
    g_witness[WitnessSlotChanged] += slots; g_witness[WitnessSlotFieldMask] |= slotMask;
    g_witness[WitnessArmyChanged] += armies;
    g_witnessOpen = false;
    return units + battle + slots + armies;
}
void WitnessAbort() { g_witnessOpen = false; }
U WitnessProbeQueries() { return g_probeQueries; }
const StageObserver* g_observer;
void SetStageObserver(const StageObserver* observer) { g_observer = observer; }
void RunWorklist(U manager, const U* cloneEntries) {
    BeginDispatch();
    const bool witness = g_bound && g_censusEnabled;
    if (witness) WitnessBegin(manager);
    const StageObserver* const observer = g_observer;
    if (observer) observer->begin(manager);
    U cursor = *reinterpret_cast<volatile U*>(manager + 0x264);
    U end = cursor + 4 * *reinterpret_cast<volatile U*>(manager + 0x260);
    while (cursor != end) {
        const U entity = *reinterpret_cast<volatile U*>(cursor);
        if (*reinterpret_cast<volatile uint8_t*>(entity + 0x30) == 1) {
            RunOccurrence(entity, cloneEntries);
            if (observer) observer->observe(entity);
        }
        cursor += 4;
        end = *reinterpret_cast<volatile U*>(manager + 0x264) +
              4 * *reinterpret_cast<volatile U*>(manager + 0x260);
    }
    if (observer) observer->end();
    if (witness) WitnessEnd();
}
void Reset() {
    memset(g_words, 0, sizeof(g_words)); memset(g_census, 0, sizeof(g_census));
    memset(g_route, 0, sizeof(g_route));
    memset(g_nodeTargets, 0, sizeof(g_nodeTargets));
    g_nodeTargetDistinct = g_nodeTargetOverflow = 0;
    memset(&g_unknownSites, 0, sizeof(g_unknownSites)); memset(&g_firstSites, 0, sizeof(g_firstSites));
    memset(g_witness, 0, sizeof(g_witness)); g_witnessOpen = false;
    g_route[RouteVersion] = 1; g_route[ConfiguredDriver] = g_censusEnabled ? 1u : 0u;
    g_clones = g_readyClones = nullptr; g_entity = g_firstActive = g_firstUnknown = g_poseMask = 0;
    g_depth = g_activeSequence = g_unknownSequence = 0;
    ntw2_node::Reset();
    ntw2_move_node::Reset();
    ntw2_idle_node::Reset(); ntw2_action_node::Reset();
    ntw2_fire::Start({g_delta, g_fireShadow});
    ntw2_finalizer::Reset();
}
void Release() {
    g_clones = g_readyClones = nullptr; g_entity = g_firstActive = g_firstUnknown = g_poseMask = 0;
    g_depth = 0; g_censusEnabled = g_timingEnabled = false;
    g_nodeShadow = g_fireShadow = g_finalizerShadow = false; g_witnessOpen = false; g_observer = nullptr;
    ntw2_finalizer::Configure(false);
    ntw2_node::Release(); ntw2_move_node::Release(); ntw2_fire::Stop();
    ntw2_idle_node::Release(); ntw2_action_node::Release();
}
void UnknownSiteSnapshot(U* words) {
    memset(words, 0, kUnknownSiteWords * sizeof(U));
    SiteTop(g_unknownSites, words);
    SiteTop(g_firstSites, words + kSiteTableWords);
    g_witness[WitnessFinalizerShadowCalls] = ntw2_finalizer::Counter(ntw2_finalizer::ShadowCalls);
    g_witness[WitnessFinalizerShadowMismatches] = ntw2_finalizer::Counter(ntw2_finalizer::ShadowMismatches) +
                                                  ntw2_finalizer::Counter(ntw2_finalizer::ShadowFaults);
    memcpy(words + 2 * kSiteTableWords, g_witness, sizeof(g_witness));
}
struct DepScope {
    WitnessDeps* saved;
    explicit DepScope(WitnessDeps* deps) : saved(t_deps) { t_deps = deps; }
    ~DepScope() { t_deps = saved; }
    DepScope(const DepScope&) = delete;
    DepScope& operator=(const DepScope&) = delete;
};
// The model LCG word the worker owner bound for this stage (0: none). Written only by the owner with no
// dispatch in flight; pool threads read it during the dispatch.
static U g_workerLcg;
void SetWorkerRandomStream(U lcg) { g_workerLcg = lcg; }
bool WorkerRandomStream(U target, U receiver) {
    return g_bound && g_workerLcg && target - g_delta == 0x5FC070 && receiver == g_workerLcg;
}
Classification WorkerClassify(U target, U site, U receiver, const U* args, U entity, U* service, WitnessDeps* deps) {
    const Service s = g_bound ? Identify(target, site) : Unknown;
    if (service) *service = s;
    if (!g_bound) return Unresolved;
    if (CloneIdForVA(target - g_delta) != ~0u) {
        if (SiteForced(site)) return Active;
        // 5B7B20's body compares this against a foreign-loaded pointer ([ebp+4] at
        // 5B7D1E/5B7DC4), so only its early-out entry guard is accepted at workers.
        if (target - g_delta == 0x5B7B20) return ClassifyService(WrapperService, receiver);
        // Watcher-node begins tail-dispatch X.vt+188 / X.vt+134 with X = [[node+8]] (node+8 = holder, set by 7E3A50):
        // accepted only for a node and holder inside the occurrence soldier whose X is that soldier, so the reached
        // installer (650DC0 / 650600, cloned containers) rebuilds the soldier's own A+22C node.
        switch (target - g_delta) {
        case 0x7FF9E0: case 0x80A190: case 0x7FF5C0: case 0x809D80:
            return NodeInstallOwn(receiver, entity) ? Inactive : Unresolved;
        default: return Inactive;
        }
    }
    // 5FC070 (imul [ecx],343FD; add 269EC3; store; ST0 = (state>>16) * [131A7AC]) writes only [ecx]. On the
    // bound model LCG the worker serves it from the occurrence's private stream word (WorkerRandomStream),
    // so the shared word is never touched: worker-safe. Any other receiver is a shared store.
    if (target - g_delta == 0x5FC070) return WorkerRandomStream(target, receiver) ? Inactive : Active;
    const DepScope scope(deps);
    return ClassifyTarget(s, receiver, target, site, args, entity, nullptr, nullptr);
}
StaticVerdict WorkerStaticVerdict(U target, U site) {
    if (!g_bound || SiteForced(site)) return StaticDynamic;
    const U va = target - g_delta;
    if (CloneIdForVA(va) != ~0u) {
        // Exactly the cloned targets whose WorkerClassify result above depends on the receiver.
        switch (va) {
        case 0x5B7B20: case 0x7FF9E0: case 0x80A190: case 0x7FF5C0: case 0x809D80: return StaticDynamic;
        default: return StaticClone;
        }
    }
    if (va == 0x5FC070) return StaticDynamic;
    // ClassifyTarget's receiver-independent Inactive prefix (the forced sites were excluded above).
    return Stub(target) || PureLeaf(target) || StaticInactiveLeaf(va) ? StaticForward : StaticDynamic;
}
void BindWitnessMemo(WitnessMemo* memo) { t_memo = memo; }
void BumpWitnessMemo(WitnessMemo& memo) {
    if (++memo.epoch == 0) { memset(memo.entries, 0, sizeof(memo.entries)); memo.epoch = 1; }
}
bool WorkerSiteForced(U site) { return SiteForced(site); }
// Never 5FC070: forwarding the original would advance the shared word from a pool thread.
bool WorkerForwardable(U target, U site, U receiver, const U* args, U entity, WitnessDeps* deps) {
    return g_bound && CloneIdForVA(target - g_delta) == ~0u && target - g_delta != 0x5FC070 &&
           WorkerClassify(target, site, receiver, args, entity, nullptr, deps) == Inactive;
}
bool WorkerWriteFree(U target) {
    if (!g_bound) return false;
    if (Stub(target) || PureLeaf(target)) return true;
    switch (target - g_delta) {
    // Store-free bodies recovered above (reads only; classification is separate).
    case 0x5DB820: case 0x62DF10: case 0x55AC60: case 0x55AD60: case 0x5DBB30:
    case 0x5DBD60: case 0x55AB90: case 0x55ABF0: case 0x55C1C0: case 0x55C2A0:
    case 0x55C4B0: case 0x55C9A0: case 0x646C20: case 0x6E9DA0: case 0x649520:
        return true;
    default: return false;
    }
}
U CloneIdFor(U originalVA) { return CloneIdForVA(originalVA); }
Classification WorkerObserveClassify(U site, const U* registers, U entity, WitnessDeps* deps) {
    Service service; Classification result; U subject, detail;
    if (!g_bound) return Unresolved;
    const DepScope scope(deps);
    if (!ObserveClassify(site, registers, entity, service, result, subject, detail, nullptr)) return Unresolved;
    return result;
}
bool WitnessDepsHold(const WitnessDeps& deps) {
    if (!g_bound || !g_witnessOpen || deps.overflow || deps.count > kWitnessDepCap) return false;
    const DepScope scope(nullptr); // re-checks record nothing
    for (U i = 0; i < deps.count; ++i) {
        const WitnessDep& d = deps.items[i];
        bool held;
        switch (d.kind) {
        case WitnessDepUnit: held = UnitStatic(d.key, nullptr, nullptr); break;
        case WitnessDepSlot: held = SlotStatic(d.key, d.frame, nullptr); break;
        case WitnessDepArmy: held = ArmyStatic(d.key, d.frame, nullptr); break;
        case WitnessDepBattle: held = BattleStatic(d.key, nullptr); break;
        case WitnessDepFrame:
            held = FrameHashMemo(d.key, d.aux != 0) == d.frame;
            break;
        case WitnessDepTerrain: {
            U hash = 0;
            held = TerrainHashMemo(d.key, hash) && hash == d.frame;
            break;
        }
        case WitnessDepWord: held = D(d.key) == d.frame; break;
        case WitnessDepTarget: held = TargetHashMemo(d.key) == d.frame; break;
        case WitnessDepCrew: held = d.aux <= kCrewMax && CrewHashMemo(d.key, d.aux) == d.frame; break;
        case WitnessDepAnim: {
            U hash = 0;
            held = AnimHashMemo(d.key, d.aux, hash) && hash == d.frame;
            break;
        }
        default: held = false; break;
        }
        if (!held) return false;
    }
    return true;
}
void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
void CensusSnapshot(U* words) { memcpy(words, g_census, sizeof(g_census)); }
void RouteSnapshot(U* words) { memcpy(words, g_route, sizeof(g_route)); }
void NodeTargetSnapshot(U* words) {
    memset(words, 0, kNodeTargetWords * sizeof(U));
    words[0] = 1; words[1] = g_nodeTargetDistinct;
    words[2] = g_nodeTargetOverflow;
    for (U kind = 0; kind != 2; ++kind) {
        const NodeTargetCount* top[kNodeTargetTop] = {};
        U count = 0;
        for (const NodeTargetCount& row : g_nodeTargets) {
            const ULONGLONG calls = kind ? row.steps : row.begins;
            if (!calls) continue;
            U position = 0;
            while (position < count) {
                const auto& other = *top[position];
                const ULONGLONG otherCalls = kind ? other.steps : other.begins;
                if (calls > otherCalls || (calls == otherCalls && row.target < other.target)) break;
                ++position;
            }
            if (position == kNodeTargetTop) continue;
            if (count < kNodeTargetTop) ++count;
            for (U j = count - 1; j > position; --j) top[j] = top[j - 1];
            top[position] = &row;
        }
        for (U i = 0; i < count; ++i) {
            words[4 + kind * 16 + i * 2] = top[i]->target;
            words[5 + kind * 16 + i * 2] =
                static_cast<U>(kind ? top[i]->steps : top[i]->begins);
        }
    }
}
void DiagSnapshot(U* reason, U* gate) {
    for (U i = 0; i < kDiagReasonWords; ++i) reason[i] = Row(static_cast<Service>(i))[FirstActiveOccurrences];
    for (U i = 0; i < 48; ++i) gate[i] = Row(static_cast<Service>(i))[Calls];
    for (U i = 0; i < 32; ++i) gate[48 + i] = Row(static_cast<Service>(i))[FirstUnknownOccurrences];
}
U GateAddress(Service service) {
    if (!g_bound || service >= ServiceCount || !kEntries[service].gate) return 0;
    return Address(reinterpret_cast<const void*>(kEntries[service].gate));
}
const char* ServiceName(Service service) {
    static const char* const names[ServiceCount] = {
        "effects", "slot_acquire", "target_acquire", "charge_callback", "move_driver", "fire_driver",
        "finalize", "fire_sequence", "path_request", "request_build", "request_commit", "order",
        "node_finish", "node_begin", "node_step", "node_destroy", "animation", "parked",
        "wrapper_effect", "wrapper_service", "pose_position", "pose_heading", "reference_step",
        "arrival", "unlink", "engage", "random", "reference_construct", "watcher", "holder_query",
        "timer", "unit_witness", "animation_lookup", "cold_lookup", "idle", "prebattle", "exit",
        "projection", "crew", "descriptor", "wrapper_610470", "wrapper_60cac0", "wrapper_5e52f0",
        "wrapper_607540", "wrapper_5b9720", "virtual_order", "virtual_query", "unknown",
        "fire_candidates", "fire_submit", "fire_gather", "melee_label", "mutable_read"
    };
    return service < ServiceCount ? names[service] : "invalid";
}
} // namespace ntw2_brain2
