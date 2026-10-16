// Puppet survival probe (native_puppet.h). Owner thread only; native transactions are the engine's own code.
#include "native_puppet.h"
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

namespace ntw2_puppet {
namespace {
static_assert(sizeof(void*) == 4, "puppet probe ABI is Win32");
constexpr const char* kLabels[] = { NTW2_PUPPET_WORD_LABELS };
static_assert(sizeof(kLabels) / sizeof(kLabels[0]) == kWords, "one label per puppet status word");
constexpr const char* kDivertLabels[] = { NTW2_PUPPET_DIVERT_LABELS };
static_assert(sizeof(kDivertLabels) / sizeof(kDivertLabels[0]) == kDivertWords, "one label per divert word");
constexpr const char* kMoverLabels[] = { NTW2_PUPPET_MOVER_LABELS };
static_assert(sizeof(kMoverLabels) / sizeof(kMoverLabels[0]) == kMoverWords, "one label per mover word");
constexpr const char* kSelectLabels[] = { NTW2_PUPPET_SELECT_LABELS };
static_assert(sizeof(kSelectLabels) / sizeof(kSelectLabels[0]) == kSelectWords, "one label per select word");

// Approved-image preferred VAs (SHA-256 13fcab62...).
constexpr U kClassTable = 0x1333714, kWaitTable = 0x1334028, kCrewNode = 0x133AE34;
constexpr U kWaitInstall = 0x650600, kWaitBegin = 0x665E30, kWaitStep = 0x66DCF0, kCommonStep = 0x670EB0;
constexpr U kBrainStep = 0x66CE00, kTerrain = 0x81AC80, kActivity = 0x663730;
constexpr U kArtilleryStep = 0x6F4660, kCavalryStep = 0x602EB0;
constexpr U kSlotNodeTable = 0x13472A4; // node constructed at A+2D4 by 0x7E3D50 from the 0x581513 slot descriptor
// +628 controller tables (0x662E90 stores the registering receiver): slot 0 returns the receiver / returns null.
constexpr U kControllerSelf = 0x1334250, kControllerNull = 0x1334218;
constexpr U kIntentWriter = 0x80B080; // thiscall(A, const float xz[2], heading word): +D4/+D8/+DC/+E0/+18C/+148 if +18==0
// Engine constants of the point-move contract 0x67A050 (heading words: 65536 per turn).
constexpr float kDt = 0.1f;                     // native tick, 0x131A7B0
constexpr float kHeadingPerRadian = 10430.378f; // 0x1325DAC
constexpr float kMaxTurnPerTick = 3.1101768f;   // 0x1335A34, cap of turn*dt in 0x67A050
// Storage: rows (serial-keyed open addressing, load <= 1/2), unit handles, the examined-unit set of one selection, and
// the parked bit per registry serial.
constexpr U kHash = 2 * kMaxRows, kUnitHash = 2 * kMaxUnits, kMaxExamined = 4096, kSeenHash = 2 * kMaxExamined;
constexpr U kSerialBits = 1u << 20;
constexpr U kNone = ~0u, kMaxArmies = kPuppetNoArmy, kNoArmy = kPuppetNoArmy;
static_assert(!(kHash & (kHash - 1)) && !(kUnitHash & (kUnitHash - 1)) && !(kSeenHash & (kSeenHash - 1)), "power-of-two hashes");

enum State : U { Free, Ignored, Pending, Parked, Native, Gone };
enum Kind : U { Admit, Repark, HandTransfer, HandIneligible, DivertRepark, DivertHandback };
enum Event : U { EvAdmit = 1, EvRepark, EvHandback, EvDepart, EvDivertBegin, EvDivertEnd };
// ax/az: position at admission (or at the end of the last divert); px/pz: position at the previous motion sample.
// divert: a +628 controller holds the member since divertStage (its site-6 step runs the original).
// f370: +370 at the previous stats-mode seam (fatigue370_frozen).
struct Row { U entity, serial, unit, generation, state, seen, foreign, commonStage, divert, divertStage, f370; float ax, az, px, pz; };
// handle/vtable/ordinal/generation/active identify the unit; members/handed/army/x/z are its published identity row;
// parked is maintained by SetState.
struct Unit { U handle, vtable, ordinal, generation, active, members, handed, army, x, z, parked; };
struct Action { U row, kind; };
struct Storage { Row rows[kMaxRows]; U hash[kHash]; Action actions[kMaxRows]; U parked[kSerialBits / 32]; };

U g_delta, g_requested, g_classVt, g_waitVt, g_crewVt, g_stage, g_generation, g_unitCount, g_rowCount, g_actionCount;
bool g_started, g_selected, g_disabled, g_stats;
U g_parkedCount, g_pendingCount; // maintained by SetState (Publish is O(row units))
U g_words[kWords], g_motion[kMotionWords], g_divert[kDivertWords], g_mover[kMoverWords], g_select[kSelectWords];
U g_divertsThisStage, g_eventHash, g_moverStage, g_tables[kInfantryTableCount], g_tableCount, g_topCount;
U* g_parked;
Unit g_units[kMaxUnits];
U g_unitHash[kUnitHash], g_seenHash[kSeenHash];
Storage* g_store; // activation storage, allocated by the first Start and kept for the process lifetime
Row* g_rows;
U* g_hash;
Action* g_actions;
LONGLONG g_adapterTicks, g_frequency, g_qpc0;
unsigned long long g_tsc0, g_dispatchCycles, g_divertTargetSum, g_divertDurationSum, g_moverUsTotal;
U g_sampleSeq, g_epochBit, g_slotVt;
const volatile long* g_tickOwner;
const volatile U* g_epochMask;

inline U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
inline void W8(U a, U v) { *reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(a)) = static_cast<uint8_t>(v); }
inline void W32(U a, U v) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a)) = v; }
inline void W16(U a, U v) { *reinterpret_cast<volatile uint16_t*>(static_cast<uintptr_t>(a)) = static_cast<uint16_t>(v); }
inline void WF(U a, float v) { *reinterpret_cast<volatile float*>(static_cast<uintptr_t>(a)) = v; }
inline U H(U a) { return *reinterpret_cast<const volatile uint16_t*>(static_cast<uintptr_t>(a)); }
inline float F(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline U Bits(float v) { U u; memcpy(&u, &v, 4); return u; }
// The engine's signed heading word: 0x8000 reads as +32768 (0x67A41C..0x67A4C4).
inline int S16(U w) { w &= 0xFFFF; return w == 0x8000 ? 32768 : static_cast<int16_t>(w); }
inline U Fnv(U h, U w) { return (h ^ w) * 16777619u; }
inline bool Finite(float v) { return v - v == 0.0f; }
inline U Centimetres(float dx, float dz) { return static_cast<U>(sqrtf(dx * dx + dz * dz) * 100.0f + 0.5f); }
inline U V(U va) { return va + g_delta; }
inline void Call(U target, U self) { reinterpret_cast<void (__thiscall*)(U)>(static_cast<uintptr_t>(target))(self); }
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }

// Multiplicative hash folded so aligned pointers (zero low bits) still spread over the low slot bits.
U HashSlot(U key, U mask) { const U h = key * 2654435761u; return (h ^ (h >> 15)) & mask; }
Row* Find(U serial) {
    for (U slot = HashSlot(serial, kHash - 1), n = 0; n < kHash; ++n, slot = (slot + 1) & (kHash - 1)) {
        const U index = g_hash[slot];
        if (!index) return nullptr;
        if (g_rows[index - 1].serial == serial) return &g_rows[index - 1];
    }
    return nullptr;
}
void SetState(Row& r, U state);
Row* AddRow(U entity, U serial, U unit, U state) {
    if (g_rowCount == kMaxRows) return nullptr;
    U slot = HashSlot(serial, kHash - 1);
    while (g_hash[slot]) slot = (slot + 1) & (kHash - 1); // load <= 1/2: never full
    Row& r = g_rows[g_rowCount];
    r = {entity, serial, unit, g_units[unit].generation, Free, g_stage};
    SetState(r, state);
    g_hash[slot] = ++g_rowCount;
    return &r;
}
// Selected units by handle (insert-only: a retired unit keeps its index, inactive).
U UnitIndex(U handle) {
    if (!handle) return kNone;
    for (U slot = HashSlot(handle, kUnitHash - 1);; slot = (slot + 1) & (kUnitHash - 1)) {
        const U index = g_unitHash[slot];
        if (!index) return kNone;
        if (g_units[index - 1].handle == handle) return index - 1;
    }
}
void AddUnitIndex(U handle, U ui) {
    U slot = HashSlot(handle, kUnitHash - 1);
    while (g_unitHash[slot]) slot = (slot + 1) & (kUnitHash - 1);
    g_unitHash[slot] = ui + 1;
}
// Examined set of one selection pass; false when the handle was already examined.
bool FirstSight(U handle) {
    for (U slot = HashSlot(handle, kSeenHash - 1);; slot = (slot + 1) & (kSeenHash - 1)) {
        if (!g_seenHash[slot]) { g_seenHash[slot] = handle; return true; }
        if (g_seenHash[slot] == handle) return false;
    }
}
void RecordFault(U code) { ++g_words[Faults]; g_words[LastFault] = code; }
bool IsInfantry(U table) {
    for (U i = 0; i < g_tableCount; ++i) if (g_tables[i] == table) return true;
    return false;
}
// Parked bit per registry serial: set exactly while the serial's row is Parked (SetState is the only state writer
// that enters or leaves Parked).
inline bool ParkedBit(U serial) { return serial < kSerialBits && (g_parked[serial >> 5] >> (serial & 31) & 1); }
void SetState(Row& r, U state) {
    if (r.state == state) return;
    if (r.serial < kSerialBits) {
        const U mask = 1u << (r.serial & 31);
        if (state == Parked) g_parked[r.serial >> 5] |= mask;
        else if (r.state == Parked) g_parked[r.serial >> 5] &= ~mask;
    }
    if (r.state == Parked) { --g_parkedCount; --g_units[r.unit].parked; }
    else if (r.state == Pending) --g_pendingCount;
    if (state == Parked) { ++g_parkedCount; ++g_units[r.unit].parked; }
    else if (state == Pending) ++g_pendingCount;
    r.state = state;
}
// Divert occupancy (puppet_divert_words active/peak), maintained at every divert transition.
void DivertOccupancy(int delta) {
    U* d = g_divert;
    d[DivertActive] += static_cast<U>(delta);
    if (d[DivertActive] > d[DivertActivePeak]) d[DivertActivePeak] = d[DivertActive];
}
bool Current(const Row& r) { return r.state == Parked && r.generation == g_units[r.unit].generation; }
// Hot path (every site-6 occurrence and every admitted-table common step): one +2C load and one bitset load; a set
// bit confirms the serial's row is parked for this very record.
Row* ParkedRow(U a) {
    const U serial = D(a + 0x2C);
    if (!ParkedBit(serial)) return nullptr;
    Row* r = Find(serial);
    return r && r->entity == a && Current(*r) ? r : nullptr;
}
bool WaitNode(U a) { return B(a + 0x2C4) == 1 && D(a + 0x22C) == g_waitVt && D(a + 0x230) == a; }
// Probe policy: no combat, target, charge, crew, rout or divert-controller (+628) state. Admission additionally starts
// with no active request sequence (+390); a repark may cancel one through begin's native stop transaction.
bool Eligible(U a, U unit, bool admission) {
    if (B(a + 0x30) != 1 || !IsInfantry(D(a)) || D(a + 0x1F0) != unit) return false;
    if (D(a + 0x628) || D(a + 0x18) || D(a + 0x1EC) || D(a + 0x4E8) || D(a + 0x66C)) return false;
    const U activity = D(a + 0x1B8), order = D(a + 0x1D8);
    if (D(a + 0x224) == 9 || activity == 0xD || activity == 0x4B || D(a + 0x220) == 2 || order == 0x3C || order == 0x3D)
        return false;
    if (B(a + 0x2C4) == 1 && D(a + 0x22C) == g_crewVt) return false;
    return !admission || !D(a + 0x390);
}
void Act(U row, U kind) { g_actions[g_actionCount++] = {row, kind}; }
// Ordered event chain of the determinism hash: (stage, serial, event) in the owner's order.
void Log(const Row& r, U event) { g_eventHash = Fnv(Fnv(Fnv(g_eventHash, g_stage), r.serial), event); ++g_mover[MoverEvents]; }
void HandBack(Row& r) {
    if (r.divert) DivertOccupancy(-1);
    SetState(r, Native); r.divert = 0; ++g_words[Handbacks]; ++g_units[r.unit].handed; Log(r, EvHandback);
}
void Rebase(Row& r) { r.ax = r.px = F(r.entity + 0x48); r.az = r.pz = F(r.entity + 0x50); }

// Stage buckets of the divert histogram: 1, 2-3, 4-7, ..., 1024-2047, >= 2048.
U DivertBucket(U stage) { U b = 0; while (b + 1 < kDivertBuckets && (stage >> (b + 1))) ++b; return b; }
// A +628 registration seen on a parked member (seam or site-6 occurrence): the event record and its histograms.
void DivertBegin(Row& r) {
    const U a = r.entity, controller = D(a + 0x628), kind = D(a + 0x62C);
    r.divert = 1; r.divertStage = g_stage; Log(r, EvDivertBegin); DivertOccupancy(1);
    U* d = g_divert;
    ++d[DivertEvents]; ++g_divertsThisStage;
    ++d[DivertKind + (kind < kDivertKinds - 1 ? kind : kDivertKinds - 1)];
    const U table = D(controller) - g_delta;
    if (table == kControllerSelf) ++d[DivertTableSelf];
    else if (table == kControllerNull) ++d[DivertTableNull];
    else { ++d[DivertTableOther]; d[DivertTableOtherVa] = table; }
    d[DivertLastKind] = kind; d[DivertLastActivity] = D(a + 0x630); d[DivertLastTable] = table;
    d[DivertLastTargetX] = D(a + 0x63C); d[DivertLastTargetZ] = D(a + 0x644);
    const float dx = F(a + 0x63C) - F(a + 0x48), dz = F(a + 0x644) - F(a + 0x50);
    if (Finite(dx) && Finite(dz)) {
        const U cm = Centimetres(dx, dz);
        g_divertTargetSum += cm; if (cm > d[DivertTargetMaxCm]) d[DivertTargetMaxCm] = cm;
        d[DivertTargetMeanCm] = static_cast<U>(g_divertTargetSum / d[DivertEvents]);
    }
    if (!d[DivertFirstStage]) d[DivertFirstStage] = g_stage;
    U* m = g_motion;
    if (!m[MotionDivertFirst]) m[MotionDivertFirst] = g_stage;
    m[MotionDivertLast] = g_stage; ++m[MotionDivertHist + DivertBucket(g_stage)];
}
// The controller released a parked member (+628 back to 0): close his divert motion sample and rebase his parked
// position; resume skipping with the surviving wait node, else repark or hand back in Apply.
void DivertEnd(Row& r, U index, U unit) {
    U* d = g_divert;
    r.divert = 0; ++d[DivertReleased]; Log(r, EvDivertEnd); DivertOccupancy(-1);
    const U duration = g_stage - r.divertStage;
    g_divertDurationSum += duration; if (duration > d[DivertDurationMax]) d[DivertDurationMax] = duration;
    d[DivertDurationMean] = static_cast<U>(g_divertDurationSum / d[DivertReleased]);
    const float x = F(r.entity + 0x48), z = F(r.entity + 0x50);
    if (Finite(x) && Finite(z) && (x != r.px || z != r.pz)) ++d[DivertMovedTicks];
    Rebase(r);
    if (WaitNode(r.entity) && !r.foreign) ++d[DivertResumed];
    else Act(index, Eligible(r.entity, unit, false) ? DivertRepark : DivertHandback);
}
void ClosePeakWindow() {
    U* m = g_motion;
    if (g_divertsThisStage > m[MotionDivertPeak]) { m[MotionDivertPeak] = g_divertsThisStage; m[MotionDivertPeakStage] = g_stage; }
    g_divertsThisStage = 0;
}

// Rejected unit: count its majority member class table (preferred VA) among the first kTopTables distinct tables.
void RecordRejectedTable(U list, U n) {
    U best = 0, bestCount = 0;
    for (U i = 0; i < n; ++i) {
        const U t = D(list + 4 * i) ? D(D(list + 4 * i)) : 0;
        U c = 0;
        for (U j = 0; j < n; ++j) if (D(list + 4 * j) && D(D(list + 4 * j)) == t) ++c;
        if (c > bestCount) { best = t; bestCount = c; }
    }
    if (!bestCount) return;
    const U va = best - g_delta;
    U* top = g_select + TopTables;
    for (U k = 0; k < g_topCount; ++k) if (top[2 * k] == va) { ++top[2 * k + 1]; return; }
    if (g_topCount == kTopTables) { ++g_select[TopOther]; return; }
    top[2 * g_topCount] = va; top[2 * g_topCount + 1] = 1; ++g_topCount;
}
bool Admissible(U m, U unit) {
    return IsInfantry(D(m)) && D(m + 0x1F0) == unit && !D(m + 0x66C) && !(B(m + 0x2C4) == 1 && D(m + 0x22C) == g_crewVt) &&
           D(m + 0x2C) < kSerialBits; // the gates' parked bit covers serials < 2^20 only
}
bool QualifyUnit(U unit, U ordinal, U army) {
    const U n = D(unit + 0x2CC), list = D(unit + 0x2D0), attached = D(unit + 0x1F4);
    U* s = g_select;
    if (!n || n > kMaxUnitMembers || !list) { ++s[RejectMemberCount]; return false; }
    U admissible = 0, reason = 0;
    for (U i = 0; i < n && !reason; ++i) {
        const U m = D(list + 4 * i);
        if (!m) { reason = RejectNullMember; break; }
        const U step = D(D(m) + 0xC) - g_delta;
        if (step == kArtilleryStep) reason = RejectArtillery;
        else if (step == kCavalryStep) reason = RejectCavalry;
        else admissible += Admissible(m, unit);
    }
    if (!reason && !admissible) reason = RejectNoInfantry;
    if (!reason && g_rowCount + n > kMaxRows) reason = RejectCapacity;
    if (reason) { ++s[reason]; if (reason != RejectNullMember) RecordRejectedTable(list, n); return false; }
    if (attached && D(attached + 0x10)) ++s[UnitsAttached]; // attached records are never touched
    const U ui = g_unitCount++;
    g_units[ui] = {unit, D(unit), ordinal, ++g_generation, 1, 0, 0, army, 0, 0};
    AddUnitIndex(unit, ui);
    bool first = true;
    for (U i = 0; i < n; ++i) {
        const U m = D(list + 4 * i), serial = D(m + 0x2C);
        if (Find(serial)) continue; // duplicate list entry
        const bool selected = Admissible(m, unit);
        if (Row* r = AddRow(m, serial, ui, selected ? Pending : Ignored)) r->seen = 0; // classified by this stage's import
        ++g_words[selected ? MembersSelected : MembersRejected];
        if (!selected) {
            if (!IsInfantry(D(m))) ++s[MemberOtherClass];
            else if (D(m + 0x1F0) != unit) ++s[MemberBacklink];
            else if (serial >= kSerialBits) ++s[SerialOutOfRange];
            else ++s[MemberCrew];
            continue;
        }
        if (D(m) != g_classVt) ++s[MemberAltTable];
        ++g_units[ui].members;
        if (first) { first = false; g_units[ui].x = D(m + 0x48); g_units[ui].z = D(m + 0x50); } // start position
    }
    ++g_words[UnitsSelected];
    return true;
}
void Select(U manager) {
    const U count = D(manager + 0x24C), data = D(manager + 0x250);
    if (!count || !data) return;
    memset(g_seenHash, 0, sizeof(g_seenHash));
    // One pass's diagnostics (a pass is retried every 64 stages while nothing qualified).
    for (U w = RejectMemberCount; w < RegistryInfantry; ++w) if (w != TablesPinned) g_select[w] = 0;
    g_topCount = 0;
    U seenCount = 0, armies[kMaxArmies], armyCount = 0, infantry = 0;
    for (U i = 0; i < count; ++i) {
        const U a = D(data + 4 * i);
        if (!a || !IsInfantry(D(a))) continue;
        ++infantry;
        if (g_unitCount >= g_requested || seenCount >= kMaxExamined) continue;
        const U unit = D(a + 0x1F0), army = D(a + 0x1F8);
        U k = 0;
        while (k < armyCount && armies[k] != army) ++k;
        if (army && k == armyCount && armyCount < kMaxArmies) armies[armyCount++] = army;
        if (!unit || !FirstSight(unit)) continue;
        ++seenCount; ++g_words[UnitsExamined];
        if (!QualifyUnit(unit, seenCount - 1, army ? (k < kMaxArmies ? k : kNoArmy) : kNoArmy)) ++g_words[UnitsRejected];
    }
    g_select[RegistryInfantry] = infantry;
    if (g_unitCount) g_selected = true;
}
bool SelectGuarded(U manager) {
    __try { Select(manager); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void Retire(U ui) {
    Unit& u = g_units[ui];
    u.active = 0; u.generation = ++g_generation; ++g_words[RetiredUnits];
    for (U i = 0; i < g_rowCount; ++i) {
        Row& r = g_rows[i];
        if (r.unit != ui) continue;
        if (r.state == Parked) HandBack(r);
        else if (r.state == Pending) SetState(r, Gone);
    }
}
void Depart(Row& r) {
    if (r.state != Parked && r.state != Pending) return;
    if (r.divert) { r.divert = 0; ++g_divert[DivertDeparted]; DivertOccupancy(-1); }
    SetState(r, Gone); ++g_words[DepartedMembers]; ++g_words[DeathsImported]; Log(r, EvDepart);
}
// Reads only, plus divert bookkeeping: classifies the live member lists into g_actions; native transactions run
// afterwards in Apply.
void Import() {
    for (U ui = 0; ui < g_unitCount; ++ui) {
        Unit& u = g_units[ui];
        if (!u.active) continue;
        const U n = D(u.handle + 0x2CC), list = D(u.handle + 0x2D0);
        if (D(u.handle) != u.vtable || n > kMaxUnitMembers || (n && !list)) { Retire(ui); continue; }
        for (U i = 0; i < n; ++i) {
            const U a = D(list + 4 * i);
            if (!a) continue;
            const U serial = D(a + 0x2C);
            Row* r = Find(serial);
            if (!r) { if (AddRow(a, serial, ui, Ignored)) ++g_words[JoinedMembers]; continue; }
            if (r->entity != a) { // serial now names another record: the old one departed
                Depart(*r);
                *r = {a, serial, ui, u.generation, Ignored, g_stage};
                ++g_words[JoinedMembers];
                continue;
            }
            if (r->seen == g_stage) continue; // duplicate entry this stage
            r->seen = g_stage;
            const U index = static_cast<U>(r - g_rows);
            if (r->unit != ui) { // moved between selected units
                if (r->state == Parked) Act(index, HandTransfer);
                else if (r->state == Pending) { SetState(*r, Ignored); ++g_words[TransfersImported]; }
                continue;
            }
            if (r->state == Parked) {
                if (D(a + 0x1F0) != u.handle) Act(index, HandTransfer);
                else if (D(a + 0x628)) { if (!r->divert) DivertBegin(*r); } // controller branch runs at site 6
                else if (r->divert) DivertEnd(*r, index, u.handle);
                else if (r->foreign || !WaitNode(a)) {
                    if (!r->foreign) { ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenSeam]; }
                    Act(index, Eligible(a, u.handle, false) ? Repark : HandIneligible);
                }
            } else if (r->state == Pending) {
                if (Eligible(a, u.handle, true)) Act(index, Admit);
                else ++g_words[AdmissionRefusals];
            }
        }
    }
    for (U i = 0; i < g_rowCount; ++i) {
        Row& r = g_rows[i];
        if (r.seen != g_stage && g_units[r.unit].active) Depart(r);
    }
}
bool ImportGuarded() {
    __try { Import(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Stats mode only, after Import: parked members confirmed in their unit's live list this stage. Did they get movement
// intent, did they move since the previous seam, how far from their admission position and from their delivered slot,
// and which skipped brain mechanics would have acted on them (mech_*). Diverted members only count their motion (the
// controller moves them natively).
void Motion() {
    U intent = 0, moved = 0, measured = 0, slotCount = 0, slotMismatch = 0, divertMoved = 0;
    unsigned long long dispSum = 0, slotSum = 0;
    U dispMax = 0, slotMax = 0;
    U* v = g_mover;
    for (U i = 0; i < g_rowCount; ++i) {
        Row& r = g_rows[i];
        if (!Current(r) || r.seen != g_stage) continue;
        const U a = r.entity;
        const float x = F(a + 0x48), z = F(a + 0x50);
        if (!Finite(x) || !Finite(z)) continue;
        const bool changed = x != r.px || z != r.pz;
        r.px = x; r.pz = z;
        if (r.divert) { divertMoved += changed; continue; }
        // Skipped brain prologue/epilogue mechanics (0x66CE00 @0x66CE7B and 0x66D439..0x66D6BB).
        const U ec = B(a + 0xEC), unit = D(a + 0x1F0), ref = D(a + 0x5B8), army = D(a + 0x1F8), f370 = D(a + 0x370);
        ++v[MechMemberTicks];
        v[Mech63C440] += ec == 1;
        v[MechFatigueFrozen] += f370 == r.f370; r.f370 = f370;
        v[MechRefHeading] += ref && (D(ref + 0x34) & 3);
        v[Mech602E00] += D(a + 0x518) != 0;
        v[MechF0] += ec == 1 && B(a + 0xA1) == 1 && unit && !D(a + 0x1EC);
        v[MechMeleeLabel] += ec == 1 && D(a + 0x1B8) == 0xD;
        v[MechF2] += army && D(army + 0x20F8);
        v[Mech639200] += ec != 0;
        v[Mech61C] += unit != 0;
        if (D(a + 0xD4) | D(a + 0xD8) | D(a + 0xDC)) ++intent; // any nonzero intent bits
        moved += changed; ++measured;
        const U disp = Centimetres(x - r.ax, z - r.az);
        dispSum += disp; if (disp > dispMax) dispMax = disp;
        if (B(a + 0x35B) == 1) { // watcher holder enabled: slot node at +2D4 carries the delivered slot descriptor
            if (D(a + 0x2D4) != g_slotVt) { ++slotMismatch; continue; }
            const float sx = F(a + 0x2F4), sz = F(a + 0x2FC);
            if (!Finite(sx) || !Finite(sz)) continue;
            const U slot = Centimetres(x - sx, z - sz);
            slotSum += slot; ++slotCount; if (slot > slotMax) slotMax = slot;
        }
    }
    U* m = g_motion;
    m[MotionIntentLast] = intent; m[MotionMovedLast] = moved;
    m[MotionIntentTicks] += intent; m[MotionMovedTicks] += moved;
    m[MotionDispMeanCm] = measured ? static_cast<U>(dispSum / measured) : 0; m[MotionDispMaxCm] = dispMax;
    m[MotionSlotMembers] = slotCount; m[MotionSlotMeanCm] = slotCount ? static_cast<U>(slotSum / slotCount) : 0;
    m[MotionSlotMaxCm] = slotMax; m[MotionSlotNodeOther] = slotMismatch;
    if (moved > m[MotionMovedPeak]) { m[MotionMovedPeak] = moved; m[MotionMovedPeakStage] = g_stage; }
    if (moved && !m[MotionFirstMoveStage]) m[MotionFirstMoveStage] = g_stage;
    g_divert[DivertMovedTicks] += divertMoved;
}
bool MotionGuarded() {
    __try { Motion(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void Apply() {
    for (U i = 0; i < g_actionCount; ++i) {
        Row& r = g_rows[g_actions[i].row];
        const U kind = g_actions[i].kind;
        if (kind == Admit || kind == Repark || kind == DivertRepark) {
            bool stopped = false;
            if (!Install(r.entity, stopped)) { RecordFault(FaultInstall); HandBack(r); continue; }
            ++g_words[stopped ? InstallStopped : InstallQuiet];
            if (kind == Admit) { ++g_words[MembersAdmitted]; Log(r, EvAdmit); }
            else { ++g_words[Reparks]; Log(r, EvRepark); }
            if (kind == DivertRepark) ++g_divert[DivertReparked];
            SetState(r, Parked); r.foreign = 0; r.generation = g_units[r.unit].generation;
            if (kind != Repark) Rebase(r);
            continue;
        }
        if (kind == HandTransfer && r.divert) ++g_divert[DivertDeparted]; // left the unit while diverted
        HandBack(r);
        if (kind == DivertHandback) { ++g_words[DivertedHandbacks]; ++g_divert[DivertHandedBack]; }
        else if (kind == HandTransfer) ++g_words[TransfersImported];
        else ++g_words[IneligibleHandbacks];
    }
}
void Publish() {
    g_words[MembersParked] = g_parkedCount; g_words[MembersPending] = g_pendingCount;
    if (g_parkedCount > g_words[ParkedPeak]) g_words[ParkedPeak] = g_parkedCount;
    for (U ui = 0; ui < g_unitCount && ui < kRowUnits; ++ui) {
        const Unit& u = g_units[ui];
        U* row = g_words + UnitRows + 4 * ui;
        row[0] = (u.ordinal & 0xFFF) | (u.army & 0xF) << 12 | (u.members & 0xFFFF) << 16;
        row[1] = (u.parked & 0xFFFF) | (u.handed & 0xFFFF) << 16;
        row[2] = u.x; row[3] = u.z;
    }
}
void Disable(U code) {
    RecordFault(code); g_disabled = true;
    for (U i = 0; i < g_rowCount; ++i) if (g_rows[i].state == Parked) HandBack(g_rows[i]);
}
void OriginalLoop(U manager) {
    U cursor = D(manager + 0x264), end = cursor + 4 * D(manager + 0x260);
    while (cursor != end) {
        const U a = D(cursor);
        if (B(a + 0x30) == 1) Call(D(D(a) + 0xC), a);
        cursor += 4;
        end = D(manager + 0x264) + 4 * D(manager + 0x260);
    }
}
} // namespace

bool Install(U a, bool& stopped) {
    stopped = false;
    U ignored = 0; // 0x7FF5C0 passes the address of a stack byte; 0x650600 forwards it to the constructor unread
    reinterpret_cast<void (__thiscall*)(U, U)>(static_cast<uintptr_t>(D(D(a) + 0x134)))(a, static_cast<U>(
        reinterpret_cast<uintptr_t>(&ignored)));
    // Holder protocol of the common step, 0x670EED..0x670F24, exactly once.
    const U node = a + 0x22C;
    if (B(a + 0x2C4) == 1 && !B(node + 8)) {
        bool step = true;
        if (!B(node + 0x10)) {
            Call(D(D(node) + 4), node);
            const bool done = B(node + 8) != 0;
            W8(node + 0x10, 1);
            if (done) step = false; else stopped = true;
        }
        if (step) { Call(D(D(node) + 8), node); W32(node + 0xC, D(node + 0xC) + 1); }
    }
    return WaitNode(a) && D(node + 0x14) == D(a + 0x2C8);
}
bool WaitNodeInstalled(U a) { return WaitNode(a); }

bool Start(const Binding& binding) {
    Stop(); Reset(); // activation: fresh membership and counters (retained after Stop until the next Start)
    if (!binding.image_base || !binding.units || binding.units > kMaxUnits || !binding.tick_owner ||
        !binding.epoch_mask || !binding.epoch_bit) return false;
    if (!g_store) {
        g_store = static_cast<Storage*>(VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_store) return false;
        g_rows = g_store->rows; g_hash = g_store->hash; g_actions = g_store->actions; // zero-filled by the allocator
        g_parked = g_store->parked;
    }
    g_tickOwner = binding.tick_owner; g_epochMask = binding.epoch_mask; g_epochBit = binding.epoch_bit;
    g_delta = binding.image_base - 0x400000;
    g_classVt = V(kClassTable); g_waitVt = V(kWaitTable); g_crewVt = V(kCrewNode); g_slotVt = V(kSlotNodeTable);
    // Pin the class and node contracts this module relies on; +08 is pinned by the runtime's slot swap.
    if (D(g_classVt + 0xC) != V(kBrainStep) || D(g_classVt + 0x134) != V(kWaitInstall) ||
        D(g_waitVt + 4) != V(kWaitBegin) || D(g_waitVt + 8) != V(kWaitStep)) return false;
    // Alternative infantry tables: admitted only when every slot this module and the native paths rely on is
    // identical to 0x1333714's.
    static const U kPinnedSlots[] = {0x08, 0x0C, 0x130, 0x134, 0x188, 0x1A4, 0x1A8, 0x108, 0xB8, 0xFC};
    g_tableCount = 0;
    for (U t : kInfantryTables) {
        bool same = true;
        for (U slot : kPinnedSlots) same = same && D(V(t) + slot) == D(g_classVt + slot);
        if (same) g_tables[g_tableCount++] = V(t);
    }
    g_select[TablesPinned] = g_tableCount;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_frequency = f.QuadPart ? f.QuadPart : 1;
    g_requested = binding.units;
    g_words[UnitsRequested] = binding.units;
    g_stats = binding.stats; g_mover[MoverStatsMode] = binding.stats ? 1 : 0;
    g_qpc0 = Now(); g_tsc0 = __rdtsc();
    g_started = true;
    return true;
}
void Stop() {
    if (!g_started) return;
    ClosePeakWindow();
    for (U i = 0; i < g_rowCount; ++i)
        if (g_rows[i].state == Parked) { HandBack(g_rows[i]); ++g_words[StopHandbacks]; }
    Publish();
    g_started = false;
}
void Reset() {
    g_started = g_selected = g_disabled = false;
    g_stage = g_generation = g_unitCount = g_actionCount = g_parkedCount = g_pendingCount = 0;
    g_adapterTicks = 0; g_dispatchCycles = 0; g_sampleSeq = 0;
    g_divertTargetSum = g_divertDurationSum = g_moverUsTotal = 0; g_eventHash = 2166136261u; g_moverStage = 0;
    memset(g_words, 0, sizeof(g_words)); memset(g_units, 0, sizeof(g_units)); memset(g_motion, 0, sizeof(g_motion));
    memset(g_divert, 0, sizeof(g_divert)); memset(g_mover, 0, sizeof(g_mover)); memset(g_unitHash, 0, sizeof(g_unitHash));
    memset(g_select, 0, sizeof(g_select)); g_topCount = 0;
    g_divertsThisStage = 0;
    if (g_store) {
        memset(g_rows, 0, g_rowCount * sizeof(Row)); memset(g_hash, 0, sizeof(g_store->hash));
        memset(g_parked, 0, sizeof(g_store->parked));
    }
    g_rowCount = 0;
}
bool Started() { return g_started; }

// Publishes the window that ends at this seam: dispatch cycles sampled 1/64 are scaled by 64 and converted with the
// TSC rate measured against QPC since Start (no estimate until 1 ms has elapsed).
static void PublishWindow(LONGLONG qpcNow) {
    const unsigned long long tsc = __rdtsc(), cycles = g_dispatchCycles;
    g_dispatchCycles = 0;
    const LONGLONG qpc = qpcNow - g_qpc0;
    if (qpc >= g_frequency / 1000 && tsc > g_tsc0) {
        const double tscPerUs = static_cast<double>(tsc - g_tsc0) * 1e-6 * static_cast<double>(g_frequency) /
                                static_cast<double>(qpc);
        const U us = static_cast<U>(static_cast<double>(cycles) * (kSampleMask + 1) / tscPerUs);
        g_words[DispatchUsLast] = us; g_words[DispatchUsTotal] += us;
    }
}
void Stage(U manager) {
    if (!g_started) { OriginalLoop(manager); return; }
    const LONGLONG begin = Now();
    if (g_stats) PublishWindow(begin);
    if (g_stage) {
        // Parked members that had no class common step since the previous seam (the window just closed).
        if (g_stats)
            for (U i = 0; i < g_rowCount; ++i)
                if (Current(g_rows[i]) && g_rows[i].commonStage != g_stage) ++g_words[ParkedNoCommonTicks];
        ClosePeakWindow(); // divert events of the previous stage (its seam and loop)
    }
    ++g_stage; ++g_words[Stages];
    if (!g_disabled) {
        g_actionCount = 0;
        if (!g_selected && (g_stage == 1 || !(g_stage & 63)) && !SelectGuarded(manager)) Disable(FaultSelectRead);
        else if (!ImportGuarded()) Disable(FaultImportRead);
        else {
            if (g_stats && !MotionGuarded()) RecordFault(FaultMotionRead); // diagnostics only: control continues
            Apply();
        }
        Publish();
    }
    g_adapterTicks += Now() - begin;
    const U us = static_cast<U>(g_adapterTicks * 1000000 / g_frequency);
    g_adapterTicks = 0;
    g_words[AdapterUsLast] = us; g_words[AdapterUsTotal] += us;
    if (us > g_words[AdapterUsMax]) g_words[AdapterUsMax] = us;
    U cursor = D(manager + 0x264), end = cursor + 4 * D(manager + 0x260), skipped = 0, occurrences = 0, diverted = 0;
    if (g_stats) { // diagnostics: sampled dispatch cost of the membership test
        while (cursor != end) {
            const U a = D(cursor);
            if (B(a + 0x30) == 1) {
                ++occurrences;
                const bool sample = !(++g_sampleSeq & kSampleMask);
                const unsigned long long t0 = sample ? __rdtsc() : 0;
                Row* r = g_disabled ? nullptr : ParkedRow(a);
                const bool divert = r && D(a + 0x628);
                const bool skip = r && !divert && WaitNode(a);
                if (sample) { g_dispatchCycles += __rdtsc() - t0; ++g_words[DispatchSamples]; }
                if (skip) ++skipped;
                else {
                    if (divert) { // native controller branch 0x67A050
                        if (!r->divert) { const LONGLONG t = Now(); DivertBegin(*r); g_adapterTicks += Now() - t; }
                        ++diverted;
                    }
                    else if (r && !r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenLoop]; }
                    Call(D(D(a) + 0xC), a);
                }
            }
            cursor += 4;
            end = D(manager + 0x264) + 4 * D(manager + 0x260);
        }
    } else { // production stats: the parked-bit test and the native calls only
        while (cursor != end) {
            const U a = D(cursor);
            if (B(a + 0x30) == 1) {
                ++occurrences;
                Row* r = g_disabled ? nullptr : ParkedRow(a);
                if (r && !D(a + 0x628) && WaitNode(a)) ++skipped;
                else {
                    if (r && D(a + 0x628)) { if (!r->divert) DivertBegin(*r); ++diverted; }
                    else if (r && !r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenLoop]; }
                    Call(D(D(a) + 0xC), a);
                }
            }
            cursor += 4;
            end = D(manager + 0x264) + 4 * D(manager + 0x260);
        }
    }
    g_words[SkippedNativeSteps] += skipped; g_words[ParkedMemberTicks] += g_words[MembersParked];
    g_words[LoopOccurrences] += occurrences; g_divert[DivertNativeSteps] += diverted;
}
bool CommonStep(U a, U ret) {
    // Two loads and a TEB read: outside the tick owner's puppet epoch nothing is touched (not even a counter).
    if (!g_started || static_cast<U>(*g_tickOwner) != __readfsdword(0x24) || !(*g_epochMask & g_epochBit)) return false;
    if (!g_stats) { // production stats: parked-bit test, node test, native calls
        Row* r = g_disabled ? nullptr : ParkedRow(a);
        if (!r || D(a + 0x628)) return false;
        if (!WaitNode(a)) {
            if (!r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenCommon]; }
            return false;
        }
        Call(V(kTerrain), a);
        Call(V(kActivity), a);
        return true;
    }
    ++g_words[CommonCalls];
    const bool sample = !(++g_sampleSeq & kSampleMask);
    const unsigned long long t0 = sample ? __rdtsc() : 0;
    bool gated = false;
    if (sample) g_words[CommonCallerVa] = ret - g_delta;
    if (!g_disabled) {
        if (Row* r = ParkedRow(a)) { // a clear parked bit ends here after two loads
            ++g_words[CommonMemberCalls]; g_words[MemberCallerVa] = ret - g_delta;
            r->commonStage = g_stage;
            if (D(a + 0x628)) ++g_divert[DivertCommonForwarded]; // controller branch: native step
            else if (WaitNode(a)) gated = true;
            else {
                ++g_words[CommonParkedForwarded];
                if (!r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenCommon]; }
            }
        }
    }
    if (sample) { g_dispatchCycles += __rdtsc() - t0; ++g_words[DispatchSamples]; }
    if (!gated) return false;
    const LONGLONG begin = Now();
    Call(V(kTerrain), a);
    Call(V(kActivity), a);
    g_adapterTicks += Now() - begin;
    ++g_words[GatedCommonSteps];
    return true;
}
void Snapshot(U* words) {
    memcpy(words, g_words, sizeof(g_words));
    words[Version] = kVersion; words[Enabled] = g_started && !g_disabled;
}
void SnapshotMotion(U* words) {
    memcpy(words, g_motion, sizeof(g_motion));
    words[MotionVersion] = kMotionVersion;
}
void SnapshotDivert(U* words) {
    memcpy(words, g_divert, sizeof(g_divert));
    words[DivertVersion] = kDivertVersion;
}
U StorageBytes() { return g_store ? static_cast<U>(sizeof(Storage)) : 0; }
U RequiredStorageBytes() { return static_cast<U>(sizeof(Storage)); }
void SnapshotMover(U* words) {
    memcpy(words, g_mover, sizeof(g_mover));
    words[MoverVersion] = kMoverVersion;
}
void SnapshotSelect(U* words) {
    memcpy(words, g_select, sizeof(g_select));
    words[SelectVersion] = kSelectVersion;
}

bool PointMove(U a) {
    const U kind = D(a + 0x62C), controller = D(a + 0x628);
    // Contract domain (native_puppet.h "PointMove"); outside it nothing is written.
    if (kind > 1 || B(a + 0xEC) != 1 || !controller || D(controller) != V(kControllerNull) || B(a + 0x65C) == 1 ||
        (!D(a + 0x224) && B(a + 0x478) == 1) || (kind == 0 && D(a + 0x630) == 0x1D)) return false;
    // 0x67A05D: 0x7FD9E0(0x20) clears bit 5 of +34/+38.
    W32(a + 0x34, D(a + 0x34) & ~0x20u); W32(a + 0x38, D(a + 0x38) & ~0x20u);
    // 0x67A272..0x67A2F5: drop the action row and its marker word; labels from the controller (kind 1: none/1).
    W32(a + 0x444, 0); W16(a + 0x458, 0);
    if (kind == 1) { W32(a + 0x1B8, 0); W32(a + 0x1BC, 1); }
    else { W32(a + 0x1C0, D(a + 0x638)); W32(a + 0x1B8, D(a + 0x630)); W32(a + 0x1BC, D(a + 0x634)); }
    // 0x67A326..0x67A3DC: step toward the target from the position plus pending intent, bounded by the speed state.
    const float x = F(a + 0x48), z = F(a + 0x50), cap = F(a + 0x64C);
    float dx = F(a + 0x63C) - (F(a + 0xD4) + x), dz = F(a + 0x644) - (F(a + 0xDC) + z);
    const float dist = sqrtf(dx * dx + dz * dz);
    const float speed = F(a + 0x650) * kDt + F(a + 0x194);
    float step = speed;
    WF(a + 0x194, speed);
    if (0.0f > speed) { WF(a + 0x194, 0.0f); step = 0.0f; } // 0x67A3A5..0x67A3AF: stopped, zero step
    else if (speed > cap) { WF(a + 0x194, cap); step = cap; }
    step *= kDt;
    if (dist > step) { const float f = step / dist; dz *= f; dx *= f; }
    // 0x67A3DC..0x67A4DB: heading toward +648, limited by min(+654*dt, 3.11 rad) in heading words.
    float turn = F(a + 0x654) * kDt;
    turn = turn < kMaxTurnPerTick ? turn : kMaxTurnPerTick; // minss: equal or NaN -> the constant
    turn *= kHeadingPerRadian;
    const int maxTurn = _mm_cvt_ss2si(_mm_set_ss(turn)); // fistp, round to nearest
    const U current = H(a + 0x64);
    const int diff = S16(H(a + 0x648) - current), low = S16(static_cast<U>(-maxTurn)), high = S16(static_cast<U>(maxTurn));
    const U delta = diff < low ? static_cast<U>(-maxTurn) : (high < diff ? static_cast<U>(maxTurn) : static_cast<U>(diff));
    const float target[2] = {dx + x, dz + z};
    const bool written = !D(a + 0x18);
    reinterpret_cast<void (__thiscall*)(U, const float*, U)>(static_cast<uintptr_t>(V(kIntentWriter)))(
        a, target, (delta + current) & 0xFFFF);
    W8(a + 0xD0, 0); // 0x67A4E5: the point move owns its speed bound (no 0x7F08F0 overspeed clamp)
    if (D(a + 0x658) < 0x10000) W32(a + 0x3C, D(a + 0x658)); // 0x67A4F3..0x67A500
    return written;
}

void Move() {
    if (!g_started || g_disabled || !g_stage || !g_stats) return; // production stats: no hash pass
    const LONGLONG begin = Now();
    U* m = g_mover;
    ++g_moverStage; ++m[MoverStages];
    U hash = Fnv(Fnv(2166136261u, g_stage), g_eventHash), parked = 0, diverted = 0, waiting = 0, waitingMax = 0;
    unsigned long long waitingSum = 0;
    __try {
        for (U i = 0; i < g_rowCount; ++i) {
            const Row& r = g_rows[i];
            if (!Current(r) || r.seen != g_stage) continue;
            const U a = r.entity;
            ++parked; diverted += r.divert;
            // Delivered slot node (0x6529B0 -> 0x7E3D50), holder enabled, not begun (node+10 = A+2E4): the engine
            // wants this man to walk to A+2F4/A+2FC.
            if (!r.divert && D(a + 0x2D4) == g_slotVt && B(a + 0x35B) == 1 && !B(a + 0x2E4)) {
                const float dx = F(a + 0x2F4) - F(a + 0x48), dz = F(a + 0x2FC) - F(a + 0x50);
                if (Finite(dx) && Finite(dz)) {
                    const U cm = Centimetres(dx, dz);
                    ++waiting; waitingSum += cm; if (cm > waitingMax) waitingMax = cm;
                }
            }
            hash = Fnv(Fnv(hash, r.serial), r.divert);
            hash = Fnv(Fnv(Fnv(hash, D(a + 0x48)), D(a + 0x4C)), D(a + 0x50));
            hash = Fnv(Fnv(Fnv(hash, H(a + 0x64)), D(a + 0xD4)), D(a + 0xDC));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Disable(FaultMoveRead);
    }
    m[MoverParkedHashed] = parked; m[MoverDiverted] = diverted;
    m[MoverSlotWaiting] = waiting; m[MoverSlotWaitingTicks] += waiting;
    m[MoverSlotWaitingMeanCm] = waiting ? static_cast<U>(waitingSum / waiting) : 0; m[MoverSlotWaitingMaxCm] = waitingMax;
    m[MoverHashLast] = hash; m[MoverHashChain] = Fnv(m[MoverHashChain], hash);
    if (g_moverStage == 64) m[MoverHashS64] = m[MoverHashChain];
    else if (g_moverStage == 256) m[MoverHashS256] = m[MoverHashChain];
    else if (g_moverStage == 1024) m[MoverHashS1024] = m[MoverHashChain];
    else if (g_moverStage == 4096) m[MoverHashS4096] = m[MoverHashChain];
    const U us = static_cast<U>((Now() - begin) * 1000000 / g_frequency);
    m[MoverUsLast] = us; if (us > m[MoverUsMax]) m[MoverUsMax] = us;
    g_moverUsTotal += us; m[MoverUsTotal] = static_cast<U>(g_moverUsTotal);
}
} // namespace ntw2_puppet
