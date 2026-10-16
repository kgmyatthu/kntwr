// Puppet survival probe stage 1 (native_puppet.h). Owner thread only; native transactions are the engine's own code.
#include "native_puppet.h"
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <math.h>

namespace ntw2_puppet {
namespace {
static_assert(sizeof(void*) == 4, "puppet probe ABI is Win32");
constexpr const char* kLabels[] = { NTW2_PUPPET_WORD_LABELS };
static_assert(sizeof(kLabels) / sizeof(kLabels[0]) == kWords, "one label per puppet status word");

// Approved-image preferred VAs (SHA-256 13fcab62...).
constexpr U kClassTable = 0x1333714, kWaitTable = 0x1334028, kCrewNode = 0x133AE34;
constexpr U kWaitInstall = 0x650600, kWaitBegin = 0x665E30, kWaitStep = 0x66DCF0, kCommonStep = 0x670EB0;
constexpr U kBrainStep = 0x66CE00, kTerrain = 0x81AC80, kActivity = 0x663730;
constexpr U kArtilleryStep = 0x6F4660, kCavalryStep = 0x602EB0;
constexpr U kHash = 8192, kMaxExamined = 512, kNone = ~0u, kMaxArmies = kPuppetNoArmy, kNoArmy = kPuppetNoArmy;
constexpr U kSlotNodeTable = 0x13472A4; // node constructed at A+2D4 by 0x7E3D50 from the 0x581513 slot descriptor

enum State : U { Free, Ignored, Pending, Parked, Native, Gone };
enum Kind : U { Admit, Repark, HandDiverted, HandTransfer, HandIneligible };
// ax/az: position at admission; px/pz: position at the previous motion sample (parked members only).
struct Row { U entity, serial, unit, generation, state, seen, foreign, commonStage; float ax, az, px, pz; };
// handle/vtable/ordinal/generation/active identify the unit; members/handed/army/x/z are its published identity row.
struct Unit { U handle, vtable, ordinal, generation, active, members, handed, army, x, z; };
struct Action { U row, kind; };

U g_delta, g_requested, g_classVt, g_waitVt, g_crewVt, g_stage, g_generation, g_unitCount, g_rowCount, g_actionCount;
bool g_started, g_selected, g_disabled;
U g_words[kWords], g_motion[kMotionWords], g_divertsThisStage;
Unit g_units[kMaxUnits];
Row g_rows[kMaxRows];
uint16_t g_hash[kHash];
Action g_actions[kMaxRows];
LONGLONG g_adapterTicks, g_frequency, g_qpc0;
unsigned long long g_tsc0, g_dispatchCycles;
U g_sampleSeq, g_epochBit, g_slotVt;
const volatile long* g_tickOwner;
const volatile U* g_epochMask;

inline U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
inline void W8(U a, U v) { *reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(a)) = static_cast<uint8_t>(v); }
inline void W32(U a, U v) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a)) = v; }
inline U V(U va) { return va + g_delta; }
inline void Call(U target, U self) { reinterpret_cast<void (__thiscall*)(U)>(static_cast<uintptr_t>(target))(self); }
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }

U HashSlot(U serial) { return (serial * 2654435761u) & (kHash - 1); }
Row* Find(U serial) {
    for (U slot = HashSlot(serial), n = 0; n < kHash; ++n, slot = (slot + 1) & (kHash - 1)) {
        const U index = g_hash[slot];
        if (!index) return nullptr;
        if (g_rows[index - 1].serial == serial) return &g_rows[index - 1];
    }
    return nullptr;
}
Row* AddRow(U entity, U serial, U unit, U state) {
    if (g_rowCount == kMaxRows) return nullptr;
    U slot = HashSlot(serial);
    while (g_hash[slot]) slot = (slot + 1) & (kHash - 1); // load <= 1/2: never full
    Row& r = g_rows[g_rowCount];
    r = {entity, serial, unit, g_units[unit].generation, state, g_stage, 0, 0};
    g_hash[slot] = static_cast<uint16_t>(++g_rowCount);
    return &r;
}
void RecordFault(U code) { ++g_words[Faults]; g_words[LastFault] = code; }

// Hot path (every site-6 occurrence and every class common step): class table, then the <= 4 unit handles, then the
// serial row. A non-infantry record costs one compare; an infantry record outside the cohort a <= 4-entry scan.
Row* MemberRow(U a) {
    if (D(a) != g_classVt) return nullptr;
    const U unit = D(a + 0x1F0);
    U ui = 0;
    while (ui < g_unitCount && !(g_units[ui].active && g_units[ui].handle == unit)) ++ui;
    if (ui == g_unitCount) return nullptr;
    Row* r = Find(D(a + 0x2C));
    return r && r->entity == a && r->unit == ui ? r : nullptr;
}
bool Current(const Row& r) { return r.state == Parked && r.generation == g_units[r.unit].generation; }
Row* ParkedRow(U a) {
    Row* r = MemberRow(a);
    return r && Current(*r) ? r : nullptr;
}
bool WaitNode(U a) { return B(a + 0x2C4) == 1 && D(a + 0x22C) == g_waitVt && D(a + 0x230) == a; }
// Probe policy: no combat, target, charge, crew, rout or divert-controller (+628) state. Admission additionally starts
// with no active request sequence (+390); a repark may cancel one through begin's native stop transaction.
bool Eligible(U a, U unit, bool admission) {
    if (B(a + 0x30) != 1 || D(a) != g_classVt || D(a + 0x1F0) != unit) return false;
    if (D(a + 0x628) || D(a + 0x18) || D(a + 0x1EC) || D(a + 0x4E8) || D(a + 0x66C)) return false;
    const U activity = D(a + 0x1B8), order = D(a + 0x1D8);
    if (D(a + 0x224) == 9 || activity == 0xD || activity == 0x4B || D(a + 0x220) == 2 || order == 0x3C || order == 0x3D)
        return false;
    if (B(a + 0x2C4) == 1 && D(a + 0x22C) == g_crewVt) return false;
    return !admission || !D(a + 0x390);
}
void Act(U row, U kind) { g_actions[g_actionCount++] = {row, kind}; }
void HandBack(Row& r) { r.state = Native; ++g_words[Handbacks]; ++g_units[r.unit].handed; }

bool QualifyUnit(U unit, U ordinal, U army) {
    const U n = D(unit + 0x2CC), list = D(unit + 0x2D0), attached = D(unit + 0x1F4);
    if (!n || n > kMaxUnitMembers || !list || (attached && D(attached + 0x10))) return false;
    U infantry = 0;
    for (U i = 0; i < n; ++i) {
        const U m = D(list + 4 * i);
        if (!m) return false;
        const U table = D(m), step = D(table + 0xC) - g_delta;
        if (step == kArtilleryStep || step == kCavalryStep || D(m + 0x66C) ||
            (B(m + 0x2C4) == 1 && D(m + 0x22C) == g_crewVt)) return false;
        if (table == g_classVt) {
            if (D(m + 0x1F0) != unit) return false;
            ++infantry;
        }
    }
    if (infantry * 2 <= n || g_rowCount + n > kMaxRows) return false;
    const U ui = g_unitCount++;
    g_units[ui] = {unit, D(unit), ordinal, ++g_generation, 1, 0, 0, army, 0, 0};
    bool first = true;
    for (U i = 0; i < n; ++i) {
        const U m = D(list + 4 * i), serial = D(m + 0x2C);
        if (Find(serial)) continue; // duplicate list entry
        const bool selected = D(m) == g_classVt;
        if (Row* r = AddRow(m, serial, ui, selected ? Pending : Ignored)) r->seen = 0; // classified by this stage's import
        ++g_words[selected ? MembersSelected : MembersRejected];
        if (!selected) continue;
        ++g_units[ui].members;
        if (first) { first = false; g_units[ui].x = D(m + 0x48); g_units[ui].z = D(m + 0x50); } // start position
    }
    ++g_words[UnitsSelected];
    return true;
}
void Select(U manager) {
    const U count = D(manager + 0x24C), data = D(manager + 0x250);
    if (!count || !data) return;
    U seen[kMaxExamined], seenCount = 0, armies[kMaxArmies], armyCount = 0;
    for (U i = 0; i < count && g_unitCount < g_requested && seenCount < kMaxExamined; ++i) {
        const U a = D(data + 4 * i);
        if (!a || D(a) != g_classVt) continue;
        const U unit = D(a + 0x1F0), army = D(a + 0x1F8);
        U k = 0;
        while (k < armyCount && armies[k] != army) ++k;
        if (army && k == armyCount && armyCount < kMaxArmies) armies[armyCount++] = army;
        if (!unit) continue;
        U j = 0;
        while (j < seenCount && seen[j] != unit) ++j;
        if (j < seenCount) continue;
        seen[seenCount++] = unit; ++g_words[UnitsExamined];
        if (!QualifyUnit(unit, seenCount - 1, army ? (k < kMaxArmies ? k : kNoArmy) : kNoArmy)) ++g_words[UnitsRejected];
    }
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
        else if (r.state == Pending) r.state = Gone;
    }
}
void Depart(Row& r) {
    if (r.state != Parked && r.state != Pending) return;
    r.state = Gone; ++g_words[DepartedMembers]; ++g_words[DeathsImported];
}
// Reads only: classifies the live member lists into g_actions. Native transactions run afterwards in Apply.
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
                *r = {a, serial, ui, u.generation, Ignored, g_stage, 0, 0};
                ++g_words[JoinedMembers];
                continue;
            }
            if (r->seen == g_stage) continue; // duplicate entry this stage
            r->seen = g_stage;
            const U index = static_cast<U>(r - g_rows);
            if (r->unit != ui) { // moved between selected units
                if (r->state == Parked) Act(index, HandTransfer);
                else if (r->state == Pending) { r->state = Ignored; ++g_words[TransfersImported]; }
                continue;
            }
            if (r->state == Parked) {
                if (D(a + 0x628)) Act(index, HandDiverted); // divert controller; deaths come from the membership diff
                else if (D(a + 0x1F0) != u.handle) Act(index, HandTransfer);
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
inline float F(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Finite(float v) { return v - v == 0.0f; }
inline U Centimetres(float dx, float dz) { return static_cast<U>(sqrtf(dx * dx + dz * dz) * 100.0f + 0.5f); }
// Reads only, after Import: parked members confirmed in their unit's live list this stage. Did they get movement intent,
// did they move since the previous seam, how far from their admission position and from their delivered slot.
void Motion() {
    U intent = 0, moved = 0, measured = 0, slotCount = 0, slotMismatch = 0;
    unsigned long long dispSum = 0, slotSum = 0;
    U dispMax = 0, slotMax = 0;
    for (U i = 0; i < g_rowCount; ++i) {
        Row& r = g_rows[i];
        if (!Current(r) || r.seen != g_stage) continue;
        const U a = r.entity;
        if (D(a + 0xD4) | D(a + 0xD8) | D(a + 0xDC)) ++intent;   // any nonzero intent bits
        const float x = F(a + 0x48), z = F(a + 0x50);
        if (!Finite(x) || !Finite(z)) continue;
        if (x != r.px || z != r.pz) ++moved;
        r.px = x; r.pz = z; ++measured;
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
}
bool MotionGuarded() {
    __try { Motion(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Stage buckets of the divert histogram: 1, 2-3, 4-7, ..., 1024-2047, >= 2048.
U DivertBucket(U stage) { U b = 0; while (b + 1 < kDivertBuckets && (stage >> (b + 1))) ++b; return b; }
void Apply() {
    for (U i = 0; i < g_actionCount; ++i) {
        Row& r = g_rows[g_actions[i].row];
        const U kind = g_actions[i].kind;
        if (kind == Admit || kind == Repark) {
            bool stopped = false;
            if (!Install(r.entity, stopped)) { RecordFault(FaultInstall); HandBack(r); continue; }
            ++g_words[stopped ? InstallStopped : InstallQuiet];
            if (kind == Admit) {
                ++g_words[MembersAdmitted];
            } else ++g_words[Reparks];
            r.state = Parked; r.foreign = 0; r.generation = g_units[r.unit].generation;
            if (kind == Admit) { r.ax = r.px = F(r.entity + 0x48); r.az = r.pz = F(r.entity + 0x50); }
            continue;
        }
        HandBack(r);
        if (kind == HandDiverted) {
            ++g_words[DivertedHandbacks]; ++g_divertsThisStage;
            U* m = g_motion;
            if (!m[MotionDivertFirst]) m[MotionDivertFirst] = g_stage;
            m[MotionDivertLast] = g_stage; ++m[MotionDivertHist + DivertBucket(g_stage)];
        }
        else if (kind == HandTransfer) ++g_words[TransfersImported];
        else ++g_words[IneligibleHandbacks];
    }
}
void Publish() {
    U parked = 0, pending = 0, perUnit[kMaxUnits] = {};
    for (U i = 0; i < g_rowCount; ++i) {
        if (g_rows[i].state == Parked) { ++parked; ++perUnit[g_rows[i].unit]; }
        else if (g_rows[i].state == Pending) ++pending;
    }
    g_words[MembersParked] = parked; g_words[MembersPending] = pending;
    if (parked > g_words[ParkedPeak]) g_words[ParkedPeak] = parked;
    for (U ui = 0; ui < g_unitCount; ++ui) {
        const Unit& u = g_units[ui];
        U* row = g_words + UnitRows + 4 * ui;
        row[0] = (u.ordinal & 0xFFF) | (u.army & 0xF) << 12 | (u.members & 0xFFFF) << 16;
        row[1] = (perUnit[ui] & 0xFFFF) | (u.handed & 0xFFFF) << 16;
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
    g_tickOwner = binding.tick_owner; g_epochMask = binding.epoch_mask; g_epochBit = binding.epoch_bit;
    g_delta = binding.image_base - 0x400000;
    g_classVt = V(kClassTable); g_waitVt = V(kWaitTable); g_crewVt = V(kCrewNode); g_slotVt = V(kSlotNodeTable);
    // Pin the class and node contracts this module relies on; +08 is pinned by the runtime's slot swap.
    if (D(g_classVt + 0xC) != V(kBrainStep) || D(g_classVt + 0x134) != V(kWaitInstall) ||
        D(g_waitVt + 4) != V(kWaitBegin) || D(g_waitVt + 8) != V(kWaitStep)) return false;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_frequency = f.QuadPart ? f.QuadPart : 1;
    g_requested = binding.units;
    g_words[UnitsRequested] = binding.units;
    g_qpc0 = Now(); g_tsc0 = __rdtsc();
    g_started = true;
    return true;
}
void Stop() {
    if (!g_started) return;
    for (U i = 0; i < g_rowCount; ++i)
        if (g_rows[i].state == Parked) { HandBack(g_rows[i]); ++g_words[StopHandbacks]; }
    Publish();
    g_started = false;
}
void Reset() {
    g_started = g_selected = g_disabled = false;
    g_stage = g_generation = g_unitCount = g_rowCount = g_actionCount = 0;
    g_adapterTicks = 0; g_dispatchCycles = 0; g_sampleSeq = 0;
    memset(g_words, 0, sizeof(g_words)); memset(g_units, 0, sizeof(g_units)); memset(g_motion, 0, sizeof(g_motion));
    g_divertsThisStage = 0;
    memset(g_rows, 0, sizeof(g_rows)); memset(g_hash, 0, sizeof(g_hash));
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
    PublishWindow(begin);
    // Parked members that had no class common step since the previous seam (the window just closed).
    if (g_stage) for (U i = 0; i < g_rowCount; ++i)
        if (Current(g_rows[i]) && g_rows[i].commonStage != g_stage) ++g_words[ParkedNoCommonTicks];
    ++g_stage; ++g_words[Stages];
    if (!g_disabled) {
        g_actionCount = 0;
        if (!g_selected && (g_stage == 1 || !(g_stage & 63)) && !SelectGuarded(manager)) Disable(FaultSelectRead);
        else if (!ImportGuarded()) Disable(FaultImportRead);
        else {
            if (!MotionGuarded()) RecordFault(FaultMotionRead); // diagnostics only: control continues
            g_divertsThisStage = 0;
            Apply();
            U* m = g_motion;
            if (g_divertsThisStage > m[MotionDivertPeak]) { m[MotionDivertPeak] = g_divertsThisStage; m[MotionDivertPeakStage] = g_stage; }
        }
        Publish();
    }
    g_adapterTicks += Now() - begin;
    const U us = static_cast<U>(g_adapterTicks * 1000000 / g_frequency);
    g_adapterTicks = 0;
    g_words[AdapterUsLast] = us; g_words[AdapterUsTotal] += us;
    if (us > g_words[AdapterUsMax]) g_words[AdapterUsMax] = us;
    U cursor = D(manager + 0x264), end = cursor + 4 * D(manager + 0x260), skipped = 0, occurrences = 0;
    while (cursor != end) {
        const U a = D(cursor);
        if (B(a + 0x30) == 1) {
            ++occurrences;
            const bool sample = !(++g_sampleSeq & kSampleMask);
            const unsigned long long t0 = sample ? __rdtsc() : 0;
            Row* r = g_disabled ? nullptr : ParkedRow(a);
            const bool skip = r && WaitNode(a);
            if (sample) { g_dispatchCycles += __rdtsc() - t0; ++g_words[DispatchSamples]; }
            if (skip) ++skipped;
            else {
                if (r && !r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenLoop]; }
                Call(D(D(a) + 0xC), a);
            }
        }
        cursor += 4;
        end = D(manager + 0x264) + 4 * D(manager + 0x260);
    }
    g_words[SkippedNativeSteps] += skipped; g_words[ParkedMemberTicks] += g_words[MembersParked];
    g_words[LoopOccurrences] += occurrences;
}
bool CommonStep(U a, U ret) {
    // Two loads and a TEB read: outside the tick owner's puppet epoch nothing is touched (not even a counter).
    if (!g_started || static_cast<U>(*g_tickOwner) != __readfsdword(0x24) || !(*g_epochMask & g_epochBit)) return false;
    ++g_words[CommonCalls];
    const bool sample = !(++g_sampleSeq & kSampleMask);
    const unsigned long long t0 = sample ? __rdtsc() : 0;
    bool gated = false;
    if (sample) g_words[CommonCallerVa] = ret - g_delta;
    if (!g_disabled && g_unitCount) {
        if (Row* r = MemberRow(a)) {
            ++g_words[CommonMemberCalls]; g_words[MemberCallerVa] = ret - g_delta;
            if (r->state == Parked) {
                r->commonStage = g_stage;
                if (Current(*r) && WaitNode(a)) gated = true;
                else {
                    ++g_words[CommonParkedForwarded];
                    if (Current(*r) && !r->foreign) {
                        r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenCommon];
                    }
                }
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
} // namespace ntw2_puppet
