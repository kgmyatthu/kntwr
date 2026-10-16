// Puppet survival probe stage 1 (native_puppet.h). Owner thread only; native transactions are the engine's own code.
#include "native_puppet.h"
#include <windows.h>
#include <string.h>

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
constexpr U kHash = 8192, kMaxExamined = 512, kNone = ~0u;

enum State : U { Free, Ignored, Pending, Parked, Native, Gone };
enum Kind : U { Admit, Repark, HandDying, HandTransfer, HandIneligible };
struct Row { U entity, serial, unit, generation, state, seen, foreign; };
struct Unit { U handle, vtable, ordinal, generation, active; };
struct Action { U row, kind; };

U g_delta, g_requested, g_classVt, g_waitVt, g_crewVt, g_stage, g_generation, g_unitCount, g_rowCount, g_actionCount;
bool g_started, g_selected, g_disabled;
U g_words[kWords];
Unit g_units[kMaxUnits];
Row g_rows[kMaxRows];
uint16_t g_hash[kHash];
Action g_actions[kMaxRows];
LONGLONG g_adapterTicks, g_frequency;

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
    r = {entity, serial, unit, g_units[unit].generation, state, g_stage, 0};
    g_hash[slot] = static_cast<uint16_t>(++g_rowCount);
    return &r;
}
void Fault(U code) { ++g_words[Faults]; g_words[LastFault] = code; }

// Hot path (every site-6 occurrence and every class common step): class table, then the <= 4 unit handles, then the
// serial row with its unit generation. A non-infantry record costs one compare.
Row* ParkedRow(U a) {
    if (D(a) != g_classVt) return nullptr;
    const U unit = D(a + 0x1F0);
    U ui = 0;
    while (ui < g_unitCount && !(g_units[ui].active && g_units[ui].handle == unit)) ++ui;
    if (ui == g_unitCount) return nullptr;
    Row* r = Find(D(a + 0x2C));
    if (!r || r->state != Parked || r->entity != a || r->unit != ui || r->generation != g_units[ui].generation)
        return nullptr;
    return r;
}
bool WaitNode(U a) { return B(a + 0x2C4) == 1 && D(a + 0x22C) == g_waitVt && D(a + 0x230) == a; }
// Probe policy: no combat, target, charge, crew, rout or death state. Admission additionally starts with no active
// request sequence (+390); a repark may cancel one through begin's native stop transaction.
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
void HandBack(Row& r) { r.state = Native; ++g_words[Handbacks]; ++g_words[UnitRows + 4 * r.unit + 3]; }

bool QualifyUnit(U unit, U ordinal) {
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
    g_units[ui] = {unit, D(unit), ordinal, ++g_generation, 1};
    g_words[UnitRows + 4 * ui] = ordinal;
    for (U i = 0; i < n; ++i) {
        const U m = D(list + 4 * i), serial = D(m + 0x2C);
        if (Find(serial)) continue; // duplicate list entry
        const bool selected = D(m) == g_classVt;
        if (Row* r = AddRow(m, serial, ui, selected ? Pending : Ignored)) r->seen = 0; // classified by this stage's import
        ++g_words[selected ? MembersSelected : MembersRejected];
        if (selected) ++g_words[UnitRows + 4 * ui + 1];
    }
    ++g_words[UnitsSelected];
    return true;
}
void Select(U manager) {
    const U count = D(manager + 0x24C), data = D(manager + 0x250);
    if (!count || !data) return;
    U seen[kMaxExamined], seenCount = 0;
    for (U i = 0; i < count && g_unitCount < g_requested && seenCount < kMaxExamined; ++i) {
        const U a = D(data + 4 * i);
        if (!a || D(a) != g_classVt) continue;
        const U unit = D(a + 0x1F0);
        if (!unit) continue;
        U j = 0;
        while (j < seenCount && seen[j] != unit) ++j;
        if (j < seenCount) continue;
        seen[seenCount++] = unit; ++g_words[UnitsExamined];
        if (!QualifyUnit(unit, seenCount - 1)) ++g_words[UnitsRejected];
    }
    if (g_unitCount) { g_selected = true; g_words[SelectionStage] = g_stage; }
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
                *r = {a, serial, ui, u.generation, Ignored, g_stage, 0};
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
                if (D(a + 0x628)) Act(index, HandDying);
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
void Apply() {
    for (U i = 0; i < g_actionCount; ++i) {
        Row& r = g_rows[g_actions[i].row];
        const U kind = g_actions[i].kind;
        if (kind == Admit || kind == Repark) {
            bool stopped = false;
            if (!Install(r.entity, stopped)) { Fault(FaultInstall); HandBack(r); continue; }
            ++g_words[stopped ? InstallStopped : InstallQuiet];
            if (kind == Admit) {
                ++g_words[MembersAdmitted];
                if (!g_words[FirstAdmissionStage]) g_words[FirstAdmissionStage] = g_stage;
            } else ++g_words[Reparks];
            r.state = Parked; r.foreign = 0; r.generation = g_units[r.unit].generation;
            continue;
        }
        HandBack(r);
        if (kind == HandDying) { ++g_words[DyingHandbacks]; ++g_words[DeathsImported]; }
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
    for (U ui = 0; ui < kMaxUnits; ++ui) g_words[UnitRows + 4 * ui + 2] = perUnit[ui];
}
void Disable(U code) {
    Fault(code); g_disabled = true;
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
    if (!binding.image_base || !binding.units || binding.units > kMaxUnits) return false;
    g_delta = binding.image_base - 0x400000;
    g_classVt = V(kClassTable); g_waitVt = V(kWaitTable); g_crewVt = V(kCrewNode);
    // Pin the class and node contracts this module relies on; +08 is pinned by the runtime's slot swap.
    if (D(g_classVt + 0xC) != V(kBrainStep) || D(g_classVt + 0x134) != V(kWaitInstall) ||
        D(g_waitVt + 4) != V(kWaitBegin) || D(g_waitVt + 8) != V(kWaitStep)) return false;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_frequency = f.QuadPart ? f.QuadPart : 1;
    g_requested = binding.units;
    g_words[UnitsRequested] = binding.units;
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
    g_adapterTicks = 0;
    memset(g_words, 0, sizeof(g_words)); memset(g_units, 0, sizeof(g_units));
    memset(g_rows, 0, sizeof(g_rows)); memset(g_hash, 0, sizeof(g_hash));
}
bool Started() { return g_started; }

void Stage(U manager) {
    if (!g_started) { OriginalLoop(manager); return; }
    const LONGLONG begin = Now();
    ++g_stage; ++g_words[Stages];
    if (!g_disabled) {
        g_actionCount = 0;
        if (!g_selected && (g_stage == 1 || !(g_stage & 63)) && !SelectGuarded(manager)) Disable(FaultSelectRead);
        else if (!ImportGuarded()) Disable(FaultImportRead);
        else Apply();
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
            Row* r = g_disabled ? nullptr : ParkedRow(a);
            if (r && WaitNode(a)) ++skipped;
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
bool CommonStep(U a) {
    ++g_words[CommonCalls];
    if (!g_started || g_disabled || !g_unitCount) return false;
    Row* r = ParkedRow(a);
    if (!r) return false;
    if (!WaitNode(a)) {
        if (!r->foreign) { r->foreign = 1; ++g_words[ExternalNodesSeen]; ++g_words[ExternalSeenCommon]; }
        return false;
    }
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
} // namespace ntw2_puppet
