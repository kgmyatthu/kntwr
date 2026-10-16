// Shared admission / unit-policy module (native_unit_policy.h). Owner thread only. No native write anywhere in this file.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stddef.h>
#include <string.h>
#include "native_unit_policy.h"
#include "ntw2_clones.h"
#include "puppet/native_unit_select.h"

namespace ntw2_unit_policy {
Occurrence g_occ;
namespace {
static_assert(sizeof(void*) == 4, "unit policy reads the Win32 game image");
constexpr const char* kLabels[] = { NTW2_UNIT_POLICY_HEADER_LABELS };
static_assert(sizeof(kLabels) / sizeof(kLabels[0]) == kHeaderWords, "one label per header word");
static_assert(offsetof(Occurrence, entity) == 0 && offsetof(Occurrence, unitIndex) == 4 && offsetof(Occurrence, mask) == 8 &&
              offsetof(Occurrence, unit) == 12 && offsetof(Occurrence, slot) == 16, "g_occ layout read by the BRAIN_U clones");

constexpr U kRoutedFatigueSlot = 0x108, kRoutedFinalizeSlot = 0x1A4;
constexpr U kFatigueFn = 0x670F40, kFinalizeFn = 0x6543D0, kBrainStep = 0x66CE00;
constexpr U kDrainStages = 64, kSelectRetry = 63;
constexpr U kNone = ~0u;

// By registry serial: the member record (guards serial reuse) and (unit+1) << 16 | member index. 8 bytes per serial; the
// pages are touched only for serials that exist.
struct Row { U entity, packed; };
struct Storage {
    Row rows[kSerialBits];
    U bits[kSerialBits / 32];
    U members[kMaxUnits][kMaxMembers];
    U serials[kMaxUnits][kMaxMembers];
    U ran[kMaxUnits][kMaxMembers];
    U slots[kMaxUnits][MechanicCount][kSlotWords];
};
struct Unit {
    UnitView view;
    U vtable, army, listCount, listHash, active, liveMask, refused;
    bool drained[MechanicCount];
    U drainGeneration[MechanicCount], drainStage[MechanicCount];
};

Storage* g_store;
Unit g_units[kMaxUnits];
Config g_cfg;
ntw2_unit_select::Rules g_rules;
U g_words[kHeaderWords];
U g_unitCount, g_stage, g_generation, g_coreEntry, g_bruEntry;
bool g_started, g_selected, g_disabled;
LONGLONG g_frequency = 1, g_seamBegin, g_seamTicks;
U g_membersSelected, g_membersRefused;

inline U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline U V(U va) { return va + g_rules.delta; }
LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
void RecordFault(U code) { ++g_words[Faults]; g_words[LastFault] = code; }
inline const Provider* P(U m) { return g_cfg.providers[m]; }

inline bool Bit(U serial) { return (g_store->bits[serial >> 5] >> (serial & 31)) & 1; }
void ClearRows(Unit& u, U ui) {
    for (U k = 0; k < u.view.memberCount; ++k) {
        const U s = g_store->serials[ui][k];
        if (s >= kSerialBits) continue;
        Row& r = g_store->rows[s];
        if (r.entity == g_store->members[ui][k] && (r.packed >> 16) == ui + 1) {
            r = Row{};
            g_store->bits[s >> 5] &= ~(1u << (s & 31));
        }
    }
}
void RetireUnit(U ui) {
    Unit& u = g_units[ui];
    if (!u.active) return;
    for (U m = 0; m < MechanicCount; ++m) if (P(m) && P(m)->retire) P(m)->retire(ui);
    ClearRows(u, ui);
    g_membersSelected -= u.view.memberCount; g_membersRefused -= u.refused;
    u.view.memberCount = 0; u.view.admitted = 0; u.liveMask = 0; u.active = 0; u.refused = 0;
    ++g_words[UnitsRetired];
}

// ---- selection ---------------------------------------------------------------------------------------------------------
bool Accept(void*, U unit, U ordinal, U army) {
    U n, list, admissible;
    if (g_rules.Qualify(unit, n, list, admissible) != ntw2_unit_select::RejectNone) { ++g_words[UnitsRejected]; return false; }
    if (g_unitCount >= kMaxUnits) { RecordFault(FaultCapacity); ++g_words[UnitsRejected]; return false; }
    const U ui = g_unitCount++;
    Unit& u = g_units[ui];
    u = Unit{};
    u.view.handle = unit; u.view.ordinal = ordinal; u.view.generation = ++g_generation; u.view.stage = g_stage;
    u.view.members = g_store->members[ui]; u.view.ran = g_store->ran[ui];
    u.vtable = D(unit); u.army = army; u.listCount = kNone; u.active = 1;
    ++g_words[UnitsSelected];
    return true;
}
bool SelectGuarded(U manager) {
    __try {
        ntw2_unit_select::Scan(g_rules, manager, &Accept, nullptr, kMaxUnits);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---- membership import -----------------------------------------------------------------------------------------------
// Rebuilds the unit's selected-member rows from its live list (the list signature changed, or first import).
void Rebuild(Unit& u, U ui, U n, U list) {
    U* const members = g_store->members[ui];
    U* const serials = g_store->serials[ui];
    U* const ran = g_store->ran[ui];
    const U oldCount = u.view.memberCount;
    // Phase 0: which of the new admissible members already were selected members of this unit (rows still old).
    U stayed = 0, count = 0, refused = 0;
    static U fresh[kMaxMembers], freshSerial[kMaxMembers];
    for (U i = 0; i < n; ++i) {
        const U a = D(list + 4 * i);
        if (!a || !g_rules.Admissible(a, u.view.handle)) { ++refused; continue; }
        const U s = D(a + 0x2C);
        const Row& r = g_store->rows[s];
        if (r.entity == a && (r.packed >> 16) == ui + 1) ++stayed;
        fresh[count] = a; freshSerial[count] = s; ++count;
    }
    // Phase 1: drop the old rows; phase 2: insert the new ones (duplicate list entries keep their first position).
    ClearRows(u, ui);
    U kept = 0;
    for (U k = 0; k < count; ++k) {
        const U a = fresh[k], s = freshSerial[k];
        Row& r = g_store->rows[s];
        if (r.entity == a && (r.packed >> 16) == ui + 1) continue; // duplicate entry of this rebuild
        r.entity = a; r.packed = ((ui + 1) << 16) | kept;
        g_store->bits[s >> 5] |= 1u << (s & 31);
        members[kept] = a; serials[kept] = s; ran[kept] = 0; ++kept;
    }
    g_words[MembersJoined] += kept > stayed ? kept - stayed : 0;
    g_words[MembersDeparted] += oldCount > stayed ? oldCount - stayed : 0;
    g_membersSelected = g_membersSelected - oldCount + kept;
    g_membersRefused = g_membersRefused - u.refused + refused;
    u.view.memberCount = kept; u.refused = refused;
    u.view.generation = ++g_generation; ++g_words[GenerationBumps];
}
void ImportUnit(U ui) {
    Unit& u = g_units[ui];
    const U n = D(u.view.handle + 0x2CC), list = D(u.view.handle + 0x2D0);
    if (D(u.view.handle) != u.vtable || n > kMaxMembers || (n && !list)) { RetireUnit(ui); return; }
    U hash = 2166136261u;
    for (U i = 0; i < n; ++i) hash = (hash ^ D(list + 4 * i)) * 16777619u;
    if (n == u.listCount && hash == u.listHash) return;
    Rebuild(u, ui, n, list);
    u.listCount = n; u.listHash = hash;
}
bool ImportGuarded() {
    __try {
        for (U ui = 0; ui < g_unitCount; ++ui) if (g_units[ui].active) ImportUnit(ui);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void Disable(U code) {
    RecordFault(code);
    g_disabled = true;
    for (U ui = 0; ui < g_unitCount; ++ui) RetireUnit(ui);
}
} // namespace

bool Bind(U imageBase, U* bindings) {
    if (!imageBase || !bindings) return false;
    bindings[NTW2_BIND_U_OCC] = static_cast<U>(reinterpret_cast<uintptr_t>(&g_occ));
    return true;
}
bool Started() { return g_started; }
U StorageBytes() { return g_store ? static_cast<U>(sizeof(Storage)) : 0; }
U RequiredStorageBytes() { return static_cast<U>(sizeof(Storage)); }

bool Start(const Config& config) {
    Stop(); Reset();
    g_cfg = config;
    if (!config.imageBase) return false;
    for (U m = 0; m < MechanicCount; ++m)
        if (g_cfg.providers[m] && (g_cfg.providers[m]->mode == Off || g_cfg.providers[m]->mechanic != m ||
                                    !g_cfg.providers[m]->decide || !g_cfg.providers[m]->end)) g_cfg.providers[m] = nullptr;
    if (!g_store) {
        g_store = static_cast<Storage*>(VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_store) return false;
    }
    if (!g_rules.Pin(config.imageBase)) return false;
    // The routed slots: every pinned table must carry the native fatigue selector and finalizer.
    if (D(g_rules.classVt + kRoutedFatigueSlot) != V(kFatigueFn) || D(g_rules.classVt + kRoutedFinalizeSlot) != V(kFinalizeFn))
        return false;
    g_coreEntry = V(kBrainStep);
    g_bruEntry = config.cloneEntries ? config.cloneEntries[NTW2_CLONE_BRAIN_U] : 0;
    if (!config.s0 && !g_bruEntry) return false;
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); g_frequency = f.QuadPart ? f.QuadPart : 1;
    g_words[Modes] = 0;
    for (U m = 0; m < MechanicCount; ++m) if (P(m)) g_words[Modes] |= P(m)->mode << (2 * m);
    g_started = true;
    return true;
}
void Stop() {
    if (!g_started) return;
    for (U ui = 0; ui < g_unitCount; ++ui) RetireUnit(ui);
    g_occ = Occurrence{}; g_occ.unitIndex = kNone;
    g_started = false;
}
void Reset() {
    g_started = g_selected = g_disabled = false;
    if (g_store) for (U ui = 0; ui < g_unitCount; ++ui) ClearRows(g_units[ui], ui);
    memset(g_units, 0, sizeof(g_units));
    memset(g_words, 0, sizeof(g_words));
    g_unitCount = g_stage = g_generation = 0;
    g_membersSelected = g_membersRefused = 0;
    g_occ = Occurrence{}; g_occ.unitIndex = kNone;
    g_seamTicks = 0;
}
void Snapshot(U* words) {
    memcpy(words, g_words, sizeof(g_words));
    words[Version] = kVersion;
    words[MembersSelected] = g_membersSelected; words[MembersRefused] = g_membersRefused;
}

void BeginStage(U manager) {
    if (!g_started || g_disabled) return;
    const LONGLONG t0 = Now();
    ++g_stage; ++g_words[Stages];
    if (!g_selected && (g_stage == 1 || !(g_stage & kSelectRetry))) {
        ++g_words[SelectPasses];
        if (!SelectGuarded(manager)) Disable(FaultSelectRead);
        else if (g_unitCount) g_selected = true;
    }
    if (!g_disabled && !ImportGuarded()) Disable(FaultImportRead);
    if (!g_disabled) {
        for (U m = 0; m < MechanicCount; ++m) g_words[AdmittedFatigue + m] = 0;
        for (U ui = 0; ui < g_unitCount; ++ui) {
            Unit& u = g_units[ui];
            if (!u.active) continue;
            u.view.stage = g_stage; u.view.admitted = 0; u.liveMask = 0;
            if (!u.view.memberCount) continue;
            U admitted = 0, live = 0;
            for (U m = 0; m < MechanicCount; ++m) {
                const Provider* p = P(m);
                if (!p) continue;
                if (u.drained[m]) {
                    if (u.view.generation != u.drainGeneration[m] && g_stage >= u.drainStage[m] + kDrainStages) u.drained[m] = false;
                    else { ++g_words[RefusedFatigue + m]; continue; }
                }
                if (p->decide(ui, u.view, g_store->slots[ui][m]) == 0) {
                    admitted |= 1u << m; if (p->mode == Live) live |= 1u << m;
                    ++g_words[AdmittedFatigue + m]; ++g_words[UnitStagesFatigue + m];
                } else ++g_words[RefusedFatigue + m];
            }
            u.view.admitted = admitted; u.liveMask = live;
        }
    }
    g_seamBegin = Now() - t0;
}
void EndStage() {
    if (!g_started || g_disabled) return;
    const LONGLONG t0 = Now();
    U outOfWorklist = 0;
    for (U ui = 0; ui < g_unitCount; ++ui) {
        Unit& u = g_units[ui];
        if (!u.active) continue;
        if (u.view.admitted) {
            const U* ran = u.view.ran;
            for (U k = 0; k < u.view.memberCount; ++k) outOfWorklist += ran[k] != g_stage;
        }
        for (U m = 0; m < MechanicCount; ++m) if (P(m)) P(m)->end(ui, u.view, g_store->slots[ui][m]);
    }
    g_words[OutOfWorklistLast] = outOfWorklist;
    const LONGLONG ticks = g_seamBegin + (Now() - t0);
    const U us = static_cast<U>(ticks * 1000000 / g_frequency);
    g_words[SeamUsLast] = us; g_words[SeamUsTotal] += us;
    if (us > g_words[SeamUsMax]) g_words[SeamUsMax] = us;
}

U BeginOccurrence(U entity) {
    Occurrence& o = g_occ;
    o.entity = entity;
    const U serial = D(entity + 0x2C);
    if (!g_started || g_disabled || serial >= kSerialBits || !Bit(serial)) goto native;
    {
        const Row& r = g_store->rows[serial];
        if (r.entity != entity) goto native;
        const U ui = (r.packed >> 16) - 1;
        Unit& u = g_units[ui];
        g_store->ran[ui][r.packed & 0xFFFF] = g_stage;
        o.unitIndex = ui; o.unit = &u.view; o.mask = u.liveMask;
        o.slot[Fatigue] = g_store->slots[ui][Fatigue];
        o.slot[Posture] = g_store->slots[ui][Posture];
        o.slot[Engage] = g_store->slots[ui][Engage];
        ++g_words[o.mask ? AdmittedOccurrences : NativeOccurrences];
        return o.mask;
    }
native:
    o.unitIndex = kNone; o.mask = 0; o.unit = nullptr;
    o.slot[0] = o.slot[1] = o.slot[2] = nullptr;
    ++g_words[NativeOccurrences];
    return 0;
}
void EndOccurrence() {
    Occurrence& o = g_occ;
    if (o.unit) {
        const UnitView& v = *o.unit;
        for (U m = 0; m < MechanicCount; ++m) {
            const Provider* p = P(m);
            if (!p || !p->observe) continue;
            if ((o.mask >> m & 1) || (p->mode == Shadow && (v.admitted >> m & 1))) p->observe(o.entity, v, o.slot[m]);
        }
    }
    o.entity = 0; o.unitIndex = kNone; o.mask = 0; o.unit = nullptr;
    o.slot[0] = o.slot[1] = o.slot[2] = nullptr;
}
void AbandonOccurrence() {
    g_occ.entity = 0; g_occ.unitIndex = kNone; g_occ.mask = 0; g_occ.unit = nullptr;
    g_occ.slot[0] = g_occ.slot[1] = g_occ.slot[2] = nullptr;
}
void RunOccurrence(U entity, U cls, U original, const U* cloneEntries) {
    using Step = void (__thiscall*)(void*);
    U entry = original, mask = 0;
    if (cls == 0 && original == g_coreEntry) mask = BeginOccurrence(entity);
    if (mask) entry = cloneEntries[NTW2_CLONE_BRAIN_U];
    bool completed = false;
    __try {
        reinterpret_cast<Step>(entry)(reinterpret_cast<void*>(entity));
        completed = true;
    } __finally {
        if (completed) EndOccurrence();
        else AbandonOccurrence();
    }
}
void Drain(U unitIndex, U mechanic, U code) {
    (void)code;
    if (unitIndex >= g_unitCount || mechanic >= MechanicCount) return;
    Unit& u = g_units[unitIndex];
    u.drained[mechanic] = true; u.drainGeneration[mechanic] = u.view.generation; u.drainStage[mechanic] = g_stage;
    ++g_words[DrainsFatigue + mechanic];
}
const UnitView* View(U unitIndex) { return unitIndex < g_unitCount ? &g_units[unitIndex].view : nullptr; }
U UnitCount() { return g_unitCount; }
U UnitIndexOf(U handle) {
    for (U ui = 0; ui < g_unitCount; ++ui) if (g_units[ui].view.handle == handle && g_units[ui].active) return ui;
    return kNone;
}
bool UnitListStable(U unitIndex) {
    if (unitIndex >= g_unitCount || !g_units[unitIndex].active) return false;
    const Unit& u = g_units[unitIndex];
    __try {
        const U n = D(u.view.handle + 0x2CC), list = D(u.view.handle + 0x2D0);
        if (n != u.listCount || (n && !list) || D(u.view.handle) != u.vtable) return false;
        U hash = 2166136261u;
        for (U i = 0; i < n; ++i) hash = (hash ^ D(list + 4 * i)) * 16777619u;
        return hash == u.listHash;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
} // namespace ntw2_unit_policy
