// Per-unit posture (S2b) and engage / fire latch / unit-lookup (S1c, S3, S1a/S2a lookups) providers and binding bodies.
// See native_unit_posture_engage.h. Owner thread only (decide/end/retire run in BeginStage/EndStage; the gate bodies run
// inside the owner's occurrence).
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string.h>
#include "native_unit_posture_engage.h"
#include "clones/kntwr_clones.h"
static_assert(sizeof(void*) == 4, "the gates are Win32 x86 naked thunks");
constexpr const char* kLabels[] = {KNTWR_UNIT_POSTURE_ENGAGE_LABELS};
static_assert(sizeof(kLabels) / sizeof(kLabels[0]) == 128, "status label count");

namespace kntwr_unit_posture_engage {
namespace {
using kntwr_unit_policy::g_occ;
using kntwr_unit_policy::Provider;
using kntwr_unit_policy::UnitView;
using kntwr_unit_policy::Drain;

constexpr U kStates = 13, kStateFirst = 0x1454168, kRestState = 0x1454198, kStateTables = 0x1346994;
constexpr U kFsmVtable = 0x1320F28, kUnitStateFirst = 0x1450908;
// 10FBBD0 reads per state: next (+0), enter (+4), update (+8), exit (+0C). Pinned from the approved image.
const U kStateSlots[kStates][4] = {
    {0x7de0c0, 0x7de0b0, 0x44a780, 0x44a780}, {0x7de1f0, 0x44a780, 0x7de1d0, 0x7de1e0},
    {0x7de2b0, 0x44a780, 0x7de2a0, 0x44a780}, {0x7de320, 0x7de2f0, 0x7de300, 0x7de310},
    {0x7de3c0, 0x44a780, 0x7de3a0, 0x7de3b0}, {0x7de450, 0x44a780, 0x7de430, 0x7de440},
    {0x7de4b0, 0x44a780, 0x44a780, 0x44a780}, {0x7de520, 0x7de500, 0x7de510, 0x7de310},
    {0x7de5a0, 0x44a780, 0x7de300, 0x44a780}, {0x7de640, 0x44a780, 0x7de630, 0x7de440},
    {0x7de6b0, 0x44a780, 0x7de300, 0x44a780}, {0x7de700, 0x44a780, 0x7de6f0, 0x44a780},
    {0x44c230, 0x7de740, 0x7de750, 0x7de760}};
constexpr U kGetters[kStates] = {0x5D6F60, 0x5D7000, 0x5D6FD0, 0x5D7060, 0x5D6FC0, 0x5D6F70, 0x5D6F80,
                                 0x5D7020, 0x5D7050, 0x5D7070, 0x5D7080, 0x5D7010, 0x5D6FB0};
// Unit FSM singletons A..E and their state tables (native-army-update-per-unit.md 10.4.5).
const U kUnitTables[5] = {0x131C67C, 0x131C7F8, 0x131C850, 0x131C91C, 0x131C930};

enum Cnt : U { CApplied, CTransition, CUpdateOnly, CNullState, CNativeState, CNativeTable, CD9d, CLkServed, CLkNative,
               CAlt, CBudget, CntCount };
enum PostureRefusal : U { PrOk, PrNoUnit, PrFsm, PrState, PrActive, PrMoving };
enum EngageRefusal : U { ErOk, ErNoUnit, ErRead };
enum GateDrain : U { DrainState = 1, DrainTable = 2, DrainAlt = 3 };

U g_delta;
bool g_bound, g_started;
U g_postureMode, g_engageMode;
U g_words[kWords];
alignas(16) U g_cnt[16];
// Native engage values: the block the driver gates read for every occurrence that is not an admitted Engage occurrence.
alignas(16) U g_native[16] = {0, 6, 7, 0, 0, 0, 1, 0, 1};
U g_evp;
U g_stateFirst, g_rest, g_native10FC370, g_native649520, g_native64F8F0, g_native64DE80, g_native57E1F0;
U g_tableOk[2], g_tableNext;
// Node-class dispatch of the driver's begin/step virtual runs: preferred-VA targets and the entry each one runs.
U g_beginTarget[3], g_beginEntry[3], g_stepTarget[4], g_stepEntry[4];
U g_lastStagePosture = ~0u, g_lastStageEngage = ~0u;
// Shadow tables (owner only).
U g_matrix[15][15];                 // native state index x unit target index (13 null, 14 other)
U g_hist[6][4][15];                 // unit activity x command speed class x native member state index
U g_speedMembers[4];
U g_actUnits[6];
Provider g_posture, g_engage;

template <class F> U Fn(F f) { return static_cast<U>(reinterpret_cast<uintptr_t>(reinterpret_cast<const void*>(f))); }
inline U V(U va) { return va + g_delta; }
inline U D(U p) { return *reinterpret_cast<const U*>(p); }

bool Rd(U address, U& value) {
    __try { value = *reinterpret_cast<const U*>(address); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool Rb(U address, U& value) {
    __try { value = *reinterpret_cast<const unsigned char*>(address); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The fsm sub-object vtable of an infantry man: 5D66E0 at +8, the 13 state getters at +0C.., select/reach slots from the
// recovered set (native_finalizer.cpp PostureTable); accepted by content.
bool PostureTable(U table) {
    if (table < V(0x1307000) || table + 0x54 > V(0x1307000) + 0x146236) return false;
    U v;
    if (!Rd(table + 4, v) || v != V(0x5562A0) || !Rd(table + 8, v) || v != V(0x5D66E0)) return false;
    for (U i = 0; i < kStates; ++i) if (!Rd(table + 0xC + 4 * i, v) || v != V(kGetters[i])) return false;
    U select, select2, probe, extent, last;
    if (!Rd(table + 0x40, select) || !Rd(table + 0x44, select2) || !Rd(table + 0x48, probe) || !Rd(table + 0x4C, extent) ||
        !Rd(table + 0x50, last)) return false;
    return (select == V(0x66B7E0) || select == V(0x462E90) || select == V(0x5FB920)) &&
           (select2 == V(0x66B990) || select2 == V(0x47BA10)) && (probe == V(0x462E90) || probe == V(0x5F8190)) &&
           (extent == V(0x5EE210) || extent == V(0x5EE220)) && last == V(0x447880);
}
bool __fastcall ValidateTable(U table) {
    if (!PostureTable(table)) return false;
    g_tableOk[g_tableNext & 1] = table; ++g_tableNext;
    return true;
}
bool StatesPinned() {
    for (U i = 0; i < kStates; ++i) {
        U state, vtable;
        if (!Rd(V(kStateFirst) + 4 * i, state) || state != V(kStateTables) + 0x14 * i) return false;
        for (U k = 0; k < 4; ++k)
            if (!Rd(state + 4 * k, vtable) || vtable != V(kStateSlots[i][k])) return false;
    }
    return true;
}
bool UnitFsmPinned() {
    for (U i = 0; i < 5; ++i) {
        U state;
        if (!Rd(V(kUnitStateFirst) + 4 * i, state) || state != V(kUnitTables[i])) return false;
    }
    return true;
}
U StateIndex(U state) {
    if (!state) return 13;
    const U off = state - g_stateFirst;
    return off <= 0x30 && !(off & 3) ? off / 4 : 14;
}

void __fastcall PostureFallback(U code, U counter) { ++g_cnt[counter]; Drain(g_occ.unitIndex, kntwr_unit_policy::Posture, code); }
void __cdecl AltReached() { ++g_cnt[CAlt]; Drain(g_occ.unitIndex, kntwr_unit_policy::Engage, DrainAlt); }

#define C(k) (4 * (k))
// ---- U_POSTURE: replaces `call 10FC370` at 819A01 (ECX = fsm = A+F4, plain ret, AL result; EAX/ECX/EDX and flags are
// clobbered like the original; EBX/ESI/EDI/EBP preserved). Admitted unit (mask & Posture, slot target set): the unit's
// target state T is applied with exactly the native per-man step effects: exit(old) -> [fsm+4] = T -> enter(T) (old != T), then
// the next native iteration's update(T) (when the iteration budget [fsm+8]+1 allows it); never the next-state virtual.
// AL = 0 when the resulting state is rest (native: step returned 0), else 1. Null state: native no-op (AL 1). An unpinned
// state / fsm table mid-stage runs the original and drains the unit.
__declspec(naked) void PostureGate() {
    __asm {
        lea eax, [ecx - 0F4h]
        cmp eax, dword ptr [g_occ]
        jne native
        test byte ptr [g_occ + 8], 2
        jz native
        mov edx, dword ptr [g_occ + 20]
        mov edx, dword ptr [edx]
        test edx, edx
        jz native
        push ebx
        push esi
        push edi
        mov esi, ecx
        mov edi, edx
        mov ecx, dword ptr [esi + 4]
        test ecx, ecx
        jz null_state
        mov eax, ecx
        sub eax, dword ptr [g_stateFirst]
        cmp eax, 30h
        ja bad_state
        test al, 3
        jnz bad_state
        mov eax, dword ptr [esi]
        cmp eax, dword ptr [g_tableOk]
        je table_ok
        cmp eax, dword ptr [g_tableOk + 4]
        je table_ok
        mov ecx, eax
        call ValidateTable
        test al, al
        jz bad_table
        mov ecx, dword ptr [esi + 4]
    table_ok:
        inc dword ptr [g_cnt + 0]
        cmp ecx, edi
        je do_update
        mov eax, dword ptr [ecx]
        push esi
        call dword ptr [eax + 0Ch]
        mov dword ptr [esi + 4], edi
        mov ecx, edi
        mov eax, dword ptr [edi]
        push esi
        call dword ptr [eax + 4]
        inc dword ptr [g_cnt + 4]
        cmp dword ptr [esi + 8], 0
        je budget
        jmp update_tail
    do_update:
        inc dword ptr [g_cnt + 8]
    update_tail:
        mov ecx, dword ptr [esi + 4]
        mov eax, dword ptr [ecx]
        push esi
        call dword ptr [eax + 8]
        xor eax, eax
        mov ecx, dword ptr [esi + 4]
        cmp ecx, dword ptr [g_rest]
        setne al
        pop edi
        pop esi
        pop ebx
        ret
    budget:
        inc dword ptr [g_cnt + 40]
        mov eax, 1
        pop edi
        pop esi
        pop ebx
        ret
    null_state:
        inc dword ptr [g_cnt + 12]
        mov eax, 1
        pop edi
        pop esi
        pop ebx
        ret
    bad_state:
        mov ecx, 1
        mov edx, 4
        jmp fallback
    bad_table:
        mov ecx, 2
        mov edx, 5
    fallback:
        call PostureFallback
        mov ecx, esi
        pop edi
        pop esi
        pop ebx
    native:
        jmp dword ptr [g_native10FC370]
    }
}
// ---- 66D402 -> 64DE80 (alternate driver): counts and drains an admitted Engage unit, then the native driver (ECX = A).
__declspec(naked) void DriverAltGate() {
    __asm {
        cmp ecx, dword ptr [g_occ]
        jne native
        test byte ptr [g_occ + 8], 4
        jz native
        push ecx
        call AltReached
        pop ecx
    native:
        jmp dword ptr [g_native64DE80]
    }
}
// ---- unit-only lookups served from the unit's Engage slot (words LkPredicate/LkArrival/LkModifier, LkValid mask).
// 649520 (6544DB): ECX = A, EAX = row pointer, plain ret. 64F8F0: ECX = A, AL, plain ret. 57E1F0: ECX = U, x87 ST0 float.
__declspec(naked) void ModifierGate() {
    __asm {
        cmp ecx, dword ptr [g_occ]
        jne native
        test byte ptr [g_occ + 8], 4
        jz native
        mov edx, dword ptr [g_occ + 24]
        test dword ptr [edx + 4 * 19], 4
        jz miss
        mov eax, dword ptr [edx + 4 * 18]
        inc dword ptr [g_cnt + 28]
        ret
    miss:
        inc dword ptr [g_cnt + 32]
    native:
        jmp dword ptr [g_native649520]
    }
}
__declspec(naked) void OrderPredicateGate() {
    __asm {
        cmp ecx, dword ptr [g_occ]
        jne native
        test byte ptr [g_occ + 8], 4
        jz native
        mov edx, dword ptr [g_occ + 24]
        test dword ptr [edx + 4 * 19], 1
        jz miss
        movzx eax, byte ptr [edx + 4 * 16]
        inc dword ptr [g_cnt + 28]
        ret
    miss:
        inc dword ptr [g_cnt + 32]
    native:
        jmp dword ptr [g_native64F8F0]
    }
}
__declspec(naked) void UnitArrivalGate() {
    __asm {
        mov eax, dword ptr [g_occ + 12]
        test eax, eax
        jz native
        cmp ecx, dword ptr [eax]
        jne native
        test byte ptr [g_occ + 8], 4
        jz native
        mov edx, dword ptr [g_occ + 24]
        test dword ptr [edx + 4 * 19], 2
        jz miss
        fld dword ptr [edx + 4 * 17]
        inc dword ptr [g_cnt + 28]
        ret
    miss:
        inc dword ptr [g_cnt + 32]
    native:
        jmp dword ptr [g_native57E1F0]
    }
}

// ---- 658FDE / 6590FC: own-phase 6 / 7 stores (the run keeps the next instruction verbatim). EDX only, plain RET, ESI = A.
__declspec(naked) void Phase6Gate() {
    __asm {
        mov edx, dword ptr [g_evp]
        mov edx, dword ptr [edx + 4]
        mov dword ptr [esi + 224h], edx
        ret
    }
}
__declspec(naked) void Phase7Gate() {
    __asm {
        mov edx, dword ptr [g_evp]
        mov edx, dword ptr [edx + 8]
        mov dword ptr [esi + 224h], edx
        ret
    }
}
// ---- the driver's node virtual runs `mov ecx,edi; call [eax+4]` (begin) / `[eax+8]` (step), EAX = node vtable, EDI = node:
// known node classes run their BRAIN_U_* clone, any other target the original; the callee returns to the driver.
__declspec(naked) void NodeBeginGate() {
    __asm {
        mov ecx, edi
        mov edx, dword ptr [eax + 4]
        cmp edx, dword ptr [g_beginTarget]
        jne n1
        jmp dword ptr [g_beginEntry]
    n1: cmp edx, dword ptr [g_beginTarget + 4]
        jne n2
        jmp dword ptr [g_beginEntry + 4]
    n2: cmp edx, dword ptr [g_beginTarget + 8]
        jne n3
        jmp dword ptr [g_beginEntry + 8]
    n3: jmp edx
    }
}
__declspec(naked) void NodeStepGate() {
    __asm {
        mov ecx, edi
        mov edx, dword ptr [eax + 8]
        cmp edx, dword ptr [g_stepTarget]
        jne n1
        jmp dword ptr [g_stepEntry]
    n1: cmp edx, dword ptr [g_stepTarget + 4]
        jne n2
        jmp dword ptr [g_stepEntry + 4]
    n2: cmp edx, dword ptr [g_stepTarget + 8]
        jne n3
        jmp dword ptr [g_stepEntry + 8]
    n3: cmp edx, dword ptr [g_stepTarget + 12]
        jne n4
        jmp dword ptr [g_stepEntry + 12]
    n4: jmp edx
    }
}
#undef C

// ---- unit activity (U+D68 FSM) ------------------------------------------------------------------------------------
struct Activity { U index, speed, stateOk; };
// index 0..4 = A..E, 5 other; speed: 0 none, 1, 2, 3 other (S+24)
Activity ReadActivity(U unit, U& refusal) {
    Activity a{5, 0, 0};
    refusal = PrOk;
    U vt, cur, s24;
    if (!Rd(unit + 0xD68, vt) || vt != V(kFsmVtable) || !Rd(unit + 0xD6C, cur)) { refusal = PrFsm; return a; }
    if (Rd(unit + 0xD68 + 0x24, s24)) a.speed = s24 == 0 ? 0 : s24 == 1 ? 1 : s24 == 2 ? 2 : 3;
    const U off = cur - V(kUnitStateFirst);
    if (off > 0x10 || (off & 3)) { refusal = PrState; return a; }
    a.index = off / 4;
    a.stateOk = 1;
    return a;
}

// The unit-only lookups evaluated natively (seam value in decide, end-of-stage re-evaluation in the shadow stale check).
struct Lookups { U valid, predicate, row; float arrival; };
void EvalLookups(U unit, Lookups& out) {
    out.valid = 0; out.predicate = 0; out.row = 0; out.arrival = 0;
    __try { out.predicate = reinterpret_cast<U(__fastcall*)(U, U)>(V(0x55B0A0))(unit, 0) & 0xFF; out.valid |= kLkPredicate; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    __try { out.arrival = reinterpret_cast<float(__fastcall*)(U, U)>(g_native57E1F0)(unit, 0); out.valid |= kLkArrival; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    U table, index;
    if (Rd(unit + 0x2C, table) && Rd(unit + 0xC70, index)) {
        U value = 0;
        if (!table || Rd(table + index * 4 + 0xE4, value)) { out.row = table ? value : 0; out.valid |= kLkModifier; }
    }
}
// Whole-unit posture admission predicate over the members' state at the seam: a member in the locomotion domain (a posture state
// other than rest/null, an active move request: sequencer +390, fsm mode/flags +108/+110, fsm speed word +100) forbids forcing rest
// (819770 would take R+140 / the finalizer its activity from the forced state). Cause bits: 1 state, 2 sequencer request, 4 fsm.
U MovingCause(const UnitView& unit) {
    U cause = 0;
    if (!unit.members) return 0;
    for (U k = 0; k < unit.memberCount && cause != 7; ++k) {
        const U a = unit.members[k];
        U state, request, mode, flags, speed;
        if (!Rd(a + 0xF8, state) || !Rd(a + 0x390, request) || !Rd(a + 0x108, mode) || !Rd(a + 0x110, flags) || !Rd(a + 0x100, speed)) { cause |= 1; continue; }
        if (state && state != g_rest) cause |= 1;
        if (request) cause |= 2;
        if (mode || flags || speed) cause |= 4;
    }
    return cause;
}

U DecidePosture(U, const UnitView& unit, U* slot) {
    if (g_lastStagePosture != unit.stage) { g_lastStagePosture = unit.stage; ++g_words[WStages]; g_words[WPDecide + 1] = 0; }
    ++g_words[WPDecide];
    slot[PsTarget] = 0; slot[PsRest] = g_rest; slot[PsActivity] = 5; slot[PsShadowTarget] = ~0u;
    slot[PsSpeedClass] = 0; slot[PsStage] = unit.stage;
    U refusal;
    if (!unit.handle) { ++g_words[WPDecide + 4]; ++g_words[WPDecide + 3]; return PrNoUnit; }
    const Activity a = ReadActivity(unit.handle, refusal);
    slot[PsActivity] = a.index; slot[PsSpeedClass] = a.speed;
    if (refusal != PrOk) {
        ++g_words[WPDecide + 3]; ++g_words[WPDecide + (refusal == PrFsm ? 5 : 6)];
        return refusal;
    }
    ++g_words[WPDecide + 8 + a.index];
    if (a.index != 0) { ++g_words[WPDecide + 3]; ++g_words[WPDecide + 7]; return PrActive; } // B..E: no closed unit mapping
    slot[PsShadowTarget] = 12;
    ++g_words[WMoving + 1];
    if (const U cause = MovingCause(unit)) {
        ++g_words[WPDecide + 3]; ++g_words[WMoving]; slot[PsShadowTarget] = ~0u;
        if (cause & 1) ++g_words[WMoving + 2];
        if (cause & 2) ++g_words[WMoving + 3];
        if (cause & 4) ++g_words[WMoving + 4];
        return PrMoving;
    }
    slot[PsTarget] = g_postureMode == kntwr_unit_policy::Live ? g_rest : 0;
    ++g_words[WPDecide + 1]; ++g_words[WPDecide + 2];
    return 0;
}
// Shadow only: the native members' end-of-stage posture state against the unit decision, and the unit-activity x speed x
// state histogram of every selected unit (also refused ones: the evidence for a B..E mapping).
void EndPosture(U, const UnitView& unit, U* slot) {
    if (g_postureMode != kntwr_unit_policy::Shadow || !unit.ran || !unit.members) return;
    const bool admitted = (unit.admitted & kntwr_unit_policy::kMaskPosture) != 0;
    const U act = slot[PsActivity] > 5 ? 5 : slot[PsActivity], speed = slot[PsSpeedClass] & 3, target = slot[PsShadowTarget];
    for (U k = 0; k < unit.memberCount; ++k) {
        if (unit.ran[k] != unit.stage) { if (admitted) ++g_words[WPCompare + 3]; continue; }
        U state;
        if (!Rd(unit.members[k] + 0xF8, state)) continue;
        const U idx = StateIndex(state);
        ++g_hist[act][speed][idx]; ++g_speedMembers[speed]; ++g_words[WPHist];
        if (!admitted || target > 12) continue;
        ++g_words[WPCompare];
        if (idx == 13) ++g_words[WPCompare + 4];
        else if (idx == 14) ++g_words[WPCompare + 5];
        else if (idx == target) ++g_words[WPCompare + 1];
        else { ++g_words[WPCompare + 2]; ++g_words[WPCompare + 6]; }
        ++g_matrix[idx][target];
    }
}

U DecideEngage(U, const UnitView& unit, U* slot) {
    if (g_lastStageEngage != unit.stage) {
        g_lastStageEngage = unit.stage; g_words[WEDecide + 1] = 0;
        if (g_postureMode == kntwr_unit_policy::Off) ++g_words[WStages];
    }
    ++g_words[WEDecide];
    memcpy(slot, g_native, 9 * sizeof(U));
    slot[EvUnit] = unit.handle; slot[EvStage] = unit.stage; slot[LkValid] = 0;
    if (!unit.handle) { ++g_words[WEDecide + 4]; ++g_words[WEDecide + 3]; return ErNoUnit; }
    U d9d;
    if (!Rb(unit.handle + 0xD9D, d9d)) { ++g_words[WEDecide + 5]; ++g_words[WEDecide + 3]; return ErRead; }
    const bool live = g_engageMode == kntwr_unit_policy::Live;
    ++g_words[WEDecide + (d9d ? 6 : 7)];
    slot[EvD9dValue] = d9d != 0;
    slot[EvD9dMode] = live ? 1 : 0;
    {
        // Unit-only lookups (analysis/native-unit-compromise-plan.md 1.3): one evaluation per unit and stage; the shadow evaluates
        // them exactly as live does so its end-of-stage re-evaluation can prove (or refute) that freezing them at the seam is safe.
        Lookups lk;
        EvalLookups(unit.handle, lk);
        slot[LkPredicate] = lk.predicate; memcpy(&slot[LkArrival], &lk.arrival, 4); slot[LkModifier] = lk.row; slot[LkValid] = lk.valid;
        if (lk.valid & kLkPredicate) ++g_words[WELookups];
        if (lk.valid & kLkArrival) ++g_words[WELookups + 1];
        if (lk.valid & kLkModifier) ++g_words[WELookups + 2];
    }
    ++g_words[WEDecide + 1]; ++g_words[WEDecide + 2];
    return 0;
}
// Shadow only: native end-of-stage engage phase / latch bytes / order / stance of the stepped members against the unit
// values; the order and stance of one unit are compared with each other (uniformity = the evidence for a unit order).
void EndEngage(U, const UnitView& unit, U* slot) {
    if (g_engageMode != kntwr_unit_policy::Shadow || !unit.ran || !unit.members) return;
    const bool admitted = (unit.admitted & kntwr_unit_policy::kMaskEngage) != 0;
    if (admitted) {   // freeze validation: re-evaluate what live freezes at the seam
        Lookups now;
        EvalLookups(unit.handle, now);
        U d9d = 0; const bool d9dRead = Rb(unit.handle + 0xD9D, d9d);
        ++g_words[WStale + 4];
        if ((slot[LkValid] & kLkPredicate) && (now.valid & kLkPredicate) && now.predicate != slot[LkPredicate]) ++g_words[WStale];
        float frozen; memcpy(&frozen, &slot[LkArrival], 4);
        if ((slot[LkValid] & kLkArrival) && (now.valid & kLkArrival) && memcmp(&frozen, &now.arrival, 4)) ++g_words[WStale + 1];
        if ((slot[LkValid] & kLkModifier) && (now.valid & kLkModifier) && now.row != slot[LkModifier]) ++g_words[WStale + 2];
        if (d9dRead && (d9d != 0) != (slot[EvD9dValue] != 0)) ++g_words[WStale + 3];
    }
    U firstOrder = 0, firstStance = 0, seen = 0, orderMixed = 0, stanceMixed = 0;
    for (U k = 0; k < unit.memberCount; ++k) {
        if (unit.ran[k] != unit.stage) continue;
        const U a = unit.members[k];
        U phase, order, stance, f1, l619;
        if (!Rd(a + 0x224, phase) || !Rd(a + 0x1D8, order) || !Rd(a + 0x220, stance) || !Rb(a + 0xF1, f1) || !Rb(a + 0x619, l619)) continue;
        if (!seen++) { firstOrder = order; firstStance = stance; }
        else { if (order != firstOrder) orderMixed = 1; if (stance != firstStance) stanceMixed = 1; }
        if (!admitted) continue;
        ++g_words[WECompare];
        ++g_words[WECompare + (phase == 0 ? 1 : phase == 6 ? 2 : phase == 7 ? 3 : phase == 9 ? 4 : 5)];
        const bool unitOn = slot[EvD9dValue] != 0;
        if (phase == 6) ++g_words[WECompare + (unitOn ? 6 : 7)];
        else if (unitOn && phase != 7 && phase != 9) ++g_words[WECompare + 8];
        ++g_words[WECompare + (f1 ? 9 : 10)];
        ++g_words[WECompare + (l619 ? 11 : 12)];
    }
    if (!seen) return;
    ++g_words[WEOrder];
    ++g_words[WEOrder + (orderMixed ? 2 : 1)];
    ++g_words[WEOrder + (stanceMixed ? 4 : 3)];
    if (admitted) ++g_words[WEOrder + 5];
}
void Retire(U) {}

} // namespace

bool Bind(U imageBase, U* bindings) {
    g_delta = imageBase - 0x400000; g_bound = imageBase != 0;
    g_stateFirst = V(kStateFirst); g_rest = V(kRestState);
    g_native10FC370 = V(0x10FC370); g_native649520 = V(0x649520); g_native64F8F0 = V(0x64F8F0);
    g_native64DE80 = V(0x64DE80); g_native57E1F0 = V(0x57E1F0);
    g_evp = Fn(g_native); g_cnt[15] = Fn(g_native); // the entry gate's native-block pointer cell (U_ENGAGE_CNT + 60)
    bindings[KNTWR_BIND_U_POSTURE] = Fn(&PostureGate);
    bindings[KNTWR_BIND_U_EVP] = Fn(&g_evp);
    bindings[KNTWR_BIND_U_ENGAGE_CNT] = Fn(g_cnt);
    bindings[KNTWR_BIND_U_DRIVER_ALT] = Fn(&DriverAltGate);
    bindings[KNTWR_BIND_U_UNIT_MODIFIER] = Fn(&ModifierGate);
    bindings[KNTWR_BIND_U_ORDER_PREDICATE] = Fn(&OrderPredicateGate);
    bindings[KNTWR_BIND_U_UNIT_ARRIVAL] = Fn(&UnitArrivalGate);
    bindings[KNTWR_BIND_U_NODE_BEGIN] = Fn(&NodeBeginGate);
    bindings[KNTWR_BIND_U_NODE_STEP] = Fn(&NodeStepGate);
    bindings[KNTWR_BIND_U_PHASE6] = Fn(&Phase6Gate);
    bindings[KNTWR_BIND_U_PHASE7] = Fn(&Phase7Gate);
    static const U kBegin[3] = {0x816900, 0x816080, 0x815FF0}, kStep[4] = {0x819310, 0x66DD10, 0x818500, 0x818330};
    for (U i = 0; i < 3; ++i) g_beginTarget[i] = g_beginEntry[i] = V(kBegin[i]);
    for (U i = 0; i < 4; ++i) g_stepTarget[i] = g_stepEntry[i] = V(kStep[i]);    return g_bound;
}

bool Start(U imageBase, U postureMode, U engageMode, const U* cloneEntries) {
    g_started = false;
    g_postureMode = kntwr_unit_policy::Off; g_engageMode = kntwr_unit_policy::Off;
    if (!g_bound || imageBase - 0x400000 != g_delta) return false;
    if ((postureMode || engageMode) && !StatesPinned()) return false;
    if ((postureMode || engageMode) && !UnitFsmPinned()) return false;
    if ((postureMode || engageMode) && !cloneEntries) return false;
    g_postureMode = postureMode; g_engageMode = engageMode;
    if (postureMode || engageMode) {
        const U begin[3] = {KNTWR_CLONE_BRAIN_U_HOT_BEGIN, KNTWR_CLONE_BRAIN_U_ACTION_BEGIN, KNTWR_CLONE_BRAIN_U_RELATED_BEGIN};
        const U step[4] = {KNTWR_CLONE_BRAIN_U_HOT_STEP, KNTWR_CLONE_BRAIN_U_IDLE_STEP, KNTWR_CLONE_BRAIN_U_ACTION_STEP,
                           KNTWR_CLONE_BRAIN_U_RELATED_STEP};
        for (U i = 0; i < 3; ++i) if (cloneEntries[begin[i]]) g_beginEntry[i] = cloneEntries[begin[i]];
        for (U i = 0; i < 4; ++i) if (cloneEntries[step[i]]) g_stepEntry[i] = cloneEntries[step[i]];
    }
    g_tableOk[0] = g_tableOk[1] = 0; g_tableNext = 0;
    g_evp = Fn(g_native);
    g_posture = Provider{kntwr_unit_policy::Posture, postureMode, &DecidePosture, &EndPosture, &Retire, nullptr};
    g_engage = Provider{kntwr_unit_policy::Engage, engageMode, &DecideEngage, &EndEngage, &Retire, nullptr};
    g_started = true;
    g_words[WVersion] = kVersion; g_words[WPostureMode] = postureMode; g_words[WEngageMode] = engageMode;
    return true;
}
const Provider* PostureProvider() { return g_started && g_postureMode ? &g_posture : nullptr; }
const Provider* EngageProvider() { return g_started && g_engageMode ? &g_engage : nullptr; }
void Stop() { g_started = false; g_evp = Fn(g_native); }
void Reset() {
    memset(g_words, 0, sizeof(g_words)); memset(g_cnt, 0, sizeof(g_cnt)); memset(g_matrix, 0, sizeof(g_matrix));
    g_cnt[15] = Fn(g_native);
    memset(g_hist, 0, sizeof(g_hist)); memset(g_speedMembers, 0, sizeof(g_speedMembers));
    g_lastStagePosture = g_lastStageEngage = ~0u;
    g_words[WVersion] = kVersion; g_words[WPostureMode] = g_postureMode; g_words[WEngageMode] = g_engageMode;
}

void Snapshot(U* words) {
    memcpy(words, g_words, sizeof(g_words));
    words[WPApply] = g_cnt[CApplied]; words[WPApply + 1] = g_cnt[CTransition]; words[WPApply + 2] = g_cnt[CUpdateOnly];
    words[WPApply + 3] = g_cnt[CNullState]; words[WPApply + 4] = g_cnt[CNativeState]; words[WPApply + 5] = g_cnt[CNativeTable];
    words[WPApply + 6] = g_cnt[CNativeState] + g_cnt[CNativeTable]; words[WPApply + 7] = g_cnt[CBudget];
    words[WESites] = g_cnt[CD9d]; words[WESites + 1] = g_cnt[CAlt]; words[WESites + 2] = g_cnt[CAlt]; // the alternate driver is the only mid-stage Engage drain
    words[WESites + 3] = g_cnt[CLkNative]; words[WELookups + 3] = g_cnt[CLkServed];
    // Top posture state pairs (count desc, then native index, then unit index).
    bool taken[15][15] = {};
    for (U p = 0; p < 6; ++p) {
        U bn = 0, bu = 0, bc = 0;
        for (U n = 0; n < 15; ++n) for (U u = 0; u < 15; ++u)
            if (!taken[n][u] && g_matrix[n][u] > bc) { bn = n; bu = u; bc = g_matrix[n][u]; }
        taken[bn][bu] = true;
        words[WPPairs + 3 * p] = bn; words[WPPairs + 3 * p + 1] = bu; words[WPPairs + 3 * p + 2] = bc;
    }
    for (U s = 0; s < 4; ++s) words[WPHist + 1 + s] = g_speedMembers[s];
    auto modal = [](U act, U speedLo, U speedHi, U& state, U& count) {
        U sum[15] = {};
        for (U s = speedLo; s <= speedHi; ++s) for (U i = 0; i < 15; ++i) sum[i] += g_hist[act][s][i];
        state = 0; count = 0;
        for (U i = 0; i < 15; ++i) if (sum[i] > count) { state = i; count = sum[i]; }
    };
    for (U a = 0; a < 5; ++a) modal(a, 0, 3, words[WPHist + 5 + 2 * a], words[WPHist + 6 + 2 * a]);
    for (U a = 1; a < 5; ++a) for (U s = 1; s <= 2; ++s)
        modal(a, s, s, words[WPHist + 15 + 4 * (a - 1) + 2 * (s - 1)], words[WPHist + 16 + 4 * (a - 1) + 2 * (s - 1)]);
}
} // namespace kntwr_unit_posture_engage
