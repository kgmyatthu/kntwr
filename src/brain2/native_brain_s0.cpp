// S0 attribution timer: counting/timing gates of the BRAIN_S0 clone family (native_brain_s0.h). Owner thread only.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <algorithm>
#include <cstring>
#include "native_brain_s0.h"
#include "native_unit_policy.h"
#include "ntw2_clones.h"
static_assert(sizeof(void*) == 4, "the S0 gates are Win32 x86 naked forwarding thunks");
namespace ntw2_brain_s0 {
namespace {
using U64 = unsigned long long;
// ---- gate data (referenced by the naked gates; layouts are part of the asm contract) -------------------------------
// Static gates: index -> routed callee. Their rows are fixed in the gate bodies (kStaticGates mirrors the generator's
// S0_GATE_CALLEE: tools/generate_clone_specs.py pins every gate site to exactly these callees).
enum StaticGate : U {
    GTarget, GDriver, GDriverAlt, GTimer, GOrderFinal, GOrderNode, GOrderAdjust, GOrderPredicate, GUnitArrival,
    GUnitModifier, GStance, GPath, GPosture, GCalibOuter, GCalibInner, StaticGateCount
};
// Dispatch gates (virtual call sites): 256-entry tables indexed by bits 8..15 of the actual target (image deltas are
// 64 KiB multiples, so the preferred-VA byte is the runtime byte). Entry hit when target + g_neg[i] == 0.
enum DispatchGate : U { DNodeBegin, DNodeStep, DFinalize, DSelector, DCalib, DispatchGateCount };
constexpr U kCalibOuter = RowCount, kCalibInner = RowCount + 1, kSlots = RowCount + 2;
constexpr U kDepth = 64;
struct alignas(64) Frame { U ret, row, startLo, startHi, childLo, childHi, direct, desc, watch, old, pad[6]; };
struct Occ { U inclLo, inclHi, exclLo, exclHi, sampled, children, desc, pad; };
static_assert(sizeof(Frame) == 64 && sizeof(Occ) == 32, "asm frame/occurrence layout");
U g_static[StaticGateCount];
U g_neg[DispatchGateCount * 256], g_repl[DispatchGateCount * 256], g_hitRow[DispatchGateCount * 256];
U g_miss[DispatchGateCount];
U g_calls[kSlots];          // this stage's calls (flag-free increments from the gates)
U g_mode;                   // nonzero: the current occurrence is timed
U g_row, g_jmp;             // gate -> S0Sampled hand-off (no gate runs in between)
U g_depth, g_maxDepth, g_overflow, g_exit, g_lastD, g_lastExcl;
Frame g_frames[kDepth];
Occ g_occ[kSlots];
// Unit-policy routing (--brain-unit-*; src/brain2/native_unit_policy.h). g_umask = the LIVE mechanic mask of the current
// occurrence (0 outside units / non-members); the routed gates index flag-free 8-entry tables by it, so the unsampled cost
// of an unrouted occurrence is two loads on the routed gates only.
U g_umask, g_save, g_unitFatigue, g_nativeFatigue, g_usDriver, g_uPosture;
bool g_unitMode;
U g_routeDriver[8], g_routePosture[8];

#define S0_RDTSCP __asm _emit 0x0F __asm _emit 0x01 __asm _emit 0xF9
#define S0_LFENCE __asm _emit 0x0F __asm _emit 0xAE __asm _emit 0xE8

// Stack at entry: [watch kind][return address][args]; every register and EFLAGS are the original call's. g_row/g_jmp
// name the row and the destination. Pushes a frame, swaps the return address for S0Exit, reads the TSC, forwards.
// watch 1: order receiver A = ECX (6631A0), 2: A = [ECX+4] (662E70); A+1D8 is compared at exit (changed -> row+1).
__declspec(naked) void S0Sampled() {
    __asm pushfd
    __asm push eax
    __asm push ecx
    __asm push edx
    __asm push ebx                                  // [ebx][edx][ecx][eax][eflags][watch][ret]
    __asm mov eax, dword ptr [g_depth]
    __asm cmp eax, 64
    __asm jae overflow
    __asm lea ebx, [eax + 1]
    __asm mov dword ptr [g_depth], ebx
    __asm cmp ebx, dword ptr [g_maxDepth]
    __asm jbe depth_ok
    __asm mov dword ptr [g_maxDepth], ebx
depth_ok:
    __asm shl eax, 6
    __asm lea ebx, g_frames[eax]
    __asm mov eax, dword ptr [esp + 24]
    __asm mov dword ptr [ebx], eax
    __asm mov eax, dword ptr [g_row]
    __asm mov dword ptr [ebx + 4], eax
    __asm xor eax, eax
    __asm mov dword ptr [ebx + 16], eax
    __asm mov dword ptr [ebx + 20], eax
    __asm mov dword ptr [ebx + 24], eax
    __asm mov dword ptr [ebx + 28], eax
    __asm mov dword ptr [ebx + 32], eax
    __asm mov eax, dword ptr [esp + 20]
    __asm test eax, eax
    __asm jz no_watch
    __asm mov ecx, dword ptr [esp + 8]
    __asm cmp eax, 1
    __asm je watch_receiver
    __asm mov ecx, dword ptr [ecx + 4]
watch_receiver:
    __asm add ecx, 0x1D8
    __asm mov dword ptr [ebx + 32], ecx
    __asm mov ecx, dword ptr [ecx]
    __asm mov dword ptr [ebx + 36], ecx
no_watch:
    __asm mov eax, dword ptr [g_exit]
    __asm mov dword ptr [esp + 24], eax
    S0_RDTSCP
    __asm mov dword ptr [ebx + 8], eax
    __asm mov dword ptr [ebx + 12], edx
    S0_LFENCE
    __asm pop ebx
    __asm pop edx
    __asm pop ecx
    __asm pop eax
    __asm popfd
    __asm lea esp, [esp + 4]
    __asm jmp dword ptr [g_jmp]
overflow:
    __asm inc dword ptr [g_overflow]
    __asm pop ebx
    __asm pop edx
    __asm pop ecx
    __asm pop eax
    __asm popfd
    __asm lea esp, [esp + 4]
    __asm jmp dword ptr [g_jmp]
}
// The callee returned here (its RET n already removed its arguments). Every register, EFLAGS and the FP state it
// produced are preserved; the frame's cycles are charged to its row (inclusive, exclusive of direct children) and to
// the parent frame's children; then the original return address is resumed.
__declspec(naked) void S0Exit() {
    __asm lea esp, [esp - 4]
    __asm pushfd
    __asm push eax
    __asm push ecx
    __asm push edx
    __asm push ebx
    __asm push esi
    __asm push edi                                  // [edi][esi][ebx][edx][ecx][eax][eflags][return slot]
    S0_RDTSCP
    __asm mov esi, dword ptr [g_depth]
    __asm dec esi
    __asm mov dword ptr [g_depth], esi
    __asm shl esi, 6
    __asm lea esi, g_frames[esi]
    __asm sub eax, dword ptr [esi + 8]
    __asm sbb edx, dword ptr [esi + 12]
    __asm mov dword ptr [g_lastD], eax
    __asm mov ecx, dword ptr [esi]
    __asm mov dword ptr [esp + 28], ecx
    __asm mov ebx, dword ptr [esi + 4]
    __asm mov ecx, dword ptr [esi + 32]
    __asm test ecx, ecx
    __asm jz unchanged
    __asm mov ecx, dword ptr [ecx]
    __asm cmp ecx, dword ptr [esi + 36]
    __asm je unchanged
    __asm inc ebx
unchanged:
    __asm shl ebx, 5
    __asm lea edi, g_occ[ebx]
    __asm add dword ptr [edi], eax
    __asm adc dword ptr [edi + 4], edx
    __asm mov ecx, eax
    __asm mov ebx, edx
    __asm sub ecx, dword ptr [esi + 16]
    __asm sbb ebx, dword ptr [esi + 20]
    __asm mov dword ptr [g_lastExcl], ecx
    __asm add dword ptr [edi + 8], ecx
    __asm adc dword ptr [edi + 12], ebx
    __asm inc dword ptr [edi + 16]
    __asm mov ecx, dword ptr [esi + 24]
    __asm add dword ptr [edi + 20], ecx
    __asm mov ecx, dword ptr [esi + 28]
    __asm add dword ptr [edi + 24], ecx
    __asm lea ecx, g_frames
    __asm cmp esi, ecx
    __asm je no_parent
    __asm add dword ptr [esi - 64 + 16], eax
    __asm adc dword ptr [esi - 64 + 20], edx
    __asm inc dword ptr [esi - 64 + 24]
    __asm mov ecx, dword ptr [esi + 28]
    __asm inc ecx
    __asm add dword ptr [esi - 64 + 28], ecx
no_parent:
    __asm pop edi
    __asm pop esi
    __asm pop ebx
    __asm pop edx
    __asm pop ecx
    __asm pop eax
    __asm popfd
    __asm ret
}

// Unsampled path of a single-row gate: flag-free counter increment and mode test (JECXZ), then the original JMP.
// PRE performs the movs of the replaced run; LOADT puts the destination in ECX (sampled path, EFLAGS saved later).
#define S0_STATIC_GATE(name, row, watch, PRE, LOADT, JMP) \
    __declspec(naked) void name() { \
        PRE \
        __asm push eax \
        __asm mov eax, dword ptr [g_calls + 4 * (row)] \
        __asm lea eax, [eax + 1] \
        __asm mov dword ptr [g_calls + 4 * (row)], eax \
        __asm pop eax \
        __asm push ecx \
        __asm mov ecx, dword ptr [g_mode] \
        __asm jecxz pass \
        __asm mov dword ptr [g_row], row \
        LOADT \
        __asm mov dword ptr [g_jmp], ecx \
        __asm pop ecx \
        __asm push watch \
        __asm jmp S0Sampled \
    __asm pass: \
        __asm pop ecx \
        JMP \
    }
#define S0_NONE
// Routed variants: destination = table[g_umask] (flag-free: loads/stores only; EAX preserved through g_save).
#define S0_LOAD_ROUTED(tab) __asm mov ecx, dword ptr [g_umask] __asm mov ecx, dword ptr [tab + ecx * 4]
#define S0_JMP_ROUTED(tab) __asm mov dword ptr [g_save], eax __asm mov eax, dword ptr [g_umask] \
    __asm mov eax, dword ptr [tab + eax * 4] __asm mov dword ptr [g_jmp], eax __asm mov eax, dword ptr [g_save] \
    __asm jmp dword ptr [g_jmp]
#define S0_LOAD_STATIC(k) __asm mov ecx, dword ptr [g_static + 4 * (k)]
#define S0_JMP_STATIC(k) __asm jmp dword ptr [g_static + 4 * (k)]
// Row literals (asm immediates); checked against Row below.
#define S0R_TARGET 3
#define S0R_DRIVER 4
#define S0R_DRIVER_ALT 5
#define S0R_ORDER_FINAL 17
#define S0R_ORDER_NODE 19
#define S0R_ORDER_ADJUST 21
#define S0R_ORDER_PREDICATE 22
#define S0R_UNIT_ARRIVAL 23
#define S0R_UNIT_MODIFIER 24
#define S0R_STANCE 25
#define S0R_PATH 26
#define S0R_POSTURE 27
#define S0R_POSTURE_NEXT 28
#define S0R_TIMER 31
#define S0R_TIMER_PROVIDER 32
#define S0R_CALIB_OUTER 33
#define S0R_CALIB_INNER 34
static_assert(S0R_TARGET == Target && S0R_DRIVER == Driver && S0R_DRIVER_ALT == DriverAlt &&
              S0R_ORDER_FINAL == OrderFinal && S0R_ORDER_NODE == OrderNode && S0R_ORDER_ADJUST == OrderAdjust &&
              S0R_ORDER_PREDICATE == OrderPredicate && S0R_UNIT_ARRIVAL == UnitArrival &&
              S0R_UNIT_MODIFIER == UnitModifier && S0R_STANCE == Stance && S0R_PATH == Path && S0R_POSTURE == Posture &&
              S0R_POSTURE_NEXT == PostureNext && S0R_TIMER == Timer && S0R_TIMER_PROVIDER == TimerProvider &&
              S0R_CALIB_OUTER == kCalibOuter && S0R_CALIB_INNER == kCalibInner, "gate row literals");
static_assert(GTarget == 0 && GDriver == 1 && GDriverAlt == 2 && GTimer == 3 && GOrderFinal == 4 && GOrderNode == 5 &&
              GOrderAdjust == 6 && GOrderPredicate == 7 && GUnitArrival == 8 && GUnitModifier == 9 && GStance == 10 &&
              GPath == 11 && GPosture == 12 && GCalibOuter == 13 && GCalibInner == 14, "static gate literals");
S0_STATIC_GATE(GateTarget, S0R_TARGET, 0, S0_NONE, S0_LOAD_STATIC(0), S0_JMP_STATIC(0))
S0_STATIC_GATE(GateDriver, S0R_DRIVER, 0, S0_NONE, S0_LOAD_ROUTED(g_routeDriver), S0_JMP_ROUTED(g_routeDriver))
S0_STATIC_GATE(GateDriverAlt, S0R_DRIVER_ALT, 0, S0_NONE, S0_LOAD_STATIC(2), S0_JMP_STATIC(2))
S0_STATIC_GATE(GateTimer, S0R_TIMER, 0, S0_NONE, S0_LOAD_STATIC(3), S0_JMP_STATIC(3))
S0_STATIC_GATE(GateOrderFinal, S0R_ORDER_FINAL, 1, S0_NONE, S0_LOAD_STATIC(4), S0_JMP_STATIC(4))
S0_STATIC_GATE(GateOrderNode, S0R_ORDER_NODE, 2, S0_NONE, S0_LOAD_STATIC(5), S0_JMP_STATIC(5))
S0_STATIC_GATE(GateOrderAdjust, S0R_ORDER_ADJUST, 0, S0_NONE, S0_LOAD_STATIC(6), S0_JMP_STATIC(6))
S0_STATIC_GATE(GateOrderPredicate, S0R_ORDER_PREDICATE, 0, S0_NONE, S0_LOAD_STATIC(7), S0_JMP_STATIC(7))
S0_STATIC_GATE(GateUnitArrival, S0R_UNIT_ARRIVAL, 0, S0_NONE, S0_LOAD_STATIC(8), S0_JMP_STATIC(8))
S0_STATIC_GATE(GateUnitModifier, S0R_UNIT_MODIFIER, 0, S0_NONE, S0_LOAD_STATIC(9), S0_JMP_STATIC(9))
S0_STATIC_GATE(GateStance, S0R_STANCE, 0, S0_NONE, S0_LOAD_STATIC(10), S0_JMP_STATIC(10))
S0_STATIC_GATE(GatePath, S0R_PATH, 0, S0_NONE, S0_LOAD_STATIC(11), S0_JMP_STATIC(11))
S0_STATIC_GATE(GatePosture, S0R_POSTURE, 0, S0_NONE, S0_LOAD_ROUTED(g_routePosture), S0_JMP_ROUTED(g_routePosture))
S0_STATIC_GATE(GateCalibOuter, S0R_CALIB_OUTER, 0, S0_NONE, S0_LOAD_STATIC(13), S0_JMP_STATIC(13))
S0_STATIC_GATE(GateCalibInner, S0R_CALIB_INNER, 0, S0_NONE, S0_LOAD_STATIC(14), S0_JMP_STATIC(14))
// Macro arguments must not contain top-level commas: every operand list goes through a named helper macro.
// 10FBBD5 `mov ecx,[esi+4]; mov eax,[ecx]; call [eax]` (FSM next-state virtual of the current state).
#define S0_PRE_NEXT __asm mov ecx, dword ptr [esi + 4] __asm mov eax, dword ptr [ecx]
#define S0_LOAD_NEXT __asm mov ecx, dword ptr [eax]
#define S0_JMP_NEXT __asm jmp dword ptr [eax]
S0_STATIC_GATE(GatePostureNext, S0R_POSTURE_NEXT, 0, S0_PRE_NEXT, S0_LOAD_NEXT, S0_JMP_NEXT)
// 602E39 `mov eax,[esi]; mov eax,[eax]; call eax` and 602E65 `mov eax,[eax+4]; call eax` (timer providers, ST0 result).
#define S0_PRE_PROVIDER0 __asm mov eax, dword ptr [esi] __asm mov eax, dword ptr [eax]
#define S0_PRE_PROVIDER1 __asm mov eax, dword ptr [eax + 4]
#define S0_LOAD_EAX __asm mov ecx, eax
#define S0_JMP_EAX __asm jmp eax
S0_STATIC_GATE(GateProvider0, S0R_TIMER_PROVIDER, 0, S0_PRE_PROVIDER0, S0_LOAD_EAX, S0_JMP_EAX)
S0_STATIC_GATE(GateProvider1, S0R_TIMER_PROVIDER, 0, S0_PRE_PROVIDER1, S0_LOAD_EAX, S0_JMP_EAX)
// Destination of the selector dispatch for the native fatigue target 670F40 when units are on: the admitted occurrence enters
// the unit gate (NTW2_BIND_U_FATIGUE, ECX = A) so the S0 fatigue row times the unit apply in place of the native body; every
// other occurrence runs the native 670F40. Reached through S0Sampled/the pass path with the original registers (ECX = A).
__declspec(naked) void S0FatigueRoute() {
    __asm test dword ptr [g_umask], 1
    __asm jz native
    __asm jmp dword ptr [g_unitFatigue]
native:
    __asm jmp dword ptr [g_nativeFatigue]
}

// Virtual-call gate: PUSHT pushes the actual target; the table maps it to (row, destination), unknown targets keep
// their own address on the gate's miss row. Flag-free on the unsampled path.
#define S0_DISPATCH_GATE(name, k, PRE, PUSHT) \
    __declspec(naked) void name() { \
        PRE \
        PUSHT \
        __asm push ecx \
        __asm push edx \
        __asm mov edx, dword ptr [esp + 8] \
        __asm movzx ecx, dh \
        __asm mov ecx, dword ptr [g_neg + 1024 * (k) + ecx * 4] \
        __asm lea ecx, [ecx + edx] \
        __asm jecxz hit \
        __asm mov dword ptr [g_jmp], edx \
        __asm mov ecx, dword ptr [g_miss + 4 * (k)] \
        __asm jmp counted \
    __asm hit: \
        __asm movzx ecx, dh \
        __asm mov edx, dword ptr [g_repl + 1024 * (k) + ecx * 4] \
        __asm mov dword ptr [g_jmp], edx \
        __asm mov ecx, dword ptr [g_hitRow + 1024 * (k) + ecx * 4] \
    __asm counted: \
        __asm mov edx, dword ptr [g_calls + ecx * 4] \
        __asm lea edx, [edx + 1] \
        __asm mov dword ptr [g_calls + ecx * 4], edx \
        __asm mov dword ptr [g_row], ecx \
        __asm pop edx \
        __asm mov ecx, dword ptr [g_mode] \
        __asm jecxz pass \
        __asm pop ecx \
        __asm lea esp, [esp + 4] \
        __asm push 0 \
        __asm jmp S0Sampled \
    __asm pass: \
        __asm pop ecx \
        __asm lea esp, [esp + 4] \
        __asm jmp dword ptr [g_jmp] \
    }
static_assert(DNodeBegin == 0 && DNodeStep == 1 && DFinalize == 2 && DSelector == 3 && DCalib == 4, "dispatch literals");
// 66D43B keeps `mov ecx,edi`; the gate replaces `call [eax+108]` (the class selector, 670F40 = fatigue).
S0_DISPATCH_GATE(GateSelector, 3, S0_NONE, __asm push dword ptr [eax + 0x108])
// 658F6E/658F7F `mov ecx,edi; call [eax+4]` / `call [eax+8]` (driver node begin/step).
#define S0_PRE_EDI __asm mov ecx, edi
S0_DISPATCH_GATE(GateNodeBegin, 0, S0_PRE_EDI, __asm push dword ptr [eax + 4])
S0_DISPATCH_GATE(GateNodeStep, 1, S0_PRE_EDI, __asm push dword ptr [eax + 8])
// 658F99 keeps `mov ecx,esi`; the gate replaces `call [eax+1A4]` (finalizer).
S0_DISPATCH_GATE(GateFinalize, 2, S0_NONE, __asm push dword ptr [eax + 0x1A4])
S0_DISPATCH_GATE(GateCalibDispatch, 4, S0_NONE, __asm push dword ptr [g_static + 4 * 14])

// ---- module state ------------------------------------------------------------------------------------------------
struct Totals { U64 calls, sampled, hits, children, desc, incl; long long excl; double sqIncl, sqExcl; U maxStage; };
Totals g_rows[kSlots];
U g_delta, g_bound, g_started, g_configured, g_state, g_shift = kDefaultShift;
U g_entries[NTW2_CLONE_COUNT];
U g_stage, g_stages, g_sampledOccurrences, g_unitOverflow, g_nestedRoot, g_abandoned, g_calSamples;
U64 g_occurrences, g_site6, g_stageStart, g_tscFirst, g_tscLast;
LONGLONG g_qpcFirst, g_qpcLast, g_qpcFreq;
U g_calTscKhz, g_floorX16, g_floorSpreadX16, g_nestX16, g_nestSpreadX16, g_rootX16, g_rootSpreadX16;
U g_passX16, g_dispatchX16, g_occurrenceX16;
// Stage unit ordinals: open addressing keyed by the unit pointer, entries valid only for the current stage tag.
constexpr U kUnits = 4096;
struct UnitSlot { U unit, tag, ordinal, members; };
UnitSlot g_units[kUnits];
U g_unitCount, g_lastUnit, g_lastSlot = ~0u, g_nullMembers, g_otherMembers;

inline U V(U va) { return va + g_delta; }
inline U D(U address) { return *reinterpret_cast<const volatile U*>(address); }
template <class F> U Fn(F f) { return static_cast<U>(reinterpret_cast<uintptr_t>(reinterpret_cast<const void*>(f))); }
inline U64 Tsc() { unsigned aux; _mm_lfence(); const U64 t = __rdtscp(&aux); _mm_lfence(); return t; }
inline U64 Join(U lo, U hi) { return (static_cast<U64>(hi) << 32) | lo; }

struct StaticSpec { U binding, va; };
const StaticSpec kStaticGates[StaticGateCount] = {
    {NTW2_BIND_S0_TARGET, 0x6718F0}, {NTW2_BIND_S0_DRIVER, 0x658C50}, {NTW2_BIND_S0_DRIVER_ALT, 0x64DE80},
    {NTW2_BIND_S0_TIMER, 0x602E00}, {NTW2_BIND_S0_ORDER_FINAL, 0x6631A0}, {NTW2_BIND_S0_ORDER_NODE, 0x662E70},
    {NTW2_BIND_S0_ORDER_ADJUST, 0x66AE10}, {NTW2_BIND_S0_ORDER_PREDICATE, 0x64F8F0},
    {NTW2_BIND_S0_UNIT_ARRIVAL, 0x57E1F0}, {NTW2_BIND_S0_UNIT_MODIFIER, 0x649520}, {NTW2_BIND_S0_STANCE, 0x662E50},
    {NTW2_BIND_S0_PATH, 0x819770}, {NTW2_BIND_S0_POSTURE, 0x10FC370}, {NTW2_BIND_COUNT, 0}, {NTW2_BIND_COUNT, 0}};
using Gate = void (*)();
const Gate kStaticFns[StaticGateCount] = {
    GateTarget, GateDriver, GateDriverAlt, GateTimer, GateOrderFinal, GateOrderNode, GateOrderAdjust,
    GateOrderPredicate, GateUnitArrival, GateUnitModifier, GateStance, GatePath, GatePosture, GateCalibOuter,
    GateCalibInner};
// Known dispatch targets: (gate, preferred VA, row, clone or ~0 for the original).
struct DispatchSpec { U gate, va, row, clone; };
const DispatchSpec kDispatch[] = {
    {DNodeBegin, 0x816900, NodeBeginHot, NTW2_CLONE_BRAIN_S0_HOT_BEGIN},
    {DNodeBegin, 0x816080, NodeBeginMove, NTW2_CLONE_BRAIN_S0_ACTION_BEGIN},
    {DNodeBegin, 0x815FF0, NodeBeginRelated, NTW2_CLONE_BRAIN_S0_RELATED_BEGIN},
    {DNodeStep, 0x819310, NodeStepHot, NTW2_CLONE_BRAIN_S0_HOT_STEP},
    {DNodeStep, 0x66DD10, NodeStepIdle, NTW2_CLONE_BRAIN_S0_IDLE_STEP},
    {DNodeStep, 0x818500, NodeStepMove, NTW2_CLONE_BRAIN_S0_ACTION_STEP},
    {DNodeStep, 0x818330, NodeStepRelated, NTW2_CLONE_BRAIN_S0_RELATED_STEP},
    {DFinalize, 0x6543D0, Finalize, NTW2_CLONE_BRAIN_S0_FINALIZE},
    {DSelector, 0x670F40, Fatigue, ~0u}};
const U kMissRow[DispatchGateCount] = {NodeBeginOther, NodeStepOther, FinalizeOther, SelectorOther, kCalibInner};
const U kRoutedClone[StaticGateCount] = {
    ~0u, NTW2_CLONE_BRAIN_S0_MOVEORDER, ~0u, NTW2_CLONE_BRAIN_S0_TIMER, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u,
    NTW2_CLONE_BRAIN_S0_PATH, NTW2_CLONE_BRAIN_S0_POSTURE, ~0u, ~0u};

void __cdecl EmptyStub() {}
void __fastcall EmptyThiscall(void*, void*) {}
void __cdecl NestStub() { reinterpret_cast<Gate>(&GateCalibInner)(); }

void SetDispatch(U gate, U target, U row, U destination) {
    const U index = gate * 256 + ((target >> 8) & 0xFF);
    g_neg[index] = 0u - target; g_hitRow[index] = row; g_repl[index] = destination;
}
// Static and dispatch tables forwarding to the originals (Bind) or into the family (Start).
// The unit-routed gates' 8-entry tables (index = live mechanic mask of the occurrence): masks with the Engage / Posture bit go
// to the unit driver clone / unit posture gate when those exist, everything else to the S0 destination of the gate.
void RefreshRoutes() {
    for (U m = 0; m < 8; ++m) {
        g_routeDriver[m] = (m & 4) && g_usDriver ? g_usDriver : g_static[GDriver];
        g_routePosture[m] = (m & 2) && g_uPosture ? g_uPosture : g_static[GPosture];
    }
}
bool Route(const U* entries) {
    for (U k = 0; k < StaticGateCount; ++k) {
        U target = kStaticGates[k].va ? V(kStaticGates[k].va) : Fn(&EmptyStub);
        if (k == GCalibOuter) target = Fn(&NestStub);
        if (entries && kRoutedClone[k] != ~0u) target = entries[kRoutedClone[k]];
        g_static[k] = target;
    }
    RefreshRoutes();
    std::memset(g_neg, 0, sizeof(g_neg));
    for (U g = 0; g < DispatchGateCount; ++g) g_miss[g] = kMissRow[g];
    for (const DispatchSpec& d : kDispatch) {
        const U index = d.gate * 256 + ((d.va >> 8) & 0xFF);
        if (g_neg[index]) return false; // byte collision: the table would misroute
        U destination = entries && d.clone != ~0u ? entries[d.clone] : V(d.va);
        if (g_unitMode && d.gate == DSelector && d.va == 0x670F40) destination = Fn(&S0FatigueRoute);
        SetDispatch(d.gate, V(d.va), d.row, destination);
    }
    SetDispatch(DCalib, Fn(&EmptyStub), kCalibInner, Fn(&EmptyStub));
    return true;
}

// ---- occurrence bookkeeping --------------------------------------------------------------------------------------
void Flush() {
    for (U r = 0; r < kSlots; ++r) {
        Occ& o = g_occ[r];
        if (!o.sampled) continue;
        Totals& t = g_rows[r];
        const U64 incl = Join(o.inclLo, o.inclHi);
        const long long excl = static_cast<long long>(Join(o.exclLo, o.exclHi));
        t.incl += incl; t.excl += excl; t.sampled += o.sampled; t.children += o.children; t.desc += o.desc; ++t.hits;
        t.sqIncl += static_cast<double>(incl) * static_cast<double>(incl);
        t.sqExcl += static_cast<double>(excl) * static_cast<double>(excl);
        o = Occ{};
    }
}
U Mix(U stage, U unit, U member) {
    U h = stage * 0x9E3779B1u ^ (unit + 0x7F4A7C15u) * 0x85EBCA77u ^ (member + 0x165667B1u) * 0xC2B2AE3Du;
    h ^= h >> 15; h *= 0x2C1B3C6Du; h ^= h >> 12; h *= 0x297A2D39u; h ^= h >> 15;
    return h;
}
// Deterministic stratum: (stage, unit ordinal, member ordinal). Classes without a brain soldier layout never have
// A+1F0 read (brain2 refuses those dereferences too): they use the unit ordinal 0xFFFF.
bool Decide(U entity, U brainClass) {
    U ordinal, member;
    const U unit = brainClass <= 3 ? D(entity + 0x1F0) : 0;
    if (brainClass > 3) { ordinal = 0xFFFF; member = g_otherMembers++; }
    else if (!unit) { ordinal = 0xFFFE; member = g_nullMembers++; }
    else {
        U slot = g_lastSlot;
        if (unit != g_lastUnit || slot == ~0u) {
            slot = ((unit >> 3) * 2654435761u) & (kUnits - 1);
            U probes = 0;
            while (g_units[slot].tag == g_stage && g_units[slot].unit != unit && ++probes < kUnits)
                slot = (slot + 1) & (kUnits - 1);
            if (g_units[slot].tag != g_stage) {
                if (g_unitCount >= kUnits / 4 * 3) { ++g_unitOverflow; slot = ~0u; }
                else g_units[slot] = {unit, g_stage, g_unitCount++, 0};
            }
            g_lastUnit = unit; g_lastSlot = slot;
        }
        if (slot == ~0u) { ordinal = 0xFFFD; member = g_nullMembers++; }
        else { ordinal = g_units[slot].ordinal; member = g_units[slot].members++; }
    }
    return !g_shift || (Mix(g_stage, ordinal, member) >> (32 - g_shift)) == 0;
}
U64 TimedRoot(U row, U entry, U receiver) {
    Frame& f = g_frames[0];
    f = Frame{}; f.row = row;
    g_depth = 1; if (!g_maxDepth) g_maxDepth = 1;
    const U64 start = Tsc();
    f.startLo = static_cast<U>(start); f.startHi = static_cast<U>(start >> 32);
    g_mode = 1;
    bool completed = false;
    U64 d = 0;
    __try {
        reinterpret_cast<void (__thiscall*)(void*)>(entry)(reinterpret_cast<void*>(receiver));
        unsigned aux; d = __rdtscp(&aux) - start;
        completed = true;
    } __finally {
        g_mode = 0;
        if (!completed || g_depth != 1) {
            ++g_abandoned; g_depth = 0;
            std::memset(g_occ, 0, sizeof(g_occ));
        }
    }
    g_depth = 0;
    Occ& o = g_occ[row];
    const U64 child = Join(f.childLo, f.childHi), excl = d - child;
    const U64 incl = Join(o.inclLo, o.inclHi) + d, ex = Join(o.exclLo, o.exclHi) + excl;
    o.inclLo = static_cast<U>(incl); o.inclHi = static_cast<U>(incl >> 32);
    o.exclLo = static_cast<U>(ex); o.exclHi = static_cast<U>(ex >> 32);
    ++o.sampled; o.children += f.direct; o.desc += f.desc;
    Flush();
    return d;
}

// ---- calibration -------------------------------------------------------------------------------------------------
constexpr U kCal = 2048;
U g_samples[kCal];
void Median(U count, U& medianX16, U& spreadX16) {
    std::sort(g_samples, g_samples + count);
    const auto at = [&](U num, U den) { return g_samples[std::min(count - 1, count * num / den)]; };
    medianX16 = at(1, 2) * 16;
    spreadX16 = static_cast<U>(0.7413 * 16.0 * (at(3, 4) - at(1, 4)));
}
bool CpuSupported() {
    int r[4];
    __cpuid(r, 0x80000000);
    if (static_cast<U>(r[0]) < 0x80000007u) return false;
    __cpuid(r, 0x80000001);
    if (!(r[3] & (1 << 27))) return false;   // RDTSCP
    __cpuid(r, 0x80000007);
    return (r[3] & (1 << 8)) != 0;           // invariant TSC
}
void Calibrate() {
    LARGE_INTEGER f, q0, q1;
    QueryPerformanceFrequency(&f); g_qpcFreq = f.QuadPart;
    QueryPerformanceCounter(&q0);
    const U64 t0 = Tsc();
    do QueryPerformanceCounter(&q1); while (q1.QuadPart - q0.QuadPart < f.QuadPart / 50);
    const U64 t1 = Tsc();
    g_calTscKhz = static_cast<U>((t1 - t0) * static_cast<U64>(f.QuadPart) / static_cast<U64>(q1.QuadPart - q0.QuadPart) / 1000);
    const Gate inner = reinterpret_cast<Gate>(&GateCalibInner), outer = reinterpret_cast<Gate>(&GateCalibOuter);
    const Gate dispatch = reinterpret_cast<Gate>(&GateCalibDispatch);
    g_depth = 0; g_mode = 1;
    for (U i = 0; i < 64; ++i) inner();                      // warm
    for (U i = 0; i < kCal; ++i) { inner(); g_samples[i] = g_lastD; }
    Median(kCal, g_floorX16, g_floorSpreadX16);
    const U floor = g_floorX16 / 16;
    for (U i = 0; i < kCal; ++i) { outer(); g_samples[i] = g_lastExcl > floor ? g_lastExcl - floor : 0; }
    Median(kCal, g_nestX16, g_nestSpreadX16);
    g_mode = 0;
    for (U i = 0; i < kCal; ++i) g_samples[i] = static_cast<U>(TimedRoot(StepOther, Fn(&EmptyThiscall), 0));
    Median(kCal, g_rootX16, g_rootSpreadX16);
    // Unsampled pass costs: loop of gate calls minus the same loop of direct calls (minimum of 9 rounds).
    U64 best = ~0ull, bestDispatch = ~0ull, bestDecide = ~0ull;
    for (U round = 0; round < 9; ++round) {
        U64 a = Tsc();
        for (U i = 0; i < kCal; ++i) EmptyStub();
        U64 b = Tsc();
        for (U i = 0; i < kCal; ++i) inner();
        U64 c = Tsc();
        for (U i = 0; i < kCal; ++i) dispatch();
        U64 e = Tsc();
        const U64 direct = b - a;
        best = std::min(best, (c - b) > direct ? (c - b) - direct : 0);
        bestDispatch = std::min(bestDispatch, (e - c) > direct ? (e - c) - direct : 0);
        // Stratum decision on a synthetic soldier whose unit changes every 16 occurrences.
        U soldier[0x200 / 4] = {};
        const U savedStage = g_stage;
        g_stage = 0xFFFFFFF0u - round;
        a = Tsc();
        for (U i = 0; i < kCal; ++i) { soldier[0x1F0 / 4] = 0x1000u + (i >> 4) * 8; Decide(Fn(soldier), 0); }
        b = Tsc();
        bestDecide = std::min(bestDecide, b - a);
        g_stage = savedStage;
    }
    g_passX16 = static_cast<U>(best * 16 / kCal);
    g_dispatchX16 = static_cast<U>(bestDispatch * 16 / kCal);
    g_occurrenceX16 = static_cast<U>(bestDecide * 16 / kCal);
    g_calSamples = kCal;
    // Calibration rows/units are not part of the attribution.
    std::memset(g_units, 0, sizeof(g_units)); g_unitCount = 0; g_lastUnit = 0; g_lastSlot = ~0u;
    g_nullMembers = g_otherMembers = 0;
    std::memset(g_occ, 0, sizeof(g_occ)); std::memset(g_calls, 0, sizeof(g_calls));
    for (Totals& t : g_rows) t = Totals{};
    g_depth = 0; g_maxDepth = 0; g_overflow = 0; g_abandoned = 0;
}
} // namespace

bool Bind(U imageBase, U* bindings) {
    g_delta = imageBase - 0x400000; g_bound = imageBase != 0;
    g_exit = Fn(&S0Exit);
    for (U k = 0; k < StaticGateCount; ++k)
        if (kStaticGates[k].binding != NTW2_BIND_COUNT) bindings[kStaticGates[k].binding] = Fn(kStaticFns[k]);
    bindings[NTW2_BIND_S0_SELECTOR] = Fn(&GateSelector);
    bindings[NTW2_BIND_S0_NODE_BEGIN] = Fn(&GateNodeBegin);
    bindings[NTW2_BIND_S0_NODE_STEP] = Fn(&GateNodeStep);
    bindings[NTW2_BIND_S0_FINALIZE] = Fn(&GateFinalize);
    bindings[NTW2_BIND_S0_POSTURE_NEXT] = Fn(&GatePostureNext);
    bindings[NTW2_BIND_S0_TIMER_PROVIDER0] = Fn(&GateProvider0);
    bindings[NTW2_BIND_S0_TIMER_PROVIDER1] = Fn(&GateProvider1);
    return g_bound && Route(nullptr);
}
bool Start(const U* cloneEntries, U sampleShift, const U* bindings, bool units) {
    g_configured = 1; g_started = 0; g_shift = sampleShift > 16 ? 16 : sampleShift;
    g_unitMode = false; g_umask = 0; g_usDriver = g_uPosture = g_unitFatigue = 0; g_nativeFatigue = V(0x670F40);
    if (!CpuSupported()) { g_state = 2; return false; }
    if (!g_bound || !cloneEntries) { g_state = 3; return false; }
    for (U id = NTW2_CLONE_BRAIN_S0; id <= NTW2_CLONE_BRAIN_S0_RELATED_STEP; ++id)
        if (!cloneEntries[id]) { g_state = 3; return false; }
    std::memcpy(g_entries, cloneEntries, sizeof(g_entries));
    if (units) {  // routes to the unit applies; an absent target keeps its route native
        g_unitMode = true;
        g_unitFatigue = bindings && bindings[NTW2_BIND_U_FATIGUE] ? bindings[NTW2_BIND_U_FATIGUE] : g_nativeFatigue;
        g_uPosture = bindings ? bindings[NTW2_BIND_U_POSTURE] : 0;
        g_usDriver = cloneEntries[NTW2_CLONE_BRAIN_US_DRIVER];
    }
    if (!Route(g_entries)) { g_state = 3; return false; }
    Calibrate();
    g_state = 1; g_started = 1;
    return true;
}
void Stop() { g_started = 0; g_mode = 0; g_depth = 0; }
void Reset() {
    for (Totals& t : g_rows) t = Totals{};
    std::memset(g_calls, 0, sizeof(g_calls)); std::memset(g_occ, 0, sizeof(g_occ));
    std::memset(g_units, 0, sizeof(g_units));
    g_unitCount = 0; g_lastUnit = 0; g_lastSlot = ~0u; g_nullMembers = g_otherMembers = 0;
    g_stage = g_stages = g_sampledOccurrences = g_unitOverflow = g_nestedRoot = g_abandoned = g_calSamples = 0;
    g_occurrences = g_site6 = g_stageStart = g_tscFirst = g_tscLast = 0;
    g_qpcFirst = g_qpcLast = 0;
    g_calTscKhz = g_floorX16 = g_floorSpreadX16 = g_nestX16 = g_nestSpreadX16 = g_rootX16 = g_rootSpreadX16 = 0;
    g_passX16 = g_dispatchX16 = g_occurrenceX16 = 0;
    g_depth = g_maxDepth = g_overflow = g_mode = 0; g_umask = 0;
    g_configured = g_state = g_started = 0;
}
void BeginStage(U manager) {
    ++g_stage;
    g_lastUnit = 0; g_lastSlot = ~0u; g_unitCount = 0; g_nullMembers = g_otherMembers = 0;
    g_stageStart = Tsc();
    if (!g_tscFirst) {
        LARGE_INTEGER q; QueryPerformanceCounter(&q);
        g_tscFirst = g_stageStart; g_qpcFirst = q.QuadPart;
    }
    if (g_unitMode) ntw2_unit_policy::BeginStage(manager); // the unit seam is site-6 time
}
void EndStage() {
    if (g_unitMode) ntw2_unit_policy::EndStage();
    const U64 end = Tsc();
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    g_site6 += end - g_stageStart; g_tscLast = end; g_qpcLast = q.QuadPart; ++g_stages;
    for (U r = 0; r < kSlots; ++r) {
        g_rows[r].calls += g_calls[r];
        if (g_calls[r] > g_rows[r].maxStage) g_rows[r].maxStage = g_calls[r];
        g_calls[r] = 0;
    }
}
// One occurrence's step exactly once (the original or its BRAIN_S0 clone), timed when the stratum selects it.
void RunStep(U entity, U brainClass, U original) {
    ++g_occurrences;
    const bool core = brainClass <= 1, wrapper = brainClass == 2 || brainClass == 3;
    const U row = core ? StepCore : wrapper ? StepWrapper : StepOther;
    U entry = original;
    if (g_started) {
        if (core) entry = g_entries[NTW2_CLONE_BRAIN_S0];
        else if (brainClass == 2) entry = g_entries[NTW2_CLONE_BRAIN_S0_602EB0];
        else if (brainClass == 3) entry = g_entries[NTW2_CLONE_BRAIN_S0_5FCEB0];
    }
    ++g_calls[row];
    if (!g_started || !Decide(entity, brainClass) || g_depth) {
        if (g_started && g_depth) ++g_nestedRoot;
        reinterpret_cast<void (__thiscall*)(void*)>(entry)(reinterpret_cast<void*>(entity));
        return;
    }
    ++g_sampledOccurrences;
    TimedRoot(row, entry, entity);
}
void RunOccurrence(U entity, U brainClass, U original, const U* cloneEntries) {
    (void)cloneEntries; // the family was captured (and verified complete) at Start
    if (!g_unitMode) { RunStep(entity, brainClass, original); return; }
    // Unit policy: the occurrence's live mask routes the selector/driver/posture gates of the S0 clone (g_umask); the
    // observe/end hooks of the providers run after the step.
    const bool member = brainClass == 0 && original == V(0x66CE00);
    g_umask = member ? ntw2_unit_policy::BeginOccurrence(entity) & 7 : 0;
    bool completed = false;
    __try {
        RunStep(entity, brainClass, original);
        completed = true;
    } __finally {
        g_umask = 0;
        if (member) { if (completed) ntw2_unit_policy::EndOccurrence(); else ntw2_unit_policy::AbandonOccurrence(); }
    }
}
bool OverrideGateTarget(U binding, U target) {
    for (U k = 0; k < StaticGateCount; ++k)
        if (kStaticGates[k].binding == binding && binding != NTW2_BIND_COUNT) { g_static[k] = target; RefreshRoutes(); return true; }
    return false;
}
uint64_t RunTimedRoot(U row, U entry, U receiver) {
    if (row > StepOther || g_depth) return 0;
    ++g_sampledOccurrences; ++g_occurrences; ++g_calls[row];
    return TimedRoot(row, entry, receiver);
}
void Snapshot(U* w) {
    std::memset(w, 0, kWords * sizeof(U));
    w[Version] = kVersion; w[Configured] = g_configured; w[State] = g_state; w[SampleShift] = g_shift;
    w[Stages] = g_stages;
    w[OccurrencesLo] = static_cast<U>(g_occurrences); w[OccurrencesHi] = static_cast<U>(g_occurrences >> 32);
    w[SampledOccurrences] = g_sampledOccurrences;
    w[Site6Lo] = static_cast<U>(g_site6); w[Site6Hi] = static_cast<U>(g_site6 >> 32);
    const U64 tsc = g_tscLast > g_tscFirst ? g_tscLast - g_tscFirst : 0;
    const U64 qpc = g_qpcLast > g_qpcFirst ? static_cast<U64>(g_qpcLast - g_qpcFirst) : 0;
    w[TscSpanLo] = static_cast<U>(tsc); w[TscSpanHi] = static_cast<U>(tsc >> 32);
    w[QpcSpanLo] = static_cast<U>(qpc); w[QpcSpanHi] = static_cast<U>(qpc >> 32);
    w[QpcFreqLo] = static_cast<U>(g_qpcFreq); w[QpcFreqHi] = static_cast<U>(static_cast<U64>(g_qpcFreq) >> 32);
    w[CalTscKhz] = g_calTscKhz;
    w[GateFloorX16] = g_floorX16; w[GateFloorSpreadX16] = g_floorSpreadX16;
    w[GateNestX16] = g_nestX16; w[GateNestSpreadX16] = g_nestSpreadX16;
    w[RootFloorX16] = g_rootX16; w[RootFloorSpreadX16] = g_rootSpreadX16;
    w[PassCostX16] = g_passX16; w[DispatchCostX16] = g_dispatchX16; w[OccurrenceCostX16] = g_occurrenceX16;
    w[DepthOverflow] = g_overflow; w[Abandoned] = g_abandoned; w[MaxDepth] = g_maxDepth;
    w[UnitOverflow] = g_unitOverflow; w[NestedRoot] = g_nestedRoot; w[CalibrationSamples] = g_calSamples;
    for (U r = 0; r < RowCount; ++r) {
        const Totals& t = g_rows[r];
        U* row = w + kHeaderWords + r * kRowWords;
        const U64 calls = t.calls + g_calls[r];
        row[CallsLo] = static_cast<U>(calls); row[CallsHi] = static_cast<U>(calls >> 32);
        row[Sampled] = static_cast<U>(t.sampled); row[HitOccurrences] = static_cast<U>(t.hits);
        row[Children] = static_cast<U>(t.children); row[Descendants] = static_cast<U>(t.desc);
        row[InclLo] = static_cast<U>(t.incl); row[InclHi] = static_cast<U>(t.incl >> 32);
        const U64 excl = static_cast<U64>(t.excl);
        row[ExclLo] = static_cast<U>(excl); row[ExclHi] = static_cast<U>(excl >> 32);
        U64 bits; std::memcpy(&bits, &t.sqIncl, 8);
        row[SqInclLo] = static_cast<U>(bits); row[SqInclHi] = static_cast<U>(bits >> 32);
        std::memcpy(&bits, &t.sqExcl, 8);
        row[SqExclLo] = static_cast<U>(bits); row[SqExclHi] = static_cast<U>(bits >> 32);
        row[MaxStageCalls] = t.maxStage > g_calls[r] ? t.maxStage : g_calls[r];
    }
}
} // namespace ntw2_brain_s0
