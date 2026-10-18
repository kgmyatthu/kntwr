// S4 per-unit fatigue (native_unit_fatigue.h). Owner thread only. The only native writes are the two dwords A+370/+374 of
// the unit's members (apply gate and out-of-worklist publication); U+C70/+C74 are never written.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include "native_unit_fatigue.h"
#include "clones/ntw2_clones.h"

namespace ntw2_unit_fatigue {
// Byte table 0x6711D8 (A+1B8 0..0x4E -> switch class), verified against the mapped image at Start.
const uint8_t kActivityClass[kActivityLimit + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 3, 4, 4, 4, 4, 10, 10, 5, 5, 5, 1, 1, 6, 6, 7, 7, 8, 9, 9, 9, 9, 9, 0, 4, 3, 6,
    7, 1, 0, 10, 9, 0, 0, 0, 0, 0, 0, 0, 0, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 10, 2, 2, 10, 10, 2, 2, 10, 10, 1,
    1, 1};

// ---- the native arithmetic ---------------------------------------------------------------------------------------------
U ActivityClass(const Inputs& in) {
    if (in.node20 == 1) return 5;                       // 670F67: AL == 1 -> 671069 (entry 0x6D0)
    if (in.activity > kActivityLimit) return 10;        // 670F75: ja 67107C, rate 0
    return kActivityClass[in.activity];
}
static int32_t Percent(int32_t multiplier, int32_t value) {
    // 671110..671124: imul ecx,edi (low 32 bits); imul ecx by 0x51EB851F (edx = high dword); sar edx,5; + sign bit
    const int32_t product = static_cast<int32_t>(static_cast<uint32_t>(multiplier) * static_cast<uint32_t>(value));
    const int64_t wide = static_cast<int64_t>(product) * 0x51EB851FLL;
    const int32_t high = static_cast<int32_t>(wide >> 32);
    const int32_t q = high >> 5;
    return q + static_cast<int32_t>(static_cast<uint32_t>(q) >> 31);
}
int32_t ClassRate(const Inputs& in) {
    int32_t edi = 0;
    const U cls = ActivityClass(in);
    if (cls == 0) {
        edi = in.entry[E10];
        if (in.envField == 0) edi = static_cast<int32_t>(static_cast<uint32_t>(edi) + static_cast<uint32_t>(in.entry[EEnv0])); // 5DBB30
        else if (in.envField == 1) edi = static_cast<int32_t>(static_cast<uint32_t>(edi) + static_cast<uint32_t>(in.entry[EEnv1])); // 5DBD60
    } else if (cls != 10) {
        edi = in.entry[kClassEntry[cls]];
    }
    if (in.speedGate) {                                  // 671083..671126
        if (in.speed > in.thrFast) edi = Percent(in.entry[EMulFast], edi);
        else if (in.speed > in.thrMed) edi = Percent(in.entry[EMulMed], edi);
        else if (in.speed > in.thrSlow) edi = Percent(in.entry[EMulSlow], edi);
    }
    return edi;
}
bool BandInvariant(const Inputs& in) {
    Inputs bare = in;
    bare.speedGate = false;
    const int32_t base = ClassRate(bare);
    return Percent(in.entry[EMulFast], base) == base && Percent(in.entry[EMulMed], base) == base &&
           Percent(in.entry[EMulSlow], base) == base;
}
int32_t Rate(const Inputs& in) {
    int32_t edi = ClassRate(in);
    int32_t ebx = in.ctrlB, ebp = in.ctrlC, edx = 0;     // 671126..671193
    if (in.hasUnit) {
        edx = in.rowAdd;
        if (in.unitFlag18E) edi = static_cast<int32_t>(static_cast<uint32_t>(edi) - 1u);
        if (in.unitFlag18F) ebx = 0;
        if (in.unitFlag190) ebp = 0;
    }
    return static_cast<int32_t>(static_cast<uint32_t>(ebx) + static_cast<uint32_t>(ebp) + static_cast<uint32_t>(edx) +
                                static_cast<uint32_t>(edi));
}
State Step(const Inputs& in, State s) {
    s.acc = static_cast<int32_t>(static_cast<uint32_t>(s.acc) + static_cast<uint32_t>(Rate(in))); // 67119C add [A+370]
    const int32_t acc = s.acc;                                                                      // 671230: hysteresis
    switch (s.level) {
    case 0: if (acc > in.entry[ET1]) s.level = 1; break;
    case 1: if (acc < in.entry[ET1]) s.level = 0; else if (acc > in.entry[ET2]) s.level = 2; break;
    case 2: if (acc < in.entry[ET2]) s.level = 1; else if (acc > in.entry[ET3]) s.level = 3; break;
    case 3: if (acc < in.entry[ET3]) s.level = 2; else if (acc > in.entry[ET4]) s.level = 4; break;
    case 4: if (acc < in.entry[ET4]) s.level = 3; else if (acc > in.entry[ET5]) s.level = 5; break;
    case 5: if (acc < in.entry[ET5]) s.level = 4; break;
    default: break;                                                                                 // 67123B: ja 6713B0
    }
    if (acc < in.entry[ELow]) s.acc = in.entry[ELow];                                               // 6713B0..6713DE: clamp
    else if (acc > in.entry[EHigh]) s.acc = in.entry[EHigh];
    return s;
}
bool ThresholdsOrdered(const Inputs& in) {
    for (U e = ELow; e < EHigh; ++e) if (in.entry[e] > in.entry[e + 1]) return false;
    return true;
}

namespace {
static_assert(sizeof(void*) == 4, "the fatigue gate is a Win32 naked thunk");
constexpr const char* kLabels[] = { NTW2_UNIT_FATIGUE_LABELS };
static_assert(sizeof(kLabels) / sizeof(kLabels[0]) == kWords, "one label per fatigue status word");
using ntw2_unit_policy::g_occ;

constexpr U kHistBuckets = 8, kLevelBuckets = 11, kClassRows = 12;
struct UnitState { U valid, generation, ever; int32_t acc; U level; };

U g_delta;
U g_mode;
bool g_started;
UnitState g_state[ntw2_unit_policy::kMaxUnits];
U g_words[kWords];
U g_occPtr;                        // &g_occ for the naked gate
U g_fatigueNative = 0x670F40;
LONGLONG g_qpc0;
unsigned long long g_tsc0;
float g_thrFast, g_thrMed, g_thrSlow;

inline U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline U Byte(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
inline float F(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline void W32(U a, U v) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a)) = v; }
inline U V(U va) { return va + g_delta; }
void Fault(U code) { ++g_words[Faults]; g_words[LastFault] = code; }

// Unit chain of the native 0x670F40 read set, resolved from the unit's own root [U+14] (every member's [A+28] is the same
// root; verified once per unit generation). Values the native function reads through a per-man pointer are the shared
// global records: A+514 == E202F0() == [manager + 0x6C0] for every soldier (stored at construction 61D16B).
struct Chain { U root, model, G, P, Mg, S, X, row; };
Reason ReadChain(U unit, Chain& c, Inputs& in) {
    c.root = D(unit + 0x14);
    if (!c.root) return RefuseColdRecords;
    c.model = D(c.root + 8);
    if (!c.model) return RefuseColdRecords;
    c.G = D(c.model + 0xB0);
    if (!c.G) return RefuseColdRecords;
    c.P = D(c.G + 0x198);                                  // 670F4E..670F5A: ebp = [[[[A+28]+8]+0xB0]+0x198]
    if (!c.P) return RefuseColdRecords;
    in.ctrlB = static_cast<int32_t>(D(c.P + 0x2C)); in.ctrlC = static_cast<int32_t>(D(c.P + 0x30));
    const U list = D(c.P + 0x10);                          // 5B9510: [[P+0x10] + 8*[P+0x24]]
    if (!list) return RefuseColdRecords;
    const U record = D(list + 8 * D(c.P + 0x24));
    if (!record) return RefuseColdRecords;
    in.envField = D(record + 0x10);
    const U holder = D(c.root + 0x2804C);                  // 670F4E: eax=[A+28]; eax=[eax+2804C]; ecx=[eax+10]; E202F0(ecx)
    if (!holder) return RefuseColdRecords;
    c.Mg = D(holder + 0x10);
    if (!c.Mg) return RefuseColdRecords;
    c.S = D(c.Mg + 0x6C0);                                 // E202F0 fast path: [ecx+6C0]; zero = cold loader (never replayed)
    if (!c.S) return RefuseColdRecords;
    for (U e = 0; e < EntryCount; ++e) in.entry[e] = static_cast<int32_t>(D(c.S + kEntryOffset[e] + 0x5C));
    // 671136..671161: eax=[A+28]; eax=[eax+8]; eax=[eax]; eax=[eax+2804C]; ecx=[eax+10]; E31490(ecx) -> [ecx+2C0] table.
    const U root2 = D(c.model);
    const U holder2 = root2 ? D(root2 + 0x2804C) : 0;
    const U Mg2 = holder2 ? D(holder2 + 0x10) : 0;
    c.X = Mg2 ? D(Mg2 + 0x2C0) : 0;
    if (!c.X) return RefuseColdRecords;
    const U index = Byte(unit + 0xD48), count = D(c.X + 0xC);
    c.row = index < count ? D(D(c.X + 0x10) + 4 * index) : 0;
    if (!c.row) return RefuseNoRow;                        // native would dereference null
    in.rowAdd = static_cast<int32_t>(D(c.row + 0x20));
    in.hasUnit = true;
    in.unitFlag18E = Byte(unit + 0x18E) == 1; in.unitFlag18F = Byte(unit + 0x18F) == 1; in.unitFlag190 = Byte(unit + 0x190) == 1;
    in.thrFast = g_thrFast; in.thrMed = g_thrMed; in.thrSlow = g_thrSlow;
    in.node20 = 0; in.activity = 0; in.speedGate = false; in.speed = 0.0f;
    return Admitted;
}

// ---- unit activity -----------------------------------------------------------------------------------------------------
// The unit's activity is decided from UNIT state only (header "Unit activity"): the FSM object [U+D68] == 1320F28 with
// current state [U+D6C] in A..E (1450908..1450918, spacing 4) and the engagement flags. A = REST (model order 4), B..E = MARCH
// (model order 5), engaged = refused. The model's activity codes are evaluated through the pack and must agree.
const uint8_t kRestCodes[] = {1, 9}, kMarchCodes[] = {2, 10, 23, 24};
Reason ClassifyUnit(U unit, UnitActivity& model) {
    if (D(unit + 0xD68) != V(0x1320F28)) return RefuseFsmUnknown;
    const U state = D(unit + 0xD6C), a = V(kFsmStateA), e = V(kFsmStateE);
    if (state == a) model = ActivityRest;
    else if (state > a && state <= e && ((state - a) & 3) == 0) model = ActivityMarch;
    else return RefuseFsmUnknown;
    if (Byte(unit + 0xD9E) || Byte(unit + 0xDA4)) return RefuseEngaged;
    return Admitted;
}
// Unit chain + activity model + closure rule (class-variance and speed-band checks); shared by decide() and ResolveUnit().
Reason ResolveUnitImpl(U unit, Chain& c, Inputs& in, UnitActivity& model) {
    Reason r = ReadChain(unit, c, in);
    if (r != Admitted) return r;
    if ((r = ClassifyUnit(unit, model)) != Admitted) return r;
    U n = 0;
    const uint8_t* codes = ActivityCodes(model, n);
    int32_t rate = 0;
    for (U k = 0; k < n; ++k) {
        in.activity = codes[k]; in.node20 = 0; in.speedGate = false; in.speed = 0.0f;
        const int32_t r2 = ClassRate(in);
        if (k == 0) rate = r2;
        else if (r2 != rate) return RefuseClassVariance;
    }
    in.activity = codes[0];
    if (!BandInvariant(in)) return RefuseSpeedBand;
    return Admitted;
}
} // namespace

const uint8_t* ActivityCodes(UnitActivity activity, U& count) {
    if (activity == ActivityRest) { count = sizeof(kRestCodes); return kRestCodes; }
    count = sizeof(kMarchCodes); return kMarchCodes;
}
U ResolveUnit(U unit, Inputs& out, U& model) {
    Chain c;
    UnitActivity m = ActivityRest;
    memset(&out, 0, sizeof(out));
    const Reason r = ResolveUnitImpl(unit, c, out, m);
    model = m;
    return r;
}

bool ResolveInputs(U unit, U activity, bool speedGate, float speed, Inputs& out, U& reason) {
    Chain c;
    memset(&out, 0, sizeof(out));
    reason = ReadChain(unit, c, out);
    if (reason) return false;
    out.activity = activity; out.speedGate = speedGate; out.speed = speed;
    return true;
}

namespace {
// Per-stage accumulators of the seam costs (TSC cycles, converted with the TSC/QPC ratio measured since Start, one QPC read
// per stage) and the unit counts of the stage; published when the next stage's first decide() rolls the window.
struct StageAcc { U stage, admitted, refused, published; unsigned long long decide, end; };
StageAcc g_acc;
U UsOf(unsigned long long cycles) {
    LARGE_INTEGER q, f; QueryPerformanceCounter(&q); QueryPerformanceFrequency(&f);
    const unsigned long long tsc = __rdtsc() - g_tsc0, qpc = static_cast<unsigned long long>(q.QuadPart - g_qpc0);
    if (!tsc || !qpc) return 0;
    const double seconds = static_cast<double>(qpc) / static_cast<double>(f.QuadPart);
    return static_cast<U>(static_cast<double>(cycles) * seconds / static_cast<double>(tsc) * 1e6);
}
void Publish() {
    if (!g_acc.stage || g_acc.published) return;
    const U d = UsOf(g_acc.decide), e = UsOf(g_acc.end);
    g_words[DecideUsLast] = d; g_words[DecideUsTotal] += d; if (d > g_words[DecideUsMax]) g_words[DecideUsMax] = d;
    g_words[EndUsLast] = e; g_words[EndUsTotal] += e;
    g_words[UnitsAdmittedLast] = g_acc.admitted; g_words[UnitsRefusedLast] = g_acc.refused;
    g_acc.published = 1;
}
void Roll(U stage) {
    if (stage == g_acc.stage) return;
    Publish();
    g_acc = StageAcc{}; g_acc.stage = stage;
}

U Decide(U ui, const ntw2_unit_policy::UnitView& v, U* slot) {
    Roll(v.stage);
    const unsigned long long t0 = __rdtsc();
    UnitState& st = g_state[ui];
    U reason = Admitted;
    UnitActivity model = ActivityRest;
    __try {
        Chain c;
        Inputs in;
        memset(&in, 0, sizeof(in));
        const U unit = v.handle;
        if (D(unit + 0xAA0) == 0) {                       // native inactive reset (57F1C3..57F1F1) is authoritative
            if (st.valid) ++g_words[Resets];
            reason = RefuseInactive;
        } else if ((reason = ResolveUnitImpl(unit, c, in, model)) == Admitted) {
            if (!ThresholdsOrdered(in)) reason = RefuseThresholdOrder;
            else if (!st.valid || st.generation != v.generation) {
                // Init at this seam from the native published means of the earlier army stage; every member must share the
                // unit's root and the global stat record (the per-man pointers native reads).
                for (U k = 0; k < v.memberCount && reason == Admitted; ++k) {
                    const U m = v.members[k];
                    if (D(m + 0x28) != c.root) reason = RefuseRootMismatch;
                    else if (D(m + 0x514) != c.S) reason = RefuseStatMismatch;
                    else if (D(m + 0x220) != 0) reason = RefuseStance;     // the unit stance of the model is 0
                }
                if (reason == Admitted && D(unit + 0xC70) > kLevels - 1) reason = RefuseLevelContract;
                if (reason == Admitted) {
                    if (st.ever) ++g_words[GenerationInits];
                    st.acc = static_cast<int32_t>(D(unit + 0xC74)); st.level = D(unit + 0xC70);
                    st.valid = 1; st.ever = 1; st.generation = v.generation; ++g_words[Inits];
                }
            }
            if (reason == Admitted) {
                State s = {st.acc, st.level};
                s = Step(in, s);                           // one advance per stage: decide runs once per unit and stage
                st.acc = s.acc; st.level = s.level;
                slot[SlotAcc] = static_cast<U>(s.acc); slot[SlotLevel] = s.level; slot[SlotClass] = ActivityClass(in);
                slot[SlotRate] = static_cast<U>(Rate(in)); slot[SlotGeneration] = v.generation; slot[SlotStage] = v.stage;
                ++g_words[Advances]; ++g_words[model == ActivityRest ? RestUnitStages : MarchUnitStages];
                g_words[LastUnitAcc] = static_cast<U>(s.acc); g_words[LastUnitLevel] = s.level;
                g_words[LastUnitClass] = ActivityClass(in); g_words[LastUnitRate] = static_cast<U>(Rate(in));
                g_words[LastUnitIndex] = ui;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        reason = RefuseFault; Fault(1);
    }
    if (reason != Admitted) { st.valid = 0; ++g_words[RefuseBase + reason - 1]; ++g_acc.refused; }
    else { ++g_words[UnitStages]; ++g_acc.admitted; }
    g_acc.decide += __rdtsc() - t0;
    return reason;
}

// Out-of-worklist publication (Live only): members of this admitted unit whose site-6 occurrence did not run this stage
// (+30 != 1: not in the worklist) get the same pair, so the next native aggregation sees the unit value rather than a
// mixture. Only when the unit's list is exactly the one imported at the seam (a member may have died during the stage).
void End(U ui, const ntw2_unit_policy::UnitView& v, U* slot) {
    if (!(v.admitted & ntw2_unit_policy::kMaskFatigue)) return;
    const unsigned long long t0 = __rdtsc();
    if (g_mode == ntw2_unit_policy::Live) {
        U pending = 0;
        for (U k = 0; k < v.memberCount; ++k) pending += v.ran[k] != v.stage;
        g_words[Applies] += v.memberCount - pending;
        if (pending) {
            if (!ntw2_unit_policy::UnitListStable(ui)) ++g_words[PublishSkipped];
            else
                for (U k = 0; k < v.memberCount; ++k)
                    if (v.ran[k] != v.stage) {
                        W32(v.members[k] + 0x370, slot[SlotAcc]); W32(v.members[k] + 0x374, slot[SlotLevel]);
                        ++g_words[OutOfWorklistWrites];
                    }
        }
    }
    if (v.stage == g_acc.stage) g_acc.end += __rdtsc() - t0;
}
void Retire(U ui) { g_state[ui] = UnitState{}; ++g_words[Retires]; }

U Bucket(U delta) {
    if (delta == 0) return 0;
    if (delta == 1) return 1;
    if (delta < 4) return 2;
    if (delta < 8) return 3;
    if (delta < 16) return 4;
    if (delta < 64) return 5;
    if (delta < 256) return 6;
    return 7;
}
// Shadow: the occurrence ran native; compare the man's native result with the unit's pair.
void Observe(U entity, const ntw2_unit_policy::UnitView&, U* slot) {
    const int32_t nativeAcc = static_cast<int32_t>(D(entity + 0x370)), unitAcc = static_cast<int32_t>(slot[SlotAcc]);
    const U nativeLevel = D(entity + 0x374), unitLevel = slot[SlotLevel];
    ++g_words[ShadowMen];
    const bool accEqual = nativeAcc == unitAcc, levelEqual = nativeLevel == unitLevel;
    ++g_words[accEqual ? ShadowAccEqual : ShadowAccDiff];
    ++g_words[levelEqual ? ShadowLevelEqual : ShadowLevelDiff];
    if (accEqual && levelEqual) ++g_words[ShadowBothEqual];
    const int64_t diff = static_cast<int64_t>(unitAcc) - static_cast<int64_t>(nativeAcc);
    const uint64_t magnitude = static_cast<uint64_t>(diff < 0 ? -diff : diff);
    ++g_words[DAccBase + (magnitude > 0xFFFFFFFFull ? kHistBuckets - 1 : Bucket(static_cast<U>(magnitude)))];
    const int64_t dl = static_cast<int64_t>(unitLevel) - static_cast<int64_t>(nativeLevel);
    ++g_words[DLevelBase + (dl < -5 ? 0 : dl > 5 ? kLevelBuckets - 1 : static_cast<U>(dl + 5))];
    const U activity = D(entity + 0x1B8);                  // the man's NATIVE class: what the unit decision displaces
    const U cls = activity > kActivityLimit ? 10 : kActivityClass[activity];
    ++g_words[ClassBase + 2 * cls];
    if (!accEqual || !levelEqual) ++g_words[ClassBase + 2 * cls + 1];
}

const ntw2_unit_policy::Provider kLive = {ntw2_unit_policy::Fatigue, ntw2_unit_policy::Live, &Decide, &End, &Retire, nullptr};
const ntw2_unit_policy::Provider kShadow = {ntw2_unit_policy::Fatigue, ntw2_unit_policy::Shadow, &Decide, &End, &Retire, &Observe};

// A gate call for a man that is not the current occurrence while a live fatigue mask is open: contract fault.
void __cdecl ContractMiss() {
    ++g_words[ContractMisses]; ++g_words[Drains];
    ntw2_unit_policy::Drain(g_occ.unitIndex, ntw2_unit_policy::Fatigue, 1);
}
} // namespace

// NTW2_BIND_U_FATIGUE: replaces `call [eax+108]` at 66D43D (`mov ecx,edi` before it stays). ECX = A, no stack argument, plain
// RET, EAX/ECX/EDX volatile (the native selector clobbers them), EBX/ESI/EDI/EBP/ESP preserved, x87 untouched, EFLAGS unused
// by the caller. g_occ: entity @0, mask @8, slot[Fatigue] @16.
__declspec(naked) static void FatigueGate() {
    __asm {
        mov eax, dword ptr [g_occPtr]
        cmp ecx, dword ptr [eax]
        jne miss
        test dword ptr [eax + 8], 1
        jz native
        mov eax, dword ptr [eax + 16]
        mov edx, dword ptr [eax]
        mov dword ptr [ecx + 0x370], edx
        mov edx, dword ptr [eax + 4]
        mov dword ptr [ecx + 0x374], edx
        ret
    miss:
        test dword ptr [eax + 8], 1
        jz native
        push ecx
        call ContractMiss
        pop ecx
    native:
        mov eax, dword ptr [ecx]
        jmp dword ptr [eax + 0x108]
    }
}
U GateAddress() { return static_cast<U>(reinterpret_cast<uintptr_t>(&FatigueGate)); }

bool Bind(U imageBase, U* bindings) {
    if (!imageBase || !bindings) return false;
    g_occPtr = static_cast<U>(reinterpret_cast<uintptr_t>(&g_occ));
    bindings[NTW2_BIND_U_FATIGUE] = GateAddress();
    return true;
}
static bool PinActivityModel() {
    // Codes of the unit activity models (mov dword ptr [reg+1B8], imm32): 663730 order 4 -> 1, order 5 -> 2; the finalizer
    // 654518.. switch (A+1D8 byte table 6547AC -> jump table 654750 -> stance table, stance 0) order 4 -> 9, order 5 -> 10;
    // posture-moving stores 0x17 (654563) / 0x18 (654580).
    auto imm = [](U va, uint8_t modrm, U expect) {
        return Byte(va) == 0xC7 && Byte(va + 1) == modrm && D(va + 2) == 0x1B8 && D(va + 6) == expect;
    };
    if (!imm(D(V(0x6639FC) + 4 * 4), 0x81, 1) || !imm(D(V(0x6639FC) + 4 * 5), 0x81, 2)) return false;
    if (Byte(V(0x6547AC) + 4) != 1 || Byte(V(0x6547AC) + 5) != 2) return false;
    if (D(V(0x654750) + 4 * 1) != V(0x6545E2) || D(V(0x654750) + 4 * 2) != V(0x654635)) return false;
    if (!imm(D(V(0x654800)), 0x86, 9) || !imm(D(V(0x654810)), 0x86, 10)) return false;
    return imm(V(0x654563), 0x86, 0x17) && imm(V(0x654580), 0x86, 0x18);
}
bool Start(U imageBase, U mode) {
    Stop(); Reset();
    if (!imageBase || (mode != ntw2_unit_policy::Shadow && mode != ntw2_unit_policy::Live)) return false;
    g_delta = imageBase - 0x400000;
    // Pin the image tables this port embeds: activity byte table, the 11-way and 6-way jump tables, the rebased constants.
    const U table = V(0x6711D8);
    for (U a = 0; a <= kActivityLimit; ++a) if (Byte(table + a) != kActivityClass[a]) return false;
    static const U kSwitch[11] = {0x670F9A, 0x67103F, 0x67104D, 0x67105B, 0x671007, 0x671069, 0x671015, 0x671023, 0x670F8C,
                                  0x671031, 0x67107C};
    static const U kLevelSwitch[6] = {0x67124B, 0x671279, 0x6712C5, 0x671311, 0x671349, 0x67138B};
    for (U i = 0; i < 11; ++i) if (D(V(0x6711AC) + 4 * i) != V(kSwitch[i])) return false;
    for (U i = 0; i < 6; ++i) if (D(V(0x6713E8) + 4 * i) != V(kLevelSwitch[i])) return false;
    g_thrFast = F(V(0x1325CA8)); g_thrMed = F(V(0x131A7B0)); g_thrSlow = F(V(0x1325C88));
    if (!PinActivityModel()) return false;
    g_mode = mode;
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&g_qpc0)); g_tsc0 = __rdtsc();
    g_started = true;
    return true;
}
void Stop() { g_started = false; }
void Reset() {
    g_started = false;
    memset(g_state, 0, sizeof(g_state)); memset(g_words, 0, sizeof(g_words));
    g_acc = StageAcc{};
}
const ntw2_unit_policy::Provider* Provider() {
    if (!g_started) return nullptr;
    return g_mode == ntw2_unit_policy::Live ? &kLive : &kShadow;
}
void Snapshot(U* words) {
    memcpy(words, g_words, sizeof(g_words));
    words[Version] = kVersion; words[Mode] = g_mode;
    words[DecideUsLast] = g_words[DecideUsLast];
}
} // namespace ntw2_unit_fatigue
