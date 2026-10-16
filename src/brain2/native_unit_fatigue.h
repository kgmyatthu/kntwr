#pragma once
#include <stdint.h>
#include "native_unit_policy.h"
// S4 — one fatigue pair per unit (--brain-unit-fatigue / --brain-unit-fatigue-shadow;
// analysis/native-unit-compromise-plan.md section 4, analysis/checkpoints/UnitBrainSlices.md, UnitFatigue.md).
//
// What native does per man (virtual call 0x66D43D -> 0x670F40 -> tail 0x671230), every time the man's brain step runs:
//   rate  = stat entry of the man's activity class (A+1B8 through byte table 0x6711D8 -> 11-way switch 0x6711AC; the node
//           virtual +20 of A+22C == 1 selects entry 0x6D0 instead), class 0 plus the environment entry of the controller
//           record, then the speed band multiplier M (percent, signed multiply by 0x51EB851F >> 37) when A+118==1 and
//           (A+110&1 || A+117==0) and A+1A0 exceeds the first of three float thresholds;
//   the unit's contribution: rate - (U+18E==1), P+0x2C (zero when U+18F==1), P+0x30 (zero when U+190==1) and the unit row
//           value [row+0x20] of table index U+D48;
//   acc (A+370, int32) += rate sum; six-level hysteresis on A+374 (one step per call, thresholds 0x8B0/0x910/0x970/0x9D0/
//           0xA30 entries of the stat record, strict comparisons, from the CURRENT level); THEN clamp of acc to
//           [entry 0x850, entry 0xA90]. Stat entries are dwords at [S + offset + 0x5C] (0x586430 is `lea eax,[ecx+5Ch]`).
// With the unit slice this body is switched OFF for admitted units: the unit decision (acc, level) is computed once per
// stage from the unit's activity, the same arithmetic (Step below, byte-equal to the native pair for a homogeneous unit)
// and written into every member by the NTW2_BIND_U_FATIGUE gate. Approved deviation (plan section 7): a tired straggler
// and a rested stationary man no longer have separate effort histories.
//
// Unit state: (acc:int32, level:uint32) per unit generation, initialised at the stage seam from the native published means
// U+C74 (acc) / U+C70 (level) of the earlier army stage (57F070, 57F1B1/57F1BB), then advanced exactly once per stage.
// U+C70/C74 are NEVER rewritten here: the next native aggregation reproduces the unit pair from the members. A native
// inactive reset (U+AA0 == 0: 57F1C3..57F1F1 zero every member and U+C70) is authoritative: the unit is refused, its state
// dropped and re-initialised from the (zero) means when it is admitted again — never resurrected.
//
// Unit activity (UnitFatigue.md "Unit activity"): decided from UNIT state only — the unit FSM U+D6C (states A..E =
// 1450908..1450918, [proven by VA/disasm] native-army-update-per-unit.md 10.4.5) and the engagement flags U+D9E/U+DA4 — never
// from a man, a majority or averaged per-man rates:
//   REST  = FSM A, not engaged: model order 4 (stand). Native activity codes reachable by a man of order 4, stance 0: 663730
//           -> A+1B8 1 (class 0) and the finalizer 6545E2 table -> 9 (class 1). Both are evaluated through the pack's own
//           stat entries (E10 + env entry, E3D0).
//   MARCH = FSM B..E, not engaged: model order 5 (move). Codes: 663730 -> 2 (class 0), finalizer table -> 10, posture-moving
//           0x17/0x18 (class 1): E10 + env entry, E3D0.
//   ENGAGED (U+D9E or U+DA4): REFUSED. Melee/firing action classes are a per-man input (the pack gives them rates 0/2/3/4 and
//           no unit field selects among them); routing has no recovered unit field (D9E "is not established as morale/routing").
// Closure rule: a state is admitted only if every reachable code of its set yields the SAME class rate under the live pack
// (RefuseClassVariance otherwise) and the speed-band multipliers (walk/run: 105%/110% of the class rate when A+1A0 exceeds
// the float thresholds) are the identity on that rate (RefuseSpeedBand otherwise), so no guessed man input is used. The unit
// stance is assumed 0 (descriptor default); a member whose A+220 != 0 at generation init refuses the unit (RefuseStance).
// Documented deviation: a stance change during a generation (the init scan is the only read of a man) is not followed; shadow
// class tables quantify native classes vs the unit decision.
//
// Status half (ntw2_status::brain_unit_policy_words[32..127], NTW2_UNIT_FATIGUE_LABELS): mode, admitted/refused units by
// reason, advances/applies/out-of-worklist writes, inits/resets/drains, decide microseconds and the shadow divergence tables.
#define NTW2_UNIT_FATIGUE_LABELS \
 "version", "mode", "units_admitted_last", "unit_stages", "units_refused_last", \
"refuse_inactive", "refuse_engaged", "refuse_fsm_unknown", "refuse_cold_records", "refuse_root_mismatch", \
 "refuse_stat_mismatch", "refuse_level_contract", "refuse_threshold_order", "refuse_fault", "refuse_no_row", \
"refuse_class_variance", "refuse_stance", "refuse_speed_band", "refuse_reserved14", "refuse_reserved15", \
 "refuse_reserved16", \
 "advances", "applies", "out_of_worklist_writes", "inits", "resets", "drains", "retires", "faults", "last_fault", \
 "decide_us_last", "decide_us_max", "decide_us_total", "end_us_last", "end_us_total", "publish_skipped_units", \
"generation_inits", "contract_misses", "rest_unit_stages", "march_unit_stages", \
 "shadow_men", "shadow_acc_equal", "shadow_acc_diff", "shadow_level_equal", "shadow_level_diff", "shadow_both_equal", \
 "dacc_0", "dacc_1", "dacc_2_3", "dacc_4_7", "dacc_8_15", "dacc_16_63", "dacc_64_255", "dacc_256_up", \
 "dlevel_m5", "dlevel_m4", "dlevel_m3", "dlevel_m2", "dlevel_m1", "dlevel_0", "dlevel_p1", "dlevel_p2", "dlevel_p3", \
 "dlevel_p4", "dlevel_p5", \
 "class0_men", "class0_diff", "class1_men", "class1_diff", "class2_men", "class2_diff", "class3_men", "class3_diff", \
 "class4_men", "class4_diff", "class5_men", "class5_diff", "class6_men", "class6_diff", "class7_men", "class7_diff", \
 "class8_men", "class8_diff", "class9_men", "class9_diff", "class10_men", "class10_diff", "classx_men", "classx_diff", \
 "last_unit_acc", "last_unit_level", "last_unit_class", "last_unit_rate", "last_units_stage", "last_unit_index", \
 "reserved95"
#ifdef __cplusplus
namespace ntw2_unit_fatigue {
using U = uint32_t;
constexpr U kVersion = 1, kWords = 96;
static_assert(kWords == ntw2_unit_policy::kFatigueWords, "fatigue status half");

// ---- the native arithmetic, as a pure function of an explicit input record -------------------------------------------------
// Stat record entries, in this order: value = *(int32*)(S + kEntryOffset[e] + 0x5C).
enum Entry : U {
    E10, E1F0, E250, E2B0, E370, E3D0, E4F0, E670, E6D0,        // per-activity-class rates
    EEnv0, EEnv1,                                                 // class-0 environment entries (0xD0 / 0x130)
    EMulFast, EMulMed, EMulSlow,                                  // speed-band percent multipliers (0xBB0 / 0xB50 / 0xAF0)
    ELow, ET1, ET2, ET3, ET4, ET5, EHigh,                         // clamp low, five hysteresis thresholds, clamp high
    EntryCount
};
constexpr U kEntryOffset[EntryCount] = {0x10, 0x1F0, 0x250, 0x2B0, 0x370, 0x3D0, 0x4F0, 0x670, 0x6D0, 0xD0, 0x130,
                                        0xBB0, 0xB50, 0xAF0, 0x850, 0x8B0, 0x910, 0x970, 0x9D0, 0xA30, 0xA90};
constexpr U kActivityLimit = 0x4E, kClasses = 11, kLevels = 6;
// Byte table 0x6711D8 (activity 0..0x4E -> switch class) and the class -> rate entry of the switch 0x6711AC.
extern const uint8_t kActivityClass[kActivityLimit + 1];
constexpr int kClassEntry[kClasses] = {E10 /*+env*/, E3D0, E4F0, E670, E1F0, E6D0, E250, E2B0, E10, E370, -1 /*no rate*/};
struct Inputs {
    int32_t entry[EntryCount];
    U node20;              // result byte of the inline node virtual +20: == 1 selects class 5 and skips the activity switch
    U activity;            // A+1B8 (native) / the unit activity code; > 0x4E: no rate
    U envField;            // [R+0x10] of the controller's selected record R (class 0: 0 adds EEnv0, 1 adds EEnv1)
    bool speedGate;        // A+118 == 1 && (A+110 & 1 || A+117 == 0)
    float speed;           // A+1A0
    float thrFast, thrMed, thrSlow; // image floats 0x1325CA8, 0x131A7B0, 0x1325C88: band applies when speed > threshold
    int32_t ctrlB, ctrlC;  // [P+0x2C] (ebx), [P+0x30] (ebp) of P = [[[[A+28]+8]+0xB0]+0x198]
    bool hasUnit;          // A+1F0 != 0: the unit contribution below applies
    int32_t rowAdd;        // [row+0x20], row = table[U+D48] of manager table +0x2C0
    bool unitFlag18E, unitFlag18F, unitFlag190; // U+18E/+18F/+190 == 1
};
struct State { int32_t acc; U level; };
U ActivityClass(const Inputs& in);         // 0..10 (native switch index; 5 for node20 == 1; 10 for activity > 0x4E)
int32_t Rate(const Inputs& in);            // the rate sum added at 0x67119C (wraps like the native lea/add chain)
int32_t ClassRate(const Inputs& in);       // the activity rate (edi) before the unit contribution, with the speed band applied
bool BandInvariant(const Inputs& in);      // the three speed-band multipliers leave the band-free class rate unchanged
State Step(const Inputs& in, State state); // 0x670F40 body + 0x671230: add, hysteresis (from the current level), clamp
bool ThresholdsOrdered(const Inputs& in);  // contract: ELow <= ET1 <= ... <= ET5 <= EHigh

// ---- module ------------------------------------------------------------------------------------------------------------
// Refusal codes of decide() (also the status word offsets above: word = kRefuseBase + code - 1).
enum Reason : U {
    Admitted, RefuseInactive, RefuseEngaged, RefuseFsmUnknown, RefuseColdRecords, RefuseRootMismatch, RefuseStatMismatch,
    RefuseLevelContract, RefuseThresholdOrder, RefuseFault, RefuseNoRow, RefuseClassVariance, RefuseStance, RefuseSpeedBand,
    ReasonCount
};
// Unit activity models of an admitted unit (word RestUnitStages / MarchUnitStages).
enum UnitActivity : U { ActivityRest, ActivityMarch, ActivityCount };
constexpr uint32_t kFsmStateA = 0x1450908, kFsmStateE = 0x1450918;   // unit FSM states A..E (image VAs, step 4)
// Activity codes (A+1B8) the model evaluates per unit activity; every code must give the same class rate.
const uint8_t* ActivityCodes(UnitActivity activity, U& count);
enum Word : U {
    Version, Mode, UnitsAdmittedLast, UnitStages, UnitsRefusedLast, RefuseBase,   // RefuseBase = 5: code c -> word 5 + c - 1
    Advances = RefuseBase + 16, Applies, OutOfWorklistWrites, Inits, Resets, Drains, Retires, Faults, LastFault,
    DecideUsLast, DecideUsMax, DecideUsTotal, EndUsLast, EndUsTotal, PublishSkipped, GenerationInits, ContractMisses,
    RestUnitStages, MarchUnitStages,
    ShadowMen = 40, ShadowAccEqual, ShadowAccDiff, ShadowLevelEqual, ShadowLevelDiff, ShadowBothEqual,
    DAccBase = 46, DLevelBase = 54, ClassBase = 65, LastUnitAcc = 89, LastUnitLevel, LastUnitClass, LastUnitRate,
    LastUnitsStage, LastUnitIndex, Reserved95
};
static_assert(Advances == 21 && ShadowMen == 40 && DAccBase == 46 && DLevelBase == 54 && ClassBase == 65 &&
              LastUnitAcc == 89 && Reserved95 == 95, "fatigue status geometry");
// Slot words of the unit's fatigue decision (ntw2_unit_policy slot[Fatigue]).
enum Slot : U { SlotAcc, SlotLevel, SlotClass, SlotRate, SlotGeneration, SlotStage, SlotWords };

bool Bind(U imageBase, U* bindings);                 // writes NTW2_BIND_U_FATIGUE (the gate)
// Owner, before the first stage: pins the image tables this port embeds. mode: ntw2_unit_policy::Shadow or Live.
bool Start(U imageBase, U mode);
void Stop();
void Reset();
void Snapshot(U* words /*[kWords]*/);
const ntw2_unit_policy::Provider* Provider();       // null when mode Off / not started

// ---- oracle surface -------------------------------------------------------------------------------------------------------
// One unit's Inputs resolved from native memory exactly like decide() does, for `activity`/band chosen by the caller.
// False with `reason` when a record is cold/unreadable/inconsistent.
bool ResolveInputs(U unit, U activity, bool speedGate, float speed, Inputs& out, U& reason);
// decide()'s unit-side admission for one unit (no member scan, no state): the unit chain + unit activity model. On success
// `out` holds the unit's Inputs (activity = the first code of the model) and `model` its UnitActivity.
U ResolveUnit(U unit, Inputs& out, U& model);        // returns Reason
U GateAddress();                                     // the NTW2_BIND_U_FATIGUE gate entry
} // namespace ntw2_unit_fatigue
#endif
