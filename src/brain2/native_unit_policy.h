#pragma once
#include <stdint.h>
// Shared admission / unit-policy module of the per-unit brain slices (analysis/checkpoints/UnitBrainSlices.md, Contract 1).
// ONE module for selection, serial bits, per-unit rows, occurrence routing, seam hooks and the status header. Mechanic
// modules (fatigue S4 here, posture S2b and engage/fire in native_unit_posture_engage.*) never select units or keep
// their own membership: each registers a Provider that decides once per selected unit and stage and applies through a
// binding that tests `g_occ`.
//
// Selection reuses the puppet's rules (src/puppet/native_unit_select.*): the eleven infantry class tables, member
// admissibility, serial < 2^20, first-appearance unit order over the primary registry (manager+24C/+250), retried every
// 64 stages while nothing qualified. NOT parking: no wait node, no slot+08 swap, no site-13 work and no native write by
// this module.
//
// Per-occurrence routing (owner, inside ntw2_brain2::RunWorklist): serial bit -> member row -> unit -> mask. Live
// mechanics admitted for the unit make `g_occ.mask` nonzero and the occurrence runs clone BRAIN_U (the 66CE00 core with
// the fatigue virtual call and the driver call retargeted); every other occurrence runs the original vt+0C. Duplicate
// occurrences route identically (the decision is per stage, the apply is idempotent).
//
// Mode semantics. A Live provider's mechanic bit is set in `Occurrence::mask` exactly when its decide() returned 0 for
// the unit this stage. A Shadow provider NEVER sets a mask bit (its occurrences run the original/native path; the
// provider compares native results against its unit decision in `observe`, called from EndOccurrence for every selected
// member occurrence of a unit whose Shadow decide() returned 0 this stage). `UnitView::admitted` carries the bits of
// every provider whose decide() returned 0 (Live or Shadow); `Occurrence::mask` only the Live subset.
//
// With --brain-s0 the S0 runner owns the occurrence call and drives the same seams: its begin/end call
// BeginStage/EndStage, its run brackets each occurrence with BeginOccurrence/EndOccurrence, and its selector gate
// (fatigue), driver gate (engage) and posture gate route admitted occurrences to the unit applies.
#ifdef __cplusplus
namespace ntw2_unit_policy {
using U = uint32_t;
constexpr U kVersion = 1;
enum Mechanic : U { Fatigue = 0, Posture = 1, Engage = 2, MechanicCount = 3 }; // Engage = S1c engage + S3 fire latches + S1a order + S2a stance (one driver apply)
constexpr U kMaskFatigue = 1u << Fatigue, kMaskPosture = 1u << Posture, kMaskEngage = 1u << Engage;
enum Mode : U { Off = 0, Shadow = 1, Live = 2 };
constexpr U kMaxUnits = 2048, kMaxMembers = 512, kSerialBits = 1u << 20, kSlotWords = 64;
// ntw2_status::brain_unit_policy_words geometry (NTW2_BRAIN_UNIT_POLICY_WORDS = 256)
constexpr U kHeaderWords = 32, kFatigueBase = 32, kFatigueWords = 96, kPolicyBase = 128, kPolicyWords = 128, kWords = 256;

struct UnitView {            // owner-written in BeginStage; immutable during the stage loop
    U handle;                // live unit record (consistency check / adapter handle only)
    U ordinal;               // first-appearance ordinal over the primary registry (deterministic, never pointer order)
    U generation;            // bumps on any membership change (death, transfer, join, backlink change) or reselection
    U stage;                 // shared site-6 stage counter
    U memberCount;           // admissible members currently in the unit list (<= kMaxMembers)
    const U* members;        // their records, unit-list order; refused members (officers/crew/foreign) never appear
    U admitted;              // kMask* : whole-unit admission for THIS stage (after every provider's decide, Live or Shadow)
    const U* ran;            // per member (parallel to `members`): the stage number of its latest site-6 occurrence;
                             // `ran[k] == stage` means member k ran this stage (EndStage: != stage = out of the worklist)
};
struct Provider {            // one per mechanic module; registered at Start (absent = mechanic off)
    U mechanic, mode;        // Mechanic, Mode (Shadow or Live)
    // Owner, BeginStage, once per selected unit in ordinal order, after membership import: write this stage's unit
    // decision into slot[kSlotWords]. Return 0 = admit the whole unit for this mechanic this stage; else a refusal code
    // (the whole unit runs native for that mechanic this stage).
    U (*decide)(U unitIndex, const UnitView& unit, U* slot);
    // Owner, EndStage, once per selected unit in ordinal order, after the last occurrence (out-of-worklist publication,
    // shadow tallies). `unit.admitted` is this stage's admission.
    void (*end)(U unitIndex, const UnitView& unit, U* slot);
    // Owner: unitIndex retired (identity change, unit gone) or Stop — drop persisted unit state.
    void (*retire)(U unitIndex);
    // Optional (null = none; zero cost when absent). Owner, EndOccurrence, after the occurrence's native step: called for
    // a Live provider when `g_occ.mask` has its mechanic, and for a Shadow provider on every selected member occurrence of
    // a unit whose Shadow decide() returned 0 this stage. `slot` is the unit's slot of this provider's mechanic.
    void (*observe)(U entity, const UnitView& unit, U* slot);
};
struct Config {
    U imageBase;
    const Provider* providers[MechanicCount]; // null = mechanic off
    const U* cloneEntries;                    // ntw2_clone_set::entries (immutable)
    bool s0;                                  // --brain-s0 owns the runner and calls the seam hooks below
};
// Owner-written, valid between BeginOccurrence and EndOccurrence; the BRAIN_U clones read it from inline asm at the fixed
// offsets asserted below. slot[m] is non-null for every member occurrence (the unit's slot, also for a mechanic that is not
// admitted: test `mask` first); a non-member occurrence has mask 0, unitIndex ~0u and null unit/slots.
struct Occurrence {
    U entity;                // @0  the occurrence's man A (0 outside an occurrence)
    U unitIndex;             // @4  ~0u when not a selected member
    U mask;                  // @8  LIVE mechanics admitted for this occurrence (unit.admitted & live bits, 0 for non-members)
    const UnitView* unit;    // @12
    U* slot[MechanicCount];  // @16 the unit's decision slots
    U reserved[4];
};
static_assert(sizeof(U) == 4 && sizeof(void*) == 4, "Win32 layout: g_occ is read by inline asm");
extern Occurrence g_occ;     // bindings: (g_occ.entity == A && (g_occ.mask & kMaskX)) ? apply slot : native (+ Drain)
bool Bind(U imageBase, U* bindings); // writes NTW2_BIND_U_OCC = &g_occ (data binding); gates themselves belong to the mechanic modules
bool Start(const Config&);   // pins the 11 infantry tables (puppet rule) and the routed slots +108/+1A4 = 670F40/6543D0
void Stop();                 // owner drained: routing off; persisted unit state stays in native men (no write)
void Reset();
void Snapshot(U* words /*[kHeaderWords]*/);
bool Started();
U StorageBytes();            // retained activation storage (0 before the first Start; kept for the process lifetime)
U RequiredStorageBytes();    // what the first Start allocates (budget it beforehand)
void BeginStage(U manager);  // selection (first stage, retried every 64), import, provider decide, serial bits
void EndStage();             // provider end, drains applied
U BeginOccurrence(U entity); // sets g_occ, returns its (live) mask (S0 runner + own runner)
void EndOccurrence();        // provider observe, clears g_occ
void AbandonOccurrence();    // occurrence ended by an exception: clears g_occ without observe
void RunOccurrence(U entity, U cls, U original, const U* cloneEntries); // OccurrenceRunner.run when S0 is off
void Drain(U unitIndex, U mechanic, U code); // gate miss / contract fault: unit native for `mechanic` from the next seam
                                             // until its generation changes and 64 stages have passed; counted
// Oracle surface: the selected unit's immutable view / handle (nullptr / 0 outside the selection).
const UnitView* View(U unitIndex);
U UnitCount();
U UnitIndexOf(U handle);     // ~0u when not selected
bool UnitListStable(U unitIndex); // the unit's live member list still equals the one imported at this stage's seam (EndStage guard)
} // namespace ntw2_unit_policy
#endif
#define NTW2_UNIT_POLICY_HEADER_LABELS "version", "modes", "stages", "units_selected", "units_rejected", \
 "members_selected", "members_refused", "admitted_fatigue", "admitted_posture", "admitted_engage", \
 "unit_stages_fatigue", "unit_stages_posture", "unit_stages_engage", "refused_fatigue", "refused_posture", \
 "refused_engage", "admitted_occurrences", "native_occurrences", "drains_fatigue", "drains_posture", "drains_engage", \
 "faults", "last_fault", "seam_us_last", "seam_us_max", "seam_us_total", "out_of_worklist_last", "generation_bumps", \
 "units_retired", "select_passes", "members_joined", "members_departed"
#ifdef __cplusplus
namespace ntw2_unit_policy {
// Header words 0..31 (kHeaderWords). Counters wrap modulo 2^32. modes: 2 bits per mechanic (Mode) at bit 2*mechanic.
// admitted_* = units admitted by that mechanic's decide() at the last stage (Live or Shadow); unit_stages_* the cumulative
// sum; refused_* cumulative unit-stages whose decide() refused. admitted_occurrences = occurrences with a nonzero live
// mask, native_occurrences all others. seam_us_* = BeginStage + EndStage (one QPC pair each per stage, never per man).
enum Word : U {
    Version, Modes, Stages, UnitsSelected, UnitsRejected, MembersSelected, MembersRefused, AdmittedFatigue,
    AdmittedPosture, AdmittedEngage, UnitStagesFatigue, UnitStagesPosture, UnitStagesEngage, RefusedFatigue,
    RefusedPosture, RefusedEngage, AdmittedOccurrences, NativeOccurrences, DrainsFatigue, DrainsPosture, DrainsEngage,
    Faults, LastFault, SeamUsLast, SeamUsMax, SeamUsTotal, OutOfWorklistLast, GenerationBumps, UnitsRetired,
    SelectPasses, MembersJoined, MembersDeparted, HeaderWordCount
};
static_assert(HeaderWordCount == kHeaderWords, "unit policy header geometry");
// last_fault codes
enum Fault : U { FaultNone, FaultSelectRead, FaultImportRead, FaultProviderRead, FaultCapacity };
} // namespace ntw2_unit_policy
#endif
