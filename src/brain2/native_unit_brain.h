#pragma once
#include <stdint.h>

// Per-unit brain, Stage A (--brain-unit-shadow): shadow only, gameplay-neutral.
//
// Question measured: how much of what each soldier's site-6 brain step decides is already a function of its unit?
// Stage B (not implemented) would decide once per unit and let non-exception soldiers follow; Stage A only counts.
//
// Per site-6 stage (ntw2_brain2::RunWorklist, owner thread):
//  1. BeginStage, BEFORE the native loop: one pool dispatch over the known units (units are independent). Each unit
//     reads ONLY unit-level inputs (UnitInput: the unit's command record U+930/U+934/[U+398+U+934*90] vtable, state
//     U+AA0, descriptor U+2C and type D+1C, flag bytes U+DA4/D9E/D9D, U+DA8, U+C2C, the ability table 0x55C9A0 reads
//     (U+DB8 count, FNV-1a of min(count,16)*0x2C bytes at U+DBC), battle phase M+14 and byte M+2704 behind the
//     55AC60/55AD60 predicates (M = [[U+C00]+8]+B0), group U+ADC and group+460 behind 53EEE0/55C2E0) and folds them
//     into a signature. Every derived pointer is proven readable (VirtualQuery, per-chunk interval table) before it is
//     dereferenced. The UnitDecision is the unit's held record (below) when the signature equals the signature the
//     record was formed under; otherwise the unit has no decision this stage (Stage B would re-decide). Workers write
//     only this module's rows; nothing native is written by anyone.
//  2. The native loop runs unchanged (original or census clone per brain2 configuration).
//  3. Observe, AFTER each occurrence's native step: the owner reads what the soldier decided (Field), its exception
//     bits (Exception) and its class vtable, and compares each field with its unit's decision. A non-exception soldier
//     whose class is not its unit's main class (the class with the most non-exception soldiers of that unit in the
//     previous stage) is an unresolved role (officer/ensign/musician candidates; roles are not recovered): it is
//     compared in the exception columns and counted in unresolved_role, never in the held columns.
//  4. EndStage: per unit, the main class of this stage is the class with the most non-exception soldiers (ties: the
//     lower census index, i.e. first seen in worklist order). Only main-class soldiers vote (others: vote_excluded).
//     Per field, the strict-majority value over the voters (Boyer-Moore candidate in worklist order, then verified
//     count*2 > n) becomes the held record for the next stage, together with this stage's signature. A field without
//     a strict majority holds no decision; its voters are counted in tick_none, never as tick agreement/disagreement.
// Formation slot rows (0x7F1730) and posture state tables are image/animation-database constants: they enter the
// soldier's decision through soldier-level indices, not the unit signature. Member count U+2CC is excluded from the
// signature on purpose (casualties would otherwise reset every decision); see analysis/native-brain2-design.md.
//
// Fields (values compared for equality): activity +1B8; order +1D8; holder = preferred vtable of the inline order
// node +22C when the enable byte +2C4 == 1, else 0; posture state = index (R+F8 - 0x1454168)/4 of the 13 posture
// singletons (0xFF null, 0xFE other pointer); stance +220; target unit = [T+1F0] of T = [A+1EC] (0 no target, ~0
// unreadable); engage phase +224; animation id +1BC; fire flags = bytes +5BC | +5AB<<8 | +F1<<16 | +619<<24 (driver
// engage/fire latches; "fire policy" semantics Unconfirmed).
// Exceptions (post-step): engage9 +224==9; melee activity 0xD or stance 2; routing [INFERENCE] order 0x3C/0x3D or
// activity 0x4B; parked +628!=0 (dead/dying candidate [INFERENCE]); deactivated +30!=1 after its step; far from the
// sequencer destination +3F4/+3FC (> kFarMeters planar from +48/+50, only while +390!=0 and the descriptor transform
// +404 is null); pending request +18!=0; artillery class 0x6F4660; crew (inline node vtable 0x133AE34 or crew list
// count +66C!=0); cavalry charge [INFERENCE] class 0x602EB0 with charge callback +4E8!=0; no unit +1F0==0; other
// class (soldier fields not read). Officer/ensign/musician roles are not recovered: they are excluded by class (see 3/4),
// and the vtable census below gives occurrences, disagreements and unit appearances per class vtable.
#define NTW2_BRAIN_UNIT_FIELD_LABELS "activity", "order", "holder", "posture_state", "stance", "target_unit", \
 "engage_phase", "anim_id", "fire_flags"
#define NTW2_BRAIN_UNIT_FIELD_WORD_LABELS "held_agree", "held_disagree", "held_none", "tick_agree", "tick_disagree", \
 "exception_agree", "exception_disagree", "worst_stage_permille"
#define NTW2_BRAIN_UNIT_HEADER_LABELS "version", "enabled", "stages", "occurrences", "observed", "units_last", \
 "unit_overflow", "decisions_last", "signature_changes", "new_units", "unit_unreadable", "soldier_unreadable", \
 "target_unreadable", "decide_us", "finalize_us", "buffer_overflow"
#define NTW2_BRAIN_UNIT_EXCEPTION_LABELS "engage9", "melee", "routing", "parked", "deactivated", "far_from_slot", \
 "pending_request", "artillery", "crew", "cavalry_charge", "no_unit", "other_class", "any_exception", \
 "far_measured", "far_unmeasured", "chunks"
#define NTW2_BRAIN_UNIT_CENSUS_LABELS "vtables_distinct", "vtable_overflow", "held_disagree_any", "held_agree_all"
#define NTW2_BRAIN_UNIT_TICK_NONE_LABEL "tick_none" /* per field, words 160..168 in field order */
#define NTW2_BRAIN_UNIT_ROLE_LABELS "unresolved_role", "vote_excluded", "observe_us"
#define NTW2_BRAIN_UNIT_TAIL_LABELS "last_stage_compared", "last_stage_agree_all", "units_decided", "reserved175"
#ifdef __cplusplus
namespace ntw2_region { struct Table; }
namespace ntw2_unit_brain {
using U = uint32_t;
constexpr U kVersion = 2;
constexpr U kFields = 9, kFieldStride = 8, kExceptionBits = 12, kVtables = 13, kInputs = 15;
constexpr float kFarMeters = 10.0f;
enum Field : U { Activity, Order, Holder, PostureState, Stance, TargetUnit, EngagePhase, AnimId, FireFlags };
enum FieldWord : U { HeldAgree, HeldDisagree, HeldNone, TickAgree, TickDisagree, ExceptionAgree, ExceptionDisagree,
                     WorstStagePermille };
enum Exception : U { ExEngage9, ExMelee, ExRouting, ExParked, ExDeactivated, ExFarFromSlot, ExPendingRequest,
                     ExArtillery, ExCrew, ExCavalryCharge, ExNoUnit, ExOtherClass };
// Status row (ntw2_status::brain_unit_words). Counters wrap modulo 2^32. WorstStagePermille is the minimum over
// stages of held_agree*1000/(held_agree+held_disagree) for that field's non-exception comparisons (0xFFFFFFFF: no
// stage compared it). Tick words count voters (main-class non-exception soldiers): tick_agree/tick_disagree only in
// unit-stages with a strict majority, tick_none (words 160..168) the voters of unit-stages without one. Units: rows
// with a soldier this stage. Vtable rows: (preferred vtable VA or runtime address, occurrences of soldiers with a unit
// row, non-exception occurrences disagreeing in >= 1 held field, unit-stage appearances summed over all stages).
// observe_us: cumulative owner time inside Observe (QPC per call, converted at EndStage).
enum Word : U {
    Version, Enabled, Stages, Occurrences, Observed, UnitsLast, UnitOverflow, DecisionsLast, SignatureChanges,
    NewUnits, UnitUnreadable, SoldierUnreadable, TargetUnreadable, DecideUs, FinalizeUs, BufferOverflow,
    FieldWords = 16,
    ExceptionWords = FieldWords + kFields * kFieldStride, // 88: kExceptionBits counts, then the four below
    AnyException = ExceptionWords + kExceptionBits, FarMeasured, FarUnmeasured, Chunks,
    VtablesDistinct = 104, VtableOverflow, HeldDisagreeAny, HeldAgreeAll,
    VtableRows = 108, // kVtables x (va, occurrences, disagree_any, unit_stages)
    TickNoneWords = VtableRows + 4 * kVtables, // 160: kFields words
    UnresolvedRole = TickNoneWords + kFields, VoteExcluded, ObserveUs,
    LastStageCompared, LastStageAgreeAll, UnitsDecided, Reserved175,
    WordCount
};
static_assert(ExceptionWords == 88 && Chunks == 103 && TickNoneWords == 160 && UnresolvedRole == 169 &&
              LastStageCompared == 172 && WordCount == 176, "brain unit status row geometry (NTW2_BRAIN_UNIT_WORDS)");
constexpr U kWords = WordCount;

struct Binding {
    U image_base; // preferred 0x400000 image base; class and posture constants are relocated by it
    void (__stdcall* dispatch)(U, U, U, void*); // ntw_pool_dispatch-compatible; null runs every chunk on the owner
    U pool;
    U workers;
};
bool Start(const Binding& binding); // allocates rows, tables and the observation buffer; false leaves it off
void Stop();                        // owner, no dispatch in flight; counters are retained
void Reset();                       // zeroes counters and every unit row (battle activation)
bool Started();
// Owner thread, in site-6 order. BeginStage runs the decision dispatch; Observe follows each occurrence's native
// step (entity = the occurrence pointer the loop just ran); EndStage forms the held records.
void BeginStage(U manager);
void Observe(U entity);
void EndStage();
void Snapshot(U* words /*[kWords]*/); // all zero until the first stage

// Pure extraction (oracle surface). `queries` counts VirtualQuery calls of the readability proofs.
struct Soldier { U values[kFields]; U exceptions; U vtable; U unit; U farMeasured; U targetUnreadable; };
// False when the soldier footprint (0x700 bytes) or its class table cannot be proven readable. Other-class
// occurrences return true with only ExOtherClass set and no field values.
bool ExtractSoldier(U entity, ntw2_region::Table& table, U& queries, Soldier& out);
// Unit-level inputs in UnitInput order (kInputs words); false when the unit itself is unreadable. Unreadable
// dependents read as 0xFFFFFFFF.
bool ReadUnitInputs(U unit, ntw2_region::Table& table, U& queries, U* inputs);
U Signature(const U* inputs);
} // namespace ntw2_unit_brain
#endif
