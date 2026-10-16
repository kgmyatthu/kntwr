#pragma once
#include <stdint.h>

// Puppet survival probe (--puppet-probe N|all): wait-node admission of ordinary foot-infantry units, N = 1..
// NTW2_PUPPET_MAX_UNITS in registry order or every qualifying unit ("all" = NTW2_PUPPET_MAX_UNITS), and (stage 2) a
// deterministic slot mover for the parked men at site 13 (see "Stage 2 movable puppets" below). Identity rows are
// published for the first NTW2_PUPPET_ROW_UNITS units; every other counter aggregates over all selected units.
// analysis/native-unit-sim-rewrite.md section 3; recovery in analysis/native-brain-node-0x66dcf0.md and
// analysis/checkpoints/PuppetProbe.md. Owner thread only; every native transaction is the engine's own code.
//
// Selection (once, first site-6 stage with a nonempty primary registry G+24C/+250; retried every 64 stages while
// nothing qualified): units in first-appearance order over the registry (deterministic for a replay; never pointer
// order) of records whose class table is an admitted infantry table (kInfantryTables). A unit qualifies when it has
// 1..512 non-null members (U+2CC/+2D0), no artillery (+0C 0x6F4660) or cavalry (+0C 0x602EB0) member and at least one
// admissible member: an admitted infantry table, unit backlink +1F0 == the unit, no crew list (+66C) and no enabled
// crew node 0x133AE34. Admissible members are selected; every other member (officer/ensign classes, crew, foreign
// backlink) and every attached container entry (U+1F4) stays native and is counted (puppet_select_words). Member
// identity is the 32-bit registry serial +2C plus a unit generation; the record address is only a consistency check
// and an adapter handle.
//
// Per stage (site 6 = the ACTIVE clone's call of 0x585D10, owner, before the first occurrence):
//   import  each selected unit's live member list: departed members (left U+2D0; death or transfer, never read again),
//           diverts (+628 != 0, see below), backlink changes and joined members are recorded. Deaths are imported only
//           from the membership diff (a member that left U+2D0: death or transfer out);
//   admit   a pending member that is active (+30==1), has no target (+1EC), pending request (+18), active request
//           sequence (+390), charge callback (+4E8), crew list (+66C), engage phase 9, melee activity 0xD / stance 2,
//           rout order 0x3C/0x3D / activity 0x4B or divert controller (+628): the native wait-node installer through the
//           class table (+134 = 0x650600: destroys an enabled +22C node, constructs 0x61D8F0 with holder +228, table
//           0x1334028), then once the holder protocol of the common step 0x670EED..0x670F24 (begin +4 with latch
//           +23C, step +8 and counter +238 while done +234 is clear). Begin either marks the quiet owner done or runs
//           the engine stop transaction 0x6669B0(A,0). Phase +224 is not written: the native installer path
//           (watcher begin 0x7FF5C0 -> 0x809D80 -> +134) never writes it, so the owning driver observes a real wait
//           node at handback exactly as after a native watcher install. No +628 park, no fake table.
//   divert  +628 is the engine's controller registration (0x662E90: A+628 = controller, +62C kind, +630 activity,
//           +634/+638 action row/frame, +63C..+644 target, +648 heading, +64C/+650/+654 speed cap/accel/turn rate);
//           the controller itself releases the man (0x65FEE0 -> 0x63CE20 clears +628). Its motion is produced ONLY by the
//           man's own brain step: 0x66CE00 @0x66D2DF..0x66D2E6 sends a battle-active man with +628 != 0 to vt+1A8
//           (0x67A050) instead of the drivers 0x62DFF0/0x6718F0/0x658C50/0x64DE80; 0x67A050 writes the movement intent
//           through 0x80B080 (kinds 0/1: +D4/+D8/+DC/+E0/+18C/+148 toward the target, speed +194) or the path follower
//           0x819770 (kind 4), and kinds 2..4 run 0x663730 + vt+1A4 (0x6543D0). The controller update (0x672B50 ->
//           0x672B80/0x672F40, 0x6735E0) writes no member pose or intent; site 13 only consumes the brain's intent. A
//           parked man whose step is skipped would therefore never follow the controller, so the divert branch is
//           REQUIRED: a parked member with +628 != 0 stays a member (wait node kept) but its site-6 step runs the original
//           +0C (the native controller branch) and its common step forwards to 0x670EB0. Each divert is an event
//           (kind/table/activity/target recorded, histogram by kind). When the controller releases him (+628 back to 0)
//           the next seam resumes skipping if his wait node survived, reparks him through the admission transaction if
//           it was replaced and he is eligible, else hands him back.
//   detect  a parked member whose +22C is no longer an enabled wait node owned by itself (an external formation,
//           order, engage or watcher install) is reparked by the same transaction when still eligible (the request
//           sequence may be active: begin's stop transaction cancels it), else handed back.
//   loop    the 0x585D10 loop itself (+30==1 filter, end reloaded after every occurrence): parked members with a
//           wait node and no divert skip the native step +0C; everybody else, a diverted member, and a parked member
//           whose node was replaced during this loop, runs the original virtual.
// Common step (slot +08 = 0x670EB0 of every admitted infantry table, swapped by the runtime): a parked, non-diverted
// member with a wait node runs 0x81AC80 (terrain/extent) and 0x663730 (order -> activity label) only; the watcher
// 0x66E780, the +22C node begin/step and the action-row/root-motion advance 0x66EE30 are gated. Anything else forwards.
// Membership fast path (both seams): one bit per registry serial +2C (2^20 serials), set exactly while the serial's
// row is parked; a clear bit costs one +2C load and one bitset load, a set bit confirms the row and its record.
// Handback (ineligible, transfer, fault, stop) writes nothing: the member holds a real native node and native control
// resumes at its next occurrence. Counters wrap modulo 2^32.
// Cost accounting, per site-6 window (the previous seam to this one): adapter_us = seam work (selection, import,
// installs) plus the gated common-step replacement work; dispatch_us = estimated routing overhead paid by EVERY
// occurrence at both seams (the site-6 membership test, and the common-step gate test for all admitted-table records
// after its two-load tick-owner epoch test), excluding forwarded original calls. dispatch_us is sampled: every 64th
// occurrence is timed with the TSC (calibrated against QPC since Start) and scaled by 64; the read overhead biases it
// upward.
// The sum adapter_us + dispatch_us is the probe's per-tick cost.
// Common-step diagnostics (live run 1: gated_common_steps 0 of 42M class calls): common_member_calls counts common
// steps of parked members; common_parked_forwarded those that were forwarded (stale generation, divert or replaced
// node); parked_no_common_ticks counts parked member-ticks that received NO common step call between two seams.
// member_caller_va / common_caller_va are the preferred-base return addresses of the last parked-member call and of the
// last sampled call of any record (the native call site of slot +08).
// Unit identity rows (words 40 + 4k, k < min(units_selected, NTW2_PUPPET_ROW_UNITS); for a human to find the unit):
//   id     = examined ordinal (bits 0..11) | army (12..15; 15 unknown/null) | selected men (16..31). The army is the
//            index of A+1F8 in first-appearance order over the primary registry scan (deterministic for a replay;
//            0 is the first army met, not necessarily the player's).
//   counts = parked now (0..15) | handed back (16..31)
//   x, z   = float bits of the first selected member's +48/+50 at selection (start position, world metres).
// Counter notes for the divert branch: parked_member_ticks counts every parked member per stage (diverted included);
// skipped_native_steps only the steps actually skipped; diverted_handbacks counts members handed back when their divert
// ended (wait node replaced and no longer eligible).
#define NTW2_PUPPET_UNIT_ORDINAL(id) ((id) & 0xFFFu)
#define NTW2_PUPPET_UNIT_ARMY(id) (((id) >> 12) & 0xFu)
#define NTW2_PUPPET_UNIT_MEN(id) ((id) >> 16)
#define NTW2_PUPPET_NO_ARMY 15u
#define NTW2_PUPPET_WORD_LABELS \
 "version", "enabled", "units_requested", "units_selected", "units_rejected", "units_examined", "stages", \
 "common_caller_va", "members_selected", "members_rejected", "members_admitted", "members_parked", "members_pending", \
 "admission_refusals", "parked_member_ticks", "skipped_native_steps", "gated_common_steps", "reparks", "handbacks", \
 "external_nodes_seen", "external_seen_seam", "external_seen_loop", "external_seen_common", "deaths_imported", \
 "diverted_handbacks", "departed_members", "transfers_imported", "joined_members", "faults", "last_fault", \
 "adapter_us_last", "adapter_us_max", "adapter_us_total", "install_quiet", "install_stopped", "ineligible_handbacks", \
 "stop_handbacks", "retired_units", "common_calls", "loop_occurrences", \
 "u0_id", "u0_counts", "u0_x", "u0_z", "u1_id", "u1_counts", "u1_x", "u1_z", \
 "u2_id", "u2_counts", "u2_x", "u2_z", "u3_id", "u3_counts", "u3_x", "u3_z", \
 "parked_no_common_ticks", "parked_peak", "dispatch_us_last", "member_caller_va", "dispatch_us_total", \
 "dispatch_samples", "common_member_calls", "common_parked_forwarded"
// Motion/divert observation row (ntw2_status::puppet_motion_words), read-only diagnostics measured at each seam after
// the membership import, over parked members confirmed in their unit's live list:
//   divert_*      divert events (+628 registered on a parked member) by stage: first/last stage, the stage with the
//                 most and that count, and a histogram over stage buckets 1, 2-3, 4-7, ..., >=2048.
//   intent/moved  parked, non-diverted members with nonzero +D4/+D8/+DC intent / whose +48/+50 changed since the
//                 previous seam (last stage and cumulative member-ticks; first stage any moved; peak and its stage).
//   disp_*        planar distance from the admission position (mean/max, centimetres, last stage; non-diverted).
//   slot_*        planar distance to the delivered formation slot: members whose watcher holder is enabled
//                 (+35B==1) and whose +2D4 node is the slot node 0x13472A4 built by 0x7E3D50 from the 0x581513
//                 descriptor; slot XZ = node+20/+28 = A+2F4/A+2FC [INFERENCE: descriptor +0/+8 are X/Z].
//                 slot_node_other counts enabled holders with a different node.
#define NTW2_PUPPET_MOTION_LABELS \
 "version", "divert_first_stage", "divert_last_stage", "divert_peak", "divert_peak_stage", \
 "divert_b1", "divert_b2_3", "divert_b4_7", "divert_b8_15", "divert_b16_31", "divert_b32_63", "divert_b64_127", \
 "divert_b128_255", "divert_b256_511", "divert_b512_1023", "divert_b1024_2047", "divert_b2048_up", \
 "intent_last", "moved_last", "intent_member_ticks", "moved_member_ticks", "first_move_stage", "moved_peak", \
 "moved_peak_stage", "disp_mean_cm", "disp_max_cm", "slot_members", "slot_mean_cm", "slot_max_cm", \
 "slot_node_other", "reserved30", "reserved31"
// Divert ownership row (ntw2_status::puppet_divert_words), one event per +628 registration seen on a parked member
// (at the seam or at its site-6 occurrence, whichever first):
//   events, active (diverted now), active_peak; kind_0..kind_4/kind_other: histogram of +62C at the event (0x67A050:
//   0/1 point move through 0x80B080, 2 heading turn, 3 hold, 4 path follower 0x819770); table_self/table_null/
//   table_other: controller table 0x1334250 (slot 0 returns the controller) / 0x1334218 (slot 0 returns null) / other
//   (table_other_va, preferred VA); last_kind/last_activity (+630)/last_target_x/z (float bits)/last_table;
//   target_mean_cm/target_max_cm: planar distance from the man to +63C/+644 at the event; native_steps: site-6 steps
//   of diverted members that ran the original (the controller branch); common_forwarded: their common steps forwarded;
//   released (+628 cleared while still a member), resumed (wait node intact: skipping again), reparked, handed_back,
//   departed (left the unit while diverted); duration_mean/max: stages from event to release; moved_member_ticks:
//   diverted members whose +48/+50 changed between seams; first_stage: stage of the first event.
#define NTW2_PUPPET_DIVERT_LABELS \
 "version", "events", "active", "active_peak", "kind_0", "kind_1", "kind_2", "kind_3", "kind_4", "kind_other", \
 "table_self", "table_null", "table_other", "table_other_va", "last_kind", "last_activity", "last_target_x", \
 "last_target_z", "last_table", "target_mean_cm", "target_max_cm", "native_steps", "common_forwarded", "released", \
 "resumed", "reparked", "handed_back", "departed", "duration_mean", "duration_max", "moved_member_ticks", "first_stage"
// Stage 2 machinery (ntw2_status::puppet_mover_words). Scope: performance rewrite only, engine targets and live
// parameters authoritative; no owned motion policy. Parked slot-followers stay parked until the native slot-follow
// chain (slot node 0x13472A4 at A+2D4 delivered by class vt+B8 0x6529B0; watcher begin 0x7FF680 -> 0x809DB0 -> class
// vt+150 0x650860 -> MOVE node 0x1347270 at +22C, begin 0x816080 / step 0x818500; path follower 0x819770; site-13
// speed controller 0x7F0260) is closed and ported (analysis/checkpoints/PuppetProbe.md "Slot-follow chain closure").
// Diverted members keep the native step: in the +628 branch the brain runs only the controller contract 0x67A050 plus
// its common prologue/epilogue (0x63C440, vt+108 0x670F40, the +5B8/+518/+F0/+5C/+88/+F2/0x639200/+61C tail), which
// a parked member currently also skips. Delivered here:
//   PointMove  the engine's point-move branch of 0x67A050 (kinds 0/1, +EC==1) as a function of the controller's
//              live parameters (target +63C/+644, heading +648, cap +64C, accel +650, turn +654): +444 = 0, word
//              +458 = 0; speed state +194 += accel*0.1, zero when negative (zero step), capped; step toward the target
//              from position + pending intent bounded by speed*0.1; heading limited by min(turn*0.1, 3.11 rad) with
//              the engine's 0x8000 word convention; intent through the native writer 0x80B080 (+D4/+D8/+DC/+E0/+18C/
//              +148, refused while +18 is pending); +D0 = 0. Byte-equal to native 0x67A050 kind 0 (oracle).
//   Move       site 13 entry (the ACTIVE clone's call of the movement loop 0x531AF0, after every other producer of
//              the tick, before the movement consumers; then the owned loco or the original loop runs): the
//              determinism hash. FNV-1a over the stage, the ordered event chain (admit/repark/handback/departure/
//              divert begin/end by serial) and every parked member in row order (serial, divert, XYZ bits, heading,
//              intent bits); chained, with checkpoints at mover stages 64/256/1024/4096 to compare runs (e.g.
//              --workers 1 vs 8). slot_waiting counts parked members holding a delivered, unbegun slot node (the
//              engine wants them to walk; native begin would install a MOVE node), with their mean/max distance.
#define NTW2_PUPPET_MOVER_LABELS \
 "version", "stages", "mover_us_last", "mover_us_max", "mover_us_total", "hash_last", "hash_chain", "hash_s64", \
 "hash_s256", "hash_s1024", "hash_s4096", "events", "parked_hashed_last", "diverted_last", "slot_waiting_last", \
 "slot_waiting_mean_cm", "slot_waiting_max_cm", "slot_waiting_member_ticks", "reserved18", "reserved19", "reserved20", \
 "reserved21", "reserved22", "reserved23", "reserved24", "reserved25", "reserved26", "reserved27", "reserved28", \
 "reserved29", "reserved30", "reserved31"
// Selection diagnostics (ntw2_status::puppet_select_words), per examined unit (first failing reason) and per member:
//   reject_*        member count 0/>512/null list, null member, artillery member (+0C 0x6F4660), cavalry member (+0C
//                   0x602EB0), no admissible member, row capacity;
//   units_attached  admitted units with attached container entries (U+1F4; the attached records are never touched);
//   member_*        refused members of admitted units: crew (+66C or enabled crew node 0x133AE34), backlink +1F0 not
//                   the unit, other class table (officers/ensigns/...), admitted on an alternative infantry table;
//   tables_pinned   infantry class tables admitted at Start (kInfantryTables whose slots equal 0x1333714's);
//   top_table_k / top_count_k (k < 8): the majority member class table (preferred VA) of rejected units and how many
//                   rejected units had it, in first-seen order; top_other: rejected units beyond eight distinct tables.
#define NTW2_PUPPET_SELECT_LABELS \
 "version", "reject_member_count", "reject_null_member", "reject_artillery", "reject_cavalry", "reject_no_infantry", \
 "reject_capacity", "units_attached", "member_crew", "member_backlink", "member_other_class", "member_alt_table", \
 "tables_pinned", "top_other", "top_table_0", "top_count_0", "top_table_1", "top_count_1", "top_table_2", \
 "top_count_2", "top_table_3", "top_count_3", "top_table_4", "top_count_4", "top_table_5", "top_count_5", \
 "top_table_6", "top_count_6", "top_table_7", "top_count_7", "registry_infantry", "reserved31"
#ifdef __cplusplus
namespace ntw2_puppet {
using U = uint32_t;
// kMaxUnits / kRowUnits equal NTW2_PUPPET_MAX_UNITS / NTW2_PUPPET_ROW_UNITS (asserted by the runtime).
constexpr U kVersion = 5, kWords = 64, kMaxUnits = 2048, kRowUnits = 4, kMaxUnitMembers = 512, kMaxRows = 65536,
            kSampleMask = 63;
constexpr U kPuppetNoArmy = NTW2_PUPPET_NO_ARMY;
// Infantry class tables of the 13-table family (native-loco-consumer-seams.md 3.1) whose slots +08/+0C/+130/+134/
// +188/+1A4/+1A8/+108/+B8/+FC equal 0x1333714's on the approved image (verified at Start; a mismatching table is
// dropped). 0x132B7D8 (+0C thunk 0x6F50F0) and 0x132BA04 (+0C wrapper 0x602EB0) are not admitted. The runtime gates
// slot +08 of every listed table.
constexpr U kInfantryTableCount = 11;
constexpr U kInfantryTables[kInfantryTableCount] = {0x1333714, 0x13473D0, 0x13475E4, 0x13477F8, 0x13479B4, 0x1347B70,
                                                   0x1347D2C, 0x1347EE8, 0x13480A4, 0x1348260, 0x134841C};
enum Word : U {
    Version, Enabled, UnitsRequested, UnitsSelected, UnitsRejected, UnitsExamined, Stages, CommonCallerVa,
    MembersSelected, MembersRejected, MembersAdmitted, MembersParked, MembersPending, AdmissionRefusals,
    ParkedMemberTicks, SkippedNativeSteps, GatedCommonSteps, Reparks, Handbacks, ExternalNodesSeen, ExternalSeenSeam,
    ExternalSeenLoop, ExternalSeenCommon, DeathsImported, DivertedHandbacks, DepartedMembers, TransfersImported,
    JoinedMembers, Faults, LastFault, AdapterUsLast, AdapterUsMax, AdapterUsTotal, InstallQuiet, InstallStopped,
    IneligibleHandbacks, StopHandbacks, RetiredUnits, CommonCalls, LoopOccurrences,
    UnitRows = 40, // kRowUnits x (id, counts, x, z): see the identity row layout above
    ParkedNoCommonTicks = UnitRows + 4 * kRowUnits, ParkedPeak, DispatchUsLast, MemberCallerVa, DispatchUsTotal,
    DispatchSamples, CommonMemberCalls, CommonParkedForwarded, WordCount
};
static_assert(UnitRows == 40 && ParkedNoCommonTicks == 56 && ParkedPeak == 57 && DispatchSamples == 61 &&
              CommonParkedForwarded == 63 && WordCount == kWords, "puppet status row geometry");
// last_fault codes (fault word counts every one).
enum Fault : U { FaultNone, FaultSelectRead, FaultImportRead, FaultInstall, FaultMotionRead, FaultMoveRead };
constexpr U kMotionVersion = 1, kMotionWords = 32, kDivertBuckets = 12;
enum MotionWord : U {
    MotionVersion, MotionDivertFirst, MotionDivertLast, MotionDivertPeak, MotionDivertPeakStage,
    MotionDivertHist, MotionIntentLast = MotionDivertHist + kDivertBuckets, MotionMovedLast, MotionIntentTicks,
    MotionMovedTicks, MotionFirstMoveStage, MotionMovedPeak, MotionMovedPeakStage, MotionDispMeanCm, MotionDispMaxCm,
    MotionSlotMembers, MotionSlotMeanCm, MotionSlotMaxCm, MotionSlotNodeOther, MotionWordCount = kMotionWords
};
static_assert(MotionIntentLast == 17 && MotionSlotNodeOther == 29, "puppet motion row geometry");
constexpr U kDivertVersion = 1, kDivertWords = 32, kDivertKinds = 6;
enum DivertWord : U {
    DivertVersion, DivertEvents, DivertActive, DivertActivePeak, DivertKind, DivertTableSelf = DivertKind + kDivertKinds,
    DivertTableNull, DivertTableOther, DivertTableOtherVa, DivertLastKind, DivertLastActivity, DivertLastTargetX,
    DivertLastTargetZ, DivertLastTable, DivertTargetMeanCm, DivertTargetMaxCm, DivertNativeSteps, DivertCommonForwarded,
    DivertReleased, DivertResumed, DivertReparked, DivertHandedBack, DivertDeparted, DivertDurationMean,
    DivertDurationMax, DivertMovedTicks, DivertFirstStage, DivertWordCount
};
static_assert(DivertTableSelf == 10 && DivertFirstStage == 31 && DivertWordCount == kDivertWords, "puppet divert row geometry");
constexpr U kMoverVersion = 2, kMoverWords = 32;
enum MoverWord : U {
    MoverVersion, MoverStages, MoverUsLast, MoverUsMax, MoverUsTotal, MoverHashLast, MoverHashChain, MoverHashS64,
    MoverHashS256, MoverHashS1024, MoverHashS4096, MoverEvents, MoverParkedHashed, MoverDiverted, MoverSlotWaiting,
    MoverSlotWaitingMeanCm, MoverSlotWaitingMaxCm, MoverSlotWaitingTicks, MoverWordCount = kMoverWords
};
static_assert(MoverHashLast == 5 && MoverSlotWaitingTicks == 17, "puppet mover row geometry");
constexpr U kSelectVersion = 1, kSelectWords = 32, kTopTables = 8;
enum SelectWord : U {
    SelectVersion, RejectMemberCount, RejectNullMember, RejectArtillery, RejectCavalry, RejectNoInfantry,
    RejectCapacity, UnitsAttached, MemberCrew, MemberBacklink, MemberOtherClass, MemberAltTable, TablesPinned,
    TopOther, TopTables, RegistryInfantry = TopTables + 2 * kTopTables, SelectWordCount = kSelectWords
};
static_assert(TopTables == 14 && RegistryInfantry == 30, "puppet select row geometry");
struct Binding {
    U image_base; // mapped base of the approved image; class/node/function constants are relocated by it
    U units;      // 1..kMaxUnits units to select (kMaxUnits = every qualifying unit)
    // Tick-owner epoch: CommonStep gates only when *tick_owner is the calling thread and (*epoch_mask & epoch_bit).
    const volatile long* tick_owner;
    const volatile U* epoch_mask;
    U epoch_bit;
};
bool Start(const Binding& binding); // false: bad binding, storage refused, or the class/node tables differ
void Stop();                        // owner drained: surviving members are handed back (no native write)
void Reset();                       // zero counters and membership (activation)
bool Started();
void Stage(U manager);       // site 6 replacement: whole 0x585D10 loop for `manager`
// Class slot +08 (every common step of an admitted infantry table): true when the gated common step ran (the caller
// then skips 0x670EB0). Outside the bound tick-owner epoch it returns false without touching module state.
bool CommonStep(U entity, U returnAddress /*runtime return address of the slot +08 call*/);
void Snapshot(U* words /*[kWords]*/);
void SnapshotMotion(U* words /*[kMotionWords]*/);
void SnapshotDivert(U* words /*[kDivertWords]*/);
void SnapshotMover(U* words /*[kMoverWords]*/);
void SnapshotSelect(U* words /*[kSelectWords]*/);
// Site 13 entry (owner, puppet epoch): determinism hash and slot-waiting census of the members parked at this seam.
void Move();
// The point-move contract of 0x67A050 kinds 0/1 on one record with the controller's live parameters (see "PointMove"
// above); byte-equal to native 0x67A050 kind 0. Returns false when the native writer refused (+18 pending).
bool PointMove(U entity, float targetX, float targetZ, U targetHeading, float cap, float accel, float turnRate);
// Oracle surface: the admission transaction on one record. `stopped` reports begin's stop transaction. Returns the
// postcondition: enabled wait node at +22C with owner = entity and context = holder +A0 (A+2C8).
bool Install(U entity, bool& stopped);
bool WaitNodeInstalled(U entity);
} // namespace ntw2_puppet
#endif
