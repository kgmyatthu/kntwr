#pragma once
#include <stdint.h>

// Puppet survival probe (--puppet-probe N|all): stationary wait-node admission of ordinary foot-infantry units, N = 1..
// NTW2_PUPPET_MAX_UNITS in registry order or every qualifying unit ("all" = NTW2_PUPPET_MAX_UNITS). Identity rows are
// published for the first NTW2_PUPPET_ROW_UNITS units; every other counter aggregates over all selected units.
// analysis/native-unit-sim-rewrite.md section 3; recovery in analysis/native-brain-node-0x66dcf0.md and
// analysis/checkpoints/PuppetProbe.md. Owner thread only; every native transaction is the engine's own code.
//
// Selection (once, first site-6 stage with a nonempty primary registry G+24C/+250; retried every 64 stages while
// nothing qualified): units in first-appearance order over the registry (deterministic for a replay; never pointer
// order) of records whose class table is the census-majority infantry class 0x1333714. A unit qualifies when it has
// 1..512 members (U+2CC/+2D0), no attached container entries (U+1F4 count +10), no artillery (+0C 0x6F4660), cavalry
// (+0C 0x602EB0) or crew member (node 0x133AE34 enabled, or +66C), and a strict majority of 0x1333714 members whose
// unit backlink +1F0 is the unit. Its 0x1333714 members are selected; other members (officer/ensign candidates) stay
// native and are counted rejected. Member identity is the 32-bit registry serial +2C plus a unit generation; the
// record address is only a consistency check and an adapter handle.
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
// Common step (class slot 0x1333714+08 = 0x670EB0, swapped by the runtime): a parked, non-diverted member with a wait
// node runs 0x81AC80 (terrain/extent) and 0x663730 (order -> activity label) only; the watcher 0x66E780, the +22C node
// begin/step and the action-row/root-motion advance 0x66EE30 are gated. Anything else forwards to 0x670EB0.
// Handback (ineligible, transfer, fault, stop) writes nothing: the member holds a real native node and native control
// resumes at its next occurrence. Counters wrap modulo 2^32.
// Cost accounting, per site-6 window (the previous seam to this one): adapter_us = seam work (selection, import,
// installs) plus the gated common-step replacement work; dispatch_us = estimated routing overhead paid by EVERY
// occurrence at both seams (the site-6 membership test, and the common-step gate test for all class-0x1333714 records
// after its two-load tick-owner epoch test), excluding forwarded original calls. dispatch_us is sampled: every 64th
// occurrence is timed with the TSC (calibrated against QPC since Start) and scaled by 64; the read overhead biases it
// upward.
// The sum adapter_us + dispatch_us is the probe's per-tick cost.
// Common-step diagnostics (live run 1: gated_common_steps 0 of 42M class calls): common_member_calls counts class
// common steps of any selected-unit member (any state); common_parked_forwarded those of a parked member that were
// forwarded (stale generation or replaced node); parked_no_common_ticks counts parked member-ticks that received NO
// common step call between two seams. member_caller_va / common_caller_va are the preferred-base return addresses of
// the last member call and of the last sampled call of any record (the native call site of slot +08).
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
#ifdef __cplusplus
namespace ntw2_puppet {
using U = uint32_t;
// kMaxUnits / kRowUnits equal NTW2_PUPPET_MAX_UNITS / NTW2_PUPPET_ROW_UNITS (asserted by the runtime).
constexpr U kVersion = 4, kWords = 64, kMaxUnits = 2048, kRowUnits = 4, kMaxUnitMembers = 512, kMaxRows = 65536,
            kSampleMask = 63;
constexpr U kPuppetNoArmy = NTW2_PUPPET_NO_ARMY;
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
enum Fault : U { FaultNone, FaultSelectRead, FaultImportRead, FaultInstall, FaultMotionRead };
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
// Class slot +08 (every class-0x1333714 common step): true when the gated common step ran (the caller then skips
// 0x670EB0). Outside the bound tick-owner epoch it returns false without touching module state.
bool CommonStep(U entity, U returnAddress /*runtime return address of the slot +08 call*/);
void Snapshot(U* words /*[kWords]*/);
void SnapshotMotion(U* words /*[kMotionWords]*/);
void SnapshotDivert(U* words /*[kDivertWords]*/);
// Oracle surface: the admission transaction on one record. `stopped` reports begin's stop transaction. Returns the
// postcondition: enabled wait node at +22C with owner = entity and context = holder +A0 (A+2C8).
bool Install(U entity, bool& stopped);
bool WaitNodeInstalled(U entity);
} // namespace ntw2_puppet
#endif
