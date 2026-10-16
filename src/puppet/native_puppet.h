#pragma once
#include <stdint.h>

// Puppet survival probe, stage 1 (--puppet-probe N): stationary wait-node admission of 1..4 ordinary foot-infantry
// units. analysis/native-unit-sim-rewrite.md section 3; recovery in analysis/native-brain-node-0x66dcf0.md and
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
//           dying members (+628 != 0, death system owns them), backlink changes and joined members are recorded;
//   admit   a pending member that is active (+30==1), has no target (+1EC), pending request (+18), active request
//           sequence (+390), charge callback (+4E8), crew list (+66C), engage phase 9, melee activity 0xD / stance 2,
//           rout order 0x3C/0x3D / activity 0x4B or death state (+628): the native wait-node installer through the
//           class table (+134 = 0x650600: destroys an enabled +22C node, constructs 0x61D8F0 with holder +228, table
//           0x1334028), then once the holder protocol of the common step 0x670EED..0x670F24 (begin +4 with latch
//           +23C, step +8 and counter +238 while done +234 is clear). Begin either marks the quiet owner done or runs
//           the engine stop transaction 0x6669B0(A,0). Phase +224 is not written: the native installer path
//           (watcher begin 0x7FF5C0 -> 0x809D80 -> +134) never writes it, so the owning driver observes a real wait
//           node at handback exactly as after a native watcher install. No +628 park, no fake table.
//   detect  a parked member whose +22C is no longer an enabled wait node owned by itself (an external formation,
//           order, engage or watcher install) is reparked by the same transaction when still eligible (the request
//           sequence may be active: begin's stop transaction cancels it), else handed back.
//   loop    the 0x585D10 loop itself (+30==1 filter, end reloaded after every occurrence): parked members with a
//           wait node skip the native step +0C; everybody else, and a parked member whose node was replaced during
//           this loop, runs the original virtual.
// Common step (class slot 0x1333714+08 = 0x670EB0, swapped by the runtime): a parked member with a wait node runs
// 0x81AC80 (terrain/extent) and 0x663730 (order -> activity label) only; the watcher 0x66E780, the +22C node
// begin/step and the action-row/root-motion advance 0x66EE30 are gated. Anything else forwards to 0x670EB0.
// Handback (ineligible, dying, transfer, fault, stop) writes nothing: the member holds a real native node and native
// control resumes at its next occurrence. Counters wrap modulo 2^32.
#define NTW2_PUPPET_WORD_LABELS \
 "version", "enabled", "units_requested", "units_selected", "units_rejected", "units_examined", "stages", \
 "selection_stage", "members_selected", "members_rejected", "members_admitted", "members_parked", "members_pending", \
 "admission_refusals", "parked_member_ticks", "skipped_native_steps", "gated_common_steps", "reparks", "handbacks", \
 "external_nodes_seen", "external_seen_seam", "external_seen_loop", "external_seen_common", "deaths_imported", \
 "dying_handbacks", "departed_members", "transfers_imported", "joined_members", "faults", "last_fault", \
 "adapter_us_last", "adapter_us_max", "adapter_us_total", "install_quiet", "install_stopped", "ineligible_handbacks", \
 "stop_handbacks", "retired_units", "common_calls", "loop_occurrences", \
 "u0_ordinal", "u0_members", "u0_parked", "u0_handed_back", "u1_ordinal", "u1_members", "u1_parked", "u1_handed_back", \
 "u2_ordinal", "u2_members", "u2_parked", "u2_handed_back", "u3_ordinal", "u3_members", "u3_parked", "u3_handed_back", \
 "first_admission_stage", "parked_peak", "reserved58", "reserved59", "reserved60", "reserved61", "reserved62", \
 "reserved63"
#ifdef __cplusplus
namespace ntw2_puppet {
using U = uint32_t;
constexpr U kVersion = 1, kWords = 64, kMaxUnits = 4, kMaxUnitMembers = 512, kMaxRows = 4096;
enum Word : U {
    Version, Enabled, UnitsRequested, UnitsSelected, UnitsRejected, UnitsExamined, Stages, SelectionStage,
    MembersSelected, MembersRejected, MembersAdmitted, MembersParked, MembersPending, AdmissionRefusals,
    ParkedMemberTicks, SkippedNativeSteps, GatedCommonSteps, Reparks, Handbacks, ExternalNodesSeen, ExternalSeenSeam,
    ExternalSeenLoop, ExternalSeenCommon, DeathsImported, DyingHandbacks, DepartedMembers, TransfersImported,
    JoinedMembers, Faults, LastFault, AdapterUsLast, AdapterUsMax, AdapterUsTotal, InstallQuiet, InstallStopped,
    IneligibleHandbacks, StopHandbacks, RetiredUnits, CommonCalls, LoopOccurrences,
    UnitRows = 40, // kMaxUnits x (ordinal, members selected, parked now, handed back)
    FirstAdmissionStage = UnitRows + 4 * kMaxUnits, ParkedPeak, WordCount = kWords
};
static_assert(UnitRows == 40 && FirstAdmissionStage == 56 && ParkedPeak == 57, "puppet status row geometry");
// last_fault codes (fault word counts every one).
enum Fault : U { FaultNone, FaultSelectRead, FaultImportRead, FaultInstall };
struct Binding {
    U image_base; // mapped base of the approved image; class/node/function constants are relocated by it
    U units;      // 1..kMaxUnits units to select
};
bool Start(const Binding& binding); // false: bad binding or the class/node tables differ from the approved image
void Stop();                        // owner drained: surviving members are handed back (no native write)
void Reset();                       // zero counters and membership (activation)
bool Started();
void Stage(U manager);       // site 6 replacement: whole 0x585D10 loop for `manager`
bool CommonStep(U entity);   // class slot +08: true when the gated common step ran (the caller then skips 0x670EB0)
void Snapshot(U* words /*[kWords]*/);
// Oracle surface: the admission transaction on one record. `stopped` reports begin's stop transaction. Returns the
// postcondition: enabled wait node at +22C with owner = entity and context = holder +A0 (A+2C8).
bool Install(U entity, bool& stopped);
bool WaitNodeInstalled(U entity);
} // namespace ntw2_puppet
#endif
