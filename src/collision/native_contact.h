#pragma once
#include <stdint.h>
// Collision contact responses: the type-8 callback 0x64CC70 -> argument vt+0x40 = 0x64CAD0
// (this = query record R, argument = neighbour S) that the soft-collision stage dispatches once
// per accepted contact. Design and closure: analysis/native-contact-response.md.
//
// Predict() is a pure port of the callback's decision logic for SAME-TEAM LAND contacts:
// tracker inputs of 0x52EDB0 (twice), 0x667260 -> 0x817160 (twice), the +0x13C gates and the
// avoidance predicate 0x664010 (0x6795D0, 0x62F1A0 -> 0x7E4BB0/0x80B5B0/0x81BD10/0x7FA690,
// 0x7FA590 -> original leaf 0x81A670). It reads only stage-entry state and writes the Plan.
// Every other contact (different teams, non-LAND tables, unknown virtual stubs, faults) is
// planned as an owner-original occurrence. Shared effects are never executed by Predict:
//   * tracker bitset/u16 append on R+0x388+0x74C and S+0x388+0x74C (owner, live state),
//   * byte writes R+0x13C / S+0x13C,
//   * avoidance manager (model+0xCC, vtable 0x1334234) virtual +0x14 = 0x629140 -> 0x629240 (R, S):
//     appends one pool-allocated {R, S, d2} record to the manager queue (+0x10 cap/+0x14 count/+0x18 data).
// Replay() applies them on the owner in contact order; Shadow() runs the original callback
// instead and compares every predicted effect bit-for-bit (the avoidance effect through the
// manager queue). Neither installs anything: no vtable, slot or vptr is changed.
#define NTW2_COLLIDE_CONTACT_WORD_LABELS \
 "version", "mode", "stages", "contacts", "port_contacts", "owner_diff_team", "owner_foreign_class", \
 "owner_unsupported", "owner_faults", "predicted_write_r", "predicted_write_s", "predicted_avoid", \
 "predicted_tracker_appends", "compared", "mismatches", "mismatch_write_r", "mismatch_write_s", \
 "mismatch_avoid", "mismatch_tracker", "mismatch_contact_pair", "unobservable_13c", "avoid_calls", \
 "combat_queue_appends", "owner_writes_13c", "owner_avoid_calls", "plan_us", "plan_thread_us", \
 "port_callback_us", "owner_callback_us", "replays", "owner_callbacks", "replay_faults", \
 "replay_revalidated", "globals_changed", "avoid_vtable", "avoid_slot14", "combat_vtable", \
 "first_mismatch_stage", "first_mismatch_contact", "first_mismatch_kind", "first_mismatch_r", \
 "first_mismatch_s", "identity_refusals", "max_contacts", "callback_faults", "tracker_replays", \
 "port_callbacks", "owner_kind_callbacks"
#ifdef __cplusplus
namespace ntw2_contact {
using U = uint32_t;
enum Mode : U { ModeOff = 0, ModeShadow = 1, ModeWorkers = 2 };
enum Word : U {
    Version, ModeWord, Stages, Contacts, PortContacts, OwnerDiffTeam, OwnerForeignClass,
    OwnerUnsupported, OwnerFaults, PredictedWriteR, PredictedWriteS, PredictedAvoid,
    PredictedTrackerAppends, Compared, Mismatches, MismatchWriteR, MismatchWriteS,
    MismatchAvoid, MismatchTracker, MismatchContactPair, Unobservable13C, AvoidCalls,
    CombatQueueAppends, OwnerWrites13C, OwnerAvoidCalls, PlanUs, PlanThreadUs,
    PortCallbackUs, OwnerCallbackUs, Replays, OwnerCallbacks, ReplayFaults,
    ReplayRevalidated, GlobalsChanged, AvoidVtable, AvoidSlot14, CombatVtable,
    FirstMismatchStage, FirstMismatchContact, FirstMismatchKind, FirstMismatchR,
    FirstMismatchS, IdentityRefusals, MaxContacts, CallbackFaults, TrackerReplays,
    PortCallbacks, OwnerKindCallbacks,
    WordCount
};
constexpr U kVersion = 1;
constexpr U kStockAvoidBitsetBytes = 0x2004u, kStockAvoidSerialCap = (kStockAvoidBitsetBytes / 4u) * 32u; // 65,568
constexpr U kAvoidBitsetBytes = 0x8004u, kAvoidSerialCap = (kAvoidBitsetBytes / 4u) * 32u;               // 262,176 (>= 262,144)
constexpr U kAvoidTrailerBytes = 16u, kAvoidAllocBytes = kAvoidBitsetBytes + kAvoidTrailerBytes;         // 0x8014 (trailer magic + self-addr + size + xor)
constexpr U kAvoidTrailerMagic = 0x4E545732u, kAvoidTrailerXor = 0xA5C35A3Cu;
enum Kind : uint16_t { KindPort, KindDiffTeam, KindForeign, KindUnsupported, KindFault, KindSerialOutOfBounds };
enum Flag : uint16_t {
    FlagRUnit = 1,        // R+0x1F0 != 0 (S-side tracker appends R's key)
    FlagSUnit = 2,        // S+0x1F0 != 0 (R-side tracker appends S's key)
    FlagWriteR = 4,       // R+0x13C = 1
    FlagWriteS = 8,       // S+0x13C = 1
    FlagAvoid = 0x10,     // avoidance manager vt+0x14(R, S)
    FlagDistR = 0x20,     // 0x52EDB0(R side) distance gate (different teams only)
    FlagDistS = 0x40,     // 0x52EDB0(S side) distance gate
    FlagUsedAvail = 0x80, // 0x664010 evaluated: its manager bitset reads are revalidated at replay
    FlagBitR = 0x100,     // stage-entry manager+0x90 bit of R+0x2C
    FlagBitS = 0x200      // stage-entry manager+0x90 bit of S+0x2C
};
// trackerX = X+0x388 ? X+0x388+0x74C : 0; keyX = low 16 bits of X+0x2C.
struct Plan { U trackerR, trackerS; uint16_t keyR, keyS, flags, kind; };
static_assert(sizeof(Plan) == 16, "plan stays one 16-byte row per contact");
// Stage-entry constants and identities, captured on the owner by BeginStage.
struct Stage {
    U delta, model, avoid, combat, avoidBits, avoidSerialCap;
    U callback40, thunk44, stubFalse, stubTrue, stubOwner, leaf;
    uint16_t headingBias, angleGate;
    float two, one, angleScale, minDistance, headingFactor, half, dominance, lead;
};
// Callback seam provided by the solver: runs the untouched original contact callback
// (S vt+0x44 with argument R) and returns false when it faulted.
using Original = bool (*)(void* context, void* s, void* r);

void Start(U image_delta, U mode);   // resets counters; mode is ModeShadow or ModeWorkers
U CurrentMode();
// Owner, before the callback pass. False: plans are not used this stage (every contact
// then runs the original callback); also refuses a manager that fails the identity pins.
bool BeginStage(Stage& stage, void* model);
// Owner, after the callback pass (checks the runtime words, publishes timers and the maximum).
void EndStage(Stage& stage, U contacts);
// Pure; any thread with the owner's MXCSR/x87 control word installed. Never faults out.
void Predict(const Stage& stage, Plan& plan, void* r, void* s);
void CountPlan(const Plan& plan);   // owner-side census of one plan
// wallUs: QPC around the plan dispatch; threadUs: per-chunk QPC occupancy (elapsed inside each
// chunk, including preemption; not CPU time) summed over owner+workers.
void AddPlanTime(U wallUs, U threadUs);
// Owner, in contact order. Both return false iff the original callback/replay faulted.
bool Shadow(const Stage& stage, const Plan& plan, U index, void* r, void* s, Original original, void* context);
bool Replay(const Stage& stage, const Plan& plan, void* r, void* s, Original original, void* context);
void Sample(U out[WordCount]);
// Avoidance bitset (model+0xC4, shared at combat+0x90 and avoid+0x90) enlargement hooks and counters:
//   * AllocBitset (NTW2_BIND_AVOID_ALLOC, replaces 0x50748A in CLONE_AVOID_506C00): allocates kAvoidBitsetBytes
//     through 0x10D3140, zeroes the full block, records the block pointer and increments the alloc counter.
//   * FreeBitset (NTW2_BIND_AVOID_FREE, replaces 0x51F40E in CLONE_AVOID_51F150): frees the block through 0x126E016
//     with the matched allocation size (kAvoidBitsetBytes if enlarged, else the passed size) and increments the free counter.
//   * AdoptModelBitset: upgrades an already-constructed model's stock 0x2004-byte block at model+0xC4 (+0xC8/+0xCC->+0x90)
//     in place to kAvoidBitsetBytes (copying the existing 0x2004 bytes and zeroing the tail) when the model ctor ran before
//     the call-site hook was installed; idempotent when the block is already enlarged.
void ConfigureAvoidHooks(U image_delta);
void ResetAvoidCounters();
void ClearAvoidRegistry();
void* __cdecl AllocBitset(U requested_bytes);
void __cdecl FreeBitset(void* block, U passed_bytes);
bool IsEnlargedBitset(U bits_address);
bool AdoptModelBitset(U model);
void SampleAvoidWords(U& allocs, U& frees, U& serial_refusals, U& active_bytes);

// Decision helpers, exposed for the mapped-original oracle. Addresses are live (relocated).
namespace port {
struct XZ { float x, z; };
XZ SlotPosition(U slot);                                   // 0x80E9D0 (x, z of the result)
bool Gate(U agent);                                        // 0x64CAA0
bool Blocks(const Stage&, U agent, U other);               // 0x817160
bool BlocksUnlessLinked(const Stage&, U agent, U other);   // 0x667260
uint16_t Heading(const Stage&, U agent);                   // 0x80B5B0
bool Far(U agent, float x, float z);                       // 0x81BD10
float Facing(const Stage&, U difference);                  // 0x7FA690 (low 16 bits)
void Facings(const Stage&, U r, U s, float out[4]);        // 0x7E4BB0
U Classify(const Stage&, U r, U s, bool& supported);       // 0x62F1A0 with mode 0
bool Available(U manager, U agent, U serial_cap = kStockAvoidSerialCap); // 0x6795D0
bool Overlap(const Stage&, U r, U s);                      // 0x7FA590
bool Avoid(const Stage&, U manager, U r, U s, bool& supported, U serial_cap = kStockAvoidSerialCap); // 0x664010
bool TrackerDistance(const Stage&, U a, U b);              // 0x52EDB0 distance gate
}
}
#endif
