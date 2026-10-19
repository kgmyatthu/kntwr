#ifndef NTW2_MOUNTED_OFFICER_H
#define NTW2_MOUNTED_OFFICER_H
#include <stdint.h>

// --mounted-officer (ntw2_config::va_watch_flags NTW2_MOUNTED_OFFICER / NTW2_MOUNTED_OFFICER_WIDEN; analysis/native-mounted-officer.md): an infantry unit whose
// unit_stats_land row names a mount (mount_model / mount_entity / mount_animations_table, `horse` = 0) gets exactly ONE mount agent for its officer.  USER-APPROVED
// GAMEPLAY FEATURE (opt-in, never implied by --features all; replays desync vs vanilla).  Data decides which units qualify: there is no class list here.
//
// Native structure [proven by disasm, Steam image 13fcab62..., details in the analysis note]:
//   * The unit constructor 0x51B7D0 embeds a copy of the unit's stats record at unit+0x20 (0x514FB0, source = *[army entry]).  That record is built by the row
//     loader 0xEDB840 -> 0xE8CFF0 from the unit_stats_land row, and the three mount references are resolved from the row's mount columns WITHOUT looking at `horse`
//     (row+0x10, copied separately to unit+0x34): [unit+0x88] = the `mounts` table row of mount_model (0 when the column is empty), [unit+0x8C] = the battle
//     entity of mount_entity (0 when empty), &unit+0x90 = the mount_animations_table key (a 12-byte string object {length, ?, wchar_t*}) plus the mount
//     armour/health words behind it.  So a row with the five mount columns filled and horse = 0 yields resolved references and [unit+0x34] == 0.
//   * The mount loop 0x51C22E..0x51C462 is gated by `[unit+0x34] > 0 && [unit+0x204] > 0`; for infantry it falls through to the engine section 0x51C462.
// Mechanism: the constructor is cloned (CLONE_UNIT_CTOR: the original bytes with the host gate MO_GATE inserted before the gate test 0x51C22E) and the single call
// 0x531340 -> 0x51B7D0 is redirected to the clone while the feature is installed (monitor start, before any battle loads; restored at stop).  The gate runs the
// stock one-mount loop body for the unit's officer (men[0] = [unit+0x208][0]) and leaves the stock gate test to skip the stock loop ([unit+0x34] stays 0):
//   alloc 0x69C (0x10D3140); serial = [ESP+0x5C]++ (the entity-counter slot of the constructor frame); anim ctx = 0xF548D0(ECX = [unit+0x88]+0xC, [[unit+0x14]+8]+0x50);
//   pose = 0x80B670(); model ctx = 0x531E30(ECX = constructor argument 1); mount = 0x59EED0(ECX = memory; model ctx, [unit+0x8C], unit, &unit+0x90, pose, anim ctx,
//   serial, men-per-mount 1); attach 0x655B20(ECX = officer; mount); append the mount to the equipment vector (+0x228/+0x22C/+0x230) and the member vector
//   (+0x2C8/+0x2CC/+0x2D0) with the stock grow policy; radius MAXSS [unit+0x2EC] <- [mount+0x58] ONLY with the widen sub-switch (default: the infantry spacing is kept).
// Gate: [unit+0x34] == 0, [unit+0x38] == 0 (no guns: artillery rows carry horse-team mount columns with horse = 0), [unit+0x204] > 0, men[0] is the unit's first personality ([unit+0x27C] > 0 and [[unit+0x280]] == men[0]: the officer, spawned first by
// 0x5307E0), and the references are RESOLVED: [unit+0x88] != 0, [unit+0x8C] != 0, anim table key length in 1..0xFFF with a non-null character pointer.  Everything
// else is counted and left native.  The loader's own validity rule is "empty column => 0; non-empty column with an unknown key => logged, reference 0"
// (0xEDB6A0/0xEDB700 return 0), and a non-empty mount_model with an unknown key makes the whole unit row fail (0xEDBC42); both are covered by the predicate.
namespace ntw2_mounted_officer {
// mounted_officer_words (ntw2_status::mounted_officer_words, NTW2_MOUNTED_OFFICER_LABELS):
//  0 version  1 flags (bit0 gate armed, bit1 widen)  2 units_seen  3 units_eligible ([unit+0x34]==0 and men>0)  4 officer_first (eligible with men[0] == first
//  personality)  5 skipped_has_mounts ([unit+0x34]>0, stock loop)  6 skipped_no_refs (eligible, references unresolved)  7 skipped_no_officer (resolved, men[0] is not
//  the first personality)  8 mounts_created  9 attach_failures (mount has no rider after 0x655B20)  10 alloc_failures  11 serial_last  12 last_rider_vtable
//  13 skipped_has_guns ([unit+0x38] > 0: artillery; their mount columns name the gun-team horses, the engine section uses them)  14 faults (SEH, the unit was left native)  15 patch_installed (the 0x531340 redirect is live)
constexpr uint32_t kWords = 16, kVersion = 1;
enum Word : uint32_t {
    WVersion, WFlags, WUnitsSeen, WEligible, WOfficerFirst, WSkippedHasMounts, WSkippedNoRefs, WSkippedNoOfficer, WMountsCreated, WAttachFailures,
    WAllocFailures, WSerialLast, WLastRiderVtable, WSkippedHasGuns, WFaults, WPatchInstalled
};
extern volatile uint32_t words[kWords];

// Unit offsets.
constexpr uint32_t kUnitEnv = 0x14, kUnitMenPerMount = 0x30, kUnitMounts = 0x34, kUnitGuns = 0x38, kUnitMountRow = 0x88, kUnitMountEntity = 0x8C, kUnitMountStats = 0x90, kUnitMountAnimPtr = 0x98,
                   kUnitMenCap = 0x200, kUnitMenCount = 0x204, kUnitMenData = 0x208, kUnitPersCount = 0x27C, kUnitPersData = 0x280, kUnitRadius = 0x2EC,
                   kUnitEquipVec = 0x228, kUnitMemberVec = 0x2C8;
constexpr uint32_t kMountRadius = 0x58, kMountRiders = 0x66C, kMountBytes = 0x69C;

struct Targets {
    uint32_t alloc;     // 0x10D3140 cdecl (bytes) -> memory or 0
    uint32_t vecAlloc;  // 0x444B40 cdecl (count, 0) -> element array
    uint32_t vecFree;   // 0xFF7EF0 cdecl (pointer)
    uint32_t modelCtx;  // 0x531E30 thiscall ECX = constructor argument 1 -> model ctx
    uint32_t animCtx;   // 0xF548D0 thiscall ECX = [unit+0x88]+0xC, one stack argument ([[unit+0x14]+8]+0x50), callee pops 4 -> anim ctx
    uint32_t pose;      // 0x80B670 cdecl () -> pose ctx
    uint32_t ctor;      // 0x59EED0 thiscall ECX = memory, eight stack arguments, callee pops 0x20 -> the mount
    uint32_t attach;    // 0x655B20 thiscall ECX = rider, one stack argument (mount), callee pops 4
};
constexpr Targets kNative = {0x10D3140, 0x444B40, 0xFF7EF0, 0x531E30, 0xF548D0, 0x80B670, 0x59EED0, 0x655B20};
constexpr uint32_t kCallSite = 0x531340, kCtor = 0x51B7D0, kGate = 0x51C22E;

// Arms the gate (targets are image-relocated VAs); `widen` also raises the unit radius.  Zeroes the row, then sets version/flags/widen.
void Configure(bool widen, const Targets& targets);
void ResetRow();                        // monitor start: zero the row before any poll of the new session
void Snapshot(volatile uint32_t* out);  // out[kWords]
// The inserted gate (__stdcall, three arguments, callee pops 12): unit = EBP, ctorArg = the constructor's first argument, serialSlot = &[ESP+0x5C].
void __stdcall Gate(uint32_t unit, uint32_t ctorArg, uint32_t* serialSlot);

// Redirect of the single call `call 0x51B7D0` at 0x531340 to the clone (rel32 field at 0x531341); `delta` = image delta from the preferred base.  Install verifies the
// original bytes, writes the four displacement bytes (lifting and restoring the page protection, flushing the instruction cache) and reads them back; Remove restores
// the original displacement when the current one is ours.  Both return false on any mismatch/failure without writing a partial change.
bool InstallRedirect(uint32_t delta, uint32_t cloneEntry);
bool RemoveRedirect(uint32_t delta);
}
#endif
