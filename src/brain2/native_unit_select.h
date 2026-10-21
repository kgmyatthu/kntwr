#pragma once
#include <stdint.h>
// Unit selection rules of the per-unit brain slices (src/brain2/native_unit_policy.*; originally the puppet probe's,
// removed from the runtime): ONE copy of the infantry-table pin, the member admissibility rule, the unit
// qualification rule and the first-appearance registry scan. Owner thread only; every read is a plain load (callers
// wrap a scan in SEH and treat a fault as "nothing selected").
//
// Selection (analysis/checkpoints/PuppetProbe.md): units in first-appearance order over the primary registry
// (manager+24C count, +250 data; deterministic for a replay, never pointer order) of records whose class table is one of
// the eleven pinned infantry tables (Rules::Pin). A unit qualifies when it has 1..512 non-null members (U+2CC/+2D0), no
// artillery (+0C 0x6F4660) or cavalry (+0C 0x602EB0) member and at least one admissible member: an admitted infantry
// table, unit backlink +1F0 == the unit, no crew list (+66C), no enabled crew node 0x133AE34 and a registry serial +2C
// below 2^20 (the gates' serial bitsets cover that range only). Every other member (officer/ensign classes, crew, foreign
// backlink, serial out of range) stays native and is counted by the caller.
namespace kntwr_unit_select {
using U = uint32_t;
// Infantry class tables of the 13-table family (native-loco-consumer-seams.md 3.1) whose slots +08/+0C/+130/+134/+188/
// +1A4/+1A8/+108/+B8/+FC equal 0x1333714's on the approved image (verified by Rules::Pin; a mismatching table is
// dropped). 0x132B7D8 (+0C thunk 0x6F50F0) and 0x132BA04 (+0C wrapper 0x602EB0) are not admitted.
constexpr U kInfantryTableCount = 11;
constexpr U kInfantryTables[kInfantryTableCount] = {0x1333714, 0x13473D0, 0x13475E4, 0x13477F8, 0x13479B4, 0x1347B70,
                                                   0x1347D2C, 0x1347EE8, 0x13480A4, 0x1348260, 0x134841C};
constexpr U kMaxUnitMembers = 512, kSerialBits = 1u << 20, kMaxArmies = 15, kNoArmy = 15, kMaxExamined = 4096;
constexpr U kSeenHash = 2 * kMaxExamined;
static_assert(!(kSeenHash & (kSeenHash - 1)), "power-of-two examined set");

// Multiplicative hash folded so aligned pointers (zero low bits) still spread over the low slot bits.
inline U HashSlot(U key, U mask) { const U h = key * 2654435761u; return (h ^ (h >> 15)) & mask; }

// First failing unit-level reason (RejectMemberCount .. RejectNoInfantry are 1..5), so a caller may index a reason
// counter row with them.
enum Reject : U { RejectNone, RejectMemberCount, RejectNullMember, RejectArtillery, RejectCavalry, RejectNoInfantry };
// Why a member of a qualified unit is not selected (first failing test, in this order).
enum MemberClass : U { MemberSelected, MemberOtherClass, MemberBacklink, MemberSerialOutOfRange, MemberCrew };

struct Rules {
    U delta;                      // image_base - 0x400000
    U classVt;                    // runtime address of 0x1333714 (the reference table)
    U crewVt;                     // runtime address of the crew node table 0x133AE34
    U tableCount;                 // pinned tables
    U tables[kInfantryTableCount];// their runtime addresses
    U V(U va) const { return va + delta; }
    // Pins the reference table (+0C must be the brain step 0x66CE00) and every other infantry table whose pinned slots
    // equal it. False: bad image base or the reference table differs.
    bool Pin(U imageBase);
    bool IsInfantry(U table) const {
        for (U i = 0; i < tableCount; ++i) if (tables[i] == table) return true;
        return false;
    }
    bool Admissible(U member, U unit) const;
    MemberClass Classify(U member, U unit) const;
    // Unit-level qualification. On RejectNone: n = member count, list = U+2D0, admissible = admissible members (>= 1).
    // The attached-container entry U+1F4 is never touched.
    Reject Qualify(U unit, U& n, U& list, U& admissible) const;
};

// Registry scan in first-appearance order. `accept(ctx, unit, ordinal, army)` is called once per distinct unit handle
// (backlink +1F0 of an infantry-table record) while fewer than `maxSelected` units were selected and fewer than
// kMaxExamined were examined; `ordinal` = examined index (0-based), `army` = index of A+1F8 in first-appearance order over
// the scan (kNoArmy for none/unknown). It returns true when it selected the unit. Returns the number of infantry-table
// records seen in the registry (all of them, also after the limits). Not reentrant (file-static examined set).
using AcceptFn = bool (*)(void* ctx, U unit, U ordinal, U army);
U Scan(const Rules& rules, U manager, AcceptFn accept, void* ctx, U maxSelected);
} // namespace kntwr_unit_select
