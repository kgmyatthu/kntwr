// Shared unit selection rules (native_unit_select.h). Owner thread only; plain loads, callers guard with SEH.
#include "native_unit_select.h"
#include <string.h>

namespace kntwr_unit_select {
namespace {
static_assert(sizeof(void*) == 4, "unit selection reads the Win32 game image");
// Approved-image preferred VAs (SHA-256 13fcab62...).
constexpr U kClassTable = 0x1333714, kCrewNode = 0x133AE34, kBrainStep = 0x66CE00;
constexpr U kArtilleryStep = 0x6F4660, kCavalryStep = 0x602EB0;
inline U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
U g_seen[kSeenHash];
// Examined set of one scan; false when the handle was already examined.
bool FirstSight(U handle) {
    for (U slot = HashSlot(handle, kSeenHash - 1);; slot = (slot + 1) & (kSeenHash - 1)) {
        if (!g_seen[slot]) { g_seen[slot] = handle; return true; }
        if (g_seen[slot] == handle) return false;
    }
}
} // namespace

bool Rules::Pin(U imageBase) {
    tableCount = 0; delta = 0; classVt = crewVt = 0;
    if (!imageBase) return false;
    delta = imageBase - 0x400000;
    classVt = V(kClassTable); crewVt = V(kCrewNode);
    if (D(classVt + 0xC) != V(kBrainStep)) return false;
    // Alternative infantry tables: admitted only when every slot the brain slices and the native paths rely on is
    // identical to 0x1333714's.
    static const U kPinnedSlots[] = {0x08, 0x0C, 0x130, 0x134, 0x188, 0x1A4, 0x1A8, 0x108, 0xB8, 0xFC};
    for (U t : kInfantryTables) {
        bool same = true;
        for (U slot : kPinnedSlots) same = same && D(V(t) + slot) == D(classVt + slot);
        if (same) tables[tableCount++] = V(t);
    }
    return tableCount != 0;
}

bool Rules::Admissible(U m, U unit) const {
    return IsInfantry(D(m)) && D(m + 0x1F0) == unit && !D(m + 0x66C) && !(B(m + 0x2C4) == 1 && D(m + 0x22C) == crewVt) &&
           D(m + 0x2C) < kSerialBits; // the gates' serial bitsets cover serials < 2^20 only
}

MemberClass Rules::Classify(U m, U unit) const {
    if (Admissible(m, unit)) return MemberSelected;
    if (!IsInfantry(D(m))) return MemberOtherClass;
    if (D(m + 0x1F0) != unit) return MemberBacklink;
    if (D(m + 0x2C) >= kSerialBits) return MemberSerialOutOfRange;
    return MemberCrew;
}

Reject Rules::Qualify(U unit, U& n, U& list, U& admissible) const {
    n = D(unit + 0x2CC); list = D(unit + 0x2D0); admissible = 0;
    if (!n || n > kMaxUnitMembers || !list) return RejectMemberCount;
    Reject reason = RejectNone;
    for (U i = 0; i < n; ++i) {
        const U m = D(list + 4 * i);
        if (!m) { reason = RejectNullMember; break; }
        const U step = D(D(m) + 0xC) - delta;
        if (step == kArtilleryStep) { reason = RejectArtillery; break; }
        if (step == kCavalryStep) { reason = RejectCavalry; break; }
        admissible += Admissible(m, unit);
    }
    if (reason == RejectNone && !admissible) reason = RejectNoInfantry;
    return reason;
}

U Scan(const Rules& rules, U manager, AcceptFn accept, void* ctx, U maxSelected) {
    const U count = D(manager + 0x24C), data = D(manager + 0x250);
    if (!count || !data) return 0;
    memset(g_seen, 0, sizeof(g_seen));
    U seenCount = 0, selected = 0, armies[kMaxArmies], armyCount = 0, infantry = 0;
    for (U i = 0; i < count; ++i) {
        const U a = D(data + 4 * i);
        if (!a || !rules.IsInfantry(D(a))) continue;
        ++infantry;
        if (selected >= maxSelected || seenCount >= kMaxExamined) continue;
        const U unit = D(a + 0x1F0), army = D(a + 0x1F8);
        U k = 0;
        while (k < armyCount && armies[k] != army) ++k;
        if (army && k == armyCount && armyCount < kMaxArmies) armies[armyCount++] = army;
        if (!unit || !FirstSight(unit)) continue;
        ++seenCount;
        if (accept(ctx, unit, seenCount - 1, army ? (k < kMaxArmies ? k : kNoArmy) : kNoArmy)) ++selected;
    }
    return infantry;
}
} // namespace kntwr_unit_select
