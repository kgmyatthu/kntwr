// --ai-hold-slots: keep the posture mark 4 on an AI attack group's eligible members until the group arrives (contract, engine facts and word layout: ntw2_group_hold.h).
// Runs wherever the native 0x7C8820 runs (the planner's tactic update); engine memory is only read (SEH-bracketed), the members' posture marks are the one write.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <string.h>
#include <windows.h>
#include "ntw2_group_hold.h"
#include "core/ntw2_guard.h"

namespace ntw2_group_hold {
using U = uint32_t;
volatile U words[kWords];

namespace {
constexpr U kEntries = 512, kMaxMembers = 512;
constexpr U kMark = 0xB34, kAliveState = 0xAA0, kLiveCount = 0x2CC, kClassPtr = 0x2C, kCategory = 0x1C, kSubclass = 0x20, kFormation = 0xADC, kMeleeWord = 0x764;
constexpr U kMembersCount = 0x6C, kMembersArray = 0x70, kBox = 0xD8, kDestX = 0x7E8, kDestZ = 0x7EC;
constexpr float kFiniteLimit = 1.0e9f;

using ThisVoid = void(__fastcall*)(U, U);

struct Entry { U tactic, last, arrived, used; };

Targets target;
Mode mode;
Entry table[kEntries];

inline void Bump(Word w, U by = 1) { words[w] += by; }
inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool Fin(float v) { return v == v && fabsf(v) < kFiniteLimit; }

// model tick of the tactic: [[[t+4]+8]+0x58] (as the formup module).
bool ModelTick(U tactic, U* tick) {
    const U a = Rd(tactic + 4);
    if (!Sane(a)) return false;
    const U model = Rd(a + 8);
    if (!Sane(model)) return false;
    *tick = Rd(model + 0x58);
    return true;
}

// Latch entry of the tactic. A tactic not seen for > kStaleTicks model ticks starts again unarrived. With create == false an absent tactic yields null and nothing is created or counted;
// with create == true null means the table is full.
Entry* Find(U tactic, U tick, bool create) {
    const U h = (tactic >> 4) * 2654435761u;
    Entry* spare = nullptr;
    for (U i = 0; i < kEntries; ++i) {
        Entry& e = table[(h + i) & (kEntries - 1)];
        if (e.used && e.tactic == tactic) {
            if (tick > e.last && tick - e.last > kStaleTicks) e.arrived = 0;
            e.last = tick;
            return &e;
        }
        if (!spare && (!e.used || (tick > e.last && tick - e.last > kStaleTicks))) spare = &e;
        if (!e.used) break;
    }
    if (!create || !spare) return nullptr;
    spare->tactic = tactic; spare->used = 1; spare->last = tick; spare->arrived = 0;
    Bump(WGroups);
    return spare;
}

// Native arrival test of 0x7A6960 (see the header). Returns false when the box / destination cannot be measured (*measured = false).
bool Arrived(U tactic, bool* measured) {
    *measured = false;
    const U box = Rd(tactic + kBox);
    if (!Sane(box)) return false;
    const float bx = RdF(box + 8), bz = RdF(box + 0xC), w = RdF(box + 0x14), d = RdF(box + 0x18);
    const float ax = RdF(box + 0x1C), az = RdF(box + 0x20), fx = RdF(box + 0x24), fz = RdF(box + 0x28);
    const float px = RdF(tactic + kDestX), pz = RdF(tactic + kDestZ);
    if (!Fin(bx) || !Fin(bz) || !Fin(w) || !Fin(d) || !Fin(ax) || !Fin(az) || !Fin(fx) || !Fin(fz) || !Fin(px) || !Fin(pz)) return false;
    if (!(w > 0.0f) || !(d > 0.0f)) return false;
    *measured = true;
    const float dx = px - bx, dz = pz - bz;
    if (fabsf(az * dz + ax * dx) <= w * 0.5f && fabsf(fz * dz + dx * fx) <= d * 0.5f) return true;
    const float ex = px - (d * fx * 0.5f + bx), ez = pz - (d * fz * 0.5f + bz);
    return ex * ex + ez * ez < 2500.0f;
}

// Re-mark the eligible members 1 -> 4. Marks already written stay if a fault interrupts the walk (the caller counts it).
void HoldMembers(U tactic) {
    const U n = Rd(tactic + kMembersCount), arr = Rd(tactic + kMembersArray);
    if (n > words[WMaxMembers]) words[WMaxMembers] = n;
    if (!n || !Sane(arr)) return;
    const U count = n < kMaxMembers ? n : kMaxMembers;
    const bool infantryOnly = mode == ModeInfantry;
    for (U i = 0; i < count; ++i) {
        const U u = Rd(arr + 4 * i);
        if (!Sane(u)) continue;
        if (Rd(u + kAliveState) == 2 || Rd(u + kLiveCount) == 0) { Bump(WDeadSkipped); continue; }
        if (Rd(u + kMark) != 1) { Bump(WSkippedMark); continue; }
        const U cls = Rd(u + kClassPtr);
        if (!Sane(cls)) { Bump(WExemptClass); continue; }
        const U cat = Rd(cls + kCategory), sub = Rd(cls + kSubclass);
        if (cat == 1 || (infantryOnly && (cat != 2 || sub == 17 || sub == 22))) { Bump(WExemptClass); continue; }
        const U f = Rd(u + kFormation);
        if (!Sane(f) || Rd(f + kMeleeWord) != 0) { Bump(WExemptMelee); continue; }
        *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(u + kMark)) = 4;
        Bump(WMarked);
    }
}

// Post-processing after the native marking. POD locals only (runs inside __try).
void Post(U tactic) {
    Bump(WCalls);
    if (target.scope && !target.scope(GetCurrentThreadId())) Bump(WOutOfScope);
    if (!Sane(tactic)) return;
    const U state = Rd(tactic + kStateOffset);
    U tick = 0;
    const bool haveTick = ModelTick(tactic, &tick);
    if (state != 4) { // leaving / outside state 4: forget a latched arrival, never create an entry
        if (haveTick) { if (Entry* old = Find(tactic, tick, false)) old->arrived = 0; }
        return;
    }
    Bump(WState4);
    if (!haveTick) { Bump(WUnmeasured); return; } // no model tick: native marks stay
    Entry* e = Find(tactic, tick, true);
    if (!e) { Bump(WTableFull); return; }          // no latch entry: native marks stay
    if (e->arrived) { Bump(WReleasedCalls); return; }
    bool measured = false;
    const bool arrived = Arrived(tactic, &measured);
    if (!measured) { Bump(WUnmeasured); return; }
    if (arrived) { e->arrived = 1; Bump(WArrivals); Bump(WReleasedCalls); return; }
    Bump(WHeldCalls);
    HoldMembers(tactic);
}

U patchedField;
bool patched;
bool PatchField(U site, U expected, U replacement) {
    unsigned char* p = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(site));
    void* const field = reinterpret_cast<void*>(static_cast<uintptr_t>(site + 1));
    DWORD old = 0;
    if (!VirtualProtect(field, 4, PAGE_EXECUTE_READWRITE, &old)) return false;
    bool ok = false;
    __try {
        U current;
        memcpy(&current, p + 1, 4);
        if (p[0] == 0xE8 && current == expected) { memcpy(p + 1, &replacement, 4); U check; memcpy(&check, p + 1, 4); ok = check == replacement; }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    DWORD ignored = 0;
    VirtualProtect(field, 4, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    return ok;
}
} // namespace

void ResetRow() { for (U i = 0; i < kWords; ++i) words[i] = 0; }
void Configure(Mode m, const Targets& t) {
    ResetRow();
    memset(table, 0, sizeof(table));
    target = t;
    mode = m;
}
void Snapshot(volatile U* out) { for (U i = 0; i < kWords; ++i) out[i] = words[i]; }

void __fastcall MarkGate(U tactic, U) {
    reinterpret_cast<ThisVoid>(static_cast<uintptr_t>(target.marking))(tactic, 0);
    if (mode == ModeOff) return;
    ++ntw2::probeDepth; // every fault below is an expected, caught one: not a crash capture (CrashVeh)
    __try { Post(tactic); }
    __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); }
    --ntw2::probeDepth;
}

bool InstallRedirect(U delta, U gate) {
    const U site = kCallSite + delta, original = kMarking + delta;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(site));
    bool ok = false;
    __try { U cur; memcpy(&cur, p + 1, 4); ok = p[0] == 0xE8 && cur == original - (site + 5); } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    if (!ok) return false;
    patchedField = gate - (site + 5);
    if (!PatchField(site, original - (site + 5), patchedField)) return false;
    patched = true;
    return true;
}

bool RemoveRedirect(U delta) {
    if (!patched) return true;
    const U site = kCallSite + delta, original = kMarking + delta;
    if (!PatchField(site, patchedField, original - (site + 5))) return false;
    patched = false;
    return true;
}
} // namespace ntw2_group_hold
