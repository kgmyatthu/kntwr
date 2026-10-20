// --ai-standoff: AI attack-group stand-off destination (contract, engine facts and word layout: ntw2_group_standoff.h).
// Runs wherever the native 0x7C7DC0 runs (the planner's tactic service); engine memory is only read (under SEH), native 0x78B1C0 / 0x78B070 / 0x5646A0 are only called.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <string.h>
#include <windows.h>
#include "ntw2_group_standoff.h"
#include "core/ntw2_guard.h"

namespace ntw2_group_standoff {
using U = uint32_t;
volatile U words[kWords];

namespace {
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxUnits = 2048, kMaxMembers = 1024, kMaxGroup = 512, kTableSlots = 128;
constexpr float kCoordLimit = 16384.0f, kBig = 1e30f;
constexpr U kDumpSlot = 0x68, kCtrl = 0x88, kCtrlCount = 0x20, kCtrlList = 0x24, kCtrlBox = 0x50;

using ThisPtr = U(__fastcall*)(U, U);
using ThisFloat = float(__fastcall*)(U, U);
using RegionFn = float*(__fastcall*)(U, U, float*);

Targets target;
bool enabled;
float factor = 0.9f;

struct Entry { U tactic, evalTick, seenTick, used, valid, status; float px, pz, cx, cz; };
struct Gu { U unit, side, members; float cx, cz, radius; };
Entry table[kTableSlots];
Gu graph[kMaxUnits];
U graphCount;
volatile LONG busy;

inline void Bump(Word w, U by = 1) { words[w] += by; }
inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool Fin(float v) { return v == v && fabsf(v) < kCoordLimit; }

enum Status : U { StOk, StNoEnemy, StNoRange, StTactic, StUnreadable };

void CountStatus(U s) {
    switch (s) {
    case StNoEnemy: Bump(WFbNoEnemy); break;
    case StNoRange: Bump(WFbNoRange); break;
    case StTactic: Bump(WFbTactic); break;
    default: Bump(WFbUnreadable); break;
    }
}

// model -> M = [model+0xB0]; sides [M+0x88] x [M+0x84]; side: index [+0x10], armies [+0x24] x [+0x20]; army: units [+0xF4] x [+0xF0] (the engage census walk).
bool Gather(U model) {
    graphCount = 0;
    const U M = Rd(model + 0xB0);
    if (!Sane(M)) return false;
    const U sideCount = Rd(M + 0x84), sideArr = Rd(M + 0x88);
    if (!Sane(sideArr) || sideCount == 0 || sideCount > kMaxSides) return false;
    U n = 0;
    for (U si = 0; si < sideCount; ++si) {
        const U side = Rd(sideArr + 4 * si);
        if (!Sane(side)) continue;
        const U sideIdx = Rd(side + 0x10), armyCount = Rd(side + 0x20), armyArr = Rd(side + 0x24);
        if (armyCount > kMaxArmies || (armyCount && !Sane(armyArr))) return false;
        for (U ai = 0; ai < armyCount; ++ai) {
            const U army = Rd(armyArr + 4 * ai);
            if (!Sane(army)) continue;
            const U unitCount = Rd(army + 0xF0), unitArr = Rd(army + 0xF4);
            if (unitCount > kMaxUnits || (unitCount && !Sane(unitArr))) return false;
            for (U ui = 0; ui < unitCount; ++ui) {
                const U unit = Rd(unitArr + 4 * ui);
                if (!Sane(unit)) continue;
                const U members = Rd(unit + 0x2CC);
                const U F = Rd(unit + 0xADC);
                if (Rd(unit + 0xAA0) == 2 || members == 0 || !Sane(F)) continue;
                const float cx = RdF(F + 0x644), cz = RdF(F + 0x648), rad = RdF(F + 0x670);
                if (!Fin(cx) || !Fin(cz)) continue;
                if (n >= kMaxUnits) return false;
                Gu& g = graph[n++];
                g.unit = unit; g.side = sideIdx; g.members = members; g.cx = cx; g.cz = cz;
                g.radius = (rad == rad && rad > 0.0f && rad < 1000.0f) ? rad : 0.0f;
            }
        }
    }
    graphCount = n;
    return true;
}
const Gu* FindUnit(U unit) {
    for (U i = 0; i < graphCount; ++i) if (graph[i].unit == unit) return &graph[i];
    return nullptr;
}

// Enemy edge search state (POD, one evaluation).
struct Edge { float gx, gz, hx, hz, halfLat, bestT; };

// Smallest t along h of an enemy man inside the approach corridor; the unit is culled with its (loosened) formation radius, only units that can still improve bestT are walked.
void ConsiderUnit(const Gu& g, Edge& e) {
    const float dx = g.cx - e.gx, dz = g.cz - e.gz;
    const float t = dx * e.hx + dz * e.hz, lat = fabsf(dx * e.hz - dz * e.hx);
    const float rad = (g.radius * 1.25f > 60.0f ? g.radius * 1.25f : 60.0f) + 20.0f;
    if (t - rad >= e.bestT || lat - rad > e.halfLat || t + rad < 0.0f) return;
    const U arr = Rd(g.unit + 0x2D0);
    if (!Sane(arr)) return;
    const U n = g.members > kMaxMembers ? kMaxMembers : g.members;
    for (U i = 0; i < n; ++i) {
        const U m = Rd(arr + 4 * i);
        if (!Sane(m)) continue;
        const float x = RdF(m + 0x48), z = RdF(m + 0x50);
        if (!Fin(x) || !Fin(z)) continue;
        const float mx = x - e.gx, mz = z - e.gz;
        const float mt = mx * e.hx + mz * e.hz;
        if (mt < 0.0f || mt >= e.bestT) continue;
        if (fabsf(mx * e.hz - mz * e.hx) <= e.halfLat) e.bestT = mt;
    }
}

// Smallest weapon range of the group's members that can shoot, and the side of the group (the first member found in the graph). Returns the status.
Status GroupFacts(U tactic, U* sideOut, float* rangeOut) {
    const U ctrl = tactic + kCtrl;
    const U n = Rd(ctrl + kCtrlCount), arr = Rd(ctrl + kCtrlList);
    if (n == 0 || n > kMaxGroup || !Sane(arr)) return StTactic;
    float minR = kBig;
    bool haveSide = false;
    U side = 0;
    for (U i = 0; i < n; ++i) {
        const U u = Rd(arr + 4 * i);
        if (!Sane(u)) continue;
        if (!haveSide) { if (const Gu* g = FindUnit(u)) { side = g->side; haveSide = true; } }
        if (!Rd(u + 0xDC4)) continue; // no weapon record: 0x5646A0 returns 0 without reading further
        const float r = reinterpret_cast<ThisFloat>(static_cast<uintptr_t>(target.range))(u, 0);
        if (r > 0.0f && r < 5000.0f && r == r && r < minR) minR = r;
    }
    if (minR >= kBig) return StNoRange;
    if (!haveSide) return StUnreadable;
    *sideOut = side; *rangeOut = minR;
    return StOk;
}

// Enemy edge te along h (metres from G). Sources: the target region's own unit list (enemy side only), then every enemy unit near the native centre.
Status Evaluate(U tactic, U region, float gx, float gz, float hx, float hz, float w, float cx, float cz, float* teOut, float* rangeOut, bool* globalOut) {
    U side = 0; float range = 0.0f;
    // The graph is gathered first: GroupFacts maps the group's first member to its side through it.
    const U model = Rd(Rd(tactic + 4) + 8);
    if (!Sane(model) || !Gather(model)) return StUnreadable;
    const Status gs = GroupFacts(tactic, &side, &range);
    if (gs != StOk) return gs;
    *rangeOut = range;
    Edge e;
    e.gx = gx; e.gz = gz; e.hx = hx; e.hz = hz;
    e.halfLat = (w > 0.0f && w < 2000.0f ? w * 0.5f : 0.0f) + range;
    e.bestT = kBig;
    *globalOut = false;
    if (Sane(region)) {
        const U cnt = Rd(region + 0x5C), list = Rd(region + 0x60);
        if (cnt && cnt <= kMaxUnits && Sane(list)) {
            for (U i = 0; i < cnt; ++i) {
                const U u = Rd(list + 4 * i);
                const Gu* g = Sane(u) ? FindUnit(u) : nullptr;
                if (g && g->side != side) ConsiderUnit(*g, e);
            }
        }
    }
    if (e.bestT >= kBig) {
        *globalOut = true;
        for (U i = 0; i < graphCount; ++i) {
            const Gu& g = graph[i];
            if (g.side == side) continue;
            const float dx = g.cx - cx, dz = g.cz - cz;
            const float lim = kSearchM + g.radius;
            if (dx * dx + dz * dz <= lim * lim) ConsiderUnit(g, e);
        }
    }
    if (e.bestT >= kBig) return StNoEnemy;
    *teOut = e.bestT;
    return StOk;
}

Entry* Find(U tactic, U tick, bool* created) {
    U h = (tactic >> 4) * 2654435761u;
    Entry* slot = nullptr;
    *created = false;
    for (U i = 0; i < kTableSlots; ++i) {
        Entry& s = table[(h + i) & (kTableSlots - 1)];
        if (s.used && s.tactic == tactic) { s.seenTick = tick; return &s; }
        if (!slot && (!s.used || (tick > s.seenTick && tick - s.seenTick > kStaleTicks))) slot = &s;
        if (!s.used) break;
    }
    if (!slot) return nullptr;
    memset(slot, 0, sizeof(*slot));
    slot->tactic = tactic; slot->used = 1; slot->seenTick = tick;
    *created = true;
    return slot;
}

inline float Dist2(float ax, float az, float bx, float bz) { const float dx = ax - bx, dz = az - bz; return dx * dx + dz * dz; }

// Body of the gate: `out` holds the native region centre; on success it is replaced by the stand-off point.
void Apply(U tactic, float* out) {
    const U vt = Rd(tactic);
    if (!Sane(vt) || Rd(vt + kDumpSlot) != target.dump) { Bump(WFbTactic); return; }
    const U ctrl = tactic + kCtrl;
    const U box = Rd(ctrl + kCtrlBox);
    if (!Sane(box)) { Bump(WFbTactic); return; }
    const U model = Rd(Rd(tactic + 4) + 8);
    if (!Sane(model)) { Bump(WFbUnreadable); return; }
    const float gx = RdF(box + 8), gz = RdF(box + 0xC), w = RdF(box + 0x14), d = RdF(box + 0x18), fx = RdF(box + 0x24), fz = RdF(box + 0x28);
    const float cx = out[0], cz = out[1];
    if (!Fin(gx) || !Fin(gz) || !Fin(cx) || !Fin(cz) || !Fin(w) || !Fin(d) || !Fin(fx) || !Fin(fz)) { Bump(WFbUnreadable); return; }
    const float dx = cx - gx, dz = cz - gz, len = sqrtf(dx * dx + dz * dz);
    if (!(len > 1.0f)) { Bump(WFbNoEnemy); return; }
    const float hx = dx / len, hz = dz / len;
    const U tick = Rd(model + 0x58);
    bool created = false;
    Entry* e = Find(tactic, tick, &created);
    if (!e) { Bump(WTableFull); return; }
    if (created) Bump(WGroups);

    const bool moved = e->valid && Dist2(cx, cz, e->cx, e->cz) > kHystM * kHystM;
    const bool backwards = tick < e->evalTick;
    const bool due = !e->evalTick || backwards || tick - e->evalTick >= kRecheckTicks || (moved && tick - e->evalTick >= kFastTicks);
    if (due) {
        const U region = reinterpret_cast<ThisPtr>(static_cast<uintptr_t>(target.regionOf))(tactic, 0);
        float te = 0.0f, range = 0.0f;
        bool global = false;
        Bump(WRecomputes);
        const Status s = Evaluate(tactic, region, gx, gz, hx, hz, w, cx, cz, &te, &range, &global);
        e->evalTick = tick ? tick : 1; e->cx = cx; e->cz = cz; e->status = s;
        if (s == StOk) {
            if (global) Bump(WSrcGlobal);
            words[WLastRange] = static_cast<U>(range);
            const float lead = te - factor * range;
            const float pxN = gx + hx * lead, pzN = gz + hz * lead;
            if (!e->valid || Dist2(pxN, pzN, e->px, e->pz) > kHystM * kHystM) { e->px = pxN; e->pz = pzN; e->valid = 1; Bump(WPoints); }
            else Bump(WKept);
        } else e->valid = 0;
    }
    if (!e->valid) { CountStatus(e->status); return; }

    // Never behind the group, never beyond the native centre.
    const float frontDot = fx * hx + fz * hz;
    const float tmin = (frontDot > 0.0f ? frontDot : 0.0f) * d * 0.5f + kLeadM;
    if (tmin >= len) { Bump(WFbNoEnemy); return; }
    float tP = (e->px - gx) * hx + (e->pz - gz) * hz;
    bool hold = false;
    if (tP < tmin) { tP = tmin; hold = true; }
    if (tP > len) tP = len;
    const float px = gx + hx * tP, pz = gz + hz * tP;
    const float xmin = RdF(model + 0x84), zmin = RdF(model + 0x88), xmax = RdF(model + 0x8C), zmax = RdF(model + 0x90);
    if (!(xmin == xmin && zmin == zmin && xmax == xmax && zmax == zmax)) { Bump(WFbUnreadable); return; }
    if (!(px >= xmin && pz >= zmin && px < xmax && pz < zmax)) { Bump(WFbBounds); return; }
    out[0] = px; out[1] = pz;
    Bump(WApplied);
    if (hold) Bump(WHolds);
}

U patchedField[2];
bool patched;
bool PatchField(U site, U expected, U replacement) {
    unsigned char* p = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(site));
    const U field = site + 1;
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, PAGE_EXECUTE_READWRITE, &old)) return false;
    bool ok = false;
    __try {
        U current;
        memcpy(&current, p + 1, 4);
        if (p[0] == 0xE8 && current == expected) { memcpy(p + 1, &replacement, 4); U check; memcpy(&check, p + 1, 4); ok = check == replacement; }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    return ok;
}
}

void ResetRow() { for (U i = 0; i < kWords; ++i) words[i] = 0; }
void Configure(bool on, U k100, const Targets& t) {
    ResetRow();
    memset(table, 0, sizeof(table));
    graphCount = 0;
    busy = 0;
    target = t;
    enabled = on;
    factor = static_cast<float>(k100) * 0.01f;
}
void Snapshot(volatile U* out) { for (U i = 0; i < kWords; ++i) out[i] = words[i]; }

float* __fastcall RegionGate(U self, U, float* out) {
    float* const r = reinterpret_cast<RegionFn>(static_cast<uintptr_t>(target.regionCentre))(self, 0, out);
    Bump(WCalls);
    if (!enabled || !r) return r;
    if (InterlockedExchange(&busy, 1) != 0) { Bump(WFbUnreadable); return r; }
    const float x = r[0], z = r[1];
    ++ntw2::probeDepth;
    __try { Apply(self, r); }
    __except (EXCEPTION_EXECUTE_HANDLER) { r[0] = x; r[1] = z; Bump(WFaults); }
    --ntw2::probeDepth;
    InterlockedExchange(&busy, 0);
    return r;
}

bool InstallRedirect(U delta, U gate) {
    const U sites[2] = { kSiteFirst + delta, kSiteReset + delta };
    const U original = kRegionCentreOriginal + delta;
    for (int i = 0; i < 2; ++i) { // both must be the expected call before either is touched
        const unsigned char* p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(sites[i]));
        bool ok = false;
        __try { U cur; memcpy(&cur, p + 1, 4); ok = p[0] == 0xE8 && cur == original - (sites[i] + 5); } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
        if (!ok) return false;
    }
    for (int i = 0; i < 2; ++i) {
        patchedField[i] = gate - (sites[i] + 5);
        if (!PatchField(sites[i], original - (sites[i] + 5), patchedField[i])) {
            for (int j = 0; j < i; ++j) PatchField(sites[j], patchedField[j], original - (sites[j] + 5));
            return false;
        }
    }
    patched = true;
    return true;
}

bool RemoveRedirect(U delta) {
    if (!patched) return true;
    const U sites[2] = { kSiteFirst + delta, kSiteReset + delta };
    const U original = kRegionCentreOriginal + delta;
    bool ok = true;
    for (int i = 0; i < 2; ++i) ok = PatchField(sites[i], patchedField[i], original - (sites[i] + 5)) && ok;
    if (ok) patched = false;
    return ok;
}
}
