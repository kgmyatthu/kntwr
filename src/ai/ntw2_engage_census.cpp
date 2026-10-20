// --engage-census: read-only observer of AI infantry engagement depth (contract, engine facts and word layout: ntw2_engage_census.h).
// Everything runs on the tick-owner thread inside one SEH bracket; engine memory is only read, native predicates are only called.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <string.h>
#include <windows.h>
#include "ntw2_engage_census.h"
#include "core/ntw2_guard.h"

namespace ntw2_engage_census {
using U = uint32_t;

namespace {
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxUnits = 1024, kMemberPool = 262144, kStateSlots = 1024, kMaxMembers = 1024, kStaleTicks = 600;
constexpr float kCoordLimit = 16384.0f;
constexpr U kTypeHalt = 1, kTypeFire = 2, kMaxBattleFaults = 64;

using ThisBool = unsigned char(__fastcall*)(U, U);
using ThisFloat = float(__fastcall*)(U, U);
using ThisPtr = U(__fastcall*)(U, U);
using ThisPtrOut = U(__fastcall*)(U, U, U);

struct UnitState { U unit, lastSeen; unsigned char prevMoving, prevFiring, used, pad; U ticksStopped; };
struct Gathered { U unit, side, ai, cx_bits, cz_bits, members, first, formation; float cx, cz, minX, maxX, minZ, maxZ; int loaded; U poolOff, poolCount; };

U words[kWords];
bool enabled, disabled;
U delta, imageLo, imageSize, lastModel, battleFaults, gCount;
UnitState table[kStateSlots];
Gathered units[kMaxUnits];
float pool[kMemberPool * 2];
U poolUsed;
float deepRatio[kRowsPerSet];

inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Good(float v) { return v == v && fabsf(v) < kCoordLimit; }
inline U Bits(float f) { U u; memcpy(&u, &f, 4); return u; }
inline U V(U preferred) { return preferred + delta; }
inline void Bump(Word w) { ++words[w]; }

// Pre-validation: a native predicate must never fault (a first-chance AV is also a crash-recorder event). Each check mirrors exactly what the callee dereferences;
// anything the checks cannot prove is caught by the per-unit SEH bracket (silent through ntw2::probeDepth).
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool InImage(U p) { return p - imageLo < imageSize; }
// Virtual-call target through `obj`: vtable in the image, slot target in the image.
inline bool Virtual(U obj, U slot, U* fn) {
    if (!Sane(obj)) return false;
    const U vt = Rd(obj);
    if (!InImage(vt)) return false;
    *fn = Rd(vt + slot);
    return InImage(*fn);
}
// 0x55AFE0 (obj = unit) / 0x55C2E0 (obj = formation object): `idx = [obj+0x460]; if (!idx) return 0; o = [obj+0x418+idx*8]; (*vt[slot])()`; the slot array holds idx 1..8.
bool SlotCallSafe(U obj, U slot) {
    const U idx = Rd(obj + 0x460);
    if (idx == 0) return true;
    U fn;
    return idx <= 8 && Virtual(Rd(obj + 0x418 + 8 * idx), slot, &fn);
}
// 0x55C320 (is_moving): idx = [U+0xAE8]; idx != 0 -> o = [U+0xADC+idx*4], vt[+0xA4]; idx == 0 -> 0x55C2E0 on [U+0xADC] (SlotCallSafe, vt[+0xC]).
bool MovingSafe(U unit) {
    const U idx = Rd(unit + 0xAE8);
    U fn;
    if (idx == 0) { const U f = Rd(unit + 0xADC); return Sane(f) && SlotCallSafe(f, 0xC); }
    return idx <= 2 && Virtual(Rd(unit + 0xADC + 4 * idx), 0xA4, &fn);
}
// 0x55C9A0(ECX = &vector, key) -> 0x57ACA0 scans {count [+0xC], data [+0x10]} of 0x2C-byte records.
bool VectorSafe(U vec) {
    const U count = Rd(vec + 0xC), data = Rd(vec + 0x10);
    return count == 0 || (count <= 4096 && Sane(data) && Sane(data + count * 0x2C - 1));
}
// 0x5646A0 (missile range): returns 1 = safe to call, 0 = the native returns 0 without further reads, -1 = unproven (skip, never call).
int RangeSafe(U unit) {
    const U d = Rd(unit + 0xDC4);
    if (!d) return 0;                                   // 0x53EFE0: no weapon record -> false -> 0
    if (!Sane(d)) return -1;
    const U kind = Rd(d + 0x24);
    if (!Sane(kind)) return -1;
    (void)Rd(kind + 0x10); (void)Rd(d + 0x60);
    const U cls = Rd(unit + 0x2C);
    if (!Sane(cls)) return -1;                          // 0x55ABF0 / 0x55AB80
    (void)Rd(cls + 0x1C);
    if (!VectorSafe(unit + 0xDAC)) return -1;           // 0x55C9A0 on U+0xDAC (0x55C2A0 and the final branch)
    const U f = Rd(unit + 0xADC);
    if (!Sane(f)) return -1;
    const U p = Rd(f + 0x62C + 0x11C);                  // 0x56AE70(ECX = F+0x62C)
    if (p) {
        if (!Sane(p)) return -1;
        const U q = Rd(p + 0x14);
        if (!Sane(q)) return -1;
        if (*reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(q + 0x231))) {
            // bonus branch: [[[[U+0x14]+8]]+0x2804C]+0x10 -> 0xE20560 (lazily CREATES [e+0x6CC] when null: refuse so the census stays read-only) -> [[e+0x6CC]+0x1E70+0x5C]
            const U a = Rd(unit + 0x14);
            if (!Sane(a)) return -1;
            const U b = Rd(a + 8);
            if (!Sane(b)) return -1;
            const U c = Rd(b);
            if (!Sane(c)) return -1;
            const U dd = Rd(c + 0x2804C);
            if (!Sane(dd)) return -1;
            const U e = Rd(dd + 0x10);
            if (!Sane(e)) return -1;
            const U g = Rd(e + 0x6CC);
            if (!Sane(g)) return -1;
            (void)Rd(g + 0x1E70 + 0x5C);
        }
    } else if (!VectorSafe(unit + 0xDAC)) return -1;
    return 1;
}

UnitState* Find(U unit, U tick) {
    U h = (unit >> 4) * 2654435761u;
    UnitState* slot = nullptr;
    for (U i = 0; i < kStateSlots; ++i) {
        UnitState& s = table[(h + i) & (kStateSlots - 1)];
        if (s.used && s.unit == unit) return &s;
        if (!slot && (!s.used || s.lastSeen + kStaleTicks < tick)) slot = &s;
        if (!s.used) break;
    }
    if (!slot) { ++words[WTableFull]; return nullptr; }
    if (!slot->used) ++words[WTableUsed];
    memset(slot, 0, sizeof(*slot));
    slot->unit = unit; slot->used = 1;
    slot->prevMoving = 2; // unseen: the first observation sets it without an event
    return slot;
}

bool LoadMembers(Gathered& g) {
    if (g.loaded) return g.loaded > 0;
    g.loaded = -1;
    const U arr = Rd(g.unit + 0x2D0);
    U n = g.members > kMaxMembers ? kMaxMembers : g.members;
    if (!arr || poolUsed + n > kMemberPool) { ++words[WTableFull]; return false; }
    float* out = pool + 2 * poolUsed;
    U kept = 0;
    g.minX = g.minZ = 1e30f; g.maxX = g.maxZ = -1e30f;
    for (U i = 0; i < n; ++i) {
        const U m = Rd(arr + 4 * i);
        if (!m) { ++words[WBadMember]; continue; }
        const float x = RdF(m + 0x48), z = RdF(m + 0x50);
        if (!Good(x) || !Good(z)) { ++words[WBadMember]; continue; }
        out[2 * kept] = x; out[2 * kept + 1] = z; ++kept;
        if (x < g.minX) g.minX = x; if (x > g.maxX) g.maxX = x;
        if (z < g.minZ) g.minZ = z; if (z > g.maxZ) g.maxZ = z;
    }
    g.poolOff = poolUsed; g.poolCount = kept; poolUsed += kept;
    g.loaded = kept ? 1 : -1;
    return kept != 0;
}

inline float BoxDist2(const Gathered& g, float x, float z) {
    const float dx = x < g.minX ? g.minX - x : (x > g.maxX ? x - g.maxX : 0.0f);
    const float dz = z < g.minZ ? g.minZ - z : (z > g.maxZ ? z - g.maxZ : 0.0f);
    return dx * dx + dz * dz;
}

void Hist(U base, U bins, float ratioOrMetres, float step) {
    if (ratioOrMetres < 0.0f) { ++words[base + kHistWords - 1]; return; }
    const float f = ratioOrMetres / step;
    const U bin = f >= static_cast<float>(bins) ? bins : static_cast<U>(f);
    ++words[base + bin];
}

void StoreRow(U* row, const U* src) { for (U i = 0; i < kRowWords; ++i) row[i] = src[i]; }

void Record(U type, const U* row, float ratio) {
    if (type == kTypeHalt) {
        if (words[WFirstCount] < kRowsPerSet) { StoreRow(&words[kFirstRows + kRowWords * words[WFirstCount]], row); ++words[WFirstCount]; }
        if (ratio >= 0.0f) {
            if (words[WDeepCount] < kRowsPerSet) {
                const U k = words[WDeepCount]++;
                deepRatio[k] = ratio; StoreRow(&words[kDeepRows + kRowWords * k], row);
            } else {
                U worst = 0;
                for (U i = 1; i < kRowsPerSet; ++i) if (deepRatio[i] > deepRatio[worst]) worst = i;
                if (ratio < deepRatio[worst]) { deepRatio[worst] = ratio; StoreRow(&words[kDeepRows + kRowWords * worst], row); }
            }
        }
    }
    StoreRow(&words[kRingRows + kRowWords * (words[WEventsTotal] % kRowsPerSet)], row);
    ++words[WEventsTotal];
}

// Graph walk into units[0..gCount); POD locals only (it runs inside __try).
void Gather(U model) {
    gCount = 0;
    const U M = Rd(model + 0xB0);
    if (!M) { ++words[WBadGraph]; return; }
    const U sideCount = Rd(M + 0x84), sideArr = Rd(M + 0x88);
    if (!sideArr || sideCount == 0 || sideCount > kMaxSides) { ++words[WBadGraph]; return; }
    U n = 0, aiSides = 0;
    for (U si = 0; si < sideCount; ++si) {
        const U side = Rd(sideArr + 4 * si);
        if (!side) { ++words[WBadGraph]; continue; }
        const U ai = Rd(side + 0xC) ? 1u : 0u, sideIdx = Rd(side + 0x10);
        aiSides += ai;
        const U armyCount = Rd(side + 0x20), armyArr = Rd(side + 0x24);
        if (armyCount > kMaxArmies || (armyCount && !armyArr)) { ++words[WBadGraph]; continue; }
        for (U ai2 = 0; ai2 < armyCount; ++ai2) {
            const U army = Rd(armyArr + 4 * ai2);
            if (!army) { ++words[WBadGraph]; continue; }
            const U unitCount = Rd(army + 0xF0), unitArr = Rd(army + 0xF4);
            if (unitCount > kMaxUnits || (unitCount && !unitArr)) { ++words[WBadGraph]; continue; }
            for (U ui = 0; ui < unitCount; ++ui) {
                const U unit = Rd(unitArr + 4 * ui);
                if (!unit) { ++words[WBadGraph]; continue; }
                const U members = Rd(unit + 0x2CC);
                if (Rd(unit + 0xAA0) == 2 || members == 0) { ++words[WInactiveUnits]; continue; }
                const U F = Rd(unit + 0xADC);
                if (!F) { ++words[WBadGraph]; continue; }
                const float cx = RdF(F + 0x644), cz = RdF(F + 0x648);
                if (!Good(cx) || !Good(cz)) { ++words[WBadMember]; continue; }
                if (n >= kMaxUnits) { ++words[WTableFull]; continue; }
                Gathered& g = units[n++];
                g.unit = unit; g.side = sideIdx; g.ai = ai; g.members = members; g.formation = F;
                g.cx = cx; g.cz = cz; g.loaded = 0; g.poolOff = g.poolCount = 0;
            }
        }
    }
    words[WAiSidesLast] = aiSides;
    gCount = n;
}
// One AI unit (units[i], n gathered); POD locals only (it runs inside __try). Native predicates are called only after the pre-validation above.
void Observe(U i, U n, U modelTick, U* eligible) {
    {
        Gathered& u = units[i];
        if (!u.ai) return;
        const int rs = RangeSafe(u.unit);
        float range = 0.0f;
        if (rs < 0) { Bump(WNativeSkipped); return; }
        if (rs > 0) { range = reinterpret_cast<ThisFloat>(static_cast<uintptr_t>(V(0x5646A0)))(u.unit, 0); ++words[WNativeCalls]; }
        if (!(range > 0.0f) || !Good(range)) { ++words[WNoMissile]; return; }
        if (!MovingSafe(u.unit) || !SlotCallSafe(u.unit, 0x10)) { Bump(WNativeSkipped); return; }
        ++*eligible; ++words[WAiUnits];
        const bool moving = reinterpret_cast<ThisBool>(static_cast<uintptr_t>(V(0x55C320)))(u.unit, 0) != 0;
        const bool firing = reinterpret_cast<ThisBool>(static_cast<uintptr_t>(V(0x55AFE0)))(u.unit, 0) == 1;
        words[WNativeCalls] += 2;
        UnitState* st = Find(u.unit, modelTick);
        // Nearest enemy unit by centre, and the three nearest for the member search.
        float d2[3] = {1e30f, 1e30f, 1e30f}; int idx[3] = {-1, -1, -1}; U enemies = 0;
        for (U j = 0; j < n; ++j) {
            if (units[j].side == u.side) continue;
            ++enemies;
            const float dx = units[j].cx - u.cx, dz = units[j].cz - u.cz, d = dx * dx + dz * dz;
            if (d < d2[2]) {
                if (d < d2[1]) {
                    d2[2] = d2[1]; idx[2] = idx[1];
                    if (d < d2[0]) { d2[1] = d2[0]; idx[1] = idx[0]; d2[0] = d; idx[0] = static_cast<int>(j); }
                    else { d2[1] = d; idx[1] = static_cast<int>(j); }
                } else { d2[2] = d; idx[2] = static_cast<int>(j); }
            }
        }
        if (enemies == 0 || idx[0] < 0) {
            ++words[WEnemyless];
            if (st) { st->prevMoving = moving; st->prevFiring = firing; st->lastSeen = modelTick; st->ticksStopped = moving ? 0 : (st->ticksStopped < 0xFFFFFFFFu ? st->ticksStopped + 1 : st->ticksStopped); }
            return;
        }
        words[WEnemyUnitsLast] = enemies;
        const float dC = sqrtf(d2[0]);
        float dM = -1.0f, dMe = -1.0f;
        if (dC < 4.0f * range + 100.0f && LoadMembers(u)) {
            float best = 1e30f, bestE = 1e30f;
            for (int k = 0; k < 3; ++k) {
                if (idx[k] < 0) continue;
                Gathered& e = units[idx[k]];
                if (!LoadMembers(e)) continue;
                const float* em = pool + 2 * e.poolOff;
                for (U a = 0; a < e.poolCount; ++a) {
                    const float dx = em[2 * a] - u.cx, dz = em[2 * a + 1] - u.cz, d = dx * dx + dz * dz;
                    if (d < bestE) bestE = d;
                }
                const float* om = pool + 2 * u.poolOff;
                for (U b = 0; b < u.poolCount; ++b) {
                    const float ox = om[2 * b], oz = om[2 * b + 1];
                    if (BoxDist2(e, ox, oz) >= best) continue;
                    for (U a = 0; a < e.poolCount; ++a) {
                        const float dx = em[2 * a] - ox;
                        const float dxx = dx * dx;
                        if (dxx >= best) continue;
                        const float dz = em[2 * a + 1] - oz, d = dxx + dz * dz;
                        if (d < best) best = d;
                    }
                }
            }
            if (best < 1e29f) { dM = sqrtf(best); ++words[WDmComputed]; }
            if (bestE < 1e29f) dMe = sqrtf(bestE);
        }
        const U b34 = Rd(u.unit + 0xB34);
        if (moving && dM >= 0.0f && dM < 1.5f * range) {
            const float r = dM / range;
            U bin = static_cast<U>(r / 0.05f); if (bin >= kMovingBins) bin = kMovingBins - 1;
            ++words[kMovingAll + bin];
            ++words[(b34 == 0 ? kMovingB0 : b34 == 1 ? kMovingB1 : b34 == 4 ? kMovingB4 : kMovingOther) + bin];
            ++words[WMovingInRange];
        }
        const float nearLimit = 3.0f * range + 2.0f * RdF(u.formation + 0x670);
        const bool inReach = dC < nearLimit;
        if (st && st->prevMoving != 2) {
            U type = 0;
            if (st->prevMoving && !moving && inReach) type = kTypeHalt;
            else if (!st->prevFiring && firing && inReach) type = kTypeFire;
            if (type) {
                const float ratio = dM >= 0.0f ? dM / range : -1.0f;
                if (type == kTypeHalt) { ++words[WHalts]; Hist(kHaltRatio, kHistBins, ratio, 0.1f); Hist(kHaltMetres, kHistBins, dM, 10.0f); }
                else { ++words[WFireStarts]; Hist(kFireRatio, kHistBins, ratio, 0.1f); }
                const U cnt = Rd(u.unit + 0x930), idxRow = Rd(u.unit + 0x934);
                U vt = 0xFFFFFFFFu;
                float destD = -1.0f, destEnemyD = -1.0f;
                U flags = 0;
                if (cnt != 0 && cnt <= 10 && idxRow < cnt) {
                    const U row = u.unit + 0x398 + 0x90 * idxRow;
                    const U table2 = Rd(row);
                    vt = table2 ? table2 - delta : 0;
                    const bool rowOk = table2 && InImage(table2) && InImage(Rd(table2 + 0x38)) && InImage(Rd(table2 + 0x2C)) && InImage(Rd(table2 + 0x30));
                    if (table2 && !rowOk) Bump(WNativeSkipped);
                    if (rowOk) {
                        const U pose = reinterpret_cast<ThisPtr>(static_cast<uintptr_t>(Rd(table2 + 0x38)))(row, 0);
                        words[WNativeCalls] += 1;
                        if (reinterpret_cast<ThisBool>(static_cast<uintptr_t>(Rd(table2 + 0x2C)))(row, 0) & 0xFF) flags |= 1u;
                        if (reinterpret_cast<ThisBool>(static_cast<uintptr_t>(Rd(table2 + 0x30)))(row, 0) & 0xFF) flags |= 2u;
                        words[WNativeCalls] += 2;
                        if (Sane(pose) && (!Rd(pose + 0x10) || Sane(Rd(pose + 0x10)))) {
                            float out[3] = {0, 0, 0};
                            const U r = reinterpret_cast<ThisPtrOut>(static_cast<uintptr_t>(V(0x80E9D0)))(pose, 0, static_cast<U>(reinterpret_cast<uintptr_t>(out)));
                            words[WNativeCalls] += 1;
                            const float dx = RdF(r), dz = RdF(r + 8);
                            if (Good(dx) && Good(dz)) {
                                flags |= 4u;
                                const float ux = dx - u.cx, uz = dz - u.cz, ex = dx - units[idx[0]].cx, ez = dz - units[idx[0]].cz;
                                destD = sqrtf(ux * ux + uz * uz); destEnemyD = sqrtf(ex * ex + ez * ez);
                            }
                        }
                    }
                }
                U r2[kRowWords] = {};
                r2[0] = modelTick; r2[1] = u.unit; r2[2] = type; r2[3] = Bits(dC); r2[4] = Bits(dM); r2[5] = Bits(dMe); r2[6] = Bits(range);
                r2[7] = b34; r2[8] = cnt; r2[9] = idxRow; r2[10] = vt; r2[11] = Rd(Rd(u.unit + 0x2C) + 0x1C); r2[12] = u.members;
                r2[13] = st->ticksStopped; r2[14] = units[idx[0]].unit; r2[15] = u.side; r2[16] = Bits(destD); r2[17] = Bits(destEnemyD); r2[18] = flags;
                Record(type, r2, ratio);
            }
        }
        if (st) {
            st->ticksStopped = moving ? 0 : (st->ticksStopped < 0xFFFFFFFFu ? st->ticksStopped + 1 : st->ticksStopped);
            st->prevMoving = moving; st->prevFiring = firing; st->lastSeen = modelTick;
        }
    }
}

bool ObserveGuarded(U i, U n, U modelTick, U* eligible) {
    __try { Observe(i, n, modelTick, eligible); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool GatherGuarded(U model) {
    __try { Gather(model); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void Fault(bool perUnit) {
    ++words[WFaults]; ++battleFaults; words[WBattleFaults] = battleFaults;
    if (perUnit) ++words[WFaultsPerUnit];
    if (battleFaults > kMaxBattleFaults) { disabled = true; words[WFlags] |= 2u; }
}
}  // namespace

void Reset(bool enable, U imageDelta, U base, U size) {
    memset(words, 0, sizeof(words));
    memset(table, 0, sizeof(table));
    memset(deepRatio, 0, sizeof(deepRatio));
    enabled = enable; disabled = false; delta = imageDelta; imageLo = base; imageSize = size; lastModel = 0; poolUsed = 0; battleFaults = 0; gCount = 0;
    words[WVersion] = kVersion; words[WDelta] = imageDelta;
    words[WFlags] = enable ? 1u : 0u;
}

void Tick(U model, U modelTick) {
    if (!enabled || disabled) return;
    LARGE_INTEGER t0, t1, f;
    QueryPerformanceCounter(&t0);
    ++ntw2::probeDepth; // every fault below is an expected, caught one: not a crash capture (CrashVeh)
    if (model != lastModel) {
        memset(table, 0, sizeof(table)); words[WTableUsed] = 0;
        if (lastModel) ++words[WModelChanges];
        lastModel = model; words[WFlags] &= ~2u; disabled = false; battleFaults = 0; words[WBattleFaults] = 0;
    }
    poolUsed = 0;
    ++words[WTicks]; words[WLastModelTick] = modelTick;
    if (!GatherGuarded(model)) Fault(false);
    else {
        U eligible = 0;
        for (U i = 0; i < gCount && !disabled; ++i)
            if (!ObserveGuarded(i, gCount, modelTick, &eligible)) Fault(true);
        words[WAiUnitsLast] = eligible;
    }
    --ntw2::probeDepth;
    QueryPerformanceCounter(&t1); QueryPerformanceFrequency(&f);
    const U us = static_cast<U>((t1.QuadPart - t0.QuadPart) * 1000000ll / f.QuadPart);
    words[WCostUsTotal] += us;
    if (us > words[WCostUsMax]) words[WCostUsMax] = us;
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}
}  // namespace ntw2_engage_census
