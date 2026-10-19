// --engage-census: read-only observer of AI infantry engagement depth (contract, engine facts and word layout: ntw2_engage_census.h).
// Everything runs on the tick-owner thread inside one SEH bracket; engine memory is only read, native predicates are only called.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <string.h>
#include <windows.h>
#include "ntw2_engage_census.h"

namespace ntw2_engage_census {
using U = uint32_t;

namespace {
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxUnits = 1024, kMemberPool = 262144, kStateSlots = 1024, kMaxMembers = 1024, kStaleTicks = 600;
constexpr float kCoordLimit = 16384.0f;
constexpr U kTypeHalt = 1, kTypeFire = 2;

using ThisBool = unsigned char(__fastcall*)(U, U);
using ThisFloat = float(__fastcall*)(U, U);
using ThisPtr = U(__fastcall*)(U, U);
using ThisPtrOut = U(__fastcall*)(U, U, U);

struct UnitState { U unit, lastSeen; unsigned char prevMoving, prevFiring, used, pad; U ticksStopped; };
struct Gathered { U unit, side, ai, cx_bits, cz_bits, members, first, formation; float cx, cz, minX, maxX, minZ, maxZ; int loaded; U poolOff, poolCount; };

U words[kWords];
bool enabled, disabled;
U delta, lastModel;
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

// The whole observation; POD locals only (it runs inside __try).
void Body(U model, U modelTick) {
    if (model != lastModel) {
        memset(table, 0, sizeof(table)); words[WTableUsed] = 0;
        if (lastModel) ++words[WModelChanges];
        lastModel = model; words[WFlags] &= ~2u; disabled = false;
    }
    poolUsed = 0;
    ++words[WTicks]; words[WLastModelTick] = modelTick;
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
    U aiEligible = 0;
    for (U i = 0; i < n; ++i) {
        Gathered& u = units[i];
        if (!u.ai) continue;
        // Native predicates (thiscall, ECX = unit; never hooked).
        const float range = reinterpret_cast<ThisFloat>(static_cast<uintptr_t>(V(0x5646A0)))(u.unit, 0);
        ++words[WNativeCalls];
        if (!(range > 0.0f) || !Good(range)) { ++words[WNoMissile]; continue; }
        ++aiEligible; ++words[WAiUnits];
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
            continue;
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
                    if (table2) {
                        const U pose = reinterpret_cast<ThisPtr>(static_cast<uintptr_t>(Rd(table2 + 0x38)))(row, 0);
                        words[WNativeCalls] += 1;
                        if (reinterpret_cast<ThisBool>(static_cast<uintptr_t>(Rd(table2 + 0x2C)))(row, 0) & 0xFF) flags |= 1u;
                        if (reinterpret_cast<ThisBool>(static_cast<uintptr_t>(Rd(table2 + 0x30)))(row, 0) & 0xFF) flags |= 2u;
                        words[WNativeCalls] += 2;
                        if (pose) {
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
    words[WAiUnitsLast] = aiEligible;
}
}  // namespace

void Reset(bool enable, U imageDelta) {
    memset(words, 0, sizeof(words));
    memset(table, 0, sizeof(table));
    memset(deepRatio, 0, sizeof(deepRatio));
    enabled = enable; disabled = false; delta = imageDelta; lastModel = 0; poolUsed = 0;
    words[WVersion] = kVersion; words[WDelta] = imageDelta;
    words[WFlags] = enable ? 1u : 0u;
}

void Tick(U model, U modelTick) {
    if (!enabled || disabled) return;
    LARGE_INTEGER t0, t1, f;
    QueryPerformanceCounter(&t0);
    __try { Body(model, modelTick); }
    __except (EXCEPTION_EXECUTE_HANDLER) { ++words[WFaults]; disabled = true; words[WFlags] |= 2u; }
    QueryPerformanceCounter(&t1); QueryPerformanceFrequency(&f);
    const U us = static_cast<U>((t1.QuadPart - t0.QuadPart) * 1000000ll / f.QuadPart);
    words[WCostUsTotal] += us;
    if (us > words[WCostUsMax]) words[WCostUsMax] = us;
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}
}  // namespace ntw2_engage_census
