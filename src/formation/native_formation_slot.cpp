// See native_formation_slot.h.  Every block cites the native VA it ports.
#include "native_formation_slot.h"
#include <cmath>
#include <cstring>

namespace ntw_formation {
namespace {

inline bool Finite(float v) {
    uint32_t b;
    std::memcpy(&b, &v, 4);
    return (b & 0x7FFFFFFFu) < 0x7F800000u;
}
inline uint32_t AbsBits(float v) {
    uint32_t b;
    std::memcpy(&b, &v, 4);
    return b & 0x7FFFFFFFu;
}
inline void Swap3(Entry& a, Entry& b) {   // 0x18F1349
    Entry t = a;
    a = b;
    b = t;
}

// 0x57CBC0 followed by the cost refresh the callers perform; Entry-like temporaries.
struct Pair {
    uint32_t man, slot;
    float cost;
};

// 0x5373F0/0x502770 recompute: cost = def; if (man) cost = slot ? PairCost : noSlot
inline float Recost(const SlotInput& in, const Constants& c, float def, float nos, uint32_t man, uint32_t slot) {
    float cost = def;
    if (man != kNone) cost = (slot != kNone) ? PairCost(in, c, man, slot) : nos;
    return cost;
}

// 0x57CBC0(T1, ctx, T2): exchange men, refresh both costs with the same rule.
inline void SwapEval(const SlotInput& in, const Constants& c, float def, float nos, Pair& t1, Pair& t2) {
    uint32_t m = t1.man;
    t1.man = t2.man;
    t2.man = m;
    t1.cost = Recost(in, c, def, nos, t1.man, t1.slot);
    t2.cost = Recost(in, c, def, nos, t2.man, t2.slot);
}

struct ModCtx {                            // 0x18F0200 output block
    uint32_t a = kNone, b = kNone, c = kNone;  // markers 1,2,0 -> ctx+0, +4, +8
    uint32_t left = kNone, right = kNone;      // ctx+0xC, +0x10 (slot indices)
    uint32_t slots = 0;                        // ctx+0x14
};

// 0x18F0200
bool PreHook(const SlotInput& in, const Constants& c, ModCtx& ctx) {
    ctx = ModCtx();
    if (!in.modEligible) return false;
    if (in.slots != in.men) return false;                       // 0x18F0277
    if (in.men < 2 || in.men > c.maxModMen) return false;       // 0x18F0280/0x18F0289
    ctx.slots = in.men;
    for (uint32_t i = 0; i < in.men; ++i) {                      // 0x18F02B7 loop
        uint32_t k = in.manMarker[i];
        if (k <= 2) {
            if (k == 0) ctx.c = i;
            else if (k == 1) ctx.a = i;
            else ctx.b = i;
        }
    }
    if (ctx.a == kNone && ctx.b == kNone) return false;         // 0x18F02E9
    ctx.left = ctx.right = 0;
    const uint16_t angle0 = in.slotAngle[0];
    const float dirx = in.angleTable[2u * angle0];
    const float dirz = in.angleTable[2u * angle0 + 1u];
    const float x0 = in.slotX[0], z0 = in.slotZ[0];
    if (!Finite(x0) || !Finite(z0)) return false;
    float minCross = 0.0f, maxCross = 0.0f;
    for (uint32_t j = 0; j < in.men; ++j) {                      // 0x18F0367 loop
        if (in.slotAngle[j] != angle0) return false;
        const float dx = in.slotX[j] - x0;
        const float dz = in.slotZ[j] - z0;
        const float along = dx * dirx + dz * dirz;
        if (!Finite(along)) return false;
        if (AbsBits(along) <= 0x3E800000u) {                     // 'ja' skips |along| > 0.25
            const float cross = dx * dirz - dz * dirx;
            if (!Finite(cross)) return false;
            if (!(cross >= minCross)) { minCross = cross; ctx.left = j; }
            if (cross > maxCross) { maxCross = cross; ctx.right = j; }
        }
    }
    return ctx.left != ctx.right;
}

void SwapMarker(const SlotInput& in, const ModCtx& ctx, Entry* data, uint32_t n, uint32_t man, uint32_t slot) { // 0x18F12EC
    if (man == kNone) return;
    Entry* em = nullptr;
    Entry* es = nullptr;
    for (uint32_t i = 0; i < n; ++i) {            // last match wins, as in the native loop
        if (data[i].man == man) em = &data[i];
        if (data[i].slot == slot) es = &data[i];
    }
    if (!em || !es) return;
    const uint32_t m = es->man;
    if (m == ctx.a || m == ctx.b || !in.manAnchored[m]) {
        const uint32_t t = em->man;
        em->man = es->man;
        es->man = t;
    }
}

}  // namespace

float PairCost(const SlotInput& in, const Constants& c, uint32_t man, uint32_t slot) {   // 0x5281D0
    const float dx = in.slotX[slot] - in.manX[man];
    const float dz = in.slotZ[slot] - in.manZ[man];
    const float d2 = dx * dx + dz * dz;
    if (d2 > c.zero) {
        const float inv = c.one / std::sqrt(d2);
        const uint16_t a = in.manAngle[man];
        const float t0 = in.angleTable[2u * a];
        const float t1 = in.angleTable[2u * a + 1u];
        const float nx = dx * inv;
        const float nz = dz * inv;
        float dot = t1 * nz + t0 * nx;
        dot = (dot < c.one) ? dot : c.one;                    // minss dot, 1.0
        return (c.one - dot) * c.pairWeight + d2;
    }
    return d2;
}

uint8_t Solver(const SlotInput& in, const Constants& c, float def, float nos, Entry* begin, Entry* end,
               uint32_t limit, float thr, uint32_t* list, uint32_t* iterationsRun) {  // 0x502770
    uint32_t ln = 0;
    for (Entry* p = begin; p != end; ++p) {                 // 0x5027B0
        p->cost = def;
        if (p->man != kNone) p->cost = (p->slot != kNone) ? PairCost(in, c, p->man, p->slot) : nos;
        list[ln++] = static_cast<uint32_t>(p - begin);
    }
    uint32_t iter = 0;
    uint8_t done = 0;
    while (!(limit != 0 && iter >= limit)) {                // 0x502887
        Entry* worst = nullptr;
        uint32_t widx = 0;
        float worstCost = def;
        if (ln == 0) {                                      // 0x502BC2
            done = 1;
            ++iter;
            break;
        }
        for (uint32_t i = 0; i < ln; ++i) {                 // 0x5028C0
            Entry* e = begin + list[i];
            if (e->man != kNone) {
                const float cst = e->cost;
                if (thr > cst && (worst == nullptr || cst > worstCost)) {
                    worst = e;
                    worstCost = cst;
                    widx = i;
                }
            }
        }
        if (!worst) {                                       // 0x502BBE
            done = 1;
            ++iter;
            break;
        }
        bool swapped = false;
        if (limit == 0) {                                   // first-improvement pass 0x502910
            for (uint32_t u = 0; u < ln; ++u) {
                if (u == widx) continue;
                Entry* o = begin + list[u];
                const float cA = (worst->slot != kNone) ? worst->cost : def;
                const float cB = (o->slot != kNone) ? o->cost : def;
                if (thr > cA && thr > cB) {
                    const float orig = cB + cA;
                    Pair t1{worst->man, worst->slot, worst->cost};
                    Pair t2{o->man, o->slot, o->cost};
                    SwapEval(in, c, def, nos, t1, t2);
                    const float nA = (t1.slot != kNone) ? t1.cost : def;
                    const float nB = (t2.slot != kNone) ? t2.cost : def;
                    if (orig > nB + nA) {
                        const uint32_t m = worst->man;      // 0x5029DF
                        worst->man = o->man;
                        o->man = m;
                        worst->cost = Recost(in, c, def, nos, worst->man, worst->slot);
                        o->cost = Recost(in, c, def, nos, o->man, o->slot);
                        swapped = true;
                        break;
                    }
                }
            }
        } else {                                            // best-improvement pass 0x502A43
            Entry* best = nullptr;
            float bestDelta = def;
            for (uint32_t u = 0; u < ln; ++u) {
                if (u == widx) continue;
                Entry* o = begin + list[u];
                const float oc = o->cost;
                if (thr > oc) {
                    const float cA = (worst->slot != kNone) ? worst->cost : def;
                    const float cB = (o->slot != kNone) ? oc : def;
                    const float orig = cB + cA;
                    Pair t1{worst->man, worst->slot, worst->cost};
                    Pair t2{o->man, o->slot, oc};
                    SwapEval(in, c, def, nos, t1, t2);
                    const float nA = (t1.slot != kNone) ? t1.cost : def;
                    const float nB = (t2.slot != kNone) ? t2.cost : def;
                    const float delta = (nB + nA) - orig;
                    if (bestDelta > delta) {
                        best = o;
                        bestDelta = delta;
                    }
                }
            }
            if (best) {                                     // 0x502B33
                const uint32_t m = worst->man;
                worst->man = best->man;
                best->man = m;
                worst->cost = Recost(in, c, def, nos, worst->man, worst->slot);
                best->cost = Recost(in, c, def, nos, best->man, best->slot);
                swapped = true;
            }
        }
        if (!swapped) list[widx] = list[--ln];              // 0x502B98
        ++iter;
    }
    if (iterationsRun) *iterationsRun = iter;
    return done;
}

void RefreshStat(const SlotInput& in, const Constants& c, const Entry* order, uint32_t count, SlotResult* out) {  // 0x557C80
    float sum = 0.0f;
    uint32_t used = 0;
    for (uint32_t k = 0; k < count; ++k) {                  // formation man k (order[k].man, or man k when null) vs slot k
        const uint32_t m = order ? order[k].man : k;
        if (!in.manSkipDistance[m]) {
            ++used;
            const float dx = in.manX[m] - in.slotX[k];
            const float dz = in.manZ[m] - in.slotZ[k];
            sum = sum + std::sqrt(dx * dx + dz * dz);
        }
    }
    out->distanceCount = used;
    out->distanceSum = sum;
    out->refreshZero = 0;
    if (used != 0) {
        const float avg = sum / static_cast<float>(static_cast<double>(used));
        out->refreshZero = !(c.refreshDistance > avg) ? 1 : 0;
    }
}

int AssignUnit(const SlotInput& in, const Constants& c, Entry* entries, uint32_t* scratch, SlotResult* out) {
    SlotResult local;
    SlotResult& r = out ? *out : local;
    r = SlotResult();
    if (in.men == 0) return kNoOp;                          // 0x5373FA
    if (in.slots < in.men) return kBadInput;
    if (in.layoutIndex >= 0 && static_cast<uint32_t>(in.layoutIndex) >= in.men) return kBadInput;

    ModCtx ctx;
    const bool preFlag = (in.layoutIndex == -1) && PreHook(in, c, ctx);  // 0x18F0A3F
    r.modPreHook = preFlag ? 1 : 0;

    uint32_t cnt = 0, pushes = 0;
    const bool unitFlag = in.unitFlag != 0;
    auto push = [&](uint32_t man) { entries[cnt] = Entry{man, cnt, 0.0f}; ++cnt; };
    if (!unitFlag) {                                        // 0x53743B
        for (uint32_t i = 0; i < in.men; ++i)
            if (in.manAnchored[i]) { push(i); ++pushes; }
    }
    if (in.layoutIndex >= 0 && static_cast<uint32_t>(in.layoutIndex) < in.slots) {  // 0x537499
        const uint32_t i = static_cast<uint32_t>(in.layoutIndex);
        if (!in.manAnchored[i]) { push(i); ++pushes; }
    }
    for (uint32_t i = 0; i < in.men; ++i)                   // 0x537500
        if (!in.manAnchored[i] && static_cast<int32_t>(i) != in.layoutIndex) push(i);

    if (in.men > pushes) {                                  // 0x537613
        const float thr = in.flagParam ? c.thresholdFlag1 : c.thresholdFlag0;
        const uint32_t limit = static_cast<uint32_t>(in.flagParam) ^ 1u;
        if (!preFlag) {                                     // 0x18F0D00 shim passes through to 0x502770
            r.solverDone = Solver(in, c, c.defaultCost, c.noSlotCost, entries + pushes, entries + cnt, limit, thr, scratch,
                                  &r.solverIterations);
            r.solverRan = 1;
        }
        if (unitFlag) {                                     // 0x53766A
            for (uint32_t i = 0; i < in.men; ++i)
                if (in.manAnchored[i] && static_cast<int32_t>(i) != in.layoutIndex) push(i);
        }
    }

    if (preFlag) {                                          // 0x18F1200 post-hook
        const uint32_t n = cnt;
        if (n != 0) {
            if (n == ctx.slots) {
                SwapMarker(in, ctx, entries, n, ctx.a, ctx.left);
                SwapMarker(in, ctx, entries, n, ctx.b, ctx.right);
            }
            Entry* esi = entries;
            Entry* edi = entries;
            Entry* end = entries + n;
            do {
                if (in.manAnchored[esi->man]) { Swap3(*esi, *edi); ++edi; }
                ++esi;
            } while (esi < end);
            if (edi < end) {
                const float thr = in.flagParam ? c.thresholdFlag1 : c.thresholdFlag0;
                r.solverDone = Solver(in, c, c.defaultCost, c.noSlotCost, edi, end, static_cast<uint32_t>(in.flagParam) ^ 1u,
                                      thr, scratch, &r.solverIterations);
                r.solverRan = 1;
            }
            for (uint32_t i = 0; i < n; ++i)                // slot indices must form a permutation of [0,n)
                if (entries[i].slot >= n) return kBadInput;
            esi = entries;
            for (;;) {                                      // 0x18F12B8 cycle sort by slot index
                Entry* tgt = entries + esi->slot;
                if (tgt != esi) {
                    Swap3(*esi, *tgt);
                } else {
                    ++esi;
                    if (esi >= end) break;
                }
            }
        }
    }

    r.entryCount = cnt;
    RefreshStat(in, c, entries, cnt, &r);
    return kOk;
}

namespace {
inline size_t Align16(size_t v) { return (v + 15u) & ~static_cast<size_t>(15u); }
}  // namespace

size_t ArenaBytes(uint32_t men, uint32_t slots) {
    size_t n = 0;
    n += Align16(4u * men) * 2;             // manX, manZ
    n += Align16(2u * men);                 // manAngle
    n += Align16(men) * 3;                  // anchored, marker, skip
    n += Align16(4u * slots) * 2;           // slotX, slotZ
    n += Align16(2u * slots);               // slotAngle
    n += Align16(sizeof(Entry) * men);      // entries
    n += Align16(4u * men);                 // scratch
    return n;
}

void BindArena(void* memory, uint32_t men, uint32_t slots, ArenaViews* v) {
    auto* p = static_cast<uint8_t*>(memory);
    auto take = [&p](size_t bytes) { uint8_t* r = p; p += Align16(bytes); return r; };
    v->manX = reinterpret_cast<float*>(take(4u * men));
    v->manZ = reinterpret_cast<float*>(take(4u * men));
    v->manAngle = reinterpret_cast<uint16_t*>(take(2u * men));
    v->manAnchored = take(men);
    v->manMarker = take(men);
    v->manSkipDistance = take(men);
    v->slotX = reinterpret_cast<float*>(take(4u * slots));
    v->slotZ = reinterpret_cast<float*>(take(4u * slots));
    v->slotAngle = reinterpret_cast<uint16_t*>(take(2u * slots));
    v->entries = reinterpret_cast<Entry*>(take(sizeof(Entry) * men));
    v->scratch = reinterpret_cast<uint32_t*>(take(4u * men));
}

}  // namespace ntw_formation
