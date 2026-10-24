// See native_formation_solver.h.  Every block cites the native VA it replaces.  Algorithm = ntw_formation::Solver
// (native_formation_slot.cpp, bit-exact against the original machine code in tests/native_formation_slot_harness.cpp)
// re-expressed over a one-shot gather, with the 0x5281D0 cost inlined in its exact SSE operation order.  Loops:
//   RunScalar  scalar loop, cost recomputed per call (limit != 0, census mode, oracle reference)
//   RunSimd    limit == 0 first-improvement solver over eager cost tables, list-order SoA, packed-SSE scans and a
//              tournament tree for the worst-cost scan
#include "native_formation_solver.h"

#include <cfloat>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <intrin.h>
#include <limits>
#include <malloc.h>
#include <xmmintrin.h>

namespace ntw_solver {

namespace {

struct ManRec { float x, z, t0, t1; };    // man+0x48, man+0x50, angleTable[2a], angleTable[2a+1]   (a = u16 at man+0x64)
struct SlotRec { float x, z; };           // out3[0], out3[2] of 0x80E9D0(slot+4)

struct Totals {
    uint32_t evals = 0, distinct = 0, iter = 0, done = 0, swaps = 0, removals = 0, scans = 0;
    uint64_t fillTicks = 0;
};

// 0x5281D0 after the pose call, in its exact SSE operation order and OPERAND order (every step is the same scalar SSE
// instruction the original executes: subss, mulss x2, addss | comiss | sqrtss, divss | mulss x2, mulss x2, addss | minss |
// subss, mulss, addss).  Written with scalar intrinsics and forced inline: a non-inlined float-returning function would
// hand its result back in ST0 and the compiler then finishes the last add in x87 (53-bit control word, CW rounding instead
// of MXCSR), which is NOT bit-identical under non-default MXCSR rounding.
__forceinline float PairCost(const ManRec& a, const SlotRec& s, __m128 vzero, __m128 vone, __m128 vpw) {
    const __m128 dx = _mm_sub_ss(_mm_set_ss(s.x), _mm_set_ss(a.x));        // SUBSS XMM3(slot x), man x
    const __m128 dz = _mm_sub_ss(_mm_set_ss(s.z), _mm_set_ss(a.z));        // SUBSS XMM4(slot z), man z
    const __m128 dx2 = _mm_mul_ss(dx, dx);                                // MULSS XMM5(dx), XMM3
    const __m128 dz2 = _mm_mul_ss(dz, dz);                                // MULSS XMM0(dz), XMM4
    const __m128 d2 = _mm_add_ss(dx2, dz2);                               // ADDSS XMM5, XMM0
    if (_mm_comigt_ss(d2, vzero)) {                                       // COMISS d2, [0x131A7A4]; JBE -> return d2
        const __m128 root = _mm_sqrt_ss(d2);                              // SQRTSS
        const __m128 inv = _mm_div_ss(vone, root);                        // DIVSS 1.0, root
        const __m128 nx = _mm_mul_ss(dx, inv);                            // MULSS XMM3, XMM1
        const __m128 nz = _mm_mul_ss(dz, inv);                            // MULSS XMM4, XMM1
        const __m128 t0nx = _mm_mul_ss(_mm_set_ss(a.t0), nx);             // MULSS XMM0(t0), XMM3
        const __m128 t1nz = _mm_mul_ss(_mm_set_ss(a.t1), nz);             // MULSS XMM1(t1), XMM4
        __m128 dot = _mm_add_ss(t1nz, t0nx);                              // ADDSS XMM1, XMM0
        dot = _mm_min_ss(dot, vone);                                      // MINSS XMM1, 1.0 (NaN -> 1.0)
        const __m128 r = _mm_add_ss(_mm_mul_ss(_mm_sub_ss(vone, dot), vpw), d2);   // SUBSS, MULSS pw, ADDSS d2
        return _mm_cvtss_f32(r);
    }
    // d2 <= 0 or NaN: 0x5281D0 returns d2 as ADDSS computed it.  With two NaN operands x86 returns the FIRST one (dx*dx),
    // with one NaN operand that one; the compiler may swap a commutative add, so state the operand order explicitly here.
    if (_mm_comineq_ss(d2, d2)) {                                         // d2 is NaN
        if (_mm_comineq_ss(dx2, dx2)) return _mm_cvtss_f32(dx2);
        return _mm_cvtss_f32(dz2);
    }
    return _mm_cvtss_f32(d2);
}

// Packed PairCost: every lane executes the same IEEE operations in the same order as the scalar PairCost (packed SSE ops are
// per-lane IEEE-exact; min/compare semantics are identical).  Its results are only ever COMPARED (never stored), see RunSimd.
__forceinline __m128 Select(__m128 mask, __m128 a, __m128 b) { return _mm_or_ps(_mm_and_ps(mask, a), _mm_andnot_ps(mask, b)); }
__forceinline __m128 PairCostPs(__m128 sx, __m128 sz, __m128 mx, __m128 mz, __m128 t0, __m128 t1, __m128 vzero, __m128 vone,
                                __m128 vpw) {
    const __m128 dx = _mm_sub_ps(sx, mx);
    const __m128 dz = _mm_sub_ps(sz, mz);
    const __m128 d2 = _mm_add_ps(_mm_mul_ps(dx, dx), _mm_mul_ps(dz, dz));
    const __m128 pos = _mm_cmpgt_ps(d2, vzero);                      // lanes with d2 > 0 (false for NaN)
    const __m128 inv = _mm_div_ps(vone, _mm_sqrt_ps(d2));
    const __m128 nx = _mm_mul_ps(dx, inv);
    const __m128 nz = _mm_mul_ps(dz, inv);
    __m128 dot = _mm_add_ps(_mm_mul_ps(t1, nz), _mm_mul_ps(t0, nx));
    dot = _mm_min_ps(dot, vone);
    const __m128 r = _mm_add_ps(_mm_mul_ps(_mm_sub_ps(vone, dot), vpw), d2);
    return Select(pos, r, d2);
}

constexpr uint8_t kPop4[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};

}  // namespace

constexpr uint32_t kPad = kMaxM + 8;            // list-order arrays: whole 4-lane blocks readable past the live length
constexpr uint32_t kS = (kMaxM + 1u + 3u) & ~3u;   // stride == rows of the kSimd tables (>= kMaxM + 1, multiple of 4)
constexpr uint32_t kP = 2048;                   // leaves of the worst-scan tournament tree (power of two >= kMaxM)
static_assert(kP >= kMaxM && (kP & (kP - 1)) == 0, "tournament tree capacity");
static_assert(kMaxM < 65535u, "list positions / tournament-tree entries are uint16_t");

struct Workspace {
    // kSimd list-order SoA (position u of the private 0x14A40AC list), 16-byte aligned for packed loads.
    alignas(16) float lcost[kPad];       // raw cost of the entry at list position u
    alignas(16) float leff[kPad];        // slot != null ? cost : def
    alignas(16) float lkey[kP];          // worst-scan key: cost when (man != null && thr > cost), else -inf (kP leaves)
    alignas(16) uint32_t lman[kPad];     // current man id at the entry (the null man is id m)
    alignas(16) uint32_t lslot[kPad];    // slot index (== entry position at solve start) of the entry at list position u
    alignas(16) uint32_t lhasMan[kPad];  // all-ones when the entry's man is non-null
    alignas(16) uint32_t lhasSlot[kPad]; // all-ones when the entry's slot is non-null
    uint16_t tree[2 * kP];               // worst-scan tournament tree over list positions
    // kSimd gather SoA: by man id and by slot
    alignas(16) float gmx[kS], gmz[kS], gt0[kS], gt1[kS];
    alignas(16) float gsx[kS], gsz[kS];
    alignas(16) uint32_t ghs[kS];
    // shared scalar / SIMD state
    uint32_t manPtr[kMaxM];       // original man pointer of man index a (entry position at solve start)
    ManRec man[kMaxM];
    SlotRec slot[kMaxM];
    int32_t curMan[kMaxM];        // entry position -> current man index, -1 = null man
    float cost[kMaxM];            // native entry.cost
    float eff[kMaxM];             // slot != null ? cost : def (the value both scalar solver passes read)
    uint8_t hasSlot[kMaxM];
    uint16_t list[kMaxM];         // private copy of the 0x14A40AC list (entry positions), scalar loop
    uint32_t valid[(kMaxM * kMaxM + 31u) / 32u];   // census: distinct-pair bitset, key = a * m + s (scalar loop)
    alignas(16) float table[kS * kS];   // kSimd T[man id][slot] (row stride S): cost, or def for a null man / null slot
    alignas(16) float tableT[kS * kS];  // kSimd TT[slot][man id] = T transposed
};
static_assert(sizeof(Workspace) <= 12u * 1024u * 1024u, "workspace budget");

Workspace* CreateWorkspace() {
    void* p = _aligned_malloc(sizeof(Workspace), 64);
    return static_cast<Workspace*>(p);
}
void DestroyWorkspace(Workspace* w) { _aligned_free(w); }
uint64_t WorkspaceBytes() { return sizeof(Workspace); }

bool ListInitialized(const Env& env) {
    if (!env.listGuard || !env.tlsIndex) return false;
    // 0x502770: MOV EAX,FS:[2C]; EDX=[tls_index]; EDX=[EAX+EDX*4]; EAX=[guard]; CMP EAX,[EDX+8]; JG init
    const uint32_t* tlsArray = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(__readfsdword(0x2C)));
    const uint8_t* block = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(tlsArray[*env.tlsIndex]));
    const int32_t epoch = *reinterpret_cast<const int32_t*>(block + 8);
    return *env.listGuard <= epoch;
}

namespace {

// Gather: man (x, z, angle) read directly, slot world (x, z) through the NATIVE 0x80E9D0 once per entry.
void Gather(Workspace& w, const Env& env, const Entry12* e, uint32_t m) {
    for (uint32_t i = 0; i < m; ++i) {
        const uint32_t mp = e[i].man;
        w.manPtr[i] = mp;
        if (mp) {
            const uint8_t* o = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(mp));
            ManRec& r = w.man[i];
            std::memcpy(&r.x, o + 0x48, 4);
            std::memcpy(&r.z, o + 0x50, 4);
            uint16_t ang;
            std::memcpy(&ang, o + 0x64, 2);
            r.t0 = env.angleTable[2u * ang];
            r.t1 = env.angleTable[2u * ang + 1u];
            w.curMan[i] = static_cast<int32_t>(i);
        } else {
            w.curMan[i] = -1;
        }
        const uint32_t sp = e[i].slot;
        w.hasSlot[i] = sp != 0;
        if (sp) {
            float out[3];
            env.pose(reinterpret_cast<void*>(static_cast<uintptr_t>(sp + 4u)), nullptr, out);   // 0x5281D0: ECX = slot + 4
            w.slot[i].x = out[0];
            w.slot[i].z = out[2];
        }
    }
}

// 0x502770 phase 2 over the gathered state (scalar).  Count adds the `valid` bitset to count distinct (man, slot) pairs.
template <bool Count>
void RunScalar(Workspace& w, const Env& env, const float def, const float nos, const uint32_t m, const uint32_t limit,
               const float thr, Totals& tot) {
    const __m128 vzero = _mm_set_ss(env.zero), vone = _mm_set_ss(env.one), vpw = _mm_set_ss(env.pairWeight);
    int32_t* const curMan = w.curMan;
    float* const cost = w.cost;
    float* const eff = w.eff;
    const uint8_t* const hasSlot = w.hasSlot;
    uint16_t* const list = w.list;
    const ManRec* const man = w.man;
    const SlotRec* const slot = w.slot;
    uint32_t* const valid = w.valid;
    uint32_t evals = 0, distinct = 0;

    if constexpr (Count) std::memset(valid, 0, ((static_cast<size_t>(m) * m + 31u) / 32u) * sizeof(uint32_t));

    // 0x5281D0 (man a at slot entry s), native-equivalent call counted.
    auto C = [&](uint32_t a, uint32_t s) [[msvc::forceinline]] -> float {
        ++evals;
        if constexpr (Count) {
            const uint32_t k = a * m + s;
            const uint32_t bit = 1u << (k & 31u);
            uint32_t& word = valid[k >> 5];
            distinct += (word & bit) ? 0u : 1u;
            word |= bit;
        }
        return PairCost(man[a], slot[s], vzero, vone, vpw);
    };

    // 0x5027B0 phase 1: cost = def; if (man) cost = slot ? 5281D0 : nos; list = all entries.
    uint32_t ln = 0;
    for (uint32_t i = 0; i < m; ++i) {
        float c = def;
        if (curMan[i] >= 0) c = hasSlot[i] ? C(static_cast<uint32_t>(curMan[i]), i) : nos;
        cost[i] = c;
        eff[i] = hasSlot[i] ? c : def;
        list[ln++] = static_cast<uint16_t>(i);
    }

    uint32_t iter = 0, done = 0, swaps = 0, removals = 0, scans = 0;
    while (limit == 0 || iter < limit) {                      // 0x502887
        if (ln == 0) { done = 1; ++iter; break; }             // 0x502BC2
        scans += ln;
        int32_t worst = -1;                                   // 0x5028C0 worst-cost scan
        uint32_t widx = 0;
        float worstCost = def;
        for (uint32_t i = 0; i < ln; ++i) {
            const uint32_t e = list[i];
            if (curMan[e] >= 0) {
                const float cst = cost[e];
                if (thr > cst && (worst < 0 || cst > worstCost)) {
                    worst = static_cast<int32_t>(e);
                    worstCost = cst;
                    widx = i;
                }
            }
        }
        if (worst < 0) { done = 1; ++iter; break; }           // 0x502BBE
        const uint32_t W = static_cast<uint32_t>(worst);
        const bool wSlot = hasSlot[W] != 0;
        const int32_t wm = curMan[W];
        bool swapped = false;
        if (limit == 0) {                                     // first-improvement pass 0x502910
            const float cA = eff[W];
            if (thr > cA) {
                for (uint32_t u = 0; u < ln; ++u) {
                    if (u == widx) continue;
                    const uint32_t o = list[u];
                    const float cB = eff[o];
                    if (!(thr > cB)) continue;
                    const float orig = cB + cA;
                    const int32_t om = curMan[o];
                    const bool oSlot = hasSlot[o] != 0;
                    // 0x57CBC0: exchange the men, refresh both costs with the same rule.
                    float t1 = def;
                    if (om >= 0) t1 = wSlot ? C(static_cast<uint32_t>(om), W) : nos;
                    float t2 = def;
                    if (wm >= 0) t2 = oSlot ? C(static_cast<uint32_t>(wm), o) : nos;
                    const float nA = wSlot ? t1 : def;
                    const float nB = oSlot ? t2 : def;
                    if (orig > nB + nA) {                     // 0x5029DF accept: swap men, recost = the two values just computed
                        curMan[W] = om;
                        curMan[o] = wm;
                        cost[W] = t1;
                        eff[W] = wSlot ? t1 : def;
                        cost[o] = t2;
                        eff[o] = oSlot ? t2 : def;
                        evals += (om >= 0 && wSlot ? 1u : 0u) + (wm >= 0 && oSlot ? 1u : 0u);   // native recost calls 5281D0 again
                        swapped = true;
                        break;
                    }
                }
            }
        } else {                                              // best-improvement pass 0x502A43
            int32_t best = -1;
            float bestDelta = def;
            float bt1 = 0.0f, bt2 = 0.0f;
            const float cA = eff[W];
            for (uint32_t u = 0; u < ln; ++u) {
                if (u == widx) continue;
                const uint32_t o = list[u];
                if (!(thr > cost[o])) continue;
                const float cB = eff[o];
                const float orig = cB + cA;
                const int32_t om = curMan[o];
                const bool oSlot = hasSlot[o] != 0;
                float t1 = def;
                if (om >= 0) t1 = wSlot ? C(static_cast<uint32_t>(om), W) : nos;
                float t2 = def;
                if (wm >= 0) t2 = oSlot ? C(static_cast<uint32_t>(wm), o) : nos;
                const float nA = wSlot ? t1 : def;
                const float nB = oSlot ? t2 : def;
                const float delta = (nB + nA) - orig;
                if (bestDelta > delta) {
                    best = static_cast<int32_t>(o);
                    bestDelta = delta;
                    bt1 = t1;
                    bt2 = t2;
                }
            }
            if (best >= 0) {                                  // 0x502B33
                const uint32_t o = static_cast<uint32_t>(best);
                const bool oSlot = hasSlot[o] != 0;
                const int32_t om = curMan[o];
                curMan[W] = om;
                curMan[o] = wm;
                cost[W] = bt1;
                eff[W] = wSlot ? bt1 : def;
                cost[o] = bt2;
                eff[o] = oSlot ? bt2 : def;
                evals += (om >= 0 && wSlot ? 1u : 0u) + (wm >= 0 && oSlot ? 1u : 0u);
                swapped = true;
            }
        }
        if (swapped) {
            ++swaps;
        } else {                                              // 0x502B98: list[widx] = list[--count]
            list[widx] = list[--ln];
            ++removals;
        }
        ++iter;
    }
    tot.evals = evals;
    tot.distinct = distinct;
    tot.iter = iter;
    tot.done = done;
    tot.swaps = swaps;
    tot.removals = removals;
    tot.scans = scans;
}

// RunSimd = the first-improvement solver (limit == 0) re-expressed over
//   * two eager cost tables T[man id][slot] and TT[slot][man id] (cost, or `def` for a null man / null slot, so a pair's
//     nA / nB values are plain lookups; the man id of a null man is `m`, a row/column that is all `def`), filled with the
//     packed PairCostPs (the same IEEE operations per lane as the scalar cost),
//   * list-order SoA arrays (position u of the private 0x14A40AC list) scanned four lanes at a time, and
//   * a tournament tree over the list positions for the worst-cost scan (first maximal key in list order).
// Accept/reject decisions only compare VALUES (NaN compares false exactly like COMISS); every cost that is STORED is
// recomputed with the scalar PairCost so NaN payload bits match the native x87 round trip.
// Preconditions (checked by the caller): limit == 0, all MXCSR exception masks set, def/nos >= -FLT_MAX (so -inf is a safe
// "not eligible" key), pairWeight >= 0 (so every PairCost >= 0 or NaN).  Writes w.curMan / w.cost (entry indexed) and Totals.
void RunSimd(Workspace& w, const Env& env, const float def, const float nos, const uint32_t m, const float thr, Totals& tot) {
    const float kNegInf = -std::numeric_limits<float>::infinity();
    const __m128 vzs = _mm_set_ss(env.zero), vos = _mm_set_ss(env.one), vws = _mm_set_ss(env.pairWeight);   // scalar PairCost
    const __m128 vz = _mm_set1_ps(env.zero), vo = _mm_set1_ps(env.one), vw = _mm_set1_ps(env.pairWeight);   // packed PairCost
    const __m128 vthr = _mm_set1_ps(thr), vdef = _mm_set1_ps(def);
    const ManRec* const man = w.man;
    const SlotRec* const slot = w.slot;
    float* const lcost = w.lcost; float* const leff = w.leff; float* const lkey = w.lkey;
    uint32_t* const lman = w.lman; uint32_t* const lslot = w.lslot;
    uint32_t* const lhasMan = w.lhasMan; uint32_t* const lhasSlot = w.lhasSlot;
    uint16_t* const tree = w.tree;
    float* const T = w.table; float* const TT = w.tableT;
    const uint32_t S = (m + 1u + 3u) & ~3u;                  // table stride == rows (>= m + 1, multiple of 4)
    uint32_t evals = 0;

    // ---- SoA snapshots by man id / by slot, then the eager tables ----
    const uint64_t f0 = __rdtsc();
    for (uint32_t i = 0; i < m; ++i) {
        const bool hm = w.manPtr[i] != 0, hs = w.hasSlot[i] != 0;
        w.gmx[i] = hm ? w.man[i].x : 0.0f;  w.gmz[i] = hm ? w.man[i].z : 0.0f;
        w.gt0[i] = hm ? w.man[i].t0 : 0.0f; w.gt1[i] = hm ? w.man[i].t1 : 0.0f;
        w.gsx[i] = hs ? w.slot[i].x : 0.0f; w.gsz[i] = hs ? w.slot[i].z : 0.0f;
        w.ghs[i] = hs ? 0xFFFFFFFFu : 0u;
    }
    for (uint32_t i = m; i < S; ++i) {
        w.gmx[i] = w.gmz[i] = w.gt0[i] = w.gt1[i] = w.gsx[i] = w.gsz[i] = 0.0f;
        w.ghs[i] = 0u;
    }
    for (uint32_t a = 0; a < S; ++a) {                       // T[a][s]: man a at slot s (def when either is null)
        float* const row = T + static_cast<size_t>(a) * S;
        if (a < m && w.manPtr[a]) {
            const __m128 bx = _mm_set1_ps(w.gmx[a]), bz = _mm_set1_ps(w.gmz[a]), b0 = _mm_set1_ps(w.gt0[a]), b1 = _mm_set1_ps(w.gt1[a]);
            for (uint32_t s0 = 0; s0 < S; s0 += 4) {
                const __m128 c = PairCostPs(_mm_load_ps(w.gsx + s0), _mm_load_ps(w.gsz + s0), bx, bz, b0, b1, vz, vo, vw);
                _mm_store_ps(row + s0, Select(_mm_castsi128_ps(_mm_load_si128(reinterpret_cast<const __m128i*>(w.ghs + s0))), c, vdef));
            }
        } else {
            for (uint32_t s0 = 0; s0 < S; s0 += 4) _mm_store_ps(row + s0, vdef);
        }
    }
    for (uint32_t rb = 0; rb < S; rb += 4)                   // TT[s][a] = T[a][s]
        for (uint32_t cb = 0; cb < S; cb += 4) {
            __m128 r0 = _mm_load_ps(T + static_cast<size_t>(rb + 0) * S + cb), r1 = _mm_load_ps(T + static_cast<size_t>(rb + 1) * S + cb);
            __m128 r2 = _mm_load_ps(T + static_cast<size_t>(rb + 2) * S + cb), r3 = _mm_load_ps(T + static_cast<size_t>(rb + 3) * S + cb);
            _MM_TRANSPOSE4_PS(r0, r1, r2, r3);
            _mm_store_ps(TT + static_cast<size_t>(cb + 0) * S + rb, r0); _mm_store_ps(TT + static_cast<size_t>(cb + 1) * S + rb, r1);
            _mm_store_ps(TT + static_cast<size_t>(cb + 2) * S + rb, r2); _mm_store_ps(TT + static_cast<size_t>(cb + 3) * S + rb, r3);
        }
    tot.fillTicks = __rdtsc() - f0;

    // ---- 0x5027B0 phase 1 (scalar, native-exact costs, m evaluations); list order == entry order ----
    for (uint32_t i = 0; i < m; ++i) {
        const bool mnNon = w.curMan[i] >= 0, hs = w.hasSlot[i] != 0;
        float c = def;
        if (mnNon) {
            if (hs) { ++evals; c = PairCost(man[w.curMan[i]], slot[i], vzs, vos, vws); }
            else c = nos;
        }
        lcost[i] = c;
        leff[i] = hs ? c : def;
        lkey[i] = (mnNon && thr > c) ? c : kNegInf;
        lman[i] = mnNon ? static_cast<uint32_t>(w.curMan[i]) : m;
        lslot[i] = i;
        lhasMan[i] = mnNon ? 0xFFFFFFFFu : 0u;
        lhasSlot[i] = hs ? 0xFFFFFFFFu : 0u;
    }
    const uint32_t m4 = (m + 3u) & ~3u;
    for (uint32_t i = m; i < m4; ++i) {                      // padding of the last 4-lane block: never eligible, indices stay valid
        lcost[i] = 0.0f; leff[i] = 0.0f; lkey[i] = kNegInf; lman[i] = m; lslot[i] = 0; lhasMan[i] = 0u; lhasSlot[i] = 0u;
    }

    // ---- tournament tree over list positions (leaves tree[P + u]); winner = greater key, ties -> smaller position ----
    uint32_t P = 2;
    while (P < m) P <<= 1;
    for (uint32_t u = m; u < P; ++u) lkey[u] = kNegInf;      // leaves beyond the list (lkey has kP entries)
    for (uint32_t u = 0; u < P; ++u) tree[P + u] = static_cast<uint16_t>(u);
    for (uint32_t i = P - 1; i >= 1; --i) {
        const uint16_t l = tree[2 * i], r = tree[2 * i + 1];
        tree[i] = lkey[r] > lkey[l] ? r : l;
    }
    auto Update = [&](uint32_t u) [[msvc::forceinline]] {
        for (uint32_t i = (P + u) >> 1; i >= 1; i >>= 1) {
            const uint16_t l = tree[2 * i], r = tree[2 * i + 1];
            tree[i] = lkey[r] > lkey[l] ? r : l;
        }
    };
    // Both leaf keys are final. Fold the equal-depth paths bottom-up, then fold their shared ancestors once.
    // Each node uses Update's strict comparison, preserving the first maximal position on ties.
    auto Update2 = [&](uint32_t a, uint32_t b) [[msvc::forceinline]] {
        uint32_t ia = (P + a) >> 1, ib = (P + b) >> 1;
        while (ia != ib) {
            const uint16_t la = tree[2 * ia], ra = tree[2 * ia + 1];
            tree[ia] = lkey[ra] > lkey[la] ? ra : la;
            const uint16_t lb = tree[2 * ib], rb = tree[2 * ib + 1];
            tree[ib] = lkey[rb] > lkey[lb] ? rb : lb;
            ia >>= 1; ib >>= 1;
        }
        for (uint32_t i = ia; i >= 1; i >>= 1) {
            const uint16_t l = tree[2 * i], r = tree[2 * i + 1];
            tree[i] = lkey[r] > lkey[l] ? r : l;
        }
    };

    const __m128i lane01 = _mm_set_epi32(3, 2, 1, 0);
    const __m128i four = _mm_set1_epi32(4);
    uint32_t ln = m, iter = 0, done = 0, swaps = 0, removals = 0, scans = 0;
    for (;;) {                                               // 0x502887 with limit == 0
        if (ln == 0) { done = 1; ++iter; break; }            // 0x502BC2
        scans += ln;
        // 0x5028C0 worst scan: first maximal eligible key in list order == tournament-tree root
        const uint32_t widx = tree[1];
        if (!(lkey[widx] > kNegInf)) { done = 1; ++iter; break; }   // 0x502BBE: no eligible worst
        const uint32_t W = lslot[widx];
        const bool wSlot = lhasSlot[widx] != 0, wmNon = lhasMan[widx] != 0;
        const uint32_t wm = lman[widx];
        const float cA = leff[widx];
        bool swapped = false;
        if (thr > cA) {                                      // 0x502910 first-improvement pass
            const __m128 vcA = _mm_set1_ps(cA);
            const float* const rowT = T + static_cast<size_t>(wm) * S;     // man wm at slot s (row of def when wm is the null id)
            const float* const rowTT = TT + static_cast<size_t>(W) * S;    // man a at slot W (row of def when W has no slot)
            const __m128i lnv = _mm_set1_epi32(static_cast<int>(ln));
            const __m128i widxv = _mm_set1_epi32(static_cast<int>(widx));
            __m128i idxv = lane01;
            for (uint32_t u0 = 0; u0 < ln; u0 += 4, idxv = _mm_add_epi32(idxv, four)) {
                const __m128 cB = _mm_load_ps(leff + u0);
                const __m128i vld = _mm_andnot_si128(_mm_cmpeq_epi32(idxv, widxv), _mm_cmplt_epi32(idxv, lnv));   // u < ln && u != widx
                const __m128 act = _mm_and_ps(_mm_cmpgt_ps(vthr, cB), _mm_castsi128_ps(vld));                    // + thr > cB
                const int actBits = _mm_movemask_ps(act);
                if (!actBits) continue;
                const uint32_t* const ps = lslot + u0;
                const uint32_t* const pm = lman + u0;
                const __m128 nB = _mm_set_ps(rowT[ps[3]], rowT[ps[2]], rowT[ps[1]], rowT[ps[0]]);     // worst's man at slot o
                const __m128 nA = _mm_set_ps(rowTT[pm[3]], rowTT[pm[2]], rowTT[pm[1]], rowTT[pm[0]]); // man o at the worst's slot
                const __m128 orig = _mm_add_ps(cB, vcA);      // cB + cA
                const __m128 sum = _mm_add_ps(nB, nA);        // nB + nA
                const int accBits = _mm_movemask_ps(_mm_and_ps(act, _mm_cmpgt_ps(orig, sum)));
                // native-equivalent 5281D0 calls: every scanned o up to and including the accepted one
                unsigned long kk = 0;
                int counted = actBits;
                if (accBits) { _BitScanForward(&kk, static_cast<unsigned long>(accBits)); counted = actBits & ((2 << kk) - 1); }
                if (wSlot) evals += kPop4[counted & _mm_movemask_ps(_mm_castsi128_ps(_mm_load_si128(reinterpret_cast<const __m128i*>(lhasMan + u0))))];
                if (wmNon) evals += kPop4[counted & _mm_movemask_ps(_mm_castsi128_ps(_mm_load_si128(reinterpret_cast<const __m128i*>(lhasSlot + u0))))];
                if (!accBits) continue;
                // 0x5029DF accept: exchange the men, recost both entries with the scalar (native-exact) cost
                const uint32_t oPos = u0 + kk;
                const uint32_t O = lslot[oPos];
                const uint32_t om = lman[oPos];
                const bool omNon = lhasMan[oPos] != 0, oSlot = lhasSlot[oPos] != 0;
                float t1 = def;
                if (omNon) t1 = wSlot ? PairCost(man[om], slot[W], vzs, vos, vws) : nos;
                float t2 = def;
                if (wmNon) t2 = oSlot ? PairCost(man[wm], slot[O], vzs, vos, vws) : nos;
                evals += (omNon && wSlot ? 1u : 0u) + (wmNon && oSlot ? 1u : 0u);   // native recost calls 5281D0 again
                lman[widx] = om;  lman[oPos] = wm;
                lhasMan[widx] = omNon ? 0xFFFFFFFFu : 0u;  lhasMan[oPos] = wmNon ? 0xFFFFFFFFu : 0u;
                lcost[widx] = t1; leff[widx] = wSlot ? t1 : def; lkey[widx] = (omNon && thr > t1) ? t1 : kNegInf;
                lcost[oPos] = t2; leff[oPos] = oSlot ? t2 : def; lkey[oPos] = (wmNon && thr > t2) ? t2 : kNegInf;
                Update2(widx, oPos);
                swapped = true;
                break;
            }
        }
        if (swapped) {
            ++swaps;
        } else {                                             // 0x502B98: list[widx] = list[--count]; the worst entry is final
            w.curMan[W] = wmNon ? static_cast<int32_t>(wm) : -1;
            w.cost[W] = lcost[widx];
            const uint32_t last = ln - 1;
            if (widx != last) {
                lslot[widx] = lslot[last]; lcost[widx] = lcost[last]; leff[widx] = leff[last]; lkey[widx] = lkey[last];
                lman[widx] = lman[last]; lhasMan[widx] = lhasMan[last]; lhasSlot[widx] = lhasSlot[last];
            }
            lkey[last] = kNegInf; lhasMan[last] = 0u; lhasSlot[last] = 0u; lman[last] = m;
            if (widx != last) Update2(widx, last); else Update(last);
            --ln;
            ++removals;
        }
        ++iter;
    }
    for (uint32_t u = 0; u < ln; ++u) {                      // entries still in the list: final man / cost
        w.curMan[lslot[u]] = lhasMan[u] ? static_cast<int32_t>(lman[u]) : -1;
        w.cost[lslot[u]] = lcost[u];
    }
    tot.evals = evals;
    tot.distinct = 0;
    tot.iter = iter;
    tot.done = done;
    tot.swaps = swaps;
    tot.removals = removals;
    tot.scans = scans;
}

// 0x5027D9..0x502854 for m pushes starting from count == 0: cap 0 -> alloc(1,0); count >= cap -> cap *= 2, alloc(cap,0),
// release(old).  Contents (the entry pointers) are dead data, so they are not written.
void ReplicateListGrowth(const Env& env, uint32_t m) {
    if (m == 0) return;
    uint32_t* const L = env.listGlobal;
    uint32_t cap = L[0];
    if (cap == 0) {
        L[0] = 1;
        L[2] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(env.alloc(1, 0)));
        cap = 1;
    }
    while (cap < m) {
        const uint32_t old = L[2];
        cap *= 2;
        L[0] = cap;
        L[2] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(env.alloc(cap, 0)));
        if (old) env.release(reinterpret_cast<void*>(static_cast<uintptr_t>(old)));
    }
}

Outcome Fail(Counters* c, FallbackReason r) {
    if (c) c->fallback = r;
    return kFallback;
}

// Argument validation; returns kReasonNone and m on success.
FallbackReason Check(const Env& env, const float* ctx, const Entry12* begin, const Entry12* end, uint32_t* m) {
    if (!ctx || !begin || !end || !env.angleTable || !env.pose) return kReasonEnv;
    const uintptr_t b = reinterpret_cast<uintptr_t>(begin), e = reinterpret_cast<uintptr_t>(end);
    if (e < b || (e - b) % sizeof(Entry12) != 0) return kReasonRange;
    const size_t n = (e - b) / sizeof(Entry12);
    if (n > kMaxM) return kReasonTooLarge;
    *m = static_cast<uint32_t>(n);
    return kReasonNone;
}

Outcome SolveImpl(Policy policy, bool replicate, Workspace& w, const Env& env, const float* ctx, Entry12* begin,
                  Entry12* end, uint32_t limit, float thr, uint32_t* eax, Counters* counters) {
    const uint64_t t0 = __rdtsc();
    const bool census = counters && counters->profile != 0;
    if (counters) {
        std::memset(counters, 0, sizeof(*counters));
        counters->profile = census ? 1u : 0u;
    }
    uint32_t m = 0;
    if (!eax) return Fail(counters, kReasonEnv);
    if (const FallbackReason r = Check(env, ctx, begin, end, &m)) return Fail(counters, r);
    if (replicate) {
        if (!env.listGlobal || !env.alloc || !env.release) return Fail(counters, kReasonEnv);
        if (!env.listGuard || !env.tlsIndex) return Fail(counters, kReasonEnv);
        if (env.listGlobal[1] != 0) return Fail(counters, kReasonListState);
        if (!ListInitialized(env)) return Fail(counters, kReasonGuard);
    }
    const float def = ctx[0], nos = ctx[1];
    const bool simd = policy == kSimd && limit == 0 && !census;
    if (simd) {                                              // packed path preconditions: nothing written yet on failure
        if ((_mm_getcsr() & 0x1F80u) != 0x1F80u) return Fail(counters, kReasonFpEnv);   // an unmasked exception could trap in garbage lanes
        if (!(def >= -FLT_MAX) || !(nos >= -FLT_MAX) || !(env.pairWeight >= 0.0f)) return Fail(counters, kReasonCtx);
    }

    Gather(w, env, begin, m);
    const uint64_t t1 = __rdtsc();
    Totals tot;
    if (simd) RunSimd(w, env, def, nos, m, thr, tot);
    else if (census) RunScalar<true>(w, env, def, nos, m, limit, thr, tot);
    else RunScalar<false>(w, env, def, nos, m, limit, thr, tot);
    const uint64_t t2 = __rdtsc();

    if (replicate) ReplicateListGrowth(env, m);              // same allocator calls, same order as the native pushes
    for (uint32_t i = 0; i < m; ++i) {                       // commit: slots never change
        begin[i].man = w.curMan[i] >= 0 ? w.manPtr[w.curMan[i]] : 0u;
        begin[i].cost = w.cost[i];
    }
    *eax = (tot.iter & 0xFFFFFF00u) | tot.done;              // 0x502BD5: MOV AL,[done] over EAX = iter
    if (counters) {
        counters->m = m;
        counters->evals = tot.evals;
        counters->distinct = tot.distinct;
        counters->iterations = tot.iter;
        counters->swaps = tot.swaps;
        counters->removals = tot.removals;
        counters->scans = tot.scans;
        counters->gatherTicks = t1 - t0;
        counters->fillTicks = tot.fillTicks;
        counters->loopTicks = t2 - t1;                       // kSimd: includes its table fill
        counters->totalTicks = __rdtsc() - t0;
    }
    return kSolved;
}

}  // namespace

Outcome Solve(Workspace& w, const Env& env, const float* ctx, Entry12* begin, Entry12* end, uint32_t limit, float thr,
              uint32_t* eax, Counters* counters) {
    return SolveImpl(kSimd, true, w, env, ctx, begin, end, limit, thr, eax, counters);
}

Outcome SolveCopy(Workspace& w, const Env& env, const float* ctx, Entry12* copyBegin, Entry12* copyEnd, uint32_t limit,
                  float thr, uint32_t* eax, Counters* counters) {
    return SolveImpl(kSimd, false, w, env, ctx, copyBegin, copyEnd, limit, thr, eax, counters);
}

Outcome SolveWith(Policy policy, bool replicateList, Workspace& w, const Env& env, const float* ctx, Entry12* begin,
                  Entry12* end, uint32_t limit, float thr, uint32_t* eax, Counters* counters) {
    return SolveImpl(policy, replicateList, w, env, ctx, begin, end, limit, thr, eax, counters);
}

}  // namespace ntw_solver
