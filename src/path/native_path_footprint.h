// Private to native_path_runtime.cpp: the READ FOOTPRINT of the ORIGINAL successor 0x800210 (original Napoleon.exe x86,
// SHA-256 13fcab62...cbad4) and the gate that decides, BEFORE the original is invoked, whether it can only take branches whose
// complete game-memory read set is known.
//
// WHY: a private path result is a pure function of (inputs, every game-memory byte the successor read).  The runtime records a
// byte snapshot of every such range when the callback runs (during the prepass) and, at consumption, re-compares live memory
// with that snapshot (memcmp, no hash, no epoch): any difference -> the result is dropped and the original 0x8026F0 runs.
// Tick boundaries do not weaken this proof: the slot owns these immutable snapshots until consumption or discard; they are
// never refreshed merely because a later prepass sees the same request. Inputs, query and sentinel are revalidated as well.
// Lifetime is covered by values, not an assumed allocation generation: every dereferenced pointer and every byte read through
// it is recorded. Freed/unreadable memory faults into fallback; reused addresses with identical recorded bytes compute the
// identical result. No world pointer is dereferenced by workers or trusted at consumption without the complete equality check.
//
// SUPPORTED BRANCHES of 0x800210 (instruction evidence: disassembly of the pinned image, VAs preferred base):
//   * direct-goal node   0x800442..0x8004BE   ([G+0xFC].object == O)
//   * edge loop plain    0x8004C1..0x800852   (edge [E+0xC] == 0, kind [E+4] != 4)
// UNSUPPORTED (the gate refuses BEFORE any callback of the request runs; the request stays with the original 0x8026F0):
//   * query special goal ([Q+0x34] != 0): 808BD0 / 7FFD20 and the 0x800227 branch,
//   * door edges ([E+0xC] != 0 and the edge survives the 0x8004E0..0x800595 filters): 8007BD / 80EA90 receiver class unresolved,
//   * edge kind 4 (80EA60 door projection), any popped / destination topology that is null (cell lookup 81C050 -> 67A790),
//   * any virtual receiver whose slot value is not one of the allow-listed, pinned targets below.
#pragma once

#include <math.h>
#include <stdint.h>
#include <string.h>

#include "native_path_workspace.h"

namespace npr {

inline uint32_t Rd32(uint32_t a) { return *reinterpret_cast<const volatile uint32_t*>(static_cast<uintptr_t>(a)); }
inline uint8_t Rd8(uint32_t a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
inline float RdF(uint32_t a) {
    const uint32_t v = Rd32(a);
    float f;
    memcpy(&f, &v, 4);
    return f;
}

// Byte snapshot of game-memory ranges.  POD: storage is owned by the slot (placement layout in the runtime).
struct Fp {
    struct Range {
        uint32_t addr, len, off;
    };
    Range* ranges;
    uint32_t nRanges, capRanges;
    uint8_t* bytes;
    uint32_t nBytes, capBytes;
    uint32_t* table;       // open addressing, value = range index + 1; size = tableMask + 1 (power of two > capRanges)
    uint32_t tableMask;
    uint32_t overflow;     // sticky: a range did not fit

    void Reset() {
        nRanges = 0;
        nBytes = 0;
        overflow = 0;
        memset(table, 0, sizeof(uint32_t) * (static_cast<size_t>(tableMask) + 1));
    }

    // Copies [addr, addr+len) (the caller's __try turns a fault into a refusal).  Duplicate (addr,len) pairs are stored once.
    bool Add(uint32_t addr, uint32_t len) {
        if (len == 0) return true;
        if (overflow) return false;
        if (addr == 0 || addr + len < addr) {
            overflow = 1;
            return false;
        }
        uint32_t h = (addr * 0x9E3779B1u) ^ (len * 0x85EBCA6Bu);
        h ^= h >> 15;
        uint32_t i = h & tableMask;
        for (;; i = (i + 1) & tableMask) {
            const uint32_t e = table[i];
            if (e == 0) break;
            const Range& r = ranges[e - 1];
            if (r.addr == addr && r.len == len) return true;
        }
        if (nRanges >= capRanges || len > capBytes - nBytes) {
            overflow = 1;
            return false;
        }
        memcpy(bytes + nBytes, reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), len);
        ranges[nRanges] = Range{addr, len, nBytes};
        nBytes += len;
        table[i] = ++nRanges;
        return true;
    }

    // true iff every recorded range still holds exactly the recorded bytes (faults are the caller's business)
    bool Equal() const {
        for (uint32_t i = 0; i < nRanges; ++i) {
            const Range& r = ranges[i];
            if (memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(r.addr)), bytes + r.off, r.len) != 0) return false;
        }
        return true;
    }
};

// Image-relative (already + delta) addresses of the ONLY virtual targets the gate accepts; each is a pinned function span.
struct Targets {
    uint32_t gwSelf;    // 0x4470B0  gateway slot +0x20:   mov eax,ecx
    uint32_t gwZero;    // 0x461180  gateway slot +0x18:   xor eax,eax
    uint32_t gwFlag;    // 0x6B7F90  gateway slot +0x28:   [[this+0x60]+0x14]+0x232
    uint32_t iface;     // 0x7FF170  topology+0xC slot 0
    uint32_t embedded;  // 0x54E920  gateway+0x1C slot 0:  mov al,[ecx+4]
};

enum PlanStatus : uint32_t {
    kPlanOk = 0,
    kPlanUnsupported,  // a branch / receiver outside the supported set is reachable
    kPlanBadShape,     // null / inconsistent pointers the original would dereference
    kPlanCapacity,     // edge count or arena capacity cannot be guaranteed
    kPlanFault,        // a guarded read faulted
};

struct Plan {
    uint32_t maxNodes;  // upper bound of node allocations of this call
    uint32_t hf;        // height-field object when some edge projects through it, else 0
};

// 0x7EB34A..0x7EB35F: g = [obj+0x24]; vcall [[g]+0x20]; 6ABC80(eax) -> [[eax+0x60]+0x14]; byte [+0x232].  obj range already added.
inline bool PlanCtorGateway(Fp& fp, const Targets& t, uint32_t obj) {
    const uint32_t g = Rd32(obj + 0x24);
    if (g == 0) return true;
    fp.Add(g, 0x68);                       // vptr, embedded vptr (+0x1C), flag (+0x20), plane (+0x30..), +0x40, +0x60
    const uint32_t vt = Rd32(g);
    fp.Add(vt + 0x20, 4);
    if (Rd32(vt + 0x20) != t.gwSelf) return false;   // returns this (eax = g, non-null)
    const uint32_t x = Rd32(g + 0x60);
    if (x == 0) return false;
    fp.Add(x + 0x14, 4);
    const uint32_t y = Rd32(x + 0x14);
    if (y == 0) return false;
    fp.Add(y + 0x230, 4);                  // byte [y+0x232]
    return true;
}

// 0x80053C: vcall [[g2]+0x28] (6B7F90) -> byte [[[g2+0x60]+0x14]+0x232]
inline bool PlanGateByte(Fp& fp, const Targets& t, uint32_t g2, uint8_t* al) {
    fp.Add(g2, 0x68);
    const uint32_t vt = Rd32(g2);
    fp.Add(vt + 0x28, 4);
    if (Rd32(vt + 0x28) != t.gwFlag) return false;
    const uint32_t x = Rd32(g2 + 0x60);
    if (x == 0) return false;
    fp.Add(x + 0x14, 4);
    const uint32_t y = Rd32(x + 0x14);
    if (y == 0) return false;
    fp.Add(y + 0x230, 4);
    *al = Rd8(y + 0x232);
    return true;
}

// 0x8005F7: vcall [[D+0xC]+0] = 7FF170(this = D+0xC)
inline bool PlanAccept(Fp& fp, const Targets& t, uint32_t d, uint8_t* al) {
    const uint32_t vt = Rd32(d + 0xC);
    fp.Add(vt, 4);
    if (Rd32(vt) != t.iface) return false;
    const uint32_t g = Rd32(d + 0x24);     // [this+0x18]
    if (g == 0) {
        *al = Rd8(d + 0x10);               // [this+4]
        return true;
    }
    fp.Add(g, 0x68);
    const uint32_t vtg = Rd32(g);
    fp.Add(vtg + 0x18, 4);
    if (Rd32(vtg + 0x18) != t.gwZero) return false;   // eax = 0 -> embedded slot
    const uint32_t vte = Rd32(g + 0x1C);
    fp.Add(vte, 4);
    if (Rd32(vte) != t.embedded) return false;
    *al = Rd8(g + 0x20);                   // 54E920: mov al,[ecx+4] with ecx = g+0x1C
    return true;
}

// 0x7F1630(Q): [[[Q+0x14]+0x43C]+0xD8] for kind 1, [[[Q+0xC]+0x1EC]+0xD8] otherwise
inline uint32_t PlanQueryChain(Fp& fp, uint32_t q) {
    uint32_t a;
    if (Rd32(q) == 1) {
        a = Rd32(q + 0x14);
        fp.Add(a + 0x43C, 4);
        a = Rd32(a + 0x43C);
    } else {
        a = Rd32(q + 0xC);
        fp.Add(a + 0x1EC, 4);
        a = Rd32(a + 0x1EC);
    }
    fp.Add(a + 0xD8, 4);
    return Rd32(a + 0xD8);
}

// Height field samples (0x64C5F0 via 0x66BB40, 0x57E870 plane == 0): EXACT read set of the original arithmetic, not a guess.
//   original (64C5F0): t = pos[k] * [hf+0x24]            (mulss, float)
//                      v = fistp(fadd(fadd(t, t), -0.5f)) (x87), idx = (v >> 1) + [hf+0x10]  (sar, add: 32-bit wrap)
//                      r0 = umin([hf+0x14], idx), r1 = umin([hf+0x14], r0 + 1)    (cmp/cmovae, unsigned)
//                      cells read: [table + ((row << [hf+8]) + col) * 8] for row in {r0z, r1z}, col in {r0x, r1x}  (4 bytes each)
//   rows come from pos[1] (z), columns from pos[0] (x); pos is clamped to [-L, L], L = [hf+0x1C], by 66BB40 (comparison form handled
//   below; NaN is refused).  PROOF that the candidate set contains every cell, for ANY x87 precision control (24 / 53 / 64 bit) and ANY
//   rounding control (nearest / down / up / truncate), for every finite |t| <= 2^20:
//     a = 2t is exact; b = fl_p(a - 0.5) has |b - (a - 0.5)| <= ulp_p(|a - 0.5|) <= 2^-2 (|a - 0.5| < 2^21 + 1, p >= 24);
//     v = round(b) has |v - b| <= 1;  hence 2t - 1.75 <= v <= 2t + 0.75 and floor(v / 2) in [floor(t - 0.875), floor(t + 0.375)],
//     which is a subset of {floor(t) - 1, floor(t), floor(t) + 1}.  The loop below uses d in {-1, 0, 1, 2} (strict superset) and
//     applies the same wrapping add / unsigned min / +1 / unsigned min as the original, so every row / column pair the original
//     can form is enumerated.  The shift count is refused unless < 24 (x86 masks shl counts mod 32; below 24 the indices are exact).
//   Anything outside the proven domain (non-finite or |t| > 2^20, null table, implausible header) makes the caller refuse the
//   request: no unproved case ever reaches consumption.  The header [hf, hf+0x28) holds every field 64C5F0 / 66BB40 read
//   (+0x00 table, +0x08 shift, +0x10 offset, +0x14 max index, +0x1C limit / origin, +0x20 cell size, +0x24 scale); the float constants
//   [0x1318048] / [0x1318130] are .rdata (read-only section).  Table cell BYTES are therefore captured exactly (8 bytes per cell,
//   a superset of the 4 read); the table need not be immutable as a whole.
inline bool SampleHeightField(Fp& fp, uint32_t hf, float x, float z) {
    fp.Add(hf, 0x28);
    const float lim = RdF(hf + 0x1C), scale = RdF(hf + 0x24);
    const uint32_t table = Rd32(hf), shift = Rd32(hf + 8), off = Rd32(hf + 0x10), maxIdx = Rd32(hf + 0x14);
    if (!(lim > 0.0f && lim < 1.0e7f) || !(scale > 0.0f && scale < 1.0e7f) || table == 0 || shift >= 24) return false;
    if (!(x == x) || !(z == z)) return false;
    const float cx = x < -lim ? -lim : (x > lim ? lim : x);
    const float cz = z < -lim ? -lim : (z > lim ? lim : z);
    const float tx = cx * scale, tz = cz * scale;
    constexpr float kMaxScaled = 1048576.0f;   // 2^20: bound of the proof above
    if (!(fabsf(tx) <= kMaxScaled) || !(fabsf(tz) <= kMaxScaled)) return false;
    const int32_t bx = static_cast<int32_t>(floorf(tx)), bz = static_cast<int32_t>(floorf(tz));
    uint32_t rows[8], cols[8];
    uint32_t nr = 0, nc = 0;
    auto push = [](uint32_t* a, uint32_t& n, uint32_t v) {
        for (uint32_t i = 0; i < n; ++i)
            if (a[i] == v) return;
        a[n++] = v;
    };
    for (int32_t d = -1; d <= 2; ++d) {
        uint32_t r0 = static_cast<uint32_t>(bz + d) + off;
        if (r0 > maxIdx) r0 = maxIdx;
        uint32_t r1 = r0 + 1;
        if (r1 > maxIdx) r1 = maxIdx;
        push(rows, nr, r0);
        push(rows, nr, r1);
        uint32_t c0 = static_cast<uint32_t>(bx + d) + off;
        if (c0 > maxIdx) c0 = maxIdx;
        uint32_t c1 = c0 + 1;
        if (c1 > maxIdx) c1 = maxIdx;
        push(cols, nc, c0);
        push(cols, nc, c1);
    }
    // Coalesce only cells actually enumerated by the proof. Insertion order need not be monotonic at the
    // unsigned wrap boundary, so sort the tiny unique column set before forming exact contiguous runs.
    // No gaps or additional game bytes are read; equality remains byte-for-byte, never probabilistic.
    for (uint32_t i = 1; i < nc; ++i) {
        const uint32_t value = cols[i];
        uint32_t j = i;
        while (j != 0 && cols[j - 1] > value) {
            cols[j] = cols[j - 1];
            --j;
        }
        cols[j] = value;
    }
    for (uint32_t i = 0; i < nr; ++i) {
        for (uint32_t j = 0; j < nc;) {
            const uint32_t first = j++;
            while (j < nc && cols[j - 1] != UINT32_MAX && cols[j] == cols[j - 1] + 1) ++j;
            const uint32_t idx = (rows[i] << shift) + cols[first];
            const uint32_t addr = table + idx * 8u, len = (j - first) * 8u;
            // Preserve the original per-cell x86 address wrap when a run crosses 0xffffffff.
            if (addr + len < addr) {
                for (uint32_t k = first; k < j; ++k)
                    fp.Add(table + ((rows[i] << shift) + cols[k]) * 8u, 8);
            } else {
                fp.Add(addr, len);
            }
        }
    }
    return true;
}

// Domain pre-check done BEFORE the original runs: every sample point is clamped to [-L, L], so |t| <= L * scale for every position
// the callback can produce; if that bound is inside the proven domain the post-call sampling cannot leave it (only NaN positions
// remain, which are refused after the call; the call itself writes nothing outside the private graph).
inline bool HeightFieldDomainOk(Fp& fp, uint32_t hf) {
    fp.Add(hf, 0x28);
    const float lim = RdF(hf + 0x1C), scale = RdF(hf + 0x24);
    if (!(lim > 0.0f && lim < 1.0e7f) || !(scale > 0.0f && scale < 1.0e7f)) return false;
    if (!(lim * scale <= 1048576.0f)) return false;
    return Rd32(hf) != 0 && Rd32(hf + 8) < 24;
}

// Gate + footprint for ONE call of the original 0x800210(G; popped node a1, &G.neighbors, &G.nodes).  Runs inside the caller's
// __try (every dereference is a plain read).  `neighborCap` / `nodeCap`: remaining capacity of the private neighbour vector /
// node arena; the call allocates at most one node per edge (+1 for the direct-goal node) and pushes at most as many.
inline PlanStatus PlanExpansion(Fp& fp, const Targets& t, const ntw_path_workspace::Graph& g, const ntw_path_workspace::Node* a1,
                                uint32_t q, uint32_t neighborCap, uint32_t nodeCap, Plan* out) {
    out->maxNodes = 0;
    out->hf = 0;
    const uint32_t o = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(a1->object));
    const ntw_path_workspace::Node* goal = g.goal;
    if (o == 0 || goal == nullptr) return kPlanBadShape;
    if (Rd32(q + 0x34) != 0) return kPlanUnsupported;            // special-goal branch 0x800227
    fp.Add(o + 0x18, 0x24);                                      // +0x1C hash id, +0x20 region, +0x24 gateway, +0x34 count, +0x38 array
    if (o == static_cast<uint32_t>(reinterpret_cast<uintptr_t>(goal->object))) {   // 0x800442 direct goal node
        if (nodeCap < 1 || neighborCap < 1) return kPlanCapacity;
        if (!PlanCtorGateway(fp, t, o)) return kPlanUnsupported;
        out->maxNodes = 1;
        return kPlanOk;
    }
    const uint32_t count = Rd32(o + 0x34);
    if (count >= neighborCap || count >= nodeCap) return kPlanCapacity;
    uint32_t arr = 0;
    if (count != 0) {
        arr = Rd32(o + 0x38);
        if (arr == 0) return kPlanBadShape;
        fp.Add(arr, 4 * count);
    }
    const uint32_t pe = a1->tag;                                 // parent edge (game pointer), [a1+0x10]
    if (pe != 0) fp.Add(pe + 0x10, 4);
    const bool flag124 = g.flag124 == 1;
    const uint32_t rs = Rd32(o + 0x20);
    uint32_t created = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t e = Rd32(arr + 4 * i);
        if (e == 0) return kPlanBadShape;
        fp.Add(e, 0x50);                                         // +4 kind, +0xC door, +0x14 dest, +0x1C segment, +0x24/+0x28, +0x30, +0x4C
        if (!flag124 && Rd8(e + 0x4C) != 1) continue;            // 0x8004E0
        const uint32_t d = Rd32(e + 0x14);
        if (pe != 0 && d == Rd32(pe + 0x10)) continue;           // 0x8004FD
        if (d == 0) return kPlanBadShape;                        // 0x800560 reads [D+0x20] unconditionally
        fp.Add(d + 0x0C, 0x1C);                                  // +0xC iface vptr, +0x10 flag, +0x1C hash id, +0x20 region, +0x24 gateway
        const uint32_t gw = Rd32(e + 0xC);
        bool dl;
        if (gw != 0) {
            dl = true;
        } else {
            const uint32_t g2 = Rd32(d + 0x24);
            dl = false;
            if (g2 != 0) {
                uint8_t al = 0;
                if (!PlanGateByte(fp, t, g2, &al)) return kPlanUnsupported;
                dl = (al == 0);                                  // cmove edx,1 when the getter returned 0
            }
        }
        const uint32_t rd = Rd32(d + 0x20);
        if (dl && Rd8(q + 0x50) != 1) continue;                  // 0x800574
        if (rs != rd && g.regionFlag != 1) continue;             // 0x800588
        if (gw != 0) return kPlanUnsupported;                    // door branch 0x800799
        if (Rd32(e + 4) == 4) return kPlanUnsupported;           // 80EA60 kind 4
        // 80EA60 generic path: 80ABD0 (E+0x24/+0x28, segment S = [E+0x1C]), 57E870 (world W = [[E]+8], plane / height field)
        const uint32_t s = Rd32(e + 0x1C);
        if (s == 0) return kPlanBadShape;
        fp.Add(s + 8, 0xC);
        const uint32_t pt = Rd32(s + 8);
        if (pt == 0) return kPlanBadShape;
        fp.Add(pt + 0xC, 8);
        const uint32_t root = Rd32(e);
        if (root == 0) return kPlanBadShape;
        fp.Add(root, 0xC);
        const uint32_t w = Rd32(root + 8);
        if (w == 0) return kPlanBadShape;
        const uint32_t plane = Rd32(d + 0x24);
        if (plane != 0) {
            fp.Add(plane + 0x30, 0x10);
        } else {
            fp.Add(w + 0x9C, 4);
            const uint32_t hf = Rd32(w + 0x9C);
            if (hf == 0) return kPlanBadShape;
            if (out->hf != 0 && out->hf != hf) return kPlanUnsupported;
            if (out->hf == 0 && !HeightFieldDomainOk(fp, hf)) return kPlanUnsupported;
            out->hf = hf;
        }
        uint8_t acc = 0;
        if (!PlanAccept(fp, t, d, &acc)) return kPlanUnsupported;
        if (acc != 1) {                                          // 0x8005FD
            const uint32_t rg = Rd32(e + 0x20);
            if (rg == 0) continue;
            fp.Add(rg + 0x88, 4);
            if (Rd32(rg + 0x88) != 0) continue;
            fp.Add(rg + 0x180, 4);
            const uint32_t want = Rd32(rg + 0x180);
            if (want != 0 && PlanQueryChain(fp, q) != want) continue;
        }
        if (!PlanCtorGateway(fp, t, d)) return kPlanUnsupported;
        ++created;
    }
    out->maxNodes = created;
    return kPlanOk;
}

}  // namespace npr
