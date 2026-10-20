// Port of the Napoleon Total War formation slot generator (0x62FD60 and callees); see native_formation_layout.h.
// Every float operation follows the order of the approved-image disassembly (SSE scalar ops; x87 where the original uses x87).
// Build: MSVC x86, /O2 /fp:strict /arch:SSE2 (inline __asm is x86 only).
//
// NaN payload exactness: SSE addss/mulss return the DESTINATION operand's NaN when both operands are NaN.  The compiler may
// swap the operands of a commutative operation, so Add/Mul below spell the (dst, src) order of the original instruction out.
#include "native_formation_layout.h"

#include <bit>
#include <cmath>
#include <emmintrin.h>
#include <xmmintrin.h>

namespace ntw_formation_layout {
namespace {

// Constants read from the approved image data (0x1318030, 0x1318038, 0x1318048, 0x131A7B0, 0x13359F8).
constexpr float kFileSlack = 0.001f;   // [0x1318030] = 0x3A83126F
constexpr float kHalf = 0.5f;          // [0x1318038] = 0x3F000000
constexpr float kOne = 1.0f;           // [0x1318048] = 0x3F800000
constexpr float kArcEps = 0.1f;        // [0x131A7B0] = 0x3DCCCCCD
constexpr float kNodeMargin = 0.02f;   // [0x13359F8] = 0x3CA3D70A
constexpr uint32_t kGapFiles = 0x3C;   // 0x18ED164: gap insertion applies when rowLength > 0x3C
constexpr uint32_t kGapPeriod = 60;    // 0x18EF200: unsigned divide by 60

// x87 control word scope (Input::fpuControlWord, 0 = keep the caller's).
struct FpuScope {
    uint16_t saved = 0;
    bool active;
    explicit FpuScope(uint16_t cw) : active(cw != 0) {
        if (active) {
            uint16_t s = 0;
            uint16_t n = cw;
            __asm {
                fnstcw word ptr [s]
                fldcw word ptr [n]
            }
            saved = s;
        }
    }
    ~FpuScope() {
        if (active) {
            uint16_t s = saved;
            __asm { fldcw word ptr [s] }
        }
    }
    FpuScope(const FpuScope&) = delete;
    FpuScope& operator=(const FpuScope&) = delete;
};

inline float Quiet(float x) { return std::bit_cast<float>(std::bit_cast<uint32_t>(x) | 0x00400000u); }
// addss/mulss dst, src: NaN in dst wins, then NaN in src, quieted.
inline float Add(float dst, float src) {
    if (dst != dst) return Quiet(dst);
    if (src != src) return Quiet(src);
    return dst + src;
}
inline float Mul(float dst, float src) {
    if (dst != dst) return Quiet(dst);
    if (src != src) return Quiet(src);
    return dst * src;
}

inline float SqrtSS(float v) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(v))); }
inline int32_t CvttSS(float v) { return _mm_cvttss_si32(_mm_set_ss(v)); }
// (float)(double)(uint32) : cvtdq2pd + [0x1318130 + sign*8] (2^32 table) + cvtpd2ps.
inline float UintToFloat(uint32_t v) { return static_cast<float>(static_cast<double>(v)); }

// 0x642C90 / 0x65A160 truncation: fld; fist; fst; fisub; fstp ; then the sign dependent correction (x87 rounding per control word).
inline int32_t X87Trunc(float x) {
    int32_t rounded = 0;
    uint32_t xbits = 0;
    uint32_t diffbits = 0;
    __asm {
        fld dword ptr [x]
        fist dword ptr [rounded]
        fst dword ptr [xbits]
        fisub dword ptr [rounded]
        fstp dword ptr [diffbits]
    }
    if (static_cast<int32_t>(xbits) < 0) {   // test ecx,ecx ; js
        return rounded + (static_cast<int32_t>(diffbits) > 0 ? 1 : 0);                  // setg cl ; add eax,ecx
    }
    return rounded - (diffbits > 0x80000000u ? 1 : 0);                                  // add edx,0x7fffffff ; sbb eax,0
}

// 0x64C5F0 index: fld; fadd st,st; fadd -0.5f; fistp; sar 1.
inline int32_t X87HalfIndex(float v) {
    float m = -0.5f;
    int32_t r = 0;
    __asm {
        fld dword ptr [v]
        fadd st(0), st(0)
        fadd dword ptr [m]
        fistp dword ptr [r]
    }
    return r >> 1;
}

inline uint32_t MinU(uint32_t a, uint32_t b) { return a >= b ? b : a; }   // cmp a,b ; cmovae a,b

struct Entry {
    uint8_t flag;
    uint32_t cellBegin, cellCount;   // O (surface set)
    float x, z;                      // +8,+0xC
    float sx, sz;                    // +0x10,+0x14
    float width;                     // +0x18
    uint16_t angle;                  // +0x1C
    uint32_t rem;                    // +0x20
};

struct Gen {
    const Input* in;
    Slot* out;
    RankOutline* outline;
    uint32_t capacity;
    uint32_t count;      // out->+8
    uint32_t mark;       // out->+0x10
    uint32_t counter;    // ctx[0x18]
    float carry;         // ctx[0x14]
    float f;             // ctx[4]
    float l8;            // ctx[8]
    float spacingPath;   // ctx[0x10]  (layout+0x14)
    float spacingFile;   // ctx[0x24]  (layout+0x10)
    int status;
};

// ---- 0x10F9A80 / 0x10F9A40: true when the position lies outside the edge a->b (margin per pass) ----
inline bool OutsideEdge(float ax, float az, float bx, float bz, float px, float pz, float margin) {
    const float a0 = ax, a1 = az, a2 = bx, a3 = bz;
    const bool swapped = (a0 > a2) || (a0 == a2 && a1 > a3);
    float p0, p1, q0, q1;
    if (swapped) { p0 = a2; p1 = a3; q0 = a0; q1 = a1; } else { p0 = a0; p1 = a1; q0 = a2; q1 = a3; }
    const float t1x = px - p0;
    const float t1z = pz - p1;
    const float t2x = q0 - p0;
    const float t2z = q1 - p1;
    const float cross = Mul(t2x, t1z) - Mul(t2z, t1x);
    if (!swapped) return cross > margin;
    return cross <= -margin;
}

// ---- 0x80DE00 passes 1 and 2 ----
int FindCell(const Input& in, const Entry& e, float px, float pz) {
    for (int pass = 0; pass < 2; ++pass) {
        for (uint32_t ci = 0; ci < e.cellCount; ++ci) {
            const uint32_t cellIdx = e.cellBegin + ci;
            const SurfaceCell& c = in.cells[cellIdx];
            bool inside = true;
            for (uint32_t j = 0; j < c.nodeCount; ++j) {
                const SurfaceNode& n = in.nodes[c.nodeBegin + j];
                const SurfaceNode& nx = in.nodes[c.nodeBegin + (j + 1 == c.nodeCount ? 0 : j + 1)];
                float margin = 0.0f;
                if (pass == 1 && n.hasLink) margin = kNodeMargin;
                if (OutsideEdge(n.x, n.z, nx.x, nx.z, px, pz, margin)) { inside = false; break; }
            }
            if (inside) return static_cast<int>(cellIdx);
        }
    }
    return -1;
}

// ---- 0x66BB40 -> 0x64C5F0 ----
bool TerrainHeight(const HeightField& H, float x, float z, float* outY) {
    const float h = H.half;
    const float nh = -h;
    float z2;
    if (nh > z) z2 = nh; else if (z > h) z2 = h; else z2 = z;
    float x2;
    if (nh > x) x2 = nh; else if (x > h) x2 = h; else x2 = x;

    const float zs = Mul(z2, H.scale);
    const int32_t izRaw = X87HalfIndex(zs);
    const uint32_t ez = static_cast<uint32_t>(izRaw) + static_cast<uint32_t>(H.base);
    const uint32_t limit = static_cast<uint32_t>(H.limit);
    const uint32_t ebx = MinU(limit, ez);
    const float xs = Mul(x2, H.scale);
    const int32_t ixRaw = X87HalfIndex(xs);
    const uint32_t ex = static_cast<uint32_t>(ixRaw) + static_cast<uint32_t>(H.base);
    const uint32_t ebp = MinU(limit, ex);

    float fx = Mul(UintToFloat(ebp), H.cell);
    fx = fx - H.half;
    fx = x2 - fx;
    fx = Mul(fx, H.scale);
    float fz = Mul(UintToFloat(ebx), H.cell);
    fz = fz - H.half;
    fz = z2 - fz;
    fz = Mul(fz, H.scale);
    if (0.0f > fx) fx = 0.0f; else if (fx > kOne) fx = kOne;
    if (0.0f > fz) fz = 0.0f; else if (fz > kOne) fz = kOne;

    const uint32_t esi = MinU(limit, ebp + 1);
    uint32_t edi = MinU(limit, ebx + 1);
    const float a = kOne - fx;
    const float b = kOne - fz;
    const uint32_t sh = H.shift & 31u;
    edi <<= sh;
    const uint32_t zrow = ebx << sh;
    float w01 = Mul(fx, fz);
    float w10 = Mul(a, fz);
    float w00 = Mul(a, b);
    float w11 = Mul(fx, b);
    const uint32_t i10 = edi + ebp;
    const uint32_t i11 = edi + esi;
    const uint32_t i00 = zrow + ebp;
    const uint32_t i01 = zrow + esi;
    if (i10 >= H.sampleCount || i11 >= H.sampleCount || i00 >= H.sampleCount || i01 >= H.sampleCount) return false;
    w10 = Mul(w10, H.samples[static_cast<size_t>(i10) * 2]);
    w01 = Mul(w01, H.samples[static_cast<size_t>(i11) * 2]);
    w00 = Mul(w00, H.samples[static_cast<size_t>(i00) * 2]);
    w11 = Mul(w11, H.samples[static_cast<size_t>(i01) * 2]);
    float r = Add(w10, w01);
    r = Add(r, w00);
    r = Add(r, w11);
    *outY = r;
    return true;
}

// ---- 0x7F4950 (local->world) ----
inline void FrameForward(const Frame& F, float x, float y, float z, float* o) {
    float ox = Mul(F.fwd[1], y);
    ox = Add(ox, Mul(F.fwd[0], x));
    ox = Add(ox, Mul(F.fwd[2], z));
    ox = Add(ox, F.t[0]);
    float oy = Mul(F.fwd[4], y);
    oy = Add(oy, Mul(x, F.fwd[3]));
    oy = Add(oy, Mul(F.fwd[5], z));
    oy = Add(oy, F.t[1]);
    float oz = Mul(F.fwd[7], y);
    oz = Add(oz, Mul(x, F.fwd[6]));
    oz = Add(oz, Mul(F.fwd[8], z));
    oz = Add(oz, F.t[2]);
    o[0] = ox; o[1] = oy; o[2] = oz;
}

// ---- 0x7F6820 (world->local) ----
inline void FrameInverse(const Frame& F, float x, float y, float z, float* o) {
    const float dx = x - F.t[0];
    const float dy = y - F.t[1];
    const float dz = z - F.t[2];
    float ox = Mul(F.inv[1], dy);
    ox = Add(ox, Mul(F.inv[0], dx));
    ox = Add(ox, Mul(F.inv[2], dz));
    float oy = Mul(F.inv[4], dy);
    oy = Add(oy, Mul(dx, F.inv[3]));
    oy = Add(oy, Mul(F.inv[5], dz));
    float oz = Mul(F.inv[7], dy);
    oz = Add(oz, Mul(F.inv[6], dx));
    oz = Add(oz, Mul(F.inv[8], dz));
    o[0] = ox; o[1] = oy; o[2] = oz;
}

// ---- 0x80DE00 tail: 0x7FCFF0 / 0x57E870 / 0x7EAD80 / 0x7F66F0 ; then 0x80E9D0 for the world position ----
bool MakeSlot(Gen& g, const Entry& e, const float pos[2], Slot* s) {
    const Input& in = *g.in;
    const int cell = FindCell(in, e, pos[0], pos[1]);
    float x = pos[0];
    float z = pos[1];
    float y = 0.0f;
    uint8_t yValid = 1;
    int32_t frame = -1;
    if (cell < 0) {
        if (in.terrain) {
            if (!TerrainHeight(*in.terrain, x, z, &y)) { g.status = kBadInput; return false; }
        } else {
            yValid = 0;
        }
    } else {
        const float* pl = in.cells[cell].plane;
        // 0x57E870: ((p38 * z) + (p30 * x)) + p3c, / p34, sign flip afterwards.
        float v = Add(Mul(pl[2], z), Mul(pl[0], x));
        v = Add(v, pl[3]);
        v = v / pl[1];
        y = -v;
        frame = in.cells[cell].frame;
        if (frame >= 0) {
            float o[3];
            FrameInverse(in.frames[frame], x, y, z, o);
            x = o[0]; y = o[1]; z = o[2];
        }
    }
    s->flag = e.flag;
    s->x = x; s->y = y; s->z = z;
    s->cell = cell;
    s->frame = frame;
    s->angle = e.angle;
    s->yValid = yValid;
    if (frame >= 0) {
        float w[3];
        FrameForward(in.frames[frame], x, y, z, w);
        s->worldX = w[0]; s->worldY = w[1]; s->worldZ = w[2];
    } else {
        s->worldX = x; s->worldY = y; s->worldZ = z;
    }
    return true;
}

// 0x65D150 via 0x629B30: mark := count when the flag is set, then push_back.
bool PushSlot(Gen& g, const Slot& s, bool markFlag) {
    if (g.count >= g.capacity) { g.status = kCapacity; return false; }
    if (markFlag) g.mark = g.count;
    g.out[g.count++] = s;
    return true;
}

// ---- 0x18ED164: gap insertion (x87 fild/fmul/fadd/fstp in the control word of the game thread) ----
void ModGap(float* pos, const Entry& e, uint32_t rowLen, uint32_t col, uint32_t row) {
    if (rowLen <= kGapFiles) return;
    uint32_t idx = rowLen >> 1;
    if ((col & 1u) == 0) idx += col >> 1; else idx = idx - 1 - (col >> 1);
    if ((rowLen & 1u) != 0 && (row & 1u) != 0) idx = rowLen - 1 - idx;
    const uint32_t k = idx / kGapPeriod;
    const uint32_t K = (rowLen - 1) / kGapPeriod;
    const uint32_t d = (k + k - K) << 1;
    if (d == 0) return;
    const int32_t gapSteps = static_cast<int32_t>(d);
    const float sx = e.sx;
    const float sz = e.sz;
    float px = pos[0];
    float pz = pos[1];
    __asm {
        fild dword ptr [gapSteps]
        fmul dword ptr [sx]
        fadd dword ptr [px]
        fstp dword ptr [px]
        fild dword ptr [gapSteps]
        fmul dword ptr [sz]
        fadd dword ptr [pz]
        fstp dword ptr [pz]
    }
    pos[0] = px;
    pos[1] = pz;
}

// ---- 0x619EB0 ----
uint32_t EmitColumn(Gen& g, const Entry& e, uint32_t rowLen, uint32_t count, float spacing) {
    const bool firstFlag = (g.counter == 0);
    float cx, cz;                         // initial position
    if ((count & 1u) == 0) {
        const float h = Mul(spacing, kHalf);
        if ((g.count & 1u) == 0) {
            cx = Add(Mul(e.sx, h), e.x);
            cz = Add(Mul(e.sz, h), e.z);
        } else {
            const float xx = Mul(e.sx, h);
            const float zz = Mul(e.sz, h);
            cx = e.x - xx;
            cz = e.z - zz;
        }
    } else {
        cx = e.x;
        cz = e.z;
    }
    float A[2] = {cx, cz};
    float B[2] = {cx, cz};
    float C[2] = {cx, cz};
    const uint32_t row0 = g.count / rowLen;
    const uint32_t col0 = g.count % rowLen;
    if (g.in->modActive) ModGap(C, e, rowLen, col0, row0);
    {
        Slot s{};
        if (!MakeSlot(g, e, C, &s)) return 0;
        if (!PushSlot(g, s, firstFlag)) return 0;
    }
    uint32_t rem = e.rem - 1;
    if (count - 1 == 0) return rem;
    uint32_t done = 0;
    do {
        const uint32_t oc = g.count;
        if (oc / rowLen != row0) return rem;
        const float sx = Mul(e.sx, spacing);
        const float sz = Mul(e.sz, spacing);
        float* cur;
        if ((oc & 1u) != 0) {
            B[0] = B[0] - sx;
            B[1] = B[1] - sz;
            cur = B;
        } else {
            A[0] = Add(A[0], sx);
            A[1] = Add(A[1], sz);
            cur = A;
        }
        float P[2] = {cur[0], cur[1]};
        if (g.in->modActive) ModGap(P, e, rowLen, oc % rowLen, row0);
        Slot s{};
        if (!MakeSlot(g, e, P, &s)) return 0;
        if (!PushSlot(g, s, false)) return 0;
        ++done;
        --rem;
    } while (done < count - 1);
    return rem;
}

// ---- 0x642C90 ----
uint32_t FilesPerRow(float w, float l8, float l10) {
    float x = Add(w, kFileSlack);
    x = x - l8;
    x = x / l10;
    const uint32_t r = static_cast<uint32_t>(X87Trunc(x)) + 1u;
    return r < 1u ? 1u : r;
}

// ---- 0x65A410 (ctx vfn0) + 0x65A3F0 (counter++) ----
template<bool OutlineOnly>
uint32_t StepEntry(Gen& g, const Entry& e) {
    const float w = (e.width < g.f) ? e.width : g.f;     // minss xmm0(width), [ctx+4]
    const uint32_t files = FilesPerRow(w, g.l8, g.spacingFile);
    uint32_t cnt = files;
    if (e.rem < files) cnt = e.rem;
    if (cnt < 1u) cnt = 1u;
    uint32_t r;
    if constexpr (OutlineOnly) {
        const uint32_t emitted = MinU(cnt, files - g.count % files);
        if (!g.count) g.outline->files = emitted;
        g.outline->rearX = e.x; g.outline->rearZ = e.z;
        g.outline->forwardX = -e.sz; g.outline->forwardZ = e.sx;
        g.outline->angle = e.angle;
        g.count += emitted;
        r = e.rem - emitted;
    } else {
        r = EmitColumn(g, e, files, cnt, g.spacingFile);
    }
    ++g.counter;
    return r;
}

// ---- 0x659F00 (class A vfn18) ----
template<bool OutlineOnly>
uint32_t WalkA(Gen& g, const Piece& c, float posx, float posz, uint32_t rem) {
    const float dx = c.p1[0] - c.p0[0];
    const float dz = c.p1[1] - c.p0[1];
    const float dirz = c.dir[1];
    const float dirx = c.dir[0];
    const float sq = Add(Mul(dx, dx), Mul(dz, dz));
    float Pz = Add(Mul(dirz, g.carry), posz);
    const float len = SqrtSS(sq);
    float Px = Add(posx, Mul(g.carry, dirx));
    float u = Add(Mul(dirz, Pz - c.p0[1]), Mul(dirx, Px - c.p0[0]));
    u = u / len;
    if (u > kOne) {
        u = u - kOne;
        u = Mul(u, len);
        g.carry = u;
        return rem;
    }
    const float spacing = g.spacingPath;
    const float remF = Mul(kOne - u, len);
    const uint8_t flag = (u >= 0.0f) ? 1 : 0;
    const int32_t n = CvttSS(remF / spacing);
    const uint32_t total = static_cast<uint32_t>(n) + 1u;
    uint32_t r = rem;
    if (total != 0) {
        uint32_t idx = 0;
        do {
            Entry e{};
            e.flag = flag;
            e.cellBegin = c.cellBegin; e.cellCount = c.cellCount;
            e.x = Px; e.z = Pz;
            e.sx = c.step[0]; e.sz = c.step[1];
            e.width = c.width;
            e.angle = c.angle;
            e.rem = r;
            r = StepEntry<OutlineOnly>(g, e);
            if (r == 0) return 0;
            const float mx = Mul(dirx, spacing);
            const float mz = Mul(dirz, spacing);
            Px = Add(Px, mx);
            Pz = Add(Pz, mz);
            ++idx;
        } while (idx < total);
    }
    if (r == 0) return r;
    const float left = remF - Mul(UintToFloat(static_cast<uint32_t>(n)), spacing);
    if (!(left > 0.0f)) g.carry = 0.0f;
    else g.carry = spacing - left;
    return r;
}

// ---- 0x63A120 ----
inline void ArcDirection(const Piece& c, float px, float pz, float* o) {
    if (c.mode == 2) {
        const float dx = c.center[0] - px;
        const float dz = c.center[1] - pz;
        const float len = SqrtSS(Add(Mul(dz, dz), Mul(dx, dx)));
        const float inv = kOne / len;
        o[1] = Mul(inv, dz);
        o[0] = Mul(inv, dx);
    } else {
        float dx = px - c.center[0];
        float dz = pz - c.center[1];
        const float len = SqrtSS(Add(Mul(dz, dz), Mul(dx, dx)));
        dx = dx / len;
        dz = dz / len;
        o[0] = dx;
        o[1] = dz;
    }
}

// ---- 0x65A160 (class B vfn18) ----
template<bool OutlineOnly>
uint32_t WalkB(Gen& g, const Piece& c, float posx, float posz, uint32_t rem) {
    const float dirx = c.dir[0];
    const float dirz = c.dir[1];
    const float cdx = Mul(g.carry, dirx);
    const float cdz = Mul(g.carry, dirz);
    float Px = Add(posx, cdx);
    float Pz = Add(posz, cdz);
    const float a = c.p1[0] - Px;
    const float b = c.p1[1] - Pz;
    const float t = Add(Mul(dirz, b), Mul(dirx, a));
    if (0.0f > t) {
        g.carry = -t;
        return rem;
    }
    const float s = Add(Mul(Pz - c.center[1], dirx), Mul(dirz, c.center[0] - Px));
    if (kArcEps > std::fabs(s)) return rem;
    const float spacing = g.spacingPath;
    const int32_t n = X87Trunc(t / spacing);
    const uint32_t total = static_cast<uint32_t>(n) + 1u;
    uint32_t r = rem;
    uint32_t idx = 0;
    if (total != 0) {
        do {
            float o[2];
            ArcDirection(c, Px, Pz, o);
            float V[2];
            if (c.mode == 2) { V[0] = -o[0]; V[1] = -o[1]; } else { V[0] = o[0]; V[1] = o[1]; }
            const float hw = Mul(c.arcWidth, kHalf);
            const float ex = Add(Mul(hw, V[0]), c.center[0]);
            const float ez = Add(Mul(hw, V[1]), c.center[1]);
            Entry e{};
            e.flag = 1;
            e.cellBegin = c.cellBegin; e.cellCount = c.cellCount;
            e.x = ex; e.z = ez;
            e.sx = o[0]; e.sz = o[1];
            e.width = c.arcWidth;
            e.angle = c.angle;
            e.rem = r;
            r = StepEntry<OutlineOnly>(g, e);
            if (r == 0) return 0;
            const float mz = Mul(spacing, dirz);
            const float mx = Mul(spacing, dirx);
            Px = Add(Px, mx);
            Pz = Add(Pz, mz);
            ++idx;
        } while (idx < total);
    }
    const float left = t - Mul(UintToFloat(total - 1u), spacing);
    g.carry = spacing - left;
    return r;
}

bool Validate(const Input& in) {
    if (in.pieceCount && !in.pieces) return false;
    if (in.cellCount && !in.cells) return false;
    if (in.nodeCount && !in.nodes) return false;
    if (in.frameCount && !in.frames) return false;
    if (in.origin.frame < -1 || (in.origin.frame >= 0 && static_cast<uint32_t>(in.origin.frame) >= in.frameCount)) return false;
    for (uint32_t i = 0; i < in.cellCount; ++i) {
        const SurfaceCell& c = in.cells[i];
        if (c.nodeCount == 0) return false;
        if (c.nodeBegin > in.nodeCount || c.nodeCount > in.nodeCount - c.nodeBegin) return false;
        if (c.frame < -1 || (c.frame >= 0 && static_cast<uint32_t>(c.frame) >= in.frameCount)) return false;
    }
    for (uint32_t i = 0; i < in.pieceCount; ++i) {
        const Piece& p = in.pieces[i];
        if (p.isArc > 1) return false;
        if (p.cellBegin > in.cellCount || p.cellCount > in.cellCount - p.cellBegin) return false;
    }
    if (in.terrain && !in.terrain->samples && in.terrain->sampleCount) return false;
    return true;
}

}  // namespace

template<bool OutlineOnly>
static int GenerateImpl(const Input& in, Slot* out, uint32_t capacity, Result* result, RankOutline* outline) {
    if (!result || (!OutlineOnly && !out && capacity)) return kBadInput;
    result->count = 0;
    result->mark = 0;
    if (!Validate(in)) return kBadInput;
    if (capacity < in.men) return kCapacity;

    FpuScope fpu(in.fpuControlWord);

    Gen g{};
    g.in = &in;
    g.out = out;
    g.capacity = capacity;
    g.outline = outline;
    g.carry = 0.0f;
    g.f = in.f;
    g.l8 = in.layout8;
    g.spacingPath = in.layout14;
    g.spacingFile = in.layout10;
    g.status = kOk;

    // 0x659E70
    uint32_t rem = in.men;
    for (uint32_t i = 0; i < in.pieceCount; ++i) {
        if (rem == 0) break;
        const Piece& p = in.pieces[i];
        float pos[2];
        if (i == 0) {
            // 0x80E9D0(container+0x18): world position of the origin object; {x, z} are passed on.
            if (in.origin.frame >= 0) {
                float w[3];
                FrameForward(in.frames[in.origin.frame], in.origin.x, in.origin.y, in.origin.z, w);
                pos[0] = w[0];
                pos[1] = w[2];
            } else {
                pos[0] = in.origin.x;
                pos[1] = in.origin.z;
            }
        } else if (p.isArc) {
            pos[0] = p.arcStart[0];   // 0x63BF90
            pos[1] = p.arcStart[1];
        } else {
            pos[0] = p.p0[0];         // 0x63BF70
            pos[1] = p.p0[1];
        }
        rem = p.isArc ? WalkB<OutlineOnly>(g, p, pos[0], pos[1], rem) : WalkA<OutlineOnly>(g, p, pos[0], pos[1], rem);
        if (g.status != kOk) break;
    }
    result->count = g.count;
    result->mark = g.mark;
    return g.status;
}

int Generate(const Input& in, Slot* out, uint32_t capacity, Result* result) {
    return GenerateImpl<false>(in, out, capacity, result, nullptr);
}

int Outline(const Input& in, RankOutline* result) {
    if (!result) return kBadInput;
    *result = {};
    Result generated{};
    const int status = GenerateImpl<true>(in, nullptr, in.men, &generated, result);
    result->count = generated.count;
    return status;
}

void ToSlotArrays(const Slot* slots, uint32_t count, float* slotX, float* slotZ, uint16_t* slotAngle) {
    for (uint32_t i = 0; i < count; ++i) {
        slotX[i] = slots[i].worldX;
        slotZ[i] = slots[i].worldZ;
        slotAngle[i] = slots[i].angle;
    }
}

}  // namespace ntw_formation_layout
