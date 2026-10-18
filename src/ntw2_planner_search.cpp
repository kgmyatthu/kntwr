#include "ntw2_planner_search.h"
#include "ntw2_record_test.h"
#include <emmintrin.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string.h>

// Bit-identical replacement of 0x10EC150 (OBB vs circular polygon) behind 0x80DCF0 kind 0. Every rounding-relevant operation is
// the SAME single-precision SSE operation with the SAME grouping as the native code (spec section 9/10); the native x87
// `fld m32; fabs; fstp m32` triplets of the first-vertex test are executed for real. The vector part (point-in-polygon and the
// four OBB edges against every polygon edge, 4 edges per step) only runs on inputs for which spec section 10.1 proves that no
// operation can raise any floating-point flag other than the inexact flag that the entry guard requires to be set already.
namespace ntw2_poly {
namespace {
using U = uint32_t;
constexpr float kHalf = 0.5f, kOne = 1.0f;
// Coordinate domain G = {0} U [2^-12, 2^14] by magnitude (bit patterns). Spec 10.1: with a=12, b=14 (a+b<=26) every difference, product,
// determinant, numerator, reciprocal and s/u stays normal and finite, so no per-lane bound check is needed.
constexpr U kCoordLo = 0x39800000u;   // 2^-12
constexpr U kCoordHi = 0x46800000u;   // 2^14 (inclusive)

inline U Bits(float f) { U u; memcpy(&u, &f, 4); return u; }
inline float Flt(U u) { float f; memcpy(&f, &u, 4); return f; }
inline bool InG(float v) { const U b = Bits(v) & 0x7fffffffu; return b == 0 || (b - kCoordLo) <= (kCoordHi - kCoordLo); }
inline float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline float Mul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
// The native triplet, executed for real so NaN/denormal inputs behave (and flag) exactly like the original.
__declspec(noinline) float AbsX87(float v) {
    float r;
    __asm {
        fld dword ptr [v]
        fabs
        fstp dword ptr [r]
    }
    return r;
}
bool FpGuard() {
    const unsigned csr = _mm_getcsr();
    if ((csr & 0x1f80u) != 0x1f80u || !(csr & 0x20u)) return false; // masks all set, inexact already sticky
    unsigned short cw = 0, sw = 0;
    __asm {
        fnstcw cw
        fnstsw sw
    }
    return (cw & 0x3f) == 0x3f && !(sw & 0x3800);
}
inline __m128 Sel(__m128 m, __m128 a, __m128 b) { return _mm_or_ps(_mm_and_ps(m, a), _mm_andnot_ps(m, b)); }
// Lanes whose magnitude is outside G (integer compares: no floating-point flag can be raised, NaN/Inf/denormal are outside).
inline __m128i OutsideG(__m128 v) {
    const __m128i a = _mm_and_si128(_mm_castps_si128(v), _mm_set1_epi32(0x7fffffff));
    const __m128i in = _mm_and_si128(_mm_cmpgt_epi32(a, _mm_set1_epi32(static_cast<int>(kCoordLo) - 1)),
                                     _mm_cmplt_epi32(a, _mm_set1_epi32(static_cast<int>(kCoordHi) + 1)));
    return _mm_xor_si128(_mm_or_si128(in, _mm_cmpeq_epi32(a, _mm_setzero_si128())), _mm_set1_epi32(-1));
}

// x[n]=x[0], z[n]=z[0] (the wrap edge's end), everything after that zero; lanes >= n of the last block are masked out of every result.
struct Poly {
    float *x, *z;   // 16-byte aligned views into the module buffer (x[n]=x[0], zeros up to padded+8)
    U n, padded;
};
constexpr U kStride = kMaxVertices + 16;     // floats per coordinate array (multiple of 4)
float* gBuffer;                              // 2*kStride floats, VirtualAlloc'd by Configure (never in a tick)
volatile LONG gBusy = 1;                     // 0 = free; 1 = in use, or locked (no buffer)
struct Claim {
    bool held;
    Claim() : held(_InterlockedCompareExchange(&gBusy, 1, 0) == 0) {}
    ~Claim() { if (held) _InterlockedExchange(&gBusy, 0); }
};
struct Seg { __m128 b1x, b1z, bx, bz; };
inline Seg MakeSeg(float b1x, float b1z, float b2x, float b2z) {
    return Seg{_mm_set1_ps(b1x), _mm_set1_ps(b1z), _mm_set1_ps(Sub(b2x, b1x)), _mm_set1_ps(Sub(b2z, b1z))};
}
// Native 0x559C10(B=seg, A=(cur->next), flags 0, eps 0) for four edges: the lanes that intersect.
inline __m128 SegHit(const Seg& s, __m128 x0, __m128 z0, __m128 dxA, __m128 dzA) {
    const __m128 zero = _mm_setzero_ps(), one = _mm_set1_ps(kOne);
    const __m128 det = _mm_sub_ps(_mm_mul_ps(dzA, s.bx), _mm_mul_ps(dxA, s.bz));
    const __m128 ok = _mm_cmpgt_ps(_mm_andnot_ps(_mm_set1_ps(-0.0f), det), zero);
    const __m128 inv = _mm_div_ps(one, _mm_or_ps(det, _mm_andnot_ps(ok, one))); // native never divides by zero
    const __m128 xx = _mm_sub_ps(s.b1x, x0), zz = _mm_sub_ps(s.b1z, z0);
    const __m128 sv = _mm_mul_ps(_mm_sub_ps(_mm_mul_ps(zz, dxA), _mm_mul_ps(xx, dzA)), inv);
    const __m128 uv = _mm_mul_ps(_mm_sub_ps(_mm_mul_ps(zz, s.bx), _mm_mul_ps(xx, s.bz)), inv);
    return _mm_and_ps(_mm_and_ps(ok, _mm_and_ps(_mm_cmpge_ps(sv, zero), _mm_cmple_ps(sv, one))),
                      _mm_and_ps(_mm_cmpge_ps(uv, zero), _mm_cmple_ps(uv, one)));
}
inline __m128 TailMask(U i, U n) {
    return _mm_castsi128_ps(_mm_cmplt_epi32(_mm_add_epi32(_mm_set1_epi32(static_cast<int>(i)), _mm_setr_epi32(0, 1, 2, 3)),
                                            _mm_set1_epi32(static_cast<int>(n))));
}
// Native 0x10E7030(P, (px,pz)) == 1 (even-odd crossing parity over every edge).
bool Inside(const Poly& p, float px, float pz) {
    const __m128 pxv = _mm_set1_ps(px), pzv = _mm_set1_ps(pz);
    U parity = 0;
    for (U i = 0; i < p.padded; i += 4) {
        const __m128 x0 = _mm_load_ps(p.x + i), z0 = _mm_load_ps(p.z + i), x1 = _mm_loadu_ps(p.x + i + 1), z1 = _mm_loadu_ps(p.z + i + 1);
        const __m128 gt = _mm_cmpgt_ps(z0, z1);
        const __m128 c1 = _mm_and_ps(_mm_cmpge_ps(pzv, z1), _mm_cmpgt_ps(z0, pzv));
        const __m128 c2 = _mm_and_ps(_mm_cmpge_ps(pzv, z0), _mm_cmpgt_ps(z1, pzv));
        __m128 active = _mm_or_ps(_mm_and_ps(gt, c1), _mm_andnot_ps(gt, c2));
        if (i + 4 > p.n) active = _mm_and_ps(active, TailMask(i, p.n));
        const __m128 xL = Sel(gt, x1, x0), zL = Sel(gt, z1, z0), zH = Sel(gt, z0, z1), xH = Sel(gt, x0, x1);
        const __m128 a = _mm_mul_ps(_mm_sub_ps(pxv, xL), _mm_sub_ps(zH, zL));
        const __m128 b = _mm_mul_ps(_mm_sub_ps(pzv, zL), _mm_sub_ps(xH, xL));
        const unsigned m = static_cast<unsigned>(_mm_movemask_ps(_mm_and_ps(active, _mm_cmpgt_ps(b, a))));
        parity ^= (0x6996u >> m) & 1u;
    }
    return parity != 0;
}
// One OBB edge (native pass 1: its corners are derived lazily after the point-in-polygon test).
bool Pass1(const Poly& p, const Seg& s) {
    for (U i = 0; i < p.padded; i += 4) {
        const __m128 x0 = _mm_load_ps(p.x + i), z0 = _mm_load_ps(p.z + i);
        __m128 hit = SegHit(s, x0, z0, _mm_sub_ps(_mm_loadu_ps(p.x + i + 1), x0), _mm_sub_ps(_mm_loadu_ps(p.z + i + 1), z0));
        if (i + 4 > p.n) hit = _mm_and_ps(hit, TailMask(i, p.n));
        if (_mm_movemask_ps(hit)) return true;
    }
    return false;
}
// Native passes 2, 3, 4 (their corners d0/d1 exist once pass 1 missed): one traversal, same per-lane operations, OR of the three.
bool Passes234(const Poly& p, const Seg& s2, const Seg& s3, const Seg& s4) {
    for (U i = 0; i < p.padded; i += 4) {
        const __m128 x0 = _mm_load_ps(p.x + i), z0 = _mm_load_ps(p.z + i);
        const __m128 dxA = _mm_sub_ps(_mm_loadu_ps(p.x + i + 1), x0), dzA = _mm_sub_ps(_mm_loadu_ps(p.z + i + 1), z0);
        __m128 hit = _mm_or_ps(SegHit(s2, x0, z0, dxA, dzA), _mm_or_ps(SegHit(s3, x0, z0, dxA, dzA), SegHit(s4, x0, z0, dxA, dzA)));
        if (i + 4 > p.n) hit = _mm_and_ps(hit, TailMask(i, p.n));
        if (_mm_movemask_ps(hit)) return true;
    }
    return false;
}
}

Reason Evaluate(const void* shape, const void* polygon, unsigned char* result, uint32_t* vertices) {
    if (vertices) *vertices = 0;
    if (static_cast<const U*>(shape)[0] != 0) return FallKind;
    if (!FpGuard()) return FallFp;
    const float* S = static_cast<const float*>(shape) + 1; // OBB: S[0..8]
    const float* pn = static_cast<const float*>(polygon);
    // Stage 1: first polygon vertex inside the OBB (native 10EC15B..10EC1DF, same ops, real x87 abs).
    const float dx = Sub(pn[3], S[0]), dz = Sub(pn[4], S[1]);
    const float pa = AbsX87(Add(Mul(S[6], dz), Mul(dx, S[5])));
    if (_mm_comige_ss(_mm_set_ss(Mul(S[3], kHalf)), _mm_set_ss(pa))) {
        const float pb = AbsX87(Add(Mul(S[8], dz), Mul(S[7], dx)));
        if (_mm_comige_ss(_mm_set_ss(Mul(S[4], kHalf)), _mm_set_ss(pb))) { *result = 1; return Served; }
    }
    // Stage 2 (native 10EC1E5..): half extents and corner 0.
    const float hBx = Mul(Mul(S[7], S[4]), kHalf), hBz = Mul(Mul(S[8], S[4]), kHalf);
    const float hAx = Mul(Mul(S[5], S[3]), kHalf), hAz = Mul(Mul(S[6], S[3]), kHalf);
    const float c0x = Sub(Add(S[0], hBx), hAx), c0z = Sub(Add(S[1], hBz), hAz);
    if (!InG(c0x) || !InG(c0z)) return FallDomain;
    Claim claim;
    if (!claim.held || !gBuffer) return FallBusy; // a locked (released/unconfigured) module also lands here: gBusy stays 1
    Poly p;
    p.x = gBuffer; p.z = gBuffer + kStride;
    {
        const U* node = static_cast<const U*>(polygon);
        U n = 0;
        do {
            if (n == kMaxVertices) return FallWalkCap;
            p.x[n] = Flt(node[3]); p.z[n] = Flt(node[4]); ++n;
            node = reinterpret_cast<const U*>(node[2]);
        } while (node != static_cast<const U*>(polygon));
        if (vertices) *vertices = n;
        p.n = n; p.padded = (n + 3) & ~3u;
        p.x[n] = p.x[0]; p.z[n] = p.z[0];
        for (U i = n + 1; i < p.padded + 8; ++i) { p.x[i] = 0; p.z[i] = 0; }
        __m128i bad = _mm_setzero_si128();
        for (U i = 0; i < p.padded; i += 4)
            bad = _mm_or_si128(bad, _mm_or_si128(OutsideG(_mm_load_ps(p.x + i)), OutsideG(_mm_load_ps(p.z + i))));
        if (_mm_movemask_epi8(bad)) return FallDomain; // NaN/Inf/denormal/huge/tiny coordinate: native
    }
    if (Inside(p, c0x, c0z)) { *result = 1; return Served; }
    // Pass 1: c0 -> c1.
    const float c1x = Add(Add(S[0], hBx), hAx), c1z = Add(Add(S[1], hBz), hAz);
    if (!InG(c1x) || !InG(c1z)) return FallDomain;
    if (Pass1(p, MakeSeg(c0x, c0z, c1x, c1z))) { *result = 1; return Served; }
    // Passes 2..4: d1 -> d0, d0 -> c0 (0x10E9450 segment), c1 -> d1 (0x65D890 segment).
    const float d0x = Sub(Sub(S[0], hBx), hAx), d0z = Sub(Sub(S[1], hBz), hAz);
    const float d1x = Add(Sub(S[0], hBx), hAx), d1z = Add(Sub(S[1], hBz), hAz);
    if (!InG(d0x) || !InG(d0z) || !InG(d1x) || !InG(d1z)) return FallDomain;
    *result = Passes234(p, MakeSeg(d1x, d1z, d0x, d0z), MakeSeg(d0x, d0z, c0x, c0z), MakeSeg(c1x, c1z, d1x, d1z)) ? 1 : 0;
    return Served;
}

volatile uint32_t words[kWords];
namespace {
Native nativeKernel;
uint32_t gMode;
inline void Bump(uint32_t i) { words[i] = words[i] + 1; }
inline void Account(Reason why, uint32_t vertices, unsigned char result) {
    if (why == Served) {
        Bump(3);
        if (result) Bump(12);
        words[13] = words[13] + vertices;
        if (vertices > words[14]) words[14] = vertices;
        Bump(vertices <= 16 ? 15 : vertices <= 64 ? 16 : vertices <= 256 ? 17 : 18);
        if (vertices > 256) Bump(vertices <= 1024 ? 21 : vertices <= 4096 ? 22 : vertices <= 16384 ? 23 : 24);
    } else if (why == FallBusy) Bump(25);
    else Bump(3 + static_cast<uint32_t>(why)); // FallKind..FallWalkCap -> words 4..7
}
}
namespace { uint64_t gServedFast, gSampledNative, gSampledFast, gFallbackNative; uint32_t gSampled, gServedCount; void Calibrate(); }
void Release() {
    // Claim the in-use flag for good: an in-flight evaluation keeps its buffer (nothing is freed), otherwise the buffer goes and the
    // flag stays locked so a late call can only answer FallBusy.
    if (_InterlockedCompareExchange(&gBusy, 1, 0) != 0) return;
    if (gBuffer) { VirtualFree(gBuffer, 0, MEM_RELEASE); gBuffer = nullptr; }
}
void Configure(Native native, uint32_t mode) {
    nativeKernel = native; gMode = mode;
    for (uint32_t i = 0; i < kWords; ++i) words[i] = 0;
    if (mode == ModeOff) { Release(); return; }
    words[0] = 1; words[1] = mode;
    gServedFast = gSampledNative = gSampledFast = gFallbackNative = 0; gSampled = gServedCount = 0;
    Calibrate();
    if (!gBuffer) gBuffer = static_cast<float*>(VirtualAlloc(nullptr, 2u * kStride * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (gBuffer) _InterlockedExchange(&gBusy, 0); // a failed allocation leaves the module locked: every call is a counted native FallBusy
}
void NoteObserver(bool routed) { if (gMode) Bump(routed ? 19 : 20); }
namespace {
// Timing (rdtsc, no QPC per call; the calibration at Configure is the only QPC use and changes no behaviour). 64-bit accumulators,
// published >> 10 (kilocycles, modulo 2^32). Row words: 26 served fast kcycles, 27/28 sampled native/fast kcycles, 29 sampled calls,
// 30 native kcycles of fallback calls, 31 tsc ticks per microsecond.
inline void Publish() {
    words[26] = static_cast<uint32_t>(gServedFast >> 10); words[27] = static_cast<uint32_t>(gSampledNative >> 10);
    words[28] = static_cast<uint32_t>(gSampledFast >> 10); words[29] = gSampled; words[30] = static_cast<uint32_t>(gFallbackNative >> 10);
}
void Calibrate() {
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
    const unsigned __int64 t0 = __rdtsc();
    do QueryPerformanceCounter(&b); while ((b.QuadPart - a.QuadPart) * 1000 < f.QuadPart); // ~1 ms
    const unsigned __int64 t1 = __rdtsc();
    const double us = 1e6 * static_cast<double>(b.QuadPart - a.QuadPart) / static_cast<double>(f.QuadPart);
    words[31] = us > 0 ? static_cast<uint32_t>(static_cast<double>(t1 - t0) / us + 0.5) : 0;
}
}
unsigned char __fastcall Gate(void* shape, void*, void* polygon) {
    // Inside ntw2_record_test::Entry (the alternate placement delegate 0x13376AC route, --ai-record-test*) the call is accounted into that
    // module's row and follows ITS mode; everything else (the default observer route, R2/R3 walk sites) keeps this module's row and mode.
    const bool alt = ntw2_record_test::InScope();
    if (!alt) Bump(2);
    unsigned char fast = 0; uint32_t v = 0;
    const bool shadow = alt ? ntw2_record_test::Shadow() : gMode == ModeShadow;
    // Shadow samples every served call; live samples every 32nd served call (by count, never by time): both start from the identical FP
    // state, native runs last on the sampled call and is compared; live then restores the fast path's state and returns the fast AL.
    const bool sample = shadow || (((alt ? ntw2_record_test::NextServedIndex() : gServedCount) + 1) & 31u) == 0;
    alignas(16) unsigned char initial[512], afterFast[512], afterNative[512];
    if (sample) _fxsave(initial);
    const unsigned __int64 t0 = __rdtsc();
    const Reason why = Evaluate(shape, polygon, &fast, &v);
    const unsigned __int64 t1 = __rdtsc();
    if (alt) ntw2_record_test::Account(static_cast<uint32_t>(why), v, fast); else Account(why, v, fast);
    if (why != Served) {
        if (sample) _fxrstor(initial);
        const unsigned __int64 t2 = __rdtsc();
        const unsigned char native = nativeKernel(shape, nullptr, polygon);
        if (alt) { ntw2_record_test::NoteFallbackNative(__rdtsc() - t2); ntw2_record_test::Publish(); }
        else { gFallbackNative += __rdtsc() - t2; Publish(); }
        return native;
    }
    if (alt) ntw2_record_test::NoteServed(t1 - t0); else { ++gServedCount; gServedFast += t1 - t0; }
    if (!sample) { if (!alt) Publish(); return fast; }
    _fxsave(afterFast);
    _fxrstor(initial);
    const unsigned __int64 t2 = __rdtsc();
    const unsigned char native = nativeKernel(shape, nullptr, polygon);
    const unsigned __int64 t3 = __rdtsc();
    _fxsave(afterNative);
    if (alt) {
        ntw2_record_test::NoteCompare(native != fast, memcmp(afterFast, afterNative, 5) != 0, memcmp(afterFast + 24, afterNative + 24, 4) != 0,
                                      t3 - t2, t1 - t0);
        ntw2_record_test::Publish();
    } else {
        Bump(8);
        if (native != fast) Bump(9);
        if (memcmp(afterFast, afterNative, 5)) Bump(10);
        if (memcmp(afterFast + 24, afterNative + 24, 4)) Bump(11);
        gSampledNative += t3 - t2; gSampledFast += t1 - t0; ++gSampled;
        Publish();
    }
    if (shadow) return native;
    _fxrstor(afterFast);
    return fast;
}
}
