#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <xmmintrin.h>
#include <cstring>
#include <algorithm>
#include <unordered_map>
#include "native_resolve.h"
#pragma fenv_access(on)

namespace kntwr_resolve {
namespace {
static_assert(sizeof(void*) == 4, "native resolve is x86 only");
using U = uint32_t;
using B = uint8_t;
Binding binding{};
U words[WordCount]{};
U frame_words[FrameWordCount]{};
volatile LONG owner_thread;
U previous_owner;
bool pending, have_inout;
U shadow_depth;
B observed_inout;
Agent* original;
AgentView saved{};
Candidates captured;
Aabb saved_box;
LARGE_INTEGER frequency{};
LONGLONG capture_ticks;

U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void* Pointer(U p) { return reinterpret_cast<void*>(p); }
template<class T> T Load(const void* p, size_t off) {
    T value; std::memcpy(&value, static_cast<const B*>(p) + off, sizeof(value)); return value;
}
template<class T> T Load(U p, size_t off) { return Load<T>(Pointer(p), off); }
U Bits(float f) { U u; std::memcpy(&u, &f, 4); return u; }
float Float(U u) { float f; std::memcpy(&f, &u, 4); return f; }
float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Mul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Div(float a, float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Sqrt(float a) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(a))); }
float Min(float a, float b) { return _mm_cvtss_f32(_mm_min_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Max(float a, float b) { return _mm_cvtss_f32(_mm_max_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Neg(float a) { return Float(Bits(a) ^ 0x80000000u); }
float Abs(float a) {
    __asm { fld a
        fabs
        fstp a }
    return a;
}
// The original rounds FPATAN to binary32, multiplies with MULSS, then
// uses FISTP (x87 control word), not CVTSS2SI (MXCSR rounding control).
int Angle(float y, float x) {
    float a;
    __asm { fld y
        fld x
        fpatan
        fstp a }
    a = Mul(a, Float(0x4622F983));
    int result;
    __asm { fld a
        fistp result }
    return result;
}
int SignedAngle(int a) { const uint16_t s = static_cast<uint16_t>(a); return s == 0x8000 ? 32768 : static_cast<int16_t>(s); }
Point ReadPoint(U p, U off) { return {Load<float>(p, off), Load<float>(p, off + 4)}; }
U Target(U receiver, U slot) { return Load<U>(Load<U>(receiver, 0), slot); }
void Record(U target) {
    // Store preferred image VAs; host oracle callbacks remain host addresses.
    const U va = target >= binding.image_delta + 0x400000u && target < binding.image_delta + 0x1900000u
        ? target - binding.image_delta : target;
    for (U i = Target0; i <= Target2; i += 2) {
        if (!words[i]) words[i] = va;
        if (words[i] == va) { ++words[i + 1]; return; }
    }
    ++words[OtherTargetCalls];
}
void RequireOwner() {
    const U thread = GetCurrentThreadId();
    // The native tick owner may migrate while no shadow frame is active.
    // Public Capture/Run are also used directly by the mapped-image oracle.
    const U active = static_cast<U>(owner_thread);
    if (active && active != thread) RaiseException(0xE0425202, 0, 0, nullptr);
}
B Predicate(U receiver, U target) {
    Record(target);
    return reinterpret_cast<B(__thiscall*)(void*)>(target)(Pointer(receiver));
}

// Projection matches the repeated SSE sequence, including its two inverse
// length multiplications rather than a division by squared length.
Point ProjectedPoint(const Segment& s, Point p, bool clamp, bool direction_first = false) {
    const float dx = Sub(s.b.x, s.a.x), dz = Sub(s.b.z, s.a.z);
    const float px = Sub(p.x, s.a.x), pz = Sub(p.z, s.a.z);
    const float len = Sqrt(Add(Mul(dx, dx), Mul(dz, dz)));
    float t = 0.0f;
    if (len > 0.0f) {
        const float inv = Div(1.0f, len);
        t = clamp ? Add(Mul(Mul(inv, dx), Mul(inv, px)), Mul(Mul(inv, dz), Mul(inv, pz)))
                  : Add(Mul(Mul(dx, inv), Mul(px, inv)), Mul(Mul(dz, inv), Mul(pz, inv)));
    }
    if (clamp) t = 0.0f > t ? 0.0f : Min(t, 1.0f);
    return {Add(s.a.x, direction_first ? Mul(dx, t) : Mul(t, dx)),
        Add(s.a.z, direction_first ? Mul(dz, t) : Mul(t, dz))};
}
float Radius(const AgentView& a, const Segment& s, bool ring) {
    const Point q = ProjectedPoint(s, {a.x, a.z}, true);
    const int angle = Angle(Sub(q.x, a.x), Sub(q.z, a.z));
    if (!a.has_shape) return a.radius;
    const U index = static_cast<uint16_t>(angle - a.heading) >> 8;
    const float radius = (a.live_shape_radii ? a.live_shape_radii : a.shape_radii)[index];
    return ring ? Mul(a.radius, radius) : Mul(radius, a.radius);
}
// 0x559C10, with both extent flags and epsilon zero (the sole 808570 use).
bool Intersects(const Segment& s, const Segment& t) {
    const float tx = Sub(t.b.x, t.a.x), tz = Sub(t.b.z, t.a.z);
    const float sx = Sub(s.b.x, s.a.x), sz = Sub(s.b.z, s.a.z);
    const float det = Sub(Mul(tz, sx), Mul(tx, sz));
    if (!(Abs(det) > 0.0f)) return false;
    const float inv = Div(1.0f, det), x = Sub(s.a.x, t.a.x), z = Sub(s.a.z, t.a.z);
    const float u = Mul(Sub(Mul(z, tx), Mul(x, tz)), inv);
    if (0.0f > u || u > 1.0f) return false;
    const float v = Mul(Sub(Mul(z, sx), Mul(x, sz)), inv);
    return !(0.0f > v || v > 1.0f);
}
Point Offset(PolygonPoint p, float radius) {
    // 10D42D0 followed by 10D46A0: normal*radius + point.
    return {Add(Mul(p.normal.x, radius), p.point.x), Add(Mul(p.normal.z, radius), p.point.z)};
}
bool Crosses(Point old, Point next, Point p) {
    if (old.z > next.z) {
        if (!(p.z >= next.z) || !(old.z > p.z)) return false;
        return Mul(Sub(p.z, next.z), Sub(old.x, next.x)) > Mul(Sub(p.x, next.x), Sub(old.z, next.z));
    }
    if (!(p.z >= old.z) || !(next.z > p.z)) return false;
    return Mul(Sub(p.z, old.z), Sub(next.x, old.x)) > Mul(Sub(p.x, old.x), Sub(next.z, old.z));
}
// 10E7430 is a read-only point-in-offset-polygon loop. The native implementation
// starts with this edge, advances +8 before each test, and includes the wrap edge.
template<class Get> bool Inside(U count, U first, Get get, Point p, float radius) {
    if (!count) return false;
    Point old = Offset(get(first), radius);
    bool inside = false;
    for (U n = 1; n <= count; ++n) {
        Point next = Offset(get((first + n) % count), radius);
        if (Crosses(old, next, p)) inside = !inside;
        old = next;
    }
    return inside;
}

// 7FFE30. This intentionally uses the INFINITE line projection, not a segment
// clamp. +199 is set even when +117 causes the remainder to be skipped.
void WallFlags(AgentView& a, const Segment& s, float radius) {
    a.flag199 = 1;
    if (a.flag117 || (a.flags110 & 1) || a.flag13c) return;
    const Point p{a.transformed_x, a.transformed_z};
    const Point q = ProjectedPoint(s, p, false, true);
    const float x = Sub(p.x, q.x), z = Sub(p.z, q.z), r = Add(radius, 0.25f);
    if (Mul(r, r) >= Add(Mul(x, x), Mul(z, z))) a.flag13c = a.flag1a8 = 1;
}
// 808570 over the snapshot, including 559C10 and 10E7430 above. "raw" is the
// candidate's unoffset point -> +8 point segment; movement is position -> +160.
template<class InsideTest> void CandidateFlags(AgentView& a, const Segment& s, float radius,
    const Segment& raw, InsideTest inside) {
    if (a.flags110 & 0x2000) a.inout = 0;
    if (a.flag117) return;
    const Segment movement{{a.x, a.z}, {a.transformed_x, a.transformed_z}};
    const float sx = Sub(s.b.x, s.a.x), sz = Sub(s.b.z, s.a.z), nx = Neg(sz);
    if (!a.flag175 || !a.flag176) {
        const Point q = ProjectedPoint(s, movement.a, true, true);
        const float qx = Sub(q.x, Mul(nx, radius)), qz = Sub(q.z, Mul(sx, radius));
        const float side = Add(Mul(Sub(a.x, qx), Sub(movement.b.z, movement.a.z)),
            Mul(Sub(movement.b.x, movement.a.x), Sub(qz, a.z)));
        if (side > 0.0f) a.flag175 = 1; else a.flag176 = 1;
    }
    bool test_crossing = !a.flag174;
    if (test_crossing && (a.flags110 & 0x1000) && a.flag188) {
        const Point q = ProjectedPoint(raw, movement.b, true);
        const float ex = Sub(q.x, movement.b.x), ez = Sub(q.z, movement.b.z);
        if (Mul(radius, radius) >= Add(Mul(ex, ex), Mul(ez, ez))) test_crossing = false;
        else {
            const int normal_angle = Angle(Sub(raw.b.z, raw.a.z), Neg(Sub(raw.b.x, raw.a.x)));
            const int movement_angle = Angle(Sub(movement.b.x, movement.a.x), Sub(movement.b.z, movement.a.z));
            if (SignedAngle(normal_angle - movement_angle) > a.angle_limit) test_crossing = false;
        }
    }
    if (test_crossing) {
        const float approach = Add(Mul(Sub(movement.b.x, movement.a.x), nx), Mul(Sub(movement.b.z, movement.a.z), sx));
        if (0.0f > approach) {
            const float distance = Add(Mul(sx, Sub(movement.a.z, s.a.z)), Mul(nx, Sub(movement.a.x, s.a.x)));
            if (0.0f >= distance || Intersects(s, movement)) a.flag174 = 1;
        }
    }
    if (!a.flag13c && !(a.flags110 & 0x1001) && inside(movement.b, radius)) a.flag13c = a.flag1a8 = 1;
}

enum class ResponseKind { Wall, Capsule, Edge };
bool Respond(AgentView& a, Point tangent, float distance, float radius, float approach, ResponseKind kind) {
    const float ox = a.dx, oz = a.dz;
    if (radius >= distance) {
        if (a.inout == 1) {
            const float k = kind == ResponseKind::Wall ? Add(Mul(oz, tangent.z), Mul(ox, tangent.x))
                : Add(Mul(tangent.z, oz), kind == ResponseKind::Edge ? Mul(tangent.x, ox) : Mul(ox, tangent.x));
            a.dx = Mul(tangent.x, k); a.dz = Mul(tangent.z, k); a.inout = 0;
        } else a.dx = a.dz = 0.0f;
        return true;
    }
    // The wall caller separately tests (approach + unexpandedRadius) + EPS.
    if (kind != ResponseKind::Wall && !(Add(radius, approach) > distance)) return false;
    const float f = Div(Sub(distance, radius), approach);
    a.dx = Mul(ox, f); a.dz = kind == ResponseKind::Edge ? Mul(f, oz) : Mul(oz, f);
    if (a.inout == 1) {
        const float px = Mul(tangent.x, Sub(ox, a.dx)), pz = Mul(tangent.z, Sub(oz, a.dz));
        const float k = kind == ResponseKind::Wall ? Add(px, pz) : Add(pz, px);
        a.dx = Add(kind == ResponseKind::Wall ? Mul(k, tangent.x) : Mul(tangent.x, k), a.dx);
        a.dz = Add(kind == ResponseKind::Wall ? Mul(k, tangent.z) : Mul(tangent.z, k), a.dz); a.inout = 0;
    }
    return true;
}
bool WallResponse(AgentView& a, const Wall& w) {
    const Segment& s = w.segment;
    const float sx = Sub(s.b.x, s.a.x), sz = Sub(s.b.z, s.a.z);
    const float inv = Div(1.0f, Sqrt(Add(Mul(sx, sx), Mul(sz, sz))));
    const float tx = Mul(inv, sx), tz = Mul(inv, sz), nx = Neg(tz);
    const float distance = Add(Mul(tx, Sub(a.z, s.a.z)), Mul(nx, Sub(a.x, s.a.x)));
    const bool positive = distance >= 0.0f;
    const float absolute = Abs(distance), hx = Mul(tx, 0.1f), hz = Mul(tz, 0.1f);
    const float start = Add(Mul(tx, Sub(a.x, Sub(s.a.x, hx))), Mul(tz, Sub(a.z, Sub(s.a.z, hz))));
    if (!(start >= 0.0f)) return false;
    const float end = Add(Mul(tx, Sub(a.x, Add(hx, s.b.x))), Mul(tz, Sub(a.z, Add(hz, s.b.z))));
    if (!(0.0f >= end)) return false;
    const float vn = Add(Mul(nx, a.dx), Mul(a.dz, tx)), approach = Abs(vn);
    if (!(positive ? 0.0f > vn : vn > 0.0f)) return false;
    WallFlags(a, s, a.radius);
    const float r = Add(a.radius, 0.25f);
    if (!(r >= absolute) && !(Add(Add(approach, a.radius), 0.25f) > absolute)) return false;
    return Respond(a, {tx, tz}, absolute, r, approach, ResponseKind::Wall);
}
bool CapsuleResponse(AgentView& a, const Capsule& c, const std::vector<PolygonPoint>& points, bool live) {
    Point start = c.point, end = c.b.point;
    const U endpointA=live ? c.endpoint_a:0, endpointB=live ? c.endpoint_b:0;
    const bool round_a = (live ? Load<U>(endpointA,0x38):c.a.type) == 2;
    const bool round_b = (live ? Load<U>(endpointB,0x38):c.b.type) == 2;
    if (round_a) { start.x = Sub(start.x, Mul(c.tangent.x, 0.1f)); start.z = Sub(start.z, Mul(c.tangent.z, 0.1f)); }
    const float px = Sub(a.x, start.x), pz = Sub(a.z, start.z);
    const float distance = Add(Mul(px, c.normal.x), Mul(pz, c.normal.z));
    if (!(distance > 0.0f)) return false;
    if (round_b) { end.x = Add(end.x, Mul(c.tangent.x, 0.1f)); end.z = Add(end.z, Mul(c.tangent.z, 0.1f)); }
    const Point n0 = round_a || (live ? Load<B>(c.native,0x2C):c.flag) ? c.normal : c.alternate_normal;
    const Point n1 = round_b || (live ? Load<B>(endpointB,0x2C):c.b.flag) ? c.normal : c.b.normal;
    bool span = false;
    if (round_a || round_b) {
        const float x = Add(a.dx, a.x), z = Add(a.dz, a.z);
        if (Add(Mul(c.tangent.x, Sub(x, start.x)), Mul(c.tangent.z, Sub(z, start.z))) >= 0.0f)
            span = 0.0f >= Add(Mul(c.tangent.x, Sub(x, end.x)), Mul(c.tangent.z, Sub(z, end.z)));
    }
    if (!(0.0f > Sub(Mul(pz, n0.x), Mul(px, n0.z))) && !span) return false;
    if (!(Add(Mul(Sub(end.x, a.x), n1.z), Mul(n1.x, Sub(a.z, end.z))) >= 0.0f) && !span) return false;
    const float approach = Neg(Add(Mul(a.dx, c.normal.x), Mul(a.dz, c.normal.z)));
    if (!(approach > 0.0f)) return false;
    const float r = Radius(a, {c.point, c.b.point}, false);
    const Segment offset{{Add(Mul(r, n0.x), c.point.x), Add(Mul(r, n0.z), c.point.z)},
        {Add(Mul(r, n1.x), c.b.point.x), Add(Mul(r, n1.z), c.b.point.z)}};
    const CycleRange& polygon = c.polygon;
    const Segment raw{c.point, polygon.count > 1 ? points[polygon.Index(1)].point : c.point};
    CandidateFlags(a, offset, r, raw, [&](Point p, float rr) {
        return Inside(polygon.count, polygon.first, [&](U i) { return points[polygon.offset + i]; }, p, rr);
    });
    return Respond(a, c.tangent, distance, r, approach, ResponseKind::Capsule);
}
bool EdgeResponse(AgentView& a, const Edge& e) {
    const float distance = Add(Mul(Sub(e.point.z, a.z), e.normal.z), Mul(Sub(e.point.x, a.x), e.normal.x));
    if (!(distance > 0.0f)) return false;
    const Point start{Sub(e.point.x, Mul(e.tangent.x, 0.1f)), Sub(e.point.z, Mul(e.tangent.z, 0.1f))};
    const Point end{Add(Mul(e.tangent.x, 0.1f), e.next.x), Add(e.next.z, Mul(e.tangent.z, 0.1f))};
    const Point target{Add(a.dx, a.x), Add(a.dz, a.z)};
    const bool span = Add(Mul(e.tangent.z, Sub(target.z, start.z)), Mul(e.tangent.x, Sub(target.x, start.x))) >= 0.0f &&
        0.0f >= Add(Mul(e.tangent.z, Sub(target.z, end.z)), Mul(e.tangent.x, Sub(target.x, end.x)));
    if (!(Add(Mul(e.tangent.z, Sub(a.z, start.z)), Mul(e.tangent.x, Sub(a.x, start.x))) >= 0.0f) && !span) return false;
    if (!(0.0f >= Add(Mul(e.tangent.z, Sub(a.z, end.z)), Mul(e.tangent.x, Sub(a.x, end.x)))) && !span) return false;
    const float approach = Add(Mul(a.dz, e.normal.z), Mul(a.dx, e.normal.x));
    if (!(approach > 0.0f)) return false;
    const float r = Min(Max(Sub(e.radius_cap, 0.25f), 0.1f), Radius(a, {end, start}, true));
    // 7F9E7F constructs end -> start. Its vf5C call passes cand=null,
    // other=edge; consequently the 10E7430/+13C branch is NOT taken.
    const Segment offset{{Sub(end.x, Mul(r, e.normal.x)), Sub(end.z, Mul(r, e.normal.z))},
        {Sub(start.x, Mul(r, e.normal.x)), Sub(start.z, Mul(r, e.normal.z))}};
    CandidateFlags(a, offset, r, {e.point, e.next}, [](Point, float) { return false; });
    return Respond(a, e.tangent, distance, r, approach, ResponseKind::Edge);
}

Endpoint ReadEndpoint(U p) { return {ReadPoint(p, 0xC), ReadPoint(p, 0x24), Load<U>(p, 0x38), Load<B>(p, 0x2C)}; }
void OutputBits(const AgentView& a, U out[10]) {
    out[0] = Bits(a.dx); out[1] = Bits(a.dz); out[2] = a.flag13c;
    out[3] = a.flag174; out[4] = a.flag175; out[5] = a.flag176;
    out[6] = a.flag199; out[7] = a.flag1a8; out[8] = a.result; out[9] = a.inout;
}
void Compare(U field, U expected, U actual) {
    if (expected == actual) return;
    ++words[field];
    if (!words[FirstCall]) {
        words[FirstEntity] = saved.entity; words[FirstCall] = words[Calls]; words[FirstField] = field;
        words[FirstExpected] = expected; words[FirstActual] = actual;
        // Last value-changing port step for this field; not an assertion about
        // an unobserved original intermediate divergence. ~0 means unchanged.
        const U index = field == MismatchInout ? 9 : field - MismatchDx;
        words[FirstCandidate] = saved.output_candidate[index]; words[FirstPass] = saved.output_pass[index];
    }
}
void Finish(B original_return) {
    Run(saved, captured, saved_box);
    const U before = words[MismatchDx] + words[MismatchDz] + words[Mismatch13C] + words[Mismatch174] +
        words[Mismatch175] + words[Mismatch176] + words[Mismatch199] + words[Mismatch1A8] + words[MismatchReturn] + words[MismatchInout];
    Compare(MismatchDx, Load<U>(original, 0xD4), Bits(saved.dx));
    Compare(MismatchDz, Load<U>(original, 0xDC), Bits(saved.dz));
    const U offsets[] = {0x13C, 0x174, 0x175, 0x176, 0x199, 0x1A8};
    const B flags[] = {saved.flag13c, saved.flag174, saved.flag175, saved.flag176, saved.flag199, saved.flag1a8};
    for (U i = 0; i < 6; ++i) Compare(Mismatch13C + i, Load<B>(original, offsets[i]), flags[i]);
    Compare(MismatchReturn, original_return, saved.result);
    if (have_inout) Compare(MismatchInout, observed_inout, saved.inout); else ++words[Faults];
    const U after = words[MismatchDx] + words[MismatchDz] + words[Mismatch13C] + words[Mismatch174] +
        words[Mismatch175] + words[Mismatch176] + words[Mismatch199] + words[Mismatch1A8] + words[MismatchReturn] + words[MismatchInout];
    if (after != before) ++words[Mismatches];
    ++words[Compared];
}
}

namespace {
void LoadFields(U p, U entity, AgentView& a, bool geometry=true, bool liveShape=false) {
    a.entity = entity; a.owner = Load<U>(p, 0x10); a.state18 = Load<U>(p, 0x18);
    a.x = Load<float>(p, 0x48); a.y = Load<float>(p, 0x4C); a.z = Load<float>(p, 0x50);
    a.radius = Load<float>(p, 0x58); a.radius_extra5c = Load<B>(p, 0x5C); a.heading = Load<uint16_t>(p, 0x64);
    a.dx = Load<float>(p, 0xD4); a.dy = Load<float>(p, 0xD8); a.dz = Load<float>(p, 0xDC);
    a.flags110 = Load<U>(p, 0x110); a.flag117 = Load<B>(p, 0x117); a.flag13c = Load<B>(p, 0x13C);
    a.flag174 = Load<B>(p, 0x174); a.flag175 = Load<B>(p, 0x175); a.flag176 = Load<B>(p, 0x176);
    a.flag188 = Load<U>(p, 0x188); a.flag199 = Load<B>(p, 0x199); a.flag1a8 = Load<B>(p, 0x1A8);
    a.context1f0 = Load<U>(p, 0x1F0); a.result_b6 = Load<B>(p, 0xB6);
    a.transform160 = Load<U>(p, 0x170);
    const U shape = Load<U>(p, 0x60); a.has_shape = shape != 0;
    a.live_shape_radii = nullptr;
    if (geometry && shape) {
        const auto radii=static_cast<const float*>(Pointer(Load<U>(shape,0x18)));
        // Movers do not write shape geometry; the owner is blocked for dispatch.
        // Read only the selected radius instead of copying all 256 per query.
        if (liveShape) a.live_shape_radii=radii;
        else std::memcpy(a.shape_radii,radii,sizeof(a.shape_radii));
    }
}
// Activation/capture-only index. Distinct candidate identities on the same +8
// cycle share storage, but retain different first indices. No index survives
// publication, and workers only read the compact backing.
template<class T> struct CycleBuilder {
    struct Location { U cycle, first; };
    std::unordered_map<U, Location> nodes;
    std::vector<CycleRange> cycles;
    std::vector<T>& values;
    explicit CycleBuilder(std::vector<T>& backing) : values(backing) { values.clear(); }
    template<class Read> CycleRange Capture(U first, Read read) {
        auto found = nodes.find(first);
        if (found != nodes.end()) {
            CycleRange range = cycles[found->second.cycle];
            range.first = found->second.first;
            return range;
        }
        const U cycle = static_cast<U>(cycles.size());
        CycleRange range{static_cast<U>(values.size()), 0, 0};
        U node = first;
        do {
            if (!nodes.emplace(node, Location{cycle, range.count}).second)
                RaiseException(kntwr_sweep::WorkerRefusal, 0, 0, nullptr);
            values.push_back(read(node));
            ++range.count;
            node = Load<U>(node, 8);
        } while (node != first);
        cycles.push_back(range);
        return range;
    }
};
void VerifyGeometry(const kntwr_sweep::WorkerScene* scene, U address, size_t bytes) {
    if (scene) kntwr_sweep::VerifyOnBuild(*scene, 3, address, bytes);
}
void CaptureRing(U native, Ring& ring, CycleBuilder<Edge>& cycles,
    const kntwr_sweep::WorkerScene* scene = nullptr) {
    ring.native = native;
    VerifyGeometry(scene, native + 8, 4); VerifyGeometry(scene, native + 0x30, 16);
    std::memcpy(ring.plane, Pointer(native + 0x30), sizeof(ring.plane));
    ring.edges = cycles.Capture(Load<U>(native, 8), [&](U edge) {
        VerifyGeometry(scene, edge + 8, 36); VerifyGeometry(scene, edge + 0x5C, 4);
        Edge e{}; e.native = edge; e.predicate_target = Target(edge, 0x14);
        e.point = ReadPoint(edge, 0xC); e.next = ReadPoint(Load<U>(edge, 8), 0xC);
        e.tangent = ReadPoint(edge, 0x14); e.normal = ReadPoint(edge, 0x1C); e.alternate_normal = ReadPoint(edge, 0x24);
        e.radius_cap = Load<float>(edge, 0x5C); e.blocking = Load<B>(edge, 0x60);
        return e;
    });
}
void CaptureCapsule(U native, Capsule& v, CycleBuilder<PolygonPoint>& cycles,
    const kntwr_sweep::WorkerScene* scene = nullptr) {
    v.native = native; v.owner = Load<U>(native, 0x3C);
    v.eligible_target = Target(v.owner + 0xC, 0); v.secondary_target = Target(v.owner, 8);
    v.point = ReadPoint(native, 0xC); v.tangent = ReadPoint(native, 0x14);
    v.normal = ReadPoint(native, 0x1C); v.alternate_normal = ReadPoint(native, 0x24);
    VerifyGeometry(scene, native + 0x40, 8); VerifyGeometry(scene, native + 0xC, 32);
    v.endpoint_a = Load<U>(native,0x40); v.endpoint_b = Load<U>(native,0x44);
    for (U endpoint : {v.endpoint_a, v.endpoint_b}) {
        VerifyGeometry(scene, endpoint + 0xC, 8); VerifyGeometry(scene, endpoint + 0x24, 8);
    }
    v.a = ReadEndpoint(v.endpoint_a); v.b = ReadEndpoint(v.endpoint_b);
    v.type = Load<U>(native, 0x38); v.flag = Load<B>(native, 0x2C);
    v.polygon = cycles.Capture(native, [&](U node) {
        VerifyGeometry(scene, node + 8, 12); VerifyGeometry(scene, node + 0x24, 8);
        return PolygonPoint{ReadPoint(node, 0xC), ReadPoint(node, 0x24)};
    });
}
void CaptureWall(U native, Wall& w) {
    w.native = native;
    std::memcpy(&w.segment, Pointer(Load<U>(native, 0)), sizeof(w.segment));
}
struct OwnedSource {
    const Candidates& c;
    size_t rings() const { return c.rings.size(); }
    size_t capsules() const { return c.capsules.size(); }
    size_t walls() const { return c.walls.size(); }
    const Ring& ring(size_t i) const { return c.rings[i]; }
    const Capsule& capsule(size_t i) const { return c.capsules[i]; }
    const Wall& wall(size_t i) const { return c.walls[i]; }
    const std::vector<Edge>& edges() const { return c.edges; }
    const std::vector<PolygonPoint>& points() const { return c.polygon_points; }
};
struct SelectedSource {
    const WorkerCandidates& c;
    const Candidates& geometry;
    size_t rings() const { return c.rings.size(); }
    size_t capsules() const { return c.capsules.size(); }
    size_t walls() const { return c.walls.size(); }
    const Ring& ring(size_t i) const { return *c.rings[i]; }
    const Capsule& capsule(size_t i) const { return *c.capsules[i]; }
    const Wall& wall(size_t i) const { return *c.walls[i]; }
    const std::vector<Edge>& edges() const { return geometry.edges; }
    const std::vector<PolygonPoint>& points() const { return geometry.polygon_points; }
};
struct OwnerDispatch {
    static constexpr bool live = false, diagnostics = true;
    B operator()(U receiver, U, U target) const { return Predicate(receiver,target); }
};
// Worker policies read the current slot and getter input, never the catalog's
// captured predicate result/target. These three leaf bodies have no FP effects.
struct WorkerDispatch {
    static constexpr bool live = true, diagnostics = false;
    U delta;
    B operator()(U receiver, U slot, U) const {
        switch(Target(receiver,slot)-delta) {
        case 0x54E920: return Load<B>(receiver,4);
        case 0x462CB0: return 0;
        case 0x447880: return 1;
        default: RaiseException(kntwr_sweep::WorkerRefusal,0,0,nullptr); return 0;
        }
    }
};
template<class Source, class Dispatch>
uint8_t RunCore(AgentView& a, const Source& c, const Aabb& box, Dispatch predicate) {
    bool phase_a = !a.owner, phase_b = a.owner != 0;
    a.inout = 1; a.result = 0; a.candidate_index = ~0u;
    if (Dispatch::diagnostics) for (U i = 0; i < 10; ++i) a.output_candidate[i] = a.output_pass[i] = ~0u;
    bool overlap = false;
    for (size_t ri = 0; ri < c.rings(); ++ri) {
        const Ring& ring = c.ring(ri);
        for (U i = 0; i < ring.edges.count; ++i) {
            const Edge& e = c.edges()[ring.edges.Index(i)];
            if (predicate(e.native,0x14,e.predicate_target) != 1 || (Dispatch::live ? Load<B>(e.native,0x60):e.blocking) != 1) continue;
            if (box.min_x > Max(e.next.x, e.point.x) || box.min_z > Max(e.next.z, e.point.z) ||
                Min(e.next.x, e.point.x) > box.max_x) continue;
            // Native JBE accepts unordered on the final comparison.
            if (!(Min(e.next.z, e.point.z) > box.max_z)) { overlap = true; break; }
        }
        if (overlap) break;
    }
    if (overlap) phase_a = phase_b = true;
    for (a.pass = 0; a.pass < 2; ++a.pass) {
        U calls = 0, ordinal = 0; bool changed = false;
        auto step = [&](auto response) {
            a.candidate_index = ordinal;
            U before[10], after[10]; if (Dispatch::diagnostics) OutputBits(a, before);
            const B old = a.inout;
            if (response()) a.result = 1;
            if (a.inout != old) changed = true;
            if (!a.pass) a.inout = 1;
            if (Dispatch::diagnostics) {
                OutputBits(a, after);
                for (U i = 0; i < 10; ++i) if (before[i] != after[i]) {
                    a.output_candidate[i] = ordinal; a.output_pass[i] = a.pass;
                }
            }
            ++calls;
        };
        for (size_t ci = 0; ci < c.capsules(); ++ci) {
            const Capsule& v = c.capsule(ci);
            if (phase_a) {
                const U owner=Dispatch::live ? Load<U>(v.native,0x3C):v.owner;
                if (predicate(owner+0xC,0,v.eligible_target)==1) {
                    const U type=Dispatch::live ? Load<U>(v.native,0x38):v.type;
                    if (type==0 || type==1 || (!a.agent_predicate && predicate(owner,8,v.secondary_target)==0))
                        step([&] { return CapsuleResponse(a,v,c.points(),Dispatch::live); });
                }
            }
            ++ordinal;
        }
        for (size_t wi = 0; wi < c.walls(); ++wi) {
            const Wall& w = c.wall(wi);
            if (phase_a) step([&] { return WallResponse(a, w); });
            ++ordinal;
        }
        for (size_t ri = 0; ri < c.rings(); ++ri) {
            const Ring& ring = c.ring(ri);
            for (U i = 0; i < ring.edges.count; ++i) {
                const Edge& e = c.edges()[ring.edges.Index(i)];
                if (phase_b && predicate(e.native,0x14,e.predicate_target) == 0) step([&] { return EdgeResponse(a, e); });
                ++ordinal;
            }
        }
        if (a.pass || !changed || calls < 2) break;
    }
    return a.result;
}
template<class T> const T* Find(const std::vector<T>& v, U native) {
    auto it = std::lower_bound(v.begin(), v.end(), native, [](const T& x, U key) { return x.native < key; });
    return it != v.end() && it->native == native ? &*it : nullptr;
}
bool Unique(std::vector<U>& v) {
    std::sort(v.begin(), v.end()); v.erase(std::unique(v.begin(), v.end()), v.end()); return true;
}
void PrepareCatalogImpl(WorkerCatalog& k, const kntwr_sweep::WorkerScene& s) {
    if (k.attempted && k.generation == s.generation) {
        if (!k.prepared || k.source != &s || k.build != s.build || k.image_delta != s.image_delta)
            RaiseException(kntwr_sweep::WorkerRefusal,0,0,nullptr);
        return;
    }
    k = WorkerCatalog{}; k.image_delta = s.image_delta;
    k.attempted = true; k.generation = s.generation; k.source = &s; k.build = s.build;
    std::vector<U> rings, capsules, walls;
    for (const auto& o : s.owners) rings.push_back(o.identity);
    const auto& t = s.topology;
    for (size_t n = 0; n < t.type.size(); ++n) {
        if (t.type[n] == 0x20) capsules.push_back(t.owner[n]);
        else if (t.type[n] == 0x800) walls.push_back(t.payload[n]);
    }
    Unique(rings); Unique(capsules); Unique(walls);
    k.geometry.rings.resize(rings.size()); k.geometry.capsules.resize(capsules.size()); k.geometry.walls.resize(walls.size());
    // Record the full immutable closure while capturing it. A canonical cycle
    // records every native node once, including nodes that are not candidates.
    // Dynamic vtable targets, eligibility, type/flag bytes and owners stay live.
    s.verification[3].clear();
    {
        CycleBuilder<Edge> edges(k.geometry.edges);
        CycleBuilder<PolygonPoint> polygons(k.geometry.polygon_points);
        for (size_t i = 0; i < rings.size(); ++i) CaptureRing(rings[i], k.geometry.rings[i], edges, &s);
        for (size_t i = 0; i < capsules.size(); ++i) CaptureCapsule(capsules[i], k.geometry.capsules[i], polygons, &s);
        k.geometry.edge_cycles = static_cast<U>(edges.cycles.size());
        k.geometry.polygon_cycles = static_cast<U>(polygons.cycles.size());
    }
    for (size_t i = 0; i < walls.size(); ++i) {
        const U native = walls[i];
        VerifyGeometry(&s, native, 4); VerifyGeometry(&s, Load<U>(native, 0), sizeof(Segment));
        CaptureWall(native, k.geometry.walls[i]);
    }
    k.geometry.edges.shrink_to_fit(); k.geometry.polygon_points.shrink_to_fit();
    if (!kntwr_sweep::VerifyBuild(s,0,4)) RaiseException(kntwr_sweep::WorkerRefusal,0,0,nullptr);
    // The complete scene and catalog have now been checked, including every
    // original cell head/link before interning. No worker or tick uses the tape.
    kntwr_sweep::ReleaseBuildVerification(s);
    kntwr_sweep::CandidateCapacities(t,s.owners.size(),k.reserve);
    k.prepared = true;
}
bool WorkerResolveImpl(WorkerContext& c, U p, U identity, U scratch, const Aabb& box) {
    if (!c.catalog || !c.catalog->prepared || c.build!=c.catalog->build ||
        !c.catalog->source || !c.catalog->source->built || c.catalog->build!=c.catalog->source->build) return false;
    const WorkerCatalog& k = *c.catalog; const U delta = k.image_delta;
    const U l0=Load<U>(scratch,0),l1=Load<U>(scratch,4),l2=Load<U>(scratch,8);
    if(!l0 || !l1 || !l2) return false;
    const U n0=Load<U>(l0,0xC),n1=Load<U>(l1,8),n2=Load<U>(l2,8);
    const bool geometry=n0 || n1 || n2;
    AgentView& a=c.view; LoadFields(p,identity,a,geometry,true);
    if (a.transform160 && !c.allow_foreign_transform) return false;
    // Same two captured virtuals as the shadow path; any other class is refused.
    if (Target(p, 0x5C) != delta + 0x808570 || Target(p, 0x60) != delta + 0x7FFE30) return false;
    const U agentTarget = Target(p, 0x3C);
    if (!kntwr_sweep::PureAgentTarget(p, agentTarget, delta)) return false;
    a.agent_predicate = reinterpret_cast<B(__thiscall*)(void*)>(agentTarget)(Pointer(p));
    a.inout = 1; a.result = 0; a.candidate_index = ~0u; a.pass = 0;
    // No response means no transform/shape-table geometry work in the native
    // closure. Keep the unconditional pure agent policy above, skip port overhead.
    if(!geometry) return true;
    float transformed[3];
    reinterpret_cast<void*(__thiscall*)(void*,float*)>(delta+0x80E9D0)(Pointer(p+0x160),transformed);
    a.transformed_x=transformed[0]; a.transformed_z=transformed[2];
    a.angle_limit=SignedAngle(Load<uint16_t>(delta+0x150FC9C,0));
    WorkerCandidates& s=c.selected; s.rings.clear(); s.capsules.clear(); s.walls.clear();
    const U d0=Load<U>(l0,0x10),d1=Load<U>(l1,0xC),d2=Load<U>(l2,0xC);
    if (n0 > s.rings.capacity() || n1 > s.capsules.capacity() || n2 > s.walls.capacity()) return false;
    for (U i = 0; i < n0; ++i) { const Ring* r = Find(k.geometry.rings, Load<U>(d0, i * 4)); if (!r) return false; s.rings.push_back(r); }
    for (U i = 0; i < n1; ++i) { const Capsule* r = Find(k.geometry.capsules, Load<U>(d1, i * 4)); if (!r) return false; s.capsules.push_back(r); }
    for (U i = 0; i < n2; ++i) { const Wall* r = Find(k.geometry.walls, Load<U>(d2, i * 4)); if (!r) return false; s.walls.push_back(r); }
    RunCore(a, SelectedSource{s, k.geometry}, box, WorkerDispatch{delta});
    return true;
}
}

void Capture(Agent* agent, Scratch* scratch, AgentView& a, Candidates& c) {
    RequireOwner();
    LoadFields(Address(agent), Address(agent), a);
    float transformed[3];
    reinterpret_cast<void*(__thiscall*)(void*, float*)>(binding.image_delta + 0x80E9D0)(Pointer(a.entity + 0x160), transformed);
    a.transformed_x = transformed[0]; a.transformed_z = transformed[2];
    a.angle_limit = SignedAngle(Load<uint16_t>(binding.image_delta + 0x150FC9C, 0));
    a.agent_predicate = Predicate(a.entity, Target(a.entity, 0x3C));
    a.inout = 1; a.result = 0; a.candidate_index = ~0u; a.pass = 0;
    // Captured live classes share these exact virtuals. A different class must
    // be surfaced, not silently given the wrong byte side effects.
    if (Target(a.entity, 0x5C) != binding.image_delta + 0x808570 || Target(a.entity, 0x60) != binding.image_delta + 0x7FFE30)
        RaiseException(0xE0425201, 0, 0, nullptr);
    const U l0 = Load<U>(scratch, 0), l1 = Load<U>(scratch, 4), l2 = Load<U>(scratch, 8);
    const U n0 = Load<U>(l0, 0xC), d0 = Load<U>(l0, 0x10);
    CycleBuilder<Edge> edges(c.edges);
    CycleBuilder<PolygonPoint> polygons(c.polygon_points);
    c.rings.resize(n0);
    for (U i = 0; i < n0; ++i) CaptureRing(Load<U>(d0, i * 4), c.rings[i], edges);
    const U n1 = Load<U>(l1, 8), d1 = Load<U>(l1, 0xC); c.capsules.resize(n1);
    for (U i = 0; i < n1; ++i) CaptureCapsule(Load<U>(d1, i * 4), c.capsules[i], polygons);
    const U n2 = Load<U>(l2, 8), d2 = Load<U>(l2, 0xC); c.walls.resize(n2);
    for (U i = 0; i < n2; ++i) CaptureWall(Load<U>(d2, i * 4), c.walls[i]);
    c.edge_cycles = static_cast<U>(edges.cycles.size());
    c.polygon_cycles = static_cast<U>(polygons.cycles.size());
}

uint8_t Run(AgentView& a, const Candidates& c, const Aabb& box) {
    RequireOwner();
    return RunCore(a, OwnedSource{c}, box, OwnerDispatch{});
}
bool PrepareCatalog(WorkerCatalog& k, const kntwr_sweep::WorkerScene& s) {
    if (!s.built) { k.prepared = false; return false; }
    bool ok = false;
    __try { PrepareCatalogImpl(k, s); ok = true; }
    __except (kntwr_sweep::RefusalFilter(GetExceptionCode())) { k.prepared = false; }
    return ok;
}
bool PrepareWorker(WorkerContext& c, const WorkerCatalog& k) {
    c.fp = kntwr_sweep::CaptureFp();
    if (!k.prepared || !k.source || !k.source->built || k.build!=k.source->build) return false;
    if (c.catalog==&k && c.build==k.build) return true;
    // Allocate/prefault the exact type-specific bounds, shedding old-build peaks.
    std::vector<const Ring*>(k.reserve[0]).swap(c.selected.rings); c.selected.rings.clear();
    std::vector<const Capsule*>(k.reserve[1]).swap(c.selected.capsules); c.selected.capsules.clear();
    std::vector<const Wall*>(k.reserve[2]).swap(c.selected.walls); c.selected.walls.clear();
    c.view = {};
    c.catalog=&k; c.build=k.build; return true;
}
void SampleCatalogStorage(const WorkerCatalog& k, U out[CatalogStorageWordCount]) {
    const Candidates& g = k.geometry;
    out[0] = static_cast<U>(g.rings.capacity() * sizeof(Ring));
    out[1] = static_cast<U>(g.capsules.capacity() * sizeof(Capsule));
    out[2] = static_cast<U>(g.walls.capacity() * sizeof(Wall));
    out[3] = static_cast<U>(g.edges.capacity() * sizeof(Edge));
    out[4] = static_cast<U>(g.polygon_points.capacity() * sizeof(PolygonPoint));
    out[5] = static_cast<U>(g.rings.size()); out[6] = static_cast<U>(g.capsules.size());
    out[7] = static_cast<U>(g.walls.size()); out[8] = static_cast<U>(g.edges.size());
    out[9] = static_cast<U>(g.polygon_points.size());
}
size_t HeapBytes(const WorkerCatalog& k) {
    U words[CatalogStorageWordCount]; SampleCatalogStorage(k, words);
    return static_cast<size_t>(words[0]) + words[1] + words[2] + words[3] + words[4];
}
size_t HeapBytes(const WorkerContext& c) {
    return (c.selected.rings.capacity()+c.selected.capsules.capacity()+c.selected.walls.capacity())*sizeof(void*);
}
bool WorkerResolve(WorkerContext& c, void* agent, uint32_t identity, void* scratch, const Aabb& box, uint8_t& result) {
    kntwr_sweep::FpState saved{}; bool ok=false;
    if (!c.fp_managed) { saved=kntwr_sweep::CaptureFp(); kntwr_sweep::ApplyFp(c.fp); }
    __try {
        __try { ok = WorkerResolveImpl(c, Address(agent), identity, Address(scratch), box); }
        __finally { if (!c.fp_managed) kntwr_sweep::ApplyFp(saved); }
    }
    __except (kntwr_sweep::RefusalFilter(GetExceptionCode())) { ok = false; }
    if (ok) {
        const AgentView& a = c.view; const U p = Address(agent);
        U bits[2] = {Bits(a.dx), Bits(a.dz)};
        std::memcpy(static_cast<B*>(agent) + 0xD4, &bits[0], 4); std::memcpy(static_cast<B*>(agent) + 0xDC, &bits[1], 4);
        static_cast<B*>(agent)[0x13C] = a.flag13c; static_cast<B*>(agent)[0x174] = a.flag174;
        static_cast<B*>(agent)[0x175] = a.flag175; static_cast<B*>(agent)[0x176] = a.flag176;
        static_cast<B*>(agent)[0x199] = a.flag199; static_cast<B*>(agent)[0x1A8] = a.flag1a8;
        if (a.result == 1) static_cast<B*>(agent)[0xB6] = 1;
        result = a.result; (void)p;
    }
    return ok;
}
bool Start(const Binding& b) {
    Stop(); binding = b; std::memset(words, 0, sizeof(words));
    std::memset(frame_words, 0, sizeof(frame_words));
    if (b.enabled) { words[Version] = 1; words[Enabled] = 1; }
    QueryPerformanceFrequency(&frequency); return true;
}
void Stop() {
    pending = have_inout = false; shadow_depth = previous_owner = 0;
    InterlockedExchange(&owner_thread, 0);
    original = nullptr; binding = {}; words[Enabled] = 0;
    captured = Candidates{};
}
void Sample(U out[WordCount]) { if (out) std::memcpy(out, words, sizeof(words)); }
void SampleFrames(U out[FrameWordCount]) {
    if (out) for (U i = 0; i < FrameWordCount; ++i)
        out[i] = static_cast<U>(InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&frame_words[i]), 0, 0));
}
void ShadowBefore(Agent* agent, Scratch* scratch, const Aabb* box) {
    if (!binding.enabled) return;
    const U thread = GetCurrentThreadId();
    const U active = static_cast<U>(InterlockedCompareExchange(&owner_thread, static_cast<LONG>(thread), 0));
    if (active && active != thread) {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&frame_words[OverlappingThreadCalls]));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&words[Faults]));
        return; // genuine overlap, not nesting; never consume the active owner's frame
    }
    if (!active) {
        if (previous_owner && previous_owner != thread) ++frame_words[OwnerHandoffs];
        previous_owner = thread;
    }
    ++shadow_depth;
    if (shadow_depth > frame_words[MaxDepth]) frame_words[MaxDepth] = shadow_depth;
    if (shadow_depth != 1) { ++words[Reentry]; ++frame_words[NestedCalls]; return; }
    ++words[Calls]; have_inout = false; original = agent;
    LARGE_INTEGER begin{}, end{}; QueryPerformanceCounter(&begin);
    __try {
        Capture(agent, scratch, saved, captured); saved_box = *box; pending = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ++words[Faults]; pending = false; }
    QueryPerformanceCounter(&end); capture_ticks = end.QuadPart - begin.QuadPart;
}
void ObserveOriginalInout(B value) {
    if (pending && shadow_depth == 1 && owner_thread == GetCurrentThreadId()) {
        observed_inout = value; have_inout = true;
    }
}
void Abandon() {
    const U active = static_cast<U>(owner_thread);
    if (active && active != GetCurrentThreadId()) return;
    if (pending || shadow_depth) ++words[Faults];
    pending = have_inout = false; shadow_depth = 0;
    InterlockedExchange(&owner_thread, 0);
}
void ShadowAfter(B original_return) {
    if (owner_thread != GetCurrentThreadId() || !shadow_depth) return;
    if (shadow_depth > 1) { --shadow_depth; return; }
    LARGE_INTEGER begin{}, end{}; QueryPerformanceCounter(&begin);
    if (pending) {
        __try { Finish(original_return); }
        __except (EXCEPTION_EXECUTE_HANDLER) { ++words[Faults]; }
    }
    pending = false; shadow_depth = 0;
    QueryPerformanceCounter(&end);
    if (frequency.QuadPart) words[ShadowUs] += static_cast<U>((capture_ticks + end.QuadPart - begin.QuadPart) * 1000000 / frequency.QuadPart);
    // Release only after every frame-owned read/write, including timing.
    InterlockedExchange(&owner_thread, 0);
}
} // namespace kntwr_resolve
