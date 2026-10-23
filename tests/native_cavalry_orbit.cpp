// Permanent behavioural regression for src/army/native_cavalry_orbit.{h,cpp} (pure cavalry-orbit policy).
// Self-contained: no image, no captures, no native memory, no RNG in the policy under test (input sampling below uses a fixed LCG).
// Covered contracts (see the header for the authoritative wording):
//   * clock: first delay longer than the interval survives normal advance; exactly one probe per advancing evaluation at/past the
//     deadline; repeated timestamps (including a saturated UINT64_MAX clock) never repeat a probe; an observed rewind rebases by one
//     interval without probing; the schedule saturates instead of wrapping; interval sanitisation keeps a >=100 ms cadence;
//     per-unit stagger is deterministic and bounded;
//   * geometry: exact coincidence escapes outward seeded by unit identity; near coincidence is radial; points inside the guarded
//     radius escape radially without ever decreasing the distance to C; points outside step along the tangent with the WHOLE segment
//     P->W at or outside the clearance circle R after native-float rounding, across large translated coordinates, both directions
//     and the accepted radius range; |W-C| bounded by guarded_R/cos(step); invalid direction values fall back to +1 while -1 mirrors;
//     nonfinite/nonpositive inputs are rejected without touching the outputs;
//   * gating/ownership: every gate (dead, dismounted, routing, square dissolved, order/target/unit identity lost, nonfinite or
//     out-of-bound coordinates, bad radii) hands an ACTIVE unit back to native in the same call (state_reset, fully cleared state);
//     model/unit/order/target changes reset first and the changed attack is established fresh on the NEXT call; the circling sense is
//     fixed per unit identity for the lifetime of the orbit.
#include "native_cavalry_orbit.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>

using namespace kntwr_cavalry_orbit;

namespace {

int g_checks = 0;
int g_failures = 0;

void Check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("FAIL %s\n", what);
    }
}

bool Near(double a, double b, double tol) { return std::fabs(a - b) <= tol; }

// Deterministic LCG for input sampling only (24 usable bits per draw).
uint32_t Lcg(uint32_t& s) {
    s = s * 1664525u + 1013904223u;
    return s >> 8;
}
double LcgUnit(uint32_t& s) { return double(Lcg(s)) / 16777216.0; }

bool Cleared(const State& st) {
    return !st.active && st.direction == 0 && st.model_token == 0 && st.unit_id == 0 && st.order_serial == 0 && st.target_id == 0 &&
           st.next_probe_ms == 0 && st.previous_ms == 0;
}

Input ValidInput() {
    Input in;
    in.model_token = 7;
    in.unit_id = 41;
    in.order_serial = 3;
    in.target_id = 902;
    in.own_x = 30.0f;
    in.own_z = -12.0f;
    in.target_x = 2.0f;
    in.target_z = 5.0f;
    in.target_radius = 10.0f;
    in.own_radius = 2.0f;
    in.mounted = true;
    in.alive = true;
    in.target_is_square = true;
    return in;
}

// Guarded radius exactly as the documented geometry contract computes it: R + fixed guard + coordinate-scaled float allowance.
double GuardedRadius(double clearance, double px, double pz, double cx, double cz) {
    double scale = std::fmax(1.0, clearance);
    scale = std::fmax(scale, std::fabs(double(px)));
    scale = std::fmax(scale, std::fabs(double(pz)));
    scale = std::fmax(scale, std::fabs(double(cx)));
    scale = std::fmax(scale, std::fabs(double(cz)));
    return clearance + 1.0e-3 + 4.0 * double(std::numeric_limits<float>::epsilon()) * scale;
}

// Exact minimum distance from C to the straight segment P->W (closest-point projection; no sampling error).
double SegmentMinDistance(double px, double pz, double wx, double wz, double cx, double cz) {
    const double vx = double(wx) - double(px), vz = double(wz) - double(pz);
    const double len2 = vx * vx + vz * vz;
    double t = 0.0;
    if (len2 > 0.0) t = ((cx - double(px)) * vx + (cz - double(pz)) * vz) / len2;
    if (t < 0.0) t = 0.0;
    if (t > 1.0) t = 1.0;
    return std::hypot(double(px) + t * vx - cx, double(pz) + t * vz - cz);
}

double WrapPi(double a) { return a - 6.283185307179586 * std::floor(a / 6.283185307179586 + 0.5); }

void TestDefaultsAndDirection() {
    int plus = 0, minus = 0;
    bool deterministic = true;
    for (uint32_t id = 1; id <= 999; ++id) {
        const int s = DirectionForUnit(id);
        if (s != 1 && s != -1) plus = minus = -1000000;  // invalid sense
        if (s == 1) ++plus; else if (s == -1) ++minus;
        if (DirectionForUnit(id) != s) deterministic = false;
    }
    Check(plus > 0 && minus > 0, "DirectionForUnit yields both circling senses across unit identities");
    Check(deterministic, "DirectionForUnit is deterministic per identity");
    Check(DirectionForUnit(0) == 1 || DirectionForUnit(0) == -1, "DirectionForUnit defined for the zero identity too");
}

void TestClearanceRadius() {
    Settings cfg;
    float r = -999.0f;
    Check(ClearanceRadius(10.0f, 2.0f, cfg, r) && Near(r, 14.0, 1.0e-5), "clearance radius sums target + own + margin");
    Check(ClearanceRadius(10.0f, 0.0f, cfg, r) && Near(r, 12.0, 1.0e-5), "zero own radius accepted");

    r = -999.0f;
    Check(!ClearanceRadius(0.0f, 2.0f, cfg, r) && r == -999.0f, "zero target radius rejected, output untouched");
    Check(!ClearanceRadius(-1.0f, 2.0f, cfg, r) && r == -999.0f, "negative target radius rejected, output untouched");
    Check(!ClearanceRadius(std::nanf(""), 2.0f, cfg, r), "nonfinite target radius rejected");
    Check(!ClearanceRadius(10.0f, -0.5f, cfg, r), "negative own radius rejected");
    Check(!ClearanceRadius(10.0f, std::nanf(""), cfg, r), "nonfinite own radius rejected");
    Check(!ClearanceRadius(1001.0f, 2.0f, cfg, r), "target radius above the default max rejected");
    Check(!ClearanceRadius(10.0f, 1001.0f, cfg, r), "own radius above the default max rejected");

    Settings wide = cfg;
    wide.max_radius = 5000.0f;
    Check(ClearanceRadius(4000.0f, 2.0f, wide, r) && Near(r, 4004.0, 1.0e-3), "raised max_radius accepts larger footprints");
    Settings absurd = cfg;
    absurd.max_radius = 20000.0f;  // above the 10000 hard ceiling -> sanitised down
    Check(!ClearanceRadius(15000.0f, 2.0f, absurd, r), "max_radius above its own ceiling cannot admit oversized footprints");
    Check(ClearanceRadius(9000.0f, 2.0f, absurd, r) && Near(r, 9004.0, 1.0e-2), "sanitised max_radius still accepts in-ceiling footprints");
    Settings fatmargin = cfg;
    fatmargin.clearance_margin = 2000.0f;  // above the 1000 clamp -> 1000
    Check(ClearanceRadius(10.0f, 2.0f, fatmargin, r) && Near(r, 1012.0, 1.0e-3), "clearance margin clamped to its ceiling");
}

void TestWaypointPrimitive() {
    Settings cfg;
    float wx = -999.0f, wz = -999.0f;
    Check(!ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1, 1, cfg, wx, wz) && wx == -999.0f && wz == -999.0f,
          "nonpositive clearance rejected, outputs untouched");
    Check(!ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, -1.0f, 1, 1, cfg, wx, wz), "negative clearance rejected");
    Check(!ComputeWaypoint(std::nanf(""), 0.0f, 0.0f, 0.0f, 10.0f, 1, 1, cfg, wx, wz) && wx == -999.0f && wz == -999.0f,
          "nonfinite own position rejected, outputs untouched");
    Check(!ComputeWaypoint(30.0f, 0.0f, std::nanf(""), 0.0f, 10.0f, 1, 1, cfg, wx, wz), "nonfinite target position rejected");
    Check(!ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, std::nanf(""), 1, 1, cfg, wx, wz), "nonfinite clearance rejected");

    // Direction contract: anything but -1 behaves as +1; -1 circles the other way.
    float ax = 0.0f, az = 0.0f, bx = 0.0f, bz = 0.0f, mx = 0.0f, mz = 0.0f;
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 5, cfg, ax, az), "baseline waypoint computes");
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 5, cfg, bx, bz) && bx == ax && bz == az, "waypoint is deterministic");
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, 0, 5, cfg, bx, bz) && bx == ax && bz == az, "direction 0 uses the +1 default");
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, -2, 5, cfg, bx, bz) && bx == ax && bz == az, "direction -2 uses the +1 default");
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, 7, 5, cfg, bx, bz) && bx == ax && bz == az, "direction +7 uses the +1 default");
    Check(ComputeWaypoint(30.0f, 0.0f, 0.0f, 0.0f, 10.0f, -1, 5, cfg, mx, mz) && (mx != ax || mz != az),
          "direction -1 produces the mirrored circling step");

    // Exact coincidence: outward escape beyond R + escape margin, seeded by unit identity, antipodal between senses.
    float e1x = 0.0f, e1z = 0.0f, e2x = 0.0f, e2z = 0.0f;
    Check(ComputeWaypoint(0.0f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, e1x, e1z) &&
              std::hypot(double(e1x), double(e1z)) >= 10.0 + cfg.escape_margin - 1.0e-3,
          "exact coincidence escapes beyond R + escape margin");
    Check(ComputeWaypoint(0.0f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, e2x, e2z) && e2x == e1x && e2z == e1z,
          "exact-coincidence escape is deterministic per identity");
    Check(ComputeWaypoint(0.0f, 0.0f, 0.0f, 0.0f, 10.0f, -1, 3, cfg, e2x, e2z) &&
              Near(std::hypot(double(e2x), double(e2z)), std::hypot(double(e1x), double(e1z)), 1.0e-4) &&
              Near(double(e1x) + double(e2x), 0.0, 1.0e-3) && Near(double(e1z) + double(e2z), 0.0, 1.0e-3),
          "exact-coincidence escape is antipodal between circling senses");
    int distinct = 0;
    for (uint32_t id = 1; id <= 32; ++id) {
        float dx = 0.0f, dz = 0.0f;
        if (!ComputeWaypoint(0.0f, 0.0f, 0.0f, 0.0f, 10.0f, 1, id, cfg, dx, dz)) { distinct = -1; break; }
        if (dx != e1x || dz != e1z) ++distinct;
    }
    Check(distinct >= 2, "exact-coincidence escape direction varies with unit identity");

    // Near coincidence (nonzero but tiny offset): radial escape, identity-independent, never inward.
    float n1x = 0.0f, n1z = 0.0f, n2x = 0.0f, n2z = 0.0f;
    Check(ComputeWaypoint(1.0e-5f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, n1x, n1z) && std::fabs(double(n1z)) <= 1.0e-4 &&
              std::hypot(double(n1x), double(n1z)) >= 1.0e-5,
          "near coincidence escapes radially without moving inward");
    Check(ComputeWaypoint(1.0e-5f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 4, cfg, n2x, n2z) && std::fabs(double(n2z)) <= 1.0e-4,
          "near-coincidence direction is radial regardless of identity");

    // Boundary discrimination at the guarded radius (R = 10, guard ~1.001e-3 at this scale).
    float bix = 0.0f, biz = 0.0f, box = 0.0f, boz = 0.0f;
    Check(ComputeWaypoint(10.0005f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, bix, biz) && std::fabs(double(biz)) <= 1.0e-6 &&
              std::hypot(double(bix), double(biz)) >= 10.0 + cfg.escape_margin - 1.0e-3,
          "point just inside the guarded radius escapes radially outward");
    Check(ComputeWaypoint(10.002f, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, box, boz) &&
              std::fabs(double(boz)) / std::hypot(double(box), double(boz)) > 0.05,
          "point just outside the guarded radius steps sideways along the tangent");

    // Inside points at several depths: distance from C never decreases.
    const float depths[4] = {0.001f, 3.0f, 9.99f, 10.0f};
    for (float dep : depths) {
        float ox = 0.0f, oz = 0.0f;
        Check(ComputeWaypoint(dep, 0.0f, 0.0f, 0.0f, 10.0f, 1, 3, cfg, ox, oz) &&
                  std::hypot(double(ox), double(oz)) >= double(dep) - 1.0e-9,
              "inside escape never decreases the distance to the centre");
    }
}

void TestSegmentAndCorridor() {
    Settings cfg;
    const double step = double(cfg.orbit_step_radians);
    uint32_t seed = 0x1234567u;
    for (int iter = 0; iter < 3000; ++iter) {
        const double cx = (LcgUnit(seed) * 2.0 - 1.0) * 1.0e6;
        const double cz = (LcgUnit(seed) * 2.0 - 1.0) * 1.0e6;
        const float target_r = 1.0f + float(LcgUnit(seed)) * 899.0f;  // inside the default max_radius
        const float own_r = float(LcgUnit(seed)) * 100.0f;
        float clearance_f = 0.0f;
        if (!ClearanceRadius(target_r, own_r, cfg, clearance_f)) {
            Check(false, "sampled radii are accepted");
            continue;
        }
        const double clearance = double(clearance_f);
        const double ang = LcgUnit(seed) * 6.283185307179586;
        // Strictly outside the guarded circle for every accepted scale (max guard at 1e6 coordinates is ~0.479 m).
        const double dist = clearance + 0.75 + LcgUnit(seed) * 500.0;
        const float px = float(cx + std::cos(ang) * dist);
        const float pz = float(cz + std::sin(ang) * dist);
        const int dir = (iter & 1) ? -1 : 1;
        float wx = 0.0f, wz = 0.0f;
        if (!ComputeWaypoint(px, pz, float(cx), float(cz), clearance_f, dir, 77, cfg, wx, wz)) {
            Check(false, "sampled waypoint computes");
            continue;
        }
        Check(SegmentMinDistance(px, pz, wx, wz, cx, cz) >= clearance, "whole segment P->W stays at or outside R after float rounding");

        const double guarded = GuardedRadius(clearance, px, pz, float(cx), float(cz));
        const double slack = 4.0 * double(std::numeric_limits<float>::epsilon()) * (guarded + std::fabs(cx) + std::fabs(cz)) + 1.0e-6;
        const double wc = std::hypot(double(wx) - cx, double(wz) - cz);
        Check(wc >= clearance && wc <= guarded / std::cos(step) + slack, "|W-C| bounded by guarded R / cos(step)");

        // Chained orbit: fixed sense, bounded corridor, every hop's segment clears R.
        if (iter % 25 == 0) {
            float qx = px, qz = pz;
            double prev_theta = std::atan2(double(qz) - cz, double(qx) - cx);
            for (int hop = 0; hop < 200; ++hop) {
                float hx = 0.0f, hz = 0.0f;
                if (!ComputeWaypoint(qx, qz, float(cx), float(cz), clearance_f, dir, 77, cfg, hx, hz)) {
                    Check(false, "chained orbit waypoint computes");
                    break;
                }
                Check(SegmentMinDistance(qx, qz, hx, hz, cx, cz) >= clearance, "chained orbit never cuts the clearance circle");
                const double hd = std::hypot(double(hx) - cx, double(hz) - cz);
                Check(hd >= clearance && hd <= guarded / std::cos(step) + slack, "chained orbit stays inside the corridor");
                const double theta = std::atan2(double(hz) - cz, double(hx) - cx);
                const double advance = dir * WrapPi(theta - prev_theta);
                Check(advance > 0.0 && advance <= 3.14159265358979323846, "orbit advances in the fixed sense without opposite-side jumps");
                if (hop >= 2) Check(advance >= 0.5 && advance <= 0.9, "settled orbit advances ~2*step per waypoint");
                prev_theta = theta;
                qx = hx;
                qz = hz;
            }
        }
    }
}

void TestClock() {
    Settings cfg;  // defaults: interval 4000
    cfg.probe_stagger_ms = 0;
    cfg.first_probe_delay_ms = 10000;  // deliberately LONGER than the interval

    Input in = ValidInput();
    in.now_ms = 100;
    State st;
    Decision d = Evaluate(st, in, cfg);
    Check(d.mode == Mode::Orbit && d.reason == Reason::Established && !d.probe_due && !d.state_reset,
          "valid attacker of a formed square establishes the orbit without a probe");
    Check(st.active && st.next_probe_ms == 10100 && st.previous_ms == 100, "first probe scheduled at now + first_probe_delay_ms");
    Check(st.direction == DirectionForUnit(in.unit_id) && (st.direction == 1 || st.direction == -1),
          "circling sense fixed from the unit identity at establishment");
    Check(st.model_token == in.model_token && st.unit_id == in.unit_id && st.order_serial == in.order_serial && st.target_id == in.target_id,
          "state carries the full attack identity");

    in.now_ms = 3000;
    d = Evaluate(st, in, cfg);
    Check(d.mode == Mode::Orbit && d.reason == Reason::Orbiting && !d.probe_due && st.next_probe_ms == 10100,
          "normal advance before the first deadline keeps the longer first delay");
    in.now_ms = 10099;
    Check(!Evaluate(st, in, cfg).probe_due && st.next_probe_ms == 10100, "one tick before the deadline stays quiet");

    in.now_ms = 10100;
    d = Evaluate(st, in, cfg);
    Check(d.probe_due && st.next_probe_ms == 14100, "probe fires exactly at the deadline and reschedules by the interval");
    d = Evaluate(st, in, cfg);
    Check(!d.probe_due && st.next_probe_ms == 14100, "repeated timestamp cannot repeat the probe");

    in.now_ms = 20000;  // far past the deadline
    d = Evaluate(st, in, cfg);
    Check(d.probe_due && st.next_probe_ms == 24000, "however late, one advancing evaluation yields at most one probe");

    in.now_ms = 15000;  // observed rewind
    d = Evaluate(st, in, cfg);
    Check(!d.probe_due && st.next_probe_ms == 19000 && st.previous_ms == 15000, "rewind rebases by one interval without probing");
    in.now_ms = 19000;
    Check(Evaluate(st, in, cfg).probe_due && st.next_probe_ms == 23000, "rebased deadline probes when reached");

    in.now_ms = UINT64_MAX - 1;
    d = Evaluate(st, in, cfg);
    Check(d.probe_due && st.next_probe_ms == UINT64_MAX, "schedule saturates instead of wrapping");
    in.now_ms = UINT64_MAX;
    d = Evaluate(st, in, cfg);
    Check(d.probe_due && st.next_probe_ms == UINT64_MAX, "the last advanceable timestamp still yields its probe");
    d = Evaluate(st, in, cfg);
    Check(!d.probe_due && st.next_probe_ms == UINT64_MAX, "saturated repeated timestamp cannot repeat a probe");

    // Interval sanitisation: below the 100 ms minimum the cadence stays >= 100 ms; above it passes through.
    Settings tiny = cfg;
    tiny.probe_interval_ms = 50;
    State st2;
    Input in2 = ValidInput();
    in2.now_ms = 0;
    Evaluate(st2, in2, tiny);
    in2.now_ms = 10000;
    d = Evaluate(st2, in2, tiny);
    Check(d.probe_due && st2.next_probe_ms - 10000 >= 100, "sub-minimum interval is sanitised to at least 100 ms");
    Settings odd = cfg;
    odd.probe_interval_ms = 150;
    State st3;
    Input in3 = ValidInput();
    in3.now_ms = 0;
    Evaluate(st3, in3, odd);
    in3.now_ms = 10000;
    d = Evaluate(st3, in3, odd);
    Check(d.probe_due && st3.next_probe_ms == 10150, "in-range interval passes through unchanged");
}

void TestStagger() {
    Settings cfg;  // defaults: first 2500, stagger 1500
    uint32_t offsets[64];
    for (uint32_t i = 0; i < 64; ++i) {
        Input in = ValidInput();
        in.unit_id = 100 + i;
        in.now_ms = 1000;
        State st;
        Evaluate(st, in, cfg);
        offsets[i] = uint32_t(st.next_probe_ms - 1000 - cfg.first_probe_delay_ms);
        Check(offsets[i] <= cfg.probe_stagger_ms, "stagger offset within [0, stagger]");
        Check(st.next_probe_ms >= 1000 + cfg.first_probe_delay_ms, "stagger never shortens the first delay");
    }
    int distinct = 0;
    for (uint32_t i = 0; i < 64; ++i) {
        bool first = true;
        for (uint32_t j = 0; j < i; ++j) first = first && offsets[j] != offsets[i];
        if (first) ++distinct;
    }
    Check(distinct >= 20, "stagger spreads a regiment across many distinct offsets");

    Input in = ValidInput();
    in.unit_id = 137;
    in.now_ms = 0;
    State a, b;
    Evaluate(a, in, cfg);
    Evaluate(b, in, cfg);
    Check(a.next_probe_ms == b.next_probe_ms, "stagger offset is deterministic per identity");

    Settings flat = cfg;
    flat.probe_stagger_ms = 0;
    State c;
    Evaluate(c, in, flat);
    Check(c.next_probe_ms == cfg.first_probe_delay_ms, "zero stagger disables the offset entirely");
}

void TestGates() {
    Settings cfg;
    cfg.probe_stagger_ms = 0;
    struct Case {
        const char* name;
        Reason reason;
        void (*mutate)(Input&);
    };
    const Case cases[] = {
        {"dead", Reason::NotAlive, [](Input& i) { i.alive = false; }},
        {"dismounted", Reason::NotMounted, [](Input& i) { i.mounted = false; }},
        {"routing", Reason::Routing, [](Input& i) { i.routing = true; }},
        {"square dissolved", Reason::TargetNotSquare, [](Input& i) { i.target_is_square = false; }},
        {"order dropped", Reason::NoOrder, [](Input& i) { i.order_serial = 0; }},
        {"target lost", Reason::NoTarget, [](Input& i) { i.target_id = 0; }},
        {"unit identity lost", Reason::NoUnit, [](Input& i) { i.unit_id = 0; }},
        {"nonfinite coordinate", Reason::InvalidInput, [](Input& i) { i.own_z = std::nanf(""); }},
        {"coordinate beyond bound", Reason::InvalidInput, [](Input& i) { i.own_x = 1000001.0f; }},
        {"negative coordinate beyond bound", Reason::InvalidInput, [](Input& i) { i.target_x = -1000001.0f; }},
        {"zero target radius", Reason::InvalidInput, [](Input& i) { i.target_radius = 0.0f; }},
        {"oversized target radius", Reason::InvalidInput, [](Input& i) { i.target_radius = 1001.0f; }},
        {"negative own radius", Reason::InvalidInput, [](Input& i) { i.own_radius = -0.5f; }},
        {"nonfinite own radius", Reason::InvalidInput, [](Input& i) { i.own_radius = std::nanf(""); }},
    };
    for (const Case& c : cases) {
        State st;
        Input in = ValidInput();
        in.now_ms = 50;
        Evaluate(st, in, cfg);
        Check(st.active, "gate case starts from an active orbit");
        c.mutate(in);
        in.now_ms = 60;
        const Decision d = Evaluate(st, in, cfg);
        Check(d.mode == Mode::Native && d.reason == c.reason && d.state_reset && !d.probe_due && Cleared(st), c.name);
    }

    // Diagnostic precedence: the life gate outranks the mount gate, routing outranks square dissolution.
    State st;
    Input in = ValidInput();
    in.now_ms = 50;
    Evaluate(st, in, cfg);
    in.alive = false;
    in.mounted = false;
    in.now_ms = 60;
    Check(Evaluate(st, in, cfg).reason == Reason::NotAlive && Cleared(st), "dead dominates dismounted in the reported reason");
    in = ValidInput();
    in.now_ms = 70;
    Evaluate(st, in, cfg);
    in.routing = true;
    in.target_is_square = false;
    in.now_ms = 80;
    Check(Evaluate(st, in, cfg).reason == Reason::Routing && Cleared(st), "routing dominates square dissolution in the reported reason");

    // Gate failure on already-inactive state: reported, but no reset claim.
    State idle;
    Input dead = ValidInput();
    dead.alive = false;
    dead.now_ms = 10;
    Decision d = Evaluate(idle, dead, cfg);
    Check(d.mode == Mode::Native && d.reason == Reason::NotAlive && !d.state_reset && Cleared(idle),
          "gate failure on inactive state claims no reset");

    // Recovery: after a gate handback the next valid evaluation establishes a fresh orbit.
    State st2;
    Input in2 = ValidInput();
    in2.now_ms = 50;
    Evaluate(st2, in2, cfg);
    in2.alive = false;
    in2.now_ms = 60;
    Evaluate(st2, in2, cfg);
    in2.alive = true;
    in2.now_ms = 70;
    d = Evaluate(st2, in2, cfg);
    Check(d.mode == Mode::Orbit && d.reason == Reason::Established && !d.probe_due && st2.active && st2.next_probe_ms == 70 + cfg.first_probe_delay_ms,
          "recovered unit re-establishes with a fresh first delay");
}

void TestIdentityTransitions() {
    Settings cfg;
    cfg.probe_stagger_ms = 0;
    const struct { const char* name; Reason reason; void (*mutate)(Input&); } cases[] = {
        {"model change", Reason::ModelChanged, [](Input& i) { i.model_token = 8; }},
        {"unit change", Reason::UnitChanged, [](Input& i) { i.unit_id = 42; }},
        {"order change", Reason::OrderChanged, [](Input& i) { i.order_serial = 4; }},
        {"target change", Reason::TargetChanged, [](Input& i) { i.target_id = 903; }},
    };
    for (const auto& c : cases) {
        State st;
        Input in = ValidInput();
        in.now_ms = 10;
        Evaluate(st, in, cfg);
        Check(st.active, "identity case starts from an active orbit");
        c.mutate(in);
        in.now_ms = 20;
        const Decision d = Evaluate(st, in, cfg);
        Check(d.mode == Mode::Native && d.reason == c.reason && d.state_reset && !d.probe_due && Cleared(st), c.name);
        // The changed attack is NOT seized in the transition call: the next valid call establishes it fresh.
        const Decision d2 = Evaluate(st, in, cfg);
        Check(d2.mode == Mode::Orbit && d2.reason == Reason::Established && !d2.probe_due && st.active &&
                  st.next_probe_ms == 20 + cfg.first_probe_delay_ms && st.model_token == in.model_token && st.unit_id == in.unit_id &&
                  st.order_serial == in.order_serial && st.target_id == in.target_id && st.direction == DirectionForUnit(in.unit_id),
              "next valid call establishes the changed attack fresh");
    }

    // The circling sense never changes while the orbit is active, and Orbit decisions carry a valid waypoint.
    State st;
    Input in = ValidInput();
    in.now_ms = 0;
    Evaluate(st, in, cfg);
    const int fixed = st.direction;
    float clearance = 0.0f;
    Check(ClearanceRadius(in.target_radius, in.own_radius, cfg, clearance), "gate-flow clearance computes");
    const double guarded = GuardedRadius(double(clearance), in.own_x, in.own_z, in.target_x, in.target_z);
    const double slack = 4.0 * double(std::numeric_limits<float>::epsilon()) * (guarded + 40.0) + 1.0e-6;

    for (uint64_t t = 100; t <= 25000; t += 700) {
        in.now_ms = t;
        const Decision d = Evaluate(st, in, cfg);
        Check(d.mode == Mode::Orbit && st.direction == fixed, "circling sense constant across the orbit");
        const double wd = std::hypot(double(d.waypoint_x) - double(in.target_x), double(d.waypoint_z) - double(in.target_z));
        Check(wd >= double(clearance) && wd <= guarded / std::cos(double(cfg.orbit_step_radians)) + slack,
              "orbit decision waypoint stays inside the corridor");
        Check(SegmentMinDistance(in.own_x, in.own_z, d.waypoint_x, d.waypoint_z, double(in.target_x), double(in.target_z)) >= double(clearance),
              "orbit decision segment clears the target circle");
    }

    // Coordinates at exactly the accepted bound are valid; one metre beyond is not.
    Input edge = ValidInput();
    edge.own_x = 1.0e6f;
    edge.own_z = 0.0f;
    edge.target_x = 0.0f;
    edge.target_z = 0.0f;
    edge.now_ms = 5;
    State stEdge;
    const Decision de = Evaluate(stEdge, edge, cfg);
    Check(de.mode == Mode::Orbit && stEdge.active, "coordinate at exactly the bound is accepted");
    edge.own_x = -1000001.0f;
    edge.now_ms = 6;
    Check(Evaluate(stEdge, edge, cfg).reason == Reason::InvalidInput && Cleared(stEdge), "coordinate one metre beyond the bound hands back");
}

}  // namespace

int main() {
    TestDefaultsAndDirection();
    TestClearanceRadius();
    TestWaypointPrimitive();
    TestSegmentAndCorridor();
    TestClock();
    TestStagger();
    TestGates();
    TestIdentityTransitions();
    std::printf("native_cavalry_orbit: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
