#include "native_cavalry_orbit.h"

#include <cmath>
#include <limits>

namespace kntwr_orbit_detail {
using kntwr_cavalry_orbit::Settings;

constexpr double kBoundaryGuard = 1.0e-3;  // metres, in addition to the coordinate-scaled float rounding allowance

inline bool Finite(float v) { return std::isfinite(v) != 0; }

inline uint32_t Hash32(uint32_t x) {  // fmix32 (finalizer of MurmurHash3); fixed integer mixing, no RNG
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

inline float SanePos(float v, float fallback, float lo, float hi) {  // nonfinite/negative/out-of-bound setting -> fallback, else clamp
    if (!Finite(v) || v < 0.0f) return fallback;
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

inline uint32_t SaneU32(uint32_t v, uint32_t fallback, uint32_t lo) {
    return v < lo ? fallback : v;
}

struct Sanitised {
    float clearance_margin;
    float escape_margin;
    float orbit_step;
    float max_radius;
    float max_coordinate;
    uint32_t probe_interval_ms;
    uint32_t first_probe_delay_ms;
    uint32_t probe_stagger_ms;
};

inline Sanitised Sanitise(const Settings& s) {
    Sanitised c;
    c.clearance_margin = SanePos(s.clearance_margin, 2.0f, 0.0f, 1000.0f);
    c.escape_margin = SanePos(s.escape_margin, 1.0f, 0.0f, 1000.0f);
    c.orbit_step = SanePos(s.orbit_step_radians, 0.35f, 0.05f, 0.6f);
    c.max_radius = SanePos(s.max_radius, 1000.0f, 1.0f, 10000.0f);
    c.max_coordinate = SanePos(s.max_coordinate, 1.0e6f, 1.0f, 1.0e7f);
    c.probe_interval_ms = SaneU32(s.probe_interval_ms, 4000, 100);
    c.first_probe_delay_ms = s.first_probe_delay_ms;  // >= 0 by type
    c.probe_stagger_ms = s.probe_stagger_ms > 3600000u ? 3600000u : s.probe_stagger_ms;  // bound: consumed as `% (stagger + 1)`, where UINT32_MAX + 1 wraps to 0
    return c;
}

inline uint64_t SatAdd(uint64_t a, uint64_t b) {  // clock arithmetic must never wrap
    uint64_t r = a + b;
    return r < a ? ~uint64_t(0) : r;
}
}  // namespace kntwr_orbit_detail

namespace kntwr_cavalry_orbit {

Settings DefaultSettings() { return Settings(); }

void Reset(State& state) {
    state.active = false;
    state.direction = 0;
    state.model_token = 0;
    state.unit_id = 0;
    state.order_serial = 0;
    state.target_id = 0;
    state.next_probe_ms = 0;
    state.previous_ms = 0;
}

int DirectionForUnit(uint32_t unit_id) { return (kntwr_orbit_detail::Hash32(unit_id ^ 0x5bd1e995u) & 1) ? -1 : 1; }

bool ClearanceRadius(float target_radius, float own_radius, const Settings& settings, float& clearance) {
    const kntwr_orbit_detail::Sanitised c = kntwr_orbit_detail::Sanitise(settings);
    if (!kntwr_orbit_detail::Finite(target_radius) || !kntwr_orbit_detail::Finite(own_radius)) return false;
    if (target_radius <= 0.0f || target_radius > c.max_radius) return false;
    if (own_radius < 0.0f || own_radius > c.max_radius) return false;
    const double r = double(target_radius) + double(own_radius) + double(c.clearance_margin);
    const float rf = float(r);
    if (!kntwr_orbit_detail::Finite(rf)) return false;  // unreachable for validated inputs; kept so the contract is total
    clearance = rf;
    return true;
}

bool ComputeWaypoint(float own_x, float own_z, float target_x, float target_z, float clearance, int direction, uint32_t unit_id, const Settings& settings,
                     float& waypoint_x, float& waypoint_z) {
    if (!kntwr_orbit_detail::Finite(own_x) || !kntwr_orbit_detail::Finite(own_z) || !kntwr_orbit_detail::Finite(target_x) ||
        !kntwr_orbit_detail::Finite(target_z) || !kntwr_orbit_detail::Finite(clearance) || clearance <= 0.0f) {
        return false;
    }
    const kntwr_orbit_detail::Sanitised c = kntwr_orbit_detail::Sanitise(settings);
    const int dir = direction == -1 ? -1 : 1;
    const double px = double(own_x), pz = double(own_z), cx = double(target_x), cz = double(target_z);
    // Tangent contact needs headroom: rounding W to native floats must not cut into the requested circle.
    const double scale = std::fmax(1.0, std::fmax(double(clearance),
        std::fmax(std::fmax(std::fabs(px), std::fabs(pz)), std::fmax(std::fabs(cx), std::fabs(cz)))));
    const double r = double(clearance) + kntwr_orbit_detail::kBoundaryGuard +
                     4.0 * std::numeric_limits<float>::epsilon() * scale;

    const double dx = px - cx, dz = pz - cz;
    const double d2 = dx * dx + dz * dz;
    const double d = std::sqrt(d2);

    double wx = 0.0, wz = 0.0;
    if (d <= r) {
        // Inside the clearance circle: radial escape. The segment P->W points away from C, so the distance from C does not decrease along it.
        double ux, uz;
        if (d == 0.0) {
            // Only exact coincidence lacks an outward direction. Never replace a nonzero offset with an arbitrary direction.
            const uint32_t h = kntwr_orbit_detail::Hash32(unit_id ^ 0x9e3779b9u);
            const double a = double(h) * (6.283185307179586 / 4294967296.0) + (dir < 0 ? 3.1415926535897932 : 0.0);
            ux = std::cos(a);
            uz = std::sin(a);
        } else {
            ux = dx / d;
            uz = dz / d;
        }
        const double reach = std::fmax(d, r + double(c.escape_margin));
        wx = cx + ux * reach;
        wz = cz + uz * reach;
    } else {
        // Outside (or on) the clearance circle: tangent-line step.
        //   alpha = acos(R/d) is the half-angle at C between C->P and the tangent radius, so T = C + R*(cos(phi), sin(phi)) with phi = theta + dir*alpha is the
        //   tangent point on the P side of the chosen circling sense, and the unit tangent there is t = dir*(-sin(phi), cos(phi)).
        //   W = T + t * R*tan(step): every point of P->T->W lies on or outside the tangent line, whose distance from C is exactly R, so the whole straight
        //   segment P->W stays outside the circle. |W-C| = R/cos(step) (<= R*1.22 at the 0.6 clamp): the outward drift per step is bounded and the next
        //   evaluation re-tangents from the new position, so a long orbit stays within a corridor [R, ~1.2 R].
        const double ratio = r / d;  // d > r, including the float-rounding allowance
        const double theta = std::atan2(dz, dx);
        const double alpha = std::acos(ratio);
        const double phi = theta + double(dir) * alpha;
        const double tx = cx + r * std::cos(phi), tz = cz + r * std::sin(phi);
        const double step = double(c.orbit_step);
        wx = tx + double(dir) * (-std::sin(phi)) * r * std::tan(step);
        wz = tz + double(dir) * (std::cos(phi)) * r * std::tan(step);
    }

    const float fx = float(wx), fz = float(wz);
    if (!kntwr_orbit_detail::Finite(fx) || !kntwr_orbit_detail::Finite(fz)) return false;
    waypoint_x = fx;
    waypoint_z = fz;
    return true;
}

Decision Evaluate(State& state, const Input& in, const Settings& settings) {
    using namespace kntwr_orbit_detail;
    Decision out;  // mode Native, probe_due false, state_reset false

    // 1. Gate: the unit must be a live, mounted, non-routing attacker of a formed square, with usable identities and finite, bounded numbers. Any failure resets
    //    ACTIVE state (immediate native handback) and yields Native for this call.
    const Sanitised cfg = Sanitise(settings);
    const bool numeric = Finite(in.own_x) && Finite(in.own_z) && Finite(in.target_x) && Finite(in.target_z) && Finite(in.target_radius) && Finite(in.own_radius) &&
                         (in.own_x >= -cfg.max_coordinate) && (in.own_x <= cfg.max_coordinate) && (in.own_z >= -cfg.max_coordinate) &&
                         (in.own_z <= cfg.max_coordinate) && (in.target_x >= -cfg.max_coordinate) && (in.target_x <= cfg.max_coordinate) &&
                         (in.target_z >= -cfg.max_coordinate) && (in.target_z <= cfg.max_coordinate);
    float clearance = 0.0f;
    const bool radii = numeric && ClearanceRadius(in.target_radius, in.own_radius, settings, clearance);
    Reason gate;
    if (!numeric || !radii) gate = Reason::InvalidInput;
    else if (!in.alive) gate = Reason::NotAlive;
    else if (!in.mounted) gate = Reason::NotMounted;
    else if (in.routing) gate = Reason::Routing;
    else if (!in.target_is_square) gate = Reason::TargetNotSquare;
    else if (in.order_serial == 0) gate = Reason::NoOrder;
    else if (in.target_id == 0) gate = Reason::NoTarget;
    else if (in.unit_id == 0) gate = Reason::NoUnit;
    else gate = Reason::Established;  // sentinel: gates passed

    if (gate != Reason::Established) {
        if (state.active) {
            Reset(state);
            out.state_reset = true;
        }
        out.reason = gate;
        return out;  // Native
    }

    // 2. Identity/order transition. A mismatch while active resets and hands back in THIS call; the new attack is not seized here. Subsequent valid input finds
    //    inactive state and establishes fresh (step 3).
    if (state.active) {
        Reason drop = Reason::Established;
        if (state.model_token != in.model_token) drop = Reason::ModelChanged;
        else if (state.unit_id != in.unit_id) drop = Reason::UnitChanged;
        else if (state.order_serial != in.order_serial) drop = Reason::OrderChanged;
        else if (state.target_id != in.target_id) drop = Reason::TargetChanged;
        if (drop != Reason::Established) {
            Reset(state);
            out.state_reset = true;
            out.reason = drop;
            return out;  // Native
        }
    }

    // 3. Geometry (before any state commit, so a failed computation cannot leave half-updated state).
    const int dir = state.active ? (state.direction < 0 ? -1 : 1) : DirectionForUnit(in.unit_id);
    float wx = 0.0f, wz = 0.0f;
    if (!ComputeWaypoint(in.own_x, in.own_z, in.target_x, in.target_z, clearance, dir, in.unit_id, settings, wx, wz)) {
        if (state.active) {
            Reset(state);
            out.state_reset = true;
        }
        out.reason = Reason::GeometryFailed;
        return out;  // Native
    }

    // 4. Preserve the initial delay. An observed clock rewind rebases by one interval without emitting a probe.
    //    Advancing time can emit at most one opportunity; repeated timestamps (including saturation) cannot repeat it.
    uint64_t next = 0;
    bool probe = false;
    const bool established = !state.active;
    if (established) {
        const uint32_t spread = cfg.probe_stagger_ms == 0 ? 0 : (Hash32(in.unit_id ^ 0x2545f491u) % (cfg.probe_stagger_ms + 1));
        next = SatAdd(in.now_ms, uint64_t(cfg.first_probe_delay_ms) + uint64_t(spread));
    } else {
        next = state.next_probe_ms;
        if (in.now_ms < state.previous_ms) next = SatAdd(in.now_ms, cfg.probe_interval_ms);
        else if (in.now_ms > state.previous_ms && in.now_ms >= next) {
            probe = true;
            next = SatAdd(in.now_ms, cfg.probe_interval_ms);
        }
    }

    // 5. Commit.
    state.active = true;
    state.direction = int8_t(dir);
    state.model_token = in.model_token;
    state.unit_id = in.unit_id;
    state.order_serial = in.order_serial;
    state.target_id = in.target_id;
    state.next_probe_ms = next;
    state.previous_ms = in.now_ms;

    out.mode = Mode::Orbit;
    out.reason = established ? Reason::Established : Reason::Orbiting;
    out.waypoint_x = wx;
    out.waypoint_z = wz;
    out.probe_due = probe;
    return out;
}
}  // namespace kntwr_cavalry_orbit
