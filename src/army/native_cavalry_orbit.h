#pragma once
#include <stdint.h>

// Cavalry orbit policy (pure, deterministic, allocation-free): decides, per mounted unit that holds an accepted attack order against a formed square, whether the
// unit keeps its native behaviour or circles the square, and where its next waypoint is. This module owns NO native memory: it never reads or writes the game, it has
// no RNG and no clock (time is a caller-supplied simulation tick in milliseconds). The caller (the native adapter) supplies the live facts each evaluation, applies the
// waypoint through whatever native movement mechanism it owns, and is solely responsible for choosing and driving the riders of a probe wave. Nothing in here
// implements gameplay by itself; a Decision is an advisory output.
//
// Tactical policy values below (Settings) are explicit named constants of THIS feature. They are not copied from, and never override, the loaded mod database's unit
// speed / range / ammo / spacing / capability values; the only database-derived inputs are the two radii the caller measures (live target footprint, own formation).
//
// Geometry contract [see native_cavalry_orbit.cpp for the derivation]: with C the target centre, P the own position and R = target_radius + own_radius +
// clearance_margin. Geometry uses R plus a small coordinate-scaled rounding allowance so conversion to native floats does not cut into R.
//   * P outside that guarded circle: W steps `orbit_step_radians` past the tangent point along the tangent line.
//     The straight segment P->W stays outside R. |W-C| is bounded by guarded_R / cos(step), avoiding opposite-side jumps.
//   * P inside the guarded circle: radial outward escape to guarded_R + escape_margin. Distance from C never decreases.
//     Only exact coincidence (P == C) picks an outward direction deterministically from the unit identity.
//   * The circling sense (+1 counter-clockwise in X/Z, -1 clockwise) is fixed per unit by a hash of the unit identity and never changes while the orbit is active.
namespace kntwr_cavalry_orbit {

enum class Mode : uint8_t {
    Native = 0,  // leave the unit entirely to the native AI/movement; the policy state has been (or already was) reset
    Orbit = 1    // the unit should circle; waypoint_x/z is valid
};

// Why the decision is what it is (diagnostic; Native reasons double as the cause of a reset).
enum class Reason : uint8_t {
    Established = 0,  // Orbit: fresh state created by this call
    Orbiting,         // Orbit: existing state continued
    InvalidInput,     // Native: a coordinate/radius is nonfinite, out of the settings' bounds, or the target radius is not positive
    NotAlive,         // Native: unit dead
    NotMounted,       // Native: unit no longer mounted
    Routing,          // Native: unit routing / fleeing
    TargetNotSquare,  // Native: the target is not (or no longer) a formed square
    NoOrder,          // Native: no accepted attack order (order_serial == 0)
    NoTarget,         // Native: no target identity (target_id == 0)
    NoUnit,           // Native: unit identity missing (unit_id == 0)
    ModelChanged,     // Native: model/battle identity token changed while active
    UnitChanged,      // Native: the state belonged to another unit identity
    OrderChanged,     // Native: a new attack order (different serial) was accepted
    TargetChanged,    // Native: same order serial but the target identity differs
    GeometryFailed    // Native: the waypoint was not finite (should be unreachable for validated input)
};

struct Settings {
    float clearance_margin = 2.0f;          // metres added to target_radius + own_radius to form the clearance radius R (>= 0)
    float escape_margin = 1.0f;             // metres beyond R that an inside-the-circle unit is sent to (>= 0)
    float orbit_step_radians = 0.35f;       // arc advanced past the tangent point per waypoint, clamped to [0.05, 0.6]
    float max_radius = 1000.0f;             // largest accepted target/own radius, metres (clamped to [1, 10000])
    float max_coordinate = 1.0e6f;          // largest accepted |x|/|z|, metres (clamped to [1, 1e7])
    uint32_t probe_interval_ms = 4000;      // cadence of probe-wave opportunities while orbiting (minimum 100)
    uint32_t first_probe_delay_ms = 2500;   // delay from establishment to the first opportunity
    uint32_t probe_stagger_ms = 1500;       // per-unit deterministic offset in [0, stagger] added to the first delay, so a regiment does not probe in lockstep
};

Settings DefaultSettings();

// Everything the policy needs, evaluated for ONE unit at ONE simulation time.
struct Input {
    uint64_t now_ms = 0;        // simulation time in milliseconds (monotonic within one model_token; a rewind is tolerated)
    uint64_t model_token = 0;   // identity of the loaded battle/model (changes between battles or reloads)
    uint32_t unit_id = 0;       // stable unit identity, non-zero
    uint32_t order_serial = 0;  // serial of the accepted attack order, non-zero; a new accepted order has a new serial
    uint32_t target_id = 0;     // identity of the attacked target unit, non-zero
    float own_x = 0.0f, own_z = 0.0f;        // own formation centre, X/Z plane
    float target_x = 0.0f, target_z = 0.0f;  // target formation centre, X/Z plane
    float target_radius = 0.0f;  // LIVE footprint radius of the target square, > 0
    float own_radius = 0.0f;     // own formation radius, >= 0
    bool mounted = false;
    bool alive = false;
    bool routing = false;
    bool target_is_square = false;
};

// Per-unit state: plain finite data, copyable, zero == inactive. Owned by the caller; the policy mutates it only through Evaluate / Reset.
struct State {
    bool active = false;
    int8_t direction = 0;          // +1 counter-clockwise, -1 clockwise (valid while active)
    uint64_t model_token = 0;
    uint32_t unit_id = 0;
    uint32_t order_serial = 0;
    uint32_t target_id = 0;
    uint64_t next_probe_ms = 0;    // next probe-wave opportunity (valid while active)
    uint64_t previous_ms = 0;      // last evaluation time: distinguishes rewinds and repeated saturated timestamps
};

struct Decision {
    Mode mode = Mode::Native;
    Reason reason = Reason::InvalidInput;
    float waypoint_x = 0.0f;       // valid only for Mode::Orbit
    float waypoint_z = 0.0f;
    bool probe_due = false;        // Orbit only: a probe-wave opportunity is due now; the caller decides what (if anything) to do with it
    bool state_reset = false;      // true when this call cleared previously ACTIVE state (the caller must hand the unit back to native control immediately)
};

void Reset(State& state);

// One transition. Policy:
//   * Any gate failure (alive / mounted / routing / target square / order / target / unit identity / finite-and-bounded numbers) resets the state and returns Native.
//   * Active state whose model_token / unit_id / order_serial / target_id differs from the input resets and returns Native IN THIS CALL; the different attack is NOT
//     seized here. The next valid call finds inactive state and establishes a fresh one.
//   * Inactive state with a valid input establishes (direction from the unit identity, first probe at now + first_probe_delay + stagger) and returns Orbit with the
//     first waypoint; probe_due is false on that call.
//   * Active matching state emits at most one probe when time advances to/past the deadline, then schedules now + interval (saturating).
//     Repeated timestamps never repeat a probe; an observed rewind rebases to now + interval without probing. Long first delays remain intact.
Decision Evaluate(State& state, const Input& input, const Settings& settings);

// The clearance radius R used by Evaluate (sanitised settings). Returns false (R unchanged) for nonfinite/out-of-bound radii or a non-positive target radius.
bool ClearanceRadius(float target_radius, float own_radius, const Settings& settings, float& clearance);

// Pure waypoint geometry (what Evaluate uses). `direction` is +1/-1 (any other value is treated as +1), `unit_id` only seeds the coincident-centre escape direction.
// `clearance` is R > 0 as from ClearanceRadius. Returns false (outputs untouched) for nonfinite input or a nonfinite result.
bool ComputeWaypoint(float own_x, float own_z, float target_x, float target_z, float clearance, int direction, uint32_t unit_id, const Settings& settings,
                     float& waypoint_x, float& waypoint_z);

// Deterministic circling sense (+1 / -1) of a unit identity; no RNG.
int DirectionForUnit(uint32_t unit_id);
}  // namespace kntwr_cavalry_orbit
