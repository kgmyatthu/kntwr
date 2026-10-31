// --cavalry-orbit native adapter: binds the pure policy (native_cavalry_orbit.h) to the live engine.
// Mechanism (see the header and local://cavalry-implementation-contract.md for the full evidence trail):
//   * BeginTick (tick owner, after the AI join, before the native tick) walks the native unit graph in two
//     passes: pass one fills the known-unit set for the WHOLE graph before any target is consulted, pass two
//     gathers facts (footprints, mounted, formed-square) and evaluates the policy for every mounted unit
//     holding the attack row 0x1324080 against a formed square.
//   * The movement hook captures the native 0x2A-byte descriptor verbatim. Orbit copies use normalized
//     world-space waypoints for each rider's sticky side/lane; captured descriptors remain native handbacks.
//   * Scoped Go (+0x118) and Combat (+0x110) hooks keep unfinished adapter-owned movement, replace it once
//     when needed, or pass through. Allowed returns are 0x7FF51A/0x7FF53D and 0x64DED6/0x7FF4AF respectively.
//     Other callers, native refusal and temporary controllers remain native; no direct phase/activity/attachment writes.
//   * A probe wave is an EXPLICIT native combat admission: the chosen mounts get a staged 0x5DCDE0 install of
//     initialized native descriptor with mode 1, the ordered target unit at +4, and loaded native defaults,
//     melee starts through the same verified installer the phase-2 driver uses - phase 1 movement nodes are
//     replaced in place, no raw phase writes.  The shared tracker-tick seam re-proves identity, membership,
//     accepted attack identity, routing and target liveness before each restriction, and releases a held
//     target only through the native 0x63CE00.
//   * Expiry (window elapsed, or any tracker recheck failure) restores the captured movement descriptor via a
//     native 0x5DD450 install in the SAME EndTick - unconditionally and unbudgeted, because a native combat
//     node persists on its own.  Handbacks on unit exit are equally unbudgeted; only renewals and probe
//     admissions are budgeted per tick.
//   * Waypoint Y is sampled with the native terrain query 0x57E870 (thiscall ECX = model, out XYZ*, in XZ*,
//     plane = 0, EAX = out) at the exact new waypoint. Failed queries never fabricate an orbit height.
//   * Orbit descriptor copies are normalized (NormalizeOrbit) AFTER the XYZ rewrite: the native begin (0x816900)
//     applies 0x66AD00 with a slot offset and paces the new leg using the OLD time at desc+0x24, so the time is
//     recomputed as distanceXZ(mount, waypoint) / speed(desc+0x20) (t == 0 = native untimed). If desc+0x29 != 0
//     the pending order adjust is resolved through the read-only native 0x66AE10 query (thiscall ECX = mount,
//     stack: order desc+0x18, mode desc+0x1C, ret 8, EAX = order; it reaches 0x586400 with the loaded unit+0x194
//     signed threshold and the DB+0x59C rule, which are never duplicated here), the queried order is stored and
//     only desc+0x29 is cleared. Speed/gait stay native. rec.desc and every original handback stay byte exact.
//   * Retained attack intent: the queue-step destructor gate (0x582736-class call sites, invoked with the
//     row intact before the native 0x529D80 body) classifies each completion. The byte-proven normal class
//     (return 0x582738, or 0x56D8D8 under outer 0x58275C) RETAINS the accepted identity across the now-dead
//     row - its serial/target are stale memory by contract and are never read again; eligibility continues
//     while the queue sits untouched at the recorded position. A flush (0x542AE0 entry observation, any
//     thread, atomics only), a new order, rout-out or death cancels. E steering (V(0x1450918)) defers installs.
//   * Native-side effects: the native destructor DOES write +0x478; this adapter never writes agent
//     activity, phase or attachments directly.
//
// Safety model: outside an owner-thread epoch every hook is the identity (the original runs, untouched
// state).  Every native dereference happens inside one __try bracket whose faults count toward a hard
// disable (state discarded without any further dereference).  Mount records are never trusted across ticks:
// EndTick re-proves every record each tick (death, changed row, routing, membership), so a newly issued
// native command is never overwritten and exits are immediate. Hooks re-prove the live row or explicitly
// retained attack identity before interposing. No allocation happens after Bind; storage is static.
//
// Bounded static storage: 128 unit entries, 32768 mount records, indexed lookup tables, a deduplicated
// target-footprint cache, and staging sufficient for every owned mount to cancel in the same tick.
// Tick scans stop at the record high-water mark rather than walking unused capacity. Full member
// bounding boxes (no sampling) refresh every three ticks; target geometry is shared between attackers.
// Admission and renewal budgets are 16 each per tick. Cancellation and expiry are never budgeted.
// Frozen-class table: 65536 slots x 16 bytes = 1 MiB (static), bounded 64-probe.
// These bounds describe adapter work, not the downstream cost of native pathfinding or combat.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include "native_cavalry_runtime.h"
#include "native_cavalry_orbit.h"
#include "core/kntwr_guard.h"
#pragma fenv_access(on)

namespace kntwr_cavalry {
using namespace kntwr_cavalry_orbit;

namespace {
using B = unsigned char;

// -------------------------------------------------------------------------------------------- constants
constexpr U kDescBytes = 0x2A;
constexpr float kSquareGap = 15.0f;   // clear space beyond square and horse extents, in game units
constexpr U kMaxUnitEntries = 128;     // tracked units; overflow stays native (rare: full scene fits)
constexpr U kKnownSlots = 8192;        // per-tick stamp table of every live unit pointer
constexpr U kMaxRecords = 32768;       // mount records (power of two); exhaustion hands the unit back
constexpr U kMountHash = 131072;       // open addressing, record index + 1 (load factor <= 0.25)
constexpr U kProbeHash = 4096;         // keyed probe agents (mount + riders), record index + 1
constexpr U kCandidateMax = 512;       // per-tick candidate scratch
constexpr U kTargetCache = 128;        // deduplicated target footprint cache
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxUnitsPerWalk = 2048;
constexpr U kMemberScanCap = 16384, kRiderCap = 4;
constexpr U kWaveSize = 4;             // mounts per probe wave
constexpr U kProbeWindowTicks = 30;    // 3 s at the 10 Hz model tick
constexpr U kFootCadence = 3;          // footprint refresh cadence in ticks
constexpr U kArrive = 4, kDrift = 6;   // metres: waypoint reached / decision moved
constexpr U kRenewMin = 10;            // ticks between two installs on the same mount
constexpr U kMaxAge = 80;              // forced refresh even without arrival or drift
constexpr U kRenewBudget = 16;         // renewal installs per EndTick (budgeted)
constexpr U kAdmitBudget = 16;         // probe combat admissions per tick (budgeted)
constexpr U kStageMax = kMaxRecords + kAdmitBudget + kRenewBudget;
constexpr U kMaxFaults = 8;            // guarded faults before the adapter disables itself until Reset
constexpr float kCoordLimit = 1000000.0f;  // the policy's own max_coordinate: mod map sizes must not be excluded
constexpr U kStampEmpty = 0xFFFFFFFFu;
constexpr double kOuterLimit = 100.0; // user-permitted hard cap (game units) on the OUTER waypoint/mount envelope from the target centre
constexpr U kClassSlots = 65536, kClassProbe = 64;  // frozen per-member side classification table (power of two; bounded probe)

// native VAs (preferred base 0x400000)
constexpr U kMoveInstall = 0x5DD450, kCombatInstall = 0x5DCDE0, kCombatRet = 0x64DED6;
// slot +0x118 go-command begin (0x5DCE70, called via the 0x809CE0 tail jump: return = 0x7FF51A entity / 0x7FF53D point) and the
// command-layer combat install (slot +0x110 called from 0x7FF4F0-class begin 0x7FF490: return 0x7FF4AF)
constexpr U kGoRetEntity = 0x7FF51A, kGoRetPoint = 0x7FF53D, kCombatRetCmd = 0x7FF4AF;
constexpr U kOrbitNodeVt = 0x1348B44, kANode = 0x22C, kANodeDone = 0x234, kAHolderFlag = 0x2C4;
constexpr U kTrackerClear = 0x63CE00, kMountedCall = 0x55ABF0, kTerrainQuery = 0x57E870;
constexpr U kOrderAdjust = 0x66AE10;
constexpr U kAttackRowVt = 0x1324080;

// unit / agent offsets (documented in the contract and the headers referenced above)
constexpr U kUClass = 0x2C, kUState = 0xAA0, kUMenCount = 0x2CC, kUMenArr = 0x2D0;
constexpr U kUFormation = 0xADC, kURowCnt = 0x930, kURowIdx = 0x934, kURowTail = 0x938, kURowBase = 0x398, kURowStride = 0x90;
constexpr U kRowSerial = 0x4, kRowTarget = 0x24;
constexpr U kUFsm = 0xD6C;               // unit FSM state slot: V(kFsmRout) routed-out, V(kFsmSteer) E steering
constexpr U kFsmRout = 0x145090C, kFsmSteer = 0x1450918;
constexpr U kAUnit = 0x1F0, kAX = 0x48, kAY = 0x4C, kAZ = 0x50, kARiders = 0x66C, kARiderArr = 0x670;
constexpr U kAOrder = 0x1D8, kAActivity = 0x1B8;  // AGENT fields only (native_unit_brain.cpp reads both as dwords)
constexpr U kTKey = 0x0, kTTarget = 0x10;
constexpr U kSlotIdx = 0xAE8, kSlotArr = 0xADC;

using ThisBool = unsigned char(__fastcall*)(U, U);
using TerrainFn = U(__fastcall*)(U, U, float*, const float*, U);
using OrderAdjustFn = U(__fastcall*)(U, U, U, U);  // thiscall ECX = mount; stack: order, mode; ret 8; EAX = order

// -------------------------------------------------------------------------------------------- SSE-only float ops
// (the hooks must not disturb the x87 state a native caller may rely on; every float op here is SSE)
__forceinline float FAdd(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float FSub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float FMul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float FDiv(float a, float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float FSqrt(float a) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(a))); }
__forceinline bool FLt(float a, float b) { return _mm_comilt_ss(_mm_set_ss(a), _mm_set_ss(b)); }
__forceinline float FMin(float a, float b) { return _mm_cvtss_f32(_mm_min_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float FMax(float a, float b) { return _mm_cvtss_f32(_mm_max_ss(_mm_set_ss(a), _mm_set_ss(b))); }

// exception-masked FP environment for the (double-precision) policy evaluation on the tick owner
// (same pattern as src/brain2/native_move_node.cpp:22-32)
struct FpGuard {
    __declspec(align(16)) B state[512];
    FpGuard() {
        _fxsave(state);
        unsigned short control; memcpy(&control, state, 2); control |= 0x3f;
        __asm fninit
        __asm fldcw word ptr [control]
        _mm_setcsr(_mm_getcsr() | 0x1f80);
    }
    ~FpGuard() { _fxrstor(state); }
};

inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline B RdB(U a) { return *reinterpret_cast<const volatile B*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline void Wr32(U a, U v) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a)) = v; }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool Good(float v) { return v == v && fabsf(v) < kCoordLimit; }  // fabsf: compiler intrinsic, no x87

// -------------------------------------------------------------------------------------------- state
struct Record {
    U mount, unit, memberIdx, lastTick;   // memberIdx is a cache; MemberOf re-proves it every use
    U flags, probeUntil;                  // flags: bit0 descriptor captured, bit1 probe, bit2 restore now
    U foreign;                            // foreignMark[mount] snapshot taken when the orbit node was last installed
    float wx, wz;                         // the waypoint currently installed for THIS mount
    float ux, uz;                         // square centre when this rider's waypoint was installed
    B desc[kDescBytes];                   // the captured native movement descriptor (verbatim)
    B lane1;                              // 1-based sticky orbit lane (0 = unassigned); odd = "+" side (direction -1), even = "-" side (direction +1)
    float rad;                            // lane radius at the last install of THIS mount's waypoint (0 = none): real prior radius for renewal
};
enum RecordFlag : U { rDesc = 1, rProbe = 2, rRenew = 4, rActivate = 8, rOrbit = 16 };
// rOrbit: the movement node currently on the mount was installed by THIS adapter from a normalized orbit descriptor
// (PlanMove/PlanCombat mode 1 or an unbudgeted Sweep stage).  A native approach node has the same vtable 0x1348B44, so the
// node alone proves nothing; rOrbit is cleared by every path that may install a native descriptor.

struct UnitEntry {
    U unit, stamp, serial, target;        // stamp == seq: confirmed by this tick's evaluation
    U footTick, cursor, probes, blockedSerial, blockedTarget;
    bool orbit, latched;     // latched to this attack after square acquisition, independent of enemy stance
    bool retained;           // attack identity retained across the consumed (dead) row: eligibility keeps
                             // running on the entry while the queue sits at the recorded empty position
    U headAfter;             // queue position recorded at consumption: count 0 and head == tail == headAfter
    float wx, wz;            // current policy waypoint (unit centre)
    float ox, oz, ownR;      // own formation centre / radius cache
    float tx, tz, tR;        // target footprint cache
    State policy;            // the pure policy's per-unit state
};

struct Stage { U mount, combat, unit, serial, target, memberIdx, orbit; B desc[kDescBytes]; };  // orbit: desc is a normalized orbit copy

U delta, imageLo, imageSize, moveInstall, combatInstall, combatRet, trackerClear, mountedCall, terrainQuery, orderAdjust;
U goRetEntity, goRetPoint, combatRetCmd;
// per-mount (hashed) counter bumped by every native order install this adapter could not observe in scope (any thread):
// a record's orbit authority is void when its snapshot no longer matches.  Collisions only void authority (fail to replace).
volatile long foreignMark[256];
inline U ForeignIdx(U mount) { return (mount >> 4) * 2654435761u >> 24; }
U ownerTid, curTick, curModel, seq, targetCursor, allocCursor, faults, staged;
U recordLimit; // high-water mark: empty capacity is never traversed on the tick path
U renewalCursor; // round-robin service; early arrivals cannot monopolize the native-install budget
volatile U epoch;
bool bound, disabled;
UnitEntry entries[kMaxUnitEntries];
Record records[kMaxRecords];
U mountHash[kMountHash];
struct ProbeSlot { U key, idx1; } probeHash[kProbeHash];   // keyed by AGENT; tombstone idx1 = kStampEmpty
U probeCount;
struct { U unit, stamp; } known[kKnownSlots];
struct { U target, tick; float cx, cz, r; } targetCache[kTargetCache];
Stage stage[kStageMax];
Settings settings;
struct Boundary { float minX, minZ, maxX, maxZ; bool valid; } boundary;
// Retained-identity publication (ObserveRowEnd/ObserveFlush).  flushKey[i] is the ring (unit+0x390) whose
// retained latch entry i carries (0 = unpublished); flushCancel[i] is the sticky flush veto, cleared before
// every key store.  flushBegin/flushEnd form a monotonic flush generation: a publication overlapping ANY
// flush (either counter moved since the entry snapshot) is discarded, so a flush can never miss a key.
// These are never reset - Bind/Reset/ClearAll leave the counters alone (a reset could wedge the protocol).
volatile long flushKey[kMaxUnitEntries];
volatile long flushCancel[kMaxUnitEntries];
volatile long flushBegin = 0, flushEnd = 0;

void ReadBoundary(U model) {
    boundary.minX = RdF(model + 0x84); boundary.minZ = RdF(model + 0x88);
    boundary.maxX = RdF(model + 0x8C); boundary.maxZ = RdF(model + 0x90);
    boundary.valid = Good(boundary.minX) && Good(boundary.minZ) &&
                     Good(boundary.maxX) && Good(boundary.maxZ) &&
                     FLt(boundary.minX, boundary.maxX) && FLt(boundary.minZ, boundary.maxZ);
}
bool BoundaryPoint(float x, float z, float memberRadius) {
    return boundary.valid && !FLt(x, FAdd(boundary.minX, memberRadius)) &&
           !FLt(FSub(boundary.maxX, memberRadius), x) &&
           !FLt(z, FAdd(boundary.minZ, memberRadius)) &&
           !FLt(FSub(boundary.maxZ, memberRadius), z);
}
// Called under FpGuard. Cover tangent and radial-escape waypoints. The native border renderer
// uses model X/Z min,min,max,max and adds a visual 2m outside this stricter playable rectangle.
bool OrbitFits(float x, float z, float targetRadius, float memberRadius, float extraRadius) {
    if (!boundary.valid) return false;
    float clearance;
    if (!ClearanceRadius(targetRadius, memberRadius, settings, clearance)) return false;
    const double scale = fmax(fmax(1.0, double(clearance)),
        fmax(fmax(fabs(double(x)), fabs(double(z))),
             fmax(fmax(fabs(double(boundary.minX)), fabs(double(boundary.minZ))),
                  fmax(fabs(double(boundary.maxX)), fabs(double(boundary.maxZ))))));
    const double guard = 0.001 + 4.0 * FLT_EPSILON * scale;
    const double step = fmax(0.05, fmin(0.6, double(settings.orbit_step_radians)));
    const double radius = double(clearance) + double(extraRadius) + guard;
    const double envelope = fmax(radius / cos(step), radius + settings.escape_margin) + guard;
    const double inset = double(memberRadius) + guard;
    if (envelope + inset > kOuterLimit) return false;  // hard cap: outer envelope + horse clearance + guard
    return double(x) - envelope >= double(boundary.minX) + inset &&
           double(x) + envelope <= double(boundary.maxX) - inset &&
           double(z) - envelope >= double(boundary.minZ) + inset &&
           double(z) + envelope <= double(boundary.maxZ) - inset;
}

// -------------------------------------------------------------------------------------------- split-flow orbit band
// A charging unit streams around BOTH sides of the attacked square. The charge line is frozen per order: origin O = own
// centre and direction D = target centre - own centre at first square acquisition (stored here, never per rider, never
// refreshed while the order lives). A rider's approach side is s = sign(cross(D, M-O)), cross = Dx*(Mz-Oz) - Dz*(Mx-Ox);
// native ComputeWaypoint sign is the NEGATIVE of the approach side. Lane1 odd => side "+" (index 0), direction -1; lane1
// even => side "-" (index 1), direction +1. Riders closer than one loaded member radius to the line are flexible.
// Lanes come in pairs (even count 2..16); each lane keeps the concentric radius/chord-capacity recursion, so adjacent lanes
// (opposite sides) stay separated by the full tangent + escape corridor and a member diameter. Per-unit, keyed by entry index.
constexpr U kMaxLanes = 16;
struct OrbitBand {
    U laneCount;                          // even once built; never shrinks within one order
    bool axisOk;                          // charge line frozen
    float ox, oz;                         // frozen origin
    double dx, dz, dLen;                  // frozen direction and its length
    U needSide[2], needTotal;             // census demand: fixed riders per side (incl. sticky assigned), all riders
    U reserve[2];                         // UNASSIGNED fixed-side riders per side: slots flexible riders may not take
    U epoch;                              // identity of this order's frozen classification (0 = none); stale slots never match
    U keyNeed[3]; float tRKey, mRKey;     // inputs of the last successful build (cache key)
    float radius[kMaxLanes];
    U capacity[kMaxLanes];
    U fill[kMaxLanes];                    // sticky occupants per lane
};
OrbitBand unitBands[kMaxUnitEntries];
inline void ClearBand(const UnitEntry* e) { memset(&unitBands[e - entries], 0, sizeof(OrbitBand)); }
// Frozen per-member classification: the side (or flexible) of a member as first counted for THIS order's band (key = mount,
// ei = unit entry index, epoch = band.epoch). Later movement around the target never reclassifies it, so the reserve
// accounting (census count vs assignment decrement) always names the same riders. Slots of cleared / superseded bands
// (epoch != unitBands[ei].epoch) are reusable. Static, bounded probe; creation failure declines the whole order.
struct ClassSlot { U key, ei, epoch; signed char cls; B assigned; };  // cls: -2 unclassified, -1 flexible, 0 "+", 1 "-"
ClassSlot classSlots[kClassSlots];
U classEpoch;
ClassSlot* ClassSlotFor(U ei, U epoch, U mount, bool create) {
    if (!epoch || ei >= kMaxUnitEntries) return nullptr;
    ClassSlot* stale = nullptr;
    const U i = ((mount >> 4) * 2654435761u) >> 16;
    for (U p = 0; p < kClassProbe; ++p) {
        ClassSlot& s = classSlots[(i + p) & (kClassSlots - 1)];
        if (!s.key) { if (!create) return nullptr; ClassSlot& t = stale ? *stale : s; t.key = mount; t.ei = ei; t.epoch = epoch; t.cls = -2; t.assigned = 0; return &t; }
        if (s.key == mount && s.ei == ei && s.epoch == epoch) return &s;
        if (!stale && s.epoch != epoch && (s.ei >= kMaxUnitEntries || unitBands[s.ei].epoch != s.epoch)) stale = &s;  // never the requested (possibly uncommitted trial) epoch
    }
    if (create && stale) { stale->key = mount; stale->ei = ei; stale->epoch = epoch; stale->cls = -2; stale->assigned = 0; return stale; }
    return nullptr;
}

// Freezes the charge line. Degenerate / nonfinite axes decline the whole order.
bool FreezeAxis(OrbitBand& b, float ox, float oz, float tx, float tz) {
    if (!Good(ox) || !Good(oz) || !Good(tx) || !Good(tz)) return false;
    const double dx = double(tx) - double(ox), dz = double(tz) - double(oz);
    const double len = sqrt(dx * dx + dz * dz);
    if (!(len > 1.0e-3) || !(len < 1.0e7)) return false;
    b.ox = ox; b.oz = oz; b.dx = dx; b.dz = dz; b.dLen = len; b.axisOk = true;
    if (!++classEpoch) ++classEpoch;
    b.epoch = classEpoch;
    return true;
}
// 0 = "+" side (odd lane1), 1 = "-" side (even lane1), -1 = flexible (inside one member radius of the line, or unreadable).
int RiderSide(const OrbitBand& b, float mx, float mz, float memberRadius) {
    if (!b.axisOk || !Good(mx) || !Good(mz)) return -1;
    const double cross = b.dx * (double(mz) - double(b.oz)) - b.dz * (double(mx) - double(b.ox));
    if (!(cross == cross) || fabs(cross) < double(memberRadius) * b.dLen) return -1;
    return cross > 0.0 ? 0 : 1;
}

// Called under FpGuard. Builds lanes in pairs (lane i serves side i&1) until every side's capacity covers its fixed
// demand and the total covers all riders (at least band.laneCount lanes, at least 2, never shrinking; sticky fills kept).
// Radii are recomputed from the live target. Fails (band untouched) on invalid input or > 16 lanes.
bool BuildOrbitBand(float targetRadius, float memberRadius, const Settings& st, OrbitBand& band) {
    if (!band.axisOk || !band.needTotal || !Good(memberRadius) || memberRadius <= 0) return false;
    if (band.laneCount && band.keyNeed[0] == band.needSide[0] && band.keyNeed[1] == band.needSide[1] &&
        band.keyNeed[2] == band.needTotal && band.tRKey == targetRadius && band.mRKey == memberRadius) return true;
    float r0;
    if (!ClearanceRadius(targetRadius, memberRadius, st, r0)) return false;
    const double esc = double(st.escape_margin);
    if (!(esc >= 0.0) || !(esc < 1.0e6)) return false;
    const double m = double(memberRadius);
    const double step = fmax(0.05, fmin(0.6, double(st.orbit_step_radians)));
    const double cosine = cos(step);
    OrbitBand nb = band;
    memset(nb.radius, 0, sizeof(nb.radius)); memset(nb.capacity, 0, sizeof(nb.capacity)); memset(nb.fill, 0, sizeof(nb.fill));
    U lanes = 0, capSide[2] = {0, 0};
    float rLane = r0;
    for (;;) {
        if (lanes >= kMaxLanes || !Good(rLane)) return false;
        nb.radius[lanes] = rLane;
        const double s = m / double(rLane);   // asin((2m) / (2R)): chord of one member diameter on the lane
        U cap = 1;
        if (s < 1.0) {
            const double c = floor(3.14159265358979323846 / asin(s));
            cap = c < 1.0 ? 1u : (c > 65535.0 ? 65535u : static_cast<U>(c));
        }
        nb.capacity[lanes] = cap;
        capSide[lanes & 1] += cap; ++lanes;
        if (lanes >= 2 && !(lanes & 1) && lanes >= band.laneCount && capSide[0] >= band.needSide[0] &&
            capSide[1] >= band.needSide[1] && capSide[0] + capSide[1] >= band.needTotal) break;
        const double rr = double(rLane);
        const double guard = 0.001 + 4.0 * FLT_EPSILON * fmax(1.0, rr);
        const double next = fmax(rr / cosine, rr + esc) + 2.0 * m + guard;
        float f = static_cast<float>(next);
        if (double(f) < next) f = nextafterf(f, 3.0e38f);
        rLane = f;
    }
    nb.laneCount = lanes;
    for (U i = 0; i < lanes && i < band.laneCount; ++i) nb.fill[i] = band.fill[i];
    nb.keyNeed[0] = band.needSide[0]; nb.keyNeed[1] = band.needSide[1]; nb.keyNeed[2] = band.needTotal;
    nb.tRKey = targetRadius; nb.mRKey = memberRadius;
    band = nb;
    return true;
}
// Sticky side assignment: fixed riders take the lowest fill/capacity lane of THEIR side only (never the opposite side);
// flexible riders take the side with the most spare capacity beyond the slots reserved for unassigned fixed riders.
// Over-full lanes keep their riders but never receive new ones. When nothing is free the band grows (same order, pairs,
// <= 16 lanes, outermost lane must fit OrbitFits incl. the 100 cap). Touches only this record and the band; no record scan.
// Called under FpGuard. False => the caller must hand the WHOLE order back.
bool AssignLane(UnitEntry& e, float memberRadius, Record& rec, float mx, float mz) {
    if (rec.lane1) return true;
    OrbitBand& b = unitBands[&e - entries];
    if (!b.axisOk || !b.laneCount) return false;
    ClassSlot* cs = ClassSlotFor(static_cast<U>(&e - entries), b.epoch, rec.mount, false);
    const int side = cs && cs->cls != -2 ? cs->cls : RiderSide(b, mx, mz, memberRadius);  // frozen when counted
    for (int pass = 0; pass < 2; ++pass) {
        U freeSide[2] = {0, 0}, capSide[2] = {0, 0}, capTotal = 0;
        for (U i = 0; i < b.laneCount; ++i) {
            capSide[i & 1] += b.capacity[i]; capTotal += b.capacity[i];
            if (b.fill[i] < b.capacity[i]) freeSide[i & 1] += b.capacity[i] - b.fill[i];
        }
        int use = -1;
        if (side >= 0) {
            // a counted rider consumes its own reservation; a rider the census never saw (no frozen slot) may only take spare
            // beyond the slots reserved for counted fixed riders, else the band grows - it never steals or decrements theirs
            if (freeSide[side] > (cs ? 0u : b.reserve[side])) use = side;
        } else {
            const long sp0 = long(freeSide[0]) - long(b.reserve[0]), sp1 = long(freeSide[1]) - long(b.reserve[1]);
            if (sp0 > 0 || sp1 > 0) use = sp0 >= sp1 ? 0 : 1;
        }
        if (use >= 0) {
            U best = kMaxLanes;
            for (U i = static_cast<U>(use); i < b.laneCount; i += 2) {
                if (b.fill[i] >= b.capacity[i]) continue;
                if (best == kMaxLanes ||
                    static_cast<unsigned long long>(b.fill[i]) * b.capacity[best] <
                    static_cast<unsigned long long>(b.fill[best]) * b.capacity[i]) best = i;
            }
            if (best == kMaxLanes) return false;
            ++b.fill[best]; rec.lane1 = static_cast<B>(best + 1);
            if (cs && side >= 0 && !cs->assigned) { cs->assigned = 1; if (b.reserve[side]) --b.reserve[side]; }
            return true;
        }
        if (pass) break;
        OrbitBand expanded = b;
        if (side >= 0) expanded.needSide[side] = capSide[side] + 1 > expanded.needSide[side] ? capSide[side] + 1 : expanded.needSide[side];
        expanded.needTotal = capTotal + 1 > expanded.needTotal ? capTotal + 1 : expanded.needTotal;
        float inner = 0;
        if (!ClearanceRadius(e.tR, memberRadius, settings, inner) ||
            !BuildOrbitBand(e.tR, memberRadius, settings, expanded) ||
            !OrbitFits(e.tx, e.tz, e.tR, memberRadius, expanded.radius[expanded.laneCount - 1] - inner))
            return false;
        b = expanded;
    }
    return false;
}
// the radius of the lane this record is assigned to (0 when unassigned): recorded at every install
float LaneRadius(const UnitEntry& e, const Record& rec) {
    const OrbitBand& b = unitBands[&e - entries];
    return rec.lane1 && rec.lane1 <= b.laneCount ? b.radius[rec.lane1 - 1] : 0.0f;
}

inline U V(U va) { return va + delta; }
inline bool InImage(U p) { return p - imageLo < imageSize; }
inline bool InScope() {
    return bound && !disabled && epoch && ownerTid == __readfsdword(0x24);
}
inline U Hash(U key, U mask) { return (key >> 4) * 2654435761u & (mask - 1); }

// -------------------------------------------------------------------------------------------- tables
U RecordFind(U mount) {
    if (!Sane(mount)) return kStampEmpty;
    for (U p = 0, i = Hash(mount, kMountHash); p < kMountHash; ++p, i = (i + 1) & (kMountHash - 1)) {
        const U e = mountHash[i];
        if (!e) return kStampEmpty;
        const U r = e - 1;
        if (records[r].mount == mount && records[r].unit) return r;
    }
    return kStampEmpty;
}
void RecordInsert(U mount, U r) {
    for (U p = 0, i = Hash(mount, kMountHash); p < kMountHash; ++p, i = (i + 1) & (kMountHash - 1)) {
        if (!mountHash[i]) { mountHash[i] = r + 1; return; }
        if (mountHash[i] == r + 1) return;
    }
}
void RebuildMountHash() {
    memset(mountHash, 0, sizeof(mountHash));
    for (U r = 0; r < recordLimit; ++r)
        if (records[r].unit && records[r].mount) RecordInsert(records[r].mount, r);
}
// probe table: keyed by AGENT (the prober mount and each of its riders); the key is stored beside the
// record index so rider lookups match (a record index alone cannot identify the agent)
void ProbeAdd(U agent, U r) {
    if (!Sane(agent)) return;
    for (U p = 0, i = Hash(agent, kProbeHash); p < kProbeHash; ++p, i = (i + 1) & (kProbeHash - 1)) {
        if (!probeHash[i].idx1 || probeHash[i].idx1 == kStampEmpty) { probeHash[i].key = agent; probeHash[i].idx1 = r + 1; ++probeCount; return; }
        if (probeHash[i].key == agent && probeHash[i].idx1 == r + 1) return;
    }
}
void RebuildProbeHash() {
    memset(probeHash, 0, sizeof(probeHash));
    probeCount = 0;
    for (U r = 0; r < recordLimit; ++r)
        if (records[r].unit && (records[r].flags & rProbe) && Sane(records[r].mount)) {
            ProbeAdd(records[r].mount, r);
            const U n = Rd(records[r].mount + kARiders), arr = Rd(records[r].mount + kARiderArr);
            if (Sane(arr)) for (U i = 0; i < n && i < kRiderCap; ++i) { const U a = Rd(arr + 4 * i); if (Sane(a)) ProbeAdd(a, r); }
        }
}
U ProbeFind(U agent) {
    if (!Sane(agent)) return kStampEmpty;
    for (U p = 0, i = Hash(agent, kProbeHash); p < kProbeHash && probeHash[i].idx1; ++p, i = (i + 1) & (kProbeHash - 1)) {
        if (probeHash[i].idx1 != kStampEmpty && probeHash[i].key == agent) {
            const U r = probeHash[i].idx1 - 1;
            if ((records[r].flags & rProbe) && records[r].unit) return r;
        }
    }
    return kStampEmpty;
}

// per-tick known-set of every live unit pointer (stamp == seq); stale slots are reusable, never matching
void KnownAdd(U unit) {
    for (U p = 0, i = Hash(unit, kKnownSlots); p < kKnownSlots; ++p, i = (i + 1) & (kKnownSlots - 1)) {
        if (known[i].stamp == seq && known[i].unit == unit) return;
        if (known[i].unit == 0 || known[i].stamp != seq) { known[i].unit = unit; known[i].stamp = seq; return; }
    }
}
bool KnownHas(U unit) {
    for (U p = 0, i = Hash(unit, kKnownSlots); p < kKnownSlots; ++p, i = (i + 1) & (kKnownSlots - 1)) {
        if (known[i].stamp == seq && known[i].unit == unit) return true;  // collision: keep probing
        if (known[i].stamp != seq) return false;
    }
    return false;
}

// exactly one entry per tracked unit; liveness for this tick is the stamp
UnitEntry* EntryByUnit(U unit) {
    for (U i = 0; i < kMaxUnitEntries; ++i) if (entries[i].unit == unit) return &entries[i];
    return nullptr;
}
UnitEntry* EntryLive(U unit) {  // hook/EndTick view: confirmed by this tick's evaluation
    UnitEntry* e = EntryByUnit(unit);
    return e && e->stamp == seq ? e : nullptr;
}
// Retained-identity publication helpers.  The key is unpublished before any entry reclaim (EntryAlloc,
// ClearAll, expiry) so an in-flight flush scan can never match a freed slot; cancel is cleared BEFORE each
// key store, so a stale cancel from an earlier publication can only veto spuriously (never revive).
void UnpublishKey(U i) { _InterlockedExchange(&flushKey[i], 0); }
void Unretain(UnitEntry& e) {
    e.retained = false;
    UnpublishKey(static_cast<U>(&e - entries));
}
// The retained identity is live exactly while: still published and unflushed, the owner epoch is open,
// unit and target are known and alive, the FSM is not routed-out, and the queue still sits untouched at
// the recorded empty position (count 0, head == tail == headAfter).  The dead row is never read.  Any
// failure clears the latch (a fresh row recaptures through the normal path).  The caller's __try bracket
// covers these native reads, exactly like RowLive's.
bool RetainedLive(UnitEntry& e) {
    if (!e.retained || !e.unit || !e.target) return false;
    if (flushCancel[&e - entries]) { Unretain(e); return false; }
    const bool ok = InScope() && KnownHas(e.unit) && KnownHas(e.target) &&
                    Rd(e.unit + kURowCnt) == 0 &&
                    Rd(e.unit + kURowIdx) == e.headAfter && Rd(e.unit + kURowTail) == e.headAfter &&
                    Rd(e.unit + kUFsm) != V(kFsmRout) &&
                    Rd(e.target + kUState) != 0 && Rd(e.target + kUState) != 2 && Rd(e.target + kUMenCount);
    if (!ok) Unretain(e);
    return ok;
}
UnitEntry* EntryAlloc(U unit) {
    UnitEntry* free = nullptr;
    for (U i = 0; i < kMaxUnitEntries; ++i) {
        if (entries[i].unit == unit) return &entries[i];
        if (!free && !entries[i].unit) free = &entries[i];
    }
    if (!free) return nullptr;
    UnpublishKey(static_cast<U>(free - entries));  // the slot may still carry a stale published key
    memset(free, 0, sizeof(UnitEntry));
    memset(&unitBands[free - entries], 0, sizeof(OrbitBand));
    free->unit = unit;
    return free;
}

// -------------------------------------------------------------------------------------------- native pre-validation
// 0x55ABF0 (thiscall ECX = unit) returns AL = mounted.  Category 3 (dragoons) makes the callee probe the
// U+0xDAC ability vector (count +0xC, data +0x10, 0x2C-byte records), so that vector is pre-validated.
bool MountedSafe(U unit) {
    const U cls = Rd(unit + kUClass);
    if (!Sane(cls)) return false;
    const U cat = Rd(cls + 0x1C);
    if (cat != 0 && cat != 3 && cat != 5) return false;
    if (cat == 3) {
        const U count = Rd(unit + 0xDAC + 0xC), data = Rd(unit + 0xDAC + 0x10);
        if (count && (count > 4096 || !Sane(data) || !Sane(data + count * 0x2C - 1))) return false;
    }
    return reinterpret_cast<ThisBool>(static_cast<uintptr_t>(mountedCall))(unit, 0) != 0;
}
// "is target a formed square": 0x557360 (thiscall ECX = &unitSlot) dispatches through the formation slot
// array (idx [unit+0xAE8], object [unit+0xADC+4*idx], method vt+0xD8); every hop is validated first.
bool SquareSafe(U unit, bool& out) {
    out = false;
    const U idx = Rd(unit + kSlotIdx);
    if (!idx) return true;
    if (idx > 8) return false;
    const U o = Rd(unit + kSlotArr + 4 * idx);
    if (!o) return true;
    if (!Sane(o)) return false;
    const U vt = Rd(o);
    if (!InImage(vt)) return false;
    const U fn = Rd(vt + 0xD8);
    if (!InImage(fn)) return false;
    out = reinterpret_cast<ThisBool>(static_cast<uintptr_t>(fn))(o, 0) != 0;
    return true;
}
// Mount is still a live member (index cache first, bounded rescan otherwise).
bool MemberOf(U unit, U mount, U& idx) {
    const U n = Rd(unit + kUMenCount), arr = Rd(unit + kUMenArr);
    if (!arr || !n || n > kMemberScanCap) return false;
    if (idx < n && Rd(arr + 4 * idx) == mount) return true;
    for (U i = 0; i < n; ++i)
        if (Rd(arr + 4 * i) == mount) { idx = i; return true; }
    return false;
}
// The agent-level routing exit of the repo's own convention (native_unit_brain.cpp: order/activity are
// dword agent fields 0x1D8/0x1B8, there marked [INFERENCE]); checked per mount before any interposition.
bool RoutingAgent(U agent) {
    const U o = Rd(agent + kAOrder);
    if (o == 0x3C || o == 0x3D) return true;
    return Rd(agent + kAActivity) == 0x4B;
}
bool YieldToNative(U agent) {
    // Worklist activation and temporary controller ownership (+0x628) are not interchangeable with
    // target suitability. Phase 0x14 is temporary horse refusal, not death; leave its native recovery untouched.
    return RdB(agent + 0x30) != 1 || Rd(agent + 0x628) != 0 ||
           Rd(agent + 0x224) == 0x14 || RoutingAgent(agent);
}
// The unit's live row is still the captured attack row against the captured target.
bool RowLive(U unit, U serial, U target) {
    const U cnt = Rd(unit + kURowCnt), idx = Rd(unit + kURowIdx);
    if (!cnt || idx >= 10) return false;
    const U row = unit + kURowBase + kURowStride * idx;
    return Rd(row) == V(kAttackRowVt) && Rd(row + kRowSerial) == serial && Rd(row + kRowTarget) == target;
}
// The accepted attack order is live through its native row OR the retained identity: a normally consumed
// order keeps the unit eligible (orbit, probes, tracker restriction, handbacks) without reading the dead
// row, until a flush, a new order, rout-out, death or graph exit clears the latch.
bool OrderLive(U unit, U serial, U target) {
    if (RowLive(unit, serial, target)) return true;
    UnitEntry* e = EntryByUnit(unit);
    return e && e->serial == serial && e->target == target && RetainedLive(*e);
}
// E steering state: native E steps own movement this tick.  New installs are DEFERRED, never cancelled -
// records, lanes and probes are kept; the deferral lasts exactly as long as the state does.
bool SteeringHold(U unit) { return Rd(unit + kUFsm) == V(kFsmSteer); }
// Native terrain height at an exact (x, z): 0x57E870 (thiscall ECX = model; out XYZ*, in XZ*, plane;
// ret 0xC, EAX = out).  [model+0x9C] is the heightfield; 0x66BB40 returns the bilinear sample.
bool TerrainY(float x, float z, float& y) {
    if (!terrainQuery || !Sane(curModel)) return false;
    const float in[2] = { x, z };
    float out[3] = { 0, 0, 0 };
    const U r = reinterpret_cast<TerrainFn>(static_cast<uintptr_t>(terrainQuery))(curModel, 0, out, in, 0);
    if (!r || r != static_cast<U>(reinterpret_cast<uintptr_t>(out))) return false;
    y = out[1];
    return Good(y);
}

// Orbit-only descriptor normalization (never applied to rec.desc or handbacks).  Everything is validated before
// the read-only native order query, and the descriptor is written only after every step succeeded.
// Layout: order dword +0x18, mode dword +0x1C, slot-adjust flag byte +0x29,
// speed float +0x20, time float +0x24.
bool NormalizeOrbit(U mount, B* desc, float wx, float wz) {
    if (!Sane(mount)) return false;
    U speedBits;
    memcpy(&speedBits, desc + 0x20, 4);
    if ((speedBits & 0x80000000u) || !(speedBits & 0x7fffffffu) ||
        (speedBits & 0x7f800000u) == 0x7f800000u) return false;
    float v;
    memcpy(&v, &speedBits, 4);
    const float mx = RdF(mount + kAX), mz = RdF(mount + kAZ);
    if (!Good(mx) || !Good(mz) || !Good(wx) || !Good(wz)) return false;
    const float dx = FSub(wx, mx), dz = FSub(wz, mz);
    const float t = FDiv(FSqrt(FAdd(FMul(dx, dx), FMul(dz, dz))), v);
    if (!(t == t) || !FLt(t, FLT_MAX)) return false;
    U order = 0, mode = 0;
    memcpy(&mode, desc + 0x1C, 4);
    // Native approach can switch to charge/melee stance while its movement descriptor is still
    // being captured. Orbit-only copies must keep moving, not re-arm melee posture/refusal.
    // Use native running stance 1 only for stance 2; preserve all other stances and the capture.
    if (mode == 2) mode = 1;
    const bool adjust = desc[0x29] != 0;
    if (adjust) {
        if (!orderAdjust) return false;
        memcpy(&order, desc + 0x18, 4);
        order = reinterpret_cast<OrderAdjustFn>(static_cast<uintptr_t>(orderAdjust))(mount, 0, order, mode);
    }
    if (adjust) { memcpy(desc + 0x18, &order, 4); desc[0x29] = 0; }
    memcpy(desc + 0x1C, &mode, 4);
    // Native 0x7FC430 -> 0x7EADF0 encodes a world point as XYZ,0,0. An old +0x10
    // frame would transform our world waypoint a second time in 0x80E9D0.
    const U world = 0;
    memcpy(desc + 0x0C, &world, 4);
    memcpy(desc + 0x10, &world, 4);
    memcpy(desc + 0x24, &t, 4);
    return true;
}

// Loaded per-member clearance, not the radius of the cavalry formation.
bool MemberRadius(U unit, float& radius) {
    float spacing = RdF(unit + 0x2F8);
    if (!Good(spacing) || spacing <= 0) spacing = RdF(unit + 0x2FC);
    if (!Good(spacing) || spacing <= 0) return false;
    radius = FMul(0.5f, spacing); // loaded base is twice the maximum member radius
    return true;
}
// Centre from member bounds; radius from actual extremes about that centre. A second cached pass
// avoids inflating a rotated square to its axis-aligned box's diagonal.
bool Footprint(U unit, float& cx, float& cz, float& r) {
    const U n = Rd(unit + kUMenCount), arr = Rd(unit + kUMenArr);
    if (!arr || !n || n > kMemberScanCap) return false;
    const U count = n;
    float mnX = 1e30f, mxX = -1e30f, mnZ = 1e30f, mxZ = -1e30f;
    U kept = 0;
    for (U i = 0; i < count; ++i) {
        const U m = Rd(arr + 4 * i);
        if (!Sane(m)) continue;
        const float x = RdF(m + kAX), z = RdF(m + kAZ);
        if (!Good(x) || !Good(z)) continue;
        ++kept;
        mnX = FMin(mnX, x); mxX = FMax(mxX, x); mnZ = FMin(mnZ, z); mxZ = FMax(mxZ, z);
    }
    if (!kept) return false;
    cx = FMul(0.5f, FAdd(mnX, mxX));
    cz = FMul(0.5f, FAdd(mnZ, mxZ));
    float memberRadius;
    if (!MemberRadius(unit, memberRadius)) return false;
    float furthestSquared = 0;
    for (U i = 0; i < count; ++i) {
        const U m = Rd(arr + 4 * i);
        if (!Sane(m)) continue;
        const float x = RdF(m + kAX), z = RdF(m + kAZ);
        if (!Good(x) || !Good(z)) continue;
        const float dx = FSub(x, cx), dz = FSub(z, cz);
        furthestSquared = FMax(furthestSquared, FAdd(FMul(dx, dx), FMul(dz, dz)));
    }
    r = FAdd(FSqrt(furthestSquared), memberRadius);
    return r > 0;
}
// Deduplicated per-target footprint: several cavalry units share one square; compute once per cadence.
bool TargetFootAt(U target, float& cx, float& cz, float& r) {
    for (U i = 0; i < kTargetCache; ++i)
        if (targetCache[i].target == target && targetCache[i].tick && curTick - targetCache[i].tick < kFootCadence) {
            cx = targetCache[i].cx; cz = targetCache[i].cz; r = targetCache[i].r;
            return true;
        }
    if (!Footprint(target, cx, cz, r)) return false;
    targetCache[targetCursor].target = target;
    targetCache[targetCursor].tick = curTick;
    targetCache[targetCursor].cx = cx; targetCache[targetCursor].cz = cz; targetCache[targetCursor].r = r;
    targetCursor = (targetCursor + 1) & (kTargetCache - 1);
    return true;
}

// -------------------------------------------------------------------------------------------- record lifecycle
void DropRecord(U r) {
    Record& rec = records[r];
    if (rec.unit && ((rec.flags & rProbe) || rec.lane1)) {
        UnitEntry* e = EntryByUnit(rec.unit);
        if (e) {
            if ((rec.flags & rProbe) && e->probes) --e->probes;
            if (rec.lane1) {
                OrbitBand& b = unitBands[e - entries];
                if (rec.lane1 <= b.laneCount && b.fill[rec.lane1 - 1]) --b.fill[rec.lane1 - 1];
            }
        }
    }
    rec.mount = rec.unit = rec.flags = rec.probeUntil = 0;
    rec.lane1 = 0;
}
void StageIdentity(Stage& s, const Record& rec, const UnitEntry& e) {
    s.unit = rec.unit; s.serial = e.serial; s.target = e.target; s.memberIdx = rec.memberIdx;
}
bool StageValid(Stage& s) {
    bool valid = false;
    ++kntwr::probeDepth;
    __try {
        valid = KnownHas(s.unit) && Rd(s.unit + kUState) != 0 && Rd(s.unit + kUState) != 2 &&
                OrderLive(s.unit, s.serial, s.target) && !SteeringHold(s.unit) &&
                MemberOf(s.unit, s.mount, s.memberIdx) && Rd(s.mount + kAUnit) == s.unit &&
                !YieldToNative(s.mount);
    } __except (EXCEPTION_EXECUTE_HANDLER) { valid = false; }
    --kntwr::probeDepth;
    return valid;
}
// Release every record of a unit.  `handback` re-installs the last captured native movement descriptor
// first - UNBUDGETED (a cancellation must not wait behind a budget); the stage covers a whole unit.  Every
// other exit trusts the engine to issue its own next command (a changed order installs its own nodes, so a
// stale descriptor must not be fought back in).
void DropUnitRecords(U unit, bool handback) {
    UnitEntry* e = EntryByUnit(unit);
    for (U r = 0; r < recordLimit; ++r)
        if (records[r].unit == unit) {
            if (handback && e && KnownHas(unit) && OrderLive(unit, e->serial, e->target) &&
                (records[r].flags & rDesc) && staged < kStageMax &&
                MemberOf(unit, records[r].mount, records[r].memberIdx) && !YieldToNative(records[r].mount)) {
                Stage& s = stage[staged++];
                s.mount = records[r].mount; s.combat = 0; s.orbit = 0;
                StageIdentity(s, records[r], *e);
                memcpy(s.desc, records[r].desc, kDescBytes);
            }
            DropRecord(r);
        }
}

// Whole-order native handback + block: used whenever the two-stream geometry cannot be honoured (pair fit, capacity, 100 cap,
// degenerate axis). Never leaves part of a unit orbiting while the rest charges; the same blocked order stays native.
void HandBackOrder(UnitEntry& e) {
    DropUnitRecords(e.unit, e.orbit);
    ClearBand(&e);
    e.blockedSerial = e.serial; e.blockedTarget = e.target;
    e.orbit = false; e.latched = false; e.policy = State(); e.probes = 0;
}
// One bounded scan of the unit's live members (callers: per footprint refresh, or first layout). Sticky riders (a record with a
// lane) count as fixed on their lane side; the rest are classified against the frozen line. Uncaptured members are included.
// Called under FpGuard; reads native memory inside the caller's __try.
bool TakeCensus(U unit, U ei, float memberRadius, OrbitBand& b) {
    const U n = Rd(unit + kUMenCount), arr = Rd(unit + kUMenArr);
    if (!b.axisOk || !arr || !n || n > kMemberScanCap) return false;
    U fixedSide[2] = {0, 0}, reserve[2] = {0, 0}, flex = 0;
    for (U i = 0; i < n; ++i) {
        const U m = Rd(arr + 4 * i);
        if (!Sane(m)) continue;
        const U r = RecordFind(m);
        if (r != kStampEmpty && records[r].unit == unit && records[r].lane1) { ++fixedSide[(records[r].lane1 - 1) & 1]; continue; }
        ClassSlot* cs = ClassSlotFor(ei, b.epoch, m, true);
        if (!cs) return false;  // table full: cannot freeze every classification -> whole order native
        if (cs->cls == -2) cs->cls = static_cast<signed char>(RiderSide(b, RdF(m + kAX), RdF(m + kAZ), memberRadius));
        cs->assigned = 0;
        const int side = cs->cls;
        if (side < 0) ++flex; else { ++fixedSide[side]; ++reserve[side]; }
    }
    const U total = fixedSide[0] + fixedSide[1] + flex;
    if (!total) return false;
    b.needSide[0] = fixedSide[0]; b.needSide[1] = fixedSide[1]; b.needTotal = total;
    b.reserve[0] = reserve[0]; b.reserve[1] = reserve[1];
    return true;
}

// -------------------------------------------------------------------------------------------- per-tick scan
// POD only (the caller's __try covers every native read); no object with a destructor in this function.
struct Cand {
    U unit, serial, target, has;  // has: 0 ineligible, 1 identity ok, 2 facts ok
    U squareOk, square, refreshed;
    float ox, oz, ownR, tx, tz, tR;
};

void Scan(U model) {
    ++seq;
    ReadBoundary(model);
    U nCand = 0;
    Cand cands[kCandidateMax];
    // pass 1: graph walk - fill the known-set for the WHOLE graph and collect cheap candidates (row
    // vtable, class).  No target is consulted yet: an enemy later in the walk must not be rejected.
    const U mgr = Rd(model + 0xB0);
    if (!mgr) return;
    const U sides = Rd(mgr + 0x84), sideArr = Rd(mgr + 0x88);
    if (!sideArr || !sides || sides > kMaxSides) return;
    for (U si = 0; si < sides; ++si) {
        const U side = Rd(sideArr + 4 * si);
        if (!side) continue;
        const U armies = Rd(side + 0x20), armyArr = Rd(side + 0x24);
        if (armies > kMaxArmies || (armies && !armyArr)) continue;
        for (U ai = 0; ai < armies; ++ai) {
            const U army = Rd(armyArr + 4 * ai);
            if (!army) continue;
            const U units = Rd(army + 0xF0), unitArr = Rd(army + 0xF4);
            if (units > kMaxUnitsPerWalk || (units && !unitArr)) continue;
            for (U ui = 0; ui < units; ++ui) {
                const U unit = Rd(unitArr + 4 * ui);
                if (!Sane(unit)) continue;
                KnownAdd(unit);
                const U cnt = Rd(unit + kURowCnt), idx = Rd(unit + kURowIdx);
                if (!cnt || idx >= 10) continue;
                const U row = unit + kURowBase + kURowStride * idx;
                if (Rd(row) != V(kAttackRowVt)) continue;
                const U cls = Rd(unit + kUClass);
                if (!Sane(cls)) continue;
                const U cat = Rd(cls + 0x1C);
                if (cat != 0 && cat != 3 && cat != 5) continue;
                if (nCand >= kCandidateMax) continue;
                Cand& c = cands[nCand++];
                c.unit = unit; c.serial = Rd(row + kRowSerial); c.target = Rd(row + kRowTarget);
                c.has = 0; c.squareOk = 0; c.square = 0; c.refreshed = 0;
            }
        }
    }
    // retained identities: the walk found these units with an empty queue (there is no row to read); the
    // accepted order continues eligibility from the entry alone.  Overflow skips WITHOUT clearing - the
    // unconfirmed loop below clears it this tick, and a fresh row recaptures later (pass-1 semantics).
    for (U i = 0; i < kMaxUnitEntries; ++i) {
        UnitEntry& e = entries[i];
        if (!e.unit || !e.retained) continue;
        if (!RetainedLive(e) || nCand >= kCandidateMax) continue;
        Cand& c = cands[nCand++];
        c.unit = e.unit; c.serial = e.serial; c.target = e.target;
        c.has = 0; c.squareOk = 0; c.square = 0; c.refreshed = 0;
    }
    // pass 2: facts - identity (now that the whole graph is known), footprint caches on a staggered
    // cadence (full member scans, targets deduplicated), then the two pre-validated native predicates
    for (U i = 0; i < nCand; ++i) {
        Cand& c = cands[i];
        const U st = Rd(c.unit + kUState), men = Rd(c.unit + kUMenCount);
        if (st != 0 && st != 2 && men && c.serial && Sane(c.target) && c.target != c.unit && KnownHas(c.target) &&
            Rd(c.target + kUState) != 0 && Rd(c.target + kUState) != 2 && Rd(c.target + kUMenCount))
            c.has = 1;
        if (c.has != 1) continue;
        UnitEntry* e = EntryByUnit(c.unit);
        if (!MountedSafe(c.unit)) { c.has = 0; continue; }
        // A square can appear after the attack begins. Once acquired, retain that same live target
        // until our order/ownership changes; the enemy changing stance must not cancel the orbit.
        if (e && e->latched && e->serial == c.serial && e->target == c.target) c.square = 1;
        else {
            bool sq = false;
            if (!SquareSafe(c.target, sq)) { c.has = 0; continue; }
            c.square = sq ? 1u : 0u;
        }
        c.squareOk = 1;
        if (!c.square) continue; // armed descriptor capture needs no per-member geometry scan
        const bool fresh = e && e->orbit && e->target == c.target && e->footTick && curTick - e->footTick < kFootCadence;
        if (fresh) {  // last evaluation's caches are still current; footTick is NOT touched
            c.ox = e->ox; c.oz = e->oz; c.ownR = e->ownR; c.tx = e->tx; c.tz = e->tz; c.tR = e->tR; c.has = 2;
        } else {
            float cx = 0, cz = 0, r = 0, tcx = 0, tcz = 0, tr = 0;
            if (Footprint(c.unit, cx, cz, r) && TargetFootAt(c.target, tcx, tcz, tr)) {
                c.ox = cx; c.oz = cz; c.ownR = r; c.tx = tcx; c.tz = tcz; c.tR = tr; c.has = 2;
                c.refreshed = 1;
            }
        }
    }
    // pass 3: policy evaluation and state updates (double-precision policy under an FpGuard)
    U admissions = 0;
    {
        FpGuard fp;
        for (U i = 0; i < nCand; ++i) {
            Cand& c = cands[i];
            UnitEntry* e = EntryByUnit(c.unit);
            if (e && (e->serial != c.serial || e->target != c.target)) {
                DropUnitRecords(c.unit, false); // a new order must never inherit the old descriptor
                e->orbit = false; e->policy = State(); e->probes = 0;
                e->latched = false;
                ClearBand(e);
            }
            if (!c.has || (c.square && c.has != 2)) {
                const bool handback = e && e->orbit;
                if (e) {
                    DropUnitRecords(c.unit, handback);
                    e->orbit = false; e->policy = State(); e->probes = 0;
                    if (!c.has) { e->latched = false; Unretain(*e); }
                    e->serial = c.serial; e->target = c.target; e->stamp = seq;
                }
                continue;
            }
            if (!e) {
                e = EntryAlloc(c.unit);
                if (!e) continue;  // entry capacity: the unit stays native this tick
            }
            e->serial = c.serial; e->target = c.target; e->stamp = seq;
            if (!c.square) continue; // remember this native attack before its target forms square
            if (e->blockedSerial == c.serial && e->blockedTarget == c.target) { e->stamp = seq; continue; }
            Input in;
            in.now_ms = static_cast<uint64_t>(curTick) * 100ull;
            in.model_token = curModel;
            in.unit_id = c.unit; in.order_serial = c.serial; in.target_id = c.target;
            in.own_x = c.ox; in.own_z = c.oz; in.target_x = c.tx; in.target_z = c.tz;
            in.target_radius = c.tR;
            if (!MemberRadius(c.unit, in.own_radius)) {
                DropUnitRecords(c.unit, e->orbit);
                e->orbit = false; e->policy = State(); e->probes = 0;
                continue;
            }
            {
                const U bi = static_cast<U>(e - entries);
                OrbitBand trial = unitBands[bi];
                float r0 = 0;
                bool fits = ClearanceRadius(c.tR, in.own_radius, settings, r0);
                if (fits && !trial.axisOk) fits = FreezeAxis(trial, c.ox, c.oz, c.tx, c.tz);  // first square acquisition of this order
                if (fits && (c.refreshed || !trial.laneCount)) fits = TakeCensus(c.unit, bi, in.own_radius, trial);
                fits = fits && BuildOrbitBand(c.tR, in.own_radius, settings, trial) &&
                    OrbitFits(c.tx, c.tz, c.tR, in.own_radius, trial.radius[trial.laneCount - 1] - r0);
                if (!fits) {  // pair fit, 100 cap, playable rectangle (outermost lane) or degenerate axis: whole order native
                    e->serial = c.serial; e->target = c.target; e->stamp = seq;
                    HandBackOrder(*e);
                    continue;
                }
                unitBands[bi] = trial;
            }
            in.mounted = true; in.alive = true; in.routing = false; in.target_is_square = true;
            Decision d = Evaluate(e->policy, in, settings);
            e->stamp = seq;

            if (d.mode == Mode::Native) {
                // Retain the old identity while deciding whether native movement can be restored.
                // A new row must never receive a descriptor captured for the previous command.
                DropUnitRecords(c.unit, true);
                e->serial = c.serial; e->target = c.target;
                e->orbit = false; e->policy = State(); e->probes = 0;
                continue;
            }
            e->serial = c.serial; e->target = c.target;
            const bool activating = !e->orbit;
            e->orbit = true; e->latched = true;
            e->wx = d.waypoint_x; e->wz = d.waypoint_z;
            e->ox = c.ox; e->oz = c.oz; e->ownR = c.ownR; e->tx = c.tx; e->tz = c.tz; e->tR = c.tR;
            if (activating) {  // armed records get lanes only at activation (later captures are assigned on first waypoint)
                bool assigned = true;
                for (U r = 0; assigned && r < recordLimit; ++r)
                    if (records[r].unit == c.unit && (records[r].flags & rDesc) && !(records[r].flags & rProbe)) {
                        records[r].flags = (records[r].flags | rActivate) & ~rOrbit;
                        float rx = 3.0e38f, rz = 3.0e38f;
                        if (Sane(records[r].mount)) { rx = RdF(records[r].mount + kAX); rz = RdF(records[r].mount + kAZ); }
                        assigned = AssignLane(*e, in.own_radius, records[r], rx, rz);
                    }
                if (!assigned) { HandBackOrder(*e); continue; }
            }
            if (c.refreshed) e->footTick = curTick;
            // probe wave: at most one per unit, small, round-robin over the unit's captured mounts.
            // Reserve the wave before firing its staged native installs on this same owner thread.
            if (d.probe_due && !e->probes && admissions < kAdmitBudget && !SteeringHold(c.unit)) {
                U picked = 0, nextCursor = e->cursor;
                for (U scan = 0; scan < recordLimit && picked < kWaveSize && admissions + picked < kAdmitBudget && staged < kStageMax; ++scan) {
                    const U r = (e->cursor + scan) % recordLimit;
                    Record& rec = records[r];
                    if (rec.unit != c.unit || !(rec.flags & rDesc) || (rec.flags & (rProbe | rActivate)) || !Sane(rec.mount)) continue;
                    if (Rd(rec.mount + kAUnit) != c.unit ||
                        !MemberOf(c.unit, rec.mount, rec.memberIdx) || YieldToNative(rec.mount)) continue;
                    Stage& s = stage[staged++];
                    s.mount = rec.mount; s.combat = 1; s.orbit = 0;
                    StageIdentity(s, rec, *e);
                    memset(s.desc, 0, kDescBytes);
                    const U mode = 1, key = e->target;
                    memcpy(s.desc, &mode, 4); memcpy(s.desc + 4, &key, 4);
                    memcpy(s.desc + 0x14, reinterpret_cast<const void*>(V(0x150FCA8)), 12);
                    memcpy(s.desc + 0x28, reinterpret_cast<const void*>(V(0x14D05B0)), 2);
                    rec.flags = (rec.flags | rProbe) & ~(rActivate | rOrbit); rec.probeUntil = curTick + kProbeWindowTicks;
                    ProbeAdd(rec.mount, r);
                    const U n = Rd(rec.mount + kARiders), arr = Rd(rec.mount + kARiderArr);
                    if (Sane(arr)) for (U ri = 0; ri < n && ri < kRiderCap; ++ri) { const U a = Rd(arr + 4 * ri); if (Sane(a)) ProbeAdd(a, r); }
                    ++picked;
                    nextCursor = (r + 1) % recordLimit;
                }
                e->cursor = nextCursor;
                if (picked) { e->probes = picked; admissions += picked; }
            }
        }
    }
    // entries not confirmed this tick lose their records (death, disband, graph change, candidate overflow)
    for (U i = 0; i < kMaxUnitEntries; ++i)
        if (entries[i].unit && entries[i].stamp != seq) {
            DropUnitRecords(entries[i].unit, entries[i].orbit);
            Unretain(entries[i]);  // unpublished before the entry slot itself is reclaimed
            entries[i].unit = 0;
        }
    RebuildMountHash();
    if (probeCount) RebuildProbeHash();
    else memset(probeHash, 0, sizeof(probeHash));
}

// -------------------------------------------------------------------------------------------- hook planning (POD only)
struct MovePlan { U mode; B desc[kDescBytes]; };  // 0 pass, 1 replace

// Each rider advances around the attacked square itself. Formation spread must neither enlarge the
// circle nor translate another rider's waypoint. The policy preserves segment clearance on approach.
bool MountWaypoint(Record& rec, UnitEntry& e, float& wx, float& wz) {
    if (!Sane(rec.mount)) return false;
    const float mx = RdF(rec.mount + kAX), mz = RdF(rec.mount + kAZ);
    if (!Good(mx) || !Good(mz)) return false;
    float memberRadius;
    if (!MemberRadius(rec.unit, memberRadius)) return false;
    if (!BoundaryPoint(mx, mz, memberRadius)) return false;
    FpGuard fp;
    if (!AssignLane(e, memberRadius, rec, mx, mz)) { HandBackOrder(e); return false; }
    const OrbitBand& band = unitBands[&e - entries];
    if (rec.lane1 > band.laneCount) return false;
    const int direction = (rec.lane1 & 1) ? -1 : 1;  // odd lane = "+" approach side = native direction -1
    return ComputeWaypoint(mx, mz, e.tx, e.tz, band.radius[rec.lane1 - 1], direction,
                           rec.mount, settings, wx, wz) && BoundaryPoint(wx, wz, memberRadius);
}
bool InstallY(U, float wx, float wz, float& y) {
    return TerrainY(wx, wz, y);
}

// orbit authority helpers (pure table access)
void StampOrbit(Record& rec) {
    rec.flags |= rOrbit;
    rec.foreign = static_cast<U>(foreignMark[ForeignIdx(rec.mount)]);
}
void ClearOrbit(U mount) {  // a native descriptor may be about to replace the node
    const U r = RecordFind(mount);
    if (r != kStampEmpty) records[r].flags &= ~rOrbit;
}
// The mount's current movement node is provably our own live orbit node: installed by this adapter, no probe/rejoin/activation pending,
// nothing foreign installed since, still a present (undone) movement node on an enabled holder.  Reads only.
bool KeepOrbit(U mount, const Record& rec) {
    return (rec.flags & rOrbit) && !(rec.flags & (rProbe | rRenew | rActivate)) && rec.mount == mount &&
           rec.foreign == static_cast<U>(foreignMark[ForeignIdx(mount)]) &&
           RdB(mount + kAHolderFlag) == 1 && Rd(mount + kANode) == V(kOrbitNodeVt) && RdB(mount + kANodeDone) == 0;
}

// shared hook prelude: the record of an owned, currently-valid mount, or kStampEmpty (record dropped when
// provably stale; untouched when simply out of scope)
U OwnedMount(U mount) {
    if (!Sane(mount)) return kStampEmpty;
    const U unit = Rd(mount + kAUnit);
    if (!Sane(unit)) return kStampEmpty;
    const U r = RecordFind(mount);
    if (r == kStampEmpty) return kStampEmpty;
    Record& rec = records[r];
    if (rec.unit != unit) { DropRecord(r); return kStampEmpty; }
    UnitEntry* e = EntryLive(unit);
    if (!e) return kStampEmpty;
    if (!KnownHas(unit) || !KnownHas(e->target)) { DropRecord(r); return kStampEmpty; }
    const U ownState = Rd(unit + kUState), targetState = Rd(e->target + kUState);
    if (ownState == 0 || ownState == 2 || targetState == 0 || targetState == 2 ||
        Rd(unit + kUFsm) == V(kFsmRout) ||
        !Rd(unit + kUMenCount) || !Rd(e->target + kUMenCount)) {
        DropRecord(r);
        return kStampEmpty;
    }
    if (!OrderLive(unit, e->serial, e->target)) { DropRecord(r); return kStampEmpty; }
    if (SteeringHold(unit)) return kStampEmpty;  // E owns steering: defer renewals/diverts, keep the record
    if (!MemberOf(unit, mount, rec.memberIdx)) { DropRecord(r); return kStampEmpty; }
    if (YieldToNative(mount)) {
        if (RoutingAgent(mount) || RdB(mount + 0x30) != 1) DropRecord(r);
        return kStampEmpty; // temporary controller ownership/refusal preserves the approach, never forces movement
    }
    if (!e->orbit) return kStampEmpty;
    return r;
}

// Orders can change inside the native tick, after Scan. Capture only the row actually owning this
// descriptor; never attach a new approach to the identity cached before the tick.
UnitEntry* CaptureEntry(U unit) {
    if (!KnownHas(unit) || !MountedSafe(unit) || !Rd(unit + kUMenCount) ||
        Rd(unit + kUState) == 0 || Rd(unit + kUState) == 2) return nullptr;
    const U count = Rd(unit + kURowCnt), index = Rd(unit + kURowIdx);
    if (!count) {
        // Normally-consumed order: the queue is empty and the last row is dead memory (never read). The
        // retained identity continues capture eligibility; RetainedLive self-clears on any violation.
        UnitEntry* e = EntryByUnit(unit);
        if (e && e->retained && RetainedLive(*e)) { e->stamp = seq; return e; }
        return nullptr;  // cancelled, superseded or never retained: native movement, nothing captured
    }
    if (index >= 10) return nullptr;
    const U row = unit + kURowBase + kURowStride * index;
    if (Rd(row) != V(kAttackRowVt)) return nullptr;
    const U serial = Rd(row + kRowSerial), target = Rd(row + kRowTarget);
    if (!serial || target == unit || !KnownHas(target) || !Rd(target + kUMenCount) ||
        Rd(target + kUState) == 0 || Rd(target + kUState) == 2) return nullptr;
    UnitEntry* e = EntryAlloc(unit);
    if (!e) return nullptr;
    if (e->serial != serial || e->target != target) {
        Unretain(*e);  // a different order: the retained latch must not survive the identity change
        DropUnitRecords(unit, false);
        e->orbit = false; e->latched = false; e->policy = State(); e->probes = 0;
        ClearBand(e);
        e->serial = serial; e->target = target;
    }
    e->stamp = seq;
    return e;
}

void PlanMove(U mount, const void* descriptor, MovePlan& p) {
    p.mode = 0;
    if (!Sane(mount)) return;
    const U unit = Rd(mount + kAUnit);
    if (!Sane(unit)) return;
    UnitEntry* e = CaptureEntry(unit);
    if (!e || (e->blockedSerial == e->serial && e->blockedTarget == e->target)) return;
    U r = RecordFind(mount);
    if (r == kStampEmpty) {
        // Capture the native approach while the attack is armed, even before its target forms square.
        if (RoutingAgent(mount) || RdB(mount + 0x30) != 1) return;  // terminal only; temporary controller/refusal still captures
        for (U i = 0; i < kMaxRecords; ++i) {
            const U s = (allocCursor + i) & (kMaxRecords - 1);
            if (!records[s].unit) {
                r = s; allocCursor = (s + 1) & (kMaxRecords - 1);
                if (recordLimit <= s) recordLimit = s + 1;
                memset(&records[r], 0, sizeof(Record));
                records[r].mount = mount; records[r].unit = unit; records[r].memberIdx = kMemberScanCap;
                records[r].ux = e->tx; records[r].uz = e->tz;
                RecordInsert(mount, r);
                break;
            }
        }
        if (r == kStampEmpty) {  // record capacity: hand the whole unit back and stop tracking this order
            if (!e->orbit) return; // no intervention occurred; do not permanently block a future square
            e->blockedSerial = e->serial; e->blockedTarget = e->target; e->orbit = false; e->latched = false;
            DropUnitRecords(unit, true);
            return;
        }
    }
    Record& rec = records[r];
    if (rec.unit != unit) { DropRecord(r); return; }
    if (!MemberOf(unit, mount, rec.memberIdx)) { DropRecord(r); return; }
    // capture the native descriptor verbatim (the caller's buffer is never written); NOT while probing -
    // the phase-2 driver's zero combat descriptor must not clobber the movement descriptor we restore with
    bool fresh = false;
    if (!(rec.flags & rProbe)) {
        fresh = !(rec.flags & rDesc);
        memcpy(rec.desc, descriptor, kDescBytes);
        rec.flags |= rDesc;
    }
    if (!e->orbit || (rec.flags & rProbe)) return;  // probes and non-orbit units keep the native destination
    if (YieldToNative(mount)) {
        if (RoutingAgent(mount) || RdB(mount + 0x30) != 1) { DropRecord(r); return; }
        if (fresh) rec.flags |= rActivate;  // let budgeted Sweep resume once native ownership releases
        return;
    }
    if (SteeringHold(unit)) return;  // E owns steering: keep the captured descriptor, install nothing
    float wx, wz;
    if (!MountWaypoint(rec, *e, wx, wz)) return;
    memcpy(p.desc, rec.desc, kDescBytes);
    float y;
    if (!InstallY(mount, wx, wz, y)) return;
    memcpy(p.desc + 0, &wx, 4); memcpy(p.desc + 4, &y, 4); memcpy(p.desc + 8, &wz, 4);
    if (!NormalizeOrbit(mount, p.desc, wx, wz)) return;
    rec.wx = wx; rec.wz = wz; rec.ux = e->tx; rec.uz = e->tz; rec.rad = LaneRadius(*e, rec); rec.lastTick = curTick;
    rec.flags &= ~rActivate;
    StampOrbit(rec);
    p.mode = 1;
}

struct CombatPlan { U mode; B desc[kDescBytes]; };  // 0 native original, 1 replace with the orbit copy (5DD450), 2 keep the installed orbit node

void PlanCombat(U mount, CombatPlan& p) {
    p.mode = 0;
    const U r = OwnedMount(mount);
    if (r == kStampEmpty) return;
    Record& rec = records[r];
    if (!(rec.flags & rDesc) || (rec.flags & rProbe)) return;  // never captured, or probing: native combat
    UnitEntry* e = EntryLive(rec.unit);
    if (!e) return;
    if (KeepOrbit(mount, rec)) { p.mode = 2; return; }  // established orbit still valid: install nothing, do no policy work
    float wx, wz;
    if (!MountWaypoint(rec, *e, wx, wz)) return;
    memcpy(p.desc, rec.desc, kDescBytes);
    float y;
    if (!InstallY(mount, wx, wz, y)) return;
    memcpy(p.desc + 0, &wx, 4); memcpy(p.desc + 4, &y, 4); memcpy(p.desc + 8, &wz, 4);
    if (!NormalizeOrbit(mount, p.desc, wx, wz)) return;
    rec.wx = wx; rec.wz = wz; rec.ux = e->tx; rec.uz = e->tz; rec.rad = LaneRadius(*e, rec); rec.lastTick = curTick;
    rec.flags &= ~rActivate;
    StampOrbit(rec);
    p.mode = 1;
}

// probe pre-step on the tracker (runs before the original 0x6671A0 mirror).  EVERY recheck must pass
// before the restriction is applied: probe membership (keyed hash), a live entry still orbiting, agent
// membership of that unit, the live attack row (serial + target: a new order is never fought), the agent
// routing exit, and the originally acquired target still being alive and known. Any failure ends the probe for the record
// (rRenew -> EndTick restores the captured movement descriptor in the same tick); nothing is written to
// the tracker in that case.  On success a held target agent belonging to another unit is released through
// the native 0x63CE00 (refcount--), and the unit search key (tracker+0, a plain store exactly like the
// ctor 0x61DB90) is the attacked square.
void PlanTracker(U tracker, U agent) {
    if (!Sane(tracker) || !Sane(agent)) return;
    const U r = ProbeFind(agent);
    if (r == kStampEmpty) return;
    Record& rec = records[r];
    UnitEntry* e = EntryLive(rec.unit);
    bool ok = e && e->orbit && e->latched && e->target && Rd(agent + kAUnit) == rec.unit;
    if (ok && (!MemberOf(rec.unit, rec.mount, rec.memberIdx) || Rd(rec.mount + kAUnit) != rec.unit)) ok = false;
    if (ok && agent != rec.mount) {
        bool attached = false;
        const U n = Rd(rec.mount + kARiders), arr = Rd(rec.mount + kARiderArr);
        if (Sane(arr)) for (U i = 0; i < n && i < kRiderCap; ++i) attached |= Rd(arr + i * 4) == agent;
        ok = attached;
    }
    if (ok && !OrderLive(rec.unit, e->serial, e->target)) ok = false;
    if (ok && (YieldToNative(agent) || YieldToNative(rec.mount))) ok = false;
    if (ok && (!KnownHas(e->target) || !Rd(e->target + kUMenCount) ||
               Rd(e->target + kUState) == 0 || Rd(e->target + kUState) == 2)) ok = false;
    if (!ok) {  // Native may already own this tracker for a newer order; do not rewrite its key/target.
        rec.flags |= rRenew;
        return;
    }
    const U held = Rd(tracker + kTTarget);
    if (held && Sane(held) && Rd(held + kAUnit) != e->target)
        reinterpret_cast<void(__fastcall*)(U, U)>(static_cast<uintptr_t>(trackerClear))(tracker, 0);
    if (Rd(tracker + kTKey) != e->target) Wr32(tracker + kTKey, e->target);
}

// -------------------------------------------------------------------------------------------- EndTick sweep (POD only)
// Full pass every tick (a 512-record rotation delayed routing/order/death exits by 8 ticks - exits must be
// immediate).  Restores (probe expiry / tracker-demanded / cancellation handbacks) are UNBUDGETED; only
// waypoint renewal is budgeted.
void Sweep() {
    U renewals = 0;
    bool probesChanged = false;
    const U start = renewalCursor < recordLimit ? renewalCursor : 0;
    for (U visited = 0; visited < recordLimit; ++visited) {
        const U index = start + visited;
        const U r = index < recordLimit ? index : index - recordLimit;
        Record& rec = records[r];
        if (!rec.unit) continue;
        // A native new order or routing decision wins over a scheduled probe expiry.
        if (OwnedMount(rec.mount) == kStampEmpty) continue;
        // 1) probe exit: window elapsed, or the tracker pre-step demanded it.  Unconditional native
        //    movement restore (a combat node persists ~8 s on its own); arrival/drift never gate this.
        if ((rec.flags & rProbe) && (curTick >= rec.probeUntil || (rec.flags & rRenew))) {
            rec.flags &= ~(rProbe | rRenew);
            UnitEntry* e = EntryByUnit(rec.unit);
            if (e && e->probes) --e->probes;
            probesChanged = true;
            if ((rec.flags & rDesc) && Sane(rec.mount) && staged < kStageMax) {
                Stage& s = stage[staged++];
                s.mount = rec.mount; s.combat = 0; s.orbit = 0;
                StageIdentity(s, rec, *e);
                memcpy(s.desc, rec.desc, kDescBytes);
                float wx, wz, y;
                B tmp[kDescBytes];
                memcpy(tmp, rec.desc, kDescBytes);
                if (MountWaypoint(rec, *e, wx, wz) && InstallY(rec.mount, wx, wz, y)) {
                    memcpy(tmp, &wx, 4); memcpy(tmp + 4, &y, 4); memcpy(tmp + 8, &wz, 4);
                    if (NormalizeOrbit(rec.mount, tmp, wx, wz)) {
                        memcpy(s.desc, tmp, kDescBytes);
                        s.orbit = 1;
                        rec.wx = wx; rec.wz = wz; rec.ux = e->tx; rec.uz = e->tz; rec.rad = LaneRadius(*e, rec); rec.lastTick = curTick;
                    } else {
                        DropRecord(r); // exact original native descriptor stays staged as the handback
                    }
                } else {
                    DropRecord(r); // terrain unavailable: native descriptor, not a fabricated orbit height
                }
            }
            continue;
        }
        if (!(rec.flags & rDesc)) continue;
        UnitEntry* e = EntryLive(rec.unit);
        if (!e || !e->orbit || (rec.flags & rProbe)) continue;
        if (Sane(rec.mount) && YieldToNative(rec.mount)) continue;  // native owns: keep rActivate/lastTick so recovery is prompt
        // 3) budgeted waypoint renewal (staggered by construction: per-record age/arrival/drift gates)
        const bool activating = (rec.flags & rActivate) != 0;
        if (!activating && curTick - rec.lastTick < kRenewMin) continue;
        float mx = RdF(rec.mount + kAX), mz = RdF(rec.mount + kAZ);
        if (!Good(mx) || !Good(mz)) continue;
        const float dx = FSub(mx, rec.wx), dz = FSub(mz, rec.wz);
        const bool arrived = FLt(FSqrt(FAdd(FMul(dx, dx), FMul(dz, dz))), static_cast<float>(kArrive));
        const float ddx = FSub(rec.ux, e->tx), ddz = FSub(rec.uz, e->tz); // square moved since install
        const bool drifted = FLt(static_cast<float>(kDrift), FSqrt(FAdd(FMul(ddx, ddx), FMul(ddz, ddz))));
        const bool aged = curTick - rec.lastTick >= kMaxAge;
        const OrbitBand& rb = unitBands[e - entries];
        const bool radiusMoved = rec.lane1 && rec.lane1 <= rb.laneCount &&
                                 FLt(static_cast<float>(kDrift), fabsf(FSub(rb.radius[rec.lane1 - 1], rec.rad)));  // real prior installed radius, existing drift tolerance
        if (!activating && !arrived && !drifted && !aged && !radiusMoved) continue;
        if (renewals >= kRenewBudget) continue;  // validated, renewed next tick (never `break`)
        float wx, wz;
        if (!MountWaypoint(rec, *e, wx, wz)) continue;
        if (staged >= kStageMax) continue;  // (defensive; renewals << stage capacity)
        Stage& s = stage[staged++];
        s.mount = rec.mount; s.combat = 0; s.orbit = 0;
        StageIdentity(s, rec, *e);
        memcpy(s.desc, rec.desc, kDescBytes);
        float y;
        if (!InstallY(rec.mount, wx, wz, y)) { --staged; continue; }
        memcpy(s.desc + 0, &wx, 4); memcpy(s.desc + 4, &y, 4); memcpy(s.desc + 8, &wz, 4);
        if (!NormalizeOrbit(rec.mount, s.desc, wx, wz)) { --staged; continue; }
        rec.wx = wx; rec.wz = wz; rec.ux = e->tx; rec.uz = e->tz; rec.rad = LaneRadius(*e, rec); rec.lastTick = curTick;
        rec.flags &= ~rActivate;
        s.orbit = 1;
        renewalCursor = r + 1 == recordLimit ? 0 : r + 1;
        ++renewals;
    }
    if (probesChanged) RebuildProbeHash();
}

void Fire() {  // no guard, no epoch interposition: one plain native install per stage entry
    for (U i = 0; i < staged; ++i)
        if (Sane(stage[i].mount) && StageValid(stage[i])) {
            const U fn = stage[i].combat ? combatInstall : moveInstall;
            reinterpret_cast<NativeOrder>(static_cast<uintptr_t>(fn))(stage[i].mount, 0, stage[i].desc);
            const U r = RecordFind(stage[i].mount);  // authority follows the install that actually ran
            if (r != kStampEmpty && records[r].unit == stage[i].unit) {
                if (stage[i].orbit) StampOrbit(records[r]); else records[r].flags &= ~rOrbit;
            }
        }
    staged = 0;
}

void ClearAll() {  // no native dereference
    for (U i = 0; i < kMaxUnitEntries; ++i) UnpublishKey(i);  // before the entries may be reclaimed;
    // flushCancel and the begin/end generation are deliberately left alone (monotonic protocol state)
    memset(entries, 0, sizeof(entries));
    memset(records, 0, sizeof(records));
    memset(mountHash, 0, sizeof(mountHash));
    memset(unitBands, 0, sizeof(unitBands));
    memset(classSlots, 0, sizeof(classSlots));
    memset(probeHash, 0, sizeof(probeHash));
    memset(known, 0, sizeof(known));
    memset(targetCache, 0, sizeof(targetCache));
    memset(stage, 0, sizeof(stage));
    recordLimit = renewalCursor = probeCount = staged = 0;
    epoch = 0;
}

void OnFault() {
    ++faults;
    ClearAll();
    if (faults >= kMaxFaults) disabled = true;
}
}  // namespace

// -------------------------------------------------------------------------------------------- interface
void Bind(U imageBase) {
    delta = imageBase - 0x400000u;
    imageLo = imageBase;
    imageSize = 0;
    // SizeOfImage from the mapped PE header (the only native read Bind ever does; failure leaves size 0 and
    // every InImage check false, which keeps every native-call pre-validation conservative).
    __try {
        const U pe = imageBase + Rd(imageBase + 0x3C);  // DOS e_lfanew -> PE signature
        if (Rd(pe) == 0x00004550u) imageSize = Rd(pe + 0x50);
    } __except (EXCEPTION_EXECUTE_HANDLER) { imageSize = 0; }
    moveInstall = V(kMoveInstall);
    combatInstall = V(kCombatInstall);
    combatRet = V(kCombatRet);
    combatRetCmd = V(kCombatRetCmd);
    goRetEntity = V(kGoRetEntity);
    goRetPoint = V(kGoRetPoint);
    trackerClear = V(kTrackerClear);
    mountedCall = V(kMountedCall);
    terrainQuery = V(kTerrainQuery);
    orderAdjust = V(kOrderAdjust);
    ownerTid = curTick = curModel = seq = targetCursor = allocCursor = faults = staged = probeCount = 0;
    epoch = 0;
    disabled = false;
    bound = imageSize != 0;
    settings = DefaultSettings();
    settings.clearance_margin = kSquareGap;
    ClearAll();
}

void Reset() { ClearAll(); }  // world teardown / dormancy: discard state, never dereference native memory
// Destructor-gate observation (0x582736-class call sites; tick owner only, called with the row intact
// BEFORE the native 0x529D80 body runs).  The entry snapshot of the flush generation opens the protocol:
// a publication overlapping ANY flush - one already in flight at entry (begin != end) or one moving
// either counter off the snapshot - is discarded, so a flush can never miss a published key.
// with outer 0x58275C); every other return (flush side effects, formation-abort pop, clone-shifted
// callers) cancels.  A row whose serial/target no longer match the entry cancels conservatively - a stale
// event never revives a superseded identity.  No queue state is read here: the pop commits head/count
// only AFTER the destructor returns, so validation happens on the next tick through RetainedLive.
void ObserveRowEnd(U row, U returnAddress, U outerReturnAddress) {
    const long e0 = flushEnd, b0 = flushBegin;  // volatile reads; the only pre-protocol action
    if (!InScope()) return;                     // outside an owner epoch: identity only, nothing retained
    ++kntwr::probeDepth;
    __try {
        UnitEntry* e = nullptr;
        U headAfter = 0;
        bool latch = false;
        if (Sane(row) && Rd(row) == V(kAttackRowVt)) {
            const U el = Rd(row + 8);           // inline slot: el == row-8; [el] is the owning unit
            if (el == row - 8) {
                const U owner = Rd(el), off = row - owner - kURowBase;
                if (Sane(owner) && off % kURowStride == 0 && off / kURowStride < 10 &&
                    Rd(owner + kURowIdx) == off / kURowStride) {
                    e = EntryByUnit(owner);
                    if (e && e->serial == Rd(row + kRowSerial) && e->target == Rd(row + kRowTarget)) {
                        const bool normal = returnAddress == V(0x582738) ||
                            (returnAddress == V(0x56D8D8) && outerReturnAddress == V(0x58275C));
                        if (normal) { latch = true; headAfter = (off / kURowStride + 1) % 10; }
                        else Unretain(*e);      // flush/abort/shifted class: the order ended abnormally
                    } else if (e) Unretain(*e); // superseded identity on the entry: cancel, never revive
                }
            }
        }
        if (latch && e) {                       // publication is the LAST step: nothing below can fault
            const U i = static_cast<U>(e - entries);
            _InterlockedExchange(&flushCancel[i], 0);              // veto cleared before the key exists
            _InterlockedExchange(&flushKey[i], static_cast<long>(e->unit + 0x390));
            if (b0 != e0 || flushBegin != b0 || flushEnd != e0) {  // a flush was already in flight at
                UnpublishKey(i);                                   // entry, or one overlapped the
            } else {                                               // publication: it may have missed
                e->retained = true;                                // the key - discard, never keep
                e->headAfter = headAfter;                          // (a later consume re-latches)
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // fail closed: an unreadable row retains nothing (a fresh row recaptures); fall through so the
        // probe-depth guard is balanced - a fault can only precede the publication, never follow it
    }
    --kntwr::probeDepth;
}

// Flush-entry observation at 0x542AE0 (ANY thread, any lifecycle point: no InScope, no native reads, no
// SEH, integer-only, allocation-free - the hook gate requires exactly that).  `ring` is the raw ECX value
// (unit+0x390) used as a VALUE key, never dereferenced.  Bounded work: two interlocked increments and one
// 128-slot scan of plain volatile loads (x86 TSO + the interlocked publication make them sound).
void ObserveFlush(U ring) {
    _InterlockedIncrement(&flushBegin);
    const long key = static_cast<long>(ring);
    for (U i = 0; i < kMaxUnitEntries; ++i)
        if (flushKey[i] == key) _InterlockedExchange(&flushCancel[i], 1);
    _InterlockedIncrement(&flushEnd);
}

void BeginTick(U model, U tick) {
    if (!bound || disabled || !Sane(model)) return;
    ownerTid = __readfsdword(0x24);
    curTick = tick; curModel = model;
    staged = 0;
    epoch = 1;
    ++kntwr::probeDepth;  // guarded reads below are expected, caught faults
    __try {
        Scan(model);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        OnFault();
    }
    --kntwr::probeDepth;
    if (staged) Fire();  // probe admissions and handbacks staged during the scan
}

void EndTick() {
    if (!bound || disabled || !epoch || ownerTid != __readfsdword(0x24)) return;
    ++kntwr::probeDepth;
    __try {
        Sweep();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        OnFault();
    }
    --kntwr::probeDepth;
    epoch = 0;
    if (staged) Fire();
}

void NoteForeignOrder(U mount) { _InterlockedIncrement(&foreignMark[ForeignIdx(mount)]); }

void Move(U mount, const void* descriptor, NativeOrder original) {
    if (!original) return;
    MovePlan p; p.mode = 0;
    if (InScope()) {
        ++kntwr::probeDepth;
        __try {
            PlanMove(mount, descriptor, p);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            p.mode = 0;
            OnFault();
        }
        --kntwr::probeDepth;
        if (!p.mode) ClearOrbit(mount);  // the caller's native descriptor replaces any orbit node
    } else {
        NoteForeignOrder(mount);
    }
    original(mount, 0, p.mode ? p.desc : descriptor);  // exactly once, the caller's buffer otherwise
}

// Shared engagement decision of the command-layer entry points (slot +0x110 combat, slot +0x118 go).  The caller's descriptor is
// never read as movement (a go descriptor is {entity-or-0, x, z}, not the 0x2A movement layout): only the descriptor captured on
// the record is ever installed.  0 -> `original` exactly once; 1 -> one 0x5DD450 install, no original; 2 -> nothing at all.
static void Engage(U mount, const void* descriptor, NativeOrder original) {
    CombatPlan p; p.mode = 0;
    {
        ++kntwr::probeDepth;
        __try {
            PlanCombat(mount, p);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            p.mode = 0;
            OnFault();
        }
        --kntwr::probeDepth;
    }
    if (p.mode == 2) return;
    if (p.mode == 1) { reinterpret_cast<NativeOrder>(static_cast<uintptr_t>(moveInstall))(mount, 0, p.desc); return; }
    ClearOrbit(mount);  // the native order replaces whatever node is installed
    original(mount, 0, descriptor);
}

void Combat(U mount, const void* descriptor, U returnAddress, NativeOrder original) {
    if (!original) return;
    const bool scoped = InScope();
    if (!scoped || (returnAddress != combatRet && returnAddress != combatRetCmd)) {  // exact call sites only
        if (scoped) ClearOrbit(mount); else NoteForeignOrder(mount);
        original(mount, 0, descriptor);
        return;
    }
    Engage(mount, descriptor, original);
}

void Go(U mount, const void* descriptor, U returnAddress, NativeOrder original) {
    if (!original) return;
    const bool scoped = InScope();
    if (!scoped || (returnAddress != goRetEntity && returnAddress != goRetPoint)) {  // exact call sites only
        if (scoped) ClearOrbit(mount); else NoteForeignOrder(mount);
        original(mount, 0, descriptor);
        return;
    }
    Engage(mount, descriptor, original);
}

U Tracker(U tracker, U agent, NativeTracker original) {
    if (!original) return 0;
    if (InScope() && probeCount) {
        ++kntwr::probeDepth;
        __try {
            PlanTracker(tracker, agent);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            OnFault();
        }
        --kntwr::probeDepth;
    }
    return original(tracker, 0, agent);
}

}  // namespace kntwr_cavalry
