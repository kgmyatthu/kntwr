// Exercise private adapter decisions against an isolated x86 memory graph without exposing a test API.
// Native mounted/square predicates are controlled here; native movement/combat execution remains a live test.
#include "army/native_cavalry_runtime.cpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <thread>

namespace {
using namespace kntwr_cavalry;
U Address(void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void Put(U p, U value) { *reinterpret_cast<U*>(p) = value; }
void Position(U p, float x, float z) {
    *reinterpret_cast<float*>(p + 0x48) = x;
    *reinterpret_cast<float*>(p + 0x50) = z;
}
void Check(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
unsigned char __fastcall Yes(U, U) { return 1; }
void __fastcall ClearTestTracker(U tracker, U) { Put(tracker + kTTarget, 0); }
U __fastcall FlatTerrain(U, U, float* out, const float* in, U) {
    out[0] = in[0]; out[1] = 0; out[2] = in[1]; return Address(out);
}
// Controlled native 0x66AE10 order query: returns a per-test order and counts queries so tests can
// prove the validate-before-query decline path never reaches native code.
U g_adjustOrder = 0x777;
U g_adjustCalls = 0;
U __fastcall MockOrderAdjust(U, U, U, U) { ++g_adjustCalls; return g_adjustOrder; }
U RdDesc32(const B* d, U off) { U v; std::memcpy(&v, d + off, 4); return v; }
float RdDescF(const B* d, U off) { float v; std::memcpy(&v, d + off, 4); return v; }
// Realistic captured movement descriptor: patterned verbatim bytes, order dword +0x18, mode DWORD
// +0x1C (upper bytes nonzero on purpose), native speed +0x20, stale native leg time +0x24, pending
// slot-adjust flag byte +0x29. Combat descriptors are synthesized elsewhere and never use this.
B* MoveDesc(B* desc, float v, float leg = 25.0f) {
    for (U i = 0; i < kDescBytes; ++i) desc[i] = static_cast<B>(0x40 + i);
    const U order = 0x66, mode = 0xBBAA0703u;  // 25.0f / 4.5f == 5.5555553f, the observed native time
    const float t = leg / v;
    std::memcpy(desc + 0x18, &order, 4);
    std::memcpy(desc + 0x1C, &mode, 4);
    std::memcpy(desc + 0x20, &v, 4);
    std::memcpy(desc + 0x24, &t, 4);
    desc[0x29] = 1;
    return desc;
}
// Stock attack-row completion plumbing (byte-proven): the row destructor 0x529D80 (thiscall(row, flags),
// ret 4, EAX = row) returns to 0x582738 - or to 0x56D8D8 under an outer frame returning to 0x58275C;
// any other pop of a tracked row (e.g. the 0x581FA0 path) cancels.  Ring slots live at U+0x398 +
// 0x90*slot (10 slots): an inline 8-byte element at row-8 ([el] = owner U) followed by the row itself,
// so el+8 IS the row vtable - there is no backlink field.  [row+8] holds the inline element pointer
// (el == row-8 is an arithmetic identity the validation enforces).
constexpr U kRowDtorRet = 0x582738, kRowDtorInner = 0x56D8D8, kRowDtorOuter = 0x58275C;
constexpr U kRowPopCancel = 0x581FA0, kRoutFsmB = 0x145090C, kSteerFsmE = 0x1450918;

struct World {
    std::vector<B> root = std::vector<B>(0xc0), manager = std::vector<B>(0x100);
    std::vector<B> side = std::vector<B>(0x30), army = std::vector<B>(0x100);
    std::vector<B> own = std::vector<B>(0x1000), enemy = std::vector<B>(0x1000);
    std::vector<B> cls = std::vector<B>(0x30), formation = std::vector<B>(0x100), vt = std::vector<B>(0x100);
    std::vector<B> ownMen = std::vector<B>(2 * 0x700), enemyMen = std::vector<B>(2 * 0x700);
    std::array<U, 2> ownArr{}, enemyArr{}, units{};
    std::array<U, 1> sides{}, armies{};
    U model, unit, target;
    World() {
        ClearAll(); delta = 0; seq = 0; targetCursor = 0;
        imageLo = 0; imageSize = 0xffffffffu;
        mountedCall = Address(reinterpret_cast<void*>(&Yes));
        orderAdjust = Address(reinterpret_cast<void*>(&MockOrderAdjust));
        g_adjustCalls = 0;
        settings = DefaultSettings(); settings.first_probe_delay_ms = 10000000;
        model = Address(root.data()); unit = Address(own.data()); target = Address(enemy.data());
        ownArr = {Address(ownMen.data()), Address(ownMen.data() + 0x700)};
        enemyArr = {Address(enemyMen.data()), Address(enemyMen.data() + 0x700)};
        units = {unit, target}; sides = {Address(side.data())}; armies = {Address(army.data())};
        Put(model + 0xb0, Address(manager.data()));
        const float rect[] = {-100000, -100000, 100000, 100000};
        std::memcpy(reinterpret_cast<void*>(model + 0x84), rect, sizeof(rect));
        Put(Address(manager.data()) + 0x84, 1); Put(Address(manager.data()) + 0x88, Address(sides.data()));
        Put(sides[0] + 0x20, 1); Put(sides[0] + 0x24, Address(armies.data()));
        Put(armies[0] + 0xf0, 2); Put(armies[0] + 0xf4, Address(units.data()));
        for (U u : units) {
            Put(u + 0xaa0, 1); Put(u + 0x2cc, 2);
            *reinterpret_cast<float*>(u + 0x2f8) = 1.0f;
        }
        Put(unit + 0x2d0, Address(ownArr.data())); Put(target + 0x2d0, Address(enemyArr.data()));
        Put(unit + 0x2c, Address(cls.data())); Put(unit + 0x930, 1);
        Put(unit + 0x398, 0x1324080); Put(unit + 0x39c, 123); Put(unit + 0x3bc, target);
        Put(Row(0) + 0x8, ElemAddr(0));  // row+8 -> inline element; [el] = owner U (el+8 is the row vt)
        Put(ElemAddr(0), unit);
        Put(unit + 0x934, 0); Put(unit + 0x938, 1);  // head slot 0, exactly one row queued
        Put(target + 0xae8, 1); Put(target + 0xae0, Address(formation.data()));
        Put(Address(formation.data()), Address(vt.data()));
        Put(Address(vt.data()) + 0xd8, Address(reinterpret_cast<void*>(&Yes)));
        Position(ownArr[0], 100, 50); Position(ownArr[1], 102, 52);
        Position(enemyArr[0], 20, 30); Position(enemyArr[1], 22, 32);
        for (U mount : ownArr) { Put(mount + 0x1f0, unit); Put(mount + 0x30, 1); }
        curModel = model;
    }
    void Tick(U tick) { curTick = tick; staged = 0; Scan(model); }
    void CaptureProbe() {
        Record& rec = records[0]; rec.mount = ownArr[0]; rec.unit = unit;
        rec.memberIdx = 0; rec.flags = rDesc | rProbe; rec.probeUntil = curTick;
        recordLimit = 1; RebuildMountHash();
    }
    U Row(U slot) { return unit + 0x398 + 0x90 * slot; }
    U ElemAddr(U slot) { return Row(slot) - 8; }  // inline element: 8 bytes immediately before the row
    // Queue a real attack row: vtable at +0, serial +4, target +0x24, plus the ownership chain the
    // native validation walks: [row+8] = el (the arithmetic row-8) and [el] = owner U.  el+8 is the
    // row vtable itself and is never written as a pointer.
    void IssueRow(U slot, U serial, U target) {
        const U row = Row(slot);
        Put(row, 0x1324080u); Put(row + 0x4, serial); Put(row + 0x24, target);
        Put(row + 0x8, ElemAddr(slot));
        Put(ElemAddr(slot), unit);
    }
    // The tick-owner epoch gate (test stand-in for BeginTick's InScope): ObserveRowEnd only records,
    // and the retained half of OrderLive only answers, while the owner thread holds the epoch open -
    // so every Scan/PlanMove/PlanCombat/Sweep/OrderLive in a retained case runs inside it; close the
    // epoch only when a case intentionally observes life from outside the owner tick.
    void OwnEpoch() { bound = true; epoch = 1; ownerTid = __readfsdword(0x24); }
    void CloseEpoch() { epoch = 0; }
    // Real native completion of the head row: the adapter observes the destructor return while the row
    // is intact and still the head slot; the pop then drains one entry and advances the head (the tail
    // moves only on enqueue, so an emptied queue leaves head == tail at the next slot).
    void CompleteRow(U ret, U outer = 0) {
        const U slot = Rd(unit + 0x934);
        ObserveRowEnd(Row(slot), ret, outer);
        Put(unit + 0x930, Rd(unit + 0x930) - 1);
        Put(unit + 0x934, (slot + 1) % 10);
    }
};

void EligibilityAndGeometry() {
    World w;
    w.Tick(1);
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && e->orbit, "enemy appearing later in the graph is eligible");
    Check(e->tx == 21 && e->tz == 31, "translated footprint centre is not scaled");
    w.Tick(2); Check(e->footTick == 1, "cache hit does not extend cache lifetime");
    Position(w.enemyArr[1], 24, 34); w.Tick(4);
    Check(e->footTick == 4 && e->tx == 22 && e->tz == 32, "expired geometry observes moved target");
    std::vector<U> large(4097, w.enemyArr[0]); large.back() = w.enemyArr[1];
    Put(w.target + 0x2cc, 4097); Put(w.target + 0x2d0, Address(large.data()));
    Position(w.enemyArr[1], 400, 600);
    float x, z, radius;
    Check(Footprint(w.target, x, z, radius) && x == 210 && z == 315 && radius > 340,
          "footprint includes outlier beyond former sampling cutoff");
}

void DeathAndOrderPrecedence() {
    World w; w.Tick(1); w.CaptureProbe();
    Put(w.target + 0xaa0, 2); w.Tick(2);
    Check(!EntryByUnit(w.unit)->orbit && records[0].unit == 0,
          "dead target immediately revokes orbit ownership");
    Check(staged == 1 && !stage[0].combat && StageValid(stage[0]),
          "same-order target death restores native movement without renewal throttling");
    Put(w.target + 0xaa0, 1); w.Tick(3); w.CaptureProbe();
    Put(w.unit + 0x39c, 124); staged = 0; Sweep();
    Check(staged == 0 && records[0].unit == 0, "new order wins over coincident probe expiry");
    Stage s = {}; s.mount = w.ownArr[1]; s.unit = w.unit; s.memberIdx = 1; s.serial = 123; s.target = w.target;
    Check(!StageValid(s), "staged install cannot overwrite a newer order");
    Put(w.unit + 0x39c, 123); Check(StageValid(s), "unchanged live order remains admissible");
    Put(w.ownArr[1] + 0x1d8, 0x3c);
    Check(!StageValid(s), "routing wins over staged movement");
    Put(s.mount + 0x1d8, 0); Put(s.mount + 0x30, 0);
    Check(!StageValid(s), "inactive mount cannot receive a staged orbit install");
    Put(s.mount + 0x30, 1); Put(s.mount + 0x628, 0x10000);
    Check(!StageValid(s), "parked native ownership wins over orbit");
    Put(s.mount + 0x628, 0); Put(s.mount + 0x224, 0x14);
    Check(!StageValid(s), "horse refusal cannot be overwritten by orbit renewal");
}

void TargetCenteredRiderOrbit() {
    World w;
    Position(w.enemyArr[0], 90, -90); Position(w.enemyArr[1], 110, -70);
    Position(w.ownArr[0], 140, -80); Position(w.ownArr[1], 600, 400);
    w.Tick(1);
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && e->orbit, "spread cavalry still tracks the ordered square");
    Record rec = {}; rec.mount = w.ownArr[0]; rec.unit = w.unit;
    float x, z;
    Check(MountWaypoint(rec, *e, x, z), "rider receives a square-centered waypoint");
    const float radius = std::hypot(x - 100, z + 80);
    Check(radius > 15 && radius < 20,
          "orbit clears square corners without adding cavalry formation spread");
    Position(w.ownArr[1], 800, -800); w.Tick(4);
    float nextX, nextZ;
    Check(MountWaypoint(rec, *e, nextX, nextZ) &&
          std::hypot(nextX - x, nextZ - z) < 0.001f,
          "another cavalry rider cannot displace this rider's circle");
}

void RenewalFairness() {
    World w;
    constexpr U count = kRenewBudget + 1;
    std::vector<B> men(count * 0x700);
    std::array<U, count> members{};
    for (U i = 0; i < count; ++i) {
        members[i] = Address(men.data() + i * 0x700);
        Put(members[i] + 0x1f0, w.unit); Position(members[i], 100 + float(i), 50);
        Put(members[i] + 0x30, 1);
    }
    Put(w.unit + 0x2cc, count); Put(w.unit + 0x2d0, Address(members.data()));
    w.Tick(100);
    for (U i = 0; i < count; ++i) {
        Record& rec = records[i]; rec.mount = members[i]; rec.unit = w.unit;
        rec.memberIdx = i; rec.flags = rDesc; rec.wx = 100 + float(i); rec.wz = 50;
        MoveDesc(rec.desc, 4.5f);
    }
    recordLimit = count; RebuildMountHash();
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    Sweep(); Check(staged == kRenewBudget, "native renewal work remains bounded");
    // Make every mount due again, including those just renewed; later records must still progress.
    for (U i = 0; i < count; ++i) Position(members[i], records[i].wx, records[i].wz);
    curTick += kRenewMin; staged = 0; Sweep();
    bool lastRenewed = false;
    for (U i = 0; i < staged; ++i) lastRenewed |= stage[i].mount == members.back();
    Check(lastRenewed, "early mounts cannot starve later mounts of orbit renewal");
    terrainQuery = savedTerrain;
}

void NativeHandbackPrecedence() {
    {
        World w; w.Tick(1); w.CaptureProbe();
        ProbeAdd(w.ownArr[0], 0);
        std::array<U, 6> tracker = {w.unit, 0, 0, 0, 0, 0};
        const U savedClear = trackerClear;
        trackerClear = Address(reinterpret_cast<void*>(&ClearTestTracker));
        Put(w.unit + 0x39c, 124); // native has accepted a newer command
        PlanTracker(Address(tracker.data()), w.ownArr[0]);
        Check(tracker[0] == w.unit, "old probe cannot erase the newer native tracker key");
        trackerClear = savedClear;
    }
    {
        World w; w.Tick(1); w.CaptureProbe();
        Put(w.unit + 0x2f8, 0);
        w.Tick(2);
        Check(staged == 1 && StageValid(stage[0]) && records[0].unit == 0,
              "lost spacing restores native movement instead of abandoning an orbit waypoint");
    }
    {
        World w; w.Tick(1); w.CaptureProbe();
        Put(w.unit + 0x39c, 124);
        w.Tick(2);
        Check(staged == 0, "identity transition cannot restore the previous order's descriptor");
    }
}

void BoundaryHandback() {
    World w; w.Tick(1); w.CaptureProbe();
    *reinterpret_cast<float*>(w.model + 0x90) = 34; // Z wall intersects the required orbit; X remains wide.
    w.Tick(2);
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && !e->orbit && e->blockedSerial == 123 && staged == 1 && StageValid(stage[0]),
          "edge-blocked circle restores native attack for the same order");
    *reinterpret_cast<float*>(w.model + 0x90) = 100000;
    w.Tick(3);
    Check(!e->orbit, "edge handback remains native for the rest of the attack order");
    Put(w.unit + 0x39c, 124); w.Tick(4);
    Check(e->orbit, "a new attack order can acquire a circle that now fits");
    const float invalidRect[] = {0, 0, 0, 0};
    std::memcpy(reinterpret_cast<void*>(w.model + 0x84), invalidRect, sizeof(invalidRect));
    w.Tick(5);
    Check(!e->orbit, "unknown playable bounds never permit an unbounded orbit");
}

void SquareActivationTransitions() {
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    B descriptor[kDescBytes]; MoveDesc(descriptor, 4.5f);
    MovePlan plan = {};
    w.Tick(1);
    PlanMove(w.ownArr[0], descriptor, plan);
    Check(plan.mode == 1, "already-square target redirects the first native movement");

    World later;
    Put(later.target + 0xae8, 0);
    later.Tick(1);
    PlanMove(later.ownArr[0], descriptor, plan);
    Check(plan.mode == 0, "attack remains native before the target forms square");
    later.Tick(2); Sweep();
    Check(staged == 0, "remembering an approach does not move a rider before square activation");
    Put(later.target + 0xae8, 1);
    later.Tick(3); Sweep();
    Check(staged == 1 && !stage[0].combat && StageValid(stage[0]),
          "late square activates remembered approach without reissuing the attack");
    float x, z;
    std::memcpy(&x, stage[0].desc, 4); std::memcpy(&z, stage[0].desc + 8, 4);
    Check(std::hypot(x - 21, z - 31) < 8,
          "late square activation installs a waypoint around the same ordered target");
}

void ArmedLifecycle() {
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    B descriptor[kDescBytes]; MoveDesc(descriptor, 4.5f);
    MovePlan move = {}; CombatPlan combat = {};
    Put(w.target + 0xae8, 0); w.Tick(1);
    PlanMove(w.ownArr[0], descriptor, move);
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 0, "armed approach does not suppress native combat before square");
    Put(w.ownArr[0] + 0x224, 0x14);
    Put(w.target + 0xae8, 1); w.Tick(2); Sweep();
    Check(staged == 0, "square activation respects temporary horse refusal");
    Put(w.ownArr[0] + 0x224, 0); w.Tick(3); Sweep();
    Check(staged == 1 && StageValid(stage[0]), "activation resumes after horse refusal without a new move");
    Put(w.target + 0xae8, 0); w.Tick(4);
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 1 && staged == 0,
          "same attack keeps circling when the enemy drops square after acquisition");
    Put(w.unit + 0x39c, 124); w.Tick(5); Sweep();
    Check(staged == 0, "new non-square attack cannot inherit the earlier square latch");
    Put(w.target + 0xae8, 1); w.Tick(6); Sweep();
    Check(staged == 0, "a new order cannot activate a descriptor from the previous attack");

    World between;
    Put(between.target + 0xae8, 0); between.Tick(1);
    Put(between.unit + 0x39c, 124); // native order issued after Scan
    PlanMove(between.ownArr[0], descriptor, move);
    Put(between.target + 0xae8, 1); between.Tick(2); Sweep();
    Check(staged == 1 && stage[0].serial == 124 && StageValid(stage[0]),
          "mid-tick native approach is captured under its current attack identity");

    World dead;
    Put(dead.target + 0xae8, 0); dead.Tick(1);
    PlanMove(dead.ownArr[0], descriptor, move);
    Put(dead.target + 0xaa0, 0); dead.Tick(2); Sweep();
    Check(staged == 0, "target death while armed does not reinstall an obsolete approach");
}

void TemporaryControllerOwnership() {
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    B descriptor[kDescBytes]; MoveDesc(descriptor, 4.5f);
    MovePlan move = {};
    Put(w.target + 0xae8, 0); w.Tick(1);
    PlanMove(w.ownArr[0], descriptor, move);
    Put(w.ownArr[0] + 0x628, 0x10000);
    w.Tick(2); Sweep();
    Put(w.target + 0xae8, 1); w.Tick(3); Sweep();
    Check(staged == 0, "native interaction controller retains control during activation");
    Put(w.ownArr[0] + 0x628, 0); w.Tick(4); Sweep();
    Check(staged == 1 && StageValid(stage[0]),
          "temporary controller release resumes captured approach without a new order");
}

Record* RecordOf(U mount) {
    for (U i = 0; i < recordLimit; ++i) if (records[i].unit && records[i].mount == mount) return &records[i];
    return nullptr;
}
void FirstCaptureDuringTemporaryOwnership() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    B descriptor[kDescBytes]; MoveDesc(descriptor, 4.5f);
    B pristine[kDescBytes]; std::memcpy(pristine, descriptor, kDescBytes);
    const struct { const char* name; U off; U val; } cases[] = {
        {"controller ownership", 0x628, 0x10000}, {"nonzero controller", 0x628, 1}, {"horse refusal", 0x224, 0x14}};
    for (const auto& c : cases) {
        // approach captured before square, while native temporarily owns the mount
        World w;
        Put(w.target + 0xae8, 0); w.Tick(1);
        Put(w.ownArr[0] + c.off, c.val);
        MovePlan move = {}; move.mode = 7;
        PlanMove(w.ownArr[0], descriptor, move);
        Check(move.mode == 0 && std::memcmp(descriptor, pristine, kDescBytes) == 0,
              c.name);
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec && (rec->flags & rDesc) && std::memcmp(rec->desc, pristine, kDescBytes) == 0,
              "first descriptor delivered during temporary native ownership is captured byte-exact");
        Put(w.target + 0xae8, 1); w.Tick(2); Sweep();
        Check(staged == 0, "nothing is installed while native ownership persists");
        Put(w.ownArr[0] + c.off, 0); staged = 0; w.Tick(3); Sweep();
        Check(staged == 1 && StageValid(stage[0]), "same order resumes after release without a new move");

        // orbit already active when the first descriptor arrives: Sweep resumes without another Move callback
        World o;
        Put(o.target + 0xae8, 1); o.Tick(1);
        Put(o.ownArr[0] + c.off, c.val);
        move = {};
        PlanMove(o.ownArr[0], descriptor, move);
        Check(move.mode == 0, "no install during temporary ownership");
        Put(o.ownArr[0] + c.off, 0); staged = 0; o.Tick(2); Sweep();
        Check(staged == 1 && StageValid(stage[0]), "orbit entry capture recovers through Sweep budget");

        // a new order cancels before recovery
        World n;
        Put(n.target + 0xae8, 0); n.Tick(1);
        Put(n.ownArr[0] + c.off, c.val);
        PlanMove(n.ownArr[0], descriptor, move);
        Put(n.unit + 0x39c, 124); Put(n.ownArr[0] + c.off, 0); Put(n.target + 0xae8, 1);
        staged = 0; n.Tick(2); Sweep();
        Check(staged == 0, "new order never recovers the previous descriptor");

        // routing cancels before recovery
        World t;
        Put(t.target + 0xae8, 0); t.Tick(1);
        Put(t.ownArr[0] + c.off, c.val);
        PlanMove(t.ownArr[0], descriptor, move);
        Put(t.ownArr[0] + 0x1b8, 0x4B); Put(t.ownArr[0] + c.off, 0); Put(t.target + 0xae8, 1);
        staged = 0; t.Tick(2); Sweep();
        Check(staged == 0, "routing cancels before recovery");
    }
    // terminal states never allocate
    World d;
    Put(d.target + 0xae8, 0); d.Tick(1);
    Put(d.ownArr[0] + 0x30, 0);
    MovePlan mv = {};
    PlanMove(d.ownArr[0], descriptor, mv);
    Check(!RecordOf(d.ownArr[0]), "inactive mount is not captured");
    World g;
    Put(g.target + 0xae8, 0); g.Tick(1);
    Put(g.ownArr[0] + 0x1b8, 0x4B);
    PlanMove(g.ownArr[0], descriptor, mv);
    Check(!RecordOf(g.ownArr[0]), "routing mount is not captured");
    terrainQuery = savedTerrain;
}

void CollisionAndRiderIdentity() {
    ClearAll(); seq = 1;
    const U a = 0x100000, b = a + kKnownSlots * 16;
    Check(Hash(a, kKnownSlots) == Hash(b, kKnownSlots), "fixture contains a collision");
    KnownAdd(a); KnownAdd(b);
    Check(KnownHas(a) && KnownHas(b), "collision does not hide a live unit");
    ++seq; KnownAdd(b);
    Check(KnownHas(b) && !KnownHas(a), "old generation cannot resurrect an absent unit");
    records[0].mount = a; records[0].unit = b; records[0].flags = rProbe;
    ProbeAdd(a + 16, 0);
    Check(ProbeFind(a + 16) == 0 && ProbeFind(a + 32) == kStampEmpty,
          "rider key resolves its mount record without admitting unrelated agents");
}
// A cavalry unit of `count` riders ringed 60 m round a point 80 m behind the ordered square (the ring centre must NOT coincide with
// the target centre: a zero charge line is degenerate and declines the whole order), each with a captured descriptor.
struct Squad {
    std::vector<B> men;
    std::vector<U> members;
    Squad(World& w, U count) : men(count * 0x700), members(count) {
        for (U i = 0; i < count; ++i) {
            members[i] = Address(men.data() + i * 0x700);
            Put(members[i] + 0x1f0, w.unit); Put(members[i] + 0x30, 1);
            const float a = 6.2831853f * float(i) / float(count);
            Position(members[i], 21 + 60 * std::cos(a), -49 + 60 * std::sin(a));
        }
        Put(w.unit + 0x2cc, count); Put(w.unit + 0x2d0, Address(members.data()));
    }
    // Capture a native descriptor for every rider through the real planner; each call must install
    // (mode 1), so the geometry measured below is the geometry the surface actually installed.
    void Capture(World& w) {
        B descriptor[kDescBytes]; MoveDesc(descriptor, 4.5f);
        MovePlan plan = {};
        for (U m : members) {
            PlanMove(m, descriptor, plan);
            Check(plan.mode == 1, "every rider receives an installed orbit waypoint");
        }
        (void)w;
    }
};
float OrbitRadius(U mount, UnitEntry& e) {
    Record* rec = RecordOf(mount);
    float x, z;
    if (!rec || !MountWaypoint(*rec, e, x, z)) return -1;
    return std::hypot(x - e.tx, z - e.tz);
}

void MultiRowOrbit() {
    constexpr U kLarge = 300;
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    float innerSmall = -1.0f;
    {
        World w; Squad s(w, 4); w.Tick(1); s.Capture(w);
        UnitEntry* e = EntryByUnit(w.unit);
        Check(e && e->orbit, "small cavalry unit orbits");
        innerSmall = 1e9f;
        for (U m : s.members) innerSmall = std::fmin(innerSmall, OrbitRadius(m, *e));
        Check(innerSmall > 1, "small unit rider receives an orbit radius");
    }
    World w; Squad s(w, kLarge); w.Tick(1); s.Capture(w);
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && e->orbit, "large cavalry unit orbits");
    std::vector<float> radii;
    for (U m : s.members) radii.push_back(OrbitRadius(m, *e));
    float lo = 1e9f, hi = 0;
    for (float r : radii) { Check(r > 0, "every large-unit rider receives a waypoint"); lo = std::fmin(lo, r); hi = std::fmax(hi, r); }
    Check(std::fabs(lo - innerSmall) < 0.01f, "innermost radius does not grow with headcount");
    for (float r : radii) Check(r >= innerSmall - 0.01f, "no rider orbits inside the square clearance");
    // Rows are separated by at least one rider diameter (the unit's spacing is 1.0 m in this fixture).
    std::vector<float> sorted = radii; std::sort(sorted.begin(), sorted.end());
    int bands = 1; float bandStart = sorted[0];
    for (float r : sorted) if (r - bandStart > 1.0f) { ++bands; bandStart = r; }
    Check(bands >= 2 && hi - lo >= 2.0f, "a large unit occupies at least two radial bands");
    U inner = 0; for (float r : radii) inner += (r - lo < 1.0f);
    Check(inner < kLarge, "endpoints are not all in the innermost band");

    // Row identity survives an unrelated casualty, a probe (through expiry and rejoin), and
    // temporary native ownership.
    Check(RecordOf(s.members[7]) && RecordOf(s.members[100]) && RecordOf(s.members[200]), "records exist");
    Put(s.members[7] + 0x30, 0);           // casualty
    Record* probed = RecordOf(s.members[100]);
    probed->flags |= rProbe; probed->probeUntil = 3;
    ProbeAdd(probed->mount, U(probed - records));
    Put(s.members[200] + 0x628, 0x10000);  // native interaction controller
    w.Tick(2); Sweep();
    Put(s.members[200] + 0x628, 0);
    w.Tick(3); Sweep();
    // Probe expiry restores native movement through a staged orbit waypoint in the SAME row.
    U restore = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == s.members[100]) restore = i;
    Check(restore != kStampEmpty && !stage[restore].combat && StageValid(stage[restore]),
          "probe expiry hands the rider back through a valid native orbit stage");
    float rx, rz;
    std::memcpy(&rx, stage[restore].desc, 4); std::memcpy(&rz, stage[restore].desc + 8, 4);
    Check(std::fabs(std::hypot(rx - e->tx, rz - e->tz) - radii[100]) < 0.001f,
          "the staged native restore keeps the rider's row");
    MovePlan rejoin = {};
    B rejoinDesc[kDescBytes]; MoveDesc(rejoinDesc, 4.5f);
    PlanMove(s.members[100], rejoinDesc, rejoin);
    Check(rejoin.mode == 1 && std::fabs(OrbitRadius(s.members[100], *e) - radii[100]) < 0.001f,
          "rider rejoins orbit in the same row after probe expiry");
    for (U i = 0; i < kLarge; ++i) {
        if (i == 7) continue;
        Check(std::fabs(OrbitRadius(s.members[i], *e) - radii[i]) < 0.001f,
              "rider keeps its row through unrelated casualty, probe, and temporary ownership");
    }

    // Stage budgets hold while the whole large unit is serviced across many ticks.
    for (U i = 0; i < kLarge; ++i) { Record* r = RecordOf(s.members[i]); if (r) r->flags |= rDesc; }
    for (U t = 10; t < 140; t += 5) {
        w.Tick(t); Sweep();
        U renew = 0, admit = 0;
        for (U i = 0; i < staged; ++i) stage[i].combat ? ++admit : ++renew;
        Check(renew <= kRenewBudget, "multi-row waypoint renewal respects its own per-tick budget");
        Check(admit <= kAdmitBudget, "multi-row probe admission respects its own per-tick budget");
    }
    terrainQuery = savedTerrain;
}

void MultiRowBoundaryHandback() {
    constexpr U kLarge = 300;
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    auto SetRect = [](World& w, float h) {
        const float rect[] = {21 - h, 31 - h, 21 + h, 31 + h};
        std::memcpy(reinterpret_cast<void*>(w.model + 0x84), rect, sizeof(rect));
    };
    // Smallest half-width at which a small unit's circle fits (measured, not computed).
    float fit = 0;
    for (float h = 4; h < 400; h += 0.25f) {
        World w; Squad s(w, 4); SetRect(w, h); w.Tick(1);
        UnitEntry* e = EntryByUnit(w.unit);
        if (e && e->orbit) { fit = h; break; }
    }
    Check(fit > 0, "a small unit fits some bounded arena");
    World big; Squad s(big, kLarge); big.Tick(1); s.Capture(big);
    for (U i = 0; i < kLarge; ++i) { Record* r = RecordOf(s.members[i]); if (r) r->flags |= rDesc; }
    UnitEntry* e = EntryByUnit(big.unit);
    Check(e && e->orbit, "large unit starts in a wide arena");
    SetRect(big, fit + 0.25f);
    big.Tick(2);
    Check(!e->orbit && e->blockedSerial == 123 && staged >= 1,
          "outer row that does not fit hands the whole order back to native movement");
    for (U i = 0; i < staged; ++i) Check(!stage[i].combat && StageValid(stage[i]), "handback is a valid native restore");
    {
        World w; Squad s2(w, 4); SetRect(w, fit + 0.25f); w.Tick(1);
        UnitEntry* se = EntryByUnit(w.unit);
        Check(se && se->orbit, "same boundary still fits the small unit's inner circle");
    }
    terrainQuery = savedTerrain;
}

// --- descriptor normalization regressions (timing, world space, lifecycle) -----------------------------

void NormalizeOrbitSeam() {
    World w;
    B desc[kDescBytes];
    // A zero-distance leg is a valid native untimed install: the waypoint is already reached.
    MoveDesc(desc, 4.5f);
    Check(NormalizeOrbit(w.ownArr[0], desc, 100.0f, 50.0f),
          "zero-distance leg normalizes as a valid native untimed install");
    Check(RdDescF(desc, 0x24) == 0.0f && desc[0x29] == 0 && RdDesc32(desc, 0x18) == g_adjustOrder,
          "zero-time leg clears the pending slot adjust and stores the queried order");
    Check(RdDesc32(desc, 0x1C) == 0xBBAA0703u && RdDescF(desc, 0x20) == 4.5f,
          "normalization preserves the full mode dword (nonzero byte 0x1D included) and the native speed");
    B fresh[kDescBytes]; MoveDesc(fresh, 4.5f);
    Check(RdDesc32(desc, 0x0C) == 0 && RdDesc32(desc, 0x10) == 0 &&
          std::memcmp(desc + 0x14, fresh + 0x14, 4) == 0 && desc[0x28] == fresh[0x28],
          "the staged world point clears the +0x0C/+0x10 frame and leaves the other verbatim bytes untouched");
    // Any nonzero slot-adjust flag matches the ported boolean, not just literal 1.
    MoveDesc(desc, 4.5f); desc[0x29] = 0x5A;
    Check(NormalizeOrbit(w.ownArr[0], desc, 103.0f, 53.0f) && desc[0x29] == 0 &&
          RdDesc32(desc, 0x18) == g_adjustOrder,
          "any nonzero slot-adjust flag is a pending order, cleared once queried");
    // With no pending order the native order stands and the native query is never entered.
    MoveDesc(desc, 4.5f); desc[0x29] = 0;
    const U before = g_adjustCalls;
    Check(NormalizeOrbit(w.ownArr[0], desc, 103.0f, 53.0f) && RdDesc32(desc, 0x18) == 0x66 &&
          RdDesc32(desc, 0x0C) == 0 && RdDesc32(desc, 0x10) == 0 && RdDescF(desc, 0x24) > 0,
          "a clean descriptor still normalizes timing and the world point without the native query");
    Check(g_adjustCalls == before, "the native order query runs only for a pending slot adjust");
    // Nonpositive or nonfinite speeds decline the install before any native query, byte-exactly.
    const float bad[] = {0.0f, -0.0f, -4.5f, std::nanf(""), HUGE_VALF};
    for (float v : bad) {
        MoveDesc(desc, v);
        B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
        const U calls = g_adjustCalls;
        Check(!NormalizeOrbit(w.ownArr[0], desc, 21.0f, 31.0f),
              "nonpositive or nonfinite speed declines the orbital install");
        Check(std::memcmp(desc, snap, kDescBytes) == 0,
              "a declined install never partially rewrites the native descriptor");
        Check(g_adjustCalls == calls, "validation precedes the read-only native order query");
    }
}

void OrbitMovementDoesNotInheritChargeStance() {
    const U savedTerrain = terrainQuery;
    for (U stance : {0u, 1u, 2u, 3u, 0xBBAA0703u}) for (B pending : {B(0), B(1)}) {
        World w;
        terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
        w.Tick(1);
        B desc[kDescBytes]; MoveDesc(desc, 4.5f);
        std::memcpy(desc + 0x1C, &stance, 4); desc[0x29] = pending;
        B original[kDescBytes]; std::memcpy(original, desc, kDescBytes);
        MovePlan plan = {}; PlanMove(w.ownArr[0], desc, plan);
        Check(plan.mode == 1, "a native charge approach can supply a perimeter movement leg");
        Check(RdDesc32(plan.desc, 0x1C) == (stance == 2 ? 1u : stance),
              "non-probing perimeter movement uses native run stance instead of charge stance");
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec && std::memcmp(rec->desc, original, kDescBytes) == 0 &&
              std::memcmp(desc, original, kDescBytes) == 0,
              "orbital stance selection never changes the original native command");
        Put(w.target + 0xaa0, 2); w.Tick(2);
        U restore = kStampEmpty;
        for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) restore = i;
        Check(restore != kStampEmpty && !stage[restore].combat &&
              std::memcmp(stage[restore].desc, original, kDescBytes) == 0,
              "native handback restores the original charge or other stance exactly");
    }
    terrainQuery = savedTerrain;
}

void MovementTimingNormalization() {
    const float speeds[] = {4.5f, 2.0f, 9.0f};
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    World w;
    w.Tick(1);
    float firstTime = 0, firstDist = 0;
    for (int i = 0; i < 3; ++i) {
        const float v = speeds[i];
        B desc[kDescBytes]; MoveDesc(desc, v);
        B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
        MovePlan plan = {};
        PlanMove(w.ownArr[0], desc, plan);
        Check(plan.mode == 1, "a realistic captured descriptor installs an orbit waypoint");
        Check(std::memcmp(desc, snap, kDescBytes) == 0, "the caller's native descriptor is never written");
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec && std::memcmp(rec->desc, snap, kDescBytes) == 0,
              "the captured original stays byte-exact for native handback");
        Check(plan.desc[0x29] == 0, "the installed waypoint carries no pending slot-shift adjust");
        Check(RdDesc32(plan.desc, 0x18) == g_adjustOrder,
              "the pending order is resolved through the read-only native query");
        Check(RdDesc32(plan.desc, 0x1C) == 0xBBAA0703u && RdDescF(plan.desc, 0x20) == v,
              "the native mode dword and speed gait survive normalization");
        Check(RdDesc32(plan.desc, 0x0C) == 0 && RdDesc32(plan.desc, 0x10) == 0 &&
              std::memcmp(plan.desc + 0x14, snap + 0x14, 4) == 0 && plan.desc[0x28] == snap[0x28],
              "normalization touches only the order, the leg time, the flag byte and the world-point frame");
        const float wx = RdDescF(plan.desc, 0), wz = RdDescF(plan.desc, 8);
        const float dist = std::hypot(wx - 100.0f, wz - 50.0f);
        const float t = RdDescF(plan.desc, 0x24);
        Check(t > 0 && std::fabs(t - dist / v) <= 1e-3f * (dist / v + 1.0f),
              "leg time is recomputed from the world-space distance and the native speed");
        if (i == 0) { firstTime = t; firstDist = dist; }
        if (i == 2)
            Check(std::fabs(dist - firstDist) <= 1e-4f &&
                  std::fabs(t - firstTime * 0.5f) <= 1e-3f * (t + firstTime + 1.0f),
                  "doubling the speed halves the same world-space leg");
    }
    // A rider elsewhere on the field gets a leg consistent with its own distance and speed.
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    MovePlan plan = {};
    PlanMove(w.ownArr[1], desc, plan);
    Check(plan.mode == 1, "a second rider installs an orbit waypoint");
    const float wx = RdDescF(plan.desc, 0), wz = RdDescF(plan.desc, 8);
    const float dist = std::hypot(wx - 102.0f, wz - 52.0f);
    Check(std::fabs(RdDescF(plan.desc, 0x24) - dist / 4.5f) <= 1e-3f * (dist / 4.5f + 1.0f),
          "another rider's leg time matches its own distance and speed");
    terrainQuery = savedTerrain;
}

void InvalidSpeedKeepsNative() {
    const float bad[] = {0.0f, -4.5f, std::nanf("")};
    for (float v : bad) {
        World w;
        terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
        w.Tick(1);
        B desc[kDescBytes]; MoveDesc(desc, v);
        B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
        MovePlan plan = {};
        PlanMove(w.ownArr[0], desc, plan);
        Check(plan.mode == 0, "an invalid captured speed leaves the native movement in place");
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec && (rec->flags & rDesc) && std::memcmp(rec->desc, snap, kDescBytes) == 0,
              "the verbatim native capture survives a declined orbit install");
        Check(g_adjustCalls == 0, "a declined install never queries the native order adjust");
        B fix[kDescBytes]; MoveDesc(fix, 4.5f);
        MovePlan again = {};
        PlanMove(w.ownArr[0], fix, again);
        Check(again.mode == 1 && again.desc[0x29] == 0,
              "a later healthy descriptor installs a normalized orbit waypoint");
    }
    // A staged restore that cannot normalize drops the record but hands back the verbatim capture.
    {
        World w;
        terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
        w.Tick(1);
        B desc[kDescBytes]; MoveDesc(desc, 0.0f);
        B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
        MovePlan plan = {};
        PlanMove(w.ownArr[0], desc, plan);
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec, "the declined install still captured the native descriptor");
        rec->flags |= rProbe; rec->probeUntil = curTick + 1;
        ProbeAdd(rec->mount, U(rec - records));
        w.Tick(2); Sweep();
        U idx = kStampEmpty;
        for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) idx = i;
        Check(idx != kStampEmpty && !stage[idx].combat && StageValid(stage[idx]),
              "an unnormalizable restore still hands the rider back through a staged native restore");
        Check(std::memcmp(stage[idx].desc, snap, kDescBytes) == 0 && stage[idx].desc[0x29] == 1,
              "the dropped record's fallback keeps the captured bytes verbatim, pending flag included");
        Check(RecordOf(w.ownArr[0]) == nullptr, "the record is dropped after the failed restore");
    }
}

void CombatNormalization() {
    const U savedTerrain = terrainQuery;
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    Put(w.target + 0xae8, 0); w.Tick(1);
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc, move);
    Check(move.mode == 0, "the armed approach before square stays native");
    Put(w.target + 0xae8, 1); w.Tick(2); Sweep();
    staged = 0;
    CombatPlan combat = {};
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 1, "square activation diverts the phase-2 combat call into movement");
    Check(combat.desc[0x29] == 0 && RdDesc32(combat.desc, 0x18) == g_adjustOrder &&
          RdDesc32(combat.desc, 0x1C) == 0xBBAA0703u && RdDescF(combat.desc, 0x20) == 4.5f,
          "the combat diversion is normalized: slot flag cleared, order queried, gait and mode preserved");
    const float wx = RdDescF(combat.desc, 0), wz = RdDescF(combat.desc, 8);
    const float dist = std::hypot(wx - 100.0f, wz - 50.0f);
    Check(std::fabs(RdDescF(combat.desc, 0x24) - dist / 4.5f) <= 1e-3f * (dist / 4.5f + 1.0f),
          "the combat diversion leg time matches the world-space distance at native speed");
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && std::memcmp(rec->desc, snap, kDescBytes) == 0,
          "a combat diversion never rewrites the captured movement descriptor");
    terrainQuery = savedTerrain;
}

void RenewalNormalization() {
    const U savedTerrain = terrainQuery;
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    w.Tick(1);
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc, move);
    Check(move.mode == 1, "the initial orbit install succeeds");
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && std::memcmp(rec->desc, snap, kDescBytes) == 0, "the capture stays byte-exact");
    const float ax = rec->wx, az = rec->wz;  // the rider rides to its installed waypoint
    Position(w.ownArr[0], ax, az);
    curTick += kRenewMin; staged = 0; Sweep();
    U idx = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) idx = i;
    Check(idx != kStampEmpty && !stage[idx].combat && StageValid(stage[idx]),
          "arrival renews the orbit waypoint through a staged install");
    Check(stage[idx].desc[0x29] == 0 && RdDesc32(stage[idx].desc, 0x18) == g_adjustOrder &&
          RdDesc32(stage[idx].desc, 0x1C) == 0xBBAA0703u && RdDescF(stage[idx].desc, 0x20) == 4.5f,
          "the renewal stage is normalized: slot flag cleared, order queried, gait and mode preserved");
    const float wx = RdDescF(stage[idx].desc, 0), wz = RdDescF(stage[idx].desc, 8);
    const float dist = std::hypot(wx - ax, wz - az);
    Check(std::fabs(RdDescF(stage[idx].desc, 0x24) - dist / 4.5f) <= 1e-3f * (dist / 4.5f + 1.0f),
          "the renewal leg time matches the world-space distance at native speed");
    Check(std::memcmp(rec->desc, snap, kDescBytes) == 0, "renewal never rewrites the captured original");
    // A renewal whose terrain query fails is unstaged entirely; nothing is committed.
    const U committed = rec->lastTick;
    Position(w.ownArr[0], rec->wx, rec->wz);
    curTick += kRenewMin;
    terrainQuery = 0; staged = 0; Sweep();
    bool halfStaged = false;
    for (U i = 0; i < staged; ++i) halfStaged |= stage[i].mount == w.ownArr[0];
    Check(!halfStaged, "a terrain failure unstages the renewal instead of half-installing it");
    Check(rec->lastTick == committed, "a failed renewal commits nothing to the record");
    Check(std::memcmp(rec->desc, snap, kDescBytes) == 0, "a failed renewal leaves the capture untouched");
    terrainQuery = savedTerrain;
}

void ProbeRejoinNormalization() {
    const U savedTerrain = terrainQuery;
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    w.Tick(1);
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc, move);
    Check(move.mode == 1, "the rider installs its orbit waypoint before probing");
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec, "the rider holds a captured record");
    rec->flags |= rProbe; rec->probeUntil = curTick + 1;
    ProbeAdd(rec->mount, U(rec - records));
    w.Tick(2);  // expiry becomes due; the tick itself must not stage a restore for a probe record
    Check(staged == 0, "the probe record stays native through the scan");
    Sweep();
    U idx = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) idx = i;
    Check(idx != kStampEmpty && !stage[idx].combat && StageValid(stage[idx]),
          "probe expiry hands the rider back through a staged orbit waypoint");
    Check(stage[idx].desc[0x29] == 0 && RdDesc32(stage[idx].desc, 0x18) == g_adjustOrder &&
          RdDesc32(stage[idx].desc, 0x1C) == 0xBBAA0703u && RdDescF(stage[idx].desc, 0x20) == 4.5f,
          "the probe rejoin is normalized: slot flag cleared, order queried, gait and mode preserved");
    const float wx = RdDescF(stage[idx].desc, 0), wz = RdDescF(stage[idx].desc, 8);
    const float dist = std::hypot(wx - 100.0f, wz - 50.0f);
    Check(std::fabs(RdDescF(stage[idx].desc, 0x24) - dist / 4.5f) <= 1e-3f * (dist / 4.5f + 1.0f),
          "the probe rejoin leg time matches the world-space distance at native speed");
    Check(std::memcmp(rec->desc, snap, kDescBytes) == 0,
          "the rejoin leaves the captured original byte-exact for later handback");
    terrainQuery = savedTerrain;
}

void HandbackKeepsNativeBytes() {
    const U savedTerrain = terrainQuery;
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    w.Tick(1);
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc, move);
    Check(move.mode == 1, "the rider orbits before the handback");
    Put(w.target + 0xaa0, 2);  // target death hands the whole order back to native movement
    w.Tick(2);
    U idx = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) idx = i;
    Check(idx != kStampEmpty && !stage[idx].combat && StageValid(stage[idx]),
          "death hands the rider back through a staged native restore");
    Check(std::memcmp(stage[idx].desc, snap, kDescBytes) == 0,
          "the native handback replays the captured descriptor byte for byte");
    Check(stage[idx].desc[0x29] == 1 && RdDesc32(stage[idx].desc, 0x18) == 0x66 &&
          RdDescF(stage[idx].desc, 0x24) == 25.0f / 4.5f,
          "the handback keeps the pending slot-adjust flag, the stale order and the stale leg time");
    terrainQuery = savedTerrain;
}

void FramePointerClearKeepsHandback() {
    const U savedTerrain = terrainQuery;
    World w;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    w.Tick(1);
    B desc[kDescBytes]; MoveDesc(desc, 4.5f);
    B snap[kDescBytes]; std::memcpy(snap, desc, kDescBytes);
    Check(RdDesc32(snap, 0x0C) != 0 && RdDesc32(snap, 0x10) != 0,
          "the captured descriptor carries a nonzero legacy +0x0C/+0x10 frame");
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc, move);
    Check(move.mode == 1 && RdDesc32(move.desc, 0x0C) == 0 && RdDesc32(move.desc, 0x10) == 0,
          "the staged world point zeroes both frame dwords for the native frame reader");
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && std::memcmp(rec->desc, snap, kDescBytes) == 0,
          "the capture keeps the original legacy frame bytes byte-exact");
    Put(w.target + 0xaa0, 2);  // target death hands the whole order back to native movement
    w.Tick(2);
    U idx = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == w.ownArr[0]) idx = i;
    Check(idx != kStampEmpty && !stage[idx].combat && StageValid(stage[idx]),
          "death hands the rider back through a staged native restore");
    Check(std::memcmp(stage[idx].desc, snap, kDescBytes) == 0,
          "the native handback replays the legacy frame bytes byte for byte");
    terrainQuery = savedTerrain;
}
// ------------------------------------------------------------------ retained attack intent
// The stock destructor pops the accepted attack row; the orbit must survive on the drained queue until
// a flush, a new order, routing or target invalidity cancels it.  Shared prologue: armed capture ->
// square activation -> a live orbit with ownArr[0]'s descriptor captured byte-exact under serial 123.
struct RetainedSetup {
    World w;
    B snap[kDescBytes];
    RetainedSetup() {
        terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
        Put(w.target + 0xae8, 0);  // armed attack, no square yet
        w.Tick(1);
        B desc[kDescBytes]; MoveDesc(desc, 4.5f);
        std::memcpy(snap, desc, kDescBytes);
        MovePlan move = {};
        PlanMove(w.ownArr[0], desc, move);
        Put(w.target + 0xae8, 1);  // the target forms square: the orbit activates over the capture
        w.Tick(2); Sweep(); staged = 0;
    }
};

void RetainedAcrossNormalCompletion() {
    const U savedTerrain = terrainQuery;
    {
        RetainedSetup s; World& w = s.w;
        UnitEntry* e = EntryByUnit(w.unit);
        Check(e && e->orbit && !e->retained, "the orbit is live before the native row completes");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 1, "the live row diverts combat into the orbit");
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        e = EntryByUnit(w.unit);
        Check(e && e->retained && e->headAfter == 1, "the normal destructor return retains the identity");
        Check(OrderLive(w.unit, 123, w.target), "the drained queue keeps the accepted order live");
        Record* rec = RecordOf(w.ownArr[0]);
        Check(rec && rec->unit == w.unit && (rec->flags & rDesc) &&
              std::memcmp(rec->desc, s.snap, kDescBytes) == 0,
              "normal completion retains the prior target and its captured descriptor byte-exact");
        combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 1, "a retained order keeps diverting combat after completion");
        w.Tick(3);  // the retained unit stays a scan candidate without its dead row
        e = EntryByUnit(w.unit);
        Check(e && e->orbit && e->retained && OrderLive(w.unit, 123, w.target),
              "the next tick reconfirms the retained order");
        combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 1, "the orbit survives the tick after completion");
        w.CloseEpoch();  // assertions stay inside the owner epoch; close only between cases
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorInner, kRowDtorOuter);
        Check(OrderLive(w.unit, 123, w.target),
              "the inner destructor return retains only under its exact outer frame");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedFlushCancels() {
    const U savedTerrain = terrainQuery;
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target), "retained before the flush");
        ObserveFlush(w.unit + 0x390);  // generic ring flush on the empty queue: ECX = U+0x390
        Check(!OrderLive(w.unit, 123, w.target), "a flush of the empty queue cancels the retained order");
        UnitEntry* e = EntryByUnit(w.unit);
        Check(e && !e->retained, "the flush unpublishes the retained identity");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
              "the flushed order hands the rider back to native combat");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target), "retained before the cross-thread flush");
        std::thread flusher([&w] { ObserveFlush(w.unit + 0x390); });
        flusher.join();
        Check(!OrderLive(w.unit, 123, w.target), "a flush signalled from another thread still cancels");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
              "the owner thread observes the cross-thread cancel");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        ObserveFlush(w.unit + 0x390);  // nothing retained yet
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target),
              "a flush with nothing retained does not poison the next retention");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedNewRowCancelsAndRecaptures() {
    const U savedTerrain = terrainQuery;
    RetainedSetup s; World& w = s.w;
    w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
    Check(OrderLive(w.unit, 123, w.target), "retained after completion");
    w.IssueRow(1, 126, w.target);  // the native queues a fresh order into the drained ring
    Put(w.unit + 0x930, 1); Put(w.unit + 0x934, 1); Put(w.unit + 0x938, 2);
    Check(!OrderLive(w.unit, 123, w.target), "a queued row cancels the retained identity");
    CombatPlan combat = {};
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
          "the superseded order hands the rider back at once");
    Check(!EntryByUnit(w.unit)->retained, "the retention is cleared by the new row");
    B desc2[kDescBytes]; MoveDesc(desc2, 9.0f);
    B snap2[kDescBytes]; std::memcpy(snap2, desc2, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc2, move);  // the freshly issued row recaptures
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && (rec->flags & rDesc) && std::memcmp(rec->desc, snap2, kDescBytes) == 0,
          "the fresh row captures its own descriptor");
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && e->serial == 126 && !e->retained, "the entry follows the fresh row's identity");
    w.CloseEpoch();
    terrainQuery = savedTerrain;
}

void RetainedRetargetCancels() {
    const U savedTerrain = terrainQuery;
    RetainedSetup s; World& w = s.w;
    // A second, fully valid enemy unit joins the graph so the retarget is a real order.
    std::vector<B> other(0x1000), otherMen(2 * 0x700);
    const U otherUnit = Address(other.data());
    Put(otherUnit + 0xaa0, 1); Put(otherUnit + 0x2cc, 2); Put(otherUnit + 0x2d0, Address(otherMen.data()));
    std::array<U, 3> all = {w.unit, w.target, otherUnit};
    Put(w.armies[0] + 0xf0, 3);
    Put(w.armies[0] + 0xf4, Address(all.data()));
    w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
    Check(OrderLive(w.unit, 123, w.target), "retained before the retarget");
    w.IssueRow(1, 127, otherUnit);
    Put(w.unit + 0x930, 1); Put(w.unit + 0x934, 1); Put(w.unit + 0x938, 2);
    Check(!OrderLive(w.unit, 123, w.target), "a different target cancels the retained identity");
    Check(OrderLive(w.unit, 127, otherUnit), "the retargeted row is live under its own identity");
    CombatPlan combat = {};
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
          "the old target's orbit never survives the retarget");
    w.CloseEpoch();
    terrainQuery = savedTerrain;
}

void RetainedAppendDoesNotRetain() {
    const U savedTerrain = terrainQuery;
    {
        RetainedSetup s; World& w = s.w;
        w.IssueRow(1, 126, w.target);  // the native appends a pending order behind the active row
        Put(w.unit + 0x930, 2); Put(w.unit + 0x938, 2);
        Check(OrderLive(w.unit, 123, w.target), "the live head row keeps the order");
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(Rd(w.unit + 0x930) == 1 && Rd(w.unit + 0x934) == 1 && Rd(w.unit + 0x938) == 2,
              "the fixture pop leaves the successor queued");
        Check(!OrderLive(w.unit, 123, w.target), "completion with a queued successor does not retain");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
              "the completed order hands back while its successor is pending");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target), "retained with an empty ring");
        Put(w.unit + 0x938, 3);  // the tail moved without a queued row
        Check(!OrderLive(w.unit, 123, w.target), "a moved tail cancels the retained identity");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedWrongDestructorReturnDeclines() {
    const U savedTerrain = terrainQuery;
    const U foreign[] = {kRowPopCancel, kRowDtorInner, 0x581000u};  // cancel path; inner return
    for (U ret : foreign) {                                         // without its frame; unrelated return
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(ret);
        UnitEntry* e = EntryByUnit(w.unit);
        Check(e && !e->retained, "only the byte-proven destructor returns may retain");
        Check(!OrderLive(w.unit, 123, w.target), "a foreign pop return cancels the order");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr,
              "the foreign return hands the rider back to native combat");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedDeathAndRoutCancel() {
    const U savedTerrain = terrainQuery;
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target), "retained before the target dies");
        Put(w.target + 0xaa0, 2);
        Check(!OrderLive(w.unit, 123, w.target), "a dead target cancels the retained order");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr, "target death hands the rider back");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(OrderLive(w.unit, 123, w.target), "retained before the rout");
        Put(w.unit + 0xd6c, V(kRoutFsmB));  // unit state machine B: rout
        Check(!OrderLive(w.unit, 123, w.target), "the rout state machine cancels the retained order");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0, "a routing unit returns to native control");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Put(w.unit + 0xd6c, V(kSteerFsmE));  // state E owns steering: defers installs, never cancels
        Check(OrderLive(w.unit, 123, w.target) && EntryByUnit(w.unit)->retained,
              "state E defers installs without cancelling the order");
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0, "state E defers the combat divert while the order stays retained");
        Check(OrderLive(w.unit, 123, w.target), "the deferred divert does not cancel retention");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Put(w.ownArr[0] + 0x1d8, 0x3c);  // agent-level routing exit
        CombatPlan combat = {};
        PlanCombat(w.ownArr[0], combat);
        Check(combat.mode == 0 && RecordOf(w.ownArr[0]) == nullptr, "agent routing hands the rider back");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedIdentityNotInherited() {
    const U savedTerrain = terrainQuery;
    RetainedSetup s; World& w = s.w;
    w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
    ObserveFlush(w.unit + 0x390);
    Check(!OrderLive(w.unit, 123, w.target), "the retention is cancelled before the reissue");
    w.IssueRow(1, 126, w.target);  // the same rider receives a genuinely new order
    Put(w.unit + 0x930, 1); Put(w.unit + 0x934, 1); Put(w.unit + 0x938, 2);
    B desc2[kDescBytes]; MoveDesc(desc2, 9.0f);
    B snap2[kDescBytes]; std::memcpy(snap2, desc2, kDescBytes);
    MovePlan move = {};
    PlanMove(w.ownArr[0], desc2, move);
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && std::memcmp(rec->desc, snap2, kDescBytes) == 0 &&
              std::memcmp(rec->desc, s.snap, kDescBytes) != 0,
          "the new identity captures fresh bytes, never the stale descriptor");
    UnitEntry* e = EntryByUnit(w.unit);
    Check(e && e->serial == 126 && !e->retained, "the fresh identity does not inherit the stale retention");
    Stage stale = {};
    stale.mount = w.ownArr[0]; stale.unit = w.unit; stale.memberIdx = 0;
    stale.serial = 123; stale.target = w.target;
    Check(!StageValid(stale), "a stage built for the cancelled identity cannot install");
    stale.serial = 126;
    Check(StageValid(stale), "the same stage under the fresh identity installs");
    w.CloseEpoch();
    terrainQuery = savedTerrain;
}

void RetainedMalformedRowIgnored() {
    const U savedTerrain = terrainQuery;
    {
        RetainedSetup s; World& w = s.w;  // no epoch open: the callback arrives outside the owner tick
        w.CompleteRow(kRowDtorRet);
        Check(!EntryByUnit(w.unit)->retained && !OrderLive(w.unit, 123, w.target),
              "a callback outside the owner epoch is ignored");
    }
    {
        RetainedSetup s; World& w = s.w;
        Put(w.Row(0) + 0x8, 0);  // owner link severed: U = [[row+8]] is unresolvable
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(!EntryByUnit(w.unit)->retained && !OrderLive(w.unit, 123, w.target),
              "a row without an owner element cannot retain");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        Put(w.Row(0) + 0x8, w.Row(1) - 8);  // a foreign inline element: the next slot's header
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(!EntryByUnit(w.unit)->retained && !OrderLive(w.unit, 123, w.target),
              "a foreign inline element pointer declines the event");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        Put(w.ElemAddr(0), w.target);  // the element claims a foreign owner
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(!EntryByUnit(w.unit)->retained && !OrderLive(w.unit, 123, w.target),
              "a foreign owner cannot retain this unit's order");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        Put(w.Row(0), 0x5DCDE0u);  // not an attack row anymore
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(!EntryByUnit(w.unit)->retained && !OrderLive(w.unit, 123, w.target),
              "a foreign row type is ignored");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;
        w.IssueRow(1, 123, w.target);  // a fully valid row that is NOT the head slot
        w.OwnEpoch(); ObserveRowEnd(w.Row(1), kRowDtorRet, 0);
        UnitEntry* e = EntryByUnit(w.unit);
        Check(e && !e->retained, "only the current head slot may complete an order");
        Check(OrderLive(w.unit, 123, w.target), "the live head row keeps the order");
        w.CloseEpoch();
    }
    {
        RetainedSetup s; World& w = s.w;  // the adapter survived every malformation
        w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
        Check(EntryByUnit(w.unit)->retained && OrderLive(w.unit, 123, w.target),
              "declined malformations leave the adapter fully functional");
        w.CloseEpoch();
    }
    terrainQuery = savedTerrain;
}

void RetainedNeverReadsFreedRow() {
    const U savedTerrain = terrainQuery;
    RetainedSetup s; World& w = s.w;
    w.OwnEpoch(); w.CompleteRow(kRowDtorRet);
    Check(OrderLive(w.unit, 123, w.target), "retained before the row storage is reused");
    std::memset(reinterpret_cast<void*>(w.ElemAddr(0)), 0xCC, 0x8);  // the inline element is destroyed
    std::memset(reinterpret_cast<void*>(w.Row(0)), 0xCC, 0x90);      // ...and the popped row with it
    Check(OrderLive(w.unit, 123, w.target), "retention never dereferences the destroyed row");
    CombatPlan combat = {};
    PlanCombat(w.ownArr[0], combat);
    Check(combat.mode == 1, "the orbit continues on the retained identity alone");
    Record* rec = RecordOf(w.ownArr[0]);
    Check(rec && std::memcmp(rec->desc, s.snap, kDescBytes) == 0,
          "the retained descriptor stays byte-exact after the row is destroyed");
    Put(w.Row(0), 0x5DCDE0u); Put(w.Row(0) + 0x4, 999);  // a different row type occupies the destroyed slot
    Check(OrderLive(w.unit, 123, w.target) && EntryByUnit(w.unit)->retained,
          "foreign reuse of the destroyed slot changes nothing");
    w.CloseEpoch();
    terrainQuery = savedTerrain;
}

// ------------------------------------------------------------------ command-layer engagement (Go slot +0x118, Combat slot +0x110)
// Controlled native callbacks: the 0x5DD450 install, the 0x5DCDE0 combat install, the original command-layer entry and the 0x57E870
// terrain query are real function pointers that count what the adapter actually DOES, so "retained / replaced / handed back" is
// observed from side effects (install count, descriptor bytes, original pointer identity), never from an echoed decision value.
U g_origCalls = 0, g_origMount = 0, g_instCalls = 0, g_instMount = 0, g_combatInstalls = 0, g_terrainCalls = 0;
const void* g_origDesc = nullptr;
B g_instDesc[kDescBytes];
std::vector<U> g_instLog;
void __fastcall OriginalProbe(U mount, U, const void* desc) {  // records the pointer only: a go descriptor is 12 bytes, never 0x2A
    ++g_origCalls; g_origMount = mount; g_origDesc = desc;
}
void __fastcall InstallProbe(U mount, U, const void* desc) {   // the 0x5DD450 movement install (reads exactly the 0x2A byte layout)
    ++g_instCalls; g_instMount = mount; g_instLog.push_back(mount);
    std::memcpy(g_instDesc, desc, kDescBytes);
}
void __fastcall CombatInstallProbe(U, U, const void*) { ++g_combatInstalls; }
U __fastcall CountingTerrain(U a, U b, float* out, const float* in, U c) { ++g_terrainCalls; return FlatTerrain(a, b, out, in, c); }
void ResetNative() {
    g_origCalls = g_origMount = g_instCalls = g_instMount = g_combatInstalls = g_terrainCalls = g_adjustCalls = 0;
    g_origDesc = nullptr; std::memset(g_instDesc, 0, sizeof(g_instDesc)); g_instLog.clear();
}
void Check2(bool ok, const char* message, const char* detail) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s [%s]\n", message, detail); std::exit(1); }
}

// A real 12-byte go descriptor {entity-or-0, x, z} ending exactly at a PAGE_NOACCESS page: any read of it as the 0x2A movement layout
// (or any read past 12 bytes) faults the process, and the bytes are compared after every call to prove they were never written.
struct GoBuf {
    B* base; B* p; B snap[12];
    GoBuf() {
        base = static_cast<B*>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Check(base != nullptr, "go descriptor page allocated");
        DWORD old = 0;
        Check(VirtualProtect(base + 0x1000, 0x1000, PAGE_NOACCESS, &old) != 0, "guard page protected");
        p = base + 0x1000 - 12;
        Set(0x1234u, 777.0f, -888.0f);
    }
    ~GoBuf() { VirtualFree(base, 0, MEM_RELEASE); }
    GoBuf(const GoBuf&) = delete;
    GoBuf& operator=(const GoBuf&) = delete;
    void Set(U entity, float x, float z) {
        std::memcpy(p, &entity, 4); std::memcpy(p + 4, &x, 4); std::memcpy(p + 8, &z, 4);
        std::memcpy(snap, p, 12);
    }
    bool Untouched() const { return std::memcmp(p, snap, 12) == 0; }
};

// Installs the probes and the exact call-site allowlists (Bind() does this in production; the World fixture does not call it).
struct NativeGuard {
    U terrain = terrainQuery, move = moveInstall, combat = combatInstall, cRet = combatRet, cRetCmd = combatRetCmd,
      gEntity = goRetEntity, gPoint = goRetPoint;
    NativeGuard() {
        delta = 0;
        terrainQuery = Address(reinterpret_cast<void*>(&CountingTerrain));
        moveInstall = Address(reinterpret_cast<void*>(&InstallProbe));
        combatInstall = Address(reinterpret_cast<void*>(&CombatInstallProbe));
        combatRet = V(kCombatRet); combatRetCmd = V(kCombatRetCmd);
        goRetEntity = V(kGoRetEntity); goRetPoint = V(kGoRetPoint);
        ResetNative();
    }
    ~NativeGuard() {
        terrainQuery = terrain; moveInstall = move; combatInstall = combat; combatRet = cRet; combatRetCmd = cRetCmd;
        goRetEntity = gEntity; goRetPoint = gPoint;
        disabled = false; epoch = 0;
    }
};

struct Shape { bool combat; U va; const char* name; };  // two separate call-site allowlists: go {7FF51A,7FF53D}, combat {64DED6,7FF4AF}
const Shape kShapes[] = {
    {false, kGoRetEntity, "go@7FF51A"}, {false, kGoRetPoint, "go@7FF53D"},
    {true, kCombatRet, "combat@64DED6"}, {true, kCombatRetCmd, "combat@7FF4AF"},
};

// One cavalry unit with a rider mount under an attack on a square target.  Installed: the adapter's own orbit install through the real
// Move hook (rOrbit + foreign stamp).  ArmedNative: the approach before the target is square (native descriptor passes, no orbit), then
// the square activates (rActivate pending).  FailedInstall: the orbit could not be built (terrain unavailable) so the native descriptor
// passed.  In every setup the mount then holds a movement node that LOOKS like a live orbit node (same vtable 0x1348B44, holder 0x2C4==1,
// done 0x234==0) - a native approach node is byte-identical, so only the adapter's authority may decide keep versus replace.
struct Charge {
    enum Mode { Installed, ArmedNative, FailedInstall };
    NativeGuard guard;
    World w;
    GoBuf go;
    B nativeDesc[kDescBytes], first[kDescBytes];
    explicit Charge(Mode mode) {
        MoveDesc(nativeDesc, 4.5f);
        if (mode == ArmedNative) Put(w.target + 0xae8, 0);
        w.Tick(1); w.OwnEpoch();
        if (mode == FailedInstall) terrainQuery = 0;
        Move(mount(), nativeDesc, &InstallProbe);
        terrainQuery = Address(reinterpret_cast<void*>(&CountingTerrain));
        Record* r = rec();
        Check(r && (r->flags & rDesc) && g_instCalls == 1 && g_origCalls == 0, "setup captured the native descriptor through Move");
        if (mode == Installed) {
            Check((r->flags & rOrbit) != 0 && !(r->flags & rActivate), "setup: the real install stamped orbit authority");
            Check(RdDescF(g_instDesc, 0) == r->wx && g_instDesc[0x29] == 0, "setup: the install was the normalized orbit copy");
            std::memcpy(first, g_instDesc, kDescBytes);
        } else {
            Check(!(r->flags & rOrbit) && std::memcmp(g_instDesc, nativeDesc, kDescBytes) == 0,
                  "setup: the native descriptor passed through verbatim with no orbit authority");
        }
        if (mode == ArmedNative) {
            Put(w.target + 0xae8, 1); w.Tick(2);
            Check((rec()->flags & rActivate) != 0 && !(rec()->flags & rOrbit), "setup: square activation is pending over the native approach");
        }
        Node(0x1348B44u, 1, 0);
        ResetNative();
    }
    U mount() const { return w.ownArr[0]; }
    Record* rec() { return RecordOf(mount()); }
    // node fixture exactly as the contract reads it: vtable at +0x22C, done byte +0x234, holder-enabled byte +0x2C4
    void Node(U vt, B holder, B done, U at = 0) {
        const U m = at ? at : mount();
        Put(m + 0x22C, vt ? V(vt) : 0);
        *reinterpret_cast<B*>(m + 0x2C4) = holder;
        *reinterpret_cast<B*>(m + 0x234) = done;
    }
    void Call(const Shape& s, U m, const void* desc) {
        if (s.combat) Combat(m, desc, V(s.va), &OriginalProbe); else Go(m, desc, V(s.va), &OriginalProbe);
    }
    void Call(const Shape& s) { Call(s, mount(), go.p); }
    // everything a keep must leave alone: both riders, the unit, and the record's authority/waypoint/descriptor fields
    std::vector<B> Snap() {
        std::vector<B> v;
        auto add = [&v](const void* p, size_t n) { const B* b = static_cast<const B*>(p); v.insert(v.end(), b, b + n); };
        add(reinterpret_cast<void*>(w.ownArr[0]), 0x700); add(reinterpret_cast<void*>(w.ownArr[1]), 0x700);
        add(reinterpret_cast<void*>(w.unit), 0x1000);
        if (Record* r = rec()) {
            add(&r->mount, sizeof(r->mount)); add(&r->unit, sizeof(r->unit)); add(&r->flags, sizeof(r->flags));
            add(&r->probeUntil, sizeof(r->probeUntil)); add(&r->foreign, sizeof(r->foreign)); add(&r->lastTick, sizeof(r->lastTick));
            add(&r->wx, sizeof(r->wx)); add(&r->wz, sizeof(r->wz)); add(&r->ux, sizeof(r->ux)); add(&r->uz, sizeof(r->uz));
            add(r->desc, kDescBytes);
        }
        return v;
    }
    bool Silent() const {
        return g_origCalls == 0 && g_instCalls == 0 && g_combatInstalls == 0 && g_adjustCalls == 0 && g_terrainCalls == 0 && staged == 0;
    }
    // exactly one 0x5DD450 install of the normalized orbit copy for `m`, no original, no combat install, caller buffer untouched
    void ExpectOneInstall(U m, const char* what, const char* detail) {
        Check2(g_instCalls == 1 && g_instMount == m && g_origCalls == 0 && g_combatInstalls == 0, what, detail);
        Check2(go.Untouched(), "the caller's go buffer is never written", detail);
        Record* r = RecordOf(m);
        Check2(r != nullptr && (r->flags & rOrbit) != 0 && !(r->flags & rActivate), "the install restamped orbit authority", detail);
        const B* d = g_instDesc;
        Check2(d[0x29] == 0 && RdDesc32(d, 0x18) == g_adjustOrder && RdDesc32(d, 0x1C) == 0xBBAA0703u && RdDescF(d, 0x20) == 4.5f &&
                   RdDesc32(d, 0x0C) == 0 && RdDesc32(d, 0x10) == 0,
               "the install is the normalized captured descriptor", detail);
        Check2(RdDescF(d, 0) == r->wx && RdDescF(d, 8) == r->wz, "the install carries the record's own waypoint", detail);
        const float mx = *reinterpret_cast<float*>(m + 0x48), mz = *reinterpret_cast<float*>(m + 0x50);
        const float dist = std::hypot(r->wx - mx, r->wz - mz);
        Check2(std::fabs(RdDescF(d, 0x24) - dist / 4.5f) <= 1e-3f * (dist / 4.5f + 1.0f), "the install leg time matches its distance", detail);
        Check2(RdDescF(d, 0) != 777.0f && RdDescF(d, 8) != -888.0f, "the go descriptor never becomes movement", detail);
    }
    void ExpectHandback(U m, const char* what, const char* detail) {
        Check2(g_origCalls == 1 && g_origMount == m && g_origDesc == go.p, what, detail);
        Check2(g_instCalls == 0 && g_combatInstalls == 0, "a handback installs nothing of ours", detail);
        Check2(go.Untouched(), "the original 12-byte go buffer is untouched", detail);
    }
    ~Charge() { w.CloseEpoch(); }
};

// An established adapter-installed orbit is retained by every command-layer re-issue: no original, no install, no terrain/order query,
// no staging, and not one byte of the mounts, unit or record authority changes - across repeated calls and across ticks.
void KeepActiveOrbit() {
    for (const Shape& s : kShapes) {
        Charge c(Charge::Installed);
        std::vector<B> before = c.Snap();
        for (int i = 0; i < 3; ++i) c.Call(s, c.mount(), i == 1 ? nullptr : c.go.p);  // the descriptor is never even read
        Check2(c.Silent(), "an active orbit is retained without any callback", s.name);
        Check2(c.go.Untouched() && before == c.Snap(), "a retained orbit changes no byte of adapter or game state", s.name);
        c.w.Tick(2); ResetNative(); staged = 0;  // the scan's own work is not under test; the Go/Combat decision is
        before = c.Snap();
        for (int i = 0; i < 2; ++i) c.Call(s);
        Check2(c.Silent(), "the orbit is still retained on a later tick", s.name);
        Check2(before == c.Snap(), "keep stays byte-neutral on a later tick", s.name);
    }
}

// A finished / missing / disabled / foreign node can never be kept: exactly one normalized install replaces it (no original, no
// combat install), after which the new node is retained again.
void ReplaceUnusableNode() {
    struct Node { const char* name; U vt; B holder, done; };
    const Node nodes[] = {
        {"finished node", 0x1348B44u, 1, 1}, {"missing node", 0, 1, 0}, {"holder disabled", 0x1348B44u, 0, 0},
        {"foreign vtable", 0x1333EA4u, 1, 0}, {"combat node", 0x1333E3Cu, 1, 0},
    };
    for (const Shape& s : kShapes)
        for (const Node& n : nodes) {
            char detail[96]; std::snprintf(detail, sizeof(detail), "%s %s", s.name, n.name);
            Charge c(Charge::Installed);
            c.Node(n.vt, n.holder, n.done);
            c.Call(s, c.mount(), nullptr);  // replacing never reads the go descriptor
            c.ExpectOneInstall(c.mount(), "a finished or missing node is replaced by exactly one install", detail);
            Check2(std::memcmp(g_instDesc, c.first, kDescBytes) == 0, "the replacement equals the original orbit install", detail);
            Check2(g_adjustCalls == 1 && g_terrainCalls == 1, "the replacement did exactly one normalization and one terrain query", detail);
            ResetNative(); c.Node(0x1348B44u, 1, 0);  // the native install produced a fresh live node
            c.Call(s);
            Check2(c.Silent(), "the freshly installed node is retained again", detail);
        }
    // terrain failure on a replace: the native original runs once and the next call cannot keep a node that adapter did not install
    for (const Shape& s : kShapes) {
        Charge c(Charge::Installed);
        c.Node(0x1348B44u, 1, 1);
        terrainQuery = 0;
        c.Call(s);
        c.ExpectHandback(c.mount(), "an unbuildable replacement hands the order to the native original once", s.name);
        Check2(!(c.rec()->flags & rOrbit), "the native handback voids orbit authority", s.name);
        terrainQuery = Address(reinterpret_cast<void*>(&CountingTerrain));
        ResetNative(); c.Node(0x1348B44u, 1, 0);  // the native order installed a same-class approach node
        c.Call(s);
        c.ExpectOneInstall(c.mount(), "the native approach node is replaced, not kept", s.name);
    }
}

// Authority, not node shape: a native approach node has the same vtable/holder/done bytes as ours.
void NativeApproachNeverKept() {
    for (const Shape& s : kShapes) {
        {   // square activation pending over the native approach (Scan set rActivate, clearing rOrbit): replace, then retain
            Charge c(Charge::ArmedNative);
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "a fresh activation replaces the native approach", s.name);
            ResetNative(); c.Call(s);
            Check2(c.Silent(), "the activated orbit is retained afterwards", s.name);
        }
        {   // the unbuildable-orbit native descriptor (no authority ever stamped)
            Charge c(Charge::FailedInstall);
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "a native descriptor that passed is replaced, not kept", s.name);
        }
        {   // pending activation forced on a stamped orbit
            Charge c(Charge::Installed);
            c.rec()->flags |= rActivate;
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "pending activation replaces even an adapter-installed orbit", s.name);
        }
        {   // pending probe-expiry rejoin
            Charge c(Charge::Installed);
            c.rec()->flags |= rRenew;
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "a pending rRenew replaces instead of keeping", s.name);
        }
        {   // a fresh native Move of the same node class inside the epoch (terrain unavailable => the native descriptor passes)
            Charge c(Charge::Installed);
            terrainQuery = 0;
            Move(c.mount(), c.nativeDesc, &InstallProbe);
            terrainQuery = Address(reinterpret_cast<void*>(&CountingTerrain));
            Check2(g_instCalls == 1 && std::memcmp(g_instDesc, c.nativeDesc, kDescBytes) == 0, "the fresh native move passed through verbatim", s.name);
            Check2(!(c.rec()->flags & rOrbit), "a native move voids orbit authority", s.name);
            ResetNative();
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "a fresh old-class native move is replaced, not kept", s.name);
        }
        {   // a second adapter install through the real Move hook keeps authority
            Charge c(Charge::Installed);
            B again[kDescBytes]; MoveDesc(again, 4.5f);
            Move(c.mount(), again, &InstallProbe);
            Check2(g_instCalls == 1 && (c.rec()->flags & rOrbit) != 0, "a replaced orbit install restamps authority", s.name);
            ResetNative();
            c.Call(s);
            Check2(c.Silent(), "the restamped orbit is retained", s.name);
        }
    }
}

// Authority is bound to the native-order epoch: anything that installed an order off-tick, or in any foreign way, voids it.
void ForeignOrderVoidsAuthority() {
    for (const Shape& s : kShapes) {
        {   // out-of-epoch native pass-through (another thread / outside the owner tick) invalidates keep
            Charge c(Charge::Installed);
            c.w.CloseEpoch();
            B nat[kDescBytes]; MoveDesc(nat, 4.5f);
            Move(c.mount(), nat, &InstallProbe);
            Check2(g_instCalls == 1 && std::memcmp(g_instDesc, nat, kDescBytes) == 0, "the off-epoch native move passes through verbatim", s.name);
            ResetNative(); c.w.OwnEpoch();
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "the next owned call replaces after an off-epoch native move", s.name);
            ResetNative(); c.Call(s);
            Check2(c.Silent(), "and retains the re-established orbit", s.name);
        }
        {   // out-of-epoch command-layer call at a valid return: original once, then the owned call replaces
            Charge c(Charge::Installed);
            c.w.CloseEpoch();
            c.Call(s);
            c.ExpectHandback(c.mount(), "an out-of-epoch valid-return call goes straight to the original", s.name);
            ResetNative(); c.w.OwnEpoch();
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "the owned call after an off-epoch command replaces", s.name);
        }
        {   // explicit foreign-order notification
            Charge c(Charge::Installed);
            NoteForeignOrder(c.mount());
            c.Call(s);
            c.ExpectOneInstall(c.mount(), "a foreign order notification voids keep", s.name);
            ResetNative(); c.Call(s);
            Check2(c.Silent(), "the restamped orbit is retained after the notification", s.name);
        }
    }
}

// Anything that is not an owned, valid, in-scope orbit at an allowed return hands the call to the original exactly once with the
// caller's untouched 12-byte buffer - even though the mount holds a node that looks keepable.
void HandbackMatrix() {
    struct Case { const char* name; void (*apply)(Charge&); };
    const Case cases[] = {
        {"probe active", [](Charge& c) { c.rec()->flags |= rProbe; }},
        {"epoch closed", [](Charge& c) { c.w.CloseEpoch(); }},
        {"adapter disabled", [](Charge&) { disabled = true; }},
        {"wrong owner thread", [](Charge&) { ownerTid += 1; }},
        {"new order", [](Charge& c) { Put(c.w.unit + 0x39c, 124); }},
        {"target dead", [](Charge& c) { Put(c.w.target + 0xaa0, 2); }},
        {"agent routing", [](Charge& c) { Put(c.mount() + 0x1d8, 0x3c); }},
        {"routing activity", [](Charge& c) { Put(c.mount() + 0x1b8, 0x4B); }},
        {"controller ownership", [](Charge& c) { Put(c.mount() + 0x628, 0x10000); }},
        {"horse refusal", [](Charge& c) { Put(c.mount() + 0x224, 0x14); }},
        {"inactive mount", [](Charge& c) { Put(c.mount() + 0x30, 0); }},
        {"steering hold", [](Charge& c) { Put(c.w.unit + 0xd6c, V(kSteerFsmE)); }},
        {"unit rout", [](Charge& c) { Put(c.w.unit + 0xd6c, V(kRoutFsmB)); }},
        {"descriptor never captured", [](Charge& c) { c.rec()->flags &= ~rDesc; }},
        {"mount of another unit", [](Charge& c) { Put(c.mount() + 0x1f0, c.w.target); }},
        {"unit not orbiting", [](Charge& c) { EntryByUnit(c.w.unit)->orbit = false; }},
        {"mount left the unit", [](Charge& c) { Put(c.w.unit + 0x2cc, 0); }},
    };
    for (const Shape& s : kShapes)
        for (const Case& k : cases) {
            char detail[96]; std::snprintf(detail, sizeof(detail), "%s %s", s.name, k.name);
            Charge c(Charge::Installed);
            k.apply(c);
            c.Call(s);
            c.ExpectHandback(c.mount(), "the call is handed to the original exactly once", detail);
        }
    for (const Shape& s : kShapes) {  // a rider the adapter never captured
        Charge c(Charge::Installed);
        c.Node(0x1348B44u, 1, 0, c.w.ownArr[1]);
        c.Call(s, c.w.ownArr[1], c.go.p);
        c.ExpectHandback(c.w.ownArr[1], "an uncaptured rider is never engaged", s.name);
    }
}

// Exact call sites only, separate per entry point: a go call at a combat return (and vice versa), off-by-one returns and null all hand
// back; an in-scope handback voids keep so the next valid call re-installs once.
void UnknownCallers() {
    const U goBad[] = {kCombatRet, kCombatRetCmd, 0, kGoRetEntity + 1, kGoRetPoint - 1, kGoRetEntity ^ 0x1000, 0x7FF4AEu};
    const U combatBad[] = {kGoRetEntity, kGoRetPoint, 0, kCombatRet - 2, kCombatRetCmd - 1, kCombatRet ^ 0x1000, 0x7FF4B0u};
    for (int kind = 0; kind < 2; ++kind)
        for (U bad : kind ? combatBad : goBad) {
            char detail[64]; std::snprintf(detail, sizeof(detail), "%s ret=%X", kind ? "combat" : "go", unsigned(bad));
            Charge c(Charge::Installed);
            if (kind) Combat(c.mount(), c.go.p, V(bad), &OriginalProbe); else Go(c.mount(), c.go.p, V(bad), &OriginalProbe);
            c.ExpectHandback(c.mount(), "an unknown caller reaches the original exactly once", detail);
            Check2(!(c.rec()->flags & rOrbit), "an in-scope native order voids orbit authority", detail);
            ResetNative();
            c.Call(kShapes[kind ? 2 : 0]);
            c.ExpectOneInstall(c.mount(), "the next valid call replaces the possibly-native node", detail);
            ResetNative(); c.Call(kShapes[kind ? 3 : 1]);
            Check2(c.Silent(), "and retains it again", detail);
        }
    {   // an out-of-scope unknown caller also bumps the foreign mark (and runs the original once)
        Charge c(Charge::Installed);
        c.w.CloseEpoch();
        Go(c.mount(), c.go.p, V(0x401000), &OriginalProbe);
        c.ExpectHandback(c.mount(), "an out-of-scope unknown caller reaches the original once", "go/out-of-scope");
        ResetNative(); c.w.OwnEpoch();
        c.Call(kShapes[0]);
        c.ExpectOneInstall(c.mount(), "the owned call after it replaces", "go/out-of-scope");
    }
    {   // a null original never runs or engages
        Charge c(Charge::Installed);
        Go(c.mount(), c.go.p, V(kGoRetEntity), nullptr);
        Combat(c.mount(), c.go.p, V(kCombatRet), nullptr);
        Check(c.Silent() && c.go.Untouched(), "a missing original is a no-op");
    }
}

// Renewal/probe-rejoin installs (Sweep -> Fire) stamp authority from the install that actually ran.
void SweptInstallStampsAuthority() {
    for (const Shape& s : kShapes) {
        {   // activation staged by Sweep and fired: the orbit is then retained
            Charge c(Charge::ArmedNative);
            staged = 0; Sweep();
            Check2(staged == 1 && stage[0].orbit == 1, "square activation stages one normalized orbit install", s.name);
            Fire();
            Check2(g_instCalls == 1 && g_instMount == c.mount() && (c.rec()->flags & rOrbit) != 0 && !(c.rec()->flags & rActivate),
                   "the fired activation stamps orbit authority", s.name);
            ResetNative(); c.Call(s);
            Check2(c.Silent(), "the activated orbit is retained", s.name);
        }
        {   // budgeted renewal restamps even after the authority was voided
            Charge c(Charge::Installed);
            NoteForeignOrder(c.mount());
            Record* r = c.rec();
            curTick += kRenewMin; Position(c.mount(), r->wx, r->wz);
            staged = 0; Sweep();
            Check2(staged == 1 && stage[0].orbit == 1 && stage[0].mount == c.mount(), "the arrived rider renews with one staged install", s.name);
            Fire();
            Check2(g_instCalls == 1 && (c.rec()->flags & rOrbit) != 0, "the renewal restamps orbit authority", s.name);
            ResetNative(); c.Call(s);
            Check2(c.Silent(), "the renewed orbit is retained", s.name);
        }
    }
}

// A large squad: retaining costs no native work at all; replacing every finished node costs exactly one install per rider and stays
// inside the normal renewal budget.
void SquadWorkIsBounded() {
    constexpr U kCount = 40;
    NativeGuard guard;
    World w; Squad s(w, kCount);
    w.Tick(1); w.OwnEpoch();
    s.Capture(w);
    auto setNodes = [&](B done) {
        for (U m : s.members) {
            Put(m + 0x22C, V(kOrbitNodeVt));
            *reinterpret_cast<B*>(m + 0x2C4) = 1; *reinterpret_cast<B*>(m + 0x234) = done;
        }
    };
    auto sweepAll = [&](B done) {
        setNodes(done);
        for (U i = 0; i < kCount; ++i) {
            const Shape& sh = kShapes[i % 4];
            B buf[12] = {};
            if (sh.combat) Combat(s.members[i], buf, V(sh.va), &OriginalProbe); else Go(s.members[i], buf, V(sh.va), &OriginalProbe);
        }
    };
    ResetNative(); staged = 0;
    sweepAll(0);
    Check(g_origCalls == 0 && g_instCalls == 0 && g_combatInstalls == 0 && g_terrainCalls == 0 && g_adjustCalls == 0 && staged == 0,
          "a squad of live orbits costs no native work");
    ResetNative();
    sweepAll(1);
    Check(g_origCalls == 0 && g_combatInstalls == 0 && g_instCalls == kCount, "every finished node gets exactly one install");
    std::vector<U> log = g_instLog; std::sort(log.begin(), log.end());
    Check(std::unique(log.begin(), log.end()) == log.end() && log.size() == kCount, "each rider is installed once, none twice");
    Check(g_terrainCalls == kCount && g_adjustCalls == kCount, "replacement work is one terrain query and one order query per install");
    staged = 0; Sweep();
    Check(staged <= kRenewBudget, "the renewal budget is unchanged by the command-layer decision");
    ResetNative(); staged = 0;
    sweepAll(0);
    Check(g_origCalls == 0 && g_instCalls == 0 && g_terrainCalls == 0, "the replaced squad is retained again");
    w.CloseEpoch();
}

// --- split-flow regressions: riders stream round BOTH sides of the square along a charge line frozen per order -------------------
// Charge line used throughout: own centre O=(0,-50), target centre T=(0,0), D=(0,50).  Approach side s = sign(Dx*(Mz-Oz) - Dz*(Mx-Ox))
// (so x=-5 is side "+", x=+5 side "-"); the native ComputeWaypoint direction is the NEGATIVE of the approach side.  Every expected
// waypoint below is computed from the pure policy with a LITERAL direction, never from the implementation's own lane helpers.
struct Flow {
    World w;
    std::vector<B> men;
    std::vector<U> members;
    explicit Flow(U count) : men(count * 0x700), members(count) {
        for (U i = 0; i < count; ++i) {
            members[i] = Address(men.data() + i * 0x700);
            Put(members[i] + 0x1f0, w.unit); Put(members[i] + 0x30, 1);
        }
        Put(w.unit + 0x2cc, count); Put(w.unit + 0x2d0, Address(members.data()));
    }
    void Place(U i, float x, float z) { Position(members[i], x, z); }
    // square of half-diagonal h*sqrt(2) centred on (cx, cz)
    void Target(float cx, float cz, float h) {
        Position(w.enemyArr[0], cx - h, cz - h); Position(w.enemyArr[1], cx + h, cz + h);
    }
    // left riders x=-5 (side +), then right riders x=+5 (side -), then flexible riders on the line (x=0); z spread about -50 so the
    // bounding-box centre stays O=(0,-50) for any population of at least three riders.
    void Layout(U left, U right, U flex) {
        U k = 0;
        auto z = [](U i) { return -50.0f + float(int(i % 3) - 1) * 0.5f; };
        for (U i = 0; i < left; ++i, ++k) Place(k, -5.0f, z(k));
        for (U i = 0; i < right; ++i, ++k) Place(k, 5.0f, z(k));
        for (U i = 0; i < flex; ++i, ++k) Place(k, 0.0f, z(k));
    }
};
double CrossAt(double ox, double oz, double dx, double dz, double x, double z) { return dx * (z - oz) - dz * (x - ox); }
bool PlanRider(Flow& f, U i, MovePlan& p) {
    B d[kDescBytes]; MoveDesc(d, 4.5f);
    p = {}; PlanMove(f.members[i], d, p);
    return p.mode == 1;
}
bool NearF(float a, float b, float tol) { return std::fabs(a - b) <= tol; }
float PolicyWp(float px, float pz, const UnitEntry& e, float radius, int direction, U mount, float& wz) {
    float wx = 0; wz = 0;
    Check(kntwr_cavalry_orbit::ComputeWaypoint(px, pz, e.tx, e.tz, radius, direction, mount, settings, wx, wz),
          "reference policy waypoint is computable");
    return wx;
}
void WiderSquareGap() {
    const U savedTerrain = terrainQuery;
    Flow f(2); settings.clearance_margin = kSquareGap;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    f.Target(0, 0, 3); f.Place(0, -5, -50); f.Place(1, 5, -50); f.w.Tick(1);
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit, "both perimeter streams fit with the requested wider gap");
    // Fixture square corners are (+/-3,+/-3); both loaded member radii are 0.5.
    const double requiredCentreDistance = std::sqrt(18.0) + 0.5 + 15.0 + 0.5;
    for (U i = 0; i < 2; ++i) {
        MovePlan p = {}; Check(PlanRider(f, i, p), "both wide-gap riders receive movement");
        const double x = i ? 5 : -5, z = -50;
        const double dx = RdDescF(p.desc, 0) - x, dz = RdDescF(p.desc, 8) - z;
        const double t = (std::max)(0.0, (std::min)(1.0, -(x * dx + z * dz) / (dx * dx + dz * dz)));
        Check(std::hypot(x + t * dx, z + t * dz) >= requiredCentreDistance,
              "the entire approach leg keeps fifteen units beyond square and horse extents");
        if (RecordOf(f.members[i])->lane1 == 1)
            Check(std::hypot(x + t * dx, z + t * dz) < requiredCentreDistance + 0.01,
                  "the inner stream uses the reduced gap rather than the previous twenty-unit gap");
    }
    const float cramped[] = {-22, -100, 22, 100};
    std::memcpy(reinterpret_cast<void*>(f.w.model + 0x84), cramped, sizeof(cramped));
    f.w.Tick(4);
    Check(!e->orbit && e->blockedSerial == 123,
          "wider clearance hands the whole order back when both streams no longer fit");
    Flow large(2); settings.clearance_margin = kSquareGap;
    large.Target(0, 0, 60); large.Place(0, -5, -200); large.Place(1, 5, -200); large.w.Tick(1);
    e = EntryByUnit(large.w.unit);
    Check(e && !e->orbit && e->blockedSerial == 123,
          "the fifteen-unit gap cannot bypass the hundred-unit outer limit");
    terrainQuery = savedTerrain;
}

// Learn the two-lane capacities of the fixture's minimal pair (side "+" = lane 1, side "-" = lane 2).
void PairCaps(U& cap0, U& cap1) {
    Flow f(2); f.Target(0, 0, 3); f.Place(0, -5, -50); f.Place(1, 5, -50); f.w.Tick(1);
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit, "minimal opposite-side pair orbits");
    const OrbitBand& b = unitBands[e - entries];
    Check(b.laneCount == 2 && b.capacity[0] >= 16 && b.capacity[1] >= 16, "a minimal pair builds exactly two lanes with real capacity");
    cap0 = b.capacity[0]; cap1 = b.capacity[1];
}

void SplitFlowOppositeSides() {
    for (int mirrored = 0; mirrored < 2; ++mirrored) {
        NativeGuard guard;
        Flow f(2); f.Target(0, 0, 3);
        const float x0 = mirrored ? 5.0f : -5.0f, x1 = -x0;
        f.Place(0, x0, -50); f.Place(1, x1, -50);
        f.w.Tick(1); f.w.OwnEpoch();
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && e->orbit, "opposite-side riders activate the charge");
        const OrbitBand& b = unitBands[e - entries];
        Check(b.laneCount == 2, "a two-rider charge builds one lane per side");
        Check(b.radius[1] - b.radius[0] >= 1.0f, "the two streams are separated by at least one member diameter");
        for (U i = 0; i < 2; ++i) {
            ResetNative();
            B d[kDescBytes]; MoveDesc(d, 4.5f);
            Move(f.members[i], d, &InstallProbe);  // the public 0x5DD450 seam
            Check(g_instCalls == 1 && g_instMount == f.members[i], "the native approach is replaced by exactly one install");
            const float sx = i ? x1 : x0, wx = RdDescF(g_instDesc, 0), wz = RdDescF(g_instDesc, 8);
            const bool plusSide = sx < 0;
            const double cr = CrossAt(0, -50, 0, 50, wx, wz);
            Check(plusSide ? cr > 0 : cr < 0, "each rider heads round the square on its OWN side");
            Record* r = RecordOf(f.members[i]);
            Check(r && r->lane1 && ((r->lane1 & 1) != 0) == plusSide, "odd lane = side +, even lane = side -");
            float ez; const float ex = PolicyWp(sx, -50, *e, b.radius[r->lane1 - 1], plusSide ? -1 : 1, f.members[i], ez);
            Check(NearF(wx, ex, 0.01f) && NearF(wz, ez, 0.01f), "the installed waypoint is the policy waypoint with the side's direction");
        }
    }
}

void SplitFlowAxisFrozen() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    Flow f(2); f.Target(0, 0, 3); f.Place(0, -5, -50); f.Place(1, 5, -50);
    f.w.Tick(1);
    MovePlan pa, pb;
    Check(PlanRider(f, 0, pa) && PlanRider(f, 1, pb), "both riders install");
    Record* ra = RecordOf(f.members[0]); Record* rb = RecordOf(f.members[1]);
    Check(ra && rb && (ra->lane1 & 1) && !(rb->lane1 & 1), "initial lanes follow the initial sides");
    const B laneA = ra->lane1, laneB = rb->lane1;
    // Move the square AND swap/relocate both riders so that a charge line recomputed from the new centres would flip both sides.
    f.Target(7, 12, 3); f.Place(0, 45, -10); f.Place(1, -33, -10);
    f.w.Tick(4);
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit && NearF(e->tx, 7, 0.01f) && NearF(e->tz, 12, 0.01f), "the moved square was observed by the refresh");
    ra = RecordOf(f.members[0]); rb = RecordOf(f.members[1]);
    Check(ra && rb && ra->lane1 == laneA && rb->lane1 == laneB, "centre movement never reassigns a rider's lane");
    const OrbitBand& band = unitBands[e - entries];
    float x, z, ez;
    Check(MountWaypoint(*ra, *e, x, z), "rider A still has a waypoint");
    float ex = PolicyWp(45, -10, *e, band.radius[laneA - 1], -1, f.members[0], ez);
    Check(NearF(x, ex, 0.01f) && NearF(z, ez, 0.01f), "rider A keeps direction -1 although it is now on the other side of the new line");
    float ox = PolicyWp(45, -10, *e, band.radius[laneA - 1], 1, f.members[0], ez);
    Check(std::hypot(ox - ex, ez - z) > 1.0f, "a recomputed axis would have produced a different waypoint (case is discriminating)");
    Check(MountWaypoint(*rb, *e, x, z), "rider B still has a waypoint");
    ex = PolicyWp(-33, -10, *e, band.radius[laneB - 1], 1, f.members[1], ez);
    Check(NearF(x, ex, 0.01f) && NearF(z, ez, 0.01f), "rider B keeps direction +1");
    terrainQuery = savedTerrain;
}

void SplitFlowStickyThroughProbeAndController() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    Flow f(4); f.Target(0, 0, 3);
    f.Place(0, -5, -50); f.Place(1, 5, -50); f.Place(2, -5, -49); f.Place(3, 5, -51);
    f.w.Tick(1);
    MovePlan p; B lanes[4];
    for (U i = 0; i < 4; ++i) { Check(PlanRider(f, i, p), "rider installs"); lanes[i] = RecordOf(f.members[i])->lane1; }
    Check((lanes[0] & 1) && !(lanes[1] & 1) && (lanes[2] & 1) && !(lanes[3] & 1), "two riders per side, parity per side");
    UnitEntry* e = EntryByUnit(f.w.unit);
    Record* probed = RecordOf(f.members[0]);
    probed->flags |= rProbe; probed->probeUntil = 3;
    ProbeAdd(probed->mount, U(probed - records));
    Put(f.members[2] + 0x628, 0x10000);   // temporary native controller on the other side-+ rider
    Put(f.members[3] + 0x30, 0);          // casualty on side -
    f.w.Tick(2); Sweep();
    Put(f.members[2] + 0x628, 0);
    f.w.Tick(3); Sweep();
    U restore = kStampEmpty;
    for (U i = 0; i < staged; ++i) if (stage[i].mount == f.members[0]) restore = i;
    Check(restore != kStampEmpty && !stage[restore].combat && StageValid(stage[restore]), "probe expiry stages a rider restore");
    const OrbitBand& band = unitBands[e - entries];
    float ez;
    const float ex = PolicyWp(-5, -50, *e, band.radius[lanes[0] - 1], -1, f.members[0], ez);
    Check(NearF(RdDescF(stage[restore].desc, 0), ex, 0.01f) && NearF(RdDescF(stage[restore].desc, 8), ez, 0.01f),
          "the restored rider resumes on its own side after probe expiry");
    Check(PlanRider(f, 0, p) && RecordOf(f.members[0])->lane1 == lanes[0], "rejoin keeps the lane");
    Check(NearF(RdDescF(p.desc, 0), ex, 0.01f) && NearF(RdDescF(p.desc, 8), ez, 0.01f), "rejoin waypoint keeps the side's direction");
    for (U i = 0; i < 3; ++i)
        Check(RecordOf(f.members[i]) && RecordOf(f.members[i])->lane1 == lanes[i],
              "probe, temporary controller and a casualty never move a surviving rider's side");
    terrainQuery = savedTerrain;
}

void SplitFlowReservesAllLiveMembers() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    U cap0, cap1; PairCaps(cap0, cap1);
    const U left = cap0 + 5, n = left + 1;  // side + overflows one lane; side - needs one rider
    Flow f(n); f.Target(0, 0, 3); f.Layout(left, 1, 0);
    f.w.Tick(1);
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit, "the unbalanced charge activates");
    const OrbitBand& band = unitBands[e - entries];
    Check(band.laneCount == 4, "capacity for ALL live members is reserved before any record exists (smallest even lane count)");
    MovePlan p;
    const U first[] = {0, 1, 2, left};  // only part of the unit has captured a descriptor so far
    for (U i : first) Check(PlanRider(f, i, p), "early capture installs");
    Check(band.laneCount == 4, "early captures do not rebuild the reservation");
    for (U i = 3; i < left; ++i) Check(PlanRider(f, i, p), "every later side-+ rider still finds capacity");
    U onLane[kMaxLanes] = {};
    for (U i = 0; i < n; ++i) {
        Record* r = RecordOf(f.members[i]);
        Check(r && r->lane1, "every rider holds a lane");
        Check(((r->lane1 & 1) != 0) == (i < left), "no rider crosses parity: side + owns odd lanes only");
        ++onLane[r->lane1 - 1];
    }
    Check(band.laneCount == 4, "late captures never grow or shrink the order's lanes");
    for (U k = 0; k < band.laneCount; ++k) Check(onLane[k] <= band.capacity[k], "no lane exceeds its chord capacity");
    Check(onLane[0] > 0 && onLane[2] > 0 && onLane[1] + onLane[3] == 1, "side + overflowed into its second lane; side - holds the single rider");
    terrainQuery = savedTerrain;
}

void SplitFlowFlexibleRidersCannotStarveFixedSide() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    U cap0, cap1; PairCaps(cap0, cap1);
    const U fixedLeft = cap0, flex = 5, n = fixedLeft + 1 + flex;
    Flow f(n); f.Target(0, 0, 3); f.Layout(fixedLeft, 1, flex);
    f.w.Tick(1);
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit, "the charge activates");
    const OrbitBand& band = unitBands[e - entries];
    Check(band.laneCount == 2, "fixed demand plus flexible total fits the smallest pair");
    MovePlan p;
    for (U i = fixedLeft + 1; i < n; ++i) Check(PlanRider(f, i, p), "flexible rider installs first");
    for (U i = 0; i <= fixedLeft; ++i) Check(PlanRider(f, i, p), "every fixed-side rider still finds its reserved slot");
    Check(band.laneCount == 2, "flexible riders did not force a lane pair");
    for (U i = 0; i < fixedLeft; ++i) Check(RecordOf(f.members[i])->lane1 == 1, "fixed side + stays on its only odd lane");
    Check(RecordOf(f.members[fixedLeft])->lane1 == 2, "the fixed side - rider stays on the even lane");
    for (U i = fixedLeft + 1; i < n; ++i) {
        const B l = RecordOf(f.members[i])->lane1;
        Check(l == 1 || l == 2, "flexible rider takes spare capacity");
    }
    for (U k = 0; k < 2; ++k) Check(band.fill[k] <= band.capacity[k], "no lane over capacity");
    terrainQuery = savedTerrain;
}

void SplitFlowOuterEnvelopeHandsBackWholeOrder() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    // half-diagonal 86: lane-1 envelope is about 95 (a single stream would fit) but the mandatory second lane is about 102 > 100.
    const float huge = 60.81f;
    {   // refused at acquisition
        Flow f(2); f.Target(0, 0, huge); f.Place(0, -5, -250); f.Place(1, 5, -250);
        f.w.Tick(1);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && !e->orbit && e->blockedSerial == 123 && e->blockedTarget == f.w.target,
              "a pair that cannot fit inside 100 units blocks the order instead of using one stream");
        MovePlan p; B d[kDescBytes]; MoveDesc(d, 4.5f);
        PlanMove(f.members[0], d, p);
        Check(p.mode == 0, "the rider keeps the native approach");
        Record* r = RecordOf(f.members[0]);
        Check(!r || r->lane1 == 0, "no lane is ever assigned for a refused order");
    }
    {   // a live orbit whose target grows beyond the cap: the WHOLE order returns to native
        Flow f(2); f.Target(0, 0, 3); f.Place(0, -5, -250); f.Place(1, 5, -250);
        f.w.Tick(1);
        MovePlan p;
        Check(PlanRider(f, 0, p) && PlanRider(f, 1, p), "both riders orbit first");
        B snap[2][kDescBytes];
        for (U i = 0; i < 2; ++i) std::memcpy(snap[i], RecordOf(f.members[i])->desc, kDescBytes);
        f.Target(0, 0, huge);
        f.w.Tick(4);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && !e->orbit && e->blockedSerial == 123, "outer envelope beyond 100 blocks the order");
        Check(staged == 2, "every rider of the unit is handed back, none left orbiting");
        for (U i = 0; i < staged; ++i) {
            Check(!stage[i].combat && StageValid(stage[i]), "handback is a valid native restore");
            const U k = stage[i].mount == f.members[0] ? 0 : 1;
            Check(stage[i].mount == f.members[k] && std::memcmp(stage[i].desc, snap[k], kDescBytes) == 0,
                  "each rider gets its captured native descriptor byte-exact");
        }
        Check(!RecordOf(f.members[0]) && !RecordOf(f.members[1]), "no record keeps an orbit lane");
        f.w.Tick(5);
        Check(!e->orbit, "the same blocked order stays native");
        B d[kDescBytes]; MoveDesc(d, 4.5f);
        PlanMove(f.members[0], d, p);
        Check(p.mode == 0, "later native moves of the blocked order pass through");
        f.Target(0, 0, 3); Put(f.w.unit + 0x39c, 124); f.w.Tick(8);
        Check(e->orbit, "a new order can acquire again once the charge fits");
    }
    terrainQuery = savedTerrain;
}

void SplitFlowSmallGroupNotForcedToHundred() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    {   // four riders: still exactly one pair of lanes, close to the square
        Flow f(4); f.Target(0, 0, 3); f.Layout(2, 2, 0);
        f.w.Tick(1);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && e->orbit, "a small group charges");
        Check(unitBands[e - entries].laneCount == 2, "a small group uses the minimum pair of lanes");
        MovePlan p;
        for (U i = 0; i < 4; ++i) {
            Check(PlanRider(f, i, p), "small-group rider installs");
            Check(std::hypot(RdDescF(p.desc, 0) - e->tx, RdDescF(p.desc, 8) - e->tz) < 20.0f,
                  "the radius is not inflated towards the 100-unit limit");
        }
    }
    {   // a larger square whose pair still fits: every waypoint stays within 100 of its centre
        Flow f(4); f.Target(0, 0, 49.5f); f.Layout(2, 2, 0);
        f.w.Tick(1);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && e->orbit, "a pair that fits under the cap is accepted");
        MovePlan p;
        for (U i = 0; i < 4; ++i) {
            Check(PlanRider(f, i, p), "rider installs");
            const float r = std::hypot(RdDescF(p.desc, 0) - e->tx, RdDescF(p.desc, 8) - e->tz);
            Check(r > 70.0f && r < 100.0f, "outer waypoint stays inside the 100-unit envelope");
        }
    }
    terrainQuery = savedTerrain;
}

// Same square centre, same mounts: only the lane radius changes (the square grows).  The installed goal must be refreshed from the
// REAL prior installed radius.  Expected radii are derived by hand: square half-diagonal h*sqrt(2), target radius = that + 0.5
// (fixture member radius), lane-1 radius = target radius + member radius 0.5 + clearance margin 2 = h*sqrt(2) + 3.
void SplitFlowLaneRadiusChangeRenews() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    Flow f(2); f.Target(0, 0, 3); f.Place(0, -5, -50); f.Place(1, 5, -50);
    f.w.Tick(1);
    MovePlan pa, pb;
    Check(PlanRider(f, 0, pa) && PlanRider(f, 1, pb), "both riders install");
    UnitEntry* e = EntryByUnit(f.w.unit);
    Check(e && e->orbit, "the charge orbits");
    const OrbitBand& band = unitBands[e - entries];
    const float r0 = 3.0f * 1.41421356f + 3.0f;
    Check(band.laneCount == 2 && NearF(band.radius[0], r0, 0.01f), "installed lane-1 radius matches the hand-derived 7.24");
    const B laneA = RecordOf(f.members[0])->lane1, laneB = RecordOf(f.members[1])->lane1;
    const float oldA = std::hypot(RdDescF(pa.desc, 0) - e->tx, RdDescF(pa.desc, 8) - e->tz);
    f.w.Tick(11); Sweep();
    Check(staged == 0, "control: after the minimum interval, an unchanged radius stages no renewal");
    f.Target(0, 0, 10);   // same centre; lane-1 radius grows to 10*sqrt(2)+3 = 17.14 (> 6 m drift tolerance)
    f.w.Tick(14); Sweep();
    Check(e->orbit && NearF(e->tx, 0, 0.01f) && NearF(e->tz, 0, 0.01f), "the square centre did not move");
    const float r1 = 10.0f * 1.41421356f + 3.0f;
    Check(band.laneCount == 2 && NearF(band.radius[0], r1, 0.01f), "the band was rebuilt for the larger square");
    Check(staged == 2 && staged <= 16, "both riders are renewed inside the 16-install budget");
    for (U s = 0; s < staged; ++s) {
        const bool isA = stage[s].mount == f.members[0];
        Check(isA || stage[s].mount == f.members[1], "renewal stages one of the unit's riders");
        Check(!stage[s].combat && stage[s].orbit == 1 && StageValid(stage[s]), "the renewal is a valid normalized orbit goal");
        Record* r = RecordOf(stage[s].mount);
        Check(r && r->lane1 == (isA ? laneA : laneB) && ((r->lane1 & 1) != 0) == isA, "the rider keeps its lane and parity");
        float ez;
        const float ex = PolicyWp(isA ? -5.0f : 5.0f, -50, *e, band.radius[r->lane1 - 1], isA ? -1 : 1, stage[s].mount, ez);
        Check(NearF(RdDescF(stage[s].desc, 0), ex, 0.01f) && NearF(RdDescF(stage[s].desc, 8), ez, 0.01f),
              "the renewed waypoint lies on the NEW lane radius with the side's direction");
        if (isA) {
            const float newA = std::hypot(RdDescF(stage[s].desc, 0) - e->tx, RdDescF(stage[s].desc, 8) - e->tz);
            Check(newA > oldA + 2.0f, "the goal moved outward by the radius growth, not merely re-emitted");
        }
    }
    terrainQuery = savedTerrain;
}

// Classification may change between the census and a rider's FIRST capture (riders keep moving).  Each rider keeps the side the
// census reserved for it; a late crossing never steals another rider's reserved slot and never causes a whole-order handback.
void SplitFlowReservationSurvivesClassificationChange() {
    const U savedTerrain = terrainQuery;
    terrainQuery = Address(reinterpret_cast<void*>(&FlatTerrain));
    U cap0, cap1; PairCaps(cap0, cap1);
    {   // fixed side + rider crosses to side - after the census while side - is exactly full
        const U left = 3, n = left + cap1;
        Flow f(n); f.Target(0, 0, 3); f.Layout(left, cap1, 0);
        f.w.Tick(1);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && e->orbit, "the charge activates");
        const OrbitBand& band = unitBands[e - entries];
        Check(band.laneCount == 2, "one pair is enough");
        f.Place(0, 5.0f, -50.5f);   // crosses the charge line before any capture or refresh
        MovePlan p;
        for (U i = left; i < n; ++i) Check(PlanRider(f, i, p), "side - riders fill their lane first");
        for (U i = 0; i < left; ++i) Check(PlanRider(f, i, p), "every side + rider incl. the crosser still installs");
        Check(e->orbit && e->blockedSerial == 0, "no whole-order handback");
        Check(band.laneCount == 2, "the crossing did not grow the order");
        Check(RecordOf(f.members[0])->lane1 == 1, "the crosser keeps its census side +");
        for (U i = 1; i < left; ++i) Check(RecordOf(f.members[i])->lane1 == 1, "side + riders stay on the odd lane");
        for (U i = left; i < n; ++i) Check(RecordOf(f.members[i])->lane1 == 2, "side - riders stay on the even lane");
        for (U k = 0; k < 2; ++k) Check(band.fill[k] <= band.capacity[k], "no lane exceeds its chord capacity");
    }
    {   // flexible rider drifts onto side + after the census and captures first
        const U fixedLeft = cap0, flex = 3, n = fixedLeft + 1 + flex;
        Flow f(n); f.Target(0, 0, 3); f.Layout(fixedLeft, 1, flex);
        f.w.Tick(1);
        UnitEntry* e = EntryByUnit(f.w.unit);
        Check(e && e->orbit, "the charge activates");
        const OrbitBand& band = unitBands[e - entries];
        Check(band.laneCount == 2, "one pair is enough");
        const U mover = fixedLeft + 1;
        f.Place(mover, -5.0f, -50.0f);   // flexible at the census, now clearly on side +
        MovePlan p;
        Check(PlanRider(f, mover, p), "the moved flexible rider captures first");
        for (U i = 0; i < fixedLeft; ++i) Check(PlanRider(f, i, p), "every fixed side + rider still finds its reserved slot");
        Check(PlanRider(f, fixedLeft, p), "the fixed side - rider installs");
        for (U i = mover + 1; i < n; ++i) Check(PlanRider(f, i, p), "remaining flexible riders install");
        Check(e->orbit && e->blockedSerial == 0 && band.laneCount == 2, "no handback and no growth");
        for (U i = 0; i < fixedLeft; ++i) Check(RecordOf(f.members[i])->lane1 == 1, "fixed side + riders keep lane 1");
        Check(RecordOf(f.members[mover])->lane1 == 2, "the formerly flexible rider took spare capacity on the other side, not a reserved slot");
        for (U k = 0; k < 2; ++k) Check(band.fill[k] <= band.capacity[k], "no lane exceeds its chord capacity");
    }
    terrainQuery = savedTerrain;
}

}
int main() {
    SplitFlowOppositeSides(); SplitFlowAxisFrozen(); SplitFlowStickyThroughProbeAndController();
    SplitFlowReservesAllLiveMembers(); SplitFlowFlexibleRidersCannotStarveFixedSide();
    SplitFlowOuterEnvelopeHandsBackWholeOrder(); SplitFlowSmallGroupNotForcedToHundred();
    SplitFlowLaneRadiusChangeRenews(); SplitFlowReservationSurvivesClassificationChange();
    EligibilityAndGeometry(); DeathAndOrderPrecedence(); CollisionAndRiderIdentity();
    TargetCenteredRiderOrbit();
    RenewalFairness();
    NativeHandbackPrecedence(); BoundaryHandback();
    SquareActivationTransitions();
    ArmedLifecycle();
    TemporaryControllerOwnership(); FirstCaptureDuringTemporaryOwnership();
    MultiRowOrbit(); MultiRowBoundaryHandback();
    NormalizeOrbitSeam(); MovementTimingNormalization(); InvalidSpeedKeepsNative();
    OrbitMovementDoesNotInheritChargeStance();
    WiderSquareGap();
    CombatNormalization(); RenewalNormalization();
    ProbeRejoinNormalization(); HandbackKeepsNativeBytes();
    FramePointerClearKeepsHandback();
    RetainedAcrossNormalCompletion(); RetainedFlushCancels();
    RetainedNewRowCancelsAndRecaptures(); RetainedRetargetCancels();
    RetainedAppendDoesNotRetain(); RetainedWrongDestructorReturnDeclines();
    RetainedDeathAndRoutCancel(); RetainedIdentityNotInherited();
    RetainedMalformedRowIgnored(); RetainedNeverReadsFreedRow();
    KeepActiveOrbit(); ReplaceUnusableNode(); NativeApproachNeverKept(); ForeignOrderVoidsAuthority();
    HandbackMatrix(); UnknownCallers(); SweptInstallStampsAuthority(); SquadWorkIsBounded();
    std::puts("PASS: cavalry adapter eligibility, geometry, lifecycle precedence, keyed ownership, "
              "descriptor normalization, retained attack intent, and command-layer orbit ownership");
    return 0;
}
