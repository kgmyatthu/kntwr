// RelinkApply oracle cases (MovementSlices Contract 3), included by native_loco_oracle.cpp after the shared helpers.
//
// Mapped-image bit-identity: a fixture with the real 0x620AD0 grid-header shape (heads / shift / rows / origin / clamp /
// scale), real 0x28 -> +8 -> +A4 receiver chains and arena nodes (type 8, serial, +30 payload, owner) is driven by one
// script of (pose write | unlink | insert | barrier | untapped native) operations twice from the same initial bytes:
//   serial: the mapped original 0x811ED0 / 0x7EFA80 called in log order;
//   log   : ExtractMoveOp for the same occurrences, batches closed at the barriers, applied by RelinkApplyLive.
// The final head array, every node word and every record byte (+AC included) must be memcmp-identical.
#pragma once
#include "native_move_delta.h"
#include "native_relink.h"
#include <random>
#include <chrono>

namespace relinkcase {
using kntwr_loco::MoveLog; using kntwr_loco::MoveOpKind; using kntwr_loco::ExtractResult;

// ---------------------------------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------------------------------
struct Fixture {
    U shift, maximum, cap, count, recSize;
    std::vector<U> heads;
    alignas(16) B header[0x40]{}; B ctx[0x20]{}; B model[0xC0]{};
    std::vector<B> arena, recs;
    Fixture(U shift_, U maximum_, U count_, U cap_, U recSize_ = 0x100, float scale = 1.0f, U origin = 0)
        : shift(shift_), maximum(maximum_), cap(cap_), count(count_), recSize(recSize_),
          heads(((maximum_ + 1) << shift_) + 1), arena(size_t(count_) * cap_ * 0x1c), recs(size_t(count_) * recSize_) {
        Put<U>(header, 0, A(heads.data())); Put<U>(header, 4, (maximum + 1) << shift); Put<U>(header, 8, shift);
        Put<U>(header, 0xc, maximum + 1); Put<U>(header, 0x10, origin); Put<U>(header, 0x14, maximum); Put<float>(header, 0x24, scale);
        Put<U>(model, 0xa4, A(header)); Put<U>(ctx, 8, A(model));
        for (U i = 0; i < count; ++i) {
            B* r = Rec(i);
            Put<U>(r, 0x28, A(ctx)); Put<U>(r, 0x2c, 0x1000u + i);
            Put<U>(r, 0xa8, A(arena.data() + size_t(i) * cap * 0x1c)); Put<U>(r, 0xac, 0); Put<U>(r, 0xb0, cap);
            Put<float>(r, 0x58, 0.25f);
            for (U n = 0; n < cap; ++n) {
                B* node = arena.data() + (size_t(i) * cap + n) * 0x1c;
                Put<U>(node, 0, 8); Put<U>(node, 4, 0x1000u + i); Put<U>(node, 8, A(r) + 0x30); Put<U>(node, 0xc, A(r));
            }
        }
    }
    Fixture(const Fixture&) = delete;
    B* Rec(U i) { return recs.data() + size_t(i) * recSize; }
    const B* Rec(U i) const { return recs.data() + size_t(i) * recSize; }
    U Va(U i) { return A(Rec(i)); }
    void Pose(U i, float x, float z, float r, B bump) {
        B* p = Rec(i); Put<float>(p, 0x48, x); Put<float>(p, 0x4c, 0.0f); Put<float>(p, 0x50, z); Put<float>(p, 0x58, r); Put<B>(p, 0x5c, bump);
    }
};
struct State { std::vector<U> heads; std::vector<B> arena, recs; };
static State Save(const Fixture& f) { return {f.heads, f.arena, f.recs}; }
static void Restore(Fixture& f, const State& s) {
    std::memcpy(f.heads.data(), s.heads.data(), s.heads.size() * 4);
    std::memcpy(f.arena.data(), s.arena.data(), s.arena.size()); std::memcpy(f.recs.data(), s.recs.data(), s.recs.size());
}
// memcmp of the head array, every node word and every record byte, with a precise location on failure.
static void SameState(const Fixture& f, const State& s, const char* what) {
    ++checks;
    if (std::memcmp(f.heads.data(), s.heads.data(), s.heads.size() * 4)) {
        U i = 0; while (f.heads[i] == s.heads[i]) ++i;
        Fail("%s: head array differs at cell %u (row %u col %u)", what, i, i >> f.shift, i & ((1u << f.shift) - 1));
    }
    if (std::memcmp(f.arena.data(), s.arena.data(), s.arena.size())) {
        size_t i = 0; while (f.arena[i] == s.arena[i]) ++i;
        const size_t node = i / 0x1c;
        Fail("%s: node words differ at record %zu node %zu +%zX", what, node / f.cap, node % f.cap, i % 0x1c);
    }
    if (std::memcmp(f.recs.data(), s.recs.data(), s.recs.size())) {
        size_t i = 0; while (f.recs[i] == s.recs[i]) ++i;
        Fail("%s: record bytes differ at record %zu +%zX (%02X vs %02X)", what, i / f.recSize, i % f.recSize, f.recs[i], s.recs[i]);
    }
}
static void NativeCall(U record, bool insert) {
    CallEntry(A(At(insert ? 0x7efa80 : 0x811ed0)), reinterpret_cast<void*>(record), insert ? "native insert" : "native unlink");
}

// ---------------------------------------------------------------------------------------------------------------------
// Scripts
// ---------------------------------------------------------------------------------------------------------------------
enum Kind : U { OpPose, OpUnlink, OpInsert, OpBarrier, OpNativeUnlink, OpNativeInsert, OpHiddenUnlink, OpHiddenInsert, OpPokeCount };
struct Op { Kind kind; U rec; float x, z, r; B bump; };
using Script = std::vector<Op>;
static void MoveRec(Script& s, U rec, float x, float z, float r, B bump = 0) {
    s.push_back({OpPose, rec, x, z, r, bump}); s.push_back({OpUnlink, rec, 0, 0, 0, 0}); s.push_back({OpInsert, rec, 0, 0, 0, 0});
}
static void Plain(Script& s, Kind k, U rec) { s.push_back({k, rec, 0, 0, 0, 0}); }

struct Cfg {
    U records = 0, memberships = 0, perBatch = 4096, minCells = 1, lanes = 1;
    bool shadow = false, reversed = false, concurrent = false;
    U rounding = 0;
};
struct Counts {
    U logged = 0, noop = 0, batchFull = 0, serial = 0, flushes = 0, dispatches = 0, partitions = 0, anomalies = 0, faults = 0, collapsed = 0;
    U parallelBatches = 0;
    kntwr_loco::RelinkShadowResult shadow{};
};
static bool tdReverse, tdConcurrent; static U tdLanes = 1, tdDispatches;
struct TdJob { U body; void* context; U chunks; volatile LONG next; bool reversed; };
static DWORD WINAPI TdThread(void* p) {
    TdJob& j = *static_cast<TdJob*>(p);
    for (;;) {
        const U t = static_cast<U>(InterlockedIncrement(&j.next) - 1);
        if (t >= j.chunks) return 0;
        reinterpret_cast<void(__fastcall*)(void*, U)>(j.body)(j.context, j.reversed ? j.chunks - 1 - t : t);
    }
}
static void __stdcall TestDispatch(U pool, U body, U chunks, void* context) {
    EqU("relink dispatcher receives its pool", pool, 0x5e11c0u);
    Require(body && context && chunks, "relink dispatcher receives a body, context and chunks");
    ++tdDispatches;
    TdJob job{body, context, chunks, 0, tdReverse};
    const U threads = tdConcurrent ? std::min(tdLanes, chunks) : 1u;
    if (threads <= 1) { TdThread(&job); return; }
    std::vector<HANDLE> h(threads);
    for (U i = 0; i < threads; ++i) { h[i] = CreateThread(nullptr, 0, &TdThread, &job, 0, nullptr); Require(h[i] != nullptr, "relink dispatch thread"); }
    Require(WaitForMultipleObjects(threads, h.data(), TRUE, INFINITE) == WAIT_OBJECT_0, "relink dispatch threads join");
    for (HANDLE x : h) CloseHandle(x);
}
static void FpFor(U rounding) { SetOwnerFp(rounding, 2, false); }

static void RunNative(Fixture& f, const Script& s, U rounding) {
    FpFor(rounding);
    for (const Op& op : s) {
        switch (op.kind) {
        case OpPose: f.Pose(op.rec, op.x, op.z, op.r, op.bump); break;
        case OpUnlink: case OpNativeUnlink: case OpHiddenUnlink: NativeCall(f.Va(op.rec), false); break;
        case OpInsert: case OpNativeInsert: case OpHiddenInsert: NativeCall(f.Va(op.rec), true); break;
        case OpPokeCount: Put<U>(f.Rec(op.rec), 0xac, Get<U>(f.Rec(op.rec), 0xac) + 1); break;
        case OpBarrier: break;
        }
    }
    ResetFp();
}
// The log side. Returns the batch statistics; `mirrorCapacity` is the shadow mirror's word capacity.
static Counts RunLog(Fixture& f, const Script& s, const Cfg& c, U mirrorWords = 1u << 18) {
    using namespace kntwr_loco;
    Counts n{};
    MoveLog log{};
    Require(MoveLogInit(log, c.records ? c.records : f.count, c.memberships ? c.memberships : f.count * f.cap, c.perBatch, A(At(0x1318038))),
        "move log allocates");
    MoveLogBeginStage(log, 7);
    RelinkMirror mirror{};
    if (c.shadow) { Require(RelinkMirrorInit(mirror, mirrorWords), "mirror allocates"); RelinkMirrorReset(mirror, log); }
    tdReverse = c.reversed; tdConcurrent = c.concurrent; tdLanes = c.lanes; tdDispatches = 0;
    RelinkDispatcher disp{&TestDispatch, 0x5e11c0u, c.lanes - 1};
    RelinkApplyStats stats{};
    const auto flush = [&] {
        if (!MoveLogBatchOps(log)) return;
        ++n.flushes;
        if (c.shadow) {
            const bool parallel = RelinkMirrorApply(mirror, log, c.lanes > 1 ? &disp : nullptr, c.minCells, stats, n.shadow);
            n.parallelBatches += parallel; RelinkMirrorReset(mirror, log);
        } else n.parallelBatches += RelinkApplyLive(log, c.lanes > 1 ? &disp : nullptr, c.minCells, stats);
        MoveLogCloseBatch(log);
    };
    FpFor(c.rounding);
    U ordinal = 0;
    for (const Op& op : s) {
        ++ordinal;
        switch (op.kind) {
        case OpPose: f.Pose(op.rec, op.x, op.z, op.r, op.bump); break;
        case OpBarrier: flush(); break;
        case OpNativeUnlink: flush(); NativeCall(f.Va(op.rec), false); break;
        case OpNativeInsert: flush(); NativeCall(f.Va(op.rec), true); break;
        case OpHiddenUnlink: NativeCall(f.Va(op.rec), false); break;
        case OpHiddenInsert: NativeCall(f.Va(op.rec), true); break;
        case OpPokeCount: Put<U>(f.Rec(op.rec), 0xac, Get<U>(f.Rec(op.rec), 0xac) + 1); break;
        case OpUnlink: case OpInsert: {
            const MoveOpKind kind = op.kind == OpUnlink ? kntwr_loco::MoveUnlinkGrid : kntwr_loco::MoveInsertGrid;
            const bool insert = op.kind == OpInsert;
            ExtractResult r = ExtractMoveOp(log, f.Va(op.rec), ordinal, kind, kntwr_loco::MoveFromWorker, !c.shadow);
            if (r == kntwr_loco::ExtractBatchFull) {
                ++n.batchFull; flush();
                r = ExtractMoveOp(log, f.Va(op.rec), ordinal, kind, kntwr_loco::MoveFromWorker, !c.shadow);
                Require(r != kntwr_loco::ExtractBatchFull, "an empty batch always has record-table room");
            }
            if (r == kntwr_loco::ExtractLogged) {
                ++n.logged;
                if (c.shadow) { RelinkMirrorTouch(mirror, log, log.count - 1); NativeCall(f.Va(op.rec), insert); }
            } else if (r == kntwr_loco::ExtractNoop) {
                ++n.noop; if (c.shadow) NativeCall(f.Va(op.rec), insert);
            } else { ++n.serial; flush(); NativeCall(f.Va(op.rec), insert); }
            break;
        }
        }
    }
    flush();
    ResetFp();
    n.collapsed = log.collapsed; n.dispatches = stats.dispatches; n.partitions = stats.partitions;
    n.anomalies = stats.anomalies; n.faults = stats.faults;
    if (c.shadow) RelinkMirrorFree(mirror);
    MoveLogFree(log);
    return n;
}

// ---------------------------------------------------------------------------------------------------------------------
// Differential driver
// ---------------------------------------------------------------------------------------------------------------------
// Both executions start from the same bytes under the same owner FP controls; initial chains come from the native service.
static void Populate(Fixture& f, std::mt19937& rng, float lo, float hi, float radiusLo, float radiusHi) {
    ResetFp();
    std::uniform_real_distribution<float> p(lo, hi), r(radiusLo, radiusHi);
    for (U i = 0; i < f.count; ++i) { f.Pose(i, p(rng), p(rng), r(rng), 0); NativeCall(f.Va(i), true); }
}
struct Reference { std::vector<State> byRounding; State start; };
static Reference MakeReference(Fixture& f, const Script& s) {
    Reference ref; ref.start = Save(f);
    for (U rounding = 0; rounding < 4; ++rounding) {
        Restore(f, ref.start); RunNative(f, s, rounding); ref.byRounding.push_back(Save(f));
    }
    Restore(f, ref.start);
    return ref;
}
static Counts RunAndCompare(Fixture& f, const Script& s, const Reference& ref, const Cfg& c, const char* what, U mirrorWords = 1u << 18) {
    Restore(f, ref.start);
    const Counts n = RunLog(f, s, c, mirrorWords);
    SameState(f, ref.byRounding[c.rounding], what);
    EqU("kernels see no broken chain invariant", n.anomalies, 0);
    EqU("kernels take no fault", n.faults, 0);
    if (!c.shadow && c.minCells == 1 && c.lanes > 1 && n.logged) Require(n.parallelBatches != 0 && n.dispatches == 2 * n.parallelBatches, "pool batches use exactly two dispatches");
    if (!c.shadow && (c.lanes == 1 || c.minCells > 1000000)) EqU("serial batches dispatch nothing", n.dispatches, 0);
    return n;
}
// One script across rounding modes, participants and dispatch orders, live and shadow.
static void Sweep(Fixture& f, const Script& s, const char* name, U records = 0, U memberships = 0, U perBatch = 4096, bool expectBatchFull = false,
                  bool expectSerial = false) {
    static char label[160];
    currentCase = name;
    const Reference ref = MakeReference(f, s);
    Counts last{};
    for (U rounding = 0; rounding < 4; ++rounding) {
        Cfg c; c.rounding = rounding; c.lanes = 4; c.concurrent = true; c.records = records; c.memberships = memberships; c.perBatch = perBatch;
        std::snprintf(label, sizeof(label), "%s rounding=%u", name, rounding); last = RunAndCompare(f, s, ref, c, label);
    }
    for (U lanes : {1u, 2u, 4u, 8u}) for (int order = 0; order < 3; ++order) for (U minCells : {1u, 64u, 1u << 30}) {
        Cfg c; c.lanes = lanes; c.reversed = order == 1; c.concurrent = order == 2 && lanes > 1; c.minCells = minCells;
        c.records = records; c.memberships = memberships; c.perBatch = perBatch;
        std::snprintf(label, sizeof(label), "%s lanes=%u order=%d min=%u", name, lanes, order, minCells);
        last = RunAndCompare(f, s, ref, c, label);
    }
    if (expectBatchFull) Require(last.batchFull != 0, "record-table capacity closed a batch");
    if (expectSerial) Require(last.serial != 0, "log capacity forced a serial native fallback");
    // Shadow: native applies serially, the mirror kernel must reproduce it with zero mismatches.
    for (U lanes : {1u, 4u}) for (U rounding : {0u, 3u}) {
        Cfg c; c.shadow = true; c.lanes = lanes; c.concurrent = lanes > 1; c.rounding = rounding; c.minCells = 1;
        c.records = records; c.memberships = memberships; c.perBatch = perBatch;
        std::snprintf(label, sizeof(label), "%s shadow lanes=%u rounding=%u", name, lanes, rounding);
        const Counts n = RunAndCompare(f, s, ref, c, label);
        EqU("shadow finds no cell mismatch", n.shadow.mismatchCells, 0);
        EqU("shadow finds no node mismatch", n.shadow.mismatchNodes, 0);
        EqU("shadow verified every batch", n.shadow.refused, 0);
    }
    ++cases;
}

static std::vector<U> Shuffled(U n, std::mt19937& rng) { std::vector<U> v(n); for (U i = 0; i < n; ++i) v[i] = i; std::shuffle(v.begin(), v.end(), rng); return v; }

static void KernelCases(U shift, U maximum, U count) {
    static char name[96];
    std::mt19937 rng(0x5eed0000u + shift * 131 + maximum);
    const float hi = float(maximum) - 3.0f;
    std::uniform_real_distribution<float> any(3.0f, hi), small(0.05f, 0.9f), big(0.5f, 2.6f);
    const auto fixture = [&](U cap, float radiusLo, float radiusHi) {
        auto f = std::make_unique<Fixture>(shift, maximum, count, cap);
        { std::mt19937 populate(77 + shift); Populate(*f, populate, 3.0f, hi, radiusLo, radiusHi); }
        return f;
    };
    {   // plain movers, shuffled
        auto f = fixture(12, 0.05f, 0.9f); Script s;
        for (U i : Shuffled(count, rng)) MoveRec(s, i, any(rng), any(rng), small(rng));
        std::snprintf(name, sizeof(name), "relink movers %ux%u", maximum + 1, maximum + 1); Sweep(*f, s, name);
    }
    {   // duplicate occurrences: the same record moves 2-4 times, interleaved, plus unlink/insert/unlink/insert
        auto f = fixture(12, 0.05f, 0.9f); Script s;
        for (U round = 0; round < 3; ++round)
            for (U i : Shuffled(count, rng)) if (round == 0 || (rng() & 1)) MoveRec(s, i, any(rng), any(rng), small(rng));
        Sweep(*f, s, "relink duplicate occurrences");
    }
    {   // insert before unlink, insert without unlink (+AC != 0: append at nodeBase), unlink of nothing, double unlink
        auto f = fixture(40, 0.05f, 0.45f); Script s;
        for (U i : Shuffled(count, rng)) {
            switch (rng() % 6) {
            case 0: Plain(s, OpInsert, i); Plain(s, OpUnlink, i); break;                       // append then remove
            case 1: Plain(s, OpInsert, i); s.push_back({OpPose, i, any(rng), any(rng), 0.3f, 0}); Plain(s, OpInsert, i); break; // two appends
            case 2: Plain(s, OpUnlink, i); Plain(s, OpUnlink, i); Plain(s, OpInsert, i); break;
            case 3: Plain(s, OpInsert, i); Plain(s, OpInsert, i); Plain(s, OpUnlink, i); Plain(s, OpInsert, i); break;
            case 4: Plain(s, OpUnlink, i); s.push_back({OpPose, i, any(rng), any(rng), 0.4f, 0}); Plain(s, OpInsert, i); Plain(s, OpUnlink, i); break;
            default: MoveRec(s, i, any(rng), any(rng), small(rng)); break;
            }
        }
        Sweep(*f, s, "relink insert-before-unlink and insert without unlink");
    }
    {   // multi-row, cross-strip footprints and long jumps across every partition window
        auto f = fixture(64, 0.5f, 2.6f); Script s;
        for (U i : Shuffled(count, rng)) MoveRec(s, i, any(rng), (rng() & 1) ? 3.5f + float(rng() % 3) : hi - float(rng() % 3), big(rng));
        for (U i : Shuffled(count, rng)) MoveRec(s, i, (rng() & 1) ? 3.5f : hi, any(rng), big(rng));
        Sweep(*f, s, "relink cross-strip multi-row footprints");
    }
    {   // same-cell churn: every record lands in one or two cells, repeatedly
        auto f = fixture(8, 0.05f, 0.2f); Script s;
        const float cx = float(maximum) * 0.5f;
        for (U round = 0; round < 4; ++round)
            for (U i : Shuffled(count, rng)) MoveRec(s, i, cx + float(rng() % 2) * 0.01f, cx + float(rng() % 2), 0.1f);
        Sweep(*f, s, "relink same-cell churn");
    }
    {   // clamp edges: negative coordinates wrap and clamp, inverted rectangles insert nothing
        auto f = fixture(30, 0.05f, 0.9f); Script s;
        const float edges[] = {-3.0f, -0.6f, -0.01f, 0.0f, 0.49f, 0.5f, 1.5f, float(maximum) - 1.5f, float(maximum) - 0.5f, float(maximum),
                               float(maximum) + 0.4f, float(maximum) + 3.0f};
        for (U i : Shuffled(count, rng)) MoveRec(s, i, edges[rng() % 12], edges[rng() % 12], (rng() & 1) ? 0.3f : 0.7f, B(rng() & 1));
        Sweep(*f, s, "relink clamp edges");
    }
    {   // +5C bump byte adds 0.5 to the radius
        auto f = fixture(30, 0.05f, 0.9f); Script s;
        for (U i : Shuffled(count, rng)) MoveRec(s, i, any(rng), any(rng), small(rng), B(rng() % 3 == 0 ? 1 : (rng() % 5 == 0 ? 2 : 0)));
        Sweep(*f, s, "relink +5C bump");
    }
    {   // untapped native writers and barriers between logged occurrences (flush-before semantics)
        auto f = fixture(12, 0.05f, 0.9f); Script s;
        for (U i : Shuffled(count, rng)) {
            if (rng() % 9 == 0) Plain(s, OpBarrier, 0);
            if (rng() % 7 == 0) { const U j = rng() % count; Plain(s, OpNativeUnlink, j); s.push_back({OpPose, j, any(rng), any(rng), 0.3f, 0}); Plain(s, OpNativeInsert, j); }
            MoveRec(s, i, any(rng), any(rng), small(rng));
        }
        Sweep(*f, s, "relink barriers and untapped native writers");
    }
    {   // record-table capacity closes batches; log capacity forces serial native fallback
        auto f = fixture(12, 0.05f, 0.9f); Script s;
        for (U round = 0; round < 4; ++round) for (U i : Shuffled(count, rng)) MoveRec(s, i, any(rng), any(rng), small(rng));
        Sweep(*f, s, "relink batch capacity", 0, 0, 8, true);
        const U tiny = 2;
        Sweep(*f, s, "relink log capacity", tiny, tiny * 12, 4096, false, true);
        Sweep(*f, s, "relink side-array capacity", 0, 40, 4096, false, true);
    }
}

// Shadow must DETECT a divergence: a native writer the log does not know about changes a touched cell (or +AC).
static void ShadowDetectionCases() {
    currentCase = "relink shadow detects injected mismatch";
    std::mt19937 rng(0xbadc0de);
    for (const Kind injected : {OpHiddenInsert, OpHiddenUnlink, OpPokeCount}) {
        Fixture f(6, 63, 80, 12);
        { std::mt19937 populate(5); Populate(f, populate, 4.0f, 59.0f, 0.1f, 0.6f); }
        // Every record moves to a cell the victim also sits in, so the victim's cell is snapshotted by the batch first.
        Script s;
        for (U i = 0; i < 60; ++i) MoveRec(s, i, 20.0f, 20.0f, 0.2f);
        // The victim sits in the batch's cell, linked by the native service, so a hidden writer changes a snapshotted chain.
        NativeCall(f.Va(70), false); f.Pose(70, 20.0f, 20.0f, 0.2f, 0); NativeCall(f.Va(70), true);
        const U victim = 70;
        // Injection in the middle of the batch (after the cell was snapshotted by an earlier op).
        const Op hidden = {injected, injected == OpPokeCount ? 5u : victim, 0, 0, 0, 0};
        s.insert(s.begin() + 30, hidden);
        Cfg c; c.shadow = true; c.lanes = 4; c.concurrent = true; c.minCells = 1;
        const State start = Save(f);
        const Counts clean = [&] { Script copy = s; copy.erase(copy.begin() + 30); Restore(f, start); return RunLog(f, copy, c); }();
        EqU("clean shadow run has no cell mismatch", clean.shadow.mismatchCells, 0);
        EqU("clean shadow run has no node mismatch", clean.shadow.mismatchNodes, 0);
        Restore(f, start);
        const Counts n = RunLog(f, s, c);
        Require(n.shadow.mismatchCells + n.shadow.mismatchNodes != 0, "shadow reports the injected divergence");
        Require(n.shadow.lastRecord != 0, "shadow reports the last mismatching record");
        ++cases;
    }
    {   // a mirror too small for the batch refuses verification instead of reporting a false match or crashing
        Fixture f(7, 100, 900, 12);
        { std::mt19937 populate(5); Populate(f, populate, 4.0f, 96.0f, 0.1f, 0.6f); }
        Script s; for (U i = 0; i < 900; ++i) MoveRec(s, i, 5.0f + float(i % 90), 5.0f + float(i / 10), 0.3f);
        Cfg c; c.shadow = true; c.lanes = 1; c.minCells = 1;
        const Counts n = RunLog(f, s, c, 8);
        Require(n.shadow.refused != 0, "an overflowing mirror refuses the batch");
        ++cases;
    }
}

// Net-effect rules and the delta view contract on a hand-built batch.
static void NetEffectCases() {
    using namespace kntwr_loco;
    currentCase = "relink net effect rules and delta view";
    Fixture f(6, 63, 4, 16);
    { std::mt19937 populate(3); Populate(f, populate, 10.0f, 50.0f, 0.2f, 0.4f); }
    const U r0 = f.Va(0), r1 = f.Va(1);
    f.Pose(1, 30.0f, 30.0f, 0.2f, 0);
    MoveLog log{};
    Require(MoveLogInit(log, 4, 64, 64, A(At(0x1318038))), "net-effect log allocates");
    MoveLogBeginStage(log, 3);
    const U n0 = Get<U>(f.Rec(0), 0xac);
    const U base0 = Get<U>(f.Rec(0), 0xa8);
    std::vector<U> startCells;
    for (U k = 0; k < n0; ++k) startCells.push_back((Get<U>(reinterpret_cast<const B*>(base0 + k * 0x1c), 0x18) - A(f.heads.data())) / 4);
    FpFor(0);
    // record 0: unlink (old cells from batch-start memory), insert, unlink again: the second unlink cancels the insert.
    EqU("unlink logs", ExtractMoveOp(log, r0, 1, MoveUnlinkGrid, MoveFromClone, true), ExtractLogged);
    EqU("unlink applies +AC synchronously", Get<U>(f.Rec(0), 0xac), 0);
    f.Pose(0, 25.0f, 25.0f, 0.2f, 0);
    EqU("insert logs", ExtractMoveOp(log, r0, 2, MoveInsertGrid, MoveFromClone, true), ExtractLogged);
    const U inserted = Get<U>(f.Rec(0), 0xac);
    Require(inserted != 0, "insert applies +AC synchronously");
    U expected = 0; Require(MoveLogExpectedCount(log, r0, expected) && expected == inserted, "expected +AC follows the log");
    EqU("second unlink logs", ExtractMoveOp(log, r0, 3, MoveUnlinkGrid, MoveFromClone, true), ExtractLogged);
    EqU("unlink after insert zeroes +AC", Get<U>(f.Rec(0), 0xac), 0);
    EqU("insert-then-unlink collapses the insert", log.collapsed, 1);
    Require(MoveLogExpectedCount(log, r0, expected) && expected == 0, "expected +AC after the cancelled insert");
    // record 1: insert without unlink appends at nodeBase = +AC.
    const U ac1 = Get<U>(f.Rec(1), 0xac);
    EqU("insert without unlink logs", ExtractMoveOp(log, r1, 4, MoveInsertGrid, MoveFromWorker, true), ExtractLogged);
    const MoveOp& op = log.ops[log.count - 1];
    EqU("insert nodeBase is the +AC before the call", op.nodeBase, ac1);
    EqU("insert node count is the rectangle area", op.nodes, uint32_t(op.right - op.left + 1u) * (op.bottom - op.top + 1u));
    EqU("insert source/kind recorded", op.kind * 2u + op.source, uint32_t(MoveInsertGrid) * 2u + MoveFromWorker);
    // The unlink's side array holds the batch-start cells only.
    const MoveOp& first = log.ops[0];
    EqU("unlink op kind", first.kind, MoveUnlinkGrid); EqU("unlink node count is +AC before the call", first.nodes, n0);
    for (U k = 0; k < n0; ++k) EqU("old cell is the batch-start node+0x18 cell index", log.oldCells[first.nodeBase + k], startCells[k]);
    const MoveOp& second = log.ops[2];
    for (U k = 0; k < second.nodes; ++k) EqU("second unlink has no batch-start node to remove", log.oldCells[second.nodeBase + k], kMoveNoCell);
    MoveLogPublish(log);
    const MoveDeltaView* view = ReadMoveDelta();
    Require(view && view->ops == log.ops && view->count == 4 && view->oldCells == log.oldCells && view->epoch == 3 && view->complete == 1,
        "delta view exposes the stage log");
    MoveLogBeginStage(log, 4); Require(ReadMoveDelta() == nullptr, "a new stage invalidates the view");
    ResetFp();
    MoveLogFree(log);
    ++cases;
}

// ---------------------------------------------------------------------------------------------------------------------
// Timing fixture: realistic scale (movers, ~1.7 nodes each, clustered). Owner-serial native services vs log + pool apply.
// ---------------------------------------------------------------------------------------------------------------------
struct EventPool { // the production dispatcher's model: one auto-reset event per worker, atomic chunk claims, token barrier
    static constexpr U kMax = 32;
    HANDLE wake[kMax] = {}, threads[kMax] = {};
    U workers = 0; volatile LONG stop = 0, next = 0, pending = 0; U body = 0, chunks = 0; void* context = nullptr;
    struct Arg { EventPool* pool; U index; };
    std::vector<Arg> args;
    void Run() { for (;;) { const U t = static_cast<U>(InterlockedIncrement(&next) - 1); if (t >= chunks) break; reinterpret_cast<void(__fastcall*)(void*, U)>(body)(context, t); } }
    static DWORD WINAPI Worker(void* raw) {
        Arg a = *static_cast<Arg*>(raw); EventPool& p = *a.pool;
        for (;;) { WaitForSingleObject(p.wake[a.index], INFINITE); if (p.stop) return 0; p.Run(); InterlockedDecrement(&p.pending); }
    }
    void Start(U count) {
        workers = count; args.resize(count);
        for (U i = 0; i < count; ++i) { wake[i] = CreateEvent(nullptr, FALSE, FALSE, nullptr); args[i] = {this, i}; threads[i] = CreateThread(nullptr, 0, &Worker, &args[i], 0, nullptr); }
    }
    void Shutdown() { stop = 1; for (U i = 0; i < workers; ++i) { SetEvent(wake[i]); WaitForSingleObject(threads[i], INFINITE); CloseHandle(threads[i]); CloseHandle(wake[i]); } workers = 0; stop = 0; }
    void Dispatch(U fn, U count, void* ctx) {
        body = fn; context = ctx; chunks = count; next = 0;
        const U woken = std::min(workers, count > 0 ? count - 1 : 0u);
        pending = static_cast<LONG>(woken) + 1;
        for (U i = 0; i < woken; ++i) SetEvent(wake[i]);
        Run(); InterlockedDecrement(&pending);
        while (pending) YieldProcessor();
    }
};
static EventPool g_eventPool;
static void __stdcall EventDispatch(U, U body, U chunks, void* context) { g_eventPool.Dispatch(body, chunks, context); }
static double NowUs() { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return double(c.QuadPart) * 1e6 / double(f.QuadPart); }

// `clustered`: the movers sit in a few dense blobs (the army layout) instead of a uniform field.
static void BenchFixture(U lanes, U movers, U stages, bool clustered, U perBatch, U minCells) {
    const U shift = 10, maximum = 1023;
    Fixture f(shift, maximum, movers, 4, 0x700, 1.0f, 0);
    std::mt19937 rng(1234);
    std::normal_distribution<float> blob(0.0f, 45.0f);
    std::uniform_real_distribution<float> uniform(8.0f, 1015.0f), radius(0.10f, 0.20f), step(-1.6f, 1.6f);
    std::vector<float> cx{200, 330, 470, 600, 730, 840, 520, 380}, cz{300, 250, 520, 380, 640, 300, 760, 620};
    std::vector<float> x(movers), z(movers);
    for (U i = 0; i < movers; ++i) {
        if (clustered) { const U k = i % cx.size(); x[i] = std::clamp(cx[k] + blob(rng), 4.0f, 1018.0f); z[i] = std::clamp(cz[k] + blob(rng), 4.0f, 1018.0f); }
        else { x[i] = uniform(rng); z[i] = uniform(rng); }
        f.Pose(i, x[i], z[i], radius(rng), 0); NativeCall(f.Va(i), true);
    }
    U members = 0; for (U i = 0; i < movers; ++i) members += Get<U>(f.Rec(i), 0xac);
    std::printf("relink bench: %u movers, %.3f nodes/record, %s, %u participants, batch<=%u records, parallel min %u cells\n", movers,
        double(members) / movers, clustered ? "clustered" : "uniform", lanes, perBatch, minCells);
    g_eventPool.Start(lanes - 1);
    kntwr_loco::MoveLog log{};
    Require(kntwr_loco::MoveLogInit(log, movers, movers * 4, perBatch, A(At(0x1318038))), "bench log allocates");
    kntwr_loco::RelinkDispatcher disp{&EventDispatch, 0, lanes - 1};
    std::vector<double> serialMs, logMs, applyMs, totalMs; double dispatches = 0, partitions = 0, batches = 0, cpuMs = 0;
    std::vector<U> order(movers); for (U i = 0; i < movers; ++i) order[i] = i;
    typedef void(__fastcall* Service)(void*);
    const Service unlink = reinterpret_cast<Service>(At(0x811ed0)), insert = reinterpret_cast<Service>(At(0x7efa80));
    double poseUs = 0; std::vector<double> poseMs;
    for (U stage = 0; stage < stages + 4; ++stage) {
        std::vector<float> nx(movers), nz(movers);
        for (U i = 0; i < movers; ++i) { nx[i] = std::clamp(x[i] + step(rng), 4.0f, 1018.0f); nz[i] = std::clamp(z[i] + step(rng), 4.0f, 1018.0f); }
        const State start = Save(f);
        const double p0 = NowUs();
        for (U i : order) f.Pose(i, nx[i], nz[i], Get<float>(f.Rec(i), 0x58), 0);
        poseUs = NowUs() - p0; Restore(f, start);
        // owner-serial native
        const double s0 = NowUs();
        for (U i : order) { f.Pose(i, nx[i], nz[i], Get<float>(f.Rec(i), 0x58), 0); unlink(f.Rec(i)); insert(f.Rec(i)); }
        const double s1 = NowUs();
        const State serialResult = Save(f);
        Restore(f, start);
        // log + pool apply, batch by batch
        kntwr_loco::MoveLogBeginStage(log, stage);
        kntwr_loco::RelinkApplyStats stats{};
        double logUs = 0, applyUs = 0; U parallelBatches = 0, batchCount = 0;
        const auto flush = [&] {
            if (!kntwr_loco::MoveLogBatchOps(log)) return;
            const double a = NowUs();
            parallelBatches += kntwr_loco::RelinkApplyLive(log, &disp, minCells, stats);
            applyUs += NowUs() - a; ++batchCount; kntwr_loco::MoveLogCloseBatch(log);
        };
        const double t0 = NowUs();
        for (U i : order) {
            f.Pose(i, nx[i], nz[i], Get<float>(f.Rec(i), 0x58), 0);
            for (const MoveOpKind kind : {kntwr_loco::MoveUnlinkGrid, kntwr_loco::MoveInsertGrid}) {
                ExtractResult r = kntwr_loco::ExtractMoveOp(log, f.Va(i), i, kind, kntwr_loco::MoveFromWorker, true);
                if (r == kntwr_loco::ExtractBatchFull) { flush(); r = kntwr_loco::ExtractMoveOp(log, f.Va(i), i, kind, kntwr_loco::MoveFromWorker, true); }
                Require(r == kntwr_loco::ExtractLogged || r == kntwr_loco::ExtractNoop, "bench op logs");
            }
        }
        flush();
        const double t1 = NowUs();
        logUs = (t1 - t0) - applyUs;
        SameState(f, serialResult, "bench: log + pool apply equals the owner-serial native result");
        if (stage >= 4) {
            poseMs.push_back(poseUs / 1000.0); serialMs.push_back((s1 - s0) / 1000.0); logMs.push_back(logUs / 1000.0); applyMs.push_back(applyUs / 1000.0); totalMs.push_back((t1 - t0) / 1000.0);
            dispatches += stats.dispatches; partitions += stats.partitions; batches += batchCount; cpuMs += stats.cpuUs / 1000.0;
        }
    }
    {   // owner-side cost split of one extraction pass (diagnostic): coverage arithmetic alone, and the node/old-cell reads alone
        kntwr_loco::CoverGeometry geometry{1.0f, 0.5f, 0, maximum};
        volatile U sink = 0; double a = NowUs();
        for (U rep = 0; rep < 8; ++rep) for (U i : order) { const kntwr_loco::CoverRect r = kntwr_loco::CoverRecord(Get<float>(f.Rec(i), 0x48), Get<float>(f.Rec(i), 0x50), Get<float>(f.Rec(i), 0x58), false, geometry); sink += r.left + r.bottom; }
        const double cover = (NowUs() - a) / 8000.0; a = NowUs();
        for (U rep = 0; rep < 8; ++rep) for (U i : order) { const U n = Get<U>(f.Rec(i), 0xac), base = Get<U>(f.Rec(i), 0xa8); for (U k = 0; k < n; ++k) sink += Get<U>(reinterpret_cast<const B*>(base + k * 0x1c), 0x18); }
        const double reads = (NowUs() - a) / 8000.0;
        std::printf("  diagnostic: CoverRecord x %u records = %.3f ms; record+node reads = %.3f ms\n", movers, cover, reads);
    }
    kntwr_loco::MoveLogFree(log); g_eventPool.Shutdown();
    const auto median = [](std::vector<double> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
    std::printf("  pose writes only (in both loops): %7.3f ms/stage\n", median(poseMs));
    std::printf("  owner-serial native services : %7.3f ms/stage (median)\n", median(serialMs));
    std::printf("  log (owner extraction)       : %7.3f ms/stage\n", median(logMs));
    std::printf("  apply (pool wall, joins incl): %7.3f ms/stage   [%.1f batches, %.1f dispatches, %.1f partitions, %.2f ms task cpu per stage]\n",
        median(applyMs), batches / stages, dispatches / stages, partitions / stages, cpuMs / stages);
    std::printf("  log + apply total            : %7.3f ms/stage   => net %.3f ms/stage vs serial\n", median(totalMs), median(serialMs) - median(totalMs));
}

static void RelinkCases() {
    for (const U shape : {0u, 1u, 2u}) {
        const U shift = shape == 0 ? 6u : shape == 1 ? 7u : 8u, maximum = shape == 0 ? 63u : shape == 1 ? 100u : 200u;
        KernelCases(shift, maximum, shape == 2 ? 400u : 160u);
    }
    NetEffectCases();
    ShadowDetectionCases();
    {   // mid-scale: one full pool apply on the 1024x1024 production grid shape, all dispatch orders
        currentCase = "relink 1024x1024 production-shape grid";
        Fixture f(10, 1023, 3000, 4, 0x100);
        std::mt19937 rng(99); std::normal_distribution<float> blob(0.0f, 30.0f);
        for (U i = 0; i < f.count; ++i) { f.Pose(i, std::clamp(500.0f + blob(rng), 4.0f, 1018.0f), std::clamp(400.0f + blob(rng), 4.0f, 1018.0f), 0.15f, 0); NativeCall(f.Va(i), true); }
        std::uniform_real_distribution<float> step(-2.0f, 2.0f); Script s;
        for (U i : Shuffled(f.count, rng)) MoveRec(s, i, std::clamp(Get<float>(f.Rec(i), 0x48) + step(rng), 4.0f, 1018.0f), std::clamp(Get<float>(f.Rec(i), 0x50) + step(rng), 4.0f, 1018.0f), 0.15f);
        Sweep(f, s, "relink production-shape grid", 0, 0, 1024);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Engine level: the module's Stage with relink shadow/live (stubs, CommitOwned replay, tapped clone fallbacks, class-wrapper
// and native-vtable barriers, end-of-loop flush) against the untouched original 0x531AF0 and the relink-off module.
// ---------------------------------------------------------------------------------------------------------------------
static void EngineStage(const Scenario& sc, OwnedPlan plan, const std::vector<U>& baseline, const char* what) {
    currentCase = what;
    plan.grid = true;
    const auto output = OwnedStageOnce(sc, plan);
    Require(output == baseline, "relink native state and published grid equal the relink-off module");
}
static void OwnedRelinkCases() {
    StageGatherPatch gather;
    const auto sweep = [&](const Scenario& sc, OwnedPlan plan, const char* what) {
        plan.grid = true; plan.relink = 0; plan.lanes = 1;
        currentCase = what;
        const auto baseline = OwnedStageOnce(sc, plan);
        for (U mode : {1u, 2u}) for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) for (U minCells : {1u, 1u << 30}) {
            if (lanes == 1 && (reversed || minCells == 1)) continue;
            OwnedPlan p = plan; p.relink = mode; p.lanes = lanes; p.reversed = reversed; p.concurrent = lanes > 1; p.relinkMin = minCells;
            EngineStage(sc, p, baseline, what);
        }
    };
    for (bool wrapper : {false, true}) sweep(OwnedScenario(24, wrapper), OwnedPlan{}, wrapper ? "relink owned battle movers" : "relink owned direct movers");
    {   // class wrapper (barrier + untapped children), native callback (native-vtable barrier) and alternate wrapper (tapped clone fallback)
        Scenario sc = OwnedScenario(24, false);
        for (U i = 0; i < sc.agents.size(); ++i) if (i & 1) sc.agents[i] = OwnedActive(i, true);
        sc.agents[3].vt = VtClass; sc.agents[3].ec = 0; sc.agents[3].b688 = 2; sc.agents[12] = Callback(12, 0, 0);
        sc.agents[15].ec = 0; sc.agents[15].b628 = 1; sc.agents[15].b62c = 4;
        OwnedPlan plan;
        for (U i : {0u, 3u, 6u}) sc.agents[i].unit = 1;
        plan.owner[3] = plan.owner[12] = plan.owner[15] = true;
        plan.classRefusals = 1; plan.alternateRefusals = 1; plan.unitRefusals = 1;
        plan.details[loco::OwnedDetailClassWrapper] = 1; plan.details[loco::OwnedDetailOtherClass] = 1; plan.details[loco::OwnedDetailAlternate] = 1;
        sweep(sc, plan, "relink class-wrapper, native-callback and alternate-wrapper barriers");
    }
    {   // admitted serial clone fallback reaching real service taps (quiet: gates jump straight to the service)
        Scenario sc = OwnedScenario(24, false);
        for (Spec& s : sc.agents) s.f0 = 1;
        sc.agents[0].xform = 1;
        for (const bool quiet : {false, true}) {
            OwnedPlan plan; plan.owner[0] = true; plan.foreignTransforms = 1; plan.quiet = quiet;
            sweep(sc, plan, quiet ? "relink quiet tapped clone fallback" : "relink tapped clone fallback");
        }
    }
    {   // many chunks: batches of hundreds of ops across the pool
        Scenario sc = OwnedScenario(320, false);
        for (U i = 0; i < sc.agents.size(); ++i) { sc.agents[i].unit = B(1 + i % 3); sc.agents[i].f0 = 1; }
        sweep(sc, OwnedPlan{}, "relink many chunks");
    }
}

// The op-log stubs replace the native services inside the clones: every callee-saved register, XMM0-7, the x87 stack and
// both control words must come back exactly as the clone left them, and the logged chains must equal the native ones.
static float g_abiX[8][4];
static const double g_abiSt = 1234.5678;
#pragma warning(suppress: 4100)
static void __declspec(naked) AbiCall(U stub, U record, U* out) {
    __asm {
        push ebx
        push esi
        push edi
        push ebp
        mov eax, dword ptr [esp + 20]
        mov ecx, dword ptr [esp + 24]
        mov edx, dword ptr [esp + 28]
        push edx
        mov ebx, 0x11111111
        mov esi, 0x22222222
        mov edi, 0x33333333
        mov ebp, 0x44444444
        movups xmm0, xmmword ptr [g_abiX]
        movups xmm1, xmmword ptr [g_abiX + 16]
        movups xmm2, xmmword ptr [g_abiX + 32]
        movups xmm3, xmmword ptr [g_abiX + 48]
        movups xmm4, xmmword ptr [g_abiX + 64]
        movups xmm5, xmmword ptr [g_abiX + 80]
        movups xmm6, xmmword ptr [g_abiX + 96]
        movups xmm7, xmmword ptr [g_abiX + 112]
        fld qword ptr [g_abiSt]
        call eax
        mov eax, dword ptr [esp]
        mov dword ptr [eax], ebx
        mov dword ptr [eax + 4], esi
        mov dword ptr [eax + 8], edi
        mov dword ptr [eax + 12], ebp
        movups xmmword ptr [eax + 32], xmm0
        movups xmmword ptr [eax + 48], xmm1
        movups xmmword ptr [eax + 64], xmm2
        movups xmmword ptr [eax + 80], xmm3
        movups xmmword ptr [eax + 96], xmm4
        movups xmmword ptr [eax + 112], xmm5
        movups xmmword ptr [eax + 128], xmm6
        movups xmmword ptr [eax + 144], xmm7
        fstp qword ptr [eax + 24]
        fnstsw word ptr [eax + 20]
        fnstcw word ptr [eax + 22]
        stmxcsr dword ptr [eax + 16]
        add esp, 4
        pop ebp
        pop edi
        pop esi
        pop ebx
        ret
    }
}
static void RelinkStubAbiCase() {
    currentCase = "relink service stubs preserve registers, XMM, x87 and control words";
    StageGatherPatch gather;
    const Scenario sc = OwnedScenario(8, false);
    World twin(sc), real(sc);
    GridRegistry twinRegistry(twin), realRegistry(real);
    std::vector<U> ids; for (U i = 0; i < 8; ++i) ids.push_back(i);
    twinRegistry.Set(ids, {}); realRegistry.Set(ids, {});
    for (World* w : {&twin, &real}) { cur = w; vlog = &w->discard; for (auto& a : w->agents) NativeGridCall(*a, false); for (auto& a : w->agents) NativeGridCall(*a, true); }
    ResetFp();
    Same(twin, real, "identical relink ABI pre-run graphs");
    auto binding = MakeBinding(); binding.use_parallel = true; binding.use_owned_services = true; binding.use_grid = binding.verify_grid = true;
    binding.use_relink_workers = true; binding.dispatch = &TestDispatch; binding.pool = 0x5e11c0u; binding.workers = 3;
    Require(loco::Start(binding), "relink live starts with owned services and grid");
    Require(loco::ActivateOwned(real.model.p(), FixtureCapacity(real, 8)), "relink log activates with the grid");
    loco::SetRelinkMinCellsForTest(1);
    tdReverse = false; tdConcurrent = true; tdLanes = 4;
    for (U i = 0; i < 8; ++i) for (U k = 0; k < 4; ++k) g_abiX[i][k] = float(i * 4 + k) + 0.125f;
    const U unlinkStub = loco::RelinkStubForTest(0), insertStub = loco::RelinkStubForTest(1);
    Require(unlinkStub != A(At(0x811ed0)) && insertStub != A(At(0x7efa80)), "relink on installs the op-log stubs over the grid services");
    // Twin: native services in the same order. Real: stubs inside an open logging window.
    cur = &twin; vlog = &twin.discard;
    for (U i = 0; i < 8; ++i) {
        NativeGridCall(*twin.agents[i], false);
        Put<float>(twin.agents[i]->b.p(), 0x48, 20.0f + float(i) * 0.7f); NativeGridCall(*twin.agents[i], true);
    }
    cur = &real; vlog = &real.discard;
    loco::RelinkWindowForTest(true);
    unsigned short cw0; U mx0; __asm fnstcw word ptr [cw0]
    mx0 = _mm_getcsr();
    for (U i = 0; i < 8; ++i) {
        for (const bool insert : {false, true}) {
            if (insert) Put<float>(real.agents[i]->b.p(), 0x48, 20.0f + float(i) * 0.7f);
            U out[40] = {};
            AbiCall(insert ? insertStub : unlinkStub, A(real.agents[i]->b.p()), out);
            EqU("stub preserves ebx", out[0], 0x11111111u); EqU("stub preserves esi", out[1], 0x22222222u);
            EqU("stub preserves edi", out[2], 0x33333333u); EqU("stub preserves ebp", out[3], 0x44444444u);
            for (U x = 0; x < 8; ++x) for (U k = 0; k < 4; ++k) {
                U expected; std::memcpy(&expected, &g_abiX[x][k], 4);
                EqU("stub preserves XMM0-7", out[8 + x * 4 + k], expected);
            }
            double st; std::memcpy(&st, out + 6, 8);
            Require(st == g_abiSt, "stub leaves the caller's x87 value intact");
            Require(((out[5] & 0xffff) >> 11 & 7) == 0, "stub leaves the x87 stack balanced");
            EqU("stub preserves x87 control word", (out[5] >> 16) & 0xffff, cw0);
            EqU("stub preserves MXCSR control", out[4] & 0xffc0, mx0 & 0xffc0);
        }
    }
    const U logged = [&] { std::array<U, loco::RelinkWordCount> w{}; loco::SampleRelink(w.data()); return w[loco::RelinkOpsUnlink] + w[loco::RelinkOpsInsert]; }();
    EqU("every stubbed service was logged, none ran natively", logged, 16);
    loco::RelinkWindowForTest(false);
    Same(twin, real, "stub log + pool apply equals native service chains");
    const loco::MoveDeltaView* view = loco::ReadMoveDelta();
    Require(view && view->count == 16 && view->complete == 1, "closing the window publishes the delta view");
    CallStop(); Require(loco::ReadMoveDelta() == nullptr, "Stop withdraws the delta view");
    EqU("Stop restores the native service targets", loco::RelinkStubForTest(0), A(At(0x811ed0)));
    ++cases;
}
} // namespace relinkcase
