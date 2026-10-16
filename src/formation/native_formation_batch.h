// Prepare / execute / consume adapter that runs the formation SLOT GENERATOR port (native_formation_layout.h) and the
// ASSIGNMENT kernel port (native_formation_slot.h) for many dirty line formations at once on a persistent worker team
// (native_worker_dispatch.h) and lets the ORIGINAL assignment call site (0x555CEB, also 0x539CA5) consume the result
// only when everything the original would have read still matches.
//
// Pinned image: Napoleon.exe SHA-256 13fcab62...cbad4 (approved modified image), preferred base 0x400000.  Every address
// below is a preferred-base VA; the owner passes the live image delta (actual base - 0x400000).
//
// Native route being batched (all inside the original tick, on the game thread):
//   0x581200 (command execute, ecx = cmd; formation = [cmd+4])
//     [formation+0x278C] != 0 && [formation+0x2788] == 0
//     -> 0x57AFC0(container = [cmd+0x18], float f = [cmd+0x1C], flag = 1, layoutIndex = -1) -> 0x555CA0 (ecx = formation)
//        0x555CA0: clears +0x278C (flag != 0); layout = [formation+0x628]; layout->vtable[+0x24](out, container, f, men)
//                  (0x62FD60 stock / 0x18ED200 mod wrapper, 36-byte records into a fresh vector)
//                  call 0x18F0A00(slotVec, flag, formation+0x518, layoutIndex)       <- 0x555CEB, replaced by Consume()
//                  rebuild formation+0x1C from the entry vector, 0x557C80 statistic, free the generator vector.
//   0x539CA5 (inside 0x539C90) calls the same 0x18F0A00 and can share Consume() (the call arguments are validated).
//
// What this module does and does NOT do
//   * Prepare (main thread): copies, into one private contiguous per-unit block, everything the generator and the assignment
//     kernel read: the layout floats, the container with its class-A/B children, surface cells / ring nodes / frames, the
//     men (pointer, x, z, angle, class, marker, skip flag), the unit flags.  Workers never see a game pointer.
//   * Execute (main thread + persistent team): ONE dispatch for all prepared units (one chunk per unit, largest unit first),
//     barrier on return, no polling, no per-unit hand-off, no allocation.  A chunk runs Generate -> ToSlotArrays -> AssignUnit
//     on the unit's private block with MXCSR 0x1F80 and the x87 control word captured at Prepare.
//   * Consume (main thread, original call site): re-reads the live men / unit / layout / slot records the original
//     assignment reads, compares them bit-for-bit with the snapshot and only then writes the entry vector (formation+0x518)
//     exactly as 0x5373F0 leaves it.  ANY difference returns kFallback and the caller runs the original 0x18F0A00 call.
//   * The native generator still runs on the game thread (it allocates the real 36-byte records with terrain-correct Y).
//     The port's slots are computed WITHOUT a terrain snapshot (Input::terrain == nullptr): terrain-resident records carry
//     yValid = 0 and only their world x / z (which do not depend on Y) are used, to feed the assignment and to be compared
//     with the real records.  The port's records are never written into the game: this module has no slot-record encoder, so
//     an unknown-height record cannot reach the game.  Replacing the native generator would need a terrain-correct Y and a
//     snapshot-equality proof of the whole container, which this module deliberately does not claim.
//   * Main-thread-only items stay on the owner: 0x54C8B0 (unit predicate; its chain 0x55C9A0 -> 0x57ACA0 -> 0x57AC90 / 0x557450 was
//     disassembled as pure reads of the unit's vector, with no writes and no indirect calls), the game allocator (0x445A50 /
//     0xFF7EF0), 0x80E9D0 for parent-relative slot records (Consume only), the optional second consumer 0x539CA5.
//   * Prepare executes NO game callback that is not a pinned pure function.  The two callbacks the original generator reaches per
//     surface cell / ring node are never called: ring link 0x6B7F50 (its 56-byte body is pinned at Init and re-implemented as
//     reads, RingLink) and the cell's vtable[+0x10] frame receiver.  Their targets (link object vtable slot 0, cell vtable
//     slot 4) are decoded as fixed thiscall leaf forms (return 0 / return this / load or lea of [this+disp] / load byte, each
//     followed by a bare RET: see DecodeLeaf in the .cpp) and evaluated from the same memory reads.  Supported in the real
//     image: 0x461180 (xor eax,eax), 0x4470B0 (mov eax,ecx) and 0x54E920 (mov al,[ecx+4]).  Any other target declines the unit
//     BEFORE it would be invoked (kUnsupportedLinkGetter / kUnsupportedCellGetter, counted in Stats::reasons) and the native
//     work stays untouched.  Link objects are only inspected for entries the original scan would reach (it stops at the first
//     AL == 1).  The byte-load form is accepted only where the caller consumes AL alone (links), never for the frame receiver.
//   * Layout types 1..6 (other generators) are not recovered: a formation whose generator is not 0x62FD60 / 0x18ED200 is
//     rejected at Prepare (kUnsupportedGenerator) and runs the original path.
//
// Activation / ownership gates (all enforced in code, see Reason)
//   Prepare: Begin() called; formation vtable 0x13211D8 (infantry formation); dirty byte +0x278C != 0 and cooldown dword
//   +0x2788 <= Config::maxCooldown; 1..maxMen men; layout generator 0x62FD60 or 0x18ED200; container with 1..maxPieces
//   children, every child class A (0x1333944) or B (0x133396C); surface/frame limits; supported pure link / frame getters (see
//   above); every man class has the known anchored thunk (vtable[+0xF4] == 0x64FA80 and vtable[+0xA8] in {0x4470B0, 0x461180});
//   one job per formation.
//   Consume: job exists and executed, same formation, same flag / layoutIndex, same men count and pointer list, same man
//   x / z / angle / class / marker / skip, same 0x54C8B0 result, same mod eligibility and generator, same x87 control word,
//   MXCSR control bits == 0x1F80 (sticky status flags excluded), same slot count and same world x / z / angle for every slot record.
//   Freshness: the snapshot is NOT an atomic capture of the world.  Prepare may run at the start of the tick while man
//   updates and other commands still change positions afterwards; the consume-time comparison is the only coherence
//   guarantee, and every mismatch is counted in Stats::reasons.  How often a real tick matches is not measured here.
//   Ownership: workers write only their own UnitJob block (64-byte aligned, no sharing); the angle table and constants are
//   immutable after Init.  Unit ownership of men (agents unique across units in the earlier capture) is NOT needed for
//   worker safety (workers read no game object) and does NOT make whole-unit updates parallel.
#pragma once

#ifndef _M_IX86
#error native_formation_batch calls 32-bit __thiscall game code; compile as x86 MSVC.
#endif

#include <cstddef>
#include <cstdint>

#include "native_formation_layout.h"
#include "native_formation_slot.h"

namespace ntw_formation_batch {

// ---- pinned VAs (preferred base 0x400000) -------------------------------------------------------------------------
namespace va {
constexpr uint32_t kPreferredBase = 0x400000;
constexpr uint32_t kFormationVtable = 0x13211D8;    // per-unit formation object (infantry)
constexpr uint32_t kGeneratorStock = 0x62FD60;      // layout type 0 (Line) generator
constexpr uint32_t kGeneratorMod = 0x18ED200;       // mod wrapper around it (sets process flag 0x18ED160)
constexpr uint32_t kChildClassA = 0x1333944;        // straight segment
constexpr uint32_t kChildClassB = 0x133396C;        // arc
constexpr uint32_t kOfficerVtable = 0x134841C;      // marker officers (+0x66C identifier 0x57460000..2)
constexpr uint32_t kAnchoredThunk = 0x64FA80;       // man vtable[+0xF4]: calls vtable[+0xA8], != 0
constexpr uint32_t kReturnThis = 0x4470B0;          // man vtable[+0xA8] -> anchored
constexpr uint32_t kReturnZero = 0x461180;          // man vtable[+0xA8] -> not anchored
constexpr uint32_t kUnitPredicate = 0x54C8B0;       // thiscall(ecx = unit) -> 0 / 1
constexpr uint32_t kResolveWorld = 0x80E9D0;        // thiscall(ecx = position object, out float[3]) ret 4
constexpr uint32_t kRingLink = 0x6B7F50;            // thiscall(ecx = ring node) -> link entry or 0; body pinned, never executed
constexpr uint32_t kVectorAlloc = 0x445A50;         // cdecl(count, 0) -> count * 12 bytes (entry vector)
constexpr uint32_t kHeapFree = 0xFF7EF0;            // cdecl(ptr)
constexpr uint32_t kAssignWrapper = 0x18F0A00;      // thiscall(formation) ret 0x10 (slotVec, flag, assignVec, layoutIndex)
constexpr uint32_t kAssignCallSite = 0x555CEB;      // call 0x18F0A00 inside 0x555CA0
constexpr uint32_t kAngleTable = 0x176CFF8;         // 65536 {sin, cos} float pairs, runtime initialised
}  // namespace va

// ---- results ------------------------------------------------------------------------------------------------------
enum Reason : uint32_t {
    kOk = 0,
    // Init / lifecycle
    kNotInitialised, kBadStorage, kImageMismatch, kAngleTableNotReady, kNoEpoch,
    // Prepare
    kTableFull, kArenaFull, kFault, kBadCommand, kNotInfantryFormation, kDuplicateFormation, kNotDirty, kCooldown, kNoMen,
    kTooManyMen, kBadFormation, kUnsupportedGenerator, kBadContainer, kUnsupportedChild, kSurfaceLimit, kUnknownManClass,
    kNullMan,
    // Execute
    kNothingPrepared, kGenerateFailed, kAssignFailed,
    // Consume
    kNotPrepared, kNotExecuted, kCallArguments, kMenCount, kMenMembership, kMenState, kUnitPredicate, kModEligibility,
    kLayoutChanged, kFpuControlWord, kMxcsr, kSlotCount, kSlotGeometry, kAllocFailed,
    // Prepare, appended so the numbering of the reasons above is unchanged: the link / frame getter is not a supported pure leaf
    kUnsupportedLinkGetter, kUnsupportedCellGetter,
    kReasonCount
};
const char* ReasonName(Reason r);

enum JobState : uint32_t { kEmpty = 0, kPrepared, kExecuted, kFailed, kConsumed, kRejected };

struct Config {
    uint32_t imageDelta = 0;          // actual image base - 0x400000
    uint32_t maxUnits = 256;          // prepared units per epoch
    uint32_t maxMen = 4096;           // men per formation (0x18F0200 bound is 0x1000)
    uint32_t maxPieces = 64;          // container children
    uint32_t maxNodes = 4096;         // ring nodes per unit
    uint32_t maxCooldown = 0;         // +0x2788 accepted at Prepare (0 = exactly the 0x581200 gate; the order of 0x580A30
                                      // relative to Prepare is not pinned, a larger value only trades wasted jobs for hits)
};

struct Stats {
    uint32_t epochs = 0, prepared = 0, executed = 0, executeFailed = 0;
    uint32_t committed = 0, fallbacks = 0, unusedJobs = 0;
    uint32_t slotsWithoutHeight = 0;  // port slots computed with yValid == 0; never written to the game
    uint32_t reasons[kReasonCount] = {};
};

// stdcall(user, body, chunks, ctx) of native_worker_dispatch (ntw_pool_dispatch); body = void(__fastcall*)(void* ctx, u32 chunk)
struct Dispatcher {
    void(__stdcall* dispatch)(uint32_t user, uint32_t body, uint32_t chunks, void* ctx) = nullptr;
    uint32_t user = 0;
};

// The four stack arguments of 0x18F0A00 plus its ECX formation receiver.
struct AssignCall {
    uint32_t formation = 0;
    uint32_t slotVec = 0;        // generator vector header: +4 cap, +8 count, +0xC data (36-byte records), +0x10 mark
    uint32_t flag = 0;           // low byte significant
    uint32_t assignVec = 0;      // formation+0x518: +4 cap, +8 count, +0xC data (12-byte entries)
    int32_t layoutIndex = -1;
};

enum class Outcome : uint32_t { kFallback = 0, kCommitted = 1 };
struct ConsumeResult {
    Outcome outcome = Outcome::kFallback;   // kFallback: run the original 0x18F0A00 call
    Reason reason = kNotPrepared;
    uint32_t unit = 0xFFFFFFFFu;            // job index when one was matched
};

// One prepared formation.  All arrays live in the batch arena (contiguous, bump allocated, reset by Begin()).
struct alignas(64) UnitJob {
    uint32_t state;
    uint32_t reason;                         // why the job was rejected / failed
    uint32_t formation, command, container, layout, unit, menArray, generator;
    uint32_t men, fBits;
    uint32_t layoutBits[4];                  // layout +8,+0xC,+0x10,+0x14 (diagnostic)
    int32_t layoutIndex;
    uint16_t fpuControlWord;
    uint8_t flag, unitFlag, modEligible, pad0;
    uint32_t* manPtr;                        // men man pointers in formation+0x1C order
    ntw_formation::ArenaViews views;         // man / slot SoA, entries, scratch
    ntw_formation_layout::Piece* pieces;
    ntw_formation_layout::SurfaceCell* cells;
    ntw_formation_layout::SurfaceNode* nodes;
    ntw_formation_layout::Frame* frames;
    ntw_formation_layout::Slot* slots;
    ntw_formation_layout::Input in;          // points into the arrays above
    // written by the worker that ran the job
    int32_t layoutStatus, assignStatus;
    ntw_formation_layout::Result layoutResult;
    uint32_t slotCount;
    ntw_formation::SlotResult assign;
};

class Batch {
public:
    // Bytes of storage for `arenaBytes` of per-epoch unit data (job table + angle table + arena).  64-byte aligned memory.
    static size_t StorageBytes(const Config& cfg, size_t arenaBytes);
    // Main thread.  Verifies the pinned image bytes at every address used, copies the runtime angle table (0x176CFF8) and
    // reads the five float constants from the image.  Safe to call again after a failure (kAngleTableNotReady).
    Reason Init(void* storage, size_t storageBytes, const Config& cfg);
    // Main thread, once per simulation tick before Prepare.  Discards every job of the previous epoch.
    void Begin();
    // Main thread.  `command` = the 0x581200 command object (formation = [cmd+4], container = [cmd+0x18], f = [cmd+0x1C]).
    Reason Prepare(uint32_t command, uint32_t* unitIndex);
    // Main thread.  One dispatch for every prepared job; returns after the barrier.
    Reason Execute(const Dispatcher& dispatcher, uint32_t* jobsRun);
    // Main thread, at the original 0x18F0A00 call (0x555CEB / 0x539CA5).  Single use per job.
    ConsumeResult Consume(const AssignCall& call);
    // Main thread, end of tick: counts jobs nobody consumed.
    void End();

    const Stats& GetStats() const { return stats_; }
    const UnitJob* Job(uint32_t index) const { return index < jobCount_ ? &jobs_[index] : nullptr; }
    uint32_t JobCount() const { return jobCount_; }

private:
    struct ManClass { uint32_t vtable; uint8_t anchored, officer; };
    struct Natives {
        uint32_t(__thiscall* unitPredicate)(void* unit);
        void*(__thiscall* resolveWorld)(void* posObj, float* out);
        void*(__cdecl* vectorAlloc)(int count, int zero);
        void(__cdecl* heapFree)(void* p);
    };

    uint32_t V(uint32_t preferred) const { return preferred + cfg_.imageDelta; }
    Reason Count(Reason r);
    uint8_t* Take(size_t bytes, size_t align);
    bool ResolveClass(uint32_t vtable, uint8_t* anchored, uint8_t* officer);
    int32_t AddFrame(UnitJob& j, uint32_t* framePtrs, uint32_t* frameCount, uint32_t capacity, uint32_t ptr);
    Reason PrepareImpl(uint32_t command, uint32_t* unitIndex);
    Reason ConsumeImpl(const AssignCall& call, ConsumeResult* out);
    Reason Commit(UnitJob& j, const AssignCall& call);
    void RunJob(UnitJob& j) const;
    static void __fastcall Body(void* ctx, uint32_t chunk);

    Config cfg_{};
    Natives nat_{};
    ntw_formation::Constants constants_{};
    uint8_t* base_ = nullptr;
    UnitJob* jobs_ = nullptr;
    uint32_t* order_ = nullptr;
    float* angleTable_ = nullptr;
    uint8_t* arena_ = nullptr;
    size_t arenaBytes_ = 0, cursor_ = 0;
    uint32_t jobCount_ = 0;
    ManClass classes_[16] = {};
    uint32_t classCount_ = 0;
    bool initialised_ = false, epochOpen_ = false;
    Stats stats_{};
};

}  // namespace ntw_formation_batch
