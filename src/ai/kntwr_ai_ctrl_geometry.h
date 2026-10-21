// AI controller site 33 (0x7C8BD0 -> 0x7492F0 -> 0x749090 -> scorer 0x7B1270): identity / pose / center-distance reuse.
//
// Two host bindings replace spans of the cloned scorer's list loop (call sites pinned in tools/generate_clone_specs.py):
//   AI_CTRL_IDENTITY        run 0x7B1484..0x7B1492 (15 B): lea edi,[eax+10]; id slot calls at 0x7B1489 (U+0x10) and 0x7B1491 (V+0x10)
//                           In EAX=V, EDX=ECX=U+0x10, EBX=i, caller [ESP+0x18]=R.  Out EDI=V+0x10, ESI=id(U), EAX=id(V).
//   AI_CTRL_POINT_DISTANCE  region 0x7B1497..0x7B14DB (68 B): pose gather 0x53FBE0/0x80E9D0 of V and 0x76DCD0(R,pose.XZ)
//                           In EBX=i, caller [ESP+0x24]=V, [ESP+0x18]=R.  Out ST(0)=float32 distance (as native `fld dword`).
// Everything native computes per (candidate U, list unit V) pair that depends only on V (identity, pose) or on (R, V) (center
// distance) is computed once per V per open batch (src/ai/kntwr_ai_ctrl_batch.h) and served by list index.  Per-U compares,
// the region-boundary distance and every integer reduction stay native.  Owner thread only; no allocation; no wall clock.
// Outside an open batch, with the flags off, or after a verify mismatch latched the feature off, both bindings execute the
// original instruction sequence's work themselves (same image calls, same order).
#pragma once
#include <cstdint>

namespace kntwr_ai_ctrl_geometry {

constexpr uint32_t kCapacity = 8192;   // list index slots; larger lists fall back to native per call
constexpr uint32_t kStatusWords = 8;

// B half of the ai_ctrl status row, in order: id_calls id_served pose_served dist_calls dist_served distinct_RV
// dist_mismatch (any identity/pose/distance verify mismatch) boundary_repeat.
struct Status {
    uint32_t id_calls, id_served, pose_served, dist_calls, dist_served, distinct_rv, dist_mismatch, boundary_repeat;
};

// imageBase = load address of the (unrelocated 0x400000-based) game image.  Publishes the two binding addresses and pins
// the native functions this module calls.  False when imageBase is 0.
bool Bind(uint32_t imageBase, uint32_t* bindings);
// census: count only (native always executes); live: serve from the per-batch tables; verify (with live): recompute native for
// every served value, mismatch -> native value + latch off.  Registers the batch retire callback; call after
// ai_ctrl_batch_reset.  All false = bindings are pure native.
void Configure(bool census, bool live, bool verify);
void Reset();                                     // zero counters, clear latch and caches
void FillStatus(uint32_t words[kStatusWords]);
bool Latched();
// Oracle probe: the pose cached for list slot i / unit v in the current batch generation.
bool CachedPose(uint32_t i, uint32_t v, uint32_t* px, uint32_t* pz);

// The 0x76DCD0 kernel on raw bits: subss, subss, mulss, mulss, addss (dest = R side), float32 result bits.
uint32_t PointDistanceBits(uint32_t rx, uint32_t rz, uint32_t px, uint32_t pz);

// Binding bodies (the naked trampolines call these; the oracle calls them and the trampolines).
uint32_t __fastcall IdentityStep(uint32_t v, uint32_t uThis, uint32_t i, uint32_t r, uint32_t* idU);  // returns id(V+0x10)
uint32_t __fastcall DistanceStep(uint32_t v, uint32_t r, uint32_t i);                                 // returns float32 bits
void* IdentityBindingAddress();
void* DistanceBindingAddress();

}  // namespace kntwr_ai_ctrl_geometry
