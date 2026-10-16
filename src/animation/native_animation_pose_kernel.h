// Worker-owned x86 re-implementation of the original NTW pose kernels.
//
// Recovered from F:/.../Napoleon.exe (SHA256 13fcab62...2cbad4, preferred base 0x400000):
//   0x10DA030  clip frame locate        (this = clip, ret 0x14)
//   0x10CE290  local pose blend         (this = out local pose, ret 0x20)
//   0x10DF020  local -> model matrices  (this = local pose, ret 8)
//   0x10F1160  root-motion sample       (this = clip, ret 8)
// Native evidence: native-animation-pose-kernel-evidence.json, native-animation-pose-blend-10ce290.asm,
// native-animation-pose-compose-10df020.asm, native-animation-libm-acos-128448c.asm.
//
// Contract
//  * Inputs are read-only and outputs are caller-provided buffers; no internal allocation or locks.
//    Concurrent jobs require disjoint outputs, stable inputs and matching native FP control state.
//  * Raw-layout inputs mirror the original in-memory objects so the parent can pass game pointers
//    unchanged (no marshalling copies).  Offsets are in native_animation_pose_kernel.cpp.
//  * Slerp uses the original libm helper for acos (0x128448c, xmm0 in/out) and the x87 `fsin` stored
//    through a float, exactly like the original. Bind the required `acos_fn` to a thunk calling
//    that native helper; no different-precision CRT fallback is provided.
//  * Ordered commit (container appends such as 0x118C6A0 / 0x1221480, RNG, hit effects) is NOT done here.
#pragma once
#include <cstdint>

#ifndef _M_IX86
#error The pose kernel reproduces x86 x87/SSE behaviour and must be built as x86.
#endif

namespace ntw_anim {

// float acos(float) with the original helper's calling convention hidden behind cdecl.
typedef float(__cdecl* AcosFn)(float);

// 0x10DA030.  Returns false on the original's divide-by-zero precondition (loop flag with frame_count < 2).
bool locate_frames(const uint8_t* clip, float time, bool no_wrap, uint32_t* i0, uint32_t* i1, float* frac);

// 0x10F1160.  Linear root-motion sample between the two located frames (frame +0xC/+0x10/+0x14).
bool root_motion(const uint8_t* clip, float time, float out_xyz[3]);

struct BlendArgs {
    const uint8_t* frame_a;      // param_2: frame object (+0 skeleton, +0x30 limit, +0x34 pos[], +0x44 quat16[])
    const uint8_t* frame_b;      // param_3
    float t;                     // param_4 blend factor
    uint32_t mode;               // param_5: 0 step, 1 nlerp-no-normalise, 2 slerp(0.993 threshold), 3 slerp(0.3 threshold)
    const uint8_t* clip_holder;  // param_6 = *(clip + 4); +0x44 -> reference frame object
    const uint8_t* clip_header;  // param_7 = clip + 8; byte at +0x28 == 1 selects partial-animation substitution
    uint32_t max_bones;          // param_1 (0 = skeleton count)
    bool sse2_quat_decode;       // value of byte [0x176CBF5] (0x10D5510); true on every SSE2 machine
    AcosFn acos_fn;              // required native acos thunk, including for worker jobs
};

// 0x10CE290.  Returns bone count n.  out_pos has n*3 floats, out_quat n*4 floats (x,y,z,w).
// For mode > 3 the original writes nothing for the bone; this routine leaves those outputs untouched.
uint32_t blend_local(const BlendArgs& a, float* out_pos, float* out_quat);

// Number of bones blend_local()/compose_global() will process: min(max_bones, skeleton count) as 0x10CE290.
uint32_t blend_bone_count(const uint8_t* frame_a, uint32_t max_bones);

// 0x10DF020 matrix core.  bone_table = *(skeleton + 0xC) (stride 0x14, signed parent index at +0x10).
// pos is n*3 floats, quat n*4 floats, out_mats n*12 floats (3x4, row-vector convention, original layout).
// Parents MUST precede children (the original reads already-written output rows).
void compose_global(const uint8_t* bone_table, uint32_t n, const float* pos, const float* quat, float* out_mats);

// ---- worker job -----------------------------------------------------------------------------------
// One independent pose evaluation = locate + blend + compose.  Different jobs never alias outputs.
struct PoseJob {
    const uint8_t* clip;             // clip object (frames at +0x8C, count +0x88, fps +0x48, flags +0x44)
    float time;
    uint32_t mode;
    bool no_wrap;
    uint32_t max_bones;
    bool sse2_quat_decode;
    AcosFn acos_fn;
    // outputs (caller sized for the skeleton's bone count)
    float* out_pos;
    float* out_quat;
    float* out_mats;
    uint32_t out_bones;              // written
    uint32_t i0, i1;                 // written
    float frac;                      // written
    bool ok;                         // written
};
// Reads clip+4 / clip+8 exactly as 0x10DF440 does.  Safe to call concurrently for distinct jobs.
void run_pose_job(PoseJob& job);

}  // namespace ntw_anim
