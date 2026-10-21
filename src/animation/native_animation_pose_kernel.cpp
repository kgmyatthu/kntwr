// See native_animation_pose_kernel.h.  Build: CMake target kntwr_animation_pose (x86, /O2 /fp:precise /arch:SSE2).
// Every expression below keeps the original instruction order (no reassociation, no FMA): the original is
// scalar SSE `mulss/addss/subss` plus x87 `fsin` stored through a float.
#include "native_animation_pose_kernel.h"
#include <cmath>
#include <cstring>

namespace ntw_anim {
namespace {

// ---- raw layouts of the original objects (offsets proven by the disassembly in this directory) ----
constexpr uint32_t CLIP_HOLDER = 0x04;      // *(clip+4)  -> param_6 of 0x10CE290
constexpr uint32_t CLIP_HEADER = 0x08;      // clip+8     -> param_7 of 0x10CE290 (byte +0x28 partial flag)
constexpr uint32_t CLIP_FLAGS = 0x44;       // bit1 = loop
constexpr uint32_t CLIP_FPS = 0x48;
constexpr uint32_t CLIP_FRAMES = 0x88;      // frame count
constexpr uint32_t CLIP_FRAME_ARRAY = 0x8C; // pointer to frame* array
constexpr uint32_t FRAME_SKELETON = 0x00;
constexpr uint32_t FRAME_ROOTMOTION = 0x0C; // 3 floats
constexpr uint32_t FRAME_LIMIT = 0x30;      // bones >= limit fall back to the reference frame (partial clips)
constexpr uint32_t FRAME_POS = 0x34;        // float3 per bone
constexpr uint32_t FRAME_QUAT = 0x44;       // 4 x int16/uint16 per bone
constexpr uint32_t SKEL_COUNT = 0x08;
constexpr uint32_t SKEL_TABLE = 0x0C;
constexpr uint32_t BONE_STRIDE = 0x14;
constexpr uint32_t BONE_PARENT = 0x10;
constexpr uint32_t HOLDER_REFFRAME = 0x44;
constexpr uint32_t HEADER_PARTIAL = 0x28;

template <class T> inline T rd(const uint8_t* base, uint32_t off) {
    T v;
    std::memcpy(&v, base + off, sizeof(T));
    return v;
}

inline float x87_sinf(float v) {
    float r;
    __asm {
        fld dword ptr v
        fsin
        fstp dword ptr r
    }
    return r;
}

struct Quat { float x, y, z, w; };

// 0x10D5510 selects the decode.  True (SSE2 CPUs): sign-extended int16 * 1/32767.  False: uint16 * 1/32767 - 1.
inline Quat decode_quat(const uint8_t* q, bool sse2) {
    constexpr float K = 0x1.000100p-15f;  // bits 0x38000080 (_DAT_01402FC0.., _DAT_0134657C)
    Quat r;
    if (sse2) {
        r.x = (float)(int32_t)rd<int16_t>(q, 0) * K;
        r.y = (float)(int32_t)rd<int16_t>(q, 2) * K;
        r.z = (float)(int32_t)rd<int16_t>(q, 4) * K;
        r.w = (float)(int32_t)rd<int16_t>(q, 6) * K;
    } else {
        r.x = (float)(int32_t)rd<uint16_t>(q, 0) * K - 1.0f;
        r.y = (float)(int32_t)rd<uint16_t>(q, 2) * K - 1.0f;
        r.z = (float)(int32_t)rd<uint16_t>(q, 4) * K - 1.0f;
        r.w = (float)(int32_t)rd<uint16_t>(q, 6) * K - 1.0f;
    }
    return r;
}

inline float neg(float v) { uint32_t b; std::memcpy(&b, &v, 4); b ^= 0x80000000u; std::memcpy(&v, &b, 4); return v; }

inline float dot4(const Quat& b, const Quat& a) {  // (((Bx*Ax)+(By*Ay))+(Bz*Az))+(Bw*Aw)
    float s = b.x * a.x;
    s = s + b.y * a.y;
    s = s + b.z * a.z;
    s = s + b.w * a.w;
    return s;
}

}  // namespace

bool locate_frames(const uint8_t* clip, float time, bool no_wrap, uint32_t* i0, uint32_t* i1, float* frac) {
    const uint32_t frames = rd<uint32_t>(clip, CLIP_FRAMES);
    const bool loop = (rd<uint8_t>(clip, CLIP_FLAGS) & 2) != 0;
    float x = rd<float>(clip, CLIP_FPS) * time;
    // x87 `fist` rounds to nearest-even under the default control word, then the sign fix-ups of 0x10DA030.
    const float rr = std::nearbyintf(x);
    const int32_t r = (rr >= -2147483648.0f && rr < 2147483648.0f) ? (int32_t)rr : (int32_t)0x80000000;  // fist "integer indefinite"
    const float resid = x - (float)r;  // exact; the original stores fisub's result as float
    uint32_t xb, rb;
    std::memcpy(&xb, &x, 4);
    std::memcpy(&rb, &resid, 4);
    int32_t idx;
    if ((int32_t)xb < 0)
        idx = r + ((int32_t)rb > 0 ? 1 : 0);
    else
        idx = r - ((uint32_t)(rb + 0x7fffffffu) < rb ? 1 : 0);  // carry out of rb + 0x7FFFFFFF
    *i0 = (uint32_t)idx;
    *frac = x - (float)((double)idx + (idx < 0 ? 4294967296.0 : 0.0));
    const uint32_t last = frames - 1u;
    if (loop && !no_wrap) {
        if (last == 0) return false;  // original: #DE
        const uint32_t m = (uint32_t)idx % last;
        *i0 = m;
        *i1 = m + 1;
        return true;
    }
    uint32_t a = (uint32_t)idx;
    if (a >= last) a = last;
    *i0 = a;
    uint32_t b = a + 1;
    if (b >= frames - 1u) b = frames - 1u;
    *i1 = b;
    if (a == b) *frac = 0.0f;
    return true;
}

bool root_motion(const uint8_t* clip, float time, float out[3]) {
    uint32_t i0, i1;
    float f;
    if (!locate_frames(clip, time, false, &i0, &i1, &f)) return false;
    const uint8_t* const* frames = reinterpret_cast<const uint8_t* const*>(rd<uintptr_t>(clip, CLIP_FRAME_ARRAY));
    const uint8_t* fb = frames[i0];  // iVar6 (earlier frame)
    const uint8_t* fa = frames[i1];  // iVar5 (later frame)
    const float a0 = rd<float>(fb, FRAME_ROOTMOTION), a1 = rd<float>(fb, FRAME_ROOTMOTION + 4), a2 = rd<float>(fb, FRAME_ROOTMOTION + 8);
    const float b0 = rd<float>(fa, FRAME_ROOTMOTION), b1 = rd<float>(fa, FRAME_ROOTMOTION + 4), b2 = rd<float>(fa, FRAME_ROOTMOTION + 8);
    out[0] = a0 + (b0 - a0) * f;
    out[1] = a1 + (b1 - a1) * f;
    out[2] = a2 + (b2 - a2) * f;
    return true;
}

uint32_t blend_bone_count(const uint8_t* frame_a, uint32_t max_bones) {
    const uint8_t* skel = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(frame_a, FRAME_SKELETON));
    uint32_t n = rd<uint32_t>(skel, SKEL_COUNT);
    if (max_bones != 0 && max_bones < n) n = max_bones;
    return n;
}

uint32_t blend_local(const BlendArgs& a, float* out_pos, float* out_quat) {
    const uint32_t n = blend_bone_count(a.frame_a, a.max_bones);
    const AcosFn acos_fn = a.acos_fn;
    const bool partial = rd<uint8_t>(a.clip_header, HEADER_PARTIAL) == 1;
    const uint8_t* ref = partial ? reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.clip_holder, HOLDER_REFFRAME)) : nullptr;
    const uint8_t* posA0 = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.frame_a, FRAME_POS));
    const uint8_t* posB0 = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.frame_b, FRAME_POS));
    const uint8_t* posR0 = ref ? reinterpret_cast<const uint8_t*>(rd<uintptr_t>(ref, FRAME_POS)) : nullptr;
    const uint8_t* qA = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.frame_a, FRAME_QUAT));
    const uint8_t* qB = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.frame_b, FRAME_QUAT));
    const uint32_t limA = rd<uint32_t>(a.frame_a, FRAME_LIMIT);
    const uint32_t limB = rd<uint32_t>(a.frame_b, FRAME_LIMIT);
    const float t = a.t;

    for (uint32_t i = 0; i < n; ++i) {
        // Translation sources exactly as 0x10CE290 +0x9D..+0xB4.
        const uint8_t* pa;
        const uint8_t* pb;
        if (partial) {
            pa = (i >= limA ? posR0 : posA0) + (size_t)i * 12;
            pb = (i >= limB ? posR0 : posB0) + (size_t)i * 12;
        } else {
            pa = posA0 + (size_t)i * 12;
            pb = posB0 + (size_t)i * 12;
        }
        const Quat A = decode_quat(qA + (size_t)i * 8, a.sse2_quat_decode);
        Quat B = decode_quat(qB + (size_t)i * 8, a.sse2_quat_decode);
        float* P = out_pos + (size_t)i * 3;
        float* Q = out_quat + (size_t)i * 4;
        const float pa0 = rd<float>(pa, 0), pa1 = rd<float>(pa, 4), pa2 = rd<float>(pa, 8);
        const float pb0 = rd<float>(pb, 0), pb1 = rd<float>(pb, 4), pb2 = rd<float>(pb, 8);

        switch (a.mode) {
        case 0:
            if (0.5f <= t) {
                P[0] = pb0; P[1] = pb1; P[2] = pb2;
                Q[0] = B.x; Q[1] = B.y; Q[2] = B.z; Q[3] = B.w;
            } else {
                P[0] = pa0; P[1] = pa1; P[2] = pa2;
                Q[0] = A.x; Q[1] = A.y; Q[2] = A.z; Q[3] = A.w;
            }
            break;
        case 1:
        case 2:
        case 3: {
            P[0] = pa0 + (pb0 - pa0) * t;
            P[1] = pa1 + (pb1 - pa1) * t;
            P[2] = pa2 + (pb2 - pa2) * t;
            float d = dot4(B, A);
            if (a.mode == 1) {
                if (0.0f > d) B = Quat{neg(B.x), neg(B.y), neg(B.z), neg(B.w)};
                Q[0] = (B.x - A.x) * t + A.x;
                Q[1] = (B.y - A.y) * t + A.y;
                Q[2] = (B.z - A.z) * t + A.z;
                Q[3] = (B.w - A.w) * t + A.w;
                break;
            }
            if (0.0f > d) {
                B = Quat{neg(B.x), neg(B.y), neg(B.z), neg(B.w)};
                if (a.mode == 3) d = neg(d);
            }
            if (a.mode == 2) d = dot4(B, A);  // 0x10CE761+: mode 2 recomputes the dot after the sign fix-up
            // comiss d, thresh; jbe -> slerp; otherwise (B-A)*t + A with the same mulss/addss order as mode 1.
            const float thresh = (a.mode == 2) ? 0x1.FC6A7Ep-1f /*0x3F7E353F*/ : 0x1.333334p-2f /*0x3E99999A*/;
            if (d > thresh) {
                Q[0] = (B.x - A.x) * t + A.x;
                Q[1] = (B.y - A.y) * t + A.y;
                Q[2] = (B.z - A.z) * t + A.z;
                Q[3] = (B.w - A.w) * t + A.w;
            } else {
                const float theta = acos_fn(d);
                const float s0 = x87_sinf(theta);
                const float inv = 1.0f / s0;
                const float w1 = x87_sinf((1.0f - t) * theta) * inv;
                const float w2 = x87_sinf(theta * t) * inv;
                Q[0] = B.x * w2 + A.x * w1;
                Q[1] = B.y * w2 + A.y * w1;
                Q[2] = B.z * w2 + A.z * w1;
                Q[3] = B.w * w2 + A.w * w1;
            }
            break;
        }
        default:
            break;  // original: `ja 0x10CEB58`, bone skipped
        }
    }
    return n;
}

void compose_global(const uint8_t* bone_table, uint32_t n, const float* pos, const float* quat, float* out) {
    constexpr float K0 = 0.0f, K1 = 0.0f, K2 = 0.0f, K3 = 1.0f;  // _DAT_01402EB0 = (0,0,0,1)
    const float one = 1.0f;
    for (uint32_t i = 0; i < n; ++i) {
        const float x = quat[i * 4 + 0], y = quat[i * 4 + 1], z = quat[i * 4 + 2], w = quat[i * 4 + 3];
        const float tx = pos[i * 3 + 0], ty = pos[i * 3 + 1], tz = pos[i * 3 + 2];
        const float x2 = x + x, y2 = y + y, z2 = z + z;
        float* o = out + (size_t)i * 12;
        const int32_t parent = rd<int32_t>(bone_table, BONE_PARENT + i * BONE_STRIDE);
        if (parent < 0) {
            const float wz = w * z2, wy = w * y2, wx = w * x2;
            const float m_wz = wz;           // + (0x1402E44 lane = +0)
            const float m_wy = neg(wy);      // 0x1402E48 lane = -0
            const float m_wx = neg(wx);      // 0x1402E4C lane = -0
            const float omzz = neg(z * z2) + one;  // (z*z2 ^ -0) + 1
            const float n_y2x = neg(y2 * x);
            const float n_z2x = neg(z2 * x);
            const float n_z2y = neg(z2 * y);
            const float f24 = omzz;                // ^ 0
            const float f25 = neg(m_wz);           // ^ -0
            const float f26 = neg(m_wy);
            const float f29 = neg(m_wx);
            o[0] = omzz - (y * y2);
            o[1] = f25 - n_y2x;
            o[2] = f26 - n_z2x;
            o[3] = tx;
            o[4] = m_wz - n_y2x;
            o[5] = f24 - x * x2;
            o[6] = m_wx - n_z2y;
            o[7] = ty;
            o[8] = m_wy - n_z2x;
            o[9] = f29 - n_z2y;
            o[10] = (one - x * x2) - y2 * y;
            o[11] = tz;
        } else {
            const float* p = out + (size_t)parent * 12;
            const float wz = w * z2, wy = w * y2, wx = w * x2;
            const float f16 = wz;        // lane +0
            const float f17 = neg(wy);
            const float f15 = neg(wx);
            const float f32 = neg(z * z2) + one;
            const float f25 = (one - x * x2) - y * y2;
            const float f26 = neg(y2 * x);
            const float f27 = neg(z2 * x);
            const float f30 = neg(z2 * y);
            const float f37 = f32 - (y2 * y);
            const float f38 = f16 - f26;
            const float f39 = f17 - f27;
            const float f40 = f15 - f30;
            const float f33 = f32 - x * x2;
            const float g26 = neg(f16) - f26;
            const float g27 = neg(f17) - f27;
            const float g30 = neg(f15) - f30;
            // rows of the parent, each: x*c0 + y*c1 + z*c2 + w*K  (order ((y*c1 + x*c0) + z*c2) + w*K)
            for (int r = 0; r < 3; ++r) {
                const float px = p[r * 4 + 0], py = p[r * 4 + 1], pz = p[r * 4 + 2], pw = p[r * 4 + 3];
                o[r * 4 + 0] = py * f38 + px * f37 + pz * f39 + pw * K0;
                o[r * 4 + 1] = py * f33 + px * g26 + pz * g30 + pw * K1;
                o[r * 4 + 2] = py * f40 + px * g27 + pz * f25 + pw * K2;
                o[r * 4 + 3] = py * ty + px * tx + pz * tz + pw * K3;
            }
        }
    }
}

void run_pose_job(PoseJob& j) {
    const uint8_t* const* frames = reinterpret_cast<const uint8_t* const*>(rd<uintptr_t>(j.clip, CLIP_FRAME_ARRAY));
    j.ok = locate_frames(j.clip, j.time, j.no_wrap, &j.i0, &j.i1, &j.frac);
    if (!j.ok) return;
    BlendArgs a{};
    a.frame_a = frames[j.i0];
    a.frame_b = frames[j.i1];
    a.t = j.frac;
    a.mode = j.mode;
    a.clip_holder = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(j.clip, CLIP_HOLDER));
    a.clip_header = j.clip + CLIP_HEADER;
    a.max_bones = j.max_bones;
    a.sse2_quat_decode = j.sse2_quat_decode;
    a.acos_fn = j.acos_fn;
    j.out_bones = blend_local(a, j.out_pos, j.out_quat);
    const uint8_t* skel = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(a.frame_a, FRAME_SKELETON));
    const uint8_t* table = reinterpret_cast<const uint8_t*>(rd<uintptr_t>(skel, SKEL_TABLE));
    compose_global(table, j.out_bones, j.out_pos, j.out_quat, j.out_mats);
}

}  // namespace ntw_anim
