// See ntw2_ai_ctrl_geometry.h.  x86 MSVC host code (naked trampolines + inline asm), owner thread only.
#include "ntw2_ai_ctrl_geometry.h"
#include "ntw2_ai_ctrl_batch.h"
#include "clones/ntw2_clones.h"
#include <cstring>

namespace ntw2_ai_ctrl_geometry {
namespace {
using U = uint32_t;

struct Entry {          // one slot per list index; valid only for the V it was filled for
    U v;
    U idStamp, id;      // id(V+0x10), valid when idStamp == g_gen
    U poseStamp, px, pz;  // world X/Z bits of V's pose (80E9D0 out[0], out[2]), valid when poseStamp == g_gen
    U distStamp, dist;  // 0x76DCD0(R, pose) bits, valid when distStamp == g_dgen
};
struct Pair { U r, u, stamp; };

constexpr U kPairSlots = 4096;
constexpr U kPairProbe = 16;
constexpr U kModeCensus = 1, kModeLive = 2, kModeVerify = 4;

Entry g_e[kCapacity];
Pair g_pairs[kPairSlots];
Status g_st;
U g_mode, g_off;
U g_epoch = ~0u;
U g_gen = 1, g_dgen = 1;      // g_gen: batch validity (identity/pose/candidate/pairs); g_dgen: g_gen AND current R
U g_rValid, g_r, g_rx, g_rz;  // the R the distance stamps belong to (pointer + its center words)
U g_candGen, g_candThis, g_candId, g_candGate;
U g_imageBase, g_getter, g_f53fbe0, g_f80e9d0, g_f76dcd0;

inline U Rd(U address) { return *reinterpret_cast<const U*>(address); }

using SlotFn = U(__thiscall*)(U);
using LeaFn = U(__thiscall*)(U);
using PoseFn = U(__thiscall*)(U, float*);
using DistFn = float(__thiscall*)(U, const float*);

void Bump() {
    if (++g_gen == 0) { std::memset(g_e, 0, sizeof g_e); std::memset(g_pairs, 0, sizeof g_pairs); g_gen = 1; }
    if (++g_dgen == 0) { std::memset(g_e, 0, sizeof g_e); g_dgen = 1; }
    g_rValid = 0; g_candGen = 0;
}
void Retire(uint32_t) { g_epoch = ~0u; Bump(); }

// Open batch with a valid cache generation.
inline bool Ensure() {
    const AiCtrlBatch* b = ai_ctrl_batch_current();
    if (!b->open) return false;
    if (b->epoch != g_epoch) { g_epoch = b->epoch; Bump(); }
    return true;
}

// ---- native references (same order and instructions the clone's original span executes) ----
inline U NativeId(U object) {   // call [[object]] with ecx = object
    return reinterpret_cast<SlotFn>(Rd(Rd(object)))(object);
}
// 0x7B1497..0x7B14B3: F=[V+ADC]; Q=53FBE0(F+62C); 80E9D0(Q,out) -> pointer to out; X=out[0], Z=out[2].
inline void NativePose(U v, U& px, U& pz) {
    float out[3];
    const U q = reinterpret_cast<LeaFn>(g_f53fbe0)(Rd(v + 0xADC) + 0x62C);
    const U p = reinterpret_cast<PoseFn>(g_f80e9d0)(q, out);
    px = Rd(p); pz = Rd(p + 8);
}
inline U NativeDistanceBits(U v, U r) {
    U px, pz; NativePose(v, px, pz);
    float pt[2]; std::memcpy(&pt[0], &px, 4); std::memcpy(&pt[1], &pz, 4);
    const float d = reinterpret_cast<DistFn>(g_f76dcd0)(r, pt);
    U bits; std::memcpy(&bits, &d, 4); return bits;
}

inline Entry* Slot(U i, U v) {
    Entry* e = &g_e[i];
    if (e->v != v) { std::memset(e, 0, sizeof *e); e->v = v; }
    return e;
}
inline void Mismatch() { ++g_st.dist_mismatch; g_off = 1; }

// Census: (R, U) pairs scored in one batch (region-boundary 0x5C3250 reuse key; count only).
void NotePair(U r, U u) {
    const U h = ((r >> 4) * 2654435761u) ^ ((u >> 4) * 40503u);
    for (U k = 0; k < kPairProbe; ++k) {
        Pair& p = g_pairs[(h + k) & (kPairSlots - 1)];
        if (p.stamp != g_gen) { p.r = r; p.u = u; p.stamp = g_gen; return; }
        if (p.r == r && p.u == u) { ++g_st.boundary_repeat; return; }
    }
}
}  // namespace

uint32_t PointDistanceBits(uint32_t rx, uint32_t rz, uint32_t px, uint32_t pz) {
    uint32_t result;
    __asm {
        movss xmm1, dword ptr [rx]
        movss xmm0, dword ptr [rz]
        subss xmm1, dword ptr [px]
        subss xmm0, dword ptr [pz]
        mulss xmm1, xmm1
        mulss xmm0, xmm0
        addss xmm1, xmm0
        movss dword ptr [result], xmm1
    }
    return result;
}

uint32_t __fastcall IdentityStep(uint32_t v, uint32_t uThis, uint32_t i, uint32_t r, uint32_t* idU) {
    if (!g_mode || g_off) { *idU = NativeId(uThis); return NativeId(v + 0x10); }
    ++g_st.id_calls;
    const bool open = Ensure();
    if (open && i == 0) { NotePair(r, uThis - 0x10); ai_ctrl_batch_set_region(reinterpret_cast<void*>(r)); }
    if (!(g_mode & kModeLive) || !open || i >= kCapacity) { *idU = NativeId(uThis); return NativeId(v + 0x10); }

    bool served = true;
    // Candidate identity: hoisted per candidate within the batch (gate = vtable slot 0 is the 0x57E910 getter).
    if (g_candGen == g_gen && g_candThis == uThis) {
        if (g_candGate) *idU = g_candId; else { *idU = NativeId(uThis); served = false; }
    } else {
        g_candGen = g_gen; g_candThis = uThis;
        g_candGate = Rd(Rd(uThis)) == g_getter;
        if (g_candGate) { g_candId = Rd(uThis - 0xC); *idU = g_candId; } else { *idU = NativeId(uThis); served = false; }
    }
    if ((g_mode & kModeVerify) && g_candGate) {
        const U nat = NativeId(uThis);
        if (nat != *idU) { Mismatch(); *idU = nat; served = false; }
    }
    // List identity: gathered once per V (first use), then served by index.
    const U vThis = v + 0x10;
    Entry* e = Slot(i, v);
    U idV;
    if (e->idStamp == g_gen) {
        idV = e->id;
        if (g_mode & kModeVerify) {
            const U nat = NativeId(vThis);
            if (nat != idV) { Mismatch(); idV = nat; served = false; }
        }
    } else if (Rd(Rd(vThis)) == g_getter) {
        idV = Rd(vThis - 0xC);
        e->id = idV; e->idStamp = g_gen;
        served = false;   // first use of this V: the gather itself is the native-equivalent work
    } else {
        idV = NativeId(vThis); served = false;
    }
    if (served && !g_off) ++g_st.id_served;
    return idV;
}

uint32_t __fastcall DistanceStep(uint32_t v, uint32_t r, uint32_t i) {
    if (!g_mode || g_off) return NativeDistanceBits(v, r);
    ++g_st.dist_calls;
    const bool open = Ensure();
    if (!open || i >= kCapacity) return NativeDistanceBits(v, r);
    const U rx = Rd(r + 8), rz = Rd(r + 0xC);
    if (!g_rValid || g_r != r || g_rx != rx || g_rz != rz) {
        g_r = r; g_rx = rx; g_rz = rz; g_rValid = 1;
        if (++g_dgen == 0) { std::memset(g_e, 0, sizeof g_e); g_dgen = 1; }
    }
    Entry* e = Slot(i, v);
    if (!(g_mode & kModeLive)) {                      // census: native executes, keys are only counted
        const U bits = NativeDistanceBits(v, r);
        if (e->distStamp != g_dgen) { e->distStamp = g_dgen; ++g_st.distinct_rv; }
        return bits;
    }
    U bits;
    if (e->distStamp == g_dgen) {
        bits = e->dist;
        ++g_st.dist_served; ++g_st.pose_served;
    } else {
        U px, pz;
        if (e->poseStamp == g_gen) { px = e->px; pz = e->pz; ++g_st.pose_served; }
        else { NativePose(v, px, pz); e->px = px; e->pz = pz; e->poseStamp = g_gen; }
        bits = PointDistanceBits(rx, rz, px, pz);
        e->dist = bits; e->distStamp = g_dgen;
        ++g_st.distinct_rv;
    }
    if (g_mode & kModeVerify) {
        const U nat = NativeDistanceBits(v, r);
        if (nat != bits) { Mismatch(); return nat; }
    }
    return bits;
}

// In EAX=V, EDX=ECX=U+0x10, EBX=i, caller [ESP+0x18]=R (at entry [ESP+0x1C]).  Out EDI=V+0x10, ESI=id(U), EAX=id(V).
__declspec(naked) static void IdentityBinding() {
    __asm {
        lea edi, [eax + 0x10]
        mov ecx, eax
        mov esi, dword ptr [esp + 0x1C]
        push 0
        lea eax, [esp]
        push eax
        push esi
        push ebx
        call IdentityStep
        pop esi
        ret
    }
}
// In EBX=i, caller [ESP+0x24]=V, [ESP+0x18]=R (at entry +4).  Out ST(0) = distance float32.
__declspec(naked) static void DistanceBinding() {
    __asm {
        mov ecx, dword ptr [esp + 0x28]
        mov edx, dword ptr [esp + 0x1C]
        push ebx
        call DistanceStep
        push eax
        fld dword ptr [esp]
        add esp, 4
        ret
    }
}
void* IdentityBindingAddress() { return reinterpret_cast<void*>(&IdentityBinding); }
void* DistanceBindingAddress() { return reinterpret_cast<void*>(&DistanceBinding); }

bool Bind(uint32_t imageBase, uint32_t* bindings) {
    if (!imageBase) return false;
    g_imageBase = imageBase;
    const U d = imageBase - 0x400000u;
    g_getter = 0x57E910u + d; g_f53fbe0 = 0x53FBE0u + d; g_f80e9d0 = 0x80E9D0u + d; g_f76dcd0 = 0x76DCD0u + d;
    bindings[NTW2_BIND_AI_CTRL_IDENTITY] = reinterpret_cast<U>(&IdentityBinding);
    bindings[NTW2_BIND_AI_CTRL_POINT_DISTANCE] = reinterpret_cast<U>(&DistanceBinding);
    return true;
}
void Configure(bool census, bool live, bool verify) {
    g_mode = (census ? kModeCensus : 0u) | (live ? kModeLive : 0u) | ((live && verify) ? kModeVerify : 0u);
    g_off = 0; g_epoch = ~0u;
    Bump();
    if (g_mode) ai_ctrl_batch_register_retire(&Retire);
}
void Reset() {
    std::memset(&g_st, 0, sizeof g_st); std::memset(g_e, 0, sizeof g_e); std::memset(g_pairs, 0, sizeof g_pairs);
    g_off = 0; g_epoch = ~0u; g_gen = 1; g_dgen = 1; g_rValid = 0; g_candGen = 0;
}
void FillStatus(uint32_t words[kStatusWords]) { std::memcpy(words, &g_st, sizeof g_st); }
bool Latched() { return g_off != 0; }
bool CachedPose(uint32_t i, uint32_t v, uint32_t* px, uint32_t* pz) {
    if (i >= kCapacity || g_e[i].v != v || g_e[i].poseStamp != g_gen) return false;
    *px = g_e[i].px; *pz = g_e[i].pz; return true;
}

}  // namespace ntw2_ai_ctrl_geometry
