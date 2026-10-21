#include "native_contact.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <string.h>

// Exact transcription of the decided part of 0x64CAD0 and its pure callees. Every SSE step is
// the original scalar instruction with the original (destination, source) operand order, so NaN
// payload selection matches as well; x87 FPATAN/FISTP/FABS run as the original instructions under
// the installed control word. Evidence: analysis/native-contact-response.md.
#pragma float_control(precise, on, push)
namespace kntwr_contact {
namespace {
using B = unsigned char;
U delta, mode;
volatile LONG words[WordCount];
ULONGLONG portTicks, ownerTicks;
LARGE_INTEGER frequency;
U stageNumber;

template<class T> __forceinline T L(U address, U offset) { return *reinterpret_cast<const volatile T*>(address + offset); }
__forceinline U Va(U preferred) { return preferred + delta; }
__forceinline float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
__forceinline float Mul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
// COMISS a,b then JA / JAE: false for unordered operands.
__forceinline bool Greater(float a, float b) { return _mm_comigt_ss(_mm_set_ss(a), _mm_set_ss(b)) != 0; }
__forceinline bool GreaterEqual(float a, float b) { return _mm_comige_ss(_mm_set_ss(a), _mm_set_ss(b)) != 0; }
// FLD x; FLD z; FPATAN; FSTP dword: atan2(x, z) rounded by the x87 precision control, then spilled.
float Angle(float x, float z) {
    float result;
    __asm { fld x }
    __asm { fld z }
    __asm { fpatan }
    __asm { fstp result }
    return result;
}
// MULSS by the angle scale, spill, FLD, FISTP dword under the current rounding control.
int Quantize(float angle, float scale) {
    float scaled = Mul(angle, scale);
    int result;
    __asm { fld scaled }
    __asm { fistp result }
    return result;
}
float AbsX87(float value) {
    __asm { fld value }
    __asm { fabs }
    __asm { fstp value }
    return value;
}
void Bump(U word, U amount = 1) { _InterlockedExchangeAdd(&words[word], static_cast<LONG>(amount)); }
ULONGLONG Clock() { LARGE_INTEGER v; QueryPerformanceCounter(&v); return static_cast<ULONGLONG>(v.QuadPart); }
U Micros(ULONGLONG ticks) { return frequency.QuadPart ? static_cast<U>(ticks * 1000000 / frequency.QuadPart) : 0; }

// 0x7FA690: low 16 bits of the difference -> |int16| (0x8000 stays +32768) -> one - 2*(n*factor).
float FacingImpl(const Stage& st, U difference) {
    uint16_t w = static_cast<uint16_t>(difference);
    if (static_cast<int16_t>(w) < 0) w = static_cast<uint16_t>(0u - w);
    int n = w == 0x8000 ? 0x8000 : static_cast<int>(static_cast<int16_t>(w));
    float f = _mm_cvtss_f32(_mm_cvtsi32_ss(_mm_setzero_ps(), n));
    f = Mul(f, st.headingFactor);
    f = Add(f, f);
    return Sub(st.one, f);
}
// Virtual stubs proven for the supported LAND tables / node classes: 0x462CB0 returns AL=0,
// 0x447880 returns AL=1, 0x5DB820 returns [this+0x67C]!=0. Anything else is unsupported.
U StubResult(const Stage& st, U slot, U self, bool& supported) {
    if (slot == st.stubFalse) return 0;
    if (slot == st.stubTrue) return 1;
    if (slot == st.stubOwner) return L<U>(self, 0x67C) != 0;
    supported = false;
    return 0;
}
U ManagerBit(U bits, U serial) { return (L<U>(bits, (serial >> 5) * 4) >> (serial & 31)) & 1; }
}

namespace port {
XZ SlotPosition(U p) {
    U m = L<U>(p, 0x10);
    if (!m) return { L<float>(p, 0), L<float>(p, 8) };
    float v0 = L<float>(p, 0), v1 = L<float>(p, 4), v2 = L<float>(p, 8);
    float x = Add(Add(Add(Mul(L<float>(m, 0xa0), v1), Mul(L<float>(m, 0x9c), v0)), Mul(L<float>(m, 0xa4), v2)), L<float>(m, 0x80));
    float z = Add(Add(Add(Mul(L<float>(m, 0xb8), v1), Mul(v0, L<float>(m, 0xb4))), Mul(L<float>(m, 0xbc), v2)), L<float>(m, 0x88));
    return { x, z };
}
bool Gate(U a) { return L<B>(a, 0x118) == 1 && ((L<B>(a, 0x110) & 1) || L<B>(a, 0x117) == 0); }
bool Blocks(const Stage& st, U x, U y) {
    if (L<B>(x, 0x117) || (L<B>(x, 0x110) & 1)) return false;
    XZ q = SlotPosition(x + 0x160);
    float xr = L<float>(x, 0x58), yr = L<float>(y, 0x58);
    float dx = Sub(L<float>(y, 0x48), q.x), dz = Sub(L<float>(y, 0x50), q.z);
    float sum = Add(xr, yr);
    float d2 = Add(Mul(dx, dx), Mul(dz, dz));
    if (!Greater(Mul(sum, sum), d2)) return false;
    U shape = L<U>(y, 0x60);
    if (!shape) return true;
    U angle = static_cast<U>(Quantize(Angle(dx, dz), st.angleScale));
    U index = static_cast<uint16_t>(static_cast<uint16_t>(angle - L<uint16_t>(y, 0x64)) + st.headingBias) >> 8;
    float scaled = Add(Mul(L<float>(L<U>(shape, 0x18), index * 4), yr), xr);
    return Greater(Mul(scaled, scaled), d2);
}
bool BlocksUnlessLinked(const Stage& st, U x, U y) {
    if (y == L<U>(x, 0x1ec) || y == L<U>(x, 0x5b8)) return false;
    return Blocks(st, x, y);
}
uint16_t Heading(const Stage& st, U a) {
    if (L<B>(a, 0x117)) return L<uint16_t>(a, 0x64);
    XZ q = SlotPosition(a + 0x160);
    float dx = Sub(q.x, L<float>(a, 0x48)), dz = Sub(q.z, L<float>(a, 0x50));
    if (!Greater(Add(Mul(dx, dx), Mul(dz, dz)), st.minDistance)) return L<uint16_t>(a, 0x64);
    return static_cast<uint16_t>(Quantize(Angle(dx, dz), st.angleScale));
}
bool Far(U a, float px, float pz) {
    if (L<B>(a, 0x118) != 1) return true;
    U bit = L<U>(a, 0x110) & 1;
    if (!bit && L<B>(a, 0x117) != 0) return true;
    if (bit) return false;
    float ax = L<float>(a, 0x48), az = L<float>(a, 0x50);
    XZ q = SlotPosition(a + 0x160);
    float sx = Sub(q.x, ax), sz = Sub(q.z, az), tx = Sub(px, ax), tz = Sub(pz, az);
    float slot = Add(Mul(sx, sx), Mul(sz, sz)), target = Add(Mul(tx, tx), Mul(tz, tz));
    return Greater(target, slot);
}
float Facing(const Stage& st, U difference) { return FacingImpl(st, difference); }
void Facings(const Stage& st, U r, U s, float out[4]) {
    out[0] = out[1] = out[2] = out[3] = -1.0f;
    bool gr = Gate(r), gs = Gate(s);
    if (!gr && !gs) return;
    float sx = L<float>(s, 0x48), sz = L<float>(s, 0x50), rx = L<float>(r, 0x48), rz = L<float>(r, 0x50);
    float dx = Sub(sx, rx), dz = Sub(sz, rz);
    U angle = static_cast<U>(Quantize(Angle(dx, dz), st.angleScale));
    U hr = Heading(st, r), hs = Heading(st, s);
    if (gr && (gs || !Far(r, sx, sz))) out[2] = FacingImpl(st, hr - angle);
    if (gs && (gr || !Far(s, rx, rz))) out[3] = FacingImpl(st, hs - static_cast<uint16_t>(angle + st.headingBias));
    if (gr && gs) {
        float v = FacingImpl(st, hr - hs);
        out[0] = _mm_cvtss_f32(_mm_xor_ps(_mm_set_ss(v), _mm_castsi128_ps(_mm_cvtsi32_si128(static_cast<int>(0x80000000u)))));
        float a = out[2], b = out[3];
        if ((Greater(a, 0) && Greater(b, 0)) || (Greater(0, a) && Greater(0, b))) out[1] = Mul(Add(a, b), st.half);
        else out[1] = Mul(a, b);
    } else if (gr) out[0] = out[1] = out[2];
    else out[0] = out[1] = out[3];
}
U Classify(const Stage& st, U r, U s, bool& supported) {
    if (L<U>(r, 0x3c) == L<U>(s, 0x2c) || L<U>(s, 0x3c) == L<U>(r, 0x2c)) return 4;
    bool skipToR117 = false, skipToR458 = false;
    if (L<B>(r, 0x118) == 1) {
        if (L<B>(r, 0x110) & 1) skipToR117 = true;
        else if (L<B>(r, 0x117) == 0) skipToR458 = true;
    }
    if (!skipToR117 && !skipToR458) {
        if (L<B>(s, 0x118) != 1) return 4;
        if (!(L<B>(s, 0x110) & 1) && L<B>(s, 0x117) != 0) return 4;
    }
    if (skipToR458 || L<B>(r, 0x117) == 0) {
        if (L<B>(r, 0x458) == 1) return 4;
    }
    if (L<B>(s, 0x117) == 0 && L<B>(s, 0x458) == 1) return 4;
    if (L<U>(r, 0x1ec) == s && (Gate(s) || L<U>(s, 0x444) != 0)) return 4;
    if (L<U>(s, 0x1ec) == r && (Gate(r) || L<U>(r, 0x444) != 0)) return 4;
    bool bl = BlocksUnlessLinked(st, r, s), bh = BlocksUnlessLinked(st, s, r);
    if (bl) { if (!Gate(s) || bh) return 4; }
    else if (bh && !Gate(r)) return 4;
    float o[4]; Facings(st, r, s, o);
    if (Greater(o[0], 0)) return Greater(o[1], 0) ? 1 : 4;
    if (!Gate(r) || !Gate(s)) return 4;
    uint16_t d = static_cast<uint16_t>(L<uint16_t>(r, 0x64) - L<uint16_t>(s, 0x64));
    if (static_cast<int16_t>(d) < 0) d = static_cast<uint16_t>(0u - d);
    int diff = d == 0x8000 ? 0x8000 : static_cast<int>(static_cast<int16_t>(d));
    uint16_t g = st.angleGate;
    int gate = g == 0x8000 ? 0x8000 : static_cast<int>(static_cast<int16_t>(g));
    if (diff >= gate) return 4;
    U unit = L<U>(r, 0x1f0);
    bool flag = true;
    if (unit && unit == L<U>(s, 0x1f0)) flag = StubResult(st, L<U>(L<U>(r, 0), 0xf0), r, supported) != 1;
    if (Greater(o[2], 0)) {
        float rv = L<float>(r, 0x10c);
        if (!Greater(rv, Mul(L<float>(s, 0x10c), st.dominance))) return 4;
        if (!flag && L<B>(s, 0x458) != 0) return 4;
        if (L<B>(r, 0x117) == 1 || L<B>(s, 0x117) == 1) return 2;
        float lead = L<float>(r, 0x144);
        if (Greater(lead, L<float>(s, 0x144))) return 2;
        return Greater(lead, Mul(rv, st.lead)) ? 2 : 4;
    }
    if (!Greater(o[3], 0)) return 4;
    float sv = L<float>(s, 0x10c);
    if (!Greater(sv, Mul(L<float>(r, 0x10c), st.dominance))) return 4;
    if (!flag && L<B>(r, 0x458) != 0) return 4;
    if (L<B>(r, 0x117) == 1 || L<B>(s, 0x117) == 1) return 3;
    float lead = L<float>(s, 0x144);
    if (Greater(lead, L<float>(r, 0x144))) return 3;
    return Greater(lead, Mul(sv, st.lead)) ? 3 : 4;
}
bool Available(U manager, U a) {
    if (L<B>(a, 0xec) != 1 || L<B>(a, 0xb4) != 0 || L<U>(a, 0x18) != 0) return false;
    if (ManagerBit(L<U>(manager, 0x90), L<U>(a, 0x2c))) return false;
    U state = L<U>(a, 0x224);
    if (state == 5) return (L<B>(a, 0xef) | L<B>(a, 0xee)) != 1;
    if ((state >= 0xe && state <= 0x14) || state == 4) return false;
    return true;
}
bool Overlap(const Stage& st, U r, U s) {
    using Radius = unsigned char (__cdecl*)(float*, U, U, float, float, float, float, U, U);
    float dz = Sub(L<float>(s, 0x50), L<float>(r, 0x50)), dx = Sub(L<float>(s, 0x48), L<float>(r, 0x48));
    float rr = L<float>(r, 0x58), rs = L<float>(s, 0x58);
    float sum = Add(rr, rs);
    float threshold = Mul(sum, sum);
    if (reinterpret_cast<Radius>(st.leaf)(&threshold, L<U>(r, 0x60), L<U>(s, 0x60), dx, dz, rr, rs,
            L<uint16_t>(r, 0x64), L<uint16_t>(s, 0x64))) {
        if (!Greater(threshold, Add(Mul(dx, dx), Mul(dz, dz)))) return false;
    }
    float dy = Sub(L<float>(r, 0x4c), L<float>(s, 0x4c));
    float extent = Greater(0, dy) ? L<float>(r, 0x54) : L<float>(s, 0x54);
    return Greater(extent, AbsX87(dy));
}
bool Avoid(const Stage& st, U manager, U r, U s, bool& supported) {
    if (!Available(manager, r) || !Available(manager, s)) return false;
    if (L<U>(r, 0x1b8) == 0xd || L<U>(s, 0x1b8) == 0xd) return false;
    U group = L<U>(r, 0x178);
    if (group && group == L<U>(s, 0x178)) return false;
    U unit = L<U>(r, 0x1f0);
    if (unit && unit == L<U>(s, 0x1f0)) {
        if (StubResult(st, L<U>(L<U>(r, 0x22c), 0x20), r + 0x22c, supported) == 1) return false;
        if (StubResult(st, L<U>(L<U>(s, 0x22c), 0x20), s + 0x22c, supported) == 1) return false;
    }
    if (Classify(st, r, s, supported) == 4) return false;
    return Overlap(st, r, s);
}
bool TrackerDistance(const Stage& st, U a, U b) {
    float radius = Add(Add(L<float>(a, 0x58), L<float>(b, 0x58)), st.two);
    float dx = Sub(L<float>(a, 0x48), L<float>(b, 0x48)), dz = Sub(L<float>(a, 0x50), L<float>(b, 0x50));
    float d2 = Add(Mul(dx, dx), Mul(dz, dz));
    return GreaterEqual(Mul(radius, radius), d2); // COMISS radius2,d2; JB rejects (unordered too)
}
}

namespace {
void PredictBody(const Stage& st, Plan& p, U r, U s) {
    using namespace port;
    // Class identity first: a foreign receiver/argument may be a smaller object, so no LAND
    // field is read (no first-chance fault) unless both tables are the LAND pair.
    if (L<U>(L<U>(s, 0), 0x44) != st.thunk44 || L<U>(L<U>(r, 0), 0x40) != st.callback40) {
        p.kind = KindForeign; return;
    }
    U tr = L<U>(r, 0x388), ts = L<U>(s, 0x388);
    p.trackerR = tr ? tr + 0x74c : 0; p.trackerS = ts ? ts + 0x74c : 0;
    p.keyR = L<uint16_t>(r, 0x2c); p.keyS = L<uint16_t>(s, 0x2c);
    uint16_t flags = 0;
    if (L<U>(r, 0x1f0)) flags |= FlagRUnit;
    if (L<U>(s, 0x1f0)) flags |= FlagSUnit;
    if (L<U>(r, 0x44) != L<U>(s, 0x44)) {
        // Different teams stay owner-original; their tracker distance gates feed the shadow only.
        if (TrackerDistance(st, r, s)) flags |= FlagDistR;
        if (TrackerDistance(st, s, r)) flags |= FlagDistS;
        p.flags = flags; p.kind = KindDiffTeam; return;
    }
    if (L<U>(L<U>(r, 0x28), 8) != st.model) { p.flags = flags; p.kind = KindUnsupported; return; }
    if (ManagerBit(st.avoidBits, L<U>(r, 0x2c))) flags |= FlagBitR;
    if (ManagerBit(st.avoidBits, L<U>(s, 0x2c))) flags |= FlagBitS;
    bool supported = true;
    bool bh = BlocksUnlessLinked(st, r, s), al = BlocksUnlessLinked(st, s, r);
    bool bl = true, avoid = false;
    if (bh) {
        if (!Gate(s) || al) { flags |= FlagWriteR; bl = false; }
        else avoid = true;
    }
    if (!avoid) {
        if (al && (!Gate(r) || bh)) { flags |= FlagWriteS; bl = false; }
        else if (bl) avoid = true;
    }
    if (avoid) {
        flags |= FlagUsedAvail;
        if (Avoid(st, st.avoid, r, s, supported)) {
            U fr = L<U>(r, 0x110), fs = L<U>(s, 0x110);
            bool writeS = false;
            if (!(fr & 1) && (fr & 0x800)) { flags |= FlagWriteR; bl = false; }
            if (!(fs & 1) && (fs & 0x800)) { flags |= FlagWriteS; writeS = true; }
            if (!writeS && bl) flags |= FlagAvoid;
        }
    }
    p.flags = flags; p.kind = supported ? KindPort : KindUnsupported;
}
// 0x52EDB0 tracker effect of the same-team arm: bit test/set by B's key, u16 append through the
// original 0x56EE80 (owner only; it may allocate through the game allocator).
bool Track(U tracker, uint16_t key) {
    volatile U* word = reinterpret_cast<volatile U*>(tracker + 0x20 + (key >> 5) * 4);
    U bit = 1u << (key & 31);
    if (*word & bit) return false;
    *word = *word | bit;
    using Append = void (__thiscall*)(void*, const void*);
    U value = key;
    reinterpret_cast<Append>(Va(0x56ee80))(reinterpret_cast<void*>(tracker + 0x2024), &value);
    return true;
}
void Mismatch(U index, U kind, U r, U s) {
    Bump(Mismatches);
    if (!words[FirstMismatchKind]) {
        words[FirstMismatchStage] = static_cast<LONG>(stageNumber);
        words[FirstMismatchContact] = static_cast<LONG>(index);
        words[FirstMismatchR] = static_cast<LONG>(r - delta);
        words[FirstMismatchS] = static_cast<LONG>(s - delta);
        words[FirstMismatchKind] = static_cast<LONG>(kind);
    }
}
enum MismatchBit : U { MissWriteR = 1, MissWriteS = 2, MissAvoid = 4, MissTracker = 8, MissPair = 0x10 };
// One 0x52EDB0 side as observed around the original callback.
struct Side {
    U tracker, a, b, word, before, count, pairs, unit, slot, slotCount; uint16_t key; B fiveEc; bool active;
};
void CaptureSide(Side& side, U tracker, U a, U b, uint16_t key) {
    side = {};
    side.tracker = tracker; side.a = a; side.b = b; side.key = key; side.active = tracker != 0;
    if (!tracker) return;
    side.word = tracker + 0x20 + (key >> 5) * 4;
    side.before = L<U>(side.word, 0);
    side.count = L<U>(tracker, 0x2024 + 8);
    side.pairs = L<U>(tracker, 8);
    side.fiveEc = L<B>(a, 0x5ec);
    side.unit = L<U>(b, 0x1f0);
    side.slot = 0xffffffffu;
    U data = L<U>(tracker, 0xc);
    for (U n = 0; n < side.pairs; ++n) if (L<U>(data, n * 12) == side.unit) { side.slot = n; side.slotCount = L<U>(data, n * 12 + 4); break; }
}
}

void Start(U image_delta, U requested) {
    delta = image_delta; mode = requested;
    for (U i = 0; i < WordCount; ++i) words[i] = 0;
    words[Version] = kVersion; words[ModeWord] = static_cast<LONG>(requested);
    portTicks = ownerTicks = 0; stageNumber = 0;
    QueryPerformanceFrequency(&frequency);
}
U CurrentMode() { return mode; }
bool BeginStage(Stage& st, void* modelPointer) {
    if (!mode || !modelPointer) return false;
    ++stageNumber; Bump(Stages);
    memset(&st, 0, sizeof(st));
    st.delta = delta;
    st.model = static_cast<U>(reinterpret_cast<uintptr_t>(modelPointer));
    __try {
        st.avoid = L<U>(st.model, 0xcc); st.combat = L<U>(st.model, 0xc8);
        if (!st.avoid) return false;
        st.avoidBits = L<U>(st.avoid, 0x90);
        U table = L<U>(st.avoid, 0);
        words[AvoidVtable] = static_cast<LONG>(table - delta);
        words[AvoidSlot14] = static_cast<LONG>(L<U>(table, 0x14) - delta);
        words[CombatVtable] = static_cast<LONG>(st.combat ? L<U>(st.combat, 0) - delta : 0);
        // Identity pins: the manager built by 0x61A9C0 (vtable 0x1334234) whose slot +0x14 is
        // 0x629140 -> 0x629240, the queue append that Shadow observes and Replay calls. Anything
        // else runs every contact of this stage through the original callback.
        if (table != Va(0x1334234) || L<U>(table, 0x14) != Va(0x629140)) { Bump(IdentityRefusals); return false; }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    st.callback40 = Va(0x64cad0); st.thunk44 = Va(0x64cc70);
    st.stubFalse = Va(0x462cb0); st.stubTrue = Va(0x447880); st.stubOwner = Va(0x5db820); st.leaf = Va(0x81a670);
    // Runtime .data/.bss words, sampled at stage entry and checked again in EndStage.
    st.headingBias = L<uint16_t>(Va(0x150fbc4), 0); st.angleGate = L<uint16_t>(Va(0x14d0844), 0);
    // File-backed .rdata constants (pinned by the generator).
    st.two = L<float>(Va(0x1325d14), 0); st.one = L<float>(Va(0x1318048), 0);
    st.angleScale = L<float>(Va(0x1325dac), 0); st.minDistance = L<float>(Va(0x131a7a4), 0);
    st.headingFactor = L<float>(Va(0x134955c), 0); st.half = L<float>(Va(0x1318038), 0);
    st.dominance = L<float>(Va(0x1325cf8), 0); st.lead = L<float>(Va(0x1325d24), 0);
    return true;
}
void EndStage(Stage& st, U contacts) {
    if (L<uint16_t>(Va(0x150fbc4), 0) != st.headingBias || L<uint16_t>(Va(0x14d0844), 0) != st.angleGate) Bump(GlobalsChanged);
    if (contacts > static_cast<U>(words[MaxContacts])) words[MaxContacts] = static_cast<LONG>(contacts);
    words[PortCallbackUs] = static_cast<LONG>(Micros(portTicks));
    words[OwnerCallbackUs] = static_cast<LONG>(Micros(ownerTicks));
}
void Predict(const Stage& st, Plan& p, void* r, void* s) {
    p = {};
    __try { PredictBody(st, p, static_cast<U>(reinterpret_cast<uintptr_t>(r)), static_cast<U>(reinterpret_cast<uintptr_t>(s))); }
    __except (EXCEPTION_EXECUTE_HANDLER) { p.flags = 0; p.kind = KindFault; }
}
void CountPlan(const Plan& p) {
    Bump(Contacts);
    switch (p.kind) {
    case KindPort:
        Bump(PortContacts);
        if (p.flags & FlagWriteR) Bump(PredictedWriteR);
        if (p.flags & FlagWriteS) Bump(PredictedWriteS);
        if (p.flags & FlagAvoid) Bump(PredictedAvoid);
        break;
    case KindDiffTeam: Bump(OwnerDiffTeam); break;
    case KindForeign: Bump(OwnerForeignClass); break;
    case KindUnsupported: Bump(OwnerUnsupported); break;
    default: Bump(OwnerFaults); break;
    }
}
void AddPlanTime(U wallUs, U threadUs) { Bump(PlanUs, wallUs); Bump(PlanThreadUs, threadUs); }

bool Shadow(const Stage& st, const Plan& p, U index, void* rp, void* sp, Original original, void* context) {
    U r = static_cast<U>(reinterpret_cast<uintptr_t>(rp)), s = static_cast<U>(reinterpret_cast<uintptr_t>(sp));
    Side sides[2];
    B before13R = 0, before13S = 0;
    U avoidQueued = 0, combatQueued = 0;
    // Foreign/faulted plans are never compared: their records are not read at all.
    bool captured = p.kind != KindForeign && p.kind != KindFault;
    if (captured) { __try {
        CaptureSide(sides[0], p.trackerR, r, s, p.keyS);
        CaptureSide(sides[1], p.trackerS, s, r, p.keyR);
        before13R = L<B>(r, 0x13c); before13S = L<B>(s, 0x13c);
        // 0x629240 appends one {R, S, d2} record pointer to the queue at manager +0x10/+0x14/+0x18.
        avoidQueued = L<U>(st.avoid, 0x14);
        combatQueued = st.combat ? L<U>(st.combat, 0x14) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { captured = false; } }
    ULONGLONG start = Clock();
    bool ok = original(context, sp, rp);
    ULONGLONG elapsed = Clock() - start;
    if (p.kind == KindPort) { portTicks += elapsed; Bump(PortCallbacks); }
    else { ownerTicks += elapsed; Bump(OwnerKindCallbacks); }
    if (!ok) { Bump(CallbackFaults); return false; }
    if (!captured) return true;
    Bump(Compared);
    U miss = 0;
    __try {
        // Sequential 0x52EDB0 expectation over the two sides (they may share one tracker).
        bool diff = p.kind == KindDiffTeam;
        U expectedCount[2] = { sides[0].count, sides[1].count };
        U simulated[2] = { sides[0].before, sides[1].before };
        bool appended[2] = {};
        for (U k = 0; k < 2; ++k) {
            Side& side = sides[k];
            if (!side.active) continue;
            bool unit = (k == 0 ? (p.flags & FlagSUnit) : (p.flags & FlagRUnit)) != 0;
            if (k == 1 && sides[0].active && sides[0].tracker == side.tracker) {
                expectedCount[1] = expectedCount[0];
                if (sides[0].word == side.word) simulated[1] = simulated[0];
            }
            if (!unit) continue;
            U bit = 1u << (side.key & 31);
            if (!(simulated[k] & bit)) {
                simulated[k] |= bit; appended[k] = true; ++expectedCount[k];
                Bump(PredictedTrackerAppends);
                if (k == 0 && sides[1].active && sides[1].tracker == side.tracker) {
                    expectedCount[1] = expectedCount[0];
                    if (sides[1].word == side.word) simulated[1] = simulated[0];
                }
            }
        }
        for (U k = 0; k < 2; ++k) {
            Side& side = sides[k];
            if (!side.active) continue;
            bool shared = sides[0].active && sides[1].active && sides[0].tracker == sides[1].tracker;
            U finalCount = shared ? expectedCount[1] : expectedCount[k];
            U finalWord = (shared && sides[0].word == sides[1].word) ? simulated[1] : simulated[k];
            if (L<U>(side.word, 0) != finalWord || L<U>(side.tracker, 0x2024 + 8) != finalCount) miss |= MissTracker;
            if (appended[k]) {
                U data = L<U>(side.tracker, 0x2024 + 0xc);
                U position = (shared && k == 0 && appended[1]) ? finalCount - 2 : finalCount - 1;
                if (L<uint16_t>(data, position * 2) != side.key) miss |= MissTracker;
            }
            bool distance = (k == 0 ? (p.flags & FlagDistR) : (p.flags & FlagDistS)) != 0;
            bool pairEvent = diff && appended[k] && distance;
            B fiveEc = L<B>(side.a, 0x5ec);
            if (pairEvent ? fiveEc != 1 : fiveEc != side.fiveEc) miss |= MissPair;
            if (!shared) {
                U pairs = L<U>(side.tracker, 8), data = L<U>(side.tracker, 0xc);
                if (!pairEvent) { if (pairs != side.pairs) miss |= MissPair; }
                else if (side.slot != 0xffffffffu) {
                    if (pairs != side.pairs || L<U>(data, side.slot * 12 + 4) != side.slotCount + 1) miss |= MissPair;
                } else if (pairs != side.pairs + 1 || L<U>(data, side.pairs * 12) != side.unit ||
                           L<U>(data, side.pairs * 12 + 4) != 1 || L<U>(data, side.pairs * 12 + 8) != 0) miss |= MissPair;
            }
        }
        B after13R = L<B>(r, 0x13c), after13S = L<B>(s, 0x13c);
        U avoidCount = L<U>(st.avoid, 0x14), avoided = avoidCount - avoidQueued;
        if (p.kind == KindPort) {
            if (before13R) Bump(Unobservable13C);
            else if ((after13R == 1) != ((p.flags & FlagWriteR) != 0) || after13R > 1) miss |= MissWriteR;
            if (before13S) Bump(Unobservable13C);
            else if ((after13S == 1) != ((p.flags & FlagWriteS) != 0) || after13S > 1) miss |= MissWriteS;
            U expected = (p.flags & FlagAvoid) ? 1u : 0u;
            if (avoided != expected) miss |= MissAvoid;
            else if (expected) {
                U entry = L<U>(L<U>(st.avoid, 0x18), (avoidCount - 1) * 4);
                if (L<U>(entry, 0) != r || L<U>(entry, 4) != s) miss |= MissAvoid;
            }
        } else {
            if ((!before13R && after13R) || (!before13S && after13S)) Bump(OwnerWrites13C);
            Bump(OwnerAvoidCalls, avoided);
            if (st.combat) Bump(CombatQueueAppends, L<U>(st.combat, 0x14) - combatQueued);
        }
        Bump(AvoidCalls, avoided);
    } __except (EXCEPTION_EXECUTE_HANDLER) { miss |= MissTracker; }
    if (miss) {
        if (miss & MissWriteR) Bump(MismatchWriteR);
        if (miss & MissWriteS) Bump(MismatchWriteS);
        if (miss & MissAvoid) Bump(MismatchAvoid);
        if (miss & MissTracker) Bump(MismatchTracker);
        if (miss & MissPair) Bump(MismatchContactPair);
        Mismatch(index, miss, r, s);
    }
    return true;
}
bool Replay(const Stage& st, const Plan& p, void* rp, void* sp, Original original, void* context) {
    U r = static_cast<U>(reinterpret_cast<uintptr_t>(rp)), s = static_cast<U>(reinterpret_cast<uintptr_t>(sp));
    if (p.kind != KindPort) { Bump(OwnerCallbacks); return original(context, sp, rp); }
    // The avoidance predicate read the manager's per-serial bitset; any change since stage entry
    // (for example by an earlier vt+0x14) makes the plan stale: execute the original instead.
    if (p.flags & FlagUsedAvail) {
        U bits = L<U>(st.avoid, 0x90);
        if (bits != st.avoidBits || ManagerBit(bits, L<U>(r, 0x2c)) != ((p.flags & FlagBitR) ? 1u : 0u) ||
            ManagerBit(bits, L<U>(s, 0x2c)) != ((p.flags & FlagBitS) ? 1u : 0u)) {
            Bump(ReplayRevalidated); Bump(OwnerCallbacks);
            return original(context, sp, rp);
        }
    }
    __try {
        if (p.trackerR && (p.flags & FlagSUnit) && Track(p.trackerR, p.keyS)) Bump(TrackerReplays);
        if (p.trackerS && (p.flags & FlagRUnit) && Track(p.trackerS, p.keyR)) Bump(TrackerReplays);
        if (p.flags & FlagWriteR) *reinterpret_cast<volatile B*>(r + 0x13c) = 1;
        if (p.flags & FlagWriteS) *reinterpret_cast<volatile B*>(s + 0x13c) = 1;
        if (p.flags & FlagAvoid) {
            using Slot = U (__thiscall*)(void*, void*, void*);
            reinterpret_cast<Slot>(L<U>(L<U>(st.avoid, 0), 0x14))(reinterpret_cast<void*>(st.avoid), rp, sp);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { Bump(ReplayFaults); return false; }
    Bump(Replays);
    return true;
}
void Sample(U out[WordCount]) { for (U i = 0; i < WordCount; ++i) out[i] = static_cast<U>(words[i]); }
}
#pragma float_control(pop)
