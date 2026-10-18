// Oracle for src/ntw2_ai_ctrl_geometry.{h,cpp} against the real supported image mapped privately (0x76DCD0 center distance,
// 0x53FBE0 + 0x80E9D0 pose [both branches], 0x57E910 identity getter).  Bit-exact comparison; the two production naked
// trampolines are exercised through a harness that reproduces the cloned scorer's register/stack contract.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "ai/ntw2_ai_ctrl_batch.h"
#include "clones/ntw2_clones.h"
#include "ai/ntw2_ai_ctrl_geometry.h"
#pragma comment(lib,"bcrypt.lib")
#pragma fenv_access(on)
namespace G = ntw2_ai_ctrl_geometry;
using U = uint32_t;
using B = unsigned char;
static_assert(sizeof(void*) == 4, "owned x86 oracle");
static B* image;
static U delta, checks;
static void Require(bool ok, const char* what) { ++checks; if (!ok) { std::fprintf(stderr, "FAIL %s\n", what); std::exit(1); } }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static void Put(void* p, U offset, U v) { std::memcpy(static_cast<B*>(p) + offset, &v, 4); }
static U Get(const void* p, U offset) { U v; std::memcpy(&v, static_cast<const B*>(p) + offset, 4); return v; }
static U Bits(float f) { U u; std::memcpy(&u, &f, 4); return u; }
static float Flt(U u) { float f; std::memcpy(&f, &u, 4); return f; }

static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open owned image");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long n = std::ftell(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image size"); std::rewind(f);
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr; B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "SHA image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(!std::strcmp(hex, NTW2_IMAGE_SHA256), "supported image identity");
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    auto sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "relocation");
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0, "flush image");
}

// ---------------- fixtures ----------------
struct Unit {   // unit object: +4 identity, +0x10 sub-object (vptr), +0xADC -> formation frame F; pose Q = F+0x6DC
    alignas(16) B raw[0xB00];
    alignas(16) B frame[0x800];
    alignas(16) B parent[0x200];
};
static U vtableStd[4], vtableAlt[4];
__declspec(naked) static void AltGetter() { __asm { mov eax, dword ptr [ecx - 0xC]
                                                    add eax, 100
                                                    ret } }
static void MakeUnit(Unit& u, U id, bool alt, bool parented, float x, float y, float z, U seed) {
    std::memset(&u, 0, sizeof u);
    Put(u.raw, 4, id); Put(u.raw, 0x10, A(alt ? vtableAlt : vtableStd)); Put(u.raw, 0xADC, A(u.frame));
    B* q = u.frame + 0x6DC;
    Put(q, 0, Bits(x)); Put(q, 4, Bits(y)); Put(q, 8, Bits(z));
    if (parented) {
        Put(q, 0x10, A(u.parent));
        for (U k = 0x80; k < 0xC0; k += 4) {
            seed = seed * 1664525u + 1013904223u;
            Put(u.parent, k, Bits(static_cast<float>(static_cast<int>(seed >> 16) % 2001 - 1000) * 0.0173f));
        }
    }
}
static void SetPose(Unit& u, float x, float z) { Put(u.frame + 0x6DC, 0, Bits(x)); Put(u.frame + 0x6DC, 8, Bits(z)); }
struct Region { alignas(16) B raw[0x100]; };
static void SetCenter(Region& r, float x, float z) { Put(r.raw, 8, Bits(x)); Put(r.raw, 0xC, Bits(z)); }

// ---------------- native references ----------------
using SlotFn = U(__thiscall*)(U);
using PoseFn = U(__thiscall*)(U, float*);
using DistFn = float(__thiscall*)(U, const float*);
static U RefId(U object) { return reinterpret_cast<SlotFn>(Get(reinterpret_cast<void*>(Get(reinterpret_cast<void*>(object), 0)), 0))(object); }
static void RefPose(U v, U& px, U& pz) {
    float out[3];
    const U q = reinterpret_cast<SlotFn>(At(0x53FBE0))(Get(reinterpret_cast<void*>(v), 0xADC) + 0x62C);
    const U p = reinterpret_cast<PoseFn>(At(0x80E9D0))(q, out);
    Require(p == A(out), "80E9D0 returns its output pointer");
    px = Get(out, 0); pz = Get(out, 8);
}
static U RefDist(U v, U r) {
    U px, pz; RefPose(v, px, pz);
    float pt[2] = {Flt(px), Flt(pz)};
    return Bits(reinterpret_cast<DistFn>(At(0x76DCD0))(r, pt));
}

// ---------------- trampoline harness (scorer contract) ----------------
static U h_stack[256];
static U h_top, h_binding, h_eaxIn, h_edxIn, h_ebxIn, h_saved;
static U h_eax, h_esi, h_edi, h_ebx, h_ebp, h_espAfter, h_fsw0, h_fswBefore, h_fswAfter;
static float h_fp;
#pragma optimize("", off)
static void RunIdentity() {
    __asm {
        pushad
        mov dword ptr [h_saved], esp
        mov esp, dword ptr [h_top]
        mov eax, dword ptr [h_eaxIn]
        mov edx, dword ptr [h_edxIn]
        mov ecx, edx
        mov ebx, dword ptr [h_ebxIn]
        mov ebp, 0x12345678
        mov esi, 0x11111111
        mov edi, 0x22222222
        call dword ptr [h_binding]
        mov dword ptr [h_eax], eax
        mov dword ptr [h_esi], esi
        mov dword ptr [h_edi], edi
        mov dword ptr [h_ebx], ebx
        mov dword ptr [h_ebp], ebp
        mov dword ptr [h_espAfter], esp
        mov esp, dword ptr [h_saved]
        popad
    }
}
static void RunDistance() {
    __asm {
        pushad
        fnstsw word ptr [h_fsw0]
        mov dword ptr [h_saved], esp
        mov esp, dword ptr [h_top]
        mov ebx, dword ptr [h_ebxIn]
        mov ebp, 0x12345678
        mov esi, 0x11111111
        mov edi, 0x22222222
        call dword ptr [h_binding]
        mov dword ptr [h_ebx], ebx
        mov dword ptr [h_ebp], ebp
        mov dword ptr [h_esi], esi
        mov dword ptr [h_edi], edi
        mov dword ptr [h_espAfter], esp
        fnstsw word ptr [h_fswBefore]
        fstp dword ptr [h_fp]
        fnstsw word ptr [h_fswAfter]
        mov esp, dword ptr [h_saved]
        popad
    }
}
#pragma optimize("", on)
static void Frame(U v, U r) { h_top = A(&h_stack[64]); h_stack[64 + 6] = r; h_stack[64 + 9] = v; }
struct IdResult { U idU, idV, edi; };
static IdResult CallIdentity(U v, U uThis, U i, U r) {
    Frame(v, r); h_binding = A(G::IdentityBindingAddress()); h_eaxIn = v; h_edxIn = uThis; h_ebxIn = i;
    RunIdentity();
    Require(h_ebx == i && h_ebp == 0x12345678 && h_espAfter == h_top, "identity trampoline preserves EBX/EBP/ESP");
    return {h_esi, h_eax, h_edi};
}
static U CallDistance(U v, U r, U i) {
    Frame(v, r); h_binding = A(G::DistanceBindingAddress()); h_ebxIn = i;
    RunDistance();
    Require(h_ebx == i && h_ebp == 0x12345678 && h_esi == 0x11111111 && h_edi == 0x22222222 && h_espAfter == h_top,
            "distance trampoline preserves EBX/EBP/ESI/EDI/ESP");
    Require(((h_fswBefore >> 11) & 7) == (((h_fsw0 >> 11) & 7) + 7 & 7), "distance leaves exactly one x87 value");
    Require(((h_fswAfter >> 11) & 7) == ((h_fsw0 >> 11) & 7), "x87 stack balanced after the consumer's fstp");
    return Bits(h_fp);
}

// ---------------- tests ----------------
static const U kEdge[] = {0x00000000, 0x80000000, 0x00000001, 0x807fffff, 0x00800000, 0x3f800000, 0x7f7fffff, 0x7f800000,
                          0xff800000, 0x7fc00000, 0x7fa00001, 0xffc00001, 0x7fffffff, 0x3f9e0652, 0x42c80000, 0xc2c80000};
static void TestKernel() {
    static Region r;
    const U modes[2] = {0x1f80u, 0x9fc0u};   // default masked; FTZ|DAZ
    const U saved = _mm_getcsr();
    for (U mode : modes) {
        _mm_setcsr(mode);
        for (U rx : kEdge) for (U rz : kEdge) for (U px : kEdge) for (U pz : kEdge) {
            Put(r.raw, 8, rx); Put(r.raw, 0xC, rz);
            const float pt[2] = {Flt(px), Flt(pz)};
            const float nat = reinterpret_cast<DistFn>(At(0x76DCD0))(A(r.raw), pt);
            if (Bits(nat) != G::PointDistanceBits(rx, rz, px, pz)) {
                _mm_setcsr(saved);
                std::fprintf(stderr, "kernel mismatch mode=%x r=%08x %08x p=%08x %08x nat=%08x mine=%08x\n", mode, rx, rz, px, pz,
                             Bits(nat), G::PointDistanceBits(rx, rz, px, pz));
                Require(false, "0x76DCD0 byte-equal");
            }
            ++checks;
        }
    }
    // pseudo-random finite + mixed
    U s = 0x9e3779b9u;
    for (U n = 0; n < 200000; ++n) {
        U v[4];
        for (U& w : v) { s = s * 1664525u + 1013904223u; w = (s >> 7) % 11 == 0 ? kEdge[(s >> 3) & 15] : (s ^ (s << 13)); }
        Put(r.raw, 8, v[0]); Put(r.raw, 0xC, v[1]);
        const float pt[2] = {Flt(v[2]), Flt(v[3])};
        const float nat = reinterpret_cast<DistFn>(At(0x76DCD0))(A(r.raw), pt);
        Require(Bits(nat) == G::PointDistanceBits(v[0], v[1], v[2], v[3]), "0x76DCD0 byte-equal (random bits)");
    }
    _mm_setcsr(saved);
}

static constexpr U kList = 48, kCand = 7;
static Unit list[kList], cand[kCand];
static Region region;
static U listPtrs[kList];
static B listObj[0x40];   // C: count at +0xC, data pointer at +0x10

static void BuildWorld() {
    for (U i = 0; i < kList; ++i) {
        const bool alt = (i % 11) == 4;
        MakeUnit(list[i], 1000 + i % 7, alt, (i & 1) != 0, static_cast<float>(i) * 3.5f - 40.f, 2.f, 17.f - static_cast<float>(i % 9) * 5.25f, 77 + i);
        listPtrs[i] = A(list[i].raw);
    }
    // exotic poses: -0, inf, NaN (payload), denormal, huge
    Put(list[6].frame + 0x6DC, 0, 0x80000000u); Put(list[6].frame + 0x6DC, 8, 0x00000001u); Put(list[6].parent, 0, 0);
    Put(list[6].frame + 0x6DC, 0x10, 0);
    Put(list[8].frame + 0x6DC, 0, 0x7f800000u); Put(list[8].frame + 0x6DC, 0x10, 0);
    Put(list[10].frame + 0x6DC, 8, 0x7fa00001u); Put(list[10].frame + 0x6DC, 0x10, 0);
    Put(list[12].frame + 0x6DC, 0, 0x7f7fffffu); Put(list[12].frame + 0x6DC, 8, 0xff7fffffu);
    for (U c = 0; c < kCand; ++c) MakeUnit(cand[c], 1000 + c % 7, c == 5, (c & 1) != 0, 0, 0, 0, 5 + c);
    std::memset(listObj, 0, sizeof listObj); Put(listObj, 0xC, kList); Put(listObj, 0x10, A(listPtrs));
    SetCenter(region, 12.5f, -3.25f);
}
// One scorer-shaped pass: the candidate loop of 0x7B1270.  Returns number of distance bindings executed.
static U Pass(U c, bool distanceOnDifferent = true) {
    U dists = 0;
    const U uThis = A(cand[c].raw) + 0x10;
    for (U i = 0; i < kList; ++i) {
        const U v = listPtrs[i];
        const IdResult id = CallIdentity(v, uThis, i, A(region.raw));
        Require(id.edi == v + 0x10, "identity binding EDI = V+0x10");
        Require(id.idU == RefId(uThis) && id.idV == RefId(v + 0x10), "identity values equal native virtual getter");
        if (id.idU != id.idV && distanceOnDifferent) {
            const U bits = CallDistance(v, A(region.raw), i);
            Require(bits == RefDist(v, A(region.raw)), "distance equals native 0x76DCD0(R, 80E9D0 pose)");
            ++dists;
        }
    }
    return dists;
}
static void Counters(G::Status& s) { U w[G::kStatusWords]; G::FillStatus(w); std::memcpy(&s, w, sizeof s); }

static void TestPose() {
    BuildWorld();
    G::Configure(false, true, false); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    U served = 0;
    for (U i = 0; i < kList; ++i) {
        const U v = listPtrs[i];
        (void)CallIdentity(v, A(cand[0].raw) + 0x10, i, A(region.raw));
        (void)CallDistance(v, A(region.raw), i);   // forces the pose gather
        U px, pz, rx, rz;
        Require(G::CachedPose(i, v, &px, &pz), "pose cached after first distance");
        RefPose(v, rx, rz);
        Require(px == rx && pz == rz, (i & 1) ? "pose == 80E9D0 (parent transform branch)" : "pose == 80E9D0 (no-parent branch)");
        ++served;
    }
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    U px, pz;
    Require(!G::CachedPose(0, listPtrs[0], &px, &pz), "pose cache retired at batch end");
    Require(served == kList, "all poses compared");
}
static void TestLiveTables() {
    BuildWorld();
    G::Configure(false, true, false); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    U totalDists = 0;
    for (U c = 0; c < kCand; ++c) totalDists += Pass(c);
    G::Status s; Counters(s);
    Require(s.id_calls == kCand * kList, "id_calls");
    Require(s.dist_calls == totalDists, "dist_calls");
    Require(s.distinct_rv <= kList && s.distinct_rv > 0, "distinct (R,V) keys are per list unit");
    Require(s.dist_served == s.dist_calls - s.distinct_rv, "every repeat of an (R,V) key is served");
    Require(s.pose_served == s.dist_served, "pose served == distance hits (single R)");
    Require(s.id_served > 0 && s.id_served < s.id_calls, "identity served after first gather");
    Require(s.dist_mismatch == 0 && !G::Latched(), "no mismatch");
    // Served from the table: mutating the pose mid-batch is invisible (contract: nothing mutates inside a batch).
    U v0 = 0, vi = 0; for (U i = 0; i < kList; ++i) if (RefId(listPtrs[i] + 0x10) != RefId(A(cand[0].raw) + 0x10)) { vi = i; v0 = listPtrs[i]; break; }
    const U before = CallDistance(v0, A(region.raw), vi);
    Unit& mutated = *reinterpret_cast<Unit*>(v0);
    const U sx = Get(mutated.frame + 0x6DC, 0), sz = Get(mutated.frame + 0x6DC, 8);
    SetPose(mutated, 999.f, -999.f);
    Require(CallDistance(v0, A(region.raw), vi) == before, "served from table, not recomputed");
    Put(mutated.frame + 0x6DC, 0, sx); Put(mutated.frame + 0x6DC, 8, sz);   // restore: the pose table must match native again
    // R change inside the batch invalidates the distance table
    SetCenter(region, -100.f, 55.f);
    Require(CallDistance(v0, A(region.raw), vi) == RefDist(v0, A(region.raw)) && RefDist(v0, A(region.raw)) != before, "R change recomputes");
    // Slot reuse by a different V recomputes
    Require(CallDistance(listPtrs[(vi + 1) % kList], A(region.raw), vi) == RefDist(listPtrs[(vi + 1) % kList], A(region.raw)), "slot holding another V recomputes");
    ai_ctrl_batch_end(AI_CTRL_END_ASSIGN);
    // Outside a batch every call is native
    Require(CallDistance(v0, A(region.raw), vi) == RefDist(v0, A(region.raw)), "closed batch: native");
    const IdResult id = CallIdentity(v0, A(cand[0].raw) + 0x10, vi, A(region.raw));
    Require(id.idV == RefId(v0 + 0x10), "closed batch: native identity");
    // New batch sees the new pose
    SetCenter(region, 12.5f, -3.25f);
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    Require(CallDistance(v0, A(region.raw), vi) == RefDist(v0, A(region.raw)), "new batch recomputes");
    // unsupported identity getter class (slot != 0x57E910) takes the native virtual call
    for (U i = 0; i < kList; ++i) if (RefId(listPtrs[i] + 0x10) != Get(reinterpret_cast<void*>(listPtrs[i]), 4)) {
        const IdResult r = CallIdentity(listPtrs[i], A(cand[0].raw) + 0x10, i, A(region.raw));
        Require(r.idV == Get(reinterpret_cast<void*>(listPtrs[i]), 4) + 100, "alt-class V uses its own getter");
    }
    const IdResult ra = CallIdentity(listPtrs[0], A(cand[5].raw) + 0x10, 0, A(region.raw));
    Require(ra.idU == Get(cand[5].raw, 4) + 100, "alt-class candidate uses its own getter");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    // index beyond capacity falls to native
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    Require(CallDistance(listPtrs[3], A(region.raw), G::kCapacity + 5) == RefDist(listPtrs[3], A(region.raw)), "index >= capacity: native");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
}
static void TestVerify() {
    BuildWorld();
    G::Configure(false, true, true); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    for (U c = 0; c < kCand; ++c) Pass(c);
    G::Status s; Counters(s);
    Require(s.dist_mismatch == 0 && !G::Latched() && s.dist_served > 0, "verify: clean run serves and matches");
    U vi = 0; for (U i = 0; i < kList; ++i) if (RefId(listPtrs[i] + 0x10) != RefId(A(cand[0].raw) + 0x10)) { vi = i; break; }
    SetPose(list[vi], 1234.f, 4321.f);   // forbidden mutation inside a batch: verify must catch it
    const U got = CallDistance(listPtrs[vi], A(region.raw), vi);
    Require(got == RefDist(listPtrs[vi], A(region.raw)), "verify: mismatch returns the native value");
    Counters(s);
    Require(s.dist_mismatch == 1 && G::Latched(), "verify: mismatch counted and feature latched off");
    SetPose(list[vi], -5.f, 6.f);
    Require(CallDistance(listPtrs[vi], A(region.raw), vi) == RefDist(listPtrs[vi], A(region.raw)), "latched: native");
    Counters(s); Require(s.dist_mismatch == 1, "latched: nothing further counted as served mismatch");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    // identity mismatch (identity word changes inside a batch) is also caught
    BuildWorld(); G::Configure(false, true, true); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    (void)Pass(0);
    Put(list[1].raw, 4, 31337);
    const IdResult id = CallIdentity(listPtrs[1], A(cand[0].raw) + 0x10, 1, A(region.raw));
    Require(id.idV == 31337 && G::Latched(), "verify: identity mismatch returns native and latches");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
}
static void TestCensus() {
    BuildWorld();
    G::Configure(true, false, false); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    U dists = 0;
    for (U c = 0; c < 3; ++c) dists += Pass(c);
    (void)Pass(0);                                   // repeated (R, U) pair
    G::Status s; Counters(s);
    Require(s.id_calls == 4 * kList && s.id_served == 0 && s.dist_served == 0 && s.pose_served == 0, "census: nothing served");
    Require(s.dist_calls > 0 && s.distinct_rv > 0 && s.distinct_rv <= kList, "census: distinct (R,V)");
    Require(s.boundary_repeat == 1, "census: one repeated (R, U) region-boundary pair");
    // native executes: a mutated pose is visible immediately
    U vi = 0; for (U i = 0; i < kList; ++i) if (RefId(listPtrs[i] + 0x10) != RefId(A(cand[0].raw) + 0x10)) { vi = i; break; }
    SetPose(list[vi], 77.f, 78.f);
    Require(CallDistance(listPtrs[vi], A(region.raw), vi) == RefDist(listPtrs[vi], A(region.raw)), "census: native value");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    // flags off: pure native, nothing counted
    BuildWorld(); G::Configure(false, false, false); G::Reset();
    ai_ctrl_batch_begin(nullptr, nullptr, listObj);
    (void)Pass(0);
    Counters(s);
    Require(s.id_calls == 0 && s.dist_calls == 0, "flags off: no counting");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
}

int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_ai_ctrl_geometry_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]);
    U bindings[NTW2_BIND_COUNT] = {};
    Require(G::Bind(A(image), bindings), "bind");
    Require(bindings[NTW2_BIND_AI_CTRL_IDENTITY] == A(G::IdentityBindingAddress()) &&
            bindings[NTW2_BIND_AI_CTRL_POINT_DISTANCE] == A(G::DistanceBindingAddress()), "binding addresses published");
    vtableStd[0] = A(At(0x57E910)); vtableAlt[0] = A(reinterpret_cast<void*>(&AltGetter));
    { const B* g = At(0x57E910); Require(g[0] == 0x8b && g[1] == 0x41 && g[2] == 0xf4 && g[3] == 0xc3, "0x57E910 is mov eax,[ecx-0xC]; ret"); }
    ntw2_ai_ctrl::Reset(NTW2_AI_CTRL_MODE_MASK, delta, 0);
    TestKernel();
    TestPose();
    TestLiveTables();
    TestVerify();
    TestCensus();
    std::printf("native_ai_ctrl_geometry_oracle: %u checks, 0 failures\n", checks);
    return 0;
}
