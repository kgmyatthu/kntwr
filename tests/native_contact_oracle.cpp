// Private-image differential oracle for the collision contact-response port
// (src/collision/native_contact.cpp): the untouched type-8 callback 0x64CC70 -> 0x64CAD0 and its
// decision callees versus the port helpers, and full contact sequences run three ways from
// identical state: original callbacks, Plan+Replay (ModeWorkers), Plan+Shadow (ModeShadow).
//
// Private boundaries only (no game file is modified):
//  * allocator jumps 0xFF7F20/0xFF7EF0 -> CRT heap (tracker u16/pair vectors, avoidance pool);
//  * the two owner-original different-team predicates 0x664100 (combat witness walk) and
//    0x62F750 jump to deterministic fixture predicates, so different-team contacts are
//    reproducible; everything downstream of them (0x629240 on the combat manager, the
//    vt+0xE8/+0xEC stubs, the same-team arm) still executes as the original image code.
//  * fixture-owned recording stand-ins: a copied LAND table whose +0x40 is a foreign callback,
//    a copied LAND table whose +0xF0 is an unknown stub, and node tables (+0x22C) whose +0x20 is
//    one of the three proven stubs or an unknown stub.
// The avoidance manager uses the real vtable 0x1334234, so vt+0x14 is the original 0x629140 ->
// 0x629240 queue append in all three runs.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <limits>
#include "native_image_relocation.h"
#include "native_contact.h"
#include "clones/ntw2_clones.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
namespace C = ntw2_contact;
static_assert(sizeof(void*) == 4, "owned x86 oracle");
static_assert(C::WordCount == 48 && C::OwnerKindCallbacks == 47 && C::IdentityRefusals == 42 &&
    C::AvoidVtable == 34 && C::CombatVtable == 36, "status words follow NTW2_COLLIDE_CONTACT_WORD_LABELS");

static B* image;
static U delta, checks;
static const char* currentCase = "mapping";
[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fprintf(stderr, "FAIL [%s]: ", currentCase);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::exit(1);
}
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail("%s", what); }
template<class T> static T Get(const void* p, size_t off) {
    T v; std::memcpy(&v, static_cast<const B*>(p) + off, sizeof(v)); return v;
}
template<class T> static void Put(void* p, size_t off, T v) { std::memcpy(static_cast<B*>(p) + off, &v, sizeof(v)); }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* P(U address) { return reinterpret_cast<B*>(static_cast<uintptr_t>(address)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static U Va(U va) { return va + delta; }
static bool SameBits(float a, float b) { return std::memcmp(&a, &b, sizeof(a)) == 0; }

struct FpEnv { unsigned short cw; U mxcsr; };
static FpEnv fp = { 0x27f, 0x1f80 };
static void InstallFp() {
    unsigned short cw = fp.cw;
    __asm { fninit }
    __asm { fldcw cw }
    _mm_setcsr(fp.mxcsr);
}
static void* __cdecl Allocate(size_t n, void*) {
    void* p = std::malloc(n ? n : 1); Require(p != nullptr, "private native heap allocation"); return p;
}
static void __cdecl Release(void* p) { std::free(p); }
static void Jump(U va, U target) { B* p = At(va); p[0] = 0xb8; Put(p, 1, target); p[5] = 0xff; p[6] = 0xe0; }

// Deterministic stand-ins for the owner-original different-team predicates (see header).
static U combatDecisions, engageDecisions, foreignCalls, oddCalls;
static bool __fastcall CombatDecide(void*, void*, void* r, void* s) {
    ++combatDecisions;
    return (Get<U>(r, 0x2c) * 31u + Get<U>(s, 0x2c)) % 5u == 0;
}
static bool __fastcall Engage(void* self, void*, void* other) {
    ++engageDecisions;
    return (Get<U>(self, 0x2c) + 3u * Get<U>(other, 0x2c)) % 7u == 0;
}
static void __fastcall ForeignContact(void* r, void*, void* s) {
    ++foreignCalls; Put<B>(r, 0x13c, 2); Put<B>(s, 0x5ec, 3);
}
static bool __fastcall OddStub(void*, void*) { ++oddCalls; return false; }

static U imageSize;
static std::vector<U> landTables;
static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open supported image read-only");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long n = std::ftell(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image size"); std::rewind(f);
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr; B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "SHA image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(!std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"), "supported image identity");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred image base");
    imageSize = nt->OptionalHeader.SizeOfImage;
    image = static_cast<B*>(VirtualAlloc(nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
            std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, imageSize, reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta),
        "image relocation");
    // Every LAND table: +0x40 = 0x64CAD0 and +0x44 = 0x64CC70 (analysis/native-contact-response.md).
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sections[i].Name, ".rdata", 7)) continue;
        for (U off = 0; off + 0x100 <= sections[i].Misc.VirtualSize; off += 4) {
            B* t = image + sections[i].VirtualAddress + off;
            if (Get<U>(t, 0x40) == Va(0x64cad0) && Get<U>(t, 0x44) == Va(0x64cc70)) landTables.push_back(A(t));
        }
    }
    // The 23 registry tables of analysis/native-agent-loop-structure.md all resolve both slots.
    if (landTables.size() != 23) Fail("expected 23 tables with +0x40=0x64CAD0/+0x44=0x64CC70, found %u", static_cast<U>(landTables.size()));
    for (U t : landTables)
        for (U slot : {0xe8u, 0xecu, 0xf0u}) {
            U target = Get<U>(P(t), slot);
            Require(target == Va(0x462cb0) || target == Va(0x447880) || target == Va(0x5db820),
                "LAND vt+0xE8/+0xEC/+0xF0 resolve to the three proven stubs");
        }
    Require(Get<U>(At(0x1334234), 0x14) == Va(0x629140) && At(0x629140)[0] == 0xe9, "avoidance vt+0x14 = 0x629140 jmp 0x629240");
    Jump(0xff7f20, Fn(&Allocate)); Jump(0xff7ef0, Fn(&Release));
    Jump(0x664100, Fn(&CombatDecide)); Jump(0x62f750, Fn(&Engage));
    Require(FlushInstructionCache(GetCurrentProcess(), image, imageSize) != 0, "flush private seams");
}

// ---------------------------------------------------------------------------------------------
// Fixture world: one arena restored byte-for-byte before every run; heap-backed vectors are
// re-created (fresh CRT blocks with identical contents) because the original may free them.
struct Rng {
    U s;
    U Next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    U Below(U n) { return Next() % n; }
    bool Chance(U percent) { return Below(100) < percent; }
    float Uniform(float lo, float hi) { return lo + (hi - lo) * float(Next() >> 8) / float(1u << 24); }
};
constexpr U kAgents = 48, kOwners = 12, kAgentBytes = 0x1000, kOwnerBytes = 0x2800, kArena = 4u << 20;
constexpr U kTracker = 0x74c, kBitsBytes = 0x2000;
struct HeapSeed { U field; std::vector<B> bytes; };
struct World {
    B* base = nullptr; U used = 0;
    std::array<B*, kAgents> agents{};
    std::array<B*, kOwners> owners{};
    B *env = nullptr, *env2 = nullptr, *model = nullptr, *model2 = nullptr;
    B *avoid = nullptr, *avoid2 = nullptr, *combat = nullptr, *combat2 = nullptr;
    B *avoidBits = nullptr, *avoidBits2 = nullptr, *combatBits = nullptr, *spareBits = nullptr;
    std::array<B*, 2> shapes{};
    std::array<B*, 4> matrices{};
    std::array<B*, 4> nodeTables{};
    B *foreignTable = nullptr, *oddTable = nullptr;
    std::vector<HeapSeed> heaps;
    std::vector<B> snapshot;
    std::vector<std::array<B*, 2>> contacts; // {R (query record), S (neighbour)}
    B* Take(U bytes) {
        U at = (used + 15) & ~15u; Require(at + bytes <= kArena, "fixture arena capacity"); used = at + bytes; return base + at;
    }
};
static void SeedHeap(World& w, B* object, U field, const std::vector<B>& bytes) { w.heaps.push_back({ A(object) + field, bytes }); }
static void Reset(World& w) {
    std::memcpy(w.base, w.snapshot.data(), w.snapshot.size());
    for (const HeapSeed& h : w.heaps) {
        void* p = std::malloc(h.bytes.size()); Require(p != nullptr, "seed heap block");
        std::memcpy(p, h.bytes.data(), h.bytes.size());
        Put<U>(P(h.field), 0, A(p));
    }
}
static B* Manager(World& w, U vtable, B* bits) {
    B* m = w.Take(0x200); Put<U>(m, 0, vtable); Put<U>(m, 0x90, A(bits)); return m;
}
static void Build(World& w, U seed) {
    if (!w.base) {
        w.base = static_cast<B*>(VirtualAlloc(nullptr, kArena, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(w.base != nullptr, "fixture arena");
    }
    std::memset(w.base, 0, kArena); w.used = 0; w.heaps.clear(); w.contacts.clear();
    Rng rng{ seed * 2654435761u + 0x9e3779b9u };
    for (B*& a : w.agents) a = w.Take(kAgentBytes);
    for (B*& o : w.owners) o = w.Take(kOwnerBytes);
    w.avoidBits = w.Take(kBitsBytes); w.avoidBits2 = w.Take(kBitsBytes);
    w.combatBits = w.Take(kBitsBytes); w.spareBits = w.Take(kBitsBytes);
    w.avoid = Manager(w, Va(0x1334234), w.avoidBits); w.avoid2 = Manager(w, Va(0x1334234), w.avoidBits2);
    w.combat = Manager(w, 0, w.combatBits); w.combat2 = Manager(w, 0, w.combatBits);
    w.model = w.Take(0x100); w.model2 = w.Take(0x100);
    Put<U>(w.model, 0xc8, A(w.combat)); Put<U>(w.model, 0xcc, A(w.avoid));
    Put<U>(w.model2, 0xc8, A(w.combat2)); Put<U>(w.model2, 0xcc, A(w.avoid2));
    w.env = w.Take(0x20); w.env2 = w.Take(0x20);
    Put<U>(w.env, 8, A(w.model)); Put<U>(w.env2, 8, A(w.model2));
    for (U k = 0; k < 2; ++k) {
        B* scales = w.Take(256 * 4);
        for (U i = 0; i < 256; ++i)
            Put<float>(scales, i * 4, k ? 0.25f + float((255 - i) % 13) / 16.0f : 0.125f + float(i % 17) / 16.0f);
        w.shapes[k] = w.Take(0x1c); Put<U>(w.shapes[k], 0x18, A(scales));
    }
    for (B*& m : w.matrices) {
        m = w.Take(0xc0);
        float angle = rng.Uniform(-3.1f, 3.1f), c = std::cos(angle), s = std::sin(angle);
        float rows[9] = { c, rng.Uniform(-0.1f, 0.1f), s, rng.Uniform(-0.1f, 0.1f), 1.0f, rng.Uniform(-0.1f, 0.1f), -s, rng.Uniform(-0.1f, 0.1f), c };
        for (U i = 0; i < 9; ++i) Put<float>(m, 0x9c + i * 4, rows[i]);
        Put<float>(m, 0x80, rng.Uniform(-1.0f, 1.0f)); Put<float>(m, 0x84, rng.Uniform(-0.2f, 0.2f)); Put<float>(m, 0x88, rng.Uniform(-1.0f, 1.0f));
    }
    const U nodeSlots[4] = { Va(0x462cb0), Va(0x447880), Va(0x5db820), Fn(&OddStub) };
    for (U k = 0; k < 4; ++k) { w.nodeTables[k] = w.Take(0x40); Put<U>(w.nodeTables[k], 0x20, nodeSlots[k]); }
    w.foreignTable = w.Take(0x204); w.oddTable = w.Take(0x204);
    std::memcpy(w.foreignTable, P(landTables[0]) - 4, 0x204); std::memcpy(w.oddTable, P(landTables[1]) - 4, 0x204);
    Put<U>(w.foreignTable + 4, 0x40, Fn(&ForeignContact)); Put<U>(w.oddTable + 4, 0xf0, Fn(&OddStub));
    // Agents: dense cluster so blocking/overlap/facing branches are all reached.
    for (U i = 0; i < kAgents; ++i) {
        B* a = w.agents[i];
        U table = landTables[rng.Below(static_cast<U>(landTables.size()))];
        U roll = rng.Below(100);
        if (roll < 3) table = A(w.foreignTable + 4); else if (roll < 6) table = A(w.oddTable + 4);
        Put<U>(a, 0, table);
        Put<U>(a, 0x18, rng.Chance(4) ? 1u : 0u);
        Put<U>(a, 0x28, A(rng.Chance(5) ? w.env2 : w.env));
        U serial = (i * 1361u + 7u + (rng.Chance(30) ? 32768u : 0u)) & 0xffffu;
        Put<U>(a, 0x2c, serial);
        Put<U>(a, 0x44, rng.Chance(78) ? 1u : 2u);
        float x = rng.Uniform(0.0f, 6.0f), z = rng.Uniform(0.0f, 6.0f);
        Put<float>(a, 0x48, x); Put<float>(a, 0x4c, rng.Uniform(0.0f, 0.6f)); Put<float>(a, 0x50, z);
        Put<float>(a, 0x54, rng.Uniform(0.3f, 2.0f)); Put<float>(a, 0x58, rng.Uniform(0.4f, 1.5f));
        Put<U>(a, 0x60, rng.Chance(25) ? A(w.shapes[rng.Below(2)]) : 0u);
        Put<uint16_t>(a, 0x64, static_cast<uint16_t>(rng.Next()));
        Put<B>(a, 0xb4, rng.Chance(4) ? 1 : 0);
        Put<B>(a, 0xec, rng.Chance(90) ? 1 : 0); Put<B>(a, 0xee, rng.Chance(30) ? 1 : 0); Put<B>(a, 0xef, rng.Chance(30) ? 1 : 0);
        Put<float>(a, 0x10c, rng.Uniform(0.0f, 3.0f)); Put<float>(a, 0x144, rng.Uniform(0.0f, 3.0f));
        U flags = rng.Next() & 0xfffff7feu;
        if (rng.Chance(20)) flags |= 1; if (rng.Chance(40)) flags |= 0x800;
        Put<U>(a, 0x110, flags);
        U r117 = rng.Below(100); Put<B>(a, 0x117, r117 < 70 ? 0 : r117 < 95 ? 1 : 2);
        U r118 = rng.Below(100); Put<B>(a, 0x118, r118 < 78 ? 1 : r118 < 96 ? 0 : 2);
        Put<B>(a, 0x13c, rng.Chance(15) ? 1 : 0);
        Put<float>(a, 0x160, x + rng.Uniform(-2.0f, 2.0f)); Put<float>(a, 0x164, rng.Uniform(-0.5f, 0.5f));
        Put<float>(a, 0x168, z + rng.Uniform(-2.0f, 2.0f));
        Put<U>(a, 0x170, rng.Chance(20) ? A(w.matrices[rng.Below(4)]) : 0u);
        Put<U>(a, 0x178, rng.Chance(40) ? 1 + rng.Below(4) : 0u);
        Put<U>(a, 0x1b8, rng.Chance(5) ? 0xdu : rng.Below(4));
        Put<U>(a, 0x1f0, rng.Chance(15) ? 0u : 0x1000u + 0x40u * rng.Below(6));
        static const U states[] = { 0, 1, 2, 3, 6, 7, 8, 0, 1, 2, 5, 5, 4, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14 };
        Put<U>(a, 0x224, states[rng.Below(20)]);
        U node = rng.Below(100);
        Put<U>(a, 0x22c, A(w.nodeTables[node < 70 ? 0 : node < 80 ? 1 : node < 95 ? 2 : 3]));
        Put<U>(a, 0x388, rng.Chance(85) ? A(w.owners[rng.Below(kOwners)]) : 0u);
        Put<U>(a, 0x444, rng.Below(2));
        Put<B>(a, 0x458, rng.Chance(20) ? 1 : 0);
        static const U owners67c[] = { 0, 1, 0x100, 0x10000 };
        Put<U>(a, 0x67c, owners67c[rng.Below(4)]); Put<U>(a, 0x22c + 0x67c, owners67c[rng.Below(4)]);
    }
    for (U i = 0; i < kAgents; ++i) {
        B* a = w.agents[i];
        Put<U>(a, 0x3c, rng.Chance(8) ? Get<U>(w.agents[rng.Below(kAgents)], 0x2c) : 0xffffffffu);
        Put<U>(a, 0x1ec, rng.Chance(6) ? A(w.agents[rng.Below(kAgents)]) : 0u);
        Put<U>(a, 0x5b8, rng.Chance(4) ? A(w.agents[rng.Below(kAgents)]) : 0u);
        if (rng.Chance(10)) Put<U>(w.avoidBits, (Get<U>(a, 0x2c) >> 5) * 4,
            Get<U>(w.avoidBits, (Get<U>(a, 0x2c) >> 5) * 4) | 1u << (Get<U>(a, 0x2c) & 31));
        if (rng.Chance(10)) Put<U>(w.combatBits, (Get<U>(a, 0x2c) >> 5) * 4,
            Get<U>(w.combatBits, (Get<U>(a, 0x2c) >> 5) * 4) | 1u << (Get<U>(a, 0x2c) & 31));
    }
    // Trackers: some keys already present; vectors empty (first append allocates) or seeded.
    for (U k = 0; k < kOwners; ++k) {
        B* t = w.owners[k] + kTracker;
        std::vector<uint16_t> keys;
        for (U n = rng.Below(4); n; --n) {
            uint16_t key = static_cast<uint16_t>(Get<U>(w.agents[rng.Below(kAgents)], 0x2c));
            U word = 0x20 + (key >> 5) * 4;
            if (Get<U>(t, word) & 1u << (key & 31)) continue;
            Put<U>(t, word, Get<U>(t, word) | 1u << (key & 31)); keys.push_back(key);
        }
        if (!keys.empty() || rng.Chance(30)) {
            U cap = static_cast<U>(keys.size()) + rng.Below(3) + (keys.empty() ? 1 : 0);
            std::vector<B> bytes(cap * 2, 0xcd);
            std::memcpy(bytes.data(), keys.data(), keys.size() * 2);
            Put<U>(t, 0x2024 + 4, cap); Put<U>(t, 0x2024 + 8, static_cast<U>(keys.size()));
            SeedHeap(w, t, 0x2024 + 0xc, bytes);
        }
        if (rng.Chance(40)) {
            U count = 1 + rng.Below(2), cap = count + rng.Below(2);
            std::vector<B> bytes(cap * 12, 0xcd);
            for (U n = 0; n < count; ++n) {
                Put<U>(bytes.data(), n * 12, 0x1000u + 0x40u * (n * 2 + rng.Below(2)));
                Put<U>(bytes.data(), n * 12 + 4, 1 + rng.Below(5)); Put<U>(bytes.data(), n * 12 + 8, 0);
            }
            Put<U>(t, 4, cap); Put<U>(t, 8, count);
            SeedHeap(w, t, 0xc, bytes);
        }
    }
    for (U n = 0; n < 2500; ++n) {
        U r = rng.Below(kAgents), s = rng.Below(kAgents - 1);
        if (s >= r) ++s;
        w.contacts.push_back({ w.agents[r], w.agents[s] });
    }
    w.snapshot.assign(w.base, w.base + w.used);
}

// Canonical post-run state: arena bytes with heap pointers replaced by their contents.
static void Append(std::vector<B>& out, const void* p, U bytes) {
    const B* b = static_cast<const B*>(p); out.insert(out.end(), b, b + bytes);
}
static void AppendQueue(std::vector<B>& out, B* manager) {
    U cap = Get<U>(manager, 0x10), count = Get<U>(manager, 0x14);
    Append(out, &cap, 4); Append(out, &count, 4);
    for (U n = 0; n < count; ++n) Append(out, P(Get<U>(P(Get<U>(manager, 0x18)), n * 4)), 12);
}
static std::vector<B> State(World& w) {
    std::vector<B> out;
    for (B* a : w.agents) Append(out, a, kAgentBytes);
    for (B* o : w.owners) {
        B* t = o + kTracker;
        std::vector<B> copy(o, o + kTracker + 0x2034);
        Put<U>(copy.data(), kTracker + 0xc, 0); Put<U>(copy.data(), kTracker + 0x2024 + 0xc, 0);
        out.insert(out.end(), copy.begin(), copy.end());
        if (Get<U>(t, 8)) Append(out, P(Get<U>(t, 0xc)), Get<U>(t, 8) * 12);
        if (Get<U>(t, 0x2024 + 8)) Append(out, P(Get<U>(t, 0x2024 + 0xc)), Get<U>(t, 0x2024 + 8) * 2);
    }
    for (B* m : { w.avoid, w.avoid2, w.combat, w.combat2 }) AppendQueue(out, m);
    for (B* bits : { w.avoidBits, w.avoidBits2, w.combatBits }) Append(out, bits, kBitsBytes);
    return out;
}

// ---------------------------------------------------------------------------------------------
using Callback = void (__thiscall*)(void*, void*);
static bool OriginalCallback(void*, void* s, void* r) {
    __try { reinterpret_cast<Callback>(Get<U>(P(Get<U>(s, 0)), 0x44))(s, r); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static void SetGlobals(uint16_t bias, uint16_t gate) { Put<uint16_t>(At(0x150fbc4), 0, bias); Put<uint16_t>(At(0x14d0844), 0, gate); }

// Mapped originals of the decision helpers.
static bool OGate(B* a) { return reinterpret_cast<bool (__thiscall*)(void*)>(At(0x64caa0))(a); }
static bool OBlocks(B* x, B* y) { return reinterpret_cast<bool (__thiscall*)(void*, void*)>(At(0x817160))(x, y); }
static bool OLinked(B* x, B* y) { return reinterpret_cast<bool (__thiscall*)(void*, void*)>(At(0x667260))(x, y); }
static void OSlot(B* p, float out[3]) { reinterpret_cast<void* (__thiscall*)(void*, float*)>(At(0x80e9d0))(p, out); }
static uint16_t OHeading(B* a) { uint16_t h = 0x5a5a; reinterpret_cast<void* (__thiscall*)(void*, uint16_t*)>(At(0x80b5b0))(a, &h); return h; }
static bool OFar(B* a, float x, float z) { float p[2] = { x, z }; return reinterpret_cast<bool (__thiscall*)(void*, float*)>(At(0x81bd10))(a, p); }
static float OFacing(U a, U b) { return reinterpret_cast<float (__stdcall*)(U, U)>(At(0x7fa690))(a, b); }
static void OFacings(B* r, B* s, float out[4]) { reinterpret_cast<void* (__thiscall*)(float*, void*, void*)>(At(0x7e4bb0))(out, r, s); }
static U OClassify(B* r, B* s) { return reinterpret_cast<U (__cdecl*)(void*, void*, U)>(At(0x62f1a0))(r, s, 0); }
static bool OAvailable(B* m, B* a) { return reinterpret_cast<bool (__thiscall*)(void*, void*)>(At(0x6795d0))(m, a); }
static bool OOverlap(B* r, B* s) { return reinterpret_cast<bool (__thiscall*)(void*, void*)>(At(0x7fa590))(r, s); }
static bool OAvoid(B* m, B* r, B* s) { return reinterpret_cast<bool (__thiscall*)(void*, void*, void*)>(At(0x664010))(m, r, s); }

static U classified[5], avoidTrue, overlapTrue, blocksTrue;
static void CompareHelpers(World& w, const C::Stage& st) {
    currentCase = "helpers vs mapped originals";
    for (B* a : w.agents) {
        Require(C::port::Gate(A(a)) == OGate(a), "0x64CAA0 gate");
        float o[3]; OSlot(a + 0x160, o); C::port::XZ q = C::port::SlotPosition(A(a) + 0x160);
        Require(SameBits(q.x, o[0]) && SameBits(q.z, o[2]), "0x80E9D0 slot position");
        Require(C::port::Heading(st, A(a)) == OHeading(a), "0x80B5B0 heading");
        for (B* m : { w.avoid, w.combat }) Require(C::port::Available(A(m), A(a)) == OAvailable(m, a), "0x6795D0 availability");
    }
    U n = 0;
    for (const auto& c : w.contacts) {
        if (++n > 900) break;
        B *r = c[0], *s = c[1];
        for (int k = 0; k < 2; ++k) {
            B *x = k ? s : r, *y = k ? r : s;
            bool b = OBlocks(x, y); blocksTrue += b;
            Require(C::port::Blocks(st, A(x), A(y)) == b, "0x817160 blocking");
            Require(C::port::BlocksUnlessLinked(st, A(x), A(y)) == OLinked(x, y), "0x667260 linked blocking");
            Require(C::port::Far(A(x), Get<float>(y, 0x48), Get<float>(y, 0x50)) == OFar(x, Get<float>(y, 0x48), Get<float>(y, 0x50)), "0x81BD10 far");
        }
        float po[4], oo[4]; C::port::Facings(st, A(r), A(s), po); OFacings(r, s, oo);
        for (U i = 0; i < 4; ++i) Require(SameBits(po[i], oo[i]), "0x7E4BB0 facings");
        bool overlap = OOverlap(r, s); overlapTrue += overlap;
        Require(C::port::Overlap(st, A(r), A(s)) == overlap, "0x7FA590 overlap");
        bool supported = true;
        U kind = C::port::Classify(st, A(r), A(s), supported);
        U original = OClassify(r, s);
        if (supported) {
            Require(kind == original, "0x62F1A0 classification");
            if (original < 5) ++classified[original];
        }
        for (B* m : { w.avoid, w.combat }) {
            supported = true;
            bool port = C::port::Avoid(st, A(m), A(r), A(s), supported);
            bool avoid = OAvoid(m, r, s);
            if (supported) { Require(port == avoid, "0x664010 avoidance predicate"); avoidTrue += avoid; }
        }
    }
}
static void CompareFacing(const C::Stage& st) {
    currentCase = "0x7FA690 exhaustive";
    for (U d = 0; d < 0x10000; ++d) {
        U high = (d * 2654435761u) & 0xffff0000u;
        Require(SameBits(C::port::Facing(st, d | high), OFacing(d | high, 0)), "facing over every low-16 difference");
        Require(SameBits(C::port::Facing(st, d - 0x1234u), OFacing(d, 0x1234u)), "facing of a wrapped difference");
    }
}

// ---------------------------------------------------------------------------------------------
struct RunResult { std::vector<B> state; U words[C::WordCount]; };
// Fixture cost census (informational; not asserted): QPC ticks and contacts per run kind.
static ULONGLONG originalTicks, planTicks, replayTicks, timedContacts;
static ULONGLONG Ticks() { LARGE_INTEGER v; QueryPerformanceCounter(&v); return static_cast<ULONGLONG>(v.QuadPart); }
static void RunOriginal(World& w, RunResult& out) {
    Reset(w); InstallFp();
    ULONGLONG start = Ticks();
    for (const auto& c : w.contacts) Require(OriginalCallback(nullptr, c[1], c[0]), "original callback");
    originalTicks += Ticks() - start; timedContacts += w.contacts.size();
    out.state = State(w); std::memset(out.words, 0, sizeof(out.words));
}
static void Plan(const C::Stage& st, World& w, std::vector<C::Plan>& plans) {
    plans.assign(w.contacts.size(), C::Plan{});
    for (U i = 0; i < w.contacts.size(); ++i) C::Predict(st, plans[i], w.contacts[i][0], w.contacts[i][1]);
}
// mutate: optional change applied after planning and before replay (stale-plan tests).
static void RunPlanned(World& w, U mode, RunResult& out, std::vector<C::Plan>* keep = nullptr, void (*mutate)(World&) = nullptr) {
    Reset(w); InstallFp();
    C::Start(delta, mode);
    C::Stage st; Require(C::BeginStage(st, w.model), "stage admitted");
    ULONGLONG start = Ticks();
    std::vector<C::Plan> plans; Plan(st, w, plans);
    if (mode == C::ModeWorkers && !mutate) planTicks += Ticks() - start;
    for (const C::Plan& p : plans) C::CountPlan(p);
    if (mutate) mutate(w);
    start = Ticks();
    for (U i = 0; i < plans.size(); ++i) {
        B *r = w.contacts[i][0], *s = w.contacts[i][1];
        bool ok = mode == C::ModeShadow ? C::Shadow(st, plans[i], i, r, s, &OriginalCallback, nullptr)
                                        : C::Replay(st, plans[i], r, s, &OriginalCallback, nullptr);
        Require(ok, "planned contact completes");
    }
    if (mode == C::ModeWorkers && !mutate) replayTicks += Ticks() - start;
    C::EndStage(st, static_cast<U>(plans.size()));
    out.state = State(w); C::Sample(out.words);
    if (keep) *keep = plans;
}
static void Census(const std::vector<C::Plan>& plans, U counts[16]) {
    for (const C::Plan& p : plans) {
        ++counts[p.kind];
        if (p.kind == C::KindPort) {
            if (p.flags & C::FlagWriteR) ++counts[8];
            if (p.flags & C::FlagWriteS) ++counts[9];
            if (p.flags & C::FlagAvoid) ++counts[10];
            if (p.flags & C::FlagUsedAvail) ++counts[11];
        }
        if (p.kind == C::KindDiffTeam && (p.flags & (C::FlagDistR | C::FlagDistS))) ++counts[12];
    }
}

static U totals[16], wordTotals[C::WordCount];
static void Sequences(World& w) {
    currentCase = "original vs plan+replay vs shadow";
    RunResult original, replay, shadow;
    RunOriginal(w, original);
    std::vector<C::Plan> plans;
    RunPlanned(w, C::ModeWorkers, replay, &plans);
    Require(replay.state == original.state, "plan+replay final state equals original callbacks");
    RunPlanned(w, C::ModeShadow, shadow);
    Require(shadow.state == original.state, "shadow final state equals original callbacks");
    const U* sw = shadow.words; const U* rw = replay.words;
    if (sw[C::Mismatches])
        Fail("shadow mismatches=%u first kind=%u contact=%u", sw[C::Mismatches], sw[C::FirstMismatchKind], sw[C::FirstMismatchContact]);
    U contacts = static_cast<U>(w.contacts.size());
    Require(sw[C::Version] == C::kVersion && sw[C::ModeWord] == C::ModeShadow && sw[C::Stages] == 1, "shadow header words");
    Require(sw[C::Contacts] == contacts && rw[C::Contacts] == contacts, "every contact counted once");
    Require(sw[C::Compared] == contacts - sw[C::OwnerForeignClass] - sw[C::OwnerFaults], "every LAND contact compared");
    Require(sw[C::PortCallbacks] == sw[C::PortContacts] && sw[C::PortCallbacks] + sw[C::OwnerKindCallbacks] == contacts, "shadow runs every original");
    Require(rw[C::Replays] == rw[C::PortContacts] - rw[C::ReplayRevalidated] &&
        rw[C::Replays] + rw[C::OwnerCallbacks] == contacts, "replay partitions contacts");
    Require(rw[C::ReplayRevalidated] == 0 && rw[C::ReplayFaults] == 0 && sw[C::CallbackFaults] == 0, "unmutated stage needs no revalidation");
    Require(sw[C::AvoidVtable] == 0x1334234 && sw[C::AvoidSlot14] == 0x629140 && sw[C::IdentityRefusals] == 0, "manager identity words");
    Require(sw[C::PredictedAvoid] <= sw[C::AvoidCalls], "port avoidance calls observed in the queue");
    U counts[16] = {}; Census(plans, counts);
    for (U i = 0; i < 16; ++i) totals[i] += counts[i];
    for (U i = 0; i < C::WordCount; ++i) wordTotals[i] += sw[i];
}

// Stale plans: the avoidance predicate's manager bitset changes after planning.
static B* staleAgent;
static void FlipBit(World& w) {
    U serial = Get<U>(staleAgent, 0x2c), at = (serial >> 5) * 4;
    Put<U>(w.avoidBits, at, Get<U>(w.avoidBits, at) ^ (1u << (serial & 31)));
}
static void MoveBits(World& w) {
    std::memcpy(w.spareBits, w.avoidBits, kBitsBytes); Put<U>(w.avoid, 0x90, A(w.spareBits));
}
static void StalePlans(World& w) {
    currentCase = "stale plan detection";
    RunResult replay, reference; std::vector<C::Plan> plans;
    RunPlanned(w, C::ModeWorkers, replay, &plans);
    // Choose an agent whose availability decided some planned avoidance.
    staleAgent = nullptr;
    for (U i = 0; i < plans.size() && !staleAgent; ++i)
        if (plans[i].kind == C::KindPort && (plans[i].flags & C::FlagAvoid)) staleAgent = w.contacts[i][0];
    Require(staleAgent != nullptr, "fixture plans an avoidance call");
    // Reference: the original callbacks with the bit already flipped at stage entry.
    Reset(w); FlipBit(w); InstallFp();
    for (const auto& c : w.contacts) Require(OriginalCallback(nullptr, c[1], c[0]), "original callback");
    reference.state = State(w);
    RunResult stale;
    RunPlanned(w, C::ModeWorkers, stale, nullptr, &FlipBit);
    Require(stale.words[C::ReplayRevalidated] > 0, "changed availability bit revalidates its plans");
    Require(stale.state == reference.state, "revalidated replay equals the original with the changed bit");
    // The stale plan really was wrong: replanning after the flip changes a decision.
    Reset(w); FlipBit(w); InstallFp();
    C::Start(delta, C::ModeWorkers); C::Stage st; Require(C::BeginStage(st, w.model), "stage admitted");
    std::vector<C::Plan> fresh; Plan(st, w, fresh); C::EndStage(st, 0);
    U changed = 0;
    for (U i = 0; i < plans.size(); ++i) changed += std::memcmp(&plans[i], &fresh[i], sizeof(C::Plan)) != 0;
    Require(changed > 0, "flipped bit changes at least one plan");
    // A moved bitset (same bits) revalidates every availability-dependent plan; state is unchanged.
    RunResult moved, original;
    RunOriginal(w, original);
    RunPlanned(w, C::ModeWorkers, moved, nullptr, &MoveBits);
    U used = 0; for (const C::Plan& p : plans) used += p.kind == C::KindPort && (p.flags & C::FlagUsedAvail);
    Require(moved.words[C::ReplayRevalidated] == used, "moved bitset revalidates every availability plan");
    // Only the manager's bitset pointer differs (outside the canonical state): equal final state.
    Require(moved.state == original.state, "moved bitset replay equals original");
}

struct ThreadJob { const C::Stage* st; World* w; C::Plan* plans; U first, stride; bool reverse; FpEnv env; };
static DWORD WINAPI PlanThread(void* context) {
    ThreadJob& j = *static_cast<ThreadJob*>(context);
    unsigned short cw = j.env.cw;
    __asm { fninit }
    __asm { fldcw cw }
    _mm_setcsr(j.env.mxcsr);
    U count = static_cast<U>(j.w->contacts.size());
    std::vector<U> mine;
    for (U i = j.first; i < count; i += j.stride) mine.push_back(i);
    if (j.reverse) std::reverse(mine.begin(), mine.end());
    for (U i : mine) C::Predict(*j.st, j.plans[i], j.w->contacts[i][0], j.w->contacts[i][1]);
    return 0;
}
static void ThreadDeterminism(World& w) {
    currentCase = "multithread plan determinism";
    Reset(w); InstallFp();
    C::Start(delta, C::ModeWorkers); C::Stage st; Require(C::BeginStage(st, w.model), "stage admitted");
    std::vector<C::Plan> reference; Plan(st, w, reference);
    for (U threads : { 2u, 3u, 5u, 8u }) for (U round = 0; round < 3; ++round) {
        std::vector<C::Plan> plans(w.contacts.size());
        std::memset(plans.data(), 0xcc, plans.size() * sizeof(C::Plan));
        std::vector<ThreadJob> jobs(threads); std::vector<HANDLE> handles(threads);
        for (U t = 0; t < threads; ++t) {
            jobs[t] = { &st, &w, plans.data(), t, threads, ((t + round) & 1) != 0, fp };
            handles[t] = CreateThread(nullptr, 0, &PlanThread, &jobs[t], 0, nullptr);
            Require(handles[t] != nullptr, "planner thread");
        }
        Require(WaitForMultipleObjects(threads, handles.data(), TRUE, 60000) == WAIT_OBJECT_0, "planner threads finish");
        for (HANDLE h : handles) CloseHandle(h);
        Require(std::memcmp(plans.data(), reference.data(), plans.size() * sizeof(C::Plan)) == 0, "worker plans equal owner plans");
    }
    C::EndStage(st, 0);
}

// 0x52EDB0 different-team distance gate: COMISS radius2,d2 / JB keeps equality and rejects NaN.
static void DistanceEdge(World& w) {
    currentCase = "0x52EDB0 distance gate edges";
    const float xs[3] = { 3.0f, 3.0000002f, std::numeric_limits<float>::quiet_NaN() };
    for (U k = 0; k < 3; ++k) for (U swap = 0; swap < 2; ++swap) {
        Reset(w); InstallFp();
        B *a = w.agents[2], *b = w.agents[3];
        Put<U>(a, 0, landTables[0]); Put<U>(b, 0, landTables[0]);
        Put<U>(a, 0x44, 1); Put<U>(b, 0x44, 2);
        Put<float>(a, 0x48, 0.0f); Put<float>(a, 0x50, 0.0f); Put<float>(b, 0x48, xs[k]); Put<float>(b, 0x50, 0.0f);
        Put<float>(a, 0x58, 0.5f); Put<float>(b, 0x58, 0.5f);
        Put<U>(a, 0x1f0, 0x1000); Put<U>(b, 0x1f0, 0x1040);
        Put<U>(a, 0x388, A(w.owners[0])); Put<U>(b, 0x388, A(w.owners[1]));
        for (B* x : { a, b }) for (B* o : { w.owners[0], w.owners[1] }) {
            U key = Get<U>(x, 0x2c) & 0xffff, at = kTracker + 0x20 + (key >> 5) * 4;
            Put<U>(o, at, Get<U>(o, at) & ~(1u << (key & 31)));
        }
        B *r = swap ? b : a, *s = swap ? a : b;
        C::Start(delta, C::ModeShadow); C::Stage st; Require(C::BeginStage(st, w.model), "stage admitted");
        C::Plan p; C::Predict(st, p, r, s); C::CountPlan(p);
        Require(p.kind == C::KindDiffTeam, "different teams stay owner-original");
        bool expect = k == 0;
        Require(((p.flags & C::FlagDistR) != 0) == expect && ((p.flags & C::FlagDistS) != 0) == expect, "distance gate edge");
        Require(C::Shadow(st, p, 0, r, s, &OriginalCallback, nullptr), "original callback");
        C::EndStage(st, 1);
        U words[C::WordCount]; C::Sample(words);
        Require(words[C::Compared] == 1 && words[C::Mismatches] == 0, "pair events agree with the original");
        Require(Get<B>(r, 0x5ec) == (expect ? 1 : 0) && Get<B>(s, 0x5ec) == (expect ? 1 : 0), "pair event observed");
    }
}
static void Refusals(World& w) {
    currentCase = "stage refusals and runtime words";
    Reset(w); InstallFp();
    C::Start(delta, C::ModeOff); C::Stage st;
    Require(!C::BeginStage(st, w.model), "mode off never plans");
    C::Start(delta, C::ModeShadow);
    Require(!C::BeginStage(st, nullptr), "missing model refused");
    Put<U>(w.avoid, 0, Va(0x1334234) + 4);
    Require(!C::BeginStage(st, w.model), "foreign avoidance vtable refused");
    Put<U>(w.avoid, 0, Va(0x1334234));
    U words[C::WordCount]; C::Sample(words);
    Require(words[C::IdentityRefusals] == 1, "identity refusal counted");
    Require(C::BeginStage(st, w.model), "pinned manager admitted");
    uint16_t bias = Get<uint16_t>(At(0x150fbc4), 0);
    Put<uint16_t>(At(0x150fbc4), 0, static_cast<uint16_t>(bias + 1));
    C::EndStage(st, 5);
    Put<uint16_t>(At(0x150fbc4), 0, bias);
    C::Sample(words);
    Require(words[C::GlobalsChanged] == 1 && words[C::MaxContacts] == 5, "runtime word change and maximum published");
    // A faulting read in Predict is a planned owner-original contact, never an escaped exception.
    B *r = w.agents[0], *s = w.agents[1];
    std::vector<B> saveR(r, r + kAgentBytes), saveS(s, s + kAgentBytes);
    Put<U>(r, 0, landTables[0]); Put<U>(s, 0, landTables[0]); Put<U>(r, 0x28, A(w.env)); Put<U>(s, 0x28, A(w.env));
    Put<U>(r, 0x44, 1); Put<U>(s, 0x44, 1); Put<B>(r, 0x117, 0); Put<U>(r, 0x110, 0);
    Put<U>(r, 0x1ec, 0); Put<U>(r, 0x5b8, 0); Put<U>(r, 0x170, 0x10);
    C::Plan plan; C::Predict(st, plan, r, s);
    Require(plan.kind == C::KindFault, "faulting prediction is classified, not raised");
    C::CountPlan(plan); C::Sample(words);
    Require(words[C::OwnerFaults] == 1, "fault census");
    std::memcpy(r, saveR.data(), kAgentBytes); std::memcpy(s, saveS.data(), kAgentBytes);
}
static U recordedSizeAllocBytes, recordedSizeFreeBytes;
static void* recordedSizeAllocPtr, *recordedSizeFreePtr;
static void* __cdecl RecordedSizeAlloc(U bytes) {
    recordedSizeAllocBytes = bytes;
    recordedSizeAllocPtr = std::malloc(bytes ? bytes : 1);
    Require(recordedSizeAllocPtr != nullptr, "recorded size alloc");
    std::memset(recordedSizeAllocPtr, 0xA5, bytes);
    return recordedSizeAllocPtr;
}
static void __cdecl RecordedSizeFree(void* p, U bytes) {
    recordedSizeFreePtr = p;
    recordedSizeFreeBytes = bytes;
    std::free(p);
}
static void AvoidBitsetEnlargement(World& w) {
    currentCase = "avoidance bitset enlargement (0x8004 bytes = 262,176 serials)";
    Reset(w); InstallFp();
    Jump(0x10d3140, Fn(&RecordedSizeAlloc));
    Jump(0x126e016, Fn(&RecordedSizeFree));
    Require(FlushInstructionCache(GetCurrentProcess(), image, imageSize) != 0, "flush size alloc/free seams");
    U bindings[NTW2_BIND_COUNT] = {};
    for (U i = 0; i < NTW2_BIND_COUNT; ++i) bindings[i] = Va(0x462cb0);
    bindings[NTW2_BIND_AVOID_ALLOC] = Fn(&C::AllocBitset);
    bindings[NTW2_BIND_AVOID_FREE] = Fn(&C::FreeBitset);
    ntw2_clone_set clones = {}; U detail = 0;
    Require(ntw2_build_clones(A(image), bindings, &clones, &detail) == 0, "ntw2_build_clones succeeds with AVOID clones");
    U c506 = clones.entries[NTW2_CLONE_AVOID_506C00], c51f = clones.entries[NTW2_CLONE_AVOID_51F150];
    Require(c506 != 0 && c51f != 0, "AVOID_506C00 and AVOID_51F150 clones emitted");
    Require(Get<U>(P(c506 + (0x507485 - 0x506c00)), 1) == 0x2004u &&
            P(c506 + (0x50748a - 0x506c00))[0] == 0xe8 &&
            c506 + (0x50748a - 0x506c00) + 5 + Get<U>(P(c506 + (0x50748a - 0x506c00)), 1) == Fn(&C::AllocBitset) &&
            Get<U>(P(c506 + (0x50749d - 0x506c00)), 1) == C::kAvoidBitsetBytes,
        "CLONE_AVOID_506C00 calls AllocBitset at +0x88A and pushes 0x8004 at +0x89D");
    Require(Get<U>(P(c51f + (0x51f403 - 0x51f150)), 1) == C::kAvoidBitsetBytes &&
            P(c51f + (0x51f40e - 0x51f150))[0] == 0xe8 &&
            c51f + (0x51f40e - 0x51f150) + 5 + Get<U>(P(c51f + (0x51f40e - 0x51f150)), 1) == Fn(&C::FreeBitset),
        "CLONE_AVOID_51F150 pushes 0x8004 at +0x2B3 and calls FreeBitset at +0x2BE");
    C::ConfigureAvoidHooks(delta); C::ResetAvoidCounters();
    recordedSizeAllocBytes = recordedSizeFreeBytes = 0;
    void* block = C::AllocBitset(C::kStockAvoidBitsetBytes);
    Require(block != nullptr && block == recordedSizeAllocPtr && recordedSizeAllocBytes == C::kAvoidBitsetBytes,
        "AllocBitset allocates 0x8004 bytes through 0x10D3140");
    bool allZero = true;
    for (U i = 0; i < C::kAvoidBitsetBytes; ++i) if (static_cast<const B*>(block)[i] != 0) { allZero = false; break; }
    Require(allZero && C::IsEnlargedBitset(A(block)), "AllocBitset zeroes all 0x8004 bytes and registers the block");
    U allocs = 0, frees = 0, refusals = 0, activeBytes = 0;
    C::SampleAvoidWords(allocs, frees, refusals, activeBytes);
    Require(allocs == 1 && frees == 0 && refusals == 0 && activeBytes == C::kAvoidBitsetBytes, "alloc counter and active bytes published");
    // High serial (>= 65,568) refused on stock 0x2004-byte block and admitted on enlarged 0x8004-byte block.
    B *r = w.agents[0], *s = w.agents[1];
    std::vector<B> saveR(r, r + kAgentBytes), saveS(s, s + kAgentBytes);
    Put<U>(r, 0, landTables[0]); Put<U>(s, 0, landTables[0]);
    Put<U>(r, 0x28, A(w.env)); Put<U>(s, 0x28, A(w.env));
    Put<U>(r, 0x44, 1); Put<U>(s, 0x44, 1);
    Put<U>(r, 0x2c, 70000u); Put<U>(s, 0x2c, 100u);
    C::Start(delta, C::ModeWorkers); C::Stage st;
    Require(C::BeginStage(st, w.model) && st.avoidSerialCap == C::kStockAvoidSerialCap, "stock block gets 65,568 serial cap");
    C::Plan plan; C::Predict(st, plan, r, s); C::CountPlan(plan);
    C::SampleAvoidWords(allocs, frees, refusals, activeBytes);
    Require(plan.kind == C::KindSerialOutOfBounds && refusals == 1, "serial 70,000 refused and counted on stock 0x2004-byte block");
    // Install the enlarged block on w.model and verify serial 70,000 and 200,000 are admitted and bit-exact with 0x629180/0x65FF20/0x6795D0.
    Put<U>(w.model, 0xc4, A(block)); Put<U>(w.avoid, 0x90, A(block)); Put<U>(w.combat, 0x90, A(block));
    Require(C::BeginStage(st, w.model) && st.avoidSerialCap == C::kAvoidSerialCap, "enlarged block gets 262,176 serial cap");
    using AvailFn = B (__thiscall*)(void*, void*);
    auto origAvail = reinterpret_cast<AvailFn>(Va(0x6795d0));
    Put<B>(r, 0xec, 1); Put<B>(r, 0xb4, 0); Put<U>(r, 0x18, 0); Put<U>(r, 0x224, 0);
    for (U testSerial : { 65536u, 65568u, 70000u, 131072u, 262143u, 262175u }) {
        Put<U>(r, 0x2c, testSerial);
        U* word = static_cast<U*>(block) + (testSerial >> 5);
        U mask = 1u << (testSerial & 31);
        Require(C::port::Available(A(w.avoid), A(r), st.avoidSerialCap) && origAvail(w.avoid, r) == 1, "available before bts above 64k");
        *word |= mask;
        Require(!C::port::Available(A(w.avoid), A(r), st.avoidSerialCap) && origAvail(w.avoid, r) == 0, "unavailable after bts above 64k");
        C::Predict(st, plan, r, s);
        Require(plan.kind == C::KindPort && (plan.flags & C::FlagBitR) != 0, "Predict observes FlagBitR above 64k");
        *word &= ~mask;
        Require(C::port::Available(A(w.avoid), A(r), st.avoidSerialCap) && origAvail(w.avoid, r) == 1, "available after btr above 64k");
    }
    Put<U>(w.model, 0xc4, 0); Put<U>(w.avoid, 0x90, A(w.avoidBits)); Put<U>(w.combat, 0x90, A(w.combatBits));
    std::memcpy(r, saveR.data(), kAgentBytes); std::memcpy(s, saveS.data(), kAgentBytes);
    // FreeBitset matches the 0x8004 allocation size even if called with 0x2004.
    C::FreeBitset(block, C::kStockAvoidBitsetBytes);
    C::SampleAvoidWords(allocs, frees, refusals, activeBytes);
    Require(recordedSizeFreePtr == block && recordedSizeFreeBytes == C::kAvoidBitsetBytes && frees == 1 && !C::IsEnlargedBitset(A(block)),
        "FreeBitset frees enlarged block with matched size 0x8004");
    // AdoptModelBitset upgrades a stock 0x2004-byte block at model+0xC4/+0xC8/+0xCC in place, preserving existing bits.
    void* stock = RecordedSizeAlloc(C::kStockAvoidBitsetBytes);
    std::memset(stock, 0, C::kStockAvoidBitsetBytes);
    static_cast<U*>(stock)[17] = 0xDEADBEEFu;
    Put<U>(w.model, 0xc4, A(stock)); Put<U>(w.avoid, 0x90, A(stock)); Put<U>(w.combat, 0x90, A(stock));
    Require(C::AdoptModelBitset(A(w.model)), "AdoptModelBitset upgrades stock model+0xC4 block");
    U adopted = Get<U>(w.model, 0xc4);
    Require(adopted != 0 && adopted != A(stock) && C::IsEnlargedBitset(adopted) &&
            Get<U>(w.avoid, 0x90) == adopted && Get<U>(w.combat, 0x90) == adopted &&
            recordedSizeFreePtr == stock && recordedSizeFreeBytes == C::kStockAvoidBitsetBytes &&
            Get<U>(P(adopted), 17 * 4) == 0xDEADBEEFu && Get<U>(P(adopted), 0x2004) == 0u,
        "AdoptModelBitset copies existing 0x2004 bytes, zeroes tail, updates model+0xC4/avoid+0x90/combat+0x90, and frees stock block with 0x2004");
    Require(C::AdoptModelBitset(A(w.model)) && Get<U>(w.model, 0xc4) == adopted, "AdoptModelBitset is idempotent");
    C::FreeBitset(P(adopted), C::kAvoidBitsetBytes);
    Put<U>(w.model, 0xc4, 0); Put<U>(w.avoid, 0x90, A(w.avoidBits)); Put<U>(w.combat, 0x90, A(w.combatBits));
    if (clones.allocation) VirtualFree(clones.allocation, 0, MEM_RELEASE);
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: native_contact_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    static World world;
    const FpEnv envs[2] = { { 0x27f, 0x1f80 }, { 0x07f, 0x9fc0 } };
    const uint16_t globals[3][2] = { { 0x4000, 0x1555 }, { 0x8000, 0x8000 }, { 0x0000, 0x2000 } };
    U worlds = 0;
    for (const FpEnv& env : envs) for (const auto& g : globals) for (U seed = 1; seed <= 4; ++seed) {
        fp = env; SetGlobals(g[0], g[1]);
        Build(world, seed * 7919u + g[0] + env.cw);
        Reset(world); InstallFp();
        C::Start(delta, C::ModeShadow); C::Stage st; Require(C::BeginStage(st, world.model), "stage admitted");
        Require(st.headingBias == g[0] && st.angleGate == g[1], "runtime words sampled at stage entry");
        if (worlds == 0) CompareFacing(st);
        CompareHelpers(world, st);
        C::EndStage(st, 0);
        Sequences(world);
        if (seed == 1) { StalePlans(world); ThreadDeterminism(world); }
        ++worlds;
    }
    Build(world, 99); Refusals(world); DistanceEdge(world); AvoidBitsetEnlargement(world);
    currentCase = "coverage";
    std::printf("plans: port=%u diff=%u foreign=%u unsupported=%u fault=%u writeR=%u writeS=%u avoid=%u usedAvail=%u diffDistance=%u\n",
        totals[C::KindPort], totals[C::KindDiffTeam], totals[C::KindForeign], totals[C::KindUnsupported], totals[C::KindFault],
        totals[8], totals[9], totals[10], totals[11], totals[12]);
    std::printf("shadow: compared=%u avoidCalls=%u ownerAvoid=%u combatAppends=%u trackerAppends=%u unobservable13c=%u ownerWrites13c=%u\n",
        wordTotals[C::Compared], wordTotals[C::AvoidCalls], wordTotals[C::OwnerAvoidCalls], wordTotals[C::CombatQueueAppends],
        wordTotals[C::PredictedTrackerAppends], wordTotals[C::Unobservable13C], wordTotals[C::OwnerWrites13C]);
    std::printf("helpers: classify 1=%u 2=%u 3=%u 4=%u avoid=%u overlap=%u blocks=%u; fixtures: combat=%u engage=%u foreign=%u odd=%u\n",
        classified[1], classified[2], classified[3], classified[4], avoidTrue, overlapTrue, blocksTrue,
        combatDecisions, engageDecisions, foreignCalls, oddCalls);
    Require(totals[C::KindPort] && totals[C::KindDiffTeam] && totals[C::KindForeign] && totals[C::KindUnsupported],
        "every plan kind reached");
    Require(totals[8] && totals[9] && totals[10] && totals[11] && totals[12], "every predicted effect reached");
    Require(classified[1] && classified[2] && classified[3] && classified[4] && avoidTrue && overlapTrue && blocksTrue,
        "every classification outcome reached");
    Require(wordTotals[C::CombatQueueAppends] && wordTotals[C::OwnerAvoidCalls] && wordTotals[C::PredictedTrackerAppends] &&
        wordTotals[C::Unobservable13C] && wordTotals[C::OwnerWrites13C], "every observed owner effect reached");
    Require(combatDecisions && engageDecisions && foreignCalls && oddCalls, "every fixture seam reached");
    LARGE_INTEGER frequency; QueryPerformanceFrequency(&frequency);
    const double ns = 1e9 / double(frequency.QuadPart) / double(timedContacts);
    std::printf("fixture cost per contact (single thread, warm caches): original %.1f ns, plan %.1f ns, owner replay %.1f ns\n",
        double(originalTicks) * ns, double(planTicks) * ns, double(replayTicks) * ns);
    std::printf("native_contact_oracle: %u worlds, %u checks passed\n", worlds, checks);
    return 0;
}
