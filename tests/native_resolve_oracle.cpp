// Bit-exact collision response oracle: mapped untouched Steam 80F290 versus
// the owned resolve state machine. Host callbacks are candidate predicates only;
// agent +3C/+5C/+60 point to the mapped original bodies.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "native_resolve.h"
#pragma fenv_access(on)
namespace r = kntwr_resolve;
using U = uint32_t;
using B = uint8_t;
static_assert(sizeof(void*) == 4, "x86 oracle");
static B* image;
static U delta, original_entry, cases, checks;
static const char* current_case = "map";
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static T Get(const void* p, size_t offset) { T v; std::memcpy(&v, static_cast<const B*>(p) + offset, sizeof(v)); return v; }
template<class T> static void Put(void* p, size_t offset, T v) { std::memcpy(static_cast<B*>(p) + offset, &v, sizeof(v)); }
static void Require(bool value, const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL [%s]: %s\n", current_case, message); std::exit(1); }
}
static void Equal(U expected, U actual, const char* field) {
    ++checks;
    if (expected != actual) {
        std::fprintf(stderr, "FAIL [%s] %s expected=%08X actual=%08X\n", current_case, field, expected, actual); std::exit(1);
    }
}
static void ResetFp(U rounding = 0) {
    unsigned short cw = static_cast<unsigned short>(0x27F | (rounding << 10));
    __asm fninit
    __asm fldcw cw
    _mm_setcsr(0x1F80 | (rounding << 13));
}
static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open supported image read-only");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long n = std::ftell(f); std::rewind(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image length");
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr; B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "hash image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(!std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"), "supported image identity");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred image base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
            std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "image relocation");
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0, "flush private image");
    original_entry = delta + 0x80F290;
}
// 80F290 uses the low byte of arg1's stack slot for inout. Read it immediately
// after RET 8, before any call/push can reuse it; never patch the original code.
__declspec(naked) static B __cdecl Original(void*, void*, const r::Aabb*, B*) {
    __asm {
        push ebp
        mov ebp, esp
        push dword ptr [ebp + 16]
        push dword ptr [ebp + 12]
        mov ecx, dword ptr [ebp + 8]
        call dword ptr [original_entry]
        mov dl, byte ptr [esp - 8]
        mov ecx, dword ptr [ebp + 20]
        mov byte ptr [ecx], dl
        pop ebp
        ret
    }
}
static B __fastcall False(void*, void*) { return 0; }
static B __fastcall AgentClass(void* p, void*) { return Get<B>(p, 0x680); }
static B __fastcall EdgePredicate(void* p, void*) { return Get<B>(p, 0x64); }
static B __fastcall Eligible(void* p, void*) { return Get<B>(p, 4); }
static B __fastcall Secondary(void* p, void*) { return Get<B>(p, 8); }

struct Fixture {
    alignas(16) B agent[0x700]{};
    U agent_vt[64]{}, edge_vt[8]{}, owner_vt[4]{}, sub_vt[2]{};
    B owner[0x20]{}, ring[0x40]{}, edges[4][0x68]{}, capsule[4][0x50]{};
    U l0[5]{}, l1[4]{}, l2[4]{}, scratch[3]{};
    U rings[1]{}, capsules[4]{}, walls[4]{}, wall_data[4]{};
    r::Segment segments[4]{};
    B shape[0x20]{}; float radii[256]{};
    r::Aabb box{-3.0f, -3.0f, 3.0f, 3.0f};
    Fixture() {
        agent_vt[0x3C / 4] = delta + 0x62A620; agent_vt[0x5C / 4] = delta + 0x808570;
        agent_vt[0x60 / 4] = delta + 0x7FFE30;
        agent_vt[0xE8 / 4] = Fn(&False); agent_vt[0xEC / 4] = Fn(&AgentClass); agent_vt[0xF0 / 4] = Fn(&False);
        edge_vt[0x14 / 4] = Fn(&EdgePredicate); owner_vt[2] = Fn(&Secondary); sub_vt[0] = Fn(&Eligible);
        Put<U>(agent, 0, A(agent_vt)); Put<float>(agent, 0x58, 0.75f);
        Put<U>(owner, 0, A(owner_vt)); Put<U>(owner, 0xC, A(sub_vt)); Put<B>(owner, 0x10, 1);
        scratch[0] = A(l0); scratch[1] = A(l1); scratch[2] = A(l2);
        l0[2] = 1; l0[4] = A(rings); l1[1] = 4; l1[3] = A(capsules); l2[1] = 4; l2[3] = A(walls);
        rings[0] = A(ring); Put<U>(ring, 8, A(edges[0]));
        const r::Point points[] = {{-2, 0}, {2, 0}, {2, 4}, {-2, 4}};
        const r::Point tangents[] = {{1, 0}, {0, 1}, {-1, 0}, {0, -1}};
        const r::Point normals[] = {{0, 1}, {-1, 0}, {0, -1}, {1, 0}};
        const r::Point corners[] = {{-1, 0}, {1, 0}, {1, 1}, {-1, 1}};
        for (U i = 0; i < 4; ++i) {
            Put<U>(edges[i], 0, A(edge_vt)); Put<U>(edges[i], 8, A(edges[(i + 1) % 4]));
            Put<r::Point>(edges[i], 0xC, points[i]); Put<r::Point>(edges[i], 0x14, tangents[i]);
            Put<r::Point>(edges[i], 0x1C, normals[i]); Put<r::Point>(edges[i], 0x24, corners[i]);
            Put<float>(edges[i], 0x5C, 10.0f); Put<B>(edges[i], 0x64, i ? 1 : 0);
            Put<U>(capsule[i], 8, A(capsule[(i + 1) % 4]));
            Put<r::Point>(capsule[i], 0xC, points[i]); Put<r::Point>(capsule[i], 0x14, tangents[i]);
            Put<r::Point>(capsule[i], 0x1C, normals[i]); Put<r::Point>(capsule[i], 0x24, corners[i]);
            Put<U>(capsule[i], 0x3C, A(owner)); Put<U>(capsule[i], 0x40, A(capsule[i]));
            Put<U>(capsule[i], 0x44, A(capsule[(i + 1) % 4]));
            capsules[i] = A(capsule[i]); walls[i] = A(wall_data + i); wall_data[i] = A(segments + i);
        }
        segments[0] = {{-4, 0}, {4, 0}};
        segments[1] = {{-2, -2}, {2, 2}};
        segments[2] = {{1, -4}, {1, 4}};
        segments[3] = segments[0];
        Put<U>(shape, 0x18, A(radii));
        for (U i = 0; i < 256; ++i) radii[i] = 0.25f + static_cast<float>(i) / 256.0f;
        Position(0.0f, 0.5f, 0.75f, -1.0f);
    }
    void Position(float x, float z, float dx, float dz) {
        Put<float>(agent, 0x48, x); Put<float>(agent, 0x50, z);
        Put<float>(agent, 0xD4, dx); Put<float>(agent, 0xDC, dz);
        Put<float>(agent, 0x160, x + dx); Put<float>(agent, 0x168, z + dz);
    }
    void Counts(U rings_count, U capsule_count, U wall_count) { l0[3] = rings_count; l1[2] = capsule_count; l2[2] = wall_count; }
};
static void CompareView(const Fixture& f, const B* initial, const r::AgentView& a, B returned, B inout) {
    Equal(Get<U>(f.agent, 0xD4), Get<U>(&a.dx, 0), "D4");
    Equal(Get<U>(f.agent, 0xDC), Get<U>(&a.dz, 0), "DC");
    const U offsets[] = {0x13C, 0x174, 0x175, 0x176, 0x199, 0x1A8};
    const B flags[] = {a.flag13c, a.flag174, a.flag175, a.flag176, a.flag199, a.flag1a8};
    B expected[sizeof(f.agent)]; std::memcpy(expected, initial, sizeof(expected));
    Put<float>(expected, 0xD4, a.dx); Put<float>(expected, 0xDC, a.dz);
    for (U i = 0; i < 6; ++i) {
        Equal(Get<B>(f.agent, offsets[i]), flags[i], "side-effect flag"); Put<B>(expected, offsets[i], flags[i]);
    }
    Equal(returned, a.result, "return"); Equal(inout, a.inout, "inout");
    Require(!std::memcmp(f.agent, expected, sizeof(expected)), "entire original agent agrees (no unmodelled stores)");
    Equal(Get<B>(f.agent, 0xB6), a.result_b6, "B6 is caller-owned, unchanged inside resolve");
}
static void Check(Fixture& f, const char* name, U rounding = 0, int expected_pass = -1, bool nested = false) {
    current_case = name; ++cases;
    static U expected_nested = 0;
    B initial[sizeof(f.agent)]; std::memcpy(initial, f.agent, sizeof(initial));
    r::AgentView a{}; r::Candidates candidates;
    auto* agent = reinterpret_cast<r::Agent*>(f.agent); auto* scratch = reinterpret_cast<r::Scratch*>(f.scratch);
    ResetFp(rounding); r::Capture(agent, scratch, a, candidates);
    r::ShadowBefore(agent, scratch, &f.box);
    if (nested) {
        expected_nested += 2;
        r::ShadowBefore(agent, scratch, &f.box);
        r::ShadowBefore(agent, scratch, &f.box);
        r::ObserveOriginalInout(0xFE); r::ShadowAfter(0xFE);
        r::ObserveOriginalInout(0xFE); r::ShadowAfter(0xFE);
    }
    B original_inout = 0xFF;
    ResetFp(rounding); const B returned = Original(f.agent, f.scratch, &f.box, &original_inout);
    ResetFp(rounding); r::Run(a, candidates, f.box);
    CompareView(f, initial, a, returned, original_inout);
    if (expected_pass >= 0) Equal(static_cast<U>(expected_pass), a.pass, "pass count");
    r::ObserveOriginalInout(original_inout); ResetFp(rounding); r::ShadowAfter(returned);
    U words[r::WordCount]; r::Sample(words);
    Equal(0, words[r::Mismatches], "shadow mismatches"); Equal(0, words[r::Faults], "shadow faults");
    Equal(cases, words[r::Compared], "every call compared");
    Equal(cases, words[r::Calls], "every top-level entry counted");
    U frames[r::FrameWordCount]; r::SampleFrames(frames);
    Equal(expected_nested, words[r::Reentry], "reentry counts only same-owner nesting");
    Equal(expected_nested, frames[r::NestedCalls], "separate nested resolve call count");
    Equal(expected_nested ? 3u : 1u, frames[r::MaxDepth], "actual resolve nesting depth");
    Equal(0, frames[r::OverlappingThreadCalls], "sequential owners never overlap");
}
static DWORD WINAPI HandoffOwner(void*) {
    Fixture f; f.Counts(0, 0, 1);
    Check(f, "quiescent native owner handoff", 0, 0, true);
    return 0;
}
static void CheckOwnerHandoff() {
    // Runtime Stage permits sequential native tick owners to migrate between
    // OS threads. Every migrated top-level gate must compare, not pin the first.
    U before[r::FrameWordCount]; r::SampleFrames(before);
    for (U i = 0; i < 3; ++i) {
        HANDLE thread = CreateThread(nullptr, 0, HandoffOwner, nullptr, 0, nullptr);
        Require(thread != nullptr, "create replacement native owner");
        Require(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, "join replacement native owner");
        DWORD code = ~0u;
        Require(GetExitCodeThread(thread, &code) != FALSE && code == 0, "replacement owner completed");
        CloseHandle(thread);
    }
    Fixture f; f.Counts(0, 0, 1);
    Check(f, "handoff back to original native owner", 0, 0);
    U after[r::FrameWordCount]; r::SampleFrames(after);
    Require(after[r::OwnerHandoffs] >= before[r::OwnerHandoffs] + 2, "owner handoff and return separately recorded");
}
static DWORD WINAPI OverlappingOwner(void* ptr) {
    auto& f = *static_cast<Fixture*>(ptr);
    r::ShadowBefore(reinterpret_cast<r::Agent*>(f.agent), reinterpret_cast<r::Scratch*>(f.scratch), &f.box);
    r::ObserveOriginalInout(0xFE); r::ShadowAfter(0xFE);
    return 0;
}
static void CheckOverlapIsolation() {
    current_case = "overlapping thread is not recursion";
    Fixture f; f.Counts(0, 0, 1);
    U before[r::WordCount]; r::Sample(before);
    U frame_before[r::FrameWordCount]; r::SampleFrames(frame_before);
    r::ShadowBefore(reinterpret_cast<r::Agent*>(f.agent), reinterpret_cast<r::Scratch*>(f.scratch), &f.box);
    HANDLE thread = CreateThread(nullptr, 0, OverlappingOwner, &f, 0, nullptr);
    Require(thread != nullptr, "create overlapping owner probe");
    Require(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, "join overlapping owner probe");
    CloseHandle(thread);
    B inout;
    const B returned = Original(f.agent, f.scratch, &f.box, &inout);
    r::ObserveOriginalInout(inout); r::ShadowAfter(returned);
    U after[r::WordCount]; r::Sample(after);
    U frame_after[r::FrameWordCount]; r::SampleFrames(frame_after);
    Equal(before[r::Calls] + 1, after[r::Calls], "overlap does not consume outer entry");
    Equal(before[r::Compared] + 1, after[r::Compared], "outer owner still compared");
    Equal(before[r::Faults] + 1, after[r::Faults], "actual overlap invalidates equivalence");
    Equal(before[r::Mismatches], after[r::Mismatches], "outer snapshot is intact");
    Equal(before[r::Reentry], after[r::Reentry], "overlap is not counted as recursion");
    Equal(frame_before[r::NestedCalls], frame_after[r::NestedCalls], "nested count remains distinct");
    Equal(frame_before[r::OverlappingThreadCalls] + 1, frame_after[r::OverlappingThreadCalls], "overlap reported separately");
    ++cases;
}
static void CheckWorkerBudget() {
    current_case="activation-bounded repeated scene and native worker differential";
    Fixture f;
    f.agent_vt[0xE8/4]=f.agent_vt[0xEC/4]=f.agent_vt[0xF0/4]=delta+0x462CB0;
    f.edge_vt[0x14/4]=delta+0x462CB0; f.sub_vt[0]=delta+0x54E920; f.owner_vt[2]=delta+0x462CB0;
    B ring[0x60]{}; std::memcpy(ring,f.ring,sizeof(f.ring));
    U active[1]={delta+0x54E920};
    Put<U>(ring,0x1C,A(active)); Put<U>(ring,0x20,1); Put<U>(ring,0x2C,1);
    Put<float>(ring,0x34,1); Put<float>(ring,0x50,64); Put<float>(ring,0x58,64);
    Put<U>(f.capsule[0],0x34,7); Put<U>(f.capsule[1],0x34,0x10007);
    struct Node { U type,id,payload,owner,previous,next,head; } nodes[5]{};
    nodes[0]={0x40,0,0,A(ring),0,A(nodes+1),0};
    nodes[1]={0x20,0,0,A(f.capsule[0]),0,A(nodes+2),0};
    nodes[2]={0x20,0,0,A(f.capsule[1]),0,A(nodes+3),0};
    nodes[3]={0x800,0,A(f.wall_data),0,0,A(nodes+4),0};
    nodes[4]={0x800,0,A(f.wall_data),0,0,0,0};
    std::vector<U> heads(4096);
    for(U i=0;i<512;++i) heads[i]=A(nodes);
    U grid[10]{},tree[20]{},root[12]{},model[49]{};
    grid[0]=A(heads.data()); grid[2]=6; grid[5]=63; Put<float>(grid,0x24,1);
    Put<float>(root,0x10,64); Put<float>(root,0x18,64);
    tree[0x4C/4]=A(root)-0xC; model[0xA8/4]=A(grid); model[0xC0/4]=A(tree);
    kntwr_sweep::WorkerScene scene;
    Require(kntwr_sweep::PrepareScene(scene,A(model),delta,90),"capture full sparse native scene");
    r::WorkerCatalog catalog;
    heads.back()=A(nodes);
    Require(!r::PrepareCatalog(catalog,scene),"catalog final verification catches uncaptured cell publication");
    Require(!scene.verification[0].empty(),"failed final verification never discards evidence");
    // The failed full-scene check retains the entire catalog tape as well.
    // Probe every static word, including capsule[2]/[3], which are reachable
    // only through the cycles and are not outer candidates in this scene.
    auto checkStatic = [&](U address) {
        const auto& tape = scene.verification[3];
        Require(std::any_of(tape.begin(), tape.end(), [&](const kntwr_sweep::VerificationWord& word) {
            return word.address == address;
        }), "complete canonical geometry verification address coverage");
        void* p = reinterpret_cast<void*>(address);
        const U saved = Get<U>(p, 0); Put<U>(p, 0, saved ^ 1);
        Require(!kntwr_sweep::VerifyBuild(scene, 3, 1), "each static geometry mutation is detected");
        Put<U>(p, 0, saved);
    };
    checkStatic(A(ring) + 8);
    for (U offset = 0x30; offset < 0x40; offset += 4) checkStatic(A(ring) + offset);
    for (U i = 0; i < 4; ++i) {
        for (U offset = 8; offset < 0x2C; offset += 4) checkStatic(A(f.edges[i]) + offset);
        checkStatic(A(f.edges[i]) + 0x5C);
        for (U offset : {8u, 0xCu, 0x10u, 0x24u, 0x28u}) checkStatic(A(f.capsule[i]) + offset);
    }
    for (U i = 0; i < 2; ++i) {
        for (U offset = 0xC; offset < 0x2C; offset += 4) checkStatic(A(f.capsule[i]) + offset);
        checkStatic(A(f.capsule[i]) + 0x40); checkStatic(A(f.capsule[i]) + 0x44);
    }
    checkStatic(A(f.wall_data));
    for (U offset = 0; offset < sizeof(r::Segment); offset += 4) checkStatic(A(f.segments) + offset);
    Require(kntwr_sweep::VerifyBuild(scene, 3, 1), "restored complete geometry tape verifies");
    heads.back()=0;
    Require(!r::PrepareCatalog(catalog,scene),"same-generation failed catalog remains refused");
    Require(kntwr_sweep::PrepareScene(scene,A(model),delta,91),"new generation rebuilds complete scene");
    Require(r::PrepareCatalog(catalog,scene),"capture and verify immutable resolve geometry");
    for(const auto& tape:scene.verification) Equal(0,static_cast<U>(tape.capacity()),"verification capacity released only after complete check");
    r::WorkerContext worker;
    Require(r::PrepareWorker(worker,catalog),"prepare exact type-specific resolve storage");
    Equal(2,static_cast<U>(worker.selected.rings.capacity()),"ring bound is distinct grid and graph domains");
    Equal(2,static_cast<U>(worker.selected.capsules.capacity()),"capsule bound counts owner identities despite ID aliases");
    Equal(1024,static_cast<U>(worker.selected.walls.capacity()),"wall multiplicity is not replaced by unique geometry count");
    Equal(4112,static_cast<U>(r::HeapBytes(worker)),"actual selected storage uses exact bounds rather than membership-wide reserves");
    kntwr_sweep::WorkerContext sweep;
    Require(kntwr_sweep::PrepareWorker(sweep,scene),"prepare source sweep");
    U headers[3][5]{},scratch[3]={A(headers[0]),A(headers[1]),A(headers[2])};
    Put<float>(f.agent,0x54,1);
    const kntwr_sweep::Aabb all{0,0,63,63};
    Require(kntwr_sweep::WorkerSweep(sweep,f.agent,A(f.agent),scratch,all,0x15),"sweep full repeated scene");
    Equal(1,headers[0][3],"grid owners deduplicate");
    Equal(1,headers[1][2],"capsule low-u16 aliases deduplicate");
    Equal(1024,headers[2][2],"every repeated wall remains in native order");
    const size_t bytes=r::HeapBytes(worker);
    for(U split=0;split<2;++split) {
        if(split) {
            Put<U>(f.capsule[1],0x34,8); std::memset(headers,0,sizeof(headers));
            Require(kntwr_sweep::WorkerSweep(sweep,f.agent,A(f.agent),scratch,all,0x15),"live aliases split inside preallocated bounds");
            Equal(2,headers[1][2],"both capsule owners remain selectable");
        }
        alignas(16) B initial[sizeof(f.agent)],copy[sizeof(f.agent)];
        std::memcpy(initial,f.agent,sizeof(initial)); std::memcpy(copy,initial,sizeof(copy));
        B inout=0,returned=0;
        ResetFp(); const B expected=Original(f.agent,scratch,&f.box,&inout);
        if(expected) Put<B>(f.agent,0xB6,1); // caller-owned store included by WorkerResolve
        ResetFp(); Require(r::WorkerResolve(worker,copy,A(copy),scratch,f.box,returned),"worker resolves full candidate bounds");
        Equal(expected,returned,"untouched native resolve return");
        Require(!std::memcmp(copy,f.agent,sizeof(copy)),"all worker result bytes agree with untouched native body");
        Require(r::HeapBytes(worker)==bytes,"resolving repeated memberships never grows selected storage");
        std::memcpy(f.agent,initial,sizeof(initial));
    }
}
static void CheckCyclicCatalogBudget() {
    current_case = "distinct candidates sharing rotated native cycles";
    Fixture f;
    f.agent_vt[0xE8/4] = f.agent_vt[0xEC/4] = f.agent_vt[0xF0/4] = delta + 0x462CB0;
    f.edge_vt[0x14/4] = delta + 0x462CB0;
    f.sub_vt[0] = delta + 0x54E920; f.owner_vt[2] = delta + 0x462CB0;
    constexpr U ringCount = 64, edgeCount = 263, cycleA = 257, cycleB = 263;
    constexpr U capsuleCount = cycleA + cycleB;
    std::vector<std::array<B, 0x68>> edges(edgeCount);
    std::vector<std::array<B, 0x50>> capsules(capsuleCount);
    std::vector<std::array<B, 0x60>> rings(ringCount);
    for (U i = 0; i < edgeCount; ++i) {
        std::memcpy(edges[i].data(), f.edges[i % 4], sizeof(f.edges[0]));
        Put<U>(edges[i].data(), 8, A(edges[(i + 1) % edgeCount].data()));
    }
    for (U i = 0; i < capsuleCount; ++i) {
        const U begin = i < cycleA ? 0 : cycleA, count = i < cycleA ? cycleA : cycleB;
        const U next = begin + (i - begin + 1) % count;
        std::memcpy(capsules[i].data(), f.capsule[i % 4], sizeof(f.capsule[0]));
        Put<U>(capsules[i].data(), 8, A(capsules[next].data()));
        Put<U>(capsules[i].data(), 0x40, A(capsules[i].data()));
        Put<U>(capsules[i].data(), 0x44, A(capsules[next].data()));
        Put<U>(capsules[i].data(), 0x34, i + 1);
    }
    U active[1] = {delta + 0x54E920};
    for (U i = 0; i < ringCount; ++i) {
        B* ring = rings[i].data();
        Put<U>(ring, 8, A(edges[(i * 17) % edgeCount].data()));
        Put<U>(ring, 0x1C, A(active)); Put<U>(ring, 0x20, 1); Put<U>(ring, 0x2C, i + 1);
        Put<float>(ring, 0x34, 1); Put<float>(ring, 0x50, 64); Put<float>(ring, 0x58, 64);
    }
    struct Node { U type, id, payload, owner, previous, next, head; };
    // Repeated outer memberships are intentional, but cannot explain this
    // regression: there are 520 DISTINCT capsules on only two native cycles.
    std::vector<Node> nodes(ringCount + capsuleCount + 8);
    for (U i = 0; i < nodes.size(); ++i) {
        nodes[i] = {i < ringCount ? 0x40u : 0x20u, 0, 0,
            i < ringCount ? A(rings[i].data()) : A(capsules[(i - ringCount) % capsuleCount].data()),
            0, i + 1 < nodes.size() ? A(&nodes[i + 1]) : 0, 0};
    }
    U heads[1] = {A(nodes.data())}, grid[10]{}, tree[20]{}, root[12]{}, model[49]{};
    grid[0] = A(heads); Put<float>(grid, 0x24, 1);
    Put<float>(root, 0x10, 64); Put<float>(root, 0x18, 64);
    tree[0x4C/4] = A(root) - 0xC; model[0xA8/4] = A(grid); model[0xC0/4] = A(tree);
    kntwr_sweep::WorkerScene scene;
    Require(kntwr_sweep::PrepareScene(scene, A(model), delta, 120), "capture rotated-cycle scene");
    r::WorkerCatalog catalog;
    Require(r::PrepareCatalog(catalog, scene), "prepare canonical nested geometry");
    const r::Candidates& geometry = catalog.geometry;
    Equal(ringCount, static_cast<U>(geometry.rings.size()), "distinct ring identities retained");
    Equal(capsuleCount, static_cast<U>(geometry.capsules.size()), "distinct capsule identities retained");
    Equal(1, geometry.edge_cycles, "rotated ring owners share one cycle");
    Equal(2, geometry.polygon_cycles, "disjoint polygon cycles remain distinct");
    Equal(edgeCount, static_cast<U>(geometry.edges.size()), "one backing edge per native edge");
    Equal(capsuleCount, static_cast<U>(geometry.polygon_points.size()), "one backing point per native polygon node");
    for (const r::Ring& ring : geometry.rings) {
        U node = Get<U>(reinterpret_cast<void*>(ring.native), 8);
        for (U i = 0; i < ring.edges.count; ++i) {
            Equal(node, geometry.edges[ring.edges.Index(i)].native, "ring preserves rotated native order");
            node = Get<U>(reinterpret_cast<void*>(node), 8);
        }
        Equal(Get<U>(reinterpret_cast<void*>(ring.native), 8), node, "ring includes exactly one wrap");
    }
    for (const r::Capsule& capsule : geometry.capsules) {
        U node = capsule.native;
        for (U i = 0; i < capsule.polygon.count; ++i) {
            const r::PolygonPoint& point = geometry.polygon_points[capsule.polygon.Index(i)];
            Require(!std::memcmp(&point.point, reinterpret_cast<void*>(node + 0xC), sizeof(r::Point)),
                "polygon preserves every rotated point");
            Require(!std::memcmp(&point.normal, reinterpret_cast<void*>(node + 0x24), sizeof(r::Point)),
                "polygon preserves every offset normal");
            node = Get<U>(reinterpret_cast<void*>(node), 8);
        }
        Equal(capsule.native, node, "polygon includes exactly one wrap");
    }
    U storage[r::CatalogStorageWordCount]; r::SampleCatalogStorage(catalog, storage);
    const U expected[] = {ringCount * sizeof(r::Ring), capsuleCount * sizeof(r::Capsule), 0,
        edgeCount * sizeof(r::Edge), capsuleCount * sizeof(r::PolygonPoint),
        ringCount, capsuleCount, 0, edgeCount, capsuleCount};
    for (U i = 0; i < r::CatalogStorageWordCount; ++i) Equal(expected[i], storage[i], "exact compact catalog subcategory");
    const size_t expectedBytes = ringCount * sizeof(r::Ring) + capsuleCount * sizeof(r::Capsule) +
        edgeCount * sizeof(r::Edge) + capsuleCount * sizeof(r::PolygonPoint);
    Equal(89576, static_cast<U>(expectedBytes), "source-derived x86 regression catalog bytes");
    Require(r::HeapBytes(catalog) == expectedBytes && expectedBytes < 96 * 1024,
        "retained bytes are linear, not per-candidate whole cycles or growth slack");
    for (const auto& tape : scene.verification) Require(tape.capacity() == 0, "complete activation check releases tapes");
    r::WorkerContext worker;
    Require(r::PrepareWorker(worker, catalog), "prepare worker for rotated views");
    U selectedRings[] = {A(rings[63].data()), A(rings[0].data()), A(rings[63].data())};
    U selectedCapsules[] = {A(capsules[256].data()), A(capsules[519].data()), A(capsules[0].data()),
        A(capsules[257].data()), A(capsules[256].data()), A(capsules[3].data())};
    f.l0[4] = A(selectedRings); f.l1[3] = A(selectedCapsules); f.Counts(3, 6, 0);
    for (U mode = 0; mode < 4; ++mode) {
        f.Position(0, .5f, .75f, -1); Put<U>(f.agent, 0x10, mode & 1 ? A(f.owner) : 0);
        for (U offset : {0xB6u, 0x13Cu, 0x174u, 0x175u, 0x176u, 0x199u, 0x1A8u}) Put<B>(f.agent, offset, 0);
        alignas(16) B initial[sizeof(f.agent)], copy[sizeof(f.agent)];
        std::memcpy(initial, f.agent, sizeof(initial)); std::memcpy(copy, initial, sizeof(copy));
        Check(f, "rotated shared geometry and repeated candidates native differential", mode);
        std::memcpy(f.agent, initial, sizeof(initial));
        ResetFp(mode); Require(r::PrepareWorker(worker, catalog), "capture worker FP mode");
        B inout = 0, returned = 0;
        ResetFp(mode); const B expectedReturn = Original(f.agent, f.scratch, &f.box, &inout);
        if (expectedReturn) Put<B>(f.agent, 0xB6, 1);
        ResetFp(mode); Require(r::WorkerResolve(worker, copy, A(copy), f.scratch, f.box, returned),
            "worker resolves repeated rotated ranges");
        Equal(expectedReturn, returned, "rotated worker return");
        Require(!std::memcmp(copy, f.agent, sizeof(copy)), "rotated worker byte-exact differential");
        std::memcpy(f.agent, initial, sizeof(initial));
        Equal(3, static_cast<U>(worker.selected.rings.size()), "worker preserves ring repetitions");
        Equal(6, static_cast<U>(worker.selected.capsules.size()), "worker preserves capsule repetitions");
    }
    // A copied shadow snapshot owns its flat storage; no range can point back
    // into the source snapshot or native geometry.
    r::AgentView view{};
    r::Candidates captured;
    ResetFp(); r::Capture(reinterpret_cast<r::Agent*>(f.agent), reinterpret_cast<r::Scratch*>(f.scratch), view, captured);
    r::Candidates copied = captured; captured = {};
    alignas(16) B initial[sizeof(f.agent)]; std::memcpy(initial, f.agent, sizeof(initial));
    B inout = 0;
    ResetFp(); const B returned = Original(f.agent, f.scratch, &f.box, &inout);
    ResetFp(); r::Run(view, copied, f.box);
    CompareView(f, initial, view, returned, inout);
}
static void Cases() {
    { Fixture f; Check(f, "empty", 0, 0); }
    { Fixture f; f.Counts(0, 0, 1); Check(f, "one wall deep slide", 0, 0); }
    { Fixture f; f.Counts(0, 0, 1); f.Position(0, 2, 0.75f, -2); Check(f, "wall partial"); }
    { Fixture f; f.Counts(0, 0, 1); f.Position(0, -0.5f, 0.75f, 1); Check(f, "wall other side"); }
    { Fixture f; f.Counts(0, 0, 1); Put<B>(f.agent, 0x117, 1); Check(f, "wall sets199 before117"); }
    { Fixture f; f.Counts(0, 0, 1); f.Position(4.05f, .5f, -.25f, -1); Check(f, "wall infinite line flag projection"); }
    { Fixture f; f.Counts(0, 0, 1); f.segments[0].b = f.segments[0].a; Check(f, "degenerate wall"); }
    { Fixture f; f.Counts(0, 0, 2); Check(f, "two wall second pass", 0, 1); }
    {
        Fixture f; f.Counts(0, 0, 2); f.segments[1] = {{-1, 2}, {3, -2}};
        Check(f, "second pass persistent inout truncates corner", 0, 1);
        Equal(0, Get<U>(f.agent, 0xD4), "second contact clears dx");
        Equal(0, Get<U>(f.agent, 0xDC), "second contact clears dz");
    }
    { Fixture f; f.Counts(0, 0, 4); Check(f, "wall duplicates retain order", 0, 1); }
    { Fixture f; f.Counts(0, 1, 0); Check(f, "one capsule", 0, 0); }
    { Fixture f; f.Counts(0, 1, 0); f.Position(0, 2, .75f, -2); Check(f, "capsule partial"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.agent, 0x110, 0x2000); Check(f, "capsule inout cleared by flag virtual"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.agent, 0x110, 0x2000); Put<B>(f.agent, 0x117, 1); Check(f, "clear inout precedes117 gate"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.capsule[0], 0x38, 2); Check(f, "capsule type2 AV excludes"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.capsule[0], 0x38, 2); Put<B>(f.agent, 0x680, 1); Check(f, "capsule type2 AV0 admits"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.capsule[0], 0x38, 2); Put<B>(f.agent, 0x680, 1); Put<B>(f.owner, 8, 1); Check(f, "capsule secondary excludes"); }
    { Fixture f; f.Counts(0, 1, 0); Put<B>(f.owner, 0x10, 0); Check(f, "capsule eligibility excludes"); }
    { Fixture f; f.Counts(0, 1, 0); Put<B>(f.owner, 0x10, 2); Check(f, "eligibility must equal one, not merely nonzero"); }
    { Fixture f; f.Counts(0, 1, 0); Put<B>(f.capsule[0], 0x2C, 1); Check(f, "capsule first normal selector"); }
    { Fixture f; f.Counts(0, 1, 0); Put<B>(f.capsule[1], 0x2C, 1); Check(f, "capsule endpoint normal selector"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.capsule[1], 0x38, 2); Check(f, "capsule rounded end"); }
    { Fixture f; f.Counts(0, 1, 0); Put<U>(f.capsule[0], 0x38, 2); Put<U>(f.capsule[1], 0x38, 2); Put<B>(f.agent, 0x680, 1); Check(f, "capsule both rounded"); }
    { Fixture f; f.Counts(0, 1, 1); Check(f, "capsule wall two pass", 0, 1); }
    { Fixture f; f.Counts(1, 0, 0); Put<U>(f.agent, 0x10, A(f.owner)); f.Position(0, -.5f, .75f, 1); Check(f, "one ring edge", 0, 0); }
    { Fixture f; f.Counts(1, 0, 0); Put<U>(f.agent, 0x10, A(f.owner)); f.Position(0, -2, .75f, 2); Check(f, "ring partial"); }
    { Fixture f; f.Counts(1, 0, 0); Put<U>(f.agent, 0x10, A(f.owner)); Put<float>(f.edges[0], 0x5C, .3f); f.Position(0, -.5f, .75f, 1); Check(f, "ring radius clamp"); }
    { Fixture f; f.Counts(1, 0, 0); f.Position(0, -.5f, .75f, 1); Check(f, "no owner skips ring response"); }
    { Fixture f; f.Counts(0, 1, 1); Put<U>(f.agent, 0x10, A(f.owner)); Check(f, "owner skips phaseA"); }
    { Fixture f; f.Counts(1, 1, 2); Put<U>(f.agent, 0x10, A(f.owner)); Put<B>(f.edges[1], 0x60, 1); Check(f, "blocking prescan opens both phases"); }
    { Fixture f; f.Counts(1, 1, 2); Put<B>(f.edges[1], 0x60, 1); f.box = {20, 20, 30, 30}; Check(f, "prescan AABB excludes"); }
    { Fixture f; f.Counts(0, 0, 1); Check(f, "nested shadow does not consume outer", 0, 0, true); }
    // All 256 shape bins and non-default x87/SSE rounding controls.
    for (U mode = 0; mode < 4; ++mode) for (U heading = 0; heading < 256; ++heading) {
        Fixture f; f.Counts(0, 1, 1); Put<U>(f.agent, 0x60, A(f.shape));
        Put<uint16_t>(f.agent, 0x64, static_cast<uint16_t>(heading * 256 + 127));
        Check(f, "capsule shape bins and rounding", mode);
    }
    for (U heading = 0; heading < 256; ++heading) {
        Fixture f; f.Counts(1, 0, 0); Put<U>(f.agent, 0x10, A(f.owner)); Put<U>(f.agent, 0x60, A(f.shape));
        Put<uint16_t>(f.agent, 0x64, static_cast<uint16_t>(heading * 256)); f.Position(0, -.5f, .75f, 1);
        Check(f, "ring shape bins");
    }
    for (U flags : {0u, 1u, 0x1000u, 0x2000u, 0x3000u}) for (U side = 0; side < 4; ++side) {
        Fixture f; f.Counts(0, 1, 2); Put<U>(f.agent, 0x110, flags); Put<U>(f.agent, 0x188, 1);
        Put<B>(f.agent, 0x175, static_cast<B>(side & 1)); Put<B>(f.agent, 0x176, static_cast<B>(side >> 1));
        Check(f, "virtual side flags and angle gate");
    }
    const float boundaries[] = {0.0f, -0.0f, .75f, 1.0f, std::nextafter(1.0f, 0.0f), std::nextafter(1.0f, 2.0f), 1.0e-38f};
    for (float z : boundaries) { Fixture f; f.Counts(0, 1, 1); f.Position(0, z, -.25f, -1); Check(f, "boundary signed zero denormal"); }
    // Deterministic non-axis-aligned walls, varying displacement and list order.
    U random = 0x801140;
    auto scalar = [&]() {
        random = random * 1664525u + 1013904223u;
        return static_cast<float>(static_cast<int>((random >> 16) & 0x7FF) - 1024) / 127.0f;
    };
    for (U i = 0; i < 512; ++i) {
        Fixture f; f.Counts(i & 1, (i >> 1) & 1, 4);
        f.Position(scalar(), scalar(), scalar(), scalar());
        for (auto& segment : f.segments) segment = {{scalar(), scalar()}, {scalar(), scalar()}};
        if (i & 1) { Put<U>(f.agent, 0x10, A(f.owner)); Put<B>(f.edges[1], 0x60, 1); }
        if (i & 4) { Put<U>(f.agent, 0x60, A(f.shape)); Put<uint16_t>(f.agent, 0x64, static_cast<uint16_t>(random)); }
        Check(f, "deterministic mixed candidate corpus");
    }
    CheckWorkerBudget();
    CheckCyclicCatalogBudget();
    CheckOwnerHandoff();
    ResetFp();
    CheckOverlapIsolation();
    U words[r::WordCount]; r::Sample(words);
    Require(words[r::Target0] && words[r::Target0Calls], "native virtual target histogram populated");
    const U faults_before_abandon = words[r::Faults];
    { Fixture f; r::ShadowBefore(reinterpret_cast<r::Agent*>(f.agent), reinterpret_cast<r::Scratch*>(f.scratch), &f.box); }
    r::Abandon(); r::Sample(words); Equal(faults_before_abandon + 1, words[r::Faults], "abandon reports discarded frame");
    r::Start({delta, 2, false}); r::Sample(words);
    for (U value : words) Equal(0, value, "disabled status entirely zero");
    U frames[r::FrameWordCount]; r::SampleFrames(frames);
    for (U value : frames) Equal(0, value, "disabled frame status entirely zero");
}
int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_resolve_oracle <supported Napoleon.exe>\n"); return 2; }
    Map(argv[1]); Require(r::Start({delta, 1, true}), "start resolve shadow");
    Cases(); r::Stop(); VirtualFree(image, 0, MEM_RELEASE);
    std::printf("native_resolve_oracle: %u cases, %u checks\n", cases, checks); return 0;
}
