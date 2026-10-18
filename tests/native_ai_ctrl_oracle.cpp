// --ai-ctrl-* oracle (src/ntw2_ai_ctrl_batch.{h,cpp}) on the mapped approved image (no game process, no .text patch).
//  1. The seven-counter leaf 0x749D90: the module's exact port (ntw2_ai_ctrl::Histogram) versus the ORIGINAL machine code, byte for
//     byte over the 28 output bytes: every class/subtype branch x B41/B44 combination x filter values (low byte decides), list
//     multiplicity/duplicates, empty lists, filter 0 versus 1, deterministic random mixes.
//  2. Batch ABI: begin/end/epoch parity, retire callbacks (begin epoch, once per end, deduplicated, cleared by Reset), a begin inside an
//     open batch ends it first.
//  3. Gates: histogram (outside a batch / filter != 1 / foreign context -> native; first call computes, repeats served from the batch
//     copy, retired at the next batch; verify mismatch -> native value + latch; census is native + shadow compare and counts repeat /
//     transition), scorer (exact slot -> clone, foreign slot ends the batch), refresh (ends the batch, native refresh runs outside, begins
//     with P=EBX, C=P+0x68), assign (EAX/ECX/EDX/EFLAGS preserved) and exit.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "clones/ntw2_clones.h"
#include "ai/ntw2_ai_ctrl_batch.h"

using U = uint32_t;
using B = unsigned char;
namespace ac = ntw2_ai_ctrl;
static_assert(sizeof(void*) == 4, "Win32 native ABI");
static B* image;
static U delta, checks;
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
[[noreturn]] static void Fail(const char* what) { std::fprintf(stderr, "FAIL: %s\n", what); std::exit(1); }
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail(what); }

static void Map(const char* path) {
    FILE* f = std::fopen(path, "rb"); Require(f != nullptr, "open approved image read-only");
    Require(!std::fseek(f, 0, SEEK_END), "seek image"); long size = std::ftell(f); std::rewind(f);
    Require(size > 0 && size < 256 * 1024 * 1024, "bounded image size");
    std::vector<B> bytes(static_cast<size_t>(size));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image"); std::fclose(f);
    BCRYPT_ALG_HANDLE algorithm = nullptr; B hash[32];
    Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(algorithm, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), hash, 32) == 0, "SHA image");
    BCryptCloseAlgorithmProvider(algorithm, 0);
    char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
    Require(!std::strcmp(hex, NTW2_IMAGE_SHA256), "pinned Steam image");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
               std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
                                reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "relocation");
}

// ---- fixtures: unit (+B41, +B44, +2C -> type {+1C class, +20 subtype}) and context (+C count, +10 -> unit pointer array)
static B* NewUnit(U cls, U sub, B b41, B b44) {
    B* type = new B[0x40](); memcpy(type + 0x1C, &cls, 4); memcpy(type + 0x20, &sub, 4);
    B* unit = new B[0xC00]();
    const U t = A(type); memcpy(unit + 0x2C, &t, 4); unit[0xB41] = b41; unit[0xB44] = b44;
    return unit;
}
struct Ctx {
    std::vector<U> list; B obj[0x40];
    Ctx() { memset(obj, 0, sizeof(obj)); }
    U Addr() { Sync(); return A(obj); }
    void Sync() {
        const U n = static_cast<U>(list.size()), p = list.empty() ? 0xDEAD0000u : A(list.data());
        memcpy(obj + 0xC, &n, 4); memcpy(obj + 0x10, &p, 4);
    }
};
typedef void (__fastcall *HistFn)(U* out, U edx, U C, U filter);
static void NativeHist(U C, U filter, U out[7]) {
    for (U i = 0; i < 7; ++i) out[i] = 0xCDCDCDCDu;
    reinterpret_cast<HistFn>(A(At(0x749D90)))(out, 0xBADF00Du, C, filter);
}
static void PortHist(U C, U filter, U out[7], U* eligible = nullptr) {
    for (U i = 0; i < 7; ++i) out[i] = 0xCDCDCDCDu;
    ac::Histogram(C, filter, out, eligible);
}
static void ExpectLeaf(Ctx& c, U filter, const char* what) {
    U n[7], p[7], e = 0;
    NativeHist(c.Addr(), filter, n); PortHist(c.Addr(), filter, p, &e);
    Require(!memcmp(n, p, sizeof(n)), what);
    // eligible = units that pass the filter (all when the low byte of filter is 0)
    U want = 0;
    for (U u : c.list) { const B* b = reinterpret_cast<const B*>(u); if ((filter & 0xFF) == 0 || (b[0xB41] && b[0xB44])) ++want; }
    Require(e == want, "eligible count");
}

static void LeafCases() {
    const U classes[] = {0, 2, 1, 3, 5, 0xFFFFFFFFu, 0x100};
    const U subs[] = {0, 4, 8, 0xD, 5, 7, 9, 0xC, 0xE, 0x80, 0xFFFFFFFFu};
    const B flags[] = {0, 1, 2, 0x80, 0xFF};
    const U filters[] = {0, 1, 2, 0x100, 0x1FF, 0xFFFFFF01u};
    U cases = 0;
    for (U cls : classes) for (U sub : subs) for (B b41 : flags) for (B b44 : flags) {
        Ctx c; c.list.push_back(A(NewUnit(cls, sub, b41, b44)));
        for (U f : filters) { ExpectLeaf(c, f, "single-unit class/subtype/B41/B44/filter combination"); ++cases; }
    }
    // Every output slot is reached by some unit and the filter flips it on/off.
    Ctx all;
    const struct { U cls, sub; U slot; } slots[] = {{2, 5, 0}, {2, 4, 1}, {2, 8, 2}, {2, 0xD, 3}, {0, 5, 4}, {0, 4, 5}, {0, 8, 6}};
    for (auto& s : slots) { all.list.push_back(A(NewUnit(s.cls, s.sub, 1, 1))); }
    U out[7]; PortHist(all.Addr(), 1, out);
    for (U i = 0; i < 7; ++i) Require(out[i] == 1, "one unit per output slot lands in its own counter");
    // Multiplicity: duplicates of one pointer and a long mixed list, with filter 0 and 1.
    Ctx dup; B* u = NewUnit(2, 8, 1, 1);
    for (U k = 0; k < 17; ++k) dup.list.push_back(A(u));
    ExpectLeaf(dup, 1, "multiplicity: 17 copies of one eligible unit"); ExpectLeaf(dup, 0, "multiplicity filter 0");
    PortHist(dup.Addr(), 1, out); Require(out[2] == 17, "multiplicity counts every entry");
    u[0xB44] = 0; ExpectLeaf(dup, 1, "multiplicity with B44 cleared"); PortHist(dup.Addr(), 1, out);
    Require(out[2] == 0, "filter 1 drops a unit with B44 == 0");
    ExpectLeaf(dup, 0, "filter 0 keeps it"); PortHist(dup.Addr(), 0, out); Require(out[2] == 17, "filter 0 ignores B41/B44");
    Ctx empty; ExpectLeaf(empty, 1, "empty list"); ExpectLeaf(empty, 0, "empty list, filter 0");
    PortHist(empty.Addr(), 1, out); for (U i = 0; i < 7; ++i) Require(out[i] == 0, "empty list zeroes every counter");
    U lcg = 0x12345678u;
    auto next = [&] { lcg = lcg * 0x343FDu + 0x269EC3u; return lcg >> 8; };
    std::vector<B*> pool;
    for (U i = 0; i < 64; ++i)
        pool.push_back(NewUnit(classes[next() % 7], subs[next() % 11], flags[next() % 5], flags[next() % 5]));
    for (U round = 0; round < 200; ++round) {
        Ctx c; const U n = next() % 300;
        for (U i = 0; i < n; ++i) c.list.push_back(A(pool[next() % pool.size()]));
        ExpectLeaf(c, 1, "random list filter 1"); ExpectLeaf(c, 0, "random list filter 0"); cases += 2;
    }
    std::printf("leaf 0x749D90: %lu fixture comparisons byte-equal\n", (unsigned long)cases);
}

// ---- batch ABI
static U retired[16], retiredCount;
static void Retire(uint32_t epoch) { if (retiredCount < 16) retired[retiredCount++] = epoch; }
static void Retire2(uint32_t) {}
static U Words(U i) { volatile U row[16]; ac::Snapshot(row); return row[i]; }

static void BatchCases() {
    ac::Reset(0, delta, 0);
    const AiCtrlBatch* b = ai_ctrl_batch_current();
    Require(b->epoch == 0 && !b->open && !b->P && !b->R, "reset batch is closed at epoch 0");
    ai_ctrl_batch_register_retire(&Retire); ai_ctrl_batch_register_retire(&Retire);   // deduplicated
    int p, n, c;
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    Require(b->epoch == 0 && retiredCount == 0 && Words(ac::WEndExit) == 0, "end of a closed batch is a no-op");
    ai_ctrl_batch_begin(&p, &n, &c);
    Require(b->open && b->epoch == 1 && b->P == &p && b->N == &n && b->C == &c && !b->R, "begin opens at an odd epoch");
    ai_ctrl_batch_set_region(&p); Require(b->R == &p, "region published by the geometry slice");
    ai_ctrl_batch_end(AI_CTRL_END_ASSIGN);
    Require(!b->open && b->epoch == 2 && retiredCount == 1 && retired[0] == 1, "end retires with the BEGIN epoch and bumps to even");
    ai_ctrl_batch_begin(&p, &n, &c);
    ai_ctrl_batch_begin(&n, &p, &c);   // a begin inside an open batch ends it first (refresh)
    Require(b->open && b->epoch == 5 && b->P == &n && retiredCount == 2 && retired[1] == 3 && Words(ac::WEndRefresh) == 1,
            "begin inside an open batch ends it with REFRESH");
    ai_ctrl_batch_end(AI_CTRL_END_CALLBACK); ai_ctrl_batch_begin(&p, &n, &c); ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    Require(Words(ac::WBatches) == 4 && Words(ac::WEndAssign) == 1 && Words(ac::WEndCallback) == 1 && Words(ac::WEndExit) == 1 &&
            b->epoch == 8 && retiredCount == 4, "batch and end-reason counters, one retire per end");
    ai_ctrl_batch_register_retire(&Retire2);
    ac::Reset(NTW2_AI_CTRL_HISTOGRAM, delta, 0);
    ai_ctrl_batch_begin(&p, &n, &c); ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    Require(retiredCount == 4 && b->epoch == 2 && ai_ctrl_batch_flags() == NTW2_AI_CTRL_HISTOGRAM, "Reset clears callbacks and epoch");
    std::printf("batch ABI: epoch, retire, reason counters ok\n");
}

// ---- gates
static U bindings[NTW2_BIND_COUNT];
static U Gate(U which) { return bindings[which]; }
static U Hist(Ctx& c, U filter, U out[7]) {
    reinterpret_cast<HistFn>(Gate(NTW2_BIND_AI_CTRL_HISTOGRAM))(out, 0x5555u, c.Addr(), filter); return 0;
}
static bool Same(const U* a, const U* b) { return !memcmp(a, b, 7 * sizeof(U)); }

static void HistogramGateCases() {
    ac::Reset(NTW2_AI_CTRL_HISTOGRAM, delta, 0); ac::Bind(bindings);
    Ctx c; B* u[4];
    u[0] = NewUnit(2, 4, 1, 1); u[1] = NewUnit(2, 8, 1, 1); u[2] = NewUnit(0, 4, 1, 1); u[3] = NewUnit(0, 9, 1, 1);
    for (B* x : u) c.list.push_back(A(x));
    Ctx other; other.list = c.list;
    int p = 0, n = 0;
    U out[7], native[7], first[7];
    Hist(c, 1, out); NativeHist(c.Addr(), 1, native);
    Require(Same(out, native) && Words(ac::WHistOutside) == 1 && Words(ac::WHistCalls) == 1, "outside a batch: native directly");
    ai_ctrl_batch_begin(&p, &n, reinterpret_cast<void*>(c.Addr()));
    Hist(c, 1, first); Require(Same(first, native) && Words(ac::WHistFirst) == 1 && Words(ac::WHistServed) == 0 && Words(ac::WEligible) == 4,
                               "first call of the batch computes exactly the native counters");
    u[2][0xB44] = 0;   // an eligibility change the batch does not see (callbacks would have ended it)
    Hist(c, 1, out); Require(Same(out, first) && Words(ac::WHistServed) == 1, "repeat served from the private copy");
    Hist(c, 0, out); NativeHist(c.Addr(), 0, native);
    Require(Same(out, native) && Words(ac::WHistOutside) == 2, "filter != 1 is native even in a batch");
    Hist(other, 1, out); NativeHist(other.Addr(), 1, native);
    Require(Same(out, native) && Words(ac::WHistOutside) == 3, "a context other than the batch's is native");
    ai_ctrl_batch_end(AI_CTRL_END_ASSIGN);
    Hist(c, 1, out); NativeHist(c.Addr(), 1, native);
    Require(Same(out, native) && !Same(out, first) && Words(ac::WHistOutside) == 4, "retired at the batch end");
    ai_ctrl_batch_begin(&p, &n, reinterpret_cast<void*>(c.Addr()));
    Hist(c, 1, out); Require(Same(out, native) && Words(ac::WHistFirst) == 2, "next batch recomputes the changed inputs");
    ai_ctrl_batch_end(AI_CTRL_END_REFRESH);

    // verify: a mutation inside the batch is caught, the NATIVE value is returned and the feature latches off
    ac::Reset(NTW2_AI_CTRL_HISTOGRAM | NTW2_AI_CTRL_VERIFY, delta, 0);
    u[2][0xB44] = 1;
    ai_ctrl_batch_begin(&p, &n, reinterpret_cast<void*>(c.Addr()));
    Hist(c, 1, first); NativeHist(c.Addr(), 1, native);
    Require(Same(first, native) && Words(ac::WHistMismatch) == 0, "verify: first computation equals native");
    Hist(c, 1, out); Require(Same(out, native) && Words(ac::WHistServed) == 1 && Words(ac::WHistMismatch) == 0, "verify: unchanged serve matches");
    u[0][0xB41] = 0;
    NativeHist(c.Addr(), 1, native);
    Hist(c, 1, out);
    Require(Same(out, native) && !Same(out, first) && Words(ac::WHistMismatch) == 1 && (Words(ac::WFlags) >> 8) == NTW2_AI_CTRL_HISTOGRAM &&
            ai_ctrl_batch_flags() == NTW2_AI_CTRL_VERIFY, "verify mismatch: native value returned, histogram latched off");
    u[0][0xB41] = 1; NativeHist(c.Addr(), 1, native);
    Hist(c, 1, out); Require(Same(out, native) && Words(ac::WHistServed) == 2, "latched: served counter stops, native answers");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);

    // census: native always executes; repeats and B41/B44 transitions are counted against the batch's first call
    ac::Reset(NTW2_AI_CTRL_CENSUS, delta, 0);
    ai_ctrl_batch_begin(&p, &n, reinterpret_cast<void*>(c.Addr()));
    Hist(c, 1, out); NativeHist(c.Addr(), 1, native);
    Require(Same(out, native) && Words(ac::WEligible) == 4 && Words(ac::WHistFirst) == 1 && Words(ac::WHistMismatch) == 0, "census: first call");
    Hist(c, 1, out); Require(Same(out, native) && Words(ac::WRepeatChanged) == 0 && Words(ac::WTransitions) == 0 && Words(ac::WHistServed) == 0,
                             "census: an unchanged repeat is native and counts nothing");
    u[1][0xB44] = 0; u[3][0xB41] = 0;
    Hist(c, 1, out); NativeHist(c.Addr(), 1, native);
    Require(Same(out, native) && Words(ac::WRepeatChanged) == 1 && Words(ac::WTransitions) == 2 && Words(ac::WHistServed) == 0,
            "census: native answers after a mutation; one changed repeat, two B44/B41 transitions");
    ai_ctrl_batch_end(AI_CTRL_END_EXIT);
    std::printf("histogram gate: native outside, once per batch, retire, verify latch, census ok\n");
}

// Fake node/scorer for the scorer and refresh gates. Both targets are __fastcall(N, edx, a, b) with RET 8 / N with plain RET.
static U scorerCloneCalls, scorerNativeCalls, refreshCalls, refreshSawOpen, lastScoreU, lastScoreC;
static U __fastcall FakeCloneScore(void*, U, U u, U c) { ++scorerCloneCalls; lastScoreU = u; lastScoreC = c; return 0xC10E; }
static U __fastcall FakeNativeScore(void*, U, U u, U c) { ++scorerNativeCalls; lastScoreU = u; lastScoreC = c; return 0x7A71; }
static void __fastcall FakeRefresh(void*, U) { ++refreshCalls; refreshSawOpen = ai_ctrl_batch_current()->open; }
typedef U (__fastcall *ScoreFn)(void* N, U edx, U u, U c);
// Drives the refresh gate with the native register contract: ECX = N, EBX = P.
#pragma warning(suppress : 4100) // the naked body reads its arguments from the stack
static __declspec(naked) void __stdcall CallRefresh(U gate, void* N, void* P) {
    __asm {
        push ebx
        mov ebx, [esp + 16]
        mov ecx, [esp + 12]
        call dword ptr [esp + 8]
        pop ebx
        ret 12
    }
}
static U savedEax, savedEcx, savedEdx, savedFlags;
static void CallPreserving(U gate) {
    __asm {
        push ebx
        mov eax, 0x11111111
        mov ecx, 0x22222222
        mov edx, 0x33333333
        xor ebx, ebx
        cmp ebx, 1         // sets CF=1 and SF; EFLAGS must survive the gate
        call dword ptr [gate]
        pushfd
        mov savedEax, eax
        mov savedEcx, ecx
        mov savedEdx, edx
        pop eax
        mov savedFlags, eax
        pop ebx
    }
}

static void GateCases() {
    ac::Reset(NTW2_AI_CTRL_HISTOGRAM, delta, A(reinterpret_cast<const void*>(&FakeCloneScore))); ac::Bind(bindings);
    U vtable[0x40]; memset(vtable, 0, sizeof(vtable));
    struct Node { U vt; } node = {A(vtable)};
    vtable[0x30 / 4] = A(reinterpret_cast<const void*>(&FakeRefresh));
    int p = 0, n = 0, c = 0;
    // scorer: exact slot -> the clone (no batch change); a foreign slot ends the open batch and runs the native target
    vtable[0x18 / 4] = A(At(0x7B1270));
    ai_ctrl_batch_begin(&p, &n, &c);
    const U r = reinterpret_cast<ScoreFn>(Gate(NTW2_BIND_AI_CTRL_SCORER))(&node, 0, 0x1234, 0x5678);
    Require(r == 0xC10E && scorerCloneCalls == 1 && lastScoreU == 0x1234 && lastScoreC == 0x5678 && Words(ac::WScorerCalls) == 1 &&
            ai_ctrl_batch_current()->open, "scorer gate: exact 0x7B1270 slot runs the clone with its stack arguments and keeps the batch");
    reinterpret_cast<ScoreFn>(Gate(NTW2_BIND_AI_CTRL_SCORER))(&node, 0, 1, 2);
    vtable[0x18 / 4] = A(reinterpret_cast<const void*>(&FakeNativeScore));
    const U r2 = reinterpret_cast<ScoreFn>(Gate(NTW2_BIND_AI_CTRL_SCORER))(&node, 0, 0x9, 0xA);
    Require(r2 == 0x7A71 && scorerNativeCalls == 1 && scorerCloneCalls == 2 && lastScoreU == 9 && lastScoreC == 0xA &&
            !ai_ctrl_batch_current()->open && Words(ac::WEndCallback) == 1 && Words(ac::WScorerCalls) == 2 && Words(ac::WMaxScorerBatch) == 2,
            "scorer gate: a foreign slot ends the batch (CALLBACK) and runs the native target");
    // refresh: ends an open batch before the native refresh, then begins with P = EBX and C = P + 0x68
    ai_ctrl_batch_begin(&p, &n, &c);
    B planner[0x100] = {};
    CallRefresh(Gate(NTW2_BIND_AI_CTRL_REFRESH), &node, planner);
    const AiCtrlBatch* b = ai_ctrl_batch_current();
    Require(refreshCalls == 1 && refreshSawOpen == 0 && b->open && b->P == planner && b->N == &node && b->C == planner + 0x68 &&
            Words(ac::WEndRefresh) == 1, "refresh gate: previous batch ended, native refresh ran outside any batch, next batch begun");
    // assign: EAX/ECX/EDX/EFLAGS preserved, batch ended with ASSIGN
    CallPreserving(Gate(NTW2_BIND_AI_CTRL_BATCH_ASSIGN));
    Require(savedEax == 0x11111111 && savedEcx == 0x22222222 && savedEdx == 0x33333333 && (savedFlags & 1) && (savedFlags & 0x80) &&
            !b->open && Words(ac::WEndAssign) == 1, "assign gate: registers and flags preserved, batch ended (ASSIGN)");
    ai_ctrl_batch_begin(&p, &n, &c);
    reinterpret_cast<void (*)()>(Gate(NTW2_BIND_AI_CTRL_BATCH_EXIT))();
    Require(!b->open && Words(ac::WEndExit) == 1, "exit gate ends the batch (EXIT)");
    std::printf("gates: scorer, refresh, assign, exit ok\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: native_ai_ctrl_oracle <Napoleon.exe>\n"); return 2; }
    Map(argv[1]);
    LeafCases();
    BatchCases();
    HistogramGateCases();
    GateCases();
    std::printf("native_ai_ctrl_oracle: %lu checks passed\n", (unsigned long)checks);
    return 0;
}
