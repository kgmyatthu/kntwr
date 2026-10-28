// Differential oracle for the 585D50 hand-port, not the 580A30 formation-update closure.
// Executes the untouched pinned image's two loops against controlled member objects, then
// replays the identical fixture through the product port (plain and real census Unit/Call).
// Vtable children record receivers/order and mutate observable state, counts, bases and
// upcoming members. They are controlled inputs, not an emulation of the loop under test.
// No game process, installed-file writes, code detours, import calls or TLS setup are needed.
// Usage: native_formation_residual_oracle.exe <pinned Napoleon.exe>
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include "native_image_relocation.h"
#include "army/native_formation_residual.h"
#include "army/native_army_storm.h"
#include "clones/kntwr_clones.h"

static_assert(sizeof(void*) == 4, "native formation oracle requires x86");
namespace {
using U = uint32_t;
using B = uint8_t;
using Native = U (__fastcall*)(void*);
B* image;
U delta, checks, cases;
const char* current = "mapping";
const char* mode = "native";
U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
void Require(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        std::fprintf(stderr, "FAIL [%s/%s] %s\n", current, mode, what);
        std::exit(1);
    }
}

void Map(const char* path) {
    FILE* f = std::fopen(path, "rb");
    Require(f != nullptr, "open image read-only");
    Require(std::fseek(f, 0, SEEK_END) == 0, "seek image");
    const long n = std::ftell(f);
    std::rewind(f);
    Require(n > 0 && n < 256 * 1024 * 1024, "image size");
    std::vector<B> bytes(static_cast<size_t>(n));
    Require(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read image");
    std::fclose(f);
    BCRYPT_ALG_HANDLE alg = nullptr;
    B digest[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA provider");
    Require(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest, 32) == 0, "hash image");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (U i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    Require(std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4") == 0,
            "supported image identity");
    // The exact digest authenticates the PE headers before they are interpreted.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    Require(nt->OptionalHeader.ImageBase == 0x400000, "preferred image base");
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image allocation");
    delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
                    std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
                               reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta),
            "loader relocations");
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD old;
        Require(VirtualProtect(image + sections[i].VirtualAddress, sections[i].Misc.VirtualSize,
                               PAGE_EXECUTE_READ, &old) != 0, "protect original code read-only");
    }
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0,
            "flush private image");
}

constexpr U kSlots = 16;
constexpr U kCount[2] = {0xAB0 / 4, 0xACC / 4};
constexpr U kBase[2] = {0xAB4 / 4, 0xAD0 / 4};
enum Action : U { None, Shrink, Grow, Forward, Backward, Empty, ReplaceNext, RetargetNext,
                  EnableSecond, DisableSecond };
struct Member { U vtable, id, calls, effect, action; };
struct Fixture {
    U unit[0xB00 / 4];
    U list[2][kSlots];
    Member member[2][kSlots];
    U vtable[2][4];
    U effect;
};
struct Event {
    U receiver, id, callee, effectBefore, counts[2], bases[2];
};
struct Trace { U count; Event events[64]; };
Fixture fixture;
Trace trace;

U __fastcall ChildA(void* receiver);
U __fastcall ChildB(void* receiver);
U Child(void* receiver, U callee) {
    // Bound a broken traversal rather than allowing an accidental cycle to hang CTest.
    Require(trace.count < 64, "bounded child trace");
    const U address = A(receiver), first = A(&fixture.member[0][0]);
    Require(address >= first && address - first < sizeof(fixture.member) &&
            (address - first) % sizeof(Member) == 0, "receiver is a fixture member");
    auto& m = *static_cast<Member*>(receiver);
    const U loop = m.id / kSlots;
    Require(loop < 2, "member identity");
    Event& e = trace.events[trace.count++];
    e.receiver = address; e.id = m.id; e.callee = callee; e.effectBefore = fixture.effect;
    for (U i = 0; i < 2; ++i) {
        e.counts[i] = fixture.unit[kCount[i]];
        e.bases[i] = fixture.unit[kBase[i]];
    }
    ++m.calls;
    fixture.effect = fixture.effect * 33u + m.id + callee * 101u;
    m.effect ^= fixture.effect;
    fixture.unit[0x100 / 4] += fixture.effect;
    // Every mutation leaves the native cursor a finite path through this same backing
    // array. Reallocation/free semantics of 580A30 are deliberately not claimed here.
    switch (m.action) {
    case None: break;
    case Shrink: fixture.unit[kCount[loop]] = 1; break;
    case Grow: fixture.unit[kCount[loop]] = 4; break;
    case Forward:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][6]);
        fixture.unit[kCount[loop]] = 1;
        break;
    case Backward:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][2]);
        fixture.unit[kCount[loop]] = 4;
        break;
    case Empty:
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][5]);
        fixture.unit[kCount[loop]] = 0;
        break;
    case ReplaceNext: fixture.list[loop][5] = A(&fixture.member[loop][10]); break;
    case RetargetNext: fixture.member[loop][5].vtable = A(fixture.vtable[0]); break;
    case EnableSecond:
        fixture.unit[kBase[1]] = A(&fixture.list[1][6]);
        fixture.unit[kCount[1]] = 2;
        break;
    case DisableSecond:
        fixture.unit[kBase[1]] = 0;
        fixture.unit[kCount[1]] = 0;
        break;
    default: Require(false, "known mutation");
    }
    m.action = None;
    return fixture.effect; // EAX is intentionally ignored: native caller 5820E3 reloads ECX.
}
U __fastcall ChildA(void* receiver) { return Child(receiver, 1); }
U __fastcall ChildB(void* receiver) { return Child(receiver, 2); }

void Setup(U count0, U count1) {
    std::memset(&fixture, 0, sizeof(fixture));
    fixture.effect = 0x12345678;
    fixture.vtable[0][3] = Fn(&ChildA);
    fixture.vtable[1][3] = Fn(&ChildB);
    for (U loop = 0; loop < 2; ++loop) {
        fixture.unit[kCount[loop]] = loop ? count1 : count0;
        fixture.unit[kBase[loop]] = A(&fixture.list[loop][4]);
        for (U i = 0; i < kSlots; ++i) {
            Member& m = fixture.member[loop][i];
            m.vtable = A(fixture.vtable[i & 1]);
            m.id = loop * kSlots + i;
            m.effect = 0xA5A50000u + m.id;
            fixture.list[loop][i] = A(&m);
        }
    }
}
U __fastcall CensusFormation(void* unit) {
    Require(kntwr_army_storm::InUnit(), "real census occurrence entered");
    return kntwr_army_storm::Call(kntwr_army_storm::BFormation, unit, &kntwr_form_residual::Formation);
}
void Execute(Native fn) {
    // Keep SEH in this POD-only frame; do not mask an oracle/native fault as a skipped case.
    __try { fn(fixture.unit); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "FAIL [%s/%s] exception=%08lX\n", current, mode, GetExceptionCode());
        std::exit(3);
    }
}
U __fastcall Census(void* unit) { return kntwr_army_storm::Unit(unit, 0, &CensusFormation); }
void Compare(const char* name, const std::vector<U>& expected) {
    current = name;
    const Fixture initial = fixture; // same addresses in both runs; copies are snapshots only
    std::memset(&trace, 0, sizeof(trace));
    mode = "native";
    Execute(reinterpret_cast<Native>(static_cast<uintptr_t>(0x585D50 + delta)));
    const Fixture nativeState = fixture;
    const Trace nativeTrace = trace;
    Require(trace.count == expected.size(), "native reference child count");
    for (U i = 0; i < trace.count; ++i) Require(trace.events[i].id == expected[i], "native reference order");
    for (U census = 0; census < 2; ++census) {
        mode = census ? "census port" : "plain port";
        fixture = initial;
        std::memset(&trace, 0, sizeof(trace));
        kntwr_army_storm::Reset();
        kntwr_form_residual::Reset();
        Require(!kntwr_army_storm::InUnit(), "outside occurrence before entry");
        Execute(census ? &Census : &kntwr_form_residual::Formation);
        Require(!kntwr_army_storm::InUnit(), "occurrence exited");
        Require(std::memcmp(&nativeTrace, &trace, sizeof(trace)) == 0,
                "child order, receivers, dispatch and intermediate observations equal native");
        Require(std::memcmp(&nativeState, &fixture, sizeof(fixture)) == 0,
                "all unit, list, member, vtable and observable effects equal native");
        ++cases;
    }
}

void Cases() {
    Setup(0, 0); Compare("both empty with allocated bases", {});
    Setup(0, 0); fixture.unit[kBase[0]] = fixture.unit[kBase[1]] = 0;
    Compare("both empty with null bases", {});
    Setup(1, 0); Compare("first loop only", {4});
    Setup(0, 1); Compare("second loop only", {20});
    Setup(3, 2); Compare("both loops ordered", {4, 5, 6, 20, 21});
    Setup(16, 16);
    fixture.unit[kBase[0]] = A(fixture.list[0]);
    fixture.unit[kBase[1]] = A(fixture.list[1]);
    std::vector<U> all;
    for (U i = 0; i < 32; ++i) all.push_back(i);
    Compare("full backing arrays", all);
    const char* names[] = {"", "shrink count", "grow count", "forward base and count", "backward base and count",
                           "zero count at advanced cursor", "replace next receiver", "replace next vtable"};
    for (U loop = 0; loop < 2; ++loop) {
        for (U action = Shrink; action <= RetargetNext; ++action) {
            const U count = action == Grow ? 1 : (action == Forward ? 4 : 3);
            Setup(loop ? 0 : count, loop ? count : 0);
            fixture.member[loop][4].action = action;
            std::vector<U> ids;
            switch (action) {
            case Shrink: case Empty: ids = {4}; break;
            case Grow: ids = {4, 5, 6, 7}; break;
            case Backward: ids = {4, 5}; break;
            case ReplaceNext: ids = {4, 10, 6}; break;
            default: ids = {4, 5, 6}; break;
            }
            for (U& id : ids) id += loop * kSlots;
            char name[96];
            std::snprintf(name, sizeof(name), "loop %u %s", loop + 1, names[action]);
            Compare(name, ids);
        }
    }
    Setup(3, 0); fixture.member[0][4].action = EnableSecond;
    Compare("first child enables and rebases second loop", {4, 5, 6, 22, 23});
    Setup(3, 3); fixture.member[0][4].action = DisableSecond;
    Compare("first child disables second loop", {4, 5, 6});
}

// ---- Limited-solve census (kntwr_form_residual::NoteLimitedSolve / TickEnd): deterministic synthetic ticks and injected QPC tick
// counts through the public module interface. Only counts, ordering and ledger arithmetic are asserted, never elapsed time.
namespace fr = kntwr_form_residual;
LONGLONG frequency;
U UsOf(unsigned long long q) { return static_cast<U>(q * 1000000ull / static_cast<unsigned long long>(frequency)); }
unsigned long long Q(U ms) { return static_cast<unsigned long long>(frequency) * ms / 1000ull; }
std::vector<U> Snap() { std::vector<U> w(fr::kWords); fr::Snapshot(w.data()); return w; }
const U* Row(const std::vector<U>& w, U tick, U qpcLo) {
    for (U i = 0; i < fr::kTop; ++i) {
        const U* e = w.data() + fr::TopTable + i * fr::kEntryWords;
        if (e[fr::ETick] == tick && e[fr::EQpcStartLo] == qpcLo) return e;
    }
    return nullptr;
}
U RowsWithLimited(const std::vector<U>& w) {
    U n = 0;
    for (U i = 0; i < fr::kTop; ++i) if (w[fr::TopTable + i * fr::kEntryWords + fr::ELimCalls]) ++n;
    return n;
}
// Calls of the currently open invocation: sink_calls - folded - aborted - outside (0 whenever no scope is open).
U Pending(const std::vector<U>& w) {
    const U* l = w.data() + fr::LedgerTable;
    return l[fr::LSinkCalls] - l[fr::LSinkFolded] - l[fr::LSinkAborted] - l[fr::LSinkOutside];
}
void LedgerArithmetic(const std::vector<U>& w) {
    const U* l = w.data() + fr::LedgerTable;
    Require(l[fr::LTopCapacity] == fr::kTop && l[fr::LEntryWords] == fr::kEntryWords, "ledger geometry");
    Require(l[fr::LTopOffered] == l[fr::LTopRetained] + l[fr::LTopRejected] + l[fr::LTopEvicted], "offered = retained + rejected + evicted");
    Require(l[fr::LLimTicksRetained] == RowsWithLimited(w), "limited retained equals limited rows present");
    Require(l[fr::LLimTicksOmitted] == l[fr::LLimTicks] - l[fr::LLimTicksRetained], "omitted = limited ticks - retained");
}

void LimitedCases() {
    current = "limited-solve census"; mode = "synthetic";
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); frequency = f.QuadPart;
    const U agg = fr::StormAggregate, calm = fr::CalmAggregate;
    fr::Reset();
    std::vector<U> w = Snap();
    Require(w[fr::Version] == 4 && w[fr::Enabled] == 1, "version 4 row, census enabled after Reset");
    Require(RowsWithLimited(w) == 0 && w[U(fr::LedgerTable) + fr::LSinkCalls] == 0, "no rows or sink calls before any tick");

    // 1. Limited-only storm tick: no member/loop calls, two limited calls.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(2)); fr::NoteLimitedSolve(Q(3));
    const unsigned long long qpcA = 0x100000002ull, qpcB = 0x100000009ull;
    fr::TickEnd(100, 5000, true, qpcA, 7000);
    w = Snap();
    Require(w[fr::Ticks] == 1 && w[fr::StormTicks] == 1, "limited-only tick is a closed storm tick");
    Require(w[agg + fr::AForms] == 0 && w[agg + fr::ALoopCalls] == 0 && w[fr::MemberCalls] == 0, "no formation work in a limited-only tick");
    Require(w[agg + fr::ALimTicks] == 1 && w[agg + fr::ALimCalls] == 2 && w[agg + fr::ALimUs] == UsOf(Q(2) + Q(3)), "storm limited aggregate");
    Require(w[agg + fr::ALimMaxCallUs] == UsOf(Q(3)) && w[agg + fr::ALimMaxTickUs] == UsOf(Q(2) + Q(3)), "storm limited maxima");
    Require(w[agg + fr::ALimOnlyTicks] == 1 && w[agg + fr::ALimOnlyCalls] == 2 && w[agg + fr::ALimOnlyUs] == UsOf(Q(2) + Q(3)), "limited-only counters");
    Require(w[calm + fr::ALimTicks] == 0 && w[calm + fr::ALimCalls] == 0, "calm class untouched by a storm tick");
    const U* a = Row(w, 100, static_cast<U>(qpcA));
    Require(a != nullptr, "limited-only storm tick retained as a row");
    Require(a[fr::EQpcStartHi] == 1 && a[fr::EQpcStartLo] == 2 && a[fr::ETickUs] == 7000 && a[fr::ESite18Us] == 5000, "row carries QPC identity, tick and site-18 us");
    Require(a[fr::ELimCalls] == 2 && a[fr::ELimUs] == UsOf(Q(2) + Q(3)) && a[fr::ELimMaxUs] == UsOf(Q(3)), "row limited count/us/max");
    Require(a[fr::EFlags] == (fr::EFlagLimited | fr::EFlagLimitedOnly) && a[fr::EForms] == 0 && a[fr::EMemberCalls] == 0, "row flagged limited-only");
    Require(w[U(fr::LedgerTable) + fr::LSinkCalls] == 2 && w[U(fr::LedgerTable) + fr::LSinkFolded] == 2, "both sink calls folded exactly once");
    LedgerArithmetic(w);

    // 2. Same tick id again with a distinct QPC start: two distinct rows, not merged.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(1));
    fr::TickEnd(100, 6000, true, qpcB, 7100);
    w = Snap();
    const U* b = Row(w, 100, static_cast<U>(qpcB));
    a = Row(w, 100, static_cast<U>(qpcA));
    Require(a && b && a != b, "repeated tick id keeps both invocations");
    Require(a[fr::ELimCalls] == 2 && b[fr::ELimCalls] == 1 && b[fr::ETickUs] == 7100, "per-invocation limited counts are not merged");
    Require(w[agg + fr::ALimTicks] == 2 && w[agg + fr::ALimCalls] == 3, "aggregate sums both invocations");
    LedgerArithmetic(w);

    // 3. Calm tick with a limited call: aggregate only, no row. Calm tick without any: nothing but the tick count.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(4));
    fr::TickEnd(101, 100, false, 0x200000001ull, 120);
    w = Snap();
    Require(w[calm + fr::ALimTicks] == 1 && w[calm + fr::ALimCalls] == 1 && w[calm + fr::ALimOnlyTicks] == 1, "calm limited-only tick aggregated");
    Require(w[calm + fr::ALimUs] == UsOf(Q(4)) && w[agg + fr::ALimTicks] == 2, "classes stay separate");
    Require(Row(w, 101, 1) == nullptr && w[fr::StormTicks] == 2, "calm ticks never become rows");
    Require(w[U(fr::LedgerTable) + fr::LLimTicks] == 3 && w[U(fr::LedgerTable) + fr::LLimTicksOmitted] == 1, "calm limited tick reported as omitted from the table");
    fr::TickBegin();
    fr::TickEnd(102, 100, false, 0x200000002ull, 120);
    w = Snap();
    Require(w[fr::Ticks] == 4 && w[calm + fr::ALimTicks] == 1 && w[U(fr::LedgerTable) + fr::LLimTicks] == 3, "tick without limited calls adds no limited tick");
    Require(w[U(fr::LedgerTable) + fr::LSinkCalls] == w[U(fr::LedgerTable) + fr::LSinkFolded], "nothing pending");
    LedgerArithmetic(w);

    // 4. Overflow: fill the eight rows, evict with larger site-18 ticks, reject a smaller one; the rejected limited tick is reported.
    for (U i = 0; i < 10; ++i) {
        fr::TickBegin(); fr::NoteLimitedSolve(Q(1));
        fr::TickEnd(200 + i, 10000 + i, true, 0x300000000ull + i, 11000);
    }
    fr::TickBegin(); fr::NoteLimitedSolve(Q(1));
    fr::TickEnd(300, 1, true, 0x400000000ull, 50);
    w = Snap();
    const U* l = w.data() + fr::LedgerTable;
    Require(l[fr::LTopOffered] == 13 && l[fr::LTopRetained] == fr::kTop, "thirteen storm ticks offered, table full");
    Require(l[fr::LTopRejected] >= 1 && Row(w, 300, 0) == nullptr, "smaller tick rejected, never a row");
    Require(l[fr::LTopEvicted] >= 1, "larger ticks evicted older rows");
    Require(l[fr::LLimTicksOmitted] >= 1 && l[fr::LLimTicks] == 3 + 11, "omitted limited ticks reported, none silently lost");
    Require(w[agg + fr::ALimTicks] == 2 + 11, "aggregate still counts omitted storm ticks");
    LedgerArithmetic(w);
    for (U i = 1; i < fr::kTop; ++i)
        Require(w[fr::TopTable + (i - 1) * fr::kEntryWords + fr::ESite18Us] >= w[fr::TopTable + i * fr::kEntryWords + fr::ESite18Us], "rows ordered by site-18 us");

    // 4b. Aborted invocation: its limited calls are discarded and accounted, never a row or aggregate, never merged into the next
    // invocation that gets a (distinct) QPC identity.
    const std::vector<U> pre = Snap();
    const U* pl = pre.data() + fr::LedgerTable;
    fr::TickBegin(); fr::NoteLimitedSolve(Q(7)); fr::NoteLimitedSolve(Q(1));
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(Pending(w) == 2 && l[fr::LSinkCalls] == pl[fr::LSinkCalls] + 2, "open invocation shows its calls as pending, live");
    fr::TickAbort();
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(Pending(w) == 0 && l[fr::LSinkAborted] == 2 && l[fr::LAbortedTicks] == 1, "abort accounts the discarded calls and the aborted invocation");
    Require(l[fr::LAbortedLimUs] == UsOf(Q(7) + Q(1)), "aborted limited time reported separately");
    Require(w[fr::Ticks] == pre[fr::Ticks] && l[fr::LLimTicks] == pl[fr::LLimTicks] && w[agg + fr::ALimCalls] == pre[agg + fr::ALimCalls] &&
            l[fr::LTopOffered] == pl[fr::LTopOffered] && l[fr::LSinkFolded] == pl[fr::LSinkFolded], "abort adds no tick, row offer, aggregate or folded call");
    fr::TickAbort(); // no open scope: ignored, not a second abort
    Require(Snap()[U(fr::LedgerTable) + fr::LAbortedTicks] == 1, "abort without an open scope is a no-op");
    const unsigned long long qpcC = 0x800000003ull;
    fr::TickBegin(); fr::NoteLimitedSolve(Q(2));
    fr::TickEnd(500, 20000, true, qpcC, 21000);
    w = Snap(); l = w.data() + fr::LedgerTable;
    const U* c = Row(w, 500, static_cast<U>(qpcC));
    Require(c != nullptr && c[fr::ELimCalls] == 1 && c[fr::ELimUs] == UsOf(Q(2)), "next invocation's row holds only its own limited call");
    Require(w[agg + fr::ALimCalls] == pre[agg + fr::ALimCalls] + 1 && Pending(w) == 0, "aggregate absorbed one call, none of the aborted ones");
    // A scope that is never closed is aborted (and accounted) by the next TickBegin.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(1));
    fr::TickBegin();
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(l[fr::LAbortedTicks] == 2 && l[fr::LSinkAborted] == 3, "an unclosed scope is aborted by the next TickBegin");
    fr::TickEnd(501, 20001, true, 0x800000004ull, 21000);
    w = Snap();
    const U* r501 = Row(w, 501, 4);
    Require(r501 != nullptr && r501[fr::ELimCalls] == 0 && Pending(w) == 0, "row after the replaced scope carries no inherited calls");

    // 4c. Calls outside an open owner scope (no TickBegin, or a foreign thread) are counted as outside and never folded; a foreign
    // thread cannot abort or close the owner's scope.
    fr::NoteLimitedSolve(Q(1));
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(l[fr::LSinkOutside] == 1 && Pending(w) == 0, "limited call with no open scope is counted as outside");
    fr::TickBegin(); fr::NoteLimitedSolve(Q(3));
    std::thread foreign([] { fr::NoteLimitedSolve(Q(9)); fr::TickAbort(); });
    foreign.join();
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(l[fr::LSinkOutside] == 2 && l[fr::LAbortedTicks] == 2 && Pending(w) == 1, "foreign thread: its call is outside, the owner's scope survives");
    fr::TickEnd(502, 20002, true, 0x800000005ull, 21000);
    w = Snap();
    Require(Row(w, 502, 5) != nullptr && Row(w, 502, 5)[fr::ELimCalls] == 1 && Pending(w) == 0, "owner row holds only the owner's call");
    LedgerArithmetic(w);

    // 4d. Adversarial foreign Begin + End (+ Abort): while the owner's scope is open a foreign thread can neither take it over,
    // fold it into a QPC-identified row of its own, nor abort it.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(3)); fr::NoteQueueCommand(0x1000, 4, Q(1));
    const std::vector<U> preForeign = Snap();
    std::thread foreignScope([] {
        fr::TickBegin();
        fr::NoteLimitedSolve(Q(9));
        fr::NoteQueueCommand(0x1000, 8, Q(9));
        fr::TickEnd(900, 99999, true, 0x900000009ull, 1);
        fr::TickAbort();
    });
    foreignScope.join();
    w = Snap(); l = w.data() + fr::LedgerTable;
    const U* pf = preForeign.data() + fr::LedgerTable;
    Require(w[fr::Ticks] == preForeign[fr::Ticks] && w[fr::StormTicks] == preForeign[fr::StormTicks] && Row(w, 900, 9) == nullptr,
            "foreign TickEnd folds nothing and creates no row");
    Require(l[fr::LAbortedTicks] == pf[fr::LAbortedTicks] && l[fr::LTopOffered] == pf[fr::LTopOffered], "foreign Begin/Abort do not abort or offer anything");
    Require(l[fr::LSinkOutside] == pf[fr::LSinkOutside] + 1 && l[fr::LQueueOutside] == pf[fr::LQueueOutside] + 1, "foreign observations are outside");
    Require(Pending(w) == 1 && l[fr::LQueueCalls] - l[fr::LQueueFolded] - l[fr::LQueueAborted] - l[fr::LQueueOutside] == 1, "owner scope survives with its own pending calls");
    fr::TickEnd(503, 20003, true, 0x800000006ull, 21000);
    w = Snap();
    const U* r503 = Row(w, 503, 6);
    Require(r503 != nullptr && r503[fr::ELimCalls] == 1 && r503[fr::ELimUs] == UsOf(Q(3)) && r503[fr::EQueueCmdCalls] == 1 &&
            r503[fr::EQueueCmdUs] == UsOf(Q(1)), "owner row holds only the owner's calls");
    LedgerArithmetic(w);

    // 4e. Formation queue commands (NoteQueueCommand): per-invocation row fields, cumulative class table, ledger.
    fr::Reset();
    const U vA = 0x00A10000, vB = 0x00B20000, vC = 0x00C30000;
    fr::TickBegin();
    fr::NoteQueueCommand(vA, 4, Q(2)); fr::NoteQueueCommand(vA, 4, Q(5)); fr::NoteQueueCommand(vA, 8, Q(1)); fr::NoteQueueCommand(vB, 8, Q(3));
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(l[fr::LQueueCalls] == 4 && l[fr::LQueueFolded] == 0 && l[fr::LQueueOutside] == 0, "open invocation: four queue calls pending, live");
    fr::TickEnd(600, 500, true, 0x900000001ull, 800);
    w = Snap(); l = w.data() + fr::LedgerTable;
    const U* q600 = Row(w, 600, 1);
    Require(q600 != nullptr && q600[fr::EQueueCmdCalls] == 4 && q600[fr::EQueueCmdUs] == UsOf(Q(2) + Q(5) + Q(1) + Q(3)), "row holds the invocation's queue command count and time");
    Require(q600[fr::ESlowVtable] == vA && q600[fr::ESlowSlot] == 4 && q600[fr::ESlowUs] == UsOf(Q(5)), "row names the slowest callback class, slot and time");
    Require(l[fr::LQueueCalls] == 4 && l[fr::LQueueFolded] == 4 && l[fr::LQueueAborted] == 0 && l[fr::LQueueOutside] == 0, "queue calls folded exactly once");
    const U* qt = w.data() + fr::QueueTable;
    Require(qt[fr::QOverflowCalls] == 0 && qt[fr::QOverflowUs] == 0, "no overflow");
    const U* k0 = qt + fr::QClassBase;
    Require(k0[fr::QVtable] == vA && k0[fr::QSlot] == 4 && k0[fr::QCalls] == 2 && k0[fr::QUs] == UsOf(Q(2) + Q(5)) && k0[fr::QMaxUs] == UsOf(Q(5)), "class 0 aggregates both calls of (vA,4)");
    const U* k1 = k0 + fr::QClassWords; const U* k2 = k1 + fr::QClassWords; const U* k3 = k2 + fr::QClassWords;
    Require(k1[fr::QVtable] == vA && k1[fr::QSlot] == 8 && k1[fr::QCalls] == 1 && k2[fr::QVtable] == vB && k2[fr::QSlot] == 8 && k2[fr::QCalls] == 1 &&
            k3[fr::QCalls] == 0, "classes are (vtable, slot) pairs in first-seen order");
    // A zero-time callback still names its class as the slowest one; a calm tick keeps the queue calls only in ledger/class table.
    fr::TickBegin(); fr::NoteQueueCommand(vC, 4, 0);
    fr::TickEnd(601, 600, true, 0x900000002ull, 800);
    w = Snap();
    const U* q601 = Row(w, 601, 2);
    Require(q601 != nullptr && q601[fr::EQueueCmdCalls] == 1 && q601[fr::ESlowVtable] == vC && q601[fr::ESlowSlot] == 4 && q601[fr::ESlowUs] == 0, "zero-time callback is still named");
    fr::TickBegin(); fr::NoteQueueCommand(vB, 8, Q(1));
    fr::TickEnd(602, 1, false, 0x900000003ull, 800);
    w = Snap(); l = w.data() + fr::LedgerTable;
    Require(Row(w, 602, 3) == nullptr && l[fr::LQueueFolded] == 6 && l[fr::LQueueCalls] == 6, "calm tick: counted and folded, never a row");
    // Aborted invocation: accounted in the ledger, kept in the cumulative class table (observed callbacks), absent from rows.
    fr::TickBegin(); fr::NoteQueueCommand(vA, 4, Q(9)); fr::TickAbort();
    w = Snap(); l = w.data() + fr::LedgerTable; qt = w.data() + fr::QueueTable;
    Require(l[fr::LQueueAborted] == 1 && l[fr::LAbortedQueueUs] == UsOf(Q(9)) && l[fr::LQueueCalls] == 7 && l[fr::LQueueFolded] == 6, "aborted queue call accounted");
    Require(qt[U(fr::QClassBase) + fr::QCalls] == 3, "class table includes the aborted invocation's observed callback");
    fr::TickBegin();
    fr::TickEnd(603, 700, true, 0x900000004ull, 800);
    w = Snap();
    const U* q603 = Row(w, 603, 4);
    Require(q603 != nullptr && q603[fr::EQueueCmdCalls] == 0 && q603[fr::EQueueCmdUs] == 0 && q603[fr::ESlowVtable] == 0 && q603[fr::ESlowUs] == 0,
            "aborted queue calls never leak into the next invocation's row");
    // Outside any open scope (and from a foreign thread while the owner's scope is open): counted as outside, class table updated.
    fr::NoteQueueCommand(vB, 8, Q(1));
    fr::TickBegin(); fr::NoteQueueCommand(vB, 8, Q(2));
    std::thread foreignQueue([] { fr::NoteQueueCommand(vB, 8, Q(4)); });
    foreignQueue.join();
    fr::TickEnd(604, 800, true, 0x900000005ull, 800);
    w = Snap(); l = w.data() + fr::LedgerTable;
    const U* q604 = Row(w, 604, 5);
    Require(q604 != nullptr && q604[fr::EQueueCmdCalls] == 1 && q604[fr::EQueueCmdUs] == UsOf(Q(2)), "only the owner's callback is in the row");
    Require(l[fr::LQueueOutside] == 2 && l[fr::LQueueCalls] == l[fr::LQueueFolded] + l[fr::LQueueAborted] + l[fr::LQueueOutside], "outside observations counted; queue ledger identity holds");
    // Class overflow: only kQueueClasses distinct (vtable, slot) pairs are tracked; the rest is explicit overflow.
    fr::Reset();
    fr::TickBegin();
    for (U i = 0; i < fr::kQueueClasses; ++i) fr::NoteQueueCommand(0x7000 + i * 0x10, 8, Q(1));
    fr::NoteQueueCommand(0x7000, 4, Q(2));        // same vtable, other slot: a new pair, no room
    fr::NoteQueueCommand(0x9000, 8, Q(3));        // new vtable, no room
    fr::NoteQueueCommand(0x7000, 8, Q(1));        // known pair still aggregates
    fr::TickEnd(700, 10, true, 0xA00000001ull, 20);
    w = Snap(); l = w.data() + fr::LedgerTable; qt = w.data() + fr::QueueTable;
    Require(qt[fr::QOverflowCalls] == 2 && qt[fr::QOverflowUs] == UsOf(Q(2) + Q(3)), "calls beyond the class capacity are counted as overflow");
    Require(qt[U(fr::QClassBase) + fr::QCalls] == 2, "a tracked class keeps aggregating after the table is full");
    Require(l[fr::LQueueCalls] == fr::kQueueClasses + 3 && l[fr::LQueueFolded] == fr::kQueueClasses + 3, "overflow calls are still ledger calls");
    fr::Reset();
    w = Snap();
    Require(w[U(fr::QueueTable) + fr::QOverflowCalls] == 0 && w[U(fr::QueueTable) + U(fr::QClassBase) + fr::QCalls] == 0, "reset clears the class table");

    // 5. Reset: a pending (unfolded) call, rows, aggregates and ledger are all gone; version/enabled words stay for the running census.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(5)); fr::NoteQueueCommand(0x3000, 4, Q(5)); // an open scope with pending calls
    fr::Reset();
    fr::TickEnd(399, 10, false, 0x4ffffffffull, 20); // Reset closed the scope: a TickEnd without an open scope is ignored
    Require(Snap()[fr::Ticks] == 0, "TickEnd after Reset without a new TickBegin is ignored");
    fr::TickBegin();
    fr::TickEnd(400, 10, false, 0x500000000ull, 20);
    w = Snap();
    Require(w[fr::Version] == 4 && w[fr::Enabled] == 1 && w[fr::Ticks] == 1, "reset restarts the census row");
    Require(w[calm + fr::ALimTicks] == 0 && w[agg + fr::ALimTicks] == 0 && RowsWithLimited(w) == 0, "no stale limited counts after reset");
    Require(w[U(fr::LedgerTable) + fr::LSinkCalls] == 0 && w[U(fr::LedgerTable) + fr::LSinkFolded] == 0 && w[U(fr::LedgerTable) + fr::LTopOffered] == 0 &&
            w[U(fr::LedgerTable) + fr::LSinkAborted] == 0 && w[U(fr::LedgerTable) + fr::LSinkOutside] == 0 && w[U(fr::LedgerTable) + fr::LAbortedTicks] == 0 &&
            w[U(fr::LedgerTable) + fr::LAbortedLimUs] == 0 && w[U(fr::LedgerTable) + fr::LAbortedFormCalls] == 0, "ledger cleared by reset");
    for (U i = fr::LQueueCalls; i <= fr::LAbortedRouteUs; ++i) Require(w[fr::LedgerTable + i] == 0, "queue and route ledger words cleared by reset");
    for (U i = 0; i < fr::kQueueWords + fr::kRouteWords; ++i) Require(w[fr::QueueTable + i] == 0, "queue class table and route table cleared by reset (no route armed)");
    for (U i = 0; i < fr::kTop; ++i) Require(w[fr::TopTable + i * fr::kEntryWords + fr::ETick] == 0, "top rows cleared by reset");

    // 6. Disabled: after Stop the sink and TickEnd are no-ops; Reset on a stopped census zeroes the whole row.
    fr::TickBegin(); fr::NoteLimitedSolve(Q(1));
    fr::TickEnd(401, 10, true, 0x600000000ull, 20);
    const std::vector<U> before = Snap();
    fr::Stop();
    fr::NoteLimitedSolve(Q(9));
    fr::NoteQueueCommand(0x1000, 4, Q(9));
    fr::TickBegin(); fr::TickAbort();
    fr::TickEnd(402, 99999, true, 0x700000000ull, 99);
    Require(Snap() == before, "stopped census ignores sink calls and ticks");
    fr::Reset();
    w = Snap();
    bool zero = true;
    for (U v : w) zero = zero && v == 0;
    Require(zero, "reset of a stopped census leaves an all-zero row");
    ++cases;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: native_formation_residual_oracle <pinned Napoleon.exe>\n");
        return 2;
    }
    Map(argv[1]);
    U bindings[KNTWR_BIND_COUNT] = {};
    kntwr_form_residual::Bind(delta, bindings);
    Require(kntwr_form_residual::Start(0, 0, 0), "start residual with original child dispatch and no private command-split route");
    Require(kntwr_army_storm::Start({A(image), 0}), "start real storm census");
    Cases();
    LimitedCases();
    kntwr_form_residual::Stop();
    kntwr_army_storm::Stop();
    Require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release private image");
    std::printf("PASS formation residual native-equivalence cases=%u checks=%u (585D50 plain+census)\n", cases, checks);
    return 0;
}
