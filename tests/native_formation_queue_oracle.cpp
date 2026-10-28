// Differential oracle for the 0x581E80 command-queue port (src/army/native_formation_queue.*).
// Executes the untouched pinned image's 0x581E80 (and its erase 0x56D990) against controlled queue fixtures, then replays the
// identical fixture through kntwr_formation_queue::Run with the probe off (null), with the probe on (no route), with the private route
// accepted / refused / absent from the table, and with a call-through erase.
// Commands, their [vtbl+4]/[vtbl+8] callbacks and their deleting destructors are controlled inputs that record receivers, EDX,
// the queue words at every call and mutate the queue (count shrink/grow, entry replacement, dirty/stop flags, own vtable,
// erase request byte, reentrant native erase, appended entries, exceptions); they are not an emulation of the walk under test.
// Every case compares exception outcome, the full event log and the entire fixture (queue, commands, vtables, guards) byte for
// byte; the probe runs additionally check one end per normally returned callback with the pre-callback class, that begin runs once
// per route-matching callback before its body with the same frame as its end, and that only accepted callbacks reach the private twin.
// No game process, installed-file writes, code detours, import calls or TLS setup are needed.
// Usage: native_formation_queue_oracle.exe <pinned Napoleon.exe>
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include "native_image_relocation.h"
#include "army/native_formation_queue.h"

static_assert(sizeof(void*) == 4, "native formation queue oracle requires x86");
namespace fq = kntwr_formation_queue;
namespace {
using U = uint32_t;
using B = uint8_t;
using Native = U (__fastcall*)(void*);
using EraseFn = fq::EraseFn;
using Probe = fq::Probe;

B* image;
U delta, checks, cases, handCases;
const char* current = "mapping";
const char* mode = "native";
U nativeQueue, nativeErase;
unsigned long long frequency;

U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template <class T> U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
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

// ---- Fixture -------------------------------------------------------------------------------------------------------------
constexpr U kQueueBytes = 0x460;
constexpr U kEntriesOff = 0x400, kCountOff = 0x440, kTotalOff = 0x444, kFreeOff = 0x448, kSpareOff = 0x44C,
            kIterOff = 0x450, kDirtyOff = 0x451, kIndexOff = 0x454;
constexpr U kMaxEntries = 8, kPool = 12, kClasses = 3, kMaxEvents = 512;
constexpr U kSlotLast = fq::kSlotLast, kSlotOther = fq::kSlotOther;

enum Action : U { ANone, ADirty, AStop, AStopOdd, ASetCount, AReplace, AEraseFlag, AMutate, AThrow, ANativeErase,
                  AAppend, ASpin, AStoreIndex, kActions };
struct Step { U action, a, b; };
struct Command {
    U vtable;          // +0x00  class identity
    U id;              // +0x04
    U spare;           // +0x08  1: the deleting destructor raises an exception
    B erase;           // +0x0C  erase request byte (== 1 requests the native erase after the last callback)
    B pad[3];
    U progress;        // +0x10  incremented by the walk after the last callback
    U deleted;         // +0x14  deleting-destructor calls
    U calls[2];        // +0x18  callbacks run per slot (4, 8)
    Step step[2][2];   // +0x20  per slot (4, 8) two scripted actions
};
static_assert(offsetof(Command, erase) == 0xC && offsetof(Command, progress) == 0x10, "command layout used by 0x581E80");

struct Fixture {
    U q[kQueueBytes / 4];
    U guard[4];                  // bytes directly behind the queue: a stray write there is a mismatch
    Command cmd[kPool];
    U vtable[kClasses][4];       // [0] deleting destructor, [1] +4 last callback, [2] +8 other callback, [3] poison
};
Fixture fx;
U& Dw(U off) { return fx.q[off / 4]; }
B& By(U off) { return reinterpret_cast<B*>(fx.q)[off]; }
U& EntryCmd(U i) { return fx.q[(kEntriesOff + 8 * i) / 4]; }
U& EntrySize(U i) { return fx.q[(kEntriesOff + 8 * i) / 4 + 1]; }

enum Kind : U { KCallback = 1, KDtor, KNativeErase, KThrow };
struct Event {
    U kind, slot, cls, id, edx, vtableAtEntry, count, index, iterating, dirty, progress, spin, threw, extra,
      endCount, endIterating, endDirty, endIndex, done;
};
struct Log { U count; Event e[kMaxEvents]; };
Log gLog;
U mutations, nativeErases, throws;

Command& Cmd(void* p) {
    const U address = A(p), first = A(&fx.cmd[0]);
    Require(address >= first && address - first < sizeof(fx.cmd) && (address - first) % sizeof(Command) == 0,
            "receiver is a fixture command");
    return *static_cast<Command*>(p);
}
Event& NewEvent(U kind, const Command& c) {
    Require(gLog.count < kMaxEvents, "bounded event log");
    Event& e = gLog.e[gLog.count++];
    std::memset(&e, 0, sizeof(e));
    e.kind = kind; e.id = c.id; e.vtableAtEntry = c.vtable; e.progress = c.progress;
    e.count = Dw(kCountOff); e.index = Dw(kIndexOff); e.iterating = By(kIterOff); e.dirty = By(kDirtyOff);
    return e;
}
void Spin(U ticks) {
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    do QueryPerformanceCounter(&b); while (static_cast<unsigned long long>(b.QuadPart - a.QuadPart) < ticks);
}

U Callback(void* self, void* edx, U slot, U cls) {
    Command& c = Cmd(self);
    const U s = slot == kSlotLast ? 0 : 1;
    Event& e = NewEvent(KCallback, c);
    e.slot = slot; e.cls = cls; e.edx = A(edx);
    ++c.calls[s];
    for (U k = 0; k < 2; ++k) {
        const Step st = c.step[s][k];
        switch (st.action) {
        case ANone: break;
        case ADirty: By(kDirtyOff) = 1; break;
        case AStop: By(kIterOff) = 0; break;
        case AStopOdd: By(kIterOff) = 2; break;
        case ASetCount: Dw(kCountOff) = st.a; break;
        case AReplace: EntryCmd(st.a) = A(&fx.cmd[st.b]); break;
        case AEraseFlag: c.erase = static_cast<B>(st.a); break;
        case AMutate: c.vtable = A(fx.vtable[st.a]); ++mutations; break;
        case AThrow: {
            e.threw = 1;
            NewEvent(KThrow, c).extra = 1;
            ++throws;
            RaiseException(0xE0000000u | c.id, 0, 0, nullptr);
            break;
        }
        case ANativeErase: {
            NewEvent(KNativeErase, c).extra = st.a;
            ++nativeErases;
            reinterpret_cast<EraseFn>(static_cast<uintptr_t>(nativeErase))(fx.q, nullptr, st.a);
            break;
        }
        case AAppend:
            if (Dw(kCountOff) < kMaxEntries) {
                EntryCmd(Dw(kCountOff)) = A(&fx.cmd[st.a]);
                EntrySize(Dw(kCountOff)) = 0x40 + st.a;
                ++Dw(kCountOff);
            }
            break;
        case ASpin: e.spin = st.a; Spin(st.a); break;
        case AStoreIndex: Dw(kIndexOff) = st.a; break;
        default: Require(false, "known scripted action");
        }
    }
    e.endCount = Dw(kCountOff); e.endIterating = By(kIterOff); e.endDirty = By(kDirtyOff); e.endIndex = Dw(kIndexOff);
    e.done = 1; // the callback returned normally (a throw from inside a nested destructor also leaves done == 0)
    return 0xC0DE0000u + c.id * 16 + slot; // EAX is intentionally ignored by 0x581E80
}
template <U C> U __fastcall LastCb(void* self, void* edx) { return Callback(self, edx, kSlotLast, C); }
template <U C> U __fastcall OtherCb(void* self, void* edx) { return Callback(self, edx, kSlotOther, C); }
// Deleting destructor [[cmd]+0]: push 1; call; callee pops the flag.
U __fastcall Dtor(void* self, void* /*edx*/, U flag) {
    Command& c = Cmd(self);
    Event& e = NewEvent(KDtor, c);
    e.extra = flag; // the destructor's own EDX is native leftover (callback/erase residue), not an input: deliberately not logged
    ++c.deleted;
    if (c.spare == 1) {
        NewEvent(KThrow, c).extra = 2;
        ++throws;
        RaiseException(0xE1000000u | c.id, 0, 0, nullptr);
    }
    return 0;
}

// ---- Probe and erase recorders (port modes) ---------------------------------------------------------------------------------
struct Obs { U vtable, slot; unsigned long long ticks; bool routed; U frame, count, iterating, dirty, index; };
Obs obs[kMaxEvents];
U obsCount;
void End(U vtable, U slot, unsigned long long ticks, bool routed, U frame) {
    Require(obsCount < kMaxEvents, "bounded observations");
    obs[obsCount++] = Obs{vtable, slot, ticks, routed, frame, Dw(kCountOff), By(kIterOff), By(kDirtyOff), Dw(kIndexOff)};
}
// Begin hook: runs before the callback (and before its first QPC read); records the log position so the oracle can prove it ran
// first, and the dispatching frame so end can be matched to it.
struct Beg { U vtable, slot, frame, logCount; };
Beg begins[kMaxEvents];
U beginCount;
bool beginAccept = true;
bool Begin(U vtable, U slot, U frame) {
    Require(beginCount < kMaxEvents, "bounded begins");
    begins[beginCount++] = Beg{vtable, slot, frame, gLog.count};
    return beginAccept;
}
U privateCalls;
// Private twins of the fixture callbacks: same ABI (ECX = command, EDX = vtable, plain ret) and identical scripted behaviour; only
// the call counter tells which copy ran.
template <U C> U __fastcall PrivateLastCb(void* self, void* edx) { ++privateCalls; return Callback(self, edx, kSlotLast, C); }
template <U C> U __fastcall PrivateOtherCb(void* self, void* edx) { ++privateCalls; return Callback(self, edx, kSlotOther, C); }
struct EraseCall { U queue, index; };
EraseCall eraseCalls[64];
U eraseCount;
U __fastcall RecordingErase(void* queue, void* edx, U index) {
    Require(eraseCount < 64, "bounded erase calls");
    eraseCalls[eraseCount++] = EraseCall{A(queue), index};
    return reinterpret_cast<EraseFn>(static_cast<uintptr_t>(nativeErase))(queue, edx, index); // exactly one native erase
}
unsigned long long wallTicks;

// Route configurations: which live table value selects the private copy (class/slot of the native callback and its twin).
struct RouteCfg { const char* name; U slot, cls; U native, privateTwin; };
const RouteCfg kRoute[] = {
    {"route class 1 slot 4", kSlotLast, 1, Fn(&LastCb<1>), Fn(&PrivateLastCb<1>)},
    {"route class 2 slot 8", kSlotOther, 2, Fn(&OtherCb<2>), Fn(&PrivateOtherCb<2>)},
    {"route target absent from the table", kSlotLast, 0, 0x00DEAD00u, Fn(&PrivateLastCb<0>)}, // never matches: begin must never run
};
const RouteCfg* routeCfg = &kRoute[0];
Probe probeOn() { return Probe{0, 0, &Begin, &End}; }
Probe probeRoute() { return Probe{routeCfg->native, routeCfg->privateTwin, &Begin, &End}; }

void RunNative() { reinterpret_cast<Native>(static_cast<uintptr_t>(nativeQueue))(fx.q); }
void RunPortOff() { fq::Run(fx.q, reinterpret_cast<EraseFn>(static_cast<uintptr_t>(nativeErase)), nullptr); }
void RunPortProbe(const Probe& p) {
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    fq::Run(fx.q, reinterpret_cast<EraseFn>(static_cast<uintptr_t>(nativeErase)), &p);
    QueryPerformanceCounter(&b);
    wallTicks = static_cast<unsigned long long>(b.QuadPart - a.QuadPart);
}
void RunPortOn() { const Probe p = probeOn(); RunPortProbe(p); }
void RunPortRoute() { const Probe p = probeRoute(); RunPortProbe(p); }
void RunPortRecording() { fq::Run(fx.q, &RecordingErase, nullptr); }
// SEH stays in this POD-only frame; the walk's own frames are discarded exactly as on a native exception.
DWORD Guarded(void (*run)()) {
    __try { run(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    return 0;
}

// ---- Fixture construction ---------------------------------------------------------------------------------------------------
const U kLast[kClasses] = {Fn(&LastCb<0>), Fn(&LastCb<1>), Fn(&LastCb<2>)};
const U kOther[kClasses] = {Fn(&OtherCb<0>), Fn(&OtherCb<1>), Fn(&OtherCb<2>)};
void Reset() {
    std::memset(&fx, 0, sizeof(fx));
    std::memset(fx.q, 0xA5, sizeof(fx.q));
    for (U& g : fx.guard) g = 0xFEEDFACEu;
    for (U c = 0; c < kClasses; ++c) {
        fx.vtable[c][0] = Fn(&Dtor); fx.vtable[c][1] = kLast[c]; fx.vtable[c][2] = kOther[c]; fx.vtable[c][3] = 0xDEAD0000u + c;
    }
    for (U i = 0; i < kPool; ++i) { fx.cmd[i].vtable = A(fx.vtable[i % kClasses]); fx.cmd[i].id = i; }
    for (U e = 0; e < kMaxEntries; ++e) { EntryCmd(e) = A(&fx.cmd[e]); EntrySize(e) = 0x10 + 4 * e; } // stale entries stay valid
    Dw(kCountOff) = 0; Dw(kTotalOff) = 0x1000; Dw(kFreeOff) = 0x200; Dw(kSpareOff) = 0x5A5A5A5Au;
    By(kIterOff) = 0x77; By(kDirtyOff) = 1; Dw(kIndexOff) = 0x1234;     // garbage the walk's entry word store must overwrite
    gLog.count = 0;
}
void Queue(std::initializer_list<U> poolIds) {
    U e = 0;
    for (U id : poolIds) { EntryCmd(e) = A(&fx.cmd[id]); EntrySize(e) = 0x10 + 4 * e; ++e; }
    Dw(kCountOff) = e;
}
void Script(U cmd, U slot, U k, U action, U a = 0, U b = 0) { fx.cmd[cmd].step[slot == kSlotLast ? 0 : 1][k] = Step{action, a, b}; }

// ---- Comparison -----------------------------------------------------------------------------------------------------------
struct Result { Fixture fx; Log log; DWORD code; };
Result nat, port;
U matrix[kClasses][2];
U totalCallbacks, totalObservations, totalErases, totalThrowCases, totalRouteBegins, totalRouteCalls;
constexpr U S(U id, U slot) { return id * 16 + slot; }

void Exec(Result& r, void (*run)()) {
    gLog.count = 0; obsCount = 0; eraseCount = 0; wallTicks = 0; beginCount = 0; privateCalls = 0;
    r.code = Guarded(run);
    r.fx = fx; r.log = gLog;
}
void Same(const Result& a, const Result& b) {
    Require(a.code == b.code, "same exception outcome as native");
    Require(a.log.count == b.log.count && std::memcmp(a.log.e, b.log.e, a.log.count * sizeof(Event)) == 0,
            "callbacks, destructors, receivers, EDX and the queue words at every call equal native");
    Require(std::memcmp(&a.fx, &b.fx, sizeof(Fixture)) == 0, "entire queue, commands, vtables and guards equal native");
}
U ClassOf(U vtable) {
    for (U c = 0; c < kClasses; ++c) if (vtable == A(fx.vtable[c])) return c;
    Require(false, "observed vtable is a fixture class");
    return 0;
}

void Compare(const char* name, const std::vector<U>* expectSeq = nullptr, const std::vector<U>* expectErase = nullptr) {
    current = name;
    static Fixture initial;
    initial = fx;
    mode = "native";
    Exec(nat, &RunNative);
    std::vector<U> seq;
    for (U i = 0; i < nat.log.count; ++i)
        if (nat.log.e[i].kind == KCallback) seq.push_back(S(nat.log.e[i].id, nat.log.e[i].slot));
    if (expectSeq) Require(seq == *expectSeq, "native reference callback order and slot selection");
    totalCallbacks += static_cast<U>(seq.size());
    if (nat.code) ++totalThrowCases;

    mode = "port observer off";
    fx = initial;
    Exec(port, &RunPortOff);
    Same(nat, port);

    mode = "port probe (no route)";
    fx = initial;
    Exec(port, &RunPortOn);
    Same(nat, port);
    Require(beginCount == 0 && privateCalls == 0, "no private route configured: begin never runs and no private copy is called");
    U k = 0;
    unsigned long long sum = 0;
    for (U i = 0; i < nat.log.count; ++i) {
        const Event& e = nat.log.e[i];
        if (e.kind != KCallback || !e.done) continue;
        Require(k < obsCount, "one observation per callback that returned");
        const Obs& o = obs[k++];
        Require(o.vtable == e.edx && o.vtable == e.vtableAtEntry && o.slot == e.slot,
                "observation carries the pre-callback class and the dispatched slot");
        Require(ClassOf(o.vtable) == e.cls, "the callback that ran belongs to the observed pre-callback class");
        Require(!o.routed && o.frame != 0, "unrouted observation, dispatching frame identity present");
        Require(o.count == e.endCount && o.iterating == e.endIterating && o.dirty == e.endDirty && o.index == e.endIndex,
                "observer runs right after the callback returned, before the walk touches the queue again");
        Require(o.ticks >= e.spin, "elapsed ticks cover the callback body");
        ++matrix[ClassOf(o.vtable)][o.slot == kSlotLast ? 0 : 1];
        sum += o.ticks;
    }
    Require(k == obsCount, "no observation for a callback that threw or did not run");
    if (!port.code) Require(sum <= wallTicks, "observed ticks lie inside the enclosing call");
    totalObservations += obsCount;

    // Private route: accepted (the twin runs in place of the raw table value), refused (native runs, begin still counted) and a
    // configuration whose native address never appears in the table (begin never runs).
    for (const RouteCfg& cfg : kRoute) {
        routeCfg = &cfg;
        for (U accept = 0; accept < 2; ++accept) {
            if (accept == 0 && &cfg != &kRoute[0]) continue; // refusal is checked once; acceptance for every configuration
            beginAccept = accept != 0;
            mode = accept ? "port route accepted" : "port route refused";
            fx = initial;
            Exec(port, &RunPortRoute);
            Same(nat, port);
            U expectBegins = 0, expectEnds = 0, b = 0;
            k = 0;
            for (U i = 0; i < nat.log.count; ++i) {
                const Event& e = nat.log.e[i];
                if (e.kind != KCallback) continue;
                const U table = e.slot == kSlotLast ? kLast[e.cls] : kOther[e.cls];
                const bool match = cfg.native == table;
                if (match) {
                    ++expectBegins;
                    Require(b < beginCount, "begin runs for every callback whose raw table value is the native route target");
                    const Beg& g = begins[b++];
                    Require(g.logCount == i, "begin ran before the callback body (no callback event yet) and after the previous work");
                    Require(g.vtable == e.vtableAtEntry && g.vtable == e.edx && g.slot == e.slot, "begin carries the pre-call class and slot");
                    Require(g.frame != 0, "begin frame identity present");
                }
                if (!e.done) continue;
                ++expectEnds;
                Require(k < obsCount, "one observation per returned callback");
                const Obs& o = obs[k++];
                Require(o.vtable == e.edx && o.slot == e.slot && ClassOf(o.vtable) == e.cls, "route observation carries the pre-call class and slot");
                Require(o.routed == (match && accept != 0), "routed flag is set exactly when begin accepted a matching callback");
                if (match) Require(o.frame == begins[b - 1].frame, "end repeats the begin frame of the same callback");
                Require(o.count == e.endCount && o.iterating == e.endIterating && o.dirty == e.endDirty && o.index == e.endIndex,
                        "route observer runs right after the callback returned");
            }
            Require(b == beginCount && beginCount == expectBegins, "no begin for a callback that does not match the route target");
            Require(k == obsCount && obsCount == expectEnds, "ends only for callbacks that returned");
            Require(privateCalls == (accept ? expectBegins : 0), "the private twin runs exactly for accepted matching callbacks");
            totalRouteBegins += beginCount; totalRouteCalls += privateCalls;
        }
    }
    beginAccept = true; routeCfg = &kRoute[0];

    mode = "port recording erase";
    fx = initial;
    Exec(port, &RunPortRecording);
    Same(nat, port);
    for (U i = 0; i < eraseCount; ++i) Require(eraseCalls[i].queue == A(fx.q), "erase receives the queue in ECX");
    if (expectErase) {
        Require(eraseCount == expectErase->size(), "erase call count");
        for (U i = 0; i < eraseCount; ++i) Require(eraseCalls[i].index == (*expectErase)[i], "erase index argument");
    }
    totalErases += eraseCount;
    fx = initial; // leave the fixture reusable by the caller
    ++cases;
}
void Case(const char* name, const std::vector<U>& seq, const std::vector<U>& erases = {}) {
    Compare(name, &seq, &erases);
    ++handCases;
}

void HandCases() {
    Reset(); Queue({});
    Case("empty queue, stale entries and garbage flags", {});
    Reset(); Queue({0});
    Case("single command is the last", {S(0, 4)});
    Reset(); Queue({1}); fx.cmd[1].erase = 1;
    Case("single command with erase request", {S(1, 4)}, {0});
    Reset(); Queue({0, 1, 2});
    Case("others then last, class 2 last", {S(0, 8), S(1, 8), S(2, 4)});
    Reset(); Queue({2, 1, 0});
    Case("class 0 last", {S(2, 8), S(1, 8), S(0, 4)});
    Reset(); Queue({0, 2, 1});
    Case("class 1 last", {S(0, 8), S(2, 8), S(1, 4)});
    Reset(); Queue({0, 1, 2, 3, 4, 5, 6, 7});
    Case("full inline array", {S(0, 8), S(1, 8), S(2, 8), S(3, 8), S(4, 8), S(5, 8), S(6, 8), S(7, 4)});
    Reset(); Queue({0, 1}); fx.cmd[0].erase = 1; fx.cmd[1].erase = 2;
    Case("erase byte only honored on the last callback and only when == 1", {S(0, 8), S(1, 4)});

    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, ADirty);
    Case("dirty on the first callback stops the loop", {S(0, 8)});
    Reset(); Queue({0, 1}); fx.cmd[1].erase = 1; Script(1, 4, 0, ADirty);
    Case("dirty on the last callback: erase requested but native skips it", {S(0, 8), S(1, 4)}, {1});
    Reset(); Queue({0, 1, 2, 3}); Script(1, 8, 0, AStop);
    Case("callback clears iterating", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1, 2, 3}); Script(1, 8, 0, AStopOdd);
    Case("iterating != 1 (value 2) stops", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1, 2}); Script(2, 4, 0, AStop); fx.cmd[2].erase = 1;
    Case("last callback clears iterating: erase request is a native no-op", {S(0, 8), S(1, 8), S(2, 4)}, {2});

    Reset(); Queue({0, 1, 2, 3, 4}); Script(1, 8, 0, ASetCount, 2);
    Case("shrink to the next index ends the loop", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1, 2, 3, 4}); Script(1, 8, 0, ASetCount, 3);
    Case("shrink makes the next entry the last (slot 4)", {S(0, 8), S(1, 8), S(2, 4)});
    Reset(); Queue({0, 1, 2, 3, 4}); Script(1, 8, 0, ASetCount, 0);
    Case("shrink to zero", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, ASetCount, 5);
    Case("grow in a non-last callback", {S(0, 8), S(1, 8), S(2, 8), S(3, 8), S(4, 4)});
    Reset(); Queue({0, 1}); Script(0, 8, 0, ASetCount, 8);
    Case("grow to full exposes stale entries", {S(0, 8), S(1, 8), S(2, 8), S(3, 8), S(4, 8), S(5, 8), S(6, 8), S(7, 4)});
    Reset(); Queue({0, 1}); Script(1, 4, 0, AAppend, 5);
    Case("last callback appends: appended entry becomes the last", {S(0, 8), S(1, 4), S(5, 4)});
    Reset(); Queue({0, 1, 2}); Script(2, 4, 0, ASetCount, 1); Script(2, 4, 1, AStoreIndex, 99);
    Case("last callback shrinks below the cursor and writes the index word", {S(0, 8), S(1, 8), S(2, 4)});
    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, AStoreIndex, 7);
    Case("callback index write is overwritten", {S(0, 8), S(1, 8), S(2, 4)});

    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, AReplace, 1, 9);
    Case("replace the next entry", {S(0, 8), S(9, 8), S(2, 4)});
    Reset(); Queue({0, 1}); fx.cmd[1].erase = 1; Script(1, 4, 0, AReplace, 1, 9);
    Case("last callback replaces its own entry: saved command keeps the increment and erase byte", {S(0, 8), S(1, 4)}, {1});
    Reset(); Queue({0, 1}); Script(1, 4, 0, AEraseFlag, 1);
    Case("last callback requests the erase on itself", {S(0, 8), S(1, 4)}, {1});
    Reset(); Queue({0, 1}); fx.cmd[1].erase = 1; Script(1, 4, 0, AEraseFlag, 0);
    Case("last callback withdraws the erase request", {S(0, 8), S(1, 4)});
    Reset(); Queue({0, 1, 2}); Script(2, 4, 0, AMutate, 0); Script(0, 8, 0, AMutate, 2);
    Case("callbacks retarget their own vtable: observer keeps the pre-callback class", {S(0, 8), S(1, 8), S(2, 4)});
    Reset(); Queue({0, 1, 2}); Script(1, 8, 0, AMutate, 1); Script(1, 8, 1, AMutate, 0);
    Case("two retargets in one callback", {S(0, 8), S(1, 8), S(2, 4)});
    Reset(); Queue({0, 1, 2}); Script(1, 8, 0, ANativeErase, 1);
    Case("native erase of the tail from a middle callback", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1, 2, 3}); Script(1, 8, 0, ANativeErase, 2);
    Case("native erase leaves the cursor behind the new count", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1}); Script(1, 4, 0, ANativeErase, 1);
    Case("last callback deletes itself (no erase request)", {S(0, 8), S(1, 4)});
    Reset(); Queue({0, 1}); fx.cmd[1].erase = 1; Script(1, 4, 0, ANativeErase, 1);
    Case("last callback deletes itself, then the erase request runs on an empty tail", {S(0, 8), S(1, 4)}, {1});
    Reset(); Queue({0, 1, 2}); fx.cmd[2].erase = 1; Script(2, 4, 0, ANativeErase, 0);
    Case("last callback erases everything", {S(0, 8), S(1, 8), S(2, 4)}, {2});
    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, ANativeErase, 1); Script(0, 8, 1, ADirty);
    Case("native erase then dirty in one callback", {S(0, 8)});

    Reset(); Queue({0, 1}); Script(0, 8, 0, AThrow);
    Case("exception in the first callback", {S(0, 8)});
    Reset(); Queue({0, 1}); Script(1, 4, 0, AThrow); fx.cmd[1].erase = 1;
    Case("exception in the last callback", {S(0, 8), S(1, 4)});
    Reset(); Queue({0, 1}); Script(0, 8, 0, ADirty); Script(0, 8, 1, AThrow);
    Case("exception after a dirty write", {S(0, 8)});
    Reset(); Queue({0, 1, 2}); Script(1, 8, 0, ASetCount, 2); Script(1, 8, 1, AThrow);
    Case("exception after a count change", {S(0, 8), S(1, 8)});
    Reset(); Queue({0, 1}); fx.cmd[1].erase = 1; fx.cmd[1].spare = 1;
    Case("exception from a deleting destructor inside the erase", {S(0, 8), S(1, 4)}, {1});
    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, ANativeErase, 2); fx.cmd[2].spare = 1;
    Case("exception from a destructor inside a reentrant erase", {S(0, 8)});

    const U spin = static_cast<U>(std::max<unsigned long long>(1, frequency / 20000)); // ~50 us
    Reset(); Queue({0, 1, 2}); Script(0, 8, 0, ASpin, spin); Script(2, 4, 0, ASpin, spin);
    Case("elapsed ticks cover a slot-8 and a slot-4 callback", {S(0, 8), S(1, 8), S(2, 4)});
}

void RandomCases(U count, U seed) {
    std::mt19937 rng(seed);
    const auto R = [&](U n) { return static_cast<U>(rng() % n); };
    static char name[48];
    for (U n = 0; n < count; ++n) {
        Reset();
        Dw(kCountOff) = R(kMaxEntries + 1);
        for (U e = 0; e < kMaxEntries; ++e) EntryCmd(e) = A(&fx.cmd[R(kPool)]);
        By(kIterOff) = static_cast<B>(R(256)); By(kDirtyOff) = static_cast<B>(R(2));
        for (U i = 0; i < kPool; ++i) {
            Command& c = fx.cmd[i];
            c.vtable = A(fx.vtable[R(kClasses)]);
            const U r = R(16);
            c.erase = static_cast<B>(r < 4 ? 1 : (r == 4 ? 2 : 0));
            c.spare = R(24) == 0;
            for (U s = 0; s < 2; ++s)
                for (U k = 0; k < 2; ++k) {
                    static const U weights[] = {ANone, ANone, ANone, ANone, ANone, ANone, ANone, ANone, ANone, ANone, ANone,
                                                ADirty, ADirty, AStop, AStopOdd, ASetCount, ASetCount, ASetCount, AReplace,
                                                AReplace, AReplace, AEraseFlag, AEraseFlag, AMutate, AMutate, AThrow,
                                                ANativeErase, ANativeErase, ANativeErase, AAppend, AAppend, AStoreIndex};
                    const U action = weights[R(sizeof(weights) / sizeof(weights[0]))];
                    U a = 0, b = 0;
                    switch (action) {
                    case ASetCount: a = R(kMaxEntries + 1); break;
                    case AReplace: a = R(kMaxEntries); b = R(kPool); break;
                    case AEraseFlag: a = R(3); break;
                    case AMutate: a = R(kClasses); break;
                    case ANativeErase: a = R(kMaxEntries + 1); break;
                    case AAppend: a = R(kPool); break;
                    case AStoreIndex: a = R(64); break;
                    default: break;
                    }
                    c.step[s][k] = Step{action, a, b};
                }
        }
        std::snprintf(name, sizeof(name), "random case %u (seed %u)", n, seed);
        Compare(name);
    }
}

void Coverage() {
    current = "coverage"; mode = "summary";
    for (U c = 0; c < kClasses; ++c)
        for (U s = 0; s < 2; ++s) Require(matrix[c][s] != 0, "every command class observed in both dispatch slots");
    Require(totalErases != 0 && totalThrowCases != 0, "erase calls and exception outcomes exercised");
    Require(mutations != 0, "scripted own-vtable mutation actions ran");
    Require(nativeErases != 0, "scripted reentrant native erase actions ran");
    Require(throws != 0, "scripted exception actions ran");
    Require(totalRouteBegins != 0 && totalRouteCalls != 0 && totalRouteCalls < totalRouteBegins, "route accepted (twin ran) and refused (native ran) callbacks both exercised");
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: native_formation_queue_oracle <pinned Napoleon.exe>\n");
        return 2;
    }
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    frequency = static_cast<unsigned long long>(f.QuadPart);
    Map(argv[1]);
    Require(fq::kNativeQueueVa == 0x581E80 && fq::kNativeEraseVa == 0x56D990 && fq::kSlotLast == 4 && fq::kSlotOther == 8,
            "header constants name the analyzed entries and vtable slots");
    nativeQueue = 0x581E80 + delta;
    nativeErase = 0x56D990 + delta;
    HandCases();
    RandomCases(4000, 20261024);
    Coverage();
    Require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release private image");
    std::printf("PASS formation queue native-equivalence cases=%u (hand %u) checks=%u callbacks=%u observations=%u erases=%u "
                "exception-cases=%u route-begins=%u route-twin-calls=%u (581E80 native vs port: observer off/on, private route "
                "accepted/refused/absent, call-through erase)\n",
                cases, handCases, checks, totalCallbacks, totalObservations, totalErases, totalThrowCases, totalRouteBegins, totalRouteCalls);
    return 0;
}
