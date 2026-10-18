// Private-image differential oracle: the untouched 0x57DC30/0x81A790 and
// 0x7EFA80 insertion bodies versus the linked production Phase-B solver.
// Only private allocator boundaries are supplied; no game file is modified.
// Recording virtuals stand in for fixture-owned entities, not collision code.
//
// Intentional Phase-B divergences from the original image (everything else is
// still compared against it):
//  * Packets are selected once from stage-entry state and computed in parallel;
//    callback mutations of geometry/flags/radius/height cannot add or remove
//    pairs in the tick that made them. Immutable-input fixtures therefore keep
//    the original accepted pair set. Mutation fixtures use a native run with the
//    mutation disabled as the frozen reference, and a live native run only to
//    document and pin the old live divergence.
//  * Per-record numeric sums (+70..+7C) are privately accumulated and reduced
//    deterministically before any callback, so they are compared with a forward
//    error bound scaled by absolute totals and by incident pair count, not bits.
//    Callbacks observe those FINAL sums, not the original's intermediate sums.
//  * Final velocities (+80/+84), labels (+88), +40 processed bytes and callback
//    receiver/argument order still match the native image exactly. Fully supported
//    stages finish ordered redistribution/label stores before any callback, so
//    callbacks observe FINAL processed bytes, velocities and labels too.
//  * Mixed native-local stages retain original per-record processed-byte timing
//    and interleaved redistribution/callbacks. Native-local queries execute at
//    their original position and retain original intermediate numeric sums.
//  * Whole-stage fallbacks to the original (grid/capacity/chunk-fault/sticky) are
//    compared bit-for-bit including callback observations.
//  * Every unordered logical pair must be applied and called back at most once
//    in both engines; the solver's Contacts/Callbacks counters must equal the
//    number of non-native-local unordered pairs, so duplicate processing fails.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>
#include <functional>
#include <memory>
#include <utility>
#include "loco/native_owned_grid.h"
#include "native_image_relocation.h"
#include "native_collision_solver.h"
#include "native_contact.h"
#include "native_worker_dispatch.h"
#pragma fenv_access(on)
using U = uint32_t;
using B = unsigned char;
using Pair = std::array<U, 2>; // unordered record pair {min, max}
static_assert(sizeof(void*) == 4, "owned x86 oracle");
static_assert(ntw2_collide::WordCount == 61, "oracle samples the full 61-word diagnostic block");
static_assert(ntw2_collide::UnsupportedCells == 43 && ntw2_collide::ShapedPairs == 44 &&
    ntw2_collide::AuditThreadUs == 60, "performance diagnostics append after the existing 44 words");
extern "C" {
U __stdcall ntw_pool_init(ntw_pool*, const ntw_pool_config*);
U __stdcall ntw_pool_shutdown(ntw_pool*);
U __stdcall ntw_pool_worker_start(void*);
void __stdcall ntw_pool_dispatch(U, U, U, void*);
}
static B* image;
static U delta, checks, cases;
static const char* currentCase = "mapping";
static U ownerThread;
[[noreturn]] static void Fail(const char* fmt, ...) {
    std::fprintf(stderr, "FAIL [%s]: ", currentCase);
    va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap);
    std::fputc('\n', stderr); std::exit(1);
}
static void Require(bool ok, const char* what) { ++checks; if (!ok) Fail("%s", what); }
template<class T> static T Get(const void* p, size_t off) {
    T v; std::memcpy(&v, static_cast<const B*>(p) + off, sizeof(v)); return v;
}
template<class T> static void Put(void* p, size_t off, T v) {
    std::memcpy(static_cast<B*>(p) + off, &v, sizeof(v));
}
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static U Fn(T p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static void ResetFp() {
    unsigned short cw = 0x27f;
    __asm { fninit }
    __asm { fldcw cw }
    _mm_setcsr(0x1f80);
}
static void* __cdecl Allocate(size_t n, void*) {
    void* p = std::malloc(n ? n : 1); Require(p != nullptr, "private native heap allocation"); return p;
}
static void __cdecl Release(void* p) { std::free(p); }
static void Jump(U va, U target) {
    B* p = At(va); p[0] = 0xb8; Put(p, 1, target); p[5] = 0xff; p[6] = 0xe0;
}
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
    image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Require(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
    std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
            std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
    Require(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
        reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "image relocation");
    Jump(0xff7f20, Fn(&Allocate)); Jump(0xff7ef0, Fn(&Release));
    Require(FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage) != 0, "flush private loader seams");
}
struct Record { B bytes[0x680]; }; // through the LAND fields Predict reads (+0x5B8, +0x67C)
struct Node { U type, serial, payload, owner, previous, next, head; };
static_assert(sizeof(Node) == 0x1c, "native node stride");
struct Event {
    U receiver, argument;
    std::array<U, 7> receiverState, argumentState; // +70..+88 at callback position
    B receiverDone, argumentDone;
};
static std::vector<Event>* events;
static B* mutationTarget;
static U mutationMode;
static bool raiseAfterContact;
static B* poisonShape;
static void __stdcall PoisonGatherDispatch(U user, U body, U chunks, void* context) {
    B* target = poisonShape;
    if (!target) { ntw_pool_dispatch(user, body, chunks, context); return; }
    poisonShape = nullptr;
    const U originalShape = Get<U>(target, 0x60);
    // Gather copies but never dereferences this pointer. Restore live memory
    // after the genuine dispatch barrier; a later numeric chunk faults on its
    // snapshot while native pre-write fallback sees the restored valid input.
    Put(target, 0x60, U(1));
    ntw_pool_dispatch(user, body, chunks, context);
    Put(target, 0x60, originalShape);
}
static void __fastcall Contact(void* receiver, void*, void* argument) {
    Require(GetCurrentThreadId() == ownerThread, "callbacks execute on owner");
    Event e{}; e.receiver = Get<U>(receiver, 0x2c); e.argument = Get<U>(argument, 0x2c);
    std::memcpy(e.receiverState.data(), static_cast<B*>(receiver) + 0x70, 28);
    std::memcpy(e.argumentState.data(), static_cast<B*>(argument) + 0x70, 28);
    e.receiverDone = Get<B>(receiver, 0x40); e.argumentDone = Get<B>(argument, 0x40);
    events->push_back(e);
    Put(receiver, 0x13c, Get<U>(receiver, 0x13c) + 1);
    Put(argument, 0x13c, Get<U>(argument, 0x13c) + 1);
    if (mutationTarget && e.receiver == 1 && e.argument == 0) {
        if (mutationMode == 1 || mutationMode == 4)
            Put(mutationTarget, 0x54, mutationMode == 1 ? 0.0f : 3.0f);
        if (mutationMode == 2 || mutationMode == 5)
            Put(mutationTarget, 0x38, mutationMode == 2 ? U(0) : U(1));
        if (mutationMode == 3 || mutationMode == 6)
            Put(mutationTarget, 0x58, mutationMode == 3 ? 0.0f : 0.5f);
    }
    if (raiseAfterContact && e.receiver == 1 && e.argument == 0) {
        // Effects have completed: fault-free native is a valid output oracle.
        // Raise only once, only inside production solver callback consumption.
        raiseAfterContact = false;
        RaiseException(0xe0422001u, 0, 0, nullptr);
    }
}
static U vtable[18];
struct Input {
    float x = 0, y = 0, z = 0, height = 3, radius = 1;
    float mass = 1, inverse = 1, vx = 0, vz = 0;
    U flags = 1, team = 1, exclusion = 0x10000, label = 0;
    B active = 1, processed = 0, bump = 0, weight = 0;
    uint16_t heading = 0;
    U shape = 0;
    bool inserted = true;
    U nodeType = 8;
};
struct Spec {
    std::vector<Input> input;
    std::vector<U> order;
    U tick = 1;
    B rebuild = 0;
    bool reverseInsertion = false;
    bool controlled = true;
    bool breadthFirst = false;
    bool invalidGrid = false;
    bool foreignNodes = false;
    U primaryCount = 0xffffffffu; // trailing records may be foreign grid producers
    U expectedNativeQueries = 0;
    U expectedSolverContacts = 0xffffffffu;
    U mutation = 0;
    bool callbackFault = false;
    bool workerFault = false;
    // Trailing inserted records (index >= primaryCount) are registered in the manager's secondary
    // registry (count +278, pointer +27C; destination-only for the solver) instead of left unregistered.
    bool secondaryRegistry = false;
    U expectedContacts = 0xffffffffu;
    // Mutation fixtures only: pair count of the frozen (mutation-disabled) reference.
    // expectedContacts then pins the old LIVE native count for the same fixture.
    U frozenContacts = 0xffffffffu;
    // Require native intermediate callback sums to differ from final solver sums.
    bool expectFinalObservation = false;
    U expectedShapedPairs = 0xffffffffu;
    bool checkCellHistogram = false;
    bool expectFinalOwnerObservation = false;
};
struct Fixture {
    std::array<B, 0x280> manager{};
    std::array<B, 0x10> root{};
    std::array<B, 0x100> model{};
    // Avoidance manager (model+0xCC) with the pinned image vtable: admits contact-response stages.
    std::array<B, 0x100> avoid{};
    std::vector<B> avoidBits = std::vector<B>(0x2000);
    std::array<B, 0x28> grid{};
    std::array<U, 1024> cells{};
    std::vector<Record> records;
    std::vector<std::vector<Node>> nodes;
    std::vector<U> registry, worklist, secondary;
    std::vector<Event> calls;
    U mutation;
    bool callbackFault;
    bool workerFault;
    explicit Fixture(const Spec& spec) : records(spec.input.size()), nodes(spec.input.size()),
        registry(spec.primaryCount == 0xffffffffu ? spec.input.size() : spec.primaryCount),
        worklist(registry.size()), mutation(spec.mutation),
        callbackFault(spec.callbackFault), workerFault(spec.workerFault) {
        Put(root.data(), 8, A(model.data())); Put(model.data(), 0x58, spec.tick);
        Put(model.data(), 0xcc, A(avoid.data())); Put(avoid.data(), 0, A(At(0x1334234)));
        Put(avoid.data(), 0x90, A(avoidBits.data()));
        Put(model.data(), 0xa4, A(grid.data())); Put(grid.data(), 0, A(cells.data()));
        // Actual insertion: both axes use +10; +14 is an UNSIGNED clamp max.
        // The original body performs FADD -0.5, not the design's historical -1.
        Put(grid.data(), 8, U(5)); Put(grid.data(), 0x10, U(16));
        Put(grid.data(), 0x14, U(31)); Put(grid.data(), 0x24, 0.25f);
        Put(manager.data(), 0, A(root.data())); Put(manager.data(), 0x24c, U(registry.size()));
        Put(manager.data(), 0x250, A(registry.data())); Put(manager.data(), 0x260, U(worklist.size()));
        Put(manager.data(), 0x264, A(worklist.data())); Put(manager.data(), 0x268, spec.rebuild);
        for (U i = 0; i < records.size(); ++i) {
            B* r = records[i].bytes; const Input& s = spec.input[i];
            if (i < registry.size()) registry[i] = A(r);
            Put(r, 0, A(vtable)); Put(r, 0x28, A(root.data())); Put(r, 0x2c, i);
            Put(r, 0x30, s.active); Put(r, 0x38, s.flags); Put(r, 0x3c, s.exclusion);
            Put(r, 0x40, s.processed); Put(r, 0x44, s.team); Put(r, 0x48, s.x);
            Put(r, 0x4c, s.y); Put(r, 0x50, s.z); Put(r, 0x54, s.height); Put(r, 0x58, s.radius);
            Put(r, 0x5c, s.bump); Put(r, 0x60, s.shape); Put(r, 0x64, s.heading); Put(r, 0x66, s.weight);
            Put(r, 0x68, s.mass); Put(r, 0x6c, s.inverse); Put(r, 0x80, s.vx); Put(r, 0x84, s.vz);
            Put(r, 0x88, s.label);
            // Nonzero incoming accumulators catch accidental replacement/clearing.
            Put(r, 0x70, 0.125f); Put(r, 0x74, -0.25f); Put(r, 0x78, 0.375f); Put(r, 0x7c, 0.5f);
            if (s.inserted) {
                nodes[i].resize(cells.size()); // enough even for fully clamped coverage
                for (Node& node : nodes[i]) node = {spec.foreignNodes ? 16u : s.nodeType, i, A(r + 0x30), A(r), 0, 0, 0};
                Put(r, 0xa8, A(nodes[i].data())); Put(r, 0xb0, U(nodes[i].size()));
            }
        }
        using Insert = void(__fastcall*)(void*);
        auto insert = reinterpret_cast<Insert>(At(0x7efa80));
        ResetFp();
        for (U j = 0; j < records.size(); ++j) {
            const U i = spec.reverseInsertion ? U(records.size()) - j - 1 : j;
            if (spec.input[i].inserted) {
                insert(records[i].bytes);
                Require(Get<U>(records[i].bytes, 0xac) <= nodes[i].size(), "real insertion fits node capacity");
            }
        }
        for (U i = 0; i < worklist.size(); ++i) worklist[i] = registry[spec.order.empty() ? i : spec.order[i]];
        if (spec.secondaryRegistry) {
            for (U i = U(registry.size()); i < records.size(); ++i) secondary.push_back(A(records[i].bytes));
            Put(manager.data(), 0x278, U(secondary.size())); Put(manager.data(), 0x27c, A(secondary.data()));
        }
        // Deliberately unsupported solver geometry, after genuine insertion.
        // Original queries use node head slots, so this is safe for native fallback.
        if (spec.invalidGrid) Put(grid.data(), 8, U(32));
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::vector<U> Order() const {
        std::vector<U> result;
        for (U r : worklist) result.push_back(Get<U>(reinterpret_cast<void*>(r), 0x2c));
        return result;
    }
    bool ShareCell(U a, U b) const {
        const U na = Get<U>(records[a].bytes, 0xac), nb = Get<U>(records[b].bytes, 0xac);
        for (U i = 0; i < na; ++i) for (U j = 0; j < nb; ++j)
            if (nodes[a][i].head == nodes[b][j].head) return true;
        return false;
    }
};
static std::vector<Pair> PairSet(const std::vector<Event>& calls, const char* who) {
    std::vector<Pair> result;
    for (const Event& e : calls) {
        if (e.receiver == e.argument) Fail("%s called record %u back with itself", who, e.receiver);
        result.push_back({std::min(e.receiver, e.argument), std::max(e.receiver, e.argument)});
    }
    std::sort(result.begin(), result.end());
    const auto duplicate = std::adjacent_find(result.begin(), result.end());
    if (duplicate != result.end())
        Fail("%s processed unordered pair {%u,%u} more than once (%zu callbacks)", who, (*duplicate)[0], (*duplicate)[1], calls.size());
    ++checks;
    return result;
}
// Records whose chains meet an unsupported node execute the original query at
// their native position; pairs touching them keep original (intermediate) timing.
static std::vector<bool> NativeLocal(const Fixture& f, const Spec& spec) {
    std::vector<bool> local(f.records.size(), false);
    if (!spec.expectedNativeQueries) return local;
    for (U i = 0; i < f.registry.size(); ++i) for (U j = 0; j < f.records.size(); ++j) {
        const bool unsupported = spec.foreignNodes || spec.input[j].nodeType != 8 || j >= f.registry.size();
        if (unsupported && f.ShareCell(i, j)) local[i] = true;
    }
    for (U j = U(f.registry.size()); j < f.records.size(); ++j) local[j] = true;
    return local;
}
static void CheckBfs(const Fixture& f) {
    // Build only the visibility graph from game-inserted node head slots, not a
    // second collision implementation. Rebuild enqueues rejected candidates too.
    const U n = U(f.records.size()); std::vector<U> component(n, n), depth(n), queue;
    for (U seed = 0; seed < n; ++seed) if (component[seed] == n) {
        queue.clear(); queue.push_back(seed); component[seed] = seed;
        for (size_t q = 0; q < queue.size(); ++q) for (U j = 0; j < n; ++j)
            if (component[j] == n && f.ShareCell(queue[q], j)) {
                component[j] = seed; depth[j] = depth[queue[q]] + 1; queue.push_back(j);
            }
    }
    auto order = f.Order(); U lastComponent = 0, lastDepth = 0;
    for (U i = 0; i < n; ++i) {
        U c = component[order[i]], d = depth[order[i]];
        if (i && c == lastComponent) Require(d >= lastDepth, "BFS nondecreasing levels within visibility component");
        else {
            Require(!i || c > lastComponent, "components follow ascending unseen registry seeds");
            Require(d == 0 && order[i] == c, "component starts at its seed");
        }
        lastComponent = c; lastDepth = d;
    }
}
static void Compare(const Fixture& expected, const Fixture& actual, const Spec& spec, bool original) {
    const auto pairs = PairSet(expected.calls, "native reference");
    Require(PairSet(actual.calls, "production solver") == pairs, "accepted unordered pair set");
    Require(expected.calls.size() == pairs.size() && actual.calls.size() == pairs.size(),
        "exactly one callback per unordered logical pair");
    if (spec.expectedContacts != 0xffffffffu) Require(pairs.size() == spec.expectedContacts, "fixture exercises intended contact count");
    const std::vector<bool> local = NativeLocal(actual, spec);
    const bool finalOwnerState = !original && spec.expectedNativeQueries == 0;
    if (spec.controlled) {
        for (size_t i = 0; i < expected.calls.size(); ++i) {
            const Event& a = expected.calls[i]; const Event& b = actual.calls[i];
            Require(a.receiver == b.receiver && a.argument == b.argument, "controlled callback receiver/argument sequence");
            if (!finalOwnerState)
                Require(a.receiverDone == b.receiverDone && a.argumentDone == b.argumentDone,
                    "fallback and mixed-stage callbacks observe original processed-byte timing");
            if (original || local[b.receiver] || local[b.argument])
                Require(a.receiverState == b.receiverState && a.argumentState == b.argumentState,
                    "original-position callbacks observe native numeric, velocity and label stores");
            else if (!finalOwnerState) {
                // Mixed stages retain interleaved live +80/+84/+88 stores.
                for (U w = 4; w < 7; ++w)
                    Require(a.receiverState[w] == b.receiverState[w] && a.argumentState[w] == b.argumentState[w],
                        "callbacks observe live velocity and label stores in record/pair order");
            }
        }
    }
    if (!original) {
        // Contract: after parallel numerics and the deterministic reduction, every solver
        // callback sees each record's FINAL +70..+7C sums, bit-for-bit what the stage leaves.
        for (const Event& e : actual.calls) {
            if (local[e.receiver] || local[e.argument]) continue;
            for (U w = 0; w < 4; ++w) {
                Require(e.receiverState[w] == Get<U>(actual.records[e.receiver].bytes, 0x70 + 4 * w) &&
                    e.argumentState[w] == Get<U>(actual.records[e.argument].bytes, 0x70 + 4 * w),
                    "solver callbacks observe final numeric sums");
            }
            if (finalOwnerState) {
                for (U w = 4; w < 7; ++w)
                    Require(e.receiverState[w] == Get<U>(actual.records[e.receiver].bytes, 0x70 + 4 * w) &&
                        e.argumentState[w] == Get<U>(actual.records[e.argument].bytes, 0x70 + 4 * w),
                        "fully supported callbacks observe final velocity and label stores");
                Require(e.receiverDone == Get<B>(actual.records[e.receiver].bytes, 0x40) &&
                    e.argumentDone == Get<B>(actual.records[e.argument].bytes, 0x40),
                    "fully supported callbacks observe final processed bytes");
            }
        }
        if (spec.expectFinalObservation) {
            bool differs = false;
            for (const Event& e : expected.calls) for (U w = 0; w < 4; ++w) {
                differs |= std::abs(Get<float>(&e.receiverState[w], 0) - Get<float>(actual.records[e.receiver].bytes, 0x70 + 4 * w)) > 1e-4f;
                differs |= std::abs(Get<float>(&e.argumentState[w], 0) - Get<float>(actual.records[e.argument].bytes, 0x70 + 4 * w)) > 1e-4f;
            }
            Require(differs, "fixture distinguishes final solver observation from original intermediate observation");
        }
        if (spec.expectFinalOwnerObservation) {
            Require(finalOwnerState, "owner-state observation fixture uses the fully supported path");
            bool velocityDiffers = false, labelDiffers = false, processedDiffers = false;
            for (const Event& e : expected.calls) {
                for (U w = 4; w < 6; ++w) {
                    velocityDiffers |= e.receiverState[w] != Get<U>(actual.records[e.receiver].bytes, 0x70 + 4 * w);
                    velocityDiffers |= e.argumentState[w] != Get<U>(actual.records[e.argument].bytes, 0x70 + 4 * w);
                }
                labelDiffers |= e.receiverState[6] != Get<U>(actual.records[e.receiver].bytes, 0x88);
                labelDiffers |= e.argumentState[6] != Get<U>(actual.records[e.argument].bytes, 0x88);
                processedDiffers |= e.receiverDone != Get<B>(actual.records[e.receiver].bytes, 0x40);
                processedDiffers |= e.argumentDone != Get<B>(actual.records[e.argument].bytes, 0x40);
            }
            Require(velocityDiffers, "fixture distinguishes final velocities from native callback-time velocities");
            Require(labelDiffers, "fixture distinguishes final labels from native callback-time labels");
            Require(processedDiffers, "fixture distinguishes final processed bytes from native callback-time bytes");
        }
    }
    std::vector<U> incident(expected.records.size());
    for (const Event& e : expected.calls) { ++incident[e.receiver]; ++incident[e.argument]; }
    const U maxIncident = incident.empty() ? 0 : *std::max_element(incident.begin(), incident.end());
    for (U i = 0; i < expected.records.size(); ++i) {
        const B* a = expected.records[i].bytes; const B* b = actual.records[i].bytes;
        for (U off = 0x70; off <= 0x7c; off += 4) {
            const float x = Get<float>(a, off), y = Get<float>(b, off);
            if (original) Require(Get<U>(a, off) == Get<U>(b, off), "original fallback correction bits");
            else {
                // Phase B reduces each record's private contributions in a deterministic order
                // different from the original's interleaved subtract/add. For k incident binary32
                // contributions both orders are within ~k*epsilon of the absolute total; bound the
                // difference by 8*(k+2)*epsilon*max(1, absolute totals). Absolute totals avoid a
                // useless relative tolerance near cancellation. Fixtures have finite inputs.
                double scale = 1.0;
                for (U absOff : {0x78u, 0x7cu}) {
                    scale = std::max(scale, std::max(std::abs(double(Get<float>(a, absOff))), std::abs(double(Get<float>(b, absOff)))));
                }
                const double tolerance = 8.0 * std::numeric_limits<float>::epsilon() * (maxIncident + 2) * scale;
                ++checks;
                if (!std::isfinite(x) || !std::isfinite(y) || std::abs(double(x) - y) > tolerance)
                    Fail("record %u +%02X sums native=%.9g solver=%.9g tolerance=%.9g", i, off, x, y, tolerance);
            }
        }
        Require(Get<U>(a, 0x80) == Get<U>(b, 0x80) && Get<U>(a, 0x84) == Get<U>(b, 0x84), "velocity transition bits");
        // Compare to instructions, not the historical spec's mistaken MIN claim.
        Require(Get<U>(a, 0x88) == Get<U>(b, 0x88), "native unsigned label propagation");
        Require(Get<B>(a, 0x40) == Get<B>(b, 0x40), "processed byte including early exits");
        Require(Get<U>(a, 0x13c) == Get<U>(b, 0x13c), "recording callback witness writes");
        Require(Get<U>(a, 0xac) == Get<U>(b, 0xac), "node counts unchanged");
    }
    Require(Get<U>(expected.manager.data(), 0x260) == Get<U>(actual.manager.data(), 0x260), "worklist count unchanged");
    Require(Get<B>(expected.manager.data(), 0x268) == Get<B>(actual.manager.data(), 0x268), "rebuild flag exact");
    auto a = expected.Order(), b = actual.Order();
    const bool rebuild = spec.rebuild == 1 || spec.tick % 100 == 0;
    if (!rebuild || spec.controlled) Require(a == b, "reuse or controlled-rebuild worklist order");
    std::sort(a.begin(), a.end()); std::sort(b.begin(), b.end());
    Require(a == b, "rebuild retains native worklist membership");
    for (U i = 0; i < b.size(); ++i) Require(b[i] == i, "worklist is a complete registry permutation");
    if (spec.breadthFirst) { CheckBfs(expected); CheckBfs(actual); }
}
// Dense differential fixtures deliberately exceed the live replay's contacts/primary ratio.
// Their explicit activation budget admits those worlds without restoring global maxima.
static const ntw2_workload::Capacity oracleCapacity{4096,4096,1024,16384,262144};
static void ActivateFixture(Fixture& f) {
    Require(ntw2_collide::Activate(f.manager.data(),oracleCapacity), "explicit fixture activation");
}
static void Execute(Fixture& f, bool native) {
    events = &f.calls; f.calls.clear(); ResetFp();
    mutationMode = f.mutation;
    mutationTarget = mutationMode ? f.records[2].bytes : nullptr;
    raiseAfterContact = f.callbackFault && !native;
    poisonShape = f.workerFault && !native ? f.records[0].bytes : nullptr;
    if (native) reinterpret_cast<U(__fastcall*)(void*)>(At(0x57dc30))(f.manager.data());
    else ntw2_collide::Stage(f.manager.data());
    Require(!raiseAfterContact, "requested callback fault was reached");
    Require(!poisonShape, "requested gather snapshot injection was reached");
    events = nullptr; mutationTarget = nullptr; mutationMode = 0;
}
static void CheckLocalQueries(const Fixture& f, const Spec& spec, const U* before, const U* after) {
    if (!spec.expectedNativeQueries) return;
    Require(after[ntw2_collide::NativeQueries] == before[ntw2_collide::NativeQueries] + spec.expectedNativeQueries,
        "only affected records execute original queries");
    Require(after[ntw2_collide::NodeFallbacks] == before[ntw2_collide::NodeFallbacks] + spec.expectedNativeQueries,
        "unsupported nodes count per-record native queries");
    Require(after[ntw2_collide::UnsupportedCells] > before[ntw2_collide::UnsupportedCells],
        "unsupported cells recorded without refusing the stage");
    Require(after[ntw2_collide::Faults] == before[ntw2_collide::Faults], "safe native aliases do not fault");
    Require(after[ntw2_collide::LayoutFallbacks] == before[ntw2_collide::LayoutFallbacks],
        "local node incompatibility is not a global layout refusal");
    if (spec.expectedSolverContacts != 0xffffffffu) {
        Require(after[ntw2_collide::Contacts] == before[ntw2_collide::Contacts] + spec.expectedSolverContacts,
            "unaffected cluster retains solver contacts");
        Require(after[ntw2_collide::Callbacks] == before[ntw2_collide::Callbacks] + spec.expectedSolverContacts,
            "unaffected cluster retains owner solver callbacks");
    }
    if (before[ntw2_collide::DiagnosticReason]) {
        for (U i = ntw2_collide::DiagnosticReason; i <= ntw2_collide::DiagnosticExpectedRecord; ++i)
            Require(after[i] == before[i], "first unsupported-node snapshot retained across stages");
    } else {
        const bool external = f.registry.size() < f.records.size();
        const U owner = external ? U(f.registry.size()) : 0;
        const Node& node = f.nodes[owner][0];
        Require(after[ntw2_collide::DiagnosticReason] == (external ? ntw2_collide::ChainOwner : ntw2_collide::OwnType),
            "first synthetic unsupported-node reason");
        Require(after[ntw2_collide::DiagnosticNode] == A(&node), "diagnostic identifies actual offending node");
        Require(after[ntw2_collide::DiagnosticType] == node.type, "diagnostic captures node type");
        Require(after[ntw2_collide::DiagnosticOwner] == node.owner, "diagnostic captures raw owner pointer");
        Require(after[ntw2_collide::DiagnosticPayload] == node.payload, "diagnostic captures raw payload pointer");
        Require(after[ntw2_collide::DiagnosticId] == node.serial, "diagnostic captures full node ID");
        Require(after[ntw2_collide::DiagnosticCell] == (node.head - A(f.cells.data())) / sizeof(U),
            "diagnostic captures actual native cell");
        Require(after[ntw2_collide::DiagnosticVtable] == A(vtable), "diagnostic captures known record vtable");
        Require(after[ntw2_collide::DiagnosticRecord] == 0, "diagnostic identifies first known querying record");
        Require(after[ntw2_collide::DiagnosticExpectedRecord] == A(f.records[0].bytes),
            "diagnostic captures expected known record address");
    }
}
static void CheckSolverCounts(const Fixture& actual, const Spec& spec, const U* before, const U* after) {
    // Counter-level once-only gate: each non-native-local unordered logical pair is
    // applied and called back by the solver exactly once, never once per worker/cell/orientation.
    const std::vector<bool> local = NativeLocal(actual, spec);
    U solverPairs = 0;
    for (const Event& e : actual.calls) if (!local[e.receiver] && !local[e.argument]) ++solverPairs;
    Require(after[ntw2_collide::Contacts] - before[ntw2_collide::Contacts] == solverPairs,
        "solver Contacts counter equals non-native-local unordered pairs (no double processing)");
    Require(after[ntw2_collide::Callbacks] - before[ntw2_collide::Callbacks] == solverPairs,
        "solver Callbacks counter equals non-native-local unordered pairs (no double callbacks)");
    // These samples come from the production solver, not an instrumented radius-leaf mock.
    // Count attempted shaped radius tests even when the original leaf rejects the contact.
    if (std::none_of(spec.input.begin(), spec.input.end(), [](const Input& in) { return in.shape != 0; }))
        Require(after[ntw2_collide::ShapedPairs] == before[ntw2_collide::ShapedPairs],
            "unshaped circles bypass the original radius leaf");
    if (spec.expectedShapedPairs != 0xffffffffu)
        Require(after[ntw2_collide::ShapedPairs] - before[ntw2_collide::ShapedPairs] == spec.expectedShapedPairs,
            "original radius leaf runs exactly once per eligible shaped pair");
    if (spec.checkCellHistogram) {
        U occupied = 0, candidates = 0;
        bool multicell = false;
        for (U cell : actual.cells) if (cell) ++occupied;
        for (U i = 0; i < actual.records.size(); ++i) {
            multicell |= Get<U>(actual.records[i].bytes, 0xac) > 1;
            for (U k = i + 1; k < actual.records.size(); ++k)
                if (actual.ShareCell(i, k)) candidates += 2;
        }
        Require(occupied > 1 && multicell, "dense histogram fixture spans multiple real native cells");
        Require(after[ntw2_collide::Cells] - before[ntw2_collide::Cells] == occupied,
            "histogram occupied-cell total matches real native insertion");
        Require(after[ntw2_collide::Pairs] - before[ntw2_collide::Pairs] == candidates,
            "histogram scatter preserves every directed shared-cell candidate exactly once");
    }
    // Eligible-query gate at stage entry: snapshot +30 nonzero (NOT active==1) and (flags&3)!=0.
    // Counts native-local and solver queries per initial worklist entry, never destination-only slots.
    U eligible = 0;
    for (U r : actual.worklist) {
        const Input& in = spec.input[Get<U>(reinterpret_cast<const void*>(r), 0x2c)];
        if (in.active != 0 && (in.flags & 3) != 0) ++eligible;
    }
    Require(after[ntw2_collide::EligibleQueries] - before[ntw2_collide::EligibleQueries] == eligible,
        "EligibleQueries equals initial worklist entries with +30 nonzero and flags&3 (queries only, no destinations)");
}
static void CheckFrozenSelection(const Fixture& actual, const Spec& spec) {
    // The six mutation fixtures: record 2's callback-time edits must have run in the production
    // solver, yet must not alter this tick's pair set, which equals the mutation-disabled native
    // reference (checked by Compare). The live native run documents the intentional divergence.
    const B* target = actual.records[2].bytes;
    switch (spec.mutation) {
    case 1: Require(Get<float>(target, 0x54) == 0.0f, "mutation 1 height edit executed"); break;
    case 2: Require(Get<U>(target, 0x38) == 0, "mutation 2 flags edit executed"); break;
    case 3: Require(Get<float>(target, 0x58) == 0.0f, "mutation 3 radius edit executed"); break;
    case 4: Require(Get<float>(target, 0x54) == 3.0f, "mutation 4 height edit executed"); break;
    case 5: Require(Get<U>(target, 0x38) == 1, "mutation 5 flags edit executed"); break;
    case 6: Require(Get<float>(target, 0x58) == 0.5f, "mutation 6 radius edit executed"); break;
    default: Fail("unknown mutation fixture");
    }
    Fixture live(spec); Execute(live, true);
    const auto livePairs = PairSet(live.calls, "live native mutation reference");
    const auto frozenPairs = PairSet(actual.calls, "production solver");
    Require(livePairs.size() == spec.expectedContacts, "live native callback mutation yields the original live pair count");
    Require(frozenPairs.size() == spec.frozenContacts, "frozen Phase B selection yields the entry-state pair count");
    Require(livePairs != frozenPairs, "intentional Phase B divergence: callback mutation does not change preselected packets");
    // Mutations 1..3 make a candidate ineligible, 4..6 eligible: live is a strict subset or superset of frozen.
    if (spec.mutation <= 3) Require(std::includes(frozenPairs.begin(), frozenPairs.end(), livePairs.begin(), livePairs.end()),
        "live native pruned pairs that the frozen selection retains");
    else Require(std::includes(livePairs.begin(), livePairs.end(), frozenPairs.begin(), frozenPairs.end()),
        "live native added pairs that the frozen selection excludes");
}
static void Run(const char* name, const Spec& spec, bool fallback = false, bool reuseAfter = false) {
    currentCase = name;
    // Reference policy: the native image is the oracle on immutable inputs. A mutating fixture's
    // reference is the frozen entry-state selection, i.e. the same native run with the mutation off.
    Spec reference = spec; reference.mutation = 0;
    if (spec.mutation) reference.expectedContacts = spec.frozenContacts;
    Fixture expected(reference), actual(spec);
    ActivateFixture(actual);
    // A callback fault still runs the solver's numeric commit and owner continuation; only
    // true fallbacks execute the original stage (bit-exact callback observations).
    const bool original = fallback && !spec.callbackFault;
    U before[ntw2_collide::WordCount], after[ntw2_collide::WordCount]; ntw2_collide::Sample(before);
    if (spec.expectedNativeQueries && spec.expectedSolverContacts != 0xffffffffu) {
        // Validate original insertion isolates one bad cell from a valid cluster.
        const U local = actual.nodes[0][0].head;
        U affected = 0;
        for (U i = 0; i < actual.registry.size(); ++i) {
            Require(Get<U>(actual.records[i].bytes, 0xac) == 1, "mixed fixture records occupy one real native cell");
            if (actual.nodes[i][0].head == local) ++affected;
        }
        Require(affected == spec.expectedNativeQueries && affected < actual.registry.size(),
            "mixed fixture isolates local fallback from distant solver queries");
    }
    if (spec.mutation) for (U i = 0; i < spec.input.size(); ++i) {
        Require(Get<U>(expected.records[i].bytes, 0xac) == 1 &&
            expected.nodes[i][0].head == expected.nodes[0][0].head,
            "controlled mutation records share exactly one native cell");
    }
    Execute(expected, true); Execute(actual, false); Compare(expected, actual, reference, original);
    ntw2_collide::Sample(after);
    Require(after[ntw2_collide::Calls] == before[ntw2_collide::Calls] + 1, "one routed stage counter");
    if (fallback) Require(after[ntw2_collide::FallbackTicks] == before[ntw2_collide::FallbackTicks] + 1, "original fallback exercised");
    else {
        Require(after[ntw2_collide::SolverTicks] == before[ntw2_collide::SolverTicks] + 1, "production solver exercised, not silent fallback");
        Require(after[ntw2_collide::FallbackTicks] == before[ntw2_collide::FallbackTicks], "supported fixture does not fall back");
        CheckSolverCounts(actual, spec, before, after);
    }
    CheckLocalQueries(actual, spec, before, after);
    if (spec.secondaryRegistry) {
        Require(after[ntw2_collide::DiagnosticReason] == 0 && before[ntw2_collide::DiagnosticReason] == 0,
            "registered secondary owner records no unsupported-node diagnostic");
        Require(after[ntw2_collide::NativeQueries] == before[ntw2_collide::NativeQueries] &&
            after[ntw2_collide::NodeFallbacks] == before[ntw2_collide::NodeFallbacks] &&
            after[ntw2_collide::UnsupportedCells] == before[ntw2_collide::UnsupportedCells],
            "registered secondary owner needs no native-local query");
        Require(after[ntw2_collide::Contacts] - before[ntw2_collide::Contacts] == PairSet(actual.calls, "production solver").size() &&
            after[ntw2_collide::Callbacks] - before[ntw2_collide::Callbacks] == actual.calls.size(),
            "solver counters cover every contact touching the secondary owner exactly once");
    }
    if (spec.mutation) CheckFrozenSelection(actual, spec);
    if (spec.workerFault) {
        Require(after[ntw2_collide::Faults] == before[ntw2_collide::Faults] + 1, "one numeric chunk fault recorded");
        Require(after[ntw2_collide::StickyFallbacks] == before[ntw2_collide::StickyFallbacks] + 1, "chunk fault makes fallback sticky");
        Require(after[ntw2_collide::SolverTicks] == before[ntw2_collide::SolverTicks], "chunk fault refuses before apply");
        Require(after[ntw2_collide::OwnerContinuations] == before[ntw2_collide::OwnerContinuations], "pre-write chunk fault needs no owner continuation");
        Require(after[ntw2_collide::LastException] == EXCEPTION_ACCESS_VIOLATION, "snapshot shape access fault retained");
    }
    if (spec.callbackFault) {
        Require(after[ntw2_collide::Faults] == before[ntw2_collide::Faults] + 1, "one callback fault recorded");
        // Numeric effects are already committed: the owner finishes the remaining precomputed
        // redistribution/callback records (counted as an owner continuation); it never re-queries
        // natively, and the original stage takes over only on the NEXT tick (sticky).
        Require(after[ntw2_collide::OwnerContinuations] == before[ntw2_collide::OwnerContinuations] + 1, "remaining records finish through owner continuation");
        Require(after[ntw2_collide::NativeQueries] == before[ntw2_collide::NativeQueries], "callback fault continuation issues no native queries");
        Require(after[ntw2_collide::LastException] == 0xe0422001u, "callback exception code retained");
    }
    ++cases;
    if (reuseAfter) {
        // Replay the native rebuild permutation on both fixtures. This isolates
        // reuse semantics from the intentionally permitted rebuild permutation.
        const auto order = expected.Order();
        for (U i = 0; i < order.size(); ++i) {
            actual.worklist[i] = actual.registry[order[i]];
            Put(expected.records[i].bytes, 0x40, B(0)); Put(actual.records[i].bytes, 0x40, B(0));
        }
        Put(expected.model.data(), 0x58, U(101)); Put(actual.model.data(), 0x58, U(101));
        Spec reuse = reference; reuse.tick = 101; reuse.rebuild = 0; reuse.breadthFirst = false;
        ntw2_collide::Sample(before);
        Execute(expected, true); Execute(actual, false); Compare(expected, actual, reuse, false);
        ntw2_collide::Sample(after);
        Require(after[ntw2_collide::SolverTicks] == before[ntw2_collide::SolverTicks] + 1,
            "post-rebuild reuse remains a solver tick");
        Require(after[ntw2_collide::FallbackTicks] == before[ntw2_collide::FallbackTicks],
            "post-rebuild reuse avoids whole-stage fallback");
        CheckSolverCounts(actual, reuse, before, after);
        CheckLocalQueries(actual, reuse, before, after); ++cases;
    }
}
static Spec Two() {
    Spec s; s.input.resize(2); s.input[1].x = 0.75f; s.input[1].z = 0.25f;
    s.input[0].label = 0x80000001u; s.input[1].label = 7; return s;
}
static void TwoRecordCases() {
    Spec s = Two(); s.expectedContacts = 1; Run("same team overlap", s);
    s.reverseInsertion = true; Run("reverse insertion", s);
    s = Two(); s.order = {1, 0}; Run("reverse worklist", s);
    s = Two(); s.input[0].team = 0; s.input[0].flags = s.input[1].flags = 5;
    s.expectedContacts = 1; Run("null current team bit four path", s);
    s.input[1].team = 0; Run("both null teams bit four path", s);
    s = Two(); s.rebuild = 1; s.expectedContacts = 1; Run("controlled contact rebuild", s, false, true);
    for (U teamMode = 0; teamMode < 3; ++teamMode) for (U a = 0; a < 8; ++a) for (U b = 0; b < 8; ++b) {
        s = Two(); s.input[0].flags = a; s.input[1].flags = b;
        s.input[1].team = teamMode == 0 ? 1 : teamMode == 1 ? 2 : 0;
        Run("team/filter flags exhaustive", s);
    }
    for (U side = 0; side < 2; ++side) {
        for (float dy : {-3.25f, -3.0f, -2.75f, 0.0f, 2.75f, 3.0f, 3.25f}) {
            s = Two(); s.input[side].y = dy; Run("strict height both directions", s);
        }
        s = Two(); s.input[side].exclusion = 1 - side; s.expectedContacts = 0; Run("symmetric exclusion", s);
        s = Two(); s.input[side].active = 0; s.expectedContacts = 0; Run("inactive record", s);
        s = Two(); s.input[side].active = 2; Run("entry nonzero versus neighbor exactly one", s);
        s = Two(); s.input[side].processed = 1; Run("already processed neighbor", s);
        s = Two(); s.input[side].inserted = false; s.expectedContacts = 0; Run("zero inserted nodes", s);
    }
    for (float x : {0.0f, 0.00001f, 1.9999f, std::nextafter(2.0f, 0.0f), 2.0f,
            std::nextafter(2.0f, std::numeric_limits<float>::infinity()), 2.0001f, 3.5f, 9.0f}) {
        s = Two(); s.input[1].x = x; s.input[1].z = 0;
        s.expectedContacts = x < 2.0f ? 1 : 0;
        Run("radius boundary and distance crossover", s);
    }
    for (U a = 0; a < 3; ++a) for (U b = 0; b < 3; ++b) {
        s = Two(); s.input[0].flags = s.input[1].flags = 2; s.input[1].team = 2;
        s.input[0].bump = B(a); s.input[1].bump = B(b); s.input[1].x = 2.125f;
        Run("different team bump flags exactly one", s);
    }
    for (U different = 0; different < 2; ++different) for (U weight = 0; weight < 3; ++weight)
        for (U toward = 0; toward < 3; ++toward) {
            s = Two(); s.input[0].flags = s.input[1].flags = different ? 2 : 0x21;
            s.input[1].team = different ? 2 : 1; s.input[1].weight = B(weight);
            s.input[0].mass = 2; s.input[0].inverse = 0.5f; s.input[1].mass = 3; s.input[1].inverse = 1.0f / 3.0f;
            s.input[0].vx = toward == 0 ? 4.0f : -2.0f;
            s.input[1].vx = toward == 1 ? -5.0f : 2.0f;
            s.input[0].vz = 0.5f; s.input[1].vz = -0.25f;
            Run("live velocity exchange weight override suppress and unsigned labels", s);
        }
    // Distinct nonconstant scale tables force the original FPATAN/FISTP helper
    // through both shape operands and wrapped heading differences.
    std::array<float, 256> scalesA{}, scalesB{}; std::array<U, 7> shapeA{}, shapeB{};
    for (U i = 0; i < 256; ++i) {
        scalesA[i] = 0.125f + float(i % 17) / 16.0f;
        scalesB[i] = 0.25f + float((255 - i) % 13) / 16.0f;
    }
    shapeA[6] = A(scalesA.data()); shapeB[6] = A(scalesB.data());
    for (U mask = 0; mask < 4; ++mask) for (U heading : {0u, 1u, 255u, 256u, 32767u, 32768u, 65535u}) {
        s = Two(); s.input[0].shape = mask & 1 ? A(shapeA.data()) : 0;
        s.input[1].shape = mask & 2 ? A(shapeB.data()) : 0;
        s.input[0].heading = uint16_t(heading); s.input[1].heading = uint16_t(65535 - heading);
        s.expectedShapedPairs = mask ? 1 : 0;
        Run("oriented radii and heading wrap", s);
    }
    for (float base : {-80.0f, -64.0f, -63.0f, -4.5f, -0.5f, 0.0f, 0.5f, 4.5f, 60.0f, 80.0f}) {
        s = Two(); s.input[0].x += base; s.input[1].x += base;
        s.input[0].z += base; s.input[1].z += base;
        Run("native grid rounding origin and unsigned clamp", s);
    }
    s = Two(); s.input[0].inserted = s.input[1].inserted = false; Run("all zero nodes", s);
    s = Spec{}; Run("empty reuse", s); s.tick = 100; Run("empty modulo rebuild", s);
}
static void MultiRecordCases() {
    Spec s; s.input.resize(8); s.expectedContacts = 4;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = float(i / 2) * 12.0f + float(i % 2) * 0.75f;
        s.input[i].flags = 0x21; s.input[i].vx = i % 2 ? -1.0f : 2.0f;
        s.input[i].label = 20 - i;
    }
    Run("controlled multi-callback order and state", s);
    // Contact path 0--1--2: 0 and 2 do not contact. Ordered redistribution leaves
    // labels {2,9,9}, not the component maximum {9,9,9}; the first callback sees
    // record 1's later velocity/label/processed stores only in the supported solver.
    s = Spec{}; s.input.resize(3); s.reverseInsertion = true; s.expectedContacts = 2;
    s.expectFinalObservation = true; s.expectFinalOwnerObservation = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = 1.5f + float(i) * 0.75f; s.input[i].z = 2.0f;
        s.input[i].radius = 0.5f; s.input[i].flags = 0x21;
        s.input[i].label = i == 2 ? 9 : i + 1;
    }
    s.input[0].vx = 4.0f;
    Run("final callback owner state preserves ordered conditional label propagation", s);
    for (U mode = 1; mode <= 6; ++mode) {
        s = Spec{}; s.input.resize(3); s.reverseInsertion = true; s.mutation = mode;
        for (Input& in : s.input) { in.radius = 0.5f; in.z = 2.0f; }
        s.input[0].x = 1.5f; s.input[1].x = 1.875f; s.input[2].x = 2.375f;
        if (mode == 4) s.input[2].height = 0;
        if (mode == 5) s.input[2].flags = 0;
        if (mode == 6) s.input[2].radius = 0;
        // Reverse insertion makes both engines visit 0->1 before 0->2. Neither old nor new
        // radius changes this fixture's single-cell cover.
        // Callback (1,0) edits record 2 after the Phase B packet set is frozen. Live native
        // (expectedContacts) prunes (modes 1..3) or adds (modes 4..6) later pairs; the frozen
        // solver selection equals the mutation-disabled native reference (frozenContacts), so
        // the reference pair set is the opposite and the intentional divergence is asserted.
        s.expectedContacts = mode <= 3 ? 1 : 3;
        s.frozenContacts = mode <= 3 ? 3 : 1;
        // Three frozen pairs give record 0/1 later contributions that the first callback must see.
        s.expectFinalObservation = mode <= 3;
        Run("callback mutation cannot change frozen Phase B packet selection", s);
    }
    // Initial +40 and reversed worklist once-only orientation: three mutually visible records
    // in every worklist permutation, every initial processed mask and both insertion orders.
    // The native image is the oracle (immutable inputs keep its accepted pair set); each logical
    // pair may be applied/called back at most once whichever record queries first.
    for (bool reverse : {false, true}) {
        std::array<U, 3> perm{0, 1, 2};
        do {
            for (U mask = 0; mask < 8; ++mask) {
                s = Spec{}; s.input.resize(3); s.reverseInsertion = reverse;
                s.order.assign(perm.begin(), perm.end());
                for (Input& in : s.input) { in.radius = 0.5f; in.z = 2.0f; }
                s.input[0].x = 1.5f; s.input[1].x = 1.875f; s.input[2].x = 2.375f;
                for (U i = 0; i < 3; ++i) s.input[i].processed = B((mask >> i) & 1);
                if (!mask) { s.expectedContacts = 3; s.expectFinalObservation = true; }
                Run("once-only pair orientation over worklist permutations and initial processed bytes", s);
            }
        } while (std::next_permutation(perm.begin(), perm.end()));
    }
    for (bool reverse : {false, true}) {
        s = Spec{}; s.input.resize(192); s.reverseInsertion = reverse; s.checkCellHistogram = true;
        for (U i = 0; i < s.input.size(); ++i) {
            s.input[i].x = float(i % 16) * 0.3f; s.input[i].z = float(i / 16) * 0.35f;
            s.input[i].radius = 0.8f + float(i % 3) * 0.1f;
            s.input[i].mass = float(1 + i % 4); s.input[i].inverse = 1.0f / s.input[i].mass;
            s.input[i].label = i + 1;
        }
        Run("dense multicell histogram, dedup and exact native callback order", s);
    }
    // Radius .25 leaves broadphase-visible, noncontact neighbors. BFS must use
    // first-seen candidate IDs, not just accepted contacts. Three distant groups.
    s = Spec{}; s.input.resize(12); s.controlled = false; s.breadthFirst = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = float(i / 4) * 16.0f + float(i % 4) * 0.8f;
        s.input[i].radius = 0.25f; s.order.push_back(U(s.input.size()) - 1 - i);
    }
    s.expectedContacts = 0; s.rebuild = 1; Run("requested rebuild includes rejected neighbors", s, false, true);
    s.rebuild = 0; s.tick = 100; Run("modulo 100 rebuild visibility BFS", s, false, true);
    s.tick = 99; s.rebuild = 2; s.breadthFirst = false; Run("rebuild flag must equal one", s);
    s.rebuild = 1; s.tick = 101; s.breadthFirst = true; s.expectedContacts = 0xffffffffu;
    for (Input& in : s.input) in.radius = 1.0f;
    Run("contact cluster rebuild and subsequent reuse", s, false, true);
}
// Contact-mode plan chunks split the dense contact range, not records: 128 five-record clusters give
// 1280 contacts (4/3/2/1/0 per cluster), so the 10 plan chunks' boundaries fall inside a record's
// contact run. A plan row left unwritten would replay as an effect-free port plan and drop a callback.
static Spec ClusterWorld() {
    Spec s; s.input.resize(640);
    for (U i = 0; i < s.input.size(); ++i) {
        U group = i / 5;
        s.input[i].x = -60.0f + float(group % 16) * 8.0f + float(i % 5) * 0.125f;
        s.input[i].z = -56.0f + float(group / 16) * 8.0f;
        s.input[i].radius = 0.5f;
    }
    return s;
}
static void PlanChunkCases() {
    Spec s = ClusterWorld(); s.expectedContacts = 1280;
    Run("contact plan chunks split record contact runs", s);
}
static __declspec(align(64)) ntw_pool pool;
static ntw2_collide::Binding Binding(U workers) { return {delta, &ntw_pool_dispatch, A(&pool), workers}; }
static void StartPool(U workers) {
    ntw_pool_config cfg{}; cfg.abi = NTW_POOL_ABI; cfg.workers = workers;
    cfg.api.create_event = Fn(&CreateEventW); cfg.api.close_handle = Fn(&CloseHandle);
    cfg.api.set_event = Fn(&SetEvent); cfg.api.wait_single = Fn(&WaitForSingleObject);
    cfg.api.create_thread = Fn(&CreateThread); cfg.api.worker_entry = Fn(&ntw_pool_worker_start);
    Require(ntw_pool_init(&pool, &cfg) == NTW_POOL_OK, "real persistent pool starts");
}
// Real LAND-class contacts through the production solver: records carry the image's type-8 callback
// pair (+0x40 = 0x64CAD0, +0x44 = 0x64CC70), so the native stage and the shadow pass run the original
// callback. +0x117 alternates blocking roles inside each cluster, so a plan's WriteR/WriteS depends on
// its orientation and its keys identify its pair; both-blocked pairs take the availability path
// (manager bits recorded and revalidated). Checked per lane count 1/3/8 and mode: final state equals
// the native stage, plan rows are predicted exactly once (counted at prediction), each row equals a
// serial Predict of its own (R, S), the rows cover the geometric pair set once, shadow agrees with the
// original on every row, and rows and final +0x13C state are identical across lane counts and modes.
static U landVtable[18];
static void MakeLand(Fixture& f) {
    for (U i = 0; i < f.records.size(); ++i) {
        B* r = f.records[i].bytes;
        Put(r, 0, A(landVtable));
        Put(r, 0x117, B(i % 5 == 0 || i % 5 == 2 ? 0 : 1)); Put(r, 0x118, B(1));
        Put(r, 0x160, Get<float>(r, 0x48)); Put(r, 0x168, Get<float>(r, 0x50)); // slot = position
    }
    for (U i = 0; i < f.records.size(); i += 7) f.avoidBits[i >> 3] |= B(1u << (i & 7));
}
static void LandPlanCases() {
    landVtable[0x40 / 4] = A(At(0x64cad0)); landVtable[0x44 / 4] = A(At(0x64cc70));
    const Spec spec = ClusterWorld();
    std::vector<Pair> pairs;
    for (U i = 0; i < spec.input.size(); ++i)
        for (U j = i + 1; j < spec.input.size() && j / 5 == i / 5; ++j) pairs.push_back({i, j});
    Require(pairs.size() == 1280, "LAND cluster world has 1280 geometric pairs");
    std::vector<ntw2_contact::Plan> firstRows;
    std::vector<U> firstState;
    for (U workers : {1u, 3u, 8u}) for (U mode : {U(ntw2_contact::ModeShadow), U(ntw2_contact::ModeWorkers)}) {
        currentCase = mode == ntw2_contact::ModeShadow ? "LAND contact plans (shadow)" : "LAND contact plans (workers)";
        StartPool(workers); auto bind = Binding(workers); bind.contact_mode = mode;
        Require(ntw2_collide::Start(bind), "contact-mode solver starts");
        Fixture expected(spec), actual(spec); MakeLand(expected); MakeLand(actual);
        ActivateFixture(actual);
        U before[ntw2_collide::WordCount], after[ntw2_collide::WordCount]; ntw2_collide::Sample(before);
        Execute(expected, true); Execute(actual, false);
        Compare(expected, actual, spec, false);
        ntw2_collide::Sample(after);
        Require(after[ntw2_collide::SolverTicks] == before[ntw2_collide::SolverTicks] + 1 &&
            after[ntw2_collide::Callbacks] - before[ntw2_collide::Callbacks] == pairs.size(), "LAND world runs the solver");
        U c[ntw2_contact::WordCount]; ntw2_contact::Sample(c);
        Require(c[ntw2_contact::Contacts] == pairs.size() && c[ntw2_contact::PortContacts] == pairs.size(),
            "every LAND contact is consumed once as a port plan");
        Require(c[ntw2_contact::PredictedWriteR] > 0 && c[ntw2_contact::PredictedWriteS] > 0,
            "fixture distinguishes receiver and argument writes");
        if (mode == ntw2_contact::ModeShadow)
            Require(c[ntw2_contact::Compared] == pairs.size() && c[ntw2_contact::Mismatches] == 0,
                "every row agrees with the original callback on the pair it was replayed for");
        else
            Require(c[ntw2_contact::Replays] == pairs.size() && c[ntw2_contact::OwnerCallbacks] == 0,
                "workers replay every LAND row without the original");
        U rows = 0, predicted = 0;
        const ntw2_contact::Plan* plans = ntw2_collide::ContactPlans(rows, predicted);
        Require(plans && rows == pairs.size() && predicted == rows, "every row predicted exactly once at plan time");
        std::vector<Pair> keyed;
        for (U n = 0; n < rows; ++n) keyed.push_back({std::min<U>(plans[n].keyR, plans[n].keyS), std::max<U>(plans[n].keyR, plans[n].keyS)});
        std::sort(keyed.begin(), keyed.end());
        Require(keyed == pairs, "plan rows cover the geometric pair set exactly once");
        // Plan inputs are untouched by the callback pass, so post-stage state re-derives every row.
        ntw2_contact::Stage stage; ResetFp();
        Require(ntw2_contact::BeginStage(stage, actual.model.data()), "serial reference stage admits");
        for (U n = 0; n < rows; ++n) {
            ntw2_contact::Plan p;
            ntw2_contact::Predict(stage, p, actual.records[plans[n].keyR].bytes, actual.records[plans[n].keyS].bytes);
            Require(!std::memcmp(&p, &plans[n], sizeof(p)), "row equals a serial prediction of its own (R, S)");
        }
        std::vector<U> state;
        for (const Record& r : actual.records) state.push_back(Get<U>(r.bytes, 0x13c));
        if (firstRows.empty()) { firstRows.assign(plans, plans + rows); firstState = state; }
        else {
            Require(!std::memcmp(firstRows.data(), plans, rows * sizeof(ntw2_contact::Plan)), "plan rows identical across lane counts and modes");
            Require(state == firstState, "final +0x13C state identical across lane counts and modes");
        }
        ntw2_collide::Stop(); Require(ntw_pool_shutdown(&pool) == NTW_POOL_OK, "real pool drains after LAND plans");
        ++cases;
    }
}
static void FallbackCases(U workers) {
    Spec s = Two(); s.invalidGrid = true;
    Run("unsupported grid pre-write fallback", s, true);
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart after layout refusal");
    // Type16 uses the native payload alias but deliberately has no type8 callback.
    s = Two(); s.foreignNodes = true; s.expectedContacts = 0; s.expectedNativeQueries = 2;
    Run("foreign nodes use record-local original queries", s);
    // Keep the binding/counters: later fixture activations must not overwrite its first diagnostic.
    s = Spec{}; s.input.resize(4); s.reverseInsertion = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = 1.5f + float(i / 2) * 16.0f + float(i % 2) * 0.375f;
        s.input[i].z = 2.0f; s.input[i].radius = 0.5f;
        s.input[i].flags = 0x21; s.input[i].vx = i % 2 ? -1.0f : 2.0f;
        s.input[i].label = 20 - i;
    }
    s.input[0].nodeType = 16; s.expectedNativeQueries = 2;
    s.expectedContacts = 2; s.expectedSolverContacts = 1;
    Run("own type16 alias local cluster and distant solver callbacks", s);
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart for mixed own-node diagnostic");
    // Interleave registry IDs across clusters: native query IDs must enqueue
    // local 2/4 before the distant seed1, not silently fall back to seed order.
    s = Spec{}; s.input.resize(6); s.reverseInsertion = true; s.rebuild = 1; s.breadthFirst = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = 1.5f + float(i % 2) * 16.0f + float(i / 2) * 0.375f;
        s.input[i].z = 2.0f; s.input[i].radius = 0.5f;
        s.input[i].flags = 0x21; s.input[i].vx = i < 2 ? 2.0f : -1.0f;
        s.input[i].label = 20 - i; s.order.push_back(5 - i);
    }
    s.input[0].nodeType = 16; s.expectedNativeQueries = 3;
    s.expectedContacts = 6; s.expectedSolverContacts = 3;
    Run("mixed native-query BFS and solver cluster rebuild reuse", s, false, true);
    for (Input& in : s.input) in.radius = 0.125f;
    s.expectedContacts = 0; s.expectedSolverContacts = 0;
    Run("mixed rebuild keeps rejected native-query IDs for BFS reuse", s, false, true);
    // A genuine inserted producer absent from the primary registry still owns
    // live numeric state and type8 callbacks; no foreign contacts may be omitted. Until a
    // secondary-registry owner is supported by the solver this stays an original native-local
    // cluster (Reason ChainOwner, original ordering and intermediate callback observations);
    // supporting it replaces this fixture with a solver-owned one (expectedNativeQueries 0).
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart for foreign-owner diagnostic");
    s = Spec{}; s.input.resize(5); s.primaryCount = 4; s.reverseInsertion = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = i == 4 ? 2.25f : 1.5f + float(i / 2) * 16.0f + float(i % 2) * 0.375f;
        s.input[i].z = 2.0f; s.input[i].radius = 0.5f;
        s.input[i].flags = 0x21; s.input[i].vx = i % 2 ? -1.0f : 2.0f;
        s.input[i].label = 20 - i;
    }
    s.expectedNativeQueries = 2; s.expectedSolverContacts = 1; s.expectedContacts = 4;
    Run("foreign chain owner outside primary registry preserves full effects", s);
    // Registered in the secondary registry (manager +278/+27C), the same producer is a
    // destination-only solver slot: no native query, no unsupported-node diagnostic, and the
    // solver itself applies and calls back every contact that touches it, once.
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart for registered secondary owner");
    s.secondaryRegistry = true; s.expectedNativeQueries = 0; s.expectedSolverContacts = 0xffffffffu; s.expectedContacts = 4;
    // The original constructor selects the secondary wrapper iff record+66 == 1; the solver reads the
    // actual byte, so the secondary record carries it. Native comparison proves the weight override
    // and the no-redistribution neighbor semantics for a destination-only slot.
    s.input[4].weight = 1;
    Run("secondary-registered chain owner is a solver destination slot", s);
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart after local node cases");
    currentCase = "capacity pre-write fallback";
    // A safe native reuse list larger than the arena. Every entry is inactive;
    // refusal must precede any worklist uniqueness/layout inspection or writes.
    Spec inactive; inactive.input.resize(1); inactive.input[0].active = 0; inactive.input[0].inserted = false;
    Fixture a(inactive), b(inactive);
    ActivateFixture(b);
    std::vector<U> wa(131073, A(a.records[0].bytes)), wb(131073, A(b.records[0].bytes));
    Put(a.manager.data(), 0x260, U(wa.size())); Put(b.manager.data(), 0x260, U(wb.size()));
    Put(a.manager.data(), 0x264, A(wa.data())); Put(b.manager.data(), 0x264, A(wb.data()));
    Put(a.manager.data(), 0x24c, U(wa.size())); Put(b.manager.data(), 0x24c, U(wb.size()));
    Put(a.manager.data(), 0x250, A(wa.data())); Put(b.manager.data(), 0x250, A(wb.data()));
    U before[ntw2_collide::WordCount], after[ntw2_collide::WordCount]; ntw2_collide::Sample(before);
    Execute(a, true); Execute(b, false);
    Require(!std::memcmp(a.records[0].bytes + 0x30, b.records[0].bytes + 0x30, 0x74), "capacity refusal leaves native record outputs");
    Require(a.calls.empty() && b.calls.empty(), "inactive capacity fallback has no callbacks");
    ntw2_collide::Sample(after);
    Require(after[ntw2_collide::FallbackTicks] == before[ntw2_collide::FallbackTicks] + 1, "capacity invokes original stage");
    Require(after[ntw2_collide::CapacityFallbacks] == before[ntw2_collide::CapacityFallbacks] + 1, "capacity reason recorded");
    ++cases;
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart after capacity refusal");
    s = Two(); s.expectedContacts = 1; Run("restart restores solver", s);
    s = Spec{}; s.input.resize(4); s.reverseInsertion = true; s.callbackFault = true;
    for (Input& in : s.input) { in.radius = 0.5f; in.z = 2.0f; }
    s.input[0].x = 1.5f; s.input[1].x = 1.875f; s.input[2].x = 2.375f; s.input[3].x = 2.75f;
    s.expectedContacts = 5;
    Run("callback fault finishes current pairs through owner continuation", s, true);
    ntw2_collide::Sample(before);
    s = Two(); s.expectedContacts = 1; Run("post-fault sticky original stage", s, true);
    ntw2_collide::Sample(after);
    Require(after[ntw2_collide::StickyFallbacks] == before[ntw2_collide::StickyFallbacks] + 1, "fault remains sticky until restart");
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart clears callback fault");
    Run("restart after callback fault restores solver", s);
    ntw2_collide::Stop();
    auto poisonBinding = Binding(workers); poisonBinding.dispatch = &PoisonGatherDispatch;
    Require(ntw2_collide::Start(poisonBinding), "start with real dispatch snapshot injection seam");
    s = Two(); s.workerFault = true; s.expectedContacts = 1;
    Run("numeric chunk fault restores inputs before original fallback", s, true);
    ntw2_collide::Sample(before);
    s = Two(); s.expectedContacts = 1; Run("post-chunk-fault sticky original stage", s, true);
    ntw2_collide::Sample(after);
    Require(after[ntw2_collide::StickyFallbacks] == before[ntw2_collide::StickyFallbacks] + 1, "chunk fault stays sticky");
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "restart clears chunk fault");
    ntw2_collide::Sample(after);
    for (U word : after) Require(word == 0, "restart resets all solver counters");
    Run("restart after chunk fault restores solver", s);
}
// ---------------------------------------------------------------------------------------------
// Owned-grid CSR consumption. The borrowed view is synthesized from the SAME fixture's genuine
// insertion (native chains read test-side, in native chain order); the solver under test never
// links the loco module. Three engines run every world: the untouched original image, the
// native-audit solver, and the owned-view solver. Owned and native-audit stages must select the
// same pair set (here also bit-identical state, because the synthetic CSR keeps chain order).
// ---------------------------------------------------------------------------------------------
static const ntw2_loco::GridView* gView;
static const ntw2_loco::GridView* ReadView(void*) { return gView; }
static B* P(U address) { return reinterpret_cast<B*>(static_cast<uintptr_t>(address)); }
struct OwnedView {
    std::vector<U> record, serial, incarnation, team, flags, active, left, right, top, bottom, inserted,
        nodeType, cellIds, offsets, occupants, cellDense;
    std::vector<float> x, z, y, extent, radius;
    ntw2_loco::GridView view{};
};
template<class T> static void Size(std::vector<T>& v, size_t n) { v.assign(n + 1, T()); } // never null
// dense=false imports native chain order. dense=true builds the production-style stable dense-slot CSR
// purely from the published bounds: compact cells in first-appearance order, ascending slot per cell.
static void BuildView(const Fixture& f, U tick, OwnedView& v, bool dense = false) {
    std::vector<U> slots(f.registry.begin(), f.registry.end()); // primary holes keep their native index
    for (U s : f.secondary)
        if (s && std::find(slots.begin(), slots.end(), s) == slots.end()) slots.push_back(s);
    const size_t count = slots.size(), cellsTotal = f.cells.size();
    for (auto* u : {&v.record, &v.serial, &v.incarnation, &v.team, &v.flags, &v.active, &v.left, &v.right,
                    &v.top, &v.bottom, &v.inserted, &v.nodeType}) Size(*u, count);
    for (auto* d : {&v.x, &v.z, &v.y, &v.extent, &v.radius}) Size(*d, count);
    U memberships = 0;
    for (size_t i = 0; i < count; ++i) {
        v.record[i] = slots[i];
        if (!slots[i]) continue;
        const B* r = P(slots[i]);
        v.serial[i] = Get<U>(r, 0x2c); v.incarnation[i] = U(i + 1); v.team[i] = Get<U>(r, 0x44);
        v.flags[i] = Get<U>(r, 0x38); v.active[i] = Get<B>(r, 0x30);
        v.x[i] = Get<float>(r, 0x48); v.y[i] = Get<float>(r, 0x4c); v.z[i] = Get<float>(r, 0x50);
        v.extent[i] = Get<float>(r, 0x54); v.radius[i] = Get<float>(r, 0x58);
        v.inserted[i] = Get<U>(r, 0xac); memberships += v.inserted[i];
        if (!v.inserted[i]) continue; // absent: node_type 0, bounds unspecified
        v.nodeType[i] = 8;
        const B* nodes = P(Get<U>(r, 0xa8));
        const U first = (Get<U>(nodes, 24) - A(f.cells.data())) / 4;
        const U last = (Get<U>(nodes + (v.inserted[i] - 1) * 0x1c, 24) - A(f.cells.data())) / 4;
        v.left[i] = first & 31; v.top[i] = first >> 5; v.right[i] = last & 31; v.bottom[i] = last >> 5;
    }
    std::vector<U> ids, offsets{0}, occupants;
    Size(v.cellDense, cellsTotal);
    if (dense) {
        std::vector<U> counts;
        for (size_t s = 0; s < count; ++s) {
            if (!v.inserted[s]) continue;
            for (U y = v.top[s]; y <= v.bottom[s]; ++y) for (U x = v.left[s]; x <= v.right[s]; ++x) {
                const U cell = (y << 5) + x;
                if (!v.cellDense[cell]) { ids.push_back(cell); v.cellDense[cell] = U(ids.size()); counts.push_back(0); }
                ++counts[v.cellDense[cell] - 1];
            }
        }
        for (U c : counts) offsets.push_back(offsets.back() + c);
        occupants.assign(offsets.back(), 0);
        std::vector<U> cursor(offsets.begin(), offsets.end() - 1);
        for (size_t s = 0; s < count; ++s) {
            if (!v.inserted[s]) continue;
            for (U y = v.top[s]; y <= v.bottom[s]; ++y) for (U x = v.left[s]; x <= v.right[s]; ++x)
                occupants[cursor[v.cellDense[(y << 5) + x] - 1]++] = U(s);
        }
    } else for (U cell = 0; cell < cellsTotal; ++cell) {
        U node = f.cells[cell];
        if (!node) continue;
        ids.push_back(cell); v.cellDense[cell] = U(ids.size());
        for (; node; node = Get<U>(P(node), 20)) { // native chain order, newest insertion first
            const U owner = Get<U>(P(node), 12);
            const auto at = std::find(slots.begin(), slots.end(), owner);
            Require(at != slots.end(), "view builder resolves every chain owner to a slot");
            occupants.push_back(U(at - slots.begin()));
        }
        offsets.push_back(U(occupants.size()));
    }
    Size(v.cellIds, ids.size()); Size(v.offsets, ids.size()); Size(v.occupants, occupants.size());
    std::copy(ids.begin(), ids.end(), v.cellIds.begin());
    std::copy(offsets.begin(), offsets.end(), v.offsets.begin());
    std::copy(occupants.begin(), occupants.end(), v.occupants.begin());
    ntw2_loco::GridView& g = v.view; g = ntw2_loco::GridView{};
    g.generation = 1; g.epoch = 1; g.count = U(count); g.cells = U(ids.size()); g.memberships = memberships;
    g.record = v.record.data(); g.serial = v.serial.data(); g.incarnation = v.incarnation.data();
    g.team = v.team.data(); g.flags = v.flags.data(); g.x = v.x.data(); g.z = v.z.data(); g.y = v.y.data();
    g.extent = v.extent.data(); g.radius = v.radius.data();
    g.left = v.left.data(); g.right = v.right.data(); g.top = v.top.data(); g.bottom = v.bottom.data();
    g.inserted = v.inserted.data(); g.cell_ids = v.cellIds.data(); g.offsets = v.offsets.data();
    g.occupants = v.occupants.data(); g.active = v.active.data();
    g.manager = A(f.manager.data()); g.model = A(f.model.data()); g.tick = tick;
    g.primary_count = U(f.registry.size()); g.secondary_count = U(f.secondary.size());
    g.primary_registry = A(f.registry.data()); g.secondary_registry = f.secondary.empty() ? 0 : A(f.secondary.data());
    g.grid = A(f.grid.data()); g.native_cells = A(f.cells.data()); g.cell_count = U(cellsTotal);
    g.row_shift = 5; g.origin = 16; g.maximum = 31; g.inverse_scale = 0.25f;
    g.cell_dense = v.cellDense.data(); g.node_type = v.nodeType.data();
}
template<class T> static uint64_t Mix(uint64_t h, const std::vector<T>& v) {
    const B* p = reinterpret_cast<const B*>(v.data());
    for (size_t i = 0; i < v.size() * sizeof(T); ++i) h = (h ^ p[i]) * 1099511628211ull;
    return h;
}
static uint64_t Hash(const OwnedView& v) {
    uint64_t h = 1469598103934665603ull;
    h = Mix(h, v.record); h = Mix(h, v.serial); h = Mix(h, v.incarnation); h = Mix(h, v.team);
    h = Mix(h, v.flags); h = Mix(h, v.active); h = Mix(h, v.left); h = Mix(h, v.right);
    h = Mix(h, v.top); h = Mix(h, v.bottom); h = Mix(h, v.inserted); h = Mix(h, v.nodeType);
    h = Mix(h, v.cellIds); h = Mix(h, v.offsets); h = Mix(h, v.occupants); h = Mix(h, v.cellDense);
    h = Mix(h, v.x); h = Mix(h, v.z); h = Mix(h, v.y); h = Mix(h, v.extent); h = Mix(h, v.radius);
    const B* g = reinterpret_cast<const B*>(&v.view);
    for (size_t i = 0; i < sizeof(v.view); ++i) h = (h ^ g[i]) * 1099511628211ull;
    return h;
}
struct OwnedCase {
    const char* name;
    Spec spec;
    std::function<void(Fixture&)> prepare;   // legitimate world setup, before the view is published
    std::function<void(Fixture&)> mutate;    // live change AFTER publication (applied to every engine)
    std::function<void(OwnedView&)> corrupt; // damage to the publication itself
    bool nullView = false, refuse = false;
    bool loose = false;      // high serials: compare by serial->record mapping, not event-as-index
    bool skipCounts = false; // mutated worlds no longer match the spec-derived counter expectations
};
struct Sampled {
    U before[ntw2_collide::WordCount], after[ntw2_collide::WordCount];
    U sourceBefore[ntw2_collide::SourceWordCount], sourceAfter[ntw2_collide::SourceWordCount];
};
static void ExecuteSampled(Fixture& f, Sampled& s) {
    ActivateFixture(f);
    ntw2_collide::Sample(s.before); ntw2_collide::SampleSource(s.sourceBefore);
    Execute(f, false);
    ntw2_collide::Sample(s.after); ntw2_collide::SampleSource(s.sourceAfter);
}
static void CompareExact(const Fixture& a, const Fixture& b, const char* what) {
    Require(a.calls.size() == b.calls.size(), what);
    for (size_t i = 0; i < a.calls.size(); ++i) {
        const Event& x = a.calls[i]; const Event& y = b.calls[i];
        Require(x.receiver == y.receiver && x.argument == y.argument && x.receiverState == y.receiverState &&
            x.argumentState == y.argumentState && x.receiverDone == y.receiverDone && x.argumentDone == y.argumentDone, what);
    }
    Require(a.records.size() == b.records.size(), what);
    for (size_t i = 0; i < a.records.size(); ++i)
        Require(!std::memcmp(a.records[i].bytes + 0x30, b.records[i].bytes + 0x30, 0x78) &&
            Get<U>(a.records[i].bytes, 0x13c) == Get<U>(b.records[i].bytes, 0x13c), what);
    Require(a.Order() == b.Order() && Get<U>(a.manager.data(), 0x260) == Get<U>(b.manager.data(), 0x260) &&
        Get<B>(a.manager.data(), 0x268) == Get<B>(b.manager.data(), 0x268), what);
}
static U IndexOf(const Fixture& f, U serial) {
    for (U i = 0; i < f.records.size(); ++i) if (Get<U>(f.records[i].bytes, 0x2c) == serial) return i;
    Fail("event serial %u has no fixture record", serial);
}
static std::vector<Pair> PairsByRecord(const Fixture& f) {
    std::vector<Pair> result;
    for (const Event& e : f.calls) {
        const U a = IndexOf(f, e.receiver), b = IndexOf(f, e.argument);
        result.push_back({std::min(a, b), std::max(a, b)});
    }
    std::sort(result.begin(), result.end());
    Require(std::adjacent_find(result.begin(), result.end()) == result.end(), "each unordered pair is applied once");
    return result;
}
static void CompareLoose(const Fixture& ref, const Fixture& own) {
    Require(PairsByRecord(ref) == PairsByRecord(own), "high-serial owned pair set equals the original image");
    for (U i = 0; i < ref.records.size(); ++i) {
        const B* a = ref.records[i].bytes; const B* b = own.records[i].bytes;
        Require(Get<B>(a, 0x40) == Get<B>(b, 0x40), "processed byte");
        Require(Get<U>(a, 0x80) == Get<U>(b, 0x80) && Get<U>(a, 0x84) == Get<U>(b, 0x84) &&
            Get<U>(a, 0x88) == Get<U>(b, 0x88) && Get<U>(a, 0x13c) == Get<U>(b, 0x13c),
            "high-serial velocity, label and callback witness state");
    }
}
static Spec Three(bool reverse) {
    Spec s; s.input.resize(3); s.reverseInsertion = reverse;
    for (Input& in : s.input) { in.radius = 0.5f; in.z = 2.0f; }
    s.input[0].x = 1.5f; s.input[1].x = 1.875f; s.input[2].x = 2.375f;
    return s;
}
static Spec SecondaryWorld() {
    Spec s; s.input.resize(5); s.primaryCount = 4; s.reverseInsertion = true; s.secondaryRegistry = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = i == 4 ? 2.25f : 1.5f + float(i / 2) * 16.0f + float(i % 2) * 0.375f;
        s.input[i].z = 2.0f; s.input[i].radius = 0.5f; s.input[i].flags = 0x21;
        s.input[i].vx = i % 2 ? -1.0f : 2.0f; s.input[i].label = 20 - i;
    }
    s.input[4].weight = 1; s.expectedContacts = 4;
    return s;
}
static std::array<float, 256> ownedScalesA, ownedScalesB;
static std::array<U, 7> ownedShapeA, ownedShapeB;
static std::vector<OwnedCase> OwnedSpecs() {
    std::vector<OwnedCase> v;
    auto add = [&v](const char* name, Spec s) -> OwnedCase& { v.push_back(OwnedCase{name, std::move(s)}); return v.back(); };
    Spec s = Two(); s.expectedContacts = 1; add("owned same team overlap", s);
    s.reverseInsertion = true; add("owned reverse insertion", s);
    s = Two(); s.order = {1, 0}; add("owned reverse worklist", s);
    s = Two(); s.input[0].team = 0; s.input[0].flags = s.input[1].flags = 5; s.expectedContacts = 1;
    add("owned null team bit four path", s);
    s = Two(); s.input[0].flags = s.input[1].flags = 2; s.input[1].team = 2; s.input[0].bump = 1; s.input[1].x = 2.125f;
    add("owned different team bump", s);
    for (U weight = 0; weight < 3; ++weight) for (U toward = 0; toward < 3; ++toward) {
        s = Two(); s.input[0].flags = s.input[1].flags = 0x21; s.input[1].weight = B(weight);
        s.input[0].mass = 2; s.input[0].inverse = 0.5f; s.input[1].mass = 3; s.input[1].inverse = 1.0f / 3.0f;
        s.input[0].vx = toward == 0 ? 4.0f : -2.0f; s.input[1].vx = toward == 1 ? -5.0f : 2.0f;
        s.input[0].vz = 0.5f; s.input[1].vz = -0.25f;
        add("owned live velocity exchange and unsigned labels", s);
    }
    for (U i = 0; i < 256; ++i) {
        ownedScalesA[i] = 0.125f + float(i % 17) / 16.0f; ownedScalesB[i] = 0.25f + float((255 - i) % 13) / 16.0f;
    }
    ownedShapeA[6] = A(ownedScalesA.data()); ownedShapeB[6] = A(ownedScalesB.data());
    for (U mask = 1; mask < 4; ++mask) for (U heading : {0u, 255u, 32768u, 65535u}) {
        s = Two(); s.input[0].shape = mask & 1 ? A(ownedShapeA.data()) : 0; s.input[1].shape = mask & 2 ? A(ownedShapeB.data()) : 0;
        s.input[0].heading = uint16_t(heading); s.input[1].heading = uint16_t(65535 - heading); s.expectedShapedPairs = 1;
        add("owned oriented radius leaf on borrowed neighbors", s);
    }
    // Absence: inserted==0 slots have node_type 0 and appear in no cell; records may also be inactive.
    s = Two(); s.input[1].inserted = false; s.expectedContacts = 0; add("owned absent neighbor", s);
    s = Two(); s.input[0].inserted = false; s.expectedContacts = 0; add("owned absent querying record", s);
    add("owned absent query never reads unspecified borrowed bounds",s).corrupt = [](OwnedView& w) {
        w.left[0]=w.right[0]=w.top[0]=w.bottom[0]=0xffffffffu;
    };
    s = Three(false); s.input[1].inserted = false; add("owned absent middle record", s);
    s = Three(true); s.input[1].active = 0; add("owned inactive middle record", s);
    s = Three(false); for (Input& in : s.input) in.inserted = false; add("owned every record absent", s);
    // Controlled multi-callback order and final-state callbacks.
    s = Spec{}; s.input.resize(8); s.expectedContacts = 4;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = float(i / 2) * 12.0f + float(i % 2) * 0.75f; s.input[i].flags = 0x21;
        s.input[i].vx = i % 2 ? -1.0f : 2.0f; s.input[i].label = 20 - i;
    }
    add("owned controlled multi-callback order and state", s);
    s = Spec{}; s.input.resize(3); s.reverseInsertion = true; s.expectedContacts = 2;
    s.expectFinalObservation = true; s.expectFinalOwnerObservation = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = 1.5f + float(i) * 0.75f; s.input[i].z = 2.0f; s.input[i].radius = 0.5f;
        s.input[i].flags = 0x21; s.input[i].label = i == 2 ? 9 : i + 1;
    }
    s.input[0].vx = 4.0f;
    add("owned final callback owner state keeps ordered label propagation", s);
    // Once-only orientation: every worklist permutation, initial processed mask and insertion order.
    for (bool reverse : {false, true}) {
        std::array<U, 3> perm{0, 1, 2};
        do {
            for (U mask = 0; mask < 8; ++mask) {
                s = Three(reverse); s.order.assign(perm.begin(), perm.end());
                for (U i = 0; i < 3; ++i) s.input[i].processed = B((mask >> i) & 1);
                add("owned once-only orientation over permutations and processed masks", s);
            }
        } while (std::next_permutation(perm.begin(), perm.end()));
    }
    for (bool reverse : {false, true}) {
        s = Spec{}; s.input.resize(192); s.reverseInsertion = reverse; s.checkCellHistogram = true;
        for (U i = 0; i < s.input.size(); ++i) {
            s.input[i].x = float(i % 16) * 0.3f; s.input[i].z = float(i / 16) * 0.35f;
            s.input[i].radius = 0.8f + float(i % 3) * 0.1f; s.input[i].mass = float(1 + i % 4);
            s.input[i].inverse = 1.0f / s.input[i].mass; s.input[i].label = i + 1;
        }
        add("owned dense multicell enumeration, dedup and callback order", s);
    }
    // Rebuild: BFS ranks consume every first-seen borrowed neighbor, including rejected ones.
    s = Spec{}; s.input.resize(12); s.controlled = false; s.breadthFirst = true;
    for (U i = 0; i < s.input.size(); ++i) {
        s.input[i].x = float(i / 4) * 16.0f + float(i % 4) * 0.8f; s.input[i].radius = 0.25f;
        s.order.push_back(U(s.input.size()) - 1 - i);
    }
    s.expectedContacts = 0; s.rebuild = 1; add("owned requested rebuild includes rejected neighbors", s);
    s.rebuild = 0; s.tick = 100; add("owned modulo 100 rebuild visibility BFS", s);
    s.rebuild = 1; s.tick = 101; s.expectedContacts = 0xffffffffu; for (Input& in : s.input) in.radius = 1.0f;
    add("owned contact cluster rebuild", s);
    // Secondary registry slots append after primary slots (and after a null primary hole).
    add("owned secondary-registered destination slot", SecondaryWorld());
    add("owned secondary slot after null primary hole", SecondaryWorld()).prepare = [](Fixture& f) {
        f.registry.push_back(0);
        Put(f.manager.data(), 0x24c, U(f.registry.size())); Put(f.manager.data(), 0x250, A(f.registry.data()));
    };
    for (B rebuild : {B(0), B(1)}) {
        OwnedCase& c = add("owned high-serial secondary record", SecondaryWorld());
        c.spec.rebuild = rebuild; c.loose = true; c.skipCounts = true; // serial 0x12345 is not a record index
        c.prepare = [](Fixture& f) {
            const U serial = 0x12345;
            Put(f.records[4].bytes, 0x2c, serial);
            for (Node& node : f.nodes[4]) node.serial = serial;
        };
    }
    // Eligibility and numerics are captured live: changes after publication must not be frozen.
    auto live = [&add](const char* name, std::function<void(Fixture&)> mutate) {
        OwnedCase& c = add(name, Three(true)); c.mutate = std::move(mutate); c.skipCounts = true;
        c.spec.expectedContacts = 0xffffffffu;
    };
    live("owned live inactive record is not frozen", [](Fixture& f) { Put(f.records[1].bytes, 0x30, B(0)); });
    live("owned live cleared flags are not frozen", [](Fixture& f) { Put(f.records[2].bytes, 0x38, U(0)); });
    live("owned live processed byte is not frozen", [](Fixture& f) { Put(f.records[0].bytes, 0x40, B(1)); });
    live("owned live team change is not frozen", [](Fixture& f) {
        Put(f.records[0].bytes, 0x38, U(3)); Put(f.records[1].bytes, 0x38, U(3)); Put(f.records[1].bytes, 0x44, U(2));
    });
    live("owned live exclusion is not frozen", [](Fixture& f) { Put(f.records[0].bytes, 0x3c, U(1)); });
    live("owned live mass velocity and label are not frozen", [](Fixture& f) {
        for (Record& r : f.records) Put(r.bytes, 0x38, U(0x21));
        Put(f.records[0].bytes, 0x68, 2.0f); Put(f.records[0].bytes, 0x6c, 0.5f);
        Put(f.records[0].bytes, 0x80, 4.0f); Put(f.records[0].bytes, 0x88, U(9));
    });
    // A publication from an earlier (or later) tick is accepted while every record still matches.
    add("owned accepts publication tick gap", Three(false)).corrupt = [](OwnedView& w) { w.view.tick = 0; };
    add("owned accepts later publication tick", Three(true)).corrupt = [](OwnedView& w) { w.view.tick = 1000; };
    // Refusals: stale or missing publications run the untouched original before any write.
    auto refuse = [&add](const char* name) -> OwnedCase& {
        OwnedCase& c = add(name, Three(false)); c.refuse = true; c.spec.expectedContacts = 0xffffffffu; return c;
    };
    refuse("owned missing view refuses").nullView = true;
    refuse("owned changed live serial refuses").mutate = [](Fixture& f) { Put(f.records[1].bytes, 0x2c, U(77)); };
    refuse("owned changed inserted count refuses").mutate = [](Fixture& f) { Put(f.records[2].bytes, 0xac, U(0)); };
    refuse("owned moved record geometry refuses").mutate = [](Fixture& f) { Put(f.records[1].bytes, 0x48, 10.875f); };
    refuse("owned swapped registry slots refuse").mutate = [](Fixture& f) { std::swap(f.registry[0], f.registry[1]); };
    refuse("owned changed grid origin refuses").mutate = [](Fixture& f) { Put(f.grid.data(), 0x10, U(17)); };
    refuse("owned changed grid maximum refuses").mutate = [](Fixture& f) { Put(f.grid.data(), 0x14, U(30)); };
    refuse("owned changed row shift refuses").mutate = [](Fixture& f) { Put(f.grid.data(), 8, U(6)); };
    refuse("owned changed own-node header refuses").mutate = [](Fixture& f) { f.nodes[1][0].type = 16; };
    refuse("owned changed live x bits refuse").mutate = [](Fixture& f) { Put(f.records[1].bytes, 0x48, std::nextafter(1.875f, 2.0f)); };
    refuse("owned changed live y bits refuse").mutate = [](Fixture& f) { Put(f.records[0].bytes, 0x4c, 0.25f); };
    refuse("owned changed live z bits refuse").mutate = [](Fixture& f) { Put(f.records[2].bytes, 0x50, std::nextafter(2.0f, 3.0f)); };
    refuse("owned changed live extent bits refuse").mutate = [](Fixture& f) { Put(f.records[2].bytes, 0x54, 0.0f); };
    refuse("owned changed live radius bits refuse").mutate = [](Fixture& f) { Put(f.records[1].bytes, 0x58, std::nextafter(0.5f, 1.0f)); };
    {
        OwnedCase& c = add("owned changed secondary registry count refuses", SecondaryWorld());
        c.refuse = true; c.spec.expectedContacts = 0xffffffffu;
        c.mutate = [](Fixture& f) { Put(f.manager.data(), 0x278, U(0)); };
    }
    refuse("owned published node type refuses").corrupt = [](OwnedView& w) { w.nodeType[1] = 0; };
    refuse("owned published bounds refuse").corrupt = [](OwnedView& w) { ++w.left[2]; };
    refuse("owned published inclusive right bound refuses").corrupt = [](OwnedView& w) { ++w.right[2]; };
    refuse("owned published inclusive bottom bound refuses").corrupt = [](OwnedView& w) { ++w.bottom[2]; };
    refuse("owned empty published cell refuses").corrupt = [](OwnedView& w) { w.cellDense[w.cellIds[0]] = 0; };
    refuse("owned out-of-range occupant refuses").corrupt = [](OwnedView& w) { w.occupants[0] = 100; };
    refuse("owned published count mismatch refuses").corrupt = [](OwnedView& w) { ++w.view.count; };
    refuse("owned published memberships mismatch refuses").corrupt = [](OwnedView& w) { ++w.view.memberships; };
    refuse("owned foreign manager publication refuses").corrupt = [](OwnedView& w) { w.view.manager ^= 4; };
    refuse("owned published slot identity refuses").corrupt = [](OwnedView& w) { w.record[1] = w.record[2]; };
    refuse("owned missing node type array refuses").corrupt = [](OwnedView& w) { w.view.node_type = nullptr; };
    refuse("owned missing x geometry refuses").corrupt = [](OwnedView& w) { w.view.x = nullptr; };
    refuse("owned missing y geometry refuses").corrupt = [](OwnedView& w) { w.view.y = nullptr; };
    refuse("owned missing z geometry refuses").corrupt = [](OwnedView& w) { w.view.z = nullptr; };
    refuse("owned missing extent geometry refuses").corrupt = [](OwnedView& w) { w.view.extent = nullptr; };
    refuse("owned missing radius geometry refuses").corrupt = [](OwnedView& w) { w.view.radius = nullptr; };
    refuse("owned undersized published cell array refuses").corrupt = [](OwnedView& w) { w.view.cell_count = 1; };
    refuse("owned changed published scale refuses").corrupt = [](OwnedView& w) { w.view.inverse_scale = 0.5f; };
    return v;
}
static void OwnedCases(U workers) {
    std::vector<OwnedCase> worlds = OwnedSpecs();
    const size_t n = worlds.size();
    std::vector<std::unique_ptr<Fixture>> audited(n);
    std::vector<Sampled> auditedSample(n);
    U accepted = 0, refused = 0;
    // Phase 1: native-audit solver (no read_grid) is the same-world baseline.
    ntw2_collide::Stop(); Require(ntw2_collide::Start(Binding(workers)), "native-audit solver starts");
    for (size_t k = 0; k < n; ++k) {
        const OwnedCase& c = worlds[k]; currentCase = c.name;
        if (c.refuse) continue;
        audited[k] = std::make_unique<Fixture>(c.spec);
        if (c.prepare) c.prepare(*audited[k]);
        if (c.mutate) c.mutate(*audited[k]);
        ExecuteSampled(*audited[k], auditedSample[k]);
        const Sampled& m = auditedSample[k];
        Require(m.after[ntw2_collide::SolverTicks] == m.before[ntw2_collide::SolverTicks] + 1 &&
            m.after[ntw2_collide::FallbackTicks] == m.before[ntw2_collide::FallbackTicks], "baseline is a native-audit solver stage");
        Require(m.sourceAfter[ntw2_collide::Source] == ntw2_collide::SourceNativeAudit &&
            m.sourceAfter[ntw2_collide::NativeStages] == m.sourceBefore[ntw2_collide::NativeStages] + 1 &&
            m.sourceAfter[ntw2_collide::OwnedStages] == 0 && m.sourceAfter[ntw2_collide::OwnedRefusals] == 0,
            "native-audit stages report native-audit source telemetry only");
        ++accepted;
    }
    U sourceWords[ntw2_collide::SourceWordCount];
    // Phase 2: owned-view solver on the identical worlds, with the original image as the oracle.
    ntw2_collide::Stop();
    ntw2_collide::Binding owned = Binding(workers); owned.read_grid = &ReadView;
    Require(ntw2_collide::Start(owned), "owned-view solver starts");
    ntw2_collide::SampleSource(sourceWords);
    for (U word : sourceWords) Require(word == 0, "restart resets source telemetry");
    U expectedOwned = 0, expectedRefusals = 0;
    for (size_t k = 0; k < n; ++k) {
        const OwnedCase& c = worlds[k]; currentCase = c.name;
        Fixture ref(c.spec), own(c.spec);
        if (c.prepare) { c.prepare(ref); c.prepare(own); }
        auto view = std::make_unique<OwnedView>();
        BuildView(own, c.spec.tick ? c.spec.tick - 1 : 0, *view);
        if (c.corrupt) c.corrupt(*view);
        if (c.mutate) { c.mutate(ref); c.mutate(own); }
        Execute(ref, true);
        gView = c.nullView ? nullptr : &view->view;
        const uint64_t hash = Hash(*view);
        Sampled s; ExecuteSampled(own, s);
        gView = nullptr;
        Require(Hash(*view) == hash, "the borrowed publication is never mutated");
        Require(s.after[ntw2_collide::Calls] == s.before[ntw2_collide::Calls] + 1, "one routed stage counter");
        Require(s.after[ntw2_collide::Faults] == s.before[ntw2_collide::Faults] &&
            s.after[ntw2_collide::StickyFallbacks] == s.before[ntw2_collide::StickyFallbacks], "owned stage has no faults");
        if (c.refuse) {
            Require(s.after[ntw2_collide::SolverTicks] == s.before[ntw2_collide::SolverTicks], "refused view runs no solver stage");
            Require(s.after[ntw2_collide::FallbackTicks] == s.before[ntw2_collide::FallbackTicks] + 1 &&
                s.after[ntw2_collide::LayoutFallbacks] == s.before[ntw2_collide::LayoutFallbacks] + 1,
                "stale or missing view is a layout refusal to the original stage");
            Require(s.after[ntw2_collide::NativeQueries] == s.before[ntw2_collide::NativeQueries], "refusal is not a native-local query");
            Require(s.sourceAfter[ntw2_collide::Source] == ntw2_collide::SourceNone &&
                s.sourceAfter[ntw2_collide::OwnedRefusals] == s.sourceBefore[ntw2_collide::OwnedRefusals] + 1 &&
                s.sourceAfter[ntw2_collide::OwnedStages] == s.sourceBefore[ntw2_collide::OwnedStages] &&
                s.sourceAfter[ntw2_collide::NativeStages] == 0, "refusal telemetry");
            // Refusal precedes the first write: bit-identical to the untouched original stage.
            CompareExact(ref, own, "refused owned stage equals the untouched original bit-for-bit");
            ++expectedRefusals; ++refused; ++cases;
            continue;
        }
        const Sampled& m = auditedSample[k];
        Require(s.after[ntw2_collide::SolverTicks] == s.before[ntw2_collide::SolverTicks] + 1 &&
            s.after[ntw2_collide::FallbackTicks] == s.before[ntw2_collide::FallbackTicks], "owned view is consumed, not refused");
        Require(s.sourceAfter[ntw2_collide::Source] == ntw2_collide::SourceOwned &&
            s.sourceAfter[ntw2_collide::OwnedStages] == s.sourceBefore[ntw2_collide::OwnedStages] + 1 &&
            s.sourceAfter[ntw2_collide::NativeStages] == 0 &&
            s.sourceAfter[ntw2_collide::OwnedRefusals] == s.sourceBefore[ntw2_collide::OwnedRefusals], "owned source telemetry");
        Require(s.after[ntw2_collide::NativeQueries] == s.before[ntw2_collide::NativeQueries] &&
            s.after[ntw2_collide::UnsupportedCells] == 0, "owned stage never needs native-local handling");
        // No chain audit or CSR binning on the owned path.
        Require(s.after[ntw2_collide::AuditUs] == 0 && s.after[ntw2_collide::AuditThreadUs] == 0 &&
            s.after[ntw2_collide::BinUs] == 0 && s.after[ntw2_collide::BinThreadUs] == 0, "owned stage neither audits nor bins");
        Require(PairSet(audited[k]->calls, "native-audit solver") == PairSet(own.calls, "owned-view solver"),
            "native-audited CSR and owned view select the same pair set");
        CompareExact(*audited[k], own, "owned and native-audit solvers agree bit-for-bit on same-order CSR");
        for (ntw2_collide::Word w : {ntw2_collide::Records, ntw2_collide::Cells, ntw2_collide::Pairs, ntw2_collide::Contacts,
                ntw2_collide::Callbacks, ntw2_collide::Rebuilds, ntw2_collide::Redistributions, ntw2_collide::LabelChanges,
                ntw2_collide::EligibleQueries, ntw2_collide::ShapedPairs})
            Require(s.after[w] - s.before[w] == m.after[w] - m.before[w], "owned and native-audit stage counters agree");
        if (c.loose) CompareLoose(ref, own);
        else {
            Compare(ref, own, c.spec, false);
            if (!c.skipCounts) CheckSolverCounts(own, c.spec, s.before, s.after);
        }
        ++expectedOwned; ++cases;
        // Production-style stable dense-slot CSR built from the published geometry. Occupant order
        // differs from chain order, so callback sequence and float sums are not asserted; the
        // unordered pair set, once-only processing and order-independent state must still agree.
        {
            Fixture dense(c.spec);
            if (c.prepare) c.prepare(dense);
            auto dview = std::make_unique<OwnedView>();
            BuildView(dense, c.spec.tick ? c.spec.tick - 1 : 0, *dview, true);
            if (c.corrupt) c.corrupt(*dview);
            if (c.mutate) c.mutate(dense);
            gView = &dview->view; const uint64_t dhash = Hash(*dview);
            Sampled d; ExecuteSampled(dense, d);
            gView = nullptr;
            Require(Hash(*dview) == dhash, "the dense borrowed publication is never mutated");
            Require(d.after[ntw2_collide::SolverTicks] == d.before[ntw2_collide::SolverTicks] + 1 &&
                d.after[ntw2_collide::FallbackTicks] == d.before[ntw2_collide::FallbackTicks], "dense view is consumed, not refused");
            Require(d.sourceAfter[ntw2_collide::Source] == ntw2_collide::SourceOwned &&
                d.sourceAfter[ntw2_collide::OwnedStages] == d.sourceBefore[ntw2_collide::OwnedStages] + 1 &&
                d.sourceAfter[ntw2_collide::OwnedRefusals] == d.sourceBefore[ntw2_collide::OwnedRefusals], "dense owned source telemetry");
            Require(d.after[ntw2_collide::NativeQueries] == d.before[ntw2_collide::NativeQueries] &&
                d.after[ntw2_collide::AuditUs] == 0 && d.after[ntw2_collide::BinUs] == 0, "dense owned stage neither audits, bins nor queries natively");
            const auto pairs = PairSet(dense.calls, "owned dense CSR");
            Require(pairs == PairSet(audited[k]->calls, "native-audit solver"), "dense-slot CSR and native-audited CSR select the same unordered pair set");
            Require(pairs == PairSet(ref.calls, "original image"), "dense-slot CSR selects the original image's unordered pair set");
            Require(dense.calls.size() == pairs.size() && d.after[ntw2_collide::Contacts] - d.before[ntw2_collide::Contacts] == pairs.size() &&
                d.after[ntw2_collide::Callbacks] - d.before[ntw2_collide::Callbacks] == pairs.size(), "dense order processes each pair exactly once");
            for (ntw2_collide::Word w : {ntw2_collide::Records, ntw2_collide::Cells, ntw2_collide::Pairs, ntw2_collide::Contacts,
                    ntw2_collide::Callbacks, ntw2_collide::Rebuilds, ntw2_collide::EligibleQueries, ntw2_collide::ShapedPairs})
                Require(d.after[w] - d.before[w] == m.after[w] - m.before[w], "dense and native-audit order-independent counters agree");
            for (U i = 0; i < dense.records.size(); ++i)
                Require(Get<B>(dense.records[i].bytes, 0x40) == Get<B>(audited[k]->records[i].bytes, 0x40) &&
                    Get<U>(dense.records[i].bytes, 0x13c) == Get<U>(audited[k]->records[i].bytes, 0x13c),
                    "dense order leaves processed bytes and callback witness counts unchanged");
            std::vector<U> order = dense.Order(), expectedOrder = audited[k]->Order();
            const bool rebuildStage = c.spec.rebuild == 1 || c.spec.tick % 100 == 0;
            if (!rebuildStage) Require(order == expectedOrder, "reuse worklist order is independent of CSR order");
            std::sort(order.begin(), order.end()); std::sort(expectedOrder.begin(), expectedOrder.end());
            Require(order == expectedOrder, "dense rebuild keeps worklist membership");
            if (c.spec.breadthFirst) CheckBfs(dense);
            ++expectedOwned; ++cases;
        }
    }
    ntw2_collide::SampleSource(sourceWords);
    Require(sourceWords[ntw2_collide::OwnedStages] == expectedOwned && sourceWords[ntw2_collide::OwnedRefusals] == expectedRefusals &&
        sourceWords[ntw2_collide::NativeStages] == 0, "cumulative source telemetry");
    Require(2 * accepted == expectedOwned && refused == expectedRefusals, "every accepted case ran in baseline, chain-order and dense-order configurations");
    // Workers must be idle across a Stop/Start cycle with no view published yet: untouched fallback.
    currentCase = "owned first stage before any publication";
    ntw2_collide::Stop(); Require(ntw2_collide::Start(owned), "owned solver restarts without a publication");
    ntw2_collide::SampleSource(sourceWords);
    for (U word : sourceWords) Require(word == 0, "restart resets source telemetry again");
    Spec first = Two(); first.expectedContacts = 1;
    Fixture ref(first), own(first); Execute(ref, true); gView = nullptr;
    Sampled s; ExecuteSampled(own, s);
    Require(s.after[ntw2_collide::FallbackTicks] == 1 && s.after[ntw2_collide::SolverTicks] == 0 &&
        s.sourceAfter[ntw2_collide::OwnedRefusals] == 1, "missing first publication falls back untouched");
    CompareExact(ref, own, "missing first publication equals the original stage");
    ++cases;
}
static void CapacityCases(U workers) {
    currentCase = "activation storage is workload bounded and owned mode allocates no audit storage";
    Spec pair = Two(); Fixture sizing(pair);
    const ntw2_workload::Capacity small{4,4,1024,64,12};
    auto owned = Binding(workers); owned.read_grid = &ReadView;
    Require(ntw2_collide::Start(owned), "bind owned solver without workload storage");
    Require(ntw2_collide::StorageBytes() == 0, "Start reserves no workload address space");
    const U smallEstimate = ntw2_collide::EstimateActivationBytes(small);
    const ntw2_workload::Capacity replayCapacity{48128,74752,1048576,160256,770048};
    Require(ntw2_collide::EstimateActivationBytes(replayCapacity) <= 13 * 1024 * 1024,
        "candidate-free replay-sized collision reservation stays below thirteen MiB");
    auto invalid = small; invalid.records = 3;
    Require(ntw2_collide::EstimateActivationBytes(invalid) == 0xffffffffu, "invalid capacity estimate fails closed");
    invalid = small; invalid.pairs = 0xffffffffu;
    Require(ntw2_collide::EstimateActivationBytes(invalid) == 0xffffffffu, "overflowing capacity estimate fails closed");
    Require(ntw2_collide::StorageBytes() == 0, "estimates neither reserve nor retain workload storage");
    Require(ntw2_collide::Activate(sizing.manager.data(),small), "activate small owned workload");
    const U ownedBytes = ntw2_collide::StorageBytes();
    Require(ownedBytes == smallEstimate, "planned and actual owned reservation agree exactly");
    Require(ownedBytes > 0 && ownedBytes <= 65536, "small owned workload uses one reservation granule");
    auto larger = small; larger.cells = 1048576;
    Require(ntw2_collide::Activate(sizing.manager.data(),larger), "activate wider borrowed grid");
    Require(ntw2_collide::StorageBytes() == ownedBytes, "owned collision reserves no native cell audit tables");
    larger = small; larger.memberships += 65536;
    Require(ntw2_collide::Activate(sizing.manager.data(),larger), "activate larger cell-order geometry cache");
    Require(ntw2_collide::StorageBytes() == ownedBytes + 12 * 65536,
        "owned memberships allocate only xyz-radius SoA, not chains or radix entries");
    larger = small; larger.records += 65536;
    Require(ntw2_collide::EstimateActivationBytes(larger) < 7 * 1024 * 1024,
        "secondary slots do not duplicate borrowed geometry or primary query metadata");
    Require(ntw2_collide::Activate(sizing.manager.data(),larger), "activate secondary-heavy owned capacity");
    Require(ntw2_collide::StorageBytes() == ntw2_collide::EstimateActivationBytes(larger),
        "secondary-heavy estimate matches actual allocation");
    const ntw2_workload::Capacity candidateBudget{4096,4096,1024,64,4096};
    larger = candidateBudget; larger.pairs = 65536; // Same contact capacity: 4096 in both.
    Require(ntw2_collide::EstimateActivationBytes(larger) == ntw2_collide::EstimateActivationBytes(candidateBudget),
        "candidate capacity allocates no candidate array at all");
    const ntw2_workload::Capacity maximum{131072,131072,1048576,2097152,4194304};
    Require(ntw2_collide::EstimateActivationBytes(maximum) != 0xffffffffu,
        "maximum supported contact capacity remains below the packet-link sentinel");
    auto otherLanes = owned; otherLanes.workers = workers == 8 ? 1 : 8;
    Require(ntw2_collide::Start(otherLanes) && ntw2_collide::Activate(sizing.manager.data(),small),
        "activate another owned lane count");
    Require(ntw2_collide::StorageBytes() == ownedBytes, "owned canonical-cell dedup allocates no lane stamp tables");
    Require(ntw2_collide::Start(Binding(workers)) && ntw2_collide::Activate(sizing.manager.data(),small),
        "activate native audit separately");
    const U auditBytes = ntw2_collide::StorageBytes();
    Require(auditBytes > ownedBytes && auditBytes < 1024 * 1024, "native audit storage is explicit and workload bounded");
    larger = small; larger.cells = 1048576;
    Require(ntw2_collide::Activate(sizing.manager.data(),larger), "activate wide native audit");
    Require(ntw2_collide::StorageBytes() > auditBytes, "only audit mode owns native cell address tables");
    ntw2_collide::Stop();
    Require(ntw2_collide::StorageBytes() == 0, "Stop releases actual reservation and accounting");

    for (bool borrowed : {false,true}) {
        auto bind = Binding(workers); if (borrowed) bind.read_grid = &ReadView;
        auto run = [&](const char* name, Spec spec, ntw2_workload::Capacity cap, bool refuse) {
            currentCase = name;
            Fixture ref(spec), own(spec);
            OwnedView view; if (borrowed) BuildView(own,spec.tick,view);
            gView = borrowed ? &view.view : nullptr;
            Require(ntw2_collide::Start(bind), "bind capacity regression");
            Require(ntw2_collide::StorageBytes() == 0, "binding has no hidden allocation");
            U estimate = ntw2_collide::EstimateActivationBytes(cap);
            Require(ntw2_collide::StorageBytes() == 0, "capacity estimate is allocation-free in either mode");
            Require(ntw2_collide::Activate(own.manager.data(),cap), "activate fixed capacity regression");
            U bytes = ntw2_collide::StorageBytes();
            Require(bytes == estimate, "estimate matches actual owned or audit reservation");
            const uint64_t viewHash = borrowed ? Hash(view) : 0;
            Execute(ref,true); Execute(own,false);
            if (borrowed) Require(Hash(view) == viewHash, "borrowed geometry and inclusive bounds remain read-only");
            U words[ntw2_collide::WordCount]; ntw2_collide::Sample(words);
            Require(ntw2_collide::StorageBytes() == bytes, "stage never grows or replaces activation storage");
            Require(words[ntw2_collide::Faults] == 0, "capacity boundary is a clean refusal, never an access fault");
            if (refuse) {
                Require(words[ntw2_collide::CapacityFallbacks] == 1 && words[ntw2_collide::SolverTicks] == 0 &&
                    words[ntw2_collide::Callbacks] == 0, "capacity failure precedes all solver writes and callbacks");
                CompareExact(ref,own,"capacity refusal runs the complete original with bit-identical observations");
            } else {
                Require(words[ntw2_collide::SolverTicks] == 1 && words[ntw2_collide::FallbackTicks] == 0,
                    "exact capacity boundary is admitted");
                Require(words[ntw2_collide::NativeQueries] == spec.expectedNativeQueries,
                    "streaming retains exactly the requested native-local query set");
                Compare(ref,own,spec,false);
            }
            gView = nullptr; ++cases;
        };
        Spec four; four.input.resize(4); four.expectedContacts = 4;
        const float xs[]{1.5f,1.875f,2.375f,3.125f};
        for (U i = 0; i < 4; ++i) {
            four.input[i].x = xs[i]; four.input[i].z = 2.0f; four.input[i].radius = 0.5f;
        }
        run("exact compact contact and candidate boundary",four,small,false);
        auto cap = small; cap.pairs = 11;
        run("candidate capacity refuses before writes",four,cap,true);
        Spec five = four; five.input[3].x = 2.75f; five.expectedContacts = 5;
        run("contact capacity plus one refuses before writes",five,small,true);
        Spec rejected = four; rejected.expectedContacts = 0;
        for (Input& in : rejected.input) in.radius = 0.01f;
        run("rejected candidates consume no contact packets",rejected,small,false);
        for (B rebuild : {B(1),B(0)}) {
            Spec ordered = four; ordered.rebuild = rebuild; ordered.reverseInsertion = true;
            ordered.order = {3,2,1,0};
            for (U i = 0; i < 4; ++i) {
                ordered.input[i].team = 1 + i % 2; ordered.input[i].flags = 3;
                ordered.input[i].vx = i % 2 ? -1.0f : 2.0f;
            }
            run("streamed contact links preserve low flag bits and native callback order",ordered,small,false);
            ordered = rejected; ordered.rebuild = rebuild; ordered.order = {3,2,1,0};
            run("streaming rebuild keeps rejected-neighbor BFS order",ordered,small,false);
            ordered = four; ordered.rebuild = rebuild;
            cap = small; cap.pairs = 11;
            run("streamed candidate overflow never publishes a partial rebuild",ordered,cap,true);
            ordered = five; ordered.rebuild = rebuild;
            run("streamed contact overflow never publishes a partial rebuild",ordered,small,true);
        }
        if (!borrowed) {
            Spec mixed; mixed.input.resize(6); mixed.reverseInsertion = true; mixed.rebuild = 1;
            mixed.breadthFirst = true; mixed.expectedNativeQueries = 3;
            mixed.expectedContacts = 6; mixed.expectedSolverContacts = 3;
            for (U i = 0; i < 6; ++i) {
                mixed.input[i].x = 1.5f + float(i % 2) * 16.0f + float(i / 2) * 0.375f;
                mixed.input[i].z = 2.0f; mixed.input[i].radius = 0.5f;
                mixed.input[i].flags = 0x21; mixed.input[i].vx = i < 2 ? 2.0f : -1.0f;
                mixed.input[i].label = 20-i; mixed.order.push_back(5-i);
            }
            mixed.input[0].nodeType = 16;
            const ntw2_workload::Capacity mixedCapacity{6,6,1024,64,512};
            run("streaming mixed native-local BFS preserves raw-ID order",mixed,mixedCapacity,false);
            mixed.rebuild = 0; mixed.breadthFirst = false;
            // Reverse reuse queries record 0 last. Its type-16 destination nodes do not
            // emit +44 callbacks for the two earlier native queries; rebuild seeded 0 first.
            mixed.expectedContacts = 4;
            run("streaming mixed native-local reuse preserves owner query order",mixed,mixedCapacity,false);
            mixed.rebuild = 1; mixed.breadthFirst = true;
            mixed.expectedContacts = mixed.expectedSolverContacts = 0;
            for (Input& in : mixed.input) in.radius = 0.125f;
            run("streaming mixed rebuild preserves rejected native raw IDs",mixed,mixedCapacity,false);
        }
        cap = small; cap.primary = 3;
        run("primary capacity refuses before writes",four,cap,true);
        cap = small; cap.cells = 1023;
        run("addressable cell capacity refuses before writes",four,cap,true);
        cap = small; cap.memberships = 3;
        run("membership capacity refuses before writes",four,cap,true);
        run("secondary records do not fit primary-only record capacity",SecondaryWorld(),small,true);
        cap = small; cap.records = 5; cap.pairs = 32;
        run("secondary destination beyond primary metadata capacity remains supported",SecondaryWorld(),cap,false);
        // More than 64 records per participant: exercise every lane, not just pool creation.
        Spec parallel; parallel.input.resize(640); parallel.expectedContacts = 320;
        for (U i = 0; i < parallel.input.size(); ++i) {
            U pair = i / 2;
            parallel.input[i].x = -60.0f + float(pair % 32) * 4.0f + float(i % 2) * 0.125f;
            parallel.input[i].z = -56.0f + float(pair / 32) * 4.0f;
            parallel.input[i].radius = 0.25f;
        }
        const ntw2_workload::Capacity lanes{640,640,1024,2560,10240};
        run("compact contacts preserve order across every worker lane",parallel,lanes,false);
        parallel.rebuild = 1;
        run("owner rebuild then streamed contacts preserve every lane's order",parallel,lanes,false);
        parallel.rebuild = 0;
        for (U i = 0; i < parallel.input.size(); ++i) {
            U group = i / 4;
            parallel.input[i].x = -60.0f + float(group % 16) * 8.0f + float(i % 4) * 0.125f;
            parallel.input[i].z = -56.0f + float(group / 16) * 8.0f;
            parallel.input[i].radius = 0.5f;
        }
        parallel.expectedContacts = 960;
        run("concurrent contact overflow never commits a partial stage",parallel,lanes,true);
        parallel.rebuild = 1;
        run("concurrent streamed overflow leaves original rebuild untouched",parallel,lanes,true);
    }
    ntw2_collide::Stop();
}

int main(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: native_collision_solver_oracle Napoleon.exe\n"); return 2; }
    Map(argv[1]); ownerThread = GetCurrentThreadId(); vtable[0x44 / 4] = Fn(&Contact);
    for (U workers : {1u, 3u}) {
        StartPool(workers); Require(ntw2_collide::Start(Binding(workers)), "production solver arena starts");
        TwoRecordCases(); MultiRecordCases();
        U counters[ntw2_collide::WordCount]; ntw2_collide::Sample(counters);
        Require(counters[ntw2_collide::Contacts] > 0 && counters[ntw2_collide::Callbacks] > 0, "contact/callback coverage");
        Require(counters[ntw2_collide::Rebuilds] > 0 && counters[ntw2_collide::Redistributions] > 0, "rebuild/redistribution coverage");
        Require(counters[ntw2_collide::ShapedPairs] > 0, "real original shaped radius leaf coverage");
        Require(counters[ntw2_collide::Faults] == 0, "supported fixtures have no solver faults");
        FallbackCases(workers);
        ntw2_collide::Stop(); Require(ntw_pool_shutdown(&pool) == NTW_POOL_OK, "real pool drains");
    }
    // Contact-response wiring: the fixture recorder tables are foreign classes, so every planned
    // contact still runs the original callback; Run() compares callback order with the native stage.
    for (U mode : {U(ntw2_contact::ModeShadow), U(ntw2_contact::ModeWorkers)}) {
        currentCase = mode == ntw2_contact::ModeShadow ? "contact shadow wiring" : "contact workers wiring";
        StartPool(3); auto bind = Binding(3); bind.contact_mode = mode;
        Require(ntw2_collide::Start(bind), "contact-mode solver starts");
        TwoRecordCases(); MultiRecordCases(); PlanChunkCases();
        U counters[ntw2_collide::WordCount], contact[ntw2_contact::WordCount];
        ntw2_collide::Sample(counters); ntw2_contact::Sample(contact);
        Require(contact[ntw2_contact::ModeWord] == mode && contact[ntw2_contact::Stages] == counters[ntw2_collide::SolverTicks],
            "every solver stage opens one contact stage");
        Require(contact[ntw2_contact::Contacts] == counters[ntw2_collide::Callbacks] && contact[ntw2_contact::Contacts] > 0,
            "every solver callback is planned exactly once");
        Require(contact[ntw2_contact::OwnerForeignClass] == contact[ntw2_contact::Contacts] &&
            contact[ntw2_contact::Mismatches] == 0 && contact[ntw2_contact::IdentityRefusals] == 0, "recorder tables plan as foreign classes");
        Require(contact[mode == ntw2_contact::ModeShadow ? ntw2_contact::OwnerKindCallbacks : ntw2_contact::OwnerCallbacks] ==
            contact[ntw2_contact::Contacts], "every foreign plan runs the original callback");
        ntw2_collide::Stop(); Require(ntw_pool_shutdown(&pool) == NTW_POOL_OK, "real pool drains after contact wiring");
    }
    LandPlanCases();
    for (U workers : {1u, 4u, 8u}) {
        StartPool(workers);
        OwnedCases(workers);
        CapacityCases(workers);
        ntw2_collide::Stop(); Require(ntw_pool_shutdown(&pool) == NTW_POOL_OK, "real pool drains after owned-grid cases");
    }
    Require(VirtualFree(image, 0, MEM_RELEASE) != 0, "release private image");
    std::printf("collision solver: %u differential stages; %u checks; real worker pools 1/3 plus owned-grid pools 1/4/8\n", cases, checks);
    return 0;
}
