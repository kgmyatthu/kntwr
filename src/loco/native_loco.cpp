#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <malloc.h>
#include <stdlib.h>
#include <algorithm>
#include <new>
#include <vector>
#include <array>
#include <utility>
#include "../clones/ntw2_clones.h"
#include "native_loco.h"
#include "native_sweep.h"
#include "native_resolve.h"
#include "native_env.h"
#include "native_move_delta.h"
#include "native_relink.h"

static_assert(sizeof(void*) == 4, "native locomotion is a Win32 x86 adapter");

namespace ntw2_loco {
namespace {
using U = uint32_t;
using TC0 = void (__thiscall*)(void*);
using Free = void (__cdecl*)(void*);
U g_delta;
Binding g_binding;
U g_words[WordCount];
U g_gateWords[GateWordCount];
U g_generation;
bool g_started;
bool g_stage;
U g_runDepth;
LARGE_INTEGER g_frequency;
// 14543B4 has a polymorphic 20-byte vector header. The other two objects are
// zero-constructed 16-byte headers, NOT embedded backing arrays. 801140 owns
// their growth via 444B40/FF7EF0. See the pinned cold tails/destructor sources.
alignas(16) U g_scratchFirst[5];
alignas(16) U g_scratchSecond[4];
alignas(16) U g_scratchThird[4];
U g_guards[3];
U g_serviceTargets[ServiceCount];
constexpr U kTraceCapacity = 256;
ServiceRecord g_trace[kTraceCapacity];
U g_traceCount;
U g_entityServices;
constexpr U kServiceFrames = 64;
struct ServiceFrame { U returnAddress, service; LARGE_INTEGER start; };
ServiceFrame g_serviceFrames[kServiceFrames];
U g_serviceDepth;
bool g_timingEnabled;
bool g_shadowEnabled;
uint8_t g_originalInout;
U g_timingWords[ServiceWordCount];
struct TimingTotals {
    unsigned long long cloneWall, serviceUnion;
    unsigned long long service[ServiceCount], maximum[ServiceCount];
} g_timingTotals;
volatile LONG g_timingSequence; // owner writes; monitor snapshots must not tear 64-bit QPC totals

// Sanity ceilings for ActivateOwned arguments ONLY: nothing is reserved at these sizes. Every real buffer is
// derived from the activation Capacity (movement slots from capacity.primary, grid from records/cells/memberships)
// and from the actual workers+caller count.
constexpr U kMaxRecords = 131072, kMaxCells = 1048576, kMaxMembers = 2097152;
constexpr U kParallelRun = 256, kParallelChunks = 32, kPrivateBytes = 0x1DC;
// Owned-grid build geometry. The native cell id is (z << shift) + x, so z rows are contiguous cell ranges. The z rows
// are split into at most kGridStrips equal strips; a strip is the unit of ownership of both the per-chunk membership
// accounting (dispatch 1) and the cell scan/scatter (dispatch 2). Cells carry bit 31 while they hold a build tally.
constexpr U kGridStrips = 64, kGridMaxTasks = 2 * kParallelChunks, kGridTag = 0x80000000u, kNoSlot = ~0u;
U g_gridWords[GridWordCount], g_gridV2Words[GridV2WordCount], g_gridBuildWords[GridBuildWordCount], g_parallelWords[ParallelWordCount];
LONGLONG g_gridBuildTicks[4]; // registry, capture wall, plan, build wall: owner QPC ticks summed over successful builds
// Cross-epoch identity (the only per-record state the NEXT capture reads from the previous one). Double buffered
// and flipped; everything else in the published view is single-buffered and rewritten in place, because a view
// is invalid from Stage entry / CaptureGrid entry onward.
struct GridIdentity {
    U count, occupied, memberships, epoch, reg; // reg: index of the registry buffer pair (record array + hash) this identity uses
    U *record, *serial, *incarnation, *active, *inserted, *hash;
};
struct alignas(64) GridChunkStat {
    U committed, fromRecord, births, reused, deactivations, removals;
    U birthBase, removed, multis, changed, tallied;
};
// Everything besides the record bytes themselves that a published rectangle and a native cell address depend on. An
// incremental build requires it to equal the previous publication's, rounding control included.
struct GridGeometry { U shift, origin, maximum, nativeCells, model, scaleBits, bumpBits, mxcsr, cw; };
struct GridStore {
    ntw2_workload::Capacity cap;
    U chunks, hashSize, rowCap, slotMask;
    unsigned char* base;
    size_t bytes, allocBytes;
    GridIdentity id[2];
    U current; // index of the identity holding the last publication
    // Registry buffers: record array + identity hash in two pairs. Each identity points into one pair. A build whose primary
    // and secondary registry arrays are word-identical to the last publication's (regValid) shares that pair, so the
    // serial hash construction and every identity lookup disappear; a changed registry builds into the other pair.
    U *regRecord[2], *regHash[2], *rawSecondary;
    U regPrimary, regSecondary;
    bool regValid;
    U *team, *flags, *nodeType, *left, *right, *top, *bottom;
    float *x, *z, *y, *extent, *radius;
    // dense: published cell -> row+1; during a build the same words hold the bit-31 tagged membership tally.
    // fill: per-row scatter cursor. stripMembers/stripRows: chunk-major [chunks][kGridStrips] build accounting.
    U *committed, *dense, *cellIds, *offsets, *occupants, *fill, *stripMembers, *stripRows;
    // Dispatch-1 output for dispatch 2: per record chunk, the inserted records that sit in exactly one z strip ordered by
    // strip (bucketSingle, strip k = [bucketStart[k], bucketStart[k+1])) and the records that span several strips
    // (bucketMulti; bucketCap words each per chunk, count in the chunk's stats). Both ascend by record slot.
    U *bucketSingle, *bucketMulti, *bucketStart, bucketCap;
    GridChunkStat* stats;
    // Incremental state (arrays carved only with grid_incremental): cnt = members per native cell of the published CSR (the
    // dense map cannot carry it: it must hold row+1); sig* = the +A8/+B0/+5C inputs of the build that last wrote each
    // record's rectangle; totals = members/rows per z strip of the publication. incValid: all of it, the published rects
    // and the dense map describe the same publication, so the next build may patch instead of recount.
    U *cnt, *sigNodes, *sigCap, *sigBump;
    U totalMembers[kGridStrips], totalRows[kGridStrips];
    GridGeometry geometry;
    bool incremental, incValid;
    U hold, holdLevel; // full builds still to run after an incremental build whose change share was too high; backoff level
    // Dense-map invariant: every word outside a live strip is zero. Dirty = a build started and never completed, so
    // the map may hold residual tallies anywhere and the next build clears all of it before counting.
    bool denseDirty;
    bool stripLive[kGridStrips];
    U liveStripHeight, liveShift; // geometry the live strips were published under
};
GridStore g_gridStore, g_gridShadowStore; // the shadow store (diagnostic full rebuild) is only allocated with grid_incremental+verify
GridStore* g_grid; // null until ActivateOwned allocates the block
GridStore* g_gridShadow;
U g_gridModel;
U g_incarnation, g_storageBytes;
U g_storageWords[StorageWordCount]; // cached allocation breakdown; first eight words sum to g_storageBytes
U g_catalogStorage[CatalogStorageWordCount]; // cached catalog geometry breakdown; first five sum to StorageCatalog
static_assert(CatalogStorageWordCount == ntw2_resolve::CatalogStorageWordCount, "catalog breakdown width");
bool g_gridValid, g_gridCommittedReady;
GridView g_gridView;
struct PublicationEvent { U entity, which, receiver; }; // all four native link services are thiscall/no stack args
struct WorkerOccurrence {
    U entity, serial, ordinal, state, eventCount, queryCount;
    bool wrapper;
    alignas(16) unsigned char input[kPrivateBytes], output[kPrivateBytes];
    PublicationEvent events[4];
};
struct WorkerArena { WorkerOccurrence occurrences[kParallelRun]; };
WorkerArena* g_workers;
__declspec(thread) WorkerOccurrence* g_workerOccurrence;
U g_parallelInFlight;

// 0x6C0: the phase-2 LOCO_CLASS_WRAP clone reads the private receiver's +688 (pre-step word, always zero) past the 0x680 mover footprint.
constexpr U kOwnedBytes = 0x6C0, kOwnedPrefix = 0x200, kNoOccurrence = ~0u;
constexpr U kOwnedChunkMin = 32, kOwnedChunkMax = 256, kOwnedHistogram = 8;
constexpr U kOwnedClasses = 13, kOwnedVirtualWords = 0xF4 / 4;
constexpr DWORD kOwnedUnsupported = 0xE042B201;
enum OwnedState : unsigned char { OwnedUnprocessed, OwnedComputed, OwnedRefused, OwnedSkipped, OwnedCommitted };
template <class T> inline T Raw(const unsigned char* p) { T v; memcpy(&v, p, sizeof(v)); return v; }
// Compact movement slot, one per worklist ordinal. The private receiver still gets the full 0x200 prefix, but
// the slot retains only the audited footprint of the closed mover closure (all offsets are native receiver offsets):
//  * GUARD = every receiver byte the closure can read before writing it (live-in): MOVE 7F08F0 and WRAP 7F0260
//    operands, vf+74 (64C780 -> +1D8), 80DBF0 (+44), 80E9D0 (+160..+16B,+170), 814AA0 (+110,+116), the resolve/
//    sweep/env port views (+10,+18,+48..+5C,+60,+64,+D4..+DC,+110,+117,+13C,+174..+176,+188,+199,+1A8,+1F0,+B4..+B6),
//    the class predicate slots (+0 vptr, +67C handled separately) and the admission reads of OwnedReason (+0,+10,+18,
//    +28,+2C,+30,+A1,+A8,+B0,+B4,+B5,+EC,+170,+628). Compared again against the live receiver at commit.
//    +4 is guarded only for an admitted 54E920 receiver predicate; other links, +98, +AC and +5ED are owned/overwritten
//    by native service replay or latch rollover, not movement inputs.
//  * OUTPUT = every receiver dword the closure can write. A written dword is either guarded (so writing back an
//    unchanged value is exact) or rewritten on every committed path (ALWAYS_WRITTEN: +54,+B8,+BC,+C8,+CC).
//    The wrapper-only dwords (+14C,+150,+190,+1A4) are written by WRAP on every path and by MOVE never, so
//    they are stored in their own group and committed only for wrapper slots.
//  * Other padding and unread fields are untouched; the separately handled latch at +5EC and predicate at +67C
//    are described below. The +1D8 receiver is included despite lying beyond the bulk movement fields.
#ifdef NTW2_LOCO_ORACLE
using Span = OwnedSpanForTest;
#else
struct Span { U offset, bytes; };
#endif
constexpr Span kGuardSpans[] = {
    {0x000, 4}, {0x010, 4}, {0x018, 4}, {0x028, 20}, {0x040, 8}, {0x048, 12}, {0x058, 64}, {0x0A0, 12},
    {0x0B0, 8}, {0x0C0, 8}, {0x0D0, 36}, {0x110, 8}, {0x12C, 4}, {0x13C, 4}, {0x160, 12}, {0x170, 8},
    {0x188, 8}, {0x194, 8}, {0x1A8, 4}, {0x1D8, 4}, {0x1F0, 4}, {0x628, 4}
};
constexpr Span kOutputSpans[] = {
    {0x010, 4}, {0x038, 4}, {0x040, 4}, {0x048, 16}, {0x064, 4}, {0x070, 40}, {0x0A0, 4}, {0x0B4, 56},
    {0x0F0, 4}, {0x13C, 4}, {0x174, 4}, {0x18C, 4}, {0x194, 8}, {0x1A8, 4}
};
constexpr Span kWrapperSpans[] = {{0x14C, 8}, {0x190, 4}, {0x1A4, 4}};
constexpr U kAlwaysWritten[] = {0x54, 0xB8, 0xBC, 0xC8, 0xCC};
constexpr size_t kGuardSpanCount = sizeof(kGuardSpans) / sizeof(Span), kOutputSpanCount = sizeof(kOutputSpans) / sizeof(Span),
                 kWrapperSpanCount = sizeof(kWrapperSpans) / sizeof(Span), kAlwaysWrittenCount = sizeof(kAlwaysWritten) / sizeof(U);
template <size_t N> constexpr U SpanTotal(const Span (&spans)[N]) { U total = 0; for (const Span& s : spans) total += s.bytes; return total; }
template <size_t N> constexpr std::array<U, N> SpanStarts(const Span (&spans)[N]) {
    std::array<U, N> starts{}; U total = 0;
    for (size_t i = 0; i < N; ++i) { starts[i] = total; total += spans[i].bytes; }
    return starts;
}
// Packed byte position of a receiver offset inside one span table; ~0u when the table does not cover it.
template <size_t N> constexpr U PackedOffset(const Span (&spans)[N], U offset) {
    U packed = 0;
    for (const Span& s : spans) { if (offset >= s.offset && offset < s.offset + s.bytes) return packed + offset - s.offset; packed += s.bytes; }
    return ~0u;
}
constexpr U kGuardBytes = SpanTotal(kGuardSpans), kOutputBytes = SpanTotal(kOutputSpans), kWrapperBytes = SpanTotal(kWrapperSpans);
constexpr auto kGuardStart = SpanStarts(kGuardSpans);
constexpr auto kOutputStart = SpanStarts(kOutputSpans);
constexpr auto kWrapperStart = SpanStarts(kWrapperSpans);
// Spans ascend, are disjoint, dword aligned and stay below `limit`; only the final guard span (+628) lies past the copied prefix.
template <size_t N> constexpr bool SpansOrdered(const Span (&spans)[N], U lastLimit, bool lastBeyondPrefix) {
    U end = 0;
    for (size_t i = 0; i < N; ++i) {
        const Span& s = spans[i];
        if (!s.bytes || ((s.offset | s.bytes) & 3) || s.offset < end) return false;
        end = s.offset + s.bytes;
        if (end > (i + 1 == N && lastBeyondPrefix ? lastLimit : kOwnedPrefix)) return false;
    }
    return true;
}
template <size_t N> constexpr bool SpansCover(const Span (&spans)[N], U offset) { return PackedOffset(spans, offset) != ~0u; }
constexpr bool OutputsProtected() {
    for (const Span& s : kOutputSpans) for (U at = s.offset; at < s.offset + s.bytes; at += 4) {
        bool always = false;
        for (U w : kAlwaysWritten) always |= w == at;
        if (!SpansCover(kGuardSpans, at) && !always) return false;
    }
    return true;
}
constexpr bool WrapperGroupsDisjoint() {
    for (const Span& w : kWrapperSpans) for (U at = w.offset; at < w.offset + w.bytes; at += 4)
        if (SpansCover(kOutputSpans, at)) return false;
    return true;
}
static_assert(SpansOrdered(kGuardSpans, 0x62C, true) && SpansOrdered(kOutputSpans, 0, false) && SpansOrdered(kWrapperSpans, 0, false),
              "movement footprint spans are ordered, dword aligned and inside the copied prefix");
static_assert(OutputsProtected(), "every committed dword is guarded or rewritten on every committed path");
static_assert(WrapperGroupsDisjoint(), "wrapper-only outputs never overlap the common outputs");
struct OwnedSlot {
    U entity, services, inputPredicate;
    unsigned char reason, detail, serviceCount, active, wrapper, readsPredicate, inputLatch, resultLatches[2], readsLinkByte, inputLinkByte, classWrapper;
    unsigned char guard[kGuardBytes];
    unsigned char output[kOutputBytes + kWrapperBytes];
};
template <size_t N, class F> __forceinline void EachSpanOf(F&& fn) {
    [&]<size_t... I>(std::index_sequence<I...>) { (fn(std::integral_constant<size_t, I>{}), ...); }(std::make_index_sequence<N>{});
}
template <U Offset> inline U GuardWord(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kGuardSpans, Offset);
    static_assert(at != ~0u, "offset is outside the guard footprint");
    return Raw<U>(s.guard + at);
}
template <U Offset> inline unsigned char GuardByte(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kGuardSpans, Offset);
    static_assert(at != ~0u, "offset is outside the guard footprint");
    return s.guard[at];
}
template <U Offset> inline U OutputWord(const OwnedSlot& s) {
    constexpr U at = PackedOffset(kOutputSpans, Offset);
    static_assert(at != ~0u, "offset is outside the output footprint");
    return Raw<U>(s.output + at);
}
template <U Bytes> inline U SpanDiff(const unsigned char* a, const unsigned char* b) {
    U diff = 0, i = 0;
    for (; i + 16 <= Bytes; i += 16)
        diff |= static_cast<U>(_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(a + i)),
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(b + i)))) ^ 0xFFFF);
    for (; i < Bytes; i += 4) diff |= Raw<U>(a + i) ^ Raw<U>(b + i);
    return diff;
}
// `live` is the native receiver (guard reads +628 beyond the copied prefix); work is the private 0x680 receiver.
inline void GatherGuard(OwnedSlot& slot, const unsigned char* live) {
    EachSpanOf<kGuardSpanCount>([&](auto i) {
        constexpr Span s = kGuardSpans[decltype(i)::value];
        memcpy(slot.guard + kGuardStart[decltype(i)::value], live + s.offset, s.bytes);
    });
}
inline void GatherOutput(OwnedSlot& slot, const unsigned char* work) {
    EachSpanOf<kOutputSpanCount>([&](auto i) {
        constexpr Span s = kOutputSpans[decltype(i)::value];
        memcpy(slot.output + kOutputStart[decltype(i)::value], work + s.offset, s.bytes);
    });
    EachSpanOf<kWrapperSpanCount>([&](auto i) {
        constexpr Span s = kWrapperSpans[decltype(i)::value];
        memcpy(slot.output + kOutputBytes + kWrapperStart[decltype(i)::value], work + s.offset, s.bytes);
    });
}
// True when every byte the worker could have read still holds the value it read (branch-free over the footprint).
inline bool OwnedGuardMatches(const OwnedSlot& slot, const unsigned char* live) {
    U diff = 0;
    EachSpanOf<kGuardSpanCount>([&](auto i) {
        constexpr Span s = kGuardSpans[decltype(i)::value];
        diff |= SpanDiff<s.bytes>(live + s.offset, slot.guard + kGuardStart[decltype(i)::value]);
    });
    diff |= static_cast<U>(live[0x5EC] ^ slot.inputLatch);
    if (slot.readsPredicate) diff |= Raw<U>(live + 0x67C) ^ slot.inputPredicate;
    if (slot.readsLinkByte) diff |= static_cast<U>(live[4] ^ slot.inputLinkByte);
    return diff == 0;
}
// Writes exactly the proven footprint; links/+98/+A8/+AC belong to the replayed native services.
inline void CommitOwnedFields(const OwnedSlot& slot) {
    unsigned char* const native = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(slot.entity));
    EachSpanOf<kOutputSpanCount>([&](auto i) {
        constexpr Span s = kOutputSpans[decltype(i)::value];
        memcpy(native + s.offset, slot.output + kOutputStart[decltype(i)::value], s.bytes);
    });
    if (slot.wrapper) EachSpanOf<kWrapperSpanCount>([&](auto i) {
        constexpr Span s = kWrapperSpans[decltype(i)::value];
        memcpy(native + s.offset, slot.output + kOutputBytes + kWrapperStart[decltype(i)::value], s.bytes);
    });
    memcpy(native + 0x5EC, slot.resultLatches, 2);
}
// The occurrence a participant is executing right now (service gates read it through TLS).
struct OwnedCurrent {
    U entity, ordinal, serial, services;
    unsigned char reason, detail, serviceCount;
    ntw2_env::Result environment;
};
// Heavy per-participant worker contexts. Created by ActivateOwned only, one per ACTUAL participant.
struct OwnedContexts {
    ntw2_sweep::WorkerContext sweep;
    ntw2_resolve::WorkerContext resolve;
    ntw2_env::WorkerContext env;
};
// Class-wrapper phase 2: one entry per real child of a worker-computed 0x132BA04 wrapper (pooled per stage, ordinal order
// via OwnedArena::cwInfo). Prefilled at gather (child, vtable, list, state); the proxy child's slot 0x36 records the
// 0x14A51A0 word it served, slot 1 records the 0x80BAC0 arguments (pose, heading dword) and sets `submitted`.
constexpr U kCwMaxChildren = 8, kCwChildTable = 0x1333714, kCwChildSlots = 0xD8 / 4 + 1;
struct CwEvent {
    U child, vtable, list, state;
    float pose[3];
    U heading;
    unsigned short word;
    unsigned char submitted, served;
};
struct OwnedParticipant {
    ntw2_clone_set clones{};
    U first[5]{}, second[4]{}, third[4]{};
    OwnedContexts* ctx = nullptr;
    OwnedCurrent current{};
    LONGLONG maximum = 0;
    ULONGLONG cpu100ns = 0, cpuAtMaximum100ns = 0;
    // Per-dispatch chunk accounting, written only by the thread that acquired this participant and folded by PrepareOwned after
    // the join (no locked operation per chunk). Timing/CPU/histogram are measured only outside --loco-quiet.
    U computed = 0, refused = 0, chunks = 0, inlineChunks = 0, chunkTimeUs = 0, histogram[8] = {};
    bool isOwner = false;
    // Class-wrapper phase 2: first pooled event of the current occurrence, selector inputs for OwnedSelect, proxy children
    // ({private child vtable, child index}) and the private child array installed at work+0x670.
    U cwBase = 0;
    bool cwWrapper = false, cwInitialA3 = false;
    U cwProxy[kCwMaxChildren][2]{};
    U cwList[kCwMaxChildren]{};
    // Private receiver. Bytes outside the copied prefix/latches/+67C are never read by the closed closure and stay zero
    // (a phase-2 class wrapper sets +224/+66C/+670 for its own call and clears them afterwards).
    alignas(64) unsigned char work[kOwnedBytes]{};
};
struct OwnedArena {
    ntw2_sweep::WorkerScene scene;
    ntw2_resolve::WorkerCatalog catalog;
    OwnedParticipant* participants[kParallelChunks]{}; // only participantsCount entries are ever allocated
    U virtualTables[kOwnedClasses][kOwnedVirtualWords];
    bool classRoute[kOwnedClasses]{}, predicate67C[kOwnedClasses]{}, predicateLinkByte[kOwnedClasses]{};
    unsigned char* movement = nullptr; // one block: slots | worklist | states [| cwInfo | cwEvents], all sized by capacity.primary
    U movementBytes = 0;
    OwnedSlot* slots = nullptr;
    unsigned char* states = nullptr;
    U slotCapacity = 0;
    U* worklist = nullptr;
    U* cwInfo = nullptr;       // per ordinal: children << 24 | first pooled event (phase-2 class wrappers only, else 0)
    CwEvent* cwEvents = nullptr; // capacity.primary entries; exhaustion refuses the occurrence (needs_capacity)
    volatile LONG cwNext = 0;
    U activationModel = 0;
    bool activated = false;
    U list = 0, count = 0, participantsCount = 0, owner = 0, mxcsr = 0, chunkSize = 0, chunks = 0;
    U failureReason = OwnedNeedsUnit;
    unsigned short cw = 0;
    bool valid = false;
    volatile LONG epoch = 0, nextParticipant = 0, overflow = 0;
};
static_assert(sizeof(OwnedSlot) == kOwnedSlotBytes, "published movement slot width");
OwnedArena* g_owned;
U g_ownedWords[OwnedWordCount], g_locoBindings[NTW2_BIND_COUNT];
U g_ownedDetails[OwnedDetailWordCount], g_ownedPhase[OwnedPhaseWordCount];
U g_ownedLoad[OwnedLoadWordCount];
LONGLONG g_replayCommitTicks, g_replayFallbackTicks;
U g_ownedReplaySeq, g_ownedFallbackSeq;
bool g_quiet;
// Class-wrapper phase 2: 0 off, 1 shadow, 2 live. g_cwChildSlots: the World agent table really has 80BAC0/5E4C60 at +4/+D8.
U g_cwMode;
bool g_cwChildSlots;
U g_cwChildTable[kCwChildSlots];
U g_cwShadowIndex = ~0u; // shadow: ordinal whose native wrapper run must be compared after the stage loop's fallback
U g_stageEntity, g_stageOrdinal;
__declspec(thread) OwnedCurrent* g_ownedOccurrence;
__declspec(thread) OwnedParticipant* g_ownedParticipant;
__declspec(thread) LONG g_ownedEpoch;
#ifdef NTW2_LOCO_ORACLE
OwnedServiceObserverForTest g_ownedObserver;
void ObserveOwned(U entity, U service, U ordinal, OwnedTestPhase phase) {
    if (g_ownedObserver) g_ownedObserver(entity, static_cast<Service>(service), ordinal, phase);
}
#endif
U g_stageGatherTarget, g_stageResetTarget, g_stagingReturn;
LONGLONG g_stagingStart;
bool g_stagingActive;
enum OccurrenceState : U { Ready, Computed, Faulted };
struct ParallelJob { U count, chunks, owner, mxcsr; unsigned short cw; };
enum GridPhase : U { GridPhaseCapture, GridPhaseBuild, GridPhaseVerify };
// Contiguous run of active strips owned by one build task: it scans those strips' cells, assigns rows and
// membership offsets from the exact bases the owner computed, and scatters the records that touch them.
struct GridTask { U first, last, rowBase, rowEnd, memberBase, memberEnd; };
// One normal build = exactly two dispatches, with only owner work in between:
//   1. capture (record chunks): snapshot, identity, node validation, bounds, per-cell tally, per-chunk strip totals,
//      committed-ordinal -> slot mapping;
//   2. build (tasks, then record chunks): per-strip cell scan -> rows/offsets/dense, in-order scatter, and
//      the incarnation/accounting finish.
// No chunk waits for another chunk of the same dispatch. Every cross-chunk dependency (strip totals, row and
// offset bases, birth prefix) is resolved by the owner between the dispatches, so serial, reversed and concurrent
// dispatchers publish identical output.
struct GridJob {
    GridStore* store;
    GridIdentity* next;
    const GridIdentity* old;
    U phase, chunks, tasks, members, rows, incarnationBase, committedCount;
    U shift, origin, maximum, cells, nativeCells, mxcsr, stripHeight, strips, activeStrips;
    float scale, bump;
    U stable, stripBits; // stable: registry shared with the previous publication; stripBits: log2(stripHeight), 32 if not a power of two
    CoverGeometry geometry;
    U incremental, shadow; // incremental: patch the previous publication's counts; shadow: diagnostic rebuild, no global accounting
    unsigned short cw;
    volatile LONG failure, mismatches, unsupported, nativeMembers;
    LONGLONG wallTicks[3]; // owner QPC wall of each dispatch kind (capture, build, verify)
    U active[kGridStrips], stripRows[kGridStrips], stripMembers[kGridStrips];
    GridTask task[kGridMaxTasks];
};

inline U Address(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
inline void* P(U address) { return reinterpret_cast<void*>(static_cast<uintptr_t>(address)); }
inline U V(U va) { return va + g_delta; }
inline U D(U address) { return *reinterpret_cast<const U*>(static_cast<uintptr_t>(address)); }
inline uint8_t B(U address) { return *reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(address)); }
inline void Call(U address, U receiver) { reinterpret_cast<TC0>(address)(P(receiver)); }
inline void Max(U word, U value) { if (g_words[word] < value) g_words[word] = value; }
inline LONGLONG Now() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
inline U Microseconds(LONGLONG ticks) {
    return static_cast<U>((static_cast<unsigned long long>(ticks) * 1000000ull) /
                          static_cast<unsigned long long>(g_frequency.QuadPart));
}

inline float Float(U address) { return *reinterpret_cast<const float*>(static_cast<uintptr_t>(address)); }
inline U GridStripOf(const GridJob& job, U z) { return job.stripBits < 32 ? z >> job.stripBits : z / job.stripHeight; }
inline bool SameWords(const void* a, const void* b, U words) { return !words || !memcmp(a, b, static_cast<size_t>(words) * sizeof(U)); }
void Prefault(void* base, size_t bytes);
// Hash capacity: power of two, at most 2/3 loaded at full record capacity.
U HashSizeFor(U records) { U size = 16; while (size < records + records / 2 + 1) size <<= 1; return size; }
// Smallest b >= 1 with 2^b >= values.
U BitsFor(U values) { U bits = 1; while (bits < 31 && (1u << bits) < values) ++bits; return bits; }
bool ValidCapacity(const ntw2_workload::Capacity& c) {
    return c.primary && c.records >= c.primary && c.cells && c.memberships &&
        c.records <= kMaxRecords && c.cells <= kMaxCells && c.memberships <= kMaxMembers;
}
// Carves (or, with base==null, only sizes) the single grid block. Each array is padded to 64 bytes.
// words: identity 2*4R | registry 2*(R+H) | rawSecondary R | view 12R | committed R | dense C | cellIds Q | offsets Q+1 |
// occupants M | fill Q | stripMembers chunks*64 | stripRows chunks*64 | buckets 2*chunks*ceil(R/chunks) + chunks*65 |
// stats chunks*64B, with R=records, H=HashSizeFor(R), Q=min(cells,memberships), M=memberships, C=cells.
struct GridCarve {
    unsigned char* base;
    unsigned long long offset;
    template <class T> T* Take(unsigned long long count) {
        T* const p = base ? reinterpret_cast<T*>(base + offset) : nullptr;
        offset += (count * sizeof(T) + 63) & ~63ull;
        return p;
    }
};
unsigned long long CarveGrid(const ntw2_workload::Capacity& c, U chunks, GridStore& s, unsigned char* base, bool incremental) {
    GridCarve m = {base, 0};
    const U R = c.records, H = HashSizeFor(R), C = c.cells, M = c.memberships, Q = (std::min)(C, M);
    s.cap = c; s.chunks = chunks; s.hashSize = H; s.rowCap = Q;
    s.slotMask = (1u << BitsFor(R + 1)) - 1; // identity hash entries carry slot+1 in the low bits and a hash tag above
    for (GridIdentity& id : s.id) {
        id.serial = m.Take<U>(R); id.incarnation = m.Take<U>(R); id.active = m.Take<U>(R); id.inserted = m.Take<U>(R);
    }
    for (U k = 0; k < 2; ++k) { s.regRecord[k] = m.Take<U>(R); s.regHash[k] = m.Take<U>(H); }
    s.rawSecondary = m.Take<U>(R);
    for (U k = 0; k < 2; ++k) { s.id[k].record = s.regRecord[k]; s.id[k].hash = s.regHash[k]; s.id[k].reg = k; }
    s.team = m.Take<U>(R); s.flags = m.Take<U>(R); s.nodeType = m.Take<U>(R);
    s.left = m.Take<U>(R); s.right = m.Take<U>(R); s.top = m.Take<U>(R); s.bottom = m.Take<U>(R);
    s.x = m.Take<float>(R); s.z = m.Take<float>(R); s.y = m.Take<float>(R); s.extent = m.Take<float>(R); s.radius = m.Take<float>(R);
    s.committed = m.Take<U>(R); s.dense = m.Take<U>(C);
    s.cellIds = m.Take<U>(Q); s.offsets = m.Take<U>(Q + 1ull);
    s.occupants = m.Take<U>(M); s.fill = m.Take<U>(Q);
    s.stripMembers = m.Take<U>(static_cast<unsigned long long>(chunks) * kGridStrips);
    s.stripRows = m.Take<U>(static_cast<unsigned long long>(chunks) * kGridStrips);
    s.bucketCap = (R + chunks - 1) / chunks;
    s.bucketSingle = m.Take<U>(static_cast<unsigned long long>(chunks) * s.bucketCap);
    s.bucketMulti = m.Take<U>(static_cast<unsigned long long>(chunks) * s.bucketCap);
    s.bucketStart = m.Take<U>(static_cast<unsigned long long>(chunks) * (kGridStrips + 1));
    s.stats = m.Take<GridChunkStat>(chunks);
    s.incremental = incremental;
    if (incremental) { s.cnt = m.Take<U>(C); s.sigNodes = m.Take<U>(R); s.sigCap = m.Take<U>(R); s.sigBump = m.Take<U>(R); }
    return m.offset;
}
// Reserves, carves and prefaults one store (page-rounded single block).
bool AllocateStore(GridStore& store, const ntw2_workload::Capacity& c, U chunks, bool incremental) {
    GridStore plan = {};
    const unsigned long long bytes = CarveGrid(c, chunks, plan, nullptr, incremental);
    if (bytes > 0x7FFFFFFFull) return false;
    const unsigned long long allocation = (bytes + 4095) & ~4095ull;
    unsigned char* const base = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(allocation), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base) return false;
    store = GridStore{};
    CarveGrid(c, chunks, store, base, incremental);
    store.base = base; store.bytes = static_cast<size_t>(bytes);
    store.allocBytes = static_cast<size_t>(allocation);
    Prefault(base, static_cast<size_t>(allocation)); // every page, before hook publication
    return true;
}
void ReleaseGrid() {
    if (g_gridStore.base) VirtualFree(g_gridStore.base, 0, MEM_RELEASE);
    if (g_gridShadowStore.base) VirtualFree(g_gridShadowStore.base, 0, MEM_RELEASE);
    g_gridStore = GridStore{}; g_gridShadowStore = GridStore{};
    g_grid = g_gridShadow = nullptr;
}
// Record chunks of the grid dispatches: several per participant, claimed dynamically, so a participant that is slow (shared
// core, descheduled, cold lines) does not decide the wall time of the whole dispatch.
constexpr U kGridChunksPerParticipant = 3;
U GridChunkCount() { return (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1) * kGridChunksPerParticipant); }
bool AllocateGrid(const ntw2_workload::Capacity& c) {
    const U chunks = GridChunkCount();
    if (!AllocateStore(g_gridStore, c, chunks, g_binding.grid_incremental)) return false;
    // --loco-grid-incremental with verification keeps a second, non-incremental store that every stage rebuilds in full.
    if (g_binding.grid_incremental && g_binding.verify_grid && !AllocateStore(g_gridShadowStore, c, chunks, false)) {
        ReleaseGrid(); return false;
    }
    g_grid = &g_gridStore; g_gridShadow = g_gridShadowStore.base ? &g_gridShadowStore : nullptr;
    g_gridWords[GridBytes] = static_cast<U>(g_gridStore.bytes);
    return true;
}
bool GridCovers(const ntw2_workload::Capacity& c) {
    const ntw2_workload::Capacity& a = g_gridStore.cap;
    return c.primary <= a.primary && c.records <= a.records && c.cells <= a.cells && c.memberships <= a.memberships;
}
U SaturatedWord(unsigned long long value) { return value > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(value); }
size_t RelinkStorageBytes(); // relink op log + shadow mirror, accounted with the grid block
// Every owned allocation, retained capacities included, split into the cached breakdown. Called once per
// activation event, never per tick. The first eight words sum to the returned total (barring saturation).
U ComputeStorage() {
    unsigned long long movement = 0, grid = 0, scene = 0, catalog = 0, participants = 0, sweep = 0, resolve = 0, env = 0;
    memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    if (g_workers) participants += sizeof(WorkerArena);
    if (g_grid) grid = g_gridStore.allocBytes + g_gridShadowStore.allocBytes;
    grid += RelinkStorageBytes();
    if (g_owned) {
        const OwnedArena& arena = *g_owned;
        participants += sizeof(OwnedArena);
        movement = arena.movementBytes;
        scene = ntw2_sweep::HeapBytes(arena.scene); catalog = ntw2_resolve::HeapBytes(arena.catalog);
        ntw2_resolve::SampleCatalogStorage(arena.catalog, g_catalogStorage);
        for (U i = 0; i < arena.participantsCount; ++i) {
            const OwnedParticipant* participant = arena.participants[i];
            if (!participant) continue;
            participants += sizeof(OwnedParticipant) + participant->clones.allocation_bytes;
            if (participant->ctx) {
                participants += sizeof(OwnedContexts);
                sweep += ntw2_sweep::HeapBytes(participant->ctx->sweep);
                resolve += ntw2_resolve::HeapBytes(participant->ctx->resolve);
                env += ntw2_env::HeapBytes(participant->ctx->env);
            }
        }
        ntw2_sweep::SampleCounts(arena.scene, g_storageWords + StorageSceneNodes);
    }
    g_storageWords[StorageMovement] = SaturatedWord(movement); g_storageWords[StorageGrid] = SaturatedWord(grid);
    g_storageWords[StorageScene] = SaturatedWord(scene); g_storageWords[StorageCatalog] = SaturatedWord(catalog);
    g_storageWords[StorageParticipants] = SaturatedWord(participants); g_storageWords[StorageSweep] = SaturatedWord(sweep);
    g_storageWords[StorageResolve] = SaturatedWord(resolve); g_storageWords[StorageEnv] = SaturatedWord(env);
    return SaturatedWord(movement + grid + scene + catalog + participants + sweep + resolve + env);
}
inline U GridHash(U record) { return (record >> 4) * 2654435761u; }
// Identity hash entry = (high product bits & ~slotMask) | (slot + 1): a non-matching probe is rejected by the tag
// without touching the record array; a tag match is always confirmed against the full record address.
U GridSlot(const GridStore& s, const GridIdentity& id, U record) {
    const U product = GridHash(record), mask = s.hashSize - 1, tagMask = ~s.slotMask;
    for (U h = product & mask;; h = (h + 1) & mask) {
        const U entry = id.hash[h];
        if (!entry) return kNoSlot;
        if (!((entry ^ product) & tagMask)) {
            const U slot = (entry & s.slotMask) - 1;
            if (id.record[slot] == record) return slot;
        }
    }
}
// Atomic maximum: duplicate occurrences of one record keep the highest committed ordinal, like the old serial scan.
inline void GridRaiseCommitted(U& word, U value) {
    volatile LONG* const target = reinterpret_cast<volatile LONG*>(&word);
    LONG current = _InterlockedCompareExchange(target, 0, 0);
    while (current < static_cast<LONG>(value)) {
        const LONG seen = _InterlockedCompareExchange(target, static_cast<LONG>(value), current);
        if (seen == current) break;
        current = seen;
    }
}
void GridFail(GridJob& job) { _InterlockedExchange(&job.failure, 1); }
void GridMismatch(GridJob& job) { _InterlockedIncrement(&job.mismatches); GridFail(job); }
inline void GridRange(U n, U chunks, U chunk, U& begin, U& end) {
    const U size = (n + chunks - 1) / chunks;
    begin = (std::min)(n, chunk * size); end = (std::min)(n, begin + size);
}
// First touch of a cell in this build replaces whatever the previous publication left there with tag|1; later touches
// add one. Exactly one caller observes the first touch (true), whichever chunk it is, so the per-strip row counts the
// owner derives are exact and schedule independent. Nothing reads a tally before the dispatch has joined.
inline bool GridTally(U& word) {
    volatile LONG* const target = reinterpret_cast<volatile LONG*>(&word);
    LONG current = *target;
    for (;;) {
        const LONG next = (static_cast<U>(current) & kGridTag) ? current + 1 : static_cast<LONG>(kGridTag | 1u);
        const LONG seen = _InterlockedCompareExchange(target, next, current);
        if (seen == current) return !(static_cast<U>(current) & kGridTag);
        current = seen;
    }
}
// Software prefetch for dispatch 1. Records are scattered heap objects, so their lines (pose/serial/flags, +A8..+B3) and
// node blocks are the dominant misses of a capture; the registry order is known, so the lines are requested a few
// records ahead (record lines far ahead, the node block, whose address lives in the record, closer).
constexpr U kGridPrefetchFar = 8, kGridPrefetchNear = 4;
inline void GridPrefetchRecord(const GridJob& job, U record) {
    if (!record) return;
    const char* const p = static_cast<const char*>(P(record));
    _mm_prefetch(p + 0x2C, _MM_HINT_T0); _mm_prefetch(p + 0x5C, _MM_HINT_T0);
    _mm_prefetch(p + 0xA8, _MM_HINT_T0); _mm_prefetch(p + 0xB3, _MM_HINT_T0);
    if (!job.stable) _mm_prefetch(reinterpret_cast<const char*>(job.old->hash + (GridHash(record) & (job.store->hashSize - 1))), _MM_HINT_T0);
}
inline void GridPrefetchNodes(U record) {
    if (!record) return;
    const char* const nodes = static_cast<const char*>(P(D(record + 0xA8)));
    _mm_prefetch(nodes, _MM_HINT_T0); _mm_prefetch(nodes + 0x40, _MM_HINT_T0); _mm_prefetch(nodes + 0x6C, _MM_HINT_T0);
}
// Dispatch 1 (record chunks): snapshot, identity, node validation, bounds, per-cell tally, per-chunk strip totals.
void GridCaptureRecord(GridJob& job, U i, U chunk) {
    GridStore& s = *job.store;
    GridIdentity& b = *job.next;
    const GridIdentity& old = *job.old;
    GridChunkStat& stat = s.stats[chunk];
    const U record = b.record[i];
    s.left[i] = s.right[i] = s.top[i] = s.bottom[i] = b.inserted[i] = s.nodeType[i] = 0;
    if (!record) { b.serial[i] = b.incarnation[i] = s.team[i] = s.flags[i] = b.active[i] = 0;
        s.x[i] = s.y[i] = s.z[i] = s.extent[i] = s.radius[i] = 0; return; }
    b.serial[i] = D(record + 0x2C); s.team[i] = D(record + 0x44); s.flags[i] = D(record + 0x38);
    b.active[i] = B(record + 0x30); b.inserted[i] = D(record + 0xAC);
    const U previous = job.stable ? i : GridSlot(s, old, record); // a shared registry keeps every record at its slot
    if (previous < old.count && old.serial[previous] == b.serial[i]) {
        b.incarnation[i] = old.incarnation[previous];
        stat.deactivations += old.active[previous] && !b.active[i];
        stat.removals += old.inserted[previous] && !b.inserted[i];
    } else {
        // The finish phase assigns births in record order from the owner's per-chunk prefix.
        b.incarnation[i] = 0; ++stat.births;
        stat.reused += previous < old.count;
    }
    const unsigned char* const pose = static_cast<const unsigned char*>(P(record + 0x48));
    memcpy(&s.x[i], pose, sizeof(float)); memcpy(&s.y[i], pose + 4, sizeof(float));
    memcpy(&s.z[i], pose + 8, sizeof(float)); memcpy(&s.extent[i], pose + 12, sizeof(float));
    memcpy(&s.radius[i], pose + 16, sizeof(float));
    if (!b.inserted[i]) return; // AC, not activity/A1, owns grid absence.
    const U nodes = D(record + 0xA8), cap = D(record + 0xB0);
    const bool bump = B(record + 0x5C) == 1;
    const CoverRect rect = CoverRecord(s.x[i], s.z[i], s.radius[i], bump, job.geometry);
    const U left = rect.left, right = rect.right, top = rect.top, bottom = rect.bottom;
    if (!nodes || left > right || top > bottom || b.inserted[i] > cap ||
        static_cast<unsigned long long>(right - left + 1) * (bottom - top + 1) != b.inserted[i]) {
        GridMismatch(job); return;
    }
    s.left[i] = left; s.right[i] = right; s.top[i] = top; s.bottom[i] = bottom;
    s.nodeType[i] = D(nodes);
    if (s.sigNodes) { s.sigNodes[i] = nodes; s.sigCap[i] = cap; s.sigBump[i] = bump; } // inputs of this rectangle
    U* const stripMembers = s.stripMembers + static_cast<size_t>(chunk) * kGridStrips;
    U* const stripRows = s.stripRows + static_cast<size_t>(chunk) * kGridStrips;
    U n = 0;
    for (U z = top; z <= bottom; ++z) {
        U fresh = 0;
        for (U x = left; x <= right; ++x, ++n) {
            const U node = nodes + n * 0x1C, cell = (z << job.shift) + x;
            if (D(node) != 8 || D(node + 4) != b.serial[i] || D(node + 8) != record + 0x30 ||
                D(node + 12) != record || D(node + 24) != job.nativeCells + 4 * cell) {
                _InterlockedIncrement(&job.unsupported); GridMismatch(job); return;
            }
            fresh += GridTally(s.dense[cell]);
        }
        const U strip = GridStripOf(job, z);
        stripMembers[strip] += right - left + 1; stripRows[strip] += fresh;
    }
}
struct GridRect { U left, right, top, bottom; };
// Incremental tally: adds d (+1/-1) to the member count of every cell of `r` that is not inside `other` (the other half of a
// rectangle change applies the opposite sign there, so shared cells need no traffic). The count before the atomic add says
// whether the cell appeared (0 -> 1, a new row) or disappeared (1 -> 0). Summed over any interleaving those events are
// exactly [count after > 0] - [count before > 0] per cell (counts never go negative: every removal belongs to a record that
// was a member), so the per-strip row and member deltas are schedule independent.
void GridDeltaRect(const GridJob& job, GridStore& s, U chunk, const GridRect& r, const GridRect* other, LONG d) {
    U* const members = s.stripMembers + static_cast<size_t>(chunk) * kGridStrips;
    U* const rows = s.stripRows + static_cast<size_t>(chunk) * kGridStrips;
    for (U z = r.top; z <= r.bottom; ++z) {
        const bool shared = other && z >= other->top && z <= other->bottom;
        LONG moved = 0, events = 0;
        for (U x = r.left; x <= r.right; ++x) {
            if (shared && x >= other->left && x <= other->right) { x = other->right; continue; }
            const LONG before = _InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&s.cnt[(z << job.shift) + x]), d);
            moved += d; events += d > 0 ? (before == 0) : -(before == 1);
        }
        const U strip = GridStripOf(job, z);
        members[strip] += static_cast<U>(moved); rows[strip] += static_cast<U>(events);
    }
}
inline void GridStoreChanged(U& word, U value) { if (word != value) word = value; }
inline void GridStoreBitsChanged(float& word, U bits) { U current; memcpy(&current, &word, sizeof(U)); if (current != bits) memcpy(&word, &bits, sizeof(U)); }
// Dispatch 1, incremental form (registry shared with the previous publication, same geometry): every record is re-read, but
// only a record whose rectangle inputs changed pays for coverage, node validation and the delta tally. A record whose
// coverage inputs (identity, +AC, x/z/radius, +5C, +A8, +B0) equal the ones its rectangle was built from keeps rectangle,
// node type and memberships: the node chain is a function of those inputs (a mismatch refuses the full build as well).
void GridCaptureRecordDelta(GridJob& job, U i, U chunk) {
    GridStore& s = *job.store;
    GridIdentity& b = *job.next;
    const GridIdentity& old = *job.old;
    GridChunkStat& stat = s.stats[chunk];
    const U record = b.record[i];
    if (!record) { b.serial[i] = b.incarnation[i] = b.active[i] = b.inserted[i] = 0; return; } // slot was empty in both publications
    const U serial = D(record + 0x2C), inserted = D(record + 0xAC), oldInserted = old.inserted[i];
    const uint8_t activity = B(record + 0x30);
    b.serial[i] = serial; b.active[i] = activity; b.inserted[i] = inserted;
    GridStoreChanged(s.team[i], D(record + 0x44)); GridStoreChanged(s.flags[i], D(record + 0x38));
    const bool sameIdentity = old.serial[i] == serial;
    if (sameIdentity) {
        b.incarnation[i] = old.incarnation[i];
        stat.deactivations += old.active[i] && !activity;
        stat.removals += oldInserted && !inserted;
    } else { b.incarnation[i] = 0; ++stat.births; ++stat.reused; } // the slot held this record before: an address reuse
    U pose[5], was[3];
    memcpy(pose, P(record + 0x48), sizeof(pose)); // x, y, z, extent, radius
    memcpy(&was[0], &s.x[i], 4); memcpy(&was[1], &s.z[i], 4); memcpy(&was[2], &s.radius[i], 4);
    // Single-buffered snapshot arrays are only written where the value moved: lines nobody changed stay clean and shared.
    GridStoreBitsChanged(s.x[i], pose[0]); GridStoreBitsChanged(s.y[i], pose[1]); GridStoreBitsChanged(s.z[i], pose[2]);
    GridStoreBitsChanged(s.extent[i], pose[3]); GridStoreBitsChanged(s.radius[i], pose[4]);
    const U nodes = D(record + 0xA8), cap = D(record + 0xB0);
    const bool bump = B(record + 0x5C) == 1;
    if (!inserted) { // AC, not activity/A1, owns grid absence
        if (oldInserted) {
            const GridRect prior = {s.left[i], s.right[i], s.top[i], s.bottom[i]};
            GridDeltaRect(job, s, chunk, prior, nullptr, -1);
            s.left[i] = s.right[i] = s.top[i] = s.bottom[i] = s.nodeType[i] = 0;
            ++stat.changed; ++stat.tallied;
        }
        return;
    }
    if (sameIdentity && inserted == oldInserted && pose[0] == was[0] && pose[2] == was[1] && pose[4] == was[2] &&
        bump == (s.sigBump[i] != 0) && nodes == s.sigNodes[i] && cap == s.sigCap[i]) return;
    ++stat.changed;
    const CoverRect rect = CoverRecord(s.x[i], s.z[i], s.radius[i], bump, job.geometry);
    const U left = rect.left, right = rect.right, top = rect.top, bottom = rect.bottom;
    if (!nodes || left > right || top > bottom || inserted > cap ||
        static_cast<unsigned long long>(right - left + 1) * (bottom - top + 1) != inserted) {
        GridMismatch(job); return;
    }
    U n = 0;
    for (U z = top; z <= bottom; ++z) for (U x = left; x <= right; ++x, ++n) {
        const U node = nodes + n * 0x1C, cell = (z << job.shift) + x;
        if (D(node) != 8 || D(node + 4) != serial || D(node + 8) != record + 0x30 ||
            D(node + 12) != record || D(node + 24) != job.nativeCells + 4 * cell) {
            _InterlockedIncrement(&job.unsupported); GridMismatch(job); return;
        }
    }
    const GridRect fresh = {left, right, top, bottom};
    if (oldInserted) {
        const GridRect prior = {s.left[i], s.right[i], s.top[i], s.bottom[i]};
        if (prior.left != left || prior.right != right || prior.top != top || prior.bottom != bottom) {
            GridDeltaRect(job, s, chunk, prior, &fresh, -1); GridDeltaRect(job, s, chunk, fresh, &prior, 1); ++stat.tallied;
        }
    } else { GridDeltaRect(job, s, chunk, fresh, nullptr, 1); ++stat.tallied; }
    s.left[i] = left; s.right[i] = right; s.top[i] = top; s.bottom[i] = bottom;
    s.nodeType[i] = D(nodes);
    s.sigNodes[i] = nodes; s.sigCap[i] = cap; s.sigBump[i] = bump;
}
// Dispatch 1, end of a record chunk: the chunk's inserted records bucketed by the z strip they sit in, ascending by record
// slot inside a bucket; records that span several strips go to the chunk's multi list. One entry per record per list, so
// the fixed per-chunk capacity (the chunk's record range) can never overflow.
void GridBucketChunk(GridJob& job, U chunk, U begin, U end) {
    GridStore& s = *job.store;
    const GridIdentity& b = *job.next;
    U* const start = s.bucketStart + static_cast<size_t>(chunk) * (kGridStrips + 1);
    U* const singles = s.bucketSingle + static_cast<size_t>(chunk) * s.bucketCap;
    U* const multis = s.bucketMulti + static_cast<size_t>(chunk) * s.bucketCap;
    U cursor[kGridStrips + 1];
    memset(start, 0, sizeof(cursor));
    U multiCount = 0;
    for (U i = begin; i < end; ++i) {
        if (!b.inserted[i]) continue;
        const U first = GridStripOf(job, s.top[i]);
        if (first == GridStripOf(job, s.bottom[i])) ++start[first + 1]; else multis[multiCount++] = i;
    }
    for (U k = 0; k < kGridStrips; ++k) start[k + 1] += start[k];
    memcpy(cursor, start, sizeof(cursor));
    for (U i = begin; i < end; ++i) {
        if (!b.inserted[i]) continue;
        const U first = GridStripOf(job, s.top[i]);
        if (first == GridStripOf(job, s.bottom[i])) singles[cursor[first]++] = i;
    }
    s.stats[chunk].multis = multiCount;
}
#ifdef NTW2_LOCO_ORACLE // bench-only per-chunk CPU accounting for the oracle's --grid-bench; compiled out of the runtime
LONGLONG g_dbg[8];
#define GRID_PROF_MARK(v) const LONGLONG v = Now()
#define GRID_PROF_ADD(slot, since) InterlockedExchangeAdd64(&g_dbg[slot], Now() - (since))
#else
#define GRID_PROF_MARK(v)
#define GRID_PROF_ADD(slot, since)
#endif
void GridCapturePhase(GridJob& job, U chunk) {
    GridStore& s = *job.store;
    const GridIdentity& b = *job.next;
    U begin, end;
    GRID_PROF_MARK(p0);
    GridRange(b.count, job.chunks, chunk, begin, end);
    for (U i = begin; i < end && !job.failure; ++i) {
        if (!job.incremental && i + kGridPrefetchNear < end) GridPrefetchNodes(b.record[i + kGridPrefetchNear]); // nodes are only read by a recompute
        if (i + kGridPrefetchFar < end) GridPrefetchRecord(job, b.record[i + kGridPrefetchFar]);
        if (job.incremental) GridCaptureRecordDelta(job, i, chunk); else GridCaptureRecord(job, i, chunk);
    }
    if (!job.failure) GridBucketChunk(job, chunk, begin, end);
    GRID_PROF_ADD(0, p0); GRID_PROF_MARK(p1);
    // Committed ordinals -> registry slots, split by worklist range. The registry hash is complete and read-only
    // during this dispatch; s.committed is read only by the build dispatch's finish chunks, after the join.
    if (job.committedCount) {
        const OwnedArena& arena = *g_owned;
        GridRange(job.committedCount, job.chunks, chunk, begin, end);
        for (U ordinal = begin; ordinal < end; ++ordinal) {
            if (arena.states[ordinal] != OwnedCommitted) continue;
            const U slot = GridSlot(s, *job.next, arena.worklist[ordinal]);
            if (slot < job.next->count) GridRaiseCommitted(s.committed[slot], ordinal + 1);
        }
    }
    GRID_PROF_ADD(1, p1);
}
// Dispatch 2, one task per run of active strips. Scan the run's cells in ascending order, turning each tallied cell
// into a row (consecutive offsets from the owner's exact bases) and zeroing stale entries of the previous publication;
// then scatter, in ascending record slot, every record that touches the run's z range. Rows and positions are owned
// by exactly one task, so each row's occupants ascend by slot whatever the chunk or task count.
void GridBuildTask(GridJob& job, U task) {
    GridStore& s = *job.store;
    const GridTask& t = job.task[task];
    const __m128i zero = _mm_setzero_si128();
    GRID_PROF_MARK(q0);
    U row = t.rowBase, position = t.memberBase;
    for (U a = t.first; a < t.last; ++a) {
        const U firstRow = job.active[a] * job.stripHeight;
        const U begin = firstRow << job.shift;
        const U end = (std::min)((std::min)(firstRow + job.stripHeight, job.maximum + 1) << job.shift, job.cells);
        if (job.incremental) { // counts are persistent (cnt); dense only gets the new row numbers and loses emptied cells
            for (U cell = begin; cell < end;) {
                if (cell + 4 <= end &&
                    _mm_movemask_epi8(_mm_and_si128(
                        _mm_cmpeq_epi32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(s.cnt + cell)), zero),
                        _mm_cmpeq_epi32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(s.dense + cell)), zero))) == 0xFFFF) {
                    cell += 4; continue;
                }
                const U count = s.cnt[cell];
                if (count) {
                    if (row >= t.rowEnd || position + count > t.memberEnd) { GridFail(job); return; }
                    s.cellIds[row] = cell; s.offsets[row] = position; s.fill[row] = position;
                    s.dense[cell] = row + 1; ++row; position += count;
                } else if (s.dense[cell]) s.dense[cell] = 0;
                ++cell;
            }
            continue;
        }
        for (U cell = begin; cell < end;) {
            if (cell + 4 <= end &&
                _mm_movemask_epi8(_mm_cmpeq_epi32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(s.dense + cell)), zero)) == 0xFFFF) {
                cell += 4; continue;
            }
            const U value = s.dense[cell];
            if (value & kGridTag) {
                const U count = value & ~kGridTag;
                if (row >= t.rowEnd || position + count > t.memberEnd) { GridFail(job); return; }
                s.cellIds[row] = cell; s.offsets[row] = position; s.fill[row] = position;
                s.dense[cell] = row + 1; ++row; position += count;
                if (s.cnt) s.cnt[cell] = count; // an incremental store keeps the counts for the next build
            } else if (value) { s.dense[cell] = 0; if (s.cnt) s.cnt[cell] = 0; }
            ++cell;
        }
    }
    GRID_PROF_ADD(2, q0); GRID_PROF_MARK(q1);
    if (row != t.rowEnd || position != t.memberEnd) { GridFail(job); return; }
    const U cap = s.bucketCap;
    for (U a = t.first; a < t.last; ++a) {
        const U strip = job.active[a], zLo = strip * job.stripHeight;
        const U zHi = (std::min)(zLo + job.stripHeight, job.maximum + 1) - 1;
        for (U c = 0; c < job.chunks; ++c) { // chunks ascend by record slot, and so do both lists inside a chunk
            const U* const start = s.bucketStart + static_cast<size_t>(c) * (kGridStrips + 1);
            const U* single = s.bucketSingle + static_cast<size_t>(c) * cap + start[strip];
            const U* const singleEnd = s.bucketSingle + static_cast<size_t>(c) * cap + start[strip + 1];
            const U* multi = s.bucketMulti + static_cast<size_t>(c) * cap;
            const U* const multiEnd = multi + s.stats[c].multis;
            for (;;) {
                while (multi != multiEnd && (s.bottom[*multi] < zLo || s.top[*multi] > zHi)) ++multi;
                U i;
                if (single != singleEnd && (multi == multiEnd || *single < *multi)) i = *single++;
                else if (multi != multiEnd) i = *multi++;
                else break;
                const U last = (std::min)(s.bottom[i], zHi);
                for (U z = (std::max)(s.top[i], zLo); z <= last; ++z) for (U x = s.left[i]; x <= s.right[i]; ++x) {
                    const U r = s.dense[(z << job.shift) + x] - 1;
                    if (r < t.rowBase || r >= t.rowEnd) { GridFail(job); return; }
                    const U to = s.fill[r]++;
                    if (to >= t.memberEnd) { GridFail(job); return; }
                    s.occupants[to] = i;
                }
            }
        }
    }
    GRID_PROF_ADD(3, q1);
}
// Owner step between the dispatches: per-chunk strip totals -> exact membership and row totals -> active strips (new
// members or stale rows of the previous publication) -> weight-balanced tasks, each with exact row/offset bases.
// O(chunks * strips) words. False = capacity refusal or inconsistent totals, before anything is published.
bool GridPlan(GridJob& job) {
    const GridStore& s = *job.store;
    long long members = 0, rows = 0;
    for (U k = 0; k < job.strips; ++k) {
        // An incremental build's chunk tables are signed deltas on top of the previous publication's strip totals.
        long long m = job.incremental ? s.totalMembers[k] : 0, r = job.incremental ? s.totalRows[k] : 0;
        for (U c = 0; c < job.chunks; ++c) {
            m += static_cast<LONG>(s.stripMembers[c * kGridStrips + k]); r += static_cast<LONG>(s.stripRows[c * kGridStrips + k]);
        }
        if (m < 0 || r < 0) return false;
        job.stripMembers[k] = static_cast<U>(m); job.stripRows[k] = static_cast<U>(r); members += m; rows += r;
    }
    if (members > s.cap.memberships || rows > s.rowCap) return false;
    job.members = static_cast<U>(members); job.rows = static_cast<U>(rows);
    const unsigned long long scanWeight = ((static_cast<unsigned long long>(job.stripHeight) << job.shift) >> 5) + 1;
    unsigned long long cumulative[kGridStrips + 1], weight = 0;
    U count = 0;
    for (U k = 0; k < job.strips; ++k) {
        if (!job.stripMembers[k] && !s.stripLive[k]) continue;
        job.active[count] = k; cumulative[count++] = weight; weight += job.stripMembers[k] + scanWeight;
    }
    cumulative[count] = weight;
    const U tasks = (std::min)(count, (std::min)(kGridMaxTasks, 2 * job.chunks));
    U cut[kGridMaxTasks + 1];
    cut[0] = 0;
    for (U g = 1; g < tasks; ++g) { // non-empty groups; each cut at the first strip reaching g/tasks of the weight
        U position = cut[g - 1] + 1;
        const unsigned long long target = weight * g / tasks;
        while (position < count - (tasks - g) && cumulative[position] < target) ++position;
        cut[g] = position;
    }
    cut[tasks] = count;
    U rowBase = 0, memberBase = 0;
    for (U g = 0; g < tasks; ++g) {
        GridTask& t = job.task[g];
        t.first = cut[g]; t.last = cut[g + 1]; t.rowBase = rowBase; t.memberBase = memberBase;
        for (U a = t.first; a < t.last; ++a) { rowBase += job.stripRows[job.active[a]]; memberBase += job.stripMembers[job.active[a]]; }
        t.rowEnd = rowBase; t.memberEnd = memberBase;
    }
    job.tasks = tasks; job.activeStrips = count;
    return true;
}
// Build dispatch, record-chunk tasks: birth incarnations in record order, registry removals and source accounting.
void GridFinishPhase(GridJob& job, U chunk) {
    GridStore& s = *job.store;
    GridIdentity& b = *job.next;
    const GridIdentity& old = *job.old;
    GridChunkStat& stat = s.stats[chunk];
    U begin, end;
    GridRange(b.count, job.chunks, chunk, begin, end);
    U incarnation = job.incarnationBase + stat.birthBase;
    // Births take incarnations in record order. Result-buffer vs live-record read accounting rides the same pass: pose
    // values published by capture always come from the live record, and a committed result counts as "direct" only
    // while the record still equals the worker's stored pose (and serial).
    for (U i = begin; i < end; ++i) {
        if (!b.record[i]) continue;
        if (!b.incarnation[i]) b.incarnation[i] = ++incarnation;
        const U committed = s.committed[i];
        bool direct = false;
        if (committed && g_owned) {
            const OwnedSlot& slot = g_owned->slots[committed - 1];
            U pose[5];
            memcpy(&pose[0], &s.x[i], sizeof(U)); memcpy(&pose[1], &s.y[i], sizeof(U)); memcpy(&pose[2], &s.z[i], sizeof(U));
            memcpy(&pose[3], &s.extent[i], sizeof(U)); memcpy(&pose[4], &s.radius[i], sizeof(U));
            direct = GuardWord<0x2C>(slot) == b.serial[i] && OutputWord<0x48>(slot) == pose[0] && OutputWord<0x4C>(slot) == pose[1] &&
                OutputWord<0x50>(slot) == pose[2] && OutputWord<0x54>(slot) == pose[3] && GuardWord<0x58>(slot) == pose[4];
        }
        if (direct) ++stat.committed; else ++stat.fromRecord;
    }
    GridRange(old.count, job.chunks, chunk, begin, end);
    U removed = 0;
    for (U i = begin; i < end; ++i) if (old.record[i]) {
        if (job.stable) { removed += b.serial[i] != old.serial[i]; continue; } // same slot, same record
        const U slot = GridSlot(s, b, old.record[i]);
        removed += slot == kNoSlot || b.serial[slot] != old.serial[i];
    }
    stat.removed = removed;
}
// Optional separate dispatch: compare every native chain with the published identity. Never part of the build.
void GridVerifyPhase(GridJob& job, U chunk) {
    const GridStore& s = *job.store;
    U begin, end;
    GridRange(job.cells, job.chunks, chunk, begin, end);
    U members = 0;
    for (U cell = begin; cell < end && !job.failure; ++cell) {
        U previous = 0, node = D(job.nativeCells + cell * 4);
        while (node) {
            if (++members > s.cap.memberships) { GridMismatch(job); break; }
            const U owner = D(node + 12), slot = GridSlot(s, *job.next, owner);
            if (slot == kNoSlot || D(node) != 8 || D(node + 8) != owner + 0x30 ||
                D(node + 4) != D(owner + 0x2C) || D(node + 16) != previous ||
                D(node + 24) != job.nativeCells + cell * 4) { GridMismatch(job); break; }
            const U offset = node - D(owner + 0xA8);
            if (offset % 0x1C || offset / 0x1C >= D(owner + 0xAC)) { GridMismatch(job); break; }
            previous = node; node = D(node + 20);
        }
    }
    _InterlockedExchangeAdd(&job.nativeMembers, static_cast<LONG>(members));
}
void __fastcall GridChunk(void* context, U chunk) {
    GridJob& job = *static_cast<GridJob*>(context);
    // Only capture touches floating point (native FISTP cell bounds follow the owner's rounding mode).
    const bool floating = job.phase == GridPhaseCapture;
    const U saved = _mm_getcsr(); unsigned short cw = 0, ownerCw = job.cw;
    if (floating) {
        __asm { fnstcw cw }
        _mm_setcsr(job.mxcsr);
        __asm { fldcw ownerCw }
    }
    __try {
        __try {
            switch (job.phase) {
            case GridPhaseCapture: GridCapturePhase(job, chunk); break;
            case GridPhaseBuild:
                if (chunk < job.tasks) GridBuildTask(job, chunk); else GridFinishPhase(job, chunk - job.tasks);
                break;
            default: GridVerifyPhase(job, chunk); break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_gridWords[GridFaults]));
            _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_gridV2Words[GridV2Faults])); GridFail(job);
        }
    } __finally {
        if (floating) {
            __asm { fnclex }
            __asm { fldcw cw }
            _mm_setcsr(saved);
        }
    }
}
void GridDispatch(GridJob& job, U phase, U count) {
    job.phase = phase;
    if (!job.shadow) { ++g_gridV2Words[GridV2Dispatches]; ++g_gridBuildWords[GridBuildDispatches]; }
    const LONGLONG start = Now();
    if (g_binding.dispatch) g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&GridChunk)), count, &job);
    else for (U i = 0; i < count; ++i) GridChunk(&job, i);
    job.wallTicks[phase] += Now() - start;
}
// Serial identity pass for a changed registry: primary slots keep their registry index (null holes included), unique
// secondary records follow. Fills the next identity's record array and open-addressed hash. False = refusal.
bool GridRegistryPass(GridStore& s, GridIdentity& next, U primaryBase, U primary, U secondaryBase, U secondary) {
    memset(next.hash, 0, static_cast<size_t>(s.hashSize) * sizeof(U));
    const U hashMask = s.hashSize - 1, tagMask = ~s.slotMask;
    U* const hash = next.hash;
    for (U domain = 0; domain < 2; ++domain) {
        const U count = domain ? secondary : primary, records = domain ? secondaryBase : primaryBase;
        for (U n = 0; n < count; ++n) {
            if (n + 8 < count) {
                const U ahead = D(records + (n + 8) * 4);
                if (ahead) _mm_prefetch(reinterpret_cast<const char*>(hash + (GridHash(ahead) & hashMask)), _MM_HINT_T0);
            }
            const U record = D(records + n * 4);
            if (!record) { // primary null holes keep their registry index; secondary holes are skipped
                if (domain) continue;
                if (next.count == s.cap.records) return false;
                const U i = next.count++;
                next.record[i] = 0; s.committed[i] = 0;
                continue;
            }
            // One probe both finds an existing identity and locates the insertion slot.
            const U product = GridHash(record);
            U h = product & hashMask;
            bool duplicate = false;
            for (U entry; (entry = hash[h]) != 0; h = (h + 1) & hashMask)
                if (!((entry ^ product) & tagMask) && next.record[(entry & s.slotMask) - 1] == record) { duplicate = true; break; }
            if (duplicate) { if (!domain) return false; continue; }
            if (next.count == s.cap.records) return false;
            const U i = next.count++;
            next.record[i] = record; s.committed[i] = 0;
            hash[h] = (product & tagMask) | (i + 1);
        }
    }
    return true;
}
enum GridFallback : U { FallbackNone, FallbackFirst, FallbackRegistry, FallbackGeometry, FallbackShare };
// Break-even of the incremental build (percent of records whose cell rectangle changed in one stage); calibrated with the
// realistic fixture of the oracle (--grid-bench). Above it the next build or builds run in full, with exponential backoff.
constexpr U kGridIncrementalMaxPercent = 35;
struct GridBuildReport { U births, removed, reused, deactivations, removals, committed, fromRecord, changed, tallied; };
// One build of `s`. shadow = diagnostic full rebuild into the shadow store: no process-wide accounting, no registry
// sharing, never incremental. False = refusal or failed build (nothing published); `view` is written only on success.
bool GridBuild(GridStore& s, U manager, bool shadow, U incarnationBase, GridBuildReport& report, GridView& view) {
    GridIdentity& old = s.id[s.current];
    GridIdentity& next = s.id[s.current ^ 1];
    const LONGLONG captureStart = Now();
    GridJob job = {}; job.store = &s; job.next = &next; job.old = &old; job.shadow = shadow;
    const U root = D(manager), model = root ? D(root + 8) : 0, grid = model ? D(model + 0xA4) : 0;
    if (!grid || model != g_gridModel) return false;
    job.shift = D(grid + 8); job.origin = D(grid + 0x10); job.maximum = D(grid + 0x14);
    if (job.shift > 20 || job.maximum >= (1u << job.shift)) return false;
    const unsigned long long cells = (static_cast<unsigned long long>(job.maximum) << job.shift) + job.maximum + 1;
    if (cells > s.cap.cells) return false;
    job.cells = static_cast<U>(cells); job.nativeCells = D(grid); job.scale = Float(grid + 0x24);
    job.bump = Float(V(0x1318038)); job.mxcsr = _mm_getcsr(); unsigned short cw;
    __asm { fnstcw cw }
    job.cw = cw; job.chunks = s.chunks;
    job.geometry = {job.scale, job.bump, job.origin, job.maximum};
    GridGeometry geometry = {job.shift, job.origin, job.maximum, job.nativeCells, model, 0, 0, job.mxcsr & 0xFFC0u, job.cw};
    memcpy(&geometry.scaleBits, &job.scale, sizeof(U)); memcpy(&geometry.bumpBits, &job.bump, sizeof(U));
    const U primary = D(manager + 0x24C), secondary = D(manager + 0x278);
    // Fixed capacities: an oversized registry refuses here, before any build step or game write.
    if (primary > s.cap.primary || secondary > s.cap.records) return false;
    next.count = next.memberships = next.occupied = 0; next.epoch = old.epoch + 1;
    const U primaryBase = D(manager + 0x250), secondaryBase = D(manager + 0x27C);
    job.stable = !shadow && s.regValid && primary == s.regPrimary && secondary == s.regSecondary &&
        SameWords(P(primaryBase), old.record, primary) && SameWords(P(secondaryBase), s.rawSecondary, secondary);
    if (job.stable) { // word-identical registries: identical record array and hash, every record keeps its slot
        next.reg = old.reg; next.record = old.record; next.hash = old.hash; next.count = old.count;
        memset(s.committed, 0, static_cast<size_t>(next.count) * sizeof(U));
    } else {
        s.regValid = false; // restored only by a completed publication
        next.reg = old.reg ^ 1; next.record = s.regRecord[next.reg]; next.hash = s.regHash[next.reg];
        s.regPrimary = primary; s.regSecondary = secondary;
        if (secondary) memcpy(s.rawSecondary, P(secondaryBase), static_cast<size_t>(secondary) * sizeof(U));
        if (!GridRegistryPass(s, next, primaryBase, primary, secondaryBase, secondary)) return false;
    }
    const LONGLONG registryEnd = Now();
    job.committedCount = g_stage && g_gridCommittedReady && g_owned && g_owned->count <= g_owned->slotCapacity ? g_owned->count : 0;
    job.incarnationBase = incarnationBase;
    job.stripHeight = (job.maximum + 1 + kGridStrips - 1) / kGridStrips;
    job.strips = (job.maximum + job.stripHeight) / job.stripHeight;
    { unsigned long bit; job.stripBits = (job.stripHeight & (job.stripHeight - 1)) == 0 && _BitScanForward(&bit, job.stripHeight) ? bit : 32u; }
    // Incremental or full: the patch needs the previous publication's counts, rectangles and dense map to be intact, the same
    // registry slots, the same geometry and rounding, and a recent change share below the break-even.
    U reason = FallbackNone;
    if (s.incremental && !shadow) {
        if (!s.incValid) reason = FallbackFirst;
        else if (!job.stable) reason = FallbackRegistry;
        else if (memcmp(&geometry, &s.geometry, sizeof(geometry)) != 0) reason = FallbackGeometry;
        else if (s.hold) { --s.hold; reason = FallbackShare; }
        job.incremental = reason == FallbackNone;
    }
    s.incValid = false; // restored only by a completed publication
    // Dense-map invariant: words outside the previous publication's live strips are zero. An interrupted build or a
    // different strip geometry voids it, so the map is cleared whole (rare; never on the normal path).
    bool anyLive = false;
    for (const bool live : s.stripLive) anyLive |= live;
    if (s.denseDirty || (anyLive && (s.liveStripHeight != job.stripHeight || s.liveShift != job.shift))) {
        memset(s.dense, 0, static_cast<size_t>(s.cap.cells) * sizeof(U));
        if (s.cnt) memset(s.cnt, 0, static_cast<size_t>(s.cap.cells) * sizeof(U));
        memset(s.stripLive, 0, sizeof(s.stripLive));
    }
    s.denseDirty = true; // from here the map holds tallies; only a completed publication clears this
    memset(s.stats, 0, static_cast<size_t>(job.chunks) * sizeof(GridChunkStat));
    memset(s.stripMembers, 0, static_cast<size_t>(job.chunks) * kGridStrips * sizeof(U));
    memset(s.stripRows, 0, static_cast<size_t>(job.chunks) * kGridStrips * sizeof(U));
    const U captureUs = Microseconds(Now() - captureStart);
    if (!shadow) { g_gridWords[GridCaptureUs] += captureUs; g_parallelWords[ParallelCaptureUs] += captureUs; }
    LONGLONG verifyTicks = 0;
    GridDispatch(job, GridPhaseCapture, job.chunks);
    if (!job.failure) {
        U births = 0;
        for (U c = 0; c < job.chunks; ++c) { s.stats[c].birthBase = births; births += s.stats[c].births; }
        if (!GridPlan(job)) GridFail(job); // fixed capacity: refuse, publish nothing
        else {
            next.memberships = job.members;
            GridDispatch(job, GridPhaseBuild, job.tasks + job.chunks);
            if (!job.failure) { s.offsets[job.rows] = job.members; next.occupied = job.rows; }
        }
    }
    if (!job.failure && !shadow && g_binding.verify_grid) {
        const LONGLONG verifyStart = Now();
        GridDispatch(job, GridPhaseVerify, job.chunks);
        verifyTicks = Now() - verifyStart;
        if (!job.failure && static_cast<U>(job.nativeMembers) != next.memberships) GridMismatch(job);
    }
    // Normal build time is everything the owner spends from entry to the published view (serial registry/identity
    // construction and strip planning included); only the optional verification dispatch is excluded.
    const LONGLONG buildTicks = Now() - captureStart - verifyTicks;
    const U buildUs = Microseconds(buildTicks);
    report = {};
    for (U c = 0; c < job.chunks; ++c) {
        const GridChunkStat& stat = s.stats[c];
        report.committed += stat.committed; report.fromRecord += stat.fromRecord; report.births += stat.births;
        report.reused += stat.reused; report.deactivations += stat.deactivations; report.removals += stat.removals;
        report.removed += stat.removed; report.changed += stat.changed; report.tallied += stat.tallied;
    }
    if (!shadow) {
        g_gridV2Words[GridV2BuildUs] += buildUs;
        g_gridV2Words[GridV2MaxBuildUs] = (std::max)(g_gridV2Words[GridV2MaxBuildUs], buildUs);
        g_gridV2Words[GridV2VerifyUs] += Microseconds(verifyTicks);
        const U csrUs = buildUs > captureUs ? buildUs - captureUs : 0; // dispatches plus the owner step between them
        g_gridWords[GridCsrUs] += csrUs; g_parallelWords[ParallelCsrUs] += csrUs;
        g_gridWords[GridMismatches] += static_cast<U>(job.mismatches);
        g_gridWords[GridUnsupported] += static_cast<U>(job.unsupported);
        g_gridV2Words[GridV2VerifyMismatches] += static_cast<U>(job.mismatches);
        g_gridV2Words[GridV2CommittedRecords] += report.committed; g_gridV2Words[GridV2RecordReads] += report.fromRecord;
        g_gridWords[GridBirths] += report.births; g_gridWords[GridReused] += report.reused;
        g_gridWords[GridDeactivations] += report.deactivations; g_gridWords[GridMembershipRemovals] += report.removals;
    }
    if (job.failure) return false;
    s.regValid = true;
    s.denseDirty = false; s.liveStripHeight = job.stripHeight; s.liveShift = job.shift;
    for (U k = 0; k < kGridStrips; ++k) s.stripLive[k] = k < job.strips && job.stripRows[k] != 0;
    if (s.incremental) { // the next build may patch: counts, rectangles, totals and geometry all describe this publication
        memcpy(s.totalMembers, job.stripMembers, sizeof(s.totalMembers)); memcpy(s.totalRows, job.stripRows, sizeof(s.totalRows));
        s.geometry = geometry; s.incValid = true;
        if (job.incremental) {
            if (static_cast<unsigned long long>(report.tallied) * 100 > static_cast<unsigned long long>(kGridIncrementalMaxPercent) * next.count) {
                s.holdLevel = (std::min)(s.holdLevel + 1, 4u); s.hold = (1u << s.holdLevel) - 1;
            } else s.holdLevel = s.hold = 0;
        }
    }
    if (!shadow) {
        g_gridBuildWords[GridBuildRegistryReuses] += job.stable;
        g_gridBuildTicks[0] += registryEnd - captureStart; g_gridBuildTicks[1] += job.wallTicks[GridPhaseCapture];
        g_gridBuildTicks[3] += job.wallTicks[GridPhaseBuild];
        g_gridBuildTicks[2] += buildTicks - (registryEnd - captureStart) - job.wallTicks[GridPhaseCapture] - job.wallTicks[GridPhaseBuild];
        if (job.incremental) { ++g_gridBuildWords[GridBuildIncremental]; g_gridBuildWords[GridBuildChanged] += report.tallied; }
        else {
            ++g_gridBuildWords[GridBuildFull];
            if (s.incremental) { ++g_gridBuildWords[GridBuildFallbacks]; g_gridBuildWords[GridBuildFallbackReason] = reason; }
        }
        g_incarnation += report.births; // numbers are consumed only by a publication that actually happens
        g_gridWords[GridRemovals] += report.removed;
        ++g_gridWords[GridCaptures]; g_gridWords[GridRecords] += next.count;
        g_gridWords[GridPrimary] += primary; g_gridWords[GridSecondary] += next.count - primary;
        g_gridWords[GridMemberships] += next.memberships; g_gridWords[GridCells] += next.occupied;
        g_gridWords[GridMaxRecords] = (std::max)(g_gridWords[GridMaxRecords], next.count);
        g_gridWords[GridMaxMemberships] = (std::max)(g_gridWords[GridMaxMemberships], next.memberships);
        ++g_gridV2Words[GridV2Builds]; g_gridV2Words[GridV2Records] += next.count;
        g_gridV2Words[GridV2Memberships] += next.memberships; g_gridV2Words[GridV2Epoch] = next.epoch;
        g_gridWords[GridEpoch] = next.epoch;
    }
    s.current ^= 1;
    view = {g_generation, next.epoch, next.count, next.occupied, next.memberships,
        next.record, next.serial, next.incarnation, s.team, s.flags,
        s.x, s.z, s.y, s.extent, s.radius, s.left, s.right, s.top, s.bottom,
        next.inserted, s.cellIds, s.offsets, s.occupants, next.active,
        manager, model, D(model + 0x58), primary, secondary, primaryBase, secondaryBase,
        grid, job.nativeCells, job.cells, job.shift, job.origin, job.maximum, job.scale, s.dense, s.nodeType};
    return true;
}
// Bit-for-bit comparison of two publications (identity, snapshot, rectangles, node types, CSR and the direct-address map).
// The epoch is a build counter, not derived data: a refused shadow rebuild leaves it one behind the primary's.
bool GridViewsEqual(const GridView& a, const GridView& b) {
    if (a.count != b.count || a.cells != b.cells || a.memberships != b.memberships || a.cell_count != b.cell_count) return false;
    const auto same = [](const void* x, const void* y, U words) { return !words || !memcmp(x, y, static_cast<size_t>(words) * sizeof(U)); };
    const U n = a.count;
    return same(a.record, b.record, n) && same(a.serial, b.serial, n) && same(a.incarnation, b.incarnation, n) &&
        same(a.team, b.team, n) && same(a.flags, b.flags, n) && same(a.x, b.x, n) && same(a.z, b.z, n) && same(a.y, b.y, n) &&
        same(a.extent, b.extent, n) && same(a.radius, b.radius, n) && same(a.left, b.left, n) && same(a.right, b.right, n) &&
        same(a.top, b.top, n) && same(a.bottom, b.bottom, n) && same(a.inserted, b.inserted, n) && same(a.active, b.active, n) &&
        same(a.node_type, b.node_type, n) && same(a.cell_ids, b.cell_ids, a.cells) && same(a.offsets, b.offsets, a.cells + 1) &&
        same(a.occupants, b.occupants, a.memberships) && same(a.cell_dense, b.cell_dense, a.cell_count);
}
bool CaptureGridImpl(U manager) {
    GridStore& s = *g_grid;
    const U incarnationBase = g_incarnation;
    GridBuildReport report;
    if (!GridBuild(s, manager, false, incarnationBase, report, g_gridView)) return false;
    if (g_gridShadow) { // --loco-grid-incremental --loco-grid-verify: the full build of the same state must be identical
        GridBuildReport expected; GridView shadowView = {};
        const bool same = GridBuild(*g_gridShadow, manager, true, incarnationBase, expected, shadowView) &&
            GridViewsEqual(g_gridView, shadowView) && report.births == expected.births && report.removed == expected.removed &&
            report.reused == expected.reused && report.deactivations == expected.deactivations && report.removals == expected.removals &&
            report.committed == expected.committed && report.fromRecord == expected.fromRecord;
        ++g_gridBuildWords[GridBuildShadowCompares]; g_gridBuildWords[GridBuildShadowMismatches] += !same;
    }
    return true;
}

// Only integer operations: the service thunks preserve flags and ALL integer
// registers, and neither this recorder nor its callees touch x87/MXCSR/XMM.
// In particular, no arbitrary observer callback can perturb live mover values.
__declspec(naked) void __stdcall RecordService(U, U) {
    __asm {
        mov eax, dword ptr [esp + 4]
        inc dword ptr [g_words + ServiceCalls * 4]
        inc dword ptr [g_words + eax * 4 + ServiceUnlinkGrid * 4]
        inc dword ptr [g_entityServices]
        mov edx, dword ptr [g_traceCount]
        cmp edx, 256
        jae trace_full
        lea ecx, [g_trace + edx * 8]
        mov dword ptr [ecx], eax
        mov eax, dword ptr [esp + 8]
        mov dword ptr [ecx + 4], eax
        inc dword ptr [g_traceCount]
        ret 8
    trace_full:
        inc dword ptr [g_words + TraceOverflow * 4]
        ret 8
    }
}

void ServiceExit(); // defined below as a naked function (the attribute belongs on the definition only)
__declspec(noinline) void __stdcall BeginService(U service, U* returnSlot, U receiver) {
#ifdef NTW2_LOCO_ORACLE
    ObserveOwned(g_stageEntity ? g_stageEntity : receiver - (service == WrapperQuery ? 0xF4 : 0),
        service, g_stageOrdinal, OwnedTestSerial);
#endif
    if (g_serviceDepth == kServiceFrames) {
        ++g_timingWords[TimingOverflows];
        return; // no return-address substitution: execute the original exactly once
    }
    ServiceFrame& frame = g_serviceFrames[g_serviceDepth];
    frame.returnAddress = *returnSlot;
    frame.service = service;
    if (!QueryPerformanceCounter(&frame.start)) {
        ++g_timingWords[TimingQpcFailures];
        return;
    }
    ++g_serviceDepth;
    if (g_serviceDepth > g_timingWords[TimingMaxDepth]) g_timingWords[TimingMaxDepth] = g_serviceDepth;
    *returnSlot = Address(reinterpret_cast<void*>(&ServiceExit));
    if (g_shadowEnabled) {
        if (service == Sweep)
            ntw2_sweep::ShadowBefore(reinterpret_cast<ntw2_sweep::Agent*>(receiver),
                reinterpret_cast<ntw2_sweep::Scratch*>(returnSlot[1]),
                reinterpret_cast<const ntw2_sweep::Aabb*>(returnSlot[2]), returnSlot[3]);
        else if (service == Resolve)
            ntw2_resolve::ShadowBefore(reinterpret_cast<ntw2_resolve::Agent*>(receiver),
                reinterpret_cast<ntw2_resolve::Scratch*>(returnSlot[1]),
                reinterpret_cast<const ntw2_resolve::Aabb*>(returnSlot[2]));
        else if (service == HeightOwner)
            ntw2_env::ShadowBefore(reinterpret_cast<ntw2_env::Agent*>(receiver),
                reinterpret_cast<ntw2_env::Scratch*>(returnSlot[1]));
    }
}
__declspec(noinline) U __stdcall EndService(U originalReturn) {
    LARGE_INTEGER end;
    const bool clockOk = QueryPerformanceCounter(&end) != FALSE;
    const ServiceFrame frame = g_serviceFrames[--g_serviceDepth];
    if (clockOk && end.QuadPart >= frame.start.QuadPart) {
        const auto ticks = static_cast<unsigned long long>(end.QuadPart - frame.start.QuadPart);
        _InterlockedIncrement(&g_timingSequence);
        ++g_timingWords[TimingCalls];
        ++g_timingWords[TimingServiceCalls + frame.service];
        g_timingTotals.service[frame.service] += ticks;
        if (ticks > g_timingTotals.maximum[frame.service]) g_timingTotals.maximum[frame.service] = ticks;
        if (!g_serviceDepth) g_timingTotals.serviceUnion += ticks;
        _InterlockedIncrement(&g_timingSequence);
    } else ++g_timingWords[TimingQpcFailures];
    if (g_shadowEnabled) {
        if (frame.service == Sweep) ntw2_sweep::ShadowAfter();
        else if (frame.service == Resolve) {
            ntw2_resolve::ObserveOriginalInout(g_originalInout);
            ntw2_resolve::ShadowAfter(static_cast<uint8_t>(originalReturn));
        }
        else if (frame.service == HeightOwner) ntw2_env::ShadowAfter();
    }
    return frame.returnAddress;
}
// Same post-cleanup return-slot technique as runtime SiteExit/SITE_THUNK.
// Preserve every native result register, EFLAGS, x87 stack/control and SSE state.
// The original callee, not this trampoline, still performs its RET n cleanup.
__declspec(naked) void ServiceExit() {
    __asm push eax
    __asm mov al, byte ptr [esp-4]
    __asm mov byte ptr [g_originalInout], al
    __asm pop eax
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm push dword ptr [ebp+28]
    __asm call EndService
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
void AbandonServiceFrames(U base) {
    // An exception may unwind past a substituted return. Discard those timer
    // frames at the enclosing invocation's finally seam; never replay services.
    if (g_serviceDepth > base) {
        g_timingWords[TimingAbandoned] += g_serviceDepth - base;
        g_serviceDepth = base;
        ntw2_sweep::Abandon(); ntw2_resolve::Abandon(); ntw2_env::Abandon();
    }
}
void RecordCloneTime(LONGLONG ticks) {
    if (!g_timingEnabled) return;
    if (ticks < 0) { ++g_timingWords[TimingQpcFailures]; return; }
    _InterlockedIncrement(&g_timingSequence);
    g_timingTotals.cloneWall += static_cast<unsigned long long>(ticks);
    _InterlockedIncrement(&g_timingSequence);
}
#define LOCO_SERVICE(name, index, offset) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm push ecx \
        __asm push index \
        __asm call RecordService \
        __asm cmp byte ptr [g_timingEnabled], 0 \
        __asm je name##Untimed \
        __asm cmp dword ptr [g_runDepth], 0 \
        __asm je name##Untimed \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm lea eax, [ebp+36] \
        __asm push dword ptr [ebp+24] \
        __asm push eax \
        __asm push index \
        __asm call BeginService \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm name##Untimed: \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [g_serviceTargets + offset] \
    }
LOCO_SERVICE(UnlinkGridGate, 0, 0)
LOCO_SERVICE(UnlinkOwnerGate, 1, 4)
LOCO_SERVICE(InsertOwnerGate, 2, 8)
LOCO_SERVICE(InsertGridGate, 3, 12)
LOCO_SERVICE(SweepGate, 4, 16)
LOCO_SERVICE(ResolveGate, 5, 20)
LOCO_SERVICE(HeightOwnerGate, 6, 24)
LOCO_SERVICE(WrapperQueryGate, 7, 28)
#undef LOCO_SERVICE

void RefuseOwned(U reason, U detail = 0) {
    g_ownedOccurrence->reason = reason;
    g_ownedOccurrence->detail = detail;
    RaiseException(kOwnedUnsupported, EXCEPTION_NONCONTINUABLE, 0, nullptr);
}
// The native MOVE decides whether F0 actually clamps the integrated position.
// Refuse only its reached +70 callback, before the unclosed holder/NODE effects.
void __fastcall OwnedClamp(void*, void*) {
    RefuseOwned(OwnedNeedsStaging, OwnedDetailClampCallback);
}
// Class-wrapper phase 2. The participant's LOCO_CLASS_WRAP clone calls this instead of the selector 0x62A290: the private
// MOVE/WRAP clone, then the selector's post-move A3 test (zero would stage: refused before the child loop).
void __fastcall OwnedSelect(void* receiver, void*) {
    OwnedParticipant& participant = *g_ownedParticipant;
    Call(participant.clones.entries[participant.cwWrapper ? NTW2_CLONE_LOCO_WRAP : NTW2_CLONE_LOCO_MOVE], Address(receiver));
    if (!static_cast<const unsigned char*>(receiver)[0xA3])
        RefuseOwned(OwnedNeedsStaging, participant.cwInitialA3 ? OwnedDetailResultA3 : OwnedDetailInitialA3);
}
// Proxy child slot 0x36 (thiscall, 1 arg, RET 4): exactly 0x5E4C60 (word [arg0] = word [0x14A51A0], returns arg0); the
// served word is recorded and re-checked at commit.
U __fastcall OwnedChildHeading(const U* proxy, void*, unsigned short* out) {
    CwEvent& event = g_owned->cwEvents[g_ownedParticipant->cwBase + proxy[1]];
    const unsigned short word = *reinterpret_cast<const unsigned short*>(static_cast<uintptr_t>(V(0x14A51A0)));
    event.word = word; event.served = 1;
    *out = word;
    return Address(out);
}
// Proxy child slot 1 (thiscall, 2 args, RET 8): records the 0x80BAC0 arguments; the owner replays the native call.
void __fastcall OwnedChildSubmit(const U* proxy, void*, const float* pose, U heading) {
    CwEvent& event = g_owned->cwEvents[g_ownedParticipant->cwBase + proxy[1]];
    if (event.submitted) RefuseOwned(OwnedNeedsClassWrapper);
    memcpy(event.pose, pose, sizeof(event.pose));
    event.heading = heading; event.submitted = 1;
}
// Every other proxy slot: never reached by 0x5B2CA0's general/skip arms; refuse rather than guess.
void __fastcall OwnedChildTrap(void*, void*) { RefuseOwned(OwnedNeedsClassWrapper); }
// Participant clone calls obey the original thiscall ABI. No blanket register/FP save is needed:
// these are real replacement callees, not instrumentation inserted into an instruction stream.
__forceinline void OwnedService(Service service, void* receiver) {
    OwnedCurrent& occurrence = *g_ownedOccurrence;
    if (occurrence.serviceCount == 8 ||
        Address(receiver) != Address(g_ownedParticipant->work) + (service == WrapperQuery ? 0xF4 : 0))
        RefuseOwned(OwnedNeedsCapacity);
    occurrence.services |= service << (4 * occurrence.serviceCount++);
#ifdef NTW2_LOCO_ORACLE
    ObserveOwned(occurrence.entity, service, occurrence.ordinal, OwnedTestPort);
#endif
}
template <Service service> void __fastcall OwnedLink(void* agent, void*) {
    OwnedService(service, agent);
    if (service == UnlinkOwner) *reinterpret_cast<U*>(static_cast<unsigned char*>(agent) + 0x98) = 0;
}
U __fastcall OwnedQuery(void* descriptor, void*) {
    OwnedService(WrapperQuery, descriptor);
    return reinterpret_cast<U (__thiscall*)(void*)>(g_serviceTargets[WrapperQuery])(descriptor);
}
void __fastcall OwnedSweep(void* agent, void*, void* scratch, const ntw2_sweep::Aabb* box, U mode) {
    OwnedService(Sweep, agent);
    if (mode & 8) RefuseOwned(OwnedNeedsEnv);
    if (!ntw2_sweep::WorkerSweep(g_ownedParticipant->ctx->sweep, agent,
        g_ownedOccurrence->entity, scratch, *box, mode)) RefuseOwned(OwnedNeedsSweep);
}
uint8_t __fastcall OwnedResolve(void* agent, void*, void* scratch, const ntw2_resolve::Aabb* box) {
    OwnedService(Resolve, agent);
    uint8_t result = 0;
    if (!ntw2_resolve::WorkerResolve(g_ownedParticipant->ctx->resolve, agent,
        g_ownedOccurrence->entity, scratch, *box, result)) RefuseOwned(OwnedNeedsResolve);
    return result;
}
void __fastcall OwnedEnvironment(void* agent, void*, void* scratch) {
    OwnedService(HeightOwner, agent);
    if (!ntw2_env::WorkerEnv(g_ownedParticipant->ctx->env, agent,
        g_ownedOccurrence->entity, scratch, g_ownedOccurrence->environment)) RefuseOwned(OwnedNeedsEnv);
    // Buildings/owner graph and transition callbacks have not had a live oracle
    // replay. Preserve owner execution rather than extrapolate the flat-terrain proof.
    if (g_ownedOccurrence->environment.event_count || D(Address(agent) + 0x10))
        RefuseOwned(OwnedNeedsEnv);
}
// Worker gates never enter native mutation/scratch closures. Four link services
// have no stack arguments or meaningful return value; their receiver is the
// entire argument contract. The admitted A1==0 closure normally emits none.
U __stdcall WorkerServiceTarget(U service, U receiver, U ownerGate) {
    WorkerOccurrence* occurrence = g_workerOccurrence;
    if (!occurrence) return ownerGate;
    if (service == WrapperQuery) { ++occurrence->queryCount; return g_serviceTargets[service]; }
    if (service >= Sweep || receiver != Address(occurrence->output) || occurrence->eventCount == 4)
        RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    occurrence->events[occurrence->eventCount++] = {occurrence->entity, service, occurrence->entity};
    return 0;
}
#define LOCO_RECORDING_GATE(name, index, ownerGate) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm cmp dword ptr [g_parallelInFlight], 0 \
        __asm jne name##Worker \
        __asm cmp byte ptr [g_quiet], 0 \
        __asm je name##Owner \
        __asm popfd \
        __asm jmp dword ptr [g_serviceTargets + index * 4] \
        __asm name##Owner: \
        __asm popfd \
        __asm jmp ownerGate \
        __asm name##Worker: \
        __asm popfd \
        __asm lea esp, [esp-4] \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm push offset ownerGate \
        __asm push ecx \
        __asm push index \
        __asm call WorkerServiceTarget \
        __asm mov dword ptr [ebp+36], eax \
        __asm test eax, eax \
        __asm jz name##Recorded \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm ret \
        __asm name##Recorded: \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm lea esp, [esp+4] \
        __asm ret \
    }
LOCO_RECORDING_GATE(RecordUnlinkGridGate, 0, UnlinkGridGate)
LOCO_RECORDING_GATE(RecordUnlinkOwnerGate, 1, UnlinkOwnerGate)
LOCO_RECORDING_GATE(RecordInsertOwnerGate, 2, InsertOwnerGate)
LOCO_RECORDING_GATE(RecordInsertGridGate, 3, InsertGridGate)
LOCO_RECORDING_GATE(RecordSweepGate, 4, SweepGate)
LOCO_RECORDING_GATE(RecordResolveGate, 5, ResolveGate)
LOCO_RECORDING_GATE(RecordHeightOwnerGate, 6, HeightOwnerGate)
LOCO_RECORDING_GATE(RecordWrapperQueryGate, 7, WrapperQueryGate)
#undef LOCO_RECORDING_GATE
// ---- Relink apply (RelinkApply, MovementSlices Contract 3) ------------------------------------------------------------
// Owner-side op log of the site-13 soft-grid relink services 0x811ED0 / 0x7EFA80 and their cell-partitioned apply
// (native_move_delta.*, native_relink.*). Mode 1 (shadow): the native services still run; every batch is also applied to a
// private mirror by the same kernel and compared. Mode 2 (live): the log replaces the native calls and a batch is applied
// by the pool at its flush barrier. The owner-list services 0x811D50 / 0x7EFDD0 stay serial in place (RelinkProbation.md).
enum RelinkCause : U { RelinkCauseFallback, RelinkCauseClassWrapper, RelinkCauseEnd, RelinkCauseOther };
constexpr U kRelinkBatchRecords = 4096;     // record-table capacity of one batch (128 KiB, L2 resident)
constexpr U kRelinkParallelMinCells = 2048; // below this many cell operations a batch is applied by the owner, same kernel
constexpr U kRelinkMirrorWords = 1u << 19;
MoveLog g_moveLog;
RelinkMirror g_relinkMirror;
RelinkDispatcher g_relinkDispatcher;
U g_relinkWords[RelinkWordCount];
U g_relinkMode, g_relinkNative[2], g_relinkSeq, g_relinkMinCells = kRelinkParallelMinCells;
bool g_relinkWindow;  // the stage replay loop is open for logging
bool g_relinkLogging; // the code running right now is a logged occurrence (tapped selector/move clone fallback)
unsigned long long RelinkPlanBytes(const ntw2_workload::Capacity& c, U mode) {
    if (!mode) return 0;
    unsigned long long bytes = 3ull * c.records * sizeof(MoveOp) + 8ull * c.memberships + (2ull * kRelinkBatchRecords + 1024) * sizeof(MoveRecordState);
    if (mode == 1) bytes += 24ull * kRelinkMirrorWords;
    return bytes;
}
size_t RelinkStorageBytes() { return g_moveLog.blockBytes + g_relinkMirror.blockBytes; }
bool AllocateRelink(const ntw2_workload::Capacity& c) {
    if (g_moveLog.block) return true;
    if (!MoveLogInit(g_moveLog, c.records, c.memberships, kRelinkBatchRecords, V(0x1318038))) return false;
    if (g_relinkMode == 1 && !RelinkMirrorInit(g_relinkMirror, kRelinkMirrorWords)) { MoveLogFree(g_moveLog); return false; }
    return true;
}
void ReleaseRelink() {
    g_relinkWindow = g_relinkLogging = false;
    MoveLogFree(g_moveLog); RelinkMirrorFree(g_relinkMirror);
    if (g_relinkMode) { g_serviceTargets[UnlinkGrid] = V(0x811ED0); g_serviceTargets[InsertGrid] = V(0x7EFA80); }
}

// Applies (live) or verifies (shadow) the open batch, then opens the next one. `cause` is a flush barrier reason.
void RelinkFlush(U cause) {
    if (!g_relinkWindow) return;
    MoveLog& log = g_moveLog;
    const U ops = MoveLogBatchOps(log);
    if (!ops) return;
    ++g_relinkWords[RelinkFlushFallback + cause];
    ++g_relinkWords[RelinkBatches];
    ++g_relinkWords[RelinkBatchesLe16 + (ops <= 16 ? 0 : ops <= 256 ? 1 : ops <= 2048 ? 2 : 3)];
    if (g_relinkWords[RelinkMaxBatchOps] < ops) g_relinkWords[RelinkMaxBatchOps] = ops;
    RelinkApplyStats stats = {};
    const LONGLONG start = Now();
    if (g_relinkMode == 2) {
        RelinkApplyLive(log, &g_relinkDispatcher, g_relinkMinCells, stats);
        g_relinkWords[RelinkApplyWallUs] += Microseconds(Now() - start);
    } else {
        RelinkShadowResult result = {};
        RelinkMirrorApply(g_relinkMirror, log, &g_relinkDispatcher, g_relinkMinCells, stats, result);
        ++g_relinkWords[RelinkShadowBatches]; g_relinkWords[RelinkShadowCells] += result.cells;
        g_relinkWords[RelinkShadowMismatchCells] += result.mismatchCells;
        g_relinkWords[RelinkShadowMismatchNodes] += result.mismatchNodes;
        g_relinkWords[RelinkRefusals] += result.refused;
        if (result.mismatchCells || result.mismatchNodes) {
            ++g_relinkWords[RelinkUntappedWriters];
            g_relinkWords[RelinkLastMismatchCell] = result.lastCell; g_relinkWords[RelinkLastMismatchRecord] = result.lastRecord;
        }
        g_relinkWords[RelinkShadowUs] += Microseconds(Now() - start);
        RelinkMirrorReset(g_relinkMirror, log);
    }
    g_relinkWords[RelinkDispatches] += stats.dispatches; g_relinkWords[RelinkPartitions] += stats.partitions;
    g_relinkWords[RelinkApplyCpuUs] += stats.cpuUs;
    g_relinkWords[RelinkRefusals] += stats.anomalies; g_relinkWords[RelinkFaults] += stats.faults;
    MoveLogCloseBatch(log);
}
// A barrier before code that may touch the chains without being logged (untapped native writer or reader).
void RelinkBarrier(U cause) {
    if (!g_relinkWindow) return;
    g_moveLog.complete = 0;
    RelinkFlush(cause);
}
// True: the occurrence is fully accounted for (logged, or a no-op the native service skips too) and the native service
// must NOT run. False: the caller runs the native service (shadow mode, or a serial fallback after a flush).
bool RelinkLog(MoveOpKind kind, U record, U ordinal, MoveOpSource source) {
    const bool live = g_relinkMode == 2;
    const bool sample = !(++g_relinkSeq & 15);
    const LONGLONG start = sample ? Now() : 0;
    ExtractResult result = ExtractMoveOp(g_moveLog, record, ordinal, kind, source, live);
    if (result == ExtractBatchFull) { RelinkFlush(RelinkCauseOther); result = ExtractMoveOp(g_moveLog, record, ordinal, kind, source, live); }
    bool skipNative = live;
    if (result == ExtractLogged) {
        ++g_relinkWords[kind == MoveUnlinkGrid ? RelinkOpsUnlink : RelinkOpsInsert];
        if (!live) RelinkMirrorTouch(g_relinkMirror, g_moveLog, g_moveLog.count - 1);
    } else if (result != ExtractNoop) {
        RelinkFlush(RelinkCauseOther);
        ++g_relinkWords[RelinkSerialFallbacks]; g_moveLog.complete = 0;
        skipNative = false;
    }
    if (sample) g_relinkWords[RelinkLogUs] += Microseconds(Now() - start) * 16;
    return skipNative;
}
// Stage entry (after PrepareOwned) / exit of the replay loop.
void RelinkBeginStage() {
    if (!g_relinkMode || !g_moveLog.block) return;
    MoveLogBeginStage(g_moveLog, g_words[Calls]);
    if (g_relinkMode == 1) RelinkMirrorReset(g_relinkMirror, g_moveLog);
    ++g_relinkWords[RelinkStages];
    g_relinkWindow = true; g_relinkLogging = false;
}
void RelinkEndStage() {
    if (!g_relinkWindow) return;
    RelinkFlush(RelinkCauseEnd);
    g_relinkWords[RelinkCollapsed] += g_moveLog.collapsed;
    MoveLogPublish(g_moveLog);
    g_relinkWindow = g_relinkLogging = false;
}
// Exception unwind: leave no deferred op behind (memory must match the +AC values already written).
void RelinkAbortStage() {
    if (!g_relinkWindow) return;
    __try { RelinkFlush(RelinkCauseEnd); } __except(EXCEPTION_EXECUTE_HANDLER) { ++g_relinkWords[RelinkFaults]; }
    g_relinkWindow = g_relinkLogging = false;
}
// Gate target for 0x811ED0 / 0x7EFA80 (kind 0 / 1) on the owner. 1 = handled, 0 = run the native service.
U __stdcall RelinkGate(U kind, U receiver) {
    if (!g_relinkWindow) return 0;
    if (!g_relinkLogging) { g_moveLog.complete = 0; RelinkFlush(RelinkCauseOther); return 0; }
    return RelinkLog(kind ? MoveInsertGrid : MoveUnlinkGrid, receiver, g_stageOrdinal, MoveFromClone) ? 1 : 0;
}
// thiscall stubs installed over g_serviceTargets[UnlinkGrid/InsertGrid] while relink is on. They preserve every integer
// register and XMM0-7 (the callers were compiled against the register footprint of the real service) and execute no x87.
#define LOCO_RELINK_STUB(name, kind, native) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 128 \
        __asm movups xmmword ptr [esp], xmm0 \
        __asm movups xmmword ptr [esp + 16], xmm1 \
        __asm movups xmmword ptr [esp + 32], xmm2 \
        __asm movups xmmword ptr [esp + 48], xmm3 \
        __asm movups xmmword ptr [esp + 64], xmm4 \
        __asm movups xmmword ptr [esp + 80], xmm5 \
        __asm movups xmmword ptr [esp + 96], xmm6 \
        __asm movups xmmword ptr [esp + 112], xmm7 \
        __asm push dword ptr [ebp + 24] \
        __asm push kind \
        __asm call RelinkGate \
        __asm mov dword ptr [ebp + 28], eax \
        __asm movups xmm0, xmmword ptr [esp] \
        __asm movups xmm1, xmmword ptr [esp + 16] \
        __asm movups xmm2, xmmword ptr [esp + 32] \
        __asm movups xmm3, xmmword ptr [esp + 48] \
        __asm movups xmm4, xmmword ptr [esp + 64] \
        __asm movups xmm5, xmmword ptr [esp + 80] \
        __asm movups xmm6, xmmword ptr [esp + 96] \
        __asm movups xmm7, xmmword ptr [esp + 112] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm test eax, eax \
        __asm jnz name##Handled \
        __asm jmp dword ptr [g_relinkNative + native * 4] \
        __asm name##Handled: \
        __asm ret \
    }
LOCO_RELINK_STUB(RelinkUnlinkStub, 0, 0)
LOCO_RELINK_STUB(RelinkInsertStub, 1, 1)
#undef LOCO_RELINK_STUB

void StagingExit();
void __stdcall BeginStaging(U*) {
    if (g_relinkLogging) { g_relinkLogging = false; RelinkBarrier(RelinkCauseOther); } // staging gather/commit may touch chains untapped
    g_stagingActive = !g_quiet && g_stage && g_binding.use_parallel;
    if (g_stagingActive) g_stagingStart = Now();
}
void __stdcall FinishStagingAfterReturn(U* returnSlot) {
    if (!g_stagingActive) return;
    g_stagingReturn = *returnSlot;
    *returnSlot = Address(reinterpret_cast<void*>(&StagingExit));
}
U __stdcall EndStaging() {
    g_parallelWords[ParallelStagingUs] += Microseconds(Now() - g_stagingStart);
    g_stagingActive = false;
    return g_stagingReturn;
}
__declspec(naked) void StagingExit() {
    __asm lea esp, [esp-4]
    __asm pushfd
    __asm pushad
    __asm mov ebp, esp
    __asm sub esp, 528
    __asm and esp, -16
    __asm fxsave [esp]
    __asm cld
    __asm call EndStaging
    __asm mov dword ptr [ebp+36], eax
    __asm fxrstor [esp]
    __asm mov esp, ebp
    __asm popad
    __asm popfd
    __asm ret
}
#define LOCO_STAGING_GATE(name, helper, target) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm mov ebp, esp \
        __asm sub esp, 528 \
        __asm and esp, -16 \
        __asm fxsave [esp] \
        __asm cld \
        __asm lea eax, [ebp+36] \
        __asm push eax \
        __asm call helper \
        __asm fxrstor [esp] \
        __asm mov esp, ebp \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [target] \
    }
LOCO_STAGING_GATE(StageGatherGate, BeginStaging, g_stageGatherTarget)
LOCO_STAGING_GATE(StageResetGate, FinishStagingAfterReturn, g_stageResetTarget)
#undef LOCO_STAGING_GATE

constexpr U kTables[] = {
    0x1333714, 0x13473D0, 0x13475E4, 0x13477F8, 0x13479B4,
    0x1347B70, 0x1347D2C, 0x1347EE8, 0x13480A4, 0x1348260,
    0x134841C, 0x132B7D8, 0x132BA04
};
static_assert(sizeof(kTables) / sizeof(kTables[0]) == kOwnedClasses, "private worker vtable inventory");
bool Candidate(U table, U* index = nullptr) {
    for (U i = 0; i < kOwnedClasses; ++i)
        if (table == V(kTables[i])) { if (index) *index = i; return true; }
    return false;
}
bool Stub(U target) {
    return target == V(0x444B60) || target == V(0x461180) ||
           target == V(0x462CB0) || target == V(0x447880) || target == V(0x62DF00);
}
bool Holder(U holder) {
    if (B(holder + 0x8F) != 1) return true;
    const U table = D(holder + 8);
    return table && Stub(D(table + 0xC)) && Stub(D(table + 0x14)) &&
           Stub(D(table + 0x24)) && Stub(D(table + 0x28));
}
bool ReferenceNode(U a) {
    if (B(a + 0x2C4) != 1) return true;
    const U n = a + 0x22C;
    if (D(n) != V(0x1334180) || D(n + 4) != a || !D(n + 0x14) || !D(n + 0x1C)) return false;
    static const U slots[13] = {
        0x624F80, 0x6666B0, 0x66E670, 0x461180, 0x461180, 0x461180,
        0x447880, 0x462CB0, 0x462CB0, 0x462CB0, 0x462CB0, 0x447880, 0x462CB0
    };
    for (U i = 0; i < 13; ++i) if (D(D(n) + i * 4) != V(slots[i])) return false;
    return D(D(n + 0x14) + 8) != 0;
}
bool ClassSlotsOk(U table) {
    return D(table + 0x10) == V(table == V(0x132BA04) ? 0x5B2CA0 : 0x62A290) &&
        D(table + 0x74) == V(0x64C780) && D(table + 0x70) == V(0x63D5B0) &&
        D(table + 0x64) == V(0x66B0F0);
}
bool ClassRouteOk(U a) {
    const U table = D(a);
    U index;
    if (!Candidate(table, &index)) return false;
    return g_owned && g_owned->activated ? g_owned->classRoute[index] : ClassSlotsOk(table);
}
U ContextModel(U a) {
    __try { const U context = D(a + 0x28); return context ? D(context + 8) : 0; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
bool EnvironmentOk(U a, U model) {
    __try {
        if (!B(a + 0xA1)) return true;
        return model && D(model + 0xA4) && D(model + 0xA8) &&
            D(a + 0xA8) && D(a + 0xB0) && D(a + 0xAC) <= D(a + 0xB0);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
U ClassifyImpl(U a) {
    if (!g_started || !a) return Lifetime;
    if (!ClassRouteOk(a)) return Class;
    const U model = ContextModel(a);
    if (!model) return Lifetime;
    if (D(a + 0x628)) return Parked;
    if (D(a + 0x18)) return Pending;
    if (!EnvironmentOk(a, model)) return Environment;
    // This is an instruction-identical, serial OWNER mover, not an owned NODE
    // or worker kernel. Activity, order, fire, target and holder state do not
    // authorize a different mover implementation. All native helper effects,
    // selector latches/staging and class-wrapper work retain their exact order.
    return Eligible;
}
bool NodeDiagnosticOk(U a, U gate, bool& fault) {
    // Borrowed NODE/holder shapes are diagnostic only. An unsupported shape
    // must not turn a valid owner-thread MOVE into a lifetime refusal.
    __try {
        switch (gate) {
        case GateReferenceNode: return ReferenceNode(a);
        case GateHolder2CC: return Holder(a + 0x2CC);
        case GateHolder51C: return Holder(a + 0x51C);
        default: {
            const U row = D(a + 0x444);
            if (!row || !D(row + 4) || D(a + 0x1C0) >= D(D(row + 4) + 0x50)) return false;
            return D(row) != 0x5D && D(row) != 0x5E;
        }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { fault = true; return false; }
}
inline bool Detail(U word, bool failed) {
    if (failed) ++g_gateWords[word];
    return failed;
}
inline U GateBit(U reason) { return 1u << (reason - 1); }
void CensusImpl(U a, U& reason) {
    if (!Candidate(D(a))) {
        ++g_gateWords[GateClass];
        ++g_gateWords[GateUnclassified];
        reason = Class;
        return; // no soldier-layout reads on unrelated classes
    }
    ++g_gateWords[GateCandidates];
    U failed = ClassRouteOk(a) ? 0 : GateBit(Class);
    const U model = ContextModel(a);
    if (!model) failed |= GateBit(Lifetime);
    if (D(a + 0x628)) failed |= GateBit(Parked);
    if (D(a + 0x18)) failed |= GateBit(Pending);
    if (!EnvironmentOk(a, model)) failed |= GateBit(Environment);
    // Compute admission once from the enforced gates, before examining any
    // diagnostic-only borrowed node/holder state.
    reason = Eligible;
    if (failed) for (U i = 0; i < 10; ++i) if (failed & (1u << i)) { reason = i + 1; break; }

    // Evaluate every old proof gate independently, including when an earlier
    // gate failed. These counters describe the intersection, not first-fail
    // attribution. The four detailed charge/fire words identify the exact
    // DWORD fields; the byte latches below were never the old fire predicate.
    const U activity = D(a + 0x1B8);
    U activityWord = GateActivityOther;
    switch (activity) {
    case 0: activityWord = GateActivity0; break;
    case 1: activityWord = GateActivity1; break;
    case 9: activityWord = GateActivity9; break;
    case 0x1D: activityWord = GateActivity1D; break;
    case 0x23: activityWord = GateActivity23; break;
    case 0xC: activityWord = GateActivity0C; break;
    }
    ++g_gateWords[activityWord];
    if (activity != 1 && activity != 9 && activity != 0x1D) failed |= GateBit(Activity);
    if (D(a + 0x1EC)) failed |= GateBit(Target);
    const bool charge = Detail(GateCharge4E8, D(a + 0x4E8) != 0);
    const bool fire = Detail(GateFire390, D(a + 0x390) != 0);
    const bool watchA = Detail(GateFire3BC, D(a + 0x3BC) != 0);
    const bool watchB = Detail(GateFire3C8, D(a + 0x3C8) != 0);
    if (charge || fire || watchA || watchB) failed |= GateBit(ChargeFire);
    const bool posture = Detail(GatePosture220, D(a + 0x220) != 0);
    const U order = D(a + 0x1D8);
    const bool orderFailed = Detail(GateOrder,
        ((activity == 1 || activity == 9) && order != 4) ||
        (activity == 0x1D && order != 0 && order != 4));
    if (posture || orderFailed) failed |= GateBit(PostureOrder);
    bool diagnosticFault = false;
    const bool row = Detail(GateSlotRow, activity == 0x1D &&
        !NodeDiagnosticOk(a, GateSlotRow, diagnosticFault));
    const bool node = Detail(GateReferenceNode, !NodeDiagnosticOk(a, GateReferenceNode, diagnosticFault));
    const bool holderA = Detail(GateHolder2CC, !NodeDiagnosticOk(a, GateHolder2CC, diagnosticFault));
    const bool holderB = Detail(GateHolder51C, !NodeDiagnosticOk(a, GateHolder51C, diagnosticFault));
    if (row || node || holderA || holderB) failed |= GateBit(Node);
    Detail(GateLatch618, B(a + 0x618) != 0);
    Detail(GateLatch619, B(a + 0x619) != 0);
    Detail(GateLatchF1, B(a + 0xF1) != 0);
    Detail(GateLatch5AB, B(a + 0x5AB) != 0);
    if (diagnosticFault) ++g_gateWords[GateDiagnosticFaults];
    for (U i = 0; i < 10; ++i) if (failed & (1u << i)) ++g_gateWords[GateClass + i];
    if (!failed) ++g_gateWords[GateLegacyAdmitted];
    if (reason == Eligible && failed) ++g_gateWords[GateNewlyAdmitted];
}
U Census(U a) {
    ++g_gateWords[GateEntities];
    U reason = Lifetime;
    __try { CensusImpl(a, reason); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_gateWords[GateDiagnosticFaults]; }
    if (reason == Eligible) ++g_gateWords[GateAdmitted];
    return reason;
}
void FinishServices() {
    Max(MaxEntityServices, g_entityServices);
    if (g_entityServices) ++g_words[ServicedEntities];
}

U WorkerReason(U a) {
    if (Classify(P(a)) != Eligible) return ParallelNeedsAdmission;
    if (D(a) == V(0x132BA04)) return ParallelNeedsClassWrapper;
    // Even motionless in-bounds A1!=0 reaches the unclosed 81AE40 closure.
    if (B(a + 0xA1)) return ParallelNeedsEnv;
    if (D(a + 0x10) || D(a + 0x18) || D(a + 0x170)) return ParallelNeedsRelationship;
    if (!B(a + 0xA3)) return ParallelNeedsStaging;
    return 0;
}
U CountEntity(U a) {
    ++g_words[Entities];
    const U reason = g_quiet ? Classify(P(a)) : Census(a);
    ++g_words[reason ? Rejected : Admitted];
    if (reason) ++g_words[RejectClass + reason - 1];
    if (Candidate(D(a))) {
        if (g_binding.use_owned_services) {
            if (B(a + 0xA1)) ++g_ownedWords[OwnedActiveEntities];
            if (B(a + 0xF0)) ++g_ownedDetails[OwnedDetailObservedF0];
            if (!B(a + 0xA3)) ++g_ownedDetails[OwnedDetailObservedInitialA3];
        }
        if (B(a + 0xEC) == 1) ++g_words[WrapperBattle];
        else if (D(a + 0x628) && D(a + 0x62C) == 4) {
            ++g_words[WrapperAlternate];
            if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailAlternate];
        }
        else ++g_words[Direct];
        if (D(a) == V(0x132BA04)) {
            ++g_words[ClassWrapper];
            if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailClassWrapper];
        }
    } else if (g_binding.use_owned_services) ++g_ownedDetails[OwnedDetailOtherClass];
    return reason;
}
int WorkerFault(WorkerOccurrence& occurrence, EXCEPTION_POINTERS* exception) {
    occurrence.state = Faulted; occurrence.eventCount = 0;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_parallelWords[ParallelFaults]));
    if (!_InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_parallelWords[ParallelSticky]), 1, 0)) {
        g_parallelWords[ParallelLastException] = exception->ExceptionRecord->ExceptionCode;
        g_parallelWords[ParallelLastEntity] = occurrence.entity;
        g_parallelWords[ParallelLastOrdinal] = occurrence.ordinal;
        g_parallelWords[ParallelLastEip] = exception->ContextRecord->Eip;
        const U code = exception->ExceptionRecord->ExceptionCode;
        g_parallelWords[ParallelLastAccess] = (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
            exception->ExceptionRecord->NumberParameters >= 2
            ? static_cast<U>(exception->ExceptionRecord->ExceptionInformation[1]) : 0;
        g_parallelWords[ParallelLastSerial] = occurrence.serial;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
void __fastcall ParallelChunk(void* context, U chunk) {
    ParallelJob& job = *static_cast<ParallelJob*>(context);
    const U saved = _mm_getcsr(); unsigned short cw, ownerCw = job.cw;
    __asm { fnstcw cw }
    _mm_setcsr(job.mxcsr);
    __asm { fldcw ownerCw }
    const U size = (job.count + job.chunks - 1) / job.chunks;
    U i = chunk * size;
    __try {
        __try {
            for (; i < (std::min)(job.count, (chunk + 1) * size); ++i) {
                WorkerOccurrence& occurrence = g_workers->occurrences[i];
                g_workerOccurrence = &occurrence;
                Call(occurrence.wrapper ? g_binding.wrap_clone : g_binding.move_clone, Address(occurrence.output));
                // The closed early-return path has no publication. A recorded
                // link here is a proof violation, never permission to continue.
                if (occurrence.eventCount) RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
                occurrence.state = Computed; g_workerOccurrence = nullptr;
            }
        } __except(WorkerFault(g_workers->occurrences[(std::min)(i, job.count - 1)], GetExceptionInformation())) {}
    } __finally {
        g_workerOccurrence = nullptr;
        __asm { fnclex }
        __asm { fldcw cw }
        _mm_setcsr(saved);
    }
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_parallelWords[
        GetCurrentThreadId() == job.owner ? ParallelInlineChunks : ParallelChunks]));
}
void CommitWorker(WorkerOccurrence& occurrence) {
    unsigned char* native = static_cast<unsigned char*>(P(occurrence.entity));
    const unsigned char* result = occurrence.output;
    // Exact A1==0 footprint, not whole-agent scatter or a shallow graph copy.
    static const U ranges[][2] = {{0x38,4},{0x54,4},{0x80,8},{0x88,4},{0xB8,24}};
    native[0x5ED] = native[0x5EC]; native[0x5EC] = 0;
    for (const auto& range : ranges) memcpy(native + range[0], result + range[0], range[1]);
    if (occurrence.wrapper) {
        static const U wrapperRanges[][2] = {
            {0x190,8},{0x1A4,4},{0x174,3},{0x199,1},{0x150,4},{0x14C,4},{0x18C,1}
        };
        for (const auto& range : wrapperRanges) memcpy(native + range[0], result + range[0], range[1]);
    }
}
U ParallelRun(U manager, U cursor, U end) {
    if (!g_binding.use_parallel || g_parallelWords[ParallelSticky]) return 0;
    const U list = D(manager + 0x264), count = D(manager + 0x260);
    U ready = 0;
    __try {
        for (U next = cursor; next != end && ready < kParallelRun; next += 4) {
            const U a = D(next);
            if (B(a + 0x30) != 1 || WorkerReason(a)) break;
            bool duplicate = false;
            for (U i = 0; i < ready; ++i) if (g_workers->occurrences[i].entity == a) { duplicate = true; break; }
            if (duplicate) { ++g_parallelWords[ParallelNeedsDuplicate]; break; }
            WorkerOccurrence& occurrence = g_workers->occurrences[ready++];
            occurrence.entity = a; occurrence.serial = D(a + 0x2C); occurrence.ordinal = (next - list) / 4;
            occurrence.wrapper = B(a + 0xEC) == 1;
            occurrence.state = Ready; occurrence.eventCount = occurrence.queryCount = 0;
            memcpy(occurrence.input, P(a), kPrivateBytes);
            memcpy(occurrence.output, occurrence.input, kPrivateBytes);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_parallelWords[ParallelInvalidated]; return 0;
    }
    if (!ready) return 0;
    ParallelJob job = {ready, (std::min)(ready, (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1))),
        GetCurrentThreadId(), _mm_getcsr(), 0};
    unsigned short cw;
    __asm { fnstcw cw }
    job.cw = cw;
    const LONGLONG start = Now();
    g_parallelInFlight = 1;
    __try {
        if (g_binding.dispatch) g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&ParallelChunk)), job.chunks, &job);
        else for (U i = 0; i < job.chunks; ++i) ParallelChunk(&job, i);
    } __finally { g_parallelInFlight = 0; }
    const LONGLONG elapsed = Now() - start;
    g_parallelWords[ParallelKernelUs] += Microseconds(elapsed);
    if (g_parallelWords[ParallelSticky]) return 0;
    // Every destination is revalidated before the first irreversible store.
    if (D(manager + 0x264) != list || D(manager + 0x260) != count) {
        ++g_parallelWords[ParallelInvalidated]; return 0;
    }
    for (U i = 0; i < ready; ++i) {
        const WorkerOccurrence& occurrence = g_workers->occurrences[i];
        if (occurrence.state != Computed || D(cursor + i * 4) != occurrence.entity ||
            memcmp(P(occurrence.entity), occurrence.input, kPrivateBytes) || WorkerReason(occurrence.entity)) {
            ++g_parallelWords[ParallelInvalidated]; return 0;
        }
    }
    const LONGLONG replayStart = Now();
    for (U i = 0; i < ready; ++i) {
        WorkerOccurrence& occurrence = g_workers->occurrences[i];
        CountEntity(occurrence.entity); CommitWorker(occurrence); ++g_words[Cloned];
        ResetServiceTrace();
        for (U n = 0; n < occurrence.queryCount; ++n) RecordService(WrapperQuery, occurrence.entity + 0xF4);
        FinishServices();
        ++g_parallelWords[ParallelWorkerEntities]; ++g_parallelWords[ParallelCommitted];
    }
    g_parallelWords[ParallelReplayUs] += Microseconds(Now() - replayStart);
    g_parallelWords[ParallelMaxWorkerRun] = (std::max)(g_parallelWords[ParallelMaxWorkerRun], ready);
    g_words[AdmittedUs] += Microseconds(elapsed); RecordCloneTime(elapsed);
    return ready;
}

void DestroyOwned() {
    if (!g_owned) return;
    OwnedArena* arena = g_owned;
    g_owned = nullptr;
    for (OwnedParticipant*& participant : arena->participants) {
        if (!participant) continue;
        if (participant->clones.allocation) VirtualFree(participant->clones.allocation, 0, MEM_RELEASE);
        delete participant->ctx;
        participant->~OwnedParticipant();
        _aligned_free(participant);
        participant = nullptr;
    }
    if (arena->movement) VirtualFree(arena->movement, 0, MEM_RELEASE);
    arena->~OwnedArena();
    _aligned_free(arena);
}
// Start: only the small per-participant state and its private clone pair exist. The heavy sweep/resolve/environment
// contexts and every capacity-sized buffer are created by ActivateOwned from the actual workers+caller count.
bool CreateOwned() {
    if (!g_binding.use_owned_services) return true;
    void* const raw = _aligned_malloc(sizeof(OwnedArena), 64);
    if (!raw) return false;
    g_owned = new (raw) OwnedArena;
    for (U i = 0; i < kOwnedClasses; ++i) {
        const U table = V(kTables[i]);
        g_owned->classRoute[i] = ClassSlotsOk(table);
        g_owned->predicate67C[i] = D(table + 0xE8) == V(0x5DB820) ||
            D(table + 0xEC) == V(0x5DB820) || D(table + 0xF0) == V(0x5DB820);
        g_owned->predicateLinkByte[i] = D(table + 0x3C) == V(0x54E920) || D(table + 0x50) == V(0x54E920);
        memcpy(g_owned->virtualTables[i], P(V(kTables[i])), sizeof(g_owned->virtualTables[i]));
        g_owned->virtualTables[i][0x70 / 4] = Address(reinterpret_cast<void*>(&OwnedClamp));
    }
    // Phase 2 proxy children share one private table: slot 1 = submit, slot 0x36 = heading, everything else traps.
    g_cwChildSlots = D(V(kCwChildTable) + 4) == V(0x80BAC0) && D(V(kCwChildTable) + 0xD8) == V(0x5E4C60);
    for (U& slot : g_cwChildTable) slot = Address(reinterpret_cast<void*>(&OwnedChildTrap));
    g_cwChildTable[1] = Address(reinterpret_cast<void*>(&OwnedChildSubmit));
    g_cwChildTable[0xD8 / 4] = Address(reinterpret_cast<void*>(&OwnedChildHeading));
    g_owned->participantsCount = (std::min)(kParallelChunks, (std::max)(1u, g_binding.workers + 1));
    for (U i = 0; i < g_owned->participantsCount; ++i) {
        void* const memory = _aligned_malloc(sizeof(OwnedParticipant), 64);
        if (!memory) { DestroyOwned(); return false; }
        OwnedParticipant& participant = *new (memory) OwnedParticipant;
        g_owned->participants[i] = &participant;
        U bindings[NTW2_BIND_COUNT];
        memcpy(bindings, g_locoBindings, sizeof(bindings));
        participant.first[0] = V(0x1312358);
        bindings[NTW2_BIND_LOCO_SCRATCH_14543B4] = Address(participant.first);
        bindings[NTW2_BIND_LOCO_SCRATCH_15A1888] = Address(participant.second);
        bindings[NTW2_BIND_LOCO_SCRATCH_15A189C] = Address(participant.third);
        bindings[NTW2_BIND_LOCO_SERVICE_811ED0] = Address(reinterpret_cast<void*>(&OwnedLink<UnlinkGrid>));
        bindings[NTW2_BIND_LOCO_SERVICE_811D50] = Address(reinterpret_cast<void*>(&OwnedLink<UnlinkOwner>));
        bindings[NTW2_BIND_LOCO_SERVICE_7EFDD0] = Address(reinterpret_cast<void*>(&OwnedLink<InsertOwner>));
        bindings[NTW2_BIND_LOCO_SERVICE_7EFA80] = Address(reinterpret_cast<void*>(&OwnedLink<InsertGrid>));
        bindings[NTW2_BIND_LOCO_SERVICE_801140] = Address(reinterpret_cast<void*>(&OwnedSweep));
        bindings[NTW2_BIND_LOCO_SERVICE_80F290] = Address(reinterpret_cast<void*>(&OwnedResolve));
        bindings[NTW2_BIND_LOCO_SERVICE_81AE40] = Address(reinterpret_cast<void*>(&OwnedEnvironment));
        bindings[NTW2_BIND_LOCO_SERVICE_814AA0] = Address(reinterpret_cast<void*>(&OwnedQuery));
        for (U k = 0; k < kCwMaxChildren; ++k) {
            participant.cwProxy[k][0] = Address(g_cwChildTable); participant.cwProxy[k][1] = k;
            participant.cwList[k] = Address(participant.cwProxy[k]);
        }
        if (ntw2_build_loco_participant(g_binding.wrap_clone, g_binding.move_clone, g_cwMode ? g_binding.class_wrap_clone : 0,
                g_cwMode ? Address(reinterpret_cast<void*>(&OwnedSelect)) : 0, bindings, &participant.clones)) {
            DestroyOwned(); return false;
        }
    }
    return true;
}
// Phase-2 gate for a 0x132BA04 receiver with a pre-step or children: 0 admissible, CwRefusedClass (a child is not a World
// agent 0x1333714) or CwRefusedGate (mode off, pre-step, aim state 9, >8 children, null/self child, unproven slots).
// Reads only the receiver's own +224/+66C/+670/+688, its child array and each child's word 0.
U CwGate(U a) {
    const U count = D(a + 0x66C), list = D(a + 0x670);
    if (!g_cwMode || !g_cwChildSlots || D(a + 0x688) || D(a + 0x224) == 9 || count > kCwMaxChildren || !list) return CwRefusedGate;
    U refusal = 0;
    for (U k = 0; k < count; ++k) {
        const U child = D(list + 4 * k);
        if (!child || child == a) return CwRefusedGate;
        if (D(child) != V(kCwChildTable)) refusal = CwRefusedClass;
    }
    return refusal;
}
inline bool CwAdmissible(U a) { return !CwGate(a); }
// Worker-side classification: reads only this entity's own cache lines plus static class/context state.
U OwnedReason(U a, U& classIndex) {
    if (!Candidate(D(a), &classIndex) || !g_owned->classRoute[classIndex]) return OwnedNeedsUnit;
    // 0x5B2CA0 with no pre-step (+688 == 0, 0x5F3040 not entered) and an empty child array (+66C == 0) is exactly its 0x62A290 selector
    // call (prologue/epilogue have no other effect): admitted. Children are admitted only by phase 2 (CwAdmissible: World agent
    // children replayed through native 0x80BAC0 on the owner); pre-step and the aim arm stay refused.
    if (D(a) == V(0x132BA04) && (D(a + 0x688) || D(a + 0x66C)) && !CwAdmissible(a)) return OwnedNeedsClassWrapper;
    if (B(a + 0xEC) != 1 && D(a + 0x628) && D(a + 0x62C) == 4) return OwnedNeedsAlternateWrapper;
    if (D(a + 0x18)) return OwnedNeedsPending;
    if (D(a + 0x170)) return OwnedNeedsForeignTransform;
    if (D(a + 0x10)) return OwnedNeedsEnv;
    const U model = ContextModel(a);
    if (!model || D(a + 0x628) || !EnvironmentOk(a, model)) return OwnedNeedsUnit;
    // The alternative secondary terrain vtable is not the proven bilinear sampler.
    if (B(a + 0xB4) && B(a + 0xB5) && D(model + 0xE0)) return OwnedNeedsEnv;
    return 0;
}
int OwnedFilter(OwnedCurrent& current, EXCEPTION_POINTERS* exception) {
    if (exception->ExceptionRecord->ExceptionCode == kOwnedUnsupported && current.reason)
        return EXCEPTION_EXECUTE_HANDLER;
    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ownedWords[OwnedFaults]));
    WorkerOccurrence fault{};
    fault.entity = current.entity; fault.serial = current.serial; fault.ordinal = current.ordinal;
    return WorkerFault(fault, exception);
}
__declspec(noinline) void OwnedRaiseFault(OwnedCurrent& current) {
    __try { RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr); }
    __except(OwnedFilter(current, GetExceptionInformation())) {}
}
// One worklist ordinal. Returns false only after a REAL fault (sticky is set; the chunk stops, the entity stays
// Unprocessed and every later one runs natively). Refusals are per entity and never touch siblings.
bool OwnedRunEntity(OwnedArena& arena, OwnedParticipant& participant, U index) {
    OwnedSlot& slot = arena.slots[index];
    OwnedCurrent& current = participant.current;
    const U a = arena.worklist[index];
    slot.entity = a;
    if (B(a + 0x30) != 1) { arena.states[index] = OwnedSkipped; return true; }
    current.entity = a; current.ordinal = index; current.serial = D(a + 0x2C);
    current.services = 0; current.serviceCount = 0; current.reason = 0; current.detail = 0;
    current.environment = {};
    U classIndex = kNoOccurrence;
    const U reason = OwnedReason(a, classIndex);
    if (reason) {
        slot.reason = static_cast<unsigned char>(reason); slot.detail = 0;
        arena.states[index] = OwnedRefused; return true;
    }
    slot.active = B(a + 0xA1) != 0; slot.wrapper = B(a + 0xEC) == 1; slot.classWrapper = D(a) == V(0x132BA04);
    // The private receiver keeps the whole prefix; the slot keeps only the audited live-in guard footprint.
    const unsigned char* const live = static_cast<const unsigned char*>(P(a));
    unsigned char* const work = participant.work;
    memcpy(work, live, kOwnedPrefix);
    GatherGuard(slot, live);
    slot.inputLatch = live[0x5EC];
    slot.readsPredicate = slot.active && arena.predicate67C[classIndex];
    slot.inputPredicate = slot.readsPredicate ? D(a + 0x67C) : 0;
    slot.readsLinkByte = slot.active && arena.predicateLinkByte[classIndex];
    slot.inputLinkByte = slot.readsLinkByte ? live[4] : 0;
    const bool initialA3 = work[0xA3] != 0;
    // The private vptr never reaches native memory: every slot equals the class table except +70 (clamp trap).
    const U privateTable = Address(arena.virtualTables[classIndex]);
    memcpy(work, &privateTable, sizeof(privateTable));
    work[0x5ED] = slot.inputLatch; work[0x5EC] = 0; // selector latch rollover
    memcpy(work + 0x67C, &slot.inputPredicate, sizeof(slot.inputPredicate));
    // Headers are participant-private; a refused call can have left a count behind.
    participant.first[3] = participant.second[2] = participant.third[2] = 0;
    // Phase 2: children (admitted by CwGate) run through the participant LOCO_CLASS_WRAP clone with proxy children; their
    // events are pooled per stage and the owner replays native 0x80BAC0 per submitted child at this ordinal.
    const U children = slot.classWrapper ? D(a + 0x66C) : 0;
    if (slot.classWrapper && arena.cwInfo) arena.cwInfo[index] = 0;
    if (children) {
        const U base = static_cast<U>(_InterlockedExchangeAdd(&arena.cwNext, static_cast<LONG>(children)));
        if (base + children > arena.slotCapacity) {
            slot.reason = OwnedNeedsCapacity; slot.detail = 0;
            arena.states[index] = OwnedRefused; return true;
        }
        const U list = D(a + 0x670), state = D(a + 0x224);
        for (U k = 0; k < children; ++k) {
            CwEvent& event = arena.cwEvents[base + k];
            event.child = D(list + 4 * k); event.vtable = D(event.child); event.list = list; event.state = state;
            event.heading = 0; event.word = 0; event.submitted = event.served = 0;
        }
        participant.cwBase = base; participant.cwWrapper = slot.wrapper != 0; participant.cwInitialA3 = initialA3;
        memcpy(work + 0x224, &state, sizeof(state));
        memcpy(work + 0x66C, &children, sizeof(children));
        const U privateList = Address(participant.cwList);
        memcpy(work + 0x670, &privateList, sizeof(privateList));
        arena.cwInfo[index] = children << 24 | base;
    }
    bool ok = false;
    __try {
        Call(children ? participant.clones.entries[NTW2_CLONE_LOCO_CLASS_WRAP] :
            participant.clones.entries[slot.wrapper ? NTW2_CLONE_LOCO_WRAP : NTW2_CLONE_LOCO_MOVE], Address(work));
        // 62A290 tests the POST-MOVE A3 byte: zero really does stage. Never inverted.
        if (!work[0xA3])
            RefuseOwned(OwnedNeedsStaging, initialA3 ? OwnedDetailResultA3 : OwnedDetailInitialA3);
        ok = true;
    } __except(OwnedFilter(current, GetExceptionInformation())) {}
    if (children) memset(work + 0x224, 0, 4), memset(work + 0x66C, 0, 8);
    if (!ok) {
        // A refusal/fault unwound out of the middle of the private mover: its x87 stack is unknown.
        const unsigned short controlWord = arena.cw;
        __asm { fninit }
        __asm { fldcw controlWord }
        if (current.reason) {
            slot.reason = current.reason; slot.detail = current.detail;
            arena.states[index] = OwnedRefused; return true;
        }
        arena.states[index] = OwnedUnprocessed; return false;
    }
    slot.reason = 0; slot.detail = 0;
    slot.services = current.services; slot.serviceCount = current.serviceCount;
    GatherOutput(slot, work);
    slot.resultLatches[0] = work[0x5EC]; slot.resultLatches[1] = work[0x5ED];
    arena.states[index] = OwnedComputed;
    return true;
}
// ntw_pool_dispatch body: ONE dispatch per stage, chunk = contiguous worklist range claimed atomically by the pool.
// The participant (clone pair, scratch, port contexts, receiver) is acquired once per thread per dispatch.
ULONGLONG ThreadCpu100ns() {
    FILETIME created, exited, kernel, user;
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) return 0;
    return (static_cast<ULONGLONG>(kernel.dwHighDateTime) << 32) + kernel.dwLowDateTime +
           (static_cast<ULONGLONG>(user.dwHighDateTime) << 32) + user.dwLowDateTime;
}
void __fastcall OwnedChunk(void* context, U chunk) {
    OwnedArena& arena = *static_cast<OwnedArena*>(context);
    if (g_parallelWords[ParallelSticky]) return; // untouched ordinals stay Unprocessed and run natively
    if (g_ownedEpoch != arena.epoch) {
        g_ownedEpoch = arena.epoch; g_ownedParticipant = nullptr;
        const LONG slotIndex = _InterlockedIncrement(&arena.nextParticipant) - 1;
        if (static_cast<U>(slotIndex) < arena.participantsCount) {
            OwnedParticipant& acquired = *arena.participants[slotIndex];
            acquired.first[2] = acquired.first[3] = acquired.first[4] = 0;
            acquired.second[1] = acquired.second[2] = acquired.second[3] = 0;
            acquired.third[1] = acquired.third[2] = acquired.third[3] = 0;
            acquired.maximum = 0;
            acquired.cpu100ns = acquired.cpuAtMaximum100ns = 0;
            acquired.computed = acquired.refused = acquired.chunks = acquired.inlineChunks = acquired.chunkTimeUs = 0;
            memset(acquired.histogram, 0, sizeof(acquired.histogram));
            acquired.isOwner = GetCurrentThreadId() == arena.owner;
            g_ownedParticipant = &acquired;
        }
    }
    OwnedParticipant* const participant = g_ownedParticipant;
    if (!participant) { _InterlockedIncrement(&arena.overflow); return; }
    const U begin = chunk * arena.chunkSize;
    const U end = (std::min)(arena.count, begin + arena.chunkSize);
    const U savedCsr = _mm_getcsr();
    unsigned short savedCw, installedCw, ownerCw = arena.cw;
    __asm { fnstcw savedCw }
    g_ownedOccurrence = &participant->current;
    U computed = 0, refused = 0;
    const bool timed = !g_quiet; // clock reads and GetThreadTimes cost ~1 us each: never per chunk under --loco-quiet
    const LONGLONG start = timed ? Now() : 0;
    const ULONGLONG cpuStart = timed ? ThreadCpu100ns() : 0;
    __try {
        // Full controls, not just rounding: FTZ, DAZ and x87 precision all participate in the native arithmetic.
        _mm_setcsr(arena.mxcsr);
        __asm { fnclex }
        __asm { fldcw ownerCw }
        __asm { fnstcw installedCw }
        if (_mm_getcsr() != arena.mxcsr || installedCw != ownerCw) {
            participant->current.entity = arena.worklist[begin]; participant->current.ordinal = begin;
            participant->current.serial = 0; participant->current.reason = 0;
            OwnedRaiseFault(participant->current);
        } else {
            for (U i = begin; i < end; ++i) {
                if (g_parallelWords[ParallelSticky]) break;
                if (i + 4 < arena.count) {
                    const U ahead = arena.worklist[i + 4];
                    for (U line = 0; line < kOwnedPrefix; line += 64) _mm_prefetch(reinterpret_cast<const char*>(ahead + line), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x5EC), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x67C), _MM_HINT_T0);
                    _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x628), _MM_HINT_T0);
                }
                if (!OwnedRunEntity(arena, *participant, i)) break;
                const unsigned char state = arena.states[i];
                if (state == OwnedComputed) ++computed; else if (state == OwnedRefused) ++refused;
            }
        }
    } __finally {
        g_ownedOccurrence = nullptr;
        __asm { fnclex }
        __asm { fldcw savedCw }
        _mm_setcsr(savedCsr);
    }
    participant->computed += computed; participant->refused += refused;
    ++(participant->isOwner ? participant->inlineChunks : participant->chunks);
    if (!timed) return;
    const LONGLONG ticks = Now() - start;
    const ULONGLONG cpuEnd = ThreadCpu100ns();
    const ULONGLONG cpu = cpuStart && cpuEnd >= cpuStart ? cpuEnd - cpuStart : 0;
    participant->cpu100ns += cpu;
    const U us = Microseconds(ticks);
    participant->chunkTimeUs += us;
    ++participant->histogram[us <= 16 ? 0 : us <= 32 ? 1 : us <= 64 ? 2 : us <= 128 ? 3 :
        us <= 256 ? 4 : us <= 512 ? 5 : us <= 1024 ? 6 : 7];
    if (ticks > participant->maximum) {
        participant->maximum = ticks; participant->cpuAtMaximum100ns = cpu;
    }
}
// Activation only: full scene/catalog construction and participant scratch preparation.
struct OwnedCapture {
    U model, sceneUs = 0, catalogUs = 0;
    bool ready = false;
};
int ActivationException(EXCEPTION_POINTERS* exception) {
    g_ownedLoad[OwnedLoadException] = exception->ExceptionRecord->ExceptionCode;
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        exception->ExceptionRecord->NumberParameters >= 2)
        g_ownedLoad[OwnedLoadDetail] = static_cast<U>(exception->ExceptionRecord->ExceptionInformation[1]);
    return EXCEPTION_EXECUTE_HANDLER;
}
void CaptureOwnedPorts(OwnedCapture& capture) {
    OwnedArena& arena = *g_owned;
    LONGLONG t = Now();
    g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneCapture;
    bool ok = ntw2_sweep::PrepareScene(arena.scene, capture.model, g_delta, g_generation);
    LONGLONG next = Now(); capture.sceneUs = Microseconds(next - t); t = next;
    if (ok) {
        g_ownedLoad[OwnedLoadFailureReason] = ActivationCatalog;
        ok = ntw2_resolve::PrepareCatalog(arena.catalog, arena.scene);
        capture.catalogUs = Microseconds(Now() - t);
    }
    if (!ok) {
        if (arena.scene.failure == ntw2_sweep::SceneVerificationFailure)
            g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneVerification;
        else if (arena.scene.failure == ntw2_sweep::SceneIdentityFailure)
            g_ownedLoad[OwnedLoadFailureReason] = ActivationSceneIdentity;
        g_ownedLoad[OwnedLoadDetail] = arena.scene.failureAddress;
        g_ownedLoad[OwnedLoadActual] = arena.scene.failureActual;
    }
    capture.ready = ok;
}
void CaptureOwnedPortsCatching(OwnedCapture& capture) {
    try { CaptureOwnedPorts(capture); }
    catch (const std::bad_alloc&) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; }
}
void CaptureOwnedPortsGuarded(void* context) {
    OwnedCapture& capture = *static_cast<OwnedCapture*>(context);
    __try { CaptureOwnedPortsCatching(capture); }
    __except(ActivationException(GetExceptionInformation())) { capture.ready = false; }
}
bool PrepareOwnedWorkers() {
    OwnedArena& arena = *g_owned;
    for (U i = 0; i < arena.participantsCount; ++i) {
        OwnedParticipant& participant = *arena.participants[i];
        g_ownedLoad[OwnedLoadFailureReason] = ActivationSweepWorker;
        if (!participant.ctx) {
            participant.ctx = new (std::nothrow) OwnedContexts;
            if (!participant.ctx) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; return false; }
        }
        OwnedContexts& context = *participant.ctx;
        if (!ntw2_sweep::PrepareWorker(context.sweep, arena.scene)) return false;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationResolveWorker;
        if (!ntw2_resolve::PrepareWorker(context.resolve, arena.catalog)) return false;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationEnvWorker;
        if (!ntw2_env::PrepareWorker(context.env, arena.scene)) return false;
        context.sweep.fp = context.resolve.fp = context.env.fp = {arena.mxcsr, arena.cw};
        context.sweep.fp_managed = context.resolve.fp_managed = context.env.fp_managed = true;
    }
    return true;
}
bool PrepareOwnedWorkersCatching() {
    try { return PrepareOwnedWorkers(); }
    catch (const std::bad_alloc&) { g_ownedLoad[OwnedLoadException] = ERROR_NOT_ENOUGH_MEMORY; return false; }
}
// Touch every page so the first tick never takes a demand-zero fault (VirtualAlloc pages are already zero).
void Prefault(void* base, size_t bytes) {
    volatile unsigned char* const page = static_cast<volatile unsigned char*>(base);
    for (size_t offset = 0; offset < bytes; offset += 4096) page[offset] = 0;
}
// One block: slots[capacity] | worklist[capacity] | states[capacity]. capacity is the PRIMARY occurrence capacity.
// Phase 2 adds cwInfo[capacity] | cwEvents[capacity] (+CwBytesPerOrdinal per ordinal) behind the states.
constexpr U kCwBytesPerOrdinal = sizeof(U) + sizeof(CwEvent);
bool AllocateOwnedSlots(OwnedArena& arena, U capacity) {
    const unsigned long long slotBytes = static_cast<unsigned long long>(capacity) * sizeof(OwnedSlot),
        listBytes = static_cast<unsigned long long>(capacity) * sizeof(U), stateBytes = g_cwMode ? (capacity + 3ull) & ~3ull : capacity,
        cwBytes = g_cwMode ? static_cast<unsigned long long>(capacity) * kCwBytesPerOrdinal : 0,
        total = slotBytes + listBytes + stateBytes + cwBytes;
    if (total > 0x7FFFFFFFull) return false;
    unsigned char* const block = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, static_cast<SIZE_T>(total), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!block) return false;
    arena.movement = block; arena.movementBytes = static_cast<U>(total);
    arena.slots = reinterpret_cast<OwnedSlot*>(block);
    arena.worklist = reinterpret_cast<U*>(block + slotBytes);
    arena.states = block + slotBytes + listBytes; // zero == OwnedUnprocessed
    unsigned char* const cw = block + slotBytes + listBytes + stateBytes;
    arena.cwInfo = g_cwMode ? reinterpret_cast<U*>(cw) : nullptr;
    arena.cwEvents = g_cwMode ? reinterpret_cast<CwEvent*>(cw + static_cast<size_t>(capacity) * sizeof(U)) : nullptr;
    Prefault(block, static_cast<size_t>(total));
    arena.slotCapacity = capacity;
    return true;
}
void WarmOwnedClones(U model) {
    alignas(16) unsigned char fp[512];
    __asm { fxsave fp }
    __try {
        U context[3] = {0, 0, model};
        for (U i = 0; i < g_owned->participantsCount; ++i) {
            OwnedParticipant& p = *g_owned->participants[i];
            memset(p.work, 0, sizeof(p.work));
            *reinterpret_cast<U*>(p.work) = Address(g_owned->virtualTables[0]);
            *reinterpret_cast<U*>(p.work + 0x28) = Address(context);
            p.work[0xA3] = p.work[0xEC] = p.work[0x13D] = 1;
            // A1==0: private arithmetic only; +13D bypasses descriptor queries in the wrapper.
            Call(p.clones.entries[NTW2_CLONE_LOCO_WRAP], Address(p.work));
            memset(p.work, 0, sizeof(p.work));
        }
    } __finally {
        __asm { fxrstor fp }
    }
}
LONG g_ownedEpochCounter; // never reset: stale thread-local participants cannot match a recreated arena
void PrepareOwned(U manager) {
    if (!g_owned || g_parallelWords[ParallelSticky]) return;
    OwnedArena& arena = *g_owned;
    arena.valid = false; arena.failureReason = OwnedNeedsUnit;
    const LONGLONG begin = Now();
    arena.list = D(manager + 0x264); arena.count = D(manager + 0x260);
    if (!arena.count) return;
    if (!arena.activated || arena.count > arena.slotCapacity) {
        ++g_ownedLoad[OwnedLoadCapacityRefusals]; arena.failureReason = OwnedNeedsCapacity; return;
    }
    const U model = D(D(manager) + 8);
    if (model != arena.activationModel) {
        ++g_ownedLoad[OwnedLoadModelChanges]; arena.failureReason = OwnedNeedsSweep; return;
    }
    memcpy(arena.worklist, P(arena.list), arena.count * sizeof(U));
    memset(arena.states, OwnedUnprocessed, arena.count);
    arena.mxcsr = _mm_getcsr();
    unsigned short cw; __asm { fnstcw cw }
    arena.cw = cw; arena.owner = GetCurrentThreadId();
    const U participants = arena.participantsCount;
    U size = arena.count / (participants * 32);
    size = (std::max)(kOwnedChunkMin, (std::min)(kOwnedChunkMax, (size + 7) & ~7u));
    arena.chunkSize = size; arena.chunks = (arena.count + size - 1) / size;
    arena.epoch = ++g_ownedEpochCounter; arena.nextParticipant = 0; arena.overflow = 0; arena.cwNext = 0;
    const LONGLONG identityStart = Now();
    // Already activated: PrepareScene performs only fixed-size identity/header checks.
    const bool ready = ntw2_sweep::PrepareScene(arena.scene, model, g_delta, g_generation);
    const U sceneUs = Microseconds(Now() - identityStart), catalogUs = 0;
    const LONGLONG fpStart = Now();
    for (U i = 0; i < participants; ++i) {
        OwnedParticipant& p = *arena.participants[i];
        p.ctx->sweep.fp = p.ctx->resolve.fp = p.ctx->env.fp = {arena.mxcsr, arena.cw};
        p.maximum = 0; p.cpu100ns = p.cpuAtMaximum100ns = 0;
    }
    const U workerUs = Microseconds(Now() - fpStart);
    const U prepareUs = Microseconds(Now() - begin);
    g_ownedWords[OwnedCaptureUs] += prepareUs;
    g_ownedPhase[OwnedPhaseIndexUs] += prepareUs - (std::min)(prepareUs, sceneUs + catalogUs + workerUs);
    g_ownedPhase[OwnedPhaseScenePrepareUs] += sceneUs;
    g_ownedPhase[OwnedPhaseCatalogPrepareUs] += catalogUs;
    g_ownedPhase[OwnedPhaseWorkerPrepareUs] += workerUs;
    g_ownedPhase[OwnedPhaseListEntities] += arena.count;
    if (!ready) { ++g_ownedLoad[OwnedLoadModelChanges]; arena.failureReason = OwnedNeedsSweep; return; }
    arena.valid = true;
    const LONGLONG kernel = Now();
    g_parallelInFlight = 1;
    // One synchronous dispatch per stage; no live publication is permitted before the join.
    if (g_binding.dispatch)
        g_binding.dispatch(g_binding.pool, Address(reinterpret_cast<void*>(&OwnedChunk)), arena.chunks, &arena);
    else for (U i = 0; i < arena.chunks; ++i) OwnedChunk(&arena, i);
    g_parallelInFlight = 0;
    const U elapsed = Microseconds(Now() - kernel);
    g_ownedWords[OwnedKernelUs] += elapsed; g_parallelWords[ParallelKernelUs] += elapsed;
    g_ownedPhase[OwnedPhaseDispatchWallUs] += elapsed;
    ++g_ownedPhase[OwnedPhaseDispatches];
    g_ownedPhase[OwnedPhaseChunks] += arena.chunks;
    g_ownedWords[OwnedChunks] += arena.chunks;
    g_ownedPhase[OwnedPhaseChunkSizeLast] = arena.chunkSize;
    g_ownedPhase[OwnedPhaseMaxChunkEntities] = (std::max)(g_ownedPhase[OwnedPhaseMaxChunkEntities],
        (std::min)(arena.chunkSize, arena.count));
    // Fold the per-participant chunk accounting (acquired participants only; the rest were reset or never ran).
    U computed = 0, refused = 0, chunkTimeUs = 0;
    for (U i = 0; i < (std::min)(participants, static_cast<U>(arena.nextParticipant)); ++i) {
        const OwnedParticipant& p = *arena.participants[i];
        computed += p.computed; refused += p.refused; chunkTimeUs += p.chunkTimeUs;
        g_parallelWords[ParallelChunks] += p.chunks; g_parallelWords[ParallelInlineChunks] += p.inlineChunks;
        for (U b = 0; b < kOwnedHistogram; ++b) g_ownedPhase[OwnedPhaseChunkLe16 + b] += p.histogram[b];
    }
    g_ownedWords[OwnedWorkerTimeUs] += chunkTimeUs;
    g_ownedPhase[OwnedPhaseChunkTimeSumUs] += chunkTimeUs;
    g_ownedPhase[OwnedPhaseComputed] += computed;
    g_ownedPhase[OwnedPhaseWorkerRefused] += refused;
    g_ownedPhase[OwnedPhaseParticipantOverflow] += static_cast<U>(arena.overflow);
    g_ownedPhase[OwnedPhaseParticipantsUsed] += (std::min)(participants, static_cast<U>(arena.nextParticipant));
    for (U i = 0; i < participants; ++i) {
        const OwnedParticipant& p = *arena.participants[i];
        const U wall = Microseconds(p.maximum);
        g_ownedWords[OwnedMaxChunkUs] = (std::max)(g_ownedWords[OwnedMaxChunkUs], wall);
        g_ownedLoad[OwnedLoadChunkCpuUs] += static_cast<U>(p.cpu100ns / 10);
        if (wall > g_ownedLoad[OwnedLoadChunkWallMaxUs]) {
            g_ownedLoad[OwnedLoadChunkWallMaxUs] = wall;
            g_ownedLoad[OwnedLoadChunkCpuAtWallMaxUs] = static_cast<U>(p.cpuAtMaximum100ns / 10);
        }
    }
    U unprocessed = 0;
    for (U i = 0; i < arena.count; ++i) unprocessed += arena.states[i] == OwnedUnprocessed;
    g_ownedPhase[OwnedPhaseUnprocessed] += unprocessed;
}
void CountCommitted(const OwnedSlot& slot) {
    ++g_words[Entities]; ++g_words[Admitted];
    if (slot.active) ++g_ownedWords[OwnedActiveEntities];
    if (GuardByte<0xF0>(slot)) ++g_ownedDetails[OwnedDetailObservedF0];
    if (!GuardByte<0xA3>(slot)) ++g_ownedDetails[OwnedDetailObservedInitialA3];
    ++g_words[slot.wrapper ? WrapperBattle : Direct];
}
void InvalidateOwned(OwnedArena& arena, U cursor) {
    arena.valid = false; arena.failureReason = OwnedNeedsUnit; ++g_parallelWords[ParallelInvalidated];
    if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[OwnedNeedsUnit];
}
// Class-wrapper census (CwWord): what the refused 0x132BA04 occurrences look like at the moment the owner replays them.
U g_cwWords[CwWordCount];
void CensusClassWrapper(U a) {
    __try {
        ++g_cwWords[CwOccurrences];
        if (g_cwMode) { const U gate = CwGate(a); ++g_cwWords[gate ? gate : CwRefusedGate]; }
        const U pre = D(a + 0x688), count = D(a + 0x66C), list = D(a + 0x670), state = D(a + 0x224);
        if (pre) ++g_cwWords[CwPreStep];
        ++g_cwWords[state == 9 ? CwState9 : state == 8 ? CwState8 : CwStateOther];
        if (count > 4096) { ++g_cwWords[CwUnreadable]; return; }
        ++g_cwWords[count == 0 ? CwKids0 : count == 1 ? CwKids1 : CwKids2Plus];
        if (count > g_cwWords[CwKidsMax]) g_cwWords[CwKidsMax] = count;
        if (!pre && !count) ++g_cwWords[CwEmpty];
        if (!pre && count) ++g_cwWords[CwWithKidsNoPre];
        g_cwWords[CwChildrenTotal] += count;
        for (U i = 0; i < count; ++i) {
            const U child = D(list + 4 * i);
            if (!child) { ++g_cwWords[CwNullChildren]; continue; }
            const U vt = D(child);
            U k = 0;
            while (k < CwVtEntries && g_cwWords[CwVtBase + 2 * k] && g_cwWords[CwVtBase + 2 * k] != vt) ++k;
            if (k == CwVtEntries) { ++g_cwWords[CwVtOverflow]; continue; }
            g_cwWords[CwVtBase + 2 * k] = vt; ++g_cwWords[CwVtBase + 2 * k + 1];
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { ++g_cwWords[CwUnreadable]; }
}
// Phase 2 commit re-check: the live wrapper still has no pre-step, the same child count, list, aim state and child
// objects/vtables, and the 0x14A51A0 word every proxy heading served is unchanged. Any difference = native run.
bool CwStillMatches(const OwnedArena& arena, U a, U info) {
    const U children = info >> 24;
    if (D(a + 0x688) || D(a + 0x66C) != children) return false;
    if (!children) return true;
    const CwEvent* const events = arena.cwEvents + (info & 0xFFFFFF);
    if (D(a + 0x670) != events[0].list || D(a + 0x224) != events[0].state) return false;
    const unsigned short word = *reinterpret_cast<const unsigned short*>(static_cast<uintptr_t>(V(0x14A51A0)));
    for (U k = 0; k < children; ++k) {
        const CwEvent& event = events[k];
        if (D(event.list + 4 * k) != event.child || D(event.child) != event.vtable) return false;
        if (event.served && event.word != word) return false;
    }
    return true;
}
// Live: the recorded child relocations, in child order, through the real 0x80BAC0 (reads the child's +28 context and the
// live model, calls the native link services directly; a relink window flushes first).
void CwReplay(const OwnedArena& arena, U info) {
    const U children = info >> 24;
    const CwEvent* const events = arena.cwEvents + (info & 0xFFFFFF);
    using Relocate = void (__thiscall*)(void*, const float*, U);
    for (U k = 0; k < children; ++k) {
        const CwEvent& event = events[k];
        if (!event.submitted) continue;
        reinterpret_cast<Relocate>(V(0x80BAC0))(P(event.child), event.pose, event.heading);
        ++g_cwWords[CwEvents];
    }
}
// Shadow: after the owner ran the wrapper natively, the worker's receiver footprint and each submitted child's
// 0x80BAC0 inputs (pose +48..+50, heading word +64) must equal what the native wrapper produced.
bool OwnedOutputMatches(const OwnedSlot& slot, const unsigned char* native) {
    U diff = 0;
    EachSpanOf<kOutputSpanCount>([&](auto i) {
        constexpr Span s = kOutputSpans[decltype(i)::value];
        diff |= SpanDiff<s.bytes>(native + s.offset, slot.output + kOutputStart[decltype(i)::value]);
    });
    if (slot.wrapper) EachSpanOf<kWrapperSpanCount>([&](auto i) {
        constexpr Span s = kWrapperSpans[decltype(i)::value];
        diff |= SpanDiff<s.bytes>(native + s.offset, slot.output + kOutputBytes + kWrapperStart[decltype(i)::value]);
    });
    diff |= static_cast<U>(native[0x5EC] ^ slot.resultLatches[0]) | static_cast<U>(native[0x5ED] ^ slot.resultLatches[1]);
    return diff == 0;
}
void CwShadowCompare() {
    const U index = g_cwShadowIndex;
    g_cwShadowIndex = ~0u;
    if (!g_owned || index >= g_owned->count) return;
    const OwnedArena& arena = *g_owned;
    const OwnedSlot& slot = arena.slots[index];
    const U info = arena.cwInfo[index], children = info >> 24;
    const CwEvent* const events = arena.cwEvents + (info & 0xFFFFFF);
    bool same = OwnedOutputMatches(slot, static_cast<const unsigned char*>(P(slot.entity)));
    for (U k = 0; k < children; ++k) {
        const CwEvent& event = events[k];
        if (!event.submitted) continue;
        same = same && !memcmp(P(event.child + 0x48), event.pose, sizeof(event.pose)) &&
            *static_cast<const unsigned short*>(P(event.child + 0x64)) == static_cast<unsigned short>(event.heading);
        ++g_cwWords[CwEvents];
    }
    ++g_cwWords[CwShadowCompares];
    if (!same) ++g_cwWords[CwShadowMismatches];
}
bool CommitOwned(U manager, U cursor) {
    if (!g_owned || g_parallelWords[ParallelSticky]) return false;
    OwnedArena& arena = *g_owned;
    if (!arena.valid) {
        if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[arena.failureReason];
        return false;
    }
    // A fallback that changed the worklist shape (erase-shift, reallocation) invalidates every prepared ordinal.
    if (D(manager + 0x264) != arena.list || D(manager + 0x260) != arena.count ||
        cursor < arena.list || (cursor - arena.list) / 4 >= arena.count) { InvalidateOwned(arena, cursor); return false; }
    const U index = (cursor - arena.list) / 4;
    const unsigned char state = arena.states[index];
    if (state == OwnedSkipped) return false;
    // Never inspect the slot of an ordinal no worker reached: its contents are stale.
    if (state == OwnedUnprocessed) {
        if (B(D(cursor) + 0x30) == 1) ++g_ownedWords[OwnedNeedsCapacity];
        return false;
    }
    OwnedSlot& slot = arena.slots[index];
    if (D(cursor) != slot.entity) { InvalidateOwned(arena, cursor); return false; }
    if (index + 6 < arena.count) {
        const U ahead = D(arena.list + (index + 6) * 4);
        for (U line = 0; line < kOwnedPrefix; line += 64) _mm_prefetch(reinterpret_cast<const char*>(ahead + line), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x5EC), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x67C), _MM_HINT_T0);
        _mm_prefetch(reinterpret_cast<const char*>(ahead + 0x628), _MM_HINT_T0);
    }
    if (state == OwnedRefused) {
        ++g_ownedWords[slot.reason];
        if (slot.reason == OwnedNeedsClassWrapper) CensusClassWrapper(slot.entity);
        if (slot.detail) ++g_ownedDetails[slot.detail];
        return false;
    }
    if (state != OwnedComputed) { ++g_ownedWords[OwnedNeedsCapacity]; return false; }
    const bool sample = !(++g_ownedReplaySeq & 15);
    const LONGLONG sampleStart = sample ? Now() : 0;
    const unsigned char* const live = static_cast<const unsigned char*>(P(slot.entity));
    // An earlier fallback/replay may have changed this very receiver (duplicate occurrence, class-wrapper children
    // callbacks...): the speculative result is stale, so this one entity runs natively at its ordinal.
    // +66C/+688 lie beyond the copied prefix: a class wrapper admitted as empty must still be empty when its result is replayed,
    // a phase-2 wrapper must still have the very children/list/state/heading word its proxies saw.
    const U cwInfo = slot.classWrapper && arena.cwInfo ? arena.cwInfo[index] : 0;
    const bool guardOk = OwnedGuardMatches(slot, live);
    if (!guardOk || (slot.classWrapper && !CwStillMatches(arena, slot.entity, cwInfo))) {
        ++g_ownedWords[OwnedNeedsUnit]; ++g_ownedWords[OwnedDuplicateRefusals];
        ++g_ownedPhase[OwnedPhaseValidationRefusals]; ++g_parallelWords[ParallelInvalidated];
        if (guardOk && cwInfo) ++g_cwWords[CwRecheckFallbacks];
        return false;
    }
    if (cwInfo) {
        ++g_cwWords[CwAdmitted];
        // Shadow: the owner runs this wrapper natively (stage loop fallback), then CwShadowCompare checks the worker result.
        if (g_cwMode == 1) { --g_ownedReplaySeq; g_cwShadowIndex = index; return false; } // not a replay: keep the 1/16 sample cadence
    }
    if (g_quiet) CountCommitted(slot); else CountEntity(slot.entity);
    if (!g_quiet) ResetServiceTrace();
    // Unlinks see the native pre-step receiver and live chain links. The result footprint is installed only
    // between unlink and insert; links, soft nodes, counts and owner masks are never copied from a stale snapshot.
    bool committed = false;
    for (U i = 0; i < slot.serviceCount; ++i) {
        const U service = (slot.services >> (4 * i)) & 15;
        if (service == InsertOwner || service == InsertGrid) {
            if (!committed) { CommitOwnedFields(slot); committed = true; }
        }
#ifdef NTW2_LOCO_ORACLE
        ObserveOwned(slot.entity, service, index, OwnedTestReplay);
#endif
        if (!g_quiet) RecordService(service, slot.entity + (service == WrapperQuery ? 0xF4 : 0));
        if (service < Sweep) {
            if (g_relinkWindow && (service == UnlinkGrid || service == InsertGrid)) {
                if (!RelinkLog(service == UnlinkGrid ? MoveUnlinkGrid : MoveInsertGrid, slot.entity, index, MoveFromWorker))
                    Call(g_relinkNative[service == UnlinkGrid ? 0 : 1], slot.entity);
            } else Call(g_serviceTargets[service], slot.entity);
            ++g_ownedWords[OwnedReplayUnlinkGrid + service];
        }
        ++g_parallelWords[ParallelReplayedServices];
    }
    if (!committed) CommitOwnedFields(slot);
    if (cwInfo) {
        // The child relocations run native link services untapped: a relink window flushes the parent's logged ops first.
        if (g_relinkWindow) RelinkBarrier(RelinkCauseClassWrapper);
        CwReplay(arena, cwInfo);
    }
    arena.states[index] = OwnedCommitted;
    g_gridCommittedReady = true;
    // Predicted transition events are env_untested and refuse before commit. No staging transaction is admitted.
    if (!g_quiet) FinishServices();
    ++g_words[Cloned]; ++g_parallelWords[ParallelWorkerEntities]; ++g_parallelWords[ParallelCommitted];
    ++g_ownedWords[slot.active ? (slot.wrapper ? OwnedWorkerBattle : OwnedWorkerDirect) : OwnedWorkerInactive];
    if (GuardByte<0xF0>(slot)) ++g_ownedDetails[OwnedDetailWorkerF0];
    if (sample) {
        g_replayCommitTicks += Now() - sampleStart;
        g_ownedPhase[OwnedPhaseReplayCommitEstUs] = Microseconds(g_replayCommitTicks * 16);
        ++g_ownedPhase[OwnedPhaseReplaySamples];
    }
    return true;
}
void FreeScratch(U* header, bool polymorphic) {
    const U data = header[polymorphic ? 4 : 3];
    // 444B60 is the pinned one-byte RET element destructor; no pointee owns
    // storage. Only the native allocator's backing buffer needs destruction.
    if (data) reinterpret_cast<Free>(V(0xFF7EF0))(P(data));
    memset(header, 0, (polymorphic ? 5 : 4) * sizeof(U));
    if (polymorphic) header[0] = V(0x1312358);
}
} // namespace

void Bind(U image_delta, U* bindings) {
    g_delta = image_delta;
    g_stageGatherTarget = V(0x7FC120); g_stageResetTarget = V(0x7F7140);
    bindings[NTW2_BIND_LOCO_STAGE_GATHER] = Address(reinterpret_cast<void*>(&StageGatherGate));
    bindings[NTW2_BIND_LOCO_STAGE_RESET] = Address(reinterpret_cast<void*>(&StageResetGate));
    bindings[NTW2_BIND_LOCO_SCRATCH_14543B4] = Address(g_scratchFirst);
    bindings[NTW2_BIND_LOCO_SCRATCH_15A1888] = Address(g_scratchSecond);
    bindings[NTW2_BIND_LOCO_SCRATCH_15A189C] = Address(g_scratchThird);
    bindings[NTW2_BIND_LOCO_GUARD_15A1884] = Address(&g_guards[0]);
    bindings[NTW2_BIND_LOCO_GUARD_15A1898] = Address(&g_guards[1]);
    bindings[NTW2_BIND_LOCO_GUARD_15A18AC] = Address(&g_guards[2]);
    bindings[NTW2_BIND_LOCO_SERVICE_811ED0] = Address(reinterpret_cast<void*>(&RecordUnlinkGridGate));
    bindings[NTW2_BIND_LOCO_SERVICE_811D50] = Address(reinterpret_cast<void*>(&RecordUnlinkOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_7EFDD0] = Address(reinterpret_cast<void*>(&RecordInsertOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_7EFA80] = Address(reinterpret_cast<void*>(&RecordInsertGridGate));
    bindings[NTW2_BIND_LOCO_SERVICE_801140] = Address(reinterpret_cast<void*>(&RecordSweepGate));
    bindings[NTW2_BIND_LOCO_SERVICE_80F290] = Address(reinterpret_cast<void*>(&RecordResolveGate));
    bindings[NTW2_BIND_LOCO_SERVICE_81AE40] = Address(reinterpret_cast<void*>(&RecordHeightOwnerGate));
    bindings[NTW2_BIND_LOCO_SERVICE_814AA0] = Address(reinterpret_cast<void*>(&RecordWrapperQueryGate));
    const U targets[ServiceCount] = {0x811ED0, 0x811D50, 0x7EFDD0, 0x7EFA80, 0x801140, 0x80F290, 0x81AE40, 0x814AA0};
    for (U i = 0; i < ServiceCount; ++i) g_serviceTargets[i] = V(targets[i]);
    memcpy(g_locoBindings, bindings, sizeof(g_locoBindings));
}

bool Start(const Binding& binding) {
    if (g_started || g_stage || g_runDepth || binding.image_delta != g_delta ||
        !QueryPerformanceFrequency(&g_frequency) || g_frequency.QuadPart <= 0) return false;
    if (binding.use_clone && (!binding.wrap_clone || !binding.move_clone ||
        !binding.selector_clone || !binding.class_wrap_clone)) return false;
    if (binding.use_parallel && !binding.use_clone) return false;
    if (binding.use_shadow && !binding.use_clone) return false;
    if (binding.use_owned_services && !binding.use_parallel) return false;
    if (binding.use_quiet && !binding.use_owned_services) return false;
    if (binding.use_relink_shadow && binding.use_relink_workers) return false;
    if ((binding.use_cw_shadow && binding.use_cw_workers) ||
        ((binding.use_cw_shadow || binding.use_cw_workers) && !binding.use_owned_services)) return false;
    if ((binding.use_relink_shadow || binding.use_relink_workers) &&
        (!binding.use_owned_services || !(binding.use_grid || binding.verify_grid))) return false;
    g_grid = nullptr; g_gridModel = 0; g_storageBytes = 0;
    memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    g_workers = nullptr;
    // Only the legacy contiguous-run path uses the 256-occurrence arena; owned execution never touches it.
    if (binding.use_parallel && !binding.use_owned_services) {
        g_workers = static_cast<WorkerArena*>(VirtualAlloc(nullptr, sizeof(WorkerArena), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_workers) return false;
    }
    g_incarnation = 0; g_gridValid = false;
    memset(&g_gridView, 0, sizeof(g_gridView));
    memset(g_gridWords, 0, sizeof(g_gridWords));
    memset(g_gridV2Words, 0, sizeof(g_gridV2Words));
    g_gridV2Words[GridV2Version] = 2;
    g_gridV2Words[GridV2Enabled] = binding.use_grid || binding.verify_grid;
    g_gridV2Words[GridV2VerifyEnabled] = binding.verify_grid;
    memset(g_gridBuildWords, 0, sizeof(g_gridBuildWords)); memset(g_gridBuildTicks, 0, sizeof(g_gridBuildTicks));
    g_gridBuildWords[GridBuildVersion] = 1;
    g_gridBuildWords[GridBuildMode] = binding.grid_incremental && (binding.use_grid || binding.verify_grid) ? 1u : 0u;
    memset(g_parallelWords, 0, sizeof(g_parallelWords));
    memset(g_ownedWords, 0, sizeof(g_ownedWords));
    g_ownedWords[OwnedVersion] = 1;
    g_ownedWords[OwnedEnabled] = binding.use_owned_services ? 1 : 0;
    memset(g_ownedDetails, 0, sizeof(g_ownedDetails));
    g_quiet = binding.use_quiet;
    g_ownedDetails[OwnedDetailVersion] = 1;
    g_ownedDetails[OwnedDetailQuiet] = g_quiet ? 1 : 0;
    memset(g_ownedPhase, 0, sizeof(g_ownedPhase));
    g_ownedPhase[OwnedPhaseVersion] = binding.use_owned_services ? 1 : 0;
    memset(g_ownedLoad, 0, sizeof(g_ownedLoad));
    g_ownedLoad[OwnedLoadVersion] = binding.use_owned_services ? 1 : 0;
    g_replayCommitTicks = g_replayFallbackTicks = 0;
    g_ownedReplaySeq = g_ownedFallbackSeq = 0;
    // Grid off: every grid word except the version stays zero (generation/bytes belong to a running grid).
    g_gridWords[GridVersion] = 1;
    g_parallelWords[ParallelVersion] = 1;
    g_parallelWords[ParallelEnabled] = binding.use_parallel ? 1 : 0;
    g_binding = binding;
    g_binding.use_grid = binding.use_grid || binding.verify_grid;
    g_binding.grid_incremental = binding.grid_incremental && g_binding.use_grid;
    memset(g_relinkWords, 0, sizeof(g_relinkWords));
    memset(g_cwWords, 0, sizeof(g_cwWords)); g_cwWords[CwVersion] = 2;
    g_cwMode = binding.use_cw_workers ? 2u : binding.use_cw_shadow ? 1u : 0u;
    g_cwWords[CwMode] = g_cwMode; g_cwShadowIndex = ~0u;
    g_relinkMode = binding.use_relink_workers ? 2u : binding.use_relink_shadow ? 1u : 0u;
    g_relinkWords[RelinkVersion] = 1; g_relinkWords[RelinkMode] = g_relinkMode;
    g_relinkDispatcher = {binding.dispatch, binding.pool, binding.workers};
    g_relinkWindow = g_relinkLogging = false; g_relinkSeq = 0; g_relinkMinCells = kRelinkParallelMinCells;
    g_relinkNative[0] = V(0x811ED0); g_relinkNative[1] = V(0x7EFA80);
    memset(g_words, 0, sizeof(g_words));
    memset(g_gateWords, 0, sizeof(g_gateWords));
    g_gateWords[GateVersion] = 1;
    g_gateWords[GateEnforcedMask] = kMoveGateMask;
    memset(g_timingWords, 0, sizeof(g_timingWords));
    memset(&g_timingTotals, 0, sizeof(g_timingTotals));
    g_timingSequence = 0;
    g_serviceDepth = 0;
    g_timingEnabled = binding.use_clone && !g_quiet;
    g_timingWords[TimingVersion] = 1;
    g_timingWords[TimingEnabled] = g_timingEnabled ? 1u : 0u;
    memset(g_scratchFirst, 0, sizeof(g_scratchFirst));
    memset(g_scratchSecond, 0, sizeof(g_scratchSecond));
    memset(g_scratchThird, 0, sizeof(g_scratchThird));
    g_scratchFirst[0] = V(0x1312358);
    // Guards are bound for census completeness, but every TLS init check and
    // cold registration path was removed from the private mover by pinned rewrites.
    g_guards[0] = g_guards[1] = g_guards[2] = 0x80000000u;
    ResetServiceTrace();
    g_words[Version] = 1;
    g_words[Generation] = ++g_generation;
    if (g_binding.use_grid) g_gridWords[GridGeneration] = g_generation;
    g_words[CloneEnabled] = binding.use_clone ? 1u : 0u;
    g_words[CloneBytes] = binding.clone_bytes;
    g_parallelInFlight = 0; g_stagingActive = false;
    g_shadowEnabled = binding.use_shadow && !g_quiet;
    const bool portsEnabled = g_shadowEnabled || binding.use_owned_services;
    if (!ntw2_sweep::Start({g_delta, g_generation, portsEnabled}) ||
        !ntw2_resolve::Start({g_delta, g_generation, portsEnabled}) ||
        !ntw2_env::Start({g_delta, g_generation, portsEnabled, g_shadowEnabled}) || !CreateOwned()) {
        ntw2_sweep::Stop(); ntw2_resolve::Stop(); ntw2_env::Stop();
        DestroyOwned();
        ReleaseGrid();
        ReleaseRelink();
        if (g_workers) VirtualFree(g_workers, 0, MEM_RELEASE);
        g_workers = nullptr;
        g_shadowEnabled = false; return false;
    }
    if (g_relinkMode) { // the grid link services go through the op-log stubs; CommitOwned and the gates use g_relinkNative for the real ones
        g_serviceTargets[UnlinkGrid] = Address(reinterpret_cast<void*>(&RelinkUnlinkStub));
        g_serviceTargets[InsertGrid] = Address(reinterpret_cast<void*>(&RelinkInsertStub));
    }
    g_started = true;
    g_storageBytes = ComputeStorage();
    return true;
}
bool ActivateOwned(void* model, const ntw2_workload::Capacity& capacity) {
    if (!g_started) { g_ownedLoad[OwnedLoadFailureReason] = ActivationNotStarted; return false; }
    if (!g_owned && !g_binding.use_grid) { g_ownedLoad[OwnedLoadFailureReason] = ActivationDisabled; return false; }
    if (g_stage || g_runDepth) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBusy; return false; }
    if (!model) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBadModel; return false; }
    if (!ValidCapacity(capacity)) { g_ownedLoad[OwnedLoadFailureReason] = ActivationBadCapacity; return false; }
    if (g_gridModel && g_gridModel != Address(model)) {
        g_ownedLoad[OwnedLoadFailureReason] = ActivationModelMismatch; return false;
    }
    if (g_binding.use_grid) {
        if (!g_grid) {
            // This is battle activation, never a tick or collision-entry lazy build.
            if (!AllocateGrid(capacity)) {
                g_ownedLoad[OwnedLoadFailureReason] = ActivationGridAllocation;
                g_storageBytes = ComputeStorage(); return false;
            }
            g_gridModel = Address(model);
        } else if (!GridCovers(capacity)) {
            g_ownedLoad[OwnedLoadFailureReason] = ActivationBadCapacity; return false;
        }
    }
    if (g_relinkMode && !AllocateRelink(g_gridStore.cap)) {
        g_ownedLoad[OwnedLoadFailureReason] = ActivationGridAllocation;
        g_storageBytes = ComputeStorage(); return false;
    }
    if (!g_owned) { g_storageBytes = ComputeStorage(); return true; } // grid-only mode does not prepare sweep/environment scenes
    OwnedArena& arena = *g_owned;
    if (arena.activated) {
        const bool same = arena.activationModel == Address(model) && capacity.primary <= arena.slotCapacity;
        g_ownedLoad[OwnedLoadFailureReason] = same ? ActivationOk : ActivationModelMismatch;
        return same;
    }
    // An unsuccessful attempt is not retried inside a generation.
    if (g_ownedLoad[OwnedLoadCalls]) { g_ownedLoad[OwnedLoadFailureReason] = ActivationAlreadyAttempted; return false; }
    ++g_ownedLoad[OwnedLoadCalls];
    const LONGLONG start = Now();
    OwnedCapture capture = {Address(model)};
    U workerUs = 0;
    g_ownedLoad[OwnedLoadException] = g_ownedLoad[OwnedLoadDetail] = g_ownedLoad[OwnedLoadActual] = 0;
    arena.mxcsr = _mm_getcsr();
    unsigned short cw; __asm { fnstcw cw }
    arena.cw = cw;
    bool ready = false;
    __try {
        const LONGLONG allocation = Now();
        g_ownedLoad[OwnedLoadFailureReason] = ActivationSlotAllocation;
        // Movement slots are sized by the PRIMARY occurrence capacity, never by primary+secondary records.
        ready = AllocateOwnedSlots(arena, capacity.primary);
        g_ownedLoad[OwnedLoadArenaUs] = Microseconds(Now() - allocation);
        if (ready) {
            // Warmup only runs inactive clones; it does not need the captured scene.
            // Keep this and every large arena/participant prefault off the tick owner.
            g_ownedLoad[OwnedLoadFailureReason] = ActivationWarmup;
            WarmOwnedClones(Address(model));
            g_ownedLoad[OwnedLoadFailureReason] = ActivationOwnerUnavailable;
            const bool captured = g_binding.capture_at_tick ?
                g_binding.capture_at_tick(&CaptureOwnedPortsGuarded, &capture) :
                (CaptureOwnedPortsGuarded(&capture), true);
            ready = captured && capture.ready;
        }
        if (ready) {
            const LONGLONG participants = Now();
            ready = PrepareOwnedWorkersCatching();
            workerUs = Microseconds(Now() - participants);
        }
    } __except(ActivationException(GetExceptionInformation())) { ready = false; }
    g_ownedLoad[OwnedLoadSceneUs] = capture.sceneUs;
    g_ownedLoad[OwnedLoadCatalogUs] = capture.catalogUs;
    g_ownedLoad[OwnedLoadParticipantsUs] = workerUs;
    g_ownedLoad[OwnedLoadUs] = Microseconds(Now() - start);
    if (ready) {
        arena.activationModel = Address(model); arena.activated = true;
        g_ownedLoad[OwnedLoadFailureReason] = ActivationOk;
    }
    g_storageBytes = ComputeStorage(); // vector capacities are final here: never iterated again per tick
    return ready;
}
void Stop() {
    if (!g_started) return;
    // Runtime drains the owner before stopping; never clean a published call
    // while it is running, nor rerun it after an exception.
    FreeScratch(g_scratchFirst, true);
    FreeScratch(g_scratchSecond, false);
    FreeScratch(g_scratchThird, false);
    ntw2_sweep::Stop(); ntw2_resolve::Stop(); ntw2_env::Stop(); g_shadowEnabled = false;
    DestroyOwned();
    g_gridValid = false; g_gridModel = 0;
    ReleaseGrid();
    ReleaseRelink();
    if (g_workers) VirtualFree(g_workers, 0, MEM_RELEASE);
    g_workers = nullptr;
    g_storageBytes = 0; memset(g_storageWords, 0, sizeof(g_storageWords)); memset(g_catalogStorage, 0, sizeof(g_catalogStorage));
    g_started = false;
    g_timingEnabled = false; // retain the published generation's metadata/counters
}
U Classify(void* entity) {
    __try { return ClassifyImpl(Address(entity)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return Lifetime; }
}
void ResetServiceTrace() { g_traceCount = 0; g_entityServices = 0; }
const ServiceRecord* ServiceTrace(U* count) { if (count) *count = g_traceCount; return g_trace; }
void Run(void* entity, bool wrapper) {
    if (!g_started || g_runDepth || !(wrapper ? g_binding.wrap_clone : g_binding.move_clone))
        RaiseException(ERROR_INVALID_STATE, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    ++g_runDepth;
    ResetServiceTrace();
    const U frameBase = g_serviceDepth;
    const LONGLONG start = g_timingEnabled ? Now() : 0;
    __try { Call(wrapper ? g_binding.wrap_clone : g_binding.move_clone, Address(entity)); }
    __finally {
        if (g_timingEnabled) RecordCloneTime(Now() - start);
        AbandonServiceFrames(frameBase);
        FinishServices();
        --g_runDepth;
    }
}
U __fastcall Stage(void* manager) {
    const U m = Address(manager);
    if (!g_started || g_stage || g_runDepth) {
        if (g_started) ++g_words[ReentryRefusals];
        Call(V(0x531AF0), m);
        return D(m + 0x264) + 4 * D(m + 0x260);
    }
    // Epoch authorization belongs to the runtime's current tick, not the
    // first thread seen in this battle. A quiescent tick-owner handoff must
    // not disable all later serial occurrences on the new owner.
    g_words[OwnerThread] = GetCurrentThreadId();
    g_stage = true;
    ++g_words[Calls];
    const LONGLONG dispatchStart = Now();
    g_gridValid = false; g_gridCommittedReady = false; // publication occurs only after replay
    if (g_shadowEnabled) {
        __try { ntw2_sweep::Activate(D(D(m)+8)); }
        __except(EXCEPTION_EXECUTE_HANDLER) { /* Before records a failed capture without changing gameplay. */ }
    }
    U entities = 0;
    U cursor = D(m + 0x264);
    U end = cursor + 4 * D(m + 0x260);
    __try {
        PrepareOwned(m);
        if (g_binding.grid_window) g_binding.grid_window(manager, 1); // probation: owner's relink window opens
        const LONGLONG replayStart = g_binding.use_owned_services ? Now() : 0;
        if (g_relinkMode) RelinkBeginStage();
        g_cwShadowIndex = ~0u;
        while (cursor != end) {
            const U parallel = g_binding.use_owned_services ? (CommitOwned(m, cursor) ? 1u : 0u) : ParallelRun(m, cursor, end);
            if (parallel) {
                entities += parallel; cursor += parallel * 4;
                end = D(m + 0x264) + 4 * D(m + 0x260);
                continue;
            }
            const U a = D(cursor);
            g_stageEntity = a; g_stageOrdinal = (cursor - D(m + 0x264)) / 4;
            if (B(a + 0x30) == 1) {
                ++entities;
                const U reason = CountEntity(a);
                const bool selector = Candidate(D(a));
                if (g_binding.use_parallel) {
                    ++g_parallelWords[ParallelOwnerEntities];
                    const U needs = g_binding.use_owned_services ? 0 : WorkerReason(a);
                    if (needs) ++g_parallelWords[needs];
                    if (needs == ParallelNeedsEnv) {
                        ++g_parallelWords[ParallelNeedsSweep]; ++g_parallelWords[ParallelNeedsResolve];
                    }
                    if (g_parallelWords[ParallelSticky]) ++g_parallelWords[ParallelNativeFallbacks];
                    if (g_binding.use_owned_services) ++g_ownedWords[OwnedFallbackEntities];
                }
                const LONGLONG start = g_quiet ? 0 : Now();
                const bool sampleFallback = g_binding.use_owned_services && !(++g_ownedFallbackSeq & 15);
                const LONGLONG fallbackStart = sampleFallback ? Now() : 0;
                LONGLONG elapsed = 0;
                if (!reason && g_binding.use_clone && !g_parallelWords[ParallelSticky]) {
                    ++g_words[Cloned];
                    ++g_runDepth;
                    ResetServiceTrace();
                    const U frameBase = g_serviceDepth;
                    // The class wrapper's children are updated through untapped native virtuals: flush first, its gates run natively.
                    if (g_relinkWindow) { if (D(a) == V(0x132BA04)) RelinkBarrier(RelinkCauseClassWrapper); else g_relinkLogging = true; }
                    __try { Call(D(a) == V(0x132BA04) ? g_binding.class_wrap_clone : g_binding.selector_clone, a); }
                    __finally {
                        g_relinkLogging = false;
                        if (!g_quiet) {
                            elapsed = Now() - start;
                            RecordCloneTime(elapsed);
                        }
                        AbandonServiceFrames(frameBase);
                        FinishServices();
                        --g_runDepth;
                    }
                } else {
                    ++g_words[Native];
                    if (g_relinkWindow) RelinkBarrier(RelinkCauseFallback);
                    Call(D(D(a) + 0x10), a);
                    if (!g_quiet) elapsed = Now() - start;
                }
                if (sampleFallback) {
                    g_replayFallbackTicks += Now() - fallbackStart;
                    g_ownedPhase[OwnedPhaseReplayFallbackEstUs] = Microseconds(g_replayFallbackTicks * 16);
                }
                if (!g_quiet) {
                    const U us = Microseconds(elapsed);
                    const U sum = reason ? RejectedUs : AdmittedUs;
                    g_words[sum] += us;
                    Max(sum + 1, us);
                }
                // Selector tests A3 AFTER integrating; the pre-call value can
                // differ at map bounds. No staging callback is replayed here.
                if (selector && B(a + 0xA3) == 0) ++g_words[Staging];
                if (g_cwShadowIndex != ~0u) CwShadowCompare(); // --loco-cw-shadow: native wrapper just ran at this ordinal
            } else ++g_words[Filtered];
            // Exact 531AF0 semantics: keep the absolute cursor; reload BOTH
            // list base and count after each occurrence (including filtered).
            cursor += 4;
            end = D(m + 0x264) + 4 * D(m + 0x260);
        }
        if (g_relinkWindow) RelinkEndStage();
        if (g_binding.use_owned_services) {
            const U replayUs = Microseconds(Now() - replayStart);
            g_ownedWords[OwnedReplayUs] += replayUs;
            g_ownedPhase[OwnedPhaseReplayLoopUs] += replayUs;
            g_parallelWords[ParallelReplayUs] += replayUs;
        }
        if (g_binding.use_grid) CaptureGrid(manager); // one end-of-site-13 publication for following collision
    } __finally {
        if (g_relinkWindow) RelinkAbortStage();
        // Probation: the owner's relink window closes after replay and grid publication; this re-arms the heads.
        if (g_binding.grid_window) g_binding.grid_window(manager, 0);
        const U us = Microseconds(Now() - dispatchStart);
        g_words[DispatchUs] += us;
        Max(DispatchMaxUs, us);
        Max(MaxEntities, entities);
        g_stage = false;
        g_stagingActive = false;
        g_stageEntity = g_stageOrdinal = 0;
        g_parallelInFlight = 0;
        if (g_owned) g_owned->valid = false;
    }
    return end;
}
void Sample(U words[WordCount]) { memcpy(words, g_words, sizeof(g_words)); }
void SampleGates(U words[GateWordCount]) { memcpy(words, g_gateWords, sizeof(g_gateWords)); }
void SampleGrid(U words[GridWordCount]) { memcpy(words, g_gridWords, sizeof(g_gridWords)); }
void SampleGridV2(U words[GridV2WordCount]) { memcpy(words, g_gridV2Words, sizeof(g_gridV2Words)); }
void SampleGridBuild(U words[GridBuildWordCount]) {
    memcpy(words, g_gridBuildWords, sizeof(g_gridBuildWords));
    for (U phase = 0; phase < 4; ++phase) words[GridBuildRegistryUs + phase] = Microseconds(g_gridBuildTicks[phase]);
}
#ifdef NTW2_LOCO_ORACLE
void DebugGrid(long long* out) { for (int i = 0; i < 8; ++i) { out[i] = g_dbg[i]; g_dbg[i] = 0; } }
#endif
void SampleParallel(U words[ParallelWordCount]) { memcpy(words, g_parallelWords, sizeof(g_parallelWords)); }
void SampleRelink(U words[RelinkWordCount]) { memcpy(words, g_relinkWords, sizeof(g_relinkWords)); }
void SampleClassWrapper(U words[CwWordCount]) { memcpy(words, g_cwWords, sizeof(g_cwWords)); }
void SampleOwned(U words[OwnedWordCount]) { memcpy(words, g_ownedWords, sizeof(g_ownedWords)); }
void SampleOwnedDetails(U words[OwnedDetailWordCount]) { memcpy(words, g_ownedDetails, sizeof(g_ownedDetails)); }
void SampleOwnedPhase(U words[OwnedPhaseWordCount]) { memcpy(words, g_ownedPhase, sizeof(g_ownedPhase)); }
void SampleOwnedLoad(U words[OwnedLoadWordCount]) { memcpy(words, g_ownedLoad, sizeof(g_ownedLoad)); }
U StorageBytes() { return g_storageBytes; }
void SampleStorage(U words[StorageWordCount]) { memcpy(words, g_storageWords, sizeof(g_storageWords)); }
void SampleCatalogStorage(U words[CatalogStorageWordCount]) { memcpy(words, g_catalogStorage, sizeof(g_catalogStorage)); }
U EstimateActivationBytes(const ntw2_workload::Capacity& capacity) {
    if (!g_started || !ValidCapacity(capacity)) return 0xFFFFFFFFu;
    unsigned long long total = 0;
    if (g_binding.use_grid && !g_grid) {
        GridStore plan = {};
        const U chunks = GridChunkCount();
        total += (CarveGrid(capacity, chunks, plan, nullptr, g_binding.grid_incremental) + 4095) & ~4095ull;
        if (g_binding.grid_incremental && g_binding.verify_grid) { // the shadow store of the verification is a plain full store
            GridStore shadowPlan = {};
            total += (CarveGrid(capacity, chunks, shadowPlan, nullptr, false) + 4095) & ~4095ull;
        }
    }
    if (g_relinkMode && !g_moveLog.block) total += RelinkPlanBytes(capacity, g_relinkMode);
    if (g_owned && !g_owned->activated) {
        total += static_cast<unsigned long long>(capacity.primary) * (sizeof(OwnedSlot) + sizeof(U) + 1);
        if (g_cwMode) total += ((capacity.primary + 3ull) & ~3ull) - capacity.primary +
            static_cast<unsigned long long>(capacity.primary) * kCwBytesPerOrdinal;
        for (U i = 0; i < g_owned->participantsCount; ++i)
            if (g_owned->participants[i] && !g_owned->participants[i]->ctx) total += sizeof(OwnedContexts);
    }
    return total >= 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<U>(total);
}
bool CaptureGrid(void* manager) {
    if (!g_started || !g_binding.use_grid) return false;
    g_gridValid = false;
    bool captured = false;
    __try { captured = g_grid && CaptureGridImpl(Address(manager)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_gridWords[GridFaults]; ++g_gridV2Words[GridV2Faults]; }
    if (!captured) { ++g_gridWords[GridRefusals]; ++g_gridV2Words[GridV2Refusals]; }
    g_gridValid = captured;
    return captured;
}
const GridView* ReadGrid() { return g_started && g_gridValid ? &g_gridView : nullptr; }
const GridView* ReadGridForCollision(void* manager) {
    const GridView* view = ReadGrid();
    if (!view || g_stage || view->manager != Address(manager)) return nullptr;
    __try {
        const U m = Address(manager), root = D(m), model = root ? D(root + 8) : 0;
        if (model != view->model || D(model + 0xA4) != view->grid ||
            D(m + 0x24C) != view->primary_count || D(m + 0x278) != view->secondary_count ||
            D(m + 0x250) != view->primary_registry || D(m + 0x27C) != view->secondary_registry) return nullptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    // The collision adapter additionally checks every identity and live geometry
    // before any solver writes; no chain import or lazy rebuild occurs here.
    return view;
}
void SampleServices(U words[ServiceWordCount]) {
    TimingTotals totals;
    for (;;) {
        const LONG before = _InterlockedCompareExchange(&g_timingSequence, 0, 0);
        if (before & 1) { YieldProcessor(); continue; }
        memcpy(&totals, &g_timingTotals, sizeof(totals));
        memcpy(words, g_timingWords, sizeof(g_timingWords));
        if (_InterlockedCompareExchange(&g_timingSequence, 0, 0) == before) break;
    }
    if (g_frequency.QuadPart <= 0) return;
    const auto frequency = static_cast<unsigned long long>(g_frequency.QuadPart);
    const auto us = [frequency](unsigned long long ticks) {
        return static_cast<U>((ticks / frequency) * 1000000ull + ((ticks % frequency) * 1000000ull) / frequency);
    };
    words[TimingCloneWallUs] = us(totals.cloneWall);
    words[TimingUnionUs] = us(totals.serviceUnion);
    // Compare raw totals before wrapping the public cumulative u32 words.
    words[TimingOutsideUs] = totals.cloneWall >= totals.serviceUnion
        ? words[TimingCloneWallUs] - words[TimingUnionUs] : 0;
    for (U i = 0; i < ServiceCount; ++i) {
        words[TimingServiceUs + i] = us(totals.service[i]);
        words[TimingServiceMaxUs + i] = us(totals.maximum[i]);
    }
}
#ifdef NTW2_LOCO_ORACLE
U SetServiceTargetForTest(Service service, U address) {
    if (service >= ServiceCount || !address || g_runDepth || g_serviceDepth) return 0;
    const U old = g_serviceTargets[service];
    g_serviceTargets[service] = address;
    return old;
}
OwnedLayoutForTest OwnedLayout() {
    return {static_cast<U>(sizeof(OwnedSlot)), kGuardBytes, kOutputBytes, kWrapperBytes,
        static_cast<U>(kGuardSpanCount), static_cast<U>(kOutputSpanCount), static_cast<U>(kWrapperSpanCount), static_cast<U>(kAlwaysWrittenCount),
        kGuardSpans, kOutputSpans, kWrapperSpans, kAlwaysWritten};
}
void SetRelinkMinCellsForTest(U cells) { g_relinkMinCells = cells; }
U RelinkStubForTest(U insert) { return g_serviceTargets[insert ? InsertGrid : UnlinkGrid]; }
void RelinkWindowForTest(bool open) {
    if (open) { RelinkBeginStage(); g_relinkLogging = g_relinkWindow; } else RelinkEndStage();
}
OwnedServiceObserverForTest SetOwnedServiceObserverForTest(OwnedServiceObserverForTest observer) {
    if (g_stage || g_runDepth || g_parallelInFlight) return g_ownedObserver;
    const auto previous = g_ownedObserver; g_ownedObserver = observer; return previous;
}
#endif
} // namespace ntw2_loco
