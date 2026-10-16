#ifndef NTW2_PLANNER_PREPASS_H
#define NTW2_PLANNER_PREPASS_H
// AI planner think census (--ai-prepass-census) + behaviour-preserving presizing (--ai-presize), and the shared walk-key
// module that the prepass children consume (analysis/native-ai-planner-los-spec.md section 10).
//
// Everything here runs on the thread that EXECUTES the think (AI worker under NTW2_AI_ASYNC, tick thread otherwise). Census is
// observation only: native always executes exactly once, in the native order, with the caller's registers, flags, stack and
// x87/SSE state; the only game memory touched is read, behind SEH guards.
//
// Census row (ntw2_status::ai_prepass_census_words, 64 words; labels NTW2_AI_PREPASS_CENSUS_LABELS in ntw2_runtime.h):
//  0 version           1 scopes (site-34 thinks)  2 node_thinks   3 child_thinks    4 walks          5 walks_in_child
//  6 distinct          7 duplicates               8 dup_same_child 9 unsupported    10 overflow     11 max_walks_scope
//  12 max_distinct_scope 13 max_walks_child      14 think_us_sum  15 think_us_max   16 walk_us      17 gather_us
//  18 traversal_us     19 max_walk_us             20 polygon_tests 21 res_al0        22 res_al1      23 gathered_sum
//  24 gathered_max     25 list_unsupported        26 child_us_sum  27 child_us_max   28 d1_checked   29 d1_other_thinks
//  30 d1_other_words   31 d1_list_thinks          32 d1_self_thinks 33 d1_self_words 34 d1_truncated 35 world_diff
//  36 world_same       37 site_7C7FD3             38 site_7C8113   39 site_other
//  40..54 five think-duration classes (<=8,<=32,<=128,<=512,>512 ms) x {thinks, think_us, walk_us}
//  55 presize_queries  56 presize_reserved        57 presize_skipped_nonempty 58 presize_skipped_nobound
//  59 presize_clamped  60 presize_alloc_failed    61 presize_pairs_reserved   62 presize_hits_sum   63 flags latched
//  64 poly_vertices_sum 65 poly_vertices_max      66 poly_hit (kernel AL=1)   67 poly_vertices_unreadable
//  68..73 kernel calls by polygon vertex count V (<=8,<=16,<=32,<=64,<=256,>256)   74..79 kernel us by the same buckets
//  80 site_808492 (walks from the observer route's 0x808040 clone)   81 poly_v_gt1024 (rings longer than kMaxCountedVertices: bucket only)
#include <stdint.h>

namespace ntw2_prepass {
using U = uint32_t;

constexpr U kCensusVersion = 1;
constexpr U kCensusWords = 82;

// ---------------------------------------------------------------------------------------------------- walk key (contract)
// Walk 0x7F1D40: thiscall, ECX = path owner, one stack dword = pointer to the 0x48-byte shape descriptor written by 0x7E1BD0,
// `ret 4`. The key is {preferred callee VA, ECX, fixed gather mask 0x10, the 18 descriptor dwords by value with dword 3
// (angle in the low 16 bits, high half padding) masked to its low 16 bits}. Identity is ALWAYS full-key equality.
constexpr U kWalkVa = 0x7F1D40u;
constexpr U kGatherMask = 0x10u;
constexpr U kKeyWords = 21;
struct WalkKey { U w[kKeyWords]; };
// False for a null/unreadable shape (SEH-safe) or a shape kind (dword 0) other than 0 (OBB). `out` is written only on success.
bool ReadWalkKey(U ecx, const void* shape, WalkKey* out);
// FNV-1a (32-bit) over the 21 words in order.
U HashWalkKey(const WalkKey& key);
bool EqualWalkKey(const WalkKey& a, const WalkKey& b);

// ----------------------------------------------------------------------------------------------- gathered-list hash (contract)
// `entries` is the gather output's data array (walk caller list 0x15AFDA8: count at +8, data at +0xC); each entry points to a
// record {+0: type (0x10 = polygon interest), +0xC: owner}. `mode` / `threshold` are shape dwords 16 / 17 (mode 1: polygons whose
// owner[+0x20] >= threshold reach 0x80DCF0; mode 2: owners with owner[+0x1C]==1 reach 0x808F90). In list order the hash covers
// the entry pointer, entry type and (type 0x10) the owner pointer, owner[+8] polygon pointer, owner[+0x1C], owner[+0x20], and for
// the entries the traversal consumes the polygon's ring by value: vertex count and every vertex (node[3], node[4]; next = node[2]),
// bounded to kMaxPolygonVertices. SEH-safe. The Ex form reports why the hash is only a lower bound.
constexpr U kMaxPolygonVertices = 64;
constexpr U kMaxListEntries = 4096;
constexpr U kMaxCountedVertices = 1024;   // census vertex-count histogram bound (independent of the list-hash bound above)
enum ListFlag : U {
    kListUnreadable = 1u,  // an entry/owner/polygon read faulted
    kListOversize = 2u,    // more than kMaxListEntries entries, or a polygon ring longer than kMaxPolygonVertices
    kListMode2 = 4u        // mode != 1: the 0x808F90 closure is not proven; hash computed with the same field set
};
U HashGatheredListEx(const U* entries, U count, U mode, float threshold, U* flags);
U HashGatheredList(const U* entries, U count, U mode, float threshold);

// ------------------------------------------------------------------------------------------------ ordered query log (contract)
enum RecordFlag : uint8_t {
    kRecUnsupportedKey = 1,   // key unreadable / shape kind != 0 (the key field is zero)
    kRecListUnsupported = 2,  // listHash is a lower bound (see ListFlag)
    kRecDuplicate = 4,        // key already seen in this planner scope
    kRecWorldChanged = 8,     // duplicate whose list hash differs from the previous occurrence
    kRecOverflow = 16,        // distinct table could not classify (probe exhaustion)
    kRecNoChild = 32          // walk issued outside any child think (child == kNoChild)
};
constexpr U kNoChild = 0xFFFFFFFFu;
// gatherCycles / traversalCycles are QueryPerformanceCounter ticks (saturated to 32 bits), converted with the status frequency.
struct QueryRecord {
    WalkKey key;
    U site;           // original call VA of the walk (0x7C7FD3 / 0x7C8113), 0 when not one of the covered call sites
    U child;          // index in [T+0x4C], kNoChild outside a child think
    U gathered;       // list count right after the gather returned (before the walk resets it)
    U listHash;
    U polygonTests;   // 0x80DCF0 / 0x808F90 calls during this walk
    U polygonVertices; // sum of the vertex counts of the 0x80DCF0 polygons tested during this walk (bounded ring read)
    U gatherCycles;
    U traversalCycles;
    uint8_t result;   // AL of the walk (1: no polygon contact / mode-2 hit, see spec 10.2)
    uint8_t flags;    // RecordFlag bits
};
constexpr U kLogCapacity = 1024;
// One log per NODE think: the first ThinkLogBegin for a (planner, node) after ThinkLogEnd (or for a different node) clears it;
// further Begins for the same pair accumulate (children in [T+0x4C] order x their queries in issue order) and only change the
// child index stamped on later appends. Owner thread only; fixed storage; no allocation.
void ThinkLogBegin(U planner, U node, U child);
bool ThinkLogAppend(const QueryRecord& record);  // false: log full (counted by ThinkLogOverflow)
void ThinkLogEnd();
U ThinkLogCount();
const QueryRecord* ThinkLogRecord(U index);      // null when out of range
U ThinkLogPlanner();
U ThinkLogNode();
U ThinkLogChild();
U ThinkLogOverflow();
bool ThinkLogOpen();

// ------------------------------------------------------------------------------------- D1 cross-child snapshot (pure logic)
// Per child: [C+0x30] / [C+0x40] (the counts the child think guards on) and the data pointers [C+0x34] / [C+0x44] they guard.
constexpr U kMaxChildren = 256;
constexpr U kChildWords = 4;
struct D1State {
    U count, data, n;          // [T+0x48], [T+0x4C], children snapshotted (<= kMaxChildren)
    bool truncated, valid;
    U child[kMaxChildren];
    U words[kMaxChildren][kChildWords];
};
struct D1Diff {
    U listChanged;       // 1: [T+0x48] or [T+0x4C] changed, or a snapshotted child pointer changed
    U otherChildren;     // children other than `self` with at least one changed word
    U otherWords;        // total changed words in those children
    U selfWords;         // changed words of `self`
};
bool D1Capture(U node, D1State* state);                                  // SEH-safe; false: [T+0x48]/[T+0x4C] unreadable
void D1Compare(const D1State& pre, U node, U self, D1Diff* out);         // re-reads the live lists

// ------------------------------------------------------------------------------------------------------------- census engine
constexpr U kFlagCensus = 1u;   // NTW2_AI_PREPASS_CENSUS
constexpr U kFlagPresize = 2u;  // NTW2_AI_PRESIZE
struct Targets {
    U nodeOriginal;        // 0x7D7BF0 (live VA)
    U nodeClone;           // CLONE_AI_THINK entry
    U shapeSearchEntry;    // CLONE_AI_SHAPE_SEARCH entry (walk call sites are classified by return address)
    bool (*inScope)(U threadId);  // true while `threadId` executes a site-34 planner update
    U route808040Entry;    // sibling's offset-preserving CLONE of 0x808040: its 0x808492 call enters the AI_WALK clone; 0 = not routed
};
// Clears every counter and table. `flags` = kFlag* bits (0: the row stays all-zero). `qpcFrequency` converts ticks to
// microseconds. Only with the gates unpublished.
void CensusReset(U flags, const Targets& targets, int64_t qpcFrequency);
bool CensusArmed();

void ScopeBegin(U planner);                         // site 34 entry (outermost; nested entries are folded by the caller)
void ScopeEnd(U thinkUs);                           // site 34 exit: classification by duration class
void WalkBegin(U ecx, U shape, U returnAddress, int64_t now);
void WalkGathered(U listHeader, int64_t frameTicks, int64_t now);
// Per polygon-predicate return. `polygon` = the stack argument (ring head; null = not a kernel/0x80DCF0 call so V is not read),
// `eax` = AL result, `ticks` = QPC ticks of the call. V is counted by a bounded SEH-safe ring walk (next = node[2]).
void WalkPolygon(U polygon, U eax, int64_t ticks);
void WalkEnd(U eax, int64_t frameTicks, int64_t now);

// Publishes the census row (version, counters, converted times; presize counters in 55..62).
void CensusSnapshot(volatile U* words);

// Preferred-base vtable words (+0x10 slot of ten node classes) each pinned to 0x7D7BF0.
constexpr U kNodeThinkSlotCount = 10;
extern const U kNodeThinkSlots[kNodeThinkSlotCount];
constexpr U kNodeThinkOriginal = 0x7D7BF0u;
// Naked gates: the slot gate (this = node; in scope it calls the clone and closes the node frame, else tail-jumps the original) and
// the AI_THINK clone binding (replaces `mov eax,[ecx]; call [eax+0x28]`; ECX = child, EDI = node, ESI = child index).
U NodeThinkGateAddress();
U ChildThinkGateAddress();

// ------------------------------------------------------------------------------------------------------------- presizing
// 0x559090 hit-pair buffer (analysis/native-ai-planner-los-spec.md 10.4): at clone offset of 0x55930E, after the cell bounds
// are stored, reserve ONCE per query. Pairs are 8 bytes, the vector header is {+4 capacity, +8 count, +0xC data}, appended once
// per accepted cell, so pairs <= (xHi-xLo)*(yHi-yLo) (unsigned). The reservation is query-local (the caller 0x551FE0 only
// consumes count and the pairs; its free at 0x5523BD is unchanged) and made with the native allocator 0x449E10.
constexpr U kPresizeMaxPairs = 256;
constexpr U kPresizeSlot = 0x13247ECu;       // vtable word holding 0x56A610 (the only route to 0x551FE0)
constexpr U kPresizeSlotOriginal = 0x56A610u;
enum ReserveResult : U { kReserved = 0, kSkippedNonEmpty, kSkippedNoBound, kReservedClamped, kAllocFailed };
using AllocFn = void* (__cdecl*)(int count, int unused);   // 0x449E10 (callee: count*8 bytes from the game's allocator)
void PresizeConfigure(AllocFn allocator);
// Pure core of the gate: `header` points at the vector {tag, capacity, count, data}.
ReserveResult PresizeReserve(U xLo, U xHi, U yLo, U yHi, U* header);
U PresizeReserveGateAddress();   // inserted at 0x55930E (EAX/ECX/EDX/ESI/EFLAGS/x87/SSE preserved)
U PresizeExitGateAddress();      // inserted at 0x559BFE (everything preserved)
void PresizeCounters(volatile U* out8);       // {queries, reserved, nonempty, nobound, clamped, alloc_failed, pairs_reserved, hits}
}

// Gate bodies (stdcall, preserve EBX/ESI/EDI/EBP). `frame` = ESP of the clone body at the insertion point.
extern "C" {
ntw2_prepass::U __stdcall ntw2_pp_NodeEnter(ntw2_prepass::U node);  // 0: original; otherwise the clone to call (node frame opened)
void __stdcall ntw2_pp_NodeLeave(ntw2_prepass::U node);
void __stdcall ntw2_pp_ChildPre(ntw2_prepass::U node, ntw2_prepass::U child, ntw2_prepass::U index);
void __stdcall ntw2_pp_ChildPost(ntw2_prepass::U node, ntw2_prepass::U child, ntw2_prepass::U index);
void __stdcall ntw2_pp_PresizeReserve(ntw2_prepass::U frame);
void __stdcall ntw2_pp_PresizeExit(ntw2_prepass::U frame);
}
#endif
