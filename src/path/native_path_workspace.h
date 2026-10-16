// Private native-path search workspace for the original x86 Napoleon Total War (approved image SHA-256
// 13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4, preferred base 0x400000).
//
// WHAT THIS IS
//   A bit-exact, instruction-validated C++ port of the pathfinder's graph engine and of its owning state:
//     G  = pf+0x1BC, 0x128 bytes      constructor 0x7EB020 (this=G, stack: pointer-to-root, ret 4)
//     S  = G+8 (self pointer)         engine 0x802A80(S; out, start, goal, limit) -> 0x7E04D0(S; out, start, goal, limit, append)
//     0x8026F0(G; query, start, goal, via, flag)  the 1- or 2-leg driver (prologue / epilogue / leg-2 reseed)
//   plus the exact helpers the engine inlines or calls: 7DF8B0 (sift-up), 8113E0 (open push), 807AF0/814270/7F70B0
//   (12-byte-row linear-probe hash, find / insert+grow / clear), 79AE00/80B0F0 (0x2808-byte block arena, mode 0),
//   807620 (path unwinding), 7ED270 (epsilon node equality incl. the query+0x34 special-goal rule), 7EFF60 (edge cost),
//   808D20 (heuristic, linear below 500 expansions, squared afterwards), 7FE320/809C40 (region-cross flag).
//
// WHAT IT OWNS (everything lives in ONE caller-supplied, 64-byte aligned block; nothing is allocated, nothing is global)
//   G, three vectors (open heap / neighbours / output), two arenas of pre-linked 0x2808-byte blocks
//   (entries: 0x14-byte stride 0x18; nodes: 0x34-byte stride 0x38), the 12-byte-row hash bucket arrays (two ping-pong
//   buffers, one per level parity), three 0x34-byte seed nodes, and compact sidecars for owner-captured hash IDs /
//   special-goal flags. Native Graph/Node/Entry layouts are unchanged. A Workspace is pinned to its storage address:
//   it must not be memcpy'd / moved. Two workspaces share no mutable engine state. Borrowed object hash IDs and query
//   flags must remain logically stable for a solve, but are dereferenced only by owner-side Begin / SealSuccessors /
//   FindEntry, never by Advance. Caller-owned nodes and seeds must remain stable while Advance executes.
//
// WHAT IT DOES NOT DO (explicit owner-thread seams; see "INTEGRATION GATES" below)
//   * It never calls game code, game allocators (0xFF7F20/0xFF7EF0/0x10D3140), the CRT, or Win32.
//   * Neighbour generation (native 0x800210 -> 0x7EB2A0 node ctor -> 0x81C050 -> 0x67A790 cell scratch, virtual
//     topology callees) is NOT executed by the engine.  It is a callback / owner-driven step:
//       Advance() returns kNeedSuccessors with PendingNode(); the owner fills the neighbour vector
//       (AllocNode / FindEntry / PushNeighbor), calls SealSuccessors() on the owner, then Advance() on any worker.
//       Run() wraps this sequence on its calling thread; it does NOT move world callbacks onto a worker safely.
//   * The native 0x6498B0 / 0x67A790 shared scratch vector (0x14D0A6C) is never touched here.
//
// NATIVE COMPATIBILITY OF THE LAYOUT
//   Graph/Node/Entry/HashRow/Vector/Arena have the exact native offsets (static_asserts below) so the ORIGINAL 0x800210 /
//   0x7EB2A0 can be run by the owner thread against a workspace Graph (arena B = &graph.nodes is arg 3 of 0x800210).
//   Preconditions for that (checked by the helpers listed): the arena chains are pre-linked, so native 0x79AE00 never
//   reaches the game allocator while NodeCapacity() > the call's worst case; the neighbour vector capacity field equals
//   the workspace buffer, so native 0x448B90 never reallocates while edgeCount <= NeighborCapacity(); the arena's
//   thread-mode byte (+0x1C) is 0 and its CRITICAL_SECTION bytes are zero and are NEVER entered (a copied or zeroed
//   live critical section would be invalid).  graph.vtable is whatever Config says (0x1347250+delta for native callees).
//
// CAPACITY
//   Native vectors / arenas / hash grow without bound through the game heap.  The workspace is fixed capacity:
//   exhausting any bound returns a kCapacity* Result, poisons the solve (phase = failed) and NEVER fabricates a path.
//   Hash growth (2n+1: 128, 257, 515, 1031, ...) is reproduced exactly up to Config::hashLevels levels.
//
// FP / THREADING
//   x86 SSE2 single-precision only (no x87 in the engine; build /arch:SSE2 /fp:strict).  Default MXCSR (round to
//   nearest, no FTZ/DAZ) is required for bit equality with the native image.  Distinct workspaces may run on distinct
//   threads concurrently.  One workspace is single-threaded (no internal locking).
#pragma once
#include <cstddef>
#include <cstdint>

#ifndef _M_IX86
#error native_path_workspace mirrors 32-bit x86 pointers; compile as x86.
#endif

namespace ntw_path_workspace {

constexpr uint32_t kBlockBytes = 0x2808;      // arena block: 0x2800 data, +0x2800 next, +0x2804 used
constexpr uint32_t kBlockData = 0x2800;
constexpr uint32_t kNodeBytes = 0x34;
constexpr uint32_t kEntryBytes = 0x14;
constexpr uint32_t kArenaShift = 2;           // push 2 at 0x802AC7/0x802AD9/0x7E0630: alignment 4, slack 4 per allocation
constexpr uint32_t kNodesPerBlock = kBlockData / (kNodeBytes + 4);     // 182
constexpr uint32_t kEntriesPerBlock = kBlockData / (kEntryBytes + 4);  // 426
constexpr uint32_t kHashLevel0Buckets = 0x80; // ctor 0x7EB020
constexpr uint32_t kDefaultExpansionLimit = 3000;
constexpr uint32_t kHeuristicSwitch = 500;    // 808D20 / 800210: [G+0xE4] < 500 -> linear heuristic, no duplicate suppression
constexpr uint32_t kQuerySpecialGoalOffset = 0x34;   // 7ED270 reads dword [node.query + 0x34]
constexpr uint32_t kObjectHashOffset = 0x1C;         // 808D00: hash(node) = node.object ? [object+0x1C] : 0
constexpr uint32_t kNullKeyHash = 0x305A9C4Bu;       // 807AF0/814270 hash of a null key
constexpr uint32_t kObjectRegionOffset = 0x20;       // 7FE320 reads [object+0x20]
constexpr float kHeuristicLinearScale = 1.5f;        // [0x131A7B8]
constexpr float kNodeEqualityEpsilon = 0.01f;        // [0x1318034] (0x3C23D70A)

// 7EB020 stores the 20 bytes at 0x150FCA0 (zero in the pinned image, verified live and by the oracle) into G.
struct Constants {
    float sentinelPair[2] = {0.0f, 0.0f};    // [0x150FCA0], [0x150FCA4]
    float sentinelPos[3] = {0.0f, 0.0f, 0.0f};   // [0x150FCA8..0x150FCB0]
};

struct Graph;
struct Entry;

// ---- node, 0x34 bytes (arena B).  Field evidence: 0x7EB5C0, 0x7EB2A0, 0x7EB210, 0x802A80, 0x7ED270, 0x808D20 ----------
struct Node {
    const void* object;      // +0x00 borrowed topology object; hash id is dword [object+0x1C]; region [object+0x20]
    float x, y, z;           // +0x04 +0x08 +0x0C (path plane is x/z; y is height)
    uint32_t tag;            // +0x10 (edge pointer in native successors; 0 in seeds)
    float aux14;             // +0x14
    uint8_t flag18;          // +0x18 (set when goal.flag18 == 1 on the direct-goal node)
    uint8_t flag19;          // +0x19 (0x800756 sets 1)
    uint8_t pad1a[2];        // +0x1A (never written by 7EB5C0 beyond the word at +0x18; not copied by 802A80)
    Graph* graph;            // +0x1C owning G (read by 808D20 for the expansion counter)
    const void* query;       // +0x20 query object (request+0x28); dword [query+0x34] != 0 enables the special-goal rule
    uint8_t goalMarker;      // +0x24 (0x814990 sets 1): 7ED270 compares it
    uint8_t pad25[3];
    uint32_t aux28;          // +0x28
    float scale;             // +0x2C multiplies edge cost / heuristic
    float accumulated;       // +0x30 added to distance before scaling
};
static_assert(sizeof(Node) == kNodeBytes, "Node size");

// ---- open-list / hash entry, 0x14 bytes (arena A) -------------------------------------------------------------------
struct Entry {
    Node* node;              // +0x00
    uint32_t state;          // +0x04 0 = open, 1 = closed, 2 = unseen (fresh from hash miss)
    Entry* parent;           // +0x08
    float g;                 // +0x0C
    float h;                 // +0x10
};
static_assert(sizeof(Entry) == kEntryBytes, "Entry size");

struct HashRow {             // 12 bytes, array allocated 4-aligned by 0x4536A0 in the native image
    Node* key;               // +0 (null = empty slot; the empty-key sentinel [hash+0x10] is 0)
    Entry* value;            // +4
    HashRow* next;           // +8 intrusive "live rows" list, newest first
};
static_assert(sizeof(HashRow) == 12, "HashRow size");

struct Hash {                // native object at G+0xCC, 0x14 bytes
    HashRow* rows;           // +0x00
    uint32_t count;          // +0x04 inserted keys since last clear/growth
    uint32_t buckets;        // +0x08 128 -> 2n+1 when completely full
    HashRow* head;           // +0x0C
    Node* emptyKey;          // +0x10 always null
};
static_assert(sizeof(Hash) == 0x14, "Hash size");

struct Vector {              // native growable dword vector header, 0x10 bytes (0x444B40 storage)
    uint32_t tag;            // +0x00 never written by the engine
    uint32_t capacity;       // +0x04 (elements)
    uint32_t size;           // +0x08
    void* data;              // +0x0C
};
static_assert(sizeof(Vector) == 0x10, "Vector size");

struct ArenaBlock {
    uint8_t data[kBlockData];
    ArenaBlock* next;        // +0x2800
    uint32_t used;           // +0x2804
};
static_assert(sizeof(ArenaBlock) == kBlockBytes, "block size");

struct Arena {               // native 0x61A700 object, 0x4C bytes (G+0x30 entries, G+0x7C nodes)
    ArenaBlock* head;        // +0x00
    ArenaBlock* current;     // +0x04 blocks head..current are live; later blocks are stale reuse capacity
    uint32_t blocks;         // +0x08 chain length
    uint32_t u0c, u10, u14, u18;
    uint8_t threadMode;      // +0x1C 0 = plain 0x79AE00 path (no TLS, no critical section)
    uint8_t pad1d[3];
    void* allocator;         // +0x20 null in mode 0
    uint32_t u24, u28, u2c;
    void* tlsTable;          // +0x30
    uint8_t criticalSection[0x18];  // +0x34 NEVER initialised or entered here (see header comment)
};
static_assert(sizeof(Arena) == 0x4C, "Arena size");

struct Graph {               // G, 0x128 bytes
    uint32_t vtable;         // +0x00 0x1347250 (+delta)
    const void* root;        // +0x04 borrowed shared root
    Graph* self;             // +0x08 == this; G+8 is `this` of 0x802A80 / 0x7E04D0
    uint8_t overwriteNode;   // +0x0C [S+4]: 1 -> an improving hit overwrites entry->node with the new node
    uint8_t pad0d[3];
    Vector open;             // +0x10 binary min-heap of Entry*, key = h + g
    Vector neighbors;        // +0x20 node* filled by the successor for the expanded node
    Arena entries;           // +0x30 arena A
    Arena nodes;             // +0x7C arena B
    Node* start;             // +0xC8 start node copy (arena B)
    Hash hash;               // +0xCC
    uint32_t pad0e0;         // +0xE0
    uint32_t expansions;     // +0xE4 per-solve neighbour counter ([S+0xDC])
    uint32_t expansionLimit; // +0xE8 3000
    Vector output;           // +0xEC node* path start..goal
    Node* goal;              // +0xFC transient: current leg goal node
    const void* query;       // +0x100 transient: query object
    float goalPos[3];        // +0x104
    float segment[4];        // +0x110 x0,z0,x1,z1 of the current leg
    uint32_t totalExpansions;// +0x120
    uint8_t flag124;         // +0x124 8026F0 param_5
    uint8_t regionFlag;      // +0x125 7FE320 result for the current leg
    uint8_t pad126[2];
};
static_assert(sizeof(Graph) == 0x128, "Graph size");

#define NTW_PW_OFFSET_CHECK(field, off) static_assert(offsetof(Graph, field) == (off), #field)
NTW_PW_OFFSET_CHECK(root, 0x04); NTW_PW_OFFSET_CHECK(self, 0x08); NTW_PW_OFFSET_CHECK(overwriteNode, 0x0C);
NTW_PW_OFFSET_CHECK(open, 0x10); NTW_PW_OFFSET_CHECK(neighbors, 0x20); NTW_PW_OFFSET_CHECK(entries, 0x30);
NTW_PW_OFFSET_CHECK(nodes, 0x7C); NTW_PW_OFFSET_CHECK(start, 0xC8); NTW_PW_OFFSET_CHECK(hash, 0xCC);
NTW_PW_OFFSET_CHECK(expansions, 0xE4); NTW_PW_OFFSET_CHECK(expansionLimit, 0xE8); NTW_PW_OFFSET_CHECK(output, 0xEC);
NTW_PW_OFFSET_CHECK(goal, 0xFC); NTW_PW_OFFSET_CHECK(query, 0x100); NTW_PW_OFFSET_CHECK(goalPos, 0x104);
NTW_PW_OFFSET_CHECK(segment, 0x110); NTW_PW_OFFSET_CHECK(totalExpansions, 0x120); NTW_PW_OFFSET_CHECK(flag124, 0x124);
#undef NTW_PW_OFFSET_CHECK
static_assert(offsetof(Vector, capacity) == 4 && offsetof(Vector, size) == 8 && offsetof(Vector, data) == 0xC, "Vector");
static_assert(offsetof(Entry, g) == 0xC && offsetof(Entry, h) == 0x10 && offsetof(Node, scale) == 0x2C, "Entry/Node");

// ---- results --------------------------------------------------------------------------------------------------------
enum class Result : uint32_t {
    kFound = 0,              // terminal: goal popped, path in Output()           (native engine returned 1)
    kNoPath,                 // terminal: open list exhausted                     (native returned 0)
    kExpansionLimit,         // terminal: counter > graph.expansionLimit          (native returned 0)
    kNeedSuccessors,         // not terminal: owner must supply neighbours for PendingNode() then Advance() again
    kOk,                     // helper succeeded
    kBadArgument,
    kBadState,               // wrong phase / uninitialised / previous solve failed
    kBadNode,                // node with wrong graph / null query / null pointer handed to the engine
    kCapacityOpen,
    kCapacityNeighbors,
    kCapacityOutput,
    kCapacityEntries,
    kCapacityNodes,
    kCapacityHash,
    kSuccessorFailed,        // the owner callback reported failure (callback result is kept in LastCallbackResult)
};
inline bool IsTerminal(Result r) { return r != Result::kNeedSuccessors && r != Result::kOk; }
inline bool IsError(Result r) { return static_cast<uint32_t>(r) >= static_cast<uint32_t>(Result::kBadArgument); }
const char* ResultName(Result r);

struct Config {
    uint32_t openCapacity = 4096;       // max entries in the open heap (storage = capacity + 1 slots, see 7E04D0 slot[size] read)
    uint32_t neighborCapacity = 64;     // max neighbours produced for one expansion
    uint32_t outputCapacity = 1024;     // max nodes in the final path (both legs)
    uint32_t entryBlocks = 16;          // arena A blocks of 0x2808 bytes -> 426 entries each
    uint32_t nodeBlocks = 64;           // arena B blocks of 0x2808 bytes -> 182 nodes each
    uint32_t hashLevels = 6;            // bucket arrays reachable: 128,257,515,1031,2063,4127,...
    uint32_t expansionLimit = kDefaultExpansionLimit;
    uint32_t graphVtable = 0;           // stored in G+0 (0x1347250 + image delta when native callees will run on G)
    const void* root = nullptr;         // stored in G+4
    uint8_t overwriteNode = 0;          // G+0xC
    Constants constants;
};

// Bucket count of hash level k (128 -> 2n+1), 0 on overflow.
uint32_t HashBucketsForLevel(uint32_t level);

struct SolveRequest {
    const void* query = nullptr;  // 8026F0 param_1: stored in G+0x100, borrowed read-only
    const Node* start = nullptr;  // param_2: template node (graph == this graph); copied into arena B like 802A80 does
    Node* goal = nullptr;         // param_3: goal node (graph == this graph); must outlive the solve
    Node* via = nullptr;          // param_4 seed node (7EB210 output; Begin sets via->flag18 = 1 like 0x8027B9); null -> single leg
    uint8_t flag124 = 0;          // param_5
    uint8_t regionFlagLeg1 = 0;   // 7FE320(query, start, via-or-goal)  (RegionCrossFlag, computed by the owner)
    uint8_t regionFlagLeg2 = 0;   // 7FE320(query, via, goal)
    float costLimit = 0.0f;       // 802A80/7E04D0 param_4 (0.0 in every 8026F0 call: unlimited)
    bool bareEngine = false;      // true: only the 802A80/7E04D0 engine on leg 1; no 8026F0 epilogue and no leg 2
};

class Workspace;
// Owner/neighbour generator: fill ws.PushNeighbor() for `parent`.  Return kOk or any error Result.
using SuccessorFn = Result (*)(void* user, Workspace& ws, Node* parent);

// Private values read on the owner; no borrowed object/query pointers. Not part of the native ABI.
struct NodeReadSnapshot {
    uint32_t hash;
    uint32_t specialGoal;
};

struct Layout {                 // byte offsets inside the storage block (all 64-byte aligned)
    size_t graph, seeds, open, neighbors, output, hashBuf[2], entryBlocks, nodeBlocks;
    size_t neighborReads, entryReads, hashReads[2], total;
    uint32_t hashBufBuckets[2];
};
bool ComputeLayout(const Config& cfg, Layout* out);   // false on invalid / overflowing configuration

class Workspace {
public:
    static constexpr size_t kAlignment = 64;
    Workspace() = default;
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;

    static size_t RequiredBytes(const Config& cfg);     // 0 if cfg is invalid
    // Builds G exactly as 0x7EB020 would (but on `storage`, with pre-linked arena blocks).  The storage must stay
    // alive and fixed until Shutdown(); nothing inside is freed by the workspace.
    Result Init(void* storage, size_t bytes, const Config& cfg);
    void Shutdown();                                     // forget the storage (caller frees it); G becomes invalid
    bool Initialized() const { return graph_ != nullptr; }
    // Pointer / invariant audit (self pointer, vector/arena/hash pointers inside the block, chain links, seeds).
    bool Validate(const char** why = nullptr) const;

    Graph& graph() { return *graph_; }
    const Graph& graph() const { return *graph_; }
    const Config& config() const { return cfg_; }
    Node* StartSeed() { return seed(0); }                // zero-initialised nodes with graph == G; owner fills them
    Node* ViaSeed() { return seed(1); }
    Node* GoalSeed() { return seed(2); }
    void ClearSeed(Node* n);

    // ---- solve state machine (mirrors 0x8026F0 -> 0x802A80 -> 0x7E04D0) ------------------------------------------------
    Result Begin(const SolveRequest& req);               // owner: captures the start node's borrowed scalar inputs
    Result SealSuccessors();                            // owner: capture every neighbour's borrowed scalar inputs
    // Runs the engine until it needs neighbours (kNeedSuccessors) or finishes (kFound / kNoPath / kExpansionLimit) or
    // fails (error). Re-entry after kNeedSuccessors requires successful owner-side SealSuccessors(). No game reads/calls.
    Result Advance();
    Result Run(SuccessorFn fn, void* user);              // Begin()+loop already done: loops Advance()/fn until terminal
    Node* PendingNode() const { return pendingEntry_ ? pendingEntry_->node : nullptr; }
    Entry* PendingEntry() const { return pendingEntry_; }
    Result LastResult() const { return last_; }
    Result LastCallbackResult() const { return callbackResult_; }
    bool Solving() const { return phase_ == Phase::kRunning || phase_ == Phase::kExpanding; }

    // ---- successor-side helpers (native: 0x80B0F0 on arena B, 0x807AF0, 0x448B90 on G+0x20) ---------------------------
    // Sticky failure: a failed Alloc/Push records the capacity error; Advance() then reports it and the solve is dead.
    Node* AllocNode();                                   // 0x34 bytes from arena B, alignment 4; contents unspecified
    bool PushNeighbor(Node* n);                          // validates n->graph == G && n->query != null
    Entry* FindEntry(const Node* n) const;               // OWNER ONLY: reads key's object/query, then probes private hash
    // O(1) remaining capacity in Init's contiguous pre-linked node arena; callers must not relink its blocks.
    uint32_t NodeCapacity() const;                       // nodes still allocatable without growing the arena
    uint32_t NeighborCapacity() const { return cfg_.neighborCapacity; }
    uint32_t Expansions() const { return graph_->expansions; }

    // ---- results ---------------------------------------------------------------------------------------------------
    uint32_t OutputCount() const { return graph_->output.size; }
    Node* const* Output() const { return static_cast<Node* const*>(graph_->output.data); }
    uint32_t HashLevel() const { return hashLevel_; }

private:
    enum class Phase : uint32_t { kIdle = 0, kRunning, kExpanding, kDone, kFailed };
    Node* seed(unsigned i) { return seeds_ + i; }
    void* ArenaAlloc(Arena* a, uint32_t size);
    Result PushOpen(Entry* e);
    Entry* FindEntrySnapshot(const Node* key, NodeReadSnapshot reads) const;
    NodeReadSnapshot& EntryReads(const Entry* e);
    Result HashPut(Node* key, Entry* value, NodeReadSnapshot reads);
    void HashClear();
    Result SeedSearch(const Node* startTemplate, const Node* goal, NodeReadSnapshot reads);
    Result Relax();
    Result PopBest(Entry** popped);
    Result BuildOutput(Entry* e, bool append);
    Result FinishLeg(bool found, Result reason, const NodeReadSnapshot* reads = nullptr);
    Result Fail(Result r);
    void Epilogue();

    Graph* graph_ = nullptr;
    Config cfg_{};
    uint8_t* base_ = nullptr;
    size_t bytes_ = 0;
    Node* seeds_ = nullptr;
    HashRow* hashBuf_[2] = {nullptr, nullptr};
    uint32_t hashBufBuckets_[2] = {0, 0};
    uint32_t hashLevel_ = 0;
    NodeReadSnapshot* neighborReads_ = nullptr;
    NodeReadSnapshot* entryReads_ = nullptr;
    NodeReadSnapshot* hashReads_[2] = {nullptr, nullptr};
    bool successorsSealed_ = false;

    Phase phase_ = Phase::kIdle;
    Result last_ = Result::kOk;
    Result callbackResult_ = Result::kOk;
    Result sticky_ = Result::kOk;
    Entry* pendingEntry_ = nullptr;
    Node* goal_ = nullptr;           // goal of the current leg
    Node* finalGoal_ = nullptr;
    Node* via_ = nullptr;
    int leg_ = 0;
    float limit_ = 0.0f;
    bool append_ = false;
    bool bare_ = false;
    uint8_t regionFlag2_ = 0;
};

// ---- exact native helpers, exposed for the oracle and for owner-thread successor ports -------------------------------
bool NodesEqual(const Node* self, const Node* other);             // 0x7ED270 (thiscall self, arg other)
float EdgeCost(const Node* from, const Node* to);                 // 0x7EFF60 (this = from)
float Heuristic(const Node* n, const Node* goal);                 // 0x808D20 (this = n; reads n->graph->expansions)
uint32_t NodeHash(const Node* n);                                 // 0x808D00 (+ null-key rule of 0x807AF0)
// 0x7FE320(query, a, b) / 0x809C40: pure reads of borrowed objects; run on the owner thread while they are stable.
uint8_t RegionCrossFlag(const void* query, const Node* a, const Node* b);

}  // namespace ntw_path_workspace
