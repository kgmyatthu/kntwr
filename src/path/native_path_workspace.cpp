// See native_path_workspace.h.  Every function below states the native VA it mirrors; all arithmetic is single precision
// SSE exactly in the operand order of the original instructions (build /arch:SSE2 /fp:strict, never x87).
#include "native_path_workspace.h"

#include <cmath>
#include <cstring>
#include <emmintrin.h>
#include <initializer_list>

namespace ntw_path_workspace {

namespace {

inline float sqrt_ss(float v) { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(v))); }
inline float fabs_f(float v) {
    uint32_t b;
    std::memcpy(&b, &v, 4);
    b &= 0x7FFFFFFFu;
    std::memcpy(&v, &b, 4);
    return v;
}
inline size_t align_up(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }
// f-value used by the open heap: movss [e+0x10]; addss [e+0xC]  (h + g)
inline float f_of(const Entry* e) {
    const float h = e->h;
    return h + e->g;
}

// 0x7DF8B0 (cdecl data, hole, top, &value): std::__push_heap with the strict "parent f > value f" move rule.
inline void sift_up(Entry** data, int hole, int top, Entry* value) {
    if (top >= hole) {
        data[hole] = value;
        return;
    }
    for (;;) {
        const int parent = (hole - 1) >> 1;
        Entry* p = data[parent];
        const float pf = f_of(p);
        const float vf = f_of(value);
        if (!(pf > vf)) break;      // comiss xmm0(parent), xmm1(value); jbe -> stop (also when unordered)
        data[hole] = p;
        hole = parent;
        if (!(top < parent)) break; // cmp ebx(top), ecx(parent); jl loop
    }
    data[hole] = value;
}

}  // namespace

const char* ResultName(Result r) {
    switch (r) {
        case Result::kFound: return "Found";
        case Result::kNoPath: return "NoPath";
        case Result::kExpansionLimit: return "ExpansionLimit";
        case Result::kNeedSuccessors: return "NeedSuccessors";
        case Result::kOk: return "Ok";
        case Result::kBadArgument: return "BadArgument";
        case Result::kBadState: return "BadState";
        case Result::kBadNode: return "BadNode";
        case Result::kCapacityOpen: return "CapacityOpen";
        case Result::kCapacityNeighbors: return "CapacityNeighbors";
        case Result::kCapacityOutput: return "CapacityOutput";
        case Result::kCapacityEntries: return "CapacityEntries";
        case Result::kCapacityNodes: return "CapacityNodes";
        case Result::kCapacityHash: return "CapacityHash";
        case Result::kSuccessorFailed: return "SuccessorFailed";
    }
    return "?";
}

// ---------------------------------------------------------------------------------------------------------------------
// exact native helpers

// 0x7ED270  thiscall(self = ecx; other = [esp+4]) -> al
static bool nodes_equal(const Node* self, const Node* other, uint32_t special) {
    if (special != 0 && other->goalMarker == 1) return self->goalMarker == 1;
    if (self->object != other->object) return false;
    if (self->goalMarker != other->goalMarker) return false;
    // |a-b| <= 0.01f through "comiss eps, |d|; jb fail": NaN is unordered -> fail
    if (!(fabs_f(self->x - other->x) <= kNodeEqualityEpsilon)) return false;
    if (!(fabs_f(self->y - other->y) <= kNodeEqualityEpsilon)) return false;
    return fabs_f(self->z - other->z) <= kNodeEqualityEpsilon;
}

bool NodesEqual(const Node* self, const Node* other) {
    uint32_t special;
    std::memcpy(&special, static_cast<const uint8_t*>(self->query) + kQuerySpecialGoalOffset, 4);
    return nodes_equal(self, other, special);
}

// 0x7EFF60  thiscall(this = from; to): (sqrt(dx^2 + dy^2 + dz^2) + from.accumulated) * from.scale   (float result)
float EdgeCost(const Node* from, const Node* to) {
    const float dy = from->y - to->y;       // movss [ecx+8]; subss [eax+8]
    const float dx = from->x - to->x;       // movss [ecx+4]; subss [eax+4]
    const float dz = from->z - to->z;       // movss [ecx+0xC]; subss [eax+0xC]
    const float ay = dy * dy;
    const float ax = dx * dx;
    const float az = dz * dz;
    float s = ax + ay;
    s = s + az;
    const float d = sqrt_ss(s);
    const float t = d + from->accumulated;
    return t * from->scale;
}

// 0x808D20  thiscall(this = n; goal): linear 1.5 * distance while [n.graph+0xE4] < 500, else ((acc + dist) * scale)^2
float Heuristic(const Node* n, const Node* goal) {
    const float dx = n->x - goal->x;
    const float dy = n->y - goal->y;
    const float dz = n->z - goal->z;
    const float ax = dx * dx;
    const float ay = dy * dy;
    const float az = dz * dz;
    float s = ax + ay;
    s = s + az;
    const float d = sqrt_ss(s);
    if (n->graph->expansions < kHeuristicSwitch) return d * kHeuristicLinearScale;
    float t = n->accumulated + d;
    t = t * n->scale;
    return t * t;
}

uint32_t NodeHash(const Node* n) {
    if (n == nullptr) return kNullKeyHash;
    if (n->object == nullptr) return 0;
    uint32_t v;
    std::memcpy(&v, static_cast<const uint8_t*>(n->object) + kObjectHashOffset, 4);
    return v;
}

static NodeReadSnapshot capture_reads(const Node* n) {
    NodeReadSnapshot r{NodeHash(n), 0};
    if (n) std::memcpy(&r.specialGoal, static_cast<const uint8_t*>(n->query) + kQuerySpecialGoalOffset, 4);
    return r;
}

// 0x809C40  thiscall(container = ecx; value): linear search of the u32 array {count @+0x30, data @+0x34}
static bool container_has(const uint8_t* container, uint32_t value) {
    uint32_t count;
    const uint32_t* data;
    std::memcpy(&count, container + 0x30, 4);
    std::memcpy(&data, container + 0x34, 4);
    for (uint32_t i = 0; i < count; ++i)
        if (data[i] == value) return true;
    return false;
}

// 0x7FE320  stdcall(query, a, b) -> al ; ret 0xC
uint8_t RegionCrossFlag(const void* query, const Node* a, const Node* b) {
    const uint8_t* aobj = static_cast<const uint8_t*>(a->object);
    if (b->goalMarker == 1) {
        const uint8_t* special;
        std::memcpy(&special, static_cast<const uint8_t*>(query) + kQuerySpecialGoalOffset, 4);
        if (special == nullptr) return 1;
        const uint8_t* container;
        std::memcpy(&container, aobj + kObjectRegionOffset, 4);
        const uint32_t token = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(special + 0xC));
        return container_has(container, token) ? 0 : 1;
    }
    const uint8_t* bobj = static_cast<const uint8_t*>(b->object);
    uint32_t ra, rb;
    std::memcpy(&rb, bobj + kObjectRegionOffset, 4);
    std::memcpy(&ra, aobj + kObjectRegionOffset, 4);
    return rb == ra ? 0 : 1;
}

uint32_t HashBucketsForLevel(uint32_t level) {
    uint64_t b = kHashLevel0Buckets;
    for (uint32_t i = 0; i < level; ++i) {
        b = b * 2 + 1;
        if (b > 0x10000000ull) return 0;
    }
    return static_cast<uint32_t>(b);
}

// ---------------------------------------------------------------------------------------------------------------------
// layout / lifecycle

bool ComputeLayout(const Config& c, Layout* out) {
    if (c.openCapacity == 0 || c.neighborCapacity == 0 || c.outputCapacity == 0 || c.entryBlocks == 0 || c.nodeBlocks == 0
        || c.hashLevels == 0 || c.hashLevels > 24 || c.openCapacity > 0x10000000u || c.neighborCapacity > 0x10000000u
        || c.outputCapacity > 0x10000000u || c.entryBlocks > 0x100000u || c.nodeBlocks > 0x100000u)
        return false;
    uint32_t maxBuckets[2] = {0, 0};
    for (uint32_t l = 0; l < c.hashLevels; ++l) {
        const uint32_t b = HashBucketsForLevel(l);
        if (b == 0) return false;
        if (b > maxBuckets[l & 1]) maxBuckets[l & 1] = b;
    }
    Layout L{};
    uint64_t off = 0;
    auto take = [&](size_t& dst, uint64_t bytes) {
        off = (off + 63) & ~63ull;
        dst = static_cast<size_t>(off);
        off += bytes;
    };
    take(L.graph, sizeof(Graph));
    take(L.seeds, 3ull * sizeof(Node));
    take(L.open, (static_cast<uint64_t>(c.openCapacity) + 1) * 4);
    take(L.neighbors, static_cast<uint64_t>(c.neighborCapacity) * 4);
    take(L.output, static_cast<uint64_t>(c.outputCapacity) * 4);
    take(L.hashBuf[0], static_cast<uint64_t>(maxBuckets[0]) * sizeof(HashRow));
    take(L.hashBuf[1], static_cast<uint64_t>(maxBuckets[1]) * sizeof(HashRow));
    take(L.entryBlocks, static_cast<uint64_t>(c.entryBlocks) * kBlockBytes);
    take(L.nodeBlocks, static_cast<uint64_t>(c.nodeBlocks) * kBlockBytes);
    take(L.neighborReads, static_cast<uint64_t>(c.neighborCapacity) * sizeof(NodeReadSnapshot));
    take(L.entryReads, static_cast<uint64_t>(c.entryBlocks) * kEntriesPerBlock * sizeof(NodeReadSnapshot));
    take(L.hashReads[0], static_cast<uint64_t>(maxBuckets[0]) * sizeof(NodeReadSnapshot));
    take(L.hashReads[1], static_cast<uint64_t>(maxBuckets[1]) * sizeof(NodeReadSnapshot));
    off = (off + 63) & ~63ull;
    if (off > 0x70000000ull) return false;   // must stay far below the 2 GiB x86 user address space
    L.total = static_cast<size_t>(off);
    L.hashBufBuckets[0] = maxBuckets[0];
    L.hashBufBuckets[1] = maxBuckets[1];
    *out = L;
    return true;
}

size_t Workspace::RequiredBytes(const Config& cfg) {
    Layout L;
    return ComputeLayout(cfg, &L) ? L.total : 0;
}

static void link_arena(Arena* a, uint8_t* blocks, uint32_t count) {
    std::memset(a, 0, sizeof(*a));       // thread mode 0, allocator 0, tls 0, critical section bytes zero (never entered)
    for (uint32_t i = 0; i < count; ++i) {
        auto b = reinterpret_cast<ArenaBlock*>(blocks + static_cast<size_t>(i) * kBlockBytes);
        b->next = (i + 1 < count) ? reinterpret_cast<ArenaBlock*>(blocks + static_cast<size_t>(i + 1) * kBlockBytes) : nullptr;
        b->used = 0;
    }
    a->head = reinterpret_cast<ArenaBlock*>(blocks);
    a->current = a->head;
    a->blocks = count;
}

Result Workspace::Init(void* storage, size_t bytes, const Config& cfg) {
    if (graph_ != nullptr) return Result::kBadState;
    Layout L;
    if (storage == nullptr || !ComputeLayout(cfg, &L)) return Result::kBadArgument;
    if ((reinterpret_cast<uintptr_t>(storage) & (kAlignment - 1)) != 0 || bytes < L.total) return Result::kBadArgument;
    auto base = static_cast<uint8_t*>(storage);
    std::memset(base, 0, L.total);

    cfg_ = cfg;
    base_ = base;
    bytes_ = bytes;
    Graph* g = reinterpret_cast<Graph*>(base + L.graph);
    // 0x7EB020
    g->vtable = cfg.graphVtable;
    g->root = cfg.root;
    g->self = g;
    g->overwriteNode = cfg.overwriteNode;
    g->open = Vector{0, cfg.openCapacity, 0, base + L.open};
    g->neighbors = Vector{0, cfg.neighborCapacity, 0, base + L.neighbors};
    link_arena(&g->entries, base + L.entryBlocks, cfg.entryBlocks);
    link_arena(&g->nodes, base + L.nodeBlocks, cfg.nodeBlocks);
    g->start = nullptr;
    hashBuf_[0] = reinterpret_cast<HashRow*>(base + L.hashBuf[0]);
    hashBuf_[1] = reinterpret_cast<HashRow*>(base + L.hashBuf[1]);
    hashBufBuckets_[0] = L.hashBufBuckets[0];
    hashBufBuckets_[1] = L.hashBufBuckets[1];
    neighborReads_ = reinterpret_cast<NodeReadSnapshot*>(base + L.neighborReads);
    entryReads_ = reinterpret_cast<NodeReadSnapshot*>(base + L.entryReads);
    hashReads_[0] = reinterpret_cast<NodeReadSnapshot*>(base + L.hashReads[0]);
    hashReads_[1] = reinterpret_cast<NodeReadSnapshot*>(base + L.hashReads[1]);
    successorsSealed_ = false;
    hashLevel_ = 0;
    g->hash = Hash{hashBuf_[0], 0, kHashLevel0Buckets, nullptr, nullptr};
    g->expansions = 0;
    g->expansionLimit = cfg.expansionLimit;
    g->output = Vector{0, cfg.outputCapacity, 0, base + L.output};
    g->goal = nullptr;
    g->query = nullptr;
    for (int i = 0; i < 3; ++i) g->goalPos[i] = cfg.constants.sentinelPos[i];
    g->segment[0] = cfg.constants.sentinelPair[0];
    g->segment[1] = cfg.constants.sentinelPair[1];
    g->segment[2] = cfg.constants.sentinelPair[0];
    g->segment[3] = cfg.constants.sentinelPair[1];
    g->totalExpansions = 0;
    g->flag124 = 0;
    g->regionFlag = 0;
    seeds_ = reinterpret_cast<Node*>(base + L.seeds);
    graph_ = g;
    for (unsigned i = 0; i < 3; ++i) ClearSeed(seeds_ + i);
    phase_ = Phase::kIdle;
    last_ = Result::kOk;
    callbackResult_ = Result::kOk;
    sticky_ = Result::kOk;
    pendingEntry_ = nullptr;
    return Result::kOk;
}

void Workspace::Shutdown() {
    graph_ = nullptr;
    base_ = nullptr;
    bytes_ = 0;
    seeds_ = nullptr;
    hashBuf_[0] = hashBuf_[1] = nullptr;
    neighborReads_ = entryReads_ = nullptr;
    hashReads_[0] = hashReads_[1] = nullptr;
    successorsSealed_ = false;
    phase_ = Phase::kIdle;
    pendingEntry_ = nullptr;
}

void Workspace::ClearSeed(Node* n) {
    std::memset(n, 0, sizeof(*n));
    n->graph = graph_;
}

bool Workspace::Validate(const char** why) const {
    auto bad = [&](const char* m) {
        if (why) *why = m;
        return false;
    };
    if (!graph_) return bad("uninitialised");
    const Graph& g = *graph_;
    const uint8_t* lo = base_;
    const uint8_t* hi = base_ + bytes_;
    auto inside = [&](const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        return b >= lo && b <= hi && n <= static_cast<size_t>(hi - b);
    };
    if (g.self != graph_) return bad("self pointer");
    if (!inside(g.open.data, (static_cast<size_t>(g.open.capacity) + 1) * 4) || g.open.size > g.open.capacity) return bad("open vector");
    if (!inside(g.neighbors.data, static_cast<size_t>(g.neighbors.capacity) * 4) || g.neighbors.size > g.neighbors.capacity) return bad("neighbour vector");
    if (!inside(g.output.data, static_cast<size_t>(g.output.capacity) * 4) || g.output.size > g.output.capacity) return bad("output vector");
    if (g.hash.emptyKey != nullptr) return bad("hash empty key");
    if (g.hash.rows != hashBuf_[hashLevel_ & 1] || g.hash.buckets != HashBucketsForLevel(hashLevel_)) return bad("hash level");
    if (!inside(g.hash.rows, static_cast<size_t>(g.hash.buckets) * sizeof(HashRow))) return bad("hash rows");
    if (!inside(neighborReads_, static_cast<size_t>(cfg_.neighborCapacity) * sizeof(NodeReadSnapshot))
        || !inside(entryReads_, static_cast<size_t>(cfg_.entryBlocks) * kEntriesPerBlock * sizeof(NodeReadSnapshot)))
        return bad("read snapshot storage");
    for (unsigned i = 0; i < 2; ++i)
        if (!inside(hashReads_[i], static_cast<size_t>(hashBufBuckets_[i]) * sizeof(NodeReadSnapshot)))
            return bad("hash read snapshot storage");
    for (const Arena* a : {&g.entries, &g.nodes}) {
        if (a->threadMode != 0 || a->allocator != nullptr) return bad("arena thread mode");
        uint32_t n = 0;
        bool sawCurrent = false;
        for (const ArenaBlock* b = a->head; b; b = b->next) {
            if (!inside(b, kBlockBytes) || ++n > a->blocks || b->used > kBlockData) return bad("arena chain");
            if (b == a->current) sawCurrent = true;
        }
        if (n != a->blocks || !sawCurrent) return bad("arena chain length/current");
    }
    return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// arena / vectors / hash

// 0x80B0F0 -> 0x79AE00 (thread mode 0), blocks pre-linked: the native "allocate a block" branches are the exhaustion case.
void* Workspace::ArenaAlloc(Arena* a, uint32_t size) {
    ArenaBlock* blk = a->current;
    if (blk == nullptr) return nullptr;
    constexpr uint32_t align = 1u << kArenaShift;
    const uint32_t need = size + align;                 // add ebx, edi
    if (need > kBlockData - blk->used) {                // cmp ebx, eax; jbe fits
        ArenaBlock* nx = blk->next;
        if (nx == nullptr) return nullptr;              // native: 0x10D3140 -> game heap (never taken here)
        nx->used = 0;                                   // mov [eax+0x2804], 0
        a->current = nx;
        blk = nx;
    }
    uintptr_t p = reinterpret_cast<uintptr_t>(blk) + blk->used;
    if ((p & (align - 1)) != 0) p = (p & ~static_cast<uintptr_t>(align - 1)) + align;
    blk->used += need;
    return reinterpret_cast<void*>(p);
}

Node* Workspace::AllocNode() {
    if (!graph_) return nullptr;
    void* p = ArenaAlloc(&graph_->nodes, kNodeBytes);
    if (p == nullptr && sticky_ == Result::kOk) sticky_ = Result::kCapacityNodes;
    return static_cast<Node*>(p);
}

uint32_t Workspace::NodeCapacity() const {
    if (!graph_) return 0;
    const Arena& a = graph_->nodes;
    if (!a.current) return 0;
    constexpr uint32_t need = kNodeBytes + (1u << kArenaShift);
    // link_arena reserves contiguous, permanently linked blocks. Native allocation only advances current;
    // walking every remaining block here made every owner callback proportional to the arena reservation.
    const uintptr_t offset = reinterpret_cast<uintptr_t>(a.current) - reinterpret_cast<uintptr_t>(a.head);
    const uint32_t current = static_cast<uint32_t>(offset / kBlockBytes);
    return (kBlockData - a.current->used) / need + (a.blocks - current - 1) * (kBlockData / need);
}

bool Workspace::PushNeighbor(Node* n) {
    if (!graph_) return false;
    Vector& v = graph_->neighbors;
    if (n == nullptr || n->graph != graph_ || n->query == nullptr) {
        if (sticky_ == Result::kOk) sticky_ = Result::kBadNode;
        return false;
    }
    if (v.size >= v.capacity) {                          // native 0x448B90 grows through the game heap
        if (sticky_ == Result::kOk) sticky_ = Result::kCapacityNeighbors;
        return false;
    }
    static_cast<Node**>(v.data)[v.size++] = n;
    successorsSealed_ = false;
    return true;
}

Result Workspace::SealSuccessors() {
    if (!graph_ || phase_ != Phase::kExpanding) return Result::kBadState;
    if (sticky_ != Result::kOk) return Fail(sticky_);
    const Vector& v = graph_->neighbors;
    if (v.size > cfg_.neighborCapacity) return Fail(Result::kCapacityNeighbors);
    Node* const* nodes = static_cast<Node* const*>(v.data);
    for (uint32_t i = 0; i < v.size; ++i) {
        const Node* n = nodes[i];
        if (!n || n->graph != graph_ || !n->query) return Fail(Result::kBadNode);
        neighborReads_[i] = capture_reads(n);
    }
    successorsSealed_ = true;
    return Result::kOk;
}

NodeReadSnapshot& Workspace::EntryReads(const Entry* e) {
    const uintptr_t off = reinterpret_cast<uintptr_t>(e) - reinterpret_cast<uintptr_t>(graph_->entries.head);
    const size_t index = (off / kBlockBytes) * kEntriesPerBlock + (off % kBlockBytes) / (kEntryBytes + 4);
    return entryReads_[index];
}

// 0x8113E0
Result Workspace::PushOpen(Entry* e) {
    Vector& v = graph_->open;
    if (v.size >= v.capacity) return Result::kCapacityOpen;
    static_cast<Entry**>(v.data)[v.size++] = e;
    return Result::kOk;
}

// 0x807AF0 (find; returns the value, native returns &row.value)
Entry* Workspace::FindEntry(const Node* key) const {
    return FindEntrySnapshot(key, capture_reads(key));
}

Entry* Workspace::FindEntrySnapshot(const Node* key, NodeReadSnapshot reads) const {
    const Hash& h = graph_->hash;
    const uint32_t buckets = h.buckets;
    const uint32_t start = reads.hash % buckets;
    for (uint32_t pass = 0; pass < 2; ++pass) {
        const uint32_t lo = pass ? 0 : start;
        const uint32_t hi = pass ? start : buckets;
        for (uint32_t i = lo; i < hi; ++i) {
            const HashRow& r = h.rows[i];
            const bool match = (key == nullptr) ? (r.key == nullptr) : (r.key != nullptr && nodes_equal(key, r.key, reads.specialGoal));
            if (match) return r.value;
            if (r.key == nullptr) return nullptr;       // empty-key sentinel test (sentinel is null)
        }
    }
    return nullptr;
}

// 0x814270 (insert / update, grow when completely full)
Result Workspace::HashPut(Node* key, Entry* value, NodeReadSnapshot reads) {
    Hash& h = graph_->hash;
    for (;;) {
        const uint32_t buckets = h.buckets;
        const uint32_t start = reads.hash % buckets;
        for (uint32_t pass = 0; pass < 2; ++pass) {
            const uint32_t lo = pass ? 0 : start;
            const uint32_t hi = pass ? start : buckets;
            for (uint32_t i = lo; i < hi; ++i) {
                HashRow& r = h.rows[i];
                const bool match = (key == nullptr) ? (r.key == nullptr) : (r.key != nullptr && nodes_equal(key, r.key, reads.specialGoal));
                if (match) {
                    r.value = value;
                    return Result::kOk;
                }
                if (r.key == nullptr) {
                    r.key = key;
                    r.next = h.head;
                    ++h.count;
                    h.head = &r;
                    r.value = value;
                    hashReads_[hashLevel_ & 1][i] = reads;
                    return Result::kOk;
                }
            }
        }
        // table completely full: new bucket array of 2n+1 rows, re-insert, free old, retry
        if (hashLevel_ + 1 >= cfg_.hashLevels) return Result::kCapacityHash;
        HashRow* oldRows = h.rows;
        NodeReadSnapshot* oldReads = hashReads_[hashLevel_ & 1];
        const uint32_t oldBuckets = buckets;
        const uint32_t oldCount = h.count;
        HashRow* oldHead = h.head;
        const uint32_t newBuckets = HashBucketsForLevel(hashLevel_ + 1);
        HashRow* nr = hashBuf_[(hashLevel_ + 1) & 1];
        std::memset(nr, 0, static_cast<size_t>(newBuckets) * sizeof(HashRow));
        ++hashLevel_;
        h.buckets = newBuckets;
        h.rows = nr;
        h.count = 0;
        h.head = nullptr;
        if ((oldCount << 2) <= oldBuckets) {              // sparse: walk the intrusive list (newest first)
            for (HashRow* p = oldHead; p != nullptr; p = p->next) {
                const Result r = HashPut(p->key, p->value, oldReads[p - oldRows]);
                if (r != Result::kOk) return r;
            }
        } else {                                          // dense: walk the old array in row order
            for (uint32_t i = 0; i < oldBuckets; ++i) {
                HashRow* p = oldRows + i;
                if (p->key == nullptr) continue;
                const Result r = HashPut(p->key, p->value, oldReads[i]);
                if (r != Result::kOk) return r;
            }
        }
    }
}

// 0x7F70B0
void Workspace::HashClear() {
    Hash& h = graph_->hash;
    if ((h.count << 2) <= h.buckets) {
        for (HashRow* p = h.head; p != nullptr; p = p->next) p->key = nullptr;
    } else {
        for (uint32_t i = 0; i < h.buckets; ++i) h.rows[i].key = nullptr;
    }
    h.head = nullptr;
    h.count = 0;
}

// ---------------------------------------------------------------------------------------------------------------------
// engine

Result Workspace::Fail(Result r) {
    phase_ = Phase::kFailed;
    last_ = r;
    pendingEntry_ = nullptr;
    return r;
}

// 0x802A80 up to the 0x7E04D0 call
Result Workspace::SeedSearch(const Node* t, const Node* goal, NodeReadSnapshot reads) {
    Graph& g = *graph_;
    g.entries.current = g.entries.head;
    if (g.entries.head) g.entries.head->used = 0;
    g.nodes.current = g.nodes.head;
    if (g.nodes.head) g.nodes.head->used = 0;
    g.open.size = 0;
    HashClear();
    Node* n = static_cast<Node*>(ArenaAlloc(&g.nodes, kNodeBytes));
    if (!n) return Result::kCapacityNodes;
    n->object = t->object;
    n->x = t->x;
    n->y = t->y;
    n->z = t->z;
    n->tag = t->tag;
    n->aux14 = t->aux14;
    n->flag18 = t->flag18;
    n->flag19 = t->flag19;
    n->graph = t->graph;
    n->query = t->query;
    n->goalMarker = t->goalMarker;
    n->aux28 = t->aux28;
    n->scale = t->scale;
    n->accumulated = t->accumulated;
    g.start = n;
    Entry* e = static_cast<Entry*>(ArenaAlloc(&g.entries, kEntryBytes));
    if (!e) return Result::kCapacityEntries;
    const float h = Heuristic(n, goal);
    e->node = n;
    EntryReads(e) = reads;
    e->state = 0;
    e->parent = nullptr;
    e->g = 0.0f;
    e->h = h;
    Result r = PushOpen(e);
    if (r != Result::kOk) return r;
    return HashPut(n, e, reads);
}

// 0x807620
Result Workspace::BuildOutput(Entry* e, bool append) {
    Vector& v = graph_->output;
    Node** data = static_cast<Node**>(v.data);
    const uint32_t base = v.size;
    if (!append) {
        for (; e != nullptr; e = e->parent) {
            if (v.size >= v.capacity) return Result::kCapacityOutput;
            data[v.size++] = e->node;
        }
    } else if (e != nullptr) {
        Entry* cur = e;
        while (cur->parent != nullptr) {                  // the root entry (duplicate of the previous leg's end) is skipped
            if (v.size >= v.capacity) return Result::kCapacityOutput;
            data[v.size++] = cur->node;
            cur = cur->parent;
        }
    }
    for (uint32_t i = 0, half = (v.size - base) >> 1; i < half; ++i) {
        Node* t = data[base + i];
        data[base + i] = data[v.size - 1 - i];
        data[v.size - 1 - i] = t;
    }
    return Result::kOk;
}

// 0x7E04D0, the neighbour loop (0x7E05C8 .. 0x7E07BC)
Result Workspace::Relax() {
    Graph& g = *graph_;
    Entry* pe = pendingEntry_;
    Node* pn = pe->node;
    Node** nb = static_cast<Node**>(g.neighbors.data);
    const uint32_t count = g.neighbors.size;
    for (uint32_t k = 0; k < count; ++k) {
        Node* n = nb[k];
        const float cost = EdgeCost(pn, n);
        const float ng = pe->g + cost;
        // skip iff (ng > limit) && (0 < limit)   (comiss/jbe, comiss/jb with unordered => proceed on the first test)
        const bool skip = (ng > limit_) && (0.0f < limit_);
        if (!skip) {
            const NodeReadSnapshot reads = neighborReads_[k];
            Entry* e = FindEntrySnapshot(n, reads);
            if (e == nullptr) {
                e = static_cast<Entry*>(ArenaAlloc(&g.entries, kEntryBytes));
                if (!e) return Result::kCapacityEntries;
                e->node = n;
                EntryReads(e) = reads;
                e->state = 2;
                e->parent = nullptr;
                e->g = 0.0f;
                e->h = 0.0f;
                const Result r = HashPut(n, e, reads);
                if (r != Result::kOk) return r;
            }
            if ((e->state != 0 && e->state != 1) || ng < e->g) {
                if (g.overwriteNode == 1) {
                    e->node = n;
                    EntryReads(e) = reads;
                }
                e->g = ng;
                e->h = Heuristic(n, goal_);
                const bool wasOpen = (e->state == 0);
                e->parent = pe;
                Entry** data = static_cast<Entry**>(g.open.data);
                if (wasOpen) {
                    Entry** p = data;
                    Entry** end = data + g.open.size;
                    while (p != end && *p != e) ++p;
                    const int idx = static_cast<int>(p - data) + 1;
                    if (idx >= 2) sift_up(data, idx - 1, 0, *p);   // *p == data[size] when e is not in the heap (native reads it too)
                } else {
                    e->state = 0;
                    const Result r = PushOpen(e);
                    if (r != Result::kOk) return r;
                    const int size = static_cast<int>(g.open.size);
                    if (size >= 2) sift_up(data, size - 1, 0, data[size - 1]);
                }
            }
        }
        ++g.expansions;
        if (g.expansions > g.expansionLimit) return Result::kExpansionLimit;
    }
    return Result::kOk;
}

// 0x8026F0 epilogue (0x802A0B..)
void Workspace::Epilogue() {
    Graph& g = *graph_;
    g.goal = nullptr;
    g.query = nullptr;
    for (int i = 0; i < 3; ++i) g.goalPos[i] = cfg_.constants.sentinelPos[i];
    g.totalExpansions += g.expansions;
    g.segment[0] = cfg_.constants.sentinelPair[0];
    g.segment[1] = cfg_.constants.sentinelPair[1];
    g.segment[2] = cfg_.constants.sentinelPair[0];
    g.segment[3] = cfg_.constants.sentinelPair[1];
    g.flag124 = 0;
    g.regionFlag = 0;
}

// leg 1 found with a via node -> 0x8026F0 0x80296F..0x8029EA seeds leg 2 on the SAME graph (no arena reset); otherwise terminal
Result Workspace::FinishLeg(bool found, Result reason, const NodeReadSnapshot* reads) {
    Graph& g = *graph_;
    if (found && leg_ == 0 && via_ != nullptr && !bare_) {
        Node* goal = finalGoal_;
        g.goal = goal;
        g.goalPos[0] = goal->x;
        g.goalPos[1] = goal->y;
        g.goalPos[2] = goal->z;
        g.segment[0] = via_->x;
        g.segment[1] = via_->z;
        g.segment[2] = goal->x;
        g.segment[3] = goal->z;
        g.regionFlag = regionFlag2_;
        g.open.size = 0;
        HashClear();
        if (g.output.size == 0) return Fail(Result::kBadState);   // cannot happen after a found leg
        Node* last = static_cast<Node**>(g.output.data)[g.output.size - 1];
        Entry* e = static_cast<Entry*>(ArenaAlloc(&g.entries, kEntryBytes));
        if (!e) return Fail(Result::kCapacityEntries);
        const float h = Heuristic(last, goal);
        e->node = last;
        EntryReads(e) = *reads;
        e->state = 0;
        e->parent = nullptr;
        e->g = 0.0f;
        e->h = h;
        Result r = PushOpen(e);
        if (r == Result::kOk) r = HashPut(last, e, *reads);
        if (r != Result::kOk) return Fail(r);
        leg_ = 1;
        goal_ = goal;
        append_ = true;
        phase_ = Phase::kRunning;
        return Result::kOk;
    }
    if (!bare_) Epilogue();
    phase_ = Phase::kDone;
    pendingEntry_ = nullptr;
    last_ = found ? Result::kFound : reason;
    return last_;
}

Result Workspace::Begin(const SolveRequest& r) {
    if (!graph_ || phase_ == Phase::kRunning || phase_ == Phase::kExpanding) return Result::kBadState;
    if (r.query == nullptr || r.start == nullptr || r.goal == nullptr) return Result::kBadArgument;
    auto ok = [&](const Node* n) { return n->graph == graph_ && n->query != nullptr; };
    if (!ok(r.start) || !ok(r.goal) || (r.via != nullptr && !ok(r.via))) return Result::kBadNode;
    Graph& g = *graph_;
    sticky_ = Result::kOk;
    callbackResult_ = Result::kOk;
    pendingEntry_ = nullptr;
    // 0x8026F0 prologue
    g.expansions = 0;
    g.output.size = 0;
    g.flag124 = r.flag124;
    g.query = r.query;
    if (r.via != nullptr && !r.bareEngine) r.via->flag18 = 1;   // 0x8027B9: mov byte [via+0x18], 1 right after the 0x7EB210 seed build
    Node* target = r.via ? r.via : r.goal;
    g.goal = target;
    g.goalPos[0] = target->x;
    g.goalPos[1] = target->y;
    g.goalPos[2] = target->z;
    g.segment[0] = r.start->x;
    g.segment[1] = r.start->z;
    g.segment[2] = target->x;
    g.segment[3] = target->z;
    g.regionFlag = r.regionFlagLeg1;
    finalGoal_ = r.goal;
    via_ = r.via;
    goal_ = target;
    leg_ = 0;
    limit_ = r.costLimit;
    append_ = false;
    bare_ = r.bareEngine;
    regionFlag2_ = r.regionFlagLeg2;
    successorsSealed_ = false;
    const Result s = SeedSearch(r.start, target, capture_reads(r.start));
    if (s != Result::kOk) return Fail(s);
    phase_ = Phase::kRunning;
    return Result::kOk;
}

// 0x7E04D0 main loop head: pop the best entry (0x7E04F0..0x7E0589), goal test, hand the node to the successor
Result Workspace::Advance() {
    if (!graph_ || (phase_ != Phase::kRunning && phase_ != Phase::kExpanding)) return Result::kBadState;
    Graph& g = *graph_;
    for (;;) {
        if (sticky_ != Result::kOk) return Fail(sticky_);
        if (phase_ == Phase::kExpanding) {
            if (!successorsSealed_) return Result::kBadState;
            const Result r = Relax();
            if (r == Result::kExpansionLimit) return FinishLeg(false, Result::kExpansionLimit);
            if (r != Result::kOk) return Fail(r);
            pendingEntry_->state = 1;                       // mov [ebp+4], 1
            pendingEntry_ = nullptr;
            phase_ = Phase::kRunning;
        }
        const uint32_t n = g.open.size;
        if (n == 0) return FinishLeg(false, Result::kNoPath);
        Entry** data = static_cast<Entry**>(g.open.data);
        if (n >= 2) {
            Entry* tmp = data[n - 1];
            data[n - 1] = data[0];
            const int idx = static_cast<int>(n) - 1;
            const int ebp = (idx - 1) >> 1;
            int hole = 0;
            if (ebp > 0) {
                int cur = 0, child = 0;
                do {
                    child *= 2;
                    const float fl = f_of(data[child + 1]);
                    const float fr = f_of(data[child + 2]);
                    int pick = child + 1;
                    if (!(fr > fl)) pick = child + 2;      // comiss xmm0(right), xmm1(left); cmovbe: right when right <= left or unordered
                    data[cur] = data[pick];
                    cur = pick;
                    child = pick;
                } while (child < ebp);
                hole = child;
            }
            if (hole == ebp && (idx & 1) == 0) {
                data[hole] = data[idx - 1];
                hole = idx - 1;
            }
            sift_up(data, hole, 0, tmp);
        }
        Entry* e = data[n - 1];
        if (nodes_equal(e->node, goal_, EntryReads(e).specialGoal)) {
            if (n >= 2) sift_up(data, static_cast<int>(n) - 1, 0, data[n - 1]);   // 0x7E082B: re-sift the popped goal entry
            const Result r = BuildOutput(e, append_);
            if (r != Result::kOk) return Fail(r);
            const Result f = FinishLeg(true, Result::kFound, &EntryReads(e));
            if (f == Result::kOk) continue;                  // leg 2 armed
            return f;
        }
        g.open.size = n - 1;                                 // dec [esi+0x10]
        g.neighbors.size = 0;                                // mov [esi+0x20], 0
        successorsSealed_ = false;
        pendingEntry_ = e;
        phase_ = Phase::kExpanding;
        return Result::kNeedSuccessors;
    }
}

Result Workspace::Run(SuccessorFn fn, void* user) {
    if (fn == nullptr) return Result::kBadArgument;
    for (;;) {
        const Result r = Advance();
        if (r != Result::kNeedSuccessors) return r;
        const Result c = fn(user, *this, PendingNode());
        if (c != Result::kOk) {
            callbackResult_ = c;
            return Fail(Result::kSuccessorFailed);
        }
        const Result sealed = SealSuccessors();
        if (sealed != Result::kOk) return sealed;
    }
}

}  // namespace ntw_path_workspace
