// Bulk owned-grid fixtures for native_loco_oracle.cpp (included there, after the oracle's own helpers).
//
// Everything a grid capture reads is synthetic native engine data laid out like the replay's: one 0x700-byte record per
// entity (+2C serial, +30 active, +38 flags, +44 team, +48..+5C pose/radius/bump, +A8 nodes, +AC inserted, +B0 node
// capacity), a separate array of 0x1C-byte nodes per record (+0 type 8, +4 serial, +8 &record+30, +C record, +10/+14 chain
// prev/next, +18 cell head address), a primary registry with null holes plus a secondary registry with holes and primary
// duplicates, and the native grid header (+0 heads, +8 shift, +10 origin, +14 maximum, +24 scale). Node cells come from the
// same x87/SSE arithmetic as the mapped 0x7EFA80 insertion (RefCoordinate: the oracle's own copy, cross-checked against the
// mapped helper by GridNumericCases), and every published view is compared with RefGrid, an independent naive model that
// derives the whole publication (identity, snapshot, rectangles, sorted CSR, direct map, accounting) from native memory.
#pragma once

namespace bulk {

struct Lcg {
    U state;
    U Next() { state = state * 1664525u + 1013904223u; return state >> 8; }
    float Unit() { return static_cast<float>(Next() & 0xffffu) / 65536.0f; }
    U Below(U n) { return n ? Next() % n : 0; }
};

inline float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
inline U RefCoordinate(float value, float scale, U origin, U maximum) {
    float scaled = _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(value), _mm_set_ss(scale))), half = -0.5f;
    int rounded;
    __asm { fld scaled }
    __asm { fadd st(0), st(0) }
    __asm { fadd half }
    __asm { fistp rounded }
    const U coordinate = static_cast<U>(rounded >> 1) + origin;
    return coordinate < maximum ? coordinate : maximum;
}

// Rounding control of the oracle thread (x87 RC and MXCSR RC), restored by the destructor.
struct FpMode {
    unsigned short cw; U mxcsr;
    explicit FpMode(U rounding) {
        unsigned short old; __asm fnstcw word ptr [old]
        cw = old; mxcsr = _mm_getcsr(); Set(rounding);
    }
    static void Set(U rounding) {
        const unsigned short next = static_cast<unsigned short>(0x27f | (rounding << 10));
        __asm fldcw word ptr [next]
        _mm_setcsr(0x1f80 | (rounding << 13));
    }
    ~FpMode() {
        const unsigned short old = cw;
        __asm { fldcw word ptr [old] }
        _mm_setcsr(mxcsr);
    }
};

struct Config {
    U primary = 48128, secondary = 26500;  // registry entries (primary includes null holes, secondary duplicates/holes)
    U spare = 2048;                        // entities (and registry room) for births
    U shift = 10, maximum = 0;             // maximum 0 = (1 << shift) - 1
    float scale = 0.2f;                    // cells per meter
    U origin = 0;
    float spacing = 2.8f;                  // formation lattice spacing, meters
    U formation = 140;                     // entities per formation
    U movingPercent = 43;                  // share of formations that drift
    U seed = 0x5eed1234u;
};

struct Entity {
    float x = 0, z = 0, y = 1, extent = 0, radius = 0.75f;
    U serial = 0, team = 0, flags = 0;
    B active = 1, bump = 0, written = 0;
};

struct World {
    static constexpr U kRecordStride = 0x700, kNodeStride = 0x200, kNodeCapacity = 16;
    Config cfg;
    U maximum = 0, cellCount = 0, entityCap = 0;
    B* records = nullptr; B* nodes = nullptr; U* heads = nullptr;
    std::vector<B> root = std::vector<B>(0x40), model = std::vector<B>(0x100), gridHeader = std::vector<B>(0x40),
                   manager = std::vector<B>(0x300);
    std::vector<U> primary, secondary;     // registry arrays (fixed backing capacity)
    U primaryCount = 0, secondaryCount = 0;
    std::vector<Entity> e;
    std::vector<B> moving;
    std::vector<U> freeList;
    std::vector<float> vx, vz;
    Lcg rng;
    U stage = 0;

    explicit World(const Config& c) : cfg(c) {
        maximum = cfg.maximum ? cfg.maximum : (1u << cfg.shift) - 1;
        cellCount = (maximum << cfg.shift) + maximum + 1;
        entityCap = cfg.primary + cfg.secondary + cfg.spare;
        rng.state = cfg.seed;
        records = static_cast<B*>(VirtualAlloc(nullptr, size_t(entityCap) * kRecordStride, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        nodes = static_cast<B*>(VirtualAlloc(nullptr, size_t(entityCap) * kNodeStride, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        heads = static_cast<U*>(VirtualAlloc(nullptr, size_t(cellCount) * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(records && nodes && heads, "bulk fixture memory");
        primary.assign(cfg.primary + cfg.spare, 0); secondary.assign(cfg.secondary + cfg.spare, 0);
        e.resize(entityCap); moving.assign(entityCap, 0); vx.assign(entityCap, 0); vz.assign(entityCap, 0);
        Put(root.data(), 8, A(model.data())); Put(model.data(), 0xA4, A(gridHeader.data())); Put(model.data(), 0x58, U(1));
        WriteGridHeader();
        Put(manager.data(), 0, A(root.data()));
        Put(manager.data(), 0x250, A(primary.data())); Put(manager.data(), 0x27c, A(secondary.data()));
        Populate();
    }
    ~World() {
        if (records) VirtualFree(records, 0, MEM_RELEASE);
        if (nodes) VirtualFree(nodes, 0, MEM_RELEASE);
        if (heads) VirtualFree(heads, 0, MEM_RELEASE);
    }
    World(const World&) = delete; World& operator=(const World&) = delete;

    B* Rec(U id) const { return records + size_t(id) * kRecordStride; }
    B* Nodes(U id) const { return nodes + size_t(id) * kNodeStride; }
    U Addr(U id) const { return A(Rec(id)); }
    U IdOf(U address) const { return (address - A(records)) / kRecordStride; }
    void* Manager() { return manager.data(); }
    void* Model() { return model.data(); }
    U Total() const { return cfg.primary + cfg.secondary; }
    void WriteGridHeader() {
        Put(gridHeader.data(), 0, A(heads)); Put(gridHeader.data(), 8, cfg.shift); Put(gridHeader.data(), 0x10, cfg.origin);
        Put(gridHeader.data(), 0x14, maximum); Put(gridHeader.data(), 0x24, cfg.scale);
    }
    // Activation capacities of the fixture: registry room for every spare birth, memberships for 6 cells per record.
    ntw2_workload::Capacity Capacity() const {
        ntw2_workload::Capacity c{};
        c.primary = cfg.primary + cfg.spare; c.records = c.primary + cfg.secondary + cfg.spare;
        c.cells = cellCount; c.memberships = c.records * 6; c.pairs = c.primary * 16u;
        return c;
    }

    // Native insertion arithmetic for the entity's current pose.
    void Rect(U id, U& l, U& r, U& t, U& b) const {
        const Entity& n = e[id];
        const float radius = n.bump == 1 ? Add(n.radius, KF(0x1318038)) : n.radius;
        l = RefCoordinate(Sub(n.x, radius), cfg.scale, cfg.origin, maximum); r = RefCoordinate(Add(n.x, radius), cfg.scale, cfg.origin, maximum);
        t = RefCoordinate(Sub(n.z, radius), cfg.scale, cfg.origin, maximum); b = RefCoordinate(Add(radius, n.z), cfg.scale, cfg.origin, maximum);
    }
    // Writes the record's pose/identity bytes and its nodes (or +AC = 0 when unlinked).
    void WriteRecord(U id, bool linked) {
        B* p = Rec(id); Entity& n = e[id]; n.written = 1;
        Put(p, 0x2c, n.serial); Put(p, 0x30, n.active); Put(p, 0x38, n.flags); Put(p, 0x44, n.team);
        Put(p, 0x48, n.x); Put(p, 0x4c, n.y); Put(p, 0x50, n.z); Put(p, 0x54, n.extent); Put(p, 0x58, n.radius); Put(p, 0x5c, n.bump);
        Put(p, 0xa8, A(Nodes(id))); Put(p, 0xb0, kNodeCapacity);
        Relink(id, linked);
    }
    void Relink(U id, bool linked) {
        B* p = Rec(id);
        if (!linked) { Put(p, 0xac, U(0)); return; }
        U l, r, t, b; Rect(id, l, r, t, b);
        Require(l <= r && t <= b && (r - l + 1) * (b - t + 1) <= kNodeCapacity, "bulk fixture coverage fits node capacity");
        U n = 0;
        for (U z = t; z <= b; ++z) for (U x = l; x <= r; ++x, ++n) {
            B* node = Nodes(id) + n * 0x1c; const U cell = (z << cfg.shift) + x;
            Put(node, 0, U(8)); Put(node, 4, e[id].serial); Put(node, 8, A(p) + 0x30); Put(node, 12, A(p));
            Put(node, 0x18, A(heads) + 4 * cell);
        }
        Put(p, 0xac, n);
    }
    bool Linked(U id) const { return Get<U>(Rec(id), 0xac) != 0; }
    // Re-inserts every written record under the current geometry and rounding. A record whose clamped rectangle inverts
    // (positions beyond the grid edge under a new maximum/rounding) is moved to the grid centre first.
    void RelinkAll() {
        for (U id = 0; id < entityCap; ++id) if (e[id].written) {
            const bool linked = Linked(id);
            U l, r, t, b; Rect(id, l, r, t, b);
            if (linked && (l > r || t > b || (r - l + 1) * (b - t + 1) > kNodeCapacity)) {
                e[id].x = e[id].z = (maximum + 1) / (2 * cfg.scale) + static_cast<float>(id % 50);
                WriteRecord(id, true);
            } else Relink(id, linked);
        }
    }
    void SetGeometry(U shift, U maximumOverride, float scale, U origin) {
        const U newMaximum = maximumOverride ? maximumOverride : (1u << shift) - 1;
        Require(shift <= cfg.shift && (newMaximum << shift) + newMaximum + 1 <= cellCount, "fixture geometry fits the allocated heads");
        cfg.shift = shift; cfg.maximum = maximumOverride; cfg.scale = scale; cfg.origin = origin;
        maximum = cfg.maximum ? cfg.maximum : (1u << cfg.shift) - 1;
        WriteGridHeader(); RelinkAll();
    }

    void Populate() {
        const U total = Total();
        const U formations = (total + cfg.formation - 1) / cfg.formation;
        const float extent = static_cast<float>(maximum + 1) / cfg.scale, margin = extent * 0.15f;
        const U columns = 14;
        for (U f = 0; f < formations; ++f) {
            const float cx = margin + rng.Unit() * (extent - 2 * margin), cz = margin + rng.Unit() * (extent - 2 * margin);
            const float dx = (rng.Unit() - 0.5f) * 0.4f, dz = (rng.Unit() - 0.5f) * 0.4f;
            const bool mover = rng.Below(100) < cfg.movingPercent;
            for (U k = 0; k < cfg.formation; ++k) {
                const U id = f * cfg.formation + k;
                if (id >= total) break;
                Entity& n = e[id];
                n.x = cx + static_cast<float>(k % columns) * cfg.spacing + (rng.Unit() - 0.5f) * 0.5f;
                n.z = cz + static_cast<float>(k / columns) * cfg.spacing + (rng.Unit() - 0.5f) * 0.5f;
                n.radius = 0.5f + rng.Unit() * 0.5f; n.bump = rng.Below(32) == 0 ? 1 : 0;
                n.team = 0x1000u + (f & 1u); n.flags = 0x20u | (id & 3u); n.active = rng.Below(64) ? 1 : 0;
                n.serial = 0x91000001u + id * 0x10u;
                moving[id] = mover; vx[id] = dx; vz[id] = dz;
            }
        }
        for (U i = 0; i < total; ++i) WriteRecord(i, true);
        // Registries: primary entities 0..P-1 with a null hole every 37th slot; secondary entities P..P+S-1 with a primary
        // duplicate every 53rd slot and a null every 97th.
        primaryCount = cfg.primary; secondaryCount = cfg.secondary;
        for (U i = 0; i < cfg.primary; ++i) primary[i] = i % 37 == 5 ? 0 : Addr(i);
        for (U i = 0; i < cfg.secondary; ++i)
            secondary[i] = i % 97 == 7 ? 0 : (i % 53 == 11 ? Addr((i * 31u) % cfg.primary) : Addr(cfg.primary + i));
        for (U i = total; i < entityCap; ++i) freeList.push_back(i);
        std::reverse(freeList.begin(), freeList.end());
        SyncRegistry();
    }
    void SyncRegistry() { Put(manager.data(), 0x24c, primaryCount); Put(manager.data(), 0x278, secondaryCount); }
    // Every registered record id once, registry order (primary first).
    std::vector<U> Registered() const {
        std::vector<U> ids; std::vector<B> seen(entityCap, 0);
        auto add = [&](U address) { if (!address) return; const U id = IdOf(address); if (!seen[id]) { seen[id] = 1; ids.push_back(id); } };
        for (U i = 0; i < primaryCount; ++i) add(primary[i]);
        for (U i = 0; i < secondaryCount; ++i) add(secondary[i]);
        return ids;
    }
    // The native chains (+10 prev / +14 next, heads) of every registered, inserted record, rebuilt from the nodes.
    void RebuildChains() {
        memset(heads, 0, size_t(cellCount) * 4);
        for (U id : Registered()) {
            const U count = Get<U>(Rec(id), 0xac);
            for (U n = 0; n < count; ++n) {
                B* node = Nodes(id) + n * 0x1c; const U cell = (Get<U>(node, 0x18) - A(heads)) / 4, head = heads[cell];
                Put(node, 0x14, head); Put(node, 0x10, U(0));
                if (head) Put(reinterpret_cast<void*>(static_cast<uintptr_t>(head)), 0x10, A(node));
                heads[cell] = A(node);
            }
        }
    }

    // ---- mutations: each leaves native memory self-consistent, like a completed engine write ----
    // Formation drift of the moving formations (movers each move with probability percentOfMovers). Returns records touched.
    U Drift(U percentOfMovers, float scale = 1.0f) {
        U touched = 0;
        const U total = Total();
        for (U id = 0; id < total; ++id) {
            if (!moving[id]) continue;
            if (rng.Below(100) >= percentOfMovers) continue;
            touched += Move(id, e[id].x + vx[id] * scale, e[id].z + vz[id] * scale);
        }
        return touched;
    }
    // Every record moves one native cell with the given probability (percent), whatever its formation does.
    U MassShift(U percent, float meters) {
        U touched = 0;
        for (U id = 0; id < Total(); ++id) if (rng.Below(100) < percent) touched += Move(id, e[id].x + meters, e[id].z);
        return touched;
    }
    // Moves the record when the native insert arithmetic yields a valid rectangle at the new pose (clamp edges can invert one).
    bool Move(U id, float x, float z) { // keeps the linked state; false (and no change) when the new pose has no valid rectangle
        const float oldX = e[id].x, oldZ = e[id].z; e[id].x = x; e[id].z = z;
        U l, r, t, b; Rect(id, l, r, t, b);
        if (Linked(id) && (l > r || t > b || (r - l + 1) * (b - t + 1) > kNodeCapacity)) { e[id].x = oldX; e[id].z = oldZ; return false; }
        WriteRecord(id, Linked(id)); return true;
    }
    bool Teleport(U id, float x, float z) {
        const float oldX = e[id].x, oldZ = e[id].z; e[id].x = x; e[id].z = z;
        U l, r, t, b; Rect(id, l, r, t, b);
        if (l > r || t > b || (r - l + 1) * (b - t + 1) > kNodeCapacity) { e[id].x = oldX; e[id].z = oldZ; return false; }
        WriteRecord(id, true); return true;
    }
    // Points the first node of a record one cell off its rectangle (native node memory corruption).
    void CorruptNode(U id) {
        const U head = Get<U>(Nodes(id), 0x18);
        Put(Nodes(id), 0x18, head + 4 < A(heads) + cellCount * 4 ? head + 4 : head - 4);
    }
    void Unlink(U id) { Put(Rec(id), 0xac, U(0)); }
    void Link(U id) { WriteRecord(id, true); }
    void Reserial(U id, U serial) { e[id].serial = serial; WriteRecord(id, Linked(id)); }
    void SetActive(U id, B active) { e[id].active = active; Put(Rec(id), 0x30, active); }
    void SetFlags(U id, U flags) { e[id].flags = flags; Put(Rec(id), 0x38, flags); }
    void SetTeam(U id, U team) { e[id].team = team; Put(Rec(id), 0x44, team); }
    void SetY(U id, float y) { e[id].y = y; Put(Rec(id), 0x4c, y); }
    void SetRadius(U id, float radius, B bump) { e[id].radius = radius; e[id].bump = bump; WriteRecord(id, Linked(id)); }
    // A birth takes a free entity into the primary registry (hole or append) or the secondary registry (inserted at position).
    U Birth(bool toPrimary, U position, float x, float z) {
        Require(!freeList.empty(), "bulk fixture has a spare entity"); const U id = freeList.back(); freeList.pop_back();
        Entity& n = e[id]; n = Entity{};
        n.x = x; n.z = z; n.radius = 0.6f; n.team = 0x1000; n.flags = 0x21; n.serial = 0x92000001u + id * 0x10u + stage; n.written = 1;
        WriteRecord(id, true);
        if (toPrimary) {
            if (position >= primaryCount) primary[primaryCount++] = Addr(id);
            else { Require(!primary[position], "birth takes a primary hole"); primary[position] = Addr(id); }
        } else {
            Require(secondaryCount < secondary.size(), "secondary capacity");
            position = (std::min)(position, secondaryCount);
            for (U i = secondaryCount; i > position; --i) secondary[i] = secondary[i - 1];
            secondary[position] = Addr(id); ++secondaryCount;
        }
        SyncRegistry(); return id;
    }
    void RemovePrimary(U slot) { primary[slot] = 0; SyncRegistry(); }
    void RemoveSecondary(U position, bool shift) {
        if (shift) { for (U i = position; i + 1 < secondaryCount; ++i) secondary[i] = secondary[i + 1]; secondary[--secondaryCount] = 0; }
        else secondary[position] = 0;
        SyncRegistry();
    }
};

// ---------------------------------------------------------------------------------------------------------------------
// Independent reference of the whole publication, derived from native memory with a naive algorithm.
// ---------------------------------------------------------------------------------------------------------------------
struct Published {
    U count = 0, cells = 0, memberships = 0;
    std::vector<U> record, serial, incarnation, team, flags, active, inserted, left, right, top, bottom, nodeType;
    std::vector<U> x, z, y, extent, radius;
    std::vector<U> cellIds, offsets, occupants, dense;
    // Name of the first array that differs, or null.
    const char* Difference(const Published& o) const {
        if (count != o.count) return "count";
        if (cells != o.cells) return "cells";
        if (memberships != o.memberships) return "memberships";
#define NTW2_BULK_CMP(f) if (f != o.f) return #f
        NTW2_BULK_CMP(record); NTW2_BULK_CMP(serial); NTW2_BULK_CMP(incarnation); NTW2_BULK_CMP(team); NTW2_BULK_CMP(flags);
        NTW2_BULK_CMP(active); NTW2_BULK_CMP(inserted); NTW2_BULK_CMP(left); NTW2_BULK_CMP(right); NTW2_BULK_CMP(top);
        NTW2_BULK_CMP(bottom); NTW2_BULK_CMP(nodeType); NTW2_BULK_CMP(x); NTW2_BULK_CMP(z); NTW2_BULK_CMP(y);
        NTW2_BULK_CMP(extent); NTW2_BULK_CMP(radius); NTW2_BULK_CMP(cellIds); NTW2_BULK_CMP(offsets); NTW2_BULK_CMP(occupants);
        NTW2_BULK_CMP(dense);
#undef NTW2_BULK_CMP
        return nullptr;
    }
};
struct Counters { U births = 0, reused = 0, deactivations = 0, membershipRemovals = 0, removed = 0; };

inline Published Read(const loco::GridView& v) {
    Published p; p.count = v.count; p.cells = v.cells; p.memberships = v.memberships;
    auto take = [&](std::vector<U>& out, const U* src, U n) { out.assign(src, src + n); };
    auto takeF = [&](std::vector<U>& out, const float* src, U n) { out.resize(n); if (n) std::memcpy(out.data(), src, n * 4); };
    take(p.record, v.record, v.count); take(p.serial, v.serial, v.count); take(p.incarnation, v.incarnation, v.count);
    take(p.team, v.team, v.count); take(p.flags, v.flags, v.count); take(p.active, v.active, v.count);
    take(p.inserted, v.inserted, v.count); take(p.left, v.left, v.count); take(p.right, v.right, v.count);
    take(p.top, v.top, v.count); take(p.bottom, v.bottom, v.count); take(p.nodeType, v.node_type, v.count);
    takeF(p.x, v.x, v.count); takeF(p.z, v.z, v.count); takeF(p.y, v.y, v.count); takeF(p.extent, v.extent, v.count); takeF(p.radius, v.radius, v.count);
    take(p.cellIds, v.cell_ids, v.cells); take(p.offsets, v.offsets, v.cells + 1); take(p.occupants, v.occupants, v.memberships);
    take(p.dense, v.cell_dense, v.cell_count);
    return p;
}

struct RefGrid {
    static constexpr U kNone = ~0u, kTable = 1u << 18;
    std::vector<U> previousRecord, previousSerial, previousIncarnation, previousActive, previousInserted;
    U nextIncarnation = 0;

    static U Slot(U record) { return ((record >> 4) * 2654435761u) >> 8 & (kTable - 1); }
    // Expected publication for the world's current native memory. False = the capture must refuse (duplicate primary
    // record, impossible rectangle). Nothing is committed until Accept.
    bool Build(const World& w, Published& out, Counters& dc) {
        out = Published{}; dc = Counters{};
        std::vector<U> records, seen(kTable, 0);
        auto contains = [&](U r) { for (U h = Slot(r);; h = (h + 1) & (kTable - 1)) { if (!seen[h]) return false; if (seen[h] == r) return true; } };
        auto insert = [&](U r) { U h = Slot(r); while (seen[h]) h = (h + 1) & (kTable - 1); seen[h] = r; };
        for (U n = 0; n < w.primaryCount; ++n) {
            const U r = w.primary[n];
            if (r) { if (contains(r)) return false; insert(r); }
            records.push_back(r);
        }
        for (U n = 0; n < w.secondaryCount; ++n) {
            const U r = w.secondary[n];
            if (!r || contains(r)) continue;
            insert(r); records.push_back(r);
        }
        const U count = static_cast<U>(records.size());
        for (auto* v : {&out.record, &out.serial, &out.incarnation, &out.team, &out.flags, &out.active, &out.inserted, &out.left, &out.right,
                        &out.top, &out.bottom, &out.nodeType, &out.x, &out.z, &out.y, &out.extent, &out.radius}) v->assign(count, 0);
        out.count = count;
        std::vector<U> oldSlot(kTable, kNone);
        for (U i = 0; i < previousRecord.size(); ++i) if (previousRecord[i]) {
            U h = Slot(previousRecord[i]); while (oldSlot[h] != kNone) h = (h + 1) & (kTable - 1); oldSlot[h] = i;
        }
        auto previousOf = [&](U r) {
            for (U h = Slot(r);; h = (h + 1) & (kTable - 1)) { if (oldSlot[h] == kNone) return kNone; if (previousRecord[oldSlot[h]] == r) return oldSlot[h]; }
        };
        std::vector<std::pair<U, U>> cellSlot; // (cell, slot)
        for (U i = 0; i < count; ++i) {
            const U r = records[i]; out.record[i] = r;
            if (!r) continue;
            const B* p = reinterpret_cast<const B*>(static_cast<uintptr_t>(r));
            out.serial[i] = Get<U>(p, 0x2c); out.team[i] = Get<U>(p, 0x44); out.flags[i] = Get<U>(p, 0x38); out.active[i] = Get<B>(p, 0x30);
            out.inserted[i] = Get<U>(p, 0xac);
            out.x[i] = Get<U>(p, 0x48); out.y[i] = Get<U>(p, 0x4c); out.z[i] = Get<U>(p, 0x50); out.extent[i] = Get<U>(p, 0x54); out.radius[i] = Get<U>(p, 0x58);
            const U prev = previousOf(r);
            if (prev != kNone && previousSerial[prev] == out.serial[i]) {
                out.incarnation[i] = previousIncarnation[prev];
                dc.deactivations += previousActive[prev] && !out.active[i];
                dc.membershipRemovals += previousInserted[prev] && !out.inserted[i];
            } else { ++dc.births; dc.reused += prev != kNone; }
            if (!out.inserted[i]) continue;
            float radius = Get<float>(p, 0x58);
            if (Get<B>(p, 0x5c) == 1) radius = Add(radius, KF(0x1318038));
            const float px = Get<float>(p, 0x48), pz = Get<float>(p, 0x50);
            const U l = RefCoordinate(Sub(px, radius), w.cfg.scale, w.cfg.origin, w.maximum), rr = RefCoordinate(Add(px, radius), w.cfg.scale, w.cfg.origin, w.maximum);
            const U t = RefCoordinate(Sub(pz, radius), w.cfg.scale, w.cfg.origin, w.maximum), b = RefCoordinate(Add(radius, pz), w.cfg.scale, w.cfg.origin, w.maximum);
            if (l > rr || t > b || out.inserted[i] > Get<U>(p, 0xb0) || static_cast<unsigned long long>(rr - l + 1) * (b - t + 1) != out.inserted[i]) return false;
            out.left[i] = l; out.right[i] = rr; out.top[i] = t; out.bottom[i] = b;
            out.nodeType[i] = Get<U>(reinterpret_cast<const B*>(static_cast<uintptr_t>(Get<U>(p, 0xa8))), 0);
            for (U z = t; z <= b; ++z) for (U x = l; x <= rr; ++x) cellSlot.push_back({(z << w.cfg.shift) + x, i});
        }
        U next = nextIncarnation;
        for (U i = 0; i < count; ++i) if (records[i] && !out.incarnation[i]) out.incarnation[i] = ++next;
        std::sort(cellSlot.begin(), cellSlot.end());
        out.memberships = static_cast<U>(cellSlot.size());
        out.dense.assign((w.maximum << w.cfg.shift) + w.maximum + 1, 0);
        for (U k = 0; k < cellSlot.size(); ++k) {
            if (!k || cellSlot[k].first != cellSlot[k - 1].first) {
                out.cellIds.push_back(cellSlot[k].first); out.offsets.push_back(k); out.dense[cellSlot[k].first] = static_cast<U>(out.cellIds.size());
            }
            out.occupants.push_back(cellSlot[k].second);
        }
        out.cells = static_cast<U>(out.cellIds.size()); out.offsets.push_back(out.memberships);
        // Removed = previous identities that vanished from the registries or changed serial.
        std::vector<U> newSlot(kTable, kNone);
        for (U i = 0; i < count; ++i) if (records[i]) {
            U h = Slot(records[i]); while (newSlot[h] != kNone) h = (h + 1) & (kTable - 1); newSlot[h] = i;
        }
        for (U i = 0; i < previousRecord.size(); ++i) if (previousRecord[i]) {
            U slot = kNone;
            for (U h = Slot(previousRecord[i]);; h = (h + 1) & (kTable - 1)) {
                if (newSlot[h] == kNone) break;
                if (records[newSlot[h]] == previousRecord[i]) { slot = newSlot[h]; break; }
            }
            dc.removed += slot == kNone || out.serial[slot] != previousSerial[i];
        }
        return true;
    }
    void Accept(const Published& p, const Counters& dc) {
        previousRecord = p.record; previousSerial = p.serial; previousIncarnation = p.incarnation;
        previousActive = p.active; previousInserted = p.inserted; nextIncarnation += dc.births;
    }
};

// ---------------------------------------------------------------------------------------------------------------------
// Dispatchers
// ---------------------------------------------------------------------------------------------------------------------
// Deterministic test dispatcher: chunks run inline (forward or reversed claim order) or on real threads whose x87/MXCSR
// rounding is seeded differently from the owner (the module must apply the owner's, not the thread's).
inline U g_bulkLanes = 1, g_bulkCalls = 0;
inline bool g_bulkReversed = false, g_bulkConcurrent = false;
struct BulkGroup { volatile LONG next; U chunks, body; void* context; bool reversed; };
inline void BulkRun(BulkGroup& g) {
    for (;;) {
        const U ticket = static_cast<U>(InterlockedIncrement(&g.next) - 1);
        if (ticket >= g.chunks) return;
        reinterpret_cast<void(__fastcall*)(void*, U)>(g.body)(g.context, g.reversed ? g.chunks - 1 - ticket : ticket);
    }
}
struct BulkThread { BulkGroup* group; U rounding; };
inline DWORD WINAPI BulkThreadBody(void* raw) {
    const BulkThread t = *static_cast<BulkThread*>(raw);
    FpMode::Set(t.rounding); _mm_setcsr(_mm_getcsr() | 0x8040);
    BulkRun(*t.group);
    return 0;
}
inline void __stdcall BulkDispatch(U pool, U body, U chunks, void* context) {
    EqU("dispatcher receives configured pool", pool, 0xc0111deu);
    Require(body != 0 && context != nullptr && chunks != 0, "dispatcher receives chunks");
    ++g_bulkCalls;
    BulkGroup group{0, chunks, body, context, g_bulkReversed};
    const U threads = g_bulkConcurrent ? (std::min)(g_bulkLanes, chunks) - 1 : 0;
    std::vector<HANDLE> handles(threads); std::vector<BulkThread> args(threads);
    for (U n = 0; n < threads; ++n) {
        args[n] = {&group, n % 4};
        handles[n] = CreateThread(nullptr, 0, &BulkThreadBody, &args[n], 0, nullptr);
        Require(handles[n] != nullptr, "bulk dispatcher thread");
    }
    BulkRun(group);
    for (HANDLE h : handles) { WaitForSingleObject(h, INFINITE); CloseHandle(h); }
}

// Persistent event-sleep pool with the production dispatcher's model (native_worker_dispatch.c): one auto-reset event per
// worker, min(workers, chunks-1) events signalled per dispatch, atomic chunk claims, a token barrier at the end. Used for
// timing and for the realistic-scale equality case.
struct Pool {
    static constexpr U kMax = 16;
    HANDLE wake[kMax] = {}, threads[kMax] = {};
    U workers = 0;
    volatile LONG stop = 0, next = 0, pending = 0;
    U body = 0, chunks = 0; void* context = nullptr;
    void Run() {
        for (;;) {
            const U ticket = static_cast<U>(InterlockedIncrement(&next) - 1);
            if (ticket >= chunks) break;
            reinterpret_cast<void(__fastcall*)(void*, U)>(body)(context, ticket);
        }
    }
    struct Arg { Pool* pool; U index; };
    static DWORD WINAPI Worker(void* raw) {
        Arg arg = *static_cast<Arg*>(raw); Pool& p = *arg.pool;
        for (;;) {
            WaitForSingleObject(p.wake[arg.index], INFINITE);
            if (p.stop) return 0;
            p.Run();
            InterlockedDecrement(&p.pending);
        }
    }
    std::vector<Arg> args;
    void Start(U count) {
        workers = count; args.resize(count);
        for (U i = 0; i < count; ++i) {
            wake[i] = CreateEvent(nullptr, FALSE, FALSE, nullptr); args[i] = {this, i};
            threads[i] = CreateThread(nullptr, 0, &Worker, &args[i], 0, nullptr);
            Require(wake[i] && threads[i], "bench pool thread");
        }
    }
    void Shutdown() {
        stop = 1;
        for (U i = 0; i < workers; ++i) { SetEvent(wake[i]); WaitForSingleObject(threads[i], INFINITE); CloseHandle(threads[i]); CloseHandle(wake[i]); }
        workers = 0; stop = 0;
    }
    void Dispatch(U fn, U count, void* ctx) {
        body = fn; context = ctx; chunks = count; next = 0;
        const U woken = (std::min)(workers, count > 0 ? count - 1 : 0u);
        pending = static_cast<LONG>(woken) + 1;
        for (U i = 0; i < woken; ++i) SetEvent(wake[i]);
        Run();
        InterlockedDecrement(&pending);
        while (pending) YieldProcessor();
    }
};
inline Pool g_pool;
inline void __stdcall PoolDispatch(U, U body, U chunks, void* ctx) { g_pool.Dispatch(body, chunks, ctx); }

inline loco::Binding GridBinding(void(__stdcall* dispatch)(U, U, U, void*), U lanes, bool incremental, bool verify) {
    loco::Binding binding = MakeBinding();
    binding.use_grid = true; binding.verify_grid = verify; binding.grid_incremental = incremental;
    binding.dispatch = dispatch; binding.pool = 0xc0111deu; binding.workers = lanes - 1;
    return binding;
}
inline std::array<U, loco::GridBuildWordCount> BuildWords() { std::array<U, loco::GridBuildWordCount> w{}; loco::SampleGridBuild(w.data()); return w; }

// ---------------------------------------------------------------------------------------------------------------------
// Per-phase timing of the realistic fixture (--grid-bench)
// ---------------------------------------------------------------------------------------------------------------------
struct PhaseRow { double registry = 0, capture = 0, plan = 0, build = 0, total = 0, call = 0; U changed = 0, full = 0, incremental = 0, reuses = 0; };

// Times `stages` builds after `warm` unmeasured ones; per-phase means in microseconds from the module's own status row.
// `cold` streams 96 MiB through the caches before each stage's drift: unmoved records, registry, nodes and every published
// array then come from DRAM, like the replay's tick (other site work between builds), while the moved records were just
// written by the owner.
inline PhaseRow Bench(World& w, U lanes, bool incremental, U stages, U warm, U movingPercent, bool cold) {
    g_pool.Start(lanes - 1);
    Require(loco::Start(GridBinding(&PoolDispatch, lanes, incremental, false)), "bench starts");
    Require(loco::ActivateOwned(w.Model(), w.Capacity()), "bench grid activates");
    LARGE_INTEGER freq, a, b; QueryPerformanceFrequency(&freq);
    PhaseRow row; std::array<U, loco::GridBuildWordCount> before{};
    std::vector<U> flush(cold ? 24u * 1024 * 1024 : 0u, 1u); volatile U sink = 0;
    double call = 0;
    for (U s = 0; s < warm + stages; ++s) {
        if (cold) { U sum = 0; for (size_t i = 0; i < flush.size(); i += 16) sum += flush[i]; sink = sum; }
        w.Drift(movingPercent);
        if (s == warm) before = BuildWords();
        QueryPerformanceCounter(&a);
        Require(loco::CaptureGrid(w.Manager()), "bench capture");
        QueryPerformanceCounter(&b);
        if (s >= warm) call += double(b.QuadPart - a.QuadPart) * 1e6 / double(freq.QuadPart);
    }
    const auto after = BuildWords(); const double n = stages;
    row.registry = (after[loco::GridBuildRegistryUs] - before[loco::GridBuildRegistryUs]) / n;
    row.capture = (after[loco::GridBuildCaptureWallUs] - before[loco::GridBuildCaptureWallUs]) / n;
    row.plan = (after[loco::GridBuildPlanUs] - before[loco::GridBuildPlanUs]) / n;
    row.build = (after[loco::GridBuildWallUs] - before[loco::GridBuildWallUs]) / n;
    row.call = call / n; row.total = row.registry + row.capture + row.plan + row.build;
    row.changed = after[loco::GridBuildChanged] - before[loco::GridBuildChanged];
    row.full = after[loco::GridBuildFull] - before[loco::GridBuildFull];
    row.incremental = after[loco::GridBuildIncremental] - before[loco::GridBuildIncremental];
    row.reuses = after[loco::GridBuildRegistryReuses] - before[loco::GridBuildRegistryReuses];
    CallStop(); g_pool.Shutdown();
    (void)sink;
    return row;
}

// ---------------------------------------------------------------------------------------------------------------------
// Multi-stage equality cases
// ---------------------------------------------------------------------------------------------------------------------
struct Sequence {
    bool incremental, verify;      // --loco-grid-incremental, --loco-grid-verify (native chains + shadow full rebuild)
    U lanes; bool reversed, concurrent;
    U rounding;                    // x87 RC / MXCSR RC of the owner (0 nearest, 1 down, 2 up, 3 truncate)
    bool variant;                  // false: 128x128 grid, strip height 2; true: 191x191 clamp in a 256 stride, strip height 3
};

// Expected build kind of one stage of a sequence.
enum Expect : int { AnyKind = -1, ExpectIncremental = 0, ExpectFirst = 1, ExpectRegistry = 2, ExpectGeometry = 3, ExpectShare = 4 };

struct SequenceRun {
    const Sequence& p; World w; RefGrid ref; U stageNo = 0, built = 0, refused = 0;
    SequenceRun(const Sequence& s, const Config& c) : p(s), w(c) {}

    // One capture of the current native state, checked against the reference model and the status words.
    // refuse: a refusal the reference cannot know about (corrupted node memory); `why` names the case.
    void Capture(const char* why, int expect, bool refuse = false) {
        currentCase = why; ++stageNo; w.stage = stageNo;
        if (p.verify) w.RebuildChains();
        const auto grid = GridStatus(); const auto build = BuildWords();
        Published expected; Counters dc;
        const bool refOk = ref.Build(w, expected, dc);
        const bool shouldBuild = refOk && !refuse;
        const bool ok = loco::CaptureGrid(w.Manager());
        Require(ok == shouldBuild, shouldBuild ? "the capture must succeed" : "the capture must refuse");
        const auto after = GridStatus(); const auto buildAfter = BuildWords();
        if (!ok) { ++refused; Require(loco::ReadGrid() == nullptr, "a refused capture publishes nothing"); return; }
        ++built;
        const loco::GridView* view = loco::ReadGrid();
        Require(view != nullptr, "a successful capture publishes");
        const Published got = Read(*view);
        if (const char* what = got.Difference(expected)) Fail("publication differs from the reference model in %s (stage %u)", what, stageNo);
        Require(loco::ReadGridForCollision(w.Manager()) == view, "collision input matches the publication");
        ref.Accept(expected, dc);
        EqU("births", after[loco::GridBirths] - grid[loco::GridBirths], dc.births);
        EqU("reused addresses", after[loco::GridReused] - grid[loco::GridReused], dc.reused);
        EqU("registry removals", after[loco::GridRemovals] - grid[loco::GridRemovals], dc.removed);
        EqU("deactivations", after[loco::GridDeactivations] - grid[loco::GridDeactivations], dc.deactivations);
        EqU("membership removals", after[loco::GridMembershipRemovals] - grid[loco::GridMembershipRemovals], dc.membershipRemovals);
        EqU("records", after[loco::GridRecords] - grid[loco::GridRecords], expected.count);
        EqU("memberships", after[loco::GridMemberships] - grid[loco::GridMemberships], expected.memberships);
        EqU("cells", after[loco::GridCells] - grid[loco::GridCells], expected.cells);
        EqU("mismatch-free", after[loco::GridMismatches] - grid[loco::GridMismatches], 0);
        const U incremental = buildAfter[loco::GridBuildIncremental] - build[loco::GridBuildIncremental];
        const U full = buildAfter[loco::GridBuildFull] - build[loco::GridBuildFull];
        EqU("exactly one build kind", incremental + full, 1);
        if (!p.incremental) { EqU("the default build is full", full, 1); return; }
        if (expect == ExpectIncremental) EqU("an unchanged-registry, unchanged-geometry stage patches", incremental, 1);
        else if (expect != AnyKind) {
            EqU("this stage falls back to a full build", full, 1);
            EqU("with the expected reason", buildAfter[loco::GridBuildFallbackReason], static_cast<U>(expect));
        }
    }
};

inline Config SequenceConfig(bool variant) {
    Config c; c.primary = 1500; c.secondary = 800; c.spare = 200; c.formation = 30; c.movingPercent = 60; c.seed = variant ? 0x1badcafeu : 0x5eed0001u;
    c.shift = variant ? 8 : 7; c.maximum = variant ? 190 : 0;
    return c;
}

inline void RunSequence(const Sequence& p) {
    FpMode fp(p.rounding);
    SequenceRun run(p, SequenceConfig(p.variant));
    World& w = run.w;
    loco::Binding binding = GridBinding(&BulkDispatch, p.lanes, p.incremental, p.verify);
    g_bulkLanes = p.lanes; g_bulkReversed = p.reversed; g_bulkConcurrent = p.concurrent; g_bulkCalls = 0;
    Require(loco::Start(binding), "bulk sequence starts");
    Require(loco::ActivateOwned(w.Model(), w.Capacity()), "bulk sequence activates");
    const U total = w.Total();
    auto pick = [&](U n) { return w.rng.Below(n); };
    auto linkedRegistered = [&]() { const auto ids = w.Registered(); U id; do { id = ids[pick(static_cast<U>(ids.size()))]; } while (!w.Linked(id)); return id; };

    run.Capture("first build", ExpectFirst);
    run.Capture("stationary: nothing changed", ExpectIncremental);
    for (U s = 0; s < 3; ++s) { w.Drift(100); run.Capture("formation drift with cell-boundary crossings", ExpectIncremental); }
    w.Drift(30); run.Capture("partial drift", ExpectIncremental);
    { // snapshot-only changes: no coverage input moves
        for (U k = 0; k < 40; ++k) { const U id = linkedRegistered(); w.SetActive(id, static_cast<B>(pick(2))); w.SetFlags(id, 0x40u + pick(8)); w.SetTeam(id, 0x2000u + pick(3)); w.SetY(id, 5.0f + pick(9)); }
        run.Capture("activity, flags, team and height only", ExpectIncremental);
    }
    { // serial reuse: same record address, new full serial
        for (U k = 0; k < 6; ++k) w.Reserial(linkedRegistered(), 0x93000001u + pick(1000) * 0x10000u + k);
        run.Capture("serial reuse on live records", ExpectIncremental);
    }
    { // +AC = 0 removals and re-insertions
        std::vector<U> unlinked;
        for (U k = 0; k < 25; ++k) { const U id = linkedRegistered(); w.Unlink(id); unlinked.push_back(id); }
        run.Capture("native unlink (+AC = 0)", ExpectIncremental);
        run.Capture("unlinked stays unlinked", ExpectIncremental);
        for (U id : unlinked) w.Link(id);
        run.Capture("native re-insert", ExpectIncremental);
    }
    { // relocation: the engine's relocation helpers unlink and insert elsewhere (data-equivalent mutation: new pose + nodes)
        for (U k = 0; k < 30; ++k) { const U id = linkedRegistered(); w.Teleport(id, 20.0f + pick(900) * 0.5f, 20.0f + pick(900) * 0.5f); }
        run.Capture("relocation across the grid", ExpectIncremental);
    }
    { // clamp edges: negative and huge coordinates (unsigned clamp), NaN, the origin and the far edge
        const float edge = (w.maximum + 1) / w.cfg.scale;
        const float coordinates[][2] = {{-10.0f, -10.0f}, {-1.0e6f, 5.0f}, {1.0e9f, 1.0e9f}, {edge, edge}, {edge - 0.1f, 7.0f}, {NAN, 7.0f}, {-3.0f, 12.0f}, {edge + 50.0f, edge - 50.0f}};
        U moved = 0;
        for (U k = 0; k < 8; ++k) moved += w.Teleport(linkedRegistered(), coordinates[k][0], coordinates[k][1]);
        Require(moved >= 4, "clamp-edge poses exist under every rounding mode");
        run.Capture("clamp edges", ExpectIncremental);
        run.Capture("clamped records stay put", ExpectIncremental);
    }
    { // radius and the +5C bump byte
        for (U k = 0; k < 20; ++k) w.SetRadius(linkedRegistered(), 0.3f + pick(30) * 0.05f, static_cast<B>(pick(3)));
        run.Capture("radius and +5C bump", ExpectIncremental);
    }
    { // births: primary hole, primary append, secondary insertion
        U hole = 0; while (w.primary[hole]) ++hole;
        w.Birth(true, hole, 100.0f, 100.0f); w.Birth(true, w.primaryCount, 130.0f, 90.0f); w.Birth(false, 3, 160.0f, 160.0f);
        run.Capture("births change the registry", ExpectRegistry);
        w.Drift(100); run.Capture("drift after a registry change", ExpectIncremental);
    }
    { // removals: primary hole, secondary shift and secondary hole
        U slot = 0; while (!w.primary[slot]) ++slot;
        w.RemovePrimary(slot); w.RemoveSecondary(2, true); w.RemoveSecondary(9, false);
        run.Capture("removals change the registry", ExpectRegistry);
        w.Drift(100); run.Capture("drift after removals", ExpectIncremental);
    }
    { // secondary registry reordering: every following slot changes
        std::swap(w.secondary[5], w.secondary[40]); std::swap(w.secondary[100], w.secondary[101]);
        run.Capture("secondary reordering", ExpectRegistry);
        run.Capture("stationary after reordering", ExpectIncremental);
    }
    { // a pointer leaves and returns with a fresh serial in the same stage window
        const U id = linkedRegistered(); w.RemoveSecondary(0, true); w.Reserial(id, 0x95000001u);
        run.Capture("mixed registry and serial change", ExpectRegistry);
    }
    { // duplicate primary entries refuse, then the registry is repaired
        U a = 0; while (!w.primary[a]) ++a; U b = a + 1; while (!w.primary[b]) ++b;
        const U saved = w.primary[b]; w.primary[b] = w.primary[a];
        run.Capture("duplicate primary registry entries refuse", AnyKind, true);
        w.primary[b] = saved;
        run.Capture("repaired registry", AnyKind);
        run.Capture("stationary after repair", ExpectIncremental);
    }
    { // geometry: scale, origin and rounding-independent clamp change
        w.SetGeometry(w.cfg.shift, w.cfg.maximum, w.cfg.scale * 1.25f, w.cfg.origin);
        run.Capture("scale change", ExpectGeometry);
        w.Drift(100); run.Capture("drift after a scale change", ExpectIncremental);
        w.SetGeometry(w.cfg.shift, w.cfg.maximum, w.cfg.scale, 3);
        run.Capture("origin change", ExpectGeometry);
        w.SetGeometry(w.cfg.shift, w.cfg.maximum ? w.cfg.maximum - 7 : (1u << w.cfg.shift) - 9, w.cfg.scale, 3);
        run.Capture("clamp (maximum) change", ExpectGeometry);
        w.Drift(100); run.Capture("drift after a clamp change", ExpectIncremental);
    }
    { // rounding control change between stages: every record is re-inserted under the new mode
        FpMode::Set((p.rounding + 1) % 4); w.RelinkAll();
        run.Capture("rounding control change", ExpectGeometry);
        w.Drift(100); run.Capture("drift under the new rounding", ExpectIncremental);
        FpMode::Set(p.rounding); w.RelinkAll();
        run.Capture("rounding control restored", ExpectGeometry);
    }
    { // a mass move above the break-even: that build is incremental, the next one falls back (share), then it patches again
        w.MassShift(70, 5.0f);
        run.Capture("mass move above the break-even", ExpectIncremental);
        run.Capture("share fallback after a mass move", ExpectShare);
        w.Drift(100); run.Capture("incremental again after the backoff", ExpectIncremental);
    }
    { // a corrupted node on a moved record refuses in every mode; the next build starts over cleanly
        const U id = linkedRegistered(); w.e[id].x += 7.0f; w.WriteRecord(id, true);
        w.CorruptNode(id);
        run.Capture("node cell mismatch on a moved record refuses", AnyKind, true);
        w.WriteRecord(id, true);
        run.Capture("rebuild after a refused build", ExpectFirst);
        w.Drift(100); run.Capture("drift after recovery", ExpectIncremental);
    }
    if (p.incremental) { // documented limit: node memory is not a diff input; the native-chain verifier catches it
        const U id = linkedRegistered();
        w.CorruptNode(id);
        run.Capture("node corruption behind an unchanged record", ExpectIncremental);
        w.WriteRecord(id, true);
        run.Capture("node repaired", AnyKind);
    }

    const auto build = BuildWords(), v2 = GridV2Status();
    EqU("status version", build[loco::GridBuildVersion], 1);
    EqU("status mode", build[loco::GridBuildMode], p.incremental ? 1u : 0u);
    EqU("build kinds partition the publications", build[loco::GridBuildFull] + build[loco::GridBuildIncremental], run.built);
    Require(v2[loco::GridV2Dispatches] >= run.built * (2 + (p.verify ? 1u : 0u)), "every build is two dispatches (+1 native verification)");
    if (p.incremental) {
        Require(build[loco::GridBuildIncremental] >= 20, "the sequence exercises many incremental builds");
        Require(build[loco::GridBuildFallbacks] >= 8, "the sequence exercises every fallback reason");
        Require(build[loco::GridBuildChanged] > 0, "rectangle changes are counted");
        EqU("every full build of an incremental run is a fallback", build[loco::GridBuildFallbacks], build[loco::GridBuildFull]);
    } else EqU("the default build never reports incremental work", build[loco::GridBuildIncremental] + build[loco::GridBuildFallbacks], 0);
    Require(build[loco::GridBuildRegistryReuses] >= 10, "unchanged registries share the previous identity");
    if (p.incremental && p.verify) {
        EqU("every successful build is compared with a full rebuild", build[loco::GridBuildShadowCompares], run.built);
        // The one corrupted node behind an unchanged record is invisible to the diff; the shadow full rebuild refuses it.
        EqU("shadow rebuilds differ exactly where the node memory was corrupted", build[loco::GridBuildShadowMismatches], 1);
        EqU("the pool saw the shadow's dispatches too (the refused rebuild stops after one)", g_bulkCalls, v2[loco::GridV2Dispatches] + 2 * run.built - 1);
    }
    EqU("no unsupported or faulting build", GridV2Status()[loco::GridV2Faults] + GridStatus()[loco::GridFaults], 0);
    CallStop(); ++cases;
}

inline void GridSequenceCases() {
    // Every rounding mode and participant count; participants 1/2/4/8 (workers + caller), reversed claim order on half of
    // them, real threads (with foreign rounding seeds) whenever there is more than one participant.
    const U lanes[4] = {1, 2, 4, 8};
    for (U rounding = 0; rounding < 4; ++rounding) for (U l = 0; l < 4; ++l) {
        const bool variant = ((rounding + l) & 1u) != 0;
        for (U mode = 0; mode < 3; ++mode) {
            Sequence p{mode != 0, mode == 2, lanes[l], ((rounding + l) & 2u) != 0, lanes[l] > 1, rounding, variant};
            RunSequence(p);
        }
    }
}

// Realistic scale (74.6k records, 1024 x 1024 grid): incremental + shadow verification across drift, a registry change and
// a geometry change, with the production-style event pool at 8 workers + caller.
inline void GridRealisticEquality() {
    currentCase = "realistic-scale incremental equality";
    Sequence p{true, true, 9, false, true, 0, false};
    Config cfg; cfg.primary = 48128; cfg.secondary = 26500; cfg.spare = 256;
    SequenceRun run(p, cfg);
    World& w = run.w;
    g_pool.Start(8);
    Require(loco::Start(GridBinding(&PoolDispatch, 9, true, true)), "realistic equality starts");
    Require(loco::ActivateOwned(w.Model(), w.Capacity()), "realistic equality activates");
    run.Capture("realistic first build", ExpectFirst);
    for (U s = 0; s < 4; ++s) { w.Drift(100); run.Capture("realistic drift", ExpectIncremental); }
    w.Birth(false, 11, 500.0f, 500.0f); w.RemovePrimary(40);
    run.Capture("realistic registry change", ExpectRegistry);
    w.Drift(100); run.Capture("realistic drift after the registry change", ExpectIncremental);
    const auto build = BuildWords();
    EqU("realistic shadow comparisons", build[loco::GridBuildShadowCompares], run.built);
    EqU("realistic shadow mismatches", build[loco::GridBuildShadowMismatches], 0);
    CallStop(); g_pool.Shutdown(); ++cases;
}

}  // namespace bulk
