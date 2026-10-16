// Per-unit brain Stage A shadow (native_unit_brain.h). Reads native memory only; writes only this module's rows.
#include "native_unit_brain.h"
#include "native_region_table.h"
#include <windows.h>
#include <string.h>
#include <new>

namespace ntw2_unit_brain {
namespace {
constexpr U kRowCapacity = 2048, kRowLimit = kRowCapacity / 4 * 3; // a quarter stays empty: short failed lookups
constexpr U kMaxChunks = 16, kUnitsPerChunk = 16;
constexpr U kBufferCapacity = 131072;  // non-exception occurrences per stage kept for the strict-majority count
constexpr U kStaleStages = 64;         // rows unreferenced this long are no longer decided
constexpr U kSoldierBytes = 0x700, kUnitBytes = 0xE00;
constexpr U kPostureFirst = 0x1454168, kPostureStates = 13, kCrewNode = 0x133AE34;
constexpr U kAllFields = (1u << kFields) - 1;

U D(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
U B(U a) { return *reinterpret_cast<const volatile uint8_t*>(static_cast<uintptr_t>(a)); }
float F(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }

struct Row {
    U unit;
    U lastSeen;        // stage number of the last occurrence that referenced it (0 never)
    U stamp;           // stage whose decision (decisionMask) and accumulation the row currently holds
    U hasRecord, recordSignature, recordMask, record[kFields];
    U signature, signed_, decisionMask, changed, unreadable;            // decision pass (one chunk per row)
    U n, cand[kFields], votes[kFields], matches[kFields], vtMask;       // owner accumulation (n = voters)
    U classCount[kVtables], mainVt;   // non-exception soldiers per census class this stage; previous main class + 1
};
struct Obs { U row; U vt; U values[kFields]; };
struct Storage {
    Row rows[kRowCapacity];
    U dense[kRowCapacity];
    ntw2_region::Table tables[kMaxChunks];
    ntw2_region::Table owner;
    Obs obs[kBufferCapacity];
};
struct DecideJob { Storage* s; U count, chunks, stage; };

Storage* g_storage;
U g_words[kWords];
U g_delta, g_pool, g_maxChunks, g_stage, g_rows;
void (__stdcall* g_dispatch)(U, U, U, void*);
U g_obsCount, g_stageAgree[kFields], g_stageDisagree[kFields], g_stageCompared, g_stageAgreeAll;
U g_ownerQueries;
unsigned long long g_observeTicks;
LARGE_INTEGER g_frequency;

U MicrosSince(const LARGE_INTEGER& start) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return g_frequency.QuadPart ? static_cast<U>((now.QuadPart - start.QuadPart) * 1000000 / g_frequency.QuadPart) : 0;
}
U RowSlot(U unit) { return ((unit >> 3) * 2654435761u) & (kRowCapacity - 1); }
Row* FindRow(Storage& s, U unit, bool insert, bool& inserted) {
    inserted = false;
    for (U probe = 0, slot = RowSlot(unit); probe != kRowCapacity; ++probe, slot = (slot + 1) & (kRowCapacity - 1)) {
        Row& r = s.rows[slot];
        if (r.unit == unit) return &r;
        if (!r.unit) {
            if (!insert || g_rows == kRowLimit) return nullptr;
            memset(&r, 0, sizeof(r)); r.unit = unit; ++g_rows; inserted = true;
            return &r;
        }
    }
    return nullptr;
}
void ClearAccumulation(Row& r, U stage) {
    r.stamp = stage; r.n = 0; r.vtMask = 0;
    memset(r.votes, 0, sizeof(r.votes)); memset(r.matches, 0, sizeof(r.matches));
    memset(r.classCount, 0, sizeof(r.classCount));
}
// Decision of one row from its unit-level inputs: the held record when the signature it was formed under still holds.
void DecideRow(Row& r, ntw2_region::Table& table, U& queries, U stage) {
    ClearAccumulation(r, stage);
    U inputs[kInputs];
    r.changed = 0; r.decisionMask = 0;
    if (!ReadUnitInputs(r.unit, table, queries, inputs)) { r.unreadable = 1; r.signed_ = 0; return; }
    r.unreadable = 0; r.signed_ = 1;
    r.signature = Signature(inputs);
    if (!r.hasRecord) return;
    if (r.recordSignature == r.signature) r.decisionMask = r.recordMask;
    else r.changed = 1;
}
void __fastcall DecideChunk(void* context, U chunk) {
    DecideJob& job = *static_cast<DecideJob*>(context);
    ntw2_region::Table& table = job.s->tables[chunk];
    table.Clear();
    U queries = 0;
    const U begin = static_cast<U>(static_cast<unsigned long long>(job.count) * chunk / job.chunks);
    const U end = static_cast<U>(static_cast<unsigned long long>(job.count) * (chunk + 1) / job.chunks);
    for (U i = begin; i < end; ++i) DecideRow(job.s->rows[job.s->dense[i]], table, queries, job.stage);
}
U Fnv(U hash, U value) {
    for (U i = 0; i < 4; ++i) { hash ^= (value >> (8 * i)) & 0xFF; hash *= 16777619u; }
    return hash;
}
} // namespace

bool ReadUnitInputs(U u, ntw2_region::Table& t, U& q, U* in) {
    if (!u || !t.Readable(u, kUnitBytes, q)) return false;
    in[0] = D(u + 0x930); in[1] = D(u + 0x934);
    // 53EEE0 dispatches the current command Q = U+398 + U+934*0x90 only while U+930 != 0.
    const U command = u + 0x398 + in[1] * 0x90;
    in[2] = !in[0] ? 0 : in[1] < 0x10000 && t.Readable(command, 4, q) ? D(command) : ~0u;
    in[3] = D(u + 0xAA0);
    const U desc = D(u + 0x2C); in[4] = desc;
    in[5] = !desc ? 0 : t.Readable(desc + 0x1C, 4, q) ? D(desc + 0x1C) : ~0u;
    in[6] = B(u + 0xDA4) | B(u + 0xD9E) << 8 | B(u + 0xD9D) << 16;
    in[7] = D(u + 0xDA8); in[8] = D(u + 0xC2C);
    const U count = D(u + 0xDB8), data = D(u + 0xDBC);
    in[9] = count;
    if (!count) in[10] = 0;
    else {
        const U bytes = (count > 16 ? 16 : count) * 0x2C;
        if (count > 0x1000000 || !t.Readable(data, bytes, q)) in[10] = ~0u;
        else {
            U hash = 2166136261u;
            for (U i = 0; i < bytes; ++i) { hash ^= B(data + i); hash *= 16777619u; }
            in[10] = hash;
        }
    }
    const U context = D(u + 0xC00);
    const U model = context && t.Readable(context + 8, 4, q) ? D(context + 8) : 0;
    const U manager = model && t.Readable(model + 0xB0, 4, q) ? D(model + 0xB0) : 0;
    in[11] = manager && t.Readable(manager + 0x14, 4, q) ? D(manager + 0x14) : ~0u;
    in[12] = manager && t.Readable(manager + 0x2704, 1, q) ? B(manager + 0x2704) : ~0u;
    const U group = D(u + 0xADC); in[13] = group;
    in[14] = !group ? 0 : t.Readable(group + 0x460, 4, q) ? D(group + 0x460) : ~0u;
    return true;
}
U Signature(const U* in) {
    U hash = 2166136261u;
    for (U i = 0; i < kInputs; ++i) hash = Fnv(hash, in[i]);
    return hash;
}
bool ExtractSoldier(U a, ntw2_region::Table& t, U& q, Soldier& out) {
    memset(&out, 0, sizeof(out));
    if (!a || !t.Readable(a, kSoldierBytes, q)) return false;
    const U table = D(a);
    if (!t.Readable(table + 0xC, 4, q)) return false;
    out.vtable = table - g_delta;
    const U entry = D(table + 0xC) - g_delta;
    const bool artillery = entry == 0x6F4660, mounted = entry == 0x602EB0;
    if (entry != 0x66CE00 && entry != 0x6F50F0 && !mounted && entry != 0x5FCEB0 && !artillery) {
        out.exceptions = 1u << ExOtherClass;
        return true;
    }
    U* v = out.values;
    v[Activity] = D(a + 0x1B8); v[Order] = D(a + 0x1D8);
    const U node = D(a + 0x22C) - g_delta;
    v[Holder] = B(a + 0x2C4) == 1 ? node : 0;
    const U posture = D(a + 0xF8);
    const U index = posture - g_delta - kPostureFirst;
    v[PostureState] = !posture ? 0xFF : (index & 3) == 0 && index / 4 < kPostureStates ? index / 4 : 0xFE;
    v[Stance] = D(a + 0x220);
    const U target = D(a + 0x1EC);
    if (!target) v[TargetUnit] = 0;
    else if (t.Readable(target + 0x1F0, 4, q)) v[TargetUnit] = D(target + 0x1F0);
    else { v[TargetUnit] = ~0u; out.targetUnreadable = 1; }
    v[EngagePhase] = D(a + 0x224); v[AnimId] = D(a + 0x1BC);
    v[FireFlags] = B(a + 0x5BC) | B(a + 0x5AB) << 8 | B(a + 0xF1) << 16 | B(a + 0x619) << 24;
    out.unit = D(a + 0x1F0);

    U x = 0;
    if (v[EngagePhase] == 9) x |= 1u << ExEngage9;
    if (v[Activity] == 0xD || v[Stance] == 2) x |= 1u << ExMelee;
    if (v[Order] == 0x3C || v[Order] == 0x3D || v[Activity] == 0x4B) x |= 1u << ExRouting;
    if (D(a + 0x628)) x |= 1u << ExParked;
    if (B(a + 0x30) != 1) x |= 1u << ExDeactivated;
    if (D(a + 0x390) && !D(a + 0x404)) {
        out.farMeasured = 1;
        const float dx = F(a + 0x3F4) - F(a + 0x48), dz = F(a + 0x3FC) - F(a + 0x50);
        if (dx * dx + dz * dz > kFarMeters * kFarMeters) x |= 1u << ExFarFromSlot; // NaN compares false
    }
    if (D(a + 0x18)) x |= 1u << ExPendingRequest;
    if (artillery) x |= 1u << ExArtillery;
    if (node == kCrewNode || D(a + 0x66C)) x |= 1u << ExCrew;
    if (mounted && D(a + 0x4E8)) x |= 1u << ExCavalryCharge;
    if (!out.unit) x |= 1u << ExNoUnit;
    out.exceptions = x;
    return true;
}

bool Start(const Binding& binding) {
    Stop();
    void* memory = VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return false;
    g_storage = new (memory) Storage; // zero-filled pages; Storage is trivially constructible
    g_delta = binding.image_base - 0x400000;
    g_dispatch = binding.workers ? binding.dispatch : nullptr;
    g_pool = binding.pool;
    g_maxChunks = binding.workers + 1 < kMaxChunks ? binding.workers + 1 : kMaxChunks;
    g_stage = 0; g_rows = 0;
    QueryPerformanceFrequency(&g_frequency);
    return true;
}
void Stop() {
    if (g_storage) VirtualFree(g_storage, 0, MEM_RELEASE);
    g_storage = nullptr; g_dispatch = nullptr; g_rows = 0;
}
void Reset() {
    memset(g_words, 0, sizeof(g_words));
    g_stage = 0; g_rows = 0; g_obsCount = 0; g_observeTicks = 0;
    if (g_storage) memset(g_storage->rows, 0, sizeof(g_storage->rows));
}
bool Started() { return g_storage != nullptr; }

void BeginStage(U) {
    Storage* const s = g_storage;
    if (!s) return;
    if (!g_words[Stages]) {
        g_words[Version] = kVersion;
        for (U f = 0; f < kFields; ++f) g_words[FieldWords + f * kFieldStride + WorstStagePermille] = ~0u;
    }
    g_words[Enabled] = 1;
    ++g_words[Stages];
    ++g_stage;
    g_obsCount = 0; g_stageCompared = g_stageAgreeAll = 0;
    memset(g_stageAgree, 0, sizeof(g_stageAgree)); memset(g_stageDisagree, 0, sizeof(g_stageDisagree));
    s->owner.Clear();
    U count = 0;
    for (U i = 0; i < kRowCapacity; ++i) {
        const Row& r = s->rows[i];
        if (r.unit && r.lastSeen && g_stage - r.lastSeen <= kStaleStages) s->dense[count++] = i;
    }
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    if (count) {
        U chunks = (count + kUnitsPerChunk - 1) / kUnitsPerChunk;
        if (chunks > g_maxChunks) chunks = g_maxChunks;
        DecideJob job{s, count, chunks, g_stage};
        if (g_dispatch && chunks > 1) g_dispatch(g_pool, static_cast<U>(reinterpret_cast<uintptr_t>(&DecideChunk)), chunks, &job);
        else for (U c = 0; c < chunks; ++c) DecideChunk(&job, c);
        g_words[Chunks] += chunks;
    }
    g_words[DecideUs] += MicrosSince(start);
    U decided = 0;
    for (U i = 0; i < count; ++i) {
        const Row& r = s->rows[s->dense[i]];
        if (r.decisionMask) ++decided;
        g_words[SignatureChanges] += r.changed;
        g_words[UnitUnreadable] += r.unreadable;
    }
    g_words[DecisionsLast] = decided; g_words[UnitsDecided] += decided;
    g_words[UnitsLast] = 0;
}

namespace {
void ObserveSoldier(Storage* const s, U entity) {
    ++g_words[Occurrences];
    Soldier sd;
    if (!ExtractSoldier(entity, s->owner, g_ownerQueries, sd)) { ++g_words[SoldierUnreadable]; return; }
    const U x = sd.exceptions;
    for (U b = 0; b < kExceptionBits; ++b) if (x >> b & 1) ++g_words[ExceptionWords + b];
    if (x) ++g_words[AnyException];
    if (x & 1u << ExOtherClass) return;
    ++g_words[Observed];
    ++g_words[sd.farMeasured ? FarMeasured : FarUnmeasured];
    g_words[TargetUnreadable] += sd.targetUnreadable;
    // Class vtable census: first-seen order (the worklist order), kVtables rows.
    U vt = kVtables;
    for (U i = 0; i < g_words[VtablesDistinct]; ++i) if (g_words[VtableRows + 4 * i] == sd.vtable) { vt = i; break; }
    if (vt == kVtables && g_words[VtablesDistinct] < kVtables) {
        vt = g_words[VtablesDistinct]++;
        g_words[VtableRows + 4 * vt] = sd.vtable;
    }
    if (vt == kVtables) ++g_words[VtableOverflow];
    if (!sd.unit) return;
    bool inserted;
    Row* const r = FindRow(*s, sd.unit, true, inserted);
    if (!r) { ++g_words[UnitOverflow]; return; }
    if (inserted) ++g_words[NewUnits];
    if (r->stamp != g_stage) { ClearAccumulation(*r, g_stage); r->decisionMask = 0; r->signed_ = 0; }
    if (r->lastSeen != g_stage) { r->lastSeen = g_stage; ++g_words[UnitsLast]; }
    if (vt < kVtables) { r->vtMask |= 1u << vt; ++g_words[VtableRows + 4 * vt + 1]; }
    // Unresolved role: not the unit's main class of the previous stage. Compared like an exception soldier.
    const bool role = !x && r->mainVt && vt + 1 != r->mainVt;
    if (role) ++g_words[UnresolvedRole];
    const bool exception = x != 0 || role;
    bool agreeAll = r->decisionMask == kAllFields, disagreeAny = false;
    for (U f = 0; f < kFields; ++f) {
        U* const w = g_words + FieldWords + f * kFieldStride;
        if (!(r->decisionMask >> f & 1)) { if (!exception) ++w[HeldNone]; continue; }
        const bool equal = sd.values[f] == r->record[f];
        if (exception) ++w[equal ? ExceptionAgree : ExceptionDisagree];
        else {
            ++w[equal ? HeldAgree : HeldDisagree];
            ++(equal ? g_stageAgree : g_stageDisagree)[f];
        }
        agreeAll = agreeAll && equal; disagreeAny = disagreeAny || !equal;
    }
    if (x) return;
    // Every non-exception soldier (roles included) is buffered; EndStage picks this stage's voters by main class.
    if (vt < kVtables) ++r->classCount[vt];
    if (!role) {
        ++g_stageCompared;
        if (agreeAll) { ++g_words[HeldAgreeAll]; ++g_stageAgreeAll; }
        if (disagreeAny) { ++g_words[HeldDisagreeAny]; if (vt < kVtables) ++g_words[VtableRows + 4 * vt + 2]; }
    }
    if (g_obsCount == kBufferCapacity) { ++g_words[BufferOverflow]; return; }
    Obs& o = s->obs[g_obsCount++];
    o.row = static_cast<U>(r - s->rows);
    o.vt = vt;
    memcpy(o.values, sd.values, sizeof(o.values));
}
} // namespace

void Observe(U entity) {
    Storage* const s = g_storage;
    if (!s) return;
    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);
    ObserveSoldier(s, entity);
    QueryPerformanceCounter(&end);
    g_observeTicks += static_cast<unsigned long long>(end.QuadPart - start.QuadPart);
}

void EndStage() {
    Storage* const s = g_storage;
    if (!s) return;
    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    // Main class per row (most non-exception soldiers this stage; ties: lower census index). n = voters.
    for (U i = 0; i < kRowCapacity; ++i) {
        Row& r = s->rows[i];
        if (!r.unit || r.lastSeen != g_stage || r.stamp != g_stage) continue;
        U main = 0;
        for (U v = 0; v < kVtables; ++v) if (r.classCount[v] > r.classCount[main]) main = v;
        if (r.classCount[main]) r.mainVt = main + 1; // otherwise the previous main class stays
    }
    for (U i = 0; i < g_obsCount; ++i) { // Boyer-Moore candidates over the voters, worklist order
        const Obs& o = s->obs[i];
        Row& r = s->rows[o.row];
        if (o.vt + 1 != r.mainVt) { ++g_words[VoteExcluded]; continue; }
        ++r.n;
        for (U f = 0; f < kFields; ++f) {
            if (!r.votes[f]) { r.cand[f] = o.values[f]; r.votes[f] = 1; }
            else if (r.cand[f] == o.values[f]) ++r.votes[f];
            else --r.votes[f];
        }
    }
    for (U i = 0; i < g_obsCount; ++i) {
        const Obs& o = s->obs[i];
        Row& r = s->rows[o.row];
        if (o.vt + 1 != r.mainVt) continue;
        for (U f = 0; f < kFields; ++f) if (o.values[f] == r.cand[f]) ++r.matches[f];
    }
    for (U i = 0; i < kRowCapacity; ++i) {
        Row& r = s->rows[i];
        if (!r.unit || r.lastSeen != g_stage || r.stamp != g_stage) continue;
        for (U v = 0; v < kVtables; ++v) g_words[VtableRows + 4 * v + 3] += r.vtMask >> v & 1;
        if (!r.n) continue; // no voter this stage: the previous record is kept unchanged
        U mask = 0;
        for (U f = 0; f < kFields; ++f) {
            const bool majority = r.matches[f] * 2 > r.n;
            U* const w = g_words + FieldWords + f * kFieldStride;
            if (majority) { w[TickAgree] += r.matches[f]; w[TickDisagree] += r.n - r.matches[f]; mask |= 1u << f; }
            else g_words[TickNoneWords + f] += r.n;
            r.record[f] = r.cand[f];
        }
        // New (or decide-time unreadable) units have no signature of this stage yet: read it now, on the owner.
        if (!r.signed_) {
            U inputs[kInputs];
            if (ReadUnitInputs(r.unit, s->owner, g_ownerQueries, inputs)) { r.signature = Signature(inputs); r.signed_ = 1; }
        }
        r.hasRecord = r.signed_; r.recordSignature = r.signature; r.recordMask = r.signed_ ? mask : 0;
    }
    for (U f = 0; f < kFields; ++f) {
        const U total = g_stageAgree[f] + g_stageDisagree[f];
        if (!total) continue;
        const U permille = static_cast<U>(static_cast<unsigned long long>(g_stageAgree[f]) * 1000 / total);
        U& worst = g_words[FieldWords + f * kFieldStride + WorstStagePermille];
        if (permille < worst) worst = permille;
    }
    g_words[LastStageCompared] = g_stageCompared; g_words[LastStageAgreeAll] = g_stageAgreeAll;
    g_words[FinalizeUs] += MicrosSince(start);
    g_words[ObserveUs] = g_frequency.QuadPart ? static_cast<U>(g_observeTicks * 1000000 / g_frequency.QuadPart) : 0;
}

void Snapshot(U* words) { memcpy(words, g_words, sizeof(g_words)); }
} // namespace ntw2_unit_brain
