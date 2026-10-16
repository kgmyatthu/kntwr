#include "ntw2_planner_prepass.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include "ntw2_guard.h"

namespace ntw2_prepass {
namespace {
inline void Mix(U& h, U v) { h ^= v; h *= 16777619u; }
inline U Bits(float f) { U u; memcpy(&u, &f, 4); return u; }
inline const U* P(U va) { return reinterpret_cast<const U*>(static_cast<uintptr_t>(va)); }
// One guarded dword read of foreign memory. Not a crash for the first-chance capture (probeDepth).
bool Read(U va, U* out) {
    bool ok = true;
    ++ntw2::probeDepth;
    __try { *out = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(va)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    --ntw2::probeDepth;
    return ok;
}
}

// ---------------------------------------------------------------------------------------------------------------- walk key
namespace {
bool ReadKeyGuarded(U ecx, const U* shape, WalkKey* out) {
    __try {
        if (shape[0] != 0) return false;           // only the OBB kind is classified
        WalkKey key;
        key.w[0] = kWalkVa; key.w[1] = ecx; key.w[2] = kGatherMask;
        for (U i = 0; i < 18; ++i) key.w[3 + i] = shape[i];
        key.w[3 + 3] &= 0xFFFFu;                   // descriptor +0xC: angle in the low half, padding in the high half
        *out = key;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
}
bool ReadWalkKey(U ecx, const void* shape, WalkKey* out) {
    if (!shape || !out) return false;
    ++ntw2::probeDepth;
    const bool ok = ReadKeyGuarded(ecx, static_cast<const U*>(shape), out);
    --ntw2::probeDepth;
    return ok;
}
U HashWalkKey(const WalkKey& key) {
    U h = 2166136261u;
    for (U i = 0; i < kKeyWords; ++i) Mix(h, key.w[i]);
    return h;
}
bool EqualWalkKey(const WalkKey& a, const WalkKey& b) { return !memcmp(a.w, b.w, sizeof(a.w)); }

// ------------------------------------------------------------------------------------------------------------ gathered list
namespace {
U HashListGuarded(const U* entries, U count, U mode, float threshold, U* flagsOut) {
    U h = 2166136261u, flags = 0;
    Mix(h, count); Mix(h, mode); Mix(h, Bits(threshold));
    if (mode != 1) flags |= kListMode2;
    __try {
        U n = count;
        if (n > kMaxListEntries) { flags |= kListOversize; n = kMaxListEntries; }
        for (U i = 0; i < n; ++i) {
            const U entry = entries[i];
            Mix(h, entry);
            if (!entry) continue;
            const U type = *P(entry);
            Mix(h, type);
            if (type != 0x10) continue;                  // the walk skips every other interest type
            const U owner = *P(entry + 0xC);
            Mix(h, owner);
            if (!owner) continue;
            const U polygon = *P(owner + 8), f1c = *P(owner + 0x1C), f20 = *P(owner + 0x20);
            Mix(h, polygon); Mix(h, f1c); Mix(h, f20);
            float level; memcpy(&level, &f20, 4);
            const bool consumed = mode == 1 ? (level >= threshold) : (mode == 2 && f1c == 1);
            if (!consumed || !polygon) continue;
            U vertices = 0, node = polygon;
            for (;;) {
                const U x = *P(node + 0xC), y = *P(node + 0x10), next = *P(node + 8);
                Mix(h, x); Mix(h, y);
                if (++vertices > kMaxPolygonVertices) { flags |= kListOversize; break; }
                if (!next) { flags |= kListUnreadable; break; }
                node = next;
                if (node == polygon) break;
            }
            Mix(h, vertices);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { flags |= kListUnreadable; }
    *flagsOut = flags;
    return h;
}
}
U HashGatheredListEx(const U* entries, U count, U mode, float threshold, U* flags) {
    U local = 0;
    if (!flags) flags = &local;
    if (!entries && count) { *flags = kListUnreadable; return 0; }
    ++ntw2::probeDepth;
    const U h = HashListGuarded(entries, count, mode, threshold, flags);
    --ntw2::probeDepth;
    return h;
}
U HashGatheredList(const U* entries, U count, U mode, float threshold) {
    U flags = 0;
    return HashGatheredListEx(entries, count, mode, threshold, &flags);
}

// --------------------------------------------------------------------------------------------------------------- query log
namespace {
QueryRecord g_log[kLogCapacity];
U g_logCount, g_logOverflow, g_logPlanner, g_logNode, g_logChild;
bool g_logOpen;
}
void ThinkLogBegin(U planner, U node, U child) {
    if (!g_logOpen || g_logPlanner != planner || g_logNode != node) {
        g_logCount = 0; g_logOverflow = 0; g_logPlanner = planner; g_logNode = node; g_logOpen = true;
    }
    g_logChild = child;
}
bool ThinkLogAppend(const QueryRecord& record) {
    if (!g_logOpen) return false;
    if (g_logCount >= kLogCapacity) { ++g_logOverflow; return false; }
    g_log[g_logCount++] = record;
    return true;
}
void ThinkLogEnd() { g_logOpen = false; }
U ThinkLogCount() { return g_logCount; }
const QueryRecord* ThinkLogRecord(U index) { return index < g_logCount ? &g_log[index] : nullptr; }
U ThinkLogPlanner() { return g_logPlanner; }
U ThinkLogNode() { return g_logNode; }
U ThinkLogChild() { return g_logChild; }
U ThinkLogOverflow() { return g_logOverflow; }
bool ThinkLogOpen() { return g_logOpen; }

// ------------------------------------------------------------------------------------------------------------------- D1
namespace {
bool CaptureGuarded(U node, D1State* s) {
    __try {
        s->count = *P(node + 0x48); s->data = *P(node + 0x4C);
        s->n = s->count < kMaxChildren ? s->count : kMaxChildren;
        s->truncated = s->count > kMaxChildren;
        if (s->count && !s->data) return false;
        for (U j = 0; j < s->n; ++j) {
            const U child = *P(s->data + 4 * j);
            s->child[j] = child;
            if (!child) { for (U k = 0; k < kChildWords; ++k) s->words[j][k] = 0; continue; }
            s->words[j][0] = *P(child + 0x30); s->words[j][1] = *P(child + 0x34);
            s->words[j][2] = *P(child + 0x40); s->words[j][3] = *P(child + 0x44);
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void CompareGuarded(const D1State& pre, U node, U self, D1Diff* out) {
    __try {
        const U count = *P(node + 0x48), data = *P(node + 0x4C);
        if (count != pre.count || data != pre.data) out->listChanged = 1;
        const U n = count < pre.n ? count : pre.n;
        for (U j = 0; j < n; ++j) {
            const U child = *P(data + 4 * j);
            if (child != pre.child[j]) { out->listChanged = 1; continue; }
            if (!child) continue;
            U changed = 0;
            const U live[kChildWords] = {*P(child + 0x30), *P(child + 0x34), *P(child + 0x40), *P(child + 0x44)};
            for (U k = 0; k < kChildWords; ++k) changed += live[k] != pre.words[j][k];
            if (!changed) continue;
            if (j == self) out->selfWords += changed;
            else { ++out->otherChildren; out->otherWords += changed; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { out->listChanged = 1; }
}
}
bool D1Capture(U node, D1State* state) {
    state->count = state->data = state->n = 0; state->truncated = false; state->valid = false;
    ++ntw2::probeDepth;
    state->valid = CaptureGuarded(node, state);
    --ntw2::probeDepth;
    return state->valid;
}
void D1Compare(const D1State& pre, U node, U self, D1Diff* out) {
    *out = D1Diff{};
    if (!pre.valid) return;
    ++ntw2::probeDepth;
    CompareGuarded(pre, node, self, out);
    --ntw2::probeDepth;
}

// ------------------------------------------------------------------------------------------------------------ census engine
const U kNodeThinkSlots[kNodeThinkSlotCount] = {0x13429b4, 0x13429e8, 0x1342a1c, 0x1342a50, 0x1342a84,
                                                0x1342ac4, 0x1342afc, 0x1342b34, 0x1342b6c, 0x1342bac};
namespace {
enum W : U {
    WVersion, WScopes, WNodes, WChildren, WWalks, WWalksInChild, WDistinct, WDup, WDupSameChild, WUnsupported, WOverflow,
    WMaxWalksScope, WMaxDistinctScope, WMaxWalksChild, WThinkUs, WThinkMaxUs, WWalkUs, WGatherUs, WTravUs, WMaxWalkUs,
    WPolygons, WAl0, WAl1, WGathered, WGatheredMax, WListUnsupported, WChildUs, WChildMaxUs, WD1Checked, WD1OtherThinks,
    WD1OtherWords, WD1ListThinks, WD1SelfThinks, WD1SelfWords, WD1Truncated, WWorldDiff, WWorldSame, WSite0, WSite1,
    WSiteOther, WClassBase = 40, WPresizeBase = 55, WFlags = 63, WPolyVSum = 64, WPolyVMax, WPolyHit, WPolyVUnreadable,
    WPolyBucketCalls = 68, WPolyBucketUs = 74, WSite808492 = 80, WPolyVOverflow
};
static_assert(WClassBase + 15 == WPresizeBase && WPresizeBase + 8 == WFlags && WPolyBucketUs + 6 == WSite808492 &&
              WPolyVOverflow + 1 == kCensusWords, "census row layout");
constexpr U kSlots = 4096, kProbes = 64, kDepth = 4;
struct Slot { U gen, hash, listHash, lastChild; WalkKey key; };
Slot g_slots[kSlots];                       // 4096 x 100 bytes, generation-tagged
U g_gen;
volatile U g_w[kCensusWords];
int64_t g_walkTicks, g_gatherTicks, g_travTicks, g_childTicks, g_classWalkTicks[5], g_polyBucketTicks[6];
int64_t g_freq = 1;
U g_flags;
Targets g_targets;
U g_nodeOriginal, g_nodeClone;              // read by the naked node gate
bool (*g_inScope)(U);
U g_planner;
bool g_scopeOpen;
U g_scopeWalks, g_scopeDistinct;
int64_t g_scopeWalkTicks;

struct Walk {
    bool active, keyOk;
    WalkKey key;
    U shape, site, gathered, listHash, listFlags, polygons, vertices;
    int64_t gatherTicks, gatherEnd;
    bool gathers;
};
Walk g_walk;
struct ChildFrame { U node, child, index, walks, savedChild; int64_t start; };
ChildFrame g_childFrames[kDepth];
D1State g_d1[kDepth];
U g_childDepth, g_nodeDepth, g_curChild = kNoChild;

inline U Sat(int64_t ticks) { return ticks < 0 ? 0u : ticks > 0xFFFFFFFFll ? 0xFFFFFFFFu : static_cast<U>(ticks); }
inline U Us(int64_t ticks) { return ticks > 0 ? static_cast<U>(ticks * 1000000 / g_freq) : 0u; }
inline void Add(U index, U v = 1) { g_w[index] += v; }
inline void Max(U index, U v) { if (v > g_w[index]) g_w[index] = v; }
inline int64_t Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }
}

void CensusReset(U flags, const Targets& targets, int64_t qpcFrequency) {
    memset(const_cast<U*>(g_w), 0, sizeof(g_w));
    memset(g_slots, 0, sizeof(g_slots));
    g_gen = 0; g_walkTicks = g_gatherTicks = g_travTicks = g_childTicks = 0;
    for (auto& t : g_classWalkTicks) t = 0;
    for (auto& t : g_polyBucketTicks) t = 0;
    g_freq = qpcFrequency > 0 ? qpcFrequency : 1;
    g_flags = flags; g_targets = targets;
    g_nodeOriginal = targets.nodeOriginal; g_nodeClone = targets.nodeClone; g_inScope = targets.inScope;
    g_planner = 0; g_scopeOpen = false; g_scopeWalks = g_scopeDistinct = 0; g_scopeWalkTicks = 0;
    g_walk = Walk{}; g_childDepth = g_nodeDepth = 0; g_curChild = kNoChild;
    g_logCount = g_logOverflow = g_logPlanner = g_logNode = g_logChild = 0; g_logOpen = false;
    PresizeCounters(nullptr);
}
bool CensusArmed() { return (g_flags & kFlagCensus) != 0; }

void ScopeBegin(U planner) {
    if (!CensusArmed()) return;
    if (!++g_gen) { memset(g_slots, 0, sizeof(g_slots)); g_gen = 1; }
    g_planner = planner; g_scopeOpen = true; g_scopeWalks = g_scopeDistinct = 0; g_scopeWalkTicks = 0;
    g_walk.active = false; g_childDepth = g_nodeDepth = 0; g_curChild = kNoChild;
    g_logOpen = false;
}
void ScopeEnd(U thinkUs) {
    if (!CensusArmed() || !g_scopeOpen) return;
    g_scopeOpen = false;
    Add(WScopes); Add(WThinkUs, thinkUs); Max(WThinkMaxUs, thinkUs);
    Max(WMaxWalksScope, g_scopeWalks); Max(WMaxDistinctScope, g_scopeDistinct);
    const U cls = thinkUs <= 8000 ? 0 : thinkUs <= 32000 ? 1 : thinkUs <= 128000 ? 2 : thinkUs <= 512000 ? 3 : 4;
    Add(WClassBase + 3 * cls); Add(WClassBase + 3 * cls + 1, thinkUs);
    g_classWalkTicks[cls] += g_scopeWalkTicks;
    g_logOpen = false; g_walk.active = false;
}

void WalkBegin(U ecx, U shape, U returnAddress, int64_t now) {
    (void)now;
    if (!CensusArmed() || !g_scopeOpen) return;
    Walk& w = g_walk;
    w = Walk{};
    w.active = true; w.shape = shape;
    w.keyOk = ReadWalkKey(ecx, reinterpret_cast<const void*>(static_cast<uintptr_t>(shape)), &w.key);
    const U e = g_targets.shapeSearchEntry;
    w.site = (e && returnAddress == e + (0x7C7FD3u + 5 - 0x7C7DC0u)) ? 0x7C7FD3u
           : (e && returnAddress == e + (0x7C8113u + 5 - 0x7C7DC0u)) ? 0x7C8113u
           : (g_targets.route808040Entry && returnAddress == g_targets.route808040Entry + (0x808492u + 5 - 0x808040u)) ? 0x808492u : 0u;
    Add(WWalks); ++g_scopeWalks;
    Add(w.site == 0x7C7FD3u ? WSite0 : w.site == 0x7C8113u ? WSite1 : w.site == 0x808492u ? WSite808492 : WSiteOther);
    if (g_curChild != kNoChild) {
        Add(WWalksInChild);
        if (g_childDepth && g_childDepth <= kDepth) ++g_childFrames[g_childDepth - 1].walks;
    }
}
void WalkGathered(U listHeader, int64_t frameTicks, int64_t now) {
    Walk& w = g_walk;
    if (!CensusArmed() || !w.active) return;
    U count = 0, data = 0, mode = 0, thresholdBits = 0;
    const bool listOk = Read(listHeader + 8, &count) && Read(listHeader + 0xC, &data);
    const bool shapeOk = Read(w.shape + 0x40, &mode) && Read(w.shape + 0x44, &thresholdBits);
    w.gathers = true; w.gatherTicks = frameTicks; w.gatherEnd = now;
    if (!listOk || !shapeOk) { w.listFlags = kListUnreadable; w.gathered = count; return; }
    float threshold; memcpy(&threshold, &thresholdBits, 4);
    w.gathered = count;
    w.listHash = HashGatheredListEx(count ? P(data) : nullptr, count, mode, threshold, &w.listFlags);
    Add(WGathered, count); Max(WGatheredMax, count);
    if (w.listFlags) Add(WListUnsupported);
}
namespace {
// Vertex count of the 0x80DCF0 polygon ring (next = node[2]); 65 stands for "more than kMaxPolygonVertices".
bool CountRing(U polygon, U* out) {
    U v = 0, node = polygon;
    __try {
        for (;;) {
            ++v;
            const U next = *P(node + 8);
            if (!next) return false;
            node = next;
            if (node == polygon) break;
            if (v > kMaxCountedVertices) { v = kMaxCountedVertices + 1; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    *out = v;
    return true;
}
}
void WalkPolygon(U polygon, U eax, int64_t ticks) {
    if (!CensusArmed() || !g_walk.active) return;
    ++g_walk.polygons; Add(WPolygons);
    if (!polygon) return;                          // 0x808F90 (mode 2): not the ring predicate, no vertex count
    if ((eax & 0xFF) == 1) Add(WPolyHit);
    U v = 0;
    ++ntw2::probeDepth;
    const bool ok = CountRing(polygon, &v);
    --ntw2::probeDepth;
    if (!ok) { Add(WPolyVUnreadable); return; }
    const U b = v <= 8 ? 0 : v <= 16 ? 1 : v <= 32 ? 2 : v <= 64 ? 3 : v <= 256 ? 4 : 5;
    Add(WPolyBucketCalls + b); g_polyBucketTicks[b] += ticks;
    if (v > kMaxCountedVertices) { Add(WPolyVOverflow); return; }   // ring longer than the counted bound: bucket only, no sum/max
    Add(WPolyVSum, v); Max(WPolyVMax, v); g_walk.vertices += v;
}
void WalkEnd(U eax, int64_t frameTicks, int64_t now) {
    Walk& w = g_walk;
    if (!CensusArmed() || !w.active) return;
    w.active = false;
    const U al = eax & 0xFF;
    const int64_t trav = w.gathers ? now - w.gatherEnd : 0;
    g_walkTicks += frameTicks; g_gatherTicks += w.gatherTicks; g_travTicks += trav;
    g_scopeWalkTicks += frameTicks;
    Max(WMaxWalkUs, Us(frameTicks));
    Add(al ? WAl1 : WAl0);
    QueryRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.site = w.site; rec.child = g_curChild; rec.gathered = w.gathered; rec.listHash = w.listHash;
    rec.polygonTests = w.polygons; rec.polygonVertices = w.vertices; rec.gatherCycles = Sat(w.gatherTicks); rec.traversalCycles = Sat(trav);
    rec.result = static_cast<uint8_t>(al);
    if (g_curChild == kNoChild) rec.flags |= kRecNoChild;
    if (w.listFlags) rec.flags |= kRecListUnsupported;
    if (!w.keyOk) {
        rec.flags |= kRecUnsupportedKey; Add(WUnsupported);
    } else {
        rec.key = w.key;
        const U hash = HashWalkKey(w.key);
        Slot* found = nullptr; Slot* empty = nullptr;
        U idx = hash & (kSlots - 1);
        for (U probe = 0; probe < kProbes; ++probe, idx = (idx + 1) & (kSlots - 1)) {
            Slot& s = g_slots[idx];
            if (s.gen != g_gen) { empty = &s; break; }
            if (s.hash == hash && EqualWalkKey(s.key, w.key)) { found = &s; break; }
        }
        if (found) {
            rec.flags |= kRecDuplicate; Add(WDup);
            if (g_curChild != kNoChild && found->lastChild == g_curChild) Add(WDupSameChild);
            if (found->listHash != w.listHash) { rec.flags |= kRecWorldChanged; Add(WWorldDiff); } else Add(WWorldSame);
            found->listHash = w.listHash; found->lastChild = g_curChild;
        } else if (empty) {
            empty->gen = g_gen; empty->hash = hash; empty->listHash = w.listHash; empty->lastChild = g_curChild;
            empty->key = w.key;
            Add(WDistinct); ++g_scopeDistinct;
        } else {
            rec.flags |= kRecOverflow; Add(WOverflow);      // never a hit, never silently distinct
        }
    }
    ThinkLogAppend(rec);
}

void CensusSnapshot(volatile U* words) {
    for (U i = 0; i < kCensusWords; ++i) words[i] = g_flags ? g_w[i] : 0;
    if (!g_flags) return;
    words[WVersion] = kCensusVersion;
    words[WWalkUs] = Us(g_walkTicks); words[WGatherUs] = Us(g_gatherTicks); words[WTravUs] = Us(g_travTicks);
    words[WChildUs] = Us(g_childTicks);
    for (U c = 0; c < 5; ++c) words[WClassBase + 3 * c + 2] = Us(g_classWalkTicks[c]);
    for (U b = 0; b < 6; ++b) words[WPolyBucketUs + b] = Us(g_polyBucketTicks[b]);
    PresizeCounters(words + WPresizeBase);
    words[WFlags] = g_flags;
}

// ------------------------------------------------------------------------------------------------------------------ gates
extern "C" U __stdcall ntw2_pp_NodeEnter(U node) {
    if (!CensusArmed() || !g_scopeOpen || !g_inScope || !g_inScope(GetCurrentThreadId())) return 0;
    ThinkLogEnd();
    Add(WNodes);
    if (g_nodeDepth < kDepth) ++g_nodeDepth;
    g_curChild = kNoChild;
    return g_nodeClone;
}
extern "C" void __stdcall ntw2_pp_NodeLeave(U node) {
    (void)node;
    if (g_nodeDepth) --g_nodeDepth;
    ThinkLogEnd();
    g_curChild = kNoChild;
}
extern "C" void __stdcall ntw2_pp_ChildPre(U node, U child, U index) {
    if (!CensusArmed()) return;
    Add(WChildren);
    const U d = g_childDepth++;
    if (d >= kDepth) return;
    ChildFrame& f = g_childFrames[d];
    f.node = node; f.child = child; f.index = index; f.walks = 0; f.savedChild = g_curChild;
    ThinkLogBegin(g_planner, node, index);
    g_curChild = index;
    D1Capture(node, &g_d1[d]);
    f.start = Now();
}
extern "C" void __stdcall ntw2_pp_ChildPost(U node, U child, U index) {
    (void)child;
    if (!CensusArmed() || !g_childDepth) return;
    const U d = --g_childDepth;
    if (d >= kDepth) return;
    ChildFrame& f = g_childFrames[d];
    const int64_t ticks = Now() - f.start;
    g_childTicks += ticks; Max(WChildMaxUs, Us(ticks));
    Max(WMaxWalksChild, f.walks);
    D1Diff diff;
    D1Compare(g_d1[d], node, index, &diff);
    Add(WD1Checked);
    if (g_d1[d].truncated) Add(WD1Truncated);
    if (diff.listChanged) Add(WD1ListThinks);
    if (diff.otherChildren) { Add(WD1OtherThinks); Add(WD1OtherWords, diff.otherWords); }
    if (diff.selfWords) { Add(WD1SelfThinks); Add(WD1SelfWords, diff.selfWords); }
    g_curChild = f.savedChild;
}

__declspec(naked) void NodeThinkGate() {
    __asm {
        lea esp, [esp-4]
        pushfd
        pushad
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push dword ptr [ebp+24]
        call ntw2_pp_NodeEnter
        mov dword ptr [ebp+36], eax
        fxrstor [esp]
        mov esp, ebp
        popad
        popfd
        pop eax
        test eax, eax
        jz original
        push ecx
        call eax
        push eax
        push edx
        push ebp
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push dword ptr [ebp+12]
        call ntw2_pp_NodeLeave
        fxrstor [esp]
        mov esp, ebp
        pop ebp
        pop edx
        pop eax
        add esp, 4
        ret
    original:
        jmp dword ptr [g_nodeOriginal]
    }
}
// Replaces the clone's `mov eax,[ecx]; call [eax+0x28]` (ECX = child, EDI = node, ESI = index; plain return). The original
// call is made exactly once with the caller's registers; ESI/EDI/EBX/EBP survive the stdcall host functions.
__declspec(naked) void ChildThinkGate() {
    __asm {
        push ebp
        mov ebp, esp
        sub esp, 8
        mov dword ptr [ebp-4], ecx
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push esi
        push ecx
        push edi
        call ntw2_pp_ChildPre
        fxrstor [esp]
        lea esp, [ebp-8]
        mov ecx, dword ptr [ebp-4]
        mov eax, dword ptr [ecx]
        call dword ptr [eax+0x28]
        mov dword ptr [ebp-8], eax
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push esi
        push dword ptr [ebp-4]
        push edi
        call ntw2_pp_ChildPost
        fxrstor [esp]
        mov eax, dword ptr [ebp-8]
        mov esp, ebp
        pop ebp
        ret
    }
}
U NodeThinkGateAddress() { return static_cast<U>(reinterpret_cast<uintptr_t>(&NodeThinkGate)); }
U ChildThinkGateAddress() { return static_cast<U>(reinterpret_cast<uintptr_t>(&ChildThinkGate)); }

// -------------------------------------------------------------------------------------------------------------- presizing
namespace {
AllocFn g_alloc;
volatile LONG g_presize[8];
}
void PresizeConfigure(AllocFn allocator) { g_alloc = allocator; }
void PresizeCounters(volatile U* out8) {
    if (!out8) { for (auto& c : g_presize) c = 0; return; }
    for (U i = 0; i < 8; ++i) out8[i] = static_cast<U>(g_presize[i]);
}
ReserveResult PresizeReserve(U xLo, U xHi, U yLo, U yHi, U* header) {
    _InterlockedIncrement(&g_presize[0]);
    const U nx = xHi > xLo ? xHi - xLo : 0, ny = yHi > yLo ? yHi - yLo : 0;
    if (!nx || !ny) { _InterlockedIncrement(&g_presize[3]); return kSkippedNoBound; }
    if (header[1] || header[2] || header[3]) { _InterlockedIncrement(&g_presize[2]); return kSkippedNonEmpty; }
    const uint64_t cells = static_cast<uint64_t>(nx) * ny;     // <= 2^64 - 1, no overflow
    const bool clamped = cells > kPresizeMaxPairs;
    const U n = clamped ? kPresizeMaxPairs : static_cast<U>(cells);
    if (!g_alloc || static_cast<uint64_t>(n) * 8 > 0xFFFFFFFFull) { _InterlockedIncrement(&g_presize[5]); return kAllocFailed; }
    void* block = g_alloc(static_cast<int>(n), 0);
    if (!block) { _InterlockedIncrement(&g_presize[5]); return kAllocFailed; }
    header[3] = static_cast<U>(reinterpret_cast<uintptr_t>(block));
    header[1] = n;
    _InterlockedIncrement(&g_presize[clamped ? 4 : 1]);
    if (clamped) _InterlockedIncrement(&g_presize[1]);
    _InterlockedExchangeAdd(&g_presize[6], static_cast<LONG>(n));
    return clamped ? kReservedClamped : kReserved;
}
extern "C" void __stdcall ntw2_pp_PresizeReserve(U frame) {
    const U* f = P(frame);
    PresizeReserve(f[0x1ac / 4], f[0x150 / 4], f[0x194 / 4], f[0x158 / 4],
                   reinterpret_cast<U*>(static_cast<uintptr_t>(f[0x1bc / 4])));
}
extern "C" void __stdcall ntw2_pp_PresizeExit(U frame) {
    const U* header = P(P(frame)[0x1bc / 4]);
    _InterlockedExchangeAdd(&g_presize[7], static_cast<LONG>(header[2]));
}
// Inserted code is `call gate`: the clone body's ESP at the insertion point is [ebp+40] (ret 4, flags 4, pushad 32).
__declspec(naked) void PresizeReserveGate() {
    __asm {
        pushfd
        pushad
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        lea eax, [ebp+40]
        push eax
        call ntw2_pp_PresizeReserve
        fxrstor [esp]
        mov esp, ebp
        popad
        popfd
        ret
    }
}
__declspec(naked) void PresizeExitGate() {
    __asm {
        pushfd
        pushad
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        lea eax, [ebp+40]
        push eax
        call ntw2_pp_PresizeExit
        fxrstor [esp]
        mov esp, ebp
        popad
        popfd
        ret
    }
}
U PresizeReserveGateAddress() { return static_cast<U>(reinterpret_cast<uintptr_t>(&PresizeReserveGate)); }
U PresizeExitGateAddress() { return static_cast<U>(reinterpret_cast<uintptr_t>(&PresizeExitGate)); }
}
