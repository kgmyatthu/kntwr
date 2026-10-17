// Site-6 locality census and warm-touch / prefetch A/B (native_brain_locality.h). Owner thread only. Never writes game
// memory: reads of entity fields and PREFETCHT0 only; every bookkeeping store goes to this module's own state.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <evntprov.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include "native_brain_locality.h"
#include "native_brain2.h"
#include "native_region_table.h"
static_assert(sizeof(void*) == 4, "the locality census reads the 32-bit Win32 x86 game");
#pragma comment(lib, "advapi32.lib")   // EventRegister / EventWrite (mark mode)
namespace ntw2_brain_locality {
namespace {
using U64 = unsigned long long;
constexpr U kTypeCount = 16, kEntityBytes = 0x680, kDeepCap = 65536, kMinPtr = 0x10000;
constexpr U kLineBitWords = (1u << 26) / 32, kPageBitWords = (1u << 20) / 32;
constexpr U kRepMax = 32, kCal = 2048, kAll = kTypeCount;
static_assert(kTypeCount == kTypes && kTypeCount + 1 == NTW2_BRAIN_LOC_TYPES, "type rows");
struct TypeSpec { const char* name; U field, count; const uint16_t* offsets; };
#include "native_brain_locality_sets.inc"
struct Storage {
    U lineBits[kLineBitWords];         // 8 MiB: one bit per 64-byte line of the 32-bit address space
    U pageBits[kPageBitWords];         // 128 KiB: one bit per 4 KiB page
    U addr[kDeepCap];                  // deep stage: entity addresses in worklist order
    U sortA[kDeepCap], sortB[kDeepCap];
    U tuple[kDeepCap][kTypeCount - 1]; // deep stage: object pointers of types 1..15 (post-step loads)
};
struct Arm { U64 n, sum, touchSum; double sq, touchSq; U hist[NTW2_BRAIN_LOC_HIST_BINS]; };
struct Bucket { U64 n, sum; double sq; };
struct Slot { U line, epoch, flags; };

Storage* g_store;
ntw2_region::Table g_probe;
U g_probeQueries;
U g_delta, g_member, g_mode, g_shift = kDefaultShift, g_deepShift = kDefaultDeepShift, g_state, g_started, g_configured;
// Static line tables: per type and object alignment (address & 63) the first hot offset of every distinct line.
uint16_t g_reps[kTypeCount][64][kRepMax];
uint8_t g_nrep[kTypeCount][64];
U g_span[kTypeCount];
// Per-stage state.
U g_stage, g_k, g_h, g_blockA, g_deep, g_n;
U g_prevE, g_prevUnit, g_run;
bool g_havePrev, g_prevValid;
U g_prevT[kTypeCount];
U64 g_stageStart;
// Totals.
U64 g_occurrences, g_members, g_timed, g_loopCycles, g_deepCycles, g_cheapSum, g_deepMembers;
U g_stages, g_deepStages, g_unreadable, g_deepOverflow, g_touchSkipped, g_cheapN, g_maxStage, g_lastStage, g_faults;
U g_blocksA, g_blocksB;
U64 g_prefetchIssued;
U64 g_pairs, g_samePage, g_sameLine, g_sameUnit, g_ascending, g_descending, g_equal, g_unitRuns, g_inversions, g_inversionPairs;
U64 g_spanSum, g_spanMax, g_entityPagesSum, g_entityPagesMax;
U g_deltaHist[NTW2_BRAIN_LOC_DELTA_BINS], g_runHist[NTW2_BRAIN_LOC_RUN_BINS];
U g_rows[kTypeCount + 1][NTW2_BRAIN_LOC_TYPE_WORDS];
Bucket g_buckets[NTW2_BRAIN_LOC_BUCKETS];
Arm g_arms[NTW2_BRAIN_LOC_ARMS];
// Calibration and scratch.
U g_calTscKhz, g_floorX16, g_floorSpreadX16, g_floor, g_calSamples;
U g_samples[kCal];
Slot g_slots[512];
U g_epoch;
volatile uint8_t g_sink;

inline U D(U address) { return *reinterpret_cast<const volatile U*>(address); }
inline U64 Tsc() { unsigned aux; _mm_lfence(); const U64 t = __rdtscp(&aux); _mm_lfence(); return t; }
inline U64 TscEnd() { unsigned aux; const U64 t = __rdtscp(&aux); _mm_lfence(); return t; }
inline U Mix2(U a, U b) {
    U h = a * 0x9E3779B1u ^ (b + 0x165667B1u) * 0xC2B2AE3Du;
    h ^= h >> 15; h *= 0x2C1B3C6Du; h ^= h >> 12; h *= 0x297A2D39u; h ^= h >> 15;
    return h;
}
inline bool Stratum(U h, U shift) { return !shift || (h >> (32 - shift)) == 0; }
inline bool TestSet(U* bits, U index) {
    const U mask = 1u << (index & 31); U& word = bits[index >> 5];
    const bool was = (word & mask) != 0; word |= mask; return was;
}
inline U Log2Floor(U v) { unsigned long i; return _BitScanReverse(&i, v) ? static_cast<U>(i) : 0; }
U64 g_edge[32];   // lower edge of bins 32..63: 1024 * 2^((b - 32) * 6 / 32), built at Start (the step path uses integers only)
inline U StepBin(U64 v) {
    if (v < 1024) return static_cast<U>(v >> 5);
    U b = 63;
    while (b > 32 && v < g_edge[b - 32]) --b;
    return b;
}
inline void Put64(U* w, U64 v) { w[0] = static_cast<U>(v); w[1] = static_cast<U>(v >> 32); }
inline void PutDouble(U* w, double v) { U64 bits; std::memcpy(&bits, &v, 8); Put64(w, bits); }

void BuildTables() {
    for (U b = 0; b < 32; ++b) g_edge[b] = static_cast<U64>(1024.0 * std::pow(2.0, b * 6.0 / 32.0));
    std::memset(g_reps, 0, sizeof(g_reps)); std::memset(g_nrep, 0, sizeof(g_nrep));
    for (U t = 0; t < kTypeCount; ++t) {
        const TypeSpec& spec = kTypeSpecs[t];
        g_span[t] = spec.offsets[spec.count - 1] + 4;
        for (U a = 0; a < 64; ++a) {
            U last = ~0u, n = 0;
            for (U i = 0; i < spec.count; ++i) {
                const U line = (a + spec.offsets[i]) >> 6;
                if (line != last) { g_reps[t][a][n++] = spec.offsets[i]; last = line; }
            }
            g_nrep[t][a] = static_cast<uint8_t>(n);
        }
    }
}
void ZeroCounters() {
    g_occurrences = g_members = g_timed = g_loopCycles = g_deepCycles = g_cheapSum = g_deepMembers = 0;
    g_stages = g_deepStages = g_unreadable = g_deepOverflow = g_touchSkipped = g_cheapN = g_faults = 0;
    g_prefetchIssued = 0;
    g_maxStage = g_lastStage = g_blocksA = g_blocksB = 0;
    g_pairs = g_samePage = g_sameLine = g_sameUnit = g_ascending = g_descending = g_equal = g_unitRuns = 0;
    g_inversions = g_inversionPairs = g_spanSum = g_spanMax = g_entityPagesSum = g_entityPagesMax = 0;
    std::memset(g_deltaHist, 0, sizeof(g_deltaHist)); std::memset(g_runHist, 0, sizeof(g_runHist));
    std::memset(g_rows, 0, sizeof(g_rows)); std::memset(g_buckets, 0, sizeof(g_buckets)); std::memset(g_arms, 0, sizeof(g_arms));
    g_stage = g_k = g_h = g_blockA = g_deep = g_n = 0;
    g_prevE = g_prevUnit = g_run = 0; g_havePrev = g_prevValid = false; g_probeQueries = 0;
}

// ---- calibration ------------------------------------------------------------------------------------------------
bool CpuSupported() {
    int r[4];
    __cpuid(r, 0x80000000);
    if (static_cast<U>(r[0]) < 0x80000007u) return false;
    __cpuid(r, 0x80000001);
    if (!(r[3] & (1 << 27))) return false;   // RDTSCP
    __cpuid(r, 0x80000007);
    return (r[3] & (1 << 8)) != 0;           // invariant TSC
}
void Calibrate() {
    LARGE_INTEGER f, q0, q1;
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&q0);
    const U64 t0 = Tsc();
    do QueryPerformanceCounter(&q1); while (q1.QuadPart - q0.QuadPart < f.QuadPart / 50);
    const U64 t1 = Tsc();
    g_calTscKhz = static_cast<U>((t1 - t0) * static_cast<U64>(f.QuadPart) / static_cast<U64>(q1.QuadPart - q0.QuadPart) / 1000);
    for (U i = 0; i < 64; ++i) { const U64 a = Tsc(); (void)(TscEnd() - a); }   // warm
    for (U i = 0; i < kCal; ++i) { const U64 a = Tsc(); g_samples[i] = static_cast<U>(TscEnd() - a); }
    std::sort(g_samples, g_samples + kCal);
    const auto at = [](U num, U den) { return g_samples[std::min(kCal - 1, kCal * num / den)]; };
    g_floorX16 = at(1, 2) * 16;
    g_floorSpreadX16 = static_cast<U>(0.7413 * 16.0 * (at(3, 4) - at(1, 4)));
    g_floor = at(1, 2);
    g_calSamples = kCal;
}

// ---- line sets --------------------------------------------------------------------------------------------------
// Pointer fields of the entity (type 0 is the entity itself). A null or implausible value (< 64 KiB) is "no object".
inline void Capture(U e, U* t) {
    t[0] = e;
    for (U ty = 1; ty < kTypeCount; ++ty) { const U p = D(e + kTypeSpecs[ty].field); t[ty] = p >= kMinPtr ? p : 0; }
}
inline const uint16_t* Reps(U ty, U p, U& count) { count = g_nrep[ty][p & 63]; return g_reps[ty][p & 63]; }
// Slot table of 64-byte line numbers with epoch stamps (flag 1 = in the previous occurrence's set, 2 = in the current's).
U Probe(U line) {
    U i = (line * 2654435761u) >> 23;
    while (g_slots[i].epoch == g_epoch && g_slots[i].line != line) i = (i + 1) & 511;
    return i;
}
struct Counted { U lines, pages, newer; };
// Distinct lines/pages of an occurrence's hot set, and how many lines the previous occurrence's set lacks.
Counted Union(const U* cur, const U* prev, bool havePrev, U* perTypeLines, U* perTypePages) {
    ++g_epoch;
    if (havePrev)
        for (U ty = 0; ty < kTypeCount; ++ty) {
            if (!prev[ty]) continue;
            U n; const uint16_t* r = Reps(ty, prev[ty], n);
            for (U j = 0; j < n; ++j) {
                const U line = (prev[ty] + r[j]) >> 6, i = Probe(line);
                if (g_slots[i].epoch != g_epoch) g_slots[i] = {line, g_epoch, 1};
            }
        }
    Counted c = {0, 0, 0};
    U pages[128], np = 0;
    for (U ty = 0; ty < kTypeCount; ++ty) {
        perTypeLines[ty] = perTypePages[ty] = 0;
        if (!cur[ty]) continue;
        U n; const uint16_t* r = Reps(ty, cur[ty], n);
        perTypeLines[ty] = n;
        U lastPage = ~0u;
        for (U j = 0; j < n; ++j) {
            const U line = (cur[ty] + r[j]) >> 6, page = line >> 6;
            if (page != lastPage) { ++perTypePages[ty]; lastPage = page; }
            const U i = Probe(line);
            if (g_slots[i].epoch != g_epoch) { g_slots[i] = {line, g_epoch, 2}; ++c.newer; }
            else if (g_slots[i].flags & 2) continue;
            else g_slots[i].flags |= 2;
            ++c.lines;
            U k = 0; while (k < np && pages[k] != page) ++k;
            if (k == np && np < 128) pages[np++] = page;
        }
    }
    c.pages = np;
    return c;
}

// ---- warm touch / prefetch --------------------------------------------------------------------------------------
// Volatile read of the first hot offset of every distinct line of the occurrence's objects. The entity region was proven
// readable; every sub-object is probed before its first byte is read, an unreadable one is skipped (never faults).
void TouchSet(U e) {
    U n; const uint16_t* r = Reps(0, e, n);
    for (U j = 0; j < n; ++j) g_sink = *reinterpret_cast<const volatile uint8_t*>(e + r[j]);
    for (U ty = 1; ty < kTypeCount; ++ty) {
        const U p = D(e + kTypeSpecs[ty].field);
        if (p < kMinPtr) continue;
        if (!g_probe.Readable(p, g_span[ty], g_probeQueries)) { ++g_touchSkipped; continue; }
        r = Reps(ty, p, n);
        for (U j = 0; j < n; ++j) g_sink = *reinterpret_cast<const volatile uint8_t*>(p + r[j]);
    }
}
inline void PrefetchEntity(U e) {
    U n; const uint16_t* r = Reps(0, e, n);
    for (U j = 0; j < n; ++j) _mm_prefetch(reinterpret_cast<const char*>(e + r[j]), _MM_HINT_T0);
    g_prefetchIssued += n;
}
// Chain lines: pointer fields of an entity whose readability is proven here (the loads are real; the prefetches are not).
void PrefetchChain(U e) {
    if (!g_probe.Readable(e, kEntityBytes, g_probeQueries)) return;
    for (U ty = 1; ty < kTypeCount; ++ty) {
        const U p = D(e + kTypeSpecs[ty].field);
        if (p < kMinPtr) continue;
        U n; const uint16_t* r = Reps(ty, p, n);
        for (U j = 0; j < n; ++j) _mm_prefetch(reinterpret_cast<const char*>(p + r[j]), _MM_HINT_T0);
        g_prefetchIssued += n;
    }
}
void IssuePrefetch() {
    U cursor, end;
    if (!ntw2_brain2::WorklistWindow(&cursor, &end)) return;
    if (g_mode == ModePrefetch1) {
        if (cursor + 4 >= end) return;
        const U next = D(cursor + 4);
        if (next < kMinPtr) return;
        PrefetchEntity(next); PrefetchChain(next);
    } else {
        if (cursor + 8 < end) { const U ahead = D(cursor + 8); if (ahead >= kMinPtr) PrefetchEntity(ahead); }
        if (cursor + 4 < end) { const U next = D(cursor + 4); if (next >= kMinPtr) PrefetchChain(next); }
    }
}

// ---- accounting -------------------------------------------------------------------------------------------------
void Account(const U* cur, bool prevValid, bool armA, U64 stepCycles, U64 touchCycles, bool touched) {
    // The accounting uses SSE double arithmetic and log2; the game must observe the MXCSR it had before (sticky flags included).
    const unsigned csr = _mm_getcsr();
    U perLines[kTypeCount], perPages[kTypeCount];
    const Counted c = Union(cur, g_prevT, prevValid, perLines, perPages);
    for (U ty = 0; ty < kTypeCount; ++ty) {
        if (!cur[ty]) continue;
        ++g_rows[ty][TimedValid]; g_rows[ty][TimedLinesSum] += perLines[ty]; g_rows[ty][TimedPagesSum] += perPages[ty];
    }
    ++g_rows[kAll][TimedValid]; g_rows[kAll][TimedLinesSum] += c.lines; g_rows[kAll][TimedPagesSum] += c.pages;
    const bool split = g_mode != ModeCensus;
    Arm& arm = g_arms[split && armA ? 1 : 0];
    const U64 v = stepCycles > g_floor ? stepCycles - g_floor : 0;
    ++arm.n; arm.sum += v; arm.sq += static_cast<double>(v) * static_cast<double>(v);
    ++arm.hist[StepBin(v)];
    if (touched) {
        const U64 t = touchCycles > g_floor ? touchCycles - g_floor : 0;
        arm.touchSum += t; arm.touchSq += static_cast<double>(t) * static_cast<double>(t);
    }
    if (prevValid && !(split && armA)) {
        Bucket& b = g_buckets[std::min<U>(c.newer / 4, NTW2_BRAIN_LOC_BUCKETS - 1)];
        ++b.n; b.sum += v; b.sq += static_cast<double>(v) * static_cast<double>(v);
    }
    ++g_timed;
    _mm_setcsr(csr);
}
U64 CountInversions(U* a, U* b, U n) {
    U64 inv = 0;
    for (U width = 1; width < n; width *= 2) {
        for (U lo = 0; lo < n; lo += 2 * width) {
            const U mid = std::min(lo + width, n), hi = std::min(lo + 2 * width, n);
            U i = lo, j = mid, o = lo;
            while (i < mid && j < hi) {
                if (a[j] < a[i]) { inv += mid - i; b[o++] = a[j++]; } else b[o++] = a[i++];
            }
            while (i < mid) b[o++] = a[i++];
            while (j < hi) b[o++] = a[j++];
        }
        std::swap(a, b);
    }
    return inv;
}
void DeepAnalyze() {
    const U n = g_n < kDeepCap ? g_n : kDeepCap;
    if (g_n > kDeepCap) ++g_deepOverflow;
    ++g_deepStages; g_deepMembers += n;
    Storage& s = *g_store;
    U* bits = s.lineBits; U* pbits = s.pageBits;
    // Entity base pages and address span.
    U lo = ~0u, hi = 0, basePages = 0;
    for (U i = 0; i < n; ++i) {
        const U e = s.addr[i];
        lo = std::min(lo, e); hi = std::max(hi, e);
        if (!TestSet(pbits, e >> 12)) ++basePages;
    }
    for (U i = 0; i < n; ++i) pbits[s.addr[i] >> 17] = 0;   // clears the words just set (page >> 5 = e >> 17)
    g_entityPagesSum += basePages; g_entityPagesMax = std::max<U64>(g_entityPagesMax, basePages);
    if (n) { const U64 kb = (static_cast<U64>(hi) - lo) >> 10; g_spanSum += kb; g_spanMax = std::max(g_spanMax, kb); }
    // Distinct lines/pages per type, then of the union.
    U allLines = 0, allPages = 0, allValid = 0;
    for (U pass = 0; pass <= 1; ++pass) {
        for (U ty = 0; ty < kTypeCount; ++ty) {
            U lines = 0, pages = 0, valid = 0;
            for (U i = 0; i < n; ++i) {
                const U p = ty ? s.tuple[i][ty - 1] : s.addr[i];
                if (p < kMinPtr) continue;
                ++valid;
                U cnt; const uint16_t* r = Reps(ty, p, cnt);
                for (U j = 0; j < cnt; ++j) {
                    const U line = (p + r[j]) >> 6;
                    if (!TestSet(bits, line)) { ++lines; if (!TestSet(pbits, line >> 6)) ++pages; }
                }
            }
            if (pass == 0) {
                U* row = g_rows[ty];
                row[DeepValid] += valid; row[StageLinesSum] += lines; row[StagePagesSum] += pages;
                row[StageLinesMax] = std::max(row[StageLinesMax], lines); row[StagePagesMax] = std::max(row[StagePagesMax], pages);
                // Clear (every set bit belongs to this type's pass).
                for (U i = 0; i < n; ++i) {
                    const U p = ty ? s.tuple[i][ty - 1] : s.addr[i];
                    if (p < kMinPtr) continue;
                    U cnt; const uint16_t* r = Reps(ty, p, cnt);
                    for (U j = 0; j < cnt; ++j) { const U line = (p + r[j]) >> 6; bits[line >> 5] = 0; pbits[line >> 11] = 0; }
                }
            } else { allLines += lines; allPages += pages; allValid += valid; }
        }
        if (pass == 1) {
            for (U ty = 0; ty < kTypeCount; ++ty)
                for (U i = 0; i < n; ++i) {
                    const U p = ty ? s.tuple[i][ty - 1] : s.addr[i];
                    if (p < kMinPtr) continue;
                    U cnt; const uint16_t* r = Reps(ty, p, cnt);
                    for (U j = 0; j < cnt; ++j) { const U line = (p + r[j]) >> 6; bits[line >> 5] = 0; pbits[line >> 11] = 0; }
                }
        }
    }
    U* row = g_rows[kAll];
    row[DeepValid] += n; row[StageLinesSum] += allLines; row[StagePagesSum] += allPages;
    row[StageLinesMax] = std::max(row[StageLinesMax], allLines); row[StagePagesMax] = std::max(row[StagePagesMax], allPages);
    (void)allValid;
    // Inversions of the entity address sequence.
    std::memcpy(s.sortA, s.addr, n * sizeof(U));
    g_inversions += CountInversions(s.sortA, s.sortB, n);
    g_inversionPairs += static_cast<U64>(n) * (n ? n - 1 : 0) / 2;
}

// ---- per occurrence ---------------------------------------------------------------------------------------------
void Post(U e, bool timed, bool nextTimed, bool armA, U64 stepCycles, U64 touchCycles, bool touched) {
    const U unit = D(e + 0x1F0);
    if (g_havePrev) {
        ++g_pairs;
        const U d = e > g_prevE ? e - g_prevE : g_prevE - e;
        ++g_deltaHist[d ? 1 + Log2Floor(d) : 0];
        g_samePage += ((e ^ g_prevE) >> 12) == 0; g_sameLine += ((e ^ g_prevE) >> 6) == 0;
        g_ascending += e > g_prevE; g_descending += e < g_prevE; g_equal += e == g_prevE;
        if (unit == g_prevUnit) { ++g_sameUnit; ++g_run; }
        else { if (g_run) { ++g_runHist[std::min<U>(Log2Floor(g_run), NTW2_BRAIN_LOC_RUN_BINS - 1)]; } ++g_unitRuns; g_run = 1; }
    } else { g_run = 1; ++g_unitRuns; }
    g_prevE = e; g_prevUnit = unit; g_havePrev = true;
    if (!(timed || nextTimed || g_deep)) { g_prevValid = false; return; }
    U t[kTypeCount];
    Capture(e, t);
    if (g_deep) {
        if (g_n < kDeepCap) {
            g_store->addr[g_n] = e;
            std::memcpy(g_store->tuple[g_n], t + 1, (kTypeCount - 1) * sizeof(U));
        }
        ++g_n;
    }
    if (timed) Account(t, g_prevValid, armA, stepCycles, touchCycles, touched);
    std::memcpy(g_prevT, t, sizeof(t));
    g_prevValid = true;
}
// Fault containment. The region table proves readability with VirtualQuery, but a proof is stale inside a stage once native code
// frees or decommits (native_region_table.h), so every DIAGNOSTIC read of game memory (post-step census loads, touch loads, chain
// loads, worklist look-ahead) runs inside one of these handlers: a fault is counted (header word diag_faults), the diagnostic op is
// abandoned and MXCSR is restored. The native step is never inside a handler and runs exactly once.
__declspec(noinline) bool TouchGuarded(U e) {
    __try { TouchSet(e); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { ++g_faults; return false; }
}
__declspec(noinline) bool IssueGuarded() {
    __try { IssuePrefetch(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { ++g_faults; return false; }
}
__declspec(noinline) bool PostGuarded(U e, bool timed, bool nextTimed, bool armA, U64 stepCycles, U64 touchCycles, bool touched) {
    const unsigned csr = _mm_getcsr();
    __try { Post(e, timed, nextTimed, armA, stepCycles, touchCycles, touched); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _mm_setcsr(csr); ++g_faults; g_prevValid = false; g_havePrev = false;
        return false;
    }
}
// --brain-locality-mark: manifest-free ETW provider (GUID NTW2_BRAIN_LOC_MARK_GUID_TEXT); event Id 1 = stage begin, Id 2 = stage end,
// payload one U32 stage ordinal (1-based, counted per Start). EventWrite is a no-op without an enabled session.
const GUID kMarkProvider = {0x6e1c4a2b, 0x5d3f, 0x4a7e, {0x9b, 0x21, 0xc8, 0xf0, 0xa3, 0xd7, 0xe5, 0x14}};
REGHANDLE g_etw;
void MarkEvent(USHORT id, U stage) {
    EVENT_DESCRIPTOR d = {};
    d.Id = id; d.Level = 4;
    EVENT_DATA_DESCRIPTOR data;
    EventDataDescCreate(&data, &stage, sizeof(stage));
    EventWrite(g_etw, &d, 1, &data);
}
} // namespace

U RequiredStorageBytes() { return static_cast<U>(sizeof(Storage)); }
U StorageBytes() { return g_store ? static_cast<U>(sizeof(Storage)) : 0; }
uint64_t InversionCount(U* values, U* scratch, U n) { return CountInversions(values, scratch, n); }
bool GuardedForTest(U op, U address, U bytes) {
    switch (op) {
    case 0: return g_probe.Readable(address, bytes, g_probeQueries);
    case 1: return TouchGuarded(address);
    case 2: return PostGuarded(address, true, false, false, 1000, 0, false);
    default: __try { PrefetchChain(address); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { ++g_faults; return false; }
    }
}

bool Start(U imageBase, U mode, U sampleShift, U deepShift) {
    Stop(); Reset();
    g_configured = 1u << (mode == ModeCensus ? 0 : mode);   // bit0 census, bit1 warm, bit2 prefetch 1, bit3 prefetch 2
    if (mode != ModeCensus) g_configured |= 1;
    if (mode == ModeMark) {   // pure pass-through: no storage, no calibration, no census; only the two ETW stage markers
        g_mode = mode; g_shift = sampleShift > 16 ? 16 : sampleShift; ZeroCounters();
        if (EventRegister(&kMarkProvider, nullptr, nullptr, &g_etw) != ERROR_SUCCESS) { g_etw = 0; g_state = 3; return false; }
        g_state = 1; g_started = 1;
        return true;
    }
    if (!CpuSupported()) { g_state = 2; return false; }
    if (!imageBase) { g_state = 3; return false; }
    if (!g_store) {
        g_store = static_cast<Storage*>(VirtualAlloc(nullptr, sizeof(Storage), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!g_store) { g_state = 3; return false; }
    }
    g_delta = imageBase - 0x400000; g_member = imageBase - 0x400000 + 0x66CE00;
    g_mode = mode; g_shift = sampleShift > 16 ? 16 : sampleShift; g_deepShift = deepShift > 16 ? 16 : deepShift;
    BuildTables();
    Calibrate();
    ZeroCounters();
    g_state = 1; g_started = 1;
    return true;
}
void Stop() { g_started = 0; if (g_etw) { EventUnregister(g_etw); g_etw = 0; } }
void Reset() {
    ZeroCounters();
    g_configured = g_state = g_started = 0;
    g_calTscKhz = g_floorX16 = g_floorSpreadX16 = g_floor = g_calSamples = 0;
}
void BeginStage(U manager) {
    (void)manager;
    if (g_mode == ModeMark) { if (g_started) { ++g_stage; MarkEvent(1, g_stage); } return; }
    ++g_stage; g_k = 0; g_h = Mix2(g_stage, 0); g_n = 0;
    g_havePrev = g_prevValid = false; g_run = 0;
    g_deep = g_started && g_store && Stratum(Mix2(g_stage, 0xDEE9u), g_deepShift);
    g_probe.Clear();
    g_stageStart = Tsc();
}
void EndStage() {
    if (g_mode == ModeMark) { if (g_started) { MarkEvent(2, g_stage); ++g_stages; } return; }
    const U64 end = Tsc();
    g_loopCycles += end - g_stageStart; ++g_stages;
    if (g_run) { ++g_runHist[std::min<U>(Log2Floor(g_run), NTW2_BRAIN_LOC_RUN_BINS - 1)]; g_run = 0; }
    g_lastStage = g_k; if (g_k > g_maxStage) g_maxStage = g_k;
    if (g_deep && g_store) { DeepAnalyze(); g_deepCycles += Tsc() - end; }
    g_deep = 0;
}
void RunOccurrence(U entity, U brainClass, U original, const U* cloneEntries) {
    (void)cloneEntries;
    using Step = void(__thiscall*)(void*);
    if (g_mode == ModeMark) { reinterpret_cast<Step>(original)(reinterpret_cast<void*>(entity)); return; }
    ++g_occurrences;
    if (!g_started || brainClass != 0 || original != g_member) {
        reinterpret_cast<Step>(original)(reinterpret_cast<void*>(entity));
        return;
    }
    ++g_members;
    const U k = g_k++;
    const U h = g_h;
    g_h = Mix2(g_stage, k + 1);
    const bool timed = Stratum(h, g_shift), nextTimed = Stratum(g_h, g_shift);
    if (!g_probe.Readable(entity, kEntityBytes, g_probeQueries)) {
        ++g_unreadable; g_prevValid = false; g_havePrev = false;
        reinterpret_cast<Step>(original)(reinterpret_cast<void*>(entity));
        return;
    }
    bool armA = false, touch = false, prefetch = false;
    if (g_mode == ModeWarm) { armA = (h >> 8) & 1; touch = timed && armA; }
    else if (g_mode >= ModePrefetch1) {
        if (!(k & (kBlock - 1))) { g_blockA = Mix2(g_stage ^ 0x5BD1E995u, k / kBlock) & 1; ++(g_blockA ? g_blocksA : g_blocksB); }
        armA = g_blockA != 0; prefetch = armA;
    }
    U64 t0 = 0, t1 = 0, touchCycles = 0;
    if (timed) {
        if (touch) { const U64 ts = Tsc(); TouchGuarded(entity); touchCycles = TscEnd() - ts; }
        t0 = Tsc();
        if (prefetch) IssueGuarded();
        reinterpret_cast<Step>(original)(reinterpret_cast<void*>(entity));
        t1 = TscEnd();
    } else {
        if (prefetch) IssueGuarded();
        reinterpret_cast<Step>(original)(reinterpret_cast<void*>(entity));
    }
    const bool cheap = !timed && !nextTimed && !g_deep && (k & 63) == 5;
    const U64 c0 = cheap ? __rdtsc() : 0;
    PostGuarded(entity, timed, nextTimed, armA, t1 - t0, touchCycles, touch);
    if (cheap) { g_cheapSum += __rdtsc() - c0; ++g_cheapN; }
}
void Snapshot(U* w) {
    std::memset(w, 0, kWords * sizeof(U));
    w[Version] = kVersion; w[Configured] = g_configured; w[State] = g_state; w[SampleShift] = g_shift;
    w[Stages] = g_stages; w[DeepStages] = g_deepStages;
    Put64(w + OccurrencesLo, g_occurrences); Put64(w + MembersLo, g_members);
    w[Timed] = static_cast<U>(g_timed); w[CalTscKhz] = g_calTscKhz;
    w[BracketFloorX16] = g_floorX16; w[BracketFloorSpreadX16] = g_floorSpreadX16;
    Put64(w + LoopCyclesLo, g_loopCycles); Put64(w + DeepCyclesLo, g_deepCycles);
    w[CheapCostX16] = g_cheapN ? static_cast<U>(g_cheapSum * 16 / g_cheapN) : 0; w[CheapSamples] = g_cheapN;
    w[Unreadable] = g_unreadable; w[DeepOverflowStages] = g_deepOverflow; w[TouchSkipped] = g_touchSkipped;
    w[PrefetchIssued] = static_cast<U>(g_prefetchIssued); w[ProbeQueries] = g_probeQueries; w[Faults] = g_faults;
    w[MaxStageMembers] = g_maxStage; w[LastStageMembers] = g_lastStage; w[BlocksA] = g_blocksA; w[BlocksB] = g_blocksB;
    w[BlockSize] = kBlock; w[CalibrationSamples] = g_calSamples;
    std::memcpy(w + NTW2_BRAIN_LOC_DELTA_BASE, g_deltaHist, sizeof(g_deltaHist));
    U* sc = w + NTW2_BRAIN_LOC_SCALAR_BASE;
    Put64(sc + PairsLo, g_pairs); sc[SamePage] = static_cast<U>(g_samePage); sc[SameLine] = static_cast<U>(g_sameLine);
    sc[SameUnit] = static_cast<U>(g_sameUnit); sc[Ascending] = static_cast<U>(g_ascending);
    sc[Descending] = static_cast<U>(g_descending); sc[Equal] = static_cast<U>(g_equal); sc[UnitRuns] = static_cast<U>(g_unitRuns);
    Put64(sc + InversionsLo, g_inversions); Put64(sc + InversionPairsLo, g_inversionPairs);
    sc[PrefetchIssuedHi] = static_cast<U>(g_prefetchIssued >> 32);
    sc[SpanKbSum] = static_cast<U>(g_spanSum); sc[SpanKbMax] = static_cast<U>(g_spanMax);
    sc[DeepMembersLo] = static_cast<U>(g_deepMembers);
    sc[EntityPagesSum] = static_cast<U>(g_entityPagesSum); sc[EntityPagesMax] = static_cast<U>(g_entityPagesMax);
    std::memcpy(w + NTW2_BRAIN_LOC_RUN_BASE, g_runHist, sizeof(g_runHist));
    std::memcpy(w + NTW2_BRAIN_LOC_TYPE_BASE, g_rows, sizeof(g_rows));
    for (U b = 0; b < NTW2_BRAIN_LOC_BUCKETS; ++b) {
        U* q = w + NTW2_BRAIN_LOC_BUCKET_BASE + b * NTW2_BRAIN_LOC_BUCKET_WORDS;
        q[0] = static_cast<U>(g_buckets[b].n); Put64(q + 1, g_buckets[b].sum); PutDouble(q + 3, g_buckets[b].sq);
    }
    for (U a = 0; a < NTW2_BRAIN_LOC_ARMS; ++a) {
        U* q = w + NTW2_BRAIN_LOC_ARM_BASE + a * NTW2_BRAIN_LOC_ARM_WORDS;
        q[0] = static_cast<U>(g_arms[a].n); Put64(q + 1, g_arms[a].sum); PutDouble(q + 3, g_arms[a].sq);
        Put64(q + 5, g_arms[a].touchSum); PutDouble(q + 7, g_arms[a].touchSq);
        std::memcpy(w + NTW2_BRAIN_LOC_HIST_BASE + a * NTW2_BRAIN_LOC_HIST_BINS, g_arms[a].hist, sizeof(g_arms[a].hist));
    }
}
} // namespace ntw2_brain_locality
