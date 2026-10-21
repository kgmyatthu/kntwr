#pragma once
#include <stdint.h>
// Site-6 locality census and warm-touch / prefetch A/B (--brain-locality, --brain-locality-warm, --brain-locality-prefetch,
// --brain-locality-prefetch2; analysis/checkpoints/BrainLocality.md). Diagnostics only: it answers whether the per-man
// step 0x66CE00 (vt+0C of soldier entities, ~47-48k occurrences per tick-stage) is memory-bound on scattered per-man
// objects, so that software prefetch inside the existing owner-thread loop could pay. No optimisation is implemented.
//
// Mechanism. The module is an kntwr_brain2::OccurrenceRunner (owner thread, inside RunWorklist, BRAIN2 required, census
// off). Every occurrence runs the ORIGINAL vt+0C entry exactly once, unchanged. Around it the module only LOADS
// (volatile reads of fields the native step itself reads, address arithmetic) and issues PREFETCHT0; it never writes game
// memory and its bookkeeping lives in a private VirtualAlloc'd block. Census loads happen AFTER the step (the E lines are
// then resident), so they cannot warm the lines the step measures; sub-objects are never dereferenced by the census:
// their addresses come from pointer fields of the entity and their cache lines are computed from the static map.
//
// Static map (analysis/tools/brain_locality_gen.py -> native_brain_locality_sets.inc): 16 object types reached from the
// entity by short pointer chains (E itself, unit U=[E+1F0], target T=[E+1EC], frame F=[E+170], slot S=[E+444], ...), each
// with the byte offsets the step's call tree dereferences. Distinct 64-byte lines are derived per actual object address.
//
// Strata (deterministic, no time, no address): occurrence ordinal k within the stage (class-0 / 66CE00 occurrences).
//   timed:  hash(stage, k) >> (32 - shift) == 0 (shift 4 = 1/16): RDTSCP..LFENCE bracket of the step; cost is bucketed by
//           the number of hot-set lines not touched by the previous occurrence.
//   warm:   among timed occurrences hash bit 8 picks arm A (volatile read-touch of every hot line, timed separately,
//           then the timed step) or arm B (cold step). Net gain = (B - A) - touch.
//   prefetch (1/2): blocks of 64 occurrences alternate by hash(stage ^ c, k>>6): arm A blocks issue PREFETCHT0 for the
//           next worklist entities from the start of every occurrence (the bracket of a timed A occurrence includes the
//           issue cost: B - A is the net gain per occurrence). Mode 1: next entity's E lines AND its chain lines (pointer
//           loads = real loads on lines requested a moment ago). Mode 2: E lines of the entity two ahead, chain lines of
//           the entity one ahead (its E lines were requested one occurrence ago).
//   deep stages: hash(stage) >> (32 - deepShift) == 0 (1/8): per-stage address array, merge-sort inversion count, distinct
//           lines/pages per type and for the union (8 MiB line bitmap).
// Status row: kntwr_status::brain_s0_words (560 words, shared with KNTWR_BRAIN_S0, mutually exclusive); layout below.
#define KNTWR_BRAIN_LOC_LABEL_HEADER "loc_version", "loc_configured", "loc_state", "sample_shift", "stages", "deep_stages", \
 "occurrences_lo", "occurrences_hi", "members_lo", "members_hi", "timed", "cal_tsc_khz", "bracket_floor_x16", \
 "bracket_floor_spread_x16", "loop_cycles_lo", "loop_cycles_hi", "deep_cycles_lo", "deep_cycles_hi", "cheap_cost_x16", \
 "cheap_samples", "unreadable", "deep_overflow_stages", "touch_skipped", "prefetch_issued", "probe_queries", \
 "max_stage_members", "diag_faults", "last_stage_members", "blocks_a", "blocks_b", "block_size", "calibration_samples"
#define KNTWR_BRAIN_LOC_LABEL_SCALARS "pairs_lo", "pairs_hi", "same_page", "same_line", "same_unit", "ascending", \
 "descending", "equal", "unit_runs", "inversions_lo", "inversions_hi", "inversion_pairs_lo", "inversion_pairs_hi", \
 "span_kb_sum", "span_kb_max", "deep_members_lo", "entity_pages_sum", "entity_pages_max", "prefetch_issued_hi", "reserved19", \
 "reserved20", "reserved21", "reserved22", "reserved23"
#define KNTWR_BRAIN_LOC_TYPE_LABELS "E_entity", "U_unit_1F0", "T_target_1EC", "F_frame_170", "S_slot_444", "X_5B8", \
 "TM_timer_518", "A_anim_218", "R_root_28", "ARMY_1F8", "N10", "N18", "N1E8", "P2D0", "P520", "N2D4", "ALL_union"
#define KNTWR_BRAIN_LOC_TYPE_WORD_LABELS "deep_valid", "timed_valid", "timed_lines_sum", "timed_pages_sum", \
 "stage_lines_sum", "stage_pages_sum", "stage_lines_max", "stage_pages_max"
#define KNTWR_BRAIN_LOC_HEADER_WORDS 32u
#define KNTWR_BRAIN_LOC_DELTA_BINS 33u
#define KNTWR_BRAIN_LOC_SCALAR_WORDS 24u
#define KNTWR_BRAIN_LOC_RUN_BINS 16u
#define KNTWR_BRAIN_LOC_TYPES 17u
#define KNTWR_BRAIN_LOC_TYPE_WORDS 8u
#define KNTWR_BRAIN_LOC_BUCKETS 16u
#define KNTWR_BRAIN_LOC_BUCKET_WORDS 5u
#define KNTWR_BRAIN_LOC_ARMS 2u
#define KNTWR_BRAIN_LOC_ARM_WORDS 9u
#define KNTWR_BRAIN_LOC_HIST_BINS 64u
#define KNTWR_BRAIN_LOC_DELTA_BASE 32u
#define KNTWR_BRAIN_LOC_SCALAR_BASE 65u
#define KNTWR_BRAIN_LOC_RUN_BASE 89u
#define KNTWR_BRAIN_LOC_TYPE_BASE 105u
#define KNTWR_BRAIN_LOC_BUCKET_BASE 241u
#define KNTWR_BRAIN_LOC_ARM_BASE 321u
#define KNTWR_BRAIN_LOC_HIST_BASE 339u
#define KNTWR_BRAIN_LOC_WORDS 560u
/* Step-cycle histogram bin b: [32 b, 32 b + 32) for b < 32; for b >= 32 [1024 * 2^((b - 32) * 6 / 32), next) (bin 63 open-ended). */
/* --brain-locality-mark (ModeMark): pure pass-through runner (no census, touch, TSC or storage; the step is called once) whose
   stage begin/end emit one manifest-free ETW event each so a WPR/PMC trace can be gated to site-6 windows. Provider GUID
   {6e1c4a2b-5d3f-4a7e-9b21-c8f0a3d7e514} (registered at Start, unregistered at Stop; EventWrite is a no-op without an enabled
   session). Event Id 1 = stage begin, Id 2 = stage end, Level 4, no keyword/task/opcode; payload one little-endian UINT32:
   the 1-based stage ordinal counted per Start (per activation). Status row: configured word = 17 (bit4 mark + bit0), state 1,
   stages = completed stages; every other word zero. */
#define KNTWR_BRAIN_LOC_MARK_GUID_TEXT "6e1c4a2b-5d3f-4a7e-9b21-c8f0a3d7e514"
#define KNTWR_BRAIN_LOC_MARK_EVENT_BEGIN 1u
#define KNTWR_BRAIN_LOC_MARK_EVENT_END 2u
#ifdef __cplusplus
namespace kntwr_brain_locality {
using U = uint32_t;
constexpr U kVersion = 1;
enum Mode : U { ModeCensus = 0, ModeWarm = 1, ModePrefetch1 = 2, ModePrefetch2 = 3, ModeMark = 4 };
constexpr U kDefaultShift = 4, kDefaultDeepShift = 3, kBlock = 64;
constexpr U kHeaderWords = KNTWR_BRAIN_LOC_HEADER_WORDS, kWords = KNTWR_BRAIN_LOC_WORDS, kTypes = 16, kTypeRows = 17;
enum HeaderWord : U {
    Version, Configured, State, SampleShift, Stages, DeepStages, OccurrencesLo, OccurrencesHi, MembersLo, MembersHi,
    Timed, CalTscKhz, BracketFloorX16, BracketFloorSpreadX16, LoopCyclesLo, LoopCyclesHi, DeepCyclesLo, DeepCyclesHi,
    CheapCostX16, CheapSamples, Unreadable, DeepOverflowStages, TouchSkipped, PrefetchIssued, ProbeQueries,
    MaxStageMembers, Faults, LastStageMembers, BlocksA, BlocksB, BlockSize, CalibrationSamples
};
static_assert(CalibrationSamples + 1 == KNTWR_BRAIN_LOC_HEADER_WORDS, "header labels");
// Configured: bit0 census, bit1 warm touch, bit2 prefetch distance 1, bit3 prefetch distance 2. State: 0 not started,
// 1 running/ran, 2 refused (no RDTSCP/invariant TSC), 3 refused (storage).
enum ScalarWord : U {
    PairsLo, PairsHi, SamePage, SameLine, SameUnit, Ascending, Descending, Equal, UnitRuns, InversionsLo, InversionsHi,
    InversionPairsLo, InversionPairsHi, SpanKbSum, SpanKbMax, DeepMembersLo, EntityPagesSum, EntityPagesMax, PrefetchIssuedHi
};
// Adjacent worklist pairs (every stage, consecutive class-0 occurrences): log2 histogram of |E_i - E_(i-1)| (bin 0 equal,
// bin b = floor(log2 d) + 1), same page / same line / same unit ([E+1F0]) / ascending / descending / equal counts, unit runs
// (maximal runs of consecutive same-unit occurrences; run-length log2 histogram at KNTWR_BRAIN_LOC_RUN_BASE). Deep stages:
// inversions of the entity address sequence (pairs i<j with E_i > E_j) over n(n-1)/2 pairs, address span in KiB.
enum TypeWord : U { DeepValid, TimedValid, TimedLinesSum, TimedPagesSum, StageLinesSum, StagePagesSum, StageLinesMax, StagePagesMax };
// Type row r (r < 16 = kntwr type table order, 16 = union of all types): deep_valid = deep-stage occurrences with a non-null
// object; timed_* = sums over timed occurrences of the static line / page count of that object (union: deduplicated);
// stage_* = sums/max over deep stages of the stage's distinct lines / 4 KiB pages.
// Cost buckets (KNTWR_BRAIN_LOC_BUCKET_BASE): bucket b = new hot-set lines vs the previous occurrence in [4b, 4b + 4) (15 =
// 60+): n, sum cycles (lo, hi), sum of squares (double bits lo, hi). Only the cold arm (all timed occurrences in census mode).
// Arms (KNTWR_BRAIN_LOC_ARM_BASE; arm 0 = cold/B (census: every timed occurrence), arm 1 = A: warmed or prefetched): n, step
// cycles sum (lo, hi), sum of squares (double lo, hi), touch cycles sum (lo, hi), touch sum of squares (double lo, hi);
// cycles have the bracket floor subtracted. Histograms (KNTWR_BRAIN_LOC_HIST_BASE + 64 * arm) are the step cycles per bin.

// One block of storage (bitmaps, address and tuple arrays) is allocated once and retained.
U RequiredStorageBytes();
U StorageBytes();
// Owner thread, before the first stage. `mode` as above; sampleShift 0 times every occurrence and deepShift 0 makes every
// stage deep (oracle use). False with state 2/3 on refusal.
bool Start(U imageBase, U mode, U sampleShift = kDefaultShift, U deepShift = kDefaultDeepShift);
void Stop();
void Reset();
void Snapshot(U* words /*[kWords]*/);
// kntwr_brain2::OccurrenceRunner entries (owner thread, inside kntwr_brain2::RunWorklist).
void BeginStage(U manager);
void EndStage();
// Runs the occurrence's +0C step exactly once (the original `original` entry); census/touch/prefetch only for brain class 0
// whose entry is the member step 66CE00.
void RunOccurrence(U entity, U brainClass, U original, const U* cloneEntries);
// Oracle seam: strict inversions (pairs i < j with values[i] > values[j]) of `values` by bottom-up merge sort; both arrays
// (n entries each) are overwritten.
uint64_t InversionCount(U* values, U* scratch, U n);
// Oracle seam for the fault containment: op 0 = region-table readability query (primes the cached proof), 1 = guarded touch of
// `address` as an entity, 2 = guarded post-step census of `address` as an entity, 3 = guarded chain prefetch. False when the
// operation faulted (counted in the diag_faults word) or the range is unreadable.
bool GuardedForTest(U op, U address, U bytes);
} // namespace kntwr_brain_locality
#endif
