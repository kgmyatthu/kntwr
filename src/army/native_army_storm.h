#pragma once
#include <stdint.h>

// Site-18 storm census (--army-storm-census, kntwr_config::va_watch_flags KNTWR_ARMY_STORM_CENSUS): performance data gathering only,
// no behaviour change. Question measured: what a site-18 tail storm (ARMY_UPDATE clone 0x580390 calling 0x581F30 per unit through
// timed sites 101 (call 0x5804C2, main list) and 103 (call 0x5804FF, alternate list)) spends its 100-260 ms on, how many units take
// the command/formation route per storm tick (one unit x 250 ms or 50 units x 5 ms), and which army/side they belong to.
//
// Hooks (runtime host data only): siteCallees[101]/[103] -> Unit (tick owner inside a routed epoch; every other caller runs the
// native 0x581F30 directly). Inside the epoch the unit runs as the ARMY_UNIT clone (instruction-identical to 0x581F30 except its
// bound call sites; see kntwr_runtime.cpp), whose preparation call 581FFB (-> 57F070), FSM call 58202E (-> 582530) and formation
// update call 5820DE (-> 585D50) reach Call() inclusive QPC brackets. Two pinned .rdata slots (installed only with the census) reach
// the route gates: 0x1325474 (0x581AE0, the per-tick execute of the class-1325470 assignment command, "R2") and 0x1331E74
// (0x617510, the state-enter that builds that command on an order/FSM transition, "R1"). All native effects are unchanged and
// authoritative; this module only READS native memory (ranges proven readable first, kntwr_region::Table, SEH bracketed by
// kntwr::probeDepth) and writes its own row.
//
// Route evidence [proven by disasm, analysis/army-storm-route-decode.md; StormDecode]: 0x581AE0 (ECX = C) calls 0x576B30 (fresh
// terrain container 0x7F2D70, assignment kernel) iff byte [C+3C]==0 or (byte [F+278C]!=0 and dword [F+2788]==0), F = [C+4]; both
// are read at gate entry (572B00/531A70 run first but write only C+30/C+34/C+38). Full solve (flag=1, unbounded 502770) iff
// byte [F+278C]!=0 and dword [F+2788]==0. R1 (0x617510) entries are commands built (an upper bound of their 576B30 runs: the
// byte [[C+18]+8C] gate is not readable at entry). route_units = units with >=1 R2 gate entry that reaches 576B30 (exact).
// Per-unit preparation/formation calls are unconditional in 0x581F30, so their call counts equal units and are not stored.
//
// Per unit occurrence: cost = QPC of the clone call alone; every own read, bracket and bookkeeping QPC is subtracted and reported
// as observer_us. Per tick (TickEnd, owner thread, from the tick trace writer): storm tick = site-18 us > 3 x the running median of
// the previous 256 routed ticks that ran site 18 (no storm is declared before 16 samples exist); the ring is updated afterwards.
// Trace slots 110/111 of the tick log carry four per-tick words (kntwr_runtime.h KNTWR_TRACE_SITES).
//
// Row layout (kntwr_status::army_storm_words, KNTWR_ARMY_STORM_WORDS == 128): header 12 words, storm aggregate 14, non-storm
// aggregate 14, top-8 storm-tick table of 11 words each (largest site-18 us first). Aggregate word 0 is the largest single-unit us of that class of ticks (storm ticks = header storm_ticks; calm ticks are only roughly ticks - storm_ticks, because routed menu/loading ticks where site 18 never ran are in header ticks but not in the calm aggregate; exact per-tick counts live in the tick log; global max = max of the two). Header/aggregate/entry word meanings are the
// Word / AggWord / EntryWord enums below. units/unit_us/route totals are the storm + non-storm sums (not repeated in the header).
// Left out (word budget / unproven): per-unit member/command-count changes, R1 inclusive us, formation/prep call counts.
#define KNTWR_ARMY_STORM_LABELS \
 "version", "enabled", "ticks", "storm_ticks", \
 "median_site18_us", "storm_factor", "observer_us", "unreadable", \
 "sample_threshold_ms", "sample_admitted", "sample_rejected", "route_outside", \
 "storm_max_unit_us", "storm_units", "storm_route_units", "storm_route_us", \
 "storm_unit_us", "storm_sum_max_unit_us", "storm_units_ge5ms", "storm_units_ge1ms", \
 "storm_prep_us", "storm_fsm_us", "storm_fsm_calls", "storm_formation_us", \
 "storm_r2_us", "storm_r1_entries", "calm_max_unit_us", "calm_units", \
 "calm_route_units", "calm_route_us", "calm_unit_us", "calm_sum_max_unit_us", \
 "calm_units_ge5ms", "calm_units_ge1ms", "calm_prep_us", "calm_fsm_us", \
 "calm_fsm_calls", "calm_formation_us", "calm_r2_us", "calm_r1_entries", \
 "top0_tick", "top0_site18_us", "top0_site34_us", "top0_units_route_units", \
 "top0_max_unit_us", "top0_max_ord_side", "top0_prep_us", "top0_fsm_us", \
 "top0_formation_us", "top0_r2_us", "top0_ge5ms_r2full_r1entries", "top1_tick", \
 "top1_site18_us", "top1_site34_us", "top1_units_route_units", "top1_max_unit_us", \
 "top1_max_ord_side", "top1_prep_us", "top1_fsm_us", "top1_formation_us", \
 "top1_r2_us", "top1_ge5ms_r2full_r1entries", "top2_tick", "top2_site18_us", \
 "top2_site34_us", "top2_units_route_units", "top2_max_unit_us", "top2_max_ord_side", \
 "top2_prep_us", "top2_fsm_us", "top2_formation_us", "top2_r2_us", \
 "top2_ge5ms_r2full_r1entries", "top3_tick", "top3_site18_us", "top3_site34_us", \
 "top3_units_route_units", "top3_max_unit_us", "top3_max_ord_side", "top3_prep_us", \
 "top3_fsm_us", "top3_formation_us", "top3_r2_us", "top3_ge5ms_r2full_r1entries", \
 "top4_tick", "top4_site18_us", "top4_site34_us", "top4_units_route_units", \
 "top4_max_unit_us", "top4_max_ord_side", "top4_prep_us", "top4_fsm_us", \
 "top4_formation_us", "top4_r2_us", "top4_ge5ms_r2full_r1entries", "top5_tick", \
 "top5_site18_us", "top5_site34_us", "top5_units_route_units", "top5_max_unit_us", \
 "top5_max_ord_side", "top5_prep_us", "top5_fsm_us", "top5_formation_us", \
 "top5_r2_us", "top5_ge5ms_r2full_r1entries", "top6_tick", "top6_site18_us", \
 "top6_site34_us", "top6_units_route_units", "top6_max_unit_us", "top6_max_ord_side", \
 "top6_prep_us", "top6_fsm_us", "top6_formation_us", "top6_r2_us", \
 "top6_ge5ms_r2full_r1entries", "top7_tick", "top7_site18_us", "top7_site34_us", \
 "top7_units_route_units", "top7_max_unit_us", "top7_max_ord_side", "top7_prep_us", \
 "top7_fsm_us", "top7_formation_us", "top7_r2_us", "top7_ge5ms_r2full_r1entries"
#ifdef __cplusplus
namespace kntwr_region { struct Table; }
namespace kntwr_army_storm {
using U = uint32_t;
constexpr U kVersion = 1;
constexpr U kStormFactor = 3;     // storm tick: site-18 us > kStormFactor x running median
constexpr U kRing = 256;          // median ring (routed ticks that ran site 18)
constexpr U kWarmup = 16;         // minimum ring samples before a tick can be classified a storm
constexpr U kTop = 8;             // top storm ticks kept
constexpr U kAggregates = 2, kAggWords = 14, kEntryWords = 11;
constexpr U kBig = 5000, kMid = 1000; // units_ge5ms / units_ge1ms thresholds, us
enum Bracket : U { BPrep, BFsm, BFormation, kBrackets };
enum Word : U {
    Version, Enabled, Ticks, StormTicks, MedianSite18Us, StormFactor, ObserverUs, Unreadable, SampleThresholdMs,
    SampleAdmitted, SampleRejected, RouteOutside, // RouteOutside: R2/R1 gate entries outside a unit occurrence (other callers)
    StormAggregate = 12, CalmAggregate = StormAggregate + kAggWords, // kAggWords each, see AggWord
    TopTable = CalmAggregate + kAggWords,                            // kTop x kEntryWords, see EntryWord
    WordCount = TopTable + kTop * kEntryWords
};
enum AggWord : U {
    AMaxUnitUs, AUnits, ARouteUnits, ARouteUs, AUnitUs, ASumMaxUnitUs, AUnitsGe5ms, AUnitsGe1ms,
    APrepUs, AFsmUs, AFsmCalls, AFormationUs, AR2Us, AR1Entries
};
// Table entry: units | route_units << 16; max_unit_ordinal | max_unit_side << 16; counts: units_ge5ms bits 0..9 |
// r2_full_solves bits 10..19 | r1_entries bits 20..29 (each saturating at 1023). r2_us = inclusive us inside 0x581AE0 gate entries
// (all of them, reaching or not). max_unit_side: 0xFFFF unproven; else bit 15 = alliance equals H+2378 (candidate local-player
// alliance [I], unconfirmed), bits 8..14 = alliance index (array H+88, H = ECX of the site-2 ARMIES call), bits 0..7 = army ordinal
// (array X+24 of that alliance X).
enum EntryWord : U {
    ETick, ESite18Us, ESite34Us, EUnitsRoute, EMaxUnitUs, EMaxOrdSide, EPrepUs, EFsmUs, EFormationUs, ER2Us, ECounts
};
static_assert(WordCount == 128 && TopTable == 40 && kEntryWords == 11 && kTop == 8, "army storm status row geometry (KNTWR_ARMY_STORM_WORDS)");
constexpr U kWords = WordCount;
constexpr U kSideUnproven = 0xFFFFu;

struct Binding {
    U image_base;  // relocation of the preferred-base image
    U sample_ms;   // storm-gated sampler threshold (reported only; the profile gate enforces it)
};
bool Start(const Binding& binding); // allocates the module storage; false leaves it off
void Stop();
void Reset();
bool Started();
using Native = U (__fastcall*)(void*);
// Tick owner inside a routed epoch: wraps one 0x581F30 occurrence (main or alternate list); always runs `native` exactly once and
// returns its EAX. `root` is H (ECX of the tick's site-2 ARMIES call, 0 unknown). Re-entrant or unstarted calls run the native
// directly.
U Unit(void* unit, U root, Native native);
// Tick owner, inside a Unit occurrence: the route gates. Route2 wraps 0x581AE0 (ECX = C, plain ret), Route1 wraps 0x617510 (ECX =
// state, EDX unused, one stack argument, ret 4); each runs `native` exactly once.
U Route2(void* command, Native native);
using Native3 = U (__fastcall*)(void*, void*, U);
U Route1(void* state, void* edx, U arg, Native3 native);
// Tick owner, inside a Unit occurrence: inclusive QPC bracket of one ECX-only callee of the ARMY_UNIT clone; runs `native` once.
U Call(Bracket which, void* ecx, Native native);
// Tick owner, tick trace writer: closes the tick (classification, aggregates, top table) and returns the four trace words
// {site_us[110], site_calls[110], site_us[111], site_calls[111]}. site18_us/site34_us are the tick's timed-site totals.
void TickEnd(U tick, U site18Us, U site34Us, U out[4]);
// Copies the row; the sampler counters (profile gate admissions/rejections) come from the profile module.
void Snapshot(U* words /*[kWords]*/, U sampleAdmitted, U sampleRejected);
} // namespace kntwr_army_storm
#endif
