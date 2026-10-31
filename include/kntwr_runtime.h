#ifndef KNTWR_RUNTIME_H
#define KNTWR_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KNTWR_ABI 2u
#define KNTWR_PATH 0x01u
#define KNTWR_FORMATION 0x02u
#define KNTWR_BALLISTICS 0x04u
#define KNTWR_AI_ASYNC 0x08u /* Whole native planner calls run in a single worker slot and join before site 34 returns. */
#define KNTWR_BATCH64 0x10u
#define KNTWR_PROFILE 0x20u /* Opt-in instrumentation and statistical sampler (--profile); outside KNTWR_ALL. Tick logging is independent. */
#define KNTWR_BRAIN 0x40u /* Opt-in, requires KNTWR_PROFILE: times every level-1 callee of the per-agent brain step per class family (see brain_words). Not part of KNTWR_ALL. */
#define KNTWR_BRAIN2 0x80u /* Opt-in BRAIN2 v2: owner-ordered observation or serial gated clones at site 6 (Stage 1); with KNTWR_BRAIN_PARALLEL (+census) the per-soldier step also runs speculatively on pool workers over private receiver copies with guarded owner-ordered commit (Stage 2). Outside KNTWR_ALL. */
#define KNTWR_VISUAL 0x100u /* Main-thread 0x779E60 loop-1 sharding; part of the shipping set. */
#define KNTWR_COLLIDE 0x200u /* Phase B soft-collision solver; part of the shipping set KNTWR_ALL (with contact workers by launcher default). */
#define KNTWR_COLLIDE_LOD 0x400u /* Opt-in half-rate far-unit queries; incompatible with COLLIDE and FORMATION. */
#define KNTWR_AI_CTRL 0x800u /* Experimental controller offload with an immediate completion barrier; requires AI_ASYNC. */
#define KNTWR_AI_BUDGET_EMA 0x1000u /* Reserved retired bit; configurations requesting it are rejected. */
#define KNTWR_AI_SAFE_PARK 0x2000u /* Reserved retired bit; configurations requesting it are rejected. */
#define KNTWR_LOCO 0x4000u /* Locomotion Stages A/B/C (timed site 13 = 0x531AF0); part of the shipping set KNTWR_ALL. Refuses BRAIN and COLLIDE_LOD. Coexists with owner-serial BRAIN2. COLLIDE requires CLONE, PARALLEL, OWNED_SERVICES and GRID (or GRID_VERIFY). */
#define KNTWR_GRID_CENSUS 0x8000u /* Opt-in reader edge counts and sampled occupancy; requires LOCO and a main thread id, not PROFILE. */
#define KNTWR_AI_CENSUS 0x10000u /* Opt-in observation of who mutates/destroys the AI planner object graph (ai_census_words): pinned vtable-slot gates, one clone-call gate and sampler ranges. Requires AI_ASYNC and a main thread id; outside KNTWR_ALL. */
#define KNTWR_AI_CENSUS_WORDS 768u /* 16 header + 7 targets * (8 + 8 callers * 12) + 3 sample ranges * 8; layout: src/ai/kntwr_ai_census.h */
#define KNTWR_AI_ASYNC2 0x20000u /* Opt-in experimental async think, boundary schedule (ai_async2_words, ai_async2_route_words): site 34 queues the whole planner call and returns; tick end publishes the batch; the AI worker runs it in the inter-tick window through its private walk/observer clone family; the next tick start is a blocking lifetime join (no think crosses into a tick); structural writers join (site 33 controller, TICK 57DFDF quadtree update, delegate replacement/destructor and observer/operation owner-destructor vtable slots; a non-tick owner teardown drains the whole batch first); worker calls of those slots and of 0x83FD00 are marshalled; stop drains before routing ends (servicing or aborting a pending marshal); 5 s watchdog with sticky synchronous fallback. Requires AI_ASYNC; refuses AI_CTRL and AI_CENSUS (same slots/site 33); outside KNTWR_ALL. */
#define KNTWR_AI_ASYNC2_WORDS 96u /* layout: src/ai/kntwr_ai_async2.h, labels KNTWR_AI_ASYNC2_LABELS */
#define KNTWR_AI_ASYNC2_ROUTE_WORDS 65u /* ai_async2_route_words; layout src/ai/kntwr_ai_async2.h (RouteWord), labels KNTWR_AI_ASYNC2_ROUTE_LABELS */
#define KNTWR_ARMY_UNIT_SHADOW 0x40000u /* Opt-in --army-unit-shadow: item 4 Stage A, instrumentation only. Site 18 (ARMY_UPDATE clone) and its 0x581F30 calls (sites 101/103) are bound to owner-thread gates that time each unit update, classify it under the approved compromises (owner-only reasons, RNG draws, foreign-unit witness, command-class census) and measure a frozen-view copy; the native calls run unchanged. Requires a routed tick (PROFILE or a simulation feature); planner writes are measured only with AI_CENSUS. Outside KNTWR_ALL. Words: army_unit_words, src/army/native_army_unit.h. */
#define KNTWR_ARMY_UNIT_WORDS 192u /* army_unit_words; layout src/army/native_army_unit.h (Word), labels KNTWR_ARMY_UNIT_*_LABELS */
/* Mask bit 0x80000u is retired (former puppet probe, removed); KNTWR_VALID_MASK refuses it and it is never reused. */
#define KNTWR_CAVALRY_ORBIT 0x100000u /* Launcher default alongside KNTWR_ALL; --cavalry-orbit adds it to an explicit feature list (enabled_mask only, not part of KNTWR_ALL): both-side cavalry orbit an attack-ordered square with small rider melee waves and native eligible mounted fire. Routes its own tick. Refuses KNTWR_AI_ASYNC2 and KNTWR_BRAIN2: requires the original driver callsite and joined owner epoch, not cloned drivers or speculative receivers. ABI 2, 64-byte config unchanged; no new logging/status row. See src/army/native_cavalry_runtime.h. */
#define KNTWR_VA_WATCH_WORDS 64u /* va_watch_words: process VA watch (former puppet probe row, same size/offset); layout KNTWR_VA_* below */
#define KNTWR_VA_WATCH 0x1u /* kntwr_config::va_watch_flags bit (launcher --va-watch): enable the VA watch sampler; default off, nothing is sampled or written without it */
#define KNTWR_ARMY_STORM_CENSUS 0x2u /* kntwr_config::va_watch_flags bit (launcher --army-storm-census): opt-in site-18 storm census (src/army/native_army_storm.h): sites 101/103 (0x581F30 calls) are bound to owner-thread gates that time each unit update, read cheap route evidence, and publish the army_storm_words row plus trace slots 110/111 (see KNTWR_TRACE_SITES); nothing changes when clear. Requires a routed tick (KNTWR_PROFILE or a simulation feature) and main_thread_id; exclusive with KNTWR_ARMY_UNIT_SHADOW. */
#define KNTWR_ARMY_STORM_SAMPLE_SHIFT 8u
#define KNTWR_ARMY_STORM_SAMPLE_MASK 0xFF00u /* bits 8..15: storm-gated sampler threshold in ms (launcher --army-storm-sample-ms, 1..255); 0: sampler unchanged. Requires KNTWR_PROFILE and profile_site 19 (site 18, with KNTWR_ARMY_STORM_CENSUS) or 35 (site 34, without KNTWR_AI_ASYNC): the profile gate then admits a sample only while the selected site has been in progress for at least this long. */
#define KNTWR_TICK_PCORE 0x4u /* kntwr_config::va_watch_flags bit (launcher --tick-pcore): on a hybrid CPU the thread that executes a routed tick gets a hard affinity to the highest-efficiency-class (P) logical processors for the tick body; its previous affinity is restored before the gate returns. Placement only: no engine state, order or result changes. Requires a routed tick (KNTWR_PROFILE or a simulation feature); inert (no pin, no error) on a non-hybrid host, when the CPU-set read is partial (any entry in another processor group or at logical processor >= 32: this 32-bit process can only address a 32-bit group-0 mask), when the usable P mask (highest class and process affinity) is empty or has fewer than 4 logical processors. Exclusive with KNTWR_TICK_CORE_AB. */
#define KNTWR_TICK_CORE_AB 0x8u /* kntwr_config::va_watch_flags bit (launcher --tick-core-ab): measurement only. Like KNTWR_TICK_PCORE, but even model ticks are pinned to P and odd model ticks to E logical processors, so neighbouring ticks give an in-run E-core penalty. Requires a routed tick; exclusive with KNTWR_TICK_PCORE. */
#define KNTWR_VA_FLOOR_UNIT_MIB 32u
#define KNTWR_VA_FLOOR_SHIFT 22u
#define KNTWR_VA_FLOOR_MASK (0x1Fu << KNTWR_VA_FLOOR_SHIFT) /* bits 22..26: total free VA floor in 32 MiB units (launcher --va-floor-mib 64..1024; 0 = default 256 MiB, encoded 2..16 => 64..512 MiB, 17 = 1024 MiB) */
#define KNTWR_VA_HOLE_SHIFT 27u
#define KNTWR_VA_HOLE_MASK (0x1Fu << KNTWR_VA_HOLE_SHIFT) /* bits 27..31: largest free hole floor in 32 MiB units (launcher --va-hole-mib 32..512; 0 = default 128 MiB, encoded 1..16 => 32..512 MiB) */
#define KNTWR_VA_WATCH_FLAGS_VALID (KNTWR_VA_WATCH | KNTWR_ARMY_STORM_CENSUS | KNTWR_ARMY_STORM_SAMPLE_MASK | KNTWR_TICK_PCORE | KNTWR_TICK_CORE_AB | KNTWR_ARMY_SOLVER_MEMO | KNTWR_ARMY_SOLVER_SHADOW | KNTWR_ALLOC_CENSUS | KNTWR_ARENA_RELEASE | KNTWR_HEAP_OPTIMIZE | KNTWR_ALLOC_FIX | KNTWR_MOUNTED_OFFICER | KNTWR_MOUNTED_OFFICER_WIDEN | KNTWR_ENGAGE_CENSUS | KNTWR_FORMATION_CENSUS | KNTWR_VA_FLOOR_MASK | KNTWR_VA_HOLE_MASK)
#define KNTWR_ARMY_SOLVER_MEMO 0x10u /* kntwr_config::va_watch_flags bit (launcher --army-solver-memo): bit-exact memoised flag=1 formation slot solver (src/army/native_army_solver.h). Inside a routed tick on the tick owner the R1/R2 assignment-command slots 0x1331E74 / 0x1332110 / 0x1325474 run a dedicated SOLVER clone chain whose 0x502770 calls (18F12AA and the 18F0D00 trampoline path) enter ntw_solver::Solve instead of the native pair-swap solver; any out-of-contract input falls back to the native solver. Entries, EAX and the allocator call sequence are bit-identical to native. Requires a routed tick (a kManagerRouted feature such as KNTWR_PROFILE) and main_thread_id; exclusive with KNTWR_ARMY_SOLVER_SHADOW; compatible with KNTWR_ARMY_STORM_CENSUS. */
#define KNTWR_ARMY_SOLVER_SHADOW 0x20u /* kntwr_config::va_watch_flags bit (launcher --army-solver-shadow): same chain, but the NATIVE 0x502770 stays authoritative; the kernel re-solves a pre-call copy and the result (entries bytes, EAX) is compared and counted; native/kernel inclusive times are recorded per solve. Same requirements as KNTWR_ARMY_SOLVER_MEMO; exclusive with it. */
#define KNTWR_ALLOC_CENSUS 0x40u /* kntwr_config::va_watch_flags bit (launcher --alloc-census): opt-in process-heap allocation callsite census (alloc_census_words, src/core/kntwr_alloc_census.*). */
#define KNTWR_ARENA_RELEASE 0x80u /* kntwr_config::va_watch_flags bit (launcher --arena-release; implied by --features all unless --no-arena-release): pose/scene 1 MB arena release at battle teardown + 600-frame high-water tail trim (arena_words, src/render/kntwr_arena_release.*). */
#define KNTWR_HEAP_OPTIMIZE 0x10000u /* kntwr_config::va_watch_flags bit (launcher --heap-optimize, opt-in): HeapOptimizeResources on GetProcessHeap + Provider[0..2] at battle teardown and <640 MiB low-VA watermark (when set without KNTWR_VA_WATCH, the monitor thread samples GlobalMemoryStatusEx at 1 Hz without a VirtualQuery walk or ring publication; arena_words). */
#define KNTWR_MOUNTED_OFFICER 0x20000u /* kntwr_config::va_watch_flags bit (launcher --mounted-officer, GAMEPLAY feature, implied by --features all unless --no-mounted-officer): a unit that has no mounts of its own ([unit+0x34]==0) but whose mount references were resolved from its unit_stats_land row (mount_model [unit+0x88], mount_entity [unit+0x8C], mount_animations_table &unit+0x90) gets exactly one mount agent for its officer (men[0]). Installed by redirecting the single call 0x531340 -> unit constructor 0x51B7D0 to CLONE_UNIT_CTOR (the constructor with a gate inserted at its mount-loop test 0x51C22E), at monitor start (before any battle loads) and restored at stop. Words: mounted_officer_words, src/army/kntwr_mounted_officer.h. */
#define KNTWR_MOUNTED_OFFICER_WIDEN 0x40000u /* kntwr_config::va_watch_flags bit (launcher --mounted-officer-widen): the officer's mount also raises the unit radius [unit+0x2EC] (MAXSS with [mount+0x58]) exactly like a stock cavalry mount, widening the unit's spacing; without it the infantry spacing is kept. Requires KNTWR_MOUNTED_OFFICER. */
#define KNTWR_ALLOC_FIX 0x200000u /* kntwr_config::va_watch_flags bit (launcher --alloc-fix; implied by --features all unless --no-alloc-fix): pathfinder +0x17C waypoint subnode leak reclamation (alloc_census_words mode 2 alone, mode 3 with KNTWR_ALLOC_CENSUS; 0 B table and 0 Provider vtable hooks when KNTWR_ALLOC_CENSUS is clear). */
#define KNTWR_ENGAGE_CENSUS 0x80000u /* kntwr_config::va_watch_flags bit (launcher --engage-census, opt-in READ-ONLY diagnostic, NEVER implied by --features all): after every routed native tick the tick owner reads the AI units' positions, calls the native is_moving/is_firing/missile-range predicates (0x55C320/0x55AFE0/0x5646A0) and records how deep AI infantry walk into their own missile range before they halt or start firing (engage_census_words, src/ai/kntwr_engage_census.h). Requires a routed tick (KNTWR_PROFILE or a simulation feature). No engine write. */
#define KNTWR_FORMATION_CENSUS 0x100000u /* kntwr_config::va_watch_flags bit (launcher --formation-census[=EVERY] --formation-census-csv FILE, opt-in READ-ONLY diagnostic, NEVER implied by --features all): every EVERY model ticks (default 30) after the routed native tick the tick owner measures, for every live unit of both alliances, the men's centroid / RMS spread against the spread of the formation's slot positions (the engine's own slot generator is called on the active 0x581200-class command) and writes one CSV row per unit plus <csv>.summary.txt with the collapse counts (src/formation/kntwr_formation_census.h). The CSV path and period travel in the game's environment (KNTWR_FORMATION_CENSUS_CSV / _EVERY), not in the config. Requires a routed tick (KNTWR_PROFILE or a simulation feature). No engine write. */
#define KNTWR_ARMY_STORM_WORDS 128u /* army_storm_words: site-18 storm census row (former retired puppet motion/divert/mover/select rows, same offset); layout src/army/native_army_storm.h, labels KNTWR_ARMY_STORM_LABELS */
/* VA watch (opt-in, --va-watch; monitor thread, every second in every phase incl. WAITING_BATTLE/loading):
   GlobalMemoryStatusEx avail virtual plus a VirtualQuery walk of the whole user space. Header 16 words, then a ring of
   KNTWR_VA_RING_ENTRIES samples x 4 words (uptime s, avail MiB, largest free region MiB, phase). Written by the monitor,
   read via the status sequence; the launcher prints the ring after a crash so the VA curve before a load crash is
   recoverable. Diagnostic only: never touches engine state, never active in a plain launch. */
#define KNTWR_VA_RING_ENTRIES 12u
#define KNTWR_VA_RING_WORDS 4u
enum kntwr_va_word {
    KNTWR_VA_VERSION, KNTWR_VA_SAMPLES, KNTWR_VA_AVAIL_LO, KNTWR_VA_AVAIL_HI, KNTWR_VA_MIN_AVAIL_LO, KNTWR_VA_MIN_AVAIL_HI,
    KNTWR_VA_LARGEST_FREE, KNTWR_VA_MIN_LARGEST_FREE, KNTWR_VA_FREE_REGIONS, KNTWR_VA_RESERVED_MIB, KNTWR_VA_COMMITTED_MIB,
    KNTWR_VA_IMAGE_MIB, KNTWR_VA_MAPPED_MIB, KNTWR_VA_MIN_PHASE, KNTWR_VA_MIN_UPTIME_S, KNTWR_VA_RING_NEXT,
    KNTWR_VA_RING_BASE /* = 16 */
};
#define KNTWR_ARMY_B0_WORDS 160u /* army_b0_words (KNTWR_ARMY_UNIT_SHADOW, Stage B0 qualification); layout src/army/native_army_unit.h (B0Word), labels KNTWR_ARMY_B0_LABELS */
#define KNTWR_BRAIN_S0_WORDS 560u /* brain_s0_words (KNTWR_BRAIN_S0 attribution timer); layout src/brain2/native_brain_s0.h (Word/RowWord), labels KNTWR_BRAIN_S0_HEADER_LABELS / KNTWR_BRAIN_S0_ROW_LABELS / KNTWR_BRAIN_S0_ROW_WORD_LABELS */
#define KNTWR_LOCO_CLONE 0x1u /* kntwr_config::loco_flags bit (launcher --loco-clone): execute admitted movement occurrences through the private LOCO clone family instead of the original code; requires KNTWR_LOCO. */
#define KNTWR_LOCO_PARALLEL 0x2u /* kntwr_config::loco_flags bit (launcher --loco-parallel): closed movement workers; requires KNTWR_LOCO and KNTWR_LOCO_CLONE. Requested grid/CSR workers also run without this bit. */
#define KNTWR_LOCO_SHADOW 0x4u /* Owner-thread sweep/resolve oracle; requires LOCO_CLONE. */
#define KNTWR_LOCO_OWNED_SERVICES 0x8u /* Opt-in supported active mover path (launcher --loco-owned-services): owner-prepared sweep/resolve/environment services replayed from worker-private state; requires KNTWR_LOCO, LOCO_CLONE and LOCO_PARALLEL. Unsupported occurrences fall back to the owner before any irreversible write. */
#define KNTWR_LOCO_QUIET 0x10u /* Low-overhead owned mode (launcher --loco-quiet): disables per-service QPC timing, owner shadow comparisons (even with KNTWR_LOCO_SHADOW) and the all-gates histogram; faults, share and detail counters stay. Requires KNTWR_LOCO_OWNED_SERVICES (thus PARALLEL, CLONE and LOCO). */
#define KNTWR_LOCO_GRID 0x20u /* Optional owned soldier grid v2 published at site-13 exit (launcher --loco-grid); requires KNTWR_LOCO. Default off; combined COLLIDE borrows the published view without rebuilding. */
#define KNTWR_LOCO_GRID_VERIFY 0x40u /* Launcher --loco-grid-verify: implies GRID and enables owner-side grid verification; requires KNTWR_LOCO. */
#define KNTWR_LOCO_GRID_PROBATION 0x80u /* kntwr_config::loco_flags bit (launcher --grid-probation): relink-retirement detector. Requires KNTWR_LOCO and KNTWR_LOCO_GRID (or GRID_VERIFY); refused with KNTWR_BALLISTICS (its query cache walks the heads in runtime code). Native chains stay dual-written; the model+A4 cell-head array is PAGE_NOACCESS outside the owner site-13 relink window; a first-chance vectored handler logs the trapping instruction/caller/thread/site, restores the page and resumes. Words: grid_probation_words, src/loco/native_grid_probation.h. */
#define KNTWR_LOCO_RELINK_SHADOW 0x200u /* kntwr_config::loco_flags bit (launcher --loco-relink-shadow): cell-partitioned relink apply in shadow. The native serial 0x811ED0/0x7EFA80 services still run; every site-13 batch is also applied by the parallel kernel to a private mirror and compared (loco_relink_words). Requires KNTWR_LOCO_OWNED_SERVICES and KNTWR_LOCO_GRID (or GRID_VERIFY); exclusive with KNTWR_LOCO_RELINK_WORKERS; Zero gameplay effect. */
#define KNTWR_LOCO_RELINK_WORKERS 0x400u /* kntwr_config::loco_flags bit (launcher --loco-relink-workers): live cell-partitioned relink apply. The op log replaces the native grid services; each batch is applied by the pool at its flush barrier with bit-identical chain order. Same requirements as KNTWR_LOCO_RELINK_SHADOW; exclusive with it. */
#define KNTWR_LOCO_GRID_INCREMENTAL 0x100u /* kntwr_config::loco_flags bit (launcher --loco-grid-incremental): patch the owned grid v2 instead of rebuilding it from scratch. Requires KNTWR_LOCO and KNTWR_LOCO_GRID (or GRID_VERIFY). Every record is re-read; only records whose cell-rectangle inputs changed pay for coverage, node validation and the per-cell delta tally, and the CSR is rebuilt from persistent per-cell counts. Falls back to the full build on the first build, a registry change, a geometry or rounding change, after a refused build, and (with backoff) when more than 35% of the records changed rectangle. Published arrays are bit-identical to the full build. With KNTWR_LOCO_GRID_VERIFY every stage also runs a full rebuild into a shadow store and memcmp's every published array (loco_grid_build_words shadow_compares / shadow_mismatches); costs one grid block of extra memory and two extra, uncounted dispatches per stage. Words: loco_grid_build_words. */
#define KNTWR_LOCO_CW_SHADOW 0x800u /* kntwr_config::loco_flags bit (launcher --loco-cw-shadow): class-wrapper phase 2 in shadow. 0x132BA04 wrappers whose children are all World agents (vtable 0x1333714, no pre-step, state != 9, <= 8 children) are computed on workers with proxy children; the owner still runs the wrapper natively and compares receiver footprint and child relocations (loco_cw_words). Requires KNTWR_LOCO_OWNED_SERVICES; exclusive with KNTWR_LOCO_CW_WORKERS. Zero gameplay effect. */
#define KNTWR_LOCO_CW_WORKERS 0x1000u /* kntwr_config::loco_flags bit (launcher --loco-cw-workers): class-wrapper phase 2 live: the worker result is committed and each child relocation is replayed on the owner through native 0x80BAC0 in ordinal order. Same requirements as KNTWR_LOCO_CW_SHADOW; exclusive with it. */
#define KNTWR_LOCO_FLAGS_VALID (KNTWR_LOCO_CLONE | KNTWR_LOCO_PARALLEL | KNTWR_LOCO_SHADOW | KNTWR_LOCO_OWNED_SERVICES | KNTWR_LOCO_QUIET | KNTWR_LOCO_GRID | KNTWR_LOCO_GRID_VERIFY | KNTWR_LOCO_GRID_PROBATION | KNTWR_LOCO_GRID_INCREMENTAL | KNTWR_LOCO_RELINK_SHADOW | KNTWR_LOCO_RELINK_WORKERS | KNTWR_LOCO_CW_SHADOW | KNTWR_LOCO_CW_WORKERS)
/* Brain profiling geometry (see kntwr_status::brain_words). Families, in entry-site order 46..50:
   0 slot +0x0C = 0x66CE00 (11 vtables), 1 = 0x6F50F0 thunk (1), 2 = 0x6F4660 wrapper (6), 3 = 0x602EB0 wrapper (1), 4 = 0x5FCEB0 wrapper (4). */
#define KNTWR_BRAIN_FAMILIES 5u
#define KNTWR_BRAIN_SITE_FIRST 46u
#define KNTWR_BRAIN_SITES 49u        /* trace sites 46..94 */
#define KNTWR_BRAIN_HEADER_WORDS 8u
#define KNTWR_BRAIN_WORDS 512u
#define KNTWR_BRAIN_SLOTS 23u        /* registry vtables whose slot +0x0C is published while KNTWR_BRAIN is armed */
#define KNTWR_BRAIN_STATE_BUCKETS 64u
#define KNTWR_BRAIN_SUBSTATE_BUCKETS 80u
#define KNTWR_BRAIN_STATE_COUNTS 16u
#define KNTWR_BRAIN_SUBSTATE_COUNTS 80u
#define KNTWR_BRAIN_TRANSITION_COUNTS 160u
#define KNTWR_BRAIN_TRANSITION_UNITS 224u
#define KNTWR_BRAIN_STATE_WORDS 288u
#define KNTWR_COLLISION_WORDS 32u
#define KNTWR_COLLIDE_WORDS 61u
#define KNTWR_BRAIN2_WORDS 48u
#define KNTWR_BRAIN2_VERSION 2u
#define KNTWR_BRAIN_CENSUS 0x1u /* Serial gated clone and per-service activity bookkeeping; --brain-census. */
#define KNTWR_BRAIN_TIMING 0x2u /* QPC original/serial-clone measurement; --brain-timing. Off by default. */
#define KNTWR_BRAIN_NODE_SHADOW 0x4u /* Owner-only reference-node differential execution; implies gated census. */
#define KNTWR_BRAIN_FIRE_SHADOW 0x8u /* Owner-only request-sequencer differential execution; implies gated census. */
#define KNTWR_BRAIN_PARALLEL 0x10u /* Stage 2 (--brain-parallel): per-soldier brain step on pool workers over private receiver copies, owner-ordered guarded commit; requires BRAIN2 and KNTWR_BRAIN_CENSUS or KNTWR_BRAIN_QUIET. Words: brain_worker_words / brain_worker_phase_words, src/brain2/native_brain_workers.h. */
#define KNTWR_BRAIN_FINALIZER_SHADOW 0x20u /* --brain-finalizer-shadow: owner-only private-copy rerun of proved 0x819770 calls, bit-exact compare; implies gated census. Words: brain2_unknown_site_words witness 21..23 (native_brain2.h). */
#define KNTWR_BRAIN_QUIET 0x40u /* --brain-quiet: the performance configuration of KNTWR_BRAIN_PARALLEL (required). Owner-run occurrences execute the ORIGINAL step (no serial gated census clone, no per-service bookkeeping, no first-unresolved histograms, no QPC per service); workers keep their classification gates and the guarded commit; guard misses are counted without block checksums. Excludes KNTWR_BRAIN_CENSUS, TIMING and every shadow flag. Phase telemetry: brain_worker_phase_words. */
#define KNTWR_BRAIN_UNIT_SHADOW 0x80u /* --brain-unit-shadow: per-unit brain Stage A, shadow only. Before the unchanged site-6 loop, pool workers compute one UnitDecision per unit from unit-level inputs (no writes); after each soldier's native step the owner compares the fields it decided against its unit's decision. Requires BRAIN2; excludes KNTWR_BRAIN_PARALLEL/QUIET. Words: brain_unit_words, src/brain2/native_unit_brain.h. */
#define KNTWR_BRAIN_S0 0x100u /* --brain-s0: diagnostics-only S0 attribution timer (analysis/native-unit-compromise-plan.md 5.3). Each occurrence's step runs through the BRAIN_S0 clone family whose candidate decision calls (target, drivers, node begin/step, finalizer, order, lookups, stance, path/posture/next-state, fatigue selector, timer/providers) reach counting gates; deterministic 1/64 occurrences are timed with serialized RDTSCP (gate overhead calibrated at start and subtracted). Native work runs exactly once, unchanged; no game-state write (unless combined with the unit bits 0x200..0x4000, whose applies the S0 gates then route to and time). Requires BRAIN2; excludes every other KNTWR_BRAIN_* flag except those unit bits. Words: brain_s0_words, src/brain2/native_brain_s0.h. */
#define KNTWR_BRAIN_UNIT_FATIGUE 0x200u /* --brain-unit-fatigue: S4 per-unit fatigue pair (src/brain2/native_unit_fatigue.h); the KNTWR_BIND_U_FATIGUE gate applies the unit's (acc, level) to A+370/+374 of admitted units instead of running 0x670F40. Unit bits require BRAIN2; exclude CENSUS/TIMING/NODE/FIRE/FINALIZER shadows, PARALLEL, QUIET and UNIT_SHADOW; combine with each other and with KNTWR_BRAIN_S0. Words: brain_unit_policy_words (header 0..31, fatigue 32..127). */
#define KNTWR_BRAIN_UNIT_FATIGUE_SHADOW 0x400u /* --brain-unit-fatigue-shadow (sets 0x200|0x400): the unit pair is decided and compared with the native pair of every admitted man; native results stay. */
#define KNTWR_BRAIN_UNIT_POSTURE 0x800u /* --brain-unit-posture: S2b per-unit posture (src/brain2/native_unit_posture_engage.h). */
#define KNTWR_BRAIN_UNIT_POSTURE_SHADOW 0x1000u /* --brain-unit-posture-shadow (sets 0x800|0x1000). */
#define KNTWR_BRAIN_UNIT_ENGAGE 0x2000u /* --brain-unit-engage: S1c/S3 engage + fire latches, S1a/S2a lookups (src/brain2/native_unit_posture_engage.h). */
#define KNTWR_BRAIN_UNIT_ENGAGE_SHADOW 0x4000u /* --brain-unit-engage-shadow (sets 0x2000|0x4000). */
#define KNTWR_BRAIN_LOCALITY 0x8000u /* --brain-locality: diagnostics-only site-6 locality census (src/brain2/native_brain_locality.h, analysis/checkpoints/BrainLocality.md). The per-man step still runs the ORIGINAL vt+0C entry exactly once per occurrence; the owner-thread runner only loads entity fields (after the step), derives hot cache-line sets from the static load map and brackets a deterministic 1/16 stratum with serialized RDTSCP. Never writes game memory. Requires BRAIN2; excludes every other KNTWR_BRAIN_* flag (including KNTWR_BRAIN_S0, whose status row it reuses) except the locality modifier bits below. Words: brain_s0_words (the S0 row, which is empty while S0 is off). */
#define KNTWR_BRAIN_LOCALITY_WARM 0x10000u /* --brain-locality-warm (sets 0x8000|0x10000): on a deterministic half of the timed occurrences every hot line of the occurrence's mapped objects is read-touched (volatile loads, timed separately) before the timed step: cold-vs-warm A/B. Excludes the prefetch bits. */
#define KNTWR_BRAIN_LOCALITY_PREFETCH 0x20000u /* --brain-locality-prefetch (sets 0x8000|0x20000): alternating 64-occurrence blocks issue PREFETCHT0 for the next worklist entity (its entity lines and chain-object lines, distance 1) from the start of each occurrence; B-A = net gain. Excludes the warm and prefetch2 bits. */
#define KNTWR_BRAIN_LOCALITY_PREFETCH2 0x40000u /* --brain-locality-prefetch2 (sets 0x8000|0x40000): as prefetch, but entity lines of the entry two ahead and chain lines of the entry one ahead. Excludes the warm and prefetch bits. */
#define KNTWR_BRAIN_LOCALITY_MARK 0x80000u /* --brain-locality-mark (sets 0x8000|0x80000): pure pass-through runner (no census/touch/TSC; the step is called once) whose stage begin/end emit one manifest-free ETW event each (provider GUID {6e1c4a2b-5d3f-4a7e-9b21-c8f0a3d7e514}, Id 1 begin / Id 2 end, UINT32 stage ordinal; src/brain2/native_brain_locality.h) so a WPR PMC trace can be gated to site-6 windows. Excludes the warm and prefetch bits. */
#define KNTWR_BRAIN_FLAGS_VALID 0xfffffu
#define KNTWR_BRAIN_UNIT_POLICY_WORDS 256u /* brain_unit_policy_words: shared header 0..31 (kntwr_unit_policy), fatigue 32..127 (KNTWR_UNIT_FATIGUE_LABELS), posture/engage 128..255 (KNTWR_UNIT_POSTURE_ENGAGE_LABELS) */
#define KNTWR_BRAIN_UNIT_WORDS 176u
#define KNTWR_BRAIN_WORKER_WORDS 144u
#define KNTWR_BRAIN_WORKER_PHASE_WORDS 40u
#define KNTWR_NODE_WORDS 32u
#define KNTWR_NODE_EVENT_WORDS 16u
#define KNTWR_FIRE_WORDS 24u
#define KNTWR_BRAIN2_ROUTE_WORDS 8u
#define KNTWR_FIRE_COMMIT_WORDS 32u
#define KNTWR_MOVE_NODE_WORDS 32u
#define KNTWR_MOVE_NODE_EVENT_WORDS 16u
#define KNTWR_BRAIN2_NODE_TARGET_WORDS 36u
#define KNTWR_BRAIN2_UNKNOWN_SITE_WORDS 128u /* 2 x (4 + 16 x 3) site tables + 24 witness words; native_brain2.h */
#define KNTWR_IDLE_NODE_CLASSES 2u
#define KNTWR_ACTION_NODE_CLASSES 3u
#define KNTWR_BRAIN2_CENSUS_WORDS 424u /* 53 service rows x 8 words; module enum order. */
#define KNTWR_AI_SLICE_BUDGET_WORDS 8u
#define KNTWR_AI_COMPLETION_WORDS 24u
#define KNTWR_AI_COMPLETION_LABELS \
    "think_count", "think_sum_us", "max_planner_us", "barrier_count", "barrier_sum_us", "max_barrier_us", \
    "think_le8ms", "think_le16ms", "think_le32ms", "think_le64ms", "think_le128ms", \
    "think_le256ms", "think_le512ms", "think_le1024ms", "think_gt1024ms", \
    "barrier_le8ms", "barrier_le16ms", "barrier_le32ms", "barrier_le64ms", "barrier_le128ms", \
    "barrier_le256ms", "barrier_le512ms", "barrier_le1024ms", "barrier_gt1024ms"
#define KNTWR_LOCO_WORDS 48u
#define KNTWR_LOCO_GATE_WORDS 48u
#define KNTWR_LOCO_SERVICE_WORDS 40u
#define KNTWR_LOCO_GRID_WORDS 32u
#define KNTWR_LOCO_PARALLEL_WORDS 32u
#define KNTWR_SWEEP_WORDS 32u
#define KNTWR_RESOLVE_WORDS 32u
#define KNTWR_ENV_WORDS 32u
#define KNTWR_LOCO_OWNED_WORDS 32u
#define KNTWR_LOCO_OWNED_DETAIL_WORDS 16u
#define KNTWR_LOCO_OWNED_PHASE_WORDS 32u
#define KNTWR_LOCO_OWNED_LOAD_WORDS 16u
#define KNTWR_LOCO_GRID_V2_WORDS 16u
#define KNTWR_LOCO_RELINK_WORDS 32u /* loco_relink_words; labels KNTWR_LOCO_RELINK_LABELS in src/loco/native_loco.h */
#define KNTWR_LOCO_CW_WORDS 32u /* loco_cw_words; labels KNTWR_LOCO_CW_LABELS in src/loco/native_loco.h */
#define KNTWR_LOCO_GRID_BUILD_WORDS 16u /* loco_grid_build_words; labels KNTWR_LOCO_GRID_BUILD_LABELS in src/loco/native_loco.h */
#define KNTWR_COLLIDE_SOURCE_WORDS 4u
#define KNTWR_COLLIDE_CONTACT_WORDS 48u /* collide_contact_words; labels/layout KNTWR_COLLIDE_CONTACT_WORD_LABELS in src/collision/native_contact.h */
#define KNTWR_COLLIDE_CONTACT_SHADOW 0x1u /* kntwr_config::collide_flags (launcher --collide-contact-shadow): plan every solver contact callback on pool workers from stage-entry state and compare each plan with the original callback the owner still runs. Requires KNTWR_COLLIDE; excludes KNTWR_COLLIDE_CONTACT_WORKERS. */
#define KNTWR_COLLIDE_CONTACT_WORKERS 0x2u /* collide_flags (--collide-contact-workers): same-team LAND contacts are decided on pool workers; the owner replays their tracker/+0x13C/avoidance effects in contact order, every other contact runs the original callback in place. Requires KNTWR_COLLIDE. */
#define KNTWR_COLLIDE_FLAGS_VALID 0x3u
#define KNTWR_GRID_PROBATION_HEADER_WORDS 32u
#define KNTWR_GRID_PROBATION_CALLERS 256u
#define KNTWR_GRID_PROBATION_WORDS (KNTWR_GRID_PROBATION_HEADER_WORDS + KNTWR_GRID_PROBATION_CALLERS * 8u)
#define KNTWR_GRID_PROBATION_LABELS \
    "version", "enabled", "state", "isolated", "arms", "window_opens", "traps", "cell_traps", \
    "edge_traps", "write_traps", "restore_failures", "foreign_faults", "callers_used", "callers_dropped", \
    "armed_pages", "uncovered_bytes", "array_base", "array_bytes", "allocation_base", "allocation_bytes", \
    "arm_us", "open_us", "max_toggle_us", "layout_changes", "refusals", "traps_tick", "traps_pool", \
    "traps_ai", "traps_main", "traps_other", "probe_arms", "disarms"
#define KNTWR_MEMORY_WORDS 60u
#define KNTWR_MEMORY_MIN_AVAIL_VIRTUAL (256u * 1024u * 1024u)
#define KNTWR_MEMORY_MIN_LARGEST_HOLE (128u * 1024u * 1024u)
#define KNTWR_LATCH_REASON_TOTAL 1u
#define KNTWR_LATCH_REASON_HOLE 2u
#define KNTWR_MEMORY_WORD_LABELS \
    "version", "loco_bytes", "collide_bytes", "profile_bytes", "runtime_image_bytes", "clone_bytes", \
    "pool_stack_bytes", "ai_stack_bytes", "other_stack_bytes", "lod_bytes", "ballistics_bytes", "other_bytes", \
    "total_bytes", "activation_avail_lo", "activation_avail_hi", "post_alloc_avail_lo", "post_alloc_avail_hi", \
    "min_avail_lo", "min_avail_hi", "samples", "budget_refusals", "memory_error", \
    "primary_capacity", "record_capacity", "cell_capacity", "membership_capacity", "pair_capacity", "floor_bytes", \
    "loco_movement_bytes", "loco_grid_bytes", "loco_scene_bytes", "loco_catalog_bytes", "loco_participants_bytes", \
    "loco_sweep_scratch_bytes", "loco_resolve_scratch_bytes", "loco_env_scratch_bytes", \
    "loco_scene_nodes", "loco_scene_owners", "loco_tree_entries", "budget_disabled_mask", "budget_release_pending", \
    "budget_releases", "released_loco_bytes", "released_collide_bytes", \
    "native_grid_shift", "native_grid_maximum", "native_grid_dimension", \
    "loco_catalog_ring_bytes", "loco_catalog_capsule_bytes", "loco_catalog_wall_bytes", \
    "loco_catalog_edge_bytes", "loco_catalog_polygon_bytes", "loco_catalog_rings", \
    "loco_catalog_capsules", "loco_catalog_walls", "loco_catalog_edges", "loco_catalog_polygon_points", \
    "hole_floor_bytes", "min_largest_hole", "latch_reason"
enum kntwr_memory_word {
    KNTWR_MEM_VERSION, KNTWR_MEM_LOCO_BYTES, KNTWR_MEM_COLLIDE_BYTES, KNTWR_MEM_PROFILE_BYTES,
    KNTWR_MEM_RUNTIME_IMAGE_BYTES, KNTWR_MEM_CLONE_BYTES, KNTWR_MEM_POOL_STACK_BYTES, KNTWR_MEM_AI_STACK_BYTES,
    KNTWR_MEM_OTHER_STACK_BYTES, KNTWR_MEM_LOD_BYTES, KNTWR_MEM_BALLISTICS_BYTES, KNTWR_MEM_OTHER_BYTES,
    KNTWR_MEM_TOTAL_BYTES, KNTWR_MEM_ACTIVATION_AVAIL_LO, KNTWR_MEM_ACTIVATION_AVAIL_HI,
    KNTWR_MEM_POST_ALLOC_AVAIL_LO, KNTWR_MEM_POST_ALLOC_AVAIL_HI, KNTWR_MEM_MIN_AVAIL_LO, KNTWR_MEM_MIN_AVAIL_HI,
    KNTWR_MEM_SAMPLES, KNTWR_MEM_BUDGET_REFUSALS, KNTWR_MEM_ERROR, KNTWR_MEM_PRIMARY_CAPACITY,
    KNTWR_MEM_RECORD_CAPACITY, KNTWR_MEM_CELL_CAPACITY, KNTWR_MEM_MEMBERSHIP_CAPACITY,
    KNTWR_MEM_PAIR_CAPACITY, KNTWR_MEM_FLOOR_BYTES,
    KNTWR_MEM_LOCO_MOVEMENT_BYTES, KNTWR_MEM_LOCO_GRID_BYTES, KNTWR_MEM_LOCO_SCENE_BYTES,
    KNTWR_MEM_LOCO_CATALOG_BYTES, KNTWR_MEM_LOCO_PARTICIPANTS_BYTES, KNTWR_MEM_LOCO_SWEEP_SCRATCH_BYTES,
    KNTWR_MEM_LOCO_RESOLVE_SCRATCH_BYTES, KNTWR_MEM_LOCO_ENV_SCRATCH_BYTES,
    KNTWR_MEM_LOCO_SCENE_NODES, KNTWR_MEM_LOCO_SCENE_OWNERS, KNTWR_MEM_LOCO_TREE_ENTRIES,
    KNTWR_MEM_BUDGET_DISABLED_MASK, KNTWR_MEM_BUDGET_RELEASE_PENDING, KNTWR_MEM_BUDGET_RELEASES,
    KNTWR_MEM_RELEASED_LOCO_BYTES, KNTWR_MEM_RELEASED_COLLIDE_BYTES,
    KNTWR_MEM_NATIVE_GRID_SHIFT, KNTWR_MEM_NATIVE_GRID_MAXIMUM, KNTWR_MEM_NATIVE_GRID_DIMENSION,
    KNTWR_MEM_LOCO_CATALOG_RING_BYTES, KNTWR_MEM_LOCO_CATALOG_CAPSULE_BYTES, KNTWR_MEM_LOCO_CATALOG_WALL_BYTES,
    KNTWR_MEM_LOCO_CATALOG_EDGE_BYTES, KNTWR_MEM_LOCO_CATALOG_POLYGON_BYTES, KNTWR_MEM_LOCO_CATALOG_RINGS,
    KNTWR_MEM_LOCO_CATALOG_CAPSULES, KNTWR_MEM_LOCO_CATALOG_WALLS, KNTWR_MEM_LOCO_CATALOG_EDGES,
    KNTWR_MEM_LOCO_CATALOG_POLYGON_POINTS,
    KNTWR_MEM_HOLE_FLOOR_BYTES, KNTWR_MEM_MIN_LARGEST_HOLE, KNTWR_MEM_LATCH_REASON
};
#define KNTWR_ENV_TARGET_WORDS 64u
#define KNTWR_RESOLVE_FRAME_WORDS 4u
#define KNTWR_COLLIDE_LOD_WORDS 16u
#define KNTWR_COLLIDE_CENSUS 0x80000000u /* collide_lod_m flag, NOT an enabled_mask feature; requires PROFILE. */
#define KNTWR_COLLIDE_LOD_METRES_MASK 0x7fffffffu
#define KNTWR_ALLOCATOR_THREADS 32u /* pool slots 0..30; dedicated AI worker = row 31 */
#define KNTWR_ALLOCATOR_ROW_WORDS 8u
#define KNTWR_ALLOCATOR_WORDS (KNTWR_ALLOCATOR_THREADS * KNTWR_ALLOCATOR_ROW_WORDS)
#define KNTWR_ERROR_ALLOCATOR 14u
#define KNTWR_ERROR_VA_BUDGET 15u
/* Accepted optimization selection (`--features all`); launcher default additionally enables CAVALRY_ORBIT.
   Reference stack (dn-cwlive/dn-cwlive2): loco owned+grid incremental+cw workers, collide Phase B + contact workers.
   Profiling/sampling, PATH, FORMATION, BALLISTICS, BRAIN2, COLLIDE_LOD, AI_CTRL and BRAIN remain opt-in. */
#define KNTWR_ALL (KNTWR_AI_ASYNC | KNTWR_BATCH64 | KNTWR_VISUAL | KNTWR_LOCO | KNTWR_COLLIDE)
/* Every feature bit the runtime accepts in kntwr_config::enabled_mask. */
#define KNTWR_VALID_MASK (KNTWR_PATH | KNTWR_FORMATION | KNTWR_BALLISTICS | KNTWR_AI_ASYNC | KNTWR_BATCH64 | KNTWR_BRAIN2 | KNTWR_VISUAL | KNTWR_PROFILE | KNTWR_BRAIN | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_AI_CTRL | KNTWR_LOCO | KNTWR_GRID_CENSUS | KNTWR_AI_CENSUS | KNTWR_AI_ASYNC2 | KNTWR_ARMY_UNIT_SHADOW | KNTWR_CAVALRY_ORBIT)
/* ai_async2_words labels, word order (histogram buckets: <=125us, <=250us, ... <=128ms, >128ms; gate kinds: site 34
   admission (capacity drain, lease wait, fallback join), site 33 controller, TICK 57DFDF quadtree update, tick end
   (start seam, abort drain), delegate replacement 6EA520/6B3010, delegate destructor 69D710/69D750, command callback
   805CE0/7DEC70 and the 83FD00 call gate, stop drain). Version 2 renamed words 3..5 for the boundary schedule; version 3
   (blocking tick-start join, owner-teardown pins, stop quiesce) names words 92..94. */
#define KNTWR_AI_ASYNC2_HIST_LABELS(p) p "_le125us", p "_le250us", p "_le500us", p "_le1ms", p "_le2ms", p "_le4ms", \
    p "_le8ms", p "_le16ms", p "_le32ms", p "_le64ms", p "_le128ms", p "_gt128ms"
#define KNTWR_AI_ASYNC2_KIND_LABELS(p) p "site34_admission", p "site33_controller", p "spatial_57dfdf", p "tick_end", \
    p "delegate_replace", p "delegate_dtor", p "command", p "stop"
#define KNTWR_AI_ASYNC2_LABELS \
    "version", "dispatches", "completions", "admit_capacity_joins", "admit_lease_waits", "fallback_joins", \
    "deadlock_suspected", "fallback", "fallback_thinks", "marshalled_calls", "marshalled_nested", "marshal_wait_sum_us", \
    "marshal_wait_max_us", "think_sum_us", "think_max_us", "overlap_sum_us", "overlap_max_us", "join_wait_sum_us", \
    "join_wait_max_us", "in_flight", KNTWR_AI_ASYNC2_HIST_LABELS("think"), KNTWR_AI_ASYNC2_HIST_LABELS("overlap"), \
    KNTWR_AI_ASYNC2_HIST_LABELS("join_wait"), \
    "waits_site34_admission", "max_wait_us_site34_admission", "waits_site33_controller", "max_wait_us_site33_controller", \
    "waits_spatial_57dfdf", "max_wait_us_spatial_57dfdf", "waits_tick_end", "max_wait_us_tick_end", \
    "waits_delegate_replace", "max_wait_us_delegate_replace", "waits_delegate_dtor", "max_wait_us_delegate_dtor", \
    "waits_command", "max_wait_us_command", "waits_stop", "max_wait_us_stop", \
    KNTWR_AI_ASYNC2_KIND_LABELS("gate_"), KNTWR_AI_ASYNC2_KIND_LABELS("marshal_"), \
    "spotting_gate_unresolved", "lease_holds", "walk_route_entries", "scratch_ready", \
    "stop_served_marshals", "stop_aborted_marshals", "owner_teardown_leases", "staged_teardown_publishes"
/* ai_async2_route_words labels: boundary schedule counters (ticks = tick-start seams; a batch is "complete" when it had
   finished by the next tick start: complete fraction = seam_complete_joins / published_batches; seam_stalls and
   seam_wait_sum_us/seam_wait_max_us are the tick-start lifetime join's stall for batches that had not), the routed-slot thread matrix (slot 0x133E2DC walk state 702BB0, slot 0x133773C observer 6A95A0;
   worker in a think -> private family, worker outside a think / tick owner / other thread -> original), entries of
   every private clone (generator AI2_ROUTE_ORDER), marshalled calls per pin, worker entries of the unrouted 83FD00 gate,
   private vector capacities after the last think and the private search-object construction mask. */
#define KNTWR_AI_ASYNC2_ROUTE_LABELS \
    "version", "schedule", "ticks", "queued", "published_batches", "queued_max", "capacity_joins", "lease_waits", \
    "seam_polls", "seam_complete_joins", "seam_marshal_serves", "seam_stalls", "seam_wait_sum_us", \
    "seam_wait_max_us", "seam_stall_last_tick", "fallback_tick", "main_served", "main_marshal_waits", \
    "walk_worker_private", "walk_worker_idle", "walk_tick", "walk_other", \
    "observer_worker_private", "observer_worker_idle", "observer_tick", "observer_other", \
    "fn_state_update", "fn_position_update", "fn_shape_search", "fn_walk", "fn_gather", "fn_7fca40", "fn_7fca90", \
    "fn_808040", "fn_7f6f20", "fn_7f1cc0", "fn_81c080", "fn_81c050", "fn_67a790", "fn_6a95a0", "fn_6c71d0", \
    "fn_6cc730", "fn_808550", "fn_7f6ed0", "fn_7f1cf0", "fn_809110", "fn_80dcf0", \
    "marshal_replace19_13378f8", "marshal_replace19_1337998", "marshal_replace19_1337bb8", "marshal_replace19_1337c30", \
    "marshal_replace19_1349c18", "marshal_replace20_1337bb8", "marshal_replace20_1337c30", "marshal_replace20_1349c18", \
    "marshal_dtor_13376fc", "marshal_dtor_13376ac", "marshal_command_805ce0", "marshal_command_7dec70", \
    "marshal_call_83fd00", "unrouted_83fd00_entries", "lookup_capacity", "gather_capacity", "walk_capacity", \
    "scratch_mask"
/* KNTWR_AI_ASYNC2 deferred schedule (kntwr_config::ai_deferred, launcher --ai-deferred [--ai-deferred-k K]
   [--ai-deferred-budget B]). A site-34 think of tick A runs in count-budgeted slices (B generate/child/whole-think
   node calls per inter-tick window, passes free) through a private node driver; the next tick start joins only the
   open slice; a finished think is consumed at the first seam >= A + K; while outstanding, its planner's site-34 calls
   are busy refusals. */
#define KNTWR_AI_DEFERRED_WORDS 64u /* ai_deferred_words; layout src/ai/kntwr_ai_async2.h (DeferWord), labels KNTWR_AI_DEFERRED_LABELS */
#define KNTWR_AI_DEFERRED_K_MASK 0xFFu
#define KNTWR_AI_DEFERRED_MAX_K 32u
#define KNTWR_AI_DEFERRED_BUDGET_SHIFT 8u
#define KNTWR_AI_DEFERRED_BUDGET_MASK 0xFFFF00u
#define KNTWR_AI_DEFERRED_DEFAULT_K 1u
#define KNTWR_AI_DEFERRED_DEFAULT_BUDGET 2u
#define KNTWR_AI_DEFERRED_BUCKET_LABELS(p) p "_1", p "_2", p "_3", p "_4", p "_5_8", p "_9_16", p "_17_32", p "_gt32"
#define KNTWR_AI_DEFERRED_KIND_LABELS(p) p "_pass_a", p "_pass_b", p "_is_current", p "_generate", p "_child_think", \
    p "_whole_think"
#define KNTWR_AI_DEFERRED_LABELS \
    "version", "k", "budget", "admitted", "busy_refusals", "capacity_refusals", "consumed", "consumed_on_time", \
    "consumed_late", "abandoned_unseen", "abandoned_stop", "slices", "budget_hits", "nodes_skipped", \
    "nodes_relocated", "children_skipped", "thinks_dropped", "seam_slice_waits", "seam_slice_complete", \
    "seam_wait_sum_us", "seam_wait_max_us", "seam_marshal_serves", "slice_max_us", "slice_sum_us", "flags_carried", \
    "snapshot_overflows", KNTWR_AI_DEFERRED_KIND_LABELS("calls"), KNTWR_AI_DEFERRED_KIND_LABELS("us"), "unit_max_us", \
    "consume_hash", "last_consume_tick", "spanned_max", "slices_max", "outstanding", \
    KNTWR_AI_DEFERRED_BUCKET_LABELS("spanned"), KNTWR_AI_DEFERRED_BUCKET_LABELS("slices"), "slices_over_2ms", \
    "slices_over_4ms", "reserved62", "reserved63"
/* --ai-ctrl-* (kntwr_config::ai_ctrl_flags; src/ai/kntwr_ai_ctrl_batch.h, src/ai/kntwr_ai_ctrl_geometry.h): reuse of the AI controller's
   node-scoring inputs inside one stable scoring batch. Flags select the mode; nonzero requires a routed MANAGER tick (PROFILE or a
   simulation feature) and excludes KNTWR_AI_CTRL / KNTWR_AI_ASYNC2. CENSUS is shadow-only (native always executes) and excludes
   HISTOGRAM/GEOMETRY; VERIFY (debug sub-mode) requires HISTOGRAM or GEOMETRY. */
#define KNTWR_AI_CTRL_CENSUS 0x1u    /* --ai-ctrl-census */
#define KNTWR_AI_CTRL_HISTOGRAM 0x2u /* --ai-ctrl-histogram */
#define KNTWR_AI_CTRL_GEOMETRY 0x4u  /* --ai-ctrl-geometry */
#define KNTWR_AI_CTRL_VERIFY 0x8u    /* --ai-ctrl-verify */
#define KNTWR_AI_CTRL_MODE_MASK 0xFu /* the four --ai-ctrl-* mode bits above */
/* --ai-claim-once / --ai-claim-once-census (src/ai/kntwr_claim_once.h): bits 8 / 9 of ai_ctrl_flags (the two exclude each
   other). Not --ai-ctrl modes. ONCE: one 0x82F3A0 placement recompute per fallback claim call instead of one per claimed unit. CENSUS: the same loop
   without the elision, publishing the same controller-state hash (native reference for a bit-exact comparison). Both ride the routed-tick / no-ai_ctrl
   validation and coexist with KNTWR_AI_ASYNC2 unless ai_deferred is set (only the KNTWR_AI_CTRL_MODE_MASK bits and ai_deferred + claim bits exclude it). */
#define KNTWR_AI_CLAIM_ONCE 0x100u
#define KNTWR_AI_CLAIM_ONCE_CENSUS 0x200u
#define KNTWR_AI_CLAIM_BITS (KNTWR_AI_CLAIM_ONCE | KNTWR_AI_CLAIM_ONCE_CENSUS)
/* --brain-target-cull-shadow / --brain-target-cull / --brain-retarget-jitter (src/brain/kntwr_target_cull.h, src/brain/kntwr_retarget_jitter.h): bits 10 / 11 / 12 of
   ai_ctrl_flags (bits 13..31 are reserved and refused, bits 13..17 formerly the retired AI group / hold-slots / march-slots levers). All three act on the soldier-brain stage's combat node step 0x676FD0 (routed through the step clone
   CLONE_STEP_676FD0 behind a gate on the node vtable slot 0x1333E44, tick thread inside site 6): TARGET_CULL(_SHADOW) replaces the contact-list search 0x553420
   (bit-exact; shadow = native answers + compare, the two exclude each other), RETARGET_JITTER delays a lost target's re-search by agent+0x2C & 0xF ticks
   (SHARED-SIMULATION behaviour change, opt-in only, never implied by --features all). Same routed-tick / no-ai_ctrl validation as the
   claim bits (they coexist with KNTWR_AI_ASYNC2), and exclusive with KNTWR_AI_CTRL_GEOMETRY (which publishes the status words 16..23 the two levers use). */
#define KNTWR_AI_TARGET_CULL_SHADOW 0x400u
#define KNTWR_AI_TARGET_CULL 0x800u
#define KNTWR_AI_RETARGET_JITTER 0x1000u
#define KNTWR_AI_BRAIN_STEP_BITS (KNTWR_AI_TARGET_CULL_SHADOW | KNTWR_AI_TARGET_CULL | KNTWR_AI_RETARGET_JITTER)
/* Clip picker crash guard (src/animation/kntwr_clip_picker_guard.h; analysis/native-crash-divzero-anim.md): ALWAYS ON while the runtime is active (monitor start .. stop),
   no switch, no config bit. A 5-byte `jmp` at the picker's entry 0xE5F760 (installed with one 8-byte interlocked swap after verifying the original bytes, restored at stop)
   enters a copy of the native instruction sequence; the n != 0 path (the category has clips) is the same instructions as native, bit-identical, with no counter. Only the
   request the native code crashes on (#DE 0xC0000094 at 0xE5F77A: the requested category AND category 0 / MISSING_ANIM have no clips - horse/camel/elephant/engine tables
   asked for a man stance, reachable with --mounted-officer) is answered differently: the clip of the first non-empty category 1..863 (rand % n_k + k*6), or table[0]
   when all 864 are empty. Publishes anim_guard_words (hot-path-free counters; a run with no hits shows only calls_cold/patch_installed/version). */
#define KNTWR_ANIM_GUARD_WORDS 8u /* anim_guard_words (kntwr_clip_picker_guard::Word, labels KNTWR_ANIM_GUARD_LABELS; table_last/cat_last are last-value words, not counters) */
#define KNTWR_FORMATION_RESIDUAL_WORDS 832u /* army_residual_words (appended after anim_guard_words; owner module src/army/native_formation_residual.*, labels KNTWR_FORMATION_RESIDUAL_LABELS; --army-storm-census only, all zero without it; version 2 adds limited-solve aggregates, top-row QPC identity, formation queue command fields/class table and the retention/abort ledger; version 3 widens the top rows to 57 words, the ledger to 29 and appends the command-split route table (13 words at word 683): the private 581CA0 chain's matched state enters / other enters / 57B000 assignments / 55F160 per-man calls of the routed queue callbacks, per top row for the invocation and for its slowest routed callback; version 4 appends the assignment split (assign_scope vs inner solver work, 8 words) to the END of each route aggregate (top row idx 57..64, slow row idx 65..72, table idx 13..20): top rows are 73 words, the ledger starts at word 700, the queue table at 729 and the route table (21 words) at 811) */
/* --drag-ladder (kntwr_config::gameplay_flags bit 0; src/formation/kntwr_drag_ladder*.{h,cpp}; analysis/FINDINGS.md "drag ladder"): implied by --features all (launcher --no-drag-ladder opts out).
   Quantizes the player's drag-out frontage to 60-file steps: a width of <= 60 files is untouched, above it the file count snaps DOWN to a multiple of 60. v6 is ONE full-body
   detour at the stock cdecl FilesPerRow 0x642C90 (the engine's only files-from-width function): its return is floored to a 60-multiple above 60 files, so the drag preview
   underlay, the placement records, the slot generator, the committed order and the formation solver all read the same laddered count by construction (consumers reach
   0x642C90 directly or through layout vtable 0x1333AA8 slot +0x10, 0x642D00 = min(FilesPerRow, cap)). The inverse WidthFromFiles 0x642B50 and the staggered-row copy 0x642D90
   stay stock. The site verifies the stock bytes first; a refusal is a silent no-op reported in the words row (installed = 0).
   SHARED-SIMULATION change: all peers of a multiplayer game must run the same setting. Publishes drag_ladder_words. */
#define KNTWR_DRAG_LADDER 0x1u
/* --wounded[=PCT] (kntwr_config::gameplay_flags bit 1 + percent in bits 8..14; src/animation/kntwr_wounded*.{h,cpp}; analysis/FINDINGS.md "wounded census 2026-10-31"):
   EXPERIMENTAL opt-in, NOT implied by --features all. Stock kill path 0x653A10 commits the death-anim state at 0x653F1A..0x653F38: only categories
   [0x14521C8]=0x32A .. +[0x14521CC]=5 (KNOCKDOWN_2..KNOCKED_FLYING_1, melee/impact deaths) enter wounded state 0x4B; every bullet death picks a DEATH_*
   category and becomes a static corpse (state 0x2A). The hook detours the 8-byte range test (8B 15 C8 21 45 01 / 3B CA) and recomputes the state in the
   host: native knockdown range unchanged; otherwise, when the man's picked death clip carries the FACE_DOWN/FACE_UP .anim trailer events (clip +0x60
   presence byte, +0x5C/+0x54 orientation ints — the same fields the stock state-0x4B stepper 0x679300 gates on), a deterministic per-death roll flips
   state 0x2A -> 0x4B with probability PCT%. Downstream is stock: the stepper picks front/back from the clip, queues the native weighted injury/crawl
   loops (categories 0x330..0x338, mapped by man_common_fragment in every man animation table). Men whose clips carry no FACE events (all non-musket/
   sabre families) stay static by construction. SHARED-SIMULATION change: all multiplayer peers must run the same setting. Publishes wounded_words. */
#define KNTWR_WOUNDED 0x2u
#define KNTWR_WOUNDED_PCT_SHIFT 8u
#define KNTWR_WOUNDED_PCT_MASK (0x7Fu << KNTWR_WOUNDED_PCT_SHIFT) /* percent 1..100 in bits 8..14; nonzero requires KNTWR_WOUNDED */
#define KNTWR_WOUNDED_PCT_DEFAULT 33u
#define KNTWR_GAMEPLAY_FLAGS_VALID (KNTWR_DRAG_LADDER | KNTWR_WOUNDED | KNTWR_WOUNDED_PCT_MASK)
#define KNTWR_WOUNDED_WORDS 16u /* wounded_words (kntwr_wounded_hook::Word, labels KNTWR_WOUNDED_LABELS; last_cat is a last-value word, the rest are counters; word 15 reserved zero) */
#define KNTWR_WOUNDED_LABELS \
    "version", "requested", "installed", "calls", "native_knockdown", "static_candidates", "eligible", "flipped", \
    "denied_roll", "untagged", "no_clip", "faults", "last_cat", "remap_fixes", "orient_tagged", "reserved15"
#define KNTWR_DRAG_LADDER_WORDS 16u /* drag_ladder_words (kntwr_drag_ladder_hook::Word, labels KNTWR_DRAG_LADDER_LABELS; calls/laddered/passthrough are plain counters, last_files_* are last-value words, words 9..15 are reserved zero) */
#define KNTWR_DRAG_LADDER_LABELS \
    "version", "requested", "installed", "calls", "laddered", "passthrough", "faults", "last_files_before", \
    "last_files_after", "reserved9", "reserved10", "reserved11", "reserved12", "reserved13", "reserved14", "reserved15"
#define KNTWR_ANIM_GUARD_LABELS \
    "calls_cold", "guarded", "scanned_max", "empty_tables", "table_last", "cat_last", "patch_installed", "version"
#define KNTWR_AI_CTRL_FLAGS_VALID (KNTWR_AI_CTRL_MODE_MASK | KNTWR_AI_CLAIM_BITS | KNTWR_AI_BRAIN_STEP_BITS)
#define KNTWR_AI_CTRL_REUSE_WORDS 32u /* ai_ctrl_reuse_words: A half words 0..15 (kntwr_ai_ctrl::Word), B half words 16..23 geometry (--ai-ctrl-geometry) or, without it, 16..19 --brain-target-cull and 20..23 --brain-retarget-jitter (kntwr_retarget_jitter::Word), 24..31 --ai-claim-once (kntwr_claim_once::Word) */
#define KNTWR_AI_CTRL_REUSE_LABELS \
    "batches", "scorer_calls", "eligible", "hist_calls", "hist_served", "hist_mismatch", "b44_b41_transitions_in_batch", \
    "hist_repeat_changed", "end_assign", "end_refresh", "end_callback", "end_exit", "max_scorer_calls_batch", \
    "hist_outside", "hist_first", "flags_latched", \
    "id_calls", "id_served", "pose_served", "dist_calls", "dist_served", "distinct_RV", "dist_mismatch", "boundary_repeat", \
    "claim_calls", "claim_entries", "claim_masked", "claim_calls_masked", "claim_refused_state", "claim_refused_other", "claim_packed", "claim_hash"
/* Word labels of the two brain-step levers (words 16..19 / 20..23 of the same row; receipt objects brain_target_cull / brain_retarget_jitter). */
#define KNTWR_AI_RETARGET_JITTER_LABELS "tracker_calls", "losses", "jittered", "delay_sum"
#define KNTWR_AI_TARGET_CULL_LABELS "calls", "candidates", "predicates", "packed"
/* --ai-prepass-census / --ai-presize (kntwr_config::ai_prepass_flags; src/ai/kntwr_planner_prepass.h). CENSUS: observation of the AI planner's
   child thinks and covered 0x7F1D40 walks on the thread that executes the think (AI worker under KNTWR_AI_ASYNC); native always executes
   once, unchanged. PRESIZE: behaviour-preserving query-local reservation of the 0x559090 hit-pair buffer. Bits 0x4 / 0x8 are reserved
   for the prepass shadow / live modes (the sibling child widens KNTWR_AI_PREPASS_FLAGS_VALID). Nonzero requires a routed MANAGER tick
   (PROFILE or a simulation feature) and excludes KNTWR_AI_ASYNC2; CENSUS excludes every other bit but PRESIZE. Row layout: header of
   src/ai/kntwr_planner_prepass.h. */
#define KNTWR_AI_PREPASS_CENSUS 0x1u /* --ai-prepass-census */
#define KNTWR_AI_PRESIZE 0x2u        /* --ai-presize */
#define KNTWR_AI_POLY_SHADOW 0x4u /* --ai-poly-shadow: native answers every 0x80DCF0 polygon test, kntwr_planner_search compares bit-for-bit (AL, x87 status, MXCSR) */
#define KNTWR_AI_POLY 0x8u        /* --ai-poly: exact SSE replacement of the kind-0 0x10EC150 OBB/polygon kernel, native fallback by reason */
/* --ai-record-test-shadow / --ai-record-test (src/ai/kntwr_record_test.h): the --ai-poly kernel extended to the ALTERNATE placement delegate
   0x13376AC (slot 16 = 0x6A99E0 -> 0x6A94B0 -> 0x6C71D0 ...), which --ai-poly does not route. Both need POLY_SHADOW or POLY (the same kernel and
   clones), exclude each other and the census, and keep the default observer route's --ai-poly mode independent of their own mode. */
#define KNTWR_AI_RECORD_TEST_SHADOW 0x20u /* --ai-record-test-shadow: native answers every polygon test of the alternate delegate route, the kernel is compared bit-for-bit */
#define KNTWR_AI_RECORD_TEST 0x40u        /* --ai-record-test: the kernel answers the alternate delegate route, native fallback by reason */
#define KNTWR_AI_RECORD_TEST_BITS (KNTWR_AI_RECORD_TEST_SHADOW | KNTWR_AI_RECORD_TEST)
#define KNTWR_AI_PREPASS_FLAGS_VALID 0xFFFF007Fu /* POLY_SHADOW and POLY exclude each other and CENSUS; both route the observer slot 0x13376FC+0x40 into the PS_* clones; bits 0x10 and 16..31: --ai-spiral-*; bits 0x20/0x40: --ai-record-test* */
/* --ai-spiral-census / --ai-spiral-cap-m N (ai_prepass_flags bit 0x10 and bits 16..31; src/ai/kntwr_spiral.h). N metres caps the observer
   ladder's last-resort placement spiral 0x7FCA90 (native: maxR -1.0, unlimited): rings of radius <= N run, then the native not-found
   exit is taken. A capped (not-found) spiral places the unit at the 0x7FCFF0 projection of its ORIGINAL requested point (possibly
   obstructed), exactly as native does when a whole ring leaves the map rectangle; the entry is not left unassigned. N = 0: native
   unlimited; 1..19 refused (the first ring, radius 20, always runs). Either the census bit or N > 0 routes the observer slot into the
   PS_* chain, publishes the fallback (0x1343318 slot 16) and controller (0x1349C18 slot 28) counting gates and fills ai_spiral_words.
   Combines with every other prepass bit. AI-only gameplay deviation when N > 0 (user-approved). */
#define KNTWR_AI_SPIRAL_CENSUS 0x10u
#define KNTWR_AI_SPIRAL_CAP_SHIFT 16u
#define KNTWR_AI_SPIRAL_CAP_MASK 0xFFFF0000u
#define KNTWR_AI_SPIRAL_CAP_MIN_M 20u
#define KNTWR_AI_SPIRAL_BITS (KNTWR_AI_SPIRAL_CENSUS | KNTWR_AI_SPIRAL_CAP_MASK)
#define KNTWR_AI_SPIRAL_WORDS 32u /* ai_spiral_words (src/ai/kntwr_spiral.h row layout, version 1) */
#define KNTWR_ARMY_SOLVER_WORDS 524u /* army_solver_words (src/army/native_army_solver.h row layout, version 3): 60 header + 16 x 13 tick table + 16 x 16 solve table */
#define KNTWR_ARMY_SOLVER_LABELS \
    "version", "mode", "started", "ticks", "solves_seen", "solves_flag1", "solved_kernel", "flag0_native", "foreign_native", \
    "fb_too_large", "fb_range", "fb_list_state", "fb_guard", "fb_env", "shadow_compares", "shadow_mismatch_solves", \
    "mismatch_entries", "mismatch_eax", "shim_suppressed", "shim_forwarded", "assign_calls", "route_r1", "route_r1b", "route_r2", \
    "native_us", "kernel_us", "evals_lo", "evals_hi", "distinct_lo", "distinct_hi", "iterations_lo", "iterations_hi", \
    "swaps", "removals", "max_m", "max_formation_members", "m_1_16", "m_17_64", "m_65_128", "m_129_256", \
    "m_257_512", "m_gt_512", "observer_us", "assign_members_sum", "scans_lo", "scans_hi", "cost_us", "loop_us", \
    "timed_solves", "kernel_total_us", "gather_us", "direct_18f12aa", "fb_fpenv", "fb_ctx", "empty_native", "cache_assign_calls", "cache_solved_kernel", "cmd_assign_calls", "cmd_solved_kernel", "cmd_gate_native"
#define KNTWR_ARMY_SOLVER_TICK_LABELS \
    "tick", "solves", "formations", "native_us", "kernel_us", "evals", "distinct", "iterations", "max_m", "solved_kernel", "fallbacks", "swaps", "assign_formations"
#define KNTWR_ARMY_SOLVER_SOLVE_LABELS \
    "tick", "formation", "m", "evals", "distinct", "iterations", "native_us", "kernel_us", "swaps", "flags", "members", "eax", \
    "scans", "cost_us", "loop_us", "spare"
#define KNTWR_AI_SPIRAL_LABELS \
    "version", "cap_m", "ladder_calls", "stage_spot", "stage_clamp", "stage_ring", "stage_spiral", "stage_none", "stage_unknown", \
    "spiral_entries", "spiral_candidates", "spiral_rings", "spiral_found", "spiral_capped", "spiral_edge", "max_radius_m", \
    "max_candidates", "fallback_calls", "e0", "e1", "e2", "e3_4", "e5_8", "e_gt8", "entries", "max_entries", "tail_runs", \
    "tail_same_tick", "tail_memo", "ladder_in_fallback", "spiral_in_fallback", "off_thread"
#define KNTWR_ALLOC_CENSUS_WORDS 1056u /* alloc_census_words (src/core/kntwr_alloc_census.*): 32 header + 128 rows x 8 (callsite_va, size_class, live_bytes, live_count, allocs, frees, peak_live_bytes, reserved) */
#define KNTWR_ALLOC_CENSUS_HEADER_WORDS 32u
#define KNTWR_ALLOC_CENSUS_ROWS 128u
#define KNTWR_ALLOC_CENSUS_ROW_WORDS 8u
#define KNTWR_ALLOC_CENSUS_MODE 2u /* header word 2: 0 = off, 1 = --alloc-census, 2 = --alloc-fix, 3 = --alloc-fix + --alloc-census */
#define KNTWR_ALLOC_CENSUS_OMITTED_THREADS 24u /* header word 24: thread entries omitted when 512-slot TEB table is full */
#define KNTWR_ALLOC_CENSUS_LABELS \
    "version", "enabled", "mode", "ptr_capacity", "ptr_used", "callsite_capacity", "callsite_used", "overflow_count", \
    "hook_faults", "live_bytes", "live_count", "baseline_bytes", "drift_bytes", "peak_live_bytes", "total_allocs", "total_frees", \
    "untracked_frees", "reentrant_skips", "samples", "fix_freed_blocks", "fix_freed_bytes", "fix_active_sites", "storage_bytes", "slots_owned", \
    "omitted_threads", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
#define KNTWR_ARENA_WORDS 32u /* arena_words (src/render/kntwr_arena_release.*): lever 4 + lever 7 counters */
#define KNTWR_ARENA_LABELS \
    "flags_active", "frames_observed", "posed_men_last", "posed_men_peak", "worklist_men_last", "scene_blocks_cur", "scene_blocks_used", "scene_blocks_peak", \
    "pose0_blocks_cur", "pose1_blocks_cur", "pose_blocks_used", "pose_blocks_peak", "scratch_blocks_cur", "scratch_blocks_used", "scratch_blocks_peak", "quadtree_blocks_cur", \
    "trim_events", "trim_blocks_freed", "trim_bytes_freed", "teardown_releases", "teardown_scene_blocks", "teardown_pose_blocks", "teardown_scratch_blocks", "teardown_blocks_freed", \
    "teardown_bytes_freed", "heap_opt_calls", "heap_opt_watermark_calls", "heap_opt_heaps_ok", "heap_opt_avail_before_mb", "heap_opt_avail_after_mb", "heap_opt_reclaimed_kb", "heap_opt_total_us"
#define KNTWR_OVERLAY_WORDS 16u /* overlay_words: lever 6 overlay/driver DLL report */
#define KNTWR_OVERLAY_LABELS \
    "version", "total_modules", "foreign_hook_modules", "nv_umd_modules", "splits_low_hole_count", "rtss_base", "rtss_size", "nvspcap_base", \
    "nvspcap_size", "steam_overlay_base", "steam_overlay_size", "nv_umd_image_bytes", "foreign_hook_image_bytes", "nv_driver_threads", "nv_driver_stack_bytes", "total_foreign_image_stack_bytes"
enum kntwr_overlay_word {
    KNTWR_OVL_VERSION, KNTWR_OVL_TOTAL_MODULES, KNTWR_OVL_FOREIGN_HOOK_MODULES, KNTWR_OVL_NV_UMD_MODULES,
    KNTWR_OVL_SPLITS_LOW_HOLE_COUNT, KNTWR_OVL_RTSS_BASE, KNTWR_OVL_RTSS_SIZE, KNTWR_OVL_NVSPCAP_BASE,
    KNTWR_OVL_NVSPCAP_SIZE, KNTWR_OVL_STEAM_OVERLAY_BASE, KNTWR_OVL_STEAM_OVERLAY_SIZE, KNTWR_OVL_NV_UMD_IMAGE_BYTES,
    KNTWR_OVL_FOREIGN_HOOK_IMAGE_BYTES, KNTWR_OVL_NV_DRIVER_THREADS, KNTWR_OVL_NV_DRIVER_STACK_BYTES,
    KNTWR_OVL_TOTAL_FOREIGN_IMAGE_STACK_BYTES
};
#define KNTWR_MOUNTED_OFFICER_WORDS 16u /* mounted_officer_words (src/army/kntwr_mounted_officer.h): unit-constructor mount gate counters */
#define KNTWR_MOUNTED_OFFICER_LABELS \
    "version", "flags", "units_seen", "units_eligible", "officer_first", "skipped_has_mounts", "skipped_no_refs", "skipped_no_officer", \
    "mounts_created", "attach_failures", "alloc_failures", "serial_last", "last_rider_vtable", "skipped_has_guns", "faults", "patch_installed"
#define KNTWR_ENGAGE_CENSUS_WORDS 6832u /* engage_census_words (src/ai/kntwr_engage_census.h): counters, histograms and 20-word event rows */
#define KNTWR_AI_POLY_WORDS 32u        /* ai_prepass_words[0..31]: src/ai/kntwr_planner_search.h row layout, version 1 */
#define KNTWR_AI_RECORD_TEST_WORDS 28u /* ai_prepass_words[32..59]: src/ai/kntwr_record_test.h row layout, version 1 */
#define KNTWR_AI_PREPASS_WORDS (KNTWR_AI_POLY_WORDS + KNTWR_AI_RECORD_TEST_WORDS) /* ai_prepass_words */
#define KNTWR_AI_POLY_LABELS \
    "version", "mode", "calls", "served", "fall_kind", "fall_fp_state", "fall_domain", "fall_walk_cap", "shadow_compares", \
    "mismatch_al", "mismatch_x87", "mismatch_mxcsr", "true_results", "vertices_sum", "vertices_max", "v_le16", "v_le64", \
    "v_le256", "v_gt256", "observer_routed", "observer_unrouted", "v_le1024", "v_le4096", "v_le16384", "v_le65536", "fall_busy", \
    "served_fast_kcycles", "sampled_native_kcycles", "sampled_fast_kcycles", "sampled_calls", "fallback_native_kcycles", "tsc_per_us"
#define KNTWR_AI_RECORD_TEST_LABELS \
    "version", "mode", "slot_routed", "slot_unrouted", "calls", "served", "fall_kind", "fall_fp_state", "fall_domain", "fall_walk_cap", \
    "fall_busy", "shadow_compares", "mismatch_al", "mismatch_x87", "mismatch_mxcsr", "true_results", "vertices_sum", "vertices_max", \
    "served_fast_kcycles", "sampled_native_kcycles", "sampled_fast_kcycles", "sampled_calls", "fallback_native_kcycles", "tsc_per_us", \
    "entry_kcycles", "entry_max_us", "v_gt256", "spare"
#define KNTWR_AI_PREPASS_LABELS KNTWR_AI_POLY_LABELS, KNTWR_AI_RECORD_TEST_LABELS
#define KNTWR_AI_PREPASS_CENSUS_WORDS 82u /* ai_prepass_census_words */
#define KNTWR_AI_PREPASS_CLASS_LABELS(c) c "_thinks", c "_think_us", c "_walk_us"
#define KNTWR_AI_PREPASS_CENSUS_LABELS \
    "version", "scopes", "node_thinks", "child_thinks", "walks", "walks_in_child", "distinct", "duplicates", "dup_same_child", \
    "unsupported", "overflow", "max_walks_scope", "max_distinct_scope", "max_walks_child", "think_us_sum", "think_us_max", "walk_us", \
    "gather_us", "traversal_us", "max_walk_us", "polygon_tests", "res_al0", "res_al1", "gathered_sum", "gathered_max", \
    "list_unsupported", "child_us_sum", "child_us_max", "d1_checked", "d1_other_thinks", "d1_other_words", "d1_list_thinks", \
    "d1_self_thinks", "d1_self_words", "d1_truncated", "world_diff", "world_same", "site_7C7FD3", "site_7C8113", "site_other", \
    KNTWR_AI_PREPASS_CLASS_LABELS("le8ms"), KNTWR_AI_PREPASS_CLASS_LABELS("le32ms"), KNTWR_AI_PREPASS_CLASS_LABELS("le128ms"), \
    KNTWR_AI_PREPASS_CLASS_LABELS("le512ms"), KNTWR_AI_PREPASS_CLASS_LABELS("gt512ms"), \
    "presize_queries", "presize_reserved", "presize_skipped_nonempty", "presize_skipped_nobound", "presize_clamped", \
    "presize_alloc_failed", "presize_pairs_reserved", "presize_hits_sum", "flags", \
    "poly_vertices_sum", "poly_vertices_max", "poly_hit", "poly_vertices_unreadable", \
    "poly_v_le8_calls", "poly_v_le16_calls", "poly_v_le32_calls", "poly_v_le64_calls", "poly_v_le256_calls", "poly_v_gt256_calls", \
    "poly_v_le8_us", "poly_v_le16_us", "poly_v_le32_us", "poly_v_le64_us", "poly_v_le256_us", "poly_v_gt256_us", \
    "site_808492", "poly_v_gt1024"
/* In-memory image identity: every clone spec, source pin, oracle test image (analysis/Napoleon_patched.exe, generated by
   tools/apply_ntwpatch.py) and Ghidra snapshot is built against this image. The game file on disk is STOCK
   (KNTWR_STOCK_IMAGE_SHA256); the launcher applies the gameplay patch (data/napoleon.ntwpatch) in memory to the suspended
   process before its first instruction runs, producing the loader-equivalent of this patched image.
   Pre-patched or otherwise modified executable files on disk are rejected. */
#define KNTWR_IMAGE_SHA256 "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"
#define KNTWR_STOCK_IMAGE_SHA256 "44880ec1770f600163a336eec83b4366901484c5cceec83dc326e2932f02a054"
#define KNTWR_STOCK_MSS32_SHA256 "d7a73a1b0e005d0f4ce1437c13196b9967c801d5cbc0c8ebcde8977d265f55fd"

/* The launcher validates the stock file before launch and applies the gameplay patch in memory. The in-process
   runtime also validates live source spans before publishing any hook. No absolute process pointers survive a process
   lifetime or battle generation. */
typedef struct kntwr_config {
    uint32_t abi;
    uint32_t size;
    uint32_t enabled_mask;
    uint32_t workers; /* requested pool worker count; Start clamps it to min(workers, max(1, usable logical processors - 2)) (usable = popcount of the process affinity mask; 0 stays 0) and publishes the clamped count in kntwr_status::workers. */
    uint32_t image_base;
    uint32_t poll_ms;
    uint32_t main_thread_id; /* Former reserved[0]; required only with KNTWR_PROFILE. */
    uint32_t profile_site;   /* 0: sampler gated on the whole tick; 1..KNTWR_TIMED_SITES: gated on that timed site only */
    uint32_t collide_lod_m;  /* Low 31 bits: 0 selects 40 metres, otherwise 1..100000. High bit KNTWR_COLLIDE_CENSUS opts into costly pair timers. */
    uint32_t loco_flags;     /* Appended (config grew 36 -> 40 bytes); own field, no other field is reinterpreted. KNTWR_LOCO_* flags; nonzero requires KNTWR_LOCO. */
    uint32_t brain_flags;    /* Appended at offset 40. KNTWR_BRAIN_* flags; nonzero requires BRAIN2. */
    uint32_t collide_flags;  /* Appended at offset 44 (config 44 -> 48 bytes). KNTWR_COLLIDE_CONTACT_* flags; nonzero requires COLLIDE; SHADOW and WORKERS are exclusive. */
    uint32_t va_watch_flags; /* Offset 48 (config 48 -> 52 bytes; former puppet probe unit count, retired). KNTWR_VA_WATCH (launcher --va-watch), KNTWR_ARMY_STORM_CENSUS (--army-storm-census) and the storm sampler threshold in ms in bits 8..15 (KNTWR_ARMY_STORM_SAMPLE_MASK, --army-storm-sample-ms); 0: off (nothing sampled); other bits refused. */
    uint32_t ai_deferred;    /* Appended at offset 52 (config 52 -> 56 bytes). 0: off. Otherwise the KNTWR_AI_ASYNC2 deferred schedule (launcher --ai-deferred): K = bits 0..7 (KNTWR_AI_DEFERRED_K_MASK, 1..KNTWR_AI_DEFERRED_MAX_K) consumption delay in ticks, B = bits 8..23 (KNTWR_AI_DEFERRED_BUDGET_SHIFT, 1..65535) costed node units per inter-tick slice; requires KNTWR_AI_ASYNC2; other bits refused. */
    uint32_t ai_ctrl_flags;  /* Appended at offset 56 (config 56 -> 60 bytes). KNTWR_AI_CTRL_* flags (launcher --ai-ctrl-census/-histogram/-geometry/-verify) in bits 0..3, KNTWR_AI_CLAIM_ONCE / KNTWR_AI_CLAIM_ONCE_CENSUS (--ai-claim-once / --ai-claim-once-census) in bits 8 / 9, KNTWR_AI_TARGET_CULL_SHADOW / KNTWR_AI_TARGET_CULL / KNTWR_AI_RETARGET_JITTER in bits 10..12; 0: off. */
    uint32_t ai_prepass_flags; /* Appended at offset 60 (config 60 -> 64 bytes; the launcher's injection blob places the DLL path at sizeof(kntwr_config)). KNTWR_AI_PREPASS_* / KNTWR_AI_PRESIZE / KNTWR_AI_POLY* flags (launcher --ai-prepass-census, --ai-presize, --ai-poly-shadow, --ai-poly), KNTWR_AI_SPIRAL_CENSUS (--ai-spiral-census) and the spiral cap in metres in bits 16..31 (--ai-spiral-cap-m); 0: off. */
    uint32_t gameplay_flags;   /* Appended at offset 64 (config 64 -> 68 bytes). KNTWR_GAMEPLAY_* opt-in gameplay hooks that need no routed tick and no enabled_mask bit (launcher --drag-ladder); 0: off (nothing patched); other bits refused. SHARED-SIMULATION change: every peer of a multiplayer game must run the same value. */
} kntwr_config;

enum kntwr_phase {
    KNTWR_IDLE = 0,
    KNTWR_VERIFYING = 1,
    KNTWR_WAITING_BATTLE = 2,
    KNTWR_ACTIVATING = 3,
    KNTWR_ACTIVE = 4,
    KNTWR_RESTORING = 5,
    KNTWR_FAILED = 6,
    KNTWR_STOPPED = 7
};

/* Diagnostic snapshot: read sequence, copy all words, read sequence again.
   Accept only equal even sequence values. Job counters are sampled module
   counters, not a transactional gameplay snapshot or a performance claim. */
#define KNTWR_GRID_READERS 64u
#define KNTWR_GRID_EDGES 512u
#define KNTWR_GRID_SITES 113u
#define KNTWR_GRID_UNKNOWN_SITE 112u
#define KNTWR_GRID_PHASES 4u
#define KNTWR_GRID_THREADS 3u
/* Counts wrap modulo 2^32. route_calls count invocations of retargeted private-clone call edges after the clone
   reaches the census gate; the gate then tail-jumps to the edge's ORIGINAL resolved destination (existing target
   binding semantics are never bypassed). route=KNTWR_GRID_ROUTE_IMAGE means that destination is the original reader
   VA, so each such invocation is an exact native reader entry (entry_calls). BINDING/CLONE routes (host gates,
   LOCO services, solver replay, private clones) may defer, skip, replace or reshape the reader: those calls are
   counted only as route_calls and must not be read as native reader entries. Samples are EIP occupancy, never
   inferred calls. Phase indices use kntwr_profile_phase (inside/outside tick is carried by phase and tick_calls);
   thread classes: 0 actual tick owner while a routed tick runs, 1 configured main/render thread (not the owner),
   2 any other thread including workers. Site 112 is unknown; non-owner threads use the owner's innermost timed
   site at the call (dispatch site, observational). last_* fields are hints. Counters accumulate per start/stop. */
#define KNTWR_GRID_ROUTE_IMAGE 0u   /* resolved destination == original reader VA: exact reader entry */
#define KNTWR_GRID_ROUTE_BINDING 1u /* host/binding route: reader entry not proven */
#define KNTWR_GRID_ROUTE_CLONE 2u   /* private clone route: reader entry not proven */
#define KNTWR_GRID_ROUTE_OTHER 3u   /* image destination other than the reader VA */
typedef struct kntwr_grid_reader_status {
    uint32_t va, end, route_calls, route_tick_calls, entry_calls, entry_tick_calls, original_samples, clone_samples;
    uint32_t last_tick, last_site, last_thread, last_phase;
    uint32_t calls_phase[KNTWR_GRID_PHASES], samples_phase[KNTWR_GRID_PHASES];
    uint32_t calls_thread[KNTWR_GRID_THREADS], samples_thread[KNTWR_GRID_THREADS];
    uint32_t calls_site[KNTWR_GRID_SITES], samples_site[KNTWR_GRID_SITES];
} kntwr_grid_reader_status;
typedef struct kntwr_grid_edge_status {
    uint32_t reader, site, source_clone, route, route_calls, route_tick_calls, last_tick, last_thread;
} kntwr_grid_edge_status;
typedef struct kntwr_grid_census_status {
    uint32_t version, reader_count, edge_count, routed_ticks;
    uint32_t sample_attempts, sample_failures, unknown_samples, attribution_dropped;
    /* edge_dropped: readers/edges beyond the status capacity (generation fails first, so normally zero).
       unresolved_edges: generator-reported direct references to reader VAs it could NOT gate (internal calls or
       direct jumps); nonzero means exact route counts are incomplete, it is not an error. */
    uint32_t edge_dropped, unresolved_edges;
    kntwr_grid_reader_status readers[KNTWR_GRID_READERS];
    kntwr_grid_edge_status edges[KNTWR_GRID_EDGES];
} kntwr_grid_census_status;

typedef struct kntwr_status {
    uint32_t sequence;
    uint32_t abi;
    uint32_t size;
    uint32_t phase;
    uint32_t requested_mask;
    uint32_t active_mask;
    uint32_t error;
    uint32_t error_detail;
    uint32_t pid;
    uint32_t image_base;
    uint32_t root;
    uint32_t model;
    uint32_t generation;
    uint32_t monitor_thread;
    uint32_t workers; /* effective pool worker count after the Start clamp (see kntwr_config::workers) */
    uint32_t tick;
    uint32_t path_completed;
    uint32_t formation_committed;
    uint32_t ballistic_committed;
    uint32_t collision_cache_hits;
    uint32_t worker_chunks;
    uint32_t storage_bytes;
    uint32_t retained_bytes;
    uint32_t probe;       /* world discovery: low byte = failing link (0 = found), bit 8 = scheduler flag read as 1 */
    uint32_t path_fallbacks;      /* npr_solve calls that ran the original (consumed + fallbacks = all solves) */
    uint32_t path_refused;        /* requests refused before planning + results dropped stale */
    uint32_t formation_epochs;    /* manager entries that took the batch path */
    uint32_t formation_refused;   /* assign fallbacks + rejected manager entries */
    uint32_t ballistic_stages;    /* ballistic manager stages the runtime staged */
    /* Raw module state words (each module's exported 16-word state) and the ballistic job statistics
       st_stages, st_items, st_skip, st_prefixed, st_committed, st_rejected, st_overflow, st_unmatched. */
    uint32_t formation_words[16];
    uint32_t query_words[16];
    uint32_t path_words[24];      /* npr_state words 0..17 (NPR_STATE_WORDS), zero padded */
    uint32_t ballistic_words[8];
    /* Module gather/capture diagnostics (nfr_diag export; layout in the module header). */
    uint32_t formation_diag[192]; /* nfr_diag words 0..191: counters, sample vtables, two sticky raw captures (native_formation_runtime.h) */
    /* Simulation tick cadence sampled by the monitor at poll_ms granularity: 0 tick changes seen, 1 sum interval ms,
       2 max interval ms, 3..9 histogram (<=20,<=50,<=100,<=200,<=500,<=1000,>1000 ms), 10 max ticks per change,
       11 last interval ms, 12 observed ms. */
    uint32_t tick_words[16];
    /* Simulation tick timing measured inside the tick gate (QPC; needs a simulation feature or profile): 0 ticks,
       1 sum duration us, 2 max duration us, 3..9 duration histogram (<=1,<=2,<=5,<=10,<=20,<=50,>50 ms),
       10 sum interval us, 11 max interval us, 12 intervals >150 ms, 13 tick thread id, 14 intervals >250 ms,
       15 ticks routed through the private clone. */
    uint32_t sim_words[16];
    /* AI planner round-robin think attribution (site 34 = 0x7D99F0): 16 rows of {vtable, sum us, calls, max us}. */
    uint32_t planner_words[64];
    /* PROFILE, owner-thread observations (all wrap modulo 2^32):
       0 completed site-34 scopes, 1 walks, 2 gathers, 3 candidate spatial nodes summed,
       4 max nodes/gather, 5 accepted interests summed, 6 filter calls, 7 walk us,
       8 gather us, 9 polygon us, 10 max walks/scope, 11 polygon calls,
       12 memo hits, 13 memo misses, 14 unsupported memo inputs, 15 max accepted interests.
       Candidate nodes are spatial scratch, NOT pending requests or a generation counter. */
    uint32_t planner_walk_words[16];
    /* KNTWR_AI_ASYNC, modulo 2^32, reset at activation:
       0 native planner calls dispatched, 1 completed, 6 max_planner_us, 7 sum_planner_us,
       10 event-operation failures. Other indices retain their old ABI positions and are zero:
       no cross-tick stack parking, arbitrary-frame abort, quarantined partial think, or dropped update.
       Native faults propagate normally and are captured in crash_words, not suppressed. */
    uint32_t ai_words[16];
    /* Retained ABI row: word 11 counts planner admissions. All other indices are zero.
       Subordinate lifetime is protected by joining native frames, not pointer snapshots, scratch swaps,
       or the removed non-unwinding abort path. */
    uint32_t ai_extra_words[32];
    /* In-process crash capture (KNTWR_AI_ASYNC runs): a first-chance vectored handler records every EXCEPTION_ACCESS_VIOLATION /
       ILLEGAL_INSTRUCTION / STACK_OVERFLOW / IN_PAGE_ERROR / 0xC0000409 that is NOT a deliberate probe (guarded reads of foreign
       memory), writes a minidump of the process
       (first two distinct exceptions only) and then lets the exception continue to the game's own handlers. The words describe the
       LAST recorded exception and are written WITHOUT the status sequence lock (the process may be about to die): 0 count (number of
       recorded exceptions, written last), 1 thread id, 2 exception code, 3 EIP (preferred-base VA when in the main image, else raw),
       4 raw EIP, 5 fault address (ExceptionInformation[1], 0 if none), 6 model tick ([model+0x58]; 0 when unreadable), 7 packed:
       bits 0..1 module of the raw EIP (0 main image, 1 runtime DLL, 2 private clone, 3 other), bits 2..3 access (0 read, 1 write,
       2 execute, 3 none/other), bit 4 aiRunning, bit 5 aiBusy, bit 6 original scratch live (always one), bit 7 retired parked bit (zero),
       bit 8 worker inside the think, bit 9 faulting thread is the tick thread, bit 10 faulting thread is the AI worker,
       bit 11 repeat of an already seen (code, EIP) signature (no dump, no launcher handshake), bits 12..13 dump state
       (0 none, 1 in progress, 2 written, 3 failed), bits 14..15 minidumps taken so far in this process, bits 16..31 low 16 bits of
       the dump error (GetLastError / HRESULT), 8..23 the first 16 in-image return-address candidates found scanning upward from
       ESP (preferred-base VAs; a word counts when a call instruction (E8 rel32 / FF /2 forms) ends right before it, the profiler's
       decoder), 24 ESP, 25 EBP, 26 EAX, 27 ECX, 28 EDX, 29 ESI, 30 EDI, 31 launcher acknowledgement written by the launcher through
       WriteProcessMemory: (count & 0xFFFF) | dump_state << 16 | 0x80000000 of the last state it has printed (the faulting thread
       waits up to ~750 ms for it, twice, so the launcher sees the record before the game exits). Dumps:
       F:\NTW2\translated_code\analysis\crashdumps\kntwr-<pid>-<n>.dmp. */
    uint32_t crash_words[32];
    /* KNTWR_BRAIN (requires KNTWR_PROFILE; all zero otherwise and until a tick ran; wraps modulo 2^32; reset at every activation).
       The 23 registry vtables' slot +0x0C (the per-entity brain step the loop 0x585D10 calls) is published as a timed entry site
       per family (trace sites 46..50, see KNTWR_SITE_CALLEE_VAS), the class wrappers and the brain run as private clones whose every
       call is a timed site. Words: 0 routed ticks while armed, 1 sum of those tick durations us, 2..7 reserved,
       then, for family f in 0..4 and site s = trace site - 46 in 0..48, at 8 + 2*(f*49 + s): inclusive us and calls of that site
       while the family f was executing. Entry site s = f counts the entities of family f (calls) and their whole [vt+0x0C] time;
       sites 5..18 (trace 51..64) are the wrapper callees and belong to their family only (51..55 family 2, 56..58 family 3,
       59..64 family 4); sites 19..48 (trace 65..94) are the brain's own callees, attributed to the family whose entry encloses
       them. Inclusive means enter-to-return of each call, so rows overlap and every timed call adds its own timing overhead to
       the enclosing rows. Sites run only on the tick-owner thread inside a routed tick; elsewhere they pass through untimed. */
    uint32_t brain_words[KNTWR_BRAIN_WORDS];
    /* BRAIN2 v2 attribution rows retain their byte positions. Layout is declared
       by src/brain2/native_brain2.h; no worker/replay counters remain. */
    uint32_t brain2_reason_words[32];
    uint32_t brain2_gate_words[80];
    /* Same-tick AI telemetry, modulo 2^32, reset at activation:
       0 jobs dispatched, 1 barrier wait us sum, 2 timeouts (zero), 3 jobs spanning ticks (zero),
       4 max windows/job (one after a dispatch), 5 lifecycle cancellations (zero),
       6 OS-suspended worker (always zero), 7 worker thread id.
       The worker sleeps on an event when idle. No deadline can release a live native stack.
       Tick duration includes its completion barrier; ai_completion_words provides duration histograms. */
    uint32_t ai_slice_words[8];
    /* Retained top-level validation ABI row, now zero. A same-tick call uses the caller's live object;
       no manager-only check is treated as proof of the lifetime of subordinate receivers. */
    uint32_t ai_validation_words[8];
    /* KNTWR_VISUAL: main-thread 0x779E60 loop 1, independently gated by enabled mask and owner/inflight acquisition,
       NOT by a tick-thread epoch. Counters wrap modulo 2^32 and reset at every kntwr_start; without work all are zero
       except word 13, which is live slot metadata, not a work counter (retained after stop).
       0 calls entered, 1 sharded calls completed (a pool worker actually claimed a chunk), 2 inline calls completed,
       including caller-only dispatches. A monitor snapshot can observe an in-flight call: word 0 is not a completion fence.
       3 items_sum, 4 chunks, 5 sum_us_sharded, 6 sum_us_inline, 7 max_us, 8 faults, 9 last fault EIP,
       10 last fault address, 11 last fault item (raw items[i] record pointer), 12 last fault index,
       13 slot_va (relocated VA of the published slot), 14 native per-worker arena epochs,
       15 inline fallbacks because an arena already belonged to a native parallel epoch, 16..31 reserved.
       Activation requires exactly one .rdata word equal to relocated 0x779E60; error 13 reports the hit count
       in error_detail on zero/multiple matches. A foreign published-slot value is error 6, never overwritten.
       Before sharding, the caller runs 0x75D280's per-frame reset once, then enables the same three
       arenas as 0x770850..0x770888 through 0x7C9350. A host provider supplies one stable index per
       pool thread plus caller index 0; 0x10E9DC0 gives each index a private chunk and locks only growth.
       After the join, native serial mode is restored before the original tail; arena buffers remain game-owned.
       Experimental, opt-in in practice: live performance is unverified. */
    uint32_t visual_words[32];
    /* Worker-start allocator admission, reset at kntwr_start and retained after stop/failure.
       32 rows of 8 words: pool slots 0..30, AI worker 31. Each row:
       0 result (0 not attempted, 1 allocation+free succeeded, otherwise failing stage:
         2 TLS lookup, 3 allocation/lazy static initialization, 4 null allocation, 5 free; bit 8 = SEH fault),
       1 thread id, 2 pre-probe executable CRT TLS epoch, 3 post-probe CRT TLS epoch,
       4 exception code, 5 exception EIP (preferred VA inside image), 6 exception access address,
       7 executable CRT TLS index. Admission failure uses error KNTWR_ERROR_ALLOCATOR and
       error_detail = (row << 16) | result; no game-code hook is activated on failed admission.
       The callback runs once per worker lifetime, not once per job: 0x444B40(16) initializes through
       the ordinary allocation path, then 0xFF7EF0 frees it. FF7F20's TLS is a static-init epoch, not
       an arena; the allocator is an explicit argument. This probe does not prove animation arena
       ownership or concurrency safety. Standalone numerical pools need no callback. */
    uint32_t allocator_words[KNTWR_ALLOCATOR_WORDS];
    /* Append-only slice-location counts, reset on activation: 0 slice_at_site34 (successfully resumed jobs),
       1 slices_at_end (must remain zero; tick-end slicing was removed). No pending job means neither count advances. */
    uint32_t ai_slice_site_words[2];
    /* Brain-state census: KNTWR_BRAIN, tick-owner only, cumulative modulo 2^32, reset on activation.
       Samples the actual 0x66CE00 entry/return (46/47 direct; 55/56/59 inside wrappers), not wrapper pre/post work.
       Header: 0 routed ticks, 1 entries, 2 entry predicate (+EC byte==0 && +1B8 dword==0x4B),
       3 active +30 byte nonzero on entry and zero on return, 4 entry engage +F0 byte!=0,
       5 entry unit!=null && unit+AA0 dword!=0 (combat proxy, NOT a proven combat flag),
       6 entries with null unit, 7 sum of distinct nonnull units per tick, 8 entry state 0x4B / return state!=0x4B,
       9 sum of distinct transitioning nonnull units per tick, 10 transitioning entries with null unit,
       11 unit-set storage failures (nonzero invalidates distinct-unit totals), 12..15 reserved.
       16..79: entry-state counts; buckets 0..61 = state 0..0x3D, 62 = 0x4B, 63 = all other states.
       80..159: entry +1D8 dword counts; buckets 0..78 exact, 79 = >=79 (dispatcher normally 0..0x48).
       160..223: 0x4B -> return-state entity counts, same state buckets.
       224..287: distinct nonnull units per tick for each transition destination bucket (a unit may appear in several).
       Predicate count is NOT actual early returns: the three virtual predicates may veto that path.
       Combat proxy evidence: 0x66D55F tests unit+AA0 before setting agent+F0 at 0x66D56A.
       Shares divide by entries; per-tick averages divide by word 0. With BRAIN2 enabled the profiling slots
       are not published, so ticks can be nonzero with zero entries. No game object is modified by this census. */
    uint32_t brain_state_words[KNTWR_BRAIN_STATE_WORDS];
    /* Explicit --collide-census + PROFILE census, cumulative since activation, modulo 2^32; zero unless both enabled, or with COLLIDE.
       0 routed ticks (including ticks not entering this stage), 1 records queried (including inactive early-outs),
       2 reuse stage calls, 3 rebuild stage calls, 4 sum of returned u16 ID-list lengths,
       5 candidate pairs reaching the first post-dedup filter (successful 0x56EE80 appends),
       6 accepted contacts (each executes all eight accumulator writes), 7 redistribution events,
       8 label-propagation pairs (two stores/event), 9 label values changed (unequal input labels),
       10 direct type-8 callbacks from COLLIDE_Q, 11 resolved 0x64CC70 -> argument vt+40 == 0x64CAD0,
       12 resolved 0x808EF0, 13 inclusive stage us, 14 traversal/filters/overhead us (stage minus 15 and 16),
       15 numeric-region us (0x81A8F1 through rejection or 0x81AC2E; includes oriented helper and writes),
       16 inclusive callback us, 17 inclusive query us, 18 u16 append us, 19 oriented-helper us,
       20 numeric regions entered, 21 stage calls, 22 maximum returned ID-list length,
       23 timed-site stack overflows (nonzero invalidates census completeness),
       24 0x64CC70 forwarding to a different vt+40 target, 25 other direct vt+44 targets,
       26 oriented-helper calls; 27..31 reserved. Recursive callbacks inside native callback bodies are
       included in time, not counted again. Sites 106..109 time query/append/helper/callback respectively.
       Times sum raw QPC deltas before conversion (unlike trace's per-call integer-us rounding).
       All measurements include instrumentation perturbation; 17..19 nest within 13..15, not extra time. */
    uint32_t collision_words[KNTWR_COLLISION_WORDS];
    /* Experimental COLLIDE solver; counters cumulative modulo 2^32 since activation; zero when disabled.
       0 stage calls, 1 solver ticks, 2 fallback ticks, 3 capacity fallbacks, 4 layout fallbacks,
       5 sticky fallbacks, 6 queried worklist records, 7 occupied CSR cells, 8 pairs, 9 contacts, 10 callbacks,
       11 gather us, 12 bin us, 13 pairs us, 14 private reduction + owner commit/second-pass us,
       15 worklist/rebuild-plan us, 16 stage us,
       17 maximum stage us, 18 faults, 19 rebuilds, 20 redistributions, 21 label changes,
       22 worker chunks, 23 inline chunks, 24 maximum pairs, 25 maximum records,
       26 active unsupported-record native queries, 27 pool fallbacks, 28 arena fallbacks,
       29 last exception code, 30 postcommit owner continuations, 31 eligible queries (R+30 != 0 and flags&3).
       32..41 first offending node snapshot per activation, not counters:
       32 reason, 33 known context record index (131072 = none), 34 node address, 35 node type,
       36 known current record vtable (+0), 37 node owner, 38 node payload, 39 full node ID,
       40 cell index (UINT32_MAX = unmappable), 41 expected record address.
       Reason 0 = no diagnostic; 1..6 = OwnType, OwnId, OwnPayload, OwnOwner, OwnCell, OwnCoverage;
       7..14 = ChainType, ChainPrevious, ChainCell, ChainOwner, ChainPayload, ChainId, ChainArray, ChainCount.
       Chain context is the first known record occupying the cell, not a foreign owner's registry slot.
       The vtable never dereferences an unvalidated foreign owner. Snapshot values are not per-tick averages.
       42 original per-record calls for unsupported records,
       43 cumulative marked unsupported cells (once per cell per stage).
       44..60 are APPENDED (words 0..43 keep their offsets):
       44 shaped pairs = calls to original 0x81A670, counted only when at least one shape pointer is nonnull; unshaped circle
          pairs bypass the leaf with the exact same radius threshold and are not counted.
       45 gather, 46 bin, 47 pairs, 48 apply, 49 worklist/rebuild-plan = THREAD CPU us (GetThreadTimes user+kernel,
          aggregated over owner + workers; counterparts of wall words 11, 12, 13, 14, 15).
       50 audit wall us (nested in 12 bin), 51 store, 52 redistribute, 53 callback, 54 reduction wall us (51..54 nested in 14 apply).
       55 thread-clock failures (GetThreadTimes calls that failed; nonzero = thread CPU totals incomplete),
       56 store, 57 redistribute, 58 callback, 59 reduction, 60 audit = thread CPU us (counterparts of 51, 52, 53, 54, 50).
       Wall words (11..16, 50..54) are QPC elapsed (17 is a maximum). Thread words are CPU time, summed over threads: they may exceed wall time
       with parallel workers and are NOT sums of elapsed QPC. Thread-time resolution is coarse (scheduler-accounting granularity),
       so one stage's value is meaningless; aggregate many solver ticks. Nested sub-timers (audit within bin; store, redistribute,
       callback, reduction within apply) are not additive to their parent or to stage again; apply minus its sub-timers is
       remainder (including native record-local query internals in mixed stages).
       Normalize per-phase cost by word 1 (actual solver ticks), NOT word 0 (calls, which include fallbacks).
       Unsupported nodes mark affected cells; every query touching them runs untouched 0x81A790 on owner.
       Snapshot first-seen IDs feed the original BFS algorithm; its permutation is published before callbacks.
       Word 2 counts whole-stage fallback or a fault-marked postcommit owner-continuation stage.
       Word 1 counts completed replacement stages, including mixed or all-native record-local work.
       Words 8..10 count solver-emitted pairs/contacts/callbacks only, excluding native query internals.
       Inspect word 42, not just word 1, when judging solver usage or speedup.
       Stop retains all words; a new activation resets them.
       Word 15 times planning/preflight, including reuse slot mapping. Word 14 spans private reduction, owner numeric scatter,
       redistribution/MAX and callbacks. Fully supported stages: ordered live redistribution + conditional sequential unsigned
       MAX over private labels first, then ONE parallel store pass committing numeric sums, dirty final labels and processed
       bytes together, then a serial timed callback pass; callbacks see final processed bytes, velocities, labels and all solver
       numeric sums. Mixed stages with unsupported records parallel-commit numeric sums before the original-interleaved owner
       replay (per-record native query/processed progression with interleaved redistribution/callbacks; the native query depends on
       +0x40); supported timers split exactly, mixed solver pair calls are timed individually and native query internals remain
       in the apply remainder.
       The native chain audit is a parallel READ-ONLY pass over disjoint cells inside the active epoch (AI joined); per-chunk SEH
       makes a fault a whole-stage fallback before any game write.
       CSR/incidence grouping: bounded-key direct-address cell->dense-id hash (only previous occupied keys cleared, no full-grid pass),
       compact per-lane histogram slab (lanes = workers + owner, bounded 32; reduced adaptively for extreme dense-key counts), one
       prefix and a stable incoming scatter; the audit supplies the native-order CSR scatter. This replaces the two-pass radix.
       Commit stores run on workers only after all read-only preparation; a store fault propagates (no rollback/restart).
       COLLIDE takes priority over the PROFILE original-stage census; use this array for solver work.
       Numerical/order tolerance is specified by the differential oracle, not inferred from these counters. */
    uint32_t collide_words[KNTWR_COLLIDE_WORDS];
    /* BRAIN2 v2 owner-serial counters, modulo 2^32, reset at activation.
       The 48-word row keeps its original offset and size; word 0 identifies v2.
       Layout: src/brain2/native_brain2.h. Service bookkeeping is opt-in and QPC
       is independently off by default. Native faults propagate: a partially
       executed occurrence is never retried. */
    uint32_t brain2_words[KNTWR_BRAIN2_WORDS];
    /* COLLIDE_LOD: reset at activation, all zero until a stage. Counts wrap modulo 2^32.
       0 stages gated, 1 records seen, 2 records skipped, 3 latest units, 4 latest far units,
       5 rebuild stages forced full-rate, 6 D_far metres, 7 max proximity us, 8 sum proximity us,
       9 faults (SEH or unsafe capacity/geometry), 10 sticky disabled, 11 reuse far records seen,
       12 unknown records seen, 13 reuse stages, 14 all-far/multiple-army stages forced full-rate,
       15 latest different-side unit pairs (original +0x44 pointer comparison). No processed-byte writes on skips.
       Word 4 reports classification before the all-far sanity refusal, not permission to skip. */
    uint32_t collide_lod_words[KNTWR_COLLIDE_LOD_WORDS];
    /* Opt-in KNTWR_AI_CTRL jobs; modulo 2^32, reset at activation:
       0 dispatched, 1 completed, 4 sum_us, 5 max_us, 6 max slot occupancy (one),
       11 site-33 barriers, 15 current slot occupancy; other retained indices are zero.
       A controller joins before its following planner can read the rebuilt node arrays. */
    uint32_t ai_ctrl_words[16];
    /* Retained budget ABI row, now zero: there is no time-budget suspension policy. */
    uint32_t ai_slice_budget_words[KNTWR_AI_SLICE_BUDGET_WORDS];
    /* Retained parking ABI row, now zero: no SuspendThread, EIP polling, or unsafe-park valve. */
    uint32_t ai_park_words[8];
    /* Opt-in KNTWR_LOCO (timed site 13, ACTIVE clone's call of 0x531AF0); APPENDED after ai_park_words, every earlier offset is unchanged.
       Reset at every activation, wraps modulo 2^32, all zero without the feature; the retained values of the last generation stay readable after stop.
       Word order is src/loco/native_loco.h kntwr_loco::Word (labels KNTWR_LOCO_WORD_LABELS): 0 layout version, 1 stage calls, 2 entity occurrences,
       3 admitted, 4 rejected, 5..14 first-rejection reasons (class, lifetime, activity, target, parked, pending, charge_fire, posture_order,
       node, environment); activity/target/charge_fire/posture_order/node are retained ABI buckets but always zero for serial MOVE.
       15..18 branch census (battle wrapper, alternate wrapper, direct, staging), 19..24 admitted/rejected/dispatch
       sum and max microseconds, 25 max entities in one stage, 26 active-byte filtered, 27 executed through the clone, 28 executed through the
       original, 29..31 owner service calls / max per entity / serviced entities, 32..39 per-service counts (unlink_grid, unlink_owner,
       insert_owner, insert_grid, sweep, resolve, height_owner, wrapper_query), 40 service trace overflow, 41 class-wrapper occurrences,
       42 emitted LOCO clone bytes, 43 generation, 44 clone execution enabled (KNTWR_LOCO_CLONE), 45 latest Stage owner thread id (no permanent owner latch), 46 re-entry refusals,
       47 reserved. Native publication/services remain owner-only; optional closed movement workers use private state.
       No speculative native execution or retry. Off-epoch ticks run the original 0x531AF0 and do not touch these counters. */
    uint32_t loco_words[KNTWR_LOCO_WORDS];
    /* Independent all-gates diagnostics for the same serial owner MOVE occurrences; appended without changing loco_words.
       Reset at start/activation, modulo 2^32; all zero when disabled, retained after stop. Order/labels: native_loco.h GateWord / KNTWR_LOCO_GATE_LABELS.
       0 layout version, 1 entities (all active +0x30 occurrences), 2 recognized candidates, 3 serial admitted, 4 enforced reason mask
       (bit reason-1: Class=1, Lifetime=2, Parked=5, Pending=6, Environment=10 => 0x233).
       5..14 independent failures of the ten old diagnostics in first-rejection order, evaluated fully for recognized candidates.
       15..18 nonzero DWORDs +0x4E8/+0x390/+0x3BC/+0x3C8 (ChargeFire), 19 posture +0x220, 20 order, 21 slot row, 22 reference node,
       23..24 holders +0x2CC/+0x51C, 25..31 activities 0/1/9/0x1D/0x23/0x0C/other, 32..35 corroborating byte latches
       +0x618/+0x619/+0xF1/+0x5AB (not ChargeFire), 36 unclassified (no soldier-field reads), 37 diagnostic faults,
       38 legacy admitted (all ten diagnostics clear), 39 newly admitted (serial admitted with a removed diagnostic failing), 40..47 reserved.
       Failures/details overlap and are NOT summable to entities; entities is the all-gates denominator, candidates the detailed-field population.
       Activity/target/fire/posture/order/node/holder diagnostics do not exclude serial MOVE. This is not NODE or worker admission. */
    uint32_t loco_gate_words[KNTWR_LOCO_GATE_WORDS];
    /* Inclusive owner-service QPC timings, appended without changing either 48-word LOCO row.
       Reset at start/activation, retained after stop; all zero without LOCO. Order/labels:
       native_loco.h ServiceWord / KNTWR_LOCO_SERVICE_LABELS. 0 version (1 while LOCO active),
       1 timing enabled (use_clone); observe-only has no timing work. 2 timed calls, 3 stack overflows,
       4 abandoned frames, 5 clone wall us, 6 outermost-service union us, 7 outside-service us,
       8 max depth, 9 QPC failures, 10..11 reserved; 12..19 inclusive service us, 20..27 service max us,
       28..35 completed timed service calls, 36..39 reserved. Service order matches loco_words[32..39].
       Raw QPC ticks accumulate before conversion at sampling; exported words wrap modulo 2^32.
       Inclusive service sums overlap; union counts only outermost brackets. Outside is clamped
       clone wall minus union, not pure arithmetic: it includes untapped native work and instrumentation
       outside service brackets. Gate/stage overhead outside the clone wall is not part of this residual.
       Ratios use cloned occurrences (loco_words[27]), stage calls (loco_words[1]), or each service's
       completed timed calls, not all entity occurrences or the attempted service census. */
    uint32_t loco_service_words[KNTWR_LOCO_SERVICE_WORDS];
    /* Retained grid geometry/oracle diagnostics. Stage C publishes owned grid v2 only at stage exit with GRID or GRID_VERIFY;
       ReadGrid/CaptureGrid remain public geometry-build oracle seams, not native-chain imports. New build/verification metrics are in loco_grid_v2_words.
       Reset at start/activation, retained after stop, zero without LOCO; without GRID only version=1 remains. GridWord / KNTWR_LOCO_GRID_LABELS:
       0 version, 1 captures, 2 records, 3 primary, 4 secondary, 5 memberships, 6 cells, 7 mismatches,
       8 sampled records, 9 births, 10 removals, 11 reused addresses, 12 capture us, 13 CSR us, 14 faults,
       15 refusals, 16 generation, 17 epoch, 18 bytes, 19 max records, 20 max memberships,
       21 native-order cells, 22 unsupported nodes, 23 deactivations, 24 membership removals,
       25..31 reserved. Counters wrap modulo 2^32; inserted==0 records have no memberships. */
    uint32_t loco_grid_words[KNTWR_LOCO_GRID_WORDS];
    /* Stage B private-state closed movement workers; ParallelWord / KNTWR_LOCO_PARALLEL_LABELS.
       Reset at start/activation, retained after stop, zero without LOCO. 0 version, 1 enabled,
       2 chunks, 3 worker entities, 4 owner entities, 5..11 needs env/sweep/resolve/class-wrapper/relationship/staging/duplicate,
       12 replayed services, 13 capture us, 14 CSR us, 15 kernel us, 16 replay us, 17 staging us,
       18 faults, 19 sticky, 20 inline chunks, 21 invalidated, 22 last exception, 23 max worker run,
       24 committed, 25 native fallbacks, 26 needs admission; first-fault snapshot 27 entity, 28 ordinal,
       29 EIP, 30 access address (0 when unavailable), 31 full serial. Counts/us wrap modulo 2^32.
       Worker entities include caller-executed kernels. Needs env/sweep/resolve overlap and describe unclosed
       closures, not actual helper-call counts. Only A1==0/no-publication occurrences are worker-certified.
       Unexpected recorded link events refuse before commit; replayed services is normally zero.
       Staging us brackets cloned-selector 7FC120 entry through 7F7140 return, excluding cold initialization
       and original-only selectors. Sweep/resolve/environment remain owner-only unless KNTWR_LOCO_OWNED_SERVICES; Stage C borrows the separately published grid. */
    uint32_t loco_parallel_words[KNTWR_LOCO_PARALLEL_WORDS];
    /* Owner-thread shadow oracle, never authoritative gameplay results. Labels in native_sweep.h/native_resolve.h. */
    uint32_t sweep_words[KNTWR_SWEEP_WORDS];
    uint32_t resolve_words[KNTWR_RESOLVE_WORDS];
    uint32_t env_words[KNTWR_ENV_WORDS];
    /* Three top-eight VA/count rows: owner+24, owner+1C virtual0, notification+8.
       48..50 distinct targets, 51..53 observed policy/predicted notification counts; 54..63 reserved. */
    uint32_t env_target_words[KNTWR_ENV_TARGET_WORDS];
    uint32_t resolve_frame_words[KNTWR_RESOLVE_FRAME_WORDS];
    /* Owned-service mover diagnostics appended after resolve_frame_words; OwnedWord / KNTWR_LOCO_OWNED_LABELS in native_loco.h.
       Reset at start/activation, retained after stop, zero without LOCO. Counts/us wrap modulo 2^32. Requires KNTWR_LOCO_OWNED_SERVICES (word 1 = enabled).
       Word 27 counts entity-range chunks claimed atomically by the pool (one dispatch per stage); word 28 counts duplicate refusals. */
    uint32_t loco_owned_words[KNTWR_LOCO_OWNED_WORDS];
    /* Owned-service mover detail tail appended after loco_owned_words; native_loco.h OwnedDetailWordCount / SampleOwnedDetails / KNTWR_LOCO_OWNED_DETAIL_LABELS.
       Reset at start/activation, retained after stop, zero without LOCO. Counts wrap modulo 2^32.
       0 version, 1 quiet_enabled (KNTWR_LOCO_QUIET), 2 staging_initial_a3_zero, 3 staging_result_a3_zero, 4 staging_clamp_callback,
       5 actual_class_wrapper, 6 other_class, 7 actual_alternate_wrapper, 8 unit_blocked_class, 9 unit_blocked_staging, 10 unit_blocked_other,
       11 observed_f0, 12 worker_f0, 13 observed_initial_a3_zero, 14..15 reserved.
       Quiet disables loco_service_words work/timing (word 1 = 0), all-gates work counters (version 1 and enforced mask 0x233 retained) and shadow
       comparisons; basic fault/share counters (loco_owned_words) remain. */
    uint32_t loco_owned_detail_words[KNTWR_LOCO_OWNED_DETAIL_WORDS];
    /* Owned phase timing appended after the detail row; native_loco.h OwnedPhaseWord / KNTWR_LOCO_OWNED_PHASE_LABELS.
       Reset at start/activation, retained after stop; all zero without owned services. 0 version=1 when owned enabled,
       1 dispatches, 2 chunks, 3 list entities, 4 max chunk entities, 5..12 chunk-duration histogram (<=16/32/64/128/256/512/1024/>1024 us),
       13 index us, 14 scene identity-check us, 15 catalog prepare us (zero after activation), 16 per-stage worker FP-control prepare us, 17 dispatch wall us, 18 replay loop us,
       19 replay commit estimated us, 20 replay fallback estimated us (x16 estimates from every 16th occurrence), 21 replay samples,
       22 unprocessed, 23 validation refusals, 24 chunk time sum us, 25 computed, 26 worker refused, 27 participants used,
       28 last chunk size, 29 participant overflow, 30..31 reserved. Counts/us wrap modulo 2^32; phase timers remain under quiet. */
    uint32_t loco_owned_phase_words[KNTWR_LOCO_OWNED_PHASE_WORDS];
    /* Owned activation/load diagnostics; native_loco.h OwnedLoadWord / KNTWR_LOCO_OWNED_LOAD_LABELS.
       Append-only, reset at Start, retained after Stop; all zero without owned services. Counts/us wrap modulo 2^32.
       0 version, 1 activation calls, 2 activation us, 3 scene us, 4 catalog us, 5 participants us, 6 arena us,
       7 model changes, 8 capacity refusals, 9 chunk CPU us, 10 max chunk wall us, 11 CPU us for that chunk,
       12 activation failure reason (native_loco.h OwnedActivationFailure), 13 structured exception code or
       ERROR_NOT_ENOUGH_MEMORY for C++ bad_alloc, 14 mismatch/fault address, 15 mismatching actual word.
       All four are zero on successful activation. The failure reason is the failing phase, including when that phase throws.
       Scene/catalog capture runs at a quiescent tick boundary; arena/participant prefault and clone warmup remain on the monitor.
       All preparation is activation-only; Stage never grows it. */
    uint32_t loco_owned_load_words[KNTWR_LOCO_OWNED_LOAD_WORDS];
    /* Owned grid v2 diagnostics; native_loco.h KNTWR_LOCO_GRID_V2_LABELS. Appended without moving any prior row.
       Layout: 0 version (2 while LOCO is active), 1 enabled, 2 verify_enabled, 3 builds, 4 build_us, 5 max_build_us, 6 records, 7 memberships,
       8 verify_mismatches, 9 verify_us, 10 dispatches, 11 committed_records, 12 record_reads, 13 refusals, 14 faults, 15 epoch; counters wrap modulo 2^32.
       Reset at Start, retained after Stop; phase words above remain the movement measurement. */
    uint32_t loco_grid_v2_words[KNTWR_LOCO_GRID_V2_WORDS];
    /* Collision source: 0 none, 1 native-audit, 2 owned; then native_stages, owned_stages, owned_refusals.
       Reset at Start, retained after Stop; no stage means all four words are zero. */
    uint32_t collide_source_words[KNTWR_COLLIDE_SOURCE_WORDS];
    /* Activation-sized retained storage and process VA telemetry, reset on Start and retained on Stop.
       KNTWR_MEMORY_WORD_LABELS / kntwr_memory_word specify indices. *_bytes count owned allocation
       payloads/VirtualAlloc reservations plus module image and explicit thread stack reservations;
       CRT heap rounding and unrelated game/driver allocation are not attributed to a module.
       ullAvailVirtual is measured by GlobalMemoryStatusEx (lo/hi pairs), not inferred from that sum.
       Activation and each large reservation require >=256MiB remaining total VA (KNTWR_MEMORY_MIN_AVAIL_VIRTUAL)
       and largest_free_hole >= 128MiB (KNTWR_MEMORY_MIN_LARGEST_HOLE); the post-allocation
       check precedes feature publication. min_avail and min_largest_hole are sampled at activation and once/second.
       Capacity growth refuses before writes, never reallocates in a tick.
       Version 2 appends indices 28..43 without moving any version-1 word.
       Version 3 appends native grid shift/inclusive clamp/dimension and catalog backing bytes/counts.
       Version 4 appends hole_floor_bytes, min_largest_hole (bytes) and latch_reason (1 total, 2 hole).
       Catalog's first five byte categories sum to loco_catalog_bytes; counts are unique retained geometry.
       cell_capacity is the address span ((clamp<<shift)+clamp+1), including any stride padding.
       Periodic VA below floor_bytes or largest hole below hole_floor_bytes on 2 consecutive samples
       latches LOCO/COLLIDE native fallback until next Start; once the
       tick owner drains, their allocations are released without stopping other features.
       active_mask excludes these bits. Released bytes and the last allocated LOCO
       breakdown remain diagnostic; loco_bytes/collide_bytes become zero after release. */
    uint32_t memory_words[KNTWR_MEMORY_WORDS];
    /* Same-tick completion telemetry; appended after memory v3, never shifts an earlier status word.
       0..2 planner count/sum us/max us; 3..5 barrier count/sum us/max us (includes opt-in controllers).
       6..14 planner duration histogram; 15..23 barrier-wait histogram. Each histogram is disjoint:
       <=8, (8,16], (16,32], (32,64], (64,128], (128,256], (256,512], (512,1024], >1024 ms.
       Counts/sums wrap modulo 2^32; reset at activation. max_planner_us excludes old between-tick parks.
       Polls are observational: the worker can update a row while status is being copied. */
    uint32_t ai_completion_words[KNTWR_AI_COMPLETION_WORDS];
    kntwr_grid_census_status grid_census; /* Append-only; canonical profiler/trace ABI unchanged. */
    /* AI mutation census (KNTWR_AI_CENSUS): zero without the feature. Version 1 layout, all words LE uint32:
       header[16]: version, targets(7), caller_capacity(256), callers_used, top_per_target(8), calls, callers_dropped, slots_owned,
       slot_count(12), ranges(3), sample_attempts, sample_outside, ticks, calls_in_tick, calls_outside_tick, reserved.
       target rows (7, stride 104): [original_va, slots, total, class0..3, dropped] then 8 caller rows (stride 12):
       [caller, kind, count, class0..3, top_site, top_site_count, outside_tick_count, second_site, second_site_count].
       Classes: 0 tick owner, 1 AI worker, 2 main/render, 3 other. Site codes: 0 outside tick, 1 in tick with no timed site, 2+i timed site i.
       Caller kind 0 = RVA in the main image, 1 = offset in the AI_CONTROLLER clone (source VA 0x7C8BD0 + offset), 2 = raw return address.
       range rows (3, stride 8): [va, end, samples, class0..3]. Rows are in the order of src/ai/kntwr_ai_census.h. */
    uint32_t ai_census_words[KNTWR_AI_CENSUS_WORDS];
    /* BRAIN2 v2 service rows: calls, active, unresolved, inactive,
       first-active occurrences, first-unresolved occurrences, QPC ticks low/high.
       Append-only; service IDs and inactive proofs: src/brain2/native_brain2.h. */
    uint32_t brain2_census_words[KNTWR_BRAIN2_CENSUS_WORDS];
    /* Owner-only shadow rows. Never authorize worker execution or fake-node installation.
       Reset at activation, retained after stop; module headers declare word/event layouts. */
    uint32_t node_words[KNTWR_NODE_WORDS];
    uint32_t node_event_words[KNTWR_NODE_EVENT_WORDS];
    uint32_t fire_words[KNTWR_FIRE_WORDS];
    /* Driver selection and reached generic node slots, independent of reference
       class admission. Layout: native_brain2.h RouteWord; configured vs actual
       driver distinguish activation intent from a reached dynamic call. */
    uint32_t brain2_route_words[KNTWR_BRAIN2_ROUTE_WORDS];
    /* Commit refusal guard split and call-site witnesses; native_fire.h CommitWord.
       Separate tail preserves existing fire and route row offsets. */
    uint32_t fire_commit_words[KNTWR_FIRE_COMMIT_WORDS];
    /* Concrete descriptor-move node (vtable 01348B44), distinct from reference
       node_words; the same node-shadow switch enables both owner-only ports. */
    uint32_t move_node_words[KNTWR_MOVE_NODE_WORDS];
    uint32_t move_node_event_words[KNTWR_MOVE_NODE_EVENT_WORDS];
    /* Version/distinct/overflow/reserved, top8 begin (VA,count), top8 step pairs. */
    uint32_t brain2_node_target_words[KNTWR_BRAIN2_NODE_TARGET_WORDS];
    /* Per-class owner shadows: idle [133405C,1334028], action
       [1347270,1348D2C,1348CC4]. Existing target/status offsets are unchanged. */
    uint32_t idle_node_words[KNTWR_IDLE_NODE_CLASSES][KNTWR_NODE_WORDS];
    uint32_t idle_node_event_words[KNTWR_IDLE_NODE_CLASSES][KNTWR_NODE_EVENT_WORDS];
    uint32_t action_node_words[KNTWR_ACTION_NODE_CLASSES][KNTWR_NODE_WORDS];
    uint32_t action_node_event_words[KNTWR_ACTION_NODE_CLASSES][KNTWR_NODE_EVENT_WORDS];
    /* BRAIN2 census tail (native_brain2.h UnknownSiteSnapshot): Unknown-row unresolved
       (site, target, calls) top16, first-unresolved-gate-per-occurrence top16, then the
       site-6 dispatch witness words. Reset at activation, retained after stop. */
    uint32_t brain2_unknown_site_words[KNTWR_BRAIN2_UNKNOWN_SITE_WORDS];
    /* BRAIN2 Stage 2 worker/commit telemetry (--brain-parallel); layout and labels in
       src/brain2/native_brain_workers.h (KNTWR_BRAIN_WORKER_WORD_LABELS / ..._REASON_LABELS).
       Words 0..47 summary, 48..65 refusal reasons, 66..118 refusing services (brain2 Service order),
       119..123 speculated_unwalked / late_activations / region_queries / witness_dep_misses / witness_dep_overflow,
       124..127 rng_worker_draws / rng_owner_draws / rng_lcg_advance / rng_owner_unmatched (version 2; RNG streams)
       (KNTWR_BRAIN_WORKER_TAIL_LABELS), 128..143 guard-miss attribution (version 3; KNTWR_BRAIN_WORKER_GUARD_LABELS).
       Zero without the feature; reset at activation, retained after stop. */
    uint32_t brain_worker_words[KNTWR_BRAIN_WORKER_WORDS];
    /* KNTWR_AI_ASYNC2 (appended): live-graph async think telemetry; KNTWR_AI_ASYNC2_LABELS order, layout src/ai/kntwr_ai_async2.h.
       Counters wrap modulo 2^32; written concurrently by tick, worker and gated threads (interlocked), so a poll is a
       non-atomic snapshot. All zero without the feature; reset at activation, retained after stop. */
    uint32_t ai_async2_words[KNTWR_AI_ASYNC2_WORDS];
    /* BRAIN2 Stage 2 phase row (appended; --brain-parallel, --brain-quiet): owner capture/commit/owner-run and worker
       capture/clone/publish microseconds, region-query counts, guard-miss writer relation and crew-dependency counts;
       KNTWR_BRAIN_WORKER_PHASE_LABELS order, layout src/brain2/native_brain_workers.h (PhaseWord). Zero without the
       feature; reset at activation, retained after stop. */
    uint32_t brain_worker_phase_words[KNTWR_BRAIN_WORKER_PHASE_WORDS];
    /* BRAIN2 per-unit brain Stage A (appended; --brain-unit-shadow): UnitDecision agreement per decided field, exception
       census and soldier vtable census; KNTWR_BRAIN_UNIT_* labels and layout in src/brain2/native_unit_brain.h (Word).
       Shadow only: nothing here changes a native write. Zero without the feature; reset at activation, retained after stop. */
    uint32_t brain_unit_words[KNTWR_BRAIN_UNIT_WORDS];
    /* COLLIDE contact responses (appended; --collide-contact-shadow / --collide-contact-workers): plan census,
       shadow agreement per predicted effect, replay counters, timers and avoidance-manager diagnostics;
       KNTWR_COLLIDE_CONTACT_WORD_LABELS order, layout src/collision/native_contact.h (Word). Zero without the
       flags; reset at activation, retained after stop. */
    uint32_t collide_contact_words[KNTWR_COLLIDE_CONTACT_WORDS];
    /* LOCO grid probation (appended; --grid-probation, KNTWR_LOCO_GRID_PROBATION): native soft-grid cell-head
       reader detector. 32 header words (layout kntwr_grid_probation::Word in src/loco/native_grid_probation.h,
       labels KNTWR_GRID_PROBATION_LABELS) then 256 caller rows of 8 words (kntwr_grid_probation::RowWord): image
       rows report preferred-base VAs, clone rows report the original instruction VA with the clone id in Where.
       Zero without the flag; reset at activation, retained after stop. */
    uint32_t grid_probation_words[KNTWR_GRID_PROBATION_WORDS];
    /* KNTWR_AI_ASYNC2 route/boundary row (appended): KNTWR_AI_ASYNC2_ROUTE_LABELS order, layout src/ai/kntwr_ai_async2.h
       (RouteWord). Written by the tick owner, the AI worker (private-clone entry counters, single writer) and gated
       threads; a poll is a non-atomic snapshot. All zero without the feature; reset at activation, retained after stop. */
    uint32_t ai_async2_route_words[KNTWR_AI_ASYNC2_ROUTE_WORDS];
    /* KNTWR_ARMY_UNIT_SHADOW (appended last): item 4 Stage A per-unit army update instrumentation; layout and labels in
       src/army/native_army_unit.h (Word, KNTWR_ARMY_UNIT_*_LABELS). Tick-owner writer; a poll is a non-atomic snapshot.
       Nothing here changes a native write. All zero without the feature; reset at activation, retained after stop. */
    uint32_t army_unit_words[KNTWR_ARMY_UNIT_WORDS];
    /* VA watch row (appended after army_unit_words; occupies the retired puppet probe row, so every later row keeps
       its offset). Layout: enum kntwr_va_word; always written, feature-independent. */
    uint32_t va_watch_words[KNTWR_VA_WATCH_WORDS];
    /* KNTWR_ARMY_UNIT_SHADOW, Stage B0 (appended after va_watch_words): qualification observers for an item 4 Stage B (FSM
       steps/transitions through the ARMY_UNIT clone's 58202E gate, formation queue/scratch, recorder pins, RNG member
       bound, own-state bytes, exclusive refusal cost). Layout and labels in src/army/native_army_unit.h (B0Word,
       KNTWR_ARMY_B0_LABELS). Tick-owner writer; reads only, no native write. Reset at activation, retained after stop. */
    uint32_t army_b0_words[KNTWR_ARMY_B0_WORDS];
    /* KNTWR_ARMY_STORM_CENSUS (appended after army_b0_words; occupies the four retired puppet motion/divert/mover/select rows,
       4 x 32 words, so every later row keeps its offset): the opt-in site-18 storm census row. Layout and labels in
       src/army/native_army_storm.h (Word, KNTWR_ARMY_STORM_LABELS). Tick-owner writer; reads only, no native write. All zero
       without the feature; reset at activation, retained after stop. */
    uint32_t army_storm_words[KNTWR_ARMY_STORM_WORDS];
    /* KNTWR_BRAIN_S0 attribution timer (appended after army_storm_words): 32 header words (calibration, stages,
       occurrences, site-6 cycles, TSC/QPC span) then 33 mechanic rows x 16 words (calls, sampled calls, nesting counts,
       inclusive/exclusive cycles and per-occurrence second moments). Layout and labels in src/brain2/native_brain_s0.h.
       The same 560 words carry the KNTWR_BRAIN_LOCALITY census instead while that flag (mutually exclusive with S0) is set:
       layout and labels in src/brain2/native_brain_locality.h (KNTWR_BRAIN_LOC_*). Tick-owner writer. Reset at activation,
       retained after stop. */
    uint32_t brain_s0_words[KNTWR_BRAIN_S0_WORDS];
    /* KNTWR_AI_ASYNC2 deferred schedule (appended after brain_s0_words; kntwr_config::ai_deferred): admissions, busy
       refusals, consumption (on time = at the first seam >= admission tick + K), abandonment, slices and budget hits,
       node revalidation, seam joins, per-kind node calls and microseconds, histograms of ticks spanned and slices per
       think. KNTWR_AI_DEFERRED_LABELS order, layout src/ai/kntwr_ai_async2.h (DeferWord). Written by the tick owner and the
       AI worker; a poll is a non-atomic snapshot. All zero without the flag; reset at activation, retained after stop. */
    uint32_t ai_deferred_words[KNTWR_AI_DEFERRED_WORDS];
    /* --ai-ctrl-* reuse telemetry (appended after ai_deferred_words; KNTWR_AI_CTRL_REUSE_LABELS): words 0..15 batch/histogram (kntwr_ai_ctrl::Word),
       words 16..23 geometry (kntwr_ai_ctrl_geometry::FillStatus) or, without --ai-ctrl-geometry, 16..19 --brain-target-cull / 20..23 --brain-retarget-jitter,
       words 24..31 --ai-claim-once. Tick-owner writer; reset at activation, retained after stop. */
    uint32_t ai_ctrl_reuse_words[KNTWR_AI_CTRL_REUSE_WORDS];
    /* LOCO relink apply (--loco-relink-shadow / --loco-relink-workers; appended after ai_ctrl_reuse_words; src/loco/native_loco.h KNTWR_LOCO_RELINK_LABELS,
       RelinkWord): mode 0 off / 1 shadow / 2 live, op/batch/flush-cause counts, owner log and apply times, pool dispatches, shadow mismatch counters.
       Tick-owner writer; reset at Start, retained after stop; all zero without the loco feature. */
    uint32_t loco_relink_words[KNTWR_LOCO_RELINK_WORDS];
    /* LOCO class-wrapper census + phase 2 (appended after loco_relink_words; src/loco/native_loco.h KNTWR_LOCO_CW_LABELS, CwWord; version 2): 0-23 shape of the
       0x132BA04 occurrences the workers refuse as needs_class_wrapper (pre-step, child count histogram, aim state, first four child vtables); 24-31 phase 2
       (--loco-cw-shadow / --loco-cw-workers): mode, admitted, events, refused_class, refused_gate, recheck_fallbacks, shadow_compares, shadow_mismatches.
       Owner-side, always on with --loco-owned-services; reset at Start, retained after stop. */
    uint32_t loco_cw_words[KNTWR_LOCO_CW_WORDS];
    /* LOCO owned-grid build (appended after loco_cw_words; src/loco/native_loco.h KNTWR_LOCO_GRID_BUILD_LABELS, GridBuildWord): 0 version, 1 mode (0 full / 1 incremental),
       2 full_builds, 3 incremental_builds, 4 changed_records (records whose cell rectangle changed, summed over incremental builds), 5 delta_hint_records (always 0: the site-13
       move delta is never consumed), 6..9 owner-QPC microseconds summed over successful builds: registry_us (serial registry compare/hash pass before dispatch 1),
       capture_wall_us (dispatch 1), plan_us (everything the owner does between and after the dispatches), build_wall_us (dispatch 2); 10 full_fallbacks (full builds of an
       incremental run), 11 last_fallback_reason (1 first/after a refused build, 2 registry changed, 3 geometry or rounding changed, 4 change-share backoff), 12 shadow_compares,
       13 shadow_mismatches, 14 dispatches (pool dispatches of the primary builds, native verification included), 15 registry_reuses (builds that shared the previous record
       array and hash). Tick-owner writer; reset at Start, retained after stop; all zero without the loco feature. */
    uint32_t loco_grid_build_words[KNTWR_LOCO_GRID_BUILD_WORDS];
    /* Per-unit brain slices (appended after loco_grid_build_words; --brain-unit-*): words 0..31 the shared admission/routing header
       (src/brain2/native_unit_policy.h KNTWR_UNIT_POLICY_HEADER_LABELS), 32..127 the fatigue half (src/brain2/native_unit_fatigue.h
       KNTWR_UNIT_FATIGUE_LABELS), 128..255 the posture/engage half (src/brain2/native_unit_posture_engage.h
       KNTWR_UNIT_POSTURE_ENGAGE_LABELS). Tick-owner writer; reset at activation, retained after stop; all zero without a unit flag. */
    uint32_t brain_unit_policy_words[KNTWR_BRAIN_UNIT_POLICY_WORDS];
    /* --ai-prepass-census / --ai-presize (appended after brain_unit_policy_words; src/ai/kntwr_planner_prepass.h row layout, labels
       KNTWR_AI_PREPASS_CENSUS_LABELS): word 0 layout version (1; 0 while the flags are off), think/walk/D1/world-change counters, microsecond
       sums converted from QPC, five think-duration classes, the 0x559090 presize counters (words 55..62), word 63 the latched flags and the
       0x80DCF0 polygon vertex-count histogram (words 64..79) and the 0x808492 observer-route walk count (80).
       Written by the thread that executes the think (AI worker under KNTWR_AI_ASYNC); a poll is a non-atomic snapshot. All zero without
       the flags; reset at activation, retained after stop. */
    uint32_t ai_prepass_census_words[KNTWR_AI_PREPASS_CENSUS_WORDS];
    /* --ai-poly-shadow / --ai-poly (appended after ai_prepass_census_words; src/ai/kntwr_planner_search.h): word 0 layout version (1; 0 while the
       poly bits are off), mode, kernel calls, served/refused-by-reason counts, shadow compare mismatches, vertex-count classes and the observer
       slot routing counts. Written by the thread executing the think; a poll is a non-atomic snapshot. Zero without the bits; reset at
       activation, retained after stop. Words 32..59 (KNTWR_AI_RECORD_TEST_WORDS, src/ai/kntwr_record_test.h, labels KNTWR_AI_RECORD_TEST_LABELS) are the
       --ai-record-test-shadow / --ai-record-test row of the alternate delegate route: mode, slot routing, kernel calls/served/fallbacks, compares and
       mismatches, vertex sums and timing; zero without those bits. */
    uint32_t ai_prepass_words[KNTWR_AI_PREPASS_WORDS];
    /* --ai-spiral-census / --ai-spiral-cap-m (appended after ai_prepass_words; src/ai/kntwr_spiral.h, labels KNTWR_AI_SPIRAL_LABELS): word 0
       layout version (1; 0 while the spiral bits are off), the cap, ladder stage counts, spiral entries/candidates/rings/found/capped/
       edge exits and maxima, fallback observer calls with the entries-per-call histogram and 0x82F3A0 tail/same-tick/memo counts.
       Written by the thread executing the think; a poll is a non-atomic snapshot. Reset at activation, retained after stop. */
    uint32_t ai_spiral_words[KNTWR_AI_SPIRAL_WORDS];
    /* --army-solver-memo / --army-solver-shadow (appended after ai_spiral_words; src/army/native_army_solver.h, labels KNTWR_ARMY_SOLVER_LABELS,
       KNTWR_ARMY_SOLVER_TICK_LABELS, KNTWR_ARMY_SOLVER_SOLVE_LABELS): bit-exact flag=1 slot-solver counters. Header 60 words (version,
       mode, solve/fallback/shadow-mismatch counts, native/kernel us, evals/iterations/scans, phase split, m histogram, cache-origin and command-route (native 57B000 call site rewrite) coverage), then the top-16 ticks
       (13 words each, at word 60) and the top-16 single solves (16 words each, at word 268) ordered by solver us; 524 words in all. Written by the tick owner; a poll is a non-atomic snapshot. All zero without
       the bits; reset at activation, retained after stop. */
    uint32_t army_solver_words[KNTWR_ARMY_SOLVER_WORDS];
    /* --alloc-census (appended after army_solver_words; owner module src/core/kntwr_alloc_census.*, labels KNTWR_ALLOC_CENSUS_LABELS):
       process-heap allocation callsite census. 32 header words + 128 rows x 8 words (callsite_va, size_class, live_bytes, live_count,
       allocs, frees, peak_live_bytes, reserved). Reset at activation, retained after stop; all zero without KNTWR_ALLOC_CENSUS. */
    uint32_t alloc_census_words[KNTWR_ALLOC_CENSUS_WORDS];
    /* --arena-release / --heap-optimize (appended after alloc_census_words; owner module src/render/kntwr_arena_release.*, labels
       KNTWR_ARENA_LABELS): lever 4 pose/scene arena release and lever 7 heap optimization counters (32 words). Reset at activation,
       retained after stop; all zero without the flags. */
    uint32_t arena_words[KNTWR_ARENA_WORDS];
    /* Overlay / driver DLL VA report (appended after arena_words; owner module OverlayDiet / launcher report, labels KNTWR_OVERLAY_LABELS):
       lever 6 counters (16 words). Reset at activation, retained after stop. */
    uint32_t overlay_words[KNTWR_OVERLAY_WORDS];
    /* --mounted-officer (appended after overlay_words; owner module src/army/kntwr_mounted_officer.*, labels KNTWR_MOUNTED_OFFICER_LABELS): gate counters of the
       unit-constructor mount gate (16 words; the constructors run while loading, so the row is published by the monitor in every phase). Reset at start,
       retained after stop; all zero without KNTWR_MOUNTED_OFFICER. */
    uint32_t mounted_officer_words[KNTWR_MOUNTED_OFFICER_WORDS];
    /* --engage-census (appended after mounted_officer_words; owner module src/ai/kntwr_engage_census.*): header counters 0..31, histograms 32..247, rows 256..2175, still/class/side tables and the trace ring 2176..6431
       (layout in kntwr_engage_census.h). Reset at start, retained after stop; all zero without KNTWR_ENGAGE_CENSUS. */
    uint32_t engage_census_words[KNTWR_ENGAGE_CENSUS_WORDS];
    /* Clip picker crash guard (appended after engage_census_words; owner module src/animation/kntwr_clip_picker_guard.*, labels KNTWR_ANIM_GUARD_LABELS). Reset at monitor start, retained after stop. */
    uint32_t anim_guard_words[KNTWR_ANIM_GUARD_WORDS];
    /* Formation residual census (appended after anim_guard_words; owner module src/army/native_formation_residual.*, labels KNTWR_FORMATION_RESIDUAL_LABELS): runs with
       --army-storm-census. Reset at monitor start, retained after stop; all zero without KNTWR_ARMY_STORM_CENSUS. */
    uint32_t army_residual_words[KNTWR_FORMATION_RESIDUAL_WORDS];
    /* --drag-ladder (appended after army_residual_words; owner module src/formation/kntwr_drag_ladder_hook.*, labels KNTWR_DRAG_LADDER_LABELS). Reset at monitor start, retained after stop; all zero without KNTWR_DRAG_LADDER. */
    uint32_t drag_ladder_words[KNTWR_DRAG_LADDER_WORDS];
    /* --wounded (appended after drag_ladder_words; owner module src/animation/kntwr_wounded_hook.*, labels KNTWR_WOUNDED_LABELS). Reset at monitor start, retained after stop; all zero without KNTWR_WOUNDED. */
    uint32_t wounded_words[KNTWR_WOUNDED_WORDS];
} kntwr_status;

/* DATA export "kntwr_profile", separate from the sequence-locked lifecycle status.
   Opt-in, ACTIVE-only observations of up to 48 process threads, never the sampler.
   Legacy tables are gated by the simulation tick or --profile-site scope; the
   main-thread phase tables sample across all four actual-tick phases regardless
   of --profile-site. EIP histograms are occupancy samples, NOT kernel CPU accounting:
   blocked threads are sampled too; in_wait identifies known ntdll
   wait stubs (the first 16 bytes of NtWaitForSingleObject, NtWaitForMultipleObjects,
   NtDelayExecution, NtWaitForAlertByThreadId, NtReleaseKeyedEvent, NtWaitForKeyedEvent).
   The frames histogram scans at most 1024 stack words in [ESP, ESP+4096) of the
   thread executing the gated scope, bounded by its readable committed region,
   without touching guard pages. Main-image words preceded by E8 rel32 or supported
   FF /2 call encodings count once per distinct 64-byte bucket per gated sample.
   The ordered chain retains the first 16 such addresses, scanning upward from ESP,
   before histogram bucket deduplication, including repeated addresses. Chains hold
   exact preferred-base VAs (0x400000 + image RVA), not bucket starts or current EIP.
   Reads are SEH-guarded. These are return-address candidates, not an unwound stack:
   stale locals can still resemble call returns; chains preserve scan order only.
   The first 64 distinct nonempty sequences are retained with exact-match counts;
   this is not a global top-64 approximation. chain_uncaptured counts gated samples
   with no candidates (including unreadable stacks) or an unretained distinct chain.
   A scan fault retains its readable prefix. Chains/counts reset on start/retarget.

   <receipt>.profile.bin format, all little-endian uint32_t, no padding:
     offset 0: this full status header (abi = 7, size = 15748); readers MUST use size
     offset size: bucket_count all-thread main-image EIP counters
     offset size + bucket_count*4: bucket_count tick-thread main-image EIP counters
     offset size + bucket_count*8: bucket_count gated-thread frames counters
     offset size + bucket_count*12: bucket_count main-thread phase A1 EIP counters
     offset size + bucket_count*16: bucket_count main-thread phase B EIP counters
     offset size + bucket_count*20: bucket_count main-thread phase C EIP counters
     offset size + bucket_count*24: bucket_count main-thread phase A2 EIP counters
     offset size + bucket_count*28: chain_count[64] (256 bytes)
     offset size + bucket_count*28 + 256: chain_len[64] (256 bytes)
     offset size + bucket_count*28 + 512: chains[64][16] (4096 bytes, row-major)
     offset size + bucket_count*28 + 4608: chain_uncaptured (4 bytes)
   The 4612-byte tick-chain trailer duplicates the header's tick chain fields from
   the same cached snapshot. Main-A1/B chains live in the header only. Zero-length rows
   are unused; unused address cells are zero. Total file bytes = size + bucket_count*28 + 4612.
   All histogram VAs are zero in files (live export holds process addresses).
   Bucket i covers preferred-base [0x400000+i*bucket_bytes, 0x400000+(i+1)*bucket_bytes).
   overflow[0..5] = runtime DLL, clones, tbb.dll, known ntdll waits, other foreign,
   individual sample attempts discarded outside the tick; [6..7] reserved.
   samples includes every gated classified EIP; failed counts suspend/context/resume errors.
   tick_thread_id is the thread last observed executing the gated scope (the tick is a
   scheduler task and may run on different threads); tick_samples counts gated-thread
   samples and is the denominator for the second/third histograms and chain counts.
   Thread rows retain counts after exit until their slot is needed for a new thread;
   reused rows reset (thread_replaced counts these resets); global totals persist.
   thread_limit counts threads omitted at refresh due to the 48-handle bound.
   wait_handle/count contains the top 8 exact counts among up to 4096 distinct
   tick-thread NtWaitForSingleObject HANDLE values read from [ESP+4] under SEH.
   Empty entries have count zero (HANDLE zero is valid data). wait_overflow counts
   observations of additional distinct values; wait_read_failed counts unsafe reads.
   Handles are raw process-local values, not stable object identities across reuse.
   Main-phase shares divide by all main samples in that phase, including waits/
   non-image EIPs, rather than just image hits. A1 is the first 25 ms of an active
   tick; A2 is the remaining active tick. B is <=40 ms after exit; C is otherwise.
   A1-C and A1-A2 report percentage-point excess occupancy at tick start; B-C reports
   post-tick excess. Positive buckets are serial-work candidates, not proof of
   causation. High A1 wait share suggests tick-entry synchronization; inspect the
   stub/handle rows and A1 chains together. Wait-stub presence alone does not prove
   a kernel-blocked state. A1/B chains retain the first 64 distinct sequences, not
   guaranteed global heavy hitters; high uncaptured counts limit their coverage.
   Entry/exit QPC is atomically published before setting/clearing the actual tick
   word. Phase boundaries are observational near concurrent transitions. A1/A2 take
   precedence over B. Exit includes AI slice/hold cleanup. C includes samples before
   the first tick. Each comparison is omitted if either of its phases is empty.
   Live copies are observational, not transactional: header/arrays may differ by
   samples taken during copying. Counts wrap modulo 2^32. The launcher caches a
   copy once per second for process exit and refreshes it at bounded observation end.
   Thread enumeration occurs at sampler start and about every 2 s. Each round
   attempts each retained thread once (only main is sampled outside the selected gate);
   ~200 rounds/s is throttled to <=10% measured
   sampler duty (including enumeration and suspension). No loop allocations except
   the periodic Toolhelp snapshot. Scheduling and impact require live measurement. */
#define KNTWR_PROFILE_ABI 8u /* 8: versioned runtime-DLL RVA bucket tables appended after the seven histogram arrays */
#define KNTWR_PROFILE_BUCKET_BYTES 64u
#define KNTWR_PROFILE_THREADS 48u
#define KNTWR_PROFILE_WAIT_HANDLES 8u
#define KNTWR_PROFILE_CHAINS 64u
#define KNTWR_PROFILE_CHAIN_DEPTH 16u
#define KNTWR_PROFILE_MAIN_PHASES 4u
/* Preserve the ABI 5/6 array offsets; slot 0 now means A1, not aggregate A.
   A2 is appended separately. Histogram storage order is A1, B, C, A2. */
#define KNTWR_PROFILE_INLINE_PHASES 3u
enum kntwr_profile_phase {
    KNTWR_PROFILE_PHASE_A1, KNTWR_PROFILE_PHASE_B, KNTWR_PROFILE_PHASE_C, KNTWR_PROFILE_PHASE_A2
};
#define KNTWR_PROFILE_START_TICK_MS 25u
#define KNTWR_PROFILE_POST_TICK_MS 40u
enum kntwr_profile_module {
    KNTWR_PROFILE_MODULE_IMAGE, KNTWR_PROFILE_MODULE_KNTWR, KNTWR_PROFILE_MODULE_D3D9,
    KNTWR_PROFILE_MODULE_DRIVER, KNTWR_PROFILE_MODULE_NTDLL, KNTWR_PROFILE_MODULE_KERNEL32,
    KNTWR_PROFILE_MODULE_TBB, KNTWR_PROFILE_MODULE_MSVCR, KNTWR_PROFILE_MODULE_OTHER,
    KNTWR_PROFILE_MODULE_COUNT
};
typedef struct kntwr_profile_phase_status {
    uint32_t hist_va, samples, wait;
    uint32_t wait_kind[8];
    uint32_t wait_handle[KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t wait_count[KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t wait_handle_kind[KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t wait_read_failed, wait_overflow;
    uint32_t modules[KNTWR_PROFILE_MODULE_COUNT];
} kntwr_profile_phase_status;
typedef struct kntwr_profile_status {
    uint32_t abi, size, bucket_bytes, bucket_count;
    uint32_t samples, failed, hist_va, tick_hist_va;
    uint32_t overflow[8];
    uint32_t tick_thread_id, tick_samples, rounds, enumeration_failed;
    uint32_t thread_limit, wait_read_failed, wait_overflow, thread_replaced;
    uint32_t thread_id[KNTWR_PROFILE_THREADS];
    uint32_t thread_samples[KNTWR_PROFILE_THREADS];
    uint32_t in_image[KNTWR_PROFILE_THREADS];
    uint32_t in_wait[KNTWR_PROFILE_THREADS];
    uint32_t in_tbb[KNTWR_PROFILE_THREADS];
    uint32_t wait_handle[KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t wait_count[KNTWR_PROFILE_WAIT_HANDLES];
    /* Tick-executing thread samples per ntdll wait stub: NtWaitForSingleObject, NtWaitForMultipleObjects,
       NtDelayExecution, NtWaitForAlertByThreadId, NtReleaseKeyedEvent, NtWaitForKeyedEvent, [6..7] reserved. */
    uint32_t tick_wait_kind[8];
    uint32_t frames_hist_va;
    uint32_t chain_count[KNTWR_PROFILE_CHAINS];
    uint32_t chain_len[KNTWR_PROFILE_CHAINS];
    uint32_t chains[KNTWR_PROFILE_CHAINS][KNTWR_PROFILE_CHAIN_DEPTH];
    uint32_t chain_uncaptured;
    /* Append-only ABI 5: main thread, independent of the optional profile-site gate.
       ABI 7 narrows slot 0 to A1 (<25 ms of active tick); B/C keep slots 1/2.
       A2 (remaining active tick) is appended below. Histograms exclude non-image EIPs.
       Wait kinds have the same ordering as tick_wait_kind. Handle rows are exact
       top counts keyed by (stub kind, raw handle), with up to 4096 keys per phase.
       Multiple-object waits count each distinct member of the observed wait set,
       not a proven blocking member. Delay/alert have no HANDLE row. Keyed-event
       rows identify the event handle (possibly NULL), not the separate key.
       B chains follow the existing first-64 retention/stack-scan contract. */
    uint32_t main_thread_id, main_post_tick_ms;
    uint32_t main_hist_va[KNTWR_PROFILE_INLINE_PHASES];
    uint32_t main_samples[KNTWR_PROFILE_INLINE_PHASES];
    uint32_t main_wait[KNTWR_PROFILE_INLINE_PHASES];
    uint32_t main_wait_kind[KNTWR_PROFILE_INLINE_PHASES][8];
    uint32_t main_wait_handle[KNTWR_PROFILE_INLINE_PHASES][KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_count[KNTWR_PROFILE_INLINE_PHASES][KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_handle_kind[KNTWR_PROFILE_INLINE_PHASES][KNTWR_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_read_failed[KNTWR_PROFILE_INLINE_PHASES];
    uint32_t main_wait_overflow[KNTWR_PROFILE_INLINE_PHASES];
    uint32_t main_post_chain_count[KNTWR_PROFILE_CHAINS];
    uint32_t main_post_chain_len[KNTWR_PROFILE_CHAINS];
    uint32_t main_post_chains[KNTWR_PROFILE_CHAINS][KNTWR_PROFILE_CHAIN_DEPTH];
    uint32_t main_post_chain_uncaptured;
    /* ABI 6: exclusive EIP module categories; each phase row sums to main_samples.
       KNTWR includes private clones. Driver names begin nv/atiu/ig; CRT begins msvcr.
       Other includes unlisted modules (including KernelBase), JIT/private code and
       uncatalogued addresses. Module ranges refresh about every 2 s, outside any
       thread suspension; unload/reload races are observational. At most 256 named
       category ranges are retained. Failures/omissions are explicit below. */
    uint32_t main_modules[KNTWR_PROFILE_INLINE_PHASES][KNTWR_PROFILE_MODULE_COUNT];
    uint32_t module_refresh_failed, module_omitted;
    /* ABI 7: the A1 start window, appended A2 counters, and independent A1 chains. */
    uint32_t main_start_tick_ms;
    kntwr_profile_phase_status main_rest;
    uint32_t main_start_chain_count[KNTWR_PROFILE_CHAINS];
    uint32_t main_start_chain_len[KNTWR_PROFILE_CHAINS];
    uint32_t main_start_chains[KNTWR_PROFILE_CHAINS][KNTWR_PROFILE_CHAIN_DEPTH];
    uint32_t main_start_chain_uncaptured;
} kntwr_profile_status;
/* Access one scalar or array field across the append-only phase layout.
   phase must be a valid enum kntwr_profile_phase with no expression side effects.
   C++ preserves volatile/lvalue access for the sampler; C readers use the same mapping. */
#define KNTWR_PROFILE_PHASE_FIELD(p, phase, field) \
    ((phase) < KNTWR_PROFILE_INLINE_PHASES ? (p)->main_##field[(phase)] : (p)->main_rest.field)

/* DATA export "kntwr_trace": per-tick trace ring written by the tick gate (needs a simulation feature or profile so the
   tick is routed through the private clone; the three sub-phase gates then time the manager 0x580640, the ballistics
   manager 0x6F6BC0 and the path scheduler 0x81A2C0 calls). Entries are written in order; `head` is the index of the
   next entry to write (wraps at KNTWR_TRACE_ENTRIES); `written` counts all ticks traced. Readers copy the ring and
   use `written` to order it. Durations are microseconds; appended start/end fields
   are raw QPC ticks, sharing PresentMon --qpc_time's clock. qpc_freq_lo/hi is ticks/s.
   End includes final hold cleanup; duration_us measures the tick body INCLUDING the site-34 AI slice.
   `remainder` = duration - manager - ballistics - path.
   The launcher receipt's tick_trace.ticks exports all retained entries chronologically.
   Align present QPC against [qpc_start,qpc_end] or subtract qpc_end and divide by
   qpc_frequency for seconds since tick exit. Live ring copies remain observational. */
#define KNTWR_TRACE_ABI 8u
#define KNTWR_TRACE_ENTRIES 1024u
/* Inclusive call-site timings, indexed by ORIGINAL callee VA:
    0: 0x554AA0 (conditional initialization)   1: 0x603A40
    2: 0x582FB0 (ARMIES clone)                3: 0x585960
    4: 0x57DA70                              5: 0x57DC30
    6: 0x585D10                              7: 0x585760
    8: 0x583A20                              9: 0x6F8B60
   10: 0x7F08D0 (each loop call)            11: 0x531920
   12: 0x531AB0                             13: 0x531AF0
   14: 0x582F70                             15: 0x6F3E00 (each loop call)
   16: 0x550360 (ARMY)                      17: 0x585F70 (ARMY)
   18: 0x580390 (each container)            19: 0x55AD60 (conditional)
   20: 0x539E80 (army AI tail)              21: 0x55AD60 (AIPASS entry, 0x5832C4)
   22: 0x539E80 (AIPASS army AI, each army) 23: 0x55AD60 (AIPASS per-army check, 0x583316)
   24: 0x583380 (AIPASS each army)          25: 0x550240 (ARMIES, each state==2 army)
   26: 0x756C80 (AICTRL initialization)     27: 0x7D6510 (AICTRL)
   28: 0x7DBA90                            29: 0x755E50
   30: 0x6387F0                            31: 0x7D7020
   32: 0x7B5F20                            33: 0x7C8BD0
   34: 0x7D99F0                            35: 0x7A4C80
   36: 0x76A580                            37: 0x75C880
   38: 0x7DB360                            39: 0x7D90A0
   40: 0x7F1D40 at 0x7C7FD3 / 0x7C8113 (initial and shrinking-shape loop walks)
   41: 0x804DD0 at 0x7F1D8D (gather)
   42: 0x809110 at 0x804E0B (2-D spatial broadphase)
   43: 0x6DC9A0 at 0x804E4B (active-interest predicate)
   44: 0x80DCF0 at 0x7F1E5A (polygon predicate, value-key memo)
   45: 0x808F90 at 0x7F1DE5 (alternate polygon predicate, native)
   Brain profiling sites (KNTWR_BRAIN, PROFILE epochs; sums are per site over all families, see kntwr_status::brain_words for
   the per-family split). Entry sites are the published slot +0x0C targets; callee VAs below 0x400000 are virtual slot offsets:
   46: 0x66CE00 entry (slot +0x0C direct, 11 vtables)        47: 0x6F50F0 entry (jmp thunk, 1 vtable)
   48: 0x6F4660 entry (6 vtables)                            49: 0x602EB0 entry (1 vtable)
   50: 0x5FCEB0 entry (4 vtables)
   51: 0x6FA2D0   52: 0x6FEE40   53: 0x6FEA90   54: 0x6FB740   55: brain call 0x6F468A     (wrapper 0x6F4660 callees)
   56: brain call 0x602EB6   57: 0x5CB830   58: 0x5B7B20                                   (wrapper 0x602EB0 callees)
   59: brain call 0x5FCF67   60: 0x610470   61: 0x60CAC0   62: 0x5E52F0   63: 0x607540   64: 0x5B9720 (tail)
   65: 0x7EE750   66: 0x679300   67: 0x63C440   68: 0x5B77A0   69: 0x444B60   70: 0x679C50   71: 0x7FD9E0
   72: 0x66EEB0   73: 0xE5F760   74: 0x10F1160  75: 0x659480   76: 0x7FD070   77: 0x80E9D0   78: 0x66B080
   79: 0x66C160   80: 0x663730   81: 0x62DFF0   82: 0x6666E0   83: 0x6718F0   84: 0x805880   85: 0x658C50
   86: 0x64DE80   87: 0x602E00   88: 0x53EEE0   89: 0x6E9DA0   90: 0x639200   91: 0x55AC60   92: 0x55C2E0
   93: [vt+0x1A8] at 0x66D433   94: [vt+0x108] at 0x66D43D                                 (brain callees, level 1)
   Sites 46..94 time only on the tick-owner thread inside a routed tick with KNTWR_BRAIN armed and nest inside site 6.
   ARMY_UPDATE direct callees (inside site 18):
   95: 0x55CB50 at 0x5803B4   96: 0x575AE0 at 0x5803CE   97: 0x6D0750 at 0x580409
   98: 0x575720 at 0x580423   99: 0x57FFE0 at 0x580458  100: 0x57FD20 at 0x580488
  101: 0x581F30 at 0x5804C2  102: 0x55AB80 at 0x5804F4  103: 0x581F30 at 0x5804FF
  104: 0x579AD0 at 0x58054E  105: 0x579AD0 at 0x580598
  106..111: reserved, zero. The two indirect calls at 0x580556/0x5805A0 remain original.
   Each invocation contributes its QPC enter-to-return duration and one call.
   Skipped sites are zero; loop calls accumulate. Site 2 INCLUDES sites 16..39 (AIPASS 0x5832C0 is a
   clone called twice by ARMIES; sites 21..24 are its four calls and nest inside site 2).
   Site 24 enters AIWRAP, whose non-null AI controller tail reaches AICTRL; sites 26..39 nest inside site 24,
   so site totals overlap each other and the three gate timings, not exclusive CPU time.
   Available only for PROFILE epochs without FORMATION; flags bit2 means timed calls.
   The army AI tail uses call/ret instead of jmp: the ECX-only callee must not inspect
   its return address (nor require the original caller's stack identity). */
/* ABI 8: 944-byte entry (112 sites + raw gate QPC pair); all site offsets/indices preserved. Slots 110 and 111 are not timed
   sites (KNTWR_TIMED_SITES == 110) and stay zero unless KNTWR_ARMY_STORM_CENSUS is on and the tick is routed; then the tick owner
   writes four storm-census words there at tick end (src/army/native_army_storm.h, TickEnd):
     site_us[110]    max single-unit 0x581F30 call us this tick (instrumentation excluded)
     site_calls[110] units this tick whose route evidence says the command/formation route ran
     site_us[111]    sum of those route units' us
     site_calls[111] bits 0..15: units with cost >= 5000 us (saturating); bits 16..31: army/side index of the max unit
                     (0xFFFF when unproven or no unit ran) */
#define KNTWR_TRACE_SITES 112u
#define KNTWR_TIMED_SITES 110u
#define KNTWR_SITE_CALLEE_VAS { \
    0x554AA0u, 0x603A40u, 0x582FB0u, 0x585960u, 0x57DA70u, 0x57DC30u, 0x585D10u, 0x585760u, \
    0x583A20u, 0x6F8B60u, 0x7F08D0u, 0x531920u, 0x531AB0u, 0x531AF0u, 0x582F70u, 0x6F3E00u, \
    0x550360u, 0x585F70u, 0x580390u, 0x55AD60u, 0x539E80u, 0x55AD60u, 0x539E80u, 0x55AD60u, \
    0x583380u, 0x550240u, 0x756C80u, 0x7D6510u, 0x7DBA90u, 0x755E50u, 0x6387F0u, 0x7D7020u, \
    0x7B5F20u, 0x7C8BD0u, 0x7D99F0u, 0x7A4C80u, 0x76A580u, 0x75C880u, 0x7DB360u, 0x7D90A0u, \
    0x7F1D40u, 0x804DD0u, 0x809110u, 0x6DC9A0u, 0x80DCF0u, 0x808F90u, \
    0x66CE00u, 0x6F50F0u, 0x6F4660u, 0x602EB0u, 0x5FCEB0u, \
    0x6FA2D0u, 0x6FEE40u, 0x6FEA90u, 0x6FB740u, 0x6F50F0u, \
    0x6F50F0u, 0x5CB830u, 0x5B7B20u, \
    0x6F50F0u, 0x610470u, 0x60CAC0u, 0x5E52F0u, 0x607540u, 0x5B9720u, \
    0x7EE750u, 0x679300u, 0x63C440u, 0x5B77A0u, 0x444B60u, 0x679C50u, 0x7FD9E0u, 0x66EEB0u, 0xE5F760u, 0x10F1160u, \
    0x659480u, 0x7FD070u, 0x80E9D0u, 0x66B080u, 0x66C160u, 0x663730u, 0x62DFF0u, 0x6666E0u, 0x6718F0u, 0x805880u, \
    0x658C50u, 0x64DE80u, 0x602E00u, 0x53EEE0u, 0x6E9DA0u, 0x639200u, 0x55AC60u, 0x55C2E0u, 0x1A8u, 0x108u, \
    0x55CB50u, 0x575AE0u, 0x6D0750u, 0x575720u, 0x57FFE0u, 0x57FD20u, 0x581F30u, 0x55AB80u, 0x581F30u, 0x579AD0u, 0x579AD0u, \
    0x81A790u, 0x56EE80u, 0x81A670u, 0x44u }
typedef struct kntwr_trace_entry {
    uint32_t tick;        /* model tick counter at entry ([model+0x58]) */
    uint32_t duration_us; /* tick body including any site-34 AI slice, excluding final tick-exit hold cleanup */
    uint32_t interval_us; /* start-to-start gap from the previous traced tick (0 for the first) */
    uint32_t manager_us;  /* time inside the army manager call (formation gate) */
    uint32_t ballistics_us;
    uint32_t path_us;
    uint32_t thread_id;
    uint32_t flags;       /* bit0: private tick clone, bit1: sub-phase gates, bit2: inclusive site timings.
                             Tick core census (routed ticks on a host whose CPU set topology was read; always on, observation only):
                             bit3: census valid; bit4: the gate was entered on an E-core (lower efficiency class), before placement;
                             bit5: the last census sample was on an E-core; bit6: the tick body was hard-pinned to P cores
                             (KNTWR_TICK_PCORE, or an even tick under KNTWR_TICK_CORE_AB); bit7: pinned to E cores (odd tick, AB);
                             bits 8..15: E-core share of the tick body 0..255; bits 16..23: E-core share of site 6 0..255
                             (also 0 when site 6 did not run: qualify with site_calls[6]);
                             bits 24..31: core-class changes between consecutive samples (saturating). Samples are the
                             processor class at gate entry (after placement), at every timed site entry/exit and at tick end;
                             the QPC gap between two samples counts for their class, half each when they differ. */
    uint32_t site_us[KNTWR_TRACE_SITES];
    uint32_t site_calls[KNTWR_TRACE_SITES];
    uint32_t qpc_start_lo, qpc_start_hi; /* raw gate-entry QPC */
    uint32_t qpc_end_lo, qpc_end_hi;     /* raw gate-exit QPC, including AI slice/hold */
} kntwr_trace_entry;
typedef struct kntwr_trace_ring {
    uint32_t abi, size, entries, head, written, qpc_freq_lo, qpc_freq_hi, reserved;
    kntwr_trace_entry ring[KNTWR_TRACE_ENTRIES];
} kntwr_trace_ring;

/* Undecorated DLL export names. Both functions use the x86 WINAPI thread-entry
   convention. Start copies config, starts one monitor, and returns promptly.
   Stop disables/restores owned hooks and joins the monitor. Private code stays
   resident; arenas are reclaimed or reused only after their owners quiesce. */
typedef uint32_t (__stdcall *kntwr_start_fn)(void *config);
typedef uint32_t (__stdcall *kntwr_stop_fn)(void *unused);
/* Diagnostic export (oracles): the callee currently bound behind timed site `site` of the private clones, 0 beyond KNTWR_TIMED_SITES.
   Site 6 is BrainKernelGate while a BRAIN2 generation is active, original 0x585D10 otherwise.
   Site 5 is the host stage gate in PROFILE/COLLIDE/COLLIDE_LOD generations, original 0x57DC30 outside those generations.
   Site 33 is the controller job gate only in AI_CTRL generations (requires AI_ASYNC), the AI_ASYNC2 join thunk (joins an in-flight
   think, then the original controller) in AI_ASYNC2 generations, original 0x7C8BD0 otherwise. Site 34 is the AI_ASYNC2 dispatch gate in
   AI_ASYNC2 generations, the same-call AI gate in other AI_ASYNC generations.
   Site 13 is the host movement gate (kntwr_loco::Stage inside a LOCO tick epoch, original 0x531AF0 otherwise) exactly while a generation with KNTWR_LOCO is active, the original 0x531AF0 otherwise.
   The stage gate additionally checks the current thread's feature epoch before routing a clone or applying LOD. */
typedef uint32_t (__stdcall *kntwr_site_callee_fn)(uint32_t site);
/* Owner-boundary diagnostic export for the mapped-image lifecycle oracle, which has no engine task scheduler.
   The caller must own a quiescent model. Executes one pending activation capture for that exact bound model, returning 1;
   returns 0 when no matching capture is pending. This is the same seam TickGate invokes before any native tick work. */
typedef uint32_t (__stdcall *kntwr_activation_boundary_fn)(void *model);
/* Mapped-image lifecycle diagnostic: caller owns the bound model. Dispatches the original planner VA
   with the supplied this/flag under tick ownership and joins through the production barrier before returning.
   Returns 1 when admitted, 0 outside an active matching AI world or when another owner holds the tick. */
typedef uint32_t (__stdcall *kntwr_ai_boundary_fn)(void *model, void *planner, uint32_t flag);
/* Mapped-image lifecycle diagnostic for KNTWR_AI_ASYNC2, one synthetic tick under tick ownership of the bound model: the
   production tick-start seam (non-blocking), site-34 admission of `planner` (queued; skipped when null), `mid(context)`
   on the tick thread while earlier batches may still run, a second admission when options bit 0 is set, the production
   TICK quadtree join (blocking; skipped when options bit 1 is set) and the tick-end publish. Returns 1 when the planner
   was admitted (or, with a null planner, when the tick ran), 0 otherwise. */
typedef uint32_t (__stdcall *kntwr_ai_async2_boundary_fn)(void *model, void *planner, uint32_t flag,
                                                        void (__stdcall *mid)(void *context), void *context, uint32_t options);
/* Lifecycle diagnostic export "kntwr_ai_async2_private_entry": the entry of an AI2 private clone (kntwr_clone_id
   KNTWR_CLONE_AI2_*) as the routed slots hand it out. Nonzero only on the AI worker inside a think of an AI_ASYNC2
   generation, after the same lazy worker-side construction of the private search objects. */
typedef uint32_t (__stdcall *kntwr_ai_async2_private_entry_fn)(uint32_t clone);

#ifdef __cplusplus
}
static_assert(sizeof(kntwr_config) == 68 && offsetof(kntwr_config, loco_flags) == 36 &&
              offsetof(kntwr_config, brain_flags) == 40 && offsetof(kntwr_config, collide_flags) == 44 &&
              offsetof(kntwr_config, va_watch_flags) == 48 && offsetof(kntwr_config, ai_deferred) == 52 &&
              offsetof(kntwr_config, ai_ctrl_flags) == 56 && offsetof(kntwr_config, ai_prepass_flags) == 60 &&
              offsetof(kntwr_config, gameplay_flags) == 64 && KNTWR_ABI == 2u,
              "configuration ABI is append-only");
static_assert(offsetof(kntwr_status,grid_census) == 4 * (29 + 16 + 16 + 24 + 8 + 192 + 16 + 16 + 64 + 16 + 16 + 32 + 32 + KNTWR_BRAIN_WORDS + 32 + 80 + 8 + 8 + 32 + KNTWR_ALLOCATOR_WORDS + 2 + KNTWR_BRAIN_STATE_WORDS + KNTWR_COLLISION_WORDS + KNTWR_COLLIDE_WORDS + KNTWR_BRAIN2_WORDS + KNTWR_COLLIDE_LOD_WORDS + 16 + KNTWR_AI_SLICE_BUDGET_WORDS + 8 + KNTWR_LOCO_WORDS + KNTWR_LOCO_GATE_WORDS + KNTWR_LOCO_SERVICE_WORDS + KNTWR_LOCO_GRID_WORDS + KNTWR_LOCO_PARALLEL_WORDS + KNTWR_SWEEP_WORDS + KNTWR_RESOLVE_WORDS + KNTWR_ENV_WORDS + KNTWR_ENV_TARGET_WORDS + KNTWR_RESOLVE_FRAME_WORDS + KNTWR_LOCO_OWNED_WORDS + KNTWR_LOCO_OWNED_DETAIL_WORDS + KNTWR_LOCO_OWNED_PHASE_WORDS + KNTWR_LOCO_OWNED_LOAD_WORDS + KNTWR_LOCO_GRID_V2_WORDS + KNTWR_COLLIDE_SOURCE_WORDS + KNTWR_MEMORY_WORDS + KNTWR_AI_COMPLETION_WORDS), "status ABI prefix");
static_assert(offsetof(kntwr_status,ai_slice_budget_words) == offsetof(kntwr_status,ai_ctrl_words) + 16 * sizeof(uint32_t) &&
              KNTWR_AI_SLICE_BUDGET_WORDS == 8u, "slice budget telemetry preserves its shipped offset");
static_assert(offsetof(kntwr_status,ai_park_words) == offsetof(kntwr_status,ai_slice_budget_words) + KNTWR_AI_SLICE_BUDGET_WORDS * sizeof(uint32_t) &&
              offsetof(kntwr_status,ai_park_words) + 8 * sizeof(uint32_t) == offsetof(kntwr_status,loco_words), "parking histogram keeps its shipped offset");
static_assert(offsetof(kntwr_status,loco_words) == offsetof(kntwr_status,ai_park_words) + 8 * sizeof(uint32_t) &&
              offsetof(kntwr_status,loco_words) + KNTWR_LOCO_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_gate_words) &&
              KNTWR_LOCO_WORDS == 48u, "loco telemetry preserves its shipped layout");
static_assert(offsetof(kntwr_status,loco_gate_words) + KNTWR_LOCO_GATE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_service_words) &&
              KNTWR_LOCO_GATE_WORDS == 48u, "loco all-gates telemetry preserves its shipped layout");
static_assert(offsetof(kntwr_status,loco_service_words) + KNTWR_LOCO_SERVICE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_grid_words) &&
              KNTWR_LOCO_SERVICE_WORDS == 40u, "loco service telemetry preserves its shipped layout");
static_assert(offsetof(kntwr_status,loco_grid_words) + KNTWR_LOCO_GRID_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_parallel_words) &&
              KNTWR_LOCO_GRID_WORDS == 32u, "loco grid telemetry is append-only");
static_assert(offsetof(kntwr_status,loco_parallel_words) + KNTWR_LOCO_PARALLEL_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,sweep_words) &&
              KNTWR_LOCO_PARALLEL_WORDS == 32u, "loco parallel telemetry is append-only");
static_assert(offsetof(kntwr_status,sweep_words) + KNTWR_SWEEP_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,resolve_words) &&
              KNTWR_SWEEP_WORDS == 32u, "sweep telemetry is append-only");
static_assert(offsetof(kntwr_status,resolve_words) + KNTWR_RESOLVE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,env_words) &&
              KNTWR_RESOLVE_WORDS == 32u, "resolve telemetry is append-only");
static_assert(offsetof(kntwr_status,env_words) + KNTWR_ENV_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,env_target_words) &&
              KNTWR_ENV_WORDS == 32u, "environment telemetry is append-only");
static_assert(offsetof(kntwr_status,env_target_words) + KNTWR_ENV_TARGET_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,resolve_frame_words) &&
              KNTWR_ENV_TARGET_WORDS == 64u, "environment targets are append-only");
static_assert(offsetof(kntwr_status,resolve_frame_words) + KNTWR_RESOLVE_FRAME_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_owned_words) &&
              KNTWR_RESOLVE_FRAME_WORDS == 4u, "resolve frames keep their shipped offset");
static_assert(offsetof(kntwr_status,loco_owned_words) + KNTWR_LOCO_OWNED_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_owned_detail_words) &&
              KNTWR_LOCO_OWNED_WORDS == 32u && KNTWR_LOCO_OWNED_SERVICES == 0x8u, "owned-service telemetry is append-only");
static_assert(offsetof(kntwr_status,loco_owned_detail_words) + KNTWR_LOCO_OWNED_DETAIL_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_owned_phase_words) &&
              KNTWR_LOCO_OWNED_DETAIL_WORDS == 16u && KNTWR_LOCO_QUIET == 0x10u, "owned detail telemetry preserves its shipped layout");
static_assert(offsetof(kntwr_status,loco_owned_phase_words) + KNTWR_LOCO_OWNED_PHASE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_owned_load_words) &&
              offsetof(kntwr_status,loco_owned_load_words) + KNTWR_LOCO_OWNED_LOAD_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_grid_v2_words) &&
              KNTWR_LOCO_OWNED_PHASE_WORDS == 32u && KNTWR_LOCO_OWNED_LOAD_WORDS == 16u && KNTWR_LOCO_GRID == 0x20u && KNTWR_LOCO_GRID_VERIFY == 0x40u && KNTWR_LOCO_GRID_PROBATION == 0x80u && (KNTWR_LOCO_FLAGS_VALID & 0xffu) == 0xffu, "owned phase and load telemetry retain their offsets; grid verification uses flag bit 0x40 and probation bit 0x80");
static_assert(offsetof(kntwr_status,loco_grid_v2_words) + KNTWR_LOCO_GRID_V2_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,collide_source_words) &&
              offsetof(kntwr_status,collide_source_words) + KNTWR_COLLIDE_SOURCE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,memory_words) &&
              KNTWR_LOCO_GRID_V2_WORDS == 16u && KNTWR_COLLIDE_SOURCE_WORDS == 4u, "Stage C rows retain their shipped offsets");
static_assert(offsetof(kntwr_status,memory_words) + KNTWR_MEMORY_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_completion_words) &&
              KNTWR_MEM_FLOOR_BYTES == 27u && KNTWR_MEM_RELEASED_COLLIDE_BYTES == 43u &&
              KNTWR_MEM_LOCO_CATALOG_POLYGON_POINTS == 56u && KNTWR_MEM_HOLE_FLOOR_BYTES == 57u &&
              KNTWR_MEM_MIN_LARGEST_HOLE == 58u && KNTWR_MEM_LATCH_REASON == 59u &&
              KNTWR_MEM_LATCH_REASON + 1 == KNTWR_MEMORY_WORDS,
              "memory diagnostics preserve earlier indices before the AI completion tail");
static_assert(offsetof(kntwr_status,ai_completion_words) + KNTWR_AI_COMPLETION_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,grid_census) &&
              offsetof(kntwr_status,grid_census) + sizeof(kntwr_grid_census_status) == offsetof(kntwr_status,ai_census_words) &&
              offsetof(kntwr_status,ai_census_words) + KNTWR_AI_CENSUS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain2_census_words) &&
              KNTWR_AI_CENSUS == 0x10000u && (KNTWR_VALID_MASK & KNTWR_AI_CENSUS) == KNTWR_AI_CENSUS && !(KNTWR_ALL & KNTWR_AI_CENSUS) &&
              KNTWR_AI_CENSUS_WORDS == 16u + 7u * (8u + 8u * 12u) + 3u * 8u,
              "ai census preserves its position after grid census; its bit stays outside KNTWR_ALL");
static_assert(offsetof(kntwr_status,brain2_census_words) + KNTWR_BRAIN2_CENSUS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,node_words) &&
              KNTWR_BRAIN2_CENSUS_WORDS == 53u * 8u && KNTWR_BRAIN2_VERSION == 2u,
              "brain2 v2 census is append-only after AI census");
static_assert(offsetof(kntwr_status,node_words) + KNTWR_NODE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,node_event_words) &&
              offsetof(kntwr_status,node_event_words) + KNTWR_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,fire_words) &&
              offsetof(kntwr_status,fire_words) + KNTWR_FIRE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain2_route_words) &&
              offsetof(kntwr_status,brain2_route_words) + KNTWR_BRAIN2_ROUTE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,fire_commit_words) &&
              offsetof(kntwr_status,fire_commit_words) + KNTWR_FIRE_COMMIT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,move_node_words) &&
              offsetof(kntwr_status,move_node_words) + KNTWR_MOVE_NODE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,move_node_event_words) &&
              offsetof(kntwr_status,move_node_event_words) + KNTWR_MOVE_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain2_node_target_words) &&
              offsetof(kntwr_status,brain2_node_target_words) + KNTWR_BRAIN2_NODE_TARGET_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,idle_node_words) &&
              offsetof(kntwr_status,idle_node_words) + KNTWR_IDLE_NODE_CLASSES * KNTWR_NODE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,idle_node_event_words) &&
              offsetof(kntwr_status,idle_node_event_words) + KNTWR_IDLE_NODE_CLASSES * KNTWR_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,action_node_words) &&
              offsetof(kntwr_status,action_node_words) + KNTWR_ACTION_NODE_CLASSES * KNTWR_NODE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,action_node_event_words) &&
              offsetof(kntwr_status,action_node_event_words) + KNTWR_ACTION_NODE_CLASSES * KNTWR_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain2_unknown_site_words) &&
              offsetof(kntwr_status,brain2_unknown_site_words) + KNTWR_BRAIN2_UNKNOWN_SITE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain_worker_words) &&
              offsetof(kntwr_status,brain_worker_words) + KNTWR_BRAIN_WORKER_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_async2_words) &&
              offsetof(kntwr_status,ai_async2_words) + KNTWR_AI_ASYNC2_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain_worker_phase_words) &&
              offsetof(kntwr_status,brain_worker_phase_words) + KNTWR_BRAIN_WORKER_PHASE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain_unit_words) &&
              offsetof(kntwr_status,brain_unit_words) + KNTWR_BRAIN_UNIT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,collide_contact_words) &&
              KNTWR_AI_ASYNC2 == 0x20000u && (KNTWR_VALID_MASK & KNTWR_AI_ASYNC2) && !(KNTWR_ALL & KNTWR_AI_ASYNC2) &&
              KNTWR_BRAIN_PARALLEL == 0x10u && KNTWR_BRAIN_FINALIZER_SHADOW == 0x20u && KNTWR_BRAIN_QUIET == 0x40u &&
              KNTWR_BRAIN_UNIT_SHADOW == 0x80u && KNTWR_BRAIN_S0 == 0x100u && KNTWR_BRAIN_FLAGS_VALID == 0xfffffu &&
              KNTWR_BRAIN_LOCALITY_MARK == 0x80000u &&
              KNTWR_BRAIN_LOCALITY == 0x8000u && KNTWR_BRAIN_LOCALITY_WARM == 0x10000u &&
              KNTWR_BRAIN_LOCALITY_PREFETCH == 0x20000u && KNTWR_BRAIN_LOCALITY_PREFETCH2 == 0x40000u &&
              KNTWR_BRAIN_UNIT_WORDS == 176u,
              "class shadow and target rows append after the existing fire commit ABI");
static_assert(offsetof(kntwr_status,collide_contact_words) + KNTWR_COLLIDE_CONTACT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,grid_probation_words) &&
              KNTWR_COLLIDE_CONTACT_WORDS == 48u && KNTWR_COLLIDE_CONTACT_SHADOW == 0x1u && KNTWR_COLLIDE_CONTACT_WORKERS == 0x2u &&
              KNTWR_COLLIDE_FLAGS_VALID == 0x3u, "collision contact row appends after brain_unit_words");
static_assert(offsetof(kntwr_status,grid_probation_words) + KNTWR_GRID_PROBATION_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_async2_route_words) &&
              KNTWR_GRID_PROBATION_WORDS == 32u + 256u * 8u, "grid probation row appends after collide_contact_words");
static_assert(offsetof(kntwr_status,ai_async2_route_words) + KNTWR_AI_ASYNC2_ROUTE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,army_unit_words) &&
              KNTWR_AI_ASYNC2_ROUTE_WORDS == 65u, "ai_async2 route row appends after grid_probation_words");
static_assert(offsetof(kntwr_status,army_unit_words) + KNTWR_ARMY_UNIT_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,va_watch_words) &&
              KNTWR_ARMY_UNIT_WORDS == 192u && KNTWR_ARMY_UNIT_SHADOW == 0x40000u &&
              (KNTWR_VALID_MASK & KNTWR_ARMY_UNIT_SHADOW) && !(KNTWR_ALL & KNTWR_ARMY_UNIT_SHADOW),
              "army unit row appends after ai_async2_route_words; its bit is valid and outside KNTWR_ALL");
static_assert(offsetof(kntwr_status,va_watch_words) + KNTWR_VA_WATCH_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,army_b0_words) &&
              KNTWR_VA_WATCH_WORDS == 64u && KNTWR_VA_RING_BASE + KNTWR_VA_RING_ENTRIES * KNTWR_VA_RING_WORDS == KNTWR_VA_WATCH_WORDS &&
              !(KNTWR_VALID_MASK & 0x80000u),
              "VA watch row keeps the retired puppet row's space after army_unit_words; the puppet mask bit stays refused");
static_assert(KNTWR_CAVALRY_ORBIT == 0x100000u && (KNTWR_VALID_MASK & KNTWR_CAVALRY_ORBIT) == KNTWR_CAVALRY_ORBIT && !(KNTWR_ALL & KNTWR_CAVALRY_ORBIT) &&
              !(KNTWR_CAVALRY_ORBIT & (KNTWR_PROFILE | 0x80000u)) && !(KNTWR_VALID_MASK & 0x80000u) && sizeof(kntwr_config) == 68,
              "cavalry orbit is its own explicit opt-in mask bit outside KNTWR_ALL; retired 0x80000 stays refused; config ABI is 68 bytes");
static_assert(offsetof(kntwr_status,army_b0_words) + KNTWR_ARMY_B0_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,army_storm_words) &&
              KNTWR_ARMY_B0_WORDS == 160u, "army B0 row appends after va_watch_words");
static_assert(offsetof(kntwr_status,army_storm_words) + KNTWR_ARMY_STORM_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain_s0_words) &&
              KNTWR_ARMY_STORM_WORDS == 128u && KNTWR_ARMY_STORM_CENSUS == 0x2u && KNTWR_ARMY_STORM_SAMPLE_MASK == (0xFFu << KNTWR_ARMY_STORM_SAMPLE_SHIFT) &&
              !(KNTWR_VA_WATCH_FLAGS_VALID & ~(KNTWR_VA_WATCH | KNTWR_ARMY_STORM_CENSUS | KNTWR_ARMY_STORM_SAMPLE_MASK | KNTWR_TICK_PCORE | KNTWR_TICK_CORE_AB | KNTWR_ARMY_SOLVER_MEMO | KNTWR_ARMY_SOLVER_SHADOW | KNTWR_ALLOC_CENSUS | KNTWR_ARENA_RELEASE | KNTWR_HEAP_OPTIMIZE | KNTWR_ALLOC_FIX | KNTWR_MOUNTED_OFFICER | KNTWR_MOUNTED_OFFICER_WIDEN | KNTWR_ENGAGE_CENSUS | KNTWR_FORMATION_CENSUS | KNTWR_VA_FLOOR_MASK | KNTWR_VA_HOLE_MASK)),
              "army storm row keeps the four retired puppet motion/divert/mover/select rows' 128 words after army_b0_words");
static_assert(offsetof(kntwr_status,brain_s0_words) + KNTWR_BRAIN_S0_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_deferred_words) &&
              KNTWR_BRAIN_S0_WORDS == 560u, "brain S0 row appends after army_storm_words");
static_assert(offsetof(kntwr_status,ai_deferred_words) + KNTWR_AI_DEFERRED_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_ctrl_reuse_words) &&
              KNTWR_AI_DEFERRED_WORDS == 64u, "ai_deferred row appends after brain_s0_words");
static_assert(offsetof(kntwr_status,ai_ctrl_reuse_words) + KNTWR_AI_CTRL_REUSE_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_relink_words) &&
              KNTWR_AI_CTRL_REUSE_WORDS == 32u && KNTWR_AI_CTRL_FLAGS_VALID == 0x1F0Fu && KNTWR_AI_CTRL_MODE_MASK == 0xFu &&
              KNTWR_AI_CLAIM_ONCE == 0x100u && KNTWR_AI_CLAIM_ONCE_CENSUS == 0x200u && KNTWR_AI_TARGET_CULL_SHADOW == 0x400u && KNTWR_AI_TARGET_CULL == 0x800u &&
              KNTWR_AI_RETARGET_JITTER == 0x1000u, "ai_ctrl_reuse row appends after ai_deferred_words");
static_assert(offsetof(kntwr_status,loco_relink_words) + KNTWR_LOCO_RELINK_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_cw_words) &&
              offsetof(kntwr_status,loco_cw_words) + KNTWR_LOCO_CW_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,loco_grid_build_words) && KNTWR_LOCO_CW_WORDS == 32u &&
              KNTWR_LOCO_RELINK_WORDS == 32u && KNTWR_LOCO_RELINK_SHADOW == 0x200u && KNTWR_LOCO_RELINK_WORKERS == 0x400u, "loco_relink row appends after ai_ctrl_reuse_words");
static_assert(offsetof(kntwr_status,loco_grid_build_words) + KNTWR_LOCO_GRID_BUILD_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,brain_unit_policy_words) &&
              KNTWR_LOCO_GRID_BUILD_WORDS == 16u && KNTWR_LOCO_GRID_INCREMENTAL == 0x100u &&
              (KNTWR_LOCO_FLAGS_VALID & KNTWR_LOCO_GRID_INCREMENTAL) != 0, "loco_grid_build row appends after loco_cw_words");
static_assert(offsetof(kntwr_status,brain_unit_policy_words) + KNTWR_BRAIN_UNIT_POLICY_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_prepass_census_words) &&
              KNTWR_BRAIN_UNIT_POLICY_WORDS == 256u && KNTWR_BRAIN_UNIT_FATIGUE == 0x200u && KNTWR_BRAIN_UNIT_FATIGUE_SHADOW == 0x400u &&
              KNTWR_BRAIN_UNIT_POSTURE == 0x800u && KNTWR_BRAIN_UNIT_POSTURE_SHADOW == 0x1000u && KNTWR_BRAIN_UNIT_ENGAGE == 0x2000u &&
              KNTWR_BRAIN_UNIT_ENGAGE_SHADOW == 0x4000u && (KNTWR_BRAIN_FLAGS_VALID & 0x7e00u) == 0x7e00u,
              "brain_unit_policy row appends after loco_grid_build_words; unit flags 0x200..0x4000 are valid brain flags");
static_assert(offsetof(kntwr_status,ai_prepass_census_words) + KNTWR_AI_PREPASS_CENSUS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_prepass_words) &&
              offsetof(kntwr_status,ai_prepass_words) + KNTWR_AI_PREPASS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,ai_spiral_words) &&
              offsetof(kntwr_status,ai_spiral_words) + KNTWR_AI_SPIRAL_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,army_solver_words) &&
              offsetof(kntwr_status,army_solver_words) + KNTWR_ARMY_SOLVER_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,alloc_census_words) &&
              offsetof(kntwr_status,alloc_census_words) + KNTWR_ALLOC_CENSUS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,arena_words) &&
              offsetof(kntwr_status,arena_words) + KNTWR_ARENA_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,overlay_words) &&
              offsetof(kntwr_status,overlay_words) + KNTWR_OVERLAY_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,mounted_officer_words) &&
              offsetof(kntwr_status,mounted_officer_words) + KNTWR_MOUNTED_OFFICER_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,engage_census_words) &&
              offsetof(kntwr_status,engage_census_words) + KNTWR_ENGAGE_CENSUS_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,anim_guard_words) &&
              offsetof(kntwr_status,anim_guard_words) + KNTWR_ANIM_GUARD_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,army_residual_words) &&
              offsetof(kntwr_status,army_residual_words) + KNTWR_FORMATION_RESIDUAL_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,drag_ladder_words) &&
              offsetof(kntwr_status,drag_ladder_words) + KNTWR_DRAG_LADDER_WORDS * sizeof(uint32_t) == offsetof(kntwr_status,wounded_words) &&
              offsetof(kntwr_status,wounded_words) + KNTWR_WOUNDED_WORDS * sizeof(uint32_t) == sizeof(kntwr_status) &&
              KNTWR_DRAG_LADDER_WORDS == 16u && KNTWR_DRAG_LADDER == 0x1u &&
              KNTWR_WOUNDED_WORDS == 16u && KNTWR_WOUNDED == 0x2u && KNTWR_WOUNDED_PCT_MASK == 0x7F00u &&
              KNTWR_GAMEPLAY_FLAGS_VALID == (KNTWR_DRAG_LADDER | KNTWR_WOUNDED | KNTWR_WOUNDED_PCT_MASK) &&
              KNTWR_ANIM_GUARD_WORDS == 8u &&
              KNTWR_FORMATION_RESIDUAL_WORDS == 832u &&
              KNTWR_ENGAGE_CENSUS_WORDS == 6832u &&
              KNTWR_ENGAGE_CENSUS == 0x80000u &&
              KNTWR_ALLOC_CENSUS_WORDS == 1056u && KNTWR_ARENA_WORDS == 32u && KNTWR_OVERLAY_WORDS == 16u && KNTWR_MOUNTED_OFFICER_WORDS == 16u &&
              KNTWR_ALLOC_CENSUS == 0x40u && KNTWR_ARENA_RELEASE == 0x80u && KNTWR_HEAP_OPTIMIZE == 0x10000u && KNTWR_ALLOC_FIX == 0x200000u &&
              KNTWR_MOUNTED_OFFICER == 0x20000u && KNTWR_MOUNTED_OFFICER_WIDEN == 0x40000u &&
              KNTWR_ARMY_SOLVER_WORDS == 524u && KNTWR_ARMY_SOLVER_MEMO == 0x10u && KNTWR_ARMY_SOLVER_SHADOW == 0x20u &&
              KNTWR_AI_PREPASS_CENSUS_WORDS == 82u && KNTWR_AI_POLY_WORDS == 32u && KNTWR_AI_RECORD_TEST_WORDS == 28u && KNTWR_AI_PREPASS_WORDS == 60u &&
              KNTWR_AI_PREPASS_CENSUS == 0x1u && KNTWR_AI_PRESIZE == 0x2u &&
              KNTWR_AI_POLY_SHADOW == 0x4u && KNTWR_AI_POLY == 0x8u && KNTWR_AI_SPIRAL_CENSUS == 0x10u && KNTWR_AI_SPIRAL_WORDS == 32u &&
              KNTWR_AI_RECORD_TEST_SHADOW == 0x20u && KNTWR_AI_RECORD_TEST == 0x40u &&
              KNTWR_AI_SPIRAL_CAP_MASK == (0xFFFFu << KNTWR_AI_SPIRAL_CAP_SHIFT) &&
              KNTWR_AI_PREPASS_FLAGS_VALID == (KNTWR_AI_PREPASS_CENSUS | KNTWR_AI_PRESIZE | KNTWR_AI_POLY_SHADOW | KNTWR_AI_POLY | KNTWR_AI_SPIRAL_BITS |
                                              KNTWR_AI_RECORD_TEST_SHADOW | KNTWR_AI_RECORD_TEST),
              "ai_prepass_census, ai_prepass, ai_spiral, army_solver, alloc_census, arena and overlay rows append in order at the status tail");
static_assert(KNTWR_GRID_CENSUS == 0x8000u && (KNTWR_VALID_MASK & KNTWR_GRID_CENSUS) && !(KNTWR_ALL & KNTWR_GRID_CENSUS) &&
              sizeof(kntwr_grid_reader_status) == 1008 && sizeof(kntwr_grid_edge_status) == 32 &&
              offsetof(kntwr_grid_census_status, readers) == 40 && offsetof(kntwr_grid_census_status, edges) == 40 + 64 * 1008 &&
              sizeof(kntwr_grid_census_status) == 40 + 64 * 1008 + 512 * 32 &&
              offsetof(kntwr_grid_reader_status, calls_site) == 96 + 8, "grid census status geometry");
static_assert(KNTWR_LOCO == 0x4000u && (KNTWR_ALL & KNTWR_LOCO) == KNTWR_LOCO && (KNTWR_VALID_MASK & KNTWR_LOCO) == KNTWR_LOCO &&
              !(KNTWR_LOCO & (KNTWR_AI_BUDGET_EMA | KNTWR_AI_SAFE_PARK | KNTWR_AI_CTRL)), "loco is part of the shipping set KNTWR_ALL");
static_assert(offsetof(kntwr_status,ai_ctrl_words) == offsetof(kntwr_status,collide_lod_words) + KNTWR_COLLIDE_LOD_WORDS * sizeof(uint32_t) &&
              sizeof(((kntwr_status*)nullptr)->ai_ctrl_words) == 16 * sizeof(uint32_t), "controller telemetry is append-only");
static_assert(KNTWR_AI_CTRL == 0x800u && !(KNTWR_ALL & KNTWR_AI_CTRL) && (KNTWR_VALID_MASK & KNTWR_AI_CTRL), "controller offload is explicit opt-in");
static_assert(!(KNTWR_ALL & (KNTWR_AI_BUDGET_EMA | KNTWR_AI_SAFE_PARK)) &&
              !(KNTWR_VALID_MASK & (KNTWR_AI_BUDGET_EMA | KNTWR_AI_SAFE_PARK)),
              "retired AI suspension policies cannot be requested");
static_assert(offsetof(kntwr_status,ai_slice_words) == 4 * (29 + 16 + 16 + 24 + 8 + 192 + 16 + 16 + 64 + 16 + 16 + 32 + 32 + KNTWR_BRAIN_WORDS + 32 + 80), "slice telemetry is append-only");
static_assert(offsetof(kntwr_status,ai_validation_words) == offsetof(kntwr_status,ai_slice_words) + 8 * sizeof(uint32_t), "validation telemetry is append-only");
static_assert(offsetof(kntwr_status,visual_words) == offsetof(kntwr_status,ai_validation_words) + 8 * sizeof(uint32_t), "visual telemetry is append-only");
static_assert(offsetof(kntwr_status,allocator_words) == offsetof(kntwr_status,visual_words) + 32 * sizeof(uint32_t), "allocator admission telemetry is append-only");
static_assert(offsetof(kntwr_status,ai_slice_site_words) == offsetof(kntwr_status,allocator_words) + KNTWR_ALLOCATOR_WORDS * sizeof(uint32_t), "slice location telemetry is append-only");
static_assert(offsetof(kntwr_status,brain_state_words) == offsetof(kntwr_status,ai_slice_site_words) + 2 * sizeof(uint32_t), "brain census telemetry is append-only");
static_assert(offsetof(kntwr_status,collision_words) == offsetof(kntwr_status,brain_state_words) + KNTWR_BRAIN_STATE_WORDS * sizeof(uint32_t), "collision census telemetry is append-only");
static_assert(offsetof(kntwr_status,collide_words) == offsetof(kntwr_status,collision_words) + KNTWR_COLLISION_WORDS * sizeof(uint32_t) &&
              KNTWR_COLLIDE_WORDS == 61u && sizeof(((kntwr_status*)nullptr)->collide_words) == 61 * sizeof(uint32_t), "collision solver telemetry is append-only");
static_assert(offsetof(kntwr_status,brain2_words) == offsetof(kntwr_status,collide_words) + KNTWR_COLLIDE_WORDS * sizeof(uint32_t) &&
              KNTWR_BRAIN2_WORDS == 48u && KNTWR_BRAIN2 == 0x80u && !(KNTWR_ALL & KNTWR_BRAIN2) && (KNTWR_VALID_MASK & KNTWR_BRAIN2) == KNTWR_BRAIN2,
              "brain2 telemetry is append-only; the feature bit is valid and outside KNTWR_ALL");
static_assert(offsetof(kntwr_status,collide_lod_words) == offsetof(kntwr_status,brain2_words) + KNTWR_BRAIN2_WORDS * sizeof(uint32_t) &&
              KNTWR_COLLIDE_LOD_WORDS == 16u && KNTWR_COLLIDE_LOD == 0x400u && !(KNTWR_ALL & KNTWR_COLLIDE_LOD),
              "collision LOD telemetry is append-only and opt-in");
static_assert(KNTWR_COLLISION_WORDS == 32u && KNTWR_TIMED_SITES == 110u, "collision census geometry");
static_assert(KNTWR_BRAIN_STATE_COUNTS + KNTWR_BRAIN_STATE_BUCKETS == KNTWR_BRAIN_SUBSTATE_COUNTS &&
              KNTWR_BRAIN_SUBSTATE_COUNTS + KNTWR_BRAIN_SUBSTATE_BUCKETS == KNTWR_BRAIN_TRANSITION_COUNTS &&
              KNTWR_BRAIN_TRANSITION_COUNTS + KNTWR_BRAIN_STATE_BUCKETS == KNTWR_BRAIN_TRANSITION_UNITS &&
              KNTWR_BRAIN_TRANSITION_UNITS + KNTWR_BRAIN_STATE_BUCKETS == KNTWR_BRAIN_STATE_WORDS, "brain census geometry");
static_assert(KNTWR_BRAIN_HEADER_WORDS + 2 * KNTWR_BRAIN_FAMILIES * KNTWR_BRAIN_SITES <= KNTWR_BRAIN_WORDS &&
              KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_SITES == 95u && KNTWR_TIMED_SITES <= KNTWR_TRACE_SITES, "brain words geometry");
static_assert(sizeof(kntwr_profile_status) == 15748, "profile ABI");
static_assert(sizeof(kntwr_profile_phase_status) == 184 &&
              offsetof(kntwr_profile_status, main_start_tick_ms) == 10948 &&
              offsetof(kntwr_profile_status, main_rest) == 10952, "split tick phase is append-only");
static_assert(offsetof(kntwr_profile_status, main_modules) == 10832, "module profile is append-only");
static_assert(offsetof(kntwr_profile_status, main_thread_id) == 5768, "main profile is append-only");
static_assert(sizeof(((kntwr_profile_status*)0)->chain_count) == 256 &&
              sizeof(((kntwr_profile_status*)0)->chain_len) == 256 &&
              sizeof(((kntwr_profile_status*)0)->chains) == 4096, "profile chain ABI");
static_assert(sizeof(((kntwr_profile_status*)0)->main_hist_va) == 12 &&
              sizeof(((kntwr_profile_status*)0)->main_post_chain_count) == 256 &&
              sizeof(((kntwr_profile_status*)0)->main_post_chain_len) == 256 &&
              sizeof(((kntwr_profile_status*)0)->main_post_chains) == 4096, "main profile ABI");
static_assert(sizeof(((kntwr_profile_status*)0)->main_start_chain_count) == 256 &&
              sizeof(((kntwr_profile_status*)0)->main_start_chain_len) == 256 &&
              sizeof(((kntwr_profile_status*)0)->main_start_chains) == 4096, "main A1 chain ABI");
static_assert(offsetof(kntwr_trace_entry, site_us) == 32 &&
              offsetof(kntwr_trace_entry, site_calls) == 480 &&
              offsetof(kntwr_trace_entry, qpc_start_lo) == 928, "trace QPC is append-only");
static_assert(sizeof(kntwr_trace_entry) == 944 && sizeof(kntwr_trace_ring) == 32 + 944 * KNTWR_TRACE_ENTRIES, "trace ABI");
#endif
#endif
