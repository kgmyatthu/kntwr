#ifndef NTW2_RUNTIME_H
#define NTW2_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NTW2_ABI 1u
#define NTW2_PATH 0x01u
#define NTW2_FORMATION 0x02u
#define NTW2_BALLISTICS 0x04u
#define NTW2_AI_ASYNC 0x08u /* Whole native planner calls run in a single worker slot and join before site 34 returns. */
#define NTW2_BATCH64 0x10u
#define NTW2_PROFILE 0x20u /* Opt-in instrumentation; deliberately not part of NTW2_ALL. */
#define NTW2_BRAIN 0x40u /* Opt-in, requires NTW2_PROFILE: times every level-1 callee of the per-agent brain step per class family (see brain_words). Not part of NTW2_ALL. */
#define NTW2_BRAIN2 0x80u /* Opt-in BRAIN2 v2: owner-ordered observation or serial gated clones at site 6 (Stage 1); with NTW2_BRAIN_PARALLEL (+census) the per-soldier step also runs speculatively on pool workers over private receiver copies with guarded owner-ordered commit (Stage 2). Outside NTW2_ALL. */
#define NTW2_VISUAL 0x100u /* Main-thread 0x779E60 loop-1 sharding; part of the shipping set. */
#define NTW2_COLLIDE 0x200u /* Opt-in experimental Phase B soft-collision solver; not part of NTW2_ALL. */
#define NTW2_COLLIDE_LOD 0x400u /* Opt-in half-rate far-unit queries; incompatible with COLLIDE and FORMATION. */
#define NTW2_AI_CTRL 0x800u /* Experimental controller offload with an immediate completion barrier; requires AI_ASYNC. */
#define NTW2_AI_BUDGET_EMA 0x1000u /* Reserved retired bit; configurations requesting it are rejected. */
#define NTW2_AI_SAFE_PARK 0x2000u /* Reserved retired bit; configurations requesting it are rejected. */
#define NTW2_LOCO 0x4000u /* Experimental locomotion Stages A/B/C (timed site 13 = 0x531AF0). Opt-in, outside NTW2_ALL; refuses BRAIN and COLLIDE_LOD. Coexists with owner-serial BRAIN2. COLLIDE requires CLONE, PARALLEL, OWNED_SERVICES and GRID (or GRID_VERIFY). */
#define NTW2_GRID_CENSUS 0x8000u /* Opt-in reader edge counts and sampled occupancy; requires LOCO and a main thread id, not PROFILE. */
#define NTW2_AI_CENSUS 0x10000u /* Opt-in observation of who mutates/destroys the AI planner object graph (ai_census_words): pinned vtable-slot gates, one clone-call gate and sampler ranges. Requires AI_ASYNC and a main thread id; outside NTW2_ALL. */
#define NTW2_AI_CENSUS_WORDS 768u /* 16 header + 7 targets * (8 + 8 callers * 12) + 3 sample ranges * 8; layout: src/ntw2_ai_census.h */
#define NTW2_AI_ASYNC2 0x20000u /* Opt-in experimental async think, boundary schedule (ai_async2_words, ai_async2_route_words): site 34 queues the whole planner call and returns; tick end publishes the batch; the AI worker runs it in the inter-tick window through its private walk/observer clone family; the next tick start is a blocking lifetime join (no think crosses into a tick); structural writers join (site 33 controller, TICK 57DFDF quadtree update, delegate replacement/destructor and observer/operation owner-destructor vtable slots; a non-tick owner teardown drains the whole batch first); worker calls of those slots and of 0x83FD00 are marshalled; stop drains before routing ends (servicing or aborting a pending marshal); 5 s watchdog with sticky synchronous fallback. Requires AI_ASYNC; refuses AI_CTRL and AI_CENSUS (same slots/site 33); outside NTW2_ALL. */
#define NTW2_AI_ASYNC2_WORDS 96u /* layout: src/ntw2_ai_async2.h, labels NTW2_AI_ASYNC2_LABELS */
#define NTW2_AI_ASYNC2_ROUTE_WORDS 65u /* ai_async2_route_words; layout src/ntw2_ai_async2.h (RouteWord), labels NTW2_AI_ASYNC2_ROUTE_LABELS */
#define NTW2_ARMY_UNIT_SHADOW 0x40000u /* Opt-in --army-unit-shadow: item 4 Stage A, instrumentation only. Site 18 (ARMY_UPDATE clone) and its 0x581F30 calls (sites 101/103) are bound to owner-thread gates that time each unit update, classify it under the approved compromises (owner-only reasons, RNG draws, foreign-unit witness, command-class census) and measure a frozen-view copy; the native calls run unchanged. Requires a routed tick (PROFILE or a simulation feature); planner writes are measured only with AI_CENSUS. Outside NTW2_ALL. Words: army_unit_words, src/army/native_army_unit.h. */
#define NTW2_ARMY_UNIT_WORDS 192u /* army_unit_words; layout src/army/native_army_unit.h (Word), labels NTW2_ARMY_UNIT_*_LABELS */
#define NTW2_PUPPET 0x80000u /* Opt-in --puppet-probe N|all: puppet survival probe (analysis/native-unit-sim-rewrite.md section 3). N = ntw2_config::puppet_units (1..NTW2_PUPPET_MAX_UNITS; the maximum selects every qualifying unit) ordinary foot-infantry units (class 0x1333714, registry order) get the engine's real wait node (0x650600 -> 0x61D8F0, table 0x1334028) at an owner stage seam; site 6 skips their native step +0C and the class common-step slot +08 (0x670EB0) keeps only terrain/extent 0x81AC80 and order->activity 0x663730 for them. A +628 divert keeps the member but runs his native step (the controller branch 0x67A050) until the controller releases him. Externally installed nodes are reparked or handed back; stop hands members back without native writes. Sole owner of site 6: refuses BRAIN2, BRAIN and brain flags. Routed simulation feature outside NTW2_ALL. Words: puppet_words, puppet_motion_words, puppet_divert_words, src/puppet/native_puppet.h. */
#define NTW2_PUPPET_WORDS 64u /* puppet_words; layout src/puppet/native_puppet.h (Word), labels NTW2_PUPPET_WORD_LABELS */
#define NTW2_ARMY_B0_WORDS 160u /* army_b0_words (NTW2_ARMY_UNIT_SHADOW, Stage B0 qualification); layout src/army/native_army_unit.h (B0Word), labels NTW2_ARMY_B0_LABELS */
#define NTW2_PUPPET_MOTION_WORDS 32u /* puppet_motion_words; layout src/puppet/native_puppet.h (MotionWord), labels NTW2_PUPPET_MOTION_LABELS */
#define NTW2_PUPPET_MAX_UNITS 2048u /* unit capacity; puppet_units == NTW2_PUPPET_MAX_UNITS is --puppet-probe all */
#define NTW2_PUPPET_ROW_UNITS 4u    /* units with an identity row in puppet_words (words 40..55) */
#define NTW2_PUPPET_DIVERT_WORDS 32u /* puppet_divert_words; layout src/puppet/native_puppet.h (DivertWord), labels NTW2_PUPPET_DIVERT_LABELS */
#define NTW2_PUPPET_MOVER_WORDS 32u /* puppet_mover_words; layout src/puppet/native_puppet.h (MoverWord), labels NTW2_PUPPET_MOVER_LABELS */
#define NTW2_PUPPET_SELECT_WORDS 32u /* puppet_select_words; layout src/puppet/native_puppet.h (SelectWord), labels NTW2_PUPPET_SELECT_LABELS */
#define NTW2_LOCO_CLONE 0x1u /* ntw2_config::loco_flags bit (launcher --loco-clone): execute admitted movement occurrences through the private LOCO clone family instead of the original code; requires NTW2_LOCO. */
#define NTW2_LOCO_PARALLEL 0x2u /* ntw2_config::loco_flags bit (launcher --loco-parallel): closed movement workers; requires NTW2_LOCO and NTW2_LOCO_CLONE. Requested grid/CSR workers also run without this bit. */
#define NTW2_LOCO_SHADOW 0x4u /* Owner-thread sweep/resolve oracle; requires LOCO_CLONE. */
#define NTW2_LOCO_OWNED_SERVICES 0x8u /* Opt-in supported active mover path (launcher --loco-owned-services): owner-prepared sweep/resolve/environment services replayed from worker-private state; requires NTW2_LOCO, LOCO_CLONE and LOCO_PARALLEL. Unsupported occurrences fall back to the owner before any irreversible write. */
#define NTW2_LOCO_QUIET 0x10u /* Low-overhead owned mode (launcher --loco-quiet): disables per-service QPC timing, owner shadow comparisons (even with NTW2_LOCO_SHADOW) and the all-gates histogram; faults, share and detail counters stay. Requires NTW2_LOCO_OWNED_SERVICES (thus PARALLEL, CLONE and LOCO). */
#define NTW2_LOCO_GRID 0x20u /* Optional owned soldier grid v2 published at site-13 exit (launcher --loco-grid); requires NTW2_LOCO. Default off; combined COLLIDE borrows the published view without rebuilding. */
#define NTW2_LOCO_GRID_VERIFY 0x40u /* Launcher --loco-grid-verify: implies GRID and enables owner-side grid verification; requires NTW2_LOCO. */
#define NTW2_LOCO_GRID_PROBATION 0x80u /* ntw2_config::loco_flags bit (launcher --grid-probation): relink-retirement detector. Requires NTW2_LOCO and NTW2_LOCO_GRID (or GRID_VERIFY); refused with NTW2_BALLISTICS (its query cache walks the heads in runtime code). Native chains stay dual-written; the model+A4 cell-head array is PAGE_NOACCESS outside the owner site-13 relink window; a first-chance vectored handler logs the trapping instruction/caller/thread/site, restores the page and resumes. Words: grid_probation_words, src/loco/native_grid_probation.h. */
#define NTW2_LOCO_FLAGS_VALID (NTW2_LOCO_CLONE | NTW2_LOCO_PARALLEL | NTW2_LOCO_SHADOW | NTW2_LOCO_OWNED_SERVICES | NTW2_LOCO_QUIET | NTW2_LOCO_GRID | NTW2_LOCO_GRID_VERIFY | NTW2_LOCO_GRID_PROBATION)
/* Brain profiling geometry (see ntw2_status::brain_words). Families, in entry-site order 46..50:
   0 slot +0x0C = 0x66CE00 (11 vtables), 1 = 0x6F50F0 thunk (1), 2 = 0x6F4660 wrapper (6), 3 = 0x602EB0 wrapper (1), 4 = 0x5FCEB0 wrapper (4). */
#define NTW2_BRAIN_FAMILIES 5u
#define NTW2_BRAIN_SITE_FIRST 46u
#define NTW2_BRAIN_SITES 49u        /* trace sites 46..94 */
#define NTW2_BRAIN_HEADER_WORDS 8u
#define NTW2_BRAIN_WORDS 512u
#define NTW2_BRAIN_SLOTS 23u        /* registry vtables whose slot +0x0C is published while NTW2_BRAIN is armed */
#define NTW2_BRAIN_STATE_BUCKETS 64u
#define NTW2_BRAIN_SUBSTATE_BUCKETS 80u
#define NTW2_BRAIN_STATE_COUNTS 16u
#define NTW2_BRAIN_SUBSTATE_COUNTS 80u
#define NTW2_BRAIN_TRANSITION_COUNTS 160u
#define NTW2_BRAIN_TRANSITION_UNITS 224u
#define NTW2_BRAIN_STATE_WORDS 288u
#define NTW2_COLLISION_WORDS 32u
#define NTW2_COLLIDE_WORDS 61u
#define NTW2_BRAIN2_WORDS 48u
#define NTW2_BRAIN2_VERSION 2u
#define NTW2_BRAIN_CENSUS 0x1u /* Serial gated clone and per-service activity bookkeeping; --brain-census. */
#define NTW2_BRAIN_TIMING 0x2u /* QPC original/serial-clone measurement; --brain-timing. Off by default. */
#define NTW2_BRAIN_NODE_SHADOW 0x4u /* Owner-only reference-node differential execution; implies gated census. */
#define NTW2_BRAIN_FIRE_SHADOW 0x8u /* Owner-only request-sequencer differential execution; implies gated census. */
#define NTW2_BRAIN_PARALLEL 0x10u /* Stage 2 (--brain-parallel): per-soldier brain step on pool workers over private receiver copies, owner-ordered guarded commit; requires BRAIN2 and NTW2_BRAIN_CENSUS or NTW2_BRAIN_QUIET. Words: brain_worker_words / brain_worker_phase_words, src/brain2/native_brain_workers.h. */
#define NTW2_BRAIN_FINALIZER_SHADOW 0x20u /* --brain-finalizer-shadow: owner-only private-copy rerun of proved 0x819770 calls, bit-exact compare; implies gated census. Words: brain2_unknown_site_words witness 21..23 (native_brain2.h). */
#define NTW2_BRAIN_QUIET 0x40u /* --brain-quiet: the performance configuration of NTW2_BRAIN_PARALLEL (required). Owner-run occurrences execute the ORIGINAL step (no serial gated census clone, no per-service bookkeeping, no first-unresolved histograms, no QPC per service); workers keep their classification gates and the guarded commit; guard misses are counted without block checksums. Excludes NTW2_BRAIN_CENSUS, TIMING and every shadow flag. Phase telemetry: brain_worker_phase_words. */
#define NTW2_BRAIN_UNIT_SHADOW 0x80u /* --brain-unit-shadow: per-unit brain Stage A, shadow only. Before the unchanged site-6 loop, pool workers compute one UnitDecision per unit from unit-level inputs (no writes); after each soldier's native step the owner compares the fields it decided against its unit's decision. Requires BRAIN2; excludes NTW2_BRAIN_PARALLEL/QUIET. Words: brain_unit_words, src/brain2/native_unit_brain.h. */
#define NTW2_BRAIN_FLAGS_VALID 0xffu
#define NTW2_BRAIN_UNIT_WORDS 176u
#define NTW2_BRAIN_WORKER_WORDS 144u
#define NTW2_BRAIN_WORKER_PHASE_WORDS 40u
#define NTW2_NODE_WORDS 32u
#define NTW2_NODE_EVENT_WORDS 16u
#define NTW2_FIRE_WORDS 24u
#define NTW2_BRAIN2_ROUTE_WORDS 8u
#define NTW2_FIRE_COMMIT_WORDS 32u
#define NTW2_MOVE_NODE_WORDS 32u
#define NTW2_MOVE_NODE_EVENT_WORDS 16u
#define NTW2_BRAIN2_NODE_TARGET_WORDS 36u
#define NTW2_BRAIN2_UNKNOWN_SITE_WORDS 128u /* 2 x (4 + 16 x 3) site tables + 24 witness words; native_brain2.h */
#define NTW2_IDLE_NODE_CLASSES 2u
#define NTW2_ACTION_NODE_CLASSES 3u
#define NTW2_BRAIN2_CENSUS_WORDS 424u /* 53 service rows x 8 words; module enum order. */
#define NTW2_AI_SLICE_BUDGET_WORDS 8u
#define NTW2_AI_COMPLETION_WORDS 24u
#define NTW2_AI_COMPLETION_LABELS \
    "think_count", "think_sum_us", "max_planner_us", "barrier_count", "barrier_sum_us", "max_barrier_us", \
    "think_le8ms", "think_le16ms", "think_le32ms", "think_le64ms", "think_le128ms", \
    "think_le256ms", "think_le512ms", "think_le1024ms", "think_gt1024ms", \
    "barrier_le8ms", "barrier_le16ms", "barrier_le32ms", "barrier_le64ms", "barrier_le128ms", \
    "barrier_le256ms", "barrier_le512ms", "barrier_le1024ms", "barrier_gt1024ms"
#define NTW2_LOCO_WORDS 48u
#define NTW2_LOCO_GATE_WORDS 48u
#define NTW2_LOCO_SERVICE_WORDS 40u
#define NTW2_LOCO_GRID_WORDS 32u
#define NTW2_LOCO_PARALLEL_WORDS 32u
#define NTW2_SWEEP_WORDS 32u
#define NTW2_RESOLVE_WORDS 32u
#define NTW2_ENV_WORDS 32u
#define NTW2_LOCO_OWNED_WORDS 32u
#define NTW2_LOCO_OWNED_DETAIL_WORDS 16u
#define NTW2_LOCO_OWNED_PHASE_WORDS 32u
#define NTW2_LOCO_OWNED_LOAD_WORDS 16u
#define NTW2_LOCO_GRID_V2_WORDS 16u
#define NTW2_COLLIDE_SOURCE_WORDS 4u
#define NTW2_COLLIDE_CONTACT_WORDS 48u /* collide_contact_words; labels/layout NTW2_COLLIDE_CONTACT_WORD_LABELS in src/collision/native_contact.h */
#define NTW2_COLLIDE_CONTACT_SHADOW 0x1u /* ntw2_config::collide_flags (launcher --collide-contact-shadow): plan every solver contact callback on pool workers from stage-entry state and compare each plan with the original callback the owner still runs. Requires NTW2_COLLIDE; excludes NTW2_COLLIDE_CONTACT_WORKERS. */
#define NTW2_COLLIDE_CONTACT_WORKERS 0x2u /* collide_flags (--collide-contact-workers): same-team LAND contacts are decided on pool workers; the owner replays their tracker/+0x13C/avoidance effects in contact order, every other contact runs the original callback in place. Requires NTW2_COLLIDE. */
#define NTW2_COLLIDE_FLAGS_VALID 0x3u
#define NTW2_GRID_PROBATION_HEADER_WORDS 32u
#define NTW2_GRID_PROBATION_CALLERS 256u
#define NTW2_GRID_PROBATION_WORDS (NTW2_GRID_PROBATION_HEADER_WORDS + NTW2_GRID_PROBATION_CALLERS * 8u)
#define NTW2_GRID_PROBATION_LABELS \
    "version", "enabled", "state", "isolated", "arms", "window_opens", "traps", "cell_traps", \
    "edge_traps", "write_traps", "restore_failures", "foreign_faults", "callers_used", "callers_dropped", \
    "armed_pages", "uncovered_bytes", "array_base", "array_bytes", "allocation_base", "allocation_bytes", \
    "arm_us", "open_us", "max_toggle_us", "layout_changes", "refusals", "traps_tick", "traps_pool", \
    "traps_ai", "traps_main", "traps_other", "probe_arms", "disarms"
#define NTW2_MEMORY_WORDS 57u
#define NTW2_MEMORY_MIN_AVAIL_VIRTUAL (512u * 1024u * 1024u)
#define NTW2_MEMORY_WORD_LABELS \
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
    "loco_catalog_capsules", "loco_catalog_walls", "loco_catalog_edges", "loco_catalog_polygon_points"
enum ntw2_memory_word {
    NTW2_MEM_VERSION, NTW2_MEM_LOCO_BYTES, NTW2_MEM_COLLIDE_BYTES, NTW2_MEM_PROFILE_BYTES,
    NTW2_MEM_RUNTIME_IMAGE_BYTES, NTW2_MEM_CLONE_BYTES, NTW2_MEM_POOL_STACK_BYTES, NTW2_MEM_AI_STACK_BYTES,
    NTW2_MEM_OTHER_STACK_BYTES, NTW2_MEM_LOD_BYTES, NTW2_MEM_BALLISTICS_BYTES, NTW2_MEM_OTHER_BYTES,
    NTW2_MEM_TOTAL_BYTES, NTW2_MEM_ACTIVATION_AVAIL_LO, NTW2_MEM_ACTIVATION_AVAIL_HI,
    NTW2_MEM_POST_ALLOC_AVAIL_LO, NTW2_MEM_POST_ALLOC_AVAIL_HI, NTW2_MEM_MIN_AVAIL_LO, NTW2_MEM_MIN_AVAIL_HI,
    NTW2_MEM_SAMPLES, NTW2_MEM_BUDGET_REFUSALS, NTW2_MEM_ERROR, NTW2_MEM_PRIMARY_CAPACITY,
    NTW2_MEM_RECORD_CAPACITY, NTW2_MEM_CELL_CAPACITY, NTW2_MEM_MEMBERSHIP_CAPACITY,
    NTW2_MEM_PAIR_CAPACITY, NTW2_MEM_FLOOR_BYTES,
    NTW2_MEM_LOCO_MOVEMENT_BYTES, NTW2_MEM_LOCO_GRID_BYTES, NTW2_MEM_LOCO_SCENE_BYTES,
    NTW2_MEM_LOCO_CATALOG_BYTES, NTW2_MEM_LOCO_PARTICIPANTS_BYTES, NTW2_MEM_LOCO_SWEEP_SCRATCH_BYTES,
    NTW2_MEM_LOCO_RESOLVE_SCRATCH_BYTES, NTW2_MEM_LOCO_ENV_SCRATCH_BYTES,
    NTW2_MEM_LOCO_SCENE_NODES, NTW2_MEM_LOCO_SCENE_OWNERS, NTW2_MEM_LOCO_TREE_ENTRIES,
    NTW2_MEM_BUDGET_DISABLED_MASK, NTW2_MEM_BUDGET_RELEASE_PENDING, NTW2_MEM_BUDGET_RELEASES,
    NTW2_MEM_RELEASED_LOCO_BYTES, NTW2_MEM_RELEASED_COLLIDE_BYTES,
    NTW2_MEM_NATIVE_GRID_SHIFT, NTW2_MEM_NATIVE_GRID_MAXIMUM, NTW2_MEM_NATIVE_GRID_DIMENSION,
    NTW2_MEM_LOCO_CATALOG_RING_BYTES, NTW2_MEM_LOCO_CATALOG_CAPSULE_BYTES, NTW2_MEM_LOCO_CATALOG_WALL_BYTES,
    NTW2_MEM_LOCO_CATALOG_EDGE_BYTES, NTW2_MEM_LOCO_CATALOG_POLYGON_BYTES, NTW2_MEM_LOCO_CATALOG_RINGS,
    NTW2_MEM_LOCO_CATALOG_CAPSULES, NTW2_MEM_LOCO_CATALOG_WALLS, NTW2_MEM_LOCO_CATALOG_EDGES,
    NTW2_MEM_LOCO_CATALOG_POLYGON_POINTS
};
#define NTW2_ENV_TARGET_WORDS 64u
#define NTW2_RESOLVE_FRAME_WORDS 4u
#define NTW2_COLLIDE_LOD_WORDS 16u
#define NTW2_COLLIDE_CENSUS 0x80000000u /* collide_lod_m flag, NOT an enabled_mask feature; requires PROFILE. */
#define NTW2_COLLIDE_LOD_METRES_MASK 0x7fffffffu
#define NTW2_ALLOCATOR_THREADS 32u /* pool slots 0..30; dedicated AI worker = row 31 */
#define NTW2_ALLOCATOR_ROW_WORDS 8u
#define NTW2_ALLOCATOR_WORDS (NTW2_ALLOCATOR_THREADS * NTW2_ALLOCATOR_ROW_WORDS)
#define NTW2_ERROR_ALLOCATOR 14u
#define NTW2_ERROR_VA_BUDGET 15u
/* Shipping feature selection (launcher `--features all` and its default). The AI lifetime cutover requires fresh live verification.
   PATH, FORMATION, BALLISTICS, BRAIN2, COLLIDE, COLLIDE_LOD, AI_CTRL, PROFILE and BRAIN are opt-in. */
#define NTW2_ALL (NTW2_AI_ASYNC | NTW2_BATCH64 | NTW2_VISUAL)
/* Every feature bit the runtime accepts in ntw2_config::enabled_mask. */
#define NTW2_VALID_MASK (NTW2_PATH | NTW2_FORMATION | NTW2_BALLISTICS | NTW2_AI_ASYNC | NTW2_BATCH64 | NTW2_BRAIN2 | NTW2_VISUAL | NTW2_PROFILE | NTW2_BRAIN | NTW2_COLLIDE | NTW2_COLLIDE_LOD | NTW2_AI_CTRL | NTW2_LOCO | NTW2_GRID_CENSUS | NTW2_AI_CENSUS | NTW2_AI_ASYNC2 | NTW2_ARMY_UNIT_SHADOW | NTW2_PUPPET)
/* ai_async2_words labels, word order (histogram buckets: <=125us, <=250us, ... <=128ms, >128ms; gate kinds: site 34
   admission (capacity drain, lease wait, fallback join), site 33 controller, TICK 57DFDF quadtree update, tick end
   (start seam, abort drain), delegate replacement 6EA520/6B3010, delegate destructor 69D710/69D750, command callback
   805CE0/7DEC70 and the 83FD00 call gate, stop drain). Version 2 renamed words 3..5 for the boundary schedule; version 3
   (blocking tick-start join, owner-teardown pins, stop quiesce) names words 92..94. */
#define NTW2_AI_ASYNC2_HIST_LABELS(p) p "_le125us", p "_le250us", p "_le500us", p "_le1ms", p "_le2ms", p "_le4ms", \
    p "_le8ms", p "_le16ms", p "_le32ms", p "_le64ms", p "_le128ms", p "_gt128ms"
#define NTW2_AI_ASYNC2_KIND_LABELS(p) p "site34_admission", p "site33_controller", p "spatial_57dfdf", p "tick_end", \
    p "delegate_replace", p "delegate_dtor", p "command", p "stop"
#define NTW2_AI_ASYNC2_LABELS \
    "version", "dispatches", "completions", "admit_capacity_joins", "admit_lease_waits", "fallback_joins", \
    "deadlock_suspected", "fallback", "fallback_thinks", "marshalled_calls", "marshalled_nested", "marshal_wait_sum_us", \
    "marshal_wait_max_us", "think_sum_us", "think_max_us", "overlap_sum_us", "overlap_max_us", "join_wait_sum_us", \
    "join_wait_max_us", "in_flight", NTW2_AI_ASYNC2_HIST_LABELS("think"), NTW2_AI_ASYNC2_HIST_LABELS("overlap"), \
    NTW2_AI_ASYNC2_HIST_LABELS("join_wait"), \
    "waits_site34_admission", "max_wait_us_site34_admission", "waits_site33_controller", "max_wait_us_site33_controller", \
    "waits_spatial_57dfdf", "max_wait_us_spatial_57dfdf", "waits_tick_end", "max_wait_us_tick_end", \
    "waits_delegate_replace", "max_wait_us_delegate_replace", "waits_delegate_dtor", "max_wait_us_delegate_dtor", \
    "waits_command", "max_wait_us_command", "waits_stop", "max_wait_us_stop", \
    NTW2_AI_ASYNC2_KIND_LABELS("gate_"), NTW2_AI_ASYNC2_KIND_LABELS("marshal_"), \
    "spotting_gate_unresolved", "lease_holds", "walk_route_entries", "scratch_ready", \
    "stop_served_marshals", "stop_aborted_marshals", "owner_teardown_leases", "reserved95"
/* ai_async2_route_words labels: boundary schedule counters (ticks = tick-start seams; a batch is "complete" when it had
   finished by the next tick start: complete fraction = seam_complete_joins / published_batches; seam_stalls and
   seam_wait_sum_us/seam_wait_max_us are the tick-start lifetime join's stall for batches that had not), the routed-slot thread matrix (slot 0x133E2DC walk state 702BB0, slot 0x133773C observer 6A95A0;
   worker in a think -> private family, worker outside a think / tick owner / other thread -> original), entries of
   every private clone (generator AI2_ROUTE_ORDER), marshalled calls per pin, worker entries of the unrouted 83FD00 gate,
   private vector capacities after the last think and the private search-object construction mask. */
#define NTW2_AI_ASYNC2_ROUTE_LABELS \
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
#define NTW2_IMAGE_SHA256 "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"

/* The launcher validates the file before launch. The in-process runtime also
   validates live source spans before publishing any hook. No absolute process
   pointers survive a process lifetime or battle generation. */
typedef struct ntw2_config {
    uint32_t abi;
    uint32_t size;
    uint32_t enabled_mask;
    uint32_t workers;
    uint32_t image_base;
    uint32_t poll_ms;
    uint32_t main_thread_id; /* Former reserved[0]; required only with NTW2_PROFILE. */
    uint32_t profile_site;   /* 0: sampler gated on the whole tick; 1..NTW2_TIMED_SITES: gated on that timed site only */
    uint32_t collide_lod_m;  /* Low 31 bits: 0 selects 40 metres, otherwise 1..100000. High bit NTW2_COLLIDE_CENSUS opts into costly pair timers. */
    uint32_t loco_flags;     /* Appended (config grew 36 -> 40 bytes); own field, no other field is reinterpreted. NTW2_LOCO_* flags; nonzero requires NTW2_LOCO. */
    uint32_t brain_flags;    /* Appended at offset 40. NTW2_BRAIN_* flags; nonzero requires BRAIN2. */
    uint32_t collide_flags;  /* Appended at offset 44 (config 44 -> 48 bytes). NTW2_COLLIDE_CONTACT_* flags; nonzero requires COLLIDE; SHADOW and WORKERS are exclusive. */
    uint32_t puppet_units;   /* Appended at offset 48 (config 48 -> 52 bytes). NTW2_PUPPET unit count 1..NTW2_PUPPET_MAX_UNITS; nonzero exactly when NTW2_PUPPET is set. */
} ntw2_config;

enum ntw2_phase {
    NTW2_IDLE = 0,
    NTW2_VERIFYING = 1,
    NTW2_WAITING_BATTLE = 2,
    NTW2_ACTIVATING = 3,
    NTW2_ACTIVE = 4,
    NTW2_RESTORING = 5,
    NTW2_FAILED = 6,
    NTW2_STOPPED = 7
};

/* Diagnostic snapshot: read sequence, copy all words, read sequence again.
   Accept only equal even sequence values. Job counters are sampled module
   counters, not a transactional gameplay snapshot or a performance claim. */
#define NTW2_GRID_READERS 64u
#define NTW2_GRID_EDGES 512u
#define NTW2_GRID_SITES 113u
#define NTW2_GRID_UNKNOWN_SITE 112u
#define NTW2_GRID_PHASES 4u
#define NTW2_GRID_THREADS 3u
/* Counts wrap modulo 2^32. route_calls count invocations of retargeted private-clone call edges after the clone
   reaches the census gate; the gate then tail-jumps to the edge's ORIGINAL resolved destination (existing target
   binding semantics are never bypassed). route=NTW2_GRID_ROUTE_IMAGE means that destination is the original reader
   VA, so each such invocation is an exact native reader entry (entry_calls). BINDING/CLONE routes (host gates,
   LOCO services, solver replay, private clones) may defer, skip, replace or reshape the reader: those calls are
   counted only as route_calls and must not be read as native reader entries. Samples are EIP occupancy, never
   inferred calls. Phase indices use ntw2_profile_phase (inside/outside tick is carried by phase and tick_calls);
   thread classes: 0 actual tick owner while a routed tick runs, 1 configured main/render thread (not the owner),
   2 any other thread including workers. Site 112 is unknown; non-owner threads use the owner's innermost timed
   site at the call (dispatch site, observational). last_* fields are hints. Counters accumulate per start/stop. */
#define NTW2_GRID_ROUTE_IMAGE 0u   /* resolved destination == original reader VA: exact reader entry */
#define NTW2_GRID_ROUTE_BINDING 1u /* host/binding route: reader entry not proven */
#define NTW2_GRID_ROUTE_CLONE 2u   /* private clone route: reader entry not proven */
#define NTW2_GRID_ROUTE_OTHER 3u   /* image destination other than the reader VA */
typedef struct ntw2_grid_reader_status {
    uint32_t va, end, route_calls, route_tick_calls, entry_calls, entry_tick_calls, original_samples, clone_samples;
    uint32_t last_tick, last_site, last_thread, last_phase;
    uint32_t calls_phase[NTW2_GRID_PHASES], samples_phase[NTW2_GRID_PHASES];
    uint32_t calls_thread[NTW2_GRID_THREADS], samples_thread[NTW2_GRID_THREADS];
    uint32_t calls_site[NTW2_GRID_SITES], samples_site[NTW2_GRID_SITES];
} ntw2_grid_reader_status;
typedef struct ntw2_grid_edge_status {
    uint32_t reader, site, source_clone, route, route_calls, route_tick_calls, last_tick, last_thread;
} ntw2_grid_edge_status;
typedef struct ntw2_grid_census_status {
    uint32_t version, reader_count, edge_count, routed_ticks;
    uint32_t sample_attempts, sample_failures, unknown_samples, attribution_dropped;
    /* edge_dropped: readers/edges beyond the status capacity (generation fails first, so normally zero).
       unresolved_edges: generator-reported direct references to reader VAs it could NOT gate (internal calls or
       direct jumps); nonzero means exact route counts are incomplete, it is not an error. */
    uint32_t edge_dropped, unresolved_edges;
    ntw2_grid_reader_status readers[NTW2_GRID_READERS];
    ntw2_grid_edge_status edges[NTW2_GRID_EDGES];
} ntw2_grid_census_status;

typedef struct ntw2_status {
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
    uint32_t workers;
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
    /* NTW2_AI_ASYNC, modulo 2^32, reset at activation:
       0 native planner calls dispatched, 1 completed, 6 max_planner_us, 7 sum_planner_us,
       10 event-operation failures. Other indices retain their old ABI positions and are zero:
       no cross-tick stack parking, arbitrary-frame abort, quarantined partial think, or dropped update.
       Native faults propagate normally and are captured in crash_words, not suppressed. */
    uint32_t ai_words[16];
    /* Retained ABI row: word 11 counts planner admissions. All other indices are zero.
       Subordinate lifetime is protected by joining native frames, not pointer snapshots, scratch swaps,
       or the removed non-unwinding abort path. */
    uint32_t ai_extra_words[32];
    /* In-process crash capture (NTW2_AI_ASYNC runs): a first-chance vectored handler records every EXCEPTION_ACCESS_VIOLATION /
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
       F:\NTW2\translated_code\analysis\crashdumps\ntw2-<pid>-<n>.dmp. */
    uint32_t crash_words[32];
    /* NTW2_BRAIN (requires NTW2_PROFILE; all zero otherwise and until a tick ran; wraps modulo 2^32; reset at every activation).
       The 23 registry vtables' slot +0x0C (the per-entity brain step the loop 0x585D10 calls) is published as a timed entry site
       per family (trace sites 46..50, see NTW2_SITE_CALLEE_VAS), the class wrappers and the brain run as private clones whose every
       call is a timed site. Words: 0 routed ticks while armed, 1 sum of those tick durations us, 2..7 reserved,
       then, for family f in 0..4 and site s = trace site - 46 in 0..48, at 8 + 2*(f*49 + s): inclusive us and calls of that site
       while the family f was executing. Entry site s = f counts the entities of family f (calls) and their whole [vt+0x0C] time;
       sites 5..18 (trace 51..64) are the wrapper callees and belong to their family only (51..55 family 2, 56..58 family 3,
       59..64 family 4); sites 19..48 (trace 65..94) are the brain's own callees, attributed to the family whose entry encloses
       them. Inclusive means enter-to-return of each call, so rows overlap and every timed call adds its own timing overhead to
       the enclosing rows. Sites run only on the tick-owner thread inside a routed tick; elsewhere they pass through untimed. */
    uint32_t brain_words[NTW2_BRAIN_WORDS];
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
    /* NTW2_VISUAL: main-thread 0x779E60 loop 1, independently gated by enabled mask and owner/inflight acquisition,
       NOT by a tick-thread epoch. Counters wrap modulo 2^32 and reset at every ntw2_start; without work all are zero
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
    /* Worker-start allocator admission, reset at ntw2_start and retained after stop/failure.
       32 rows of 8 words: pool slots 0..30, AI worker 31. Each row:
       0 result (0 not attempted, 1 allocation+free succeeded, otherwise failing stage:
         2 TLS lookup, 3 allocation/lazy static initialization, 4 null allocation, 5 free; bit 8 = SEH fault),
       1 thread id, 2 pre-probe executable CRT TLS epoch, 3 post-probe CRT TLS epoch,
       4 exception code, 5 exception EIP (preferred VA inside image), 6 exception access address,
       7 executable CRT TLS index. Admission failure uses error NTW2_ERROR_ALLOCATOR and
       error_detail = (row << 16) | result; no game-code hook is activated on failed admission.
       The callback runs once per worker lifetime, not once per job: 0x444B40(16) initializes through
       the ordinary allocation path, then 0xFF7EF0 frees it. FF7F20's TLS is a static-init epoch, not
       an arena; the allocator is an explicit argument. This probe does not prove animation arena
       ownership or concurrency safety. Standalone numerical pools need no callback. */
    uint32_t allocator_words[NTW2_ALLOCATOR_WORDS];
    /* Append-only slice-location counts, reset on activation: 0 slice_at_site34 (successfully resumed jobs),
       1 slices_at_end (must remain zero; tick-end slicing was removed). No pending job means neither count advances. */
    uint32_t ai_slice_site_words[2];
    /* Brain-state census: NTW2_BRAIN, tick-owner only, cumulative modulo 2^32, reset on activation.
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
    uint32_t brain_state_words[NTW2_BRAIN_STATE_WORDS];
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
    uint32_t collision_words[NTW2_COLLISION_WORDS];
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
    uint32_t collide_words[NTW2_COLLIDE_WORDS];
    /* BRAIN2 v2 owner-serial counters, modulo 2^32, reset at activation.
       The 48-word row keeps its original offset and size; word 0 identifies v2.
       Layout: src/brain2/native_brain2.h. Service bookkeeping is opt-in and QPC
       is independently off by default. Native faults propagate: a partially
       executed occurrence is never retried. */
    uint32_t brain2_words[NTW2_BRAIN2_WORDS];
    /* COLLIDE_LOD: reset at activation, all zero until a stage. Counts wrap modulo 2^32.
       0 stages gated, 1 records seen, 2 records skipped, 3 latest units, 4 latest far units,
       5 rebuild stages forced full-rate, 6 D_far metres, 7 max proximity us, 8 sum proximity us,
       9 faults (SEH or unsafe capacity/geometry), 10 sticky disabled, 11 reuse far records seen,
       12 unknown records seen, 13 reuse stages, 14 all-far/multiple-army stages forced full-rate,
       15 latest different-side unit pairs (original +0x44 pointer comparison). No processed-byte writes on skips.
       Word 4 reports classification before the all-far sanity refusal, not permission to skip. */
    uint32_t collide_lod_words[NTW2_COLLIDE_LOD_WORDS];
    /* Opt-in NTW2_AI_CTRL jobs; modulo 2^32, reset at activation:
       0 dispatched, 1 completed, 4 sum_us, 5 max_us, 6 max slot occupancy (one),
       11 site-33 barriers, 15 current slot occupancy; other retained indices are zero.
       A controller joins before its following planner can read the rebuilt node arrays. */
    uint32_t ai_ctrl_words[16];
    /* Retained budget ABI row, now zero: there is no time-budget suspension policy. */
    uint32_t ai_slice_budget_words[NTW2_AI_SLICE_BUDGET_WORDS];
    /* Retained parking ABI row, now zero: no SuspendThread, EIP polling, or unsafe-park valve. */
    uint32_t ai_park_words[8];
    /* Opt-in NTW2_LOCO (timed site 13, ACTIVE clone's call of 0x531AF0); APPENDED after ai_park_words, every earlier offset is unchanged.
       Reset at every activation, wraps modulo 2^32, all zero without the feature; the retained values of the last generation stay readable after stop.
       Word order is src/loco/native_loco.h ntw2_loco::Word (labels NTW2_LOCO_WORD_LABELS): 0 layout version, 1 stage calls, 2 entity occurrences,
       3 admitted, 4 rejected, 5..14 first-rejection reasons (class, lifetime, activity, target, parked, pending, charge_fire, posture_order,
       node, environment); activity/target/charge_fire/posture_order/node are retained ABI buckets but always zero for serial MOVE.
       15..18 branch census (battle wrapper, alternate wrapper, direct, staging), 19..24 admitted/rejected/dispatch
       sum and max microseconds, 25 max entities in one stage, 26 active-byte filtered, 27 executed through the clone, 28 executed through the
       original, 29..31 owner service calls / max per entity / serviced entities, 32..39 per-service counts (unlink_grid, unlink_owner,
       insert_owner, insert_grid, sweep, resolve, height_owner, wrapper_query), 40 service trace overflow, 41 class-wrapper occurrences,
       42 emitted LOCO clone bytes, 43 generation, 44 clone execution enabled (NTW2_LOCO_CLONE), 45 latest Stage owner thread id (no permanent owner latch), 46 re-entry refusals,
       47 reserved. Native publication/services remain owner-only; optional closed movement workers use private state.
       No speculative native execution or retry. Off-epoch ticks run the original 0x531AF0 and do not touch these counters. */
    uint32_t loco_words[NTW2_LOCO_WORDS];
    /* Independent all-gates diagnostics for the same serial owner MOVE occurrences; appended without changing loco_words.
       Reset at start/activation, modulo 2^32; all zero when disabled, retained after stop. Order/labels: native_loco.h GateWord / NTW2_LOCO_GATE_LABELS.
       0 layout version, 1 entities (all active +0x30 occurrences), 2 recognized candidates, 3 serial admitted, 4 enforced reason mask
       (bit reason-1: Class=1, Lifetime=2, Parked=5, Pending=6, Environment=10 => 0x233).
       5..14 independent failures of the ten old diagnostics in first-rejection order, evaluated fully for recognized candidates.
       15..18 nonzero DWORDs +0x4E8/+0x390/+0x3BC/+0x3C8 (ChargeFire), 19 posture +0x220, 20 order, 21 slot row, 22 reference node,
       23..24 holders +0x2CC/+0x51C, 25..31 activities 0/1/9/0x1D/0x23/0x0C/other, 32..35 corroborating byte latches
       +0x618/+0x619/+0xF1/+0x5AB (not ChargeFire), 36 unclassified (no soldier-field reads), 37 diagnostic faults,
       38 legacy admitted (all ten diagnostics clear), 39 newly admitted (serial admitted with a removed diagnostic failing), 40..47 reserved.
       Failures/details overlap and are NOT summable to entities; entities is the all-gates denominator, candidates the detailed-field population.
       Activity/target/fire/posture/order/node/holder diagnostics do not exclude serial MOVE. This is not NODE or worker admission. */
    uint32_t loco_gate_words[NTW2_LOCO_GATE_WORDS];
    /* Inclusive owner-service QPC timings, appended without changing either 48-word LOCO row.
       Reset at start/activation, retained after stop; all zero without LOCO. Order/labels:
       native_loco.h ServiceWord / NTW2_LOCO_SERVICE_LABELS. 0 version (1 while LOCO active),
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
    uint32_t loco_service_words[NTW2_LOCO_SERVICE_WORDS];
    /* Retained grid geometry/oracle diagnostics. Stage C publishes owned grid v2 only at stage exit with GRID or GRID_VERIFY;
       ReadGrid/CaptureGrid remain public geometry-build oracle seams, not native-chain imports. New build/verification metrics are in loco_grid_v2_words.
       Reset at start/activation, retained after stop, zero without LOCO; without GRID only version=1 remains. GridWord / NTW2_LOCO_GRID_LABELS:
       0 version, 1 captures, 2 records, 3 primary, 4 secondary, 5 memberships, 6 cells, 7 mismatches,
       8 sampled records, 9 births, 10 removals, 11 reused addresses, 12 capture us, 13 CSR us, 14 faults,
       15 refusals, 16 generation, 17 epoch, 18 bytes, 19 max records, 20 max memberships,
       21 native-order cells, 22 unsupported nodes, 23 deactivations, 24 membership removals,
       25..31 reserved. Counters wrap modulo 2^32; inserted==0 records have no memberships. */
    uint32_t loco_grid_words[NTW2_LOCO_GRID_WORDS];
    /* Stage B private-state closed movement workers; ParallelWord / NTW2_LOCO_PARALLEL_LABELS.
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
       and original-only selectors. Sweep/resolve/environment remain owner-only unless NTW2_LOCO_OWNED_SERVICES; Stage C borrows the separately published grid. */
    uint32_t loco_parallel_words[NTW2_LOCO_PARALLEL_WORDS];
    /* Owner-thread shadow oracle, never authoritative gameplay results. Labels in native_sweep.h/native_resolve.h. */
    uint32_t sweep_words[NTW2_SWEEP_WORDS];
    uint32_t resolve_words[NTW2_RESOLVE_WORDS];
    uint32_t env_words[NTW2_ENV_WORDS];
    /* Three top-eight VA/count rows: owner+24, owner+1C virtual0, notification+8.
       48..50 distinct targets, 51..53 observed policy/predicted notification counts; 54..63 reserved. */
    uint32_t env_target_words[NTW2_ENV_TARGET_WORDS];
    uint32_t resolve_frame_words[NTW2_RESOLVE_FRAME_WORDS];
    /* Owned-service mover diagnostics appended after resolve_frame_words; OwnedWord / NTW2_LOCO_OWNED_LABELS in native_loco.h.
       Reset at start/activation, retained after stop, zero without LOCO. Counts/us wrap modulo 2^32. Requires NTW2_LOCO_OWNED_SERVICES (word 1 = enabled).
       Word 27 counts entity-range chunks claimed atomically by the pool (one dispatch per stage); word 28 counts duplicate refusals. */
    uint32_t loco_owned_words[NTW2_LOCO_OWNED_WORDS];
    /* Owned-service mover detail tail appended after loco_owned_words; native_loco.h OwnedDetailWordCount / SampleOwnedDetails / NTW2_LOCO_OWNED_DETAIL_LABELS.
       Reset at start/activation, retained after stop, zero without LOCO. Counts wrap modulo 2^32.
       0 version, 1 quiet_enabled (NTW2_LOCO_QUIET), 2 staging_initial_a3_zero, 3 staging_result_a3_zero, 4 staging_clamp_callback,
       5 actual_class_wrapper, 6 other_class, 7 actual_alternate_wrapper, 8 unit_blocked_class, 9 unit_blocked_staging, 10 unit_blocked_other,
       11 observed_f0, 12 worker_f0, 13 observed_initial_a3_zero, 14..15 reserved.
       Quiet disables loco_service_words work/timing (word 1 = 0), all-gates work counters (version 1 and enforced mask 0x233 retained) and shadow
       comparisons; basic fault/share counters (loco_owned_words) remain. */
    uint32_t loco_owned_detail_words[NTW2_LOCO_OWNED_DETAIL_WORDS];
    /* Owned phase timing appended after the detail row; native_loco.h OwnedPhaseWord / NTW2_LOCO_OWNED_PHASE_LABELS.
       Reset at start/activation, retained after stop; all zero without owned services. 0 version=1 when owned enabled,
       1 dispatches, 2 chunks, 3 list entities, 4 max chunk entities, 5..12 chunk-duration histogram (<=16/32/64/128/256/512/1024/>1024 us),
       13 index us, 14 scene identity-check us, 15 catalog prepare us (zero after activation), 16 per-stage worker FP-control prepare us, 17 dispatch wall us, 18 replay loop us,
       19 replay commit estimated us, 20 replay fallback estimated us (x16 estimates from every 16th occurrence), 21 replay samples,
       22 unprocessed, 23 validation refusals, 24 chunk time sum us, 25 computed, 26 worker refused, 27 participants used,
       28 last chunk size, 29 participant overflow, 30..31 reserved. Counts/us wrap modulo 2^32; phase timers remain under quiet. */
    uint32_t loco_owned_phase_words[NTW2_LOCO_OWNED_PHASE_WORDS];
    /* Owned activation/load diagnostics; native_loco.h OwnedLoadWord / NTW2_LOCO_OWNED_LOAD_LABELS.
       Append-only, reset at Start, retained after Stop; all zero without owned services. Counts/us wrap modulo 2^32.
       0 version, 1 activation calls, 2 activation us, 3 scene us, 4 catalog us, 5 participants us, 6 arena us,
       7 model changes, 8 capacity refusals, 9 chunk CPU us, 10 max chunk wall us, 11 CPU us for that chunk,
       12 activation failure reason (native_loco.h OwnedActivationFailure), 13 structured exception code or
       ERROR_NOT_ENOUGH_MEMORY for C++ bad_alloc, 14 mismatch/fault address, 15 mismatching actual word.
       All four are zero on successful activation. The failure reason is the failing phase, including when that phase throws.
       Scene/catalog capture runs at a quiescent tick boundary; arena/participant prefault and clone warmup remain on the monitor.
       All preparation is activation-only; Stage never grows it. */
    uint32_t loco_owned_load_words[NTW2_LOCO_OWNED_LOAD_WORDS];
    /* Owned grid v2 diagnostics; native_loco.h NTW2_LOCO_GRID_V2_LABELS. Appended without moving any prior row.
       Layout: 0 version (2 while LOCO is active), 1 enabled, 2 verify_enabled, 3 builds, 4 build_us, 5 max_build_us, 6 records, 7 memberships,
       8 verify_mismatches, 9 verify_us, 10 dispatches, 11 committed_records, 12 record_reads, 13 refusals, 14 faults, 15 epoch; counters wrap modulo 2^32.
       Reset at Start, retained after Stop; phase words above remain the movement measurement. */
    uint32_t loco_grid_v2_words[NTW2_LOCO_GRID_V2_WORDS];
    /* Collision source: 0 none, 1 native-audit, 2 owned; then native_stages, owned_stages, owned_refusals.
       Reset at Start, retained after Stop; no stage means all four words are zero. */
    uint32_t collide_source_words[NTW2_COLLIDE_SOURCE_WORDS];
    /* Activation-sized retained storage and process VA telemetry, reset on Start and retained on Stop.
       NTW2_MEMORY_WORD_LABELS / ntw2_memory_word specify indices. *_bytes count owned allocation
       payloads/VirtualAlloc reservations plus module image and explicit thread stack reservations;
       CRT heap rounding and unrelated game/driver allocation are not attributed to a module.
       ullAvailVirtual is measured by GlobalMemoryStatusEx (lo/hi pairs), not inferred from that sum.
       Activation and each large reservation require >=512MiB remaining VA; the post-allocation
       check precedes feature publication. min_avail is sampled at activation and once/second.
       Capacity growth refuses before writes, never reallocates in a tick.
       Version 2 appends indices 28..43 without moving any version-1 word.
       Version 3 appends native grid shift/inclusive clamp/dimension and catalog backing bytes/counts.
       Catalog's first five byte categories sum to loco_catalog_bytes; counts are unique retained geometry.
       cell_capacity is the address span ((clamp<<shift)+clamp+1), including any stride padding.
       Low periodic VA latches LOCO/COLLIDE native fallback until next Start; once the
       tick owner drains, their allocations are released without stopping other features.
       active_mask excludes these bits. Released bytes and the last allocated LOCO
       breakdown remain diagnostic; loco_bytes/collide_bytes become zero after release. */
    uint32_t memory_words[NTW2_MEMORY_WORDS];
    /* Same-tick completion telemetry; appended after memory v3, never shifts an earlier status word.
       0..2 planner count/sum us/max us; 3..5 barrier count/sum us/max us (includes opt-in controllers).
       6..14 planner duration histogram; 15..23 barrier-wait histogram. Each histogram is disjoint:
       <=8, (8,16], (16,32], (32,64], (64,128], (128,256], (256,512], (512,1024], >1024 ms.
       Counts/sums wrap modulo 2^32; reset at activation. max_planner_us excludes old between-tick parks.
       Polls are observational: the worker can update a row while status is being copied. */
    uint32_t ai_completion_words[NTW2_AI_COMPLETION_WORDS];
    ntw2_grid_census_status grid_census; /* Append-only; canonical profiler/trace ABI unchanged. */
    /* AI mutation census (NTW2_AI_CENSUS): zero without the feature. Version 1 layout, all words LE uint32:
       header[16]: version, targets(7), caller_capacity(256), callers_used, top_per_target(8), calls, callers_dropped, slots_owned,
       slot_count(12), ranges(3), sample_attempts, sample_outside, ticks, calls_in_tick, calls_outside_tick, reserved.
       target rows (7, stride 104): [original_va, slots, total, class0..3, dropped] then 8 caller rows (stride 12):
       [caller, kind, count, class0..3, top_site, top_site_count, outside_tick_count, second_site, second_site_count].
       Classes: 0 tick owner, 1 AI worker, 2 main/render, 3 other. Site codes: 0 outside tick, 1 in tick with no timed site, 2+i timed site i.
       Caller kind 0 = RVA in the main image, 1 = offset in the AI_CONTROLLER clone (source VA 0x7C8BD0 + offset), 2 = raw return address.
       range rows (3, stride 8): [va, end, samples, class0..3]. Rows are in the order of src/ntw2_ai_census.h. */
    uint32_t ai_census_words[NTW2_AI_CENSUS_WORDS];
    /* BRAIN2 v2 service rows: calls, active, unresolved, inactive,
       first-active occurrences, first-unresolved occurrences, QPC ticks low/high.
       Append-only; service IDs and inactive proofs: src/brain2/native_brain2.h. */
    uint32_t brain2_census_words[NTW2_BRAIN2_CENSUS_WORDS];
    /* Owner-only shadow rows. Never authorize worker execution or fake-node installation.
       Reset at activation, retained after stop; module headers declare word/event layouts. */
    uint32_t node_words[NTW2_NODE_WORDS];
    uint32_t node_event_words[NTW2_NODE_EVENT_WORDS];
    uint32_t fire_words[NTW2_FIRE_WORDS];
    /* Driver selection and reached generic node slots, independent of reference
       class admission. Layout: native_brain2.h RouteWord; configured vs actual
       driver distinguish activation intent from a reached dynamic call. */
    uint32_t brain2_route_words[NTW2_BRAIN2_ROUTE_WORDS];
    /* Commit refusal guard split and call-site witnesses; native_fire.h CommitWord.
       Separate tail preserves existing fire and route row offsets. */
    uint32_t fire_commit_words[NTW2_FIRE_COMMIT_WORDS];
    /* Concrete descriptor-move node (vtable 01348B44), distinct from reference
       node_words; the same node-shadow switch enables both owner-only ports. */
    uint32_t move_node_words[NTW2_MOVE_NODE_WORDS];
    uint32_t move_node_event_words[NTW2_MOVE_NODE_EVENT_WORDS];
    /* Version/distinct/overflow/reserved, top8 begin (VA,count), top8 step pairs. */
    uint32_t brain2_node_target_words[NTW2_BRAIN2_NODE_TARGET_WORDS];
    /* Per-class owner shadows: idle [133405C,1334028], action
       [1347270,1348D2C,1348CC4]. Existing target/status offsets are unchanged. */
    uint32_t idle_node_words[NTW2_IDLE_NODE_CLASSES][NTW2_NODE_WORDS];
    uint32_t idle_node_event_words[NTW2_IDLE_NODE_CLASSES][NTW2_NODE_EVENT_WORDS];
    uint32_t action_node_words[NTW2_ACTION_NODE_CLASSES][NTW2_NODE_WORDS];
    uint32_t action_node_event_words[NTW2_ACTION_NODE_CLASSES][NTW2_NODE_EVENT_WORDS];
    /* BRAIN2 census tail (native_brain2.h UnknownSiteSnapshot): Unknown-row unresolved
       (site, target, calls) top16, first-unresolved-gate-per-occurrence top16, then the
       site-6 dispatch witness words. Reset at activation, retained after stop. */
    uint32_t brain2_unknown_site_words[NTW2_BRAIN2_UNKNOWN_SITE_WORDS];
    /* BRAIN2 Stage 2 worker/commit telemetry (--brain-parallel); layout and labels in
       src/brain2/native_brain_workers.h (NTW2_BRAIN_WORKER_WORD_LABELS / ..._REASON_LABELS).
       Words 0..47 summary, 48..65 refusal reasons, 66..118 refusing services (brain2 Service order),
       119..123 speculated_unwalked / late_activations / region_queries / witness_dep_misses / witness_dep_overflow,
       124..127 rng_worker_draws / rng_owner_draws / rng_lcg_advance / rng_owner_unmatched (version 2; RNG streams)
       (NTW2_BRAIN_WORKER_TAIL_LABELS), 128..143 guard-miss attribution (version 3; NTW2_BRAIN_WORKER_GUARD_LABELS).
       Zero without the feature; reset at activation, retained after stop. */
    uint32_t brain_worker_words[NTW2_BRAIN_WORKER_WORDS];
    /* NTW2_AI_ASYNC2 (appended): live-graph async think telemetry; NTW2_AI_ASYNC2_LABELS order, layout src/ntw2_ai_async2.h.
       Counters wrap modulo 2^32; written concurrently by tick, worker and gated threads (interlocked), so a poll is a
       non-atomic snapshot. All zero without the feature; reset at activation, retained after stop. */
    uint32_t ai_async2_words[NTW2_AI_ASYNC2_WORDS];
    /* BRAIN2 Stage 2 phase row (appended; --brain-parallel, --brain-quiet): owner capture/commit/owner-run and worker
       capture/clone/publish microseconds, region-query counts, guard-miss writer relation and crew-dependency counts;
       NTW2_BRAIN_WORKER_PHASE_LABELS order, layout src/brain2/native_brain_workers.h (PhaseWord). Zero without the
       feature; reset at activation, retained after stop. */
    uint32_t brain_worker_phase_words[NTW2_BRAIN_WORKER_PHASE_WORDS];
    /* BRAIN2 per-unit brain Stage A (appended; --brain-unit-shadow): UnitDecision agreement per decided field, exception
       census and soldier vtable census; NTW2_BRAIN_UNIT_* labels and layout in src/brain2/native_unit_brain.h (Word).
       Shadow only: nothing here changes a native write. Zero without the feature; reset at activation, retained after stop. */
    uint32_t brain_unit_words[NTW2_BRAIN_UNIT_WORDS];
    /* COLLIDE contact responses (appended; --collide-contact-shadow / --collide-contact-workers): plan census,
       shadow agreement per predicted effect, replay counters, timers and avoidance-manager diagnostics;
       NTW2_COLLIDE_CONTACT_WORD_LABELS order, layout src/collision/native_contact.h (Word). Zero without the
       flags; reset at activation, retained after stop. */
    uint32_t collide_contact_words[NTW2_COLLIDE_CONTACT_WORDS];
    /* LOCO grid probation (appended; --grid-probation, NTW2_LOCO_GRID_PROBATION): native soft-grid cell-head
       reader detector. 32 header words (layout ntw2_grid_probation::Word in src/loco/native_grid_probation.h,
       labels NTW2_GRID_PROBATION_LABELS) then 256 caller rows of 8 words (ntw2_grid_probation::RowWord): image
       rows report preferred-base VAs, clone rows report the original instruction VA with the clone id in Where.
       Zero without the flag; reset at activation, retained after stop. */
    uint32_t grid_probation_words[NTW2_GRID_PROBATION_WORDS];
    /* NTW2_AI_ASYNC2 route/boundary row (appended): NTW2_AI_ASYNC2_ROUTE_LABELS order, layout src/ntw2_ai_async2.h
       (RouteWord). Written by the tick owner, the AI worker (private-clone entry counters, single writer) and gated
       threads; a poll is a non-atomic snapshot. All zero without the feature; reset at activation, retained after stop. */
    uint32_t ai_async2_route_words[NTW2_AI_ASYNC2_ROUTE_WORDS];
    /* NTW2_ARMY_UNIT_SHADOW (appended last): item 4 Stage A per-unit army update instrumentation; layout and labels in
       src/army/native_army_unit.h (Word, NTW2_ARMY_UNIT_*_LABELS). Tick-owner writer; a poll is a non-atomic snapshot.
       Nothing here changes a native write. All zero without the feature; reset at activation, retained after stop. */
    uint32_t army_unit_words[NTW2_ARMY_UNIT_WORDS];
    /* NTW2_PUPPET (appended after army_unit_words): puppet probe stage 1 membership/admission counters; layout and labels
       in src/puppet/native_puppet.h (Word, NTW2_PUPPET_WORD_LABELS). Tick-owner writer; a poll is a non-atomic snapshot.
       All zero without the feature; reset at activation, retained after stop. */
    uint32_t puppet_words[NTW2_PUPPET_WORDS];
    /* NTW2_ARMY_UNIT_SHADOW, Stage B0 (appended after puppet_words): qualification observers for an item 4 Stage B (FSM
       steps/transitions through the ARMY_UNIT clone's 58202E gate, formation queue/scratch, recorder pins, RNG member
       bound, own-state bytes, exclusive refusal cost). Layout and labels in src/army/native_army_unit.h (B0Word,
       NTW2_ARMY_B0_LABELS). Tick-owner writer; reads only, no native write. Reset at activation, retained after stop. */
    uint32_t army_b0_words[NTW2_ARMY_B0_WORDS];
    /* NTW2_PUPPET motion/divert diagnostics (appended after army_b0_words): +628 divert timing, parked members' movement
       intent, actual motion, admission displacement and delivered-slot distance per seam. Layout and labels in
       src/puppet/native_puppet.h (MotionWord, NTW2_PUPPET_MOTION_LABELS). Tick-owner writer, reads only. */
    uint32_t puppet_motion_words[NTW2_PUPPET_MOTION_WORDS];
    /* NTW2_PUPPET +628 divert ownership (appended after puppet_motion_words): divert events by kind/controller table,
       last target, native controller-branch steps, release outcomes (resumed/reparked/handed back). Layout and labels in
       src/puppet/native_puppet.h (DivertWord, NTW2_PUPPET_DIVERT_LABELS). Tick-owner writer. */
    uint32_t puppet_divert_words[NTW2_PUPPET_DIVERT_WORDS];
    /* NTW2_PUPPET stage 2 machinery (appended after puppet_divert_words): site-13 determinism hash chain with fixed
       checkpoints, parked/diverted members hashed, parked men holding a delivered unbegun slot (slot_waiting) and the
       hash cost. Layout and labels in src/puppet/native_puppet.h (MoverWord, NTW2_PUPPET_MOVER_LABELS). Tick-owner writer. */
    uint32_t puppet_mover_words[NTW2_PUPPET_MOVER_WORDS];
    /* NTW2_PUPPET selection diagnostics (appended after puppet_mover_words): unit rejection reasons, member refusals,
       pinned infantry tables, top rejected majority class tables. Layout and labels in src/puppet/native_puppet.h
       (SelectWord, NTW2_PUPPET_SELECT_LABELS). Tick-owner writer. */
    uint32_t puppet_select_words[NTW2_PUPPET_SELECT_WORDS];
} ntw2_status;

/* DATA export "ntw2_profile", separate from the sequence-locked lifecycle status.
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
#define NTW2_PROFILE_ABI 8u /* 8: versioned runtime-DLL RVA bucket tables appended after the seven histogram arrays */
#define NTW2_PROFILE_BUCKET_BYTES 64u
#define NTW2_PROFILE_THREADS 48u
#define NTW2_PROFILE_WAIT_HANDLES 8u
#define NTW2_PROFILE_CHAINS 64u
#define NTW2_PROFILE_CHAIN_DEPTH 16u
#define NTW2_PROFILE_MAIN_PHASES 4u
/* Preserve the ABI 5/6 array offsets; slot 0 now means A1, not aggregate A.
   A2 is appended separately. Histogram storage order is A1, B, C, A2. */
#define NTW2_PROFILE_INLINE_PHASES 3u
enum ntw2_profile_phase {
    NTW2_PROFILE_PHASE_A1, NTW2_PROFILE_PHASE_B, NTW2_PROFILE_PHASE_C, NTW2_PROFILE_PHASE_A2
};
#define NTW2_PROFILE_START_TICK_MS 25u
#define NTW2_PROFILE_POST_TICK_MS 40u
enum ntw2_profile_module {
    NTW2_PROFILE_MODULE_IMAGE, NTW2_PROFILE_MODULE_NTW2, NTW2_PROFILE_MODULE_D3D9,
    NTW2_PROFILE_MODULE_DRIVER, NTW2_PROFILE_MODULE_NTDLL, NTW2_PROFILE_MODULE_KERNEL32,
    NTW2_PROFILE_MODULE_TBB, NTW2_PROFILE_MODULE_MSVCR, NTW2_PROFILE_MODULE_OTHER,
    NTW2_PROFILE_MODULE_COUNT
};
typedef struct ntw2_profile_phase_status {
    uint32_t hist_va, samples, wait;
    uint32_t wait_kind[8];
    uint32_t wait_handle[NTW2_PROFILE_WAIT_HANDLES];
    uint32_t wait_count[NTW2_PROFILE_WAIT_HANDLES];
    uint32_t wait_handle_kind[NTW2_PROFILE_WAIT_HANDLES];
    uint32_t wait_read_failed, wait_overflow;
    uint32_t modules[NTW2_PROFILE_MODULE_COUNT];
} ntw2_profile_phase_status;
typedef struct ntw2_profile_status {
    uint32_t abi, size, bucket_bytes, bucket_count;
    uint32_t samples, failed, hist_va, tick_hist_va;
    uint32_t overflow[8];
    uint32_t tick_thread_id, tick_samples, rounds, enumeration_failed;
    uint32_t thread_limit, wait_read_failed, wait_overflow, thread_replaced;
    uint32_t thread_id[NTW2_PROFILE_THREADS];
    uint32_t thread_samples[NTW2_PROFILE_THREADS];
    uint32_t in_image[NTW2_PROFILE_THREADS];
    uint32_t in_wait[NTW2_PROFILE_THREADS];
    uint32_t in_tbb[NTW2_PROFILE_THREADS];
    uint32_t wait_handle[NTW2_PROFILE_WAIT_HANDLES];
    uint32_t wait_count[NTW2_PROFILE_WAIT_HANDLES];
    /* Tick-executing thread samples per ntdll wait stub: NtWaitForSingleObject, NtWaitForMultipleObjects,
       NtDelayExecution, NtWaitForAlertByThreadId, NtReleaseKeyedEvent, NtWaitForKeyedEvent, [6..7] reserved. */
    uint32_t tick_wait_kind[8];
    uint32_t frames_hist_va;
    uint32_t chain_count[NTW2_PROFILE_CHAINS];
    uint32_t chain_len[NTW2_PROFILE_CHAINS];
    uint32_t chains[NTW2_PROFILE_CHAINS][NTW2_PROFILE_CHAIN_DEPTH];
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
    uint32_t main_hist_va[NTW2_PROFILE_INLINE_PHASES];
    uint32_t main_samples[NTW2_PROFILE_INLINE_PHASES];
    uint32_t main_wait[NTW2_PROFILE_INLINE_PHASES];
    uint32_t main_wait_kind[NTW2_PROFILE_INLINE_PHASES][8];
    uint32_t main_wait_handle[NTW2_PROFILE_INLINE_PHASES][NTW2_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_count[NTW2_PROFILE_INLINE_PHASES][NTW2_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_handle_kind[NTW2_PROFILE_INLINE_PHASES][NTW2_PROFILE_WAIT_HANDLES];
    uint32_t main_wait_read_failed[NTW2_PROFILE_INLINE_PHASES];
    uint32_t main_wait_overflow[NTW2_PROFILE_INLINE_PHASES];
    uint32_t main_post_chain_count[NTW2_PROFILE_CHAINS];
    uint32_t main_post_chain_len[NTW2_PROFILE_CHAINS];
    uint32_t main_post_chains[NTW2_PROFILE_CHAINS][NTW2_PROFILE_CHAIN_DEPTH];
    uint32_t main_post_chain_uncaptured;
    /* ABI 6: exclusive EIP module categories; each phase row sums to main_samples.
       NTW2 includes private clones. Driver names begin nv/atiu/ig; CRT begins msvcr.
       Other includes unlisted modules (including KernelBase), JIT/private code and
       uncatalogued addresses. Module ranges refresh about every 2 s, outside any
       thread suspension; unload/reload races are observational. At most 256 named
       category ranges are retained. Failures/omissions are explicit below. */
    uint32_t main_modules[NTW2_PROFILE_INLINE_PHASES][NTW2_PROFILE_MODULE_COUNT];
    uint32_t module_refresh_failed, module_omitted;
    /* ABI 7: the A1 start window, appended A2 counters, and independent A1 chains. */
    uint32_t main_start_tick_ms;
    ntw2_profile_phase_status main_rest;
    uint32_t main_start_chain_count[NTW2_PROFILE_CHAINS];
    uint32_t main_start_chain_len[NTW2_PROFILE_CHAINS];
    uint32_t main_start_chains[NTW2_PROFILE_CHAINS][NTW2_PROFILE_CHAIN_DEPTH];
    uint32_t main_start_chain_uncaptured;
} ntw2_profile_status;
/* Access one scalar or array field across the append-only phase layout.
   phase must be a valid enum ntw2_profile_phase with no expression side effects.
   C++ preserves volatile/lvalue access for the sampler; C readers use the same mapping. */
#define NTW2_PROFILE_PHASE_FIELD(p, phase, field) \
    ((phase) < NTW2_PROFILE_INLINE_PHASES ? (p)->main_##field[(phase)] : (p)->main_rest.field)

/* DATA export "ntw2_trace": per-tick trace ring written by the tick gate (needs a simulation feature or profile so the
   tick is routed through the private clone; the three sub-phase gates then time the manager 0x580640, the ballistics
   manager 0x6F6BC0 and the path scheduler 0x81A2C0 calls). Entries are written in order; `head` is the index of the
   next entry to write (wraps at NTW2_TRACE_ENTRIES); `written` counts all ticks traced. Readers copy the ring and
   use `written` to order it. Durations are microseconds; appended start/end fields
   are raw QPC ticks, sharing PresentMon --qpc_time's clock. qpc_freq_lo/hi is ticks/s.
   End includes final hold cleanup; duration_us measures the tick body INCLUDING the site-34 AI slice.
   `remainder` = duration - manager - ballistics - path.
   The launcher receipt's tick_trace.ticks exports all retained entries chronologically.
   Align present QPC against [qpc_start,qpc_end] or subtract qpc_end and divide by
   qpc_frequency for seconds since tick exit. Live ring copies remain observational. */
#define NTW2_TRACE_ABI 8u
#define NTW2_TRACE_ENTRIES 1024u
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
   Brain profiling sites (NTW2_BRAIN, PROFILE epochs; sums are per site over all families, see ntw2_status::brain_words for
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
   Sites 46..94 time only on the tick-owner thread inside a routed tick with NTW2_BRAIN armed and nest inside site 6.
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
/* ABI 8: 944-byte entry (112 sites + raw gate QPC pair); all site offsets/indices preserved. */
#define NTW2_TRACE_SITES 112u
#define NTW2_TIMED_SITES 110u
#define NTW2_SITE_CALLEE_VAS { \
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
typedef struct ntw2_trace_entry {
    uint32_t tick;        /* model tick counter at entry ([model+0x58]) */
    uint32_t duration_us; /* tick body including any site-34 AI slice, excluding final tick-exit hold cleanup */
    uint32_t interval_us; /* start-to-start gap from the previous traced tick (0 for the first) */
    uint32_t manager_us;  /* time inside the army manager call (formation gate) */
    uint32_t ballistics_us;
    uint32_t path_us;
    uint32_t thread_id;
    uint32_t flags;       /* bit0: private tick clone, bit1: sub-phase gates, bit2: inclusive site timings */
    uint32_t site_us[NTW2_TRACE_SITES];
    uint32_t site_calls[NTW2_TRACE_SITES];
    uint32_t qpc_start_lo, qpc_start_hi; /* raw gate-entry QPC */
    uint32_t qpc_end_lo, qpc_end_hi;     /* raw gate-exit QPC, including AI slice/hold */
} ntw2_trace_entry;
typedef struct ntw2_trace_ring {
    uint32_t abi, size, entries, head, written, qpc_freq_lo, qpc_freq_hi, reserved;
    ntw2_trace_entry ring[NTW2_TRACE_ENTRIES];
} ntw2_trace_ring;

/* Undecorated DLL export names. Both functions use the x86 WINAPI thread-entry
   convention. Start copies config, starts one monitor, and returns promptly.
   Stop disables/restores owned hooks and joins the monitor. Private code stays
   resident; arenas are reclaimed or reused only after their owners quiesce. */
typedef uint32_t (__stdcall *ntw2_start_fn)(void *config);
typedef uint32_t (__stdcall *ntw2_stop_fn)(void *unused);
/* Diagnostic export (oracles): the callee currently bound behind timed site `site` of the private clones, 0 beyond NTW2_TIMED_SITES.
   Site 6 is BrainKernelGate while a BRAIN2 generation is active, original 0x585D10 otherwise.
   Site 5 is the host stage gate in PROFILE/COLLIDE/COLLIDE_LOD generations, original 0x57DC30 outside those generations.
   Site 33 is the controller job gate only in AI_CTRL generations (requires AI_ASYNC), the AI_ASYNC2 join thunk (joins an in-flight
   think, then the original controller) in AI_ASYNC2 generations, original 0x7C8BD0 otherwise. Site 34 is the AI_ASYNC2 dispatch gate in
   AI_ASYNC2 generations, the same-call AI gate in other AI_ASYNC generations.
   Site 13 is the host movement gate (ntw2_loco::Stage inside a LOCO tick epoch, original 0x531AF0 otherwise) exactly while a generation with NTW2_LOCO is active, the original 0x531AF0 otherwise.
   The stage gate additionally checks the current thread's feature epoch before routing a clone or applying LOD. */
typedef uint32_t (__stdcall *ntw2_site_callee_fn)(uint32_t site);
/* Owner-boundary diagnostic export for the mapped-image lifecycle oracle, which has no engine task scheduler.
   The caller must own a quiescent model. Executes one pending activation capture for that exact bound model, returning 1;
   returns 0 when no matching capture is pending. This is the same seam TickGate invokes before any native tick work. */
typedef uint32_t (__stdcall *ntw2_activation_boundary_fn)(void *model);
/* Mapped-image lifecycle diagnostic: caller owns the bound model. Dispatches the original planner VA
   with the supplied this/flag under tick ownership and joins through the production barrier before returning.
   Returns 1 when admitted, 0 outside an active matching AI world or when another owner holds the tick. */
typedef uint32_t (__stdcall *ntw2_ai_boundary_fn)(void *model, void *planner, uint32_t flag);
/* Mapped-image lifecycle diagnostic for NTW2_AI_ASYNC2, one synthetic tick under tick ownership of the bound model: the
   production tick-start seam (non-blocking), site-34 admission of `planner` (queued; skipped when null), `mid(context)`
   on the tick thread while earlier batches may still run, a second admission when options bit 0 is set, the production
   TICK quadtree join (blocking; skipped when options bit 1 is set) and the tick-end publish. Returns 1 when the planner
   was admitted (or, with a null planner, when the tick ran), 0 otherwise. */
typedef uint32_t (__stdcall *ntw2_ai_async2_boundary_fn)(void *model, void *planner, uint32_t flag,
                                                        void (__stdcall *mid)(void *context), void *context, uint32_t options);
/* Lifecycle diagnostic export "ntw2_ai_async2_private_entry": the entry of an AI2 private clone (ntw2_clone_id
   NTW2_CLONE_AI2_*) as the routed slots hand it out. Nonzero only on the AI worker inside a think of an AI_ASYNC2
   generation, after the same lazy worker-side construction of the private search objects. */
typedef uint32_t (__stdcall *ntw2_ai_async2_private_entry_fn)(uint32_t clone);

#ifdef __cplusplus
}
static_assert(sizeof(ntw2_config) == 52 && offsetof(ntw2_config, loco_flags) == 36 &&
              offsetof(ntw2_config, brain_flags) == 40 && offsetof(ntw2_config, collide_flags) == 44 &&
              offsetof(ntw2_config, puppet_units) == 48, "configuration ABI is append-only");
static_assert(offsetof(ntw2_status,grid_census) == 4 * (29 + 16 + 16 + 24 + 8 + 192 + 16 + 16 + 64 + 16 + 16 + 32 + 32 + NTW2_BRAIN_WORDS + 32 + 80 + 8 + 8 + 32 + NTW2_ALLOCATOR_WORDS + 2 + NTW2_BRAIN_STATE_WORDS + NTW2_COLLISION_WORDS + NTW2_COLLIDE_WORDS + NTW2_BRAIN2_WORDS + NTW2_COLLIDE_LOD_WORDS + 16 + NTW2_AI_SLICE_BUDGET_WORDS + 8 + NTW2_LOCO_WORDS + NTW2_LOCO_GATE_WORDS + NTW2_LOCO_SERVICE_WORDS + NTW2_LOCO_GRID_WORDS + NTW2_LOCO_PARALLEL_WORDS + NTW2_SWEEP_WORDS + NTW2_RESOLVE_WORDS + NTW2_ENV_WORDS + NTW2_ENV_TARGET_WORDS + NTW2_RESOLVE_FRAME_WORDS + NTW2_LOCO_OWNED_WORDS + NTW2_LOCO_OWNED_DETAIL_WORDS + NTW2_LOCO_OWNED_PHASE_WORDS + NTW2_LOCO_OWNED_LOAD_WORDS + NTW2_LOCO_GRID_V2_WORDS + NTW2_COLLIDE_SOURCE_WORDS + NTW2_MEMORY_WORDS + NTW2_AI_COMPLETION_WORDS), "status ABI prefix");
static_assert(offsetof(ntw2_status,ai_slice_budget_words) == offsetof(ntw2_status,ai_ctrl_words) + 16 * sizeof(uint32_t) &&
              NTW2_AI_SLICE_BUDGET_WORDS == 8u, "slice budget telemetry preserves its shipped offset");
static_assert(offsetof(ntw2_status,ai_park_words) == offsetof(ntw2_status,ai_slice_budget_words) + NTW2_AI_SLICE_BUDGET_WORDS * sizeof(uint32_t) &&
              offsetof(ntw2_status,ai_park_words) + 8 * sizeof(uint32_t) == offsetof(ntw2_status,loco_words), "parking histogram keeps its shipped offset");
static_assert(offsetof(ntw2_status,loco_words) == offsetof(ntw2_status,ai_park_words) + 8 * sizeof(uint32_t) &&
              offsetof(ntw2_status,loco_words) + NTW2_LOCO_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_gate_words) &&
              NTW2_LOCO_WORDS == 48u, "loco telemetry preserves its shipped layout");
static_assert(offsetof(ntw2_status,loco_gate_words) + NTW2_LOCO_GATE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_service_words) &&
              NTW2_LOCO_GATE_WORDS == 48u, "loco all-gates telemetry preserves its shipped layout");
static_assert(offsetof(ntw2_status,loco_service_words) + NTW2_LOCO_SERVICE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_grid_words) &&
              NTW2_LOCO_SERVICE_WORDS == 40u, "loco service telemetry preserves its shipped layout");
static_assert(offsetof(ntw2_status,loco_grid_words) + NTW2_LOCO_GRID_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_parallel_words) &&
              NTW2_LOCO_GRID_WORDS == 32u, "loco grid telemetry is append-only");
static_assert(offsetof(ntw2_status,loco_parallel_words) + NTW2_LOCO_PARALLEL_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,sweep_words) &&
              NTW2_LOCO_PARALLEL_WORDS == 32u, "loco parallel telemetry is append-only");
static_assert(offsetof(ntw2_status,sweep_words) + NTW2_SWEEP_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,resolve_words) &&
              NTW2_SWEEP_WORDS == 32u, "sweep telemetry is append-only");
static_assert(offsetof(ntw2_status,resolve_words) + NTW2_RESOLVE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,env_words) &&
              NTW2_RESOLVE_WORDS == 32u, "resolve telemetry is append-only");
static_assert(offsetof(ntw2_status,env_words) + NTW2_ENV_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,env_target_words) &&
              NTW2_ENV_WORDS == 32u, "environment telemetry is append-only");
static_assert(offsetof(ntw2_status,env_target_words) + NTW2_ENV_TARGET_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,resolve_frame_words) &&
              NTW2_ENV_TARGET_WORDS == 64u, "environment targets are append-only");
static_assert(offsetof(ntw2_status,resolve_frame_words) + NTW2_RESOLVE_FRAME_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_owned_words) &&
              NTW2_RESOLVE_FRAME_WORDS == 4u, "resolve frames keep their shipped offset");
static_assert(offsetof(ntw2_status,loco_owned_words) + NTW2_LOCO_OWNED_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_owned_detail_words) &&
              NTW2_LOCO_OWNED_WORDS == 32u && NTW2_LOCO_OWNED_SERVICES == 0x8u, "owned-service telemetry is append-only");
static_assert(offsetof(ntw2_status,loco_owned_detail_words) + NTW2_LOCO_OWNED_DETAIL_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_owned_phase_words) &&
              NTW2_LOCO_OWNED_DETAIL_WORDS == 16u && NTW2_LOCO_QUIET == 0x10u, "owned detail telemetry preserves its shipped layout");
static_assert(offsetof(ntw2_status,loco_owned_phase_words) + NTW2_LOCO_OWNED_PHASE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_owned_load_words) &&
              offsetof(ntw2_status,loco_owned_load_words) + NTW2_LOCO_OWNED_LOAD_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,loco_grid_v2_words) &&
              NTW2_LOCO_OWNED_PHASE_WORDS == 32u && NTW2_LOCO_OWNED_LOAD_WORDS == 16u && NTW2_LOCO_GRID == 0x20u && NTW2_LOCO_GRID_VERIFY == 0x40u && NTW2_LOCO_GRID_PROBATION == 0x80u && NTW2_LOCO_FLAGS_VALID == 0xffu, "owned phase and load telemetry retain their offsets; grid verification uses flag bit 0x40 and probation bit 0x80");
static_assert(offsetof(ntw2_status,loco_grid_v2_words) + NTW2_LOCO_GRID_V2_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,collide_source_words) &&
              offsetof(ntw2_status,collide_source_words) + NTW2_COLLIDE_SOURCE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,memory_words) &&
              NTW2_LOCO_GRID_V2_WORDS == 16u && NTW2_COLLIDE_SOURCE_WORDS == 4u, "Stage C rows retain their shipped offsets");
static_assert(offsetof(ntw2_status,memory_words) + NTW2_MEMORY_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,ai_completion_words) &&
              NTW2_MEM_FLOOR_BYTES == 27u && NTW2_MEM_RELEASED_COLLIDE_BYTES == 43u &&
              NTW2_MEM_LOCO_CATALOG_POLYGON_POINTS + 1 == NTW2_MEMORY_WORDS,
              "memory diagnostics preserve earlier indices before the AI completion tail");
static_assert(offsetof(ntw2_status,ai_completion_words) + NTW2_AI_COMPLETION_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,grid_census) &&
              offsetof(ntw2_status,grid_census) + sizeof(ntw2_grid_census_status) == offsetof(ntw2_status,ai_census_words) &&
              offsetof(ntw2_status,ai_census_words) + NTW2_AI_CENSUS_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain2_census_words) &&
              NTW2_AI_CENSUS == 0x10000u && (NTW2_VALID_MASK & NTW2_AI_CENSUS) == NTW2_AI_CENSUS && !(NTW2_ALL & NTW2_AI_CENSUS) &&
              NTW2_AI_CENSUS_WORDS == 16u + 7u * (8u + 8u * 12u) + 3u * 8u,
              "ai census preserves its position after grid census; its bit stays outside NTW2_ALL");
static_assert(offsetof(ntw2_status,brain2_census_words) + NTW2_BRAIN2_CENSUS_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,node_words) &&
              NTW2_BRAIN2_CENSUS_WORDS == 53u * 8u && NTW2_BRAIN2_VERSION == 2u,
              "brain2 v2 census is append-only after AI census");
static_assert(offsetof(ntw2_status,node_words) + NTW2_NODE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,node_event_words) &&
              offsetof(ntw2_status,node_event_words) + NTW2_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,fire_words) &&
              offsetof(ntw2_status,fire_words) + NTW2_FIRE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain2_route_words) &&
              offsetof(ntw2_status,brain2_route_words) + NTW2_BRAIN2_ROUTE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,fire_commit_words) &&
              offsetof(ntw2_status,fire_commit_words) + NTW2_FIRE_COMMIT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,move_node_words) &&
              offsetof(ntw2_status,move_node_words) + NTW2_MOVE_NODE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,move_node_event_words) &&
              offsetof(ntw2_status,move_node_event_words) + NTW2_MOVE_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain2_node_target_words) &&
              offsetof(ntw2_status,brain2_node_target_words) + NTW2_BRAIN2_NODE_TARGET_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,idle_node_words) &&
              offsetof(ntw2_status,idle_node_words) + NTW2_IDLE_NODE_CLASSES * NTW2_NODE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,idle_node_event_words) &&
              offsetof(ntw2_status,idle_node_event_words) + NTW2_IDLE_NODE_CLASSES * NTW2_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,action_node_words) &&
              offsetof(ntw2_status,action_node_words) + NTW2_ACTION_NODE_CLASSES * NTW2_NODE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,action_node_event_words) &&
              offsetof(ntw2_status,action_node_event_words) + NTW2_ACTION_NODE_CLASSES * NTW2_NODE_EVENT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain2_unknown_site_words) &&
              offsetof(ntw2_status,brain2_unknown_site_words) + NTW2_BRAIN2_UNKNOWN_SITE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain_worker_words) &&
              offsetof(ntw2_status,brain_worker_words) + NTW2_BRAIN_WORKER_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,ai_async2_words) &&
              offsetof(ntw2_status,ai_async2_words) + NTW2_AI_ASYNC2_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain_worker_phase_words) &&
              offsetof(ntw2_status,brain_worker_phase_words) + NTW2_BRAIN_WORKER_PHASE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,brain_unit_words) &&
              offsetof(ntw2_status,brain_unit_words) + NTW2_BRAIN_UNIT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,collide_contact_words) &&
              NTW2_AI_ASYNC2 == 0x20000u && (NTW2_VALID_MASK & NTW2_AI_ASYNC2) && !(NTW2_ALL & NTW2_AI_ASYNC2) &&
              NTW2_BRAIN_PARALLEL == 0x10u && NTW2_BRAIN_FINALIZER_SHADOW == 0x20u && NTW2_BRAIN_QUIET == 0x40u &&
              NTW2_BRAIN_UNIT_SHADOW == 0x80u && NTW2_BRAIN_FLAGS_VALID == 0xffu && NTW2_BRAIN_UNIT_WORDS == 176u,
              "class shadow and target rows append after the existing fire commit ABI");
static_assert(offsetof(ntw2_status,collide_contact_words) + NTW2_COLLIDE_CONTACT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,grid_probation_words) &&
              NTW2_COLLIDE_CONTACT_WORDS == 48u && NTW2_COLLIDE_CONTACT_SHADOW == 0x1u && NTW2_COLLIDE_CONTACT_WORKERS == 0x2u &&
              NTW2_COLLIDE_FLAGS_VALID == 0x3u, "collision contact row appends after brain_unit_words");
static_assert(offsetof(ntw2_status,grid_probation_words) + NTW2_GRID_PROBATION_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,ai_async2_route_words) &&
              NTW2_GRID_PROBATION_WORDS == 32u + 256u * 8u, "grid probation row appends after collide_contact_words");
static_assert(offsetof(ntw2_status,ai_async2_route_words) + NTW2_AI_ASYNC2_ROUTE_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,army_unit_words) &&
              NTW2_AI_ASYNC2_ROUTE_WORDS == 65u, "ai_async2 route row appends after grid_probation_words");
static_assert(offsetof(ntw2_status,army_unit_words) + NTW2_ARMY_UNIT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,puppet_words) &&
              NTW2_ARMY_UNIT_WORDS == 192u && NTW2_ARMY_UNIT_SHADOW == 0x40000u &&
              (NTW2_VALID_MASK & NTW2_ARMY_UNIT_SHADOW) && !(NTW2_ALL & NTW2_ARMY_UNIT_SHADOW),
              "army unit row appends after ai_async2_route_words; its bit is valid and outside NTW2_ALL");
static_assert(offsetof(ntw2_status,puppet_words) + NTW2_PUPPET_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,army_b0_words) &&
              NTW2_PUPPET_WORDS == 64u && NTW2_PUPPET == 0x80000u && NTW2_PUPPET_ROW_UNITS == 4u &&
              (NTW2_VALID_MASK & NTW2_PUPPET) && !(NTW2_ALL & NTW2_PUPPET),
              "puppet row appends after army_unit_words; its bit is valid and outside NTW2_ALL");
static_assert(offsetof(ntw2_status,army_b0_words) + NTW2_ARMY_B0_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,puppet_motion_words) &&
              NTW2_ARMY_B0_WORDS == 160u, "army B0 row appends after puppet_words");
static_assert(offsetof(ntw2_status,puppet_motion_words) + NTW2_PUPPET_MOTION_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,puppet_divert_words) &&
              NTW2_PUPPET_MOTION_WORDS == 32u, "puppet motion row appends after army_b0_words");
static_assert(offsetof(ntw2_status,puppet_divert_words) + NTW2_PUPPET_DIVERT_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,puppet_mover_words) &&
              NTW2_PUPPET_DIVERT_WORDS == 32u, "puppet divert row appends after puppet_motion_words");
static_assert(offsetof(ntw2_status,puppet_mover_words) + NTW2_PUPPET_MOVER_WORDS * sizeof(uint32_t) == offsetof(ntw2_status,puppet_select_words) &&
              NTW2_PUPPET_MOVER_WORDS == 32u, "puppet mover row appends after puppet_divert_words");
static_assert(offsetof(ntw2_status,puppet_select_words) + NTW2_PUPPET_SELECT_WORDS * sizeof(uint32_t) == sizeof(ntw2_status) &&
              NTW2_PUPPET_SELECT_WORDS == 32u, "puppet select row appends after puppet_mover_words");
static_assert(NTW2_GRID_CENSUS == 0x8000u && (NTW2_VALID_MASK & NTW2_GRID_CENSUS) && !(NTW2_ALL & NTW2_GRID_CENSUS) &&
              sizeof(ntw2_grid_reader_status) == 1008 && sizeof(ntw2_grid_edge_status) == 32 &&
              offsetof(ntw2_grid_census_status, readers) == 40 && offsetof(ntw2_grid_census_status, edges) == 40 + 64 * 1008 &&
              sizeof(ntw2_grid_census_status) == 40 + 64 * 1008 + 512 * 32 &&
              offsetof(ntw2_grid_reader_status, calls_site) == 96 + 8, "grid census status geometry");
static_assert(NTW2_LOCO == 0x4000u && !(NTW2_ALL & NTW2_LOCO) && (NTW2_VALID_MASK & NTW2_LOCO) == NTW2_LOCO &&
              !(NTW2_LOCO & (NTW2_AI_BUDGET_EMA | NTW2_AI_SAFE_PARK | NTW2_AI_CTRL)), "loco is an opt-in simulation feature outside NTW2_ALL");
static_assert(offsetof(ntw2_status,ai_ctrl_words) == offsetof(ntw2_status,collide_lod_words) + NTW2_COLLIDE_LOD_WORDS * sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->ai_ctrl_words) == 16 * sizeof(uint32_t), "controller telemetry is append-only");
static_assert(NTW2_AI_CTRL == 0x800u && !(NTW2_ALL & NTW2_AI_CTRL) && (NTW2_VALID_MASK & NTW2_AI_CTRL), "controller offload is explicit opt-in");
static_assert(!(NTW2_ALL & (NTW2_AI_BUDGET_EMA | NTW2_AI_SAFE_PARK)) &&
              !(NTW2_VALID_MASK & (NTW2_AI_BUDGET_EMA | NTW2_AI_SAFE_PARK)),
              "retired AI suspension policies cannot be requested");
static_assert(offsetof(ntw2_status,ai_slice_words) == 4 * (29 + 16 + 16 + 24 + 8 + 192 + 16 + 16 + 64 + 16 + 16 + 32 + 32 + NTW2_BRAIN_WORDS + 32 + 80), "slice telemetry is append-only");
static_assert(offsetof(ntw2_status,ai_validation_words) == offsetof(ntw2_status,ai_slice_words) + 8 * sizeof(uint32_t), "validation telemetry is append-only");
static_assert(offsetof(ntw2_status,visual_words) == offsetof(ntw2_status,ai_validation_words) + 8 * sizeof(uint32_t), "visual telemetry is append-only");
static_assert(offsetof(ntw2_status,allocator_words) == offsetof(ntw2_status,visual_words) + 32 * sizeof(uint32_t), "allocator admission telemetry is append-only");
static_assert(offsetof(ntw2_status,ai_slice_site_words) == offsetof(ntw2_status,allocator_words) + NTW2_ALLOCATOR_WORDS * sizeof(uint32_t), "slice location telemetry is append-only");
static_assert(offsetof(ntw2_status,brain_state_words) == offsetof(ntw2_status,ai_slice_site_words) + 2 * sizeof(uint32_t), "brain census telemetry is append-only");
static_assert(offsetof(ntw2_status,collision_words) == offsetof(ntw2_status,brain_state_words) + NTW2_BRAIN_STATE_WORDS * sizeof(uint32_t), "collision census telemetry is append-only");
static_assert(offsetof(ntw2_status,collide_words) == offsetof(ntw2_status,collision_words) + NTW2_COLLISION_WORDS * sizeof(uint32_t) &&
              NTW2_COLLIDE_WORDS == 61u && sizeof(((ntw2_status*)nullptr)->collide_words) == 61 * sizeof(uint32_t), "collision solver telemetry is append-only");
static_assert(offsetof(ntw2_status,brain2_words) == offsetof(ntw2_status,collide_words) + NTW2_COLLIDE_WORDS * sizeof(uint32_t) &&
              NTW2_BRAIN2_WORDS == 48u && NTW2_BRAIN2 == 0x80u && !(NTW2_ALL & NTW2_BRAIN2) && (NTW2_VALID_MASK & NTW2_BRAIN2) == NTW2_BRAIN2,
              "brain2 telemetry is append-only; the feature bit is valid and outside NTW2_ALL");
static_assert(offsetof(ntw2_status,collide_lod_words) == offsetof(ntw2_status,brain2_words) + NTW2_BRAIN2_WORDS * sizeof(uint32_t) &&
              NTW2_COLLIDE_LOD_WORDS == 16u && NTW2_COLLIDE_LOD == 0x400u && !(NTW2_ALL & NTW2_COLLIDE_LOD),
              "collision LOD telemetry is append-only and opt-in");
static_assert(NTW2_COLLISION_WORDS == 32u && NTW2_TIMED_SITES == 110u, "collision census geometry");
static_assert(NTW2_BRAIN_STATE_COUNTS + NTW2_BRAIN_STATE_BUCKETS == NTW2_BRAIN_SUBSTATE_COUNTS &&
              NTW2_BRAIN_SUBSTATE_COUNTS + NTW2_BRAIN_SUBSTATE_BUCKETS == NTW2_BRAIN_TRANSITION_COUNTS &&
              NTW2_BRAIN_TRANSITION_COUNTS + NTW2_BRAIN_STATE_BUCKETS == NTW2_BRAIN_TRANSITION_UNITS &&
              NTW2_BRAIN_TRANSITION_UNITS + NTW2_BRAIN_STATE_BUCKETS == NTW2_BRAIN_STATE_WORDS, "brain census geometry");
static_assert(NTW2_BRAIN_HEADER_WORDS + 2 * NTW2_BRAIN_FAMILIES * NTW2_BRAIN_SITES <= NTW2_BRAIN_WORDS &&
              NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_SITES == 95u && NTW2_TIMED_SITES <= NTW2_TRACE_SITES, "brain words geometry");
static_assert(sizeof(ntw2_profile_status) == 15748, "profile ABI");
static_assert(sizeof(ntw2_profile_phase_status) == 184 &&
              offsetof(ntw2_profile_status, main_start_tick_ms) == 10948 &&
              offsetof(ntw2_profile_status, main_rest) == 10952, "split tick phase is append-only");
static_assert(offsetof(ntw2_profile_status, main_modules) == 10832, "module profile is append-only");
static_assert(offsetof(ntw2_profile_status, main_thread_id) == 5768, "main profile is append-only");
static_assert(sizeof(((ntw2_profile_status*)0)->chain_count) == 256 &&
              sizeof(((ntw2_profile_status*)0)->chain_len) == 256 &&
              sizeof(((ntw2_profile_status*)0)->chains) == 4096, "profile chain ABI");
static_assert(sizeof(((ntw2_profile_status*)0)->main_hist_va) == 12 &&
              sizeof(((ntw2_profile_status*)0)->main_post_chain_count) == 256 &&
              sizeof(((ntw2_profile_status*)0)->main_post_chain_len) == 256 &&
              sizeof(((ntw2_profile_status*)0)->main_post_chains) == 4096, "main profile ABI");
static_assert(sizeof(((ntw2_profile_status*)0)->main_start_chain_count) == 256 &&
              sizeof(((ntw2_profile_status*)0)->main_start_chain_len) == 256 &&
              sizeof(((ntw2_profile_status*)0)->main_start_chains) == 4096, "main A1 chain ABI");
static_assert(offsetof(ntw2_trace_entry, site_us) == 32 &&
              offsetof(ntw2_trace_entry, site_calls) == 480 &&
              offsetof(ntw2_trace_entry, qpc_start_lo) == 928, "trace QPC is append-only");
static_assert(sizeof(ntw2_trace_entry) == 944 && sizeof(ntw2_trace_ring) == 32 + 944 * NTW2_TRACE_ENTRIES, "trace ABI");
#endif
#endif
