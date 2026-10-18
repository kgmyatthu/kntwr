// Owned-process runtime lifecycle oracle. No game is launched. The real DLL sees
// a privately relocated supported image through a test-owned GetModuleHandleW
// import substitution. All source pins, clone generation, slot publication and
// restoration execute unchanged. Startup allocation/free use owned-process heap
// fixtures; AI lifecycle cases execute a synthetic planner, never the game's planner or renderer.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ntw2_runtime.h"
#include "native_image_relocation.h"
#include "../src/clones/ntw2_clones.h"

static_assert(NTW2_TRACE_ABI==8u && NTW2_TRACE_ENTRIES==1024u, "trace ABI 8 ring contract");
static_assert(NTW2_TRACE_SITES==112u && NTW2_TIMED_SITES==110u, "trace site capacity and populated range");
static_assert(sizeof(ntw2_trace_entry)==944u, "trace ABI 8 entry layout");
static_assert(sizeof(ntw2_trace_ring)==966688u, "trace ABI 8 ring layout");
static_assert(offsetof(ntw2_trace_entry,site_us)==32u && offsetof(ntw2_trace_entry,site_calls)==480u &&
              offsetof(ntw2_trace_entry,qpc_start_lo)==928u && offsetof(ntw2_trace_entry,qpc_end_lo)==936u,
              "raw gate QPC fields preserve site offsets");
static_assert(offsetof(ntw2_trace_ring,ring)==32u && offsetof(ntw2_trace_ring,qpc_freq_lo)==20u,
              "QPC frequency reuses trace header reserved words");
static_assert(NTW2_PROFILE_ABI==8u && sizeof(ntw2_profile_status)==15748u &&
              offsetof(ntw2_profile_status,main_modules)==10832u && NTW2_PROFILE_MODULE_COUNT==9,
              "split tick phases preserve module counter offsets");
static_assert(NTW2_PROFILE_MAIN_PHASES==4u && NTW2_PROFILE_INLINE_PHASES==3u &&
              offsetof(ntw2_profile_status,main_start_tick_ms)==10948u &&
              offsetof(ntw2_profile_status,main_rest)==10952u && sizeof(ntw2_profile_phase_status)==184u,
              "A2 and A1 chains are appended after ABI 6");
static_assert(NTW2_PROFILE_START_TICK_MS==25u && NTW2_PROFILE_POST_TICK_MS==40u &&
              NTW2_PROFILE_PHASE_A1==0 && NTW2_PROFILE_PHASE_B==1 &&
              NTW2_PROFILE_PHASE_C==2 && NTW2_PROFILE_PHASE_A2==3,
              "split-phase timing and histogram storage order");
static constexpr uint32_t kSiteCallees[]=NTW2_SITE_CALLEE_VAS;
static_assert(sizeof(kSiteCallees)/sizeof(kSiteCallees[0])==NTW2_TIMED_SITES, "all timed sites have labels");
static_assert(kSiteCallees[18]==0x580390u && kSiteCallees[95]==0x55CB50u &&
              kSiteCallees[101]==0x581F30u && kSiteCallees[105]==0x579AD0u, "army direct callees appended without renumbering");
static_assert(kSiteCallees[106]==0x81A790u && kSiteCallees[107]==0x56EE80u &&
              kSiteCallees[108]==0x81A670u && kSiteCallees[109]==0x44u, "collision sites append without renumbering");
static_assert(NTW2_AI_ASYNC==0x08u && (NTW2_ALL&NTW2_AI_ASYNC)==NTW2_AI_ASYNC && !(NTW2_PROFILE&NTW2_AI_ASYNC), "ai feature bit");
static_assert(NTW2_AI_CTRL==0x800u && !(NTW2_ALL&NTW2_AI_CTRL) && (NTW2_VALID_MASK&NTW2_AI_CTRL), "controller feature is opt-in");
static_assert(NTW2_AI_BUDGET_EMA==0x1000u && NTW2_AI_SAFE_PARK==0x2000u &&
              !(NTW2_ALL&(NTW2_AI_BUDGET_EMA|NTW2_AI_SAFE_PARK)) &&
              !(NTW2_VALID_MASK&(NTW2_AI_BUDGET_EMA|NTW2_AI_SAFE_PARK)),
              "retired policy bits cannot bypass same-tick completion");
static_assert(NTW2_BRAIN==0x40u && !(NTW2_ALL&NTW2_BRAIN) && !(NTW2_PROFILE&NTW2_BRAIN), "brain feature bit is opt-in and outside NTW2_ALL");
static_assert(NTW2_BRAIN2==0x80u && !(NTW2_ALL&NTW2_BRAIN2) && (NTW2_VALID_MASK&NTW2_BRAIN2)==NTW2_BRAIN2 && !(NTW2_PROFILE&NTW2_BRAIN2) && !(NTW2_BRAIN&NTW2_BRAIN2), "brain2 feature bit is an opt-in simulation feature, valid but outside NTW2_ALL");
static_assert(NTW2_VISUAL==0x100u && (NTW2_ALL&NTW2_VISUAL)==NTW2_VISUAL && !(NTW2_PROFILE&NTW2_VISUAL) && !(NTW2_BRAIN2&NTW2_VISUAL), "visual feature bit is a main-thread feature inside the shipping set NTW2_ALL");
static_assert(NTW2_COLLIDE==0x200u && (NTW2_ALL&NTW2_COLLIDE)==NTW2_COLLIDE && (NTW2_VALID_MASK&NTW2_COLLIDE)==NTW2_COLLIDE, "collide is part of the shipping set");
static_assert(NTW2_COLLIDE_LOD==0x400u && !(NTW2_ALL&NTW2_COLLIDE_LOD) &&
              (NTW2_VALID_MASK&NTW2_COLLIDE_LOD)==NTW2_COLLIDE_LOD, "collision LOD is an opt-in simulation feature");
static_assert(NTW2_ALL==(NTW2_AI_ASYNC|NTW2_BATCH64|NTW2_VISUAL|NTW2_PROFILE|NTW2_LOCO|NTW2_COLLIDE), "NTW2_ALL is exactly the shipping set batch64,ai,visual,profile,loco,collide");
static_assert(NTW2_BRAIN_SLOTS==23u && NTW2_BRAIN_FAMILIES==5u && NTW2_BRAIN_SITE_FIRST==46u && NTW2_BRAIN_SITES==49u && NTW2_BRAIN_WORDS==512u, "brain profiling geometry");
static_assert(sizeof(ntw2_status)==4*(29+16+16+24+8+192+16+16+64+16+16+32+32+512+32+80+8+8+32+NTW2_ALLOCATOR_WORDS+2+NTW2_BRAIN_STATE_WORDS+NTW2_COLLISION_WORDS+NTW2_COLLIDE_WORDS+NTW2_BRAIN2_WORDS+NTW2_COLLIDE_LOD_WORDS+16+NTW2_AI_SLICE_BUDGET_WORDS+8+NTW2_LOCO_WORDS+NTW2_LOCO_GATE_WORDS+NTW2_LOCO_SERVICE_WORDS+NTW2_LOCO_GRID_WORDS+NTW2_LOCO_PARALLEL_WORDS+NTW2_SWEEP_WORDS+NTW2_RESOLVE_WORDS+NTW2_ENV_WORDS+NTW2_ENV_TARGET_WORDS+NTW2_RESOLVE_FRAME_WORDS+NTW2_LOCO_OWNED_WORDS+NTW2_LOCO_OWNED_DETAIL_WORDS+NTW2_LOCO_OWNED_PHASE_WORDS+NTW2_LOCO_OWNED_LOAD_WORDS+NTW2_LOCO_GRID_V2_WORDS+NTW2_COLLIDE_SOURCE_WORDS+NTW2_MEMORY_WORDS+NTW2_AI_COMPLETION_WORDS+NTW2_AI_CENSUS_WORDS+NTW2_BRAIN2_CENSUS_WORDS+NTW2_NODE_WORDS+NTW2_NODE_EVENT_WORDS+NTW2_FIRE_WORDS+NTW2_BRAIN2_ROUTE_WORDS+NTW2_FIRE_COMMIT_WORDS+NTW2_MOVE_NODE_WORDS+NTW2_MOVE_NODE_EVENT_WORDS+NTW2_BRAIN2_NODE_TARGET_WORDS+(NTW2_IDLE_NODE_CLASSES+NTW2_ACTION_NODE_CLASSES)*(NTW2_NODE_WORDS+NTW2_NODE_EVENT_WORDS)+NTW2_BRAIN2_UNKNOWN_SITE_WORDS+NTW2_BRAIN_WORKER_WORDS+NTW2_AI_ASYNC2_WORDS+NTW2_BRAIN_WORKER_PHASE_WORDS+NTW2_BRAIN_UNIT_WORDS+NTW2_COLLIDE_CONTACT_WORDS+NTW2_GRID_PROBATION_WORDS+NTW2_AI_ASYNC2_ROUTE_WORDS+NTW2_ARMY_UNIT_WORDS+NTW2_VA_WATCH_WORDS+NTW2_ARMY_B0_WORDS+NTW2_ARMY_STORM_WORDS+NTW2_BRAIN_S0_WORDS+NTW2_AI_DEFERRED_WORDS+NTW2_AI_CTRL_REUSE_WORDS+NTW2_LOCO_RELINK_WORDS+NTW2_LOCO_CW_WORDS+NTW2_LOCO_GRID_BUILD_WORDS+NTW2_BRAIN_UNIT_POLICY_WORDS+NTW2_AI_PREPASS_CENSUS_WORDS+NTW2_AI_PREPASS_WORDS+NTW2_AI_SPIRAL_WORDS+NTW2_ARMY_SOLVER_WORDS)+sizeof(ntw2_grid_census_status), "status ABI appends class shadow, target, unknown-site, brain worker, ai_async2, brain worker phase, army unit, reserved (former puppet), army B0, reserved (former puppet motion, divert, mover, select), brain S0, ai_deferred and ai_ctrl_reuse words, loco relink, class-wrapper census, grid build, brain unit policy, ai prepass census, ai prepass, ai spiral and army solver words without changing existing words");
static_assert(NTW2_AI_SLICE_BUDGET_WORDS==8u && offsetof(ntw2_status,ai_slice_budget_words)==offsetof(ntw2_status,ai_ctrl_words)+16*sizeof(uint32_t), "slice budget words retain their shipped offset");
static_assert(offsetof(ntw2_status,ai_park_words)==offsetof(ntw2_status,ai_slice_budget_words)+NTW2_AI_SLICE_BUDGET_WORDS*sizeof(uint32_t) &&
              offsetof(ntw2_status,ai_park_words)+8*sizeof(uint32_t)==offsetof(ntw2_status,loco_words), "parking refusal histogram keeps its shipped offset");
static_assert(NTW2_LOCO_WORDS==48u && offsetof(ntw2_status,loco_words)==offsetof(ntw2_status,ai_park_words)+8*sizeof(uint32_t) &&
              offsetof(ntw2_status,loco_words)+NTW2_LOCO_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_gate_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_words)==48*sizeof(uint32_t), "loco telemetry preserves its shipped layout");
static_assert(NTW2_LOCO_GATE_WORDS==48u &&
              offsetof(ntw2_status,loco_gate_words)+NTW2_LOCO_GATE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_service_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_gate_words)==48*sizeof(uint32_t), "loco all-gates telemetry preserves its shipped layout");
static_assert(NTW2_LOCO_SERVICE_WORDS==40u &&
              offsetof(ntw2_status,loco_service_words)+NTW2_LOCO_SERVICE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_grid_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_service_words)==40*sizeof(uint32_t), "loco service timing telemetry preserves its shipped layout");
static_assert(NTW2_LOCO_GRID_WORDS==32u &&
              offsetof(ntw2_status,loco_grid_words)+NTW2_LOCO_GRID_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_parallel_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_grid_words)==32*sizeof(uint32_t), "loco grid telemetry is append-only");
static_assert(NTW2_LOCO_PARALLEL_WORDS==32u &&
              offsetof(ntw2_status,loco_parallel_words)+NTW2_LOCO_PARALLEL_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,sweep_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_parallel_words)==32*sizeof(uint32_t), "loco parallel telemetry is append-only");
static_assert(NTW2_SWEEP_WORDS==32u && NTW2_RESOLVE_WORDS==32u &&
              offsetof(ntw2_status,sweep_words)+32*sizeof(uint32_t)==offsetof(ntw2_status,resolve_words) &&
              offsetof(ntw2_status,resolve_words)+32*sizeof(uint32_t)==offsetof(ntw2_status,env_words) &&
              offsetof(ntw2_status,env_words)+32*sizeof(uint32_t)==offsetof(ntw2_status,env_target_words) &&
              offsetof(ntw2_status,env_target_words)+64*sizeof(uint32_t)==offsetof(ntw2_status,resolve_frame_words) &&
              offsetof(ntw2_status,resolve_frame_words)+4*sizeof(uint32_t)==offsetof(ntw2_status,loco_owned_words) &&
              NTW2_LOCO_OWNED_WORDS==32u && offsetof(ntw2_status,loco_owned_words)+NTW2_LOCO_OWNED_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_owned_detail_words) &&
              NTW2_LOCO_OWNED_DETAIL_WORDS==16u && offsetof(ntw2_status,loco_owned_detail_words)+NTW2_LOCO_OWNED_DETAIL_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_owned_phase_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_owned_detail_words)==16*sizeof(uint32_t) &&
              NTW2_LOCO_OWNED_PHASE_WORDS==32u && offsetof(ntw2_status,loco_owned_phase_words)+NTW2_LOCO_OWNED_PHASE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_owned_load_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_owned_phase_words)==32*sizeof(uint32_t) &&
              NTW2_LOCO_OWNED_LOAD_WORDS==16u && offsetof(ntw2_status,loco_owned_load_words)+NTW2_LOCO_OWNED_LOAD_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_grid_v2_words) &&
              sizeof(((ntw2_status*)nullptr)->loco_owned_load_words)==16*sizeof(uint32_t), "shadow, owned, detail, phase and load arrays append without moving existing words");
static_assert(NTW2_LOCO_GRID_V2_WORDS==16u && NTW2_COLLIDE_SOURCE_WORDS==4u &&
              offsetof(ntw2_status,loco_grid_v2_words)+16*sizeof(uint32_t)==offsetof(ntw2_status,collide_source_words) &&
              offsetof(ntw2_status,collide_source_words)+4*sizeof(uint32_t)==offsetof(ntw2_status,memory_words),
              "Stage C telemetry keeps all shipped offsets");
static_assert(offsetof(ntw2_status,memory_words)+NTW2_MEMORY_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_completion_words) &&
              offsetof(ntw2_status,ai_completion_words)+NTW2_AI_COMPLETION_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,grid_census) &&
              offsetof(ntw2_status,grid_census)+sizeof(ntw2_grid_census_status)==offsetof(ntw2_status,ai_census_words) &&
              offsetof(ntw2_status,ai_census_words)+NTW2_AI_CENSUS_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain2_census_words) &&
              offsetof(ntw2_status,brain2_census_words)+NTW2_BRAIN2_CENSUS_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,node_words) &&
              offsetof(ntw2_status,node_words)+NTW2_NODE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,node_event_words) &&
              offsetof(ntw2_status,node_event_words)+NTW2_NODE_EVENT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,fire_words) &&
              offsetof(ntw2_status,fire_words)+NTW2_FIRE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain2_route_words) &&
              offsetof(ntw2_status,brain2_route_words)+NTW2_BRAIN2_ROUTE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,fire_commit_words) &&
              offsetof(ntw2_status,fire_commit_words)+NTW2_FIRE_COMMIT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,move_node_words) &&
              offsetof(ntw2_status,move_node_words)+NTW2_MOVE_NODE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,move_node_event_words) &&
              offsetof(ntw2_status,move_node_event_words)+NTW2_MOVE_NODE_EVENT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain2_node_target_words) &&
              offsetof(ntw2_status,brain2_node_target_words)+NTW2_BRAIN2_NODE_TARGET_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,idle_node_words) &&
              offsetof(ntw2_status,idle_node_words)+NTW2_IDLE_NODE_CLASSES*NTW2_NODE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,idle_node_event_words) &&
              offsetof(ntw2_status,idle_node_event_words)+NTW2_IDLE_NODE_CLASSES*NTW2_NODE_EVENT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,action_node_words) &&
              offsetof(ntw2_status,action_node_words)+NTW2_ACTION_NODE_CLASSES*NTW2_NODE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,action_node_event_words) &&
              offsetof(ntw2_status,action_node_event_words)+NTW2_ACTION_NODE_CLASSES*NTW2_NODE_EVENT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain2_unknown_site_words) &&
              offsetof(ntw2_status,brain2_unknown_site_words)+NTW2_BRAIN2_UNKNOWN_SITE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain_worker_words) &&
              offsetof(ntw2_status,brain_worker_words)+NTW2_BRAIN_WORKER_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_async2_words) &&
              offsetof(ntw2_status,ai_async2_words)+NTW2_AI_ASYNC2_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain_worker_phase_words) &&
              offsetof(ntw2_status,brain_worker_phase_words)+NTW2_BRAIN_WORKER_PHASE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain_unit_words) &&
              offsetof(ntw2_status,brain_unit_words)+NTW2_BRAIN_UNIT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,collide_contact_words) && NTW2_BRAIN_UNIT_WORDS==176u &&
              offsetof(ntw2_status,collide_contact_words)+NTW2_COLLIDE_CONTACT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,grid_probation_words) && NTW2_COLLIDE_CONTACT_WORDS==48u &&
              offsetof(ntw2_status,grid_probation_words)+NTW2_GRID_PROBATION_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_async2_route_words) && NTW2_GRID_PROBATION_WORDS==32u+256u*8u &&
              offsetof(ntw2_status,ai_async2_route_words)+NTW2_AI_ASYNC2_ROUTE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,army_unit_words) && NTW2_AI_ASYNC2_ROUTE_WORDS==65u &&
              offsetof(ntw2_status,army_unit_words)+NTW2_ARMY_UNIT_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,va_watch_words) && NTW2_ARMY_UNIT_WORDS==192u &&
              offsetof(ntw2_status,va_watch_words)+NTW2_VA_WATCH_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,army_b0_words) && NTW2_VA_WATCH_WORDS==64u &&
              offsetof(ntw2_status,army_b0_words)+NTW2_ARMY_B0_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,army_storm_words) && NTW2_ARMY_B0_WORDS==160u &&
              offsetof(ntw2_status,army_storm_words)+NTW2_ARMY_STORM_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain_s0_words) && NTW2_ARMY_STORM_WORDS==128u &&
              offsetof(ntw2_status,brain_s0_words)+NTW2_BRAIN_S0_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_deferred_words) && NTW2_BRAIN_S0_WORDS==560u &&
              offsetof(ntw2_status,ai_deferred_words)+NTW2_AI_DEFERRED_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_ctrl_reuse_words) && NTW2_AI_DEFERRED_WORDS==64u &&
              offsetof(ntw2_status,ai_ctrl_reuse_words)+NTW2_AI_CTRL_REUSE_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_relink_words) && NTW2_AI_CTRL_REUSE_WORDS==32u &&
              offsetof(ntw2_status,loco_relink_words)+NTW2_LOCO_RELINK_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_cw_words) && NTW2_LOCO_RELINK_WORDS==32u &&
              offsetof(ntw2_status,loco_cw_words)+NTW2_LOCO_CW_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,loco_grid_build_words) && NTW2_LOCO_CW_WORDS==32u &&
              offsetof(ntw2_status,loco_grid_build_words)+NTW2_LOCO_GRID_BUILD_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,brain_unit_policy_words) && NTW2_LOCO_GRID_BUILD_WORDS==16u &&
              offsetof(ntw2_status,brain_unit_policy_words)+NTW2_BRAIN_UNIT_POLICY_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_prepass_census_words) && NTW2_BRAIN_UNIT_POLICY_WORDS==256u &&
              offsetof(ntw2_status,ai_prepass_census_words)+NTW2_AI_PREPASS_CENSUS_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_prepass_words) && NTW2_AI_PREPASS_CENSUS_WORDS==82u &&
              offsetof(ntw2_status,ai_prepass_words)+NTW2_AI_PREPASS_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,ai_spiral_words) && NTW2_AI_PREPASS_WORDS==60u && NTW2_AI_POLY_WORDS==32u && NTW2_AI_RECORD_TEST_WORDS==28u &&
              offsetof(ntw2_status,ai_spiral_words)+NTW2_AI_SPIRAL_WORDS*sizeof(uint32_t)==offsetof(ntw2_status,army_solver_words) && NTW2_AI_SPIRAL_WORDS==32u &&
              offsetof(ntw2_status,army_solver_words)+NTW2_ARMY_SOLVER_WORDS*sizeof(uint32_t)==sizeof(ntw2_status) && NTW2_ARMY_SOLVER_WORDS==519u &&
              NTW2_AI_POLY_SHADOW==0x4u && NTW2_AI_POLY==0x8u && NTW2_AI_SPIRAL_CENSUS==0x10u && NTW2_AI_SPIRAL_CAP_SHIFT==16u &&
              NTW2_AI_RECORD_TEST_SHADOW==0x20u && NTW2_AI_RECORD_TEST==0x40u && NTW2_AI_PREPASS_FLAGS_VALID==0xFFFF007Fu &&
              NTW2_AI_ASYNC2==0x20000u && !(NTW2_ALL&NTW2_AI_ASYNC2) && (NTW2_VALID_MASK&NTW2_AI_ASYNC2)==NTW2_AI_ASYNC2,
              "class shadow and target rows append after the existing fire commit tail");
static_assert(NTW2_ARMY_UNIT_SHADOW==0x40000u && !(NTW2_ALL&NTW2_ARMY_UNIT_SHADOW) &&
              (NTW2_VALID_MASK&NTW2_ARMY_UNIT_SHADOW)==NTW2_ARMY_UNIT_SHADOW && !(NTW2_ARMY_UNIT_SHADOW&NTW2_PROFILE),
              "army unit shadow is its own opt-in observation bit outside the shipping set");
static_assert(!(NTW2_VALID_MASK&0x80000u),"the retired puppet probe mask bit stays refused");
static_assert(NTW2_AI_CENSUS==0x10000u && !(NTW2_ALL&NTW2_AI_CENSUS) && (NTW2_VALID_MASK&NTW2_AI_CENSUS)==NTW2_AI_CENSUS &&
              !(NTW2_AI_CENSUS&(NTW2_PROFILE|NTW2_GRID_CENSUS)) && NTW2_AI_CENSUS_WORDS==768u,
              "ai census is its own opt-in bit outside the shipping set");
static_assert(NTW2_GRID_CENSUS==0x8000u && !(NTW2_ALL&NTW2_GRID_CENSUS) &&
              (NTW2_VALID_MASK&NTW2_GRID_CENSUS)==NTW2_GRID_CENSUS && !(NTW2_GRID_CENSUS&NTW2_PROFILE),
              "grid census is independent of PROFILE and off in the shipping set");
static_assert(NTW2_GRID_READERS==64u && NTW2_GRID_EDGES==512u &&
              NTW2_GRID_SITES==113u && NTW2_GRID_UNKNOWN_SITE==112u &&
              NTW2_GRID_PHASES==4u && NTW2_GRID_THREADS==3u,
              "grid census reader, edge and attribution capacities are bounded");
static_assert(sizeof(ntw2_grid_reader_status)==1008u && sizeof(ntw2_grid_edge_status)==32u &&
              sizeof(ntw2_grid_census_status)==80936u &&
              offsetof(ntw2_grid_census_status,readers)==40u &&
              offsetof(ntw2_grid_census_status,edges)==64552u &&
              offsetof(ntw2_grid_reader_status,calls_phase)==48u &&
              offsetof(ntw2_grid_reader_status,calls_site)==104u,
              "grid census v1 is a fixed-width append-only status payload");
static_assert(NTW2_LOCO==0x4000u && (NTW2_ALL&NTW2_LOCO)==NTW2_LOCO && (NTW2_VALID_MASK&NTW2_LOCO)==NTW2_LOCO &&
              !(NTW2_LOCO&(NTW2_BRAIN|NTW2_BRAIN2|NTW2_COLLIDE|NTW2_COLLIDE_LOD)), "loco is part of the shipping set NTW2_ALL");
static_assert(offsetof(ntw2_status,ai_ctrl_words)==offsetof(ntw2_status,collide_lod_words)+NTW2_COLLIDE_LOD_WORDS*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->ai_ctrl_words)==16*sizeof(uint32_t), "controller counters preserve all previous offsets");
static_assert(offsetof(ntw2_status,ai_slice_words)==4*(29+16+16+24+8+192+16+16+64+16+16+32+32+512+32+80), "slice counters preserve all previous offsets");
static_assert(offsetof(ntw2_status,ai_validation_words)==offsetof(ntw2_status,ai_slice_words)+32, "validation counters preserve all previous offsets");
static_assert(offsetof(ntw2_status,visual_words)==offsetof(ntw2_status,ai_validation_words)+32 && sizeof(((ntw2_status*)nullptr)->visual_words)==32*sizeof(uint32_t), "visual words are appended after validation counters");
static_assert(offsetof(ntw2_status,allocator_words)==offsetof(ntw2_status,visual_words)+32*sizeof(uint32_t), "allocator words preserve visual offsets");
static_assert(offsetof(ntw2_status,ai_slice_site_words)==offsetof(ntw2_status,allocator_words)+NTW2_ALLOCATOR_WORDS*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->ai_slice_site_words)==2*sizeof(uint32_t), "slice-location counters preserve all previous offsets");
static_assert(offsetof(ntw2_status,brain_state_words)==offsetof(ntw2_status,ai_slice_site_words)+2*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->brain_state_words)==288*sizeof(uint32_t), "brain census preserves all previous offsets");
static_assert(NTW2_BRAIN_STATE_BUCKETS==64 && NTW2_BRAIN_SUBSTATE_BUCKETS==80 &&
              NTW2_BRAIN_STATE_COUNTS==16 && NTW2_BRAIN_SUBSTATE_COUNTS==80 &&
              NTW2_BRAIN_TRANSITION_COUNTS==160 && NTW2_BRAIN_TRANSITION_UNITS==224, "brain census histogram geometry");
static_assert(offsetof(ntw2_status,collision_words)==offsetof(ntw2_status,brain_state_words)+NTW2_BRAIN_STATE_WORDS*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->collision_words)==32*sizeof(uint32_t), "collision census preserves all previous offsets");
static_assert(offsetof(ntw2_status,collide_words)==offsetof(ntw2_status,collision_words)+NTW2_COLLISION_WORDS*sizeof(uint32_t) &&
              NTW2_COLLIDE_WORDS==61u && sizeof(((ntw2_status*)nullptr)->collide_words)==61*sizeof(uint32_t),
              "collision solver appends diagnostics, then shaped-pair/thread/sub-timer words, without moving earlier fields");
static_assert(NTW2_BRAIN2_WORDS==48u && offsetof(ntw2_status,brain2_words)==offsetof(ntw2_status,collide_words)+NTW2_COLLIDE_WORDS*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->brain2_words)==48*sizeof(uint32_t) &&
              offsetof(ntw2_status,brain2_reason_words)==4*(29+16+16+24+8+192+16+16+64+16+16+32+32+512) &&
              offsetof(ntw2_status,brain2_gate_words)==offsetof(ntw2_status,brain2_reason_words)+32*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->brain2_reason_words)==32*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->brain2_gate_words)==80*sizeof(uint32_t),
              "brain2 words are appended after the collide words; the attribution arrays keep the byte positions of the former agents arrays");
static_assert(offsetof(ntw2_status,collide_lod_words)==offsetof(ntw2_status,brain2_words)+NTW2_BRAIN2_WORDS*sizeof(uint32_t) &&
              sizeof(((ntw2_status*)nullptr)->collide_lod_words)==16*sizeof(uint32_t), "collision LOD preserves every prior status offset");
static_assert(sizeof(ntw2_config)==64 && offsetof(ntw2_config,ai_prepass_flags)==60 && offsetof(ntw2_config,ai_ctrl_flags)==56 && offsetof(ntw2_config,ai_deferred)==52 && offsetof(ntw2_config,va_watch_flags)==48 && NTW2_VA_WATCH==1u && NTW2_VA_WATCH_FLAGS_VALID==(NTW2_VA_WATCH|NTW2_ARMY_STORM_CENSUS|NTW2_ARMY_STORM_SAMPLE_MASK|NTW2_TICK_PCORE|NTW2_TICK_CORE_AB|NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW) && NTW2_ARMY_STORM_CENSUS==2u && NTW2_ARMY_STORM_SAMPLE_MASK==0xFF00u && NTW2_TICK_PCORE==4u && NTW2_TICK_CORE_AB==8u && NTW2_ARMY_SOLVER_MEMO==0x10u && NTW2_ARMY_SOLVER_SHADOW==0x20u && offsetof(ntw2_config,collide_lod_m)==32 && offsetof(ntw2_config,loco_flags)==36 &&
              offsetof(ntw2_config,collide_flags)==44 && NTW2_COLLIDE_CONTACT_SHADOW==1u && NTW2_COLLIDE_CONTACT_WORKERS==2u &&
              NTW2_COLLIDE_FLAGS_VALID==3u &&
              offsetof(ntw2_config,brain_flags)==40 && NTW2_BRAIN2_VERSION==2u &&
              NTW2_BRAIN_CENSUS==1u && NTW2_BRAIN_TIMING==2u &&
              NTW2_BRAIN_NODE_SHADOW==4u && NTW2_BRAIN_FIRE_SHADOW==8u && NTW2_BRAIN_PARALLEL==16u &&
              NTW2_BRAIN_FINALIZER_SHADOW==32u && NTW2_BRAIN_QUIET==64u && NTW2_BRAIN_UNIT_SHADOW==128u && NTW2_BRAIN_S0==256u &&
              NTW2_BRAIN_UNIT_FATIGUE==512u && NTW2_BRAIN_UNIT_FATIGUE_SHADOW==1024u && NTW2_BRAIN_UNIT_POSTURE==2048u &&
              NTW2_BRAIN_UNIT_POSTURE_SHADOW==4096u && NTW2_BRAIN_UNIT_ENGAGE==8192u && NTW2_BRAIN_UNIT_ENGAGE_SHADOW==16384u &&
              NTW2_BRAIN_LOCALITY==32768u && NTW2_BRAIN_LOCALITY_WARM==65536u && NTW2_BRAIN_LOCALITY_PREFETCH==131072u &&
              NTW2_BRAIN_LOCALITY_PREFETCH2==262144u && NTW2_BRAIN_LOCALITY_MARK==524288u && NTW2_BRAIN_FLAGS_VALID==1048575u,
              "brain flags append without moving existing configuration fields");
static_assert((NTW2_COLLIDE_CENSUS&NTW2_COLLIDE_LOD_METRES_MASK)==0 &&
              (NTW2_COLLIDE_CENSUS|NTW2_COLLIDE_LOD_METRES_MASK)==UINT32_MAX, "census flag keeps collide_lod_m self-contained");

using U=uint32_t;
static uint8_t* image;
static U delta;
static unsigned checks, failures;
static HMODULE (WINAPI *realModule)(LPCWSTR)=GetModuleHandleW;
static HMODULE WINAPI TestModule(LPCWSTR name) { return name ? realModule(name) : reinterpret_cast<HMODULE>(image); }
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
static void Check(bool ok,const char* what) { ++checks; if(!ok) { ++failures; fprintf(stderr,"FAIL %s (%lu)\n",what,GetLastError()); } }
static bool InRuntime(U address);
static bool AiEventWorker(const ntw2_status& s) {
    if(s.ai_slice_words[6] || !s.ai_slice_words[7]) return false;
    HANDLE thread=OpenThread(THREAD_SUSPEND_RESUME,FALSE,s.ai_slice_words[7]);
    if(!thread) return false;
    // The oracle briefly samples the suspend count; production must never own a suspension.
    const DWORD previous=SuspendThread(thread);
    const bool restored=previous!=static_cast<DWORD>(-1) && ResumeThread(thread)!=static_cast<DWORD>(-1);
    CloseHandle(thread);
    return restored && previous==0;
}
static U* At(U va) { return reinterpret_cast<U*>(va+delta); }
static bool MapImage(const char* path) {
    HANDLE file=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE) return false;
    const DWORD fileSize=GetFileSize(file,nullptr);
    auto read=[&](DWORD offset,void* out,DWORD size) {
        if(offset>fileSize || size>fileSize-offset) return false;
        LARGE_INTEGER pos={}; pos.QuadPart=offset; DWORD got=0;
        return SetFilePointerEx(file,pos,nullptr,FILE_BEGIN) && ReadFile(file,out,size,&got,nullptr) && got==size;
    };
    alignas(4) uint8_t header[4096];
    if(!read(0,header,sizeof(header))) { CloseHandle(file); return false; }
    auto dos=reinterpret_cast<IMAGE_DOS_HEADER*>(header);
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<0 || static_cast<size_t>(dos->e_lfanew)>sizeof(header)-sizeof(IMAGE_NT_HEADERS32)) { CloseHandle(file); return false; }
    auto nt=reinterpret_cast<IMAGE_NT_HEADERS32*>(header+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386) { CloseHandle(file); return false; }
    const U size=nt->OptionalHeader.SizeOfImage, base=nt->OptionalHeader.ImageBase;
    image=static_cast<uint8_t*>(VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
    if(!image) { CloseHandle(file); return false; }
    bool ok=nt->OptionalHeader.SizeOfHeaders<=size && read(0,image,nt->OptionalHeader.SizeOfHeaders);
    auto loaded=reinterpret_cast<IMAGE_NT_HEADERS32*>(image+dos->e_lfanew);
    auto sections=IMAGE_FIRST_SECTION(loaded);
    for(unsigned i=0;ok && i<loaded->FileHeader.NumberOfSections;++i) {
        const U n=sections[i].SizeOfRawData<sections[i].Misc.VirtualSize ? sections[i].SizeOfRawData : sections[i].Misc.VirtualSize;
        ok=sections[i].VirtualAddress<=size && n<=size-sections[i].VirtualAddress && read(sections[i].PointerToRawData,image+sections[i].VirtualAddress,n);
    }
    CloseHandle(file);
    delta=A(image)-base;
    if(!ok || !RelocateNativeImage(image,size,loaded,delta)) return false;
    loaded->OptionalHeader.ImageBase=A(image); // the loader publishes the actual base after relocation
    for(unsigned i=0;i<loaded->FileHeader.NumberOfSections;++i) {
        const U flags=sections[i].Characteristics;
        if(!sections[i].Misc.VirtualSize) continue;
        const DWORD protect=(flags&IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : ((flags&IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
        DWORD old=0;
        if(!VirtualProtect(image+sections[i].VirtualAddress,sections[i].Misc.VirtualSize,protect,&old)) return false;
    }
    return true;
}
static U* ModuleImport(HMODULE module,const char* name) {
    auto base=reinterpret_cast<uint8_t*>(module);
    auto nt=reinterpret_cast<IMAGE_NT_HEADERS32*>(base+reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!dir.VirtualAddress) return nullptr;
    auto descriptor=reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base+dir.VirtualAddress);
    for(;descriptor->Name;++descriptor) {
        if(!descriptor->OriginalFirstThunk) continue;
        auto names=reinterpret_cast<IMAGE_THUNK_DATA32*>(base+descriptor->OriginalFirstThunk);
        auto slots=reinterpret_cast<U*>(base+descriptor->FirstThunk);
        for(;names->u1.AddressOfData;++names,++slots) {
            if(IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal)) continue;
            auto entry=reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base+names->u1.AddressOfData);
            if(!strcmp(reinterpret_cast<char*>(entry->Name),name)) return slots;
        }
    }
    return nullptr;
}
static bool Replace(U* cell,U value) {
    DWORD old=0,ignored=0;
    if(!VirtualProtect(cell,4,PAGE_READWRITE,&old)) return false;
    InterlockedExchange(reinterpret_cast<volatile LONG*>(cell),static_cast<LONG>(value));
    return VirtualProtect(cell,4,old,&ignored)!=FALSE;
}
static bool ReadState(volatile ntw2_status* state,ntw2_status& out) {
    for(unsigned i=0;i<1000;++i) {
        const U before=static_cast<U>(InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&state->sequence),0,0));
        if(before&1) { if(i>=8) Sleep(0); continue; } // writer in progress (may be preempted mid-copy): yield instead of hot-spinning
        memcpy(&out,const_cast<const ntw2_status*>(state),sizeof(out));
        const U after=static_cast<U>(InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&state->sequence),0,0));
        if(before==after && !(after&1)) return true;
    }
    return false;
}
static ntw2_activation_boundary_fn activationBoundary;
static U activationBoundaries;
static void PumpActivation(const ntw2_status& state) {
    // The fixture owns this synthetic model exclusively; production calls the
    // identical seam from TickGate before executing the native tick.
    if (state.phase==NTW2_ACTIVATING && activationBoundary) {
        Check(activationBoundary(reinterpret_cast<void*>(state.model+4))==0,"foreign model cannot consume an activation request");
        if (activationBoundary(reinterpret_cast<void*>(state.model))) {
            Check(state.active_mask==0,"capture completes before any feature epoch is enabled");
            ++activationBoundaries;
        }
    }
}
static bool WaitActive(volatile ntw2_status* state,U mask=NTW2_BATCH64) {
    const ULONGLONG end=GetTickCount64()+3000;
    do {
        ntw2_status value={};
        if(ReadState(state,value)) {
            PumpActivation(value);
            if(value.phase==NTW2_ACTIVE && value.active_mask==mask) return true;
            if(value.phase==NTW2_FAILED) { fprintf(stderr,"runtime error=%u detail=%08x\n",value.error,value.error_detail); return false; }
        }
        Sleep(1);
    } while(GetTickCount64()<end);
    return false;
}
static bool ReadOnly(U* cell) { MEMORY_BASIC_INFORMATION m={}; return VirtualQuery(cell,&m,sizeof(m)) && m.Protect==PAGE_READONLY; }
static void __fastcall ForeignWorker(void*) {}
static uint8_t engine[0x200], root[0x29000], model[0x800], armyManager[0x400];
static void Put(uint8_t* p,U offset,U value) { memcpy(p+offset,&value,4); }
// Minimal real immutable owned scene read by NTW2_LOCO_OWNED_SERVICES activation: [model+A8] obstacle grid (empty 32x32 cell heads)
// and [model+C0] kd root node whose bounds straddle everything. Bound only around loco cycles; absent it activation fails closed.
static uint8_t locoGrid[0x40], locoCells[4096], locoKd[0x80], locoTree[0x40];
static void BindLocoScene(bool on) {
    if(!on) { Put(model,0xA8,0); Put(model,0xC0,0); return; }
    memset(locoGrid,0,sizeof(locoGrid)); memset(locoCells,0,sizeof(locoCells)); memset(locoKd,0,sizeof(locoKd)); memset(locoTree,0,sizeof(locoTree));
    const float huge=1.0e9f, scale=0.25f;
    Put(locoGrid,0,A(locoCells)); Put(locoGrid,8,5); Put(locoGrid,0x10,16); Put(locoGrid,0x14,31); memcpy(locoGrid+0x24,&scale,4);
    Put(locoKd,0x4C,A(locoTree));
    const float lo=-huge; memcpy(locoTree+0x10,&lo,4); memcpy(locoTree+0x18,&lo,4); memcpy(locoTree+0x1C,&huge,4); memcpy(locoTree+0x24,&huge,4);
    Put(model,0xA4,A(locoGrid)); Put(model,0xA8,A(locoGrid)); Put(model,0xC0,A(locoKd));
}
// Only the private mapped image is patched: its allocator cannot run without the game's process startup.
// Startup still executes the runtime's real worker callback, SEH admission, barrier and activation refusal.
static volatile LONG allocatorProbeFault, allocatorAllocations, allocatorFrees;
__declspec(thread) static volatile U allocatorTestTls[3]={0,0,0x80000000u};
static void* __cdecl TestAllocate(U count) {
    if(allocatorTestTls[2]!=0x80000000u) return nullptr;
    if(InterlockedCompareExchange(&allocatorProbeFault,0,0)==1)
        RaiseException(EXCEPTION_ACCESS_VIOLATION,0,0,nullptr);
    InterlockedIncrement(&allocatorAllocations);
    return HeapAlloc(GetProcessHeap(),0,count*sizeof(U));
}
static void __cdecl TestFree(void* value) {
    if(value) { InterlockedIncrement(&allocatorFrees); HeapFree(GetProcessHeap(),0,value); }
    if(InterlockedCompareExchange(&allocatorProbeFault,0,0)==2)
        RaiseException(EXCEPTION_ACCESS_VIOLATION,0,0,nullptr);
}
static bool RedirectImage(U va,const void* destination) {
    uint8_t* entry=reinterpret_cast<uint8_t*>(At(va));
    DWORD old=0,ignored=0;
    if(!VirtualProtect(entry,5,PAGE_EXECUTE_READWRITE,&old)) return false;
    entry[0]=0xe9;
    const U relative=A(destination)-A(entry)-5;
    memcpy(entry+1,&relative,sizeof(relative));
    const bool flushed=FlushInstructionCache(GetCurrentProcess(),entry,5)!=FALSE;
    return VirtualProtect(entry,5,old,&ignored)!=FALSE && flushed;
}
static bool InstallAllocatorTlsFixture() {
    auto base=reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    auto nt=reinterpret_cast<IMAGE_NT_HEADERS32*>(base+reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    const U rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(!rva) return false;
    auto tls=reinterpret_cast<IMAGE_TLS_DIRECTORY32*>(base+rva);
    *At(0x1841bb8)=*reinterpret_cast<const U*>(tls->AddressOfIndex);
    return true;
}
// Exercises the actual native 7C9350 / 4456D0 vector setup and 10E9DC0 allocator, through the published
// visual entry/item clones. Only world lookup, reset, item work, heap backing and Win32 lock adapters
// are fixtures; the runtime's provider, dispatch, native per-slot allocation and restoration are real.
constexpr U kArenaItems=256;
alignas(4) static uint8_t arenaContext[0x200], arenaRoot[0x4c], arenaSelf[0x140], arenaEntity[0x200];
static U arenaBuckets[3][NTW2_ALLOCATOR_THREADS], arenaItems[kArenaItems][8], arenaRecords[kArenaItems][2];
static U arenaList[kArenaItems], arenaPose[8], arenaEntityMethods[8], arenaOwnerMethods[2], arenaOwner[1];
static unsigned char arenaStatus[kArenaItems];
static volatile LONG arenaSlotOwners[NTW2_ALLOCATOR_THREADS], arenaSeen, arenaCalls, arenaProblems, arenaResets, arenaTails;
static HANDLE arenaOverlap;
static volatile LONG arenaArrivals, arenaArrived[NTW2_ALLOCATOR_THREADS];
static U ArenaAddress(U i) { return i==0 ? A(arenaRoot) : A(arenaContext)+(i==1 ? 0x80 : 0x118); }
static void __fastcall TestArenaPrepare(U context) {
    auto bytes=reinterpret_cast<uint8_t*>(context);
    if(bytes[0x16c]) return;
    InterlockedIncrement(&arenaResets);
    for(U i=0;i<3;++i) {
        U* arena=reinterpret_cast<U*>(ArenaAddress(i));
        arena[1]=arena[0];
        if(arena[0]) *reinterpret_cast<U*>(arena[0]+0xf4244)=0;
    }
    bytes[0x16c]=1;
}
static U __fastcall TestAnimationOwner(U) { return A(arenaOwner); }
static U __fastcall TestRootArena(U) { return A(arenaRoot); }
static U __fastcall TestArenaVirtualZero(U) { return 0; }
static void* __cdecl TestArenaBacking(U bytes) { return HeapAlloc(GetProcessHeap(),0,bytes); }
static void __fastcall TestArenaEnter(U* guard,void*,CRITICAL_SECTION* lock) {
    *guard=A(lock); EnterCriticalSection(lock);
}
static void __fastcall TestArenaLeave(U* guard) { LeaveCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(*guard)); }
static void __fastcall TestArenaResize(U* vector,void*,U count) { vector[2]=count; vector[3]=A(arenaStatus); }
static void __cdecl TestArenaTail(void*,void*,void*) {
    InterlockedIncrement(&arenaTails);
    for(U i=0;i<3;++i) {
        const U arena=ArenaAddress(i);
        if(*reinterpret_cast<unsigned char*>(arena+0x1c) || *reinterpret_cast<U*>(arena+0x20) ||
           *reinterpret_cast<U*>(arena+0x2c)) InterlockedIncrement(&arenaProblems);
    }
}
static void __fastcall TestArenaPose(U context,void*,U item) {
    if(!reinterpret_cast<uint8_t*>(context)[0x16c]) InterlockedIncrement(&arenaProblems);
    TestArenaPrepare(context); // the real 7911E0 starts with this call on every item
    U allocation[3]={}, participant=0;
    for(U i=0;i<3;++i) {
        const U arena=ArenaAddress(i), provider=*reinterpret_cast<const U*>(arena+0x20);
        if(!provider || !*reinterpret_cast<const unsigned char*>(arena+0x1c)) { InterlockedIncrement(&arenaProblems); return; }
        const U methods=*reinterpret_cast<const U*>(provider);
        const U count=reinterpret_cast<U (__fastcall*)(U)>(*reinterpret_cast<const U*>(methods))(provider);
        const U slot=reinterpret_cast<U (__fastcall*)(U)>(*reinterpret_cast<const U*>(methods+4))(provider);
        if(count!=3 || slot>=count) { InterlockedIncrement(&arenaProblems); return; }
        participant=slot;
        const LONG tid=static_cast<LONG>(GetCurrentThreadId());
        const LONG previous=InterlockedCompareExchange(&arenaSlotOwners[slot],tid,0);
        if(previous && previous!=tid) InterlockedIncrement(&arenaProblems);
        InterlockedOr(&arenaSeen,1L<<slot);
        allocation[i]=reinterpret_cast<U (__fastcall*)(U,void*,U,U)>(At(0x10e9dc0))(arena,nullptr,64,4);
        if(!allocation[i]) { InterlockedIncrement(&arenaProblems); return; }
        for(U word=0;word<16;++word) reinterpret_cast<volatile U*>(allocation[i])[word]=item+i+word;
    }
    // A one-time rendezvous guarantees overlapping live outputs on all three participants.
    // Per-item Sleep(1) is unsuitable: Windows can round it to a full ~15.6 ms timer interval.
    if(!InterlockedCompareExchange(&arenaArrived[participant],1,0)) {
        if(InterlockedIncrement(&arenaArrivals)==3) SetEvent(arenaOverlap);
        if(WaitForSingleObject(arenaOverlap,1000)!=WAIT_OBJECT_0) InterlockedIncrement(&arenaProblems);
    }
    SwitchToThread();
    for(U i=0;i<3;++i) for(U word=0;word<16;++word)
        if(reinterpret_cast<volatile U*>(allocation[i])[word]!=item+i+word) InterlockedIncrement(&arenaProblems);
    InterlockedIncrement(&arenaCalls);
}

struct StopCall { ntw2_stop_fn stop; U result; };
static DWORD WINAPI ConcurrentStop(void* value) {
    auto call=static_cast<StopCall*>(value);
    call->result=call->stop(nullptr);
    return 0;
}

// Independent copy of the census (analysis/native-agent-loop-structure.md 2.1): the 23 registry vtables whose slot +0x0C the brain
// profiling publishes, and the exact value each must hold before it is touched.
struct BrainSlot { U table, original; };
static const BrainSlot kBrain[NTW2_BRAIN_SLOTS]={
    {0x1333714,0x66ce00},{0x13473d0,0x66ce00},{0x13475e4,0x66ce00},{0x13477f8,0x66ce00},{0x13479b4,0x66ce00},{0x1347b70,0x66ce00},
    {0x1347d2c,0x66ce00},{0x134841c,0x66ce00},{0x1347ee8,0x66ce00},{0x13480a4,0x66ce00},{0x1348260,0x66ce00},
    {0x132b7d8,0x6f50f0},
    {0x13394c0,0x6f4660},{0x13396e4,0x6f4660},{0x1339924,0x6f4660},{0x1339b64,0x6f4660},{0x1339da4,0x6f4660},{0x133af78,0x6f4660},
    {0x132ba04,0x602eb0},
    {0x132be3c,0x5fceb0},{0x132c0c8,0x5fceb0},{0x132c2f0,0x5fceb0},{0x132c528,0x5fceb0}};
static const U kBrainFamilyOriginal[5]={0x66ce00,0x6f50f0,0x6f4660,0x602eb0,0x5fceb0};
constexpr U kSlotConflict=6; // runtime Error::SlotConflict
static HMODULE runtimeModule;
static bool InRuntime(U address) {
    MEMORY_BASIC_INFORMATION m={};
    return VirtualQuery(reinterpret_cast<void*>(static_cast<uintptr_t>(address)),&m,sizeof(m)) && m.AllocationBase==runtimeModule;
}
static bool AllBrainWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_BRAIN_WORDS;++i) if(s.brain_words[i]) return false;
    for(unsigned i=0;i<NTW2_BRAIN_STATE_WORDS;++i) if(s.brain_state_words[i]) return false;
    return true;
}
static bool AllCollisionWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_COLLISION_WORDS;++i) if(s.collision_words[i]) return false;
    return true;
}
static bool AllCollideWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_COLLIDE_WORDS;++i) if(s.collide_words[i]) return false;
    for(unsigned i=0;i<NTW2_COLLIDE_SOURCE_WORDS;++i) if(s.collide_source_words[i]) return false;
    return true;
}
static bool GridCensusWithoutCalls(const ntw2_status& s, bool enabled) {
    const auto& c=s.grid_census;
    if(!enabled) {
        static const ntw2_grid_census_status zero={};
        return !memcmp(&c,&zero,sizeof(c));
    }
    if(c.version!=1u || !c.reader_count || c.reader_count>NTW2_GRID_READERS ||
       !c.edge_count || c.edge_count>NTW2_GRID_EDGES || c.routed_ticks || c.edge_dropped) return false;
    for(U i=0;i<c.reader_count;++i) {
        const auto& r=c.readers[i];
        if(r.va>=r.end || (i && r.va<=c.readers[i-1].va) ||
           r.route_calls || r.route_tick_calls || r.entry_calls || r.entry_tick_calls) return false;
        for(U j=0;j<NTW2_GRID_PHASES;++j) if(r.calls_phase[j]) return false;
        for(U j=0;j<NTW2_GRID_THREADS;++j) if(r.calls_thread[j]) return false;
        for(U j=0;j<NTW2_GRID_SITES;++j) if(r.calls_site[j]) return false;
    }
    for(U i=0;i<c.edge_count;++i) {
        const auto& e=c.edges[i];
        if(e.reader>=c.reader_count || !e.site || !e.source_clone ||
           e.route>NTW2_GRID_ROUTE_OTHER || e.route_calls || e.route_tick_calls) return false;
    }
    return true; // Sampler attempts/failures/occupancy may advance independently of exact calls.
}
// Work excludes loco 0,42..45, gate 0/4, service 0/1, grid 0/16/18 (version/generation/storage bytes) and parallel 0/1 metadata.
static bool AllLocoWorkWordsZero(const ntw2_status& s) {
    for(unsigned i=1;i<=41;++i) if(s.loco_words[i]) return false;
    for(unsigned i=1;i<NTW2_LOCO_GATE_WORDS;++i) if(i!=4 && s.loco_gate_words[i]) return false;
    for(unsigned i=2;i<NTW2_LOCO_SERVICE_WORDS;++i) if(s.loco_service_words[i]) return false;
    for(unsigned i=1;i<NTW2_LOCO_GRID_WORDS;++i) if(i!=16 && i!=18 && s.loco_grid_words[i]) return false;
    for(unsigned i=2;i<NTW2_LOCO_PARALLEL_WORDS;++i) if(s.loco_parallel_words[i]) return false;
    for(unsigned i=2;i<NTW2_SWEEP_WORDS;++i) if(s.sweep_words[i]) return false;
    for(unsigned i=2;i<NTW2_RESOLVE_WORDS;++i) if(s.resolve_words[i]) return false;
    for(unsigned i=2;i<NTW2_ENV_WORDS;++i) if(i!=30 && s.env_words[i]) return false;
    for(unsigned i=0;i<NTW2_ENV_TARGET_WORDS;++i) if(s.env_target_words[i]) return false;
    for(unsigned i=0;i<NTW2_RESOLVE_FRAME_WORDS;++i) if(s.resolve_frame_words[i]) return false;
    for(unsigned i=2;i<NTW2_LOCO_OWNED_WORDS;++i) if(s.loco_owned_words[i]) return false;
    for(unsigned i=2;i<NTW2_LOCO_OWNED_DETAIL_WORDS;++i) if(s.loco_owned_detail_words[i]) return false;
    for(unsigned i=1;i<NTW2_LOCO_OWNED_PHASE_WORDS;++i) if(s.loco_owned_phase_words[i]) return false;
    for(unsigned i=7;i<NTW2_LOCO_OWNED_LOAD_WORDS;++i) if(s.loco_owned_load_words[i]) return false;
    for(unsigned i=3;i<NTW2_LOCO_GRID_V2_WORDS;++i) if(s.loco_grid_v2_words[i]) return false; // builds..epoch are work; no stage has run
    return !s.loco_words[46] && !s.loco_words[47];
}
static bool AllLocoWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_LOCO_WORDS;++i) if(s.loco_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_GATE_WORDS;++i) if(s.loco_gate_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_SERVICE_WORDS;++i) if(s.loco_service_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_GRID_WORDS;++i) if(s.loco_grid_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_PARALLEL_WORDS;++i) if(s.loco_parallel_words[i]) return false;
    for(unsigned i=0;i<NTW2_SWEEP_WORDS;++i) if(s.sweep_words[i]) return false;
    for(unsigned i=0;i<NTW2_RESOLVE_WORDS;++i) if(s.resolve_words[i]) return false;
    for(unsigned i=0;i<NTW2_ENV_WORDS;++i) if(s.env_words[i]) return false;
    for(unsigned i=0;i<NTW2_ENV_TARGET_WORDS;++i) if(s.env_target_words[i]) return false;
    for(unsigned i=0;i<NTW2_RESOLVE_FRAME_WORDS;++i) if(s.resolve_frame_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_OWNED_WORDS;++i) if(s.loco_owned_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_OWNED_DETAIL_WORDS;++i) if(s.loco_owned_detail_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_OWNED_PHASE_WORDS;++i) if(s.loco_owned_phase_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_OWNED_LOAD_WORDS;++i) if(s.loco_owned_load_words[i]) return false;
    for(unsigned i=0;i<NTW2_LOCO_GRID_V2_WORDS;++i) if(s.loco_grid_v2_words[i]) return false;
    return true;
}
// Quiet disables per-service QPC timing even with clone execution; version stays 1 while LOCO is active.
static bool LocoServiceMetadata(const ntw2_status& s, bool clone, bool quiet=false) {
    return s.loco_service_words[0]==1u && s.loco_service_words[1]==((clone && !quiet) ? 1u : 0u);
}
// Stage C grid v2 metadata: version 2 and enabled/verify mirror the effective flags while LOCO is active; every later word is work.
static bool LocoGridV2Metadata(const ntw2_status& s, bool grid, bool verify) {
    return s.loco_grid_v2_words[0]==2u && s.loco_grid_v2_words[1]==(grid ? 1u : 0u) && s.loco_grid_v2_words[2]==(verify ? 1u : 0u);
}
// Detail tail: version 1, quiet_enabled mirrors --loco-quiet, every other word is work. Quiet requires owned services.
static bool LocoOwnedMetadata(const ntw2_status& s, bool parallel, bool owned=false, bool quiet=false, bool grid=false) {
    if (!grid)
        for(unsigned i=1;i<NTW2_LOCO_GRID_WORDS;++i) if(s.loco_grid_words[i]) return false;
    return s.loco_grid_words[0]==1u && s.loco_grid_words[16]==(grid ? s.loco_words[43] : 0u) &&
           s.loco_owned_phase_words[0]==(owned ? 1u : 0u) &&
           s.loco_owned_load_words[0]==(owned ? 1u : 0u) && s.loco_owned_load_words[1]==(owned ? 1u : 0u) &&
           s.loco_parallel_words[0]==1u && s.loco_parallel_words[1]==(parallel ? 1u : 0u) &&
           s.loco_owned_words[0]==1u && s.loco_owned_words[1]==(owned ? 1u : 0u) &&
           s.loco_owned_detail_words[0]==1u && s.loco_owned_detail_words[1]==(quiet ? 1u : 0u) && (!quiet || owned);
}
static bool LocoPortMetadata(const ntw2_status& s, bool ports) {
    const U enabled=ports ? 1u : 0u;
    return s.sweep_words[0]==(ports ? 2u : 0u) && s.sweep_words[1]==enabled &&
           s.sweep_words[2]==0 &&
           s.resolve_words[0]==enabled && s.resolve_words[1]==enabled &&
           s.env_words[0]==enabled && s.env_words[1]==enabled &&
           s.env_words[30]==(ports ? s.loco_words[43] : 0u);
}
static bool AllCollideLodWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_COLLIDE_LOD_WORDS;++i) if(s.collide_lod_words[i]) return false;
    return true;
}
// No dispatch means every BRAIN2 v2 work/attribution/census word stays zero.
static bool AllBrain2WordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<NTW2_BRAIN2_WORDS;++i) if(s.brain2_words[i]) return false;
    for(unsigned i=0;i<32;++i) if(s.brain2_reason_words[i]) return false;
    for(unsigned i=0;i<80;++i) if(s.brain2_gate_words[i]) return false;
    for(unsigned i=0;i<NTW2_BRAIN2_CENSUS_WORDS;++i) if(s.brain2_census_words[i]) return false;
    for(unsigned i=0;i<NTW2_BRAIN_UNIT_WORDS;++i) if(s.brain_unit_words[i]) return false;
    for(unsigned i=0;i<NTW2_COLLIDE_CONTACT_WORDS;++i) if(s.collide_contact_words[i]) return false;
    return true;
}

// NTW2_VISUAL: the runtime publishes the host thunk into the single read-only .rdata word holding the relocated original 0x779E60.
// The test finds that slot by an independent scan of the mapped real image and never takes its address from the runtime.
constexpr U kVisualOriginalVa=0x779e60;
constexpr U kVisualScanError=13; // runtime Error::VisualSlotScan; error_detail = hit count
static bool RdataWords(U*& begin,U*& end) {
    auto nt=reinterpret_cast<IMAGE_NT_HEADERS32*>(image+reinterpret_cast<IMAGE_DOS_HEADER*>(image)->e_lfanew);
    auto sections=IMAGE_FIRST_SECTION(nt);
    for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i) {
        if(strncmp(reinterpret_cast<const char*>(sections[i].Name),".rdata",8)) continue;
        begin=reinterpret_cast<U*>(image+sections[i].VirtualAddress);
        end=begin+sections[i].Misc.VirtualSize/4;
        return true;
    }
    return false;
}
static unsigned VisualHits(U** first) {
    U *begin=nullptr,*end=nullptr;
    if(first) *first=nullptr;
    if(!RdataWords(begin,end)) return 0;
    unsigned hits=0;
    for(U* p=begin;p<end;++p) if(*p==kVisualOriginalVa+delta) { if(!hits && first) *first=p; ++hits; }
    return hits;
}
// Every visual word except word 13 (live slot metadata, not a work counter) is zero.
static bool AllVisualWorkWordsZero(const ntw2_status& s) {
    for(unsigned i=0;i<32;++i) if(i!=13 && s.visual_words[i]) return false;
    return true;
}

// Terminal scenarios run in child processes (each leaves the runtime FAILED for the life of its process): the slot scan finding zero
// or several original-value words refuses activation with runtime error 13 (detail = hit count) without touching any slot, and a
// foreign value in the published slot makes stop refuse restoration (error 6) without overwriting the foreign value.
static int VisualFixture(const char* mode,ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    const bool zero=!strcmp(mode,"--visual-scan-zero"), multiple=!strcmp(mode,"--visual-scan-multiple"), stopConflict=!strcmp(mode,"--visual-stop-conflict");
    if(!zero && !multiple && !stopConflict) { fprintf(stderr,"unknown child mode %s\n",mode); return 2; }
    const U original=kVisualOriginalVa+delta, foreign=A(reinterpret_cast<void*>(&ForeignWorker));
    U* slot=nullptr; U* extra=nullptr;
    Check(VisualHits(&slot)==1 && slot && *slot==original && ReadOnly(slot),"visual fixture: exactly one pristine read-only slot");
    if(!slot) return 1;
    config.enabled_mask=NTW2_VISUAL; config.main_thread_id=0; config.workers=0;
    if(zero) {
        Check(Replace(slot,foreign) && VisualHits(nullptr)==0,"scan fixture: no word holds the original");
    }
    if(multiple) {
        U *begin=nullptr,*end=nullptr;
        Check(RdataWords(begin,end),".rdata section found");
        for(U* p=begin;p && p<end;++p) if(!*p) { extra=p; break; }
        Check(extra && Replace(extra,original) && VisualHits(nullptr)==2,"scan fixture: a second word holds the original");
    }
    Check(start(&config)==0,"visual start accepted");
    ntw2_status snapshot={};
    if(stopConflict) {
        Check(WaitActive(state,NTW2_VISUAL),"visual became active for the stop conflict");
        Check(*slot!=original && ReadOnly(slot) && Replace(slot,foreign),"foreign value replaces the published visual slot");
        Check(stop(nullptr)!=0,"stop reports refused visual restoration");
        Check(*slot==foreign && ReadOnly(slot),"stop does not overwrite the foreign visual value");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED && snapshot.error==kSlotConflict,"foreign-value stop refusal is runtime error 6");
        Check(start(&config)!=0,"failed restoration prevents restart");
        Replace(slot,original);
    } else {
        bool failed=false;
        for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
            if(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED) { failed=true; break; }
        Check(failed,"visual slot scan refusal published");
        Check(failed && snapshot.error==kVisualScanError && snapshot.error_detail==(zero ? 0u : 2u) && !snapshot.active_mask,"scan refusal is error 13 with the hit count as detail");
        Check(failed && AllVisualWorkWordsZero(snapshot),"no visual work counter after a refused scan");
        if(zero) Check(*slot==foreign && ReadOnly(slot),"zero-hit scan touched no slot");
        else Check(*slot==original && ReadOnly(slot) && *extra==original && ReadOnly(extra),"multiple-hit scan published no hook into either word");
        Check(start(&config)!=0,"refused scan prevents restart");
        Check(stop(nullptr)==0,"stop after a refused scan is clean");
        Replace(slot,original);
        if(extra) Replace(extra,0);
    }
    printf("native host lifecycle (visual %s): checks=%u failures=%u\n",mode+2,checks,failures);
    return failures ? 1 : 0;
}

// Terminal scenario run in a child process (a refused install leaves the runtime FAILED for the life of its process): the last of the
// 23 slots holds a foreign hook before start, so the install must be refused, every slot published before it rolled back, and the
// foreign hook never overwritten.
static int InstallConflict(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    U* cells[NTW2_BRAIN_SLOTS];
    for(unsigned i=0;i<NTW2_BRAIN_SLOTS;++i) cells[i]=At(kBrain[i].table+0x0c);
    const unsigned bad=NTW2_BRAIN_SLOTS-1;
    const U foreign=A(reinterpret_cast<void*>(&ForeignWorker));
    U* task=At(0x132e954); U* walk=At(0x133e2dc);
    Check(*cells[bad]==kBrain[bad].original+delta && ReadOnly(cells[bad]) && Replace(cells[bad],foreign),"foreign hook installed in the last brain slot");
    config.enabled_mask=NTW2_PROFILE|NTW2_BRAIN; config.main_thread_id=GetCurrentThreadId();
    Check(start(&config)==0,"brain start accepted for the foreign-slot scenario");
    ntw2_status snapshot={};
    bool failed=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
        if(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED) { failed=true; break; }
    Check(failed,"a brain slot that does not hold the expected original is refused");
    Check(failed && snapshot.error==kSlotConflict && snapshot.error_detail==A(cells[bad]) && !snapshot.active_mask,"slot conflict names the foreign slot");
    bool rolledBack=true;
    for(unsigned i=0;i<bad;++i) rolledBack=rolledBack && *cells[i]==kBrain[i].original+delta && ReadOnly(cells[i]);
    Check(rolledBack,"every brain slot published before the refusal was restored read-only");
    Check(*cells[bad]==foreign && ReadOnly(cells[bad]),"the foreign hook was not overwritten");
    Check(*task==0x5cc390+delta && ReadOnly(task) && *walk==0x702bb0+delta && ReadOnly(walk),"task and planner slots rolled back");
    Check(failed && AllBrainWordsZero(snapshot),"no brain counter without work");
    Check(failed && AllCollisionWordsZero(snapshot),"no collision counter without work");
    Check(start(&config)!=0,"failed install prevents restart");
    Check(stop(nullptr)==0,"stop after a refused install is clean");
    Replace(cells[bad],kBrain[bad].original+delta);
    printf("native host lifecycle (brain install conflict): checks=%u failures=%u\n",checks,failures);
    return failures ? 1 : 0;
}
static int AllocatorFailureFixture(bool ai,U faultMode,ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    static uint8_t manager[0x100]={};
    Put(model,0xB0,A(manager));
    root[0x2829c]=ai ? 1 : 0;
    config.enabled_mask=NTW2_VISUAL|(ai ? NTW2_AI_ASYNC : 0);
    config.workers=2;
    U* visual=nullptr;
    Check(VisualHits(&visual)==1 && visual,"allocator refusal fixture finds the visual slot");
    if(!visual) return 1;
    const U original=*visual;
    InterlockedExchange(&allocatorProbeFault,static_cast<LONG>(faultMode));
    Check(start(&config)==0,"allocator refusal start accepted for asynchronous admission");
    ntw2_status snapshot={};
    bool failed=false;
    const ULONGLONG deadline=GetTickCount64()+3000;
    do {
        if(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED) { failed=true; break; }
        Sleep(1);
    } while(GetTickCount64()<deadline);
    const U row=ai ? NTW2_ALLOCATOR_THREADS-1 : 0;
    const U result=faultMode==1 ? 0x103u : 0x105u;
    Check(failed && snapshot.error==NTW2_ERROR_ALLOCATOR && snapshot.error_detail==((row<<16)|result),
          "allocator SEH has a distinct admission error and worker index");
    Check(!snapshot.active_mask && *visual==original && ReadOnly(visual),"failed admission publishes no visual hook");
    Check(snapshot.allocator_words[row*NTW2_ALLOCATOR_ROW_WORDS]==result &&
          snapshot.allocator_words[row*NTW2_ALLOCATOR_ROW_WORDS+4]==EXCEPTION_ACCESS_VIOLATION,
          "allocator stage and exception survive failed startup unwind");
    if(!ai) Check(snapshot.allocator_words[NTW2_ALLOCATOR_ROW_WORDS]==result,"every created pool worker reports its failed probe");
    Check(!snapshot.crash_words[0],"caught admission fault is not reported as a gameplay crash");
    Check(stop(nullptr)==0,"failed allocator admission joins its workers");
    printf("native host lifecycle (allocator %s refusal): checks=%u failures=%u\n",ai ? "AI" : "pool",checks,failures);
    return failures ? 1 : 0;
}
alignas(8) static volatile LONG64 virtualAvailOverride;
static volatile LONG virtualMemoryCalls, virtualLowAfter;
static BOOL WINAPI TestMemoryStatus(LPMEMORYSTATUSEX memory) {
    if(!GlobalMemoryStatusEx(memory)) return FALSE;
    const LONG call=InterlockedIncrement(&virtualMemoryCalls);
    const LONG lowAfter=InterlockedCompareExchange(&virtualLowAfter,0,0);
    memory->ullAvailVirtual=lowAfter && call>=lowAfter ? 511ull<<20 :
        static_cast<ULONGLONG>(InterlockedCompareExchange64(&virtualAvailOverride,0,0));
    return TRUE;
}
static ULONGLONG MemoryValue(const ntw2_status& state,U at) {
    return state.memory_words[at] | (static_cast<ULONGLONG>(state.memory_words[at+1])<<32);
}
static int VirtualBudgetFixture(bool post,ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    U* import=ModuleImport(runtimeModule,"GlobalMemoryStatusEx");
    Check(import!=nullptr,"runtime exposes actual GlobalMemoryStatusEx admission seam");
    if(!import) return 1;
    const U original=*import;
    Check(Replace(import,A(reinterpret_cast<void*>(&TestMemoryStatus))),"install bounded-VA memory query fixture");
    InterlockedExchange64(&virtualAvailOverride,2ll<<30);
    InterlockedExchange(&virtualMemoryCalls,0); InterlockedExchange(&virtualLowAfter,0);
    root[0x2829c]=1; config.enabled_mask=NTW2_BATCH64; config.workers=0;
    Check(start(&config)==0 && WaitActive(state,NTW2_BATCH64),"ample VA admits the original workload");
    ntw2_status snapshot={};
    Check(ReadState(state,snapshot) && MemoryValue(snapshot,NTW2_MEM_ACTIVATION_AVAIL_LO)==2ull<<30 &&
          MemoryValue(snapshot,NTW2_MEM_POST_ALLOC_AVAIL_LO)==2ull<<30,"activation and post-reservation VA are measured separately");
    InterlockedExchange64(&virtualAvailOverride,3ll<<29);
    bool sampled=false;
    for(const ULONGLONG end=GetTickCount64()+2500;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && MemoryValue(snapshot,NTW2_MEM_MIN_AVAIL_LO)==3ull<<29) { sampled=true; break; }
    Check(sampled && snapshot.memory_words[NTW2_MEM_SAMPLES]>=4,"periodic memory sampling records a decreasing available-VA minimum");
    Check(stop(nullptr)==0,"periodic memory fixture stops");
    // Admission failure is terminal for this DLL lifetime. Each refusal mode
    // runs in its own child rather than restarting a Failed runtime.
    if(!failures) {
        InterlockedExchange64(&virtualAvailOverride,post ? 2ll<<30 : 511ll<<20);
        InterlockedExchange(&virtualMemoryCalls,0);
        // Activation floor, thread reserve, collision reserve, and movement
        // reserve pass; pressure arrives at the final pre-publication check.
        InterlockedExchange(&virtualLowAfter,post ? 5 : 0);
        config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE; config.workers=2;
        config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID_VERIFY;
        BindLocoScene(true);
        Check(start(&config)==0,"low-VA admission is monitored asynchronously");
        bool failed=false;
        for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
            if(ReadState(state,snapshot)) {
                PumpActivation(snapshot);
                if(snapshot.phase==NTW2_FAILED) { failed=true; break; }
            }
        Check(failed && snapshot.error==NTW2_ERROR_VA_BUDGET && !snapshot.active_mask &&
              snapshot.memory_words[NTW2_MEM_BUDGET_REFUSALS]==1,"low VA refuses activation without enabling a feature epoch");
        Check(MemoryValue(snapshot,post ? NTW2_MEM_POST_ALLOC_AVAIL_LO : NTW2_MEM_ACTIVATION_AVAIL_LO)==511ull<<20,
              "the failing available-VA sample is retained exactly");
        Check((snapshot.memory_words[NTW2_MEM_LOCO_BYTES]>0)==(post!=0) &&
              (snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES]>0)==(post!=0),
              "post-allocation refusal records owned bytes; early refusal reserves no workload arenas");
        U* task=At(0x132e954);
        Check(*task==0x5cc390+delta && ReadOnly(task),"VA refusal restores the task slot and native fallback");
        Check(stop(nullptr)==0 && activationBoundary(model)==0,"VA refusal drains contexts and stops cleanly");
    }
    Check(Replace(import,original),"restore real memory query import");
    printf("native host lifecycle (VA budget %s): checks=%u failures=%u\n",post ? "post-allocation" : "early",checks,failures);
    return failures ? 1 : 0;
}
static int PeriodicBudgetFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    U* import=ModuleImport(runtimeModule,"GlobalMemoryStatusEx");
    Check(import!=nullptr,"runtime exposes periodic available-VA seam");
    if(!import) return 1;
    const U original=*import, owned=NTW2_LOCO|NTW2_COLLIDE;
    Check(Replace(import,A(reinterpret_cast<void*>(&TestMemoryStatus))),"install periodic VA pressure fixture");
    InterlockedExchange64(&virtualAvailOverride,2ll<<30);
    InterlockedExchange(&virtualMemoryCalls,0); InterlockedExchange(&virtualLowAfter,0);
    root[0x2829c]=1; BindLocoScene(true);
    config.enabled_mask=NTW2_BATCH64|owned; config.workers=2;
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID_VERIFY;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"periodic pressure starts real owned modules plus an unrelated feature");
    ntw2_status before={}, snapshot={};
    Check(ReadState(state,before),"capture allocated owned storage before pressure");
    U breakdown=0;
    for(U i=NTW2_MEM_LOCO_MOVEMENT_BYTES;i<=NTW2_MEM_LOCO_ENV_SCRATCH_BYTES;++i) breakdown+=before.memory_words[i];
    Check(before.memory_words[NTW2_MEM_LOCO_BYTES]>0 && before.memory_words[NTW2_MEM_COLLIDE_BYTES]>0 &&
          breakdown==before.memory_words[NTW2_MEM_LOCO_BYTES],"LOCO categories exactly reconcile with actual reserved storage");
    Check(before.memory_words[NTW2_MEM_NATIVE_GRID_SHIFT]==5 &&
          before.memory_words[NTW2_MEM_NATIVE_GRID_MAXIMUM]==31 &&
          before.memory_words[NTW2_MEM_NATIVE_GRID_DIMENSION]==32 &&
          before.memory_words[NTW2_MEM_CELL_CAPACITY]==1024,"grid capacity and dimensions come from the captured native header");
    U catalogBytes=0;
    for(U i=NTW2_MEM_LOCO_CATALOG_RING_BYTES;i<=NTW2_MEM_LOCO_CATALOG_POLYGON_BYTES;++i) catalogBytes+=before.memory_words[i];
    Check(catalogBytes==before.memory_words[NTW2_MEM_LOCO_CATALOG_BYTES],"catalog backing categories reconcile with its retained allocation");
    InterlockedExchange64(&virtualAvailOverride,511ll<<20);
    bool retired=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.memory_words[NTW2_MEM_BUDGET_RELEASES]==1) { retired=true; break; }
    Check(retired && snapshot.phase==NTW2_ACTIVE && snapshot.active_mask==NTW2_BATCH64 && !snapshot.error,
          "periodic low VA disables only owned stages without failing unrelated features");
    Check(snapshot.memory_words[NTW2_MEM_BUDGET_REFUSALS]==1 &&
          snapshot.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK]==owned &&
          !snapshot.memory_words[NTW2_MEM_BUDGET_RELEASE_PENDING] &&
          MemoryValue(snapshot,NTW2_MEM_MIN_AVAIL_LO)==511ull<<20,"pressure latches one exact budget refusal and completes quiescent retirement");
    Check(!snapshot.memory_words[NTW2_MEM_LOCO_BYTES] && !snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES] &&
          snapshot.memory_words[NTW2_MEM_RELEASED_LOCO_BYTES]==before.memory_words[NTW2_MEM_LOCO_BYTES] &&
          snapshot.memory_words[NTW2_MEM_RELEASED_COLLIDE_BYTES]==before.memory_words[NTW2_MEM_COLLIDE_BYTES],
          "retirement releases both real module arenas and records exact released sizes");
    for(U i=NTW2_MEM_LOCO_MOVEMENT_BYTES;i<=NTW2_MEM_LOCO_TREE_ENTRIES;++i)
        Check(snapshot.memory_words[i]==before.memory_words[i],"retirement retains allocation attribution");
    for(U i=NTW2_MEM_NATIVE_GRID_SHIFT;i<=NTW2_MEM_LOCO_CATALOG_POLYGON_POINTS;++i)
        Check(snapshot.memory_words[i]==before.memory_words[i],"retirement retains header and distinct catalog geometry attribution");
    Check(*At(0x1345374)!=0x78bac0+delta && ReadOnly(At(0x1345374)),"unrelated batch hook survives owned retirement");
    const U samples=snapshot.memory_words[NTW2_MEM_SAMPLES];
    InterlockedExchange64(&virtualAvailOverride,2ll<<30);
    bool recovered=false;
    for(const ULONGLONG end=GetTickCount64()+2500;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.memory_words[NTW2_MEM_SAMPLES]>samples) { recovered=true; break; }
    Check(recovered && snapshot.active_mask==NTW2_BATCH64 &&
          snapshot.memory_words[NTW2_MEM_BUDGET_REFUSALS]==1 && snapshot.memory_words[NTW2_MEM_BUDGET_RELEASES]==1 &&
          !snapshot.memory_words[NTW2_MEM_LOCO_BYTES] && !snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES],
          "restored VA does not silently re-enable or reallocate retired stages");
    Check(snapshot.loco_owned_load_words[0]==1,"retired owned activation counters survive later monitoring samples");
    root[0x2829c]=0;
    bool waiting=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE) { waiting=true; break; }
    Check(waiting,"budget fallback can leave the current battle normally");
    root[0x2829c]=1;
    Check(WaitActive(state,NTW2_BATCH64) && ReadState(state,snapshot) &&
          snapshot.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK]==owned &&
          !snapshot.memory_words[NTW2_MEM_LOCO_BYTES] && !snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES],
          "a new battle generation preserves the sticky native fallback");
    Check(stop(nullptr)==0,"periodic fallback stops cleanly");
    Put(locoGrid,0x14,15); // valid 16-by-16 coordinates with native row stride 32
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask) && ReadState(state,snapshot) &&
          !snapshot.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK] && !snapshot.memory_words[NTW2_MEM_BUDGET_REFUSALS] &&
          snapshot.memory_words[NTW2_MEM_LOCO_BYTES]>0 && snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES]>0,
          "explicit runtime restart clears the latch and admits owned stages again");
    Check(snapshot.memory_words[NTW2_MEM_NATIVE_GRID_SHIFT]==5 &&
          snapshot.memory_words[NTW2_MEM_NATIVE_GRID_MAXIMUM]==15 &&
          snapshot.memory_words[NTW2_MEM_NATIVE_GRID_DIMENSION]==16 &&
          snapshot.memory_words[NTW2_MEM_CELL_CAPACITY]==496,"header sizing preserves native row-stride padding without a fixed million-cell reserve");
    Check(stop(nullptr)==0,"restarted periodic fixture stops cleanly");
    Check(Replace(import,original),"restore real memory query after periodic pressure");
    printf("native host lifecycle (periodic VA retirement): checks=%u failures=%u\n",checks,failures);
    return failures ? 1 : 0;
}
// Owned services with no real scene at the quiescent boundary: activation refuses,
// restores the temporary disabled task route and never enables a feature epoch.
static int LocoOwnedActivationRefusalFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    U* taskSlot=At(0x132e954);
    const U taskOriginal=0x5cc390+delta;
    root[0x2829c]=1; BindLocoScene(false);
    config.enabled_mask=NTW2_LOCO; config.workers=2; config.main_thread_id=0;
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES;
    Check(start(&config)==0,"owned activation refusal start accepted for asynchronous admission");
    ntw2_status snapshot={};
    bool failed=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
        if(ReadState(state,snapshot)) {
            PumpActivation(snapshot);
            if(snapshot.phase==NTW2_FAILED) { failed=true; break; }
        }
    Check(failed && snapshot.error==5u && snapshot.error_detail==NTW2_LOCO && !snapshot.active_mask,"missing owned scene fails activation as module error 5 for LOCO");
    Check(*taskSlot==taskOriginal && ReadOnly(taskSlot),"refused owned activation restores the temporary tick route");
    Check(failed && snapshot.loco_owned_load_words[0]==1u && snapshot.loco_owned_load_words[9]==0u,
          "refused activation publishes load metadata and no tick ever ran");
    Check(snapshot.loco_owned_load_words[12]==12u && snapshot.loco_owned_load_words[13]==EXCEPTION_ACCESS_VIOLATION,
          "missing scene reports scene-capture phase and exact access violation");
    Check(stop(nullptr)==0,"refused owned activation stops cleanly");
    printf("native host lifecycle (owned activation refusal): checks=%u failures=%u\n",checks,failures);
    return failures ? 1 : 0;
}
static int VisualArenaFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    const struct { U va; const void* fn; } redirects[]={
        {0x75d280,reinterpret_cast<const void*>(&TestArenaPrepare)},
        {0x611a60,reinterpret_cast<const void*>(&TestAnimationOwner)},
        {0x7911e0,reinterpret_cast<const void*>(&TestArenaPose)},
        {0x10d3140,reinterpret_cast<const void*>(&TestArenaBacking)},
        {0x4c3900,reinterpret_cast<const void*>(&TestArenaEnter)},
        {0x4c3a00,reinterpret_cast<const void*>(&TestArenaLeave)},
        {0x7c5990,reinterpret_cast<const void*>(&TestArenaResize)},
        {0x708870,reinterpret_cast<const void*>(&TestArenaTail)}};
    for(const auto& redirect:redirects) Check(RedirectImage(redirect.va,redirect.fn),"install native-arena owned-process adapter");
    arenaOwnerMethods[1]=A(reinterpret_cast<const void*>(&TestRootArena));
    arenaOwner[0]=A(arenaOwnerMethods);
    arenaEntityMethods[7]=A(reinterpret_cast<const void*>(&TestArenaVirtualZero));
    Put(arenaEntity,0,A(arenaEntityMethods));
    Put(arenaContext,4,A(root)); Put(arenaContext,0x2c,A(arenaList));
    Put(arenaSelf,0xec,A(arenaContext)); Put(arenaSelf,0xf8,kArenaItems);
    for(U i=0;i<kArenaItems;++i) {
        arenaItems[i][2]=A(arenaEntity); arenaItems[i][5]=A(arenaPose);
        arenaRecords[i][0]=A(arenaItems[i]); arenaList[i]=A(arenaRecords[i]);
    }
    for(U i=0;i<3;++i) {
        U* arena=reinterpret_cast<U*>(ArenaAddress(i));
        arena[0x28/4]=NTW2_ALLOCATOR_THREADS; arena[0x30/4]=A(arenaBuckets[i]);
        InitializeCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(ArenaAddress(i)+0x34));
    }
    U* slot=nullptr;
    Check(VisualHits(&slot)==1 && slot,"native-arena fixture finds visual slot");
    config.enabled_mask=NTW2_VISUAL; config.workers=2;
    root[0x2829c]=0;
    arenaOverlap=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    Check(arenaOverlap!=nullptr,"create the three-participant overlap barrier");
    U maxDispatchUs=0;
    LARGE_INTEGER frequency={};
    QueryPerformanceFrequency(&frequency);
    Check(start(&config)==0 && WaitActive(state,NTW2_VISUAL),"native arena fixture activates");
    if(slot && !failures) {
        for(U tick=0;tick<2;++tick) {
            arenaContext[0x16c]=0;
            ResetEvent(arenaOverlap);
            arenaArrivals=0;
            for(U i=0;i<NTW2_ALLOCATOR_THREADS;++i) arenaArrived[i]=0;
            LARGE_INTEGER begin,finish;
            QueryPerformanceCounter(&begin);
            reinterpret_cast<void (__fastcall*)(void*,void*,U)>(*slot)(arenaSelf,nullptr,0);
            QueryPerformanceCounter(&finish);
            const U elapsed=static_cast<U>((finish.QuadPart-begin.QuadPart)*1000000/frequency.QuadPart);
            if(elapsed>maxDispatchUs) maxDispatchUs=elapsed;
            Check(elapsed<1000000,"256-item native-arena dispatch completes below one second without injected timer delays");
        }
        ntw2_status snapshot={};
        const ULONGLONG deadline=GetTickCount64()+3000;
        do {
            // calls counts entries, not completions. A sequence-consistent monitor snapshot can be mid-call.
            if(ReadState(state,snapshot) && snapshot.visual_words[1]+snapshot.visual_words[2]==2) break;
            Sleep(1);
        } while(GetTickCount64()<deadline);
        Check(snapshot.visual_words[1]==2 && snapshot.visual_words[8]==0 && snapshot.visual_words[14]==2,
              "native arenas shard both calls without faults");
        Check(arenaCalls==2*kArenaItems && !arenaProblems && arenaSeen==7,
              "native arena slots are bounded, thread-exclusive and preserve every concurrent output");
        Check(arenaResets==2 && arenaTails==2,"one main-thread reset per call; native serial tail sees restored arenas");
    }
    Check(stop(nullptr)==0,"native arena fixture joins before releasing backing chunks");
    if(arenaOverlap) { CloseHandle(arenaOverlap); arenaOverlap=nullptr; }
    for(U i=0;i<3;++i) {
        U chunk=*reinterpret_cast<U*>(ArenaAddress(i));
        while(chunk) {
            const U next=*reinterpret_cast<U*>(chunk+0xf4240);
            HeapFree(GetProcessHeap(),0,reinterpret_cast<void*>(chunk)); chunk=next;
        }
        DeleteCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(ArenaAddress(i)+0x34));
    }
    printf("native host lifecycle (per-worker native arenas): checks=%u failures=%u max_dispatch_us=%u\n",checks,failures,maxDispatchUs);
    return failures ? 1 : 0;
}
// Synthetic native planner: retain an element pointer in a native frame past the former 40 ms cap.
// Destruction changes that receiver's virtual table and owner link between tick boundaries.
// A stale dispatch is observable without freeing the fixture's storage or suppressing a real purecall.
struct AiFakeUnit { U* vtable; void* owner; };
struct AiFakePlanner { AiFakeUnit* units[2]; U count, delayMs, calls, dispatches, flags, thread; };
static volatile LONG aiFakeStale;
static void __fastcall AiFakeLive(AiFakeUnit* unit,void*) {
    if(!unit->owner) { InterlockedIncrement(&aiFakeStale); return; }
    ++static_cast<AiFakePlanner*>(unit->owner)->dispatches;
}
static void __fastcall AiFakeDestroyed(AiFakeUnit*,void*) { InterlockedIncrement(&aiFakeStale); }
static void __fastcall AiFakeThink(AiFakePlanner* planner,void*,U flag) {
    AiFakeUnit* cached[2]={planner->units[0],planner->units[1]};
    const U count=planner->count;
    planner->flags=(planner->flags<<1)|(flag&1u);
    planner->thread=GetCurrentThreadId();
    Sleep(planner->delayMs);
    for(U i=0;i<count;++i)
        reinterpret_cast<void (__fastcall*)(AiFakeUnit*,void*)>(cached[i]->vtable[10])(cached[i],nullptr);
    ++planner->calls;
}
static int AiCompletionFixture(bool controller,ntw2_start_fn start,ntw2_stop_fn stop,
                               volatile ntw2_status* state,ntw2_config config) {
    auto boundary=reinterpret_cast<ntw2_ai_boundary_fn>(GetProcAddress(runtimeModule,"ntw2_ai_boundary"));
    Check(boundary!=nullptr,"AI lifecycle completion boundary export exists");
    root[0x2829c]=1; Put(model,0xB0,A(armyManager));
    config.enabled_mask=NTW2_AI_ASYNC|(controller ? NTW2_AI_CTRL : 0);
    config.workers=0;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"AI completion fixture activates");
    // Redirect only the oracle's private image, after clone byte validation. No installed executable is patched.
    Check(RedirectImage(0x7D99F0,reinterpret_cast<const void*>(&AiFakeThink)),"install synthetic planner in owned image");
    U live[11]={}, destroyed[11]={};
    live[10]=A(reinterpret_cast<void*>(&AiFakeLive)); destroyed[10]=A(reinterpret_cast<void*>(&AiFakeDestroyed));
    AiFakePlanner planner={}; AiFakeUnit first={live,&planner}, second={live,&planner};
    planner.units[0]=&first; planner.units[1]=&second; planner.count=2; planner.delayMs=80;
    const U owner=GetCurrentThreadId();
    if(boundary && !failures) {
        Check(boundary(model+4,&planner,1)==0,"foreign model cannot dispatch AI work");
        Check(boundary(model,&planner,1)==1,"first native call is admitted in its own tick");
        Check(planner.calls==1 && planner.dispatches==2 && planner.thread!=owner,
              "long native call finishes on worker before tick boundary returns");
        // Combat/cleanup in the next tick unlinks the unit, rewrites its vtable and clears its backlink.
        planner.units[1]=nullptr; planner.count=1;
        second.vtable=destroyed; second.owner=nullptr;
        planner.delayMs=12;
        Check(boundary(model,&planner,0)==1,"next tick runs a fresh native frame with the changed list");
        Check(planner.calls==2 && planner.dispatches==3 && planner.flags==2 && !aiFakeStale,
              "subordinate destruction between ticks never causes stale slot +0x28 dispatch");
    }
    Check(stop(nullptr)==0,"AI completion fixture joins before teardown");
    ntw2_status snapshot={};
    Check(ReadState(state,snapshot),"AI completion telemetry remains readable after stop");
    U thinks=0, barriers=0, longThinks=0;
    for(U i=0;i<9;++i) {
        thinks+=snapshot.ai_completion_words[6+i];
        barriers+=snapshot.ai_completion_words[15+i];
        if(i>=4) longThinks+=snapshot.ai_completion_words[6+i];
    }
    Check(thinks==2 && barriers==2 && snapshot.ai_completion_words[0]==2 &&
          snapshot.ai_completion_words[3]==2,"each completed native call and boundary records one histogram bucket");
    Check(longThinks>=1 && snapshot.ai_completion_words[2]>=80000 &&
          snapshot.ai_words[6]==snapshot.ai_completion_words[2],"duration histogram measures calls beyond the former slice cap");
    Check(!snapshot.ai_slice_words[3] && snapshot.ai_slice_words[4]==1 &&
          !snapshot.ai_slice_words[6] && !snapshot.ai_slice_words[7] && !aiFakeStale,
          "no native job spans ticks and no suspended worker survives teardown");
    printf("AI completion fixture: max_planner_us=%u max_barrier_us=%u think_hist=",
           snapshot.ai_completion_words[2],snapshot.ai_completion_words[5]);
    for(U i=6;i<15;++i) printf("%s%u",i==6 ? "" : ",",snapshot.ai_completion_words[i]);
    printf(" barrier_hist=");
    for(U i=15;i<24;++i) printf("%s%u",i==15 ? "" : ",",snapshot.ai_completion_words[i]);
    printf(" stale_dispatches=%ld\n",aiFakeStale);
    return failures ? 1 : 0;
}

static int GridCensusFixture(bool lateEnable,ntw2_start_fn start,ntw2_stop_fn stop,
                             volatile ntw2_status* state,ntw2_config config) {
    auto profile=reinterpret_cast<volatile ntw2_profile_status*>(GetProcAddress(runtimeModule,"ntw2_profile"));
    Check(profile!=nullptr,"canonical profiler export present for grid census");
    U* taskSlot=At(0x132e954);
    const U taskOriginal=*taskSlot;
    root[0x2829c]=1; BindLocoScene(true);
    ntw2_status snapshot={};
    if(lateEnable) {
        config.enabled_mask=NTW2_LOCO;
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"build resident clones with census disabled");
        Check(stop(nullptr)==0,"stop disabled-first generation");
        config.enabled_mask|=NTW2_GRID_CENSUS; config.main_thread_id=GetCurrentThreadId();
        Check(start(&config)==0,"late census request reaches asynchronous clone admission");
        bool refused=false;
        for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
            if(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED) { refused=true; break; }
        Check(refused && snapshot.error && snapshot.error_detail==0x7f000001u && !snapshot.active_mask,
              "late census enable refuses non-instrumented resident clones rather than claiming coverage");
        Check(stop(nullptr)==0 && *taskSlot==taskOriginal && ReadOnly(taskSlot),
              "late census refusal leaves the original tick slot intact");
        return failures ? 1 : 0;
    }
    struct Cycle { U mask, flags, workers; };
    const Cycle cycles[]={
        {NTW2_LOCO|NTW2_GRID_CENSUS,0,0},
        {NTW2_LOCO,0,0},
        {NTW2_LOCO|NTW2_GRID_CENSUS,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL,2},
        {NTW2_LOCO|NTW2_PROFILE|NTW2_GRID_CENSUS,NTW2_LOCO_CLONE,1},
        {NTW2_BATCH64,0,0}
    };
    for(U i=0;i<2*(sizeof(cycles)/sizeof(cycles[0])) && !failures;++i) {
        const auto& c=cycles[i%(sizeof(cycles)/sizeof(cycles[0]))];
        config.enabled_mask=c.mask; config.loco_flags=c.flags; config.workers=c.workers;
        config.main_thread_id=(c.mask&(NTW2_PROFILE|NTW2_GRID_CENSUS)) ? GetCurrentThreadId() : 0;
        Check(start(&config)==0 && WaitActive(state,c.mask),"census-first mixed cycle activates exactly the requested mask");
        Check(ReadState(state,snapshot) && snapshot.requested_mask==c.mask &&
              GridCensusWithoutCalls(snapshot,(c.mask&NTW2_GRID_CENSUS)!=0),
              "census metadata is bounded, route/entry counts stay zero without work, and disabled starts clear the tail");
        if(c.mask&NTW2_GRID_CENSUS)
            Check(profile && profile->abi==NTW2_PROFILE_ABI && profile->size==sizeof(ntw2_profile_status) &&
                  profile->hist_va && profile->tick_hist_va,
                  "census-only starts canonical sampler storage without setting PROFILE");
        Check(stop(nullptr)==0 && *taskSlot==taskOriginal && ReadOnly(taskSlot),
              "census cycle stops sampler and restores the tick route");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask &&
              GridCensusWithoutCalls(snapshot,(c.mask&NTW2_GRID_CENSUS)!=0),
              "census stop retains metadata and zero route/entry counts, never treating occupancy as calls");
    }
    return failures ? 1 : 0;
}

// ---- NTW2_AI_CENSUS: pinned vtable-slot gates + AI_CONTROLLER clone-call gate, in the owned (relocated) image --------------------------
// Same table as src/ntw2_ai_census.cpp, restated here from the audited image scan: delegate replacement virtual 0x6EA520 is slot 19 of five
// vtables, its sibling 0x6B3010 slot 20 of three; observer vtables 0x13432A0/0x1343318 slot 0 hold the `ret 4` no-op 0x44A780; delegate
// destructors 0x69D710/0x69D750 are slot 0 of 0x13376FC/0x13376AC.
struct CensusPin { U vtable, slot, original, target; };
static const CensusPin kCensusPins[12]={
    {0x13378F8,19,0x6EA520,0},{0x1337998,19,0x6EA520,0},{0x1337BB8,19,0x6EA520,0},{0x1337C30,19,0x6EA520,0},{0x1349C18,19,0x6EA520,0},
    {0x1337BB8,20,0x6B3010,1},{0x1337C30,20,0x6B3010,1},{0x1349C18,20,0x6B3010,1},
    {0x13432A0,0,0x44A780,2},{0x1343318,0,0x44A780,3},{0x13376FC,0,0x69D710,4},{0x13376AC,0,0x69D750,5}};
static const U kCensusTargetOriginal[7]={0x6EA520,0x6B3010,0x44A780,0x44A780,0x69D710,0x69D750,0x7492F0};
constexpr U kCensusHeaderWords=16, kCensusTargetWords=104, kCensusRangeBase=16+7*104;
static U* CensusCell(unsigned i) { return At(kCensusPins[i].vtable+4*kCensusPins[i].slot); }
// The observer slot-0 original is `ret 4`: calling through the (gated) slot is harmless in the owned image.
static void CallNoop(U word) { reinterpret_cast<void (__stdcall*)(U)>(static_cast<uintptr_t>(word))(0); }
static U* aiCensusProbeCell;
static void __fastcall AiCensusProbe(AiFakeUnit*,void*) { if(aiCensusProbeCell) CallNoop(*aiCensusProbeCell); }
static DWORD WINAPI CensusHelper(void* cell) { CallNoop(*static_cast<U*>(cell)); return 0; }
// Each gate ends in `jmp dword ptr [abs]`; the cell holds the forwarded original.
static U GateForward(U gate) {
    const uint8_t* p=reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(gate));
    for(unsigned i=0;i<96;++i) if(p[i]==0xFF && p[i+1]==0x25) { U cell; memcpy(&cell,p+i+2,4); return *reinterpret_cast<const U*>(static_cast<uintptr_t>(cell)); }
    return 0;
}
static bool CloneBranch(U clone,U offset,uint8_t opcode,U& target) {
    const uint8_t* p=reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(clone+offset));
    int32_t rel; memcpy(&rel,p+1,4);
    target=clone+offset+5+static_cast<U>(rel);
    return p[0]==opcode;
}
template<class F> static bool WaitFor(volatile ntw2_status* state,ntw2_status& out,F ok) {
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(2))
        if(ReadState(state,out) && ok(out)) return true;
    return false;
}
static int AiCensusFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(runtimeModule,"ntw2_site_callee"));
    auto boundary=reinterpret_cast<ntw2_ai_boundary_fn>(GetProcAddress(runtimeModule,"ntw2_ai_boundary"));
    Check(siteCallee!=nullptr && boundary!=nullptr,"census fixture exports present");
    if(!siteCallee || !boundary) return 1;
    root[0x2829c]=1; Put(model,0xB0,A(armyManager));
    const U controllerOriginal=0x7C8BD0+delta;
    for(unsigned i=0;i<12;++i)
        Check(*CensusCell(i)==kCensusPins[i].original+delta && ReadOnly(CensusCell(i)),"census pin holds the pinned original word and is read-only before start");
    // 1. AI alone never touches a census slot, never clones the controller into the site, and leaves every census word zero.
    config.enabled_mask=NTW2_AI_ASYNC; config.workers=0; config.main_thread_id=GetCurrentThreadId();
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai without census activates");
    for(unsigned i=0;i<12;++i) Check(*CensusCell(i)==kCensusPins[i].original+delta,"ai alone leaves census slots untouched");
    Check(siteCallee(33)==controllerOriginal,"ai alone keeps the original controller callee");
    ntw2_status snapshot={};
    bool zero=ReadState(state,snapshot);
    for(unsigned i=0;i<NTW2_AI_CENSUS_WORDS;++i) zero=zero && !snapshot.ai_census_words[i];
    Check(zero,"census words are all zero without the feature");
    Check(stop(nullptr)==0,"stop ai-only generation");
    // 2. Census generation.
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_CENSUS;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai census activates (sampler thread admitted)");
    U gates[7]={};
    for(unsigned i=0;i<12;++i) {
        const U word=*CensusCell(i);
        Check(word!=kCensusPins[i].original+delta && InRuntime(word) && ReadOnly(CensusCell(i)),"census slot holds a read-only runtime gate");
        const U target=kCensusPins[i].target;
        if(!gates[target]) gates[target]=word;
        Check(gates[target]==word,"every slot of one target holds the same gate");
        Check(GateForward(word)==kCensusTargetOriginal[target]+delta,"gate forwards to the exact pinned original");
    }
    for(unsigned a=0;a<6;++a) for(unsigned b=a+1;b<6;++b) Check(gates[a]!=gates[b],"each target has its own gate");
    const U clone=siteCallee(33);
    U callTarget=0, rebuildGate=0;
    Check(clone!=controllerOriginal && !InRuntime(clone),"census binds the AI_CONTROLLER clone at site 33");
    Check(CloneBranch(clone,0x8A,0xE8,callTarget) && InRuntime(callTarget),"clone call at 0x7C8C5A reaches a runtime gate");
    rebuildGate=callTarget;
    Check(CloneBranch(clone,0xB3,0xE8,callTarget) && callTarget==rebuildGate,"clone call at 0x7C8C83 reaches the same gate");
    Check(GateForward(rebuildGate)==0x7492F0+delta,"rebuild gate forwards to the original planner rebuild 0x7492F0");
    Check(CloneBranch(clone,0x0A,0xE8,callTarget) && callTarget==0x7C8CB0+delta,"other controller calls are untouched direct calls");
    Check(CloneBranch(clone,0x1E,0xE9,callTarget) && callTarget==0x7C8F70+delta,"controller tail jump stays original");
    {
        const uint8_t* jump=reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(clone+0x2F));
        U table; memcpy(&table,jump+3,4);
        bool inside=jump[0]==0xFF && jump[1]==0x24 && jump[2]==0x85 && table==clone+0xBC;
        for(unsigned i=0;i<9 && inside;++i) {
            U entry; memcpy(&entry,reinterpret_cast<const void*>(static_cast<uintptr_t>(table+4*i)),4);
            inside=entry>=clone && entry<clone+0xBC;
        }
        Check(inside,"controller switch table is rebased into the clone");
    }
    Check(WaitFor(state,snapshot,[](const ntw2_status& s){ return s.ai_census_words[0]==1 && s.ai_census_words[7]==12; }),
          "census publishes version 1 with all twelve slots owned");
    Check(snapshot.ai_census_words[1]==7 && snapshot.ai_census_words[2]==256 && snapshot.ai_census_words[4]==8 &&
          snapshot.ai_census_words[8]==12 && snapshot.ai_census_words[9]==3 && snapshot.ai_census_words[5]==0,"census geometry metadata and zero calls before any caller");
    for(unsigned t=0;t<7;++t) {
        const U* row=snapshot.ai_census_words+kCensusHeaderWords+t*kCensusTargetWords;
        U slots=0; for(const CensusPin& pin:kCensusPins) slots+=pin.target==t;
        Check(row[0]==kCensusTargetOriginal[t] && row[1]==slots,"target row names its original and slot count");
    }
    // Calls through the gated slots. Observer slot 0 is a `ret 4` no-op, so the whole call chain is safe in the owned image.
    {   // (a) register/flag/stack preservation from the test thread (class main_render, outside tick).
        U gate=*CensusCell(8), r[6]={}, carry=0;
        __asm {
            pushfd
            pushad
            stc
            mov eax, 0x11111111
            mov ecx, 0x22222222
            mov edx, 0x33333333
            mov ebx, 0x44444444
            mov esi, 0x55555555
            mov edi, 0x66666666
            push 0xABCD
            call dword ptr [gate]
            mov dword ptr [r+0], eax
            mov dword ptr [r+4], ecx
            mov dword ptr [r+8], edx
            mov dword ptr [r+12], ebx
            mov dword ptr [r+16], esi
            mov dword ptr [r+20], edi
            setc byte ptr [carry]
            popad
            popfd
        }
        Check(r[0]==0x11111111 && r[1]==0x22222222 && r[2]==0x33333333 && r[3]==0x44444444 && r[4]==0x55555555 && r[5]==0x66666666 && (carry&0xFF)==1,
              "gate preserves every general register and the flags and forwards ret 4 unchanged");
    }
    // (b) the AI worker, inside a planner job dispatched through the lifecycle boundary.
    U live[11]={}, destroyed[11]={};
    live[10]=A(reinterpret_cast<void*>(&AiCensusProbe)); destroyed[10]=A(reinterpret_cast<void*>(&AiFakeDestroyed));
    Check(RedirectImage(0x7D99F0,reinterpret_cast<const void*>(&AiFakeThink)),"install synthetic planner in owned image");
    AiFakePlanner planner={}; AiFakeUnit unit={live,&planner};
    planner.units[0]=&unit; planner.count=1; planner.delayMs=1;
    aiCensusProbeCell=CensusCell(8);
    Check(boundary(model,&planner,1)==1 && planner.calls==1 && planner.thread!=GetCurrentThreadId(),"synthetic planner runs on the AI worker");
    aiCensusProbeCell=nullptr;
    // (c) an unrelated thread (class other) through observer vtable 0x1343318.
    HANDLE helper=CreateThread(nullptr,0,CensusHelper,CensusCell(9),0,nullptr);
    Check(helper!=nullptr && WaitForSingleObject(helper,3000)==WAIT_OBJECT_0,"helper thread calls through the second observer slot");
    if(helper) CloseHandle(helper);
    Check(WaitFor(state,snapshot,[](const ntw2_status& s){ return s.ai_census_words[5]==3; }),"census publishes the three calls");
    {
        const U* w=snapshot.ai_census_words;
        const U* t2=w+kCensusHeaderWords+2*kCensusTargetWords;
        const U* t3=w+kCensusHeaderWords+3*kCensusTargetWords;
        Check(w[3]==3 && w[6]==0 && w[13]==0 && w[14]==3 && w[12]==0,"three distinct callers, none dropped, all outside any tick");
        Check(t2[2]==2 && t2[3]==0 && t2[4]==1 && t2[5]==1 && t2[6]==0 && t2[7]==0,"observer 0x13432A0: one AI-worker and one main/render call");
        Check(t3[2]==1 && t3[3]==0 && t3[4]==0 && t3[5]==0 && t3[6]==1,"observer 0x1343318: one other-thread call");
        const U exe=A(GetModuleHandleA(nullptr));
        auto nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(exe+reinterpret_cast<const IMAGE_DOS_HEADER*>(static_cast<uintptr_t>(exe))->e_lfanew);
        unsigned rows=0; bool placed=true;
        for(unsigned k=0;k<8;++k) {
            const U* c=t2+8+k*12; // caller rows follow the 8-word target header
            if(!c[2]) continue;
            ++rows;
            placed=placed && c[1]==2 && c[0]>=exe && c[0]-exe<nt->OptionalHeader.SizeOfImage && c[7]==0 && c[8]==c[2] && c[9]==c[2];
        }
        Check(rows==2 && placed,"each caller row names a raw return address inside the test, outside-tick site code 0");
        for(unsigned t=0;t<7;++t) if(t!=2 && t!=3) Check(w[kCensusHeaderWords+t*kCensusTargetWords+2]==0,"untouched targets stay at zero");
    }
    Check(stop(nullptr)==0,"census generation stops");
    for(unsigned i=0;i<12;++i)
        Check(*CensusCell(i)==kCensusPins[i].original+delta && ReadOnly(CensusCell(i)),"stop restores every census word exactly and its read-only protection");
    Check(siteCallee(33)==controllerOriginal,"stop restores the original controller callee");
    Check(ReadState(state,snapshot) && snapshot.ai_census_words[0]==1 && snapshot.ai_census_words[5]==3 && snapshot.ai_census_words[7]==0,
          "final totals are retained after stop with no slot owned");
    return failures ? 1 : 0;
}

// ---- NTW2_AI_ASYNC2 boundary schedule ------------------------------------------------------------------------------------
// Every ntw2_ai_async2_boundary call is one synthetic tick: the blocking tick-start lifetime join, site-34 queueing, a
// tick-side callback, the optional TICK quadtree join and the tick-end publish. The planner 0x7D99F0, the delegate
// destructor 0x69D750 (slot 0 of 0x13376AC, ret 4), the observer owner destructor 0x73E180 (slot 2 of 0x1343318, ret 4)
// and the observer 0x6A95A0 (slot 16 of 0x13376FC, ret 0xC) are redirected in the owned image to probes. No installed
// executable is patched.
struct Ai2Planner { volatile U calls; volatile LONG started; U delayMs, thread, destroyFromWorker, walk; };
struct Ai2Probe { volatile LONG calls; U thread, thinksAtEntry; Ai2Planner* planner; };
static Ai2Probe ai2Probe;
static U* Ai2DestroyCell() { return At(0x13376AC); }
static U* Ai2OwnerCell() { return At(0x1343318+4*2); }
static U* Ai2ObserverCell() { return At(0x13376FC+4*16); }
static void* __fastcall Ai2FakeDestroy(void* self,void*,U) {
    ai2Probe.thread=GetCurrentThreadId();
    ai2Probe.thinksAtEntry=ai2Probe.planner ? ai2Probe.planner->calls : 0;
    InterlockedIncrement(&ai2Probe.calls);
    return self;
}
static void CallDeleting(U* cell) {
    U object=0;
    reinterpret_cast<void* (__fastcall*)(void*,void*,U)>(static_cast<uintptr_t>(*cell))(&object,nullptr,0);
}
static void CallDestroySlot() { CallDeleting(Ai2DestroyCell()); }
static volatile LONG ai2ObserverCalls;
static U ai2ObserverThread[4];
static U __fastcall Ai2FakeObserver(void*,void*,U,U,U) {
    const LONG n=InterlockedIncrement(&ai2ObserverCalls);
    if(n<=4) ai2ObserverThread[n-1]=GetCurrentThreadId();
    return 0;
}
static void CallObserverSlot() {
    U object=0;
    reinterpret_cast<U (__fastcall*)(void*,void*,U,U,U)>(static_cast<uintptr_t>(*Ai2ObserverCell()))(&object,nullptr,1,2,3);
}

// AI-thread private walk vs shared-global mutation. The AI worker, inside a think, runs the real AI2_WALK clone
// (7F1D40 family: AI2_GATHER, AI2_809110, kept originals 7EE620/6DC9A0/448B90/7FA540; vector growth through the owned
// image's 444B40/FF7EF0 fixture) on a synthetic static interest tree while another thread keeps sentinels in the ORIGINAL
// scratch the clones were rebased away from.
// Layouts (recovered from 7F1D40/804DD0/809110/7FA540/7EE620/6DC9A0): walker[0]=obj, obj+8=model, model+0xBC=tree holder,
// [holder+0x24]+0x1C=root node; node +4..+0x18 = min xyz/max xyz, +0x1C interest list, +0x20 four children (leaf: 0);
// interest +0 type (0x10 = owner record), +0xC owner, +0x14 next; owner +8 tag, +0xC vtable (slot 0: live predicate,
// ecx=owner+0xC), +0x1C LOS flag; query[0]=1 = box from the points at +0x28/+0x30/+0x38, query+0x40 mode 2 = report each
// gathered owner with flag 1 through 808F90(query, owner+8) (redirected to a recorder returning 0).
struct Ai2Node { U pad; float minX, minY, minZ, maxX, maxY, maxZ; U list, child[4]; };
struct Ai2Owner { U pad[2]; U tag, vtable, live, pad2[2], los; };
struct Ai2Interest { U type, pad[2], owner, pad2, next; };
static_assert(sizeof(Ai2Node)==0x30 && offsetof(Ai2Node,list)==0x1C && offsetof(Ai2Node,child)==0x20 &&
              offsetof(Ai2Owner,tag)==8 && offsetof(Ai2Owner,vtable)==0xC && offsetof(Ai2Owner,los)==0x1C &&
              offsetof(Ai2Interest,owner)==0xC && offsetof(Ai2Interest,next)==0x14, "synthetic tree layouts");
constexpr U kAi2WalkIterations=2000, kAi2Hits=5;
static const U kAi2ExpectedHits[kAi2Hits]={0x100,0x200,0x302,0x303,0x220};
struct Ai2WalkTest {
    ntw2_ai_async2_private_entry_fn entry;
    U walker[1], query[0x20], aux[8], hits[16];
    volatile U hitCount;
    U walkEntry, observerEntry, badEntry, thread, correct, wrong;
};
static Ai2WalkTest ai2Walk;
static uint8_t ai2WalkObj[0x28200], ai2WalkModel[0x100], ai2WalkHolder[0x40], ai2WalkTreeRef[0x40];
static Ai2Node ai2Nodes[13];
static Ai2Owner ai2Owners[12];
static Ai2Interest ai2Interests[12];
static U ai2OwnerVtable[1];
static bool __fastcall Ai2OwnerLive(const U* sub) { return sub[1]!=0; } // sub = owner+0xC, sub[1] = owner+0x10
static U __fastcall Ai2RecordLos(void*,void*,U ownerTag) {
    const U n=ai2Walk.hitCount;
    if(n<16) ai2Walk.hits[n]=ownerTag;
    ai2Walk.hitCount=n+1;
    return 0; // not blocked: the walk reports every gathered owner
}
static volatile LONG ai2CtorCalls;
static U ai2CtorSelf[8], ai2CtorThread[8];
static U __fastcall Ai2FakeSearchCtor(U self,void*) {
    const LONG n=InterlockedIncrement(&ai2CtorCalls);
    if(n<=8) { ai2CtorSelf[n-1]=self; ai2CtorThread[n-1]=GetCurrentThreadId(); }
    return self;
}
static void Ai2BuildTree() {
    auto node=[](U i,float x0,float z0,float x1,float z1) {
        Ai2Node& n=ai2Nodes[i]; n={}; n.minX=x0; n.minZ=z0; n.maxX=x1; n.maxZ=z1; n.minY=-10; n.maxY=10;
    };
    auto interest=[](U i,U node,U type,U tag,bool live,U los) {
        ai2Owners[i]={}; ai2Owners[i].tag=tag; ai2Owners[i].vtable=A(ai2OwnerVtable); ai2Owners[i].live=live ? 1 : 0; ai2Owners[i].los=los;
        ai2Interests[i]={}; ai2Interests[i].type=type; ai2Interests[i].owner=A(&ai2Owners[i]);
        ai2Interests[i].next=ai2Nodes[node].list; ai2Nodes[node].list=A(&ai2Interests[i]); // push front
    };
    ai2OwnerVtable[0]=A(reinterpret_cast<const void*>(&Ai2OwnerLive));
    enum { R, C0, C1, C2, C3, G0, G1, G2, G3 };
    node(R,0,0,100,100); node(C0,0,0,50,50); node(C1,50,0,100,50); node(C2,0,50,50,100); node(C3,50,50,100,100);
    node(G0,0,0,25,25); node(G1,25,0,50,25); node(G2,0,25,25,50); node(G3,25,25,40,50);
    for(U k=0;k<4;++k) { ai2Nodes[R].child[k]=A(&ai2Nodes[C0+k]); ai2Nodes[C0].child[k]=A(&ai2Nodes[G0+k]); }
    // Query box x[5,45] z[5,55]: R, C0, G0, G1, G2, C2 overlap partially; G3 is contained (7FA540); C1, C3 are rejected.
    interest(0,R,0x10,0x100,true,1);
    interest(3,C0,0x08,0x202,true,1);  // type outside the 0x10 mask: never gathered
    interest(2,C0,0x10,0x201,false,1); // live predicate false: never gathered
    interest(1,C0,0x10,0x200,true,1);  // list order: 0x200, 0x201, 0x202
    interest(4,G0,0x10,0x300,true,0);  // gathered, LOS flag 0: not reported
    interest(5,G2,0x10,0x302,true,1);
    interest(6,G3,0x10,0x303,true,1);
    interest(7,C1,0x10,0x210,true,1);  // rejected node
    interest(8,C2,0x10,0x220,true,1);
    interest(9,C3,0x10,0x230,true,1);  // rejected node
    Put(ai2WalkTreeRef,0x1C,A(&ai2Nodes[R])); Put(ai2WalkHolder,0x24,A(ai2WalkTreeRef)); Put(ai2WalkModel,0xBC,A(ai2WalkHolder));
    Put(ai2WalkObj,8,A(ai2WalkModel)); Put(ai2WalkObj,0x281AC,A(ai2Walk.aux)); ai2Walk.aux[6]=1; // [[obj+281AC]+18] != 0
    ai2Walk.walker[0]=A(ai2WalkObj);
    const float points[6]={5,5,45,10,20,55};
    ai2Walk.query[0]=1; memcpy(&ai2Walk.query[10],points,sizeof(points)); ai2Walk.query[16]=2;
}
static void Ai2WalkThink() {
    Ai2WalkTest& t=ai2Walk;
    t.thread=GetCurrentThreadId();
    t.walkEntry=t.entry(NTW2_CLONE_AI2_WALK);
    t.observerEntry=t.entry(NTW2_CLONE_AI2_6A95A0);
    t.badEntry=t.entry(NTW2_CLONE_TICK);
    if(!t.walkEntry) return;
    const auto walk=reinterpret_cast<U (__fastcall*)(void*,void*,void*)>(static_cast<uintptr_t>(t.walkEntry)); // thiscall, ret 4
    for(U i=0;i<kAi2WalkIterations;++i) {
        t.hitCount=0;
        const U result=walk(t.walker,nullptr,t.query)&0xFF;
        bool ok=result==0 && t.hitCount==kAi2Hits;
        for(U k=0;ok && k<kAi2Hits;++k) ok=t.hits[k]==kAi2ExpectedHits[k];
        ++(ok ? t.correct : t.wrong);
    }
}
struct Ai2Region { U va, bytes; };
static const Ai2Region kAi2Regions[4]={{0x15AFBA8,0x214},{0x15BBF4C,0x14},{0x14D0A6C,0x14},{0x150B5F8,0x100}};
static U Ai2Sentinel(U va) { return 0xA5000000u^va; }
static volatile LONG ai2MutatorStop, ai2MutatorPasses, ai2MutatorClobbers;
static void Ai2FillSentinels() {
    for(const Ai2Region& r:kAi2Regions) for(U o=0;o<r.bytes;o+=4) *reinterpret_cast<volatile U*>(At(r.va+o))=Ai2Sentinel(r.va+o);
}
static U Ai2SentinelMismatches() {
    U bad=0;
    for(const Ai2Region& r:kAi2Regions) for(U o=0;o<r.bytes;o+=4) bad+=*reinterpret_cast<volatile U*>(At(r.va+o))!=Ai2Sentinel(r.va+o);
    return bad;
}
static DWORD WINAPI Ai2Mutator(void*) { // shared-global writer: any foreign write between two passes is a clobber
    while(!ai2MutatorStop) {
        for(const Ai2Region& r:kAi2Regions)
            for(U o=0;o<r.bytes;o+=4) {
                volatile U* p=reinterpret_cast<volatile U*>(At(r.va+o));
                if(*p!=Ai2Sentinel(r.va+o)) InterlockedIncrement(&ai2MutatorClobbers);
                *p=Ai2Sentinel(r.va+o);
            }
        InterlockedIncrement(&ai2MutatorPasses);
    }
    return 0;
}

static void __fastcall Ai2FakeThink(Ai2Planner* planner,void*,U) {
    planner->thread=GetCurrentThreadId();
    InterlockedIncrement(&planner->started);
    if(planner->destroyFromWorker) CallDestroySlot(); // worker-side delegate destruction inside the think: marshalled
    if(planner->walk) Ai2WalkThink();
    Sleep(planner->delayMs);
    ++planner->calls;
}
static DWORD WINAPI Ai2DestroyHelper(void* cell) { CallDeleting(static_cast<U*>(cell)); return 0; }
struct Ai2Mid { Ai2Planner* planner; ULONGLONG begin, elapsed; U thinksAtMid, sleepMs; bool destroy, observer; };
static void __stdcall Ai2MidTick(void* raw) {
    Ai2Mid& m=*static_cast<Ai2Mid*>(raw);
    m.elapsed=GetTickCount64()-m.begin;
    m.thinksAtMid=m.planner->calls;
    if(m.sleepMs) Sleep(m.sleepMs);
    if(m.destroy) CallDestroySlot();   // tick-owner writer: the batch has already been joined at the tick start
    if(m.observer) CallObserverSlot(); // routed observer slot on the tick thread: original
}
static bool Ai2WaitCalls(const Ai2Planner& p,U calls,U ms) {
    const ULONGLONG end=GetTickCount64()+ms;
    while(p.calls<calls) { if(GetTickCount64()>=end) return false; Sleep(1); }
    return true;
}
static bool Ai2WaitStarted(const Ai2Planner& p,LONG started,U ms) {
    const ULONGLONG end=GetTickCount64()+ms;
    while(p.started<started) { if(GetTickCount64()>=end) return false; Sleep(1); }
    return true;
}
// A non-tick owner/delegate destructor started while the published batch runs: it must not enter before every queued
// call of that batch returned (thinksAtEntry), and it must block while they run.
static void Ai2TeardownWhileThinking(Ai2Planner& p,U* cell,LONG started,U callsAtEntry,LONG probeCalls,const char* what) {
    Check(Ai2WaitStarted(p,started,3000),what);
    DWORD helperId=0;
    HANDLE helper=CreateThread(nullptr,0,Ai2DestroyHelper,cell,0,&helperId);
    Check(helper && WaitForSingleObject(helper,40)==WAIT_TIMEOUT,what);
    if(helper) { WaitForSingleObject(helper,15000); CloseHandle(helper); }
    Check(ai2Probe.calls==probeCalls && ai2Probe.thinksAtEntry==callsAtEntry && ai2Probe.thread==helperId,what);
    Sleep(50); // the lease release resumes the worker, which reports idle before the next tick start
}

// ---- --ai-prepass-census / --ai-presize: ten pinned node-think slots + the walk-state slot (census) and the 0x56A610 slot (presize) in the owned
// image: untouched without the flags, published read-only while active, restored on stop with the row retained; an out-of-scope call through a
// node gate runs the original 0x7D7BF0 unchanged and records nothing.
static const U kPrepassNodeSlots[10]={0x13429b4,0x13429e8,0x1342a1c,0x1342a50,0x1342a84,0x1342ac4,0x1342afc,0x1342b34,0x1342b6c,0x1342bac};
static int AiPrepassFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    root[0x2829c]=1; Put(model,0xB0,A(armyManager));
    const U nodeOriginal=0x7D7BF0+delta, presizeOriginal=0x56A610+delta, walkOriginal=0x702BB0+delta;
    U* presizeSlot=At(0x13247EC); U* walkSlot=At(0x133e2dc);
    for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal && ReadOnly(At(slot)),"prepass node slot holds the pinned 0x7D7BF0 and is read-only before start");
    Check(*presizeSlot==presizeOriginal && ReadOnly(presizeSlot) && *walkSlot==walkOriginal,"presize and walk-state slots pristine before start");
    config.enabled_mask=NTW2_AI_ASYNC; config.workers=0; config.main_thread_id=GetCurrentThreadId(); config.ai_prepass_flags=0;
    // 1. AI alone: nothing published, row all zero.
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai without prepass flags activates");
    for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal,"no flags leave the node slots untouched");
    Check(*presizeSlot==presizeOriginal && *walkSlot==walkOriginal,"no flags leave the presize and walk slots untouched");
    ntw2_status snapshot={};
    bool zero=ReadState(state,snapshot);
    for(unsigned i=0;i<NTW2_AI_PREPASS_CENSUS_WORDS;++i) zero=zero && !snapshot.ai_prepass_census_words[i];
    for(unsigned i=0;i<NTW2_AI_PREPASS_WORDS;++i) zero=zero && !snapshot.ai_prepass_words[i];
    Check(zero,"prepass row is all zero without the flags");
    Check(stop(nullptr)==0,"stop prepass-free generation");
    // 2. Census.
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai prepass census activates");
    const U gate=*At(kPrepassNodeSlots[0]);
    Check(gate!=nodeOriginal && InRuntime(gate),"census node slot holds a runtime gate");
    for(U slot:kPrepassNodeSlots) Check(*At(slot)==gate && ReadOnly(At(slot)),"all ten node slots hold the same read-only gate");
    Check(*walkSlot!=walkOriginal && InRuntime(*walkSlot),"census publishes the walk-state gate");
    Check(*presizeSlot==presizeOriginal,"census alone leaves the presize slot untouched");
    Check(WaitFor(state,snapshot,[](const ntw2_status& s){ return s.ai_prepass_census_words[0]==1 && s.ai_prepass_census_words[63]==NTW2_AI_PREPASS_CENSUS; }),
          "census row publishes version 1 and the latched flag");
    {   // Out of any site-34 scope: the gate tail-jumps the original think (one child with an empty guard, nothing to do).
        static uint8_t nodeBuf[0x200], childBuf[0x100]; static U childList[1];
        childList[0]=A(childBuf); Put(nodeBuf,0x48,1); Put(nodeBuf,0x4C,A(childList));
        const U g=gate; const void* node=nodeBuf; U esiBefore=0, esiAfter=0, ediBefore=0, ediAfter=0;
        __asm {
            pushad
            mov esi, 0x55555555
            mov edi, 0x66666666
            mov esiBefore, esi
            mov ediBefore, edi
            mov ecx, node
            call dword ptr [g]
            mov esiAfter, esi
            mov ediAfter, edi
            popad
        }
        Check(esiAfter==esiBefore && ediAfter==ediBefore,"out-of-scope node gate preserves the callee-saved registers");
        Check(ReadState(state,snapshot) && snapshot.ai_prepass_census_words[2]==0 && snapshot.ai_prepass_census_words[3]==0,
              "out-of-scope node think records nothing");
    }
    Check(stop(nullptr)==0,"stop census generation");
    for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal && ReadOnly(At(slot)),"stop restores every node slot read-only");
    Check(*walkSlot==walkOriginal && *presizeSlot==presizeOriginal,"stop restores the walk-state slot");
    Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && snapshot.ai_prepass_census_words[0]==1,"stop retains the census row");
    // 3. Presize alone.
    config.ai_prepass_flags=NTW2_AI_PRESIZE;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai presize activates");
    Check(*presizeSlot!=presizeOriginal && !InRuntime(*presizeSlot) && ReadOnly(presizeSlot),"presize publishes the PRESIZE clone chain entry read-only");
    for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal,"presize alone leaves the node slots untouched");
    Check(*walkSlot==walkOriginal,"presize alone leaves the walk-state slot untouched");
    Check(WaitFor(state,snapshot,[](const ntw2_status& s){ return s.ai_prepass_census_words[0]==1 && s.ai_prepass_census_words[63]==NTW2_AI_PRESIZE; }),
          "presize row publishes version 1 and the latched flag");
    Check(stop(nullptr)==0 && *presizeSlot==presizeOriginal,"stop restores the presize slot");
    // 4. Both.
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_PRESIZE;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"census+presize activates");
    Check(*presizeSlot!=presizeOriginal && *At(kPrepassNodeSlots[9])!=nodeOriginal,"both sets of slots published");
    Check(stop(nullptr)==0 && *presizeSlot==presizeOriginal && *At(kPrepassNodeSlots[9])==nodeOriginal && *walkSlot==walkOriginal,"stop restores both sets");
    // 5. --ai-poly-shadow / --ai-poly: the observer slot 0x13376FC+0x40 and the walk-state slot are published read-only, the node slots are not, the
    // row publishes version 1 and its mode, stop restores both slots and retains the row; a later generation without the bits zeroes it.
    {
        U* observerSlot=At(0x13376fc+4*16); const U observerOriginal=0x6A95A0+delta;
        Check(*observerSlot==observerOriginal && ReadOnly(observerSlot),"observer slot pristine before the poly modes");
        const U modes[2]={NTW2_AI_POLY_SHADOW,NTW2_AI_POLY};
        for(U k=0;k<2;++k) {
            config.ai_prepass_flags=modes[k];
            Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai poly mode activates");
            Check(*observerSlot!=observerOriginal && InRuntime(*observerSlot) && ReadOnly(observerSlot),"poly publishes the read-only observer gate");
            Check(*walkSlot!=walkOriginal && InRuntime(*walkSlot) && *presizeSlot==presizeOriginal,"poly publishes the walk-state gate, not the presize slot");
            for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal,"poly leaves the node slots untouched");
            bool published=false;
            for(U i=0;i<300 && !published;++i) { if(ReadState(state,snapshot) && snapshot.ai_prepass_words[0]==1 && snapshot.ai_prepass_words[1]==k+1) published=true; else Sleep(10); }
            Check(published,"poly row publishes version 1 and its mode (1 shadow, 2 live)");
            bool censusZero=true; for(unsigned i=0;i<NTW2_AI_PREPASS_CENSUS_WORDS;++i) censusZero=censusZero && !snapshot.ai_prepass_census_words[i];
            Check(censusZero,"poly leaves the census row zero");
            Check(stop(nullptr)==0 && *observerSlot==observerOriginal && ReadOnly(observerSlot) && *walkSlot==walkOriginal,"stop restores the observer and walk-state slots");
            Check(ReadState(state,snapshot) && snapshot.ai_prepass_words[0]==1,"stop retains the poly row");
        }
        config.ai_prepass_flags=0;
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai without prepass flags activates after the poly generations");
        bool rowZero=ReadState(state,snapshot);
        for(unsigned i=0;i<NTW2_AI_PREPASS_WORDS;++i) rowZero=rowZero && !snapshot.ai_prepass_words[i];
        Check(rowZero && *observerSlot==observerOriginal,"poly row is all zero and the observer slot pristine without the bits");
        Check(stop(nullptr)==0,"stop poly-free generation");
    }
    // 5b. --ai-record-test-shadow / --ai-record-test (on top of --ai-poly): the alternate delegate slot 0x13376EC (= 0x6A99E0) is published read-only
    // next to the default observer slot, both restored by stop; words 32..59 of the prepass row publish version 1 and the mode; a generation without
    // the bits zeroes them.
    {
        U* altSlot=At(0x13376ac+4*16); U* observerSlot=At(0x13376fc+4*16);
        const U altOriginal=0x6A99E0+delta, observerOriginal=0x6A95A0+delta;
        Check(*altSlot==altOriginal && ReadOnly(altSlot),"alternate delegate slot pristine before the record-test modes");
        const U modes[2]={NTW2_AI_POLY|NTW2_AI_RECORD_TEST_SHADOW,NTW2_AI_POLY_SHADOW|NTW2_AI_RECORD_TEST};
        for(U k=0;k<2;++k) {
            config.ai_prepass_flags=modes[k];
            Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai record-test mode activates");
            Check(*altSlot!=altOriginal && InRuntime(*altSlot) && ReadOnly(altSlot),"record-test publishes the read-only alternate delegate gate");
            Check(*observerSlot!=observerOriginal && InRuntime(*observerSlot),"record-test keeps the poly observer gate");
            bool published=false;
            for(U i=0;i<300 && !published;++i) {
                if(ReadState(state,snapshot) && snapshot.ai_prepass_words[NTW2_AI_POLY_WORDS]==1 && snapshot.ai_prepass_words[NTW2_AI_POLY_WORDS+1]==(k==0?1u:2u)) published=true;
                else Sleep(10);
            }
            Check(published,"record-test row publishes version 1 and its own mode (1 shadow, 2 live)");
            Check(snapshot.ai_prepass_words[0]==1 && snapshot.ai_prepass_words[1]==(k==0?2u:1u),"record-test leaves the poly row mode independent");
            Check(stop(nullptr)==0 && *altSlot==altOriginal && ReadOnly(altSlot) && *observerSlot==observerOriginal,"stop restores the alternate delegate and observer slots");
        }
        config.ai_prepass_flags=NTW2_AI_POLY;
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai poly without record-test bits activates");
        bool recordZero=ReadState(state,snapshot);
        for(unsigned i=0;i<NTW2_AI_RECORD_TEST_WORDS;++i) recordZero=recordZero && !snapshot.ai_prepass_words[NTW2_AI_POLY_WORDS+i];
        Check(recordZero && *altSlot==altOriginal,"record-test row is zero and the alternate slot pristine without the bits");
        Check(stop(nullptr)==0,"stop record-test-free generation");
    }
    // 6. --ai-spiral-census / --ai-spiral-cap-m: the observer slot plus the fallback observer (0x1343318 slot 16) and inline controller
    // (0x1349C18 slot 28) gates are published read-only, the walk-state slot is not (R2 routing unchanged); the row publishes version 1 and the
    // cap; stop restores all three slots and retains the row; a generation without the bits zeroes it.
    {
        U* observerSlot=At(0x13376fc+4*16); U* fallbackSlot=At(0x1343318+4*16); U* controllerSlot=At(0x1349c18+4*28);
        const U observerOriginal=0x6A95A0+delta, fallbackOriginal=0x7524A0+delta, controllerOriginal=0x826E80+delta;
        Check(*observerSlot==observerOriginal && *fallbackSlot==fallbackOriginal && *controllerSlot==controllerOriginal &&
              ReadOnly(fallbackSlot) && ReadOnly(controllerSlot),"spiral slots pristine before start");
        const U modes[3]={NTW2_AI_SPIRAL_CENSUS,200u<<NTW2_AI_SPIRAL_CAP_SHIFT,NTW2_AI_POLY|NTW2_AI_SPIRAL_CENSUS|(20u<<NTW2_AI_SPIRAL_CAP_SHIFT)};
        const U caps[3]={0,200,20};
        for(U k=0;k<3;++k) {
            config.ai_prepass_flags=modes[k];
            Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai spiral mode activates");
            Check(*observerSlot!=observerOriginal && InRuntime(*observerSlot) && ReadOnly(observerSlot),"spiral publishes the read-only observer gate");
            Check(*fallbackSlot!=fallbackOriginal && InRuntime(*fallbackSlot) && ReadOnly(fallbackSlot),"spiral publishes the read-only fallback gate");
            Check(*controllerSlot!=controllerOriginal && InRuntime(*controllerSlot) && ReadOnly(controllerSlot),"spiral publishes the read-only controller gate");
            Check((*walkSlot!=walkOriginal)==((modes[k]&NTW2_AI_POLY)!=0),"spiral alone leaves the walk-state slot untouched");
            for(U slot:kPrepassNodeSlots) Check(*At(slot)==nodeOriginal,"spiral leaves the node slots untouched");
            bool published=false;
            for(U i=0;i<300 && !published;++i) { if(ReadState(state,snapshot) && snapshot.ai_spiral_words[0]==1 && snapshot.ai_spiral_words[1]==caps[k]) published=true; else Sleep(10); }
            Check(published,"spiral row publishes version 1 and the cap");
            Check(stop(nullptr)==0 && *observerSlot==observerOriginal && *fallbackSlot==fallbackOriginal && *controllerSlot==controllerOriginal &&
                  ReadOnly(fallbackSlot) && ReadOnly(controllerSlot) && *walkSlot==walkOriginal,"stop restores the spiral slots");
            Check(ReadState(state,snapshot) && snapshot.ai_spiral_words[0]==1 && snapshot.ai_spiral_words[1]==caps[k],"stop retains the spiral row");
        }
        config.ai_prepass_flags=0;
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai without prepass flags activates after the spiral generations");
        bool rowZero=ReadState(state,snapshot);
        for(unsigned i=0;i<NTW2_AI_SPIRAL_WORDS;++i) rowZero=rowZero && !snapshot.ai_spiral_words[i];
        Check(rowZero && *fallbackSlot==fallbackOriginal && *controllerSlot==controllerOriginal,"spiral row is all zero and its slots pristine without the bits");
        Check(stop(nullptr)==0,"stop spiral-free generation");
    }
    return failures ? 1 : 0;
}
static int AiAsync2Fixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    auto boundary=reinterpret_cast<ntw2_ai_async2_boundary_fn>(GetProcAddress(runtimeModule,"ntw2_ai_async2_boundary"));
    auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(runtimeModule,"ntw2_site_callee"));
    ai2Walk.entry=reinterpret_cast<ntw2_ai_async2_private_entry_fn>(GetProcAddress(runtimeModule,"ntw2_ai_async2_private_entry"));
    Check(boundary!=nullptr && siteCallee!=nullptr && ai2Walk.entry!=nullptr,"ai_async2 lifecycle exports present");
    if(!boundary || !siteCallee || !ai2Walk.entry) return 1;
    root[0x2829c]=1; Put(model,0xB0,A(armyManager));
    config.workers=0; config.main_thread_id=GetCurrentThreadId();
    config.enabled_mask=NTW2_AI_ASYNC2; Check(start(&config)==1,"ai_async2 without ai is refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2|NTW2_AI_CTRL; Check(start(&config)==1,"ai_async2 with ai_ctrl is refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2|NTW2_AI_CENSUS; Check(start(&config)==1,"ai_async2 with ai_census is refused");
    const U destroyOriginal=*Ai2DestroyCell(), walkOriginal=*At(0x133E2DC), observerOriginal=*Ai2ObserverCell(),
            ownerOriginal=*Ai2OwnerCell();
    Check(destroyOriginal==0x69D750+delta && walkOriginal==0x702BB0+delta && observerOriginal==0x6A95A0+delta &&
          ownerOriginal==0x73E180+delta,"pinned originals before start");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai_async2 activates");
    // Probes go in only after the first activation validated and copied the clone sources (0x7D99F0 and 0x6A95A0 are
    // sources); the resident clones call the probed entries as kept externals.
    Check(RedirectImage(0x7D99F0,reinterpret_cast<const void*>(&Ai2FakeThink)) &&
          RedirectImage(0x69D750,reinterpret_cast<const void*>(&Ai2FakeDestroy)) &&
          RedirectImage(0x73E180,reinterpret_cast<const void*>(&Ai2FakeDestroy)) &&
          RedirectImage(0x6A95A0,reinterpret_cast<const void*>(&Ai2FakeObserver)) &&
          RedirectImage(0x7E6C30,reinterpret_cast<const void*>(&Ai2FakeSearchCtor)) &&
          RedirectImage(0x808F90,reinterpret_cast<const void*>(&Ai2RecordLos)),
          "install planner, delegate/owner destructor, observer, search-object ctor and LOS recorder probes");
    Check(InRuntime(*Ai2DestroyCell()) && ReadOnly(Ai2DestroyCell()) && InRuntime(*At(0x133E2DC)) &&
          InRuntime(*Ai2ObserverCell()) && ReadOnly(Ai2ObserverCell()) && InRuntime(*Ai2OwnerCell()) && ReadOnly(Ai2OwnerCell()) &&
          InRuntime(*At(0x1349C18+4*26)) && InRuntime(*At(0x134B48C+4*2)),
          "delegate, owner-destructor, walk-entry and observer slots hold read-only runtime gates");
    Check(InRuntime(siteCallee(33)) && InRuntime(siteCallee(34)),"site 33 join gate and site 34 queueing gate are bound");
    Ai2Planner p={};
    ai2Probe={}; ai2Probe.planner=&p;
    const U owner=GetCurrentThreadId();
    Ai2Mid m={};
    auto tick=[&](Ai2Planner* planner,U delayMs,U options,Ai2Mid* mid) {
        if(planner) p.delayMs=delayMs; // a null-planner tick must not retime a think still queued or running
        if(mid) { const Ai2Mid keep=*mid; *mid={}; mid->planner=&p; mid->sleepMs=keep.sleepMs; mid->destroy=keep.destroy;
                  mid->observer=keep.observer; mid->begin=GetTickCount64(); }
        return boundary(model,planner,1,mid ? &Ai2MidTick : nullptr,mid,options);
    };
    // T1: site 34 queues and returns; nothing runs during the admitting tick (published only at its end); the think
    // runs on the AI worker in the inter-tick window. The tick-side observer call keeps the original.
    m={}; m.sleepMs=50; m.observer=true;
    Check(tick(&p,0,0,&m)==1 && m.elapsed<100 && m.thinksAtMid==0,"T1: site 34 queued and returned; no think ran inside the admitting tick");
    Check(Ai2WaitCalls(p,1,3000) && p.thread!=owner,"T1: the think ran once on the AI worker after the tick end");
    CallObserverSlot(); // outside any tick: class other
    Check(ai2ObserverCalls==2 && ai2ObserverThread[0]==owner && ai2ObserverThread[1]==owner,"observer slot: tick and other threads run the original");
    Sleep(50); // let the worker report idle so the next start join counts the batch as complete
    Check(tick(nullptr,0,0,nullptr)==1,"T2: tick start counts the complete batch without stalling");
    // T3/T4: a think longer than the window: the next tick start blocks until it returns (no think crosses into a tick).
    Check(tick(&p,300,0,nullptr)==1,"T3: long think queued");
    m={};
    Check(tick(nullptr,0,2,&m)==1 && m.thinksAtMid==2 && p.calls==2,"T4: the tick-start lifetime join waited for the whole think");
    // T5/T6: a tick-owner structural writer runs after the start join, never concurrently with the think.
    Check(tick(&p,150,0,nullptr)==1,"T5: think queued");
    m={}; m.destroy=true;
    Check(tick(nullptr,0,2,&m)==1 && ai2Probe.calls==1 && ai2Probe.thread==owner && ai2Probe.thinksAtEntry==3 && p.calls==3,
          "T6: tick-side destructor ran only after the think completed");
    // T7: a main/render delegate destructor waits for the executing think (owner teardown lease).
    Check(tick(&p,150,0,nullptr)==1,"T7: think queued");
    Ai2TeardownWhileThinking(p,Ai2DestroyCell(),4,4,2,"T7: non-tick delegate destructor blocks until the think returned");
    Check(tick(nullptr,0,0,nullptr)==1,"T8: tick start counts the drained batch as complete");
    // T9: owner teardown while a think runs and a second call of the same batch is still queued: the observer owner
    // destructor (0x1343318 slot 2 -> 0x73E180) enters only after BOTH calls returned -- the queued call holds a raw
    // planner pointer, so waiting for the executing call alone would let it run on a destroyed owner.
    Check(tick(&p,100,1,nullptr)==1,"T9: two thinks queued in one tick");
    Ai2TeardownWhileThinking(p,Ai2OwnerCell(),5,6,3,"T9: owner teardown waits for the whole published batch, not only the executing call");
    Check(tick(nullptr,0,0,nullptr)==1,"T10: drained batch complete at tick start");
    // T11/T12: the worker's own destructor call is marshalled; posted in the window it is served by the next tick start.
    p.destroyFromWorker=1;
    Check(tick(&p,20,0,nullptr)==1,"T11: think queued");
    Sleep(100);
    Check(ai2Probe.calls==3,"T11: the marshalled call waits for a servicing thread");
    Check(tick(nullptr,0,2,nullptr)==1 && ai2Probe.calls==4 && ai2Probe.thread==owner && ai2Probe.thinksAtEntry==6 && p.calls==7,
          "T12: the tick-start join executed the worker's destructor call and drained the think");
    p.destroyFromWorker=0;
    // T13/T14: two admissions in one tick both run in FIFO order (nothing is skipped).
    Check(tick(&p,10,1,nullptr)==1 && Ai2WaitCalls(p,9,3000),"T13: both queued thinks ran");
    Sleep(50);
    Check(tick(nullptr,0,0,nullptr)==1,"T14: complete batch counted at the tick start");
    // T15/T16: watchdog. A join waiting more than 5 s records deadlock_suspected and the sticky fallback; it is not aborted.
    Check(tick(&p,5600,0,nullptr)==1,"T15: very long think queued");
    Check(tick(nullptr,0,2,nullptr)==1 && p.calls==10,"T16: the waiting tick-start join was not aborted");
    // T17: sticky fallback: the planner now runs through the synchronous same-call barrier.
    m={};
    Check(tick(&p,10,0,&m)==1 && m.thinksAtMid==11 && p.calls==11,"T17: fallback think completes before site 34 returns");
    ntw2_status snapshot={};
    Check(stop(nullptr)==0,"ai_async2 generation stops");
    Check(*Ai2DestroyCell()==destroyOriginal && ReadOnly(Ai2DestroyCell()) && *At(0x133E2DC)==walkOriginal &&
          *Ai2ObserverCell()==observerOriginal && ReadOnly(Ai2ObserverCell()) && *Ai2OwnerCell()==ownerOriginal &&
          ReadOnly(Ai2OwnerCell()),"stop restores the pinned slot words and their protection");
    Check(ReadState(state,snapshot),"ai_async2 telemetry readable after stop");
    {
        const U* w=snapshot.ai_async2_words;
        const U* q=snapshot.ai_async2_route_words;
        U think=0, overlap=0, join=0, fn=0;
        for(U i=0;i<12;++i) { think+=w[20+i]; overlap+=w[32+i]; join+=w[44+i]; }
        for(U i=26;i<47;++i) fn+=q[i];
        Check(w[0]==3 && w[1]==8 && w[2]==10 && w[3]==0 && w[4]==0 && w[5]==1 && w[19]==0,
              "eight published batches, ten async completions, one fallback join");
        Check(w[6]>=1 && w[7]==1 && w[8]==1,"watchdog recorded deadlock_suspected, sticky fallback and one fallback think");
        Check(w[9]==1 && w[80+5]==1 && w[12]>=w[11],"one worker destructor call marshalled");
        Check(think==10 && overlap==8 && join==8 && w[14]>=5600000u && w[18]>=5000000u,
              "one think sample per async think; one overlap and one join-wait sample per batch");
        Check(w[56+2*5]==2 && w[56+2*5+1]>=50000u && w[89]==2 && w[94]==2,"two owner-teardown leases waited for their batches");
        Check(w[88]==1 && w[92]==0 && w[93]==0,"spotting route reported unresolved; nothing serviced or aborted by stop");
        Check(q[0]==3 && q[1]==2 && q[2]==17 && q[3]==10 && q[4]==8 && q[6]==0 && q[7]==0,"route row: ticks, queued, batches");
        Check(q[8]==8 && q[9]==4 && q[10]==1 && q[16]==0,"four batches complete before the next tick start; one start-join marshal service");
        Check(q[11]==4 && q[12]>=5600000u && q[13]>=5000000u && q[14]==16 && q[15]==16,
              "four tick-start stalls reported separately (last at tick 16); fallback at tick 16");
        Check(q[18]==0 && q[19]==0 && q[20]==0 && q[21]==0 && q[22]==0 && q[23]==0 && q[24]==1 && q[25]==1,
              "route matrix: one tick and one other observer call, no walk-slot entry");
        Check(fn==0 && q[47+9]==1 && q[60]==0 && q[64]==0,"no private clone entered, pin 9 marshalled once, no scratch constructed");
        printf("ai_async2 fixture: max_think_us=%u start_stalls=%u start_stall_sum_us=%u marshal_wait_max_us=%u deadlock=%u\n",
               w[14],q[11],q[12],w[12],w[6]);
    }

    // Second generation: the fallback is sticky only for its generation; the AI-thread private walk runs on the real
    // clones against a synthetic tree while the original scratch is continuously rewritten by another thread; then the
    // generation stops with a worker marshal pending and no tick to service it.
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2;
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"second ai_async2 generation activates");
    Check(ai2CtorCalls==0,"no private search object is constructed at activation");
    Ai2BuildTree();
    Check(ai2Walk.entry(NTW2_CLONE_AI2_WALK)==0,"private clone entries are refused to a non-worker thread");
    m={};
    Check(tick(&p,10,0,&m)==1 && m.thinksAtMid==11 && Ai2WaitCalls(p,12,3000),"new generation queues asynchronously again");
    Check(tick(nullptr,0,0,nullptr)==1,"second generation joins its first batch");
    Ai2FillSentinels();
    ai2MutatorStop=0; ai2MutatorPasses=0; ai2MutatorClobbers=0;
    HANDLE mutator=CreateThread(nullptr,0,Ai2Mutator,nullptr,0,nullptr);
    { const ULONGLONG end=GetTickCount64()+1000; while(mutator && ai2MutatorPasses<2 && GetTickCount64()<end) Sleep(1); }
    p.walk=1;
    Check(mutator && tick(&p,0,0,nullptr)==1 && tick(nullptr,0,0,nullptr)==1 && p.calls==13,"walk think queued and joined");
    p.walk=0;
    const LONG passes=ai2MutatorPasses;
    InterlockedExchange(&ai2MutatorStop,1);
    if(mutator) { WaitForSingleObject(mutator,5000); CloseHandle(mutator); }
    Check(ai2Walk.thread==p.thread && ai2Walk.thread!=owner && ai2Walk.walkEntry && ai2Walk.walkEntry!=0x7F1D40+delta &&
          ai2Walk.observerEntry && ai2Walk.badEntry==0,"the AI worker inside a think receives the private walk and observer entries");
    Check(ai2Walk.correct==kAi2WalkIterations && ai2Walk.wrong==0,
          "every private walk gathered exactly the expected owners (partial, contained, rejected nodes; mask, predicate, LOS flag)");
    Check(passes>0 && ai2MutatorClobbers==0 && Ai2SentinelMismatches()==0,
          "the private walk never wrote the original search objects, walk/gather/lookup vectors or observer object");
    const U congruent[3]={0x15AFBA8u&15u,0x15AFCA8u&15u,0x150B5F8u&15u}, originals[3]={0x15AFBA8,0x15AFCA8,0x150B5F8};
    bool constructed=ai2CtorCalls==3;
    for(U i=0;constructed && i<3;++i)
        constructed=ai2CtorThread[i]==p.thread && (ai2CtorSelf[i]&15u)==congruent[i] && InRuntime(ai2CtorSelf[i]) &&
                    ai2CtorSelf[i]!=A(At(originals[i]));
    Check(constructed,"the three private search objects were constructed once, lazily, on the AI worker, congruent mod 16");
    // Stop with an inter-tick marshal pending and the receivers still bound: no tick comes, so the stopping thread
    // services the call itself after the grace period; the think returns and stop completes.
    p.destroyFromWorker=1;
    Check(tick(&p,0,0,nullptr)==1,"stop-pending: think queued");
    Sleep(100);
    Check(ai2Probe.calls==4 && p.calls==13,"stop-pending: the worker is blocked in its marshalled call");
    const ULONGLONG stopBegin=GetTickCount64();
    Check(stop(nullptr)==0 && GetTickCount64()-stopBegin<5000,"stop-pending: stop drains the pending marshal instead of timing out");
    Check(ai2Probe.calls==5 && ai2Probe.thread!=owner && ai2Probe.thread!=p.thread && p.calls==14,
          "stop-pending: the stopping thread executed the call while the receivers were bound; the think returned");
    p.destroyFromWorker=0;
    Check(*Ai2DestroyCell()==destroyOriginal && *Ai2OwnerCell()==ownerOriginal && *Ai2ObserverCell()==observerOriginal,
          "stop-pending: slots restored after the drain");
    Check(ReadState(state,snapshot),"second generation telemetry readable");
    {
        const U* w=snapshot.ai_async2_words;
        const U* q=snapshot.ai_async2_route_words;
        U otherFn=0;
        for(U i=26;i<47;++i) if(i!=29 && i!=30 && i!=45) otherFn+=q[i];
        Check(w[7]==0 && w[1]==3 && w[2]==3 && w[92]==1 && w[93]==0,"fallback reset at activation; three batches; one stop-serviced marshal");
        Check(q[29]==kAi2WalkIterations && q[30]==kAi2WalkIterations && q[45]==9*kAi2WalkIterations && otherFn==0,
              "route counters: one AI2_WALK and AI2_GATHER entry per walk, nine AI2_809110 node visits per walk");
        Check(q[64]==3 && q[63]>=6 && q[62]>=6 && w[90]==2 && w[91]==1,"private vectors grew in the private images; scratch constructed");
    }
    // Third generation: the battle disappears (world unbound) with a worker marshal pending. The monitor's world-loss
    // deactivation aborts the call (EAX = 0, the original is NOT executed on destroyed receivers) so the think returns.
    Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"third ai_async2 generation activates");
    p.destroyFromWorker=1;
    Check(tick(&p,0,0,nullptr)==1,"world-loss: think queued");
    Sleep(100);
    Check(ai2Probe.calls==5 && p.calls==14,"world-loss: the worker is blocked in its marshalled call");
    Put(model,0,0); // the model no longer names the root: the battle is gone
    Check(WaitFor(state,snapshot,[](const ntw2_status& s){ return s.phase==NTW2_WAITING_BATTLE; }) && Ai2WaitCalls(p,15,3000),
          "world-loss: the monitor deactivated and the think returned");
    Check(ai2Probe.calls==5,"world-loss: the aborted call never executed the destructor");
    Check(stop(nullptr)==0 && ReadState(state,snapshot) && snapshot.ai_async2_words[93]==1 && snapshot.ai_async2_words[92]==0,
          "world-loss: one aborted marshal recorded; stop succeeds");
    Put(model,0,A(root));
    p.destroyFromWorker=0;
    return failures ? 1 : 0;
}

// ---- NTW2_AI_ASYNC2 deferred schedule (--ai-deferred) -------------------------------------------------------------------
// A synthetic planner (P+9C/A0 node list, P+B0/B4 second array, P+B8 round-robin counter, P->vt+8->+64->+80 full-walk
// gate) whose node bodies record their order. 0x7CD010 / 0x7CCF80 are redirected in the owned image to recorders;
// decomposable nodes carry 0x7D7BF0 in their think slot (redirected to a trap: the driver must never call it), whole
// nodes a recording think. Every tick's callback appends a tick marker after the start seam joined the slice, so the
// log is the exact interleaving of slices and ticks. The scenario runs under four perturbations (workers 1/8, sleeps in
// the worker's node bodies, sleeps on the tick thread) and must produce the identical log and counters each time.
struct DfChild { U vtable, id, pad[10], f30, pad2[3], f40, marshal; };
struct DfNode { U vtable, id, current, pad[15], childCount, children, pendingCount, pending[4], childArray[4]; };
static_assert(offsetof(DfChild,f30)==0x30 && offsetof(DfChild,f40)==0x40 && offsetof(DfNode,childCount)==0x48 &&
              offsetof(DfNode,children)==0x4C, "synthetic planner node layouts");
static char dfLog[4096];
static size_t dfLen;
static volatile LONG dfCalls, dfOverlaps, dfThinkBodyCalls, dfPlannerCalls;
static U dfChildSleepMs, dfMidSleepMs, dfWorkerThread, dfDestroyThread;
static void DfNote(const char* format,U value) {
    if(dfLen<sizeof(dfLog)) dfLen+=static_cast<size_t>(_snprintf_s(dfLog+dfLen,sizeof(dfLog)-dfLen,_TRUNCATE,format,value));
    InterlockedIncrement(&dfCalls);
}
static void __fastcall DfPassA(DfNode* n,void*) { dfWorkerThread=GetCurrentThreadId(); DfNote(" A%u",n->id); }
static void __fastcall DfPassB(DfNode* n,void*) { DfNote(" B%u",n->id); }
static void __fastcall DfGenerate(DfNode* n,void*) {
    DfNote(" G%u",n->id);
    for(U i=0;i<n->pendingCount;++i) n->childArray[i]=n->pending[i];
    n->childCount=n->pendingCount; n->children=A(n->childArray);
}
static U __fastcall DfCurrent(DfNode* n,void*) { return n->current; }
static void __fastcall DfWhole(DfNode* n,void*) { DfNote(" W%u",n->id); if(dfChildSleepMs) Sleep(dfChildSleepMs); }
static void __fastcall DfChildThink(DfChild* c,void*) {
    DfNote(" C%u",c->id);
    if(dfChildSleepMs) Sleep(dfChildSleepMs);
    if(c->marshal) CallDestroySlot(); // worker-side delegate destruction inside a slice: marshalled to the next seam
}
static void* __fastcall DfDestroy(void* self,void*,U) { dfDestroyThread=GetCurrentThreadId(); DfNote(" D",0); return self; }
static void __fastcall DfThinkBody(void*,void*) { InterlockedIncrement(&dfThinkBodyCalls); }
static void __fastcall DfPlannerBody(void*,void*,U) { InterlockedIncrement(&dfPlannerCalls); }
static U dfDecomposableVt[11], dfWholeVt[11], dfChildVt[11], dfPlannerVt[4], dfGateA[32], dfGateB[40];
static DfNode dfNodes[5]; // N0..N3 (array 1), M0 (array 2, id 10)
static DfChild dfChildren[5]; // 11, 12 (flags zero), 13 of N1; 21, 22 of M0
static U dfArray1[4], dfArray2[1], dfPlanner[0x40];
static void DfBuild() {
    dfDecomposableVt[0]=A(reinterpret_cast<const void*>(&DfGenerate)); dfDecomposableVt[4]=0x7D7BF0+delta;
    dfDecomposableVt[8]=A(reinterpret_cast<const void*>(&DfCurrent));
    dfWholeVt[4]=A(reinterpret_cast<const void*>(&DfWhole)); dfWholeVt[8]=A(reinterpret_cast<const void*>(&DfCurrent));
    dfChildVt[10]=A(reinterpret_cast<const void*>(&DfChildThink));
    const U childIds[5]={11,12,13,21,22};
    for(U i=0;i<5;++i) { dfChildren[i]={}; dfChildren[i].vtable=A(dfChildVt); dfChildren[i].id=childIds[i]; dfChildren[i].f30=i==1 ? 0 : 1; }
    const U nodeIds[5]={0,1,2,3,10};
    for(U i=0;i<5;++i) { dfNodes[i]={}; dfNodes[i].vtable=A(i==3 ? dfWholeVt : dfDecomposableVt); dfNodes[i].id=nodeIds[i]; }
    dfNodes[0].current=1;
    dfNodes[1].pendingCount=3; for(U i=0;i<3;++i) dfNodes[1].pending[i]=A(&dfChildren[i]);
    dfNodes[4].pendingCount=2; dfNodes[4].pending[0]=A(&dfChildren[3]); dfNodes[4].pending[1]=A(&dfChildren[4]);
    for(U i=0;i<4;++i) dfArray1[i]=A(&dfNodes[i]);
    dfArray2[0]=A(&dfNodes[4]);
    memset(dfPlanner,0,sizeof(dfPlanner)); memset(dfGateA,0,sizeof(dfGateA)); memset(dfGateB,0,sizeof(dfGateB));
    dfPlannerVt[2]=A(dfGateA); dfGateA[0x64/4]=A(dfGateB); dfGateB[0x80/4]=0; // full walk enabled
    dfPlanner[0]=A(dfPlannerVt);
    dfPlanner[0x9C/4]=4; dfPlanner[0xA0/4]=A(dfArray1); dfPlanner[0xB0/4]=1; dfPlanner[0xB4/4]=A(dfArray2); dfPlanner[0xB8/4]=0;
    dfLen=0; dfLog[0]=0; dfCalls=dfOverlaps=0;
}
// Tick-thread callback (after site 34): the marker, an optional sleep that must not overlap any node body, and the
// scheduled mutations of the live planner state between slices.
static void __stdcall DfMid(void* raw) {
    const U tick=*static_cast<U*>(raw);
    const LONG before=dfCalls;
    DfNote(" T%u",tick);
    if(dfMidSleepMs) Sleep(dfMidSleepMs);
    if(tick==3) { dfNodes[4].childArray[0]=A(&dfChildren[4]); dfNodes[4].childCount=1; } // M0 loses child 21
    if(tick==5) { dfArray1[2]=A(&dfNodes[3]); dfPlanner[0x9C/4]=3; }                     // N2 leaves the node list
    if(tick==7) dfChildren[4].marshal=1;
    if(tick==8) dfChildren[4].marshal=0;
    if(dfCalls!=before+1) InterlockedIncrement(&dfOverlaps);
}
static const char kDfExpected[]=
    " T1 A0 A1 A2 A3 B0 B1 B2 B3 G1 B1 C11 T2 C13 G10 B10 T3 C22 T4 A0 A1 A2 A3 B0 B1 B2 B3 C11 C13 T5 W3"
    " T6 A0 A1 A3 B0 B1 B3 W3 C22 T7 A0 A1 A3 B0 B1 B3 C22 D T8 A0 A1 A3 B0 B1 B3 C11 C13 T9"
    " T10 A0 A1 A3 B0 B1 B3 W3 C22 T11";
// Deferred-row words that are functions of the schedule only (everything except the timing words).
static const U kDfDeterministic[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,21,24,25,26,27,28,29,30,31,39,40,41,42,43,
                                   44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59};
static int AiDeferredFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    auto boundary=reinterpret_cast<ntw2_ai_async2_boundary_fn>(GetProcAddress(runtimeModule,"ntw2_ai_async2_boundary"));
    auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(runtimeModule,"ntw2_site_callee"));
    Check(boundary!=nullptr && siteCallee!=nullptr,"ai_deferred lifecycle exports present");
    if(!boundary || !siteCallee) return 1;
    root[0x2829c]=1; Put(model,0xB0,A(armyManager));
    config.workers=0; config.main_thread_id=GetCurrentThreadId();
    const U deferred=1u|(2u<<NTW2_AI_DEFERRED_BUDGET_SHIFT);
    config.enabled_mask=NTW2_AI_ASYNC; config.ai_deferred=deferred;
    Check(start(&config)==1,"ai_deferred without ai_async2 is refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2|NTW2_AI_CTRL; Check(start(&config)==1,"ai_deferred with ai_ctrl is refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2|NTW2_AI_CENSUS; Check(start(&config)==1,"ai_deferred with ai_census is refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2;
    config.ai_deferred=2u<<NTW2_AI_DEFERRED_BUDGET_SHIFT; Check(start(&config)==1,"K = 0 is refused");
    config.ai_deferred=(NTW2_AI_DEFERRED_MAX_K+1)|(2u<<NTW2_AI_DEFERRED_BUDGET_SHIFT); Check(start(&config)==1,"K above the maximum is refused");
    config.ai_deferred=1u; Check(start(&config)==1,"budget 0 is refused");
    config.ai_deferred=deferred|0x1000000u; Check(start(&config)==1,"unknown ai_deferred bits are refused");
    const U destroyOriginal=*Ai2DestroyCell();
    U tickIndex=0, gapMs=0;
    auto tick=[&](U* planner,U flag,U options) {
        if(gapMs) Sleep(gapMs); // a long inter-tick window: slices finish before the seam instead of stalling it
        ++tickIndex;
        return boundary(model,planner,flag,&DfMid,&tickIndex,options);
    };
    ntw2_status reference={};
    char referenceLog[sizeof(dfLog)]={};
    // workers, sleep in the worker's node bodies, sleep on the tick thread, sleep between ticks
    struct Run { U workers, childSleepMs, midSleepMs, gapMs; };
    const Run runs[5]={{1,0,0,0},{8,0,0,0},{1,15,0,0},{8,0,15,0},{8,0,0,20}};
    for(U r=0;r<5;++r) {
        config.workers=runs[r].workers; config.ai_deferred=deferred;
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"ai_deferred generation activates");
        if(r==0) {
            // Probes go in only after the first activation validated and copied the clone sources.
            Check(RedirectImage(0x7CD010,reinterpret_cast<const void*>(&DfPassA)) &&
                  RedirectImage(0x7CCF80,reinterpret_cast<const void*>(&DfPassB)) &&
                  RedirectImage(0x7D7BF0,reinterpret_cast<const void*>(&DfThinkBody)) &&
                  RedirectImage(0x7D99F0,reinterpret_cast<const void*>(&DfPlannerBody)) &&
                  RedirectImage(0x69D750,reinterpret_cast<const void*>(&DfDestroy)),
                  "install node-body, think-body trap, planner trap and destructor probes");
            Check(InRuntime(siteCallee(34)) && InRuntime(*Ai2DestroyCell()),"site 34 and the delegate destructor slot are gated");
        }
        DfBuild(); tickIndex=0;
        dfChildSleepMs=runs[r].childSleepMs; dfMidSleepMs=runs[r].midSleepMs; gapMs=runs[r].gapMs;
        const U owner=GetCurrentThreadId();
        U* p=dfPlanner;
        Check(tick(p,0,0)==1,"tick 1: site 34 admits; the think is deferred");
        tick(p,1,0);  // busy refusal; the refused full-walk flag is owed
        tick(p,0,0);  // busy refusal; M0 loses child 21 between slices
        tick(p,0,0);  // think 1 consumed late (3 ticks); think 2 admitted with the owed full walk
        tick(p,0,0);  // busy refusal; N2 leaves the node list between slices
        tick(p,0,0);  // think 2 consumed late (2 ticks); think 3 admitted, finishes in one slice
        tick(p,0,0);  // think 3 consumed on time; think 4 marshals the destructor from its slice
        tick(p,0,0);  // the seam served the marshal; think 4 consumed on time; think 5 blocks on the budget
        tick(nullptr,0,0); // planner not presented: think 5 is abandoned before the slice
        tick(p,0,1);  // think 6 admitted, the second same-tick admission is a busy refusal
        tick(nullptr,0,0); // think 6 consumed on time
        Check(stop(nullptr)==0,"ai_deferred generation stops");
        Check(*Ai2DestroyCell()==destroyOriginal && ReadOnly(Ai2DestroyCell()),"stop restores the gated destructor slot");
        ntw2_status snapshot={};
        Check(ReadState(state,snapshot),"ai_deferred telemetry readable after stop");
        Check(dfLen<sizeof(dfLog) && !strcmp(dfLog,kDfExpected),"node order and slice/tick interleaving match the driver contract");
        if(strcmp(dfLog,kDfExpected)) fprintf(stderr,"run %u log:%s\n",r,dfLog);
        Check(dfOverlaps==0,"no node body ran while a tick was in progress");
        Check(dfThinkBodyCalls==0 && dfPlannerCalls==0,"the driver never entered 0x7D7BF0 or the whole planner 0x7D99F0");
        Check(dfWorkerThread && dfWorkerThread!=owner && dfDestroyThread==owner,"node bodies ran on the AI worker; the marshal was served by the tick");
        const U* d=snapshot.ai_deferred_words;
        Check(d[0]==1 && d[1]==1 && d[2]==2 && d[3]==6 && d[4]==4 && d[5]==0,"admitted 6, busy refusals 4, K=1, B=2");
        Check(d[6]==5 && d[7]==3 && d[8]==2 && d[9]==1 && d[10]==0,"consumed 5 (3 on time, 2 late); one think abandoned unseen");
        Check(d[11]==9 && d[12]==4 && d[13]==1 && d[14]==2 && d[15]==1 && d[16]==0,
              "9 slices, 4 budget hits; one node skipped and two relocated on resume; one child skipped");
        Check(d[17]+d[18]==9 && d[21]==1 && d[24]==1 && d[25]==0,"every slice joined at a seam; one seam marshal service; one carried flag");
        Check(d[26]==20 && d[27]==22 && d[28]==12 && d[29]==2 && d[30]==10 && d[31]==3,"per-kind node calls");
        Check(d[41]==3 && d[42]==3 && d[40]==11 && d[43]==0,"spanned max 3, slices max 3, last consumption at tick 11, nothing outstanding");
        Check(d[44]==3 && d[45]==1 && d[46]==1 && d[52]==3 && d[53]==1 && d[54]==1,"histograms of ticks spanned and slices per think");
        Check(snapshot.ai_async2_route_words[1]==3 && snapshot.ai_async2_words[1]==9 && snapshot.ai_async2_words[2]==9 &&
              snapshot.ai_async2_words[6]==0,"route schedule 3; one dispatch and one completion per slice; no watchdog");
        printf("ai_deferred fixture run %u (workers=%u child_sleep=%u mid_sleep=%u gap=%u): slices=%u slice_max_us=%u "
               "slice_sum_us=%u seam_waits=%u seam_complete=%u seam_wait_sum_us=%u unit_max_us=%u\n",r,runs[r].workers,
               runs[r].childSleepMs,runs[r].midSleepMs,runs[r].gapMs,d[11],d[22],d[23],d[17],d[18],d[19],d[38]);
        if(r==0) { reference=snapshot; memcpy(referenceLog,dfLog,sizeof(dfLog)); continue; }
        bool same=!strcmp(referenceLog,dfLog);
        for(U w:kDfDeterministic) same=same && reference.ai_deferred_words[w]==d[w];
        Check(same,"identical log, consumption hash and schedule counters under scheduling perturbations and worker counts");
    }
    // K = 2, B = 1: a finished think is consumed only at the seam two ticks after its admission; the planner is busy in
    // between. Stop with a think parked between slices (no native frame) completes and drops it.
    {
        static DfNode x={};
        static U arrayX[1];
        DfBuild(); x={}; x.vtable=A(dfWholeVt); x.id=9; arrayX[0]=A(&x);
        dfPlanner[0x9C/4]=1; dfPlanner[0xA0/4]=A(arrayX); dfPlanner[0xB0/4]=1; dfPlanner[0xB4/4]=A(arrayX);
        dfChildSleepMs=dfMidSleepMs=0; gapMs=0; tickIndex=0;
        config.workers=1; config.ai_deferred=2u|(1u<<NTW2_AI_DEFERRED_BUDGET_SHIFT);
        Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"K=2 generation activates");
        for(U t=0;t<4;++t) tick(dfPlanner,0,0);
        Sleep(50);
        const ULONGLONG stopBegin=GetTickCount64();
        Check(stop(nullptr)==0 && GetTickCount64()-stopBegin<5000,"stop with a think parked between slices completes");
        ntw2_status snapshot={};
        Check(ReadState(state,snapshot),"K=2 telemetry readable");
        const U* d=snapshot.ai_deferred_words;
        Check(!strcmp(dfLog," T1 A9 B9 W9 T2 W9 T3 A9 B9 W9 T4 W9"),"K=2: two slices per think, consumption at the second seam");
        if(strcmp(dfLog," T1 A9 B9 W9 T2 W9 T3 A9 B9 W9 T4 W9")) fprintf(stderr,"K=2 log:%s\n",dfLog);
        Check(d[1]==2 && d[2]==1 && d[3]==2 && d[4]==2 && d[6]==1 && d[7]==1 && d[8]==0 && d[11]==4 && d[12]==2 &&
              d[45]==1 && d[53]==1 && d[40]==3,"K=2: admitted 2, busy 2, one on-time consumption spanning 2 ticks after 2 slices");
    }
    return failures ? 1 : 0;
}

// --grid-probation: the real runtime's vectored handler traps, logs and resumes accesses to a synthetic
// PAGE_NOACCESS range armed through the same handler path the owner window uses for the native cell heads.
typedef U (__stdcall *ntw2_grid_probation_probe_fn)(void* base,U bytes);
static __declspec(noinline) U ProbationRead(const volatile U* p) { return *p; }
static __declspec(noinline) void ProbationWrite(volatile U* p,U value) { *p=value; }
// Distinct instruction (different displacement) so the foreign-thread trap forms its own {EIP, caller} row.
static __declspec(noinline) U ProbationReadNext(const volatile U* p) { return p[1]; }
static DWORD WINAPI ProbationReader(void* raw) { return ProbationReadNext(static_cast<const volatile U*>(raw)); }
static volatile LONG probationSpinStop;
static DWORD WINAPI ProbationSpinReader(void* raw) { // keeps faulting while the main thread toggles and retires
    U sum=0;
    while(!probationSpinStop) sum^=ProbationReadNext(static_cast<const volatile U*>(raw));
    return sum&1;
}
static volatile LONG probationGate, probationReady;
static DWORD WINAPI ProbationGatedReader(void* raw) { // spin-gate: both threads' faults land before any restore
    InterlockedIncrement(&probationReady);
    while(!probationGate) YieldProcessor();
    return ProbationReadNext(static_cast<const volatile U*>(raw));
}
static U PageProtection(const void* p) { MEMORY_BASIC_INFORMATION m={}; return VirtualQuery(p,&m,sizeof(m)) ? m.Protect : 0; }
static int GridProbationFixture(ntw2_start_fn start,ntw2_stop_fn stop,volatile ntw2_status* state,ntw2_config config) {
    auto probe=reinterpret_cast<ntw2_grid_probation_probe_fn>(GetProcAddress(runtimeModule,"ntw2_grid_probation_probe"));
    Check(probe!=nullptr,"grid probation probe export present");
    if(!probe) return 1;
    root[0x2829c]=1; BindLocoScene(true);
    config.enabled_mask=NTW2_LOCO; config.workers=2; config.main_thread_id=GetCurrentThreadId();
    const U owned=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES;
    config.loco_flags=owned|NTW2_LOCO_GRID_PROBATION; Check(start(&config)==1,"probation without the owned grid is refused");
    config.enabled_mask=NTW2_LOCO|NTW2_BALLISTICS; config.loco_flags=owned|NTW2_LOCO_GRID|NTW2_LOCO_GRID_PROBATION;
    Check(start(&config)==1,"probation with the ballistics query cache is refused");
    config.enabled_mask=NTW2_BATCH64; config.loco_flags=NTW2_LOCO_GRID|NTW2_LOCO_GRID_PROBATION;
    Check(start(&config)==1,"probation without the loco feature is refused");
    U* pages=static_cast<U*>(VirtualAlloc(nullptr,4*4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    Check(pages!=nullptr,"synthetic probation pages allocated");
    if(!pages) return 1;
    for(U i=0;i<4*1024;++i) pages[i]=0xC0DE0000u+i;
    Check(probe(pages,4*4096)==0,"probe refused while no probation generation runs");
    config.enabled_mask=NTW2_LOCO; config.loco_flags=owned|NTW2_LOCO_GRID|NTW2_LOCO_GRID_PROBATION;
    Check(start(&config)==0 && WaitActive(state,NTW2_LOCO),"probation generation activates with owned grid");
    ntw2_status snapshot={};
    Check(ReadState(state,snapshot) && snapshot.grid_probation_words[0]==1 && snapshot.grid_probation_words[1]==1 &&
          snapshot.grid_probation_words[2]==0 && snapshot.grid_probation_words[4]==0,
          "detector starts enabled, idle and unarmed until the first owner window closes");
    Check(probe(pages,4*4096)==1,"synthetic range armed through the probation handler");
    Check(probe(pages,4*4096)==0,"a second synthetic arm is refused");
    Check(PageProtection(pages)==PAGE_NOACCESS && PageProtection(pages+3*1024)==PAGE_NOACCESS,"armed pages are PAGE_NOACCESS");
    // Main thread: one read (page 0) and one write (page 1), each trapped once, values intact, then resumed.
    Check(ProbationRead(pages+7)==0xC0DE0007u,"trapped read resumes with the original value");
    ProbationWrite(pages+1024+5,0x5EED0005u);
    Check(pages[1024+5]==0x5EED0005u,"trapped write resumes and lands");
    Check(ProbationRead(pages+9)==0xC0DE0009u,"a restored page no longer traps");
    Check(PageProtection(pages)==PAGE_READWRITE && PageProtection(pages+1024)==PAGE_READWRITE &&
          PageProtection(pages+2*1024)==PAGE_NOACCESS,"only the trapped pages were restored");
    // A foreign thread (no runtime thread class) traps on page 2.
    HANDLE reader=CreateThread(nullptr,0,ProbationReader,pages+2*1024+2,0,nullptr);
    DWORD readerValue=0;
    Check(reader && WaitForSingleObject(reader,5000)==WAIT_OBJECT_0 && GetExitCodeThread(reader,&readerValue) &&
          readerValue==0xC0DE0803u,"foreign-thread trap resumes with the original value");
    if(reader) CloseHandle(reader);
    Check(probe(nullptr,0)==1,"synthetic range disarmed");
    Check(PageProtection(pages+3*1024)==PAGE_READWRITE,"disarm restores the untouched page");
    bool published=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.grid_probation_words[6]==3 && snapshot.grid_probation_words[31]==1) { published=true; break; }
    const U* w=snapshot.grid_probation_words;
    Check(published && w[7]==3 && w[8]==0 && w[9]==1 && w[10]==0 && w[11]==0,"three cell traps (one write), no restore failure or foreign fault");
    Check(w[4]==1 && w[5]==0 && w[14]==4 && w[15]==0 && w[3]==1 && w[30]==1,"one probe arm of four isolated pages; no owner window ran");
    Check(w[25]==0 && w[26]==0 && w[27]==0 && w[28]==2 && w[29]==1,"thread classes: two main-thread traps, one foreign-thread trap");
    Check(w[12]==3 && w[13]==0,"three distinct caller rows recorded, none dropped");
    U rows=0, mainMask=0, otherMask=0, writes=0;
    for(U i=0;i<NTW2_GRID_PROBATION_CALLERS;++i) {
        const U* row=w+NTW2_GRID_PROBATION_HEADER_WORDS+8*i;
        if(!row[4]) continue;
        ++rows; writes+=row[5];
        Check(row[0] && (row[2]&0xF)==3 && row[4]>=1 && (row[2]>>16)==0,"test-module EIP rows carry no clone id");
        if((row[2]>>8)&(1u<<3)) ++mainMask;
        if((row[2]>>8)&(1u<<4)) ++otherMask;
        Check(!(row[6]&0x80000000u),"no routed tick was executing at the trap");
    }
    Check(rows==3 && mainMask==2 && otherMask==1 && writes==1,"rows attribute two main-thread and one foreign-thread instruction");
    // Two threads fault the SAME armed page concurrently. A spin-gate releases both faulting instructions within
    // nanoseconds, well before either vectored handler reaches VirtualProtect, so both threads genuinely trap;
    // the second handler then sees the restore race (page already PAGE_READWRITE) and resumes. Re-arm per
    // iteration (the page is open again after a restore) and require at least one double-trap iteration.
    const U samePageTrapsBefore=3, kSamePageIterations=12;
    U iter=0;
    for(;iter<kSamePageIterations;++iter) {
        Check(probe(pages,4*4096)==1,"synthetic range re-armed for the same-page race");
        probationGate=0; probationReady=0;
        HANDLE pair[2]={};
        for(U t=0;t<2;++t) pair[t]=CreateThread(nullptr,0,ProbationGatedReader,pages+1024+9,0,nullptr);
        DWORD pairValues[2]={};
        // Both readers must be parked at the gate before release, otherwise one thread's whole trap/restore
        // cycle can complete before the other's first instruction and the page is already open.
        for(const ULONGLONG readyEnd=GetTickCount64()+2000;probationReady!=2 && GetTickCount64()<readyEnd;Sleep(0)) {}
        Check(probationReady==2,"same-page readers reached the gate");
        probationGate=1;
        Check(pair[0] && pair[1] && WaitForMultipleObjects(2,pair,TRUE,5000)==WAIT_OBJECT_0 &&
              GetExitCodeThread(pair[0],&pairValues[0]) && GetExitCodeThread(pair[1],&pairValues[1]) &&
              pairValues[0]==0xC0DE040Au && pairValues[1]==0xC0DE040Au,"same-page faults on two threads both resume");
        if(pair[0]) CloseHandle(pair[0]);
        if(pair[1]) CloseHandle(pair[1]);
        if(iter+1<kSamePageIterations) Check(probe(nullptr,0)==1,"same-page iteration disarmed");
    }
    published=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.grid_probation_words[30]==1+iter &&
           snapshot.grid_probation_words[31]==iter) { published=true; break; }
    w=snapshot.grid_probation_words;
    const U trapsAfterSamePage=w[6];
    Check(published && trapsAfterSamePage>samePageTrapsBefore+iter && trapsAfterSamePage<=samePageTrapsBefore+2*iter,
          "gated iterations each trapped once or twice, at least one double (both handlers raced the restore)");
    Check(w[12]==3 && w[29]==trapsAfterSamePage-2 && w[10]==0 && w[11]==0,
          "same-page traps merged into the existing row; no restore failure or foreign fault");
    // Retirement with a fault stream in flight: the spin reader keeps trapping page 2 while the main thread
    // re-arms it behind the handler and then retires the whole span; every raised trap must stay resumable.
    probationSpinStop=0;
    HANDLE spinner=CreateThread(nullptr,0,ProbationSpinReader,pages+2*1024+2,0,nullptr);
    Check(spinner!=nullptr,"pending-fault reader started");
    const ULONGLONG toggleEnd=GetTickCount64()+60;
    while(GetTickCount64()<toggleEnd) {
        DWORD old=0;
        VirtualProtect(pages+2*1024,4096,PAGE_NOACCESS,&old);
        VirtualProtect(pages+2*1024,4096,PAGE_READWRITE,&old);
    }
    Check(probe(nullptr,0)==1,"span retired while faults were in flight");
    probationSpinStop=1;
    Check(spinner && WaitForSingleObject(spinner,5000)==WAIT_OBJECT_0,"pending-fault reader survived retirement");
    if(spinner) CloseHandle(spinner);
    published=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.grid_probation_words[31]==iter+1) { published=true; break; }
    w=snapshot.grid_probation_words;
    Check(published && w[6]>=trapsAfterSamePage && w[10]==0 && w[11]==0,
          "retirement under a pending fault stream: no restore failure or foreign fault");
    // Allocation reuse: the same address range recommitted for a new owner is never claimed by the detector.
    const U trapsBeforeReuse=w[6];
    Check(VirtualFree(pages,0,MEM_RELEASE)!=0,"synthetic pages released before reuse");
    pages=static_cast<U*>(VirtualAlloc(pages,4*4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    Check(pages!=nullptr,"same-address range reallocated");
    if(!pages) return 1;
    for(U i=0;i<4*1024;++i) pages[i]=0xF00D0000u+i;
    HANDLE reuser=CreateThread(nullptr,0,ProbationReader,pages+2*1024+2,0,nullptr);
    DWORD reusedValue=0;
    Check(reuser && WaitForSingleObject(reuser,5000)==WAIT_OBJECT_0 && GetExitCodeThread(reuser,&reusedValue) &&
          reusedValue==0xF00D0803u,"reused allocation reads without interference");
    if(reuser) CloseHandle(reuser);
    Check(ProbationRead(pages+7)==0xF00D0007u,"reused allocation read on the main thread");
    published=false;
    for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(5))
        if(ReadState(state,snapshot) && snapshot.grid_probation_words[6]==trapsBeforeReuse) { published=true; break; }
    Check(published && snapshot.grid_probation_words[11]==0,"reused allocation produced no detector activity");
    Check(stop(nullptr)==0,"probation generation stops");
    Check(ReadState(state,snapshot) && snapshot.grid_probation_words[6]==trapsBeforeReuse && snapshot.grid_probation_words[2]==4,
          "final detector totals are retained and the state is retired after stop");
    Check(probe(pages,4096)==0,"probe refused after stop");
    Check(VirtualFree(pages,0,MEM_RELEASE)!=0,"synthetic pages released");
    printf("native host lifecycle (grid probation): checks=%u failures=%u\n",checks,failures);
    return failures ? 1 : 0;
}

static bool RunChild(const char* image,const char* dllPath,const char* mode) {
    char self[MAX_PATH];
    if(!GetModuleFileNameA(nullptr,self,MAX_PATH)) return false;
    char command[3*MAX_PATH+64];
    if(snprintf(command,sizeof(command),"\"%s\" \"%s\" \"%s\" %s",self,image,dllPath,mode)<=0) return false;
    STARTUPINFOA si={}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    const HANDLE inherited[3]={si.hStdInput,si.hStdOutput,si.hStdError};
    for(HANDLE h:inherited) if(h && h!=INVALID_HANDLE_VALUE) SetHandleInformation(h,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT);
    PROCESS_INFORMATION pi={};
    if(!CreateProcessA(nullptr,command,nullptr,nullptr,TRUE,0,nullptr,nullptr,&si,&pi)) return false;
    DWORD code=1;
    const bool finished=WaitForSingleObject(pi.hProcess,90000)==WAIT_OBJECT_0;
    if(!finished) TerminateProcess(pi.hProcess,3);
    const bool ok=finished && GetExitCodeProcess(pi.hProcess,&code) && code==0;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ok;
}

int main(int argc,char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    const bool child=argc==4 && !strncmp(argv[3],"--",2);
    if(argc!=3 && !child) { fprintf(stderr,"usage: native_runtime_lifecycle Napoleon.exe ntw2_runtime.dll\n"); return 2; }
    HMODULE dll=LoadLibraryA(argv[2]);
    runtimeModule=dll;
    if(!dll || !MapImage(argv[1])) { fprintf(stderr,"cannot load test inputs (%lu)\n",GetLastError()); return 2; }
    auto start=reinterpret_cast<ntw2_start_fn>(GetProcAddress(dll,"ntw2_start"));
    auto stop=reinterpret_cast<ntw2_stop_fn>(GetProcAddress(dll,"ntw2_stop"));
    auto state=reinterpret_cast<volatile ntw2_status*>(GetProcAddress(dll,"ntw2_state"));
    activationBoundary=reinterpret_cast<ntw2_activation_boundary_fn>(GetProcAddress(dll,"ntw2_activation_boundary"));
    if(!start || !stop || !state || !activationBoundary) return 2;
    ntw2_config config={NTW2_ABI,sizeof(config),NTW2_BATCH64,0,A(image),10,0,0,0};
    Check(stop(nullptr)==0,"stop before start");
    Check(start(nullptr)==1,"null configuration refused");
    void* unreadable=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
    Check(unreadable && start(unreadable)==1,"unreadable configuration refused");
    if(unreadable) VirtualFree(unreadable,0,MEM_RELEASE);
    Check(start(&config)==2,"valid 10ms configuration refuses a foreign main image");
    config.poll_ms=9; Check(start(&config)==1,"poll below supported boundary refused"); config.poll_ms=10;
    config.workers=17; Check(start(&config)==1,"unsupported worker count refused"); config.workers=0;
    config.profile_site=NTW2_TIMED_SITES+1; Check(start(&config)==1,"profile site beyond the timed sites refused"); config.profile_site=0;
    config.enabled_mask=0; Check(start(&config)==1,"empty feature set refused");
    config.enabled_mask=0x10000u; Check(start(&config)==1,"undefined feature bit refused");
    config.enabled_mask=NTW2_GRID_CENSUS; config.main_thread_id=GetCurrentThreadId();
    Check(start(&config)==1,"grid census without LOCO refused");
    config.enabled_mask=NTW2_LOCO|NTW2_GRID_CENSUS; config.main_thread_id=0;
    Check(start(&config)==1,"grid census sampler without main thread refused");
    config.enabled_mask=NTW2_COLLIDE_LOD|NTW2_COLLIDE; Check(start(&config)==1,"LOD and replacement solver cannot silently override each other");
    config.enabled_mask=NTW2_COLLIDE_LOD|NTW2_FORMATION; Check(start(&config)==1,"LOD rejects the original-manager formation route");
    config.enabled_mask=NTW2_COLLIDE_LOD; config.collide_lod_m=100001;
    Check(start(&config)==1,"invalid collision LOD distance refused"); config.collide_lod_m=0;
    config.collide_lod_m=NTW2_COLLIDE_CENSUS;
    Check(start(&config)==1,"explicit collision census without PROFILE refused"); config.collide_lod_m=0;
    config.enabled_mask=NTW2_BATCH64; config.collide_flags=NTW2_COLLIDE_CONTACT_SHADOW;
    Check(start(&config)==1,"contact shadow requires the collision solver");
    config.collide_flags=NTW2_COLLIDE_CONTACT_WORKERS;
    Check(start(&config)==1,"contact workers require the collision solver");
    config.enabled_mask=NTW2_COLLIDE; config.workers=2;
    config.collide_flags=NTW2_COLLIDE_CONTACT_SHADOW|NTW2_COLLIDE_CONTACT_WORKERS;
    Check(start(&config)==1,"contact shadow and contact workers are exclusive");
    config.collide_flags=0x4u;
    Check(start(&config)==1,"unknown collide flags refused");
    config.collide_flags=0; config.workers=0;
    config.enabled_mask=NTW2_ARMY_UNIT_SHADOW; Check(start(&config)==1,"army unit shadow alone refused (no routed tick reaches site 18)");
    config.enabled_mask=NTW2_BATCH64|NTW2_VISUAL|NTW2_ARMY_UNIT_SHADOW;
    Check(start(&config)==1,"army unit shadow refused without profile or a simulation feature");
    // Retired puppet probe: its mask bit and the config word at offset 48 are refused.
    config.enabled_mask=0x80000u; Check(start(&config)==1,"retired puppet mask bit refused");
    config.enabled_mask=NTW2_BATCH64; config.va_watch_flags=0x4u; Check(start(&config)==1,"unknown va_watch_flags bit 2 refused");
    config.va_watch_flags=0x10000u; Check(start(&config)==1,"unknown va_watch_flags bit 16 refused");
    config.va_watch_flags=NTW2_VA_WATCH; Check(start(&config)==2,"--va-watch passes validation and refuses a foreign main image");
    config.va_watch_flags=NTW2_VA_WATCH|NTW2_ARMY_STORM_CENSUS; Check(start(&config)==1,"census beside --va-watch still needs a routed tick");
    // --army-storm-census / --army-storm-sample-ms validation: routed tick + main thread, exclusive with the shadow, threshold needs
    // census + PROFILE + profile_site 19 (site 18), only the defined bits.
    config.main_thread_id=GetCurrentThreadId();
    config.enabled_mask=NTW2_PATH; config.va_watch_flags=NTW2_ARMY_STORM_CENSUS;
    Check(start(&config)==1,"storm census refused on a mask without the manager-routed tick (PATH only)");
    config.enabled_mask=NTW2_BATCH64|NTW2_VISUAL; config.va_watch_flags=NTW2_ARMY_STORM_CENSUS;
    Check(start(&config)==1,"storm census refused without a routed tick");
    config.enabled_mask=NTW2_AI_ASYNC; config.main_thread_id=0;
    Check(start(&config)==1,"storm census refused without a main thread id");
    config.main_thread_id=GetCurrentThreadId();
    config.enabled_mask=NTW2_PROFILE|NTW2_ARMY_UNIT_SHADOW;
    Check(start(&config)==1,"storm census and the army unit shadow are exclusive");
    config.enabled_mask=NTW2_PROFILE; Check(start(&config)==2,"storm census with PROFILE passes validation and refuses a foreign main image");
    config.enabled_mask=NTW2_AI_ASYNC; Check(start(&config)==2,"storm census with a simulation feature passes validation");
    config.va_watch_flags=NTW2_ARMY_STORM_CENSUS|0x10000u; config.enabled_mask=NTW2_PROFILE;
    Check(start(&config)==1,"unknown va_watch_flags bit refused beside the census");
    config.va_watch_flags=5u<<NTW2_ARMY_STORM_SAMPLE_SHIFT; config.profile_site=19;
    Check(start(&config)==1,"storm sample threshold without the census refused");
    config.va_watch_flags=NTW2_ARMY_STORM_CENSUS|(5u<<NTW2_ARMY_STORM_SAMPLE_SHIFT); config.enabled_mask=NTW2_AI_ASYNC;
    Check(start(&config)==1,"storm sample threshold without PROFILE refused");
    config.enabled_mask=NTW2_PROFILE; config.profile_site=0;
    Check(start(&config)==1,"storm sample threshold without a selected site refused");
    config.profile_site=18; Check(start(&config)==1,"storm sample threshold with the wrong profile site (index 17) refused");
    config.profile_site=20; Check(start(&config)==1,"storm sample threshold with the wrong profile site (index 19) refused");
    config.profile_site=19; Check(start(&config)==2,"storm sample threshold with census, PROFILE and site 18 passes validation");
    config.va_watch_flags=NTW2_ARMY_STORM_CENSUS|NTW2_ARMY_STORM_SAMPLE_MASK; Check(start(&config)==2,"storm sample threshold 255 ms passes validation");
    // --tick-pcore / --tick-core-ab validation: routed tick only, one placement mode at a time.
    config.profile_site=0; config.enabled_mask=NTW2_BATCH64|NTW2_VISUAL; config.va_watch_flags=NTW2_TICK_PCORE;
    Check(start(&config)==1,"tick placement refused without a routed tick");
    config.enabled_mask=NTW2_AI_ASYNC; Check(start(&config)==2,"tick placement with a simulation feature passes validation");
    config.enabled_mask=NTW2_PROFILE; config.va_watch_flags=NTW2_TICK_CORE_AB;
    Check(start(&config)==2,"tick core A/B with PROFILE passes validation");
    config.va_watch_flags=NTW2_TICK_PCORE|NTW2_TICK_CORE_AB; Check(start(&config)==1,"tick placement modes are exclusive");
    // --army-solver-memo / --army-solver-shadow validation: manager-routed tick and main thread id, one mode at a time, compatible with the storm census.
    config.main_thread_id=GetCurrentThreadId(); config.profile_site=0; config.enabled_mask=NTW2_BATCH64|NTW2_VISUAL; config.va_watch_flags=NTW2_ARMY_SOLVER_MEMO;
    Check(start(&config)==1,"solver memo refused without a routed tick");
    config.enabled_mask=NTW2_PROFILE; Check(start(&config)==2,"solver memo with PROFILE passes validation and refuses a foreign main image");
    config.va_watch_flags=NTW2_ARMY_SOLVER_SHADOW; Check(start(&config)==2,"solver shadow with PROFILE passes validation");
    config.va_watch_flags=NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_SOLVER_SHADOW; Check(start(&config)==1,"solver memo and shadow are exclusive");
    config.va_watch_flags=NTW2_ARMY_SOLVER_MEMO|NTW2_ARMY_STORM_CENSUS; Check(start(&config)==2,"solver memo is compatible with the storm census");
    config.va_watch_flags=NTW2_ARMY_SOLVER_SHADOW|NTW2_ARMY_STORM_CENSUS; Check(start(&config)==2,"solver shadow is compatible with the storm census");
    config.enabled_mask=NTW2_AI_ASYNC; config.va_watch_flags=NTW2_ARMY_SOLVER_MEMO; Check(start(&config)==2,"solver memo with a simulation feature passes validation");
    config.main_thread_id=0; Check(start(&config)==1,"solver refused without a main thread id");
    config.main_thread_id=GetCurrentThreadId(); config.va_watch_flags=NTW2_ARMY_SOLVER_MEMO|0x10000u; Check(start(&config)==1,"unknown va_watch_flags bit refused beside the solver");
    config.va_watch_flags=0; config.profile_site=0; config.main_thread_id=0;
    // --ai-ctrl-* validation: routed tick, census shadow-only, verify needs a live feature, no ai_ctrl/ai_async2, known bits only.
    config.enabled_mask=NTW2_AI_ASYNC; config.ai_ctrl_flags=NTW2_AI_CTRL_HISTOGRAM;
    Check(start(&config)==2,"ai-ctrl histogram passes validation and refuses a foreign main image");
    config.ai_ctrl_flags=NTW2_AI_CTRL_HISTOGRAM|NTW2_AI_CTRL_GEOMETRY|NTW2_AI_CTRL_VERIFY;
    Check(start(&config)==2,"ai-ctrl histogram+geometry+verify passes validation");
    config.ai_ctrl_flags=NTW2_AI_CTRL_CENSUS; Check(start(&config)==2,"ai-ctrl census passes validation");
    config.ai_ctrl_flags=NTW2_AI_CTRL_CENSUS|NTW2_AI_CTRL_HISTOGRAM; Check(start(&config)==1,"ai-ctrl census is shadow-only");
    config.ai_ctrl_flags=NTW2_AI_CTRL_VERIFY; Check(start(&config)==1,"ai-ctrl verify alone refused");
    config.ai_ctrl_flags=NTW2_AI_CTRL_FLAGS_VALID+1; Check(start(&config)==1,"ai-ctrl unknown flag bit refused");
    config.ai_ctrl_flags=NTW2_AI_CTRL_HISTOGRAM; config.enabled_mask=NTW2_BATCH64;
    Check(start(&config)==1,"ai-ctrl without a routed tick refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2; Check(start(&config)==1,"ai-ctrl excludes ai_async2");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_CTRL; Check(start(&config)==1,"ai-ctrl excludes the controller offload");
    config.ai_ctrl_flags=0;
    // --ai-claim-once (ai_ctrl_flags bit 8): same routed-tick / exclusion rules as the --ai-ctrl modes, composes with them.
    config.enabled_mask=NTW2_AI_ASYNC; config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE;
    Check(start(&config)==2,"ai-claim-once passes validation and refuses a foreign main image");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE|NTW2_AI_CTRL_HISTOGRAM; Check(start(&config)==2,"ai-claim-once combines with an --ai-ctrl mode");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE|NTW2_AI_CTRL_VERIFY; Check(start(&config)==1,"ai-claim-once does not relax the --ai-ctrl-verify rule");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE|0x10u; Check(start(&config)==1,"ai-claim-once beside an unknown ai_ctrl bit refused");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE_CENSUS; Check(start(&config)==2,"ai-claim-once-census passes validation");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE|NTW2_AI_CLAIM_ONCE_CENSUS; Check(start(&config)==1,"ai-claim-once and its census are exclusive");
    config.ai_ctrl_flags=NTW2_AI_RETARGET_JITTER<<1; Check(start(&config)==1,"bits 13..15 are reserved");
    config.ai_ctrl_flags=NTW2_AI_CLAIM_ONCE; config.enabled_mask=NTW2_BATCH64;
    Check(start(&config)==1,"ai-claim-once without a routed tick refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2; Check(start(&config)==1,"ai-claim-once excludes ai_async2");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_CTRL; Check(start(&config)==1,"ai-claim-once excludes the controller offload");
    config.ai_ctrl_flags=0;
    // --brain-target-cull-shadow / --brain-target-cull / --brain-retarget-jitter (bits 10..12): same routed-tick / exclusion rules, compose with the claim bits.
    config.enabled_mask=NTW2_AI_ASYNC; config.ai_ctrl_flags=NTW2_AI_RETARGET_JITTER;
    Check(start(&config)==2,"brain-retarget-jitter passes validation and refuses a foreign main image");
    config.ai_ctrl_flags=NTW2_AI_TARGET_CULL; Check(start(&config)==2,"brain-target-cull passes validation");
    config.ai_ctrl_flags=NTW2_AI_TARGET_CULL_SHADOW; Check(start(&config)==2,"brain-target-cull-shadow passes validation");
    config.ai_ctrl_flags=NTW2_AI_TARGET_CULL|NTW2_AI_RETARGET_JITTER|NTW2_AI_CLAIM_ONCE; Check(start(&config)==2,"the brain-step levers compose with each other and the claim bit");
    config.ai_ctrl_flags=NTW2_AI_TARGET_CULL|NTW2_AI_TARGET_CULL_SHADOW; Check(start(&config)==1,"brain-target-cull and its shadow are exclusive");
    config.ai_ctrl_flags=NTW2_AI_RETARGET_JITTER|NTW2_AI_CTRL_GEOMETRY; Check(start(&config)==1,"the brain-step levers exclude the geometry mode (shared status words 16..23)");
    config.ai_ctrl_flags=NTW2_AI_RETARGET_JITTER|NTW2_AI_CTRL_HISTOGRAM; Check(start(&config)==2,"brain-retarget-jitter combines with the histogram mode");
    config.ai_ctrl_flags=NTW2_AI_RETARGET_JITTER; config.enabled_mask=NTW2_BATCH64;
    Check(start(&config)==1,"brain-retarget-jitter without a routed tick refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2; Check(start(&config)==1,"brain-retarget-jitter excludes ai_async2");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_CTRL; Check(start(&config)==1,"brain-retarget-jitter excludes the controller offload");
    config.ai_ctrl_flags=0;
    // --ai-prepass-*: routed tick, no ai_async2, census combines only with presize, known bits only.
    config.enabled_mask=NTW2_AI_ASYNC; config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS;
    Check(start(&config)==2,"ai-prepass census passes validation and refuses a foreign main image");
    config.ai_prepass_flags=NTW2_AI_PRESIZE; Check(start(&config)==2,"ai-presize passes validation");
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_PRESIZE; Check(start(&config)==2,"ai-prepass census+presize passes validation");
    config.ai_prepass_flags=NTW2_AI_POLY_SHADOW; Check(start(&config)==2,"ai-poly-shadow passes validation");
    config.ai_prepass_flags=NTW2_AI_POLY; Check(start(&config)==2,"ai-poly passes validation");
    config.ai_prepass_flags=NTW2_AI_POLY|NTW2_AI_PRESIZE; Check(start(&config)==2,"ai-poly combines with presize");
    config.ai_prepass_flags=NTW2_AI_POLY_SHADOW|NTW2_AI_POLY; Check(start(&config)==1,"ai-poly-shadow and ai-poly exclude each other");
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY; Check(start(&config)==1,"ai-poly excludes the census");
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY_SHADOW; Check(start(&config)==1,"ai-poly-shadow excludes the census");
    config.ai_prepass_flags=NTW2_AI_PREPASS_FLAGS_VALID+1; Check(start(&config)==1,"ai-prepass unknown flag bit refused");
    config.ai_prepass_flags=0x80; Check(start(&config)==1,"ai-prepass bit 0x80 refused");
    config.ai_prepass_flags=NTW2_AI_POLY|NTW2_AI_RECORD_TEST; Check(start(&config)==2,"ai-record-test passes validation with ai-poly");
    config.ai_prepass_flags=NTW2_AI_POLY_SHADOW|NTW2_AI_RECORD_TEST_SHADOW; Check(start(&config)==2,"ai-record-test-shadow passes validation with ai-poly-shadow");
    config.ai_prepass_flags=NTW2_AI_POLY|NTW2_AI_RECORD_TEST|NTW2_AI_PRESIZE|(200u<<NTW2_AI_SPIRAL_CAP_SHIFT); Check(start(&config)==2,"ai-record-test combines with presize and the spiral cap");
    config.ai_prepass_flags=NTW2_AI_RECORD_TEST; Check(start(&config)==1,"ai-record-test without a poly bit refused");
    config.ai_prepass_flags=NTW2_AI_RECORD_TEST_SHADOW; Check(start(&config)==1,"ai-record-test-shadow without a poly bit refused");
    config.ai_prepass_flags=NTW2_AI_POLY|NTW2_AI_RECORD_TEST|NTW2_AI_RECORD_TEST_SHADOW; Check(start(&config)==1,"ai-record-test-shadow and ai-record-test exclude each other");
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_POLY|NTW2_AI_RECORD_TEST; Check(start(&config)==1,"ai-record-test excludes the census");
    config.ai_prepass_flags=NTW2_AI_SPIRAL_CENSUS; Check(start(&config)==2,"ai-spiral-census passes validation");
    config.ai_prepass_flags=200u<<NTW2_AI_SPIRAL_CAP_SHIFT; Check(start(&config)==2,"ai-spiral-cap-m 200 passes validation");
    config.ai_prepass_flags=0xFFFFu<<NTW2_AI_SPIRAL_CAP_SHIFT; Check(start(&config)==2,"ai-spiral-cap-m 65535 passes validation");
    config.ai_prepass_flags=NTW2_AI_SPIRAL_CAP_MIN_M<<NTW2_AI_SPIRAL_CAP_SHIFT; Check(start(&config)==2,"ai-spiral-cap-m 20 passes validation");
    config.ai_prepass_flags=19u<<NTW2_AI_SPIRAL_CAP_SHIFT; Check(start(&config)==1,"ai-spiral-cap-m below the first ring refused");
    config.ai_prepass_flags=1u<<NTW2_AI_SPIRAL_CAP_SHIFT; Check(start(&config)==1,"ai-spiral-cap-m 1 refused");
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS|NTW2_AI_SPIRAL_CENSUS|(200u<<NTW2_AI_SPIRAL_CAP_SHIFT); Check(start(&config)==2,"ai-spiral combines with the prepass census");
    config.ai_prepass_flags=NTW2_AI_POLY|NTW2_AI_PRESIZE|(200u<<NTW2_AI_SPIRAL_CAP_SHIFT); Check(start(&config)==2,"ai-spiral combines with ai-poly and presize");
    config.ai_prepass_flags=200u<<NTW2_AI_SPIRAL_CAP_SHIFT; config.enabled_mask=NTW2_BATCH64;
    Check(start(&config)==1,"ai-spiral without a routed tick refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2; Check(start(&config)==1,"ai-spiral excludes ai_async2");
    config.enabled_mask=NTW2_AI_ASYNC;
    config.ai_prepass_flags=NTW2_AI_PREPASS_CENSUS; config.enabled_mask=NTW2_BATCH64;
    Check(start(&config)==1,"ai-prepass without a routed tick refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_ASYNC2; Check(start(&config)==1,"ai-prepass excludes ai_async2");
    config.ai_prepass_flags=0;
    config.enabled_mask=NTW2_BRAIN; config.main_thread_id=1; Check(start(&config)==1,"brain profiling without profile refused"); config.main_thread_id=0;
    config.enabled_mask=NTW2_AI_CTRL; Check(start(&config)==1,"controller offload without ai refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_BUDGET_EMA; Check(start(&config)==1,"retired EMA budget refused with ai");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_SAFE_PARK; Check(start(&config)==1,"retired unsafe parking refused with ai");
    config.enabled_mask=NTW2_BATCH64; config.brain_flags=NTW2_BRAIN_CENSUS;
    Check(start(&config)==1,"brain census requires brain2");
    config.brain_flags=NTW2_BRAIN_TIMING;
    Check(start(&config)==1,"brain timing requires brain2");
    config.brain_flags=NTW2_BRAIN_NODE_SHADOW;
    Check(start(&config)==1,"node shadow requires brain2");
    config.brain_flags=NTW2_BRAIN_FIRE_SHADOW;
    Check(start(&config)==1,"sequence shadow requires brain2");
    config.enabled_mask=NTW2_BRAIN2; config.brain_flags=16u;
    Check(start(&config)==1,"brain parallel without census or quiet refused");
    config.brain_flags=0x100000u;
    Check(start(&config)==1,"unknown brain flags refused");
    {
        // Per-unit brain slices: every refusal is a pure validation result (no activation).
        const U unit=NTW2_BRAIN_UNIT_FATIGUE;
        const U bad[]={unit|NTW2_BRAIN_CENSUS,unit|NTW2_BRAIN_TIMING,unit|NTW2_BRAIN_NODE_SHADOW,unit|NTW2_BRAIN_FIRE_SHADOW,
                       unit|NTW2_BRAIN_FINALIZER_SHADOW,unit|NTW2_BRAIN_UNIT_SHADOW,unit|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_CENSUS,
                       unit|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET,NTW2_BRAIN_UNIT_FATIGUE_SHADOW,NTW2_BRAIN_UNIT_POSTURE_SHADOW,
                       NTW2_BRAIN_UNIT_ENGAGE_SHADOW};
        config.workers=2;
        for (unsigned k=0;k<sizeof(bad)/sizeof(bad[0]);++k) { config.brain_flags=bad[k]; Check(start(&config)==1,"unit brain flag combination refused"); }
        config.workers=0;
        const U saved=config.enabled_mask;
        config.enabled_mask=NTW2_BATCH64; config.brain_flags=unit; Check(start(&config)==1,"unit brain flag requires brain2");
        config.enabled_mask=saved;
    }
    config.brain_flags=NTW2_BRAIN_UNIT_SHADOW|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_CENSUS; config.workers=2;
    Check(start(&config)==1,"unit shadow with brain parallel refused");
    config.brain_flags=NTW2_BRAIN_UNIT_SHADOW|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET;
    Check(start(&config)==1,"unit shadow with brain quiet refused");
    {
        const U others[]={NTW2_BRAIN_CENSUS,NTW2_BRAIN_TIMING,NTW2_BRAIN_NODE_SHADOW,NTW2_BRAIN_FIRE_SHADOW,
                          NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET,NTW2_BRAIN_FINALIZER_SHADOW,NTW2_BRAIN_UNIT_SHADOW};
        for (unsigned k=0;k<sizeof(others)/sizeof(others[0]);++k) {
            config.brain_flags=NTW2_BRAIN_S0|others[k];
            Check(start(&config)==1,"brain S0 excludes every other brain flag");
        }
    }
    config.enabled_mask=NTW2_BATCH64; config.brain_flags=NTW2_BRAIN_S0;
    Check(start(&config)==1,"brain S0 requires brain2");
    {
        // --brain-locality owns the occurrence call and the S0 status row; its modifiers need the base bit and exclude each other.
        const U L=NTW2_BRAIN_LOCALITY;
        const U bad[]={L|NTW2_BRAIN_CENSUS,L|NTW2_BRAIN_TIMING,L|NTW2_BRAIN_NODE_SHADOW,L|NTW2_BRAIN_FIRE_SHADOW,
                       L|NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET,L|NTW2_BRAIN_FINALIZER_SHADOW,L|NTW2_BRAIN_UNIT_SHADOW,L|NTW2_BRAIN_S0,
                       L|NTW2_BRAIN_UNIT_FATIGUE,L|NTW2_BRAIN_UNIT_POSTURE,L|NTW2_BRAIN_UNIT_ENGAGE,
                       NTW2_BRAIN_LOCALITY_WARM,NTW2_BRAIN_LOCALITY_PREFETCH,NTW2_BRAIN_LOCALITY_PREFETCH2,
                       L|NTW2_BRAIN_LOCALITY_WARM|NTW2_BRAIN_LOCALITY_PREFETCH,L|NTW2_BRAIN_LOCALITY_PREFETCH|NTW2_BRAIN_LOCALITY_PREFETCH2,
                       L|NTW2_BRAIN_LOCALITY_WARM|NTW2_BRAIN_LOCALITY_PREFETCH2,
                       L|NTW2_BRAIN_LOCALITY_WARM|NTW2_BRAIN_LOCALITY_PREFETCH|NTW2_BRAIN_LOCALITY_PREFETCH2,0x100000u|L,
                       NTW2_BRAIN_LOCALITY_MARK,L|NTW2_BRAIN_LOCALITY_MARK|NTW2_BRAIN_LOCALITY_WARM,
                       L|NTW2_BRAIN_LOCALITY_MARK|NTW2_BRAIN_LOCALITY_PREFETCH,L|NTW2_BRAIN_LOCALITY_MARK|NTW2_BRAIN_LOCALITY_PREFETCH2,
                       L|NTW2_BRAIN_LOCALITY_MARK|NTW2_BRAIN_S0,L|NTW2_BRAIN_LOCALITY_MARK|NTW2_BRAIN_CENSUS};
        config.enabled_mask=NTW2_BRAIN2; config.workers=2;
        for (unsigned k=0;k<sizeof(bad)/sizeof(bad[0]);++k) { config.brain_flags=bad[k]; Check(start(&config)==1,"locality flag combination refused"); }
        config.workers=0;
        config.enabled_mask=NTW2_BATCH64; config.brain_flags=L; Check(start(&config)==1,"locality requires brain2");
        config.brain_flags=L|NTW2_BRAIN_LOCALITY_WARM; Check(start(&config)==1,"locality warm requires brain2");
    }
    config.enabled_mask=NTW2_BATCH64; config.brain_flags=NTW2_BRAIN_UNIT_SHADOW;
    Check(start(&config)==1,"unit shadow requires brain2");
    config.enabled_mask=NTW2_BRAIN2;
    config.workers=2;
    config.brain_flags=NTW2_BRAIN_QUIET;
    Check(start(&config)==1,"brain quiet without parallel refused");
    config.brain_flags=NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET|NTW2_BRAIN_CENSUS;
    Check(start(&config)==1,"brain quiet with census refused");
    config.brain_flags=NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET|NTW2_BRAIN_TIMING;
    Check(start(&config)==1,"brain quiet with timing refused");
    config.brain_flags=NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET|NTW2_BRAIN_FINALIZER_SHADOW;
    Check(start(&config)==1,"brain quiet with a shadow refused");
    config.workers=0; config.brain_flags=NTW2_BRAIN_PARALLEL|NTW2_BRAIN_QUIET;
    Check(start(&config)==1,"brain quiet parallel without workers refused");
    config.brain_flags=0;
    config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE; Check(start(&config)==1,"combined loco and collision require explicit owned grid and movement flags");
    config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE_LOD; Check(start(&config)==1,"loco and collision LOD are refused");
    config.enabled_mask=NTW2_LOCO|NTW2_PROFILE|NTW2_BRAIN; config.main_thread_id=1;
    Check(start(&config)==1,"loco and brain profiling slots are refused"); config.main_thread_id=0;
    config.enabled_mask=NTW2_BATCH64; config.loco_flags=NTW2_LOCO_CLONE; Check(start(&config)==1,"loco clone flag without the loco feature refused");
    config.loco_flags=NTW2_LOCO_PARALLEL; Check(start(&config)==1,"loco parallel flag without the loco feature refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL; Check(start(&config)==1,"loco parallel and clone flags without the loco feature refused");
    config.loco_flags=NTW2_LOCO_GRID; Check(start(&config)==1,"loco grid without the loco feature refused");
    config.loco_flags=NTW2_LOCO_GRID_VERIFY; Check(start(&config)==1,"grid verification without the loco feature refused");
    config.enabled_mask=NTW2_LOCO; config.loco_flags=NTW2_LOCO_PARALLEL; Check(start(&config)==1,"loco parallel without clone refused");
    config.loco_flags=NTW2_LOCO_SHADOW; Check(start(&config)==1,"loco shadow without clone refused");
    config.loco_flags=NTW2_LOCO_GRID|NTW2_LOCO_PARALLEL; Check(start(&config)==1,"grid does not relax parallel's clone dependency");
    config.loco_flags=NTW2_LOCO_GRID|NTW2_LOCO_QUIET; Check(start(&config)==1,"grid does not relax quiet's owned-service dependency");
    config.loco_flags=NTW2_LOCO_RELINK_SHADOW; Check(start(&config)==1,"relink shadow without owned services and grid refused");
    config.loco_flags=NTW2_LOCO_GRID_INCREMENTAL; Check(start(&config)==1,"incremental grid without the grid refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID_INCREMENTAL; Check(start(&config)==1,"incremental grid with owned services but without the grid refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_RELINK_WORKERS; Check(start(&config)==1,"relink workers without the grid refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_GRID|NTW2_LOCO_RELINK_WORKERS; Check(start(&config)==1,"relink workers without owned services refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID|NTW2_LOCO_RELINK_SHADOW|NTW2_LOCO_RELINK_WORKERS; Check(start(&config)==1,"relink shadow and workers are exclusive");
    config.loco_flags=NTW2_LOCO_OWNED_SERVICES; Check(start(&config)==1,"loco owned services without clone and parallel refused");
    config.loco_flags=NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet without clone, parallel and owned services refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet without owned services refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_SHADOW|NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet with shadow but without owned services refused");
    config.loco_flags=NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet with owned services but without clone and parallel refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet with owned services and clone but without parallel refused");
    config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_OWNED_SERVICES; Check(start(&config)==1,"loco owned services without parallel refused");
    config.loco_flags=NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES; Check(start(&config)==1,"loco owned services with parallel but without clone refused");
    config.enabled_mask=NTW2_BATCH64; config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES; Check(start(&config)==1,"loco owned services without the loco feature refused");
    config.enabled_mask=NTW2_BATCH64; config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET; Check(start(&config)==1,"loco quiet without the loco feature refused");
    config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE; config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL;
    Check(start(&config)==1,"combined loco and collision without owned services and grid refused");
    const U combinedFlags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID;
    const U requiredFlags[]={NTW2_LOCO_CLONE,NTW2_LOCO_PARALLEL,NTW2_LOCO_OWNED_SERVICES,NTW2_LOCO_GRID};
    for(U missing:requiredFlags) {
        config.loco_flags=combinedFlags&~missing;
        Check(start(&config)==1,"combined mode rejects each missing requirement");
    }
    config.loco_flags=combinedFlags|NTW2_LOCO_GRID_VERIFY;
    config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE|NTW2_COLLIDE_LOD;
    Check(start(&config)==1,"complete combined flags do not relax collision LOD exclusion");
    config.enabled_mask=NTW2_LOCO; config.loco_flags=NTW2_LOCO_FLAGS_VALID<<1; Check(start(&config)==1,"undefined loco flag refused");
    config.loco_flags=0;
    config.enabled_mask=NTW2_AI_CENSUS; config.main_thread_id=GetCurrentThreadId(); Check(start(&config)==1,"ai census without ai refused");
    config.enabled_mask=NTW2_AI_ASYNC|NTW2_AI_CENSUS; config.main_thread_id=0; Check(start(&config)==1,"ai census without a main thread id refused");
    config.main_thread_id=0;
    config.enabled_mask=NTW2_BATCH64;
    ntw2_status snapshot={};
    Check(ReadState(state,snapshot) && snapshot.phase==NTW2_IDLE && !snapshot.retained_bytes,"rejected starts publish no runtime resources");
    U* import=ModuleImport(dll,"GetModuleHandleW");
    if(!import) { fprintf(stderr,"main-module identity import not found\n"); return 2; }
    const U originalImport=*import;
    Check(Replace(import,A(reinterpret_cast<void*>(&TestModule))),"install owned-image identity fixture");
    Put(engine,0xf8,A(root)); Put(root,8,A(model)); Put(model,0,A(root));
    Put(model,0xB0,A(armyManager)); Put(armyManager,0,A(root)); BindLocoScene(true);
    *At(0x14a418c)=A(engine);
    Check(RedirectImage(0x444b40,reinterpret_cast<const void*>(&TestAllocate)) &&
          RedirectImage(0xff7ef0,reinterpret_cast<const void*>(&TestFree)),"install owned-image allocation probes");
    Check(InstallAllocatorTlsFixture(),"bind executable CRT TLS lookup to the owned-process TLS block");
    if(child) {
        if(!strcmp(argv[3],"--grid-census")) return GridCensusFixture(false,start,stop,state,config);
        if(!strcmp(argv[3],"--grid-census-late-enable")) return GridCensusFixture(true,start,stop,state,config);
        if(!strcmp(argv[3],"--allocator-pool-fault")) return AllocatorFailureFixture(false,1,start,stop,state,config);
        if(!strcmp(argv[3],"--allocator-ai-fault")) return AllocatorFailureFixture(true,1,start,stop,state,config);
        if(!strcmp(argv[3],"--allocator-free-fault")) return AllocatorFailureFixture(false,2,start,stop,state,config);
        if(!strcmp(argv[3],"--visual-native-arenas")) return VisualArenaFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--ai-completion")) return AiCompletionFixture(false,start,stop,state,config);
        if(!strcmp(argv[3],"--ai-completion-controller")) return AiCompletionFixture(true,start,stop,state,config);
        if(!strcmp(argv[3],"--ai-census")) return AiCensusFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--ai-prepass")) return AiPrepassFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--ai-async2")) return AiAsync2Fixture(start,stop,state,config);
        if(!strcmp(argv[3],"--ai-deferred")) return AiDeferredFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--loco-owned-activation-refusal")) return LocoOwnedActivationRefusalFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--va-budget")) return VirtualBudgetFixture(false,start,stop,state,config);
        if(!strcmp(argv[3],"--va-budget-post")) return VirtualBudgetFixture(true,start,stop,state,config);
        if(!strcmp(argv[3],"--va-budget-periodic")) return PeriodicBudgetFixture(start,stop,state,config);
        if(!strcmp(argv[3],"--grid-probation")) return GridProbationFixture(start,stop,state,config);
        return !strcmp(argv[3],"--install-conflict") ? InstallConflict(start,stop,state,config) : VisualFixture(argv[3],start,stop,state,config);
    }
    if(!failures) Check(RunChild(argv[1],argv[2],"--grid-census"),"census-first lifecycle child passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--grid-census-late-enable"),"late census admission refusal child passed");
    U* slot=At(0x1345374);
    const U original=0x78bac0+delta;
    Check(*slot==original && ReadOnly(slot),"pristine read-only batch worker slot");
    U retained=0;
    for(unsigned i=0;i<80 && !failures;++i) {
        Check(start(&config)==0,"start/restart accepted");
        Check(WaitActive(state),"batch hook became active");
        Check(*slot!=original && ReadOnly(slot),"published hook retains read-only protection");
        Check(start(&config)==1,"duplicate start refused");
        Check(stop(nullptr)==0,"stop joins the monitor");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask && !snapshot.root,"stopped snapshot published");
        Check(*slot==original && ReadOnly(slot),"original slot and protection restored");
        if(!i) retained=snapshot.retained_bytes;
        else Check(snapshot.retained_bytes==retained,"restart reuses the clone allocation");
        Check(stop(nullptr)==0,"stop is idempotent");
    }
    for(unsigned i=0;i<80 && !failures;++i) {
        Check(start(&config)==0,"immediate restart accepted");
        Check(stop(nullptr)==0,"immediate cancellation joins the monitor");
        Check(*slot==original && ReadOnly(slot),"immediate cancellation leaves no hook");
    }
    for(unsigned i=0;i<32 && !failures;++i) {
        Check(start(&config)==0 && WaitActive(state),"start for concurrent stop/restart");
        StopCall call={stop,0xffffffffu};
        HANDLE stopper=CreateThread(nullptr,0,ConcurrentStop,&call,0,nullptr);
        Check(stopper!=nullptr,"create concurrent stop caller");
        if(!stopper) break;
        const ULONGLONG deadline=GetTickCount64()+3000;
        bool stopped=false;
        while(GetTickCount64()<deadline) {
            if(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED) { stopped=true; break; }
            YieldProcessor();
        }
        Check(stopped,"monitor publishes stopped phase");
        Check(stop(nullptr)==0,"concurrent stop acknowledgement joins the same monitor");
        Check(start(&config)==0,"restart cannot race the old monitor tail");
        Check(WaitForSingleObject(stopper,3000)==WAIT_OBJECT_0 && call.result==0,"first stop caller completed");
        CloseHandle(stopper);
        Check(stop(nullptr)==0,"stop the restarted generation");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && *slot==original,"no false completion from an old generation");
    }
    if(!failures) {
        U* walkSlot=At(0x133e2dc);
        const U walkOriginal=0x702bb0+delta;
        Check(*walkSlot==walkOriginal && ReadOnly(walkSlot),"pristine read-only planner state slot");
        config.enabled_mask=NTW2_PROFILE; config.main_thread_id=GetCurrentThreadId();
        Check(start(&config)==0 && WaitActive(state,NTW2_PROFILE),"profile publishes primary walk route");
        Check(*walkSlot!=walkOriginal && ReadOnly(walkSlot),"planner gate retains read-only slot protection");
        Check(stop(nullptr)==0,"profile stop joins sampler and owner monitor");
        Check(*walkSlot==walkOriginal && ReadOnly(walkSlot),"planner slot and protection restored");
        config.enabled_mask=NTW2_BATCH64; config.main_thread_id=0;
    }
    if(!failures) {
        // NTW2_BRAIN: slot +0x0C of all 23 registry vtables is published (read-only protection retained) and restored with the
        // runtime; without the feature none is touched; no counter moves without work (no tick runs in the owned image).
        U* cells[NTW2_BRAIN_SLOTS];
        bool pristine=true;
        for(unsigned i=0;i<NTW2_BRAIN_SLOTS;++i) { cells[i]=At(kBrain[i].table+0x0c); pristine=pristine && *cells[i]==kBrain[i].original+delta && ReadOnly(cells[i]); }
        Check(pristine,"all 23 registry vtable slots +0x0C pristine and read-only");
        config.main_thread_id=GetCurrentThreadId();
        for(unsigned cycle=0;cycle<12 && !failures;++cycle) {
            const bool brain=(cycle&1)==0;
            config.enabled_mask=NTW2_PROFILE|(brain ? NTW2_BRAIN : 0u);
            Check(start(&config)==0 && WaitActive(state,config.enabled_mask),"brain profiling cycle became active");
            U entry[5]={};
            bool published=true, consistent=true;
            for(unsigned i=0;i<NTW2_BRAIN_SLOTS;++i) {
                const U cur=*cells[i], orig=kBrain[i].original+delta;
                published=published && ReadOnly(cells[i]);
                if(!brain) { published=published && cur==orig; continue; }
                unsigned family=5;
                for(unsigned f=0;f<5;++f) if(kBrain[i].original==kBrainFamilyOriginal[f]) family=f;
                published=published && cur!=orig && InRuntime(cur) && family<5;
                if(family<5) { if(!entry[family]) entry[family]=cur; else consistent=consistent && entry[family]==cur; }
            }
            bool distinct=true;
            if(brain) for(unsigned a=0;a<5;++a) for(unsigned b=a+1;b<5;++b) distinct=distinct && entry[a] && entry[b] && entry[a]!=entry[b];
            Check(published,brain ? "all 23 brain slots published read-only to entry thunks" : "profile alone leaves every brain slot untouched");
            Check(consistent && distinct,"slots of one family share one entry, families differ");
            Check(ReadState(state,snapshot) && snapshot.requested_mask==config.enabled_mask && snapshot.active_mask==config.enabled_mask,"brain request and activation published");
            Check(AllBrainWordsZero(snapshot),"no brain counter without work");
            Check(AllCollisionWordsZero(snapshot),"no collision counter without routed tick work");
            Check(stop(nullptr)==0,"brain profiling stop joins the monitor");
            bool restored=true;
            for(unsigned i=0;i<NTW2_BRAIN_SLOTS;++i) restored=restored && *cells[i]==kBrain[i].original+delta && ReadOnly(cells[i]);
            Check(restored,"stop restores all 23 brain slots and their protection");
            Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask,"brain stop published");
        }
        config.enabled_mask=NTW2_BATCH64; config.main_thread_id=0;
    }
    if(!failures) Check(RunChild(argv[1],argv[2],"--install-conflict"),"foreign brain slot refusal scenario (child process) passed");
    if(!failures) {
        // NTW2_AI_ASYNC: refusable (no asynchronous scheduler route) and startable (worker created/stopped per generation).
        // No think runs in these idle cycles: counters stay zero and the worker sleeps without OS suspension.
        U* taskSlot=At(0x132e954);
        const U taskOriginal=0x5cc390+delta;
        const U aiMasks[]={
            NTW2_AI_ASYNC|NTW2_BATCH64, NTW2_AI_ASYNC,
            NTW2_AI_ASYNC|NTW2_AI_CTRL};
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot),"pristine read-only tick task slot");
        config.enabled_mask=aiMasks[0];
        Put(model,0xB0,A(armyManager));
        root[0x2829c]=0;
        Check(start(&config)==0,"start with the ai feature");
        Sleep(80); // several 10 ms monitor polls
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && !snapshot.active_mask &&
              *taskSlot==taskOriginal && *slot==original,"ai feature is refused without the asynchronous scheduler route");
        Put(model,0xB0,0);
        root[0x2829c]=1;
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && snapshot.probe==6 &&
              !snapshot.active_mask,"AI without formation refuses a missing army manager instead of cancelling every job");
        Put(model,0xB0,A(armyManager));
        Check(WaitActive(state,aiMasks[0]),"AI without formation binds its manager and becomes active");
        Check(*taskSlot!=taskOriginal && ReadOnly(taskSlot),"tick task hook published for the ai feature");
        Check(ReadState(state,snapshot) && AiEventWorker(snapshot),"ai worker owns no suspension after activation");
        Check(stop(nullptr)==0,"ai stop joins the monitor and the think worker");
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"ai stop restores the task slot and protection");
        for(unsigned i=0;i<16 && !failures;++i) {
            const U mask=aiMasks[i%(sizeof(aiMasks)/sizeof(aiMasks[0]))];
            config.enabled_mask=mask;
            Check(start(&config)==0 && WaitActive(state,mask),"ai policy start/restart accepted");
            Check(ReadState(state,snapshot) && snapshot.requested_mask==mask,"ai policy request published");
            bool zero=true;
            for(unsigned w=0;w<32;++w) zero=zero && !(w<16 && snapshot.ai_words[w]) && !snapshot.ai_extra_words[w] && !snapshot.crash_words[w];
            for(unsigned w=0;w<6;++w) zero=zero && !snapshot.ai_slice_words[w];
            for(unsigned w=0;w<8;++w) zero=zero && !snapshot.ai_validation_words[w];
            for(unsigned w=0;w<2;++w) zero=zero && !snapshot.ai_slice_site_words[w];
            for(unsigned w=0;w<NTW2_AI_SLICE_BUDGET_WORDS;++w) zero=zero && !snapshot.ai_slice_budget_words[w];
            for(unsigned w=0;w<16;++w) zero=zero && !snapshot.ai_ctrl_words[w];
            for(unsigned w=0;w<8;++w) zero=zero && !snapshot.ai_park_words[w];
            for(unsigned w=0;w<NTW2_AI_COMPLETION_WORDS;++w) zero=zero && !snapshot.ai_completion_words[w];
            Check(AiEventWorker(snapshot),"ai restart leaves the event worker unsuspended");
            Check(zero,"no think ran in the owned image and the crash capture stayed silent");
            Check(stop(nullptr)==0,"ai stop joins the monitor and the think worker");
            Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"ai stop restores every slot");
        }
        root[0x2829c]=0;
        config.enabled_mask=NTW2_BATCH64;
    }
    if(!failures) {
        // BRAIN2 v2 owns site 6 only while active. It needs no worker pool,
        // preserves the asynchronous-route lifecycle, and keeps profiling entry
        // slots original in both observation and serial-census modes.
        auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(dll,"ntw2_site_callee"));
        Check(siteCallee!=nullptr,"site callee diagnostic export present");
        U* taskSlot=At(0x132e954); U* cells[NTW2_BRAIN_SLOTS];
        const U taskOriginal=0x5cc390+delta, loopOriginal=0x585d10+delta;
        for(unsigned i=0;i<NTW2_BRAIN_SLOTS;++i) cells[i]=At(kBrain[i].table+0x0c);
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot),"pristine read-only tick task slot");
        config.enabled_mask=NTW2_BRAIN2|NTW2_BATCH64; config.workers=2;
        root[0x2829c]=0;
        Check(start(&config)==0,"start with the brain2 feature");
        Sleep(80); // several 10 ms monitor polls
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && !snapshot.active_mask &&
              *taskSlot==taskOriginal && *slot==original && AllBrain2WordsZero(snapshot),"brain2 feature is refused without the asynchronous scheduler route and counters stay zero");
        Check(siteCallee && siteCallee(6)==loopOriginal,"entity loop site stays the original until the feature is armed");
        root[0x2829c]=1;
        Check(WaitActive(state,config.enabled_mask),"brain2 feature became active with the exact mask");
        Check(*taskSlot!=taskOriginal && ReadOnly(taskSlot),"tick task hook published for the brain2 feature");
        Check(ReadState(state,snapshot) && AllBrain2WordsZero(snapshot),"brain2 counters are zero without a dispatch");
        Check(siteCallee && siteCallee(6)!=loopOriginal && InRuntime(siteCallee(6)),"entity loop site bound to the host dispatcher while brain2 is active");
        const U brain2Generation=snapshot.generation, brain2Task=*taskSlot;
        U brain2Before[NTW2_BRAIN2_WORDS];
        memcpy(brain2Before,snapshot.brain2_words,sizeof(brain2Before));
        root[0x2829c]=0;
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_ACTIVE && snapshot.generation==brain2Generation &&
              snapshot.active_mask==config.enabled_mask && snapshot.probe==0 && *taskSlot==brain2Task && ReadOnly(taskSlot),
              "same-world synchronous interval keeps brain2 hooks owned and generation active");
        Check(!memcmp(brain2Before,snapshot.brain2_words,sizeof(brain2Before)),"dormant brain2 interval retains counters");
        root[0x2829c]=1;
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_ACTIVE && snapshot.generation==brain2Generation &&
              snapshot.probe==0x100 && *taskSlot==brain2Task,"asynchronous route resumes without reactivation");
        Check(stop(nullptr)==0,"brain2 stop joins the monitor and drains owner dispatch");
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"brain2 stop restores the task slot and protection");
        Check(ReadState(state,snapshot) && AllBrain2WordsZero(snapshot) && siteCallee && siteCallee(6)==loopOriginal,"brain2 stopped status retains zero counters and restores the original site6 callee");
        // Restart observe/census/timing modes, alone and alongside other pool features.
        struct Cycle { U mask; U workers; bool brain2; };
        const Cycle cycles[]={{NTW2_BRAIN2|NTW2_BATCH64,2,true},{NTW2_BRAIN2,0,true},{NTW2_AI_ASYNC,0,false},{NTW2_BRAIN2|NTW2_AI_ASYNC|NTW2_AI_CTRL,3,true},
                              {NTW2_BATCH64,0,false},{NTW2_BRAIN2|NTW2_PROFILE|NTW2_BRAIN,1,true},
                              {NTW2_BRAIN2|NTW2_LOCO,0,true},{NTW2_AI_ASYNC|NTW2_AI_CTRL,4,false}};
        for(unsigned i=0;i<2*(sizeof(cycles)/sizeof(cycles[0])) && !failures;++i) {
            const Cycle& c=cycles[i%(sizeof(cycles)/sizeof(cycles[0]))];
            config.enabled_mask=c.mask; config.workers=c.workers;
            // The second pass adds the per-unit Stage A shadow (it needs no census and runs inline without workers).
            config.brain_flags=c.brain2 ? (i&NTW2_BRAIN_FLAGS_VALID)|(i>=sizeof(cycles)/sizeof(cycles[0]) ? NTW2_BRAIN_UNIT_SHADOW : 0u) : 0u;
            config.main_thread_id=(c.mask&NTW2_PROFILE) ? GetCurrentThreadId() : 0;
            Check(start(&config)==0 && WaitActive(state,c.mask),"brain2 cycle became active with the exact mask");
            Check(ReadState(state,snapshot) && snapshot.requested_mask==c.mask && snapshot.active_mask==c.mask && snapshot.workers==c.workers,"brain2 request and activation published");
            Check(siteCallee && ((siteCallee(6)==loopOriginal)==!c.brain2) && (!c.brain2 || InRuntime(siteCallee(6))),
                  c.brain2 ? "entity loop site bound to the host dispatcher" : "entity loop site stays the original without the feature");
            Check(siteCallee && ((siteCallee(13)==0x531AF0+delta)==!(c.mask&NTW2_LOCO)),
                  "brain and movement loop bindings coexist independently");
            Check(siteCallee && ((siteCallee(33)==0x7C8BD0+delta)==!(c.mask&NTW2_AI_CTRL)) &&
                  (!(c.mask&NTW2_AI_CTRL) || InRuntime(siteCallee(33))),
                  "controller site binds the host gate only with explicit ai_ctrl; ai alone stays original");
            Check(AllBrain2WordsZero(snapshot),"no brain2 counter without work");
            if (c.brain2) {
                const U gated = (config.brain_flags & (NTW2_BRAIN_CENSUS | NTW2_BRAIN_NODE_SHADOW | NTW2_BRAIN_FIRE_SHADOW |
                                                       NTW2_BRAIN_FINALIZER_SHADOW)) ? 1u : 0u;
                Check(snapshot.brain2_route_words[0]==1 && snapshot.brain2_route_words[1]==gated &&
                      snapshot.brain2_route_words[2]==0 && snapshot.brain2_route_words[3]==0,
                      "site6 selects BRAIN_W driver for shadow without census; LOCO does not change its variant");
            }
            if(c.mask&NTW2_BRAIN) {
                bool untouched=true;
                for(unsigned s=0;s<NTW2_BRAIN_SLOTS;++s) untouched=untouched && *cells[s]==kBrain[s].original+delta && ReadOnly(cells[s]);
                Check(untouched,"brain profiling slots are not published while brain2 runs the clones");
            }
            bool zero=true;
            for(unsigned w=0;w<32;++w) zero=zero && !(w<16 && snapshot.ai_words[w]) && !snapshot.ai_extra_words[w] && !snapshot.crash_words[w];
            for(unsigned w=0;w<6;++w) zero=zero && !snapshot.ai_slice_words[w];
            for(unsigned w=0;w<2;++w) zero=zero && !snapshot.ai_slice_site_words[w];
            for(unsigned w=0;w<NTW2_AI_SLICE_BUDGET_WORDS;++w) zero=zero && !snapshot.ai_slice_budget_words[w];
            for(unsigned w=0;w<16;++w) zero=zero && !snapshot.ai_ctrl_words[w];
            for(unsigned w=0;w<8;++w) zero=zero && !snapshot.ai_park_words[w];
            Check(zero,"no think ran and the crash capture stayed silent");
            Check(stop(nullptr)==0,"brain2 cycle stop drains the owner and any other feature workers");
            Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"brain2 cycle stop restores every slot");
            Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask && AllBrain2WordsZero(snapshot),"brain2 cycle stop published with zero counters");
            Check(siteCallee && siteCallee(6)==loopOriginal,"brain2 cycle stop unbinds the dispatcher");
            Check(siteCallee && siteCallee(33)==0x7C8BD0+delta,"stop restores the original controller site");
        }
        // --brain-s0: activation starts the timer (CPU check, BRAIN_S0 family routed, calibration) without any dispatch.
        config.enabled_mask=NTW2_BRAIN2; config.workers=0; config.main_thread_id=0; config.brain_flags=NTW2_BRAIN_S0;
        Check(start(&config)==0 && WaitActive(state,NTW2_BRAIN2),"brain S0 generation became active");
        Check(ReadState(state,snapshot) && snapshot.brain_s0_words[0]==1 && snapshot.brain_s0_words[1]==1 &&
              snapshot.brain_s0_words[2]==1 && snapshot.brain_s0_words[3]==6 && snapshot.brain_s0_words[4]==0 &&
              snapshot.brain_s0_words[17]!=0 && snapshot.brain_s0_words[31]==2048,
              "brain S0 published version/configured/running, 1/64 sampling, calibration and no stage");
        Check(siteCallee && siteCallee(6)!=loopOriginal && InRuntime(siteCallee(6)),"brain S0 binds the site-6 dispatcher");
        Check(stop(nullptr)==0,"brain S0 stop drains the owner");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && snapshot.brain_s0_words[2]==1 &&
              siteCallee(6)==loopOriginal,"brain S0 stop retains its row and restores site 6");
        // --brain-locality: activation starts the census (CPU check, storage, static line tables, bracket calibration) without any
        // dispatch; it reuses the S0 status row: version, configured bits (1 census, +2 warm, +4 prefetch, +8 prefetch2), running.
        {
            const U locCycles[]={NTW2_BRAIN_LOCALITY,NTW2_BRAIN_LOCALITY|NTW2_BRAIN_LOCALITY_WARM,
                                 NTW2_BRAIN_LOCALITY|NTW2_BRAIN_LOCALITY_PREFETCH,NTW2_BRAIN_LOCALITY|NTW2_BRAIN_LOCALITY_PREFETCH2,
                                 NTW2_BRAIN_LOCALITY|NTW2_BRAIN_LOCALITY_MARK};
            const U configured[]={1u,3u,5u,9u,17u};
            for (unsigned i=0;i<sizeof(locCycles)/sizeof(locCycles[0]) && !failures;++i) {
                config.enabled_mask=NTW2_BRAIN2; config.workers=0; config.main_thread_id=0; config.brain_flags=locCycles[i];
                Check(start(&config)==0 && WaitActive(state,NTW2_BRAIN2),"brain locality generation became active");
                const bool mark=(locCycles[i]&NTW2_BRAIN_LOCALITY_MARK)!=0;   // pass-through: no calibration, no storage
                Check(ReadState(state,snapshot) && snapshot.brain_s0_words[0]==1 && snapshot.brain_s0_words[1]==configured[i] &&
                      snapshot.brain_s0_words[2]==1 && snapshot.brain_s0_words[4]==0 && snapshot.brain_s0_words[30]==64 &&
                      (mark || (snapshot.brain_s0_words[3]==4 && snapshot.brain_s0_words[11]!=0 && snapshot.brain_s0_words[12]!=0 &&
                                snapshot.brain_s0_words[31]==2048)),
                      "brain locality published version/configured/running, 1/16 sampling, calibration and no stage");
                Check(siteCallee && siteCallee(6)!=loopOriginal && InRuntime(siteCallee(6)),"brain locality binds the site-6 dispatcher");
                Check(stop(nullptr)==0,"brain locality stop drains the owner");
                Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && snapshot.brain_s0_words[2]==1 &&
                      siteCallee(6)==loopOriginal,"brain locality stop retains its row and restores site 6");
            }
        }
        // Per-unit fatigue slices: shadow, live, live with S0 and a second shadow cycle. Activation pins the image tables and
        // publishes the unit policy / fatigue rows (modes 1 = shadow, 2 = live; the posture/engage half stays zero); stop restores
        // site 6. A later activation without any unit flag leaves the whole unit row zero.
        {
            const U unitCycles[]={NTW2_BRAIN_UNIT_FATIGUE|NTW2_BRAIN_UNIT_FATIGUE_SHADOW,NTW2_BRAIN_UNIT_FATIGUE,
                                  NTW2_BRAIN_S0|NTW2_BRAIN_UNIT_FATIGUE,NTW2_BRAIN_UNIT_FATIGUE|NTW2_BRAIN_UNIT_FATIGUE_SHADOW};
            for (unsigned i=0;i<sizeof(unitCycles)/sizeof(unitCycles[0]) && !failures;++i) {
                config.enabled_mask=NTW2_BRAIN2; config.workers=0; config.main_thread_id=0; config.brain_flags=unitCycles[i];
                Check(start(&config)==0 && WaitActive(state,NTW2_BRAIN2),"unit fatigue generation became active");
                const U mode=(unitCycles[i]&NTW2_BRAIN_UNIT_FATIGUE_SHADOW) ? 1u : 2u;
                bool halfZero=true;
                Check(ReadState(state,snapshot) && snapshot.brain_unit_policy_words[0]==1 && snapshot.brain_unit_policy_words[1]==mode &&
                      snapshot.brain_unit_policy_words[2]==0 && snapshot.brain_unit_policy_words[32]==1 &&
                      snapshot.brain_unit_policy_words[33]==mode,"unit fatigue row published version/mode and no stage at activation");
                for (unsigned w=128;w<NTW2_BRAIN_UNIT_POLICY_WORDS;++w) halfZero=halfZero && !snapshot.brain_unit_policy_words[w];
                Check(halfZero,"the posture/engage half of the unit policy row stays zero");
                Check(siteCallee && siteCallee(6)!=loopOriginal && InRuntime(siteCallee(6)),"unit fatigue binds the site-6 dispatcher");
                Check(stop(nullptr)==0,"unit fatigue stop drains the owner");
                Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && siteCallee(6)==loopOriginal,"unit fatigue stop restores site 6");
            }
            config.brain_flags=NTW2_BRAIN_S0;
            Check(start(&config)==0 && WaitActive(state,NTW2_BRAIN2),"S0 only generation after unit cycles became active");
            bool zero=true;
            Check(ReadState(state,snapshot),"read state");
            for (unsigned w=0;w<NTW2_BRAIN_UNIT_POLICY_WORDS;++w) zero=zero && !snapshot.brain_unit_policy_words[w];
            Check(zero,"a later activation without unit flags leaves every unit policy word zero");
            Check(stop(nullptr)==0,"S0-only stop after unit cycles");
        }
        root[0x2829c]=0;
        config.enabled_mask=NTW2_BATCH64; config.workers=0; config.main_thread_id=0;
        config.brain_flags=0;
    }
    if(!failures) {
        // COLLIDE shares the simulation epoch and persistent pool; no stage is invoked by this lifecycle fixture.
        U* taskSlot=At(0x132e954);
        const U taskOriginal=0x5cc390+delta;
        config.enabled_mask=NTW2_COLLIDE; config.workers=2; config.main_thread_id=0;
        root[0x2829c]=0;
        Check(start(&config)==0,"collide start accepted while scheduler is unarmed");
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && !snapshot.active_mask &&
              *taskSlot==taskOriginal && ReadOnly(taskSlot) && AllCollideWordsZero(snapshot),
              "collide activation refused until asynchronous route is armed");
        Put(model,0xB0,0);
        root[0x2829c]=1;
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && snapshot.probe==6 &&
              !snapshot.active_mask && *taskSlot==taskOriginal,
              "standalone collide waits for its own manager without requiring LOCO or AI");
        Put(model,0xB0,A(armyManager));
        const U boundariesBefore=activationBoundaries;
        Check(WaitActive(state,NTW2_COLLIDE),"collide activates with exact requested mask");
        Check(*taskSlot!=taskOriginal && ReadOnly(taskSlot),"collide publishes the tick task hook");
        Check(ReadState(state,snapshot) && AllCollideWordsZero(snapshot),"collide counters remain zero without a stage");
        Check(activationBoundaries-boundariesBefore==1 &&
              snapshot.memory_words[NTW2_MEM_PRIMARY_CAPACITY]==256 &&
              snapshot.memory_words[NTW2_MEM_RECORD_CAPACITY]==256 &&
              snapshot.memory_words[NTW2_MEM_COLLIDE_BYTES]>0 && snapshot.memory_words[NTW2_MEM_LOCO_BYTES]==0,
              "standalone collide captures an empty workload once and allocates only native-audit collision storage");
        Check(stop(nullptr)==0,"collide stop drains and joins the pool");
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot),"collide stop restores task slot and protection");
        struct CollideCycle { U mask; U workers; };
        const CollideCycle cycles[]={{NTW2_COLLIDE,0},{NTW2_COLLIDE|NTW2_PROFILE,2},
                                    {NTW2_BATCH64,0},{NTW2_COLLIDE|NTW2_BRAIN2,3},
                                    {NTW2_COLLIDE|NTW2_BATCH64,1}};
        for(unsigned i=0;i<10 && !failures;++i) {
            const CollideCycle& c=cycles[i%(sizeof(cycles)/sizeof(cycles[0]))];
            config.enabled_mask=c.mask; config.workers=c.workers;
            config.main_thread_id=(c.mask&NTW2_PROFILE) ? GetCurrentThreadId() : 0;
            Check(start(&config)==0 && WaitActive(state,c.mask),"collide restart activates exact feature mask");
            Check(ReadState(state,snapshot) && snapshot.requested_mask==c.mask && snapshot.workers==c.workers &&
                  AllCollideWordsZero(snapshot),"collide restart resets counters, including disabled generations");
            Check(stop(nullptr)==0,"collide restart stop joins monitor and pool");
            Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"collide restart restores slots");
            Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask &&
                  AllCollideWordsZero(snapshot),"collide stopped status retains zero work counters");
        }
        root[0x2829c]=0;
        config.enabled_mask=NTW2_BATCH64; config.workers=0; config.main_thread_id=0;
    }
    if(!failures) {
        auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(dll,"ntw2_site_callee"));
        U* taskSlot=At(0x132e954);
        const U taskOriginal=0x5cc390+delta, stageOriginal=0x57dc30+delta, queryOriginal=0x81a790+delta;
        config.enabled_mask=NTW2_COLLIDE_LOD; config.workers=0; config.main_thread_id=0;
        root[0x2829c]=0;
        Check(start(&config)==0,"collision LOD start accepted while scheduler unarmed");
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && !snapshot.active_mask &&
              *taskSlot==taskOriginal && ReadOnly(taskSlot) && AllCollideLodWordsZero(snapshot),
              "collision LOD activation refused until asynchronous route armed; counters zero");
        Check(siteCallee && siteCallee(5)==stageOriginal,"site 5 stays original until LOD activation");
        Check(siteCallee && siteCallee(106)==queryOriginal,"query site remains original while unarmed");
        root[0x2829c]=1;
        Check(WaitActive(state,NTW2_COLLIDE_LOD),"collision LOD activates alone without PROFILE or workers");
        Check(*taskSlot!=taskOriginal && ReadOnly(taskSlot),"collision LOD owns the tick task slot");
        Check(siteCallee && siteCallee(5)!=stageOriginal && InRuntime(siteCallee(5)),"site 5 binds the host stage gate while LOD active");
        Check(siteCallee && siteCallee(106)==queryOriginal,"LOD without census never binds the pair-timed query clone");
        Check(ReadState(state,snapshot) && AllCollideLodWordsZero(snapshot),"collision LOD remains zero before a stage");
        Check(stop(nullptr)==0 && siteCallee && siteCallee(5)==stageOriginal,"collision LOD stop unbinds site 5");
        const U masks[]={NTW2_COLLIDE_LOD,NTW2_BATCH64,NTW2_COLLIDE_LOD|NTW2_PROFILE,
                         NTW2_COLLIDE_LOD|NTW2_BATCH64,NTW2_AI_ASYNC|NTW2_COLLIDE_LOD,NTW2_PROFILE};
        for(unsigned i=0;i<12 && !failures;++i) {
            const U mask=masks[i%(sizeof(masks)/sizeof(masks[0]))];
            config.enabled_mask=mask; config.workers=i%3;
            config.main_thread_id=(mask&NTW2_PROFILE) ? GetCurrentThreadId() : 0;
            config.collide_lod_m=i%2 ? 55 : 0; // explicit distance and default-zero contract
            const bool census=(mask&NTW2_PROFILE) && i>=6;
            if (census) config.collide_lod_m|=NTW2_COLLIDE_CENSUS;
            Check(start(&config)==0 && WaitActive(state,mask),"collision LOD restart activates exact requested mask");
            Check(siteCallee && ((siteCallee(5)!=stageOriginal)==((mask&(NTW2_COLLIDE_LOD|NTW2_PROFILE))!=0)),
                  "site 5 inclusive timing remains bound in PROFILE generations without census");
            Check(siteCallee && ((siteCallee(106)!=queryOriginal)==census),
                  "PROFILE alone keeps original queries; explicit census alone admits the timed query clone");
            Check(siteCallee && ((siteCallee(33)==0x7C8BD0+delta)==!(mask&NTW2_AI_CTRL)),
                  "planner ai, PROFILE and collision features alone do not bind the controller gate");
            Check(ReadState(state,snapshot) && AllCollideLodWordsZero(snapshot),"collision LOD restart and disabled generation reset every word");
            Check(stop(nullptr)==0 && siteCallee && siteCallee(5)==stageOriginal,"collision LOD restart stop restores site 5");
            Check(siteCallee && siteCallee(106)==queryOriginal,"stop restores the untimed original query after census generations");
            Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"collision LOD restart restores all slots");
            Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask &&
                  AllCollideLodWordsZero(snapshot),"stopped collision LOD status retains zero counters without work");
        }
        root[0x2829c]=0;
        config.enabled_mask=NTW2_BATCH64; config.workers=0; config.main_thread_id=0; config.collide_lod_m=0;
    }
    if(!failures) {
        // NTW2_LOCO Stages A/B/C: shares the simulation epoch; sites 13 and 5 bind independently in combined mode.
        // No battle tick runs in the owned image, so every work counter stays zero; metadata words are asserted separately.
        auto siteCallee=reinterpret_cast<ntw2_site_callee_fn>(GetProcAddress(dll,"ntw2_site_callee"));
        U* taskSlot=At(0x132e954);
        const U taskOriginal=0x5cc390+delta, moveOriginal=0x531af0+delta, stageOriginal=0x57dc30+delta;
        Check(siteCallee!=nullptr,"site callee diagnostic export present for loco");
        BindLocoScene(true);
        config.enabled_mask=NTW2_LOCO; config.workers=0; config.main_thread_id=0; config.loco_flags=0;
        root[0x2829c]=0;
        Check(start(&config)==0,"loco start accepted while scheduler unarmed");
        Sleep(80);
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_WAITING_BATTLE && !snapshot.active_mask &&
              *taskSlot==taskOriginal && ReadOnly(taskSlot) && AllLocoWordsZero(snapshot),
              "loco activation refused until the asynchronous route is armed");
        Check(siteCallee && siteCallee(13)==moveOriginal,"site 13 stays the original until loco activation");
        root[0x2829c]=1;
        Check(WaitActive(state,NTW2_LOCO),"loco activates alone with the exact mask and an inline-capable shared pool");
        Check(*taskSlot!=taskOriginal && ReadOnly(taskSlot),"loco owns the tick task slot");
        Check(siteCallee && siteCallee(13)!=moveOriginal && InRuntime(siteCallee(13)),"site 13 binds the host movement gate while loco is active");
        Check(ReadState(state,snapshot) && AllLocoWorkWordsZero(snapshot) && snapshot.loco_words[44]==0 &&
              snapshot.loco_gate_words[0]==1 && snapshot.loco_gate_words[4]==0x233 && LocoServiceMetadata(snapshot,false) &&
              LocoOwnedMetadata(snapshot,false),
              "loco work counters zero before a stage; observe-only gate/service/grid/parallel metadata published at activation");
        Check(stop(nullptr)==0 && siteCallee && siteCallee(13)==moveOriginal,"loco stop unbinds site 13");
        Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"loco stop restores the task slot and protection");
        // Stop while the handoff is still pending: no owner callback may retain
        // this generation's context or run after its arenas have been destroyed.
        config.enabled_mask=NTW2_LOCO|NTW2_COLLIDE;
        config.loco_flags=NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID_VERIFY;
        config.workers=2; config.main_thread_id=0;
        Check(start(&config)==0,"pending combined activation starts");
        bool pending=false;
        for(const ULONGLONG end=GetTickCount64()+3000;GetTickCount64()<end;Sleep(1))
            if(ReadState(state,snapshot) && snapshot.phase==NTW2_ACTIVATING && *taskSlot!=taskOriginal) {
                pending=true; break;
            }
        Check(pending && !snapshot.active_mask && ReadOnly(taskSlot),"only the disabled task route is published before capture");
        Check(stop(nullptr)==0 && *taskSlot==taskOriginal && ReadOnly(taskSlot),"pending capture cancels and restores its task slot");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.error && !snapshot.active_mask,
              "explicit stop during capture wait is not an activation error");
        Check(activationBoundary(model)==0,"cancelled capture cannot run against freed arenas");
        struct LocoCycle { U mask; U flags; U workers; };
        const LocoCycle cycles[]={{NTW2_LOCO,NTW2_LOCO_CLONE,0},{NTW2_LOCO|NTW2_BATCH64,0,2},{NTW2_BATCH64,0,0},
                                  {NTW2_LOCO,NTW2_LOCO_GRID,0}, {NTW2_LOCO,NTW2_LOCO_GRID,2},
                                  {NTW2_LOCO,NTW2_LOCO_GRID_VERIFY,0}, {NTW2_LOCO,NTW2_LOCO_GRID_VERIFY,2},
                                  {NTW2_LOCO,NTW2_LOCO_GRID|NTW2_LOCO_GRID_INCREMENTAL,0}, {NTW2_LOCO,NTW2_LOCO_GRID_VERIFY|NTW2_LOCO_GRID_INCREMENTAL,2},
                                  {NTW2_LOCO|NTW2_COLLIDE|NTW2_BRAIN2,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID,0},
                                  {NTW2_LOCO|NTW2_COLLIDE|NTW2_BRAIN2,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID_VERIFY,2},
                                  {NTW2_LOCO|NTW2_COLLIDE|NTW2_PROFILE,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY|NTW2_LOCO_QUIET,2},
                                  {NTW2_COLLIDE,0,2}, {NTW2_BATCH64,0,0},
                                  {NTW2_LOCO,NTW2_LOCO_GRID|NTW2_LOCO_CLONE,2},
                                  {NTW2_LOCO,NTW2_LOCO_GRID|NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL,2},
                                  {NTW2_LOCO,NTW2_LOCO_GRID|NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET,2},
                                  {NTW2_LOCO|NTW2_AI_ASYNC,NTW2_LOCO_CLONE,1},{NTW2_LOCO|NTW2_PROFILE,0,0},
                                  {NTW2_LOCO|NTW2_PROFILE,NTW2_LOCO_CLONE,3},{NTW2_LOCO|NTW2_AI_ASYNC|NTW2_AI_CTRL,0,4},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL,0},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL,2},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_SHADOW,0},
                                  {NTW2_LOCO|NTW2_PROFILE,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL,3},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES,0},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES,2},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_SHADOW|NTW2_LOCO_OWNED_SERVICES,2},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET,2},
                                  {NTW2_LOCO,NTW2_LOCO_CLONE|NTW2_LOCO_PARALLEL|NTW2_LOCO_SHADOW|NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_QUIET,2}};
        for(unsigned i=0;i<2*(sizeof(cycles)/sizeof(cycles[0])) && !failures;++i) {
            const LocoCycle& c=cycles[i%(sizeof(cycles)/sizeof(cycles[0]))];
            config.enabled_mask=c.mask; config.loco_flags=c.flags; config.workers=c.workers;
            config.brain_flags=(c.mask&NTW2_BRAIN2) ? NTW2_BRAIN_CENSUS : 0u;
            config.main_thread_id=(c.mask&(NTW2_PROFILE|NTW2_GRID_CENSUS)) ? GetCurrentThreadId() : 0;
            const bool loco=(c.mask&NTW2_LOCO)!=0;
            const U boundariesBefore=activationBoundaries;
            Check(start(&config)==0 && WaitActive(state,c.mask),"loco cycle became active with the exact mask");
            const U expectedBoundaries=((c.mask&NTW2_COLLIDE) ||
                (c.flags&(NTW2_LOCO_OWNED_SERVICES|NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY)) ? 1u : 0u)+
                ((c.flags&NTW2_LOCO_OWNED_SERVICES) ? 1u : 0u);
            Check(activationBoundaries==boundariesBefore+expectedBoundaries,
                  "each generation captures workload once and owned scene once at quiescent boundaries");
            Check(ReadState(state,snapshot) && snapshot.requested_mask==c.mask && snapshot.active_mask==c.mask && snapshot.workers==c.workers,"loco request and activation published");
            Check(GridCensusWithoutCalls(snapshot,false),"ordinary LOCO starts keep census disabled");
            U storage=0;
            for(U m=NTW2_MEM_LOCO_BYTES;m<=NTW2_MEM_OTHER_BYTES;++m) storage+=snapshot.memory_words[m];
            Check(snapshot.memory_words[NTW2_MEM_VERSION]==3 && snapshot.memory_words[NTW2_MEM_TOTAL_BYTES]==storage &&
                  snapshot.memory_words[NTW2_MEM_FLOOR_BYTES]==NTW2_MEMORY_MIN_AVAIL_VIRTUAL &&
                  !snapshot.memory_words[NTW2_MEM_BUDGET_REFUSALS],"memory row accounts every module and preserves VA floor");
            Check(storage<96u*1024u*1024u,"small workloads never reserve worst-case Stage C arenas");
            Check(siteCallee && ((siteCallee(13)==moveOriginal)==!loco) && (!loco || InRuntime(siteCallee(13))),
                  loco ? "site 13 bound to the host movement gate" : "site 13 stays the original without the feature");
            Check(siteCallee && ((siteCallee(5)!=stageOriginal)==((c.mask&(NTW2_COLLIDE|NTW2_PROFILE))!=0)) &&
                  (!(c.mask&NTW2_COLLIDE) || InRuntime(siteCallee(5))), "collision site binds alongside movement in combined generations");
            Check(AllCollideWordsZero(snapshot),"combined and standalone restarts reset collision work and source tails before any stage");
            Check(siteCallee && ((siteCallee(6)==0x585D10+delta)==!(c.mask&NTW2_BRAIN2)) && AllBrain2WordsZero(snapshot),
                  "combined owned mover and brain census bind separately without executing work");
            Check(AllLocoWorkWordsZero(snapshot) && LocoPortMetadata(snapshot,(c.flags&(NTW2_LOCO_SHADOW|NTW2_LOCO_OWNED_SERVICES))!=0) &&
                  (loco ? snapshot.loco_words[44]==((c.flags&NTW2_LOCO_CLONE) ? 1u : 0u) &&
                          snapshot.loco_gate_words[0]==1 && snapshot.loco_gate_words[4]==0x233 &&
                          LocoServiceMetadata(snapshot,(c.flags&NTW2_LOCO_CLONE)!=0,(c.flags&NTW2_LOCO_QUIET)!=0) &&
                          LocoGridV2Metadata(snapshot,(c.flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))!=0,(c.flags&NTW2_LOCO_GRID_VERIFY)!=0) &&
                          LocoOwnedMetadata(snapshot,(c.flags&NTW2_LOCO_PARALLEL)!=0,(c.flags&NTW2_LOCO_OWNED_SERVICES)!=0,(c.flags&NTW2_LOCO_QUIET)!=0,(c.flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))!=0) : AllLocoWordsZero(snapshot)),
                  "loco cycle has zero work and exact clone/gate/service/grid-v2/parallel/owned-phase metadata; all arrays zero when disabled");
            Check(start(&config)==1,"duplicate loco start refused");
            Check(stop(nullptr)==0,"loco cycle stop joins the monitor and the pool");
            Check(*taskSlot==taskOriginal && ReadOnly(taskSlot) && *slot==original,"loco cycle stop restores every slot");
            Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask && AllLocoWorkWordsZero(snapshot) &&
                  LocoPortMetadata(snapshot,(c.flags&(NTW2_LOCO_SHADOW|NTW2_LOCO_OWNED_SERVICES))!=0) &&
                  (loco ? snapshot.loco_gate_words[0]==1 && snapshot.loco_gate_words[4]==0x233 &&
                          LocoServiceMetadata(snapshot,(c.flags&NTW2_LOCO_CLONE)!=0,(c.flags&NTW2_LOCO_QUIET)!=0) &&
                          LocoGridV2Metadata(snapshot,(c.flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))!=0,(c.flags&NTW2_LOCO_GRID_VERIFY)!=0) &&
                          LocoOwnedMetadata(snapshot,(c.flags&NTW2_LOCO_PARALLEL)!=0,(c.flags&NTW2_LOCO_OWNED_SERVICES)!=0,(c.flags&NTW2_LOCO_QUIET)!=0,(c.flags&(NTW2_LOCO_GRID|NTW2_LOCO_GRID_VERIFY))!=0) : AllLocoWordsZero(snapshot)),
                  "loco stop retains grid-v2/parallel/owned-phase metadata and zero work; disabled arrays stay entirely zero");
            Check(GridCensusWithoutCalls(snapshot,false),"ordinary LOCO stops retain an all-zero census tail");
            Check(siteCallee && siteCallee(13)==moveOriginal,"loco cycle stop restores the original movement loop");
            Check(siteCallee && siteCallee(5)==stageOriginal && AllCollideWordsZero(snapshot),
                  "combined stop restores collision site and retains zero source/work tails");
        }
        root[0x2829c]=0; BindLocoScene(false);
        config.enabled_mask=NTW2_BATCH64; config.workers=0; config.main_thread_id=0; config.loco_flags=0;
    }
    if(!failures) {
        // NTW2_VISUAL: published into the single .rdata word holding the relocated original 0x779E60 (found by scanning the mapped
        // real image), read-only throughout, restored on every stop. It is not a simulation feature: no tick epoch gates it, so it
        // is startable alone with no scheduler route. No work runs in the owned image: every work counter stays zero; word 13
        // (live slot VA) is slot metadata and is asserted separately.
        static uint8_t visualManager[0x100]={};
        U* vslot=nullptr;
        Check(VisualHits(&vslot)==1 && vslot && ReadOnly(vslot) && *vslot==kVisualOriginalVa+delta,"exactly one read-only .rdata word holds the relocated original 0x779E60");
        if(vslot) {
            const U vOriginal=*vslot;
            U* taskSlot=At(0x132e954); U* walkSlot=At(0x133e2dc);
            const U taskOriginal=0x5cc390+delta, walkOriginal=0x702bb0+delta;
            struct VisualCycle { U mask; bool async; };
            const VisualCycle cycles[]={{NTW2_VISUAL,false},{NTW2_BATCH64|NTW2_AI_ASYNC|NTW2_VISUAL|NTW2_PROFILE,true},{NTW2_BATCH64|NTW2_VISUAL,false},{NTW2_VISUAL,true}};
            Put(model,0xB0,A(visualManager));
            for(unsigned i=0;i<16 && !failures;++i) {
                const VisualCycle& c=cycles[i%(sizeof(cycles)/sizeof(cycles[0]))];
                config.enabled_mask=c.mask; config.workers=i%3;
                const LONG allocatedBefore=allocatorAllocations, freedBefore=allocatorFrees;
                config.main_thread_id=(c.mask&NTW2_PROFILE) ? GetCurrentThreadId() : 0;
                root[0x2829c]=c.async ? 1 : 0;
                Check(start(&config)==0 && WaitActive(state,c.mask),"visual cycle became active with the exact mask");
                const U published=*vslot;
                Check(published!=vOriginal && ReadOnly(vslot) && InRuntime(published),"visual slot holds a read-only host thunk");
                Check(ReadState(state,snapshot) && snapshot.requested_mask==c.mask && snapshot.active_mask==c.mask,"visual request and activation published");
                Check(snapshot.visual_words[13]==A(vslot),"visual words[13] reports the live slot VA");
                Check(AllVisualWorkWordsZero(snapshot),"no visual work counter without work");
                if(c.mask&NTW2_AI_ASYNC) Check(AiEventWorker(snapshot),"ai worker idles without suspension beside visual");
                bool admitted=true;
                for(U worker=0;worker<config.workers;++worker)
                    admitted=admitted && snapshot.allocator_words[worker*NTW2_ALLOCATOR_ROW_WORDS]==1;
                if(c.mask&NTW2_AI_ASYNC)
                    admitted=admitted && snapshot.allocator_words[(NTW2_ALLOCATOR_THREADS-1)*NTW2_ALLOCATOR_ROW_WORDS]==1;
                const LONG probes=static_cast<LONG>(config.workers+((c.mask&NTW2_AI_ASYNC) ? 1 : 0));
                Check(admitted && allocatorAllocations-allocatedBefore==probes && allocatorFrees-freedBefore==probes,
                      "every pool and AI worker allocates and frees exactly once before activation");
                Check(start(&config)==1,"duplicate visual start refused");
                Check(stop(nullptr)==0,"visual stop joins the monitor");
                Check(*vslot==vOriginal && ReadOnly(vslot),"visual stop restores the read-only original");
                Check(*slot==original && ReadOnly(slot) && *taskSlot==taskOriginal && ReadOnly(taskSlot) && *walkSlot==walkOriginal && ReadOnly(walkSlot),"visual stop restores every companion slot");
                Check(ReadState(state,snapshot) && snapshot.phase==NTW2_STOPPED && !snapshot.active_mask,"visual stop published");
                Check(stop(nullptr)==0,"visual stop is idempotent");
            }
            config.enabled_mask=NTW2_VISUAL; config.main_thread_id=0; root[0x2829c]=0;
            for(unsigned i=0;i<32 && !failures;++i) {
                Check(start(&config)==0,"visual immediate restart accepted");
                Check(stop(nullptr)==0,"visual immediate cancellation joins the monitor");
                Check(*vslot==vOriginal && ReadOnly(vslot),"visual immediate cancellation leaves no hook");
            }
        }
        root[0x2829c]=0;
        config.enabled_mask=NTW2_BATCH64; config.workers=0; config.main_thread_id=0;
    }
    if(!failures) Check(RunChild(argv[1],argv[2],"--visual-scan-zero"),"visual zero-hit scan refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--visual-scan-multiple"),"visual multiple-hit scan refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--visual-stop-conflict"),"visual foreign-value stop refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--allocator-pool-fault"),"pool allocator refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--allocator-ai-fault"),"AI allocator refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--allocator-free-fault"),"allocator free-side refusal scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--visual-native-arenas"),"native per-worker arena scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-completion"),"AI subordinate destruction completion barrier scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-completion-controller"),"AI controller configuration preserves subordinate completion boundary scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-census"),"AI mutation census gates, clone-call retarget, restore and refusals scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-prepass"),"AI prepass census/presize slot gates, restore, row and refusals scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-async2"),"ai_async2 boundary schedule, writer joins, worker marshalling, watchdog and private walk scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--ai-deferred"),"ai_deferred sliced thinks: node order, consumption seams, busy refusals, revalidation and perturbation determinism scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--loco-owned-activation-refusal"),"owned activation without a scene fails closed scenario (child process) passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--va-budget"),"activation VA floor and periodic minimum scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--va-budget-post"),"post-reservation VA refusal scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--va-budget-periodic"),"periodic VA native fallback and arena retirement scenario passed");
    if(!failures) Check(RunChild(argv[1],argv[2],"--grid-probation"),"grid probation trap/log/resume on a synthetic page scenario passed");
    if(!failures) {
        Check(start(&config)==0 && WaitActive(state),"start for external-hook conflict");
        const U foreign=A(reinterpret_cast<void*>(&ForeignWorker));
        Check(Replace(slot,foreign),"install owned-process competing hook");
        Check(stop(nullptr)!=0,"stop reports incomplete restoration");
        Check(*slot==foreign && ReadOnly(slot),"stop does not overwrite another hook");
        Check(ReadState(state,snapshot) && snapshot.phase==NTW2_FAILED,"restoration failure is visible");
        Check(start(&config)!=0,"failed restoration prevents restart");
        Replace(slot,original);
    }
    stop(nullptr);
    Check(Replace(import,originalImport),"restore the identity fixture");
    printf("native host lifecycle: checks=%u failures=%u retained_clone_bytes=%u; no renderer executed\n",checks,failures,retained);
    VirtualFree(image,0,MEM_RELEASE);
    return failures ? 1 : 0;
}
