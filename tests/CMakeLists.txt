# Native oracles, harnesses and payload audits.  Every executable is a real differential/native test with a meaningful exit
# code.  Nothing here is part of the product and nothing here launches or touches the game: the oracles map a private
# relocated copy of the supported image inside their own process.
#
#   KNTWR_TEST_IMAGE   path of the supported Napoleon.exe  -> enables the image oracles
#   KNTWR_TEST_ASSETS  directory of pinned captures        -> enables kit/clone/table based tests
# A test whose input is missing is NOT registered (and is listed at configure time); it is never registered as a pass.

set(KNTWR_TEST_DIR "${CMAKE_BINARY_DIR}/bin/tests")

if(NOT KNTWR_TEST_IMAGE AND DEFINED ENV{KNTWR_TEST_IMAGE})
  set(KNTWR_TEST_IMAGE "$ENV{KNTWR_TEST_IMAGE}")
endif()
set(KNTWR_HAVE_IMAGE OFF)
if(KNTWR_TEST_IMAGE AND EXISTS "${KNTWR_TEST_IMAGE}")
  set(KNTWR_HAVE_IMAGE ON)
  file(TO_NATIVE_PATH "${KNTWR_TEST_IMAGE}" KNTWR_IMAGE_ARG)
endif()

set_property(GLOBAL PROPERTY KNTWR_TESTS_REGISTERED "")
set_property(GLOBAL PROPERTY KNTWR_TESTS_SKIPPED "")

function(kntwr_note_registered name)
  set_property(GLOBAL APPEND PROPERTY KNTWR_TESTS_REGISTERED "${name}")
endfunction()
function(kntwr_note_skipped name reason)
  set_property(GLOBAL APPEND PROPERTY KNTWR_TESTS_SKIPPED "${name} (${reason})")
endfunction()

# kntwr_asset(<out> <file>): native path of KNTWR_TEST_ASSETS/<file>, empty when absent.
function(kntwr_asset out file)
  if(EXISTS "${KNTWR_TEST_ASSETS}/${file}")
    file(TO_NATIVE_PATH "${KNTWR_TEST_ASSETS}/${file}" _p)
    set(${out} "${_p}" PARENT_SCOPE)
  else()
    set(${out} "" PARENT_SCOPE)
  endif()
endfunction()

# kntwr_export_names(<out> <link flags...>): undecorated public names of /EXPORT:name[=decorated][,DATA] flags.
function(kntwr_export_names out)
  set(_names "")
  foreach(_f IN LISTS ARGN)
    string(REGEX REPLACE "^/EXPORT:([^=,]+).*$" "\\1" _n "${_f}")
    list(APPEND _names "${_n}")
  endforeach()
  set(${out} "${_names}" PARENT_SCOPE)
endfunction()

# kntwr_harness(<target> STD <n> FP <strict|precise|none> SOURCES ... [OBJECTS ...] [INCLUDES ...] [DEFINES ...] [LIBS ...])
function(kntwr_harness target)
  cmake_parse_arguments(H "" "STD;FP" "SOURCES;OBJECTS;INCLUDES;DEFINES;LIBS" ${ARGN})
  add_executable(${target} ${H_SOURCES})
  kntwr_host_flags(${target} ${H_STD} ${H_FP})
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support" ${H_INCLUDES})
  if(H_DEFINES)
    target_compile_definitions(${target} PRIVATE ${H_DEFINES})
  endif()
  if(H_OBJECTS OR H_LIBS)
    target_link_libraries(${target} PRIVATE ${H_OBJECTS} ${H_LIBS})
  endif()
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${KNTWR_TEST_DIR}")
endfunction()

# kntwr_payload(<target> OUTPUT <name> OBJECTS <object libs...> EXPORTS <link flags...>)
# Standalone import-free x86 DLL (no CRT, no entry point, no manifest): the shape of the code the runtime copies into owned
# allocations.  Distinct from the full host DLL.
function(kntwr_payload target)
  cmake_parse_arguments(P "" "OUTPUT" "OBJECTS;EXPORTS" ${ARGN})
  set(_objs "")
  foreach(_o IN LISTS P_OBJECTS)
    list(APPEND _objs "$<TARGET_OBJECTS:${_o}>")
  endforeach()
  add_library(${target} SHARED ${_objs})
  set_target_properties(${target} PROPERTIES LINKER_LANGUAGE C OUTPUT_NAME ${P_OUTPUT}
                        RUNTIME_OUTPUT_DIRECTORY "${KNTWR_TEST_DIR}")
  kntwr_payload_link(${target})
  target_link_options(${target} PRIVATE /MANIFEST:NO ${P_EXPORTS})
endfunction()

# kntwr_host_module(<target> OUTPUT <name> OBJECTS <object libs...>)
# Standalone CRT-linked module DLL carrying the same objects as the product DLL; exports come from /EXPORT pragmas.
function(kntwr_host_module target)
  cmake_parse_arguments(M "" "OUTPUT" "OBJECTS" ${ARGN})
  set(_objs "")
  foreach(_o IN LISTS M_OBJECTS)
    list(APPEND _objs "$<TARGET_OBJECTS:${_o}>")
  endforeach()
  add_library(${target} SHARED ${_objs})
  set_target_properties(${target} PROPERTIES LINKER_LANGUAGE CXX OUTPUT_NAME ${M_OUTPUT}
                        RUNTIME_OUTPUT_DIRECTORY "${KNTWR_TEST_DIR}")
endfunction()

# ---------------------------------------------------------------------------------------------------------------------
# Import-free payload DLLs + structural audits
# ---------------------------------------------------------------------------------------------------------------------
kntwr_payload(kntwr_payload_worker_dispatch OUTPUT native_worker_dispatch
  OBJECTS kntwr_worker_dispatch EXPORTS ${KNTWR_EXPORTS_DISPATCH})
kntwr_payload(kntwr_payload_ballistics_helpers OUTPUT native_ballistics_helpers
  OBJECTS kntwr_ballistics_helpers kntwr_worker_dispatch EXPORTS ${KNTWR_EXPORTS_BALLISTICS_HELPERS} ${KNTWR_EXPORTS_DISPATCH})
kntwr_payload(kntwr_payload_ballistics_collision OUTPUT native_ballistics_collision
  OBJECTS kntwr_ballistics_collision EXPORTS ${KNTWR_EXPORTS_COLLISION})
kntwr_payload(kntwr_payload_render_batch OUTPUT native_render_batch
  OBJECTS kntwr_render_batch EXPORTS ${KNTWR_EXPORTS_RENDER_BATCH})

foreach(_p worker_dispatch ballistics_helpers ballistics_collision render_batch)
  if(_p STREQUAL "ballistics_helpers")
    kntwr_export_names(_exports ${KNTWR_EXPORTS_BALLISTICS_HELPERS} ${KNTWR_EXPORTS_DISPATCH})
  elseif(_p STREQUAL "worker_dispatch")
    kntwr_export_names(_exports ${KNTWR_EXPORTS_DISPATCH})
  elseif(_p STREQUAL "ballistics_collision")
    kntwr_export_names(_exports ${KNTWR_EXPORTS_COLLISION})
  else()
    kntwr_export_names(_exports ${KNTWR_EXPORTS_RENDER_BATCH})
  endif()
  set(_cmd kntwr_pe_audit "$<TARGET_FILE:kntwr_payload_${_p}>" --no-imports --no-entry --no-code-relocs)
  foreach(_e IN LISTS _exports)
    list(APPEND _cmd --export ${_e})
  endforeach()
  add_test(NAME kntwr_payload_audit_${_p} COMMAND ${_cmd})
  set_tests_properties(kntwr_payload_audit_${_p} PROPERTIES LABELS "audit;native" TIMEOUT 60)
  kntwr_note_registered(kntwr_payload_audit_${_p})
endforeach()

# ---------------------------------------------------------------------------------------------------------------------
# Standalone host modules (same objects as the product DLL) for their owned-process harnesses
# ---------------------------------------------------------------------------------------------------------------------
kntwr_host_module(kntwr_module_query_cache OUTPUT native_ballistics_query_cache
  OBJECTS kntwr_ballistics_query_cache kntwr_ballistics_collision)
kntwr_host_module(kntwr_module_formation_runtime OUTPUT native_formation_runtime
  OBJECTS kntwr_formation_runtime kntwr_formation_batch kntwr_formation_layout kntwr_formation_slot kntwr_worker_dispatch)

add_test(NAME kntwr_module_audit_query_cache
  COMMAND kntwr_pe_audit "$<TARGET_FILE:kntwr_module_query_cache>"
          --export nqc_initialize --export nqc_stop --export nqc_query_hook --export nqc_gather_hook --export nqc_unit_hook --export nqc_state)
add_test(NAME kntwr_module_audit_formation_runtime
  COMMAND kntwr_pe_audit "$<TARGET_FILE:kntwr_module_formation_runtime>"
          --export nfr_initialize --export nfr_stop --export nfr_manager_hook --export nfr_assign_hook --export nfr_state)
set_tests_properties(kntwr_module_audit_query_cache kntwr_module_audit_formation_runtime PROPERTIES LABELS "audit;native" TIMEOUT 60)
kntwr_note_registered(kntwr_module_audit_query_cache)
kntwr_note_registered(kntwr_module_audit_formation_runtime)

# Product DLL contract: the ABI exports and every module export the runtime must keep resolvable.
if(TARGET kntwr_runtime)
  set(_runtime_exports kntwr_start kntwr_stop kntwr_state
      nfr_initialize nfr_stop nfr_manager_hook nfr_assign_hook nfr_state
      nqc_initialize nqc_stop nqc_query_hook nqc_gather_hook nqc_unit_hook nqc_state
      npr_initialize npr_stop npr_scheduler_hook npr_prepass npr_end npr_solve npr_state npr_storage_bytes)
  kntwr_export_names(_helper_exports ${KNTWR_EXPORTS_DISPATCH} ${KNTWR_EXPORTS_BALLISTICS_HELPERS}
                    ${KNTWR_EXPORTS_COLLISION} ${KNTWR_EXPORTS_RENDER_BATCH})
  list(APPEND _runtime_exports ${_helper_exports})
  set(_cmd kntwr_pe_audit "$<TARGET_FILE:kntwr_runtime>")
  foreach(_e IN LISTS _runtime_exports)
    list(APPEND _cmd --export ${_e})
  endforeach()
  add_test(NAME kntwr_runtime_exports COMMAND ${_cmd})
  set_tests_properties(kntwr_runtime_exports PROPERTIES LABELS "audit;native" TIMEOUT 60)
  kntwr_note_registered(kntwr_runtime_exports)
endif()

# ---------------------------------------------------------------------------------------------------------------------
# Self-contained native tests (no image, no capture)
# ---------------------------------------------------------------------------------------------------------------------
kntwr_harness(native_worker_dispatch_smoke STD 20 FP none
  SOURCES native_worker_dispatch_smoke.cpp INCLUDES "${KNTWR_SRC}/worker")
add_dependencies(native_worker_dispatch_smoke kntwr_payload_worker_dispatch)
add_test(NAME kntwr_worker_dispatch_smoke
  COMMAND native_worker_dispatch_smoke "$<TARGET_FILE:kntwr_payload_worker_dispatch>")
set_tests_properties(kntwr_worker_dispatch_smoke PROPERTIES LABELS "native" TIMEOUT 600)
kntwr_note_registered(kntwr_worker_dispatch_smoke)

kntwr_harness(native_render_batch_smoke STD 20 FP none SOURCES native_render_batch_smoke.cpp)
add_dependencies(native_render_batch_smoke kntwr_payload_render_batch)
add_test(NAME kntwr_render_batch_smoke
  COMMAND native_render_batch_smoke "$<TARGET_FILE:kntwr_payload_render_batch>")
set_tests_properties(kntwr_render_batch_smoke PROPERTIES LABELS "native" TIMEOUT 600)
kntwr_note_registered(kntwr_render_batch_smoke)

# ---------------------------------------------------------------------------------------------------------------------
# Ballistics (capture-backed kits; no image)
# ---------------------------------------------------------------------------------------------------------------------
kntwr_harness(native_ballistics_smoke STD 20 FP precise
  SOURCES native_ballistics_smoke.cpp INCLUDES "${KNTWR_SRC}/ballistics" "${KNTWR_SRC}/worker")
add_dependencies(native_ballistics_smoke kntwr_payload_ballistics_helpers)
kntwr_asset(_testkit native-ballistics-testkit.bin)
kntwr_asset(_corpus native-ballistics-live-28252.corpus.bin)
if(_testkit)
  set(_args "$<TARGET_FILE:kntwr_payload_ballistics_helpers>" "${_testkit}")
  if(_corpus)
    list(APPEND _args "${_corpus}")
  endif()
  add_test(NAME kntwr_ballistics_smoke COMMAND native_ballistics_smoke ${_args})
  set_tests_properties(kntwr_ballistics_smoke PROPERTIES LABELS "native;assets" TIMEOUT 1200)
  kntwr_note_registered(kntwr_ballistics_smoke)
else()
  kntwr_note_skipped(kntwr_ballistics_smoke "missing native-ballistics-testkit.bin in KNTWR_TEST_ASSETS")
endif()

kntwr_harness(native_ballistics_collision_harness STD 20 FP precise
  SOURCES native_ballistics_collision_harness.cpp OBJECTS kntwr_ballistics_collision INCLUDES "${KNTWR_SRC}/worker")
add_dependencies(native_ballistics_collision_harness kntwr_payload_worker_dispatch)
kntwr_asset(_ckit native-ballistics-collision-kit.bin)
kntwr_asset(_wkit native-ballistics-collision-worker-kit.bin)
if(_ckit AND _wkit)
  add_test(NAME kntwr_ballistics_collision
    COMMAND native_ballistics_collision_harness "${_ckit}" "${_wkit}" "$<TARGET_FILE:kntwr_payload_worker_dispatch>" 600)
  set_tests_properties(kntwr_ballistics_collision PROPERTIES LABELS "native;assets" TIMEOUT 1800)
  kntwr_note_registered(kntwr_ballistics_collision)
else()
  kntwr_note_skipped(kntwr_ballistics_collision "missing collision kit / worker kit in KNTWR_TEST_ASSETS")
endif()

# ---------------------------------------------------------------------------------------------------------------------
# Image oracles: the ORIGINAL machine code of KNTWR_TEST_IMAGE vs the port, inside the test process
# ---------------------------------------------------------------------------------------------------------------------
kntwr_harness(native_ballistics_query_cache_harness STD 20 FP strict
  SOURCES native_ballistics_query_cache_harness.cpp
  INCLUDES "${KNTWR_SRC}/ballistics" "${KNTWR_SRC}/worker" LIBS bcrypt)
add_dependencies(native_ballistics_query_cache_harness kntwr_module_query_cache kntwr_payload_worker_dispatch)

kntwr_harness(native_formation_slot_harness STD 17 FP strict
  SOURCES native_formation_slot_harness.cpp OBJECTS kntwr_formation_slot LIBS bcrypt)
kntwr_harness(native_formation_solver_oracle STD 20 FP strict
  SOURCES native_formation_solver_oracle.cpp "${KNTWR_SRC}/formation/native_formation_solver.cpp"
  INCLUDES "${KNTWR_SRC}/formation" LIBS bcrypt)
kntwr_harness(native_army_solver_chain_oracle STD 20 FP strict
  SOURCES native_army_solver_chain_oracle.cpp "${KNTWR_SRC}/clones/kntwr_clones.cpp" "${KNTWR_SRC}/army/native_army_solver.cpp"
          "${KNTWR_SRC}/formation/native_formation_solver.cpp" "${KNTWR_GAMEPLAY_PATCH_SOURCE}"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_formation_layout_oracle STD 20 FP strict
  SOURCES native_formation_layout_oracle.cpp OBJECTS kntwr_formation_layout LIBS bcrypt)
kntwr_harness(native_formation_batch_harness STD 20 FP strict
  SOURCES native_formation_batch_harness.cpp
  OBJECTS kntwr_formation_batch kntwr_formation_layout kntwr_formation_slot kntwr_worker_dispatch LIBS bcrypt)
kntwr_harness(native_formation_runtime_smoke STD 20 FP strict
  SOURCES native_formation_batch_harness.cpp DEFINES NFR_RUNTIME_SMOKE
  OBJECTS kntwr_formation_batch kntwr_formation_layout kntwr_formation_slot kntwr_worker_dispatch
  INCLUDES "${KNTWR_SRC}/formation" LIBS bcrypt)
add_dependencies(native_formation_runtime_smoke kntwr_module_formation_runtime)
kntwr_harness(native_path_workspace_oracle STD 17 FP strict
  SOURCES native_path_workspace_oracle.cpp OBJECTS kntwr_path LIBS bcrypt)
kntwr_harness(native_path_runtime_oracle STD 20 FP strict
  SOURCES native_path_runtime_oracle.cpp
  OBJECTS kntwr_path_runtime kntwr_path kntwr_worker_dispatch
  INCLUDES "${KNTWR_SRC}/path" "${KNTWR_SRC}/worker" LIBS bcrypt)
kntwr_harness(native_animation_oracle_smoke STD 20 FP precise
  SOURCES native_animation_oracle_smoke.cpp OBJECTS kntwr_animation_pose)
kntwr_harness(native_animation_render_batch_oracle STD 20 FP precise
  SOURCES native_animation_render_batch_oracle.cpp
  OBJECTS kntwr_animation_pose kntwr_animation_render_batch kntwr_worker_dispatch)
kntwr_harness(native_ballistics_runtime_integration STD 20 FP strict
  SOURCES native_ballistics_runtime_integration.cpp "${KNTWR_SRC}/clones/kntwr_clones.cpp"
  OBJECTS kntwr_ballistics_query_cache kntwr_ballistics_collision kntwr_worker_dispatch kntwr_ballistics_helpers
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/ballistics" "${KNTWR_SRC}/worker" LIBS bcrypt)
kntwr_harness(native_walk_memo_oracle STD 20 FP strict
  SOURCES native_walk_memo_oracle.cpp "${KNTWR_SRC}/clones/kntwr_clones.cpp" "${KNTWR_SRC}/ai/kntwr_walk_memo.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_planner_search_oracle STD 20 FP strict
  SOURCES native_planner_search_oracle.cpp "${KNTWR_SRC}/ai/kntwr_planner_search.cpp" "${KNTWR_SRC}/ai/kntwr_record_test.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_record_test_oracle STD 20 FP strict
  SOURCES native_record_test_oracle.cpp "${KNTWR_SRC}/ai/kntwr_planner_search.cpp" "${KNTWR_SRC}/ai/kntwr_record_test.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_ai_ctrl_geometry_oracle STD 20 FP strict
  SOURCES native_ai_ctrl_geometry_oracle.cpp "${KNTWR_SRC}/ai/kntwr_ai_ctrl_geometry.cpp" "${KNTWR_SRC}/ai/kntwr_ai_ctrl_batch.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_ai_ctrl_oracle STD 20 FP strict
  SOURCES native_ai_ctrl_oracle.cpp "${KNTWR_SRC}/ai/kntwr_ai_ctrl_batch.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_planner_prepass_oracle STD 20 FP strict
  SOURCES native_planner_prepass_oracle.cpp "${KNTWR_SRC}/clones/kntwr_clones.cpp" "${KNTWR_SRC}/ai/kntwr_planner_prepass.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_spiral_oracle STD 20 FP strict
  SOURCES native_spiral_oracle.cpp "${KNTWR_SRC}/clones/kntwr_clones.cpp" "${KNTWR_SRC}/ai/kntwr_spiral.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_claim_once_oracle STD 20 FP strict
  SOURCES native_claim_once_oracle.cpp "${KNTWR_SRC}/ai/kntwr_claim_once.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_retarget_jitter_oracle STD 20 FP strict
  SOURCES native_retarget_jitter_oracle.cpp "${KNTWR_SRC}/brain/kntwr_retarget_jitter.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_target_cull_oracle STD 20 FP strict
  SOURCES native_target_cull_oracle.cpp "${KNTWR_SRC}/brain/kntwr_target_cull.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_mounted_officer_oracle STD 20 FP strict
  SOURCES native_mounted_officer_oracle.cpp "${KNTWR_SRC}/army/kntwr_mounted_officer.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
# Pure cavalry-orbit policy: no image, no assets, no native memory.
kntwr_harness(native_cavalry_orbit_oracle STD 20 FP strict
  SOURCES native_cavalry_orbit.cpp "${KNTWR_SRC}/army/native_cavalry_orbit.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/army")
add_test(NAME kntwr_cavalry_orbit COMMAND native_cavalry_orbit_oracle)
set_tests_properties(kntwr_cavalry_orbit PROPERTIES LABELS "native" TIMEOUT 120)
kntwr_note_registered(kntwr_cavalry_orbit)
# Pure topology/worker-clamp decision rules (src/core/kntwr_topology.h): no image, no affinity changes.
kntwr_harness(native_topology_oracle STD 20 FP strict
  SOURCES native_topology_oracle.cpp
  INCLUDES "${KNTWR_SRC}")
add_test(NAME kntwr_topology COMMAND native_topology_oracle)
set_tests_properties(kntwr_topology PROPERTIES LABELS "native" TIMEOUT 60)
kntwr_note_registered(kntwr_topology)
# --drag-ladder file-count policy (src/formation/kntwr_drag_ladder.h LadderFiles): pure integer rules, no image, no live process.
kntwr_harness(native_drag_ladder_oracle STD 20 FP strict
  SOURCES native_drag_ladder_oracle.cpp
  INCLUDES "${KNTWR_SRC}")
add_test(NAME kntwr_drag_ladder COMMAND native_drag_ladder_oracle)
set_tests_properties(kntwr_drag_ladder PROPERTIES LABELS "native" TIMEOUT 60)
kntwr_note_registered(kntwr_drag_ladder)
# --wounded decision policy (src/animation/kntwr_wounded.h): pure integer rules, no image, no live process.
kntwr_harness(native_wounded_oracle STD 20 FP strict
  SOURCES native_wounded_oracle.cpp
  INCLUDES "${KNTWR_SRC}")
add_test(NAME kntwr_wounded COMMAND native_wounded_oracle)
set_tests_properties(kntwr_wounded PROPERTIES LABELS "native" TIMEOUT 60)
kntwr_note_registered(kntwr_wounded)
# Isolated adapter graph: no game image, native movement, input, or live processes.
kntwr_harness(native_cavalry_runtime_oracle STD 20 FP strict
  SOURCES native_cavalry_runtime.cpp "${KNTWR_SRC}/army/native_cavalry_orbit.cpp"
  INCLUDES "${KNTWR_SRC}")
add_test(NAME kntwr_cavalry_runtime COMMAND native_cavalry_runtime_oracle)
set_tests_properties(kntwr_cavalry_runtime PROPERTIES LABELS "synthetic" TIMEOUT 120)
kntwr_note_registered(kntwr_cavalry_runtime)
kntwr_harness(native_clip_picker_guard_oracle STD 20 FP strict
  SOURCES native_clip_picker_guard_oracle.cpp "${KNTWR_SRC}/animation/kntwr_clip_picker_guard.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_drag_ladder_hook_oracle STD 20 FP strict
  SOURCES native_drag_ladder_hook_oracle.cpp "${KNTWR_SRC}/formation/kntwr_drag_ladder_hook.cpp"
  OBJECTS kntwr_formation_layout
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_wounded_hook_oracle STD 20 FP strict
  SOURCES native_wounded_hook_oracle.cpp "${KNTWR_SRC}/animation/kntwr_wounded_hook.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_terrain_merge_guard_oracle STD 20 FP strict
  SOURCES native_terrain_merge_guard_oracle.cpp "${KNTWR_SRC}/ai/kntwr_terrain_merge_guard.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
kntwr_harness(native_collision_solver_oracle STD 20 FP strict
  SOURCES native_collision_solver_oracle.cpp "${KNTWR_SRC}/collision/native_collision_solver.cpp"
          "${KNTWR_SRC}/collision/native_contact.cpp"
  OBJECTS kntwr_worker_dispatch
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/collision" "${KNTWR_SRC}/worker" LIBS bcrypt)
kntwr_harness(native_contact_oracle STD 20 FP strict
  SOURCES native_contact_oracle.cpp "${KNTWR_SRC}/collision/native_contact.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/collision" LIBS bcrypt)
kntwr_harness(native_brain2_oracle STD 20 FP strict
  SOURCES native_brain2_oracle.cpp "${KNTWR_SRC}/brain2/native_brain2.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/brain2/native_node.cpp" "${KNTWR_SRC}/brain2/native_node_projection.cpp" "${KNTWR_SRC}/brain2/native_fire.cpp"
          "${KNTWR_SRC}/brain2/native_finalizer.cpp"
          "${KNTWR_SRC}/brain2/native_move_node.cpp"
          "${KNTWR_SRC}/brain2/native_idle_node.cpp" "${KNTWR_SRC}/brain2/native_action_node.cpp"
          "${KNTWR_SRC}/brain2/native_brain_s0.cpp" "${KNTWR_SRC}/brain2/native_brain_locality.cpp"
          "${KNTWR_SRC}/brain2/native_unit_policy.cpp" "${KNTWR_SRC}/brain2/native_unit_select.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
kntwr_harness(native_brain_workers_oracle STD 20 FP strict
  SOURCES native_brain_workers_oracle.cpp "${KNTWR_SRC}/brain2/native_brain_workers.cpp"
          "${KNTWR_SRC}/brain2/native_brain2.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/brain2/native_node.cpp" "${KNTWR_SRC}/brain2/native_node_projection.cpp" "${KNTWR_SRC}/brain2/native_fire.cpp"
          "${KNTWR_SRC}/brain2/native_finalizer.cpp"
          "${KNTWR_SRC}/brain2/native_move_node.cpp"
          "${KNTWR_SRC}/brain2/native_idle_node.cpp" "${KNTWR_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" DEFINES KNTWR_BRAIN_WORKERS_ORACLE LIBS bcrypt)
# Untouched mapped 585D50 versus the production two-loop port, plain and inside the real census occurrence.
kntwr_harness(native_formation_residual_oracle STD 20 FP strict
  SOURCES native_formation_residual_oracle.cpp
          "${KNTWR_SRC}/army/native_formation_residual.cpp"
          "${KNTWR_SRC}/army/native_formation_queue.cpp"
          "${KNTWR_SRC}/army/native_army_storm.cpp"
          "${KNTWR_SRC}/army/native_army_solver.cpp"
          "${KNTWR_SRC}/formation/native_formation_solver.cpp"
          "${KNTWR_SRC}/clones/kntwr_clones.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
# Untouched mapped 581E80 (formation command queue walk) versus the diagnostic port: observer off/on, call-through erase.
kntwr_harness(native_formation_queue_oracle STD 20 FP strict
  SOURCES native_formation_queue_oracle.cpp
          "${KNTWR_SRC}/army/native_formation_queue.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
# Untouched mapped 581CA0 command chain (581E80 walk -> 581CA0 -> 10FC370 -> 10FBBD0 -> 4F84C0 -> 5736B0) versus the private
# census clones through the real storm census occurrence: observer off / refused / armed / abort / exception native twins.
kntwr_harness(native_formation_command_split_oracle STD 20 FP strict
  SOURCES native_formation_command_split_oracle.cpp
          "${KNTWR_SRC}/army/native_formation_residual.cpp"
          "${KNTWR_SRC}/army/native_formation_queue.cpp"
          "${KNTWR_SRC}/army/native_army_storm.cpp"
          "${KNTWR_SRC}/army/native_army_solver.cpp"
          "${KNTWR_SRC}/formation/native_formation_solver.cpp"
          "${KNTWR_SRC}/clones/kntwr_clones.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
# Per-unit brain Stage A: synthetic soldiers/units (no image); links kntwr_brain2::RunWorklist for the observer seam.
kntwr_harness(native_unit_brain_oracle STD 20 FP strict
  SOURCES native_unit_brain_oracle.cpp "${KNTWR_SRC}/brain2/native_unit_brain.cpp"
          "${KNTWR_SRC}/brain2/native_brain2.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/brain2/native_node.cpp" "${KNTWR_SRC}/brain2/native_node_projection.cpp" "${KNTWR_SRC}/brain2/native_fire.cpp"
          "${KNTWR_SRC}/brain2/native_finalizer.cpp"
          "${KNTWR_SRC}/brain2/native_move_node.cpp"
          "${KNTWR_SRC}/brain2/native_idle_node.cpp" "${KNTWR_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
add_test(NAME kntwr_unit_brain_oracle COMMAND native_unit_brain_oracle)
set_tests_properties(kntwr_unit_brain_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 120)
kntwr_note_registered(kntwr_unit_brain_oracle)
# Army per-unit update Stage A: synthetic units/containers (no image); classifier, probe reader and module gates.
kntwr_harness(native_army_unit_oracle STD 20 FP strict
  SOURCES native_army_unit_oracle.cpp "${KNTWR_SRC}/army/native_army_unit.cpp"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include")
add_test(NAME kntwr_army_unit_oracle COMMAND native_army_unit_oracle)
set_tests_properties(kntwr_army_unit_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 120)
kntwr_note_registered(kntwr_army_unit_oracle)
kntwr_harness(native_node_oracle STD 20 FP strict
  SOURCES native_node_oracle.cpp "${KNTWR_SRC}/brain2/native_node.cpp" "${KNTWR_SRC}/brain2/native_node_projection.cpp"
          "${KNTWR_SRC}/brain2/native_brain2.cpp" "${KNTWR_SRC}/brain2/native_fire.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/brain2/native_finalizer.cpp"
          "${KNTWR_SRC}/brain2/native_move_node.cpp"
          "${KNTWR_SRC}/brain2/native_idle_node.cpp" "${KNTWR_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
kntwr_harness(native_move_node_oracle STD 20 FP strict
  SOURCES native_move_node_oracle.cpp "${KNTWR_SRC}/brain2/native_move_node.cpp"
          "${KNTWR_SRC}/brain2/native_idle_node.cpp" "${KNTWR_SRC}/brain2/native_action_node.cpp"
          "${KNTWR_SRC}/brain2/native_node.cpp" "${KNTWR_SRC}/brain2/native_node_projection.cpp"
          "${KNTWR_SRC}/brain2/native_brain2.cpp" "${KNTWR_SRC}/brain2/native_fire.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/brain2/native_brain_s0.cpp"
          "${KNTWR_SRC}/brain2/native_unit_policy.cpp" "${KNTWR_SRC}/brain2/native_unit_select.cpp"
          "${KNTWR_SRC}/brain2/native_finalizer.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
# The native and owned follow-node paths share mounted-officer placement.
foreach(_consumer native_brain2_oracle native_brain_workers_oracle native_unit_brain_oracle native_node_oracle native_move_node_oracle)
  target_sources(${_consumer} PRIVATE "${KNTWR_SRC}/army/kntwr_mounted_officer.cpp")
endforeach()
# Per-unit posture / engage: the BRAIN_U_* clones and gates against the mapped originals (private relocated image).
kntwr_harness(native_unit_posture_engage_oracle STD 20 FP strict
  SOURCES native_unit_posture_engage_oracle.cpp "${KNTWR_SRC}/brain2/native_unit_posture_engage.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
# Per-unit fatigue (S4): the ported 670F40 arithmetic against the mapped original, unit model, gate ABI, provider through the
# shared module on a manager/registry fixture.
kntwr_harness(native_unit_fatigue_oracle STD 20 FP strict
  SOURCES native_unit_fatigue_oracle.cpp "${KNTWR_SRC}/brain2/native_unit_fatigue.cpp"
          "${KNTWR_SRC}/brain2/native_unit_policy.cpp" "${KNTWR_SRC}/brain2/native_unit_select.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
kntwr_harness(native_fire_oracle STD 20 FP strict
  SOURCES native_fire_oracle.cpp "${KNTWR_SRC}/brain2/native_fire.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/brain2" LIBS bcrypt)
kntwr_harness(native_loco_oracle STD 20 FP strict
  SOURCES native_loco_oracle.cpp "${KNTWR_SRC}/loco/native_loco.cpp" "${KNTWR_SRC}/loco/native_move_delta.cpp" "${KNTWR_SRC}/loco/native_relink.cpp" "${KNTWR_SRC}/clones/kntwr_clones.cpp"
          "${KNTWR_SRC}/loco/native_sweep.cpp" "${KNTWR_SRC}/loco/native_resolve.cpp" "${KNTWR_SRC}/loco/native_env.cpp"
          "${KNTWR_SRC}/collision/native_collision_solver.cpp" "${KNTWR_SRC}/collision/native_contact.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/loco" DEFINES KNTWR_LOCO_ORACLE=1 LIBS bcrypt)
kntwr_harness(native_sweep_oracle STD 20 FP strict
  SOURCES native_sweep_oracle.cpp "${KNTWR_SRC}/loco/native_sweep.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/loco")
kntwr_harness(native_resolve_oracle STD 20 FP strict
  SOURCES native_resolve_oracle.cpp "${KNTWR_SRC}/loco/native_resolve.cpp" "${KNTWR_SRC}/loco/native_sweep.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/loco" LIBS bcrypt)
kntwr_harness(native_env_oracle STD 20 FP strict
  SOURCES native_env_oracle.cpp "${KNTWR_SRC}/loco/native_env.cpp" "${KNTWR_SRC}/loco/native_sweep.cpp"
  INCLUDES "${KNTWR_SRC}" "${KNTWR_SRC}/loco" LIBS bcrypt)
add_test(NAME kntwr_sweep_oracle COMMAND native_sweep_oracle)
set_tests_properties(kntwr_sweep_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 60)
kntwr_note_registered(kntwr_sweep_oracle)
if(TARGET kntwr_runtime)
  kntwr_harness(native_runtime_lifecycle STD 20 FP strict SOURCES native_runtime_lifecycle.cpp
    INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include")
  add_dependencies(native_runtime_lifecycle kntwr_runtime)
endif()
# In-memory gameplay patch: the applier (src/core/kntwr_gameplay_patch.c, also linked into kntwr.exe) against the loader-equivalent
# patched image. Needs the STOCK game file (KNTWR_STOCK_IMAGE) next to the generated patched image.
kntwr_harness(native_gameplay_patch_oracle STD 20 FP strict
  SOURCES native_gameplay_patch_oracle.cpp "${KNTWR_GAMEPLAY_PATCH_SOURCE}"
  INCLUDES "${KNTWR_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)

# The chain oracle maps stock and applies the production overlay itself; no historical patched image is required.
kntwr_asset(_solver_table native-formation-angle-table-28252.bin)
if(NOT _solver_table)
  kntwr_note_skipped(kntwr_army_solver_chain "missing native-formation-angle-table-28252.bin")
  kntwr_note_skipped(kntwr_army_solver_chain_stock_cache "missing native-formation-angle-table-28252.bin")
elseif(KNTWR_STOCK_IMAGE AND EXISTS "${KNTWR_STOCK_IMAGE}")
  file(TO_NATIVE_PATH "${KNTWR_STOCK_IMAGE}" _solver_stock_arg)
  add_test(NAME kntwr_army_solver_chain
    COMMAND native_army_solver_chain_oracle --image "${_solver_stock_arg}" --table "${_solver_table}" --cases 300 --seed 20261018)
  add_test(NAME kntwr_army_solver_chain_stock_cache
    COMMAND native_army_solver_chain_oracle --image "${_solver_stock_arg}" --table "${_solver_table}" --cases 300 --seed 20261018 --skip-cache-overlay 1)
  set_tests_properties(kntwr_army_solver_chain kntwr_army_solver_chain_stock_cache PROPERTIES LABELS "image;assets" TIMEOUT 3600)
  kntwr_note_registered(kntwr_army_solver_chain)
  kntwr_note_registered(kntwr_army_solver_chain_stock_cache)
else()
  kntwr_note_skipped(kntwr_army_solver_chain "KNTWR_STOCK_IMAGE not set to the stock Napoleon.exe")
  kntwr_note_skipped(kntwr_army_solver_chain_stock_cache "KNTWR_STOCK_IMAGE not set to the stock Napoleon.exe")
endif()

if(KNTWR_HAVE_IMAGE)
  kntwr_asset(_table native-formation-angle-table-28252.bin)
  kntwr_asset(_clones native-ballistics-query-clones.bin)
  kntwr_asset(_live native-formation-layout-live-replay.bin)
  kntwr_asset(_fixture native-formation-fixture-28252.bin)

  if(_clones AND _wkit)
    add_test(NAME kntwr_ballistics_query_cache
      COMMAND native_ballistics_query_cache_harness --image "${KNTWR_IMAGE_ARG}"
              --cache-dll "$<TARGET_FILE:kntwr_module_query_cache>" --clones "${_clones}" --worker-kit "${_wkit}"
              --pool-dll "$<TARGET_FILE:kntwr_payload_worker_dispatch>"
              --worlds 240 --seed 6392 --workers 3 --wrapper 1 --strict-wrapper 0)
    set_tests_properties(kntwr_ballistics_query_cache PROPERTIES LABELS "image;assets" TIMEOUT 3600)
    kntwr_note_registered(kntwr_ballistics_query_cache)
  else()
    kntwr_note_skipped(kntwr_ballistics_query_cache "missing query clones / collision worker kit")
  endif()

  if(_table)
    set(_slot_args --image "${KNTWR_IMAGE_ARG}" --table "${_table}" --cases 2000 --seed 1)
    if(_fixture)
      list(APPEND _slot_args --fixture "${_fixture}")
    endif()
    add_test(NAME kntwr_formation_slot COMMAND native_formation_slot_harness ${_slot_args})
    add_test(NAME kntwr_formation_batch
      COMMAND native_formation_batch_harness --image "${KNTWR_IMAGE_ARG}" --table "${_table}"
              --cases 400 --seed 20261013 --workers 0)
    add_test(NAME kntwr_formation_runtime
      COMMAND native_formation_runtime_smoke --image "${KNTWR_IMAGE_ARG}" --table "${_table}"
              --runtime-dll "$<TARGET_FILE:kntwr_module_formation_runtime>" --cases 400 --seed 20261013 --workers 0)
    set_tests_properties(kntwr_formation_slot kntwr_formation_batch kntwr_formation_runtime
                         PROPERTIES LABELS "image;assets" TIMEOUT 3600)
    kntwr_note_registered(kntwr_formation_slot)
    kntwr_note_registered(kntwr_formation_batch)
    kntwr_note_registered(kntwr_formation_runtime)
    add_test(NAME kntwr_formation_solver
      COMMAND native_formation_solver_oracle --image "${KNTWR_IMAGE_ARG}" --table "${_table}"
              --cases 2000 --seed 20261018 --bench 0)
    set_tests_properties(kntwr_formation_solver PROPERTIES LABELS "image;assets" TIMEOUT 3600)
    kntwr_note_registered(kntwr_formation_solver)
  else()
    kntwr_note_skipped(kntwr_formation_slot "missing native-formation-angle-table-28252.bin")
    kntwr_note_skipped(kntwr_formation_batch "missing native-formation-angle-table-28252.bin")
    kntwr_note_skipped(kntwr_formation_runtime "missing native-formation-angle-table-28252.bin")
    kntwr_note_skipped(kntwr_formation_solver "missing native-formation-angle-table-28252.bin")
  endif()

  set(_layout_args "${KNTWR_IMAGE_ARG}" cases=300 seed=20240601)
  if(_live)
    list(APPEND _layout_args "live=${_live}")
  endif()
  add_test(NAME kntwr_formation_layout COMMAND native_formation_layout_oracle ${_layout_args})
  add_test(NAME kntwr_path_workspace COMMAND native_path_workspace_oracle "${KNTWR_IMAGE_ARG}" cases=40 seed=20261013)
  add_test(NAME kntwr_path_runtime COMMAND native_path_runtime_oracle "${KNTWR_IMAGE_ARG}" cases=16 seed=20261013)
  add_test(NAME kntwr_animation_pose COMMAND native_animation_oracle_smoke "${KNTWR_IMAGE_ARG}")
  add_test(NAME kntwr_animation_render_batch COMMAND native_animation_render_batch_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_formation_layout kntwr_path_workspace kntwr_path_runtime
                       kntwr_animation_pose kntwr_animation_render_batch
                       PROPERTIES LABELS "image" TIMEOUT 3600)
  kntwr_note_registered(kntwr_formation_layout)
  kntwr_note_registered(kntwr_path_workspace)
  kntwr_note_registered(kntwr_path_runtime)
  kntwr_note_registered(kntwr_animation_pose)
  kntwr_note_registered(kntwr_animation_render_batch)
  add_test(NAME kntwr_ballistics_runtime_integration
    COMMAND native_ballistics_runtime_integration "${KNTWR_IMAGE_ARG}" worlds=64 workers=3 seed=6392)
  set_tests_properties(kntwr_ballistics_runtime_integration PROPERTIES LABELS "image" TIMEOUT 1800)
  kntwr_note_registered(kntwr_ballistics_runtime_integration)
  add_test(NAME kntwr_walk_memo COMMAND native_walk_memo_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_walk_memo PROPERTIES LABELS "image" TIMEOUT 120)
  kntwr_note_registered(kntwr_walk_memo)
  add_test(NAME kntwr_planner_search COMMAND native_planner_search_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_planner_search PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_planner_search)
  add_test(NAME kntwr_record_test COMMAND native_record_test_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_record_test PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_record_test)
  add_test(NAME kntwr_ai_ctrl_geometry COMMAND native_ai_ctrl_geometry_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_ai_ctrl_geometry PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_ai_ctrl_geometry)
  add_test(NAME kntwr_ai_ctrl_oracle COMMAND native_ai_ctrl_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_ai_ctrl_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_ai_ctrl_oracle)
  add_test(NAME kntwr_planner_prepass COMMAND native_planner_prepass_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_planner_prepass PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_planner_prepass)
  add_test(NAME kntwr_spiral COMMAND native_spiral_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_spiral PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_spiral)
  add_test(NAME kntwr_claim_once COMMAND native_claim_once_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_claim_once PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_claim_once)
  add_test(NAME kntwr_retarget_jitter COMMAND native_retarget_jitter_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_retarget_jitter PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_retarget_jitter)
  add_test(NAME kntwr_target_cull COMMAND native_target_cull_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_target_cull PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_target_cull)
  add_test(NAME kntwr_mounted_officer COMMAND native_mounted_officer_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_mounted_officer PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_mounted_officer)
  add_test(NAME kntwr_clip_picker_guard COMMAND native_clip_picker_guard_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_clip_picker_guard PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_clip_picker_guard)
  add_test(NAME kntwr_drag_ladder_hook COMMAND native_drag_ladder_hook_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_drag_ladder_hook PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_drag_ladder_hook)
  add_test(NAME kntwr_wounded_hook COMMAND native_wounded_hook_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_wounded_hook PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_wounded_hook)
  add_test(NAME kntwr_terrain_merge_guard COMMAND native_terrain_merge_guard_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_terrain_merge_guard PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_terrain_merge_guard)
  add_test(NAME kntwr_collision_solver COMMAND native_collision_solver_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_collision_solver PROPERTIES LABELS "image" TIMEOUT 300)
  add_test(NAME kntwr_contact_oracle COMMAND native_contact_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_contact_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_contact_oracle)
  add_test(NAME kntwr_brain2_oracle COMMAND native_brain2_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_brain2_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_brain2_oracle)
  add_test(NAME kntwr_brain_workers_oracle COMMAND native_brain_workers_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_brain_workers_oracle PROPERTIES LABELS "image" TIMEOUT 600)
  kntwr_note_registered(kntwr_brain_workers_oracle)
  add_test(NAME kntwr_formation_residual_oracle COMMAND native_formation_residual_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_formation_residual_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_formation_residual_oracle)
  add_test(NAME kntwr_formation_queue_oracle COMMAND native_formation_queue_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_formation_queue_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_formation_queue_oracle)
  add_test(NAME kntwr_formation_command_split COMMAND native_formation_command_split_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_formation_command_split PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_formation_command_split)
  add_test(NAME kntwr_node_oracle COMMAND native_node_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_node_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_node_oracle)
  add_test(NAME kntwr_move_node_oracle COMMAND native_move_node_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_move_node_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_move_node_oracle)
  add_test(NAME kntwr_unit_posture_engage_oracle COMMAND native_unit_posture_engage_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_unit_posture_engage_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 600)
  kntwr_note_registered(kntwr_unit_posture_engage_oracle)
  add_test(NAME kntwr_unit_fatigue_oracle COMMAND native_unit_fatigue_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_unit_fatigue_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_unit_fatigue_oracle)
  add_test(NAME kntwr_fire_oracle COMMAND native_fire_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_fire_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_fire_oracle)
  add_test(NAME kntwr_loco_oracle COMMAND native_loco_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_loco_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  kntwr_note_registered(kntwr_loco_oracle)
  add_test(NAME kntwr_resolve_oracle COMMAND native_resolve_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_resolve_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_resolve_oracle)
  add_test(NAME kntwr_env_oracle COMMAND native_env_oracle "${KNTWR_IMAGE_ARG}")
  set_tests_properties(kntwr_env_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  kntwr_note_registered(kntwr_env_oracle)
  kntwr_note_registered(kntwr_collision_solver)
  if(TARGET native_runtime_lifecycle)
    add_test(NAME kntwr_runtime_lifecycle
      COMMAND native_runtime_lifecycle "${KNTWR_IMAGE_ARG}" "$<TARGET_FILE:kntwr_runtime>")
    set_tests_properties(kntwr_runtime_lifecycle PROPERTIES LABELS "image" TIMEOUT 120)
    kntwr_note_registered(kntwr_runtime_lifecycle)
  endif()
  if(KNTWR_STOCK_IMAGE AND EXISTS "${KNTWR_STOCK_IMAGE}")
    file(TO_NATIVE_PATH "${KNTWR_STOCK_IMAGE}" _stock_arg)
    get_filename_component(_stock_dir "${KNTWR_STOCK_IMAGE}" DIRECTORY)
    set(_gp_args --patched "${KNTWR_IMAGE_ARG}" --stock "${_stock_arg}")
    kntwr_asset(_mss_patched mss32_patched.dll)
    if(_mss_patched AND EXISTS "${_stock_dir}/mss32.dll")
      file(TO_NATIVE_PATH "${_stock_dir}/mss32.dll" _mss_stock)
      list(APPEND _gp_args --mss32-patched "${_mss_patched}" --mss32-stock "${_mss_stock}")
    endif()
    # --process also creates the stock game SUSPENDED (no instruction of it ever runs), applies the patch through the process
    # backend and compares the whole live image with the loader image of the patched file.
    list(APPEND _gp_args --process)
    add_test(NAME kntwr_gameplay_patch COMMAND native_gameplay_patch_oracle ${_gp_args})
    set_tests_properties(kntwr_gameplay_patch PROPERTIES LABELS "image" TIMEOUT 300)
    kntwr_note_registered(kntwr_gameplay_patch)
  else()
    kntwr_note_skipped(kntwr_gameplay_patch "KNTWR_STOCK_IMAGE not set to the stock Napoleon.exe")
  endif()
else()
  foreach(_t ballistics_query_cache ballistics_runtime_integration formation_slot formation_batch formation_runtime
             formation_residual_oracle formation_queue_oracle formation_command_split
             formation_layout path_workspace path_runtime animation_pose animation_render_batch walk_memo ai_ctrl_geometry ai_ctrl_oracle planner_prepass planner_search record_test collision_solver contact_oracle brain2_oracle brain_workers_oracle node_oracle fire_oracle loco_oracle resolve_oracle)
    kntwr_note_skipped(kntwr_${_t} "KNTWR_TEST_IMAGE not set to an existing Napoleon.exe")
  endforeach()
  if(TARGET native_runtime_lifecycle)
    kntwr_note_skipped(kntwr_runtime_lifecycle "KNTWR_TEST_IMAGE not set to an existing Napoleon.exe")
  endif()
endif()

# Launcher version.  No game files: --version returns before discovery.  Dots in the version are literal.
if(TARGET kntwr)
  string(REPLACE "." "\\." _kntwr_version_re "${PROJECT_VERSION}")
  add_test(NAME kntwr_launcher_version COMMAND kntwr --version)
  set_tests_properties(kntwr_launcher_version PROPERTIES
    PASS_REGULAR_EXPRESSION "KNTWR ${_kntwr_version_re}"
    LABELS "native"
    TIMEOUT 30)
  kntwr_note_registered(kntwr_launcher_version)
else()
  kntwr_note_skipped(kntwr_launcher_version "KNTWR_BUILD_RUNTIME is OFF")
endif()

get_property(_reg GLOBAL PROPERTY KNTWR_TESTS_REGISTERED)
get_property(_skip GLOBAL PROPERTY KNTWR_TESTS_SKIPPED)
list(JOIN _reg ", " _reg_text)
message(STATUS "kntwr tests registered: ${_reg_text}")
if(_skip)
  list(JOIN _skip "; " _skip_text)
  message(STATUS "kntwr tests NOT registered (missing input): ${_skip_text}")
endif()
