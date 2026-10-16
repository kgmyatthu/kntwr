# Native oracles, harnesses and payload audits.  Every executable is a real differential/native test with a meaningful exit
# code.  Nothing here is part of the product and nothing here launches or touches the game: the oracles map a private
# relocated copy of the supported image inside their own process.
#
#   NTW2_TEST_IMAGE   path of the supported Napoleon.exe  -> enables the image oracles
#   NTW2_TEST_ASSETS  directory of pinned captures        -> enables kit/clone/table based tests
# A test whose input is missing is NOT registered (and is listed at configure time); it is never registered as a pass.

set(NTW2_TEST_DIR "${CMAKE_BINARY_DIR}/bin/tests")

if(NOT NTW2_TEST_IMAGE AND DEFINED ENV{NTW2_TEST_IMAGE})
  set(NTW2_TEST_IMAGE "$ENV{NTW2_TEST_IMAGE}")
endif()
set(NTW2_HAVE_IMAGE OFF)
if(NTW2_TEST_IMAGE AND EXISTS "${NTW2_TEST_IMAGE}")
  set(NTW2_HAVE_IMAGE ON)
  file(TO_NATIVE_PATH "${NTW2_TEST_IMAGE}" NTW2_IMAGE_ARG)
endif()

set_property(GLOBAL PROPERTY NTW2_TESTS_REGISTERED "")
set_property(GLOBAL PROPERTY NTW2_TESTS_SKIPPED "")

function(ntw2_note_registered name)
  set_property(GLOBAL APPEND PROPERTY NTW2_TESTS_REGISTERED "${name}")
endfunction()
function(ntw2_note_skipped name reason)
  set_property(GLOBAL APPEND PROPERTY NTW2_TESTS_SKIPPED "${name} (${reason})")
endfunction()

# ntw2_asset(<out> <file>): native path of NTW2_TEST_ASSETS/<file>, empty when absent.
function(ntw2_asset out file)
  if(EXISTS "${NTW2_TEST_ASSETS}/${file}")
    file(TO_NATIVE_PATH "${NTW2_TEST_ASSETS}/${file}" _p)
    set(${out} "${_p}" PARENT_SCOPE)
  else()
    set(${out} "" PARENT_SCOPE)
  endif()
endfunction()

# ntw2_export_names(<out> <link flags...>): undecorated public names of /EXPORT:name[=decorated][,DATA] flags.
function(ntw2_export_names out)
  set(_names "")
  foreach(_f IN LISTS ARGN)
    string(REGEX REPLACE "^/EXPORT:([^=,]+).*$" "\\1" _n "${_f}")
    list(APPEND _names "${_n}")
  endforeach()
  set(${out} "${_names}" PARENT_SCOPE)
endfunction()

# ntw2_harness(<target> STD <n> FP <strict|precise|none> SOURCES ... [OBJECTS ...] [INCLUDES ...] [DEFINES ...] [LIBS ...])
function(ntw2_harness target)
  cmake_parse_arguments(H "" "STD;FP" "SOURCES;OBJECTS;INCLUDES;DEFINES;LIBS" ${ARGN})
  add_executable(${target} ${H_SOURCES})
  ntw2_host_flags(${target} ${H_STD} ${H_FP})
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support" ${H_INCLUDES})
  if(H_DEFINES)
    target_compile_definitions(${target} PRIVATE ${H_DEFINES})
  endif()
  if(H_OBJECTS OR H_LIBS)
    target_link_libraries(${target} PRIVATE ${H_OBJECTS} ${H_LIBS})
  endif()
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${NTW2_TEST_DIR}")
endfunction()

# ntw2_payload(<target> OUTPUT <name> OBJECTS <object libs...> EXPORTS <link flags...>)
# Standalone import-free x86 DLL (no CRT, no entry point, no manifest): the shape of the code the runtime copies into owned
# allocations.  Distinct from the full host DLL.
function(ntw2_payload target)
  cmake_parse_arguments(P "" "OUTPUT" "OBJECTS;EXPORTS" ${ARGN})
  set(_objs "")
  foreach(_o IN LISTS P_OBJECTS)
    list(APPEND _objs "$<TARGET_OBJECTS:${_o}>")
  endforeach()
  add_library(${target} SHARED ${_objs})
  set_target_properties(${target} PROPERTIES LINKER_LANGUAGE C OUTPUT_NAME ${P_OUTPUT}
                        RUNTIME_OUTPUT_DIRECTORY "${NTW2_TEST_DIR}")
  ntw2_payload_link(${target})
  target_link_options(${target} PRIVATE /MANIFEST:NO ${P_EXPORTS})
endfunction()

# ntw2_host_module(<target> OUTPUT <name> OBJECTS <object libs...>)
# Standalone CRT-linked module DLL carrying the same objects as the product DLL; exports come from /EXPORT pragmas.
function(ntw2_host_module target)
  cmake_parse_arguments(M "" "OUTPUT" "OBJECTS" ${ARGN})
  set(_objs "")
  foreach(_o IN LISTS M_OBJECTS)
    list(APPEND _objs "$<TARGET_OBJECTS:${_o}>")
  endforeach()
  add_library(${target} SHARED ${_objs})
  set_target_properties(${target} PROPERTIES LINKER_LANGUAGE CXX OUTPUT_NAME ${M_OUTPUT}
                        RUNTIME_OUTPUT_DIRECTORY "${NTW2_TEST_DIR}")
endfunction()

# ---------------------------------------------------------------------------------------------------------------------
# Import-free payload DLLs + structural audits
# ---------------------------------------------------------------------------------------------------------------------
ntw2_payload(ntw2_payload_worker_dispatch OUTPUT native_worker_dispatch
  OBJECTS ntw2_worker_dispatch EXPORTS ${NTW2_EXPORTS_DISPATCH})
ntw2_payload(ntw2_payload_ballistics_helpers OUTPUT native_ballistics_helpers
  OBJECTS ntw2_ballistics_helpers ntw2_worker_dispatch EXPORTS ${NTW2_EXPORTS_BALLISTICS_HELPERS} ${NTW2_EXPORTS_DISPATCH})
ntw2_payload(ntw2_payload_ballistics_collision OUTPUT native_ballistics_collision
  OBJECTS ntw2_ballistics_collision EXPORTS ${NTW2_EXPORTS_COLLISION})
ntw2_payload(ntw2_payload_render_batch OUTPUT native_render_batch
  OBJECTS ntw2_render_batch EXPORTS ${NTW2_EXPORTS_RENDER_BATCH})

foreach(_p worker_dispatch ballistics_helpers ballistics_collision render_batch)
  if(_p STREQUAL "ballistics_helpers")
    ntw2_export_names(_exports ${NTW2_EXPORTS_BALLISTICS_HELPERS} ${NTW2_EXPORTS_DISPATCH})
  elseif(_p STREQUAL "worker_dispatch")
    ntw2_export_names(_exports ${NTW2_EXPORTS_DISPATCH})
  elseif(_p STREQUAL "ballistics_collision")
    ntw2_export_names(_exports ${NTW2_EXPORTS_COLLISION})
  else()
    ntw2_export_names(_exports ${NTW2_EXPORTS_RENDER_BATCH})
  endif()
  set(_cmd ntw2_pe_audit "$<TARGET_FILE:ntw2_payload_${_p}>" --no-imports --no-entry --no-code-relocs)
  foreach(_e IN LISTS _exports)
    list(APPEND _cmd --export ${_e})
  endforeach()
  add_test(NAME ntw2_payload_audit_${_p} COMMAND ${_cmd})
  set_tests_properties(ntw2_payload_audit_${_p} PROPERTIES LABELS "audit;native" TIMEOUT 60)
  ntw2_note_registered(ntw2_payload_audit_${_p})
endforeach()

# ---------------------------------------------------------------------------------------------------------------------
# Standalone host modules (same objects as the product DLL) for their owned-process harnesses
# ---------------------------------------------------------------------------------------------------------------------
ntw2_host_module(ntw2_module_query_cache OUTPUT native_ballistics_query_cache
  OBJECTS ntw2_ballistics_query_cache ntw2_ballistics_collision)
ntw2_host_module(ntw2_module_formation_runtime OUTPUT native_formation_runtime
  OBJECTS ntw2_formation_runtime ntw2_formation_batch ntw2_formation_layout ntw2_formation_slot ntw2_worker_dispatch)

add_test(NAME ntw2_module_audit_query_cache
  COMMAND ntw2_pe_audit "$<TARGET_FILE:ntw2_module_query_cache>"
          --export nqc_initialize --export nqc_stop --export nqc_query_hook --export nqc_gather_hook --export nqc_unit_hook --export nqc_state)
add_test(NAME ntw2_module_audit_formation_runtime
  COMMAND ntw2_pe_audit "$<TARGET_FILE:ntw2_module_formation_runtime>"
          --export nfr_initialize --export nfr_stop --export nfr_manager_hook --export nfr_assign_hook --export nfr_state)
set_tests_properties(ntw2_module_audit_query_cache ntw2_module_audit_formation_runtime PROPERTIES LABELS "audit;native" TIMEOUT 60)
ntw2_note_registered(ntw2_module_audit_query_cache)
ntw2_note_registered(ntw2_module_audit_formation_runtime)

# Product DLL contract: the ABI exports and every module export the runtime must keep resolvable.
if(TARGET ntw2_runtime)
  set(_runtime_exports ntw2_start ntw2_stop ntw2_state
      nfr_initialize nfr_stop nfr_manager_hook nfr_assign_hook nfr_state
      nqc_initialize nqc_stop nqc_query_hook nqc_gather_hook nqc_unit_hook nqc_state
      npr_initialize npr_stop npr_scheduler_hook npr_prepass npr_end npr_solve npr_state npr_storage_bytes)
  ntw2_export_names(_helper_exports ${NTW2_EXPORTS_DISPATCH} ${NTW2_EXPORTS_BALLISTICS_HELPERS}
                    ${NTW2_EXPORTS_COLLISION} ${NTW2_EXPORTS_RENDER_BATCH})
  list(APPEND _runtime_exports ${_helper_exports})
  set(_cmd ntw2_pe_audit "$<TARGET_FILE:ntw2_runtime>")
  foreach(_e IN LISTS _runtime_exports)
    list(APPEND _cmd --export ${_e})
  endforeach()
  add_test(NAME ntw2_runtime_exports COMMAND ${_cmd})
  set_tests_properties(ntw2_runtime_exports PROPERTIES LABELS "audit;native" TIMEOUT 60)
  ntw2_note_registered(ntw2_runtime_exports)
endif()

# ---------------------------------------------------------------------------------------------------------------------
# Self-contained native tests (no image, no capture)
# ---------------------------------------------------------------------------------------------------------------------
ntw2_harness(native_worker_dispatch_smoke STD 20 FP none
  SOURCES native_worker_dispatch_smoke.cpp INCLUDES "${NTW2_SRC}/worker")
add_dependencies(native_worker_dispatch_smoke ntw2_payload_worker_dispatch)
add_test(NAME ntw2_worker_dispatch_smoke
  COMMAND native_worker_dispatch_smoke "$<TARGET_FILE:ntw2_payload_worker_dispatch>")
set_tests_properties(ntw2_worker_dispatch_smoke PROPERTIES LABELS "native" TIMEOUT 600)
ntw2_note_registered(ntw2_worker_dispatch_smoke)

ntw2_harness(native_render_batch_smoke STD 20 FP none SOURCES native_render_batch_smoke.cpp)
add_dependencies(native_render_batch_smoke ntw2_payload_render_batch)
add_test(NAME ntw2_render_batch_smoke
  COMMAND native_render_batch_smoke "$<TARGET_FILE:ntw2_payload_render_batch>")
set_tests_properties(ntw2_render_batch_smoke PROPERTIES LABELS "native" TIMEOUT 600)
ntw2_note_registered(ntw2_render_batch_smoke)

# ---------------------------------------------------------------------------------------------------------------------
# Ballistics (capture-backed kits; no image)
# ---------------------------------------------------------------------------------------------------------------------
ntw2_harness(native_ballistics_smoke STD 20 FP precise
  SOURCES native_ballistics_smoke.cpp INCLUDES "${NTW2_SRC}/ballistics" "${NTW2_SRC}/worker")
add_dependencies(native_ballistics_smoke ntw2_payload_ballistics_helpers)
ntw2_asset(_testkit native-ballistics-testkit.bin)
ntw2_asset(_corpus native-ballistics-live-28252.corpus.bin)
if(_testkit)
  set(_args "$<TARGET_FILE:ntw2_payload_ballistics_helpers>" "${_testkit}")
  if(_corpus)
    list(APPEND _args "${_corpus}")
  endif()
  add_test(NAME ntw2_ballistics_smoke COMMAND native_ballistics_smoke ${_args})
  set_tests_properties(ntw2_ballistics_smoke PROPERTIES LABELS "native;assets" TIMEOUT 1200)
  ntw2_note_registered(ntw2_ballistics_smoke)
else()
  ntw2_note_skipped(ntw2_ballistics_smoke "missing native-ballistics-testkit.bin in NTW2_TEST_ASSETS")
endif()

ntw2_harness(native_ballistics_collision_harness STD 20 FP precise
  SOURCES native_ballistics_collision_harness.cpp OBJECTS ntw2_ballistics_collision INCLUDES "${NTW2_SRC}/worker")
add_dependencies(native_ballistics_collision_harness ntw2_payload_worker_dispatch)
ntw2_asset(_ckit native-ballistics-collision-kit.bin)
ntw2_asset(_wkit native-ballistics-collision-worker-kit.bin)
if(_ckit AND _wkit)
  add_test(NAME ntw2_ballistics_collision
    COMMAND native_ballistics_collision_harness "${_ckit}" "${_wkit}" "$<TARGET_FILE:ntw2_payload_worker_dispatch>" 600)
  set_tests_properties(ntw2_ballistics_collision PROPERTIES LABELS "native;assets" TIMEOUT 1800)
  ntw2_note_registered(ntw2_ballistics_collision)
else()
  ntw2_note_skipped(ntw2_ballistics_collision "missing collision kit / worker kit in NTW2_TEST_ASSETS")
endif()

# ---------------------------------------------------------------------------------------------------------------------
# Image oracles: the ORIGINAL machine code of NTW2_TEST_IMAGE vs the port, inside the test process
# ---------------------------------------------------------------------------------------------------------------------
ntw2_harness(native_ballistics_query_cache_harness STD 20 FP strict
  SOURCES native_ballistics_query_cache_harness.cpp
  INCLUDES "${NTW2_SRC}/ballistics" "${NTW2_SRC}/worker" LIBS bcrypt)
add_dependencies(native_ballistics_query_cache_harness ntw2_module_query_cache ntw2_payload_worker_dispatch)

ntw2_harness(native_formation_slot_harness STD 17 FP strict
  SOURCES native_formation_slot_harness.cpp OBJECTS ntw2_formation_slot LIBS bcrypt)
ntw2_harness(native_formation_layout_oracle STD 20 FP strict
  SOURCES native_formation_layout_oracle.cpp OBJECTS ntw2_formation_layout LIBS bcrypt)
ntw2_harness(native_formation_batch_harness STD 20 FP strict
  SOURCES native_formation_batch_harness.cpp
  OBJECTS ntw2_formation_batch ntw2_formation_layout ntw2_formation_slot ntw2_worker_dispatch LIBS bcrypt)
ntw2_harness(native_formation_runtime_smoke STD 20 FP strict
  SOURCES native_formation_batch_harness.cpp DEFINES NFR_RUNTIME_SMOKE
  OBJECTS ntw2_formation_batch ntw2_formation_layout ntw2_formation_slot ntw2_worker_dispatch
  INCLUDES "${NTW2_SRC}/formation" LIBS bcrypt)
add_dependencies(native_formation_runtime_smoke ntw2_module_formation_runtime)
ntw2_harness(native_path_workspace_oracle STD 17 FP strict
  SOURCES native_path_workspace_oracle.cpp OBJECTS ntw2_path LIBS bcrypt)
ntw2_harness(native_path_runtime_oracle STD 20 FP strict
  SOURCES native_path_runtime_oracle.cpp
  OBJECTS ntw2_path_runtime ntw2_path ntw2_worker_dispatch
  INCLUDES "${NTW2_SRC}/path" "${NTW2_SRC}/worker" LIBS bcrypt)
ntw2_harness(native_animation_oracle_smoke STD 20 FP precise
  SOURCES native_animation_oracle_smoke.cpp OBJECTS ntw2_animation_pose)
ntw2_harness(native_animation_render_batch_oracle STD 20 FP precise
  SOURCES native_animation_render_batch_oracle.cpp
  OBJECTS ntw2_animation_pose ntw2_animation_render_batch ntw2_worker_dispatch)
ntw2_harness(native_ballistics_runtime_integration STD 20 FP strict
  SOURCES native_ballistics_runtime_integration.cpp "${NTW2_SRC}/ntw2_clones.cpp"
  OBJECTS ntw2_ballistics_query_cache ntw2_ballistics_collision ntw2_worker_dispatch ntw2_ballistics_helpers
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/ballistics" "${NTW2_SRC}/worker" LIBS bcrypt)
ntw2_harness(native_walk_memo_oracle STD 20 FP strict
  SOURCES native_walk_memo_oracle.cpp "${NTW2_SRC}/ntw2_clones.cpp" "${NTW2_SRC}/ntw2_walk_memo.cpp"
  INCLUDES "${NTW2_SRC}" "${CMAKE_SOURCE_DIR}/include" LIBS bcrypt)
ntw2_harness(native_collision_solver_oracle STD 20 FP strict
  SOURCES native_collision_solver_oracle.cpp "${NTW2_SRC}/collision/native_collision_solver.cpp"
          "${NTW2_SRC}/collision/native_contact.cpp"
  OBJECTS ntw2_worker_dispatch
  INCLUDES "${NTW2_SRC}/collision" "${NTW2_SRC}/worker" LIBS bcrypt)
ntw2_harness(native_contact_oracle STD 20 FP strict
  SOURCES native_contact_oracle.cpp "${NTW2_SRC}/collision/native_contact.cpp"
  INCLUDES "${NTW2_SRC}/collision" LIBS bcrypt)
ntw2_harness(native_brain2_oracle STD 20 FP strict
  SOURCES native_brain2_oracle.cpp "${NTW2_SRC}/brain2/native_brain2.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/brain2/native_node.cpp" "${NTW2_SRC}/brain2/native_node_projection.cpp" "${NTW2_SRC}/brain2/native_fire.cpp"
          "${NTW2_SRC}/brain2/native_finalizer.cpp"
          "${NTW2_SRC}/brain2/native_move_node.cpp"
          "${NTW2_SRC}/brain2/native_idle_node.cpp" "${NTW2_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" LIBS bcrypt)
ntw2_harness(native_brain_workers_oracle STD 20 FP strict
  SOURCES native_brain_workers_oracle.cpp "${NTW2_SRC}/brain2/native_brain_workers.cpp"
          "${NTW2_SRC}/brain2/native_brain2.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/brain2/native_node.cpp" "${NTW2_SRC}/brain2/native_node_projection.cpp" "${NTW2_SRC}/brain2/native_fire.cpp"
          "${NTW2_SRC}/brain2/native_finalizer.cpp"
          "${NTW2_SRC}/brain2/native_move_node.cpp"
          "${NTW2_SRC}/brain2/native_idle_node.cpp" "${NTW2_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" DEFINES NTW2_BRAIN_WORKERS_ORACLE LIBS bcrypt)
# Per-unit brain Stage A: synthetic soldiers/units (no image); links ntw2_brain2::RunWorklist for the observer seam.
ntw2_harness(native_unit_brain_oracle STD 20 FP strict
  SOURCES native_unit_brain_oracle.cpp "${NTW2_SRC}/brain2/native_unit_brain.cpp"
          "${NTW2_SRC}/brain2/native_brain2.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/brain2/native_node.cpp" "${NTW2_SRC}/brain2/native_node_projection.cpp" "${NTW2_SRC}/brain2/native_fire.cpp"
          "${NTW2_SRC}/brain2/native_finalizer.cpp"
          "${NTW2_SRC}/brain2/native_move_node.cpp"
          "${NTW2_SRC}/brain2/native_idle_node.cpp" "${NTW2_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" LIBS bcrypt)
add_test(NAME ntw2_unit_brain_oracle COMMAND native_unit_brain_oracle)
set_tests_properties(ntw2_unit_brain_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 120)
ntw2_note_registered(ntw2_unit_brain_oracle)
# Army per-unit update Stage A: synthetic units/containers (no image); classifier, probe reader and module gates.
ntw2_harness(native_army_unit_oracle STD 20 FP strict
  SOURCES native_army_unit_oracle.cpp "${NTW2_SRC}/army/native_army_unit.cpp"
  INCLUDES "${NTW2_SRC}" "${CMAKE_SOURCE_DIR}/include")
add_test(NAME ntw2_army_unit_oracle COMMAND native_army_unit_oracle)
set_tests_properties(ntw2_army_unit_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 120)
ntw2_note_registered(ntw2_army_unit_oracle)
ntw2_harness(native_node_oracle STD 20 FP strict
  SOURCES native_node_oracle.cpp "${NTW2_SRC}/brain2/native_node.cpp" "${NTW2_SRC}/brain2/native_node_projection.cpp"
          "${NTW2_SRC}/brain2/native_brain2.cpp" "${NTW2_SRC}/brain2/native_fire.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/brain2/native_finalizer.cpp"
          "${NTW2_SRC}/brain2/native_move_node.cpp"
          "${NTW2_SRC}/brain2/native_idle_node.cpp" "${NTW2_SRC}/brain2/native_action_node.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" LIBS bcrypt)
ntw2_harness(native_move_node_oracle STD 20 FP strict
  SOURCES native_move_node_oracle.cpp "${NTW2_SRC}/brain2/native_move_node.cpp"
          "${NTW2_SRC}/brain2/native_idle_node.cpp" "${NTW2_SRC}/brain2/native_action_node.cpp"
          "${NTW2_SRC}/brain2/native_node.cpp" "${NTW2_SRC}/brain2/native_node_projection.cpp"
          "${NTW2_SRC}/brain2/native_brain2.cpp" "${NTW2_SRC}/brain2/native_fire.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/brain2/native_finalizer.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" LIBS bcrypt)
ntw2_harness(native_fire_oracle STD 20 FP strict
  SOURCES native_fire_oracle.cpp "${NTW2_SRC}/brain2/native_fire.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/brain2" LIBS bcrypt)
ntw2_harness(native_loco_oracle STD 20 FP strict
  SOURCES native_loco_oracle.cpp "${NTW2_SRC}/loco/native_loco.cpp" "${NTW2_SRC}/ntw2_clones.cpp"
          "${NTW2_SRC}/loco/native_sweep.cpp" "${NTW2_SRC}/loco/native_resolve.cpp" "${NTW2_SRC}/loco/native_env.cpp"
          "${NTW2_SRC}/collision/native_collision_solver.cpp" "${NTW2_SRC}/collision/native_contact.cpp"
  INCLUDES "${NTW2_SRC}" "${NTW2_SRC}/loco" DEFINES NTW2_LOCO_ORACLE=1 LIBS bcrypt)
ntw2_harness(native_sweep_oracle STD 20 FP strict
  SOURCES native_sweep_oracle.cpp "${NTW2_SRC}/loco/native_sweep.cpp"
  INCLUDES "${NTW2_SRC}/loco")
ntw2_harness(native_resolve_oracle STD 20 FP strict
  SOURCES native_resolve_oracle.cpp "${NTW2_SRC}/loco/native_resolve.cpp" "${NTW2_SRC}/loco/native_sweep.cpp"
  INCLUDES "${NTW2_SRC}/loco" LIBS bcrypt)
ntw2_harness(native_env_oracle STD 20 FP strict
  SOURCES native_env_oracle.cpp "${NTW2_SRC}/loco/native_env.cpp" "${NTW2_SRC}/loco/native_sweep.cpp"
  INCLUDES "${NTW2_SRC}/loco" LIBS bcrypt)
add_test(NAME ntw2_sweep_oracle COMMAND native_sweep_oracle)
set_tests_properties(ntw2_sweep_oracle PROPERTIES LABELS "synthetic;shadow" TIMEOUT 60)
ntw2_note_registered(ntw2_sweep_oracle)
if(TARGET ntw2_runtime)
  ntw2_harness(native_runtime_lifecycle STD 20 FP strict SOURCES native_runtime_lifecycle.cpp
    INCLUDES "${CMAKE_SOURCE_DIR}/include")
  add_dependencies(native_runtime_lifecycle ntw2_runtime)
endif()

if(NTW2_HAVE_IMAGE)
  ntw2_asset(_table native-formation-angle-table-28252.bin)
  ntw2_asset(_clones native-ballistics-query-clones.bin)
  ntw2_asset(_live native-formation-layout-live-replay.bin)
  ntw2_asset(_fixture native-formation-fixture-28252.bin)

  if(_clones AND _wkit)
    add_test(NAME ntw2_ballistics_query_cache
      COMMAND native_ballistics_query_cache_harness --image "${NTW2_IMAGE_ARG}"
              --cache-dll "$<TARGET_FILE:ntw2_module_query_cache>" --clones "${_clones}" --worker-kit "${_wkit}"
              --pool-dll "$<TARGET_FILE:ntw2_payload_worker_dispatch>"
              --worlds 240 --seed 6392 --workers 3 --wrapper 1 --strict-wrapper 0)
    set_tests_properties(ntw2_ballistics_query_cache PROPERTIES LABELS "image;assets" TIMEOUT 3600)
    ntw2_note_registered(ntw2_ballistics_query_cache)
  else()
    ntw2_note_skipped(ntw2_ballistics_query_cache "missing query clones / collision worker kit")
  endif()

  if(_table)
    set(_slot_args --image "${NTW2_IMAGE_ARG}" --table "${_table}" --cases 2000 --seed 1)
    if(_fixture)
      list(APPEND _slot_args --fixture "${_fixture}")
    endif()
    add_test(NAME ntw2_formation_slot COMMAND native_formation_slot_harness ${_slot_args})
    add_test(NAME ntw2_formation_batch
      COMMAND native_formation_batch_harness --image "${NTW2_IMAGE_ARG}" --table "${_table}"
              --cases 400 --seed 20261013 --workers 0)
    add_test(NAME ntw2_formation_runtime
      COMMAND native_formation_runtime_smoke --image "${NTW2_IMAGE_ARG}" --table "${_table}"
              --runtime-dll "$<TARGET_FILE:ntw2_module_formation_runtime>" --cases 400 --seed 20261013 --workers 0)
    set_tests_properties(ntw2_formation_slot ntw2_formation_batch ntw2_formation_runtime
                         PROPERTIES LABELS "image;assets" TIMEOUT 3600)
    ntw2_note_registered(ntw2_formation_slot)
    ntw2_note_registered(ntw2_formation_batch)
    ntw2_note_registered(ntw2_formation_runtime)
  else()
    ntw2_note_skipped(ntw2_formation_slot "missing native-formation-angle-table-28252.bin")
    ntw2_note_skipped(ntw2_formation_batch "missing native-formation-angle-table-28252.bin")
    ntw2_note_skipped(ntw2_formation_runtime "missing native-formation-angle-table-28252.bin")
  endif()

  set(_layout_args "${NTW2_IMAGE_ARG}" cases=300 seed=20240601)
  if(_live)
    list(APPEND _layout_args "live=${_live}")
  endif()
  add_test(NAME ntw2_formation_layout COMMAND native_formation_layout_oracle ${_layout_args})
  add_test(NAME ntw2_path_workspace COMMAND native_path_workspace_oracle "${NTW2_IMAGE_ARG}" cases=40 seed=20261013)
  add_test(NAME ntw2_path_runtime COMMAND native_path_runtime_oracle "${NTW2_IMAGE_ARG}" cases=16 seed=20261013)
  add_test(NAME ntw2_animation_pose COMMAND native_animation_oracle_smoke "${NTW2_IMAGE_ARG}")
  add_test(NAME ntw2_animation_render_batch COMMAND native_animation_render_batch_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_formation_layout ntw2_path_workspace ntw2_path_runtime
                       ntw2_animation_pose ntw2_animation_render_batch
                       PROPERTIES LABELS "image" TIMEOUT 3600)
  ntw2_note_registered(ntw2_formation_layout)
  ntw2_note_registered(ntw2_path_workspace)
  ntw2_note_registered(ntw2_path_runtime)
  ntw2_note_registered(ntw2_animation_pose)
  ntw2_note_registered(ntw2_animation_render_batch)
  add_test(NAME ntw2_ballistics_runtime_integration
    COMMAND native_ballistics_runtime_integration "${NTW2_IMAGE_ARG}" worlds=64 workers=3 seed=6392)
  set_tests_properties(ntw2_ballistics_runtime_integration PROPERTIES LABELS "image" TIMEOUT 1800)
  ntw2_note_registered(ntw2_ballistics_runtime_integration)
  add_test(NAME ntw2_walk_memo COMMAND native_walk_memo_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_walk_memo PROPERTIES LABELS "image" TIMEOUT 120)
  ntw2_note_registered(ntw2_walk_memo)
  add_test(NAME ntw2_collision_solver COMMAND native_collision_solver_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_collision_solver PROPERTIES LABELS "image" TIMEOUT 300)
  add_test(NAME ntw2_contact_oracle COMMAND native_contact_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_contact_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_contact_oracle)
  add_test(NAME ntw2_brain2_oracle COMMAND native_brain2_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_brain2_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  ntw2_note_registered(ntw2_brain2_oracle)
  add_test(NAME ntw2_brain_workers_oracle COMMAND native_brain_workers_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_brain_workers_oracle PROPERTIES LABELS "image" TIMEOUT 600)
  ntw2_note_registered(ntw2_brain_workers_oracle)
  add_test(NAME ntw2_node_oracle COMMAND native_node_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_node_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_node_oracle)
  add_test(NAME ntw2_move_node_oracle COMMAND native_move_node_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_move_node_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_move_node_oracle)
  add_test(NAME ntw2_fire_oracle COMMAND native_fire_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_fire_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_fire_oracle)
  add_test(NAME ntw2_loco_oracle COMMAND native_loco_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_loco_oracle PROPERTIES LABELS "image" TIMEOUT 300)
  ntw2_note_registered(ntw2_loco_oracle)
  add_test(NAME ntw2_resolve_oracle COMMAND native_resolve_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_resolve_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_resolve_oracle)
  add_test(NAME ntw2_env_oracle COMMAND native_env_oracle "${NTW2_IMAGE_ARG}")
  set_tests_properties(ntw2_env_oracle PROPERTIES LABELS "image;shadow" TIMEOUT 300)
  ntw2_note_registered(ntw2_env_oracle)
  ntw2_note_registered(ntw2_collision_solver)
  if(TARGET native_runtime_lifecycle)
    add_test(NAME ntw2_runtime_lifecycle
      COMMAND native_runtime_lifecycle "${NTW2_IMAGE_ARG}" "$<TARGET_FILE:ntw2_runtime>")
    set_tests_properties(ntw2_runtime_lifecycle PROPERTIES LABELS "image" TIMEOUT 120)
    ntw2_note_registered(ntw2_runtime_lifecycle)
  endif()
else()
  foreach(_t ballistics_query_cache ballistics_runtime_integration formation_slot formation_batch formation_runtime
             formation_layout path_workspace path_runtime animation_pose animation_render_batch walk_memo collision_solver contact_oracle brain2_oracle brain_workers_oracle node_oracle fire_oracle loco_oracle resolve_oracle)
    ntw2_note_skipped(ntw2_${_t} "NTW2_TEST_IMAGE not set to an existing Napoleon.exe")
  endforeach()
  if(TARGET native_runtime_lifecycle)
    ntw2_note_skipped(ntw2_runtime_lifecycle "NTW2_TEST_IMAGE not set to an existing Napoleon.exe")
  endif()
endif()

get_property(_reg GLOBAL PROPERTY NTW2_TESTS_REGISTERED)
get_property(_skip GLOBAL PROPERTY NTW2_TESTS_SKIPPED)
list(JOIN _reg ", " _reg_text)
message(STATUS "ntw2 tests registered: ${_reg_text}")
if(_skip)
  list(JOIN _skip "; " _skip_text)
  message(STATUS "ntw2 tests NOT registered (missing input): ${_skip_text}")
endif()
