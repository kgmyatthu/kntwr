cmake_minimum_required(VERSION 3.21)

# MSVC runtime: static /MT for every target (the game process must not gain a CRT DLL dependency).  Set before project().
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

project(ntw2 VERSION 1.0 LANGUAGES C CXX ASM_MASM)

# ---------------------------------------------------------------------------------------------------------------------
# Toolchain contract.  The target game is a 32-bit MSVC image and every native module is verified against it bit for
# bit, so the only supported toolchain is MSVC targeting x86 (Win32).
#   Visual Studio generator:  cmake -S . -B build -A Win32
#   Ninja:                    run from an "x86 Native Tools" / vcvarsamd64_x86 shell, then use the `x86-ninja` preset
# ---------------------------------------------------------------------------------------------------------------------
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" OR NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
  message(FATAL_ERROR "ntw2 requires the MSVC compiler (found C=${CMAKE_C_COMPILER_ID} CXX=${CMAKE_CXX_COMPILER_ID}).")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "ntw2 must be built for x86 (Win32): the game and all native modules are 32-bit. "
                      "Use -A Win32 with a Visual Studio generator, or configure from an x86 developer shell.")
endif()

# Only the validated configuration exists: the import-free payload objects must not receive /RTC or debug CRT calls and
# the numeric modules were verified with exactly these flags.
if(CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Only Release is supported" FORCE)
else()
  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Only Release is supported" FORCE)
  endif()
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "ntw2 supports CMAKE_BUILD_TYPE=Release only (got '${CMAKE_BUILD_TYPE}').")
  endif()
endif()

# Compiler flags are explicit per target below.  Drop the generator defaults (/GR /EHsc /DWIN32 ...) so the import-free
# modules can state /EHs-c- /GR- without conflicts, and keep Release free of /DNDEBUG (the validated builds never defined it).
set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")
set(CMAKE_C_FLAGS_RELEASE "/O2 /Ob2")
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/INCREMENTAL:NO /OPT:REF")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/INCREMENTAL:NO /OPT:REF")

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

option(NTW2_BUILD_RUNTIME "Build ntw2_runtime.dll and the ntw2.exe launcher (the product)" ON)
option(NTW2_BUILD_TESTS "Build native oracles/harnesses/payload audits and register them with CTest" OFF)
set(NTW2_TEST_IMAGE "" CACHE FILEPATH
    "Supported Napoleon.exe (SHA-256 in include/ntw2_runtime.h). Image oracles are registered only when this file exists.")
get_filename_component(_ntw2_default_assets "${CMAKE_CURRENT_SOURCE_DIR}/../analysis" ABSOLUTE)
set(NTW2_TEST_ASSETS "${_ntw2_default_assets}" CACHE PATH
    "Directory holding the pinned oracle captures (*.bin kits, angle table, replay records). Tests whose capture is missing are not registered.")

set(NTW2_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")

# ---------------------------------------------------------------------------------------------------------------------
# Flag recipes.  Names mirror the validated analysis build scripts these replaced.
#   ntw2_pic_flags        import-free position-independent code: no CRT, no stack cookie, no default lib (/Zl)
#   ntw2_host_flags       CRT-linked C++ modules: /O2 /arch:SSE2 /fp:<mode> /EHsc /W4 /utf-8, /MT from the runtime property
# ---------------------------------------------------------------------------------------------------------------------
function(ntw2_pic_flags target)
  target_compile_options(${target} PRIVATE /O2 /GS- /Gy /Zl /W4)
endfunction()

function(ntw2_pic_cxx_flags target)
  target_compile_options(${target} PRIVATE /O2 /GS- /Gy /Zl /EHs-c- /GR- /arch:SSE2 /fp:precise /W4)
endfunction()

# ntw2_host_flags(<target> <cxx-standard> <strict|precise|none>)
function(ntw2_host_flags target std fp)
  set_target_properties(${target} PROPERTIES CXX_STANDARD ${std} CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
  target_compile_options(${target} PRIVATE /O2 /arch:SSE2 /EHsc /W4 /utf-8)
  if(NOT fp STREQUAL "none")
    target_compile_options(${target} PRIVATE /fp:${fp})
  endif()
endfunction()

# Linker recipe of the import-free payload DLLs (code section is copied verbatim into an owned allocation).
function(ntw2_payload_link target)
  target_link_options(${target} PRIVATE /NOENTRY /NODEFAULTLIB /MACHINE:X86 /OPT:REF /INCREMENTAL:NO)
endfunction()

# ---------------------------------------------------------------------------------------------------------------------
# Native module object libraries.  Each module is compiled once; the product DLL and every standalone payload/harness
# link the same objects.  Object libraries are linked directly into final targets (never through static libraries) so
# that /EXPORT pragmas inside the objects are always honoured.
# ---------------------------------------------------------------------------------------------------------------------

# Persistent worker dispatcher (import-free, PIC)
add_library(ntw2_worker_dispatch OBJECT src/worker/native_worker_dispatch.c)
target_include_directories(ntw2_worker_dispatch PUBLIC src/worker)
ntw2_pic_flags(ntw2_worker_dispatch)

# Ballistics prefix-stage helpers (import-free, PIC)
add_library(ntw2_ballistics_helpers OBJECT src/ballistics/native_ballistics_helpers.c)
target_include_directories(ntw2_ballistics_helpers PUBLIC src/ballistics)
ntw2_pic_flags(ntw2_ballistics_helpers)

# Ballistics direct leaf collision core (import-free, PIC; the sole definition of _fltused in any link that uses it)
add_library(ntw2_ballistics_collision OBJECT src/ballistics/native_ballistics_collision.cpp)
target_include_directories(ntw2_ballistics_collision PUBLIC src/ballistics)
ntw2_pic_cxx_flags(ntw2_ballistics_collision)

# Ballistics query cache hooks (host DLL code).  Receives the address of the existing persistent dispatcher at init, so the
# dispatcher object is NOT linked into this object library.  Source pins live next to the source (generated once at
# development time from the pinned image and committed; no runtime or build-time Python).
add_library(ntw2_ballistics_query_cache OBJECT src/ballistics/native_ballistics_query_cache.cpp)
target_include_directories(ntw2_ballistics_query_cache PUBLIC src/ballistics PRIVATE src/worker)
ntw2_host_flags(ntw2_ballistics_query_cache 20 strict)

# Formation: slot assignment, slot generator, batch adapter, runtime hooks
add_library(ntw2_formation_slot OBJECT src/formation/native_formation_slot.cpp)
add_library(ntw2_formation_layout OBJECT src/formation/native_formation_layout.cpp)
add_library(ntw2_formation_batch OBJECT src/formation/native_formation_batch.cpp)
add_library(ntw2_formation_runtime OBJECT src/formation/native_formation_runtime.cpp)
foreach(_t ntw2_formation_slot ntw2_formation_layout ntw2_formation_batch ntw2_formation_runtime)
  target_include_directories(${_t} PUBLIC src/formation PRIVATE src/worker)
  ntw2_host_flags(${_t} 20 strict)
endforeach()

# Private path-search workspace and the in-process scheduler owner.
add_library(ntw2_path OBJECT src/path/native_path_workspace.cpp)
target_include_directories(ntw2_path PUBLIC src/path)
ntw2_host_flags(ntw2_path 17 strict)
add_library(ntw2_path_runtime OBJECT src/path/native_path_runtime.cpp)
target_include_directories(ntw2_path_runtime PUBLIC src/path PRIVATE src/worker)
ntw2_host_flags(ntw2_path_runtime 20 strict)

# Animation: pose kernel + render batch adapter (the persistent dispatcher is linked by the final target)
add_library(ntw2_animation_pose OBJECT src/animation/native_animation_pose_kernel.cpp)
add_library(ntw2_animation_render_batch OBJECT src/animation/native_animation_render_batch.cpp)
foreach(_t ntw2_animation_pose ntw2_animation_render_batch)
  target_include_directories(${_t} PUBLIC src/animation PRIVATE src/worker)
  ntw2_host_flags(${_t} 20 precise)
endforeach()

# Render-batch helpers (MASM, position independent: ECX/ESP-relative only)
add_library(ntw2_render_batch OBJECT src/render/native_render_batch.asm)
# /Cp: ml.exe upper-cases identifiers by default; the exported names (append_vec3, flush_vec3, batch_contract) are lower case.
target_compile_options(ntw2_render_batch PRIVATE /Cp)

# ---------------------------------------------------------------------------------------------------------------------
# Linker export sets.  Undecorated public names for the decorated MSVC x86 symbols (the same maps the analysis scripts
# passed to link.exe).  nfr_* and nqc_* are exported by /EXPORT pragmas inside their sources.
# ---------------------------------------------------------------------------------------------------------------------
set(NTW2_EXPORTS_DISPATCH
  /EXPORT:ntw_pool_dispatch=_ntw_pool_dispatch@16
  /EXPORT:ntw_pool_init=_ntw_pool_init@8
  /EXPORT:ntw_pool_shutdown=_ntw_pool_shutdown@4
  /EXPORT:ntw_pool_worker_start=_ntw_pool_worker_start@4
  /EXPORT:ntw_pool_contract,DATA)
set(NTW2_EXPORTS_BALLISTICS_HELPERS
  /EXPORT:bal_stage=@bal_stage@8
  /EXPORT:bal_worker=@bal_worker@8
  /EXPORT:bal_step=@bal_step@8
  /EXPORT:bal_tail_enter=@bal_tail_enter@8
  /EXPORT:bal_contract,DATA)
set(NTW2_EXPORTS_COLLISION
  /EXPORT:nbc_batch_init=_nbc_batch_init@32
  /EXPORT:nbc_batch_reset=_nbc_batch_reset@4
  /EXPORT:nbc_add_plane_ring_entry=_nbc_add_plane_ring_entry@16
  /EXPORT:nbc_add_wall_entry=_nbc_add_wall_entry@16
  /EXPORT:nbc_add_box_entry=_nbc_add_box_entry@16
  /EXPORT:nbc_add_unit_entry=_nbc_add_unit_entry@32
  /EXPORT:nbc_unit_flag_ok=_nbc_unit_flag_ok@8
  /EXPORT:nbc_add_plane_ring=_nbc_add_plane_ring@24
  /EXPORT:nbc_add_wall=_nbc_add_wall@28
  /EXPORT:nbc_add_box=_nbc_add_box@20
  /EXPORT:nbc_add_unit=_nbc_add_unit@36
  /EXPORT:nbc_add_owner_result=_nbc_add_owner_result@20
  /EXPORT:nbc_run=_nbc_run@4
  /EXPORT:nbc_merge=_nbc_merge@24
  /EXPORT:nbc_chunk_body=@nbc_chunk_body@8
  /EXPORT:nbc_contract,DATA)
set(NTW2_EXPORTS_RENDER_BATCH
  /EXPORT:append_vec3
  /EXPORT:flush_vec3
  /EXPORT:batch_contract,DATA)
set(NTW2_EXPORTS_RUNTIME_ABI
  /EXPORT:ntw2_start=_ntw2_start@4
  /EXPORT:ntw2_stop=_ntw2_stop@4
  /EXPORT:ntw2_site_callee=_ntw2_site_callee@4
  /EXPORT:ntw2_activation_boundary=_ntw2_activation_boundary@4
  /EXPORT:ntw2_ai_boundary=_ntw2_ai_boundary@12
  /EXPORT:ntw2_ai_async2_boundary=_ntw2_ai_async2_boundary@24
  /EXPORT:ntw2_ai_async2_private_entry=_ntw2_ai_async2_private_entry@4
  /EXPORT:ntw2_grid_probation_probe=_ntw2_grid_probation_probe@8
  /EXPORT:ntw2_state,DATA
  /EXPORT:ntw2_profile,DATA)

# ---------------------------------------------------------------------------------------------------------------------
# Product: ntw2_runtime.dll (loaded into the game by the launcher) + ntw2.exe (launcher), side by side in bin/.
#
# Generated source-pinning metadata is checked in; product builds need no Python.
# Missing required runtime sources are a configure error, never a skipped module.
# ---------------------------------------------------------------------------------------------------------------------
if(NTW2_BUILD_RUNTIME)
  set(NTW2_RUNTIME_SOURCES src/ntw2_runtime.cpp src/ntw2_clones.cpp src/ntw2_profile.cpp src/ntw2_ai_census.cpp src/ntw2_ai_async2.cpp src/ntw2_ai_deferred.cpp src/ntw2_walk_memo.cpp
                           src/collision/native_collision_solver.cpp src/collision/native_contact.cpp src/brain2/native_brain2.cpp src/loco/native_loco.cpp src/loco/native_move_delta.cpp src/loco/native_relink.cpp src/loco/native_grid_probation.cpp
                           src/brain2/native_node.cpp src/brain2/native_node_projection.cpp src/brain2/native_fire.cpp src/brain2/native_finalizer.cpp
                           src/brain2/native_move_node.cpp src/brain2/native_brain_workers.cpp src/brain2/native_unit_brain.cpp
                           src/brain2/native_idle_node.cpp src/brain2/native_action_node.cpp src/army/native_army_unit.cpp src/army/native_army_storm.cpp
                           src/army/native_army_solver.cpp src/formation/native_formation_solver.cpp
                           src/brain2/native_brain_s0.cpp src/brain2/native_brain_locality.cpp src/brain2/native_unit_posture_engage.cpp src/ntw2_ai_ctrl_batch.cpp src/ntw2_ai_ctrl_geometry.cpp src/ntw2_planner_prepass.cpp
                           src/loco/native_sweep.cpp src/loco/native_resolve.cpp src/loco/native_env.cpp
                           src/brain2/native_unit_select.cpp src/brain2/native_unit_policy.cpp src/brain2/native_unit_fatigue.cpp src/ntw2_planner_search.cpp
                           src/ntw2_spiral.cpp
                           src/ntw2_claim_chunk.cpp
                           src/ntw2_record_test.cpp)
  foreach(_s IN LISTS NTW2_RUNTIME_SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_s}")
      message(FATAL_ERROR "Runtime source ${_s} does not exist yet. Provide it, or configure with -DNTW2_BUILD_RUNTIME=OFF "
                          "to build only the module libraries and tests.")
    endif()
  endforeach()
  file(GLOB NTW2_LAUNCHER_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/launcher/*.c"
                                                       "${CMAKE_CURRENT_SOURCE_DIR}/launcher/*.h")
  if(NOT NTW2_LAUNCHER_SOURCES MATCHES "launcher/main\\.c")
    message(FATAL_ERROR "launcher/main.c does not exist yet. Provide it, or configure with -DNTW2_BUILD_RUNTIME=OFF.")
  endif()

  add_library(ntw2_runtime SHARED ${NTW2_RUNTIME_SOURCES})
  target_include_directories(ntw2_runtime PRIVATE include src)
  ntw2_host_flags(ntw2_runtime 20 strict)
  target_link_libraries(ntw2_runtime PRIVATE
    ntw2_worker_dispatch ntw2_ballistics_helpers ntw2_ballistics_collision ntw2_ballistics_query_cache
    ntw2_formation_slot ntw2_formation_layout ntw2_formation_batch ntw2_formation_runtime
    ntw2_path ntw2_path_runtime ntw2_animation_pose ntw2_animation_render_batch ntw2_render_batch)
  # Offline profiler needs private runtime functions and lines, not just exports.
  # Keep optimized Release code; retain its matching full PDB beside the DLL.
  get_target_property(_ntw2_runtime_objects ntw2_runtime LINK_LIBRARIES)
  foreach(_t ntw2_runtime ${_ntw2_runtime_objects})
    target_compile_options(${_t} PRIVATE "$<$<COMPILE_LANGUAGE:C,CXX>:/Zi>")
  endforeach()
  target_link_options(ntw2_runtime PRIVATE /DEBUG:FULL /OPT:REF /OPT:ICF)
  set_target_properties(ntw2_runtime PROPERTIES PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  target_link_options(ntw2_runtime PRIVATE
    ${NTW2_EXPORTS_RUNTIME_ABI} ${NTW2_EXPORTS_DISPATCH} ${NTW2_EXPORTS_BALLISTICS_HELPERS}
    ${NTW2_EXPORTS_COLLISION} ${NTW2_EXPORTS_RENDER_BATCH})
  set_target_properties(ntw2_runtime PROPERTIES OUTPUT_NAME ntw2_runtime)

  # Launcher: plain C, x86, static CRT.  The runtime DLL name is baked from the target so launcher and DLL cannot drift.
  add_executable(ntw2 ${NTW2_LAUNCHER_SOURCES})
  target_include_directories(ntw2 PRIVATE include launcher src) # src: C-compatible src/loco/native_loco.h word labels
  target_compile_options(ntw2 PRIVATE /O2 /W4 /utf-8)
  target_compile_definitions(ntw2 PRIVATE NTW2_RUNTIME_DLL_NAME="$<TARGET_FILE_NAME:ntw2_runtime>")
  target_link_libraries(ntw2 PRIVATE bcrypt shell32 ole32 user32 advapi32)
  add_dependencies(ntw2 ntw2_runtime)
  set_target_properties(ntw2 PROPERTIES OUTPUT_NAME ntw2)

  install(TARGETS ntw2 ntw2_runtime RUNTIME DESTINATION .)
endif()

if(NTW2_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tools)
  add_subdirectory(tests)
endif()
