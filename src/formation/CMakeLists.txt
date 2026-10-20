# Slot assignment, slot generator, batch adapter, runtime hooks
add_library(ntw2_formation_slot OBJECT native_formation_slot.cpp)
add_library(ntw2_formation_layout OBJECT native_formation_layout.cpp)
add_library(ntw2_formation_batch OBJECT native_formation_batch.cpp)
add_library(ntw2_formation_runtime OBJECT native_formation_runtime.cpp)
foreach(_t ntw2_formation_slot ntw2_formation_layout ntw2_formation_batch ntw2_formation_runtime)
  target_include_directories(${_t} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${NTW2_SRC}/worker")
  ntw2_host_flags(${_t} 20 strict)
endforeach()

# Compiled straight into ntw2_runtime.
ntw2_runtime_sources(native_formation_solver.cpp)
ntw2_runtime_sources(ntw2_formation_census.cpp)
