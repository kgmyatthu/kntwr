# Slot assignment, slot generator, batch adapter, runtime hooks
add_library(kntwr_formation_slot OBJECT native_formation_slot.cpp)
add_library(kntwr_formation_layout OBJECT native_formation_layout.cpp)
add_library(kntwr_formation_batch OBJECT native_formation_batch.cpp)
add_library(kntwr_formation_runtime OBJECT native_formation_runtime.cpp)
foreach(_t kntwr_formation_slot kntwr_formation_layout kntwr_formation_batch kntwr_formation_runtime)
  target_include_directories(${_t} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${KNTWR_SRC}/worker")
  kntwr_host_flags(${_t} 20 strict)
endforeach()

# Compiled straight into kntwr_runtime.
kntwr_runtime_sources(native_formation_solver.cpp)
kntwr_runtime_sources(kntwr_formation_census.cpp)
