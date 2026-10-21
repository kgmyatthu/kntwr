# Private path-search workspace and the in-process scheduler owner.
add_library(kntwr_path OBJECT native_path_workspace.cpp)
target_include_directories(kntwr_path PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
kntwr_host_flags(kntwr_path 17 strict)
add_library(kntwr_path_runtime OBJECT native_path_runtime.cpp)
target_include_directories(kntwr_path_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${KNTWR_SRC}/worker")
kntwr_host_flags(kntwr_path_runtime 20 strict)
