# Private path-search workspace and the in-process scheduler owner.
add_library(ntw2_path OBJECT native_path_workspace.cpp)
target_include_directories(ntw2_path PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
ntw2_host_flags(ntw2_path 17 strict)
add_library(ntw2_path_runtime OBJECT native_path_runtime.cpp)
target_include_directories(ntw2_path_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${NTW2_SRC}/worker")
ntw2_host_flags(ntw2_path_runtime 20 strict)
