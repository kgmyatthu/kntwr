# Prefix-stage helpers (import-free, PIC)
add_library(ntw2_ballistics_helpers OBJECT native_ballistics_helpers.c)
target_include_directories(ntw2_ballistics_helpers PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
ntw2_pic_flags(ntw2_ballistics_helpers)

# Direct leaf collision core (import-free, PIC; the sole definition of _fltused in any link that uses it)
add_library(ntw2_ballistics_collision OBJECT native_ballistics_collision.cpp)
target_include_directories(ntw2_ballistics_collision PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
ntw2_pic_cxx_flags(ntw2_ballistics_collision)

# Query cache hooks (host DLL code).  Receives the address of the existing persistent dispatcher at init, so the
# dispatcher object is NOT linked into this object library.  Source pins live next to the source (generated once at
# development time from the pinned image and committed; no runtime or build-time Python).
add_library(ntw2_ballistics_query_cache OBJECT native_ballistics_query_cache.cpp)
target_include_directories(ntw2_ballistics_query_cache PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" PRIVATE "${NTW2_SRC}/worker")
ntw2_host_flags(ntw2_ballistics_query_cache 20 strict)
