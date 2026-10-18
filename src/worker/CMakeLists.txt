# Persistent worker dispatcher (import-free, PIC)
add_library(ntw2_worker_dispatch OBJECT native_worker_dispatch.c)
target_include_directories(ntw2_worker_dispatch PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
ntw2_pic_flags(ntw2_worker_dispatch)
