# Persistent worker dispatcher (import-free, PIC)
add_library(kntwr_worker_dispatch OBJECT native_worker_dispatch.c)
target_include_directories(kntwr_worker_dispatch PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
kntwr_pic_flags(kntwr_worker_dispatch)
