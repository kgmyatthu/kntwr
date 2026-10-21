# Build/test-time tools.  Never part of the product; built only with KNTWR_BUILD_TESTS.
add_executable(kntwr_pe_audit kntwr_pe_audit.c)
target_compile_options(kntwr_pe_audit PRIVATE /O2 /W4)
set_target_properties(kntwr_pe_audit PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests")

add_executable(kntwr_run_limited kntwr_run_limited.c)
target_compile_options(kntwr_run_limited PRIVATE /O2 /W4)
set_target_properties(kntwr_run_limited PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests")
add_test(NAME analysis_memory_denial COMMAND kntwr_run_limited 32 4096 10 -- $<TARGET_FILE:kntwr_run_limited> --budget-probe deny)
add_test(NAME analysis_memory_success COMMAND kntwr_run_limited 32 4096 10 -- $<TARGET_FILE:kntwr_run_limited> --budget-probe allow)
