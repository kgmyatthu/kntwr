# Build/test-time tools.  Never part of the product; built only with NTW2_BUILD_TESTS.
add_executable(ntw2_pe_audit ntw2_pe_audit.c)
target_compile_options(ntw2_pe_audit PRIVATE /O2 /W4)
set_target_properties(ntw2_pe_audit PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests")

add_executable(ntw2_run_limited ntw2_run_limited.c)
target_compile_options(ntw2_run_limited PRIVATE /O2 /W4)
set_target_properties(ntw2_run_limited PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests")
add_test(NAME analysis_memory_denial COMMAND ntw2_run_limited 32 4096 10 -- $<TARGET_FILE:ntw2_run_limited> --budget-probe deny)
add_test(NAME analysis_memory_success COMMAND ntw2_run_limited 32 4096 10 -- $<TARGET_FILE:ntw2_run_limited> --budget-probe allow)
