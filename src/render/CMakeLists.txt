# Render-batch helpers (MASM, position independent: ECX/ESP-relative only)
add_library(ntw2_render_batch OBJECT native_render_batch.asm)
# /Cp: ml.exe upper-cases identifiers by default; the exported names (append_vec3, flush_vec3, batch_contract) are lower case.
target_compile_options(ntw2_render_batch PRIVATE /Cp)
ntw2_runtime_sources(
  ntw2_arena_release.cpp
)
