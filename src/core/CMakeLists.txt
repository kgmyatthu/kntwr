# Runtime host: DLL entry, tick gates, config, shared guard/workload headers.
kntwr_runtime_sources(
  kntwr_runtime.cpp
  kntwr_alloc_census.cpp
)
# In-memory gameplay patch (data/*.ntwpatch embedded by tools/apply_ntwpatch.py embed). NOT a runtime DLL source: the launcher
# (kntwr.exe) applies it to the suspended game before the first instruction runs, and the oracle links the same file.
set(KNTWR_GAMEPLAY_PATCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/kntwr_gameplay_patch.c" PARENT_SCOPE)
