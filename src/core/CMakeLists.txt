# Runtime host: DLL entry, tick gates, config, shared guard/workload headers.
ntw2_runtime_sources(
  ntw2_runtime.cpp
  ntw2_alloc_census.cpp
)
# In-memory gameplay patch (data/*.ntwpatch embedded by tools/apply_ntwpatch.py embed). NOT a runtime DLL source: the launcher
# (ntw2.exe) applies it to the suspended game before the first instruction runs, and the oracle links the same file.
set(NTW2_GAMEPLAY_PATCH_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/ntw2_gameplay_patch.c" PARENT_SCOPE)
