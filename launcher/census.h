/* Launcher-side formation census: the same CSV schema as the in-process --formation-census (src/formation/ntw2_formation_census.h), gathered from OUTSIDE
 * the game with ReadProcessMemory only.  No injection, no hook, no engine call: it works on a vanilla, an in-memory-patched or an on-disk-patched game with or
 * without the runtime (--no-activate).  Engine reads are not synchronised with the simulation tick, so a sample may mix two adjacent ticks; the statistics do
 * not care (each man moves well under a metre per tick).  Slot generation is an engine call and is therefore NOT available here: nslots is 0, the slot_* /
 * ratio / err_* columns carry 0 / -1, and `moving` is derived from the men centroid speed (> 0.5 m/s since this unit's previous sample).
 */
#ifndef NTW2_LAUNCHER_CENSUS_H
#define NTW2_LAUNCHER_CENSUS_H

#include <stdint.h>
#include <windows.h>

/* 0 on success.  every_ticks 1..10000 (0 selects 30); the summary goes to <csv>.summary.txt. */
int ext_census_open(const wchar_t *csv_path, uint32_t every_ticks);
/* One poll (cheap when no new sample is due).  image_base = the game's actual main image base.  Returns 1 when a sample pass ran. */
int ext_census_poll(HANDLE proc, uint32_t image_base);
/* Flushes, writes the summary and closes the CSV. */
void ext_census_close(void);
uint32_t ext_census_rows(void);

#endif
