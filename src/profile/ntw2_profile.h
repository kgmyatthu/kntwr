#ifndef NTW2_PROFILE_H
#define NTW2_PROFILE_H
#include <stdint.h>
#include <stddef.h>

/* ABI 8 keeps the ABI-7 status header, seven image histograms and 4612-byte
   tick-chain trailer unchanged. Then comes this tagged section, entirely LE
   uint32_t words (no pointers/padding): 96-byte header, histogram_count dense
   arrays of bucket_count words, pair_capacity triples, wait_capacity triples.
   bytes includes this header. Empty sparse slots have count=0; *_count is the
   number of occupied slots; *_overflow counts observations lost to a full table.
   The identical section lives immediately after the seven in-process histograms.
   Histogram order: all observed threads, actual tick owner, worker heuristic,
   selected-gate tick owner. All/worker sampling covers actual ticks (main thread
   is also observed outside ticks). Worker means runtime EIP during an actual
   tick, excluding its owner and the published AI worker id; it is NOT pool ID
   membership and may include other runtime threads. The sampler excludes itself.
   Pairs join an actual-tick runtime bucket RVA with each distinct main-image
   stack bucket RVA in that sample. These are call-validated stack scans, not
   unwinds or proof of an active site; different frame gates must not be summed.
   Wait rows retain exact return RVAs, keyed by wait-stub kind. Prefer [ESP];
   otherwise retain the first call-validated runtime address in the first 1 KiB
   of stack, which can be stale. These are occupancy/caller hints, not wait times.
   selected_site is 0 for whole tick, otherwise CLI site index + 1; launcher
   fills it from the observation config. Flags bit 0 = worker heuristic,
   bit 1 = frame scan attribution, bit 2 = bounded wait-stack scan,
   bit 3 = histogram bucket_count ends at the highest executable section RVA;
   runtime_size remains the complete module image extent. */
#define NTW2_PROFILE_RUNTIME_MAGIC 0x3852544eu /* "NTR8" */
#define NTW2_PROFILE_RUNTIME_VERSION 1u
#define NTW2_PROFILE_RUNTIME_HISTOGRAMS 4u
#define NTW2_PROFILE_RUNTIME_PAIRS 8192u
#define NTW2_PROFILE_RUNTIME_WAITS 1024u
typedef struct ntw2_profile_runtime_header {
    uint32_t magic, version, bytes, runtime_base, runtime_size, bucket_bytes, bucket_count, histogram_count;
    uint32_t pair_capacity, pair_count, pair_overflow, wait_capacity, wait_count, wait_overflow;
    uint32_t wait_samples, wait_unresolved, wait_direct, wait_scanned;
    uint32_t tick_runtime_samples, worker_runtime_samples, all_runtime_samples, selected_runtime_samples;
    uint32_t selected_site, flags;
} ntw2_profile_runtime_header;
typedef struct ntw2_profile_runtime_pair { uint32_t rva, frame_rva, count; } ntw2_profile_runtime_pair;
typedef struct ntw2_profile_runtime_wait { uint32_t rva, kind, count; } ntw2_profile_runtime_wait;
#define NTW2_PROFILE_RUNTIME_BYTES(n) (sizeof(ntw2_profile_runtime_header) + \
    (size_t)(n) * NTW2_PROFILE_RUNTIME_HISTOGRAMS * sizeof(uint32_t) + \
    NTW2_PROFILE_RUNTIME_PAIRS * sizeof(ntw2_profile_runtime_pair) + \
    NTW2_PROFILE_RUNTIME_WAITS * sizeof(ntw2_profile_runtime_wait))
#define NTW2_PROFILE_RUNTIME_HIST(h) ((uint32_t*)((h) + 1))
#define NTW2_PROFILE_RUNTIME_PAIR_TABLE(h) ((ntw2_profile_runtime_pair*)(NTW2_PROFILE_RUNTIME_HIST(h) + \
    (size_t)(h)->bucket_count * (h)->histogram_count))
#define NTW2_PROFILE_RUNTIME_WAIT_TABLE(h) ((ntw2_profile_runtime_wait*)(NTW2_PROFILE_RUNTIME_PAIR_TABLE(h) + (h)->pair_capacity))

#ifdef __cplusplus

struct ntw2_grid_census_status;
/* Called only with the prior sampler stopped and runtime gates quiesced. */
void ntw2_grid_census_reset(bool enabled);
void ntw2_grid_census_snapshot(volatile ntw2_grid_census_status* out);
void __cdecl ntw2_grid_census_call(uint32_t edge);
void ntw2_grid_census_tick(uint32_t tick);
extern volatile uint32_t ntw2_grid_census_site;

/* Monitor-owned lifecycle. SetActive(false) drains the current sample before
   returning; call before publishing RESTORING/FAILED or reclaiming any code.
   Stop joins the sampler before freeing its one histogram allocation. */
uint32_t ntw2_profile_start(uint32_t thread_id, uint32_t image_base, uint32_t image_size,
                            uint32_t runtime_base, uint32_t clone_base, uint32_t clone_size);
void ntw2_profile_set_active(bool active);
uint32_t ntw2_profile_storage_bytes();
/* Legacy all-thread/tick tables are gated by this tick or selected-site word. */
extern volatile uint32_t* ntw2_profile_tick_gate;
/* Main-thread phases always use the actual TickGate, not a selected profile site.
   Publish its exit timestamp immediately before clearing the actual gate word. */
extern volatile uint32_t* ntw2_profile_main_tick_gate;
/* Publish the same raw entry QPC as the trace before setting the actual gate word. */
void ntw2_profile_tick_start(uint64_t qpc_start);
void ntw2_profile_tick_end(uint64_t qpc_end);
/* --army-storm-sample-ms (NTW2_ARMY_STORM_SAMPLE_MASK): nonzero threshold makes the selected-site gate admit a sample only once
   the site has been in progress that many ms. The runtime publishes the site's entry QPC (before it sets the gate word) via
   ntw2_profile_storm_entry; admitted/rejected count gated sampler visits. Zero: sampler unchanged. */
extern volatile uint32_t ntw2_profile_storm_threshold_ms;
extern volatile uint32_t ntw2_profile_storm_admitted;
extern volatile uint32_t ntw2_profile_storm_rejected;
void ntw2_profile_storm_entry(uint64_t qpc);
void ntw2_profile_stop();
#endif /* __cplusplus */
#endif
