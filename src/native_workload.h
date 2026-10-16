#pragma once
#include <stdint.h>

/* Fixed, activation-only capacities. Growth during a battle is admitted only while
   it fits these bounds; otherwise the complete untouched native stage is used.
   C-compatible: launcher/main.c includes loco/native_loco.h for the label macros. */
#ifdef __cplusplus
namespace ntw2_workload {
struct Capacity {
    uint32_t primary;     // movement occurrence / primary collision index slots
    uint32_t records;     // primary + unique secondary grid records (upper bound)
    uint32_t cells;       // addressable native cell slots, including empty cells
    uint32_t memberships;
    uint32_t pairs;       // candidate-pair estimate derived from the measured census
};
}
#endif
