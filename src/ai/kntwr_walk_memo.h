#ifndef KNTWR_WALK_MEMO_H
#define KNTWR_WALK_MEMO_H
#include <stdint.h>

// Owner-thread cache for the allocation-free, kind-0 0x80DCF0 polygon predicate.
// Every lookup re-reads the OBB and ordered polygon vertices by value. There is
// deliberately no world/queue-pointer generation heuristic and no gather cache.
namespace kntwr_walk_memo {
using Kernel = unsigned char (__fastcall *)(void*, void*, void*);
void configure(Kernel original, const uint32_t* half, const uint32_t* one);
void begin();
void end();
unsigned char __fastcall kernel(void* shape, void*, void* polygon);
// Calls, hits, misses, unsupported/oversized keys. Owner updates; monitor reads.
extern volatile uint32_t counters[4];
}
#endif
