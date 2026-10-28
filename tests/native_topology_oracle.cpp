// Pure decision rules of src/core/kntwr_topology.h: worker clamp arithmetic and tick-placement (pin) eligibility.
// No image, no live process, no affinity change.
#include <cstdio>
#include <cstdint>
#include "core/kntwr_topology.h"
#include <initializer_list>

using namespace kntwr_topology;

static unsigned failures;
#define CHECK(cond) do { if (!(cond)) { ++failures; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } } while (0)

int main() {
    // PopCount
    CHECK(PopCount(0) == 0 && PopCount(1) == 1 && PopCount(0xFFu) == 8 && PopCount(0xFFFFFFFFu) == 32 && PopCount(0x80000001u) == 2);
    for (uint32_t m : {0x0u, 0x5u, 0xF0F0F0F0u, 0x12345678u}) {
        unsigned ref = 0; for (unsigned b = 0; b < 32; ++b) ref += (m >> b) & 1u;
        CHECK(PopCount(m) == ref);
    }

    // ClampWorkers = min(configured, max(1, usable - 2)); 0 stays 0; unreadable affinity (0) leaves the request.
    CHECK(ClampWorkers(8, 20) == 8);   // dev box: unchanged
    CHECK(ClampWorkers(8, 10) == 8);
    CHECK(ClampWorkers(8, 9) == 7);
    CHECK(ClampWorkers(8, 4) == 2);    // 4-LP box: 8 -> 2
    CHECK(ClampWorkers(8, 3) == 1);
    CHECK(ClampWorkers(8, 2) == 1);    // never below 1
    CHECK(ClampWorkers(8, 1) == 1);
    CHECK(ClampWorkers(1, 4) == 1);
    CHECK(ClampWorkers(2, 4) == 2);
    CHECK(ClampWorkers(3, 4) == 2);
    CHECK(ClampWorkers(16, 32) == 16);
    CHECK(ClampWorkers(0, 4) == 0);    // no pool requested
    CHECK(ClampWorkers(8, 0) == 8);    // affinity unreadable
    for (uint32_t cfg = 0; cfg <= 16; ++cfg)
        for (uint32_t lps = 1; lps <= 32; ++lps) {
            const uint32_t w = ClampWorkers(cfg, lps);
            CHECK(w <= cfg);
            CHECK(cfg == 0 || w >= 1);
            CHECK(cfg == 0 || lps < 4 || w <= lps - 2);
        }

    // Partial coverage / census.
    CHECK(!PartialCoverage(false, false));
    CHECK(PartialCoverage(true, false) && PartialCoverage(false, true) && PartialCoverage(true, true));
    CHECK(CensusUsable(true, false));
    CHECK(!CensusUsable(true, true));
    CHECK(!CensusUsable(false, false));

    // PinUsable(partial, minClass, maxClass, P, E)
    const uint32_t p8 = 0x000000FFu, e8 = 0x0000FF00u;
    CHECK(PinUsable(false, 0, 1, p8, e8));                 // hybrid, 8 P
    CHECK(!PinUsable(true, 0, 1, p8, e8));                 // partial read (other group / LP >= 32): inert
    CHECK(!PinUsable(false, 1, 1, p8, e8));                // single class
    CHECK(!PinUsable(false, 0, 1, 0, e8));                 // empty P mask
    CHECK(!PinUsable(false, 0, 1, p8, 0));                 // empty E mask
    CHECK(PinUsable(false, 0, 1, 0xFu, e8));               // exactly 4 P
    CHECK(!PinUsable(false, 0, 1, 0x7u, e8));              // 3 P
    CHECK(!PinUsable(false, 0, 1, 0x1u, e8));              // 1 P
    CHECK(PinUsable(false, 0, 2, 0xA5A5u, 0x1u << 20));    // sparse P bits, 8 of them

    if (failures) { std::printf("native_topology_oracle: %u failures\n", failures); return 1; }
    std::printf("native_topology_oracle: ok\n");
    return 0;
}
