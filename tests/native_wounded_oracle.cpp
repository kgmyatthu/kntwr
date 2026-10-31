// --wounded decision policy (src/animation/kntwr_wounded.h): pure integer rules, no image, no live process.
//  * NativeKnockdown reproduces the stock jl (signed lo) + jb (unsigned span) pair for every real category 0..0x35F,
//    checked exhaustively against the literal two-branch composition for the stock {lo 0x32A, n 5} and edge tables.
//  * ClipEligible matches the stock stepper requirement (presence byte AND at least one orientation int) over the
//    full truth table.
//  * Roll stays in 0..99, is deterministic, varies across men sharing one volley random, and Flip hits the requested
//    percentage within tolerance for pct 1/33/50/100 over large sweeps; pct=100 always flips, pct=0 never does.
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include "animation/kntwr_wounded.h"

using U = uint32_t;
namespace w = kntwr_wounded;
static U checks;
static void Require(bool ok, const char* what) {
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL %s\n", what); std::exit(1); }
}

// Literal re-composition of the bypassed stock select 0x653F22..0x653F38: jl (signed) rejects below lo, jb (unsigned)
// accepts below lo+n.
static bool StockKnockdown(U cat, U lo, U n) {
    if (static_cast<int32_t>(cat) < static_cast<int32_t>(lo)) return false;
    return cat < lo + n;
}

int main() {
    Require(w::kStateWounded == 0x4Bu && w::kStateStatic == 0x2Au, "state constants");

    // ---- NativeKnockdown == stock jl/jb pair, exhaustively over the real category domain ----
    static const U kRanges[][2] = {{0x32A, 5}, {0, 1}, {0, 0}, {0x35F, 1}, {0x100, 0x20}, {0x35B, 5}};
    for (const auto& r : kRanges)
        for (U cat = 0; cat < 0x360u; ++cat)
            Require(w::NativeKnockdown(cat, r[0], r[1]) == StockKnockdown(cat, r[0], r[1]),
                    "NativeKnockdown == stock jl+jb composition");
    Require(!w::NativeKnockdown(0x329, 0x32A, 5), "0x329 below the knockdown range");
    Require(w::NativeKnockdown(0x32A, 0x32A, 5) && w::NativeKnockdown(0x32E, 0x32A, 5), "0x32A..0x32E native");
    Require(!w::NativeKnockdown(0x32F, 0x32A, 5), "0x32F (landed flyer) outside the range");

    // ---- ClipEligible truth table ----
    for (U present = 0; present < 2; ++present)
        for (U fd = 0; fd < 2; ++fd)
            for (U fu = 0; fu < 2; ++fu)
                Require(w::ClipEligible(present, fd, fu) == (present != 0 && (fd != 0 || fu != 0)),
                        "ClipEligible == presence AND an orientation int");
    Require(w::ClipEligible(0xFF, 0xFFFFFFFFu, 0), "nonzero byte/int values accepted as set");

    // ---- Roll: range and determinism ----
    for (U rnd = 0; rnd < 4096; ++rnd)
        for (U key = 0x4000000; key < 0x4000000 + 8 * 0x660; key += 0x660) {
            const U roll = w::Roll(rnd, key);
            Require(roll < 100u, "roll in 0..99");
            Require(roll == w::Roll(rnd, key), "roll deterministic");
        }

    // ---- volley variance: one shared random, distinct men still spread ----
    {
        U seen[100] = {};
        U distinct = 0;
        for (U i = 0; i < 1000; ++i) {
            const U roll = w::Roll(0x1234u, 0x8000000u + i * 0x660u);
            if (!seen[roll]++) ++distinct;
        }
        Require(distinct > 60u, "shared volley random still spreads rolls across men");
    }

    // ---- Flip percentage over large sweeps ----
    static const U kPcts[] = {1, 33, 50, 100};
    for (U pct : kPcts) {
        U flips = 0;
        const U kMen = 100000;
        for (U i = 0; i < kMen; ++i)
            if (w::Flip(0xBEEFu, 0x9000000u + i * 0x660u, pct)) ++flips;
        const U lo = pct > 3 ? (pct - 3) * kMen / 100 : 0, hi = (pct + 3) * kMen / 100;
        Require(flips >= lo && flips <= hi, "flip rate within 3% of pct (fixed volley random)");
        flips = 0;
        for (U rnd = 0; rnd < kMen; ++rnd)
            if (w::Flip(rnd, 0xA123450u, pct)) ++flips;
        Require(flips >= lo && flips <= hi, "flip rate within 3% of pct (fixed man)");
    }
    for (U rnd = 0; rnd < 1000; ++rnd) {
        Require(w::Flip(rnd, 0xB000000u + rnd, 100), "pct 100 always flips");
        Require(!w::Flip(rnd, 0xB000000u + rnd, 0), "pct 0 never flips");
    }
    // boundary: pct == roll denies, pct == roll+1 flips
    for (U rnd = 7; rnd < 50; ++rnd) {
        const U key = 0xC000000u + rnd * 0x660u;
        const U roll = w::Roll(rnd, key);
        if (roll == 0 || roll > 99) continue;
        Require(!w::Flip(rnd, key, roll), "pct == roll denies");
        Require(w::Flip(rnd, key, roll + 1), "pct == roll+1 flips");
    }

    // ---- orientation table: hash, lookup, ordering, case folding ----
    {
        const wchar_t* upName = KNTWR_WOUNDED_ORIENT_SAMPLE_UP_NAME;
        const wchar_t* downName = KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_NAME;
        Require(w::OrientHash(upName, static_cast<unsigned>(std::wcslen(upName))) == KNTWR_WOUNDED_ORIENT_SAMPLE_UP_HASH,
                "OrientHash(sample up name) == generated hash");
        Require(w::OrientHash(downName, static_cast<unsigned>(std::wcslen(downName))) == KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_HASH,
                "OrientHash(sample down name) == generated hash");
        Require(w::OrientLookup(KNTWR_WOUNDED_ORIENT_SAMPLE_UP_HASH) == 0, "OrientLookup(sample up) == face-up");
        Require(w::OrientLookup(KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_HASH) == 1, "OrientLookup(sample down) == face-down");
        // a hash absent from the table (pick the first value not present, deterministic)
        U miss = 0x12345678u;
        for (;; ++miss) {
            bool present = false;
            for (U i = 0; i < KNTWR_WOUNDED_ORIENT_COUNT; ++i) if (kntwr_wounded_orient[i].hash == miss) present = true;
            if (!present) break;
        }
        Require(w::OrientLookup(miss) == -1, "OrientLookup(absent hash) == -1");
        Require(w::OrientLookup(0u) == -1 || kntwr_wounded_orient[0].hash == 0u, "OrientLookup(0) misses unless the table holds 0");
        for (U i = 1; i < KNTWR_WOUNDED_ORIENT_COUNT; ++i)
            Require(kntwr_wounded_orient[i - 1].hash < kntwr_wounded_orient[i].hash, "orient table strictly ascending by hash");
        U downs = 0;
        for (U i = 0; i < KNTWR_WOUNDED_ORIENT_COUNT; ++i) {
            Require(kntwr_wounded_orient[i].face_down <= 1u, "orient entry face_down is 0/1");
            Require(w::OrientLookup(kntwr_wounded_orient[i].hash) == static_cast<int>(kntwr_wounded_orient[i].face_down),
                    "every table entry is found by its own hash");
            downs += kntwr_wounded_orient[i].face_down;
        }
        Require(downs > 0u && downs < KNTWR_WOUNDED_ORIENT_COUNT, "table carries both orientations");
        std::wstring upper = upName;
        for (auto& c : upper) if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
        Require(upper != upName, "uppercase variant differs textually");
        Require(w::OrientHash(upper.c_str(), static_cast<unsigned>(upper.size())) == KNTWR_WOUNDED_ORIENT_SAMPLE_UP_HASH,
                "uppercase variant hashes identically (ASCII fold)");
        Require(w::OrientHash(upName, 0u) == 0x811C9DC5u, "empty name hashes to the FNV offset");
        Require(w::OrientHash(L"\x0141", 1u) == w::OrientHash(L"\x0141", 1u) && w::OrientHash(L"\x0141", 1u) != w::OrientHash(L"A", 1u),
                "high byte of a code unit participates in the hash");
    }

    std::printf("native_wounded_oracle: %u checks\n", checks);
    return 0;
}
