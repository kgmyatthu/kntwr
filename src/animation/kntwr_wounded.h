// --wounded decision policy (pure, image-free; hook: animation/kntwr_wounded_hook.*).
// Evidence: analysis/FINDINGS.md "Wounded/corpse animation infrastructure census" (2026-10-31).
//
// The stock kill path commits the death-anim state with a category range test (0x653F1A..0x653F38): categories
// [0x14521C8] .. +[0x14521CC] (the five melee/impact knockdowns) become wounded state 0x4B, everything else a static
// corpse 0x2A. This policy reproduces that test bit-equivalently and adds the opt-in flip: a death clip that carries
// the FACE_DOWN presence event and a nonzero FACE_DOWN or FACE_UP orientation int (the exact fields the stock state-0x4B
// stepper 0x679300 requires at clip end: byte clip+0x60, dword clip+0x5C, dword clip+0x54) may enter state 0x4B with
// probability pct%, decided by a deterministic per-death roll.
//
// The roll mixes the man's clip-variant random [M+0x1E0] (the same value the stepper reuses to re-pick the clip, so the
// inspected clip IS the clip that will play) with the man object address, so a volley sharing one random still varies
// per man. Knuth multiplicative hash; bits 8..31 taken modulo 100.
#ifndef KNTWR_WOUNDED_H
#define KNTWR_WOUNDED_H
#include <stdint.h>
#include "kntwr_wounded_orient.h"

namespace kntwr_wounded {
using U = uint32_t;

constexpr U kStateWounded = 0x4Bu;
constexpr U kStateStatic = 0x2Au;

// Stock range test: cat in [lo, lo+n) -> native wounded (knockdowns). Matches the stock jl/jb pair for every real
// category value (0 <= cat < 0x360, lo = 0x32A, n = 5; the unsigned-subtract form equals the signed jl + unsigned jb
// composition over that domain).
inline bool NativeKnockdown(U cat, U lo, U n) { return cat - lo < n; }

// Stock stepper eligibility (0x6794A7..0x6794B7): FACE_DOWN presence byte must be set AND at least one orientation int
// nonzero; otherwise the stepper would re-commit static at clip end and the flip would be a no-op.
inline bool ClipEligible(U faceDownPresent, U faceDownParam, U faceUpParam) {
    return faceDownPresent != 0 && (faceDownParam != 0 || faceUpParam != 0);
}

// Deterministic per-death roll in 0..99.
inline U Roll(U rnd, U manKey) {
    U h = (rnd ^ (manKey >> 4)) * 2654435761u;
    h ^= h >> 15;
    return (h >> 8) % 100u;
}

inline bool Flip(U rnd, U manKey, U pct) { return Roll(rnd, manKey) < pct; }

// FNV-1a 32 over the UTF-16LE bytes of s[0..len), ASCII A-Z lowered per code unit first
// (offset 0x811C9DC5, prime 0x01000193). Matches tools/gen_wounded_orient.py and kntwr_wounded_orient.h.
inline U OrientHash(const wchar_t* s, unsigned len) {
    U h = 0x811C9DC5u;
    for (unsigned i = 0; i < len; ++i) {
        unsigned unit = static_cast<unsigned>(s[i]);
        if (unit >= static_cast<unsigned>(L'A') && unit <= static_cast<unsigned>(L'Z'))
            unit = unit - static_cast<unsigned>(L'A') + static_cast<unsigned>(L'a');
        h ^= unit & 0xFFu;
        h *= 0x01000193u;
        h ^= (unit >> 8) & 0xFFu;
        h *= 0x01000193u;
    }
    return h;
}

// Binary search of kntwr_wounded_orient (sorted by hash). -1 miss, 0 face-up, 1 face-down.
inline int OrientLookup(unsigned hash) {
    unsigned lo = 0, hi = KNTWR_WOUNDED_ORIENT_COUNT;
    while (lo < hi) {
        const unsigned mid = lo + (hi - lo) / 2u;
        const unsigned h = kntwr_wounded_orient[mid].hash;
        if (h == hash) return kntwr_wounded_orient[mid].face_down ? 1 : 0;
        if (h < hash) lo = mid + 1u;
        else hi = mid;
    }
    return -1;
}
} // namespace kntwr_wounded
#endif
