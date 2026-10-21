// --brain-retarget-jitter: the 0x6671A0 mirror and the lost-target search delay (contract and proof: kntwr_retarget_jitter.h).
// Integer-only: no x87/SSE arithmetic runs between the native caller and the native callees.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "kntwr_retarget_jitter.h"

namespace kntwr_retarget_jitter {
using U = uint32_t;
volatile U words[kWords];

namespace {
using Valid = bool(__fastcall*)(U, U, U);         // 0x6795A0(tracker; agent)
using Clear = void(__fastcall*)(U, U);            // 0x63CE00(tracker)
using Search = U(__fastcall*)(U, U, U, U);        // 0x553420 / 0x553220 / 0x6C6910(ECX; a, b)
using Assign = void(__fastcall*)(U, U, U);        // 0x662960(tracker; target)

Targets target;
bool jitter;

inline U Rd(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
inline void Wr(U address, U value) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(address)) = value; }
inline void Bump(U word, U by = 1) { words[word] += by; }
} // namespace

void ResetRow() {
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(bool enable, const Targets& targets) {
    ResetRow();
    target = targets;
    jitter = enable;
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

// 0x6671A0 instruction by instruction: 0x6671A4..0x6671AC cooldown decrement, 0x6671B4 0x6795A0, 0x6671BF 0x63CE00, 0x6671C4 cooldown test, 0x6671CA..0x667212
// key dispatch (+0 -> 0x553420, +4 -> 0x553220, +8 -> 0x6C6910, else straight to 0x66721E), 0x667216 0x662960, 0x66721E..0x66722D failed-search cooldown,
// 0x667230 return +0x10.  Every read of the tracker follows the native callee that may have written it (the callees are the original bytes).
U __fastcall TrackerTick(U tracker, U, U agent) {
    Bump(WTrackerCalls);
    const U cooldown = Rd(tracker + kCooldown);
    if (cooldown) Wr(tracker + kCooldown, cooldown - 1);
    if (reinterpret_cast<Valid>(static_cast<uintptr_t>(target.valid))(tracker, 0, agent)) return Rd(tracker + kTarget);
    const bool lost = Rd(tracker + kTarget) != 0;   // 0x6795A0 only reads: +0x10 is what the native 0x63CE00 is about to clear
    reinterpret_cast<Clear>(static_cast<uintptr_t>(target.clear))(tracker, 0);
    if (lost) {
        Bump(WLosses);
        if (jitter && !Rd(tracker + kCooldown)) {   // the lever: delay the search by the engine's own per-man jitter (0..15 ticks)
            const U delay = Rd(agent + kAgentId) & kJitterMask;
            if (delay) { Wr(tracker + kCooldown, delay); Bump(WJittered); Bump(WDelaySum, delay); }
        }
    }
    if (Rd(tracker + kCooldown)) return Rd(tracker + kTarget);
    U found;
    const U key = Rd(tracker + kSearchKey);
    if (key) found = reinterpret_cast<Search>(static_cast<uintptr_t>(target.search))(Rd(agent + kAgentUnit) + kContactList, 0, agent, key);
    else {
        const U second = Rd(tracker + kSecondKey);
        if (second) found = reinterpret_cast<Search>(static_cast<uintptr_t>(target.second))(Rd(agent + kAgentUnit) + kContactList, 0, agent, second);
        else {
            const U third = Rd(tracker + kThirdKey);
            if (!third) goto failed;
            found = reinterpret_cast<Search>(static_cast<uintptr_t>(target.third))(third, 0, agent, *reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(tracker + kFlag)));
        }
    }
    if (found) reinterpret_cast<Assign>(static_cast<uintptr_t>(target.assign))(tracker, 0, found);
failed:
    if (!Rd(tracker + kTarget)) Wr(tracker + kCooldown, (Rd(agent + kAgentId) & kJitterMask) + kFailCooldown);
    return Rd(tracker + kTarget);
}
} // namespace kntwr_retarget_jitter
