// --ai-claim-once: one placement recompute per fallback claim call (contract and proof: kntwr_claim_once.h).
// Integer-only: no x87/SSE arithmetic runs between the native caller and the native callees.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "kntwr_claim_once.h"

namespace kntwr_claim_once {
using U = uint32_t;
volatile U words[kWords];

namespace {
using Native1 = U(__fastcall*)(U, U, U);          // 0x7524A0(obs, list); 0x84B1D0(ctrl, 0); 0x82F3A0(ctrl, 30.0f bits)
using Getter = bool(__fastcall*)(U, U);           // 0x55AB90(unit), 0x55AD60(stateObject)
using Claim = U(__fastcall*)(U, U, U, U);         // 0x74F430(obs, row, ctrl)

Targets target;
Mode mode;
U maxEntries, noFinalTail, hashedCalls, hash;

inline void Bump(U word, U by = 1) { words[word] += by; }
inline U Sat(U v, U max) { return v > max ? max : v; }
void Publish() { words[WPacked] = Sat(maxEntries, 0xFF) | (Sat(noFinalTail, 0xFF) << 8) | (hashedCalls << 16); words[WHash] = hash; }
inline void Fold(U v) { hash = (hash ^ v) * 16777619u; }
U ReadU(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
void WriteU(U address, U value) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(address)) = value; }
// 0x82F3A0's gate inputs: tick = [[[ctrl+8]+8]+0x58], state object = [[[ctrl+8]+8]+0xB0] (0x82F6EE..0x82F6FD); SEH-guarded.
bool ReadGate(U ctrl, U* tick, U* stateObject) {
    __try {
        const U model = ReadU(ReadU(ctrl + 8) + 8);
        *tick = ReadU(model + 0x58);
        *stateObject = ReadU(model + 0xB0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 0x7524B6..0x7524D7: row+8 == 0, !0x55AB90(unit), unit+0xB34 != 8. 0x55AB90 is a pure getter (no calls, no stores), so the native reload of
// the data pointer after it (0x7524C9) cannot observe a change and the row address stays valid.
bool Claimable(U row) {
    if (*reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(row + 8))) return false;
    if (reinterpret_cast<Getter>(static_cast<uintptr_t>(target.eligible))(ReadU(row), 0)) return false;
    return ReadU(ReadU(row) + 0xB34) != 8;
}
// 0x826E80 skips 0x82F3A0 for unit+0xB34 in {6,7}.
bool Tails(U row) {
    const U state = ReadU(ReadU(row) + 0xB34);
    return state != 6 && state != 7;
}
bool LaterTail(U list, U from) {
    for (U j = from; j < ReadU(list + 8); ++j) {
        const U row = ReadU(list + 0xC) + j * 12;
        if (Claimable(row) && Tails(row)) return true;
    }
    return false;
}

// The loop body; `saved`/`original` are the caller's so the unwind handler in Run can restore the memo word.
void Loop(U obs, U list, U controller, U memoWord, bool& saved, U& original, U& entries, U& masked, bool& pending) {
    const Claim claim = reinterpret_cast<Claim>(static_cast<uintptr_t>(target.claim));
    for (U i = 0; i < ReadU(list + 8); ++i) {            // [L+8] is reloaded every iteration (0x7524E9)
        const U row = ReadU(list + 0xC) + i * 12;
        if (!Claimable(row)) continue;
        const bool tails = Tails(row);
        bool mask = false;
        if (mode == ModeOnce && tails && LaterTail(list, i + 1)) {
            const U last = saved ? original : ReadU(memoWord);
            U tick, stateObject;
            const bool latched = *reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(controller + 0x75D)) != 0; // byte, as 0x826EF4 tests it
            if (!ReadGate(controller, &tick, &stateObject) || tick < 2 || !latched) Bump(WRefusedOther);
            else if (reinterpret_cast<Getter>(static_cast<uintptr_t>(target.memoState))(stateObject, 0)) Bump(WRefusedState);
            else if (last == 0 || last == tick || last + 10 < tick) { // native would recompute here
                if (!saved) { original = last; saved = true; }
                WriteU(memoWord, tick - 1);                   // a memo the native gate accepts and does not write
                mask = true;
            }
        }
        if (!mask && saved) { WriteU(memoWord, original); saved = false; }
        // `pending`: a masked recompute is owed until an unmasked tailing entry runs after it. The prediction (LaterTail) can be wrong
        // when a claim changes a later row's eligibility/state, so the owed recompute is settled by Run after the loop.
        if (mask) { ++masked; pending = true; } else if (tails) pending = false;
        ++entries;
        claim(obs, 0, row, controller);
    }
}

U Run(U obs, U list) {
    const Native1 post = reinterpret_cast<Native1>(static_cast<uintptr_t>(target.post));
    const U controller = obs + 0x78, memoWord = controller + 0x724;
    Bump(WCalls);
    U entries = 0, masked = 0, original = 0;
    bool saved = false, pending = false;
    __try {
        Loop(obs, list, controller, memoWord, saved, original, entries, masked, pending);
    } __finally {
        // Unwinding through a native claim must not leave the temporary memo in the controller (it would mask recomputes for 10 ticks).
        if (saved) { WriteU(memoWord, original); saved = false; }
    }
    if (pending) {
        // The predicted last tailing entry did not run (or ran masked): settle the owed recompute exactly as 0x826EE8..0x826EFB does
        // (ECX = ctrl, 30.0f, EAX -> ctrl+0x758). The memo word holds the pre-loop value, which the native gate rejects, so the query runs
        // with the full membership; the latch +0x75D is already set (masking requires it), so no 0x5D9A20 suffix is owed.
        const Native1 recompute = reinterpret_cast<Native1>(static_cast<uintptr_t>(target.recompute));
        WriteU(controller + 0x758, recompute(controller, 0, 0x41F00000u));
        ++noFinalTail;
    }
    Bump(WEntries, entries);
    if (entries > maxEntries) maxEntries = entries;
    if (masked) { Bump(WMasked, masked); Bump(WCallsMasked); }
    if (entries >= 2 && hashedCalls < kHashCalls) {
        Fold(entries); Fold(ReadU(controller + 0x6B0) & 0xFFFFu); Fold(ReadU(controller + 0x704)); Fold(ReadU(controller + 0x708));
        Fold(ReadU(controller + 0x720)); Fold(ReadU(controller + 0x724)); Fold(ReadU(controller + 0x758));
        ++hashedCalls;
    }
    Publish();
    return post(controller, 0, 0);
}
} // namespace

void ResetRow() {
    mode = ModeOff; // the gate stays pure until the next Configure (its targets are kept)
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(Mode m, const Targets& targets) {
    target = targets;
    mode = m;
    maxEntries = noFinalTail = hashedCalls = 0;
    hash = 2166136261u;
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

U __fastcall Gate(U self, U, U list) {
    if (mode == ModeOff || list != target.list || !target.scope(GetCurrentThreadId()))
        return reinterpret_cast<Native1>(static_cast<uintptr_t>(target.native))(self, 0, list);
    return Run(self, list);
}
} // namespace kntwr_claim_once
