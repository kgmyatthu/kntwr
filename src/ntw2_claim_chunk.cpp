// --ai-claim-chunk: the capped fallback claim loop and its continuation bookkeeping (contract and proof: ntw2_claim_chunk.h).
// Integer-only: no x87/SSE arithmetic runs between the native caller and the native callees.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string.h>
#include "ntw2_claim_chunk.h"

namespace ntw2_claim_chunk {
using U = uint32_t;
volatile U words[kWords];

namespace {
using Native1 = U(__fastcall*)(U, U, U);          // 0x7524A0(obs, list); 0x84B1D0(ctrl, 0)
using Eligible = bool(__fastcall*)(U, U);         // 0x55AB90(unit)
using Claim = U(__fastcall*)(U, U, U, U);         // 0x74F430(obs, row, ctrl)

Targets target;
U chunk;
U maxPending, maxTicks;

// Bounded per-observer table of the entries the cap left unclaimed (bookkeeping only).
struct Observer {
    U obs, count, last;
    U unit[kPending], first[kPending];
    bool alive[kPending];
};
Observer table[kObservers];
Observer* current;
U sequence, nowTick;

inline void Bump(U word, U by = 1) { words[word] += by; }
U ReadU(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
// The controller's model tick, [[[ctrl+8]+8]+0x58] (0x82F6EE..0x82F6F4); SEH-guarded so the bookkeeping can never fault the think.
bool ReadTick(U ctrl, U* tick) {
    __try {
        *tick = ReadU(ReadU(ReadU(ctrl + 8) + 8) + 0x58);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
void Publish() {
    const U ticks = maxTicks > 0xFFFFu ? 0xFFFFu : maxTicks;
    words[WPacked] = (maxPending & 0xFFu) | (ticks << 8) | (chunk << 24);
}
void Latency(U first) {
    const U age = nowTick - first;
    if (nowTick >= first && age > maxTicks) { maxTicks = age; Publish(); }
}
void Remove(Observer& o, U index) {
    --o.count;
    o.unit[index] = o.unit[o.count]; o.first[index] = o.first[o.count]; o.alive[index] = o.alive[o.count];
}
Observer* Acquire(U obs) {
    Observer* vacant = nullptr; Observer* idle = nullptr; Observer* oldest = nullptr;
    for (Observer& o : table) {
        if (o.obs == obs) return &o;
        if (!o.obs) { if (!vacant) vacant = &o; }
        else if (!o.count) { if (!idle || o.last < idle->last) idle = &o; }
        if (o.obs && (!oldest || o.last < oldest->last)) oldest = &o;
    }
    Observer* slot = vacant ? vacant : idle ? idle : oldest;
    if (slot->count) Bump(WDrops, slot->count); // record of an observer not seen for the longest time: its pending entries are lost
    slot->obs = obs; slot->count = 0;
    return slot;
}
void BeginCall(U obs) {
    if (!ReadTick(obs + 0x78, &nowTick)) nowTick = 0;
    current = Acquire(obs);
    current->last = ++sequence;
    if (current->count) {
        Bump(WContinuations);
        for (U i = 0; i < current->count; ++i) current->alive[i] = false;
    }
}
void NoteClaim(U unit) {
    Observer& o = *current;
    for (U i = 0; i < o.count; ++i)
        if (o.unit[i] == unit) {
            Bump(WContinuationClaims);
            Latency(o.first[i]);
            Remove(o, i);
            return;
        }
    Bump(WClaimed);
}
void NoteDeferred(U unit) {
    Observer& o = *current;
    for (U i = 0; i < o.count; ++i)
        if (o.unit[i] == unit) { o.alive[i] = true; return; }
    Bump(WDeferred);
    if (o.count == kPending) { Bump(WUntracked); return; }
    o.unit[o.count] = unit; o.first[o.count] = nowTick; o.alive[o.count] = true; ++o.count;
}
void EndCall() {
    Observer& o = *current;
    for (U i = 0; i < o.count;)
        if (!o.alive[i]) { Bump(WDrops); Latency(o.first[i]); Remove(o, i); }
        else ++i;
    if (o.count > maxPending) { maxPending = o.count; Publish(); }
}

// Host mirror of 0x7524A0 (0x7524AB..0x7524FC): same eligibility, same native callees, same order; the cap only stops claiming.
U Run(U obs, U list) {
    const Eligible blocked = reinterpret_cast<Eligible>(static_cast<uintptr_t>(target.eligible));
    const Claim claim = reinterpret_cast<Claim>(static_cast<uintptr_t>(target.claim));
    const Native1 post = reinterpret_cast<Native1>(static_cast<uintptr_t>(target.post));
    const U controller = obs + 0x78;
    BeginCall(obs);
    Bump(WCalls);
    U claimed = 0;
    for (U i = 0; i < ReadU(list + 8); ++i) {            // [L+8] is reloaded every iteration (0x7524E9)
        U row = ReadU(list + 0xC) + i * 12;
        if (*reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(row + 8))) continue;
        if (blocked(ReadU(row), 0)) continue;
        row = ReadU(list + 0xC) + i * 12;                 // 0x7524C9 reloads the data pointer after the predicate call
        const U unit = ReadU(row);
        if (ReadU(unit + 0xB34) == 8) continue;
        if (claimed < chunk) {
            ++claimed;
            NoteClaim(unit);
            claim(obs, 0, row, controller);
        } else NoteDeferred(unit);
    }
    EndCall();
    return post(controller, 0, 0);
}
} // namespace

void ResetRow() {
    chunk = 0; // the gate stays pure until the next Configure (its targets are kept)
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(U n, const Targets& targets) {
    target = targets;
    chunk = n;
    maxPending = maxTicks = sequence = nowTick = 0;
    current = nullptr;
    memset(table, 0, sizeof(table));
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    if (n) Publish();
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

U __fastcall Gate(U self, U, U list) {
    if (!chunk || list != target.list || !target.scope(GetCurrentThreadId()))
        return reinterpret_cast<Native1>(static_cast<uintptr_t>(target.native))(self, 0, list);
    return Run(self, list);
}
} // namespace ntw2_claim_chunk
