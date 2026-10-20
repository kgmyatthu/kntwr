// --ai-formup-gate: withhold the REFORM / MOVE_TO_FORMUP "exit" answers of an AI attack group until the group is formed (contract and proof: ntw2_group_formup.h).
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <windows.h>
#include "ntw2_group_formup.h"
#include "core/ntw2_guard.h"

namespace ntw2_group_formup {
using U = uint32_t;
volatile U words[kWords];

namespace {
constexpr U kEntries = 512, kMaxMembers = 512, kStaleTicks = 100000;
constexpr float kCoordLimit = 16384.0f;

using ThisBool = unsigned char(__fastcall*)(U, U);
using ThisPtr = U(__fastcall*)(U, U);
using ThisPtrOut = U(__fastcall*)(U, U, U);
using Slot = U(__stdcall*)(U);

struct Entry { U tactic, enter, last; unsigned char state, blocked, used, pad; };

Targets target;
Params param;
bool enabled;
Entry table[kEntries];

inline void Bump(Word w, U by = 1) { words[w] += by; }
inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline unsigned char Rd8(U a) { return *reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool Good(float v) { return v == v && fabsf(v) < kCoordLimit; }
inline bool Call(U fn, U self) { return (reinterpret_cast<ThisBool>(static_cast<uintptr_t>(fn))(self, 0) & 0xFFu) != 0; }
inline U Event(U tactic, U slot) { return reinterpret_cast<ThisPtr>(static_cast<uintptr_t>(Rd(Rd(tactic) + slot)))(tactic, 0); }
inline U Forward(U original, U sub) { return reinterpret_cast<Slot>(static_cast<uintptr_t>(original))(sub); }
inline U TacticOf(U sub) { return sub ? sub - 0x7Cu : 0u; } // 0x702A81..0x702A8C: lea eax,[sub-0x7C]; neg; sbb; and

// model tick of the tactic: [[[t+4]+8]+0x58] (0x7A5730 / 0x7A5A80 read [[t+4]+8] as the battle model).
bool ModelTick(U tactic, U* tick) {
    const U a = Rd(tactic + 4);
    if (!Sane(a)) return false;
    const U model = Rd(a + 8);
    if (!Sane(model)) return false;
    *tick = Rd(model + 0x58);
    return true;
}

Entry* Find(U tactic, U tick) {
    const U h = (tactic >> 4) * 2654435761u;
    Entry* spare = nullptr;
    for (U i = 0; i < kEntries; ++i) {
        Entry& e = table[(h + i) & (kEntries - 1)];
        if (e.used && e.tactic == tactic) { e.last = tick; return &e; }
        if (!spare && (!e.used || e.last + kStaleTicks < tick)) spare = &e;
        if (!e.used) break;
    }
    if (!spare) return nullptr;
    spare->tactic = tactic; spare->used = 1; spare->state = 0; spare->enter = tick; spare->last = tick; spare->blocked = 0;
    return spare;
}

// formed% of the tactic's member units (contract in the header); *members receives the counted members. Engine reads only; POD locals (runs inside __try).
U FormedPercent(U tactic, U* members) {
    const U count = Rd(tactic + 0x6C), array = Rd(tactic + 0x70);
    U m = 0, formed = 0, unmeasured = 0;
    *members = 0;
    if (!count || count > kMaxMembers || !Sane(array)) return 100;
    const float metres = static_cast<float>(param.metres), limit2 = metres * metres;
    for (U i = 0; i < count; ++i) {
        const U u = Rd(array + 4 * i);
        if (!Sane(u)) continue;
        if (Rd(u + 0xAA0) == 2 || Rd(u + 0x2CC) == 0) continue;       // 0x55CB50: not live
        const U ai = Rd(u + 0xB34);
        if (ai == 6 || ai == 7 || Rd8(u + 0xB42)) continue;           // not under the group move (0x7D3760 skips them)
        ++m;
        const U f = Rd(u + 0xADC);
        if (!Sane(f)) { ++formed; ++unmeasured; continue; }
        const float cx = RdF(f + 0x644), cz = RdF(f + 0x648);
        const U cnt = Rd(u + 0x930), idx = Rd(u + 0x934);
        if (cnt == 0 || idx >= 10) { ++formed; continue; }            // no active order: standing where its last move ended
        if (!Good(cx) || !Good(cz)) { ++formed; ++unmeasured; continue; }
        const U row = u + 0x398 + 0x90 * idx, vt = Rd(row);
        if (vt != target.moveVtable) { ++formed; ++unmeasured; continue; } // an attack/halt/other command: not a slot move
        const U pose = reinterpret_cast<ThisPtr>(static_cast<uintptr_t>(Rd(vt + 0x38)))(row, 0);
        if (!Sane(pose) || (Rd(pose + 0x10) && !Sane(Rd(pose + 0x10)))) { ++formed; ++unmeasured; continue; }
        float out[3] = {0, 0, 0};
        const U v = reinterpret_cast<ThisPtrOut>(static_cast<uintptr_t>(target.poseToVec))(pose, 0, static_cast<U>(reinterpret_cast<uintptr_t>(out)));
        const float dx = RdF(v), dz = RdF(v + 8);
        if (!Good(dx) || !Good(dz)) { ++formed; ++unmeasured; continue; }
        const float ux = dx - cx, uz = dz - cz;
        if (ux * ux + uz * uz <= limit2) ++formed;
    }
    *members = m;
    if (unmeasured) Bump(WUnmeasured, unmeasured);
    return m ? (formed * 100u) / m : 100u;
}

inline void Account(Entry& e, U wait) {
    if (e.blocked) { Bump(WWaitSum, wait); if (wait > words[WWaitMax]) words[WWaitMax] = wait; e.blocked = 0; }
}

// true: let the native "exit" through. POD locals only.
bool AllowImpl(U tactic, U state) {
    if (Rd8(tactic + 0x81E) == 0) { Bump(WPassWaived); return true; }
    if (RdF(tactic + 0x80C) <= kEscapeMetres) { Bump(WPassEscape); return true; }
    U tick;
    if (!ModelTick(tactic, &tick)) { Bump(WFaults); return true; }
    Entry* e = Find(tactic, tick);
    if (!e) { Bump(WFaults); return true; }
    if (e->state != state) { e->state = static_cast<unsigned char>(state); e->enter = tick; e->blocked = 0; } // exit tested without a seen entry: start the clock here
    const U wait = tick >= e->enter ? tick - e->enter : 0;
    if (wait >= param.timeoutTicks) { Bump(WPassTimeout); Account(*e, wait); return true; }
    U members;
    const U pct = FormedPercent(tactic, &members);
    Bump(pct <= 25 ? WHist0 : pct <= 50 ? WHist1 : pct <= 75 ? WHist2 : WHist3);
    if (pct >= param.pct) { Bump(WPassFormed); Account(*e, wait); return true; }
    Bump(WBlocked);
    if (!e->blocked) { e->blocked = 1; Bump(WBlockedEntries); }
    if (wait > words[WWaitMax]) words[WWaitMax] = wait;
    return false;
}
bool Allow(U tactic, U state) {
    bool ok = true;
    ++ntw2::probeDepth; // every fault below is an expected, caught one: not a crash capture (CrashVeh)
    __try { ok = AllowImpl(tactic, state); }
    __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); ok = true; }
    --ntw2::probeDepth;
    return ok;
}

// Mirror of 0x702A80 / 0x702B20 (see the header).
U Test(U sub, U state, U original) {
    const U t = TacticOf(sub);
    if (!enabled || !t) return Forward(original, sub);
    Bump(WEvals);
    if (target.scope && !target.scope(GetCurrentThreadId())) words[WFaults] += 0x10000u;
    const bool reform = state == 2;
    if (Call(reform ? target.reformExit : target.formupExit, t)) {
        Bump(WNativeExit);
        if (!Allow(t, state)) return 0;
        return Event(t, 0x88);
    }
    if (reform) return Call(target.reformAlt, t) ? Event(t, 0x84) : 0;
    if (Call(target.formupAlt, t)) return Event(t, 0x80);
    if (Call(target.formupAlt2, t)) return Event(t, 0x8C);
    return 0;
}
void NoteEntry(U t, U state) {
    ++ntw2::probeDepth;
    __try {
        U tick;
        if (ModelTick(t, &tick)) {
            Entry* e = Find(t, tick);
            if (e) { e->state = static_cast<unsigned char>(state); e->enter = tick; e->blocked = 0; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); }
    --ntw2::probeDepth;
}
U Enter(U sub, U state, U original) {
    const U t = TacticOf(sub);
    if (enabled && t) NoteEntry(t, state);
    return Forward(original, sub);
}
} // namespace

void ResetRow() {
    enabled = false; // the gates stay pure forwarders until the next Configure (their targets are kept)
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(bool on, const Params& params, const Targets& targets) {
    target = targets;
    param = params;
    enabled = on;
    for (Entry& e : table) e = Entry{};
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

U __stdcall TestGate2(U sub) { return Test(sub, 2, target.test2); }
U __stdcall TestGate3(U sub) { return Test(sub, 3, target.test3); }
U __stdcall EnterGate2(U sub) { return Enter(sub, 2, target.enter2); }
U __stdcall EnterGate3(U sub) { return Enter(sub, 3, target.enter3); }
} // namespace ntw2_group_formup
