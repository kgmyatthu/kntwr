// --ai-march-slots: uncapped slot assignment + full order issue for the first execute of an AI formation MOVE command (contract, engine facts and word layout:
// ntw2_march_slots.h). Runs inside the R2 gate (slot 0x1325474) on the tick owner; engine memory is read inside SEH brackets, the only writes are [C+0x30] and what the
// native 0x576B30 / 0x584E10 do.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include "ntw2_march_slots.h"
#include "core/ntw2_guard.h"

namespace ntw2_march_slots {
volatile U words[kWords];

namespace {
constexpr U kFormation = 4, kLatch = 0x7C, kPacing = 0x30, kUnit = 0x510, kArmy = 0x1EC, kQueueCount = 0x460, kQueueBase = 0x420, kMen = 0x18, kDirty = 0x278C, kCooldown = 0x2788;
constexpr U kBattle = 0xB0, kSideCount = 0x84, kSideArray = 0x88, kSideCommander = 0xC, kSideArmies = 0x20, kSideArmyArray = 0x24;
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxMen = 4096;

using ThisOne = void(__fastcall*)(U ecx, U edx, U a);

Targets target;
bool configured;
double usPerTick;

inline void Bump(Word w, U by = 1) { words[w] += by; }
inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline unsigned char RdB(U a) { return *reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(a)); }
inline void Wr(U a, U v) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(a)) = v; }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }

// 1 = the army belongs to an AI side ([side+0xC] != 0), 2 = a human side, 0 = not found / unreadable.
U SideKind(U model, U army) {
    const U world = Rd(model + kBattle);
    if (!Sane(world)) return 0;
    const U sideCount = Rd(world + kSideCount), sideArray = Rd(world + kSideArray);
    if (!Sane(sideArray) || sideCount == 0 || sideCount > kMaxSides) return 0;
    for (U i = 0; i < sideCount; ++i) {
        const U side = Rd(sideArray + 4 * i);
        if (!Sane(side)) continue;
        const U armyCount = Rd(side + kSideArmies), armyArray = Rd(side + kSideArmyArray);
        if (armyCount > kMaxArmies || (armyCount && !Sane(armyArray))) continue;
        for (U j = 0; j < armyCount; ++j)
            if (Rd(armyArray + 4 * j) == army) return Rd(side + kSideCommander) ? 1u : 2u;
    }
    return 0;
}

// *verdict: 0 latched (not a first execute), 1 first execute of an AI unit, 2 first execute of a human unit, 3 unresolved. POD locals only (runs inside __try).
void PreBody(U command, U model, U* verdict) {
    *verdict = 0;
    if (RdB(command + kLatch) != 0) return;
    const U formation = Rd(command + kFormation);
    if (!Sane(formation)) { *verdict = 3; return; }
    const U unit = Rd(formation + kUnit);
    if (!Sane(unit)) { *verdict = 3; return; }
    const U army = Rd(unit + kArmy);
    if (!Sane(army)) { *verdict = 3; return; }
    const U kind = SideKind(model, army);
    *verdict = kind == 1 ? 1u : (kind == 2 ? 2u : 3u);
}
bool PreGuarded(U command, U model, U* verdict) {
    __try { PreBody(command, model, verdict); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// *state: 0 gone, 1 done. *men / *solveUs / *issueUs filled when done.
void PostBody(U command, U solve, U* state, U* men, U* solveTicks, U* issueTicks) {
    *state = 0;
    const U formation = Rd(command + kFormation);
    if (!Sane(formation)) return;
    const U queued = Rd(formation + kQueueCount);
    if (queued == 0 || queued > 8) return;
    if (Rd(formation + kQueueBase + 8 * (queued - 1)) != command) return;
    if (Rd(command) != target.delta + kMoveVtable) return;
    if (RdB(command + kLatch) == 0) return;
    const U count = Rd(formation + kMen);
    if (count == 0 || count > kMaxMen) return;
    // 0x581AE0's own argument of 0x576B30: 1 when the formation is dirty and its cooldown is zero.
    const U param = (RdB(formation + kDirty) != 0 && Rd(formation + kCooldown) == 0) ? 1u : 0u;
    LARGE_INTEGER a, b, c;
    Wr(command + kPacing, 1);   // solve flag byte 1 = the uncapped first-improvement pass (0x5373F0: limit = byte ^ 1 = 0, threshold FLT_MAX)
    QueryPerformanceCounter(&a);
    reinterpret_cast<ThisOne>(static_cast<uintptr_t>(solve))(command, 0, param);
    QueryPerformanceCounter(&b);
    reinterpret_cast<ThisOne>(static_cast<uintptr_t>(target.issue))(command, 0, 1);   // every man gets its move order to the re-solved slot (0x584E10 rewrites [C+0x30])
    QueryPerformanceCounter(&c);
    *men = count;
    *solveTicks = static_cast<U>(b.QuadPart - a.QuadPart);
    *issueTicks = static_cast<U>(c.QuadPart - b.QuadPart);
    *state = 1;
}
bool PostGuarded(U command, U solve, U* state, U* men, U* solveTicks, U* issueTicks) {
    __try { PostBody(command, solve, state, men, solveTicks, issueTicks); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
}  // namespace

void ResetRow() { for (U i = 0; i < kWords; ++i) words[i] = 0; }

void Configure(const Targets& t) {
    target = t;
    configured = t.issue != 0 && t.solveOriginal != 0;
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    usPerTick = f.QuadPart ? 1.0e6 / static_cast<double>(f.QuadPart) : 0.0;
    ResetRow();
}

void Snapshot(volatile U* out) { for (U i = 0; i < kWords; ++i) out[i] = words[i]; }

bool Pre(U command, U model) {
    if (!configured) return false;
    Bump(WCalls);
    U verdict = 0;
    ++ntw2::probeDepth;
    const bool ok = PreGuarded(command, model, &verdict);
    --ntw2::probeDepth;
    if (!ok) { Bump(WFaults); return false; }
    if (verdict == 0) { Bump(WLatched); return false; }
    Bump(WFirstExec);
    if (verdict == 1) { Bump(WAiFresh); return true; }
    if (verdict == 2) Bump(WPlayerFresh); else Bump(WUnmeasured);
    return false;
}

void Post(U command, U solve, bool solverClone) {
    if (!configured) return;
    U state = 0, men = 0, solveTicks = 0, issueTicks = 0;
    ++ntw2::probeDepth;
    const bool ok = PostGuarded(command, solve ? solve : target.solveOriginal, &state, &men, &solveTicks, &issueTicks);
    --ntw2::probeDepth;
    if (!ok) { Bump(WFaults); return; }
    if (!state) { Bump(WGone); return; }
    Bump(WResolved);
    if (solverClone) Bump(WSolverClone);
    Bump(WMenSum, men);
    if (men > words[WMaxMen]) words[WMaxMen] = men;
    const U solveUs = static_cast<U>(solveTicks * usPerTick), issueUs = static_cast<U>(issueTicks * usPerTick);
    Bump(WSolveUs, solveUs);
    Bump(WIssueUs, issueUs);
    if (solveUs + issueUs > words[WMaxUs]) words[WMaxUs] = solveUs + issueUs;
}
}  // namespace ntw2_march_slots
