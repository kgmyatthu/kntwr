// NTW2_AI_ASYNC2 deferred schedule: count-sliced private driver of the planner update 0x7D99F0. See the header.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include "ntw2_ai_deferred.h"

namespace ntw2_ai_deferred {
namespace {
constexpr U kNone = 0xFFFFFFFFu;

U D(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
void Put(U address, U value) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(address)) = value; }

// Index of `node` in the live array (hint first), kNone when it is not a member.
U Find(U array, U count, U node, U hint) {
    if (!array) return kNone;
    if (hint < count && D(array + 4 * hint) == node) return hint;
    for (U i = 0; i < count; ++i)
        if (D(array + 4 * i) == node) return i;
    return kNone;
}
// Planner array 1 = P+A0 / P+9C (the node list), 2 = P+B4 / P+B0 (the second round-robin array).
U FindPlanner(U planner, U list, U node, U hint) {
    return list == 1 ? Find(D(planner + 0xA0), D(planner + 0x9C), node, hint)
                     : Find(D(planner + 0xB4), D(planner + 0xB0), node, hint);
}

struct Run {
    Think& t;
    const Natives& n;
    U& budget;
    Counters& c;
    int64_t freq;

    U Micro(const LARGE_INTEGER& a, const LARGE_INTEGER& b) const {
        return b.QuadPart > a.QuadPart ? static_cast<U>((b.QuadPart - a.QuadPart) * 1000000 / freq) : 0;
    }
    void Note(U kind, const LARGE_INTEGER& a) {
        LARGE_INTEGER b; QueryPerformanceCounter(&b);
        const U us = Micro(a, b);
        ++c.calls[kind]; c.us[kind] += us;
        if (kind >= KGenerate && us > c.unitMaxUs) c.unitMaxUs = us;
    }
    // thiscall, no stack argument (the planner body calls them with ECX only).
    void Call(U kind, U target, U self) {
        LARGE_INTEGER a; QueryPerformanceCounter(&a);
        reinterpret_cast<void (__fastcall*)(U, U)>(static_cast<uintptr_t>(target))(self, 0);
        Note(kind, a);
    }
    bool Current(U node) {
        LARGE_INTEGER a; QueryPerformanceCounter(&a);
        const U result = reinterpret_cast<U (__fastcall*)(U, U)>(static_cast<uintptr_t>(D(D(node) + 0x20)))(node, 0);
        Note(KCurrent, a);
        return (result & 0xFF) != 0;
    }
    void Spend() { if (budget) --budget; }

    // Live mode (snapshot overflow): index into the live array, re-read per unit exactly like the original loop.
    U PlannerNode(U index, U& count) const {
        if (t.nodeCount != kNone) { count = t.nodeCount; return index < count ? t.nodes[index] : 0; }
        count = D(t.planner + 0x9C);
        return index < count ? D(D(t.planner + 0xA0) + 4 * index) : 0;
    }
    bool Member(U node, U index) {
        if (t.nodeCount == kNone) return true; // live index: the node was just read from the array
        const U at = FindPlanner(t.planner, 1, node, index);
        if (at == kNone) { ++c.skipped; return false; }
        if (at != index) ++c.relocated;
        return true;
    }

    // think(T) under a budget > 0. Starts the decomposed form or runs a non-decomposable think whole.
    void StartThink(U node, U list, U hint) {
        if (Current(node)) return;
        const U slot = D(D(node) + 0x10);
        if (slot != n.think) { Call(KWhole, slot, node); Spend(); return; }
        if (!D(node + 0x48)) { // 0x7D7BF0: generate, then the observer refresh of T
            Call(KGenerate, D(D(node)), node);
            Call(KPassB, n.passB, node);
            Spend();
        }
        t.tActive = 1; t.t = node; t.tList = list; t.tHint = hint; t.childIndex = 0;
        const U count = D(node + 0x48);
        if (count > kMaxChildren) { ++c.overflows; t.childCount = kNone; return; }
        const U array = D(node + 0x4C);
        t.childCount = count;
        for (U i = 0; i < count; ++i) t.children[i] = D(array + 4 * i);
    }
    // One child unit of the active decomposed think. False: blocked by the budget (nothing executed).
    bool Child() {
        const U at = FindPlanner(t.planner, t.tList, t.t, t.tHint);
        if (at == kNone) { ++c.thinksDropped; t.tActive = 0; return true; }
        if (at != t.tHint) { ++c.relocated; t.tHint = at; }
        const U live = D(t.t + 0x48), array = D(t.t + 0x4C);
        const bool snapshot = t.childCount != kNone;
        if (t.childIndex >= (snapshot ? t.childCount : live)) { t.tActive = 0; return true; }
        U child = 0;
        if (snapshot) {
            child = t.children[t.childIndex];
            const U found = Find(array, live, child, t.childIndex);
            if (found == kNone) { ++c.childSkipped; ++t.childIndex; return true; }
            if (found != t.childIndex) ++c.relocated;
        } else child = D(array + 4 * t.childIndex);
        if (!(D(child + 0x40) + D(child + 0x30))) { ++t.childIndex; return true; }
        if (!budget) return false;
        Call(KChild, D(D(child) + 0x28), child);
        Spend();
        ++t.childIndex;
        return true;
    }

    bool Go() {
        for (;;) {
            U count = 0;
            switch (t.phase) {
            case PPassA:
            case PPassB: {
                const U node = PlannerNode(t.index, count);
                if (t.index >= count) { t.phase = t.phase == PPassA ? PPassB : PFlag; t.index = 0; break; }
                if (Member(node, t.index)) Call(t.phase == PPassA ? KPassA : KPassB, t.phase == PPassA ? n.passA : n.passB, node);
                ++t.index;
                break;
            }
            case PFlag:
                PlannerNode(0, count);
                if (!(t.flag & 0xFF)) t.phase = PRound1;
                else if (D(D(D(D(t.planner) + 8) + 0x64) + 0x80) == 1 || !count) t.phase = PDone;
                else { t.phase = PFull; t.index = 0; }
                break;
            case PFull: {
                if (t.tActive) { if (!Child()) return false; break; }
                const U node = PlannerNode(t.index, count);
                if (t.index >= count) { t.phase = PDone; break; }
                if (!Member(node, t.index)) { ++t.index; break; }
                if (!budget) return false;
                StartThink(node, 1, t.index);
                ++t.index;
                break;
            }
            case PRound1: {
                const U live = D(t.planner + 0x9C);
                if (!live) { t.phase = PRound2; break; }
                if (!budget) return false;
                Put(t.planner + 0xB8, D(t.planner + 0xB8) + 1);
                const U index = D(t.planner + 0xB8) % live;
                t.phase = PRound1Think;
                StartThink(D(D(t.planner + 0xA0) + 4 * index), 1, index);
                break;
            }
            case PRound1Think:
                if (t.tActive) { if (!Child()) return false; } else t.phase = PRound2;
                break;
            case PRound2: {
                const U live = D(t.planner + 0xB0);
                if (!live) { t.phase = PDone; break; }
                const U index = D(t.planner + 0xB8) % live, node = D(D(t.planner + 0xB4) + 4 * index);
                if (!node) { t.phase = PDone; break; }
                if (!budget) return false;
                t.phase = PRound2Think;
                StartThink(node, 2, index);
                break;
            }
            case PRound2Think:
                if (t.tActive) { if (!Child()) return false; } else t.phase = PDone;
                break;
            default:
                t.phase = PDone;
                return true;
            }
        }
    }
};
}

void Begin(Think& t, U planner, U flag, Counters& counters) {
    t.planner = planner; t.flag = flag; t.phase = PPassA; t.index = 0;
    t.tActive = t.t = t.tList = t.tHint = t.childIndex = t.childCount = 0;
    const U count = D(planner + 0x9C), array = D(planner + 0xA0);
    if (count > kMaxNodes) { t.nodeCount = kNone; ++counters.overflows; return; } // live index mode
    t.nodeCount = count;
    for (U i = 0; i < count; ++i) t.nodes[i] = D(array + 4 * i);
}

bool Step(Think& t, const Natives& natives, U& budget, Counters& counters, int64_t qpcFreq) {
    if (t.phase == PIdle || t.phase == PDone) return true;
    Run run{t, natives, budget, counters, qpcFreq};
    return run.Go();
}
}
