// NTW2_AI_CENSUS recorder: naked register-preserving gates, bounded caller table, sampler range counters. See the header.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "ntw2_ai_census.h"

namespace ntw2_ai_census {

const U kTargetOriginal[kTargets] = {0x6EA520, 0x6B3010, 0x44A780, 0x44A780, 0x69D710, 0x69D750, 0x7492F0};
// Vtable bases are the constructors' stored vptr values (0x13378F8/0x1337998/0x1337BB8/0x1337C30/0x1349C18 for the delegate
// replacement virtual at slot 19 and its sibling at slot 20); the observer and delegate-destructor tables are slot 0 as specified.
// Every word is verified against the live image by the runtime before it is swapped (SwapSlot pins the original exactly).
static const Pin kPins[kPinCount] = {
    {0x13378F8, 19, 0x6EA520, 0}, {0x1337998, 19, 0x6EA520, 0}, {0x1337BB8, 19, 0x6EA520, 0},
    {0x1337C30, 19, 0x6EA520, 0}, {0x1349C18, 19, 0x6EA520, 0},
    {0x1337BB8, 20, 0x6B3010, 1}, {0x1337C30, 20, 0x6B3010, 1}, {0x1349C18, 20, 0x6B3010, 1},
    {0x13432A0, 0, 0x44A780, 2}, {0x1343318, 0, 0x44A780, 3},
    {0x13376FC, 0, 0x69D710, 4}, {0x13376AC, 0, 0x69D750, 5},
};
const Pin* Pins() { return kPins; }
const U kRangeVa[kRanges] = {0x8254D0, 0x739670, 0x69A990};
const U kRangeEnd[kRanges] = {0x825670, 0x739689, 0x69A9F5};

namespace {
struct __declspec(align(8)) Entry {
    volatile LONGLONG key;   // ((target + 1) << 32) | return address; 0 = free
    volatile LONG count, cls[kClasses], site[kSiteCodes];
};
struct Target { volatile LONG total, cls[kClasses], dropped; };
struct Range { volatile U total, cls[kClasses]; };

Entry g_entries[kCallers];
Target g_targets[kTargets];
Range g_ranges[kRanges];
U g_original[kTargets];
volatile LONG g_on, g_used, g_calls, g_dropped, g_inTick, g_outsideTick, g_ticks;
volatile U g_sampleAttempts, g_sampleOutside;
U g_imageBase, g_imageSize, g_delta, g_main, g_controller, g_controllerSize;
volatile U *g_tickGate, *g_aiThread, *g_site;

Entry* Find(U target, U ret) {
    const LONGLONG key = (static_cast<LONGLONG>(target + 1) << 32) | ret;
    U at = ((ret >> 2) * 2654435761u + target * 0x9E3779B9u) >> 24; // 8 bits: kCallers == 256
    for (U probe = 0; probe < kCallers; ++probe, at = (at + 1) & (kCallers - 1)) {
        const LONGLONG prior = InterlockedCompareExchange64(&g_entries[at].key, key, 0);
        if (prior == 0) { InterlockedIncrement(&g_used); return &g_entries[at]; }
        if (prior == key) return &g_entries[at];
    }
    return nullptr;
}

// Called from a gate with every register and the flags saved. No allocation, no lock, no import beyond GetCurrentThreadId.
__declspec(noinline) void __cdecl Record(U target, U ret) {
    if (!g_on || target >= kTargets) return;
    const U tid = GetCurrentThreadId();
    const U tick = g_tickGate ? *g_tickGate : 0, ai = g_aiThread ? *g_aiThread : 0;
    const U cls = (tick && tid == tick) ? 0u : (ai && tid == ai) ? 1u : (g_main && tid == g_main) ? 2u : 3u;
    U code = 0;
    if (tick) {
        const U site = g_site ? *g_site : 0;
        code = site ? site + 1 : 1;
        if (code >= kSiteCodes) code = kSiteCodes - 1;
    }
    Target& t = g_targets[target];
    InterlockedIncrement(&t.total); InterlockedIncrement(&t.cls[cls]);
    InterlockedIncrement(&g_calls); InterlockedIncrement(tick ? &g_inTick : &g_outsideTick);
    Entry* e = Find(target, ret);
    if (!e) { InterlockedIncrement(&t.dropped); InterlockedIncrement(&g_dropped); return; }
    InterlockedIncrement(&e->count); InterlockedIncrement(&e->cls[cls]); InterlockedIncrement(&e->site[code]);
}

// Preserves EAX..EDI, EBP and EFLAGS and leaves the stack untouched: the original sees the caller's frame and return address.
#define NTW2_AI_CENSUS_GATE(name, k) \
    __declspec(naked) void name() { \
        __asm pushfd \
        __asm pushad \
        __asm push dword ptr [esp + 36] \
        __asm push k \
        __asm cld \
        __asm call Record \
        __asm add esp, 8 \
        __asm popad \
        __asm popfd \
        __asm jmp dword ptr [g_original + 4 * k] \
    }
NTW2_AI_CENSUS_GATE(Gate0, 0)
NTW2_AI_CENSUS_GATE(Gate1, 1)
NTW2_AI_CENSUS_GATE(Gate2, 2)
NTW2_AI_CENSUS_GATE(Gate3, 3)
NTW2_AI_CENSUS_GATE(Gate4, 4)
NTW2_AI_CENSUS_GATE(Gate5, 5)
NTW2_AI_CENSUS_GATE(Gate6, 6)
#undef NTW2_AI_CENSUS_GATE

U Kind(U ret, U& value) {
    if (ret - g_imageBase < g_imageSize) { value = ret - g_imageBase; return 0; }
    if (g_controller && ret - g_controller < g_controllerSize) { value = ret - g_controller; return 1; }
    value = ret; return 2;
}
}

U Gate(U target) {
    static void (*const gates[kTargets])() = {&Gate0, &Gate1, &Gate2, &Gate3, &Gate4, &Gate5, &Gate6};
    return target < kTargets ? static_cast<U>(reinterpret_cast<uintptr_t>(gates[target])) : 0;
}

void Reset(bool enabled, U imageBase, U imageSize, U delta, U mainThread, volatile U* tickGate, volatile U* aiThread,
           volatile U* site) {
    InterlockedExchange(&g_on, 0);
    memset(g_entries, 0, sizeof(g_entries)); memset(g_targets, 0, sizeof(g_targets)); memset(g_ranges, 0, sizeof(g_ranges));
    g_used = g_calls = g_dropped = g_inTick = g_outsideTick = g_ticks = 0;
    g_sampleAttempts = g_sampleOutside = 0;
    g_controller = g_controllerSize = 0;
    g_imageBase = imageBase; g_imageSize = imageSize; g_delta = delta; g_main = mainThread;
    g_tickGate = tickGate; g_aiThread = aiThread; g_site = site;
    for (U i = 0; i < kTargets; ++i) g_original[i] = kTargetOriginal[i] + delta;
    if (enabled) InterlockedExchange(&g_on, 1);
}

void SetController(U entry, U size) { g_controller = entry; g_controllerSize = size; }

void Tick() { if (g_on) InterlockedIncrement(&g_ticks); }
U OwnerCalls() {
    U sum = 0;
    for (U t = 0; t < kTargets; ++t) sum += static_cast<U>(g_targets[t].cls[0]);
    return sum;
}

void Sample(U eip, U cls) {
    if (!g_on) return;
    ++g_sampleAttempts;
    for (U i = 0; i < kRanges; ++i)
        if (eip - (kRangeVa[i] + g_delta) < kRangeEnd[i] - kRangeVa[i]) {
            ++g_ranges[i].total; ++g_ranges[i].cls[cls < kClasses ? cls : kClasses - 1];
            return;
        }
    ++g_sampleOutside;
}

void Snapshot(volatile U* words, U slotsOwned) {
    for (U i = 0; i < kWords; ++i) words[i] = 0;
    if (!g_on) return;
    U slotsPerTarget[kTargets] = {};
    for (U i = 0; i < kPinCount; ++i) ++slotsPerTarget[kPins[i].target];
    words[HVersion] = kVersion; words[HTargets] = kTargets; words[HCallerCapacity] = kCallers; words[HTop] = kTop;
    words[HCallersUsed] = static_cast<U>(g_used); words[HCalls] = static_cast<U>(g_calls);
    words[HCallersDropped] = static_cast<U>(g_dropped); words[HSlotsOwned] = slotsOwned; words[HSlotCount] = kPinCount;
    words[HRanges] = kRanges; words[HSampleAttempts] = g_sampleAttempts; words[HSampleOutside] = g_sampleOutside;
    words[HTicks] = static_cast<U>(g_ticks); words[HCallsInTick] = static_cast<U>(g_inTick);
    words[HCallsOutsideTick] = static_cast<U>(g_outsideTick);
    for (U t = 0; t < kTargets; ++t) {
        volatile U* row = words + kHeaderWords + t * kTargetWords;
        row[TOriginal] = kTargetOriginal[t]; row[TSlots] = slotsPerTarget[t]; row[TTotal] = static_cast<U>(g_targets[t].total);
        for (U c = 0; c < kClasses; ++c) row[TClass0 + c] = static_cast<U>(g_targets[t].cls[c]);
        row[TDropped] = static_cast<U>(g_targets[t].dropped);
        U top[kTop], topCount[kTop], n = 0;
        for (U e = 0; e < kCallers; ++e) {
            const LONGLONG key = InterlockedCompareExchange64(&g_entries[e].key, 0, 0);
            if (static_cast<U>(key >> 32) != t + 1) continue;
            const U count = static_cast<U>(g_entries[e].count);
            if (n == kTop && count <= topCount[kTop - 1]) continue;
            U at = n < kTop ? n++ : kTop - 1;
            for (; at && count > topCount[at - 1]; --at) { top[at] = top[at - 1]; topCount[at] = topCount[at - 1]; }
            top[at] = e; topCount[at] = count;
        }
        for (U r = 0; r < n; ++r) {
            const Entry& e = g_entries[top[r]];
            volatile U* out = row + kTargetHeaderWords + r * kCallerWords;
            U value = 0;
            const U kind = Kind(static_cast<U>(InterlockedCompareExchange64(&const_cast<Entry&>(e).key, 0, 0)), value);
            out[CCaller] = value; out[CKind] = kind; out[CCount] = topCount[r];
            for (U c = 0; c < kClasses; ++c) out[CClass0 + c] = static_cast<U>(e.cls[c]);
            U best = 0, second = 0, bestCount = 0, secondCount = 0;
            for (U s = 0; s < kSiteCodes; ++s) {
                const U count = static_cast<U>(e.site[s]);
                if (!count) continue;
                if (count > bestCount) { second = best; secondCount = bestCount; best = s; bestCount = count; }
                else if (count > secondCount) { second = s; secondCount = count; }
            }
            out[CTopSite] = best; out[CTopSiteCount] = bestCount; out[COutside] = static_cast<U>(e.site[0]);
            out[CSecondSite] = second; out[CSecondSiteCount] = secondCount;
        }
    }
    for (U r = 0; r < kRanges; ++r) {
        volatile U* out = words + kHeaderWords + kTargets * kTargetWords + r * kRangeWords;
        out[0] = kRangeVa[r]; out[1] = kRangeEnd[r]; out[2] = g_ranges[r].total;
        for (U c = 0; c < kClasses; ++c) out[3 + c] = g_ranges[r].cls[c];
    }
}
}
