#include "native_finalizer.h"
#include <string.h>
#include <windows.h>

static_assert(sizeof(void*) == 4, "0x819770 is the pinned Win32 x86 original");
namespace ntw2_finalizer {
namespace {
U g_delta;
bool g_bound, g_shadow, g_shadowSticky;
U g_words[WordCount];
// Owner-only shadow copy; 819770 reaches no gated service, so it never nests.
alignas(16) uint8_t g_copy[kReceiverBytes];
U g_shadowReceiver;
inline U V(U va) { return va + g_delta; }
inline U D(U p) { return *reinterpret_cast<const U*>(p); }
inline uint8_t B(U p) { return *reinterpret_cast<const uint8_t*>(p); }
inline uint16_t W(U p) { return *reinterpret_cast<const uint16_t*>(p); }
inline void Mix(U& h, U value) {
    for (U i = 0; i < 4; ++i) { h ^= (value >> (8 * i)) & 0xFF; h *= 16777619u; }
}
inline U Detail(Refusal r) { return kDetailBase + r; }
} // namespace

void Bind(U imageBase) { g_delta = imageBase - 0x400000; g_bound = imageBase != 0; }

// Posture-FSM tables are accepted by content: every slot the closure reaches must hold a recovered target
// (native_finalizer.h, analysis/native-brain-unknowns.md §18). The 13 state singletons carry their image vtables
// (stride 0x14: next, enter, update, exit).
constexpr U kStates = 13, kStateFirst = 0x1454168, kStateRest = 0x1454198, kStateTables = 0x1346994;
constexpr U kGetters[kStates] = {0x5D6F60, 0x5D7000, 0x5D6FD0, 0x5D7060, 0x5D6FC0, 0x5D6F70, 0x5D6F80,
                                 0x5D7020, 0x5D7050, 0x5D7070, 0x5D7080, 0x5D7010, 0x5D6FB0};
bool PostureTable(U table) {
    // .rdata (vtables are never heap objects): the slot reads below are image reads.
    if (table < V(0x1307000) || table + 0x54 > V(0x1307000) + 0x146236) return false;
    if (D(table + 4) != V(0x5562A0) || D(table + 8) != V(0x5D66E0)) return false;
    for (U i = 0; i < kStates; ++i) if (D(table + 0xC + 4 * i) != V(kGetters[i])) return false;
    // +0x40/+0x48/+0x4C: the base selectors (0x66B7E0 / 0x462E90 / 0x5EE210) or the 0x132BBC0 reach family
    // (0x5FB920 / 0x5F8190 / 0x5EE220, analysis/native-brain-unknowns.md §19.1): own-field store R+0xE8 and the
    // reach float [[[[S]+0x1C]+0x44]+0x14] (kAnimReach).
    const U select = D(table + 0x40), select2 = D(table + 0x44), probe = D(table + 0x48), extent = D(table + 0x4C);
    return (select == V(0x66B7E0) || select == V(0x462E90) || select == V(0x5FB920)) &&
           (select2 == V(0x66B990) || select2 == V(0x47BA10)) && (probe == V(0x462E90) || probe == V(0x5F8190)) &&
           (extent == V(0x5EE210) || extent == V(0x5EE220)) && D(table + 0x50) == V(0x447880);
}
// The table reaches the animation set: 66B7E0 (directly or through 5FB920), 66B990, or the reach float readers.
bool ReadsSet(U table) {
    return D(table + 0x40) == V(0x66B7E0) || D(table + 0x40) == V(0x5FB920) || D(table + 0x44) == V(0x66B990) ||
           D(table + 0x48) == V(0x5F8190) || D(table + 0x4C) == V(0x5EE220);
}
bool ReadsReach(U table) {
    return D(table + 0x40) == V(0x5FB920) || D(table + 0x48) == V(0x5F8190) || D(table + 0x4C) == V(0x5EE220);
}
U PostureClosure(U r, U* detail) {
    U why = 0;
    Refusal result = Closed;
    if (const U state = D(r + 0xF8)) {
        const U table = D(r + 0xF4);
        if (!g_bound || !PostureTable(table)) { result = FsmTable; why = table; }
        else if (state - V(kStateFirst) > V(kStateRest) - V(kStateFirst) || (state - V(kStateFirst)) % 4) {
            result = FsmState; why = state;
        } else {
            for (U i = 0; i < kStates; ++i)
                if (D(V(kStateFirst) + 4 * i) != V(kStateTables) + 0x14 * i) { result = FsmState; why = state; break; }
        }
    }
    if (detail) *detail = result == Closed ? 0 : why ? why : Detail(result);
    return result;
}
// Callers reach these only after PostureClosure accepted the table (or with a null state, which short-circuits).
bool PostureAnimates(U r) {
    const U state = D(r + 0xF8);
    return state && state != V(kStateRest) && ReadsSet(D(r + 0xF4));
}
U AnimKey(U r) {
    U key = kNoAnimIndex;
    if (B(r + 0x458) == 1) {
        key = D(r + 0x1BC);
        if (key >= kAnimEntries) return ~0u;
    }
    if (static_cast<int32_t>(D(r + 0x1D8)) <= 3) key |= kAnimSelects;
    if (D(r + 0xF8) && ReadsReach(D(r + 0xF4))) key |= kAnimReach;
    return key;
}

U FinalizeClosure(U r, U* detail) {
    U why = 0;
    U result = Closed;
    if (!g_bound) result = World;
    else if (D(r + 0x18)) result = Attached;
    else if (D(r + 0x10)) result = Surface;
    else if (D(D(r) + 0x84) != V(0x659220)) { result = Heading; why = D(D(r) + 0x84); }
    else result = PostureClosure(r, &why);
    if (result == Closed) {
        const U root = D(r + 0x28), model = root ? D(root + 8) : 0;
        if (!model || !D(model + 0x9C) || !D(model + 0xA0)) result = World;
    }
    if (detail) *detail = result == Closed ? 0 : why && why < kDetailBase ? why : Detail(static_cast<Refusal>(result));
    return result;
}

bool TerrainHash(U root, U& hash) {
    if (!g_bound || !root) return false;
    const U model = D(root + 8);
    if (!model) return false;
    const U grid = D(model + 0xA0), field = D(model + 0x9C);
    if (!grid) return false;
    U h = 2166136261u;
    Mix(h, model); Mix(h, D(model + 0x58));
    for (U o = 0x84; o < 0x94; o += 4) Mix(h, D(model + o));
    Mix(h, grid); Mix(h, field);
    for (U o = 0; o < 0x28; o += 4) Mix(h, D(grid + o));
    if (field) for (U o = 0; o < 0x28; o += 4) Mix(h, D(field + o));
    Mix(h, B(V(0x150FBA4))); Mix(h, D(V(0x150FCA0))); Mix(h, D(V(0x150FCA4)));
    hash = h;
    return true;
}

U FrameHash(U frame) {
    U h = 2166136261u;
    Mix(h, frame);
    for (U o = 0x80; o < 0x8C; o += 4) Mix(h, D(frame + o));
    for (U o = 0x9C; o < 0xC0; o += 4) Mix(h, D(frame + o));
    Mix(h, W(frame + 0x1E4));
    return h;
}
U TransformHash(U frame) {
    U h = 2166136261u;
    Mix(h, frame);
    for (U o = 0x80; o < 0x8C; o += 4) Mix(h, D(frame + o));
    for (U o = 0x9C; o < 0xC0; o += 4) Mix(h, D(frame + o));
    return h;
}

namespace {
// 0x6616C0 (+4AC..+4F4) and 0x6618D0 (+50C..+584, +7C4..+83C): the database row-count words they test.
constexpr U kRowWords[] = {0x4AC, 0x4C4, 0x4DC, 0x4F4, 0x50C, 0x524, 0x53C, 0x554, 0x56C, 0x584,
                           0x7C4, 0x7DC, 0x7F4, 0x80C, 0x824, 0x83C};
// 0x7F1730 entry (null falls back to T[0], hashed separately), then 0x817CA0/0x7F16C0's [E+4]+0x44 chain.
void MixEntry(U& h, U table, U index) {
    const U entry = D(table + 4 * index);
    Mix(h, entry);
    if (!entry) return;
    const U animation = D(entry + 4);
    Mix(h, animation);
    if (!animation) return;
    const U data = D(animation + 0x44);
    Mix(h, data);
    if (!data) return;
    Mix(h, D(data + 0x4C)); Mix(h, D(data + 0x70));
}
} // namespace

bool AnimHash(U set, U key, U& hash) {
    const U index = key & 0xFFFF;
    if (!g_bound || !set || (key & ~(kAnimSelects | kAnimReach | 0xFFFF)) || (index != kNoAnimIndex && index >= kAnimEntries)) return false;
    const U database = D(set);
    const U rows = database ? D(database + 0x2C) : 0, table = D(set + 0x10);
    if (!rows || !table) return false;
    U h = 2166136261u;
    Mix(h, set); Mix(h, database); Mix(h, rows); Mix(h, table); Mix(h, key);
    for (U o : kRowWords) Mix(h, D(rows + o));
    MixEntry(h, table, 0);
    if (key & kAnimSelects) for (U i = 0x2F; i <= 0x34; ++i) MixEntry(h, table, i);
    if (index != kNoAnimIndex) MixEntry(h, table, index);
    if (key & kAnimReach) {
        // 0x10F1200 on [[S]+0x1C]: [+0x44]+0xC, then the float at +8 (0x5FB920, 0x5F8190, 0x5EE220).
        const U holder = D(database + 0x1C), block = holder ? D(holder + 0x44) : 0;
        if (!block) return false;
        Mix(h, holder); Mix(h, block); Mix(h, D(block + 0x14));
    }
    hash = h;
    return true;
}

void Configure(bool shadow) { g_shadow = shadow; g_shadowSticky = false; g_shadowReceiver = 0; }
bool ShadowEnabled() { return g_shadow && g_bound && !g_shadowSticky; }
void Reset() { memset(g_words, 0, sizeof(g_words)); g_shadowReceiver = 0; g_shadowSticky = false; }
U Counter(Word word) { return word < WordCount ? g_words[word] : 0; }

namespace {
bool RunCopy() {
    __try {
        reinterpret_cast<void (__thiscall*)(void*)>(V(0x819770))(g_copy);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Owner thread only. The receiver's kReceiverBytes may extend past the end of the soldier's committed
// region (page-edge records): prove the range committed+readable before copying so no access violation
// is raised (the crash recorder reports even handled faults). Unprovable ranges skip the shadow.
bool ReceiverReadable(U receiver) {
    const U last = receiver + kReceiverBytes;
    if (!receiver || last < receiver) return false;
    for (U at = receiver; at < last;) {
        MEMORY_BASIC_INFORMATION m;
        if (!::VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(at)), &m, sizeof(m))) return false;
        if (m.State != MEM_COMMIT || (m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) || (m.Protect & 0xFF) == 0) return false;
        at = static_cast<U>(reinterpret_cast<uintptr_t>(m.BaseAddress)) + static_cast<U>(m.RegionSize);
    }
    return true;
}
} // namespace

void ShadowBefore(U receiver) {
    g_shadowReceiver = 0;
    if (!ShadowEnabled()) return;
    if (!ReceiverReadable(receiver)) { ++g_words[ShadowSkippedUnreadable]; return; }
    memcpy(g_copy, reinterpret_cast<const void*>(receiver), kReceiverBytes);
    if (!RunCopy()) { ++g_words[ShadowFaults]; g_shadowSticky = true; return; }
    g_shadowReceiver = receiver;
}

void ShadowAfter() {
    const U receiver = g_shadowReceiver;
    if (!receiver) return;
    g_shadowReceiver = 0;
    ++g_words[ShadowCalls];
    const uint8_t* live = reinterpret_cast<const uint8_t*>(receiver);
    for (U i = 0; i < kReceiverBytes; ++i) {
        if (live[i] == g_copy[i]) continue;
        if (!g_words[ShadowMismatches]) g_words[ShadowFirstOffset] = i;
        ++g_words[ShadowMismatches];
        return;
    }
}
} // namespace ntw2_finalizer
