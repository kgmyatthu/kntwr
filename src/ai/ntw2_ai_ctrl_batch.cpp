// --ai-ctrl-* batch boundaries, histogram reuse and census. See ntw2_ai_ctrl_batch.h. Owner thread only.
#include <stdint.h>
#include <string.h>
#include "ntw2_ai_ctrl_batch.h"
#include "ntw2_clones.h"

static_assert(sizeof(void*) == 4, "Win32 native ABI");
using ntw2_ai_ctrl::U;
using namespace ntw2_ai_ctrl;

namespace {
AiCtrlBatch g_batch;
U g_flags, g_latched, g_histNative, g_scorerNative, g_scorerClone;
U g_words[kWords];
U g_batchScorer; // scorer calls inside the open batch (incremented by ScorerGate)
struct Cache { U epoch; bool valid; U out[7]; } g_cache;
void (*g_retire[4])(uint32_t);
U g_retireCount;
// Census: the first histogram call of a batch is the reference for its repeats.
constexpr U kBitsCap = 4096;
uint8_t g_firstBits[kBitsCap];
U g_firstCount, g_firstOut[7];
bool g_haveFirst;

inline U Live() { return g_flags & ~g_latched; }
inline U Addr(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
inline const uint8_t* Bytes(U a) { return reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(a)); }
inline U Load32(const uint8_t* p) { U v; memcpy(&v, p, 4); return v; }

typedef void (__fastcall *NativeHistogram)(U* out, U edx, U C, U filter);
inline void Native(U* out, U C, U filter) { reinterpret_cast<NativeHistogram>(static_cast<uintptr_t>(g_histNative))(out, 0, C, filter); }
inline bool Same(const U* a, const U* b) { return memcmp(a, b, 7 * sizeof(U)) == 0; }

// Units whose (B41, B44) byte pair differs from the batch's first histogram call.
U CountTransitions(U C) {
    const U count = Load32(Bytes(C) + 0xC);
    const uint8_t* list = Bytes(Load32(Bytes(C) + 0x10));
    const U n = count < g_firstCount ? count : g_firstCount;
    U changed = 0;
    for (U i = 0; i < n; ++i) {
        const uint8_t* u = Bytes(Load32(list + 4 * i));
        const uint8_t bits = static_cast<uint8_t>((u[0xB41] != 0) | ((u[0xB44] != 0) << 1));
        changed += bits != g_firstBits[i];
    }
    return changed;
}
void CensusFirst(U C, const U* out, U eligible) {
    const U count = Load32(Bytes(C) + 0xC);
    const uint8_t* list = Bytes(Load32(Bytes(C) + 0x10));
    g_firstCount = count < kBitsCap ? count : kBitsCap;
    for (U i = 0; i < g_firstCount; ++i) {
        const uint8_t* u = Bytes(Load32(list + 4 * i));
        g_firstBits[i] = static_cast<uint8_t>((u[0xB41] != 0) | ((u[0xB44] != 0) << 1));
    }
    memcpy(g_firstOut, out, sizeof(g_firstOut));
    g_haveFirst = true;
    ++g_words[WHistFirst];
    g_words[WEligible] += eligible;
}

void __fastcall HistogramGate(U* out, U, U C, U filter) {
    ++g_words[WHistCalls];
    const U live = Live();
    if (!g_batch.open || (filter & 0xFF) != 1 || C != Addr(g_batch.C) || !(live & (NTW2_AI_CTRL_CENSUS | NTW2_AI_CTRL_HISTOGRAM))) {
        ++g_words[WHistOutside];
        Native(out, C, filter);
        return;
    }
    U ref[7];
    if (live & NTW2_AI_CTRL_HISTOGRAM) {
        const bool serve = g_cache.valid && g_cache.epoch == g_batch.epoch;
        if (serve) {
            ++g_words[WHistServed];
            memcpy(out, g_cache.out, sizeof(g_cache.out));
        } else {
            U eligible = 0;
            ++g_words[WHistFirst];
            Histogram(C, filter, out, &eligible);
            g_words[WEligible] += eligible;
        }
        if (live & NTW2_AI_CTRL_VERIFY) {
            Native(ref, C, filter);
            if (!Same(ref, out)) { // native value wins; the feature latches off for the rest of the generation
                ++g_words[WHistMismatch];
                g_latched |= NTW2_AI_CTRL_HISTOGRAM;
                g_cache.valid = false;
                memcpy(out, ref, sizeof(ref));
                return;
            }
        }
        if (!serve) { memcpy(g_cache.out, out, sizeof(g_cache.out)); g_cache.epoch = g_batch.epoch; g_cache.valid = true; }
        return;
    }
    // Census: native executes; the port and the first call of the batch are only compared against it.
    U eligible = 0;
    Native(out, C, filter);
    Histogram(C, filter, ref, &eligible);
    if (!Same(ref, out)) ++g_words[WHistMismatch];
    if (!g_haveFirst) { CensusFirst(C, out, eligible); return; }
    if (!Same(out, g_firstOut)) ++g_words[WRepeatChanged];
    g_words[WTransitions] += CountTransitions(C);
}

// ECX = N, stack (U, C), RET 8. Exact scorer slot -> the scorer clone; anything else ends the batch (it is an unknown callback)
// and runs the native target. The rewritten call site keeps `lea eax,[ebx+68]; push eax; push esi`.
__declspec(naked) void ScorerGate() {
    __asm {
        mov eax, [ecx]
        mov eax, [eax + 0x18]
        cmp eax, dword ptr [g_scorerNative]
        jne foreign
        inc dword ptr [g_words + 4]   // WScorerCalls
        inc dword ptr [g_batchScorer]
        jmp dword ptr [g_scorerClone]
    foreign:
        push eax
        push ecx
        push 3                        // AI_CTRL_END_CALLBACK
        call ai_ctrl_batch_end
        add esp, 4
        pop ecx
        pop eax
        jmp eax
    }
}
// ECX = N, EBX = P (callee-saved by the native refresh). Ends the previous batch, runs the native refresh, begins the next.
__declspec(naked) void RefreshGate() {
    __asm {
        push ecx
        push 2                        // AI_CTRL_END_REFRESH
        call ai_ctrl_batch_end
        add esp, 4
        mov ecx, [esp]
        mov eax, [ecx]
        call dword ptr [eax + 0x30]
        lea eax, [ebx + 0x68]
        push eax                      // C
        push dword ptr [esp + 4]      // N
        push ebx                      // P
        call ai_ctrl_batch_begin
        add esp, 12
        add esp, 4
        ret
    }
}
// Inserted before `push ecx; mov ecx,eax; call 0x7CF3F0`: EAX/ECX/EDX/EFLAGS preserved.
__declspec(naked) void AssignGate() {
    __asm {
        pushfd
        push eax
        push ecx
        push edx
        push 1                        // AI_CTRL_END_ASSIGN
        call ai_ctrl_batch_end
        add esp, 4
        pop edx
        pop ecx
        pop eax
        popfd
        ret
    }
}
void __cdecl ExitGate() { ai_ctrl_batch_end(AI_CTRL_END_EXIT); }
}

static_assert(WScorerCalls == 1, "ScorerGate increments word 1");

const AiCtrlBatch* ai_ctrl_batch_current(void) { return &g_batch; }

void ai_ctrl_batch_begin(void* P, void* N, void* C) {
    if (g_batch.open) ai_ctrl_batch_end(AI_CTRL_END_REFRESH);
    ++g_batch.epoch;
    g_batch.P = P; g_batch.N = N; g_batch.C = C; g_batch.R = nullptr;
    g_batch.open = 1;
    g_cache.valid = false; g_haveFirst = false; g_batchScorer = 0;
    ++g_words[WBatches];
}

void ai_ctrl_batch_end(int reason) {
    if (!g_batch.open) return;
    switch (reason) {
    case AI_CTRL_END_ASSIGN: ++g_words[WEndAssign]; break;
    case AI_CTRL_END_REFRESH: ++g_words[WEndRefresh]; break;
    case AI_CTRL_END_CALLBACK: ++g_words[WEndCallback]; break;
    default: ++g_words[WEndExit]; break;
    }
    if (g_batchScorer > g_words[WMaxScorerBatch]) g_words[WMaxScorerBatch] = g_batchScorer;
    for (U i = 0; i < g_retireCount; ++i) g_retire[i](g_batch.epoch);
    g_batch.open = 0;
    ++g_batch.epoch;
    g_cache.valid = false; g_haveFirst = false;
}

void ai_ctrl_batch_register_retire(void (*fn)(uint32_t epoch)) {
    for (U i = 0; i < g_retireCount; ++i) if (g_retire[i] == fn) return;
    if (g_retireCount < sizeof(g_retire) / sizeof(g_retire[0])) g_retire[g_retireCount++] = fn;
}

void ai_ctrl_batch_set_region(void* R) { g_batch.R = R; }
uint32_t ai_ctrl_batch_flags(void) { return Live(); }

namespace ntw2_ai_ctrl {
void Histogram(U C, U filter, U out[7], U* eligible) {
    for (U i = 0; i < 7; ++i) out[i] = 0;
    const U count = Load32(Bytes(C) + 0xC);
    const uint8_t* list = Bytes(Load32(Bytes(C) + 0x10));
    const bool filtered = (filter & 0xFF) != 0;
    U kept = 0;
    for (U i = 0; i < count; ++i) {
        const uint8_t* u = Bytes(Load32(list + 4 * i));
        if (filtered && (!u[0xB41] || !u[0xB44])) continue;
        ++kept;
        const uint8_t* type = Bytes(Load32(u + 0x2C));
        const U cls = Load32(type + 0x1C), sub = Load32(type + 0x20);
        if (cls == 2) ++out[sub == 4 ? 1 : sub == 8 ? 2 : sub == 0xD ? 3 : 0];
        else if (cls == 0) ++out[sub == 4 ? 5 : sub == 8 ? 6 : 4];
    }
    if (eligible) *eligible = kept;
}

void Reset(U flags, U delta, U scorerClone) {
    g_batch = AiCtrlBatch();
    memset(g_words, 0, sizeof(g_words));
    memset(&g_cache, 0, sizeof(g_cache));
    g_retireCount = 0;
    for (auto& fn : g_retire) fn = nullptr;
    g_flags = flags; g_latched = 0;
    g_histNative = 0x749D90u + delta; g_scorerNative = 0x7B1270u + delta; g_scorerClone = scorerClone;
    g_haveFirst = false; g_firstCount = 0; g_batchScorer = 0;
}

bool Bind(U* bindings) {
    bindings[NTW2_BIND_AI_CTRL_REFRESH] = Addr(reinterpret_cast<const void*>(&RefreshGate));
    bindings[NTW2_BIND_AI_CTRL_SCORER] = Addr(reinterpret_cast<const void*>(&ScorerGate));
    bindings[NTW2_BIND_AI_CTRL_BATCH_ASSIGN] = Addr(reinterpret_cast<const void*>(&AssignGate));
    bindings[NTW2_BIND_AI_CTRL_BATCH_EXIT] = Addr(reinterpret_cast<const void*>(&ExitGate));
    bindings[NTW2_BIND_AI_CTRL_HISTOGRAM] = Addr(reinterpret_cast<const void*>(&HistogramGate));
    return true;
}

void Snapshot(volatile U* row) {
    for (U i = 0; i < kAWords; ++i) row[i] = g_words[i];
    row[WFlags] = g_flags | (g_latched << 8);
}
}
