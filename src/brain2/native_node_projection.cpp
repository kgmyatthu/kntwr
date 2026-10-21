#include <windows.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include "native_node_projection.h"

static_assert(sizeof(void*) == 4, "native node projection is a Win32 x86 adapter");

namespace kntwr_node {
namespace projection {
namespace {

using Free = void (__cdecl*)(void*);

constexpr uint32_t kPreferredBase = 0x400000;
constexpr uint32_t kHeapFree = 0xFF7EF0;
constexpr uint32_t kDescriptorBuilder = 0x7FCFF0;
// Preferred-base images of the original statics (all BSS in the pinned executable, i.e. zero-constructed):
//   15ADB74 ring {capacity,data,count,read,write}  15ADB88 ring guard  15ADB90 bitset[0x2000]
//   15AFB90 id vector {tag,capacity,count,data}    15AFBA0 id guard
//   14D0A6C lookup vector {tag,capacity,count,data}  14D0A7C lookup guard
constexpr uint32_t kVisitWords = 0x2030 / 4;
constexpr uint32_t kRingCount = (0x15ADB7C - 0x15ADB74) / 4;
constexpr uint32_t kRingData = (0x15ADB78 - 0x15ADB74) / 4;
constexpr uint32_t kRingGuard = (0x15ADB88 - 0x15ADB74) / 4;
constexpr uint32_t kIdCount = (0x15AFB98 - 0x15ADB74) / 4;
constexpr uint32_t kIdData = (0x15AFB9C - 0x15ADB74) / 4;
constexpr uint32_t kIdGuard = (0x15AFBA0 - 0x15ADB74) / 4;
constexpr uint32_t kLookupData = 3, kLookupGuard = 4;
constexpr uint32_t kGuardInitialised = 0xFFFFFFFFu; // never read by the warm clones

// The original bases are 4 and 12 modulo 16; the private images keep that congruence so every interior operand keeps the
// alignment it has natively (bitset 16-aligned, vector headers 4-aligned).
struct alignas(16) Participant {
    uint32_t pre;
    uint32_t visit[kVisitWords];   // image of 15ADB74..15AFBA3
    uint32_t mid[2];
    uint32_t lookup[5];            // image of 14D0A6C..14D0A7F
};
static_assert(sizeof(Participant) % 16 == 0, "participants must tile at 16 bytes");
static_assert(offsetof(Participant, visit) == 4, "visit image must be 4 mod 16");
static_assert(offsetof(Participant, visit) + 0x1C == 0x20, "bitset must be 16-aligned");
static_assert(offsetof(Participant, lookup) % 16 == 12, "lookup image must be 12 mod 16");
static_assert(kVisitWords * 4 == 0x15AFBA4 - 0x15ADB74, "visit image covers 15ADB74..15AFBA3");
static_assert(kIdGuard == kVisitWords - 1, "id guard is the last visit word");
static_assert(KNTWR_BIND_NODE_PROJ_LOOKUP_0 == KNTWR_BIND_NODE_PROJ_VISIT_0 + KNTWR_NODE_PROJ_PARTICIPANTS,
              "binding order: VISIT_0..8 then LOOKUP_0..8");
static_assert(KNTWR_CLONE_NODE_PROJ_67A790_8 == KNTWR_CLONE_NODE_PROJ_7FD070_0 + 4 * KNTWR_NODE_PROJ_PARTICIPANTS - 1,
              "clone order: four contiguous clones per participant");

Participant* g_participants;
uint32_t g_imageBase;
uint32_t g_codeBegin, g_codeEnd;
__declspec(thread) bool g_certifying;
__declspec(thread) uint32_t g_refusedTarget;
constexpr DWORD kCallbackRefusal = 0xE04E5052u;
uint32_t Native(uint32_t va) { return g_imageBase + va - kPreferredBase; }
template<class T> T Read(uint32_t address) {
    T result; memcpy(&result, reinterpret_cast<const void*>(address), sizeof(result)); return result;
}
// Exact store-free single-instruction leaf certificates, followed by RET.
// Inspect only mapped .text. Never infer purity from a vtable position alone.
bool LeafValue(uint32_t target, uint32_t receiver, uint32_t& value, bool byteResult) {
    if (target < g_codeBegin || target > g_codeEnd - 8) return false;
    const auto* code = reinterpret_cast<const unsigned char*>(target);
    if ((code[0] == 0x33 || code[0] == 0x31) && code[1] == 0xC0 && code[2] == 0xC3) {
        value = 0; return true;
    }
    if (code[0] == 0xB8 && code[5] == 0xC3) { value = Read<uint32_t>(target + 1); return true; }
    if (code[0] == 0x8B && code[1] == 0xC1 && code[2] == 0xC3) { value = receiver; return true; }
    if (byteResult && code[0] == 0x32 && code[1] == 0xC0 && code[2] == 0xC3) {
        value = 0; return true;
    }
    if (byteResult && code[0] == 0xB0 && code[2] == 0xC3) { value = code[1]; return true; }
    const bool dword = code[0] == 0x8B, address = code[0] == 0x8D;
    const bool byte = byteResult && code[0] == 0x8A;
    if (!dword && !address && !byte) return false;
    uint32_t field;
    if (code[1] == 0x01 && code[2] == 0xC3) field = receiver;
    else if (code[1] == 0x41 && code[3] == 0xC3)
        field = receiver + static_cast<int8_t>(code[2]);
    else if (code[1] == 0x81 && code[6] == 0xC3) field = receiver + Read<uint32_t>(target + 2);
    else return false;
    value = address ? field : byte ? Read<unsigned char>(field) : Read<uint32_t>(field);
    return true;
}
[[noreturn]] void Refuse(uint32_t target) {
    g_refusedTarget = target;
    RaiseException(kCallbackRefusal, 0, 0, nullptr);
    __assume(0);
}
void CertifyBoolean(uint32_t receiver, uint32_t slot, unsigned depth = 0) {
    const uint32_t target = Read<uint32_t>(Read<uint32_t>(receiver) + slot);
    uint32_t value;
    if (LeafValue(target, receiver, value, true)) return;
    // Cell's embedded reader: optional surface vt+18, then its embedded
    // reader at +1C, otherwise the cell's own byte +4. No native writes.
    if (target == Native(0x7FF170) && depth < 16) {
        const uint32_t surface = Read<uint32_t>(receiver + 0x18);
        if (!surface) return;
        const uint32_t getter = Read<uint32_t>(Read<uint32_t>(surface) + 0x18);
        if (!LeafValue(getter, surface, value, false)) Refuse(getter);
        if (!value) CertifyBoolean(surface + 0x1C, 0, depth + 1);
        return;
    }
    Refuse(target);
}
unsigned char __fastcall CheckedCell(uint32_t receiver, uint32_t) {
    if (g_certifying) CertifyBoolean(receiver, 0);
    using Call = unsigned char (__thiscall*)(uint32_t);
    return reinterpret_cast<Call>(Read<uint32_t>(Read<uint32_t>(receiver)))(receiver);
}
unsigned char __fastcall CheckedEdge(uint32_t receiver, uint32_t) {
    if (g_certifying) CertifyBoolean(receiver, 0x14);
    using Call = unsigned char (__thiscall*)(uint32_t);
    return reinterpret_cast<Call>(Read<uint32_t>(Read<uint32_t>(receiver) + 0x14))(receiver);
}
uint32_t __fastcall CheckedDescriptor(uint32_t output, uint32_t, const float* xyz, uint32_t surface) {
    if (g_certifying && surface) {
        const uint32_t target = Read<uint32_t>(Read<uint32_t>(surface) + 0x10);
        uint32_t value;
        if (!LeafValue(target, surface, value, false)) Refuse(target);
    }
    using Call = uint32_t (__thiscall*)(uint32_t, const float*, uint32_t);
    return reinterpret_cast<Call>(Native(0x7EAD80))(output, xyz, surface);
}

uint32_t Address(const void* p) { return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p)); }

void FreeData(uint32_t* slot) {
    // The registered destructors run the pinned RET element destructor over each element, then free the backing array.
    const uint32_t data = *slot;
    if (data) reinterpret_cast<Free>(static_cast<uintptr_t>(g_imageBase - kPreferredBase + kHeapFree))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(data)));
    *slot = 0;
}

} // namespace

bool Initialize(uint32_t imageBase, uint32_t* bindings) {
    if (!bindings || !imageBase || (imageBase & 0xFFFFu)) return false;
    if (g_participants) {
        if (g_imageBase != imageBase) return false;
    } else {
        void* block = _aligned_malloc(sizeof(Participant) * kParticipants, 16);
        if (!block) return false;
        memset(block, 0, sizeof(Participant) * kParticipants);
        g_participants = static_cast<Participant*>(block);
        g_imageBase = imageBase;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(imageBase);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(imageBase + dos->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; ++s)
            if (!memcmp(sections[s].Name, ".text", 5)) {
                g_codeBegin = imageBase + sections[s].VirtualAddress;
                g_codeEnd = g_codeBegin + sections[s].Misc.VirtualSize;
            }
        for (unsigned p = 0; p < kParticipants; ++p) {
            g_participants[p].visit[kRingGuard] = kGuardInitialised;
            g_participants[p].visit[kIdGuard] = kGuardInitialised;
            g_participants[p].lookup[kLookupGuard] = kGuardInitialised;
        }
    }
    for (unsigned p = 0; p < kParticipants; ++p) {
        bindings[KNTWR_BIND_NODE_PROJ_VISIT_0 + p] = Address(&g_participants[p].visit[0]);
        bindings[KNTWR_BIND_NODE_PROJ_LOOKUP_0 + p] = Address(&g_participants[p].lookup[0]);
    }
    bindings[KNTWR_BIND_NODE_PROJ_CELL] = Address(reinterpret_cast<const void*>(&CheckedCell));
    bindings[KNTWR_BIND_NODE_PROJ_EDGE] = Address(reinterpret_cast<const void*>(&CheckedEdge));
    bindings[KNTWR_BIND_NODE_PROJ_DESCRIPTOR] = Address(reinterpret_cast<const void*>(&CheckedDescriptor));
    return true;
}

void Release() {
    if (!g_participants) return;
    for (unsigned p = 0; p < kParticipants; ++p) {
        FreeData(&g_participants[p].visit[kRingData]);
        FreeData(&g_participants[p].visit[kIdData]);
        FreeData(&g_participants[p].lookup[kLookupData]);
    }
    _aligned_free(g_participants);
    g_participants = nullptr;
    g_imageBase = 0;
}

uint32_t Entry(const uint32_t* cloneEntries, unsigned participant) {
    if (!g_participants || !cloneEntries || participant >= kParticipants) return 0;
    return cloneEntries[KNTWR_CLONE_NODE_PROJ_7FD070_0 + 4 * participant];
}

bool Ready(unsigned participant) {
    if (!g_participants || participant >= kParticipants) return false;
    const Participant& p = g_participants[participant];
    return p.visit[kRingCount] == 0 && p.visit[kIdCount] == 0;
}
bool ProjectCertified(const uint32_t* entries, uint32_t query, uint32_t* output,
                      const float* planar, const uint32_t* reference, uint32_t mode,
                      uint32_t* refusedTarget, unsigned participant) {
    if (refusedTarget) *refusedTarget = 0;
    const uint32_t entry = Entry(entries, participant);
    if (!entry || !query || !Ready(participant) || g_certifying) return false;
    bool complete = false;
    g_refusedTarget = 0; g_certifying = true;
    __try {
        __try {
            using Call = uint32_t (__thiscall*)(uint32_t, uint32_t*, const float*, const uint32_t*, uint32_t, uint32_t);
            reinterpret_cast<Call>(entry)(query, output, planar, reference, mode, 0);
            complete = true;
        } __except (GetExceptionCode() == kCallbackRefusal ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            Participant& p = g_participants[participant];
            p.visit[kRingCount] = 0; p.visit[3] = p.visit[4];
            memset(p.visit + 7, 0, 0x2000);
            p.visit[kIdCount] = 0; p.lookup[2] = 0;
        }
    } __finally {
        g_certifying = false;
    }
    if (refusedTarget && g_refusedTarget) *refusedTarget = g_refusedTarget - g_imageBase + kPreferredBase;
    return complete;
}

uint32_t DescriptorEntry(uint32_t imageBase) {
    return imageBase ? imageBase - kPreferredBase + kDescriptorBuilder : 0;
}

} // namespace projection
} // namespace kntwr_node
