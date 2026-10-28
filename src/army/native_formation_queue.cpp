// Exact port of the formation command queue walk 0x581E80 (native_formation_queue.h). Every native memory access keeps the order,
// width and count of the original; the loop state lives in locals exactly like the original's registers (EDI = index, EBX = saved
// command, EBP = entry cursor), so nothing Q-resident is cached across a callback.
#include "native_formation_queue.h"
#include <intrin.h>
#include <windows.h>

static_assert(sizeof(void*) == 4, "native formation queue port requires x86");

namespace kntwr_formation_queue {
namespace {
constexpr U kEntries = 0x400, kEntryStride = 8;           // Q: inline {command, size} entries
constexpr U kCount = 0x440, kIterating = 0x450, kDirty = 0x451, kIndex = 0x454;
constexpr U kCommandErase = 0xC, kCommandProgress = 0x10; // command: byte erase request, dword progress counter

template <class T> volatile T& At(U address) { return *reinterpret_cast<volatile T*>(static_cast<uintptr_t>(address)); }

// ECX = command, EDX = vtable, no stack argument, plain ret; EAX unused by the walk.
using Callback = U(__fastcall*)(void* command, void* vtable);

inline void Dispatch(U command, U vtable, U slot, const Probe* probe) {
    const Callback callback = reinterpret_cast<Callback>(static_cast<uintptr_t>(At<U>(vtable + slot)));
    void* const self = reinterpret_cast<void*>(static_cast<uintptr_t>(command));
    void* const table = reinterpret_cast<void*>(static_cast<uintptr_t>(vtable));
    if (!probe) {
        callback(self, table);
        return;
    }
    // The frame identity is taken in the frame that owns both hooks, so begin and end of one callback always agree even when
    // this function is inlined into Run (the address then simply belongs to Run's frame; nested walks are deeper).
    const U frame = static_cast<U>(reinterpret_cast<uintptr_t>(_AddressOfReturnAddress()));
    Callback target = callback;
    bool routed = false;
    if (probe->routePrivate && static_cast<U>(reinterpret_cast<uintptr_t>(callback)) == probe->routeNative &&
        probe->begin(vtable, slot, frame)) {
        target = reinterpret_cast<Callback>(static_cast<uintptr_t>(probe->routePrivate));
        routed = true;
    }
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    target(self, table);
    QueryPerformanceCounter(&t1);
    probe->end(vtable, slot, static_cast<unsigned long long>(t1.QuadPart - t0.QuadPart), routed, frame);
}
} // namespace

void Run(void* queue, EraseFn erase, const Probe* probe) {
    const U q = static_cast<U>(reinterpret_cast<uintptr_t>(queue));
    At<uint16_t>(q + kIterating) = 1;                       // 581E86: iterating = 1, dirty = 0 (one word store)
    if (At<U>(q + kCount) != 0) {                           // 581E8F: unsigned count <= 0
        U i = 0, entry = q + kEntries;
        do {
            if (At<uint8_t>(q + kIterating) != 1) break;    // 581EA3
            const U count = At<U>(q + kCount);
            At<U>(q + kIndex) = i;
            const U command = At<U>(entry);                 // saved across the callback (EBX)
            const U vtable = At<U>(command);
            if (i == count - 1) {
                Dispatch(command, vtable, kSlotLast, probe);
                if (At<uint8_t>(q + kDirty) != 0) At<uint8_t>(q + kIterating) = 0;
                At<U>(command + kCommandProgress) = At<U>(command + kCommandProgress) + 1;
                if (At<uint8_t>(command + kCommandErase) == 1) erase(queue, nullptr, i);
            } else {
                Dispatch(command, vtable, kSlotOther, probe);
                if (At<uint8_t>(q + kDirty) != 0) At<uint8_t>(q + kIterating) = 0;
            }
            ++i;
            At<U>(q + kIndex) = 0xFFFFFFFFu;
            entry += kEntryStride;
        } while (i < At<U>(q + kCount));                    // 581F0B: count re-read
    }
    At<uint8_t>(q + kIterating) = 1;                        // 581F16 / 581F20
}
} // namespace kntwr_formation_queue
