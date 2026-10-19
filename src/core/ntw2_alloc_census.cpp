// Process-heap allocation callsite census (--alloc-census) and leak fix (--alloc-fix).
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>
#include "core/ntw2_alloc_census.h"
#include "ntw2_guard.h"

namespace ntw2_alloc_census {

namespace {

struct AllocResult {
    U ptr;
    U owner;
};

using ProviderAllocFn = AllocResult* (__fastcall *)(void* self, void* edx, AllocResult* out, U size);
using ProviderFreeFn = U (__fastcall *)(void* self, void* edx, U ptr);

struct PtrSlot {
    volatile LONG ptr; // 0 = empty, 1 = tombstone, 2 = busy, >= 8 = live pointer
    volatile U meta;   // (callsite_id << 19) | encoded_size
};
static_assert(sizeof(PtrSlot) == 8, "PtrSlot must be 8 bytes (32 MiB for 4M slots)");

struct __declspec(align(32)) CallsiteEntry {
    volatile LONGLONG key; // ((uint64_t(size_class) + 1u) << 32) | callsite_va; 0 = unused
    volatile LONG live_bytes;
    volatile LONG live_count;
    volatile LONG allocs;
    volatile LONG frees;
    volatile LONG peak_live_bytes;
    volatile LONG caller2_va;
};
static_assert(sizeof(CallsiteEntry) == 32, "CallsiteEntry must be 32 bytes (256 KiB for 8K slots)");

struct ThreadSlot {
    volatile LONG teb;
    volatile LONG depth;
};

constexpr U kPtrBytes = sizeof(PtrSlot) * kPtrCapacity;
constexpr U kCallsiteBytes = sizeof(CallsiteEntry) * kCallsiteCapacity;
constexpr U kTotalStorageBytes = kPtrBytes + kCallsiteBytes;
constexpr U kMaxPtrProbe = 128u;
constexpr U kMaxCallsiteProbe = 64u;
constexpr U kThreadSlots = 512u;
constexpr ULONGLONG kSampleIntervalMs = 10000ull;

void* g_storage = nullptr;
PtrSlot* g_ptrs = nullptr;
CallsiteEntry* g_callsites = nullptr;
ThreadSlot g_threads[kThreadSlots] = {};

volatile LONG g_enabled = 0;
volatile LONG g_mode = kModeOff;
volatile LONG g_callsiteUsed = 0;
volatile LONG g_overflowCount = 0;
volatile LONG g_hookFaults = 0;
volatile LONG g_untrackedFrees = 0;
volatile LONG g_reentrantSkips = 0;
volatile LONG g_fixFreedBlocks = 0;
volatile LONG g_fixFreedBytes = 0;
volatile LONG g_fixActiveSites = 0;
volatile LONG g_omittedThreads = 0;
U g_imageBase = 0;
U g_imageSize = 0;
U g_delta = 0;
U g_textBegin = 0;
U g_textEnd = 0;
U g_retFF7F20 = 0;
const ntw2_clone_set* g_clones = nullptr;
U g_cloneBase = 0;
U g_cloneBytes = 0;

ProviderAllocFn g_originalAlloc = nullptr;
ProviderFreeFn g_originalFree = nullptr;

ULONGLONG g_nextSampleTick = 0;
U g_samples = 0;
U g_baselineBytes = 0;
bool g_hasBaseline = false;
U g_peakLiveBytes = 0;
U g_snapshot[NTW2_ALLOC_CENSUS_WORDS] = {};
bool g_hasSnapshot = false;

__forceinline LONG Load(volatile LONG* p) {
    return _InterlockedCompareExchange(p, 0, 0);
}

__forceinline U SizeClass(U size) {
    if (size <= 1u) return 0u;
    unsigned long idx = 0;
    _BitScanReverse(&idx, size);
    return static_cast<U>(idx);
}

// 19-bit size encoding:
//   0x00000..0x3FFFF (< 256 KiB): exact 1-byte resolution
//   0x40000..0x6FFFF (256 KiB .. 1.5 MiB): 8-byte resolution (exact for 0xF4248 and 0x100008)
//   0x70000..0x7FFFF (>= 1.5 MiB .. 64 MiB): 1 KiB resolution
__forceinline U EncodeSize(U size) {
    if (size < 0x40000u) return size;
    const U qwords = size >> 3;
    if (qwords < 0x30000u) return 0x40000u + qwords;
    U kb = size >> 10;
    if (kb > 0xFFFFu) kb = 0xFFFFu;
    return 0x70000u | kb;
}

__forceinline U DecodeSize(U encoded) {
    if (encoded < 0x40000u) return encoded;
    if (encoded < 0x70000u) return (encoded - 0x40000u) << 3;
    return (encoded & 0xFFFFu) << 10;
}

__forceinline U HashPtr(U ptr) {
    U h = ptr >> 3;
    h ^= h >> 16;
    h *= 0x85EBCA6Bu;
    h ^= h >> 13;
    h *= 0xC2B2AE35u;
    h ^= h >> 16;
    return h;
}

__forceinline ThreadSlot* FindThreadSlot(U teb) {
    if (teb < 8u) return nullptr;
    U idx = ((teb >> 12) * 2654435761u) & (kThreadSlots - 1u);
    U firstTombstone = UINT32_MAX;
    for (U probe = 0; probe < kThreadSlots; ++probe, idx = (idx + 1u) & (kThreadSlots - 1u)) {
        const LONG cur = Load(&g_threads[idx].teb);
        if (static_cast<U>(cur) == teb) return &g_threads[idx];
        if (cur == 1) {
            if (firstTombstone == UINT32_MAX) firstTombstone = idx;
            continue;
        }
        if (cur == 0) {
            if (firstTombstone != UINT32_MAX) {
                if (_InterlockedCompareExchange(&g_threads[firstTombstone].teb, static_cast<LONG>(teb), 1) == 1) {
                    return &g_threads[firstTombstone];
                }
            }
            const LONG prev = _InterlockedCompareExchange(&g_threads[idx].teb, static_cast<LONG>(teb), 0);
            if (prev == 0 || static_cast<U>(prev) == teb) return &g_threads[idx];
            if (prev == 1 && firstTombstone == UINT32_MAX) firstTombstone = idx;
        }
    }
    if (firstTombstone != UINT32_MAX) {
        if (_InterlockedCompareExchange(&g_threads[firstTombstone].teb, static_cast<LONG>(teb), 1) == 1) {
            return &g_threads[firstTombstone];
        }
    }
    _InterlockedIncrement(&g_omittedThreads);
    return nullptr;
}

// Fast check for whether an instruction address inside Napoleon.exe .text is a 0-frame
// allocator wrapper (`add esp, 8; ret` = 83 C4 08 C3 or `add esp, 8; ret 4` = 83 C4 08 C2 04 00).
__forceinline bool IsWrapperRet(U va) {
    if (va < g_textBegin || va + 6u > g_textEnd) return false;
    const U w = *reinterpret_cast<const U*>(va);
    return w == 0xC308C483u || w == 0xC208C483u;
}

__forceinline bool IsAllocatorInternalPreferred(U pref) {
    return (pref >= 0x00FF7B00u && pref < 0x00FF8980u) ||
           (pref >= 0x010D3140u && pref < 0x010D3190u);
}

// Validates that `address` (inside .text) is immediately preceded by a CALL instruction.
__forceinline bool FollowsCallFast(U address) {
    if (address < g_textBegin + 8u || address >= g_textEnd) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(address);
    if (p[-5] == 0xE8u) {
        const int32_t rel = *reinterpret_cast<const int32_t*>(p - 4);
        const U target = static_cast<U>(static_cast<int32_t>(address) + rel);
        if (target >= g_textBegin && target < g_textEnd) return true;
    }
    if (p[-2] == 0xFFu) {
        const U m = p[-1];
        if ((m >= 0xD0u && m <= 0xD7u) || (m >= 0x10u && m <= 0x17u && m != 0x14u && m != 0x15u)) return true;
    }
    if (p[-3] == 0xFFu) {
        const U m = p[-2];
        if ((m >= 0x50u && m <= 0x57u && m != 0x54u) || (m == 0x14u && p[-1] == 0x24u)) return true;
    }
    if (p[-4] == 0xFFu && p[-3] == 0x54u && p[-2] == 0x24u) return true;
    if (p[-6] == 0xFFu) {
        const U m = p[-5];
        if (m == 0x15u || (m >= 0x90u && m <= 0x97u && m != 0x94u)) return true;
    }
    if (p[-7] == 0xFFu && p[-6] == 0x94u && p[-5] == 0x24u) return true;
    return false;
}

__forceinline void CaptureCallsiteFast(const U* sp, U ret0, U& outCallsiteVa, U& outNextScanIdx) {
    outCallsiteVa = ret0 - g_delta;
    outNextScanIdx = 0u;
    const U stackBase = __readfsdword(0x04);
    const U stackLimit = __readfsdword(0x08);
    const uintptr_t spAddr = reinterpret_cast<uintptr_t>(sp);
    if (spAddr < stackLimit || spAddr + 24u > stackBase) return;

    U startIdx = 0u;
    if (ret0 == g_retFF7F20 && spAddr + 36u <= stackBase) {
        const U callerFF7F20 = sp[5];
        startIdx = IsWrapperRet(callerFF7F20) ? 8u : 5u;
    }
    if (reinterpret_cast<uintptr_t>(&sp[startIdx + 1]) <= stackBase) {
        const U w0 = sp[startIdx];
        if (w0 >= g_textBegin && w0 < g_textEnd) {
            outCallsiteVa = w0 - g_delta;
            outNextScanIdx = startIdx + 1u;
            return;
        }
        if (g_cloneBase && w0 - g_cloneBase < g_cloneBytes) {
            const U origin = ntw2_clone_origin(g_clones, w0, nullptr);
            if (origin) {
                outCallsiteVa = origin;
                outNextScanIdx = startIdx + 1u;
                return;
            }
        }
    }
    const U maxIdx = startIdx + 24u;
    for (U i = startIdx; i < maxIdx; ++i) {
        if (reinterpret_cast<uintptr_t>(&sp[i + 1]) > stackBase) break;
        const U w = sp[i];
        if (w >= g_textBegin && w < g_textEnd && FollowsCallFast(w)) {
            outCallsiteVa = w - g_delta;
            outNextScanIdx = i + 1u;
            return;
        }
        if (g_cloneBase && w - g_cloneBase < g_cloneBytes) {
            const U origin = ntw2_clone_origin(g_clones, w, nullptr);
            if (origin) {
                outCallsiteVa = origin;
                outNextScanIdx = i + 1u;
                return;
            }
        }
    }
}

__forceinline U CaptureCaller2Slow(const U* sp, U nextScanIdx) {
    if (!nextScanIdx) return 0u;
    const U stackBase = __readfsdword(0x04);
    const U maxIdx = nextScanIdx + 28u;
    for (U i = nextScanIdx; i < maxIdx; ++i) {
        if (reinterpret_cast<uintptr_t>(&sp[i + 1]) > stackBase) break;
        const U w = sp[i];
        if (w >= g_textBegin && w < g_textEnd) {
            if (!FollowsCallFast(w)) continue;
            const U pref = w - g_delta;
            if (IsAllocatorInternalPreferred(pref) || IsWrapperRet(w)) continue;
            return pref;
        }
        if (g_cloneBase && w - g_cloneBase < g_cloneBytes) {
            const U origin = ntw2_clone_origin(g_clones, w, nullptr);
            if (origin) return origin;
        }
    }
    return 0u;
}

__forceinline U FindOrInsertCallsite(U callsiteVa, U sizeClass, const U* sp, U nextScanIdx) {
    const U keyHi = sizeClass + 1u;
    const LONGLONG key = (static_cast<LONGLONG>(keyHi) << 32) | static_cast<LONGLONG>(callsiteVa);
    U idx = (((callsiteVa * 2654435761u) >> 19) ^ (sizeClass * 4099u)) & kCallsiteMask;
    for (U probe = 0; probe < kMaxCallsiteProbe; ++probe, idx = (idx + 1u) & kCallsiteMask) {
        CallsiteEntry& e = g_callsites[idx];
        const volatile U* keyWords = reinterpret_cast<const volatile U*>(&e.key);
        const U lo = keyWords[0];
        const U hi = keyWords[1];
        if (lo == callsiteVa && hi == keyHi) {
            if (!e.caller2_va && nextScanIdx) {
                const U c2 = CaptureCaller2Slow(sp, nextScanIdx);
                if (c2) e.caller2_va = static_cast<LONG>(c2);
            }
            return idx;
        }
        if (lo == 0 && hi == 0) {
            const LONGLONG prev = _InterlockedCompareExchange64(&e.key, key, 0);
            if (prev == 0) {
                _InterlockedIncrement(&g_callsiteUsed);
                const U c2 = CaptureCaller2Slow(sp, nextScanIdx);
                if (c2) e.caller2_va = static_cast<LONG>(c2);
                return idx;
            }
            if (prev == key) return idx;
        }
    }
    return UINT32_MAX;
}

__forceinline bool InsertPtr(U ptr, U meta) {
    const U base = HashPtr(ptr);
    for (U probe = 0; probe < kMaxPtrProbe; ++probe) {
        const U idx = (base + ((probe * (probe + 1u)) >> 1)) & kPtrMask;
        const LONG cur = g_ptrs[idx].ptr;
        if (cur == 0 || cur == 1) {
            if (_InterlockedCompareExchange(&g_ptrs[idx].ptr, 2, cur) == cur) {
                g_ptrs[idx].meta = meta;
                _ReadWriteBarrier();
                g_ptrs[idx].ptr = static_cast<LONG>(ptr);
                return true;
            }
        }
    }
    return false;
}

__forceinline bool RemovePtr(U ptr, U& outMeta) {
    const U base = HashPtr(ptr);
    for (U probe = 0; probe < kMaxPtrProbe; ++probe) {
        const U idx = (base + ((probe * (probe + 1u)) >> 1)) & kPtrMask;
        const LONG cur = g_ptrs[idx].ptr;
        if (cur == 0) return false;
        if (static_cast<U>(cur) == ptr) {
            if (_InterlockedCompareExchange(&g_ptrs[idx].ptr, 2, cur) == cur) {
                outMeta = g_ptrs[idx].meta;
                _ReadWriteBarrier();
                g_ptrs[idx].ptr = 1; // tombstone: preserves concurrent probe chains and is reusable by InsertPtr
                return true;
            }
        }
    }
    return false;
}

void RecordAllocLocked(U ptr, U rawSize, const U* sp, U ret0) {
    ++ntw2::probeDepth;
    __try {
        if (Load(&g_enabled) && g_ptrs && g_callsites) {
            U callsiteVa = 0, nextScanIdx = 0;
            CaptureCallsiteFast(sp, ret0, callsiteVa, nextScanIdx);
            const U sizeClass = SizeClass(rawSize);
            const U csId = FindOrInsertCallsite(callsiteVa, sizeClass, sp, nextScanIdx);
            if (csId == UINT32_MAX) {
                _InterlockedIncrement(&g_overflowCount);
            } else {
                const U encSize = EncodeSize(rawSize);
                const U trackedSize = DecodeSize(encSize);
                const U meta = (csId << 19) | encSize;
                if (!InsertPtr(ptr, meta)) {
                    _InterlockedIncrement(&g_overflowCount);
                } else {
                    CallsiteEntry& cs = g_callsites[csId];
                    const LONG prevBytes = _InterlockedExchangeAdd(&cs.live_bytes, static_cast<LONG>(trackedSize));
                    const LONG newBytes = prevBytes + static_cast<LONG>(trackedSize);
                    LONG peak = cs.peak_live_bytes;
                    while (newBytes > peak) {
                        const LONG prevPeak = _InterlockedCompareExchange(&cs.peak_live_bytes, newBytes, peak);
                        if (prevPeak == peak) break;
                        peak = prevPeak;
                    }
                    _InterlockedIncrement(&cs.live_count);
                    _InterlockedIncrement(&cs.allocs);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _InterlockedIncrement(&g_hookFaults);
    }
    --ntw2::probeDepth;
}

void RecordFreeLocked(U ptr) {
    ++ntw2::probeDepth;
    __try {
        if (Load(&g_enabled) && g_ptrs && g_callsites) {
            U meta = 0;
            if (!RemovePtr(ptr, meta)) {
                _InterlockedIncrement(&g_untrackedFrees);
            } else {
                const U csId = meta >> 19;
                const U trackedSize = DecodeSize(meta & 0x7FFFFu);
                if (csId < kCallsiteCapacity) {
                    CallsiteEntry& cs = g_callsites[csId];
                    _InterlockedExchangeAdd(&cs.live_bytes, -static_cast<LONG>(trackedSize));
                    _InterlockedDecrement(&cs.live_count);
                    _InterlockedIncrement(&cs.frees);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _InterlockedIncrement(&g_hookFaults);
    }
    --ntw2::probeDepth;
}

// Restrict census tracking to Provider[3] (GetProcessHeap(), [self + 4] == 3).
// Provider[0] (0xFF8100) resizes blocks > 0x50 bytes via HeapReAlloc at 0xFF826E without
// going through the Provider vtable; excluding Provider[0..2] avoids stale resized pointers.
__forceinline bool IsProcessHeapProvider(const void* self) {
    return self && *reinterpret_cast<const U*>(static_cast<const uint8_t*>(self) + 4u) == 3u;
}

AllocResult* __fastcall AllocGate(void* self, void* edx, AllocResult* out, U size) {
    if (!Load(&g_enabled)) {
        return g_originalAlloc(self, edx, out, size);
    }
    const U* sp = reinterpret_cast<const U*>(_AddressOfReturnAddress());
    const U ret0 = sp[0];
    const U teb = __readfsdword(0x18);
    ThreadSlot* ts = FindThreadSlot(teb);
    if (!ts || _InterlockedCompareExchange(&ts->depth, 1, 0) != 0) {
        if (ts) _InterlockedIncrement(&g_reentrantSkips);
        return g_originalAlloc(self, edx, out, size);
    }
    AllocResult* res = nullptr;
    __try {
        res = g_originalAlloc(self, edx, out, size);
        if (Load(&g_enabled) && out && out->ptr >= 8u && IsProcessHeapProvider(self) &&
            IsProcessHeapProvider(reinterpret_cast<const void*>(static_cast<uintptr_t>(out->owner)))) {
            RecordAllocLocked(out->ptr, size, sp, ret0);
        }
    } __finally {
        _InterlockedExchange(&ts->depth, 0);
    }
    return res;
}

U __fastcall FreeGate(void* self, void* edx, U ptr) {
    if (!Load(&g_enabled)) {
        return g_originalFree(self, edx, ptr);
    }
    const U teb = __readfsdword(0x18);
    ThreadSlot* ts = FindThreadSlot(teb);
    if (!ts || _InterlockedCompareExchange(&ts->depth, 1, 0) != 0) {
        if (ts) _InterlockedIncrement(&g_reentrantSkips);
        return g_originalFree(self, edx, ptr);
    }
    U res = 0;
    __try {
        if (ptr >= 8u && IsProcessHeapProvider(self)) {
            RecordFreeLocked(ptr);
        }
        res = g_originalFree(self, edx, ptr);
    } __finally {
        _InterlockedExchange(&ts->depth, 0);
    }
    return res;
}

struct RowCandidate {
    U callsite_va;
    U size_class;
    U live_bytes;
    U live_count;
    U allocs;
    U frees;
    U peak_live_bytes;
    U caller2_va;
};

bool BetterCandidate(const RowCandidate& a, const RowCandidate& b) {
    if (a.live_bytes != b.live_bytes) return a.live_bytes > b.live_bytes;
    if (a.peak_live_bytes != b.peak_live_bytes) return a.peak_live_bytes > b.peak_live_bytes;
    if (a.allocs != b.allocs) return a.allocs > b.allocs;
    return a.callsite_va < b.callsite_va;
}

void BuildSnapshot(U slotsOwned) {
    U out[NTW2_ALLOC_CENSUS_WORDS] = {};
    const U mode = static_cast<U>(Load(&g_mode));
    out[HVersion] = kVersion;
    out[HEnabled] = static_cast<U>(Load(&g_enabled));
    out[HMode] = mode;
    out[HPtrCapacity] = kPtrCapacity;
    out[HCallsiteCapacity] = kCallsiteCapacity;
    out[HCallsiteUsed] = static_cast<U>(Load(&g_callsiteUsed));
    out[HOverflowCount] = static_cast<U>(Load(&g_overflowCount));
    out[HHookFaults] = static_cast<U>(Load(&g_hookFaults));
    out[HUntrackedFrees] = static_cast<U>(Load(&g_untrackedFrees));
    out[HReentrantSkips] = static_cast<U>(Load(&g_reentrantSkips));
    out[HFixFreedBlocks] = static_cast<U>(Load(&g_fixFreedBlocks));
    out[HFixFreedBytes] = static_cast<U>(Load(&g_fixFreedBytes));
    out[HFixActiveSites] = static_cast<U>(Load(&g_fixActiveSites));
    out[HStorageBytes] = g_storage ? kTotalStorageBytes : 0u;
    out[HSlotsOwned] = slotsOwned;
    out[HOmittedThreads] = static_cast<U>(Load(&g_omittedThreads));
    RowCandidate top[NTW2_ALLOC_CENSUS_ROWS] = {};
    U topCount = 0;
    uint64_t sumLiveBytes = 0;
    uint64_t sumLiveCount = 0;
    uint64_t sumAllocs = 0;
    uint64_t sumFrees = 0;

    if (g_callsites) {
        for (U i = 0; i < kCallsiteCapacity; ++i) {
            const CallsiteEntry& e = g_callsites[i];
            const volatile U* kw = reinterpret_cast<const volatile U*>(&e.key);
            const U callsiteVa = kw[0];
            const U keyHi = kw[1];
            if (!callsiteVa || !keyHi) continue;
            const LONG lb = e.live_bytes;
            const LONG lc = e.live_count;
            const U liveBytes = lb > 0 ? static_cast<U>(lb) : 0u;
            const U liveCount = lc > 0 ? static_cast<U>(lc) : 0u;
            const U allocs = static_cast<U>(e.allocs);
            const U frees = static_cast<U>(e.frees);
            const LONG pk = e.peak_live_bytes;
            const U peakBytes = pk > 0 ? static_cast<U>(pk) : liveBytes;
            const U caller2Va = static_cast<U>(e.caller2_va);

            sumLiveBytes += liveBytes;
            sumLiveCount += liveCount;
            sumAllocs += allocs;
            sumFrees += frees;

            RowCandidate cand = {callsiteVa, keyHi - 1u, liveBytes, liveCount, allocs, frees, peakBytes, caller2Va};
            if (topCount < NTW2_ALLOC_CENSUS_ROWS) {
                U pos = topCount++;
                while (pos > 0 && BetterCandidate(cand, top[pos - 1])) {
                    top[pos] = top[pos - 1];
                    --pos;
                }
                top[pos] = cand;
            } else if (BetterCandidate(cand, top[NTW2_ALLOC_CENSUS_ROWS - 1])) {
                U pos = NTW2_ALLOC_CENSUS_ROWS - 1;
                while (pos > 0 && BetterCandidate(cand, top[pos - 1])) {
                    top[pos] = top[pos - 1];
                    --pos;
                }
                top[pos] = cand;
            }
        }
    }

    const U liveBytes32 = sumLiveBytes > UINT32_MAX ? UINT32_MAX : static_cast<U>(sumLiveBytes);
    const U liveCount32 = sumLiveCount > UINT32_MAX ? UINT32_MAX : static_cast<U>(sumLiveCount);
    if (!g_hasBaseline && sumAllocs > 0) {
        g_baselineBytes = liveBytes32;
        g_hasBaseline = true;
    }
    if (liveBytes32 > g_peakLiveBytes) g_peakLiveBytes = liveBytes32;
    for (U i = 0; i < topCount; ++i) {
        if (top[i].peak_live_bytes > g_peakLiveBytes) g_peakLiveBytes = top[i].peak_live_bytes;
    }
    ++g_samples;
    out[HPtrUsed] = liveCount32;
    out[HLiveBytes] = liveBytes32;
    out[HLiveCount] = liveCount32;
    out[HBaselineBytes] = g_baselineBytes;
    out[HDriftBytes] = liveBytes32 >= g_baselineBytes ? (liveBytes32 - g_baselineBytes) : 0u;
    out[HPeakLiveBytes] = g_peakLiveBytes;
    out[HTotalAllocs] = static_cast<U>(sumAllocs);
    out[HTotalFrees] = static_cast<U>(sumFrees);
    out[HSamples] = g_samples;

    for (U i = 0; i < topCount; ++i) {
        U* row = out + NTW2_ALLOC_CENSUS_HEADER_WORDS + i * NTW2_ALLOC_CENSUS_ROW_WORDS;
        row[RCallsiteVa] = top[i].callsite_va;
        row[RSizeClass] = top[i].size_class;
        row[RLiveBytes] = top[i].live_bytes;
        row[RLiveCount] = top[i].live_count;
        row[RAllocs] = top[i].allocs;
        row[RFrees] = top[i].frees;
        row[RPeakLiveBytes] = top[i].peak_live_bytes;
        row[RReserved] = top[i].caller2_va;
    }

    memcpy(g_snapshot, out, sizeof(g_snapshot));
    g_hasSnapshot = true;
}

} // namespace

U RequiredStorageBytes(U mode) {
    return (mode & kModeCensus) ? kTotalStorageBytes : 0u;
}

U StorageBytes() {
    return g_storage ? kTotalStorageBytes : 0u;
}

U AllocGateAddress() {
    return static_cast<U>(reinterpret_cast<uintptr_t>(&AllocGate));
}

U FreeGateAddress() {
    return static_cast<U>(reinterpret_cast<uintptr_t>(&FreeGate));
}

void Configure(U imageBase, U imageSize, U delta, U mode) {
    g_imageBase = imageBase;
    g_imageSize = imageSize;
    g_delta = delta;
    g_textBegin = imageBase + 0x1000u;
    g_textEnd = imageBase + (imageSize > 0x00F068FCu ? 0x00F068FCu : imageSize);
    g_retFF7F20 = 0x00FF7F50u + delta;
    g_originalAlloc = reinterpret_cast<ProviderAllocFn>(static_cast<uintptr_t>(kProviderAllocOriginal + delta));
    g_originalFree = reinterpret_cast<ProviderFreeFn>(static_cast<uintptr_t>(kProviderFreeOriginal + delta));
    _InterlockedExchange(&g_mode, static_cast<LONG>(mode));
}

void Reset() {
    Stop();
    memset(g_threads, 0, sizeof(g_threads));
    _InterlockedExchange(&g_mode, kModeOff);
    _InterlockedExchange(&g_callsiteUsed, 0);
    _InterlockedExchange(&g_overflowCount, 0);
    _InterlockedExchange(&g_hookFaults, 0);
    _InterlockedExchange(&g_untrackedFrees, 0);
    _InterlockedExchange(&g_reentrantSkips, 0);
    _InterlockedExchange(&g_fixFreedBlocks, 0);
    _InterlockedExchange(&g_fixFreedBytes, 0);
    _InterlockedExchange(&g_fixActiveSites, 0);
    _InterlockedExchange(&g_omittedThreads, 0);
    g_nextSampleTick = 0;
    g_samples = 0;
    g_baselineBytes = 0;
    g_hasBaseline = false;
    g_peakLiveBytes = 0;
    memset(g_snapshot, 0, sizeof(g_snapshot));
    g_hasSnapshot = false;
}

bool Start(const Binding& binding) {
    Stop();
    Configure(binding.image_base, binding.image_size, binding.delta, binding.mode);
    g_clones = binding.clones;
    g_cloneBase = (g_clones && g_clones->allocation)
        ? static_cast<U>(reinterpret_cast<uintptr_t>(g_clones->allocation)) : 0u;
    g_cloneBytes = g_clones ? g_clones->allocation_bytes : 0u;

    if (binding.mode & kModeCensus) {
        void* mem = VirtualAlloc(nullptr, kTotalStorageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!mem) return false;
        g_storage = mem;
        g_ptrs = static_cast<PtrSlot*>(mem);
        g_callsites = reinterpret_cast<CallsiteEntry*>(static_cast<uint8_t*>(mem) + kPtrBytes);
    }
    memset(g_threads, 0, sizeof(g_threads));
    _InterlockedExchange(&g_callsiteUsed, 0);
    _InterlockedExchange(&g_overflowCount, 0);
    _InterlockedExchange(&g_hookFaults, 0);
    _InterlockedExchange(&g_untrackedFrees, 0);
    _InterlockedExchange(&g_reentrantSkips, 0);
    _InterlockedExchange(&g_fixFreedBlocks, 0);
    _InterlockedExchange(&g_fixFreedBytes, 0);
    _InterlockedExchange(&g_omittedThreads, 0);
    g_nextSampleTick = 0;
    g_samples = 0;
    g_baselineBytes = 0;
    g_hasBaseline = false;
    g_peakLiveBytes = 0;
    memset(g_snapshot, 0, sizeof(g_snapshot));
    g_hasSnapshot = false;

    _InterlockedExchange(&g_enabled, 1);
    BuildSnapshot((binding.mode & kModeCensus) ? kSlotCount : 0u);
    g_nextSampleTick = GetTickCount64() + kSampleIntervalMs;
    return true;
}

void Stop() {
    const LONG wasEnabled = _InterlockedExchange(&g_enabled, 0);
    if (wasEnabled) {
        if (g_storage) {
            for (U spin = 0; spin < 5000u; ++spin) {
                bool busy = false;
                for (U i = 0; i < kThreadSlots; ++i) {
                    if (Load(&g_threads[i].depth) != 0) { busy = true; break; }
                }
                if (!busy) break;
                Sleep(1);
            }
        }
        BuildSnapshot(0u);
        g_snapshot[HEnabled] = 1u;
        g_snapshot[HStorageBytes] = 0u;
    }
    if (g_storage) {
        VirtualFree(g_storage, 0, MEM_RELEASE);
        g_storage = nullptr;
        g_ptrs = nullptr;
        g_callsites = nullptr;
    }
}

void Snapshot(volatile U* words, U slotsOwned, bool force) {
    if (!words) return;
    if (!Load(&g_enabled)) {
        if (g_hasSnapshot) {
            for (U i = 0; i < NTW2_ALLOC_CENSUS_WORDS; ++i) words[i] = g_snapshot[i];
        } else {
            for (U i = 0; i < NTW2_ALLOC_CENSUS_WORDS; ++i) words[i] = 0;
        }
        return;
    }
    const ULONGLONG now = GetTickCount64();
    if (force || !g_hasSnapshot || now >= g_nextSampleTick) {
        BuildSnapshot(slotsOwned);
        g_nextSampleTick = now + kSampleIntervalMs;
    } else {
        g_snapshot[HSlotsOwned] = slotsOwned;
        g_snapshot[HFixFreedBlocks] = static_cast<U>(Load(&g_fixFreedBlocks));
        g_snapshot[HFixFreedBytes] = static_cast<U>(Load(&g_fixFreedBytes));
        g_snapshot[HFixActiveSites] = static_cast<U>(Load(&g_fixActiveSites));
    }
    for (U i = 0; i < NTW2_ALLOC_CENSUS_WORDS; ++i) words[i] = g_snapshot[i];
}

void RecordFixFreed(U blocks, U bytes, U siteBit) {
    _InterlockedExchangeAdd(&g_fixFreedBlocks, static_cast<LONG>(blocks));
    _InterlockedExchangeAdd(&g_fixFreedBytes, static_cast<LONG>(bytes));
    _InterlockedOr(&g_fixActiveSites, static_cast<LONG>(siteBit));
}

// Reclaims waypoint subnodes (`[node + 0x64]`) that `0x008021E0` (at `0x00802553`) and `0x0080ED40` (at `0x0080EEA0`)
// popped from `[pathfinder + 0x170]` (`0x70`-byte node pool, `0x007E1630`) and that `0x007FE270` (at `0x007FE2E3..0x007FE2EB`)
// pushed onto the dead freelist `[pathfinder + 0x17C]` (which no instruction in `Napoleon.exe` ever pops from).
// Splices the `[pathfinder + 0x17C]` freelist chain back onto `[pathfinder + 0x170]` on the tick owner thread.
void ReclaimTick(U model) {
    if (!(static_cast<U>(Load(&g_mode)) & kModeFix) || !model || model < 0x10000u) return;
    ++ntw2::probeDepth;
    __try {
        const U pf = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(model + 0xB4u));
        if (pf >= 0x10000u &&
            *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(pf + 0x178u)) == 0xC8u &&
            *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(pf + 0x184u)) == 0x3E8u) {
            const U deadHead = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(pf + 0x17Cu));
            if (deadHead >= 0x10000u) {
                U cur = deadHead;
                U tail = deadHead;
                U count = 0;
                constexpr U kMaxChain = 65536u;
                while (cur >= 0x10000u && count < kMaxChain) {
                    tail = cur;
                    ++count;
                    cur = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(cur));
                }
                if (cur == 0u && count > 0u) {
                    const U oldFreeHead = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(pf + 0x170u));
                    *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(tail)) = oldFreeHead;
                    *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(pf + 0x170u)) = deadHead;
                    *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(pf + 0x17Cu)) = 0u;
                    RecordFixFreed(count, count * 0x70u, 1u);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        _InterlockedIncrement(&g_hookFaults);
    }
    --ntw2::probeDepth;
}
void OnThreadDetach() {
    const U teb = __readfsdword(0x18);
    if (teb < 8u) return;
    U idx = ((teb >> 12) * 2654435761u) & (kThreadSlots - 1u);
    for (U probe = 0; probe < kThreadSlots; ++probe, idx = (idx + 1u) & (kThreadSlots - 1u)) {
        const LONG cur = Load(&g_threads[idx].teb);
        if (cur == 0) return;
        if (static_cast<U>(cur) == teb) {
            _InterlockedExchange(&g_threads[idx].depth, 0);
            _InterlockedCompareExchange(&g_threads[idx].teb, 1, cur);
            return;
        }
    }
}

U CurrentMode() {
    return static_cast<U>(Load(&g_mode));
}

} // namespace ntw2_alloc_census
