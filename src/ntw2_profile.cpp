#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <wchar.h>
#include <algorithm>
#include "ntw2_runtime.h"
#include "ntw2_profile.h"
#include "ntw2_guard.h"
#include "ntw2_clones.h"
#include "ntw2_ai_census.h"

extern "C" {
extern volatile ntw2_status ntw2_state;
__declspec(dllexport) volatile ntw2_profile_status ntw2_profile = {
    NTW2_PROFILE_ABI, sizeof(ntw2_profile_status), NTW2_PROFILE_BUCKET_BYTES
};
}
volatile uint32_t* ntw2_profile_tick_gate;
volatile uint32_t* ntw2_profile_main_tick_gate;
volatile uint32_t ntw2_profile_storm_threshold_ms;
volatile uint32_t ntw2_profile_storm_admitted;
volatile uint32_t ntw2_profile_storm_rejected;
volatile uint32_t ntw2_grid_census_site;

namespace {
using U = uint32_t;
SRWLOCK sampleLock = SRWLOCK_INIT;
HANDLE sampler, stopEvent, timer;
HANDLE threads[NTW2_PROFILE_THREADS];
bool active;
U imageBase, imageSize, runtimeBase, runtimeSize, cloneBase, cloneSize, tbbBase, tbbSize;
U imageCodeBytes, runtimeCodeBytes, histogramBytes;
U waitStubs[6];
U* histogram;
U* tickHistogram;
U* framesHistogram;
U* mainHistograms[NTW2_PROFILE_MAIN_PHASES];
U* framesSeen;
ntw2_profile_runtime_header* runtimeProfile;
U* runtimeHistograms[NTW2_PROFILE_RUNTIME_HISTOGRAMS];
U frameBuckets[1024];
U frameChain[NTW2_PROFILE_CHAIN_DEPTH];
LARGE_INTEGER frequency;
__declspec(align(8)) volatile LONGLONG lastTickEnd;
__declspec(align(8)) volatile LONGLONG lastTickStart;
__declspec(align(8)) volatile LONGLONG stormEntry; // QPC when the selected site (18) was entered, set before its gate word
LONGLONG postTickWindow, startTickWindow;
U mainWaitHandles[MAXIMUM_WAIT_OBJECTS];
// Preallocated exact handle counts, not a misleading first-eight or approximate
// heavy-hitter counter. Overflow is explicit if an unusually diverse run fills it.
struct WaitCount { U handle, count; } waitCounts[4096];
struct PhaseWaitCount { U handle, kind, count; } mainWaitCounts[NTW2_PROFILE_MAIN_PHASES][4096];
struct ModuleRange { U base, size, kind; } modules[256];
U moduleCount;

bool InRange(U address, U base, U size) { return address >= base && address - base < size; }
U MainPhase() {
    // No retry/spin: the gate and boundary are observational near transitions.
    // Atomic 64-bit access prevents torn QPC reads on the 32-bit runtime.
    const LONGLONG ended = InterlockedCompareExchange64(&lastTickEnd, 0, 0);
    const bool during = ntw2_profile_main_tick_gate && *ntw2_profile_main_tick_gate;
    const LONGLONG started = during ? InterlockedCompareExchange64(&lastTickStart, 0, 0) : 0;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (during)
        return started && now.QuadPart >= started && now.QuadPart - started < startTickWindow
            ? NTW2_PROFILE_PHASE_A1 : NTW2_PROFILE_PHASE_A2;
    return ended && now.QuadPart >= ended && now.QuadPart - ended <= postTickWindow
        ? NTW2_PROFILE_PHASE_B : NTW2_PROFILE_PHASE_C;
}

U WaitKind(U eip) {
    for (U i = 0; i < 6; ++i)
        if (waitStubs[i] && InRange(eip, waitStubs[i], 16)) return i;
    return 6;
}

U ModuleSize(U base) {
    if (!base) return 0;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    return reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew)->OptionalHeader.SizeOfImage;
}
U ExecutableSpan(U base,U bytes) {
    const auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto nt=reinterpret_cast<const IMAGE_NT_HEADERS*>(base+dos->e_lfanew);
    const IMAGE_SECTION_HEADER* section=IMAGE_FIRST_SECTION(nt);
    U end=0;
    for(U i=0;i<nt->FileHeader.NumberOfSections;++i) {
        if (!(section[i].Characteristics&IMAGE_SCN_MEM_EXECUTE)) continue;
        const U size=(std::max)(section[i].Misc.VirtualSize,section[i].SizeOfRawData);
        if(section[i].VirtualAddress>bytes || size>bytes-section[i].VirtualAddress) return 0;
        end=(std::max)(end,static_cast<U>(section[i].VirtualAddress)+size);
    }
    return end;
}

U NamedModuleKind(const wchar_t* name) {
    if (!_wcsicmp(name, L"d3d9.dll")) return NTW2_PROFILE_MODULE_D3D9;
    if (!_wcsnicmp(name, L"nv", 2) || !_wcsnicmp(name, L"atiu", 4) || !_wcsnicmp(name, L"ig", 2))
        return NTW2_PROFILE_MODULE_DRIVER;
    if (!_wcsicmp(name, L"ntdll.dll")) return NTW2_PROFILE_MODULE_NTDLL;
    if (!_wcsicmp(name, L"kernel32.dll")) return NTW2_PROFILE_MODULE_KERNEL32;
    if (!_wcsicmp(name, L"tbb.dll")) return NTW2_PROFILE_MODULE_TBB;
    if (!_wcsnicmp(name, L"msvcr", 5)) return NTW2_PROFILE_MODULE_MSVCR;
    return NTW2_PROFILE_MODULE_OTHER;
}

void RefreshModules() {
    // Toolhelp/CRT/module-name work only between rounds, never under suspension.
    moduleCount = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        ntw2_profile.module_refresh_failed = ntw2_profile.module_refresh_failed + 1;
        return;
    }
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    BOOL more = Module32FirstW(snapshot, &entry);
    if (!more) ntw2_profile.module_refresh_failed = ntw2_profile.module_refresh_failed + 1;
    for (; more; more = Module32NextW(snapshot, &entry)) {
        const U kind = NamedModuleKind(entry.szModule);
        if (kind == NTW2_PROFILE_MODULE_OTHER) continue;
        if (moduleCount == sizeof(modules) / sizeof(modules[0])) {
            ntw2_profile.module_omitted = ntw2_profile.module_omitted + 1;
            continue;
        }
        ModuleRange& range = modules[moduleCount++];
        range.base = static_cast<U>(reinterpret_cast<uintptr_t>(entry.modBaseAddr));
        range.size = entry.modBaseSize;
        range.kind = kind;
    }
    CloseHandle(snapshot);
}

U MainModule(U eip) {
    if (InRange(eip, imageBase, imageSize)) return NTW2_PROFILE_MODULE_IMAGE;
    if (InRange(eip, runtimeBase, runtimeSize) || InRange(eip, cloneBase, cloneSize))
        return NTW2_PROFILE_MODULE_NTW2;
    for (U i = 0; i < moduleCount; ++i)
        if (InRange(eip, modules[i].base, modules[i].size)) return modules[i].kind;
    return NTW2_PROFILE_MODULE_OTHER;
}

void SetThread(U slot, HANDLE handle, U id) {
    if (threads[slot]) CloseHandle(threads[slot]);
    if (ntw2_profile.thread_id[slot])
        ntw2_profile.thread_replaced = ntw2_profile.thread_replaced + 1;
    threads[slot] = handle;
    ntw2_profile.thread_id[slot] = id;
    ntw2_profile.thread_samples[slot] = 0;
    ntw2_profile.in_image[slot] = ntw2_profile.in_wait[slot] = ntw2_profile.in_tbb[slot] = 0;
}

void RefreshThreads() {
    for (U i = 0; i < NTW2_PROFILE_THREADS; ++i) {
        DWORD exitCode;
        if (threads[i] && (!GetExitCodeThread(threads[i], &exitCode) || exitCode != STILL_ACTIVE)) {
            CloseHandle(threads[i]);
            threads[i] = nullptr; // Preserve the row until its slot is needed.
        }
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        ntw2_profile.enumeration_failed = ntw2_profile.enumeration_failed + 1;
        return;
    }
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    BOOL more = Thread32First(snapshot, &entry);
    if (!more) ntw2_profile.enumeration_failed = ntw2_profile.enumeration_failed + 1;
    const DWORD pid = GetCurrentProcessId();
    for (; more; more = Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == GetCurrentThreadId()) continue;
        U freeSlot = NTW2_PROFILE_THREADS;
        bool found = false;
        for (U i = 0; i < NTW2_PROFILE_THREADS; ++i) {
            if (threads[i] && ntw2_profile.thread_id[i] == entry.th32ThreadID) { found = true; break; }
            if (!threads[i] && freeSlot == NTW2_PROFILE_THREADS) freeSlot = i;
        }
        if (found) continue;
        if (freeSlot == NTW2_PROFILE_THREADS) {
            ntw2_profile.thread_limit = ntw2_profile.thread_limit + 1;
            continue;
        }
        HANDLE handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                   FALSE, entry.th32ThreadID);
        if (!handle) continue; // A thread may exit between snapshot and open.
        if (GetProcessIdOfThread(handle) != pid) { CloseHandle(handle); continue; }
        SetThread(freeSlot, handle, entry.th32ThreadID);
    }
    CloseHandle(snapshot);
    // Retain the module while reading its PE header, never while a thread is suspended.
    HMODULE tbb;
    if (GetModuleHandleExW(0, L"tbb.dll", &tbb)) {
        tbbBase = static_cast<U>(reinterpret_cast<uintptr_t>(tbb));
        tbbSize = ModuleSize(tbbBase);
        FreeLibrary(tbb);
    } else { tbbBase = tbbSize = 0; }
}

bool ReadWords(U address, U* values, U count) {
    if (!count || count > MAXIMUM_WAIT_OBJECTS || address > UINT32_MAX - count * sizeof(U)) return false;
    MEMORY_BASIC_INFORMATION memory;
    // Do not consume a stack-growth guard page while observing a suspended thread.
    if (!VirtualQuery(reinterpret_cast<void*>(address), &memory, sizeof(memory)) ||
        memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(memory.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        static_cast<uintptr_t>(address) + count * sizeof(U) > reinterpret_cast<uintptr_t>(memory.BaseAddress) + memory.RegionSize)
        return false;
    __try {
        for (U i = 0; i < count; ++i) values[i] = reinterpret_cast<const volatile U*>(address)[i];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool ReadWaitHandle(U esp, U& value) {
    return esp <= UINT32_MAX - 8 && ReadWords(esp + 4, &value, 1);
}

bool ReadMainWaitHandles(U esp, U kind, U& count) {
    if (kind != 1) {
        count = 1; // Single-object and both keyed-event stubs take HANDLE first.
        return ReadWaitHandle(esp, mainWaitHandles[0]);
    }
    U args[2];
    if (esp > UINT32_MAX - 12 || !ReadWords(esp + 4, args, 2) ||
        !args[0] || args[0] > MAXIMUM_WAIT_OBJECTS) return false;
    count = args[0];
    return ReadWords(args[1], mainWaitHandles, count);
}

bool FollowsCall(U address, U base = imageBase) {
    const U offset = address - base;
    const auto p = reinterpret_cast<const volatile unsigned char*>(address);
    // Only inspect bytes inside the caller-validated module range.
    __try {
        if (offset >= 5 && p[-5] == 0xe8) return true;
        if (offset >= 2 && p[-2] == 0xff) {
            const U modrm = p[-1];
            if (modrm >= 0xd0 && modrm <= 0xd7) return true;
            // [esp] needs a SIB byte; mod=00/rm=5 needs an absolute address.
            if (modrm >= 0x10 && modrm <= 0x17 && modrm != 0x14 && modrm != 0x15) return true;
        }
        if (offset >= 3 && p[-3] == 0xff) {
            const U modrm = p[-2];
            if (modrm >= 0x50 && modrm <= 0x57 && modrm != 0x54) return true;
            if (modrm == 0x14 && p[-1] == 0x24) return true;
        }
        if (offset >= 4 && p[-4] == 0xff && p[-3] == 0x54 && p[-2] == 0x24) return true;
        if (offset >= 6 && p[-6] == 0xff) {
            const U modrm = p[-5];
            if (modrm == 0x15 || (modrm >= 0x90 && modrm <= 0x97 && modrm != 0x94)) return true;
        }
        return offset >= 7 && p[-7] == 0xff && p[-6] == 0x94 && p[-5] == 0x24;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

U ReadFrameBuckets(U esp, U& chainLength) {
    MEMORY_BASIC_INFORMATION memory;
    if (!VirtualQuery(reinterpret_cast<void*>(esp), &memory, sizeof(memory)) ||
        memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(memory.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return 0;
    // Subtract before adding so even a region ending at 4 GiB cannot wrap.
    const SIZE_T available = memory.RegionSize - (esp - reinterpret_cast<uintptr_t>(memory.BaseAddress));
    const U words = available < sizeof(frameBuckets) ? static_cast<U>(available / sizeof(U)) : 1024;
    U count = 0;
    __try {
        const auto stack = reinterpret_cast<const volatile U*>(esp);
        for (U i = 0; i < words; ++i) {
            const U address = stack[i];
            if (!InRange(address, imageBase, imageCodeBytes)) continue;
            const U bucket = (address - imageBase) / NTW2_PROFILE_BUCKET_BYTES;
            const U bit = 1u << (bucket & 31);
            const bool seen = (framesSeen[bucket / 32] & bit) != 0;
            if ((seen && chainLength == NTW2_PROFILE_CHAIN_DEPTH) || !FollowsCall(address)) continue;
            // Preserve stack-word order, exact addresses and repeated frames.
            if (chainLength < NTW2_PROFILE_CHAIN_DEPTH)
                frameChain[chainLength++] = 0x400000u + (address - imageBase);
            if (seen) continue;
            frameBuckets[count++] = bucket;
            framesSeen[bucket / 32] |= bit;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return count;
}

U ReadRuntimeWaitCaller(U esp, bool& direct) {
    MEMORY_BASIC_INFORMATION memory;
    if (!VirtualQuery(reinterpret_cast<void*>(esp), &memory, sizeof(memory)) ||
        memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
        !(memory.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return 0;
    const SIZE_T available = memory.RegionSize - (esp - reinterpret_cast<uintptr_t>(memory.BaseAddress));
    const U words = available < 1024 ? static_cast<U>(available / sizeof(U)) : 256;
    __try {
        const auto stack = reinterpret_cast<const volatile U*>(esp);
        for (U i = 0; i < words; ++i) {
            const U address = stack[i];
            if (InRange(address, runtimeBase, runtimeCodeBytes) && FollowsCall(address, runtimeBase)) {
                direct = i == 0;
                return address;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

void CountRuntimePair(U rva, U frameRva) {
    auto rows = NTW2_PROFILE_RUNTIME_PAIR_TABLE(runtimeProfile);
    U index = ((rva / NTW2_PROFILE_BUCKET_BYTES) * 2654435761u ^ (frameRva / NTW2_PROFILE_BUCKET_BYTES)) &
              (NTW2_PROFILE_RUNTIME_PAIRS - 1);
    for (U probe = 0; probe < NTW2_PROFILE_RUNTIME_PAIRS;
         ++probe, index = (index + 1) & (NTW2_PROFILE_RUNTIME_PAIRS - 1)) {
        auto& row = rows[index];
        if (row.count && (row.rva != rva || row.frame_rva != frameRva)) continue;
        if (!row.count) { row.rva = rva; row.frame_rva = frameRva; ++runtimeProfile->pair_count; }
        ++row.count;
        return;
    }
    ++runtimeProfile->pair_overflow;
}

void CountRuntimeWait(U address, U kind, bool direct) {
    ++runtimeProfile->wait_samples;
    if (!address) { ++runtimeProfile->wait_unresolved; return; }
    if (direct) ++runtimeProfile->wait_direct;
    else ++runtimeProfile->wait_scanned;
    const U rva = address - runtimeBase;
    auto rows = NTW2_PROFILE_RUNTIME_WAIT_TABLE(runtimeProfile);
    U index = ((rva * 2654435761u) ^ kind) & (NTW2_PROFILE_RUNTIME_WAITS - 1);
    for (U probe = 0; probe < NTW2_PROFILE_RUNTIME_WAITS;
         ++probe, index = (index + 1) & (NTW2_PROFILE_RUNTIME_WAITS - 1)) {
        auto& row = rows[index];
        if (row.count && (row.rva != rva || row.kind != kind)) continue;
        if (!row.count) { row.rva = rva; row.kind = kind; ++runtimeProfile->wait_count; }
        ++row.count;
        return;
    }
    ++runtimeProfile->wait_overflow;
}

void CountFrameChain(U length, volatile U* counts, volatile U* lengths,
                     volatile U (*chains)[NTW2_PROFILE_CHAIN_DEPTH], volatile U& uncaptured) {
    if (length) {
        for (U i = 0; i < NTW2_PROFILE_CHAINS; ++i) {
            const U storedLength = lengths[i];
            if (!storedLength) {
                for (U j = 0; j < length; ++j) chains[i][j] = frameChain[j];
                lengths[i] = length;
                counts[i] = 1;
                return;
            }
            if (storedLength != length) continue;
            U j = 0;
            for (; j < length; ++j)
                if (chains[i][j] != frameChain[j]) break;
            if (j == length) {
                counts[i] = counts[i] + 1;
                return;
            }
        }
    }
    // First 64 distinct nonempty chains only; never imply these are heavy hitters.
    uncaptured = uncaptured + 1;
}

void CountWaitHandle(U handle) {
    U index = (handle * 2654435761u) & 4095u;
    for (U probe = 0; probe < 4096; ++probe, index = (index + 1) & 4095u) {
        WaitCount& entry = waitCounts[index];
        if (entry.count && entry.handle != handle) continue;
        entry.handle = handle;
        ++entry.count;
        U least = 0;
        for (U i = 0; i < NTW2_PROFILE_WAIT_HANDLES; ++i) {
            if (ntw2_profile.wait_count[i] && ntw2_profile.wait_handle[i] == handle) {
                ntw2_profile.wait_count[i] = entry.count;
                return;
            }
            if (ntw2_profile.wait_count[i] < ntw2_profile.wait_count[least]) least = i;
        }
        if (entry.count > ntw2_profile.wait_count[least]) {
            ntw2_profile.wait_handle[least] = handle;
            ntw2_profile.wait_count[least] = entry.count;
        }
        return;
    }
    ntw2_profile.wait_overflow = ntw2_profile.wait_overflow + 1;
}

void CountMainWaitHandle(U phase, U kind, U handle) {
    volatile U* counts = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_count);
    volatile U* handles = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_handle);
    volatile U* kinds = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_handle_kind);
    U index = ((handle * 2654435761u) ^ kind) & 4095u;
    for (U probe = 0; probe < 4096; ++probe, index = (index + 1) & 4095u) {
        PhaseWaitCount& entry = mainWaitCounts[phase][index];
        if (entry.count && (entry.handle != handle || entry.kind != kind)) continue;
        entry.handle = handle;
        entry.kind = kind;
        ++entry.count;
        U least = 0;
        for (U i = 0; i < NTW2_PROFILE_WAIT_HANDLES; ++i) {
            if (counts[i] && handles[i] == handle && kinds[i] == kind) {
                counts[i] = entry.count;
                return;
            }
            if (counts[i] < counts[least]) least = i;
        }
        if (entry.count > counts[least]) {
            handles[least] = handle;
            kinds[least] = kind;
            counts[least] = entry.count;
        }
        return;
    }
    volatile U& overflow = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_overflow);
    overflow = overflow + 1;
}

// ---- opt-in grid reader census -------------------------------------------------------------------------------------
// Exact edge calls come from the private clone gates; sampler rows are EIP occupancy only. They never substitute for each other.
volatile LONG censusOn;
volatile U censusTick;
volatile ntw2_grid_census_status census;
volatile U* CensusWords() { return reinterpret_cast<volatile U*>(&census); }
U CensusSite() {
    const U s = ntw2_grid_census_site;
    return s && s - 1 < NTW2_GRID_UNKNOWN_SITE ? s - 1 : NTW2_GRID_UNKNOWN_SITE;
}
void CensusAdd(volatile U& word) { InterlockedIncrement(reinterpret_cast<volatile LONG*>(&word)); }
void CensusBump(volatile U& word) { word = word + 1; } // sampler-thread-only fields
U CensusReader(U eip, bool* clone) {
    U best = UINT32_MAX;
    if (InRange(eip, imageBase, imageCodeBytes)) {
        const U rva = eip - imageBase;
        for (U i = 0; i < census.reader_count; ++i) {
            const U lo = census.readers[i].va - 0x400000u, hi = census.readers[i].end - 0x400000u;
            if (rva >= lo && rva < hi && (best == UINT32_MAX || census.readers[i].va > census.readers[best].va)) best = i;
        }
        *clone = false;
        return best;
    }
    if (InRange(eip, runtimeBase, runtimeSize)) return UINT32_MAX;
    *clone = true;
    return ntw2_clones_grid_reader(eip);
}
void CensusSample(U eip, U phase, bool owner, bool main) {
    CensusBump(census.sample_attempts);
    bool clone = false;
    const U reader = CensusReader(eip, &clone);
    if (reader == UINT32_MAX || reader >= census.reader_count) { CensusBump(census.unknown_samples); return; }
    volatile ntw2_grid_reader_status& row = census.readers[reader];
    const U cls = owner ? 0u : main ? 1u : 2u;
    CensusBump(clone ? row.clone_samples : row.original_samples);
    CensusBump(row.samples_phase[phase]); CensusBump(row.samples_thread[cls]); CensusBump(row.samples_site[CensusSite()]);
}

void Sample(U slot, CONTEXT& context) {
    const bool main = ntw2_profile.thread_id[slot] == ntw2_profile.main_thread_id;
    if (!main && !(ntw2_profile_main_tick_gate && *ntw2_profile_main_tick_gate)) {
        ntw2_profile.overflow[5] = ntw2_profile.overflow[5] + 1;
        return;
    }
    context.ContextFlags = CONTEXT_CONTROL;
    if (SuspendThread(threads[slot]) == static_cast<DWORD>(-1)) {
        ntw2_profile.failed = ntw2_profile.failed + 1;
        return;
    }
    // No allocation, loader/CRT locks or runtime locks while any target is suspended.
    const BOOL got = GetThreadContext(threads[slot], &context);
    const U phase = main ? MainPhase() : NTW2_PROFILE_PHASE_C;
    U tickThread = ntw2_profile_tick_gate ? *ntw2_profile_tick_gate : 0;
    if (tickThread && ntw2_profile_storm_threshold_ms) {
        // --army-storm-sample-ms: the selected site (18) admits a sample only once it has been in progress for the threshold.
        const LONGLONG entry = InterlockedCompareExchange64(&stormEntry, 0, 0);
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        const bool admit = entry && now.QuadPart - entry >= frequency.QuadPart * ntw2_profile_storm_threshold_ms / 1000;
        if (ntw2_profile.thread_id[slot] == tickThread) { // count the site thread's visits only, not every sampled thread
            if (admit) ntw2_profile_storm_admitted = ntw2_profile_storm_admitted + 1;
            else ntw2_profile_storm_rejected = ntw2_profile_storm_rejected + 1;
        }
        if (!admit) tickThread = 0;
    }
    const bool gated = tickThread != 0;
    const bool tick = gated && ntw2_profile.thread_id[slot] == tickThread;
    const U actualTickThread = ntw2_profile_main_tick_gate ? *ntw2_profile_main_tick_gate : 0;
    const bool runtimeTick = actualTickThread && ntw2_profile.thread_id[slot] == actualTickThread;
    const U aiThread = ntw2_state.ai_slice_words[7];
    const U waitKind = got ? WaitKind(context.Eip) : 6;
    U waitHandle = 0, mainWaitCount = 0;
    const bool singleWait = got && tick && waitKind == 0;
    const bool readWait = singleWait && ReadWaitHandle(context.Esp, waitHandle);
    const bool mainHandleWait = main && (waitKind == 0 || waitKind == 1 || waitKind == 4 || waitKind == 5);
    const bool readMainWait = mainHandleWait && ReadMainWaitHandles(context.Esp, waitKind, mainWaitCount);
    U chainLength = 0;
    const bool mainChain = main && (phase == NTW2_PROFILE_PHASE_A1 || phase == NTW2_PROFILE_PHASE_B);
    const U frameCount = got && (tick || runtimeTick || mainChain) ? ReadFrameBuckets(context.Esp, chainLength) : 0;
    bool waitDirect = false;
    const U runtimeWaitCaller = got && runtimeTick && waitKind < 6
        ? ReadRuntimeWaitCaller(context.Esp, waitDirect) : 0;
    // Exactly one resume for our one suspension; preserve pre-existing suspend counts.
    const DWORD resumed = ResumeThread(threads[slot]);
    for (U i = 0; i < frameCount; ++i) {
        const U bucket = frameBuckets[i];
        framesSeen[bucket / 32] &= ~(1u << (bucket & 31));
        if (tick && resumed != static_cast<DWORD>(-1)) ++framesHistogram[bucket];
    }
    if (!got || resumed == static_cast<DWORD>(-1)) {
        ntw2_profile.failed = ntw2_profile.failed + 1;
        if (censusOn) { CensusBump(census.sample_attempts); CensusBump(census.sample_failures); }
        return;
    }
    const U eip = context.Eip;
    if (censusOn) CensusSample(eip, phase, runtimeTick, main);
    ntw2_ai_census::Sample(eip, runtimeTick ? 0u : ntw2_profile.thread_id[slot] == aiThread ? 1u : main ? 2u : 3u);
    const bool inImage = InRange(eip, imageBase, imageCodeBytes);
    if (InRange(eip, runtimeBase, runtimeCodeBytes)) {
        const U bucket = (eip - runtimeBase) / NTW2_PROFILE_BUCKET_BYTES;
        ++runtimeHistograms[0][bucket];
        ++runtimeProfile->all_runtime_samples;
        if (runtimeTick) {
            ++runtimeHistograms[1][bucket];
            ++runtimeProfile->tick_runtime_samples;
            for (U i = 0; i < frameCount; ++i)
                CountRuntimePair(bucket * NTW2_PROFILE_BUCKET_BYTES, frameBuckets[i] * NTW2_PROFILE_BUCKET_BYTES);
        } else if (actualTickThread && ntw2_profile.thread_id[slot] != aiThread) {
            ++runtimeHistograms[2][bucket];
            ++runtimeProfile->worker_runtime_samples;
        }
        if (runtimeTick && tick) {
            ++runtimeHistograms[3][bucket];
            ++runtimeProfile->selected_runtime_samples;
        }
    }
    if (runtimeTick && waitKind < 6) CountRuntimeWait(runtimeWaitCaller, waitKind, waitDirect);
    if (main) {
        volatile U& samples = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, samples);
        samples = samples + 1;
        volatile U& module = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, modules)[MainModule(eip)];
        module = module + 1;
        if (inImage) ++mainHistograms[phase][(eip - imageBase) / NTW2_PROFILE_BUCKET_BYTES];
        if (waitKind < 6) {
            volatile U& waits = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait);
            volatile U& kind = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_kind)[waitKind];
            waits = waits + 1;
            kind = kind + 1;
        }
        if (mainHandleWait) {
            if (readMainWait) {
                for (U i = 0; i < mainWaitCount; ++i) {
                    U j = 0;
                    for (; j < i; ++j) if (mainWaitHandles[j] == mainWaitHandles[i]) break;
                    if (j == i) CountMainWaitHandle(phase, waitKind, mainWaitHandles[i]);
                }
            } else {
                volatile U& failed = NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, phase, wait_read_failed);
                failed = failed + 1;
            }
        }
        if (phase == NTW2_PROFILE_PHASE_B)
            CountFrameChain(chainLength, ntw2_profile.main_post_chain_count, ntw2_profile.main_post_chain_len,
                            ntw2_profile.main_post_chains, ntw2_profile.main_post_chain_uncaptured);
        else if (phase == NTW2_PROFILE_PHASE_A1)
            CountFrameChain(chainLength, ntw2_profile.main_start_chain_count, ntw2_profile.main_start_chain_len,
                            ntw2_profile.main_start_chains, ntw2_profile.main_start_chain_uncaptured);
    }
    // Preserve the original selected-gate semantics for all pre-ABI-5 counters.
    if (!gated) {
        ntw2_profile.overflow[5] = ntw2_profile.overflow[5] + 1;
        return;
    }
    if (tick) ntw2_profile.tick_thread_id = tickThread;
    if (inImage) {
        const U bucket = (eip - imageBase) / NTW2_PROFILE_BUCKET_BYTES;
        ++histogram[bucket];
        if (tick) ++tickHistogram[bucket];
        ntw2_profile.in_image[slot] = ntw2_profile.in_image[slot] + 1;
    } else {
        U kind = 4;
        if (InRange(eip, runtimeBase, runtimeSize)) kind = 0;
        else if (InRange(eip, cloneBase, cloneSize)) kind = 1;
        else if (InRange(eip, tbbBase, tbbSize)) kind = 2;
        else if (waitKind < 6) {
            kind = 3;
            if (tick) ntw2_profile.tick_wait_kind[waitKind] = ntw2_profile.tick_wait_kind[waitKind] + 1;
        }
        ntw2_profile.overflow[kind] = ntw2_profile.overflow[kind] + 1;
        if (kind == 2) ntw2_profile.in_tbb[slot] = ntw2_profile.in_tbb[slot] + 1;
        if (kind == 3) ntw2_profile.in_wait[slot] = ntw2_profile.in_wait[slot] + 1;
        if (kind == 3 && tick) ntw2_profile.overflow[7] = eip;
    }
    if (singleWait) {
        if (readWait) CountWaitHandle(waitHandle);
        else ntw2_profile.wait_read_failed = ntw2_profile.wait_read_failed + 1;
    }
    ntw2_profile.thread_samples[slot] = ntw2_profile.thread_samples[slot] + 1;
    ntw2_profile.samples = ntw2_profile.samples + 1;
    if (tick) {
        CountFrameChain(chainLength, ntw2_profile.chain_count, ntw2_profile.chain_len,
                        ntw2_profile.chains, ntw2_profile.chain_uncaptured);
        ntw2_profile.tick_samples = ntw2_profile.tick_samples + 1;
    }
}

DWORD WINAPI Sampler(void*) {
    ntw2::probeDepth = 1; // every __try on this thread is a deliberate probe of another thread's stack/image bytes (not a crash)
    CONTEXT context = {};
    const HANDLE waits[2] = {stopEvent, timer};
    LONGLONG delay = 0, nextRefresh = 0;
    for (;;) {
        LARGE_INTEGER begin, end;
        QueryPerformanceCounter(&begin);
        AcquireSRWLockExclusive(&sampleLock);
        if (begin.QuadPart >= nextRefresh) {
            RefreshThreads();
            RefreshModules();
            nextRefresh = begin.QuadPart + frequency.QuadPart * 2;
        }
        const bool attempted = active;
        if (attempted) {
            ntw2_profile.rounds = ntw2_profile.rounds + 1;
            // --army-storm-sample-ms: only the thread inside the selected site matters; skipping the other ~20 threads
            // keeps a round near the 5 ms target instead of ~30 ms, so a 500 ms tail yields ~100 samples instead of ~15.
            const U gatedThread = ntw2_profile_storm_threshold_ms && ntw2_profile_tick_gate ? *ntw2_profile_tick_gate : 0;
            for (U i = 0; i < NTW2_PROFILE_THREADS; ++i)
                if (threads[i] && (ntw2_profile_storm_threshold_ms ? ntw2_profile.thread_id[i] == gatedThread : true)) Sample(i, context);
        }
        ReleaseSRWLockExclusive(&sampleLock);
        QueryPerformanceCounter(&end);
        const LONGLONG work = (end.QuadPart - begin.QuadPart) * 10000000 / frequency.QuadPart;
        // Nine units idle per measured unit of work bounds sampler duty to 10%.
        // The 5 ms round period is a target, not a catch-up deadline.
        delay = work * 9;
        if (delay < 50000 - work) delay = 50000 - work;
        if (!attempted && delay < 1000000) delay = 1000000;
        LARGE_INTEGER due;
        due.QuadPart = -delay;
        if (!SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) break;
        if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) break;
    }
    return 0;
}
}

void ntw2_profile_tick_start(uint64_t qpc_start) {
    InterlockedExchange64(&lastTickStart, static_cast<LONGLONG>(qpc_start));
}

void ntw2_profile_tick_end(uint64_t qpc_end) {
    InterlockedExchange64(&lastTickEnd, static_cast<LONGLONG>(qpc_end));
}

void ntw2_profile_storm_entry(uint64_t qpc) {
    InterlockedExchange64(&stormEntry, static_cast<LONGLONG>(qpc));
}

void ntw2_grid_census_reset(bool enabled) {
    for (U i = 0; i < sizeof(census) / sizeof(U); ++i) CensusWords()[i] = 0;
    InterlockedExchange(&censusOn, 0);
    censusTick = 0; ntw2_grid_census_site = 0;
    if (!enabled) return;
    U readers = 0, edges = 0;
    const ntw2_grid_reader_spec* readerSpecs = ntw2_grid_reader_specs(&readers);
    const ntw2_grid_edge_spec* edgeSpecs = ntw2_grid_edge_specs(&edges);
    census.version = 1;
    census.reader_count = (std::min)(readers, NTW2_GRID_READERS);
    census.edge_count = (std::min)(edges, NTW2_GRID_EDGES);
    census.edge_dropped = (readers > NTW2_GRID_READERS ? readers - NTW2_GRID_READERS : 0) + (edges > NTW2_GRID_EDGES ? edges - NTW2_GRID_EDGES : 0);
    census.unresolved_edges = ntw2_grid_unresolved_edges();
    for (U i = 0; i < census.reader_count; ++i) { census.readers[i].va = readerSpecs[i].va; census.readers[i].end = readerSpecs[i].end; }
    for (U i = 0; i < census.edge_count; ++i) {
        census.edges[i].reader = edgeSpecs[i].reader; census.edges[i].site = edgeSpecs[i].site;
        census.edges[i].source_clone = edgeSpecs[i].clone; census.edges[i].route = ntw2_grid_edge_route(i);
    }
    InterlockedExchange(&censusOn, 1);
}

void ntw2_grid_census_snapshot(volatile ntw2_grid_census_status* out) {
    volatile U* dst = reinterpret_cast<volatile U*>(out);
    for (U i = 0; i < sizeof(census) / sizeof(U); ++i) dst[i] = CensusWords()[i];
}

void ntw2_grid_census_tick(uint32_t tick) {
    if (!censusOn) return;
    censusTick = tick;
    CensusAdd(census.routed_ticks);
}

void __cdecl ntw2_grid_census_call(uint32_t edge) {
    if (!censusOn) return;
    if (edge >= census.edge_count || census.edges[edge].reader >= census.reader_count) { CensusAdd(census.attribution_dropped); return; }
    volatile ntw2_grid_edge_status& e = census.edges[edge];
    volatile ntw2_grid_reader_status& row = census.readers[e.reader];
    const U tid = GetCurrentThreadId();
    const U tickThread = ntw2_profile_main_tick_gate ? *ntw2_profile_main_tick_gate : 0;
    const bool inTick = tickThread != 0;
    const U cls = inTick && tid == tickThread ? 0u : tid == ntw2_profile.main_thread_id ? 1u : 2u;
    const U phase = tid == ntw2_profile.main_thread_id ? MainPhase() : NTW2_PROFILE_PHASE_C;
    const U site = CensusSite();
    CensusAdd(e.route_calls); CensusAdd(row.route_calls);
    if (inTick) { CensusAdd(e.route_tick_calls); CensusAdd(row.route_tick_calls); }
    if (e.route == NTW2_GRID_ROUTE_IMAGE) { CensusAdd(row.entry_calls); if (inTick) CensusAdd(row.entry_tick_calls); }
    CensusAdd(row.calls_phase[phase]); CensusAdd(row.calls_thread[cls]); CensusAdd(row.calls_site[site]);
    e.last_tick = censusTick; row.last_tick = censusTick; e.last_thread = tid; row.last_thread = tid;
    row.last_site = site; row.last_phase = phase;
}

void ntw2_profile_set_active(bool value) {
    AcquireSRWLockExclusive(&sampleLock);
    active = value;
    ReleaseSRWLockExclusive(&sampleLock);
}

void ntw2_profile_stop() {
    ntw2_profile_set_active(false);
    if (sampler) {
        SetEvent(stopEvent);
        WaitForSingleObject(sampler, INFINITE);
        CloseHandle(sampler);
        sampler = nullptr;
    }
    ntw2_profile.hist_va = ntw2_profile.tick_hist_va = ntw2_profile.frames_hist_va = 0;
    for (U i = 0; i < NTW2_PROFILE_MAIN_PHASES; ++i) {
        NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, i, hist_va) = 0;
        mainHistograms[i] = nullptr;
    }
    if (histogram) VirtualFree(histogram, 0, MEM_RELEASE);
    histogram = tickHistogram = framesHistogram = framesSeen = nullptr;
    histogramBytes=0;
    runtimeProfile = nullptr;
    for (U i = 0; i < NTW2_PROFILE_RUNTIME_HISTOGRAMS; ++i) runtimeHistograms[i] = nullptr;
    for (U i = 0; i < NTW2_PROFILE_THREADS; ++i) {
        if (threads[i]) CloseHandle(threads[i]);
        threads[i] = nullptr;
    }
    if (timer) CloseHandle(timer);
    if (stopEvent) CloseHandle(stopEvent);
    timer = stopEvent = nullptr;
}
uint32_t ntw2_profile_storage_bytes() { return histogramBytes; }

uint32_t ntw2_profile_start(U threadId, U base, U bytes, U self, U clones, U cloneBytes) {
    ntw2_profile_stop();
    imageBase = base; imageSize = bytes; runtimeBase = self; runtimeSize = ModuleSize(self);
    // Histograms are RVA-indexed code coverage, not storage for .data/.bss.
    // Keep full module extents for attribution while reserving only code buckets.
    imageCodeBytes=ExecutableSpan(base,bytes);
    runtimeCodeBytes=ExecutableSpan(self,runtimeSize);
    if(!imageCodeBytes || !runtimeCodeBytes) return ERROR_BAD_EXE_FORMAT;
    cloneBase = clones; cloneSize = cloneBytes; tbbBase = tbbSize = 0;
    moduleCount = 0;
    const U buckets = (imageCodeBytes + NTW2_PROFILE_BUCKET_BYTES - 1) / NTW2_PROFILE_BUCKET_BYTES;
    const U runtimeBuckets = (runtimeCodeBytes + NTW2_PROFILE_BUCKET_BYTES - 1) / NTW2_PROFILE_BUCKET_BYTES;
    const SIZE_T imageWords = static_cast<SIZE_T>(buckets) * (3 + NTW2_PROFILE_MAIN_PHASES);
    const SIZE_T runtimeWords = NTW2_PROFILE_RUNTIME_BYTES(runtimeBuckets) / sizeof(U);
    const SIZE_T histogramWords = imageWords + runtimeWords + (buckets + 31) / 32;
    ntw2_profile_status fresh = {};
    fresh.abi = NTW2_PROFILE_ABI; fresh.size = sizeof(fresh);
    fresh.bucket_bytes = NTW2_PROFILE_BUCKET_BYTES; fresh.bucket_count = buckets;
    fresh.main_thread_id = threadId;
    fresh.main_post_tick_ms = NTW2_PROFILE_POST_TICK_MS;
    fresh.main_start_tick_ms = NTW2_PROFILE_START_TICK_MS;
    // The sampler is stopped, so publishing a fresh observational header is safe.
    const U* words = reinterpret_cast<const U*>(&fresh);
    volatile U* exported = reinterpret_cast<volatile U*>(&ntw2_profile);
    for (U i = 0; i < sizeof(fresh) / sizeof(U); ++i) exported[i] = words[i];
    ZeroMemory(waitCounts, sizeof(waitCounts));
    ZeroMemory(mainWaitCounts, sizeof(mainWaitCounts));
    ZeroMemory(mainWaitHandles, sizeof(mainWaitHandles));
    InterlockedExchange64(&lastTickEnd, 0);
    InterlockedExchange64(&lastTickStart, 0);
    InterlockedExchange64(&stormEntry, 0);
    ntw2_profile_storm_admitted = 0; ntw2_profile_storm_rejected = 0; // the threshold is runtime-configured before start
    ZeroMemory(frameChain, sizeof(frameChain));
    static const char* const names[6] = { "NtWaitForSingleObject", "NtWaitForMultipleObjects",
        "NtDelayExecution", "NtWaitForAlertByThreadId", "NtReleaseKeyedEvent", "NtWaitForKeyedEvent" };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    for (U i = 0; i < 6; ++i) waitStubs[i] = static_cast<U>(reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, names[i])));
    ntw2_profile.overflow[6] = waitStubs[0]; // resolved NtWaitForSingleObject stub (diagnostic)
    threads[0] = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);
    DWORD error = ERROR_INVALID_PARAMETER;
    if (!threads[0]) { error = GetLastError(); goto failed; }
    if (GetProcessIdOfThread(threads[0]) != GetCurrentProcessId() || threadId == GetCurrentThreadId()) goto failed;
    ntw2_profile.thread_id[0] = threadId;
    histogram = static_cast<U*>(VirtualAlloc(nullptr, histogramWords * sizeof(U),
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!histogram) { error = GetLastError(); goto failed; }
    {
        MEMORY_BASIC_INFORMATION memory={};
        histogramBytes=VirtualQuery(histogram,&memory,sizeof(memory)) ? static_cast<U>(memory.RegionSize) :
            static_cast<U>((histogramWords*sizeof(U)+4095u)&~size_t(4095u));
    }
    tickHistogram = histogram + buckets;
    framesHistogram = tickHistogram + buckets;
    for (U i = 0; i < NTW2_PROFILE_MAIN_PHASES; ++i) {
        mainHistograms[i] = framesHistogram + buckets * (i + 1);
        NTW2_PROFILE_PHASE_FIELD(&ntw2_profile, i, hist_va) = static_cast<U>(reinterpret_cast<uintptr_t>(mainHistograms[i]));
    }
    runtimeProfile = reinterpret_cast<ntw2_profile_runtime_header*>(histogram + imageWords);
    runtimeProfile->magic = NTW2_PROFILE_RUNTIME_MAGIC;
    runtimeProfile->version = NTW2_PROFILE_RUNTIME_VERSION;
    runtimeProfile->bytes = static_cast<U>(runtimeWords * sizeof(U));
    runtimeProfile->runtime_base = runtimeBase;
    runtimeProfile->runtime_size = runtimeSize;
    runtimeProfile->bucket_bytes = NTW2_PROFILE_BUCKET_BYTES;
    runtimeProfile->bucket_count = runtimeBuckets;
    runtimeProfile->histogram_count = NTW2_PROFILE_RUNTIME_HISTOGRAMS;
    runtimeProfile->pair_capacity = NTW2_PROFILE_RUNTIME_PAIRS;
    runtimeProfile->wait_capacity = NTW2_PROFILE_RUNTIME_WAITS;
    runtimeProfile->flags = 15; // bit 3: dense RVA histograms end at the last executable section
    for (U i = 0; i < NTW2_PROFILE_RUNTIME_HISTOGRAMS; ++i)
        runtimeHistograms[i] = NTW2_PROFILE_RUNTIME_HIST(runtimeProfile) + runtimeBuckets * i;
    framesSeen = histogram + imageWords + runtimeWords;
    // Fault in histogram and scratch pages before suspending any game thread.
    for (SIZE_T i = 0; i < histogramWords; i += 1024) {
        volatile U* page = histogram + i;
        const U value = *page;
        *page = value;
    }
    for (U i = 0; i < 1024; ++i) static_cast<volatile U*>(frameBuckets)[i] = 0;
    ntw2_profile.hist_va = static_cast<U>(reinterpret_cast<uintptr_t>(histogram));
    ntw2_profile.tick_hist_va = static_cast<U>(reinterpret_cast<uintptr_t>(tickHistogram));
    ntw2_profile.frames_hist_va = static_cast<U>(reinterpret_cast<uintptr_t>(framesHistogram));
    stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    timer = CreateWaitableTimerExW(nullptr, nullptr, 0x2 /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION */, TIMER_ALL_ACCESS);
    if (!timer) timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (!stopEvent || !timer || !QueryPerformanceFrequency(&frequency)) { error = GetLastError(); goto failed; }
    postTickWindow = frequency.QuadPart * NTW2_PROFILE_POST_TICK_MS / 1000;
    startTickWindow = frequency.QuadPart * NTW2_PROFILE_START_TICK_MS / 1000;
    sampler = CreateThread(nullptr, 0, Sampler, nullptr, 0, nullptr);
    if (!sampler) { error = GetLastError(); goto failed; }
    return 0;
failed:
    ntw2_profile_stop();
    return error ? error : ERROR_GEN_FAILURE;
}
