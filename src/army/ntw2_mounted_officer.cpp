// --mounted-officer: the unit-constructor mount gate and the 0x531340 redirect (contract and proof: ntw2_mounted_officer.h).
// The gate runs on whichever thread constructs units (battle load); every counter is interlocked, every read of game memory is inside the SEH bracket.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include <atomic>
#include "ntw2_mounted_officer.h"

namespace ntw2_mounted_officer {
using U = uint32_t;
volatile U words[kWords];

namespace {
using Alloc = U(__cdecl*)(U);
using VecAlloc = U(__cdecl*)(U, U);
using VecFree = void(__cdecl*)(U);
using ThisNoArg = U(__fastcall*)(U, U);
using ThisOneArg = U(__fastcall*)(U, U, U);
using Pose = U(__cdecl*)();
using Ctor = U(__fastcall*)(U, U, U, U, U, U, U, U, U, U);
using Attach = void(__fastcall*)(U, U, U);

Targets target;
bool widenRadius;
U patchedBytes;

inline U Rd(U address) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(address)); }
inline void Wr(U address, U value) { *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(address)) = value; }
inline void Bump(Word w) { _InterlockedIncrement(reinterpret_cast<volatile long*>(&words[w])); }
inline void Set(Word w, U v) { _InterlockedExchange(reinterpret_cast<volatile long*>(&words[w]), static_cast<long>(v)); }

// The engine's inline vector append (0x51C2FF..0x51C392 / 0x51C398..0x51C431): {capacity +0, count +4, data +8}; capacity 0 -> 1 (count untouched, allocated
// with (1, 0)), count >= capacity -> double (alloc (2*cap, 0), copy `count` elements, free the old block), then data[count++] = value.
void PushBack(const Targets& t, U base, U value) {
    const U capacity = Rd(base);
    if (!capacity) {
        Wr(base, 1);
        Wr(base + 8, reinterpret_cast<VecAlloc>(static_cast<uintptr_t>(t.vecAlloc))(1, 0));
    } else if (Rd(base + 4) >= capacity) {
        const U old = Rd(base + 8);
        const U doubled = capacity + capacity;
        Wr(base, doubled);
        U fresh = 0;
        if (doubled) fresh = reinterpret_cast<VecAlloc>(static_cast<uintptr_t>(t.vecAlloc))(doubled, 0);
        Wr(base + 8, fresh);
        const U count = Rd(base + 4);
        for (U i = 0; count && i < count; ++i) Wr(fresh + 4 * i, Rd(old + 4 * i));
        if (old) reinterpret_cast<VecFree>(static_cast<uintptr_t>(t.vecFree))(old);
    }
    const U count = Rd(base + 4);
    Wr(Rd(base + 8) + 4 * count, value);
    Wr(base + 4, count + 1);
}

// Resolved mount references (ntw2_mounted_officer.h): the three loader outputs, readable.
bool RefsResolved(U unit) {
    const U row = Rd(unit + kUnitMountRow), entity = Rd(unit + kUnitMountEntity);
    const U length = Rd(unit + kUnitMountStats), characters = Rd(unit + kUnitMountAnimPtr);
    if (!row || !entity || !length || length > 0xFFFu || !characters) return false;
    (void)Rd(row + 0xC);  // the anim-ctx call dereferences [unit+0x88]+0xC
    (void)Rd(entity);
    (void)*reinterpret_cast<const volatile wchar_t*>(static_cast<uintptr_t>(characters));
    return true;
}

void GateImpl(U unit, U ctorArg, U* serialSlot) {
    const Targets& t = target;
    const int mounts = static_cast<int>(Rd(unit + kUnitMounts));
    if (mounts > 0) { Bump(WSkippedHasMounts); return; }
    if (Rd(unit + kUnitGuns)) { Bump(WSkippedHasGuns); return; }
    const U men = Rd(unit + kUnitMenCount);
    if (mounts < 0 || !men) return;
    Bump(WEligible);
    const U rider = Rd(Rd(unit + kUnitMenData));
    const U personalities = Rd(unit + kUnitPersCount), personalityData = Rd(unit + kUnitPersData);
    const bool officerFirst = rider && personalities && personalityData && Rd(personalityData) == rider;
    if (officerFirst) { Bump(WOfficerFirst); Set(WLastRiderVtable, Rd(rider)); }
    if (!RefsResolved(unit)) { Bump(WSkippedNoRefs); return; }
    if (!officerFirst) { Bump(WSkippedNoOfficer); return; }
    const U memory = reinterpret_cast<Alloc>(static_cast<uintptr_t>(t.alloc))(kMountBytes);
    if (!memory) { Bump(WAllocFailures); return; }
    const U serial = *serialSlot;
    *serialSlot = serial + 1;
    const U anim = reinterpret_cast<ThisOneArg>(static_cast<uintptr_t>(t.animCtx))(Rd(unit + kUnitMountRow) + 0xC, 0, Rd(Rd(unit + kUnitEnv) + 8) + 0x50);
    const U pose = reinterpret_cast<Pose>(static_cast<uintptr_t>(t.pose))();
    const U model = reinterpret_cast<ThisNoArg>(static_cast<uintptr_t>(t.modelCtx))(ctorArg, 0);
    const U mount = reinterpret_cast<Ctor>(static_cast<uintptr_t>(t.ctor))(memory, 0, model, Rd(unit + kUnitMountEntity), unit, unit + kUnitMountStats, pose, anim,
                                                                           serial, 1);
    Set(WSerialLast, serial);
    reinterpret_cast<Attach>(static_cast<uintptr_t>(t.attach))(rider, 0, mount);
    if (!Rd(mount + kMountRiders)) Bump(WAttachFailures);
    PushBack(t, unit + kUnitEquipVec, mount);
    PushBack(t, unit + kUnitMemberVec, mount);
    if (widenRadius) {  // MAXSS xmm0 = [mount+0x58], [unit+0x2EC]: the second operand wins ties and NaNs
        const float mine = *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(mount + kMountRadius));
        const float current = *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(unit + kUnitRadius));
        *reinterpret_cast<volatile float*>(static_cast<uintptr_t>(unit + kUnitRadius)) = mine > current ? mine : current;
    }
    Bump(WMountsCreated);
}
} // namespace

void ResetRow() {
    for (U i = 0; i < kWords; ++i) words[i] = 0;
}
void Configure(bool widen, const Targets& targets) {
    ResetRow();
    target = targets;
    widenRadius = widen;
    words[WVersion] = kVersion;
    words[WFlags] = 1u | (widen ? 2u : 0u);
}
void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = words[i];
}

void __stdcall Gate(U unit, U ctorArg, U* serialSlot) {
    Bump(WUnitsSeen);
    __try { GateImpl(unit, ctorArg, serialSlot); }
    __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); }
}

bool InstallRedirect(U delta, U cloneEntry) {
    const U site = kCallSite + delta;
    const U field = site + 1;
    const U original = kCtor + delta - (site + 5);
    unsigned char* p = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(site));
    __try {
        U current;
        memcpy(&current, p + 1, 4);
        if (p[0] != 0xE8 || current != original) return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    const U replacement = cloneEntry - (site + 5);
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, PAGE_EXECUTE_READWRITE, &old)) return false;
    bool ok = false;
    __try {
        memcpy(p + 1, &replacement, 4);
        U check;
        memcpy(&check, p + 1, 4);
        ok = check == replacement;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    if (ok) { patchedBytes = replacement; Set(WPatchInstalled, 1); }
    else { // a partial write cannot be told apart from a torn read: restore the verified original
        DWORD o2 = 0;
        if (VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, PAGE_EXECUTE_READWRITE, &o2)) {
            memcpy(p + 1, &original, 4);
            VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, o2, &ignored);
            FlushInstructionCache(GetCurrentProcess(), p, 5);
        }
    }
    return ok;
}

bool RemoveRedirect(U delta) {
    if (!words[WPatchInstalled]) return true;
    const U site = kCallSite + delta;
    const U field = site + 1;
    const U original = kCtor + delta - (site + 5);
    unsigned char* p = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(site));
    U current = 0;
    __try { memcpy(&current, p + 1, 4); } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (current == original) { Set(WPatchInstalled, 0); return true; }
    if (current != patchedBytes) return false;
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(p + 1, &original, 4);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(field)), 4, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    Set(WPatchInstalled, 0);
    return true;
}

namespace {
U placementDelta, adjustResume;
std::atomic<bool> placementActive{false};
unsigned char adjustPatch[8];
constexpr unsigned char kAdjustOriginal[8] = {0x83,0xEC,0x28,0x53,0x8B,0x5C,0x24,0x34};
inline float Float(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Finite(float f) { U bits; memcpy(&bits,&f,4); return (bits & 0x7FFFFFFFu) < 0x7F800000u; }
U OfficerUnit(U agent) {
    if (!placementActive || !agent || Rd(agent) != placementDelta + 0x132BA04) return 0;
    const U unit = Rd(agent + 0x1F0);
    if (!unit || Rd(unit + kUnitMounts) || Rd(unit + kUnitGuns) || Rd(unit + 0xAA0) == 2 ||
        !Rd(unit + kUnitMenCount) || !Rd(unit + kUnitPersCount) || Rd(agent + kMountRiders) != 1) return 0;
    const U rider = Rd(Rd(agent + 0x670));
    return rider && rider == Rd(Rd(unit + kUnitMenData)) && rider == Rd(Rd(unit + kUnitPersData)) ? unit : 0;
}
bool Place(U agent, const float world[3], float planar[2]) {
    const U unit = OfficerUnit(agent);
    if (!unit || Rd(unit + 0xAE8) != 0 || !Finite(world[0]) || !Finite(world[2])) return false;
    const U formation = Rd(unit + 0xADC);
    if (!formation) return false;
    const U angle = *reinterpret_cast<const volatile uint16_t*>(static_cast<uintptr_t>(formation + 0x64C));
    const float fx = Float(placementDelta + 0x176CFF8 + 8 * angle);
    const float fz = Float(placementDelta + 0x176CFFC + 8 * angle);
    if (!Finite(fx) || !Finite(fz)) return false;
    // Constant policy: original slot + 8 game units along formation facing,
    // for every order family, marching or stationary.
    const float x = world[0] + 8.0f * fx, z = world[2] + 8.0f * fz;
    if (!Finite(x) || !Finite(z)) return false;
    planar[0] = x; planar[1] = z;
    return true;
}
// Complete displaced instructions, no relative operands; the untouched native
// body retains its own prologue/epilogue and thiscall ret 8.
__declspec(naked) U __fastcall OriginalAdjust(U, U, U*, const U*) {
    __asm {
        sub esp, 0x28
        push ebx
        mov ebx, [esp + 0x34]
        jmp dword ptr [adjustResume]
    }
}
U __fastcall Adjust(U agent, U, U* out, const U* reference) {
    const bool eligible = HasPlacement(agent);
    if (eligible) {
        float xyz[3], planar[2];
        using World = U(__fastcall*)(const U*, U, float*);
        reinterpret_cast<World>(static_cast<uintptr_t>(placementDelta + 0x80E9D0))(reference, 0, xyz);
        if (Placement(agent, xyz, planar)) {
            using Project = U(__fastcall*)(U, U, U*, const float*, const U*, U, U);
            const U model = Rd(Rd(agent + 0x28) + 8);
            return reinterpret_cast<Project>(static_cast<uintptr_t>(placementDelta + 0x7FD070))(
                Rd(model + 0xB4), 0, out, planar, reference, 3, 0);
        }
    }
    return OriginalAdjust(agent, 0, out, reference);
}
// Atomic code bytes do not protect a thread between displaced instructions.
// Enumerate through the kernel (no heap/loader activity while threads are held),
// freeze peers, and refuse an interior IP rather than rewriting its context.
struct PlacementThreads {
    HANDLE handles[512]{};
    DWORD ids[512]{};
    U count = 0;
    ~PlacementThreads() {
        for (U i = count; i; --i) {
            ResumeThread(handles[i - 1]);
            CloseHandle(handles[i - 1]);
        }
    }
    bool Freeze(U site) {
        using NextThread = LONG (NTAPI*)(HANDLE,HANDLE,ACCESS_MASK,ULONG,ULONG,PHANDLE);
        const auto nextThread = reinterpret_cast<NextThread>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
        if (!nextThread) return false;
        const DWORD self = GetCurrentThreadId();
        for (U pass = 0; pass < 16; ++pass) {
            const U previousCount = count;
            HANDLE cursor = nullptr;
            bool retained = false;
            for (;;) {
                HANDLE next = nullptr;
                const LONG status = nextThread(GetCurrentProcess(),cursor,
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    0,0,&next);
                if (cursor && !retained) CloseHandle(cursor);
                cursor = next; retained = false;
                if (status == static_cast<LONG>(0x8000001Au)) break;
                if (status < 0) return false;
                const DWORD id = GetThreadId(cursor);
                if (!id) { CloseHandle(cursor); return false; }
                bool known = id == self;
                for (U i = 0; !known && i < count; ++i) known = ids[i] == id;
                if (known) continue;
                if (count == 512 || SuspendThread(cursor) == static_cast<DWORD>(-1)) {
                    CloseHandle(cursor); return false;
                }
                handles[count] = cursor; ids[count++] = id; retained = true;
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(cursor,&context) ||
                    (context.Eip > site && context.Eip < site + 8)) return false;
            }
            if (count == previousCount) return true;
        }
        return false;
    }
};
bool SwapAdjust(U site, const unsigned char* from, const unsigned char* to, bool activeAfter) {
    LONG64 before, after;
    memcpy(&before,from,8); memcpy(&after,to,8);
    PlacementThreads peers;
    if (!peers.Freeze(site)) return false;
    DWORD protection;
    if (!VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8,PAGE_EXECUTE_READWRITE,&protection)) return false;
    const bool changed = _InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(static_cast<uintptr_t>(site)),after,before) == before;
    DWORD ignored;
    VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8,protection,&ignored);
    FlushInstructionCache(GetCurrentProcess(),reinterpret_cast<void*>(static_cast<uintptr_t>(site)),8);
    if (changed) placementActive.store(activeAfter,std::memory_order_release);
    return changed;
}
}
bool HasPlacement(U agent) {
    __try { return OfficerUnit(agent) != 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); return false; }
}
bool Placement(U agent, const float world[3], float planar[2]) {
    __try { return Place(agent,world,planar); }
    __except (EXCEPTION_EXECUTE_HANDLER) { Bump(WFaults); return false; }
}
bool InstallPlacement(U delta) {
    if (placementActive) return placementDelta == delta;
    const U site = delta + kSlotAdjust;
    __try { if (memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(site)),kAdjustOriginal,8)) return false; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    placementDelta = delta; adjustResume = site + 8;
    memcpy(adjustPatch,kAdjustOriginal,8); adjustPatch[0] = 0xE9;
    const U displacement = static_cast<U>(reinterpret_cast<uintptr_t>(&Adjust)) - site - 5;
    memcpy(adjustPatch + 1,&displacement,4);
    if (!SwapAdjust(site,kAdjustOriginal,adjustPatch,true)) return false;
    Set(WFlags,words[WFlags] | 4u);
    return true;
}
bool RemovePlacement(U delta) {
    if (!placementActive) return true;
    if (delta != placementDelta || !SwapAdjust(delta + kSlotAdjust,adjustPatch,kAdjustOriginal,false)) return false;
    Set(WFlags,words[WFlags] & ~4u);
    return true;
}
} // namespace ntw2_mounted_officer
