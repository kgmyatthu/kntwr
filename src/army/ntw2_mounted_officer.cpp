// --mounted-officer: the unit-constructor mount gate and the 0x531340 redirect (contract and proof: ntw2_mounted_officer.h).
// The gate runs on whichever thread constructs units (battle load); every counter is interlocked, every read of game memory is inside the SEH bracket.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <math.h>
#include <windows.h>
#include <intrin.h>
#include <atomic>
#include "ntw2_mounted_officer.h"
#include "formation/native_formation_layout.h"

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
// The controller's persistent container is the intended formation, unlike the
// physical rectangle at F+644. This is the input recipe used by native 581D40.
// Traverse rows only: no generated soldier array, terrain query or allocation.
bool IntendedRear(U unit, U formation, ntw_formation_layout::RankOutline& rear) {
    namespace layout = ntw_formation_layout;
    const U men = Rd(formation + 0x18);
    if (men <= 250 || men > 4096) return false;
    const U controller = Rd(unit + 0x384), shape = Rd(formation + 0x628);
    if (!controller || !shape || !Rd(shape)) return false;
    const U generator = Rd(Rd(shape) + 0x24) - placementDelta;
    if (generator != 0x62FD60 && generator != 0x18ED200) return false;
    const U alternate = Rd(controller + 8);
    const U container = alternate ? Rd(alternate + 0x48) : Rd(controller + 0xC);
    if (!container || Rd(container + 0x2C) < men) return false;
    const U count = Rd(container + 0x10), children = Rd(container + 0x14);
    if (!count || count > 64 || !children) return false;
    layout::Input in{};
    in.men = men; in.f = Float(controller + 0x24);
    in.layout8 = Float(shape + 8); in.layout10 = Float(shape + 0x10); in.layout14 = Float(shape + 0x14);
    if (!Finite(in.f) || !Finite(in.layout8) || !Finite(in.layout10) || !Finite(in.layout14) ||
        in.f <= 0 || in.layout8 < 0 || in.layout10 <= 0 || in.layout14 <= 0) return false;
    layout::Piece pieces[64]{};
    for (U i = 0; i < count; ++i) {
        const U child = Rd(children + 4 * i), type = child ? Rd(child) - placementDelta : 0;
        if (type != 0x1333944 && type != 0x133396C) return false;
        layout::Piece& p = pieces[i];
        p.isArc = type == 0x133396C;
        p.mode = static_cast<int32_t>(Rd(child + 4));
        p.angle = static_cast<uint16_t>(Rd(child + 8));
        p.p0[0] = Float(child + 0xC); p.p0[1] = Float(child + 0x10);
        p.p1[0] = Float(child + 0x14); p.p1[1] = Float(child + 0x18);
        p.step[0] = Float(child + 0x60); p.step[1] = Float(child + 0x64);
        p.width = Float(child + 0x70);
        p.dir[0] = Float(child + 0x8C); p.dir[1] = Float(child + 0x90);
        if (p.isArc) {
            p.arcStart[0] = Float(child + 0x7C); p.arcStart[1] = Float(child + 0x80);
            p.center[0] = Float(child + 0x98); p.center[1] = Float(child + 0x9C);
            p.arcWidth = Float(child + 0xA0);
        }
        const float coordinates[] = {p.p0[0],p.p0[1],p.p1[0],p.p1[1],p.step[0],p.step[1],
            p.dir[0],p.dir[1],p.width,p.arcStart[0],p.arcStart[1],p.center[0],p.center[1],p.arcWidth};
        for (float value : coordinates) if (!Finite(value)) return false;
        const float dx = p.p1[0] - p.p0[0], dz = p.p1[1] - p.p0[1];
        if ((!p.isArc && dx * dx + dz * dz <= 0) || (p.isArc ? p.arcWidth : p.width) <= 0) return false;
    }
    float xyz[3];
    const U origin = container + 0x18;
    if (!Rd(origin + 0x10)) {
        xyz[0] = Float(origin); xyz[1] = Float(origin + 4); xyz[2] = Float(origin + 8);
    } else {
        using World = U(__fastcall*)(U, U, float*);
        reinterpret_cast<World>(static_cast<uintptr_t>(placementDelta + 0x80E9D0))(origin,0,xyz);
    }
    if (!Finite(xyz[0]) || !Finite(xyz[2])) return false;
    in.origin = {xyz[0],xyz[1],xyz[2],-1}; in.pieces = pieces; in.pieceCount = count;
    if (layout::Outline(in,&rear) != layout::kOk || rear.count != men || rear.files <= 250 ||
        !Finite(rear.rearX) || !Finite(rear.rearZ)) return false;
    const float norm = rear.forwardX * rear.forwardX + rear.forwardZ * rear.forwardZ;
    if (!Finite(norm) || norm <= 0) return false;
    const float inverse = 1.0f / sqrtf(norm);
    rear.forwardX *= inverse; rear.forwardZ *= inverse;
    return true;
}
bool Place(U agent, const float world[3], float planar[2]) {
    const U unit = OfficerUnit(agent);
    if (!unit || Rd(unit + 0xAE8) != 0 || !Finite(world[0]) || !Finite(world[2])) return false;
    const U formation = Rd(unit + 0xADC);
    if (!formation) return false;
    const U queued = Rd(formation + 0x460);
    if (queued > 8) return false;
    const U command = queued ? Rd(formation + 0x418 + 8 * queued) : 0;
    const U vt = command ? Rd(command) - placementDelta : 0;
    const bool marching = vt == 0x1325470;
    // Native is_moving is command vtable+C (55C320/55C2E0). Recognise the
    // pinned false leaf, not a guessed list of "fire" command class names.
    const bool resting = !vt || (vt >= 0x1300000 && vt < 0x14A0000 &&
        Rd(placementDelta + vt + 0xC) == placementDelta + 0x462CB0);
    if (!marching && !resting) return false;
    const U angle = *reinterpret_cast<const volatile uint16_t*>(static_cast<uintptr_t>(formation + 0x64C));
    float fx = Float(placementDelta + 0x176CFF8 + 8 * angle);
    float fz = Float(placementDelta + 0x176CFFC + 8 * angle);
    if (!Finite(fx) || !Finite(fz)) return false;
    float distance = 5.0f;
    if (!marching) {
        const U count = Rd(formation + 0x18), members = Rd(formation + 0x1C);
        if (!count || count > 4096 || !members) return false;
        ntw_formation_layout::RankOutline intended{};
        if (IntendedRear(unit,formation,intended)) {
            fx = intended.forwardX; fz = intended.forwardZ;
            distance = (intended.rearX - world[0]) * fx + (intended.rearZ - world[2]) * fz - 5.0f;
        } else {
            bool haveRear = false;
            float rear = 0.0f;
            for (U i = 0; i < count; ++i) {
                const U member = Rd(members + 4 * i);
                if (!member || member == agent) continue;
                const float x = Float(member + 0x48), z = Float(member + 0x50);
                if (!Finite(x) || !Finite(z)) return false;
                const float along = (x - world[0]) * fx + (z - world[2]) * fz;
                if (!haveRear || along < rear) rear = along;
                haveRear = true;
            }
            if (!haveRear) return false;
            distance = rear - 5.0f;
        }
    }
    const float x = world[0] + distance * fx, z = world[2] + distance * fz;
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
