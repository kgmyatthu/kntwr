// Owned-process smoke of native_formation_runtime.dll.  #included by native_formation_batch_harness.cpp INSIDE its anonymous
// namespace when NFR_RUNTIME_SMOKE is defined (CMake target native_formation_runtime_smoke), so it reuses that harness' image mapping,
// fixtures (Spec / Mock / Build), original-code runners and comparison helpers instead of copying them.
//
// What runs (all inside this process, on the privately mapped pinned image; nothing outside it is touched):
//   * the REAL dll is loaded and driven only through its exports: nfr_initialize / nfr_manager_hook / nfr_assign_hook / nfr_stop /
//     nfr_state.  Its Batch + persistent worker team run for real.
//   * private-copy glue (never the installed image): the call 0x555CEB inside the ORIGINAL 0x555CA0 is pointed at nfr_assign_hook
//     (and back to 0x18F0A00 for the native twin), the entry of 0x580640 jumps to RtContinuation, a manager continuation fixture
//     that stands in for the native army tick: for every queued command in registry order it runs the ORIGINAL 0x57AFC0 (the
//     function 0x581235 calls), i.e. original container/generator/0x18F0A00 call site/0x557C80 chain, not a mock.
//   * every unit has a TWIN fixture that runs the same original chain with the original call site; entry vector (cap, count, man,
//     slot index, cost bits), formation+0x1C order and the 0x557C80 result must be bit-equal between runtime and native twin.
//   * checks of the DLL contract: exact-once original manager, committed vs fallback accounting, mismatch -> fallback, non-owner
//     thread / outside-epoch / reentrant / concurrent entries stay native, caller-only below minJobs, registry bounds and
//     guarded-read faults, thunk register / EFLAGS / xmm / stack contract on the commit and fallback paths, initialize failures,
//     double initialize, stop busy while an epoch is active (entries disabled first), idempotent stop, counters retained,
//     worker threads joined, entries after stop stay native, RESTART (second session after stop: counters reset, new team size /
//     minJobs, failed restarts leave the stopped state untouched, second stop) with the same differential checks.

// ---- private image glue ------------------------------------------------------------------------------------------------------
constexpr uint32_t kRtMarker = 0xC0DEF00Du;
const uint32_t kRtCmdVt[6] = {0x13239B0, 0x13239F0, 0x1323A30, 0x1323A70, 0x1323AB0, 0x1323AF0};

CRITICAL_SECTION g_allocCs;
uint32_t g_logPtr[4096], g_logSize[4096], g_logN = 0;
bool g_logOn = false;
extern "C" void* __cdecl HostAllocLogged(size_t size, void*) {   // zero filled: heap tails past `count` are deterministic
    void* p = std::calloc(size ? size : 1, 1);
    EnterCriticalSection(&g_allocCs);
    if (g_logOn && g_logN < 4096) { g_logPtr[g_logN] = PtrU(p); g_logSize[g_logN] = static_cast<uint32_t>(size); ++g_logN; }
    LeaveCriticalSection(&g_allocCs);
    return p;
}

struct RtDll {
    HMODULE h = nullptr;
    uint32_t(__stdcall* init)(void*) = nullptr;
    uint32_t(__stdcall* stop)(void*) = nullptr;
    uint32_t(__fastcall* mgr)(void*) = nullptr;
    void* assign = nullptr;
    volatile uint32_t* state = nullptr;
    volatile uint32_t* diag = nullptr;
} g_dll;

struct Snap { uint32_t w[NFR_STATE_WORDS]; };
Snap TakeSnap() { Snap s; for (uint32_t i = 0; i < NFR_STATE_WORDS; ++i) s.w[i] = g_dll.state[i]; return s; }
uint32_t D(const Snap& a, const Snap& b, uint32_t word) { return b.w[word] - a.w[word]; }

uint32_t g_chk = 0, g_fail = 0;
void Chk(bool ok, const char* fmt, ...) {
    ++g_chk;
    if (ok) return;
    ++g_fail;
    if (g_fail > 60) return;
    char buf[400];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    std::printf("CHECK FAILED: %s\n", buf);
}

// Which function the call at 0x555CEB reaches (private copy only).
uint32_t g_hookAddr = 0;
void SetAssignRoute(bool hook) {
    const uint32_t site = NA(nb::va::kAssignCallSite);
    uint8_t* p = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(site));
    const uint32_t target = hook ? g_hookAddr : NA(nb::va::kAssignWrapper);
    const uint32_t rel = target - (site + 5);
    p[0] = 0xE8;
    std::memcpy(p + 1, &rel, 4);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
}

// ---- manager continuation fixture ---------------------------------------------------------------------------------------------
enum RtKind : int { R_CLEAN = 0, R_QUEUE2, R_MUTATE, R_OTHER_THREAD, R_NOT_DIRTY, R_COOLDOWN, R_BAD_CMD_VT, R_BAD_BACKLINK, R_CW, R__END };
const char* RtKindName(int k) {
    static const char* n[R__END] = {"clean", "queue2", "mutate", "other-thread", "not-dirty", "cooldown", "bad-cmd-vtable", "bad-backlink", "fpu-cw"};
    return k >= 0 && k < R__END ? n[k] : "?";
}
enum RtMode : int { MODE_COUNT = 0, MODE_NORMAL, MODE_PROBE, MODE_REENTER, MODE_STOPMID, MODE_NATIVE };
uint32_t g_workers = 0, g_minJobs = 2;

struct RealRun { Extracted x; bool faulted = false; uint32_t slotData = 0; };

void HeapMen(Mock& k) {   // the native tail of 0x555CA0 frees / reallocates the men vector with the (host) game heap
    const uint32_t n = Get<uint32_t>(k.formation, 0x18);
    uint8_t* arr = static_cast<uint8_t*>(std::calloc(n + 8, 4));
    std::memcpy(arr, k.menArray, 4u * n);
    Put<uint32_t>(k.formation, 0x14, n);
    Put<uint32_t>(k.formation, 0x1C, PtrU(arr));
    k.menArray = arr;
}
void FreeHeapVectors(Mock& k) {
    if (!k.formation) return;
    std::free(reinterpret_cast<void*>(static_cast<uintptr_t>(Get<uint32_t>(k.formation, 0x1C))));
    std::free(reinterpret_cast<void*>(static_cast<uintptr_t>(Get<uint32_t>(k.formation, 0x524))));
}

struct RtUnit {
    UnitCase uc;
    int kind = R_CLEAN, mut = M_NONE;
    Mock decoy;                      // R_QUEUE2: owns the container of the EARLIER (non-executing) queued command
    bool gathered = true, prepared = true, runs = true;
    bool mutApplied = false, expectCommit = false, ranA = false;
    RealRun ra;
    ~RtUnit() { FreeHeapVectors(uc.a); FreeHeapVectors(uc.b); }
};

using CmdFn = void(__thiscall*)(void* cmd, void* container, float f, uint32_t flag, int32_t layoutIndex);
bool CallCommand(Mock& k, float f) {   // the call 0x581235 makes: 0x57AFC0(ecx = command, container, f, flag 1, layoutIndex -1)
    __try {
        reinterpret_cast<CmdFn>(static_cast<uintptr_t>(NA(0x57AFC0)))(k.cmd, reinterpret_cast<void*>(static_cast<uintptr_t>(Get<uint32_t>(k.cmd, 0x18))), f, 1, -1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void ExtractReal(Mock& k, uint32_t slotData, Extracted* x) {
    x->cap = Get<uint32_t>(k.formation, 0x51C);
    x->count = Get<uint32_t>(k.formation, 0x520);
    const uint32_t data = Get<uint32_t>(k.formation, 0x524);
    for (uint32_t i = 0; i < x->count; ++i) {
        const uint8_t* e = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(data)) + 12u * i;
        Ent en;
        const uint32_t man = Get<uint32_t>(e, 0), slot = Get<uint32_t>(e, 4);
        en.costBits = Get<uint32_t>(e, 8);
        if (man == 0) en.man = 0xFFFFFFFFu;
        else { auto it = k.manIdx.find(man); en.man = it == k.manIdx.end() ? 0xFFFFFFFEu : it->second; }
        if (slot == 0) en.slot = 0xFFFFFFFFu;
        else if (!slotData || slot < slotData || (slot - slotData) % 36 != 0) en.slot = 0xFFFFFFFEu;
        else en.slot = (slot - slotData) / 36;
        x->e.push_back(en);
    }
    const uint32_t menCount = Get<uint32_t>(k.formation, 0x18);
    const uint8_t* arr = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(Get<uint32_t>(k.formation, 0x1C)));
    for (uint32_t i = 0; i < menCount; ++i) {
        auto it = k.manIdx.find(Get<uint32_t>(arr, 4 * i));
        x->order.push_back(it == k.manIdx.end() ? 0xFFFFFFFFu : it->second);
    }
    x->stat = Get<uint32_t>(k.formation, 0x2784);
}

RealRun RunReal(Mock& k, const Spec& s) {
    RealRun r;
    const uint32_t men = Get<uint32_t>(k.formation, 0x18);
    uint32_t* flag = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NA(0x18ED160)));
    *flag = 0;
    EnterCriticalSection(&g_allocCs); g_logN = 0; g_logOn = true; LeaveCriticalSection(&g_allocCs);
    const bool ok = CallCommand(k, s.f);
    EnterCriticalSection(&g_allocCs); g_logOn = false; LeaveCriticalSection(&g_allocCs);
    *flag = 0;
    r.faulted = !ok;
    for (uint32_t i = 0; i < g_logN; ++i) if (g_logSize[i] == 36u * men) { r.slotData = g_logPtr[i]; break; }
    if (ok) ExtractReal(k, r.slotData, &r.x);
    return r;
}

struct RtCtx {
    int mode = MODE_COUNT;
    std::vector<RtUnit*> order;
    volatile long calls = 0;
    DWORD mainTid = 0;
    volatile bool inner = false;
    uint8_t* manager = nullptr;
    // MODE_PROBE
    RtUnit* probeUnit = nullptr;
    bool probeDone = false;
    // MODE_REENTER
    uint32_t nestedRv = 0, threadRv = 0;
    // MODE_STOPMID
    uint32_t stopRv = 0, enabledAfterStop = 99;
    std::atomic<long> hammerCalls{0}, hammerBad{0};
    std::vector<std::thread> hammers;
} g_rt;

// ---- thunk register / stack contract probe --------------------------------------------------------------------------------------
struct Probe {
    uint32_t fn;          // 0x00
    uint32_t in[8];       // 0x04  eax ebx ecx edx esi edi ebp eflags
    uint32_t args[4];     // 0x24  slotVec, flag, assignVec, layoutIndex
    uint32_t out[8];      // 0x34
    uint32_t espBefore;   // 0x54
    uint32_t espAfter;    // 0x58
    uint32_t pad;         // 0x5C
    uint8_t xin[8][16];   // 0x60
    uint8_t xout[8][16];  // 0xE0
};
static_assert(offsetof(Probe, in) == 0x04 && offsetof(Probe, args) == 0x24 && offsetof(Probe, out) == 0x34 &&
              offsetof(Probe, espBefore) == 0x54 && offsetof(Probe, xin) == 0x60 && offsetof(Probe, xout) == 0xE0, "probe layout");

// Calls p->fn with ECX = in[2], the four stack arguments, and every other register / EFLAGS / xmm0..7 loaded from p->in / p->xin;
// afterwards stores every register / EFLAGS / xmm / ESP it sees into p->out / p->xout.
__declspec(naked) void __cdecl ProbeCall(Probe* p) {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov edi, [esp + 0x14]
        push edi
        push dword ptr [edi]
        push dword ptr [edi + 0x24 + 12]
        push dword ptr [edi + 0x24 + 8]
        push dword ptr [edi + 0x24 + 4]
        push dword ptr [edi + 0x24]
        mov [edi + 0x54], esp
        movups xmm0, xmmword ptr [edi + 0x60]
        movups xmm1, xmmword ptr [edi + 0x70]
        movups xmm2, xmmword ptr [edi + 0x80]
        movups xmm3, xmmword ptr [edi + 0x90]
        movups xmm4, xmmword ptr [edi + 0xA0]
        movups xmm5, xmmword ptr [edi + 0xB0]
        movups xmm6, xmmword ptr [edi + 0xC0]
        movups xmm7, xmmword ptr [edi + 0xD0]
        mov ebp, [edi + 4 + 24]
        mov esi, [edi + 4 + 16]
        mov ebx, [edi + 4 + 4]
        mov edx, [edi + 4 + 12]
        mov ecx, [edi + 4 + 8]
        mov eax, [edi + 4 + 28]
        push eax
        popfd
        mov eax, [edi + 4]
        mov edi, [edi + 4 + 20]
        call dword ptr [esp + 0x10]
        xchg eax, [esp + 4]
        mov [eax + 0x34 + 4], ebx
        mov [eax + 0x34 + 8], ecx
        mov [eax + 0x34 + 12], edx
        mov [eax + 0x34 + 16], esi
        mov [eax + 0x34 + 20], edi
        mov [eax + 0x34 + 24], ebp
        pushfd
        pop dword ptr [eax + 0x34 + 28]
        mov [eax + 0x58], esp
        movups xmmword ptr [eax + 0xE0], xmm0
        movups xmmword ptr [eax + 0xF0], xmm1
        movups xmmword ptr [eax + 0x100], xmm2
        movups xmmword ptr [eax + 0x110], xmm3
        movups xmmword ptr [eax + 0x120], xmm4
        movups xmmword ptr [eax + 0x130], xmm5
        movups xmmword ptr [eax + 0x140], xmm6
        movups xmmword ptr [eax + 0x150], xmm7
        mov ecx, [esp + 4]
        mov [eax + 0x34], ecx
        add esp, 8
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret
    }
}

constexpr uint32_t kFlagMask = 0x8D5;   // CF PF AF ZF SF OF
void FillProbe(Probe& p, uint32_t fn, uint32_t formation, uint32_t slotVec, uint32_t flag, uint32_t assignVec, int32_t layoutIndex) {
    std::memset(&p, 0, sizeof p);
    p.fn = fn;
    p.in[0] = 0xA5A51111u; p.in[1] = 0xB6B62222u; p.in[2] = formation; p.in[3] = 0xD7D73333u;
    p.in[4] = 0xE8E84444u; p.in[5] = 0xF9F95555u; p.in[6] = 0x12345678u;
    p.in[7] = 0x202u | 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;   // IF, CF, PF, ZF, SF, OF (DF clear)
    p.args[0] = slotVec; p.args[1] = flag; p.args[2] = assignVec; p.args[3] = static_cast<uint32_t>(layoutIndex);
    for (int i = 0; i < 8; ++i)
        for (int b = 0; b < 16; ++b) p.xin[i][b] = static_cast<uint8_t>(0x11 * (i + 1) + b);
}
// commit path: every register, flags and xmm unchanged; fallback path: callee-saved registers unchanged.  Both: ESP + 0x10.
void CheckProbe(const Probe& p, bool commit, const char* tag) {
    Chk(p.espAfter == p.espBefore + 0x10, "%s: ESP after %08x != before+0x10 (%08x)", tag, p.espAfter, p.espBefore + 0x10);
    static const char* names[8] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "eflags"};
    for (int i = 0; i < 7; ++i) {
        const bool must = commit || i == 1 || i == 4 || i == 5 || i == 6;
        if (must) Chk(p.out[i] == p.in[i], "%s: %s %08x != %08x", tag, names[i], p.out[i], p.in[i]);
    }
    if (commit) {
        Chk((p.out[7] & kFlagMask) == (p.in[7] & kFlagMask), "%s: eflags %08x != %08x", tag, p.out[7], p.in[7]);
        for (int i = 0; i < 8; ++i) Chk(std::memcmp(p.xin[i], p.xout[i], 16) == 0, "%s: xmm%d changed", tag, i);
    }
}

// ---- continuation ---------------------------------------------------------------------------------------------------------------
void RunUnitA(RtUnit& u) {
    if (!u.runs) return;
    Mock& k = u.uc.a;
    if (u.kind == R_MUTATE) u.mutApplied = ApplyMutation(u.uc, k, u.mut);
    u.expectCommit = u.kind == R_CLEAN || u.kind == R_QUEUE2 || (u.kind == R_MUTATE && !u.mutApplied);
    if (u.kind == R_CW) SetCw(0x37F);
    if (u.kind == R_OTHER_THREAD) {
        std::thread t([&] { u.ra = RunReal(k, u.uc.spec); });
        t.join();
    } else {
        u.ra = RunReal(k, u.uc.spec);
    }
    if (u.kind == R_CW) SetCw(0x27F);
    u.ranA = true;
}

void StartHammers(uint32_t threads, uint32_t calls) {
    for (uint32_t t = 0; t < threads; ++t)
        g_rt.hammers.emplace_back([calls] {
            for (uint32_t i = 0; i < calls; ++i) {
                if (g_dll.mgr(g_rt.manager) != kRtMarker) g_rt.hammerBad.fetch_add(1);
                g_rt.hammerCalls.fetch_add(1);
            }
        });
}

uint32_t __fastcall RtContinuation(void* manager) {
    InterlockedIncrement(&g_rt.calls);
    if (GetCurrentThreadId() != g_rt.mainTid || g_rt.inner || g_rt.mode == MODE_COUNT) return kRtMarker;   // other contexts: count only
    if (g_rt.mode == MODE_REENTER) {
        g_rt.inner = true;
        g_rt.nestedRv = g_dll.mgr(manager);                  // same thread, epoch active: must stay native
        g_rt.inner = false;
        std::thread t([&] { g_rt.threadRv = g_dll.mgr(manager); });   // other thread, epoch active: must stay native
        t.join();
    }
    if (g_rt.mode == MODE_STOPMID) {
        g_rt.stopRv = g_dll.stop(nullptr);                   // epoch active: busy, but entries must already be disabled
        g_rt.enabledAfterStop = g_dll.state[NFR_S_ENABLED];
        StartHammers(4, 3000);                               // concurrent entries during the epoch and during the final stop
    }
    if (g_rt.mode == MODE_PROBE) {
        RtUnit& u = *g_rt.probeUnit;
        Mock& k = u.uc.a;
        if (!RunGenerator(k, u.uc.spec)) { Chk(false, "probe: original generator faulted"); return kRtMarker; }
        ZeroTail(k);
        Probe p;
        FillProbe(p, g_hookAddr, PtrU(k.formation), PtrU(k.hdr), 1, PtrU(k.formation) + 0x518, -1);
        ProbeCall(&p);
        CheckProbe(p, true, "thunk commit path");
        g_rt.probeDone = true;
        u.ra.x = ExtractAndTail(k);
        FreeGenerator(k);
        u.ranA = true;
        return kRtMarker;
    }
    for (RtUnit* u : g_rt.order) RunUnitA(*u);
    return kRtMarker;
}

// ---- fixtures ---------------------------------------------------------------------------------------------------------------------
void BuildRtUnit(RtUnit& u, Rng& r, int kind, int mut) {
    u.kind = kind;
    u.mut = mut;
    do { u.uc.spec = MakeSpec(r); } while (u.uc.spec.men < 12);
    Spec& s = u.uc.spec;
    s.cw = 0x27F;
    Build(s, u.uc.a);
    Build(s, u.uc.b);
    HeapMen(u.uc.a);
    HeapMen(u.uc.b);
    u.uc.mutation = mut;
    u.uc.i1 = r.u(1u << 20);
    u.uc.i2 = r.u(1u << 20);
    Mock& a = u.uc.a;
    Mock& b = u.uc.b;
    Put<uint32_t>(a.unit, 0, NA(0x1321298));
    const uint32_t cmdVt = NA(kRtCmdVt[r.u(6)]);
    Put<uint32_t>(a.cmd, 0, kind == R_BAD_CMD_VT ? NA(0x1333AA8) : cmdVt);
    uint32_t queued = 1;
    if (kind == R_QUEUE2) {   // an earlier queued command with a DIFFERENT container: preparing it would never match the native run
        Spec other = MakeSpec(r);
        other.cw = 0x27F;
        Build(other, u.decoy);
        Put<uint32_t>(u.decoy.cmd, 0, cmdVt);
        Put<uint32_t>(u.decoy.cmd, 4, PtrU(a.formation));
        Put<uint32_t>(a.formation, 0x420, PtrU(u.decoy.cmd));
        queued = 2;
    }
    Put<uint32_t>(a.formation, 0x420 + 8 * (queued - 1), PtrU(a.cmd));
    Put<uint32_t>(a.formation, 0x460, queued);
    uint8_t* notFormation = a.Alloc(0x600);
    Put<uint32_t>(notFormation, 0, NA(0x1333AA8));
    Put<uint32_t>(notFormation, 0x510, PtrU(a.unit));
    uint8_t* list = a.Alloc(8);
    Put<uint32_t>(list, 0, PtrU(notFormation));
    Put<uint32_t>(list, 4, PtrU(a.formation));
    Put<uint32_t>(a.unit, 0xACC, 2);
    Put<uint32_t>(a.unit, 0xAD0, PtrU(list));
    if (kind == R_NOT_DIRTY) { Put<uint8_t>(a.formation, 0x278C, 0); Put<uint8_t>(b.formation, 0x278C, 0); }
    if (kind == R_COOLDOWN) { Put<uint32_t>(a.formation, 0x2788, 1); Put<uint32_t>(b.formation, 0x2788, 1); }
    if (kind == R_BAD_BACKLINK) {   // identical unit object, but not the one whose list holds the formation
        uint8_t* clone = a.Alloc(0x1000);
        std::memcpy(clone, a.unit, 0x1000);
        Put<uint32_t>(a.formation, 0x510, PtrU(clone));
    }
    u.gathered = kind != R_BAD_CMD_VT && kind != R_BAD_BACKLINK;
    u.prepared = u.gathered && kind != R_NOT_DIRTY && kind != R_COOLDOWN;
    u.runs = kind != R_NOT_DIRTY && kind != R_COOLDOWN && kind != R_BAD_CMD_VT;
}

std::unique_ptr<RtUnit> NewUnit(uint64_t seed, uint32_t salt, int kind, int mut = M_NONE) {
    Rng r(Mix64(seed ^ Mix64(0x52540000ull + salt)));
    auto u = std::make_unique<RtUnit>();
    BuildRtUnit(*u, r, kind, mut);
    return u;
}

// manager -> armies (+0x84/+0x88) -> containers (+0x20/+0x24) -> units (+0xF0/+0xF4); `junk` appends an unsafe army last:
// 1 = oversized container count (rejected by a bound), 2 = unreadable container pointer (guarded read fault).
// Extra entries the gather must skip: a null container pointer, a non-unit object in every container.
void BuildRegistry(Mock& reg, uint8_t* manager, std::vector<std::unique_ptr<RtUnit>>& us, int junk, std::vector<RtUnit*>* order) {
    std::vector<RtUnit*> lists[2][2];
    for (size_t i = 0; i < us.size(); ++i) lists[i % 2][(i / 2) % 2].push_back(us[i].get());
    uint32_t armies[3];
    uint32_t armyCount = 0;
    order->clear();
    for (int a = 0; a < 2; ++a) {
        uint8_t* conts = reg.Alloc(4 * 4);
        Put<uint32_t>(conts, 0, 0);   // null container pointer
        uint32_t cc = 1;
        for (int c = 0; c < 2; ++c) {
            uint8_t* cont = reg.Alloc(0x100);
            uint8_t* units = reg.Alloc(4 * (lists[a][c].size() + 1));
            uint8_t* notUnit = reg.Alloc(0x1000);
            Put<uint32_t>(notUnit, 0, NA(0x1333AA8));
            Put<uint32_t>(units, 0, PtrU(notUnit));
            uint32_t n = 1;
            for (RtUnit* u : lists[a][c]) { Put<uint32_t>(units, 4 * n++, PtrU(u->uc.a.unit)); order->push_back(u); }
            Put<uint32_t>(cont, 0xF0, n);
            Put<uint32_t>(cont, 0xF4, PtrU(units));
            Put<uint32_t>(conts, 4 * cc++, PtrU(cont));
        }
        uint8_t* army = reg.Alloc(0x40);
        Put<uint32_t>(army, 0x20, cc);
        Put<uint32_t>(army, 0x24, PtrU(conts));
        armies[armyCount++] = PtrU(army);
    }
    if (junk != 0) {
        uint8_t* army = reg.Alloc(0x40);
        uint8_t* conts = reg.Alloc(16);
        if (junk == 1) { Put<uint32_t>(army, 0x20, 5000); Put<uint32_t>(army, 0x24, PtrU(conts)); }
        else { Put<uint32_t>(conts, 0, 0x10); Put<uint32_t>(army, 0x20, 1); Put<uint32_t>(army, 0x24, PtrU(conts)); }
        armies[armyCount++] = PtrU(army);
    }
    uint8_t* arr = reg.Alloc(4 * 4);
    for (uint32_t i = 0; i < armyCount; ++i) Put<uint32_t>(arr, 4 * i, armies[i]);
    Put<uint32_t>(manager, 0x84, armyCount);
    Put<uint32_t>(manager, 0x88, PtrU(arr));
}
void ClearRegistry(uint8_t* manager) { Put<uint32_t>(manager, 0x84, 0); Put<uint32_t>(manager, 0x88, 0); }

struct RtTally {
    uint32_t epochs = 0, units = 0, runsA = 0, committedUnits = 0, fallbackUnits = 0, equalCompared = 0, kindUnits[R__END] = {},
             teamEpochs = 0, callerOnlyEpochs = 0, junkRejected = 0;
    uint32_t mutApplied[M__END] = {};
};
RtTally g_t;

// One epoch: builds the registry, calls the real nfr_manager_hook (-> RtContinuation -> original chain with the hook at 0x555CEB),
// then runs every twin natively (original call site) and compares.
void RtEpoch(const char* tag, std::vector<std::unique_ptr<RtUnit>>& us, int junk, int mode) {
    Mock reg;
    BuildRegistry(reg, g_rt.manager, us, junk, &g_rt.order);
    g_rt.mode = mode;
    g_rt.calls = 0;
    g_rt.inner = false;
    SetCw(0x27F);
    SetAssignRoute(true);
    const Snap before = TakeSnap();
    const uint32_t rv = g_dll.mgr(g_rt.manager);
    const Snap after = TakeSnap();
    SetAssignRoute(false);
    ClearRegistry(g_rt.manager);
    Chk(rv == kRtMarker, "%s: hook did not return the original's EAX (%08x)", tag, rv);
    Chk(g_rt.calls >= 1 && (mode == MODE_REENTER || mode == MODE_STOPMID || g_rt.calls == 1), "%s: original manager ran %ld times", tag, static_cast<long>(g_rt.calls));
    Chk(after.w[NFR_S_OWNER_THREAD] == 0, "%s: owner thread %u left set", tag, after.w[NFR_S_OWNER_THREAD]);
    ++g_t.epochs;

    uint32_t wantPrepared = 0, wantCommit = 0, wantEntries = 0, wantUnusedMax = 0;
    for (auto& up : us) {
        RtUnit& u = *up;
        ++g_t.units;
        ++g_t.kindUnits[u.kind];
        if (u.prepared) ++wantPrepared;
        if (u.runs) ++wantEntries;
        if (u.kind == R_OTHER_THREAD && u.prepared) ++wantUnusedMax;
        if (u.expectCommit) ++wantCommit;
    }
    if (mode == MODE_NATIVE) {
        // runtime stopped: no counter may move (checked by the caller); only the native twin comparison below applies
    } else if (mode != MODE_PROBE) {
        Chk(D(before, after, NFR_S_EPOCHS) == 1, "%s: epochs +%u", tag, D(before, after, NFR_S_EPOCHS));
        Chk(D(before, after, NFR_S_PREPARED) == wantPrepared, "%s: prepared +%u, expected %u", tag, D(before, after, NFR_S_PREPARED), wantPrepared);
        Chk(D(before, after, NFR_S_EXECUTED) <= wantPrepared, "%s: executed +%u > prepared %u", tag, D(before, after, NFR_S_EXECUTED), wantPrepared);
        const uint32_t failedJobs = wantPrepared - std::min(wantPrepared, D(before, after, NFR_S_EXECUTED));
        const uint32_t committed = D(before, after, NFR_S_COMMITTED), fb = D(before, after, NFR_S_FALLBACKS);
        Chk(committed <= wantCommit && committed + failedJobs >= wantCommit, "%s: committed +%u, expected %u (failed jobs %u)", tag, committed, wantCommit, failedJobs);
        Chk(committed + fb == wantEntries, "%s: committed %u + fallbacks %u != assignment entries %u", tag, committed, fb, wantEntries);
        Chk(D(before, after, NFR_S_UNUSED) <= wantUnusedMax, "%s: unused +%u > %u", tag, D(before, after, NFR_S_UNUSED), wantUnusedMax);
        // every prepared job is exactly one chunk, run either by the team or by the caller
        Chk(D(before, after, NFR_S_WORKER_CHUNKS) + D(before, after, NFR_S_CALLER_CHUNKS) == wantPrepared, "%s: chunks worker %u + caller %u != prepared %u", tag,
            D(before, after, NFR_S_WORKER_CHUNKS), D(before, after, NFR_S_CALLER_CHUNKS), wantPrepared);
        const uint32_t minJobs = g_minJobs;
        const uint32_t team = D(before, after, NFR_S_TEAM_DISPATCHES);
        const bool wantTeam = wantPrepared >= minJobs && g_workers > 0;
        Chk(team == (wantTeam ? 1u : 0u), "%s: team dispatches +%u, expected %u (prepared %u, workers %u)", tag, team, wantTeam ? 1u : 0u, wantPrepared, g_workers);
        if (wantPrepared < minJobs) Chk(D(before, after, NFR_S_WORKER_CHUNKS) == 0, "%s: workers ran chunks below minJobs", tag);
        if (wantTeam) ++g_t.teamEpochs; else if (wantPrepared > 0) ++g_t.callerOnlyEpochs;
        if (mode == MODE_NORMAL || mode == MODE_REENTER) {
            const uint32_t wantRejected = junk != 0 ? 1u : 0u;
            const uint32_t extra = mode == MODE_REENTER ? 2u : 0u;   // nested + other-thread entries
            Chk(D(before, after, NFR_S_REJECTED) == wantRejected + extra, "%s: rejected +%u, expected %u", tag, D(before, after, NFR_S_REJECTED), wantRejected + extra);
            g_t.junkRejected += wantRejected;
        }
    } else {
        Chk(D(before, after, NFR_S_EPOCHS) == 1 && D(before, after, NFR_S_PREPARED) == 1, "%s: probe epoch counters", tag);
        Chk(D(before, after, NFR_S_COMMITTED) == 1 && D(before, after, NFR_S_FALLBACKS) == 0, "%s: probe committed +%u fallbacks +%u", tag,
            D(before, after, NFR_S_COMMITTED), D(before, after, NFR_S_FALLBACKS));
    }

    // native twins (original call site) and bit-equality
    for (auto& up : us) {
        RtUnit& u = *up;
        if (mode == MODE_PROBE) {
            Mock& k = u.uc.b;
            if (!RunGenerator(k, u.uc.spec)) { Chk(false, "%s: native generator faulted", tag); continue; }
            ZeroTail(k);
            const bool ok = CallWrapper(k.formation, k.hdr, 1, -1);
            Chk(ok, "%s: native 0x18F0A00 faulted", tag);
            const Extracted xb = ExtractAndTail(k);
            FreeGenerator(k);
            std::string why;
            const bool same = SameExtracted(u.ra.x, xb, &why);
            Chk(same, "%s: probe commit != native: %s", tag, why.c_str());
            if (same) ++g_t.equalCompared;
            continue;
        }
        if (!u.runs) { Chk(!u.ranA, "%s: unit %s ran although the native flow would not", tag, RtKindName(u.kind)); continue; }
        ++g_t.runsA;
        if (u.kind == R_MUTATE) {
            const bool ap = ApplyMutation(u.uc, u.uc.b, u.mut);
            Chk(ap == u.mutApplied, "%s: mutation applied to one twin only", tag);
            if (u.mutApplied) ++g_t.mutApplied[u.mut];
        }
        if (u.kind == R_CW) SetCw(0x37F);
        RealRun rb = RunReal(u.uc.b, u.uc.spec);
        if (u.kind == R_CW) SetCw(0x27F);
        if (!u.ranA || u.ra.faulted || rb.faulted) { Chk(false, "%s: %s unit: run faulted/missing (ranA %d, A faulted %d, B faulted %d)", tag, RtKindName(u.kind), u.ranA, u.ra.faulted, rb.faulted); continue; }
        std::string why;
        if (!SameExtracted(u.ra.x, rb.x, &why)) Chk(false, "%s: %s unit: runtime != native twin: %s", tag, RtKindName(u.kind), why.c_str());
        else if (Get<uint8_t>(u.uc.a.formation, 0x278C) != Get<uint8_t>(u.uc.b.formation, 0x278C) || Get<uint32_t>(u.uc.a.formation, 0x2788) != Get<uint32_t>(u.uc.b.formation, 0x2788))
            Chk(false, "%s: %s unit: dirty/cooldown state differs", tag, RtKindName(u.kind));
        else ++g_t.equalCompared;
        if (mode != MODE_NATIVE) { if (u.expectCommit) ++g_t.committedUnits; else ++g_t.fallbackUnits; }
    }
    if (*reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(NA(0x18ED160))) != 0) Chk(false, "%s: process flag 0x18ED160 left set", tag);
}

uint32_t ThreadCount() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    uint32_t n = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) do { if (te.th32OwnerProcessID == GetCurrentProcessId()) ++n; } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return n;
}

std::vector<std::unique_ptr<RtUnit>> MakeUnits(uint64_t seed, uint32_t salt, std::initializer_list<int> kinds, uint32_t* mutRotor) {
    std::vector<std::unique_ptr<RtUnit>> us;
    static const int mutList[] = {M_X, M_Z, M_ANGLE, M_SKIP, M_SWAP, M_COUNT, M_CLASS, M_PRED, M_SIDE, M_GENERATOR};
    uint32_t i = 0;
    for (int k : kinds) {
        const int mut = k == R_MUTATE ? mutList[(*mutRotor)++ % (sizeof mutList / sizeof mutList[0])] : M_NONE;
        us.push_back(NewUnit(seed, salt * 64 + i++, k, mut));
    }
    return us;
}

// Receipt i-all samples are DECIMAL: 20073300 / 20075632 / 20075560, i.e. 0x1324B54 / 0x1325470 / 0x1325428.
// The former fixture's 0x13250D4 / 0x1325990 / 0x1325948 tested unrelated image locations and missed the live capture failure.
// Use independent receipt literals, relocated into the private image, and compare raw dumps against actual image/object bytes.
void CheckCapture(const char* tag, uint32_t base, RtUnit* u, uint32_t vtAddr, uint32_t firstVtDword, bool isRelocated) {
    volatile uint32_t* d = g_dll.diag + base;
    Mock& a = u->uc.a;
    Chk(d[NFR_C_STATUS] == 1, "%s: status %u", tag, d[NFR_C_STATUS]);
    Chk(d[NFR_C_FAULTS] == 0, "%s: faults %08x", tag, d[NFR_C_FAULTS]);
    Chk(d[NFR_C_FORMATION] == PtrU(a.formation), "%s: formation %08x != %08x", tag, d[NFR_C_FORMATION], PtrU(a.formation));
    const uint32_t queued = Get<uint32_t>(a.formation, 0x460);
    Chk(d[NFR_C_QUEUE_COUNT] == queued && d[NFR_C_QUEUE_INDEX] == queued - 1, "%s: queue count %u index %u", tag, d[NFR_C_QUEUE_COUNT], d[NFR_C_QUEUE_INDEX]);
    Chk(d[NFR_C_ENTRY_POINTER] == PtrU(a.cmd), "%s: entry pointer %08x != %08x", tag, d[NFR_C_ENTRY_POINTER], PtrU(a.cmd));
    Chk(d[NFR_C_ENTRY_SECOND] == Get<uint32_t>(a.formation, 0x424 + 8 * (queued - 1)), "%s: entry second dword %08x", tag, d[NFR_C_ENTRY_SECOND]);
    Chk(d[NFR_C_EPOCH] == g_dll.diag[NFR_D_EPOCH] && d[NFR_C_EPOCH] != 0, "%s: capture did not fire in the first matching epoch", tag);
    for (uint32_t i = 0; i < 32; ++i)
        Chk(d[NFR_C_FORMATION_DUMP + i] == Get<uint32_t>(a.formation, 0x400 + 4 * i), "%s: formation dump dword %u", tag, i);
    for (uint32_t i = 0; i < 16; ++i)
        Chk(d[NFR_C_COMMAND_DUMP + i] == Get<uint32_t>(a.cmd, 4 * i), "%s: command dump dword %u", tag, i);
    Chk(d[NFR_C_COMMAND_DUMP] == vtAddr, "%s: [cmd] %08x != %08x", tag, d[NFR_C_COMMAND_DUMP], vtAddr);
    for (uint32_t i = 0; i < 16; ++i)
        Chk(d[NFR_C_VTABLE_DUMP + i] == *reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(vtAddr + 4 * i)), "%s: [cmd] dump dword %u", tag, i);
    Chk(d[NFR_C_VTABLE_DUMP] == (isRelocated ? firstVtDword + static_cast<uint32_t>(g_delta) : firstVtDword), "%s: first [cmd] dword %08x", tag, d[NFR_C_VTABLE_DUMP]);
}

void RunDiagCaptureTest(uint64_t seed, uint32_t session, uint32_t* rotor) {
    volatile uint32_t* d = g_dll.diag;
    char tag[64];
    std::snprintf(tag, sizeof tag, "session %u diag capture", session);
    Chk(d[NFR_D_ABI] == NFR_ABI && d[NFR_D_BYTES] == NFR_DIAG_BYTES, "%s: diag abi/size %u/%u", tag, d[NFR_D_ABI], d[NFR_D_BYTES]);
    for (uint32_t w = NFR_D_CAPTURE_A; w < NFR_DIAG_WORDS; ++w) Chk(d[w] == 0, "%s: word %u not empty before the test (earlier unsupported commands must not capture)", tag, w);
    // Five unsupported commands plus one clean native differential: captures must not change preparation/assignment behavior.
    // 0x1333AA8 is neither observed identity. The literal decimal values deliberately do not share the runtime constants.
    // Every epoch gets FRESH units: a clean unit that already ran its assignment is no longer dirty, so reusing it would legitimately
    // prepare nothing in a later epoch.
    static const uint32_t kVt[5] = {0x1333AA8, 20073300u, 20075632u, 20073300u, 20075560u};
    std::unordered_map<RtUnit*, uint32_t> vtOf;
    auto makeSet = [&](uint32_t salt) {
        auto set = MakeUnits(seed, salt, {R_BAD_CMD_VT, R_BAD_CMD_VT, R_BAD_CMD_VT, R_BAD_CMD_VT, R_BAD_CMD_VT, R_CLEAN}, rotor);
        for (size_t i = 0; i < 5; ++i) {
            Mock& a = set[i]->uc.a;
            Put<uint32_t>(a.cmd, 0, NA(kVt[i]));
            vtOf[set[i].get()] = kVt[i];
            // Only the last queued entry is inspected, even if the earlier entry is unreadable.
            Put<uint32_t>(a.formation, 0x420, 0x10);
            Put<uint32_t>(a.formation, 0x428, PtrU(a.cmd));
            Put<uint32_t>(a.formation, 0x42C, 0xA1000000u + static_cast<uint32_t>(i));
            Put<uint32_t>(a.formation, 0x460, 2);
        }
        return set;
    };
    Chk(static_cast<uint32_t>(g_delta) != 0, "%s: private image must exercise relocated capture identities", tag);
    auto us = makeSet(7010);
    RtEpoch(tag, us, 0, MODE_NORMAL);
    RtUnit* firstA = nullptr;
    RtUnit* firstB = nullptr;
    for (RtUnit* u : g_rt.order) {   // gather order
        if (!firstA && vtOf[u] == 20073300u) firstA = u;
        if (!firstB && (vtOf[u] == 20075632u || vtOf[u] == 20075560u)) firstB = u;
    }
    Chk(d[NFR_D_COMMANDS_SEEN] == 6 && d[NFR_D_COMMANDS_WRONG_VTABLE] == 5 && d[NFR_D_CANDIDATES] == 1 && d[NFR_D_COMMAND_VTABLE_COUNT] == 4,
        "%s: counters seen %u wrong %u candidates %u distinct %u", tag, d[NFR_D_COMMANDS_SEEN], d[NFR_D_COMMANDS_WRONG_VTABLE], d[NFR_D_CANDIDATES], d[NFR_D_COMMAND_VTABLE_COUNT]);
    if (firstA && firstB) {
        CheckCapture("capture A", NFR_D_CAPTURE_A, firstA, NA(20073300u), 0x529840u, true);
        Chk(d[NFR_D_CAPTURE_A + NFR_C_VTABLE_DUMP + 1] == NA(0x5819D0u),
            "capture A: original execute slot 0x5819D0");
        const uint32_t vb = vtOf[firstB];
        CheckCapture("capture B", NFR_D_CAPTURE_B, firstB, NA(vb), vb == 20075632u ? 0x5299C0u : 0x529AB0u, true);
        Chk(d[NFR_D_CAPTURE_B + NFR_C_VTABLE_DUMP + 1] == NA(vb == 20075632u ? 0x581AE0u : 0x581CA0u),
            "capture B: original sibling execute slot");
    } else {
        Chk(false, "%s: fixture produced no A/B candidates", tag);
    }
    for (uint32_t w = NFR_D_CAPTURE_B + NFR_CAPTURE_WORDS; w < NFR_DIAG_WORDS; ++w) Chk(d[w] == 0, "%s: reserved word %u written", tag, w);
    // sticky: a second epoch with the same commands changes nothing (first formation of each class only)
    uint32_t before[NFR_DIAG_WORDS - NFR_D_CAPTURE_A];
    for (uint32_t w = NFR_D_CAPTURE_A; w < NFR_DIAG_WORDS; ++w) before[w - NFR_D_CAPTURE_A] = d[w];
    auto us2 = makeSet(7011);
    RtEpoch(tag, us2, 0, MODE_NORMAL);
    Chk(d[NFR_D_COMMANDS_SEEN] == 6 && d[NFR_D_COMMANDS_WRONG_VTABLE] == 5 && d[NFR_D_CANDIDATES] == 1, "%s: second epoch counters seen %u wrong %u candidates %u", tag,
        d[NFR_D_COMMANDS_SEEN], d[NFR_D_COMMANDS_WRONG_VTABLE], d[NFR_D_CANDIDATES]);
    for (uint32_t w = NFR_D_CAPTURE_A; w < NFR_DIAG_WORDS; ++w) Chk(before[w - NFR_D_CAPTURE_A] == d[w], "%s: capture word %u changed by a later epoch", tag, w);
}

// One running session: registry epochs, single/no-job/probe/reentrant epochs, stop while active with concurrent entries, final stop.
void RunSession(uint64_t seed0, uint32_t session, uint32_t rounds, uint32_t baseThreads, uint32_t workers, uint32_t* rotor) {
    const uint64_t seed = Mix64(seed0 + session);
    static const int kPattern[] = {R_CLEAN, R_CLEAN, R_QUEUE2, R_MUTATE, R_CLEAN, R_OTHER_THREAD, R_NOT_DIRTY, R_CLEAN, R_CW, R_COOLDOWN,
                                   R_BAD_CMD_VT, R_BAD_BACKLINK, R_MUTATE, R_CLEAN, R_QUEUE2, R_MUTATE, R_CLEAN, R_OTHER_THREAD, R_CLEAN, R_MUTATE,
                                   R_CW, R_CLEAN, R_MUTATE, R_BAD_BACKLINK};
    const uint32_t perRound = static_cast<uint32_t>(sizeof kPattern / sizeof kPattern[0]);
    static const int kMuts[10] = {M_X, M_Z, M_ANGLE, M_SKIP, M_SWAP, M_COUNT, M_CLASS, M_PRED, M_SIDE, M_GENERATOR};
    for (uint32_t r = 0; r < rounds; ++r) {
        std::vector<std::unique_ptr<RtUnit>> us;
        for (uint32_t i = 0; i < perRound; ++i) {
            const int kind = kPattern[(i + r) % perRound];
            const int mut = kind == R_MUTATE ? kMuts[(*rotor)++ % 10] : M_NONE;
            us.push_back(NewUnit(seed, 100 + r * 64 + i, kind, mut));
        }
        const int junk = r % 5 == 3 ? 1 : r % 5 == 4 ? 2 : 0;
        char tag[64];
        std::snprintf(tag, sizeof tag, "session %u round %u", session, r);
        RtEpoch(tag, us, junk, MODE_NORMAL);
    }
    {   // a single prepared job: caller only (below minJobs)
        auto us = MakeUnits(seed, 7001, {R_CLEAN}, rotor);
        RtEpoch("single-job epoch", us, 0, MODE_NORMAL);
    }
    {   // every unit unsupported: no job, the original still runs exactly once
        auto us = MakeUnits(seed, 7002, {R_NOT_DIRTY, R_BAD_CMD_VT, R_COOLDOWN}, rotor);
        RtEpoch("no-job epoch", us, 0, MODE_NORMAL);
    }
    RunDiagCaptureTest(seed, session, rotor);
    {   // thunk commit path inside an epoch
        auto us = MakeUnits(seed, 7003, {R_CLEAN}, rotor);
        g_rt.probeUnit = us[0].get();
        g_rt.probeDone = false;
        RtEpoch("probe epoch", us, 0, MODE_PROBE);
        Chk(g_rt.probeDone, "probe epoch: the thunk was never called");
    }
    {   // reentrant and concurrent entries while the epoch is active
        auto us = MakeUnits(seed, 7004, {R_CLEAN, R_CLEAN, R_CLEAN}, rotor);
        RtEpoch("reentrant epoch", us, 0, MODE_REENTER);
        Chk(g_rt.nestedRv == kRtMarker && g_rt.threadRv == kRtMarker, "reentrant/other-thread entries did not return the original's EAX");
        Chk(g_rt.calls == 3, "reentrant epoch: original ran %ld times, expected 3", static_cast<long>(g_rt.calls));
    }

    // stop while an epoch is active (busy), concurrent entries, final stop
    Chk(ThreadCount() == baseThreads + workers, "threads before stop %u", ThreadCount());
    Snap preStop;
    {
        auto us = MakeUnits(seed, 7005, {R_CLEAN, R_CLEAN}, rotor);
        g_rt.hammerCalls = 0; g_rt.hammerBad = 0;
        RtEpoch("stop-while-active epoch", us, 0, MODE_STOPMID);   // MODE_STOPMID starts the hammer threads from inside the epoch
        Chk(NFR_ERR_CLASS(g_rt.stopRv) == NFR_E_BUSY, "stop during an active epoch returned %08x", g_rt.stopRv);
        Chk(g_rt.enabledAfterStop == 0, "entries still enabled after stop was requested (%u)", g_rt.enabledAfterStop);
        preStop = TakeSnap();
        Chk(preStop.w[NFR_S_COMMITTED] > 0, "no commit before stop");
        uint32_t tries = 0, rc = NFR_E_BUSY;
        while (tries++ < 200000) { rc = g_dll.stop(nullptr); if (rc != NFR_E_BUSY) break; Sleep(0); }
        Chk(rc == NFR_OK, "final stop returned %08x", rc);
        for (auto& t : g_rt.hammers) t.join();
        g_rt.hammers.clear();
        Chk(g_rt.hammerBad.load() == 0, "%ld hammer entries did not return the original's EAX", g_rt.hammerBad.load());
        Chk(g_rt.calls == 1 + g_rt.hammerCalls.load(), "exact-once: original ran %ld times for %ld entries", static_cast<long>(g_rt.calls), 1 + g_rt.hammerCalls.load());
    }
    Chk(g_dll.state[NFR_S_PHASE] == NFR_PHASE_STOPPED && g_dll.state[NFR_S_ENABLED] == 0 && g_dll.state[NFR_S_OWNER_THREAD] == 0, "state after stop");
    {
        const Snap post = TakeSnap();
        static const uint32_t keep[] = {NFR_S_EPOCHS, NFR_S_PREPARED, NFR_S_EXECUTED, NFR_S_COMMITTED, NFR_S_UNUSED, NFR_S_TEAM_DISPATCHES,
                                        NFR_S_WORKER_CHUNKS, NFR_S_CALLER_CHUNKS, NFR_S_STORAGE_BYTES};
        for (uint32_t w : keep) Chk(post.w[w] == preStop.w[w], "counter word %u changed by stop (%u -> %u)", w, preStop.w[w], post.w[w]);
        Chk(post.w[NFR_S_WORKER_CHUNKS] + post.w[NFR_S_CALLER_CHUNKS] == post.w[NFR_S_PREPARED], "chunks worker %u + caller %u != prepared %u", post.w[NFR_S_WORKER_CHUNKS],
            post.w[NFR_S_CALLER_CHUNKS], post.w[NFR_S_PREPARED]);
        Chk(post.w[NFR_S_COMMITTED] + post.w[NFR_S_FALLBACKS] > 0 && post.w[NFR_S_EXECUTED] > 0, "empty counters after stop");
        if (workers > 0) Chk(post.w[NFR_S_TEAM_DISPATCHES] > 0 && post.w[NFR_S_WORKER_CHUNKS] > 0, "the persistent team never took a chunk (team %u worker %u)",
                             post.w[NFR_S_TEAM_DISPATCHES], post.w[NFR_S_WORKER_CHUNKS]);
        std::printf("session %u final counters: epochs %u prepared %u executed %u committed %u fallbacks %u unused %u rejected %u | team dispatches %u, worker chunks %u, caller chunks %u\n",
                    session, post.w[NFR_S_EPOCHS], post.w[NFR_S_PREPARED], post.w[NFR_S_EXECUTED], post.w[NFR_S_COMMITTED], post.w[NFR_S_FALLBACKS], post.w[NFR_S_UNUSED],
                    post.w[NFR_S_REJECTED], post.w[NFR_S_TEAM_DISPATCHES], post.w[NFR_S_WORKER_CHUNKS], post.w[NFR_S_CALLER_CHUNKS]);
    }
    uint32_t threadsAfter = ThreadCount();
    for (int i = 0; i < 200 && threadsAfter != baseThreads; ++i) { Sleep(10); threadsAfter = ThreadCount(); }
    Chk(threadsAfter == baseThreads, "worker threads left after stop: %u", threadsAfter - baseThreads);
    Chk(g_dll.stop(nullptr) == NFR_OK, "second stop is not idempotent");

    // entries after stop stay native (hooks fetched by the finished session fall through)
    {
        const Snap s0 = TakeSnap();
        auto us = MakeUnits(seed, 7006, {R_CLEAN, R_CLEAN}, rotor);
        RtEpoch("post-stop epoch", us, 0, MODE_NATIVE);
        const Snap s1 = TakeSnap();
        for (uint32_t w : {NFR_S_EPOCHS, NFR_S_PREPARED, NFR_S_EXECUTED, NFR_S_COMMITTED, NFR_S_TEAM_DISPATCHES, NFR_S_WORKER_CHUNKS, NFR_S_CALLER_CHUNKS, NFR_S_STORAGE_BYTES})
            Chk(s0.w[w] == s1.w[w], "post-stop entry changed counter word %u", w);
        Chk(D(s0, s1, NFR_S_REJECTED) == 1, "post-stop entry rejected +%u", D(s0, s1, NFR_S_REJECTED));
        Chk(D(s0, s1, NFR_S_FALLBACKS) == 2, "post-stop assignment entries counted %u fallbacks, expected 2", D(s0, s1, NFR_S_FALLBACKS));
        Chk(s1.w[NFR_S_PHASE] == NFR_PHASE_STOPPED && s1.w[NFR_S_ENABLED] == 0 && s1.w[NFR_S_OWNER_THREAD] == 0, "state moved after a post-stop entry");
    }
}

bool RunRuntimeSmoke(const std::string& dllPath, uint32_t cases, uint64_t seed, uint32_t workers) {
    std::printf("== native_formation_runtime smoke: %s\n", dllPath.c_str());
    InitializeCriticalSection(&g_allocCs);
    g_workers = workers;
    g_minJobs = 2;
    // private-copy glue: logging zero-filling allocator, manager entry -> continuation fixture
    PatchJump(0x00FF7F20, reinterpret_cast<const void*>(&HostAllocLogged));
    PatchJump(0x00580640, reinterpret_cast<const void*>(&RtContinuation));
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    {
        const uint8_t* site = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(NA(nb::va::kAssignCallSite)));
        uint32_t rel;
        std::memcpy(&rel, site + 1, 4);
        if (site[0] != 0xE8 || NA(nb::va::kAssignCallSite) + 5 + rel != NA(nb::va::kAssignWrapper)) { std::printf("0x555CEB is not call 0x18F0A00\n"); return false; }
    }

    g_dll.h = LoadLibraryA(dllPath.c_str());
    if (!g_dll.h) { std::printf("LoadLibrary failed (%lu)\n", GetLastError()); return false; }
    g_dll.init = reinterpret_cast<uint32_t(__stdcall*)(void*)>(GetProcAddress(g_dll.h, "nfr_initialize"));
    g_dll.stop = reinterpret_cast<uint32_t(__stdcall*)(void*)>(GetProcAddress(g_dll.h, "nfr_stop"));
    g_dll.mgr = reinterpret_cast<uint32_t(__fastcall*)(void*)>(GetProcAddress(g_dll.h, "nfr_manager_hook"));
    g_dll.assign = reinterpret_cast<void*>(GetProcAddress(g_dll.h, "nfr_assign_hook"));
    g_dll.state = reinterpret_cast<volatile uint32_t*>(GetProcAddress(g_dll.h, "nfr_state"));
    g_dll.diag = reinterpret_cast<volatile uint32_t*>(GetProcAddress(g_dll.h, "nfr_diag"));
    if (!g_dll.init || !g_dll.stop || !g_dll.mgr || !g_dll.assign || !g_dll.state || !g_dll.diag) { std::printf("missing export\n"); return false; }
    g_hookAddr = PtrU(g_dll.assign);
    g_rt.mainTid = GetCurrentThreadId();

    // ---- lifecycle before initialize ----
    Chk(g_dll.state[NFR_S_ABI] == NFR_ABI && g_dll.state[NFR_S_SIZE] == NFR_STATE_BYTES, "state abi/size words %u/%u", g_dll.state[0], g_dll.state[1]);
    for (uint32_t w = NFR_S_PHASE; w < NFR_STATE_WORDS; ++w) Chk(g_dll.state[w] == 0, "state word %u not zero before initialize", w);
    Chk(NFR_ERR_CLASS(g_dll.stop(nullptr)) == NFR_E_STATE, "stop before initialize");

    // root / model / manager fixture (model[0] = root, model[+0xB0] = manager)
    uint8_t* root = static_cast<uint8_t*>(_aligned_malloc(0x100, 16));
    uint8_t* model = static_cast<uint8_t*>(_aligned_malloc(0x100, 16));
    uint8_t* manager = static_cast<uint8_t*>(_aligned_malloc(0x100, 16));
    std::memset(root, 0, 0x100); std::memset(model, 0, 0x100); std::memset(manager, 0, 0x100);
    Put<uint32_t>(root, 8, PtrU(model));
    Put<uint32_t>(model, 0, PtrU(root));
    Put<uint32_t>(model, NFR_VA_MODEL_MANAGER_OFFSET, PtrU(manager));
    Put<uint32_t>(manager, 0, PtrU(root));
    g_rt.manager = manager;

    nfr_config good{};
    good.abi = NFR_ABI; good.size = NFR_CONFIG_BYTES; good.imageDelta = static_cast<uint32_t>(g_delta);
    good.root = PtrU(root); good.model = PtrU(model); good.workers = workers; good.maxUnits = 128; good.maxMen = 4096;
    good.arenaBytes = 24u << 20; good.minJobs = 2;
    const uint32_t baseThreads = ThreadCount();

    struct BadCfg { const char* name; uint32_t cls; void (*mutate)(nfr_config&); };
    static const BadCfg bad[] = {
        {"abi", NFR_E_ARG, [](nfr_config& c) { c.abi = 2; }},
        {"size", NFR_E_ARG, [](nfr_config& c) { c.size = 44; }},
        {"root", NFR_E_ARG, [](nfr_config& c) { c.root = 0; }},
        {"model", NFR_E_ARG, [](nfr_config& c) { c.model = 0; }},
        {"workers", NFR_E_ARG, [](nfr_config& c) { c.workers = 32; }},
        {"maxUnits0", NFR_E_ARG, [](nfr_config& c) { c.maxUnits = 0; }},
        {"maxUnitsBig", NFR_E_ARG, [](nfr_config& c) { c.maxUnits = NFR_MAX_UNITS + 1; }},
        {"maxMen0", NFR_E_ARG, [](nfr_config& c) { c.maxMen = 0; }},
        {"maxMenBig", NFR_E_ARG, [](nfr_config& c) { c.maxMen = NFR_MAX_MEN + 1; }},
        {"arenaSmall", NFR_E_ARG, [](nfr_config& c) { c.arenaBytes = 0x1000; }},
        {"arenaBig", NFR_E_ARG, [](nfr_config& c) { c.arenaBytes = NFR_MAX_ARENA_BYTES + 1; }},
        {"minJobs0", NFR_E_ARG, [](nfr_config& c) { c.minJobs = 0; }},
        {"wrongImageDelta", NFR_E_IMAGE, [](nfr_config& c) { c.imageDelta += 0x10000u; }},
        {"unmappedImageDelta", NFR_E_IMAGE, [](nfr_config& c) { c.imageDelta = 0; }},
    };
    Chk(NFR_ERR_CLASS(g_dll.init(nullptr)) == NFR_E_ARG, "initialize(null)");
    Chk(NFR_ERR_CLASS(g_dll.init(reinterpret_cast<void*>(0x10))) == NFR_E_ARG, "initialize(unreadable)");
    for (const BadCfg& b : bad) {
        nfr_config c = good;
        b.mutate(c);
        const uint32_t e = g_dll.init(&c);
        Chk(NFR_ERR_CLASS(e) == b.cls, "initialize(%s) = %08x, expected class %u", b.name, e, b.cls);
        if (b.cls == NFR_E_IMAGE) Chk(NFR_ERR_DETAIL(e) == nb::kImageMismatch, "initialize(%s) detail %u", b.name, NFR_ERR_DETAIL(e));
        Chk(g_dll.state[NFR_S_PHASE] == NFR_PHASE_UNINITIALIZED && g_dll.state[NFR_S_ENABLED] == 0, "state changed by failed initialize(%s)", b.name);
    }
    Chk(ThreadCount() == baseThreads, "failed initializes left %u extra threads", ThreadCount() - baseThreads);

    // ---- initialize ----
    const uint32_t ie = g_dll.init(&good);
    Chk(ie == NFR_OK, "initialize failed: %08x (class %u detail %u)", ie, NFR_ERR_CLASS(ie), NFR_ERR_DETAIL(ie));
    if (ie != NFR_OK) return false;
    Chk(g_dll.state[NFR_S_PHASE] == NFR_PHASE_READY && g_dll.state[NFR_S_ENABLED] == 1 && g_dll.state[NFR_S_OWNER_THREAD] == 0, "state after initialize");
    Chk(g_dll.state[NFR_S_STORAGE_BYTES] > (24u << 20), "storage bytes %u", g_dll.state[NFR_S_STORAGE_BYTES]);
    Chk(ThreadCount() == baseThreads + workers, "threads %u, expected %u (+%u workers)", ThreadCount(), baseThreads + workers, workers);
    const Snap afterInit = TakeSnap();
    Chk(NFR_ERR_CLASS(g_dll.init(&good)) == NFR_E_STATE, "second initialize");
    const Snap afterSecond = TakeSnap();
    Chk(std::memcmp(&afterInit, &afterSecond, sizeof afterInit) == 0, "second initialize changed nfr_state");
    std::printf("initialized: %u workers, minJobs 2, storage %u bytes\n", workers, g_dll.state[NFR_S_STORAGE_BYTES]);

    // ---- thunk outside an epoch (non-owner context): native fallback, register contract ----
    {
        auto u = NewUnit(seed, 9001, R_CLEAN);
        Mock& a = u->uc.a;
        Mock& b = u->uc.b;
        const Snap s0 = TakeSnap();
        const bool gen = RunGenerator(a, u->uc.spec) && RunGenerator(b, u->uc.spec);
        Chk(gen, "fallback probe: generator faulted");
        if (gen) {
            ZeroTail(a); ZeroTail(b);
            Probe p;
            FillProbe(p, g_hookAddr, PtrU(a.formation), PtrU(a.hdr), 1, PtrU(a.formation) + 0x518, -1);
            ProbeCall(&p);
            CheckProbe(p, false, "thunk fallback path");
            const bool okB = CallWrapper(b.formation, b.hdr, 1, -1);
            Chk(okB, "fallback probe: native twin faulted");
            const Extracted xa = ExtractAndTail(a), xb = ExtractAndTail(b);
            std::string why;
            const bool same = SameExtracted(xa, xb, &why);
            Chk(same, "thunk fallback != native: %s", why.c_str());
            if (same) ++g_t.equalCompared;
            const Snap s1 = TakeSnap();
            Chk(D(s0, s1, NFR_S_FALLBACKS) == 1 && D(s0, s1, NFR_S_COMMITTED) == 0, "outside-epoch hook entry not counted as one fallback");
            FreeGenerator(a); FreeGenerator(b);
        }
    }

    // ---- session 1 ----
    uint32_t rotor = 0;
    const uint32_t rounds = std::max<uint32_t>(2, (cases + 23) / 24);
    RunSession(seed, 1, rounds, baseThreads, workers, &rotor);

    // ---- restart: only from the stopped state, same imageDelta; failed restarts leave the stopped state untouched ----
    const Snap stoppedSnap = TakeSnap();
    {
        nfr_config c = good;
        c.imageDelta += 0x10000u;
        const uint32_t e = g_dll.init(&c);
        Chk(NFR_ERR_CLASS(e) == NFR_E_ARG && NFR_ERR_DETAIL(e) == 1, "restart with another imageDelta returned %08x", e);
        c = good; c.workers = 32;
        Chk(NFR_ERR_CLASS(g_dll.init(&c)) == NFR_E_ARG, "restart with bad workers");
        c = good; c.arenaBytes = NFR_MIN_ARENA_BYTES - 1;
        Chk(NFR_ERR_CLASS(g_dll.init(&c)) == NFR_E_ARG, "restart with bad arena");
        const Snap now = TakeSnap();
        Chk(std::memcmp(&stoppedSnap, &now, sizeof now) == 0, "failed restarts changed nfr_state");
        Chk(ThreadCount() == baseThreads, "failed restarts left threads");
        Chk(NFR_ERR_CLASS(g_dll.stop(nullptr)) == NFR_OK, "stop in stopped phase");
    }
    {
        nfr_config c = good;
        c.workers = workers > 1 ? workers - 1 : workers;   // a new session may change the team size
        c.minJobs = 3;
        const uint32_t e = g_dll.init(&c);
        Chk(e == NFR_OK, "restart failed: %08x (class %u detail %u)", e, NFR_ERR_CLASS(e), NFR_ERR_DETAIL(e));
        if (e == NFR_OK) {
            Chk(g_dll.state[NFR_S_PHASE] == NFR_PHASE_READY && g_dll.state[NFR_S_ENABLED] == 1 && g_dll.state[NFR_S_OWNER_THREAD] == 0, "state after restart");
            for (uint32_t w = NFR_D_CAPTURE_A; w < NFR_DIAG_WORDS; ++w) Chk(g_dll.diag[w] == 0, "diag capture word %u not reset by the new session", w);
            for (uint32_t w = NFR_S_EPOCHS; w < NFR_S_STORAGE_BYTES; ++w) Chk(g_dll.state[w] == 0, "counter word %u not reset by the new session", w);
            Chk(g_dll.state[NFR_S_STORAGE_BYTES] > (24u << 20), "restart storage bytes %u", g_dll.state[NFR_S_STORAGE_BYTES]);
            Chk(ThreadCount() == baseThreads + c.workers, "restart threads %u, expected %u", ThreadCount(), baseThreads + c.workers);
            Chk(NFR_ERR_CLASS(g_dll.init(&c)) == NFR_E_STATE, "initialize while ready after restart");
            g_minJobs = c.minJobs;
            g_workers = c.workers;
            RunSession(seed, 2, std::max<uint32_t>(2, rounds / 3), baseThreads, c.workers, &rotor);
        }
    }

    std::printf("runtime smoke: %u checks, %u failures | epochs %u (team %u, caller-only %u), units %u (clean/queue2/mutate committed-expected %u, fallback-expected %u), twin comparisons equal %u,\n"
                "  bounds/fault epochs rejected %u, kinds:", g_chk, g_fail, g_t.epochs, g_t.teamEpochs, g_t.callerOnlyEpochs, g_t.units, g_t.committedUnits, g_t.fallbackUnits,
                g_t.equalCompared, g_t.junkRejected);
    for (int k = 0; k < R__END; ++k) std::printf(" %s=%u", RtKindName(k), g_t.kindUnits[k]);
    std::printf("\n  mutations applied:");
    for (int m = 1; m < M__END; ++m) if (g_t.mutApplied[m]) std::printf(" %s=%u", MutName(m), g_t.mutApplied[m]);
    std::printf("\n");
    bool coverage = g_t.committedUnits > 0 && g_t.fallbackUnits > 0 && g_t.equalCompared > 0 && g_t.junkRejected >= 2 && g_t.callerOnlyEpochs > 0 && (workers == 0 || g_t.teamEpochs > 0);
    for (int k = 0; k < R__END; ++k) coverage = coverage && g_t.kindUnits[k] > 0;
    if (!coverage) { std::printf("FAIL: a required class was never observed\n"); ++g_fail; }
    std::printf("%s: native_formation_runtime owned-process smoke (%u failures)\n", g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0;
}
