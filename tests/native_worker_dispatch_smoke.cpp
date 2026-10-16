// Native smoke for the NTW persistent worker dispatcher (x86 only).
//
//   native_worker_dispatch_smoke.exe HELPER.dll
//
// Executes the SHIPPED position-independent helper code: the DLL's .text is copied into an owned RWX region
// exactly like the payload does (the DLL is then unloaded, only the copy runs), and every Win32 entry the
// helpers use is an OWNED stdcall wrapper handed over through the init table.  The wrappers count and track
// every event/thread handle (and can inject a failure at the Nth CreateEvent/CreateThread), so cleanup is
// judged on observable resource state: tracked live handles, process handle count, process thread count,
// thread exit codes at close time and the byte-exact zeroed pool storage.  No game process, no game memory.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <float.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "native_worker_dispatch.h"

static void require(bool ok, const char* what, unsigned long long detail = 0) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s (%llu)\n", what, detail);
        std::fflush(stderr);
        std::exit(1);
    }
}

// ---------------------------------------------------------------------------------------- loaded code
typedef void(__stdcall* dispatch_fn)(uint32_t user, uint32_t body, uint32_t chunks, void* ctx);
typedef uint32_t(__stdcall* init_fn)(ntw_pool*, const ntw_pool_config*);
typedef uint32_t(__stdcall* shutdown_fn)(ntw_pool*);

struct Code {
    unsigned char* copy = nullptr;
    dispatch_fn dispatch = nullptr;
    init_fn init = nullptr;
    shutdown_fn shutdown = nullptr;
    unsigned char* worker_entry = nullptr;
};
static Code g;

static Code load_code(const wchar_t* dll) {
    Code c;
    HMODULE module = LoadLibraryW(dll);
    require(module != nullptr, "LoadLibraryW helper");
    auto* contract = reinterpret_cast<const uint32_t*>(GetProcAddress(module, "ntw_pool_contract"));
    auto* dispatch = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_dispatch"));
    auto* init = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_init"));
    auto* shutdown = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_shutdown"));
    auto* worker = reinterpret_cast<unsigned char*>(GetProcAddress(module, "ntw_pool_worker_start"));
    require(contract && dispatch && init && shutdown && worker, "helper exports");
    require(contract[0] == NTW_POOL_ABI && contract[1] == NTW_POOL_BYTES && contract[2] == NTW_POOL_ALIGN &&
                contract[3] == NTW_POOL_MAX_WORKERS && contract[4] == NTW_POOL_CONFIG_BYTES &&
                contract[5] == NTW_POOL_MAX_CHUNKS && contract[6] == NTW_POOL_S_READY && contract[7] == 0,
            "helper ABI words");
    auto* image = reinterpret_cast<unsigned char*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew);
    auto* sections = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* text = nullptr;
    const uint32_t rva = static_cast<uint32_t>(dispatch - image);
    for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i) {
        if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) text = &sections[i];
    }
    require(text && (text->Characteristics & IMAGE_SCN_MEM_EXECUTE), "helper code section");
    const uint32_t tb = text->VirtualAddress, te = tb + text->Misc.VirtualSize;
    for (auto* fn : {dispatch, init, shutdown, worker}) {
        const uint32_t r = static_cast<uint32_t>(fn - image);
        require(r >= tb && r < te, "export inside the copied code section");
    }
    require(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0, "helper must be import free");
    // Position independence: not one base relocation may land inside the copied code section.
    const IMAGE_DATA_DIRECTORY& rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    unsigned long long textRelocs = 0, relocs = 0;
    for (uint32_t off = 0; rd.Size != 0 && off + sizeof(IMAGE_BASE_RELOCATION) <= rd.Size;) {
        auto* b = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + rd.VirtualAddress + off);
        if (b->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        const unsigned entries = (b->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        auto* e = reinterpret_cast<WORD*>(b + 1);
        for (unsigned i = 0; i != entries; ++i) {
            if ((e[i] >> 12) == IMAGE_REL_BASED_ABSOLUTE) continue;
            ++relocs;
            const uint32_t at = b->VirtualAddress + (e[i] & 0xFFF);
            if (at >= tb && at < te) ++textRelocs;
        }
        off += b->SizeOfBlock;
    }
    require(textRelocs == 0, "helper code must contain no absolute (relocated) addresses", textRelocs);
    c.copy = static_cast<unsigned char*>(VirtualAlloc(nullptr, text->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    require(c.copy != nullptr, "helper allocation");
    std::memcpy(c.copy, image + tb, text->Misc.VirtualSize);
    FlushInstructionCache(GetCurrentProcess(), c.copy, text->Misc.VirtualSize);
    const auto at = [&](unsigned char* fn) { return c.copy + (fn - image - tb); };
    c.dispatch = reinterpret_cast<dispatch_fn>(at(dispatch));
    c.init = reinterpret_cast<init_fn>(at(init));
    c.shutdown = reinterpret_cast<shutdown_fn>(at(shutdown));
    c.worker_entry = at(worker);
    FreeLibrary(module);  // the owned copy is the only code executed from here on
    std::printf("code: %u bytes copied, %llu module relocations, none inside the code section\n", te - tb, relocs);
    return c;
}

// ---------------------------------------------------------------------------------------- owned Win32 layer
namespace {
std::mutex g_m;
std::map<HANDLE, int> g_live;  // 1 = event, 2 = thread
std::atomic<long> g_event_calls{0}, g_thread_calls{0}, g_events_closed{0}, g_threads_joined{0};
std::atomic<long> g_set_calls{0}, g_wait_calls{0};
std::atomic<long> g_fail_event_at{0}, g_fail_thread_at{0};
std::atomic<unsigned long long> g_last_stack{0}, g_last_flags{0};
unsigned char* g_expected_entry = nullptr;

HANDLE WINAPI w_create_event(LPSECURITY_ATTRIBUTES a, BOOL manual, BOOL initial, LPCWSTR name) {
    require(a == nullptr && !manual && !initial && name == nullptr, "CreateEvent args: auto-reset, unsignalled, unnamed");
    const long n = ++g_event_calls;
    if (g_fail_event_at.load() == n) return nullptr;
    HANDLE h = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    require(h != nullptr, "real CreateEventW");
    std::lock_guard<std::mutex> lock(g_m);
    g_live[h] = 1;
    return h;
}

HANDLE WINAPI w_create_thread(LPSECURITY_ATTRIBUTES a, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD id) {
    require(a == nullptr && id == nullptr, "CreateThread args");
    require(reinterpret_cast<unsigned char*>(start) == g_expected_entry, "worker entry is the relocated copy entry");
    const long n = ++g_thread_calls;
    if (g_fail_thread_at.load() == n) return nullptr;
    g_last_stack = stack;
    g_last_flags = flags;
    HANDLE h = CreateThread(nullptr, stack, start, param, flags, nullptr);
    require(h != nullptr, "real CreateThread");
    std::lock_guard<std::mutex> lock(g_m);
    g_live[h] = 2;
    return h;
}

BOOL WINAPI w_close(HANDLE h) {
    int kind = 0;
    {
        std::lock_guard<std::mutex> lock(g_m);
        auto it = g_live.find(h);
        require(it != g_live.end(), "CloseHandle of a handle the pool does not own");
        kind = it->second;
        g_live.erase(it);
    }
    if (kind == 2) {
        // A thread must be closed only after it was joined: terminated and exited cleanly.
        require(WaitForSingleObject(h, 0) == WAIT_OBJECT_0, "thread handle closed before the thread ended");
        DWORD ec = 99;
        GetExitCodeThread(h, &ec);
        require(ec == 0, "worker thread exit code", ec);
        ++g_threads_joined;
    } else {
        ++g_events_closed;
    }
    return CloseHandle(h);
}

BOOL WINAPI w_set_event(HANDLE h) {
    ++g_set_calls;
    return SetEvent(h);
}

std::atomic<bool> g_fail_thread_wait{false};

DWORD WINAPI w_wait(HANDLE h, DWORD ms) {
    require(ms == INFINITE, "only INFINITE waits are used");
    ++g_wait_calls;
    if (g_fail_thread_wait.load()) {  // injected join failure: only waits on tracked thread handles fail
        std::lock_guard<std::mutex> lock(g_m);
        auto it = g_live.find(h);
        if (it != g_live.end() && it->second == 2) return WAIT_FAILED;
    }
    return WaitForSingleObject(h, ms);
}

size_t live_of(int kind) {
    std::lock_guard<std::mutex> lock(g_m);
    size_t n = 0;
    for (auto& kv : g_live) n += (kv.second == kind);
    return n;
}

void reset_counters() {
    g_event_calls = g_thread_calls = g_events_closed = g_threads_joined = 0;
    g_set_calls = g_wait_calls = 0;
    g_fail_event_at = g_fail_thread_at = 0;
    g_fail_thread_wait = false;
}

unsigned process_threads() {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    require(s != INVALID_HANDLE_VALUE, "thread snapshot");
    THREADENTRY32 e;
    e.dwSize = sizeof(e);
    unsigned n = 0;
    const DWORD pid = GetCurrentProcessId();
    for (BOOL ok = Thread32First(s, &e); ok; ok = Thread32Next(s, &e)) n += (e.th32OwnerProcessID == pid);
    CloseHandle(s);
    return n;
}

DWORD process_handles() {
    DWORD n = 0;
    require(GetProcessHandleCount(GetCurrentProcess(), &n) != 0, "GetProcessHandleCount");
    return n;
}

// Terminated threads can linger in a system snapshot for a moment: poll for the expected count.
void expect_threads(unsigned expect, const char* what) {
    unsigned n = 0;
    for (int i = 0; i < 600; ++i) {
        n = process_threads();
        if (n <= expect) return;
        Sleep(5);
    }
    require(false, what, n);
}

bool all_zero(const void* p, size_t n) {
    const auto* b = static_cast<const unsigned char*>(p);
    for (size_t i = 0; i != n; ++i) if (b[i]) return false;
    return true;
}
}  // namespace

alignas(64) static ntw_pool g_pool;
static ntw_pool* const P = &g_pool;

static ntw_pool_config make_cfg(uint32_t workers, uint32_t stack = 0) {
    ntw_pool_config c{};
    c.abi = NTW_POOL_ABI;
    c.workers = workers;
    c.stack_bytes = stack;
    c.api.create_event = reinterpret_cast<uint32_t>(&w_create_event);
    c.api.close_handle = reinterpret_cast<uint32_t>(&w_close);
    c.api.set_event = reinterpret_cast<uint32_t>(&w_set_event);
    c.api.wait_single = reinterpret_cast<uint32_t>(&w_wait);
    c.api.create_thread = reinterpret_cast<uint32_t>(&w_create_thread);
    c.api.worker_entry = reinterpret_cast<uint32_t>(g.worker_entry);
    return c;
}

static void run(void* ctx, void(__fastcall* body)(void*, uint32_t), uint32_t chunks) {
    g.dispatch(reinterpret_cast<uint32_t>(P), reinterpret_cast<uint32_t>(body), chunks, ctx);
}

static void pool_init_ok(uint32_t workers, uint32_t stack = 0) {
    const ntw_pool_config cfg = make_cfg(workers, stack);
    const uint32_t r = g.init(P, &cfg);
    require(r == NTW_POOL_OK, "ntw_pool_init", r);
    require(P->state == NTW_POOL_S_READY && P->workers == workers && P->created == workers, "pool state after init");
}

static void pool_shutdown_clean(uint32_t workers) {
    const uint32_t r = g.shutdown(P);
    require(r == NTW_POOL_OK, "ntw_pool_shutdown", r);
    require(all_zero(P, sizeof(*P)), "pool storage must be zero after shutdown");
    require(live_of(1) == 0 && live_of(2) == 0, "no tracked handle may stay open after shutdown");
    require(g_events_closed == static_cast<long>(workers) + 1 && g_threads_joined == static_cast<long>(workers),
            "every event closed and every thread joined exactly once", workers);
}

// ---------------------------------------------------------------------------------------- job bodies
static uint64_t mix(uint64_t seed, uint32_t i) {
    uint64_t x = seed + i * 0x9E3779B97F4A7C15ull;
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

static void spin_us(unsigned us) {
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    const long long ticks = f.QuadPart * us / 1000000;
    do QueryPerformanceCounter(&b); while (b.QuadPart - a.QuadPart < ticks);
}

struct Plain {
    Plain(uint32_t chunks, uint64_t s) : n(chunks), seed(s), hits(chunks), out(chunks, 0) {}
    uint32_t n;
    uint64_t seed;
    std::vector<std::atomic<uint32_t>> hits;
    std::vector<uint64_t> out;
    std::atomic<uint32_t> fin{0}, oob{0}, slow{0}, off_main{0};
    DWORD main_tid = 0;
    bool slow_mode = false;
};

static void __fastcall body_plain(void* c, uint32_t i) {
    auto* p = static_cast<Plain*>(c);
    if (i >= p->n) {
        ++p->oob;
        return;
    }
    p->hits[i].fetch_add(1);
    if (p->slow_mode) {
        spin_us(100);
        if (GetCurrentThreadId() != p->main_tid) {
            ++p->off_main;
            if (!p->slow.exchange(1)) Sleep(40);  // one worker chunk straggles: the barrier must wait for it
        }
    }
    p->out[i] = mix(p->seed, i);
    p->fin.fetch_add(1);  // set at the very END of the body: proves the dispatch waited for completion
}

static void verify_plain(const Plain& p, const char* what) {
    require(p.oob == 0, what, p.oob);
    require(p.fin == p.n, "dispatch returned before every body finished", p.n);
    for (uint32_t i = 0; i != p.n; ++i) {
        require(p.hits[i] == 1, "chunk must run exactly once", i);
        require(p.out[i] == mix(p.seed, i), "chunk output", i);
    }
}

struct Rdv {
    explicit Rdv(uint32_t chunks) : n(chunks), tid(chunks, 0) {}
    uint32_t n;
    std::vector<DWORD> tid;
    std::atomic<uint32_t> arrived{0};
};

static void __fastcall body_rdv(void* c, uint32_t i) {
    auto* r = static_cast<Rdv*>(c);
    r->tid[i] = GetCurrentThreadId();
    r->arrived.fetch_add(1);
    const ULONGLONG t0 = GetTickCount64();
    while (r->arrived.load() < r->n) {  // returns only once ALL chunks are inside a body at the same time
        require(GetTickCount64() - t0 < 15000, "rendezvous timed out: chunks did not run concurrently", r->arrived.load());
        SwitchToThread();
    }
}

struct Nest {
    ntw_pool_config cfg;
    uint32_t outer = 0;
    std::vector<Plain*> inner;
    std::vector<std::atomic<uint32_t>> outer_hits;
    std::atomic<uint32_t> busy_ok{0}, state_ok{0}, inner_done{0};
};


static void __fastcall body_nest(void* c, uint32_t i) {
    auto* x = static_cast<Nest*>(c);
    x->outer_hits[i].fetch_add(1);
    Plain& in = *x->inner[i];
    run(&in, body_plain, in.n);  // reentrant: must run inline, in full, before returning
    if (in.fin == in.n) ++x->inner_done;
    if (g.shutdown(P) == NTW_POOL_E_BUSY) ++x->busy_ok;  // lifecycle misuse is rejected, not obeyed
    if (g.init(P, &x->cfg) == NTW_POOL_E_STATE) ++x->state_ok;
}

struct Hold {
    HANDLE started = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<bool> other_done{false};
    std::atomic<uint32_t> calls{0};
};

static void __fastcall body_hold(void* c, uint32_t) {
    auto* h = static_cast<Hold*>(c);
    ++h->calls;
    SetEvent(h->started);
    const ULONGLONG t0 = GetTickCount64();
    while (!h->other_done.load()) {
        require(GetTickCount64() - t0 < 15000, "second-thread dispatch never completed", 0);
        Sleep(1);
    }
}

static DWORD g_main_tid = 0;
static std::atomic<bool> g_main_in{false};
static void __fastcall body_csr(void* c, uint32_t i) {
    auto* p = static_cast<Plain*>(c);
    p->hits[i].fetch_add(1);
    if (GetCurrentThreadId() == g_main_tid) {
        g_main_in = true;
        _mm_setcsr(0x7F80u);  // a body that forgets to restore MXCSR
    } else {
        const ULONGLONG t0 = GetTickCount64();
        while (!g_main_in.load()) {  // workers hold one chunk each until the caller is inside a body
            require(GetTickCount64() - t0 < 15000, "caller never claimed a chunk", 0);
            SwitchToThread();
        }
    }
    p->fin.fetch_add(1);
}

// stdcall(fn, user, body, chunks, ctx) -> 1 when the callee kept EBX/ESI/EDI/ESP/EBP and DF clear.
__declspec(naked) static int __stdcall call_dispatch(void* fn, uint32_t user, uint32_t body, uint32_t chunks, void* ctx) {
    __asm {
        push ebp
        mov ebp, esp
        push ebx
        push esi
        push edi
        mov ebx, 11111111h
        mov esi, 22222222h
        mov edi, 33333333h
        push dword ptr [ebp + 24]
        push dword ptr [ebp + 20]
        push dword ptr [ebp + 16]
        push dword ptr [ebp + 12]
        call dword ptr [ebp + 8]
        xor eax, eax
        lea edx, [ebp - 12]
        cmp esp, edx
        jne done
        cmp ebx, 11111111h
        jne done
        cmp esi, 22222222h
        jne done
        cmp edi, 33333333h
        jne done
        pushfd
        pop edx
        test edx, 400h
        jnz done
        mov eax, 1
    done:
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 20
    }
}

// ---------------------------------------------------------------------------------------- tests
static void test_static_contract() {
    // Argument rejection must not create or touch anything.
    reset_counters();
    const ntw_pool_config good = make_cfg(2);
    require(g.init(nullptr, &good) == NTW_POOL_E_ARG, "init(null pool)");
    require(g.init(P, nullptr) == NTW_POOL_E_ARG, "init(null cfg)");
    require(g.init(reinterpret_cast<ntw_pool*>(reinterpret_cast<unsigned char*>(P) + 4), &good) == NTW_POOL_E_ALIGN, "init(misaligned)");
    ntw_pool_config bad = good;
    bad.abi = NTW_POOL_ABI + 1;
    require(g.init(P, &bad) == NTW_POOL_E_ARG, "init(wrong abi)");
    bad = good;
    bad.workers = NTW_POOL_MAX_WORKERS + 1;
    require(g.init(P, &bad) == NTW_POOL_E_ARG, "init(too many workers)");
    uint32_t* words = &bad.api.create_event;
    for (int i = 0; i != 6; ++i) {
        bad = good;
        words[i] = 0;
        require(g.init(P, &bad) == NTW_POOL_E_ARG, "init(missing api entry)", i);
    }
    require(g.shutdown(nullptr) == NTW_POOL_E_ARG, "shutdown(null)");
    require(g.shutdown(P) == NTW_POOL_E_STATE, "shutdown of never-initialised pool");
    require(g_event_calls == 0 && g_thread_calls == 0 && live_of(1) == 0 && live_of(2) == 0 && P->state == 0,
            "rejected init must not create anything");

    // Never-initialised pool: the dispatch still executes everything inline (exact once, full completion).
    Plain p(37, 7);
    run(&p, body_plain, 37);
    verify_plain(p, "uninitialised pool dispatch");
    require(P->st_inline == 1, "inline fallback counted", P->st_inline);
    run(nullptr, nullptr, 0);  // zero chunks: nothing runs, even with a null body
    std::puts("ok: argument rejection, uninitialised pool dispatch runs inline");
}

static void test_partial_init() {
    const uint32_t W = 4;
    const DWORD h0 = process_handles();
    const unsigned t0 = process_threads();
    // Event creation order: done, wake0, wake1, ...; thread creation order: thread0, thread1, ...
    for (int kind = 0; kind != 2; ++kind) {
        const long points = kind == 0 ? 1 + W : W;
        for (long at = 1; at <= points; ++at) {
            reset_counters();
            (kind == 0 ? g_fail_event_at : g_fail_thread_at) = at;
            const ntw_pool_config cfg = make_cfg(W);
            const uint32_t r = g.init(P, &cfg);
            require(r == (kind == 0 ? NTW_POOL_E_EVENT : NTW_POOL_E_THREAD), "init failure code", r);
            const long threadsMade = kind == 0 ? (at >= 2 ? at - 2 : 0) : at - 1;
            require(g_thread_calls == (kind == 0 ? threadsMade : at), "thread creations attempted", g_thread_calls);
            require(g_threads_joined == threadsMade, "every started worker was woken, ran to its end and was joined", g_threads_joined);
            require(live_of(1) == 0 && live_of(2) == 0, "partial init leaked a tracked handle", at);
            require(g_events_closed == g_event_calls - (kind == 0 ? 1 : 0), "every created event closed", g_events_closed);
            require(all_zero(P, sizeof(*P)), "partial init must leave zero storage", at);
            require(process_handles() <= h0, "process handle count after failed init", process_handles());
            expect_threads(t0, "process thread count after failed init");
        }
    }
    // The storage is reusable after every failure.
    reset_counters();
    pool_init_ok(W);
    Plain p(100, 3);
    run(&p, body_plain, 100);
    verify_plain(p, "dispatch after failed-then-successful init");
    pool_shutdown_clean(W);
    require(process_handles() <= h0, "process handle count after clean cycle", process_handles());
    expect_threads(t0, "process thread count after clean cycle");
    std::printf("ok: partial init unwound at %u event + %u thread failure points\n", 1 + W, W);
}

static void test_lifecycle_and_idle() {
    const DWORD h0 = process_handles();
    const unsigned t0 = process_threads();
    const uint32_t W = 7;
    reset_counters();
    pool_init_ok(W, 256 * 1024);
    require(g_last_stack == 256 * 1024 && (g_last_flags & 0x10000) != 0, "stack reservation requested");
    require(live_of(1) == W + 1 && live_of(2) == W, "live handles while running");
    require(process_threads() >= W + 1, "worker threads exist while running", process_threads());
    require(process_handles() >= h0 + W + 1, "process handles while running", process_handles());
    const long events = g_event_calls, threads = g_thread_calls;
    const ntw_pool_config cfg = make_cfg(W);
    require(g.init(P, &cfg) == NTW_POOL_E_STATE, "init on a live pool");
    require(g_event_calls == events && g_thread_calls == threads && P->state == NTW_POOL_S_READY, "live pool untouched by second init");

    Plain p(500, 11);
    run(&p, body_plain, 500);
    verify_plain(p, "stack-limited workers");

    // Idle workers must sleep: 7 spinning workers would burn ~3.5 s of CPU in 500 ms.
    auto cpu = [] {
        FILETIME c, e, k, u;
        GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
        return ((static_cast<unsigned long long>(k.dwHighDateTime) << 32) | k.dwLowDateTime) +
               ((static_cast<unsigned long long>(u.dwHighDateTime) << 32) | u.dwLowDateTime);
    };
    const unsigned long long c0 = cpu();
    Sleep(500);
    const unsigned long long idle = (cpu() - c0) / 10000;  // ms
    require(idle < 60, "idle workers burn CPU (ms in 500 ms wall)", idle);

    pool_shutdown_clean(W);
    require(g.shutdown(P) == NTW_POOL_E_STATE, "second shutdown");
    require(process_handles() <= h0, "process handle count after shutdown", process_handles());
    expect_threads(t0, "process thread count after shutdown");
    Plain after(9, 5);
    run(&after, body_plain, 9);
    verify_plain(after, "dispatch after shutdown runs inline");

    // Repeated cycles over every team size (including caller-only): no handle or thread growth.
    for (uint32_t w = 0; w <= NTW_POOL_MAX_WORKERS; ++w) {
        reset_counters();
        pool_init_ok(w);
        require(live_of(1) == w + 1 && live_of(2) == w, "live handles for team size", w);
        Plain q(w + 3, w);
        run(&q, body_plain, w + 3);
        verify_plain(q, "cycle dispatch");
        pool_shutdown_clean(w);
    }
    require(process_handles() <= h0, "process handle count after all cycles", process_handles());
    expect_threads(t0, "process thread count after all cycles");
    std::printf("ok: lifecycle (idle CPU %llu ms/500 ms), %u team sizes, handles and threads back to baseline\n", idle, NTW_POOL_MAX_WORKERS + 1);
}

static void test_exact_once_and_reuse() {
    const uint32_t W = 4;
    reset_counters();
    pool_init_ok(W);
    g_main_tid = GetCurrentThreadId();
    std::mt19937 rng(0x4E5457u);
    unsigned long long totalChunks = 0, calls = 0;
    uint32_t sizes[] = {0, 1, 2, 3, W, W + 1, W + 2, 2 * W + 1, 63, 64, 65, 1000};
    std::vector<uint32_t> plan(std::begin(sizes), std::end(sizes));
    for (int i = 0; i < 3000; ++i) plan.push_back(rng() % 401);
    for (int i = 0; i < 6; ++i) plan.push_back(20000 + rng() % 5000);
    for (uint32_t n : plan) {
        Plain p(n, rng());
        p.main_tid = g_main_tid;
        run(&p, body_plain, n);
        verify_plain(p, "varied dispatch");
        totalChunks += n;
        calls += (n != 0);
    }
    require(P->st_calls == calls && P->st_inline == 0, "owned dispatch count", P->st_calls);
    require(P->st_team + P->st_serial == P->st_calls, "team+serial paths", P->st_team);
    unsigned long long workerChunks = 0;
    for (uint32_t i = 0; i != W; ++i) {
        require(P->slots[i].wakes > 0, "every worker took part", i);
        workerChunks += P->slots[i].chunks;
    }
    require(workerChunks > 0, "workers executed chunks");
    require(workerChunks + P->st_main_chunks == totalChunks, "chunk accounting (workers + caller == total)", workerChunks);
    require(P->outstanding == 0, "barrier counter drained", P->outstanding);

    // Barrier: a straggling WORKER chunk must hold the dispatch back although the caller ran out of work.
    bool sawSlow = false;
    for (int attempt = 0; attempt < 40 && !sawSlow; ++attempt) {
        Plain p(64, 99 + attempt);
        p.main_tid = g_main_tid;
        p.slow_mode = true;
        LARGE_INTEGER qf, qa, qb;
        QueryPerformanceFrequency(&qf);
        QueryPerformanceCounter(&qa);
        run(&p, body_plain, 64);
        QueryPerformanceCounter(&qb);
        const long long ms = (qb.QuadPart - qa.QuadPart) * 1000 / qf.QuadPart;
        verify_plain(p, "slow-worker dispatch");
        if (p.slow.load() != 0) {
            sawSlow = true;
            require(ms >= 35, "dispatch returned before the straggling worker chunk finished", ms);
        }
    }
    require(sawSlow, "no worker ever claimed a chunk in the barrier test");

    // Chunk 1 only: serial path, runs on the caller.
    Plain one(1, 5);
    one.main_tid = g_main_tid;
    one.slow_mode = false;
    const uint32_t serialBefore = P->st_serial;
    run(&one, body_plain, 1);
    verify_plain(one, "single chunk");
    require(P->st_serial == serialBefore + 1, "single chunk is serial");
    pool_shutdown_clean(W);
    std::printf("ok: exact-once/barrier over %zu dispatches, %llu chunks (workers %llu, caller %llu)\n", plan.size(), totalChunks,
                workerChunks, totalChunks - workerChunks);
}

static void test_concurrency() {
    for (uint32_t W : {1u, 4u, NTW_POOL_MAX_WORKERS}) {
        reset_counters();
        pool_init_ok(W);
        for (int round = 0; round != 20; ++round) {
            Rdv r(W + 1);
            run(&r, body_rdv, W + 1);
            std::vector<DWORD> t = r.tid;
            std::sort(t.begin(), t.end());
            require(std::unique(t.begin(), t.end()) == t.end(), "each participant ran exactly one chunk on its own thread", W);
            bool hasMain = false;
            for (DWORD d : r.tid) hasMain |= (d == GetCurrentThreadId());
            require(hasMain, "the calling thread participates", W);
        }
        pool_shutdown_clean(W);
    }
    std::printf("ok: %u participants executed bodies simultaneously (rendezvous), caller participates\n", NTW_POOL_MAX_WORKERS + 1);
}

static void test_misuse() {
    const uint32_t W = 4;
    reset_counters();
    pool_init_ok(W);
    // Reentrant dispatch/shutdown/init from inside bodies.
    Nest nest;
    nest.cfg = make_cfg(W);
    nest.outer = 16;
    nest.outer_hits = std::vector<std::atomic<uint32_t>>(nest.outer);
    std::vector<Plain*> inner;
    for (uint32_t i = 0; i != nest.outer; ++i) inner.push_back(new Plain(5 + i, i));
    nest.inner = inner;
    run(&nest, body_nest, nest.outer);
    for (uint32_t i = 0; i != nest.outer; ++i) {
        require(nest.outer_hits[i] == 1, "outer chunk exactly once", i);
        verify_plain(*inner[i], "reentrant inner dispatch");
        delete inner[i];
    }
    require(nest.inner_done == nest.outer && nest.busy_ok == nest.outer && nest.state_ok == nest.outer,
            "nested dispatch inline + shutdown E_BUSY + init E_STATE for every outer chunk", nest.busy_ok);
    require(P->st_inline == nest.outer && P->state == NTW_POOL_S_READY && P->outstanding == 0, "pool intact after misuse", P->st_inline);
    Plain after(50, 8);
    run(&after, body_plain, 50);
    verify_plain(after, "dispatch after misuse");

    // A second thread dispatches while the first dispatch is still in flight: it runs inline, completely.
    Hold hold;
    const uint32_t inlineBefore = P->st_inline;
    std::thread other([&] {
        require(WaitForSingleObject(hold.started, 15000) == WAIT_OBJECT_0, "first dispatch never started");
        Plain p(20, 77);
        run(&p, body_plain, 20);
        verify_plain(p, "second-thread dispatch");
        hold.other_done = true;
    });
    run(&hold, body_hold, 8);
    other.join();
    require(hold.calls == 8, "held dispatch ran its 8 chunks", hold.calls);
    require(P->st_inline == inlineBefore + 1, "second-thread dispatch counted as inline", P->st_inline);
    CloseHandle(hold.started);
    pool_shutdown_clean(W);
    std::puts("ok: reentrant dispatch/shutdown/init and concurrent second-thread dispatch handled without false completion");
}

static void test_abi_state_preservation() {
    const uint32_t W = 3;
    reset_counters();
    pool_init_ok(W);
    g_main_tid = GetCurrentThreadId();
    Plain p(40, 1);
    p.main_tid = g_main_tid;
    require(call_dispatch(reinterpret_cast<void*>(g.dispatch), reinterpret_cast<uint32_t>(P), reinterpret_cast<uint32_t>(&body_plain), 40, &p) == 1,
            "EBX/ESI/EDI/ESP/DF preserved across the stdcall dispatch");
    verify_plain(p, "register-checked dispatch");

    const unsigned savedCsr = _mm_getcsr();
    unsigned short cw0 = 0, cw1 = 0;
    __asm fnstcw cw0
    _mm_setcsr(0x5F80u);
    Plain q(32, 2);
    g_main_in = false;
    run(&q, body_csr, 32);
    const unsigned csr = _mm_getcsr();
    __asm fnstcw cw1
    _mm_setcsr(savedCsr);
    require(q.fin == 32, "csr dispatch completed");
    require(csr == 0x5F80u, "caller MXCSR restored by the dispatch", csr);
    require(cw0 == cw1, "x87 control word untouched", cw1);
    pool_shutdown_clean(W);
    Plain fallback(1, 3);
    _mm_setcsr(0x5F80u);
    run(&fallback, body_csr, 1);
    const unsigned inlineCsr = _mm_getcsr();
    _mm_setcsr(savedCsr);
    require(fallback.fin == 1 && fallback.hits[0] == 1, "inline FP dispatch completes exactly once");
    require(inlineCsr == 0x5F80u, "inline dispatch preserves caller MXCSR", inlineCsr);
    std::puts("ok: nonvolatile registers, stack, DF, MXCSR and x87 control word preserved");
}

// ---------------------------------------------------------------------------------------- startup callback
namespace {
struct InitProbe {
    std::atomic<uint32_t> calls[NTW_POOL_MAX_WORKERS];
    std::atomic<DWORD> tid[NTW_POOL_MAX_WORKERS];
    std::atomic<uint32_t> total{0}, bad_ctx{0}, bad_thread{0}, bad_index{0};
    std::atomic<uint32_t> bodies_before_init{0};
    uint32_t workers = 0;
    uint32_t fail_mask = 0;      // bit i: callback of worker i fails
    uint32_t slow_index = ~0u;   // callback of this worker sleeps before returning
    DWORD main_tid = 0;
    InitProbe() { reset(); }
    void reset() {
        for (auto& c : calls) c = 0;
        for (auto& t : tid) t = 0;
        total = bad_ctx = bad_thread = bad_index = bodies_before_init = 0;
        workers = fail_mask = 0;
        slow_index = ~0u;
    }
};
InitProbe g_probe;
constexpr uint32_t kProbeContext = 0xC0DEF00Du;

uint32_t __stdcall probe_init(uint32_t context, uint32_t index) {
    if (context != kProbeContext) ++g_probe.bad_ctx;
    if (index >= g_probe.workers || index >= NTW_POOL_MAX_WORKERS) {
        ++g_probe.bad_index;
        return 0xBAD1u;
    }
    if (GetCurrentThreadId() == g_probe.main_tid) ++g_probe.bad_thread;  // must run on the created worker
    g_probe.tid[index] = GetCurrentThreadId();
    if (index == g_probe.slow_index) Sleep(150);
    g_probe.calls[index].fetch_add(1);
    g_probe.total.fetch_add(1);
    return (g_probe.fail_mask >> index) & 1u ? 0xE000u + index : 0u;
}

// Body that proves every worker that executes it already ran its startup callback, on this same thread.
void __fastcall body_probe(void* c, uint32_t i) {
    auto* p = static_cast<Plain*>(c);
    p->hits[i].fetch_add(1);
    if (GetCurrentThreadId() != g_probe.main_tid) {
        bool found = false;
        for (uint32_t w = 0; w != g_probe.workers; ++w) found |= (g_probe.tid[w] == GetCurrentThreadId() && g_probe.calls[w] == 1);
        if (!found) ++g_probe.bodies_before_init;
    }
    p->out[i] = mix(p->seed, i);
    p->fin.fetch_add(1);
}

ntw_pool_config make_init_cfg(uint32_t workers, uint32_t failMask = 0, uint32_t slowIndex = ~0u) {
    g_probe.reset();
    g_probe.workers = workers;
    g_probe.fail_mask = failMask;
    g_probe.slow_index = slowIndex;
    g_probe.main_tid = GetCurrentThreadId();
    ntw_pool_config c = make_cfg(workers);
    c.thread_init = reinterpret_cast<uint32_t>(&probe_init);
    c.thread_init_context = kProbeContext;
    return c;
}

void require_workers_called_once(uint32_t workers, const char* what) {
    require(g_probe.total == workers && g_probe.bad_ctx == 0 && g_probe.bad_thread == 0 && g_probe.bad_index == 0, what, g_probe.total);
    for (uint32_t w = 0; w != workers; ++w) require(g_probe.calls[w] == 1 && g_probe.tid[w] != 0, "callback exactly once per worker", w);
    for (uint32_t a = 0; a != workers; ++a)
        for (uint32_t b = a + 1; b != workers; ++b) require(g_probe.tid[a] != g_probe.tid[b], "callbacks ran on distinct worker threads", a);
}

// All storage outside the retained startup diagnostics is zero after an unwound callback failure.
void require_unwound_with_diagnostics(uint32_t workers, uint32_t failMask, uint32_t completed, const char* what) {
    const unsigned char* raw = reinterpret_cast<const unsigned char*>(P);
    const size_t resultOffset = offsetof(ntw_pool_slot, init_result);
    require(P->state == NTW_POOL_S_UNINIT && P->workers == 0 && P->created == 0 && P->done == 0 && P->stop == 0, what);
    for (size_t off = 0; off != sizeof(*P); ++off) {
        const bool diag = off >= offsetof(ntw_pool, init_completed) && off < offsetof(ntw_pool, init_completed) + 4 ||
                          off >= offsetof(ntw_pool, init_failed) && off < offsetof(ntw_pool, init_failed) + 4;
        bool result = false;
        if (off >= offsetof(ntw_pool, slots) && off < offsetof(ntw_pool, slots) + sizeof(P->slots)) {
            const size_t in = (off - offsetof(ntw_pool, slots)) % sizeof(ntw_pool_slot);
            result = in >= resultOffset && in < resultOffset + 4;
        }
        require(diag || result || raw[off] == 0, "failed init leaked state outside diagnostics", off);
    }
    uint32_t expectFailed = 0;
    for (uint32_t w = 0; w != NTW_POOL_MAX_WORKERS; ++w) {
        const bool fail = w < workers && ((failMask >> w) & 1u);
        expectFailed += fail;
        require(P->slots[w].init_result == (fail ? 0xE000u + w : 0u), "per-slot startup result survives unwind", w);
    }
    require(P->init_failed == expectFailed && P->init_completed == completed, "aggregate startup diagnostics survive unwind", P->init_completed);
}
}  // namespace

static void test_thread_init_success() {
    const DWORD h0 = process_handles();
    const unsigned t0 = process_threads();
    for (uint32_t W : {1u, 4u, NTW_POOL_MAX_WORKERS}) {
        reset_counters();
        // Slow callback on the last worker: init must not return (nor publish READY) before it finishes.
        const ntw_pool_config cfg = make_init_cfg(W, 0, W - 1);
        std::atomic<bool> stopWatch{false};
        std::atomic<uint32_t> premature{0};
        std::thread watcher([&] {
            while (!stopWatch.load()) {
                if (*reinterpret_cast<volatile uint32_t*>(&P->state) == NTW_POOL_S_READY && g_probe.total != W) ++premature;
                Sleep(0);
            }
        });
        const uint32_t r = g.init(P, &cfg);
        stopWatch = true;
        watcher.join();
        require(r == NTW_POOL_OK, "init with startup callback", r);
        require(premature == 0, "READY published before every startup callback finished", premature);
        require(g_probe.total == W, "every callback finished before init returned", g_probe.total);
        require_workers_called_once(W, "startup callback arguments");
        require(P->state == NTW_POOL_S_READY && P->workers == W && P->created == W, "pool state after callback init");
        require(P->init_completed == W && P->init_failed == 0 && P->thread_init == cfg.thread_init && P->thread_init_context == kProbeContext,
                "success diagnostics", P->init_completed);
        for (uint32_t w = 0; w != W; ++w) require(P->slots[w].init_result == 0, "success slot result", w);
        require(P->outstanding == 0, "startup barrier fully released", P->outstanding);

        // Work: every body runs after its worker's callback; the callback is not repeated per dispatch.
        for (int round = 0; round != 8; ++round) {
            Plain p(W + 5, 40u + round);
            run(&p, body_probe, W + 5);
            require(p.oob == 0 && p.fin == p.n, "callback pool dispatch completed", p.fin);
            for (uint32_t i = 0; i != p.n; ++i) require(p.hits[i] == 1 && p.out[i] == mix(p.seed, i), "callback pool chunk exact once", i);
        }
        Rdv r2(W + 1);
        run(&r2, body_rdv, W + 1);  // proves all W callback-initialised workers participate concurrently
        require(g_probe.bodies_before_init == 0, "a body ran on a worker whose callback had not completed", g_probe.bodies_before_init);
        require(g_probe.total == W, "callbacks must not run again during dispatch", g_probe.total);
        pool_shutdown_clean(W);
        require(g_probe.total == W, "callbacks must not run again during shutdown", g_probe.total);
        require(all_zero(P, sizeof(*P)), "successful shutdown zeroes the diagnostics too");
    }

    // No callback: existing behavior, startup completion still counted, results zero, context ignored.
    reset_counters();
    g_probe.reset();
    ntw_pool_config plain = make_cfg(3);
    plain.thread_init_context = kProbeContext;
    require(g.init(P, &plain) == NTW_POOL_OK, "init without callback");
    require(P->thread_init == 0 && P->init_completed == 3 && P->init_failed == 0 && g_probe.total == 0, "no-callback diagnostics");
    for (uint32_t w = 0; w != 3; ++w) require(P->slots[w].init_result == 0, "no-callback slot result", w);
    Plain p(20, 9);
    run(&p, body_plain, 20);
    verify_plain(p, "no-callback dispatch");
    pool_shutdown_clean(3);
    require(process_handles() <= h0, "process handle count after callback cycles", process_handles());
    expect_threads(t0, "process thread count after callback cycles");
    std::puts("ok: startup callback ran exactly once per worker thread before work, init waited, READY after success");
}

static void test_thread_init_failure() {
    const DWORD h0 = process_handles();
    const unsigned t0 = process_threads();
    const uint32_t W = 5;
    // Single failures at every index, plus an all-fail team and a mixed team.
    std::vector<uint32_t> masks;
    for (uint32_t w = 0; w != W; ++w) masks.push_back(1u << w);
    masks.push_back((1u << W) - 1u);
    masks.push_back(0x0Au);
    for (uint32_t mask : masks) {
        reset_counters();
        const ntw_pool_config cfg = make_init_cfg(W, mask, 1);
        const uint32_t r = g.init(P, &cfg);
        require(r == NTW_POOL_E_INIT, "callback failure returns NTW_POOL_E_INIT", r);
        require_workers_called_once(W, "every worker initialised exactly once even though some failed");
        require(g_threads_joined == static_cast<long>(W) && g_events_closed == static_cast<long>(W) + 1,
                "failed startup joined every thread and closed every event", g_threads_joined);
        require(live_of(1) == 0 && live_of(2) == 0, "failed startup leaked a tracked handle", mask);
        require_unwound_with_diagnostics(W, mask, W, "failed callback init state");
        require(process_handles() <= h0, "process handle count after failed callback init", process_handles());
        expect_threads(t0, "process thread count after failed callback init");

        // The failed pool refuses the team (serial fallback) and the storage stays reusable.
        Plain inlineRun(12, 3);
        const uint32_t inlineBefore = P->st_inline;
        run(&inlineRun, body_plain, 12);
        verify_plain(inlineRun, "dispatch on a pool whose startup failed");
        require(P->st_inline == inlineBefore + 1, "unready dispatch counted inline");
        require(g.shutdown(P) == NTW_POOL_E_STATE, "shutdown of a failed-init pool");
    }

    // Failure injected into resource creation after callbacks started: unwind preserves what ran, exactly once.
    for (int kind = 0; kind != 2; ++kind) {
        const long points = kind == 0 ? 1 + W : W;
        for (long at = 1; at <= points; ++at) {
            reset_counters();
            ntw_pool_config cfg = make_init_cfg(W);
            (kind == 0 ? g_fail_event_at : g_fail_thread_at) = at;
            const uint32_t r = g.init(P, &cfg);
            require(r == (kind == 0 ? NTW_POOL_E_EVENT : NTW_POOL_E_THREAD), "resource failure code with callback", r);
            const long made = kind == 0 ? (at >= 2 ? at - 2 : 0) : at - 1;
            require(g_threads_joined == made && live_of(1) == 0 && live_of(2) == 0, "partial callback init leaked a handle", at);
            require(g_probe.total == static_cast<uint32_t>(made), "created workers, and only those, ran the callback", g_probe.total);
            for (long w = 0; w != made; ++w) require(g_probe.calls[w] == 1, "partial callback exactly once", w);
            for (long w = made; w != NTW_POOL_MAX_WORKERS; ++w) require(g_probe.calls[w] == 0, "callback for an uncreated worker", w);
            require_unwound_with_diagnostics(W, 0, static_cast<uint32_t>(made), "partial callback init state");
            require(process_handles() <= h0, "handles after partial callback init", process_handles());
            expect_threads(t0, "threads after partial callback init");
        }
    }

    // A later successful init on the same storage starts from clean diagnostics.
    reset_counters();
    const ntw_pool_config again = make_init_cfg(W);
    require(g.init(P, &again) == NTW_POOL_OK, "init after failed callback init");
    require(P->init_completed == W && P->init_failed == 0, "diagnostics reset by next init");
    for (uint32_t w = 0; w != W; ++w) require(P->slots[w].init_result == 0, "stale failure result survived next init", w);
    Plain p(50, 4);
    run(&p, body_probe, 50);
    require(p.fin == 50 && g_probe.bodies_before_init == 0, "dispatch after recovered init", p.fin);
    pool_shutdown_clean(W);

    // The callback result is observable by a status copy taken after the unwound failure.
    reset_counters();
    const ntw_pool_config copyCfg = make_init_cfg(W, 0x14u);
    require(g.init(P, &copyCfg) == NTW_POOL_E_INIT, "failure for the status copy");
    ntw_pool statusCopy;
    std::memcpy(&statusCopy, P, sizeof statusCopy);
    require(statusCopy.init_failed == 2 && statusCopy.slots[2].init_result == 0xE002u && statusCopy.slots[4].init_result == 0xE004u &&
                statusCopy.slots[0].init_result == 0 && statusCopy.state == NTW_POOL_S_UNINIT,
            "failures observable from a copied status");
    std::printf("ok: callback failures return E_INIT, joined %u workers each time, diagnostics survive the safe unwind\n", W);
}

static void test_thread_init_join_failure() {
    const DWORD h0 = process_handles();
    const unsigned t0 = process_threads();
    const uint32_t W = 3;
    reset_counters();
    const ntw_pool_config cfg = make_init_cfg(W, 0x2u);
    g_fail_thread_wait = true;  // the unwind cannot join the workers: handles must be kept, state BROKEN
    require(g.init(P, &cfg) == NTW_POOL_E_JOIN, "unjoinable worker returns E_JOIN");
    require(P->state == NTW_POOL_S_BROKEN && P->created == W && P->stop == 1, "broken pool state", P->state);
    require(live_of(2) == W && live_of(1) == W + 1 && g_threads_joined == 0, "nothing closed for unjoinable workers");
    require(g.init(P, &cfg) == NTW_POOL_E_STATE, "init on a broken pool");
    require(g.shutdown(P) == NTW_POOL_E_JOIN && P->state == NTW_POOL_S_BROKEN, "retry still unjoinable keeps the pool broken");
    require(live_of(2) == W, "retry did not close handles it could not join");

    g_fail_thread_wait = false;
    require(g.shutdown(P) == NTW_POOL_OK, "shutdown retry joins and releases a broken pool");
    require(live_of(1) == 0 && live_of(2) == 0 && g_threads_joined == static_cast<long>(W) && g_events_closed == static_cast<long>(W) + 1,
            "broken pool resources released by retry");
    require_workers_called_once(W, "callbacks exactly once across broken unwind");
    require_unwound_with_diagnostics(W, 0x2u, W, "retried teardown keeps startup diagnostics");
    require(process_handles() <= h0, "handles after broken pool retry", process_handles());
    expect_threads(t0, "threads after broken pool retry");
    std::puts("ok: E_JOIN keeps handles/diagnostics, shutdown retry completes the unwind");
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* e) -> LONG {
        std::fprintf(stderr, "native fault: code=%08lx eip=%08lx copied-code=%p eax=%08lx ecx=%08lx edx=%08lx\n",
            e->ExceptionRecord->ExceptionCode, e->ContextRecord->Eip, g.copy,
            e->ContextRecord->Eax, e->ContextRecord->Ecx, e->ContextRecord->Edx);
        return EXCEPTION_EXECUTE_HANDLER;
    });
    if (argc < 2) {
        std::fprintf(stderr, "usage: native_worker_dispatch_smoke HELPER.dll\n");
        return 2;
    }
    g = load_code(argv[1]);
    g_expected_entry = g.worker_entry;
    Sleep(250);  // let loader-owned startup threads settle before the thread/handle baselines are taken
    test_static_contract();
    test_partial_init();
    test_lifecycle_and_idle();
    test_exact_once_and_reuse();
    test_concurrency();
    test_misuse();
    test_abi_state_preservation();
    test_thread_init_success();
    test_thread_init_failure();
    test_thread_init_join_failure();
    require(live_of(1) == 0 && live_of(2) == 0, "no tracked handle left at exit");
    std::puts("PASS: native worker dispatch smoke");
    return 0;
}
