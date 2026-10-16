/*
 * ntw2.exe - native launcher for the Napoleon Total War x86 multithreading runtime.
 *
 * Flow: locate game directory (argument or prompt) -> validate Napoleon.exe (PE32/i386 + SHA-256 pin, streamed, no heap
 * copy) -> validate the adjacent runtime DLL (PE32/i386 DLL, start/stop/state/profile/trace exports, file-mapped, no
 * heap copy) -> refuse if any Napoleon.exe is already running -> CreateProcessW the game -> wait for loader stability ->
 * verify the remote lifetime (image file identity, main module base) -> remote LoadLibraryW of the runtime DLL ->
 * verify the remote module against the local file -> remote ntw2_start(config) -> monitor ntw2_state until game exit,
 * Ctrl+C or --observe-seconds.  Activation is only reported when the in-process status says ACTIVE with every requested
 * feature bit set. Game files are read-only; outputs are --receipt and its .profile.bin / .ticks.bin companions.
 *
 * Contract with ntw2_runtime.dll (include/ntw2_runtime.h):
 *   ntw2_start  (_ntw2_start@4)  WINAPI thread entry, param = pointer to ntw2_config in the game; returns 0 on success.
 *   ntw2_stop   (_ntw2_stop@4)   WINAPI thread entry; returns 0 on success.
 *   ntw2_state  (DATA export)    an ntw2_status object (128 bytes, sequence-locked); read with ReadProcessMemory.
 *   ntw2_trace  (DATA export)    966688-byte little-endian tick ring (ABI 8, 112 sites + raw gate QPC); live snapshots are observational.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "loco/native_loco.h" /* C-compatible labels for all append-only LOCO status rows. */
#include "loco/native_sweep.h"
#include "loco/native_resolve.h"
#include "loco/native_env.h"
#include "brain2/native_node.h"
#include "brain2/native_move_node.h"
#include "brain2/native_idle_node.h"
#include "brain2/native_action_node.h"
#include "brain2/native_fire.h"
#include "brain2/native_brain_workers.h"
#include "brain2/native_unit_brain.h"
#include "army/native_army_unit.h"
#include "collision/native_contact.h"

#include "ntw2_runtime.h"
#include "../src/ntw2_profile.h"

#if !defined(_M_IX86) && !defined(__i386__)
#error "ntw2.exe must be built as a 32-bit x86 executable: it resolves 32-bit system exports for the 32-bit game process."
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#ifndef NTW2_RUNTIME_DLL_NAME
#define NTW2_RUNTIME_DLL_NAME "ntw2_runtime.dll"
#endif
#define NTW2_WIDEN2(x) L##x
#define NTW2_WIDEN(x) NTW2_WIDEN2(x)
#define RUNTIME_DLL_NAME NTW2_WIDEN(NTW2_RUNTIME_DLL_NAME)

#define GAME_EXE_NAME L"Napoleon.exe"
#define MAXP 4096u

enum {
    EXIT_OK = 0,
    EXIT_USAGE = 1,
    EXIT_VALIDATE = 2,     /* game or runtime DLL missing / unsupported */
    EXIT_CONFLICT = 3,     /* a Napoleon.exe is already running */
    EXIT_LAUNCH = 4,       /* CreateProcessW failed or the game died before install */
    EXIT_INSTALL = 5,      /* remote load / verification / ntw2_start failed */
    EXIT_RUNTIME_FAILED = 6,   /* runtime reported FAILED (or stopped unexpectedly) */
    EXIT_NOT_ACTIVE = 7,   /* armed, but all requested features never became ACTIVE */
    EXIT_INTERRUPTED = 8,  /* Ctrl+C: runtime stop requested and completed */
    EXIT_STOP_FAILED = 9,  /* Ctrl+C: runtime stop failed or timed out */
    EXIT_RECEIPT = 10,     /* everything else succeeded but the receipt could not be written */
    EXIT_GAME_STOP_FAILED = 11 /* owned game did not exit after the observation bound */
};

/* ------------------------------------------------------------------------------------------------ console output */
static HANDLE g_hout, g_herr, g_hin;
static BOOL g_out_con, g_err_con, g_in_con;

static void emit(HANDLE h, BOOL con, const wchar_t *s, size_t n)
{
    DWORD w;
    if (!h || h == INVALID_HANDLE_VALUE || n == 0) return;
    if (con) {
        WriteConsoleW(h, s, (DWORD)n, &w, NULL);
    } else {
        static char u8[MAXP * 4];
        int len = WideCharToMultiByte(CP_UTF8, 0, s, (int)n, u8, (int)sizeof u8, NULL, NULL);
        if (len > 0) WriteFile(h, u8, (DWORD)len, &w, NULL);
    }
}

static void vsay(HANDLE h, BOOL con, const wchar_t *prefix, const wchar_t *fmt, va_list ap)
{
    static wchar_t buf[MAXP];
    int n = 0;
    if (prefix) n = _snwprintf_s(buf, MAXP, _TRUNCATE, L"%ls", prefix);
    if (n < 0) n = 0;
    {
        int m = _vsnwprintf_s(buf + n, MAXP - (size_t)n, _TRUNCATE, fmt, ap);
        if (m < 0) m = (int)wcslen(buf + n);
        n += m;
    }
    emit(h, con, buf, (size_t)n);
}

static void say(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(g_hout, g_out_con, NULL, fmt, ap);
    va_end(ap);
}

static void errsay(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsay(g_herr, g_err_con, L"ntw2: error: ", fmt, ap);
    va_end(ap);
}

static void init_console(void)
{
    DWORD mode;
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_herr = GetStdHandle(STD_ERROR_HANDLE);
    g_hin = GetStdHandle(STD_INPUT_HANDLE);
    g_out_con = g_hout && g_hout != INVALID_HANDLE_VALUE && GetConsoleMode(g_hout, &mode);
    g_err_con = g_herr && g_herr != INVALID_HANDLE_VALUE && GetConsoleMode(g_herr, &mode);
    g_in_con = g_hin && g_hin != INVALID_HANDLE_VALUE && GetConsoleMode(g_hin, &mode);
}

static void win_message(DWORD e, wchar_t *out, size_t n)
{
    DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e, 0, out, (DWORD)n, NULL);
    while (len && (out[len - 1] == L'\r' || out[len - 1] == L'\n' || out[len - 1] == L' ')) out[--len] = 0;
    if (!len) _snwprintf_s(out, n, _TRUNCATE, L"Windows error");
}

/* "<what> failed: <message> (Win32 <code>)" on stderr. */
static void win_fail(const wchar_t *what, DWORD e)
{
    wchar_t m[512];
    win_message(e, m, 512);
    errsay(L"%ls failed: %ls (Win32 %lu)\n", what, m, (unsigned long)e);
}

/* ------------------------------------------------------------------------------------------------ run state */
typedef struct FileId {
    DWORD volume, hi, lo;
} FileId;

typedef struct Options {
    wchar_t game[MAXP];
    wchar_t replay[MAXP];
    wchar_t receipt[MAXP];
    wchar_t tick_log[MAXP];
    uint32_t mask;
    uint32_t workers;
    uint32_t poll_ms;
    uint32_t profile_site;    /* 0 = sampler gated on the whole tick; else timed site index + 1 */
    uint32_t collide_lod_m;   /* far-unit surface separation in world metres */
    BOOL collide_census;     /* expensive per-pair collision profiling, independent opt-in */
    BOOL brain_census;       /* BRAIN2 v2 serial gated clones and service bookkeeping. */
    BOOL brain_timing;       /* Independent opt-in QPC; default off. */
    BOOL brain_node_shadow;  /* Detached owner-only reference-node differential proof. */
    BOOL brain_fire_shadow;  /* Detached owner-only request-sequencer differential proof. */
    BOOL brain_finalizer_shadow; /* Owner-only private-copy rerun of proved 0x819770 calls, bit-exact compare. */
    BOOL brain_parallel;     /* BRAIN2 Stage 2: per-soldier brain step on pool workers with guarded owner commit; requires census or quiet. */
    BOOL brain_quiet;        /* --brain-quiet: performance mode of --brain-parallel; owner runs the original step, no census/QPC bookkeeping. */
    BOOL brain_unit_shadow;  /* --brain-unit-shadow: per-unit brain Stage A; UnitDecision vs each soldier's native step, shadow only. */
    BOOL collide_contact_shadow;  /* --collide-contact-shadow: plan contact callbacks on workers, owner runs and compares the original. */
    BOOL collide_contact_workers; /* --collide-contact-workers: same-team contact decisions on workers, owner replays effects in order. */
    BOOL loco_clone;         /* --loco-clone: NTW2_LOCO executes admitted movement through the private clone family (ntw2_config::loco_flags) */
    BOOL loco_parallel;      /* --loco-parallel: closed movement workers; requires loco and --loco-clone */
    BOOL loco_shadow;        /* Owner-thread validation; never selects port results. */
    BOOL loco_owned;         /* --loco-owned-services: opt-in supported active mover path; requires loco, --loco-clone and --loco-parallel */
    BOOL loco_quiet;         /* --loco-quiet: low-overhead owned mode; no service QPC, shadow comparisons or all-gates histogram; requires --loco-owned-services */
    BOOL loco_grid;          /* --loco-grid: owned soldier grid v2, published at site-13 exit; default off */
    BOOL loco_grid_verify;   /* --loco-grid-verify: implies grid; owner-side verification */
    BOOL grid_probation;     /* --grid-probation: native cell-head trap detector; requires --loco-grid (or verify), not ballistic */
    uint32_t observe_s;       /* 0 = until the game exits */
    uint32_t inject_timeout_s;
    BOOL activate;
    BOOL validate_only;
    BOOL focus;
    BOOL exit_game_after_observe;
} Options;

static uint32_t loco_flags_from(const Options *o)
{
    return (o->loco_clone ? NTW2_LOCO_CLONE : 0u) | (o->loco_parallel ? NTW2_LOCO_PARALLEL : 0u) | (o->loco_shadow ? NTW2_LOCO_SHADOW : 0u) |
           (o->loco_owned ? NTW2_LOCO_OWNED_SERVICES : 0u) | (o->loco_quiet ? NTW2_LOCO_QUIET : 0u) |
           ((o->loco_grid || o->loco_grid_verify) ? NTW2_LOCO_GRID : 0u) | (o->loco_grid_verify ? NTW2_LOCO_GRID_VERIFY : 0u) |
           (o->grid_probation ? NTW2_LOCO_GRID_PROBATION : 0u);
}

/* Quiet overrides owner shadow comparisons even when --loco-shadow is also supplied. */
static BOOL loco_shadow_effective(const Options *o)
{
    return o->loco_shadow && !o->loco_quiet;
}

typedef struct DllInfo {
    uint32_t ts, size_of_image, checksum;
    uint32_t dir_rva, dir_size;
    uint32_t start_rva, stop_rva, state_rva, profile_rva, trace_rva;
} DllInfo;

typedef struct TickTrace {
    /* Two slots in one allocation: a partial remote read must not destroy the last complete copy. */
    ntw2_trace_ring copies[2];
    uint32_t current;
    BOOL have, finalized, analyzed;
    uint32_t count, first_tick, last_tick, duration[4], interval[4], over100, over150;
    uint32_t mod100[10], mod10[10], top[16], top_count;
    uint64_t duration_sum, manager_sum, ballistics_sum, path_sum;
    uint64_t site_sum[NTW2_TIMED_SITES], site_calls[NTW2_TIMED_SITES];
    uint32_t timed_ticks;
    int64_t remainder_sum;
    uint32_t scratch[NTW2_TRACE_ENTRIES];
} TickTrace;

#define TICK_LOG_MAX_ENTRIES 200000u
typedef struct TickLog {
    ntw2_trace_entry *entries;
    uint32_t count, capacity, written;
    uint64_t lost;
    BOOL failed;
    char *receipt_storage;
    size_t receipt_capacity;
} TickLog;

typedef struct Run {
    Options opt;
    wchar_t game_dir[MAXP];
    wchar_t exe_path[MAXP];
    wchar_t dll_path[MAXP];
    char exe_sha[65];
    char dll_sha[65];
    uint64_t exe_size, dll_size;
    FileId exe_id;
    HANDLE exe_file;   /* held share-read-only from validation until the game is set up: no swap/modify window */
    HANDLE dll_file;
    DllInfo dll;
    HANDLE proc;
    DWORD pid;
    FILETIME created;
    uint32_t exe_base, dll_base, state_addr;
    ntw2_config cfg;
    ntw2_status last;
    uint32_t crash_tag;   /* acknowledgement tag of the last crash_words state printed (see ntw2_runtime.h crash_words[31]) */
    BOOL have_status, ever_armed, ever_full, stop_requested, stop_confirmed;
    BOOL game_exited;
    DWORD game_exit;
    BOOL observation_complete, game_close_requested, game_terminated;
    DWORD game_close_windows, game_stop_error;
    uint64_t observed_ms, status_samples, battle_tick_advance;
    uint32_t active_generations, last_active_generation, battle_returns, battle_reactivations;
    uint32_t peak_workers, peak_storage_bytes, peak_retained_bytes;
    BOOL battle_active, waiting_after_active;
    BOOL remote_leaked;   /* a remote thread timed out; its memory is intentionally never freed */
    const wchar_t *outcome;
    FILETIME t_start;
    ntw2_profile_status profile;
    uint32_t *profile_arrays;
    BOOL have_profile;
    TickTrace *trace;
    TickLog tick_log;
} Run;

static Run g_run;
static volatile LONG g_stop;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

/* ------------------------------------------------------------------------------------------------ small helpers */
static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static const wchar_t *phase_name(uint32_t p)
{
    switch (p) {
    case NTW2_IDLE: return L"IDLE";
    case NTW2_VERIFYING: return L"VERIFYING";
    case NTW2_WAITING_BATTLE: return L"WAITING_BATTLE";
    case NTW2_ACTIVATING: return L"ACTIVATING";
    case NTW2_ACTIVE: return L"ACTIVE";
    case NTW2_RESTORING: return L"RESTORING";
    case NTW2_FAILED: return L"FAILED";
    case NTW2_STOPPED: return L"STOPPED";
    default: return L"UNKNOWN";
    }
}

static const struct { uint32_t bit; const wchar_t *name; const char *jname; } k_features[] = {
    { NTW2_PATH, L"path", "path" },
    { NTW2_FORMATION, L"formation", "formation" },
    { NTW2_BALLISTICS, L"ballistics", "ballistics" },
    { NTW2_AI_ASYNC, L"ai", "ai" },
    { NTW2_AI_CTRL, L"ai_ctrl", "ai_ctrl" },
    { NTW2_BATCH64, L"batch64", "batch64" },
    { NTW2_BRAIN2, L"brain2", "brain2" },
    { NTW2_VISUAL, L"visual", "visual" },
    { NTW2_COLLIDE, L"collide", "collide" },
    { NTW2_COLLIDE_LOD, L"collide_lod", "collide_lod" },
    { NTW2_PROFILE, L"profile", "profile" },
    { NTW2_BRAIN, L"brain", "brain" },
    { NTW2_LOCO, L"loco", "loco" },
    { NTW2_GRID_CENSUS, L"grid_census", "grid_census" },
    { NTW2_AI_CENSUS, L"ai_census", "ai_census" },
    { NTW2_AI_ASYNC2, L"ai_async2", "ai_async2" },
    { NTW2_ARMY_UNIT_SHADOW, L"army_unit_shadow", "army_unit_shadow" },
};
#define NFEATURES (sizeof k_features / sizeof k_features[0])

static void mask_str(uint32_t m, wchar_t *out, size_t n)
{
    size_t i, used = 0;
    out[0] = 0;
    for (i = 0; i < NFEATURES; ++i) {
        if (m & k_features[i].bit) {
            int w = _snwprintf_s(out + used, n - used, _TRUNCATE, L"%ls%ls", used ? L"," : L"", k_features[i].name);
            if (w < 0) return;
            used += (size_t)w;
        }
    }
    if (!used) _snwprintf_s(out, n, _TRUNCATE, L"none");
}

static uint64_t now_ms(void) { return GetTickCount64(); }

static BOOL file_id_handle(HANDLE h, FileId *id)
{
    BY_HANDLE_FILE_INFORMATION i;
    if (!GetFileInformationByHandle(h, &i)) return FALSE;
    id->volume = i.dwVolumeSerialNumber;
    id->hi = i.nFileIndexHigh;
    id->lo = i.nFileIndexLow;
    return TRUE;
}

static BOOL file_id_path(const wchar_t *path, FileId *id)
{
    BOOL ok;
    HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = file_id_handle(h, id);
    CloseHandle(h);
    return ok;
}

static BOOL same_id(const FileId *a, const FileId *b) { return a->volume == b->volume && a->hi == b->hi && a->lo == b->lo; }

static BOOL read_at(HANDLE h, uint64_t off, void *buf, DWORD len)
{
    OVERLAPPED ov;
    DWORD got = 0;
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
    ov.OffsetHigh = (DWORD)(off >> 32);
    if (!ReadFile(h, buf, len, &got, &ov)) return FALSE;
    return got == len;
}

/* SHA-256 of the whole file through one reusable 256 KiB buffer (no whole-file allocation). */
static BOOL sha256_handle(HANDLE h, char out_hex[65], uint64_t *size_out, DWORD *win_err, NTSTATUS *nt_err)
{
    static uint8_t iobuf[256 * 1024];
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t *obj = NULL, digest[32];
    DWORD objlen = 0, cb = 0, got;
    LARGE_INTEGER zero;
    uint64_t total = 0;
    NTSTATUS st;
    BOOL ok = FALSE;

    *win_err = 0;
    *nt_err = 0;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(h, zero, NULL, FILE_BEGIN)) { *win_err = GetLastError(); return FALSE; }
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st < 0) { *nt_err = st; return FALSE; }
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen, sizeof objlen, &cb, 0);
    if (st < 0) { *nt_err = st; goto done; }
    obj = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, objlen);
    if (!obj) { *win_err = ERROR_OUTOFMEMORY; goto done; }
    st = BCryptCreateHash(alg, &hash, obj, objlen, NULL, 0, 0);
    if (st < 0) { *nt_err = st; goto done; }
    for (;;) {
        if (!ReadFile(h, iobuf, sizeof iobuf, &got, NULL)) { *win_err = GetLastError(); goto done; }
        if (got == 0) break;
        st = BCryptHashData(hash, iobuf, got, 0);
        if (st < 0) { *nt_err = st; goto done; }
        total += got;
    }
    st = BCryptFinishHash(hash, digest, sizeof digest, 0);
    if (st < 0) { *nt_err = st; goto done; }
    hex(digest, sizeof digest, out_hex);
    *size_out = total;
    ok = TRUE;
done:
    if (hash) BCryptDestroyHash(hash);
    if (obj) HeapFree(GetProcessHeap(), 0, obj);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static void report_hash_failure(const wchar_t *what, DWORD we, NTSTATUS ne)
{
    if (ne < 0) errsay(L"hashing %ls failed: BCrypt status 0x%08lX\n", what, (unsigned long)ne);
    else win_fail(what, we);
}

/* ------------------------------------------------------------------------------------------------ PE validation */
static const wchar_t *check_pe32_header(const uint8_t *b, size_t n, BOOL want_dll, const IMAGE_NT_HEADERS32 **nt_out)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)b;
    const IMAGE_NT_HEADERS32 *nt;
    if (n < sizeof *dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return L"missing MZ header";
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew + sizeof *nt > n) return L"PE header offset out of range";
    nt = (const IMAGE_NT_HEADERS32 *)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return L"missing PE signature";
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return L"not an x86 (i386) image";
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return L"not a PE32 image";
    if (want_dll && !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) return L"not a DLL";
    if (!want_dll && (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) return L"is a DLL, not an executable";
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) return L"not an executable image";
    *nt_out = nt;
    return NULL;
}

typedef const uint8_t *(*rva_fn)(void *ctx, uint32_t rva, uint32_t len);

/* Finds the named, non-forwarded exports; names and rvas have n entries each. */
static const wchar_t *find_exports(rva_fn f, void *ctx, uint32_t dir_rva, uint32_t dir_size, const char *const *names,
                                   size_t n, uint32_t *rvas)
{
    const IMAGE_EXPORT_DIRECTORY *d;
    const uint8_t *nm, *ords, *funcs;
    uint32_t i;
    size_t k, found = 0;
    if (!dir_rva || dir_size < sizeof *d) return L"no export directory";
    d = (const IMAGE_EXPORT_DIRECTORY *)f(ctx, dir_rva, sizeof *d);
    if (!d) return L"export directory is not readable";
    if (d->NumberOfNames == 0 || d->NumberOfNames > 65536 || d->NumberOfFunctions == 0 || d->NumberOfFunctions > 65536)
        return L"export directory counts are invalid";
    nm = f(ctx, d->AddressOfNames, d->NumberOfNames * 4u);
    ords = f(ctx, d->AddressOfNameOrdinals, d->NumberOfNames * 2u);
    funcs = f(ctx, d->AddressOfFunctions, d->NumberOfFunctions * 4u);
    if (!nm || !ords || !funcs) return L"export tables are not contained in the readable export data";
    for (k = 0; k < n; ++k) rvas[k] = 0;
    for (i = 0; i < d->NumberOfNames; ++i) {
        uint32_t name_rva;
        uint16_t ord;
        memcpy(&name_rva, nm + 4u * i, 4);
        memcpy(&ord, ords + 2u * i, 2);
        for (k = 0; k < n; ++k) {
            size_t l = strlen(names[k]) + 1;
            const uint8_t *s;
            if (rvas[k]) continue;
            s = f(ctx, name_rva, (uint32_t)l);
            if (s && memcmp(s, names[k], l) == 0) {
                uint32_t rva;
                if (ord >= d->NumberOfFunctions) return L"export ordinal out of range";
                memcpy(&rva, funcs + 4u * ord, 4);
                if (rva >= dir_rva && rva < dir_rva + dir_size) return L"a required export is a forwarder";
                if (!rva) return L"a required export has no address";
                rvas[k] = rva;
                ++found;
            }
        }
    }
    return found == n ? NULL : L"a required export is missing";
}

static const char *const k_export_names[5] = { "ntw2_start", "ntw2_stop", "ntw2_state", "ntw2_profile", "ntw2_trace" };

typedef struct LocalCtx {
    const uint8_t *v;
    size_t n;
    const IMAGE_SECTION_HEADER *sec;
    unsigned nsec;
    uint32_t hdr_size;
} LocalCtx;

static const uint8_t *local_rva(void *c, uint32_t rva, uint32_t len)
{
    const LocalCtx *x = (const LocalCtx *)c;
    unsigned i;
    if ((uint64_t)rva + len <= x->hdr_size) return (uint64_t)rva + len <= x->n ? x->v + rva : NULL;
    for (i = 0; i < x->nsec; ++i) {
        const IMAGE_SECTION_HEADER *s = &x->sec[i];
        uint32_t lim = s->SizeOfRawData;
        if (s->Misc.VirtualSize && s->Misc.VirtualSize < lim) lim = s->Misc.VirtualSize;
        if (rva >= s->VirtualAddress && (uint64_t)rva + len <= (uint64_t)s->VirtualAddress + lim) {
            uint64_t off = (uint64_t)s->PointerToRawData + (rva - s->VirtualAddress);
            return off + len <= x->n ? x->v + off : NULL;
        }
    }
    return NULL;
}

static const IMAGE_SECTION_HEADER *section_of(const LocalCtx *x, uint32_t rva)
{
    unsigned i;
    for (i = 0; i < x->nsec; ++i) {
        const IMAGE_SECTION_HEADER *s = &x->sec[i];
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + ext) return s;
    }
    return NULL;
}

static const wchar_t *parse_dll_view(const uint8_t *v, size_t n, DllInfo *out)
{
    const IMAGE_NT_HEADERS32 *nt;
    const wchar_t *why;
    const IMAGE_DATA_DIRECTORY *ed;
    LocalCtx x;
    uint32_t rvas[5];
    const IMAGE_SECTION_HEADER *s;
    size_t sec_end;

    why = check_pe32_header(v, n, TRUE, &nt);
    if (why) return why;
    x.v = v;
    x.n = n;
    x.hdr_size = nt->OptionalHeader.SizeOfHeaders;
    x.nsec = nt->FileHeader.NumberOfSections;
    x.sec = (const IMAGE_SECTION_HEADER *)((const uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    sec_end = (size_t)((const uint8_t *)x.sec - v) + (size_t)x.nsec * sizeof(IMAGE_SECTION_HEADER);
    if (sec_end > n) return L"section table is out of range";
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return L"no export directory";
    ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    why = find_exports(local_rva, &x, ed->VirtualAddress, ed->Size, k_export_names, 5, rvas);
    if (why) return why;
    s = section_of(&x, rvas[0]);
    if (!s || !(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) return L"ntw2_start is not in an executable section";
    s = section_of(&x, rvas[1]);
    if (!s || !(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) return L"ntw2_stop is not in an executable section";
    s = section_of(&x, rvas[2]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"ntw2_state is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[2] + sizeof(ntw2_status) > (uint64_t)s->VirtualAddress + ext)
            return L"ntw2_state is smaller than the ntw2_status ABI";
    }
    s = section_of(&x, rvas[3]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"ntw2_profile is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[3] + sizeof(ntw2_profile_status) > (uint64_t)s->VirtualAddress + ext)
            return L"ntw2_profile is smaller than the profile ABI";
    }
    s = section_of(&x, rvas[4]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"ntw2_trace is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[4] + sizeof(ntw2_trace_ring) > (uint64_t)s->VirtualAddress + ext ||
            (uint64_t)rvas[4] + sizeof(ntw2_trace_ring) > nt->OptionalHeader.SizeOfImage)
            return L"ntw2_trace is smaller than the trace ABI";
    }
    out->ts = nt->FileHeader.TimeDateStamp;
    out->size_of_image = nt->OptionalHeader.SizeOfImage;
    out->checksum = nt->OptionalHeader.CheckSum;
    out->dir_rva = ed->VirtualAddress;
    out->dir_size = ed->Size;
    out->start_rva = rvas[0];
    out->stop_rva = rvas[1];
    out->state_rva = rvas[2];
    out->profile_rva = rvas[3];
    out->trace_rva = rvas[4];
    return NULL;
}

static const wchar_t *parse_dll_guarded(const uint8_t *v, size_t n, DllInfo *out)
{
    const wchar_t *why;
    __try {
        why = parse_dll_view(v, n, out);
    } __except (GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        why = L"I/O error while reading the file mapping";
    }
    return why;
}

/* ------------------------------------------------------------------------------------------------ path helpers */
static void join_path(wchar_t *out, const wchar_t *dir, const wchar_t *leaf)
{
    size_t n = wcslen(dir);
    _snwprintf_s(out, MAXP, _TRUNCATE, L"%ls%ls%ls", dir, (n && dir[n - 1] != L'\\') ? L"\\" : L"", leaf);
}

static BOOL dir_exists(const wchar_t *p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static void trim_input(wchar_t *s)
{
    size_t n = wcslen(s), b = 0;
    while (n && (s[n - 1] == L'\r' || s[n - 1] == L'\n' || s[n - 1] == L' ' || s[n - 1] == L'\t')) s[--n] = 0;
    while (s[b] == L' ' || s[b] == L'\t') ++b;
    if (b) memmove(s, s + b, (n - b + 1) * sizeof(wchar_t));
    n = wcslen(s);
    if (n >= 2 && s[0] == L'"' && s[n - 1] == L'"') {
        memmove(s, s + 1, (n - 2) * sizeof(wchar_t));
        s[n - 2] = 0;
    }
}

/* Resolves the user's text to a directory: a directory, or a path to a file inside it (e.g. the Napoleon.exe itself). */
static BOOL resolve_game_dir(const wchar_t *in, wchar_t *out)
{
    wchar_t full[MAXP];
    DWORD n = GetFullPathNameW(in, MAXP, full, NULL), a;
    size_t len;
    if (n == 0 || n >= MAXP) return FALSE;
    a = GetFileAttributesW(full);
    if (a == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) {
        wchar_t *slash = wcsrchr(full, L'\\');
        if (!slash) return FALSE;
        *slash = 0;
    }
    len = wcslen(full);
    while (len > 3 && full[len - 1] == L'\\') full[--len] = 0;
    if (!dir_exists(full)) return FALSE;
    wcscpy_s(out, MAXP, full);
    return TRUE;
}

/* Suggest the Steam install when it can be found; never required. */
static BOOL suggest_game_dir(wchar_t *out)
{
    static const wchar_t *const keys[] = { L"SOFTWARE\\Valve\\Steam", L"SOFTWARE\\WOW6432Node\\Valve\\Steam" };
    wchar_t steam[MAXP], cand[MAXP], exe[MAXP];
    size_t i;
    for (i = 0; i < 3; ++i) {
        HKEY k;
        DWORD type, sz = sizeof steam - sizeof(wchar_t);
        LONG r;
        steam[0] = 0;
        if (i == 0) r = RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Valve\\Steam", 0, KEY_READ | KEY_WOW64_32KEY, &k);
        else r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i - 1], 0, KEY_READ, &k);
        if (r != ERROR_SUCCESS) continue;
        r = RegQueryValueExW(k, i == 0 ? L"SteamPath" : L"InstallPath", NULL, &type, (LPBYTE)steam, &sz);
        RegCloseKey(k);
        if (r != ERROR_SUCCESS || type != REG_SZ) continue;
        steam[sz / sizeof(wchar_t)] = 0;
        {
            wchar_t *p;
            for (p = steam; *p; ++p) if (*p == L'/') *p = L'\\';
        }
        _snwprintf_s(cand, MAXP, _TRUNCATE, L"%ls\\steamapps\\common\\Napoleon Total War", steam);
        join_path(exe, cand, GAME_EXE_NAME);
        if (GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out, MAXP, cand);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL read_line(wchar_t *buf, DWORD cap)
{
    DWORD n = 0;
    if (!ReadConsoleW(g_hin, buf, cap - 1, &n, NULL)) return FALSE;
    buf[n] = 0;
    trim_input(buf);
    return TRUE;
}

/* ------------------------------------------------------------------------------------------------ game validation */
static BOOL validate_game(Run *r)
{
    uint8_t hdr[1024];
    const IMAGE_NT_HEADERS32 *nt;
    const wchar_t *why;
    DWORD we;
    NTSTATUS ne;
    const IMAGE_DOS_HEADER *dos;
    uint8_t pe[512];
    DWORD e;

    join_path(r->exe_path, r->game_dir, GAME_EXE_NAME);
    r->exe_file = CreateFileW(r->exe_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r->exe_file == INVALID_HANDLE_VALUE) {
        e = GetLastError();
        r->exe_file = NULL;
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            errsay(L"%ls was not found in \"%ls\". Select the folder that contains the Steam Napoleon.exe.\n", GAME_EXE_NAME, r->game_dir);
        else win_fail(L"opening Napoleon.exe for reading", e);
        return FALSE;
    }
    if (!read_at(r->exe_file, 0, hdr, sizeof hdr)) {
        win_fail(L"reading the Napoleon.exe header", GetLastError());
        return FALSE;
    }
    dos = (const IMAGE_DOS_HEADER *)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000) {
        errsay(L"\"%ls\" is not a Windows executable.\n", r->exe_path);
        return FALSE;
    }
    if (!read_at(r->exe_file, (uint64_t)dos->e_lfanew, pe, sizeof pe)) {
        win_fail(L"reading the Napoleon.exe PE header", GetLastError());
        return FALSE;
    }
    /* check_pe32_header expects the DOS header at offset 0: build a compact view in hdr with e_lfanew relocated. */
    {
        IMAGE_DOS_HEADER fake;
        uint8_t view[sizeof(IMAGE_DOS_HEADER) + sizeof pe];
        memset(&fake, 0, sizeof fake);
        fake.e_magic = IMAGE_DOS_SIGNATURE;
        fake.e_lfanew = (LONG)sizeof fake;
        memcpy(view, &fake, sizeof fake);
        memcpy(view + sizeof fake, pe, sizeof pe);
        why = check_pe32_header(view, sizeof view, FALSE, &nt);
        if (why) {
            errsay(L"\"%ls\" is not a supported x86 PE32 executable: %ls.\n", r->exe_path, why);
            return FALSE;
        }
        if (((const IMAGE_NT_HEADERS32 *)(view + sizeof fake))->OptionalHeader.ImageBase != 0x400000u) {
            errsay(L"\"%ls\" has unexpected preferred image base 0x%08lX (supported: 0x00400000).\n", r->exe_path,
                   (unsigned long)((const IMAGE_NT_HEADERS32 *)(view + sizeof fake))->OptionalHeader.ImageBase);
            return FALSE;
        }
    }
    if (!file_id_handle(r->exe_file, &r->exe_id)) {
        win_fail(L"querying Napoleon.exe file identity", GetLastError());
        return FALSE;
    }
    say(L"Hashing %ls ...\n", r->exe_path);
    if (!sha256_handle(r->exe_file, r->exe_sha, &r->exe_size, &we, &ne)) {
        report_hash_failure(L"Napoleon.exe", we, ne);
        return FALSE;
    }
    if (_stricmp(r->exe_sha, NTW2_IMAGE_SHA256) != 0) {
        wchar_t got[65], want[65];
        MultiByteToWideChar(CP_ACP, 0, r->exe_sha, -1, got, 65);
        MultiByteToWideChar(CP_ACP, 0, NTW2_IMAGE_SHA256, -1, want, 65);
        errsay(L"\"%ls\" is not the supported Napoleon.exe.\n  size   : %I64u bytes\n  sha256 : %ls\n  expected: %ls\n"
               L"Only the exact pinned image is supported; the game files were not modified.\n",
               r->exe_path, (unsigned long long)r->exe_size, got, want);
        return FALSE;
    }
    say(L"Supported Napoleon.exe confirmed (x86 PE32, %I64u bytes, SHA-256 match).\n", (unsigned long long)r->exe_size);
    return TRUE;
}

static BOOL validate_runtime(Run *r)
{
    wchar_t self[MAXP];
    wchar_t *slash;
    HANDLE map = NULL;
    const uint8_t *view = NULL;
    LARGE_INTEGER sz;
    const wchar_t *why;
    DWORD we;
    NTSTATUS ne;
    BOOL ok = FALSE;

    if (GetModuleFileNameW(NULL, self, MAXP) == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        win_fail(L"locating ntw2.exe", GetLastError());
        return FALSE;
    }
    slash = wcsrchr(self, L'\\');
    if (!slash) { errsay(L"cannot derive the launcher directory from \"%ls\".\n", self); return FALSE; }
    slash[1] = 0;
    join_path(r->dll_path, self, RUNTIME_DLL_NAME);
    r->dll_file = CreateFileW(r->dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r->dll_file == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        r->dll_file = NULL;
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            errsay(L"runtime DLL \"%ls\" was not found next to ntw2.exe.\n", r->dll_path);
        else win_fail(L"opening the runtime DLL", e);
        return FALSE;
    }
    if (!GetFileSizeEx(r->dll_file, &sz) || sz.QuadPart < 1024 || sz.QuadPart > 0x7FFFFFFF) {
        errsay(L"runtime DLL \"%ls\" has an invalid size.\n", r->dll_path);
        return FALSE;
    }
    map = CreateFileMappingW(r->dll_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map) { win_fail(L"mapping the runtime DLL", GetLastError()); return FALSE; }
    view = (const uint8_t *)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!view) { win_fail(L"mapping a view of the runtime DLL", GetLastError()); CloseHandle(map); return FALSE; }
    why = parse_dll_guarded(view, (size_t)sz.QuadPart, &r->dll);
    UnmapViewOfFile(view);
    CloseHandle(map);
    if (why) {
        errsay(L"runtime DLL \"%ls\" is not usable: %ls.\n", r->dll_path, why);
        return FALSE;
    }
    if (!sha256_handle(r->dll_file, r->dll_sha, &r->dll_size, &we, &ne)) {
        report_hash_failure(L"the runtime DLL", we, ne);
        return FALSE;
    }
    say(L"Runtime DLL verified: %ls (x86 DLL; ntw2_start/ntw2_stop/ntw2_state exported; %I64u bytes).\n", r->dll_path,
        (unsigned long long)r->dll_size);
    ok = TRUE;
    return ok;
}

/* ------------------------------------------------------------------------------------------------ process helpers */
typedef BOOL (*mod_cb)(const MODULEENTRY32W *me, void *ctx);

/* 1 = callback stopped the walk, 0 = walk completed, -1 = enumeration failed (*err set). */
static int module_walk(DWORD pid, mod_cb cb, void *ctx, DWORD *err)
{
    HANDLE snap = INVALID_HANDLE_VALUE;
    MODULEENTRY32W me;
    int tries, rc = 0;
    for (tries = 0; tries < 100; ++tries) {
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(10);
    }
    if (snap == INVALID_HANDLE_VALUE) { *err = GetLastError(); return -1; }
    me.dwSize = sizeof me;
    if (!Module32FirstW(snap, &me)) {
        *err = GetLastError();
        CloseHandle(snap);
        return -1;
    }
    do {
        if (cb(&me, ctx)) { rc = 1; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return rc;
}

typedef struct ReadyScan {
    unsigned count;
    BOOL first_seen, has_kernel32, has_user32;
    uint32_t main_base;
    wchar_t main_path[MAXP];
} ReadyScan;

static BOOL ready_cb(const MODULEENTRY32W *me, void *c)
{
    ReadyScan *s = (ReadyScan *)c;
    if (!s->first_seen) {
        s->first_seen = TRUE;
        s->main_base = (uint32_t)(uintptr_t)me->modBaseAddr;
        wcsncpy_s(s->main_path, MAXP, me->szExePath, _TRUNCATE);
    }
    if (_wcsicmp(me->szModule, L"kernel32.dll") == 0) s->has_kernel32 = TRUE;
    if (_wcsicmp(me->szModule, L"user32.dll") == 0) s->has_user32 = TRUE;
    ++s->count;
    return FALSE;
}

typedef struct NameFind {
    const wchar_t *name;
    uint32_t base, size;
    wchar_t path[MAXP];
} NameFind;

static BOOL name_cb(const MODULEENTRY32W *me, void *c)
{
    NameFind *f = (NameFind *)c;
    if (_wcsicmp(me->szModule, f->name) != 0) return FALSE;
    f->base = (uint32_t)(uintptr_t)me->modBaseAddr;
    f->size = me->modBaseSize;
    wcsncpy_s(f->path, MAXP, me->szExePath, _TRUNCATE);
    return TRUE;
}

static BOOL process_alive(HANDLE p) { return WaitForSingleObject(p, 0) == WAIT_TIMEOUT; }

static BOOL remote_read(HANDLE p, uint32_t addr, void *buf, SIZE_T len)
{
    SIZE_T got = 0;
    return ReadProcessMemory(p, (LPCVOID)(uintptr_t)addr, buf, len, &got) && got == len;
}

typedef struct RemoteIdent {
    uint32_t ts, size_of_image, checksum, dir_rva, dir_size;
    uint16_t characteristics;
} RemoteIdent;

static const wchar_t *read_remote_ident(HANDLE p, uint32_t base, BOOL want_dll, RemoteIdent *out)
{
    uint8_t hdr[4096];
    const IMAGE_NT_HEADERS32 *nt;
    const wchar_t *why;
    if (!remote_read(p, base, hdr, sizeof hdr)) return L"remote PE header is unreadable";
    why = check_pe32_header(hdr, sizeof hdr, want_dll, &nt);
    if (why) return why;
    out->ts = nt->FileHeader.TimeDateStamp;
    out->size_of_image = nt->OptionalHeader.SizeOfImage;
    out->checksum = nt->OptionalHeader.CheckSum;
    out->characteristics = nt->FileHeader.Characteristics;
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        out->dir_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        out->dir_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        out->dir_rva = out->dir_size = 0;
    }
    return NULL;
}

typedef struct BufCtx {
    const uint8_t *b;
    uint32_t base_rva, size;
} BufCtx;

static const uint8_t *buf_rva(void *c, uint32_t rva, uint32_t len)
{
    const BufCtx *x = (const BufCtx *)c;
    if (rva >= x->base_rva && (uint64_t)rva + len <= (uint64_t)x->base_rva + x->size) return x->b + (rva - x->base_rva);
    return NULL;
}

/* Verifies the module the game actually loaded against the validated local DLL file. */
static const wchar_t *verify_remote_runtime(Run *r, uint32_t base)
{
    RemoteIdent id;
    const wchar_t *why;
    uint8_t *dir;
    BufCtx bc;
    uint32_t rvas[5];
    why = read_remote_ident(r->proc, base, TRUE, &id);
    if (why) return why;
    if (id.ts != r->dll.ts || id.size_of_image != r->dll.size_of_image || id.checksum != r->dll.checksum)
        return L"loaded module headers (timestamp/size/checksum) differ from the validated DLL file";
    if (id.dir_rva != r->dll.dir_rva || id.dir_size != r->dll.dir_size) return L"loaded module export directory differs from the validated DLL file";
    if (id.dir_size > 1024 * 1024) return L"loaded module export directory is implausibly large";
    dir = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, id.dir_size);
    if (!dir) return L"out of memory reading the remote export directory";
    if (!remote_read(r->proc, base + id.dir_rva, dir, id.dir_size)) {
        HeapFree(GetProcessHeap(), 0, dir);
        return L"remote export directory is unreadable";
    }
    bc.b = dir;
    bc.base_rva = id.dir_rva;
    bc.size = id.dir_size;
    why = find_exports(buf_rva, &bc, id.dir_rva, id.dir_size, k_export_names, 5, rvas);
    HeapFree(GetProcessHeap(), 0, dir);
    if (why) return why;
    if (rvas[0] != r->dll.start_rva || rvas[1] != r->dll.stop_rva || rvas[2] != r->dll.state_rva ||
        rvas[3] != r->dll.profile_rva || rvas[4] != r->dll.trace_rva)
        return L"loaded module export RVAs differ from the validated DLL file";
    return NULL;
}

/* Locate kernel32!LoadLibraryW (possibly forwarded) in the game: containing local system module offset + matching remote module. */
static BOOL resolve_remote_loadlibrary(Run *r, uint32_t *addr)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll"), owner = NULL;
    FARPROC p = k32 ? GetProcAddress(k32, "LoadLibraryW") : NULL;
    wchar_t lpath[MAXP], *leaf;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS32 *nt;
    NameFind nf;
    RemoteIdent id;
    const wchar_t *why;
    DWORD err = 0;
    int rc;
    uint32_t off;

    if (!p) { win_fail(L"resolving local LoadLibraryW", GetLastError()); return FALSE; }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p, &owner)) {
        win_fail(L"finding the module containing LoadLibraryW", GetLastError());
        return FALSE;
    }
    if (GetModuleFileNameW(owner, lpath, MAXP) == 0) { win_fail(L"naming the module containing LoadLibraryW", GetLastError()); return FALSE; }
    leaf = wcsrchr(lpath, L'\\');
    leaf = leaf ? leaf + 1 : lpath;
    dos = (const IMAGE_DOS_HEADER *)owner;
    nt = (const IMAGE_NT_HEADERS32 *)((const uint8_t *)owner + dos->e_lfanew);
    nf.name = leaf;
    nf.base = nf.size = 0;
    rc = module_walk(r->pid, name_cb, &nf, &err);
    if (rc < 0) { win_fail(L"enumerating game modules", err); return FALSE; }
    if (rc == 0) { errsay(L"the game process has no module named %ls to host LoadLibraryW.\n", leaf); return FALSE; }
    why = read_remote_ident(r->proc, nf.base, TRUE, &id);
    if (why) { errsay(L"game module %ls rejected: %ls.\n", leaf, why); return FALSE; }
    if (id.ts != nt->FileHeader.TimeDateStamp || id.size_of_image != nt->OptionalHeader.SizeOfImage ||
        id.checksum != nt->OptionalHeader.CheckSum) {
        errsay(L"game module %ls does not match the local system module; refusing to call into it.\n", leaf);
        return FALSE;
    }
    off = (uint32_t)((uintptr_t)p - (uintptr_t)owner);
    if (off >= id.size_of_image) { errsay(L"LoadLibraryW offset is outside %ls.\n", leaf); return FALSE; }
    *addr = nf.base + off;
    return TRUE;
}

enum { RC_OK = 0, RC_TIMEOUT, RC_DIED, RC_CREATE };

static int remote_call(Run *r, uint32_t fn, uint32_t arg, DWORD timeout_ms, DWORD *exit_code, DWORD *err)
{
    HANDLE th, w[2];
    DWORD tid, wr;
    int rc;
    th = CreateRemoteThread(r->proc, NULL, 0, (LPTHREAD_START_ROUTINE)(uintptr_t)fn, (LPVOID)(uintptr_t)arg, 0, &tid);
    if (!th) { *err = GetLastError(); return RC_CREATE; }
    w[0] = th;
    w[1] = r->proc;
    wr = WaitForMultipleObjects(2, w, FALSE, timeout_ms);
    if (wr == WAIT_OBJECT_0 || (wr == WAIT_OBJECT_0 + 1 && WaitForSingleObject(th, 0) == WAIT_OBJECT_0)) {
        if (!GetExitCodeThread(th, exit_code)) { *err = GetLastError(); rc = RC_CREATE; }
        else rc = RC_OK;
    } else if (wr == WAIT_OBJECT_0 + 1) {
        rc = RC_DIED;
    } else {
        rc = RC_TIMEOUT;   /* thread may still be running in the game: caller must not free what it uses */
    }
    CloseHandle(th);
    return rc;
}

/* ------------------------------------------------------------------------------------------------ status */
static BOOL read_status(Run *r, ntw2_status *out, const wchar_t **why)
{
    int i;
    for (i = 0; i < 16; ++i) {
        uint32_t s1, s2;
        if (!remote_read(r->proc, r->state_addr, &s1, 4)) { *why = L"ReadProcessMemory on ntw2_state failed"; return FALSE; }
        if (s1 & 1) { Sleep(0); continue; }
        if (!remote_read(r->proc, r->state_addr, out, sizeof *out)) { *why = L"ReadProcessMemory on ntw2_state failed"; return FALSE; }
        if (!remote_read(r->proc, r->state_addr, &s2, 4)) { *why = L"ReadProcessMemory on ntw2_state failed"; return FALSE; }
        if (s1 != s2 || out->sequence != s1) continue;
        if (out->abi != NTW2_ABI || out->size != sizeof *out) {
            *why = L"ntw2_state ABI/size does not match this launcher";
            return FALSE;
        }
        return TRUE;
    }
    *why = L"no coherent ntw2_state snapshot (sequence kept changing)";
    return FALSE;
}

static void print_status(const ntw2_status *s, uint32_t req)
{
    wchar_t a[192], m[192];
    mask_str(s->active_mask, a, 192);
    mask_str(req & ~s->active_mask, m, 192);
    say(L"  phase=%ls active=[%ls] missing=[%ls] generation=%lu tick=%lu workers=%lu error=0x%08lX detail=0x%08lX probe=0x%03lX\n",
        phase_name(s->phase), a, m, (unsigned long)s->generation, (unsigned long)s->tick, (unsigned long)s->workers,
        (unsigned long)s->error, (unsigned long)s->error_detail, (unsigned long)s->probe);
}

static void print_counters(const ntw2_status *s)
{
    say(L"  counters: path=%lu formation=%lu ballistic=%lu collision_cache_hits=%lu worker_chunks=%lu "
        L"storage=%lu retained=%lu bytes\n"
        L"  modules: path_fallbacks=%lu path_refused=%lu formation_epochs=%lu formation_refused=%lu ballistic_stages=%lu\n",
        (unsigned long)s->path_completed, (unsigned long)s->formation_committed, (unsigned long)s->ballistic_committed,
        (unsigned long)s->collision_cache_hits, (unsigned long)s->worker_chunks,
        (unsigned long)s->storage_bytes, (unsigned long)s->retained_bytes,
        (unsigned long)s->path_fallbacks, (unsigned long)s->path_refused, (unsigned long)s->formation_epochs,
        (unsigned long)s->formation_refused, (unsigned long)s->ballistic_stages);
}
/* In-process crash capture (ntw2_status::crash_words, layout in ntw2_runtime.h). Prints nothing when no exception was recorded. */
static void print_crash(const ntw2_status *s)
{
    static const wchar_t *const modules[4] = {L"main image", L"runtime dll", L"private clone", L"other"};
    static const wchar_t *const accesses[4] = {L"read", L"write", L"execute", L"n/a"};
    static const wchar_t *const dump_states[4] = {L"none", L"in progress", L"written", L"failed"};
    const uint32_t *c = s->crash_words;
    const uint32_t st = c[7];
    const unsigned dumps = (st >> 14) & 3u, dump_state = (st >> 12) & 3u;
    unsigned i;
    if (!c[0]) return;
    say(L"crash: n=%lu code=0x%08lX thread=%lu%ls eip=0x%08lX (%ls; raw 0x%08lX) %ls address=0x%08lX tick=%lu "
        L"worker[running=%u busy=%u swapped=%u parked=%u in_think=%u] repeat=%u dump=%ls dumps=%u err=0x%04lX",
        (unsigned long)c[0], (unsigned long)c[2], (unsigned long)c[1],
        (st & 0x200u) ? L" (tick thread)" : (st & 0x400u) ? L" (ai worker)" : L"",
        (unsigned long)c[3], modules[st & 3u], (unsigned long)c[4], accesses[(st >> 2) & 3u], (unsigned long)c[5],
        (unsigned long)c[6], (st >> 4) & 1u, (st >> 5) & 1u, (st >> 6) & 1u, (st >> 7) & 1u, (st >> 8) & 1u,
        (st >> 11) & 1u, dump_states[dump_state], dumps, (unsigned long)(st >> 16));
    if (dump_state == 2u && dumps)
        say(L" file=F:\\NTW2\\translated_code\\analysis\\crashdumps\\ntw2-%lu-%u.dmp", (unsigned long)s->pid, dumps - 1u);
    say(L" stack=[");
    for (i = 8; i < 24 && c[i]; ++i) say(L"%ls%08lX", i > 8 ? L" " : L"", (unsigned long)c[i]);
    say(L"]\n");
    say(L"  crash regs: esp=%08lX ebp=%08lX eax=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
        (unsigned long)c[24], (unsigned long)c[25], (unsigned long)c[26], (unsigned long)c[27], (unsigned long)c[28],
        (unsigned long)c[29], (unsigned long)c[30]);
}

/* Live crash hand-off: the faulting thread publishes the record and waits (bounded) for this acknowledgement before it lets the
   game's own handler terminate the process; the 200 ms status poll is the only chance to see the record in a dying process. */
static void observe_crash(Run *r, const ntw2_status *s)
{
    uint32_t tag, ack;
    SIZE_T wrote = 0;
    if (!s->crash_words[0]) return;
    tag = (s->crash_words[0] & 0xFFFFu) | (((s->crash_words[7] >> 12) & 3u) << 16) | 0x80000000u;
    if (tag == r->crash_tag) return;
    r->crash_tag = tag;
    if (!(s->crash_words[7] & 0x800u)) print_crash(s);   /* a repeat of an earlier signature is not printed until the final recap */
    ack = tag;
    WriteProcessMemory(r->proc, (LPVOID)(uintptr_t)(r->state_addr + (uint32_t)offsetof(ntw2_status, crash_words) + 31u * 4u),
                       &ack, sizeof ack, &wrote);
}
/* BRAIN2 v2 service IDs match native_brain2.h; no legacy replay-event labels. */
static const char *const k_brain2_services[NTW2_BRAIN2_CENSUS_WORDS / 8u] = {
    "effects", "slot_acquire", "target_acquire", "charge_callback", "move_driver", "fire_driver",
    "finalize", "fire_sequence", "path_request", "request_build", "request_commit", "order",
    "node_finish", "node_begin", "node_step", "node_destroy", "animation", "parked",
    "wrapper_effect", "wrapper_service", "pose_position", "pose_heading", "reference_step",
    "arrival", "unlink", "engage", "random", "reference_construct", "watcher", "holder_query",
    "timer", "unit_witness", "animation_lookup", "cold_lookup", "idle", "prebattle", "exit",
    "projection", "crew", "descriptor", "wrapper_610470", "wrapper_60cac0", "wrapper_5e52f0",
    "wrapper_607540", "wrapper_5b9720", "virtual_order", "virtual_query", "unknown",
    "fire_candidates_62e910", "fire_submit_8021e0", "fire_gather_80bf70", "melee_label_14d060c", "mutable_read"
};
static const char *const k_ai_completion_metrics[NTW2_AI_COMPLETION_WORDS] = { NTW2_AI_COMPLETION_LABELS };
static const char *const k_ai_async2_metrics[NTW2_AI_ASYNC2_WORDS] = { NTW2_AI_ASYNC2_LABELS };
static const char *const k_ai_async2_route_metrics[NTW2_AI_ASYNC2_ROUTE_WORDS] = { NTW2_AI_ASYNC2_ROUTE_LABELS };
static double pct(uint32_t part, uint32_t whole) { return whole ? 100.0 * (double)part / (double)whole : 0.0; }
/* Per-unit brain Stage A agreement table (native_unit_brain.h, version 2). held = this stage's UnitDecision (the
   unit's strict-majority record of the previous stage, valid while the unit-level input signature is unchanged),
   over non-exception main-class soldiers. tick = this stage's own strict majority over its voters (main-class
   non-exception soldiers), counted only in unit-stages that have one; voters of unit-stages without a strict majority
   are tick_none (neither agreement nor disagreement). exception = held comparison over exception and
   unresolved-role soldiers (Stage B would run those natively). */
static void print_unit_brain(const uint32_t *u)
{
    static const char *const header[] = { NTW2_BRAIN_UNIT_HEADER_LABELS };
    static const char *const fields[] = { NTW2_BRAIN_UNIT_FIELD_LABELS };
    static const char *const exceptions[] = { NTW2_BRAIN_UNIT_EXCEPTION_LABELS };
    static const char *const census[] = { NTW2_BRAIN_UNIT_CENSUS_LABELS };
    static const char *const roles[] = { NTW2_BRAIN_UNIT_ROLE_LABELS };
    static const char *const tail[] = { NTW2_BRAIN_UNIT_TAIL_LABELS };
    const double stages = u[2] ? (double)u[2] : 1.0;
    /* observed minus observed exceptions (other_class is not observed) minus unresolved roles */
    const uint32_t compared = u[4] - (u[100] - u[99]) - u[169];
    unsigned f, i;
    if (!u[0]) return;
    say(L"  brain unit shadow (Stage A v%lu, shadow only; stages=%lu occurrences/stage=%.0f last stage: units=%lu "
        L"decided=%lu; decide %.3f ms finalize %.3f ms observe %.3f ms per stage):\n", (unsigned long)u[0],
        (unsigned long)u[2], u[3] / stages, (unsigned long)u[5], (unsigned long)u[7], u[13] / stages / 1000.0,
        u[14] / stages / 1000.0, u[171] / stages / 1000.0);
    say(L"    %-14hs %9hs %9hs %9hs %9hs %9hs %10hs %10hs   (counts: held agree/disagree/none, tick agree/disagree/none, exc agree/disagree)\n",
        "field", "held%", "held_cov%", "tick%", "tick_none%", "exc%", "worst_stg%", "n/stage");
    for (f = 0; f < sizeof(fields) / sizeof(fields[0]); ++f) {
        const uint32_t *w = u + 16u + 8u * f;
        const uint32_t none = u[160u + f];
        const uint32_t held = w[0] + w[1], tick = w[3] + w[4], exc = w[5] + w[6];
        wchar_t worst[16];
        if (w[7] == 0xFFFFFFFFu) wcscpy_s(worst, 16, L"n/a"); else _snwprintf_s(worst, 16, _TRUNCATE, L"%.1f", w[7] / 10.0);
        say(L"    %-14hs %8.3f%% %8.3f%% %8.3f%% %8.3f%% %8.3f%% %10ls %10.0f   (%lu/%lu/%lu, %lu/%lu/%lu, %lu/%lu)\n",
            fields[f], pct(w[0], held), pct(held, held + w[2]), pct(w[3], tick), pct(none, tick + none), pct(w[5], exc),
            worst, (held + w[2]) / stages, (unsigned long)w[0], (unsigned long)w[1], (unsigned long)w[2],
            (unsigned long)w[3], (unsigned long)w[4], (unsigned long)none, (unsigned long)w[5], (unsigned long)w[6]);
    }
    say(L"    all nine fields held-agree: %.3f%% of %lu non-exception main-class occurrences (any held disagreement %.3f%%); "
        L"last stage %lu/%lu\n", pct(u[107], compared), (unsigned long)compared, pct(u[106], compared),
        (unsigned long)u[173], (unsigned long)u[172]);
    say(L"    exceptions (%% of %lu occurrences):", (unsigned long)u[3]);
    for (i = 0; i < 13u; ++i) say(L" %hs=%.2f%%", exceptions[i], pct(u[88u + i], u[3]));
    say(L" %hs=%.2f%% (%hs=%lu)", roles[0], pct(u[169], u[3]), roles[1], (unsigned long)u[170]);
    say(L"\n    far_from_slot measured=%lu unmeasured=%lu (destination +3F4 only while +390!=0 and +404 null)\n",
        (unsigned long)u[101], (unsigned long)u[102]);
    say(L"    class vtables (%hs=%lu %hs=%lu): preferred VA, soldiers/stage, soldiers/unit-stage, held-disagree-any%%, "
        L"units/stage\n", census[0], (unsigned long)u[104], census[1], (unsigned long)u[105]);
    for (i = 0; i < 13u && i < u[104]; ++i) {
        const uint32_t *v = u + 108u + 4u * i;
        say(L"      0x%08lX %10.1f %8.2f %8.3f%% %8.1f\n", (unsigned long)v[0], v[1] / stages,
            v[3] ? v[1] / (double)v[3] : 0.0, pct(v[2], v[1]), v[3] / stages);
    }
    say(L"   ");
    for (i = 0; i < 16u; ++i) say(L" %hs=%lu", header[i], (unsigned long)u[i]);
    say(L" %hs=%lu %hs=%lu %hs=%lu %hs=%lu\n", exceptions[15], (unsigned long)u[103], tail[2], (unsigned long)u[174],
        census[2], (unsigned long)u[106], roles[2], (unsigned long)u[171]);
}
/* Army per-unit update Stage A table (native_army_unit.h): go/no-go input for an item 4 Stage B. strict = no owner-only
   reason (every reached unclosed callee counts as non_closed); dynamic = no reason except non_closed, i.e. eligible once
   the reached section 8.2 classes are closed as private. Tnew = non-unit site-18 work + owner-only unit cost
   + eligible unit cost / W + measured frozen-copy cost, per tick (dispatch/join overhead not included). */
static void print_army_unit(const uint32_t *u)
{
    static const char *const reasons[] = { NTW2_ARMY_UNIT_REASON_LABELS };
    static const char *const details[] = { NTW2_ARMY_UNIT_DETAIL_LABELS };
    const double occ = u[3] ? (double)u[3] : 1.0, ticks = u[6] ? (double)u[6] : 1.0, q = u[23] ? (double)u[23] : 1.0;
    const double unit_ms = u[16] / ticks / 1000.0, snap_ms = u[21] / ticks / 1000.0;
    const double native_ms = ((double)u[19] - u[20] - u[21]) / ticks / 1000.0, other_ms = native_ms - unit_ms;
    const double strict_ms = u[17] / ticks / 1000.0, dynamic_ms = u[18] / ticks / 1000.0;
    unsigned ws[3];
    unsigned i, j, order[16], rows = u[104] < 16u ? u[104] : 16u;
    uint32_t seen = 0;
    double p50 = 0.0, p90 = 0.0;
    ws[0] = 4u; ws[1] = 8u; ws[2] = u[30];
    if (!u[0]) return;
    for (i = 0; i < 16u; ++i) { /* histogram-derived global quantile upper bounds */
        const double upper = i == 15u ? 32768.0 : (double)(1u << i);
        seen += u[88u + i];
        if (!p50 && seen * 2u >= u[3]) p50 = upper;
        if (!p90 && (double)seen >= 0.9 * u[3]) p90 = upper;
    }
    say(L"  army unit shadow (Stage A instrumentation, native 0x581F30 authoritative): stages=%lu ticks=%lu units/stage=%.1f "
        L"units/tick=%.1f (main=%lu alternate=%lu repeated=%lu) max_units_stage=%lu\n", (unsigned long)u[2], (unsigned long)u[6],
        u[3] / (u[2] ? (double)u[2] : 1.0), u[3] / ticks, (unsigned long)u[4], (unsigned long)u[5], (unsigned long)u[47],
        (unsigned long)u[8]);
    say(L"    per-unit cost: mean %.1f us; tick p50 %.1f us p90 %.1f us (mean over %lu ticks; last %.1f/%.1f, max p90 %.1f); "
        L"run p50<=%.0f us p90<=%.0f us\n", u[16] / occ, u[24] / q / 10.0, u[25] / q / 10.0, (unsigned long)u[23],
        u[26] / 10.0, u[27] / 10.0, u[28] / 10.0, p50, p90);
    say(L"    site 18 per tick: native %.3f ms = units %.3f + other %.3f; instrumentation %.3f ms; frozen-copy %.3f ms (%.1f units)\n",
        native_ms, unit_ms, other_ms, u[20] / ticks / 1000.0, snap_ms, u[22] / ticks);
    say(L"    eligible: strict %.2f%% of units (%.2f%% of unit cost); dynamic %.2f%% (%.2f%% of cost); unreadable %.2f%% "
        L"(%.2f%% of cost, never eligible); RNG-drawing %.2f%% (%.2f draws/unit by bounded LCG-step inference, unresolved %lu, "
        L"%.2f%% of cost, eligible under compromise 5)\n", pct(u[9], u[3]), pct(u[17], u[16]), pct(u[10], u[3]), pct(u[18], u[16]),
        pct(u[15], u[3]), pct(u[107], u[16]), pct(u[11], u[3]), u[12] / occ, (unsigned long)u[13], pct(u[106], u[16]));
    say(L"    owner-only reasons (units%% / cost%% / sole-reason units%%):");
    for (i = 0; i < 5u; ++i) say(L" %hs=%.2f/%.2f/%.2f", reasons[i], pct(u[32u + i], u[3]), pct(u[37u + i], u[16]), pct(u[42u + i], u[3]));
    say(L"%ls\n", u[14] ? L"" : L" (planner_write NOT measured: needs --features ai,ai_census)");
    if (u[31]) say(L"    WARNING ai_async2 active: model+50 RNG deltas may include AI-worker draws\n");
    say(L"    Tnew site 18 ms/tick (other + owner units + eligible/W + frozen copy; no dispatch overhead):");
    for (i = 0; i < 3u; ++i) {
        const double w = ws[i] ? (double)ws[i] : 1.0;
        const double closed = other_ms + (unit_ms - dynamic_ms) + dynamic_ms / w + snap_ms;
        const double as_is = other_ms + (unit_ms - strict_ms) + strict_ms / w + snap_ms;
        if (i == 2u && (!ws[2] || ws[2] == 4u || ws[2] == 8u)) continue;
        say(L" W=%u closed %.3f (save %.3f) / as-is %.3f (save %.3f);", ws[i], closed, native_ms - closed, as_is, native_ms - as_is);
    }
    say(L"\n    foreign witness per unit: distinct %.1f (max %lu), aggregation list %.1f (skipped %.1f%%), neighbour candidates %.1f, "
        L"pinned cells %.1f; unreadable=%lu set_overflow=%lu\n", u[80] / occ, (unsigned long)u[81], u[82] / occ, pct(u[84], u[3]),
        u[83] / occ, u[87] / occ, (unsigned long)u[85], (unsigned long)u[86]);
    say(L"    kinds/effects (%% of units):");
    for (i = 0; i < 32u; ++i) if (u[48u + i]) say(L" %hs=%.2f", details[i], pct(u[48u + i], u[3]));
    say(L"\n    command classes by cumulative cost (selected command U+398+90*U+934 vtable; 0 none, FFFFFFFF unreadable; distinct=%lu "
        L"overflow=%lu): VA, units/stage, dynamic-owner%%, mean us, ms/tick, cost%%, rng%%\n", (unsigned long)u[104], (unsigned long)u[105]);
    for (i = 0; i < rows; ++i) {
        for (j = i; j && u[108u + 5u * order[j - 1] + 3u] < u[108u + 5u * i + 3u]; --j) order[j] = order[j - 1];
        order[j] = i;
    }
    for (i = 0; i < rows; ++i) {
        const uint32_t *v = u + 108u + 5u * order[i];
        say(L"      0x%08lX %8.2f %7.2f%% %9.1f %8.3f %7.2f%% %7.2f%%\n", (unsigned long)v[0], v[1] / (u[2] ? (double)u[2] : 1.0),
            pct(v[2], v[1]), v[1] ? (double)v[3] / v[1] : 0.0, v[3] / ticks / 1000.0, pct(v[3], u[16]), pct(v[4], v[1]));
    }
}
static void print_module_words(const ntw2_status *s)
{
    static const wchar_t *const names[45] = {L"formation", L"query", L"path", L"ballistic", L"formation_diag", L"tick_cadence", L"sim_tick", L"ai_planner", L"planner_walk", L"ai_async", L"ai_async_extra", L"crash", L"brain_header", L"brain2", L"ai_slices", L"ai_validation", L"visual", L"ai_slice_sites", L"brain_state_header", L"collision", L"collide", L"collide_lod", L"ai_ctrl", L"ai_slice_budget", L"ai_park", L"loco", L"loco_gates", L"loco_services", L"loco_grid", L"loco_parallel", L"sweep", L"resolve", L"env", L"env_targets", L"resolve_frames", L"loco_owned", L"loco_owned_detail", L"loco_owned_phase", L"loco_owned_load", L"loco_grid_v2", L"collide_source", L"memory", L"brain_unit", L"collide_contact", L"grid_probation_header"};
    const uint32_t *arrays[45] = {s->formation_words, s->query_words, s->path_words, s->ballistic_words,
                                  s->formation_diag, s->tick_words, s->sim_words, s->planner_words, s->planner_walk_words,
                                  s->ai_words, s->ai_extra_words, s->crash_words, s->brain_words, s->brain2_words, s->ai_slice_words, s->ai_validation_words, s->visual_words, s->ai_slice_site_words, s->brain_state_words, s->collision_words, s->collide_words, s->collide_lod_words, s->ai_ctrl_words, s->ai_slice_budget_words, s->ai_park_words, s->loco_words, s->loco_gate_words, s->loco_service_words, s->loco_grid_words, s->loco_parallel_words, s->sweep_words, s->resolve_words, s->env_words, s->env_target_words, s->resolve_frame_words, s->loco_owned_words, s->loco_owned_detail_words, s->loco_owned_phase_words, s->loco_owned_load_words, s->loco_grid_v2_words, s->collide_source_words, s->memory_words, s->brain_unit_words, s->collide_contact_words, s->grid_probation_words};
    const unsigned counts[45] = {16, 16, 24, 8, 192, 16, 16, 64, 16, 16, 32, 32, NTW2_BRAIN_HEADER_WORDS, NTW2_BRAIN2_WORDS, 8, 8, 32, 2, NTW2_BRAIN_STATE_COUNTS, NTW2_COLLISION_WORDS, NTW2_COLLIDE_WORDS, NTW2_COLLIDE_LOD_WORDS, 16, NTW2_AI_SLICE_BUDGET_WORDS, 8, NTW2_LOCO_WORDS, NTW2_LOCO_GATE_WORDS, NTW2_LOCO_SERVICE_WORDS, NTW2_LOCO_GRID_WORDS, NTW2_LOCO_PARALLEL_WORDS, NTW2_SWEEP_WORDS, NTW2_RESOLVE_WORDS, NTW2_ENV_WORDS, NTW2_ENV_TARGET_WORDS, NTW2_RESOLVE_FRAME_WORDS, NTW2_LOCO_OWNED_WORDS, NTW2_LOCO_OWNED_DETAIL_WORDS, NTW2_LOCO_OWNED_PHASE_WORDS, NTW2_LOCO_OWNED_LOAD_WORDS, NTW2_LOCO_GRID_V2_WORDS, NTW2_COLLIDE_SOURCE_WORDS, NTW2_MEMORY_WORDS, NTW2_BRAIN_UNIT_WORDS, NTW2_COLLIDE_CONTACT_WORDS, NTW2_GRID_PROBATION_HEADER_WORDS};
    unsigned i, j;
    for (i = 0; i < 45; ++i) {
        say(L"  %ls words:", names[i]);
        for (j = 0; j < counts[i]; ++j) say(L" %lu", (unsigned long)arrays[i][j]);
        say(L"\n");
    }
    {
        const uint32_t *q = s->planner_walk_words;
        say(L"  planner walks (7C7DC0 route only; think = site-34 scope): scopes=%lu walks/think=%.3f "
            L"nodes/walk=%.3f interests/walk=%.3f filters/walk=%.3f gather/walk-time=%.3f%% "
            L"polygon/walk-time=%.3f%% memo hits=%lu misses=%lu unsupported=%lu\n",
            (unsigned long)q[0], q[0] ? (double)q[1]/q[0] : 0.0,
            q[1] ? (double)q[3]/q[1] : 0.0, q[1] ? (double)q[5]/q[1] : 0.0,
            q[1] ? (double)q[6]/q[1] : 0.0, q[7] ? 100.0*q[8]/q[7] : 0.0,
            q[7] ? 100.0*q[9]/q[7] : 0.0,
            (unsigned long)q[12], (unsigned long)q[13], (unsigned long)q[14]);
    }
    {
        const uint32_t *a=s->ai_completion_words, *c=s->ai_ctrl_words;
        say(L"  ai_async: same-tick completion; dispatched=%lu completed=%lu max_planner_us=%lu "
            L"barriers=%lu max_barrier_us=%lu event_errors=%lu worker_tid=%lu\n",
            (unsigned long)s->ai_words[0], (unsigned long)a[0], (unsigned long)a[2],
            (unsigned long)a[3], (unsigned long)a[5], (unsigned long)s->ai_words[10],
            (unsigned long)s->ai_slice_words[7]);
        say(L"  ai_ctrl: dispatched=%lu completed=%lu sum_us=%lu max_us=%lu site33_barriers=%lu\n",
            (unsigned long)c[0], (unsigned long)c[1], (unsigned long)c[4],
            (unsigned long)c[5], (unsigned long)c[11]);
        for (i=0;i<NTW2_AI_COMPLETION_WORDS;++i)
            say(L"  %hs=%lu%ls",k_ai_completion_metrics[i],(unsigned long)a[i],(i+1)%3 ? L" " : L"\n");
        if (s->requested_mask & NTW2_AI_ASYNC2) {
            const uint32_t *w = s->ai_async2_words, *q = s->ai_async2_route_words;
            unsigned k = 0;
            say(L"  ai_async2 v%lu: dispatches=%lu completions=%lu capacity_joins=%lu lease_waits=%lu "
                L"overlap_sum_us=%lu join_wait_sum_us=%lu deadlock_suspected=%lu fallback=%lu marshalled=%lu\n",
                (unsigned long)w[0], (unsigned long)w[1], (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4],
                (unsigned long)w[15], (unsigned long)w[17], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[9]);
            say(L"  ai_async2 boundary: ticks=%lu batches=%lu complete_before_next_tick=%lu (%.1f%%) spanning_ticks=%lu "
                L"spanning_thinks=%lu first/last=%lu/%lu fallback_tick=%lu unrouted_83fd00=%lu\n",
                (unsigned long)q[2], (unsigned long)q[4], (unsigned long)q[9], pct(q[9], q[4]), (unsigned long)q[11],
                (unsigned long)q[12], (unsigned long)q[13], (unsigned long)q[14], (unsigned long)q[15], (unsigned long)q[60]);
            for (i = 0; i < NTW2_AI_ASYNC2_WORDS; ++i)
                if (w[i]) say(L"  %hs=%lu%ls", k_ai_async2_metrics[i], (unsigned long)w[i], (++k % 4) ? L"" : L"\n");
            for (i = 0; i < NTW2_AI_ASYNC2_ROUTE_WORDS; ++i)
                if (q[i]) say(L"  route.%hs=%lu%ls", k_ai_async2_route_metrics[i], (unsigned long)q[i], (++k % 4) ? L"" : L"\n");
            if (k % 4) say(L"\n");
        }
    }
    if (s->requested_mask & NTW2_BRAIN2) {
        const uint32_t *g = s->brain2_words;
        say(L"  brain2 v%lu: dispatches=%lu occurrences=%lu original=%lu serial_clone=%lu "
            L"fully_inactive=%lu any_active=%lu any_unknown=%lu; census=%lu timing=%lu\n",
            (unsigned long)g[0], (unsigned long)g[4], (unsigned long)g[5],
            (unsigned long)g[6], (unsigned long)g[7], (unsigned long)g[8],
            (unsigned long)g[9], (unsigned long)g[10], (unsigned long)g[1], (unsigned long)g[2]);
        if (g[1] && g[7])
            say(L"    fully inactive among completed serial clones: %.3f%% (unknown is NOT inactive)\n",
                100.0 * g[8] / g[7]);
        say(L"    pose_reads=%lu leader=%lu target=%lu other=%lu self=%lu\n",
            (unsigned long)g[16], (unsigned long)g[17], (unsigned long)g[18],
            (unsigned long)g[19], (unsigned long)g[20]);
        if (g[2]) say(L"    QPC ticks: original=%I64u clone=%I64u frequency=%I64u (separate runs, not a paired speedup)\n",
            (ULONGLONG)g[26] | ((ULONGLONG)g[27] << 32),
            (ULONGLONG)g[46] | ((ULONGLONG)g[47] << 32),
            (ULONGLONG)g[28] | ((ULONGLONG)g[29] << 32));
        for (i = 0; i < NTW2_BRAIN2_CENSUS_WORDS / 8u; ++i) {
            const uint32_t *q = s->brain2_census_words + i * 8;
            if (q[0]) say(L"    %hs: calls=%lu active=%lu unknown=%lu inactive=%lu first_active=%lu first_unknown=%lu\n",
                k_brain2_services[i], (unsigned long)q[0], (unsigned long)q[1],
                (unsigned long)q[2], (unsigned long)q[3], (unsigned long)q[4], (unsigned long)q[5]);
        }
        {
            static const char *const node_labels[NTW2_NODE_WORDS] = { NTW2_NODE_WORD_LABELS };
            static const char *const move_labels[NTW2_MOVE_NODE_WORDS] = { NTW2_MOVE_NODE_WORD_LABELS };
            static const char *const move_event_labels[NTW2_MOVE_NODE_EVENT_WORDS] = { NTW2_MOVE_NODE_EVENT_WORD_LABELS };
            static const char *const fire_labels[NTW2_FIRE_WORDS] = { NTW2_FIRE_WORD_LABELS };
            static const char *const commit_labels[NTW2_FIRE_COMMIT_WORDS] = { NTW2_FIRE_COMMIT_LABELS };
            say(L"  brain reference node shadow (vtable=0x01334180, owner only):\n");
            for (i = 0; i < NTW2_NODE_WORDS; ++i)
                say(L"    %hs=%lu\n", node_labels[i], (unsigned long)s->node_words[i]);
            say(L"    event words:");
            for (i = 0; i < NTW2_NODE_EVENT_WORDS; ++i) say(L" %lu", (unsigned long)s->node_event_words[i]);
            say(L"\n  brain descriptor-move node shadow (vtable=0x01348B44, step=0x00819310, owner only):\n");
            for (i = 0; i < NTW2_MOVE_NODE_WORDS; ++i)
                say(L"    %hs=%lu\n", move_labels[i], (unsigned long)s->move_node_words[i]);
            for (i = 0; i < NTW2_MOVE_NODE_EVENT_WORDS; ++i)
                say(L"    %hs=%lu\n", move_event_labels[i], (unsigned long)s->move_node_event_words[i]);
            {
                static const uint32_t idle_tables[NTW2_IDLE_NODE_CLASSES] = { 0x133405Cu, 0x1334028u };
                static const uint32_t action_tables[NTW2_ACTION_NODE_CLASSES] = { 0x1347270u, 0x1348D2Cu, 0x1348CC4u };
                static const char *const idle_labels[NTW2_NODE_WORDS] = { NTW2_IDLE_NODE_WORD_LABELS };
                static const char *const idle_events[NTW2_NODE_EVENT_WORDS] = { NTW2_IDLE_NODE_EVENT_WORD_LABELS };
                static const char *const action_labels[NTW2_NODE_WORDS] = { NTW2_ACTION_NODE_WORD_LABELS };
                static const char *const action_events[NTW2_NODE_EVENT_WORDS] = { NTW2_ACTION_NODE_EVENT_WORD_LABELS };
                uint32_t cls;
                for (cls = 0; cls < NTW2_IDLE_NODE_CLASSES; ++cls) {
                    say(L"  brain idle node shadow (vtable=0x%08lX, owner only):\n", (unsigned long)idle_tables[cls]);
                    for (i = 0; i < NTW2_NODE_WORDS; ++i)
                        say(L"    %hs=%lu\n", idle_labels[i], (unsigned long)s->idle_node_words[cls][i]);
                    for (i = 0; i < NTW2_NODE_EVENT_WORDS; ++i)
                        say(L"    %hs=%lu\n", idle_events[i], (unsigned long)s->idle_node_event_words[cls][i]);
                }
                for (cls = 0; cls < NTW2_ACTION_NODE_CLASSES; ++cls) {
                    say(L"  brain action node shadow (vtable=0x%08lX, owner only):\n", (unsigned long)action_tables[cls]);
                    for (i = 0; i < NTW2_NODE_WORDS; ++i)
                        say(L"    %hs=%lu\n", action_labels[i], (unsigned long)s->action_node_words[cls][i]);
                    for (i = 0; i < NTW2_NODE_EVENT_WORDS; ++i)
                        say(L"    %hs=%lu\n", action_events[i], (unsigned long)s->action_node_event_words[cls][i]);
                }
            }
            say(L"\n  brain request-sequencer shadow (owner only):\n");
            for (i = 0; i < NTW2_FIRE_WORDS; ++i)
                say(L"    %hs=%lu\n", fire_labels[i], (unsigned long)s->fire_words[i]);
            say(L"  brain sequencer commit refusal guards:\n");
            for (i = 0; i < NTW2_FIRE_COMMIT_WORDS; ++i)
                say(L"    %hs=%lu\n", commit_labels[i], (unsigned long)s->fire_commit_words[i]);
            {
                const uint32_t *route = s->brain2_route_words;
                say(L"  brain site6 route: configured_driver=%ls last_driver_clone_id_plus1=%lu driver_calls=%lu "
                    L"node_virtual_begin=%lu node_virtual_step=%lu reference_ctor=%lu last_node_target=0x%08lX\n",
                    route[1] == 1 ? L"BRAIN_W_MOVEORDER" : L"original",
                    (unsigned long)route[2], (unsigned long)route[3], (unsigned long)route[4],
                    (unsigned long)route[5], (unsigned long)route[6], (unsigned long)route[7]);
                const uint32_t *targets = s->brain2_node_target_words;
                say(L"    node_targets: distinct=%lu overflow_calls=%lu begin_top8:",
                    (unsigned long)targets[1], (unsigned long)targets[2]);
                for (i = 0; i < 8u && targets[4u + 2u * i]; ++i)
                    say(L" 0x%08lX:%lu", (unsigned long)targets[4u + 2u * i], (unsigned long)targets[5u + 2u * i]);
                say(L" step_top8:");
                for (i = 0; i < 8u && targets[20u + 2u * i]; ++i)
                    say(L" 0x%08lX:%lu", (unsigned long)targets[20u + 2u * i], (unsigned long)targets[21u + 2u * i]);
                say(L"\n");
            }
            {
                static const char *const table_labels[2] = {
                    "unknown_row_unresolved_sites", "first_unresolved_gate_per_occurrence" };
                static const char *const witness_labels[24] = {
                    "dispatches", "units_last", "unit_overflow", "snapshot_faults", "units_changed",
                    "unit_field_mask", "battle_changed", "battle_field_mask", "unit_mismatch_calls",
                    "unit_missing_calls", "battle_mismatch_calls", "unit_inactive_calls",
                    "battle_inactive_calls", "manager_missing_calls", "slots_changed", "slot_field_mask",
                    "slot_mismatch_calls", "slots_last", "armies_changed", "army_mismatch_calls", "armies_last",
                    "finalizer_inactive_calls", "finalizer_shadow_calls", "finalizer_shadow_mismatches" };
                const uint32_t *w = s->brain2_unknown_site_words;
                uint32_t t;
                for (t = 0; t < 2u; ++t) {
                    const uint32_t *q = w + t * 52u;
                    say(L"    %hs: distinct=%lu overflow=%lu counted=%lu (site->target:count)\n", table_labels[t],
                        (unsigned long)q[1], (unsigned long)q[2], (unsigned long)q[3]);
                    for (i = 0; i < 16u && q[6u + 3u * i]; ++i)
                        say(L"      0x%08lX->0x%08lX:%lu\n", (unsigned long)q[4u + 3u * i],
                            (unsigned long)q[5u + 3u * i], (unsigned long)q[6u + 3u * i]);
                }
                say(L"    site6 witness:");
                for (i = 0; i < 24u; ++i)
                    say(L" %hs=%lu", witness_labels[i], (unsigned long)w[104u + i]);
                say(L"\n");
            }
            {
                static const char *const worker_labels[48] = { NTW2_BRAIN_WORKER_WORD_LABELS };
                static const char *const reason_labels[18] = { NTW2_BRAIN_WORKER_REASON_LABELS };
                const uint32_t *w = s->brain_worker_words;
                if (w[0]) {
                    say(L"  brain workers (Stage 2, owner-ordered guarded commit; receiver=%lu bytes):\n", (unsigned long)w[47]);
                    for (i = 0; i < 47u; ++i)
                        say(L"    %hs=%lu\n", worker_labels[i], (unsigned long)w[i]);
                    if (w[6])
                        say(L"    worker_commit_share=%.3f%% of %lu ==1 occurrences (the remainder ran on the owner at its ordinal)\n",
                            100.0 * (double)w[11] / (double)w[6], (unsigned long)w[6]);
                    say(L"    refusal reasons:");
                    for (i = 0; i < 18u; ++i)
                        if (w[48u + i]) say(L" %hs=%lu", reason_labels[i], (unsigned long)w[48u + i]);
                    say(L"\n    refusing services:");
                    for (i = 0; i < NTW2_BRAIN2_CENSUS_WORDS / 8u; ++i)
                        if (w[66u + i]) say(L" %hs=%lu", k_brain2_services[i], (unsigned long)w[66u + i]);
                    say(L"\n");
                    {
                        static const char *const tail_labels[] = { NTW2_BRAIN_WORKER_TAIL_LABELS };
                        static const char *const guard_labels[] = { NTW2_BRAIN_WORKER_GUARD_LABELS };
                        for (i = 0; i < sizeof(tail_labels) / sizeof(tail_labels[0]); ++i)
                            say(L"    %hs=%lu\n", tail_labels[i], (unsigned long)w[119u + i]);
                        for (i = 0; i < sizeof(guard_labels) / sizeof(guard_labels[0]); ++i)
                            say(L"    %hs=%lu\n", guard_labels[i], (unsigned long)w[128u + i]);
                    }
                    {
                        static const char *const phase_labels[NTW2_BRAIN_WORKER_PHASE_WORDS] = { NTW2_BRAIN_WORKER_PHASE_LABELS };
                        const uint32_t *p = s->brain_worker_phase_words;
                        const double stages = p[2] ? (double)p[2] : 1.0;
                        say(L"    phases (quiet=%lu, stages=%lu; per stage ms: capture %.2f [witness %.2f] dispatch %.2f commit %.2f owner_run %.2f "
                            L"walk_other %.2f witness_end %.2f; worker CPU ms: capture %.2f clone %.2f publish %.2f busy %.2f critical %.2f):\n",
                            (unsigned long)p[1], (unsigned long)p[2], p[3] / stages / 1000.0, p[4] / stages / 1000.0,
                            p[5] / stages / 1000.0, p[6] / stages / 1000.0, p[7] / stages / 1000.0, p[8] / stages / 1000.0,
                            p[9] / stages / 1000.0, p[10] / stages / 1000.0, p[11] / stages / 1000.0, p[12] / stages / 1000.0,
                            p[13] / stages / 1000.0, p[14] / stages / 1000.0);
                        for (i = 0; i < NTW2_BRAIN_WORKER_PHASE_WORDS; ++i)
                            say(L"      %hs=%lu\n", phase_labels[i], (unsigned long)p[i]);
                    }
                }
            }
            print_unit_brain(s->brain_unit_words);
        }
    }
    if (s->requested_mask & NTW2_ARMY_UNIT_SHADOW) print_army_unit(s->army_unit_words);
    if (s->requested_mask & NTW2_VISUAL) {
        const uint32_t *v = s->visual_words;
        say(L"  visual: calls=%lu sharded=%lu inline_fallbacks=%lu items_sum=%lu chunks=%lu "
            L"sum_us_sharded=%lu sum_us_inline=%lu max_us=%lu faults=%lu "
            L"last_fault_eip=0x%08lX last_fault_address=0x%08lX last_fault_item=0x%08lX "
            L"last_fault_index=%lu slot_va=0x%08lX arena_epochs=%lu arena_busy_fallbacks=%lu\n",
            (unsigned long)v[0], (unsigned long)v[1], (unsigned long)v[2], (unsigned long)v[3],
            (unsigned long)v[4], (unsigned long)v[5], (unsigned long)v[6], (unsigned long)v[7],
            (unsigned long)v[8], (unsigned long)v[9], (unsigned long)v[10], (unsigned long)v[11],
            (unsigned long)v[12], (unsigned long)v[13], (unsigned long)v[14], (unsigned long)v[15]);
    }
    for (i = 0; i < NTW2_ALLOCATOR_THREADS; ++i) {
        const uint32_t *a = s->allocator_words + i * NTW2_ALLOCATOR_ROW_WORDS;
        if (!a[0]) continue;
        say(L"  allocator %ls[%u]: result=0x%lX thread=%lu tls_before=0x%08lX tls_after=0x%08lX "
            L"exception=0x%08lX eip=0x%08lX address=0x%08lX tls_index=%lu\n",
            i == NTW2_ALLOCATOR_THREADS - 1 ? L"ai" : L"pool", i,
            (unsigned long)a[0], (unsigned long)a[1], (unsigned long)a[2], (unsigned long)a[3],
            (unsigned long)a[4], (unsigned long)a[5], (unsigned long)a[6], (unsigned long)a[7]);
    }
    print_crash(s);
}

/* ------------------------------------------------------------------------------------------------ tick trace */
static const uint32_t k_site_callee_vas[NTW2_TIMED_SITES] = NTW2_SITE_CALLEE_VAS;
static uint64_t trace_qpc(uint32_t lo, uint32_t hi)
{
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/* The producer's written count is cumulative across battle/model tick resets.
   Unsigned subtraction also handles its uint32_t rollover. */
static void append_tick_log(Run *r, const ntw2_trace_ring *p)
{
    TickLog *log = &r->tick_log;
    uint32_t added = p->written - log->written, start, i, needed;
    if (!r->opt.tick_log[0] || log->failed || !added) return;
    if (added > p->entries) {
        log->lost += added - p->entries;
        added = p->entries;
    }
    needed = log->count + added;
    if (needed > TICK_LOG_MAX_ENTRIES) needed = TICK_LOG_MAX_ENTRIES;
    if (needed > log->capacity) {
        uint32_t capacity = log->capacity ? log->capacity * 2u : NTW2_TRACE_ENTRIES;
        ntw2_trace_entry *entries;
        if (capacity < needed) capacity = needed;
        if (capacity > TICK_LOG_MAX_ENTRIES) capacity = TICK_LOG_MAX_ENTRIES;
        entries = log->entries
            ? (ntw2_trace_entry *)HeapReAlloc(GetProcessHeap(), 0, log->entries, (size_t)capacity * sizeof *entries)
            : (ntw2_trace_entry *)HeapAlloc(GetProcessHeap(), 0, (size_t)capacity * sizeof *entries);
        if (!entries) {
            log->failed = TRUE;
            errsay(L"unable to grow the tick log capture buffer.\n");
            return;
        }
        log->entries = entries;
        log->capacity = capacity;
    }
    start = (p->head + p->entries - added) % p->entries;
    for (i = 0; i < added; ++i) {
        const ntw2_trace_entry *e = &p->ring[(start + i) % p->entries];
        /* Chronological written deltas exclude old slots; guard the boundary
           identity as well, without scanning the entire accumulated run. */
        if (log->count) {
            const ntw2_trace_entry *last = &log->entries[log->count - 1u];
            if (e->tick == last->tick && e->qpc_start_lo == last->qpc_start_lo &&
                e->qpc_start_hi == last->qpc_start_hi) continue;
        }
        if (log->count == TICK_LOG_MAX_ENTRIES) ++log->lost;
        else log->entries[log->count++] = *e;
    }
    log->written = p->written;
}

static BOOL read_trace(Run *r)
{
    TickTrace *t = r->trace;
    ntw2_trace_ring *p;
    uint32_t next;
    if (!r->active_generations) return TRUE;
    if (!t) return FALSE;
    next = t->current ^ 1u;
    p = &t->copies[next];
    /* One full-ring read. No allocation or full-ring local copy per poll. */
    if (!remote_read(r->proc, r->dll_base + r->dll.trace_rva, p, sizeof *p) ||
        p->abi != NTW2_TRACE_ABI || p->size != sizeof *p ||
        p->entries != NTW2_TRACE_ENTRIES || p->head >= p->entries)
        return FALSE;
    if (r->opt.tick_log[0]) {
        uint32_t header[8];
        /* Reject a publication overlapping the copy; retry on the next poll.
           The runtime publishes head before written, so check their agreement. */
        if (p->head != p->written % p->entries ||
            !remote_read(r->proc, r->dll_base + r->dll.trace_rva, header, sizeof header) ||
            memcmp(header, p, sizeof header) != 0) return FALSE;
        append_tick_log(r, p);
    }
    t->current = next;
    t->have = TRUE;
    return TRUE;
}

static void finalize_trace(Run *r)
{
    if (!r->trace || r->trace->finalized || !r->active_generations) return;
    if (!read_trace(r))
        say(L"Final tick trace read unavailable; using the last complete periodic copy if retained.\n");
    r->trace->finalized = TRUE;
}

static int compare_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* Nearest-rank percentiles, including the first interval (zero by ABI). */
static void trace_percentiles(uint32_t *values, uint32_t count, uint32_t out[4])
{
    if (!count) return;
    qsort(values, count, sizeof *values, compare_u32);
    out[0] = values[(count * 50u + 99u) / 100u - 1u];
    out[1] = values[(count * 90u + 99u) / 100u - 1u];
    out[2] = values[(count * 99u + 99u) / 100u - 1u];
    out[3] = values[count - 1u];
}

static void analyze_trace(TickTrace *t)
{
    const ntw2_trace_ring *p = &t->copies[t->current];
    uint32_t i, start, rank, j;
    if (t->analyzed) return;
    t->count = p->written < p->entries ? p->written : p->entries;
    start = (p->head + p->entries - t->count) % p->entries;
    for (i = 0; i < t->count; ++i) {
        uint32_t index = (start + i) % p->entries;
        const ntw2_trace_entry *e = &p->ring[index];
        if (!i) t->first_tick = e->tick;
        t->last_tick = e->tick;
        t->scratch[i] = e->duration_us;
        t->duration_sum += e->duration_us;
        t->manager_sum += e->manager_us;
        t->ballistics_sum += e->ballistics_us;
        t->path_sum += e->path_us;
        for (j = 0; j < NTW2_TIMED_SITES; ++j) {
            t->site_sum[j] += e->site_us[j];
            t->site_calls[j] += e->site_calls[j];
        }
        if (e->flags & 4u) ++t->timed_ticks;
        if (e->duration_us > 100000u) ++t->over100;
        if (e->duration_us > 150000u) ++t->over150;
        /* Descending duration; ties retain chronological order, not model-tick order
           (the model tick can restart on a later battle generation). */
        for (rank = 0; rank < t->top_count; ++rank)
            if (e->duration_us > p->ring[t->top[rank]].duration_us) break;
        if (rank < 16u) {
            if (t->top_count < 16u) ++t->top_count;
            for (j = t->top_count - 1u; j > rank; --j) t->top[j] = t->top[j - 1u];
            t->top[rank] = index;
        }
    }
    trace_percentiles(t->scratch, t->count, t->duration);
    for (i = 0; i < t->count; ++i) {
        const ntw2_trace_entry *e = &p->ring[(start + i) % p->entries];
        t->scratch[i] = e->interval_us;
        if ((uint64_t)e->duration_us * 2u > (uint64_t)t->duration[0] * 3u) {
            ++t->mod100[(e->tick % 100u) / 10u];
            ++t->mod10[e->tick % 10u];
        }
    }
    trace_percentiles(t->scratch, t->count, t->interval);
    /* Signed: do not hide overlapping sub-phase timings or observational skew. */
    t->remainder_sum = (int64_t)t->duration_sum - (int64_t)t->manager_sum -
                       (int64_t)t->ballistics_sum - (int64_t)t->path_sum;
    t->analyzed = TRUE;
}

static BOOL write_trace(Run *r)
{
    TickTrace *t = r->trace;
    const ntw2_trace_ring *p;
    uint32_t i, j;
    double share_scale;
    wchar_t path[MAXP + 16], tmp[MAXP + 20];
    HANDLE file;
    DWORD wrote, error = 0;
    if (!r->active_generations) return TRUE;
    if (!t || !t->have) {
        errsay(L"no complete tick trace snapshot is available after ACTIVE.\n");
        return FALSE;
    }
    analyze_trace(t);
    p = &t->copies[t->current];
    share_scale = t->duration_sum ? 100.0 / (double)t->duration_sum : 0.0;
    say(L"Tick trace: %lu retained of %lu written; chronological first/last tick=%lu/%lu (live observational copy).\n",
        (unsigned long)t->count, (unsigned long)p->written, (unsigned long)t->first_tick, (unsigned long)t->last_tick);
    say(L"  QPC frequency: %I64u ticks/s; receipt tick_trace.ticks uses raw PresentMon --qpc_time coordinates.\n",
        (unsigned long long)trace_qpc(p->qpc_freq_lo, p->qpc_freq_hi));
    say(L"  QPC start/end spans the whole gate including AI slice/hold; duration_us below is tick-body time.\n");
    say(L"  Duration us p50/p90/p99/max: %lu / %lu / %lu / %lu\n"
        L"  Interval us p50/p90/p99/max: %lu / %lu / %lu / %lu\n",
        (unsigned long)t->duration[0], (unsigned long)t->duration[1], (unsigned long)t->duration[2], (unsigned long)t->duration[3],
        (unsigned long)t->interval[0], (unsigned long)t->interval[1], (unsigned long)t->interval[2], (unsigned long)t->interval[3]);
    say(L"  Duration sums us: total=%I64u manager=%I64u ballistics=%I64u path=%I64u remainder=%I64d\n"
        L"  Shares: manager=%.3f%% ballistics=%.3f%% path=%.3f%% remainder=%.3f%%; ticks >100ms=%lu >150ms=%lu\n",
        (unsigned long long)t->duration_sum, (unsigned long long)t->manager_sum,
        (unsigned long long)t->ballistics_sum, (unsigned long long)t->path_sum, (long long)t->remainder_sum,
        t->manager_sum * share_scale, t->ballistics_sum * share_scale,
        t->path_sum * share_scale, t->remainder_sum * share_scale,
        (unsigned long)t->over100, (unsigned long)t->over150);
    say(L"  Inclusive sites: %lu timed ticks; shares of all %lu retained tick durations.\n"
        L"  Each call is timed and counted; site 2 includes sites 16..25; totals overlap gate timings.\n"
        L"    site callee sum_us calls duration_share\n",
        (unsigned long)t->timed_ticks, (unsigned long)t->count);
    for (i = 0; i < NTW2_TIMED_SITES; ++i)
        say(L"    %2lu 0x%06lX %I64u %I64u %.3f%%\n", (unsigned long)i, (unsigned long)k_site_callee_vas[i],
            (unsigned long long)t->site_sum[i], (unsigned long long)t->site_calls[i], t->site_sum[i] * share_scale);
    say(L"  Longest ticks (us): tick duration interval manager ballistics path\n");
    for (i = 0; i < t->top_count; ++i) {
        const ntw2_trace_entry *e = &p->ring[t->top[i]];
        say(L"    %lu %lu %lu %lu %lu %lu\n", (unsigned long)e->tick, (unsigned long)e->duration_us,
            (unsigned long)e->interval_us, (unsigned long)e->manager_us, (unsigned long)e->ballistics_us, (unsigned long)e->path_us);
        say(L"      Sites (index:callee=us/calls):");
        for (j = 0; j < NTW2_TIMED_SITES; ++j)
            say(L" %lu:0x%06lX=%lu/%lu", (unsigned long)j, (unsigned long)k_site_callee_vas[j],
                (unsigned long)e->site_us[j], (unsigned long)e->site_calls[j]);
        say(L"\n");
    }
    say(L"  Periodicity for duration >1.5 x p50: tick%%100 range count | tick%%10 count\n");
    for (i = 0; i < 10; ++i)
        say(L"    %2lu-%2lu %lu | %lu %lu\n", (unsigned long)(i * 10u), (unsigned long)(i * 10u + 9u),
            (unsigned long)t->mod100[i], (unsigned long)i, (unsigned long)t->mod10[i]);
    if (!r->opt.receipt[0]) {
        say(L"No --receipt path: tick trace printed only; no binary written.\n");
        return TRUE;
    }
    _snwprintf_s(path, MAXP + 16, _TRUNCATE, L"%ls.ticks.bin", r->opt.receipt);
    _snwprintf_s(tmp, MAXP + 20, _TRUNCATE, L"%ls.tmp", path);
    file = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_fail(L"creating the tick trace temp file", GetLastError());
        return FALSE;
    }
    if (!WriteFile(file, p, sizeof *p, &wrote, NULL) || wrote != sizeof *p || !FlushFileBuffers(file))
        error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    CloseHandle(file);
    if (!error && !MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        error = GetLastError();
    if (error) {
        DeleteFileW(tmp);
        win_fail(L"writing the tick trace", error);
        return FALSE;
    }
    say(L"Tick trace written: %ls (%lu bytes, verbatim LE header + ring).\n", path, (unsigned long)sizeof *p);
    return TRUE;
}

/* Little-endian 20-byte header followed by count chronological ABI entries. */
static BOOL write_tick_log(Run *r)
{
    const TickLog *log = &r->tick_log;
    struct {
        char magic[8];
        uint32_t abi, entry_size, count;
    } header = {{'N', 'T', 'W', '2', 'T', 'L', 'O', 'G'}, NTW2_TRACE_ABI, sizeof(ntw2_trace_entry), 0};
    wchar_t tmp[MAXP + 8];
    HANDLE file;
    DWORD wrote, error = 0, bytes;
    if (!r->opt.tick_log[0]) return TRUE;
    header.count = log->count;
    bytes = (DWORD)((size_t)log->count * sizeof *log->entries);
    _snwprintf_s(tmp, MAXP + 8, _TRUNCATE, L"%ls.tmp", r->opt.tick_log);
    file = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_fail(L"creating the tick log temp file", GetLastError());
        return FALSE;
    }
    if (!WriteFile(file, &header, sizeof header, &wrote, NULL) || wrote != sizeof header ||
        (bytes && (!WriteFile(file, log->entries, bytes, &wrote, NULL) || wrote != bytes)) ||
        !FlushFileBuffers(file))
        error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    CloseHandle(file);
    if (!error && !MoveFileExW(tmp, r->opt.tick_log, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        error = GetLastError();
    if (error) {
        DeleteFileW(tmp);
        win_fail(L"writing the tick log", error);
        return FALSE;
    }
    say(L"Tick log written: %ls (%lu entries, %I64u lost).\n", r->opt.tick_log,
        (unsigned long)log->count, (unsigned long long)log->lost);
    return !log->failed;
}

/* ------------------------------------------------------------------------------------------------ brain sites (NTW2_BRAIN) */
/* Cumulative since the last activation (ntw2_status::brain_words, layout in ntw2_runtime.h). Families are the entry sites 46..50. */
static const struct { const wchar_t *name; const char *jname; uint32_t tables, entry_va; } k_brain_families[NTW2_BRAIN_FAMILIES] = {
    { L"slot +0x0C = 0x66CE00 (brain direct)", "direct_66CE00", 11, 0x66CE00u },
    { L"slot +0x0C = 0x6F50F0 (jmp thunk to the brain)", "thunk_6F50F0", 1, 0x6F50F0u },
    { L"slot +0x0C = 0x6F4660 (LOS/registration wrapper)", "wrapper_6F4660", 6, 0x6F4660u },
    { L"slot +0x0C = 0x602EB0 (wrapper)", "wrapper_602EB0", 1, 0x602EB0u },
    { L"slot +0x0C = 0x5FCEB0 (pose/animation wrapper)", "wrapper_5FCEB0", 4, 0x5FCEB0u },
};
#define BRAIN_FIRST_CALLEE 65u

static uint32_t brain_us(const ntw2_status *s, uint32_t f, uint32_t site)
{
    return s->brain_words[NTW2_BRAIN_HEADER_WORDS + 2u * (f * NTW2_BRAIN_SITES + (site - NTW2_BRAIN_SITE_FIRST))];
}

static uint32_t brain_calls(const ntw2_status *s, uint32_t f, uint32_t site)
{
    return s->brain_words[NTW2_BRAIN_HEADER_WORDS + 2u * (f * NTW2_BRAIN_SITES + (site - NTW2_BRAIN_SITE_FIRST)) + 1u];
}

/* Sites family f can run: its own entry, its wrapper's callees (51..55 / 56..58 / 59..64) and the brain callees 65..94. */
static BOOL brain_family_owns(uint32_t f, uint32_t site)
{
    if (site == NTW2_BRAIN_SITE_FIRST + f || site >= BRAIN_FIRST_CALLEE) return TRUE;
    return (f == 2 && site >= 51 && site <= 55) || (f == 3 && site >= 56 && site <= 58) || (f == 4 && site >= 59 && site <= 64);
}

/* Callee label: original VA, "vt+0xNNN" for the two virtual sites, annotated for the wrappers' brain calls and the entries. */
static void brain_site_label(uint32_t site, wchar_t *out, size_t n)
{
    const uint32_t va = k_site_callee_vas[site];
    if (site >= NTW2_BRAIN_SITE_FIRST && site < NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_FAMILIES)
        _snwprintf_s(out, n, _TRUNCATE, L"entry 0x%06lX", (unsigned long)va);
    else if (site == 55 || site == 56 || site == 59)
        _snwprintf_s(out, n, _TRUNCATE, L"0x%06lX (brain call)", (unsigned long)va);
    else if (va < 0x400000u)
        _snwprintf_s(out, n, _TRUNCATE, L"vt+0x%lX", (unsigned long)va);
    else
        _snwprintf_s(out, n, _TRUNCATE, L"0x%06lX", (unsigned long)va);
}

static void print_brain_sites(const Run *r)
{
    const ntw2_status *s = &r->last;
    const uint32_t ticks = s->brain_words[0], tick_us = s->brain_words[1];
    uint64_t agg_us[NTW2_TIMED_SITES], agg_calls[NTW2_TIMED_SITES];
    double scale = tick_us ? 100.0 / (double)tick_us : 0.0;
    uint32_t f, site;
    wchar_t label[64];
    if (!(r->opt.mask & NTW2_BRAIN) || !r->active_generations) return;
    if (!r->have_status || !ticks) {
        say(L"Brain sites: no routed tick with brain profiling was observed.\n");
        return;
    }
    memset(agg_us, 0, sizeof agg_us);
    memset(agg_calls, 0, sizeof agg_calls);
    say(L"Brain sites: %lu routed ticks, tick duration sum %lu us (cumulative since the last activation; counters wrap modulo 2^32).\n"
        L"  Inclusive enter-to-return per call, so rows overlap; every timed call includes its own timing overhead (QPC + FP state\n"
        L"  save/restore), which inflates the enclosing rows in proportion to their nested call counts. share = sum_us / tick sum.\n",
        (unsigned long)ticks, (unsigned long)tick_us);
    for (f = 0; f < NTW2_BRAIN_FAMILIES; ++f) {
        const uint32_t entities = brain_calls(s, f, NTW2_BRAIN_SITE_FIRST + f);
        const uint32_t entry_us = brain_us(s, f, NTW2_BRAIN_SITE_FIRST + f);
        say(L"  family %lu: %ls, %lu vtables: entities=%lu (%.2f/tick) entry_us=%lu (%.3f%% of tick sum, %.3f us/entity)\n",
            (unsigned long)f, k_brain_families[f].name, (unsigned long)k_brain_families[f].tables, (unsigned long)entities,
            (double)entities / ticks, (unsigned long)entry_us, entry_us * scale, entities ? (double)entry_us / entities : 0.0);
        for (site = NTW2_BRAIN_SITE_FIRST; site < NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_SITES; ++site) {
            const uint32_t us = brain_us(s, f, site), calls = brain_calls(s, f, site);
            if (site >= BRAIN_FIRST_CALLEE) { agg_us[site] += us; agg_calls[site] += calls; }
            if (!brain_family_owns(f, site) || site == NTW2_BRAIN_SITE_FIRST + f || (!calls && !us)) continue;
            brain_site_label(site, label, 64);
            say(L"    site %2lu %-24ls sum_us=%lu calls=%lu (%.2f/tick, %.3f us/call) share=%.3f%%\n", (unsigned long)site, label,
                (unsigned long)us, (unsigned long)calls, (double)calls / ticks, calls ? (double)us / calls : 0.0, us * scale);
        }
    }
    say(L"  brain callees, all families: site callee sum_us calls calls/tick us/call share\n");
    for (site = BRAIN_FIRST_CALLEE; site < NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_SITES; ++site) {
        brain_site_label(site, label, 64);
        say(L"    %2lu %-18ls %I64u %I64u %.2f %.3f %.3f%%\n", (unsigned long)site, label,
            (unsigned long long)agg_us[site], (unsigned long long)agg_calls[site], (double)agg_calls[site] / ticks,
            agg_calls[site] ? (double)agg_us[site] / (double)agg_calls[site] : 0.0, agg_us[site] * scale);
    }
}

static const struct { unsigned word; const char *name; } k_collision_metrics[] = {
    {1, "records"}, {2, "reuse"}, {3, "rebuild"}, {4, "first_seen_ids"}, {5, "candidate_pairs"},
    {6, "accepted_contacts"}, {7, "redistributions"}, {8, "label_pairs"}, {9, "labels_changed"},
    {10, "callbacks"}, {11, "callback_64CC70_64CAD0"}, {12, "callback_808EF0"},
    {13, "stage_us"}, {14, "traversal_us"}, {15, "numeric_us"}, {16, "callbacks_us"},
    {17, "query_us"}, {18, "append_us"}, {19, "oriented_helper_us"}, {20, "numeric_regions"},
    {21, "stage_calls"}, {24, "callback_64CC70_other"}, {25, "callback_other"}, {26, "oriented_helper_calls"}
};
static void print_collision(const Run *r)
{
    const uint32_t *w = r->last.collision_words;
    unsigned i;
    if (!(r->opt.mask & NTW2_PROFILE)) return;
    if (!r->opt.collide_census) {
        say(L"collision: pair census disabled (opt in with --collide-census); site 5 inclusive timing remains enabled.\n");
        return;
    }
    if (r->opt.mask & NTW2_COLLIDE) {
        say(L"collision: original PROFILE census bypassed by collide; see collide counters.\n");
        return;
    }
    if (!r->have_status || !w[0]) {
        say(L"collision: no routed PROFILE tick observed.\n");
        return;
    }
    say(L"collision: %lu routed ticks, %lu stage calls (%.3f/routed_tick); averages since activation (instrumented, modulo-2^32 totals)\n",
        (unsigned long)w[0], (unsigned long)w[21], (double)w[21]/w[0]);
    for (i = 0; i < sizeof k_collision_metrics/sizeof k_collision_metrics[0]; ++i) {
        say(L"  %hs=%.3f/routed_tick%ls", k_collision_metrics[i].name,
            (double)w[k_collision_metrics[i].word]/w[0], (i+1)%4 ? L" " : L"\n");
    }
    if (w[21]) {
        say(L"  Per-stage averages (denominator collision_words[21], not routed ticks):\n");
        for (i = 0; i < sizeof k_collision_metrics/sizeof k_collision_metrics[0]; ++i)
            say(L"  %hs=%.3f/stage%ls", k_collision_metrics[i].name,
                (double)w[k_collision_metrics[i].word]/w[21], (i+1)%4 ? L" " : L"\n");
    }
    say(L"  max_ids/query=%lu timed_stack_overflows=%lu\n"
        L"  traversal = stage - numeric - callbacks; query/append/helper overlap these totals.\n"
        L"  Callback counts are direct vt+44 calls; recursive native callbacks are timed, not recounted.\n",
        (unsigned long)w[22], (unsigned long)w[23]);
}

static const char *const k_collide_metrics[NTW2_COLLIDE_WORDS] = {
    "stage_calls", "solver_ticks", "fallback_ticks", "capacity_fallbacks", "layout_fallbacks",
    "sticky_fallbacks", "records", "cells", "pairs", "contacts", "callbacks",
    "gather_us", "bin_us", "pairs_us", "apply_us", "worklist_plan_us", "stage_us", "max_stage_us",
    "faults", "rebuilds", "redistributions", "label_changes", "worker_chunks", "inline_chunks",
    "max_pairs", "max_records", "node_fallbacks", "pool_fallbacks", "arena_fallbacks",
    "last_exception", "owner_continuations", "eligible_queries",
    "diagnostic_reason", "diagnostic_record", "diagnostic_node", "diagnostic_type",
    "diagnostic_vtable", "diagnostic_owner", "diagnostic_payload", "diagnostic_id",
    "diagnostic_cell", "diagnostic_expected_record", "native_queries", "unsupported_cells",
    "shaped_pairs", "gather_thread_us", "bin_thread_us", "pairs_thread_us", "apply_thread_us",
    "worklist_plan_thread_us", "audit_us", "store_us", "redistribute_us", "callback_us", "reduction_us",
    "thread_clock_failures", "store_thread_us", "redistribute_thread_us", "callback_thread_us",
    "reduction_thread_us", "audit_thread_us"
};
/* Derived per-solver-tick phase costs: wall = QPC word, thread = GetThreadTimes CPU word (-1 = none), nested_in = enclosing timer. */
static const struct { const char *name; int wall; int thread; const char *nested_in; } k_collide_phases[] = {
    {"gather", 11, 45, NULL}, {"bin", 12, 46, NULL}, {"pairs", 13, 47, NULL}, {"apply", 14, 48, NULL},
    {"worklist_plan", 15, 49, NULL}, {"stage", 16, -1, NULL},
    {"audit", 50, 60, "bin"}, {"store", 51, 56, "apply"}, {"redistribute", 52, 57, "apply"},
    {"callback", 53, 58, "apply"}, {"reduction", 54, 59, "apply"}
};
static const char *const k_collide_lod_metrics[NTW2_COLLIDE_LOD_WORDS] = {
    "ticks_gated", "records_seen", "records_skipped", "units", "far_units", "rebuild_ticks_forced",
    "distance_m", "max_proximity_us", "sum_proximity_us", "faults", "disabled",
    "reuse_far_records", "unknown_records", "reuse_ticks", "all_far_refused_ticks", "different_side_pairs"
};
static void print_collide_lod(const Run *r)
{
    const uint32_t *w = r->last.collide_lod_words;
    unsigned i;
    if (!(r->opt.mask & NTW2_COLLIDE_LOD)) return;
    if (!r->have_status) { say(L"collide_lod: no runtime status observed.\n"); return; }
    say(L"collide_lod: half-rate far-unit queries; near/unknown and rebuild queries remain full-rate\n");
    for (i = 0; i < NTW2_COLLIDE_LOD_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_collide_lod_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    say(L"  reuse far records skipped=%.3f%%; cumulative counts since activation, latest units/far_units\n",
        w[11] ? 100.0*w[2]/w[11] : 0.0);
}

static const char *const k_loco_metrics[NTW2_LOCO_WORDS] = { NTW2_LOCO_WORD_LABELS };
static const char *const k_loco_gate_metrics[NTW2_LOCO_GATE_WORDS] = { NTW2_LOCO_GATE_LABELS };
static const char *const k_loco_service_metrics[NTW2_LOCO_SERVICE_WORDS] = { NTW2_LOCO_SERVICE_LABELS };
static const char *const k_loco_grid_metrics[NTW2_LOCO_GRID_WORDS] = { NTW2_LOCO_GRID_LABELS };
static const char *const k_loco_parallel_metrics[NTW2_LOCO_PARALLEL_WORDS] = { NTW2_LOCO_PARALLEL_LABELS };
static const char *const k_sweep_metrics[NTW2_SWEEP_WORDS] = { NTW2_SWEEP_WORD_LABELS };
static const char *const k_resolve_metrics[NTW2_RESOLVE_WORDS] = { NTW2_RESOLVE_WORD_LABELS };
static const char *const k_env_metrics[NTW2_ENV_WORDS] = { NTW2_ENV_WORD_LABELS };
static const char *const k_resolve_frame_metrics[NTW2_RESOLVE_FRAME_WORDS] = { NTW2_RESOLVE_FRAME_LABELS };
static const char *const k_loco_owned_metrics[NTW2_LOCO_OWNED_WORDS] = { NTW2_LOCO_OWNED_LABELS };
static const char *const k_loco_owned_detail_metrics[NTW2_LOCO_OWNED_DETAIL_WORDS] = { NTW2_LOCO_OWNED_DETAIL_LABELS };
static const char *const k_loco_owned_phase_metrics[NTW2_LOCO_OWNED_PHASE_WORDS] = { NTW2_LOCO_OWNED_PHASE_LABELS };
static const char *const k_loco_owned_load_metrics[NTW2_LOCO_OWNED_LOAD_WORDS] = { NTW2_LOCO_OWNED_LOAD_LABELS };
static const char *const k_loco_grid_v2_metrics[NTW2_LOCO_GRID_V2_WORDS] = { NTW2_LOCO_GRID_V2_LABELS };
static const char *const k_grid_probation_metrics[NTW2_GRID_PROBATION_HEADER_WORDS] = { NTW2_GRID_PROBATION_LABELS };
static const char *const k_grid_probation_modules[4] = { "image", "runtime", "clone", "other" };
/* --grid-probation: header words then every used caller row (EIP/caller preferred-base VAs; clone rows give the
   original instruction VA plus the clone id). An empty table on a full replay is the Stage C/D entry criterion. */
static void print_grid_probation(const Run *r)
{
    const uint32_t *w = r->last.grid_probation_words;
    unsigned i;
    say(L"grid.probation: %ls; native heads PAGE_NOACCESS outside the owner site-13 relink window; traps are logged, restored and resumed\n",
        r->opt.grid_probation ? L"ENABLED" : L"off");
    if (!r->opt.grid_probation) return;
    for (i = 0; i < NTW2_GRID_PROBATION_HEADER_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_grid_probation_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    for (i = 0; i < NTW2_GRID_PROBATION_CALLERS; ++i) {
        const uint32_t *row = w + NTW2_GRID_PROBATION_HEADER_WORDS + 8u * i;
        if (!row[4]) continue;
        say(L"  trap eip=0x%08lX(%hs) caller=0x%08lX(%hs) threads=0x%02lX clone=%ld count=%lu writes=%lu first_site=0x%08lX last_site=0x%08lX\n",
            (unsigned long)row[0], k_grid_probation_modules[row[2] & 3u], (unsigned long)row[1],
            k_grid_probation_modules[(row[2] >> 4) & 3u], (unsigned long)((row[2] >> 8) & 0xFFu),
            (long)(row[2] >> 16) - 1, (unsigned long)row[4], (unsigned long)row[5], (unsigned long)row[6], (unsigned long)row[7]);
    }
}
static const char *const k_collide_source_metrics[NTW2_COLLIDE_SOURCE_WORDS] = { "source", "native_stages", "owned_stages", "owned_refusals" };
static const char *const k_memory_metrics[NTW2_MEMORY_WORDS] = { NTW2_MEMORY_WORD_LABELS };
static void print_memory(const Run *r)
{
    unsigned i;
    if (!r->have_status) return;
    say(L"memory: activation-sized storage; VA floor=512MiB; periodic low VA latches native LOCO/COLLIDE fallback until restart\n");
    for (i = 0; i < NTW2_MEMORY_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_memory_metrics[i], (unsigned long)r->last.memory_words[i], (i+1)%4 ? L" " : L"\n");
    if (NTW2_MEMORY_WORDS % 4) say(L"\n");
    if(r->last.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK])
        say(L"  Budget fallback mask=0x%08lX; retired arenas=%lu; released LOCO=%lu COLLIDE=%lu bytes; LOCO breakdown retains last allocation\n",
            (unsigned long)r->last.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK],
            (unsigned long)r->last.memory_words[NTW2_MEM_BUDGET_RELEASES],
            (unsigned long)r->last.memory_words[NTW2_MEM_RELEASED_LOCO_BYTES],
            (unsigned long)r->last.memory_words[NTW2_MEM_RELEASED_COLLIDE_BYTES]);
}
/* Service order equals loco_words[32..39] and native_loco.h ServiceWord slots 12/20/28; us/max/calls start at these word indices. */
enum { LOCO_SERVICES = 8, LOCO_SVC_US = 12, LOCO_SVC_MAX = 20, LOCO_SVC_CALLS = 28 };
static const char *const k_loco_service_names[LOCO_SERVICES] = {
    "unlink_grid", "unlink_owner", "insert_owner", "insert_grid", "sweep", "resolve", "height_owner", "wrapper_query"
};
static void print_loco_services(const Run *r)
{
    const uint32_t *w = r->last.loco_words;
    const uint32_t *t = r->last.loco_service_words;
    const double clones = (double)w[27], stages = (double)w[1];
    unsigned i;
    say(L"loco.services: version=%lu timing %ls; QPC raw ticks accumulate before conversion; cumulative modulo 2^32 since activation\n",
        (unsigned long)t[0], t[1] ? L"ENABLED (--loco-clone only)" : L"off (observe-only, inactive or --loco-quiet: no timing frames, all work words zero)");
    if (!t[1]) return;
    say(L"  timed_calls=%lu overflows=%lu abandoned=%lu max_depth=%lu qpc_failures=%lu\n",
        (unsigned long)t[2], (unsigned long)t[3], (unsigned long)t[4], (unsigned long)t[8], (unsigned long)t[9]);
    say(L"  clone_wall=%lu us (%.3f us/clone, %.3f us/stage); service_union=%lu us (%.3f us/clone); outside=%lu us (%.3f us/clone)\n",
        (unsigned long)t[5], clones ? t[5]/clones : 0.0, stages ? t[5]/stages : 0.0,
        (unsigned long)t[6], clones ? t[6]/clones : 0.0, (unsigned long)t[7], clones ? t[7]/clones : 0.0);
    for (i = 0; i < LOCO_SERVICES; ++i) {
        const double calls = (double)t[LOCO_SVC_CALLS+i];
        say(L"  %hs: us=%lu max=%lu calls=%lu us/call=%.3f us/clone=%.3f us/stage=%.3f calls/clone=%.3f\n",
            k_loco_service_names[i], (unsigned long)t[LOCO_SVC_US+i], (unsigned long)t[LOCO_SVC_MAX+i], (unsigned long)t[LOCO_SVC_CALLS+i],
            calls ? t[LOCO_SVC_US+i]/calls : 0.0, clones ? t[LOCO_SVC_US+i]/clones : 0.0,
            stages ? t[LOCO_SVC_US+i]/stages : 0.0, clones ? calls/clones : 0.0);
    }
    say(L"  denominators: clone=loco_words[27] clone-executed occurrences, stage=loco_words[1] stage calls, call=that service's completed timed calls (excludes overflow/abandoned/QPC-invalid)\n");
    say(L"  service us are inclusive and overlap (nested services count in each); union counts only outermost timed calls. outside=clone_wall-union (clamped) is NOT pure arithmetic: untapped native calls plus gate/service/QPC instrumentation outside service brackets; all-gates classification precedes the clone wall and is stage-minus-clone-wall. Instrumentation perturbs each interval (FP save/restore, trampolines, QPC); not the uninstrumented ~12 ms decomposition\n");
}

static void print_loco(const Run *r)
{
    const uint32_t *w = r->last.loco_words;
    const uint32_t *g = r->last.loco_gate_words;
    unsigned i;
    if (!(r->opt.mask & NTW2_LOCO)) return;
    if (!r->have_status) { say(L"loco: no runtime status observed.\n"); return; }
    say(L"loco: Stages A/B/C site-13 movement loop 0x531AF0; optional owned grid v2 published at stage end; clone execution %ls; closed movement workers %ls; owned services %ls\n",
        r->opt.loco_clone ? L"ENABLED" : L"off (observe only: original movement)",
        r->opt.loco_parallel ? L"ENABLED (--loco-parallel)" : L"off",
        r->opt.loco_owned ? L"ENABLED (--loco-owned-services)" : L"off");
    say(L"loco.mode: quiet %ls (--loco-quiet disables per-service QPC, shadow comparisons and the all-gates histogram; faults/share retained); effective shadow comparisons %ls\n",
        r->opt.loco_quiet ? L"ENABLED" : L"off", loco_shadow_effective(&r->opt) ? L"ENABLED" : L"off");
    for (i = 0; i < NTW2_LOCO_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    if (NTW2_LOCO_WORDS % 4) say(L"\n");
    say(L"  admitted %.3f%% of entity occurrences; cloned=%lu native=%lu; us sums are wall time inside the stage (admitted, rejected, dispatch)\n",
        w[2] ? 100.0*w[3]/w[2] : 0.0, (unsigned long)w[27], (unsigned long)w[28]);
    say(L"  serial MOVE enforces Class/Lifetime/Parked/Pending/Environment only; removed first-fail buckets stay zero; no NODE/worker safety claim\n");
    say(L"  all-gates: denominator=%lu active +0x30 occurrences, candidates=%lu, enforced_mask=0x%03lx (bit reason-1); independent failures/details overlap and must not be summed\n",
        (unsigned long)g[1], (unsigned long)g[2], (unsigned long)g[4]);
    for (i = 0; i < NTW2_LOCO_GATE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_gate_metrics[i], (unsigned long)g[i], (i+1)%4 ? L" " : L"\n");
    if (NTW2_LOCO_GATE_WORDS % 4) say(L"\n");
    say(L"  all-gates admitted %.3f%%; legacy=%lu newly_admitted=%lu; detailed fields are recognized-candidate diagnostics, not first failures\n",
        g[1] ? 100.0*g[3]/g[1] : 0.0, (unsigned long)g[38], (unsigned long)g[39]);
    say(L"  ChargeFire uses DWORD +4E8/+390/+3BC/+3C8; byte +618/+619/+F1/+5AB are corroborating latches only\n");
    print_loco_services(r);
    say(L"loco.grid: %ls; combined COLLIDE borrows the published view; counters cumulative modulo 2^32\n",
        r->opt.loco_grid ? L"ENABLED: owned grid v2 published at site-13 exit" : L"grid disabled; pass --loco-grid or --loco-grid-verify");
    for (i = 0; i < NTW2_LOCO_GRID_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_grid_metrics[i], (unsigned long)r->last.loco_grid_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.grid_v2: verification %ls; phase words remain the movement measurement\n", r->opt.loco_grid_verify ? L"ENABLED" : L"off");
    for (i = 0; i < NTW2_LOCO_GRID_V2_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_grid_v2_metrics[i], (unsigned long)r->last.loco_grid_v2_words[i], (i+1)%4 ? L" " : L"\n");
    print_grid_probation(r);
    say(L"loco.parallel: without --loco-owned-services only A1==0 direct/battle occurrences enter workers; native publication is always owner-only; combined collision requires clone+parallel+owned-services+grid\n");
    for (i = 0; i < NTW2_LOCO_PARALLEL_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_parallel_metrics[i], (unsigned long)r->last.loco_parallel_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned: %ls; one dispatch per stage, entity-range chunks claimed atomically by the pool; counters cumulative modulo 2^32; unsupported occurrences are refused to the owner before irreversible writes\n",
        r->opt.loco_owned ? L"ENABLED" : L"off");
    for (i = 0; i < NTW2_LOCO_OWNED_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_metrics[i], (unsigned long)r->last.loco_owned_words[i], (i+1)%4 ? L" " : L"\n");
    if (r->last.loco_owned_words[31])
        say(L"  active_worker_share=%.3f%% (%lu direct + %lu battle / %lu A1!=0 mover occurrences); PROFILE outer site 13 is the timing acceptance bracket\n",
            100.0 * ((double)r->last.loco_owned_words[2] + r->last.loco_owned_words[3]) / r->last.loco_owned_words[31],
            (unsigned long)r->last.loco_owned_words[2], (unsigned long)r->last.loco_owned_words[3],
            (unsigned long)r->last.loco_owned_words[31]);
    say(L"loco.owned.detail: quiet_enabled=%lu; staging initial/result A3==0, clamp callback, class and unit-blocked splits, F0 census\n",
        (unsigned long)r->last.loco_owned_detail_words[1]);
    for (i = 0; i < NTW2_LOCO_OWNED_DETAIL_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_detail_metrics[i], (unsigned long)r->last.loco_owned_detail_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned.phase: stage/dispatch/chunk timings; replay commit/fallback us are x16 estimates from every 16th occurrence\n");
    for (i = 0; i < NTW2_LOCO_OWNED_PHASE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_phase_metrics[i], (unsigned long)r->last.loco_owned_phase_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned.load: activation-only scene/catalog/participants/prefaulted arena; Stage never prepares or grows storage; chunk CPU and worst-chunk wall/CPU remain under quiet\n");
    for (i = 0; i < NTW2_LOCO_OWNED_LOAD_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_load_metrics[i], (unsigned long)r->last.loco_owned_load_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.shadow: owner-thread diagnostic only; faults invalidate equivalence; histogram targets use preferred-image VAs (host callbacks retain host addresses); sweep four kinds top2\nsweep:\n");
    for (i = 0; i < NTW2_SWEEP_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_sweep_metrics[i], (unsigned long)r->last.sweep_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"resolve:\n");
    for (i = 0; i < NTW2_RESOLVE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_resolve_metrics[i], (unsigned long)r->last.resolve_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"resolve frames:\n");
    for (i = 0; i < NTW2_RESOLVE_FRAME_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_resolve_frame_metrics[i], (unsigned long)r->last.resolve_frame_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"env: direct outputs compared; transition events inferred from flags, notifications unobserved; callback-implied is not proof of callback causality\n");
    for (i = 0; i < NTW2_ENV_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_env_metrics[i], (unsigned long)r->last.env_words[i], (i+1)%4 ? L" " : L"\n");
    for (i = 0; i < 3; ++i) {
        unsigned j;
        say(L"  env target kind %u (owner+24, owner+1C, notification+8):", i);
        for (j = 0; j < 8; ++j) say(L" %08lX/%lu", (unsigned long)r->last.env_target_words[i*16+j*2], (unsigned long)r->last.env_target_words[i*16+j*2+1]);
        say(L"\n");
    }
    if (r->opt.loco_parallel && w[2])
        say(L"  worker share %.3f%% of active occurrences (%.3f%% of serial-admitted); worker=%lu NeedsOwner=%lu; caller-executed chunks are included in worker-kernel entities\n",
            100.0*r->last.loco_parallel_words[3]/w[2],
            w[3] ? 100.0*r->last.loco_parallel_words[3]/w[3] : 0.0,
            (unsigned long)r->last.loco_parallel_words[3], (unsigned long)r->last.loco_parallel_words[4]);
    if (w[1])
        say(L"  inclusive LOCO gate mean %.3f ms versus supplied 12 ms reference (%.3fx); PROFILE site 13 is the separate outer bracket, not this inner gate sum\n",
            (double)w[23]/w[1]/1000.0, (double)w[23]/w[1]/12000.0);
}

static void print_collide(const Run *r)
{
    const uint32_t *w = r->last.collide_words;
    unsigned i;
    if (!(r->opt.mask & NTW2_COLLIDE)) return;
    if (!r->have_status) {
        say(L"collide: no runtime status observed.\n");
        return;
    }
    say(L"collide: Phase B opt-in; cumulative modulo-2^32 counters since activation\n"
        L"  parallel private numeric reduction; fully supported stages: ordered live redistribution + conditional sequential MAX\n"
        L"  over private labels, then ONE parallel store pass (numeric sums + dirty final labels + processed bytes), then a serial\n"
        L"  timed callback pass (callbacks see final processed bytes, velocities, labels and numeric sums); mixed unsupported stages\n"
        L"  parallel-commit numeric sums first, then keep owner per-record native queries\n"
        L"  with interleaved redistribution/callbacks. Native chain audit = parallel read-only pass, per-chunk SEH whole-stage fallback.\n"
        L"  diagnostics = first offending node snapshot, not per-tick averages; reason 0 = none\n"
        L"  record 131072 = no known context; cell 0xFFFFFFFF = unmappable; vtable = known current record\n"
        L"  reason 10 = owner absent from known primary/secondary registries; expected_record is validation context\n"
        L"  native_queries = unsupported original per-record calls; cells = occupied CSR cells (compact counting histogram)\n"
        L"  owner_continuations = postcommit callback-fault stages; solver suffix numerics are never reapplied\n"
        L"  solver_ticks may be all-native; pairs/contacts/callbacks exclude native query internals\n"
        L"  records = all worklist entries; eligible_queries = entry-snapshot +30 != 0 and (flags & 3) != 0\n"
        L"  shaped_pairs = original 0x81A670 calls with >=1 nonnull shape pointer (unshaped circles bypass it)\n"
        L"  *_thread_us = GetThreadTimes user+kernel CPU aggregated over owner+workers, not summed QPC; coarse resolution\n"
        L"  Compare per-stage counts using collide stage_calls vs collision_words[21], never original per-routed-tick averages.\n");
    for (i = 0; i < NTW2_COLLIDE_WORDS; ++i) {
        if (i == 29 || (i >= 34 && i <= 41))
            say(L"  %hs=0x%08lX%ls", k_collide_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
        else
            say(L"  %hs=%lu%ls", k_collide_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    }
    if (NTW2_COLLIDE_WORDS % 4) say(L"\n");
    say(L"collide.source: 0=none, 1=native-audit, 2=owned; missing owned view falls back before writes\n");
    for (i = 0; i < NTW2_COLLIDE_SOURCE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_collide_source_metrics[i], (unsigned long)r->last.collide_source_words[i], (i+1)%4 ? L" " : L"\n");
    {
        static const char *const contact_labels[NTW2_COLLIDE_CONTACT_WORDS] = { NTW2_COLLIDE_CONTACT_WORD_LABELS };
        const uint32_t *c = r->last.collide_contact_words;
        say(L"collide.contact (mode 1=shadow, 2=workers; vtables/slot are image-relative VAs):\n");
        for (i = 0; i < NTW2_COLLIDE_CONTACT_WORDS; ++i) {
            if (i >= 34 && i <= 36)
                say(L"  %hs=0x%08lX%ls", contact_labels[i], (unsigned long)c[i], (i+1)%4 ? L" " : L"\n");
            else
                say(L"  %hs=%lu%ls", contact_labels[i], (unsigned long)c[i], (i+1)%4 ? L" " : L"\n");
        }
        if (NTW2_COLLIDE_CONTACT_WORDS % 4) say(L"\n");
    }
    say(L"  per solver tick (denominator solver_ticks=%lu, NOT stage_calls=%lu which includes fallbacks):\n",
        (unsigned long)w[1], (unsigned long)w[0]);
    if (w[1]) {
        for (i = 0; i < sizeof k_collide_phases/sizeof k_collide_phases[0]; ++i) {
            say(L"    %hs: wall=%.3f us", k_collide_phases[i].name, (double)w[k_collide_phases[i].wall]/w[1]);
            if (k_collide_phases[i].thread >= 0)
                say(L" thread_cpu=%.3f us", (double)w[k_collide_phases[i].thread]/w[1]);
            if (k_collide_phases[i].nested_in) say(L" (nested in %hs; not additive)", k_collide_phases[i].nested_in);
            say(L"\n");
        }
    } else {
        say(L"    n/a: no completed solver tick\n");
    }
    say(L"    shaped_pairs: total=%lu", (unsigned long)w[44]);
    if (w[1]) say(L" per_solver_tick=%.3f", (double)w[44]/w[1]);
    say(L"\n  thread_clock_failures=%lu%ls\n", (unsigned long)w[55],
        w[55] ? L" (thread CPU totals are incomplete)" : L"");
}

static const struct { unsigned word; const wchar_t *label; const char *json; } k_brain_state_flags[] = {
    {2, L"early-exit entry predicate", "early_exit_predicate"},
    {3, L"self-deactivated (+30 cleared)", "self_deactivated"},
    {4, L"entry engage byte +F0 != 0", "entry_engage"},
    {5, L"unit combat proxy +AA0 != 0", "unit_combat_proxy"},
    {6, L"entry has no owning unit", "null_unit"}
};

/* Stable descending counts == descending shares; ties retain bucket order. */
static void brain_state_order(const uint32_t *counts, unsigned n, unsigned *order)
{
    unsigned i, j;
    for (i = 0; i < n; ++i) {
        for (j = i; j && counts[order[j-1]] < counts[i]; --j) order[j] = order[j-1];
        order[j] = i;
    }
}

static void brain_state_label(unsigned bucket, BOOL substate, wchar_t *label, size_t n)
{
    if (substate && bucket == 79)
        _snwprintf_s(label, n, _TRUNCATE, L">=0x4F");
    else if (!substate && bucket == 63)
        _snwprintf_s(label, n, _TRUNCATE, L"other");
    else
        _snwprintf_s(label, n, _TRUNCATE, L"0x%02X", !substate && bucket == 62 ? 0x4B : bucket);
}

static void print_brain_states(const Run *r)
{
    const uint32_t *w = r->last.brain_state_words;
    unsigned group, i, order[NTW2_BRAIN_SUBSTATE_BUCKETS];
    wchar_t label[24];
    if (!(r->opt.mask & NTW2_BRAIN) || !r->active_generations) return;
    if (!r->have_status || !w[0]) {
        say(L"Brain states: no routed tick with brain profiling was observed.\n");
        return;
    }
    say(L"Brain states: %lu routed ticks, %.2f entities/tick, %.2f distinct units/tick.\n"
        L"  Actual brain entry/return; cumulative since activation, modulo 2^32. Sorted by share.\n"
        L"  State buckets: 0x00..0x3D, 0x4B, other. Sub-state buckets: 0x00..0x4E, >=0x4F.\n",
        (unsigned long)w[0], (double)w[1]/w[0], (double)w[7]/w[0]);
    if (!w[1]) say(L"  No brain entries sampled (BRAIN2 suppresses the BRAIN entry hooks).\n");
    if (w[11]) say(L"  WARNING: %lu unit-set storage failures; distinct-unit totals are incomplete.\n", (unsigned long)w[11]);
    for (group = 0; group < 2; ++group) {
        const unsigned base = group ? NTW2_BRAIN_SUBSTATE_COUNTS : NTW2_BRAIN_STATE_COUNTS;
        const unsigned n = group ? NTW2_BRAIN_SUBSTATE_BUCKETS : NTW2_BRAIN_STATE_BUCKETS;
        brain_state_order(w+base, n, order);
        say(L"  %ls: state  entries/tick  entry-share\n", group ? L"Sub-FSM +1D8" : L"Brain +1B8");
        for (i = 0; i < n; ++i) {
            const unsigned bucket = order[i];
            const uint32_t count = w[base+bucket];
            if (!count) continue;
            brain_state_label(bucket, group != 0, label, 24);
            say(L"    %-8ls %12.2f %10.3f%%\n", label, (double)count/w[0], w[1] ? 100.0*count/w[1] : 0.0);
        }
    }
    for (i = 0; i < sizeof k_brain_state_flags/sizeof k_brain_state_flags[0]; ++i) {
        const uint32_t count = w[k_brain_state_flags[i].word];
        say(L"  %-36ls %.2f/tick (%.3f%% of entries)\n", k_brain_state_flags[i].label,
            (double)count/w[0], w[1] ? 100.0*count/w[1] : 0.0);
    }
    say(L"  Early predicate is not an observed return (three virtual checks can veto it).\n"
        L"  Combat proxy is NOT a proven combat flag: brain 0x66D55F tests unit+AA0 before setting +F0.\n"
        L"  0x4B -> other state: %.2f entities/tick, %.2f distinct units/tick; %.2f null-unit entities/tick.\n"
        L"    destination  entities/tick  units/tick  transition-share\n",
        (double)w[8]/w[0], (double)w[9]/w[0], (double)w[10]/w[0]);
    brain_state_order(w+NTW2_BRAIN_TRANSITION_COUNTS, NTW2_BRAIN_STATE_BUCKETS, order);
    for (i = 0; i < NTW2_BRAIN_STATE_BUCKETS; ++i) {
        const unsigned bucket = order[i];
        const uint32_t count = w[NTW2_BRAIN_TRANSITION_COUNTS+bucket];
        if (!count) continue;
        brain_state_label(bucket, FALSE, label, 24);
        say(L"    %-11ls %12.2f %11.2f %16.3f%%\n", label, (double)count/w[0],
            (double)w[NTW2_BRAIN_TRANSITION_UNITS+bucket]/w[0], w[8] ? 100.0*count/w[8] : 0.0);
    }
}

/* ------------------------------------------------------------------------------------------------ receipt */
typedef struct Sb {
    char *p;
    size_t len, cap;
    BOOL oom;
} Sb;

static void sb_put(Sb *b, const char *s, size_t n)
{
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        b->oom = TRUE;
        return;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_fmt(Sb *b, const char *fmt, ...)
{
    char tmp[2048];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = _vsnprintf_s(tmp, sizeof tmp, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n > 0) sb_put(b, tmp, (size_t)n);
    else if (n < 0) b->oom = TRUE;
}

static void sb_wstr(Sb *b, const wchar_t *s)
{
    static char u8[MAXP * 4];
    char esc[8];
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, u8, (int)sizeof u8, NULL, NULL);
    int i;
    sb_put(b, "\"", 1);
    for (i = 0; n > 0 && i < n - 1; ++i) {
        unsigned char c = (unsigned char)u8[i];
        if (c == '"' || c == '\\') { esc[0] = '\\'; esc[1] = (char)c; sb_put(b, esc, 2); }
        else if (c < 0x20) { _snprintf_s(esc, sizeof esc, _TRUNCATE, "\\u%04x", c); sb_put(b, esc, 6); }
        else sb_put(b, (const char *)&c, 1);
    }
    sb_put(b, "\"", 1);
}

static void iso_time(const FILETIME *ft, char *out, size_t n)
{
    SYSTEMTIME st;
    if (FileTimeToSystemTime(ft, &st))
        _snprintf_s(out, n, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay, st.wHour,
                    st.wMinute, st.wSecond, st.wMilliseconds);
    else
        _snprintf_s(out, n, _TRUNCATE, "unknown");
}

static void sb_mask(Sb *b, uint32_t m)
{
    size_t i, c = 0;
    sb_put(b, "[", 1);
    for (i = 0; i < NFEATURES; ++i)
        if (m & k_features[i].bit) sb_fmt(b, "%s\"%s\"", c++ ? "," : "", k_features[i].jname);
    sb_put(b, "]", 1);
}

static void sb_tick_log(Sb *b, const Run *r)
{
    const TickLog *log = &r->tick_log;
    uint32_t i;
    if (!r->opt.tick_log[0]) return;
    sb_fmt(b, "  \"tick_log\": {\"file\":");
    sb_wstr(b, r->opt.tick_log);
    sb_fmt(b, ",\"count\":%lu,\"lost\":%I64u},\n  \"tick_log_summary\": [",
           (unsigned long)log->count, (unsigned long long)log->lost);
    for (i = 0; i < log->count; ++i) {
        const ntw2_trace_entry *e = &log->entries[i];
        sb_fmt(b, "%s{\"tick\":%lu,\"qpc_start\":%I64u,\"qpc_end\":%I64u,"
               "\"duration_us\":%lu,\"interval_us\":%lu,\"site5_us\":%lu,\"site6_us\":%lu,"
               "\"site13_us\":%lu,\"site18_us\":%lu,\"site33_us\":%lu,\"site34_us\":%lu}",
               i ? "," : "", (unsigned long)e->tick,
               (unsigned long long)trace_qpc(e->qpc_start_lo, e->qpc_start_hi),
               (unsigned long long)trace_qpc(e->qpc_end_lo, e->qpc_end_hi),
               (unsigned long)e->duration_us, (unsigned long)e->interval_us,
               (unsigned long)e->site_us[5], (unsigned long)e->site_us[6],
               (unsigned long)e->site_us[13], (unsigned long)e->site_us[18],
               (unsigned long)e->site_us[33], (unsigned long)e->site_us[34]);
    }
    sb_fmt(b, "],\n");
}

static const char *const k_profile_modules[NTW2_PROFILE_MODULE_COUNT] = {
    "main_image", "ntw2", "d3d9", "driver", "ntdll", "kernel32", "tbb", "msvcr", "other"
};
static const char *const k_profile_phases[NTW2_PROFILE_MAIN_PHASES] = { "A1", "B", "C", "A2" };
static const uint32_t k_profile_phase_order[NTW2_PROFILE_MAIN_PHASES] = {
    NTW2_PROFILE_PHASE_A1, NTW2_PROFILE_PHASE_A2, NTW2_PROFILE_PHASE_B, NTW2_PROFILE_PHASE_C
};

static void sb_profile_modules(Sb *b, const Run *r)
{
    const ntw2_profile_status *p = &r->profile;
    uint32_t phase, index, module;
    if (!r->have_profile) {
        sb_fmt(b, "  \"main_thread_profile\": null,\n");
        return;
    }
    sb_fmt(b, "  \"main_thread_profile\": {\"abi\": %lu, \"thread_id\": %lu, \"post_tick_ms\": %lu, \"start_tick_ms\": %lu, "
           "\"module_refresh_failed\": %lu, \"module_omitted\": %lu, \"phases\": [",
           (unsigned long)p->abi, (unsigned long)p->main_thread_id, (unsigned long)p->main_post_tick_ms,
           (unsigned long)p->main_start_tick_ms, (unsigned long)p->module_refresh_failed, (unsigned long)p->module_omitted);
    for (index = 0; index < NTW2_PROFILE_MAIN_PHASES; ++index) {
        phase = k_profile_phase_order[index];
        sb_fmt(b, "%s{\"phase\": \"%s\", \"samples\": %lu, \"wait_samples\": %lu, \"modules\": {",
               index ? "," : "", k_profile_phases[phase], (unsigned long)NTW2_PROFILE_PHASE_FIELD(p, phase, samples),
               (unsigned long)NTW2_PROFILE_PHASE_FIELD(p, phase, wait));
        for (module = 0; module < NTW2_PROFILE_MODULE_COUNT; ++module)
            sb_fmt(b, "%s\"%s\": %lu", module ? "," : "", k_profile_modules[module],
                   (unsigned long)NTW2_PROFILE_PHASE_FIELD(p, phase, modules)[module]);
        sb_fmt(b, "}}");
    }
    sb_fmt(b, "]},\n");
}

static void sb_trace(Sb *b, const TickTrace *t)
{
    const ntw2_trace_ring *p;
    double share_scale;
    uint32_t i, j, start;
    if (!t || !t->analyzed) {
        sb_fmt(b, "  \"tick_trace\": null,\n");
        return;
    }
    p = &t->copies[t->current];
    start = (p->head + p->entries - t->count) % p->entries;
    share_scale = t->duration_sum ? 1.0 / (double)t->duration_sum : 0.0;
    sb_fmt(b, "  \"tick_trace\": {\n    \"count\": %lu, \"written\": %lu, \"first_tick\": %lu, \"last_tick\": %lu,\n"
           "    \"duration_us\": {\"p50\": %lu, \"p90\": %lu, \"p99\": %lu, \"max\": %lu},\n"
           "    \"interval_us\": {\"p50\": %lu, \"p90\": %lu, \"p99\": %lu, \"max\": %lu},\n",
           (unsigned long)t->count, (unsigned long)p->written, (unsigned long)t->first_tick, (unsigned long)t->last_tick,
           (unsigned long)t->duration[0], (unsigned long)t->duration[1], (unsigned long)t->duration[2], (unsigned long)t->duration[3],
           (unsigned long)t->interval[0], (unsigned long)t->interval[1], (unsigned long)t->interval[2], (unsigned long)t->interval[3]);
    sb_fmt(b, "    \"sums_us\": {\"duration\": %I64u, \"manager\": %I64u, \"ballistics\": %I64u, \"path\": %I64u, \"remainder\": %I64d},\n"
           "    \"duration_share\": {\"manager\": %.9f, \"ballistics\": %.9f, \"path\": %.9f, \"remainder\": %.9f},\n"
           "    \"over_100ms\": %lu, \"over_150ms\": %lu,\n",
           (unsigned long long)t->duration_sum, (unsigned long long)t->manager_sum,
           (unsigned long long)t->ballistics_sum, (unsigned long long)t->path_sum, (long long)t->remainder_sum,
           t->manager_sum * share_scale, t->ballistics_sum * share_scale,
           t->path_sum * share_scale, t->remainder_sum * share_scale,
           (unsigned long)t->over100, (unsigned long)t->over150);
    sb_fmt(b, "    \"qpc_frequency\": %I64u,\n    \"qpc_semantics\": \"raw QPC; duration_us includes site-34 AI slice; end includes final hold cleanup\",\n"
           "    \"ticks\": [", (unsigned long long)trace_qpc(p->qpc_freq_lo, p->qpc_freq_hi));
    for (i = 0; i < t->count; ++i) {
        const ntw2_trace_entry *e = &p->ring[(start + i) % p->entries];
        sb_fmt(b, "%s\n      {\"tick\": %lu, \"qpc_start\": %I64u, \"qpc_end\": %I64u, \"duration_us\": %lu}",
               i ? "," : "", (unsigned long)e->tick,
               (unsigned long long)trace_qpc(e->qpc_start_lo, e->qpc_start_hi),
               (unsigned long long)trace_qpc(e->qpc_end_lo, e->qpc_end_hi), (unsigned long)e->duration_us);
    }
    sb_fmt(b, "\n    ],\n");
    sb_fmt(b, "    \"trace_abi\": %u,\n    \"timed_ticks\": %lu,\n"
           "    \"site_semantics\": \"inclusive enter-to-return per call; site 2 includes sites 16..25; skipped sites zero\",\n"
           "    \"site_share_basis\": \"all retained tick durations\",\n    \"sites\": [",
           NTW2_TRACE_ABI, (unsigned long)t->timed_ticks);
    for (i = 0; i < NTW2_TIMED_SITES; ++i)
        sb_fmt(b, "%s\n      {\"index\": %lu, \"callee_va\": \"0x%06lX\", \"sum_us\": %I64u, \"calls\": %I64u, \"duration_share\": %.9f}",
               i ? "," : "", (unsigned long)i, (unsigned long)k_site_callee_vas[i],
               (unsigned long long)t->site_sum[i], (unsigned long long)t->site_calls[i], t->site_sum[i] * share_scale);
    sb_fmt(b, "\n    ],\n    \"longest_ticks\": [");
    for (i = 0; i < t->top_count; ++i) {
        const ntw2_trace_entry *e = &p->ring[t->top[i]];
        sb_fmt(b, "%s\n      {\"tick\": %lu, \"duration_us\": %lu, \"interval_us\": %lu, "
               "\"manager_us\": %lu, \"ballistics_us\": %lu, \"path_us\": %lu, \"sites\": [",
               i ? "," : "", (unsigned long)e->tick, (unsigned long)e->duration_us, (unsigned long)e->interval_us,
               (unsigned long)e->manager_us, (unsigned long)e->ballistics_us, (unsigned long)e->path_us);
        for (j = 0; j < NTW2_TIMED_SITES; ++j)
            sb_fmt(b, "%s{\"index\": %lu, \"callee_va\": \"0x%06lX\", \"us\": %lu, \"calls\": %lu}",
                   j ? ", " : "", (unsigned long)j, (unsigned long)k_site_callee_vas[j],
                   (unsigned long)e->site_us[j], (unsigned long)e->site_calls[j]);
        sb_fmt(b, "]}");
    }
    sb_fmt(b, "\n    ],\n    \"periodicity\": {\"duration_threshold\": \"duration_us > 1.5 * p50\", "
           "\"tick_mod_100_bin_width\": 10, \"tick_mod_100\": [");
    for (i = 0; i < 10; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)t->mod100[i]);
    sb_fmt(b, "], \"tick_mod_10\": [");
    for (i = 0; i < 10; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)t->mod10[i]);
    sb_fmt(b, "]}\n  },\n");
}

/* BRAIN2 v2: raw QPC totals are separated for native and serial clone calls.
   Service counters are absent in observe-only mode, not inferred to be inactive. */
static void sb_brain2(Sb *b, const Run *r)
{
    const uint32_t *g = r->last.brain2_words;
    unsigned i;
    if (!(r->opt.mask & NTW2_BRAIN2) || !r->have_status) {
        sb_fmt(b, "  \"brain2\": null,\n");
        return;
    }
    sb_fmt(b, "  \"brain2\": {\"schema_version\": 2, \"requested_census\": %s, \"requested_timing\": %s, "
           "\"version\": %lu, \"census_enabled\": %lu, \"timing_enabled\": %lu, "
           "\"dispatches\": %lu, \"occurrences\": %lu, \"original_occurrences\": %lu, "
           "\"serial_clone_occurrences\": %lu, \"fully_inactive\": %lu, \"any_active\": %lu, "
           "\"any_unknown\": %lu, \"needs_owner\": %lu, \"fully_inactive_fraction\": ",
           r->opt.brain_census ? "true" : "false", r->opt.brain_timing ? "true" : "false",
           (unsigned long)g[0], (unsigned long)g[1], (unsigned long)g[2], (unsigned long)g[4],
           (unsigned long)g[5], (unsigned long)g[6], (unsigned long)g[7], (unsigned long)g[8],
           (unsigned long)g[9], (unsigned long)g[10], (unsigned long)g[11]);
    if (g[1] && g[7]) sb_fmt(b, "%.9f", (double)g[8] / g[7]);
    else sb_fmt(b, "null");
    sb_fmt(b, ", \"original_qpc_ticks\": %I64u, \"clone_qpc_ticks\": %I64u, \"qpc_frequency\": %I64u, "
           "\"pose_reads\": %lu, \"leader_pose_reads\": %lu, \"target_pose_reads\": %lu, "
           "\"other_pose_reads\": %lu, \"self_pose_reads\": %lu, "
           "\"last_first_active\": %lu, \"last_first_unknown\": %lu, "
           "\"last_pose\": {\"reader\": %lu, \"subject\": %lu, \"leader\": %lu, \"target\": %lu}, \"class_counts\": [",
           (ULONGLONG)g[26] | ((ULONGLONG)g[27] << 32),
           (ULONGLONG)g[46] | ((ULONGLONG)g[47] << 32),
           (ULONGLONG)g[28] | ((ULONGLONG)g[29] << 32),
           (unsigned long)g[16], (unsigned long)g[17], (unsigned long)g[18], (unsigned long)g[19],
           (unsigned long)g[20], (unsigned long)g[32], (unsigned long)g[33],
           (unsigned long)g[34], (unsigned long)g[35], (unsigned long)g[36], (unsigned long)g[37]);
    for (i = 0; i < 6; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)g[40+i]);
    sb_fmt(b, "], \"class_order\": [\"core\",\"thunk\",\"wrapper602eb0\",\"wrapper5fceb0\",\"artillery\",\"other\"], \"services\": [");
    for (i = 0; i < NTW2_BRAIN2_CENSUS_WORDS / 8u; ++i) {
        const uint32_t *q = r->last.brain2_census_words + i * 8;
        sb_fmt(b, "%s{\"id\": %u, \"name\": \"%s\", \"calls\": %lu, \"active\": %lu, \"unknown\": %lu, "
               "\"inactive\": %lu, \"first_active_occurrences\": %lu, \"first_unknown_occurrences\": %lu, \"qpc_ticks\": %I64u}",
               i ? "," : "", i, k_brain2_services[i], (unsigned long)q[0], (unsigned long)q[1],
               (unsigned long)q[2], (unsigned long)q[3], (unsigned long)q[4], (unsigned long)q[5],
               (ULONGLONG)q[6] | ((ULONGLONG)q[7] << 32));
    }
    sb_fmt(b, "], \"requested_node_shadow\": %s, \"requested_fire_shadow\": %s, \"node_words\": [",
           r->opt.brain_node_shadow ? "true" : "false", r->opt.brain_fire_shadow ? "true" : "false");
    for (i = 0; i < NTW2_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.node_words[i]);
    sb_fmt(b, "], \"node_event_words\": [");
    for (i = 0; i < NTW2_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.node_event_words[i]);
    sb_fmt(b, "], \"fire_words\": [");
    for (i = 0; i < NTW2_FIRE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.fire_words[i]);
    sb_fmt(b, "], \"route_words\": [");
    for (i = 0; i < NTW2_BRAIN2_ROUTE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_route_words[i]);
    sb_fmt(b, "], \"fire_commit_words\": [");
    for (i = 0; i < NTW2_FIRE_COMMIT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.fire_commit_words[i]);
    sb_fmt(b, "], \"move_node_words\": [");
    for (i = 0; i < NTW2_MOVE_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.move_node_words[i]);
    sb_fmt(b, "], \"move_node_event_words\": [");
    for (i = 0; i < NTW2_MOVE_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.move_node_event_words[i]);
    sb_fmt(b, "], \"node_target_words\": [");
    for (i = 0; i < NTW2_BRAIN2_NODE_TARGET_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_node_target_words[i]);
    sb_fmt(b, "], \"requested_parallel\": %s, \"requested_quiet\": %s, \"brain_worker_words\": [",
           r->opt.brain_parallel ? "true" : "false", r->opt.brain_quiet ? "true" : "false");
    for (i = 0; i < NTW2_BRAIN_WORKER_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_worker_words[i]);
    sb_fmt(b, "], \"requested_unit_shadow\": %s, \"brain_unit_words\": [", r->opt.brain_unit_shadow ? "true" : "false");
    for (i = 0; i < NTW2_BRAIN_UNIT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_unit_words[i]);
    {
        static const char *const fields[] = { NTW2_BRAIN_UNIT_FIELD_LABELS };
        static const char *const columns[] = { NTW2_BRAIN_UNIT_FIELD_WORD_LABELS };
        unsigned f, c;
        sb_fmt(b, "], \"unit_agreement\": {");
        for (f = 0; f < sizeof(fields) / sizeof(fields[0]); ++f) {
            sb_fmt(b, "%s\"%s\": {", f ? ", " : "", fields[f]);
            for (c = 0; c < sizeof(columns) / sizeof(columns[0]); ++c)
                sb_fmt(b, "%s\"%s\": %lu", c ? ", " : "", columns[c],
                       (unsigned long)r->last.brain_unit_words[16u + 8u * f + c]);
            sb_fmt(b, ", \"%s\": %lu}", NTW2_BRAIN_UNIT_TICK_NONE_LABEL, (unsigned long)r->last.brain_unit_words[160u + f]);
        }
        {
            static const char *const roles[] = { NTW2_BRAIN_UNIT_ROLE_LABELS };
            for (c = 0; c < 3u; ++c)
                sb_fmt(b, ", \"%s\": %lu", roles[c], (unsigned long)r->last.brain_unit_words[169u + c]);
        }
    }
    sb_fmt(b, "}, \"brain_worker_phase_words\": [");
    for (i = 0; i < NTW2_BRAIN_WORKER_PHASE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_worker_phase_words[i]);
    sb_fmt(b, "], \"unknown_site_words\": [");
    for (i = 0; i < NTW2_BRAIN2_UNKNOWN_SITE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_unknown_site_words[i]);
    sb_fmt(b, "], \"idle_node_words\": [");
    for (i = 0; i < NTW2_IDLE_NODE_CLASSES * NTW2_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.idle_node_words[i / NTW2_NODE_WORDS][i % NTW2_NODE_WORDS]);
    sb_fmt(b, "], \"idle_node_event_words\": [");
    for (i = 0; i < NTW2_IDLE_NODE_CLASSES * NTW2_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.idle_node_event_words[i / NTW2_NODE_EVENT_WORDS][i % NTW2_NODE_EVENT_WORDS]);
    sb_fmt(b, "], \"action_node_words\": [");
    for (i = 0; i < NTW2_ACTION_NODE_CLASSES * NTW2_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.action_node_words[i / NTW2_NODE_WORDS][i % NTW2_NODE_WORDS]);
    sb_fmt(b, "], \"action_node_event_words\": [");
    for (i = 0; i < NTW2_ACTION_NODE_CLASSES * NTW2_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.action_node_event_words[i / NTW2_NODE_EVENT_WORDS][i % NTW2_NODE_EVENT_WORDS]);
    sb_fmt(b, "]},\n");
}

/* "brain_sites": cumulative per-family and aggregate brain/wrapper callee timings (see print_brain_sites); null unless the brain
   feature was requested and a routed tick was observed. Shares divide by the routed tick duration sum (brain_words[1]). */
static void sb_brain(Sb *b, const Run *r)
{
    const ntw2_status *s = &r->last;
    const uint32_t ticks = s->brain_words[0], tick_us = s->brain_words[1];
    const double scale = tick_us ? 1.0 / (double)tick_us : 0.0;
    uint64_t agg_us[NTW2_TIMED_SITES], agg_calls[NTW2_TIMED_SITES];
    uint32_t f, site;
    char callee[24];
    if (!(r->opt.mask & NTW2_BRAIN) || !r->have_status || !ticks) {
        sb_fmt(b, "  \"brain_sites\": null,\n");
        return;
    }
    memset(agg_us, 0, sizeof agg_us);
    memset(agg_calls, 0, sizeof agg_calls);
    sb_fmt(b, "  \"brain_sites\": {\n    \"routed_ticks\": %lu, \"tick_sum_us\": %lu,\n"
           "    \"semantics\": \"cumulative since the last activation; inclusive enter-to-return per call; rows overlap and include "
           "each timed call's own timing overhead; tick_share = sum_us / tick_sum_us; callee is the original VA or vt+offset\",\n"
           "    \"families\": [",
           (unsigned long)ticks, (unsigned long)tick_us);
    for (f = 0; f < NTW2_BRAIN_FAMILIES; ++f) {
        const uint32_t entities = brain_calls(s, f, NTW2_BRAIN_SITE_FIRST + f);
        const uint32_t entry_us = brain_us(s, f, NTW2_BRAIN_SITE_FIRST + f);
        uint32_t rows = 0;
        sb_fmt(b, "%s\n      {\"index\": %lu, \"name\": \"%s\", \"vtables\": %lu, \"entry_va\": \"0x%06lX\", \"entities\": %lu, "
               "\"entities_per_tick\": %.6f, \"entry_sum_us\": %lu, \"entry_tick_share\": %.9f, \"sites\": [",
               f ? "," : "", (unsigned long)f, k_brain_families[f].jname, (unsigned long)k_brain_families[f].tables,
               (unsigned long)k_brain_families[f].entry_va, (unsigned long)entities, (double)entities / ticks,
               (unsigned long)entry_us, entry_us * scale);
        for (site = NTW2_BRAIN_SITE_FIRST; site < NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_SITES; ++site) {
            const uint32_t us = brain_us(s, f, site), calls = brain_calls(s, f, site);
            if (site >= BRAIN_FIRST_CALLEE) { agg_us[site] += us; agg_calls[site] += calls; }
            if (!brain_family_owns(f, site) || site == NTW2_BRAIN_SITE_FIRST + f) continue;
            if (k_site_callee_vas[site] < 0x400000u)
                _snprintf_s(callee, sizeof callee, _TRUNCATE, "vt+0x%lX", (unsigned long)k_site_callee_vas[site]);
            else
                _snprintf_s(callee, sizeof callee, _TRUNCATE, "0x%06lX", (unsigned long)k_site_callee_vas[site]);
            sb_fmt(b, "%s\n        {\"index\": %lu, \"callee\": \"%s\", \"sum_us\": %lu, \"calls\": %lu, \"calls_per_tick\": %.6f, "
                   "\"us_per_call\": %.6f, \"tick_share\": %.9f}",
                   rows++ ? "," : "", (unsigned long)site, callee, (unsigned long)us, (unsigned long)calls,
                   (double)calls / ticks, calls ? (double)us / calls : 0.0, us * scale);
        }
        sb_fmt(b, "\n      ]}");
    }
    sb_fmt(b, "\n    ],\n    \"brain_callees_all_families\": [");
    for (site = BRAIN_FIRST_CALLEE; site < NTW2_BRAIN_SITE_FIRST + NTW2_BRAIN_SITES; ++site) {
        if (k_site_callee_vas[site] < 0x400000u)
            _snprintf_s(callee, sizeof callee, _TRUNCATE, "vt+0x%lX", (unsigned long)k_site_callee_vas[site]);
        else
            _snprintf_s(callee, sizeof callee, _TRUNCATE, "0x%06lX", (unsigned long)k_site_callee_vas[site]);
        sb_fmt(b, "%s\n      {\"index\": %lu, \"callee\": \"%s\", \"sum_us\": %I64u, \"calls\": %I64u, \"calls_per_tick\": %.6f, "
               "\"us_per_call\": %.6f, \"tick_share\": %.9f}",
               site > BRAIN_FIRST_CALLEE ? "," : "", (unsigned long)site, callee, (unsigned long long)agg_us[site],
               (unsigned long long)agg_calls[site], (double)agg_calls[site] / ticks,
               agg_calls[site] ? (double)agg_us[site] / (double)agg_calls[site] : 0.0, agg_us[site] * scale);
    }
    sb_fmt(b, "\n    ]\n  },\n");
}

static void sb_collision(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.collision_words;
    unsigned i;
    if (!r->opt.collide_census || !(r->opt.mask & NTW2_PROFILE) || (r->opt.mask & NTW2_COLLIDE) || !r->have_status || !w[0]) {
        sb_fmt(b, "  \"collision\": null,\n");
        return;
    }
    sb_fmt(b, "  \"collision\": {\"routed_ticks\": %lu, \"stage_calls\": %lu, \"max_ids_per_query\": %lu, \"timed_stack_overflows\": %lu,\n"
           "    \"semantics\": \"cumulative since activation, u32 totals; per_tick divides by all routed PROFILE ticks, "
           "including ticks without a stage; per_stage divides by collision_words[21] stage_calls (null if zero); "
           "compare solver counts only with matching per-stage or per-routed-tick denominators; explicit --collide-census plus PROFILE original ordered collision clones; "
           "candidate = first post-dedup filter; numeric = height/radius/response region including helper and writes; "
           "traversal = stage - numeric - callbacks including bookkeeping/instrumentation; query/append/helper are nested; "
           "raw QPC sums converted to us; callback counts are direct vt+44 calls, recursive callbacks only included in time\",\n"
           "    \"metrics\": {",
           (unsigned long)w[0], (unsigned long)w[21], (unsigned long)w[22], (unsigned long)w[23]);
    for (i = 0; i < sizeof k_collision_metrics/sizeof k_collision_metrics[0]; ++i) {
        sb_fmt(b, "%s\n      \"%s\": {\"sum\": %lu, \"per_tick\": %.6f, \"per_stage\": ", i ? "," : "",
               k_collision_metrics[i].name, (unsigned long)w[k_collision_metrics[i].word],
               (double)w[k_collision_metrics[i].word]/w[0]);
        if (w[21]) sb_fmt(b, "%.6f}", (double)w[k_collision_metrics[i].word]/w[21]);
        else sb_fmt(b, "null}");
    }
    sb_fmt(b, "\n    }\n  },\n");
}

static void sb_ratio(Sb *b, uint32_t sum, uint32_t denominator)
{
    if (denominator) sb_fmt(b, "%.6f", (double)sum/denominator);
    else sb_fmt(b, "null");
}

static const char *const k_grid_threads[NTW2_GRID_THREADS] = {
    "tick_owner", "main_render", "other"
};

static const char *grid_route_name(uint32_t route)
{
    switch (route) {
    case NTW2_GRID_ROUTE_IMAGE: return "image";
    case NTW2_GRID_ROUTE_BINDING: return "binding";
    case NTW2_GRID_ROUTE_CLONE: return "clone";
    case NTW2_GRID_ROUTE_OTHER: return "other";
    default: return "unknown";
    }
}

static void print_grid_census(const Run *r)
{
    const ntw2_grid_census_status *c = &r->last.grid_census;
    unsigned i, j;
    if (!(r->opt.mask & NTW2_GRID_CENSUS)) return;
    if (!r->have_status || c->version != 1u) {
        say(L"Grid census: no initialized census snapshot available.\n");
        return;
    }
    say(L"Grid census: %lu routed ticks; %lu readers (capacity %u), %lu instrumented edges (capacity %u).\n",
        (unsigned long)c->routed_ticks, (unsigned long)c->reader_count, NTW2_GRID_READERS,
        (unsigned long)c->edge_count, NTW2_GRID_EDGES);
    say(L"  Route calls count retargeted private-clone edges. Only IMAGE destinations prove native reader entries.\n"
        L"  Binding/clone/other destinations may defer, skip or replace readers; route calls are NOT reader entries.\n"
        L"  Rates divide the corresponding in-tick calls by routed ticks (n/a if zero). Samples are EIP occupancy, never calls.\n"
        L"  Totals wrap modulo 2^32 over this start/stop session. Phase/site/thread histograms count routes, not entries.\n"
        L"  Last tick/site/thread/phase are hints; site %u is unknown; non-owner sites observe the owner's dispatch site.\n",
        NTW2_GRID_UNKNOWN_SITE);
    say(L"  sample_attempts=%lu sample_failures=%lu unknown_samples=%lu attribution_dropped=%lu edge_dropped=%lu unresolved_edges=%lu\n",
        (unsigned long)c->sample_attempts, (unsigned long)c->sample_failures,
        (unsigned long)c->unknown_samples, (unsigned long)c->attribution_dropped,
        (unsigned long)c->edge_dropped, (unsigned long)c->unresolved_edges);
    say(L"  unresolved_edges counts ungated internal-call/direct-jump references, not measured calls or complete coverage.\n");
    for (i = 0; i < c->reader_count && i < NTW2_GRID_READERS; ++i) {
        const ntw2_grid_reader_status *v = &c->readers[i];
        say(L"  reader %u [0x%08lX,0x%08lX): route_calls=%lu route_tick_calls=%lu routes/routed_tick=",
            i, (unsigned long)v->va, (unsigned long)v->end,
            (unsigned long)v->route_calls, (unsigned long)v->route_tick_calls);
        if (c->routed_ticks) say(L"%.6f", (double)v->route_tick_calls/c->routed_ticks);
        else say(L"n/a");
        say(L" entry_calls=%lu entry_tick_calls=%lu entries/routed_tick=",
            (unsigned long)v->entry_calls, (unsigned long)v->entry_tick_calls);
        if (c->routed_ticks) say(L"%.6f", (double)v->entry_tick_calls/c->routed_ticks);
        else say(L"n/a");
        say(L" occupancy original=%lu clone=%lu; last tick=%lu site=%lu thread=%lu phase=%lu\n",
            (unsigned long)v->original_samples, (unsigned long)v->clone_samples,
            (unsigned long)v->last_tick, (unsigned long)v->last_site,
            (unsigned long)v->last_thread, (unsigned long)v->last_phase);
        for (j = 0; j < NTW2_GRID_PHASES; ++j)
            say(L"    phase %-2hs route_calls=%lu occupancy=%lu\n", k_profile_phases[j],
                (unsigned long)v->calls_phase[j], (unsigned long)v->samples_phase[j]);
        for (j = 0; j < NTW2_GRID_THREADS; ++j)
            say(L"    thread %-17hs route_calls=%lu occupancy=%lu\n", k_grid_threads[j],
                (unsigned long)v->calls_thread[j], (unsigned long)v->samples_thread[j]);
        for (j = 0; j < NTW2_GRID_SITES; ++j)
            if (v->calls_site[j] || v->samples_site[j])
                say(L"    site %u route_calls=%lu occupancy=%lu\n", j,
                    (unsigned long)v->calls_site[j], (unsigned long)v->samples_site[j]);
    }
    for (i = 0; i < c->edge_count && i < NTW2_GRID_EDGES; ++i) {
        const ntw2_grid_edge_status *e = &c->edges[i];
        say(L"  edge %u reader=%lu callsite=0x%08lX source_clone=0x%08lX route=%hs route_calls=%lu route_tick_calls=%lu routes/routed_tick=",
            i, (unsigned long)e->reader, (unsigned long)e->site, (unsigned long)e->source_clone,
            grid_route_name(e->route), (unsigned long)e->route_calls, (unsigned long)e->route_tick_calls);
        if (c->routed_ticks) say(L"%.6f", (double)e->route_tick_calls/c->routed_ticks);
        else say(L"n/a");
        say(L" last tick=%lu thread=%lu\n", (unsigned long)e->last_tick, (unsigned long)e->last_thread);
    }
}

static void sb_grid_census(Sb *b, const Run *r)
{
    const ntw2_grid_census_status *c = &r->last.grid_census;
    unsigned i, j;
    if (!(r->opt.mask & NTW2_GRID_CENSUS) || !r->have_status || c->version != 1u) {
        sb_fmt(b, "  \"grid_census\": null,\n");
        return;
    }
    sb_fmt(b, "  \"grid_census\": {\"version\":%lu,\"reader_count\":%lu,\"edge_count\":%lu,"
           "\"reader_capacity\":%u,\"edge_capacity\":%u,\"routed_ticks\":%lu,"
           "\"sample_attempts\":%lu,\"sample_failures\":%lu,\"unknown_samples\":%lu,"
           "\"attribution_dropped\":%lu,\"edge_dropped\":%lu,\"unresolved_edges\":%lu,\n",
           (unsigned long)c->version, (unsigned long)c->reader_count, (unsigned long)c->edge_count,
           NTW2_GRID_READERS, NTW2_GRID_EDGES, (unsigned long)c->routed_ticks,
           (unsigned long)c->sample_attempts, (unsigned long)c->sample_failures,
           (unsigned long)c->unknown_samples, (unsigned long)c->attribution_dropped,
           (unsigned long)c->edge_dropped, (unsigned long)c->unresolved_edges);
    sb_fmt(b, "    \"semantics\":\"u32 totals wrap; cumulative over one start/stop session including reactivations; "
           "route_calls count retargeted private-clone edges; only IMAGE routes prove native reader entry_calls; "
           "binding/clone/other routes may defer, skip or replace readers and are not reader entries; "
           "rates divide corresponding in-tick calls by every routed tick (null if zero); "
           "samples are EIP occupancy, never inferred calls; phase/thread/site histograms count routes and are independent marginals; "
           "last_* are hints; site 112 is unknown; non-owner sites observe the owner's dispatch site; "
           "unresolved_edges counts ungated internal-call/direct-jump references, not measured calls; "
           "edge site/source_clone are preferred-image VAs; reader id joins the static census readers array\","
           "\"readers\":[");
    for (i = 0; i < c->reader_count && i < NTW2_GRID_READERS; ++i) {
        const ntw2_grid_reader_status *v = &c->readers[i];
        sb_fmt(b, "%s{\"id\":%u,\"va\":%lu,\"end\":%lu,\"route_calls\":%lu,\"route_tick_calls\":%lu,"
               "\"route_calls_per_routed_tick\":", i ? "," : "", i,
               (unsigned long)v->va, (unsigned long)v->end,
               (unsigned long)v->route_calls, (unsigned long)v->route_tick_calls);
        sb_ratio(b, v->route_tick_calls, c->routed_ticks);
        sb_fmt(b, ",\"entry_calls\":%lu,\"entry_tick_calls\":%lu,\"entry_calls_per_routed_tick\":",
               (unsigned long)v->entry_calls, (unsigned long)v->entry_tick_calls);
        sb_ratio(b, v->entry_tick_calls, c->routed_ticks);
        sb_fmt(b, ",\"original_samples\":%lu,\"clone_samples\":%lu,"
               "\"last_tick\":%lu,\"last_site\":%lu,\"last_thread\":%lu,\"last_phase\":%lu,\"phases\":{",
               (unsigned long)v->original_samples, (unsigned long)v->clone_samples,
               (unsigned long)v->last_tick, (unsigned long)v->last_site,
               (unsigned long)v->last_thread, (unsigned long)v->last_phase);
        for (j = 0; j < NTW2_GRID_PHASES; ++j)
            sb_fmt(b, "%s\"%s\":{\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", k_profile_phases[j],
                   (unsigned long)v->calls_phase[j], (unsigned long)v->samples_phase[j]);
        sb_fmt(b, "},\"thread_classes\":{");
        for (j = 0; j < NTW2_GRID_THREADS; ++j)
            sb_fmt(b, "%s\"%s\":{\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", k_grid_threads[j],
                   (unsigned long)v->calls_thread[j], (unsigned long)v->samples_thread[j]);
        sb_fmt(b, "},\"sites\":[");
        for (j = 0; j < NTW2_GRID_SITES; ++j)
            sb_fmt(b, "%s{\"site\":%u,\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", j,
                   (unsigned long)v->calls_site[j], (unsigned long)v->samples_site[j]);
        sb_fmt(b, "]}");
    }
    sb_fmt(b, "],\"edges\":[");
    for (i = 0; i < c->edge_count && i < NTW2_GRID_EDGES; ++i) {
        const ntw2_grid_edge_status *e = &c->edges[i];
        sb_fmt(b, "%s{\"id\":%u,\"reader\":%lu,\"site\":%lu,\"source_clone\":%lu,\"route\":%lu,\"route_name\":\"%s\","
               "\"native_entry_proven\":%s,\"route_calls\":%lu,\"route_tick_calls\":%lu,\"route_calls_per_routed_tick\":",
               i ? "," : "", i, (unsigned long)e->reader, (unsigned long)e->site,
               (unsigned long)e->source_clone, (unsigned long)e->route, grid_route_name(e->route),
               e->route==NTW2_GRID_ROUTE_IMAGE ? "true" : "false",
               (unsigned long)e->route_calls, (unsigned long)e->route_tick_calls);
        sb_ratio(b, e->route_tick_calls, c->routed_ticks);
        sb_fmt(b, ",\"last_tick\":%lu,\"last_thread\":%lu}",
               (unsigned long)e->last_tick, (unsigned long)e->last_thread);
    }
    sb_fmt(b, "]},\n");
}

/* ---- AI mutation census (NTW2_AI_CENSUS): word layout documented at ntw2_status::ai_census_words in include/ntw2_runtime.h ---- */
#define AIC_HEADER 16u
#define AIC_TARGETS 7u
#define AIC_TARGET_HEADER 8u
#define AIC_TOP 8u
#define AIC_CALLER 12u
#define AIC_TARGET_WORDS (AIC_TARGET_HEADER + AIC_TOP * AIC_CALLER)
#define AIC_RANGES 3u
#define AIC_RANGE_WORDS 8u
typedef char ntw2_launcher_ai_census_layout[(NTW2_AI_CENSUS_WORDS == AIC_HEADER + AIC_TARGETS * AIC_TARGET_WORDS + AIC_RANGES * AIC_RANGE_WORDS) ? 1 : -1];
static const char *const k_ai_census_targets[AIC_TARGETS] = {
    "0x6EA520 delegate replacement virtual: slot 19 of vtables 0x13378F8 0x1337998 0x1337BB8 0x1337C30 0x1349C18",
    "0x6B3010 delegate sibling virtual: slot 20 of vtables 0x1337BB8 0x1337C30 0x1349C18",
    "observer vtable 0x13432A0 slot 0 (word 0x44A780 = `ret 4` no-op, not a destructor)",
    "observer vtable 0x1343318 slot 0 (word 0x44A780 = `ret 4` no-op, not a destructor)",
    "small delegate dtor 0x69D710: vtable 0x13376FC slot 0",
    "composite delegate dtor 0x69D750: vtable 0x13376AC slot 0",
    "planner rebuild 0x7492F0 called by the AI_CONTROLLER clone at 0x7C8C5A / 0x7C8C83 (call-site retarget, not a vtable)"
};
static const char *const k_ai_census_classes[4] = { "tick_owner", "ai_worker", "main_render", "other" };
static const char *const k_ai_census_ranges[AIC_RANGES] = {
    "operation dtor body 0x8254D0", "observer dtor route 0x739670", "base delegate/operation dtor 0x69A990"
};
static const char *ai_census_site_text(uint32_t code, char *buf, size_t size)
{
    if (!code) return "outside_tick";
    if (code == 1u) return "tick_no_site";
    _snprintf_s(buf, size, _TRUNCATE, "site_%lu", (unsigned long)(code - 2u));
    return buf;
}
static const char *ai_census_caller_text(const uint32_t *row, char *buf, size_t size)
{
    if (row[1] == 0u) _snprintf_s(buf, size, _TRUNCATE, "0x%08lX", (unsigned long)(0x400000u + row[0]));
    else if (row[1] == 1u)
        _snprintf_s(buf, size, _TRUNCATE, "AI_CONTROLLER clone+0x%lX (source 0x%08lX)", (unsigned long)row[0], (unsigned long)(0x7C8BD0u + row[0]));
    else _snprintf_s(buf, size, _TRUNCATE, "raw 0x%08lX", (unsigned long)row[0]);
    return buf;
}

static void print_ai_census(const Run *r)
{
    const uint32_t *w = r->last.ai_census_words;
    unsigned t, k, c;
    char a[64], b[96];
    if (!(r->opt.mask & NTW2_AI_CENSUS)) return;
    if (!r->have_status || w[0] != 1u) {
        say(L"AI mutation census: no initialized census snapshot available.\n");
        return;
    }
    say(L"AI mutation census (observation only; totals wrap; cumulative over one start/stop session)\n");
    say(L"  calls=%lu (in_tick=%lu outside_tick=%lu) ticks=%lu callers_used=%lu/%lu callers_dropped=%lu slots_owned=%lu/%lu\n",
        (unsigned long)w[5], (unsigned long)w[13], (unsigned long)w[14], (unsigned long)w[12], (unsigned long)w[3],
        (unsigned long)w[2], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8]);
    for (t = 0; t < AIC_TARGETS; ++t) {
        const uint32_t *row = w + AIC_HEADER + t * AIC_TARGET_WORDS;
        say(L"  target %u: %hs\n", t, k_ai_census_targets[t]);
        say(L"    slots=%lu total=%lu dropped_callers=%lu; by class:", (unsigned long)row[1], (unsigned long)row[2], (unsigned long)row[7]);
        for (c = 0; c < 4u; ++c) say(L" %hs=%lu", k_ai_census_classes[c], (unsigned long)row[3 + c]);
        say(L"\n");
        for (k = 0; k < AIC_TOP; ++k) {
            const uint32_t *cr = row + AIC_TARGET_HEADER + k * AIC_CALLER;
            if (!cr[2]) continue;
            say(L"    caller %hs count=%lu; class", ai_census_caller_text(cr, b, sizeof b), (unsigned long)cr[2]);
            for (c = 0; c < 4u; ++c) if (cr[3 + c]) say(L" %hs=%lu", k_ai_census_classes[c], (unsigned long)cr[3 + c]);
            say(L"; top %hs=%lu", ai_census_site_text(cr[7], a, sizeof a), (unsigned long)cr[8]);
            if (cr[10]) say(L", next %hs=%lu", ai_census_site_text(cr[10], a, sizeof a), (unsigned long)cr[11]);
            say(L"; outside_tick=%lu\n", (unsigned long)cr[9]);
        }
    }
    say(L"  sampler EIP occupancy (sampled threads only: main always, others only inside ticks): attempts=%lu outside_ranges=%lu\n",
        (unsigned long)w[10], (unsigned long)w[11]);
    for (t = 0; t < AIC_RANGES; ++t) {
        const uint32_t *row = w + AIC_HEADER + AIC_TARGETS * AIC_TARGET_WORDS + t * AIC_RANGE_WORDS;
        say(L"    range [0x%08lX,0x%08lX) %hs: samples=%lu", (unsigned long)row[0], (unsigned long)row[1], k_ai_census_ranges[t], (unsigned long)row[2]);
        for (c = 0; c < 4u; ++c) say(L" %hs=%lu", k_ai_census_classes[c], (unsigned long)row[3 + c]);
        say(L"\n");
    }
}

/* army_unit (NTW2_ARMY_UNIT_SHADOW): raw words plus the labelled header/reason/foreign words and command rows. */
static void sb_army_unit(Sb *b, const Run *r)
{
    static const char *const header[] = { NTW2_ARMY_UNIT_HEADER_LABELS };
    static const char *const reasons[] = { NTW2_ARMY_UNIT_REASON_LABELS };
    static const char *const details[] = { NTW2_ARMY_UNIT_DETAIL_LABELS };
    static const char *const foreign[] = { NTW2_ARMY_UNIT_FOREIGN_LABELS };
    static const char *const command[] = { NTW2_ARMY_UNIT_COMMAND_LABELS };
    const uint32_t *w = r->last.army_unit_words;
    unsigned i, c;
    if (!(r->opt.mask & NTW2_ARMY_UNIT_SHADOW) || !r->have_status || !w[0]) {
        sb_fmt(b, "  \"army_unit\": null,\n");
        return;
    }
    sb_fmt(b, "  \"army_unit\": {\"header\": {");
    for (i = 0; i < 32u; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", header[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"reasons\": {");
    for (i = 0; i < 5u; ++i)
        sb_fmt(b, "%s\"%s\": {\"units\": %lu, \"us\": %lu, \"sole\": %lu}", i ? ", " : "", reasons[i],
               (unsigned long)w[32u + i], (unsigned long)w[37u + i], (unsigned long)w[42u + i]);
    sb_fmt(b, "}, \"duplicate_occurrences\": %lu, \"details\": {", (unsigned long)w[47]);
    for (i = 0; i < 32u; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", details[i], (unsigned long)w[48u + i]);
    sb_fmt(b, "}, \"foreign\": {");
    for (i = 0; i < 8u; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", foreign[i], (unsigned long)w[80u + i]);
    sb_fmt(b, "}, \"cost_histogram_log2_us\": [");
    for (i = 0; i < 16u; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[88u + i]);
    sb_fmt(b, "], \"command_distinct\": %lu, \"command_overflow\": %lu, \"rng_drawing_us\": %lu, \"unreadable_us\": %lu, \"commands\": [",
           (unsigned long)w[104], (unsigned long)w[105], (unsigned long)w[106], (unsigned long)w[107]);
    for (i = 0; i < 16u && i < w[104]; ++i) {
        sb_fmt(b, "%s{", i ? ", " : "");
        for (c = 0; c < 5u; ++c) sb_fmt(b, "%s\"%s\": %lu", c ? ", " : "", command[c], (unsigned long)w[108u + 5u * i + c]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "], \"words\": [");
    for (i = 0; i < NTW2_ARMY_UNIT_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
static void sb_ai_census(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.ai_census_words;
    unsigned t, k, c;
    char a[64], s[96];
    if (!(r->opt.mask & NTW2_AI_CENSUS) || !r->have_status || w[0] != 1u) {
        sb_fmt(b, "  \"ai_census\": null,\n");
        return;
    }
    sb_fmt(b, "  \"ai_census\": {\"version\":%lu,\"calls\":%lu,\"calls_in_tick\":%lu,\"calls_outside_tick\":%lu,\"ticks\":%lu,"
           "\"callers_used\":%lu,\"caller_capacity\":%lu,\"callers_dropped\":%lu,\"slots_owned\":%lu,\"slot_count\":%lu,"
           "\"sample_attempts\":%lu,\"sample_outside_ranges\":%lu,\n",
           (unsigned long)w[0], (unsigned long)w[5], (unsigned long)w[13], (unsigned long)w[14], (unsigned long)w[12],
           (unsigned long)w[3], (unsigned long)w[2], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8],
           (unsigned long)w[10], (unsigned long)w[11]);
    sb_fmt(b, "    \"semantics\":\"u32 totals wrap; cumulative over one start/stop session; observation only. Classes: tick_owner, ai_worker, "
           "main_render (not tick owner), other. Site codes: 0 outside_tick, 1 tick_no_site, N+2 timed site N. Caller kind image = RVA "
           "(source VA = 0x400000 + rva); clone = offset into the AI_CONTROLLER clone (source VA 0x7C8BD0 + offset). Observer slot 0 is the "
           "`ret 4` no-op 0x44A780, not a destructor; 0x739670/0x8254D0/0x69A990 are EIP-sampled only, so sample counts are occupancy, not calls.\",\n"
           "    \"targets\":[");
    for (t = 0; t < AIC_TARGETS; ++t) {
        const uint32_t *row = w + AIC_HEADER + t * AIC_TARGET_WORDS;
        sb_fmt(b, "%s{\"index\":%u,\"original\":\"0x%08lX\",\"slots\":%lu,\"total\":%lu,\"dropped_callers\":%lu,\"label\":",
               t ? "," : "", t, (unsigned long)row[0], (unsigned long)row[1], (unsigned long)row[2], (unsigned long)row[7]);
        sb_fmt(b, "\"%s\"", k_ai_census_targets[t]);
        sb_fmt(b, ",\"classes\":{");
        for (c = 0; c < 4u; ++c)
            sb_fmt(b, "%s\"%s\":%lu", c ? "," : "", k_ai_census_classes[c], (unsigned long)row[3 + c]);
        sb_fmt(b, "},\"callers\":[");
        for (k = 0, c = 0; k < AIC_TOP; ++k) {
            const uint32_t *cr = row + AIC_TARGET_HEADER + k * AIC_CALLER;
            unsigned j;
            if (!cr[2]) continue;
            sb_fmt(b, "%s{\"caller\":\"%s\",\"kind\":%lu,\"value\":%lu,\"count\":%lu,\"classes\":{", c++ ? "," : "",
                   ai_census_caller_text(cr, s, sizeof s), (unsigned long)cr[1], (unsigned long)cr[0], (unsigned long)cr[2]);
            for (j = 0; j < 4u; ++j)
                sb_fmt(b, "%s\"%s\":%lu", j ? "," : "", k_ai_census_classes[j], (unsigned long)cr[3 + j]);
            sb_fmt(b, "},\"top_site\":\"%s\",\"top_site_count\":%lu,", ai_census_site_text(cr[7], a, sizeof a), (unsigned long)cr[8]);
            sb_fmt(b, "\"second_site\":\"%s\",\"second_site_count\":%lu,\"outside_tick\":%lu}",
                   cr[11] ? ai_census_site_text(cr[10], a, sizeof a) : "none", (unsigned long)cr[11], (unsigned long)cr[9]);
        }
        sb_fmt(b, "]}");
    }
    sb_fmt(b, "],\n    \"ranges\":[");
    for (t = 0; t < AIC_RANGES; ++t) {
        const uint32_t *row = w + AIC_HEADER + AIC_TARGETS * AIC_TARGET_WORDS + t * AIC_RANGE_WORDS;
        sb_fmt(b, "%s{\"va\":\"0x%08lX\",\"end\":\"0x%08lX\",\"label\":\"%s\",\"samples\":%lu,\"classes\":{", t ? "," : "",
               (unsigned long)row[0], (unsigned long)row[1], k_ai_census_ranges[t], (unsigned long)row[2]);
        for (c = 0; c < 4u; ++c)
            sb_fmt(b, "%s\"%s\":%lu", c ? "," : "", k_ai_census_classes[c], (unsigned long)row[3 + c]);
        sb_fmt(b, "}}");
    }
    sb_fmt(b, "]},\n");
}

static void sb_collide_lod(Sb *b, const Run *r)
{
    unsigned i;
    if (!(r->opt.mask & NTW2_COLLIDE_LOD) || !r->have_status) {
        sb_fmt(b, "  \"collide_lod\": null,\n");
        return;
    }
    sb_fmt(b, "  \"collide_lod\": {\"experimental\": true, \"configured_distance_m\": %lu, "
           "\"semantics\": \"far units skip alternating model ticks by stable unit index; near and unknown units and rebuild ticks full-rate; "
           "counts cumulative modulo 2^32 since activation; units/far_units latest proximity classification before all-far multi-army refusal; "
           "different_side_pairs compares the original +0x44 pointers; faults disable skipping until activation\", \"metrics\": {",
           (unsigned long)(r->cfg.collide_lod_m & NTW2_COLLIDE_LOD_METRES_MASK));
    for (i = 0; i < NTW2_COLLIDE_LOD_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_collide_lod_metrics[i], (unsigned long)r->last.collide_lod_words[i]);
    sb_fmt(b, "}, \"reuse_far_skip_fraction\": ");
    sb_ratio(b, r->last.collide_lod_words[2], r->last.collide_lod_words[11]);
    sb_fmt(b, "},\n");
}

/* --grid-probation receipt object: the 32 header words by label and every used caller row. */
static void sb_grid_probation(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.grid_probation_words;
    unsigned i, n = 0;
    sb_fmt(b, "{\"enabled\": %s, \"metrics\": {", r->opt.grid_probation ? "true" : "false");
    for (i = 0; i < NTW2_GRID_PROBATION_HEADER_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_grid_probation_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"callers\": [");
    for (i = 0; i < NTW2_GRID_PROBATION_CALLERS; ++i) {
        const uint32_t *row = w + NTW2_GRID_PROBATION_HEADER_WORDS + 8u * i;
        if (!row[4]) continue;
        sb_fmt(b, "%s{\"eip\": \"0x%08lX\", \"eip_module\": \"%s\", \"caller\": \"0x%08lX\", \"caller_module\": \"%s\", "
                  "\"thread_mask\": %lu, \"clone\": %ld, \"clone_address\": \"0x%08lX\", \"count\": %lu, \"writes\": %lu, "
                  "\"first_site\": %lu, \"last_site\": %lu}",
               n++ ? ", " : "", (unsigned long)row[0], k_grid_probation_modules[row[2] & 3u], (unsigned long)row[1],
               k_grid_probation_modules[(row[2] >> 4) & 3u], (unsigned long)((row[2] >> 8) & 0xFFu), (long)(row[2] >> 16) - 1,
               (unsigned long)row[3], (unsigned long)row[4], (unsigned long)row[5], (unsigned long)row[6], (unsigned long)row[7]);
    }
    sb_fmt(b, "]}");
}
/* Eight per-service rows; denominators: clone = loco_words[27] clone-executed occurrences, stage = loco_words[1], call = that service's completed timed calls. */
static void sb_loco_services(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.loco_words;
    const uint32_t *t = r->last.loco_service_words;
    unsigned i;
    sb_fmt(b, "{\"semantics\": \"inclusive QPC timing of eight owner services inside the private clone family, enabled only with --loco-clone; raw QPC ticks accumulate before conversion to us; "
           "counts and us wrap modulo 2^32; calls count completed valid start/end pairs only (overflow, abandoned frames and QPC failures excluded and reported separately); "
           "service us are inclusive and overlap, service_union counts outermost timed calls only; outside_us = max(clone_wall_us - union_us, 0) and is NOT pure arithmetic: it includes untapped native calls and "
           "gate/service/QPC instrumentation outside service brackets; all-gates classification occurs before the clone wall; "
           "intervals include FP save/restore, trampoline and QPC perturbation and are not the uninstrumented decomposition\", \"version\": %lu, \"enabled\": %s, \"denominators\": {\"clones\": %lu, \"stages\": %lu}, \"metrics\": {",
           (unsigned long)t[0], t[1] ? "true" : "false", (unsigned long)w[27], (unsigned long)w[1]);
    for (i = 0; i < NTW2_LOCO_SERVICE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_service_metrics[i], (unsigned long)t[i]);
    sb_fmt(b, "}, \"totals\": {\"timed_calls\": %lu, \"overflows\": %lu, \"abandoned\": %lu, \"max_depth\": %lu, \"qpc_failures\": %lu, \"clone_wall_us\": %lu, "
           "\"union_us\": %lu, \"outside_us\": %lu, \"clone_wall_us_per_clone\": ",
           (unsigned long)t[2], (unsigned long)t[3], (unsigned long)t[4], (unsigned long)t[8], (unsigned long)t[9],
           (unsigned long)t[5], (unsigned long)t[6], (unsigned long)t[7]);
    sb_ratio(b, t[5], w[27]);
    sb_fmt(b, ", \"clone_wall_us_per_stage\": ");
    sb_ratio(b, t[5], w[1]);
    sb_fmt(b, ", \"union_us_per_clone\": ");
    sb_ratio(b, t[6], w[27]);
    sb_fmt(b, ", \"union_us_per_stage\": ");
    sb_ratio(b, t[6], w[1]);
    sb_fmt(b, ", \"outside_us_per_clone\": ");
    sb_ratio(b, t[7], w[27]);
    sb_fmt(b, ", \"outside_us_per_stage\": ");
    sb_ratio(b, t[7], w[1]);
    sb_fmt(b, "}, \"per_service\": {");
    for (i = 0; i < LOCO_SERVICES; ++i) {
        sb_fmt(b, "%s\"%s\": {\"us\": %lu, \"max_us\": %lu, \"calls\": %lu, \"us_per_call\": ",
               i ? ", " : "", k_loco_service_names[i], (unsigned long)t[LOCO_SVC_US+i], (unsigned long)t[LOCO_SVC_MAX+i], (unsigned long)t[LOCO_SVC_CALLS+i]);
        sb_ratio(b, t[LOCO_SVC_US+i], t[LOCO_SVC_CALLS+i]);
        sb_fmt(b, ", \"us_per_clone\": ");
        sb_ratio(b, t[LOCO_SVC_US+i], w[27]);
        sb_fmt(b, ", \"us_per_stage\": ");
        sb_ratio(b, t[LOCO_SVC_US+i], w[1]);
        sb_fmt(b, ", \"calls_per_clone\": ");
        sb_ratio(b, t[LOCO_SVC_CALLS+i], w[27]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "}}");
}

static void sb_loco(Sb *b, const Run *r)
{
    unsigned i;
    if (!(r->opt.mask & NTW2_LOCO) || !r->have_status) {
        sb_fmt(b, "  \"loco\": null,\n");
        return;
    }
    sb_fmt(b, "  \"loco\": {\"experimental\": true, \"clone_execution\": %s, \"parallel_execution\": %s, \"semantics\": \"Stages A/B/C timed site 13 (0x531AF0 loop): "
           "optional --loco-grid or --loco-grid-verify publishes owned grid v2 at stage end; combined COLLIDE borrows that view without audit or rebuild; optional closed direct-selector A1==0 movement runs on private worker state; "
           "native publication and collision callbacks remain owner-only with Phase B frozen input semantics; combined collision requires clone, parallel, owned services and grid; private precommit faults replay originals at their ordinals, never postcommit retry; "
           "serial MOVE enforces Class/Lifetime/Parked/Pending/Environment only (mask 0x233), not worker admission; "
           "counts cumulative modulo 2^32 since activation; us sums are wall time inside the stage\", \"metrics\": {",
           r->opt.loco_clone ? "true" : "false", r->opt.loco_parallel ? "true" : "false");
    for (i = 0; i < NTW2_LOCO_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_metrics[i], (unsigned long)r->last.loco_words[i]);
    sb_fmt(b, "}, \"derived\": {\"admitted_fraction\": ");
    sb_ratio(b, r->last.loco_words[3], r->last.loco_words[2]);
    sb_fmt(b, ", \"entities\": %lu, \"stage_calls\": %lu}, \"all_gates\": {\"semantics\": "
           "\"denominator is every active +0x30 entity occurrence; recognized candidates evaluate all ten old diagnostics even after an earlier failure; "
           "unknown classes have no soldier-field reads; independent failures and details overlap and must not be summed to entities; "
           "enforced_mask uses bit(reason-1); ChargeFire is DWORD +4E8/+390/+3BC/+3C8, while byte +618/+619/+F1/+5AB are corroborating latches only; "
           "legacy_admitted clears all ten diagnostics, newly_admitted passes serial MOVE with a removed diagnostic failing\", \"metrics\": {",
           (unsigned long)r->last.loco_words[2], (unsigned long)r->last.loco_words[1]);
    for (i = 0; i < NTW2_LOCO_GATE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_gate_metrics[i], (unsigned long)r->last.loco_gate_words[i]);
    sb_fmt(b, "}, \"derived\": {\"denominator_entities\": %lu, \"candidates\": %lu, \"enforced_mask\": %lu, \"admitted_fraction\": ",
           (unsigned long)r->last.loco_gate_words[1], (unsigned long)r->last.loco_gate_words[2], (unsigned long)r->last.loco_gate_words[4]);
    sb_ratio(b, r->last.loco_gate_words[3], r->last.loco_gate_words[1]);
    sb_fmt(b, "}}, \"services\": ");
    sb_loco_services(b, r);
    sb_fmt(b, ", \"grid\": {\"enabled\": %s, \"metrics\": {", r->opt.loco_grid ? "true" : "false");
    for (i = 0; i < NTW2_LOCO_GRID_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_grid_metrics[i], (unsigned long)r->last.loco_grid_words[i]);
    sb_fmt(b, "}}, \"grid_v2\": {\"verify\": %s, \"metrics\": {", r->opt.loco_grid_verify ? "true" : "false");
    for (i = 0; i < NTW2_LOCO_GRID_V2_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_grid_v2_metrics[i], (unsigned long)r->last.loco_grid_v2_words[i]);
    sb_fmt(b, "}}, \"grid_probation\": ");
    sb_grid_probation(b, r);
    sb_fmt(b, ", \"parallel\": {\"metrics\": {");
    for (i = 0; i < NTW2_LOCO_PARALLEL_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_parallel_metrics[i], (unsigned long)r->last.loco_parallel_words[i]);
    sb_fmt(b, "}, \"derived\": {\"worker_fraction_of_active\": ");
    if (r->opt.loco_parallel) sb_ratio(b, r->last.loco_parallel_words[3], r->last.loco_words[2]);
    else sb_fmt(b, "null");
    sb_fmt(b, ", \"worker_fraction_of_admitted\": ");
    if (r->opt.loco_parallel) sb_ratio(b, r->last.loco_parallel_words[3], r->last.loco_words[3]);
    else sb_fmt(b, "null");
    sb_fmt(b, ", \"inclusive_gate_mean_us\": ");
    sb_ratio(b, r->last.loco_words[23], r->last.loco_words[1]);
    sb_fmt(b, ", \"inclusive_gate_vs_12ms\": ");
    if (r->last.loco_words[1]) sb_fmt(b, "%.9f", (double)r->last.loco_words[23]/r->last.loco_words[1]/12000.0);
    else sb_fmt(b, "null");
    sb_fmt(b, "}}, \"owned\": {\"enabled\": %s, \"quiet\": %s, \"semantics\": \"one dispatch per stage; entity-range chunks claimed atomically by the pool; chunks and duplicate_refusals replace the former unit counters\", \"metrics\": {", r->opt.loco_owned ? "true" : "false", r->opt.loco_quiet ? "true" : "false");
    for (i = 0; i < NTW2_LOCO_OWNED_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_metrics[i], (unsigned long)r->last.loco_owned_words[i]);
    sb_fmt(b, "}, \"detail\": {\"quiet_enabled\": %lu, \"metrics\": {", (unsigned long)r->last.loco_owned_detail_words[1]);
    for (i = 0; i < NTW2_LOCO_OWNED_DETAIL_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_detail_metrics[i], (unsigned long)r->last.loco_owned_detail_words[i]);
    sb_fmt(b, "}}, \"phase\": {\"semantics\": \"phase timers remain under quiet; replay commit/fallback us are x16 estimates from every 16th occurrence\", \"metrics\": {");
    for (i = 0; i < NTW2_LOCO_OWNED_PHASE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_phase_metrics[i], (unsigned long)r->last.loco_owned_phase_words[i]);
    sb_fmt(b, "}, \"derived\": {\"dispatches_per_stage\": ");
    sb_ratio(b, r->last.loco_owned_phase_words[1], r->last.loco_words[1]);
    sb_fmt(b, ", \"chunks_per_dispatch\": ");
    sb_ratio(b, r->last.loco_owned_phase_words[2], r->last.loco_owned_phase_words[1]);
    sb_fmt(b, ", \"mean_chunk_us\": ");
    sb_ratio(b, r->last.loco_owned_phase_words[24], r->last.loco_owned_phase_words[2]);
    sb_fmt(b, ", \"replay_commit_est_us_per_worker_entity\": ");
    if (r->last.loco_owned_words[2] || r->last.loco_owned_words[3])
        sb_fmt(b, "%.6f", r->last.loco_owned_phase_words[19] / ((double)r->last.loco_owned_words[2] + r->last.loco_owned_words[3]));
    else sb_fmt(b, "null");
    sb_fmt(b, ", \"replay_fallback_est_us_per_fallback_entity\": ");
    sb_ratio(b, r->last.loco_owned_phase_words[20], r->last.loco_owned_words[30]);
    sb_fmt(b, ", \"list_entities_per_stage\": ");
    sb_ratio(b, r->last.loco_owned_phase_words[3], r->last.loco_words[1]);
    sb_fmt(b, "}}, \"load\": {\"semantics\": \"activation-only scene/catalog/participants/prefaulted arena; no tick-time preparation or growth; chunk CPU and worst-chunk wall/CPU remain under quiet\", \"metrics\": {");
    for (i = 0; i < NTW2_LOCO_OWNED_LOAD_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_load_metrics[i], (unsigned long)r->last.loco_owned_load_words[i]);
    sb_fmt(b, "}}, \"active_worker_fraction\": ");
    if (r->last.loco_owned_words[31])
        sb_fmt(b, "%.9f", ((double)r->last.loco_owned_words[2] + r->last.loco_owned_words[3]) / r->last.loco_owned_words[31]);
    else sb_fmt(b, "null");
    sb_fmt(b, "}");
    sb_fmt(b, ", \"shadow\": {\"enabled\": %s, \"requested\": %s, \"suppressed_by_quiet\": %s, \"sweep\": {",
           loco_shadow_effective(&r->opt) ? "true" : "false", r->opt.loco_shadow ? "true" : "false",
           (r->opt.loco_shadow && r->opt.loco_quiet) ? "true" : "false");
    for (i = 0; i < NTW2_SWEEP_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_sweep_metrics[i], (unsigned long)r->last.sweep_words[i]);
    sb_fmt(b, "}, \"resolve\": {");
    for (i = 0; i < NTW2_RESOLVE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_resolve_metrics[i], (unsigned long)r->last.resolve_words[i]);
    sb_fmt(b, "}, \"resolve_frames\": {");
    for (i = 0; i < NTW2_RESOLVE_FRAME_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_resolve_frame_metrics[i], (unsigned long)r->last.resolve_frame_words[i]);
    sb_fmt(b, "}, \"env\": {");
    for (i = 0; i < NTW2_ENV_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_env_metrics[i], (unsigned long)r->last.env_words[i]);
    sb_fmt(b, "}, \"env_targets\": [");
    for (i = 0; i < NTW2_ENV_TARGET_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? ", " : "", (unsigned long)r->last.env_target_words[i]);
    sb_fmt(b, "], \"env_event_evidence\": \"post-state inference only; notification unobserved\"}");
    sb_fmt(b, "},\n");
}

static void sb_collide(Sb *b, const Run *r)
{
    unsigned i;
    if (!(r->opt.mask & NTW2_COLLIDE) || !r->have_status) {
        sb_fmt(b, "  \"collide\": null,\n");
        return;
    }
    sb_fmt(b, "  \"collide\": {\"experimental\": true, \"phase\": \"B\", "
           "\"semantics\": \"counters cumulative modulo 2^32 since activation; stage calls include fallbacks; "
           "compare per-stage totals using stage_calls versus collision_words[21], not original per_tick values; "
           "fallback_ticks counts whole-stage refusals/faults or fault-marked owner-continuation stages; "
           "node_fallbacks and native_queries count active unsupported original per-record queries; "
           "unsupported_cells counts marked cells per stage; cells counts occupied CSR cells; "
           "owner_continuations (word 30) replaces Phase A suffix_fallbacks without changing its offset; "
           "records counts every worklist entry; eligible_queries (word 31) counts entry-snapshot "
           "R+30 nonzero and (flags & 3) nonzero before native/solver choice; "
           "solver_ticks counts completed replacement stages, including mixed or all-native record-local work; "
           "pairs, contacts and callbacks exclude native query internals; inspect native_queries, not just "
           "solver_ticks, when judging solver usage or speedup; "
           "maxima, last exception and diagnostic fields are not totals or per-tick averages; "
           "diagnostic fields retain the first offending node snapshot per activation; reason 0 means none; "
           "record 131072 means no known context; cell 4294967295 means unmappable; "
           "chain context is the first known record occupying the cell, not the foreign owner slot; "
           "vtable is from the known current record, not an unchecked foreign owner; "
           "solver takes priority over PROFILE census; ");
    sb_fmt(b, "private reduction starts from existing accumulators, outgoing-first then incoming packet-index order; "
           "deterministic, not bit-identical to native float order; rebuilt worklist is published before callbacks; "
           "callback geometry/eligibility mutations do not reselect this stage's solver packets or replan BFS; "
           "fully supported stages run ordered live redistribution with conditional sequential MAX over private labels, "
           "then one parallel store pass commits numeric sums, dirty final labels and processed bytes together, then a "
           "serial timed callback pass, so callbacks see final processed bytes, velocities, labels and all solver numeric sums; "
           "mixed stages with unsupported records parallel-commit numeric sums before the original-interleaved owner replay and keep owner per-record native-query/processed progression with "
           "interleaved redistribution/callbacks because native queries read +0x40; "
           "postcommit callback faults finish precomputed owner work without replaying solver numerics, "
           "then use sticky original-stage fallback next tick; ");
    sb_fmt(b, "CSR/incidence grouping uses a bounded-key direct-address cell-to-dense-id hash (only previous occupied keys cleared), "
           "a compact per-lane histogram slab with one prefix and a stable incoming scatter (no two-pass radix, no full-grid pass); "
           "the native chain audit is a parallel read-only pass over disjoint cells inside the active epoch with AI joined, "
           "supplies the native-order CSR scatter and fills cell-local x/z/radius/team/flags, and a per-chunk SEH fault is a "
           "whole-stage fallback before any game write; commit stores run on workers only after all read-only preparation, "
           "and a store fault propagates with no rollback or restart; "
           "unshaped circle pairs bypass original 0x81A670 with the exact same radius threshold, and shaped_pairs counts "
           "only leaf calls with at least one nonnull shape pointer; ");
    sb_fmt(b, "wall timers are QPC; audit_us is nested in bin_us, and store_us, redistribute_us, callback_us and reduction_us "
           "are nested in apply_us, so none is additive to stage_us again; supported-stage timers split exactly, mixed "
           "solver pair calls are timed individually and native query internals stay in the apply remainder; "
           "*_thread_us are GetThreadTimes user+kernel CPU aggregated over owner and workers, not summed elapsed QPC; "
           "they may exceed wall time, have coarse resolution, are meaningful only as totals over many solver ticks, "
           "and are incomplete when thread_clock_failures is nonzero; "
           "derived values divide by solver_ticks, not stage_calls; ");
    sb_fmt(b, "primary and secondary registries supply destinations, but only worklist records query; "
           "reason 10 means owner absent from known registries, not a stale expected_record mapping; "
           "numerical and ordering tolerance is defined by the differential oracle\", \"metrics\": {");
    for (i = 0; i < NTW2_COLLIDE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_collide_metrics[i], (unsigned long)r->last.collide_words[i]);
    sb_fmt(b, "}, \"source\": {");
    for (i = 0; i < NTW2_COLLIDE_SOURCE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_collide_source_metrics[i], (unsigned long)r->last.collide_source_words[i]);
    {
        static const char *const contact_labels[NTW2_COLLIDE_CONTACT_WORDS] = { NTW2_COLLIDE_CONTACT_WORD_LABELS };
        sb_fmt(b, "}, \"contact\": {\"requested_shadow\": %s, \"requested_workers\": %s, \"metrics\": {",
               r->opt.collide_contact_shadow ? "true" : "false", r->opt.collide_contact_workers ? "true" : "false");
        for (i = 0; i < NTW2_COLLIDE_CONTACT_WORDS; ++i)
            sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", contact_labels[i], (unsigned long)r->last.collide_contact_words[i]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "}, \"derived\": {\"denominator\": \"solver_ticks\", \"solver_ticks\": %lu, \"stage_calls\": %lu, "
           "\"thread_clock_failures\": %lu, \"phases\": {",
           (unsigned long)r->last.collide_words[1], (unsigned long)r->last.collide_words[0],
           (unsigned long)r->last.collide_words[55]);
    for (i = 0; i < sizeof k_collide_phases/sizeof k_collide_phases[0]; ++i) {
        const uint32_t *w = r->last.collide_words;
        sb_fmt(b, "%s\"%s\": {\"wall_us\": %lu, \"wall_us_per_solver_tick\": ", i ? ", " : "",
               k_collide_phases[i].name, (unsigned long)w[k_collide_phases[i].wall]);
        sb_ratio(b, w[k_collide_phases[i].wall], w[1]);
        if (k_collide_phases[i].thread >= 0) {
            sb_fmt(b, ", \"thread_us\": %lu, \"thread_us_per_solver_tick\": ", (unsigned long)w[k_collide_phases[i].thread]);
            sb_ratio(b, w[k_collide_phases[i].thread], w[1]);
        } else {
            sb_fmt(b, ", \"thread_us\": null, \"thread_us_per_solver_tick\": null");
        }
        if (k_collide_phases[i].nested_in) sb_fmt(b, ", \"nested_in\": \"%s\"}", k_collide_phases[i].nested_in);
        else sb_fmt(b, ", \"nested_in\": null}");
    }
    sb_fmt(b, "}, \"shaped_pairs\": {\"sum\": %lu, \"per_solver_tick\": ", (unsigned long)r->last.collide_words[44]);
    sb_ratio(b, r->last.collide_words[44], r->last.collide_words[1]);
    sb_fmt(b, "}}},\n");
}

static void sb_brain_states(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.brain_state_words;
    unsigned group, i, rows, order[NTW2_BRAIN_SUBSTATE_BUCKETS];
    wchar_t label[24];
    if (!(r->opt.mask & NTW2_BRAIN) || !r->have_status || !w[0]) {
        sb_fmt(b, "  \"brain_states\": null,\n");
        return;
    }
    sb_fmt(b, "  \"brain_states\": {\"routed_ticks\": %lu, \"entries\": %lu, \"entities_per_tick\": %.6f, "
           "\"distinct_units_per_tick\": %.6f, \"distinct_unit_counts_complete\": %s, \"unit_set_storage_failures\": %lu,\n"
           "    \"semantics\": \"actual brain entry/return; cumulative modulo 2^32 since activation; entry state buckets "
           "0..61, 0x4B, other; sub-state buckets 0..78, >=79; entry_share=count/entries; transition_share=count/transitions; "
           "distinct units deduplicated per routed tick, and separately per transition destination bucket; null units excluded\",\n"
           "    \"combat_proxy\": \"unit!=null && [unit+0xAA0]!=0; 0x66D55F gates setting agent+0xF0 on this; not a proven combat flag\",\n"
           "    \"early_exit_predicate\": \"[agent+0xEC] byte==0 && [agent+0x1B8] dword==0x4B at entry; three virtual checks may veto return\",\n",
           (unsigned long)w[0], (unsigned long)w[1], (double)w[1]/w[0], (double)w[7]/w[0],
           w[11] ? "false" : "true", (unsigned long)w[11]);
    for (group = 0; group < 2; ++group) {
        const unsigned base = group ? NTW2_BRAIN_SUBSTATE_COUNTS : NTW2_BRAIN_STATE_COUNTS;
        const unsigned n = group ? NTW2_BRAIN_SUBSTATE_BUCKETS : NTW2_BRAIN_STATE_BUCKETS;
        brain_state_order(w+base, n, order);
        sb_fmt(b, "    \"%s\": [", group ? "sub_states" : "states");
        rows = 0;
        for (i = 0; i < n; ++i) {
            const unsigned bucket = order[i];
            const uint32_t count = w[base+bucket];
            if (!count) continue;
            brain_state_label(bucket, group != 0, label, 24);
            sb_fmt(b, "%s{\"bucket\": %u, \"state\": ", rows++ ? "," : "", bucket);
            sb_wstr(b, label);
            sb_fmt(b, ", \"entries\": %lu, \"entities_per_tick\": %.6f, \"entry_share\": %.9f}",
                   (unsigned long)count, (double)count/w[0], w[1] ? (double)count/w[1] : 0.0);
        }
        sb_fmt(b, "],\n");
    }
    sb_fmt(b, "    \"booleans\": {");
    for (i = 0; i < sizeof k_brain_state_flags/sizeof k_brain_state_flags[0]; ++i) {
        const uint32_t count = w[k_brain_state_flags[i].word];
        sb_fmt(b, "%s\"%s\": {\"true_count\": %lu, \"true_per_tick\": %.6f, \"entry_share\": %.9f}",
               i ? "," : "", k_brain_state_flags[i].json, (unsigned long)count,
               (double)count/w[0], w[1] ? (double)count/w[1] : 0.0);
    }
    sb_fmt(b, "},\n    \"transitions_from_0x4B\": {\"entities\": %lu, \"entities_per_tick\": %.6f, "
           "\"distinct_units_per_tick\": %.6f, \"null_unit_entities_per_tick\": %.6f, \"destinations\": [",
           (unsigned long)w[8], (double)w[8]/w[0], (double)w[9]/w[0], (double)w[10]/w[0]);
    brain_state_order(w+NTW2_BRAIN_TRANSITION_COUNTS, NTW2_BRAIN_STATE_BUCKETS, order);
    rows = 0;
    for (i = 0; i < NTW2_BRAIN_STATE_BUCKETS; ++i) {
        const unsigned bucket = order[i];
        const uint32_t count = w[NTW2_BRAIN_TRANSITION_COUNTS+bucket];
        if (!count) continue;
        brain_state_label(bucket, FALSE, label, 24);
        sb_fmt(b, "%s{\"bucket\": %u, \"state\": ", rows++ ? "," : "", bucket);
        sb_wstr(b, label);
        sb_fmt(b, ", \"entities\": %lu, \"entities_per_tick\": %.6f, \"distinct_units_per_tick\": %.6f, \"transition_share\": %.9f}",
               (unsigned long)count, (double)count/w[0], (double)w[NTW2_BRAIN_TRANSITION_UNITS+bucket]/w[0],
               w[8] ? (double)count/w[8] : 0.0);
    }
    sb_fmt(b, "]}\n  },\n");
}

/*
 * Receipt schema (JSON; snapshots are measured, never synthetic success):
 * Existing top-level fields: tool, abi, started, finished (UTC publication time),
 * exit_code (null while observing), outcome, game_dir, image_path, image_sha256,
 * image_size, image_sha256_expected, runtime_dll, runtime_sha256, runtime_size,
 * pid, process_created/image_base/runtime_base (when pid != 0), requested_mask,
 * requested, workers, poll_ms, armed, reached_full_activation,
 * remote_thread_outstanding, game_exited, game_exit_code, last_status.
 * last_status is null before a valid sample; otherwise phase, sequence,
 * requested_mask, active_mask, active, error, error_detail, pid, image_base,
 * root, model, generation, monitor_thread, workers, tick, path_completed,
 * formation_committed, ballistic_committed, collision_cache_hits,
 * worker_chunks, storage_bytes, retained_bytes, probe
 * (world discovery: low byte = failing link index, 0 = found; bit 8 = scheduler flag),
 * path_fallbacks, path_refused, formation_epochs, formation_refused, ballistic_stages (per-module diagnostic sums).
 * Added top-level fields: receipt_complete (bool), replay (absolute path or ""),
 * focus (bool), observe_seconds, exit_game_after_observe (bool).
 * observation: complete (bound reached), elapsed_ms, status_samples,
 * active_generations (distinct successive sampled ACTIVE generation IDs),
 * last_active_generation, active_to_waiting (ACTIVE -> [RESTORING] -> WAITING),
 * reactivations (subsequent ACTIVE after such WAITING), battle_tick_advance
 * (sum of forward tick deltas between consecutive ACTIVE samples of the same
 * generation/model/root; resets and unsampled lifecycle transitions excluded),
 * peak_workers, peak_storage_bytes, peak_retained_bytes.
 * game_shutdown: requested, wm_close_windows (successful posts),
 * forced (TerminateProcess succeeded), error (Win32 error; 0 on success),
 * close_timeout_ms (10000). The retained process handle is the only kill target.
 * tick_trace: null until final analysis (or if never ACTIVE/no complete copy).
 * count=min(written,entries); chronological traversal begins at
 * (head+entries-count)%entries, so model tick resets do not reorder battles.
 * first_tick/last_tick bound that traversal; duration_us/interval_us contain
 * nearest-rank p50/p90/p99/max (first zero interval included). sums_us uses
 * 64-bit totals; duration_share is each sub-phase sum / duration sum (0 when
 * duration sum is 0), with signed remainder to expose overlapping measurements.
 * over_100ms/over_150ms use strict duration thresholds; longest_ticks contains
 * up to 16 descending-duration rows, chronological ties. periodicity counts
 * strict >1.5*p50 durations by floor((tick%100)/10) and tick%10, bins ascending.
 * <receipt>.ticks.bin is the unmodified ABI header and ring; use its header to
 * reconstruct chronology. Two alternating slots retain the last complete copy.
 * --tick-log FILE additionally drains new written entries on every monitor poll
 * (10 ms wait instead of 200 ms), retaining at most 200000 chronological entries.
 * FILE has an 8-byte ASCII NTW2TLOG magic, then uint32 LE abi, entry_size, count,
 * followed by count unmodified ntw2_trace_entry records (20-byte header).
 * tick_log: {file,count,lost}; lost counts overwritten and capacity-dropped entries.
 * tick_log_summary contains every retained entry's tick, raw QPC start/end,
 * duration_us, interval_us and site5/6/13/18/33/34_us (zero-based ABI sites).
 * Log summary storage grows with the bounded capture; the legacy ring still
 * refreshes once per second when --tick-log is absent.
 * Live rings are observational, not sequence-locked; copying can overlap a tick.
 * Sampling cannot prove transitions that occur entirely between status reads.
 * brain_sites: null unless --features brain was requested and a routed tick was observed; otherwise routed_ticks, tick_sum_us
 * (denominator of every tick_share), families[5] {index, name, vtables, entry_va, entities, entities_per_tick, entry_sum_us,
 * entry_tick_share, sites[] {index, callee (original VA or vt+offset), sum_us, calls, calls_per_tick, us_per_call, tick_share}} and
 * brain_callees_all_families[30] (the same fields summed over families). Cumulative since the last activation, inclusive per call,
 * rows overlap and include each timed call's own timing overhead. last_status.brain_words carries the raw ntw2_status words.
 * brain_states: brain entry-state/sub-FSM histograms sorted by entry share, entry predicates and core-return self-deactivation,
 * unit+AA0 combat proxy, per-tick distinct units and 0x4B -> destination entity/unit counts. Raw brain_state_words is append-only.
 * loco.services: version, enabled (clone execution only), denominators {clones = loco_words[27], stages = loco_words[1]}, metrics (all 40 labelled
 * loco_service_words), totals {timed_calls, overflows, abandoned, max_depth, qpc_failures, clone_wall/union/outside us and per-clone/per-stage ratios} and
 * per_service {unlink_grid, unlink_owner, insert_owner, insert_grid, sweep, resolve, height_owner, wrapper_query: {us, max_us, calls, us_per_call, us_per_clone, us_per_stage, calls_per_clone}}; ratios are null on a zero denominator. Counts/us wrap
 * modulo 2^32; service us are inclusive and overlap; outside is clone_wall-union (clamped), not pure arithmetic; last_status.loco_service_words is raw.
 * loco.grid.metrics, loco.parallel.metrics and loco.owned.metrics contain all 32 labelled words from each appended row; last_status carries all raw arrays
 * (loco_owned_words follows resolve_frame_words; loco_owned_detail_words[16], loco_owned_phase_words[32] and loco_owned_load_words[16] follow it). loco.owned.enabled records --loco-owned-services (requires loco, loco_clone and loco_parallel);
 * loco.owned.quiet records --loco-quiet (requires --loco-owned-services); loco.owned.detail.metrics holds all 16 labelled detail words. loco.shadow.enabled is the EFFECTIVE state (false under quiet), requested/suppressed_by_quiet report the CLI.
 * loco_parallel records --loco-parallel (requires loco and loco_clone); loco.grid.enabled records effective grid mode (--loco-grid or --loco-grid-verify), default off.
 * loco.grid_v2.metrics exports the 16 NTW2_LOCO_GRID_V2_LABELS words; verify records --loco-grid-verify. collide.source exports source/native_stages/owned_stages/owned_refusals.
 * loco_grid_v2_words[16], collide_source_words[4], memory_words[57], then ai_completion_words[24] append at the status tail.
 * loco.grid_probation (--grid-probation) exports the 32 NTW2_GRID_PROBATION_LABELS words and every used caller row
 * {eip, eip_module, caller, caller_module, thread_mask, clone, clone_address, count, writes, first_site, last_site}.
 * grid_census follows ai_completion_words as a typed status tail, not an entry in the raw uint32 counts[] tables.
 * grid_census is null without the explicit feature or an initialized snapshot. It exports <=64 reader rows and <=512
 * retargeted-edge rows; route calls, proven native reader entries and EIP sample occupancy are distinct. Rates divide
 * corresponding in-tick calls by routed ticks (null if zero); phase/thread/site histograms are route-count marginals.
 * The reader id joins analysis/native-grid-reader-census.json. Edge site is the direct-call VA, not a timed-site index.
 * Sample failures/unknown samples and attribution/edge drops/unresolved edges remain explicit, including zeros.
 * ai_completion.metrics labels native planner duration and same-tick barrier wait count/sum/max plus disjoint
 * <=8/16/32/64/128/256/512/1024/>1024 ms histograms; no between-tick parked time is included.
 * memory.metrics labels the raw memory row: module bytes, activation/post-allocation/minimum available VA (low/high pairs),
 * samples, budget refusals and capacities. Total includes image and runtime-owned thread stack reservations, not game/driver memory.
 * Memory version 2 appends LOCO allocation detail and sticky budget fallback/release fields; original 28 indices are unchanged.
 * Memory version 3 appends native grid shift/inclusive maximum/dimension and catalog backing byte/count categories; cell_capacity includes native stride padding.
 * loco.owned.phase.metrics exports all 32 labelled phase words; derived ratios use stage calls, dispatches, chunks, worker entities or fallback entities as named and are null on zero denominators.
 * loco.owned.load.metrics exports activation preparation, model/capacity refusals and chunk CPU/wall diagnostics; storage is prepared once per generation before hooks publish.
 * Owned chunks are entity ranges claimed atomically by the pool, with one dispatch per stage, not per-unit dispatches.
 */
static BOOL write_receipt(Run *r, int exit_code)
{
    Sb b;
    /* Four MAXP strings, <=6 JSON bytes per UTF-16 unit: 98304 bytes.
       Existing scalar/status fields have 16384 bytes. Trace reserves 256 bytes per
       top tick plus 128 per site, 192 per aggregate site and 4096 for other totals.
       Retained raw-QPC tick rows reserve 192 bytes each; module rows reserve 4096.
       Individual sb_fmt calls stay below 2048 bytes. */
    static char storage[MAXP * 24u + 16384u + 4096u + 8192u + 65536u + NTW2_BRAIN2_CENSUS_WORDS * 96u +
                        NTW2_GRID_READERS * (2048u + NTW2_GRID_SITES * 80u) + NTW2_GRID_EDGES * 384u +
                        16u * (256u + NTW2_TIMED_SITES * 128u) + NTW2_TIMED_SITES * 192u +
                        NTW2_TRACE_ENTRIES * 192u + 4096u + NTW2_BRAIN_STATE_WORDS * 192u + NTW2_COLLISION_WORDS * 192u + NTW2_BRAIN2_WORDS * 192u + (NTW2_LOCO_WORDS + NTW2_LOCO_GATE_WORDS + NTW2_LOCO_SERVICE_WORDS + NTW2_LOCO_GRID_WORDS + NTW2_LOCO_PARALLEL_WORDS + NTW2_SWEEP_WORDS + NTW2_RESOLVE_WORDS + NTW2_ENV_WORDS + NTW2_ENV_TARGET_WORDS + NTW2_RESOLVE_FRAME_WORDS + NTW2_LOCO_OWNED_WORDS) * 192u +
                        NTW2_GRID_PROBATION_WORDS * 12u + NTW2_GRID_PROBATION_CALLERS * 320u + 4096u];
    char ts[48];
    FILETIME now;
    wchar_t tmp[MAXP + 8];
    HANDLE h;
    DWORD w;
    BOOL ok = FALSE;
    memset(&b, 0, sizeof b);
    b.p = storage;
    b.cap = sizeof storage;
    if (r->opt.tick_log[0]) {
        TickLog *log = &r->tick_log;
        /* 512 bytes exceeds a summary row even at maximum uint32/uint64
           values; include the additional escaped MAXP path separately.
           Reuse this allocation until the capture capacity grows. */
        size_t capacity = sizeof storage + MAXP * 6u + (size_t)log->capacity * 512u;
        if (capacity > log->receipt_capacity) {
            char *p = log->receipt_storage
                ? (char *)HeapReAlloc(GetProcessHeap(), 0, log->receipt_storage, capacity)
                : (char *)HeapAlloc(GetProcessHeap(), 0, capacity);
            if (!p) {
                errsay(L"unable to allocate the tick log receipt buffer.\n");
                return FALSE;
            }
            log->receipt_storage = p;
            log->receipt_capacity = capacity;
        }
        b.p = log->receipt_storage;
        b.cap = log->receipt_capacity;
    }
    GetSystemTimePreciseAsFileTime(&now);
    sb_put(&b, "{\n", 2);
    sb_fmt(&b, "  \"tool\": \"ntw2.exe\",\n  \"abi\": %u,\n", NTW2_ABI);
    iso_time(&r->t_start, ts, sizeof ts);
    sb_fmt(&b, "  \"started\": \"%s\",\n", ts);
    iso_time(&now, ts, sizeof ts);
    sb_fmt(&b, "  \"finished\": \"%s\",\n", ts);
    if (exit_code < 0)
        sb_fmt(&b, "  \"receipt_complete\": false,\n  \"exit_code\": null,\n  \"outcome\": ");
    else
        sb_fmt(&b, "  \"receipt_complete\": true,\n  \"exit_code\": %d,\n  \"outcome\": ", exit_code);
    sb_wstr(&b, r->outcome ? r->outcome : L"unknown");
    sb_put(&b, ",\n  \"game_dir\": ", 16);
    sb_wstr(&b, r->game_dir);
    sb_put(&b, ",\n  \"image_path\": ", 18);
    sb_wstr(&b, r->exe_path);
    sb_fmt(&b, ",\n  \"image_sha256\": \"%s\",\n  \"image_size\": %I64u,\n  \"image_sha256_expected\": \"%s\",\n", r->exe_sha,
           (unsigned long long)r->exe_size, NTW2_IMAGE_SHA256);
    sb_put(&b, "  \"runtime_dll\": ", 17);
    sb_wstr(&b, r->dll_path);
    sb_fmt(&b, ",\n  \"runtime_sha256\": \"%s\",\n  \"runtime_size\": %I64u,\n", r->dll_sha, (unsigned long long)r->dll_size);
    sb_fmt(&b, "  \"pid\": %lu,\n", (unsigned long)r->pid);
    if (r->pid) {
        iso_time(&r->created, ts, sizeof ts);
        sb_fmt(&b, "  \"process_created\": \"%s\",\n  \"image_base\": \"0x%08lX\",\n  \"runtime_base\": \"0x%08lX\",\n", ts,
               (unsigned long)r->exe_base, (unsigned long)r->dll_base);
    }
    sb_fmt(&b, "  \"requested_mask\": %lu,\n  \"requested\": ", (unsigned long)r->cfg.enabled_mask);
    sb_mask(&b, r->cfg.enabled_mask);
    sb_fmt(&b, ",\n  \"workers\": %lu,\n  \"poll_ms\": %lu,\n", (unsigned long)r->cfg.workers, (unsigned long)r->cfg.poll_ms);
    sb_fmt(&b, "  \"collide_census\": %s,\n", r->opt.collide_census ? "true" : "false");
    sb_fmt(&b, "  \"grid_census_requested\": %s,\n", (r->opt.mask & NTW2_GRID_CENSUS) ? "true" : "false");
    sb_fmt(&b, "  \"ai_census_requested\": %s,\n", (r->opt.mask & NTW2_AI_CENSUS) ? "true" : "false");
    sb_fmt(&b, "  \"loco_clone\": %s,\n", r->opt.loco_clone ? "true" : "false");
    sb_fmt(&b, "  \"loco_parallel\": %s,\n", r->opt.loco_parallel ? "true" : "false");
    sb_fmt(&b, "  \"loco_owned_services\": %s,\n", r->opt.loco_owned ? "true" : "false");
    sb_fmt(&b, "  \"loco_shadow\": %s,\n", r->opt.loco_shadow ? "true" : "false");
    sb_fmt(&b, "  \"loco_shadow_effective\": %s,\n", loco_shadow_effective(&r->opt) ? "true" : "false");
    sb_fmt(&b, "  \"loco_quiet\": %s,\n", r->opt.loco_quiet ? "true" : "false");
    sb_fmt(&b, "  \"loco_grid\": %s,\n", r->opt.loco_grid ? "true" : "false");
    sb_fmt(&b, "  \"loco_grid_verify\": %s,\n", r->opt.loco_grid_verify ? "true" : "false");
    sb_fmt(&b, "  \"grid_probation\": %s,\n", r->opt.grid_probation ? "true" : "false");
    sb_fmt(&b, "  \"brain_parallel\": %s,\n", r->opt.brain_parallel ? "true" : "false");
    sb_fmt(&b, "  \"brain_quiet\": %s,\n", r->opt.brain_quiet ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_shadow\": %s,\n", r->opt.brain_unit_shadow ? "true" : "false");
    sb_fmt(&b, "  \"collide_contact_shadow\": %s,\n", r->opt.collide_contact_shadow ? "true" : "false");
    sb_fmt(&b, "  \"collide_contact_workers\": %s,\n", r->opt.collide_contact_workers ? "true" : "false");
    sb_fmt(&b, "  \"army_unit_shadow\": %s,\n", (r->opt.mask & NTW2_ARMY_UNIT_SHADOW) ? "true" : "false");
    sb_fmt(&b, "  \"armed\": %s,\n  \"reached_full_activation\": %s,\n  \"remote_thread_outstanding\": %s,\n",
           r->ever_armed ? "true" : "false", r->ever_full ? "true" : "false", r->remote_leaked ? "true" : "false");
    sb_fmt(&b, "  \"game_exited\": %s,\n  \"game_exit_code\": %lu,\n", r->game_exited ? "true" : "false",
           (unsigned long)(r->game_exited ? r->game_exit : 0));
    sb_fmt(&b, "  \"replay\": ");
    sb_wstr(&b, r->opt.replay);
    sb_fmt(&b, ",\n  \"focus\": %s,\n  \"observe_seconds\": %lu,\n  \"exit_game_after_observe\": %s,\n",
           r->opt.focus ? "true" : "false", (unsigned long)r->opt.observe_s,
           r->opt.exit_game_after_observe ? "true" : "false");
    sb_fmt(&b, "  \"observation\": {\n    \"complete\": %s,\n    \"elapsed_ms\": %I64u,\n"
           "    \"status_samples\": %I64u,\n    \"active_generations\": %lu,\n"
           "    \"last_active_generation\": %lu,\n    \"active_to_waiting\": %lu,\n"
           "    \"reactivations\": %lu,\n    \"battle_tick_advance\": %I64u,\n"
           "    \"peak_workers\": %lu,\n    \"peak_storage_bytes\": %lu,\n    \"peak_retained_bytes\": %lu\n  },\n",
           r->observation_complete ? "true" : "false", (unsigned long long)r->observed_ms,
           (unsigned long long)r->status_samples, (unsigned long)r->active_generations,
           (unsigned long)r->last_active_generation, (unsigned long)r->battle_returns,
           (unsigned long)r->battle_reactivations, (unsigned long long)r->battle_tick_advance,
           (unsigned long)r->peak_workers, (unsigned long)r->peak_storage_bytes,
           (unsigned long)r->peak_retained_bytes);
    sb_fmt(&b, "  \"game_shutdown\": {\n    \"requested\": %s,\n    \"wm_close_windows\": %lu,\n"
           "    \"forced\": %s,\n    \"error\": %lu,\n    \"close_timeout_ms\": 10000\n  },\n",
           r->game_close_requested ? "true" : "false", (unsigned long)r->game_close_windows,
           r->game_terminated ? "true" : "false", (unsigned long)r->game_stop_error);
    sb_trace(&b, r->trace);
    sb_tick_log(&b, r);
    sb_profile_modules(&b, r);
    sb_brain(&b, r);
    sb_brain_states(&b, r);
    sb_collision(&b, r);
    sb_collide(&b, r);
    sb_collide_lod(&b, r);
    sb_loco(&b, r);
    sb_grid_census(&b, r);
    sb_ai_census(&b, r);
    sb_army_unit(&b, r);
    sb_brain2(&b, r);
    if (r->have_status) {
        unsigned memory_index;
        sb_fmt(&b, "  \"memory\": {\"metrics\": {");
        for (memory_index = 0; memory_index < NTW2_MEMORY_WORDS; ++memory_index)
            sb_fmt(&b, "%s\"%s\": %lu", memory_index ? ", " : "", k_memory_metrics[memory_index],
                   (unsigned long)r->last.memory_words[memory_index]);
        sb_fmt(&b, "}},\n");
    } else sb_fmt(&b, "  \"memory\": null,\n");
    if (r->have_status) {
        unsigned ai_index;
        sb_fmt(&b, "  \"ai_completion\": {\"metrics\": {");
        for (ai_index=0;ai_index<NTW2_AI_COMPLETION_WORDS;++ai_index)
            sb_fmt(&b, "%s\"%s\": %lu",ai_index ? ", " : "",k_ai_completion_metrics[ai_index],
                   (unsigned long)r->last.ai_completion_words[ai_index]);
        sb_fmt(&b, "}},\n");
    } else sb_fmt(&b, "  \"ai_completion\": null,\n");
    if (r->have_status && (r->opt.mask & NTW2_AI_ASYNC2)) {
        unsigned ai2_index;
        sb_fmt(&b, "  \"ai_async2\": {\"metrics\": {");
        for (ai2_index = 0; ai2_index < NTW2_AI_ASYNC2_WORDS; ++ai2_index)
            sb_fmt(&b, "%s\"%s\": %lu", ai2_index ? ", " : "", k_ai_async2_metrics[ai2_index],
                   (unsigned long)r->last.ai_async2_words[ai2_index]);
        sb_fmt(&b, "}, \"route\": {");
        for (ai2_index = 0; ai2_index < NTW2_AI_ASYNC2_ROUTE_WORDS; ++ai2_index)
            sb_fmt(&b, "%s\"%s\": %lu", ai2_index ? ", " : "", k_ai_async2_route_metrics[ai2_index],
                   (unsigned long)r->last.ai_async2_route_words[ai2_index]);
        sb_fmt(&b, "}, \"complete_before_next_tick_fraction\": ");
        sb_ratio(&b, r->last.ai_async2_route_words[9], r->last.ai_async2_route_words[4]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_async2\": null,\n");
    if (r->have_status) {
        const ntw2_status *s = &r->last;
        sb_put(&b, "  \"last_status\": {\n    \"phase\": ", 32);
        sb_wstr(&b, phase_name(s->phase));
        sb_fmt(&b,
               ",\n    \"sequence\": %lu,\n    \"requested_mask\": %lu,\n    \"active_mask\": %lu,\n    \"active\": ",
               (unsigned long)s->sequence, (unsigned long)s->requested_mask, (unsigned long)s->active_mask);
        sb_mask(&b, s->active_mask);
        sb_fmt(&b,
               ",\n    \"error\": %lu,\n    \"error_detail\": %lu,\n    \"pid\": %lu,\n    \"image_base\": %lu,\n"
               "    \"root\": %lu,\n    \"model\": %lu,\n    \"generation\": %lu,\n    \"monitor_thread\": %lu,\n"
               "    \"workers\": %lu,\n    \"tick\": %lu,\n    \"path_completed\": %lu,\n    \"formation_committed\": %lu,\n"
               "    \"ballistic_committed\": %lu,\n    \"collision_cache_hits\": %lu,\n"
               "    \"worker_chunks\": %lu,\n    \"storage_bytes\": %lu,\n    \"retained_bytes\": %lu,\n    \"probe\": %lu,\n"
               "    \"path_fallbacks\": %lu,\n    \"path_refused\": %lu,\n    \"formation_epochs\": %lu,\n"
               "    \"formation_refused\": %lu,\n    \"ballistic_stages\": %lu,\n",
               (unsigned long)s->error, (unsigned long)s->error_detail, (unsigned long)s->pid, (unsigned long)s->image_base,
               (unsigned long)s->root, (unsigned long)s->model, (unsigned long)s->generation, (unsigned long)s->monitor_thread,
               (unsigned long)s->workers, (unsigned long)s->tick, (unsigned long)s->path_completed,
               (unsigned long)s->formation_committed, (unsigned long)s->ballistic_committed,
               (unsigned long)s->collision_cache_hits, (unsigned long)s->worker_chunks,
               (unsigned long)s->storage_bytes, (unsigned long)s->retained_bytes, (unsigned long)s->probe,
               (unsigned long)s->path_fallbacks, (unsigned long)s->path_refused, (unsigned long)s->formation_epochs,
               (unsigned long)s->formation_refused, (unsigned long)s->ballistic_stages);
        {
            unsigned ai_index;
            sb_fmt(&b, "    \"ai_completion_words\": [");
            for (ai_index=0;ai_index<NTW2_AI_COMPLETION_WORDS;++ai_index)
                sb_fmt(&b, "%s%lu",ai_index ? "," : "",(unsigned long)s->ai_completion_words[ai_index]);
            sb_fmt(&b, "],\n");
        }
        {
            static const char *const names[45] = {"formation_words", "query_words", "path_words", "ballistic_words",
                                                  "formation_diag", "tick_words", "sim_words", "planner_words", "planner_walk_words",
                                                  "ai_words", "ai_extra_words", "crash_words", "brain_words", "ai_slice_words", "ai_validation_words", "visual_words", "allocator_words", "ai_slice_site_words", "brain_state_words", "collision_words", "collide_words", "brain2_words", "collide_lod_words", "ai_ctrl_words", "ai_slice_budget_words", "ai_park_words", "loco_words", "loco_gate_words", "loco_service_words", "loco_grid_words", "loco_parallel_words", "sweep_words", "resolve_words", "env_words", "env_target_words", "resolve_frame_words", "loco_owned_words", "loco_owned_detail_words", "loco_owned_phase_words", "loco_owned_load_words", "loco_grid_v2_words", "collide_source_words", "memory_words", "collide_contact_words", "grid_probation_words"};
            const uint32_t *arrays[45] = {s->formation_words, s->query_words, s->path_words, s->ballistic_words,
                                          s->formation_diag, s->tick_words, s->sim_words, s->planner_words, s->planner_walk_words,
                                          s->ai_words, s->ai_extra_words, s->crash_words, s->brain_words, s->ai_slice_words, s->ai_validation_words, s->visual_words, s->allocator_words, s->ai_slice_site_words, s->brain_state_words, s->collision_words, s->collide_words, s->brain2_words, s->collide_lod_words, s->ai_ctrl_words, s->ai_slice_budget_words, s->ai_park_words, s->loco_words, s->loco_gate_words, s->loco_service_words, s->loco_grid_words, s->loco_parallel_words, s->sweep_words, s->resolve_words, s->env_words, s->env_target_words, s->resolve_frame_words, s->loco_owned_words, s->loco_owned_detail_words, s->loco_owned_phase_words, s->loco_owned_load_words, s->loco_grid_v2_words, s->collide_source_words, s->memory_words, s->collide_contact_words, s->grid_probation_words};
            const unsigned counts[45] = {16, 16, 24, 8, 192, 16, 16, 64, 16, 16, 32, 32, NTW2_BRAIN_WORDS, 8, 8, 32, NTW2_ALLOCATOR_WORDS, 2, NTW2_BRAIN_STATE_WORDS, NTW2_COLLISION_WORDS, NTW2_COLLIDE_WORDS, NTW2_BRAIN2_WORDS, NTW2_COLLIDE_LOD_WORDS, 16, NTW2_AI_SLICE_BUDGET_WORDS, 8, NTW2_LOCO_WORDS, NTW2_LOCO_GATE_WORDS, NTW2_LOCO_SERVICE_WORDS, NTW2_LOCO_GRID_WORDS, NTW2_LOCO_PARALLEL_WORDS, NTW2_SWEEP_WORDS, NTW2_RESOLVE_WORDS, NTW2_ENV_WORDS, NTW2_ENV_TARGET_WORDS, NTW2_RESOLVE_FRAME_WORDS, NTW2_LOCO_OWNED_WORDS, NTW2_LOCO_OWNED_DETAIL_WORDS, NTW2_LOCO_OWNED_PHASE_WORDS, NTW2_LOCO_OWNED_LOAD_WORDS, NTW2_LOCO_GRID_V2_WORDS, NTW2_COLLIDE_SOURCE_WORDS, NTW2_MEMORY_WORDS, NTW2_COLLIDE_CONTACT_WORDS, NTW2_GRID_PROBATION_WORDS};
            unsigned i, j;
            for (i = 0; i < 45; ++i) {
                sb_fmt(&b, "    \"%s\": [", names[i]);
                for (j = 0; j < counts[i]; ++j) sb_fmt(&b, "%s%lu", j ? "," : "", (unsigned long)arrays[i][j]);
                sb_fmt(&b, "]%s\n", i + 1 < 45 ? "," : "");
            }
            sb_put(&b, "  }\n", 4);
        }
    } else {
        sb_put(&b, "  \"last_status\": null\n", 22);
    }
    sb_put(&b, "}\n", 2);
    if (b.oom) { errsay(L"receipt exceeds its serialization buffer.\n"); goto done; }
    _snwprintf_s(tmp, MAXP + 8, _TRUNCATE, L"%ls.tmp", r->opt.receipt);
    h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { win_fail(L"creating the receipt temp file", GetLastError()); goto done; }
    if (!WriteFile(h, b.p, (DWORD)b.len, &w, NULL) || w != b.len || !FlushFileBuffers(h)) {
        win_fail(L"writing the receipt", GetLastError());
        CloseHandle(h);
        DeleteFileW(tmp);
        goto done;
    }
    CloseHandle(h);
    if (!MoveFileExW(tmp, r->opt.receipt, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        win_fail(L"publishing the receipt", GetLastError());
        DeleteFileW(tmp);
        goto done;
    }
    ok = TRUE;
done:
    return ok;
}

/* Keep the most recent complete copy so a spontaneous game exit still has a
   bounded-age profile. Live copies are deliberately observational (see ABI). */
static BOOL read_profile(Run *r)
{
    ntw2_profile_status p;
    ntw2_profile_runtime_header runtime;
    ntw2_profile_runtime_header *stored;
    SIZE_T bytes, image_bytes;
    uint32_t phase, runtime_va;
    if (!(r->opt.mask & (NTW2_PROFILE | NTW2_GRID_CENSUS | NTW2_AI_CENSUS))) return TRUE;
    if (!remote_read(r->proc, r->dll_base + r->dll.profile_rva, &p, sizeof p) ||
        p.abi != NTW2_PROFILE_ABI || p.size != sizeof p ||
        p.bucket_bytes != NTW2_PROFILE_BUCKET_BYTES || !p.bucket_count ||
        p.bucket_count > 0x10000000u / NTW2_PROFILE_BUCKET_BYTES ||
        !p.hist_va || !p.tick_hist_va || !p.frames_hist_va)
        return FALSE;
    for (phase = 0; phase < NTW2_PROFILE_MAIN_PHASES; ++phase)
        if (!NTW2_PROFILE_PHASE_FIELD(&p, phase, hist_va)) return FALSE;
    bytes = (SIZE_T)p.bucket_count * sizeof(uint32_t);
    image_bytes = bytes * (3 + NTW2_PROFILE_MAIN_PHASES);
    if ((uint64_t)p.hist_va + image_bytes + sizeof runtime > UINT32_MAX) return FALSE;
    runtime_va = p.hist_va + (uint32_t)image_bytes;
    if (!remote_read(r->proc, runtime_va, &runtime, sizeof runtime) ||
        runtime.magic != NTW2_PROFILE_RUNTIME_MAGIC || runtime.version != NTW2_PROFILE_RUNTIME_VERSION ||
        runtime.runtime_base != r->dll_base || !runtime.runtime_size || runtime.runtime_size > 0x10000000u ||
        runtime.bucket_bytes != NTW2_PROFILE_BUCKET_BYTES ||
        !runtime.bucket_count ||
        runtime.bucket_count > (runtime.runtime_size + NTW2_PROFILE_BUCKET_BYTES - 1) / NTW2_PROFILE_BUCKET_BYTES ||
        (!(runtime.flags & 8u) && runtime.bucket_count != (runtime.runtime_size + NTW2_PROFILE_BUCKET_BYTES - 1) / NTW2_PROFILE_BUCKET_BYTES) ||
        runtime.histogram_count != NTW2_PROFILE_RUNTIME_HISTOGRAMS ||
        runtime.pair_capacity != NTW2_PROFILE_RUNTIME_PAIRS || runtime.wait_capacity != NTW2_PROFILE_RUNTIME_WAITS ||
        runtime.bytes != NTW2_PROFILE_RUNTIME_BYTES(runtime.bucket_count) ||
        (uint64_t)runtime_va + runtime.bytes > UINT32_MAX) return FALSE;
    if (r->profile_arrays) {
        if (p.bucket_count != r->profile.bucket_count) return FALSE;
        stored = (ntw2_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
        if (stored->bytes != runtime.bytes) return FALSE;
    } else {
        r->profile_arrays = (uint32_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, image_bytes + runtime.bytes);
        if (!r->profile_arrays) return FALSE;
        r->profile = p;
        stored = (ntw2_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
        *stored = runtime;
    }
    r->have_profile = FALSE;
    if (!remote_read(r->proc, p.hist_va, r->profile_arrays, bytes) ||
        !remote_read(r->proc, p.tick_hist_va, r->profile_arrays + p.bucket_count, bytes) ||
        !remote_read(r->proc, p.frames_hist_va, r->profile_arrays + p.bucket_count * 2, bytes))
        return FALSE;
    for (phase = 0; phase < NTW2_PROFILE_MAIN_PHASES; ++phase)
        if (!remote_read(r->proc, NTW2_PROFILE_PHASE_FIELD(&p, phase, hist_va),
                         r->profile_arrays + p.bucket_count * (3 + phase), bytes)) return FALSE;
    stored = (ntw2_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
    if (!remote_read(r->proc, runtime_va, stored, runtime.bytes)) return FALSE;
    /* Metadata is immutable while sampling; never trust a changed layout. */
    if (stored->magic != runtime.magic || stored->version != runtime.version || stored->bytes != runtime.bytes ||
        stored->runtime_base != runtime.runtime_base || stored->runtime_size != runtime.runtime_size ||
        stored->bucket_bytes != runtime.bucket_bytes || stored->bucket_count != runtime.bucket_count ||
        stored->histogram_count != runtime.histogram_count || stored->pair_capacity != runtime.pair_capacity ||
        stored->wait_capacity != runtime.wait_capacity) return FALSE;
    stored->selected_site = r->opt.profile_site;
    r->profile = p;
    r->have_profile = TRUE;
    return TRUE;
}

static void print_profile_threads(const ntw2_profile_status *p)
{
    uint32_t order[NTW2_PROFILE_THREADS], count = 0, i, rank;
    for (i = 0; i < NTW2_PROFILE_THREADS; ++i) {
        if (!p->thread_id[i]) continue;
        for (rank = count; rank && p->in_image[i] > p->in_image[order[rank - 1]]; --rank)
            order[rank] = order[rank - 1];
        order[rank] = i;
        ++count;
    }
    say(L"  Process threads during simulation ticks (sorted by image samples; EIP occupancy, not CPU accounting):\n");
    say(L"      thread id    samples     image%%     wait%%      tbb%%\n");
    for (rank = 0; rank < count; ++rank) {
        double scale;
        i = order[rank];
        scale = p->thread_samples[i] ? 100.0 / p->thread_samples[i] : 0.0;
        say(L"    %11lu %10lu %9.2f%% %8.2f%% %8.2f%%%ls\n",
            (unsigned long)p->thread_id[i], (unsigned long)p->thread_samples[i],
            scale * p->in_image[i], scale * p->in_wait[i], scale * p->in_tbb[i],
            p->thread_id[i] == p->tick_thread_id ? L"  tick" : L"");
    }
}

static void print_profile_waits(const ntw2_profile_status *p)
{
    uint32_t order[NTW2_PROFILE_WAIT_HANDLES], count = 0, i, rank;
    for (i = 0; i < NTW2_PROFILE_WAIT_HANDLES; ++i) {
        if (!p->wait_count[i]) continue;
        for (rank = count; rank && p->wait_count[i] > p->wait_count[order[rank - 1]]; --rank)
            order[rank] = order[rank - 1];
        order[rank] = i;
        ++count;
    }
    say(L"  Tick thread %lu: top 8 NtWaitForSingleObject HANDLE values ([ESP+4], exact tracked counts):\n",
        (unsigned long)p->tick_thread_id);
    for (rank = 0; rank < count; ++rank) {
        i = order[rank];
        say(L"    0x%08lX %10lu\n", (unsigned long)p->wait_handle[i], (unsigned long)p->wait_count[i]);
    }
    say(L"    unsafe reads=%lu; untracked observations after 4096 distinct handles=%lu\n",
        (unsigned long)p->wait_read_failed, (unsigned long)p->wait_overflow);
    say(L"  Tick-executing thread wait stubs: single=%lu multiple=%lu delay=%lu alert=%lu keyed_release=%lu keyed_wait=%lu (of %lu tick samples)\n",
        (unsigned long)p->tick_wait_kind[0], (unsigned long)p->tick_wait_kind[1], (unsigned long)p->tick_wait_kind[2],
        (unsigned long)p->tick_wait_kind[3], (unsigned long)p->tick_wait_kind[4], (unsigned long)p->tick_wait_kind[5],
        (unsigned long)p->tick_samples);
}

static void print_profile_top(const wchar_t *name, const uint32_t *counts, const ntw2_profile_status *p,
                              uint32_t samples, uint32_t limit)
{
    struct { uint32_t bucket, count; } top[30] = {{0, 0}};
    uint32_t i, rank;
    for (i = 0; i < p->bucket_count; ++i) {
        uint32_t count = counts[i];
        if (!count || count <= top[limit - 1].count) continue;
        for (rank = limit - 1; rank && count > top[rank - 1].count; --rank)
            top[rank] = top[rank - 1];
        top[rank].bucket = i;
        top[rank].count = count;
    }
    if (limit == 30)
        say(L"Profile: top 30 frames (main-image 64-byte buckets; preferred-base addresses; %% of %lu gated samples)\n",
            (unsigned long)samples);
    else
        say(L"Profile %ls: top 20 main-image 64-byte buckets (preferred-base addresses; %% of %lu observations)\n",
            name, (unsigned long)samples);
    for (rank = 0; rank < limit && top[rank].count; ++rank)
        say(L"  0x%08lX  %10lu  %7.3f%%\n",
            (unsigned long)(0x400000u + top[rank].bucket * p->bucket_bytes),
            (unsigned long)top[rank].count,
            samples ? 100.0 * top[rank].count / samples : 0.0);
}

static void print_profile_chains(const wchar_t *name, const uint32_t *counts, const uint32_t *lengths,
                                 const uint32_t chains[][NTW2_PROFILE_CHAIN_DEPTH],
                                 uint32_t uncaptured, uint32_t samples, uint32_t limit)
{
    struct { uint32_t index, count; } top[12] = {{0, 0}};
    uint32_t i, rank, frame;
    for (i = 0; i < NTW2_PROFILE_CHAINS; ++i) {
        uint32_t count = counts[i];
        if (!lengths[i] || lengths[i] > NTW2_PROFILE_CHAIN_DEPTH ||
            !count || count <= top[limit - 1].count) continue;
        for (rank = limit - 1; rank && count > top[rank - 1].count; --rank)
            top[rank] = top[rank - 1];
        top[rank].index = i;
        top[rank].count = count;
    }
    say(L"Profile %ls: top %lu retained ordered chains (first 64 distinct; preferred-base VAs; %% of %lu samples)\n",
        name, (unsigned long)limit, (unsigned long)samples);
    say(L"  Stack scan from ESP upward, not an unwind; repeated frames preserved; uncaptured=%lu.\n",
        (unsigned long)uncaptured);
    for (rank = 0; rank < limit && top[rank].count; ++rank) {
        i = top[rank].index;
        say(L"  %10lu  %7.3f%%  ", (unsigned long)top[rank].count,
            samples ? 100.0 * top[rank].count / samples : 0.0);
        for (frame = 0; frame < lengths[i]; ++frame)
            say(L"%ls0x%08lX", frame ? L" <- " : L"", (unsigned long)chains[i][frame]);
        say(L"\n");
    }
}

static void print_profile_main(const ntw2_profile_status *p, const uint32_t *arrays)
{
    static const wchar_t *const names[NTW2_PROFILE_MAIN_PHASES] = {
        L"main A1 (tick start)", L"main B (post-tick)", L"main C (otherwise)", L"main A2 (remaining tick)"
    };
    static const wchar_t *const kinds[6] = { L"single", L"multiple-set", L"delay",
        L"alert", L"keyed_release", L"keyed_wait" };
    uint32_t phase, index, i, rank;
    say(L"Main-thread phase profile: thread=%lu; A1=first %lu ms of active tick, A2=remaining active tick,\n"
        L"  B=within %lu ms after exit, C=otherwise. A1/A2 take precedence over B.\n",
        (unsigned long)p->main_thread_id, (unsigned long)p->main_start_tick_ms, (unsigned long)p->main_post_tick_ms);
    say(L"  Shares use ALL successful main-thread samples in each phase (including waits/non-image EIPs).\n");
    say(L"  Module refresh failures=%lu, capacity omissions=%lu; ranges refresh about every 2 s.\n",
        (unsigned long)p->module_refresh_failed, (unsigned long)p->module_omitted);
    say(L"  ntw2 includes clones; driver=nv*/atiu*/ig*, msvcr=msvcr*; unlisted modules (including KernelBase) count as other.\n");
    for (index = 0; index < NTW2_PROFILE_MAIN_PHASES; ++index) {
        uint32_t order[NTW2_PROFILE_WAIT_HANDLES], count = 0, samples, waits;
        const uint32_t *counts, *handles, *handle_kinds, *wait_kinds, *modules;
        phase = k_profile_phase_order[index];
        samples = NTW2_PROFILE_PHASE_FIELD(p, phase, samples);
        waits = NTW2_PROFILE_PHASE_FIELD(p, phase, wait);
        counts = NTW2_PROFILE_PHASE_FIELD(p, phase, wait_count);
        handles = NTW2_PROFILE_PHASE_FIELD(p, phase, wait_handle);
        handle_kinds = NTW2_PROFILE_PHASE_FIELD(p, phase, wait_handle_kind);
        wait_kinds = NTW2_PROFILE_PHASE_FIELD(p, phase, wait_kind);
        modules = NTW2_PROFILE_PHASE_FIELD(p, phase, modules);
        say(L"  %ls: samples=%lu waits=%lu wait=%.3f%%\n", names[phase],
            (unsigned long)samples, (unsigned long)waits, samples ? 100.0 * waits / samples : 0.0);
        say(L"    Module EIP occupancy (%% of phase samples):\n");
        for (i = 0; i < NTW2_PROFILE_MODULE_COUNT; ++i)
            say(L"      %-12hs %10lu %8.3f%%\n", k_profile_modules[i], (unsigned long)modules[i],
                samples ? 100.0 * modules[i] / samples : 0.0);
        say(L"    Wait-stub occupancy:");
        for (i = 0; i < 6; ++i) say(L" %ls=%lu", kinds[i], (unsigned long)wait_kinds[i]);
        say(L"\n    Top handles by exact (stub, HANDLE) counts:\n");
        for (i = 0; i < NTW2_PROFILE_WAIT_HANDLES; ++i) {
            if (!counts[i]) continue;
            for (rank = count; rank && counts[i] > counts[order[rank - 1]]; --rank)
                order[rank] = order[rank - 1];
            order[rank] = i;
            ++count;
        }
        for (rank = 0; rank < count; ++rank) {
            uint32_t kind;
            i = order[rank];
            kind = handle_kinds[i];
            say(L"      %-14ls 0x%08lX %10lu\n", kind < 6 ? kinds[kind] : L"unknown",
                (unsigned long)handles[i], (unsigned long)counts[i]);
        }
        say(L"    unsafe reads=%lu; untracked observations after 4096 (stub, HANDLE) keys=%lu\n",
            (unsigned long)NTW2_PROFILE_PHASE_FIELD(p, phase, wait_read_failed),
            (unsigned long)NTW2_PROFILE_PHASE_FIELD(p, phase, wait_overflow));
        print_profile_top(names[phase], arrays + p->bucket_count * phase, p, samples, 20);
    }
    say(L"  Wait EIPs are occupancy, not proof of blocking. Multiple-set rows count each distinct set member;\n");
    say(L"  delay/alert have no HANDLE; keyed-event HANDLE may be NULL and does not identify the key.\n");
    print_profile_chains(L"main A1", p->main_start_chain_count, p->main_start_chain_len,
                         p->main_start_chains, p->main_start_chain_uncaptured, p->main_samples[NTW2_PROFILE_PHASE_A1], 10);
    print_profile_chains(L"main B", p->main_post_chain_count, p->main_post_chain_len,
                         p->main_post_chains, p->main_post_chain_uncaptured, p->main_samples[NTW2_PROFILE_PHASE_B], 10);
}

static void print_profile_main_diff(const ntw2_profile_status *p, const uint32_t *arrays,
                                    uint32_t first, uint32_t second)
{
    struct { uint32_t bucket; double first, second, delta; } top[20] = {{0, 0, 0, 0}};
    uint32_t i, rank, count = 0;
    const uint32_t *a = arrays + p->bucket_count * first, *b = arrays + p->bucket_count * second;
    const uint32_t samples_a = NTW2_PROFILE_PHASE_FIELD(p, first, samples);
    const uint32_t samples_b = NTW2_PROFILE_PHASE_FIELD(p, second, samples);
    say(L"Profile main %hs vs %hs: top 20 bucket share differences, descending (percentage points; per-tick work candidates)\n",
        k_profile_phases[first], k_profile_phases[second]);
    if (!samples_a || !samples_b) {
        say(L"  Unavailable: both phases need samples (%hs=%lu %hs=%lu).\n",
            k_profile_phases[first], (unsigned long)samples_a, k_profile_phases[second], (unsigned long)samples_b);
        return;
    }
    for (i = 0; i < p->bucket_count; ++i) {
        double share_a, share_b, delta;
        if (!a[i] && !b[i]) continue;
        share_a = 100.0 * a[i] / samples_a;
        share_b = 100.0 * b[i] / samples_b;
        delta = share_a - share_b;
        if (count == 20 && delta <= top[19].delta) continue;
        if (count < 20) ++count;
        for (rank = count - 1; rank && delta > top[rank - 1].delta; --rank)
            top[rank] = top[rank - 1];
        top[rank].bucket = i;
        top[rank].first = share_a;
        top[rank].second = share_b;
        top[rank].delta = delta;
    }
    say(L"    preferred VA  first samples second samples first share second share first-second pp\n");
    for (rank = 0; rank < count; ++rank) {
        i = top[rank].bucket;
        say(L"    0x%08lX %10lu %10lu %8.3f%% %8.3f%% %+10.3f\n",
            (unsigned long)(0x400000u + i * p->bucket_bytes), (unsigned long)a[i], (unsigned long)b[i],
            top[rank].first, top[rank].second, top[rank].delta);
    }
}

static void print_profile_runtime(const ntw2_profile_runtime_header *header)
{
    static const wchar_t *const names[NTW2_PROFILE_RUNTIME_HISTOGRAMS] = {
        L"all observed threads", L"actual tick owner", L"workers (heuristic)", L"selected-gate tick owner"
    };
    const uint32_t *histograms = NTW2_PROFILE_RUNTIME_HIST(header);
    const ntw2_profile_runtime_pair *pairs = NTW2_PROFILE_RUNTIME_PAIR_TABLE(header);
    const ntw2_profile_runtime_wait *waits = NTW2_PROFILE_RUNTIME_WAIT_TABLE(header);
    uint32_t table, i, rank;
    struct { uint32_t rva, key, count; } top[20];
    say(L"Profile runtime: module base=0x%08lX size=0x%08lX; selected site=%ld (-1=whole tick).\n",
        (unsigned long)header->runtime_base, (unsigned long)header->runtime_size,
        header->selected_site ? (long)header->selected_site - 1 : -1L);
    say(L"  Workers exclude actual tick owner and published AI thread; not exact pool membership.\n");
    say(L"  All-thread runtime samples cover actual ticks plus main-thread observations outside ticks.\n");
    for (table = 0; table < NTW2_PROFILE_RUNTIME_HISTOGRAMS + 2; ++table) {
        uint32_t size = table < NTW2_PROFILE_RUNTIME_HISTOGRAMS ? header->bucket_count :
            table == NTW2_PROFILE_RUNTIME_HISTOGRAMS ? header->pair_capacity : header->wait_capacity;
        ZeroMemory(top, sizeof top);
        for (i = 0; i < size; ++i) {
            uint32_t count, rva, key = 0;
            if (table < NTW2_PROFILE_RUNTIME_HISTOGRAMS) {
                count = histograms[table * header->bucket_count + i]; rva = i * header->bucket_bytes;
            } else if (table == NTW2_PROFILE_RUNTIME_HISTOGRAMS) {
                count = pairs[i].count; rva = pairs[i].rva; key = pairs[i].frame_rva;
            } else {
                count = waits[i].count; rva = waits[i].rva; key = waits[i].kind;
            }
            if (!count || count <= top[19].count) continue;
            for (rank = 19; rank && count > top[rank - 1].count; --rank) top[rank] = top[rank - 1];
            top[rank].rva = rva; top[rank].key = key; top[rank].count = count;
        }
        say(L"  Top 20 runtime %ls:\n", table < NTW2_PROFILE_RUNTIME_HISTOGRAMS ? names[table] :
            table == NTW2_PROFILE_RUNTIME_HISTOGRAMS ? L"tick owner / main-image frame pairs" : L"tick wait-stub callers (exact RVAs)");
        for (rank = 0; rank < 20 && top[rank].count; ++rank) {
            say(L"    RVA 0x%08lX  %10lu", (unsigned long)top[rank].rva, (unsigned long)top[rank].count);
            if (table == NTW2_PROFILE_RUNTIME_HISTOGRAMS)
                say(L"  frame RVA=0x%08lX preferred VA=0x%08lX", (unsigned long)top[rank].key,
                    (unsigned long)(0x400000u + top[rank].key));
            else if (table == NTW2_PROFILE_RUNTIME_HISTOGRAMS + 1)
                say(L"  wait kind=%lu", (unsigned long)top[rank].key);
            say(L"\n");
        }
    }
    say(L"  Frame pairs=%lu dropped=%lu (stack-scan hints, not proof of active site; do not sum gates).\n",
        (unsigned long)header->pair_count, (unsigned long)header->pair_overflow);
    say(L"  Wait callers=%lu dropped=%lu; samples=%lu unresolved=%lu direct=%lu scanned=%lu (scans may be stale).\n",
        (unsigned long)header->wait_count, (unsigned long)header->wait_overflow,
        (unsigned long)header->wait_samples, (unsigned long)header->wait_unresolved,
        (unsigned long)header->wait_direct, (unsigned long)header->wait_scanned);
}

static BOOL write_profile(Run *r)
{
    ntw2_profile_status p;
    const ntw2_profile_runtime_header *runtime;
    wchar_t path[MAXP + 16], tmp[MAXP + 20];
    HANDLE file;
    DWORD wrote, bytes, error = 0;
    if (!(r->opt.mask & (NTW2_PROFILE | NTW2_GRID_CENSUS | NTW2_AI_CENSUS))) return TRUE;
    if (!r->have_profile) {
        errsay(L"no complete profiling snapshot is available (sampling may not have started).\n");
        return FALSE;
    }
    p = r->profile;
    runtime = (const ntw2_profile_runtime_header *)(r->profile_arrays + p.bucket_count * (3 + NTW2_PROFILE_MAIN_PHASES));
    say(L"Profile: %lu samples, %lu failed, %lu rounds; runtime=%lu clones=%lu tbb=%lu wait=%lu other=%lu outside-tick=%lu.\n",
        (unsigned long)p.samples, (unsigned long)p.failed, (unsigned long)p.rounds,
        (unsigned long)p.overflow[0], (unsigned long)p.overflow[1], (unsigned long)p.overflow[2],
        (unsigned long)p.overflow[3], (unsigned long)p.overflow[4], (unsigned long)p.overflow[5]);
    say(L"  Enumeration failures=%lu, capacity omissions=%lu, reused thread rows=%lu; tick samples=%lu.\n",
        (unsigned long)p.enumeration_failed, (unsigned long)p.thread_limit,
        (unsigned long)p.thread_replaced, (unsigned long)p.tick_samples);
    print_profile_threads(&p);
    print_profile_waits(&p);
    print_profile_top(L"all-thread EIP (critical-path candidates)", r->profile_arrays, &p, p.samples, 20);
    print_profile_top(L"tick-thread EIP", r->profile_arrays + p.bucket_count, &p, p.tick_samples, 20);
    print_profile_top(L"frames", r->profile_arrays + p.bucket_count * 2, &p, p.tick_samples, 30);
    print_profile_chains(L"tick", p.chain_count, p.chain_len, p.chains, p.chain_uncaptured, p.tick_samples, 12);
    print_profile_main(&p, r->profile_arrays + p.bucket_count * 3);
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, NTW2_PROFILE_PHASE_A1, NTW2_PROFILE_PHASE_C);
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, NTW2_PROFILE_PHASE_A1, NTW2_PROFILE_PHASE_A2);
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, NTW2_PROFILE_PHASE_B, NTW2_PROFILE_PHASE_C);
    print_profile_runtime(runtime);
    if (!r->opt.receipt[0]) {
        say(L"No --receipt path: profile printed only; no binary written.\n");
        return TRUE;
    }
    _snwprintf_s(path, MAXP + 16, _TRUNCATE, L"%ls.profile.bin", r->opt.receipt);
    _snwprintf_s(tmp, MAXP + 20, _TRUNCATE, L"%ls.tmp", path);
    file = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        win_fail(L"creating the profile temp file", GetLastError());
        return FALSE;
    }
    p.hist_va = p.tick_hist_va = p.frames_hist_va = 0;
    ZeroMemory(p.main_hist_va, sizeof p.main_hist_va);
    p.main_rest.hist_va = 0;
    bytes = p.bucket_count * sizeof(uint32_t) * (3 + NTW2_PROFILE_MAIN_PHASES);
    if (!WriteFile(file, &p, sizeof p, &wrote, NULL) || wrote != sizeof p ||
        !WriteFile(file, r->profile_arrays, bytes, &wrote, NULL) || wrote != bytes ||
        !WriteFile(file, p.chain_count, sizeof p.chain_count, &wrote, NULL) || wrote != sizeof p.chain_count ||
        !WriteFile(file, p.chain_len, sizeof p.chain_len, &wrote, NULL) || wrote != sizeof p.chain_len ||
        !WriteFile(file, p.chains, sizeof p.chains, &wrote, NULL) || wrote != sizeof p.chains ||
        !WriteFile(file, &p.chain_uncaptured, sizeof p.chain_uncaptured, &wrote, NULL) || wrote != sizeof p.chain_uncaptured ||
        !WriteFile(file, runtime, runtime->bytes, &wrote, NULL) || wrote != runtime->bytes ||
        !FlushFileBuffers(file))
        error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    CloseHandle(file);
    if (!error && !MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        error = GetLastError();
    if (error) {
        DeleteFileW(tmp);
        win_fail(L"writing the profile", error);
        return FALSE;
    }
    say(L"Profile written: %ls (%lu-byte LE ABI %lu header; all/tick/frames/main A1/B/C/A2 arrays; tick chain trailer; NTR8 runtime tables).\n",
        path, (unsigned long)p.size, (unsigned long)p.abi);
    return TRUE;
}

/* Releases launcher resources; game shutdown, when requested, happens before this. */
static int finish(Run *r, int code, const wchar_t *outcome)
{
    r->outcome = outcome;
    finalize_trace(r);
    if (!write_trace(r) && (code == EXIT_OK || code == EXIT_INTERRUPTED)) code = EXIT_RECEIPT;
    if (!write_tick_log(r) && (code == EXIT_OK || code == EXIT_INTERRUPTED)) code = EXIT_RECEIPT;
    print_brain_sites(r);
    print_brain_states(r);
    print_collision(r);
    print_collide(r);
    print_collide_lod(r);
    print_loco(r);
    print_grid_census(r);
    print_ai_census(r);
    print_memory(r);
    if (r->opt.receipt[0]) {
        if (!write_receipt(r, code)) {
            if (code == EXIT_OK) code = EXIT_RECEIPT;
        } else {
            say(L"Receipt written: %ls\n", r->opt.receipt);
        }
    }
    if (r->profile_arrays) { HeapFree(GetProcessHeap(), 0, r->profile_arrays); r->profile_arrays = NULL; }
    if (r->trace) { HeapFree(GetProcessHeap(), 0, r->trace); r->trace = NULL; }
    if (r->tick_log.entries) { HeapFree(GetProcessHeap(), 0, r->tick_log.entries); r->tick_log.entries = NULL; }
    if (r->tick_log.receipt_storage) { HeapFree(GetProcessHeap(), 0, r->tick_log.receipt_storage); r->tick_log.receipt_storage = NULL; }
    if (r->proc) { CloseHandle(r->proc); r->proc = NULL; }
    if (r->exe_file) { CloseHandle(r->exe_file); r->exe_file = NULL; }
    if (r->dll_file) { CloseHandle(r->dll_file); r->dll_file = NULL; }
    return code;
}

/* ------------------------------------------------------------------------------------------------ install & monitor */
static const wchar_t *rc_text(int rc)
{
    return rc == RC_TIMEOUT ? L"timed out (the remote thread may still be running; its memory was not freed)"
           : rc == RC_DIED ? L"the game process exited"
                           : L"CreateRemoteThread failed";
}

static int install_runtime(Run *r)
{
    ReadyScan scan, last;
    uint64_t t0 = now_ms(), stable = 0;
    DWORD err = 0, code = 0;
    int rc;
    FileId pid_id;
    wchar_t proc_path[MAXP];
    DWORD plen = MAXP;
    uint32_t ll_addr = 0, mem = 0;
    SIZE_T plen_bytes, total;
    uint8_t *local = NULL;
    const wchar_t *why;
    RemoteIdent id;
    NameFind nf;
    FileId mod_id;

    memset(&last, 0, sizeof last);
    say(L"Waiting for the game's loader to settle (up to %lu s) ...\n", (unsigned long)r->opt.inject_timeout_s);
    for (;;) {
        DWORD w;
        if (g_stop) { errsay(L"interrupted before the runtime was installed; the game was left running unmodified.\n"); return EXIT_INTERRUPTED; }
        if (!process_alive(r->proc)) {
            GetExitCodeProcess(r->proc, &code);
            r->game_exited = TRUE;
            r->game_exit = code;
            errsay(L"the game exited (code 0x%08lX) before the runtime could be installed. If Steam relaunched the game "
                   L"in a different process, start Steam first and retry.\n", (unsigned long)code);
            return EXIT_LAUNCH;
        }
        if (now_ms() - t0 > (uint64_t)r->opt.inject_timeout_s * 1000u) {
            errsay(L"the game process did not finish loading within %lu s; runtime not installed.\n", (unsigned long)r->opt.inject_timeout_s);
            return EXIT_INSTALL;
        }
        memset(&scan, 0, sizeof scan);
        rc = module_walk(r->pid, ready_cb, &scan, &err);
        if (rc == 0 && scan.has_kernel32 && scan.has_user32) {
            if (scan.count != last.count) { last.count = scan.count; stable = now_ms(); }
            else if (now_ms() - stable >= 500) break;
        } else {
            last.count = 0;
        }
        w = WaitForSingleObject(r->proc, 100);
        (void)w;
    }

    /* Lifetime verification: the process image is the validated file, and the first module is that image. */
    if (!QueryFullProcessImageNameW(r->proc, 0, proc_path, &plen)) { win_fail(L"querying the game's image path", GetLastError()); return EXIT_INSTALL; }
    if (!file_id_path(proc_path, &pid_id) || !same_id(&pid_id, &r->exe_id)) {
        errsay(L"the running process image \"%ls\" is not the validated Napoleon.exe; runtime not installed.\n", proc_path);
        return EXIT_INSTALL;
    }
    if (!file_id_path(scan.main_path, &mod_id) || !same_id(&mod_id, &r->exe_id)) {
        errsay(L"the game's main module \"%ls\" is not the validated Napoleon.exe; runtime not installed.\n", scan.main_path);
        return EXIT_INSTALL;
    }
    why = read_remote_ident(r->proc, scan.main_base, FALSE, &id);
    if (why) { errsay(L"the game's main module at 0x%08lX is not a valid x86 image: %ls.\n", (unsigned long)scan.main_base, why); return EXIT_INSTALL; }
    r->exe_base = scan.main_base;
    say(L"Game pid %lu, main image base 0x%08lX%ls.\n", (unsigned long)r->pid, (unsigned long)r->exe_base,
        r->exe_base == 0x400000u ? L"" : L" (relocated)");

    if (!resolve_remote_loadlibrary(r, &ll_addr)) return EXIT_INSTALL;

    /* One remote page-granular block: [0,40) ntw2_config, [64,...) runtime DLL path. */
    plen_bytes = (wcslen(r->dll_path) + 1) * sizeof(wchar_t);
    total = 64 + plen_bytes;
    mem = (uint32_t)(uintptr_t)VirtualAllocEx(r->proc, NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { win_fail(L"VirtualAllocEx in the game", GetLastError()); return EXIT_INSTALL; }
    local = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!local) { errsay(L"out of memory.\n"); VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE); return EXIT_INSTALL; }

    r->cfg.abi = NTW2_ABI;
    r->cfg.size = sizeof r->cfg;
    r->cfg.enabled_mask = r->opt.mask;
    r->cfg.workers = r->opt.workers;
    r->cfg.image_base = r->exe_base;
    r->cfg.poll_ms = r->opt.poll_ms;
    r->cfg.profile_site = r->opt.profile_site;
    r->cfg.collide_lod_m = r->opt.collide_lod_m | (r->opt.collide_census ? NTW2_COLLIDE_CENSUS : 0u);
    r->cfg.loco_flags = loco_flags_from(&r->opt);
    r->cfg.brain_flags = (r->opt.brain_census ? NTW2_BRAIN_CENSUS : 0u) |
                         (r->opt.brain_timing ? NTW2_BRAIN_TIMING : 0u) |
                         (r->opt.brain_node_shadow ? NTW2_BRAIN_NODE_SHADOW : 0u) |
                         (r->opt.brain_fire_shadow ? NTW2_BRAIN_FIRE_SHADOW : 0u) |
                         (r->opt.brain_finalizer_shadow ? NTW2_BRAIN_FINALIZER_SHADOW : 0u) |
                         (r->opt.brain_parallel ? NTW2_BRAIN_PARALLEL : 0u) |
                         (r->opt.brain_quiet ? NTW2_BRAIN_QUIET : 0u) |
                         (r->opt.brain_unit_shadow ? NTW2_BRAIN_UNIT_SHADOW : 0u);
    r->cfg.collide_flags = (r->opt.collide_contact_shadow ? NTW2_COLLIDE_CONTACT_SHADOW : 0u) |
                           (r->opt.collide_contact_workers ? NTW2_COLLIDE_CONTACT_WORKERS : 0u);
    memcpy(local, &r->cfg, sizeof r->cfg);
    memcpy(local + 64, r->dll_path, plen_bytes);
    {
        SIZE_T wrote = 0;
        if (!WriteProcessMemory(r->proc, (LPVOID)(uintptr_t)mem, local, total, &wrote) || wrote != total) {
            win_fail(L"WriteProcessMemory in the game", GetLastError());
            HeapFree(GetProcessHeap(), 0, local);
            VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
            return EXIT_INSTALL;
        }
    }
    HeapFree(GetProcessHeap(), 0, local);

    say(L"Loading %ls into the game ...\n", r->dll_path);
    rc = remote_call(r, ll_addr, mem + 64, 60000, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(LoadLibraryW)", err);
        else errsay(L"remote LoadLibraryW %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        else if (rc != RC_DIED) VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        if (rc == RC_DIED) { GetExitCodeProcess(r->proc, &code); r->game_exited = TRUE; r->game_exit = code; }
        return EXIT_INSTALL;
    }
    if (code == 0) {
        errsay(L"LoadLibraryW returned NULL inside the game for \"%ls\" (missing dependency, wrong architecture or blocked "
               L"load). The game keeps running unmodified.\n", r->dll_path);
        VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }

    /* The returned HMODULE must be exactly the module with our DLL's file identity, and must match the validated file. */
    nf.name = RUNTIME_DLL_NAME;
    nf.base = nf.size = 0;
    rc = module_walk(r->pid, name_cb, &nf, &err);
    if (rc <= 0 || nf.base != (uint32_t)code || !file_id_path(nf.path, &mod_id) || !file_id_handle(r->dll_file, &pid_id) ||
        !same_id(&mod_id, &pid_id)) {
        errsay(L"the module loaded by LoadLibraryW (0x%08lX) is not the validated runtime DLL; the runtime was NOT started.\n", (unsigned long)code);
        VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    why = verify_remote_runtime(r, nf.base);
    if (why) {
        errsay(L"loaded runtime rejected: %ls. The runtime was NOT started.\n", why);
        VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    r->dll_base = nf.base;
    r->state_addr = r->dll_base + r->dll.state_rva;
    say(L"Runtime loaded at 0x%08lX and verified against the local file.\n", (unsigned long)r->dll_base);

    rc = remote_call(r, r->dll_base + r->dll.start_rva, mem, 30000, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(ntw2_start)", err);
        else errsay(L"ntw2_start %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        else if (rc != RC_DIED) VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        if (rc == RC_DIED) { GetExitCodeProcess(r->proc, &code); r->game_exited = TRUE; r->game_exit = code; }
        return EXIT_INSTALL;
    }
    if (code != 0) {
        errsay(L"ntw2_start rejected the configuration or failed (returned 0x%08lX).\n", (unsigned long)code);
        {
            ntw2_status s;
            const wchar_t *sw;
            if (read_status(r, &s, &sw)) { r->last = s; r->have_status = TRUE; print_status(&s, r->opt.mask); }
        }
        VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);   /* ntw2_start copied the config; thread has returned */
    return EXIT_OK;
}

/* Stop wait policy. A runtime tick in shadow modes can run for tens of seconds, and ntw2_stop only confirms
   NTW2_STOPPED after the tick owner drains, slots are restored, and modules are stopped. The launcher therefore
   waits at least kStopTimeoutMs and keeps waiting up to kStopProgressCapMs while the status still changes. */
enum { kStopTimeoutMs = 15000, kStopProgressCapMs = 60000 };

static BOOL request_stop(Run *r)
{
    DWORD code = 0, err = 0;
    int rc;
    ntw2_status s;
    const wchar_t *why;
    uint64_t t0, last_change;
    BOOL have_prev = FALSE;
    ntw2_status prev;
    say(L"Stopping the runtime (restoring hooks); the game keeps running ...\n");
    rc = remote_call(r, r->dll_base + r->dll.stop_rva, 0, kStopProgressCapMs, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(ntw2_stop)", err);
        else errsay(L"ntw2_stop %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        return FALSE;
    }
    if (code != 0) { errsay(L"ntw2_stop returned 0x%08lX.\n", (unsigned long)code); }
    t0 = last_change = now_ms();
    memset(&prev, 0, sizeof prev);
    for (;;) {
        uint64_t t;
        if (read_status(r, &s, &why)) {
            r->last = s;
            r->have_status = TRUE;
            if (s.phase == NTW2_STOPPED) break;
            if (s.phase == NTW2_FAILED) break;
            if (!have_prev || memcmp(&prev, &s, sizeof s)) { prev = s; have_prev = TRUE; last_change = now_ms(); }
        }
        if (!process_alive(r->proc)) break;
        t = now_ms();
        /* Give up after kStopTimeoutMs without progress, or at the hard cap regardless. */
        if (t - t0 > kStopProgressCapMs || (t - t0 > kStopTimeoutMs && t - last_change > kStopTimeoutMs)) break;
        Sleep(50);
    }
    if (r->have_status) print_status(&r->last, r->opt.mask);
    r->stop_confirmed = code == 0 && r->have_status && r->last.phase == NTW2_STOPPED;
    return r->stop_confirmed;
}

static void observe_status(Run *r, const ntw2_status *s)
{
    if (s->phase == NTW2_ACTIVE) {
        if (!r->active_generations || r->last_active_generation != s->generation) {
            ++r->active_generations;
            r->last_active_generation = s->generation;
        }
        if (r->waiting_after_active) {
            ++r->battle_reactivations;
            r->waiting_after_active = FALSE;
        }
        r->battle_active = TRUE;
        if (r->have_status && r->last.phase == NTW2_ACTIVE &&
            r->last.generation == s->generation && r->last.model == s->model &&
            r->last.root == s->root && s->tick >= r->last.tick)
            r->battle_tick_advance += s->tick - r->last.tick;
    } else if (s->phase == NTW2_WAITING_BATTLE && r->battle_active) {
        ++r->battle_returns;
        r->battle_active = FALSE;
        r->waiting_after_active = TRUE;
    }
    if (s->workers > r->peak_workers) r->peak_workers = s->workers;
    if (s->storage_bytes > r->peak_storage_bytes) r->peak_storage_bytes = s->storage_bytes;
    if (s->retained_bytes > r->peak_retained_bytes) r->peak_retained_bytes = s->retained_bytes;
    ++r->status_samples;
    observe_crash(r, s);
    r->last = *s;
    r->have_status = TRUE;
}

static BOOL CALLBACK close_game_window(HWND window, LPARAM param)
{
    Run *r = (Run *)param;
    DWORD pid = 0;
    /* A signaled retained handle also prevents targeting a recycled process ID. */
    if (WaitForSingleObject(r->proc, 0) != WAIT_TIMEOUT) return FALSE;
    GetWindowThreadProcessId(window, &pid);
    if (pid == r->pid && PostMessageW(window, WM_CLOSE, 0, 0))
        ++r->game_close_windows;
    return TRUE;
}

static BOOL close_observed_game(Run *r)
{
    DWORD wait;
    r->game_close_requested = TRUE;
    if (!r->proc || !r->pid) {
        r->game_stop_error = ERROR_INVALID_HANDLE;
        return FALSE;
    }
    wait = WaitForSingleObject(r->proc, 0);
    if (wait == WAIT_TIMEOUT) {
        say(L"Closing only the launched game (pid %lu); allowing 10 s for WM_CLOSE.\n", (unsigned long)r->pid);
        EnumWindows(close_game_window, (LPARAM)r);
        wait = WaitForSingleObject(r->proc, 10000);
        if (wait == WAIT_TIMEOUT) {
            if (!TerminateProcess(r->proc, ERROR_TIMEOUT)) {
                DWORD error = GetLastError();
                if (WaitForSingleObject(r->proc, 0) != WAIT_OBJECT_0) {
                    r->game_stop_error = error;
                    win_fail(L"terminating the launched game", error);
                    return FALSE;
                }
            } else {
                r->game_terminated = TRUE;
            }
            wait = WaitForSingleObject(r->proc, 5000);
        }
    }
    if (wait != WAIT_OBJECT_0) {
        r->game_stop_error = wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
        win_fail(L"waiting for the launched game to exit", r->game_stop_error);
        return FALSE;
    }
    r->game_exited = TRUE;
    if (!GetExitCodeProcess(r->proc, &r->game_exit)) {
        r->game_stop_error = GetLastError();
        return FALSE;
    }
    return TRUE;
}

/* Unattended shutdown of our own game: the runtime must be confirmed STOPPED before WM_CLOSE, because the game's
   WinMain teardown would otherwise destroy engine objects under a still-running tick. If the stop cannot be
   confirmed, no WM_CLOSE is posted; only the launched process (retained handle) is terminated. */
static BOOL stop_then_close_game(Run *r)
{
    if (!r->stop_confirmed && r->proc && process_alive(r->proc)) {
        request_stop(r);
        r->stop_requested = TRUE;
    }
    if (r->stop_confirmed || !r->proc || !process_alive(r->proc)) return close_observed_game(r);
    r->game_close_requested = TRUE;
    errsay(L"runtime stop was not confirmed; NOT sending WM_CLOSE into a live runtime. Terminating only the launched game (pid %lu).\n",
           (unsigned long)r->pid);
    if (TerminateProcess(r->proc, ERROR_TIMEOUT)) r->game_terminated = TRUE;
    else r->game_stop_error = GetLastError();
    if (WaitForSingleObject(r->proc, 5000) == WAIT_OBJECT_0) {
        r->game_exited = TRUE;
        GetExitCodeProcess(r->proc, &r->game_exit);
    } else if (!r->game_stop_error) {
        r->game_stop_error = ERROR_TIMEOUT;
    }
    return FALSE;
}

static int monitor(Run *r)
{
    uint64_t t0 = now_ms(), last_stats = t0, last_receipt = 0, last_profile = 0, first_ok_deadline = t0 + 15000;
    uint64_t last_trace = 0;
    BOOL have_prev = FALSE;
    uint32_t prev_phase = 0, prev_active = 0, prev_gen = 0, prev_err = 0;
    unsigned bad = 0;
    const wchar_t *why = L"";
    wchar_t rq[192];

    r->trace = (TickTrace *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *r->trace);
    if (!r->trace) {
        errsay(L"unable to allocate the tick trace capture buffers.\n");
        return EXIT_RECEIPT;
    }
    r->outcome = L"observing";
    mask_str(r->opt.mask, rq, 192);
    say(L"Runtime started (workers=%lu, requested=[%ls]). Monitoring until the game exits%ls.\n", (unsigned long)r->opt.workers, rq,
        r->opt.observe_s ? L" or the observation bound elapses" : L" (Ctrl+C stops the runtime, not the game)");
    for (;;) {
        ntw2_status s;
        DWORD w;
        r->observed_ms = now_ms() - t0;
        if ((r->opt.mask & (NTW2_PROFILE | NTW2_GRID_CENSUS | NTW2_AI_CENSUS)) && (!last_profile || now_ms() - last_profile >= 1000)) {
            read_profile(r);
            last_profile = now_ms();
        }
        if (r->active_generations && (r->opt.tick_log[0] || !last_trace || now_ms() - last_trace >= 1000)) {
            read_trace(r);
            last_trace = now_ms();
        }
        if (r->tick_log.failed) return EXIT_RECEIPT;
        if (r->opt.receipt[0] && (!last_receipt || now_ms() - last_receipt >= 1000)) {
            if (!write_receipt(r, -1)) return EXIT_RECEIPT;
            last_receipt = now_ms();
        }
        if (g_stop) {
            BOOL profile_ok, ok;
            finalize_trace(r);
            if (!read_profile(r)) say(L"Final profile read unavailable; using the last complete periodic copy if retained.\n");
            profile_ok = write_profile(r);
            ok = request_stop(r);
            r->stop_requested = TRUE;
            say(ok ? L"Runtime stopped cleanly. Game left running (pid %lu).\n" : L"Runtime stop did not complete cleanly. Game left running (pid %lu).\n", (unsigned long)r->pid);
            return !ok ? EXIT_STOP_FAILED : (!profile_ok ? EXIT_RECEIPT : EXIT_INTERRUPTED);
        }
        if (r->opt.observe_s && now_ms() - t0 >= (uint64_t)r->opt.observe_s * 1000u) {
            BOOL profile_ok;
            finalize_trace(r);
            r->observation_complete = TRUE;
            say(L"Observation bound (%lu s) reached (game pid %lu).\n",
                (unsigned long)r->opt.observe_s, (unsigned long)r->pid);
            if (r->have_status) { print_status(&r->last, r->opt.mask); print_counters(&r->last); print_module_words(&r->last); }
            if (!read_profile(r)) say(L"Final profile read unavailable; using the last complete periodic copy if retained.\n");
            profile_ok = write_profile(r);
            if (r->opt.exit_game_after_observe) {
                if (!stop_then_close_game(r)) return EXIT_GAME_STOP_FAILED;
            } else {
                say(L"Game and runtime are left running, unchanged.\n");
            }
            return !profile_ok ? EXIT_RECEIPT : (r->ever_full ? EXIT_OK : EXIT_NOT_ACTIVE);
        }
        w = WaitForSingleObject(r->proc, r->opt.tick_log[0] ? 10 : 200);
        if (w == WAIT_OBJECT_0) {
            GetExitCodeProcess(r->proc, &r->game_exit);
            r->game_exited = TRUE;
            say(L"Game exited with code 0x%08lX.\n", (unsigned long)r->game_exit);
            if (r->have_status) { print_status(&r->last, r->opt.mask); print_crash(&r->last); }
            if (r->game_exit != 0) say(L"  (non-zero exit: the runtime state above is the last snapshot taken before exit)\n");
            if (r->opt.mask & (NTW2_PROFILE | NTW2_GRID_CENSUS | NTW2_AI_CENSUS))
                say(L"Game exited before final capture; using the last periodic profile snapshot (normally <=1.2 s old).\n");
            if (r->active_generations)
                say(L"Game exited before final tick capture; using the last complete periodic tick trace.\n");
            if (!write_profile(r)) return EXIT_RECEIPT;
            return r->ever_full ? EXIT_OK : EXIT_NOT_ACTIVE;
        }
        if (!read_status(r, &s, &why)) {
            ++bad;
            if (!r->have_status && now_ms() > first_ok_deadline) {
                errsay(L"no valid runtime status within 15 s of ntw2_start: %ls.\n", why);
                return EXIT_INSTALL;
            }
            if (r->have_status && bad >= 50) {
                errsay(L"runtime status unreadable for %u consecutive polls: %ls.\n", bad, why);
                return EXIT_RUNTIME_FAILED;
            }
            continue;
        }
        bad = 0;
        observe_status(r, &s);
        if (s.phase == NTW2_WAITING_BATTLE || s.phase == NTW2_ACTIVATING || s.phase == NTW2_ACTIVE) r->ever_armed = TRUE;
        if (!have_prev || s.phase != prev_phase || s.active_mask != prev_active || s.generation != prev_gen || s.error != prev_err) {
            have_prev = TRUE;
            prev_phase = s.phase;
            prev_active = s.active_mask;
            prev_gen = s.generation;
            prev_err = s.error;
            switch (s.phase) {
            case NTW2_VERIFYING: say(L"Runtime verifying the live image ...\n"); break;
            case NTW2_WAITING_BATTLE: say(L"Runtime ARMED: waiting for a battle. NOT active yet.\n"); break;
            case NTW2_ACTIVATING: say(L"Runtime activating ...\n"); break;
            case NTW2_ACTIVE:
                if ((s.active_mask & r->opt.mask) == r->opt.mask) {
                    r->ever_full = TRUE;
                    say(L"Runtime ACTIVE: every requested feature is active.\n");
                } else {
                    if(s.memory_words[NTW2_MEM_BUDGET_DISABLED_MASK])
                        say(L"Runtime ACTIVE with VA-budget fallback: LOCO/COLLIDE use originals; budget_refusals=%lu; other features continue.\n",
                            (unsigned long)s.memory_words[NTW2_MEM_BUDGET_REFUSALS]);
                    else say(L"Runtime ACTIVE but PARTIAL: not every requested feature is active.\n");
                }
                break;
            case NTW2_RESTORING: say(L"Runtime restoring original code ...\n"); break;
            case NTW2_FAILED: errsay(L"runtime reported FAILED.\n"); break;
            case NTW2_STOPPED: say(L"Runtime STOPPED.\n"); break;
            default: break;
            }
            print_status(&s, r->opt.mask);
            last_stats = now_ms();
        } else if (s.phase == NTW2_ACTIVE && now_ms() - last_stats >= 15000) {
            print_counters(&s);
            last_stats = now_ms();
        }
        if (s.phase == NTW2_FAILED) {
            errsay(L"runtime failure: error=0x%08lX detail=0x%08lX. Requesting stop so original code is restored.\n",
                   (unsigned long)s.error, (unsigned long)s.error_detail);
            write_profile(r);
            request_stop(r);
            r->stop_requested = TRUE;
            return EXIT_RUNTIME_FAILED;
        }
        if (s.phase == NTW2_STOPPED) {
            errsay(L"runtime stopped without a launcher request.\n");
            write_profile(r);
            return EXIT_RUNTIME_FAILED;
        }
    }
}

/* ------------------------------------------------------------------------------------------------ launch */
static BOOL napoleon_running(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    BOOL any = FALSE;
    if (snap == INVALID_HANDLE_VALUE) {
        win_fail(L"enumerating processes", GetLastError());
        return TRUE;   /* cannot prove there is no conflicting instance */
    }
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, GAME_EXE_NAME) == 0) {
                wchar_t path[MAXP];
                DWORD n = MAXP;
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                path[0] = 0;
                if (p) {
                    if (!QueryFullProcessImageNameW(p, 0, path, &n)) path[0] = 0;
                    CloseHandle(p);
                }
                errsay(L"Napoleon.exe is already running (pid %lu, %ls). Close it first; this launcher never terminates processes it did not start.\n",
                       (unsigned long)pe.th32ProcessID, path[0] ? path : L"image path not accessible");
                any = TRUE;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return any;
}

static BOOL launch_game(Run *r)
{
    static wchar_t cmd[32768];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    FILETIME ex, kt, ut;
    int n;

    if (r->opt.replay[0])
        n = _snwprintf_s(cmd, 32768, _TRUNCATE, L"\"%ls\" game_startup_mode replay \"%ls\"", r->exe_path, r->opt.replay);
    else
        n = _snwprintf_s(cmd, 32768, _TRUNCATE, L"\"%ls\"", r->exe_path);
    if (n < 0) { errsay(L"the game command line is too long.\n"); return FALSE; }
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!r->opt.focus) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNOACTIVATE;
    }
    memset(&pi, 0, sizeof pi);
    say(L"Launching: %ls\n  working directory: %ls\n", cmd, r->game_dir);
    if (!CreateProcessW(r->exe_path, cmd, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, r->game_dir, &si, &pi)) {
        DWORD e = GetLastError();
        if (e == ERROR_ELEVATION_REQUIRED)
            errsay(L"Windows says Napoleon.exe requires elevation. Run ntw2.exe from an elevated prompt (nothing was started).\n");
        else win_fail(L"CreateProcessW(Napoleon.exe)", e);
        return FALSE;
    }
    CloseHandle(pi.hThread);
    r->proc = pi.hProcess;
    r->pid = pi.dwProcessId;
    r->cfg.main_thread_id = pi.dwThreadId;
    GetProcessTimes(r->proc, &r->created, &ex, &kt, &ut);   /* creation time recorded for the receipt */
    say(L"Game started (pid %lu).\n", (unsigned long)r->pid);
    return TRUE;
}

/* ------------------------------------------------------------------------------------------------ command line */
static void usage(void)
{
    say(L"ntw2 - Napoleon Total War native multithreading launcher\n\n"
        L"usage: ntw2.exe [--game DIR] [options]\n"
        L"  --game DIR            folder containing Napoleon.exe (prompted when omitted)\n"
        L"  --replay FILE         start the game on a replay (game_startup_mode replay \"FILE\")\n"
        L"  --features LIST       all (default) or comma list of path,formation,ballistics,ai,ai_ctrl,batch64,brain2,visual,collide,collide_lod,loco,profile,brain,grid_census,ai_census,ai_async2\n"
        L"                        all = batch64,ai,visual (the shipping set); every other feature is an explicit opt-in, e.g. all,profile\n"
        L"                        ai_ctrl = experimental controller offload (not in all); requires ai\n"
        L"                        ai_census = opt-in observation of AI planner mutators (vtable-slot gates, one clone-call gate, EIP ranges); requires ai (not in all)\n"
        L"                        ai_async2 = experimental: site 34 queues the planner; the AI worker runs it between ticks on private clones;\n"
        L"                        the next tick start never blocks (a still-running think is a counted divergence point); writers join\n"
        L"                        (site 33, quadtree update, delegate slots; 5 s watchdog -> synchronous fallback); requires ai, excludes ai_ctrl/ai_census\n"
        L"                        collide = Phase B opt-in soft-collision solver (not in all); overrides the PROFILE collision census\n"
        L"                        collide_lod = half-rate far-unit queries (not in all); cannot combine with collide or formation\n"
        L"                        (~200 all-thread rounds/s, <=10%% measured duty)\n"
        L"                        brain (needs profile) publishes the 23 vtable slots +0x0C as timed entries and prints/records the\n"
        L"                        per-callee 'brain sites' table of the per-agent brain step, per class family\n"
        L"                        brain2 v2 observes native per-soldier steps on the owner in exact worklist order; --brain-parallel adds the guarded worker path\n"
        L"  --brain-census        requires brain2: run serial gated clones; count active/inactive/unknown services (QPC stays off)\n"
        L"  --brain-timing        requires brain2: opt-in QPC for original/serial-clone comparison; independent of census\n"
        L"  --brain-node-shadow   requires brain2: compare owned reference node and private projection on owner; never install fake nodes\n"
        L"  --brain-fire-shadow   requires brain2: compare request-sequencer supported paths on owner; unresolved services stay owner\n"
        L"  --brain-finalizer-shadow requires brain2: rerun each proved 0x819770 finalizer call on a private soldier copy on the\n"
        L"                        owner and compare it byte for byte with the live call (site6 witness finalizer_* words)\n"
        L"  --brain-parallel      requires brain2, --brain-census or --brain-quiet: run the per-soldier brain step on pool workers over\n"
        L"                        private receiver copies; the owner validates, publishes and replays in worklist order; refused/stale\n"
        L"                        soldiers run serially. shadow modes imply serial gated census; none enables workers or duplicates events\n"
        L"  --brain-quiet         requires --brain-parallel; excludes --brain-census/--brain-timing/shadows: performance mode. Owner-run\n"
        L"                        soldiers execute the original step (no gated census clone, no per-service bookkeeping or QPC); guard\n"
        L"                        misses counted without block checksums; phase telemetry in brain_worker_phase_words\n"
        L"                        visual shards main-thread 0x779E60 loop 1, independently of tick epochs\n"
        L"                        ai runs one whole native planner call on its event worker and joins before site 34 returns;\n"
        L"                        no cross-tick parking or partial-call replay; long native calls still delay the tick\n"
        L"  --brain-unit-shadow   requires brain2; excludes --brain-parallel/--brain-quiet: per-unit brain Stage A, shadow only. Before\n"
        L"                        the unchanged site-6 loop pool workers decide every unit from unit-level inputs; after each\n"
        L"                        soldier's native step its decided fields are compared with its unit's decision (brain_unit_words)\n"
        L"  --collide-contact-shadow  requires collide: contact callbacks are planned on pool workers from stage-entry state and each\n"
        L"                        plan is compared with the original callback the owner still runs (collide.contact)\n"
        L"  --collide-contact-workers requires collide; excludes the shadow: same-team contact decisions on pool workers, owner replays\n"
        L"                        tracker/+0x13C/avoidance effects in contact order; other contacts run the original callback in place\n"
        L"  --ai-ctrl             experimental controller offload with immediate join (same as ai_ctrl; default off; requires ai)\n"
        L"                        loco = experimental locomotion Stages A/B/C (not in all); optional owned grid v2 published at site-13 exit;\n"
        L"                        cannot combine with brain or collide_lod; brain2 v2 can coexist; collide requires --loco-clone --loco-parallel --loco-owned-services and grid\n"
        L"  --loco-clone          loco only: execute admitted movement occurrences through the private clone family (default: observe only, original code)\n"
        L"  --loco-parallel       requires loco and --loco-clone: closed direct-selector movement workers; native services/publication stay owner-only\n"
        L"  --loco-owned-services requires loco, --loco-clone and --loco-parallel: opt-in supported active mover path (owner-prepared sweep/resolve/environment services); unsupported occurrences fall back to the owner\n"
        L"  --loco-quiet          requires --loco-owned-services: low-overhead mode; disables per-service QPC timing, shadow comparisons (even with --loco-shadow) and the all-gates histogram; faults/share/detail counters stay\n"
        L"  --loco-shadow         requires loco and --loco-clone: compare owner-thread sweep/resolve ports, retaining original outputs (ignored under --loco-quiet)\n"
        L"  --loco-grid           requires loco: publish owned soldier grid v2 at site-13 exit (default off); combined collide borrows it without rebuilding\n"
        L"  --loco-grid-verify    requires loco: implies --loco-grid and enables owner-side grid verification\n"
        L"  --grid-probation      requires loco + --loco-grid (not ballistic): native cell-head array PAGE_NOACCESS outside the\n"
        L"                        owner's site-13 relink window; every trapping reader is logged (EIP/caller/thread/site),\n"
        L"                        its page restored and resumed (grid_probation_words, receipt loco.grid_probation)\n"
        L"  --grid-census         requires loco: opt-in soldier soft-grid reader census (default off; profile not required)\n"
        L"                        private-clone route calls and proven native reader entries per routed tick; occupancy is separate\n"
        L"                        must be selected before the process first builds resident runtime clones\n"
        L"  --army-unit-shadow    requires profile or a simulation feature: item 4 Stage A instrumentation of the army per-unit\n"
        L"                        update (sites 18/101/103): per-unit 0x581F30 cost, owner-only reasons, RNG draws, foreign-unit\n"
        L"                        witness, command classes and projected site-18 time (army_unit_words, receipt army_unit);\n"
        L"                        add ai,ai_census to measure planner writes\n"
        L"  --workers N           worker threads 1..8 (default 4)\n"
        L"  --poll-ms N           runtime monitor poll interval 10..1000 (default 100)\n"
        L"  --profile-site N      with profile or grid-census: restrict sampling to timed site N (see trace sites)\n"
        L"  --collide-lod-m N      far-unit surface separation in world metres, 1..100000 (default 40)\n"
        L"  --collide-census      with profile: enable costly per-pair collision timers (default off; site 5 always timed)\n"
        L"  --observe-seconds N   stop monitoring after N seconds (default: until exit)\n"
        L"  --exit-game-after-observe  after the bound, stop the runtime (confirmed STOPPED, up to 60 s while it\n"
        L"                        progresses), then close ONLY this launch (WM_CLOSE, kill after 10 s); if the stop\n"
        L"                        is not confirmed, no WM_CLOSE is sent: the launched game is terminated (exit 11)\n"
        L"  --inject-timeout N    seconds to wait for the game loader (default 120)\n"
        L"  --receipt FILE        JSON status every second and final outcome (atomic replace)\n"
        L"                        profile or grid-census also writes FILE.profile.bin at observation end (before exit/stop)\n"
        L"  --tick-log FILE       retain every observed tick (10 ms launcher polls, maximum 200000 entries)\n"
        L"                        write NTW2TLOG binary at observation end; receipt includes summary and loss count\n"
        L"  --no-activate         launch the game without installing the runtime\n"
        L"  --validate-only       validate Napoleon.exe and the runtime DLL, start nothing\n"
        L"  --focus               allow normal game-window activation (default: no activation requested)\n"
        L"  --no-focus            explicitly keep the default nonactivating startup (best effort)\n"
        L"  --help\n\n"
        L"exit codes: 0 active/ok, 1 usage, 2 unsupported game/runtime, 3 game already running, 4 launch failed,\n"
        L"  5 install failed, 6 runtime failed, 7 armed but never fully active, 8 interrupted (runtime stopped),\n"
        L"  9 runtime stop failed, 10 receipt write failed, 11 launched game shutdown failed\n");
}

static BOOL parse_uint(const wchar_t *s, uint32_t lo, uint32_t hi, uint32_t *out)
{
    wchar_t *end;
    unsigned long v;
    if (!*s) return FALSE;
    v = wcstoul(s, &end, 10);
    if (*end || v < lo || v > hi) return FALSE;
    *out = (uint32_t)v;
    return TRUE;
}

static BOOL parse_features(const wchar_t *s, uint32_t *mask)
{
    wchar_t buf[256], *tok, *next;
    uint32_t m = 0;
    if (!*s || wcslen(s) >= 256) {
        errsay(L"--features needs a nonempty list shorter than 256 characters.\n");
        return FALSE;
    }
    wcscpy_s(buf, 256, s);
    for (tok = buf; tok; tok = next) {
        size_t i;
        uint32_t bit = 0;
        next = wcschr(tok, L',');
        if (next) *next++ = 0;
        if (!*tok) {
            errsay(L"--features contains an empty item (leading, trailing, or repeated comma).\n");
            return FALSE;
        }
        if (_wcsicmp(tok, L"all") == 0) bit = NTW2_ALL;
        for (i = 0; i < NFEATURES; ++i)
            if (_wcsicmp(tok, k_features[i].name) == 0) { bit = k_features[i].bit; break; }
        if (!bit) {
            errsay(L"unknown --features item \"%ls\"; use all,path,formation,ballistics,ai,ai_ctrl,batch64,brain2,visual,collide,collide_lod,loco,profile,brain,grid_census,ai_census,ai_async2,army_unit_shadow.\n", tok);
            return FALSE;
        }
        if (m & bit) {
            errsay(L"duplicate --features item \"%ls\".\n", tok);
            return FALSE;
        }
        m |= bit;
    }
    *mask = m;
    return TRUE;
}

/* Returns 0 ok, 1 help, -1 error. */
static int parse_args(int argc, wchar_t **argv, Options *o)
{
    int i;
    uint32_t feature_options = 0;
    o->mask = NTW2_ALL;
    o->workers = 4;
    o->poll_ms = 100;
    o->collide_lod_m = 40;
    o->inject_timeout_s = 120;
    o->activate = TRUE;
    for (i = 1; i < argc; ++i) {
        wchar_t *a = argv[i], *eq = wcschr(a, L'='), *val = NULL;
        wchar_t name[64];
        size_t nl;
        if (wcsncmp(a, L"--", 2) != 0) { errsay(L"unexpected argument \"%ls\".\n", a); return -1; }
        nl = eq ? (size_t)(eq - a) : wcslen(a);
        if (nl >= 64) { errsay(L"unknown option \"%ls\".\n", a); return -1; }
        wmemcpy(name, a, nl);
        name[nl] = 0;
        if (eq) val = eq + 1;
#define NEEDVAL() do { if (!val) { if (i + 1 >= argc) { errsay(L"%ls needs a value.\n", name); return -1; } val = argv[++i]; } } while (0)
        if (!wcscmp(name, L"--help") || !wcscmp(name, L"-h")) return 1;
        else if (!wcscmp(name, L"--no-activate")) o->activate = FALSE;
        else if (!wcscmp(name, L"--collide-census")) o->collide_census = TRUE;
        else if (!wcscmp(name, L"--grid-census")) feature_options |= NTW2_GRID_CENSUS;
        else if (!wcscmp(name, L"--army-unit-shadow")) feature_options |= NTW2_ARMY_UNIT_SHADOW;
        else if (!wcscmp(name, L"--loco-clone")) o->loco_clone = TRUE;
        else if (!wcscmp(name, L"--loco-parallel")) o->loco_parallel = TRUE;
        else if (!wcscmp(name, L"--loco-owned-services")) o->loco_owned = TRUE;
        else if (!wcscmp(name, L"--brain-census")) o->brain_census = TRUE;
        else if (!wcscmp(name, L"--brain-timing")) o->brain_timing = TRUE;
        else if (!wcscmp(name, L"--brain-node-shadow")) o->brain_node_shadow = TRUE;
        else if (!wcscmp(name, L"--brain-fire-shadow")) o->brain_fire_shadow = TRUE;
        else if (!wcscmp(name, L"--brain-finalizer-shadow")) o->brain_finalizer_shadow = TRUE;
        else if (!wcscmp(name, L"--brain-parallel")) o->brain_parallel = TRUE;
        else if (!wcscmp(name, L"--brain-quiet")) o->brain_quiet = TRUE;
        else if (!wcscmp(name, L"--brain-unit-shadow")) o->brain_unit_shadow = TRUE;
        else if (!wcscmp(name, L"--collide-contact-shadow")) o->collide_contact_shadow = TRUE;
        else if (!wcscmp(name, L"--collide-contact-workers")) o->collide_contact_workers = TRUE;
        else if (!wcscmp(name, L"--loco-quiet")) o->loco_quiet = TRUE;
        else if (!wcscmp(name, L"--loco-grid")) o->loco_grid = TRUE;
        else if (!wcscmp(name, L"--loco-grid-verify")) { o->loco_grid_verify = TRUE; o->loco_grid = TRUE; }
        else if (!wcscmp(name, L"--grid-probation")) o->grid_probation = TRUE;
        else if (!wcscmp(name, L"--loco-shadow")) o->loco_shadow = TRUE;
        else if (!wcscmp(name, L"--ai-ctrl")) feature_options |= NTW2_AI_CTRL;
        else if (!wcscmp(name, L"--validate-only")) o->validate_only = TRUE;
        else if (!wcscmp(name, L"--no-focus")) o->focus = FALSE;
        else if (!wcscmp(name, L"--focus")) o->focus = TRUE;
        else if (!wcscmp(name, L"--exit-game-after-observe")) o->exit_game_after_observe = TRUE;
        else if (!wcscmp(name, L"--game")) { NEEDVAL(); wcsncpy_s(o->game, MAXP, val, _TRUNCATE); }
        else if (!wcscmp(name, L"--replay")) { NEEDVAL(); wcsncpy_s(o->replay, MAXP, val, _TRUNCATE); }
        else if (!wcscmp(name, L"--receipt")) { NEEDVAL(); wcsncpy_s(o->receipt, MAXP, val, _TRUNCATE); }
        else if (!wcscmp(name, L"--tick-log")) {
            NEEDVAL();
            if (!val[0] || wcslen(val) >= MAXP) { errsay(L"--tick-log needs a nonempty path shorter than MAXP.\n"); return -1; }
            wcscpy_s(o->tick_log, MAXP, val);
        }
        else if (!wcscmp(name, L"--features")) {
            NEEDVAL();
            if (!parse_features(val, &o->mask)) return -1;
        } else if (!wcscmp(name, L"--workers")) {
            NEEDVAL();
            if (!parse_uint(val, 1, 8, &o->workers)) { errsay(L"--workers must be 1..8.\n"); return -1; }
        } else if (!wcscmp(name, L"--poll-ms")) {
            NEEDVAL();
            if (!parse_uint(val, 10, 1000, &o->poll_ms)) { errsay(L"--poll-ms must be 10..1000.\n"); return -1; }
        } else if (!wcscmp(name, L"--collide-lod-m")) {
            NEEDVAL();
            if (!parse_uint(val, 1, 100000, &o->collide_lod_m)) { errsay(L"--collide-lod-m must be 1..100000.\n"); return -1; }
        } else if (!wcscmp(name, L"--profile-site")) {
            uint32_t site;
            NEEDVAL();
            if (!parse_uint(val, 0, NTW2_TIMED_SITES - 1, &site)) { errsay(L"--profile-site must be 0..%u.\n", NTW2_TIMED_SITES - 1); return -1; }
            o->profile_site = site + 1;
        } else if (!wcscmp(name, L"--observe-seconds")) {
            NEEDVAL();
            if (!parse_uint(val, 0, 86400 * 7, &o->observe_s)) { errsay(L"--observe-seconds must be 0..604800.\n"); return -1; }
        } else if (!wcscmp(name, L"--inject-timeout")) {
            NEEDVAL();
            if (!parse_uint(val, 5, 3600, &o->inject_timeout_s)) { errsay(L"--inject-timeout must be 5..3600.\n"); return -1; }
        } else {
            errsay(L"unknown option \"%ls\".\n", name);
            return -1;
        }
#undef NEEDVAL
    }
    o->mask |= feature_options; /* independent of the position of --features */
    if ((o->mask & NTW2_GRID_CENSUS) && !(o->mask & NTW2_LOCO)) {
        errsay(L"--grid-census (grid_census) requires --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if ((o->mask & NTW2_AI_CENSUS) && !(o->mask & NTW2_AI_ASYNC)) {
        errsay(L"ai_census requires --features ai (or a feature list containing ai).\n");
        return -1;
    }
    if ((o->mask & NTW2_ARMY_UNIT_SHADOW) &&
        !(o->mask & (NTW2_PROFILE | NTW2_PATH | NTW2_FORMATION | NTW2_BALLISTICS | NTW2_AI_ASYNC | NTW2_BRAIN2 |
                     NTW2_COLLIDE | NTW2_COLLIDE_LOD | NTW2_LOCO))) {
        errsay(L"--army-unit-shadow needs a routed tick: add profile or a simulation feature (e.g. --features ai,profile).\n");
        return -1;
    }
    if ((o->mask & NTW2_AI_ASYNC2) && (!(o->mask & NTW2_AI_ASYNC) || (o->mask & (NTW2_AI_CTRL | NTW2_AI_CENSUS)))) {
        errsay(L"ai_async2 requires --features ai and excludes ai_ctrl and ai_census (shared worker, site 33 and slots).\n");
        return -1;
    }
    if ((o->mask & NTW2_BRAIN) && !(o->mask & NTW2_PROFILE)) {
        errsay(L"--features brain requires profile (brain sites exist only inside the profiling epoch).\n");
        return -1;
    }
    if ((o->mask & NTW2_AI_CTRL) && !(o->mask & NTW2_AI_ASYNC)) {
        errsay(L"Controller offload (ai_ctrl) requires --features ai (or a list containing ai).\n");
        return -1;
    }
    if (o->collide_census && !(o->mask & NTW2_PROFILE)) {
        errsay(L"--collide-census requires --features profile (or a feature list containing profile).\n");
        return -1;
    }
    if ((o->mask & NTW2_COLLIDE_LOD) && (o->mask & (NTW2_COLLIDE | NTW2_FORMATION))) {
        errsay(L"collide_lod cannot combine with collide or formation; its original-query gate requires the private manager.\n");
        return -1;
    }
    if ((o->collide_contact_shadow || o->collide_contact_workers) && !(o->mask & NTW2_COLLIDE)) {
        errsay(L"--collide-contact-shadow and --collide-contact-workers require --features collide.\n");
        return -1;
    }
    if (o->collide_contact_shadow && o->collide_contact_workers) {
        errsay(L"--collide-contact-shadow and --collide-contact-workers are exclusive.\n");
        return -1;
    }
    if ((o->brain_census || o->brain_timing || o->brain_node_shadow || o->brain_fire_shadow || o->brain_finalizer_shadow ||
         o->brain_parallel || o->brain_quiet || o->brain_unit_shadow) && !(o->mask & NTW2_BRAIN2)) {
        errsay(L"--brain-census, --brain-timing, --brain-parallel, --brain-quiet, --brain-unit-shadow and brain shadow options require --features brain2.\n");
        return -1;
    }
    if (o->brain_parallel && ((!o->brain_census && !o->brain_quiet) || o->workers == 0)) {
        errsay(L"--brain-parallel requires --brain-census or --brain-quiet and at least one worker (--workers).\n");
        return -1;
    }
    if (o->brain_quiet && (!o->brain_parallel || o->brain_census || o->brain_timing || o->brain_node_shadow ||
                           o->brain_fire_shadow || o->brain_finalizer_shadow)) {
        errsay(L"--brain-quiet requires --brain-parallel and excludes --brain-census, --brain-timing and the brain shadow options.\n");
        return -1;
    }
    if (o->brain_unit_shadow && (o->brain_parallel || o->brain_quiet)) {
        errsay(L"--brain-unit-shadow observes the serial site-6 loop and excludes --brain-parallel and --brain-quiet.\n");
        return -1;
    }
    if ((o->mask & NTW2_LOCO) && (o->mask & (NTW2_BRAIN | NTW2_COLLIDE_LOD))) {
        errsay(L"loco cannot combine with brain or collide_lod.\n");
        return -1;
    }
    if ((o->mask & (NTW2_LOCO | NTW2_COLLIDE)) == (NTW2_LOCO | NTW2_COLLIDE) &&
        (!o->loco_clone || !o->loco_parallel || !o->loco_owned || !(o->loco_grid || o->loco_grid_verify))) {
        errsay(L"loco+collide requires --loco-clone, --loco-parallel, --loco-owned-services and --loco-grid (or --loco-grid-verify).\n");
        return -1;
    }
    if (o->loco_clone && !(o->mask & NTW2_LOCO)) {
        errsay(L"--loco-clone requires --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if (o->loco_parallel && (!(o->mask & NTW2_LOCO) || !o->loco_clone)) {
        errsay(L"--loco-parallel requires --features loco (or a feature list containing loco) and --loco-clone.\n");
        return -1;
    }
    if (o->loco_shadow && (!(o->mask & NTW2_LOCO) || !o->loco_clone)) {
        errsay(L"--loco-shadow requires --features loco and --loco-clone.\n");
        return -1;
    }
    if (o->loco_owned && (!(o->mask & NTW2_LOCO) || !o->loco_clone || !o->loco_parallel)) {
        errsay(L"--loco-owned-services requires --features loco (or a feature list containing loco), --loco-clone and --loco-parallel.\n");
        return -1;
    }
    if (o->loco_quiet && (!(o->mask & NTW2_LOCO) || !o->loco_clone || !o->loco_parallel || !o->loco_owned)) {
        errsay(L"--loco-quiet requires --features loco, --loco-clone, --loco-parallel and --loco-owned-services.\n");
        return -1;
    }
    if ((o->loco_grid || o->loco_grid_verify) && !(o->mask & NTW2_LOCO)) {
        errsay(L"--loco-grid and --loco-grid-verify require --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if (o->grid_probation && (!(o->mask & NTW2_LOCO) || !o->loco_grid || (o->mask & NTW2_BALLISTICS))) {
        errsay(L"--grid-probation requires --features loco with --loco-grid (or --loco-grid-verify) and is refused with ballistic "
               L"(its query cache walks the native cell heads itself).\n");
        return -1;
    }
    if ((o->mask & NTW2_LOCO) && (o->mask & NTW2_FORMATION))
        say(L"note: loco stays inert while formation is enabled (the original manager bypasses the ACTIVE clone); omit formation to run it.\n");
    if ((o->mask & NTW2_BRAIN2) && (o->mask & NTW2_FORMATION))
        say(L"note: brain2 stays inert while formation is enabled (the formation module runs the original army manager, so the per-entity "
            L"loop is not reached through the private clones); omit formation to run it.\n");
    if ((o->mask & NTW2_BRAIN2) && (o->mask & NTW2_BRAIN))
        say(L"note: brain2 runs the private clones, so the brain profiling entry slots are not published (brain sites stay empty); "
            L"the brain2 counters measure the loop instead.\n");
    if ((o->mask & NTW2_COLLIDE) && (o->mask & NTW2_FORMATION))
        say(L"note: collide stays inert while formation is enabled (the original manager bypasses the ACTIVE clone); "
            L"omit formation to run the experimental solver.\n");
    if (o->exit_game_after_observe && (!o->observe_s || !o->activate)) {
        errsay(L"--exit-game-after-observe requires nonzero --observe-seconds and runtime activation.\n");
        return -1;
    }
    return 0;
}

static BOOL choose_game_dir(Run *r)
{
    wchar_t line[MAXP], sug[MAXP];
    int attempt;
    if (r->opt.game[0]) {
        trim_input(r->opt.game);
        if (!resolve_game_dir(r->opt.game, r->game_dir)) {
            errsay(L"game directory \"%ls\" does not exist.\n", r->opt.game);
            return FALSE;
        }
        return TRUE;
    }
    if (!g_in_con) {
        errsay(L"no --game DIR given and standard input is not a console; cannot prompt.\n");
        return FALSE;
    }
    for (attempt = 0; attempt < 3; ++attempt) {
        BOOL have_sug = suggest_game_dir(sug);
        if (have_sug) say(L"Napoleon Total War game directory (folder containing Napoleon.exe)\n  [Enter = %ls]: ", sug);
        else say(L"Napoleon Total War game directory (folder containing Napoleon.exe): ");
        if (!read_line(line, MAXP)) { win_fail(L"reading the game directory", GetLastError()); return FALSE; }
        if (!line[0] && have_sug) wcscpy_s(line, MAXP, sug);
        if (!line[0]) { errsay(L"no game directory entered.\n"); return FALSE; }
        if (resolve_game_dir(line, r->game_dir)) {
            wchar_t exe[MAXP];
            join_path(exe, r->game_dir, GAME_EXE_NAME);
            if (GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES) return TRUE;
            errsay(L"%ls was not found in \"%ls\".\n", GAME_EXE_NAME, r->game_dir);
        } else {
            errsay(L"\"%ls\" is not an existing directory.\n", line);
        }
    }
    return FALSE;
}

int wmain(int argc, wchar_t **argv)
{
    Run *r = &g_run;
    int pr, code;

    init_console();
    GetSystemTimePreciseAsFileTime(&r->t_start);
    pr = parse_args(argc, argv, &r->opt);
    if (pr == 1) { usage(); return EXIT_OK; }
    if (pr < 0) { say(L"Run ntw2.exe --help for usage.\n"); return EXIT_USAGE; }
    r->cfg.enabled_mask = r->opt.mask;
    r->cfg.workers = r->opt.workers;
    r->cfg.poll_ms = r->opt.poll_ms;
    r->cfg.collide_lod_m = r->opt.collide_lod_m | (r->opt.collide_census ? NTW2_COLLIDE_CENSUS : 0u);
    r->cfg.loco_flags = loco_flags_from(&r->opt);
    r->cfg.brain_flags = (r->opt.brain_census ? NTW2_BRAIN_CENSUS : 0u) |
                         (r->opt.brain_timing ? NTW2_BRAIN_TIMING : 0u) |
                         (r->opt.brain_node_shadow ? NTW2_BRAIN_NODE_SHADOW : 0u) |
                         (r->opt.brain_fire_shadow ? NTW2_BRAIN_FIRE_SHADOW : 0u) |
                         (r->opt.brain_finalizer_shadow ? NTW2_BRAIN_FINALIZER_SHADOW : 0u) |
                         (r->opt.brain_parallel ? NTW2_BRAIN_PARALLEL : 0u) |
                         (r->opt.brain_quiet ? NTW2_BRAIN_QUIET : 0u) |
                         (r->opt.brain_unit_shadow ? NTW2_BRAIN_UNIT_SHADOW : 0u);
    r->cfg.collide_flags = (r->opt.collide_contact_shadow ? NTW2_COLLIDE_CONTACT_SHADOW : 0u) |
                           (r->opt.collide_contact_workers ? NTW2_COLLIDE_CONTACT_WORKERS : 0u);

    if (r->opt.replay[0]) {
        wchar_t full[MAXP];
        DWORD n = GetFullPathNameW(r->opt.replay, MAXP, full, NULL), a;
        if (n == 0 || n >= MAXP || (a = GetFileAttributesW(full)) == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) {
            errsay(L"replay file \"%ls\" does not exist.\n", r->opt.replay);
            return EXIT_USAGE;
        }
        if (wcschr(full, L'"')) { errsay(L"replay path must not contain a double quote.\n"); return EXIT_USAGE; }
        wcscpy_s(r->opt.replay, MAXP, full);
    }

    if (!choose_game_dir(r)) return finish(r, EXIT_VALIDATE, L"no usable game directory");
    if (!validate_game(r)) return finish(r, EXIT_VALIDATE, L"unsupported or missing Napoleon.exe");
    if (r->opt.activate || r->opt.validate_only) {
        if (!validate_runtime(r)) return finish(r, EXIT_VALIDATE, L"unusable runtime DLL");
    }
    if (r->opt.validate_only) {
        say(L"Validation complete; nothing was started.\n");
        return finish(r, EXIT_OK, L"validated");
    }
    if (napoleon_running()) return finish(r, EXIT_CONFLICT, L"Napoleon.exe already running");

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    if (!launch_game(r)) return finish(r, EXIT_LAUNCH, L"game launch failed");
    if (!r->opt.activate) {
        say(L"--no-activate: the runtime was NOT installed. Game pid %lu left running.\n", (unsigned long)r->pid);
        return finish(r, EXIT_OK, L"launched without runtime");
    }

    code = install_runtime(r);
    if (code != EXIT_OK) {
        if (code == EXIT_INSTALL || code == EXIT_LAUNCH)
            say(L"The runtime is NOT active. %ls\n", r->game_exited ? L"The game has exited."
                                                                       : L"The game was left running without the runtime; close it manually if unwanted.");
        if (r->remote_leaked) say(L"A remote thread timed out inside the game; its memory is intentionally retained until the game exits.\n");
        return finish(r, code, code == EXIT_INTERRUPTED ? L"interrupted before install" : L"runtime installation failed");
    }
    code = monitor(r);
    /* An unattended run (--exit-game-after-observe) must never leave its own game behind. The runtime is stopped
       (confirmed) before WM_CLOSE; if that cannot be confirmed, only the launched process is terminated. */
    if (r->opt.exit_game_after_observe && code == EXIT_RUNTIME_FAILED && !r->game_exited && process_alive(r->proc))
        if (!stop_then_close_game(r)) code = EXIT_GAME_STOP_FAILED;
    switch (code) {
    case EXIT_OK: return finish(r, code, r->game_exited ? L"all requested features were active; game exited" : L"all requested features active");
    case EXIT_NOT_ACTIVE: return finish(r, code, L"runtime armed but requested features never all active");
    case EXIT_RUNTIME_FAILED: return finish(r, code, L"runtime failed");
    case EXIT_INTERRUPTED: return finish(r, code, L"interrupted; runtime stopped");
    case EXIT_STOP_FAILED: return finish(r, code, L"interrupted; runtime stop failed");
    case EXIT_RECEIPT: return finish(r, code, L"live receipt write failed");
    case EXIT_GAME_STOP_FAILED: return finish(r, code, L"observation finished; launched game shutdown failed");
    default: return finish(r, code, L"runtime status unavailable");
    }
}
