/*
 * KNTWR.exe - native launcher for KNTWR, Kaung's Napoleon Total War Runtime (x86 multithreading runtime for Napoleon Total War).
 *
 * Flow: locate game directory (--game argument, else the saved configuration, else every Steam library, else -- interactively
 * only -- a folder picker) -> validate Napoleon.exe (PE32/i386 + SHA-256 pin, streamed, no heap
 * copy) -> validate the adjacent runtime DLL (PE32/i386 DLL, start/stop/state/profile/trace exports, file-mapped, no
 * heap copy) -> refuse if any Napoleon.exe is already running -> CreateProcessW the game -> wait for loader stability ->
 * verify the remote lifetime (image file identity, main module base) -> remote LoadLibraryW of the runtime DLL ->
 * verify the remote module against the local file -> remote kntwr_start(config) -> monitor kntwr_state until game exit,
 * Ctrl+C or --observe-seconds.  Activation is only reported when the in-process status says ACTIVE with every requested
 * feature bit set. Game files are read-only; outputs are --receipt and its .profile.bin / .ticks.bin companions.
 *
 * Contract with kntwr_runtime.dll (include/kntwr_runtime.h):
 *   kntwr_start  (_kntwr_start@4)  WINAPI thread entry, param = pointer to kntwr_config in the game; returns 0 on success.
 *   kntwr_stop   (_kntwr_stop@4)   WINAPI thread entry; returns 0 on success.
 *   kntwr_state  (DATA export)    a kntwr_status object (128 bytes, sequence-locked); read with ReadProcessMemory.
 *   kntwr_trace  (DATA export)    966688-byte little-endian tick ring (ABI 8, 112 sites + raw gate QPC); live snapshots are observational.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdarg.h>
#include <intrin.h>
#include <math.h>
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
#include "brain2/native_brain_s0.h"
#include "brain2/native_brain_locality.h"
#include "brain2/native_unit_policy.h"
#include "brain2/native_unit_fatigue.h"
#include "brain2/native_unit_posture_engage.h"
#include "brain2/native_unit_posture_engage.h"
#include "army/native_army_unit.h"
#include "army/native_army_storm.h"
#include "army/native_formation_residual.h"
#include "collision/native_contact.h"

#include "kntwr_runtime.h"
#include "profile/kntwr_profile.h"
#include "core/kntwr_gameplay_patch.h"
#include "census.h"
#include "setup.h"

#if !defined(_M_IX86) && !defined(__i386__)
#error "KNTWR.exe must be built as a 32-bit x86 executable: it resolves 32-bit system exports for the 32-bit game process."
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#ifndef KNTWR_RUNTIME_DLL_NAME
#define KNTWR_RUNTIME_DLL_NAME "kntwr_runtime.dll"
#endif
#define KNTWR_WIDEN2(x) L##x
#define KNTWR_WIDEN(x) KNTWR_WIDEN2(x)
#define RUNTIME_DLL_NAME KNTWR_WIDEN(KNTWR_RUNTIME_DLL_NAME)

static const wchar_t *g_game_exe = L"Napoleon.exe";   /* --game-exe NAME (diagnostic): the exe file name inside the game folder */
#define GAME_EXE_NAME (g_game_exe)
#define KNTWR_STEAM_APP_ID L"34030"   /* Total War: NAPOLEON - Definitive Edition (steamapps/appmanifest_34030.acf) */
#define MAXP 4096u

enum {
    EXIT_OK = 0,
    EXIT_USAGE = 1,
    EXIT_VALIDATE = 2,     /* game or runtime DLL missing / unsupported */
    EXIT_CONFLICT = 3,     /* a Napoleon.exe is already running */
    EXIT_LAUNCH = 4,       /* CreateProcessW failed or the game died before install */
    EXIT_INSTALL = 5,      /* remote load / verification / kntwr_start failed */
    EXIT_RUNTIME_FAILED = 6,   /* runtime reported FAILED (or stopped unexpectedly) */
    EXIT_NOT_ACTIVE = 7,   /* armed, but all requested features never became ACTIVE */
    EXIT_INTERRUPTED = 8,  /* Ctrl+C: runtime stop requested and completed */
    EXIT_STOP_FAILED = 9,  /* Ctrl+C: runtime stop failed or timed out */
    EXIT_RECEIPT = 10,     /* everything else succeeded but the receipt could not be written */
    EXIT_GAME_STOP_FAILED = 11 /* owned game did not exit after the observation bound */
};

/* ------------------------------------------------------------------------------------------------ console output */
static HANDLE g_hout, g_herr;
static BOOL g_out_con, g_err_con;
static wchar_t g_err_text[2048];  /* newline-joined text of every errsay() call, shown by the quiet-failure MessageBox */
static size_t g_err_len;
static BOOL g_redirected;         /* any std handle is a pipe/file: sampled in wmain before console acquisition */
static BOOL g_attached;           /* the process attached to the caller's terminal (text output is visible there) */
static BOOL g_ui_mute;            /* --check/--validate-only: read-only runs never show a dialog */

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
    vsay(g_herr, g_err_con, L"kntwr: error: ", fmt, ap);
    va_end(ap);
    /* Also keep the message for the quiet-failure MessageBox (a double-click run has nowhere else to show it). */
    va_start(ap, fmt);
    {
        wchar_t buf[MAXP];
        int n = _vsnwprintf_s(buf, MAXP, _TRUNCATE, fmt, ap);
        if (n > 0) {
            while (n && buf[n - 1] == L'\n') --n;
            if (g_err_len + 2 + (size_t)n >= sizeof g_err_text / sizeof g_err_text[0]) g_err_len = 0; /* keep the newest */
            if (g_err_len) g_err_text[g_err_len++] = L'\n';
            memcpy(g_err_text + g_err_len, buf, (size_t)n * sizeof(wchar_t));
            g_err_len += (size_t)n;
            g_err_text[g_err_len] = 0;
        }
    }
    va_end(ap);
}

/* KNTWR.exe is a Windows-subsystem executable (CMakeLists: /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup), so Windows never
   creates a console for it: no window can flash on a double-click or when a wrapper spawns it, and a caller that
   redirected stdout/stderr (pipe or file) gets exactly that output with no console touched.  The shipping no-argument
   run is fully quiet but never drops the caller's text: when the standard handles are an inherited terminal (a GUI
   process gets the handles without the attachment, and console writes are rejected without it), it attaches to that
   terminal only -- AttachConsole creates no window and never hides or detaches a shared terminal, and the inherited
   handles start working as-is; no handle is ever replaced.  AllocConsole (a window of our own) happens only for
   --console (development) with no terminal to attach to. */
static BOOL std_handle_usable(DWORD which)
{
    HANDLE h = GetStdHandle(which);
    return h && h != INVALID_HANDLE_VALUE && GetFileType(h) != FILE_TYPE_UNKNOWN;
}

/* TRUE when a standard handle is a console device handle (FILE_TYPE_CHAR) that console APIs reject, i.e. the caller's
   console handle was inherited without console attachment.  GetConsoleMode on NUL also fails, so this also reports NUL;
   treating it as "needs attach" is harmless (attaching changes nothing visibly and no handle is replaced). */
static BOOL std_handle_inherited_console(DWORD which)
{
    HANDLE h = GetStdHandle(which);
    DWORD mode;
    return h && h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_CHAR && !GetConsoleMode(h, &mode);
}

static void std_handle_from_console(DWORD which, const wchar_t *device)
{
    HANDLE h;
    if (std_handle_usable(which)) return;
    h = CreateFileW(device, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) SetStdHandle(which, h);
}

/* TRUE when any standard handle is redirected to a pipe or file: an automated/wrapper run.  Sampled before any console
   is acquired so the launcher's own attach/alloc cannot mask the caller's redirection. */
static BOOL std_redirected(void)
{
    static const DWORD which[3] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
    int i;
    for (i = 0; i < 3; ++i) {
        HANDLE h = GetStdHandle(which[i]);
        DWORD t;
        if (!h || h == INVALID_HANDLE_VALUE) continue;
        t = GetFileType(h);
        if (t == FILE_TYPE_DISK || t == FILE_TYPE_PIPE) return TRUE;
    }
    return FALSE;
}

static void acquire_console(int console_mode) /* 1 = --console, 0 = default, -1 = --no-console */
{
    BOOL inherited_console = std_handle_inherited_console(STD_INPUT_HANDLE) ||
                             std_handle_inherited_console(STD_OUTPUT_HANDLE) ||
                             std_handle_inherited_console(STD_ERROR_HANDLE);
    if (console_mode < 0) return; /* --no-console: leave every handle and every console exactly as the caller left it */
    if (console_mode == 0) {
        /* Quiet default: attach to the caller's terminal only when its handles were inherited without the attachment
           (otherwise every text write would be dropped).  Never create a console of our own, never touch a handle. */
        if (inherited_console && AttachConsole(ATTACH_PARENT_PROCESS)) g_attached = TRUE;
        return;
    }
    if (!inherited_console && std_handle_usable(STD_OUTPUT_HANDLE) && std_handle_usable(STD_ERROR_HANDLE)) return;
    if (AttachConsole(ATTACH_PARENT_PROCESS)) g_attached = TRUE;
    else if (!AllocConsole()) return;
    std_handle_from_console(STD_INPUT_HANDLE, L"CONIN$");
    std_handle_from_console(STD_OUTPUT_HANDLE, L"CONOUT$");
    std_handle_from_console(STD_ERROR_HANDLE, L"CONOUT$");
}

static void init_console(void)
{
    DWORD mode;
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_herr = GetStdHandle(STD_ERROR_HANDLE);
    g_out_con = g_hout && g_hout != INVALID_HANDLE_VALUE && GetConsoleMode(g_hout, &mode);
    g_err_con = g_herr && g_herr != INVALID_HANDLE_VALUE && GetConsoleMode(g_herr, &mode);
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

/* On-disk state of mss32.dll.  Only Napoleon.exe is required to be a supported image: the gameplay patch does not depend on the
   audio DLL, so an unrecognised or missing mss32.dll is reported loudly (console + receipt) and the in-memory audio patch is
   skipped; it is never silently labelled patched. */
enum { MSS_MISSING = 0, MSS_STOCK, MSS_UNKNOWN };
static const char *const k_mss_state_name[3] = { "missing", "stock", "unknown" };

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
    BOOL brain_s0;           /* --brain-s0: S0 attribution timer (BRAIN_S0 clone family, 1/64 RDTSCP strata); diagnostics only. */
    BOOL brain_locality;     /* --brain-locality: site-6 locality census (KNTWR_BRAIN_LOCALITY); original step unchanged, diagnostics only. */
    BOOL brain_locality_warm;      /* --brain-locality-warm: cold-vs-warm read-touch A/B (sets --brain-locality). */
    BOOL brain_locality_prefetch;  /* --brain-locality-prefetch: PREFETCHT0 distance-1 A/B blocks (sets --brain-locality). */
    BOOL brain_locality_prefetch2; /* --brain-locality-prefetch2: entity lines two ahead, chain lines one ahead (sets --brain-locality). */
    BOOL brain_locality_mark;      /* --brain-locality-mark: pass-through runner emitting one ETW event per site-6 stage begin/end (sets --brain-locality). */
    BOOL brain_unit_fatigue;        /* --brain-unit-fatigue: S4 per-unit fatigue pair, live (KNTWR_BRAIN_UNIT_FATIGUE). */
    BOOL brain_unit_fatigue_shadow; /* --brain-unit-fatigue-shadow: same decision, native results stay, divergence tables (sets both bits). */
    BOOL brain_unit_posture;        /* --brain-unit-posture: S2b per-unit posture, live. */
    BOOL brain_unit_posture_shadow; /* --brain-unit-posture-shadow. */
    BOOL brain_unit_engage;         /* --brain-unit-engage: S1c/S3 engage + fire latches, S1a/S2a lookups, live. */
    BOOL brain_unit_engage_shadow;  /* --brain-unit-engage-shadow. */
    BOOL collide_contact_shadow;  /* --collide-contact-shadow: plan contact callbacks on workers, owner runs and compares the original. */
    BOOL collide_contact_workers; /* --collide-contact-workers: same-team contact decisions on workers, owner replays effects in order. */
    BOOL no_collide_contact_workers; /* Explicit opt-out; never changes the feature mask. */
    BOOL va_watch;           /* --va-watch: opt-in 1 Hz process-VA sampler on the monitor thread (kntwr_config::va_watch_flags); load-crash forensics only. */
    BOOL army_storm_census;  /* --army-storm-census: opt-in site-18 storm census (kntwr_config::va_watch_flags KNTWR_ARMY_STORM_CENSUS) */
    uint32_t army_storm_sample_ms; /* --army-storm-sample-ms N, 1..255 (0 = off): storm-gated sampler threshold, bits 8..15 of va_watch_flags */
    BOOL tick_pcore;         /* --tick-pcore: pin the routed tick body to P cores on a hybrid CPU (va_watch_flags KNTWR_TICK_PCORE) */
    BOOL no_tick_pcore;      /* --no-tick-pcore: opt out of tick placement under --features all */
    BOOL tick_core_ab;       /* --tick-core-ab: measurement; even ticks on P, odd ticks on E cores (va_watch_flags KNTWR_TICK_CORE_AB) */
    BOOL army_solver_memo;   /* --army-solver-memo: bit-exact memoised flag=1 slot solver (kntwr_config::va_watch_flags KNTWR_ARMY_SOLVER_MEMO) */
    BOOL army_solver_shadow; /* --army-solver-shadow: same chain, native authoritative, kernel compared (KNTWR_ARMY_SOLVER_SHADOW); exclusive with memo */
    BOOL alloc_census;       /* --alloc-census: process-heap allocation callsite census (va_watch_flags KNTWR_ALLOC_CENSUS) */
    BOOL alloc_fix;          /* --alloc-fix: live pathfinder subnode reclamation (va_watch_flags KNTWR_ALLOC_FIX; mode=2 alone, mode=3 with --alloc-census) */
    BOOL no_alloc_fix;       /* --no-alloc-fix: opt out of --alloc-fix under --features all */
    BOOL arena_release;      /* --arena-release: release pose/scene arena blocks at battle teardown + high-water trim (KNTWR_ARENA_RELEASE) */
    BOOL no_arena_release;   /* --no-arena-release: opt out of --arena-release under --features all */
    BOOL heap_optimize;      /* --heap-optimize: process-heap / provider HeapOptimizeResources (KNTWR_HEAP_OPTIMIZE) */
    BOOL mounted_officer;    /* --mounted-officer: gameplay feature, one mount for the officer of units with resolved mount columns (KNTWR_MOUNTED_OFFICER); implied by --features all unless --no-mounted-officer */
    BOOL no_mounted_officer; /* --no-mounted-officer: opt out of --mounted-officer under --features all */
    BOOL mounted_officer_widen; /* --mounted-officer-widen: sets mounted_officer; the mount also raises the unit radius (KNTWR_MOUNTED_OFFICER_WIDEN) */
    BOOL drag_ladder;        /* --drag-ladder: GAMEPLAY feature, 60-file frontage ladder for drag-out formation (KNTWR_DRAG_LADDER in kntwr_config::gameplay_flags); implied by --features all unless --no-drag-ladder */
    BOOL no_drag_ladder;     /* --no-drag-ladder: opt out of --drag-ladder under --features all */
    BOOL wounded;            /* --wounded[=PCT]: EXPERIMENTAL GAMEPLAY feature, FACE-tagged shot deaths flip to the native wounded state with probability PCT% (KNTWR_WOUNDED in kntwr_config::gameplay_flags); never implied by --features all */
    uint32_t wounded_pct;    /* PCT 1..100 (default KNTWR_WOUNDED_PCT_DEFAULT) */
    BOOL no_cavalry_orbit;   /* --no-cavalry-orbit: opt out of cavalry_orbit (clears the default and the --features all implication) */
    BOOL engage_census;      /* --engage-census: opt-in read-only AI engagement-depth diagnostic (KNTWR_ENGAGE_CENSUS); never implied by --features all */
    BOOL formation_census;   /* --formation-census[=EVERY]: opt-in read-only formation compactness census (KNTWR_FORMATION_CENSUS with a runtime; launcher-side RPM census with --no-activate) */
    uint32_t formation_census_every; /* EVERY model ticks (0 = default 30) */
    wchar_t formation_census_csv[MAXP]; /* --formation-census-csv FILE */
    BOOL formation_census_men; /* --formation-census-men: also write FILE.men.csv (per-man steering detail of a few tracked units; KNTWR_FORMATION_CENSUS_MEN) */
    BOOL no_gameplay_patch;  /* --no-gameplay-patch: stock bytes in memory (diagnostic bisection; the runtime refuses a stock image, so it needs --no-activate) */
    kntwr_gp_filter gp_filter;/* --gameplay-patch-only-runs / --gameplay-patch-skip-runs: which non-header runs the in-memory applier writes (the D3D9 swap runs are removed with --no-d3d9-swap) */
    BOOL gp_filter_listed;   /* an explicit --gameplay-patch-*-runs list was given */
    BOOL no_d3d9_swap;       /* --no-d3d9-swap: leave the patch's Direct3DCreate9 swap (runs 65, 92) stock; default writes the whole patch */
    BOOL steam;              /* --steam (default) / --no-steam: give the game SteamAppId/SteamGameId=34030 (multiplayer, lobbies, overlay) */
    wchar_t game_exe[MAXP];  /* --game-exe NAME */
    uint32_t va_floor_mib;   /* --va-floor-mib N, 64..1024 (0 = default 256): total free VA floor, bits 22..26 of va_watch_flags in 32 MiB units */
    uint32_t va_hole_mib;    /* --va-hole-mib M, 32..512 (0 = default 128): largest free hole floor, bits 27..31 of va_watch_flags in 32 MiB units */
    BOOL loco_clone;         /* --loco-clone: KNTWR_LOCO executes admitted movement through the private clone family (kntwr_config::loco_flags) */
    BOOL loco_parallel;      /* --loco-parallel: closed movement workers; requires loco and --loco-clone */
    BOOL loco_shadow;        /* Owner-thread validation; never selects port results. */
    BOOL loco_owned;         /* --loco-owned-services: opt-in supported active mover path; requires loco, --loco-clone and --loco-parallel */
    BOOL loco_quiet;         /* --loco-quiet: low-overhead owned mode; no service QPC, shadow comparisons or all-gates histogram; requires --loco-owned-services */
    BOOL loco_grid;          /* --loco-grid: owned soldier grid v2, published at site-13 exit; default off */
    BOOL loco_grid_verify;   /* --loco-grid-verify: implies grid; owner-side verification */
    BOOL loco_grid_incremental; /* --loco-grid-incremental: patch the owned grid instead of rebuilding it; requires --loco-grid (or verify); with verify also a shadow full rebuild per stage */
    BOOL grid_probation;     /* --grid-probation: native cell-head trap detector; requires --loco-grid (or verify), not ballistic */
    BOOL loco_relink_shadow; /* --loco-relink-shadow: parallel relink apply verified on a private mirror; requires --loco-owned-services and --loco-grid */
    BOOL loco_relink_workers;/* --loco-relink-workers: live cell-partitioned relink apply on the pool; exclusive with shadow */
    BOOL loco_cw_shadow;     /* --loco-cw-shadow: class-wrapper phase 2 computed on workers, native wrapper still runs and is compared; requires --loco-owned-services */
    BOOL loco_cw_workers;    /* --loco-cw-workers: class-wrapper phase 2 live (owner replays child relocations natively); exclusive with shadow */
    BOOL no_loco_cw_workers; /* Explicit opt-out of live class-wrapper workers. */
    BOOL ai_deferred;        /* --ai-deferred: ai_async2 deferred sliced thinks (kntwr_config::ai_deferred) */
    uint32_t ai_deferred_k;  /* --ai-deferred-k K, 1..KNTWR_AI_DEFERRED_MAX_K (default KNTWR_AI_DEFERRED_DEFAULT_K) */
    uint32_t ai_deferred_budget; /* --ai-deferred-budget B, 1..65535 (default KNTWR_AI_DEFERRED_DEFAULT_BUDGET) */
    uint32_t ai_ctrl_flags;  /* --ai-ctrl-census/-histogram/-geometry/-verify: KNTWR_AI_CTRL_* (kntwr_config::ai_ctrl_flags bits 0..3) */
    BOOL ai_claim_once;      /* --ai-claim-once: kntwr_config::ai_ctrl_flags bit 8 (KNTWR_AI_CLAIM_ONCE) */
    BOOL ai_claim_once_census; /* --ai-claim-once-census: bit 9 (KNTWR_AI_CLAIM_ONCE_CENSUS) */
    BOOL brain_target_cull_shadow; /* --brain-target-cull-shadow: bit 10 (KNTWR_AI_TARGET_CULL_SHADOW) */
    BOOL brain_target_cull;  /* --brain-target-cull: bit 11 (KNTWR_AI_TARGET_CULL) */
    BOOL brain_retarget_jitter; /* --brain-retarget-jitter: bit 12 (KNTWR_AI_RETARGET_JITTER); opt-in only, never implied by --features all */
    uint32_t ai_prepass_flags; /* --ai-prepass-census / --ai-presize / --ai-poly* / --ai-spiral-census, cap metres in bits 16..31 (--ai-spiral-cap-m) (kntwr_config::ai_prepass_flags) */
    uint32_t observe_s;       /* 0 = until the game exits */
    uint32_t inject_timeout_s;
    BOOL activate;
    BOOL validate_only;
    BOOL no_launch;         /* --no-launch: validate + save the resolved game folder, start nothing; no picker, no dialog */
    BOOL setup;             /* --setup: pick a game folder with the native picker, validate exe + DLL, save it, start nothing */
    BOOL no_steam;          /* --no-steam: start the game without the Steam app id (flag accepted; steam=FALSE does the work) */
    BOOL allow_concurrent;
    BOOL focus;
    BOOL exit_game_after_observe;
} Options;

static uint32_t loco_flags_from(const Options *o)
{
    return (o->loco_clone ? KNTWR_LOCO_CLONE : 0u) | (o->loco_parallel ? KNTWR_LOCO_PARALLEL : 0u) | (o->loco_shadow ? KNTWR_LOCO_SHADOW : 0u) |
           (o->loco_owned ? KNTWR_LOCO_OWNED_SERVICES : 0u) | (o->loco_quiet ? KNTWR_LOCO_QUIET : 0u) |
           ((o->loco_grid || o->loco_grid_verify) ? KNTWR_LOCO_GRID : 0u) | (o->loco_grid_verify ? KNTWR_LOCO_GRID_VERIFY : 0u) |
           (o->grid_probation ? KNTWR_LOCO_GRID_PROBATION : 0u) | (o->loco_grid_incremental ? KNTWR_LOCO_GRID_INCREMENTAL : 0u) |
           (o->loco_relink_shadow ? KNTWR_LOCO_RELINK_SHADOW : 0u) | (o->loco_relink_workers ? KNTWR_LOCO_RELINK_WORKERS : 0u) |
           (o->loco_cw_shadow ? KNTWR_LOCO_CW_SHADOW : 0u) | (o->loco_cw_workers ? KNTWR_LOCO_CW_WORKERS : 0u);
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
    kntwr_trace_ring copies[2];
    uint32_t current;
    BOOL have, finalized, analyzed;
    uint32_t count, first_tick, last_tick, duration[4], interval[4], over100, over150;
    uint32_t mod100[10], mod10[10], top[16], top_count;
    uint64_t duration_sum, manager_sum, ballistics_sum, path_sum;
    uint64_t site_sum[KNTWR_TIMED_SITES], site_calls[KNTWR_TIMED_SITES];
    uint32_t timed_ticks;
    int64_t remainder_sum;
    uint32_t scratch[KNTWR_TRACE_ENTRIES];
} TickTrace;

#define TICK_LOG_MAX_ENTRIES 200000u
typedef struct TickLog {
    kntwr_trace_entry *entries;
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
    BOOL exe_is_stock, gp_applied, gp_live_verified, mss32_applied;
    int mss32_state;
    char mss32_sha[65];
    uint64_t mss32_size;
    uint32_t mss32_base;
    kntwr_gp_report gp_rep, mss32_rep;
    HANDLE exe_file;   /* held share-read-only from validation until the game is set up: no swap/modify window */
    /* The creation-time reservation for the gameplay-patched child (kntwr_gameplay_patch.h): planned from the held source
       handle, attached through a scoped import wrapper, verified before patching, released by the remap exactly once. */
    kntwr_gp_reserve gp_rsv;
    kntwr_gp_reserve_report gp_rsv_rep;
    HANDLE dll_file;
    DllInfo dll;
    HANDLE proc;
    DWORD pid;
    FILETIME created;
    uint32_t exe_base, dll_base, state_addr;
    kntwr_config cfg;
    kntwr_status last;
    uint32_t crash_tag;   /* acknowledgement tag of the last crash_words state printed (see kntwr_runtime.h crash_words[31]) */
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
    kntwr_profile_status profile;
    uint32_t *profile_arrays;
    BOOL have_profile;
    TickTrace *trace;
    TickLog tick_log;
    uint32_t overlay_words[KNTWR_OVERLAY_WORDS];
    struct OverlayMod {
        wchar_t name[64];
        uint32_t base, size;
        BOOL is_nv_umd;
        BOOL splits_low_hole;
    } overlay_mods[32];
    unsigned overlay_mod_count;
    BOOL have_overlay;
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
    case KNTWR_IDLE: return L"IDLE";
    case KNTWR_VERIFYING: return L"VERIFYING";
    case KNTWR_WAITING_BATTLE: return L"WAITING_BATTLE";
    case KNTWR_ACTIVATING: return L"ACTIVATING";
    case KNTWR_ACTIVE: return L"ACTIVE";
    case KNTWR_RESTORING: return L"RESTORING";
    case KNTWR_FAILED: return L"FAILED";
    case KNTWR_STOPPED: return L"STOPPED";
    default: return L"UNKNOWN";
    }
}

static const struct { uint32_t bit; const wchar_t *name; const char *jname; } k_features[] = {
    { KNTWR_PATH, L"path", "path" },
    { KNTWR_FORMATION, L"formation", "formation" },
    { KNTWR_BALLISTICS, L"ballistics", "ballistics" },
    { KNTWR_AI_ASYNC, L"ai", "ai" },
    { KNTWR_AI_CTRL, L"ai_ctrl", "ai_ctrl" },
    { KNTWR_BATCH64, L"batch64", "batch64" },
    { KNTWR_BRAIN2, L"brain2", "brain2" },
    { KNTWR_VISUAL, L"visual", "visual" },
    { KNTWR_COLLIDE, L"collide", "collide" },
    { KNTWR_COLLIDE_LOD, L"collide_lod", "collide_lod" },
    { KNTWR_PROFILE, L"profile", "profile" },
    { KNTWR_BRAIN, L"brain", "brain" },
    { KNTWR_LOCO, L"loco", "loco" },
    { KNTWR_GRID_CENSUS, L"grid_census", "grid_census" },
    { KNTWR_AI_CENSUS, L"ai_census", "ai_census" },
    { KNTWR_AI_ASYNC2, L"ai_async2", "ai_async2" },
    { KNTWR_ARMY_UNIT_SHADOW, L"army_unit_shadow", "army_unit_shadow" },
    { KNTWR_CAVALRY_ORBIT, L"cavalry_orbit", "cavalry_orbit" },
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

static const char *const k_export_names[5] = { "kntwr_start", "kntwr_stop", "kntwr_state", "kntwr_profile", "kntwr_trace" };

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
    if (!s || !(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) return L"kntwr_start is not in an executable section";
    s = section_of(&x, rvas[1]);
    if (!s || !(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) return L"kntwr_stop is not in an executable section";
    s = section_of(&x, rvas[2]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"kntwr_state is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[2] + sizeof(kntwr_status) > (uint64_t)s->VirtualAddress + ext)
            return L"kntwr_state is smaller than the kntwr_status ABI";
    }
    s = section_of(&x, rvas[3]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"kntwr_profile is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[3] + sizeof(kntwr_profile_status) > (uint64_t)s->VirtualAddress + ext)
            return L"kntwr_profile is smaller than the profile ABI";
    }
    s = section_of(&x, rvas[4]);
    if (!s || (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(s->Characteristics & IMAGE_SCN_MEM_READ))
        return L"kntwr_trace is not in a readable data section";
    {
        uint32_t ext = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if ((uint64_t)rvas[4] + sizeof(kntwr_trace_ring) > (uint64_t)s->VirtualAddress + ext ||
            (uint64_t)rvas[4] + sizeof(kntwr_trace_ring) > nt->OptionalHeader.SizeOfImage)
            return L"kntwr_trace is smaller than the trace ABI";
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
    if (_stricmp(r->exe_sha, KNTWR_STOCK_IMAGE_SHA256) == 0) {
        r->exe_is_stock = TRUE;
        say(L"Napoleon.exe: stock (gameplay patch applied in memory; x86 PE32, %I64u bytes, SHA-256 match).\n",
            (unsigned long long)r->exe_size);
    } else {
        wchar_t got[65], want_s[65];
        MultiByteToWideChar(CP_ACP, 0, r->exe_sha, -1, got, 65);
        MultiByteToWideChar(CP_ACP, 0, KNTWR_STOCK_IMAGE_SHA256, -1, want_s, 65);
        errsay(L"\"%ls\" is not a supported Napoleon.exe.\n  size   : %I64u bytes\n  sha256 : %ls\n  stock  : %ls\n"
               L"Only the stock Steam executable is supported. Restore it with Steam > Properties > Installed Files > Verify integrity of game files.\n"
               L"The game files were not modified.\n",
               r->exe_path, (unsigned long long)r->exe_size, got, want_s);
        return FALSE;
    }
    {
        wchar_t mpath[MAXP];
        HANDLE mf;
        join_path(mpath, r->game_dir, L"mss32.dll");
        r->mss32_state = MSS_MISSING;
        mf = CreateFileW(mpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (mf == INVALID_HANDLE_VALUE) {
            say(L"mss32.dll: not readable at \"%ls\" (Win32 %lu); the in-memory audio patch will be skipped.\n", mpath, (unsigned long)GetLastError());
        } else {
            r->mss32_state = MSS_UNKNOWN;
            if (!sha256_handle(mf, r->mss32_sha, &r->mss32_size, &we, &ne)) {
                r->mss32_sha[0] = 0;
                say(L"mss32.dll: hashing failed; treated as unknown, the in-memory audio patch will be skipped.\n");
            } else if (_stricmp(r->mss32_sha, KNTWR_STOCK_MSS32_SHA256) == 0) {
                r->mss32_state = MSS_STOCK;
                say(L"mss32.dll: stock (audio DSP patch applied in memory; %I64u bytes, SHA-256 match).\n", (unsigned long long)r->mss32_size);
            } else {
                wchar_t got[65];
                MultiByteToWideChar(CP_ACP, 0, r->mss32_sha, -1, got, 65);
                say(L"mss32.dll: UNKNOWN (%I64u bytes, sha256 %ls; not the supported stock build). The in-memory audio patch is skipped.\n",
                    (unsigned long long)r->mss32_size, got);
            }
            CloseHandle(mf);
        }
    }
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
        win_fail(L"locating KNTWR.exe", GetLastError());
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
            errsay(L"runtime DLL \"%ls\" was not found next to KNTWR.exe.\n", r->dll_path);
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
    say(L"Runtime DLL verified: %ls (x86 DLL; kntwr_start/kntwr_stop/kntwr_state exported; %I64u bytes).\n", r->dll_path,
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
static BOOL path_starts_icase(const wchar_t *p, const wchar_t *prefix)
{
    size_t n = wcslen(prefix);
    return _wcsnicmp(p, prefix, n) == 0;
}

static BOOL is_nv_umd_module(const wchar_t *name, const wchar_t *path)
{
    if (_wcsicmp(name, L"nvd3dum.dll") == 0 || _wcsicmp(name, L"nvgpucomp32.dll") == 0 ||
        _wcsicmp(name, L"nvppe.dll") == 0 || _wcsicmp(name, L"NvMemMapStorage.dll") == 0 ||
        _wcsicmp(name, L"nvldumd.dll") == 0 || _wcsicmp(name, L"nvoglv32.dll") == 0 ||
        _wcsicmp(name, L"nvwgf2um.dll") == 0)
        return TRUE;
    if (wcsstr(path, L"\\DriverStore\\") || wcsstr(path, L"\\driverstore\\")) {
        if (_wcsnicmp(name, L"nv", 2) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL is_foreign_hook_module(const Run *r, const wchar_t *name, const wchar_t *path)
{
    if (_wcsicmp(name, GAME_EXE_NAME) == 0 || _wcsicmp(name, RUNTIME_DLL_NAME) == 0) return FALSE;
    if (_wcsicmp(path, r->exe_path) == 0 || _wcsicmp(path, r->dll_path) == 0) return FALSE;
    if (r->game_dir[0] && path_starts_icase(path, r->game_dir)) return FALSE;
    if (is_nv_umd_module(name, path)) return FALSE;
    if (_wcsicmp(name, L"RTSSHooks.dll") == 0 || _wcsicmp(name, L"nvspcap.dll") == 0 ||
        _wcsicmp(name, L"gameoverlayrenderer.dll") == 0 || _wcsicmp(name, L"DiscordHook.dll") == 0 ||
        _wcsicmp(name, L"graphics-hook32.dll") == 0 || _wcsicmp(name, L"fraps32.dll") == 0)
        return TRUE;
    if (path_starts_icase(path, L"C:\\Windows\\SysWOW64\\") ||
        path_starts_icase(path, L"C:\\Windows\\System32\\") ||
        path_starts_icase(path, L"C:\\Windows\\WinSxS\\"))
        return FALSE;
    return TRUE;
}

static BOOL overlay_mod_cb(const MODULEENTRY32W *me, void *c)
{
    Run *r = (Run *)c;
    uint32_t base = (uint32_t)(uintptr_t)me->modBaseAddr;
    uint32_t size = me->modBaseSize;
    BOOL nv_umd = is_nv_umd_module(me->szModule, me->szExePath);
    BOOL foreign_hook = !nv_umd && is_foreign_hook_module(r, me->szModule, me->szExePath);
    ++r->overlay_words[KNTWR_OVL_TOTAL_MODULES];
    if (!nv_umd && !foreign_hook) return FALSE;
    /* A foreign or non-ASLR hook DLL mapped below tbb.dll (0x10000000) splits the lower-256 MiB hole between Napoleon.exe/tbbmalloc.dll and tbb.dll. */
    {
        BOOL splits_low = (base >= 0x01580000u && base < 0x10000000u);
        if (splits_low) ++r->overlay_words[KNTWR_OVL_SPLITS_LOW_HOLE_COUNT];
        if (nv_umd) {
            ++r->overlay_words[KNTWR_OVL_NV_UMD_MODULES];
            r->overlay_words[KNTWR_OVL_NV_UMD_IMAGE_BYTES] += size;
        } else {
            ++r->overlay_words[KNTWR_OVL_FOREIGN_HOOK_MODULES];
            r->overlay_words[KNTWR_OVL_FOREIGN_HOOK_IMAGE_BYTES] += size;
        }
        if (_wcsicmp(me->szModule, L"RTSSHooks.dll") == 0) {
            r->overlay_words[KNTWR_OVL_RTSS_BASE] = base;
            r->overlay_words[KNTWR_OVL_RTSS_SIZE] = size;
        } else if (_wcsicmp(me->szModule, L"nvspcap.dll") == 0) {
            r->overlay_words[KNTWR_OVL_NVSPCAP_BASE] = base;
            r->overlay_words[KNTWR_OVL_NVSPCAP_SIZE] = size;
        } else if (_wcsicmp(me->szModule, L"gameoverlayrenderer.dll") == 0) {
            r->overlay_words[KNTWR_OVL_STEAM_OVERLAY_BASE] = base;
            r->overlay_words[KNTWR_OVL_STEAM_OVERLAY_SIZE] = size;
        }
        if (r->overlay_mod_count < 32u) {
            struct OverlayMod *m = &r->overlay_mods[r->overlay_mod_count++];
            wcsncpy_s(m->name, 64, me->szModule, _TRUNCATE);
            m->base = base;
            m->size = size;
            m->is_nv_umd = nv_umd;
            m->splits_low_hole = splits_low;
        }
    }
    return FALSE;
}

typedef LONG (NTAPI *pfn_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void scan_overlay_threads(Run *r)
{
    HANDLE snap;
    THREADENTRY32 te;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pfn_NtQueryInformationThread qit = ntdll ? (pfn_NtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread") : NULL;
    uint32_t nv_threads = 0, nv_stack_bytes = 0;
    if (!r->pid) return;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != r->pid) continue;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (th) {
                PVOID start_addr = NULL;
                BOOL is_nv = FALSE;
                if (qit && qit(th, 9 /* ThreadQuerySetWin32StartAddress */, &start_addr, sizeof start_addr, NULL) == 0 && start_addr) {
                    uint32_t sa = (uint32_t)(uintptr_t)start_addr;
                    unsigned i;
                    for (i = 0; i < r->overlay_mod_count; ++i) {
                        if (r->overlay_mods[i].is_nv_umd && sa >= r->overlay_mods[i].base && sa < r->overlay_mods[i].base + r->overlay_mods[i].size) {
                            is_nv = TRUE;
                            break;
                        }
                    }
                }
                if (is_nv) {
                    uint32_t reserve_32 = 65536u; /* nvd3dum worker default 64 KiB 32-bit stack reserve */
                    struct { LONG ExitStatus; uint32_t TebBaseAddress; uint32_t ClientId[2]; uint32_t AffinityMask; LONG Priority; LONG BasePriority; } tbi;
                    ZeroMemory(&tbi, sizeof tbi);
                    if (qit && qit(th, 0 /* ThreadBasicInformation */, &tbi, sizeof tbi, NULL) == 0 && tbi.TebBaseAddress) {
                        uint32_t stack_base = 0, dealloc_stack = 0;
                        if (remote_read(r->proc, tbi.TebBaseAddress + 4u, &stack_base, 4) &&
                            remote_read(r->proc, tbi.TebBaseAddress + 0xE0Cu, &dealloc_stack, 4) &&
                            stack_base > dealloc_stack && (stack_base - dealloc_stack) <= 16u * 1024u * 1024u)
                            reserve_32 = stack_base - dealloc_stack;
                    }
                    ++nv_threads;
                    /* Every WOW64 thread also reserves a 256 KiB (262,144 B) 64-bit transition stack inside <4 GiB VA. */
                    nv_stack_bytes += reserve_32 + 262144u;
                }
                CloseHandle(th);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    r->overlay_words[KNTWR_OVL_NV_DRIVER_THREADS] = nv_threads;
    r->overlay_words[KNTWR_OVL_NV_DRIVER_STACK_BYTES] = nv_stack_bytes;
}

static void print_overlay_report(const Run *r);
static void capture_overlay_report(Run *r, BOOL print)
{
    DWORD err = 0;
    memset(r->overlay_words, 0, sizeof r->overlay_words);
    r->overlay_mod_count = 0;
    r->overlay_words[KNTWR_OVL_VERSION] = 1u;
    module_walk(r->pid, overlay_mod_cb, r, &err);
    scan_overlay_threads(r);
    r->overlay_words[KNTWR_OVL_TOTAL_FOREIGN_IMAGE_STACK_BYTES] =
        r->overlay_words[KNTWR_OVL_FOREIGN_HOOK_IMAGE_BYTES] +
        r->overlay_words[KNTWR_OVL_NV_UMD_IMAGE_BYTES] +
        r->overlay_words[KNTWR_OVL_NV_DRIVER_STACK_BYTES];
    r->have_overlay = TRUE;
    memcpy(r->last.overlay_words, r->overlay_words, sizeof r->overlay_words);
    if (print) print_overlay_report(r);
}

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

/* A dying process terminates every one of its threads, a remote call's thread included, with the process exit status as
   the thread exit code.  That status is not the function's return value, so remote_call classifies a finished thread against
   the process before it hands the exit code to its caller.  The wait ceiling matches the other post-termination waits. */
enum { kDeathSettleMs = 5000 };

static const wchar_t *exit_status_name(DWORD s)
{
    switch (s) {
    case 0xC0000005u: return L" STATUS_ACCESS_VIOLATION";
    case 0xC000001Du: return L" STATUS_ILLEGAL_INSTRUCTION";
    case 0xC0000094u: return L" STATUS_INTEGER_DIVIDE_BY_ZERO";
    case 0xC00000FDu: return L" STATUS_STACK_OVERFLOW";
    case 0xC0000135u: return L" STATUS_DLL_NOT_FOUND";
    case 0xC0000142u: return L" STATUS_DLL_INIT_FAILED";
    case 0xC00001A5u: return L" STATUS_INVALID_EXCEPTION_HANDLER";
    case 0xC0000374u: return L" STATUS_HEAP_CORRUPTION";
    case 0xC0000409u: return L" STATUS_STACK_BUFFER_OVERRUN";
    case 0x80000003u: return L" STATUS_BREAKPOINT";
    default: return L"";
    }
}

/* TRUE once the game process has terminated (object signalled, or its exit status already published). */
static BOOL game_terminated(Run *r)
{
    DWORD status;
    if (WaitForSingleObject(r->proc, 0) == WAIT_OBJECT_0) return TRUE;
    return GetExitCodeProcess(r->proc, &status) && status != STILL_ACTIVE;
}

/* Records an observed game exit (receipt game_exited / game_exit_code and the failure summary) without touching a live game. */
static void note_game_exit(Run *r)
{
    DWORD status;
    if (r->game_exited || !r->proc) return;
    if (!GetExitCodeProcess(r->proc, &status)) return;
    if (status == STILL_ACTIVE && WaitForSingleObject(r->proc, 0) != WAIT_OBJECT_0) return;
    r->game_exited = TRUE;
    r->game_exit = status;
}

/* The game died while a remote call was in flight: record its exit status and report that as the cause. */
static void report_remote_death(Run *r, const wchar_t *what)
{
    note_game_exit(r);
    if (r->game_exited)
        errsay(L"%ls: the game process exited while the remote call was running (exit status 0x%08lX%ls).\n", what,
               (unsigned long)r->game_exit, exit_status_name(r->game_exit));
    else
        errsay(L"%ls: the game process exited while the remote call was running.\n", what);
}

/* impossible_bits: exit-code bits a genuine return value never has (an HMODULE is 64 KiB aligned; the kntwr entry points
   return small codes).  A code with one of them set is a process exit status; the process object is then awaited, which
   settles the thread-versus-process signalling order without delaying any real result. */
static int remote_call(Run *r, uint32_t fn, uint32_t arg, DWORD timeout_ms, DWORD impossible_bits, DWORD *exit_code, DWORD *err)
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
        else if (game_terminated(r) ||
                 ((*exit_code & impossible_bits) && WaitForSingleObject(r->proc, kDeathSettleMs) == WAIT_OBJECT_0)) rc = RC_DIED;
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
static BOOL read_status(Run *r, kntwr_status *out, const wchar_t **why)
{
    int i;
    for (i = 0; i < 16; ++i) {
        uint32_t s1, s2;
        if (!remote_read(r->proc, r->state_addr, &s1, 4)) { *why = L"ReadProcessMemory on kntwr_state failed"; return FALSE; }
        if (s1 & 1) { Sleep(0); continue; }
        if (!remote_read(r->proc, r->state_addr, out, sizeof *out)) { *why = L"ReadProcessMemory on kntwr_state failed"; return FALSE; }
        if (!remote_read(r->proc, r->state_addr, &s2, 4)) { *why = L"ReadProcessMemory on kntwr_state failed"; return FALSE; }
        if (s1 != s2 || out->sequence != s1) continue;
        if (out->abi != KNTWR_ABI || out->size != sizeof *out) {
            *why = L"kntwr_state ABI/size does not match this launcher";
            return FALSE;
        }
        return TRUE;
    }
    *why = L"no coherent kntwr_state snapshot (sequence kept changing)";
    return FALSE;
}

static void print_status(const kntwr_status *s, uint32_t req)
{
    wchar_t a[192], m[192];
    mask_str(s->active_mask, a, 192);
    mask_str(req & ~s->active_mask, m, 192);
    say(L"  phase=%ls active=[%ls] missing=[%ls] generation=%lu tick=%lu workers=%lu error=0x%08lX detail=0x%08lX probe=0x%03lX\n",
        phase_name(s->phase), a, m, (unsigned long)s->generation, (unsigned long)s->tick, (unsigned long)s->workers,
        (unsigned long)s->error, (unsigned long)s->error_detail, (unsigned long)s->probe);
}

static void print_counters(const kntwr_status *s)
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
/* In-process crash capture (kntwr_status::crash_words, layout in kntwr_runtime.h). Prints nothing when no exception was recorded. */
static void print_crash(const kntwr_status *s)
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
        say(L" file=F:\\NTW2\\translated_code\\analysis\\crashdumps\\kntwr-%lu-%u.dmp", (unsigned long)s->pid, dumps - 1u);
    say(L" stack=[");
    for (i = 8; i < 24 && c[i]; ++i) say(L"%ls%08lX", i > 8 ? L" " : L"", (unsigned long)c[i]);
    say(L"]\n");
    say(L"  crash regs: esp=%08lX ebp=%08lX eax=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX\n",
        (unsigned long)c[24], (unsigned long)c[25], (unsigned long)c[26], (unsigned long)c[27], (unsigned long)c[28],
        (unsigned long)c[29], (unsigned long)c[30]);
}

/* --va-watch (kntwr_status::va_watch_words, layout enum kntwr_va_word). One line of the current sample; `ring` adds the last
   KNTWR_VA_RING_ENTRIES seconds oldest-first (the curve before a crash). Prints nothing when the sampler never ran. */
static void print_va_watch(const kntwr_status *s, BOOL ring)
{
    static const wchar_t *const phases[9] = {L"idle", L"verifying", L"waiting", L"activating", L"active", L"restoring", L"failed", L"stopped", L"?"};
    const uint32_t *v = s->va_watch_words;
    unsigned i;
    if (!v[KNTWR_VA_SAMPLES]) return;
    say(L"va: avail=%lu MiB (min %lu MiB at %lu s, %ls) largest_free=%lu MiB (min %lu) free_regions=%lu reserved=%lu MiB "
        L"committed=%lu MiB image=%lu MiB mapped=%lu MiB samples=%lu\n",
        (unsigned long)(((uint64_t)v[KNTWR_VA_AVAIL_HI] << 32 | v[KNTWR_VA_AVAIL_LO]) >> 20),
        (unsigned long)(((uint64_t)v[KNTWR_VA_MIN_AVAIL_HI] << 32 | v[KNTWR_VA_MIN_AVAIL_LO]) >> 20),
        (unsigned long)v[KNTWR_VA_MIN_UPTIME_S], phases[v[KNTWR_VA_MIN_PHASE] < 8u ? v[KNTWR_VA_MIN_PHASE] : 8u],
        (unsigned long)v[KNTWR_VA_LARGEST_FREE], (unsigned long)v[KNTWR_VA_MIN_LARGEST_FREE], (unsigned long)v[KNTWR_VA_FREE_REGIONS],
        (unsigned long)v[KNTWR_VA_RESERVED_MIB], (unsigned long)v[KNTWR_VA_COMMITTED_MIB], (unsigned long)v[KNTWR_VA_IMAGE_MIB],
        (unsigned long)v[KNTWR_VA_MAPPED_MIB], (unsigned long)v[KNTWR_VA_SAMPLES]);
    if (!ring) return;
    say(L"  va ring (uptime s: avail MiB / largest free MiB / phase), oldest first:");
    for (i = 0; i < KNTWR_VA_RING_ENTRIES; ++i) {
        const unsigned slot = (v[KNTWR_VA_RING_NEXT] + i) % KNTWR_VA_RING_ENTRIES;
        const uint32_t *e = v + KNTWR_VA_RING_BASE + slot * KNTWR_VA_RING_WORDS;
        if (i < KNTWR_VA_RING_ENTRIES - (v[KNTWR_VA_RING_NEXT] < KNTWR_VA_RING_ENTRIES ? v[KNTWR_VA_RING_NEXT] : KNTWR_VA_RING_ENTRIES)) continue;
        say(L" %lu:%lu/%lu/%ls", (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], phases[e[3] < 8u ? e[3] : 8u]);
    }
    say(L"\n");
}
/* Live crash hand-off: the faulting thread publishes the record and waits (bounded) for this acknowledgement before it lets the
   game's own handler terminate the process; the 200 ms status poll is the only chance to see the record in a dying process. */
static void observe_crash(Run *r, const kntwr_status *s)
{
    uint32_t tag, ack;
    SIZE_T wrote = 0;
    if (!s->crash_words[0]) return;
    tag = (s->crash_words[0] & 0xFFFFu) | (((s->crash_words[7] >> 12) & 3u) << 16) | 0x80000000u;
    if (tag == r->crash_tag) return;
    r->crash_tag = tag;
    if (!(s->crash_words[7] & 0x800u)) print_crash(s);   /* a repeat of an earlier signature is not printed until the final recap */
    ack = tag;
    WriteProcessMemory(r->proc, (LPVOID)(uintptr_t)(r->state_addr + (uint32_t)offsetof(kntwr_status, crash_words) + 31u * 4u),
                       &ack, sizeof ack, &wrote);
}
/* BRAIN2 v2 service IDs match native_brain2.h; no legacy replay-event labels. */
static const char *const k_brain2_services[KNTWR_BRAIN2_CENSUS_WORDS / 8u] = {
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
static const char *const k_ai_completion_metrics[KNTWR_AI_COMPLETION_WORDS] = { KNTWR_AI_COMPLETION_LABELS };
static const char *const k_ai_async2_metrics[KNTWR_AI_ASYNC2_WORDS] = { KNTWR_AI_ASYNC2_LABELS };
static const char *const k_ai_async2_route_metrics[KNTWR_AI_ASYNC2_ROUTE_WORDS] = { KNTWR_AI_ASYNC2_ROUTE_LABELS };
static const char *const k_ai_deferred_metrics[KNTWR_AI_DEFERRED_WORDS] = { KNTWR_AI_DEFERRED_LABELS };
static const char *const k_ai_ctrl_reuse_metrics[KNTWR_AI_CTRL_REUSE_WORDS] = { KNTWR_AI_CTRL_REUSE_LABELS };
static const char *const k_brain_retarget_jitter_metrics[4] = { KNTWR_AI_RETARGET_JITTER_LABELS };
static const char *const k_brain_target_cull_metrics[4] = { KNTWR_AI_TARGET_CULL_LABELS };
static const char *const k_ai_prepass_census_metrics[KNTWR_AI_PREPASS_CENSUS_WORDS] = { KNTWR_AI_PREPASS_CENSUS_LABELS };
static const char *const k_ai_poly_metrics[KNTWR_AI_POLY_WORDS] = { KNTWR_AI_POLY_LABELS };
static const char *const k_ai_record_test_metrics[KNTWR_AI_RECORD_TEST_WORDS] = { KNTWR_AI_RECORD_TEST_LABELS };
static const char *const k_ai_spiral_metrics[KNTWR_AI_SPIRAL_WORDS] = { KNTWR_AI_SPIRAL_LABELS };
static const char *const k_alloc_census_metrics[32] = { KNTWR_ALLOC_CENSUS_LABELS };
static const char *const k_arena_metrics[KNTWR_ARENA_WORDS] = { KNTWR_ARENA_LABELS };
static const char *const k_overlay_metrics[KNTWR_OVERLAY_WORDS] = { KNTWR_OVERLAY_LABELS };
static const char *const k_mounted_officer_metrics[KNTWR_MOUNTED_OFFICER_WORDS] = { KNTWR_MOUNTED_OFFICER_LABELS };
/* --engage-census (src/ai/kntwr_engage_census.h): header words 0..30, histograms 32..247, 20-word rows from 256. */
#define EC_HDR 31u
#define EC_HALT_RATIO 32u
#define EC_HALT_METRES 54u
#define EC_FIRE_RATIO 76u
#define EC_MOVING_ALL 98u
#define EC_MOVING_B0 128u
#define EC_MOVING_B1 158u
#define EC_MOVING_B4 188u
#define EC_MOVING_OTHER 218u
#define EC_ROW_WORDS 20u
#define EC_FIRST_ROWS 256u
#define EC_DEEP_ROWS 896u
#define EC_RING_ROWS 1536u
#define EC_ROWS 32u
#define EC_STILL_ALL 2176u
#define EC_STILL_FIRING 2206u
#define EC_CLASS_STATS 2236u
#define EC_SIDE_VAL 2268u
#define EC_SIDE_WORDS 32u
#define EC_TRACE 2336u
#define EC_TRACE_WORDS 8u
#define EC_TRACE_ROWS 512u
#define EC_FIDX_HIST 6432u
#define EC_DIAG_UNITS 6442u
#define EC_OBJ_VT 6456u
#define EC_ROW_VT 6472u
#define EC_SIDE_DIAG 6512u
#define EC_SIDE_DIAG_WORDS 160u
static float ec_f(uint32_t u)
{
    float f;
    memcpy(&f, &u, sizeof f);
    return f;
}
static const char *const k_engage_census_metrics[EC_HDR] = {
    "version", "flags", "ticks", "ai_units", "halts", "fire_starts", "faults", "bad_member", "enemyless", "table_full", "native_calls", "cost_us_total", "cost_us_max",
    "last_model_tick", "ai_sides_last", "ai_units_last", "enemy_units_last", "dm_computed", "moving_in_range", "inactive_units", "no_missile", "bad_graph", "table_used",
    "first_count", "deep_count", "events_total", "model_changes", "image_delta", "native_skipped", "faults_per_unit", "battle_faults" };
/* Percentile (0..1) of a histogram of `bins` equal-width bins plus one overflow bin; the bin centre, or bins*step when it lands in the overflow. */
static double ec_percentile(const uint32_t *h, unsigned bins, double step, double pct, unsigned long *total_out)
{
    unsigned long total = 0, run = 0;
    unsigned i;
    for (i = 0; i <= bins; ++i) total += h[i];
    if (total_out) *total_out = total;
    if (!total) return -1.0;
    for (i = 0; i <= bins; ++i) {
        run += h[i];
        if ((double)run >= pct * (double)total) return i < bins ? ((double)i + 0.5) * step : (double)bins * step;
    }
    return (double)bins * step;
}
static void print_engage_census_line(const uint32_t *w)
{
    unsigned long nh = 0, nm = 0;
    double h10, h50, m10, m50;
    if (!w[0]) return;
    h10 = ec_percentile(w + EC_HALT_RATIO, 20, 0.1, 0.10, &nh);
    h50 = ec_percentile(w + EC_HALT_RATIO, 20, 0.1, 0.50, NULL);
    m10 = ec_percentile(w + EC_MOVING_ALL, 30, 0.05, 0.10, &nm);
    m50 = ec_percentile(w + EC_MOVING_ALL, 30, 0.05, 0.50, NULL);
    say(L"  engage_census: ticks=%lu ai_units=%lu halts=%lu fire_starts=%lu faults=%lu bad_member=%lu table_full=%lu cost_us total=%lu max=%lu | halt dM/range n=%lu p10=%.2f median=%.2f | "
        L"moving-in-range n=%lu dM/range p10=%.2f median=%.2f%ls\n",
        (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[9],
        (unsigned long)w[11], (unsigned long)w[12], nh, h10, h50, nm, m10, m50, (w[1] & 2u) ? L" [DISABLED by fault]" : L"");
    {
        unsigned sd;
        for (sd = 0; sd < 2; ++sd) {
            const uint32_t *v = w + EC_SIDE_VAL + EC_SIDE_WORDS * sd;
            const uint32_t *x = w + EC_SIDE_DIAG + EC_SIDE_DIAG_WORDS * sd;
            say(L"  engage_census side%u(raw=%lu %ls): unit_ticks=%lu moving=%lu firing=%lu max_simul_firing=%lu live_units=%lu live_members=%lu firing_now=%lu | halts=%lu "
                L"fire_starts=%lu atk30=%lu atk2C=%lu ever(firing=%lu atk30=%lu atk2C=%lu)\n", sd, (unsigned long)x[143], v[0] ? L"AI" : L"non-AI", (unsigned long)v[1], (unsigned long)v[2],
                (unsigned long)v[3], (unsigned long)v[4], (unsigned long)v[5], (unsigned long)v[6], (unsigned long)v[7], (unsigned long)x[134], (unsigned long)x[135],
                (unsigned long)x[136], (unsigned long)x[137], (unsigned long)x[140], (unsigned long)x[141], (unsigned long)x[142]);
        }
        say(L"  engage_census: ever_firing_nonart=%lu art_halts=%lu art_fire_starts=%lu trace_samples=%lu atk30_events=%lu atk2C_events=%lu firing_calls=%lu firing_true=%lu "
            L"diag_units=%lu\n", (unsigned long)w[250], (unsigned long)w[31], (unsigned long)w[248], (unsigned long)w[249], (unsigned long)w[251], (unsigned long)w[252],
            (unsigned long)w[6448], (unsigned long)w[6449], (unsigned long)w[EC_DIAG_UNITS]);
    }
}
/* --ai-ctrl-* (src/ai/kntwr_ai_ctrl_batch.h, src/ai/kntwr_ai_ctrl_geometry.h): one line, labelled words 0..23 (A: batch/histogram, B: geometry).
   Words 16..23 are the geometry half only when no brain lever repurposes them (--brain-target-cull[-shadow] words 16..19,
   --brain-retarget-jitter 20..23 have their own print lines and receipt objects). */
static void print_ai_ctrl(const uint32_t *w, uint32_t ai_ctrl_flags)
{
    const unsigned count = (ai_ctrl_flags & KNTWR_AI_BRAIN_STEP_BITS) ? 16u : 24u;
    unsigned i;
    if (!(w[15] & KNTWR_AI_CTRL_MODE_MASK)) return;
    say(L"  ai_ctrl: flags=0x%lX latched=0x%lX", (unsigned long)(w[15] & 0xFFu), (unsigned long)(w[15] >> 8));
    for (i = 0; i < count; ++i)
        if (i != 15) say(L" %hs=%lu", k_ai_ctrl_reuse_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
static double pct(uint32_t part, uint32_t whole) { return whole ? 100.0 * (double)part / (double)whole : 0.0; }
/* --ai-prepass-census / --ai-presize (src/ai/kntwr_planner_prepass.h): per-think verdict lines, then every nonzero labelled word. */
static void print_ai_prepass(const uint32_t *w)
{
    unsigned i;
    uint32_t scopes = w[1], walks = w[4], classified = w[6] + w[7];
    if (!w[0]) return;
    if (w[63] & KNTWR_AI_PREPASS_CENSUS) {
        static const char *const cls[5] = { "<=8ms", "<=32ms", "<=128ms", "<=512ms", ">512ms" };
        say(L"  ai_prepass census: think_scopes=%lu node_thinks=%lu child_thinks=%lu walks=%lu queries/think=%.1f distinct/think=%.1f "
            L"duplicate%%=%.1f unsupported=%lu overflow=%lu max_walks/think=%lu max_distinct/think=%lu\n",
            (unsigned long)scopes, (unsigned long)w[2], (unsigned long)w[3], (unsigned long)walks,
            scopes ? (double)walks / scopes : 0.0, scopes ? (double)w[6] / scopes : 0.0, pct(w[7], classified),
            (unsigned long)w[9], (unsigned long)w[10], (unsigned long)w[11], (unsigned long)w[12]);
        say(L"  ai_prepass walk time: walk_us=%lu (gather %.1f%%, traversal %.1f%%) think_us=%lu walk_share_of_think=%.1f%% "
            L"polygon_tests=%lu res_al0=%lu res_al1=%lu gathered/walk=%.1f\n",
            (unsigned long)w[16], pct(w[17], w[16]), pct(w[18], w[16]), (unsigned long)w[14], pct(w[16], w[14]),
            (unsigned long)w[20], (unsigned long)w[21], (unsigned long)w[22], walks ? (double)w[23] / walks : 0.0);
        for (i = 0; i < 5; ++i)
            say(L"  ai_prepass think class %hs: thinks=%lu think_us=%lu walk_us=%lu walk_share=%.1f%%\n", cls[i],
                (unsigned long)w[40 + 3 * i], (unsigned long)w[41 + 3 * i], (unsigned long)w[42 + 3 * i],
                pct(w[42 + 3 * i], w[41 + 3 * i]));
        say(L"  ai_prepass D1: checked=%lu verdict=%hs other_child_thinks=%lu other_words=%lu list_changed=%lu self_thinks=%lu "
            L"self_words=%lu truncated=%lu\n",
            (unsigned long)w[28], w[29] ? "CROSS_TALK" : "no_cross_talk", (unsigned long)w[29], (unsigned long)w[30],
            (unsigned long)w[31], (unsigned long)w[32], (unsigned long)w[33], (unsigned long)w[34]);
        say(L"  ai_prepass world: same_key_diff_list=%lu same_key_same_list=%lu verdict=%hs\n", (unsigned long)w[35],
            (unsigned long)w[36], w[35] ? "WORLD_CHANGES_BETWEEN_IDENTICAL_QUERIES" : "stable");
    }
    say(L"  ai_prepass: flags=0x%lX", (unsigned long)w[63]);
    for (i = 0; i < KNTWR_AI_PREPASS_CENSUS_WORDS; ++i)
        if (i != 63 && w[i]) say(L" %hs=%lu", k_ai_prepass_census_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
/* --ai-poly-shadow / --ai-poly (src/ai/kntwr_planner_search.h): one verdict line, then every nonzero labelled word. */
static void print_ai_poly(const uint32_t *w, uint32_t thinks)
{
    unsigned i;
    if (!w[0]) return;
    say(L"  ai_poly: mode=%hs calls=%lu served=%.1f%% fallback kind=%lu fp_state=%lu domain=%lu walk_cap=%lu busy=%lu mean_vertices=%.1f max_vertices=%lu",
        w[1] == 1 ? "shadow" : "live", (unsigned long)w[2], pct(w[3], w[2]), (unsigned long)w[4], (unsigned long)w[5], (unsigned long)w[6],
        (unsigned long)w[7], (unsigned long)w[25], w[3] ? (double)w[13] / w[3] : 0.0, (unsigned long)w[14]);
    if (w[1] == 1)
        say(L" shadow_compares=%lu mismatch_al=%lu mismatch_x87=%lu mismatch_mxcsr=%lu verdict=%hs", (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10],
            (unsigned long)w[11], (w[9] || w[10] || w[11]) ? "MISMATCH" : "bit_identical");
    /* Within-run gain estimate (rdtsc kilocycles): native cost of the served calls = served_fast * sampled_native / sampled_fast. */
    if (w[26] && w[28] && w[29] && w[31]) {
        const double est_native = (double)w[26] * (double)w[27] / (double)w[28];
        const double saved_ms = (est_native - (double)w[26]) * 1024.0 / ((double)w[31] * 1000.0);
        say(L"\n  ai_poly gain: sampled=%lu S=%.2f served_fast=%.1f ms est_native_served=%.1f ms fallback_native=%.1f ms served_time_share=%.1f%% est_saved=%.1f ms",
            (unsigned long)w[29], (double)w[27] / (double)w[28], (double)w[26] * 1024.0 / ((double)w[31] * 1000.0),
            est_native * 1024.0 / ((double)w[31] * 1000.0), (double)w[30] * 1024.0 / ((double)w[31] * 1000.0),
            100.0 * est_native / (est_native + (double)w[30]), saved_ms);
        if (thinks) say(L" per_think=%.2f ms (thinks=%lu)", saved_ms / (double)thinks, (unsigned long)thinks);
    }
    say(L"\n  ai_poly words:");
    for (i = 0; i < KNTWR_AI_POLY_WORDS; ++i)
        if (w[i]) say(L" %hs=%lu", k_ai_poly_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
/* --ai-record-test-shadow / --ai-record-test (src/ai/kntwr_record_test.h): ai_prepass_words[32..59]; one verdict line, the gain line, every nonzero word. */
static void print_ai_record_test(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"  ai_record_test: mode=%hs slot_routed=%lu slot_unrouted=%lu calls=%lu served=%.1f%% fallback kind=%lu fp_state=%lu domain=%lu walk_cap=%lu busy=%lu"
        L" mean_records=%.1f max_records=%lu",
        w[1] == 1 ? "shadow" : "live", (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], pct(w[5], w[4]), (unsigned long)w[6], (unsigned long)w[7],
        (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10], w[5] ? (double)w[16] / w[5] : 0.0, (unsigned long)w[17]);
    say(L" shadow_compares=%lu mismatch_al=%lu mismatch_x87=%lu mismatch_mxcsr=%lu verdict=%hs", (unsigned long)w[11], (unsigned long)w[12], (unsigned long)w[13],
        (unsigned long)w[14], (w[12] || w[13] || w[14]) ? "MISMATCH" : "bit_identical");
    if (w[23]) {
        const double ms_per_kc = 1024.0 / ((double)w[23] * 1000.0);
        if (w[18] && w[20] && w[21]) {
            const double est_native = (double)w[18] * (double)w[19] / (double)w[20];
            say(L"\n  ai_record_test gain: sampled=%lu S=%.2f served_fast=%.1f ms est_native_served=%.1f ms fallback_native=%.1f ms est_saved=%.1f ms",
                (unsigned long)w[21], (double)w[19] / (double)w[20], (double)w[18] * ms_per_kc, est_native * ms_per_kc, (double)w[22] * ms_per_kc,
                (est_native - (double)w[18]) * ms_per_kc);
        }
        say(L"\n  ai_record_test route: entry_total=%.1f ms entry_max=%.3f ms served_fast_us=%.1f", (double)w[24] * ms_per_kc, (double)w[25] / 1000.0,
            (double)w[18] * ms_per_kc * 1000.0);
    }
    say(L"\n  ai_record_test words:");
    for (i = 0; i < KNTWR_AI_RECORD_TEST_WORDS; ++i)
        if (w[i]) say(L" %hs=%lu", k_ai_record_test_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
/* --ai-claim-once[-census] (src/ai/kntwr_claim_once.h): ai_ctrl_reuse_words[24..31] (calls, entries, masked, calls_masked, refused_state, refused_other, packed, hash). */
static void print_ai_claim_once(const uint32_t *w)
{
    if (!w[24]) return;
    say(L"  ai_claim_once: calls=%lu entries=%lu (%.2f/call, max %lu) masked_recomputes=%lu calls_masked=%lu refused_state=%lu refused_other=%lu"
        L" no_final_tail=%lu hashed_calls=%lu hash=0x%08lX\n",
        (unsigned long)w[24], (unsigned long)w[25], (double)w[25] / w[24], (unsigned long)(w[30] & 0xFFu), (unsigned long)w[26], (unsigned long)w[27],
        (unsigned long)w[28], (unsigned long)w[29], (unsigned long)((w[30] >> 8) & 0xFFu), (unsigned long)(w[30] >> 16), (unsigned long)w[31]);
}
/* --brain-retarget-jitter (src/brain/kntwr_retarget_jitter.h): ai_ctrl_reuse_words[20..23] (tracker_calls, losses, jittered, delay_sum). */
static void print_brain_retarget_jitter(const uint32_t *w)
{
    if (!w[20]) return;
    say(L"  brain_retarget_jitter: tracker_calls=%lu losses=%lu (%.3f%% of calls) jittered=%lu (%.1f%% of losses) delay_sum=%lu mean_delay=%.2f ticks (of the jittered)\n",
        (unsigned long)w[20], (unsigned long)w[21], pct(w[21], w[20]), (unsigned long)w[22], pct(w[22], w[21]), (unsigned long)w[23], w[22] ? (double)w[23] / w[22] : 0.0);
}
/* --brain-target-cull[-shadow] (src/brain/kntwr_target_cull.h): ai_ctrl_reuse_words[16..19] (calls, candidates, predicates, packed mismatch/flag bytes). */
static void print_brain_target_cull(const uint32_t *w)
{
    if (!w[16]) return;
    say(L"  brain_target_cull: loops=%lu candidates=%lu (%.1f/loop) predicates=%lu culled=%lu (%.2f%% of candidates; flag searches %lu) mismatches: result=%lu score=%lu scratch=%lu\n",
        (unsigned long)w[16], (unsigned long)w[17], w[16] ? (double)w[17] / w[16] : 0.0, (unsigned long)w[18],
        (unsigned long)(w[17] > w[18] ? w[17] - w[18] : 0u), pct(w[17] > w[18] ? w[17] - w[18] : 0u, w[17]), (unsigned long)(w[19] >> 24),
        (unsigned long)(w[19] & 0xFFu), (unsigned long)((w[19] >> 8) & 0xFFu), (unsigned long)((w[19] >> 16) & 0xFFu));
}
/* --ai-spiral-census / --ai-spiral-cap-m (src/ai/kntwr_spiral.h): ladder stages, spiral exits, fallback entries-per-call, then every nonzero word. */
static void print_ai_spiral(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"  ai_spiral: cap=%lu m ladders=%lu spot=%lu clamp=%lu ring=%lu spiral=%lu none=%lu | spirals=%lu found=%lu capped=%lu (%.1f%%) edge=%lu"
        L" candidates=%lu (%.1f/spiral, max %lu) rings=%lu max_radius=%lu m",
        (unsigned long)w[1], (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5], (unsigned long)w[6],
        (unsigned long)w[7], (unsigned long)w[9], (unsigned long)w[12], (unsigned long)w[13], pct(w[13], w[9]), (unsigned long)w[14],
        (unsigned long)w[10], w[9] ? (double)w[10] / w[9] : 0.0, (unsigned long)w[16], (unsigned long)w[11], (unsigned long)w[15]);
    say(L"\n  ai_spiral fallback: calls=%lu entries=%lu (E=0:%lu 1:%lu 2:%lu 3-4:%lu 5-8:%lu >8:%lu, max %lu) tail_runs=%lu same_tick=%lu memo=%lu"
        L" ladders_in_fallback=%lu spirals_in_fallback=%lu",
        (unsigned long)w[17], (unsigned long)w[24], (unsigned long)w[18], (unsigned long)w[19], (unsigned long)w[20], (unsigned long)w[21],
        (unsigned long)w[22], (unsigned long)w[23], (unsigned long)w[25], (unsigned long)w[26], (unsigned long)w[27], (unsigned long)w[28],
        (unsigned long)w[29], (unsigned long)w[30]);
    say(L"\n  ai_spiral words:");
    for (i = 0; i < KNTWR_AI_SPIRAL_WORDS; ++i)
        if (w[i]) say(L" %hs=%lu", k_ai_spiral_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
/* Per-unit brain Stage A agreement table (native_unit_brain.h, version 2). held = this stage's UnitDecision (the
   unit's strict-majority record of the previous stage, valid while the unit-level input signature is unchanged),
   over non-exception main-class soldiers. tick = this stage's own strict majority over its voters (main-class
   non-exception soldiers), counted only in unit-stages that have one; voters of unit-stages without a strict majority
   are tick_none (neither agreement nor disagreement). exception = held comparison over exception and
   unresolved-role soldiers (Stage B would run those natively). */
static void print_unit_brain(const uint32_t *u)
{
    static const char *const header[] = { KNTWR_BRAIN_UNIT_HEADER_LABELS };
    static const char *const fields[] = { KNTWR_BRAIN_UNIT_FIELD_LABELS };
    static const char *const exceptions[] = { KNTWR_BRAIN_UNIT_EXCEPTION_LABELS };
    static const char *const census[] = { KNTWR_BRAIN_UNIT_CENSUS_LABELS };
    static const char *const roles[] = { KNTWR_BRAIN_UNIT_ROLE_LABELS };
    static const char *const tail[] = { KNTWR_BRAIN_UNIT_TAIL_LABELS };
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
    static const char *const reasons[] = { KNTWR_ARMY_UNIT_REASON_LABELS };
    static const char *const details[] = { KNTWR_ARMY_UNIT_DETAIL_LABELS };
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
/* --brain-s0 attribution (src/brain2/native_brain_s0.h). Occurrences are sampled uniformly by deterministic strata, so a
   row's population total is (occurrences / timed occurrences) x its timed cycles after the in-build calibration is
   subtracted: gate rows excl - sampled*o - children*c, incl - sampled*o - descendants*(o+c); step rows use the root floor r
   instead of o. stat = one standard error of that total from the per-occurrence second moments (finite-population
   corrected); cal = the same subtraction moved by one robust sigma of each calibration (a conservative systematic bound:
   the calibration ran warm, the game runs cold). share = exclusive / total +0C step inclusive. */
typedef struct {
    double calls, sampled, excl_ms, excl_stat, excl_cal, incl_ms, incl_stat, share;
} BrainS0Row;
typedef struct {
    double stages, occurrences, timed, cycles_per_ms, o, so, c, sc, r, sr;
    double step_ms, site6_ms, overhead_ms;
    BrainS0Row rows[KNTWR_BRAIN_S0_ROWS];
} BrainS0Table;
static uint64_t s0_u64(const uint32_t *p) { return ((uint64_t)p[1] << 32) | p[0]; }
static double s0_f64(const uint32_t *p) { double d; uint64_t v = s0_u64(p); memcpy(&d, &v, sizeof d); return d; }
static int s0_dispatch_row(unsigned r) { return (r >= 6 && r <= 16) || r == 29 || r == 30; }
static int brain_s0_table(const uint32_t *w, BrainS0Table *t)
{
    const double qpc = (double)s0_u64(w + 12), freq = (double)s0_u64(w + 14), tsc = (double)s0_u64(w + 10);
    double scale, step_incl = 0.0, pass = w[23] / 16.0, dispatch = w[24] / 16.0, decide = w[25] / 16.0;
    double static_calls = 0.0, dispatch_calls = 0.0, timed_frames = 0.0;
    unsigned r;
    memset(t, 0, sizeof *t);
    t->stages = w[4]; t->occurrences = (double)s0_u64(w + 5); t->timed = w[7];
    t->cycles_per_ms = (qpc > 0.0 && freq > 0.0 && tsc > 0.0) ? tsc / (qpc / freq * 1000.0) : w[16];
    t->o = w[17] / 16.0; t->so = w[18] / 16.0; t->c = w[19] / 16.0; t->sc = w[20] / 16.0;
    t->r = w[21] / 16.0; t->sr = w[22] / 16.0;
    if (!w[4] || !w[7] || t->cycles_per_ms <= 0.0) return 0;
    scale = t->occurrences / t->timed;
    for (r = 0; r < KNTWR_BRAIN_S0_ROWS; ++r) {
        const uint32_t *q = w + KNTWR_BRAIN_S0_HEADER_WORDS + r * KNTWR_BRAIN_S0_ROW_WORDS;
        const double s = q[2], ch = q[4], de = q[5], incl = (double)s0_u64(q + 6);
        const double excl = (double)(int64_t)s0_u64(q + 8), sq_incl = s0_f64(q + 10), sq_excl = s0_f64(q + 12);
        const int step = r <= 2;
        const double floor = step ? t->r : t->o, floor_sigma = step ? t->sr : t->so;
        const double unit = scale / t->cycles_per_ms / t->stages, n = t->timed, N = t->occurrences;
        const double fpc = N > n ? sqrt((N - n) / N) : 0.0;
        double var_e = n > 1.0 ? (sq_excl - excl * excl / n) / (n - 1.0) : 0.0;
        double var_i = n > 1.0 ? (sq_incl - incl * incl / n) / (n - 1.0) : 0.0;
        BrainS0Row *row = &t->rows[r];
        if (var_e < 0.0) var_e = 0.0;
        if (var_i < 0.0) var_i = 0.0;
        row->calls = (double)s0_u64(q) / t->stages; row->sampled = s;
        row->excl_ms = (excl - s * floor - ch * t->c) * unit;
        row->incl_ms = (incl - s * floor - de * (t->o + t->c)) * unit;
        row->excl_stat = N * sqrt(var_e / n) * fpc / t->cycles_per_ms / t->stages;
        row->incl_stat = N * sqrt(var_i / n) * fpc / t->cycles_per_ms / t->stages;
        row->excl_cal = (s * floor_sigma + ch * t->sc) * unit;
        if (step) step_incl += row->incl_ms;
        else if (r != 18 && r != 20) {
            if (s0_dispatch_row(r)) dispatch_calls += (double)s0_u64(q); else static_calls += (double)s0_u64(q);
            timed_frames += s;
        } else timed_frames += s;
    }
    for (r = 0; r < KNTWR_BRAIN_S0_ROWS; ++r) t->rows[r].share = step_incl > 0.0 ? t->rows[r].excl_ms / step_incl : 0.0;
    t->step_ms = step_incl;
    t->site6_ms = (double)s0_u64(w + 8) / t->cycles_per_ms / t->stages;
    t->overhead_ms = (static_calls * pass + dispatch_calls * dispatch + t->occurrences * decide +
                      timed_frames * (t->o + t->c) + t->timed * t->r) / t->cycles_per_ms / t->stages;
    return 1;
}
static void print_brain_s0(const uint32_t *w)
{
    static const char *const rows[] = { KNTWR_BRAIN_S0_ROW_LABELS };
    static const unsigned depth[] = { KNTWR_BRAIN_S0_ROW_DEPTHS };
    static const char *const states[] = { "not started", "running", "refused: no RDTSCP/invariant TSC", "refused: BRAIN_S0 clones missing" };
    BrainS0Table t;
    unsigned r;
    if (!w[1]) return;
    say(L"  brain S0 attribution (v%lu, %hs; 1/%lu strata of (stage, unit ordinal, member ordinal)):\n",
        (unsigned long)w[0], w[2] < 4 ? states[w[2]] : "?", 1ul << w[3]);
    if (!brain_s0_table(w, &t)) { say(L"    no timed stage yet (stages=%lu, timed occurrences=%lu)\n", (unsigned long)w[4], (unsigned long)w[7]); return; }
    say(L"    stages=%.0f occurrences=%.0f (%.1f/stage) timed=%.0f; TSC %.1f MHz (QPC span; start calibration %lu kHz)\n",
        t.stages, t.occurrences, t.occurrences / t.stages, t.timed, t.cycles_per_ms / 1000.0, (unsigned long)w[16]);
    say(L"    calibration (cycles, median +- robust sigma): gate floor o %.1f+-%.1f, nest c %.1f+-%.1f, root r %.1f+-%.1f; "
        L"unsampled pass %.2f, dispatch %.2f, stratum %.2f; depth max %lu overflow %lu, abandoned %lu, unit overflow %lu, nested %lu\n",
        t.o, t.so, t.c, t.sc, t.r, t.sr, w[23] / 16.0, w[24] / 16.0, w[25] / 16.0, (unsigned long)w[28],
        (unsigned long)w[26], (unsigned long)w[27], (unsigned long)w[29], (unsigned long)w[30]);
    say(L"    +0C step total %.3f ms/stage vs site-6 worklist inclusive %.3f ms/stage (step %.1f%% of site 6); "
        L"S0 overhead est. %.3f ms/stage\n", t.step_ms, t.site6_ms, t.site6_ms > 0.0 ? 100.0 * t.step_ms / t.site6_ms : 0.0,
        t.overhead_ms);
    say(L"    %-34hs %11hs %8hs %9hs %8hs %8hs %9hs %8hs %7hs\n", "mechanic (exclusive = minus timed children)", "calls/stage",
        "timed", "excl ms", "+-stat", "+-cal", "incl ms", "+-stat", "share");
    for (r = 0; r < KNTWR_BRAIN_S0_ROWS; ++r) {
        const BrainS0Row *x = &t.rows[r];
        char name[48];
        if (!x->calls && !x->sampled) continue;
        _snprintf_s(name, sizeof name, _TRUNCATE, "%*s%s", (int)(2 * depth[r]), "", rows[r]);
        say(L"    %-34hs %11.1f %8.0f %9.4f %8.4f %8.4f %9.4f %8.4f %6.2f%%\n", name, x->calls, x->sampled, x->excl_ms,
            x->excl_stat, x->excl_cal, x->incl_ms, x->incl_stat, 100.0 * x->share);
    }
    say(L"    not separately timed (inside a parent's exclusive): engage policy 658C62/658FDE/6590FC and fire latches "
        L"658DEF/658DFB in driver_658C50; 660180/660230 have no step call site; animation select 66B7E0/66B990 "
        L"(fsm.vt+40/+44) in posture_10FC370; 64DE80 internals; other node classes' order calls\n");
}
/* --brain-locality census (src/brain2/native_brain_locality.h; analysis/checkpoints/BrainLocality.md). The words share the
   S0 status row. Step cycles have the in-build bracket floor subtracted. gain = cold mean - warm/prefetched mean (A is
   the touched or prefetched arm); net = gain - touch cycles (warm only; the prefetch arms include their issue cost in the
   bracket). ms per stage = per-occurrence cycles x members per stage / TSC rate (uniform occurrence sampling). */
typedef struct {
    double stages, deep, members, per_stage, timed, cpm, floor_c, loop_ms, deep_ms, cheap;
    double n[2], mean[2], se[2], median[2], touch_mean, touch_se;
    double gain, gain_se, net, net_se, gain_ms, net_ms, touch_ms, cold_ms;
    double slope, intercept;
} BrainLocStats;
static double loc_bin_lo(unsigned b) { return b < 32u ? 32.0 * b : 1024.0 * pow(2.0, (b - 32u) * 6.0 / 32.0); }
static double loc_median(const uint32_t *h, double n)
{
    double cum = 0.0;
    unsigned b;
    if (n <= 0.0) return 0.0;
    for (b = 0; b < KNTWR_BRAIN_LOC_HIST_BINS; ++b) {
        if (h[b] && cum + h[b] >= n / 2.0) {
            const double lo = loc_bin_lo(b), hi = b + 1u < KNTWR_BRAIN_LOC_HIST_BINS ? loc_bin_lo(b + 1u) : lo * 2.0;
            return lo + (hi - lo) * (n / 2.0 - cum) / h[b];
        }
        cum += h[b];
    }
    return loc_bin_lo(KNTWR_BRAIN_LOC_HIST_BINS - 1u);
}
static int brain_loc_stats(const uint32_t *w, BrainLocStats *t)
{
    unsigned a, b;
    double sw = 0.0, sx = 0.0, sy = 0.0, sxx = 0.0, sxy = 0.0;
    memset(t, 0, sizeof *t);
    t->stages = w[4]; t->deep = w[5]; t->members = (double)s0_u64(w + 8); t->timed = w[10]; t->cpm = w[11];
    t->floor_c = w[12] / 16.0; t->cheap = w[18] / 16.0;
    if (!w[4] || t->cpm <= 0.0 || !t->members) return 0;
    t->per_stage = t->members / t->stages;
    t->loop_ms = (double)s0_u64(w + 14) / t->cpm / t->stages;
    t->deep_ms = t->deep > 0.0 ? (double)s0_u64(w + 16) / t->cpm / t->deep : 0.0;
    for (a = 0; a < KNTWR_BRAIN_LOC_ARMS; ++a) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_ARM_BASE + a * KNTWR_BRAIN_LOC_ARM_WORDS;
        const double n = q[0], sum = (double)s0_u64(q + 1), sq = s0_f64(q + 3);
        double var;
        t->n[a] = n;
        if (n <= 0.0) continue;
        t->mean[a] = sum / n;
        var = n > 1.0 ? (sq - sum * sum / n) / (n - 1.0) : 0.0;
        t->se[a] = sqrt(var > 0.0 ? var / n : 0.0);
        t->median[a] = loc_median(w + KNTWR_BRAIN_LOC_HIST_BASE + a * KNTWR_BRAIN_LOC_HIST_BINS, n);
        if (a == 1) {
            const double ts = (double)s0_u64(q + 5), tq = s0_f64(q + 7);
            t->touch_mean = ts / n;
            var = n > 1.0 ? (tq - ts * ts / n) / (n - 1.0) : 0.0;
            t->touch_se = sqrt(var > 0.0 ? var / n : 0.0);
        }
    }
    t->cold_ms = t->mean[0] * t->per_stage / t->cpm;
    if (t->n[0] > 0.0 && t->n[1] > 0.0) {
        t->gain = t->mean[0] - t->mean[1];
        t->gain_se = sqrt(t->se[0] * t->se[0] + t->se[1] * t->se[1]);
        t->net = t->gain - t->touch_mean;
        t->net_se = sqrt(t->gain_se * t->gain_se + t->touch_se * t->touch_se);
        t->gain_ms = t->gain * t->per_stage / t->cpm;
        t->net_ms = t->net * t->per_stage / t->cpm;
        t->touch_ms = t->touch_mean * t->per_stage / t->cpm;
    }
    for (b = 0; b < KNTWR_BRAIN_LOC_BUCKETS; ++b) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_BUCKET_BASE + b * KNTWR_BRAIN_LOC_BUCKET_WORDS;
        const double n = q[0], x = 4.0 * b + 2.0, y = n > 0.0 ? (double)s0_u64(q + 1) / n : 0.0;
        if (n <= 0.0) continue;
        sw += n; sx += n * x; sy += n * y; sxx += n * x * x; sxy += n * x * y;
    }
    if (sw > 0.0 && sxx * sw - sx * sx > 1e-9) {
        t->slope = (sxy * sw - sx * sy) / (sxx * sw - sx * sx);
        t->intercept = (sy - t->slope * sx) / sw;
    }
    return 1;
}
static const char *loc_mode_name(uint32_t configured)
{
    return (configured & 16u) ? "mark (ETW stage markers only)" :
           (configured & 2u) ? "census + warm-touch A/B" : (configured & 4u) ? "census + prefetch distance 1 A/B" :
           (configured & 8u) ? "census + prefetch distance 2/1 A/B" : "census";
}
static double loc_pct(double a, double b) { return b > 0.0 ? 100.0 * a / b : 0.0; }
static void print_brain_locality(const uint32_t *w)
{
    static const char *const types[] = { KNTWR_BRAIN_LOC_TYPE_LABELS };
    static const char *const states[] = { "not started", "running", "refused: no RDTSCP/invariant TSC", "refused: storage" };
    static const char *const arms[2][4] = { { "census (all timed)", "cold (B)", "cold (B)", "cold (B)" },
                                            { "", "warm (A)", "prefetch (A)", "prefetch (A)" } };
    static const unsigned cut[] = { 6, 12, 16, 20, 24, 32 };
    static const char *const cutn[] = { "<64 B", "<4 KiB", "<64 KiB", "<1 MiB", "<16 MiB", "any" };
    const uint32_t *sc = w + KNTWR_BRAIN_LOC_SCALAR_BASE, *dh = w + KNTWR_BRAIN_LOC_DELTA_BASE, *rh = w + KNTWR_BRAIN_LOC_RUN_BASE;
    BrainLocStats t;
    const unsigned mode = (w[1] & 2u) ? 1u : (w[1] & 4u) ? 2u : (w[1] & 8u) ? 3u : 0u;
    double pairs, cum;
    unsigned r, b;
    if (!w[1]) return;
    if (w[1] & 16u) {
        say(L"  brain locality mark (v%lu, %hs): pass-through runner (no census, touch or TSC), ETW provider {%hs}, event 1 = stage begin, "
            L"event 2 = stage end, UINT32 payload = 1-based stage ordinal; stages completed %lu\n", (unsigned long)w[0],
            w[2] < 4 ? states[w[2]] : "?", KNTWR_BRAIN_LOC_MARK_GUID_TEXT, (unsigned long)w[4]);
        return;
    }
    say(L"  brain locality census (v%lu, %hs, %hs; strata of (stage, occurrence ordinal): timed 1/%lu, deep stages 1/8, blocks of %lu):\n",
        (unsigned long)w[0], loc_mode_name(w[1]), w[2] < 4 ? states[w[2]] : "?", 1ul << w[3], (unsigned long)w[30]);
    if (!brain_loc_stats(w, &t)) { say(L"    no stage yet (stages=%lu, members=%.0f)\n", (unsigned long)w[4], (double)s0_u64(w + 8)); return; }
    say(L"    stages=%.0f (deep %.0f) members=%.0f (%.1f/stage, max %lu, last %lu) other-class=%.0f timed=%lu unreadable=%lu deep-overflow=%lu; "
        L"TSC %.1f MHz, bracket floor %.1f+-%.1f cycles\n", t.stages, t.deep, t.members, t.per_stage, (unsigned long)w[25],
        (unsigned long)w[27], (double)s0_u64(w + 6) - t.members, (unsigned long)w[10], (unsigned long)w[20], (unsigned long)w[21],
        t.cpm / 1000.0, t.floor_c, w[13] / 16.0);
    say(L"    runner loop %.3f ms/stage (inclusive of census bookkeeping; deep-stage analysis %.2f ms per deep stage is outside it); "
        L"post-step cheap path ~%.1f cycles/occurrence (unserialised RDTSC pair, indicative); prefetch lines issued %.0f, touch skipped %lu, "
        L"VirtualQuery %lu, diagnostic faults contained %lu\n", t.loop_ms, t.deep_ms, t.cheap,
        (double)(((uint64_t)sc[18] << 32) | w[23]), (unsigned long)w[22], (unsigned long)w[24], (unsigned long)w[26]);
    pairs = (double)s0_u64(sc);
    say(L"    worklist adjacency over %.0f consecutive pairs: same 4 KiB page %.2f%%, same 64 B line %.2f%%, same unit %.2f%%, "
        L"ascending %.2f%% / descending %.2f%% / equal %.2f%%; unit runs %lu (mean run %.1f men)\n", pairs,
        loc_pct(sc[2], pairs), loc_pct(sc[3], pairs), loc_pct(sc[4], pairs), loc_pct(sc[5], pairs), loc_pct(sc[6], pairs),
        loc_pct(sc[7], pairs), (unsigned long)sc[8], sc[8] ? pairs / sc[8] : 0.0);
    say(L"    |E_i - E_(i-1)| cumulative:");
    for (b = 0, cum = 0.0, r = 0; r < 6; ++r) {
        for (; b <= cut[r] && b < KNTWR_BRAIN_LOC_DELTA_BINS; ++b) cum += dh[b];
        say(L" %hs %.1f%%", cutn[r], loc_pct(cum, pairs));
    }
    say(L"\n    unit run length log2 histogram:");
    for (b = 0; b < KNTWR_BRAIN_LOC_RUN_BINS; ++b) if (rh[b]) say(L" %lu:%lu", 1ul << b, (unsigned long)rh[b]);
    say(L"\n");
    if (t.deep > 0.0) {
        const double invp = (double)s0_u64(sc + 11);
        say(L"    deep stages (%.0f, %.0f members): entity address span mean %.1f MiB (max %.1f MiB), entity base pages/stage %.0f (max %lu); "
            L"order inversions %.3f%% of pairs (random 50%%, address-sorted 0%%)\n", t.deep, (double)sc[15],
            sc[13] / t.deep / 1024.0, sc[14] / 1024.0, sc[16] / t.deep, (unsigned long)sc[17],
            invp > 0.0 ? 100.0 * (double)s0_u64(sc + 9) / invp : 0.0);
    }
    say(L"    mapped hot set per object type (static load map; lines/pages = distinct 64 B lines / 4 KiB pages; stage = per deep stage):\n");
    say(L"      %-14hs %8hs %9hs %9hs %12hs %11hs %11hs %9hs\n", "object", "present", "lines/man", "pages/man", "stage lines", "stage pages",
        "max lines", "MiB");
    for (r = 0; r < KNTWR_BRAIN_LOC_TYPES; ++r) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_TYPE_BASE + r * KNTWR_BRAIN_LOC_TYPE_WORDS;
        if (!q[0] && !q[1]) continue;
        say(L"      %-14hs %7.1f%% %9.2f %9.2f %12.0f %11.0f %11lu %9.2f\n", types[r], loc_pct(q[0], (double)sc[15]),
            q[1] ? (double)q[2] / q[1] : 0.0, q[1] ? (double)q[3] / q[1] : 0.0, t.deep > 0.0 ? q[4] / t.deep : 0.0,
            t.deep > 0.0 ? q[5] / t.deep : 0.0, (unsigned long)q[6], t.deep > 0.0 ? q[4] / t.deep * 64.0 / 1048576.0 : 0.0);
    }
    say(L"    step cycles, %hs arm: n=%.0f mean %.1f +-%.1f median %.0f cycles (%.0f ns mean) => step %.3f ms/stage (%.1f%% of the runner loop)\n",
        arms[0][mode], t.n[0], t.mean[0], t.se[0], t.median[0], t.mean[0] / t.cpm * 1e6, t.cold_ms, loc_pct(t.cold_ms, t.loop_ms));
    say(L"    cost vs hot lines not touched by the previous occurrence (cold arm; bucket width 4 lines):\n");
    for (b = 0; b < KNTWR_BRAIN_LOC_BUCKETS; ++b) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_BUCKET_BASE + b * KNTWR_BRAIN_LOC_BUCKET_WORDS;
        const double bn = q[0], bs = (double)s0_u64(q + 1), bq = s0_f64(q + 3);
        double var;
        if (bn <= 0.0) continue;
        var = bn > 1.0 ? (bq - bs * bs / bn) / (bn - 1.0) : 0.0;
        say(L"      new %2lu-%2lu: n=%8.0f mean %8.1f +-%6.1f cycles\n", (unsigned long)(4 * b), (unsigned long)(4 * b + 3), bn, bs / bn,
            sqrt(var > 0.0 ? var / bn : 0.0));
    }
    say(L"      linear fit: %.1f cycles intercept + %.2f cycles per new line (weighted by n)\n", t.intercept, t.slope);
    if (mode && t.n[1] > 0.0) {
        say(L"    A/B (%hs): %hs n=%.0f mean %.1f +-%.1f median %.0f vs %hs n=%.0f mean %.1f +-%.1f median %.0f cycles\n", loc_mode_name(w[1]),
            arms[1][mode], t.n[1], t.mean[1], t.se[1], t.median[1], arms[0][mode], t.n[0], t.mean[0], t.se[0], t.median[0]);
        if (mode == 1)
            say(L"      touch of every mapped hot line: %.1f +-%.1f cycles/occurrence (%.3f ms/stage if every man were touched)\n",
                t.touch_mean, t.touch_se, t.touch_ms);
        say(L"      measured miss cost on the mapped set (B - A) = %.1f +-%.1f cycles/occurrence = %.3f ms/stage over %.1f members\n",
            t.gain, t.gain_se, t.gain_ms, t.per_stage);
        say(L"      net gain after %hs = %.1f +-%.1f cycles/occurrence = %.3f ms/stage (%.1f%% of the cold step)\n",
            mode == 1 ? "the touch itself" : "the prefetch issue cost (inside the A bracket)", t.net, t.net_se, t.net_ms,
            loc_pct(t.net, t.mean[0]));
    }
}
/* --brain-unit-* (src/brain2/native_unit_policy.h header words 0..31 of brain_unit_policy_words; the fatigue half, words
   32..127, is src/brain2/native_unit_fatigue.h). */
static const char *unit_mode_name(uint32_t modes, unsigned mechanic)
{
    static const char *const names[] = { "off", "shadow", "live", "?" };
    return names[(modes >> (2u * mechanic)) & 3u];
}
static void print_unit_policy(const uint32_t *w)
{
    const double stages = w[2] ? (double)w[2] : 1.0, occ = (double)w[16] + (double)w[17];
    if (!w[1]) return;
    say(L"  brain unit policy (shared admission v%lu; fatigue %hs, posture %hs, engage %hs): stages=%lu, units selected=%lu rejected=%lu, "
        L"members selected=%lu refused (officers/crew/foreign) %lu\n", (unsigned long)w[0], unit_mode_name(w[1], 0),
        unit_mode_name(w[1], 1), unit_mode_name(w[1], 2), (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4],
        (unsigned long)w[5], (unsigned long)w[6]);
    say(L"    units admitted last stage fatigue/posture/engage = %lu/%lu/%lu; unit-stages admitted %lu/%lu/%lu, refused %lu/%lu/%lu; "
        L"drains %lu/%lu/%lu\n", (unsigned long)w[7], (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10],
        (unsigned long)w[11], (unsigned long)w[12], (unsigned long)w[13], (unsigned long)w[14], (unsigned long)w[15],
        (unsigned long)w[18], (unsigned long)w[19], (unsigned long)w[20]);
    say(L"    occurrences: unit-routed %lu, native %lu (%.1f%% routed); out-of-worklist members last stage %lu; generation bumps %lu "
        L"(members joined %lu, departed %lu), units retired %lu, selection passes %lu; faults %lu (last %lu)\n",
        (unsigned long)w[16], (unsigned long)w[17], occ > 0.0 ? 100.0 * w[16] / occ : 0.0, (unsigned long)w[26],
        (unsigned long)w[27], (unsigned long)w[30], (unsigned long)w[31], (unsigned long)w[28], (unsigned long)w[29],
        (unsigned long)w[21], (unsigned long)w[22]);
    say(L"    seam us per stage: last %lu max %lu mean %.1f (BeginStage + EndStage; QPC once per seam, never per man)\n",
        (unsigned long)w[23], (unsigned long)w[24], (double)w[25] / stages);
}
static void print_unit_fatigue(const uint32_t *f, const uint32_t *h)
{
    static const char *const labels[] = { KNTWR_UNIT_FATIGUE_LABELS };
    static const char *const classes[] = { "0 base+env", "1 stat3D0", "2 stat4F0", "3 melee", "4 stat1F0", "5 node20/6D0",
                                           "6 stat250", "7 stat2B0", "8 row-path", "9 stat370", "10 none", "other" };
    static const char *const dacc[] = { "0", "1", "2-3", "4-7", "8-15", "16-63", "64-255", ">=256" };
    const double stages = h[2] ? (double)h[2] : 1.0;
    unsigned i;
    if (!f[1]) return;
    say(L"  brain unit fatigue (S4 v%lu, %hs): one (acc, level) pair per unit generation, advanced once per stage; units admitted last "
        L"stage %lu refused %lu, admitted unit-stages %lu\n", (unsigned long)f[0], f[1] == 1 ? "shadow" : "live",
        (unsigned long)f[2], (unsigned long)f[4], (unsigned long)f[3]);
    say(L"    refused unit-stages by reason:");
    for (i = 0; i < 10; ++i) say(L" %hs=%lu", labels[5 + i] + 7, (unsigned long)f[5 + i]);
    say(L"\n    advances=%lu applies=%lu out_of_worklist_writes=%lu inits=%lu (generation inits %lu) resets=%lu drains=%lu retires=%lu "
        L"publish_skipped=%lu contract_misses=%lu faults=%lu (last %lu)\n", (unsigned long)f[21], (unsigned long)f[22],
        (unsigned long)f[23], (unsigned long)f[24], (unsigned long)f[36], (unsigned long)f[25], (unsigned long)f[26],
        (unsigned long)f[27], (unsigned long)f[35], (unsigned long)f[37], (unsigned long)f[28], (unsigned long)f[29]);
    say(L"    decide us per stage: last %lu max %lu mean %.1f; end us: last %lu mean %.1f\n", (unsigned long)f[30],
        (unsigned long)f[31], (double)f[32] / stages, (unsigned long)f[33], (double)f[34] / stages);
    say(L"    last unit %lu: acc %ld level %lu class %lu rate %ld\n", (unsigned long)f[94], (long)(int32_t)f[89],
        (unsigned long)f[90], (unsigned long)f[91], (long)(int32_t)f[92]);
    if (f[1] != 1) return;
    if (!f[40]) { say(L"    shadow: no admitted man observed yet\n"); return; }
    say(L"    shadow (unit pair vs the man's native pair after his native step; heterogeneous divergence is the approved deviation): "
        L"men=%lu acc equal %.2f%% level equal %.2f%% both equal %.2f%%\n", (unsigned long)f[40], 100.0 * f[41] / f[40],
        100.0 * f[43] / f[40], 100.0 * f[45] / f[40]);
    say(L"    |acc diff| buckets:");
    for (i = 0; i < 8; ++i) say(L" %hs:%lu", dacc[i], (unsigned long)f[46 + i]);
    say(L"\n    level diff (unit - native) -5..+5:");
    for (i = 0; i < 11; ++i) say(L" %lu", (unsigned long)f[54 + i]);
    say(L"\n    by the man's NATIVE activity class (men / differing):");
    for (i = 0; i < 12; ++i) if (f[65 + 2 * i]) say(L" [%hs %lu/%lu]", classes[i], (unsigned long)f[65 + 2 * i], (unsigned long)f[66 + 2 * i]);
    say(L"\n");
}
/* Posture / engage half (words 128..255 of brain_unit_policy_words; src/brain2/native_unit_posture_engage.h, labels
   KNTWR_UNIT_POSTURE_ENGAGE_LABELS): p = the half, h = the shared header words (modes). */
static void print_unit_posture_engage(const uint32_t *p, const uint32_t *h)
{
    static const char *const act[] = { "A idle", "B", "C", "D", "E" };
    static const char *const phase[] = { "0", "6", "7", "9", "other" };
    const double stages = h[2] ? (double)h[2] : 1.0;
    unsigned i;
    if (!p[1] && !p[2]) return;
    say(L"  brain unit posture/engage (v%lu; posture %hs, engage %hs): stages=%lu\n", (unsigned long)p[0], p[1] == 2 ? "live" : p[1] == 1 ? "shadow" : "off",
        p[2] == 2 ? "live" : p[2] == 1 ? "shadow" : "off", (unsigned long)p[3]);
    if (p[1]) {
        say(L"    posture decide: units %lu, admitted last stage %lu, admitted unit-stages %lu, refused %lu (no unit %lu, fsm %lu, state %lu, "
            L"active B..E %lu); unit-stages by unit FSM activity A/B/C/D/E = %lu/%lu/%lu/%lu/%lu\n", (unsigned long)p[4], (unsigned long)p[5],
            (unsigned long)p[6], (unsigned long)p[7], (unsigned long)p[8], (unsigned long)p[9], (unsigned long)p[10], (unsigned long)p[11],
            (unsigned long)p[12], (unsigned long)p[13], (unsigned long)p[14], (unsigned long)p[15], (unsigned long)p[16]);
        say(L"    posture admission over members (idle units only): checked %lu, refused moving %lu; member causes (unit-stages) state %lu, "
            L"sequencer request %lu, fsm request fields %lu\n", (unsigned long)p[122], (unsigned long)p[121], (unsigned long)p[123],
            (unsigned long)p[124], (unsigned long)p[125]);
        say(L"    posture apply (men): applied %lu = transitions %lu + update-only %lu; null state %lu; native fallback state %lu table %lu "
            L"(drains %lu); iteration-budget stops %lu\n", (unsigned long)p[17], (unsigned long)p[18], (unsigned long)p[19],
            (unsigned long)p[20], (unsigned long)p[21], (unsigned long)p[22], (unsigned long)p[23], (unsigned long)p[24]);
        if (p[1] == 1) {
            say(L"    posture shadow (native end-of-stage state vs the unit target; idle units only): men %lu agree %lu disagree %lu null %lu other %lu, "
                L"not run this stage %lu; top (native -> unit) pairs (13 = null state):", (unsigned long)p[25], (unsigned long)p[26],
                (unsigned long)p[27], (unsigned long)p[29], (unsigned long)p[30], (unsigned long)p[28]);
            for (i = 0; i < 6u; ++i) if (p[34 + 3 * i]) say(L" %lu->%lu:%lu", (unsigned long)p[32 + 3 * i], (unsigned long)p[33 + 3 * i], (unsigned long)p[34 + 3 * i]);
            say(L"\n    posture histogram of stepped members (every selected unit; evidence for a B..E mapping): members %lu, by unit command speed "
                L"none/1/2/other %lu/%lu/%lu/%lu\n", (unsigned long)p[50], (unsigned long)p[51], (unsigned long)p[52], (unsigned long)p[53], (unsigned long)p[54]);
            say(L"      modal native state (members) by unit activity:");
            for (i = 0; i < 5u; ++i) say(L" [%hs %lu x%lu]", act[i], (unsigned long)p[55 + 2 * i], (unsigned long)p[56 + 2 * i]);
            say(L"\n      modal native state by (activity, command speed 1|2):");
            for (i = 0; i < 4u; ++i)
                say(L" [%hs s1 %lu x%lu | s2 %lu x%lu]", act[1 + i], (unsigned long)p[65 + 4 * i], (unsigned long)p[66 + 4 * i],
                    (unsigned long)p[67 + 4 * i], (unsigned long)p[68 + 4 * i]);
            say(L"\n");
        }
    }
    if (p[2]) {
        say(L"    engage decide: units %lu, admitted last stage %lu, admitted unit-stages %lu, refused %lu (no unit %lu, read fault %lu); "
            L"frozen D9D on/off units %lu/%lu\n", (unsigned long)p[81], (unsigned long)p[82], (unsigned long)p[83], (unsigned long)p[84],
            (unsigned long)p[85], (unsigned long)p[86], (unsigned long)p[87], (unsigned long)p[88]);
        say(L"    engage apply: frozen-D9D branch taken %lu, alternate driver reached %lu (drains %lu); lookups served %lu, native %lu "
            L"(unit-stages evaluated predicate %lu arrival %lu modifier %lu)\n", (unsigned long)p[89], (unsigned long)p[90], (unsigned long)p[91],
            (unsigned long)p[96], (unsigned long)p[92], (unsigned long)p[93], (unsigned long)p[94], (unsigned long)p[95]);
        if (p[2] == 1) {
            say(L"    engage shadow (native end-of-stage vs the unit decision): admitted men %lu; own phase", (unsigned long)p[97]);
            for (i = 0; i < 5u; ++i) say(L" %hs=%lu", phase[i], (unsigned long)p[98 + i]);
            say(L"; phase 6 native/unit on %lu native/unit off %lu native off/unit on %lu; +F1 1/0 %lu/%lu; +619 1/0 %lu/%lu\n",
                (unsigned long)p[103], (unsigned long)p[104], (unsigned long)p[105], (unsigned long)p[106], (unsigned long)p[107],
                (unsigned long)p[108], (unsigned long)p[109]);
            say(L"    freeze validation (admitted unit-stages checked %lu): stale predicate %lu, arrival %lu, modifier %lu, D9D %lu\n",
                (unsigned long)p[120], (unsigned long)p[116], (unsigned long)p[117], (unsigned long)p[118], (unsigned long)p[119]);
            say(L"    order/stance uniformity (units with stepped members %lu): order uniform %lu mixed %lu, stance uniform %lu mixed %lu; "
                L"unfolded (native order/stance) admitted units %lu\n", (unsigned long)p[110], (unsigned long)p[111], (unsigned long)p[112],
                (unsigned long)p[113], (unsigned long)p[114], (unsigned long)p[115]);
        }
    }
    if (p[127]) say(L"    posture/engage faults: %lu\n", (unsigned long)p[127]);
    (void)stages;
}
/* Army Stage B0 qualification (native_army_unit.h B0 comment, analysis/native-army-stage-b-plan.md sections 6, 7, 9).
   Refusal buckets are mutually exclusive whole-occurrence costs (unreadable, alloc_list, FSM transition, recorder not
   replayable, other refused, completable). Section 6 inputs: a = alloc_list + unreadable, t = FSM transition,
   x = recorder + other, p = completable; Tnew = O + U(a+t+x) + U p / P_eff + F + D + H. Gates: coverage p >= 60%
   (completable once the reached classes are closed) and p_closed (completable with only the closed step bodies,
   closed_step_mask) within 5 points of it (closed common steps); recorder qualified at every stage and occurrence;
   projected saving >= 4 ms at the plan's expected P_eff 6, D .044, H .750. */
static void print_army_b0(const uint32_t *u, const uint32_t *b)
{
    static const char *const refusal[] = { "unreadable", "alloc_list", "fsm_transition", "recorder", "other", "completable" };
    static const char *const split[] = { "growth", "reserve_522D70", "list_change", "predicate_only" };
    static const char *const others[] = { "stage_a_notify_planner_return", "dirty_formation", "fsm_unknown" };
    static const char *const states[] = { "A", "B", "C", "D", "E", "sentinel", "other" };
    static const char *const secondary[] = { "1450BDC", "1450BE0", "1450BE4", "1450BE8", "sentinel", "other" };
    const double occ = b[1] ? (double)b[1] : 1.0, ticks = u[6] ? (double)u[6] : 1.0, U = u[16] ? (double)u[16] : 1.0;
    const double unit_ms = u[16] / ticks / 1000.0, snap_ms = u[21] / ticks / 1000.0;
    const double native_ms = ((double)u[19] - u[20] - u[21]) / ticks / 1000.0, other_ms = native_ms - unit_ms;
    const double a = ((double)b[133] + b[135]) / U, t = b[137] / U, x = ((double)b[139] + b[141]) / U, p = b[143] / U;
    const double p_closed = ((double)b[143] - b[145]) / U, copy_ms = b[127] / ticks / 1000.0;
    const double fsm_x = b[155] / U;
    const double t_exp = other_ms + unit_ms * (a + t + x) + unit_ms * p / 6.0 + snap_ms + 0.044 + 0.750;
    const double t_opt = other_ms + unit_ms * (a + t + x) + unit_ms * p / 8.0 + snap_ms + 0.026 + 0.100;
    const int g_cover = p >= 0.60, g_steps = p - p_closed <= 0.05;
    const int g_rec = b[101] && b[102] == b[101] && !b[103] && !b[104] && !b[105] && !b[106] && !b[107] && !b[108] && !b[110] &&
                      !b[119];
    const int g_save = native_ms - t_exp >= 4.0;
    unsigned i;
    if (!b[0]) { say(L"  army B0: no stage observed\n"); return; }
    say(L"  army B0 qualification v%lu (shadow only, ARMY_UNIT clone + FSM gate 58202E; no native write): occurrences=%lu "
        L"instrumentation %.3f ms/tick\n", (unsigned long)b[0], (unsigned long)b[1], b[13] / ticks / 1000.0);
    say(L"    refusal (exclusive, units%% / cost%% / ms/tick):");
    for (i = 0; i < 6u; ++i)
        say(L" %hs=%.2f/%.2f/%.3f", refusal[i], pct(b[132u + 2u * i], b[1]), pct(b[133u + 2u * i], u[16]), b[133u + 2u * i] / ticks / 1000.0);
    say(L"\n      completable split: step not closed %.2f%% cost, no FSM step %.2f%% cost; other split:",
        pct(b[145], u[16]), pct(b[147], u[16]));
    for (i = 0; i < 3u; ++i) say(L" %hs=%.2f%%", others[i], pct(b[149u + 2u * i], u[16]));
    say(L"; alloc_list split (units/cost%%):");
    for (i = 0; i < 4u; ++i) say(L" %hs=%lu/%.2f%%", split[i], (unsigned long)b[93u + 2u * i], pct(b[94u + 2u * i], u[16]));
    say(L"\n    FSM 582530: calls=%lu (occurrences %lu, multi %lu, outside unit %lu) transitions=%lu (%.2f%% of units, %.2f%% "
        L"of cost) steps=%lu unreadable=%lu foreign_table=%lu; native %.3f ms/tick (transition %.3f, step %.3f); not reached "
        L"%.2f%% of cost; closed_step_mask=0x%lX\n", (unsigned long)b[2], (unsigned long)b[3], (unsigned long)b[4],
        (unsigned long)b[14], (unsigned long)b[5], pct(b[154], b[1]), 100.0 * fsm_x, (unsigned long)b[6], (unsigned long)b[7],
        (unsigned long)b[8], b[9] / ticks / 1000.0, b[10] / ticks / 1000.0, b[11] / ticks / 1000.0, pct(b[15], u[16]),
        (unsigned long)b[12]);
    say(L"      per state: steps / step ms/tick / cost%% of stepping occurrences / transitions from / to:");
    for (i = 0; i < 7u; ++i) {
        const uint32_t *s = b + 16u + 5u * i;
        if (s[0] || s[3] || s[4])
            say(L" %hs%ls=%lu/%.3f/%.2f%%/%lu/%lu", states[i], (b[12] >> i & 1u) ? L"(closed)" : L"", (unsigned long)s[0],
                s[1] / ticks / 1000.0, pct(s[2], u[16]), (unsigned long)s[3], (unsigned long)s[4]);
    }
    say(L"\n    formation: infantry %.2f/unit other %.2f unreadable %lu; scratch N (largest per unit) mean %.1f max %lu (participant bank %lu B); "
        L"members %.1f/unit; cap max record %lu distance %lu; growth record %lu distance %lu; nonzero scratch count %lu "
        L"(unreadable %lu)\n", b[51] / occ, b[52] / occ, (unsigned long)b[53], b[54] / occ,
        (unsigned long)b[55], (unsigned long)b[131], b[56] / occ, (unsigned long)b[57], (unsigned long)b[58], (unsigned long)b[59],
        (unsigned long)b[60], (unsigned long)b[61], (unsigned long)b[62]);
    say(L"      queue: commands %.2f/unit (unreadable %lu) reserved %lu truncated %lu dirty %lu (%.2f%% cost); 1324B54 "
        L"secondary:", b[63] / occ, (unsigned long)b[64], (unsigned long)b[65], (unsigned long)b[66], (unsigned long)b[129],
        pct(b[130], u[16]));
    for (i = 0; i < 6u; ++i) if (b[67u + i]) say(L" %hs=%lu", secondary[i], (unsigned long)b[67u + i]);
    say(L"; classes (distinct %lu overflow %lu): VA/commands/cost%%", (unsigned long)b[73], (unsigned long)b[74]);
    for (i = 0; i < 6u && i < b[73]; ++i)
        say(L" 0x%08lX/%lu/%.2f%%", (unsigned long)b[75u + 3u * i], (unsigned long)b[76u + 3u * i], pct(b[77u + 3u * i], u[16]));
    say(L"\n    recorder: stages %lu qualified %lu; enable0=%lu manager_null=%lu manager_changes=%lu provider_set=%lu "
        L"comparator_set=%lu inhibit=%lu dcc_zero=%lu unreadable=%lu (of %lu observations); last manager 0x%08lX provider "
        L"0x%08lX comparator 0x%08lX; tails %.3f/unit (max %lu, %lu units, %.2f%% cost) drops %lu unqualified-tail units %lu\n",
        (unsigned long)b[101], (unsigned long)b[102], (unsigned long)b[103], (unsigned long)b[104], (unsigned long)b[105],
        (unsigned long)b[106], (unsigned long)b[107], (unsigned long)b[108], (unsigned long)b[109], (unsigned long)b[110],
        (unsigned long)b[114], (unsigned long)b[111], (unsigned long)b[112], (unsigned long)b[113], b[115] / occ,
        (unsigned long)b[116], (unsigned long)b[117], pct(b[120], u[16]), (unsigned long)b[118], (unsigned long)b[119]);
    say(L"    RNG model+50: member-loop bound %.1f/unit; drawing units within bound %lu, over bound/unresolved %lu, max draws %lu\n",
        b[121] / occ, (unsigned long)b[122], (unsigned long)b[123], (unsigned long)b[124]);
    say(L"    own state (first order: U E38 + formations + attached list; members not copied): %.1f KiB/unit max %lu B; copy "
        L"%.3f ms/tick (%.2f us/unit; unreadable %lu)\n", b[125] / occ, (unsigned long)b[126], copy_ms, b[127] / occ,
        (unsigned long)b[128]);
    say(L"    section 6: U=%.3f O=%.3f F=%.3f ms; a=%.4f t=%.4f x=%.4f p=%.4f (p_closed %.4f); Tnew expected (P_eff 6, D .044, "
        L"H .750) %.3f ms save %.3f; optimistic (8, .026, .100) %.3f save %.3f; H floor from own copy %.3f ms\n",
        unit_ms, other_ms, snap_ms, a, t, x, p, p_closed, t_exp, native_ms - t_exp, t_opt, native_ms - t_opt, copy_ms);
    say(L"    release gates: coverage p>=60%% %ls (%.2f%%); closed common steps %ls (p_closed %.2f%%); recorder qualified %ls "
        L"(owner residue %.2f%% cost); projected saving>=4 ms %ls (%.3f) => B1 %ls\n", g_cover ? L"PASS" : L"FAIL", 100.0 * p,
        g_steps ? L"PASS" : L"FAIL", 100.0 * p_closed, g_rec ? L"PASS" : L"FAIL", pct(b[139], u[16]), g_save ? L"PASS" : L"FAIL",
        native_ms - t_exp, g_cover && g_steps && g_rec && g_save ? L"GO" : L"NO-GO");
}
/* Site-18 storm census (native_army_storm.h): header 12 words, storm aggregate at 12 and non-storm aggregate at 26 (14 words each, AggWord),
   top-8 storm-tick table at 40 (11 words each, largest site-18 us first). Prints nothing when the census is off (enabled word 0). */
#define STORM_AGG_STORM 12u
#define STORM_AGG_CALM 26u
#define STORM_TOP 40u
#define STORM_ENTRY_WORDS 11u
static void print_army_storm(const uint32_t *w)
{
    unsigned i;
    if (!w[1]) return;
    say(L"army_storm v%lu: ticks=%lu storm_ticks=%lu median_site18_us=%lu (storm > %lux median) observer_us=%lu unreadable=%lu "
        L"sample_ms=%lu admitted=%lu rejected=%lu route_gate_outside_unit=%lu\n",
        (unsigned long)w[0], (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5],
        (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10],
        (unsigned long)w[11]);
    for (i = 0; i < 2; ++i) {
        const uint32_t *a = w + (i ? STORM_AGG_CALM : STORM_AGG_STORM);
        say(L"  %ls max_unit_us=%lu units=%lu route_units(R2 reaches 576B30)=%lu route_us=%lu unit_us=%lu sum_max_unit_us=%lu units>=5ms=%lu "
            L"units>=1ms=%lu prep=%lu us fsm=%lu us/%lu calls formation=%lu us R2_gate=%lu us R1_entries=%lu\n",
            i ? L"calm: " : L"storm:", (unsigned long)a[0], (unsigned long)a[1], (unsigned long)a[2], (unsigned long)a[3],
            (unsigned long)a[4], (unsigned long)a[5], (unsigned long)a[6], (unsigned long)a[7], (unsigned long)a[8],
            (unsigned long)a[9], (unsigned long)a[10], (unsigned long)a[11], (unsigned long)a[12], (unsigned long)a[13]);
    }
    for (i = 0; i < 8; ++i) {
        const uint32_t *e = w + STORM_TOP + i * STORM_ENTRY_WORDS;
        if (!e[0] && !e[1]) continue;
        say(L"  top%lu: tick=%lu site18=%lu us site34=%lu us units=%lu route_units=%lu max_unit_us=%lu (ordinal %lu, side 0x%04lX) "
            L"prep=%lu fsm=%lu formation=%lu R2_gate=%lu us units>=5ms=%lu R2_full_solves=%lu R1_entries=%lu\n",
            (unsigned long)i, (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], (unsigned long)(e[3] & 0xFFFFu),
            (unsigned long)(e[3] >> 16), (unsigned long)e[4], (unsigned long)(e[5] & 0xFFFFu), (unsigned long)(e[5] >> 16),
            (unsigned long)e[6], (unsigned long)e[7], (unsigned long)e[8], (unsigned long)e[9],
            (unsigned long)(e[10] & 0x3FFu), (unsigned long)((e[10] >> 10) & 0x3FFu), (unsigned long)((e[10] >> 20) & 0x3FFu));
    }
}
/* --army-storm-census formation residual (kntwr_status::army_residual_words; layout in src/army/native_formation_residual.h).
   Prints the header, the [vtbl+0xC] callee table, both aggregates and the top storm ticks; all times inclusive us.
   Residue of the formation update 0x580A30 = form_us - (dirty_a+dirty_b+agg+fsm+cmdpred+cmdctor+queue+tail+rec) us. */
static void print_army_residual(const uint32_t *w)
{
    unsigned i;
    static const char *const gates[9] = { "dirty_a(576EA0)", "dirty_b(57C9F0)", "agg(53C180)", "fsm(580990)",
        "cmdpred(586440)", "cmdctor(51A3A0)", "queue(581E80)", "tail(551A40)", "rec(DACDC0)" };
    if (!w[1]) return;
    if (w[0] != KNTWR_FORMATION_RESIDUAL_VERSION) {
        say(L"army_residual: row version %lu is not the version %lu this launcher decodes; layout not printed\n",
            (unsigned long)w[0], (unsigned long)KNTWR_FORMATION_RESIDUAL_VERSION);
        return;
    }
    say(L"army_residual v%lu: ticks=%lu storm_ticks=%lu form_calls=%lu clone_forms=%lu other_forms=%lu member_calls=%lu "
        L"observer_us=%lu qpc_read_cost_q16=%lu gate_outside=%lu callee_overflow=%lu\n",
        (unsigned long)w[0], (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5],
        (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10],
        (unsigned long)w[11]);
    for (i = 0; i < 6; ++i) {
        const uint32_t *c = w + 12 + i * 4;
        if (!c[2]) continue;
        say(L"  callee %08lX: loops=%c%c calls=%lu us=%lu\n", (unsigned long)c[0],
            (c[1] & 1) ? '1' : '-', (c[1] & 2) ? '2' : '-', (unsigned long)c[2], (unsigned long)c[3]);
    }
    for (i = 0; i < 2; ++i) {
        const uint32_t *a = w + (i ? 76 : 36);
        unsigned g;
        say(L"  %ls forms=%lu form=%lu us (max %lu us, %lu members, gate sum max %lu us) members_sum=%lu ge1ms=%lu "
            L"loop1=%lu loop2=%lu us loop_calls=%lu r1=%lu r1b=%lu r2=%lu queue_r2=%lu us\n",
            i ? L"calm: " : L"storm:", (unsigned long)a[0], (unsigned long)a[1], (unsigned long)a[2], (unsigned long)a[3],
            (unsigned long)a[31], (unsigned long)a[4], (unsigned long)a[5], (unsigned long)a[6], (unsigned long)a[7],
            (unsigned long)a[8], (unsigned long)a[27], (unsigned long)a[28], (unsigned long)a[29], (unsigned long)a[30]);
        for (g = 0; g < 9; ++g)
            say(L"    %hs calls=%lu us=%lu\n", gates[g], (unsigned long)a[9 + g * 2], (unsigned long)a[10 + g * 2]);
        say(L"    limited-solve (inclusive wall us inside tick/site18/formation buckets, never additive): ticks=%lu calls=%lu us=%lu (max call %lu us, max tick %lu us) limited-only ticks=%lu calls=%lu us=%lu\n",
            (unsigned long)a[32], (unsigned long)a[33], (unsigned long)a[34], (unsigned long)a[35], (unsigned long)a[36],
            (unsigned long)a[37], (unsigned long)a[38], (unsigned long)a[39]);
    }
    for (i = 0; i < KNTWR_FORMATION_RESIDUAL_TOP_ROWS; ++i) {
        const uint32_t *e = w + KNTWR_FORMATION_RESIDUAL_TOP_OFFSET + i * KNTWR_FORMATION_RESIDUAL_ENTRY_WORDS;
        if (!e[0] && !e[3] && !e[24] && !e[25]) continue;
        say(L"  top%lu: tick=%lu qpc_start=%I64u tick_us=%lu site18=%lu us forms=%lu form=%lu us (max %lu us %lu members) loop1=%lu loop2=%lu us "
            L"members=%lu loop_calls=%lu | dirtyA=%lu dirtyB=%lu agg=%lu fsm=%lu cmdpred=%lu cmdctor=%lu queue=%lu tail=%lu "
            L"rec=%lu r1=%lu r1b=%lu r2=%lu queue_r2=%lu us dirty_ab_calls=%lu/%lu | limited calls=%lu us=%lu max=%lu us flags=%lu | "
            L"queue_cmds=%lu us=%lu slowest vtable=%08lX slot=%lu us=%lu\n",
            (unsigned long)i, (unsigned long)e[0], ((unsigned long long)e[25] << 32) | e[24], (unsigned long)e[26],
            (unsigned long)e[1], (unsigned long)e[2], (unsigned long)e[3],
            (unsigned long)e[4], (unsigned long)e[5], (unsigned long)e[6], (unsigned long)e[7], (unsigned long)e[8],
            (unsigned long)e[9], (unsigned long)e[10], (unsigned long)e[11], (unsigned long)e[12], (unsigned long)e[13],
            (unsigned long)e[14], (unsigned long)e[15], (unsigned long)e[16], (unsigned long)e[17], (unsigned long)e[18],
            (unsigned long)e[19], (unsigned long)e[20], (unsigned long)e[21], (unsigned long)e[22],
            (unsigned long)(e[23] & 0xFFFFu), (unsigned long)(e[23] >> 16),
            (unsigned long)e[27], (unsigned long)e[28], (unsigned long)e[29], (unsigned long)e[30],
            (unsigned long)e[31], (unsigned long)e[32], (unsigned long)e[33], (unsigned long)e[34], (unsigned long)e[35]);
        if (!e[36])
            say(L"    route: no routed callback this tick (coverage none: the private 581CA0 chain did not run, so zero nested counts here are NOT zero native work; the slowest callback above ran native)\n");
        else
            say(L"    route: callbacks=%lu us=%lu | enter(4F84C0 transition)=%lu/%lu us other_enter=%lu/%lu us assign(57B000)=%lu/%lu us perman(55F160)=%lu/%lu us | "
                L"slowest routed vtable=%08lX slot=%lu us=%lu enter=%lu/%lu us other_enter=%lu/%lu us assign=%lu/%lu us perman=%lu/%lu us%ls\n",
                (unsigned long)e[36], (unsigned long)e[37], (unsigned long)e[38], (unsigned long)e[39], (unsigned long)e[40], (unsigned long)e[41],
                (unsigned long)e[42], (unsigned long)e[43], (unsigned long)e[44], (unsigned long)e[45],
                (unsigned long)e[46], (unsigned long)e[47], (unsigned long)e[48], (unsigned long)e[49], (unsigned long)e[50],
                (unsigned long)e[51], (unsigned long)e[52], (unsigned long)e[53], (unsigned long)e[54], (unsigned long)e[55], (unsigned long)e[56],
                (e[30] & 4u) ? L" (= the slowest queue callback of the tick)" : L" (not the slowest queue callback of the tick)");
        if (e[36])
            say(L"    assign split (census; assign scope = solver-clone scopes inside the routed 57B000, inner = solver chain deltas over the same span): "
                L"scope=%lu us/%lu scopes kernel=%lu us solves=%lu lim=%lu us/%lu calls suppressed=%lu assign_entries=%lu | "
                L"slowest routed: scope=%lu us/%lu scopes kernel=%lu us solves=%lu lim=%lu us/%lu calls suppressed=%lu assign_entries=%lu\n",
                (unsigned long)e[57], (unsigned long)e[58], (unsigned long)e[59], (unsigned long)e[60],
                (unsigned long)e[61], (unsigned long)e[62], (unsigned long)e[63], (unsigned long)e[64],
                (unsigned long)e[65], (unsigned long)e[66], (unsigned long)e[67], (unsigned long)e[68],
                (unsigned long)e[69], (unsigned long)e[70], (unsigned long)e[71], (unsigned long)e[72]);
    }
    {
        const uint32_t *l = w + KNTWR_FORMATION_RESIDUAL_LEDGER_OFFSET;
        say(L"  ledger: top_capacity=%lu entry_words=%lu offered=%lu retained=%lu rejected=%lu evicted=%lu | limited ticks=%lu retained=%lu omitted=%lu | sink_calls=%lu folded=%lu aborted=%lu outside=%lu pending=%lu | aborted_ticks=%lu aborted_lim_us=%lu aborted_form_calls=%lu | queue_calls=%lu folded=%lu aborted=%lu outside=%lu pending=%lu aborted_queue_us=%lu | route_begun=%lu folded=%lu aborted=%lu discarded=%lu pending=%lu refused_scope=%lu refused_depth=%lu unscoped_gates=%lu aborted_route_us=%lu\n",
            (unsigned long)l[0], (unsigned long)l[1], (unsigned long)l[2], (unsigned long)l[3], (unsigned long)l[4], (unsigned long)l[5],
            (unsigned long)l[6], (unsigned long)l[7], (unsigned long)l[8], (unsigned long)l[9], (unsigned long)l[10],
            (unsigned long)l[11], (unsigned long)l[12], (unsigned long)(l[9] - l[10] - l[11] - l[12]),
            (unsigned long)l[13], (unsigned long)l[14], (unsigned long)l[15],
            (unsigned long)l[16], (unsigned long)l[17], (unsigned long)l[18], (unsigned long)l[19],
            (unsigned long)(l[16] - l[17] - l[18] - l[19]), (unsigned long)l[20],
            (unsigned long)l[21], (unsigned long)l[22], (unsigned long)l[23], (unsigned long)l[24],
            (unsigned long)(l[21] - l[22] - l[23] - l[24]), (unsigned long)l[25], (unsigned long)l[26], (unsigned long)l[27], (unsigned long)l[28]);
    }
    {
        const uint32_t *q = w + KNTWR_FORMATION_RESIDUAL_QUEUE_OFFSET;
        say(L"  queue commands (cumulative over every observed returned callback, aborted ticks included; inclusive us): overflow calls=%lu us=%lu\n",
            (unsigned long)q[0], (unsigned long)q[1]);
        for (i = 0; i < KNTWR_FORMATION_RESIDUAL_QUEUE_CLASSES; ++i) {
            const uint32_t *c = q + 2 + i * 5;
            if (!c[2]) continue;
            say(L"    class vtable=%08lX slot=%lu calls=%lu us=%lu max=%lu us\n",
                (unsigned long)c[0], (unsigned long)c[1], (unsigned long)c[2], (unsigned long)c[3], (unsigned long)c[4]);
        }
    }
    {
        const uint32_t *t = w + KNTWR_FORMATION_RESIDUAL_ROUTE_OFFSET;
        say(L"  command-split route (cumulative over every routed 581CA0 callback that ended normally in an owner invocation; inclusive us): armed=%lu calls=%lu us=%lu max=%lu us no_enter_calls=%lu | "
            L"enter(4F84C0 transition)=%lu/%lu us other_enter=%lu/%lu us assign(57B000)=%lu/%lu us perman(55F160)=%lu/%lu us\n",
            (unsigned long)t[0], (unsigned long)t[1], (unsigned long)t[2], (unsigned long)t[3], (unsigned long)t[4],
            (unsigned long)t[5], (unsigned long)t[6], (unsigned long)t[7], (unsigned long)t[8], (unsigned long)t[9],
            (unsigned long)t[10], (unsigned long)t[11], (unsigned long)t[12]);
        say(L"  assign split (cumulative; census): scope=%lu us/%lu scopes kernel=%lu us solves=%lu lim=%lu us/%lu calls suppressed=%lu assign_entries=%lu\n",
            (unsigned long)t[13], (unsigned long)t[14], (unsigned long)t[15], (unsigned long)t[16],
            (unsigned long)t[17], (unsigned long)t[18], (unsigned long)t[19], (unsigned long)t[20]);
    }
}
/* Army solver (native_army_solver.h): header 60 words (KNTWR_ARMY_SOLVER_LABELS), top-16 tick table at 60 (13 words each) and top-16 solve table
   at 268 (16 words each), longest solver time first, 524 words in all. Prints nothing when the module is off (version word 0). */
#define SOLVER_TICK_TABLE 60u
#define SOLVER_SOLVE_TABLE 268u
#define SOLVER_ENTRY_WORDS 13u
#define SOLVER_SOLVE_WORDS 16u
static void print_army_solver(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"army_solver v%lu: mode=%ls started=%lu ticks=%lu solves=%lu flag1=%lu kernel=%lu flag0_native=%lu foreign_native=%lu "
        L"fallback(too_large=%lu range=%lu list_state=%lu guard=%lu env=%lu) shadow(compares=%lu mismatch_solves=%lu entries=%lu eax=%lu)\n",
        (unsigned long)w[0], w[1] == 1u ? L"memo" : L"shadow", (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4],
        (unsigned long)w[5], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[10],
        (unsigned long)w[11], (unsigned long)w[12], (unsigned long)w[13], (unsigned long)w[14], (unsigned long)w[15], (unsigned long)w[16],
        (unsigned long)w[17]);
    say(L"  route: assign_calls=%lu r1=%lu r1b=%lu r2=%lu shim_suppressed=%lu shim_forwarded=%lu | native_us=%lu kernel_us=%lu observer_us=%lu | "
        L"evals=%I64u distinct=%I64u iterations=%I64u swaps=%lu removals=%lu | max_m=%lu max_formation=%lu members_sum=%lu | "
        L"m hist 1-16=%lu 17-64=%lu 65-128=%lu 129-256=%lu 257-512=%lu >512=%lu\n",
        (unsigned long)w[20], (unsigned long)w[21], (unsigned long)w[22], (unsigned long)w[23], (unsigned long)w[18], (unsigned long)w[19],
        (unsigned long)w[24], (unsigned long)w[25], (unsigned long)w[42],
        ((unsigned __int64)w[27] << 32) | w[26], ((unsigned __int64)w[29] << 32) | w[28], ((unsigned __int64)w[31] << 32) | w[30],
        (unsigned long)w[32], (unsigned long)w[33], (unsigned long)w[34], (unsigned long)w[35], (unsigned long)w[43],
        (unsigned long)w[36], (unsigned long)w[37], (unsigned long)w[38], (unsigned long)w[39], (unsigned long)w[40], (unsigned long)w[41]);
    say(L"  phases (timed kernel solves=%lu, kernel total %lu us): scans=%I64u cost_phase=%lu us (gather+table fill) loop_phase=%lu us | gather=%lu us | fallbacks fpenv=%lu ctx=%lu empty_native=%lu | solves via 18F12AA direct=%lu (via 53765A shim = solves - this)\n",
        (unsigned long)w[48], (unsigned long)w[49], ((unsigned __int64)w[45] << 32) | w[44], (unsigned long)w[46], (unsigned long)w[47], (unsigned long)w[50], (unsigned long)w[52], (unsigned long)w[53], (unsigned long)w[54], (unsigned long)w[51]);
    say(L"  cache route: assignments=%lu solved_kernel=%lu (solve flags bit9 marks cache origin)\n",
        (unsigned long)w[55], (unsigned long)w[56]);
    say(L"  command route (57B021 rewrite): assignments=%lu solved_kernel=%lu gate_native=%lu (solve flags bit10 marks command origin)\n",
        (unsigned long)w[57], (unsigned long)w[58], (unsigned long)w[59]);
    for (i = 0; i < 16; ++i) {
        const uint32_t *e = w + SOLVER_TICK_TABLE + i * SOLVER_ENTRY_WORDS;
        if (!e[0] && !e[1]) continue;
        say(L"  tick%lu: tick=%lu solves=%lu formations(distinct among flag=1 solves)=%lu native=%lu us kernel=%lu us evals=%lu distinct=%lu iterations=%lu max_m=%lu "
            L"solved_kernel=%lu fallbacks=%lu swaps=%lu assign_formations=%lu\n",
            (unsigned long)i, (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], (unsigned long)e[3], (unsigned long)e[4],
            (unsigned long)e[5], (unsigned long)e[6], (unsigned long)e[7], (unsigned long)e[8], (unsigned long)e[9], (unsigned long)e[10],
            (unsigned long)e[11], (unsigned long)e[12]);
    }
    for (i = 0; i < 16; ++i) {
        const uint32_t *e = w + SOLVER_SOLVE_TABLE + i * SOLVER_SOLVE_WORDS;
        if (!e[0] && !e[1] && !e[2]) continue;
        say(L"  solve%lu: tick=%lu F=0x%08lX m=%lu evals=%lu distinct=%lu iterations=%lu native=%lu us kernel=%lu us swaps=%lu flags=0x%lX "
            L"members=%lu eax=0x%08lX scans=%lu cost=%lu us loop=%lu us\n",
            (unsigned long)i, (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], (unsigned long)e[3], (unsigned long)e[4],
            (unsigned long)e[5], (unsigned long)e[6], (unsigned long)e[7], (unsigned long)e[8], (unsigned long)e[9], (unsigned long)e[10],
            (unsigned long)e[11], (unsigned long)e[12], (unsigned long)e[13], (unsigned long)e[14]);
    }
}
static void print_alloc_census(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"alloc_census:\n");
    for (i = 0; i < 32u; ++i)
        say(L"  %hs=%lu%ls", k_alloc_census_metrics[i], (unsigned long)w[i], (i + 1) % 4 ? L" " : L"\n");
    for (i = 0; i < 128u; ++i) {
        const uint32_t *r = w + 32u + i * 8u;
        if (!r[0] && !r[4]) continue;
        say(L"  row%lu: callsite=0x%08lX size_class=%lu live_bytes=%lu live_count=%lu allocs=%lu frees=%lu peak_live_bytes=%lu reserved=%lu\n",
            (unsigned long)i, (unsigned long)r[0], (unsigned long)r[1], (unsigned long)r[2], (unsigned long)r[3],
            (unsigned long)r[4], (unsigned long)r[5], (unsigned long)r[6], (unsigned long)r[7]);
    }
}
static void print_arena(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"arena:\n");
    for (i = 0; i < KNTWR_ARENA_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_arena_metrics[i], (unsigned long)w[i], (i + 1) % 4 ? L" " : L"\n");
}
static void print_overlay_words_row(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"overlay:\n");
    for (i = 0; i < KNTWR_OVERLAY_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_overlay_metrics[i], (unsigned long)w[i], (i + 1) % 4 ? L" " : L"\n");
}
static void print_overlay_report(const Run *r)
{
    const uint32_t *w = r->overlay_words;
    unsigned i;
    if (!r->have_overlay || !w[0]) return;
    say(L"Overlay / foreign & driver VA report (report-only; unloading an overlay DLL that has hooked Present is unsafe):\n");
    say(L"  modules=%lu foreign_hook=%lu (%.2f MiB) nv_umd=%lu (%.2f MiB) splits_low_hole=%lu nv_driver_threads=%lu (stack_va=%.2f MiB, incl. 256 KiB WOW64/thread) total_foreign_image_stack=%.2f MiB (%lu B)\n",
        (unsigned long)w[KNTWR_OVL_TOTAL_MODULES],
        (unsigned long)w[KNTWR_OVL_FOREIGN_HOOK_MODULES], (double)w[KNTWR_OVL_FOREIGN_HOOK_IMAGE_BYTES] / (1024.0 * 1024.0),
        (unsigned long)w[KNTWR_OVL_NV_UMD_MODULES], (double)w[KNTWR_OVL_NV_UMD_IMAGE_BYTES] / (1024.0 * 1024.0),
        (unsigned long)w[KNTWR_OVL_SPLITS_LOW_HOLE_COUNT],
        (unsigned long)w[KNTWR_OVL_NV_DRIVER_THREADS], (double)w[KNTWR_OVL_NV_DRIVER_STACK_BYTES] / (1024.0 * 1024.0),
        (double)w[KNTWR_OVL_TOTAL_FOREIGN_IMAGE_STACK_BYTES] / (1024.0 * 1024.0),
        (unsigned long)w[KNTWR_OVL_TOTAL_FOREIGN_IMAGE_STACK_BYTES]);
    for (i = 0; i < r->overlay_mod_count; ++i) {
        const struct OverlayMod *m = &r->overlay_mods[i];
        say(L"  [%ls] %ls base=0x%08lX..0x%08lX size=%lu KiB (%.2f MiB) splits_low_hole=%ls\n",
            m->is_nv_umd ? L"nv_umd" : L"foreign_hook", m->name,
            (unsigned long)m->base, (unsigned long)(m->base + m->size),
            (unsigned long)(m->size / 1024u), (double)m->size / (1024.0 * 1024.0),
            m->splits_low_hole ? L"YES" : L"no");
    }
}
static void print_overlay(const uint32_t *w)
{
    print_overlay_words_row(w);
}
static void print_mounted_officer(const uint32_t *w)
{
    unsigned i;
    if (!w[0]) return;
    say(L"  mounted_officer: units_seen=%lu eligible(no mounts)=%lu officer_first=%lu has_mounts=%lu skipped_no_refs=%lu skipped_no_officer=%lu MOUNTS_CREATED=%lu "
        L"attach_failures=%lu alloc_failures=%lu faults=%lu widen=%lu patch_installed=%lu visual_gate=%lu\n",
        (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[8],
        (unsigned long)w[9], (unsigned long)w[10], (unsigned long)w[14], (unsigned long)(w[1] >> 1 & 1u), (unsigned long)w[15], (unsigned long)(w[1] >> 3 & 1u));
    say(L"  mounted_officer words:");
    for (i = 0; i < KNTWR_MOUNTED_OFFICER_WORDS; ++i) say(L" %hs=%lu", k_mounted_officer_metrics[i], (unsigned long)w[i]);
    say(L"\n");
}
/* Clip picker crash guard (src/animation/kntwr_clip_picker_guard.h): always installed; printed only when the guard saw a cold request. */
static void print_anim_guard(const uint32_t *w)
{
    static const char *const names[KNTWR_ANIM_GUARD_WORDS] = { KNTWR_ANIM_GUARD_LABELS };
    unsigned i;
    if (!w[7] || !w[0]) return;
    say(L"  anim_guard:");
    for (i = 0; i < KNTWR_ANIM_GUARD_WORDS; ++i) say(L" %hs=%lu", names[i], (unsigned long)w[i]);
    say(L"\n");
}
/* --drag-ladder (src/formation/kntwr_drag_ladder_hook.h): printed only when the runtime published the row (word 0 = version). */
static void print_drag_ladder(const uint32_t *w)
{
    static const char *const names[KNTWR_DRAG_LADDER_WORDS] = { KNTWR_DRAG_LADDER_LABELS };
    unsigned i;
    if (!w[0]) return;
    say(L"  drag_ladder: files-per-row laddered at source (FilesPerRow 0x642C90) applied_this_run=%ls calls=%lu laddered=%lu passthrough=%lu faults=%lu last_files=%lu->%lu\n",
        w[2] ? L"APPLIED" : L"NOT-APPLIED", (unsigned long)w[3], (unsigned long)w[4], (unsigned long)w[5], (unsigned long)w[6],
        (unsigned long)w[7], (unsigned long)w[8]);
    say(L"  drag_ladder words:");
    for (i = 0; i < KNTWR_DRAG_LADDER_WORDS; ++i) say(L" %hs=%lu", names[i], (unsigned long)w[i]);
    say(L"\n");
}
/* --wounded (src/animation/kntwr_wounded_hook.h): printed only when the runtime published the row (word 0 = version). */
static void print_wounded(const uint32_t *w)
{
    static const char *const names[KNTWR_WOUNDED_WORDS] = { KNTWR_WOUNDED_LABELS };
    unsigned i;
    if (!w[0]) return;
    say(L"  wounded: state-commit detour (0x653F1A) applied_this_run=%ls calls=%lu flipped=%lu eligible=%lu denied_roll=%lu untagged=%lu faults=%lu\n",
        w[2] ? L"APPLIED" : L"NOT-APPLIED", (unsigned long)w[3], (unsigned long)w[7], (unsigned long)w[6],
        (unsigned long)w[8], (unsigned long)w[9], (unsigned long)w[11]);
    say(L"  wounded words:");
    for (i = 0; i < KNTWR_WOUNDED_WORDS; ++i) say(L" %hs=%lu", names[i], (unsigned long)w[i]);
    say(L"\n");
}
static void print_engage_census(const uint32_t *w)
{
    print_engage_census_line(w);
}
static void print_module_words(const kntwr_status *s, uint32_t brain_flags, uint32_t ai_ctrl_flags)
{
    static const wchar_t *const names[48] = {L"formation", L"query", L"path", L"ballistic", L"formation_diag", L"tick_cadence", L"sim_tick", L"ai_planner", L"planner_walk", L"ai_async", L"ai_async_extra", L"crash", L"brain_header", L"brain2", L"ai_slices", L"ai_validation", L"visual", L"ai_slice_sites", L"brain_state_header", L"collision", L"collide", L"collide_lod", L"ai_ctrl", L"ai_slice_budget", L"ai_park", L"loco", L"loco_gates", L"loco_services", L"loco_grid", L"loco_parallel", L"sweep", L"resolve", L"env", L"env_targets", L"resolve_frames", L"loco_owned", L"loco_owned_detail", L"loco_owned_phase", L"loco_owned_load", L"loco_grid_v2", L"collide_source", L"memory", L"brain_unit", L"collide_contact", L"grid_probation_header", L"loco_relink", L"loco_cw", L"loco_grid_build"};
    const uint32_t *arrays[48] = {s->formation_words, s->query_words, s->path_words, s->ballistic_words,
                                  s->formation_diag, s->tick_words, s->sim_words, s->planner_words, s->planner_walk_words,
                                  s->ai_words, s->ai_extra_words, s->crash_words, s->brain_words, s->brain2_words, s->ai_slice_words, s->ai_validation_words, s->visual_words, s->ai_slice_site_words, s->brain_state_words, s->collision_words, s->collide_words, s->collide_lod_words, s->ai_ctrl_words, s->ai_slice_budget_words, s->ai_park_words, s->loco_words, s->loco_gate_words, s->loco_service_words, s->loco_grid_words, s->loco_parallel_words, s->sweep_words, s->resolve_words, s->env_words, s->env_target_words, s->resolve_frame_words, s->loco_owned_words, s->loco_owned_detail_words, s->loco_owned_phase_words, s->loco_owned_load_words, s->loco_grid_v2_words, s->collide_source_words, s->memory_words, s->brain_unit_words, s->collide_contact_words, s->grid_probation_words, s->loco_relink_words, s->loco_cw_words, s->loco_grid_build_words};
    const unsigned counts[48] = {16, 16, 24, 8, 192, 16, 16, 64, 16, 16, 32, 32, KNTWR_BRAIN_HEADER_WORDS, KNTWR_BRAIN2_WORDS, 8, 8, 32, 2, KNTWR_BRAIN_STATE_COUNTS, KNTWR_COLLISION_WORDS, KNTWR_COLLIDE_WORDS, KNTWR_COLLIDE_LOD_WORDS, 16, KNTWR_AI_SLICE_BUDGET_WORDS, 8, KNTWR_LOCO_WORDS, KNTWR_LOCO_GATE_WORDS, KNTWR_LOCO_SERVICE_WORDS, KNTWR_LOCO_GRID_WORDS, KNTWR_LOCO_PARALLEL_WORDS, KNTWR_SWEEP_WORDS, KNTWR_RESOLVE_WORDS, KNTWR_ENV_WORDS, KNTWR_ENV_TARGET_WORDS, KNTWR_RESOLVE_FRAME_WORDS, KNTWR_LOCO_OWNED_WORDS, KNTWR_LOCO_OWNED_DETAIL_WORDS, KNTWR_LOCO_OWNED_PHASE_WORDS, KNTWR_LOCO_OWNED_LOAD_WORDS, KNTWR_LOCO_GRID_V2_WORDS, KNTWR_COLLIDE_SOURCE_WORDS, KNTWR_MEMORY_WORDS, KNTWR_BRAIN_UNIT_WORDS, KNTWR_COLLIDE_CONTACT_WORDS, KNTWR_GRID_PROBATION_HEADER_WORDS, KNTWR_LOCO_RELINK_WORDS, KNTWR_LOCO_CW_WORDS, KNTWR_LOCO_GRID_BUILD_WORDS};
    unsigned i, j;
    for (i = 0; i < 48; ++i) {
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
        for (i=0;i<KNTWR_AI_COMPLETION_WORDS;++i)
            say(L"  %hs=%lu%ls",k_ai_completion_metrics[i],(unsigned long)a[i],(i+1)%3 ? L" " : L"\n");
        if (s->requested_mask & KNTWR_AI_ASYNC2) {
            const uint32_t *w = s->ai_async2_words, *q = s->ai_async2_route_words;
            unsigned k = 0;
            say(L"  ai_async2 v%lu: dispatches=%lu completions=%lu capacity_joins=%lu lease_waits=%lu "
                L"overlap_sum_us=%lu join_wait_sum_us=%lu deadlock_suspected=%lu fallback=%lu marshalled=%lu\n",
                (unsigned long)w[0], (unsigned long)w[1], (unsigned long)w[2], (unsigned long)w[3], (unsigned long)w[4],
                (unsigned long)w[15], (unsigned long)w[17], (unsigned long)w[6], (unsigned long)w[7], (unsigned long)w[9]);
            say(L"  ai_async2 boundary: ticks=%lu batches=%lu complete_before_next_tick=%lu (%.1f%%) tick_start_stalls=%lu "
                L"stall_sum_us=%lu stall_max_us=%lu last_stall_tick=%lu fallback_tick=%lu unrouted_83fd00=%lu\n",
                (unsigned long)q[2], (unsigned long)q[4], (unsigned long)q[9], pct(q[9], q[4]), (unsigned long)q[11],
                (unsigned long)q[12], (unsigned long)q[13], (unsigned long)q[14], (unsigned long)q[15], (unsigned long)q[60]);
            for (i = 0; i < KNTWR_AI_ASYNC2_WORDS; ++i)
                if (w[i]) say(L"  %hs=%lu%ls", k_ai_async2_metrics[i], (unsigned long)w[i], (++k % 4) ? L"" : L"\n");
            for (i = 0; i < KNTWR_AI_ASYNC2_ROUTE_WORDS; ++i)
                if (q[i]) say(L"  route.%hs=%lu%ls", k_ai_async2_route_metrics[i], (unsigned long)q[i], (++k % 4) ? L"" : L"\n");
            if (k % 4) say(L"\n");
            if (s->ai_deferred_words[0]) {
                const uint32_t *d = s->ai_deferred_words;
                k = 0;
                say(L"  ai_deferred v%lu K=%lu B=%lu: admitted=%lu consumed=%lu (on_time=%lu late=%lu) busy_refusals=%lu "
                    L"abandoned=%lu/%lu slices=%lu budget_hits=%lu slice_max_us=%lu slice_mean_us=%.1f seam_waits=%lu "
                    L"seam_wait_sum_us=%lu skipped=%lu\n",
                    (unsigned long)d[0], (unsigned long)d[1], (unsigned long)d[2], (unsigned long)d[3], (unsigned long)d[6],
                    (unsigned long)d[7], (unsigned long)d[8], (unsigned long)d[4], (unsigned long)d[9], (unsigned long)d[10],
                    (unsigned long)d[11], (unsigned long)d[12], (unsigned long)d[22], d[11] ? (double)d[23] / d[11] : 0.0,
                    (unsigned long)d[17], (unsigned long)d[19], (unsigned long)d[13]);
                for (i = 0; i < KNTWR_AI_DEFERRED_WORDS; ++i)
                    if (d[i]) say(L"  deferred.%hs=%lu%ls", k_ai_deferred_metrics[i], (unsigned long)d[i], (++k % 4) ? L"" : L"\n");
                if (k % 4) say(L"\n");
            }
        }
    }
    if (s->requested_mask & KNTWR_BRAIN2) {
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
        for (i = 0; i < KNTWR_BRAIN2_CENSUS_WORDS / 8u; ++i) {
            const uint32_t *q = s->brain2_census_words + i * 8;
            if (q[0]) say(L"    %hs: calls=%lu active=%lu unknown=%lu inactive=%lu first_active=%lu first_unknown=%lu\n",
                k_brain2_services[i], (unsigned long)q[0], (unsigned long)q[1],
                (unsigned long)q[2], (unsigned long)q[3], (unsigned long)q[4], (unsigned long)q[5]);
        }
        {
            static const char *const node_labels[KNTWR_NODE_WORDS] = { KNTWR_NODE_WORD_LABELS };
            static const char *const move_labels[KNTWR_MOVE_NODE_WORDS] = { KNTWR_MOVE_NODE_WORD_LABELS };
            static const char *const move_event_labels[KNTWR_MOVE_NODE_EVENT_WORDS] = { KNTWR_MOVE_NODE_EVENT_WORD_LABELS };
            static const char *const fire_labels[KNTWR_FIRE_WORDS] = { KNTWR_FIRE_WORD_LABELS };
            static const char *const commit_labels[KNTWR_FIRE_COMMIT_WORDS] = { KNTWR_FIRE_COMMIT_LABELS };
            say(L"  brain reference node shadow (vtable=0x01334180, owner only):\n");
            for (i = 0; i < KNTWR_NODE_WORDS; ++i)
                say(L"    %hs=%lu\n", node_labels[i], (unsigned long)s->node_words[i]);
            say(L"    event words:");
            for (i = 0; i < KNTWR_NODE_EVENT_WORDS; ++i) say(L" %lu", (unsigned long)s->node_event_words[i]);
            say(L"\n  brain descriptor-move node shadow (vtable=0x01348B44, step=0x00819310, owner only):\n");
            for (i = 0; i < KNTWR_MOVE_NODE_WORDS; ++i)
                say(L"    %hs=%lu\n", move_labels[i], (unsigned long)s->move_node_words[i]);
            for (i = 0; i < KNTWR_MOVE_NODE_EVENT_WORDS; ++i)
                say(L"    %hs=%lu\n", move_event_labels[i], (unsigned long)s->move_node_event_words[i]);
            {
                static const uint32_t idle_tables[KNTWR_IDLE_NODE_CLASSES] = { 0x133405Cu, 0x1334028u };
                static const uint32_t action_tables[KNTWR_ACTION_NODE_CLASSES] = { 0x1347270u, 0x1348D2Cu, 0x1348CC4u };
                static const char *const idle_labels[KNTWR_NODE_WORDS] = { KNTWR_IDLE_NODE_WORD_LABELS };
                static const char *const idle_events[KNTWR_NODE_EVENT_WORDS] = { KNTWR_IDLE_NODE_EVENT_WORD_LABELS };
                static const char *const action_labels[KNTWR_NODE_WORDS] = { KNTWR_ACTION_NODE_WORD_LABELS };
                static const char *const action_events[KNTWR_NODE_EVENT_WORDS] = { KNTWR_ACTION_NODE_EVENT_WORD_LABELS };
                uint32_t cls;
                for (cls = 0; cls < KNTWR_IDLE_NODE_CLASSES; ++cls) {
                    say(L"  brain idle node shadow (vtable=0x%08lX, owner only):\n", (unsigned long)idle_tables[cls]);
                    for (i = 0; i < KNTWR_NODE_WORDS; ++i)
                        say(L"    %hs=%lu\n", idle_labels[i], (unsigned long)s->idle_node_words[cls][i]);
                    for (i = 0; i < KNTWR_NODE_EVENT_WORDS; ++i)
                        say(L"    %hs=%lu\n", idle_events[i], (unsigned long)s->idle_node_event_words[cls][i]);
                }
                for (cls = 0; cls < KNTWR_ACTION_NODE_CLASSES; ++cls) {
                    say(L"  brain action node shadow (vtable=0x%08lX, owner only):\n", (unsigned long)action_tables[cls]);
                    for (i = 0; i < KNTWR_NODE_WORDS; ++i)
                        say(L"    %hs=%lu\n", action_labels[i], (unsigned long)s->action_node_words[cls][i]);
                    for (i = 0; i < KNTWR_NODE_EVENT_WORDS; ++i)
                        say(L"    %hs=%lu\n", action_events[i], (unsigned long)s->action_node_event_words[cls][i]);
                }
            }
            say(L"\n  brain request-sequencer shadow (owner only):\n");
            for (i = 0; i < KNTWR_FIRE_WORDS; ++i)
                say(L"    %hs=%lu\n", fire_labels[i], (unsigned long)s->fire_words[i]);
            say(L"  brain sequencer commit refusal guards:\n");
            for (i = 0; i < KNTWR_FIRE_COMMIT_WORDS; ++i)
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
                static const char *const worker_labels[48] = { KNTWR_BRAIN_WORKER_WORD_LABELS };
                static const char *const reason_labels[18] = { KNTWR_BRAIN_WORKER_REASON_LABELS };
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
                    for (i = 0; i < KNTWR_BRAIN2_CENSUS_WORDS / 8u; ++i)
                        if (w[66u + i]) say(L" %hs=%lu", k_brain2_services[i], (unsigned long)w[66u + i]);
                    say(L"\n");
                    {
                        static const char *const tail_labels[] = { KNTWR_BRAIN_WORKER_TAIL_LABELS };
                        static const char *const guard_labels[] = { KNTWR_BRAIN_WORKER_GUARD_LABELS };
                        for (i = 0; i < sizeof(tail_labels) / sizeof(tail_labels[0]); ++i)
                            say(L"    %hs=%lu\n", tail_labels[i], (unsigned long)w[119u + i]);
                        for (i = 0; i < sizeof(guard_labels) / sizeof(guard_labels[0]); ++i)
                            say(L"    %hs=%lu\n", guard_labels[i], (unsigned long)w[128u + i]);
                    }
                    {
                        static const char *const phase_labels[KNTWR_BRAIN_WORKER_PHASE_WORDS] = { KNTWR_BRAIN_WORKER_PHASE_LABELS };
                        const uint32_t *p = s->brain_worker_phase_words;
                        const double stages = p[2] ? (double)p[2] : 1.0;
                        say(L"    phases (quiet=%lu, stages=%lu; per stage ms: capture %.2f [witness %.2f] dispatch %.2f commit %.2f owner_run %.2f "
                            L"walk_other %.2f witness_end %.2f; worker CPU ms: capture %.2f clone %.2f publish %.2f busy %.2f critical %.2f):\n",
                            (unsigned long)p[1], (unsigned long)p[2], p[3] / stages / 1000.0, p[4] / stages / 1000.0,
                            p[5] / stages / 1000.0, p[6] / stages / 1000.0, p[7] / stages / 1000.0, p[8] / stages / 1000.0,
                            p[9] / stages / 1000.0, p[10] / stages / 1000.0, p[11] / stages / 1000.0, p[12] / stages / 1000.0,
                            p[13] / stages / 1000.0, p[14] / stages / 1000.0);
                        for (i = 0; i < KNTWR_BRAIN_WORKER_PHASE_WORDS; ++i)
                            say(L"      %hs=%lu\n", phase_labels[i], (unsigned long)p[i]);
                    }
                }
            }
            print_unit_brain(s->brain_unit_words);
            if (brain_flags & KNTWR_BRAIN_LOCALITY) print_brain_locality(s->brain_s0_words);
            else print_brain_s0(s->brain_s0_words);
            print_unit_policy(s->brain_unit_policy_words);
            print_unit_fatigue(s->brain_unit_policy_words + 32, s->brain_unit_policy_words);
            print_unit_posture_engage(s->brain_unit_policy_words + 128, s->brain_unit_policy_words);
        }
    }
    if (s->requested_mask & KNTWR_ARMY_UNIT_SHADOW) { print_army_unit(s->army_unit_words); print_army_b0(s->army_unit_words, s->army_b0_words); }
    print_army_storm(s->army_storm_words);
    print_army_residual(s->army_residual_words);
    print_army_solver(s->army_solver_words);
    print_alloc_census(s->alloc_census_words);
    print_arena(s->arena_words);
    print_overlay(s->overlay_words);
    print_mounted_officer(s->mounted_officer_words);
    print_anim_guard(s->anim_guard_words);
    print_drag_ladder(s->drag_ladder_words);
    print_wounded(s->wounded_words);
    print_engage_census(s->engage_census_words);
    print_ai_ctrl(s->ai_ctrl_reuse_words, ai_ctrl_flags);
    print_ai_prepass(s->ai_prepass_census_words);
    print_ai_poly(s->ai_prepass_words, s->ai_completion_words[0] ? s->ai_completion_words[0] : s->planner_walk_words[0]);
    print_ai_record_test(s->ai_prepass_words + KNTWR_AI_POLY_WORDS);
    print_ai_spiral(s->ai_spiral_words);
    print_ai_claim_once(s->ai_ctrl_reuse_words);
    if (!(s->requested_mask & KNTWR_AI_CTRL)) print_brain_retarget_jitter(s->ai_ctrl_reuse_words); /* words 20..23 are the geometry words under KNTWR_AI_CTRL (exclusive) */
    if (!(s->requested_mask & KNTWR_AI_CTRL)) print_brain_target_cull(s->ai_ctrl_reuse_words); /* words 16..19 are the geometry words under KNTWR_AI_CTRL (exclusive) */
    if (s->requested_mask & KNTWR_VISUAL) {
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
    for (i = 0; i < KNTWR_ALLOCATOR_THREADS; ++i) {
        const uint32_t *a = s->allocator_words + i * KNTWR_ALLOCATOR_ROW_WORDS;
        if (!a[0]) continue;
        say(L"  allocator %ls[%u]: result=0x%lX thread=%lu tls_before=0x%08lX tls_after=0x%08lX "
            L"exception=0x%08lX eip=0x%08lX address=0x%08lX tls_index=%lu\n",
            i == KNTWR_ALLOCATOR_THREADS - 1 ? L"ai" : L"pool", i,
            (unsigned long)a[0], (unsigned long)a[1], (unsigned long)a[2], (unsigned long)a[3],
            (unsigned long)a[4], (unsigned long)a[5], (unsigned long)a[6], (unsigned long)a[7]);
    }
    print_crash(s);
}

/* ------------------------------------------------------------------------------------------------ tick trace */
static const uint32_t k_site_callee_vas[KNTWR_TIMED_SITES] = KNTWR_SITE_CALLEE_VAS;
static uint64_t trace_qpc(uint32_t lo, uint32_t hi)
{
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/* The producer's written count is cumulative across battle/model tick resets.
   Unsigned subtraction also handles its uint32_t rollover. */
static void append_tick_log(Run *r, const kntwr_trace_ring *p)
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
        uint32_t capacity = log->capacity ? log->capacity * 2u : KNTWR_TRACE_ENTRIES;
        kntwr_trace_entry *entries;
        if (capacity < needed) capacity = needed;
        if (capacity > TICK_LOG_MAX_ENTRIES) capacity = TICK_LOG_MAX_ENTRIES;
        entries = log->entries
            ? (kntwr_trace_entry *)HeapReAlloc(GetProcessHeap(), 0, log->entries, (size_t)capacity * sizeof *entries)
            : (kntwr_trace_entry *)HeapAlloc(GetProcessHeap(), 0, (size_t)capacity * sizeof *entries);
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
        const kntwr_trace_entry *e = &p->ring[(start + i) % p->entries];
        /* Chronological written deltas exclude old slots; guard the boundary
           identity as well, without scanning the entire accumulated run. */
        if (log->count) {
            const kntwr_trace_entry *last = &log->entries[log->count - 1u];
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
    kntwr_trace_ring *p;
    uint32_t next;
    if (!r->active_generations) return TRUE;
    if (!t) return FALSE;
    next = t->current ^ 1u;
    p = &t->copies[next];
    /* One full-ring read. No allocation or full-ring local copy per poll. */
    if (!remote_read(r->proc, r->dll_base + r->dll.trace_rva, p, sizeof *p) ||
        p->abi != KNTWR_TRACE_ABI || p->size != sizeof *p ||
        p->entries != KNTWR_TRACE_ENTRIES || p->head >= p->entries)
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
    const kntwr_trace_ring *p = &t->copies[t->current];
    uint32_t i, start, rank, j;
    if (t->analyzed) return;
    t->count = p->written < p->entries ? p->written : p->entries;
    start = (p->head + p->entries - t->count) % p->entries;
    for (i = 0; i < t->count; ++i) {
        uint32_t index = (start + i) % p->entries;
        const kntwr_trace_entry *e = &p->ring[index];
        if (!i) t->first_tick = e->tick;
        t->last_tick = e->tick;
        t->scratch[i] = e->duration_us;
        t->duration_sum += e->duration_us;
        t->manager_sum += e->manager_us;
        t->ballistics_sum += e->ballistics_us;
        t->path_sum += e->path_us;
        for (j = 0; j < KNTWR_TIMED_SITES; ++j) {
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
        const kntwr_trace_entry *e = &p->ring[(start + i) % p->entries];
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
    const kntwr_trace_ring *p;
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
    {   /* Tick core census (kntwr_trace_entry::flags bits 3..31): processor class carrying each routed tick, and placement. */
        uint32_t census = 0, census6 = 0, entered_e = 0, pinned_p = 0, pinned_e = 0;
        uint64_t share = 0, share6 = 0, changes = 0;
        const uint32_t first = (p->head + p->entries - t->count) % p->entries;
        for (i = 0; i < t->count; ++i) {
            const kntwr_trace_entry *e = &p->ring[(first + i) % p->entries];
            const uint32_t f = e->flags;
            if (!(f & 8u)) continue;
            ++census;
            entered_e += (f >> 4) & 1u; pinned_p += (f >> 6) & 1u; pinned_e += (f >> 7) & 1u;
            share += (f >> 8) & 255u; changes += f >> 24;
            /* The site-6 byte is 0 both for an all-P site 6 and for a tick without site 6: average only ticks that ran it. */
            if (e->site_calls[6]) { ++census6; share6 += (f >> 16) & 255u; }
        }
        if (census)
            say(L"  Tick core census: %lu ticks; entered on E-core %.1f%%; mean E share tick %.1f%% site 6 %.1f%% (%lu ticks ran it); "
                L"class changes/tick %.2f; pinned P/E %lu/%lu\n",
                (unsigned long)census, 100.0 * entered_e / census, 100.0 * share / (255.0 * census),
                census6 ? 100.0 * share6 / (255.0 * census6) : 0.0, (unsigned long)census6, (double)changes / census,
                (unsigned long)pinned_p, (unsigned long)pinned_e);
    }
    say(L"  Inclusive sites: %lu timed ticks; shares of all %lu retained tick durations.\n"
        L"  Each call is timed and counted; site 2 includes sites 16..25; totals overlap gate timings.\n"
        L"    site callee sum_us calls duration_share\n",
        (unsigned long)t->timed_ticks, (unsigned long)t->count);
    for (i = 0; i < KNTWR_TIMED_SITES; ++i)
        say(L"    %2lu 0x%06lX %I64u %I64u %.3f%%\n", (unsigned long)i, (unsigned long)k_site_callee_vas[i],
            (unsigned long long)t->site_sum[i], (unsigned long long)t->site_calls[i], t->site_sum[i] * share_scale);
    say(L"  Longest ticks (us): tick duration interval manager ballistics path\n");
    for (i = 0; i < t->top_count; ++i) {
        const kntwr_trace_entry *e = &p->ring[t->top[i]];
        say(L"    %lu %lu %lu %lu %lu %lu\n", (unsigned long)e->tick, (unsigned long)e->duration_us,
            (unsigned long)e->interval_us, (unsigned long)e->manager_us, (unsigned long)e->ballistics_us, (unsigned long)e->path_us);
        say(L"      Sites (index:callee=us/calls):");
        for (j = 0; j < KNTWR_TIMED_SITES; ++j)
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
    } header = {{'N', 'T', 'W', '2', 'T', 'L', 'O', 'G'}, KNTWR_TRACE_ABI, sizeof(kntwr_trace_entry), 0};
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

/* ------------------------------------------------------------------------------------------------ brain sites (KNTWR_BRAIN) */
/* Cumulative since the last activation (kntwr_status::brain_words, layout in kntwr_runtime.h). Families are the entry sites 46..50. */
static const struct { const wchar_t *name; const char *jname; uint32_t tables, entry_va; } k_brain_families[KNTWR_BRAIN_FAMILIES] = {
    { L"slot +0x0C = 0x66CE00 (brain direct)", "direct_66CE00", 11, 0x66CE00u },
    { L"slot +0x0C = 0x6F50F0 (jmp thunk to the brain)", "thunk_6F50F0", 1, 0x6F50F0u },
    { L"slot +0x0C = 0x6F4660 (LOS/registration wrapper)", "wrapper_6F4660", 6, 0x6F4660u },
    { L"slot +0x0C = 0x602EB0 (wrapper)", "wrapper_602EB0", 1, 0x602EB0u },
    { L"slot +0x0C = 0x5FCEB0 (pose/animation wrapper)", "wrapper_5FCEB0", 4, 0x5FCEB0u },
};
#define BRAIN_FIRST_CALLEE 65u

static uint32_t brain_us(const kntwr_status *s, uint32_t f, uint32_t site)
{
    return s->brain_words[KNTWR_BRAIN_HEADER_WORDS + 2u * (f * KNTWR_BRAIN_SITES + (site - KNTWR_BRAIN_SITE_FIRST))];
}

static uint32_t brain_calls(const kntwr_status *s, uint32_t f, uint32_t site)
{
    return s->brain_words[KNTWR_BRAIN_HEADER_WORDS + 2u * (f * KNTWR_BRAIN_SITES + (site - KNTWR_BRAIN_SITE_FIRST)) + 1u];
}

/* Sites family f can run: its own entry, its wrapper's callees (51..55 / 56..58 / 59..64) and the brain callees 65..94. */
static BOOL brain_family_owns(uint32_t f, uint32_t site)
{
    if (site == KNTWR_BRAIN_SITE_FIRST + f || site >= BRAIN_FIRST_CALLEE) return TRUE;
    return (f == 2 && site >= 51 && site <= 55) || (f == 3 && site >= 56 && site <= 58) || (f == 4 && site >= 59 && site <= 64);
}

/* Callee label: original VA, "vt+0xNNN" for the two virtual sites, annotated for the wrappers' brain calls and the entries. */
static void brain_site_label(uint32_t site, wchar_t *out, size_t n)
{
    const uint32_t va = k_site_callee_vas[site];
    if (site >= KNTWR_BRAIN_SITE_FIRST && site < KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_FAMILIES)
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
    const kntwr_status *s = &r->last;
    const uint32_t ticks = s->brain_words[0], tick_us = s->brain_words[1];
    uint64_t agg_us[KNTWR_TIMED_SITES], agg_calls[KNTWR_TIMED_SITES];
    double scale = tick_us ? 100.0 / (double)tick_us : 0.0;
    uint32_t f, site;
    wchar_t label[64];
    if (!(r->opt.mask & KNTWR_BRAIN) || !r->active_generations) return;
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
    for (f = 0; f < KNTWR_BRAIN_FAMILIES; ++f) {
        const uint32_t entities = brain_calls(s, f, KNTWR_BRAIN_SITE_FIRST + f);
        const uint32_t entry_us = brain_us(s, f, KNTWR_BRAIN_SITE_FIRST + f);
        say(L"  family %lu: %ls, %lu vtables: entities=%lu (%.2f/tick) entry_us=%lu (%.3f%% of tick sum, %.3f us/entity)\n",
            (unsigned long)f, k_brain_families[f].name, (unsigned long)k_brain_families[f].tables, (unsigned long)entities,
            (double)entities / ticks, (unsigned long)entry_us, entry_us * scale, entities ? (double)entry_us / entities : 0.0);
        for (site = KNTWR_BRAIN_SITE_FIRST; site < KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_SITES; ++site) {
            const uint32_t us = brain_us(s, f, site), calls = brain_calls(s, f, site);
            if (site >= BRAIN_FIRST_CALLEE) { agg_us[site] += us; agg_calls[site] += calls; }
            if (!brain_family_owns(f, site) || site == KNTWR_BRAIN_SITE_FIRST + f || (!calls && !us)) continue;
            brain_site_label(site, label, 64);
            say(L"    site %2lu %-24ls sum_us=%lu calls=%lu (%.2f/tick, %.3f us/call) share=%.3f%%\n", (unsigned long)site, label,
                (unsigned long)us, (unsigned long)calls, (double)calls / ticks, calls ? (double)us / calls : 0.0, us * scale);
        }
    }
    say(L"  brain callees, all families: site callee sum_us calls calls/tick us/call share\n");
    for (site = BRAIN_FIRST_CALLEE; site < KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_SITES; ++site) {
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
    if (!(r->opt.mask & KNTWR_PROFILE)) return;
    if (!r->opt.collide_census) {
        say(L"collision: pair census disabled (opt in with --collide-census); site 5 inclusive timing remains enabled.\n");
        return;
    }
    if (r->opt.mask & KNTWR_COLLIDE) {
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

static const char *const k_collide_metrics[KNTWR_COLLIDE_WORDS] = {
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
static const char *const k_collide_lod_metrics[KNTWR_COLLIDE_LOD_WORDS] = {
    "ticks_gated", "records_seen", "records_skipped", "units", "far_units", "rebuild_ticks_forced",
    "distance_m", "max_proximity_us", "sum_proximity_us", "faults", "disabled",
    "reuse_far_records", "unknown_records", "reuse_ticks", "all_far_refused_ticks", "different_side_pairs"
};
static void print_collide_lod(const Run *r)
{
    const uint32_t *w = r->last.collide_lod_words;
    unsigned i;
    if (!(r->opt.mask & KNTWR_COLLIDE_LOD)) return;
    if (!r->have_status) { say(L"collide_lod: no runtime status observed.\n"); return; }
    say(L"collide_lod: half-rate far-unit queries; near/unknown and rebuild queries remain full-rate\n");
    for (i = 0; i < KNTWR_COLLIDE_LOD_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_collide_lod_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    say(L"  reuse far records skipped=%.3f%%; cumulative counts since activation, latest units/far_units\n",
        w[11] ? 100.0*w[2]/w[11] : 0.0);
}

static const char *const k_loco_metrics[KNTWR_LOCO_WORDS] = { KNTWR_LOCO_WORD_LABELS };
static const char *const k_loco_gate_metrics[KNTWR_LOCO_GATE_WORDS] = { KNTWR_LOCO_GATE_LABELS };
static const char *const k_loco_service_metrics[KNTWR_LOCO_SERVICE_WORDS] = { KNTWR_LOCO_SERVICE_LABELS };
static const char *const k_loco_grid_metrics[KNTWR_LOCO_GRID_WORDS] = { KNTWR_LOCO_GRID_LABELS };
static const char *const k_loco_parallel_metrics[KNTWR_LOCO_PARALLEL_WORDS] = { KNTWR_LOCO_PARALLEL_LABELS };
static const char *const k_sweep_metrics[KNTWR_SWEEP_WORDS] = { KNTWR_SWEEP_WORD_LABELS };
static const char *const k_resolve_metrics[KNTWR_RESOLVE_WORDS] = { KNTWR_RESOLVE_WORD_LABELS };
static const char *const k_env_metrics[KNTWR_ENV_WORDS] = { KNTWR_ENV_WORD_LABELS };
static const char *const k_resolve_frame_metrics[KNTWR_RESOLVE_FRAME_WORDS] = { KNTWR_RESOLVE_FRAME_LABELS };
static const char *const k_loco_owned_metrics[KNTWR_LOCO_OWNED_WORDS] = { KNTWR_LOCO_OWNED_LABELS };
static const char *const k_loco_owned_detail_metrics[KNTWR_LOCO_OWNED_DETAIL_WORDS] = { KNTWR_LOCO_OWNED_DETAIL_LABELS };
static const char *const k_loco_owned_phase_metrics[KNTWR_LOCO_OWNED_PHASE_WORDS] = { KNTWR_LOCO_OWNED_PHASE_LABELS };
static const char *const k_loco_owned_load_metrics[KNTWR_LOCO_OWNED_LOAD_WORDS] = { KNTWR_LOCO_OWNED_LOAD_LABELS };
static const char *const k_loco_grid_v2_metrics[KNTWR_LOCO_GRID_V2_WORDS] = { KNTWR_LOCO_GRID_V2_LABELS };
static const char *const k_loco_relink_metrics[KNTWR_LOCO_RELINK_WORDS] = { KNTWR_LOCO_RELINK_LABELS };
static const char *const k_loco_cw_metrics[KNTWR_LOCO_CW_WORDS] = { KNTWR_LOCO_CW_LABELS };
static const char *const k_loco_grid_build_metrics[KNTWR_LOCO_GRID_BUILD_WORDS] = { KNTWR_LOCO_GRID_BUILD_LABELS };
static const char *const k_grid_probation_metrics[KNTWR_GRID_PROBATION_HEADER_WORDS] = { KNTWR_GRID_PROBATION_LABELS };
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
    for (i = 0; i < KNTWR_GRID_PROBATION_HEADER_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_grid_probation_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    for (i = 0; i < KNTWR_GRID_PROBATION_CALLERS; ++i) {
        const uint32_t *row = w + KNTWR_GRID_PROBATION_HEADER_WORDS + 8u * i;
        if (!row[4]) continue;
        say(L"  trap eip=0x%08lX(%hs) caller=0x%08lX(%hs) threads=0x%02lX clone=%ld count=%lu writes=%lu first_site=0x%08lX last_site=0x%08lX\n",
            (unsigned long)row[0], k_grid_probation_modules[row[2] & 3u], (unsigned long)row[1],
            k_grid_probation_modules[(row[2] >> 4) & 3u], (unsigned long)((row[2] >> 8) & 0xFFu),
            (long)(row[2] >> 16) - 1, (unsigned long)row[4], (unsigned long)row[5], (unsigned long)row[6], (unsigned long)row[7]);
    }
}
static const char *const k_collide_source_metrics[KNTWR_COLLIDE_SOURCE_WORDS] = { "source", "native_stages", "owned_stages", "owned_refusals" };
static const char *const k_memory_metrics[KNTWR_MEMORY_WORDS] = { KNTWR_MEMORY_WORD_LABELS };
static void print_memory(const Run *r)
{
    unsigned i;
    if (!r->have_status) return;
    say(L"memory: activation-sized storage; VA total floor=%luMiB, hole floor=%luMiB; periodic low VA (2 consecutive samples) latches native LOCO/COLLIDE fallback until restart\n",
        (unsigned long)(r->last.memory_words[KNTWR_MEM_FLOOR_BYTES] >> 20),
        (unsigned long)(r->last.memory_words[KNTWR_MEM_HOLE_FLOOR_BYTES] >> 20));
    for (i = 0; i < KNTWR_MEMORY_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_memory_metrics[i], (unsigned long)r->last.memory_words[i], (i+1)%4 ? L" " : L"\n");
    if (KNTWR_MEMORY_WORDS % 4) say(L"\n");
    if(r->last.memory_words[KNTWR_MEM_BUDGET_DISABLED_MASK])
        say(L"  Budget fallback mask=0x%08lX (latch_reason=%lu: %ls); retired arenas=%lu; released LOCO=%lu COLLIDE=%lu bytes; LOCO breakdown retains last allocation\n",
            (unsigned long)r->last.memory_words[KNTWR_MEM_BUDGET_DISABLED_MASK],
            (unsigned long)r->last.memory_words[KNTWR_MEM_LATCH_REASON],
            r->last.memory_words[KNTWR_MEM_LATCH_REASON] == KNTWR_LATCH_REASON_HOLE ? L"hole" :
            (r->last.memory_words[KNTWR_MEM_LATCH_REASON] == KNTWR_LATCH_REASON_TOTAL ? L"total" : L"none"),
            (unsigned long)r->last.memory_words[KNTWR_MEM_BUDGET_RELEASES],
            (unsigned long)r->last.memory_words[KNTWR_MEM_RELEASED_LOCO_BYTES],
            (unsigned long)r->last.memory_words[KNTWR_MEM_RELEASED_COLLIDE_BYTES]);
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
    if (!(r->opt.mask & KNTWR_LOCO)) return;
    if (!r->have_status) { say(L"loco: no runtime status observed.\n"); return; }
    say(L"loco: Stages A/B/C site-13 movement loop 0x531AF0; optional owned grid v2 published at stage end; clone execution %ls; closed movement workers %ls; owned services %ls\n",
        r->opt.loco_clone ? L"ENABLED" : L"off (observe only: original movement)",
        r->opt.loco_parallel ? L"ENABLED (--loco-parallel)" : L"off",
        r->opt.loco_owned ? L"ENABLED (--loco-owned-services)" : L"off");
    say(L"loco.mode: quiet %ls (--loco-quiet disables per-service QPC, shadow comparisons and the all-gates histogram; faults/share retained); effective shadow comparisons %ls\n",
        r->opt.loco_quiet ? L"ENABLED" : L"off", loco_shadow_effective(&r->opt) ? L"ENABLED" : L"off");
    for (i = 0; i < KNTWR_LOCO_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    if (KNTWR_LOCO_WORDS % 4) say(L"\n");
    say(L"  admitted %.3f%% of entity occurrences; cloned=%lu native=%lu; us sums are wall time inside the stage (admitted, rejected, dispatch)\n",
        w[2] ? 100.0*w[3]/w[2] : 0.0, (unsigned long)w[27], (unsigned long)w[28]);
    say(L"  serial MOVE enforces Class/Lifetime/Parked/Pending/Environment only; removed first-fail buckets stay zero; no NODE/worker safety claim\n");
    say(L"  all-gates: denominator=%lu active +0x30 occurrences, candidates=%lu, enforced_mask=0x%03lx (bit reason-1); independent failures/details overlap and must not be summed\n",
        (unsigned long)g[1], (unsigned long)g[2], (unsigned long)g[4]);
    for (i = 0; i < KNTWR_LOCO_GATE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_gate_metrics[i], (unsigned long)g[i], (i+1)%4 ? L" " : L"\n");
    if (KNTWR_LOCO_GATE_WORDS % 4) say(L"\n");
    say(L"  all-gates admitted %.3f%%; legacy=%lu newly_admitted=%lu; detailed fields are recognized-candidate diagnostics, not first failures\n",
        g[1] ? 100.0*g[3]/g[1] : 0.0, (unsigned long)g[38], (unsigned long)g[39]);
    say(L"  ChargeFire uses DWORD +4E8/+390/+3BC/+3C8; byte +618/+619/+F1/+5AB are corroborating latches only\n");
    print_loco_services(r);
    say(L"loco.grid: %ls; combined COLLIDE borrows the published view; counters cumulative modulo 2^32\n",
        r->opt.loco_grid ? L"ENABLED: owned grid v2 published at site-13 exit" : L"grid disabled; pass --loco-grid or --loco-grid-verify");
    for (i = 0; i < KNTWR_LOCO_GRID_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_grid_metrics[i], (unsigned long)r->last.loco_grid_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.grid_v2: verification %ls; phase words remain the movement measurement\n", r->opt.loco_grid_verify ? L"ENABLED" : L"off");
    for (i = 0; i < KNTWR_LOCO_GRID_V2_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_grid_v2_metrics[i], (unsigned long)r->last.loco_grid_v2_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.grid_build: %ls; phase words are owner-QPC microseconds summed over successful builds\n",
        r->opt.loco_grid_incremental ? (r->opt.loco_grid_verify ? L"INCREMENTAL with shadow full rebuild per stage" : L"INCREMENTAL") : L"full builds");
    for (i = 0; i < KNTWR_LOCO_GRID_BUILD_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_grid_build_metrics[i], (unsigned long)r->last.loco_grid_build_words[i], (i+1)%4 ? L" " : L"\n");
    print_grid_probation(r);
    say(L"loco.relink: %ls; the op log replaces the native grid link services (live) or verifies them on a mirror (shadow)\n",
        r->opt.loco_relink_workers ? L"ENABLED (workers: live parallel apply)" : r->opt.loco_relink_shadow ? L"ENABLED (shadow: native serial apply verified)" : L"off");
    if (r->opt.loco_relink_shadow || r->opt.loco_relink_workers)
        for (i = 0; i < KNTWR_LOCO_RELINK_WORDS; ++i)
            say(L"  %hs=%lu%ls", k_loco_relink_metrics[i], (unsigned long)r->last.loco_relink_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.class_wrapper: census of the 0x132BA04 occurrences refused as needs_class_wrapper (pre-step, children, aim state, child vtables)\n");
    for (i = 0; i < KNTWR_LOCO_CW_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_cw_metrics[i], (unsigned long)r->last.loco_cw_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.parallel: without --loco-owned-services only A1==0 direct/battle occurrences enter workers; native publication is always owner-only; combined collision requires clone+parallel+owned-services+grid\n");
    for (i = 0; i < KNTWR_LOCO_PARALLEL_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_parallel_metrics[i], (unsigned long)r->last.loco_parallel_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned: %ls; one dispatch per stage, entity-range chunks claimed atomically by the pool; counters cumulative modulo 2^32; unsupported occurrences are refused to the owner before irreversible writes\n",
        r->opt.loco_owned ? L"ENABLED" : L"off");
    for (i = 0; i < KNTWR_LOCO_OWNED_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_metrics[i], (unsigned long)r->last.loco_owned_words[i], (i+1)%4 ? L" " : L"\n");
    if (r->last.loco_owned_words[31])
        say(L"  active_worker_share=%.3f%% (%lu direct + %lu battle / %lu A1!=0 mover occurrences); PROFILE outer site 13 is the timing acceptance bracket\n",
            100.0 * ((double)r->last.loco_owned_words[2] + r->last.loco_owned_words[3]) / r->last.loco_owned_words[31],
            (unsigned long)r->last.loco_owned_words[2], (unsigned long)r->last.loco_owned_words[3],
            (unsigned long)r->last.loco_owned_words[31]);
    say(L"loco.owned.detail: quiet_enabled=%lu; staging initial/result A3==0, clamp callback, class and unit-blocked splits, F0 census\n",
        (unsigned long)r->last.loco_owned_detail_words[1]);
    for (i = 0; i < KNTWR_LOCO_OWNED_DETAIL_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_detail_metrics[i], (unsigned long)r->last.loco_owned_detail_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned.phase: stage/dispatch/chunk timings; replay commit/fallback us are x16 estimates from every 16th occurrence\n");
    for (i = 0; i < KNTWR_LOCO_OWNED_PHASE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_phase_metrics[i], (unsigned long)r->last.loco_owned_phase_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.owned.load: activation-only scene/catalog/participants/prefaulted arena; Stage never prepares or grows storage; chunk CPU and worst-chunk wall/CPU remain under quiet\n");
    for (i = 0; i < KNTWR_LOCO_OWNED_LOAD_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_loco_owned_load_metrics[i], (unsigned long)r->last.loco_owned_load_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"loco.shadow: owner-thread diagnostic only; faults invalidate equivalence; histogram targets use preferred-image VAs (host callbacks retain host addresses); sweep four kinds top2\nsweep:\n");
    for (i = 0; i < KNTWR_SWEEP_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_sweep_metrics[i], (unsigned long)r->last.sweep_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"resolve:\n");
    for (i = 0; i < KNTWR_RESOLVE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_resolve_metrics[i], (unsigned long)r->last.resolve_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"resolve frames:\n");
    for (i = 0; i < KNTWR_RESOLVE_FRAME_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_resolve_frame_metrics[i], (unsigned long)r->last.resolve_frame_words[i], (i+1)%4 ? L" " : L"\n");
    say(L"env: direct outputs compared; transition events inferred from flags, notifications unobserved; callback-implied is not proof of callback causality\n");
    for (i = 0; i < KNTWR_ENV_WORDS; ++i)
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
    if (!(r->opt.mask & KNTWR_COLLIDE)) return;
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
    for (i = 0; i < KNTWR_COLLIDE_WORDS; ++i) {
        if (i == 29 || (i >= 34 && i <= 41))
            say(L"  %hs=0x%08lX%ls", k_collide_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
        else
            say(L"  %hs=%lu%ls", k_collide_metrics[i], (unsigned long)w[i], (i+1)%4 ? L" " : L"\n");
    }
    if (KNTWR_COLLIDE_WORDS % 4) say(L"\n");
    say(L"collide.source: 0=none, 1=native-audit, 2=owned; missing owned view falls back before writes\n");
    for (i = 0; i < KNTWR_COLLIDE_SOURCE_WORDS; ++i)
        say(L"  %hs=%lu%ls", k_collide_source_metrics[i], (unsigned long)r->last.collide_source_words[i], (i+1)%4 ? L" " : L"\n");
    {
        static const char *const contact_labels[KNTWR_COLLIDE_CONTACT_WORDS] = { KNTWR_COLLIDE_CONTACT_WORD_LABELS };
        const uint32_t *c = r->last.collide_contact_words;
        say(L"collide.contact (mode 1=shadow, 2=workers; vtables/slot are image-relative VAs):\n");
        for (i = 0; i < KNTWR_COLLIDE_CONTACT_WORDS; ++i) {
            if (i >= 34 && i <= 36)
                say(L"  %hs=0x%08lX%ls", contact_labels[i], (unsigned long)c[i], (i+1)%4 ? L" " : L"\n");
            else
                say(L"  %hs=%lu%ls", contact_labels[i], (unsigned long)c[i], (i+1)%4 ? L" " : L"\n");
        }
        if (KNTWR_COLLIDE_CONTACT_WORDS % 4) say(L"\n");
        say(L"  plan_thread_us = per-chunk QPC occupancy summed over owner+workers (elapsed incl. preemption, not CPU time); plan_thread_us/plan_us = plan parallelism\n");
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
    unsigned group, i, order[KNTWR_BRAIN_SUBSTATE_BUCKETS];
    wchar_t label[24];
    if (!(r->opt.mask & KNTWR_BRAIN) || !r->active_generations) return;
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
        const unsigned base = group ? KNTWR_BRAIN_SUBSTATE_COUNTS : KNTWR_BRAIN_STATE_COUNTS;
        const unsigned n = group ? KNTWR_BRAIN_SUBSTATE_BUCKETS : KNTWR_BRAIN_STATE_BUCKETS;
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
    brain_state_order(w+KNTWR_BRAIN_TRANSITION_COUNTS, KNTWR_BRAIN_STATE_BUCKETS, order);
    for (i = 0; i < KNTWR_BRAIN_STATE_BUCKETS; ++i) {
        const unsigned bucket = order[i];
        const uint32_t count = w[KNTWR_BRAIN_TRANSITION_COUNTS+bucket];
        if (!count) continue;
        brain_state_label(bucket, FALSE, label, 24);
        say(L"    %-11ls %12.2f %11.2f %16.3f%%\n", label, (double)count/w[0],
            (double)w[KNTWR_BRAIN_TRANSITION_UNITS+bucket]/w[0], w[8] ? 100.0*count/w[8] : 0.0);
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

static void sb_brain_locality(Sb *b, const uint32_t *w, int requested)
{
    static const char *const header[] = { KNTWR_BRAIN_LOC_LABEL_HEADER };
    static const char *const scalars[] = { KNTWR_BRAIN_LOC_LABEL_SCALARS };
    static const char *const types[] = { KNTWR_BRAIN_LOC_TYPE_LABELS };
    static const char *const tw[] = { KNTWR_BRAIN_LOC_TYPE_WORD_LABELS };
    static const char *const armn[] = { "cold", "treated" };
    BrainLocStats t;
    unsigned i, k;
    int ok;
    if (!requested) { sb_fmt(b, "null"); return; }
    ok = brain_loc_stats(w, &t);
    sb_fmt(b, "{\"header\": {");
    for (i = 0; i < KNTWR_BRAIN_LOC_HEADER_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", header[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"scalars\": {");
    for (i = 0; i < KNTWR_BRAIN_LOC_SCALAR_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", scalars[i], (unsigned long)w[KNTWR_BRAIN_LOC_SCALAR_BASE + i]);
    sb_fmt(b, "}, \"delta_log2_hist\": [");
    for (i = 0; i < KNTWR_BRAIN_LOC_DELTA_BINS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[KNTWR_BRAIN_LOC_DELTA_BASE + i]);
    sb_fmt(b, "], \"unit_run_log2_hist\": [");
    for (i = 0; i < KNTWR_BRAIN_LOC_RUN_BINS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[KNTWR_BRAIN_LOC_RUN_BASE + i]);
    sb_fmt(b, "], \"types\": {");
    for (i = 0; i < KNTWR_BRAIN_LOC_TYPES; ++i) {
        sb_fmt(b, "%s\"%s\": {", i ? ", " : "", types[i]);
        for (k = 0; k < KNTWR_BRAIN_LOC_TYPE_WORDS; ++k)
            sb_fmt(b, "%s\"%s\": %lu", k ? ", " : "", tw[k], (unsigned long)w[KNTWR_BRAIN_LOC_TYPE_BASE + i * KNTWR_BRAIN_LOC_TYPE_WORDS + k]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "}, \"new_line_buckets\": [");
    for (i = 0; i < KNTWR_BRAIN_LOC_BUCKETS; ++i) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_BUCKET_BASE + i * KNTWR_BRAIN_LOC_BUCKET_WORDS;
        sb_fmt(b, "%s{\"new_lines_from\": %lu, \"n\": %lu, \"cycles_sum\": %.0f, \"cycles_sq\": %.6g}", i ? ", " : "", (unsigned long)(4 * i),
               (unsigned long)q[0], (double)s0_u64(q + 1), s0_f64(q + 3));
    }
    sb_fmt(b, "], \"arms\": {");
    for (i = 0; i < KNTWR_BRAIN_LOC_ARMS; ++i) {
        const uint32_t *q = w + KNTWR_BRAIN_LOC_ARM_BASE + i * KNTWR_BRAIN_LOC_ARM_WORDS;
        sb_fmt(b, "%s\"%s\": {\"n\": %lu, \"cycles_sum\": %.0f, \"cycles_sq\": %.6g, \"touch_sum\": %.0f, \"touch_sq\": %.6g, \"hist\": [",
               i ? ", " : "", armn[i], (unsigned long)q[0], (double)s0_u64(q + 1), s0_f64(q + 3), (double)s0_u64(q + 5), s0_f64(q + 7));
        for (k = 0; k < KNTWR_BRAIN_LOC_HIST_BINS; ++k)
            sb_fmt(b, "%s%lu", k ? "," : "", (unsigned long)w[KNTWR_BRAIN_LOC_HIST_BASE + i * KNTWR_BRAIN_LOC_HIST_BINS + k]);
        sb_fmt(b, "]}");
    }
    sb_fmt(b, "}, \"estimated\": %s, \"cycles_per_ms\": %.3f, \"members_per_stage\": %.3f, \"loop_ms_per_stage\": %.6f, "
              "\"cold_step_ms_per_stage\": %.6f, \"cold_mean\": %.3f, \"cold_se\": %.3f, \"cold_median\": %.1f, \"treated_mean\": %.3f, "
              "\"treated_se\": %.3f, \"treated_median\": %.1f, \"touch_mean\": %.3f, \"touch_se\": %.3f, \"gain_cycles\": %.3f, "
              "\"gain_se\": %.3f, \"net_cycles\": %.3f, \"net_se\": %.3f, \"gain_ms_per_stage\": %.6f, \"net_ms_per_stage\": %.6f, "
              "\"cycles_per_new_line\": %.4f, \"intercept_cycles\": %.3f}", ok ? "true" : "false", t.cpm, t.per_stage, t.loop_ms,
           t.cold_ms, t.mean[0], t.se[0], t.median[0], t.mean[1], t.se[1], t.median[1], t.touch_mean, t.touch_se, t.gain, t.gain_se,
           t.net, t.net_se, t.gain_ms, t.net_ms, t.slope, t.intercept);
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

/* A short ASCII/ANSI diagnostic (the gameplay patch's error buffers) as a JSON string. */
static void sb_astr(Sb *b, const char *s)
{
    wchar_t w[256];
    if (MultiByteToWideChar(CP_ACP, 0, s, -1, w, 256) <= 0) w[0] = 0;
    sb_wstr(b, w);
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
        const kntwr_trace_entry *e = &log->entries[i];
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

static const char *const k_profile_modules[KNTWR_PROFILE_MODULE_COUNT] = {
    "main_image", "kntwr", "d3d9", "driver", "ntdll", "kernel32", "tbb", "msvcr", "other"
};
static const char *const k_profile_phases[KNTWR_PROFILE_MAIN_PHASES] = { "A1", "B", "C", "A2" };
static const uint32_t k_profile_phase_order[KNTWR_PROFILE_MAIN_PHASES] = {
    KNTWR_PROFILE_PHASE_A1, KNTWR_PROFILE_PHASE_A2, KNTWR_PROFILE_PHASE_B, KNTWR_PROFILE_PHASE_C
};

static void sb_profile_modules(Sb *b, const Run *r)
{
    const kntwr_profile_status *p = &r->profile;
    uint32_t phase, index, module;
    if (!r->have_profile) {
        sb_fmt(b, "  \"main_thread_profile\": null,\n");
        return;
    }
    sb_fmt(b, "  \"main_thread_profile\": {\"abi\": %lu, \"thread_id\": %lu, \"post_tick_ms\": %lu, \"start_tick_ms\": %lu, "
           "\"module_refresh_failed\": %lu, \"module_omitted\": %lu, \"phases\": [",
           (unsigned long)p->abi, (unsigned long)p->main_thread_id, (unsigned long)p->main_post_tick_ms,
           (unsigned long)p->main_start_tick_ms, (unsigned long)p->module_refresh_failed, (unsigned long)p->module_omitted);
    for (index = 0; index < KNTWR_PROFILE_MAIN_PHASES; ++index) {
        phase = k_profile_phase_order[index];
        sb_fmt(b, "%s{\"phase\": \"%s\", \"samples\": %lu, \"wait_samples\": %lu, \"modules\": {",
               index ? "," : "", k_profile_phases[phase], (unsigned long)KNTWR_PROFILE_PHASE_FIELD(p, phase, samples),
               (unsigned long)KNTWR_PROFILE_PHASE_FIELD(p, phase, wait));
        for (module = 0; module < KNTWR_PROFILE_MODULE_COUNT; ++module)
            sb_fmt(b, "%s\"%s\": %lu", module ? "," : "", k_profile_modules[module],
                   (unsigned long)KNTWR_PROFILE_PHASE_FIELD(p, phase, modules)[module]);
        sb_fmt(b, "}}");
    }
    sb_fmt(b, "]},\n");
}

static void sb_trace(Sb *b, const TickTrace *t)
{
    const kntwr_trace_ring *p;
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
        const kntwr_trace_entry *e = &p->ring[(start + i) % p->entries];
        sb_fmt(b, "%s\n      {\"tick\": %lu, \"qpc_start\": %I64u, \"qpc_end\": %I64u, \"duration_us\": %lu}",
               i ? "," : "", (unsigned long)e->tick,
               (unsigned long long)trace_qpc(e->qpc_start_lo, e->qpc_start_hi),
               (unsigned long long)trace_qpc(e->qpc_end_lo, e->qpc_end_hi), (unsigned long)e->duration_us);
    }
    sb_fmt(b, "\n    ],\n");
    sb_fmt(b, "    \"trace_abi\": %u,\n    \"timed_ticks\": %lu,\n"
           "    \"site_semantics\": \"inclusive enter-to-return per call; site 2 includes sites 16..25; skipped sites zero\",\n"
           "    \"site_share_basis\": \"all retained tick durations\",\n    \"sites\": [",
           KNTWR_TRACE_ABI, (unsigned long)t->timed_ticks);
    for (i = 0; i < KNTWR_TIMED_SITES; ++i)
        sb_fmt(b, "%s\n      {\"index\": %lu, \"callee_va\": \"0x%06lX\", \"sum_us\": %I64u, \"calls\": %I64u, \"duration_share\": %.9f}",
               i ? "," : "", (unsigned long)i, (unsigned long)k_site_callee_vas[i],
               (unsigned long long)t->site_sum[i], (unsigned long long)t->site_calls[i], t->site_sum[i] * share_scale);
    sb_fmt(b, "\n    ],\n    \"longest_ticks\": [");
    for (i = 0; i < t->top_count; ++i) {
        const kntwr_trace_entry *e = &p->ring[t->top[i]];
        sb_fmt(b, "%s\n      {\"tick\": %lu, \"duration_us\": %lu, \"interval_us\": %lu, "
               "\"manager_us\": %lu, \"ballistics_us\": %lu, \"path_us\": %lu, \"sites\": [",
               i ? "," : "", (unsigned long)e->tick, (unsigned long)e->duration_us, (unsigned long)e->interval_us,
               (unsigned long)e->manager_us, (unsigned long)e->ballistics_us, (unsigned long)e->path_us);
        for (j = 0; j < KNTWR_TIMED_SITES; ++j)
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
    if (!(r->opt.mask & KNTWR_BRAIN2) || !r->have_status) {
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
    for (i = 0; i < KNTWR_BRAIN2_CENSUS_WORDS / 8u; ++i) {
        const uint32_t *q = r->last.brain2_census_words + i * 8;
        sb_fmt(b, "%s{\"id\": %u, \"name\": \"%s\", \"calls\": %lu, \"active\": %lu, \"unknown\": %lu, "
               "\"inactive\": %lu, \"first_active_occurrences\": %lu, \"first_unknown_occurrences\": %lu, \"qpc_ticks\": %I64u}",
               i ? "," : "", i, k_brain2_services[i], (unsigned long)q[0], (unsigned long)q[1],
               (unsigned long)q[2], (unsigned long)q[3], (unsigned long)q[4], (unsigned long)q[5],
               (ULONGLONG)q[6] | ((ULONGLONG)q[7] << 32));
    }
    sb_fmt(b, "], \"requested_node_shadow\": %s, \"requested_fire_shadow\": %s, \"node_words\": [",
           r->opt.brain_node_shadow ? "true" : "false", r->opt.brain_fire_shadow ? "true" : "false");
    for (i = 0; i < KNTWR_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.node_words[i]);
    sb_fmt(b, "], \"node_event_words\": [");
    for (i = 0; i < KNTWR_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.node_event_words[i]);
    sb_fmt(b, "], \"fire_words\": [");
    for (i = 0; i < KNTWR_FIRE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.fire_words[i]);
    sb_fmt(b, "], \"route_words\": [");
    for (i = 0; i < KNTWR_BRAIN2_ROUTE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_route_words[i]);
    sb_fmt(b, "], \"fire_commit_words\": [");
    for (i = 0; i < KNTWR_FIRE_COMMIT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.fire_commit_words[i]);
    sb_fmt(b, "], \"move_node_words\": [");
    for (i = 0; i < KNTWR_MOVE_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.move_node_words[i]);
    sb_fmt(b, "], \"move_node_event_words\": [");
    for (i = 0; i < KNTWR_MOVE_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.move_node_event_words[i]);
    sb_fmt(b, "], \"node_target_words\": [");
    for (i = 0; i < KNTWR_BRAIN2_NODE_TARGET_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_node_target_words[i]);
    sb_fmt(b, "], \"requested_parallel\": %s, \"requested_quiet\": %s, \"brain_worker_words\": [",
           r->opt.brain_parallel ? "true" : "false", r->opt.brain_quiet ? "true" : "false");
    for (i = 0; i < KNTWR_BRAIN_WORKER_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_worker_words[i]);
    sb_fmt(b, "], \"requested_unit_shadow\": %s, \"brain_unit_words\": [", r->opt.brain_unit_shadow ? "true" : "false");
    for (i = 0; i < KNTWR_BRAIN_UNIT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_unit_words[i]);
    {
        static const char *const fields[] = { KNTWR_BRAIN_UNIT_FIELD_LABELS };
        static const char *const columns[] = { KNTWR_BRAIN_UNIT_FIELD_WORD_LABELS };
        unsigned f, c;
        sb_fmt(b, "], \"unit_agreement\": {");
        for (f = 0; f < sizeof(fields) / sizeof(fields[0]); ++f) {
            sb_fmt(b, "%s\"%s\": {", f ? ", " : "", fields[f]);
            for (c = 0; c < sizeof(columns) / sizeof(columns[0]); ++c)
                sb_fmt(b, "%s\"%s\": %lu", c ? ", " : "", columns[c],
                       (unsigned long)r->last.brain_unit_words[16u + 8u * f + c]);
            sb_fmt(b, ", \"%s\": %lu}", KNTWR_BRAIN_UNIT_TICK_NONE_LABEL, (unsigned long)r->last.brain_unit_words[160u + f]);
        }
        {
            static const char *const roles[] = { KNTWR_BRAIN_UNIT_ROLE_LABELS };
            for (c = 0; c < 3u; ++c)
                sb_fmt(b, ", \"%s\": %lu", roles[c], (unsigned long)r->last.brain_unit_words[169u + c]);
        }
    }
    sb_fmt(b, "}, \"brain_worker_phase_words\": [");
    for (i = 0; i < KNTWR_BRAIN_WORKER_PHASE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_worker_phase_words[i]);
    sb_fmt(b, "], \"requested_s0\": %s, \"requested_locality\": %s, \"brain_locality\": ", r->opt.brain_s0 ? "true" : "false",
           r->opt.brain_locality ? "true" : "false");
    sb_brain_locality(b, r->last.brain_s0_words, r->opt.brain_locality);
    sb_fmt(b, ", \"brain_s0_words\": [");
    for (i = 0; i < KNTWR_BRAIN_S0_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain_s0_words[i]);
    {
        /* Labelled header and the launcher's per-mechanic estimate (print_brain_s0 / brain_s0_table formulas). */
        static const char *const header[] = { KNTWR_BRAIN_S0_HEADER_LABELS };
        static const char *const rows[] = { KNTWR_BRAIN_S0_ROW_LABELS };
        BrainS0Table t;
        unsigned k;
        static const uint32_t zero_words[KNTWR_BRAIN_S0_WORDS] = { 0 };
        const uint32_t *s0w = r->opt.brain_locality ? zero_words : r->last.brain_s0_words;
        const int ok = brain_s0_table(s0w, &t);
        sb_fmt(b, "], \"brain_s0\": {\"header\": {");
        for (k = 0; k < KNTWR_BRAIN_S0_HEADER_WORDS; ++k)
            sb_fmt(b, "%s\"%s\": %lu", k ? ", " : "", header[k], (unsigned long)s0w[k]);
        sb_fmt(b, "}, \"estimated\": %s, \"cycles_per_ms\": %.3f, \"step_ms_per_stage\": %.6f, \"site6_ms_per_stage\": %.6f, "
                  "\"s0_overhead_ms_per_stage\": %.6f, \"rows\": {", ok ? "true" : "false", t.cycles_per_ms, t.step_ms,
               t.site6_ms, t.overhead_ms);
        for (k = 0; k < KNTWR_BRAIN_S0_ROWS; ++k) {
            const BrainS0Row *x = &t.rows[k];
            sb_fmt(b, "%s\"%s\": {\"calls_per_stage\": %.3f, \"timed\": %.0f, \"excl_ms\": %.6f, \"excl_stat_ms\": %.6f, "
                      "\"excl_cal_ms\": %.6f, \"incl_ms\": %.6f, \"incl_stat_ms\": %.6f, \"share\": %.6f}", k ? ", " : "",
                   rows[k], x->calls, x->sampled, x->excl_ms, x->excl_stat, x->excl_cal, x->incl_ms, x->incl_stat, x->share);
        }
        {
            static const char *const policy_labels[] = { KNTWR_UNIT_POLICY_HEADER_LABELS };
            static const char *const fatigue_labels[] = { KNTWR_UNIT_FATIGUE_LABELS };
            static const char *const posture_labels[] = { KNTWR_UNIT_POSTURE_ENGAGE_LABELS };
            const uint32_t *u = r->last.brain_unit_policy_words;
            sb_fmt(b, "}}, \"requested_unit_fatigue\": %s, \"requested_unit_fatigue_shadow\": %s, \"requested_unit_posture\": %s, "
                      "\"requested_unit_posture_shadow\": %s, \"requested_unit_engage\": %s, \"requested_unit_engage_shadow\": %s, "
                      "\"unit_policy_words\": [",
                   r->opt.brain_unit_fatigue ? "true" : "false", r->opt.brain_unit_fatigue_shadow ? "true" : "false",
                   r->opt.brain_unit_posture ? "true" : "false", r->opt.brain_unit_posture_shadow ? "true" : "false",
                   r->opt.brain_unit_engage ? "true" : "false", r->opt.brain_unit_engage_shadow ? "true" : "false");
            for (k = 0; k < KNTWR_BRAIN_UNIT_POLICY_WORDS; ++k) sb_fmt(b, "%s%lu", k ? "," : "", (unsigned long)u[k]);
            sb_fmt(b, "], \"unit_policy\": {");
            for (k = 0; k < 32; ++k) sb_fmt(b, "%s\"%s\": %lu", k ? ", " : "", policy_labels[k], (unsigned long)u[k]);
            sb_fmt(b, "}, \"unit_fatigue\": {");
            for (k = 0; k < 96; ++k) sb_fmt(b, "%s\"%s\": %lu", k ? ", " : "", fatigue_labels[k], (unsigned long)u[32 + k]);
            sb_fmt(b, "}, \"unit_posture_engage\": {");
            for (k = 0; k < 128; ++k) sb_fmt(b, "%s\"%s\": %lu", k ? ", " : "", posture_labels[k], (unsigned long)u[128 + k]);
            sb_fmt(b, "}, \"unknown_site_words\": [");
        }
    }
    for (i = 0; i < KNTWR_BRAIN2_UNKNOWN_SITE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.brain2_unknown_site_words[i]);
    sb_fmt(b, "], \"idle_node_words\": [");
    for (i = 0; i < KNTWR_IDLE_NODE_CLASSES * KNTWR_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.idle_node_words[i / KNTWR_NODE_WORDS][i % KNTWR_NODE_WORDS]);
    sb_fmt(b, "], \"idle_node_event_words\": [");
    for (i = 0; i < KNTWR_IDLE_NODE_CLASSES * KNTWR_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.idle_node_event_words[i / KNTWR_NODE_EVENT_WORDS][i % KNTWR_NODE_EVENT_WORDS]);
    sb_fmt(b, "], \"action_node_words\": [");
    for (i = 0; i < KNTWR_ACTION_NODE_CLASSES * KNTWR_NODE_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.action_node_words[i / KNTWR_NODE_WORDS][i % KNTWR_NODE_WORDS]);
    sb_fmt(b, "], \"action_node_event_words\": [");
    for (i = 0; i < KNTWR_ACTION_NODE_CLASSES * KNTWR_NODE_EVENT_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.action_node_event_words[i / KNTWR_NODE_EVENT_WORDS][i % KNTWR_NODE_EVENT_WORDS]);
    sb_fmt(b, "]},\n");
}

/* "brain_sites": cumulative per-family and aggregate brain/wrapper callee timings (see print_brain_sites); null unless the brain
   feature was requested and a routed tick was observed. Shares divide by the routed tick duration sum (brain_words[1]). */
static void sb_brain(Sb *b, const Run *r)
{
    const kntwr_status *s = &r->last;
    const uint32_t ticks = s->brain_words[0], tick_us = s->brain_words[1];
    const double scale = tick_us ? 1.0 / (double)tick_us : 0.0;
    uint64_t agg_us[KNTWR_TIMED_SITES], agg_calls[KNTWR_TIMED_SITES];
    uint32_t f, site;
    char callee[24];
    if (!(r->opt.mask & KNTWR_BRAIN) || !r->have_status || !ticks) {
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
    for (f = 0; f < KNTWR_BRAIN_FAMILIES; ++f) {
        const uint32_t entities = brain_calls(s, f, KNTWR_BRAIN_SITE_FIRST + f);
        const uint32_t entry_us = brain_us(s, f, KNTWR_BRAIN_SITE_FIRST + f);
        uint32_t rows = 0;
        sb_fmt(b, "%s\n      {\"index\": %lu, \"name\": \"%s\", \"vtables\": %lu, \"entry_va\": \"0x%06lX\", \"entities\": %lu, "
               "\"entities_per_tick\": %.6f, \"entry_sum_us\": %lu, \"entry_tick_share\": %.9f, \"sites\": [",
               f ? "," : "", (unsigned long)f, k_brain_families[f].jname, (unsigned long)k_brain_families[f].tables,
               (unsigned long)k_brain_families[f].entry_va, (unsigned long)entities, (double)entities / ticks,
               (unsigned long)entry_us, entry_us * scale);
        for (site = KNTWR_BRAIN_SITE_FIRST; site < KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_SITES; ++site) {
            const uint32_t us = brain_us(s, f, site), calls = brain_calls(s, f, site);
            if (site >= BRAIN_FIRST_CALLEE) { agg_us[site] += us; agg_calls[site] += calls; }
            if (!brain_family_owns(f, site) || site == KNTWR_BRAIN_SITE_FIRST + f) continue;
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
    for (site = BRAIN_FIRST_CALLEE; site < KNTWR_BRAIN_SITE_FIRST + KNTWR_BRAIN_SITES; ++site) {
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
    if (!r->opt.collide_census || !(r->opt.mask & KNTWR_PROFILE) || (r->opt.mask & KNTWR_COLLIDE) || !r->have_status || !w[0]) {
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

static const char *const k_grid_threads[KNTWR_GRID_THREADS] = {
    "tick_owner", "main_render", "other"
};

static const char *grid_route_name(uint32_t route)
{
    switch (route) {
    case KNTWR_GRID_ROUTE_IMAGE: return "image";
    case KNTWR_GRID_ROUTE_BINDING: return "binding";
    case KNTWR_GRID_ROUTE_CLONE: return "clone";
    case KNTWR_GRID_ROUTE_OTHER: return "other";
    default: return "unknown";
    }
}

static void print_grid_census(const Run *r)
{
    const kntwr_grid_census_status *c = &r->last.grid_census;
    unsigned i, j;
    if (!(r->opt.mask & KNTWR_GRID_CENSUS)) return;
    if (!r->have_status || c->version != 1u) {
        say(L"Grid census: no initialized census snapshot available.\n");
        return;
    }
    say(L"Grid census: %lu routed ticks; %lu readers (capacity %u), %lu instrumented edges (capacity %u).\n",
        (unsigned long)c->routed_ticks, (unsigned long)c->reader_count, KNTWR_GRID_READERS,
        (unsigned long)c->edge_count, KNTWR_GRID_EDGES);
    say(L"  Route calls count retargeted private-clone edges. Only IMAGE destinations prove native reader entries.\n"
        L"  Binding/clone/other destinations may defer, skip or replace readers; route calls are NOT reader entries.\n"
        L"  Rates divide the corresponding in-tick calls by routed ticks (n/a if zero). Samples are EIP occupancy, never calls.\n"
        L"  Totals wrap modulo 2^32 over this start/stop session. Phase/site/thread histograms count routes, not entries.\n"
        L"  Last tick/site/thread/phase are hints; site %u is unknown; non-owner sites observe the owner's dispatch site.\n",
        KNTWR_GRID_UNKNOWN_SITE);
    say(L"  sample_attempts=%lu sample_failures=%lu unknown_samples=%lu attribution_dropped=%lu edge_dropped=%lu unresolved_edges=%lu\n",
        (unsigned long)c->sample_attempts, (unsigned long)c->sample_failures,
        (unsigned long)c->unknown_samples, (unsigned long)c->attribution_dropped,
        (unsigned long)c->edge_dropped, (unsigned long)c->unresolved_edges);
    say(L"  unresolved_edges counts ungated internal-call/direct-jump references, not measured calls or complete coverage.\n");
    for (i = 0; i < c->reader_count && i < KNTWR_GRID_READERS; ++i) {
        const kntwr_grid_reader_status *v = &c->readers[i];
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
        for (j = 0; j < KNTWR_GRID_PHASES; ++j)
            say(L"    phase %-2hs route_calls=%lu occupancy=%lu\n", k_profile_phases[j],
                (unsigned long)v->calls_phase[j], (unsigned long)v->samples_phase[j]);
        for (j = 0; j < KNTWR_GRID_THREADS; ++j)
            say(L"    thread %-17hs route_calls=%lu occupancy=%lu\n", k_grid_threads[j],
                (unsigned long)v->calls_thread[j], (unsigned long)v->samples_thread[j]);
        for (j = 0; j < KNTWR_GRID_SITES; ++j)
            if (v->calls_site[j] || v->samples_site[j])
                say(L"    site %u route_calls=%lu occupancy=%lu\n", j,
                    (unsigned long)v->calls_site[j], (unsigned long)v->samples_site[j]);
    }
    for (i = 0; i < c->edge_count && i < KNTWR_GRID_EDGES; ++i) {
        const kntwr_grid_edge_status *e = &c->edges[i];
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
    const kntwr_grid_census_status *c = &r->last.grid_census;
    unsigned i, j;
    if (!(r->opt.mask & KNTWR_GRID_CENSUS) || !r->have_status || c->version != 1u) {
        sb_fmt(b, "  \"grid_census\": null,\n");
        return;
    }
    sb_fmt(b, "  \"grid_census\": {\"version\":%lu,\"reader_count\":%lu,\"edge_count\":%lu,"
           "\"reader_capacity\":%u,\"edge_capacity\":%u,\"routed_ticks\":%lu,"
           "\"sample_attempts\":%lu,\"sample_failures\":%lu,\"unknown_samples\":%lu,"
           "\"attribution_dropped\":%lu,\"edge_dropped\":%lu,\"unresolved_edges\":%lu,\n",
           (unsigned long)c->version, (unsigned long)c->reader_count, (unsigned long)c->edge_count,
           KNTWR_GRID_READERS, KNTWR_GRID_EDGES, (unsigned long)c->routed_ticks,
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
    for (i = 0; i < c->reader_count && i < KNTWR_GRID_READERS; ++i) {
        const kntwr_grid_reader_status *v = &c->readers[i];
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
        for (j = 0; j < KNTWR_GRID_PHASES; ++j)
            sb_fmt(b, "%s\"%s\":{\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", k_profile_phases[j],
                   (unsigned long)v->calls_phase[j], (unsigned long)v->samples_phase[j]);
        sb_fmt(b, "},\"thread_classes\":{");
        for (j = 0; j < KNTWR_GRID_THREADS; ++j)
            sb_fmt(b, "%s\"%s\":{\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", k_grid_threads[j],
                   (unsigned long)v->calls_thread[j], (unsigned long)v->samples_thread[j]);
        sb_fmt(b, "},\"sites\":[");
        for (j = 0; j < KNTWR_GRID_SITES; ++j)
            sb_fmt(b, "%s{\"site\":%u,\"route_calls\":%lu,\"samples\":%lu}", j ? "," : "", j,
                   (unsigned long)v->calls_site[j], (unsigned long)v->samples_site[j]);
        sb_fmt(b, "]}");
    }
    sb_fmt(b, "],\"edges\":[");
    for (i = 0; i < c->edge_count && i < KNTWR_GRID_EDGES; ++i) {
        const kntwr_grid_edge_status *e = &c->edges[i];
        sb_fmt(b, "%s{\"id\":%u,\"reader\":%lu,\"site\":%lu,\"source_clone\":%lu,\"route\":%lu,\"route_name\":\"%s\","
               "\"native_entry_proven\":%s,\"route_calls\":%lu,\"route_tick_calls\":%lu,\"route_calls_per_routed_tick\":",
               i ? "," : "", i, (unsigned long)e->reader, (unsigned long)e->site,
               (unsigned long)e->source_clone, (unsigned long)e->route, grid_route_name(e->route),
               e->route==KNTWR_GRID_ROUTE_IMAGE ? "true" : "false",
               (unsigned long)e->route_calls, (unsigned long)e->route_tick_calls);
        sb_ratio(b, e->route_tick_calls, c->routed_ticks);
        sb_fmt(b, ",\"last_tick\":%lu,\"last_thread\":%lu}",
               (unsigned long)e->last_tick, (unsigned long)e->last_thread);
    }
    sb_fmt(b, "]},\n");
}

/* ---- AI mutation census (KNTWR_AI_CENSUS): word layout documented at kntwr_status::ai_census_words in include/kntwr_runtime.h ---- */
#define AIC_HEADER 16u
#define AIC_TARGETS 7u
#define AIC_TARGET_HEADER 8u
#define AIC_TOP 8u
#define AIC_CALLER 12u
#define AIC_TARGET_WORDS (AIC_TARGET_HEADER + AIC_TOP * AIC_CALLER)
#define AIC_RANGES 3u
#define AIC_RANGE_WORDS 8u
typedef char kntwr_launcher_ai_census_layout[(KNTWR_AI_CENSUS_WORDS == AIC_HEADER + AIC_TARGETS * AIC_TARGET_WORDS + AIC_RANGES * AIC_RANGE_WORDS) ? 1 : -1];
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
    if (!(r->opt.mask & KNTWR_AI_CENSUS)) return;
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

/* army_unit (KNTWR_ARMY_UNIT_SHADOW): raw words plus the labelled header/reason/foreign words and command rows; b0 holds
   the labelled Stage B0 qualification row (army_b0_words, native_army_unit.h B0Word). */
static void sb_army_unit(Sb *b, const Run *r)
{
    static const char *const header[] = { KNTWR_ARMY_UNIT_HEADER_LABELS };
    static const char *const reasons[] = { KNTWR_ARMY_UNIT_REASON_LABELS };
    static const char *const details[] = { KNTWR_ARMY_UNIT_DETAIL_LABELS };
    static const char *const foreign[] = { KNTWR_ARMY_UNIT_FOREIGN_LABELS };
    static const char *const command[] = { KNTWR_ARMY_UNIT_COMMAND_LABELS };
    static const char *const b0[] = { KNTWR_ARMY_B0_LABELS };
    const uint32_t *w = r->last.army_unit_words;
    unsigned i, c;
    if (!(r->opt.mask & KNTWR_ARMY_UNIT_SHADOW) || !r->have_status || !w[0]) {
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
    for (i = 0; i < KNTWR_ARMY_UNIT_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "], \"b0\": {");
    for (i = 0; i < KNTWR_ARMY_B0_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", b0[i], (unsigned long)r->last.army_b0_words[i]);
    sb_fmt(b, "}, \"b0_words\": [");
    for (i = 0; i < KNTWR_ARMY_B0_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)r->last.army_b0_words[i]);
    sb_fmt(b, "]},\n");
}
/* army_storm (KNTWR_ARMY_STORM_CENSUS): every labelled word of army_storm_words (native_army_storm.h) plus the decoded top-8 table. */
static void sb_army_storm(Sb *b, const Run *r)
{
    static const char *const labels[KNTWR_ARMY_STORM_WORDS] = { KNTWR_ARMY_STORM_LABELS };
    const uint32_t *w = r->last.army_storm_words;
    unsigned i;
    if (!(r->cfg.va_watch_flags & KNTWR_ARMY_STORM_CENSUS) || !r->have_status || !w[1]) {
        sb_fmt(b, "  \"army_storm\": null,\n");
        return;
    }
    sb_fmt(b, "  \"army_storm\": {\"sample_ms\": %lu, \"words\": {", (unsigned long)((r->cfg.va_watch_flags & KNTWR_ARMY_STORM_SAMPLE_MASK) >> KNTWR_ARMY_STORM_SAMPLE_SHIFT));
    for (i = 0; i < KNTWR_ARMY_STORM_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", labels[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"raw\": [");
    for (i = 0; i < KNTWR_ARMY_STORM_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
/* army_residual (KNTWR_ARMY_STORM_CENSUS): every labelled word of army_residual_words (native_formation_residual.h, 832 words) plus the decoded
   top rows with their 64-bit QPC start identity ("top": retained rows in table order; "ledger" in the words map counts what was offered/omitted;
   "route" of a row = the routed command-split callbacks of that invocation and "route_slow" the slowest routed callback's own nested counts,
   valid only when route.calls != 0), the decoded queue class table ("queue_classes": cumulative over every observed normally-returned callback,
   aborted ticks included) and the cumulative "route_table". */
static void sb_army_residual(Sb *b, const Run *r)
{
    static const char *const labels[KNTWR_FORMATION_RESIDUAL_WORDS] = { KNTWR_FORMATION_RESIDUAL_LABELS };
    const uint32_t *w = r->last.army_residual_words;
    unsigned i, n = 0;
    if (!(r->cfg.va_watch_flags & KNTWR_ARMY_STORM_CENSUS) || !r->have_status || !w[1]) {
        sb_fmt(b, "  \"army_residual\": null,\n");
        return;
    }
    if (w[0] != KNTWR_FORMATION_RESIDUAL_VERSION) {
        sb_fmt(b, "  \"army_residual\": {\"unsupported_version\": %lu, \"expected_version\": %lu},\n",
               (unsigned long)w[0], (unsigned long)KNTWR_FORMATION_RESIDUAL_VERSION);
        return;
    }
    sb_fmt(b, "  \"army_residual\": {\"version\": %lu, \"words\": {", (unsigned long)w[0]);
    for (i = 0; i < KNTWR_FORMATION_RESIDUAL_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", labels[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"raw\": [");
    for (i = 0; i < KNTWR_FORMATION_RESIDUAL_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "], \"top\": [");
    for (i = 0; i < KNTWR_FORMATION_RESIDUAL_TOP_ROWS; ++i) {
        const uint32_t *e = w + KNTWR_FORMATION_RESIDUAL_TOP_OFFSET + i * KNTWR_FORMATION_RESIDUAL_ENTRY_WORDS;
        if (!e[0] && !e[3] && !e[24] && !e[25]) continue;
        sb_fmt(b, "%s{\"tick\": %lu, \"qpc_start\": %I64u, \"tick_us\": %lu, \"site18_us\": %lu, \"form_us\": %lu, \"member_calls\": %lu, "
                  "\"loop_calls\": %lu, \"lim_calls\": %lu, \"lim_us\": %lu, \"lim_max_us\": %lu, \"flags\": %lu, "
                  "\"queue_cmd_calls\": %lu, \"queue_cmd_us\": %lu, \"slow_vtable\": %lu, \"slow_slot\": %lu, \"slow_us\": %lu, "
                  "\"slow_routed\": %s, \"route\": {\"calls\": %lu, \"us\": %lu, \"enter_calls\": %lu, \"enter_us\": %lu, \"other_enter_calls\": %lu, \"other_enter_us\": %lu, "
                  "\"assign_calls\": %lu, \"assign_us\": %lu, \"perman_calls\": %lu, \"perman_us\": %lu, "
                  "\"assign_scope_us\": %lu, \"assign_scope_calls\": %lu, \"inner_kernel_us\": %lu, \"inner_solves\": %lu, "
                  "\"inner_lim_us\": %lu, \"inner_lim_calls\": %lu, \"inner_suppressed\": %lu, \"inner_assign_entries\": %lu}, "
                  "\"route_slow\": {\"vtable\": %lu, \"slot\": %lu, \"us\": %lu, \"enter_calls\": %lu, \"enter_us\": %lu, \"other_enter_calls\": %lu, \"other_enter_us\": %lu, "
                  "\"assign_calls\": %lu, \"assign_us\": %lu, \"perman_calls\": %lu, \"perman_us\": %lu, "
                  "\"assign_scope_us\": %lu, \"assign_scope_calls\": %lu, \"inner_kernel_us\": %lu, \"inner_solves\": %lu, "
                  "\"inner_lim_us\": %lu, \"inner_lim_calls\": %lu, \"inner_suppressed\": %lu, \"inner_assign_entries\": %lu}}",
               n++ ? ", " : "", (unsigned long)e[0], ((unsigned long long)e[25] << 32) | e[24],
               (unsigned long)e[26], (unsigned long)e[1], (unsigned long)e[3], (unsigned long)e[8], (unsigned long)e[9],
               (unsigned long)e[27], (unsigned long)e[28], (unsigned long)e[29], (unsigned long)e[30],
               (unsigned long)e[31], (unsigned long)e[32], (unsigned long)e[33], (unsigned long)e[34], (unsigned long)e[35],
               (e[30] & 4u) ? "true" : "false",
               (unsigned long)e[36], (unsigned long)e[37], (unsigned long)e[38], (unsigned long)e[39], (unsigned long)e[40], (unsigned long)e[41],
               (unsigned long)e[42], (unsigned long)e[43], (unsigned long)e[44], (unsigned long)e[45],
               (unsigned long)e[57], (unsigned long)e[58], (unsigned long)e[59], (unsigned long)e[60],
               (unsigned long)e[61], (unsigned long)e[62], (unsigned long)e[63], (unsigned long)e[64],
               (unsigned long)e[46], (unsigned long)e[47], (unsigned long)e[48], (unsigned long)e[49], (unsigned long)e[50],
               (unsigned long)e[51], (unsigned long)e[52], (unsigned long)e[53], (unsigned long)e[54], (unsigned long)e[55], (unsigned long)e[56],
               (unsigned long)e[65], (unsigned long)e[66], (unsigned long)e[67], (unsigned long)e[68],
               (unsigned long)e[69], (unsigned long)e[70], (unsigned long)e[71], (unsigned long)e[72]);
    }
    sb_fmt(b, "], \"queue_classes\": [");
    for (i = 0, n = 0; i < KNTWR_FORMATION_RESIDUAL_QUEUE_CLASSES; ++i) {
        const uint32_t *c = w + KNTWR_FORMATION_RESIDUAL_QUEUE_OFFSET + 2 + i * 5;
        if (!c[2]) continue;
        sb_fmt(b, "%s{\"vtable\": %lu, \"slot\": %lu, \"calls\": %lu, \"us\": %lu, \"max_us\": %lu}",
               n++ ? ", " : "", (unsigned long)c[0], (unsigned long)c[1], (unsigned long)c[2], (unsigned long)c[3], (unsigned long)c[4]);
    }
    {
        const uint32_t *t = w + KNTWR_FORMATION_RESIDUAL_ROUTE_OFFSET;
        sb_fmt(b, "], \"route_table\": {\"armed\": %lu, \"calls\": %lu, \"us\": %lu, \"max_us\": %lu, \"no_enter_calls\": %lu, "
                  "\"enter_calls\": %lu, \"enter_us\": %lu, \"other_enter_calls\": %lu, \"other_enter_us\": %lu, "
                  "\"assign_calls\": %lu, \"assign_us\": %lu, \"perman_calls\": %lu, \"perman_us\": %lu, "
                  "\"assign_scope_us\": %lu, \"assign_scope_calls\": %lu, \"inner_kernel_us\": %lu, \"inner_solves\": %lu, "
                  "\"inner_lim_us\": %lu, \"inner_lim_calls\": %lu, \"inner_suppressed\": %lu, \"inner_assign_entries\": %lu}},\n",
               (unsigned long)t[0], (unsigned long)t[1], (unsigned long)t[2], (unsigned long)t[3], (unsigned long)t[4],
               (unsigned long)t[5], (unsigned long)t[6], (unsigned long)t[7], (unsigned long)t[8], (unsigned long)t[9],
               (unsigned long)t[10], (unsigned long)t[11], (unsigned long)t[12],
               (unsigned long)t[13], (unsigned long)t[14], (unsigned long)t[15], (unsigned long)t[16],
               (unsigned long)t[17], (unsigned long)t[18], (unsigned long)t[19], (unsigned long)t[20]);
    }
}
/* army_solver (KNTWR_ARMY_SOLVER_MEMO/SHADOW): every labelled header word of army_solver_words (native_army_solver.h) plus the decoded top-16 tick and solve tables. */
static void sb_army_solver(Sb *b, const Run *r)
{
    static const char *const labels[SOLVER_TICK_TABLE] = { KNTWR_ARMY_SOLVER_LABELS };
    static const char *const tick_labels[13] = { KNTWR_ARMY_SOLVER_TICK_LABELS };
    static const char *const solve_labels[16] = { KNTWR_ARMY_SOLVER_SOLVE_LABELS };
    const uint32_t *w = r->last.army_solver_words;
    unsigned i, j, first;
    if (!(r->cfg.va_watch_flags & (KNTWR_ARMY_SOLVER_MEMO | KNTWR_ARMY_SOLVER_SHADOW)) || !r->have_status || !w[0]) {
        sb_fmt(b, "  \"army_solver\": null,\n");
        return;
    }
    sb_fmt(b, "  \"army_solver\": {\"mode\": \"%s\", \"words\": {", w[1] == 1u ? "memo" : "shadow");
    for (i = 0; i < SOLVER_TICK_TABLE; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", labels[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"ticks\": [");
    for (i = 0, first = 1; i < 16; ++i) {
        const uint32_t *e = w + SOLVER_TICK_TABLE + i * SOLVER_ENTRY_WORDS;
        if (!e[0] && !e[1]) continue;
        sb_fmt(b, "%s{", first ? "" : ", "); first = 0;
        for (j = 0; j < 13; ++j) sb_fmt(b, "%s\"%s\": %lu", j ? ", " : "", tick_labels[j], (unsigned long)e[j]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "], \"solves\": [");
    for (i = 0, first = 1; i < 16; ++i) {
        const uint32_t *e = w + SOLVER_SOLVE_TABLE + i * SOLVER_SOLVE_WORDS;
        if (!e[0] && !e[1] && !e[2]) continue;
        sb_fmt(b, "%s{", first ? "" : ", "); first = 0;
        for (j = 0; j < 16; ++j) sb_fmt(b, "%s\"%s\": %lu", j ? ", " : "", solve_labels[j], (unsigned long)e[j]);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "], \"raw\": [");
    for (i = 0; i < KNTWR_ARMY_SOLVER_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
static void sb_alloc_census(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.alloc_census_words;
    unsigned i, first;
    if (!r->have_status || (!w[0] && !(r->cfg.va_watch_flags & (KNTWR_ALLOC_CENSUS | KNTWR_ALLOC_FIX)))) {
        sb_fmt(b, "  \"alloc_census\": null,\n");
        return;
    }
    sb_fmt(b, "  \"alloc_census\": {\"words\": {");
    for (i = 0; i < 32u; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_alloc_census_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"rows\": [");
    for (i = 0, first = 1; i < 128u; ++i) {
        const uint32_t *e = w + 32u + i * 8u;
        if (!e[0] && !e[4]) continue;
        sb_fmt(b, "%s{\"callsite_va\": %lu, \"size_class\": %lu, \"live_bytes\": %lu, \"live_count\": %lu, \"allocs\": %lu, \"frees\": %lu, \"peak_live_bytes\": %lu, \"reserved\": %lu}",
               first ? "" : ", ", (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], (unsigned long)e[3],
               (unsigned long)e[4], (unsigned long)e[5], (unsigned long)e[6], (unsigned long)e[7]);
        first = 0;
    }
    sb_fmt(b, "], \"raw\": [");
    for (i = 0; i < KNTWR_ALLOC_CENSUS_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
static void sb_arena(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.arena_words;
    unsigned i;
    if (!r->have_status || (!w[0] && !(r->cfg.va_watch_flags & (KNTWR_ARENA_RELEASE | KNTWR_HEAP_OPTIMIZE)))) {
        sb_fmt(b, "  \"arena\": null,\n");
        return;
    }
    sb_fmt(b, "  \"arena\": {\"words\": {");
    for (i = 0; i < KNTWR_ARENA_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_arena_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"raw\": [");
    for (i = 0; i < KNTWR_ARENA_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
static void sb_overlay(Sb *b, const Run *r)
{
    const uint32_t *w = r->have_overlay ? r->overlay_words : r->last.overlay_words;
    unsigned i;
    if (!w[0]) {
        sb_fmt(b, "  \"overlay\": null,\n");
        return;
    }
    sb_fmt(b, "  \"overlay\": {\"note\": \"report-only; unloading an overlay DLL that has hooked Present is unsafe\", \"words\": {");
    for (i = 0; i < KNTWR_OVERLAY_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_overlay_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"modules\": [");
    for (i = 0; i < r->overlay_mod_count; ++i) {
        const struct OverlayMod *m = &r->overlay_mods[i];
        sb_fmt(b, "%s{\"name\": ", i ? ", " : "");
        sb_wstr(b, m->name);
        sb_fmt(b, ", \"kind\": \"%s\", \"base\": \"0x%08lX\", \"size\": %lu, \"splits_low_hole\": %s}",
               m->is_nv_umd ? "nv_umd" : "foreign_hook", (unsigned long)m->base, (unsigned long)m->size,
               m->splits_low_hole ? "true" : "false");
    }
    sb_fmt(b, "], \"raw\": [");
    for (i = 0; i < KNTWR_OVERLAY_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
/* --mounted-officer (src/army/kntwr_mounted_officer.h): the gate counters; null unless requested. */
static void sb_mounted_officer(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.mounted_officer_words;
    unsigned i;
    if (!r->opt.mounted_officer) {
        sb_fmt(b, "  \"mounted_officer\": null,\n");
        return;
    }
    sb_fmt(b, "  \"mounted_officer\": {\"have_status\": %s, \"words\": {", r->have_status ? "true" : "false");
    for (i = 0; i < KNTWR_MOUNTED_OFFICER_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_mounted_officer_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"raw\": [");
    for (i = 0; i < KNTWR_MOUNTED_OFFICER_WORDS; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]},\n");
}
/* Clip picker crash guard (always on): the counters of the entry redirect at 0xE5F760. */
static void sb_anim_guard(Sb *b, const Run *r)
{
    static const char *const names[KNTWR_ANIM_GUARD_WORDS] = { KNTWR_ANIM_GUARD_LABELS };
    unsigned i;
    if (!r->have_status) {
        sb_fmt(b, "  \"anim_guard\": null,\n");
        return;
    }
    sb_fmt(b, "  \"anim_guard\": {");
    for (i = 0; i < KNTWR_ANIM_GUARD_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", names[i], (unsigned long)r->last.anim_guard_words[i]);
    sb_fmt(b, "},\n");
}
/* --drag-ladder (src/formation/kntwr_drag_ladder_hook.h): the hook counters; null unless requested. installed is sticky applied-this-run (1 after a successful Install until ResetRow), not live hook presence. */
static void sb_drag_ladder(Sb *b, const Run *r)
{
    static const char *const names[KNTWR_DRAG_LADDER_WORDS] = { KNTWR_DRAG_LADDER_LABELS };
    unsigned i;
    if (!r->opt.drag_ladder) {
        sb_fmt(b, "  \"drag_ladder\": null,\n");
        return;
    }
    sb_fmt(b, "  \"drag_ladder\": {\"have_status\": %s, \"words\": {", r->have_status ? "true" : "false");
    for (i = 0; i < KNTWR_DRAG_LADDER_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", names[i], (unsigned long)r->last.drag_ladder_words[i]);
    sb_fmt(b, "}},\n");
}
/* --wounded (src/animation/kntwr_wounded_hook.h): the hook counters; null unless requested. installed is sticky applied-this-run (1 after a successful Install until ResetRow), not live hook presence. */
static void sb_wounded(Sb *b, const Run *r)
{
    static const char *const names[KNTWR_WOUNDED_WORDS] = { KNTWR_WOUNDED_LABELS };
    unsigned i;
    if (!r->opt.wounded) {
        sb_fmt(b, "  \"wounded\": null,\n");
        return;
    }
    sb_fmt(b, "  \"wounded\": {\"have_status\": %s, \"pct\": %lu, \"words\": {", r->have_status ? "true" : "false", (unsigned long)r->opt.wounded_pct);
    for (i = 0; i < KNTWR_WOUNDED_WORDS; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", names[i], (unsigned long)r->last.wounded_words[i]);
    sb_fmt(b, "}},\n");
}
static void sb_u32_array(Sb *b, const char *name, const uint32_t *w, unsigned n)
{
    unsigned i;
    sb_fmt(b, "\"%s\": [", name);
    for (i = 0; i < n; ++i) sb_fmt(b, "%s%lu", i ? "," : "", (unsigned long)w[i]);
    sb_fmt(b, "]");
}
static void sb_engage_rows(Sb *b, const char *name, const uint32_t *base, unsigned count, unsigned first)
{
    unsigned i, j;
    sb_fmt(b, "\"%s\": [", name);
    for (i = 0; i < count; ++i) {
        const uint32_t *row = base + ((first + i) % EC_ROWS) * EC_ROW_WORDS;
        sb_fmt(b, "%s[", i ? "," : "");
        for (j = 0; j < EC_ROW_WORDS; ++j) sb_fmt(b, "%s%lu", j ? "," : "", (unsigned long)row[j]);
        sb_fmt(b, "]");
    }
    sb_fmt(b, "]");
}
/* --engage-census (src/ai/kntwr_engage_census.h): counters, histograms and rows as raw uint32 words (floats are IEEE bit patterns; -1.0f = 0xBF800000 = unknown); null unless requested.
   Rows: [tick, unit, type(1 HALT/2 FIRE_START), dC, dM, dMe, range, B34, ring count, ring index, cmd vtable, class, members, ticks_stopped, enemy unit, side, destD, destEnemyD, flags, 0]. */
static void sb_engage_census(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.engage_census_words;
    unsigned i, ev, ring_n;
    if (!r->opt.engage_census) {
        sb_fmt(b, "  \"engage_census\": null,\n");
        return;
    }
    sb_fmt(b, "  \"engage_census\": {\"have_status\": %s, \"counters\": {", r->have_status ? "true" : "false");
    for (i = 0; i < EC_HDR; ++i) sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_engage_census_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, ", \"art_halts\": %lu, \"art_fire_starts\": %lu, \"trace_samples\": %lu, \"ever_firing_nonart\": %lu, \"atk30_events\": %lu, \"atk2C_events\": %lu, "
           "\"firing_calls\": %lu, \"firing_true\": %lu},\n    ",
           (unsigned long)w[31], (unsigned long)w[248], (unsigned long)w[249], (unsigned long)w[250], (unsigned long)w[251], (unsigned long)w[252], (unsigned long)w[6448],
           (unsigned long)w[6449]);
    sb_u32_array(b, "halt_ratio_hist", w + EC_HALT_RATIO, 22);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "halt_metres_hist", w + EC_HALT_METRES, 22);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "fire_ratio_hist", w + EC_FIRE_RATIO, 22);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "moving_all", w + EC_MOVING_ALL, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "moving_b34_0", w + EC_MOVING_B0, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "moving_b34_1", w + EC_MOVING_B1, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "moving_b34_4", w + EC_MOVING_B4, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "moving_b34_other", w + EC_MOVING_OTHER, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "still_all_hist", w + EC_STILL_ALL, 30);
    sb_fmt(b, ",\n    ");
    sb_u32_array(b, "still_firing_hist", w + EC_STILL_FIRING, 30);
    sb_fmt(b, ",\n    \"class_stats\": [");
    for (i = 0; i < 8; ++i) {
        const uint32_t *c = w + EC_CLASS_STATS + 4 * i;
        sb_fmt(b, "%s{\"class\": %u, \"unit_ticks\": %lu, \"min_dC\": %.2f, \"min_dC_tick\": %lu, \"min_dM\": %.2f}", i ? ", " : "", i, (unsigned long)c[0],
               (double)ec_f(c[1]), (unsigned long)c[2], (double)ec_f(c[3]));
    }
    sb_fmt(b, "],\n    \"side_validation\": [");
    for (i = 0; i < 2; ++i) {
        const uint32_t *v = w + EC_SIDE_VAL + EC_SIDE_WORDS * i;
        sb_fmt(b, "%s{\"side\": %u, \"ai\": %lu, \"unit_ticks\": %lu, \"moving_ticks\": %lu, \"firing_ticks\": %lu, \"max_simul_firing\": %lu, \"live_units_last\": %lu, "
               "\"live_members_last\": %lu, \"firing_last_tick\": %lu, ", i ? ", " : "", i, (unsigned long)v[0], (unsigned long)v[1], (unsigned long)v[2], (unsigned long)v[3],
               (unsigned long)v[4], (unsigned long)v[5], (unsigned long)v[6], (unsigned long)v[7]);
        sb_u32_array(b, "class_unit_ticks", v + 8, 8);
        sb_fmt(b, ", ");
        sb_u32_array(b, "class_moving_ticks", v + 16, 8);
        sb_fmt(b, ", ");
        sb_u32_array(b, "class_firing_ticks", v + 24, 8);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "],\n    \"firing_diag\": {\"diag_units\": %lu, ", (unsigned long)w[EC_DIAG_UNITS]);
    sb_u32_array(b, "formation_slot_idx_hist_0_8_other", w + EC_FIDX_HIST, 10);
    sb_fmt(b, ", \"slot_obj_null\": %lu, \"reject_idx\": %lu, \"slot_obj_insane\": %lu, \"slot_vt_not_image\": %lu, \"slot_target_not_image\": %lu, \"slot_vt_other\": %lu, "
           "\"rowvt_other\": %lu, \"row_none\": %lu, \"row_bad_idx\": %lu, \"row_vt_rejected\": %lu, \"object_vtables\": [",
           (unsigned long)w[6443], (unsigned long)w[6444], (unsigned long)w[6445], (unsigned long)w[6446], (unsigned long)w[6447], (unsigned long)w[6450], (unsigned long)w[6451],
           (unsigned long)w[6452], (unsigned long)w[6453], (unsigned long)w[6454]);
    for (i = 0; i < 8; ++i) {
        const uint32_t *e = w + EC_OBJ_VT + 2 * i;
        if (e[0]) sb_fmt(b, "%s{\"vtable\": \"0x%08lX\", \"count\": %lu}", i ? ", " : "", (unsigned long)e[0], (unsigned long)e[1]);
    }
    sb_fmt(b, "], \"row_vtables\": [");
    for (i = 0; i < 8; ++i) {
        const uint32_t *e = w + EC_ROW_VT + 4 * i;
        if (e[0])
            sb_fmt(b, "%s{\"vtable\": \"0x%08lX\", \"moving\": %lu, \"not_moving\": %lu, \"vt2C\": \"%s%s\", \"vt30\": \"%s%s\", \"vt28\": \"%s%s\"}", i ? ", " : "",
                   (unsigned long)e[0], (unsigned long)e[1], (unsigned long)e[2], (e[3] & 1u) ? "T" : "", (e[3] & 2u) ? "F" : "", (e[3] & 4u) ? "T" : "", (e[3] & 8u) ? "F" : "",
                   (e[3] & 16u) ? "T" : "", (e[3] & 32u) ? "F" : "");
    }
    sb_fmt(b, "]},\n    \"per_side\": [");
    for (i = 0; i < 2; ++i) {
        const uint32_t *x = w + EC_SIDE_DIAG + EC_SIDE_DIAG_WORDS * i;
        sb_fmt(b, "%s{\"side\": %u, \"raw_side_index\": %lu, \"ai_flag\": %lu, \"observed_unit_ticks\": %lu, \"halts\": %lu, \"fire_starts\": %lu, \"atk30_events\": %lu, "
               "\"atk2C_events\": %lu, \"atk30_transitions_any_distance\": %lu, \"atk2C_transitions_any_distance\": %lu, \"ever_firing_units\": %lu, \"ever_atk30_units\": %lu, "
               "\"ever_atk2C_units\": %lu, ", i ? ", " : "", i, (unsigned long)x[143], (unsigned long)x[144], (unsigned long)x[145], (unsigned long)x[134], (unsigned long)x[135],
               (unsigned long)x[136], (unsigned long)x[137], (unsigned long)x[138], (unsigned long)x[139], (unsigned long)x[140], (unsigned long)x[141], (unsigned long)x[142]);
        sb_u32_array(b, "halt_ratio_hist", x + 0, 22);
        sb_fmt(b, ", ");
        sb_u32_array(b, "fire_ratio_hist", x + 22, 22);
        sb_fmt(b, ", ");
        sb_u32_array(b, "moving_hist", x + 44, 30);
        sb_fmt(b, ", ");
        sb_u32_array(b, "still_hist", x + 74, 30);
        sb_fmt(b, ", ");
        sb_u32_array(b, "still_firing_hist", x + 104, 30);
        sb_fmt(b, "}");
    }
    sb_fmt(b, "],\n    ");
    sb_engage_rows(b, "first_halt_rows", w + EC_FIRST_ROWS, w[23] > EC_ROWS ? EC_ROWS : w[23], 0);
    sb_fmt(b, ",\n    ");
    sb_engage_rows(b, "deepest_halt_rows", w + EC_DEEP_ROWS, w[24] > EC_ROWS ? EC_ROWS : w[24], 0);
    sb_fmt(b, ",\n    ");
    ev = w[25];
    ring_n = ev > EC_ROWS ? EC_ROWS : ev;
    sb_engage_rows(b, "last_events_oldest_first", w + EC_RING_ROWS, ring_n, ev > EC_ROWS ? ev % EC_ROWS : 0);
    /* Infantry trace ring, oldest first, decoded: [tick, unit, dC, dM, moving, firing, B34, ncmd>0, unit_samples, cmd_vtable, destD, destEnemyD, side, ai, atk30, atk2C]. */
    sb_fmt(b, ",\n    \"trace_columns\": [\"tick\",\"unit\",\"dC\",\"dM\",\"moving\",\"firing\",\"b34\",\"has_cmd\",\"unit_samples\",\"cmd_vtable\",\"destD\",\"destEnemyD\",\"side\",\"ai\",\"atk30\",\"atk2C\"],\n    \"trace\": [");
    {
        const unsigned tn = w[249] > EC_TRACE_ROWS ? EC_TRACE_ROWS : w[249];
        const unsigned t0 = w[249] > EC_TRACE_ROWS ? w[249] % EC_TRACE_ROWS : 0;
        unsigned k;
        for (k = 0; k < tn; ++k) {
            const uint32_t *t = w + EC_TRACE + EC_TRACE_WORDS * ((t0 + k) % EC_TRACE_ROWS);
            sb_fmt(b, "%s[%lu,%lu,%.1f,%.1f,%lu,%lu,%lu,%lu,%lu,%lu,%.1f,%.1f,%lu,%lu,%lu,%lu]", k ? "," : "", (unsigned long)t[0], (unsigned long)t[1], (double)ec_f(t[2]), (double)ec_f(t[3]),
                   (unsigned long)(t[4] & 1u), (unsigned long)(t[4] >> 1 & 1u), (unsigned long)(t[4] >> 8 & 0xFFu), (unsigned long)(t[4] >> 16 & 1u), (unsigned long)(t[4] >> 17),
                   (unsigned long)t[5], (double)ec_f(t[6]), (double)ec_f(t[7]), (unsigned long)(t[4] >> 2 & 1u), (unsigned long)(t[4] >> 3 & 1u),
                   (unsigned long)(t[4] >> 4 & 1u), (unsigned long)(t[4] >> 5 & 1u));
        }
    }
    sb_fmt(b, "]");
    sb_fmt(b, "},\n");
}
static void sb_ai_census(Sb *b, const Run *r)
{
    const uint32_t *w = r->last.ai_census_words;
    unsigned t, k, c;
    char a[64], s[96];
    if (!(r->opt.mask & KNTWR_AI_CENSUS) || !r->have_status || w[0] != 1u) {
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
    if (!(r->opt.mask & KNTWR_COLLIDE_LOD) || !r->have_status) {
        sb_fmt(b, "  \"collide_lod\": null,\n");
        return;
    }
    sb_fmt(b, "  \"collide_lod\": {\"experimental\": true, \"configured_distance_m\": %lu, "
           "\"semantics\": \"far units skip alternating model ticks by stable unit index; near and unknown units and rebuild ticks full-rate; "
           "counts cumulative modulo 2^32 since activation; units/far_units latest proximity classification before all-far multi-army refusal; "
           "different_side_pairs compares the original +0x44 pointers; faults disable skipping until activation\", \"metrics\": {",
           (unsigned long)(r->cfg.collide_lod_m & KNTWR_COLLIDE_LOD_METRES_MASK));
    for (i = 0; i < KNTWR_COLLIDE_LOD_WORDS; ++i)
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
    for (i = 0; i < KNTWR_GRID_PROBATION_HEADER_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_grid_probation_metrics[i], (unsigned long)w[i]);
    sb_fmt(b, "}, \"callers\": [");
    for (i = 0; i < KNTWR_GRID_PROBATION_CALLERS; ++i) {
        const uint32_t *row = w + KNTWR_GRID_PROBATION_HEADER_WORDS + 8u * i;
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
    for (i = 0; i < KNTWR_LOCO_SERVICE_WORDS; ++i)
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
    if (!(r->opt.mask & KNTWR_LOCO) || !r->have_status) {
        sb_fmt(b, "  \"loco\": null,\n");
        return;
    }
    sb_fmt(b, "  \"loco\": {\"experimental\": true, \"clone_execution\": %s, \"parallel_execution\": %s, \"semantics\": \"Stages A/B/C timed site 13 (0x531AF0 loop): "
           "optional --loco-grid or --loco-grid-verify publishes owned grid v2 at stage end; combined COLLIDE borrows that view without audit or rebuild; optional closed direct-selector A1==0 movement runs on private worker state; "
           "native publication and collision callbacks remain owner-only with Phase B frozen input semantics; combined collision requires clone, parallel, owned services and grid; private precommit faults replay originals at their ordinals, never postcommit retry; "
           "serial MOVE enforces Class/Lifetime/Parked/Pending/Environment only (mask 0x233), not worker admission; "
           "counts cumulative modulo 2^32 since activation; us sums are wall time inside the stage\", \"metrics\": {",
           r->opt.loco_clone ? "true" : "false", r->opt.loco_parallel ? "true" : "false");
    for (i = 0; i < KNTWR_LOCO_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_metrics[i], (unsigned long)r->last.loco_words[i]);
    sb_fmt(b, "}, \"derived\": {\"admitted_fraction\": ");
    sb_ratio(b, r->last.loco_words[3], r->last.loco_words[2]);
    sb_fmt(b, ", \"entities\": %lu, \"stage_calls\": %lu}, \"all_gates\": {\"semantics\": "
           "\"denominator is every active +0x30 entity occurrence; recognized candidates evaluate all ten old diagnostics even after an earlier failure; "
           "unknown classes have no soldier-field reads; independent failures and details overlap and must not be summed to entities; "
           "enforced_mask uses bit(reason-1); ChargeFire is DWORD +4E8/+390/+3BC/+3C8, while byte +618/+619/+F1/+5AB are corroborating latches only; "
           "legacy_admitted clears all ten diagnostics, newly_admitted passes serial MOVE with a removed diagnostic failing\", \"metrics\": {",
           (unsigned long)r->last.loco_words[2], (unsigned long)r->last.loco_words[1]);
    for (i = 0; i < KNTWR_LOCO_GATE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_gate_metrics[i], (unsigned long)r->last.loco_gate_words[i]);
    sb_fmt(b, "}, \"derived\": {\"denominator_entities\": %lu, \"candidates\": %lu, \"enforced_mask\": %lu, \"admitted_fraction\": ",
           (unsigned long)r->last.loco_gate_words[1], (unsigned long)r->last.loco_gate_words[2], (unsigned long)r->last.loco_gate_words[4]);
    sb_ratio(b, r->last.loco_gate_words[3], r->last.loco_gate_words[1]);
    sb_fmt(b, "}}, \"services\": ");
    sb_loco_services(b, r);
    sb_fmt(b, ", \"grid\": {\"enabled\": %s, \"metrics\": {", r->opt.loco_grid ? "true" : "false");
    for (i = 0; i < KNTWR_LOCO_GRID_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_grid_metrics[i], (unsigned long)r->last.loco_grid_words[i]);
    sb_fmt(b, "}}, \"grid_v2\": {\"verify\": %s, \"metrics\": {", r->opt.loco_grid_verify ? "true" : "false");
    for (i = 0; i < KNTWR_LOCO_GRID_V2_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_grid_v2_metrics[i], (unsigned long)r->last.loco_grid_v2_words[i]);
    sb_fmt(b, "}}, \"grid_build\": {\"incremental\": %s, \"metrics\": {", r->opt.loco_grid_incremental ? "true" : "false");
    for (i = 0; i < KNTWR_LOCO_GRID_BUILD_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_grid_build_metrics[i], (unsigned long)r->last.loco_grid_build_words[i]);
    sb_fmt(b, "}}, \"grid_probation\": ");
    sb_grid_probation(b, r);
    sb_fmt(b, ", \"relink\": {\"mode\": \"%s\", \"metrics\": {", r->opt.loco_relink_workers ? "workers" : r->opt.loco_relink_shadow ? "shadow" : "off");
    for (i = 0; i < KNTWR_LOCO_RELINK_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_relink_metrics[i], (unsigned long)r->last.loco_relink_words[i]);
    sb_fmt(b, "}}");
    sb_fmt(b, ", \"class_wrapper\": {\"metrics\": {");
    for (i = 0; i < KNTWR_LOCO_CW_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_cw_metrics[i], (unsigned long)r->last.loco_cw_words[i]);
    sb_fmt(b, "}}");
    sb_fmt(b, ", \"parallel\": {\"metrics\": {");
    for (i = 0; i < KNTWR_LOCO_PARALLEL_WORDS; ++i)
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
    for (i = 0; i < KNTWR_LOCO_OWNED_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_metrics[i], (unsigned long)r->last.loco_owned_words[i]);
    sb_fmt(b, "}, \"detail\": {\"quiet_enabled\": %lu, \"metrics\": {", (unsigned long)r->last.loco_owned_detail_words[1]);
    for (i = 0; i < KNTWR_LOCO_OWNED_DETAIL_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_detail_metrics[i], (unsigned long)r->last.loco_owned_detail_words[i]);
    sb_fmt(b, "}}, \"phase\": {\"semantics\": \"phase timers remain under quiet; replay commit/fallback us are x16 estimates from every 16th occurrence\", \"metrics\": {");
    for (i = 0; i < KNTWR_LOCO_OWNED_PHASE_WORDS; ++i)
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
    for (i = 0; i < KNTWR_LOCO_OWNED_LOAD_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_loco_owned_load_metrics[i], (unsigned long)r->last.loco_owned_load_words[i]);
    sb_fmt(b, "}}, \"active_worker_fraction\": ");
    if (r->last.loco_owned_words[31])
        sb_fmt(b, "%.9f", ((double)r->last.loco_owned_words[2] + r->last.loco_owned_words[3]) / r->last.loco_owned_words[31]);
    else sb_fmt(b, "null");
    sb_fmt(b, "}");
    sb_fmt(b, ", \"shadow\": {\"enabled\": %s, \"requested\": %s, \"suppressed_by_quiet\": %s, \"sweep\": {",
           loco_shadow_effective(&r->opt) ? "true" : "false", r->opt.loco_shadow ? "true" : "false",
           (r->opt.loco_shadow && r->opt.loco_quiet) ? "true" : "false");
    for (i = 0; i < KNTWR_SWEEP_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_sweep_metrics[i], (unsigned long)r->last.sweep_words[i]);
    sb_fmt(b, "}, \"resolve\": {");
    for (i = 0; i < KNTWR_RESOLVE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_resolve_metrics[i], (unsigned long)r->last.resolve_words[i]);
    sb_fmt(b, "}, \"resolve_frames\": {");
    for (i = 0; i < KNTWR_RESOLVE_FRAME_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_resolve_frame_metrics[i], (unsigned long)r->last.resolve_frame_words[i]);
    sb_fmt(b, "}, \"env\": {");
    for (i = 0; i < KNTWR_ENV_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_env_metrics[i], (unsigned long)r->last.env_words[i]);
    sb_fmt(b, "}, \"env_targets\": [");
    for (i = 0; i < KNTWR_ENV_TARGET_WORDS; ++i)
        sb_fmt(b, "%s%lu", i ? ", " : "", (unsigned long)r->last.env_target_words[i]);
    sb_fmt(b, "], \"env_event_evidence\": \"post-state inference only; notification unobserved\"}");
    sb_fmt(b, "},\n");
}

static void sb_collide(Sb *b, const Run *r)
{
    unsigned i;
    if (!(r->opt.mask & KNTWR_COLLIDE) || !r->have_status) {
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
    for (i = 0; i < KNTWR_COLLIDE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_collide_metrics[i], (unsigned long)r->last.collide_words[i]);
    sb_fmt(b, "}, \"source\": {");
    for (i = 0; i < KNTWR_COLLIDE_SOURCE_WORDS; ++i)
        sb_fmt(b, "%s\"%s\": %lu", i ? ", " : "", k_collide_source_metrics[i], (unsigned long)r->last.collide_source_words[i]);
    {
        static const char *const contact_labels[KNTWR_COLLIDE_CONTACT_WORDS] = { KNTWR_COLLIDE_CONTACT_WORD_LABELS };
        sb_fmt(b, "}, \"contact\": {\"requested_shadow\": %s, \"requested_workers\": %s, \"metrics\": {",
               r->opt.collide_contact_shadow ? "true" : "false", r->opt.collide_contact_workers ? "true" : "false");
        for (i = 0; i < KNTWR_COLLIDE_CONTACT_WORDS; ++i)
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
    unsigned group, i, rows, order[KNTWR_BRAIN_SUBSTATE_BUCKETS];
    wchar_t label[24];
    if (!(r->opt.mask & KNTWR_BRAIN) || !r->have_status || !w[0]) {
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
        const unsigned base = group ? KNTWR_BRAIN_SUBSTATE_COUNTS : KNTWR_BRAIN_STATE_COUNTS;
        const unsigned n = group ? KNTWR_BRAIN_SUBSTATE_BUCKETS : KNTWR_BRAIN_STATE_BUCKETS;
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
    brain_state_order(w+KNTWR_BRAIN_TRANSITION_COUNTS, KNTWR_BRAIN_STATE_BUCKETS, order);
    rows = 0;
    for (i = 0; i < KNTWR_BRAIN_STATE_BUCKETS; ++i) {
        const unsigned bucket = order[i];
        const uint32_t count = w[KNTWR_BRAIN_TRANSITION_COUNTS+bucket];
        if (!count) continue;
        brain_state_label(bucket, FALSE, label, 24);
        sb_fmt(b, "%s{\"bucket\": %u, \"state\": ", rows++ ? "," : "", bucket);
        sb_wstr(b, label);
        sb_fmt(b, ", \"entities\": %lu, \"entities_per_tick\": %.6f, \"distinct_units_per_tick\": %.6f, \"transition_share\": %.9f}",
               (unsigned long)count, (double)count/w[0], (double)w[KNTWR_BRAIN_TRANSITION_UNITS+bucket]/w[0],
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
 * FILE has an 8-byte ASCII KNTWRTLOG magic, then uint32 LE abi, entry_size, count,
 * followed by count unmodified kntwr_trace_entry records (20-byte header).
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
 * rows overlap and include each timed call's own timing overhead. last_status.brain_words carries the raw kntwr_status words.
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
 * loco.grid_v2.metrics exports the 16 KNTWR_LOCO_GRID_V2_LABELS words; verify records --loco-grid-verify. collide.source exports source/native_stages/owned_stages/owned_refusals.
 * loco_grid_v2_words[16], collide_source_words[4], memory_words[60], then ai_completion_words[24] append at the status tail.
 * loco.grid_build.metrics exports the 16 KNTWR_LOCO_GRID_BUILD_LABELS words (loco_grid_build_words[16], the last status row); loco_grid_incremental records --loco-grid-incremental.
 * loco.grid_probation (--grid-probation) exports the 32 KNTWR_GRID_PROBATION_LABELS words and every used caller row
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
    static char storage[MAXP * 24u + 16384u + 4096u + 8192u + 65536u + KNTWR_BRAIN2_CENSUS_WORDS * 96u +
                        KNTWR_GRID_READERS * (2048u + KNTWR_GRID_SITES * 80u) + KNTWR_GRID_EDGES * 384u +
                        16u * (256u + KNTWR_TIMED_SITES * 128u) + KNTWR_TIMED_SITES * 192u +
                        KNTWR_TRACE_ENTRIES * 192u + 4096u + KNTWR_BRAIN_STATE_WORDS * 192u + KNTWR_COLLISION_WORDS * 192u + KNTWR_BRAIN2_WORDS * 192u + (KNTWR_LOCO_WORDS + KNTWR_LOCO_GATE_WORDS + KNTWR_LOCO_SERVICE_WORDS + KNTWR_LOCO_GRID_WORDS + KNTWR_LOCO_PARALLEL_WORDS + KNTWR_SWEEP_WORDS + KNTWR_RESOLVE_WORDS + KNTWR_ENV_WORDS + KNTWR_ENV_TARGET_WORDS + KNTWR_RESOLVE_FRAME_WORDS + KNTWR_LOCO_OWNED_WORDS) * 192u +
                        KNTWR_GRID_PROBATION_WORDS * 12u + KNTWR_GRID_PROBATION_CALLERS * 320u +
                        KNTWR_ARMY_B0_WORDS * 64u + KNTWR_BRAIN_S0_WORDS * 16u +
                        KNTWR_BRAIN_S0_HEADER_WORDS * 64u + KNTWR_BRAIN_S0_ROWS * 320u + KNTWR_BRAIN_UNIT_POLICY_WORDS * 48u +
                        KNTWR_BRAIN_LOC_WORDS * 24u + KNTWR_ENGAGE_CENSUS_WORDS * 24u + 16384u + 8192u + 4096u];
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
    sb_fmt(&b, "  \"tool\": \"KNTWR.exe\",\n  \"abi\": %u,\n", KNTWR_ABI);
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
           (unsigned long long)r->exe_size, KNTWR_IMAGE_SHA256);
    sb_fmt(&b, "  \"image_on_disk\": \"%s\",\n  \"image_sha256_stock_expected\": \"%s\",\n",
           r->exe_is_stock ? "stock" : "unknown", KNTWR_STOCK_IMAGE_SHA256);
    {
        const kntwr_gp_report *g = &r->gp_rep;
        sb_fmt(&b, "  \"gameplay_patch\": {\n    \"on_disk\": \"%s\",\n    \"applied\": %s,\n    \"status\": %lu,\n"
                   "    \"runs_total\": %lu,\n    \"runs_header\": %lu,\n    \"runs_applied\": %lu,\n    \"runs_skipped\": %lu,\n    \"bytes_applied\": %lu,\n"
                   "    \"fixups_stock_unrelocated\": %lu,\n    \"fixups_patched_relocated\": %lu,\n"
                   "    \"sections_mapped\": %lu,\n    \"section_bytes\": %lu,\n    \"section_fixups\": %lu,\n"
                   "    \"section_base_va\": \"0x%08lX\",\n    \"proof_site_va\": \"0x%08lX\",\n    \"proof_target_va\": \"0x%08lX\",\n"
                   "    \"proof_site_bytes\": \"%02x%02x%02x%02x%02x\",\n    \"proof_section_va\": \"0x%08lX\",\n"
                   "    \"proof_section_bytes\": \"%02x%02x%02x%02x%02x%02x%02x%02x\",\n    \"live_verified\": %s,\n    \"d3d9_swap\": %s,\n"
                   "    \"mss32_on_disk\": \"%s\",\n    \"mss32_applied\": %s,\n    \"mss32_runs_applied\": %lu,\n    \"mss32_bytes_applied\": %lu\n  },\n",
               r->exe_is_stock ? "stock" : "unknown", r->gp_applied ? "true" : "false", (unsigned long)g->status,
               (unsigned long)g->runs_total, (unsigned long)g->runs_header, (unsigned long)g->runs_applied, (unsigned long)g->runs_skipped, (unsigned long)g->bytes_applied,
               (unsigned long)g->fixups_stock_unrelocated, (unsigned long)g->fixups_patched_relocated,
               (unsigned long)g->sections_mapped, (unsigned long)g->section_bytes, (unsigned long)g->section_fixups,
               (unsigned long)g->section_base_va, (unsigned long)g->proof_site_va, (unsigned long)g->proof_target_va,
               g->proof_site_bytes[0], g->proof_site_bytes[1], g->proof_site_bytes[2], g->proof_site_bytes[3], g->proof_site_bytes[4],
               (unsigned long)g->proof_section_va,
               g->proof_section_bytes[0], g->proof_section_bytes[1], g->proof_section_bytes[2], g->proof_section_bytes[3],
               g->proof_section_bytes[4], g->proof_section_bytes[5], g->proof_section_bytes[6], g->proof_section_bytes[7],
               r->gp_live_verified ? "true" : "false",
               (r->gp_applied && !r->opt.no_d3d9_swap) ? "true" : "false",
               k_mss_state_name[r->mss32_state], r->mss32_applied ? "true" : "false",
               (unsigned long)r->mss32_rep.runs_applied, (unsigned long)r->mss32_rep.bytes_applied);
    }
    {
        const kntwr_gp_reserve *v = &r->gp_rsv;
        const kntwr_gp_reserve_report *s = &r->gp_rsv_rep;
        const kntwr_gp_remalloc_diag *d = &r->gp_rep.remap;
        sb_fmt(&b, "  \"launch_reserve\": {\n    \"active\": %s,\n    \"predicted_base\": \"0x%08lX\",\n    \"reserve_base\": \"0x%08lX\",\n"
                   "    \"reserve_size\": \"0x%08lX\",\n    \"stock_size_of_image\": \"0x%08lX\",\n    \"patched_size_of_image\": \"0x%08lX\",\n"
                   "    \"hook_installed\": %s,\n    \"hook_restored\": %s,\n    \"calls_seen\": %lu,\n    \"calls_modified\": %lu,\n"
                   "    \"reject\": %lu,\n    \"hook_ntstatus\": \"0x%08lX\",\n    \"status\": %lu,\n    \"stage\": \"%s\",\n    \"code\": \"0x%08lX\",\n"
                   "    \"code_is_ntstatus\": %s,\n    \"error\": ",
               v->reserve_size ? "true" : "false", (unsigned long)v->predicted_base, (unsigned long)v->reserve_base,
               (unsigned long)v->reserve_size, (unsigned long)v->stock_soi, (unsigned long)v->patched_soi,
               v->hook_installed ? "true" : "false", v->hook_restored ? "true" : "false",
               (unsigned long)v->calls_seen, (unsigned long)v->calls_modified, (unsigned long)v->reject,
               (unsigned long)v->hook_ntstatus, (unsigned long)s->status, kntwr_gp_reserve_stage_name(s->stage),
               (unsigned long)s->code, s->code_is_ntstatus ? "true" : "false");
        sb_astr(&b, s->error);
        sb_fmt(&b, ",\n    \"gameplay_patch_error\": ");
        sb_astr(&b, r->gp_rep.error);
        sb_fmt(&b, ",\n    \"gameplay_patch_phase\": %lu,\n    \"remap\": {\"stage\": \"%s\", \"code\": \"0x%08lX\", \"code_is_ntstatus\": %s, \"mutated\": %s, "
                   "\"region_base\": \"0x%08lX\", \"region_size\": \"0x%08lX\", \"region_state\": \"0x%08lX\", \"region_type\": \"0x%08lX\", "
                   "\"region_alloc_base\": \"0x%08lX\"}\n  },\n",
               (unsigned long)r->gp_rep.phase, kntwr_gp_remalloc_stage_name(d->stage), (unsigned long)d->code, d->code_is_ntstatus ? "true" : "false",
               d->mutated ? "true" : "false", (unsigned long)d->region_base, (unsigned long)d->region_size, (unsigned long)d->region_state,
               (unsigned long)d->region_type, (unsigned long)d->region_alloc_base);
    }
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
    sb_fmt(&b, "  \"grid_census_requested\": %s,\n", (r->opt.mask & KNTWR_GRID_CENSUS) ? "true" : "false");
    sb_fmt(&b, "  \"ai_census_requested\": %s,\n", (r->opt.mask & KNTWR_AI_CENSUS) ? "true" : "false");
    sb_fmt(&b, "  \"loco_clone\": %s,\n", r->opt.loco_clone ? "true" : "false");
    sb_fmt(&b, "  \"loco_parallel\": %s,\n", r->opt.loco_parallel ? "true" : "false");
    sb_fmt(&b, "  \"loco_owned_services\": %s,\n", r->opt.loco_owned ? "true" : "false");
    sb_fmt(&b, "  \"loco_shadow\": %s,\n", r->opt.loco_shadow ? "true" : "false");
    sb_fmt(&b, "  \"loco_shadow_effective\": %s,\n", loco_shadow_effective(&r->opt) ? "true" : "false");
    sb_fmt(&b, "  \"loco_quiet\": %s,\n", r->opt.loco_quiet ? "true" : "false");
    sb_fmt(&b, "  \"loco_grid\": %s,\n", r->opt.loco_grid ? "true" : "false");
    sb_fmt(&b, "  \"loco_grid_verify\": %s,\n", r->opt.loco_grid_verify ? "true" : "false");
    sb_fmt(&b, "  \"loco_grid_incremental\": %s,\n", r->opt.loco_grid_incremental ? "true" : "false");
    sb_fmt(&b, "  \"grid_probation\": %s,\n", r->opt.grid_probation ? "true" : "false");
    sb_fmt(&b, "  \"loco_relink_shadow\": %s,\n", r->opt.loco_relink_shadow ? "true" : "false");
    sb_fmt(&b, "  \"loco_relink_workers\": %s,\n", r->opt.loco_relink_workers ? "true" : "false");
    sb_fmt(&b, "  \"loco_cw_shadow\": %s,\n", r->opt.loco_cw_shadow ? "true" : "false");
    sb_fmt(&b, "  \"loco_cw_workers\": %s,\n", r->opt.loco_cw_workers ? "true" : "false");
    sb_fmt(&b, "  \"ai_poly_requested\": %s,\n  \"ai_prepass_flags\": %lu,\n", (r->opt.ai_prepass_flags & KNTWR_AI_POLY) ? "true" : "false",
           (unsigned long)r->opt.ai_prepass_flags);
    sb_fmt(&b, "  \"tick_pcore\": %s,\n", r->opt.tick_pcore ? "true" : "false");
    sb_fmt(&b, "  \"army_solver_memo\": %s,\n", r->opt.army_solver_memo ? "true" : "false");
    sb_fmt(&b, "  \"alloc_census_requested\": %s,\n", r->opt.alloc_census ? "true" : "false");
    sb_fmt(&b, "  \"alloc_fix_requested\": %s,\n", r->opt.alloc_fix ? "true" : "false");
    sb_fmt(&b, "  \"arena_release_requested\": %s,\n", r->opt.arena_release ? "true" : "false");
    sb_fmt(&b, "  \"heap_optimize_requested\": %s,\n", r->opt.heap_optimize ? "true" : "false");
    sb_fmt(&b, "  \"mounted_officer_requested\": %s,\n  \"mounted_officer_widen_requested\": %s,\n", r->opt.mounted_officer ? "true" : "false",
           r->opt.mounted_officer_widen ? "true" : "false");
    sb_fmt(&b, "  \"drag_ladder_requested\": %s,\n", r->opt.drag_ladder ? "true" : "false");
    sb_fmt(&b, "  \"wounded_requested\": %s,\n", r->opt.wounded ? "true" : "false");
    sb_fmt(&b, "  \"engage_census_requested\": %s,\n", r->opt.engage_census ? "true" : "false");
    sb_fmt(&b, "  \"va_floor_mib\": %lu,\n  \"va_hole_mib\": %lu,\n",
           (unsigned long)(r->opt.va_floor_mib ? r->opt.va_floor_mib : (KNTWR_MEMORY_MIN_AVAIL_VIRTUAL >> 20)),
           (unsigned long)(r->opt.va_hole_mib ? r->opt.va_hole_mib : (KNTWR_MEMORY_MIN_LARGEST_HOLE >> 20)));
    sb_fmt(&b, "  \"brain_parallel\": %s,\n", r->opt.brain_parallel ? "true" : "false");
    sb_fmt(&b, "  \"brain_quiet\": %s,\n", r->opt.brain_quiet ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_shadow\": %s,\n", r->opt.brain_unit_shadow ? "true" : "false");
    sb_fmt(&b, "  \"brain_s0\": %s,\n", r->opt.brain_s0 ? "true" : "false");
    sb_fmt(&b, "  \"brain_locality\": %s,\n  \"brain_locality_warm\": %s,\n  \"brain_locality_prefetch\": %s,\n  \"brain_locality_prefetch2\": %s,\n"
               "  \"brain_locality_mark\": %s,\n",
           r->opt.brain_locality ? "true" : "false", r->opt.brain_locality_warm ? "true" : "false",
           r->opt.brain_locality_prefetch ? "true" : "false", r->opt.brain_locality_prefetch2 ? "true" : "false",
           r->opt.brain_locality_mark ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_fatigue\": %s,\n", r->opt.brain_unit_fatigue ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_fatigue_shadow\": %s,\n", r->opt.brain_unit_fatigue_shadow ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_posture\": %s,\n", r->opt.brain_unit_posture ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_posture_shadow\": %s,\n", r->opt.brain_unit_posture_shadow ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_engage\": %s,\n", r->opt.brain_unit_engage ? "true" : "false");
    sb_fmt(&b, "  \"brain_unit_engage_shadow\": %s,\n", r->opt.brain_unit_engage_shadow ? "true" : "false");
    sb_fmt(&b, "  \"collide_contact_shadow\": %s,\n", r->opt.collide_contact_shadow ? "true" : "false");
    sb_fmt(&b, "  \"collide_contact_workers\": %s,\n", r->opt.collide_contact_workers ? "true" : "false");
    sb_fmt(&b, "  \"army_unit_shadow\": %s,\n", (r->opt.mask & KNTWR_ARMY_UNIT_SHADOW) ? "true" : "false");
    sb_fmt(&b, "  \"cavalry_orbit\": %s,\n", (r->opt.mask & KNTWR_CAVALRY_ORBIT) ? "true" : "false");
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
    sb_army_storm(&b, r);
    sb_army_residual(&b, r);
    sb_army_solver(&b, r);
    sb_alloc_census(&b, r);
    sb_arena(&b, r);
    sb_overlay(&b, r);
    sb_mounted_officer(&b, r);
    sb_anim_guard(&b, r);
    sb_drag_ladder(&b, r);
    sb_wounded(&b, r);
    sb_engage_census(&b, r);
    sb_brain2(&b, r);
    if (r->have_status) {
        unsigned memory_index;
        sb_fmt(&b, "  \"memory\": {\"metrics\": {");
        for (memory_index = 0; memory_index < KNTWR_MEMORY_WORDS; ++memory_index)
            sb_fmt(&b, "%s\"%s\": %lu", memory_index ? ", " : "", k_memory_metrics[memory_index],
                   (unsigned long)r->last.memory_words[memory_index]);
        sb_fmt(&b, "}},\n");
    } else sb_fmt(&b, "  \"memory\": null,\n");
    if (r->have_status) {
        unsigned ai_index;
        sb_fmt(&b, "  \"ai_completion\": {\"metrics\": {");
        for (ai_index=0;ai_index<KNTWR_AI_COMPLETION_WORDS;++ai_index)
            sb_fmt(&b, "%s\"%s\": %lu",ai_index ? ", " : "",k_ai_completion_metrics[ai_index],
                   (unsigned long)r->last.ai_completion_words[ai_index]);
        sb_fmt(&b, "}},\n");
    } else sb_fmt(&b, "  \"ai_completion\": null,\n");
    if (r->have_status && (r->opt.mask & KNTWR_AI_ASYNC2)) {
        unsigned ai2_index;
        sb_fmt(&b, "  \"ai_async2\": {\"metrics\": {");
        for (ai2_index = 0; ai2_index < KNTWR_AI_ASYNC2_WORDS; ++ai2_index)
            sb_fmt(&b, "%s\"%s\": %lu", ai2_index ? ", " : "", k_ai_async2_metrics[ai2_index],
                   (unsigned long)r->last.ai_async2_words[ai2_index]);
        sb_fmt(&b, "}, \"route\": {");
        for (ai2_index = 0; ai2_index < KNTWR_AI_ASYNC2_ROUTE_WORDS; ++ai2_index)
            sb_fmt(&b, "%s\"%s\": %lu", ai2_index ? ", " : "", k_ai_async2_route_metrics[ai2_index],
                   (unsigned long)r->last.ai_async2_route_words[ai2_index]);
        sb_fmt(&b, "}, \"complete_before_next_tick_fraction\": ");
        sb_ratio(&b, r->last.ai_async2_route_words[9], r->last.ai_async2_route_words[4]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_async2\": null,\n");
    if (r->have_status && r->cfg.ai_deferred) {
        unsigned defer_index;
        sb_fmt(&b, "  \"ai_deferred\": {");
        for (defer_index = 0; defer_index < KNTWR_AI_DEFERRED_WORDS; ++defer_index)
            sb_fmt(&b, "%s\"%s\": %lu", defer_index ? ", " : "", k_ai_deferred_metrics[defer_index],
                   (unsigned long)r->last.ai_deferred_words[defer_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_deferred\": null,\n");
    if (r->have_status && (r->cfg.ai_ctrl_flags & KNTWR_AI_CTRL_MODE_MASK)) {
        /* Words 16..23 belong to the brain levers when one is on (their own receipt objects carry them); 24..31 to claim-once. */
        const unsigned ctrl_count = (r->cfg.ai_ctrl_flags & KNTWR_AI_BRAIN_STEP_BITS) ? 16u : 24u;
        unsigned ctrl_index;
        sb_fmt(&b, "  \"ai_ctrl\": {\"flags\": %lu", (unsigned long)r->cfg.ai_ctrl_flags);
        for (ctrl_index = 0; ctrl_index < ctrl_count; ++ctrl_index)
            sb_fmt(&b, ", \"%s\": %lu", k_ai_ctrl_reuse_metrics[ctrl_index], (unsigned long)r->last.ai_ctrl_reuse_words[ctrl_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_ctrl\": null,\n");
    if (r->have_status && (r->cfg.ai_ctrl_flags & KNTWR_AI_CLAIM_BITS)) {
        const uint32_t *cw = r->last.ai_ctrl_reuse_words;
        sb_fmt(&b, "  \"ai_claim_once\": {\"mode\": \"%s\", \"calls\": %lu, \"entries\": %lu, \"masked_recomputes\": %lu, \"calls_masked\": %lu, \"refused_state\": %lu, "
                   "\"refused_other\": %lu, \"max_entries\": %lu, \"no_final_tail\": %lu, \"hashed_calls\": %lu, \"hash\": %lu},\n",
               (r->cfg.ai_ctrl_flags & KNTWR_AI_CLAIM_ONCE) ? "once" : "census", (unsigned long)cw[24], (unsigned long)cw[25], (unsigned long)cw[26],
               (unsigned long)cw[27], (unsigned long)cw[28], (unsigned long)cw[29], (unsigned long)(cw[30] & 0xFFu), (unsigned long)((cw[30] >> 8) & 0xFFu),
               (unsigned long)(cw[30] >> 16), (unsigned long)cw[31]);
    } else sb_fmt(&b, "  \"ai_claim_once\": null,\n");
    if (r->have_status && (r->cfg.ai_ctrl_flags & KNTWR_AI_RETARGET_JITTER)) {
        const uint32_t *jw = r->last.ai_ctrl_reuse_words + 20;
        unsigned jitter_index;
        sb_fmt(&b, "  \"brain_retarget_jitter\": {\"flags\": %lu", (unsigned long)r->cfg.ai_ctrl_flags);
        for (jitter_index = 0; jitter_index < 4; ++jitter_index)
            sb_fmt(&b, ", \"%s\": %lu", k_brain_retarget_jitter_metrics[jitter_index], (unsigned long)jw[jitter_index]);
        sb_fmt(&b, ", \"losses_per_call\": ");
        sb_ratio(&b, jw[1], jw[0]);
        sb_fmt(&b, ", \"jittered_share_of_losses\": ");
        sb_ratio(&b, jw[2], jw[1]);
        sb_fmt(&b, ", \"mean_delay_ticks\": ");
        sb_ratio(&b, jw[3], jw[2]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"brain_retarget_jitter\": null,\n");
    if (r->have_status && (r->cfg.ai_ctrl_flags & (KNTWR_AI_TARGET_CULL_SHADOW | KNTWR_AI_TARGET_CULL))) {
        const uint32_t *tw = r->last.ai_ctrl_reuse_words + 16;
        unsigned cull_index;
        sb_fmt(&b, "  \"brain_target_cull\": {\"mode\": \"%s\"", (r->cfg.ai_ctrl_flags & KNTWR_AI_TARGET_CULL) ? "live" : "shadow");
        for (cull_index = 0; cull_index < 3; ++cull_index)
            sb_fmt(&b, ", \"%s\": %lu", k_brain_target_cull_metrics[cull_index], (unsigned long)tw[cull_index]);
        sb_fmt(&b, ", \"mismatch_result\": %lu, \"mismatch_score\": %lu, \"mismatch_scratch\": %lu, \"flag_searches\": %lu",
               (unsigned long)(tw[3] & 0xFFu), (unsigned long)((tw[3] >> 8) & 0xFFu), (unsigned long)((tw[3] >> 16) & 0xFFu), (unsigned long)(tw[3] >> 24));
        sb_fmt(&b, ", \"culled\": %lu, \"culled_share\": ", (unsigned long)(tw[1] > tw[2] ? tw[1] - tw[2] : 0u));
        sb_ratio(&b, tw[1] > tw[2] ? tw[1] - tw[2] : 0u, tw[1]);
        sb_fmt(&b, ", \"candidates_per_loop\": ");
        sb_ratio(&b, tw[1], tw[0]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"brain_target_cull\": null,\n");
    if (r->have_status && r->cfg.ai_prepass_flags) {
        unsigned prepass_index;
        sb_fmt(&b, "  \"ai_prepass_census\": {\"flags\": %lu", (unsigned long)r->cfg.ai_prepass_flags);
        for (prepass_index = 0; prepass_index < KNTWR_AI_PREPASS_CENSUS_WORDS; ++prepass_index)
            sb_fmt(&b, ", \"%s\": %lu", k_ai_prepass_census_metrics[prepass_index], (unsigned long)r->last.ai_prepass_census_words[prepass_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_prepass_census\": null,\n");
    if (r->have_status && (r->cfg.ai_prepass_flags & (KNTWR_AI_POLY_SHADOW | KNTWR_AI_POLY))) {
        unsigned poly_index;
        sb_fmt(&b, "  \"ai_poly\": {\"flags\": %lu", (unsigned long)r->cfg.ai_prepass_flags);
        for (poly_index = 0; poly_index < KNTWR_AI_POLY_WORDS; ++poly_index)
            sb_fmt(&b, ", \"%s\": %lu", k_ai_poly_metrics[poly_index], (unsigned long)r->last.ai_prepass_words[poly_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_poly\": null,\n");
    if (r->have_status && (r->cfg.ai_prepass_flags & KNTWR_AI_RECORD_TEST_BITS)) {
        unsigned rt_index;
        const uint32_t *rt = r->last.ai_prepass_words + KNTWR_AI_POLY_WORDS;
        sb_fmt(&b, "  \"ai_record_test\": {\"flags\": %lu, \"mode_name\": \"%s\", \"served_fast_us\": %.1f", (unsigned long)r->cfg.ai_prepass_flags,
               rt[1] == 1 ? "shadow" : rt[1] == 2 ? "live" : "off", rt[23] ? (double)rt[18] * 1024.0 / (double)rt[23] : 0.0);
        for (rt_index = 0; rt_index < KNTWR_AI_RECORD_TEST_WORDS; ++rt_index)
            sb_fmt(&b, ", \"%s\": %lu", k_ai_record_test_metrics[rt_index], (unsigned long)rt[rt_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_record_test\": null,\n");
    if (r->have_status && (r->cfg.ai_prepass_flags & KNTWR_AI_SPIRAL_BITS)) {
        unsigned spiral_index;
        sb_fmt(&b, "  \"ai_spiral\": {\"flags\": %lu, \"requested_cap_m\": %lu", (unsigned long)r->cfg.ai_prepass_flags,
               (unsigned long)(r->cfg.ai_prepass_flags >> KNTWR_AI_SPIRAL_CAP_SHIFT));
        for (spiral_index = 0; spiral_index < KNTWR_AI_SPIRAL_WORDS; ++spiral_index)
            sb_fmt(&b, ", \"%s\": %lu", k_ai_spiral_metrics[spiral_index], (unsigned long)r->last.ai_spiral_words[spiral_index]);
        sb_fmt(&b, "},\n");
    } else sb_fmt(&b, "  \"ai_spiral\": null,\n");
    if (r->have_status) {
        const kntwr_status *s = &r->last;
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
            for (ai_index=0;ai_index<KNTWR_AI_COMPLETION_WORDS;++ai_index)
                sb_fmt(&b, "%s%lu",ai_index ? "," : "",(unsigned long)s->ai_completion_words[ai_index]);
            sb_fmt(&b, "],\n");
        }
        {
            static const char *const names[52] = {"formation_words", "query_words", "path_words", "ballistic_words",
                                                  "formation_diag", "tick_words", "sim_words", "planner_words", "planner_walk_words",
                                                  "ai_words", "ai_extra_words", "crash_words", "brain_words", "ai_slice_words", "ai_validation_words", "visual_words", "allocator_words", "ai_slice_site_words", "brain_state_words", "collision_words", "collide_words", "brain2_words", "collide_lod_words", "ai_ctrl_words", "ai_slice_budget_words", "ai_park_words", "loco_words", "loco_gate_words", "loco_service_words", "loco_grid_words", "loco_parallel_words", "sweep_words", "resolve_words", "env_words", "env_target_words", "resolve_frame_words", "loco_owned_words", "loco_owned_detail_words", "loco_owned_phase_words", "loco_owned_load_words", "loco_grid_v2_words", "collide_source_words", "memory_words", "collide_contact_words", "grid_probation_words", "loco_relink_words", "loco_cw_words", "loco_grid_build_words", "va_watch_words", "alloc_census_words", "arena_words", "overlay_words"};
            const uint32_t *arrays[52] = {s->formation_words, s->query_words, s->path_words, s->ballistic_words,
                                          s->formation_diag, s->tick_words, s->sim_words, s->planner_words, s->planner_walk_words,
                                          s->ai_words, s->ai_extra_words, s->crash_words, s->brain_words, s->ai_slice_words, s->ai_validation_words, s->visual_words, s->allocator_words, s->ai_slice_site_words, s->brain_state_words, s->collision_words, s->collide_words, s->brain2_words, s->collide_lod_words, s->ai_ctrl_words, s->ai_slice_budget_words, s->ai_park_words, s->loco_words, s->loco_gate_words, s->loco_service_words, s->loco_grid_words, s->loco_parallel_words, s->sweep_words, s->resolve_words, s->env_words, s->env_target_words, s->resolve_frame_words, s->loco_owned_words, s->loco_owned_detail_words, s->loco_owned_phase_words, s->loco_owned_load_words, s->loco_grid_v2_words, s->collide_source_words, s->memory_words, s->collide_contact_words, s->grid_probation_words, s->loco_relink_words, s->loco_cw_words, s->loco_grid_build_words, s->va_watch_words, s->alloc_census_words, s->arena_words, s->overlay_words};
            const unsigned counts[52] = {16, 16, 24, 8, 192, 16, 16, 64, 16, 16, 32, 32, KNTWR_BRAIN_WORDS, 8, 8, 32, KNTWR_ALLOCATOR_WORDS, 2, KNTWR_BRAIN_STATE_WORDS, KNTWR_COLLISION_WORDS, KNTWR_COLLIDE_WORDS, KNTWR_BRAIN2_WORDS, KNTWR_COLLIDE_LOD_WORDS, 16, KNTWR_AI_SLICE_BUDGET_WORDS, 8, KNTWR_LOCO_WORDS, KNTWR_LOCO_GATE_WORDS, KNTWR_LOCO_SERVICE_WORDS, KNTWR_LOCO_GRID_WORDS, KNTWR_LOCO_PARALLEL_WORDS, KNTWR_SWEEP_WORDS, KNTWR_RESOLVE_WORDS, KNTWR_ENV_WORDS, KNTWR_ENV_TARGET_WORDS, KNTWR_RESOLVE_FRAME_WORDS, KNTWR_LOCO_OWNED_WORDS, KNTWR_LOCO_OWNED_DETAIL_WORDS, KNTWR_LOCO_OWNED_PHASE_WORDS, KNTWR_LOCO_OWNED_LOAD_WORDS, KNTWR_LOCO_GRID_V2_WORDS, KNTWR_COLLIDE_SOURCE_WORDS, KNTWR_MEMORY_WORDS, KNTWR_COLLIDE_CONTACT_WORDS, KNTWR_GRID_PROBATION_WORDS, KNTWR_LOCO_RELINK_WORDS, KNTWR_LOCO_CW_WORDS, KNTWR_LOCO_GRID_BUILD_WORDS, KNTWR_VA_WATCH_WORDS, KNTWR_ALLOC_CENSUS_WORDS, KNTWR_ARENA_WORDS, KNTWR_OVERLAY_WORDS};
            unsigned i, j;
            for (i = 0; i < 52; ++i) {
                sb_fmt(&b, "    \"%s\": [", names[i]);
                for (j = 0; j < counts[i]; ++j) sb_fmt(&b, "%s%lu", j ? "," : "", (unsigned long)arrays[i][j]);
                sb_fmt(&b, "]%s\n", i + 1 < 52 ? "," : "");
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
    /* Replacing the target needs DELETE access on it: a concurrent reader holding receipt.json open (tail/poller) makes
       MoveFileExW fail with a sharing violation even though the reader opened with full sharing. Transient by nature, so
       retry briefly instead of aborting the 1 Hz live-receipt loop (which would stop receipts for the rest of the run). */
    {
        int attempt;
        DWORD err = 0;
        for (attempt = 0; attempt < 20; ++attempt) {
            if (MoveFileExW(tmp, r->opt.receipt, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { ok = TRUE; break; }
            err = GetLastError();
            if (err != ERROR_SHARING_VIOLATION && err != ERROR_ACCESS_DENIED) break;
            Sleep(25);
        }
        if (!ok) {
            win_fail(L"publishing the receipt", err);
            DeleteFileW(tmp);
            goto done;
        }
    }
done:
    return ok;
}

/* Keep the most recent complete copy so a spontaneous game exit still has a
   bounded-age profile. Live copies are deliberately observational (see ABI). */
static BOOL read_profile(Run *r)
{
    kntwr_profile_status p;
    kntwr_profile_runtime_header runtime;
    kntwr_profile_runtime_header *stored;
    SIZE_T bytes, image_bytes;
    uint32_t phase, runtime_va;
    if (!(r->opt.mask & (KNTWR_PROFILE | KNTWR_GRID_CENSUS | KNTWR_AI_CENSUS))) return TRUE;
    if (!remote_read(r->proc, r->dll_base + r->dll.profile_rva, &p, sizeof p) ||
        p.abi != KNTWR_PROFILE_ABI || p.size != sizeof p ||
        p.bucket_bytes != KNTWR_PROFILE_BUCKET_BYTES || !p.bucket_count ||
        p.bucket_count > 0x10000000u / KNTWR_PROFILE_BUCKET_BYTES ||
        !p.hist_va || !p.tick_hist_va || !p.frames_hist_va)
        return FALSE;
    for (phase = 0; phase < KNTWR_PROFILE_MAIN_PHASES; ++phase)
        if (!KNTWR_PROFILE_PHASE_FIELD(&p, phase, hist_va)) return FALSE;
    bytes = (SIZE_T)p.bucket_count * sizeof(uint32_t);
    image_bytes = bytes * (3 + KNTWR_PROFILE_MAIN_PHASES);
    if ((uint64_t)p.hist_va + image_bytes + sizeof runtime > UINT32_MAX) return FALSE;
    runtime_va = p.hist_va + (uint32_t)image_bytes;
    if (!remote_read(r->proc, runtime_va, &runtime, sizeof runtime) ||
        runtime.magic != KNTWR_PROFILE_RUNTIME_MAGIC || runtime.version != KNTWR_PROFILE_RUNTIME_VERSION ||
        runtime.runtime_base != r->dll_base || !runtime.runtime_size || runtime.runtime_size > 0x10000000u ||
        runtime.bucket_bytes != KNTWR_PROFILE_BUCKET_BYTES ||
        !runtime.bucket_count ||
        runtime.bucket_count > (runtime.runtime_size + KNTWR_PROFILE_BUCKET_BYTES - 1) / KNTWR_PROFILE_BUCKET_BYTES ||
        (!(runtime.flags & 8u) && runtime.bucket_count != (runtime.runtime_size + KNTWR_PROFILE_BUCKET_BYTES - 1) / KNTWR_PROFILE_BUCKET_BYTES) ||
        runtime.histogram_count != KNTWR_PROFILE_RUNTIME_HISTOGRAMS ||
        runtime.pair_capacity != KNTWR_PROFILE_RUNTIME_PAIRS || runtime.wait_capacity != KNTWR_PROFILE_RUNTIME_WAITS ||
        runtime.bytes != KNTWR_PROFILE_RUNTIME_BYTES(runtime.bucket_count) ||
        (uint64_t)runtime_va + runtime.bytes > UINT32_MAX) return FALSE;
    if (r->profile_arrays) {
        if (p.bucket_count != r->profile.bucket_count) return FALSE;
        stored = (kntwr_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
        if (stored->bytes != runtime.bytes) return FALSE;
    } else {
        r->profile_arrays = (uint32_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, image_bytes + runtime.bytes);
        if (!r->profile_arrays) return FALSE;
        r->profile = p;
        stored = (kntwr_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
        *stored = runtime;
    }
    r->have_profile = FALSE;
    if (!remote_read(r->proc, p.hist_va, r->profile_arrays, bytes) ||
        !remote_read(r->proc, p.tick_hist_va, r->profile_arrays + p.bucket_count, bytes) ||
        !remote_read(r->proc, p.frames_hist_va, r->profile_arrays + p.bucket_count * 2, bytes))
        return FALSE;
    for (phase = 0; phase < KNTWR_PROFILE_MAIN_PHASES; ++phase)
        if (!remote_read(r->proc, KNTWR_PROFILE_PHASE_FIELD(&p, phase, hist_va),
                         r->profile_arrays + p.bucket_count * (3 + phase), bytes)) return FALSE;
    stored = (kntwr_profile_runtime_header *)((uint8_t *)r->profile_arrays + image_bytes);
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

static void print_profile_threads(const kntwr_profile_status *p)
{
    uint32_t order[KNTWR_PROFILE_THREADS], count = 0, i, rank;
    for (i = 0; i < KNTWR_PROFILE_THREADS; ++i) {
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
    /* Render-load tag: the busiest non-tick thread is the renderer; its image share during ticks is the only
       camera-dependent quantity in a run. Compare it across runs before trusting sub-2 ms tick deltas. */
    for (rank = 0; rank < count; ++rank) {
        i = order[rank];
        if (p->thread_id[i] == p->tick_thread_id || !p->thread_samples[i]) continue;
        say(L"  render-load tag: busiest non-tick thread %lu at %.2f%% image occupancy during ticks (camera/render pressure indicator)\n",
            (unsigned long)p->thread_id[i], 100.0 * p->in_image[i] / p->thread_samples[i]);
        break;
    }
}

static void print_profile_waits(const kntwr_profile_status *p)
{
    uint32_t order[KNTWR_PROFILE_WAIT_HANDLES], count = 0, i, rank;
    for (i = 0; i < KNTWR_PROFILE_WAIT_HANDLES; ++i) {
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

static void print_profile_top(const wchar_t *name, const uint32_t *counts, const kntwr_profile_status *p,
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
                                 const uint32_t chains[][KNTWR_PROFILE_CHAIN_DEPTH],
                                 uint32_t uncaptured, uint32_t samples, uint32_t limit)
{
    struct { uint32_t index, count; } top[12] = {{0, 0}};
    uint32_t i, rank, frame;
    for (i = 0; i < KNTWR_PROFILE_CHAINS; ++i) {
        uint32_t count = counts[i];
        if (!lengths[i] || lengths[i] > KNTWR_PROFILE_CHAIN_DEPTH ||
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

static void print_profile_main(const kntwr_profile_status *p, const uint32_t *arrays)
{
    static const wchar_t *const names[KNTWR_PROFILE_MAIN_PHASES] = {
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
    say(L"  kntwr includes clones; driver=nv*/atiu*/ig*, msvcr=msvcr*; unlisted modules (including KernelBase) count as other.\n");
    for (index = 0; index < KNTWR_PROFILE_MAIN_PHASES; ++index) {
        uint32_t order[KNTWR_PROFILE_WAIT_HANDLES], count = 0, samples, waits;
        const uint32_t *counts, *handles, *handle_kinds, *wait_kinds, *modules;
        phase = k_profile_phase_order[index];
        samples = KNTWR_PROFILE_PHASE_FIELD(p, phase, samples);
        waits = KNTWR_PROFILE_PHASE_FIELD(p, phase, wait);
        counts = KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_count);
        handles = KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_handle);
        handle_kinds = KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_handle_kind);
        wait_kinds = KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_kind);
        modules = KNTWR_PROFILE_PHASE_FIELD(p, phase, modules);
        say(L"  %ls: samples=%lu waits=%lu wait=%.3f%%\n", names[phase],
            (unsigned long)samples, (unsigned long)waits, samples ? 100.0 * waits / samples : 0.0);
        say(L"    Module EIP occupancy (%% of phase samples):\n");
        for (i = 0; i < KNTWR_PROFILE_MODULE_COUNT; ++i)
            say(L"      %-12hs %10lu %8.3f%%\n", k_profile_modules[i], (unsigned long)modules[i],
                samples ? 100.0 * modules[i] / samples : 0.0);
        say(L"    Wait-stub occupancy:");
        for (i = 0; i < 6; ++i) say(L" %ls=%lu", kinds[i], (unsigned long)wait_kinds[i]);
        say(L"\n    Top handles by exact (stub, HANDLE) counts:\n");
        for (i = 0; i < KNTWR_PROFILE_WAIT_HANDLES; ++i) {
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
            (unsigned long)KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_read_failed),
            (unsigned long)KNTWR_PROFILE_PHASE_FIELD(p, phase, wait_overflow));
        print_profile_top(names[phase], arrays + p->bucket_count * phase, p, samples, 20);
    }
    say(L"  Wait EIPs are occupancy, not proof of blocking. Multiple-set rows count each distinct set member;\n");
    say(L"  delay/alert have no HANDLE; keyed-event HANDLE may be NULL and does not identify the key.\n");
    print_profile_chains(L"main A1", p->main_start_chain_count, p->main_start_chain_len,
                         p->main_start_chains, p->main_start_chain_uncaptured, p->main_samples[KNTWR_PROFILE_PHASE_A1], 10);
    print_profile_chains(L"main B", p->main_post_chain_count, p->main_post_chain_len,
                         p->main_post_chains, p->main_post_chain_uncaptured, p->main_samples[KNTWR_PROFILE_PHASE_B], 10);
}

static void print_profile_main_diff(const kntwr_profile_status *p, const uint32_t *arrays,
                                    uint32_t first, uint32_t second)
{
    struct { uint32_t bucket; double first, second, delta; } top[20] = {{0, 0, 0, 0}};
    uint32_t i, rank, count = 0;
    const uint32_t *a = arrays + p->bucket_count * first, *b = arrays + p->bucket_count * second;
    const uint32_t samples_a = KNTWR_PROFILE_PHASE_FIELD(p, first, samples);
    const uint32_t samples_b = KNTWR_PROFILE_PHASE_FIELD(p, second, samples);
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

static void print_profile_runtime(const kntwr_profile_runtime_header *header)
{
    static const wchar_t *const names[KNTWR_PROFILE_RUNTIME_HISTOGRAMS] = {
        L"all observed threads", L"actual tick owner", L"workers (heuristic)", L"selected-gate tick owner"
    };
    const uint32_t *histograms = KNTWR_PROFILE_RUNTIME_HIST(header);
    const kntwr_profile_runtime_pair *pairs = KNTWR_PROFILE_RUNTIME_PAIR_TABLE(header);
    const kntwr_profile_runtime_wait *waits = KNTWR_PROFILE_RUNTIME_WAIT_TABLE(header);
    uint32_t table, i, rank;
    struct { uint32_t rva, key, count; } top[20];
    say(L"Profile runtime: module base=0x%08lX size=0x%08lX; selected site=%ld (-1=whole tick).\n",
        (unsigned long)header->runtime_base, (unsigned long)header->runtime_size,
        header->selected_site ? (long)header->selected_site - 1 : -1L);
    say(L"  Workers exclude actual tick owner and published AI thread; not exact pool membership.\n");
    say(L"  All-thread runtime samples cover actual ticks plus main-thread observations outside ticks.\n");
    for (table = 0; table < KNTWR_PROFILE_RUNTIME_HISTOGRAMS + 2; ++table) {
        uint32_t size = table < KNTWR_PROFILE_RUNTIME_HISTOGRAMS ? header->bucket_count :
            table == KNTWR_PROFILE_RUNTIME_HISTOGRAMS ? header->pair_capacity : header->wait_capacity;
        ZeroMemory(top, sizeof top);
        for (i = 0; i < size; ++i) {
            uint32_t count, rva, key = 0;
            if (table < KNTWR_PROFILE_RUNTIME_HISTOGRAMS) {
                count = histograms[table * header->bucket_count + i]; rva = i * header->bucket_bytes;
            } else if (table == KNTWR_PROFILE_RUNTIME_HISTOGRAMS) {
                count = pairs[i].count; rva = pairs[i].rva; key = pairs[i].frame_rva;
            } else {
                count = waits[i].count; rva = waits[i].rva; key = waits[i].kind;
            }
            if (!count || count <= top[19].count) continue;
            for (rank = 19; rank && count > top[rank - 1].count; --rank) top[rank] = top[rank - 1];
            top[rank].rva = rva; top[rank].key = key; top[rank].count = count;
        }
        say(L"  Top 20 runtime %ls:\n", table < KNTWR_PROFILE_RUNTIME_HISTOGRAMS ? names[table] :
            table == KNTWR_PROFILE_RUNTIME_HISTOGRAMS ? L"tick owner / main-image frame pairs" : L"tick wait-stub callers (exact RVAs)");
        for (rank = 0; rank < 20 && top[rank].count; ++rank) {
            say(L"    RVA 0x%08lX  %10lu", (unsigned long)top[rank].rva, (unsigned long)top[rank].count);
            if (table == KNTWR_PROFILE_RUNTIME_HISTOGRAMS)
                say(L"  frame RVA=0x%08lX preferred VA=0x%08lX", (unsigned long)top[rank].key,
                    (unsigned long)(0x400000u + top[rank].key));
            else if (table == KNTWR_PROFILE_RUNTIME_HISTOGRAMS + 1)
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
    kntwr_profile_status p;
    const kntwr_profile_runtime_header *runtime;
    wchar_t path[MAXP + 16], tmp[MAXP + 20];
    HANDLE file;
    DWORD wrote, bytes, error = 0;
    if (!(r->opt.mask & (KNTWR_PROFILE | KNTWR_GRID_CENSUS | KNTWR_AI_CENSUS))) return TRUE;
    if (!r->have_profile) {
        errsay(L"no complete profiling snapshot is available (sampling may not have started).\n");
        return FALSE;
    }
    p = r->profile;
    runtime = (const kntwr_profile_runtime_header *)(r->profile_arrays + p.bucket_count * (3 + KNTWR_PROFILE_MAIN_PHASES));
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
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, KNTWR_PROFILE_PHASE_A1, KNTWR_PROFILE_PHASE_C);
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, KNTWR_PROFILE_PHASE_A1, KNTWR_PROFILE_PHASE_A2);
    print_profile_main_diff(&p, r->profile_arrays + p.bucket_count * 3, KNTWR_PROFILE_PHASE_B, KNTWR_PROFILE_PHASE_C);
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
    bytes = p.bucket_count * sizeof(uint32_t) * (3 + KNTWR_PROFILE_MAIN_PHASES);
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

/* A launch that failed after CreateProcessW: nothing of the suspended process may survive. */
static void launch_abort(PROCESS_INFORMATION *pi)
{
    TerminateProcess(pi->hProcess, 1);
    WaitForSingleObject(pi->hProcess, 2000);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
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
/* Freeze EVERY thread of pid so a non-atomic write into an already-loaded DLL (mss32.dll's rel32 at RVA 0x314EF straddles a dword
   boundary) cannot tear on another thread (e.g. the Miles mixer).  Threads can be created while enumerating, so snapshots repeat
   until a whole pass finds no thread that is not already frozen and had no failure.  Any unrecoverable failure unwinds every
   suspension taken so far and returns FALSE: the caller must then not write. */
typedef struct ThreadFreeze {
    HANDLE *h;
    DWORD *tid;
    unsigned n, cap;
} ThreadFreeze;

static BOOL freeze_has(const ThreadFreeze *f, DWORD tid)
{
    unsigned i;
    for (i = 0; i < f->n; ++i) if (f->tid[i] == tid) return TRUE;
    return FALSE;
}

static void thaw_threads(ThreadFreeze *f)
{
    unsigned i;
    for (i = 0; i < f->n; ++i) { ResumeThread(f->h[i]); CloseHandle(f->h[i]); }
    if (f->h) HeapFree(GetProcessHeap(), 0, f->h);
    if (f->tid) HeapFree(GetProcessHeap(), 0, f->tid);
    memset(f, 0, sizeof *f);
}

static BOOL freeze_threads(DWORD pid, ThreadFreeze *f, wchar_t *why, size_t why_cap)
{
    enum { kMaxPasses = 64 };
    int pass;
    memset(f, 0, sizeof *f);
    why[0] = 0;
    for (pass = 0; pass < kMaxPasses; ++pass) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te;
        BOOL progress = FALSE, failed = FALSE;
        DWORD last_err = 0;
        if (snap == INVALID_HANDLE_VALUE) {
            _snwprintf_s(why, why_cap, _TRUNCATE, L"thread snapshot failed (Win32 %lu)", (unsigned long)GetLastError());
            thaw_threads(f);
            return FALSE;
        }
        te.dwSize = sizeof te;
        if (Thread32First(snap, &te)) {
            do {
                HANDLE th;
                if (te.th32OwnerProcessID != pid || freeze_has(f, te.th32ThreadID)) continue;
                th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!th) { failed = TRUE; last_err = GetLastError(); continue; }   /* may have exited since the snapshot: next pass decides */
                if (SuspendThread(th) == (DWORD)-1) { failed = TRUE; last_err = GetLastError(); CloseHandle(th); continue; }
                if (f->n == f->cap) {
                    unsigned cap = f->cap ? f->cap * 2u : 64u;
                    HANDLE *nh = f->h ? (HANDLE *)HeapReAlloc(GetProcessHeap(), 0, f->h, cap * sizeof *nh) : (HANDLE *)HeapAlloc(GetProcessHeap(), 0, cap * sizeof *nh);
                    DWORD *nt;
                    if (nh) f->h = nh;
                    nt = nh ? (f->tid ? (DWORD *)HeapReAlloc(GetProcessHeap(), 0, f->tid, cap * sizeof *nt) : (DWORD *)HeapAlloc(GetProcessHeap(), 0, cap * sizeof *nt)) : NULL;
                    if (nt) f->tid = nt;
                    if (!nh || !nt) {
                        ResumeThread(th); CloseHandle(th); CloseHandle(snap);
                        _snwprintf_s(why, why_cap, _TRUNCATE, L"out of memory while tracking suspended threads");
                        thaw_threads(f);
                        return FALSE;
                    }
                    f->cap = cap;
                }
                f->h[f->n] = th;
                f->tid[f->n] = te.th32ThreadID;
                f->n++;
                progress = TRUE;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        if (!progress && !failed) return TRUE;     /* a clean pass found nothing new: every thread is stopped */
        if (failed && !progress) {
            _snwprintf_s(why, why_cap, _TRUNCATE, L"a thread could not be opened/suspended (Win32 %lu)", (unsigned long)last_err);
            if (pass >= 8) { thaw_threads(f); return FALSE; }   /* transient (thread exiting) vs persistent */
        }
        Sleep(1);
    }
    _snwprintf_s(why, why_cap, _TRUNCATE, L"the process kept creating threads (%d passes)", (int)kMaxPasses);
    thaw_threads(f);
    return FALSE;
}

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
        errsay(L"the running process image \"%ls\" is not the validated Napoleon.exe \"%ls\"; runtime not installed.\n", proc_path, r->exe_path);
        return EXIT_INSTALL;
    }
    if (!file_id_path(scan.main_path, &mod_id) || !same_id(&mod_id, &r->exe_id)) {
        errsay(L"the game's main module \"%ls\" is not the validated Napoleon.exe \"%ls\"; runtime not installed.\n", scan.main_path, r->exe_path);
        return EXIT_INSTALL;
    }
    why = read_remote_ident(r->proc, scan.main_base, FALSE, &id);
    if (why) { errsay(L"the game's main module at 0x%08lX is not a valid x86 image: %ls.\n", (unsigned long)scan.main_base, why); return EXIT_INSTALL; }
    r->exe_base = scan.main_base;
    say(L"Game pid %lu, main image base 0x%08lX%ls.\n", (unsigned long)r->pid, (unsigned long)r->exe_base,
        r->exe_base == 0x400000u ? L"" : L" (relocated)");
    if (r->gp_applied && r->gp_rep.proof_site_va && r->gp_rep.proof_section_va) {
        uint8_t sb[5], cb[8];
        SIZE_T n1 = 0, n2 = 0;
        if (ReadProcessMemory(r->proc, (LPCVOID)(uintptr_t)r->gp_rep.proof_site_va, sb, 5, &n1) && n1 == 5 &&
            ReadProcessMemory(r->proc, (LPCVOID)(uintptr_t)r->gp_rep.proof_section_va, cb, 8, &n2) && n2 == 8 &&
            memcmp(sb, r->gp_rep.proof_site_bytes, 5) == 0 && memcmp(cb, r->gp_rep.proof_section_bytes, 8) == 0) {
            r->gp_live_verified = TRUE;
            say(L"  gameplay patch live: trampoline 0x%08lX -> 0x%08lX (%02X %02X %02X %02X %02X), .sq4 @ 0x%08lX (%02X %02X %02X %02X %02X %02X %02X %02X).\n",
                (unsigned long)r->gp_rep.proof_site_va, (unsigned long)r->gp_rep.proof_target_va,
                sb[0], sb[1], sb[2], sb[3], sb[4], (unsigned long)r->gp_rep.proof_section_va,
                cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6], cb[7]);
        } else {
            errsay(L"live read-back of the in-memory gameplay patch failed; runtime not installed.\n");
            return EXIT_INSTALL;
        }
    }
    if (r->mss32_state == MSS_STOCK) {
        NameFind mf;
        uint32_t msz = 0, tries;
        const uint8_t *mb = kntwr_gp_mss32_blob(&msz);
        kntwr_gp_pm mm_ctx;
        kntwr_gp_memory mm;
        ThreadFreeze fz;
        wchar_t why_freeze[256];
        unsigned fz_count;
        int mrc;
        mf.name = L"mss32.dll";
        mf.base = mf.size = 0;
        /* mss32.dll is a static import, mapped before the entry point; the loader has settled, so a bounded retry covers a
           transient enumeration failure.  Never a silent skip. */
        for (tries = 0; tries < 50 && !mf.base; ++tries) {
            if (tries) Sleep(100);
            mf.base = mf.size = 0;
            if (module_walk(r->pid, name_cb, &mf, &err) <= 0) mf.base = 0;
        }
        if (!mf.base) {
            errsay(L"mss32.dll is stock on disk but was not found among the game's modules after %u tries (Win32 %lu); the in-memory audio patch "
                   L"cannot be applied, so the runtime was NOT installed.\n", tries, (unsigned long)err);
            return EXIT_INSTALL;
        }
        r->mss32_base = mf.base;
        if (!freeze_threads(r->pid, &fz, why_freeze, 256)) {
            errsay(L"cannot freeze every game thread (%ls); refusing the mss32.dll write, the runtime was NOT installed.\n", why_freeze);
            return EXIT_INSTALL;
        }
        fz_count = fz.n;
        kntwr_gp_pm_init(&mm_ctx, r->proc);
        mm = kntwr_gp_pm_memory(&mm_ctx);
        mrc = kntwr_gp_apply(&mm, mf.base, 0x21100000u, mb, msz, &r->mss32_rep);
        if (mrc != 0 && r->mss32_rep.rollback == KNTWR_GP_ROLLBACK_FAILED) {
            /* The patch is partly written and could not be undone: the launcher-owned game must not run. */
            errsay(L"applying the in-memory mss32.dll patch failed and could not be rolled back: %hs. Terminating the launched game (pid %lu).\n",
                   r->mss32_rep.error, (unsigned long)r->pid);
            TerminateProcess(r->proc, 1);
            WaitForSingleObject(r->proc, 5000);
            r->game_exited = TRUE;
            r->game_exit = 1;
            thaw_threads(&fz);
            return EXIT_INSTALL;
        }
        thaw_threads(&fz);   /* only after success, nothing-written, or a verified rollback */
        if (mrc != 0) {
            errsay(L"applying the in-memory mss32.dll patch failed (%ls): %hs.\n",
                   r->mss32_rep.rollback == KNTWR_GP_ROLLBACK_RESTORED ? L"original bytes restored and verified" : L"nothing was written", r->mss32_rep.error);
            return EXIT_INSTALL;
        }
        r->mss32_applied = TRUE;
        say(L"  mss32.dll patch applied in memory at 0x%08lX (%lu runs, %lu bytes, %u threads frozen).\n",
            (unsigned long)mf.base, (unsigned long)r->mss32_rep.runs_applied, (unsigned long)r->mss32_rep.bytes_applied, fz_count);
    }

    if (!resolve_remote_loadlibrary(r, &ll_addr)) return EXIT_INSTALL;

    /* One remote page-granular block: [0,sizeof kntwr_config) kntwr_config, [sizeof kntwr_config,...) runtime DLL path. */
    plen_bytes = (wcslen(r->dll_path) + 1) * sizeof(wchar_t);
    total = sizeof r->cfg + plen_bytes;
    mem = (uint32_t)(uintptr_t)VirtualAllocEx(r->proc, NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { win_fail(L"VirtualAllocEx in the game", GetLastError()); return EXIT_INSTALL; }
    local = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!local) { errsay(L"out of memory.\n"); VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE); return EXIT_INSTALL; }

    r->cfg.abi = KNTWR_ABI;
    r->cfg.size = sizeof r->cfg;
    r->cfg.enabled_mask = r->opt.mask;
    r->cfg.workers = r->opt.workers;
    r->cfg.image_base = r->exe_base;
    r->cfg.poll_ms = r->opt.poll_ms;
    r->cfg.profile_site = r->opt.profile_site;
    r->cfg.collide_lod_m = r->opt.collide_lod_m | (r->opt.collide_census ? KNTWR_COLLIDE_CENSUS : 0u);
    r->cfg.loco_flags = loco_flags_from(&r->opt);
    r->cfg.brain_flags = (r->opt.brain_census ? KNTWR_BRAIN_CENSUS : 0u) |
                         (r->opt.brain_timing ? KNTWR_BRAIN_TIMING : 0u) |
                         (r->opt.brain_node_shadow ? KNTWR_BRAIN_NODE_SHADOW : 0u) |
                         (r->opt.brain_fire_shadow ? KNTWR_BRAIN_FIRE_SHADOW : 0u) |
                         (r->opt.brain_finalizer_shadow ? KNTWR_BRAIN_FINALIZER_SHADOW : 0u) |
                         (r->opt.brain_parallel ? KNTWR_BRAIN_PARALLEL : 0u) |
                         (r->opt.brain_quiet ? KNTWR_BRAIN_QUIET : 0u) |
                         (r->opt.brain_unit_shadow ? KNTWR_BRAIN_UNIT_SHADOW : 0u) |
                         (r->opt.brain_s0 ? KNTWR_BRAIN_S0 : 0u) |
                         (r->opt.brain_locality ? KNTWR_BRAIN_LOCALITY : 0u) |
                         (r->opt.brain_locality_warm ? KNTWR_BRAIN_LOCALITY_WARM : 0u) |
                         (r->opt.brain_locality_prefetch ? KNTWR_BRAIN_LOCALITY_PREFETCH : 0u) |
                         (r->opt.brain_locality_prefetch2 ? KNTWR_BRAIN_LOCALITY_PREFETCH2 : 0u) |
                         (r->opt.brain_locality_mark ? KNTWR_BRAIN_LOCALITY_MARK : 0u) |
                         ((r->opt.brain_unit_fatigue || r->opt.brain_unit_fatigue_shadow) ? KNTWR_BRAIN_UNIT_FATIGUE : 0u) |
                         (r->opt.brain_unit_fatigue_shadow ? KNTWR_BRAIN_UNIT_FATIGUE_SHADOW : 0u) |
                         ((r->opt.brain_unit_posture || r->opt.brain_unit_posture_shadow) ? KNTWR_BRAIN_UNIT_POSTURE : 0u) |
                         (r->opt.brain_unit_posture_shadow ? KNTWR_BRAIN_UNIT_POSTURE_SHADOW : 0u) |
                         ((r->opt.brain_unit_engage || r->opt.brain_unit_engage_shadow) ? KNTWR_BRAIN_UNIT_ENGAGE : 0u) |
                         (r->opt.brain_unit_engage_shadow ? KNTWR_BRAIN_UNIT_ENGAGE_SHADOW : 0u);
    r->cfg.collide_flags = (r->opt.collide_contact_shadow ? KNTWR_COLLIDE_CONTACT_SHADOW : 0u) |
                           (r->opt.collide_contact_workers ? KNTWR_COLLIDE_CONTACT_WORKERS : 0u);
    r->cfg.va_watch_flags = (r->opt.va_watch ? KNTWR_VA_WATCH : 0u) | (r->opt.army_storm_census ? KNTWR_ARMY_STORM_CENSUS : 0u) |
                            (r->opt.army_storm_sample_ms << KNTWR_ARMY_STORM_SAMPLE_SHIFT) |
                            (r->opt.tick_pcore ? KNTWR_TICK_PCORE : 0u) | (r->opt.tick_core_ab ? KNTWR_TICK_CORE_AB : 0u);
    r->cfg.va_watch_flags |= (r->opt.army_solver_memo ? KNTWR_ARMY_SOLVER_MEMO : 0u) | (r->opt.army_solver_shadow ? KNTWR_ARMY_SOLVER_SHADOW : 0u) |
                             (r->opt.alloc_census ? KNTWR_ALLOC_CENSUS : 0u) | (r->opt.alloc_fix ? KNTWR_ALLOC_FIX : 0u) |
                             (r->opt.arena_release ? KNTWR_ARENA_RELEASE : 0u) | (r->opt.heap_optimize ? KNTWR_HEAP_OPTIMIZE : 0u) |
                             (r->opt.mounted_officer ? KNTWR_MOUNTED_OFFICER : 0u) | (r->opt.mounted_officer_widen ? KNTWR_MOUNTED_OFFICER_WIDEN : 0u) |
                             (r->opt.engage_census ? KNTWR_ENGAGE_CENSUS : 0u) | (r->opt.formation_census ? KNTWR_FORMATION_CENSUS : 0u) |
                             ((r->opt.va_floor_mib == 1024u ? 17u : (r->opt.va_floor_mib / KNTWR_VA_FLOOR_UNIT_MIB)) << KNTWR_VA_FLOOR_SHIFT) |
                             ((r->opt.va_hole_mib / KNTWR_VA_FLOOR_UNIT_MIB) << KNTWR_VA_HOLE_SHIFT);
    r->cfg.ai_deferred = r->opt.ai_deferred ? r->opt.ai_deferred_k | (r->opt.ai_deferred_budget << KNTWR_AI_DEFERRED_BUDGET_SHIFT) : 0u;
    r->cfg.ai_ctrl_flags = r->opt.ai_ctrl_flags | (r->opt.ai_claim_once ? KNTWR_AI_CLAIM_ONCE : 0u) | (r->opt.ai_claim_once_census ? KNTWR_AI_CLAIM_ONCE_CENSUS : 0u) |
                           (r->opt.brain_target_cull_shadow ? KNTWR_AI_TARGET_CULL_SHADOW : 0u) | (r->opt.brain_target_cull ? KNTWR_AI_TARGET_CULL : 0u) |
                           (r->opt.brain_retarget_jitter ? KNTWR_AI_RETARGET_JITTER : 0u);
    r->cfg.ai_prepass_flags = r->opt.ai_prepass_flags;
    r->cfg.gameplay_flags = (r->opt.drag_ladder ? KNTWR_DRAG_LADDER : 0u) |
                            (r->opt.wounded ? (KNTWR_WOUNDED | (r->opt.wounded_pct << KNTWR_WOUNDED_PCT_SHIFT)) : 0u);
    memcpy(local, &r->cfg, sizeof r->cfg);
    memcpy(local + sizeof r->cfg, r->dll_path, plen_bytes);
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
    rc = remote_call(r, ll_addr, mem + sizeof r->cfg, 60000, 0xFFFFu, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(LoadLibraryW)", err);
        else if (rc == RC_DIED) report_remote_death(r, L"remote LoadLibraryW");
        else errsay(L"remote LoadLibraryW %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        else if (rc != RC_DIED) VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    if (code == 0) {
        note_game_exit(r);
        errsay(L"LoadLibraryW returned NULL inside the game for \"%ls\" (missing dependency, wrong architecture or blocked "
               L"load). %ls\n", r->dll_path,
               r->game_exited ? L"The game process has since exited." : L"The game keeps running unmodified.");
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

    rc = remote_call(r, r->dll_base + r->dll.start_rva, mem, 30000, 0xFFFF0000u, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(kntwr_start)", err);
        else if (rc == RC_DIED) report_remote_death(r, L"kntwr_start");
        else errsay(L"kntwr_start %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        else if (rc != RC_DIED) VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    if (code != 0) {
        errsay(L"kntwr_start rejected the configuration or failed (returned 0x%08lX).\n", (unsigned long)code);
        {
            kntwr_status s;
            const wchar_t *sw;
            if (read_status(r, &s, &sw)) { r->last = s; r->have_status = TRUE; print_status(&s, r->opt.mask); }
        }
        VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);
        return EXIT_INSTALL;
    }
    VirtualFreeEx(r->proc, (LPVOID)(uintptr_t)mem, 0, MEM_RELEASE);   /* kntwr_start copied the config; thread has returned */
    return EXIT_OK;
}

/* Stop wait policy. A runtime tick in shadow modes can run for tens of seconds, and kntwr_stop only confirms
   KNTWR_STOPPED after the tick owner drains, slots are restored, and modules are stopped. The launcher therefore
   waits at least kStopTimeoutMs and keeps waiting up to kStopProgressCapMs while the status still changes. */
enum { kStopTimeoutMs = 15000, kStopProgressCapMs = 60000 };

static BOOL request_stop(Run *r)
{
    DWORD code = 0, err = 0;
    int rc;
    kntwr_status s;
    const wchar_t *why;
    uint64_t t0, last_change;
    BOOL have_prev = FALSE;
    kntwr_status prev;
    say(L"Stopping the runtime (restoring hooks); the game keeps running ...\n");
    rc = remote_call(r, r->dll_base + r->dll.stop_rva, 0, kStopProgressCapMs, 0xFFFF0000u, &code, &err);
    if (rc != RC_OK) {
        if (rc == RC_CREATE) win_fail(L"CreateRemoteThread(kntwr_stop)", err);
        else if (rc == RC_DIED) report_remote_death(r, L"kntwr_stop");
        else errsay(L"kntwr_stop %ls.\n", rc_text(rc));
        if (rc == RC_TIMEOUT) r->remote_leaked = TRUE;
        return FALSE;
    }
    if (code != 0) { errsay(L"kntwr_stop returned 0x%08lX.\n", (unsigned long)code); }
    t0 = last_change = now_ms();
    memset(&prev, 0, sizeof prev);
    for (;;) {
        uint64_t t;
        if (read_status(r, &s, &why)) {
            r->last = s;
            if (r->have_overlay) memcpy(r->last.overlay_words, r->overlay_words, sizeof r->overlay_words);
            r->have_status = TRUE;
            if (s.phase == KNTWR_STOPPED) break;
            if (s.phase == KNTWR_FAILED) break;
            if (!have_prev || memcmp(&prev, &s, sizeof s)) { prev = s; have_prev = TRUE; last_change = now_ms(); }
        }
        if (!process_alive(r->proc)) break;
        t = now_ms();
        /* Give up after kStopTimeoutMs without progress, or at the hard cap regardless. */
        if (t - t0 > kStopProgressCapMs || (t - t0 > kStopTimeoutMs && t - last_change > kStopTimeoutMs)) break;
        Sleep(50);
    }
    if (r->have_status) print_status(&r->last, r->opt.mask);
    r->stop_confirmed = code == 0 && r->have_status && r->last.phase == KNTWR_STOPPED;
    return r->stop_confirmed;
}

static void observe_status(Run *r, const kntwr_status *s)
{
    if (s->phase == KNTWR_ACTIVE) {
        if (!r->active_generations || r->last_active_generation != s->generation) {
            ++r->active_generations;
            r->last_active_generation = s->generation;
        }
        if (r->waiting_after_active) {
            ++r->battle_reactivations;
            r->waiting_after_active = FALSE;
        }
        r->battle_active = TRUE;
        if (r->have_status && r->last.phase == KNTWR_ACTIVE &&
            r->last.generation == s->generation && r->last.model == s->model &&
            r->last.root == s->root && s->tick >= r->last.tick)
            r->battle_tick_advance += s->tick - r->last.tick;
    } else if (s->phase == KNTWR_WAITING_BATTLE && r->battle_active) {
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
    if (r->have_overlay) memcpy(r->last.overlay_words, r->overlay_words, sizeof r->overlay_words);
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
    uint64_t last_trace = 0, last_va = 0, last_ec = 0;
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
    capture_overlay_report(r, TRUE);
    for (;;) {
        kntwr_status s;
        DWORD w;
        r->observed_ms = now_ms() - t0;
        if ((r->opt.mask & (KNTWR_PROFILE | KNTWR_GRID_CENSUS | KNTWR_AI_CENSUS)) && (!last_profile || now_ms() - last_profile >= 1000)) {
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
            note_game_exit(r);
            if (r->game_exited)
                say(ok ? L"Runtime stopped cleanly. The game has exited (exit status 0x%08lX%ls).\n"
                       : L"Runtime stop did not complete cleanly. The game has exited (exit status 0x%08lX%ls).\n",
                    (unsigned long)r->game_exit, exit_status_name(r->game_exit));
            else
                say(ok ? L"Runtime stopped cleanly. Game left running (pid %lu).\n" : L"Runtime stop did not complete cleanly. Game left running (pid %lu).\n", (unsigned long)r->pid);
            return !ok ? EXIT_STOP_FAILED : (!profile_ok ? EXIT_RECEIPT : EXIT_INTERRUPTED);
        }
        if (r->opt.observe_s && now_ms() - t0 >= (uint64_t)r->opt.observe_s * 1000u) {
            BOOL profile_ok;
            finalize_trace(r);
            r->observation_complete = TRUE;
            say(L"Observation bound (%lu s) reached (game pid %lu).\n",
                (unsigned long)r->opt.observe_s, (unsigned long)r->pid);
            if (r->have_status) { print_status(&r->last, r->opt.mask); print_counters(&r->last); print_module_words(&r->last, r->cfg.brain_flags, r->cfg.ai_ctrl_flags); }
            if (!read_profile(r)) say(L"Final profile read unavailable; using the last complete periodic copy if retained.\n");
            profile_ok = write_profile(r);
            if (r->opt.exit_game_after_observe) {
                if (!stop_then_close_game(r)) return EXIT_GAME_STOP_FAILED;
            } else {
                note_game_exit(r);
                if (r->game_exited)
                    say(L"The game has exited (exit status 0x%08lX%ls); the runtime was left unchanged.\n",
                        (unsigned long)r->game_exit, exit_status_name(r->game_exit));
                else
                    say(L"Game and runtime are left running, unchanged.\n");
            }
            return !profile_ok ? EXIT_RECEIPT : (r->ever_full ? EXIT_OK : EXIT_NOT_ACTIVE);
        }
        w = WaitForSingleObject(r->proc, r->opt.tick_log[0] ? 10 : 200);
        if (w == WAIT_OBJECT_0) {
            GetExitCodeProcess(r->proc, &r->game_exit);
            r->game_exited = TRUE;
            say(L"Game exited with code 0x%08lX.\n", (unsigned long)r->game_exit);
            if (r->have_status) { print_status(&r->last, r->opt.mask); print_crash(&r->last); if (r->opt.va_watch) print_va_watch(&r->last, TRUE); }
            if (r->game_exit != 0) say(L"  (non-zero exit: the runtime state above is the last snapshot taken before exit)\n");
            if (r->opt.mask & (KNTWR_PROFILE | KNTWR_GRID_CENSUS | KNTWR_AI_CENSUS))
                say(L"Game exited before final capture; using the last periodic profile snapshot (normally <=1.2 s old).\n");
            if (r->active_generations)
                say(L"Game exited before final tick capture; using the last complete periodic tick trace.\n");
            if (!write_profile(r)) return EXIT_RECEIPT;
            return r->ever_full ? EXIT_OK : EXIT_NOT_ACTIVE;
        }
        if (!read_status(r, &s, &why)) {
            ++bad;
            if (!r->have_status && now_ms() > first_ok_deadline) {
                errsay(L"no valid runtime status within 15 s of kntwr_start: %ls.\n", why);
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
        if (s.phase == KNTWR_WAITING_BATTLE || s.phase == KNTWR_ACTIVATING || s.phase == KNTWR_ACTIVE) r->ever_armed = TRUE;
        if (!have_prev || s.phase != prev_phase || s.active_mask != prev_active || s.generation != prev_gen || s.error != prev_err) {
            have_prev = TRUE;
            prev_phase = s.phase;
            prev_active = s.active_mask;
            prev_gen = s.generation;
            prev_err = s.error;
            switch (s.phase) {
            case KNTWR_VERIFYING: say(L"Runtime verifying the live image ...\n"); break;
            case KNTWR_WAITING_BATTLE: say(L"Runtime ARMED: waiting for a battle. NOT active yet.\n"); break;
            case KNTWR_ACTIVATING: say(L"Runtime activating ...\n"); break;
            case KNTWR_ACTIVE:
                if ((s.active_mask & r->opt.mask) == r->opt.mask) {
                    r->ever_full = TRUE;
                    say(L"Runtime ACTIVE: every requested feature is active.\n");
                } else {
                    if(s.memory_words[KNTWR_MEM_BUDGET_DISABLED_MASK])
                        say(L"Runtime ACTIVE with VA-budget fallback: LOCO/COLLIDE use originals; budget_refusals=%lu; other features continue.\n",
                            (unsigned long)s.memory_words[KNTWR_MEM_BUDGET_REFUSALS]);
                    else say(L"Runtime ACTIVE but PARTIAL: not every requested feature is active.\n");
                }
                capture_overlay_report(r, TRUE);
                break;
            case KNTWR_RESTORING: say(L"Runtime restoring original code ...\n"); break;
            case KNTWR_FAILED: errsay(L"runtime reported FAILED.\n"); break;
            case KNTWR_STOPPED: say(L"Runtime STOPPED.\n"); break;
            default: break;
            }
            print_status(&s, r->opt.mask);
            last_stats = now_ms();
        } else if (s.phase == KNTWR_ACTIVE && now_ms() - last_stats >= 15000) {
            print_counters(&s);
            last_stats = now_ms();
        }
        if (r->opt.va_watch && now_ms() - last_va >= 10000) { print_va_watch(&s, FALSE); last_va = now_ms(); }
        if (r->opt.engage_census && s.phase == KNTWR_ACTIVE && now_ms() - last_ec >= 10000) { print_engage_census_line(s.engage_census_words); last_ec = now_ms(); }
        if (s.phase == KNTWR_FAILED) {
            errsay(L"runtime failure: error=0x%08lX detail=0x%08lX. Requesting stop so original code is restored.\n",
                   (unsigned long)s.error, (unsigned long)s.error_detail);
            write_profile(r);
            request_stop(r);
            r->stop_requested = TRUE;
            return EXIT_RUNTIME_FAILED;
        }
        if (s.phase == KNTWR_STOPPED) {
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

typedef LONG(NTAPI *nt_query_proc_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOL query_peb32_image_base(HANDLE proc, uint32_t *out)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    nt_query_proc_fn nq = ntdll ? (nt_query_proc_fn)GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;
    ULONG_PTR peb = 0;
    ULONG got = 0;
    SIZE_T rd = 0;
    if (!nq) return FALSE;
    if (nq(proc, 26 /* ProcessWow64Information */, &peb, sizeof peb, &got) != 0 || peb == 0) {
        struct { PVOID a, peb, c, d, e, f; } pbi;
        memset(&pbi, 0, sizeof pbi);
        if (nq(proc, 0 /* ProcessBasicInformation */, &pbi, sizeof pbi, &got) != 0) return FALSE;
        peb = (ULONG_PTR)pbi.peb;
    }
    return ReadProcessMemory(proc, (LPCVOID)(peb + 8), out, 4, &rd) && rd == 4 && *out != 0;
}

/* --formation-census with --no-activate: no runtime, no injection. The launcher polls the game's memory (census.c) until the observation bound or the exit. */
static int run_external_census(Run *r)
{
    uint32_t base = r->exe_base;
    uint64_t t0 = now_ms();
    int code = EXIT_OK;
    if (ext_census_open(r->opt.formation_census_csv, r->opt.formation_census_every) != 0) {
        errsay(L"cannot create the formation census CSV \"%ls\".\n", r->opt.formation_census_csv);
        return EXIT_RECEIPT;
    }
    say(L"Launcher-side formation census running (no runtime): csv %ls; Ctrl+C%ls stops it.\n", r->opt.formation_census_csv,
        r->opt.observe_s ? L" or the observation bound" : L"");
    for (;;) {
        if (g_stop) { code = EXIT_INTERRUPTED; break; }
        if (!process_alive(r->proc)) {
            GetExitCodeProcess(r->proc, &r->game_exit);
            r->game_exited = TRUE;
            say(L"The game exited (code 0x%08lX).\n", (unsigned long)r->game_exit);
            break;
        }
        if (r->opt.observe_s && now_ms() - t0 >= (uint64_t)r->opt.observe_s * 1000u) {
            say(L"Observation bound (%lu s) reached.\n", (unsigned long)r->opt.observe_s);
            break;
        }
        if (!base) query_peb32_image_base(r->proc, &base);
        else ext_census_poll(r->proc, base);
        WaitForSingleObject(r->proc, 100);
    }
    say(L"Formation census: %lu rows written to %ls.\n", (unsigned long)ext_census_rows(), r->opt.formation_census_csv);
    ext_census_close();
    if (r->opt.exit_game_after_observe && !r->game_exited && !close_observed_game(r)) code = EXIT_GAME_STOP_FAILED;
    return code;
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
    say(L"Launching: %ls\n  working directory: %ls\n", cmd, r->game_dir);
    if (r->opt.army_storm_census) say(L"  army storm census: ON, storm-gated sampler threshold %lu ms (0 = sampler unchanged)\n", (unsigned long)r->opt.army_storm_sample_ms);
    if (r->opt.army_solver_memo || r->opt.army_solver_shadow) say(L"  army solver: %ls\n", r->opt.army_solver_memo ? L"MEMO (kernel replaces the native flag=1 solver)" : L"SHADOW (native authoritative, kernel compared)");
    if (r->opt.alloc_census || r->opt.alloc_fix)
        say(L"  alloc: %ls\n", (r->opt.alloc_census && r->opt.alloc_fix) ? L"FIX + CENSUS (mode=3)" :
                               (r->opt.alloc_fix ? L"FIX (mode=2, zero-VA pathfinder subnode reclamation)" : L"CENSUS (mode=1, 32.25 MiB callsite table)"));
    if (r->opt.mounted_officer) say(L"  mounted officer: ON (%ls radius)\n", r->opt.mounted_officer_widen ? L"WIDENED" : L"infantry-spacing");
    if (r->opt.drag_ladder) say(L"  drag ladder: ON (GAMEPLAY change: files-per-row laddered at source, drag-out frontage snaps down to 60-file steps above 60 files; all multiplayer peers must use the same setting)\n");
    if (r->opt.wounded) say(L"  wounded: ON %lu%% (EXPERIMENTAL GAMEPLAY change: FACE-tagged shot deaths enter the native wounded/crawl loops instead of a static corpse; all multiplayer peers must use the same setting)\n", (unsigned long)r->opt.wounded_pct);
    if (r->opt.engage_census) say(L"  engage census: ON (read-only observer after every routed tick)\n");
    if (r->opt.formation_census)
        say(L"  formation census: ON (%ls, every %lu ticks, csv %ls)\n", r->opt.activate ? L"in-process observer after every routed tick" : L"launcher-side ReadProcessMemory",
            (unsigned long)(r->opt.formation_census_every ? r->opt.formation_census_every : 30u), r->opt.formation_census_csv);
    if (r->opt.no_gameplay_patch) say(L"  gameplay patch and heap serialization correction: NOT applied (--no-gameplay-patch, disk image unchanged in memory)\n");
    else {
        if (r->opt.gp_filter_listed)
            say(L"  gameplay patch: SUBSET (--gameplay-patch-%ls-runs: %lu run bits listed; header and appended sections always applied)\n",
                r->opt.gp_filter.mode == KNTWR_GP_ONLY ? L"only" : L"skip",
                (unsigned long)(__popcnt(r->opt.gp_filter.runs[0]) + __popcnt(r->opt.gp_filter.runs[1]) + __popcnt(r->opt.gp_filter.runs[2]) + __popcnt(r->opt.gp_filter.runs[3])));
        if (r->opt.no_d3d9_swap) say(L"  gameplay patch: D3D9 swap OFF (--no-d3d9-swap: Direct3DCreate9 runs 65, 92 left stock)\n");
    }
    if (r->opt.formation_census && r->opt.activate) {   /* the in-process census reads its path / period from the game's environment */
        wchar_t ev[16];
        SetEnvironmentVariableW(L"KNTWR_FORMATION_CENSUS_CSV", r->opt.formation_census_csv);
        _snwprintf_s(ev, 16, _TRUNCATE, L"%lu", (unsigned long)(r->opt.formation_census_every ? r->opt.formation_census_every : 30u));
        SetEnvironmentVariableW(L"KNTWR_FORMATION_CENSUS_EVERY", ev);
        if (r->opt.formation_census_men) SetEnvironmentVariableW(L"KNTWR_FORMATION_CENSUS_MEN", L"1");
    }
    /* --steam (default): a game created outside Steam has no app id, so SteamAPI_Init cannot attach (no steam_appid.txt, no
       RestartAppIfNecessary) and multiplayer, lobbies and the overlay are unavailable. Give the child what a Steam launch gives
       it; values already present (KNTWR started by Steam or by the user) are kept. --no-steam opts out of Steam integration. */
    if (r->opt.steam) {
        static const wchar_t *const steam_vars[2] = { L"SteamAppId", L"SteamGameId" };
        wchar_t val[64];
        int v;
        for (v = 0; v < 2; ++v) {
            const DWORD got = GetEnvironmentVariableW(steam_vars[v], val, 64);
            const BOOL keep = got > 0 && got < 64;
            if (!keep) SetEnvironmentVariableW(steam_vars[v], KNTWR_STEAM_APP_ID);
            say(L"  steam: %ls=%ls (%ls)\n", steam_vars[v], keep ? val : KNTWR_STEAM_APP_ID, keep ? L"inherited" : L"set by kntwr");
        }
    }
    memset(&pi, 0, sizeof pi);
    if (!r->opt.no_gameplay_patch) {
        /* The stock image ends 0x5000 below a 64 KiB boundary and the patch appends 0xA000 bytes of sections; Windows places
           the PEBs and other allocations in that gap before any game code runs, so a running image cannot reliably be
           extended after creation.  Instead the child is created with one extra input attribute, PS_ATTRIBUTE_MEMORY_RESERVE, reserving exactly
           the computed 64 KiB-aligned tail above the stock image, attached through a scoped wrapper around this process's OWN
           KernelBase import of NtCreateUserProcess.  The installed file, its path, identity, hash and every stock behavior are
           untouched (multiplayer checksums see the stock image); the wrapper wraps only this one creation on this thread and is
           restored immediately afterwards. */
        uint32_t bsz = 0;
        const uint8_t *blob = kntwr_gp_napoleon_blob(&bsz);
        if (kntwr_gp_reserve_plan(r->exe_file, blob, bsz, &r->gp_rsv, &r->gp_rsv_rep) != 0) {
            errsay(L"planning the launch reservation failed at stage %hs (code %lu): %hs. Nothing was started; the installed game was not touched.\n",
                   kntwr_gp_reserve_stage_name(r->gp_rsv_rep.stage), (unsigned long)r->gp_rsv_rep.code, r->gp_rsv_rep.error);
            return FALSE;
        }
        if (kntwr_gp_reserve_hook(&r->gp_rsv, &r->gp_rsv_rep) != 0) {
            errsay(L"installing the launch-reservation wrapper failed at stage %hs (code %lu): %hs. No game was started.\n",
                   kntwr_gp_reserve_stage_name(r->gp_rsv_rep.stage), (unsigned long)r->gp_rsv_rep.code, r->gp_rsv_rep.error);
            kntwr_gp_reserve_dispose(&r->gp_rsv);
            return FALSE;
        }
        say(L"  launch reservation: 0x%lX bytes at 0x%08lX (SizeOfImage 0x%lX -> 0x%lX held at creation via PS_ATTRIBUTE_MEMORY_RESERVE; "
            L"the stock image, its path and its identity are untouched)\n",
            (unsigned long)r->gp_rsv.reserve_size, (unsigned long)r->gp_rsv.reserve_base,
            (unsigned long)r->gp_rsv.stock_soi, (unsigned long)r->gp_rsv.patched_soi);
    }
    {
        const BOOL hooked = r->gp_rsv.hook_installed != 0;
        const BOOL created = CreateProcessW(r->exe_path, cmd, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, NULL, r->game_dir, &si, &pi);
        const DWORD cp_err = created ? 0 : GetLastError();
        if (hooked) {
            /* The import is always restored before anything else looks at the child. */
            kntwr_gp_reserve_report urep;
            if (kntwr_gp_reserve_unhook(&r->gp_rsv, &urep) != 0) {
                r->gp_rsv_rep = urep;
                errsay(L"restoring the import after process creation failed at stage %hs (code %lu): %hs.\n",
                       kntwr_gp_reserve_stage_name(urep.stage), (unsigned long)urep.code, urep.error);
                kntwr_gp_reserve_dispose(&r->gp_rsv);
                if (created) launch_abort(&pi);
                return FALSE;
            }
        }
        kntwr_gp_reserve_dispose(&r->gp_rsv); /* the pin's lifetime is the creation; idempotent on the no-patch path */
        if (!created) {
            if (cp_err == ERROR_ELEVATION_REQUIRED)
                errsay(L"Windows says Napoleon.exe requires elevation. Run KNTWR.exe from an elevated prompt (nothing was started).\n");
            else if (r->gp_rsv.reject)
                errsay(L"the launch-reservation wrapper refused the child creation (reject %lu; %lu call(s) seen, %lu wrapped). Nothing was started.\n",
                       (unsigned long)r->gp_rsv.reject, (unsigned long)r->gp_rsv.calls_seen, (unsigned long)r->gp_rsv.calls_modified);
            else
                win_fail(L"CreateProcessW(Napoleon.exe)", cp_err);
            return FALSE;
        }
    }
    {
        uint32_t base = 0;
        if (!query_peb32_image_base(pi.hProcess, &base)) {
            errsay(L"unable to read the suspended game's image base from the PEB.\n");
            launch_abort(&pi);
            return FALSE;
        }
        if (r->opt.no_gameplay_patch) {
            if (ResumeThread(pi.hThread) == (DWORD)-1) {
                win_fail(L"ResumeThread(Napoleon.exe)", GetLastError());
                launch_abort(&pi);
                return FALSE;
            }
            r->exe_base = base;
            say(L"  gameplay patch and heap correction NOT applied (--no-gameplay-patch): disk image resumed at base 0x%08lX (delta %+ld).\n", (unsigned long)base, (long)(base - 0x400000u));
        } else {
            /* Patch the stock image and correct heap serialization before any game code executes. */
            uint32_t bsz = 0;
            const uint8_t *blob = kntwr_gp_napoleon_blob(&bsz);
            kntwr_gp_pm pm_ctx;
            kntwr_gp_memory pm;
            int grc;
            if (kntwr_gp_reserve_verify(&r->gp_rsv, pi.hProcess, base, &r->gp_rsv_rep) != 0) {
                errsay(L"the launch reservation is not what creation was asked for (stage %hs, code %lu): %hs. The suspended process was terminated, nothing ran.\n",
                       kntwr_gp_reserve_stage_name(r->gp_rsv_rep.stage), (unsigned long)r->gp_rsv_rep.code, r->gp_rsv_rep.error);
                launch_abort(&pi);
                return FALSE;
            }
            kntwr_gp_pm_init(&pm_ctx, pi.hProcess);
            pm_ctx.owned_reserve_base = r->gp_rsv.reserve_base;
            pm_ctx.owned_reserve_size = r->gp_rsv.reserve_size;
            pm = kntwr_gp_pm_memory(&pm_ctx);
            grc = kntwr_gp_apply_filtered(&pm, base, 0x400000u, blob, bsz, &r->opt.gp_filter, &r->gp_rep);
            if (grc != 0) {
                errsay(L"applying the in-memory gameplay patch failed: %hs (%ls; the suspended process was terminated, nothing ran).\n", r->gp_rep.error,
                       r->gp_rep.phase ? L"the target had already been modified" : L"the target was unchanged");
                launch_abort(&pi);
                return FALSE;
            }
            if (ResumeThread(pi.hThread) == (DWORD)-1) {
                win_fail(L"ResumeThread(Napoleon.exe)", GetLastError());
                launch_abort(&pi);
                return FALSE;
            }
            r->gp_applied = TRUE;
            r->exe_base = base;
            say(L"  gameplay patch applied in memory before first instruction: base 0x%08lX (delta %+ld), %lu/%lu runs (%lu B), "
                L"%lu appended sections (0x%lX B at 0x%08lX, %lu relocs).\n",
                (unsigned long)base, (long)(base - 0x400000u), (unsigned long)r->gp_rep.runs_applied, (unsigned long)r->gp_rep.runs_total,
                (unsigned long)r->gp_rep.bytes_applied, (unsigned long)r->gp_rep.sections_mapped, (unsigned long)r->gp_rep.section_bytes,
                (unsigned long)r->gp_rep.section_base_va, (unsigned long)r->gp_rep.section_fixups);
        }
    }
    CloseHandle(pi.hThread);
    r->proc = pi.hProcess;
    r->pid = pi.dwProcessId;
    r->cfg.main_thread_id = pi.dwThreadId;
    GetProcessTimes(r->proc, &r->created, &ex, &kt, &ut);   /* creation time recorded for the receipt */
    say(L"Game started (pid %lu).\n", (unsigned long)r->pid);
    return TRUE;
}

/* KNTWR_VERSION is the quoted CMake project version ("1.0.0").  The two-level widen runs after that macro expands. */
#ifndef KNTWR_VERSION
#error "KNTWR_VERSION must be set from the CMake project version"
#endif
#define KNTWR_WIDE_LIT(s) L##s
#define KNTWR_WIDE(s) KNTWR_WIDE_LIT(s)

/* ------------------------------------------------------------------------------------------------ command line */
static void usage(void)
{
    say(L"KNTWR - Kaung's Napoleon Total War Runtime (native multithreading launcher)\n\n"
        L"usage: KNTWR.exe [--game DIR] [options]\n"
        L"  --game DIR            folder containing Napoleon.exe (default: the saved configuration, then every Steam library;\n"
        L"                        a launch that finds nothing interactively opens a folder picker and remembers the choice)\n"
        L"  --replay FILE         start the game on a replay (game_startup_mode replay \"FILE\")\n"
        L"  --features LIST       default: all,cavalry_orbit; an explicit list replaces it (all selects accepted optimizations only,\n"
        L"                        and implies cavalry_orbit unless --no-cavalry-orbit or the exclusive ai_async2/brain2 are listed)\n"
        L"                        all = batch64,ai,visual,loco,collide plus their default switches (--loco-clone --loco-parallel\n"
        L"                        --loco-owned-services --loco-quiet --loco-grid --loco-grid-incremental --loco-cw-workers\n"
        L"                        --collide-contact-workers --ai-poly --ai-record-test --ai-claim-once --brain-target-cull --tick-pcore\n"
        L"                        --army-solver-memo). Positive-only --loco-*/--collide-contact-* options replace their default bundle.\n"
        L"                        --no-tick-pcore, --no-loco-cw-workers and --no-collide-contact-workers retain unrelated defaults,\n"
        L"                        including alongside independent positive options; explicit positives conflicting with an opt-out are errors.\n"
        L"                        --ai-poly*/--ai-prepass-census, --ai-record-test-shadow, --ai-claim-once-census, --brain-target-cull-shadow,\n"
        L"                        --tick-core-ab and --army-solver-shadow retain their existing overrides; shipping set: all,cavalry_orbit\n"
        L"                        ai_ctrl = experimental controller offload (not in all); requires ai\n"
        L"                        ai_census = opt-in observation of AI planner mutators (vtable-slot gates, one clone-call gate, EIP ranges); requires ai (not in all)\n"
        L"                        ai_async2 = experimental: site 34 queues the planner; the AI worker runs it between ticks on private clones;\n"
        L"                        the next tick start joins it (no think crosses into a tick; the stall is reported); writers join\n"
        L"                        (site 33, quadtree update, delegate and owner-destructor slots; 5 s watchdog -> synchronous fallback);\n"
        L"                        requires ai, excludes ai_ctrl/ai_census; experimental (non-tick direct-call owner teardown is not covered)\n"
        L"                        collide = Phase B soft-collision solver; overrides the PROFILE collision census\n"
        L"                        collide_lod = half-rate far-unit queries (not in all); cannot combine with collide or formation\n"
        L"                        profile = opt-in instrumentation and statistical sampler (~200 all-thread rounds/s, <=10%% measured duty)\n"
        L"                        brain (needs profile) publishes the 23 vtable slots +0x0C as timed entries and prints/records the\n"
        L"                        per-callee 'brain sites' table of the per-agent brain step, per class family\n"
        L"                        brain2 v2 observes native per-soldier steps on the owner in exact worklist order; --brain-parallel adds the guarded worker path\n"
        L"  --profile            enable profiling and its sampler (default off); additive regardless of --features position\n"
        L"                        --features all,profile also enables it; all/default retain tick logging without profiling\n"
        L"                        explicit grid_census or ai_census may start their diagnostic sampler without profile\n"
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
        L"                        no cross-tick parking or partial-call replay; long native calls still delay the tick\n");
    say(L"%ls",
        L"  --brain-unit-shadow   requires brain2; excludes --brain-parallel/--brain-quiet: per-unit brain Stage A, shadow only. Before\n"
        L"                        the unchanged site-6 loop pool workers decide every unit from unit-level inputs; after each\n"
        L"                        soldier's native step its decided fields are compared with its unit's decision (brain_unit_words)\n"
        L"  --brain-s0            requires brain2; excludes every other --brain-* option except --brain-unit-*: S0 attribution timer. Each\n"
        L"                        step runs the BRAIN_S0 clone family (identical code, counting gates around target, drivers,\n"
        L"                        node begin/step, finalizer, order, lookups, stance, path/posture/next-state, fatigue, timers);\n"
        L"                        1/64 deterministic occurrences timed with RDTSCP, calibrated gate cost subtracted (brain_s0_words)\n"
        L"  --brain-locality      requires brain2; excludes every other --brain-* option (S0 included): site-6 locality census. The original\n"
        L"                        +0C step runs exactly once per occurrence, unchanged; the runner only loads entity fields after the step\n"
        L"                        and derives hot cache-line sets from the static load map: worklist address order, unit/page/line\n"
        L"                        adjacency, distinct lines/pages per object type and per stage, inversion count, and a 1/16 RDTSCP\n"
        L"                        bracket of the step bucketed by lines not touched by the previous occurrence (reuses brain_s0_words)\n"
        L"  --brain-locality-warm       sets --brain-locality: on half of the timed occurrences read-touch every mapped hot line first\n"
        L"                        (touch timed separately): cold-vs-warm step A/B, measured miss cost of the mapped set\n"
        L"  --brain-locality-prefetch   sets --brain-locality: alternating 64-occurrence blocks issue PREFETCHT0 for the next worklist\n"
        L"                        entity (entity + chain-object lines, distance 1); B-A = net gain incl. issue cost\n"
        L"  --brain-locality-prefetch2  sets --brain-locality: entity lines two ahead, chain lines one ahead (software pipeline)\n"
        L"  --brain-locality-mark       sets --brain-locality: pure pass-through (no census/touch/TSC); one manifest-free ETW event per site-6\n"
        L"                        stage begin/end (provider {6e1c4a2b-5d3f-4a7e-9b21-c8f0a3d7e514}, Id 1 begin / Id 2 end, UINT32 stage\n"
        L"                        ordinal) to gate a WPR PMC trace to site-6 windows\n");
    say(L"%ls",
        L"  --brain-unit-fatigue  requires brain2; excludes --brain-census/timing/parallel/quiet/unit-shadow and the brain shadows;\n"
        L"                        combines with the other --brain-unit-* options and --brain-s0: S4 per-unit fatigue. One (acc, level) pair\n"
        L"                        per unit generation, initialised from the native unit means and advanced once per stage from the unit's\n"
        L"                        activity (units at rest only; every other unit stays native); admitted men receive the pair instead of\n"
        L"                        running 0x670F40 (brain_unit_policy_words: shared header 0..31, fatigue 32..127)\n"
        L"  --brain-unit-fatigue-shadow  same decision, native fatigue stays; per-man native-vs-unit divergence tables (sets --brain-unit-fatigue)\n"
        L"  --brain-unit-posture, --brain-unit-posture-shadow  S2b per-unit posture (live / shadow; words 128..255)\n"
        L"  --brain-unit-engage, --brain-unit-engage-shadow    S1c/S3 engage + fire latches and S1a/S2a lookups (live / shadow; words 128..255)\n"
        L"  --collide-contact-shadow  requires collide: contact callbacks are planned on pool workers from stage-entry state and each\n"
        L"                        plan is compared with the original callback the owner still runs (collide.contact)\n"
        L"  --collide-contact-workers requires collide; excludes the shadow: same-team contact decisions on pool workers, owner replays\n"
        L"                        tracker/+0x13C/avoidance effects in contact order; other contacts run the original callback in place\n"
        L"  --no-collide-contact-workers  disable live contact workers only; independent contact shadow remains available\n"
        L"  --va-watch            diagnostic: sample process VA (avail, largest free region, VirtualQuery walk) once a second in every\n"
        L"                        phase incl. battle loading; printed every 10 s and as a ring after a crash (va_watch_words). Default off.\n"
        L"  --va-floor-mib N      total free VA floor in MiB (64..512 in 32 MiB steps, or 1024; default 256). Latches LOCO/COLLIDE fallback.\n"
        L"  --va-hole-mib M       largest free VA hole floor in MiB (32..512 in 32 MiB steps; default 128). Latches LOCO/COLLIDE fallback.\n");
    say(L"%ls",
        L"  --alloc-census        diagnostic: process-heap allocation callsite census (alloc_census_words, receipt alloc_census). Default off.\n"
        L"  --alloc-fix           live pathfinder +0x17C waypoint subnode leak reclamation (mode=2 zero-VA alone, mode=3 with --alloc-census;\n"
        L"                        alloc_census_words, receipt alloc_census; implied by --features all unless --no-alloc-fix)\n"
        L"  --no-alloc-fix        opt out of --alloc-fix under --features all\n"
        L"  --arena-release       release pose/scene 1 MB arena blocks at battle teardown and trim 600-frame high-water tails\n"
        L"                        (arena_words, receipt arena; implied by --features all unless --no-arena-release)\n"
        L"  --no-arena-release    opt out of --arena-release under --features all\n"
        L"  --heap-optimize       opt-in HeapOptimizeResources at teardown and <640 MiB watermark (1 Hz GlobalMemoryStatusEx\n"
        L"                        sample even without --va-watch; arena_words, receipt arena). Default off.\n"
        L"  --mounted-officer     GAMEPLAY feature (implied by --features all unless --no-mounted-officer; replays desync vs vanilla): an infantry unit whose unit_stats_land\n"
        L"                        row fills the mount columns (mount_model, mount_entity, mount_animations_table, mount_armour, mount_health) with horse = 0\n"
        L"                        gets exactly one mount for its officer (men[0]). Data decides which units qualify. Redirects the unit constructor call\n"
        L"                        0x531340 to a private constructor clone and the unit visual constructor test at 0x72C9D2 to a gate that still builds the bayonet\n"
        L"                        attachment list for infantry that carry the officer's horse (all restored at stop). Words: mounted_officer_words, receipt mounted_officer.\n"
        L"  --no-mounted-officer  opt out of --mounted-officer under --features all\n"
        L"  --drag-ladder         GAMEPLAY feature (implied by --features all unless --no-drag-ladder; changes the simulation: every multiplayer peer must run the same setting): the player's\n"
        L"                        drag-out formation frontage snaps DOWN to 60-file steps once it exceeds 60 files (<= 60 files is untouched). One detour at the engine's\n"
        L"                        files-per-row function (FilesPerRow 0x642C90) floors its result to a 60-multiple above 60 files, so the blue preview markers, the placement\n"
        L"                        records, the slot generator, the issued order and the formation solver all read the same laddered count by construction. Needs no routed\n"
        L"                        tick. The site verifies the stock bytes first; restored at stop. Words: drag_ladder_words (installed, calls, laddered, passthrough, last files),\n"
        L"                        receipt drag_ladder.\n"
        L"  --no-drag-ladder      opt out of --drag-ladder under --features all\n"
        L"  --wounded[=PCT]       EXPERIMENTAL GAMEPLAY feature (NEVER implied by --features all; changes the simulation: every multiplayer peer must run the same setting): a shot\n"
        L"                        soldier whose death clip carries the stock FACE_DOWN/FACE_UP orientation events enters the engine's own wounded state (front/back injury loops,\n"
        L"                        crawling; categories WOUNDED_* 0x330..0x338, shipped in every man animation table) with probability PCT% (1..100, default 33) instead of freezing\n"
        L"                        as a static corpse. One detour at the kill-path state commit (0x653F1A); deterministic per-death roll; men without FACE-tagged clips (all\n"
        L"                        non-musket/sabre families) are untouched by construction. Untagged death animations are orientation-classified automatically at table build. The site verifies the stock bytes first; restored at stop. Words: wounded_words\n"
        L"                        (installed, calls, eligible, flipped, denied_roll, untagged), receipt wounded.\n"
        L"  --engage-census       opt-in READ-ONLY diagnostic (NEVER implied by --features all; requires a routed tick: profile or a simulation feature): after every\n"
        L"                        routed native tick the tick owner reads the AI units' positions, calls the native is_moving / is_firing / missile-range predicates\n"
        L"                        and records how deep (dM/range) AI infantry walk into their own range before they halt or start firing. One line every 10 s;\n"
        L"                        words: engage_census_words (src/ai/kntwr_engage_census.h), receipt engage_census (counters, histograms, event rows).\n"
        L"  --formation-census[=EVERY] --formation-census-csv FILE  opt-in READ-ONLY diagnostic (NEVER implied by --features all): every EVERY model ticks (default 30)\n"
        L"                        one CSV row per live unit of both alliances: men centroid / RMS spread vs the spread of the formation's slot positions (collapsed =\n"
        L"                        moving, >= 60 men, men_rms < 0.35 x slot_rms), nearest-neighbour spacing, spacing and layout floats; FILE.summary.txt has the counts.\n"
        L"                        With a runtime: in-process (needs a routed tick; calls the engine's own slot generator). With --no-activate: launcher-side\n"
        L"                        ReadProcessMemory census of an unmodified game (no slots; moving = centroid speed > 0.5 m/s). Honours --observe-seconds.\n"
        L"  --formation-census-men  with --formation-census (runtime only): also FILE.men.csv, per-man steering of the first 6 AI + 3 player marching 400+-man units\n"
        L"                        (agent order/path-follower state, move-target position object and its world point, order-node slot object, sampled men + unit aggregates)\n"
        L"  --no-gameplay-patch   diagnostic bisection, needs --no-activate: resume the disk image without gameplay or heap-serialization corrections\n"
        L"  --gameplay-patch-only-runs LIST / --gameplay-patch-skip-runs LIST  diagnostic bisection: write only (or all but) the listed non-header runs of the 103-run\n"
        L"                        gameplay patch (LIST like 14-16,36-38,44); PE layout and the two heap-serialization safety runs are always applied\n"
        L"  --no-d3d9-swap        leave the patch's Direct3DCreate9 swap stock (runs 65, 92: both factory calls -> .aistbl 0x18F3000, which hot-patches\n"
        L"                        one copy loop of an already-loaded, exact-build SysWOW64 d3d9.dll; no-op otherwise). Default: the whole patch is written\n"
        L"  --steam               give the game Steam's app id (SteamAppId / SteamGameId = 34030, kept when already set) so Steam multiplayer,\n"
        L"                        lobbies and the overlay work; Steam must be running. Default ON\n"
        L"  --no-steam            start the game without the Steam app id (the previous default)\n"
        L"  --game-exe NAME       diagnostic: the game executable inside the game folder (default Napoleon.exe; must match the supported stock image)\n"
        L"  --mounted-officer-widen  sets --mounted-officer; the officer's mount also raises the unit radius like a stock cavalry mount (default keeps\n"
        L"                        the infantry spacing)\n"
        L"  --ai-ctrl             experimental controller offload with immediate join (same as ai_ctrl; default off; requires ai)\n"
        L"                        loco = locomotion Stages A/B/C; optional owned grid v2 published at site-13 exit;\n"
        L"                        cannot combine with brain or collide_lod; brain2 v2 can coexist; collide requires --loco-clone --loco-parallel --loco-owned-services and grid\n"
        L"  --loco-clone          loco only: execute admitted movement occurrences through the private clone family (default: observe only, original code)\n"
        L"  --loco-parallel       requires loco and --loco-clone: closed direct-selector movement workers; native services/publication stay owner-only\n"
        L"  --loco-owned-services requires loco, --loco-clone and --loco-parallel: opt-in supported active mover path (owner-prepared sweep/resolve/environment services); unsupported occurrences fall back to the owner\n"
        L"  --loco-quiet          requires --loco-owned-services: low-overhead mode; disables per-service QPC timing, shadow comparisons (even with --loco-shadow) and the all-gates histogram; faults/share/detail counters stay\n"
        L"  --loco-shadow         requires loco and --loco-clone: compare owner-thread sweep/resolve ports, retaining original outputs (ignored under --loco-quiet)\n"
        L"  --loco-grid           requires loco: publish owned soldier grid v2 at site-13 exit (default off); combined collide borrows it without rebuilding\n"
        L"  --loco-grid-verify    requires loco: implies --loco-grid and enables owner-side grid verification\n"
        L"  --loco-grid-incremental requires loco + --loco-grid (or verify): patch the owned grid from the previous stage instead of rebuilding it\n"
        L"                        (bit-identical publication; full rebuild on first build, registry/geometry/rounding change, refusal, large change set);\n"
        L"                        with --loco-grid-verify every stage also rebuilds in full into a shadow store and compares (loco_grid_build_words)\n"
        L"  --loco-relink-shadow  requires loco + --loco-owned-services + --loco-grid: log the site-13 grid relink ops, apply each batch with the\n"
        L"                        cell-partitioned parallel kernel to a private mirror and compare with the native serial services (zero gameplay\n"
        L"                        effect; loco_relink_words, receipt loco.relink); exclusive with --loco-relink-workers\n"
        L"  --loco-relink-workers same requirements: live parallel relink apply; the op log replaces the native grid services, batches are applied\n"
        L"                        on the pool at flush barriers with bit-identical chain order\n"
        L"  --loco-cw-shadow      requires loco + --loco-owned-services: class wrappers 0x132BA04 whose children are all World agents run on\n"
        L"                        workers with proxy children; the owner still runs them natively and compares (zero gameplay effect;\n"
        L"                        loco_cw_words cw_*); exclusive with --loco-cw-workers\n"
        L"  --loco-cw-workers     same requirements: live; the worker result is committed and each child relocation is replayed\n"
        L"                        through native 0x80BAC0 on the owner in worklist order\n"
        L"  --no-loco-cw-workers  disable live class-wrapper workers only; independent CW shadow remains available\n"
        L"  --grid-probation      requires loco + --loco-grid (not ballistic): native cell-head array PAGE_NOACCESS outside the\n"
        L"                        owner's site-13 relink window; every trapping reader is logged (EIP/caller/thread/site),\n"
        L"                        its page restored and resumed (grid_probation_words, receipt loco.grid_probation)\n"
        L"  --grid-census         requires loco: opt-in soldier soft-grid reader census (default off; profile not required)\n"
        L"                        private-clone route calls and proven native reader entries per routed tick; occupancy is separate\n"
        L"                        must be selected before the process first builds resident runtime clones\n");
    say(L"%ls",
        L"  --army-unit-shadow    requires profile or a simulation feature: item 4 Stage A instrumentation of the army per-unit\n"
        L"                        update (sites 18/101/103): per-unit 0x581F30 cost, owner-only reasons, RNG draws, foreign-unit\n"
        L"                        witness, command classes and projected site-18 time (army_unit_words, receipt army_unit);\n"
        L"                        add ai,ai_census to measure planner writes. Also Stage B0 qualification (army_b0_words,\n"
        L"                        receipt army_unit.b0): FSM steps/transitions, formation queue/scratch, recorder pins, RNG\n"
        L"                        member bound, own-state copy, exclusive refusal cost and the Stage B release gates\n"
        L"  --cavalry-orbit       gameplay feature enabled by default and implied by --features all (--no-cavalry-orbit opts out;\n"
        L"                        listing the exclusive ai_async2/brain2 suppresses the implication): cavalry of\n"
        L"                        both sides orbit an explicitly attack-ordered square in periodic small rider melee waves\n"
        L"                        with native eligible mounted fire and immediate native handback (mask bit cavalry_orbit,\n"
        L"                        0x100000; no status row, no logging). Routes its own tick; excludes ai_async2 and brain2\n"
        L"                        (including serial cloned-driver diagnostics); replays desync vs vanilla\n"
        L"  --no-cavalry-orbit    opt out of cavalry_orbit (default set and --features all implication)\n"
        L"  --army-storm-census   requires profile or a simulation feature; exclusive with --army-unit-shadow: opt-in site-18 storm\n"
        L"                        census. Times every 0x581F30 call (sites 101/103), counts units taking the command/formation\n"
        L"                        route, sub-brackets the preparation/FSM/formation calls, and keeps the top-8 storm ticks (site 18\n"
        L"                        > 3 x its running 256-tick median) in army_storm_words (receipt army_storm); the longest unit,\n"
        L"                        route-unit count/us and >=5 ms units per tick go to tick-log slots 110/111. Default off.\n"
        L"  --army-storm-sample-ms N  with --army-storm-census, --profile and --profile-site 18: the sampler admits a\n"
        L"                        sample only once site 18 has been in progress for N ms (1..255), profiling just the storm tails.\n"
        L"  --tick-pcore          requires profile or a simulation feature: on a hybrid CPU the thread executing a routed tick is\n"
        L"                        hard-pinned to the P cores (highest efficiency class) for the tick body and restored afterwards.\n"
        L"                        Placement only; inert on a non-hybrid host. Every tick-log entry carries the core census (flags).\n"
        L"  --no-tick-pcore       opt out of tick P-core placement only; conflicts with --tick-pcore and --tick-core-ab\n"
        L"  --tick-core-ab        measurement only, exclusive with --tick-pcore: even model ticks pinned to P, odd ticks to E cores,\n"
        L"                        so neighbouring ticks measure the in-run E-core penalty (tick-log flags bits 6/7).\n"
        L"  --army-solver-memo    requires profile or a simulation feature (manager-routed tick), exclusive with --army-solver-shadow,\n"
        L"                        compatible with --army-storm-census: the flag=1 formation slot solver (0x502770, reached from the R1 FSM\n"
        L"                        state-enters and the R2 per-tick execute of the assignment command) is replaced by a bit-exact memoised\n"
        L"                        kernel through a dedicated clone chain; any out-of-contract input runs the native solver. Entries, EAX and\n"
        L"                        allocator calls are identical to native; counters in army_solver_words (receipt army_solver). Default off.\n"
        L"  --army-solver-shadow  same chain, native solver authoritative: the kernel re-solves a pre-call copy and the entries/EAX are\n"
        L"                        compared and counted (mismatches in army_solver); native and kernel times per solve/tick/top tables.\n"
        L"  --ai-deferred         with ai,ai_async2: deferred sliced thinks. The planner runs through a private node driver in\n"
        L"                        slices of B costed node calls (generate/child think/whole think; passes free) in the inter-tick\n"
        L"                        window; the next tick start joins only that slice; a finished think is consumed at the first\n"
        L"                        tick start >= admission tick + K; a planner with an outstanding think is refused at site 34\n"
        L"  --ai-deferred-k K     with --ai-deferred: consumption delay in ticks, 1..32 (default 1)\n"
        L"  --ai-deferred-budget B  with --ai-deferred: costed node calls per slice, 1..65535 (default 2)\n"
        );
    say(L"%ls",
        L"  --ai-ctrl-census      needs a routed tick (profile or a simulation feature); excludes ai_ctrl/ai_async2: AI controller scoring\n"
        L"                        batches observed (batches, scorer calls, eligible units, histogram repeats, B44/B41 transitions inside\n"
        L"                        a batch); native always executes (ai_ctrl words, one line)\n"
        L"  --ai-ctrl-histogram   the node scorer's seven-counter histogram is computed once per scoring batch and served from a copy\n"
        L"  --ai-ctrl-geometry    identity/pose/region-distance reuse inside a scoring batch\n"
        L"  --ai-ctrl-verify      with --ai-ctrl-histogram/-geometry: recompute native for every served value; a mismatch returns the\n"
        L"                        native value and latches the feature off\n"
        L"  --ai-prepass-census   needs a routed tick (profile or a simulation feature, ai recommended); excludes ai_async2: AI planner think census on the\n"
        L"                        executing thread (AI worker with ai): child thinks, covered 0x7F1D40 walks (distinct/duplicate keys, gather vs\n"
        L"                        traversal time, 0x80DCF0 polygon vertex histogram), D1 cross-child writes, world-change, think-duration classes;\n"
        L"                        native always executes once (ai_prepass_census row, several lines)\n"
        L"  --ai-presize          behaviour-preserving query-local reserve of the 0x559090 hit-pair buffer (vtable word 0x13247EC); may combine\n"
        L"                        with --ai-prepass-census; needs a routed tick, excludes ai_async2\n"
        L"  --ai-poly-shadow      needs a routed tick, excludes ai_async2/--ai-prepass-census/--ai-poly: exact-kernel shadow. The native 0x80DCF0 OBB/polygon\n"
        L"                        predicate answers; its SSE replacement (src/ai/kntwr_planner_search) is compared bit-for-bit (AL, x87 status, MXCSR);\n"
        L"                        the observer route 0x13376FC+0x40 runs on pure-retarget clones (ai_poly row)\n");
    say(L"%ls",
        L"  --ai-poly             same routing; the replacement answers, native on any guard refusal (counted by reason in the ai_poly row)\n"
        L"  --ai-record-test-shadow  needs --ai-poly or --ai-poly-shadow (--features all implies --ai-poly), excludes --ai-record-test/--ai-prepass-census: the\n"
        L"                        kernel of --ai-poly extended to the ALTERNATE placement delegate 0x13376AC (slot 0x13376EC = 0x6A99E0 -> 0x6A94B0\n"
        L"                        per-record ladder loop), which --ai-poly leaves native. Shadow: native answers every polygon test of that route and\n"
        L"                        the kernel is compared bit-for-bit (AL, x87 status, MXCSR), independent of the --ai-poly mode (ai_record_test row)\n"
        L"  --ai-record-test      same routing; the kernel answers, native on any guard refusal (by reason in the ai_record_test row). Bit-identical;\n"
        L"                        with --ai-spiral-cap-m N the cap also applies on this route (it shares the PS_6C71D0 ladder clone)\n"
        L"  --ai-spiral-census    needs a routed tick, excludes ai_async2: observer placement-ladder census (stage that placed each entry,\n"
        L"                        0x7FCA90 spiral candidates/rings/exits) and fallback 0x7524A0 entries-per-call / 0x82F3A0 same-tick tail\n"
        L"                        counts (ai_spiral row); behaviour unchanged. Combines with the other --ai-prepass/--ai-poly options\n"
        L"  --ai-spiral-cap-m N   AI-ONLY GAMEPLAY DEVIATION. Cap the ladder's last-resort spiral at radius N metres (20..65535; 0 = native\n"
        L"                        unlimited, the default): rings of radius <= N run, then the native not-found exit. A capped spiral places the\n"
        L"                        unit at the projection of its ORIGINAL requested point (possibly obstructed, as native does when a ring leaves\n"
        L"                        the map); it is not left unassigned or retried. Implies --ai-spiral-census\n"
        L"  --ai-claim-once       AI-ONLY GAMEPLAY DEVIATION. One 0x82F3A0 placement recompute per planner fallback claim call instead of one per claimed\n"
        L"                        unit: every unit is still claimed in the same think as native (none is left without owner/orders across a tick), but\n"
        L"                        the controller's placement score (+0x720/+0x758) is recomputed only for the last claimed unit (earlier units hit the\n"
        L"                        native memo gate). Needs a routed tick (e.g. --features all), excludes ai_ctrl/--ai-deferred; combines with\n"
        L"                        --ai-poly and --ai-spiral-census (ai_claim_once row: entries, masked recomputes, refusals, controller-state hash)\n"
        L"  --ai-claim-once-census  the same claim loop WITHOUT the elision (native recomputes) publishing the same controller-state hash: the native\n"
        L"                        reference for comparing hashes against a --ai-claim-once run of the same replay; excludes --ai-claim-once\n");
    say(L"%ls",
        L"  --brain-retarget-jitter  SHARED-SIMULATION GAMEPLAY DEVIATION (both armies, the player included; replays desync vs vanilla; opt-in, NEVER implied by\n"
        L"                        --features all). A soldier whose melee target became invalid this tick no longer re-searches immediately: its\n"
        L"                        search cooldown is set to (agent+0x2C & 0xF) ticks (the engine's own per-man jitter, 0..15), so a target-loss\n"
        L"                        wave of searches spreads over 16 ticks; meanwhile the man has no target (walks to its slot or stands, as in the\n"
        L"                        native 40..55-tick failed-search wait). Forced melee targets (enemy within 3 m), the periodic 64-tick clear and the\n"
        L"                        failed-search cooldown stay native. Needs a routed tick (e.g. --features all) and excludes ai_ctrl and\n"
        L"                        --ai-ctrl-geometry (brain_retarget_jitter row: tracker_calls, losses, jittered, delay_sum)\n"
        L"  --brain-target-cull   bit-exact host mirror of soldier-brain melee target search 0x553420 (src/brain/kntwr_target_cull.h); no gameplay\n"
        L"                        change. Needs a routed tick, excludes ai_ctrl/--ai-ctrl-geometry and --brain-target-cull-shadow\n"
        L"  --brain-target-cull-shadow  native answers every target search while the host replacement runs beside it and is compared (mismatch\n"
        L"                        counters in the brain_target_cull row); excludes --brain-target-cull\n"
        L"  --workers N           worker threads 1..16 (default 8; pool supports 31, keep <= hardware threads - 2 for the tick and render threads)\n"
        L"  --poll-ms N           runtime monitor poll interval 10..1000 (default 100)\n"
        L"  --profile-site N      with profile, grid_census or ai_census: restrict sampling to timed site N (does not enable sampling)\n"
        L"  --collide-lod-m N      far-unit surface separation in world metres, 1..100000 (default 40)\n");
    say(L"%ls",
        L"  --collide-census      with profile: enable costly per-pair collision timers (default off; profile times site 5 without it)\n"
        L"  --observe-seconds N   stop monitoring after N seconds (default: until exit)\n"
        L"  --exit-game-after-observe  after the bound, stop the runtime (confirmed STOPPED, up to 60 s while it\n"
        L"                        progresses), then close ONLY this launch (WM_CLOSE, kill after 10 s); if the stop\n"
        L"                        is not confirmed, no WM_CLOSE is sent: the launched game is terminated (exit 11)\n"
        L"  --inject-timeout N    seconds to wait for the game loader (default 120)\n"
        L"  --receipt FILE        JSON status every second and final outcome (atomic replace)\n"
        L"                        profile, grid_census or ai_census also writes FILE.profile.bin at observation end (before exit/stop)\n"
        L"  --tick-log FILE       retain every observed tick (10 ms launcher polls, maximum 200000 entries)\n"
        L"                        write KNTWRTLOG binary at observation end; receipt includes summary and loss count\n"
        L"  --no-activate         launch the game without installing the runtime\n"
        L"  --check               read-only: resolve the game folder (saved config, then every Steam library; never a picker),\n"
        L"                        print it with workers and the Steam state; no dialog, nothing started, nothing saved\n"
        L"  --validate-only       same as --check\n"
        L"  --setup               open the folder picker, validate Napoleon.exe and the runtime DLL, save the folder to the configuration and exit;\n"
        L"                        never starts the game; cannot be combined with --game, --check/--validate-only or --no-launch\n"
        L"  --no-launch           validate and save the resolved game folder to the configuration, but start nothing;\n"
        L"                        never a folder picker, and no dialog when output is redirected (automation-safe)\n"
        L"  --allow-concurrent    diagnostic: allow a second game instance (replay verification); timings are not comparable between concurrent runs\n"
        L"  --focus               allow normal game-window activation (default: no activation requested)\n"
        L"  --no-focus            explicitly keep the default nonactivating startup (best effort)\n"
        L"  --console             development: attach to the parent terminal or create a console window for launcher output\n"
        L"                        (the default for a no-argument run, i.e. a double-click; a run from a terminal shows its output there either way)\n"
        L"  --no-console          skip even the inherited-terminal attach, dropping terminal output (wrappers only)\n"
        L"  --version             print KNTWR <version> and exit before any game lookup\n"
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
        if (_wcsicmp(tok, L"all") == 0) bit = KNTWR_ALL;
        for (i = 0; i < NFEATURES; ++i)
            if (_wcsicmp(tok, k_features[i].name) == 0) { bit = k_features[i].bit; break; }
        if (!bit) {
            errsay(L"unknown --features item \"%ls\"; use all,path,formation,ballistics,ai,ai_ctrl,batch64,brain2,visual,collide,collide_lod,loco,profile,brain,grid_census,ai_census,ai_async2,army_unit_shadow,cavalry_orbit.\n", tok);
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

/* Returns 0 ok, 1 help, 2 version, -1 error.  2 is not a process exit code (process exit 2 is unsupported game). */
static int parse_args(int argc, wchar_t **argv, Options *o)
{
    int i;
    uint32_t feature_options = 0;
    o->mask = KNTWR_ALL | KNTWR_CAVALRY_ORBIT;
    o->workers = 8;
    o->poll_ms = 100;
    o->ai_deferred_k = KNTWR_AI_DEFERRED_DEFAULT_K;
    o->ai_deferred_budget = KNTWR_AI_DEFERRED_DEFAULT_BUDGET;
    o->ai_ctrl_flags = 0;
    o->ai_claim_once = FALSE;
    o->ai_claim_once_census = FALSE;
    o->brain_target_cull_shadow = FALSE;
    o->brain_target_cull = FALSE;
    o->brain_retarget_jitter = FALSE;
    o->ai_prepass_flags = 0;
    o->collide_lod_m = 40;
    o->inject_timeout_s = 120;
    o->activate = TRUE;
    o->steam = TRUE;   /* shipping default; --no-steam opts out */
    o->no_launch = FALSE;
    o->no_steam = FALSE;
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
        else if (!wcscmp(name, L"--version")) {
            if (val) { errsay(L"--version takes no value.\n"); return -1; }
            return 2;
        }
        else if (!wcscmp(name, L"--console")) { /* consumed in wmain before any console is acquired */ }
        else if (!wcscmp(name, L"--no-console")) { /* consumed in wmain before any console is acquired */ }
        else if (!wcscmp(name, L"--no-activate")) o->activate = FALSE;
        else if (!wcscmp(name, L"--collide-census")) o->collide_census = TRUE;
        else if (!wcscmp(name, L"--profile")) feature_options |= KNTWR_PROFILE;
        else if (!wcscmp(name, L"--grid-census")) feature_options |= KNTWR_GRID_CENSUS;
        else if (!wcscmp(name, L"--army-unit-shadow")) feature_options |= KNTWR_ARMY_UNIT_SHADOW;
        else if (!wcscmp(name, L"--cavalry-orbit")) feature_options |= KNTWR_CAVALRY_ORBIT;
        else if (!wcscmp(name, L"--no-cavalry-orbit")) o->no_cavalry_orbit = TRUE;
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
        else if (!wcscmp(name, L"--brain-s0")) o->brain_s0 = TRUE;
        else if (!wcscmp(name, L"--brain-locality")) o->brain_locality = TRUE;
        else if (!wcscmp(name, L"--brain-locality-warm")) o->brain_locality = o->brain_locality_warm = TRUE;
        else if (!wcscmp(name, L"--brain-locality-prefetch")) o->brain_locality = o->brain_locality_prefetch = TRUE;
        else if (!wcscmp(name, L"--brain-locality-prefetch2")) o->brain_locality = o->brain_locality_prefetch2 = TRUE;
        else if (!wcscmp(name, L"--brain-locality-mark")) o->brain_locality = o->brain_locality_mark = TRUE;
        else if (!wcscmp(name, L"--brain-unit-fatigue")) o->brain_unit_fatigue = TRUE;
        else if (!wcscmp(name, L"--brain-unit-fatigue-shadow")) o->brain_unit_fatigue = o->brain_unit_fatigue_shadow = TRUE;
        else if (!wcscmp(name, L"--brain-unit-posture")) o->brain_unit_posture = TRUE;
        else if (!wcscmp(name, L"--brain-unit-posture-shadow")) o->brain_unit_posture = o->brain_unit_posture_shadow = TRUE;
        else if (!wcscmp(name, L"--brain-unit-engage")) o->brain_unit_engage = TRUE;
        else if (!wcscmp(name, L"--brain-unit-engage-shadow")) o->brain_unit_engage = o->brain_unit_engage_shadow = TRUE;
        else if (!wcscmp(name, L"--ai-ctrl-census")) o->ai_ctrl_flags |= KNTWR_AI_CTRL_CENSUS;
        else if (!wcscmp(name, L"--ai-ctrl-histogram")) o->ai_ctrl_flags |= KNTWR_AI_CTRL_HISTOGRAM;
        else if (!wcscmp(name, L"--ai-ctrl-geometry")) o->ai_ctrl_flags |= KNTWR_AI_CTRL_GEOMETRY;
        else if (!wcscmp(name, L"--ai-ctrl-verify")) o->ai_ctrl_flags |= KNTWR_AI_CTRL_VERIFY;
        else if (!wcscmp(name, L"--ai-prepass-census")) o->ai_prepass_flags |= KNTWR_AI_PREPASS_CENSUS;
        else if (!wcscmp(name, L"--ai-presize")) o->ai_prepass_flags |= KNTWR_AI_PRESIZE;
        else if (!wcscmp(name, L"--ai-poly-shadow")) o->ai_prepass_flags |= KNTWR_AI_POLY_SHADOW;
        else if (!wcscmp(name, L"--ai-poly")) o->ai_prepass_flags |= KNTWR_AI_POLY;
        else if (!wcscmp(name, L"--ai-record-test-shadow")) o->ai_prepass_flags |= KNTWR_AI_RECORD_TEST_SHADOW;
        else if (!wcscmp(name, L"--ai-record-test")) o->ai_prepass_flags |= KNTWR_AI_RECORD_TEST;
        else if (!wcscmp(name, L"--ai-spiral-census")) o->ai_prepass_flags |= KNTWR_AI_SPIRAL_CENSUS;
        else if (!wcscmp(name, L"--collide-contact-shadow")) o->collide_contact_shadow = TRUE;
        else if (!wcscmp(name, L"--collide-contact-workers")) o->collide_contact_workers = TRUE;
        else if (!wcscmp(name, L"--no-collide-contact-workers")) o->no_collide_contact_workers = TRUE;
        else if (!wcscmp(name, L"--va-watch")) o->va_watch = TRUE;
        else if (!wcscmp(name, L"--army-storm-census")) o->army_storm_census = TRUE;
        else if (!wcscmp(name, L"--tick-pcore")) o->tick_pcore = TRUE;
        else if (!wcscmp(name, L"--no-tick-pcore")) o->no_tick_pcore = TRUE;
        else if (!wcscmp(name, L"--tick-core-ab")) o->tick_core_ab = TRUE;
        else if (!wcscmp(name, L"--army-solver-memo")) o->army_solver_memo = TRUE;
        else if (!wcscmp(name, L"--army-solver-shadow")) o->army_solver_shadow = TRUE;
        else if (!wcscmp(name, L"--alloc-census")) o->alloc_census = TRUE;
        else if (!wcscmp(name, L"--alloc-fix")) o->alloc_fix = TRUE;
        else if (!wcscmp(name, L"--no-alloc-fix")) o->no_alloc_fix = TRUE;
        else if (!wcscmp(name, L"--arena-release")) o->arena_release = TRUE;
        else if (!wcscmp(name, L"--no-arena-release")) o->no_arena_release = TRUE;
        else if (!wcscmp(name, L"--heap-optimize")) o->heap_optimize = TRUE;
        else if (!wcscmp(name, L"--mounted-officer")) o->mounted_officer = TRUE;
        else if (!wcscmp(name, L"--no-mounted-officer")) o->no_mounted_officer = TRUE;
        else if (!wcscmp(name, L"--engage-census")) o->engage_census = TRUE;
        else if (!wcscmp(name, L"--formation-census")) {
            o->formation_census = TRUE;
            if (val && !parse_uint(val, 1, 10000, &o->formation_census_every)) { errsay(L"--formation-census=EVERY must be 1..10000 (model ticks).\n"); return -1; }
        }
        else if (!wcscmp(name, L"--formation-census-men")) o->formation_census_men = TRUE;
        else if (!wcscmp(name, L"--formation-census-csv")) {
            NEEDVAL();
            if (!val[0] || wcslen(val) >= MAXP || wcschr(val, L'"')) { errsay(L"--formation-census-csv needs a nonempty path without double quotes.\n"); return -1; }
            wcscpy_s(o->formation_census_csv, MAXP, val);
        }
        else if (!wcscmp(name, L"--no-gameplay-patch")) o->no_gameplay_patch = TRUE;
        else if (!wcscmp(name, L"--no-d3d9-swap")) o->no_d3d9_swap = TRUE;
        else if (!wcscmp(name, L"--steam")) o->steam = TRUE;
        else if (!wcscmp(name, L"--gameplay-patch-only-runs") || !wcscmp(name, L"--gameplay-patch-skip-runs")) {
            const uint32_t want = name[wcslen(L"--gameplay-patch-")] == L'o' ? KNTWR_GP_ONLY : KNTWR_GP_SKIP;
            char narrow[256];
            NEEDVAL();
            if (o->gp_filter.mode != KNTWR_GP_ALL && o->gp_filter.mode != want) { errsay(L"--gameplay-patch-only-runs and --gameplay-patch-skip-runs are exclusive.\n"); return -1; }
            if (WideCharToMultiByte(CP_ACP, 0, val, -1, narrow, (int)sizeof narrow, NULL, NULL) <= 0 || kntwr_gp_filter_parse(narrow, &o->gp_filter) != 0) {
                errsay(L"%ls needs a run list like 14-16,36-38,44 (runs 0..127 of the patch).\n", name);
                return -1;
            }
            o->gp_filter.mode = want;
            o->gp_filter_listed = TRUE;
        }
        else if (!wcscmp(name, L"--game-exe")) {
            NEEDVAL();
            if (!val[0] || wcspbrk(val, L"\\/:\"")) { errsay(L"--game-exe takes a bare file name inside the game folder.\n"); return -1; }
            wcscpy_s(o->game_exe, MAXP, val);
            g_game_exe = o->game_exe;
        }
        else if (!wcscmp(name, L"--mounted-officer-widen")) { o->mounted_officer_widen = TRUE; o->mounted_officer = TRUE; }
        else if (!wcscmp(name, L"--drag-ladder")) o->drag_ladder = TRUE;
        else if (!wcscmp(name, L"--no-drag-ladder")) o->no_drag_ladder = TRUE;
        else if (!wcscmp(name, L"--wounded")) {
            o->wounded = TRUE;
            o->wounded_pct = KNTWR_WOUNDED_PCT_DEFAULT;
            if (val && !parse_uint(val, 1, 100, &o->wounded_pct)) { errsay(L"--wounded=PCT must be 1..100 (percent of FACE-tagged shot deaths that go wounded).\n"); return -1; }
        }
        else if (!wcscmp(name, L"--army-storm-sample-ms")) {
            NEEDVAL();
            if (!parse_uint(val, 1, 255, &o->army_storm_sample_ms)) { errsay(L"--army-storm-sample-ms must be 1..255.\n"); return -1; }
        }
        else if (!wcscmp(name, L"--va-floor-mib")) {
            NEEDVAL();
            if (!parse_uint(val, 64, 1024, &o->va_floor_mib) || (o->va_floor_mib % KNTWR_VA_FLOOR_UNIT_MIB != 0) ||
                (o->va_floor_mib > 512 && o->va_floor_mib != 1024)) {
                errsay(L"--va-floor-mib must be 64..512 in multiples of 32, or 1024.\n");
                return -1;
            }
        }
        else if (!wcscmp(name, L"--va-hole-mib")) {
            NEEDVAL();
            if (!parse_uint(val, 32, 512, &o->va_hole_mib) || (o->va_hole_mib % KNTWR_VA_FLOOR_UNIT_MIB != 0)) {
                errsay(L"--va-hole-mib must be 32..512 in multiples of 32.\n");
                return -1;
            }
        }
        else if (!wcscmp(name, L"--loco-quiet")) o->loco_quiet = TRUE;
        else if (!wcscmp(name, L"--loco-grid")) o->loco_grid = TRUE;
        else if (!wcscmp(name, L"--loco-grid-verify")) { o->loco_grid_verify = TRUE; o->loco_grid = TRUE; }
        else if (!wcscmp(name, L"--loco-grid-incremental")) o->loco_grid_incremental = TRUE;
        else if (!wcscmp(name, L"--grid-probation")) o->grid_probation = TRUE;
        else if (!wcscmp(name, L"--loco-relink-shadow")) o->loco_relink_shadow = TRUE;
        else if (!wcscmp(name, L"--loco-relink-workers")) o->loco_relink_workers = TRUE;
        else if (!wcscmp(name, L"--loco-cw-shadow")) o->loco_cw_shadow = TRUE;
        else if (!wcscmp(name, L"--loco-cw-workers")) o->loco_cw_workers = TRUE;
        else if (!wcscmp(name, L"--no-loco-cw-workers")) o->no_loco_cw_workers = TRUE;
        else if (!wcscmp(name, L"--loco-shadow")) o->loco_shadow = TRUE;
        else if (!wcscmp(name, L"--ai-ctrl")) feature_options |= KNTWR_AI_CTRL;
        else if (!wcscmp(name, L"--check") || !wcscmp(name, L"--validate-only")) o->validate_only = TRUE;
        else if (!wcscmp(name, L"--no-launch")) o->no_launch = TRUE;
        else if (!wcscmp(name, L"--setup")) o->setup = TRUE;
        else if (!wcscmp(name, L"--no-steam")) o->steam = FALSE;
        else if (!wcscmp(name, L"--allow-concurrent")) o->allow_concurrent = TRUE;
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
            if (!parse_uint(val, 1, 16, &o->workers)) { errsay(L"--workers must be 1..16.\n"); return -1; }
        } else if (!wcscmp(name, L"--ai-deferred")) {
            o->ai_deferred = TRUE;
        } else if (!wcscmp(name, L"--ai-deferred-k")) {
            NEEDVAL();
            if (!parse_uint(val, 1, KNTWR_AI_DEFERRED_MAX_K, &o->ai_deferred_k)) { errsay(L"--ai-deferred-k must be 1..%u.\n", KNTWR_AI_DEFERRED_MAX_K); return -1; }
        } else if (!wcscmp(name, L"--ai-deferred-budget")) {
            NEEDVAL();
            if (!parse_uint(val, 1, 65535, &o->ai_deferred_budget)) { errsay(L"--ai-deferred-budget must be 1..65535.\n"); return -1; }
        } else if (!wcscmp(name, L"--poll-ms")) {
            NEEDVAL();
            if (!parse_uint(val, 10, 1000, &o->poll_ms)) { errsay(L"--poll-ms must be 10..1000.\n"); return -1; }
        } else if (!wcscmp(name, L"--collide-lod-m")) {
            NEEDVAL();
            if (!parse_uint(val, 1, 100000, &o->collide_lod_m)) { errsay(L"--collide-lod-m must be 1..100000.\n"); return -1; }
        } else if (!wcscmp(name, L"--ai-claim-once")) {
            o->ai_claim_once = TRUE;
        } else if (!wcscmp(name, L"--ai-claim-once-census")) {
            o->ai_claim_once_census = TRUE;
        } else if (!wcscmp(name, L"--brain-target-cull-shadow")) {
            o->brain_target_cull_shadow = TRUE;
        } else if (!wcscmp(name, L"--brain-target-cull")) {
            o->brain_target_cull = TRUE;
        } else if (!wcscmp(name, L"--brain-retarget-jitter")) {
            o->brain_retarget_jitter = TRUE;
        } else if (!wcscmp(name, L"--ai-spiral-cap-m")) {
            uint32_t cap;
            NEEDVAL();
            if (!parse_uint(val, 0, KNTWR_AI_SPIRAL_CAP_MASK >> KNTWR_AI_SPIRAL_CAP_SHIFT, &cap) || (cap && cap < KNTWR_AI_SPIRAL_CAP_MIN_M)) {
                errsay(L"--ai-spiral-cap-m must be 0 (native unlimited) or 20..65535 (the first spiral ring, radius 20 m, always runs).\n");
                return -1;
            }
            o->ai_prepass_flags = (o->ai_prepass_flags & ~KNTWR_AI_SPIRAL_CAP_MASK) | (cap << KNTWR_AI_SPIRAL_CAP_SHIFT);
        } else if (!wcscmp(name, L"--profile-site")) {
            uint32_t site;
            NEEDVAL();
            if (!parse_uint(val, 0, KNTWR_TIMED_SITES - 1, &site)) { errsay(L"--profile-site must be 0..%u.\n", KNTWR_TIMED_SITES - 1); return -1; }
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
    /* Check explicit contradictions before adding defaults, independent of argument order. */
    if (o->no_tick_pcore && (o->tick_pcore || o->tick_core_ab)) {
        errsay(L"--no-tick-pcore conflicts with --tick-pcore and --tick-core-ab.\n");
        return -1;
    }
    if (o->no_loco_cw_workers && o->loco_cw_workers) {
        errsay(L"--loco-cw-workers and --no-loco-cw-workers are exclusive.\n");
        return -1;
    }
    if (o->no_collide_contact_workers && o->collide_contact_workers) {
        errsay(L"--collide-contact-workers and --no-collide-contact-workers are exclusive.\n");
        return -1;
    }
    /* The shipping set implies its verified default switches (dn-cwlive2 reference stack).
       Positive-only CLI keeps its legacy all-or-explicit bundle. New diagnostic opt-outs
       retain the bundle even alongside independent positives; explicit shadow modes replace
       only their live counterpart. No feature-mask changes are needed. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL &&
        (o->no_tick_pcore || o->no_loco_cw_workers || o->no_collide_contact_workers ||
         (!o->loco_clone && !o->loco_parallel && !o->loco_shadow && !o->loco_owned && !o->loco_quiet &&
          !o->loco_grid && !o->loco_grid_verify && !o->loco_grid_incremental && !o->grid_probation &&
          !o->loco_relink_shadow && !o->loco_relink_workers && !o->loco_cw_shadow && !o->loco_cw_workers &&
          !o->collide_contact_shadow && !o->collide_contact_workers))) {
        o->loco_clone = TRUE; o->loco_parallel = TRUE; o->loco_owned = TRUE; o->loco_quiet = TRUE;
        o->loco_grid = TRUE; o->loco_grid_incremental = TRUE;
        if (!o->no_loco_cw_workers && !o->loco_cw_shadow) o->loco_cw_workers = TRUE;
        if (!o->no_collide_contact_workers && !o->collide_contact_shadow) o->collide_contact_workers = TRUE;
    }
    /* The shipping set also implies the live polygon kernel (--ai-poly; dp-polylive2 S=2.98, 0 mismatches).
       An explicit --ai-poly-shadow / --ai-prepass-census or the ai_async2 feature opts out. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !(o->mask & KNTWR_AI_ASYNC2) &&
        !(o->ai_prepass_flags & (KNTWR_AI_POLY_SHADOW | KNTWR_AI_POLY | KNTWR_AI_PREPASS_CENSUS)))
        o->ai_prepass_flags |= KNTWR_AI_POLY;
    /* The shipping set also implies P-core placement of the tick thread (--tick-pcore; ta-pc: perf bad mean tick
       61.5 -> 54.6 ms, p90 97 -> 74, borodino p99 -30 ms; inert on a non-hybrid host). --tick-core-ab / --no-tick-pcore opt out. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->tick_core_ab && !o->no_tick_pcore) o->tick_pcore = TRUE;
    /* The shipping set also implies the bit-exact slot solver kernel (--army-solver-memo; sv-memo4: perf bad storm-tick
       site 18 2306 -> 473 ms, ticks >300 ms 5 -> 1; 0 mismatches over 2132 live shadow solves). --army-solver-shadow opts out. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->army_solver_shadow) o->army_solver_memo = TRUE;
    /* The shipping set also implies the two planner-tail levers (dx-gate, perf bad: tick p99 132 -> 88 ms, max 618 -> 283, ticks >150 ms
       28 -> 6, planner sum 26.9 -> 13.7 s; borodino unchanged):
       - --ai-record-test: the alternate placement delegate 0x13376AC routed into the bit-exact poly kernel (rt-shadow: 304,318 compares,
         0 mismatches). Needs the poly kernel live, so it follows --ai-poly; --ai-record-test-shadow opts out.
       - --ai-claim-once (AI-only deviation, user-approved): one placement recompute per fallback claim call (controller-state hash equal
         to the native-recompute census over 3000 multi-entry calls). --ai-claim-once-census, ai_ctrl, --ai-deferred opt out. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && (o->ai_prepass_flags & KNTWR_AI_POLY) && !(o->ai_prepass_flags & KNTWR_AI_RECORD_TEST_SHADOW))
        o->ai_prepass_flags |= KNTWR_AI_RECORD_TEST;
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !(o->mask & KNTWR_AI_CTRL) && !o->ai_claim_once_census && !o->ai_deferred)
        o->ai_claim_once = TRUE;
    /* The shipping set also implies the bit-exact melee target-search replacement (--brain-target-cull; tc-shadow/tc-shadow2:
       4.7 M compares, 0 mismatches; frontier: brain >80 ms 21 ticks -> 0, brain max 168 -> 49 ms, mean brain -2.4 ms/tick;
       perf bad / waterloo unchanged at p50). --brain-target-cull-shadow, --ai-ctrl-geometry and ai_ctrl opt out.
       --brain-retarget-jitter (NO-GO as a lever, behaviour change) is never implied. */
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !(o->mask & KNTWR_AI_CTRL) && !o->brain_target_cull_shadow &&
        !(o->ai_ctrl_flags & KNTWR_AI_CTRL_GEOMETRY))
        o->brain_target_cull = TRUE;
    /* The shipping set also implies pathfinder +0x17C waypoint subnode leak reclamation
       (--alloc-fix; lh-fix/lh-fix600: 3.00 M nodes / 336.3 MiB reclaimed in 1800 s, non-arena heap leak slope
       11.35 -> 0.11 MiB/min (-99.0%), +311 MiB avail VA at 1800 s, 0 B VirtualAlloc and 0 hooks in mode 2,
       0 faults). --no-alloc-fix opts out; --alloc-census stays opt-in (combines with all as mode 3). */
    if (o->alloc_fix && o->no_alloc_fix) {
        errsay(L"--alloc-fix and --no-alloc-fix are exclusive.\n");
        return -1;
    }
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->no_alloc_fix)
        o->alloc_fix = TRUE;
    /* The shipping set also implies pose/scene 1 MB arena release + 600-frame high-water tail trim
       (--arena-release; lever4-arena: 25 blocks / 23.8 MiB trimmed in-battle + 33 blocks / 31.5 MiB released
       at stop, +49 MiB avail VA at 600 s, 0 faults). --no-arena-release opts out; --heap-optimize stays opt-in. */
    if (o->arena_release && o->no_arena_release) {
        errsay(L"--arena-release and --no-arena-release are exclusive.\n");
        return -1;
    }
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->no_arena_release)
        o->arena_release = TRUE;
    /* The shipping set also implies the mounted officer (user decision 2026-10-21; infantry spacing unless --mounted-officer-widen).
       --no-mounted-officer opts out. */
    if (o->mounted_officer && o->no_mounted_officer) {
        errsay(L"--mounted-officer / --mounted-officer-widen and --no-mounted-officer are exclusive.\n");
        return -1;
    }
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->no_mounted_officer)
        o->mounted_officer = TRUE;
    /* The shipping set also implies the drag ladder (user decision 2026-10-30; GAMEPLAY change: drag-out frontage snaps down to
       60-file steps above 60 files; every multiplayer peer must run the same setting). --no-drag-ladder opts out. */
    if (o->drag_ladder && o->no_drag_ladder) {
        errsay(L"--drag-ladder and --no-drag-ladder are exclusive.\n");
        return -1;
    }
    if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !o->no_drag_ladder)
        o->drag_ladder = TRUE;
    /* The shipping set (and --features all) implies the cavalry orbit (user decision 2026-10-31; GAMEPLAY change: cavalry of
       both sides orbit an attack-ordered square; replays desync vs vanilla). --no-cavalry-orbit opts out (clears the default
       too); ai_async2 and brain2 (exclusive with the orbit) suppress the implication rather than erroring, so
       --features all,ai_async2 keeps working. An explicit --cavalry-orbit still errors against them below. */
    if ((feature_options & KNTWR_CAVALRY_ORBIT) && o->no_cavalry_orbit) {
        errsay(L"--cavalry-orbit and --no-cavalry-orbit are exclusive.\n");
        return -1;
    }
    if (o->no_cavalry_orbit)
        o->mask &= ~KNTWR_CAVALRY_ORBIT;
    else if ((o->mask & KNTWR_ALL) == KNTWR_ALL && !(feature_options & KNTWR_CAVALRY_ORBIT) &&
             !(o->mask & (KNTWR_AI_ASYNC2 | KNTWR_BRAIN2)))
        o->mask |= KNTWR_CAVALRY_ORBIT;
    if ((o->mask & KNTWR_GRID_CENSUS) && !(o->mask & KNTWR_LOCO)) {
        errsay(L"--grid-census (grid_census) requires --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if ((o->mask & KNTWR_AI_CENSUS) && !(o->mask & KNTWR_AI_ASYNC)) {
        errsay(L"ai_census requires --features ai (or a feature list containing ai).\n");
        return -1;
    }
    if ((o->mask & KNTWR_ARMY_UNIT_SHADOW) &&
        !(o->mask & (KNTWR_PROFILE | KNTWR_PATH | KNTWR_FORMATION | KNTWR_BALLISTICS | KNTWR_AI_ASYNC | KNTWR_BRAIN2 |
                     KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
        errsay(L"--army-unit-shadow needs a routed tick: add profile or a simulation feature (e.g. --features ai,profile).\n");
        return -1;
    }
    if ((o->mask & KNTWR_CAVALRY_ORBIT) && (o->mask & KNTWR_AI_ASYNC2)) {
        errsay(L"--cavalry-orbit and ai_async2 are exclusive: the orbit owner epoch is never speculative copies or inter-tick AI.\n");
        return -1;
    }
    if ((o->mask & KNTWR_CAVALRY_ORBIT) && (o->mask & KNTWR_BRAIN2)) {
        errsay(L"--cavalry-orbit excludes brain2: cloned driver callsites and speculative receivers are not supported.\n");
        return -1;
    }
    if ((o->mask & KNTWR_AI_ASYNC2) && (!(o->mask & KNTWR_AI_ASYNC) || (o->mask & (KNTWR_AI_CTRL | KNTWR_AI_CENSUS)))) {
        errsay(L"ai_async2 requires --features ai and excludes ai_ctrl and ai_census (shared worker, site 33 and slots).\n");
        return -1;
    }
    if (o->ai_deferred && !(o->mask & KNTWR_AI_ASYNC2)) {
        errsay(L"--ai-deferred requires --features ai,ai_async2 (it is a schedule of the ai_async2 machinery; ai_ctrl and ai_census stay excluded).\n");
        return -1;
    }
    if (((o->ai_ctrl_flags & KNTWR_AI_CTRL_CENSUS) && (o->ai_ctrl_flags & (KNTWR_AI_CTRL_HISTOGRAM | KNTWR_AI_CTRL_GEOMETRY))) ||
        ((o->ai_ctrl_flags & KNTWR_AI_CTRL_VERIFY) && !(o->ai_ctrl_flags & (KNTWR_AI_CTRL_HISTOGRAM | KNTWR_AI_CTRL_GEOMETRY))) ||
        (o->ai_ctrl_flags && (o->mask & (KNTWR_AI_CTRL | KNTWR_AI_ASYNC2)))) {
        errsay(L"--ai-ctrl-census is shadow-only (excludes -histogram/-geometry); --ai-ctrl-verify needs -histogram or -geometry; "
               L"every --ai-ctrl-* excludes the ai_ctrl and ai_async2 features.\n");
        return -1;
    }
    if ((o->ai_claim_once || o->ai_claim_once_census) && ((o->ai_claim_once && o->ai_claim_once_census) || (o->mask & KNTWR_AI_CTRL) || o->ai_deferred ||
                             !(o->mask & (KNTWR_PROFILE | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT)))) {
        errsay(L"--ai-claim-once / --ai-claim-once-census are exclusive, need a routed tick (add profile or a simulation feature, e.g. --features all) "
               L"and exclude the ai_ctrl feature and --ai-deferred.\n");
        return -1;
    }
    if ((o->brain_target_cull || o->brain_target_cull_shadow || o->brain_retarget_jitter) &&
        ((o->brain_target_cull && o->brain_target_cull_shadow) || (o->ai_ctrl_flags & KNTWR_AI_CTRL_GEOMETRY) || (o->mask & KNTWR_AI_CTRL) ||
         !(o->mask & (KNTWR_PROFILE | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT)))) {
        errsay(L"--brain-target-cull / --brain-target-cull-shadow / --brain-retarget-jitter need a routed tick (add profile or a simulation feature, e.g. --features all), "
               L"exclude the ai_ctrl feature and --ai-ctrl-geometry; --brain-target-cull and --brain-target-cull-shadow are exclusive.\n");
        return -1;
    }
    if (o->ai_prepass_flags && (o->mask & KNTWR_AI_ASYNC2)) {
        errsay(L"--ai-prepass-census / --ai-presize / --ai-poly* / --ai-spiral-* exclude the ai_async2 feature (its think runs on private clones outside a site-34 scope).\n");
        return -1;
    }
    if (((o->ai_prepass_flags & KNTWR_AI_POLY_SHADOW) && (o->ai_prepass_flags & KNTWR_AI_POLY)) ||
        ((o->ai_prepass_flags & KNTWR_AI_PREPASS_CENSUS) && (o->ai_prepass_flags & (KNTWR_AI_POLY_SHADOW | KNTWR_AI_POLY)))) {
        errsay(L"--ai-poly-shadow, --ai-poly and --ai-prepass-census are mutually exclusive (the census perturbs timing; shadow and live are separate gates).\n");
        return -1;
    }
    if (((o->ai_prepass_flags & KNTWR_AI_RECORD_TEST_SHADOW) && (o->ai_prepass_flags & KNTWR_AI_RECORD_TEST)) ||
        ((o->ai_prepass_flags & KNTWR_AI_RECORD_TEST_BITS) && !(o->ai_prepass_flags & (KNTWR_AI_POLY_SHADOW | KNTWR_AI_POLY)))) {
        errsay(L"--ai-record-test-shadow and --ai-record-test are mutually exclusive and need --ai-poly or --ai-poly-shadow (--features all implies --ai-poly; "
               L"an explicit --ai-prepass-census opts out of it).\n");
        return -1;
    }
    if (o->army_storm_census &&
        !(o->mask & (KNTWR_PROFILE | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
        errsay(L"--army-storm-census needs the manager-routed tick: add profile, ai, brain2, collide, collide_lod or loco (e.g. --features ai,profile).\n");
        return -1;
    }
    if (o->army_storm_census && (o->mask & KNTWR_ARMY_UNIT_SHADOW)) {
        errsay(L"--army-storm-census and --army-unit-shadow are exclusive (both bind sites 101/103).\n");
        return -1;
    }
    /* The gated sampler is generic in the runtime (entry QPC of the selected --profile-site); the launcher admits site 18
       (with the storm census) and site 34 (planner think tails, no census needed). */
    if (o->army_storm_sample_ms &&
        (!(o->mask & KNTWR_PROFILE) || (o->profile_site != 7u && o->profile_site != 19u && o->profile_site != 35u) || (o->profile_site == 19u && !o->army_storm_census))) {
        errsay(L"--army-storm-sample-ms requires --profile (or a feature list containing profile) and --profile-site 18 (with --army-storm-census), --profile-site 34 or --profile-site 6.\n");
        return -1;
    }
    if ((o->tick_pcore || o->tick_core_ab) &&
        !(o->mask & (KNTWR_PROFILE | KNTWR_PATH | KNTWR_FORMATION | KNTWR_BALLISTICS | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
        errsay(L"--tick-pcore/--tick-core-ab need a routed tick: add profile or a simulation feature (e.g. --features all).\n");
        return -1;
    }
    if (o->engage_census &&
        !(o->mask & (KNTWR_PROFILE | KNTWR_PATH | KNTWR_FORMATION | KNTWR_BALLISTICS | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
        errsay(L"--engage-census needs a routed tick: add profile or a simulation feature (e.g. --features all).\n");
        return -1;
    }
    if (o->formation_census) {
        if (!o->formation_census_csv[0]) { errsay(L"--formation-census needs --formation-census-csv FILE.\n"); return -1; }
        if (o->activate && !(o->mask & (KNTWR_PROFILE | KNTWR_PATH | KNTWR_FORMATION | KNTWR_BALLISTICS | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
            errsay(L"--formation-census with a runtime needs a routed tick: add profile or a simulation feature (e.g. --features all); or use --no-activate for the launcher-side census.\n");
            return -1;
        }
    } else if (o->formation_census_csv[0]) {
        errsay(L"--formation-census-csv needs --formation-census.\n");
        return -1;
    }
    if (o->no_gameplay_patch && (o->activate || o->gp_filter.mode != KNTWR_GP_ALL || o->no_d3d9_swap)) {
        errsay(L"--no-gameplay-patch needs --no-activate (the runtime requires the patched image) and excludes --gameplay-patch-only-runs/--gameplay-patch-skip-runs/--no-d3d9-swap.\n");
        return -1;
    }
    /* --no-d3d9-swap: the gameplay patch without its Direct3DCreate9 swap (runs 65, 92; no clone, pin or binding depends on them). */
    if (o->no_d3d9_swap) kntwr_gp_filter_exclude_d3d9_swap(&o->gp_filter);
    if (o->tick_pcore && o->tick_core_ab) {
        errsay(L"--tick-pcore and --tick-core-ab are exclusive.\n");
        return -1;
    }
    if ((o->army_solver_memo || o->army_solver_shadow) &&
        !(o->mask & (KNTWR_PROFILE | KNTWR_AI_ASYNC | KNTWR_BRAIN2 | KNTWR_COLLIDE | KNTWR_COLLIDE_LOD | KNTWR_LOCO | KNTWR_CAVALRY_ORBIT))) {
        errsay(L"--army-solver-memo/--army-solver-shadow need the manager-routed tick: add profile, ai, brain2, collide, collide_lod or loco (e.g. --features ai,profile).\n");
        return -1;
    }
    if (o->army_solver_memo && o->army_solver_shadow) {
        errsay(L"--army-solver-memo and --army-solver-shadow are exclusive.\n");
        return -1;
    }
    if (!o->ai_deferred && (o->ai_deferred_k != KNTWR_AI_DEFERRED_DEFAULT_K || o->ai_deferred_budget != KNTWR_AI_DEFERRED_DEFAULT_BUDGET)) {
        errsay(L"--ai-deferred-k / --ai-deferred-budget require --ai-deferred.\n");
        return -1;
    }
    if ((o->mask & KNTWR_BRAIN) && !(o->mask & KNTWR_PROFILE)) {
        errsay(L"--features brain requires --profile (or a feature list containing profile); brain sites exist only inside the profiling epoch.\n");
        return -1;
    }
    if ((o->mask & KNTWR_AI_CTRL) && !(o->mask & KNTWR_AI_ASYNC)) {
        errsay(L"Controller offload (ai_ctrl) requires --features ai (or a list containing ai).\n");
        return -1;
    }
    if (o->collide_census && !(o->mask & KNTWR_PROFILE)) {
        errsay(L"--collide-census requires --profile (or a feature list containing profile).\n");
        return -1;
    }
    if ((o->mask & KNTWR_COLLIDE_LOD) && (o->mask & (KNTWR_COLLIDE | KNTWR_FORMATION))) {
        errsay(L"collide_lod cannot combine with collide or formation; its original-query gate requires the private manager.\n");
        return -1;
    }
    if ((o->collide_contact_shadow || o->collide_contact_workers) && !(o->mask & KNTWR_COLLIDE)) {
        errsay(L"--collide-contact-shadow and --collide-contact-workers require --features collide.\n");
        return -1;
    }
    if (o->collide_contact_shadow && o->collide_contact_workers) {
        errsay(L"--collide-contact-shadow and --collide-contact-workers are exclusive.\n");
        return -1;
    }
    if ((o->brain_census || o->brain_timing || o->brain_node_shadow || o->brain_fire_shadow || o->brain_finalizer_shadow ||
         o->brain_parallel || o->brain_quiet || o->brain_unit_shadow || o->brain_s0 || o->brain_locality) && !(o->mask & KNTWR_BRAIN2)) {
        errsay(L"--brain-census, --brain-timing, --brain-parallel, --brain-quiet, --brain-unit-shadow, --brain-s0, --brain-locality* and brain shadow options require --features brain2.\n");
        return -1;
    }
    if ((o->brain_unit_fatigue || o->brain_unit_posture || o->brain_unit_engage) && !(o->mask & KNTWR_BRAIN2)) {
        errsay(L"--brain-unit-* options require --features brain2.\n");
        return -1;
    }
    if ((o->brain_unit_fatigue || o->brain_unit_posture || o->brain_unit_engage) &&
        (o->brain_census || o->brain_timing || o->brain_node_shadow || o->brain_fire_shadow || o->brain_finalizer_shadow ||
         o->brain_parallel || o->brain_quiet || o->brain_unit_shadow)) {
        errsay(L"--brain-unit-* options own the serial site-6 occurrence call: they exclude --brain-census, --brain-timing, "
               L"--brain-parallel, --brain-quiet, --brain-unit-shadow and the brain shadow options (they combine with each other and --brain-s0).\n");
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
    if (o->brain_s0 && (o->brain_census || o->brain_timing || o->brain_node_shadow || o->brain_fire_shadow ||
                        o->brain_finalizer_shadow || o->brain_parallel || o->brain_quiet || o->brain_unit_shadow)) {
        errsay(L"--brain-s0 owns the site-6 occurrence call and excludes every other --brain-* option except the --brain-unit-* options.\n");
        return -1;
    }
    if (o->brain_locality && (o->brain_census || o->brain_timing || o->brain_node_shadow || o->brain_fire_shadow ||
                              o->brain_finalizer_shadow || o->brain_parallel || o->brain_quiet || o->brain_unit_shadow || o->brain_s0 ||
                              o->brain_unit_fatigue || o->brain_unit_posture || o->brain_unit_engage)) {
        errsay(L"--brain-locality* owns the site-6 occurrence call and excludes every other --brain-* option (including --brain-s0 and --brain-unit-*).\n");
        return -1;
    }
    if ((o->brain_locality_warm ? 1 : 0) + (o->brain_locality_prefetch ? 1 : 0) + (o->brain_locality_prefetch2 ? 1 : 0) +
        (o->brain_locality_mark ? 1 : 0) > 1) {
        errsay(L"--brain-locality-warm, --brain-locality-prefetch, --brain-locality-prefetch2 and --brain-locality-mark are exclusive modes.\n");
        return -1;
    }
    if ((o->mask & KNTWR_LOCO) && (o->mask & (KNTWR_BRAIN | KNTWR_COLLIDE_LOD))) {
        errsay(L"loco cannot combine with brain or collide_lod.\n");
        return -1;
    }
    if ((o->mask & (KNTWR_LOCO | KNTWR_COLLIDE)) == (KNTWR_LOCO | KNTWR_COLLIDE) &&
        (!o->loco_clone || !o->loco_parallel || !o->loco_owned || !(o->loco_grid || o->loco_grid_verify))) {
        errsay(L"loco+collide requires --loco-clone, --loco-parallel, --loco-owned-services and --loco-grid (or --loco-grid-verify).\n");
        return -1;
    }
    if (o->loco_clone && !(o->mask & KNTWR_LOCO)) {
        errsay(L"--loco-clone requires --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if (o->loco_parallel && (!(o->mask & KNTWR_LOCO) || !o->loco_clone)) {
        errsay(L"--loco-parallel requires --features loco (or a feature list containing loco) and --loco-clone.\n");
        return -1;
    }
    if (o->loco_shadow && (!(o->mask & KNTWR_LOCO) || !o->loco_clone)) {
        errsay(L"--loco-shadow requires --features loco and --loco-clone.\n");
        return -1;
    }
    if (o->loco_owned && (!(o->mask & KNTWR_LOCO) || !o->loco_clone || !o->loco_parallel)) {
        errsay(L"--loco-owned-services requires --features loco (or a feature list containing loco), --loco-clone and --loco-parallel.\n");
        return -1;
    }
    if (o->loco_quiet && (!(o->mask & KNTWR_LOCO) || !o->loco_clone || !o->loco_parallel || !o->loco_owned)) {
        errsay(L"--loco-quiet requires --features loco, --loco-clone, --loco-parallel and --loco-owned-services.\n");
        return -1;
    }
    if ((o->loco_grid || o->loco_grid_verify) && !(o->mask & KNTWR_LOCO)) {
        errsay(L"--loco-grid and --loco-grid-verify require --features loco (or a feature list containing loco).\n");
        return -1;
    }
    if (o->loco_grid_incremental && (!(o->mask & KNTWR_LOCO) || !(o->loco_grid || o->loco_grid_verify))) {
        errsay(L"--loco-grid-incremental requires --features loco and --loco-grid (or --loco-grid-verify).\n");
        return -1;
    }
    if (o->loco_relink_shadow && o->loco_relink_workers) {
        errsay(L"--loco-relink-shadow and --loco-relink-workers are exclusive.\n");
        return -1;
    }
    if ((o->loco_relink_shadow || o->loco_relink_workers) &&
        (!(o->mask & KNTWR_LOCO) || !o->loco_owned || !(o->loco_grid || o->loco_grid_verify))) {
        errsay(L"--loco-relink-shadow and --loco-relink-workers require --features loco, --loco-owned-services and --loco-grid (or --loco-grid-verify).\n");
        return -1;
    }
    if (o->loco_cw_shadow && o->loco_cw_workers) {
        errsay(L"--loco-cw-shadow and --loco-cw-workers are exclusive.\n");
        return -1;
    }
    if ((o->loco_cw_shadow || o->loco_cw_workers) && (!(o->mask & KNTWR_LOCO) || !o->loco_owned)) {
        errsay(L"--loco-cw-shadow and --loco-cw-workers require --features loco and --loco-owned-services.\n");
        return -1;
    }
    if (o->grid_probation && (!(o->mask & KNTWR_LOCO) || !o->loco_grid || (o->mask & KNTWR_BALLISTICS))) {
        errsay(L"--grid-probation requires --features loco with --loco-grid (or --loco-grid-verify) and is refused with ballistic "
               L"(its query cache walks the native cell heads itself).\n");
        return -1;
    }
    if ((o->mask & KNTWR_LOCO) && (o->mask & KNTWR_FORMATION))
        say(L"note: loco stays inert while formation is enabled (the original manager bypasses the ACTIVE clone); omit formation to run it.\n");
    if ((o->mask & KNTWR_BRAIN2) && (o->mask & KNTWR_FORMATION))
        say(L"note: brain2 stays inert while formation is enabled (the formation module runs the original army manager, so the per-entity "
            L"loop is not reached through the private clones); omit formation to run it.\n");
    if ((o->mask & KNTWR_BRAIN2) && (o->mask & KNTWR_BRAIN))
        say(L"note: brain2 runs the private clones, so the brain profiling entry slots are not published (brain sites stay empty); "
            L"the brain2 counters measure the loop instead.\n");
    if ((o->mask & KNTWR_COLLIDE) && (o->mask & KNTWR_FORMATION))
        say(L"note: collide stays inert while formation is enabled (the original manager bypasses the ACTIVE clone); "
            L"omit formation to run the experimental solver.\n");
    if (o->exit_game_after_observe && (!o->observe_s || (!o->activate && !o->formation_census))) {
        errsay(L"--exit-game-after-observe requires nonzero --observe-seconds and runtime activation (or --formation-census with --no-activate).\n");
        return -1;
    }
    if (o->setup && (o->game[0] || o->validate_only || o->no_launch)) {
        errsay(L"--setup cannot be combined with --game, --check/--validate-only or --no-launch.\n");
        return -1;
    }
    return 0;
}

/* Explicit --game wins (including a --game-exe folder).  Otherwise the setup module resolves the folder: saved config
   first, then every Steam library, then - only for a real interactive launch - the IFileOpenDialog picker.  --check and
   --no-launch are automation modes: they never open the picker and fail fast in text instead. */
static BOOL choose_game_dir(Run *r)
{
    BOOL interactive = !g_redirected && !r->opt.validate_only && !r->opt.no_launch;
    if (r->opt.setup) {
        if (!kntwr_setup_pick(r->game_dir, MAXP)) {
            errsay(L"--setup: no game folder was selected (the folder picker was cancelled); nothing was saved.\n");
            return FALSE;
        }
        if (!resolve_game_dir(r->game_dir, r->game_dir)) {
            errsay(L"the selected game directory \"%ls\" is not usable.\n", r->game_dir);
            return FALSE;
        }
        return TRUE;
    }
    if (r->opt.game[0]) {
        trim_input(r->opt.game);
        if (!resolve_game_dir(r->opt.game, r->game_dir)) {
            errsay(L"game directory \"%ls\" does not exist.\n", r->opt.game);
            return FALSE;
        }
        return TRUE;
    }
    if (!kntwr_setup_locate(r->game_dir, MAXP, interactive)) {
        errsay(L"no Napoleon.exe game folder was found (tried the saved configuration, then every Steam library%ls).\n",
               interactive ? L"; the folder picker was cancelled" : L"");
        return FALSE;
    }
    if (!resolve_game_dir(r->game_dir, r->game_dir)) { /* normalize (quotes, trailing slashes, inner-file path) */
        errsay(L"the located game directory \"%ls\" is not usable.\n", r->game_dir);
        return FALSE;
    }
    return TRUE;
}

/* Everything after console acquisition and argument parsing; wmain wraps it for the quiet-failure MessageBox. */
static int run_main(Run *r, int argc, wchar_t **argv)
{
    int pr, code;

    pr = parse_args(argc, argv, &r->opt);
    if (pr == 1) { usage(); return EXIT_OK; }
    if (pr == 2) { say(L"KNTWR " KNTWR_WIDE(KNTWR_VERSION) L"\n"); return EXIT_OK; }
    if (pr < 0) { say(L"Run KNTWR.exe --console --help for usage.\n"); return EXIT_USAGE; }
    if (r->opt.validate_only) g_ui_mute = TRUE; /* --check/--validate-only: read-only, never a dialog */
    r->cfg.enabled_mask = r->opt.mask;
    r->cfg.workers = r->opt.workers;
    r->cfg.poll_ms = r->opt.poll_ms;
    r->cfg.collide_lod_m = r->opt.collide_lod_m | (r->opt.collide_census ? KNTWR_COLLIDE_CENSUS : 0u);
    r->cfg.loco_flags = loco_flags_from(&r->opt);
    r->cfg.brain_flags = (r->opt.brain_census ? KNTWR_BRAIN_CENSUS : 0u) |
                         (r->opt.brain_timing ? KNTWR_BRAIN_TIMING : 0u) |
                         (r->opt.brain_node_shadow ? KNTWR_BRAIN_NODE_SHADOW : 0u) |
                         (r->opt.brain_fire_shadow ? KNTWR_BRAIN_FIRE_SHADOW : 0u) |
                         (r->opt.brain_finalizer_shadow ? KNTWR_BRAIN_FINALIZER_SHADOW : 0u) |
                         (r->opt.brain_parallel ? KNTWR_BRAIN_PARALLEL : 0u) |
                         (r->opt.brain_quiet ? KNTWR_BRAIN_QUIET : 0u) |
                         (r->opt.brain_unit_shadow ? KNTWR_BRAIN_UNIT_SHADOW : 0u) |
                         (r->opt.brain_s0 ? KNTWR_BRAIN_S0 : 0u) |
                         (r->opt.brain_locality ? KNTWR_BRAIN_LOCALITY : 0u) |
                         (r->opt.brain_locality_warm ? KNTWR_BRAIN_LOCALITY_WARM : 0u) |
                         (r->opt.brain_locality_prefetch ? KNTWR_BRAIN_LOCALITY_PREFETCH : 0u) |
                         (r->opt.brain_locality_prefetch2 ? KNTWR_BRAIN_LOCALITY_PREFETCH2 : 0u) |
                         (r->opt.brain_locality_mark ? KNTWR_BRAIN_LOCALITY_MARK : 0u) |
                         ((r->opt.brain_unit_fatigue || r->opt.brain_unit_fatigue_shadow) ? KNTWR_BRAIN_UNIT_FATIGUE : 0u) |
                         (r->opt.brain_unit_fatigue_shadow ? KNTWR_BRAIN_UNIT_FATIGUE_SHADOW : 0u) |
                         ((r->opt.brain_unit_posture || r->opt.brain_unit_posture_shadow) ? KNTWR_BRAIN_UNIT_POSTURE : 0u) |
                         (r->opt.brain_unit_posture_shadow ? KNTWR_BRAIN_UNIT_POSTURE_SHADOW : 0u) |
                         ((r->opt.brain_unit_engage || r->opt.brain_unit_engage_shadow) ? KNTWR_BRAIN_UNIT_ENGAGE : 0u) |
                         (r->opt.brain_unit_engage_shadow ? KNTWR_BRAIN_UNIT_ENGAGE_SHADOW : 0u);
    r->cfg.collide_flags = (r->opt.collide_contact_shadow ? KNTWR_COLLIDE_CONTACT_SHADOW : 0u) |
                           (r->opt.collide_contact_workers ? KNTWR_COLLIDE_CONTACT_WORKERS : 0u);
    r->cfg.va_watch_flags = (r->opt.va_watch ? KNTWR_VA_WATCH : 0u) | (r->opt.army_storm_census ? KNTWR_ARMY_STORM_CENSUS : 0u) |
                            (r->opt.army_storm_sample_ms << KNTWR_ARMY_STORM_SAMPLE_SHIFT) |
                            (r->opt.tick_pcore ? KNTWR_TICK_PCORE : 0u) | (r->opt.tick_core_ab ? KNTWR_TICK_CORE_AB : 0u);
    r->cfg.va_watch_flags |= (r->opt.army_solver_memo ? KNTWR_ARMY_SOLVER_MEMO : 0u) | (r->opt.army_solver_shadow ? KNTWR_ARMY_SOLVER_SHADOW : 0u) |
                             (r->opt.alloc_census ? KNTWR_ALLOC_CENSUS : 0u) | (r->opt.alloc_fix ? KNTWR_ALLOC_FIX : 0u) |
                             (r->opt.arena_release ? KNTWR_ARENA_RELEASE : 0u) | (r->opt.heap_optimize ? KNTWR_HEAP_OPTIMIZE : 0u) |
                             (r->opt.mounted_officer ? KNTWR_MOUNTED_OFFICER : 0u) | (r->opt.mounted_officer_widen ? KNTWR_MOUNTED_OFFICER_WIDEN : 0u) |
                             (r->opt.engage_census ? KNTWR_ENGAGE_CENSUS : 0u) | (r->opt.formation_census ? KNTWR_FORMATION_CENSUS : 0u) |
                             ((r->opt.va_floor_mib == 1024u ? 17u : (r->opt.va_floor_mib / KNTWR_VA_FLOOR_UNIT_MIB)) << KNTWR_VA_FLOOR_SHIFT) |
                             ((r->opt.va_hole_mib / KNTWR_VA_FLOOR_UNIT_MIB) << KNTWR_VA_HOLE_SHIFT);
    r->cfg.ai_deferred = r->opt.ai_deferred ? r->opt.ai_deferred_k | (r->opt.ai_deferred_budget << KNTWR_AI_DEFERRED_BUDGET_SHIFT) : 0u;
    r->cfg.ai_ctrl_flags = r->opt.ai_ctrl_flags | (r->opt.ai_claim_once ? KNTWR_AI_CLAIM_ONCE : 0u) | (r->opt.ai_claim_once_census ? KNTWR_AI_CLAIM_ONCE_CENSUS : 0u) |
                           (r->opt.brain_target_cull_shadow ? KNTWR_AI_TARGET_CULL_SHADOW : 0u) | (r->opt.brain_target_cull ? KNTWR_AI_TARGET_CULL : 0u) |
                           (r->opt.brain_retarget_jitter ? KNTWR_AI_RETARGET_JITTER : 0u);
    r->cfg.ai_prepass_flags = r->opt.ai_prepass_flags;
    r->cfg.gameplay_flags = (r->opt.drag_ladder ? KNTWR_DRAG_LADDER : 0u) |
                            (r->opt.wounded ? (KNTWR_WOUNDED | (r->opt.wounded_pct << KNTWR_WOUNDED_PCT_SHIFT)) : 0u);
    say(L"Effective config: mask=0x%08lX workers=%lu loco_flags=0x%08lX collide_flags=0x%08lX va_watch_flags=0x%08lX\n",
        (unsigned long)r->cfg.enabled_mask, (unsigned long)r->cfg.workers, (unsigned long)r->cfg.loco_flags,
        (unsigned long)r->cfg.collide_flags, (unsigned long)r->cfg.va_watch_flags);

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
    if (r->opt.activate || r->opt.validate_only || r->opt.setup) {
        if (!validate_runtime(r)) return finish(r, EXIT_VALIDATE, L"unusable runtime DLL");
    }
    if (r->opt.setup) {
        if (!kntwr_setup_save(r->game_dir)) {
            wchar_t cfg[MAXP];
            const wchar_t *where = kntwr_setup_config_path(cfg, MAXP) ? cfg : L"the configuration file";
            errsay(L"the game directory could not be saved to %ls.\n", where);
            return finish(r, EXIT_VALIDATE, L"validated, but the configuration could not be saved");
        }
        say(L"--setup: game directory validated and saved: %ls; nothing was started.\n", r->game_dir);
        return finish(r, EXIT_OK, L"setup saved");
    }
    if (r->opt.validate_only) {
        say(L"  game: %ls\n  workers: %lu\n  steam: %ls (%ls)\n", r->game_dir, (unsigned long)r->opt.workers,
            r->opt.steam ? L"on" : L"off", r->opt.steam ? L"SteamAppId 34030; --no-steam opts out" : L"--no-steam");
        if (r->opt.alloc_census || r->opt.alloc_fix)
            say(L"  alloc: %ls\n", (r->opt.alloc_census && r->opt.alloc_fix) ? L"FIX + CENSUS (mode=3)" :
                                   (r->opt.alloc_fix ? L"FIX (mode=2, zero-VA pathfinder subnode reclamation)" : L"CENSUS (mode=1, 32.25 MiB callsite table)"));
        if (r->opt.mounted_officer) say(L"  mounted officer: ON (%ls radius)\n", r->opt.mounted_officer_widen ? L"WIDENED" : L"infantry-spacing");
        if (r->opt.drag_ladder) say(L"  drag ladder: ON (GAMEPLAY change: files-per-row laddered at source, drag-out frontage snaps down to 60-file steps above 60 files; all multiplayer peers must use the same setting)\n");
        if (r->opt.wounded) say(L"  wounded: ON %lu%% (EXPERIMENTAL GAMEPLAY change: FACE-tagged shot deaths enter the native wounded/crawl loops instead of a static corpse; all multiplayer peers must use the same setting)\n", (unsigned long)r->opt.wounded_pct);
        if (r->opt.engage_census) say(L"  engage census: ON (read-only observer after every routed tick)\n");
        if (r->opt.allow_concurrent) say(L"  concurrent: ALLOWED (a second game instance may run; timings are not comparable between concurrent runs)\n");
        say(L"Validation complete; nothing was started.\n");
        return finish(r, EXIT_OK, L"validated");
    }
    /* Remember the directory that just validated (explicit --game, saved config, Steam library or picker) so the next
       quiet double-click finds it.  Persistence failure is a warning for a launch (the game still runs) but fatal for
       --no-launch, whose whole job is to leave a working configuration behind. */
    if (!kntwr_setup_save(r->game_dir)) {
        wchar_t cfg[MAXP];
        const wchar_t *where = kntwr_setup_config_path(cfg, MAXP) ? cfg : L"the configuration file";
        errsay(L"the game directory could not be saved to %ls; it must be found again next run.\n", where);
        if (r->opt.no_launch) return finish(r, EXIT_VALIDATE, L"validated, but the configuration could not be saved");
    }
    if (r->opt.no_launch) {
        say(L"--no-launch: validation complete and the game directory saved; nothing was started.\n");
        return finish(r, EXIT_OK, L"validated (no launch)");
    }
    if (!r->opt.allow_concurrent && napoleon_running()) return finish(r, EXIT_CONFLICT, L"Napoleon.exe already running");

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    if (!launch_game(r)) return finish(r, EXIT_LAUNCH, L"game launch failed");
    if (!r->opt.activate) {
        if (r->opt.formation_census) {
            code = run_external_census(r);
            return finish(r, code, code == EXIT_OK ? L"formation census complete (no runtime)" : L"formation census ended abnormally (no runtime)");
        }
        say(L"--no-activate: the runtime was NOT installed. Game pid %lu left running.\n", (unsigned long)r->pid);
        return finish(r, EXIT_OK, L"launched without runtime");
    }

    code = install_runtime(r);
    if (code != EXIT_OK) {
        if (code == EXIT_INSTALL || code == EXIT_LAUNCH) {
            note_game_exit(r);
            if (r->game_exited)
                say(L"The runtime is NOT active. The game has exited (exit status 0x%08lX%ls).\n", (unsigned long)r->game_exit,
                    exit_status_name(r->game_exit));
            else
                say(L"The runtime is NOT active. The game was left running without the runtime; close it manually if unwanted.\n");
        }
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

int wmain(int argc, wchar_t **argv)
{
    Run *r = &g_run;
    const BOOL no_args = argc <= 1;
    int i, code, console_mode = no_args ? 1 : 0; /* Double-click opens a console; other invocations retain inherited-terminal behavior. */

    /* Both flags are consumed here, before any console is acquired (a later flag wins). */
    for (i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"--console")) console_mode = 1;
        else if (!wcscmp(argv[i], L"--no-console")) console_mode = -1;
    }
    g_redirected = std_redirected(); /* sample before acquire_console can replace the caller's handles */
    acquire_console(console_mode);
    init_console();
    GetSystemTimePreciseAsFileTime(&r->t_start);
    code = run_main(r, argc, argv);
    /* Preserve readable errors for quiet interactive runs and double-click launches: an allocated console closes on exit.
       Attached terminals and redirected automation already retain the output; explicit --console keeps its existing behavior.
       Help is not a failure, and Ctrl+C is deliberate. */
    if (code != EXIT_OK && code != EXIT_INTERRUPTED && (console_mode <= 0 || no_args) && !g_redirected && !g_attached && !g_ui_mute) {
        wchar_t msg[MAXP];
        if (g_err_text[0]) _snwprintf_s(msg, MAXP, _TRUNCATE, L"%ls", g_err_text);
        else _snwprintf_s(msg, MAXP, _TRUNCATE, L"KNTWR failed (exit code %d). Run KNTWR.exe --console for details.\n", code);
        MessageBoxW(NULL, msg, L"KNTWR", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
    }
    return code;
}
