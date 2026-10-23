/*
 * setup.c - game folder discovery and persistence for the native KNTWR launcher (see setup.h).
 *
 * Pipeline: saved config.json -> every Steam library (HKCU/HKLM SteamPath/InstallPath across registry views,
 * steamapps/libraryfolders.vdf in both the modern and legacy layout, then appmanifest_34030.acf "installdir" plus
 * known install-folder fallbacks) -> native IFileOpenDialog folder picker (interactive only; accepts a pasted path or
 * the Napoleon.exe file itself, retries with an error dialog when the selection is invalid).  A candidate counts only
 * when it contains Napoleon.exe; nothing is written except by kntwr_setup_save, which validates first and replaces
 * config.json atomically via a temp file + MoveFileExW.
 *
 * No third-party dependencies: a strict minimal JSON reader/writer (UTF-8, \u escapes incl. surrogate pairs, any
 * malformed document is treated as a missing preference) and a small Valve VDF parser are implemented locally.
 * COM GUIDs are defined as statics (initguid-free) so uuid.lib is not required.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#define COBJMACROS
#include <windows.h>
#include <objbase.h>    /* CoInitializeEx, CoCreateInstance, CoTaskMemFree */
#include <shobjidl.h>   /* IFileOpenDialog, IShellItem, SIGDN_FILESYSPATH, FOS_PICKFOLDERS */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "setup.h"

/* ---------------------------------------------------------------------------------------------- shared constants */

#define SS_EXE_NAME     L"Napoleon.exe"
#define SS_APP_ID       L"34030"             /* Total War: NAPOLEON - Definitive Edition */
#define SS_MAXP         4096u                /* path buffer size, matches MAXP in main.c */
#define SS_MAX_FILE     (64u * 1024u)        /* config.json / libraryfolders.vdf / appmanifest read cap */
#define SS_MAX_DEPTH    48u                  /* JSON nesting cap */
#define SS_LIBP         1024u                /* max characters of a stored Steam library root */
#define SS_MAX_LIBS     64u

/* initguid-free GUID definitions so uuid.lib is not needed (MinGW and MSVC both link these statics). */
static const CLSID ss_CLSID_FileOpenDialog = { 0xDC1C5A9C, 0xE88A, 0x4dde, { 0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7 } };
static const IID   ss_IID_IFileOpenDialog  = { 0xD57C7288, 0xD4AD, 0x4768, { 0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60 } };

/* ------------------------------------------------------------------------------------------------ string helpers */

/* Appends `src` after `base`, separated by one backslash.  FALSE when the result would not fit in `cap` wide characters. */
static BOOL ss_join(wchar_t *dst, size_t cap, const wchar_t *base, const wchar_t *src)
{
    size_t n = wcslen(base);

    if (n && base[n - 1] == L'\\') --n;                 /* avoid doubling the separator */
    if (n + 1 >= cap) return FALSE;
    memcpy(dst, base, n * sizeof(wchar_t));
    dst[n] = 0;
    if (src && *src) {
        dst[n++] = L'\\';
        dst[n] = 0;
        if (wcscat_s(dst, cap, src) != 0) return FALSE;
    }
    return TRUE;
}

/* Replaces every forward slash with a backslash in place (Steam writes registry paths with '/'). */
static void ss_slashes(wchar_t *s)
{
    for (; *s; ++s) if (*s == L'/') *s = L'\\';
}

/* Strips trailing backslashes; a drive root ("C:\\") keeps its slash. */
static void ss_strip_tail(wchar_t *s)
{
    size_t n = wcslen(s);
    while (n > 3 && s[n - 1] == L'\\') s[--n] = 0;
}

/* Reads the whole file (up to SS_MAX_FILE bytes) into a NUL-terminated heap buffer.  NULL on failure. */
static char *ss_read_file(const wchar_t *path)
{
    HANDLE f;
    DWORD high = 0, size, done, total = 0;
    char *buf;

    f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(f, &high);
    if (size == INVALID_FILE_SIZE || high != 0 || size > SS_MAX_FILE) { CloseHandle(f); return NULL; }
    buf = (char *)HeapAlloc(GetProcessHeap(), 0, (size_t)size + 1);
    if (!buf) { CloseHandle(f); return NULL; }
    while (total < size) {
        if (!ReadFile(f, buf + total, size - total, &done, NULL) || done == 0) {
            HeapFree(GetProcessHeap(), 0, buf);
            CloseHandle(f);
            return NULL;
        }
        total += done;
    }
    buf[size] = 0;
    CloseHandle(f);
    return buf;
}

/* Directory test that tolerates a trailing backslash. */
static BOOL ss_is_dir(const wchar_t *dir)
{
    DWORD a = GetFileAttributesW(dir);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

/* TRUE when `dir` is a directory that contains Napoleon.exe. */
static BOOL ss_dir_ok(const wchar_t *dir)
{
    wchar_t exe[SS_MAXP];
    DWORD a;

    if (!ss_is_dir(dir)) return FALSE;
    if (!ss_join(exe, SS_MAXP, dir, SS_EXE_NAME)) return FALSE;
    a = GetFileAttributesW(exe);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/*
 * Normalizes user/saved/picked text to an absolute directory: trims whitespace and quotes, expands to a full path,
 * takes the parent when a file (e.g. Napoleon.exe itself) was given, and strips trailing backslashes.
 * `in` and `out` may alias.  FALSE when the text is empty, unresolvable, or longer than `cap` - 1 characters.
 */
static BOOL ss_normalize_dir(const wchar_t *in, wchar_t *out, size_t cap)
{
    wchar_t full[SS_MAXP], expanded[SS_MAXP];
    const wchar_t *s = in;
    size_t n;
    DWORD len;

    while (*s == L' ' || *s == L'\t') ++s;
    n = wcslen(s);
    while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t' || s[n - 1] == L'\r' || s[n - 1] == L'\n' || s[n - 1] == L'"')) --n;
    if (n == 0 || n >= SS_MAXP) return FALSE;
    memcpy(full, s, n * sizeof(wchar_t));
    full[n] = 0;

    len = GetFullPathNameW(full, SS_MAXP, expanded, NULL);  /* lpBuffer must not alias lpFileName */
    if (len == 0 || len >= SS_MAXP) return FALSE;
    if (GetFileAttributesW(expanded) == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (!ss_is_dir(expanded)) {
        wchar_t *slash = wcsrchr(expanded, L'\\');
        if (!slash) return FALSE;
        *slash = 0;                                      /* a file was given: use its folder */
    }
    ss_strip_tail(expanded);
    if (!ss_is_dir(expanded)) return FALSE;
    n = wcslen(expanded);
    if (n >= cap) return FALSE;
    memcpy(out, expanded, (n + 1) * sizeof(wchar_t));
    return TRUE;
}

/* Composes pre + path + post into `dst` with truncation (always NUL-terminated). */
static void ss_msg(wchar_t *dst, size_t cap, const wchar_t *pre, const wchar_t *path, const wchar_t *post)
{
    size_t w = 0;

    if (cap == 0) return;
    {
        const wchar_t *q = pre ? pre : L"";
        while (*q && w < cap - 1) dst[w++] = *q++;
    }
    if (path) {
        const wchar_t *q = path;
        while (*q && w < cap - 1) dst[w++] = *q++;
    }
    if (post) {
        const wchar_t *q = post;
        while (*q && w < cap - 1) dst[w++] = *q++;
    }
    dst[w] = 0;
}

/* -------------------------------------------------------------------------------------------------- JSON (subset) */

/* Skips JSON whitespace. */
static const char *ss_jspace(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    return p;
}

static unsigned ss_hex4(const char *p)
{
    unsigned v = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0xFFFFFFFFu;
    }
    return v;
}

/* Appends one code point to a UTF-8 buffer; returns the bytes written, 0 on overflow or invalid code point. */
static size_t ss_utf8_put(char *out, size_t cap, size_t at, uint32_t cp)
{
    unsigned char b[4];
    size_t n;

    if (cp < 0x80) { b[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800) { b[0] = (unsigned char)(0xC0 | (cp >> 6)); b[1] = (unsigned char)(0x80 | (cp & 0x3F)); n = 2; }
    else if (cp < 0x10000) {
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;      /* unpaired surrogate */
        b[0] = (unsigned char)(0xE0 | (cp >> 12)); b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[2] = (unsigned char)(0x80 | (cp & 0x3F)); n = 3;
    } else if (cp < 0x110000) {
        b[0] = (unsigned char)(0xF0 | (cp >> 18)); b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (cp & 0x3F)); n = 4;
    } else return 0;
    if (at + n > cap) return 0;
    memcpy(out + at, b, n);
    return n;
}

/*
 * Parses the JSON string starting at *pp (which must point at '"'); advances *pp past the closing quote.
 * With `out` == NULL the string is only validated.  Otherwise the decoded UTF-8 value is written (NUL-terminated;
 * `out_len` counts the terminator).  FALSE on malformed escape, raw control character, unpaired surrogate,
 * embedded NUL or overflow.
 */
static BOOL ss_json_string(const char **pp, const char *end, char *out, size_t out_len)
{
    const char *p = *pp + 1;
    size_t w = 0;

    if (out && out_len == 0) return FALSE;
    for (;;) {
        unsigned char c;

        if (p >= end) return FALSE;
        c = (unsigned char)*p;
        if (c == '"') { ++p; break; }
        if (c == '\\') {
            char e;
            uint32_t cp;

            if (++p >= end) return FALSE;
            e = *p++;
            switch (e) {
            case '"': case '\\': case '/': cp = (unsigned char)e; break;
            case 'b': cp = 0x08; break;
            case 'f': cp = 0x0C; break;
            case 'n': cp = 0x0A; break;
            case 'r': cp = 0x0D; break;
            case 't': cp = 0x09; break;
            case 'u': {
                unsigned hi, lo;

                if (end - p < 4) return FALSE;
                hi = ss_hex4(p);
                if (hi == 0xFFFFFFFFu) return FALSE;
                p += 4;
                if (hi >= 0xD800 && hi <= 0xDBFF) {      /* high surrogate: a low surrogate must follow */
                    if (end - p < 6 || p[0] != '\\' || p[1] != 'u') return FALSE;
                    lo = ss_hex4(p + 2);
                    if (lo == 0xFFFFFFFFu || lo < 0xDC00 || lo > 0xDFFF) return FALSE;
                    p += 6;
                    cp = 0x10000u + ((hi - 0xD800u) << 10) + (lo - 0xDC00u);
                } else if (hi >= 0xDC00 && hi <= 0xDFFF) {
                    return FALSE;                        /* lone low surrogate */
                } else {
                    cp = hi;
                }
                break;
            }
            default:
                return FALSE;
            }
            if (cp == 0) return FALSE;                   /* an embedded NUL cannot round-trip a path */
            if (out) {
                size_t n = ss_utf8_put(out, out_len - 1, w, cp);   /* reserve one byte for the terminator */
                if (n == 0) return FALSE;
                w += n;
            }
            continue;
        }
        if (c < 0x20) return FALSE;                      /* raw control character */
        if (c >= 0x80) {                                 /* copy well-formed UTF-8 through unchanged */
            size_t n = 1;
            size_t i;
            uint32_t cp;

            if ((c & 0xE0) == 0xC0) n = 2;
            else if ((c & 0xF0) == 0xE0) n = 3;
            else if ((c & 0xF8) == 0xF0) n = 4;
            if (n == 1 || (size_t)(end - p) < n) return FALSE;
            for (i = 1; i < n; ++i) if (((unsigned char)p[i] & 0xC0) != 0x80) return FALSE;
            cp = (uint32_t)(c & (0xFFu >> (n + 1)));
            for (i = 1; i < n; ++i) cp = (cp << 6) | (uint32_t)((unsigned char)p[i] & 0x3F);
            if (cp >= 0xD800 && cp <= 0xDFFF) return FALSE;
            if (out) {
                size_t k = ss_utf8_put(out, out_len - 1, w, cp);
                if (k == 0) return FALSE;
                w += k;
            }
            p += n;
            continue;
        }
        if (out) {
            if (w + 1 >= out_len) return FALSE;
            out[w++] = (char)c;
        }
        ++p;
    }
    if (out) out[w] = 0;
    *pp = p;
    return TRUE;
}

/* Skips one JSON value of any type. */
static BOOL ss_json_skip(const char **pp, const char *end, unsigned depth)
{
    const char *p = ss_jspace(*pp, end);

    if (p >= end || depth > SS_MAX_DEPTH) return FALSE;
    if (*p == '"') {
        *pp = p;
        return ss_json_string(pp, end, NULL, 0);
    }
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';

        ++p;
        p = ss_jspace(p, end);
        if (p < end && *p == close) { *pp = p + 1; return TRUE; }
        for (;;) {
            if (p >= end) return FALSE;
            if (open == '{') {
                const char *q = p;

                if (*p != '"') return FALSE;
                if (!ss_json_string(&q, end, NULL, 0)) return FALSE;
                p = ss_jspace(q, end);
                if (p >= end || *p != ':') return FALSE;
                ++p;
            }
            p = ss_jspace(p, end);
            if (!ss_json_skip(&p, end, depth + 1)) return FALSE;
            p = ss_jspace(p, end);
            if (p >= end) return FALSE;
            if (*p == ',') { ++p; p = ss_jspace(p, end); continue; }
            if (*p == close) { *pp = p + 1; return TRUE; }
            return FALSE;
        }
    }
    if (*p == 't') { if (end - p < 4 || memcmp(p, "true", 4) != 0) return FALSE; *pp = p + 4; return TRUE; }
    if (*p == 'f') { if (end - p < 5 || memcmp(p, "false", 5) != 0) return FALSE; *pp = p + 5; return TRUE; }
    if (*p == 'n') { if (end - p < 4 || memcmp(p, "null", 4) != 0) return FALSE; *pp = p + 4; return TRUE; }
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        ++p;
        while (p < end && *p >= '0' && *p <= '9') ++p;
        if (p < end && *p == '.') { ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
        if (p < end && (*p == 'e' || *p == 'E')) {
            ++p;
            if (p < end && (*p == '+' || *p == '-')) ++p;
            if (p >= end || *p < '0' || *p > '9') return FALSE;
            while (p < end && *p >= '0' && *p <= '9') ++p;
        }
        *pp = p;
        return TRUE;
    }
    return FALSE;
}

/* ss_json_get_string result codes. */
#define SS_JSON_MISSING    0
#define SS_JSON_FOUND      1
#define SS_JSON_MALFORMED  2

/*
 * Extracts the string value of `want_key` from a JSON object.  The whole document must be well-formed (including
 * after the closing brace); anything malformed returns SS_JSON_MALFORMED, which callers treat as "missing".
 * A non-string value for `want_key` is also malformed by contract (the file is launcher-owned).
 */
static int ss_json_get_string(const char *buf, size_t size, const char *want_key, char *out, size_t out_len)
{
    const char *p = buf, *end = buf + size;
    int found = SS_JSON_MISSING;

    p = ss_jspace(p, end);
    if (p >= end || *p != '{') return SS_JSON_MALFORMED;
    ++p;
    p = ss_jspace(p, end);
    if (p < end && *p == '}') return SS_JSON_MISSING;
    for (;;) {
        char key[256];

        if (p >= end || *p != '"') return SS_JSON_MALFORMED;
        if (!ss_json_string(&p, end, key, sizeof key)) return SS_JSON_MALFORMED;
        p = ss_jspace(p, end);
        if (p >= end || *p != ':') return SS_JSON_MALFORMED;
        ++p;
        p = ss_jspace(p, end);
        if (p < end && *p == '"') {
            if (strcmp(key, want_key) == 0) {
                if (!ss_json_string(&p, end, out, out_len)) return SS_JSON_MALFORMED;
                found = SS_JSON_FOUND;
            } else if (!ss_json_string(&p, end, NULL, 0)) {
                return SS_JSON_MALFORMED;
            }
        } else if (!ss_json_skip(&p, end, 1)) {
            return SS_JSON_MALFORMED;
        }
        p = ss_jspace(p, end);
        if (p >= end) return SS_JSON_MALFORMED;
        if (*p == ',') { ++p; p = ss_jspace(p, end); continue; }
        if (*p == '}') { ++p; break; }
        return SS_JSON_MALFORMED;
    }
    return (ss_jspace(p, end) == end) ? found : SS_JSON_MALFORMED;
}

/* ------------------------------------------------------------------------- config.json path, read, write */

BOOL kntwr_setup_config_path(wchar_t *out, size_t capacity)
{
    wchar_t self[SS_MAXP];
    DWORD n;
    wchar_t *slash;

    if (!out || capacity < 8) return FALSE;
    n = GetModuleFileNameW(NULL, self, SS_MAXP);
    if (n == 0 || n >= SS_MAXP) return FALSE;
    self[n] = 0;
    slash = wcsrchr(self, L'\\');
    if (!slash) return FALSE;
    *slash = 0;                                          /* directory of the running executable */
    return ss_join(out, capacity, self, L"config.json");
}

/* Loads the saved game_dir preference; FALSE when absent, malformed, or undecodable. */
static BOOL ss_config_read(wchar_t *out, size_t cap)
{
    wchar_t cfg[SS_MAXP];
    char *raw, *buf;
    size_t size;
    char utf8[SS_MAXP * 3];
    int r;

    if (!kntwr_setup_config_path(cfg, SS_MAXP)) return FALSE;
    raw = ss_read_file(cfg);
    if (!raw) return FALSE;
    buf = raw;
    size = strlen(buf);
    if (size >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF) {
        buf += 3;                                       /* UTF-8 BOM */
        size -= 3;
    }
    r = ss_json_get_string(buf, size, "game_dir", utf8, sizeof utf8);
    HeapFree(GetProcessHeap(), 0, raw);
    if (r != SS_JSON_FOUND) return FALSE;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out, (int)cap) == 0) return FALSE;
    return TRUE;
}

BOOL kntwr_setup_save(const wchar_t *dir)
{
    static const char prefix[] = "{\"game_dir\": \"";
    static const char suffix[] = "\"}\n";
    wchar_t norm[SS_MAXP], cfg[SS_MAXP], tmp[SS_MAXP];
    char utf8[SS_MAXP * 3];
    char body[(SS_MAXP * 3) * 2 + 64];                  /* JSON-escaped value with headroom for \\ escapes */
    int len;
    size_t i, w = 0;
    HANDLE f;
    DWORD total = 0, done;

    if (!dir) return FALSE;
    if (!ss_normalize_dir(dir, norm, SS_MAXP)) return FALSE;   /* never persist a folder without Napoleon.exe */
    if (!kntwr_setup_config_path(cfg, SS_MAXP)) return FALSE;

    len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, norm, -1, utf8, sizeof utf8, NULL, NULL);
    if (len <= 0) return FALSE;                          /* len includes the NUL */
    --len;

    memcpy(body, prefix, sizeof prefix - 1);
    w = sizeof prefix - 1;
    for (i = 0; i < (size_t)len; ++i) {
        unsigned char c = (unsigned char)utf8[i];
        const char *esc;
        char one[2];

        switch (c) {
        case '"':  esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\b': esc = "\\b"; break;
        case '\f': esc = "\\f"; break;
        case '\n': esc = "\\n"; break;
        case '\r': esc = "\\r"; break;
        case '\t': esc = "\\t"; break;
        default:
            if (c < 0x20) {
                static const char hexd[] = "0123456789abcdef";

                if (w + 6 > sizeof body) return FALSE;
                body[w++] = '\\'; body[w++] = 'u'; body[w++] = '0'; body[w++] = '0';
                body[w++] = hexd[(c >> 4) & 0xF];
                body[w++] = hexd[c & 0xF];
                continue;
            }
            one[0] = (char)c; one[1] = 0; esc = one;
            break;
        }
        {
            size_t n = strlen(esc);

            if (w + n > sizeof body) return FALSE;
            memcpy(body + w, esc, n);
            w += n;
        }
    }
    if (w + (sizeof suffix - 1) > sizeof body) return FALSE;
    memcpy(body + w, suffix, sizeof suffix - 1);
    w += sizeof suffix - 1;

    /* Write a sibling temp file, then atomically replace config.json so a crash never leaves a partial preference. */
    if (wcslen(cfg) + 5 > SS_MAXP) return FALSE;         /* cfg plus ".tmp" and the terminator must fit */
    wcscpy_s(tmp, SS_MAXP, cfg);
    wcscat_s(tmp, SS_MAXP, L".tmp");
    f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    while (total < (DWORD)w) {
        if (!WriteFile(f, body + total, (DWORD)w - total, &done, NULL) || done == 0) {
            CloseHandle(f);
            DeleteFileW(tmp);
            return FALSE;
        }
        total += done;
    }
    if (!FlushFileBuffers(f)) { CloseHandle(f); DeleteFileW(tmp); return FALSE; }
    CloseHandle(f);
    if (!MoveFileExW(tmp, cfg, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp);
        return FALSE;
    }
    return TRUE;
}

/* ----------------------------------------------------------------------------------------------------- VDF (Steam) */

typedef struct {
    const char *p, *end;
    BOOL ok;
} ss_vdf;

/* Callback for each string pair of a VDF document.  depth 1 = pairs directly inside the document root. */
typedef void (*ss_vdf_pair_fn)(void *ctx, unsigned depth, const wchar_t *key, const wchar_t *value);

/* Skips whitespace and // comments. */
static void ss_vdf_space(ss_vdf *v)
{
    for (;;) {
        while (v->p < v->end && (*v->p == ' ' || *v->p == '\t' || *v->p == '\r' || *v->p == '\n')) ++v->p;
        if (v->p + 1 < v->end && v->p[0] == '/' && v->p[1] == '/') {
            v->p += 2;
            while (v->p < v->end && *v->p != '\n') ++v->p;
            continue;
        }
        return;
    }
}

/*
 * Reads one quoted VDF token (with \-escapes).  VDF text is UTF-8, so the bytes are collected first and widened with
 * CP_UTF8; a token that is not valid UTF-8 falls back to byte-per-character widening rather than failing the file.
 */
static BOOL ss_vdf_token(ss_vdf *v, wchar_t *out, size_t cap)
{
    char nb[2048];                                       /* VDF tokens (paths) are far shorter than this */
    size_t w = 0, i;

    if (v->p >= v->end || *v->p != '"') return FALSE;
    ++v->p;
    while (v->p < v->end && *v->p != '"') {
        char c = *v->p++;

        if (c == '\\') {                                 /* VDF escapes the next character */
            if (v->p >= v->end) return FALSE;
            c = *v->p++;
        }
        if (w + 1 >= sizeof nb) return FALSE;
        nb[w++] = c;
    }
    if (v->p >= v->end) return FALSE;
    ++v->p;
    nb[w] = 0;
    if (cap > SS_MAXP) cap = SS_MAXP;                    /* MultiByteToWideChar takes an int buffer count */
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, nb, -1, out, (int)cap) != 0) return TRUE;
    if (w >= cap) return FALSE;
    for (i = 0; i <= w; ++i) out[i] = (wchar_t)(unsigned char)nb[i];
    return TRUE;
}

/* Parses pairs until the matching '}'.  `depth` is 1 for the document root body. */
static void ss_vdf_block(ss_vdf *v, unsigned depth, ss_vdf_pair_fn fn, void *ctx)
{
    wchar_t key[1024], val[1024];                        /* small frames: this parser recurses once per block */

    for (;;) {
        ss_vdf_space(v);
        if (v->p >= v->end) return;                     /* clean end of the root body */
        if (*v->p == '}') { ++v->p; return; }
        if (*v->p == '{') { ++v->p; ss_vdf_block(v, depth + 1, fn, ctx); if (!v->ok) return; continue; }
        if (!ss_vdf_token(v, key, 1024)) { v->ok = FALSE; return; }
        ss_vdf_space(v);
        if (v->p < v->end && *v->p == '{') {
            ++v->p;
            ss_vdf_block(v, depth + 1, fn, ctx);         /* "key" { sub-block } */
            if (!v->ok) return;
        } else if (v->p < v->end && *v->p == '"') {
            if (!ss_vdf_token(v, val, 1024)) { v->ok = FALSE; return; }
            fn(ctx, depth, key, val);
        } else {
            v->ok = FALSE;                               /* a token must be followed by a value or a block */
            return;
        }
    }
}

/* Walks a whole VDF document.  FALSE when the document ends mid-block (pairs found so far were already delivered). */
static BOOL ss_vdf_walk(const char *buf, size_t size, ss_vdf_pair_fn fn, void *ctx)
{
    ss_vdf v;

    v.p = buf;
    v.end = buf + size;
    v.ok = TRUE;
    ss_vdf_block(&v, 1, fn, ctx);                        /* the root body behaves like a block without its brace */
    return v.ok;
}

/* -------------------------------------------------------------------------------------------------- Steam discovery */

typedef struct {
    wchar_t path[SS_LIBP];
} ss_lib_entry;

typedef struct {
    ss_lib_entry libs[SS_MAX_LIBS];
    size_t count;
} ss_libs;

/* Adds a library path (slash-normalized, trailing-stripped, case-insensitively de-duplicated). */
static void ss_add_lib(ss_libs *l, const wchar_t *path)
{
    wchar_t copy[SS_MAXP];
    size_t i, n;

    if (wcslen(path) >= SS_MAXP) return;
    wcscpy_s(copy, SS_MAXP, path);
    ss_slashes(copy);
    ss_strip_tail(copy);
    if (wcslen(copy) < 3 || !wcschr(copy, L':') || wcslen(copy) >= SS_LIBP) return; /* absolute drive path that fits an entry */
    for (i = 0; i < l->count; ++i) if (_wcsicmp(l->libs[i].path, copy) == 0) return;
    if (l->count >= SS_MAX_LIBS) return;
    n = wcslen(copy);
    memcpy(l->libs[l->count].path, copy, (n + 1) * sizeof(wchar_t));
    ++l->count;
}

/*
 * libraryfolders.vdf sink.  Modern: "libraryfolders" { "1" { "path" "D:\\..." } } -> depth-3 "path".
 * Legacy:   "LibraryFolders" { "1" "D:\\..." } -> depth-2 numeric key with a path value.
 */
static void ss_lib_pair(void *ctx, unsigned depth, const wchar_t *key, const wchar_t *value)
{
    ss_libs *l = (ss_libs *)ctx;

    if (depth >= 2 && wcscmp(key, L"path") == 0) {
        ss_add_lib(l, value);
        return;
    }
    if (depth == 2 && key[0] >= L'0' && key[0] <= L'9' &&
        (wcschr(value, L':') || wcschr(value, L'\\') || wcschr(value, L'/')))
        ss_add_lib(l, value);                            /* legacy "time" etc. are not path-shaped and drop out */
}

/* appmanifest_34030.acf sink: captures "installdir" (rejecting separators and traversal). */
static void ss_manifest_pair(void *ctx, unsigned depth, const wchar_t *key, const wchar_t *value)
{
    wchar_t *out = (wchar_t *)ctx;

    if (depth == 2 && wcscmp(key, L"installdir") == 0 && value[0] &&
        !wcschr(value, L'/') && !wcschr(value, L'\\') && wcsncmp(value, L"..", 2) != 0 && wcslen(value) < SS_MAXP)
        wcscpy_s(out, SS_MAXP, value);
}

/* Reads the Steam install root from the registry (HKCU first, then HKLM 32-bit and 64-bit views). */
static BOOL ss_steam_root(wchar_t *out, size_t cap)
{
    static const HKEY roots[3] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE };
    static const wchar_t *const subs[3] = { L"SOFTWARE\\Valve\\Steam", L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"SOFTWARE\\Valve\\Steam" };
    static const wchar_t *const vals[3] = { L"SteamPath", L"InstallPath", L"InstallPath" };
    static const DWORD views[3] = { KEY_WOW64_32KEY, KEY_WOW64_32KEY, KEY_WOW64_64KEY };
    size_t i;

    if (!out || cap < 8 || cap > SS_MAXP) return FALSE;
    for (i = 0; i < 3; ++i) {
        HKEY k;
        DWORD type, sz = (DWORD)((cap - 1) * sizeof(wchar_t));
        LONG r;

        out[0] = 0;
        r = RegOpenKeyExW(roots[i], subs[i], 0, KEY_READ | views[i], &k);
        if (r != ERROR_SUCCESS) continue;
        r = RegQueryValueExW(k, vals[i], NULL, &type, (LPBYTE)out, &sz);
        RegCloseKey(k);
        if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
        out[sz / sizeof(wchar_t)] = 0;                   /* registry strings are not guaranteed NUL-terminated */
        ss_slashes(out);
        ss_strip_tail(out);
        if (out[0]) return TRUE;
    }
    return FALSE;
}

/* Loads every Steam library: the root itself plus everything libraryfolders.vdf lists. */
static void ss_steam_libs(ss_libs *libs)
{
    wchar_t root[SS_MAXP], vdf[SS_MAXP];
    char *buf;

    memset(libs, 0, sizeof *libs);
    if (!ss_steam_root(root, SS_MAXP)) return;
    ss_add_lib(libs, root);
    /* NTFS is case-insensitive, so "SteamApps\\libraryfolders.vdf" and "steamapps\\libraryfolders.vdf" are one file. */
    if (ss_join(vdf, SS_MAXP, root, L"steamapps\\libraryfolders.vdf")) {
        buf = ss_read_file(vdf);
        if (buf) {
            ss_vdf_walk(buf, strlen(buf), ss_lib_pair, libs);
            HeapFree(GetProcessHeap(), 0, buf);
        }
    }
}

/* Tries every library: appmanifest installdir first, then known install folder names. */
static BOOL ss_steam_find(wchar_t *out, size_t cap)
{
    static const wchar_t *const names[2] = { L"Napoleon Total War", L"Total War NAPOLEON - Definitive Edition" };
    ss_libs libs;
    size_t i, n;

    ss_steam_libs(&libs);
    for (i = 0; i < libs.count; ++i) {
        wchar_t manifest[SS_MAXP], mdir[SS_MAXP], common[SS_MAXP], cand[SS_MAXP];
        char *buf;

        mdir[0] = 0;
        if (ss_join(manifest, SS_MAXP, libs.libs[i].path, L"steamapps\\appmanifest_" SS_APP_ID L".acf")) {
            buf = ss_read_file(manifest);
            if (buf) {
                ss_vdf_walk(buf, strlen(buf), ss_manifest_pair, mdir);
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }
        if (mdir[0] && ss_join(common, SS_MAXP, libs.libs[i].path, L"steamapps\\common") &&
            ss_join(cand, SS_MAXP, common, mdir) &&
            ss_normalize_dir(cand, cand, SS_MAXP) && ss_dir_ok(cand) && wcslen(cand) < cap) {
            wcscpy_s(out, cap, cand);
            return TRUE;
        }
        for (n = 0; n < 2; ++n) {
            if (ss_join(common, SS_MAXP, libs.libs[i].path, L"steamapps\\common") &&
                ss_join(cand, SS_MAXP, common, names[n]) &&
                ss_normalize_dir(cand, cand, SS_MAXP) && ss_dir_ok(cand) && wcslen(cand) < cap) {
                wcscpy_s(out, cap, cand);
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* --------------------------------------------------------------------------------------------------- folder picker */

/*
 * Native folder picker.  The dialog's edit box accepts a pasted path (FOS_PICKFOLDERS), and selecting the
 * Napoleon.exe file itself also works (the parent folder is used).  An invalid selection shows an error dialog
 * with Retry/Cancel.  FALSE on cancel, COM failure, or when the result does not fit `cap`.
 */
static BOOL ss_pick_dir(wchar_t *out, size_t cap)
{
    BOOL co = FALSE, result = FALSE;
    IFileOpenDialog *dlg = NULL;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) co = TRUE;
    else if (hr != RPC_E_CHANGED_MODE) return FALSE;     /* host apartment mismatch: a dialog may still show */

    for (;;) {
        IShellItem *item = NULL;

        if (dlg) { IUnknown_Release(dlg); dlg = NULL; }
        hr = CoCreateInstance(&ss_CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &ss_IID_IFileOpenDialog, (void **)&dlg);
        if (FAILED(hr) || !dlg) {
            MessageBoxW(NULL, L"Could not open the folder picker (the common file dialog is unavailable).",
                        L"KNTWR setup", MB_ICONERROR | MB_OK);
            break;
        }
        {
            DWORD opts;

            if (SUCCEEDED(IFileDialog_GetOptions(dlg, &opts)))
                IFileDialog_SetOptions(dlg, opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
            IFileDialog_SetTitle(dlg, L"Select the Napoleon: Total War folder that contains Napoleon.exe");
        }
        hr = IModalWindow_Show(dlg, NULL);
        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) break;
        if (FAILED(hr)) {
            MessageBoxW(NULL, L"The folder picker could not be shown.", L"KNTWR setup", MB_ICONERROR | MB_OK);
            break;
        }
        hr = IFileOpenDialog_GetResult(dlg, &item);
        if (FAILED(hr) || !item) break;
        {
            wchar_t *sel = NULL;

            if (SUCCEEDED(IShellItem_GetDisplayName(item, SIGDN_FILESYSPATH, &sel)) && sel) {
                wchar_t norm[SS_MAXP];

                if (ss_normalize_dir(sel, norm, SS_MAXP) && ss_dir_ok(norm) && wcslen(norm) < cap) {
                    wcscpy_s(out, cap, norm);
                    result = TRUE;
                } else {
                    wchar_t msg[SS_MAXP + 256];

                    ss_msg(msg, SS_MAXP + 256,
                           L"The selected folder does not contain Napoleon.exe:\n\n",
                           sel,
                           L"\n\nSelect the folder that contains the Steam Napoleon.exe.\n\nChoose Retry to pick again.");
                    if (MessageBoxW(NULL, msg, L"KNTWR setup", MB_ICONERROR | MB_RETRYCANCEL) != IDRETRY) result = FALSE;
                    else { CoTaskMemFree(sel); IUnknown_Release(item); continue; }
                }
                CoTaskMemFree(sel);
            } else {
                IUnknown_Release(item);                 /* no filesystem path: nothing to validate or retry with */
                break;
            }
        }
        IUnknown_Release(item);
        if (result) break;
        /* result == FALSE after a "Cancel" from the retry dialog: stop, the user declined to pick again. */
        break;
    }

    if (dlg) IUnknown_Release(dlg);
    if (co) CoUninitialize();
    return result;
}

/* --------------------------------------------------------------------------------------------------- public entry */

BOOL kntwr_setup_locate(wchar_t *out, size_t capacity, BOOL interactive)
{
    wchar_t saved[SS_MAXP], norm[SS_MAXP], found[SS_MAXP];

    if (!out || capacity < 8) return FALSE;

    if (ss_config_read(saved, SS_MAXP) && ss_normalize_dir(saved, norm, SS_MAXP) && ss_dir_ok(norm) &&
        wcslen(norm) < capacity && wcscpy_s(out, capacity, norm) == 0)
        return TRUE;

    if (ss_steam_find(found, SS_MAXP) && wcslen(found) < capacity && wcscpy_s(out, capacity, found) == 0)
        return TRUE;

    if (!interactive) return FALSE;
    return ss_pick_dir(out, capacity);
}

BOOL kntwr_setup_pick(wchar_t *out, size_t capacity)
{
    if (!out || capacity < 8) return FALSE;
    return ss_pick_dir(out, capacity);
}
