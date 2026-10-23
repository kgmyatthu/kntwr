/* See kntwr_gameplay_patch.h.  Plain C (compiled into kntwr.exe and into the oracle). */
#include "kntwr_gameplay_patch.h"
#include "kntwr_gameplay_patch_data.inc"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#define GP_PAGE 0x1000u
#define GP_MAX_SECTIONS 24u
#define GP_HDR_READ 0x1000u

#define GP_SCN_EXEC 0x20000000u
#define GP_SCN_READ 0x40000000u
#define GP_SCN_WRITE 0x80000000u

const uint8_t *kntwr_gp_napoleon_blob(uint32_t *size)
{
    *size = (uint32_t)sizeof kntwr_gameplay_patch_napoleon;
    return kntwr_gameplay_patch_napoleon;
}

const uint8_t *kntwr_gp_mss32_blob(uint32_t *size)
{
    *size = (uint32_t)sizeof kntwr_gameplay_patch_mss32;
    return kntwr_gameplay_patch_mss32;
}

/* ------------------------------------------------------------------------------------------------ little endian */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static uint32_t rd32u(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static void wr32u(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof v);
}

static uint32_t align_up(uint32_t v, uint32_t a)
{
    return (v + a - 1u) & ~(a - 1u);
}

static void hex_of(const uint8_t *h, char out[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; ++i) {
        out[2 * i] = digits[h[i] >> 4];
        out[2 * i + 1] = digits[h[i] & 15];
    }
    out[64] = 0;
}

/* ------------------------------------------------------------------------------------------------ blob */
typedef struct gp_run {
    uint64_t off;           /* file offset */
    uint32_t len;
    const uint8_t *old_b, *new_b;
    uint32_t rva;           /* image RVA of the first byte */
    int header;             /* inside the PE headers */
    uint32_t idx;           /* blob run index; GP_RUN_PINNED for the heap-serialization overlay */
    int pinned;             /* heap-serialization overlay run: always written, never filtered, never counted skipped */
} gp_run;

typedef struct gp_blob {
    uint64_t stock_len, patched_len;
    const uint8_t *stock_sha, *patched_sha;
    uint32_t run_count;
    gp_run *runs;
    uint64_t old_tail_len, new_tail_len;
    const uint8_t *old_tail, *new_tail;
} gp_blob;

/* ------------------------------------------------------------------------------------------------ pinned heap-serialization runs */
/* Merged into the Napoleon patch (keyed on the blob's stock SHA-256); see the header for the crash this fixes.
 * File offsets are inside .text/.data raw data; the
 * RVAs are 0xBF8895 (.text `xor eax,1` of the flags setter at 0xBF8890) and 0x1062CE8 (the .data HeapAlloc-flags global).
 * Both runs are FIXUP-FREE in the stock relocation table (nearest HIGHLOW entries: 0xBF8899 and 0x1062CF0), so the old/new
 * bytes are identical in the file and in the live image at any base. */
enum { GP_HS_RUNS = 2 };
static const uint32_t GP_RUN_PINNED = UINT32_MAX - 1u;
static const uint8_t gp_hs_stock_sha[32] = {
    0x44, 0x88, 0x0e, 0xc1, 0x77, 0x0f, 0x60, 0x01, 0x63, 0xa3, 0x36, 0xee, 0xc8, 0x3b, 0x43, 0x66,
    0x90, 0x14, 0x84, 0xc5, 0xcc, 0xee, 0xc8, 0x3d, 0xc3, 0x26, 0xe2, 0x93, 0x2f, 0x02, 0xa0, 0x54
};
static const struct { uint64_t off; uint32_t len; uint8_t old_b[4], new_b[4]; } gp_hs_runs[GP_HS_RUNS] = {
    { 0xBF7C95ull, 3u, { 0x83, 0xF0, 0x01, 0 }, { 0x31, 0xC0, 0x90, 0 } },      /* xor eax,1  -> xor eax,eax; nop */
    { 0x1060EE8ull, 4u, { 0x01, 0x00, 0x00, 0x00 }, { 0x00, 0x00, 0x00, 0x00 } } /* flags global 1 -> 0 */
};

static int gp_error(kntwr_gp_report *rep, uint32_t status, const char *fmt, ...)
{
    va_list ap;
    if (rep) {
        rep->status = status;
        va_start(ap, fmt);
        vsnprintf(rep->error, sizeof rep->error, fmt, ap);
        va_end(ap);
        rep->error[sizeof rep->error - 1] = 0;
    }
    return (int)status;
}

static int gp_parse_blob(const uint8_t *d, uint32_t size, gp_blob *b, kntwr_gp_report *rep)
{
    uint32_t pos = 0, i;
    uint64_t common;
    uint32_t body;
    memset(b, 0, sizeof *b);
    if (size < 8u + 4u + 8u + 32u + 8u + 32u + 4u + 8u + 8u + 32u) return gp_error(rep, KNTWR_GP_E_BLOB, "patch blob too short");
    body = size - 32u; /* trailing sha256 checksum; verified by tools/apply_ntwpatch.py embed --check */
    if (memcmp(d, "NTWPATCH", 8) != 0) return gp_error(rep, KNTWR_GP_E_BLOB, "bad patch magic");
    if (rd32(d + 8) != 1u) return gp_error(rep, KNTWR_GP_E_BLOB, "unsupported patch version %u", (unsigned)rd32(d + 8));
    pos = 12;
    b->stock_len = rd64(d + pos); pos += 8;
    b->stock_sha = d + pos; pos += 32;
    b->patched_len = rd64(d + pos); pos += 8;
    b->patched_sha = d + pos; pos += 32;
    b->run_count = rd32(d + pos); pos += 4;
    common = b->stock_len < b->patched_len ? b->stock_len : b->patched_len;
    if (b->run_count > 100000u) return gp_error(rep, KNTWR_GP_E_BLOB, "implausible run count %u", (unsigned)b->run_count);
    b->runs = (gp_run *)calloc(b->run_count ? b->run_count : 1u, sizeof(gp_run));
    if (!b->runs) return gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (runs)");
    {
        uint64_t prev_end = 0;
        for (i = 0; i < b->run_count; ++i) {
            gp_run *r = &b->runs[i];
            r->idx = i;
            if (body - pos < 12u) goto truncated; /* run header (off 8 + len 4); pos <= body, no underflow */
            r->off = rd64(d + pos); pos += 8;
            r->len = rd32(d + pos); pos += 4;
            if (r->len == 0 || r->off < prev_end || r->off + r->len > common) return gp_error(rep, KNTWR_GP_E_BLOB, "run %u out of range", (unsigned)i);
            if ((uint64_t)(body - pos) < 2ull * r->len) goto truncated;
            r->old_b = d + pos; pos += r->len;
            r->new_b = d + pos; pos += r->len;
            prev_end = r->off + r->len;
        }
    }
    if (body - pos < 8u) goto truncated;
    b->old_tail_len = rd64(d + pos); pos += 8;
    if ((uint64_t)(body - pos) < b->old_tail_len) goto truncated;
    b->old_tail = d + pos; pos += (uint32_t)b->old_tail_len;
    if (body - pos < 8u) goto truncated;
    b->new_tail_len = rd64(d + pos); pos += 8;
    if ((uint64_t)(body - pos) < b->new_tail_len) goto truncated;
    b->new_tail = d + pos; pos += (uint32_t)b->new_tail_len;
    if (pos != body || common + b->old_tail_len != b->stock_len || common + b->new_tail_len != b->patched_len)
        return gp_error(rep, KNTWR_GP_E_BLOB, "patch length mismatch");
    return 0;
truncated:
    return gp_error(rep, KNTWR_GP_E_BLOB, "patch blob truncated");
}

int kntwr_gp_blob_describe(const uint8_t *blob, uint32_t size, kntwr_gp_blob_info *info)
{
    gp_blob b;
    kntwr_gp_report rep;
    memset(&rep, 0, sizeof rep);
    memset(info, 0, sizeof *info);
    if (gp_parse_blob(blob, size, &b, &rep) != 0) {
        free(b.runs);
        return (int)rep.status;
    }
    info->stock_len = b.stock_len;
    info->patched_len = b.patched_len;
    hex_of(b.stock_sha, info->stock_sha256);
    hex_of(b.patched_sha, info->patched_sha256);
    info->runs = b.run_count;
    info->appended_bytes = b.new_tail_len;
    free(b.runs);
    return 0;
}

/* ------------------------------------------------------------------------------------------------ PE headers */
typedef struct gp_sec {
    uint32_t va, vsize, rawsize, rawptr, chars;
} gp_sec;

typedef struct gp_hdr {
    uint32_t nsec, soi, soh, salign, reloc_rva, reloc_size;
    gp_sec sec[GP_MAX_SECTIONS];
} gp_hdr;

static int gp_parse_header(const uint8_t *h, uint32_t n, gp_hdr *o, kntwr_gp_report *rep, const char *what)
{
    uint32_t lf, opt, table, i, nrva;
    memset(o, 0, sizeof *o);
    if (n < 0x200u || h[0] != 'M' || h[1] != 'Z') return gp_error(rep, KNTWR_GP_E_HEADER, "%s: not a DOS/PE image", what);
    lf = rd32(h + 0x3c);
    if (lf < 0x40u || lf > n - 0x108u) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: e_lfanew %#x out of range", what, (unsigned)lf);
    if (memcmp(h + lf, "PE\0\0", 4) != 0) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: missing PE signature", what);
    if ((uint32_t)(h[lf + 4] | (h[lf + 5] << 8)) != 0x14cu) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: not an x86 image", what);
    o->nsec = (uint32_t)(h[lf + 6] | (h[lf + 7] << 8));
    opt = lf + 24u;
    if ((uint32_t)(h[opt] | (h[opt + 1] << 8)) != 0x10bu) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: not PE32", what);
    if ((uint32_t)(h[lf + 20] | (h[lf + 21] << 8)) < 96u + 8u * 6u) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: optional header too small", what);
    o->salign = rd32(h + opt + 32);
    o->soi = rd32(h + opt + 56);
    o->soh = rd32(h + opt + 60);
    nrva = rd32(h + opt + 92);
    if (nrva < 6u) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: no base relocation directory slot", what);
    o->reloc_rva = rd32(h + opt + 96 + 5 * 8);
    o->reloc_size = rd32(h + opt + 96 + 5 * 8 + 4);
    if (o->nsec == 0 || o->nsec > GP_MAX_SECTIONS) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: %u sections", what, (unsigned)o->nsec);
    table = opt + (uint32_t)(h[lf + 20] | (h[lf + 21] << 8));
    if (table + 40u * o->nsec > n) return gp_error(rep, KNTWR_GP_E_HEADER, "%s: section table beyond the header read", what);
    for (i = 0; i < o->nsec; ++i) {
        const uint8_t *s = h + table + 40u * i;
        o->sec[i].vsize = rd32(s + 8);
        o->sec[i].va = rd32(s + 12);
        o->sec[i].rawsize = rd32(s + 16);
        o->sec[i].rawptr = rd32(s + 20);
        o->sec[i].chars = rd32(s + 36);
    }
    if (o->salign != GP_PAGE || o->soi == 0 || (o->soi & (GP_PAGE - 1u)) != 0 || o->soh == 0 || o->soh > n)
        return gp_error(rep, KNTWR_GP_E_HEADER, "%s: unsupported alignment/size (align %#x, image %#x, headers %#x)", what,
                        (unsigned)o->salign, (unsigned)o->soi, (unsigned)o->soh);
    return 0;
}

static uint32_t gp_protection(uint32_t chars)
{
    const int e = (chars & GP_SCN_EXEC) != 0, r = (chars & GP_SCN_READ) != 0, w = (chars & GP_SCN_WRITE) != 0;
    if (e && w) return 0x40u; /* PAGE_EXECUTE_READWRITE */
    if (e && r) return 0x20u; /* PAGE_EXECUTE_READ */
    if (e) return 0x10u;      /* PAGE_EXECUTE */
    if (w) return 0x04u;      /* PAGE_READWRITE */
    if (r) return 0x02u;      /* PAGE_READONLY */
    return 0x01u;             /* PAGE_NOACCESS */
}

/* ------------------------------------------------------------------------------------------------ relocation tables */
typedef struct gp_fix {
    uint32_t *v;
    size_t n, cap;
} gp_fix;

static int gp_fix_push(gp_fix *f, uint32_t rva)
{
    if (f->n == f->cap) {
        size_t cap = f->cap ? f->cap * 2u : 4096u;
        uint32_t *p = (uint32_t *)realloc(f->v, cap * sizeof(uint32_t));
        if (!p) return 0;
        f->v = p;
        f->cap = cap;
    }
    f->v[f->n++] = rva;
    return 1;
}

static int gp_cmp_u32(const void *a, const void *b)
{
    const uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : (x > y);
}

/* HIGHLOW entries only; anything else the loader would honour is refused rather than silently ignored. */
static int gp_parse_relocs(const uint8_t *d, uint32_t size, uint32_t image_size, gp_fix *out, kntwr_gp_report *rep, const char *what)
{
    uint32_t pos = 0, sorted = 1;
    while (pos < size) {
        uint32_t page, block, i, count;
        if (size - pos < 8u) return gp_error(rep, KNTWR_GP_E_LAYOUT, "%s: truncated relocation block header", what);
        page = rd32(d + pos);
        block = rd32(d + pos + 4);
        if (block < 8u || (block & 1u) || block > size - pos) return gp_error(rep, KNTWR_GP_E_LAYOUT, "%s: invalid relocation block extent", what);
        if (page >= image_size) return gp_error(rep, KNTWR_GP_E_LAYOUT, "%s: relocation page %#x outside the image", what, (unsigned)page);
        count = (block - 8u) / 2u;
        for (i = 0; i < count; ++i) {
            const uint32_t word = (uint32_t)(d[pos + 8 + 2 * i] | (d[pos + 9 + 2 * i] << 8));
            const uint32_t type = word >> 12, rva = page + (word & 0xfffu);
            if (type == 0) continue; /* IMAGE_REL_BASED_ABSOLUTE padding */
            if (type != 3u) return gp_error(rep, KNTWR_GP_E_LAYOUT, "%s: unsupported relocation type %u", what, (unsigned)type);
            if (rva + 4u > image_size) return gp_error(rep, KNTWR_GP_E_LAYOUT, "%s: relocation %#x outside the image", what, (unsigned)rva);
            if (out->n && rva <= out->v[out->n - 1]) sorted = 0;
            if (!gp_fix_push(out, rva)) return gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (relocations)");
        }
        pos += block;
    }
    if (!sorted && out->n > 1) {
        size_t i, used = 0;
        qsort(out->v, out->n, sizeof(uint32_t), gp_cmp_u32);
        for (i = 0; i < out->n; ++i)
            if (used == 0 || out->v[i] != out->v[used - 1]) out->v[used++] = out->v[i];
        out->n = used;
    }
    return 0;
}

/* First index whose value >= key. */
static size_t gp_lower_bound(const gp_fix *f, uint32_t key)
{
    size_t lo = 0, hi = f->n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2u;
        if (f->v[mid] < key) lo = mid + 1u; else hi = mid;
    }
    return lo;
}

static int gp_has_fix(const gp_fix *f, uint32_t rva)
{
    const size_t i = gp_lower_bound(f, rva);
    return i < f->n && f->v[i] == rva;
}

/* ------------------------------------------------------------------------------------------------ plan */
typedef struct gp_write {
    uint32_t rva, len;
    uint8_t *data;
    uint8_t *orig; /* live bytes before any write: the rollback image */
} gp_write;

static int gp_run_rva(const gp_hdr *h, gp_run *r)
{
    uint32_t i;
    if (r->off + r->len <= h->soh) {
        r->header = 1;
        r->rva = (uint32_t)r->off;
        return 1;
    }
    if (r->off < h->soh) return 0; /* straddles the header end */
    r->header = 0;
    for (i = 0; i < h->nsec; ++i) {
        const gp_sec *s = &h->sec[i];
        if (r->off >= s->rawptr && r->off + r->len <= (uint64_t)s->rawptr + s->rawsize) {
            r->rva = s->va + (uint32_t)(r->off - s->rawptr);
            return 1;
        }
    }
    return 0;
}

static int gp_mem_read(const kntwr_gp_memory *m, uint32_t va, void *dst, uint32_t n, kntwr_gp_report *rep, const char *what)
{
    if (m->read(m->ctx, va, dst, n) != 0) return gp_error(rep, KNTWR_GP_E_READ, "cannot read %s at %#x (+%#x)", what, (unsigned)va, (unsigned)n);
    return 0;
}

/* Run selection (header runs are always part of the loader-equivalent layout; the filter picks which other runs are written into the live image). */
static int gp_run_selected(const kntwr_gp_filter *f, uint32_t i)
{
    int bit;
    if (!f || f->mode == KNTWR_GP_ALL) return 1;
    bit = i < KNTWR_GP_MAX_RUNS && ((f->runs[i >> 5] >> (i & 31u)) & 1u) != 0;
    return f->mode == KNTWR_GP_ONLY ? bit : !bit;
}

int kntwr_gp_filter_parse(const char *list, kntwr_gp_filter *f)
{
    const char *p = list;
    if (!list || !*list) return -1;
    while (*p) {
        char *end;
        unsigned long a, b;
        if (*p < '0' || *p > '9') return -1;
        a = strtoul(p, &end, 10);
        b = a;
        p = end;
        if (*p == '-') {
            ++p;
            if (*p < '0' || *p > '9') return -1;
            b = strtoul(p, &end, 10);
            p = end;
        }
        if (b < a || b >= KNTWR_GP_MAX_RUNS) return -1;
        for (; a <= b; ++a) f->runs[a >> 5] |= 1u << (a & 31u);
        if (*p == ',') { ++p; if (!*p) return -1; }
        else if (*p) return -1;
    }
    return 0;
}

void kntwr_gp_filter_exclude_d3d9_swap(kntwr_gp_filter *f)
{
    const uint32_t runs[2] = { KNTWR_GP_RUN_D3D9_FACTORY_A, KNTWR_GP_RUN_D3D9_FACTORY_B };
    int k;
    if (f->mode == KNTWR_GP_ALL) f->mode = KNTWR_GP_SKIP;
    for (k = 0; k < 2; ++k) {
        const uint32_t bit = 1u << (runs[k] & 31u);
        if (f->mode == KNTWR_GP_ONLY) f->runs[runs[k] >> 5] &= ~bit;
        else f->runs[runs[k] >> 5] |= bit;
    }
}

/* ----------------------------------------------------------------------------------------------- patched SizeOfImage */
/* The patch enlarges the SizeOfImage field at file offset `field`: blob runs cover the bytes that differ, every byte no run
   covers is identical in both images.  Derives the patched value from the stock one; a covered byte must carry exactly the
   run's old value in the stock header.  The patched value must be a page-aligned, bounded enlargement. */
static int gp_soi_derive(const gp_blob *b, uint32_t field, uint32_t stock_soi, uint32_t *expanded, kntwr_gp_report *rep)
{
    uint8_t sb[4], eb[4];
    uint32_t k, i, covered = 0;
    wr32u(sb, stock_soi);
    memcpy(eb, sb, sizeof eb);
    for (k = 0; k < 4; ++k) {
        const uint64_t at = (uint64_t)field + k;
        for (i = 0; i < b->run_count; ++i) {
            const gp_run *r = &b->runs[i];
            if (r->pinned || at < r->off || at >= r->off + r->len) continue;
            if (r->old_b[at - r->off] != sb[k])
                return gp_error(rep, KNTWR_GP_E_STOCK, "SizeOfImage byte %u: the patch expects %#x, the stock header has %#x", (unsigned)k,
                                (unsigned)r->old_b[at - r->off], (unsigned)sb[k]);
            eb[k] = r->new_b[at - r->off];
            covered++;
            break;
        }
    }
    *expanded = rd32(eb);
    if (!covered || *expanded <= stock_soi || (*expanded & (GP_PAGE - 1u)) != 0 || *expanded - stock_soi > 0x4000000u)
        return gp_error(rep, KNTWR_GP_E_LAYOUT, "the patch does not enlarge SizeOfImage by whole pages (%#x -> %#x)", (unsigned)stock_soi, (unsigned)*expanded);
    return 0;
}

const char *kntwr_gp_remalloc_stage_name(uint32_t stage)
{
    static const char *const names[] = { "none", "tail-query", "tail-foreign", "tail-release", "params", "ntdll", "backing-create", "backing-write",
                                         "section", "unmap", "map", "verify" };
    return stage < sizeof names / sizeof names[0] ? names[stage] : "unknown";
}

static int gp_apply_impl(const kntwr_gp_memory *mem, uint32_t base, uint32_t preferred, const uint8_t *blob, uint32_t blob_size,
                         const kntwr_gp_filter *filter, kntwr_gp_report *rep)
{
    gp_blob b;
    gp_hdr sh, ph;
    uint8_t hdr_live[GP_HDR_READ], hdr_new[GP_HDR_READ];
    uint8_t *rbuf = NULL, *pbuf = NULL, *secbuf = NULL, *imgbuf = NULL;
    int rollback_armed = 0;
    gp_fix stock_fix = {0}, patched_fix = {0};
    gp_write *plan = NULL;
    uint32_t plan_n = 0, i, delta = base - preferred, app_total = 0, app_runs = 0;
    uint32_t reloc_end = 0;
    int rc = 0;

    memset(rep, 0, sizeof *rep);
    rep->fail_run = 0xFFFFFFFFu;
    rep->image_base = base;
    rep->preferred_base = preferred;
    rep->delta = delta;
    memset(&b, 0, sizeof b);

    if ((rc = gp_parse_blob(blob, blob_size, &b, rep)) != 0) goto done;
    rep->runs_total = b.run_count;
    /* The pinned heap-serialization runs ride with the Napoleon patch (runs_total keeps counting the blob's runs; the
       overlay is reported through runs_applied/bytes_applied and GP_RUN_PINNED in fail_run).  Inserted in file-offset
       order so the run list stays ordered, and far from every blob run (verified: no blob run within +/-0x40). */
    if (memcmp(b.stock_sha, gp_hs_stock_sha, 32) == 0) {
        gp_run *grown = (gp_run *)realloc(b.runs, (size_t)(b.run_count + GP_HS_RUNS) * sizeof(gp_run));
        if (!grown) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (pinned runs)"); goto done; }
        b.runs = grown;
        for (i = 0; i < GP_HS_RUNS; ++i) {
            gp_run pr;
            uint32_t at;
            memset(&pr, 0, sizeof pr);
            pr.off = gp_hs_runs[i].off;
            pr.len = gp_hs_runs[i].len;
            pr.old_b = gp_hs_runs[i].old_b;
            pr.new_b = gp_hs_runs[i].new_b;
            pr.idx = GP_RUN_PINNED;
            pr.pinned = 1;
            for (at = 0; at < b.run_count && b.runs[at].off < pr.off; ++at) {}
            memmove(b.runs + at + 1, b.runs + at, (size_t)(b.run_count - at) * sizeof(gp_run));
            b.runs[at] = pr;
            b.run_count++;
        }
    }
    if ((rc = gp_mem_read(mem, base, hdr_live, sizeof hdr_live, rep, "the image header")) != 0) goto done;
    if ((rc = gp_parse_header(hdr_live, sizeof hdr_live, &sh, rep, "live image")) != 0) goto done;

    /* Runs: file offset -> RVA through the STOCK section table. */
    for (i = 0; i < b.run_count; ++i) {
        if (!gp_run_rva(&sh, &b.runs[i])) {
            rep->fail_run = b.runs[i].idx;
            rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "run %u at file offset %#llx (+%u) is in no stock section", (unsigned)b.runs[i].idx,
                          (unsigned long long)b.runs[i].off, (unsigned)b.runs[i].len);
            goto done;
        }
    }

    /* Header runs: verified against the live header, applied only to a scratch copy (to learn the patched section table). */
    memcpy(hdr_new, hdr_live, sizeof hdr_new);
    for (i = 0; i < b.run_count; ++i) {
        const gp_run *r = &b.runs[i];
        if (!r->header) continue;
        if (memcmp(hdr_live + r->rva, r->old_b, r->len) != 0) {
            rep->fail_run = r->idx;
            rep->fail_va = base + r->rva;
            rc = gp_error(rep, KNTWR_GP_E_STOCK, "header run %u (RVA %#x) does not match the live stock header", (unsigned)r->idx, (unsigned)r->rva);
            goto done;
        }
        memcpy(hdr_new + r->rva, r->new_b, r->len);
        rep->runs_header++;
    }
    if ((rc = gp_parse_header(hdr_new, sizeof hdr_new, &ph, rep, "patched header")) != 0) goto done;

    /* Layout contract: stock sections unchanged in place, appended sections tile the range above the stock image. */
    if (ph.nsec < sh.nsec || ph.soi < sh.soi || ph.reloc_rva != sh.reloc_rva || ph.reloc_size < sh.reloc_size) {
        rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "patched header shrinks the stock layout");
        goto done;
    }
    for (i = 0; i < sh.nsec; ++i) {
        if (ph.sec[i].va != sh.sec[i].va || ph.sec[i].rawptr != sh.sec[i].rawptr || ph.sec[i].rawsize != sh.sec[i].rawsize) {
            rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "patched header moves stock section %u", (unsigned)i);
            goto done;
        }
    }
    {
        uint32_t cursor = sh.soi;
        for (i = sh.nsec; i < ph.nsec; ++i) {
            const gp_sec *s = &ph.sec[i];
            const uint32_t span = align_up(s->vsize, GP_PAGE);
            if (s->va < cursor || (uint64_t)s->va + span > ph.soi || (s->va & (GP_PAGE - 1u)) != 0 || s->rawptr < b.stock_len ||
                (uint64_t)s->rawptr + s->rawsize > b.stock_len + b.new_tail_len) {
                rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "appended section %u (rva %#x size %#x raw %#x+%#x) does not fit the patch tail", (unsigned)i,
                              (unsigned)s->va, (unsigned)s->vsize, (unsigned)s->rawptr, (unsigned)s->rawsize);
                goto done;
            }
            cursor = s->va + span;
        }
    }
    rep->sections_mapped = ph.nsec - sh.nsec;
    rep->section_bytes = ph.soi - sh.soi;
    rep->section_base_va = base + sh.soi;

    /* Relocation tables: the live .reloc is the stock table; the patched table is that plus the patch's own .reloc runs. */
    reloc_end = ph.reloc_rva + ph.reloc_size;
    if (sh.reloc_size) {
        rbuf = (uint8_t *)malloc(ph.reloc_size);
        pbuf = (uint8_t *)malloc(ph.reloc_size);
        if (!rbuf || !pbuf) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (relocation tables)"); goto done; }
        if ((rc = gp_mem_read(mem, base + ph.reloc_rva, rbuf, ph.reloc_size, rep, "the relocation table")) != 0) goto done;
        memcpy(pbuf, rbuf, ph.reloc_size);
        for (i = 0; i < b.run_count; ++i) {
            const gp_run *r = &b.runs[i];
            uint32_t lo, hi;
            if (r->header || r->rva >= reloc_end || r->rva + r->len <= ph.reloc_rva) continue;
            lo = r->rva < ph.reloc_rva ? ph.reloc_rva : r->rva;
            hi = r->rva + r->len > reloc_end ? reloc_end : r->rva + r->len;
            if (memcmp(rbuf + (lo - ph.reloc_rva), r->old_b + (lo - r->rva), hi - lo) != 0) {
                rep->fail_run = r->idx;
                rep->fail_va = base + lo;
                rc = gp_error(rep, KNTWR_GP_E_STOCK, "relocation-table run %u (RVA %#x) does not match the live stock table", (unsigned)r->idx, (unsigned)r->rva);
                goto done;
            }
            memcpy(pbuf + (lo - ph.reloc_rva), r->new_b + (lo - r->rva), hi - lo);
        }
        if ((rc = gp_parse_relocs(rbuf, sh.reloc_size, sh.soi, &stock_fix, rep, "stock relocation table")) != 0) goto done;
        if ((rc = gp_parse_relocs(pbuf, ph.reloc_size, ph.soi, &patched_fix, rep, "patched relocation table")) != 0) goto done;
    }
    rep->fixups_stock_total = (uint32_t)stock_fix.n;
    rep->fixups_patched_total = (uint32_t)patched_fix.n;

    /* Plan every non-header run: read the live window, un-relocate stock fixups, verify old, apply new, relocate patched fixups. */
    plan = (gp_write *)calloc(b.run_count ? b.run_count : 1u, sizeof(gp_write));
    if (!plan) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (plan)"); goto done; }
    for (i = 0; i < b.run_count; ++i) {
        const gp_run *r = &b.runs[i];
        uint32_t ustart = r->rva, uend = r->rva + r->len, ulen;
        size_t k;
        uint8_t *buf;
        if (r->header) continue;
        if (!r->pinned && !gp_run_selected(filter, r->idx)) { rep->runs_skipped++; continue; }
        if (r->rva + r->len > sh.soi) {
            rep->fail_run = r->idx;
            rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "run %u (RVA %#x) extends beyond the stock image", (unsigned)r->idx, (unsigned)r->rva);
            goto done;
        }
        /* Window = run plus every stock/patched fixup dword overlapping it. */
        for (k = gp_lower_bound(&stock_fix, r->rva >= 3u ? r->rva - 3u : 0u); k < stock_fix.n && stock_fix.v[k] < r->rva + r->len; ++k) {
            if (stock_fix.v[k] < ustart) ustart = stock_fix.v[k];
            if (stock_fix.v[k] + 4u > uend) uend = stock_fix.v[k] + 4u;
        }
        for (k = gp_lower_bound(&patched_fix, r->rva >= 3u ? r->rva - 3u : 0u); k < patched_fix.n && patched_fix.v[k] < r->rva + r->len; ++k) {
            if (patched_fix.v[k] < ustart) ustart = patched_fix.v[k];
            if (patched_fix.v[k] + 4u > uend) uend = patched_fix.v[k] + 4u;
        }
        ulen = uend - ustart;
        buf = (uint8_t *)malloc(ulen);
        if (!buf) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (window)"); goto done; }
        plan[plan_n].rva = ustart;
        plan[plan_n].len = ulen;
        plan[plan_n].data = buf;
        plan_n++;
        if ((rc = gp_mem_read(mem, base + ustart, buf, ulen, rep, "a patch site")) != 0) goto done;
        plan[plan_n - 1].orig = (uint8_t *)malloc(ulen);
        if (!plan[plan_n - 1].orig) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (rollback image)"); goto done; }
        memcpy(plan[plan_n - 1].orig, buf, ulen);
        for (k = gp_lower_bound(&stock_fix, r->rva >= 3u ? r->rva - 3u : 0u); k < stock_fix.n && stock_fix.v[k] < r->rva + r->len; ++k) {
            uint8_t *f = buf + (stock_fix.v[k] - ustart);
            wr32u(f, rd32u(f) - delta);
            rep->fixups_stock_unrelocated++;
        }
        if (memcmp(buf + (r->rva - ustart), r->old_b, r->len) != 0) {
            rep->fail_run = r->idx;
            rep->fail_va = base + r->rva;
            rc = r->pinned
                     ? gp_error(rep, KNTWR_GP_E_STOCK, "pinned heap-serialization run at VA %#x: live bytes differ from the stock image",
                                (unsigned)(base + r->rva))
                     : gp_error(rep, KNTWR_GP_E_STOCK, "run %u at VA %#x: live bytes (relocation removed) differ from the stock image", (unsigned)r->idx,
                                (unsigned)(base + r->rva));
            goto done;
        }
        memcpy(buf + (r->rva - ustart), r->new_b, r->len);
        for (k = gp_lower_bound(&patched_fix, r->rva >= 3u ? r->rva - 3u : 0u); k < patched_fix.n && patched_fix.v[k] < r->rva + r->len; ++k) {
            uint8_t *f = buf + (patched_fix.v[k] - ustart);
            wr32u(f, rd32u(f) + delta);
            rep->fixups_patched_relocated++;
        }
        app_total += ulen;
        app_runs++;
    }
    for (i = 1; i < plan_n; ++i) {
        if (plan[i].rva < plan[i - 1].rva + plan[i - 1].len) {
            rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "patch windows at RVA %#x and %#x overlap", (unsigned)plan[i - 1].rva, (unsigned)plan[i].rva);
            goto done;
        }
    }

    /* Fixups that differ between the two tables must be explained by a run (or lie in an appended section). */
    for (i = 0; i < 2u; ++i) {
        const gp_fix *a = i == 0 ? &patched_fix : &stock_fix, *o = i == 0 ? &stock_fix : &patched_fix;
        size_t k;
        for (k = 0; k < a->n; ++k) {
            uint32_t j;
            int covered = 0;
            if (a->v[k] >= sh.soi || gp_has_fix(o, a->v[k])) continue;
            for (j = 0; j < b.run_count; ++j) {
                const gp_run *r = &b.runs[j];
                if (!r->header && a->v[k] + 4u > r->rva && a->v[k] < r->rva + r->len) { covered = 1; break; }
            }
            if (!covered) {
                rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "%s relocation at RVA %#x is not covered by any patch run", i == 0 ? "patched-only" : "stock-only",
                              (unsigned)a->v[k]);
                goto done;
            }
        }
    }

    /* Appended sections: tail bytes + the patched relocations that fall inside them. */
    if (ph.soi > sh.soi) {
        const uint32_t total = ph.soi - sh.soi;
        size_t k;
        secbuf = (uint8_t *)calloc(total, 1u);
        if (!secbuf) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (sections)"); goto done; }
        for (i = sh.nsec; i < ph.nsec; ++i) {
            const gp_sec *s = &ph.sec[i];
            uint32_t n = s->rawsize < align_up(s->vsize, GP_PAGE) ? s->rawsize : align_up(s->vsize, GP_PAGE);
            if (n) memcpy(secbuf + (s->va - sh.soi), b.new_tail + (s->rawptr - b.stock_len), n);
        }
        for (k = gp_lower_bound(&patched_fix, sh.soi); k < patched_fix.n; ++k) {
            const uint32_t f = patched_fix.v[k];
            int inside = 0;
            for (i = sh.nsec; i < ph.nsec; ++i)
                if (f >= ph.sec[i].va && f + 4u <= ph.sec[i].va + ph.sec[i].vsize) { inside = 1; break; }
            if (!inside) { rc = gp_error(rep, KNTWR_GP_E_LAYOUT, "relocation at RVA %#x is outside every appended section", (unsigned)f); goto done; }
            wr32u(secbuf + (f - sh.soi), rd32u(secbuf + (f - sh.soi)) + delta);
            rep->section_fixups++;
        }
    }

    /* Proof points for live read-back: the first run that becomes a jump into an appended section, and the first section bytes. */
    for (i = 0; i < b.run_count; ++i) {
        const gp_run *r = &b.runs[i];
        if (!r->header && !r->pinned && r->len >= 5u && r->new_b[0] == 0xE9u && gp_run_selected(filter, r->idx)) {
            const uint32_t target = r->rva + 5u + rd32u(r->new_b + 1);
            if (target >= sh.soi && target < ph.soi) {
                rep->proof_site_va = base + r->rva;
                rep->proof_target_va = base + target;
                memcpy(rep->proof_site_bytes, r->new_b, 5);
                break;
            }
        }
    }
    if (secbuf) {
        rep->proof_section_va = base + sh.soi;
        memcpy(rep->proof_section_bytes, secbuf, 8);
    }

    /* ---- verification complete: nothing has been written yet ---- */
    rep->phase = 1;
    if (ph.soi > sh.soi) {
        uint32_t done = 0;
        rep->phase = 0; /* still reading; nothing written yet */
        imgbuf = (uint8_t *)malloc(sh.soi);
        if (!imgbuf) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (image snapshot)"); goto done; }
        while (done < sh.soi) {
            const uint32_t n = sh.soi - done > (1u << 20) ? (1u << 20) : (sh.soi - done);
            if ((rc = gp_mem_read(mem, base + done, imgbuf + done, n, rep, "the stock image")) != 0) goto done;
            done += n;
        }
        memcpy(imgbuf, hdr_new, ph.soh);
        {
            kntwr_gp_remalloc_diag ra;
            memset(&ra, 0, sizeof ra);
            if (mem->remalloc(mem->ctx, base, sh.soi, ph.soi, hdr_new, ph.soh, &ra) != 0) {
                rep->remap = ra;
                rep->phase = ra.mutated ? 1u : 0u; /* an unmapped old view is a changed target, even though nothing was written */
                rc = gp_error(rep, (ra.stage == KNTWR_GP_RA_TAIL_FOREIGN || ra.stage == KNTWR_GP_RA_TAIL_QUERY) ? KNTWR_GP_E_ALLOC : KNTWR_GP_E_REMAP,
                              "remap failed at stage %s (%s %#lx)%s; range [%#x, %#x); region %#x+%#x state %#x type %#x alloc-base %#x",
                              kntwr_gp_remalloc_stage_name(ra.stage), ra.code_is_ntstatus ? "NTSTATUS" : "Win32", (unsigned long)ra.code,
                              ra.mutated ? " (the old image was already unmapped)" : " (nothing changed)", (unsigned)(base + sh.soi),
                              (unsigned)(base + ph.soi), (unsigned)ra.region_base, (unsigned)ra.region_size, (unsigned)ra.region_state,
                              (unsigned)ra.region_type, (unsigned)ra.region_alloc_base);
                goto done;
            }
            rep->remap = ra;
        }
        rep->phase = 1;
        if (mem->write(mem->ctx, base, imgbuf, sh.soi) != 0 || mem->write(mem->ctx, base + sh.soi, secbuf, ph.soi - sh.soi) != 0) {
            rc = gp_error(rep, KNTWR_GP_E_WRITE, "writing the expanded image failed");
            goto done;
        }
        if (mem->protect(mem->ctx, base, ph.soh, 0x02u /* PAGE_READONLY */) != 0) {
            rc = gp_error(rep, KNTWR_GP_E_WRITE, "protecting the PE header failed");
            goto done;
        }
        for (i = 0; i < ph.nsec; ++i) {
            if (mem->protect(mem->ctx, base + ph.sec[i].va, align_up(ph.sec[i].vsize, GP_PAGE), gp_protection(ph.sec[i].chars)) != 0) {
                rc = gp_error(rep, KNTWR_GP_E_WRITE, "protecting section %u failed", (unsigned)i);
                goto done;
            }
        }
    }
    /* Without a remapped image (e.g. mss32.dll) the target is a live module: from here every failure restores the original
       bytes (see done:).  The exe path replaces the whole image and cannot roll back: the caller discards that process. */
    rollback_armed = (ph.soi == sh.soi);
    /* Write from high RVA to low RVA: in an already-loaded DLL (mss32.dll), high-RVA stub caves are populated before the
       low-RVA call sites that branch into them. */
    for (i = plan_n; i > 0; --i) {
        if (mem->write(mem->ctx, base + plan[i - 1].rva, plan[i - 1].data, plan[i - 1].len) != 0) {
            rc = gp_error(rep, KNTWR_GP_E_WRITE, "writing the patch window at %#x failed", (unsigned)(base + plan[i - 1].rva));
            goto done;
        }
    }
    rep->runs_applied = app_runs;
    rep->bytes_applied = app_total;

    /* Read everything back. */
    {
        uint8_t *chk = (uint8_t *)malloc(ph.soi > sh.soi ? ph.soi - sh.soi : 1u);
        uint32_t maxw = 0;
        for (i = 0; i < plan_n; ++i) if (plan[i].len > maxw) maxw = plan[i].len;
        if (!chk) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (verify)"); goto done; }
        if (ph.soi > sh.soi) {
            if (mem->read(mem->ctx, base + sh.soi, chk, ph.soi - sh.soi) != 0 || memcmp(chk, secbuf, ph.soi - sh.soi) != 0) {
                free(chk);
                rc = gp_error(rep, KNTWR_GP_E_VERIFY, "appended-section read-back mismatch");
                goto done;
            }
            if (mem->read(mem->ctx, base, chk, ph.soh) != 0 || memcmp(chk, hdr_new, ph.soh) != 0) {
                free(chk);
                rc = gp_error(rep, KNTWR_GP_E_VERIFY, "patched PE header read-back mismatch");
                goto done;
            }
        }
        free(chk);
        chk = (uint8_t *)malloc(maxw ? maxw : 1u);
        if (!chk) { rc = gp_error(rep, KNTWR_GP_E_NOMEM, "out of memory (verify)"); goto done; }
        for (i = 0; i < plan_n; ++i) {
            if (mem->read(mem->ctx, base + plan[i].rva, chk, plan[i].len) != 0 || memcmp(chk, plan[i].data, plan[i].len) != 0) {
                free(chk);
                rep->fail_va = base + plan[i].rva;
                rc = gp_error(rep, KNTWR_GP_E_VERIFY, "read-back mismatch at %#x", (unsigned)(base + plan[i].rva));
                goto done;
            }
        }
        free(chk);
    }
    rep->status = KNTWR_GP_OK;
    rc = 0;
    rollback_armed = 0;

done:
    if (rc != 0 && rollback_armed) {
        /* Restore low RVA first (call sites before the caves they branch into), then verify every window byte for byte. */
        int ok = 1;
        uint8_t *chk = NULL;
        uint32_t maxw = 0;
        for (i = 0; i < plan_n; ++i) if (plan[i].len > maxw) maxw = plan[i].len;
        chk = (uint8_t *)malloc(maxw ? maxw : 1u);
        for (i = 0; i < plan_n; ++i)
            if (mem->write(mem->ctx, base + plan[i].rva, plan[i].orig, plan[i].len) != 0) ok = 0;
        for (i = 0; ok && i < plan_n; ++i)
            if (!chk || mem->read(mem->ctx, base + plan[i].rva, chk, plan[i].len) != 0 || memcmp(chk, plan[i].orig, plan[i].len) != 0) ok = 0;
        free(chk);
        rep->rollback = ok ? KNTWR_GP_ROLLBACK_RESTORED : KNTWR_GP_ROLLBACK_FAILED;
        {
            const size_t used = strlen(rep->error);
            snprintf(rep->error + used, sizeof rep->error - used, "%s",
                     ok ? " [rolled back: original bytes restored and verified]" : " [ROLLBACK FAILED: target is partially patched]");
        }
    }
    if (plan) {
        for (i = 0; i < plan_n; ++i) { free(plan[i].data); free(plan[i].orig); }
        free(plan);
    }
    free(secbuf);
    free(imgbuf);
    free(rbuf);
    free(pbuf);
    free(stock_fix.v);
    free(patched_fix.v);
    free(b.runs);
    return rc;
}

int kntwr_gp_apply_filtered(const kntwr_gp_memory *mem, uint32_t base, uint32_t preferred, const uint8_t *blob, uint32_t blob_size,
                           const kntwr_gp_filter *filter, kntwr_gp_report *rep)
{
    return gp_apply_impl(mem, base, preferred, blob, blob_size, filter, rep);
}

int kntwr_gp_apply(const kntwr_gp_memory *mem, uint32_t base, uint32_t preferred, const uint8_t *blob, uint32_t blob_size,
                  kntwr_gp_report *rep)
{
    return kntwr_gp_apply_filtered(mem, base, preferred, blob, blob_size, NULL, rep);
}

/* ------------------------------------------------------------------------------------------------ process backend */
#ifdef _WIN32
static int pm_fail(void)
{
    const DWORD e = GetLastError();
    return e ? (int)e : 1;
}

static int pm_read(void *ctx, uint32_t va, void *dst, uint32_t n)
{
    const kntwr_gp_pm *pm = (const kntwr_gp_pm *)ctx;
    SIZE_T got = 0;
    if (!ReadProcessMemory((HANDLE)pm->process, (LPCVOID)(uintptr_t)va, dst, n, &got) || got != n) return pm_fail();
    return 0;
}

static int pm_write(void *ctx, uint32_t va, const void *src, uint32_t n)
{
    const kntwr_gp_pm *pm = (const kntwr_gp_pm *)ctx;
    HANDLE h = (HANDLE)pm->process;
    uint32_t done = 0;
    while (done < n) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD oldp = 0, tmp = 0;
        SIZE_T wrote = 0;
        const uint32_t cur = va + done;
        uint32_t chunk;
        BOOL ok;
        if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)cur, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) return 1;
        chunk = (uint32_t)((uintptr_t)mbi.BaseAddress + mbi.RegionSize - cur);
        if (chunk > n - done) chunk = n - done;
        if (!VirtualProtectEx(h, (LPVOID)(uintptr_t)cur, chunk, PAGE_EXECUTE_READWRITE, &oldp)) return pm_fail();
        ok = WriteProcessMemory(h, (LPVOID)(uintptr_t)cur, (const uint8_t *)src + done, chunk, &wrote) && wrote == chunk;
        if (!ok) { const int e = pm_fail(); VirtualProtectEx(h, (LPVOID)(uintptr_t)cur, chunk, oldp, &tmp); return e; }
        VirtualProtectEx(h, (LPVOID)(uintptr_t)cur, chunk, oldp, &tmp);
        FlushInstructionCache(h, (LPCVOID)(uintptr_t)cur, chunk);
        done += chunk;
    }
    return 0;
}

typedef LONG(NTAPI *nt_unmap_fn)(HANDLE, PVOID);
typedef LONG(NTAPI *nt_create_section_fn)(PHANDLE, ACCESS_MASK, void *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG(NTAPI *nt_map_view_fn)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, LARGE_INTEGER *, SIZE_T *, DWORD, DWORD, DWORD);

/* The backing image of a remap: a header-only PE (patched header, no data directories, no raw data) whose kernel view is
   demand-zero, so every page the applier writes is a plain copy-on-write private page of an image-typed mapping.  The
   handle is deliberately held for the life of this process: DELETE_ON_CLOSE is silently skipped while the image view
   exists (the kernel's MmFlushImageSection check fails the delete), so the file only disappears once the target's view
   is gone and our handle is closed; files left behind by a crashed run are swept by the next remap.  No FILE_SHARE_DELETE,
   so an external deleter (including that sweep) cannot race this handle. */
static HANDLE gp_backing_keep[64];
static unsigned gp_backing_n;

static void gp_sweep_backings(void)
{
    wchar_t dir[MAX_PATH], pat[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    if (!GetTempPathW(MAX_PATH, dir)) return;
    if (swprintf(pat, MAX_PATH, L"%lskntwr-gp-image-*.tmp", dir) <= 0) return;
    find = FindFirstFileW(pat, &fd);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t path[MAX_PATH];
        if (swprintf(path, MAX_PATH, L"%ls%ls", dir, fd.cFileName) > 0) DeleteFileW(path); /* in use => fails, fine */
    } while (FindNextFileW(find, &fd));
    FindClose(find);
}

/* Build the header-only backing image: patched_header with ImageBase = va, every data directory cleared and every
   section's raw size/pointer zeroed (demand-zero).  gp_parse_header has validated the layout. */
static int gp_skeleton(const uint8_t *patched_header, uint32_t header_len, uint32_t va, uint8_t *out, uint32_t out_len)
{
    const uint32_t lf = rd32(patched_header + 0x3c);
    const uint32_t opt = lf + 24u;
    const uint32_t nsec = (uint32_t)(patched_header[lf + 6] | (patched_header[lf + 7] << 8));
    const uint32_t opt_size = (uint32_t)(patched_header[lf + 20] | (patched_header[lf + 21] << 8));
    const uint32_t table = opt + opt_size;
    const uint32_t ndir = rd32(patched_header + opt + 92);
    uint32_t i;
    if (header_len == 0 || header_len > out_len) return 1;
    memcpy(out, patched_header, header_len);
    wr32u(out + opt + 28, va); /* ImageBase = the exact view address: the kernel maps it unrelocated */
    wr32u(out + opt + 64, 0); /* CheckSum */
    if ((uint64_t)opt + 96u + 8ull * ndir > header_len) return 1;
    for (i = 0; i < ndir; ++i) memset(out + opt + 96u + 8u * i, 0, 8); /* no imports, no relocs: nothing for the kernel to do */
    for (i = 0; i < nsec; ++i) {
        uint8_t *s = out + table + 40u * i;
        if ((uint64_t)(table + 40u * i + 40u) > header_len) return 1;
        wr32u(s + 16, 0); /* SizeOfRawData = 0 */
        wr32u(s + 20, 0); /* PointerToRawData = 0 */
    }
    return 0;
}

static uint32_t ra_win32_error(void)
{
    const DWORD e = GetLastError();
    return e ? (uint32_t)e : (uint32_t)ERROR_GEN_FAILURE;
}

static int ra_fail(kntwr_gp_remalloc_diag *d, uint32_t stage, uint32_t code, uint32_t is_ntstatus)
{
    d->stage = stage;
    d->code = code;
    d->code_is_ntstatus = is_ntstatus;
    return 1;
}

static void ra_region(kntwr_gp_remalloc_diag *d, const MEMORY_BASIC_INFORMATION *m)
{
    d->region_base = (uint32_t)(uintptr_t)m->BaseAddress;
    d->region_size = m->RegionSize > UINT32_MAX ? UINT32_MAX : (uint32_t)m->RegionSize;
    d->region_state = (uint32_t)m->State;
    d->region_type = (uint32_t)m->Type;
    d->region_alloc_base = (uint32_t)(uintptr_t)m->AllocationBase;
}

/* The creation-time reservation (kntwr_gp_pm::owned_reserve_*): the region the kernel was asked to reserve for this image
   at process creation.  It is accepted as part of the tail (and released) only when the live region matches the recording
   EXACTLY: one region, MEM_RESERVE | MEM_PRIVATE, AllocationBase == the recorded base, exactly the recorded span. */
static int ra_region_is_owned(const kntwr_gp_pm *pm, const MEMORY_BASIC_INFORMATION *m)
{
    return pm->owned_reserve_size && m->BaseAddress == (PVOID)(uintptr_t)pm->owned_reserve_base &&
           m->AllocationBase == m->BaseAddress && m->RegionSize == (SIZE_T)pm->owned_reserve_size &&
           m->State == MEM_RESERVE && m->Type == MEM_PRIVATE;
}

/* Preflight: every region of [lo, hi) must be MEM_FREE or exactly the recorded reservation.  Validates only; the
   reservation is NOT released here, so a foreign page (or a later pre-remap failure) never consumes it. */
static int ra_validate_tail(const kntwr_gp_pm *pm, HANDLE h, uint32_t lo, uint32_t hi, kntwr_gp_remalloc_diag *d)
{
    uint64_t cur = lo;
    while (cur < hi) {
        MEMORY_BASIC_INFORMATION mbi;
        uint64_t end;
        if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)cur, &mbi, sizeof mbi)) return ra_fail(d, KNTWR_GP_RA_TAIL_QUERY, ra_win32_error(), 0);
        ra_region(d, &mbi);
        if (mbi.State != MEM_FREE && !ra_region_is_owned(pm, &mbi)) return ra_fail(d, KNTWR_GP_RA_TAIL_FOREIGN, ERROR_INVALID_ADDRESS, 0);
        end = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (end <= cur) return ra_fail(d, KNTWR_GP_RA_TAIL_QUERY, ERROR_INVALID_ADDRESS, 0);
        cur = end;
    }
    return 0;
}

/* Immediately before the old view is unmapped: revalidate the recorded reservation (it must still be exactly the pinned
   region) and release only it, exactly once. */
static int ra_release_reserve(kntwr_gp_pm *pm, HANDLE h, kntwr_gp_remalloc_diag *d)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!pm->owned_reserve_size) return 0;
    if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)pm->owned_reserve_base, &mbi, sizeof mbi))
        return ra_fail(d, KNTWR_GP_RA_TAIL_QUERY, ra_win32_error(), 0);
    ra_region(d, &mbi);
    if (!ra_region_is_owned(pm, &mbi)) return ra_fail(d, KNTWR_GP_RA_TAIL_FOREIGN, ERROR_INVALID_ADDRESS, 0);
    if (!VirtualFreeEx(h, (LPVOID)(uintptr_t)pm->owned_reserve_base, 0, MEM_RELEASE))
        return ra_fail(d, KNTWR_GP_RA_TAIL_RELEASE, ra_win32_error(), 0);
    pm->owned_reserve_base = 0; /* exactly once: a later remap sees no owned reservation */
    pm->owned_reserve_size = 0;
    return 0;
}

static int pm_remalloc(void *ctx, uint32_t va, uint32_t old_size, uint32_t new_size,
                       const uint8_t *patched_header, uint32_t header_len, kntwr_gp_remalloc_diag *diag)
{
    kntwr_gp_pm *pm = (kntwr_gp_pm *)ctx;
    HANDLE h = (HANDLE)pm->process;
    MEMORY_BASIC_INFORMATION mbi;
    HMODULE ntdll;
    nt_unmap_fn unmap;
    nt_create_section_fn create_section;
    nt_map_view_fn map_view;
    uint8_t skel[0x1000];
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    HANDLE file = INVALID_HANDLE_VALUE, section = NULL;
    LARGE_INTEGER max_size;
    PVOID view = (PVOID)(uintptr_t)va;
    SIZE_T view_size = 0;
    unsigned attempt;
    DWORD wrote = 0;
    LONG st;
    kntwr_gp_remalloc_diag scratch;
    kntwr_gp_remalloc_diag *d = diag ? diag : &scratch;

    memset(d, 0, sizeof *d);
    if (ra_validate_tail(pm, h, va + old_size, va + new_size, d) != 0) return 1; /* refuse before any change; the reservation stays */
    d->region_base = d->region_size = d->region_state = d->region_type = d->region_alloc_base = 0;
    if (gp_skeleton(patched_header, header_len, va, skel, sizeof skel) != 0) return ra_fail(d, KNTWR_GP_RA_PARAMS, ERROR_INVALID_PARAMETER, 0);
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return ra_fail(d, KNTWR_GP_RA_NTDLL, ra_win32_error(), 0);
    unmap = (nt_unmap_fn)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    create_section = (nt_create_section_fn)GetProcAddress(ntdll, "NtCreateSection");
    map_view = (nt_map_view_fn)GetProcAddress(ntdll, "NtMapViewOfSection");
    if (!unmap || !create_section || !map_view) return ra_fail(d, KNTWR_GP_RA_NTDLL, ra_win32_error(), 0);

    gp_sweep_backings();
    if (!GetTempPathW(MAX_PATH, dir)) return ra_fail(d, KNTWR_GP_RA_BACKING_CREATE, ra_win32_error(), 0);
    for (attempt = 0; attempt < 4096 && file == INVALID_HANDLE_VALUE; ++attempt) {
        if (swprintf(path, MAX_PATH, L"%lskntwr-gp-image-%lu-%lu-%u.tmp", dir, GetCurrentProcessId(), GetTickCount(), attempt) <= 0)
            return ra_fail(d, KNTWR_GP_RA_BACKING_CREATE, ERROR_INSUFFICIENT_BUFFER, 0);
        file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (file == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_EXISTS) return ra_fail(d, KNTWR_GP_RA_BACKING_CREATE, ra_win32_error(), 0);
    }
    if (file == INVALID_HANDLE_VALUE) return ra_fail(d, KNTWR_GP_RA_BACKING_CREATE, ERROR_FILE_EXISTS, 0);
    if (!WriteFile(file, skel, header_len, &wrote, NULL) || wrote != header_len) { ra_fail(d, KNTWR_GP_RA_BACKING_WRITE, ra_win32_error(), 0); goto fail; }
    max_size.QuadPart = 0;
    st = create_section(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_EXECUTE_WRITECOPY, SEC_IMAGE, file);
    if (st != 0) { section = NULL; ra_fail(d, KNTWR_GP_RA_SECTION, (uint32_t)st, 1); goto fail; }
    /* The backing image exists while the reservation is still held; only now, at the remap itself, revalidate and release
       exactly our reservation.  A preflight or backing/section failure above never consumed it. */
    if (ra_release_reserve(pm, h, d) != 0) goto fail;
    /* Free the old mapping by type: a section view (the stock loader view, or a previous remap) via NtUnmapViewOfSection
       (it takes the reserved tail with it), a private allocation (the oracle's in-process stock mapping) via
       VirtualFreeEx.  Either way the replacement is the same SEC_IMAGE view; once the old view is gone the caller must
       discard that process (diag->mutated). */
    if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)va, &mbi, sizeof mbi)) { ra_fail(d, KNTWR_GP_RA_UNMAP, ra_win32_error(), 0); goto fail; }
    ra_region(d, &mbi);
    if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
        st = unmap(h, (PVOID)(uintptr_t)va);
        if (st != 0) { ra_fail(d, KNTWR_GP_RA_UNMAP, (uint32_t)st, 1); goto fail; }
    } else if (!VirtualFreeEx(h, (LPVOID)(uintptr_t)va, 0, MEM_RELEASE)) {
        ra_fail(d, KNTWR_GP_RA_UNMAP, ra_win32_error(), 0);
        goto fail;
    }
    d->mutated = 1;
    {   /* ViewUnmap = 1, no AllocationType, PAGE_EXECUTE_WRITECOPY: the kernel may answer a warning (e.g. IMAGE_NOT_AT_BASE). */
        st = map_view(section, h, &view, 0, 0, NULL, &view_size, 1, 0, PAGE_EXECUTE_WRITECOPY);
        if (st < 0 || view != (PVOID)(uintptr_t)va || view_size < (SIZE_T)new_size) { ra_fail(d, KNTWR_GP_RA_MAP, (uint32_t)st, 1); goto fail; }
    }
    if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)va, &mbi, sizeof mbi)) { ra_fail(d, KNTWR_GP_RA_VERIFY, ra_win32_error(), 0); goto fail; }
    if (mbi.Type != MEM_IMAGE || mbi.AllocationBase != (PVOID)(uintptr_t)va) {
        ra_region(d, &mbi);
        ra_fail(d, KNTWR_GP_RA_VERIFY, ERROR_INVALID_ADDRESS, 0);
        goto fail;
    }
    CloseHandle(section);
    if (gp_backing_n < sizeof gp_backing_keep / sizeof gp_backing_keep[0])
        gp_backing_keep[gp_backing_n++] = file; /* keep DELETE_ON_CLOSE armed until this process exits */
    else
        CloseHandle(file); /* registry full (many remaps in one process): the file outlives the view; the next sweep takes it */
    memset(d, 0, sizeof *d);
    return 0;

fail:
    if (section) CloseHandle(section);
    CloseHandle(file);
    return 1;
}

static int pm_protect(void *ctx, uint32_t va, uint32_t size, uint32_t prot)
{
    const kntwr_gp_pm *pm = (const kntwr_gp_pm *)ctx;
    DWORD old = 0;
    return VirtualProtectEx((HANDLE)pm->process, (LPVOID)(uintptr_t)va, size, prot, &old) ? 0 : pm_fail();
}

void kntwr_gp_pm_init(kntwr_gp_pm *pm, void *handle)
{
    pm->process = handle;
    pm->owned_reserve_base = 0;
    pm->owned_reserve_size = 0;
}

kntwr_gp_memory kntwr_gp_pm_memory(kntwr_gp_pm *pm)
{
    kntwr_gp_memory m;
    m.ctx = pm;
    m.read = pm_read;
    m.write = pm_write;
    m.remalloc = pm_remalloc;
    m.protect = pm_protect;
    return m;
}

/* ------------------------------------------------------------------------------------------------ creation-time reservation */

/* Minimal NT declarations (resolved at runtime, never linked). */
typedef LONG(NTAPI *gp_nt_create_user_process_fn)(void *, void *, ULONG, ULONG, void *, void *, ULONG, ULONG, void *, void *, void *);
typedef LONG(NTAPI *gp_nt_query_section_fn)(HANDLE, int, PVOID, ULONG, PULONG);

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((LONG)0xC000000DL)
#endif

typedef struct gp_ps_attribute {
    uintptr_t attribute;
    SIZE_T size;
    uintptr_t value;            /* Value / ValuePtr share the storage */
    SIZE_T *retlen;
} gp_ps_attribute;

typedef struct gp_ps_attribute_list {
    SIZE_T total;
    gp_ps_attribute attrs[1];
} gp_ps_attribute_list;

typedef struct gp_ps_memory_reserve {
    void *address;
    SIZE_T size;
} gp_ps_memory_reserve;

typedef struct gp_section_image_information { /* SectionImageInformation, 48 bytes on Win32 */
    void *transfer_address;
    uint32_t zero_bits;
    SIZE_T max_stack, committed_stack;
    uint32_t subsys_type;
    uint32_t subsys_version;
    uint32_t os_version;
    uint16_t image_char, dll_char, machine;
    uint8_t contains_code, image_flags;
    uint32_t loader_flags, image_file_size, checksum;
} gp_section_image_information;
typedef char gp_sii_size_check[(sizeof(gp_section_image_information) == 48) ? 1 : -1];

/* Scoped wrapper around the launcher process's OWN KernelBase import slot for NtCreateUserProcess.  Single thread, single
   call: installed by kntwr_gp_reserve_hook, wraps exactly the one child-creating call on the owning thread (a second call,
   a malformed attribute list or a pre-existing memory-reserve attribute is refused with STATUS_INVALID_PARAMETER, failing
   that child creation), and restored by kntwr_gp_reserve_unhook immediately after CreateProcessW returns.  gp_rsv_orig is
   published BEFORE the slot ever holds the wrapper and is never cleared (ntdll never unloads), so any thread reaching the
   slot always finds a valid original; gp_rsv_installed is the separate ownership state (0 = the slot is not ours). */
static gp_nt_create_user_process_fn gp_rsv_orig;
static void **gp_rsv_slot;
static volatile LONG gp_rsv_installed;
static volatile LONG gp_rsv_enabled;
static volatile DWORD gp_rsv_owner;
static volatile LONG gp_rsv_calls_seen;
static volatile LONG gp_rsv_calls_modified;
static volatile LONG gp_rsv_reject;      /* 1 malformed list, 2 too many attributes, 3 attribute already present, 4 second call */
static volatile LONG gp_rsv_status;      /* NTSTATUS returned to the (one) child-creating call */
static volatile LONG gp_rsv_has_status;
static volatile uintptr_t gp_rsv_addr;
static volatile SIZE_T gp_rsv_size;

static LONG NTAPI gp_hook_nt_create_user_process(void *proc, void *thread, ULONG pa, ULONG ta, void *po, void *to,
                                                 ULONG flags, ULONG dbg, void *tok, void *ctx, void *attr_list)
{
    const gp_ps_attribute_list *in = (const gp_ps_attribute_list *)attr_list;
    uint8_t buf[1024];
    gp_ps_attribute_list *out = (gp_ps_attribute_list *)buf;
    gp_ps_memory_reserve res;
    size_t count, i, bytes;
    LONG st;
    if (!gp_rsv_enabled || GetCurrentThreadId() != gp_rsv_owner)
        return gp_rsv_orig(proc, thread, pa, ta, po, to, flags, dbg, tok, ctx, attr_list);
    InterlockedIncrement(&gp_rsv_calls_seen);
    if (InterlockedCompareExchange(&gp_rsv_calls_modified, 1, 0) != 0) { gp_rsv_reject = 4; goto refuse; }
    if (!in || in->total < sizeof(SIZE_T) || (in->total - sizeof(SIZE_T)) % sizeof(gp_ps_attribute) != 0) { gp_rsv_reject = 1; goto refuse; }
    count = (in->total - sizeof(SIZE_T)) / sizeof(gp_ps_attribute);
    if (count > 30) { gp_rsv_reject = 2; goto refuse; }
    for (i = 0; i < count; ++i)
        if ((in->attrs[i].attribute & 0xFFFFu) == 7u) { gp_rsv_reject = 3; goto refuse; } /* a memory-reserve attribute is already present */
    bytes = sizeof(SIZE_T) + (count + 1u) * sizeof(gp_ps_attribute);
    if (bytes > sizeof buf) { gp_rsv_reject = 2; goto refuse; }
    out->total = bytes;
    if (count) memcpy(out->attrs, in->attrs, count * sizeof(gp_ps_attribute)); /* every original attribute and its outputs pass through */
    res.address = (void *)gp_rsv_addr;
    res.size = gp_rsv_size;
    memset(&out->attrs[count], 0, sizeof out->attrs[count]);
    out->attrs[count].attribute = 0x00020007u; /* PS_ATTRIBUTE_MEMORY_RESERVE (input-only) */
    out->attrs[count].size = sizeof res;
    out->attrs[count].value = (uintptr_t)&res;
    out->attrs[count].retlen = NULL;
    st = gp_rsv_orig(proc, thread, pa, ta, po, to, flags, dbg, tok, ctx, out);
    gp_rsv_status = st;
    gp_rsv_has_status = 1;
    return st;
refuse:
    gp_rsv_status = STATUS_INVALID_PARAMETER;
    gp_rsv_has_status = 1;
    return STATUS_INVALID_PARAMETER;
}

/* The IAT slot of `module`'s import of `want_name` from `want_dll` (or the slot holding `genuine`, for ordinal imports). */
static void **gp_find_import_slot(HMODULE module, const char *want_dll, const char *want_name, const void *genuine)
{
    const uint8_t *base = (const uint8_t *)module;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_IMPORT_DESCRIPTOR *imp;
    uint32_t dir;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!dir) return NULL;
    imp = (const IMAGE_IMPORT_DESCRIPTOR *)(base + dir);
    for (; imp->Name; ++imp) {
        const char *dll = (const char *)(base + imp->Name);
        const IMAGE_THUNK_DATA *name_thunk, *iat;
        if (_stricmp(dll, want_dll) != 0) continue;
        name_thunk = (const IMAGE_THUNK_DATA *)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        iat = (const IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; name_thunk->u1.AddressOfData; ++name_thunk, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
                if ((const void *)(uintptr_t)iat->u1.Function == genuine) return (void **)&iat->u1.Function;
                continue;
            }
            {
                const IMAGE_IMPORT_BY_NAME *ibn = (const IMAGE_IMPORT_BY_NAME *)(base + name_thunk->u1.AddressOfData);
                if (strcmp((const char *)ibn->Name, want_name) == 0) return (void **)&iat->u1.Function;
            }
        }
        return NULL; /* the dll is imported, but not this function */
    }
    return NULL;
}

const char *kntwr_gp_reserve_stage_name(uint32_t stage)
{
    static const char *const names[] = { "none", "blob", "source", "section", "query", "ntdll", "imports", "foreign-hook", "hook",
                                         "restore", "base", "tail" };
    return stage < sizeof names / sizeof names[0] ? names[stage] : "unknown";
}

static int rs_fail(kntwr_gp_reserve_report *rep, uint32_t status, uint32_t stage, uint32_t code, uint32_t is_ntstatus, const char *fmt, ...)
{
    va_list ap;
    rep->status = status;
    rep->stage = stage;
    rep->code = code;
    rep->code_is_ntstatus = is_ntstatus;
    va_start(ap, fmt);
    vsnprintf(rep->error, sizeof rep->error, fmt, ap);
    va_end(ap);
    rep->error[sizeof rep->error - 1] = 0;
    return (int)status;
}

/* A failure reported through a kntwr_gp_report by a shared helper (blob/header parsing) becomes a reserve failure. */
static int rs_from_report(kntwr_gp_reserve_report *rep, uint32_t stage, const kntwr_gp_report *from)
{
    return rs_fail(rep, from->status, stage, 0, 0, "%s", from->error);
}

int kntwr_gp_reserve_plan(void *source_file, const uint8_t *blob, uint32_t blob_size,
                          kntwr_gp_reserve *rsv, kntwr_gp_reserve_report *rep)
{
    HANDLE src = (HANDLE)source_file, section = NULL;
    kntwr_gp_report tmp;
    gp_blob b;
    gp_hdr sh;
    uint8_t hdr[GP_HDR_READ];
    LARGE_INTEGER sz, zero;
    DWORD got = 0;
    uint32_t field, patched_soi, entry;
    HMODULE ntdll;
    nt_create_section_fn create_section;
    gp_nt_query_section_fn query_section;
    gp_section_image_information sii;
    uint64_t a, e;
    LONG st;
    int rc = 0;

    memset(rsv, 0, sizeof *rsv);
    memset(rep, 0, sizeof *rep);
    memset(&tmp, 0, sizeof tmp);
    memset(&b, 0, sizeof b);
    zero.QuadPart = 0;

    if (gp_parse_blob(blob, blob_size, &b, &tmp) != 0) { rc = rs_from_report(rep, KNTWR_GP_RS_BLOB, &tmp); goto done; }
    if (!src || src == INVALID_HANDLE_VALUE) { rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_SOURCE, 0, 0, "no source file handle"); goto done; }
    if (!GetFileSizeEx(src, &sz)) { rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_SOURCE, ra_win32_error(), 0, "cannot size the source image"); goto done; }
    if ((uint64_t)sz.QuadPart != b.stock_len) {
        rc = rs_fail(rep, KNTWR_GP_E_STOCK, KNTWR_GP_RS_SOURCE, 0, 0, "the source image is %llu bytes, the patch expects the stock %llu",
                     (unsigned long long)sz.QuadPart, (unsigned long long)b.stock_len);
        goto done;
    }
    if (!SetFilePointerEx(src, zero, NULL, FILE_BEGIN) || !ReadFile(src, hdr, sizeof hdr, &got, NULL) || got != sizeof hdr) {
        rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_SOURCE, ra_win32_error(), 0, "cannot read the source image header");
        goto done;
    }
    if (gp_parse_header(hdr, sizeof hdr, &sh, &tmp, "source image") != 0) { rc = rs_from_report(rep, KNTWR_GP_RS_SOURCE, &tmp); goto done; }
    field = rd32(hdr + 0x3c) + 24u + 56u; /* SizeOfImage; e_lfanew validated by gp_parse_header */
    entry = rd32(hdr + rd32(hdr + 0x3c) + 24u + 16u); /* AddressOfEntryPoint */
    if (gp_soi_derive(&b, field, sh.soi, &patched_soi, &tmp) != 0) { rc = rs_from_report(rep, KNTWR_GP_RS_BLOB, &tmp); goto done; }
    rsv->stock_soi = sh.soi;
    rsv->patched_soi = patched_soi;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_NTDLL, ra_win32_error(), 0, "ntdll.dll is not loaded"); goto done; }
    create_section = (nt_create_section_fn)GetProcAddress(ntdll, "NtCreateSection");
    query_section = (gp_nt_query_section_fn)GetProcAddress(ntdll, "NtQuerySection");
    if (!create_section || !query_section) { rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_NTDLL, 0, 0, "NtCreateSection/NtQuerySection unavailable"); goto done; }
    st = create_section(&section, SECTION_QUERY | SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, src);
    if (st != 0) { section = NULL; rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_SECTION, (uint32_t)st, 1, "cannot open an image section of the source"); goto done; }
    memset(&sii, 0, sizeof sii);
    st = query_section(section, 1 /* SectionImageInformation */, &sii, sizeof sii, NULL);
    if (st != 0) { rc = rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_QUERY, (uint32_t)st, 1, "cannot query the image section"); goto done; }
    rsv->predicted_base = (uint32_t)(uintptr_t)sii.transfer_address - entry;

    /* Only the computed 64 KiB-aligned tail above the stock image is reserved (normally a single 64 KiB block). */
    a = ((uint64_t)rsv->predicted_base + sh.soi + 0xFFFFu) & ~(uint64_t)0xFFFFu;
    e = ((uint64_t)rsv->predicted_base + patched_soi + 0xFFFFu) & ~(uint64_t)0xFFFFu;
    if (!rsv->predicted_base || e <= a || e - a > 0x4000000u || e > 0x7FFF0000ull) {
        rc = rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_BLOB, 0, 0,
                     "the derived reservation [%#llx, %#llx) is not a bounded tail above the stock image", (unsigned long long)a, (unsigned long long)e);
        goto done;
    }
    rsv->reserve_base = (uint32_t)a;
    rsv->reserve_size = (uint32_t)(e - a);
    rsv->section = section; /* pinned until kntwr_gp_reserve_dispose: held through CreateProcessW */
    section = NULL;

done:
    if (section) CloseHandle(section);
    free(b.runs);
    return rc;
}

int kntwr_gp_reserve_hook(kntwr_gp_reserve *rsv, kntwr_gp_reserve_report *rep)
{
    HMODULE ntdll, kb;
    void *genuine, **slot, *prev;
    DWORD oldp = 0, tmp = 0;

    memset(rep, 0, sizeof *rep);
    rsv->hook_installed = rsv->hook_restored = 0;
    rsv->calls_seen = rsv->calls_modified = rsv->reject = 0;
    rsv->hook_ntstatus = rsv->hook_has_status = 0;
    if (!rsv->reserve_size || !rsv->predicted_base) return rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_BLOB, 0, 0, "no reservation plan");
    /* Claim ownership of the wrapper state BEFORE publishing any per-launch global: a concurrent caller loses the CAS and
       can never overwrite the first caller's context.  0 = idle, 2 = claimed (installing), 1 = installed. */
    if (InterlockedCompareExchange(&gp_rsv_installed, 2, 0) != 0)
        return rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_HOOK, 0, 0, "the reservation wrapper is already installed");
    ntdll = GetModuleHandleW(L"ntdll.dll");
    kb = GetModuleHandleW(L"KernelBase.dll");
    if (!ntdll || !kb) { gp_rsv_installed = 0; return rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_NTDLL, ra_win32_error(), 0, "ntdll.dll or KernelBase.dll is not loaded"); }
    genuine = (void *)GetProcAddress(ntdll, "NtCreateUserProcess");
    if (!genuine) { gp_rsv_installed = 0; return rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_NTDLL, 0, 0, "NtCreateUserProcess is unavailable"); }
    slot = gp_find_import_slot(kb, "ntdll.dll", "NtCreateUserProcess", genuine);
    if (!slot) { gp_rsv_installed = 0; return rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_IMPORTS, 0, 0, "KernelBase.dll does not import NtCreateUserProcess"); }
    if (*slot != genuine) {
        gp_rsv_installed = 0;
        return rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_FOREIGN_HOOK, 0, 0, "the KernelBase import slot for NtCreateUserProcess does not hold the genuine export");
    }
    /* Publish the immutable original and the per-launch data BEFORE the slot can route any call to the wrapper. */
    gp_rsv_orig = (gp_nt_create_user_process_fn)genuine;
    gp_rsv_slot = slot;
    gp_rsv_owner = GetCurrentThreadId();
    gp_rsv_addr = rsv->reserve_base;
    gp_rsv_size = rsv->reserve_size;
    gp_rsv_calls_seen = gp_rsv_calls_modified = gp_rsv_reject = gp_rsv_status = gp_rsv_has_status = 0;
    gp_rsv_enabled = 0;
    if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldp)) {
        const DWORD e = ra_win32_error();
        gp_rsv_installed = 0;
        return rs_fail(rep, KNTWR_GP_E_WRITE, KNTWR_GP_RS_HOOK, e, 0, "cannot make the import slot writable");
    }
    rsv->slot_protect = oldp;
    prev = InterlockedCompareExchangePointer((void *volatile *)slot, (void *)&gp_hook_nt_create_user_process, genuine);
    if (prev != genuine) { /* a foreign owner raced in: the CAS wrote nothing */
        VirtualProtect(slot, sizeof(void *), oldp, &tmp);
        gp_rsv_installed = 0;
        return rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_FOREIGN_HOOK, 0, 0, "the import slot changed while the wrapper was being installed");
    }
    if (!VirtualProtect(slot, sizeof(void *), oldp, &tmp)) { /* undo the install; never leave the page writable or the wrapper half-live */
        const DWORD e = ra_win32_error();
        if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &tmp)) {
            InterlockedCompareExchangePointer((void *volatile *)slot, genuine, (void *)&gp_hook_nt_create_user_process);
            VirtualProtect(slot, sizeof(void *), oldp, &tmp);
        }
        gp_rsv_installed = 0; /* the wrapper is not installed (undone or never routed): release the claim */
        return rs_fail(rep, KNTWR_GP_E_WRITE, KNTWR_GP_RS_HOOK, e, 0, "cannot restore the import slot protection after install");
    }
    gp_rsv_enabled = 1;
    gp_rsv_installed = 1;
    rsv->hook_installed = 1;
    return 0;
}

int kntwr_gp_reserve_unhook(kntwr_gp_reserve *rsv, kntwr_gp_reserve_report *rep)
{
    void **slot = gp_rsv_slot;
    gp_nt_create_user_process_fn orig = gp_rsv_orig;
    void *prev;
    DWORD oldp = 0, tmp = 0;

    memset(rep, 0, sizeof *rep);
    gp_rsv_enabled = 0;
    if (gp_rsv_installed != 1 || !orig || !slot)
        return 0; /* never installed, or already restored: keep this record's own stats and restored state (no global copy) */
    rsv->calls_seen = (uint32_t)gp_rsv_calls_seen;
    rsv->calls_modified = (uint32_t)gp_rsv_calls_modified;
    rsv->reject = (uint32_t)gp_rsv_reject;
    rsv->hook_ntstatus = (uint32_t)gp_rsv_status;
    rsv->hook_has_status = (uint32_t)gp_rsv_has_status;
    /* Restore only our own wrapper (CAS expected = wrapper): a foreign pointer is never transiently replaced. */
    if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldp)) {
        rsv->hook_restored = 0;
        return rs_fail(rep, KNTWR_GP_E_WRITE, KNTWR_GP_RS_RESTORE, ra_win32_error(), 0, "cannot make the import slot writable for restore");
    }
    prev = InterlockedCompareExchangePointer((void *volatile *)slot, (void *)orig, (void *)&gp_hook_nt_create_user_process);
    if (prev != (void *)&gp_hook_nt_create_user_process) {
        VirtualProtect(slot, sizeof(void *), rsv->slot_protect, &tmp);
        rsv->hook_restored = 0;
        return rs_fail(rep, KNTWR_GP_E_WRITE, KNTWR_GP_RS_RESTORE, 0, 0, "the import slot no longer held the wrapper (left as found)");
    }
    if (!VirtualProtect(slot, sizeof(void *), rsv->slot_protect, &tmp) || *slot != (void *)orig) {
        rsv->hook_restored = 0;
        return rs_fail(rep, KNTWR_GP_E_WRITE, KNTWR_GP_RS_RESTORE, ra_win32_error(), 0,
                       "the import slot pointer or its original protection could not be restored (writable page or wrong pointer)");
    }
    gp_rsv_installed = 0; /* gp_rsv_orig/gp_rsv_slot stay published: ntdll never unloads, the original stays valid */
    rsv->hook_restored = 1;
    return 0;
}

void kntwr_gp_reserve_dispose(kntwr_gp_reserve *rsv)
{
    if (rsv && rsv->section) {
        CloseHandle((HANDLE)rsv->section);
        rsv->section = NULL;
    }
}

int kntwr_gp_reserve_verify(const kntwr_gp_reserve *rsv, void *process, uint32_t actual_base, kntwr_gp_reserve_report *rep)
{
    MEMORY_BASIC_INFORMATION mbi;

    memset(rep, 0, sizeof *rep);
    if (!rsv || !process) return rs_fail(rep, KNTWR_GP_E_LAYOUT, KNTWR_GP_RS_BLOB, 0, 0, "no reservation plan or process");
    if (!rsv->hook_restored || rsv->calls_seen != 1 || rsv->calls_modified != 1 || rsv->reject != 0 ||
        !rsv->hook_has_status || (int32_t)rsv->hook_ntstatus < 0)
        return rs_fail(rep, KNTWR_GP_E_HEADER, KNTWR_GP_RS_HOOK, 0, 0,
                       "the wrapper did not wrap exactly one successful call (restored %lu, seen %lu, wrapped %lu, reject %lu, status %#lx)",
                       (unsigned long)rsv->hook_restored, (unsigned long)rsv->calls_seen, (unsigned long)rsv->calls_modified,
                       (unsigned long)rsv->reject, (unsigned long)rsv->hook_ntstatus);
    if (actual_base != rsv->predicted_base)
        return rs_fail(rep, KNTWR_GP_E_HEADER, KNTWR_GP_RS_BASE, 0, 0, "the child's image base %#x is not the predicted %#x", (unsigned)actual_base,
                       (unsigned)rsv->predicted_base);
    if (!VirtualQueryEx((HANDLE)process, (LPCVOID)(uintptr_t)rsv->reserve_base, &mbi, sizeof mbi))
        return rs_fail(rep, KNTWR_GP_E_READ, KNTWR_GP_RS_TAIL, ra_win32_error(), 0, "cannot query the reserved tail in the child");
    if (mbi.BaseAddress != (PVOID)(uintptr_t)rsv->reserve_base || mbi.AllocationBase != mbi.BaseAddress ||
        mbi.RegionSize != (SIZE_T)rsv->reserve_size || mbi.State != MEM_RESERVE || mbi.Type != MEM_PRIVATE)
        return rs_fail(rep, KNTWR_GP_E_HEADER, KNTWR_GP_RS_TAIL, 0, 0,
                       "the reserved tail is %#x+%#x state %#x type %#x alloc-base %#x, not the recorded %#x+%#x private reservation",
                       (unsigned)(uintptr_t)mbi.BaseAddress, (unsigned)mbi.RegionSize, (unsigned)mbi.State, (unsigned)mbi.Type,
                       (unsigned)(uintptr_t)mbi.AllocationBase, (unsigned)rsv->reserve_base, (unsigned)rsv->reserve_size);
    return 0;
}
#endif
