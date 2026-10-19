/* See ntw2_gameplay_patch.h.  Plain C (compiled into ntw2.exe and into the oracle). */
#include "ntw2_gameplay_patch.h"
#include "ntw2_gameplay_patch_data.inc"

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

const uint8_t *ntw2_gp_napoleon_blob(uint32_t *size)
{
    *size = (uint32_t)sizeof ntw2_gameplay_patch_napoleon;
    return ntw2_gameplay_patch_napoleon;
}

const uint8_t *ntw2_gp_mss32_blob(uint32_t *size)
{
    *size = (uint32_t)sizeof ntw2_gameplay_patch_mss32;
    return ntw2_gameplay_patch_mss32;
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
} gp_run;

typedef struct gp_blob {
    uint64_t stock_len, patched_len;
    const uint8_t *stock_sha, *patched_sha;
    uint32_t run_count;
    gp_run *runs;
    uint64_t old_tail_len, new_tail_len;
    const uint8_t *old_tail, *new_tail;
} gp_blob;

static int gp_error(ntw2_gp_report *rep, uint32_t status, const char *fmt, ...)
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

static int gp_parse_blob(const uint8_t *d, uint32_t size, gp_blob *b, ntw2_gp_report *rep)
{
    uint32_t pos = 0, i;
    uint64_t common;
    uint32_t body;
    memset(b, 0, sizeof *b);
    if (size < 8u + 4u + 8u + 32u + 8u + 32u + 4u + 8u + 8u + 32u) return gp_error(rep, NTW2_GP_E_BLOB, "patch blob too short");
    body = size - 32u; /* trailing sha256 checksum; verified by tools/apply_ntwpatch.py embed --check */
    if (memcmp(d, "NTWPATCH", 8) != 0) return gp_error(rep, NTW2_GP_E_BLOB, "bad patch magic");
    if (rd32(d + 8) != 1u) return gp_error(rep, NTW2_GP_E_BLOB, "unsupported patch version %u", (unsigned)rd32(d + 8));
    pos = 12;
    b->stock_len = rd64(d + pos); pos += 8;
    b->stock_sha = d + pos; pos += 32;
    b->patched_len = rd64(d + pos); pos += 8;
    b->patched_sha = d + pos; pos += 32;
    b->run_count = rd32(d + pos); pos += 4;
    common = b->stock_len < b->patched_len ? b->stock_len : b->patched_len;
    if (b->run_count > 100000u) return gp_error(rep, NTW2_GP_E_BLOB, "implausible run count %u", (unsigned)b->run_count);
    b->runs = (gp_run *)calloc(b->run_count ? b->run_count : 1u, sizeof(gp_run));
    if (!b->runs) return gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (runs)");
    {
        uint64_t prev_end = 0;
        for (i = 0; i < b->run_count; ++i) {
            gp_run *r = &b->runs[i];
            if (body - pos < 12u) goto truncated;
            r->off = rd64(d + pos); pos += 8;
            r->len = rd32(d + pos); pos += 4;
            if (r->len == 0 || r->off < prev_end || r->off + r->len > common) return gp_error(rep, NTW2_GP_E_BLOB, "run %u out of range", (unsigned)i);
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
        return gp_error(rep, NTW2_GP_E_BLOB, "patch length mismatch");
    return 0;
truncated:
    return gp_error(rep, NTW2_GP_E_BLOB, "patch blob truncated");
}

int ntw2_gp_blob_describe(const uint8_t *blob, uint32_t size, ntw2_gp_blob_info *info)
{
    gp_blob b;
    ntw2_gp_report rep;
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

static int gp_parse_header(const uint8_t *h, uint32_t n, gp_hdr *o, ntw2_gp_report *rep, const char *what)
{
    uint32_t lf, opt, table, i, nrva;
    memset(o, 0, sizeof *o);
    if (n < 0x200u || h[0] != 'M' || h[1] != 'Z') return gp_error(rep, NTW2_GP_E_HEADER, "%s: not a DOS/PE image", what);
    lf = rd32(h + 0x3c);
    if (lf < 0x40u || lf > n - 0x108u) return gp_error(rep, NTW2_GP_E_HEADER, "%s: e_lfanew %#x out of range", what, (unsigned)lf);
    if (memcmp(h + lf, "PE\0\0", 4) != 0) return gp_error(rep, NTW2_GP_E_HEADER, "%s: missing PE signature", what);
    if ((uint32_t)(h[lf + 4] | (h[lf + 5] << 8)) != 0x14cu) return gp_error(rep, NTW2_GP_E_HEADER, "%s: not an x86 image", what);
    o->nsec = (uint32_t)(h[lf + 6] | (h[lf + 7] << 8));
    opt = lf + 24u;
    if ((uint32_t)(h[opt] | (h[opt + 1] << 8)) != 0x10bu) return gp_error(rep, NTW2_GP_E_HEADER, "%s: not PE32", what);
    if ((uint32_t)(h[lf + 20] | (h[lf + 21] << 8)) < 96u + 8u * 6u) return gp_error(rep, NTW2_GP_E_HEADER, "%s: optional header too small", what);
    o->salign = rd32(h + opt + 32);
    o->soi = rd32(h + opt + 56);
    o->soh = rd32(h + opt + 60);
    nrva = rd32(h + opt + 92);
    if (nrva < 6u) return gp_error(rep, NTW2_GP_E_HEADER, "%s: no base relocation directory slot", what);
    o->reloc_rva = rd32(h + opt + 96 + 5 * 8);
    o->reloc_size = rd32(h + opt + 96 + 5 * 8 + 4);
    if (o->nsec == 0 || o->nsec > GP_MAX_SECTIONS) return gp_error(rep, NTW2_GP_E_HEADER, "%s: %u sections", what, (unsigned)o->nsec);
    table = opt + (uint32_t)(h[lf + 20] | (h[lf + 21] << 8));
    if (table + 40u * o->nsec > n) return gp_error(rep, NTW2_GP_E_HEADER, "%s: section table beyond the header read", what);
    for (i = 0; i < o->nsec; ++i) {
        const uint8_t *s = h + table + 40u * i;
        o->sec[i].vsize = rd32(s + 8);
        o->sec[i].va = rd32(s + 12);
        o->sec[i].rawsize = rd32(s + 16);
        o->sec[i].rawptr = rd32(s + 20);
        o->sec[i].chars = rd32(s + 36);
    }
    if (o->salign != GP_PAGE || o->soi == 0 || (o->soi & (GP_PAGE - 1u)) != 0 || o->soh == 0 || o->soh > n)
        return gp_error(rep, NTW2_GP_E_HEADER, "%s: unsupported alignment/size (align %#x, image %#x, headers %#x)", what,
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
static int gp_parse_relocs(const uint8_t *d, uint32_t size, uint32_t image_size, gp_fix *out, ntw2_gp_report *rep, const char *what)
{
    uint32_t pos = 0, sorted = 1;
    while (pos < size) {
        uint32_t page, block, i, count;
        if (size - pos < 8u) return gp_error(rep, NTW2_GP_E_LAYOUT, "%s: truncated relocation block header", what);
        page = rd32(d + pos);
        block = rd32(d + pos + 4);
        if (block < 8u || (block & 1u) || block > size - pos) return gp_error(rep, NTW2_GP_E_LAYOUT, "%s: invalid relocation block extent", what);
        if (page >= image_size) return gp_error(rep, NTW2_GP_E_LAYOUT, "%s: relocation page %#x outside the image", what, (unsigned)page);
        count = (block - 8u) / 2u;
        for (i = 0; i < count; ++i) {
            const uint32_t word = (uint32_t)(d[pos + 8 + 2 * i] | (d[pos + 9 + 2 * i] << 8));
            const uint32_t type = word >> 12, rva = page + (word & 0xfffu);
            if (type == 0) continue; /* IMAGE_REL_BASED_ABSOLUTE padding */
            if (type != 3u) return gp_error(rep, NTW2_GP_E_LAYOUT, "%s: unsupported relocation type %u", what, (unsigned)type);
            if (rva + 4u > image_size) return gp_error(rep, NTW2_GP_E_LAYOUT, "%s: relocation %#x outside the image", what, (unsigned)rva);
            if (out->n && rva <= out->v[out->n - 1]) sorted = 0;
            if (!gp_fix_push(out, rva)) return gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (relocations)");
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

static int gp_mem_read(const ntw2_gp_memory *m, uint32_t va, void *dst, uint32_t n, ntw2_gp_report *rep, const char *what)
{
    if (m->read(m->ctx, va, dst, n) != 0) return gp_error(rep, NTW2_GP_E_READ, "cannot read %s at %#x (+%#x)", what, (unsigned)va, (unsigned)n);
    return 0;
}

int ntw2_gp_apply(const ntw2_gp_memory *mem, uint32_t base, uint32_t preferred, const uint8_t *blob, uint32_t blob_size,
                  ntw2_gp_report *rep)
{
    gp_blob b;
    gp_hdr sh, ph;
    uint8_t hdr_live[GP_HDR_READ], hdr_new[GP_HDR_READ];
    uint8_t *rbuf = NULL, *pbuf = NULL, *secbuf = NULL, *imgbuf = NULL;
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
    if ((rc = gp_mem_read(mem, base, hdr_live, sizeof hdr_live, rep, "the image header")) != 0) goto done;
    if ((rc = gp_parse_header(hdr_live, sizeof hdr_live, &sh, rep, "live image")) != 0) goto done;

    /* Runs: file offset -> RVA through the STOCK section table. */
    for (i = 0; i < b.run_count; ++i) {
        if (!gp_run_rva(&sh, &b.runs[i])) {
            rep->fail_run = i;
            rc = gp_error(rep, NTW2_GP_E_LAYOUT, "run %u at file offset %#llx (+%u) is in no stock section", (unsigned)i,
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
            rep->fail_run = i;
            rep->fail_va = base + r->rva;
            rc = gp_error(rep, NTW2_GP_E_STOCK, "header run %u (RVA %#x) does not match the live stock header", (unsigned)i, (unsigned)r->rva);
            goto done;
        }
        memcpy(hdr_new + r->rva, r->new_b, r->len);
        rep->runs_header++;
    }
    if ((rc = gp_parse_header(hdr_new, sizeof hdr_new, &ph, rep, "patched header")) != 0) goto done;

    /* Layout contract: stock sections unchanged in place, appended sections tile the range above the stock image. */
    if (ph.nsec < sh.nsec || ph.soi < sh.soi || ph.reloc_rva != sh.reloc_rva || ph.reloc_size < sh.reloc_size) {
        rc = gp_error(rep, NTW2_GP_E_LAYOUT, "patched header shrinks the stock layout");
        goto done;
    }
    for (i = 0; i < sh.nsec; ++i) {
        if (ph.sec[i].va != sh.sec[i].va || ph.sec[i].rawptr != sh.sec[i].rawptr || ph.sec[i].rawsize != sh.sec[i].rawsize) {
            rc = gp_error(rep, NTW2_GP_E_LAYOUT, "patched header moves stock section %u", (unsigned)i);
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
                rc = gp_error(rep, NTW2_GP_E_LAYOUT, "appended section %u (rva %#x size %#x raw %#x+%#x) does not fit the patch tail", (unsigned)i,
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
        if (!rbuf || !pbuf) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (relocation tables)"); goto done; }
        if ((rc = gp_mem_read(mem, base + ph.reloc_rva, rbuf, ph.reloc_size, rep, "the relocation table")) != 0) goto done;
        memcpy(pbuf, rbuf, ph.reloc_size);
        for (i = 0; i < b.run_count; ++i) {
            const gp_run *r = &b.runs[i];
            uint32_t lo, hi;
            if (r->header || r->rva >= reloc_end || r->rva + r->len <= ph.reloc_rva) continue;
            lo = r->rva < ph.reloc_rva ? ph.reloc_rva : r->rva;
            hi = r->rva + r->len > reloc_end ? reloc_end : r->rva + r->len;
            if (memcmp(rbuf + (lo - ph.reloc_rva), r->old_b + (lo - r->rva), hi - lo) != 0) {
                rep->fail_run = i;
                rep->fail_va = base + lo;
                rc = gp_error(rep, NTW2_GP_E_STOCK, "relocation-table run %u (RVA %#x) does not match the live stock table", (unsigned)i, (unsigned)r->rva);
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
    if (!plan) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (plan)"); goto done; }
    for (i = 0; i < b.run_count; ++i) {
        const gp_run *r = &b.runs[i];
        uint32_t ustart = r->rva, uend = r->rva + r->len, ulen;
        size_t k;
        uint8_t *buf;
        if (r->header) continue;
        if (r->rva + r->len > sh.soi) {
            rep->fail_run = i;
            rc = gp_error(rep, NTW2_GP_E_LAYOUT, "run %u (RVA %#x) extends beyond the stock image", (unsigned)i, (unsigned)r->rva);
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
        if (!buf) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (window)"); goto done; }
        plan[plan_n].rva = ustart;
        plan[plan_n].len = ulen;
        plan[plan_n].data = buf;
        plan_n++;
        if ((rc = gp_mem_read(mem, base + ustart, buf, ulen, rep, "a patch site")) != 0) goto done;
        for (k = gp_lower_bound(&stock_fix, r->rva >= 3u ? r->rva - 3u : 0u); k < stock_fix.n && stock_fix.v[k] < r->rva + r->len; ++k) {
            uint8_t *f = buf + (stock_fix.v[k] - ustart);
            wr32u(f, rd32u(f) - delta);
            rep->fixups_stock_unrelocated++;
        }
        if (memcmp(buf + (r->rva - ustart), r->old_b, r->len) != 0) {
            rep->fail_run = i;
            rep->fail_va = base + r->rva;
            rc = gp_error(rep, NTW2_GP_E_STOCK, "run %u at VA %#x: live bytes (relocation removed) differ from the stock image", (unsigned)i,
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
            rc = gp_error(rep, NTW2_GP_E_LAYOUT, "patch windows at RVA %#x and %#x overlap", (unsigned)plan[i - 1].rva, (unsigned)plan[i].rva);
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
                rc = gp_error(rep, NTW2_GP_E_LAYOUT, "%s relocation at RVA %#x is not covered by any patch run", i == 0 ? "patched-only" : "stock-only",
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
        if (!secbuf) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (sections)"); goto done; }
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
            if (!inside) { rc = gp_error(rep, NTW2_GP_E_LAYOUT, "relocation at RVA %#x is outside every appended section", (unsigned)f); goto done; }
            wr32u(secbuf + (f - sh.soi), rd32u(secbuf + (f - sh.soi)) + delta);
            rep->section_fixups++;
        }
    }

    /* Proof points for live read-back: the first run that becomes a jump into an appended section, and the first section bytes. */
    for (i = 0; i < b.run_count; ++i) {
        const gp_run *r = &b.runs[i];
        if (!r->header && r->len >= 5u && r->new_b[0] == 0xE9u) {
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
        if (!imgbuf) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (image snapshot)"); goto done; }
        while (done < sh.soi) {
            const uint32_t n = sh.soi - done > (1u << 20) ? (1u << 20) : (sh.soi - done);
            if ((rc = gp_mem_read(mem, base + done, imgbuf + done, n, rep, "the stock image")) != 0) goto done;
            done += n;
        }
        memcpy(imgbuf, hdr_new, ph.soh);
        if (mem->remalloc(mem->ctx, base, sh.soi, ph.soi) != 0) {
            rc = gp_error(rep, NTW2_GP_E_ALLOC, "pages [%#x, %#x) above the image are not free for the appended sections", (unsigned)(base + sh.soi),
                          (unsigned)(base + ph.soi));
            goto done;
        }
        rep->phase = 1;
        if (mem->write(mem->ctx, base, imgbuf, sh.soi) != 0 || mem->write(mem->ctx, base + sh.soi, secbuf, ph.soi - sh.soi) != 0) {
            rc = gp_error(rep, NTW2_GP_E_WRITE, "writing the expanded image failed");
            goto done;
        }
        if (mem->protect(mem->ctx, base, ph.soh, 0x02u /* PAGE_READONLY */) != 0) {
            rc = gp_error(rep, NTW2_GP_E_WRITE, "protecting the PE header failed");
            goto done;
        }
        for (i = 0; i < ph.nsec; ++i) {
            if (mem->protect(mem->ctx, base + ph.sec[i].va, align_up(ph.sec[i].vsize, GP_PAGE), gp_protection(ph.sec[i].chars)) != 0) {
                rc = gp_error(rep, NTW2_GP_E_WRITE, "protecting section %u failed", (unsigned)i);
                goto done;
            }
        }
    }
    /* Write from high RVA to low RVA: in an already-loaded DLL (mss32.dll), high-RVA stub caves are populated before the
       low-RVA call sites that branch into them. */
    for (i = plan_n; i > 0; --i) {
        if (mem->write(mem->ctx, base + plan[i - 1].rva, plan[i - 1].data, plan[i - 1].len) != 0) {
            rc = gp_error(rep, NTW2_GP_E_WRITE, "writing the patch window at %#x failed", (unsigned)(base + plan[i - 1].rva));
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
        if (!chk) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (verify)"); goto done; }
        if (ph.soi > sh.soi) {
            if (mem->read(mem->ctx, base + sh.soi, chk, ph.soi - sh.soi) != 0 || memcmp(chk, secbuf, ph.soi - sh.soi) != 0) {
                free(chk);
                rc = gp_error(rep, NTW2_GP_E_VERIFY, "appended-section read-back mismatch");
                goto done;
            }
            if (mem->read(mem->ctx, base, chk, ph.soh) != 0 || memcmp(chk, hdr_new, ph.soh) != 0) {
                free(chk);
                rc = gp_error(rep, NTW2_GP_E_VERIFY, "patched PE header read-back mismatch");
                goto done;
            }
        }
        free(chk);
        chk = (uint8_t *)malloc(maxw ? maxw : 1u);
        if (!chk) { rc = gp_error(rep, NTW2_GP_E_NOMEM, "out of memory (verify)"); goto done; }
        for (i = 0; i < plan_n; ++i) {
            if (mem->read(mem->ctx, base + plan[i].rva, chk, plan[i].len) != 0 || memcmp(chk, plan[i].data, plan[i].len) != 0) {
                free(chk);
                rep->fail_va = base + plan[i].rva;
                rc = gp_error(rep, NTW2_GP_E_VERIFY, "read-back mismatch at %#x", (unsigned)(base + plan[i].rva));
                goto done;
            }
        }
        free(chk);
    }
    rep->status = NTW2_GP_OK;
    rc = 0;

done:
    if (plan) {
        for (i = 0; i < plan_n; ++i) free(plan[i].data);
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

/* ------------------------------------------------------------------------------------------------ process backend */
#ifdef _WIN32
static int pm_fail(void)
{
    const DWORD e = GetLastError();
    return e ? (int)e : 1;
}

static int pm_read(void *ctx, uint32_t va, void *dst, uint32_t n)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory((HANDLE)ctx, (LPCVOID)(uintptr_t)va, dst, n, &got) || got != n) return pm_fail();
    return 0;
}

static int pm_write(void *ctx, uint32_t va, const void *src, uint32_t n)
{
    HANDLE h = (HANDLE)ctx;
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

static int pm_remalloc(void *ctx, uint32_t va, uint32_t old_size, uint32_t new_size)
{
    HANDLE h = (HANDLE)ctx;
    MEMORY_BASIC_INFORMATION mbi;
    uint32_t cur = va + old_size;
    LPVOID p;
    while (cur < va + new_size) {
        uint64_t end;
        if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)cur, &mbi, sizeof mbi) || mbi.State != MEM_FREE) return ERROR_INVALID_ADDRESS;
        end = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (end <= cur) return ERROR_INVALID_ADDRESS;
        cur = end > (uint64_t)va + new_size ? va + new_size : (uint32_t)end;
    }
    if (!VirtualQueryEx(h, (LPCVOID)(uintptr_t)va, &mbi, sizeof mbi)) return pm_fail();
    if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        nt_unmap_fn unmap = ntdll ? (nt_unmap_fn)GetProcAddress(ntdll, "NtUnmapViewOfSection") : NULL;
        if (!unmap || unmap(h, (PVOID)(uintptr_t)va) != 0) return ERROR_INVALID_ADDRESS;
    } else {
        if (!VirtualFreeEx(h, (LPVOID)(uintptr_t)va, 0, MEM_RELEASE)) return pm_fail();
    }
    p = VirtualAllocEx(h, (LPVOID)(uintptr_t)va, new_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return (p == (LPVOID)(uintptr_t)va) ? 0 : pm_fail();
}

static int pm_protect(void *ctx, uint32_t va, uint32_t size, uint32_t prot)
{
    DWORD old = 0;
    return VirtualProtectEx((HANDLE)ctx, (LPVOID)(uintptr_t)va, size, prot, &old) ? 0 : pm_fail();
}

ntw2_gp_memory ntw2_gp_process_memory(void *handle)
{
    ntw2_gp_memory m;
    m.ctx = handle;
    m.read = pm_read;
    m.write = pm_write;
    m.remalloc = pm_remalloc;
    m.protect = pm_protect;
    return m;
}
#endif
