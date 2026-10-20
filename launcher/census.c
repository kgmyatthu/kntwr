/* See census.h.  Plain C, x86, static CRT. */
#include "census.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define EC_MAX_MEN 4096u
#define EC_MAX_UNITS 2048u
#define EC_STATE_SLOTS 4096u
#define EC_MOVING_MIN_MEN 60u
#define EC_DEFAULT_EVERY 30u
#define EC_COORD_LIMIT 16384.0f

typedef struct ECState {
    uint32_t unit, ctick;
    float lcx, lcz, rms0;
    unsigned char used, have, counted, collapsed_ever;
} ECState;

typedef struct ECAgg {
    uint32_t unit_samples, units, moving60, collapsed_ref, collapsed_units;
    double rms_sum, nn_sum;
} ECAgg;

static FILE *g_csv;
static wchar_t g_sum_path[MAX_PATH + 16];
static uint32_t g_every = EC_DEFAULT_EVERY, g_next_tick, g_rows, g_passes, g_bad_graph, g_no_men, g_last_model;
static ECState g_state[EC_STATE_SLOTS];
static ECAgg g_agg[2];
static float g_mx[EC_MAX_MEN], g_mz[EC_MAX_MEN];
static uint32_t g_ptrs[EC_MAX_MEN];

static int rd(HANDLE p, uint32_t va, void *dst, uint32_t n)
{
    SIZE_T got = 0;
    return va >= 0x10000u && ReadProcessMemory(p, (LPCVOID)(uintptr_t)va, dst, n, &got) && got == n;
}

static int rd32(HANDLE p, uint32_t va, uint32_t *out)
{
    return rd(p, va, out, 4);
}

static int rdf(HANDLE p, uint32_t va, float *out)
{
    return rd(p, va, out, 4);
}

static int good(float v)
{
    return v == v && fabsf(v) < EC_COORD_LIMIT;
}

static ECState *find_state(uint32_t unit)
{
    uint32_t h = (unit >> 4) * 2654435761u, i;
    for (i = 0; i < EC_STATE_SLOTS; ++i) {
        ECState *s = &g_state[(h + i) & (EC_STATE_SLOTS - 1u)];
        if (s->used && s->unit == unit) return s;
        if (!s->used) {
            memset(s, 0, sizeof *s);
            s->unit = unit; s->used = 1; s->rms0 = -1.0f;
            return s;
        }
    }
    return NULL;
}

typedef struct ECStats { float cx, cz, rms, s1, s2; } ECStats;

static void moments(const float *x, const float *z, uint32_t count, ECStats *o)
{
    double sx = 0, sz = 0, a = 0, b = 0, c = 0, cx, cz, h, d;
    uint32_t k, n = 0;
    memset(o, 0, sizeof *o);
    for (k = 0; k < count; ++k) if (good(x[k]) && good(z[k])) { sx += x[k]; sz += z[k]; ++n; }
    if (!n) return;
    cx = sx / n; cz = sz / n;
    for (k = 0; k < count; ++k) if (good(x[k]) && good(z[k])) {
        const double dx = x[k] - cx, dz = z[k] - cz;
        a += dx * dx; b += dx * dz; c += dz * dz;
    }
    a /= n; b /= n; c /= n;
    h = (a + c) * 0.5;
    d = sqrt(((a - c) * 0.5) * ((a - c) * 0.5) + b * b);
    o->cx = (float)cx; o->cz = (float)cz;
    o->rms = (float)sqrt(a + c);
    o->s1 = (float)sqrt(h + d > 0 ? h + d : 0);
    o->s2 = (float)sqrt(h - d > 0 ? h - d : 0);
}

static float nn_mean(const float *x, const float *z, uint32_t count)
{
    double sum = 0;
    uint32_t i, j, n = 0;
    for (i = 0; i < count && n < 1024u; ++i) {
        float best = 1e30f;
        if (!good(x[i]) || !good(z[i])) continue;
        for (j = 0; j < count; ++j) {
            float dx, dz, d;
            if (j == i || !good(x[j]) || !good(z[j])) continue;
            dx = x[i] - x[j]; dz = z[i] - z[j]; d = dx * dx + dz * dz;
            if (d < best) best = d;
        }
        if (best < 1e29f) { sum += sqrt((double)best); ++n; }
    }
    return n ? (float)(sum / n) : -1.0f;
}

static void write_summary(void)
{
    FILE *f;
    uint32_t a;
    if (!g_sum_path[0] || _wfopen_s(&f, g_sum_path, L"wb") != 0 || !f) return;
    fprintf(f, "formation-census (launcher-side, ReadProcessMemory) summary, every %u ticks\npasses %u rows %u bad_graph %u no_men_units %u\n",
            g_every, g_passes, g_rows, g_bad_graph, g_no_men);
    for (a = 0; a < 2; ++a) {
        const ECAgg *g = &g_agg[a];
        fprintf(f, "%s: unit_samples %u distinct_units %u moving60 %u (speed > 0.5 m/s, >= 60 men) mean_men_rms_moving60 %.3f mean_nn_moving60 %.3f "
                   "collapsed_vs_first_sample %u (distinct units %u; men_rms < 0.35 x the unit's first-sample men_rms)\n",
                a ? "AI" : "player", g->unit_samples, g->units, g->moving60, g->moving60 ? g->rms_sum / g->moving60 : -1.0,
                g->moving60 ? g->nn_sum / g->moving60 : -1.0, g->collapsed_ref, g->collapsed_units);
    }
    fclose(f);
}

int ext_census_open(const wchar_t *csv_path, uint32_t every_ticks)
{
    if (g_csv || !csv_path || !csv_path[0]) return -1;
    if (_wfopen_s(&g_csv, csv_path, L"wb") != 0 || !g_csv) { g_csv = NULL; return -1; }
    _snwprintf_s(g_sum_path, MAX_PATH + 16, _TRUNCATE, L"%ls.summary.txt", csv_path);
    g_every = every_ticks ? every_ticks : EC_DEFAULT_EVERY;
    g_next_tick = 0; g_rows = g_passes = g_bad_graph = g_no_men = g_last_model = 0;
    memset(g_state, 0, sizeof g_state);
    memset(g_agg, 0, sizeof g_agg);
    fputs("tick,model,side,ai,unit,cls,members_u,men,moving,b34,sel,fvt,lvt,gen,cvt,dirty,cd,nslots,npieces,"
          "men_cx,men_cz,men_rms,men_s1,men_s2,slot_cx,slot_cz,slot_rms,slot_s1,slot_s2,ratio,err_mean,err_max,"
          "sp0,sp1,l8,lc,l10,l14,rms0,ratio0,collapsed,collapsed_ref,speed,nn_mean,slotwhy\n", g_csv);
    return 0;
}

static void observe_unit(HANDLE p, uint32_t delta, uint32_t model, uint32_t tick, uint32_t unit, uint32_t side, uint32_t ai, uint32_t members)
{
    uint32_t sel = 0, F = 0, men = 0, manArr = 0, k, nvalid = 0, fvt = 0, cls = 0xFFu, clsPtr = 0, b34 = 0, queued = 0, cmd = 0, cvt = 0, layout = 0, lvt = 0, gen = 0;
    uint32_t cd = 0;
    unsigned char dirty = 0;
    float sp0 = 0, sp1 = 0, l8 = 0, lc = 0, l10 = 0, l14 = 0, rms0 = -1.0f, ratio0 = -1.0f, speed = -1.0f, nn;
    ECStats ms;
    ECState *st;
    ECAgg *g = &g_agg[ai ? 1 : 0];
    int moving, collapsed_ref;

    rd32(p, unit + 0xAE8, &sel);
    if (!rd32(p, unit + 0xADC, &F)) { ++g_bad_graph; return; }
    if (sel == 1 || sel == 2) { uint32_t alt = 0; if (rd32(p, unit + 0xADC + 4 * sel, &alt) && alt) F = alt; }
    if (!F || !rd32(p, F + 0x18, &men) || !rd32(p, F + 0x1C, &manArr) || men == 0 || men > EC_MAX_MEN || !manArr || !rd(p, manArr, g_ptrs, men * 4u)) { ++g_no_men; return; }
    for (k = 0; k < men; ++k) {
        float v[3];
        g_mx[k] = g_mz[k] = NAN;
        if (!rd(p, g_ptrs[k] + 0x48, v, 12) || !good(v[0]) || !good(v[2])) continue;
        g_mx[k] = v[0]; g_mz[k] = v[2]; ++nvalid;
    }
    if (!nvalid) { ++g_no_men; return; }
    moments(g_mx, g_mz, men, &ms);
    nn = nn_mean(g_mx, g_mz, men);

    rd32(p, F, &fvt);
    if (rd32(p, unit + 0x2C, &clsPtr) && clsPtr) { if (!rd32(p, clsPtr + 0x1C, &cls)) cls = 0xFFu; }
    rd32(p, unit + 0xB34, &b34);
    rdf(p, unit + 0x2F8, &sp0); rdf(p, unit + 0x2FC, &sp1);
    rd(p, F + 0x278C, &dirty, 1); rd32(p, F + 0x2788, &cd);
    if (rd32(p, F + 0x460, &queued) && queued >= 1 && queued <= 8 && rd32(p, F + 0x420 + 8 * (queued - 1), &cmd) && cmd) { rd32(p, cmd, &cvt); if (cvt) cvt -= delta; }
    if (rd32(p, F + 0x628, &layout) && layout) {
        rdf(p, layout + 8, &l8); rdf(p, layout + 0xC, &lc); rdf(p, layout + 0x10, &l10); rdf(p, layout + 0x14, &l14);
        if (rd32(p, layout, &lvt) && lvt) { uint32_t g0 = 0; if (rd32(p, lvt + 0x24, &g0) && g0) gen = g0 - delta; lvt -= delta; }
    }

    st = find_state(unit);
    if (st) {
        if (st->rms0 < 0.0f) st->rms0 = ms.rms;
        rms0 = st->rms0;
        if (st->have && tick > st->ctick)
            speed = sqrtf((ms.cx - st->lcx) * (ms.cx - st->lcx) + (ms.cz - st->lcz) * (ms.cz - st->lcz)) * 10.0f / (float)(tick - st->ctick);
        st->lcx = ms.cx; st->lcz = ms.cz; st->ctick = tick; st->have = 1;
        if (!st->counted) { st->counted = 1; ++g->units; }
    }
    if (rms0 > 0.01f) ratio0 = ms.rms / rms0;
    moving = speed > 0.5f;
    collapsed_ref = moving && men >= EC_MOVING_MIN_MEN && ratio0 >= 0.0f && ratio0 < 0.35f;
    ++g->unit_samples;
    if (moving && men >= EC_MOVING_MIN_MEN) {
        ++g->moving60; g->rms_sum += ms.rms; if (nn >= 0.0f) g->nn_sum += nn;
        if (collapsed_ref) {
            ++g->collapsed_ref;
            if (st && !st->collapsed_ever) { st->collapsed_ever = 1; ++g->collapsed_units; }
        }
    }
    fprintf(g_csv, "%u,0x%08X,%u,%u,0x%08X,%u,%u,%u,%u,%u,%u,0x%X,0x%X,0x%X,0x%X,%u,%u,%u,%u,"
                   "%.2f,%.2f,%.3f,%.3f,%.3f,%.2f,%.2f,%.3f,%.3f,%.3f,%.4f,%.3f,%.3f,"
                   "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.3f,%.4f,%d,%d,%.3f,%.3f,%u\n",
            tick, model, side, ai, unit, cls, members, men, moving ? 1u : 0u, b34, sel, fvt ? fvt - delta : 0u, lvt, gen, cvt, (uint32_t)dirty, cd, 0u, 0u,
            ms.cx, ms.cz, ms.rms, ms.s1, ms.s2, 0.0, 0.0, 0.0, 0.0, 0.0, -1.0, -1.0, -1.0,
            sp0, sp1, l8, lc, l10, l14, rms0, ratio0, 0, collapsed_ref ? 1 : 0, speed, nn, 99u);
    ++g_rows;
}

static void pass(HANDLE p, uint32_t delta, uint32_t model, uint32_t tick)
{
    uint32_t M = 0, side_count = 0, side_arr = 0, si;
    ++g_passes;
    if (!rd32(p, model + 0xB0, &M) || !M || !rd32(p, M + 0x84, &side_count) || !rd32(p, M + 0x88, &side_arr) || !side_arr || side_count == 0 || side_count > 16) { ++g_bad_graph; return; }
    for (si = 0; si < side_count; ++si) {
        uint32_t side = 0, aicmd = 0, side_idx = 0, army_count = 0, army_arr = 0, ai2;
        if (!rd32(p, side_arr + 4 * si, &side) || !side) { ++g_bad_graph; continue; }
        rd32(p, side + 0xC, &aicmd); rd32(p, side + 0x10, &side_idx);
        if (!rd32(p, side + 0x20, &army_count) || !rd32(p, side + 0x24, &army_arr) || army_count > 128 || (army_count && !army_arr)) { ++g_bad_graph; continue; }
        for (ai2 = 0; ai2 < army_count; ++ai2) {
            uint32_t army = 0, unit_count = 0, unit_arr = 0, ui;
            static uint32_t units[EC_MAX_UNITS];
            if (!rd32(p, army_arr + 4 * ai2, &army) || !army) { ++g_bad_graph; continue; }
            if (!rd32(p, army + 0xF0, &unit_count) || !rd32(p, army + 0xF4, &unit_arr) || unit_count > EC_MAX_UNITS || (unit_count && !unit_arr)) { ++g_bad_graph; continue; }
            if (unit_count && !rd(p, unit_arr, units, unit_count * 4u)) { ++g_bad_graph; continue; }
            for (ui = 0; ui < unit_count; ++ui) {
                uint32_t members = 0, alive = 0;
                if (!units[ui] || !rd32(p, units[ui] + 0x2CC, &members) || !rd32(p, units[ui] + 0xAA0, &alive)) continue;
                if (alive == 2 || members == 0) continue;
                observe_unit(p, delta, model, tick, units[ui], side_idx, aicmd ? 1u : 0u, members);
            }
        }
    }
}

int ext_census_poll(HANDLE proc, uint32_t image_base)
{
    uint32_t engine = 0, root = 0, model = 0, back = 0, tick = 0, delta = image_base - 0x400000u;
    if (!g_csv) return 0;
    if (!rd32(proc, 0x14a418cu + delta, &engine) || !engine || !rd32(proc, engine + 0xF8, &root) || !root || !rd32(proc, root + 8, &model) || !model ||
        !rd32(proc, model, &back) || back != root || !rd32(proc, model + 0x58, &tick)) return 0;
    if (model != g_last_model) { g_last_model = model; g_next_tick = 0; memset(g_state, 0, sizeof g_state); }
    if (tick < g_next_tick) return 0;
    g_next_tick = tick - tick % g_every + g_every;
    pass(proc, delta, model, tick);
    fflush(g_csv);
    write_summary();
    return 1;
}

uint32_t ext_census_rows(void)
{
    return g_rows;
}

void ext_census_close(void)
{
    if (!g_csv) return;
    write_summary();
    fclose(g_csv);
    g_csv = NULL;
}
