// --formation-census: per-unit men vs formation-slot compactness diagnostic (contract, engine facts and output files: ntw2_formation_census.h).
// Runs on the tick-owner thread inside one SEH bracket per unit; engine memory is only read, the three natives of the header are only called.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "ntw2_formation_census.h"
#include "core/ntw2_guard.h"

namespace ntw2_formation_census {
using U = uint32_t;

namespace {
constexpr U kMaxSides = 16, kMaxArmies = 128, kMaxUnits = 2048, kMaxMen = 4096, kStateSlots = 4096, kMaxPieces = 64, kMaxBattleFaults = 64;
constexpr U kDefaultEvery = 30, kMovingMinMen = 60, kHistBins = 22;
constexpr float kCoordLimit = 16384.0f, kCollapseRatio = 0.35f;
constexpr U kBufBytes = 1u << 20, kFlushAt = kBufBytes - 8192;
constexpr U kFormationVtable = 0x13211D8, kMoveCommandVtable = 0x1325470, kCommandVtables[6] = {0x13239B0, 0x13239F0, 0x1323A30, 0x1323A70, 0x1323AB0, 0x1323AF0};

using ThisBool = unsigned char(__fastcall*)(U, U);
using ThisPtrOut = U(__fastcall*)(U, U, U);
using Generator = U(__fastcall*)(U layout, U edx, U out, U container, U fBits, U men);  // thiscall, four stack dwords, callee pops 0x10
using HeapFree = void(__cdecl*)(U);
using HeapFree2 = void(__cdecl*)(U, U);
using ThisVoid = void(__fastcall*)(U, U);
using Builder = U(__fastcall*)(U obj, U edx, U route, U zero);  // thiscall, two stack dwords, callee pops 8

struct Gathered { U unit, side, ai, members; };
struct UnitState { U unit, tick0, lastSeen, ctick; float rms0, lcx, lcz; unsigned char used, collapsedEver, counted, have, track, pad0, pad1, pad2; };
struct Agg {
    U unitSamples, moving60, movingNoSlots, slotted, collapsed, collapsedRef, units, collapsedUnits, hist[kHistBins];
    float ratioMin, ratioSum;
};

bool enabled, disabled, opened, openFailed, menOn, menOpened, menFailed;
U delta, imageLo, imageSize, lastModel, battleFaults, gCount, every = kDefaultEvery;
U passes, totalRows, faults, nativeCalls, noGenerator, noMen, badGraph, slotWhy, whyHist[16];
wchar_t csvPath[MAX_PATH], sumPath[MAX_PATH + 16], menPath[MAX_PATH + 16];
HANDLE csv = INVALID_HANDLE_VALUE, menCsv = INVALID_HANDLE_VALUE;
char buf[kBufBytes];
U bufLen;
char menBuf[kBufBytes];
U menLen, lastCmd, pieceDump[3][15], pieceDumpN, trackedAi, trackedPlayer;
constexpr U kTrackAi = 8, kTrackPlayer = 4, kDetailMen = 24;
U slotRec0[9], slotRecN[9], containerAddr;
struct ProbeRow { U unit, ai, nArmy, nSide, armyOff[4], sideOff[4]; };
ProbeRow probes[8];
U probeCount, probeTotal, probeAi, probePl;
Gathered units[kMaxUnits];
UnitState table[kStateSlots];
Agg agg[2];
float mx[kMaxMen], mz[kMaxMen], sx[kMaxMen], sz[kMaxMen];

inline U Rd(U a) { return *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(a)); }
inline float RdF(U a) { return *reinterpret_cast<const volatile float*>(static_cast<uintptr_t>(a)); }
inline bool Good(float v) { return v == v && fabsf(v) < kCoordLimit; }
inline U Bits(float f) { U u; memcpy(&u, &f, 4); return u; }
inline U V(U preferred) { return preferred + delta; }
inline bool Sane(U p) { return p >= 0x10000u && p < 0xFFFF0000u; }
inline bool InImage(U p) { return p - imageLo < imageSize; }
inline bool Virtual(U obj, U slot, U* fn) {
    if (!Sane(obj)) return false;
    const U vt = Rd(obj);
    if (!InImage(vt)) return false;
    *fn = Rd(vt + slot);
    return InImage(*fn);
}
// 0x55C2E0 (obj = formation object): idx = [obj+0x460]; idx != 0 -> o = [obj+0x418+idx*8], (*vt[slot])(); the slot array holds idx 1..8.
bool SlotCallSafe(U obj, U slot) {
    const U idx = Rd(obj + 0x460);
    if (idx == 0) return true;  // the native returns 0 without further reads
    if (idx > 8) return false;
    const U o = Rd(obj + 0x418 + 8 * idx);
    if (!Sane(o)) return false;
    const U vt = Rd(o);
    return InImage(vt) && InImage(Rd(vt + slot));
}
// 0x55C320 (is_moving): idx = [U+0xAE8]; idx != 0 -> o = [U+0xADC+idx*4], vt[+0xA4]; idx == 0 -> 0x55C2E0 on [U+0xADC] (vt[+0xC]).
bool MovingSafe(U unit) {
    const U idx = Rd(unit + 0xAE8);
    U fn;
    if (idx == 0) { const U f = Rd(unit + 0xADC); return Sane(f) && SlotCallSafe(f, 0xC); }
    return idx <= 2 && Virtual(Rd(unit + 0xADC + 4 * idx), 0xA4, &fn);
}

UnitState* Find(U unit, U tick) {
    U h = (unit >> 4) * 2654435761u;
    for (U i = 0; i < kStateSlots; ++i) {
        UnitState& s = table[(h + i) & (kStateSlots - 1)];
        if (s.used && s.unit == unit) return &s;
        if (!s.used) {
            memset(&s, 0, sizeof(s));
            s.unit = unit; s.used = 1; s.tick0 = tick; s.rms0 = -1.0f;
            return &s;
        }
    }
    return nullptr;
}

void Flush() {
    if (csv != INVALID_HANDLE_VALUE && bufLen) {
        DWORD w = 0;
        WriteFile(csv, buf, bufLen, &w, nullptr);
    }
    bufLen = 0;
}
template <class... A> void Emit(const char* fmt, A... a) {
    if (bufLen + 2048 > kBufBytes) Flush();
    const int n = _snprintf_s(buf + bufLen, kBufBytes - bufLen, _TRUNCATE, fmt, a...);
    if (n > 0) bufLen += static_cast<U>(n);
}

const char kColumns[] =
    "tick,model,side,ai,unit,cls,members_u,men,moving,b34,sel,fvt,lvt,gen,cvt,dirty,cd,nslots,npieces,"
    "men_cx,men_cz,men_rms,men_s1,men_s2,slot_cx,slot_cz,slot_rms,slot_s1,slot_s2,ratio,err_mean,err_max,"
    "sp0,sp1,l8,lc,l10,l14,rms0,ratio0,collapsed,collapsed_ref,speed,nn_mean,slotwhy\n";

void WriteSummary() {
    if (!sumPath[0]) return;
    char s[8192];
    int n = 0;
    n += _snprintf_s(s + n, sizeof(s) - n, _TRUNCATE,
        "formation-census summary (every %u ticks)\npasses %u rows %u faults %u native_calls %u no_generator_units %u no_men_units %u bad_graph %u\n"
        "slot reasons (0 ok, 1 no queued command, 2 command insane, 3 command class has no slots, 4 [cmd+4] != formation, 5 no generator, 6 men, 7 move object insane, 8 container insane, 9 pieces bad, 10 generator returned nothing): "
        "%u %u %u %u %u %u %u %u %u %u %u\n",
        every, passes, totalRows, faults, nativeCalls, noGenerator, noMen, badGraph,
        whyHist[0], whyHist[1], whyHist[2], whyHist[3], whyHist[4], whyHist[5], whyHist[6], whyHist[7], whyHist[8], whyHist[9], whyHist[10]);
    for (U a = 0; a < 2; ++a) {
        const Agg& g = agg[a];
        n += _snprintf_s(s + n, sizeof(s) - n, _TRUNCATE,
            "%s: unit_samples %u distinct_units %u moving60 %u (with slots %u, without %u) collapsed %u (distinct units %u) collapsed_vs_first_sample %u "
            "ratio_min %.3f ratio_mean %.3f\n  ratio histogram (moving, >=60 men, slots; bins of 0.1, last = >=2.1):",
            a ? "AI" : "player", g.unitSamples, g.units, g.moving60, g.slotted, g.movingNoSlots, g.collapsed, g.collapsedUnits, g.collapsedRef,
            g.slotted ? g.ratioMin : -1.0f, g.slotted ? g.ratioSum / static_cast<float>(g.slotted) : -1.0f);
        for (U b = 0; b < kHistBins; ++b) n += _snprintf_s(s + n, sizeof(s) - n, _TRUNCATE, " %u", g.hist[b]);
        n += _snprintf_s(s + n, sizeof(s) - n, _TRUNCATE, "\n");
    }
    const HANDLE h = CreateFileW(sumPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, s, static_cast<DWORD>(n), &w, nullptr);
        CloseHandle(h);
    }
}

bool OpenOutput() {
    if (opened) return true;
    if (openFailed) return false;
    wchar_t env[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"NTW2_FORMATION_CENSUS_CSV", env, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { openFailed = true; return false; }
    wcscpy_s(csvPath, MAX_PATH, env);
    _snwprintf_s(sumPath, MAX_PATH + 16, _TRUNCATE, L"%ls.summary.txt", csvPath);
    wchar_t ev[32];
    const DWORD en = GetEnvironmentVariableW(L"NTW2_FORMATION_CENSUS_EVERY", ev, 32);
    if (en > 0 && en < 32) { const U v = static_cast<U>(_wtoi(ev)); if (v >= 1 && v <= 10000) every = v; }
    csv = CreateFileW(csvPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (csv == INVALID_HANDLE_VALUE) { openFailed = true; return false; }
    opened = true;
    Emit("%s", kColumns);
    wchar_t mev[8];
    const DWORD mn = GetEnvironmentVariableW(L"NTW2_FORMATION_CENSUS_MEN", mev, 8);
    if (mn > 0 && mn < 8 && mev[0] != L'0') {
        menOn = true;
        _snwprintf_s(menPath, MAX_PATH + 16, _TRUNCATE, L"%ls.men.csv", csvPath);
        menCsv = CreateFileW(menPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (menCsv == INVALID_HANDLE_VALUE) menFailed = true;
        else {
            menOpened = true;
            static const char hdr[] =
                "#M,tick,unit,ai,k,x,z,st390,ord1D8,t0x,t0y,t0z,t0w,t0frame,twx,twz,nodevt,ndone,nbegin,nenable2C4,n0x,n0y,n0z,n0frame,nwx,nwz,n45,n54,n08,f408,f414,f418,f419,f41a,f41b,mf438,spd40C,f410,f43C,v1A0,v1A4,p18,p444,a1BC,sx,sz,facing64\n"
                "#U,tick,unit,ai,cls,moving,b34,cvt,men,nslots,nTgt,tgt_cx,tgt_cz,tgt_rms,tgt_s1,tgt_s2,tgt_man_d,tgt_slot_d,nNode,node_rms,node_s1,node_s2,node_man_d,node_slot_d,st0..st8(9),frameNonNull,fr0,frN0,fr1,frN1,nvt0,nvtN0,nvt1,nvtN1,spd_mean,timedN,lateN,men_cx,men_cz,cmd,container,npieces,slot_cx,slot_cz,err_mean,F2784,dirty278C,cd2788,slotrec0[9],slotrecN[9],pieces(3x15 raw),cmd+0x18..0x84 raw\n";
            DWORD w = 0;
            WriteFile(menCsv, hdr, static_cast<DWORD>(sizeof(hdr) - 1), &w, nullptr);
        }
    }
    return true;
}

// Graph walk into units[0..gCount); POD locals only (it runs inside __try).
void Gather(U model) {
    gCount = 0;
    const U M = Rd(model + 0xB0);
    if (!M) { ++badGraph; return; }
    const U sideCount = Rd(M + 0x84), sideArr = Rd(M + 0x88);
    if (!sideArr || sideCount == 0 || sideCount > kMaxSides) { ++badGraph; return; }
    U n = 0;
    for (U si = 0; si < sideCount; ++si) {
        const U side = Rd(sideArr + 4 * si);
        if (!side) { ++badGraph; continue; }
        const U ai = Rd(side + 0xC) ? 1u : 0u, sideIdx = Rd(side + 0x10);
        const U armyCount = Rd(side + 0x20), armyArr = Rd(side + 0x24);
        if (armyCount > kMaxArmies || (armyCount && !armyArr)) { ++badGraph; continue; }
        for (U ai2 = 0; ai2 < armyCount; ++ai2) {
            const U army = Rd(armyArr + 4 * ai2);
            if (!army) { ++badGraph; continue; }
            const U unitCount = Rd(army + 0xF0), unitArr = Rd(army + 0xF4);
            if (unitCount > kMaxUnits || (unitCount && !unitArr)) { ++badGraph; continue; }
            for (U ui = 0; ui < unitCount && n < kMaxUnits; ++ui) {
                const U unit = Rd(unitArr + 4 * ui);
                if (!unit) continue;
                const U members = Rd(unit + 0x2CC);
                if (Rd(unit + 0xAA0) == 2 || members == 0) continue;
                units[n].unit = unit; units[n].side = sideIdx; units[n].ai = ai; units[n].members = members;
                if (menOn && probeTotal < 8 && (ai ? probeAi < 4 : probePl < 4)) {  // one-off: where does a unit keep its army / side pointer (the lever needs unit -> side)
                    ProbeRow& p = probes[probeCount++];
                    p.unit = unit; p.ai = ai; p.nArmy = p.nSide = 0;
                    for (U off = 0; off < 0x1000; off += 4) {
                        const U v = Rd(unit + off);
                        if (v == army && p.nArmy < 4) p.armyOff[p.nArmy++] = off;
                        if (v == side && p.nSide < 4) p.sideOff[p.nSide++] = off;
                    }
                    ++probeTotal; if (ai) ++probeAi; else ++probePl;
                }
                ++n;
            }
        }
    }
    gCount = n;
}

// Mean and 2x2 covariance of n points -> centroid, rms radius and the two principal standard deviations.
struct Stats { float cx, cz, rms, s1, s2; U n; };
void Moments(const float* x, const float* z, U count, Stats* out) {
    double sxs = 0, szs = 0;
    U n = 0;
    for (U k = 0; k < count; ++k) if (Good(x[k]) && Good(z[k])) { sxs += x[k]; szs += z[k]; ++n; }
    out->n = n;
    if (!n) { out->cx = out->cz = out->rms = out->s1 = out->s2 = 0.0f; return; }
    const double cx = sxs / n, cz = szs / n;
    double a = 0, b = 0, c = 0;
    for (U k = 0; k < count; ++k) if (Good(x[k]) && Good(z[k])) {
        const double dx = x[k] - cx, dz = z[k] - cz;
        a += dx * dx; b += dx * dz; c += dz * dz;
    }
    a /= n; b /= n; c /= n;
    const double h = (a + c) * 0.5, d = sqrt(((a - c) * 0.5) * ((a - c) * 0.5) + b * b);
    out->cx = static_cast<float>(cx); out->cz = static_cast<float>(cz);
    out->rms = static_cast<float>(sqrt(a + c));
    out->s1 = static_cast<float>(sqrt(h + d > 0 ? h + d : 0));
    out->s2 = static_cast<float>(sqrt(h - d > 0 ? h - d : 0));
}

// Slot world positions of the formation's active command, as the engine itself generates them. Returns the slot count (0 = none).
//   - the six 0x581200 command classes (vtables 0x13239B0..): container [cmd+0x18], f [cmd+0x1C] (stored with the command);
//   - the formation MOVE command (vtable 0x1325470, execute slot 0x581AE0, reaching 0x576B30): the engine builds the container fresh from the command's
//     route every refresh: container = 0x7F2D70(ecx = obj = [cmd+0x18], &cmd+0x34, 0) (thiscall, ret 8), f = [obj+0x54], destroyed afterwards by
//     0x623BD0(ecx = container) + 0x126E016(container, 0x3C) exactly as 0x576B30 does.
// Every other command class (0x1324B54 idle/neighbour scan, 0x1325428 shuffle) generates no slots: the row carries nslots = 0.
U Slots(U F, U men, U* cvtOut, U* lvtOut, U* genOut, U* piecesOut) {
    *cvtOut = *lvtOut = *genOut = *piecesOut = 0;
    lastCmd = 0; pieceDumpN = 0; containerAddr = 0; memset(slotRec0, 0, sizeof slotRec0); memset(slotRecN, 0, sizeof slotRecN);
    const U queued = Rd(F + 0x460);
    slotWhy = 1;
    if (queued == 0 || queued > 8) return 0;
    const U cmd = Rd(F + 0x420 + 8 * (queued - 1));
    slotWhy = 2;
    if (!Sane(cmd)) return 0;
    lastCmd = cmd;
    const U cvt = Rd(cmd);
    *cvtOut = cvt ? cvt - delta : 0;
    bool supported = false;
    for (U i = 0; i < 6; ++i) supported = supported || cvt == V(kCommandVtables[i]);
    const bool move = cvt == V(kMoveCommandVtable) && InImage(cvt) && Rd(cvt + 4) == V(0x581AE0);
    const U layout = Rd(F + 0x628);
    if (Sane(layout)) {
        const U lvt = Rd(layout);
        *lvtOut = lvt ? lvt - delta : 0;
        if (InImage(lvt)) { const U g = Rd(lvt + 0x24); *genOut = InImage(g) ? g - delta : 0; }
    }
    slotWhy = (!supported && !move) ? 3 : (Rd(cmd + 4) != F ? 4 : (!*genOut ? 5 : 0));
    if (slotWhy) return 0;
    slotWhy = 6;
    if (men == 0 || men > kMaxMen) return 0;
    U container, fBits;
    bool ownContainer = false;
    if (move) {
        const U obj = Rd(cmd + 0x18);
        slotWhy = 7;
        if (!Sane(obj)) return 0;
        container = reinterpret_cast<Builder>(static_cast<uintptr_t>(V(0x7F2D70)))(obj, 0, cmd + 0x34, 0);
        ++nativeCalls;
        ownContainer = true;
        fBits = Rd(obj + 0x54);
    } else {
        container = Rd(cmd + 0x18);
        fBits = Rd(cmd + 0x1C);
    }
    U got = 0;
    slotWhy = 8;
    if (Sane(container)) {
        slotWhy = 9;
        const U pieces = Rd(container + 0x10), pieceArr = Rd(container + 0x14);
        *piecesOut = pieces;
        containerAddr = container;
        if (pieces != 0 && pieces <= kMaxPieces && Sane(pieceArr)) {
            pieceDumpN = pieces < 3 ? pieces : 3;
            for (U p = 0; p < pieceDumpN; ++p) for (U q = 0; q < 15; ++q) pieceDump[p][q] = Rd(pieceArr + 0x3C * p + 4 * q);
            U out[5] = {0, 0, 0, 0, 0};  // generator vector header: +4 capacity, +8 count, +0xC data (36-byte records), +0x10 mark; the generator initialises all of it
            reinterpret_cast<Generator>(static_cast<uintptr_t>(V(*genOut)))(layout, 0, static_cast<U>(reinterpret_cast<uintptr_t>(out)), container, fBits, men);
            ++nativeCalls;
            const U count = out[2], data = out[3];
            if (data && count && count <= kMaxMen && Sane(data)) {
                for (U q = 0; q < 9; ++q) { slotRec0[q] = Rd(data + 4 * q); slotRecN[q] = Rd(data + 0x24 * (count - 1) + 4 * q); }
                for (U k = 0; k < count; ++k) {
                    float w[3] = {0, 0, 0};
                    reinterpret_cast<ThisPtrOut>(static_cast<uintptr_t>(V(0x80E9D0)))(data + 0x24 * k + 4, 0, static_cast<U>(reinterpret_cast<uintptr_t>(w)));
                    ++nativeCalls;
                    sx[k] = w[0]; sz[k] = w[2];
                }
                got = count;
                slotWhy = 0;
            }
            if (data) reinterpret_cast<HeapFree>(static_cast<uintptr_t>(V(0xFF7EF0)))(data);
        }
    }
    if (ownContainer && container) {
        reinterpret_cast<ThisVoid>(static_cast<uintptr_t>(V(0x623BD0)))(container, 0);
        reinterpret_cast<HeapFree2>(static_cast<uintptr_t>(V(0x126E016)))(container, 0x3C);
        nativeCalls += 2;
    }
    return got;
}

// Mean distance of each man (first 1024 valid men) to its nearest other man (all valid men): spacing for a formation, the soft-collision floor for a packed blob.
float NnMean(const float* x, const float* z, U count) {
    double sum = 0; U n = 0;
    for (U i = 0; i < count && n < 1024; ++i) {
        if (!Good(x[i]) || !Good(z[i])) continue;
        float best = 1e30f;
        for (U j = 0; j < count; ++j) {
            if (j == i || !Good(x[j]) || !Good(z[j])) continue;
            const float dx = x[i] - x[j], dz = z[i] - z[j], d = dx * dx + dz * dz;
            if (d < best) best = d;
        }
        if (best < 1e29f) { sum += sqrt(static_cast<double>(best)); ++n; }
    }
    return n ? static_cast<float>(sum / n) : -1.0f;
}

// ---- men-level steering census (NTW2_FORMATION_CENSUS_MEN=1, launcher --formation-census-men): what each man of a tracked unit is actually steering to ----
// Agent A (the man object, position [A+0x48]/[A+0x50]): order [A+0x1D8], path-follower state [A+0x390] (1 request, 2/3 path, 4/5 moving, 6/7 done), MOVE target = 20-byte
// position object at A+0x3F4 (x,y,z,?,frame* at +0x10; world = 0x80E9D0), desired speed [A+0x40C], timed-arrival time [A+0x410], elapsed [A+0x43C], flags [A+0x414/418..41B/420],
// move flags [A+0x438]; order-FSM node inline at A+0x22C (vtable, owner +4, done +8 = A+0x234, slot position object at node+0x1C = A+0x248, node+0x45 relative flag, +0x54 unfinished flag).
void FlushMen() {
    if (menCsv != INVALID_HANDLE_VALUE && menLen) { DWORD w = 0; WriteFile(menCsv, menBuf, menLen, &w, nullptr); }
    menLen = 0;
}
template <class... A> void EmitM(const char* fmt, A... a) {
    if (menLen + 8192 > kBufBytes) FlushMen();
    const int n = _snprintf_s(menBuf + menLen, kBufBytes - menLen, _TRUNCATE, fmt, a...);
    if (n > 0) menLen += static_cast<U>(n);
}
float tx[kMaxMen], tz[kMaxMen], nx[kMaxMen], nz[kMaxMen];
inline unsigned char RdB(U a) { return *reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(a)); }

// World position of a 20-byte position object (0x80E9D0); false if the frame pointer is bad or the call faults.
bool WorldOfRaw(U obj, float* x, float* z) {
    __try {
        const U frame = Rd(obj + 0x10);
        if (frame != 0 && !Sane(frame)) return false;
        float w[3] = {0, 0, 0};
        reinterpret_cast<ThisPtrOut>(static_cast<uintptr_t>(V(0x80E9D0)))(obj, 0, static_cast<U>(reinterpret_cast<uintptr_t>(w)));
        *x = w[0]; *z = w[2];
        return Good(w[0]) && Good(w[2]);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void MenDetail(const Gathered& u, U F, U cmd, U men, U manArr, U nslots, bool moving, U cls, U cvt, U tick) {
    if (menFailed || !menOpened) return;
    U stHist[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0}, frameNonNull = 0, nTgt = 0, nNode = 0;
    U frames[2] = {0, 0}, frameN[2] = {0, 0}, nodeVt[2] = {0, 0}, nodeVtN[2] = {0, 0};
    double dSlot = 0, dMan = 0, dNodeSlot = 0, dNodeMan = 0;
    U nDSlot = 0, nDMan = 0, nDNodeSlot = 0, nDNodeMan = 0, timedN = 0, lateN = 0, spdN = 0;
    float spdSum = 0;
    const U step = men / kDetailMen ? men / kDetailMen : 1;
    for (U k = 0; k < men; ++k) {
        tx[k] = tz[k] = nx[k] = nz[k] = NAN;
        const U A = Rd(manArr + 4 * k);
        if (!Sane(A)) continue;
        const U st = Rd(A + 0x390);
        ++stHist[st < 8 ? st : 8];
        const U fr = Rd(A + 0x3F4 + 0x10);
        if (fr) {
            ++frameNonNull;
            for (U i = 0; i < 2; ++i) if (frames[i] == fr || !frames[i]) { frames[i] = fr; ++frameN[i]; break; }
        }
        float wx = 0, wz = 0;
        const bool haveT = WorldOfRaw(A + 0x3F4, &wx, &wz);
        if (haveT) {
            tx[k] = wx; tz[k] = wz; ++nTgt;
            if (Good(mx[k])) { dMan += sqrt((wx - mx[k]) * (wx - mx[k]) + (wz - mz[k]) * (wz - mz[k])); ++nDMan; }
            if (k < nslots && Good(sx[k])) { dSlot += sqrt((wx - sx[k]) * (wx - sx[k]) + (wz - sz[k]) * (wz - sz[k])); ++nDSlot; }
        }
        const U vt = Rd(A + 0x22C);
        for (U i = 0; i < 2; ++i) if (nodeVt[i] == vt || !nodeVtN[i]) { nodeVt[i] = vt; ++nodeVtN[i]; break; }
        float nwx = 0, nwz = 0;
        const bool haveN = WorldOfRaw(A + 0x248, &nwx, &nwz);
        if (haveN) {
            nx[k] = nwx; nz[k] = nwz; ++nNode;
            if (Good(mx[k])) { dNodeMan += sqrt((nwx - mx[k]) * (nwx - mx[k]) + (nwz - mz[k]) * (nwz - mz[k])); ++nDNodeMan; }
            if (k < nslots && Good(sx[k])) { dNodeSlot += sqrt((nwx - sx[k]) * (nwx - sx[k]) + (nwz - sz[k]) * (nwz - sz[k])); ++nDNodeSlot; }
        }
        if (st == 4 || st == 5) { const float sp = RdF(A + 0x40C); if (Good(sp)) { spdSum += sp; ++spdN; } }
        if (RdB(A + 0x414)) ++timedN;
        if (RdF(A + 0x43C) > RdF(A + 0x410)) ++lateN;
        if (k % step == 0 || k + 1 == men) {
            const float x = Good(mx[k]) ? mx[k] : -1.0f, z = Good(mz[k]) ? mz[k] : -1.0f;
            EmitM("M,%u,0x%08X,%u,%u,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%.3f,0x%X,%.2f,%.2f,"
                  "0x%X,%u,%u,%u,%.2f,%.2f,%.2f,0x%X,%.2f,%.2f,%u,%u,%u,"
                  "%u,%u,%u,%u,%u,%u,0x%X,%.3f,%.3f,%.3f,%.3f,%.3f,0x%X,0x%X,%u,%.2f,%.2f,%u\n",
                  tick, u.unit, u.ai, k, x, z, st, Rd(A + 0x1D8), RdF(A + 0x3F4), RdF(A + 0x3F8), RdF(A + 0x3FC), RdF(A + 0x400), Rd(A + 0x404), haveT ? wx : -1.0f, haveT ? wz : -1.0f,
                  vt ? vt - delta : 0, RdB(A + 0x234), RdB(A + 0x23C), Rd(A + 0x2C4), RdF(A + 0x248), RdF(A + 0x24C), RdF(A + 0x250), Rd(A + 0x258), haveN ? nwx : -1.0f, haveN ? nwz : -1.0f,
                  RdB(A + 0x22C + 0x45), RdB(A + 0x22C + 0x54), RdB(A + 0x22C + 0x8),
                  RdB(A + 0x408), RdB(A + 0x414), RdB(A + 0x418), RdB(A + 0x419), RdB(A + 0x41A), RdB(A + 0x41B), Rd(A + 0x438), RdF(A + 0x40C), RdF(A + 0x410), RdF(A + 0x43C), RdF(A + 0x1A0), RdF(A + 0x1A4),
                  Rd(A + 0x18), Rd(A + 0x444), Rd(A + 0x1BC), k < nslots ? sx[k] : -1.0f, k < nslots ? sz[k] : -1.0f, Rd(A + 0x64) & 0xFFFFu);
        }
    }
    Stats ts, ns, ms;
    Moments(tx, tz, men, &ts);
    Moments(nx, nz, men, &ns);
    Moments(mx, mz, men, &ms);
    Stats sst = {0, 0, 0, 0, 0, 0};
    float errMean = -1.0f;
    if (nslots) {
        Moments(sx, sz, nslots, &sst);
        double es = 0; U en = 0;
        for (U k = 0; k < men && k < nslots; ++k) if (Good(mx[k]) && Good(sx[k]) && Good(sz[k])) { es += sqrt((mx[k] - sx[k]) * (mx[k] - sx[k]) + (mz[k] - sz[k]) * (mz[k] - sz[k])); ++en; }
        if (en) errMean = static_cast<float>(es / en);
    }
    const float dm = nDMan ? static_cast<float>(dMan / nDMan) : -1.0f, ds = nDSlot ? static_cast<float>(dSlot / nDSlot) : -1.0f;
    const float ndm = nDNodeMan ? static_cast<float>(dNodeMan / nDNodeMan) : -1.0f, nds = nDNodeSlot ? static_cast<float>(dNodeSlot / nDNodeSlot) : -1.0f;
    EmitM("U,%u,0x%08X,%u,%u,%u,%u,0x%X,%u,%u,%u,%.2f,%.2f,%.3f,%.3f,%.3f,%.2f,%.2f,%u,%.3f,%.3f,%.3f,%.2f,%.2f,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
          "%u,0x%X,%u,0x%X,%u,0x%X,%u,0x%X,%u,%.3f,%u,%u,%.2f,%.2f,0x%X,0x%X,%u,%.2f,%.2f,%.2f,0x%X,%u,%u",
          tick, u.unit, u.ai, cls, moving ? 1u : 0u, Rd(u.unit + 0xB34), cvt, men, nslots, nTgt, ts.cx, ts.cz, ts.rms, ts.s1, ts.s2, dm, ds,
          nNode, ns.rms, ns.s1, ns.s2, ndm, nds,
          stHist[0], stHist[1], stHist[2], stHist[3], stHist[4], stHist[5], stHist[6], stHist[7], stHist[8],
          frameNonNull, frames[0], frameN[0], frames[1], frameN[1], nodeVt[0] ? nodeVt[0] - delta : 0, nodeVtN[0], nodeVt[1] ? nodeVt[1] - delta : 0, nodeVtN[1],
          spdN ? spdSum / spdN : -1.0f, timedN, lateN, ms.cx, ms.cz, lastCmd, containerAddr, pieceDumpN, sst.cx, sst.cz, errMean,
          Rd(F + 0x2784), static_cast<U>(RdB(F + 0x278C)), Rd(F + 0x2788));
    for (U q = 0; q < 9; ++q) EmitM(",%08X", slotRec0[q]);
    for (U q = 0; q < 9; ++q) EmitM(",%08X", slotRecN[q]);
    for (U p = 0; p < pieceDumpN; ++p) for (U q = 0; q < 15; ++q) EmitM(",%08X", pieceDump[p][q]);
    if (Sane(cmd)) for (U q = 0x18; q <= 0x84; q += 4) EmitM(",%08X", Rd(cmd + q));
    if (Sane(cmd) && Sane(Rd(cmd + 0x18))) for (U q = 0; q <= 0x98; q += 4) EmitM(",%08X", Rd(Rd(cmd + 0x18) + q));
    EmitM("\n");
}

// Tracked units are also sampled EVERY tick for kFreshTicks ticks after a new formation command object appears in their queue (the first ticks of a march decide the
// man<->slot assignment; the regular period is too coarse to see them).
struct Tracked { U unit, side, ai, members, cmd, fresh; };
constexpr U kMaxTracked = 16, kFreshTicks = 60;
Tracked tr[kMaxTracked];
U trCount;

void ObserveFine(Tracked& t, U tick) {
    if (Rd(t.unit + 0xAA0) == 2) return;
    U sel = Rd(t.unit + 0xAE8);
    U F = Rd(t.unit + 0xADC);
    if ((sel == 1 || sel == 2) && Sane(Rd(t.unit + 0xADC + 4 * sel))) F = Rd(t.unit + 0xADC + 4 * sel);
    if (!Sane(F)) return;
    const U queued = Rd(F + 0x460);
    U cmd = 0;
    if (queued >= 1 && queued <= 8) cmd = Rd(F + 0x420 + 8 * (queued - 1));
    const U cvtNow = Sane(cmd) ? Rd(cmd) : 0;
    if (cvtNow != t.cmd) { t.cmd = cvtNow; if (cvtNow == V(kMoveCommandVtable)) t.fresh = kFreshTicks; }
    if (!t.fresh) return;
    --t.fresh;
    const U men = Rd(F + 0x18), manArr = Rd(F + 0x1C);
    if (men == 0 || men > kMaxMen || !Sane(manArr)) return;
    for (U k = 0; k < men; ++k) {
        const U m = Rd(manArr + 4 * k);
        mx[k] = mz[k] = NAN;
        if (!Sane(m)) continue;
        const float x = RdF(m + 0x48), z = RdF(m + 0x50);
        if (Good(x) && Good(z)) { mx[k] = x; mz[k] = z; }
    }
    U cvt, lvt, gen, pieces;
    const U nslots = Slots(F, men, &cvt, &lvt, &gen, &pieces);
    bool moving = false;
    if (MovingSafe(t.unit)) { moving = reinterpret_cast<ThisBool>(static_cast<uintptr_t>(V(0x55C320)))(t.unit, 0) != 0; ++nativeCalls; }
    const U clsPtr = Rd(t.unit + 0x2C);
    const Gathered g = {t.unit, t.side, t.ai, t.members};
    MenDetail(g, F, lastCmd, men, manArr, nslots, moving, Sane(clsPtr) ? Rd(clsPtr + 0x1C) : 0xFFu, cvt, tick);
}
bool ObserveFineGuarded(Tracked& t, U tick) {
    __try { ObserveFine(t, tick); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void Observe(const Gathered& u, U model, U tick) {
    U sel = Rd(u.unit + 0xAE8);
    U F = Rd(u.unit + 0xADC);
    if ((sel == 1 || sel == 2) && Sane(Rd(u.unit + 0xADC + 4 * sel))) F = Rd(u.unit + 0xADC + 4 * sel);
    if (!Sane(F)) { ++badGraph; return; }
    const U men = Rd(F + 0x18), manArr = Rd(F + 0x1C);
    if (men == 0 || men > kMaxMen || !Sane(manArr)) { ++noMen; return; }
    const U fvt = Rd(F);
    U nValid = 0;
    for (U k = 0; k < men; ++k) {
        const U m = Rd(manArr + 4 * k);
        mx[k] = mz[k] = NAN;
        if (!Sane(m)) continue;
        const float x = RdF(m + 0x48), z = RdF(m + 0x50);
        if (!Good(x) || !Good(z)) continue;
        mx[k] = x; mz[k] = z; ++nValid;
    }
    if (nValid == 0) { ++noMen; return; }
    Stats ms;
    Moments(mx, mz, men, &ms);

    const U clsPtr = Rd(u.unit + 0x2C);
    const U cls = Sane(clsPtr) ? Rd(clsPtr + 0x1C) : 0xFFu;
    bool moving = false;
    if (MovingSafe(u.unit)) { moving = reinterpret_cast<ThisBool>(static_cast<uintptr_t>(V(0x55C320)))(u.unit, 0) != 0; ++nativeCalls; }

    U cvt, lvt, gen, pieces;
    const U nslots = Slots(F, men, &cvt, &lvt, &gen, &pieces);
    if (nslots == 0 && slotWhy == 0) slotWhy = 10;
    ++whyHist[slotWhy > 15 ? 15 : slotWhy];
    Stats ss = {0, 0, 0, 0, 0, 0};
    float errMean = -1.0f, errMax = -1.0f;
    if (nslots) {
        Moments(sx, sz, nslots, &ss);
        double es = 0; U en = 0; float em = 0;
        for (U k = 0; k < men && k < nslots; ++k) {
            if (!Good(mx[k]) || !Good(sx[k]) || !Good(sz[k])) continue;
            const float dx = mx[k] - sx[k], dz = mz[k] - sz[k], d = sqrtf(dx * dx + dz * dz);
            es += d; ++en; if (d > em) em = d;
        }
        if (en) { errMean = static_cast<float>(es / en); errMax = em; }
    } else ++noGenerator;
    const float ratio = (nslots && ss.rms > 0.01f) ? ms.rms / ss.rms : -1.0f;

    UnitState* st = Find(u.unit, tick);
    float rms0 = -1.0f;
    if (st) { if (st->rms0 < 0.0f) st->rms0 = ms.rms; rms0 = st->rms0; st->lastSeen = tick; }
    const float ratio0 = rms0 > 0.01f ? ms.rms / rms0 : -1.0f;
    float speed = -1.0f;  // metres per second of the men centroid since this unit's previous sample (10 model ticks per second)
    if (st) {
        if (st->have && tick > st->ctick) speed = sqrtf((ms.cx - st->lcx) * (ms.cx - st->lcx) + (ms.cz - st->lcz) * (ms.cz - st->lcz)) * 10.0f / static_cast<float>(tick - st->ctick);
        st->lcx = ms.cx; st->lcz = ms.cz; st->ctick = tick; st->have = 1;
    }
    const float nn = NnMean(mx, mz, men);
    const bool eligible = moving && men >= kMovingMinMen;
    const bool collapsed = eligible && ratio >= 0.0f && ratio < kCollapseRatio;
    const bool collapsedRef = eligible && ratio0 >= 0.0f && ratio0 < kCollapseRatio;

    Agg& g = agg[u.ai ? 1 : 0];
    ++g.unitSamples;
    if (st && !st->counted) { st->counted = 1; ++g.units; }
    if (eligible) {
        ++g.moving60;
        if (ratio >= 0.0f) {
            ++g.slotted;
            U b = static_cast<U>(ratio / 0.1f); if (b >= kHistBins) b = kHistBins - 1;
            ++g.hist[b];
            if (ratio < g.ratioMin) g.ratioMin = ratio;
            g.ratioSum += ratio;
        } else ++g.movingNoSlots;
        if (collapsed) {
            ++g.collapsed;
            if (st && !(st->collapsedEver & 1u)) { st->collapsedEver |= 1u; ++g.collapsedUnits; }
        }
        if (collapsedRef) ++g.collapsedRef;
    }

    const U layout = Rd(F + 0x628);
    float l8 = 0, lc = 0, l10 = 0, l14 = 0;
    if (Sane(layout)) { l8 = RdF(layout + 8); lc = RdF(layout + 0xC); l10 = RdF(layout + 0x10); l14 = RdF(layout + 0x14); }
    Emit("%u,0x%08X,%u,%u,0x%08X,%u,%u,%u,%u,%u,%u,0x%X,0x%X,0x%X,0x%X,%u,%u,%u,%u,"
         "%.2f,%.2f,%.3f,%.3f,%.3f,%.2f,%.2f,%.3f,%.3f,%.3f,%.4f,%.3f,%.3f,"
         "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.3f,%.4f,%d,%d,%.3f,%.3f,%u\n",
         tick, model, u.side, u.ai, u.unit, cls, u.members, men, moving ? 1u : 0u, Rd(u.unit + 0xB34), sel, fvt ? fvt - delta : 0, lvt, gen, cvt,
         static_cast<U>(*reinterpret_cast<const volatile unsigned char*>(static_cast<uintptr_t>(F + 0x278C))), Rd(F + 0x2788), nslots, pieces,
         ms.cx, ms.cz, ms.rms, ms.s1, ms.s2, ss.cx, ss.cz, ss.rms, ss.s1, ss.s2, ratio, errMean, errMax,
         RdF(u.unit + 0x2F8), RdF(u.unit + 0x2FC), l8, lc, l10, l14, rms0, ratio0, collapsed ? 1 : 0, collapsedRef ? 1 : 0, speed, nn, slotWhy);
    ++totalRows;
    if (menOn && st) {
        if (!st->track && men >= 400 && trCount < kMaxTracked) {
            bool take = false;
            if (u.ai && trackedAi < kTrackAi) { ++trackedAi; take = true; }
            else if (!u.ai && trackedPlayer < kTrackPlayer) { ++trackedPlayer; take = true; }
            if (take) { st->track = 1; tr[trCount].unit = u.unit; tr[trCount].side = u.side; tr[trCount].ai = u.ai; tr[trCount].members = u.members; tr[trCount].cmd = Sane(lastCmd) ? Rd(lastCmd) : 0; tr[trCount].fresh = 0; ++trCount; }
        }
        if (st->track) {
            for (U i = 0; i < trCount; ++i) if (tr[i].unit == u.unit) { const U cvtNow = Sane(lastCmd) ? Rd(lastCmd) : 0; if (tr[i].cmd != cvtNow) { tr[i].cmd = cvtNow; if (cvtNow == V(kMoveCommandVtable)) tr[i].fresh = kFreshTicks; } break; }
            MenDetail(u, F, lastCmd, men, manArr, nslots, moving, cls, cvt, tick);
        }
    }
}

bool ObserveGuarded(const Gathered& u, U model, U tick) {
    __try { Observe(u, model, tick); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool GatherGuarded(U model) {
    __try { Gather(model); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void Fault() {
    ++faults; ++battleFaults;
    if (battleFaults > kMaxBattleFaults) disabled = true;
}
}  // namespace

void Reset(bool enable, U imageDelta, U base, U size) {
    if (csv != INVALID_HANDLE_VALUE) { Flush(); CloseHandle(csv); csv = INVALID_HANDLE_VALUE; }
    if (menCsv != INVALID_HANDLE_VALUE) { FlushMen(); CloseHandle(menCsv); menCsv = INVALID_HANDLE_VALUE; }
    menOn = menOpened = menFailed = false; menLen = 0; trackedAi = trackedPlayer = 0; trCount = 0;
    memset(table, 0, sizeof(table));
    memset(agg, 0, sizeof(agg));
    for (U a = 0; a < 2; ++a) agg[a].ratioMin = 1e9f;
    enabled = enable; disabled = false; opened = openFailed = false;
    delta = imageDelta; imageLo = base; imageSize = size; lastModel = 0; battleFaults = 0; gCount = 0; bufLen = 0; every = kDefaultEvery;
    passes = totalRows = faults = nativeCalls = noGenerator = noMen = badGraph = slotWhy = 0;
    memset(whyHist, 0, sizeof(whyHist));
    csvPath[0] = 0; sumPath[0] = 0;
}

void Tick(U model, U modelTick) {
    if (!enabled || disabled) return;
    if (model != lastModel) {
        memset(table, 0, sizeof(table));
        lastModel = model; disabled = false; battleFaults = 0; trackedAi = trackedPlayer = 0; trCount = 0;
    }
    if (!OpenOutput()) return;
    if (modelTick % every != 0) {
        if (menOn && trCount) {
            ++ntw2::probeDepth;
            for (U i = 0; i < trCount; ++i) if (!ObserveFineGuarded(tr[i], modelTick)) Fault();
            --ntw2::probeDepth;
            FlushMen();
        }
        return;
    }
    ++ntw2::probeDepth;  // every fault below is an expected, caught one: not a crash capture (CrashVeh)
    ++passes;
    if (!GatherGuarded(model)) Fault();
    else {
        for (U i = 0; i < gCount && !disabled; ++i)
            if (!ObserveGuarded(units[i], model, modelTick)) Fault();
    }
    for (U i = 0; i < probeCount; ++i) {
        const ProbeRow& p = probes[i];
        EmitM("#probe,unit=0x%08X,ai=%u,army_off=", p.unit, p.ai);
        for (U q = 0; q < p.nArmy; ++q) EmitM("0x%X;", p.armyOff[q]);
        EmitM(",side_off=");
        for (U q = 0; q < p.nSide; ++q) EmitM("0x%X;", p.sideOff[q]);
        EmitM("\n");
    }
    probeCount = 0;
    --ntw2::probeDepth;
    Flush(); FlushMen();
    WriteSummary();
}

void Stop() {
    if (!enabled) return;
    Flush(); FlushMen();
    WriteSummary();  // the file stays open: a dormant runtime that resumes ticking keeps appending to the same CSV (Reset closes it)
}
}  // namespace ntw2_formation_census
