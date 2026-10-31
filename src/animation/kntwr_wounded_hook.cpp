// --wounded hooks (contract: kntwr_wounded_hook.h; policy: kntwr_wounded.h; evidence: analysis/FINDINGS.md
// "Wounded/corpse animation infrastructure census" and "--wounded render freeze" entries, 2026-10-31).
//
// Two 8-byte entry patches, both installed by Install and removed by Remove:
//
// Site A (state commit) 0x653F1A (kill path 0x653A10; ECX = normalized death category 1..0x35F, EBP = man anim FSM M):
//   8B 15 C8 21 45 01     mov edx, [0x14521C8]      (knockdown range lo)
//   3B CA                 cmp ecx, edx
// = 8 bytes of complete displaced instructions, replaced by `jmp rel32` (CommitGate) + 3 int3. The gate does NOT replay
// them: Decide() recomputes the full state select the stock code 0x653F1A..0x653F38 performs (range test -> 0x4B, else
// 0x2A) plus the opt-in flip, writes the state into the saved-EAX slot and [0x14521C8] into the saved-EDX slot of its
// pushad frame (the exact registers stock code leaves at the resume point), then jumps g_resume = site+0x1F (0x653F39
// relocated: `mov [ebp+0x1B8], eax`). The bypassed stock select is dead while installed and restored bit-exactly.
//
// Site B (render remap repair) 0xE61020 (unique-clip builder, thiscall, ECX = anim table; runs at table load):
//   83 EC 08              sub esp, 8
//   56                    push esi
//   8B F1                 mov esi, ecx
//   33 C9                 xor ecx, ecx
// = 8 bytes of complete, position-independent displaced instructions. BuildGate identity-writes the render
// pose-category remap [table+0x3C] for the wounded families BEFORE the builder's two passes run, replays the displaced
// bytes and resumes at site+8. Why before: the builder's pass 1 marks only clip entries reachable through the remap,
// pass 2 and the slot assigner 0xE61160 then give exactly those entries their sampler slot [entry+0x4C] and size
// [table+0x50]. The stock remap maps every WOUNDED_*/FALL_OVER_* category (0x330..0x33C) to 0x360 "no pose", so wounded
// clips keep slot -1 forever; repairing the remap at RUNTIME (the first shipped attempt) made the picker return
// slot-less clips and the keyframe sampler 0x121E7A0 indexed its row table with -1 -> crash at 0x121EAC0 (minidump
// kntwr-27396-0.dmp: [item+0x20] = 0xFFFFFFFF). Repairing at build time gives the wounded clips real slots and sizes
// every downstream array consistently. Without site B the remap stays stock and flipped men freeze (the renderer skips
// posing them) - degraded but safe; that is the deliberate fallback whenever only site A can be (or stay) patched.
// The same gate also FACE-tags untagged men death clips (TagOrient: categories 0x293..0x311, name A-string on the clip hashed
// into kntwr_wounded_orient.h) so the stock wounded FSM, which only accepts clips with the FACE presence bytes set, can use them.
//
// Decide walks native memory read-only on the owner (simulation) thread that runs the kill path, exactly like the stock
// stepper 0x679300 does one frame later: holder [M+0x218] -> table -> records [table+0x2C] -> record cat*0x18 -> clip
// (rnd % count, rnd = [M+0x1E0] - the same deterministic re-pick the stepper performs, so the inspected FACE fields
// belong to the clip that is actually playing). Every dereference sits under SEH; a fault counts WFaults and commits the
// stock static state. No allocation, no native call, integer-only. BuildFix repairs the remap and FACE-tags untagged death clips under the same SEH policy.
//
// Thread-freeze / interior-IP refusal / 8-byte CAS policy is the shared core/kntwr_entry_patch.h. Remove refuses while
// any peer is inside either gate (EIP in its [begin, end) or its in-gate counter); a CAS mismatch writes NOTHING.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string.h>
#include <windows.h>
#include <intrin.h>
#include "core/kntwr_entry_patch.h"
#include "kntwr_wounded.h"
#include "kntwr_wounded_hook.h"

namespace kntwr_wounded_hook {
namespace {

constexpr U kPreferred = 0x400000u;      // Napoleon.exe preferred image base
constexpr U kSpan = 8;                   // both sites displace exactly 8 bytes of complete instructions
constexpr U kResumeOffset = 0x1Fu;       // site A+0x1F = 0x653F39, the `mov [ebp+0x1B8], eax` state store
constexpr U kRangeLo = 0x14521C8u;       // preferred-VA of the knockdown category range {lo, count}
constexpr U kCategoryCount = 0x360u;     // anim category table size; normalized cat is always < this
// Render pose-category remap ([table+0x3C], 0x360 dwords, read by the visual item update 0x7725D0 at 0x772AE3 and by
// the unique-clip builder 0xE61020 pass 1): entries holding 0x360 mean "no pose". Identity-map the wounded families at
// table-build time so their clips get sampler slots and the renderer poses them (see the site B header comment).
constexpr U kRemapOffset = 0x3Cu;        // table+0x3C -> U[0x360] pose-category remap
constexpr U kRemapFirst = 0x330u;        // WOUNDED_FRONT_IDLE .. FALL_OVER_4
constexpr U kRemapLast = 0x33Cu;         // inclusive; 9 WOUNDED_* + 4 FALL_OVER_* (cat 0x339 observed live in state 0x4B)
// Site A preferred-base template: the disp32 at +2 carries a base relocation, rebuilt per image base at Install.
constexpr unsigned char kStock[kSpan] = {0x8B,0x15,0xC8,0x21,0x45,0x01,0x3B,0xCA};
// Site B stock bytes carry no relocation; compared and restored verbatim.
constexpr U kBuildSite = 0xE61020u;
constexpr unsigned char kBuildStock[kSpan] = {0x83,0xEC,0x08,0x56,0x8B,0xF1,0x33,0xC9};
// Gate tail markers (never executed): scanned at Install to bound each gate's code range, validated by requiring the
// absolute jmp immediately before them, so a coincidental earlier match cannot shrink the range.
constexpr unsigned char kTailMarker[8] = {0xD1,0x6E,0x3A,0x97,0xC4,0x08,0x5F,0xB2};
constexpr unsigned char kBuildTailMarker[8] = {0x3E,0x81,0xD4,0x5A,0x29,0xC7,0x66,0x1B};
constexpr U kJmpBytes = 6;               // FF 25 <addr32>: jmp dword ptr [g_resume]
constexpr U kGateScanBytes = 192;

volatile U g_resume = 0;                 // site A+0x1F; written only while no gate execution can be in flight
volatile U g_buildResume = 0;            // site B+8; written only while no gate execution can be in flight
volatile U g_rangeLo = 0;                // relocated address of [0x14521C8]; written before the patch is reachable
volatile U g_pct = 0;                    // flip probability 1..100; written before the patch is reachable
volatile LONG g_inGate = 0;              // >0 while some thread is between CommitGate's inc and dec
volatile LONG g_inBuildGate = 0;         // >0 while some thread is between BuildGate's inc and dec
volatile LONG g_installed = 0;
volatile LONG g_wasInstalled = 0;        // sticky applied-this-run, cleared only by ResetRow
volatile LONG g_lifecycle = 0;           // Install/Remove reentrancy guard (activation/teardown owner thread)
U g_site = 0;
U g_buildSite = 0;
unsigned char g_patch[8];
unsigned char g_stock[8];                // relocated site A original: 8B 15 <&rangeLo for this base> 3B CA
unsigned char g_buildPatch[8];
volatile U g_words[kWords];

bool BytesAre(U address, const unsigned char* expected, U bytes) {
    __try {
        return memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), expected, bytes) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Repairs the render pose remap of one anim table so the wounded families get sampler slots in the build passes that
// run right after this gate. Idempotent per table (first entry already identity -> no writes); runs on whatever thread
// loads the table, before any clip of it can be picked. Tables without a remap are skipped.
void FixupRemap(U table) {
    const U remap = *reinterpret_cast<const U*>(static_cast<uintptr_t>(table + kRemapOffset));
    if (!remap) return;
    volatile U* entries = reinterpret_cast<volatile U*>(static_cast<uintptr_t>(remap));
    if (entries[kRemapFirst] == kRemapFirst) return;
    for (U cat = kRemapFirst; cat <= kRemapLast; ++cat) entries[cat] = cat;
    ++g_words[WRemapFixes];
}

// Tags untagged men death clips FACE_UP/FACE_DOWN in memory from the generated orientation table so the stock wounded
// FSM (which requires byte[clip+0x60] and a nonzero param) accepts them. Death categories 0x293..0x311; clip name is the
// A-string on the clip ({len +0x8, wchar_t* +0x10}); hash = lowercased FNV-1a over UTF-16LE. Clips that already carry
// either presence byte (native tags, or tagged by an earlier build) are left alone, which makes this idempotent.
constexpr U kDeathFirst = 0x293u;
constexpr U kDeathLast = 0x311u;         // inclusive
constexpr U kRecordStride = 0x18u;
constexpr U kRecordCountOff = 0x14u;
constexpr U kRecordClipSlots = 5u;
constexpr U kClipNameLen = 0x8u, kClipNamePtr = 0x10u;
constexpr U kClipFaceUpParam = 0x54u, kClipFaceUpPresent = 0x58u;
constexpr U kClipFaceDownParam = 0x5Cu, kClipFaceDownPresent = 0x60u;
constexpr U kMaxNameLen = 512u;
void TagOrient(U table) {
    const U records = *reinterpret_cast<const U*>(static_cast<uintptr_t>(table + 0x2Cu));
    if (!records) return;
    for (U cat = kDeathFirst; cat <= kDeathLast; ++cat) {
        const U record = records + cat * kRecordStride;
        U count = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + kRecordCountOff));
        if (count > kRecordClipSlots) count = kRecordClipSlots;
        for (U i = 0; i < count; ++i) {
            const U clip = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + i * 4u));
            if (!clip) continue;
            volatile unsigned char* upPresent = reinterpret_cast<volatile unsigned char*>(static_cast<uintptr_t>(clip + kClipFaceUpPresent));
            volatile unsigned char* downPresent = reinterpret_cast<volatile unsigned char*>(static_cast<uintptr_t>(clip + kClipFaceDownPresent));
            if (*upPresent || *downPresent) continue;
            const U nameLen = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + kClipNameLen));
            const U namePtr = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + kClipNamePtr));
            if (!namePtr || !nameLen || nameLen > kMaxNameLen) continue;
            const int orient = kntwr_wounded::OrientLookup(
                kntwr_wounded::OrientHash(reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(namePtr)), nameLen));
            if (orient < 0) continue;
            *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(clip + kClipFaceUpParam)) = orient ? 0u : 1u;
            *reinterpret_cast<volatile U*>(static_cast<uintptr_t>(clip + kClipFaceDownParam)) = orient ? 1u : 0u;
            *upPresent = 1;
            *downPresent = 1;
            ++g_words[WOrientTagged];
        }
    }
}

// The only code BuildGate runs. stdcall so the gate's stack arithmetic is independent of calling-convention flags.
void __stdcall BuildFix(U table) {
    __try {
        FixupRemap(table);
        TagOrient(table);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_words[WFaults];
    }
}

// Native-memory walk; every dereference may fault, the caller holds the SEH frame. Returns the committed state.
U DecideBody(U cat, U m) {
    const U lo = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(g_rangeLo));
    const U n = *reinterpret_cast<const volatile U*>(static_cast<uintptr_t>(g_rangeLo + 4));
    if (kntwr_wounded::NativeKnockdown(cat, lo, n)) { ++g_words[WNativeKnockdown]; return kntwr_wounded::kStateWounded; }
    ++g_words[WStaticCandidates];
    const U pct = g_pct;
    if (!pct || cat >= kCategoryCount) return kntwr_wounded::kStateStatic;
    const U holder = *reinterpret_cast<const U*>(static_cast<uintptr_t>(m + 0x218));
    const U table = holder ? *reinterpret_cast<const U*>(static_cast<uintptr_t>(holder)) : 0;
    const U records = table ? *reinterpret_cast<const U*>(static_cast<uintptr_t>(table + 0x2C)) : 0;
    if (!records) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U record = records + cat * 0x18u;
    const U count = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + 0x14));
    if (!count) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U rnd = *reinterpret_cast<const U*>(static_cast<uintptr_t>(m + 0x1E0));
    const U clip = *reinterpret_cast<const U*>(static_cast<uintptr_t>(record + (rnd % count) * 4u));
    if (!clip) { ++g_words[WNoClip]; return kntwr_wounded::kStateStatic; }
    const U faceDownPresent = *reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(clip + 0x60));
    const U faceDownParam = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + 0x5C));
    const U faceUpParam = *reinterpret_cast<const U*>(static_cast<uintptr_t>(clip + 0x54));
    if (!kntwr_wounded::ClipEligible(faceDownPresent, faceDownParam, faceUpParam)) {
        ++g_words[WUntagged];
        return kntwr_wounded::kStateStatic;
    }
    ++g_words[WEligible];
    if (!kntwr_wounded::Flip(rnd, m, pct)) { ++g_words[WDeniedRoll]; return kntwr_wounded::kStateStatic; }
    ++g_words[WFlipped];
    return kntwr_wounded::kStateWounded;
}

// The only code CommitGate runs: compute the state the store at 0x653F39 commits. stdcall so the gate's stack
// arithmetic is independent of any project calling-convention flag. Counters are diagnostic only, never control flow.
U __stdcall Decide(U cat, U m) {
    ++g_words[WCalls];
    g_words[WLastCat] = cat;
    U state = kntwr_wounded::kStateStatic;
    __try {
        state = DecideBody(cat, m);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_words[WFaults];
        state = kntwr_wounded::kStateStatic;
    }
    return state;
}

// Entry state at the jmp: ECX = normalized category, EBP = man anim FSM M, ESP/EFLAGS/other GPRs = native. pushad frame
// (after `mov ebp, esp`): [ebp+0]=EDI +4=ESI +8=EBP(=M) +12=ESP +16=EBX +20=EDX +24=ECX(=cat) +28=EAX, [ebp+32]=EFLAGS.
// The gate writes Decide's state into the saved-EAX slot and [g_rangeLo] into the saved-EDX slot, so popad materializes
// the exact registers the bypassed stock select leaves: EAX = state, EDX = range lo, ECX untouched. Resumes at site+0x1F.
__declspec(naked) void CommitGate() {
    __asm {
        pushfd
        pushad
        lock inc dword ptr [g_inGate]
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push dword ptr [ebp+8]       // m  (saved EBP)
        push dword ptr [ebp+24]      // cat (saved ECX)
        call Decide
        mov [ebp+28], eax            // saved EAX = committed state
        mov ecx, [g_rangeLo]
        mov ecx, [ecx]
        mov [ebp+20], ecx            // saved EDX = [0x14521C8], as the displaced mov left it
        fxrstor [esp]
        mov esp, ebp
        lock dec dword ptr [g_inGate]
        popad
        popfd
        jmp dword ptr [g_resume]     // 6 bytes: FF 25 <&g_resume>; target = site+0x1F (0x653F39 relocated)
        _emit 0xD1                   // tail marker (never executed)
        _emit 0x6E
        _emit 0x3A
        _emit 0x97
        _emit 0xC4
        _emit 0x08
        _emit 0x5F
        _emit 0xB2
    }
}

// Entry state at the jmp: ECX = anim table (thiscall this). The gate repairs the table's remap, restores every
// register, replays the four displaced stock instructions verbatim and resumes at site B+8 (0xE61028 relocated).
__declspec(naked) void BuildGate() {
    __asm {
        pushfd
        pushad
        lock inc dword ptr [g_inBuildGate]
        mov ebp, esp
        sub esp, 528
        and esp, -16
        fxsave [esp]
        cld
        push dword ptr [ebp+24]      // table (saved ECX)
        call BuildFix
        fxrstor [esp]
        mov esp, ebp
        lock dec dword ptr [g_inBuildGate]
        popad
        popfd
        sub esp, 8                   // displaced stock bytes, replayed verbatim
        push esi
        mov esi, ecx
        xor ecx, ecx
        jmp dword ptr [g_buildResume]   // 6 bytes: FF 25 <&g_buildResume>; target = site B+8
        _emit 0x3E                   // tail marker (never executed)
        _emit 0x81
        _emit 0xD4
        _emit 0x5A
        _emit 0x29
        _emit 0xC7
        _emit 0x66
        _emit 0x1B
    }
}

// Follows a jmp rel32 thunk if the toolchain emitted one for a gate symbol (the naked bodies start 9C pushfd).
U Resolve(U fn) {
    for (U hop = 0; hop < 4; ++hop) {
        const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(fn));
        U displacement = 0, next = 0;
        __try {
            if (p[0] != 0xE9) return fn;
            memcpy(&displacement, p + 1, 4);
            next = fn + 5 + displacement;
        } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        if (next <= fn || next - fn > 0x10000u) return 0;
        fn = next;
    }
    return 0;
}

// [begin, end) covering every byte of the given gate a frozen thread could still execute, including the final 6-byte
// jmp. False on failure. The candidate marker is accepted only when the absolute jmp sits immediately before it.
bool GateRangeOf(void (*gateFn)(), const unsigned char* marker, U& begin, U& end) {
    const U gate = Resolve(static_cast<U>(reinterpret_cast<uintptr_t>(gateFn)));
    if (!gate) return false;
    const auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(gate));
    for (U offset = 0; offset + 8 <= kGateScanBytes; ++offset) {
        if (memcmp(p + offset, marker, 8) != 0) continue;
        if (offset < kJmpBytes) return false;
        if (p[offset - kJmpBytes] != 0xFF || p[offset - kJmpBytes + 1] != 0x25) continue;
        begin = gate;
        end = gate + offset;   // marker start: the whole final jmp lies in [end-6, end); a thread parked on it
                               // has already dec'd its in-gate counter, so only this EIP range catches it
        return true;
    }
    return false;
}

void MakeJmpPatch(unsigned char* patch, U site, U target) {
    memset(patch, 0xCC, 8);
    patch[0] = 0xE9;
    const U displacement = target - site - 5;
    memcpy(patch + 1, &displacement, 4);
}

bool InstallLocked(U imageBase, U pct) {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) != 0) return false;
    if (!imageBase || !pct || pct > 100u) return false;
    U gateBegin = 0, gateEnd = 0, buildBegin = 0, buildEnd = 0;
    if (!GateRangeOf(&CommitGate, kTailMarker, gateBegin, gateEnd)) return false;      // gate layouts pinned before
    if (!GateRangeOf(&BuildGate, kBuildTailMarker, buildBegin, buildEnd)) return false; // they are ever entered
    const U site = imageBase - kPreferred + kCommitSite;
    const U buildSite = imageBase - kPreferred + kBuildSite;
    const U rangeLo = imageBase - kPreferred + kRangeLo;
    unsigned char stock[8];
    memcpy(stock, kStock, 8);
    memcpy(stock + 2, &rangeLo, 4);                                 // the loader relocated the disp32 with the image
    if (!BytesAre(site, stock, kSpan)) return false;                // exact pinned originals, all 8 bytes, both sites
    if (!BytesAre(buildSite, kBuildStock, kSpan)) return false;
    memcpy(g_stock, stock, 8);
    MakeJmpPatch(g_patch, site, gateBegin);
    MakeJmpPatch(g_buildPatch, buildSite, buildBegin);
    // Written BEFORE either patch is reachable and immutable afterwards: not installed (checked above), and a previous
    // successful Remove drained the gates, so no in-flight gate execution can read these.
    g_site = site;
    g_buildSite = buildSite;
    g_resume = site + kResumeOffset;                                // 0x653F39 relocated
    g_buildResume = buildSite + kSpan;                              // 0xE61028 relocated
    g_rangeLo = rangeLo;
    g_pct = pct;
    const kntwr_entry_patch::Guard drainA{gateBegin, gateEnd, &g_inGate};        // cannot trip before the patch exists
    if (!kntwr_entry_patch::Swap8(site, g_stock, g_patch, kSpan, drainA, [] {})) return false;
    const kntwr_entry_patch::Guard drainB{buildBegin, buildEnd, &g_inBuildGate};
    if (!kntwr_entry_patch::Swap8(buildSite, kBuildStock, g_buildPatch, kSpan, drainB, [] {
            _InterlockedExchange(&g_installed, 1);
            _InterlockedExchange(&g_wasInstalled, 1);
            g_words[WInstalled] = 1;
        })) {
        // Site B refused (foreign bytes raced in, or a frozen peer sat in the fresh commit-gate span). Roll site A
        // back so a failed Install leaves the image untouched. A rollback refusal can only mean a peer is executing
        // the commit gate right now; the half state (site A only) is the safe degraded mode - flips freeze, never
        // crash - so account it as installed rather than leaving an unowned patch behind.
        const kntwr_entry_patch::Guard redrainA{gateBegin, gateEnd, &g_inGate};
        if (!kntwr_entry_patch::Swap8(site, g_patch, g_stock, kSpan, redrainA, [] {})) {
            _InterlockedExchange(&g_installed, 1);
            _InterlockedExchange(&g_wasInstalled, 1);
            g_words[WInstalled] = 1;
            return true;
        }
        g_site = 0;
        g_buildSite = 0;
        return false;
    }
    return true;
}

bool RemoveLocked() {
    if (_InterlockedCompareExchange(&g_installed, 0, 0) == 0) return true;
    U gateBegin = 0, gateEnd = 0, buildBegin = 0, buildEnd = 0;
    if (!GateRangeOf(&CommitGate, kTailMarker, gateBegin, gateEnd)) return false;   // cannot prove drain; keep the
    if (!GateRangeOf(&BuildGate, kBuildTailMarker, buildBegin, buildEnd)) return false; // patches and the resources
    // Site B first: with it gone, remaining flips only freeze (remap untouched for new tables), never crash. Each Swap8
    // refuses while a frozen peer is anywhere in its gate (EIP range or in-gate counter); a CAS mismatch (foreign
    // bytes) writes nothing and reports failure - never claims success on a mismatch.
    const kntwr_entry_patch::Guard drainB{buildBegin, buildEnd, &g_inBuildGate};
    if (g_buildSite && !kntwr_entry_patch::Swap8(g_buildSite, g_buildPatch, kBuildStock, kSpan, drainB, [] {})) return false;
    const U removedBuildSite = g_buildSite;
    g_buildSite = 0;
    const kntwr_entry_patch::Guard drainA{gateBegin, gateEnd, &g_inGate};
    const bool swapped = kntwr_entry_patch::Swap8(g_site, g_patch, g_stock, kSpan, drainA, [] {
        _InterlockedExchange(&g_installed, 0);
    });
    if (!swapped) {
        // Site A still patched: re-arm site B so the installed state stays the full, consistent pair. If the re-arm
        // also refuses, the remaining half state (site A only) is the safe degraded mode described above.
        if (removedBuildSite) {
            const kntwr_entry_patch::Guard redrainB{buildBegin, buildEnd, &g_inBuildGate};
            if (kntwr_entry_patch::Swap8(removedBuildSite, kBuildStock, g_buildPatch, kSpan, redrainB, [] {}))
                g_buildSite = removedBuildSite;
        }
        return false;
    }
    g_site = 0;
    return true;
}
} // namespace

void ResetRow() {
    for (U i = 0; i < kWords; ++i) g_words[i] = 0;
    _InterlockedExchange(&g_wasInstalled, 0);
    g_words[WVersion] = kVersion;
}

void Snapshot(volatile U* out) {
    for (U i = 0; i < kWords; ++i) out[i] = g_words[i];
    out[WInstalled] = _InterlockedCompareExchange(&g_wasInstalled, 0, 0) != 0 ? 1u : 0u;
}

bool Install(U imageBase, U pct) {
    g_words[WRequested] = 1;
    if (_InterlockedCompareExchange(&g_lifecycle, 1, 0) != 0) return false;
    const bool ok = InstallLocked(imageBase, pct);
    _InterlockedExchange(&g_lifecycle, 0);
    return ok;
}

bool Remove() {
    if (_InterlockedCompareExchange(&g_lifecycle, 1, 0) != 0) return false;
    const bool ok = RemoveLocked();
    _InterlockedExchange(&g_lifecycle, 0);
    return ok;
}

bool Installed() {
    return _InterlockedCompareExchange(&g_installed, 0, 0) != 0;
}
} // namespace kntwr_wounded_hook
