// See native_formation_batch.h.  Every block cites the native VA it mirrors.
#include "native_formation_batch.h"

#include <cstring>
#include <xmmintrin.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>   // structured exceptions only: a stale game pointer must not take the process down

namespace ntw_formation_batch {
namespace {

namespace nf = ntw_formation_layout;
namespace ns = ntw_formation;

constexpr uint32_t kMxcsrDefault = 0x1F80;
constexpr uint32_t kAngleEntries = 65536;
constexpr uint32_t kMaxInlineCells = 10;          // child+0x20 .. +0x47 (count1 lives at +0x48)
constexpr uint32_t kMaxClassCache = 16;

// ---- raw reads of game memory (main thread only; the callers are SEH guarded) ----------------------------------------
template <class T>
inline T Rd(uint32_t address) {
    T v;
    std::memcpy(&v, reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), sizeof(T));
    return v;
}
inline uint32_t R32(uint32_t a) { return Rd<uint32_t>(a); }
inline uint32_t Bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
template <class T>
inline void Wr(uint32_t address, T v) { std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(address)), &v, sizeof(T)); }

inline size_t Align(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }

uint16_t ReadFpuControlWord() {
    uint16_t w = 0;
    __asm { fnstcw w }
    return w;
}

// Bytes that must be present at each address the adapter calls or patches around (pinned image, preferred-base VA).
struct CodeCheck { uint32_t va; uint8_t n; uint8_t bytes[8]; };
const CodeCheck kCodeChecks[] = {
    {va::kAssignWrapper, 7, {0x55, 0x89, 0xE5, 0x56, 0x83, 0xEC, 0x24}},
    {0x5373F0, 4, {0x83, 0xEC, 0x2C, 0x53}},
    {va::kUnitPredicate, 8, {0x6A, 0x01, 0x81, 0xC1, 0xAC, 0x0D, 0x00, 0x00}},
    {va::kResolveWorld, 5, {0x8B, 0x41, 0x10, 0x85, 0xC0}},
    // 0x6B7F50 (ring link flag) is not called: its whole body is pinned below (kRingLinkBody) and re-implemented as reads.
    {va::kVectorAlloc, 6, {0x8B, 0x44, 0x24, 0x04, 0x33, 0xC9}},
    {va::kAnchoredThunk, 8, {0x8B, 0x01, 0xFF, 0x90, 0xA8, 0x00, 0x00, 0x00}},
    {va::kReturnThis, 3, {0x8B, 0xC1, 0xC3}},
    {va::kReturnZero, 3, {0x33, 0xC0, 0xC3}},
    {0x555CA0, 4, {0x83, 0xEC, 0x14, 0x53}},
};

// Constants read from the image: .rdata VA, expected bit pattern (ntw_formation::Constants defaults).
struct ConstCheck { uint32_t va; uint32_t bits; };
const ConstCheck kConstChecks[] = {
    {0x1318038, 0x3F000000u},   // 0.5f
    {0x1318048, 0x3F800000u},   // 1.0f
    {0x131A7A4, 0x00000000u},   // 0.0f
    {0x1325DB4, 0x7F7FFFFFu},   // FLT_MAX
    {0x1325D48, 0x41800000u},   // 16.0f
};

// 0x6B7F50 body, bytes 0x6B7F50 .. 0x6B7F87 (no absolute operands, so it is identical at any image delta).  RingLink() below is
// a source-checked re-implementation of exactly this code; Init() refuses to run unless the image holds it byte for byte.
//   edi = ecx (node); for (esi = 0; esi < [edi+0x44]; ++esi) { entry = [edi+0x48] + esi*8; ecx = [entry] + 0x1C;
//   call [[ecx]]; if (al == 1) return entry; }  return 0
constexpr uint8_t kRingLinkBody[56] = {
    0x53, 0x56, 0x57, 0x8B, 0xF9, 0x33, 0xF6, 0x39, 0x77, 0x44, 0x76, 0x20, 0x0F, 0x1F, 0x40, 0x00, 0x8B, 0x47, 0x48, 0x8B,
    0x0C, 0xF0, 0x8D, 0x1C, 0xF0, 0x83, 0xC1, 0x1C, 0x8B, 0x01, 0x8B, 0x00, 0xFF, 0xD0, 0x3C, 0x01, 0x74, 0x0C, 0x46, 0x3B,
    0x77, 0x44, 0x72, 0xE4, 0x5F, 0x5E, 0x33, 0xC0, 0x5B, 0xC3, 0x5F, 0x5E, 0x8B, 0xC3, 0x5B, 0xC3};

constexpr uint32_t kMaxLinkEntries = 4096;        // link entries scanned per ring node; more declines (kSurfaceLimit)

// ---- pure leaf getters ------------------------------------------------------------------------------------------------------
// Prepare must never execute a game callback: an unknown virtual may write the world even if Consume later rejects the job.
// The two callbacks the original generator reaches per surface cell / ring node (cell vtable[+0x10], link object vtable[0]) are
// therefore never called.  The callee's machine code is read and accepted only when it is exactly one of the fixed leaf forms
// below (thiscall, ecx = receiver, no stack arguments, a bare RET right after the single instruction, nothing is written, no
// call, no other register or memory access); its value is then computed from the same memory reads the code performs.
//   33 C0 C3                      xor eax,eax ; ret         -> 0            (0x461180: surface class 0x133ADD0 vtable[+0x10])
//   8B C1 C3                      mov eax,ecx ; ret         -> this         (0x4470B0)
//   8B 41 d8 C3 | 8B 81 d32 C3    mov eax,[ecx+d] ; ret     -> dword at this+d
//   8D 41 d8 C3 | 8D 81 d32 C3    lea eax,[ecx+d] ; ret     -> this+d
//   8A 41 d8 C3 | 8A 81 d32 C3    mov al,[ecx+d] ; ret      -> byte at this+d in AL (0x54E920, d = 4: link object vtable
//                                                              0x132B5D8 slot 0); EAX[31:8] keeps the caller's value, so this
//                                                              form is only accepted where the caller reads AL alone
// Any other target, including a longer body that merely starts like one of these, is unsupported and is NOT executed.  The
// bytes are re-read on every use (3..7 bytes, the same cost as validating a cache entry), so patched code is never trusted.
enum class LeafKind : uint8_t { kZero, kThis, kLoad32, kLea, kLoad8 };
struct Leaf { LeafKind kind; int32_t disp; };

bool DecodeLeaf(uint32_t target, Leaf* out) {
    const uint8_t b0 = Rd<uint8_t>(target), b1 = Rd<uint8_t>(target + 1);
    out->disp = 0;
    if ((b0 == 0x33 && b1 == 0xC0) || (b0 == 0x8B && b1 == 0xC1)) {
        out->kind = b0 == 0x33 ? LeafKind::kZero : LeafKind::kThis;
        return Rd<uint8_t>(target + 2) == 0xC3;
    }
    if (b0 == 0x8B) out->kind = LeafKind::kLoad32;
    else if (b0 == 0x8D) out->kind = LeafKind::kLea;
    else if (b0 == 0x8A) out->kind = LeafKind::kLoad8;
    else return false;
    uint32_t retAt;
    if (b1 == 0x41) { out->disp = Rd<int8_t>(target + 2); retAt = target + 3; }
    else if (b1 == 0x81) { out->disp = Rd<int32_t>(target + 2); retAt = target + 6; }
    else return false;
    return Rd<uint8_t>(retAt) == 0xC3;
}

// EAX after the leaf ran with ECX = ecx.  needFullEax: the caller consumes all 32 bits (Load8 leaves EAX[31:8] undefined).
bool EvalLeaf(const Leaf& l, uint32_t ecx, bool needFullEax, uint32_t* eax) {
    const uint32_t at = ecx + static_cast<uint32_t>(l.disp);
    switch (l.kind) {
        case LeafKind::kZero:   *eax = 0; return true;
        case LeafKind::kThis:   *eax = ecx; return true;
        case LeafKind::kLoad32: *eax = R32(at); return true;
        case LeafKind::kLea:    *eax = at; return true;
        case LeafKind::kLoad8:  if (needFullEax) return false; *eax = Rd<uint8_t>(at); return true;
    }
    return false;
}

// 0x6B7F50(node) != 0 without running it.  The link object's virtual 0 (embedded object at [entry]+0x1C) must be a supported
// leaf; it is only looked at for entries the original would reach (the scan stops at the first AL == 1).  Unsupported -> the
// caller declines the whole unit before anything was executed.
Reason RingLink(uint32_t node, uint8_t* hasLink) {
    *hasLink = 0;
    const uint32_t count = R32(node + 0x44);
    if (count == 0) return kOk;
    if (count > kMaxLinkEntries) return kSurfaceLimit;
    const uint32_t data = R32(node + 0x48);
    if (!data) return kBadContainer;
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t object = R32(data + 8u * i) + 0x1C;
        const uint32_t vtable = R32(object);
        const uint32_t fn = vtable ? R32(vtable) : 0;
        if (!fn) return kBadContainer;
        Leaf leaf;
        uint32_t eax;
        if (!DecodeLeaf(fn, &leaf) || !EvalLeaf(leaf, object, false, &eax)) return kUnsupportedLinkGetter;
        if ((eax & 0xFFu) == 1u) { *hasLink = 1; break; }
    }
    return kOk;
}

}  // namespace

const char* ReasonName(Reason r) {
    static const char* const names[kReasonCount] = {
        "ok", "not-initialised", "bad-storage", "image-mismatch", "angle-table-not-ready", "no-epoch",
        "table-full", "arena-full", "fault", "bad-command", "not-infantry-formation", "duplicate-formation", "not-dirty",
        "cooldown", "no-men", "too-many-men", "bad-formation", "unsupported-generator", "bad-container",
        "unsupported-child", "surface-limit", "unknown-man-class", "null-man",
        "nothing-prepared", "generate-failed", "assign-failed",
        "not-prepared", "not-executed", "call-arguments", "men-count", "men-membership", "men-state", "unit-predicate",
        "mod-eligibility", "layout-changed", "fpu-control-word", "mxcsr", "slot-count", "slot-geometry", "alloc-failed",
        "unsupported-link-getter", "unsupported-cell-getter",
    };
    return r < kReasonCount ? names[r] : "?";
}

// ---- storage -------------------------------------------------------------------------------------------------------
// [job table][order table][angle table][arena]; every part 64-byte aligned.
static size_t FixedBytes(const Config& cfg) {
    return Align(sizeof(UnitJob) * cfg.maxUnits, 64) + Align(sizeof(uint32_t) * cfg.maxUnits, 64) +
           Align(sizeof(float) * 2u * kAngleEntries, 64);
}

size_t Batch::StorageBytes(const Config& cfg, size_t arenaBytes) { return FixedBytes(cfg) + Align(arenaBytes, 64); }

Reason Batch::Init(void* storage, size_t storageBytes, const Config& cfg) {
    initialised_ = false;
    epochOpen_ = false;
    jobCount_ = 0;
    classCount_ = 0;
    stats_ = Stats();
    if (!storage || (reinterpret_cast<uintptr_t>(storage) & 63u) != 0 || cfg.maxUnits == 0 || cfg.maxMen == 0 ||
        cfg.maxPieces == 0 || cfg.maxNodes == 0)
        return kBadStorage;
    const size_t fixed = FixedBytes(cfg);
    if (storageBytes <= fixed + 4096) return kBadStorage;
    cfg_ = cfg;

    // Pinned image identity at every address this module calls, constants and the angle table.  A mismatch (wrong delta, wrong
    // image, patched code) refuses to run; nothing is written anywhere.
    Reason bad = kOk;
    __try {
        for (const CodeCheck& c : kCodeChecks) {
            if (c.n == 0) continue;
            if (std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(V(c.va))), c.bytes, c.n) != 0) bad = kImageMismatch;
        }
        // 0x555CEB must be `call 0x18F0A00` (E8 rel32): this is the hook site Consume() replaces.
        const uint32_t site = V(va::kAssignCallSite);
        if (Rd<uint8_t>(site) != 0xE8 || site + 5u + R32(site + 1) != V(va::kAssignWrapper)) bad = kImageMismatch;
        for (const ConstCheck& k : kConstChecks)
            if (R32(V(k.va)) != k.bits) bad = kImageMismatch;
        // 0x6B7F50 is not executed any more; RingLink() re-implements this exact body (kRingLinkBody)
        if (std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(V(va::kRingLink))), kRingLinkBody, sizeof kRingLinkBody) != 0)
            bad = kImageMismatch;
        if (bad == kOk) {
            // runtime-initialised table: pair 0 must be {sin 0, cos 1}
            const uint32_t t = V(va::kAngleTable);
            if (R32(t) != 0u || R32(t + 4) != 0x3F800000u) bad = kAngleTableNotReady;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bad = kImageMismatch;
    }
    if (bad != kOk) return bad;

    base_ = static_cast<uint8_t*>(storage);
    jobs_ = reinterpret_cast<UnitJob*>(base_);
    order_ = reinterpret_cast<uint32_t*>(base_ + Align(sizeof(UnitJob) * cfg.maxUnits, 64));
    angleTable_ = reinterpret_cast<float*>(reinterpret_cast<uint8_t*>(order_) + Align(sizeof(uint32_t) * cfg.maxUnits, 64));
    arena_ = reinterpret_cast<uint8_t*>(angleTable_) + Align(sizeof(float) * 2u * kAngleEntries, 64);
    arenaBytes_ = (storageBytes - fixed) & ~static_cast<size_t>(63);
    cursor_ = 0;

    // The table is written once by the game during start-up; this copy is immutable and shared by every worker.
    std::memcpy(angleTable_, reinterpret_cast<const void*>(static_cast<uintptr_t>(V(va::kAngleTable))),
                sizeof(float) * 2u * kAngleEntries);

    nat_.unitPredicate = reinterpret_cast<uint32_t(__thiscall*)(void*)>(static_cast<uintptr_t>(V(va::kUnitPredicate)));
    nat_.resolveWorld = reinterpret_cast<void*(__thiscall*)(void*, float*)>(static_cast<uintptr_t>(V(va::kResolveWorld)));
    nat_.vectorAlloc = reinterpret_cast<void*(__cdecl*)(int, int)>(static_cast<uintptr_t>(V(va::kVectorAlloc)));
    nat_.heapFree = reinterpret_cast<void(__cdecl*)(void*)>(static_cast<uintptr_t>(V(va::kHeapFree)));
    constants_ = ns::Constants();
    initialised_ = true;
    return kOk;
}

void Batch::Begin() {
    if (!initialised_) return;
    jobCount_ = 0;
    cursor_ = 0;
    epochOpen_ = true;
    ++stats_.epochs;
}

void Batch::End() {
    if (!initialised_) return;
    for (uint32_t i = 0; i < jobCount_; ++i)
        if (jobs_[i].state == kPrepared || jobs_[i].state == kExecuted) ++stats_.unusedJobs;
    epochOpen_ = false;
}

Reason Batch::Count(Reason r) {
    ++stats_.reasons[r];
    return r;
}

uint8_t* Batch::Take(size_t bytes, size_t align) {
    const size_t at = Align(cursor_, align);
    if (at > arenaBytes_ || bytes > arenaBytes_ - at) return nullptr;
    cursor_ = at + bytes;
    return arena_ + at;
}

// ---- man classes: 0x5373F0 asks vtable[+0xF4] (0x64FA80: vtable[+0xA8]() != 0) for every man ----------------------------
// Both known [+0xA8] implementations are state-free (mov eax,ecx ; ret  /  xor eax,eax ; ret), so the answer is a pure function
// of the vtable pointer.  Any other [+0xA8] / [+0xF4] makes the unit ineligible instead of guessing.
bool Batch::ResolveClass(uint32_t vtable, uint8_t* anchored, uint8_t* officer) {
    for (uint32_t i = 0; i < classCount_; ++i)
        if (classes_[i].vtable == vtable) { *anchored = classes_[i].anchored; *officer = classes_[i].officer; return true; }
    if (vtable == 0 || R32(vtable + 0xF4) != V(va::kAnchoredThunk)) return false;
    const uint32_t f = R32(vtable + 0xA8);
    uint8_t a;
    if (f == V(va::kReturnThis)) a = 1;
    else if (f == V(va::kReturnZero)) a = 0;
    else return false;
    const uint8_t o = vtable == V(va::kOfficerVtable) ? 1 : 0;
    if (classCount_ < kMaxClassCache) classes_[classCount_++] = ManClass{vtable, a, o};
    *anchored = a;
    *officer = o;
    return true;
}

// Frame object F: translation +0x80, local->world 3x3 at +0x9C, world->local 3x3 at +0xC0 (see native_formation_layout.h).
int32_t Batch::AddFrame(UnitJob& j, uint32_t* framePtrs, uint32_t* frameCount, uint32_t capacity, uint32_t ptr) {
    if (ptr == 0) return -1;
    for (uint32_t i = 0; i < *frameCount; ++i)
        if (framePtrs[i] == ptr) return static_cast<int32_t>(i);
    if (*frameCount >= capacity) return -2;
    const uint32_t i = (*frameCount)++;
    framePtrs[i] = ptr;
    nf::Frame& f = j.frames[i];
    for (uint32_t k = 0; k < 3; ++k) f.t[k] = Rd<float>(ptr + 0x80 + 4 * k);
    for (uint32_t k = 0; k < 9; ++k) f.fwd[k] = Rd<float>(ptr + 0x9C + 4 * k);
    for (uint32_t k = 0; k < 9; ++k) f.inv[k] = Rd<float>(ptr + 0xC0 + 4 * k);
    return static_cast<int32_t>(i);
}

// ---- Prepare ---------------------------------------------------------------------------------------------------------
Reason Batch::Prepare(uint32_t command, uint32_t* unitIndex) {
    if (unitIndex) *unitIndex = 0xFFFFFFFFu;
    if (!initialised_) return Count(kNotInitialised);
    if (!epochOpen_) return Count(kNoEpoch);
    const size_t mark = cursor_;
    Reason r;
    __try {
        r = PrepareImpl(command, unitIndex);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = kFault;
    }
    if (r != kOk) cursor_ = mark;
    else ++stats_.prepared;
    return Count(r);
}

Reason Batch::PrepareImpl(uint32_t cmd, uint32_t* outIndex) {
    if (jobCount_ >= cfg_.maxUnits) return kTableFull;
    if (cmd == 0) return kBadCommand;
    const uint32_t formation = R32(cmd + 4);                       // 0x4B4A50
    if (formation == 0) return kBadCommand;
    if (R32(formation) != V(va::kFormationVtable)) return kNotInfantryFormation;
    for (uint32_t i = 0; i < jobCount_; ++i)
        if (jobs_[i].formation == formation) return kDuplicateFormation;
    if (Rd<uint8_t>(formation + 0x278C) == 0) return kNotDirty;                 // 0x58120F
    if (R32(formation + 0x2788) > cfg_.maxCooldown) return kCooldown;          // 0x581218
    const uint32_t men = R32(formation + 0x18);
    if (men == 0) return kNoMen;
    if (men > cfg_.maxMen) return kTooManyMen;
    const uint32_t menArray = R32(formation + 0x1C);
    const uint32_t layout = R32(formation + 0x628);
    const uint32_t unit = R32(formation + 0x510);
    const uint32_t container = R32(cmd + 0x18);
    if (!menArray || !layout || !unit) return kBadFormation;
    const uint32_t layoutVtable = R32(layout);
    if (!layoutVtable) return kBadFormation;
    const uint32_t generator = R32(layoutVtable + 0x24);
    if (generator != V(va::kGeneratorStock) && generator != V(va::kGeneratorMod)) return kUnsupportedGenerator;
    if (!container) return kBadContainer;

    // container: +0x10 child count, +0x14 child pointer array, +0x18 origin position object, +0x28 its frame
    const uint32_t pieceCount = R32(container + 0x10);
    const uint32_t pieceArray = R32(container + 0x14);
    if (pieceCount == 0 || pieceCount > cfg_.maxPieces || !pieceArray) return kBadContainer;
    uint32_t totalCells = 0;
    for (uint32_t i = 0; i < pieceCount; ++i) {
        const uint32_t child = R32(pieceArray + 4 * i);
        if (!child) return kBadContainer;
        const uint32_t vt = R32(child);
        if (vt != V(va::kChildClassA) && vt != V(va::kChildClassB)) return kUnsupportedChild;
        const uint32_t c1 = R32(child + 0x48), c2 = R32(child + 0x54);   // inline / overflow surface cell counts
        if (c1 > kMaxInlineCells || c2 > cfg_.maxNodes) return kSurfaceLimit;
        if (c2 != 0 && R32(child + 0x58) == 0) return kBadContainer;
        totalCells += c1 + c2;
        if (totalCells > cfg_.maxNodes) return kSurfaceLimit;
    }

    // ---- private block ----
    UnitJob& j = jobs_[jobCount_];
    std::memset(&j, 0, sizeof j);
    j.manPtr = reinterpret_cast<uint32_t*>(Take(sizeof(uint32_t) * men, 16));
    uint8_t* viewMemory = Take(ns::ArenaBytes(men, men), 16);
    j.slots = reinterpret_cast<nf::Slot*>(Take(sizeof(nf::Slot) * men, 16));
    j.pieces = reinterpret_cast<nf::Piece*>(Take(sizeof(nf::Piece) * pieceCount, 16));
    j.cells = reinterpret_cast<nf::SurfaceCell*>(Take(sizeof(nf::SurfaceCell) * totalCells, 16));
    const uint32_t frameCapacity = 1u + totalCells;
    j.frames = reinterpret_cast<nf::Frame*>(Take(sizeof(nf::Frame) * frameCapacity, 16));
    uint32_t* framePtrs = reinterpret_cast<uint32_t*>(Take(sizeof(uint32_t) * frameCapacity, 16));
    const size_t nodeBytes = sizeof(nf::SurfaceNode) * static_cast<size_t>(cfg_.maxNodes);
    j.nodes = reinterpret_cast<nf::SurfaceNode*>(Take(totalCells ? nodeBytes : 0, 16));   // last: trimmed below
    if (!j.manPtr || !viewMemory || !j.slots || !j.pieces || !j.cells || !j.frames || !framePtrs || !j.nodes) return kArenaFull;
    const size_t nodeEnd = cursor_;
    ns::BindArena(viewMemory, men, men, &j.views);

    uint32_t cellCount = 0, nodeCount = 0, frameCount = 0;
    nf::Input& in = j.in;
    in.origin.x = Rd<float>(container + 0x18);
    in.origin.y = Rd<float>(container + 0x1C);
    in.origin.z = Rd<float>(container + 0x20);
    in.origin.frame = AddFrame(j, framePtrs, &frameCount, frameCapacity, R32(container + 0x28));
    if (in.origin.frame < -1) return kSurfaceLimit;

    for (uint32_t i = 0; i < pieceCount; ++i) {
        const uint32_t child = R32(pieceArray + 4 * i);
        nf::Piece& p = j.pieces[i];
        p = nf::Piece();
        p.isArc = R32(child) == V(va::kChildClassB) ? 1 : 0;
        p.mode = Rd<int32_t>(child + 0x04);
        p.angle = Rd<uint16_t>(child + 0x08);
        p.p0[0] = Rd<float>(child + 0x0C); p.p0[1] = Rd<float>(child + 0x10);
        p.p1[0] = Rd<float>(child + 0x14); p.p1[1] = Rd<float>(child + 0x18);
        p.step[0] = Rd<float>(child + 0x60); p.step[1] = Rd<float>(child + 0x64);
        p.width = Rd<float>(child + 0x70);
        p.arcStart[0] = Rd<float>(child + 0x7C); p.arcStart[1] = Rd<float>(child + 0x80);
        p.dir[0] = Rd<float>(child + 0x8C); p.dir[1] = Rd<float>(child + 0x90);
        if (p.isArc) {   // class B only: the class-A object ends at +0x98
            p.center[0] = Rd<float>(child + 0x98); p.center[1] = Rd<float>(child + 0x9C);
            p.arcWidth = Rd<float>(child + 0xA0);
        }
        // surface set O = {inline list child+0x20.., overflow list [child+0x58]} flattened in 0x80DE00 iteration order
        const uint32_t c1 = R32(child + 0x48), c2 = R32(child + 0x54);
        const uint32_t overflow = c2 ? R32(child + 0x58) : 0;
        p.cellBegin = cellCount;
        p.cellCount = c1 + c2;
        for (uint32_t k = 0; k < c1 + c2; ++k) {
            const uint32_t E = k < c1 ? R32(child + 0x20 + 4 * k) : R32(overflow + 4 * (k - c1));
            if (!E) return kBadContainer;
            nf::SurfaceCell& c = j.cells[cellCount++];
            c.nodeBegin = nodeCount;
            const uint32_t head = R32(E + 8);                  // ring head node; node+8 = next, +0xC/+0x10 = point
            if (!head) return kBadContainer;
            uint32_t node = head;
            do {
                if (nodeCount >= cfg_.maxNodes) return kSurfaceLimit;
                nf::SurfaceNode& n = j.nodes[nodeCount++];
                n.x = Rd<float>(node + 0x0C);
                n.z = Rd<float>(node + 0x10);
                const Reason lr = RingLink(node, &n.hasLink);                  // 0x6B7F50, read-only (see RingLink)
                if (lr != kOk) return lr;
                node = R32(node + 8);
                if (!node) return kBadContainer;
            } while (node != head);
            c.nodeCount = nodeCount - c.nodeBegin;
            for (uint32_t q = 0; q < 4; ++q) c.plane[q] = Rd<float>(E + 0x30 + 4 * q);
            // frame = *(E->vfn+0x10() + 0x80), -1 when either is null; vfn+0x10 is evaluated, never executed, and must be a
            // supported pure leaf (typically 0x461180 -> 0 or 0x4470B0 -> E)
            const uint32_t evt = R32(E);
            if (!evt) return kBadContainer;
            const uint32_t vfn = R32(evt + 0x10);
            if (!vfn) return kBadContainer;
            Leaf leaf;
            uint32_t G;
            if (!DecodeLeaf(vfn, &leaf) || !EvalLeaf(leaf, E, true, &G)) return kUnsupportedCellGetter;
            c.frame = G ? AddFrame(j, framePtrs, &frameCount, frameCapacity, R32(G + 0x80)) : -1;
            if (c.frame < -1) return kSurfaceLimit;
        }
    }
    cursor_ = nodeEnd - (totalCells ? (nodeBytes - sizeof(nf::SurfaceNode) * static_cast<size_t>(nodeCount)) : 0);

    // ---- layout scalars (0x62FD60 reads layout+8,+0xC,+0x10,+0x14 and the command's f) ----
    in.men = men;
    in.f = Rd<float>(cmd + 0x1C);
    in.layout8 = Rd<float>(layout + 0x08);
    in.layoutC = Rd<float>(layout + 0x0C);
    in.layout10 = Rd<float>(layout + 0x10);
    in.layout14 = Rd<float>(layout + 0x14);
    in.pieces = j.pieces; in.pieceCount = pieceCount;
    in.cells = j.cells; in.cellCount = cellCount;
    in.nodes = j.nodes; in.nodeCount = nodeCount;
    in.frames = j.frames; in.frameCount = frameCount;
    in.terrain = nullptr;                                      // no world pointer for workers: heights stay unknown (yValid 0)
    in.modActive = generator == V(va::kGeneratorMod) ? 1 : 0;
    in.fpuControlWord = ReadFpuControlWord();
    for (uint32_t k = 0; k < 4; ++k) j.layoutBits[k] = R32(layout + 8 + 4 * k);

    // ---- men ----
    const ns::ArenaViews& v = j.views;
    for (uint32_t i = 0; i < men; ++i) {
        const uint32_t m = R32(menArray + 4 * i);
        if (!m) return kNullMan;
        uint8_t anchored = 0, officer = 0;
        if (!ResolveClass(R32(m), &anchored, &officer)) return kUnknownManClass;
        j.manPtr[i] = m;
        v.manX[i] = Rd<float>(m + 0x48);
        v.manZ[i] = Rd<float>(m + 0x50);
        v.manAngle[i] = Rd<uint16_t>(m + 0x64);
        v.manAnchored[i] = anchored;
        const uint32_t k = officer ? R32(m + 0x66C) - constants_.markerBase : 0xFFFFFFFFu;
        v.manMarker[i] = k <= 2u ? static_cast<uint8_t>(k) : 0xFF;
        v.manSkipDistance[i] = Rd<uint8_t>(m + 0x1A8) != 0 ? 1 : 0;
    }

    // ---- unit ----
    j.unitFlag = nat_.unitPredicate(reinterpret_cast<void*>(static_cast<uintptr_t>(unit))) != 0 ? 1 : 0;   // 0x54C8B0, main thread
    const uint32_t side = R32(unit + 0x2C);
    j.modEligible = (generator == V(va::kGeneratorMod) && side != 0 && R32(side + 0x1C) == 2) ? 1 : 0;

    j.formation = formation; j.command = cmd; j.container = container; j.layout = layout; j.unit = unit;
    j.menArray = menArray; j.generator = generator;
    j.men = men; j.fBits = Bits(in.f);
    j.layoutIndex = -1;                                        // 0x581200 -> 0x57AFC0 passes flag 1, layoutIndex -1
    j.flag = 1;
    j.fpuControlWord = in.fpuControlWord;
    j.state = kPrepared;
    if (outIndex) *outIndex = jobCount_;
    ++jobCount_;
    return kOk;
}

// ---- Execute / worker body -------------------------------------------------------------------------------------------
void Batch::RunJob(UnitJob& j) const {
    const unsigned savedCsr = _mm_getcsr();
    _mm_setcsr(kMxcsrDefault);
    nf::Result res;
    res.count = 0; res.mark = 0;
    j.layoutStatus = nf::Generate(j.in, j.slots, j.men, &res);
    j.layoutResult = res;
    j.slotCount = res.count;
    j.assignStatus = -1;
    j.reason = kOk;
    if (j.layoutStatus != nf::kOk) {
        j.reason = kGenerateFailed;
        j.state = kFailed;
    } else {
        nf::ToSlotArrays(j.slots, res.count, j.views.slotX, j.views.slotZ, j.views.slotAngle);
        ns::SlotInput si;
        si.men = j.men;
        si.slots = res.count;
        si.manX = j.views.manX; si.manZ = j.views.manZ; si.manAngle = j.views.manAngle;
        si.manAnchored = j.views.manAnchored; si.manMarker = j.views.manMarker; si.manSkipDistance = j.views.manSkipDistance;
        si.slotX = j.views.slotX; si.slotZ = j.views.slotZ; si.slotAngle = j.views.slotAngle;
        si.angleTable = angleTable_;
        si.unitFlag = j.unitFlag;
        si.flagParam = j.flag;
        si.layoutIndex = j.layoutIndex;
        si.modEligible = j.modEligible;
        j.assignStatus = ns::AssignUnit(si, constants_, j.views.entries, j.views.scratch, &j.assign);
        if (j.assignStatus == ns::kOk) {
            j.state = kExecuted;
        } else {
            j.reason = kAssignFailed;
            j.state = kFailed;
        }
    }
    _mm_setcsr(savedCsr);
}

void __fastcall Batch::Body(void* ctx, uint32_t chunk) {
    Batch* b = static_cast<Batch*>(ctx);
    b->RunJob(b->jobs_[b->order_[chunk]]);
}

Reason Batch::Execute(const Dispatcher& d, uint32_t* jobsRun) {
    if (jobsRun) *jobsRun = 0;
    if (!initialised_ || !d.dispatch) return Count(kNotInitialised);
    if (!epochOpen_) return Count(kNoEpoch);
    uint32_t n = 0;
    for (uint32_t i = 0; i < jobCount_; ++i)
        if (jobs_[i].state == kPrepared) order_[n++] = i;
    if (n == 0) return kNothingPrepared;
    // Longest-processing-time first: the solver is O(men^2) and chunks are claimed in index order by the team.  Insertion sort,
    // stable, no allocation (n is bounded by Config::maxUnits).
    for (uint32_t a = 1; a < n; ++a) {
        const uint32_t key = order_[a];
        const uint32_t keyMen = jobs_[key].men;
        uint32_t b = a;
        while (b > 0 && jobs_[order_[b - 1]].men < keyMen) { order_[b] = order_[b - 1]; --b; }
        order_[b] = key;
    }
    d.dispatch(d.user, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&Batch::Body)), n, this);   // returns after the barrier
    uint32_t ok = 0;
    for (uint32_t k = 0; k < n; ++k) {
        const UnitJob& j = jobs_[order_[k]];
        if (j.state == kExecuted) {
            ++ok;
            for (uint32_t s = 0; s < j.slotCount; ++s) stats_.slotsWithoutHeight += j.slots[s].yValid ? 0u : 1u;
        } else if (j.state == kFailed) {
            ++stats_.executeFailed;
        }
    }
    stats_.executed += ok;
    if (jobsRun) *jobsRun = n;
    return kOk;
}

// ---- Consume -------------------------------------------------------------------------------------------------------------
ConsumeResult Batch::Consume(const AssignCall& call) {
    ConsumeResult r;
    r.outcome = Outcome::kFallback;
    if (!initialised_ || !epochOpen_) {
        r.reason = Count(!initialised_ ? kNotInitialised : kNoEpoch);
        ++stats_.fallbacks;
        return r;
    }
    Reason why;
    __try {
        why = ConsumeImpl(call, &r);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        why = kFault;
    }
    r.reason = why;
    if (why == kOk) {
        r.outcome = Outcome::kCommitted;
        ++stats_.committed;
        ++stats_.reasons[kOk];
        return r;
    }
    if (r.unit < jobCount_) {
        jobs_[r.unit].state = kRejected;       // single use: the original call (and any second consumer) runs natively
        jobs_[r.unit].reason = why;
    }
    ++stats_.fallbacks;
    Count(why);
    return r;
}

Reason Batch::ConsumeImpl(const AssignCall& c, ConsumeResult* out) {
    uint32_t idx = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < jobCount_; ++i)
        if (jobs_[i].formation == c.formation) { idx = i; break; }
    if (idx == 0xFFFFFFFFu) return kNotPrepared;
    out->unit = idx;
    UnitJob& j = jobs_[idx];
    if (j.state == kPrepared) return kNotExecuted;
    if (j.state == kFailed) return static_cast<Reason>(j.reason);
    if (j.state != kExecuted) return kNotPrepared;           // already consumed / rejected

    // the call arguments (0x18F0A00: slotVec, flag byte, assignVec, layoutIndex)
    if ((c.flag & 0xFFu) != j.flag || c.layoutIndex != j.layoutIndex) return kCallArguments;
    if (c.assignVec != c.formation + 0x518) return kCallArguments;

    const uint32_t f = j.formation;
    // layout / unit identity and the generator that produced the slots (0x18F0A3F pre-hook reads exactly these)
    if (R32(f + 0x510) != j.unit || R32(f + 0x628) != j.layout) return kLayoutChanged;
    const uint32_t layoutVtable = R32(j.layout);
    if (!layoutVtable || R32(layoutVtable + 0x24) != j.generator) return kLayoutChanged;
    const uint32_t side = R32(j.unit + 0x2C);
    const uint8_t modEligible = (j.generator == V(va::kGeneratorMod) && side != 0 && R32(side + 0x1C) == 2) ? 1 : 0;
    if (modEligible != j.modEligible) return kModEligibility;
    const uint8_t unitFlag = nat_.unitPredicate(reinterpret_cast<void*>(static_cast<uintptr_t>(j.unit))) != 0 ? 1 : 0;
    if (unitFlag != j.unitFlag) return kUnitPredicate;
    if (ReadFpuControlWord() != j.fpuControlWord) return kFpuControlWord;
    if ((_mm_getcsr() & ~0x3Fu) != kMxcsrDefault) return kMxcsr;   // bits 0..5 are sticky exception flags, not control state

    // men: membership, order and every field the assignment reads (0x5373F0 / 0x502770 / 0x5281D0 / 0x18F0200 / 0x557C80)
    if (R32(f + 0x18) != j.men) return kMenCount;
    const uint32_t menArray = R32(f + 0x1C);
    if (!menArray) return kMenMembership;
    const ns::ArenaViews& v = j.views;
    for (uint32_t i = 0; i < j.men; ++i) {
        const uint32_t m = R32(menArray + 4 * i);
        if (m != j.manPtr[i]) return kMenMembership;
        uint8_t anchored = 0, officer = 0;
        if (!ResolveClass(R32(m), &anchored, &officer)) return kMenState;
        if (anchored != v.manAnchored[i]) return kMenState;
        if (Bits(Rd<float>(m + 0x48)) != Bits(v.manX[i]) || Bits(Rd<float>(m + 0x50)) != Bits(v.manZ[i])) return kMenState;
        if (Rd<uint16_t>(m + 0x64) != v.manAngle[i]) return kMenState;
        if ((Rd<uint8_t>(m + 0x1A8) != 0 ? 1 : 0) != v.manSkipDistance[i]) return kMenState;
        const uint32_t k = officer ? R32(m + 0x66C) - constants_.markerBase : 0xFFFFFFFFu;
        if ((k <= 2u ? static_cast<uint8_t>(k) : 0xFF) != v.manMarker[i]) return kMenState;
    }

    // generated slots: the REAL records the native generator just produced (their Y is terrain-correct and is never replaced
    // by anything from this module); only world x / z / angle feed the assignment, so those are what is compared.
    const uint32_t slotCount = R32(c.slotVec + 8);
    if (slotCount != j.slotCount) return kSlotCount;
    const uint32_t slotData = R32(c.slotVec + 0xC);
    if (slotCount != 0 && slotData == 0) return kSlotCount;
    for (uint32_t k = 0; k < slotCount; ++k) {
        const uint32_t rec = slotData + 36u * k;
        uint32_t wx, wz;
        if (R32(rec + 0x14) == 0) {               // 0x80E9D0 with no parent frame copies {x,y,z} unchanged
            wx = R32(rec + 4);
            wz = R32(rec + 0xC);
        } else {                                  // parent-relative record: the game's own transform, main thread
            float w[3];
            nat_.resolveWorld(reinterpret_cast<void*>(static_cast<uintptr_t>(rec + 4)), w);
            wx = Bits(w[0]);
            wz = Bits(w[2]);
        }
        if (wx != Bits(v.slotX[k]) || wz != Bits(v.slotZ[k]) || Rd<uint16_t>(rec + 0x18) != v.slotAngle[k]) return kSlotGeometry;
    }

    const Reason cr = Commit(j, c);
    if (cr == kOk) j.state = kConsumed;
    return cr;
}

// Writes the entry vector as 0x5373F0 leaves it: count = entries, entry k = {man*, slotData + 0x24 * slot or 0, cost}.  Native
// growth (cap 0 -> 1, then doubling, copy, free old data with 0xFF7EF0) ends in the same state as one allocation of
// the final capacity, which is what is done here, through the game's own allocator 0x445A50.
Reason Batch::Commit(UnitJob& j, const AssignCall& call) {
    const uint32_t vec = call.assignVec;
    const uint32_t n = j.assign.entryCount;
    const uint32_t cap = R32(vec + 4);
    const uint32_t oldData = R32(vec + 0xC);
    const uint32_t slotData = R32(call.slotVec + 0xC);
    uint32_t newCap = cap ? cap : 1u;
    while (newCap < n) newCap *= 2u;
    const bool grow = cap == 0 || oldData == 0 || n > cap;
    uint32_t data = oldData;
    if (grow) {
        void* p = nat_.vectorAlloc(static_cast<int>(newCap), 0);
        if (!p) return kAllocFailed;
        data = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
    }
    const ns::Entry* e = j.views.entries;
    for (uint32_t k = 0; k < n; ++k) {
        const uint32_t at = data + 12u * k;
        Wr<uint32_t>(at, e[k].man == ns::kNone ? 0u : j.manPtr[e[k].man]);
        Wr<uint32_t>(at + 4, e[k].slot == ns::kNone ? 0u : slotData + 36u * e[k].slot);
        Wr<uint32_t>(at + 8, Bits(e[k].cost));
    }
    if (grow) {
        Wr<uint32_t>(vec + 0xC, data);        // data before cap: a cap larger than the block is never visible
        Wr<uint32_t>(vec + 4, newCap);
    }
    Wr<uint32_t>(vec + 8, n);
    if (grow && cap != 0 && oldData != 0) nat_.heapFree(reinterpret_cast<void*>(static_cast<uintptr_t>(oldData)));
    return kOk;
}

}  // namespace ntw_formation_batch
