// Native source-pinned private code builder for the original Napoleon.exe (x86, MSVC).
//
// ntw2_build_clones() reads LIVE bytes from the already-loaded, already-relocated image, proves they are the pinned
// build (FNV-1a64 over each source span with PE HIGHLOW words normalized back to preferred base 0x400000), then
// assembles every clone described by the generated metadata (ntw2_clone_specs.inc) into ONE private region:
//
//   1. validate x86 PE32 headers + section table of the live image            (guarded by SEH, inspection only)
//   2. validate and hash every source span                                    (guarded by SEH, inspection only)
//   3. validate every clone's operation list structurally (bounds/overlap/exact coverage)
//   4. compute 16-byte aligned clone offsets with checked arithmetic, VirtualAlloc one RW region (0xCC filled)
//   5. COPY/LITERAL operations, then ABSOLUTE/RELATIVE fixups (all clone bases already known, so CLONE targets may
//      point at any clone including the one being patched)
//   6. VirtualProtect the whole region PAGE_EXECUTE_READ, FlushInstructionCache
//
// Nothing here executes emitted code, so SEH is used only around reads of the image; a fault inside emitted code is
// never intercepted by this module. No Python, no disassembler, no heap allocation, no per-instruction allocation.
//
// Return value / error codes (also the numeric contract for harnesses). Zero means complete construction.
// *detail: low 16 bits = source index (SOURCE_* errors) or clone index (clone errors); high 16 bits = operation
// index + 1 (capped at 0xFFFF) for operation-level errors, otherwise 0. For ALLOC_FAILED/PROTECT_FAILED/FLUSH_FAILED
// detail is GetLastError(). For IMAGE_* errors detail is 0 (or the offending header field value where stated).
//
//    0 OK
//    1 BAD_ARGUMENT        out or bindings is null
//    2 BAD_IMAGE_BASE      image_base zero or not 64 KiB aligned
//    3 BAD_PE              DOS/NT/optional header, section table or address range is not a valid x86 PE32 image,
//                          or reading the headers faulted
//    4 IMAGE_IDENTITY      header ImageBase (detail) is neither the pinned preferred base 0x400000 nor the live base
//                          (the loader rewrites the mapped field to the actual base after an ASLR relocation)
//    5 SOURCE_TABLE        reserved (table shape/count is enforced by static_assert when the generated .inc is compiled)
//    6 SOURCE_RANGE        source span empty, below 0x400000, outside SizeOfImage, or outside every section
//    7 SOURCE_UNREADABLE   source span has uncommitted/no-access/guard pages, or reading it faulted
//    8 SOURCE_RELOCATION   relocation offsets null/unsorted/overlapping/past span end
//    9 SOURCE_HASH         live bytes (normalized) differ from the pinned FNV-1a64
//   10 CLONE_SPEC          clone size zero/oversized, or null operations / zero operation count
//   11 CLONE_LAYOUT        checked layout arithmetic overflow or total beyond 16 MiB
//   12 ALLOC_FAILED        VirtualAlloc failed
//   13 OP_KIND             unknown operation kind
//   14 OP_BOUNDS           zero-size operation or destination/size outside the clone
//   15 OP_SOURCE           COPY source index/offset/size outside its pinned span (or outside the image at copy time)
//   16 OP_OVERLAP          two COPY/LITERAL operations overlap
//   17 OP_COVERAGE         COPY/LITERAL operations do not cover exactly [0,size) of the clone
//   18 OP_LITERAL          LITERAL operation with a null literal pointer
//   19 FIXUP_TARGET        unknown target kind/identifier, or resolved target outside image / outside target clone
//   20 FIXUP_BINDING       fixup references a binding whose supplied address is zero
//   21 FIXUP_SIZE          ABSOLUTE not 4 bytes, or RELATIVE not 1 or 4 bytes
//   22 FIXUP_REL8_RANGE    signed rel8 displacement does not fit
//   23 FIXUP_OVERLAP       two ABSOLUTE/RELATIVE fixups overlap
//   24 COPY_UNREADABLE     source bytes became unreadable (or faulted) between validation and copy
//   25 PROTECT_FAILED      VirtualProtect(PAGE_EXECUTE_READ) failed
//   26 FLUSH_FAILED        FlushInstructionCache failed
//
// On any failure the (still private, unpublished) allocation is released and *out is zeroed. On success
// out->allocation is owned by the caller until process exit: the region is never freed by this module, and
// existing callers may have published code pointers into it.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(_WIN32) || !defined(_M_IX86)
#error "ntw2_clones.cpp builds x86 Windows code for the 32-bit original game process only"
#endif

extern "C" {
#include "ntw2_clones.h"
}
#include "ntw2_clone_specs.inc"

enum ntw2_clone_error : uint32_t {
    NTW2_CLONE_OK = 0,
    NTW2_CLONE_ERR_BAD_ARGUMENT = 1,
    NTW2_CLONE_ERR_BAD_IMAGE_BASE = 2,
    NTW2_CLONE_ERR_BAD_PE = 3,
    NTW2_CLONE_ERR_IMAGE_IDENTITY = 4,
    NTW2_CLONE_ERR_SOURCE_TABLE = 5,
    NTW2_CLONE_ERR_SOURCE_RANGE = 6,
    NTW2_CLONE_ERR_SOURCE_UNREADABLE = 7,
    NTW2_CLONE_ERR_SOURCE_RELOCATION = 8,
    NTW2_CLONE_ERR_SOURCE_HASH = 9,
    NTW2_CLONE_ERR_CLONE_SPEC = 10,
    NTW2_CLONE_ERR_CLONE_LAYOUT = 11,
    NTW2_CLONE_ERR_ALLOC_FAILED = 12,
    NTW2_CLONE_ERR_OP_KIND = 13,
    NTW2_CLONE_ERR_OP_BOUNDS = 14,
    NTW2_CLONE_ERR_OP_SOURCE = 15,
    NTW2_CLONE_ERR_OP_OVERLAP = 16,
    NTW2_CLONE_ERR_OP_COVERAGE = 17,
    NTW2_CLONE_ERR_OP_LITERAL = 18,
    NTW2_CLONE_ERR_FIXUP_TARGET = 19,
    NTW2_CLONE_ERR_FIXUP_BINDING = 20,
    NTW2_CLONE_ERR_FIXUP_SIZE = 21,
    NTW2_CLONE_ERR_FIXUP_REL8_RANGE = 22,
    NTW2_CLONE_ERR_FIXUP_OVERLAP = 23,
    NTW2_CLONE_ERR_COPY_UNREADABLE = 24,
    NTW2_CLONE_ERR_PROTECT_FAILED = 25,
    NTW2_CLONE_ERR_FLUSH_FAILED = 26
};

namespace {

constexpr uint32_t kPreferredBase = 0x400000u;
constexpr uint32_t kBaseAlignment = 0x10000u;
constexpr uint32_t kCloneAlignment = 16u;
constexpr uint32_t kMaxCloneBytes = 1u << 20;
constexpr uint32_t kMaxTotalBytes = 16u << 20;
constexpr uint32_t kMaxSections = 96u;
constexpr uint32_t kMaxNtHeaderOffset = 0x1000u;
constexpr uint8_t kPadding = 0xCC;  // int3 between clones
constexpr uint64_t kFnvOffset = 0xcbf29ce484222325ull;
constexpr uint64_t kFnvPrime = 0x100000001b3ull;

constexpr uint32_t kGridMagic = 0x31435247u; // GRC1; private allocation header, not game text
constexpr uint32_t kGridGateBytes = 48;
struct GridArena { uint32_t magic, image_base, callback, entries[NTW2_CLONE_COUNT]; };
constexpr uint32_t kGridHeaderBytes = (sizeof(GridArena) + 15u) & ~15u;
uint32_t gridCallback;

constexpr uint32_t kSourceCount = static_cast<uint32_t>(sizeof(ntw2_sources) / sizeof(ntw2_sources[0]));
static_assert(kSourceCount != 0, "generated source table is empty");
static_assert(kSourceCount == ntw2_source_count, "ntw2_source_count disagrees with ntw2_sources[]");
static_assert(sizeof(ntw2_specs) / sizeof(ntw2_specs[0]) == NTW2_CLONE_COUNT, "ntw2_specs must have one entry per clone id");
static_assert(sizeof(void*) == 4, "x86 only");

struct SectionExtent {
    uint32_t rva, size;
};
struct ImageInfo {
    uint32_t base;           // live base
    uint32_t delta;          // base - preferred, modulo 2^32
    uint32_t size_of_image;
    uint32_t section_count;
    SectionExtent sections[kMaxSections];
};

uint32_t Detail(uint32_t index, uint32_t op) {
    const uint32_t hi = op + 1u > 0xFFFFu ? 0xFFFFu : op + 1u;
    return (hi << 16) | (index & 0xFFFFu);
}

int GuardFilter(DWORD code) {
    return (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR || code == EXCEPTION_GUARD_PAGE ||
            code == EXCEPTION_DATATYPE_MISALIGNMENT)
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}

// ---- image inspection ------------------------------------------------------------------------------------------

uint32_t ParseImageUnguarded(ImageInfo* info, uint32_t* detail) {
    const uint8_t* const p = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(info->base));
    const IMAGE_DOS_HEADER* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(p);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NTW2_CLONE_ERR_BAD_PE;
    if (dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) || dos->e_lfanew > static_cast<LONG>(kMaxNtHeaderOffset))
        return NTW2_CLONE_ERR_BAD_PE;
    const uint32_t lfanew = static_cast<uint32_t>(dos->e_lfanew);
    const IMAGE_NT_HEADERS32* const nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(p + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NTW2_CLONE_ERR_BAD_PE;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return NTW2_CLONE_ERR_BAD_PE;
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) return NTW2_CLONE_ERR_BAD_PE;
    if (nt->FileHeader.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)) return NTW2_CLONE_ERR_BAD_PE;
    const IMAGE_OPTIONAL_HEADER32* const oh = &nt->OptionalHeader;
    if (oh->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return NTW2_CLONE_ERR_BAD_PE;
    const uint32_t nsec = nt->FileHeader.NumberOfSections;
    if (nsec == 0 || nsec > kMaxSections) return NTW2_CLONE_ERR_BAD_PE;
    const uint32_t size_of_image = oh->SizeOfImage;
    const uint32_t size_of_headers = oh->SizeOfHeaders;
    if (size_of_headers == 0 || size_of_image < size_of_headers) return NTW2_CLONE_ERR_BAD_PE;
    if (static_cast<uint64_t>(info->base) + size_of_image > 0x100000000ull) return NTW2_CLONE_ERR_BAD_PE;
    const uint64_t table_begin = static_cast<uint64_t>(lfanew) + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
                                 nt->FileHeader.SizeOfOptionalHeader;
    const uint64_t table_end = table_begin + static_cast<uint64_t>(nsec) * sizeof(IMAGE_SECTION_HEADER);
    if (table_end > size_of_headers) return NTW2_CLONE_ERR_BAD_PE;
    if (oh->ImageBase != kPreferredBase && oh->ImageBase != info->base) {
        *detail = oh->ImageBase;
        return NTW2_CLONE_ERR_IMAGE_IDENTITY;
    }
    const IMAGE_SECTION_HEADER* const sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(p + static_cast<uint32_t>(table_begin));
    for (uint32_t i = 0; i < nsec; ++i) {
        uint32_t extent = sec[i].Misc.VirtualSize > sec[i].SizeOfRawData ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        const uint32_t rva = sec[i].VirtualAddress;
        if (rva >= size_of_image) return NTW2_CLONE_ERR_BAD_PE;
        if (static_cast<uint64_t>(rva) + extent > size_of_image) extent = size_of_image - rva;
        info->sections[i].rva = rva;
        info->sections[i].size = extent;
    }
    info->size_of_image = size_of_image;
    info->section_count = nsec;
    return NTW2_CLONE_OK;
}

uint32_t ParseImage(ImageInfo* info, uint32_t* detail) {
    __try {
        return ParseImageUnguarded(info, detail);
    } __except (GuardFilter(GetExceptionCode())) {
        return NTW2_CLONE_ERR_BAD_PE;
    }
}

// True when every byte of [addr, addr+size) lies in committed, readable, non-guard pages.
bool Readable(uint32_t addr, uint32_t size) {
    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY;
    uint64_t cur = addr;
    const uint64_t end = static_cast<uint64_t>(addr) + size;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(cur)), &mbi, sizeof mbi) != sizeof mbi) return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 || (mbi.Protect & kReadable) == 0)
            return false;
        const uint64_t region_end = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)) + mbi.RegionSize;
        if (region_end <= cur) return false;
        cur = region_end;
    }
    return true;
}

// FNV-1a64 over the span with each HIGHLOW dword rebased to the preferred image base. Relocation offsets must
// already have been validated (sorted, non-overlapping, inside the span). Returns false if reading faulted.
bool HashSourceGuarded(const uint8_t* p, const ntw2_source_spec* s, uint32_t delta, uint64_t* out) {
    __try {
        uint64_t h = kFnvOffset;
        uint32_t next = 0;
        for (uint32_t i = 0; i < s->size;) {
            if (next < s->relocation_count && s->relocations[next] == i) {
                uint32_t v = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8) |
                             (static_cast<uint32_t>(p[i + 2]) << 16) | (static_cast<uint32_t>(p[i + 3]) << 24);
                v -= delta;
                for (uint32_t b = 0; b < 4; ++b) {
                    h ^= static_cast<uint8_t>(v >> (8 * b));
                    h *= kFnvPrime;
                }
                i += 4;
                ++next;
            } else {
                h ^= p[i];
                h *= kFnvPrime;
                ++i;
            }
        }
        *out = h;
        return true;
    } __except (GuardFilter(GetExceptionCode())) {
        return false;
    }
}

bool CopyGuarded(void* dst, const void* src, uint32_t n) {
    __try {
        memcpy(dst, src, n);
        return true;
    } __except (GuardFilter(GetExceptionCode())) {
        return false;
    }
}

uint32_t ValidateSource(const ImageInfo& img, uint32_t index, uint32_t* detail) {
    const ntw2_source_spec& s = ntw2_sources[index];
    *detail = index;
    if (s.size == 0 || s.va < kPreferredBase) return NTW2_CLONE_ERR_SOURCE_RANGE;
    const uint64_t rva = s.va - kPreferredBase;
    if (rva + s.size > img.size_of_image) return NTW2_CLONE_ERR_SOURCE_RANGE;
    bool in_section = false;
    for (uint32_t i = 0; i < img.section_count; ++i) {
        const uint64_t b = img.sections[i].rva;
        if (rva >= b && rva + s.size <= b + img.sections[i].size) {
            in_section = true;
            break;
        }
    }
    if (!in_section) return NTW2_CLONE_ERR_SOURCE_RANGE;
    if (s.relocation_count != 0) {
        if (s.relocations == nullptr) return NTW2_CLONE_ERR_SOURCE_RELOCATION;
        uint64_t floor_offset = 0;
        for (uint32_t r = 0; r < s.relocation_count; ++r) {
            const uint32_t off = s.relocations[r];
            if (off < floor_offset || static_cast<uint64_t>(off) + 4 > s.size) return NTW2_CLONE_ERR_SOURCE_RELOCATION;
            floor_offset = static_cast<uint64_t>(off) + 4;
        }
    }
    const uint32_t addr = img.base + static_cast<uint32_t>(rva);
    if (!Readable(addr, s.size)) return NTW2_CLONE_ERR_SOURCE_UNREADABLE;
    uint64_t hash = 0;
    if (!HashSourceGuarded(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(addr)), &s, img.delta, &hash))
        return NTW2_CLONE_ERR_SOURCE_UNREADABLE;
    if (hash != s.hash) return NTW2_CLONE_ERR_SOURCE_HASH;
    *detail = 0;
    return NTW2_CLONE_OK;
}

// ---- metadata validation ---------------------------------------------------------------------------------------

bool IsData(uint32_t kind) { return kind == NTW2_COPY || kind == NTW2_LITERAL; }

// Structural checks that do not depend on any address: bounds, source spans, exact non-overlapping coverage of the
// clone by COPY/LITERAL operations, fixup sizes and non-overlap.
uint32_t ValidateClone(uint32_t ci, uint32_t* detail) {
    const ntw2_clone_spec& s = ntw2_specs[ci];
    *detail = ci;
    if (s.size == 0 || s.size > kMaxCloneBytes || s.operations == nullptr || s.operation_count == 0)
        return NTW2_CLONE_ERR_CLONE_SPEC;
    uint64_t covered = 0;
    for (uint32_t i = 0; i < s.operation_count; ++i) {
        const ntw2_clone_op& o = s.operations[i];
        *detail = Detail(ci, i);
        if (o.kind > NTW2_RELATIVE) return NTW2_CLONE_ERR_OP_KIND;
        if (o.size == 0 || o.destination > s.size || o.size > s.size - o.destination) return NTW2_CLONE_ERR_OP_BOUNDS;
        switch (o.kind) {
        case NTW2_COPY: {
            if (o.source >= kSourceCount) return NTW2_CLONE_ERR_OP_SOURCE;
            const ntw2_source_spec& src = ntw2_sources[o.source];
            if (o.offset > src.size || o.size > src.size - o.offset) return NTW2_CLONE_ERR_OP_SOURCE;
            covered += o.size;
            break;
        }
        case NTW2_LITERAL:
            if (o.literal == nullptr) return NTW2_CLONE_ERR_OP_LITERAL;
            covered += o.size;
            break;
        case NTW2_ABSOLUTE:
            if (o.size != 4) return NTW2_CLONE_ERR_FIXUP_SIZE;
            if (o.source > NTW2_TARGET_BINDING) return NTW2_CLONE_ERR_FIXUP_TARGET;
            break;
        default:  // NTW2_RELATIVE
            if (o.size != 4 && o.size != 1) return NTW2_CLONE_ERR_FIXUP_SIZE;
            if (o.source > NTW2_TARGET_BINDING) return NTW2_CLONE_ERR_FIXUP_TARGET;
            break;
        }
    }
    for (uint32_t j = 1; j < s.operation_count; ++j) {
        const ntw2_clone_op& b = s.operations[j];
        const bool data = IsData(b.kind);
        for (uint32_t i = 0; i < j; ++i) {
            const ntw2_clone_op& a = s.operations[i];
            if (IsData(a.kind) != data) continue;
            if (a.destination < b.destination + b.size && b.destination < a.destination + a.size) {
                // sums are within the clone (<= 1 MiB), so no overflow
                *detail = Detail(ci, j);
                return data ? NTW2_CLONE_ERR_OP_OVERLAP : NTW2_CLONE_ERR_FIXUP_OVERLAP;
            }
        }
    }
    // Disjoint and each inside [0,size): equal sum <=> exact coverage.
    if (covered != s.size) {
        *detail = ci;
        return NTW2_CLONE_ERR_OP_COVERAGE;
    }
    *detail = 0;
    return NTW2_CLONE_OK;
}

// ---- emission --------------------------------------------------------------------------------------------------

struct Emit {
    ImageInfo image;
    const uint32_t* bindings;
    uint8_t* region;
    uint32_t offsets[NTW2_CLONE_COUNT];
    uint32_t entries[NTW2_CLONE_COUNT];
    uint32_t grid_gates;
};

void Put32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t GridEdge(uint32_t clone, uint32_t field) {
    for (uint32_t i = 0; i < ntw2_grid_edge_count; ++i)
        if (ntw2_grid_edges[i].clone == clone && ntw2_grid_edges[i].field == field) return i;
    return UINT32_MAX;
}

uint32_t EmitGridGate(uint8_t* gate, uint32_t edge, uint32_t target, uint32_t callback) {
    // Preserve flags, every GPR, x87/MMX and SSE state. The callback receives one
    // cdecl argument on a private aligned stack, then we tail-jump with the
    // original return address and all original stack arguments untouched.
    static const uint8_t code[] = {
        0x9c,0x60,0x89,0xe3,0x81,0xec,0x10,0x02,0x00,0x00,0x83,0xe4,0xf0,
        0x0f,0xae,0x04,0x24,0xfc,0x68,0,0,0,0,0xe8,0,0,0,0,
        0x83,0xc4,0x04,0x0f,0xae,0x0c,0x24,0x89,0xdc,0x61,0x9d,0xe9,0,0,0,0
    };
    const uint32_t address = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(gate));
    memcpy(gate, code, sizeof(code));
    Put32(gate + 19, edge);
    Put32(gate + 24, callback - (address + 28));
    Put32(gate + 40, target - (address + 44));
    return address;
}

uint32_t ResolveTarget(const Emit& e, const ntw2_clone_op& o, uint32_t* value) {
    switch (o.source) {
    case NTW2_TARGET_IMAGE: {
        const int64_t t = static_cast<int64_t>(o.offset) + o.addend;
        if (t < static_cast<int64_t>(kPreferredBase) || t - kPreferredBase >= e.image.size_of_image)
            return NTW2_CLONE_ERR_FIXUP_TARGET;
        *value = static_cast<uint32_t>(t - kPreferredBase) + e.image.base;
        return NTW2_CLONE_OK;
    }
    case NTW2_TARGET_CLONE: {
        if (o.offset >= NTW2_CLONE_COUNT) return NTW2_CLONE_ERR_FIXUP_TARGET;
        if (o.addend < 0 || static_cast<uint32_t>(o.addend) >= ntw2_specs[o.offset].size) return NTW2_CLONE_ERR_FIXUP_TARGET;
        *value = e.entries[o.offset] + static_cast<uint32_t>(o.addend);
        return NTW2_CLONE_OK;
    }
    case NTW2_TARGET_BINDING: {
        if (o.offset >= NTW2_BIND_COUNT) return NTW2_CLONE_ERR_FIXUP_TARGET;
        const uint32_t b = e.bindings[o.offset];
        if (b == 0) return NTW2_CLONE_ERR_FIXUP_BINDING;
        *value = b + static_cast<uint32_t>(o.addend);  // modular, like the target address space
        return NTW2_CLONE_OK;
    }
    default:
        return NTW2_CLONE_ERR_FIXUP_TARGET;
    }
}

uint32_t EmitClone(Emit& e, uint32_t ci, uint32_t* detail) {
    const ntw2_clone_spec& s = ntw2_specs[ci];
    uint8_t* const dst = e.region + e.offsets[ci];
    for (uint32_t i = 0; i < s.operation_count; ++i) {
        const ntw2_clone_op& o = s.operations[i];
        *detail = Detail(ci, i);
        if (o.kind == NTW2_LITERAL) {
            memcpy(dst + o.destination, o.literal, o.size);
        } else if (o.kind == NTW2_COPY) {
            if (o.source >= kSourceCount) return NTW2_CLONE_ERR_OP_SOURCE;
            const ntw2_source_spec& src = ntw2_sources[o.source];
            if (src.va < kPreferredBase || o.offset > src.size || o.size > src.size - o.offset) return NTW2_CLONE_ERR_OP_SOURCE;
            const uint64_t rva = static_cast<uint64_t>(src.va - kPreferredBase) + o.offset;
            if (rva + o.size > e.image.size_of_image) return NTW2_CLONE_ERR_OP_SOURCE;
            const uint32_t addr = e.image.base + static_cast<uint32_t>(rva);
            if (!Readable(addr, o.size)) return NTW2_CLONE_ERR_COPY_UNREADABLE;
            if (!CopyGuarded(dst + o.destination, reinterpret_cast<const void*>(static_cast<uintptr_t>(addr)), o.size))
                return NTW2_CLONE_ERR_COPY_UNREADABLE;
        }
    }
    for (uint32_t i = 0; i < s.operation_count; ++i) {
        const ntw2_clone_op& o = s.operations[i];
        if (IsData(o.kind)) continue;
        *detail = Detail(ci, i);
        uint32_t target = 0;
        const uint32_t rc = ResolveTarget(e, o, &target);
        if (rc != NTW2_CLONE_OK) return rc;
        if (gridCallback && o.kind == NTW2_RELATIVE) {
            const uint32_t edge = GridEdge(ci, o.destination);
            if (edge != UINT32_MAX) {
                if (o.size != 4 || !o.destination || dst[o.destination - 1] != 0xe8)
                    return NTW2_CLONE_ERR_FIXUP_TARGET;
                target = EmitGridGate(e.region + e.grid_gates + edge * kGridGateBytes, edge, target, gridCallback);
            }
        }
        uint8_t* const field = dst + o.destination;
        if (o.kind == NTW2_ABSOLUTE) {
            Put32(field, target);
        } else {
            const uint32_t field_end = e.entries[ci] + o.destination + o.size;
            const uint32_t rel = target - field_end;  // modulo 2^32: exact x86 rel32 encoding
            if (o.size == 4) {
                Put32(field, rel);
            } else {
                const int32_t d = static_cast<int32_t>(rel);
                if (d < -128 || d > 127) return NTW2_CLONE_ERR_FIXUP_REL8_RANGE;
                field[0] = static_cast<uint8_t>(d);
            }
        }
    }
    *detail = 0;
    return NTW2_CLONE_OK;
}

uint32_t Build(uint32_t image_base, const uint32_t* bindings, void** region_out, ntw2_clone_set* set, uint32_t* detail) {
    if ((image_base & (kBaseAlignment - 1)) != 0 || image_base == 0) return NTW2_CLONE_ERR_BAD_IMAGE_BASE;

    Emit e;
    memset(&e, 0, sizeof e);
    e.image.base = image_base;
    e.image.delta = image_base - kPreferredBase;
    e.bindings = bindings;
    uint32_t rc = ParseImage(&e.image, detail);
    if (rc != NTW2_CLONE_OK) return rc;

    for (uint32_t i = 0; i < kSourceCount; ++i) {
        rc = ValidateSource(e.image, i, detail);
        if (rc != NTW2_CLONE_OK) return rc;
    }
    for (uint32_t c = 0; c < NTW2_CLONE_COUNT; ++c) {
        rc = ValidateClone(c, detail);
        if (rc != NTW2_CLONE_OK) return rc;
    }

    // Layout: 16-byte aligned clone starts, checked in 64 bits.
    uint64_t cursor = gridCallback ? kGridHeaderBytes : 0;
    for (uint32_t c = 0; c < NTW2_CLONE_COUNT; ++c) {
        cursor = (cursor + kCloneAlignment - 1) & ~static_cast<uint64_t>(kCloneAlignment - 1);
        e.offsets[c] = static_cast<uint32_t>(cursor);
        cursor += ntw2_specs[c].size;
        if (cursor > kMaxTotalBytes) {
            *detail = c;
            return NTW2_CLONE_ERR_CLONE_LAYOUT;
        }
    }
    e.grid_gates = static_cast<uint32_t>(cursor);
    if (gridCallback) cursor += ntw2_grid_edge_count * kGridGateBytes;
    if (cursor > kMaxTotalBytes) return NTW2_CLONE_ERR_CLONE_LAYOUT;
    const uint32_t total = static_cast<uint32_t>(cursor);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uint64_t page = si.dwPageSize ? si.dwPageSize : 4096u;
    const uint64_t rounded = (static_cast<uint64_t>(total) + page - 1) / page * page;
    if (rounded > kMaxTotalBytes + page) {
        *detail = 0;
        return NTW2_CLONE_ERR_CLONE_LAYOUT;
    }

    void* const mem = VirtualAlloc(nullptr, static_cast<SIZE_T>(rounded), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == nullptr) {
        *detail = GetLastError();
        return NTW2_CLONE_ERR_ALLOC_FAILED;
    }
    *region_out = mem;
    e.region = static_cast<uint8_t*>(mem);
    memset(mem, kPadding, static_cast<size_t>(rounded));
    const uint32_t base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mem));
    if (static_cast<uint64_t>(base) + rounded > 0x100000000ull) {
        *detail = 0;
        return NTW2_CLONE_ERR_CLONE_LAYOUT;
    }
    for (uint32_t c = 0; c < NTW2_CLONE_COUNT; ++c) e.entries[c] = base + e.offsets[c];
    if (gridCallback) {
        GridArena* header = reinterpret_cast<GridArena*>(mem);
        header->magic = kGridMagic; header->image_base = image_base; header->callback = gridCallback;
        memcpy(header->entries, e.entries, sizeof(e.entries));
    }

    for (uint32_t c = 0; c < NTW2_CLONE_COUNT; ++c) {
        rc = EmitClone(e, c, detail);
        if (rc != NTW2_CLONE_OK) return rc;
    }

    DWORD old = 0;
    if (!VirtualProtect(mem, static_cast<SIZE_T>(rounded), PAGE_EXECUTE_READ, &old)) {
        *detail = GetLastError();
        return NTW2_CLONE_ERR_PROTECT_FAILED;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), mem, static_cast<SIZE_T>(rounded))) {
        *detail = GetLastError();
        return NTW2_CLONE_ERR_FLUSH_FAILED;
    }

    set->allocation = mem;
    set->allocation_bytes = static_cast<uint32_t>(rounded);
    for (uint32_t c = 0; c < NTW2_CLONE_COUNT; ++c) set->entries[c] = e.entries[c];
    *detail = 0;
    return NTW2_CLONE_OK;
}

}  // namespace

extern "C" void ntw2_clones_grid_callback(uint32_t callback) { gridCallback = callback; }
extern "C" const ntw2_grid_reader_spec* ntw2_grid_reader_specs(uint32_t* count) {
    *count = static_cast<uint32_t>(sizeof(ntw2_grid_readers) / sizeof(ntw2_grid_readers[0]));
    return ntw2_grid_readers;
}
extern "C" const ntw2_grid_edge_spec* ntw2_grid_edge_specs(uint32_t* count) {
    *count = ntw2_grid_edge_count;
    return ntw2_grid_edges;
}
extern "C" uint32_t ntw2_grid_edge_route(uint32_t edge) {
    // Values mirror NTW2_GRID_ROUTE_IMAGE/BINDING/CLONE/OTHER in ntw2_runtime.h.
    if (edge >= ntw2_grid_edge_count) return 3;
    const ntw2_grid_edge_spec& e = ntw2_grid_edges[edge];
    const ntw2_clone_spec& spec = ntw2_specs[e.clone];
    for (uint32_t i = 0; i < spec.operation_count; ++i) {
        const ntw2_clone_op& o = spec.operations[i];
        if (o.kind != NTW2_RELATIVE || o.destination != e.field) continue;
        if (o.source == NTW2_TARGET_BINDING) return 1;
        if (o.source == NTW2_TARGET_CLONE) return 2;
        return o.source == NTW2_TARGET_IMAGE && static_cast<int64_t>(o.offset) + o.addend == ntw2_grid_readers[e.reader].va ? 0u : 3u;
    }
    return 3;
}
extern "C" uint32_t ntw2_grid_unresolved_edges(void) { return ntw2_grid_unresolved_edge_count; }
extern "C" uint32_t ntw2_clones_grid_reader(uint32_t eip) {
    MEMORY_BASIC_INFORMATION memory = {};
    if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(eip)), &memory, sizeof(memory)) ||
        memory.Type != MEM_PRIVATE || memory.State != MEM_COMMIT) return UINT32_MAX;
    GridArena header;
    if (!CopyGuarded(&header, memory.AllocationBase, sizeof(header)) || header.magic != kGridMagic) return UINT32_MAX;
    for (uint32_t i = 0; i < ntw2_grid_range_count; ++i) {
        const ntw2_grid_range_spec& range = ntw2_grid_ranges[i];
        const uint32_t entry = header.entries[range.clone];
        if (entry && eip >= entry && eip - entry >= range.begin && eip - entry < range.end) return range.reader;
    }
    return UINT32_MAX;
}
extern "C" uint32_t ntw2_clone_origin(const ntw2_clone_set* set, uint32_t address, uint32_t* clone) {
    if (clone) *clone = UINT32_MAX;
    if (!set || !set->allocation) return 0;
    const uint32_t base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(set->allocation));
    if (address < base || address - base >= set->allocation_bytes) return 0;
    for (uint32_t ci = 0; ci < NTW2_CLONE_COUNT; ++ci) {
        const uint32_t entry = set->entries[ci];
        const ntw2_clone_spec& s = ntw2_specs[ci];
        if (!entry || address < entry || address - entry >= s.size) continue;
        if (clone) *clone = ci;
        const uint32_t offset = address - entry;
        for (uint32_t i = 0; i < s.operation_count; ++i) {
            const ntw2_clone_op& o = s.operations[i];
            if (o.kind == NTW2_COPY && offset >= o.destination && offset - o.destination < o.size)
                return ntw2_sources[o.source].va + o.offset + (offset - o.destination);
        }
        return 0; // emitted literal (rewritten call/thunk bytes): no single original instruction
    }
    return 0;
}

extern "C" uint32_t ntw2_build_clones(uint32_t image_base, const uint32_t bindings[NTW2_BIND_COUNT], ntw2_clone_set* out,
                                      uint32_t* detail) {
    uint32_t scratch = 0;
    uint32_t* const d = detail ? detail : &scratch;
    *d = 0;
    if (out == nullptr || bindings == nullptr) return NTW2_CLONE_ERR_BAD_ARGUMENT;
    memset(out, 0, sizeof *out);

    ntw2_clone_set built;
    memset(&built, 0, sizeof built);
    void* region = nullptr;
    const uint32_t rc = Build(image_base, bindings, &region, &built, d);
    if (rc != NTW2_CLONE_OK) {
        // Only an unpublished allocation can exist here; nothing ever executed from it.
        if (region != nullptr) VirtualFree(region, 0, MEM_RELEASE);
        return rc;
    }
    *out = built;
    return NTW2_CLONE_OK;
}

extern "C" uint32_t ntw2_build_loco_participant(uint32_t wrap, uint32_t move, uint32_t class_wrap, uint32_t select,
    const uint32_t bindings[NTW2_BIND_COUNT], ntw2_clone_set* out) {
    if (!wrap || !move || !bindings || !out || (class_wrap && !select)) return NTW2_CLONE_ERR_BAD_ARGUMENT;
    memset(out, 0, sizeof *out);
    const uint32_t ids[3] = {NTW2_CLONE_LOCO_WRAP, NTW2_CLONE_LOCO_MOVE, NTW2_CLONE_LOCO_CLASS_WRAP};
    const uint32_t source[3] = {wrap, move, class_wrap};
    const uint32_t clones = class_wrap ? 3u : 2u;
    GridArena header = {};
    MEMORY_BASIC_INFORMATION memory = {};
    if (VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(wrap)), &memory, sizeof(memory)))
        CopyGuarded(&header, memory.AllocationBase, sizeof(header));
    const bool census = header.magic == kGridMagic && header.callback;
    const uint32_t prefix = census ? kGridHeaderBytes : 0;
    const uint32_t moveOffset = prefix + ((ntw2_specs[ids[0]].size + 15u) & ~15u);
    const uint32_t classOffset = moveOffset + ((ntw2_specs[ids[1]].size + 15u) & ~15u);
    const uint32_t gatesOffset = class_wrap ? classOffset + ntw2_specs[ids[2]].size : moveOffset + ntw2_specs[ids[1]].size;
    uint32_t gateCount = 0;
    if (census) for (uint32_t i = 0; i < ntw2_grid_edge_count; ++i)
        for (uint32_t n = 0; n < clones; ++n) if (ntw2_grid_edges[i].clone == ids[n]) ++gateCount;
    const uint32_t size = gatesOffset + gateCount * kGridGateBytes;
    uint8_t* region = static_cast<uint8_t*>(VirtualAlloc(nullptr, size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!region) return NTW2_CLONE_ERR_ALLOC_FAILED;
    const uint32_t regionBase = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(region));
    const uint32_t offsets[3] = {prefix, moveOffset, classOffset};
    const uint32_t destination[3] = {regionBase + prefix, regionBase + moveOffset, class_wrap ? regionBase + classOffset : 0u};
    uint32_t error = NTW2_CLONE_OK;
    uint32_t gateIndex = 0;
    for (uint32_t n = 0; n < clones && !error; ++n) {
        const ntw2_clone_spec& spec = ntw2_specs[ids[n]];
        uint8_t* dst = region + offsets[n];
        const uint8_t* src = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(source[n]));
        if (!CopyGuarded(dst, src, spec.size)) { error = NTW2_CLONE_ERR_COPY_UNREADABLE; break; }
        for (uint32_t i = 0; i < spec.operation_count; ++i) {
            const ntw2_clone_op& op = spec.operations[i];
            if (op.kind != NTW2_RELATIVE && op.kind != NTW2_ABSOLUTE) continue;
            uint32_t target;
            if (op.source == NTW2_TARGET_BINDING) {
                if (op.offset >= NTW2_BIND_COUNT || !bindings[op.offset]) {
                    error = NTW2_CLONE_ERR_FIXUP_BINDING; break;
                }
                target = bindings[op.offset] + op.addend;
            } else if (op.source == NTW2_TARGET_CLONE) {
                // The participant class wrapper calls the host selector (private mover + A3 refusal), never the staging selector clone.
                if (n == 2 && op.offset == NTW2_CLONE_LOCO_SELECT) target = select + op.addend;
                else if (op.offset == ids[0] || op.offset == ids[1]) target = destination[op.offset == ids[1]] + op.addend;
                else { error = NTW2_CLONE_ERR_FIXUP_TARGET; break; }
            } else if (op.kind == NTW2_ABSOLUTE) {
                continue; // image address is already relocated in the validated source clone
            } else if (census && op.source == NTW2_TARGET_IMAGE) {
                target = op.offset + op.addend + header.image_base - kPreferredBase;
            } else {
                if (op.size != 4) { error = NTW2_CLONE_ERR_FIXUP_SIZE; break; }
                uint32_t displacement;
                memcpy(&displacement, src + op.destination, 4);
                target = source[n] + op.destination + 4 + displacement;
            }
            if (op.size != 4) { error = NTW2_CLONE_ERR_FIXUP_SIZE; break; }
            if (census && op.kind == NTW2_RELATIVE) {
                const uint32_t edge = GridEdge(ids[n], op.destination);
                if (edge != UINT32_MAX)
                    target = EmitGridGate(region + gatesOffset + gateIndex++ * kGridGateBytes, edge, target, header.callback);
            }
            Put32(dst + op.destination, op.kind == NTW2_ABSOLUTE ? target :
                target - (destination[n] + op.destination + 4));
        }
    }
    if (census && !error) {
        GridArena* emitted = reinterpret_cast<GridArena*>(region);
        memset(emitted, 0, sizeof(*emitted));
        emitted->magic = kGridMagic; emitted->image_base = header.image_base; emitted->callback = header.callback;
        for (uint32_t n = 0; n < clones; ++n) emitted->entries[ids[n]] = destination[n];
    }
    DWORD old;
    if (!error && !VirtualProtect(region, size, PAGE_EXECUTE_READ, &old)) error = NTW2_CLONE_ERR_PROTECT_FAILED;
    if (!error && !FlushInstructionCache(GetCurrentProcess(), region, size)) error = NTW2_CLONE_ERR_FLUSH_FAILED;
    if (error) { VirtualFree(region, 0, MEM_RELEASE); return error; }
    out->allocation = region; out->allocation_bytes = size;
    for (uint32_t n = 0; n < clones; ++n) out->entries[ids[n]] = destination[n];
    return NTW2_CLONE_OK;
}

// Brain worker family: ONE duplicate of the validated BRAIN_W closure whose binding fixups take the supplied table
// (B2_SERVICE_GATE/B2_OBSERVE select the worker gates). The primary arena is the byte source and keeps every other
// clone; family-internal CLONE fixups retarget into the duplicate, all others keep the primary entry. The span between
// the first and last family clone is copied verbatim, so intra-span rel8/rel32 layout is identical to the primary.
namespace {
bool BrainWorkerMember(uint32_t id) {
    return (id >= NTW2_CLONE_BRAIN_W && id <= NTW2_CLONE_BRAIN_W_UNLINK) ||
           (id >= NTW2_CLONE_BRAIN_W_COMMON_STEP && id <= NTW2_CLONE_BRAIN_ACTION_EMPTY) ||
           (id >= NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF9E0 && id <= NTW2_CLONE_BRAIN_W_NODE_DISPATCH_809D80);
}
}  // namespace

extern "C" uint32_t ntw2_build_brain_worker_family(const ntw2_clone_set* primary, uint32_t image_base,
    const uint32_t bindings[NTW2_BIND_COUNT], ntw2_clone_set* out) {
    if (!primary || !bindings || !out || !image_base) return NTW2_CLONE_ERR_BAD_ARGUMENT;
    memset(out, 0, sizeof *out);
    uint32_t lo = UINT32_MAX, hi = 0;
    for (uint32_t id = 0; id < NTW2_CLONE_COUNT; ++id) {
        if (!BrainWorkerMember(id)) continue;
        const uint32_t entry = primary->entries[id];
        if (!entry) return NTW2_CLONE_ERR_BAD_ARGUMENT;
        if (entry < lo) lo = entry;
        if (entry + ntw2_specs[id].size > hi) hi = entry + ntw2_specs[id].size;
    }
    if (lo >= hi || hi - lo > kMaxTotalBytes) return NTW2_CLONE_ERR_CLONE_LAYOUT;
    const uint32_t size = hi - lo;
    uint8_t* const region = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!region) return NTW2_CLONE_ERR_ALLOC_FAILED;
    const uint32_t base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(region));
    uint32_t error = CopyGuarded(region, reinterpret_cast<const void*>(static_cast<uintptr_t>(lo)), size)
        ? NTW2_CLONE_OK : NTW2_CLONE_ERR_COPY_UNREADABLE;
    uint32_t entries[NTW2_CLONE_COUNT] = {};
    for (uint32_t id = 0; id < NTW2_CLONE_COUNT; ++id)
        entries[id] = BrainWorkerMember(id) ? base + (primary->entries[id] - lo) : primary->entries[id];
    for (uint32_t id = 0; id < NTW2_CLONE_COUNT && !error; ++id) {
        if (!BrainWorkerMember(id)) continue;
        const ntw2_clone_spec& spec = ntw2_specs[id];
        uint8_t* const dst = region + (entries[id] - base);
        for (uint32_t i = 0; i < spec.operation_count && !error; ++i) {
            const ntw2_clone_op& op = spec.operations[i];
            if (IsData(op.kind)) continue;
            uint32_t target;
            if (op.source == NTW2_TARGET_BINDING) {
                if (op.offset >= NTW2_BIND_COUNT || !bindings[op.offset]) { error = NTW2_CLONE_ERR_FIXUP_BINDING; break; }
                target = bindings[op.offset] + static_cast<uint32_t>(op.addend);
            } else if (op.source == NTW2_TARGET_CLONE) {
                if (op.offset >= NTW2_CLONE_COUNT || !entries[op.offset]) { error = NTW2_CLONE_ERR_FIXUP_TARGET; break; }
                target = entries[op.offset] + static_cast<uint32_t>(op.addend);
            } else if (op.source == NTW2_TARGET_IMAGE) {
                // Metadata, never the primary field: a grid-census primary may route through its own gates.
                target = op.offset + static_cast<uint32_t>(op.addend) - kPreferredBase + image_base;
            } else { error = NTW2_CLONE_ERR_FIXUP_TARGET; break; }
            uint8_t* const field = dst + op.destination;
            if (op.kind == NTW2_ABSOLUTE) {
                if (op.size != 4) { error = NTW2_CLONE_ERR_FIXUP_SIZE; break; }
                Put32(field, target);
            } else {
                const uint32_t rel = target - (entries[id] + op.destination + op.size);
                if (op.size == 4) Put32(field, rel);
                else if (op.size == 1) {
                    const int32_t d = static_cast<int32_t>(rel);
                    if (d < -128 || d > 127) { error = NTW2_CLONE_ERR_FIXUP_REL8_RANGE; break; }
                    field[0] = static_cast<uint8_t>(d);
                } else { error = NTW2_CLONE_ERR_FIXUP_SIZE; break; }
            }
        }
    }
    DWORD old;
    if (!error && !VirtualProtect(region, size, PAGE_EXECUTE_READ, &old)) error = NTW2_CLONE_ERR_PROTECT_FAILED;
    if (!error && !FlushInstructionCache(GetCurrentProcess(), region, size)) error = NTW2_CLONE_ERR_FLUSH_FAILED;
    if (error) { VirtualFree(region, 0, MEM_RELEASE); return error; }
    out->allocation = region; out->allocation_bytes = size;
    for (uint32_t id = 0; id < NTW2_CLONE_COUNT; ++id) if (BrainWorkerMember(id)) out->entries[id] = entries[id];
    return NTW2_CLONE_OK;
}
