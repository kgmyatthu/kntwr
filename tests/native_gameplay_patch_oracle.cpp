// Byte-identity oracle for the in-memory gameplay patch (src/core/ntw2_gameplay_patch.c).
//
// The game files on disk are stock; the launcher turns the loader-mapped stock image into the patched image in memory. The
// proof obligation is that the live image is exactly what the Windows loader would have produced from the PATCHED file
// at the same base. This test builds that loader-equivalent image independently of the applier (sections mapped by raw/virtual
// size, base relocations of the patched file applied) and compares it, byte for byte over the whole image above the PE
// header, against:
//   1. private x86 mappings of the STOCK file at several bases (delta 0 and non-zero) after ntw2_gp_apply;
//   2. (optional) the same for mss32.dll;
//   3. (optional) a REAL game process: CreateProcess(CREATE_SUSPENDED) of the stock Napoleon.exe, the same applier through
//      the process backend before the process executes a single instruction, then a full read of the live image.
// Negative cases prove refusal without a single write: occupied appended-section range, a tampered stock byte, a wrong
// preferred base, an already-patched image, a non-PE target. Nothing here starts the game's code.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "native_image_relocation.h"
#include "ntw2_runtime.h"
#include "core/ntw2_gameplay_patch.h"
#pragma comment(lib, "bcrypt.lib")

using Bytes = std::vector<uint8_t>;
static_assert(sizeof(void*) == 4, "owned x86 oracle");
static uint32_t g_checks;

static void Require(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { std::fprintf(stderr, "FAIL %s\n", what); std::exit(1); }
}
static void RequireF(bool ok, const char* fmt, ...) {
    ++g_checks;
    if (ok) return;
    va_list ap;
    va_start(ap, fmt);
    std::fprintf(stderr, "FAIL ");
    std::vfprintf(stderr, fmt, ap);
    std::fprintf(stderr, "\n");
    va_end(ap);
    std::exit(1);
}

static Bytes ReadAll(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "FAIL cannot open %s\n", path); std::exit(1); }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::rewind(f);
    Bytes b(static_cast<size_t>(n));
    if (n > 0 && std::fread(b.data(), 1, b.size(), f) != b.size()) { std::fprintf(stderr, "FAIL read %s\n", path); std::exit(1); }
    std::fclose(f);
    return b;
}

static std::string Sha256Hex(const Bytes& b) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    uint8_t d[32];
    Require(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA-256 provider");
    Require(BCryptHash(alg, nullptr, 0, const_cast<uint8_t*>(b.data()), static_cast<ULONG>(b.size()), d, 32) == 0, "SHA-256");
    BCryptCloseAlgorithmProvider(alg, 0);
    char hex[65];
    for (int i = 0; i < 32; ++i) std::snprintf(hex + 2 * i, 3, "%02x", d[i]);
    return hex;
}

// ---------------------------------------------------------------------------------------------------- independent PE model
struct Pe {
    const Bytes* file = nullptr;
    const IMAGE_NT_HEADERS32* nt = nullptr;
    const IMAGE_SECTION_HEADER* sec = nullptr;
    uint32_t nsec = 0, soi = 0, soh = 0, base = 0;
};

static Pe ParsePe(const Bytes& f, const char* what) {
    Pe p;
    p.file = &f;
    RequireF(f.size() > 0x400 && f[0] == 'M' && f[1] == 'Z', "%s is not a PE", what);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(f.data());
    p.nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(f.data() + dos->e_lfanew);
    RequireF(p.nt->Signature == IMAGE_NT_SIGNATURE && p.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386, "%s is not x86 PE", what);
    p.sec = IMAGE_FIRST_SECTION(p.nt);
    p.nsec = p.nt->FileHeader.NumberOfSections;
    p.soi = p.nt->OptionalHeader.SizeOfImage;
    p.soh = p.nt->OptionalHeader.SizeOfHeaders;
    p.base = p.nt->OptionalHeader.ImageBase;
    return p;
}

static uint32_t AlignUp(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

// The image the loader builds for `file` at `base`: headers, every section's raw data at its RVA (page-rounded virtual
// extent), HIGHLOW relocations with delta = base - ImageBase, the actual base written into the header.
static Bytes LoaderImage(const Bytes& file, uint32_t base, const char* what) {
    Pe p = ParsePe(file, what);
    Bytes out(p.soi, 0);
    std::memcpy(out.data(), file.data(), p.soh);
    for (uint32_t i = 0; i < p.nsec; ++i) {
        const IMAGE_SECTION_HEADER& s = p.sec[i];
        uint32_t n = std::min<uint32_t>(s.SizeOfRawData, AlignUp(s.Misc.VirtualSize, 0x1000));
        RequireF(static_cast<uint64_t>(s.PointerToRawData) + n <= file.size() && static_cast<uint64_t>(s.VirtualAddress) + n <= p.soi,
                 "%s section %u raw data out of range", what, i);
        if (n) std::memcpy(out.data() + s.VirtualAddress, file.data() + s.PointerToRawData, n);
    }
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(out.data() + reinterpret_cast<const IMAGE_DOS_HEADER*>(out.data())->e_lfanew);
    RequireF(RelocateNativeImage(out.data(), out.size(), nt, base - p.base), "%s relocation", what);
    nt->OptionalHeader.ImageBase = base;
    return out;
}

static uint32_t SectionProtection(uint32_t c) {
    bool e = c & IMAGE_SCN_MEM_EXECUTE, r = c & IMAGE_SCN_MEM_READ, w = c & IMAGE_SCN_MEM_WRITE;
    if (e && w) return PAGE_EXECUTE_READWRITE;
    if (e && r) return PAGE_EXECUTE_READ;
    if (e) return PAGE_EXECUTE;
    if (w) return PAGE_READWRITE;
    return r ? PAGE_READONLY : PAGE_NOACCESS;
}

static std::string SectionName(const Pe& p, uint32_t rva) {
    if (rva < p.soh) return "header";
    for (uint32_t i = 0; i < p.nsec; ++i)
        if (rva >= p.sec[i].VirtualAddress && rva < p.sec[i].VirtualAddress + AlignUp(p.sec[i].Misc.VirtualSize, 0x1000))
            return std::string(reinterpret_cast<const char*>(p.sec[i].Name), strnlen(reinterpret_cast<const char*>(p.sec[i].Name), 8));
    return "?";
}

// Compare live[0..soi) against the loader-equivalent PATCHED image over the whole image (when sections are appended, the PE
// header is updated too so ParseImage/ValidateSource see the appended sections; when no sections are appended, the header keeps
// the stock bytes). Returns the number of mismatching bytes (first 6 printed).
static uint64_t CompareImage(const char* label, const uint8_t* live, const Bytes& patchedImage, const Bytes& stockImage,
                             const Pe& pp, const Pe& sp, bool imageBaseMayBePreferred) {
    uint64_t bad = 0;
    const uint32_t soh = pp.soh;
    const bool headerPatched = pp.soi > sp.soi;
    const uint32_t ibOff = reinterpret_cast<const uint8_t*>(&sp.nt->OptionalHeader.ImageBase) - sp.file->data();
    for (uint32_t i = 0; i < patchedImage.size(); ++i) {
        uint8_t want = (i < soh && !headerPatched) ? stockImage[i] : patchedImage[i];
        if (i >= ibOff && i < ibOff + 4 && imageBaseMayBePreferred && live[i] != want) {
            const uint32_t pref = sp.base;
            want = reinterpret_cast<const uint8_t*>(&pref)[i - ibOff];
        }
        if (live[i] != want) {
            if (bad < 6) std::fprintf(stderr, "  %s mismatch rva %#x (%s): live %02x want %02x\n", label, i, SectionName(pp, i).c_str(), live[i], want);
            ++bad;
        }
    }
    return bad;
}

// ---------------------------------------------------------------------------------------------------- private mappings
struct Mapping {
    uint8_t* base = nullptr;
    uint32_t stockSoi = 0, patchedSoi = 0;
};

// Probe that [base, base+patchedSoi) is entirely free, then commit only the stock part (the applier must claim the rest).
static bool MapStock(const Bytes& stock, const Pe& sp, const Pe& pp, uint32_t base, Mapping* m) {
    void* probe = VirtualAlloc(reinterpret_cast<void*>(base), pp.soi, MEM_RESERVE, PAGE_NOACCESS);
    if (!probe) return false;
    VirtualFree(probe, 0, MEM_RELEASE);
    void* p = VirtualAlloc(reinterpret_cast<void*>(base), sp.soi, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return false;
    Bytes image = LoaderImage(stock, base, "stock");
    std::memcpy(p, image.data(), image.size());
    DWORD old;
    VirtualProtect(p, sp.soh, PAGE_READONLY, &old);
    for (uint32_t i = 0; i < sp.nsec; ++i)
        VirtualProtect(static_cast<uint8_t*>(p) + sp.sec[i].VirtualAddress, AlignUp(sp.sec[i].Misc.VirtualSize, 0x1000),
                       SectionProtection(sp.sec[i].Characteristics), &old);
    m->base = static_cast<uint8_t*>(p);
    m->stockSoi = sp.soi;
    m->patchedSoi = pp.soi;
    return true;
}

static void Unmap(Mapping* m) {
    if (!m->base) return;
    VirtualFree(m->base, 0, MEM_RELEASE);
    m->base = nullptr;
}

struct Case {
    const char* name;
    const uint8_t* blob;
    uint32_t blobSize;
    Bytes stock, patched;
    Pe sp, pp;
    bool hasAppended;
};

static Case MakeCase(const char* name, const uint8_t* blob, uint32_t blobSize, const Bytes& stock, const Bytes& patched) {
    Case c;
    c.name = name;
    c.blob = blob;
    c.blobSize = blobSize;
    c.stock = stock;
    c.patched = patched;
    c.sp = ParsePe(c.stock, "stock");
    c.pp = ParsePe(c.patched, "patched");
    c.hasAppended = c.pp.soi > c.sp.soi;
    return c;
}

static void ReportLine(const char* what, const ntw2_gp_report& r) {
    std::printf("  %-26s runs %u (header %u, applied %u, %u B in windows)  fixups in windows: stock %u un-relocated, patched %u re-relocated  "
                "tables: stock %u patched %u  sections %u (%#x B, %u fixups)\n",
                what, r.runs_total, r.runs_header, r.runs_applied, r.bytes_applied, r.fixups_stock_unrelocated, r.fixups_patched_relocated,
                r.fixups_stock_total, r.fixups_patched_total, r.sections_mapped, r.section_bytes, r.section_fixups);
}

static void RunPrivate(const Case& c, uint32_t base, bool* unrelocatedWindowSeen) {
    Mapping m;
    Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock image");
    ntw2_gp_report rep;
    ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
    int rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep);
    if (rc != 0) std::fprintf(stderr, "  apply failed: status %u phase %u: %s (run %u va %#x)\n", rep.status, rep.phase, rep.error, rep.fail_run, rep.fail_va);
    Require(rc == 0, "ntw2_gp_apply on a private stock mapping");
    char label[64];
    std::snprintf(label, sizeof label, "%s @ %#010x (delta %+d)", c.name, base, static_cast<int>(base - c.sp.base));
    ReportLine(label, rep);
    Require(rep.runs_applied + rep.runs_header == rep.runs_total, "every run is applied or header-verified");
    Require(rep.status == NTW2_GP_OK && rep.phase == 1, "report status");
    Bytes patchedImage = LoaderImage(c.patched, base, "patched");
    Bytes stockImage = LoaderImage(c.stock, base, "stock");
    const uint64_t bad = CompareImage(label, m.base, patchedImage, stockImage, c.pp, c.sp, false);
    RequireF(bad == 0, "live image differs from the loader-equivalent patched image (%llu bytes)", static_cast<unsigned long long>(bad));
    // The appended range exists with section protections; patched stock pages keep their original protection.
    for (uint32_t i = 0; i < c.pp.nsec; ++i) {
        MEMORY_BASIC_INFORMATION mbi;
        Require(VirtualQuery(m.base + c.pp.sec[i].VirtualAddress, &mbi, sizeof mbi) == sizeof mbi, "VirtualQuery section");
        RequireF(mbi.Protect == SectionProtection(c.pp.sec[i].Characteristics), "section %s protection %#lx", SectionName(c.pp, c.pp.sec[i].VirtualAddress).c_str(),
                 static_cast<unsigned long>(mbi.Protect));
        Require(mbi.AllocationBase == m.base, "every section shares AllocationBase == imageBase");
    }
    if (c.hasAppended) {
        Require(rep.sections_mapped == c.pp.nsec - c.sp.nsec && rep.section_bytes == c.pp.soi - c.sp.soi, "section accounting");
        Require(rep.proof_site_va && rep.proof_target_va >= base + c.sp.soi && rep.proof_target_va < base + c.pp.soi, "trampoline proof site");
        Require(std::memcmp(m.base + (rep.proof_site_va - base), rep.proof_site_bytes, 5) == 0, "trampoline proof bytes live");
        Require(std::memcmp(m.base + (rep.proof_section_va - base), rep.proof_section_bytes, 8) == 0, "section proof bytes live");
    }
    if (rep.fixups_stock_unrelocated + rep.fixups_patched_relocated) *unrelocatedWindowSeen = true;
    Unmap(&m);
}

static void RunNegatives(const Case& c, uint32_t base) {
    // 1. Occupied appended range: refused before any write, image untouched.
    if (c.hasAppended) {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (occupied)");
        void* blocker = VirtualAlloc(m.base + AlignUp(c.sp.soi, 0x10000), 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Require(blocker != nullptr, "place blocker page inside the appended range");
        Bytes before(m.base, m.base + c.sp.soi);
        ntw2_gp_report rep;
        ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
        int rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep);
        Require(rc == NTW2_GP_E_ALLOC && rep.phase == 0, "occupied appended range is refused with E_ALLOC before writing");
        Require(std::memcmp(before.data(), m.base, c.sp.soi) == 0, "occupied range: stock image untouched");
        std::printf("  negative: occupied range -> %s\n", rep.error);
        VirtualFree(blocker, 0, MEM_RELEASE);
        Unmap(&m);
    }
    // 2. Tampered stock byte (first byte of the first non-header run's site): E_STOCK, nothing written.
    {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (tamper)");
        ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
        // Tamper with the first stock byte the patch changes above the header (found by diffing the two files).
        uint32_t firstCode = 0;
        const uint32_t common = static_cast<uint32_t>(std::min(c.stock.size(), c.patched.size()));
        for (uint32_t i = c.sp.soh; i < common; ++i)
            if (c.stock[i] != c.patched[i]) { firstCode = i; break; }
        Require(firstCode != 0, "stock and patched files differ above the header");
        uint32_t rva = 0;
        for (uint32_t i = 0; i < c.sp.nsec; ++i)
            if (firstCode >= c.sp.sec[i].PointerToRawData && firstCode < c.sp.sec[i].PointerToRawData + c.sp.sec[i].SizeOfRawData)
                rva = c.sp.sec[i].VirtualAddress + (firstCode - c.sp.sec[i].PointerToRawData);
        Require(rva != 0, "first differing file offset maps to a stock section");
        DWORD old;
        VirtualProtect(m.base + rva, 1, PAGE_EXECUTE_READWRITE, &old);
        m.base[rva] ^= 0x5A;
        Bytes before(m.base, m.base + c.sp.soi);
        ntw2_gp_report rep;
        int rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep);
        Require(rc == NTW2_GP_E_STOCK && rep.phase == 0, "tampered stock byte is refused with E_STOCK before writing");
        Require(rep.fail_va == base + rva, "failure names the tampered address");
        Require(std::memcmp(before.data(), m.base, c.sp.soi) == 0, "tamper: image untouched");
        std::printf("  negative: tampered byte -> %s\n", rep.error);
        Unmap(&m);
    }
    // 3. Wrong preferred base: every fixup-bearing run mismatches (or, without any, the identity result still holds).
    {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (wrong delta)");
        Bytes before(m.base, m.base + c.sp.soi);
        ntw2_gp_report rep;
        ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
        int rc = ntw2_gp_apply(&mem, base, c.sp.base + 0x10000, c.blob, c.blobSize, &rep);
        if (rep.fixups_stock_unrelocated + rep.fixups_patched_relocated != 0 || rc != 0) {
            Require(rc == NTW2_GP_E_STOCK && rep.phase == 0, "a wrong relocation delta is refused with E_STOCK before writing");
            Require(std::memcmp(before.data(), m.base, c.sp.soi) == 0, "wrong delta: image untouched");
            std::printf("  negative: wrong delta -> %s\n", rep.error);
        } else {
            std::printf("  negative: wrong delta -> no run touches a relocation, nothing to refuse (identity already proven)\n");
        }
        Unmap(&m);
    }
    // 4. Non-PE target.
    {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (garbage header)");
        DWORD old;
        VirtualProtect(m.base, 0x1000, PAGE_READWRITE, &old);
        m.base[0] = 'X';
        ntw2_gp_report rep;
        ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
        Require(ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep) == NTW2_GP_E_HEADER, "a non-PE target is refused with E_HEADER");
        Unmap(&m);
    }
}

// An already-patched image is not a valid input: applying twice must refuse.
static void RunDoubleApply(const Case& c, uint32_t base) {
    Mapping m;
    Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (double apply)");
    ntw2_gp_report rep;
    ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
    Require(ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep) == 0, "first apply");
    Bytes after(m.base, m.base + c.pp.soi);
    ntw2_gp_report again;
    int rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &again);
    Require(rc != 0, "second apply on the patched image must refuse");
    // The refusal happens in verification (header/run mismatch) or on the now-occupied appended range; never after a write.
    Require(again.runs_applied == 0, "second apply wrote nothing");
    Require(std::memcmp(after.data(), m.base, c.pp.soi) == 0, "second apply left the patched image intact");
    std::printf("  negative: double apply -> %s\n", again.error);
    Unmap(&m);
}

// ---------------------------------------------------------------------------------------------------- real suspended process
typedef LONG(NTAPI* NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static uint32_t Peb32ImageBase(HANDLE process) {
    auto nq = reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    Require(nq != nullptr, "NtQueryInformationProcess");
    ULONG_PTR peb = 0;
    ULONG got = 0;
    if (nq(process, 26 /* ProcessWow64Information */, &peb, sizeof peb, &got) != 0 || peb == 0) {
        struct { PVOID exit, peb, aff, prio, pid, ppid; } pbi = {};
        Require(nq(process, 0, &pbi, sizeof pbi, &got) == 0, "ProcessBasicInformation");
        peb = reinterpret_cast<ULONG_PTR>(pbi.peb);
    }
    uint32_t imageBase = 0;
    SIZE_T rd = 0;
    Require(ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb + 8), &imageBase, 4, &rd) && rd == 4, "read PEB.ImageBaseAddress");
    return imageBase;
}

static void RunProcess(const Case& c, const char* exePath) {
    char dir[MAX_PATH];
    std::strncpy(dir, exePath, sizeof dir);
    dir[sizeof dir - 1] = 0;
    char* slash = std::strrchr(dir, '\\');
    if (!slash) slash = std::strrchr(dir, '/');
    if (slash) *slash = 0;
    char cmd[MAX_PATH + 4];
    std::snprintf(cmd, sizeof cmd, "\"%s\"", exePath);
    STARTUPINFOA si = {};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi = {};
    ntw2_gp_report rep;
    uint32_t base = 0;
    int rc = -1;
    // About a quarter of fresh processes have an early private allocation inside the 40 KiB range above the image (observed
    // at 0x2420000 for base 0xF30000); the applier refuses those with E_ALLOC before writing, and the launcher retries with a
    // new process.  Model exactly that.
    int attempts = 0;
    for (; attempts < 16; ++attempts) {
        pi = {};
        Require(CreateProcessA(exePath, cmd, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, dir, &si, &pi) != 0, "CreateProcess(CREATE_SUSPENDED) of the stock game");
        base = Peb32ImageBase(pi.hProcess);
        ntw2_gp_memory mem = ntw2_gp_process_memory(pi.hProcess);
        rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep);
        if (rc == NTW2_GP_E_ALLOC && rep.phase == 0) {
            std::printf("  attempt %d: range above the image is busy in this process (%s); new process\n", attempts + 1, rep.error);
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            continue;
        }
        break;
    }
    std::printf("  suspended process pid %lu, image base %#010x (preferred %#010x, delta %+d), %d attempt(s)\n", pi.dwProcessId, base, c.sp.base,
                static_cast<int>(base - c.sp.base), attempts + 1);
    if (rc != 0) std::fprintf(stderr, "  process apply failed: status %u phase %u: %s (run %u va %#x)\n", rep.status, rep.phase, rep.error, rep.fail_run, rep.fail_va);
    if (rc != 0) TerminateProcess(pi.hProcess, 1);
    Require(rc == 0, "ntw2_gp_apply on the suspended real process");
    ReportLine("suspended game process", rep);
    Bytes live(c.pp.soi);
    uint32_t done = 0;
    while (done < live.size()) {
        const uint32_t n = std::min<uint32_t>(1u << 20, static_cast<uint32_t>(live.size()) - done);
        SIZE_T rd = 0;
        if (!ReadProcessMemory(pi.hProcess, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(base) + done), live.data() + done, n, &rd) || rd != n) {
            std::fprintf(stderr, "  read of the live image failed at rva %#x (error %lu)\n", done, GetLastError());
            TerminateProcess(pi.hProcess, 1);
            Require(false, "read the live image");
        }
        done += n;
    }
    Bytes patchedImage = LoaderImage(c.patched, base, "patched");
    Bytes stockImage = LoaderImage(c.stock, base, "stock");
    // The kernel may or may not rewrite OptionalHeader.ImageBase of a relocated image; either value is the loader's output.
    const uint64_t bad = CompareImage("process", live.data(), patchedImage, stockImage, c.pp, c.sp, true);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    RequireF(bad == 0, "live game image differs from the loader-equivalent patched image (%llu bytes)", static_cast<unsigned long long>(bad));
    std::printf("  live game image == loader image of the patched file over [0x0, %#x) (every section + patched PE header)\n", c.pp.soi);
}

// ---------------------------------------------------------------------------------------------------- driver
// ---------------------------------------------------------------------------------------------------- rollback of a live module
// Fault-injecting memory backend over the current process: fails or silently corrupts the Nth write.
struct FaultMem {
    ntw2_gp_memory inner;
    int mode;      // 0 pass, 1 fail only write N, 2 fail every write from N on, 3 corrupt write N (reports success)
    uint32_t n;
    uint32_t writes;
};
static int FmRead(void* c, uint32_t va, void* d, uint32_t n) { auto f = static_cast<FaultMem*>(c); return f->inner.read(f->inner.ctx, va, d, n); }
static int FmWrite(void* c, uint32_t va, const void* s, uint32_t n) {
    auto f = static_cast<FaultMem*>(c);
    const uint32_t w = ++f->writes;
    if ((f->mode == 1 && w == f->n) || (f->mode == 2 && w >= f->n)) return 1;
    if (f->mode == 3 && w == f->n) {
        Bytes bad(static_cast<const uint8_t*>(s), static_cast<const uint8_t*>(s) + n);
        bad[0] ^= 0xFF;
        return f->inner.write(f->inner.ctx, va, bad.data(), n);
    }
    return f->inner.write(f->inner.ctx, va, s, n);
}
static int FmRemalloc(void* c, uint32_t va, uint32_t o, uint32_t n) { auto f = static_cast<FaultMem*>(c); return f->inner.remalloc(f->inner.ctx, va, o, n); }
static int FmProtect(void* c, uint32_t va, uint32_t s, uint32_t p) { auto f = static_cast<FaultMem*>(c); return f->inner.protect(f->inner.ctx, va, s, p); }

static void RunRollback(const Case& c, uint32_t base) {
    struct Inj { const char* name; int mode; uint32_t n; bool expectRestored; };
    const Inj cases[] = {{"second write fails", 1, 2, true}, {"first write fails", 1, 1, true}, {"first write silently corrupted (read-back)", 3, 1, true},
                         {"last write silently corrupted (read-back)", 3, 2, true}, {"write fails and so does the restore", 2, 2, false}};
    for (const Inj& inj : cases) {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock (rollback)");
        Bytes before(m.base, m.base + c.sp.soi);
        FaultMem fm = {ntw2_gp_process_memory(GetCurrentProcess()), inj.mode, inj.n, 0};
        ntw2_gp_memory mem = {&fm, FmRead, FmWrite, FmRemalloc, FmProtect};
        ntw2_gp_report rep;
        int rc = ntw2_gp_apply(&mem, base, c.sp.base, c.blob, c.blobSize, &rep);
        RequireF(rc != 0, "%s: apply must fail", inj.name);
        std::printf("  rollback: %s -> status %u, rollback %u: %s\n", inj.name, rep.status, rep.rollback, rep.error);
        if (inj.expectRestored) {
            Require(rep.rollback == NTW2_GP_ROLLBACK_RESTORED, "failed write/verify of a live module is rolled back");
            Require(std::memcmp(before.data(), m.base, c.sp.soi) == 0, "rollback left the stock image byte-identical");
            // The restored module can be patched again, and then equals the loader image of the patched file.
            ntw2_gp_report again;
            ntw2_gp_memory real = ntw2_gp_process_memory(GetCurrentProcess());
            Require(ntw2_gp_apply(&real, base, c.sp.base, c.blob, c.blobSize, &again) == 0, "re-apply after rollback");
            Bytes want = LoaderImage(c.patched, base, "patched");
            Bytes stockImage = LoaderImage(c.stock, base, "stock");
            Require(CompareImage("after rollback", m.base, want, stockImage, c.pp, c.sp, false) == 0, "re-applied image equals the patched loader image");
        } else {
            Require(rep.rollback == NTW2_GP_ROLLBACK_FAILED, "a failed restore is reported as ROLLBACK_FAILED");
        }
        Unmap(&m);
    }
}

static const char* Arg(int argc, char** argv, const char* key) {
    for (int i = 1; i + 1 < argc; ++i)
        if (!std::strcmp(argv[i], key)) return argv[i + 1];
    return nullptr;
}

static void CheckBlob(const char* name, const uint8_t* blob, uint32_t size, const Bytes& stock, const Bytes& patched) {
    ntw2_gp_blob_info info;
    Require(ntw2_gp_blob_describe(blob, size, &info) == 0, "embedded blob parses");
    RequireF(Sha256Hex(stock) == info.stock_sha256, "%s: stock file is not the blob's stock image", name);
    RequireF(Sha256Hex(patched) == info.patched_sha256, "%s: patched file is not the blob's patched image", name);
    RequireF(info.stock_len == stock.size() && info.patched_len == patched.size(), "%s: blob lengths match the files", name);
    std::printf("%s: blob %u bytes, %u runs, +%llu appended bytes, stock %.12s.. -> patched %.12s..\n", name, size, info.runs,
                static_cast<unsigned long long>(info.appended_bytes), info.stock_sha256, info.patched_sha256);
}

// Diagnostic bisection (--gameplay-patch-only-runs / --gameplay-patch-skip-runs): the filter only decides which non-header runs reach the live image.
//   ONLY={}  : no code run is written: the image is the stock loader image with the patched header and the appended sections;
//   SKIP={44,48}: the two relocated-operand runs (RVA 0x43C70C / 0x43F2F1) stay stock, every other byte is the loader-equivalent patched image;
//   launcher default (ntw2_gp_filter_exclude_d3d9_swap on ALL): exactly the rel32 fields of the two Direct3DCreate9 calls (RVA 0xCA6203 / 0xDFD3FF,
//   4 bytes after the E8 opcode) stay stock, every other byte is the loader-equivalent patched image.
static void RunFilter(const Case& c, uint32_t base) {
    ntw2_gp_filter parsed;
    std::memset(&parsed, 0, sizeof parsed);
    Require(ntw2_gp_filter_parse("14-16,36,44", &parsed) == 0, "filter list parses");
    Require((parsed.runs[0] & (7u << 14)) == (7u << 14) && (parsed.runs[1] & (1u << 4)) && (parsed.runs[1] & (1u << 12)) && !(parsed.runs[0] & (1u << 17)) && !(parsed.runs[0] & (1u << 13)),
            "filter bits: 14-16, 36, 44");
    const char* bad[] = {"", "x", "1-", "-3", "5-2", "3,,4", "3,", "128", "1 2"};
    for (const char* s : bad) { ntw2_gp_filter f; std::memset(&f, 0, sizeof f); RequireF(ntw2_gp_filter_parse(s, &f) != 0, "malformed run list \"%s\" refused", s); }
    {
        const uint32_t d3dA = 1u << (NTW2_GP_RUN_D3D9_FACTORY_A & 31u), d3dB = 1u << (NTW2_GP_RUN_D3D9_FACTORY_B & 31u);
        ntw2_gp_filter skip, only;
        std::memset(&skip, 0, sizeof skip); std::memset(&only, 0, sizeof only);
        skip.mode = NTW2_GP_SKIP; Require(ntw2_gp_filter_parse("44", &skip) == 0, "skip list parses");
        only.mode = NTW2_GP_ONLY; Require(ntw2_gp_filter_parse("14,65,92", &only) == 0, "only list parses");
        ntw2_gp_filter_exclude_d3d9_swap(&skip);
        ntw2_gp_filter_exclude_d3d9_swap(&only);
        Require(skip.mode == NTW2_GP_SKIP && (skip.runs[1] & (1u << 12)) && (skip.runs[2] & d3dA) && (skip.runs[2] & d3dB), "exclude keeps a SKIP list and adds 65, 92");
        Require(only.mode == NTW2_GP_ONLY && (only.runs[0] & (1u << 14)) && !(only.runs[2] & d3dA) && !(only.runs[2] & d3dB), "exclude keeps an ONLY list without 65, 92");
    }

    Bytes patchedImage = LoaderImage(c.patched, base, "patched");
    Bytes stockImage = LoaderImage(c.stock, base, "stock");
    const uint32_t windows[2] = {0x43C70Cu, 0x43F2F1u};
    const uint32_t d3dSites[2] = {0xCA6203u, 0xDFD3FFu};
    const char* names[3] = {"ONLY={}", "SKIP={44,48}", "default"};
    for (int variant = 0; variant < 3; ++variant) {
        Mapping m;
        Require(MapStock(c.stock, c.sp, c.pp, base, &m), "map stock image (filter)");
        ntw2_gp_filter f;
        std::memset(&f, 0, sizeof f);
        if (variant == 0) f.mode = NTW2_GP_ONLY;
        else if (variant == 1) { f.mode = NTW2_GP_SKIP; Require(ntw2_gp_filter_parse("44,48", &f) == 0, "skip list parses"); }
        else ntw2_gp_filter_exclude_d3d9_swap(&f);
        if (variant == 2)
            for (uint32_t s : d3dSites)
                RequireF(std::memcmp(&stockImage[s], &patchedImage[s], 4) != 0 && patchedImage[s - 1] == 0xE8u && stockImage[s - 1] == 0xE8u,
                         "D3D9 swap site %#x is the rel32 of a patched call", s);
        ntw2_gp_report rep;
        ntw2_gp_memory mem = ntw2_gp_process_memory(GetCurrentProcess());
        Require(ntw2_gp_apply_filtered(&mem, base, c.sp.base, c.blob, c.blobSize, &f, &rep) == 0, "filtered apply");
        Require(rep.status == NTW2_GP_OK && rep.phase == 1, "filtered report status");
        const uint32_t soh = c.pp.soh;
        uint64_t bad = 0, stockWindowBytes = 0;
        for (uint32_t i = 0; i < c.pp.soi; ++i) {
            uint8_t want = patchedImage[i];
            if (variant == 0) {
                if (i >= soh && i < c.sp.soi) want = stockImage[i];
            } else if (variant == 1) {
                for (uint32_t w : windows)
                    if (i >= w && i < w + 8u && m.base[i] == stockImage[i] && m.base[i] != patchedImage[i]) { want = stockImage[i]; ++stockWindowBytes; }
            } else {
                for (uint32_t s : d3dSites)
                    if (i >= s && i < s + 4u) { want = stockImage[i]; if (stockImage[i] != patchedImage[i]) ++stockWindowBytes; }
            }
            if (m.base[i] != want) {
                if (bad < 6) std::fprintf(stderr, "  filter variant %d mismatch rva %#x: live %02x want %02x\n", variant, i, m.base[i], want);
                ++bad;
            }
        }
        RequireF(bad == 0, "filter variant %d: live image differs from its expectation (%llu bytes)", variant, static_cast<unsigned long long>(bad));
        if (variant == 0) {
            Require(rep.runs_applied == 0 && rep.runs_skipped == rep.runs_total - rep.runs_header && rep.runs_skipped > 90, "ONLY={} writes no run");
            Require(rep.sections_mapped == c.pp.nsec - c.sp.nsec, "ONLY={} still maps the appended sections");
        } else if (variant == 1) {
            Require(rep.runs_skipped == 2 && rep.runs_applied + rep.runs_skipped + rep.runs_header == rep.runs_total, "SKIP={44,48} skips exactly two runs");
            Require(stockWindowBytes >= 2, "the two skipped runs stay stock in the live image");
        } else {
            Require(rep.runs_skipped == 2 && rep.runs_applied + rep.runs_skipped + rep.runs_header == rep.runs_total, "default skips exactly the two D3D9 runs");
            Require(stockWindowBytes >= 2, "both Direct3DCreate9 call sites stay stock in the live image");
        }
        std::printf("  filter %-12s applied %u skipped %u header %u: live image matches its expectation over [0, %#x)\n", names[variant],
                    rep.runs_applied, rep.runs_skipped, rep.runs_header, c.pp.soi);
        Unmap(&m);
    }
}

int main(int argc, char** argv) {
    const char* patchedPath = Arg(argc, argv, "--patched");
    const char* stockPath = Arg(argc, argv, "--stock");
    if (!patchedPath || !stockPath) {
        std::fprintf(stderr, "usage: native_gameplay_patch_oracle --patched Napoleon_patched.exe --stock Napoleon.exe [--mss32-patched F --mss32-stock F] [--process]\n");
        return 2;
    }
    uint32_t blobSize = 0;
    const uint8_t* blob = ntw2_gp_napoleon_blob(&blobSize);
    Bytes stock = ReadAll(stockPath), patched = ReadAll(patchedPath);
    CheckBlob("napoleon", blob, blobSize, stock, patched);
    RequireF(Sha256Hex(patched) == NTW2_IMAGE_SHA256, "%s: the patched image is not NTW2_IMAGE_SHA256", "napoleon");
    Case nap = MakeCase("napoleon", blob, blobSize, stock, patched);

    // Bases: the preferred base (delta 0) when free, plus relocated bases with distinct deltas.
    const uint32_t candidates[] = {0x00400000u, 0x10000000u, 0x2A5B0000u, 0x5E170000u, 0x6E7A0000u};
    uint32_t used = 0, firstNonZero = 0;
    bool delta0 = false, windowSeen = false;
    for (uint32_t base : candidates) {
        Mapping probe;
        if (!MapStock(nap.stock, nap.sp, nap.pp, base, &probe)) { std::printf("  base %#010x not free in this process; skipped\n", base); continue; }
        Unmap(&probe);
        RunPrivate(nap, base, &windowSeen);
        ++used;
        if (base == nap.sp.base) delta0 = true; else if (!firstNonZero) firstNonZero = base;
    }
    Require(used >= 2 && firstNonZero != 0, "at least two bases (one relocated) were exercised");
    std::printf("napoleon: %u private bases verified byte-identical%s\n", used, delta0 ? " (incl. delta 0)" : " (delta 0 base not free here)");
    Require(windowSeen, "at least one patch run overlaps a relocation fixup (the relocation arithmetic was exercised)");
    RunNegatives(nap, firstNonZero);
    RunDoubleApply(nap, firstNonZero);
    RunFilter(nap, firstNonZero);

    const char* mp = Arg(argc, argv, "--mss32-patched");
    const char* ms = Arg(argc, argv, "--mss32-stock");
    if (mp && ms) {
        uint32_t msize = 0;
        const uint8_t* mblob = ntw2_gp_mss32_blob(&msize);
        Bytes mstock = ReadAll(ms), mpatched = ReadAll(mp);
        CheckBlob("mss32", mblob, msize, mstock, mpatched);
        Case mss = MakeCase("mss32", mblob, msize, mstock, mpatched);
        uint32_t mused = 0;
        bool mseen = false;
        uint32_t mssBase = 0;
        for (uint32_t base : {mss.sp.base, 0x20000000u, 0x4C310000u, 0x3A720000u}) {
            Mapping probe;
            if (!MapStock(mss.stock, mss.sp, mss.pp, base, &probe)) { std::printf("  base %#010x not free in this process; skipped\n", base); continue; }
            Unmap(&probe);
            RunPrivate(mss, base, &mseen);
            ++mused;
            if (base != mss.sp.base && !mssBase) mssBase = base;
        }
        Require(mused >= 2 && mssBase != 0, "mss32 verified at two bases (one relocated)");
        RunNegatives(mss, mssBase);
        RunDoubleApply(mss, mssBase);
        RunRollback(mss, mssBase);
    }

    for (int i = 1; i < argc; ++i)
        if (!std::strcmp(argv[i], "--process")) { RunProcess(nap, stockPath); break; }
    std::printf("native_gameplay_patch_oracle: OK (%u checks)\n", g_checks);
    return 0;
}
