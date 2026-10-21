/* kntwr_pe_audit: structural audit of a built PE32 (x86) module.  Build/test-time only; it never loads or runs the module.
 *
 *   kntwr_pe_audit <module.dll> [--no-imports] [--no-entry] [--no-code-relocs] [--export NAME]...
 *
 *   --no-imports      import and delay-import directories must be empty (import-free payload).
 *   --no-entry        the image has no entry point (linked /NOENTRY).
 *   --no-code-relocs  no base relocation may land in an executable/code section: the code bytes are position
 *                     independent and may be copied verbatim into an owned allocation.
 *   --export NAME     the export table must contain NAME (undecorated, exact); repeatable.
 *
 * Exit 0 only when the image is PE32/I386 and every requested property holds; every failure is printed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_REQUIRED_EXPORTS 128

static const unsigned char* g_file;
static size_t g_size;
static const IMAGE_NT_HEADERS32* g_nt;
static const IMAGE_SECTION_HEADER* g_sections;
static unsigned g_failures;

static void fail(const char* what) {
    fprintf(stderr, "AUDIT FAIL: %s\n", what);
    ++g_failures;
}

static const IMAGE_SECTION_HEADER* section_of_rva(uint32_t rva) {
    for (unsigned i = 0; i < g_nt->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER* s = &g_sections[i];
        uint32_t span = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva - s->VirtualAddress < span) return s;
    }
    return NULL;
}

/* File pointer for an RVA that must be backed by raw data; NULL when the span is not fully in the file. */
static const unsigned char* file_at(uint32_t rva, uint32_t length) {
    const IMAGE_SECTION_HEADER* s = section_of_rva(rva);
    if (!s) return NULL;
    uint32_t delta = rva - s->VirtualAddress;
    if (delta >= s->SizeOfRawData || length > s->SizeOfRawData - delta) return NULL;
    uint64_t offset = (uint64_t)s->PointerToRawData + delta;
    if (offset > g_size || length > g_size - offset) return NULL;
    return g_file + offset;
}

static int is_code(const IMAGE_SECTION_HEADER* s) {
    return (s->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0;
}

static unsigned char* read_all(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    unsigned char* data = (unsigned char*)malloc((size_t)n);
    if (!data || fread(data, 1, (size_t)n, f) != (size_t)n) { free(data); fclose(f); return NULL; }
    fclose(f);
    *size = (size_t)n;
    return data;
}

int main(int argc, char** argv) {
    const char* path = NULL;
    int no_imports = 0, no_entry = 0, no_code_relocs = 0;
    const char* required[MAX_REQUIRED_EXPORTS];
    unsigned required_count = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--no-imports")) no_imports = 1;
        else if (!strcmp(argv[i], "--no-entry")) no_entry = 1;
        else if (!strcmp(argv[i], "--no-code-relocs")) no_code_relocs = 1;
        else if (!strcmp(argv[i], "--export") && i + 1 < argc) {
            if (required_count == MAX_REQUIRED_EXPORTS) { fprintf(stderr, "too many --export\n"); return 2; }
            required[required_count++] = argv[++i];
        } else if (argv[i][0] != '-' && !path) path = argv[i];
        else { fprintf(stderr, "bad argument: %s\n", argv[i]); return 2; }
    }
    if (!path) { fprintf(stderr, "usage: kntwr_pe_audit <module> [--no-imports] [--no-entry] [--no-code-relocs] [--export NAME]...\n"); return 2; }

    unsigned char* data = read_all(path, &g_size);
    if (!data) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    g_file = data;

    if (g_size < sizeof(IMAGE_DOS_HEADER) || ((const IMAGE_DOS_HEADER*)data)->e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "not a PE (MZ)\n"); return 2; }
    uint32_t nt_off = (uint32_t)((const IMAGE_DOS_HEADER*)data)->e_lfanew;
    if (nt_off > g_size || g_size - nt_off < sizeof(IMAGE_NT_HEADERS32)) { fprintf(stderr, "not a PE (NT headers)\n"); return 2; }
    g_nt = (const IMAGE_NT_HEADERS32*)(data + nt_off);
    if (g_nt->Signature != IMAGE_NT_SIGNATURE) { fprintf(stderr, "not a PE (signature)\n"); return 2; }
    if (g_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || g_nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) fail("image is not PE32/I386");
    g_sections = IMAGE_FIRST_SECTION(g_nt);
    if ((const unsigned char*)(g_sections + g_nt->FileHeader.NumberOfSections) > data + g_size) { fprintf(stderr, "section table outside file\n"); return 2; }

    const IMAGE_DATA_DIRECTORY* dir = g_nt->OptionalHeader.DataDirectory;
    printf("%s: PE32 sections=%u entry=0x%08X\n", path, (unsigned)g_nt->FileHeader.NumberOfSections,
           (unsigned)g_nt->OptionalHeader.AddressOfEntryPoint);

    if (no_imports) {
        if (dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || dir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) fail("import directory is not empty");
        if (dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress || dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size) fail("delay-import directory is not empty");
        if (dir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress || dir[IMAGE_DIRECTORY_ENTRY_IAT].Size) fail("IAT directory is not empty");
    }
    if (no_entry && g_nt->OptionalHeader.AddressOfEntryPoint != 0) fail("image has an entry point");

    /* base relocations */
    unsigned relocs = 0, code_relocs = 0;
    const IMAGE_DATA_DIRECTORY rd = dir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rd.Size) {
        const unsigned char* base = file_at(rd.VirtualAddress, rd.Size);
        if (!base) fail("base relocation directory is not backed by file data");
        else {
            uint32_t cursor = 0;
            while (cursor < rd.Size) {
                if (rd.Size - cursor < sizeof(IMAGE_BASE_RELOCATION)) { fail("truncated relocation block header"); break; }
                const IMAGE_BASE_RELOCATION* b = (const IMAGE_BASE_RELOCATION*)(base + cursor);
                if (b->SizeOfBlock < sizeof(*b) || b->SizeOfBlock > rd.Size - cursor) { fail("bad relocation block size"); break; }
                const uint16_t* e = (const uint16_t*)(b + 1);
                uint32_t count = (b->SizeOfBlock - (uint32_t)sizeof(*b)) / 2;
                for (uint32_t k = 0; k < count; ++k) {
                    unsigned type = e[k] >> 12;
                    if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                    ++relocs;
                    uint32_t rva = b->VirtualAddress + (e[k] & 0xFFFu);
                    const IMAGE_SECTION_HEADER* s = section_of_rva(rva);
                    if (s && is_code(s)) {
                        if (++code_relocs <= 8) fprintf(stderr, "  relocation at RVA 0x%08X lands in code section %.8s\n", (unsigned)rva, (const char*)s->Name);
                    }
                }
                cursor += b->SizeOfBlock;
            }
        }
    }
    printf("relocations=%u in_code=%u\n", relocs, code_relocs);
    if (no_code_relocs && code_relocs) fail("base relocations land in executable code (code is not position independent)");

    /* exports */
    const IMAGE_DATA_DIRECTORY ed = dir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    unsigned char found[MAX_REQUIRED_EXPORTS] = {0};
    if (ed.Size) {
        const IMAGE_EXPORT_DIRECTORY* ex = (const IMAGE_EXPORT_DIRECTORY*)file_at(ed.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
        const uint32_t* names = ex ? (const uint32_t*)file_at(ex->AddressOfNames, ex->NumberOfNames * 4u) : NULL;
        if (!ex || (ex->NumberOfNames && !names)) fail("export directory is unreadable");
        else {
            printf("exports=%u named=%u\n", (unsigned)ex->NumberOfFunctions, (unsigned)ex->NumberOfNames);
            for (uint32_t i = 0; i < ex->NumberOfNames; ++i) {
                const char* n = (const char*)file_at(names[i], 1);
                if (!n) { fail("export name outside file"); continue; }
                printf("  export %s\n", n);
                for (unsigned r = 0; r < required_count; ++r) if (!strcmp(n, required[r])) found[r] = 1;
            }
        }
    }
    for (unsigned r = 0; r < required_count; ++r) {
        if (!found[r]) { fprintf(stderr, "AUDIT FAIL: missing export %s\n", required[r]); ++g_failures; }
    }

    free(data);
    if (g_failures) { fprintf(stderr, "AUDIT FAILED (%u)\n", g_failures); return 1; }
    printf("AUDIT PASS\n");
    return 0;
}
