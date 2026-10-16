#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#ifndef _M_IX86
#error This smoke harness must execute as x86.
#endif

struct Vec3 { uint32_t bits[3]; };
struct Owner { unsigned char unused[0x25c]; Vec3* data; LONG count; };
struct Batch { Owner* owner; uint32_t count; Vec3 data[64]; };
static_assert(offsetof(Owner, data) == 0x25c && offsetof(Owner, count) == 0x260);
static_assert(sizeof(Batch) == 776 && sizeof(Vec3) == 12);

// Reproduce the cloned callee's seventh argument position, not the game itself.
__declspec(naked) static void __stdcall invoke_append(void*, Owner*, const Vec3*, Batch*) {
    __asm {
        push ebp
        mov ebp, esp
        sub esp, 0a8h
        mov eax, [ebp + 20]
        mov [esp + 0a4h], eax
        mov ecx, [ebp + 12]
        mov eax, [ebp + 16]
        push eax
        call DWORD PTR [ebp + 8]
        mov esp, ebp
        pop ebp
        ret 16
    }
}
__declspec(naked) static void __stdcall invoke_flush(void*, Batch*) {
    __asm {
        mov ecx, [esp + 8]
        call DWORD PTR [esp + 4]
        ret 8
    }
}
static void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
static Vec3 value(uint32_t worker, uint32_t index) {
    return {{worker, index, 0x80000000u ^ (index * 0x9e3779b9u) ^ worker}};
}
static bool equal(const Vec3& a, const Vec3& b) { return std::memcmp(&a, &b, sizeof(a)) == 0; }

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    require(argc == 2, "usage: native_render_batch_smoke HELPER.dll");
    HMODULE module = LoadLibraryW(argv[1]);
    require(module != nullptr, "LoadLibraryW");
    auto* contract = reinterpret_cast<const uint32_t*>(GetProcAddress(module, "batch_contract"));
    auto* append = reinterpret_cast<unsigned char*>(GetProcAddress(module, "append_vec3"));
    auto* flush = reinterpret_cast<unsigned char*>(GetProcAddress(module, "flush_vec3"));
    require(contract && append && flush, "helper exports");
    require(contract[0] == 1 && contract[1] == 64 && contract[2] == sizeof(Batch) && contract[3] == 0xb0, "helper ABI");
    auto* image = reinterpret_cast<unsigned char*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew);
    auto* sections = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* text = nullptr;
    const auto appendRva = static_cast<uint32_t>(append - image);
    for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i) {
        if (appendRva >= sections[i].VirtualAddress && appendRva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) text = &sections[i];
    }
    require(text != nullptr, "helper code section");
    auto* code = static_cast<unsigned char*>(VirtualAlloc(nullptr, text->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(code != nullptr, "owned code allocation");
    std::memcpy(code, image + text->VirtualAddress, text->Misc.VirtualSize);
    DWORD previous;
    require(VirtualProtect(code, text->Misc.VirtualSize, PAGE_EXECUTE_READ, &previous) != 0, "owned RX protection");
    require(FlushInstructionCache(GetCurrentProcess(), code, text->Misc.VirtualSize) != 0, "owned instruction cache");
    void* appendCode = code + (append - image - text->VirtualAddress);
    void* flushCode = code + (flush - image - text->VirtualAddress);
    const Vec3 guard = {{0x7fc12345, 0x80000000, 0x7f800000}};
    constexpr unsigned prefix = 3;
    const unsigned lengths[] = {0, 1, 63, 64, 65, 127, 129};
    for (unsigned length : lengths) {
        std::vector<Vec3> storage(prefix + length + 2, guard);
        Owner owner{};
        owner.data = storage.data() + 1;
        owner.count = prefix;
        for (unsigned i = 0; i != prefix; ++i) owner.data[i] = value(99, i);
        Batch batch;
        batch.owner = &owner;
        batch.count = 0;
        for (unsigned i = 0; i != length; ++i) {
            const Vec3 input = value(1, i);
            invoke_append(appendCode, &owner, &input, &batch);
        }
        require(owner.count == static_cast<LONG>(prefix + length / 64 * 64), "full-batch reservation count");
        require(batch.count == length % 64, "partial batch count");
        invoke_flush(flushCode, &batch);
        require(owner.count == static_cast<LONG>(prefix + length) && batch.count == 0, "final flush count");
        for (unsigned i = 0; i != prefix; ++i) require(equal(owner.data[i], value(99, i)), "existing prefix preserved");
        for (unsigned i = 0; i != length; ++i) require(equal(owner.data[prefix + i], value(1, i)), "single-worker exact records and order");
        require(equal(storage.front(), guard) && equal(storage.back(), guard), "single-worker bounds");
    }
    constexpr unsigned workers = 12, perWorker = 4097, total = workers * perWorker;
    std::vector<Vec3> storage(prefix + total + 2, guard);
    Owner owner{};
    owner.data = storage.data() + 1;
    owner.count = prefix;
    for (unsigned i = 0; i != prefix; ++i) owner.data[i] = value(99, i);
    std::vector<std::thread> threads;
    threads.reserve(workers);
    std::barrier start(workers);
    for (unsigned worker = 1; worker <= workers; ++worker) {
        threads.emplace_back([&, worker] {
            Batch batch;
            batch.owner = &owner;
            batch.count = 0;
            start.arrive_and_wait();
            for (unsigned i = 0; i != perWorker; ++i) {
                const Vec3 input = value(worker, i);
                invoke_append(appendCode, &owner, &input, &batch);
            }
            invoke_flush(flushCode, &batch);
        });
    }
    for (auto& thread : threads) thread.join();
    require(owner.count == static_cast<LONG>(prefix + total), "concurrent total count");
    std::vector<unsigned> seen(total, 0);
    std::vector<int> last(workers, -1);
    for (unsigned i = 0; i != prefix; ++i) require(equal(owner.data[i], value(99, i)), "concurrent prefix preserved");
    for (unsigned i = 0; i != total; ++i) {
        const Vec3& actual = owner.data[prefix + i];
        const unsigned worker = actual.bits[0], index = actual.bits[1];
        require(worker >= 1 && worker <= workers && index < perWorker, "concurrent record domain");
        require(equal(actual, value(worker, index)), "concurrent exact bit patterns");
        require(++seen[(worker - 1) * perWorker + index] == 1, "no duplicate or overlapping reservations");
        require(static_cast<int>(index) > last[worker - 1], "per-worker order preserved");
        last[worker - 1] = static_cast<int>(index);
    }
    for (unsigned count : seen) require(count == 1, "no lost records");
    require(equal(storage.front(), guard) && equal(storage.back(), guard), "concurrent bounds");
    require(VirtualFree(code, 0, MEM_RELEASE) != 0, "owned code release after joins");
    FreeLibrary(module);
    std::printf("PASS: 7 batch boundaries; %u concurrent records on %u workers; prefix, exact bits, order and guards preserved; relocated x86 helpers executed.\n", total, workers);
    return 0;
}
