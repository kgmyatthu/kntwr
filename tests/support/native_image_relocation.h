#pragma once
#include <windows.h>
#include <cstdint>

// For owned x86 native-code oracles only. Apply the pinned PE's loader relocations;
// never interpret data bytes as addresses or patch a live process.
inline bool RelocateNativeImage(uint8_t* image, SIZE_T size,
                               const IMAGE_NT_HEADERS32* headers, uintptr_t delta) {
    if (delta == 0) return true;
    const auto reloc = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc.Size == 0 || reloc.VirtualAddress > size || reloc.Size > size - reloc.VirtualAddress) return false;
    DWORD cursor = 0;
    while (cursor < reloc.Size) {
        if (reloc.Size - cursor < sizeof(IMAGE_BASE_RELOCATION)) return false;
        auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + reloc.VirtualAddress + cursor);
        if (block->SizeOfBlock < sizeof(*block) || block->SizeOfBlock > reloc.Size - cursor
            || (block->SizeOfBlock - sizeof(*block)) % sizeof(WORD) != 0) return false;
        const auto entries = reinterpret_cast<const WORD*>(block + 1);
        const size_t count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
        for (size_t i = 0; i < count; ++i) {
            const unsigned type = entries[i] >> 12;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_HIGHLOW) return false;
            const uint64_t rva = static_cast<uint64_t>(block->VirtualAddress) + (entries[i] & 0xfff);
            if (rva + sizeof(uint32_t) > size) return false;
            auto field = reinterpret_cast<uint32_t*>(image + static_cast<size_t>(rva));
            *field += static_cast<uint32_t>(delta);
        }
        cursor += block->SizeOfBlock;
    }
    return true;
}
