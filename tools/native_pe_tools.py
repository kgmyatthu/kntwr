"""Small-memory PE32 metadata and incremental x86 analysis (development only)."""
from array import array
from contextlib import closing
import struct


def decode_highlow_relocations(data, image_size, base=0):
    """Return sorted unique HIGHLOW addresses without pefile's per-entry objects."""
    values = array('I')
    pos = 0
    view = memoryview(data)
    while pos < len(view):
        if len(view) - pos < 8:
            raise ValueError('truncated relocation block header')
        page, size = struct.unpack_from('<II', view, pos)
        if size < 8 or size % 2 or size > len(view) - pos:
            raise ValueError('invalid relocation block extent')
        if page >= image_size:
            raise ValueError('relocation page outside image')
        for (word,) in struct.iter_unpack('<H', view[pos + 8:pos + size]):
            kind, offset = word >> 12, word & 0xfff
            if kind == 0:
                continue
            if kind != 3:
                raise ValueError(f'unsupported relocation type {kind}')
            rva = page + offset
            if rva + 4 > image_size or not 0 <= base + rva <= 0xffffffff:
                raise ValueError('relocation outside PE32 image')
            values.append(base + rva)
        pos += size
    # The pinned file is normally ordered. Avoid an intermediate Python-int list
    # unless an input actually needs sorting, then deduplicate in place.
    if any(values[i] < values[i - 1] for i in range(1, len(values))):
        values = array('I', sorted(values))
    used = 0
    for value in values:
        if used == 0 or value != values[used - 1]:
            values[used] = value
            used += 1
    del values[used:]
    return values


def highlow_relocations(pe, base=0):
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    if not directory.Size:
        return array('I')
    data = pe.get_data(directory.VirtualAddress, directory.Size)
    if len(data) != directory.Size:
        raise ValueError('truncated relocation directory')
    return decode_highlow_relocations(data, pe.OPTIONAL_HEADER.SizeOfImage, base)


def iter_instructions(engine, read, address, size, count=0):
    """Detailed disassembly with <=256 native instructions allocated at once.

    Capstone's Python generator calls eager cs_disasm. Limit the native count,
    not just Python iteration. A window fits 256 maximum-length x86 instructions,
    so an internal boundary never truncates an instruction. Stop at invalid bytes
    exactly as a single disasm call would; the caller chooses whether to skip them.
    """
    if size < 0 or count < 0:
        raise ValueError('negative disassembly extent/count')
    end = address + size
    emitted = 0
    while address < end and (not count or emitted < count):
        take = min(256, count - emitted) if count else 256
        code = read(address, min(end - address, take * 15))
        decoded = 0
        with closing(engine.disasm(code, address, take)) as instructions:
            for instruction in instructions:
                address = instruction.address + instruction.size
                decoded += 1
                emitted += 1
                yield instruction
        if decoded < take:
            return
