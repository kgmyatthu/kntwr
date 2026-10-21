#!/usr/bin/env python3
"""Apply / revert / inspect / embed an NTWPATCH binary patch (data/napoleon.ntwpatch, data/mss32.ntwpatch).

Build- and test-time tool.  The game files on disk stay STOCK: kntwr.exe applies the same patch in memory
(src/core/kntwr_gameplay_patch.c).  This script is the independent file-level implementation of the same format and is what
produces the pinned image every clone spec, oracle and Ghidra snapshot is built against.

NTWPATCH layout (little endian; documented in F:/NTW2/patcher/src/lib.rs):
    magic 'NTWPATCH'  version u32  stock_len u64  stock_sha256[32]  patched_len u64  patched_sha256[32]  run_count u32
    run_count x { file_offset u64, len u32, old[len], new[len] }
    old_tail_len u64, old_tail   (stock bytes past the shorter length)
    new_tail_len u64, new_tail   (patched bytes past the shorter length: the appended sections)
    checksum[32] = sha256 of everything above

Commands (default: generate):
    generate  stock Napoleon.exe + mss32.dll  ->  analysis/Napoleon_patched.exe + analysis/mss32_patched.dll
              (an input that is already the patched file is copied; anything else is refused)
    apply     --patch P --input STOCK --output OUT       verify stock sha, apply, verify patched sha, write OUT
    revert    --patch P --input PATCHED --output OUT     the inverse
    info      --patch P                                  header, hashes, run census, appended sections
    embed     [--check]   write (or compare) src/core/kntwr_gameplay_patch_data.inc from data/*.ntwpatch
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA = REPO / 'data'
DEFAULT_GAME_DIR = Path('E:/steam/steamapps/common/Napoleon Total War')
DEFAULT_OUT_DIR = Path('F:/NTW2/translated_code/analysis')
EMBED_PATH = REPO / 'src' / 'core' / 'kntwr_gameplay_patch_data.inc'

MAGIC = b'NTWPATCH'
VERSION = 1


class PatchError(Exception):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class Patch:
    def __init__(self, raw: bytes):
        if len(raw) < 32 + 8 + 4:
            raise PatchError('patch too short')
        body, checksum = raw[:-32], raw[-32:]
        if sha256(body) != checksum:
            raise PatchError('patch checksum mismatch')
        self.raw = raw
        pos = 0

        def take(n: int) -> bytes:
            nonlocal pos
            if pos + n > len(body):
                raise PatchError('patch truncated')
            out = body[pos:pos + n]
            pos += n
            return out

        if take(8) != MAGIC:
            raise PatchError('bad magic')
        version, = struct.unpack('<I', take(4))
        if version != VERSION:
            raise PatchError(f'unsupported version {version}')
        self.stock_len, = struct.unpack('<Q', take(8))
        self.stock_sha = take(32)
        self.patched_len, = struct.unpack('<Q', take(8))
        self.patched_sha = take(32)
        count, = struct.unpack('<I', take(4))
        common = min(self.stock_len, self.patched_len)
        self.runs: list[tuple[int, bytes, bytes]] = []
        prev_end = 0
        for _ in range(count):
            offset, length = struct.unpack('<QI', take(12))
            if length == 0 or offset < prev_end or offset + length > common:
                raise PatchError('run out of range')
            prev_end = offset + length
            self.runs.append((offset, take(length), take(length)))
        old_tail_len, = struct.unpack('<Q', take(8))
        self.old_tail = take(old_tail_len)
        new_tail_len, = struct.unpack('<Q', take(8))
        self.new_tail = take(new_tail_len)
        if pos != len(body) or common + len(self.old_tail) != self.stock_len or common + len(self.new_tail) != self.patched_len:
            raise PatchError('length mismatch')

    @classmethod
    def load(cls, path: Path) -> 'Patch':
        return cls(path.read_bytes())

    def _transform(self, data: bytes, in_sha: bytes, out_sha: bytes, forward: bool) -> bytes:
        actual = sha256(data)
        if actual != in_sha:
            raise PatchError(f'input sha256 {actual.hex()} is not the expected {"stock" if forward else "patched"} '
                             f'image {in_sha.hex()}')
        common = min(self.stock_len, self.patched_len)
        out = bytearray(data[:common])
        for offset, old, new in self.runs:
            src, dst = (old, new) if forward else (new, old)
            if bytes(out[offset:offset + len(dst)]) != src:
                raise PatchError(f'run at file offset {offset:#x} does not match the input')
            out[offset:offset + len(dst)] = dst
        out += self.new_tail if forward else self.old_tail
        if sha256(bytes(out)) != out_sha:
            raise PatchError('result sha256 mismatch')
        return bytes(out)

    def apply(self, stock: bytes) -> bytes:
        return self._transform(stock, self.stock_sha, self.patched_sha, True)

    def revert(self, patched: bytes) -> bytes:
        return self._transform(patched, self.patched_sha, self.stock_sha, False)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f'wrote {path} ({len(data)} bytes, sha256 {sha256(data).hex()})')


def cmd_apply(args, forward: bool = True) -> int:
    patch = Patch.load(Path(args.patch))
    data = Path(args.input).read_bytes()
    out = patch.apply(data) if forward else patch.revert(data)
    _write(Path(args.output), out)
    return 0


def cmd_revert(args) -> int:
    return cmd_apply(args, forward=False)


def _generate_one(patch_path: Path, stock_path: Path, out_path: Path) -> None:
    patch = Patch.load(patch_path)
    data = stock_path.read_bytes()
    actual = sha256(data)
    if actual == patch.patched_sha:
        print(f'{stock_path} is already the patched image')
        out = data
    else:
        out = patch.apply(data)
    _write(out_path, out)


def cmd_generate(args) -> int:
    game = Path(args.game_dir)
    out_dir = Path(args.out_dir)
    _generate_one(DATA / 'napoleon.ntwpatch', game / 'Napoleon.exe', out_dir / 'Napoleon_patched.exe')
    _generate_one(DATA / 'mss32.ntwpatch', game / 'mss32.dll', out_dir / 'mss32_patched.dll')
    return 0


def _sections(image: bytes):
    lfanew, = struct.unpack_from('<I', image, 0x3C)
    nsec, = struct.unpack_from('<H', image, lfanew + 6)
    opt_size, = struct.unpack_from('<H', image, lfanew + 20)
    table = lfanew + 24 + opt_size
    for i in range(nsec):
        base = table + 40 * i
        name = image[base:base + 8].rstrip(b'\0').decode('ascii', 'replace')
        vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', image, base + 8)
        flags, = struct.unpack_from('<I', image, base + 36)
        yield name, va, vsize, rawptr, rawsize, flags


def cmd_info(args) -> int:
    patch = Patch.load(Path(args.patch))
    print(f'stock   : {patch.stock_len} bytes  sha256 {patch.stock_sha.hex()}')
    print(f'patched : {patch.patched_len} bytes  sha256 {patch.patched_sha.hex()}')
    inside = sum(len(old) for _, old, _ in patch.runs)
    print(f'runs    : {len(patch.runs)}  ({inside} differing bytes inside the stock length)')
    print(f'tails   : old {len(patch.old_tail)} bytes, new {len(patch.new_tail)} bytes (appended sections)')
    if args.input:
        stock = Path(args.input).read_bytes()
        if sha256(stock) != patch.stock_sha:
            raise PatchError('--input is not the stock image')
        patched = patch.apply(stock)
        print('patched sections:')
        for name, va, vsize, rawptr, rawsize, flags in _sections(patched):
            mark = '  (appended)' if rawptr >= patch.stock_len else ''
            print(f'  {name:8s} rva {va:#010x} vsize {vsize:#8x} raw {rawptr:#09x}+{rawsize:#x} flags {flags:#010x}{mark}')
    return 0


def _c_array(name: str, data: bytes) -> str:
    lines = [f'static const unsigned char {name}[{len(data)}u] = {{']
    for i in range(0, len(data), 24):
        lines.append('    ' + ','.join(f'0x{b:02x}' for b in data[i:i + 24]) + ',')
    lines.append('};')
    return '\n'.join(lines)


def embed_text() -> str:
    nap = Patch.load(DATA / 'napoleon.ntwpatch')
    mss = Patch.load(DATA / 'mss32.ntwpatch')
    out = ['/* GENERATED by tools/apply_ntwpatch.py embed from data/napoleon.ntwpatch and data/mss32.ntwpatch. Do not edit.',
           f' * napoleon: stock {nap.stock_sha.hex()} -> patched {nap.patched_sha.hex()}',
           f' * mss32   : stock {mss.stock_sha.hex()} -> patched {mss.patched_sha.hex()}',
           ' * Verbatim NTWPATCH files (see tools/apply_ntwpatch.py for the layout). */',
           _c_array('kntwr_gameplay_patch_napoleon', nap.raw),
           _c_array('kntwr_gameplay_patch_mss32', mss.raw), '']
    return '\n'.join(out)


def cmd_embed(args) -> int:
    text = embed_text()
    if args.check:
        current = EMBED_PATH.read_text(encoding='utf-8') if EMBED_PATH.exists() else None
        if current != text:
            print(f'{EMBED_PATH} is stale; run tools/apply_ntwpatch.py embed', file=sys.stderr)
            return 1
        print(f'{EMBED_PATH} matches data/*.ntwpatch')
        return 0
    EMBED_PATH.write_text(text, encoding='utf-8', newline='\n')
    print(f'wrote {EMBED_PATH}')
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='command')
    g = sub.add_parser('generate', help='write analysis/Napoleon_patched.exe and analysis/mss32_patched.dll from the stock game files')
    g.add_argument('--game-dir', default=str(DEFAULT_GAME_DIR))
    g.add_argument('--out-dir', default=str(DEFAULT_OUT_DIR))
    g.set_defaults(func=cmd_generate)
    for name, fn in (('apply', cmd_apply), ('revert', cmd_revert)):
        p = sub.add_parser(name)
        p.add_argument('--patch', default=str(DATA / 'napoleon.ntwpatch'))
        p.add_argument('--input', required=True)
        p.add_argument('--output', required=True)
        p.set_defaults(func=fn)
    i = sub.add_parser('info')
    i.add_argument('--patch', default=str(DATA / 'napoleon.ntwpatch'))
    i.add_argument('--input', help='stock image: also list the patched section table')
    i.set_defaults(func=cmd_info)
    e = sub.add_parser('embed')
    e.add_argument('--check', action='store_true')
    e.set_defaults(func=cmd_embed)
    args = ap.parse_args(argv)
    if not args.command:
        args = ap.parse_args(['generate'] + (argv or []))
    try:
        return args.func(args)
    except (PatchError, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
